//! Historical reads replay independently of the live room and attention state.
use super::*;
use crate::discourse::{
    pack_map, validate_room_join_review_payload, validate_room_write, verify_archive_chain,
    verify_archive_records, verify_pack_digest, ArchiveManifest, Pack, PackDocument,
    PermissionContext, Role, RoomState, TypeDeclaration, TypeRegistry,
};
use std::collections::BTreeSet;

fn replay(
    records: &[ArchiveRecord],
    host: &str,
    packs: &BTreeMap<String, Pack>,
) -> Result<(LocalRoomState, bool)> {
    verify_archive_chain(records)?;
    let first = match records.first() {
        Some(ArchiveRecord::Signed(r)) if r.envelope.event.kind == "room.create" => r,
        _ => {
            return Err(SdkError::InvalidPayload(
                "history requires an unredacted room.create genesis".into(),
            ))
        }
    };
    let payload: RoomCreatePayload = serde_json::from_value(first.envelope.event.payload.clone())?;
    crate::discourse::validate_room_create_payload(&payload)?;
    if payload.host != host {
        return Err(SdkError::InvalidPayload(
            "history genesis host mismatch".into(),
        ));
    }
    let mut resource = serde_json::to_value(&payload)?;
    for (field, value) in [
        ("id", json!(first.room_id)),
        ("url", json!(format!("{host}/v1/rooms/{}", first.room_id))),
        ("creator", json!(first.envelope.event.actor)),
        ("created_at", json!(first.envelope.event.created_at)),
        ("status", json!("scheduled")),
        ("seq", json!(0)),
        ("hash", json!("")),
        ("accepted_at", json!(first.accepted_at)),
        ("types", json!([])),
    ] {
        resource[field] = value;
    }
    let mut room = LocalRoomState::new(host.to_owned(), serde_json::from_value(resource)?);
    materialize_creator(&mut room);
    let mut registry = TypeRegistry::default();
    let mut state_verified = true;
    let schema = &catalog::catalog_data()["schemas"]["agent-discourse/1.0"];
    let validator =
        jsonschema::validator_for(schema).map_err(|e| SdkError::InvalidPayload(e.to_string()))?;
    for record in records {
        if record.room_id() != first.room_id {
            return Err(SdkError::InvalidPayload("history room mismatch".into()));
        }
        match record {
            ArchiveRecord::Redacted(_) => state_verified = false,
            ArchiveRecord::Signed(r) => {
                let event = &r.envelope.event;
                validate_discourse_envelope(&r.envelope)?;
                validate_room_path(&r.envelope, &first.room_id)?;
                validator
                    .validate(&serde_json::to_value(&r.envelope)?)
                    .map_err(|e| {
                        SdkError::InvalidPayload(format!("history envelope schema: {e}"))
                    })?;
                if r.seq == 1 {
                    registry = TypeRegistry::from_declarations(
                        payload.types.as_deref().unwrap_or_default(),
                        packs,
                    )?;
                    room.room.types = registry.definitions().cloned().collect();
                } else if state_verified {
                    if !matches!(room.room.status, RoomState::Ended | RoomState::Cancelled) {
                        room.room.status = if r.accepted_at < room.room.start_time.unwrap_or(0) {
                            RoomState::Scheduled
                        } else if r.accepted_at >= room.room.end_time.unwrap_or(0) {
                            RoomState::Ended
                        } else {
                            RoomState::Active
                        };
                    }
                    let member = room.members.get(&event.actor);
                    let role = member
                        .filter(|m| m.status == RoomMemberStatus::Active)
                        .map(|m| m.role);
                    let direct_join_allowed = if event.kind == "room.join" {
                        let role: Role = serde_json::from_value(event.payload["role"].clone())?;
                        can_join_directly(
                            room.room
                                .visibility
                                .unwrap_or(crate::discourse::Visibility::Private),
                            room.room.policy.as_ref(),
                            &event.actor,
                            role,
                        ) && member.is_none_or(|m| m.status != RoomMemberStatus::Banned)
                    } else {
                        false
                    };
                    validate_room_write(
                        &event.kind,
                        room.room.status,
                        &PermissionContext {
                            role,
                            is_creator: room.room.creator.as_ref() == Some(&event.actor),
                            direct_join_allowed,
                        },
                        &registry,
                    )?;
                    validate_record_base_precondition(&room, record)?;
                    if event.kind == "room.join.review" {
                        validate_room_join_review_payload(
                            &serde_json::from_value(event.payload.clone())?,
                            Some(&first.room_id),
                        )?;
                    }
                    if !schema["$defs"]["builtinEventType"]["enum"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|t| t == &event.kind)
                    {
                        registry.validate_payload(&event.kind, &event.payload)?;
                    }
                    if event.kind == "type.define" {
                        registry.apply(
                            &serde_json::from_value::<TypeDeclaration>(event.payload.clone())?,
                            packs,
                        )?;
                    }
                }
            }
        }
        let item = TimelineItem::from_record(record, &room.room.types);
        apply_record_projection(
            &mut room,
            record,
            &item,
            &first.envelope.event.actor,
            &mut Vec::new(),
        )?;
        if state_verified {
            room.room.types = registry.definitions().cloned().collect();
        }
        if record_advances_room_head(&room, record) {
            room.head_seq = record.seq();
            room.head_hash = Some(record.hash().to_owned());
        }
        room.synced_seq = record.seq();
        room.synced_hash = Some(record.hash().to_owned());
        room.records.push(record.clone());
        room.timeline.push(item);
    }
    Ok((room, state_verified))
}

fn referenced_packs(records: &[ArchiveRecord]) -> Result<BTreeMap<String, String>> {
    let mut references = BTreeMap::new();
    for record in records {
        if let ArchiveRecord::Signed(r) = record {
            let event = &r.envelope.event;
            let declarations: Vec<Value> = match event.kind.as_str() {
                "room.create" => event.payload["types"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
                "type.define" => vec![event.payload.clone()],
                _ => vec![],
            };
            for declaration in declarations {
                if let (Some(url), Some(digest)) =
                    (declaration["pack"].as_str(), declaration["digest"].as_str())
                {
                    if references.get(url).is_some_and(|old| old != digest) {
                        return Err(SdkError::InvalidPayload(
                            "conflicting external pack versions need separate pack URLs".into(),
                        ));
                    }
                    references.insert(url.into(), digest.into());
                }
            }
        }
    }
    Ok(references)
}

impl LocalConnector {
    pub(super) async fn remote_timeline(&self, input: RoomTimelineInput) -> Result<Value> {
        if input.mark_read || input.unread_only {
            return Err(SdkError::InvalidPayload(
                "remote history does not mark read or filter unread".into(),
            ));
        }
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        self.require_allowed_host(&key.0)?;
        let client = self.discourse(&key.0).await?;
        let jwt = self.request_jwt(&key.0)?;
        let mut cursor = None;
        let mut cursors = BTreeSet::new();
        let mut records = Vec::new();
        loop {
            let page = client
                .events_with_options(
                    &key.1,
                    &RoomEventsOptions {
                        after_seq: Some(0),
                        limit: Some(1000),
                        cursor: cursor.clone(),
                        jwt: Some(jwt.clone()),
                    },
                )
                .await?;
            records.extend(page.result);
            cursor = page.next_cursor;
            if let Some(c) = &cursor {
                if !cursors.insert(c.clone()) {
                    return Err(SdkError::InvalidPayload(
                        "history cursor did not advance".into(),
                    ));
                }
            } else {
                break;
            }
        }
        let packs: PackDocument = serde_json::from_value(catalog::catalog_data()["packs"].clone())?;
        let mut packs = pack_map(&packs);
        for (url, digest) in referenced_packs(&records)? {
            let bytes = self.connector_get(&url, None).await?.bytes().await?;
            verify_pack_digest(&bytes, &digest)?;
            let document: PackDocument = serde_json::from_slice(&bytes)?;
            let pack = document.packs.iter().find(|p| p.id == url).ok_or_else(|| {
                SdkError::InvalidPayload("external pack identity mismatch".into())
            })?;
            packs.insert(url, pack.clone());
        }
        let (room, _) = replay(&records, &key.0, &packs)?;
        let items: Vec<_> = room
            .timeline
            .iter()
            .filter(|item| {
                input.after_seq.is_none_or(|seq| item.seq > seq)
                    && input.before_seq.is_none_or(|seq| item.seq < seq)
                    && input
                        .types
                        .as_ref()
                        .is_none_or(|t| t.contains(&item.event_type))
                    && input.actors.as_ref().is_none_or(|actors| {
                        item.actor.as_ref().is_some_and(|a| actors.contains(a))
                    })
            })
            .take(input.limit.unwrap_or(50))
            .cloned()
            .collect();
        let sync = if self.state.rooms.contains_key(&key) {
            serde_json::to_value(self.sync_state(&key)?)?
        } else {
            json!({"host":key.0,"room_id":key.1,"head_seq":room.head_seq,"head_hash":room.head_hash,"synced_seq":room.synced_seq,"remote_seq":room.synced_seq,"subscribed":false,"unread_count":0,"pending_inbox_count":0})
        };
        let mut out = json!({"items":items,"sync":sync,"unread_count":self.state.rooms.get(&key).map_or(0,|r|r.unread_count()),"history":{"source":"remote","first_seq":records.first().map_or(0,|r|r.seq()),"last_seq":records.last().map_or(0,|r|r.seq()),"truncated":false}});
        if let Some(item) = items.last() {
            out["next_after_seq"] = json!(item.seq);
        }
        Ok(out)
    }

    pub(super) async fn room_archive(&self, input: RoomArchiveInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        self.require_allowed_host(&key.0)?;
        let client = self.discourse(&key.0).await?;
        let jwt = self.request_jwt(&key.0)?;
        let manifest: ArchiveManifest = self
            .connector_get(
                &format!("{}/{}/archive", client.rooms_url(), key.1),
                Some(&jwt),
            )
            .await?
            .json()
            .await?;
        if manifest.protocol != "agent-discourse/1.0"
            || manifest.kind != "room.archive"
            || manifest.room_id != key.1
        {
            return Err(SdkError::InvalidPayload("invalid archive manifest".into()));
        }
        let url = manifest
            .formats
            .get("jsonl")
            .ok_or_else(|| SdkError::InvalidPayload("archive has no jsonl".into()))?;
        if service_origin(url)? != key.0 {
            return Err(SdkError::PermissionDenied);
        }
        let log = self.connector_get(url, Some(&jwt)).await?.text().await?;
        let records: Vec<ArchiveRecord> = log
            .lines()
            .filter(|s| !s.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let redacted = verify_archive_records(&manifest, &records)?;
        let registered: PackDocument =
            serde_json::from_value(catalog::catalog_data()["packs"].clone())?;
        let mut packs = pack_map(&registered);
        let mut documents = Vec::new();
        let references = referenced_packs(&records)?;
        for entry in &manifest.packs {
            if references
                .get(&entry.pack)
                .is_some_and(|d| d != &entry.digest)
            {
                return Err(SdkError::InvalidPayload(
                    "archive pack digest differs from the signed import".into(),
                ));
            }
            if service_origin(&entry.url)? != key.0 {
                return Err(SdkError::PermissionDenied);
            }
            let bytes = self
                .connector_get(&entry.url, Some(&jwt))
                .await?
                .bytes()
                .await?;
            verify_pack_digest(&bytes, &entry.digest)?;
            let document: PackDocument = serde_json::from_slice(&bytes)?;
            let pack = document
                .packs
                .iter()
                .find(|p| p.id == entry.pack)
                .ok_or_else(|| {
                    SdkError::InvalidPayload("archived pack identity mismatch".into())
                })?;
            packs.insert(entry.pack.clone(), pack.clone());
            documents.push(document);
        }
        for (url, digest) in references {
            if !manifest
                .packs
                .iter()
                .any(|p| p.pack == url && p.digest == digest)
            {
                return Err(SdkError::InvalidPayload(
                    "archive is missing a referenced pack".into(),
                ));
            }
        }
        let state_verified = if redacted.contains(&1) {
            false
        } else {
            replay(&records, &key.0, &packs)?.1
        };
        Ok(
            json!({"manifest":manifest,"records":records,"verified":true,"redacted":redacted,"state_verified":state_verified,"packs":documents}),
        )
    }
}
