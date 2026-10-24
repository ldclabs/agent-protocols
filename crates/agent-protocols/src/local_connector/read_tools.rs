//! Agent-facing discovery and verified reads, over existing protocol APIs.
use super::*;
use crate::delegation::validate_delegation_envelope;
use crate::identity::validate_origin;
use crate::mail::{check_card_usable, format_mail_address, parse_mail_address, MailClient};
use crate::profile::materialize_profile;
use std::collections::BTreeSet;

impl LocalConnector {
    pub(super) async fn connector_get(
        &self,
        url: &str,
        jwt: Option<&str>,
    ) -> Result<reqwest::Response> {
        self.require_allowed_origin(url)?;
        let mut request = self.http.get(url);
        if let Some(jwt) = jwt {
            request = request.bearer_auth(jwt);
        }
        let response = request.send().await?;
        if service_origin(response.url().as_str())? != service_origin(url)? {
            return Err(SdkError::PermissionDenied);
        }
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await?;
            let error: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            return Err(SdkError::HttpStatus {
                status,
                code: error["error"]["code"].as_str().map(str::to_owned),
                data: error["error"].get("data").cloned(),
                max_seen_nonce: None,
                body,
            });
        }
        Ok(response)
    }

    async fn verified_profile_client(&self, service: &str) -> Result<ProfileClient> {
        self.require_allowed_origin(service)?;
        let client = ProfileClient::discover_with_client(service, self.http.clone()).await;
        self.require_allowed_origin(client.profiles_url())?;
        Ok(client)
    }

    pub(super) async fn services_list(&self, input: ServicesListInput) -> Result<Value> {
        let origins: BTreeSet<String> = match input.host {
            Some(host) => BTreeSet::from([host]),
            None => self
                .state
                .hosts
                .values()
                .filter(|h| h.allowed)
                .flat_map(|h| std::iter::once(h.host.clone()).chain(h.profile_service.clone()))
                .collect(),
        };
        let protocols = input.protocol.map_or_else(
            || {
                vec![
                    "agent-profile/1.0".into(),
                    "agent-discourse/1.0".into(),
                    "agent-delegation/1.0".into(),
                    "agent-mail/1.0".into(),
                    "agent-knowledge/1.0".into(),
                ]
            },
            |p| vec![p],
        );
        let mut services = Vec::new();
        let mut errors = Vec::new();
        for origin in origins {
            validate_origin(&origin)?;
            self.require_allowed_origin(&origin)?;
            for protocol in &protocols {
                let url = format!(
                    "{origin}/.well-known/{}",
                    protocol.split('/').next().unwrap_or_default()
                );
                let result: Result<Value> = async {
                    let doc: Value =
                        crate::http_client::read_json(self.connector_get(&url, None).await?)
                            .await?;
                    if doc["protocol"] != *protocol || doc["service"] != origin {
                        return Err(SdkError::InvalidPayload(
                            "discovery protocol/service mismatch".into(),
                        ));
                    }
                    if let Some(endpoints) = doc["endpoints"].as_object() {
                        for endpoint in endpoints.values() {
                            if service_origin(endpoint.as_str().unwrap_or_default())? != origin {
                                return Err(SdkError::InvalidPayload(
                                    "discovery endpoint origin mismatch".into(),
                                ));
                            }
                        }
                    }
                    Ok(doc)
                }
                .await;
                match result { Ok(doc)=>services.push(doc), Err(SdkError::HttpStatus{status:404,..})=>{}, Err(error)=>errors.push(json!({"service":origin,"protocol":protocol,"code":error.code().unwrap_or("network_error"),"message":error.to_string()})) }
            }
        }
        Ok(json!({"services":services,"errors":errors}))
    }

    pub(super) async fn profiles_get(&mut self, input: ProfilesGetInput) -> Result<Value> {
        let client = self.verified_profile_client(&input.profile_service).await?;
        let mut profiles = Vec::new();
        let mut missing = Vec::new();
        for id in input.ids.unwrap_or_else(|| vec![self.agent_id()]) {
            id.public_key_bytes()?;
            match client.latest_profile_update(&id).await {
                Ok(envelope) => {
                    let envelope = self.state.profile_pins.observe(&envelope, &id)?;
                    profiles.push(materialize_profile(&envelope)?);
                }
                Err(error)
                    if error.code() == Some("not_found")
                        || matches!(error, SdkError::HttpStatus { status: 404, .. }) =>
                {
                    missing.push(id)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(json!({"profiles":profiles,"missing":missing,"profile_service":input.profile_service}))
    }

    pub(super) async fn profile_history(&self, input: ProfileHistoryInput) -> Result<Value> {
        let client = self.verified_profile_client(&input.profile_service).await?;
        let id = input.agent_id.unwrap_or_else(|| self.agent_id());
        let page = client
            .profile_events_page(
                &id,
                Some(input.limit.unwrap_or(20) as usize),
                input.cursor.as_deref(),
            )
            .await?;
        let mut previous = None;
        for envelope in &page.result {
            if materialize_profile(envelope)?.id != id
                || previous.is_some_and(|nonce| envelope.event.nonce >= nonce)
            {
                return Err(SdkError::InvalidPayload(
                    "profile history identity/order mismatch".into(),
                ));
            }
            previous = Some(envelope.event.nonce);
        }
        Ok(with_cursor(
            json!({"envelopes":page.result,"profile_service":input.profile_service,"agent_id":id}),
            page.next_cursor,
        ))
    }

    pub(super) async fn delegation_history(&self, input: DelegationHistoryInput) -> Result<Value> {
        let (document, _) = self.resolve_principal(&input.principal_id).await?;
        let client = self.principal_delegation_service(&document).await?;
        let credential = client.delegation(&input.id).await?;
        if credential.id != input.id || credential.principal_id != document.id {
            return Err(SdkError::InvalidPayload(
                "credential id or principal mismatch".into(),
            ));
        }
        let page = client
            .delegation_events(&input.id, input.cursor.as_deref())
            .await?;
        for record in &page.result {
            validate_delegation_envelope(&record.envelope)?;
            let payload = serde_json::to_value(&record.envelope.event.payload)?;
            if payload["id"] != input.id || payload["principal_id"] != document.id {
                return Err(SdkError::InvalidPayload(
                    "delegation history binding mismatch".into(),
                ));
            }
        }
        Ok(with_cursor(
            json!({"credential":credential,"records":page.result,"signatures_verified":true}),
            page.next_cursor,
        ))
    }

    pub(super) async fn mail_resolve(&mut self, input: MailResolveInput) -> Result<Value> {
        input.agent_id.public_key_bytes()?;
        if [
            input.address.is_some(),
            input.card_url.is_some(),
            input.profile_service.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count()
            != 1
        {
            return Err(SdkError::InvalidPayload(
                "supply exactly one of address, card_url or profile_service".into(),
            ));
        }
        let profile_lookup = input.profile_service.is_some();
        let mut errors = Vec::new();
        let mut contacts: Vec<(String, Vec<String>)> = Vec::new();
        let mut urls = Vec::new();
        if let Some(address) = input.address {
            let address = parse_mail_address(&address)?;
            if address.owner != input.agent_id {
                return Err(SdkError::InvalidPayload(
                    "mailbox address owner mismatch".into(),
                ));
            }
            let routes = if address.routes.is_empty() {
                self.state
                    .mail
                    .pins
                    .get(&input.agent_id, &address.mailbox_id)
                    .map(|c| c.event.payload.routes.clone())
                    .unwrap_or_default()
            } else {
                address.routes
            };
            contacts.push((address.mailbox_id, routes));
        } else if let Some(url) = input.card_url {
            urls.push(url);
        } else {
            let value = self
                .profiles_get(ProfilesGetInput {
                    profile_service: input.profile_service.unwrap(),
                    ids: Some(vec![input.agent_id.clone()]),
                })
                .await?;
            if let Some(endpoints) = value["profiles"][0]["service_endpoints"].as_array() {
                for endpoint in endpoints {
                    if endpoint["type"] == "agent-mail" {
                        urls.push(endpoint["url"].as_str().unwrap_or_default().to_owned());
                    }
                }
            }
        }
        for url in urls {
            let parsed = (|| -> Result<(String, Vec<String>)> {
                let parsed = reqwest::Url::parse(&url)
                    .map_err(|_| SdkError::InvalidPayload("invalid mailbox card URL".into()))?;
                let segments: Vec<_> = parsed.path().split('/').collect();
                if parsed.query().is_some()
                    || parsed.fragment().is_some()
                    || segments.len() != 5
                    || segments[1] != "v1"
                    || segments[2] != "mailboxes"
                    || segments[4] != "card"
                {
                    return Err(SdkError::InvalidPayload("invalid mailbox card URL".into()));
                }
                let origin = service_origin(&url)?;
                validate_origin(&origin)?;
                format_mail_address(&input.agent_id, segments[3], std::slice::from_ref(&origin))?;
                Ok((segments[3].to_owned(), vec![origin]))
            })();
            match parsed {
                Ok(contact) => contacts.push(contact),
                Err(error) if profile_lookup => {
                    errors.push(json!({"url":url,"code":"invalid_url","message":error.to_string()}))
                }
                Err(error) => return Err(error),
            }
        }
        let mut ids = BTreeSet::new();
        for (id, routes) in contacts {
            ids.insert(id.clone());
            for route in routes {
                let result = async {
                    self.require_allowed_host(&route)?;
                    let record = MailClient::with_client(&route, self.http.clone())?
                        .card(&id, &input.agent_id)
                        .await?;
                    self.state.mail.pins.observe_historical(
                        &serde_json::to_value(record.envelope)?,
                        &input.agent_id,
                        unix_ms(),
                    )
                }
                .await;
                if let Err(error) = result {
                    errors.push(json!({"route":route,"mailbox_id":id,"code":error.code().unwrap_or("network_error"),"message":error.to_string()}));
                }
            }
        }
        let mut mailboxes = Vec::new();
        for id in ids {
            if let Some(card) = self.state.mail.pins.get(&input.agent_id, &id) {
                let usable = check_card_usable(card, &input.agent_id, unix_ms()).is_ok()
                    && card
                        .event
                        .payload
                        .routes
                        .iter()
                        .any(|r| self.require_allowed_host(r).is_ok());
                mailboxes.push(json!({"address":format_mail_address(&input.agent_id,&id,&card.event.payload.routes)?,"card":card,"usable":usable}));
            }
        }
        Ok(json!({"agent_id":input.agent_id,"mailboxes":mailboxes,"errors":errors}))
    }

    pub(super) fn schema_get(&self, input: SchemaGetInput) -> Result<Value> {
        let data = catalog::catalog_data();
        let schema = &data["schemas"][&input.protocol];
        if schema.is_null() {
            return Err(SdkError::InvalidPayload("unsupported protocol".into()));
        }
        let mappings: &[(&str, &str)] = match input.protocol.as_str() {
            "agent-profile/1.0" => &[("profile.update", "profileUpdatePayload")],
            "agent-knowledge/1.0" => &[
                ("knowledge.publish", "publishPayload"),
                ("knowledge.assess", "assessPayload"),
                ("knowledge.retract", "retractPayload"),
            ],
            _ => &[
                ("room.create", "roomCreatePayload"),
                ("room.update", "roomUpdatePayload"),
                ("room.join", "roomJoinPayload"),
                ("room.join.request", "roomJoinRequestPayload"),
                ("room.join.review", "roomJoinReviewPayload"),
                ("room.leave", "reasonPayload"),
                ("room.close", "reasonPayload"),
                ("room.cancel", "reasonPayload"),
                ("room.member.role.update", "roomMemberRoleUpdatePayload"),
                ("room.member.remove", "roomMemberRemovePayload"),
                ("message.create", "messageCreatePayload"),
                ("type.define", "typeDeclaration"),
            ],
        };
        let mut schemas:Vec<_>=mappings.iter().filter(|(name,_)|input.event_type.as_deref().is_none_or(|t|t==*name)).map(|(name,definition)|json!({"type":name,"schema":catalog::payload_schema(schema,definition)})).collect();
        if let Some(room_id) = input.room_id {
            if input.protocol != "agent-discourse/1.0" {
                return Err(SdkError::InvalidPayload(
                    "room_id requires agent-discourse/1.0".into(),
                ));
            }
            let key = self.resolve_room_key(input.host.as_deref(), &room_id)?;
            for def in &self.local_room(&key)?.room.types {
                if input.event_type.as_deref().is_none_or(|t| t == def.name) {
                    schemas.push(json!({"type":def.name,"schema":def.schema}));
                }
            }
        }
        if input.event_type.is_some() && schemas.is_empty() {
            return Err(SdkError::InvalidPayload(
                "unknown event type; open the room for custom schemas".into(),
            ));
        }
        let mut out = json!({"protocol":input.protocol,"schemas":schemas});
        if input.protocol == "agent-discourse/1.0" {
            out["registered_packs"] = data["packs"]["packs"].clone();
        }
        Ok(out)
    }

    pub(super) fn room_watch(&mut self, input: RoomWatchInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let room = self.local_room_mut(&key)?;
        if let Some(types) = input.types {
            for name in &types {
                if !room.room.types.iter().any(|d| &d.name == name) {
                    return Err(SdkError::InvalidPayload(format!(
                        "unknown custom event type: {name}"
                    )));
                }
            }
            room.watch_types = Some(types);
        }
        let types = room.watch_types.clone().unwrap_or_default();
        Ok(json!({"types":types,"sync":self.sync_state(&key)?}))
    }

    pub(super) async fn my_rooms(&mut self, input: RoomsListInput) -> Result<Value> {
        let host = normalize_host(input.host.as_deref().unwrap_or_default());
        self.require_allowed_host(&host)?;
        let client = self.discourse(&host).await?;
        if service_origin(client.my_rooms_url())? != host {
            return Err(SdkError::PermissionDenied);
        }
        let mut url = reqwest::Url::parse(client.my_rooms_url())
            .map_err(|_| SdkError::InvalidPayload("invalid my_rooms endpoint".into()))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(status) = input.status {
                query.append_pair("status", &status);
            }
            if let Some(membership) = input.membership {
                query.append_pair(
                    "membership",
                    serde_json::to_value(membership)?
                        .as_str()
                        .unwrap_or_default(),
                );
            }
            if let Some(limit) = input.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(cursor) = input.cursor {
                query.append_pair("cursor", &cursor);
            }
        }
        let page: Value = crate::http_client::read_json(
            self.connector_get(url.as_str(), Some(&self.request_jwt(&host)?))
                .await?,
        )
        .await?;
        let records = page["result"]
            .as_array()
            .ok_or_else(|| SdkError::InvalidPayload("invalid rooms list".into()))?;
        let mut rooms = Vec::new();
        for record in records {
            let room: RoomResponse = serde_json::from_value(record.clone())?;
            self.observe_room(host.clone(), room.clone());
            let mut summary = serde_json::to_value(self.summary_for_response(&host, &room))?;
            for field in ["membership", "role"] {
                if let Some(value) = record.get(field) {
                    summary[field] = value.clone();
                }
            }
            rooms.push(summary);
        }
        Ok(with_cursor(
            json!({"rooms":rooms}),
            page["next_cursor"].as_str().map(str::to_owned),
        ))
    }
}
