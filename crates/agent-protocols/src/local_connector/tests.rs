use super::inputs::{
    DraftDropInput, DraftGetInput, DraftsListInput, InboxNextInput, RoomMembersListInput,
    RoomSendMessageInput,
};
use super::*;

use crate::discourse::{
    build_server_record, discourse_event, event_type, room_create_event, MessageCreatePayload,
    Role, RoomCreatePayload, RoomJoinPayload, RoomResponse, RoomState, TypeDef, Visibility,
};
use crate::error::SdkError;
use crate::identity::AgentSigner;
use crate::profile::{materialize_profile, ProfileUpdatePayload};

use serde_json::json;
use std::collections::BTreeMap;

fn signer(byte: u8) -> AgentSigner {
    AgentSigner::from_seed([byte; 32])
}

fn room_response(room_id: &str, signer: &AgentSigner) -> RoomResponse {
    let envelope = signer
        .sign_event(room_create_event(
            signer.agent_id(),
            100,
            1,
            RoomCreatePayload::new("Room", Visibility::Public, 1, 2),
        ))
        .unwrap();
    RoomResponse {
        id: room_id.to_owned(),
        status: RoomState::Active,
        url: format!("https://api.example.test/v1/rooms/{room_id}"),
        creator: None,
        created_at: None,
        topic: Some("Room".to_owned()),
        agenda: None,
        guidance: None,
        visibility: Some(Visibility::Public),
        start_time: Some(1),
        end_time: Some(2),
        tags: Vec::new(),
        language: None,
        policy: None,
        types: Vec::new(),
        seq: 1,
        pre_hash: None,
        hash: "room-create-head".to_owned(),
        received_at: 100,
        head: Some(crate::discourse::RoomHead {
            seq: 1,
            hash: "room-create-head".to_owned(),
        }),
        envelope: Some(envelope),
    }
}

#[test]
fn standard_tool_definitions_include_agent_facing_tools() {
    let tools = standard_tool_definitions();
    let names = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&TOOL_ROOM_MEMBERS_LIST));
    assert!(names.contains(&TOOL_INBOX_NEXT));
    assert!(names.contains(&TOOL_DRAFTS_LIST));
    assert!(names.contains(&TOOL_ROOM_JOIN));
    assert!(!names.contains(&TOOL_ROOM_JOIN_REQUEST));
    assert!(names.contains(&TOOL_ROOM_SEND_MESSAGE));
    assert!(
        tools
            .iter()
            .find(|tool| tool.name == TOOL_ROOM_MEMBERS_LIST)
            .unwrap()
            .annotations
            .read_only_hint
    );
}

#[test]
fn observed_hosts_do_not_bypass_allowlist_for_signing() {
    let active = signer(1);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    connector.accept_room_response(
        "https://untrusted.example.test",
        room_response("room1", &creator),
    );

    assert_eq!(
        connector
            .state
            .hosts
            .get("https://untrusted.example.test")
            .unwrap()
            .allowed,
        false
    );
    let result = connector.sign_room_event(
        event_type::MESSAGE_CREATE,
        &(
            "https://untrusted.example.test".to_owned(),
            "room1".to_owned(),
        ),
        None,
        None,
        Vec::new(),
        MessageCreatePayload::text("hi"),
    );
    assert!(matches!(result, Err(SdkError::PermissionDenied)));
}

#[test]
fn room_views_fall_back_to_room_create_payload_metadata() {
    let active = signer(1);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    let mut room = room_response("room1", &creator);
    let payload = &mut room.envelope.as_mut().unwrap().event.payload;
    payload.agenda = Some("Review the proposal".to_owned());
    payload.guidance = Some("Stay concise".to_owned());
    payload.tags = vec!["review".to_owned()];
    payload.language = Some("en".to_owned());
    room.topic = None;
    room.agenda = None;
    room.guidance = None;
    room.visibility = None;
    room.start_time = None;
    room.end_time = None;
    room.tags.clear();
    room.language = None;

    connector.observe_room("https://api.example.test", room);
    let key = ("https://api.example.test".to_owned(), "room1".to_owned());
    let room = connector.local_room(&key).unwrap();
    let view = connector.room_state_view(room);
    let summary = connector.summary_for_room(room);

    assert_eq!(view.topic.as_deref(), Some("Room"));
    assert_eq!(view.agenda.as_deref(), Some("Review the proposal"));
    assert_eq!(view.guidance.as_deref(), Some("Stay concise"));
    assert_eq!(view.visibility, Some(Visibility::Public));
    assert_eq!(view.start_time, Some(1));
    assert_eq!(view.end_time, Some(2));
    assert_eq!(view.tags, vec!["review"]);
    assert_eq!(view.language.as_deref(), Some("en"));
    assert_eq!(summary.topic.as_deref(), Some("Room"));
    assert_eq!(summary.tags, vec!["review"]);
}

#[test]
fn applies_room_records_into_members_timeline_and_inbox() {
    let active = signer(1);
    let speaker = signer(2);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    connector.add_host(AgentProtocolsHost {
        host: "https://api.example.test".to_owned(),
        label: None,
        allowed: true,
        features: Vec::new(),
        profile_service: None,
        last_checked_at: None,
    });
    connector
        .accept_room_response("https://api.example.test", room_response("room1", &creator));

    let join_envelope = speaker
        .sign_event(discourse_event(
            event_type::ROOM_JOIN,
            speaker.agent_id(),
            110,
            1,
            "room1",
            1,
            "room-create-head",
            RoomJoinPayload {
                request_id: Some("jr1".to_owned()),
                role: Role::Speaker,
                perspective: None,
            },
        ))
        .unwrap();
    let join = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        111,
        join_envelope,
    )
    .unwrap();
    connector
        .apply_record(typed_record_to_value(join).unwrap())
        .unwrap();

    // room.join is a membership signal: it does not advance the room head,
    // so the message still bases on the room.create head.
    let key = ("https://api.example.test".to_owned(), "room1".to_owned());
    let head_after_join = connector.local_room(&key).unwrap().head_seq;
    assert_eq!(head_after_join, 1);
    let join_record_hash = connector
        .local_room(&key)
        .unwrap()
        .synced_hash
        .clone()
        .unwrap();
    let message = MessageCreatePayload::text("please review this");
    let message_envelope = speaker
        .sign_event(
            discourse_event(
                event_type::MESSAGE_CREATE,
                speaker.agent_id(),
                120,
                2,
                "room1",
                1,
                "room-create-head",
                message,
            )
            .with_mention(connector.agent_id()),
        )
        .unwrap();
    let message =
        build_server_record("room1", 3, Some(join_record_hash), 121, message_envelope).unwrap();
    connector
        .apply_record(typed_record_to_value(message).unwrap())
        .unwrap();

    let members = connector
        .room_members_list(RoomMembersListInput {
            room_id: "room1".to_owned(),
            host: None,
            status: Some(RoomMemberStatus::Active),
            role: None,
            include_profiles: false,
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(members["members"].as_array().unwrap().len(), 2);

    let inbox = connector
        .inbox_next(InboxNextInput {
            room_id: Some("room1".to_owned()),
            kinds: Some(vec!["room.mention".to_owned()]),
            limit: None,
            wait_ms: None,
            claim: true,
        })
        .unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["kind"], "room.mention");
    assert_eq!(inbox["pending_count"], 0);
}

#[test]
fn room_head_mismatch_holds_message_draft_before_network_submit() {
    let active = signer(1);
    let speaker = signer(2);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    connector
        .accept_room_response("https://api.example.test", room_response("room1", &creator));

    let message = MessageCreatePayload::text("new context");
    let message_envelope = speaker
        .sign_event(discourse_event(
            event_type::MESSAGE_CREATE,
            speaker.agent_id(),
            120,
            1,
            "room1",
            1,
            "room-create-head",
            message,
        ))
        .unwrap();
    let message = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        121,
        message_envelope,
    )
    .unwrap();
    connector
        .apply_record(typed_record_to_value(message).unwrap())
        .unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime
        .block_on(connector.room_send_message(RoomSendMessageInput {
            room_id: "room1".to_owned(),
            host: None,
            content: "answer based on old context".to_owned(),
            content_type: None,
            mentions: Vec::new(),
            references: Vec::new(),
            extra: BTreeMap::new(),
            base_seq: Some(1),
            base_hash: Some("room-create-head".to_owned()),
            on_head_mismatch: HeadMismatchPolicy::Hold,
        }))
        .unwrap();

    assert_eq!(result["status"], "held");
    assert_eq!(result["draft"]["kind"], "message");
    assert_eq!(result["draft"]["base_seq"], 1);
    assert_eq!(result["changes"].as_array().unwrap().len(), 1);
    assert_eq!(connector.state.drafts.len(), 1);

    let draft_id = result["draft"]["id"].as_str().unwrap().to_owned();
    let drafts = connector
        .drafts_list(DraftsListInput {
            room_id: Some("room1".to_owned()),
            host: None,
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(drafts["drafts"].as_array().unwrap().len(), 1);

    let draft = connector
        .draft_get(DraftGetInput {
            draft_id: draft_id.clone(),
        })
        .unwrap();
    assert_eq!(draft["changes"].as_array().unwrap().len(), 1);

    let dropped = connector.draft_drop(DraftDropInput { draft_id }).unwrap();
    assert_eq!(dropped["status"], "dropped");
    assert_eq!(connector.state.drafts.len(), 0);
}

#[test]
fn signal_records_do_not_advance_room_head() {
    let active = signer(1);
    let speaker = signer(2);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    let mut room = room_response("room1", &creator);
    room.types.push(TypeDef {
        name: "reaction.create".to_owned(),
        kind: crate::discourse::TypeKind::Signal,
        title: "Reaction".to_owned(),
        description: None,
        schema: json!({"type": "object"}),
        roles: None,
        instructions: None,
        version: None,
        status: None,
        rate_hint: None,
        max_payload_hint: None,
        extra: BTreeMap::new(),
    });
    connector.accept_room_response("https://api.example.test", room);

    let signal_envelope = speaker
        .sign_event(discourse_event(
            "reaction.create",
            speaker.agent_id(),
            120,
            1,
            "room1",
            1,
            "room-create-head",
            json!({"emoji": "+1"}),
        ))
        .unwrap();
    let signal = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        121,
        signal_envelope,
    )
    .unwrap();
    connector
        .apply_record(typed_record_to_value(signal).unwrap())
        .unwrap();

    let key = ("https://api.example.test".to_owned(), "room1".to_owned());
    let sync = connector.sync_state(&key).unwrap();
    assert_eq!(sync.head_seq, 1);
    assert_eq!(sync.head_hash, "room-create-head");
    assert_eq!(sync.synced_seq, 2);
    assert_eq!(sync.remote_seq, 2);
}

#[test]
fn rejects_non_signal_records_not_based_on_room_head() {
    let active = signer(1);
    let speaker = signer(2);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    let mut room = room_response("room1", &creator);
    room.types.push(TypeDef {
        name: "reaction.create".to_owned(),
        kind: crate::discourse::TypeKind::Signal,
        title: "Reaction".to_owned(),
        description: None,
        schema: json!({"type": "object"}),
        roles: None,
        instructions: None,
        version: None,
        status: None,
        rate_hint: None,
        max_payload_hint: None,
        extra: BTreeMap::new(),
    });
    connector.accept_room_response("https://api.example.test", room);

    let signal_envelope = speaker
        .sign_event(discourse_event(
            "reaction.create",
            speaker.agent_id(),
            120,
            1,
            "room1",
            1,
            "room-create-head",
            json!({"emoji": "+1"}),
        ))
        .unwrap();
    let signal = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        121,
        signal_envelope,
    )
    .unwrap();
    let signal_hash = signal.hash.clone();
    connector
        .apply_record(typed_record_to_value(signal).unwrap())
        .unwrap();

    let stale_message_envelope = speaker
        .sign_event(discourse_event(
            event_type::MESSAGE_CREATE,
            speaker.agent_id(),
            122,
            2,
            "room1",
            2,
            signal_hash.clone(),
            MessageCreatePayload::text("based on signal, not room head"),
        ))
        .unwrap();
    let stale_message =
        build_server_record("room1", 3, Some(signal_hash), 123, stale_message_envelope)
            .unwrap();

    let err = connector
        .apply_record(typed_record_to_value(stale_message).unwrap())
        .unwrap_err();
    assert!(err.to_string().contains("must match current room head"));
}

#[test]
fn member_remove_records_project_removal_bans_and_inbox() {
    let active = signer(1);
    let moderator = signer(5);
    let mut connector = LocalConnector::new(active);
    let mut room = room_response("room1", &moderator);
    room.creator = Some(moderator.agent_id());
    connector.accept_room_response("https://api.example.test", room);
    let key = ("https://api.example.test".to_owned(), "room1".to_owned());

    // The active agent joins, then is removed with a ban.
    let active_id = connector.agent_id();
    let join_envelope = connector
        .signer
        .sign_event(discourse_event(
            event_type::ROOM_JOIN,
            active_id.clone(),
            110,
            1,
            "room1",
            1,
            "room-create-head",
            RoomJoinPayload {
                request_id: None,
                role: Role::Speaker,
                perspective: None,
            },
        ))
        .unwrap();
    let join = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        111,
        join_envelope,
    )
    .unwrap();
    connector
        .apply_host_record(
            "https://api.example.test",
            typed_record_to_value(join).unwrap(),
        )
        .unwrap();
    // Membership signals never advance the room head.
    assert_eq!(connector.local_room(&key).unwrap().head_seq, 1);

    let join_hash = connector
        .local_room(&key)
        .unwrap()
        .synced_hash
        .clone()
        .unwrap();
    let remove_envelope = moderator
        .sign_event(discourse_event(
            event_type::ROOM_MEMBER_REMOVE,
            moderator.agent_id(),
            120,
            2,
            "room1",
            1,
            "room-create-head",
            crate::discourse::RoomMemberRemovePayload {
                ban: Some(true),
                reason: Some("spam".to_owned()),
                ..crate::discourse::RoomMemberRemovePayload::new(active_id.clone())
            },
        ))
        .unwrap();
    let remove =
        build_server_record("room1", 3, Some(join_hash), 121, remove_envelope).unwrap();
    connector
        .apply_host_record(
            "https://api.example.test",
            typed_record_to_value(remove).unwrap(),
        )
        .unwrap();

    // Still anchored, still not head-advancing.
    assert_eq!(connector.local_room(&key).unwrap().head_seq, 1);
    let member = connector
        .local_room(&key)
        .unwrap()
        .members
        .get(&active_id)
        .cloned()
        .unwrap();
    assert_eq!(member.status, RoomMemberStatus::Banned);
    assert_eq!(member.left_seq, Some(3));

    let banned_members = connector
        .room_members_list(RoomMembersListInput {
            room_id: "room1".to_owned(),
            host: None,
            status: Some(RoomMemberStatus::Banned),
            role: None,
            include_profiles: false,
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(banned_members["members"].as_array().unwrap().len(), 1);

    let inbox = connector
        .inbox_next(InboxNextInput {
            room_id: Some("room1".to_owned()),
            kinds: Some(vec!["room.member.removed".to_owned()]),
            limit: None,
            wait_ms: None,
            claim: false,
        })
        .unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["kind"], "room.member.removed");
    assert_eq!(inbox["items"][0]["reason"], "member_banned");
}

#[test]
fn room_update_records_advance_head_and_revise_the_contract() {
    let active = signer(1);
    let moderator = signer(5);
    let mut connector = LocalConnector::new(active);
    connector.accept_room_response(
        "https://api.example.test",
        room_response("room1", &moderator),
    );
    let key = ("https://api.example.test".to_owned(), "room1".to_owned());

    let update_envelope = moderator
        .sign_event(discourse_event(
            event_type::ROOM_UPDATE,
            moderator.agent_id(),
            120,
            2,
            "room1",
            1,
            "room-create-head",
            crate::discourse::RoomUpdatePayload {
                topic: Some("Sharper topic".to_owned()),
                guidance: Some(String::new()),
                end_time: Some(5000),
                // An all-default policy is still an explicit revision: it
                // must be stored verbatim, not cleared.
                policy: Some(crate::discourse::RoomPolicy::default()),
                ..crate::discourse::RoomUpdatePayload::default()
            },
        ))
        .unwrap();
    let update = build_server_record(
        "room1",
        2,
        Some("room-create-head".to_owned()),
        121,
        update_envelope,
    )
    .unwrap();
    connector
        .apply_host_record(
            "https://api.example.test",
            typed_record_to_value(update).unwrap(),
        )
        .unwrap();

    // room.update is a lifecycle event: it advances the room head.
    let room = connector.local_room(&key).unwrap();
    assert_eq!(room.head_seq, 2);
    assert_eq!(room.room.topic.as_deref(), Some("Sharper topic"));
    assert_eq!(room.room.guidance, None);
    assert_eq!(room.room.end_time, Some(5000));
    assert_eq!(
        room.room.policy,
        Some(crate::discourse::RoomPolicy::default())
    );
    assert_eq!(connector.pending_inbox_count(Some("room1")), 1);
}

#[test]
fn duplicate_room_ids_across_hosts_require_a_host_input() {
    let active = signer(1);
    let creator = signer(5);
    let mut connector = LocalConnector::new(active);
    connector.accept_room_response("https://a.example.test", room_response("room1", &creator));
    connector.accept_room_response("https://b.example.test", room_response("room1", &creator));

    assert!(connector.resolve_room_key(None, "room1").is_err());
    assert_eq!(
        connector
            .resolve_room_key(Some("https://a.example.test"), "room1")
            .unwrap(),
        ("https://a.example.test".to_owned(), "room1".to_owned())
    );
    let listed = connector
        .room_members_list(RoomMembersListInput {
            room_id: "room1".to_owned(),
            host: Some("https://b.example.test".to_owned()),
            status: None,
            role: None,
            include_profiles: false,
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(listed["sync"]["host"], "https://b.example.test");
}

#[test]
fn standard_tools_exclude_host_mutation_and_mark_timeline_writable() {
    let tools = standard_tool_definitions();
    assert!(!tools
        .iter()
        .any(|tool| tool.name == "agent_protocols_host_add"));
    let timeline = tools
        .iter()
        .find(|tool| tool.name == TOOL_ROOM_TIMELINE)
        .unwrap();
    assert!(!timeline.annotations.read_only_hint);
    assert!(timeline.annotations.idempotent_hint);
    let inbox_next = tools
        .iter()
        .find(|tool| tool.name == TOOL_INBOX_NEXT)
        .unwrap();
    assert!(!inbox_next.annotations.read_only_hint);
}

#[test]
fn signs_profile_update_without_exposing_private_key() {
    let signer = signer(3);
    let mut connector = LocalConnector::new(signer);
    let payload = ProfileUpdatePayload::new(connector.agent_id(), "Agent");
    let envelope = connector.sign_profile_update(payload).unwrap();
    let profile = materialize_profile(&envelope).unwrap();
    assert_eq!(profile.name, "Agent");
    assert_eq!(envelope.event.nonce, 1);
}

#[test]
fn payload_with_references_stores_references_under_extra() {
    let payload =
        payload_with_references(json!({"instruction": "answer"}), vec!["abc".to_owned()])
            .unwrap();
    assert_eq!(payload["extra"]["references"][0], "abc");
}
