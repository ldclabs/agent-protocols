use super::inputs::{
    DraftCommitInput, DraftsListInput, InboxNextInput, MemberStatusFilter, RoomMembersListInput,
    RoomSendMessageInput, RoomTimelineInput,
};
use super::*;

use crate::discourse::{
    build_server_record, discourse_event, event_type, redact_server_record, room_create_event,
    room_join_request_event, JoinDecision, MessageCreatePayload, RecordClass, Role,
    RoomCreatePayload, RoomJoinPayload, RoomJoinRequestPayload, RoomJoinReviewPayload,
    RoomMemberRemovePayload, RoomPolicy, RoomResponse, RoomState, RoomUpdatePayload, ServerRecord,
    TypeDef, TypeKind, Visibility,
};
use crate::error::SdkError;
use crate::identity::AgentSigner;
use crate::profile::{materialize_profile, ProfileUpdatePayload};

use serde_json::json;
use std::collections::BTreeMap;

const HOST: &str = "https://api.example.test";
const HEAD: &str = "room-create-head";

fn signer(byte: u8) -> AgentSigner {
    AgentSigner::from_seed([byte; 32])
}

fn key() -> RoomKey {
    (HOST.to_owned(), "room1".to_owned())
}

fn allowed(host: &str) -> AgentProtocolsHost {
    AgentProtocolsHost {
        host: host.to_owned(),
        label: None,
        allowed: true,
        features: Vec::new(),
        profile_service: None,
        last_checked_at: None,
    }
}

fn room_response(room_id: &str, signer: &AgentSigner) -> RoomResponse {
    let envelope = signer
        .sign_event(room_create_event(
            signer.agent_id(),
            100,
            1,
            RoomCreatePayload::new(HOST, "Room", Visibility::Public, 1, 2),
        ))
        .unwrap();
    RoomResponse {
        id: room_id.to_owned(),
        status: RoomState::Active,
        url: format!("{HOST}/v1/rooms/{room_id}"),
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
        hash: HEAD.to_owned(),
        accepted_at: 100,
        head: Some(crate::discourse::RoomHead {
            seq: 1,
            hash: HEAD.to_owned(),
        }),
        envelope: Some(envelope),
    }
}

fn signal_type(name: &str) -> TypeDef {
    serde_json::from_value(json!({
        "type": name, "kind": "signal", "title": "Signal", "schema": {"type": "object"}
    }))
    .unwrap()
}

/// Signs a room event and wraps it as the record at `seq` after `pre_hash`.
#[allow(clippy::too_many_arguments)]
fn record<P: Serialize>(
    author: &AgentSigner,
    kind: &str,
    nonce: u64,
    base_seq: u64,
    base_hash: &str,
    seq: u64,
    pre_hash: &str,
    payload: P,
) -> ServerRecord {
    let envelope = author
        .sign_event(discourse_event(
            kind,
            author.agent_id(),
            100 + seq as i64,
            nonce,
            "room1",
            base_seq,
            base_hash,
            serde_json::to_value(payload).unwrap(),
        ))
        .unwrap();
    build_server_record(
        "room1",
        seq,
        Some(pre_hash.to_owned()),
        100 + seq as i64,
        envelope,
    )
    .unwrap()
}

fn connector_with_room(active: u8, creator: &AgentSigner) -> LocalConnector {
    let mut connector = LocalConnector::new(signer(active));
    connector.add_host(allowed(HOST));
    connector.accept_room_response(HOST, room_response("room1", creator));
    connector
}

fn members_input(status: Option<MemberStatusFilter>) -> RoomMembersListInput {
    RoomMembersListInput {
        room_id: "room1".to_owned(),
        host: None,
        agent_id: None,
        status,
        role: None,
        include_profiles: false,
        include_recent_activity: false,
        limit: None,
        cursor: None,
    }
}

fn timeline_input() -> RoomTimelineInput {
    RoomTimelineInput {
        room_id: "room1".to_owned(),
        host: None,
        after_seq: None,
        before_seq: None,
        limit: None,
        types: None,
        actors: None,
        unread_only: false,
        mark_read: false,
        refresh: false,
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn standard_tool_definitions_list_the_25_tools() {
    let tools = standard_tool_definitions();
    assert_eq!(tools.len(), 25);
    let names = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    for name in TOOL_NAMES {
        assert!(names.contains(&name), "{name}");
    }
    assert!(!names.contains(&"agent_protocols_host_add"));
    let find = |name: &str| tools.iter().find(|tool| tool.name == name).unwrap();
    assert!(find(TOOL_ROOM_MEMBERS_LIST).annotations.read_only_hint);
    assert!(!find(TOOL_ROOM_TIMELINE).annotations.read_only_hint);
    assert!(!find(TOOL_INBOX_NEXT).annotations.read_only_hint);
    assert_eq!(
        find(TOOL_DELEGATION_CHECK).input_schema["required"],
        json!(["principal_id", "audience"])
    );
    assert!(find(TOOL_DELEGATION_GRANT).input_schema["properties"]
        .get("delegation_service")
        .is_none());
    assert_eq!(
        find(TOOL_DRAFT_COMMIT).input_schema["properties"]["action"]["enum"],
        json!(["revise", "send", "drop"])
    );
    for name in [
        TOOL_PRINCIPAL_RESOLVE,
        TOOL_DELEGATION_CHECK,
        TOOL_DELEGATIONS_LIST,
    ] {
        let tool = find(name);
        assert!(tool.annotations.read_only_hint && tool.annotations.open_world_hint);
    }
    for name in [TOOL_DELEGATION_GRANT, TOOL_DELEGATION_REVOKE] {
        let tool = find(name);
        assert!(!tool.annotations.read_only_hint && !tool.annotations.idempotent_hint);
    }
}

#[test]
fn observed_hosts_do_not_bypass_allowlist_for_signing() {
    let mut connector = LocalConnector::new(signer(1));
    connector.accept_room_response(
        "https://untrusted.example.test",
        room_response("room1", &signer(5)),
    );
    assert!(!connector.state.hosts["https://untrusted.example.test"].allowed);
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
fn request_jwts_and_service_origins_follow_the_allowlist() {
    let mut connector = LocalConnector::new(signer(1));
    let host = "https://delegation.example.test";
    assert!(matches!(
        connector.request_jwt(host),
        Err(SdkError::PermissionDenied)
    ));
    connector.add_host(AgentProtocolsHost {
        profile_service: Some("https://profiles.example.test/v1".to_owned()),
        ..allowed(host)
    });
    assert!(connector.request_jwt(&format!("{host}/")).is_ok());
    connector
        .require_allowed_origin("https://profiles.example.test/v1/profiles")
        .unwrap();
    connector
        .require_allowed_origin("https://delegation.example.test/x")
        .unwrap();
    assert!(connector
        .require_allowed_origin("https://evil.example.test")
        .is_err());
}

#[test]
fn room_views_fall_back_to_room_create_payload_metadata() {
    let mut connector = LocalConnector::new(signer(1));
    let mut room = room_response("room1", &signer(5));
    let payload = &mut room.envelope.as_mut().unwrap().event.payload;
    payload.agenda = Some("Review the proposal".to_owned());
    payload.guidance = Some("Stay concise".to_owned());
    payload.tags = Some(vec!["review".to_owned()]);
    payload.language = Some("en".to_owned());
    room.topic = None;
    room.visibility = None;
    room.start_time = None;
    room.end_time = None;
    connector.observe_room(HOST, room);
    let room = connector.local_room(&key()).unwrap();
    let view = connector.room_state_view(room);
    let summary = connector.summary_for_room(room);
    assert_eq!(view.topic.as_deref(), Some("Room"));
    assert_eq!(view.agenda.as_deref(), Some("Review the proposal"));
    assert_eq!(view.guidance.as_deref(), Some("Stay concise"));
    assert_eq!(view.visibility, Some(Visibility::Public));
    assert_eq!((view.start_time, view.end_time), (Some(1), Some(2)));
    assert_eq!(view.tags, vec!["review"]);
    assert_eq!(view.language.as_deref(), Some("en"));
    assert_eq!(view.creator, Some(signer(5).agent_id()));
    assert_eq!(summary.tags, vec!["review"]);
}

#[test]
fn applies_room_records_into_members_timeline_and_inbox() {
    let speaker = signer(2);
    let mut connector = connector_with_room(1, &signer(5));
    let join = record(
        &speaker,
        event_type::ROOM_JOIN,
        1,
        1,
        HEAD,
        2,
        HEAD,
        RoomJoinPayload {
            role: Role::Speaker,
            perspective: Some("reviewer".to_owned()),
        },
    );
    let join_hash = join.hash.clone();
    connector.apply_record(join).unwrap();
    // room.join is a membership signal: it does not advance the room head.
    assert_eq!(connector.local_room(&key()).unwrap().head_seq, 1);

    let envelope = speaker
        .sign_event(
            discourse_event(
                event_type::MESSAGE_CREATE,
                speaker.agent_id(),
                120,
                2,
                "room1",
                1,
                HEAD,
                MessageCreatePayload::text("please review this"),
            )
            .with_mention(connector.agent_id()),
        )
        .unwrap();
    let message = build_server_record("room1", 3, Some(join_hash), 121, envelope).unwrap();
    connector
        .apply_record(
            serde_json::from_value::<ServerRecord>(serde_json::to_value(message).unwrap()).unwrap(),
        )
        .unwrap();

    let members = connector
        .room_members_list(members_input(Some(MemberStatusFilter::Status(
            RoomMemberStatus::Active,
        ))))
        .unwrap();
    assert_eq!(members["members"].as_array().unwrap().len(), 2);
    let room = connector.local_room(&key()).unwrap();
    assert_eq!(
        room.members[&speaker.agent_id()].perspective.as_deref(),
        Some("reviewer")
    );
    assert_eq!(room.timeline[0].kind, RecordClass::Signal);
    assert_eq!(room.timeline[1].kind, RecordClass::Message);
    assert_eq!(room.timeline[1].summary, "please review this");

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
    // A claim is a lease that expires.
    let entry = connector.state.inbox.values().next().unwrap();
    match entry.state {
        InboxEntryState::Claimed(until) => {
            assert!(until > unix_ms() + INBOX_CLAIM_LEASE_MS - 5_000);
            assert!(inbox_entry_ready(entry, until));
        }
        ref other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn head_bound_writes_hold_on_a_stale_base_before_any_network_call() {
    let speaker = signer(2);
    let mut connector = connector_with_room(1, &signer(5));
    let message = record(
        &speaker,
        event_type::MESSAGE_CREATE,
        1,
        1,
        HEAD,
        2,
        HEAD,
        MessageCreatePayload::text("new context"),
    );
    let head_hash = message.hash.clone();
    connector.apply_record(message).unwrap();

    let result = block_on(connector.submit_room_write(HeldDraftRequest::Message(
        RoomSendMessageInput {
            room_id: "room1".to_owned(),
            host: None,
            content: "answer based on old context".to_owned(),
            content_type: None,
            mentions: Vec::new(),
            references: Vec::new(),
            extra: BTreeMap::new(),
            base_seq: Some(1),
            base_hash: Some(HEAD.to_owned()),
            on_head_mismatch: HeadMismatchPolicy::Hold,
        },
    )))
    .unwrap();
    assert_eq!(result["status"], "held");
    assert_eq!(result["draft"]["kind"], "message");
    assert_eq!(result["draft"]["base_seq"], 1);
    assert_eq!(
        result["draft"]["options"],
        json!(["revise", "send", "drop"])
    );
    assert_eq!(result["changes"].as_array().unwrap().len(), 1);
    // The held result shows every change up to the current head.
    assert_eq!(result["sync"]["presented_seq"], 2);
    assert_eq!(result["sync"]["presented_hash"], head_hash.as_str());

    let draft_id = result["draft"]["id"].as_str().unwrap().to_owned();
    let listed = connector
        .drafts_list(DraftsListInput {
            room_id: Some("room1".to_owned()),
            host: None,
            draft_id: None,
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(listed["drafts"].as_array().unwrap().len(), 1);
    let one = connector
        .drafts_list(DraftsListInput {
            room_id: None,
            host: None,
            draft_id: Some(draft_id.clone()),
            limit: None,
            cursor: None,
        })
        .unwrap();
    assert_eq!(one["changes"].as_array().unwrap().len(), 1);

    let dropped = block_on(connector.draft_commit(DraftCommitInput {
        draft_id,
        action: DraftAction::Drop,
        content: None,
        content_type: None,
        mentions: None,
        references: None,
        extra: None,
        event_type: None,
        payload: None,
        on_head_mismatch: HeadMismatchPolicy::Hold,
    }))
    .unwrap();
    assert_eq!(dropped["status"], "dropped");
    assert!(connector.state.drafts.is_empty());

    // Rejecting instead presents the head and returns the changes.
    let rejected = block_on(connector.submit_room_write(HeldDraftRequest::Message(
        RoomSendMessageInput {
            room_id: "room1".to_owned(),
            host: None,
            content: "again".to_owned(),
            content_type: None,
            mentions: Vec::new(),
            references: Vec::new(),
            extra: BTreeMap::new(),
            base_seq: Some(1),
            base_hash: Some(HEAD.to_owned()),
            on_head_mismatch: HeadMismatchPolicy::Reject,
        },
    )))
    .unwrap();
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["reason"], "room_head_mismatch");
    assert!(connector.state.drafts.is_empty());
}

#[test]
fn freshness_classes_decide_which_records_move_the_head() {
    let speaker = signer(2);
    let moderator = signer(5);
    let mut room = room_response("room1", &moderator);
    room.types.push(signal_type("reaction.create"));
    let mut connector = LocalConnector::new(signer(1));
    connector.add_host(allowed(HOST));
    connector.accept_room_response(HOST, room);

    let signal = record(
        &speaker,
        "reaction.create",
        1,
        1,
        HEAD,
        2,
        HEAD,
        json!({"emoji": "+1"}),
    );
    let signal_hash = signal.hash.clone();
    connector.apply_record(signal).unwrap();
    let sync = connector.sync_state(&key()).unwrap();
    assert_eq!((sync.head_seq, sync.synced_seq, sync.remote_seq), (1, 2, 2));
    assert_eq!(sync.head_hash, HEAD);

    // A head-bound record must name the current head, not the signal.
    let stale = record(
        &speaker,
        event_type::MESSAGE_CREATE,
        2,
        2,
        &signal_hash,
        3,
        &signal_hash,
        MessageCreatePayload::text("x"),
    );
    let error = connector.apply_record(stale).unwrap_err();
    assert!(error.to_string().contains("must match current room head"));

    // A contract write only anchors, but it advances the head.
    let update = record(
        &moderator,
        event_type::ROOM_UPDATE,
        2,
        2,
        &signal_hash,
        3,
        &signal_hash,
        RoomUpdatePayload {
            topic: Some("Sharper topic".to_owned()),
            guidance: Some(String::new()),
            end_time: Some(5000),
            // An all-default policy is still an explicit revision.
            policy: Some(RoomPolicy::default()),
            ..RoomUpdatePayload::default()
        },
    );
    connector.apply_record(update).unwrap();
    let room = connector.local_room(&key()).unwrap();
    assert_eq!(room.head_seq, 3);
    assert_eq!(room.room.topic.as_deref(), Some("Sharper topic"));
    assert_eq!(room.room.guidance, None);
    assert_eq!(room.room.end_time, Some(5000));
    assert_eq!(room.room.policy, Some(RoomPolicy::default()));
    assert_eq!(room.timeline[1].kind, RecordClass::Contract);
    assert!(!event_type_requires_room_head(
        room,
        event_type::ROOM_UPDATE
    ));
    assert!(event_type_requires_room_head(
        room,
        event_type::MESSAGE_CREATE
    ));
    assert!(!event_type_requires_room_head(room, "reaction.create"));
    assert_eq!(connector.pending_inbox_count(Some("room1")), 1);

    // An anchor must match the record it names.
    let bad_anchor = record(
        &speaker,
        "reaction.create",
        3,
        2,
        "not-the-signal",
        4,
        room.synced_hash.as_deref().unwrap(),
        json!({}),
    );
    assert!(connector.apply_record(bad_anchor).is_err());
}

#[test]
fn member_remove_records_project_removal_bans_and_inbox() {
    let moderator = signer(5);
    let mut connector = connector_with_room(1, &moderator);
    let active = signer(1);
    let join = record(
        &active,
        event_type::ROOM_JOIN,
        1,
        1,
        HEAD,
        2,
        HEAD,
        RoomJoinPayload {
            role: Role::Speaker,
            perspective: None,
        },
    );
    let join_hash = join.hash.clone();
    connector.apply_host_record(HOST, join).unwrap();
    let remove = record(
        &moderator,
        event_type::ROOM_MEMBER_REMOVE,
        2,
        1,
        HEAD,
        3,
        &join_hash,
        RoomMemberRemovePayload {
            ban: Some(true),
            reason: Some("spam".to_owned()),
            ..RoomMemberRemovePayload::new(active.agent_id())
        },
    );
    connector.apply_host_record(HOST, remove).unwrap();

    let room = connector.local_room(&key()).unwrap();
    assert_eq!(room.head_seq, 1);
    let member = &room.members[&active.agent_id()];
    assert_eq!(member.status, RoomMemberStatus::Banned);
    assert_eq!(member.left_seq, Some(3));
    let banned = connector
        .room_members_list(members_input(Some(MemberStatusFilter::Status(
            RoomMemberStatus::Banned,
        ))))
        .unwrap();
    assert_eq!(banned["members"].as_array().unwrap().len(), 1);
    let all = connector
        .room_members_list(members_input(Some(MemberStatusFilter::All(
            inputs::AllMarker::All,
        ))))
        .unwrap();
    assert_eq!(all["members"].as_array().unwrap().len(), 2);

    let inbox = connector
        .inbox_next(InboxNextInput {
            room_id: Some("room1".to_owned()),
            kinds: Some(vec!["room.member.removed".to_owned()]),
            limit: None,
            wait_ms: None,
            claim: false,
        })
        .unwrap();
    assert_eq!(inbox["items"][0]["reason"], "member_banned");
}

#[test]
fn an_approving_review_is_the_applicants_membership_event() {
    let moderator = signer(5);
    let mut connector = connector_with_room(1, &moderator);
    let applicant = signer(1);
    let mut request_payload = RoomJoinRequestPayload::new(Role::Speaker);
    request_payload.perspective = Some("skeptic".to_owned());
    let request = applicant
        .sign_event(room_join_request_event(
            applicant.agent_id(),
            100,
            1,
            "room1",
            request_payload,
        ))
        .unwrap();
    let review = record(
        &moderator,
        event_type::ROOM_JOIN_REVIEW,
        2,
        1,
        HEAD,
        2,
        HEAD,
        RoomJoinReviewPayload {
            request,
            decision: JoinDecision::Approve,
            role: Some(Role::Speaker),
            reason: None,
            extra: None,
        },
    );
    connector.apply_record(review).unwrap();
    let room = connector.local_room(&key()).unwrap();
    let member = &room.members[&applicant.agent_id()];
    assert_eq!(
        (member.role, member.status),
        (Role::Speaker, RoomMemberStatus::Active)
    );
    assert_eq!(member.perspective.as_deref(), Some("skeptic"));
    assert_eq!(member.joined_seq, Some(2));
    assert_eq!(room.head_seq, 1);
    let inbox = connector
        .inbox_next(InboxNextInput {
            room_id: None,
            kinds: Some(vec!["room.join.approved".to_owned()]),
            limit: None,
            wait_ms: None,
            claim: false,
        })
        .unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
}

#[test]
fn redacted_records_keep_the_chain_and_type_but_project_nothing() {
    let speaker = signer(2);
    let mut connector = connector_with_room(1, &signer(5));
    let message = record(
        &speaker,
        event_type::MESSAGE_CREATE,
        1,
        1,
        HEAD,
        2,
        HEAD,
        MessageCreatePayload::text("secret"),
    );
    let redacted = redact_server_record(&message).unwrap();
    connector.apply_record(redacted).unwrap();
    let room = connector.local_room(&key()).unwrap();
    assert_eq!(room.head_seq, 2);
    let item = &room.timeline[0];
    assert!(item.redacted);
    assert_eq!(item.summary, "[redacted]");
    assert_eq!(item.event_type, event_type::MESSAGE_CREATE);
    assert_eq!(item.kind, RecordClass::Message);
    assert!(item.actor.is_none() && item.payload.is_none());
    assert_eq!(connector.pending_inbox_count(None), 0);
    let value = serde_json::to_value(item).unwrap();
    assert_eq!(value["redacted"], true);
    assert!(value.get("actor").is_none());
}

#[test]
fn unfiltered_gap_free_reads_advance_the_presented_head() {
    let speaker = signer(2);
    let mut connector = connector_with_room(1, &signer(5));
    // The first state read of a known room presents its head without a sync.
    let state = block_on(connector.room_state(inputs::RoomStateInput {
        room_id: "room1".to_owned(),
        host: None,
        refresh: false,
        subscribe: Some(true),
    }))
    .unwrap();
    assert_eq!(state["sync"]["presented_seq"], 1);
    assert_eq!(state["sync"]["subscribed"], true);
    let first = record(
        &speaker,
        event_type::MESSAGE_CREATE,
        1,
        1,
        HEAD,
        2,
        HEAD,
        MessageCreatePayload::text("one"),
    );
    let first_hash = first.hash.clone();
    connector.apply_record(first).unwrap();
    let second = record(
        &speaker,
        event_type::MESSAGE_CREATE,
        2,
        2,
        &first_hash,
        3,
        &first_hash,
        MessageCreatePayload::text("two"),
    );
    let second_hash = second.hash.clone();
    connector.apply_record(second).unwrap();
    // A filtered read presents nothing.
    let filtered = block_on(connector.room_timeline(RoomTimelineInput {
        types: Some(vec![event_type::MESSAGE_CREATE.to_owned()]),
        ..timeline_input()
    }))
    .unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 2);
    assert_eq!(filtered["sync"]["presented_seq"], 1);
    // A read that starts after the presented head leaves a gap.
    let gap = block_on(connector.room_timeline(RoomTimelineInput {
        after_seq: Some(2),
        ..timeline_input()
    }))
    .unwrap();
    assert_eq!(gap["sync"]["presented_seq"], 1);
    let read = block_on(connector.room_timeline(RoomTimelineInput {
        limit: Some(1),
        mark_read: true,
        ..timeline_input()
    }))
    .unwrap();
    assert_eq!(read["sync"]["presented_seq"], 2);
    assert_eq!(read["unread_count"], 1);
    assert_eq!(read["next_after_seq"], 2);
    let rest = block_on(connector.room_timeline(RoomTimelineInput {
        after_seq: Some(2),
        ..timeline_input()
    }))
    .unwrap();
    assert_eq!(rest["sync"]["presented_seq"], 3);
    assert_eq!(rest["sync"]["presented_hash"], second_hash.as_str());
    // The write base is now the presented head.
    assert_eq!(
        connector.write_base(&key(), None, None).unwrap(),
        (3, second_hash)
    );
    assert!(connector.write_base(&key(), Some(1), None).is_err());
}

#[test]
fn summaries_truncate_to_160_code_points() {
    let long = "界".repeat(200);
    let summary = summarize_payload(
        event_type::MESSAGE_CREATE,
        &json!({"content_type": "text/plain", "content": long}),
    );
    assert_eq!(summary.chars().count(), 160);
    assert!(summary.ends_with('…'));
    assert_eq!(
        summarize_payload(
            "poll.create",
            &json!({"question": "  ", "title": "Pick one"})
        ),
        "Pick one"
    );
    assert_eq!(summarize_payload("custom.kind", &json!({})), "custom.kind");
    assert_eq!(
        summarize_payload(
            event_type::MESSAGE_CREATE,
            &json!({"content_type": "application/json", "content": {"a": 1}})
        ),
        event_type::MESSAGE_CREATE
    );
}

#[test]
fn duplicate_room_ids_across_hosts_require_a_host_input() {
    let creator = signer(5);
    let mut connector = LocalConnector::new(signer(1));
    connector.accept_room_response("https://a.example.test", room_response("room1", &creator));
    connector.accept_room_response("https://b.example.test", room_response("room1", &creator));
    assert!(connector.resolve_room_key(None, "room1").is_err());
    assert_eq!(
        connector
            .resolve_room_key(Some("https://a.example.test/"), "room1")
            .unwrap(),
        ("https://a.example.test".to_owned(), "room1".to_owned())
    );
    let listed = connector
        .room_members_list(RoomMembersListInput {
            host: Some("https://b.example.test".to_owned()),
            ..members_input(None)
        })
        .unwrap();
    assert_eq!(listed["sync"]["host"], "https://b.example.test");
    let missing = connector.room_members_list(RoomMembersListInput {
        host: Some("https://b.example.test".to_owned()),
        agent_id: Some(signer(9).agent_id()),
        ..members_input(None)
    });
    assert!(missing.is_err());
}

#[test]
fn signs_profile_update_with_a_clock_derived_nonce() {
    let mut connector = LocalConnector::new(signer(3));
    let payload = ProfileUpdatePayload::new(connector.agent_id(), "Agent");
    let envelope = connector.sign_profile_update(payload.clone()).unwrap();
    let profile = materialize_profile(&envelope).unwrap();
    assert_eq!(profile.name, "Agent");
    assert!(envelope.event.nonce >= envelope.event.created_at as u64);
    let next = connector.sign_profile_update(payload).unwrap();
    assert!(next.event.nonce > envelope.event.nonce);
}

#[test]
fn resyncs_nonces_only_from_bounded_max_seen_nonce_rejections() {
    let mut connector = LocalConnector::new(signer(3));
    let rejection = |value: &str| SdkError::HttpStatus {
        status: 409,
        code: Some("nonce_not_greater".to_owned()),
        data: None,
        max_seen_nonce: Some(value.to_owned()),
        body: String::new(),
    };
    let far = (unix_ms() as u64 + (1_u64 << 33)).to_string();
    assert!(!connector.resync_nonce(&rejection(&far)));
    let near = (unix_ms() as u64 + 1_000).to_string();
    assert!(connector.resync_nonce(&rejection(&near)));
    let payload = ProfileUpdatePayload::new(connector.agent_id(), "Agent");
    let envelope = connector.sign_profile_update(payload).unwrap();
    assert!(envelope.event.nonce > near.parse::<u64>().unwrap());
    assert!(!connector.resync_nonce(&SdkError::PermissionDenied));
}

#[test]
fn payload_with_references_stores_references_under_extra() {
    let payload =
        payload_with_references(json!({"instruction": "answer"}), &["abc".to_owned()]).unwrap();
    assert_eq!(payload["extra"]["references"][0], "abc");
    assert!(payload_with_references(json!([]), &["abc".to_owned()]).is_err());
}

#[test]
fn pages_carry_a_next_cursor_only_when_more_follow() {
    assert_eq!(
        page(vec![1, 2, 3], None, 2),
        (vec![1, 2], Some("2".to_owned()))
    );
    assert_eq!(page(vec![1, 2, 3], Some("2"), 2), (vec![3], None));
    let _ = TypeKind::Signal;
}
