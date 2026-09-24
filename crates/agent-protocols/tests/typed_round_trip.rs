//! Typed payloads must re-serialize to exactly the event another SDK signed:
//! an explicit empty array or object stays distinct from an absent field, so
//! the recomputed event hash matches the signature.

use agent_protocols::delegation::{DelegationPayload, PROTOCOL as DELEGATION};
use agent_protocols::discourse::{
    validate_discourse_envelope, validate_room_join_review_payload, validate_room_update_payload,
    MessageCreatePayload, ReasonPayload, RoleUpdatePayload, RoomCreatePayload,
    RoomJoinReviewPayload, RoomMemberRemovePayload, RoomUpdatePayload, TypeDeclaration,
    PROTOCOL as DISCOURSE,
};
use agent_protocols::identity::{verify_envelope, AgentSigner, Envelope, Event};
use agent_protocols::profile::{
    materialize_profile, validate_profile_update, ProfileUpdatePayload, PROTOCOL as PROFILE,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const ROOM: &str = "d8ftedhpqhsusbg001tg";
const BASE: &str = "cm9vbS1jcmVhdGUtcmVjb3JkLWhhc2gtMDAwMDAwMDA";

fn signer() -> AgentSigner {
    AgentSigner::from_seed([91; 32])
}

/// Signs `event` over raw JSON, as an SDK without typed payloads would, then
/// parses the envelope into the typed payload `P`. The typed event must
/// re-serialize to the signed JSON and verify.
fn signed_as<P>(event: Event<Value>) -> Envelope<P>
where
    P: DeserializeOwned + Serialize,
{
    let envelope = signer().sign_event(event).unwrap();
    let signed = serde_json::to_value(&envelope).unwrap();
    let typed: Envelope<P> = serde_json::from_value(signed.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), signed);
    verify_envelope(&typed).unwrap();
    typed
}

fn room_event(kind: &str, payload: Value) -> Event<Value> {
    Event::new(DISCOURSE, kind, signer().agent_id(), 1_000, 1, payload)
        .with_room_id(ROOM)
        .with_room_head(1, BASE)
}

#[test]
fn profile_update_keeps_explicit_empty_arrays_and_objects() {
    let id = signer().agent_id();
    for payload in [
        // The Agent Profile specification's own example shape.
        json!({"id": id, "name": "A", "service_endpoints": [], "delegations": []}),
        json!({
            "id": id,
            "name": "A",
            "capabilities": [],
            "service_endpoints": [
                {"type": "agent-api", "url": "https://agent.example.com/api", "protocols": []}
            ],
            "links": [],
            "delegations": [{
                "principal": {"id": "https://api.al.ink/d9c6a99cne5g00a6scn0", "note": "kept"},
                "scopes": []
            }],
            "extra": {}
        }),
    ] {
        let envelope = signed_as::<ProfileUpdatePayload>(Event::new(
            PROFILE,
            "profile.update",
            id.clone(),
            1_000,
            1,
            payload.clone(),
        ));
        validate_profile_update(&envelope).unwrap();
        // The materialized document keeps the payload's fields as signed.
        let document = serde_json::to_value(materialize_profile(&envelope).unwrap()).unwrap();
        for (field, value) in payload.as_object().unwrap() {
            assert_eq!(&document[field], value, "{field}");
        }
    }
}

#[test]
fn absent_optional_fields_stay_absent() {
    let id = signer().agent_id();
    let envelope = signed_as::<ProfileUpdatePayload>(Event::new(
        PROFILE,
        "profile.update",
        id.clone(),
        1_000,
        1,
        json!({"id": id, "name": "A"}),
    ));
    let document = serde_json::to_value(materialize_profile(&envelope).unwrap()).unwrap();
    for field in [
        "capabilities",
        "service_endpoints",
        "links",
        "delegations",
        "extra",
    ] {
        assert!(document.get(field).is_none(), "{field}");
    }
}

#[test]
fn room_create_and_type_define_keep_empty_type_extensions() {
    let definition = json!({
        "type": "review.finding",
        "kind": "message",
        "title": "Finding",
        "schema": {"type": "object"},
        "roles": ["moderator"],
        "extra": {}
    });
    let import = json!({"use": "adp:reactions/1.0", "overrides": {}});
    let create = Event::new(
        DISCOURSE,
        "room.create",
        signer().agent_id(),
        1_000,
        1,
        json!({
            "host": "https://api.example.com",
            "topic": "Room",
            "visibility": "public",
            "start_time": 1,
            "end_time": 2,
            "tags": [],
            "policy": {"invites": {}, "open_roles": [], "extra": {}},
            "types": [definition, import],
            "extra": {}
        }),
    );
    let envelope = signed_as::<RoomCreatePayload>(create);
    validate_discourse_envelope(&envelope).unwrap();
    for declaration in [definition, import] {
        let envelope = signed_as::<TypeDeclaration>(room_event("type.define", declaration));
        validate_discourse_envelope(&envelope).unwrap();
    }
}

#[test]
fn room_events_keep_empty_references_mentions_and_extra() {
    let message = room_event(
        "message.create",
        json!({"content_type": "text/plain", "content": "hi", "references": [], "extra": {}}),
    )
    .with_mentions(Vec::new());
    validate_discourse_envelope(&signed_as::<MessageCreatePayload>(message)).unwrap();

    let request = signer()
        .sign_event(
            Event::new(
                DISCOURSE,
                "room.join.request",
                signer().agent_id(),
                1_000,
                2,
                json!({"role": "speaker", "extra": {}}),
            )
            .with_room_id(ROOM),
        )
        .unwrap();
    let review = room_event(
        "room.join.review",
        json!({"request": request, "decision": "approve", "role": "speaker", "extra": {}}),
    );
    let review = signed_as::<RoomJoinReviewPayload>(review);
    validate_room_join_review_payload(&review.event.payload, Some(ROOM)).unwrap();

    let member = AgentSigner::from_seed([93; 32]).agent_id();
    let update = signed_as::<RoomUpdatePayload>(room_event(
        "room.update",
        json!({"tags": [], "policy": {"invites": {}, "extra": {}}}),
    ));
    validate_room_update_payload(&update.event.payload).unwrap();
    signed_as::<RoomMemberRemovePayload>(room_event(
        "room.member.remove",
        json!({"member": member, "references": [], "extra": {}}),
    ));
    signed_as::<RoleUpdatePayload>(room_event(
        "room.member.role.update",
        json!({"member": member, "role": "observer", "extra": {}}),
    ));
    signed_as::<ReasonPayload>(room_event(
        "room.leave",
        json!({"references": [], "extra": {}}),
    ));
}

#[test]
fn delegation_grant_keeps_empty_constraints() {
    let grant = Event::new(
        DELEGATION,
        "delegation.grant",
        signer().agent_id(),
        1_000,
        1,
        json!({
            "id": "del_1",
            "principal_id": "https://example.com/p",
            "subject": AgentSigner::from_seed([92; 32]).agent_id(),
            "audiences": ["https://dmsg.net"],
            "scopes": ["message.draft"],
            "constraints": {}
        }),
    );
    signed_as::<DelegationPayload>(grant);
}
