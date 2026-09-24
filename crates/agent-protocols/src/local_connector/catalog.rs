//! Static local connector catalog: tool and resource names plus the standard
//! tool/list declarations. This module is pure data — it never touches signing
//! keys or room state — so an MCP server can advertise the surface without a
//! live [`super::LocalConnector`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const TOOL_IDENTITY_CURRENT: &str = "agent_protocols_identity_current";
pub const TOOL_PRINCIPAL_RESOLVE: &str = "agent_protocols_principal_resolve";
pub const TOOL_DELEGATION_CHECK: &str = "agent_protocols_delegation_check";
pub const TOOL_DELEGATIONS_LIST: &str = "agent_protocols_delegations_list";
pub const TOOL_DELEGATION_GRANT: &str = "agent_protocols_delegation_grant";
pub const TOOL_DELEGATION_REVOKE: &str = "agent_protocols_delegation_revoke";
pub const TOOL_ROOMS_LIST: &str = "agent_protocols_rooms_list";
pub const TOOL_ROOM_STATE: &str = "agent_protocols_room_state";
pub const TOOL_ROOM_MEMBERS_LIST: &str = "agent_protocols_room_members_list";
pub const TOOL_AGENT_STATUS_LIST: &str = "agent_protocols_agent_status_list";
pub const TOOL_AGENT_STATUS_SET: &str = "agent_protocols_agent_status_set";
pub const TOOL_ROOM_TIMELINE: &str = "agent_protocols_room_timeline";
pub const TOOL_INBOX_NEXT: &str = "agent_protocols_inbox_next";
pub const TOOL_INBOX_ACK: &str = "agent_protocols_inbox_ack";
pub const TOOL_DRAFTS_LIST: &str = "agent_protocols_drafts_list";
pub const TOOL_DRAFT_COMMIT: &str = "agent_protocols_draft_commit";
pub const TOOL_PROFILE_UPDATE: &str = "agent_protocols_profile_update";
pub const TOOL_ROOM_CREATE: &str = "agent_protocols_room_create";
pub const TOOL_ROOM_JOIN: &str = "agent_protocols_room_join";
pub const TOOL_ROOM_SEND_MESSAGE: &str = "agent_protocols_room_send_message";
pub const TOOL_ROOM_SUBMIT_EVENT: &str = "agent_protocols_room_submit_event";
pub const TOOL_JOIN_REQUESTS_LIST: &str = "agent_protocols_join_requests_list";
pub const TOOL_JOIN_REQUEST_REVIEW: &str = "agent_protocols_join_request_review";

/// Every standard tool name, in `tools/list` order.
pub const TOOL_NAMES: [&str; 23] = [
    TOOL_IDENTITY_CURRENT,
    TOOL_PRINCIPAL_RESOLVE,
    TOOL_DELEGATION_CHECK,
    TOOL_DELEGATIONS_LIST,
    TOOL_DELEGATION_GRANT,
    TOOL_DELEGATION_REVOKE,
    TOOL_ROOMS_LIST,
    TOOL_ROOM_STATE,
    TOOL_ROOM_MEMBERS_LIST,
    TOOL_AGENT_STATUS_LIST,
    TOOL_AGENT_STATUS_SET,
    TOOL_ROOM_TIMELINE,
    TOOL_INBOX_NEXT,
    TOOL_INBOX_ACK,
    TOOL_DRAFTS_LIST,
    TOOL_DRAFT_COMMIT,
    TOOL_PROFILE_UPDATE,
    TOOL_ROOM_CREATE,
    TOOL_ROOM_JOIN,
    TOOL_ROOM_SEND_MESSAGE,
    TOOL_ROOM_SUBMIT_EVENT,
    TOOL_JOIN_REQUESTS_LIST,
    TOOL_JOIN_REQUEST_REVIEW,
];

pub const RESOURCE_IDENTITY_CURRENT: &str = "agent-protocols://identity/current";
pub const RESOURCE_HOSTS: &str = "agent-protocols://hosts";
pub const RESOURCE_ROOMS: &str = "agent-protocols://rooms";
pub const RESOURCE_INBOX_PENDING: &str = "agent-protocols://inbox/pending";
pub const RESOURCE_DRAFTS_HELD: &str = "agent-protocols://drafts/held";
pub const RESOURCE_ROOM_AGENT_STATUS_SUFFIX: &str = "/agent-status";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalConnectorToolAnnotations {
    pub read_only_hint: bool,
    pub idempotent_hint: bool,
    pub destructive_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LocalConnectorToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub annotations: LocalConnectorToolAnnotations,
}

pub fn standard_tool_definitions() -> Vec<LocalConnectorToolDefinition> {
    [
        (
            TOOL_IDENTITY_CURRENT,
            "Return the active local Agent ID, profile services, and the operator host allowlist.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOMS_LIST,
            "List locally known rooms with unread summaries, or search an allowed host's public rooms.",
            true,
            true,
            true,
        ),
        (
            TOOL_ROOM_STATE,
            "Read a room's verified state, opening and syncing it on first use; optionally (un)subscribe.",
            false,
            true,
            true,
        ),
        (
            TOOL_ROOM_MEMBERS_LIST,
            "List materialized room members, or one member with recent activity.",
            true,
            true,
            false,
        ),
        (
            TOOL_AGENT_STATUS_LIST,
            "Read current transient agent statuses for a room, or one agent's status.",
            true,
            false,
            true,
        ),
        (
            TOOL_AGENT_STATUS_SET,
            "Update the active local agent's transient status in a room.",
            false,
            false,
            true,
        ),
        // MCP tool annotations are static declarations from tools/list: a pure
        // read is the degenerate case, so mark_read-capable reads declare
        // read_only_hint: false.
        (
            TOOL_ROOM_TIMELINE,
            "Read timeline items from the local cache, optionally marking them read.",
            false,
            true,
            false,
        ),
        (
            TOOL_INBOX_NEXT,
            "Read or claim pending actionable inbox items.",
            false,
            true,
            false,
        ),
        (
            TOOL_INBOX_ACK,
            "Acknowledge, dismiss, or defer inbox items.",
            false,
            true,
            false,
        ),
        (
            TOOL_DRAFTS_LIST,
            "List local held drafts, or read one with the room changes since it was held.",
            true,
            true,
            false,
        ),
        (
            TOOL_DRAFT_COMMIT,
            "Revise, send, or drop a local held draft.",
            false,
            false,
            true,
        ),
        (
            TOOL_PROFILE_UPDATE,
            "Sign and submit a profile.update envelope.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_CREATE,
            "Sign and submit a room.create envelope bound to the host.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_JOIN,
            "Join a room directly when invited or open, otherwise sign and submit a room.join.request.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_SEND_MESSAGE,
            "Sign and submit message.create.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_SUBMIT_EVENT,
            "Sign and submit a built-in event without a dedicated tool, such as room.leave, or a room-defined event.",
            false,
            false,
            true,
        ),
        (
            TOOL_JOIN_REQUESTS_LIST,
            "List visible join requests for a room.",
            true,
            false,
            true,
        ),
        (
            TOOL_JOIN_REQUEST_REVIEW,
            "Sign and submit room.join.review embedding the signed request.",
            false,
            false,
            true,
        ),
        (
            TOOL_PRINCIPAL_RESOLVE,
            "Resolve a principal URL to its canonical identifier and controller keys.",
            true,
            true,
            true,
        ),
        (
            TOOL_DELEGATION_CHECK,
            "Find and verify an agent's delegations from a principal for a relying party.",
            true,
            true,
            true,
        ),
        (
            TOOL_DELEGATIONS_LIST,
            "List the active local agent's own delegation credentials.",
            true,
            true,
            true,
        ),
        (
            TOOL_DELEGATION_GRANT,
            "Sign and submit delegation.grant as a controller key of the principal.",
            false,
            false,
            true,
        ),
        (
            TOOL_DELEGATION_REVOKE,
            "Sign and submit delegation.revoke as a controller key of the principal.",
            false,
            false,
            true,
        ),
    ]
    .into_iter()
    .map(
        |(name, description, read_only, idempotent, open_world)| LocalConnectorToolDefinition {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: input_schema(name),
            output_schema: json!({"type": "object"}),
            annotations: LocalConnectorToolAnnotations {
                read_only_hint: read_only,
                idempotent_hint: idempotent,
                destructive_hint: false,
                open_world_hint: open_world,
            },
        },
    )
    .collect()
}

/// Input schemas for tools whose inputs carry authority-relevant fields.
fn input_schema(name: &str) -> Value {
    let string = json!({"type": "string"});
    let string_set =
        json!({"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}});
    match name {
        TOOL_DELEGATION_CHECK => json!({
            "type": "object", "required": ["principal_id", "audience"],
            "properties": {"principal_id": string, "audience": string, "subject": string, "id": string}
        }),
        TOOL_DELEGATION_GRANT => json!({
            "type": "object", "required": ["id", "principal_id", "subject", "scopes", "audiences"],
            "properties": {
                "id": string, "principal_id": string, "subject": string, "scopes": string_set, "audiences": string_set,
                "relationship": string, "constraints": {"type": "object"}, "not_before": {"type": "integer"}, "expires_at": {"type": "integer"}
            }
        }),
        TOOL_DELEGATION_REVOKE => json!({
            "type": "object", "required": ["id", "principal_id"],
            "properties": {"id": string, "principal_id": string, "reason": string}
        }),
        TOOL_ROOMS_LIST => json!({
            "type": "object",
            "properties": {"scope": {"enum": ["known", "public"]}, "host": string}
        }),
        TOOL_DRAFT_COMMIT => json!({
            "type": "object", "required": ["draft_id", "action"],
            "properties": {"draft_id": string, "action": {"enum": ["revise", "send", "drop"]}}
        }),
        _ => json!({"type": "object"}),
    }
}
