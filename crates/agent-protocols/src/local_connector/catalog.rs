//! Static local connector catalog: tool and resource names plus the standard
//! tool/list declarations. This module is pure data — it never touches signing
//! keys or room state — so an MCP server can advertise the surface without a
//! live [`super::LocalConnector`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const TOOL_IDENTITY_CURRENT: &str = "agent_protocols_identity_current";
pub const TOOL_HOSTS_LIST: &str = "agent_protocols_hosts_list";
pub const TOOL_ROOMS_SEARCH: &str = "agent_protocols_rooms_search";
pub const TOOL_ROOMS_LIST: &str = "agent_protocols_rooms_list";
pub const TOOL_ROOM_OPEN: &str = "agent_protocols_room_open";
pub const TOOL_ROOM_STATE: &str = "agent_protocols_room_state";
pub const TOOL_ROOM_MEMBERS_LIST: &str = "agent_protocols_room_members_list";
pub const TOOL_ROOM_MEMBER_GET: &str = "agent_protocols_room_member_get";
pub const TOOL_AGENT_STATUS_LIST: &str = "agent_protocols_agent_status_list";
pub const TOOL_AGENT_STATUS_GET: &str = "agent_protocols_agent_status_get";
pub const TOOL_AGENT_STATUS_SET: &str = "agent_protocols_agent_status_set";
pub const TOOL_AGENT_STATUS_CLEAR: &str = "agent_protocols_agent_status_clear";
pub const TOOL_ROOM_TIMELINE: &str = "agent_protocols_room_timeline";
pub const TOOL_ROOM_UNREAD: &str = "agent_protocols_room_unread";
pub const TOOL_ROOM_MARK_READ: &str = "agent_protocols_room_mark_read";
pub const TOOL_INBOX_NEXT: &str = "agent_protocols_inbox_next";
pub const TOOL_INBOX_ACK: &str = "agent_protocols_inbox_ack";
pub const TOOL_DRAFTS_LIST: &str = "agent_protocols_drafts_list";
pub const TOOL_DRAFT_GET: &str = "agent_protocols_draft_get";
pub const TOOL_DRAFT_COMMIT: &str = "agent_protocols_draft_commit";
pub const TOOL_DRAFT_DROP: &str = "agent_protocols_draft_drop";
pub const TOOL_PROFILE_UPDATE: &str = "agent_protocols_profile_update";
pub const TOOL_ROOM_CREATE: &str = "agent_protocols_room_create";
pub const TOOL_ROOM_JOIN: &str = "agent_protocols_room_join";
pub const TOOL_ROOM_JOIN_REQUEST: &str = "agent_protocols_room_join_request";
pub const TOOL_ROOM_JOIN_WHEN_APPROVED: &str = "agent_protocols_room_join_when_approved";
pub const TOOL_ROOM_LEAVE: &str = "agent_protocols_room_leave";
pub const TOOL_ROOM_SEND_MESSAGE: &str = "agent_protocols_room_send_message";
pub const TOOL_ROOM_SUBMIT_EVENT: &str = "agent_protocols_room_submit_event";
pub const TOOL_JOIN_REQUESTS_LIST: &str = "agent_protocols_join_requests_list";
pub const TOOL_JOIN_REQUEST_REVIEW: &str = "agent_protocols_join_request_review";

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
            "Return the active local Agent ID and non-secret connector configuration.",
            true,
            true,
            false,
        ),
        (
            TOOL_HOSTS_LIST,
            "List configured Agent Discourse hosts.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOMS_SEARCH,
            "Search public rooms on an allowed host.",
            true,
            false,
            true,
        ),
        (
            TOOL_ROOMS_LIST,
            "List locally known rooms and unread summaries.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_OPEN,
            "Open a room, refresh local state, and optionally mark it subscribed.",
            false,
            true,
            true,
        ),
        (
            TOOL_ROOM_STATE,
            "Read the local materialized room state.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_MEMBERS_LIST,
            "List materialized room members.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_MEMBER_GET,
            "Read one materialized room member.",
            true,
            true,
            false,
        ),
        (
            TOOL_AGENT_STATUS_LIST,
            "Read current transient agent statuses for a room.",
            true,
            false,
            true,
        ),
        (
            TOOL_AGENT_STATUS_GET,
            "Read one agent's current transient status in a room.",
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
        (
            TOOL_AGENT_STATUS_CLEAR,
            "Clear the active local agent's transient status in a room.",
            false,
            true,
            true,
        ),
        // MCP tool annotations are static declarations from tools/list: a pure
        // read is the degenerate case, so mark_read-capable reads declare
        // read_only_hint: false.
        (
            TOOL_ROOM_TIMELINE,
            "Read simplified timeline items from the local cache.",
            false,
            true,
            false,
        ),
        (
            TOOL_ROOM_UNREAD,
            "Read unread timeline items, optionally marking them read.",
            false,
            true,
            false,
        ),
        (
            TOOL_ROOM_MARK_READ,
            "Mark a room timeline read through a sequence number.",
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
            "List local held drafts that need explicit agent action.",
            true,
            true,
            false,
        ),
        (
            TOOL_DRAFT_GET,
            "Read one local held draft with room changes since it was held.",
            true,
            true,
            false,
        ),
        (
            TOOL_DRAFT_COMMIT,
            "Revise, send, or silence a local held draft.",
            false,
            false,
            true,
        ),
        (
            TOOL_DRAFT_DROP,
            "Drop a local held draft without submitting it.",
            false,
            true,
            false,
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
            "Sign and submit a room.create envelope.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_JOIN,
            "Create a join request when needed or sign and submit room.join.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_LEAVE,
            "Sign and submit room.leave.",
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
            "Sign and submit a room-defined event.",
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
            "Sign and submit room.join.review.",
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
            input_schema: json!({"type": "object"}),
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
