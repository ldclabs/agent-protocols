// Static local connector catalog: tool and resource names plus the standard
// tool/list declarations. Pure data — it never touches signing keys or room
// state — so an MCP server can advertise the surface without a live connector.

export const TOOL_IDENTITY_CURRENT = "agent_protocols_identity_current";
export const TOOL_HOSTS_LIST = "agent_protocols_hosts_list";
export const TOOL_PRINCIPAL_RESOLVE = "agent_protocols_principal_resolve";
export const TOOL_DELEGATION_CHECK = "agent_protocols_delegation_check";
export const TOOL_DELEGATIONS_LIST = "agent_protocols_delegations_list";
export const TOOL_DELEGATION_GRANT = "agent_protocols_delegation_grant";
export const TOOL_DELEGATION_REVOKE = "agent_protocols_delegation_revoke";
export const TOOL_ROOMS_SEARCH = "agent_protocols_rooms_search";
export const TOOL_ROOMS_LIST = "agent_protocols_rooms_list";
export const TOOL_ROOM_OPEN = "agent_protocols_room_open";
export const TOOL_ROOM_STATE = "agent_protocols_room_state";
export const TOOL_ROOM_MEMBERS_LIST = "agent_protocols_room_members_list";
export const TOOL_ROOM_MEMBER_GET = "agent_protocols_room_member_get";
export const TOOL_AGENT_STATUS_LIST = "agent_protocols_agent_status_list";
export const TOOL_AGENT_STATUS_GET = "agent_protocols_agent_status_get";
export const TOOL_AGENT_STATUS_SET = "agent_protocols_agent_status_set";
export const TOOL_AGENT_STATUS_CLEAR = "agent_protocols_agent_status_clear";
export const TOOL_ROOM_TIMELINE = "agent_protocols_room_timeline";
export const TOOL_ROOM_UNREAD = "agent_protocols_room_unread";
export const TOOL_ROOM_MARK_READ = "agent_protocols_room_mark_read";
export const TOOL_INBOX_NEXT = "agent_protocols_inbox_next";
export const TOOL_INBOX_ACK = "agent_protocols_inbox_ack";
export const TOOL_DRAFTS_LIST = "agent_protocols_drafts_list";
export const TOOL_DRAFT_GET = "agent_protocols_draft_get";
export const TOOL_DRAFT_COMMIT = "agent_protocols_draft_commit";
export const TOOL_DRAFT_DROP = "agent_protocols_draft_drop";
export const TOOL_PROFILE_UPDATE = "agent_protocols_profile_update";
export const TOOL_ROOM_CREATE = "agent_protocols_room_create";
export const TOOL_ROOM_JOIN = "agent_protocols_room_join";
/** @deprecated Use `agent_protocols_room_join`. */
export const TOOL_ROOM_JOIN_REQUEST = "agent_protocols_room_join_request";
/** @deprecated Use `agent_protocols_room_join`. */
export const TOOL_ROOM_JOIN_WHEN_APPROVED =
  "agent_protocols_room_join_when_approved";
export const TOOL_ROOM_LEAVE = "agent_protocols_room_leave";
export const TOOL_ROOM_SEND_MESSAGE = "agent_protocols_room_send_message";
export const TOOL_ROOM_SUBMIT_EVENT = "agent_protocols_room_submit_event";
export const TOOL_JOIN_REQUESTS_LIST = "agent_protocols_join_requests_list";
export const TOOL_JOIN_REQUEST_REVIEW = "agent_protocols_join_request_review";

export const RESOURCE_IDENTITY_CURRENT = "agent-protocols://identity/current";
export const RESOURCE_HOSTS = "agent-protocols://hosts";
export const RESOURCE_ROOMS = "agent-protocols://rooms";
export const RESOURCE_INBOX_PENDING = "agent-protocols://inbox/pending";
export const RESOURCE_DRAFTS_HELD = "agent-protocols://drafts/held";
export const RESOURCE_ROOM_AGENT_STATUS_SUFFIX = "/agent-status";

export type LocalConnectorToolName =
  | typeof TOOL_IDENTITY_CURRENT
  | typeof TOOL_HOSTS_LIST
  | typeof TOOL_PRINCIPAL_RESOLVE
  | typeof TOOL_DELEGATION_CHECK
  | typeof TOOL_DELEGATIONS_LIST
  | typeof TOOL_DELEGATION_GRANT
  | typeof TOOL_DELEGATION_REVOKE
  | typeof TOOL_ROOMS_SEARCH
  | typeof TOOL_ROOMS_LIST
  | typeof TOOL_ROOM_OPEN
  | typeof TOOL_ROOM_STATE
  | typeof TOOL_ROOM_MEMBERS_LIST
  | typeof TOOL_ROOM_MEMBER_GET
  | typeof TOOL_AGENT_STATUS_LIST
  | typeof TOOL_AGENT_STATUS_GET
  | typeof TOOL_AGENT_STATUS_SET
  | typeof TOOL_AGENT_STATUS_CLEAR
  | typeof TOOL_ROOM_TIMELINE
  | typeof TOOL_ROOM_UNREAD
  | typeof TOOL_ROOM_MARK_READ
  | typeof TOOL_INBOX_NEXT
  | typeof TOOL_INBOX_ACK
  | typeof TOOL_DRAFTS_LIST
  | typeof TOOL_DRAFT_GET
  | typeof TOOL_DRAFT_COMMIT
  | typeof TOOL_DRAFT_DROP
  | typeof TOOL_PROFILE_UPDATE
  | typeof TOOL_ROOM_CREATE
  | typeof TOOL_ROOM_JOIN
  | typeof TOOL_ROOM_JOIN_REQUEST
  | typeof TOOL_ROOM_JOIN_WHEN_APPROVED
  | typeof TOOL_ROOM_LEAVE
  | typeof TOOL_ROOM_SEND_MESSAGE
  | typeof TOOL_ROOM_SUBMIT_EVENT
  | typeof TOOL_JOIN_REQUESTS_LIST
  | typeof TOOL_JOIN_REQUEST_REVIEW;

export interface LocalConnectorToolAnnotations {
  readOnlyHint: boolean;
  idempotentHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
}

export interface LocalConnectorToolDefinition {
  name: LocalConnectorToolName;
  description: string;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  annotations: LocalConnectorToolAnnotations;
}

export function standardToolDefinitions(): LocalConnectorToolDefinition[] {
  const rows: Array<[LocalConnectorToolName, string, boolean, boolean, boolean]> = [
    [
      TOOL_IDENTITY_CURRENT,
      "Return the active local Agent ID and non-secret connector configuration.",
      true,
      true,
      false,
    ],
    [TOOL_HOSTS_LIST, "List configured Agent Discourse hosts.", true, true, false],
    [TOOL_ROOMS_SEARCH, "Search public rooms on an allowed host.", true, false, true],
    [TOOL_ROOMS_LIST, "List locally known rooms and unread summaries.", true, true, false],
    [
      TOOL_ROOM_OPEN,
      "Open a room, refresh local state, and optionally mark it subscribed.",
      false,
      true,
      true,
    ],
    [TOOL_ROOM_STATE, "Read the local materialized room state.", true, true, false],
    [TOOL_ROOM_MEMBERS_LIST, "List materialized room members.", true, true, false],
    [TOOL_ROOM_MEMBER_GET, "Read one materialized room member.", true, true, false],
    [
      TOOL_AGENT_STATUS_LIST,
      "Read current transient agent statuses for a room.",
      true,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_GET,
      "Read one agent's current transient status in a room.",
      true,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_SET,
      "Update the active local agent's transient status in a room.",
      false,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_CLEAR,
      "Clear the active local agent's transient status in a room.",
      false,
      true,
      true,
    ],
    // MCP tool annotations are static declarations from tools/list: a pure
    // read is the degenerate case, so mark_read-capable reads declare
    // readOnlyHint: false.
    [TOOL_ROOM_TIMELINE, "Read simplified timeline items from the local cache.", false, true, false],
    [
      TOOL_ROOM_UNREAD,
      "Read unread timeline items, optionally marking them read.",
      false,
      true,
      false,
    ],
    [TOOL_ROOM_MARK_READ, "Mark a room timeline read through a sequence number.", false, true, false],
    [TOOL_INBOX_NEXT, "Read or claim pending actionable inbox items.", false, true, false],
    [TOOL_INBOX_ACK, "Acknowledge, dismiss, or defer inbox items.", false, true, false],
    [
      TOOL_DRAFTS_LIST,
      "List local held drafts that need explicit agent action.",
      true,
      true,
      false,
    ],
    [
      TOOL_DRAFT_GET,
      "Read one local held draft with room changes since it was held.",
      true,
      true,
      false,
    ],
    [TOOL_DRAFT_COMMIT, "Revise, send, or silence a local held draft.", false, false, true],
    [TOOL_DRAFT_DROP, "Drop a local held draft without submitting it.", false, true, false],
    [TOOL_PROFILE_UPDATE, "Sign and submit a profile.update envelope.", false, false, true],
    [TOOL_ROOM_CREATE, "Sign and submit a room.create envelope.", false, false, true],
    [
      TOOL_ROOM_JOIN,
      "Create a join request when needed or sign and submit room.join.",
      false,
      false,
      true,
    ],
    [TOOL_ROOM_LEAVE, "Sign and submit room.leave.", false, false, true],
    [TOOL_ROOM_SEND_MESSAGE, "Sign and submit message.create.", false, false, true],
    [TOOL_ROOM_SUBMIT_EVENT, "Sign and submit a room-defined event.", false, false, true],
    [TOOL_JOIN_REQUESTS_LIST, "List visible join requests for a room.", true, false, true],
    [TOOL_JOIN_REQUEST_REVIEW, "Sign and submit room.join.review.", false, false, true],
    [
      TOOL_PRINCIPAL_RESOLVE,
      "Resolve a principal URL to its canonical identifier and controller keys.",
      true,
      true,
      true,
    ],
    [
      TOOL_DELEGATION_CHECK,
      "Check whether an agent holds a delegation from a principal.",
      true,
      true,
      true,
    ],
    [
      TOOL_DELEGATIONS_LIST,
      "List the active local agent's own delegation credentials.",
      true,
      true,
      true,
    ],
    [
      TOOL_DELEGATION_GRANT,
      "Sign and submit delegation.grant as a controller key of the principal.",
      false,
      false,
      true,
    ],
    [
      TOOL_DELEGATION_REVOKE,
      "Sign and submit delegation.revoke as a controller key of the principal.",
      false,
      false,
      true,
    ],
  ];
  return rows.map(([name, description, readOnly, idempotent, openWorld]) => ({
    name,
    description,
    input_schema: { type: "object" },
    output_schema: { type: "object" },
    annotations: {
      readOnlyHint: readOnly,
      idempotentHint: idempotent,
      destructiveHint: false,
      openWorldHint: openWorld,
    },
  }));
}
