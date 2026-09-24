// Static local connector catalog: tool and resource names plus the standard
// tool/list declarations. Pure data — it never touches signing keys or room
// state — so an MCP server can advertise the surface without a live connector.

export const TOOL_IDENTITY_CURRENT = "agent_protocols_identity_current";
export const TOOL_PRINCIPAL_RESOLVE = "agent_protocols_principal_resolve";
export const TOOL_DELEGATION_CHECK = "agent_protocols_delegation_check";
export const TOOL_DELEGATIONS_LIST = "agent_protocols_delegations_list";
export const TOOL_DELEGATION_GRANT = "agent_protocols_delegation_grant";
export const TOOL_DELEGATION_REVOKE = "agent_protocols_delegation_revoke";
export const TOOL_ROOMS_SEARCH = "agent_protocols_rooms_search";
export const TOOL_ROOMS_LIST = "agent_protocols_rooms_list";
export const TOOL_ROOM_STATE = "agent_protocols_room_state";
export const TOOL_ROOM_MEMBERS_LIST = "agent_protocols_room_members_list";
export const TOOL_AGENT_STATUS_LIST = "agent_protocols_agent_status_list";
export const TOOL_AGENT_STATUS_SET = "agent_protocols_agent_status_set";
export const TOOL_ROOM_TIMELINE = "agent_protocols_room_timeline";
export const TOOL_INBOX_NEXT = "agent_protocols_inbox_next";
export const TOOL_INBOX_ACK = "agent_protocols_inbox_ack";
export const TOOL_DRAFTS_LIST = "agent_protocols_drafts_list";
export const TOOL_DRAFT_COMMIT = "agent_protocols_draft_commit";
export const TOOL_PROFILE_UPDATE = "agent_protocols_profile_update";
export const TOOL_ROOM_CREATE = "agent_protocols_room_create";
export const TOOL_ROOM_JOIN = "agent_protocols_room_join";
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
  | typeof TOOL_PRINCIPAL_RESOLVE
  | typeof TOOL_DELEGATION_CHECK
  | typeof TOOL_DELEGATIONS_LIST
  | typeof TOOL_DELEGATION_GRANT
  | typeof TOOL_DELEGATION_REVOKE
  | typeof TOOL_ROOMS_SEARCH
  | typeof TOOL_ROOMS_LIST
  | typeof TOOL_ROOM_STATE
  | typeof TOOL_ROOM_MEMBERS_LIST
  | typeof TOOL_AGENT_STATUS_LIST
  | typeof TOOL_AGENT_STATUS_SET
  | typeof TOOL_ROOM_TIMELINE
  | typeof TOOL_INBOX_NEXT
  | typeof TOOL_INBOX_ACK
  | typeof TOOL_DRAFTS_LIST
  | typeof TOOL_DRAFT_COMMIT
  | typeof TOOL_PROFILE_UPDATE
  | typeof TOOL_ROOM_CREATE
  | typeof TOOL_ROOM_JOIN
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

const STRING = { type: "string" };
const STRING_SET = { type: "array", minItems: 1, uniqueItems: true, items: STRING };

/** Input schemas for tools whose inputs carry authority-relevant fields. */
const INPUT_SCHEMAS: Partial<Record<LocalConnectorToolName, Record<string, unknown>>> = {
  [TOOL_DELEGATION_CHECK]: {
    type: "object", required: ["principal_id", "audience"],
    properties: { principal_id: STRING, audience: STRING, subject: STRING, id: STRING },
  },
  [TOOL_DELEGATION_GRANT]: {
    type: "object", required: ["id", "principal_id", "subject", "scopes", "audiences"],
    properties: {
      id: STRING, principal_id: STRING, subject: STRING, scopes: STRING_SET, audiences: STRING_SET,
      relationship: STRING, constraints: { type: "object" }, not_before: { type: "integer" }, expires_at: { type: "integer" },
    },
  },
  [TOOL_DELEGATION_REVOKE]: {
    type: "object", required: ["id", "principal_id"],
    properties: { id: STRING, principal_id: STRING, reason: STRING },
  },
  [TOOL_DRAFT_COMMIT]: {
    type: "object", required: ["draft_id", "action"],
    properties: { draft_id: STRING, action: { enum: ["revise", "send", "drop"] } },
  },
};

export function standardToolDefinitions(): LocalConnectorToolDefinition[] {
  const rows: Array<[LocalConnectorToolName, string, boolean, boolean, boolean]> = [
    [
      TOOL_IDENTITY_CURRENT,
      "Return the active local Agent ID, profile services, and the operator host allowlist.",
      true,
      true,
      false,
    ],
    [TOOL_ROOMS_SEARCH, "Search public rooms on an allowed host.", true, false, true],
    [TOOL_ROOMS_LIST, "List locally known rooms and unread summaries.", true, true, false],
    [
      TOOL_ROOM_STATE,
      "Read a room's verified state, opening and syncing it on first use; optionally (un)subscribe.",
      false,
      true,
      true,
    ],
    [TOOL_ROOM_MEMBERS_LIST, "List materialized room members, or one member with recent activity.", true, true, false],
    [
      TOOL_AGENT_STATUS_LIST,
      "Read current transient agent statuses for a room, or one agent's status.",
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
    // MCP tool annotations are static declarations from tools/list: a pure
    // read is the degenerate case, so mark_read-capable reads declare
    // readOnlyHint: false.
    [TOOL_ROOM_TIMELINE, "Read timeline items from the local cache, optionally marking them read.", false, true, false],
    [TOOL_INBOX_NEXT, "Read or claim pending actionable inbox items.", false, true, false],
    [TOOL_INBOX_ACK, "Acknowledge, dismiss, or defer inbox items.", false, true, false],
    [
      TOOL_DRAFTS_LIST,
      "List local held drafts, or read one with the room changes since it was held.",
      true,
      true,
      false,
    ],
    [TOOL_DRAFT_COMMIT, "Revise, send, or drop a local held draft.", false, false, true],
    [TOOL_PROFILE_UPDATE, "Sign and submit a profile.update envelope.", false, false, true],
    [TOOL_ROOM_CREATE, "Sign and submit a room.create envelope bound to the host.", false, false, true],
    [
      TOOL_ROOM_JOIN,
      "Join a room directly when invited or open, otherwise sign and submit a room.join.request.",
      false,
      false,
      true,
    ],
    [TOOL_ROOM_LEAVE, "Sign and submit room.leave.", false, false, true],
    [TOOL_ROOM_SEND_MESSAGE, "Sign and submit message.create.", false, false, true],
    [TOOL_ROOM_SUBMIT_EVENT, "Sign and submit a built-in or room-defined event.", false, false, true],
    [TOOL_JOIN_REQUESTS_LIST, "List visible join requests for a room.", true, false, true],
    [TOOL_JOIN_REQUEST_REVIEW, "Sign and submit room.join.review embedding the signed request.", false, false, true],
    [
      TOOL_PRINCIPAL_RESOLVE,
      "Resolve a principal URL to its canonical identifier and controller keys.",
      true,
      true,
      true,
    ],
    [
      TOOL_DELEGATION_CHECK,
      "Find and verify an agent's delegations from a principal for a relying application.",
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
    input_schema: INPUT_SCHEMAS[name] ?? { type: "object" },
    output_schema: { type: "object" },
    annotations: {
      readOnlyHint: readOnly,
      idempotentHint: idempotent,
      destructiveHint: false,
      openWorldHint: openWorld,
    },
  }));
}
