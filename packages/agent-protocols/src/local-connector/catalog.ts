import { Validator, type Schema } from "@cfworker/json-schema";
import { protocolError } from "../errors.js";
// Static local connector catalog: tool and resource names plus the standard
// tool/list declarations. Pure data — it never touches signing keys or room
// state — so an MCP server can advertise the surface without a live connector.

import { CONNECTOR_CATALOG } from "./catalog-data.js";

export const TOOL_SERVICES_LIST = "agent_protocols_services_list";
export const TOOL_PROFILES_GET = "agent_protocols_profiles_get";
export const TOOL_PROFILE_HISTORY = "agent_protocols_profile_history";
export const TOOL_DELEGATION_HISTORY = "agent_protocols_delegation_history";
export const TOOL_MAIL_RESOLVE = "agent_protocols_mail_resolve";
export const TOOL_SCHEMA_GET = "agent_protocols_schema_get";
export const TOOL_ROOM_ARCHIVE = "agent_protocols_room_archive";
export const TOOL_ROOM_WATCH = "agent_protocols_room_watch";

export const TOOL_IDENTITY_CURRENT = "agent_protocols_identity_current";
export const TOOL_PRINCIPAL_RESOLVE = "agent_protocols_principal_resolve";
export const TOOL_DELEGATION_CHECK = "agent_protocols_delegation_check";
export const TOOL_DELEGATIONS_LIST = "agent_protocols_delegations_list";
export const TOOL_DELEGATION_GRANT = "agent_protocols_delegation_grant";
export const TOOL_DELEGATION_REVOKE = "agent_protocols_delegation_revoke";
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
export const TOOL_ROOM_SEND_MESSAGE = "agent_protocols_room_send_message";
export const TOOL_ROOM_SUBMIT_EVENT = "agent_protocols_room_submit_event";
export const TOOL_JOIN_REQUESTS_LIST = "agent_protocols_join_requests_list";
export const TOOL_JOIN_REQUEST_REVIEW = "agent_protocols_join_request_review";
export const TOOL_MAIL_MAILBOXES_LIST = "agent_protocols_mail_mailboxes_list";
export const TOOL_MAIL_MAILBOX_PUBLISH = "agent_protocols_mail_mailbox_publish";
export const TOOL_MAIL_SEND = "agent_protocols_mail_send";
export const TOOL_MAIL_SYNC = "agent_protocols_mail_sync";
export const TOOL_MAIL_LIST = "agent_protocols_mail_list";
export const TOOL_KNOWLEDGE_SUBMIT = "agent_protocols_knowledge_submit";
export const TOOL_KNOWLEDGE_QUERY = "agent_protocols_knowledge_query";
export const TOOL_KNOWLEDGE_GET = "agent_protocols_knowledge_get";
export const TOOL_KNOWLEDGE_SEARCH = "agent_protocols_knowledge_search";
export const TOOL_KNOWLEDGE_STATUS = "agent_protocols_knowledge_status";

export const RESOURCE_IDENTITY_CURRENT = "agent-protocols://identity/current";
export const RESOURCE_HOSTS = "agent-protocols://hosts";
export const RESOURCE_ROOMS = "agent-protocols://rooms";
export const RESOURCE_INBOX_PENDING = "agent-protocols://inbox/pending";
export const RESOURCE_DRAFTS_HELD = "agent-protocols://drafts/held";
export const RESOURCE_MAIL_MAILBOXES = "agent-protocols://mail/mailboxes";
export const RESOURCE_MAIL_MESSAGES = "agent-protocols://mail/messages";
export const RESOURCE_ROOM_AGENT_STATUS_SUFFIX = "/agent-status";

export type LocalConnectorToolName =
  | typeof TOOL_SERVICES_LIST
  | typeof TOOL_PROFILES_GET
  | typeof TOOL_PROFILE_HISTORY
  | typeof TOOL_DELEGATION_HISTORY
  | typeof TOOL_MAIL_RESOLVE
  | typeof TOOL_SCHEMA_GET
  | typeof TOOL_ROOM_ARCHIVE
  | typeof TOOL_ROOM_WATCH
  | typeof TOOL_IDENTITY_CURRENT
  | typeof TOOL_PRINCIPAL_RESOLVE
  | typeof TOOL_DELEGATION_CHECK
  | typeof TOOL_DELEGATIONS_LIST
  | typeof TOOL_DELEGATION_GRANT
  | typeof TOOL_DELEGATION_REVOKE
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
  | typeof TOOL_ROOM_SEND_MESSAGE
  | typeof TOOL_ROOM_SUBMIT_EVENT
  | typeof TOOL_JOIN_REQUESTS_LIST
  | typeof TOOL_JOIN_REQUEST_REVIEW
  | typeof TOOL_MAIL_MAILBOXES_LIST
  | typeof TOOL_MAIL_MAILBOX_PUBLISH
  | typeof TOOL_MAIL_SEND
  | typeof TOOL_MAIL_SYNC
  | typeof TOOL_MAIL_LIST
  | typeof TOOL_KNOWLEDGE_SUBMIT
  | typeof TOOL_KNOWLEDGE_QUERY
  | typeof TOOL_KNOWLEDGE_GET
  | typeof TOOL_KNOWLEDGE_SEARCH
  | typeof TOOL_KNOWLEDGE_STATUS;

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

/** A fresh copy: transport adapters may enrich descriptions without mutating the catalog. */
export function standardToolDefinitions(): LocalConnectorToolDefinition[] {
  return structuredClone(CONNECTOR_CATALOG.tools).map((t) => ({
    name: t.name as LocalConnectorToolName,
    description: t.description,
    input_schema: t.inputSchema,
    output_schema: t.outputSchema,
    annotations: t.annotations,
  }));
}

const INPUT_VALIDATORS = new Map<string, Validator>();
/** Validate before networking/signing and keep field locations in machine-readable errors. */
export function validateToolInput(name: string, input: unknown): void {
  const tool = CONNECTOR_CATALOG.tools.find((t) => t.name === name);
  if (!tool) return;
  let validator = INPUT_VALIDATORS.get(name);
  if (!validator) {
    const schema = structuredClone(tool.inputSchema) as unknown as Schema;
    // Knowledge validates the exact type-specific payload below, preserving invalid_event paths.
    if (name === TOOL_KNOWLEDGE_SUBMIT) schema.properties!.payload = {};
    validator = new Validator(schema, "2020-12", false);
    INPUT_VALIDATORS.set(name, validator);
  }
  const result = validator.validate(input);
  if (!result.valid) {
    const payload =
      name === TOOL_KNOWLEDGE_SUBMIT &&
      result.errors.every((e) => e.instanceLocation.startsWith("#/payload"));
    const errors = result.errors
      .slice(0, 16)
      .map((e) => ({
        path: e.instanceLocation.replace(payload ? /^#\/payload/ : /^#/, ""),
        message: e.error,
      }));
    throw protocolError(
      payload ? "invalid_event" : "invalid_payload",
      errors.map((e) => `${e.path}: ${e.message}`).join("; "),
      { errors },
    );
  }
}

/** Keep returned schemas self-contained without repeating unrelated protocol definitions. */
export function payloadSchema(
  schema: Record<string, unknown>,
  definition: string,
): Record<string, unknown> {
  const source = schema.$defs as Record<string, unknown>;
  const definitions: Record<string, unknown> = {};
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== "object") return;
    const node = value as Record<string, unknown>;
    if (typeof node.$ref === "string" && node.$ref.startsWith("#/$defs/")) {
      const name = node.$ref.slice(8);
      if (!(name in definitions)) {
        definitions[name] = source[name];
        visit(source[name]);
      }
    }
    Object.values(node).forEach(visit);
  };
  const root = { $ref: `#/$defs/${definition}` };
  visit(root);
  return { ...root, $defs: definitions };
}
