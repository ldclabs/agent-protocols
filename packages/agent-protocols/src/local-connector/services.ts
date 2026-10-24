// Pure helpers of the Mail and Knowledge tools: result views, inbox items,
// and error classification. Internal, like projection.ts — used by the engine
// and absent from the connector's public interface.

import { base64UrlEncode } from "../encoding.js";
import { AgentProtocolError } from "../errors.js";
import { HttpResponseError } from "../http-client.js";
import { validateOrigin } from "../identity.js";
import type { KnowledgeRecord } from "../knowledge.js";
import {
  decodeMailBytes,
  formatMailAddress,
  mailCanonicalBytes,
  validateMailboxCard,
  type MailboxCard,
  type MailMessagePayload,
} from "../mail.js";

import { TOOL_MAIL_LIST } from "./catalog.js";
import { invalidPayload } from "./internal.js";
import type { StoredMailMessage } from "./state.js";
import {
  SUMMARY_MAX_CHARS,
  truncate,
  type InboxItem,
  type KnowledgeItem,
  type MailboxView,
  type MailMessageView,
  type RouteError,
} from "./views.js";

const MAX_ROUTES = 8;

/** The error code a tool result reports: the Agent Protocol code, or `network_error` when the request never completed. */
export function errorCode(error: unknown): string {
  if (error instanceof AgentProtocolError) return error.code;
  if (error instanceof HttpResponseError)
    return error.code ?? "invalid_request";
  return "network_error";
}

/** Network failures, `rate_limited`, and 5xx statuses are worth retrying. */
export function isTransient(error: unknown): boolean {
  if (error instanceof HttpResponseError)
    return (
      error.status >= 500 ||
      error.status === 429 ||
      error.code === "rate_limited"
    );
  return !(error instanceof AgentProtocolError);
}

export function routeError(route: string, error: unknown): RouteError {
  return {
    route,
    code: errorCode(error),
    message: error instanceof Error ? error.message : String(error),
  };
}

export function errorJson(error: unknown): Record<string, unknown> {
  const data =
    error instanceof AgentProtocolError || error instanceof HttpResponseError
      ? error.data
      : undefined;
  return {
    code: errorCode(error),
    message: error instanceof Error ? error.message : String(error),
    ...(data === undefined ? {} : { data }),
  };
}

export function checkedRoutes(routes: unknown): string[] {
  if (!Array.isArray(routes) || routes.length > MAX_ROUTES) {
    throw invalidPayload("a card lists at most 8 routes");
  }
  const checked: string[] = [];
  for (const route of routes) {
    validateOrigin(route);
    if (checked.includes(route)) throw invalidPayload("duplicate route");
    checked.push(route);
  }
  return checked;
}

export function isQueued(stored: StoredMailMessage): boolean {
  return stored.direction === "sent" && stored.delivery?.status === "queued";
}

export function isUnread(stored: StoredMailMessage): boolean {
  return stored.direction === "received" && !stored.read;
}

export function sameMessage(
  a: MailMessagePayload,
  b: MailMessagePayload,
): boolean {
  return (
    base64UrlEncode(mailCanonicalBytes(a)) ===
    base64UrlEncode(mailCanonicalBytes(b))
  );
}

export function mailboxView(
  mailboxId: string,
  card: MailboxCard,
  now: number,
  unreadCount: number,
): MailboxView {
  const payload = card.event.payload;
  return {
    key_available: false,
    pending_routes: [],
    mailbox_id: mailboxId,
    address: formatMailAddress(card.event.actor, mailboxId, payload.routes),
    routes: [...payload.routes],
    card_hash: card.hash,
    created_at: card.event.created_at,
    expires_at: payload.expires_at,
    receive_until: payload.receive_until,
    max_packet_bytes: payload.max_packet_bytes,
    status:
      payload.routes.length === 0
        ? "closed"
        : now >= payload.expires_at
          ? "expired"
          : "open",
    unread_count: unreadCount,
  };
}

function replyAddress(card: unknown): string | undefined {
  try {
    validateMailboxCard(card);
    const payload = card.event.payload;
    return formatMailAddress(
      card.event.actor,
      payload.mailbox_id,
      payload.routes,
    );
  } catch {
    return undefined;
  }
}

export function mailMessageView(
  stored: StoredMailMessage,
  includeData: boolean,
): MailMessageView {
  const message = stored.message;
  const parts = message.parts.map((part) => {
    const bytes = decodeMailBytes(part.data);
    const text = part.media_type.startsWith("text/")
      ? new TextDecoder().decode(bytes)
      : undefined;
    return {
      media_type: part.media_type,
      ...(part.name === undefined ? {} : { name: part.name }),
      size: bytes.length,
      ...(text === undefined ? {} : { text }),
      ...(includeData && text === undefined ? { data: part.data } : {}),
    };
  });
  const reply =
    message.reply_card === undefined
      ? undefined
      : replyAddress(message.reply_card);
  return {
    direction: stored.direction,
    message_id: message.message_id,
    thread_id: message.thread_id,
    from: message.from,
    to: message.to,
    mailbox_id: stored.mailbox_id,
    ...(message.subject === undefined ? {} : { subject: message.subject }),
    created_at: message.created_at,
    expires_at: message.expires_at,
    ...(stored.received_at === undefined
      ? {}
      : { received_at: stored.received_at }),
    ...(message.in_reply_to === undefined
      ? {}
      : { in_reply_to: message.in_reply_to }),
    ...(reply === undefined ? {} : { reply_address: reply }),
    parts,
    ...(stored.direction === "received" ? { read: stored.read } : {}),
    ...(stored.delivery === undefined ? {} : { delivery: stored.delivery }),
  };
}

export function mailInboxItem(
  message: MailMessagePayload,
  now: number,
): InboxItem {
  const textPart = message.parts.find((part) =>
    part.media_type.startsWith("text/"),
  );
  const text =
    textPart === undefined
      ? undefined
      : new TextDecoder().decode(decodeMailBytes(textPart.data));
  const candidate = message.subject ?? text;
  const summary =
    candidate !== undefined && candidate.trim() !== ""
      ? truncate(candidate, SUMMARY_MAX_CHARS)
      : "mail";
  return {
    id: `mail.received:${message.from}:${message.message_id}`,
    kind: "mail.received",
    priority: "normal",
    actor: message.from,
    created_at: now,
    requires_response: false,
    reason: "received",
    suggested_tools: [TOOL_MAIL_LIST],
    message: {
      summary,
      message_id: message.message_id,
      thread_id: message.thread_id,
    },
  };
}

/** Flattens a verified acceptance record. */
export function knowledgeItem(record: KnowledgeRecord): KnowledgeItem {
  const event = record.envelope.event;
  return {
    id: record.envelope.hash,
    type: event.type,
    actor: event.actor,
    created_at: event.created_at,
    seq: record.seq,
    accepted_at: record.accepted_at,
    payload: event.payload,
  };
}

/** Adds the service's `service`, `checkpoint`, and `as_of` scope to a result. */
export function scoped<T extends Record<string, unknown>>(
  response: { service: string; checkpoint: number; as_of: number },
  result: T,
): T & { service: string; checkpoint: number; as_of: number } {
  return {
    ...result,
    service: response.service,
    checkpoint: response.checkpoint,
    as_of: response.as_of,
  };
}
