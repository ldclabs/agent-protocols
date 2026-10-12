// The local connector's Mail and Knowledge tools against the SDK's own
// reference relay and Knowledge store, behind an injected fetch. Two
// connectors play sender and recipient.

import assert from "node:assert/strict";
import test from "node:test";

import { AgentProtocolError } from "./errors.js";
import { AgentSigner } from "./identity.js";
import {
  KnowledgeStore,
  knowledgeQueryMatches,
  knowledgeTextMatches,
  parseKnowledgeQuery,
  type KnowledgeEnvelope,
  type KnowledgeSearchRequest,
} from "./knowledge.js";
import {
  LOCAL_CONNECTOR_SNAPSHOT_VERSION,
  LocalConnector,
  TOOL_INBOX_NEXT,
  TOOL_KNOWLEDGE_GET,
  TOOL_KNOWLEDGE_QUERY,
  TOOL_KNOWLEDGE_SEARCH,
  TOOL_KNOWLEDGE_STATUS,
  TOOL_KNOWLEDGE_SUBMIT,
  TOOL_MAIL_LIST,
  TOOL_MAIL_MAILBOXES_LIST,
  TOOL_MAIL_MAILBOX_PUBLISH,
  TOOL_MAIL_SEND,
  TOOL_MAIL_SYNC,
} from "./local-connector.js";
import { MailRelayStore, type MailboxCard, type MailPacket } from "./mail.js";

const ORIGIN = "https://services.example.test";

const STATUS: Record<string, number> = {
  mailbox_unavailable: 404,
  not_found: 404,
  stale_card: 409,
  mailbox_conflict: 409,
  missing_dependency: 409,
  nonce_not_greater: 409,
  packet_expired: 410,
  permission_denied: 403,
  invalid_token: 401,
  payload_too_large: 413,
  rate_limited: 429,
};

/** One origin serving both a Mail relay and a Knowledge service. */
function services() {
  const relay = new MailRelayStore(ORIGIN);
  const knowledge = new KnowledgeStore({ service: ORIGIN });
  const state = { failingDeliveries: 0 };
  const json = (
    status: number,
    value: unknown,
    headers: Record<string, string> = {},
  ) =>
    new Response(status === 204 ? null : JSON.stringify(value), {
      status,
      headers: { "content-type": "application/json", ...headers },
    });
  const route = (
    method: string,
    url: URL,
    body: unknown,
    jwt: string,
  ): Response => {
    const path = url.pathname.split("/").filter(Boolean);
    const at = (...parts: string[]) =>
      parts.length === path.length &&
      parts.every((part, i) => part === "*" || part === path[i]);
    if (method === "POST" && at("v1", "mailboxes"))
      return json(200, relay.publish(body as MailboxCard));
    if (method === "GET" && at("v1", "mailboxes", "*", "card"))
      return json(200, relay.card(path[2]));
    if (method === "POST" && at("v1", "mailboxes", "*", "packets")) {
      if (state.failingDeliveries > 0) {
        state.failingDeliveries -= 1;
        return json(503, {
          error: { code: "service_unavailable", message: "relay restarting" },
        });
      }
      return json(202, relay.deliver(path[2], body as MailPacket));
    }
    if (method === "GET" && at("v1", "mailboxes", "*", "packets")) {
      return json(
        200,
        relay.list(path[2], jwt, {
          limit: Number(url.searchParams.get("limit") ?? 100),
          cursor: url.searchParams.get("cursor") ?? undefined,
        }),
      );
    }
    if (method === "DELETE" && at("v1", "mailboxes", "*", "packets", "*")) {
      relay.delete(path[2], path[4], jwt);
      return json(204, null);
    }
    if (method === "GET" && at(".well-known", "agent-knowledge")) {
      return json(200, {
        protocol: "agent-knowledge/1.0",
        service: ORIGIN,
        endpoints: {
          events: `${ORIGIN}/v1/knowledge/events`,
          query: `${ORIGIN}/v1/knowledge/query`,
          batch: `${ORIGIN}/v1/knowledge/batch`,
          search: `${ORIGIN}/v1/knowledge/search`,
        },
        features: ["ranked-search"],
        search_modes: ["lexical"],
      });
    }
    if (method === "POST" && at("v1", "knowledge", "events"))
      return json(200, knowledge.submit(body as KnowledgeEnvelope));
    if (method === "GET" && at("v1", "knowledge", "query"))
      return json(200, knowledge.query(parseKnowledgeQuery(url.searchParams)));
    if (method === "POST" && at("v1", "knowledge", "batch"))
      return json(200, knowledge.batch(body as { hashes: string[] }));
    if (method === "POST" && at("v1", "knowledge", "search")) {
      const request = body as KnowledgeSearchRequest;
      // Every lexical match, so the page may claim exhaustive coverage.
      const candidates = [...knowledge.knownEnvelopes()]
        .filter(
          ([, envelope]) =>
            knowledgeQueryMatches(envelope, request.filters ?? {}) &&
            knowledgeTextMatches(envelope, request.text),
        )
        .map(([id]) => id);
      return json(
        200,
        knowledge.search(
          request,
          {
            candidates,
            ranking: { mode: "lexical", id: "test-1" },
            coverage: { exhaustive: true, reasons: [] },
          },
          ["lexical"],
        ),
      );
    }
    return json(404, { error: { code: "not_found", message: "no route" } });
  };
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = new URL(String(input));
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const jwt = (headers.authorization ?? "").replace(/^Bearer /, "");
    const body =
      typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    try {
      return route(init?.method ?? "GET", url, body, jwt);
    } catch (error) {
      if (!(error instanceof AgentProtocolError)) throw error;
      const nonce =
        error.code === "nonce_not_greater"
          ? { "Max-Seen-Nonce": String(error.data?.max_nonce) }
          : {};
      return json(
        STATUS[error.code] ?? 400,
        {
          error: {
            code: error.code,
            message: error.message,
            ...(error.data === undefined ? {} : { data: error.data }),
          },
        },
        nonce,
      );
    }
  }) as typeof fetch;
  const connector = (seed: number) => {
    const local = new LocalConnector(
      AgentSigner.fromSeed(new Uint8Array(32).fill(seed)),
      { fetchImpl },
    );
    local.addHost({ host: ORIGIN, allowed: true, features: [] });
    return local;
  };
  /** Packets the relay still holds for a mailbox. */
  const packets = (mailboxId: string) =>
    relay
      .snapshot()
      .mailboxes.find(
        (box) => box.current.envelope.event.payload.mailbox_id === mailboxId,
      )?.packets.length ?? 0;
  return { state, fetchImpl, connector, packets };
}

type Json = Record<string, any>;

async function call(
  connector: LocalConnector,
  tool: string,
  input: unknown,
): Promise<Json> {
  return (await connector.callTool(tool, input)) as Json;
}

async function rejects(
  connector: LocalConnector,
  tool: string,
  input: unknown,
  code: string,
): Promise<AgentProtocolError> {
  let caught: unknown;
  await assert.rejects(
    async () => {
      try {
        await connector.callTool(tool, input);
      } catch (error) {
        caught = error;
        throw error;
      }
    },
    { code },
  );
  return caught as AgentProtocolError;
}

async function openMailbox(connector: LocalConnector): Promise<Json> {
  const published = await call(connector, TOOL_MAIL_MAILBOX_PUBLISH, {
    routes: [ORIGIN],
  });
  assert.deepEqual(published.published, [ORIGIN]);
  assert.deepEqual(published.failed, []);
  return published.mailbox;
}

test("letters round-trip with replies, retries, and restored keys", async () => {
  const s = services();
  const alice = s.connector(1);
  const bob = s.connector(2);
  const bobBox = await openMailbox(bob);
  assert.equal(bobBox.status, "open");
  assert.equal(
    bobBox.address,
    `${bob.agentId()}/mail/${bobBox.mailbox_id}?route=${ORIGIN}`,
  );
  const aliceBox = await openMailbox(alice);

  const sent = await call(alice, TOOL_MAIL_SEND, {
    to: bobBox.address,
    subject: "Draft review",
    text: "Could you review section 4?",
    parts: [
      { media_type: "application/pdf", name: "draft.pdf", data: "JVBERi0" },
    ],
    reply_mailbox_id: aliceBox.mailbox_id,
  });
  assert.equal(sent.status, "delivered");
  assert.equal(sent.message.delivery.route, ORIGIN);
  const messageId = sent.message.message_id;

  // The first sync stores the letter and keeps the relay copy until the state
  // it produced has been saved; the next sync deletes it.
  let synced = await call(bob, TOOL_MAIL_SYNC, {});
  assert.equal(synced.received.length, 1);
  assert.deepEqual(synced.errors, []);
  assert.equal(s.packets(bobBox.mailbox_id), 1);
  const inbox = await call(bob, TOOL_INBOX_NEXT, { kinds: ["mail.received"] });
  assert.equal(inbox.items[0].actor, alice.agentId());
  assert.equal(inbox.items[0].message.summary, "Draft review");
  assert.equal(inbox.items[0].requires_response, false);
  synced = await call(bob, TOOL_MAIL_SYNC, {});
  assert.deepEqual(synced.received, []);
  assert.equal(s.packets(bobBox.mailbox_id), 0);

  const read = await call(bob, TOOL_MAIL_LIST, {
    unread_only: true,
    mark_read: true,
  });
  const letter = read.messages[0];
  assert.equal(letter.message_id, messageId);
  assert.equal(letter.parts[0].text, "Could you review section 4?");
  assert.equal(letter.parts[1].size, 5);
  assert.equal(letter.parts[1].data, undefined);
  assert.equal(letter.reply_address, aliceBox.address);
  assert.equal(read.unread_count, 0);
  const withData = await call(bob, TOOL_MAIL_LIST, {
    message_id: messageId,
    include_data: true,
  });
  assert.equal(withData.messages[0].parts[1].data, "JVBERi0");
  const mailboxes = await call(bob, TOOL_MAIL_MAILBOXES_LIST, {});
  assert.equal(mailboxes.mailboxes[0].unread_count, 0);

  // A reply needs no address: the parent's reply card names Alice's mailbox.
  const reply = await call(bob, TOOL_MAIL_SEND, {
    in_reply_to: messageId,
    text: "Done, see my notes.",
  });
  assert.equal(reply.status, "delivered");
  const answer = (await call(alice, TOOL_MAIL_SYNC, {})).received[0];
  assert.equal(answer.in_reply_to, messageId);
  assert.equal(answer.thread_id, sent.message.thread_id);
  assert.equal(answer.from, bob.agentId());

  // A transient relay failure queues the letter; the next sync delivers it.
  s.state.failingDeliveries = 1;
  const queued = await call(alice, TOOL_MAIL_SEND, {
    to: bobBox.address,
    text: "second",
  });
  assert.equal(queued.status, "queued");
  assert.equal(queued.message.delivery.last_error.code, "service_unavailable");
  const retried = await call(alice, TOOL_MAIL_SYNC, {});
  assert.deepEqual(retried.delivered, [queued.message.message_id]);
  assert.equal(retried.queued, 0);

  // Bob restarts from his snapshot and his separately stored mail keys.
  const snapshot = bob.snapshot();
  assert.equal(snapshot.version, LOCAL_CONNECTOR_SNAPSHOT_VERSION);
  assert.ok(!JSON.stringify(snapshot).includes("secret"));
  const keys = bob.mailKeysSnapshot();
  const restore = () =>
    LocalConnector.fromSnapshot(
      AgentSigner.fromSeed(new Uint8Array(32).fill(2)),
      snapshot,
      { fetchImpl: s.fetchImpl },
    );
  assert.deepEqual(restore().snapshot(), snapshot);
  const keyless = await call(restore(), TOOL_MAIL_SYNC, {});
  assert.deepEqual(keyless.received, []);
  assert.equal(keyless.errors[0].code, "invalid_event");
  const restored = restore();
  restored.restoreMailKeys(keys);
  const resynced = await call(restored, TOOL_MAIL_SYNC, {});
  assert.equal(resynced.received[0].parts[0].text, "second");
});

test("mailbox rotation, closing, sender policy, and the allowlist", async () => {
  const s = services();
  const alice = s.connector(3);
  const bob = s.connector(4);
  const bobBox = await openMailbox(bob);
  const mailboxId = bobBox.mailbox_id;
  await call(alice, TOOL_MAIL_SEND, {
    to: bobBox.address,
    text: "under the first key",
  });

  // Rotation keeps the old key until its card's receive_until.
  const rotated = await call(bob, TOOL_MAIL_MAILBOX_PUBLISH, {
    mailbox_id: mailboxId,
    routes: [ORIGIN],
    rotate_key: true,
  });
  assert.notEqual(rotated.mailbox.card_hash, bobBox.card_hash);
  assert.equal(rotated.mailbox.address, bobBox.address);
  assert.equal(Object.keys(bob.mailKeysSnapshot().keys).length, 2);
  // The stable address works once the card is pinned, and the sender reads
  // the rotated card before encrypting.
  const stable = `${bob.agentId()}/mail/${mailboxId}`;
  await call(alice, TOOL_MAIL_SEND, {
    to: stable,
    text: "under the second key",
  });
  let synced = await call(bob, TOOL_MAIL_SYNC, { mailbox_id: mailboxId });
  assert.deepEqual(
    synced.received.map((message: Json) => message.parts[0].text).sort(),
    ["under the first key", "under the second key"],
  );

  // A blocked sender's packets are deleted unopened.
  bob.setMailSenderBlocked(alice.agentId(), true);
  await call(bob, TOOL_MAIL_SYNC, {});
  await call(alice, TOOL_MAIL_SEND, { to: stable, text: "blocked" });
  synced = await call(bob, TOOL_MAIL_SYNC, {});
  assert.deepEqual(synced.received, []);
  assert.equal(s.packets(mailboxId), 0);

  // A route outside the allowlist is never contacted; without a pinned card
  // for that mailbox the send is refused.
  const elsewhere = "https://relay.elsewhere.example";
  const carol = AgentSigner.fromSeed(new Uint8Array(32).fill(7)).agentId();
  await rejects(
    alice,
    TOOL_MAIL_SEND,
    {
      to: `${carol}/mail/AAECAwQFBgcICQoLDA0ODw?route=${elsewhere}`,
      text: "hi",
    },
    "permission_denied",
  );
  await rejects(
    bob,
    TOOL_MAIL_MAILBOX_PUBLISH,
    { routes: [elsewhere] },
    "permission_denied",
  );

  // Closing publishes an empty route list; senders then refuse.
  const closed = await call(bob, TOOL_MAIL_MAILBOX_PUBLISH, {
    mailbox_id: mailboxId,
    routes: [],
  });
  assert.equal(closed.mailbox.status, "closed");
  assert.deepEqual(closed.published, [ORIGIN]);
  await rejects(
    alice,
    TOOL_MAIL_SEND,
    { to: bobBox.address, text: "too late" },
    "mailbox_unavailable",
  );
});

test("unread pages marked read skip no letter", async () => {
  const s = services();
  const alice = s.connector(9);
  const bob = s.connector(10);
  const bobBox = await openMailbox(bob);
  for (const text of ["one", "two", "three"]) {
    await call(alice, TOOL_MAIL_SEND, { to: bobBox.address, text });
  }
  await call(bob, TOOL_MAIL_SYNC, {});

  // Each page leaves the unread selection, so following next_cursor still
  // reaches every letter.
  const texts: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await call(bob, TOOL_MAIL_LIST, {
      unread_only: true,
      mark_read: true,
      limit: 2,
      ...(cursor === undefined ? {} : { cursor }),
    });
    texts.push(...page.messages.map((message: Json) => message.parts[0].text));
    cursor = page.next_cursor;
  } while (cursor !== undefined);
  assert.deepEqual(texts.sort(), ["one", "three", "two"]);
});

test("knowledge publish, query, search, and status", async () => {
  const s = services();
  const alice = s.connector(5);
  const bob = s.connector(6);
  const published = await call(alice, TOOL_KNOWLEDGE_SUBMIT, {
    services: [ORIGIN],
    type: "knowledge.publish",
    payload: {
      license: "https://creativecommons.org/licenses/by/4.0/",
      kind: "observation",
      title: "Cache keys need the language",
      statement:
        "A user-only cache key returns the first language for later requests.",
      language: "en",
      context: {
        scope: "An in-memory greeting cache.",
        conditions: [],
        limitations: [],
      },
      basis: "A two-request fixture.",
      tags: ["caching"],
    },
  });
  const id = published.id;
  assert.equal(published.results[0].item.id, id);
  assert.equal(published.results[0].item.seq, 1);

  const page = await call(bob, TOOL_KNOWLEDGE_QUERY, {
    service: ORIGIN,
    tag: "caching",
  });
  assert.equal(page.items[0].id, id);
  assert.equal(page.items[0].actor, alice.agentId());
  assert.equal(page.service, ORIGIN);
  assert.equal(page.checkpoint, 1);
  const unknown = "A".repeat(43);
  const got = await call(bob, TOOL_KNOWLEDGE_GET, {
    service: ORIGIN,
    ids: [id, unknown],
  });
  assert.equal(got.items[0].payload.title, "Cache keys need the language");
  assert.deepEqual(got.missing, [unknown]);
  const found = await call(bob, TOOL_KNOWLEDGE_SEARCH, {
    service: ORIGIN,
    text: "cache LANGUAGE",
    mode: "lexical",
  });
  assert.equal(found.hits[0].item.id, id);
  assert.equal(found.coverage.exhaustive, true);

  // Bob's assessment and a third party's attempted retraction leave the
  // capsule active; only the author's own retraction withdraws it.
  const assessment = await call(bob, TOOL_KNOWLEDGE_SUBMIT, {
    services: [ORIGIN],
    type: "knowledge.assess",
    payload: {
      license: "https://creativecommons.org/licenses/by/4.0/",
      target: id,
      verdict: "supports",
      summary: "Same result here.",
      context: { scope: "The same fixture.", conditions: [], limitations: [] },
      basis: "Reran the fixture.",
    },
  });
  await rejects(
    bob,
    TOOL_KNOWLEDGE_SUBMIT,
    {
      services: [ORIGIN],
      type: "knowledge.retract",
      payload: { target: id, reason: "not mine" },
    },
    "invalid_target",
  );
  let status = await call(bob, TOOL_KNOWLEDGE_STATUS, { service: ORIGIN, id });
  assert.equal(status.complete, true);
  assert.equal(status.status, "active");
  assert.deepEqual(status.assessments, [assessment.id]);
  const retraction = await call(alice, TOOL_KNOWLEDGE_SUBMIT, {
    services: [ORIGIN],
    type: "knowledge.retract",
    payload: { target: id, reason: "superseded" },
  });
  status = await call(bob, TOOL_KNOWLEDGE_STATUS, { service: ORIGIN, id });
  assert.equal(status.status, "retracted");
  assert.deepEqual(status.retractions, [retraction.id]);

  // Dependencies the service lacks keep their data; unknown services are refused.
  const missing = await rejects(
    alice,
    TOOL_KNOWLEDGE_SUBMIT,
    {
      services: [ORIGIN],
      type: "knowledge.retract",
      payload: { target: unknown, reason: "gone" },
    },
    "missing_dependency",
  );
  assert.deepEqual(missing.data?.missing, [unknown]);
  await rejects(
    alice,
    TOOL_KNOWLEDGE_QUERY,
    { service: "https://knowledge.elsewhere.example" },
    "permission_denied",
  );
  await rejects(
    alice,
    TOOL_KNOWLEDGE_SUBMIT,
    {
      services: [ORIGIN],
      type: "knowledge.publish",
      payload: { title: "incomplete" },
    },
    "invalid_event",
  );
});

test("one nonce sequence spans mail and knowledge", async () => {
  const s = services();
  const seed = new Uint8Array(32).fill(8);
  // Another holder of the same key signs far ahead of this one.
  const far = Date.now() + 3_600_000;
  const ahead = LocalConnector.fromSnapshot(
    AgentSigner.fromSeed(seed),
    { ...s.connector(8).snapshot(), next_nonce: far },
    { fetchImpl: s.fetchImpl },
  );
  await openMailbox(ahead);

  // The relay refuses this connector's card with Max-Seen-Nonce; it resyncs
  // and re-signs once.
  const behind = s.connector(8);
  const mailbox = await openMailbox(behind);
  const card = behind.snapshot().mail.mailboxes[0].cards[0].event.nonce;
  assert.ok(card > far);

  // Knowledge events and mail packets continue the same sequence.
  const submitted = await call(behind, TOOL_KNOWLEDGE_SUBMIT, {
    services: [ORIGIN],
    type: "knowledge.publish",
    payload: {
      license: "https://creativecommons.org/licenses/by/4.0/",
      kind: "question",
      title: "Nonce order",
      statement: "Does one sequence cover every protocol?",
      language: "en",
      context: { scope: "One Agent ID.", conditions: [], limitations: [] },
      basis: "A regression test.",
    },
  });
  const knowledge = submitted.envelope.event.nonce;
  assert.ok(knowledge > card);
  await call(behind, TOOL_MAIL_SEND, {
    to: mailbox.address,
    text: "a note to self",
  });
  const state = behind.snapshot();
  const packet = state.mail.messages[0].packet!.event.nonce;
  assert.ok(packet > knowledge);
  assert.ok(state.next_nonce > packet);
});
