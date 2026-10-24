// The local connector's Mail and Knowledge tools against the SDK's own
// reference relay and Knowledge store, behind an injected fetch. Two
// connectors play sender and recipient.

import { Validator, type Schema } from "@cfworker/json-schema";
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
  type LocalConnectorOptions,
  standardToolDefinitions,
  TOOL_INBOX_ACK,
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
  TOOL_ROOM_STATE,
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
  const state = {
    failingDeliveries: 0,
    losePublicationResponses: 0,
    failCardReads: false,
  };
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
    if (method === "POST" && at("v1", "mailboxes")) {
      const record = relay.publish(body as MailboxCard);
      if (state.losePublicationResponses > 0) {
        state.losePublicationResponses--;
        throw new TypeError("response lost after commit");
      }
      return json(200, record);
    }
    if (method === "GET" && at("v1", "me", "mailboxes"))
      return json(
        200,
        relay.mailboxes(jwt, {
          limit: Number(url.searchParams.get("limit") ?? 100),
          cursor: url.searchParams.get("cursor") ?? undefined,
        }),
      );
    if (method === "GET" && at("v1", "mailboxes", "*", "card")) {
      if (state.failCardReads) throw new TypeError("card read unavailable");
      return json(200, relay.card(path[2]));
    }
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
  const connector = (seed: number, options: LocalConnectorOptions = {}) => {
    const local = new LocalConnector(
      AgentSigner.fromSeed(new Uint8Array(32).fill(seed)),
      { ...options, fetchImpl },
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
  return { state, fetchImpl, connector, packets, relay };
}

type Json = Record<string, any>;

async function call(
  connector: LocalConnector,
  tool: string,
  input: unknown,
): Promise<Json> {
  const result = JSON.parse(
    JSON.stringify(await connector.callTool(tool, input)),
  ) as Json;
  const schema = standardToolDefinitions().find(
    (t) => t.name === tool,
  )!.output_schema;
  const validation = new Validator(schema as Schema, "2020-12", false).validate(
    result,
  );
  assert.equal(
    validation.valid,
    true,
    `${tool}: ${JSON.stringify(validation.errors)}`,
  );
  return result;
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
  // The view reports the read state this call left behind.
  assert.equal(letter.read, true);
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

test("empty Mail text and subject are preserved", async () => {
  const s = services();
  const alice = s.connector(11);
  const bob = s.connector(12);
  const mailbox = await openMailbox(bob);
  await call(alice, TOOL_MAIL_SEND, {
    to: mailbox.address,
    text: "",
    subject: "",
  });
  await call(bob, TOOL_MAIL_SYNC, {});
  const result = await call(bob, TOOL_MAIL_LIST, {});
  assert.equal(result.messages[0].subject, "");
  assert.equal(result.messages[0].parts.length, 1);
  assert.equal(result.messages[0].parts[0].text, "");
  assert.equal(result.messages[0].parts[0].size, 0);
});

test("blank and null arguments read as left out", async () => {
  const s = services();
  const alice = s.connector(11);
  const bob = s.connector(12);
  const bobBox = await openMailbox(bob);
  for (const text of ["first", "second"]) {
    await call(alice, TOOL_MAIL_SEND, { to: bobBox.address, text });
  }
  await call(bob, TOOL_MAIL_SYNC, {});

  // A host that must serialize every advertised property sends "" for the
  // filters it leaves out. A blank sender is no sender, not a bad agent ID, and
  // blank mailbox, thread, and message IDs match no empty value.
  const all = await call(bob, TOOL_MAIL_LIST, { from: "" });
  assert.equal(all.messages.length, 2);
  const page = await call(bob, TOOL_MAIL_LIST, {
    from: alice.agentId(),
    mailbox_id: "",
    thread_id: "",
    message_id: "",
    unread_only: true,
    mark_read: true,
  });
  assert.equal(page.messages.length, 2);
  assert.equal(page.unread_count, 0);
  assert.equal(
    page.messages.every((message: Json) => message.read === true),
    true,
  );

  // A null optional argument is an omitted one, not a type error.
  const inbox = await call(bob, TOOL_INBOX_NEXT, { kinds: ["mail.received"] });
  const ids = inbox.items.map((item: Json) => item.id);
  assert.equal(ids.length, 2);
  const acked = await call(bob, TOOL_INBOX_ACK, {
    ids,
    action: "defer",
    defer_until: null,
  });
  assert.equal(acked.acknowledged.length, 2);

  // A required argument that arrives blank is still missing.
  await rejects(bob, TOOL_ROOM_STATE, { room_id: "" }, "invalid_payload");
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
  // A payload that is not its type's is refused before anything is signed
  // or sent, naming each failing member.
  const unreached = new LocalConnector(
    AgentSigner.fromSeed(new Uint8Array(32).fill(7)),
    {
      fetchImpl: (async () => {
        throw new Error("no request expected");
      }) as typeof fetch,
    },
  );
  unreached.addHost({ host: ORIGIN, allowed: true, features: [] });
  const refused = await rejects(
    unreached,
    TOOL_KNOWLEDGE_SUBMIT,
    {
      services: [ORIGIN],
      type: "knowledge.publish",
      payload: { title: "incomplete", body: "text", license: "CC-BY-4.0" },
    },
    "invalid_event",
  );
  for (const member of [
    "kind",
    "statement",
    "language",
    "context",
    "basis",
    "body",
    "/license",
  ]) {
    assert.ok(
      refused.message.includes(member),
      `${member}: ${refused.message}`,
    );
  }
  const errors = refused.data?.errors as { path: string }[];
  assert.ok(errors.some((e) => e.path === "/license"));
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
  const card = behind.snapshot().mail.mailboxes[0].cards.at(-1)!.event.nonce;
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

test("mail publication survives response loss and restart; inventory recovers metadata only", async () => {
  const s = services();
  let saved: any, keys: any;
  const persist: LocalConnectorOptions["mailPersistence"] = (
    snapshot,
    material,
  ) => {
    saved = structuredClone(snapshot);
    keys = structuredClone(material);
  };
  const bob = s.connector(8, { mailPersistence: persist });
  const first = await openMailbox(bob);
  s.state.losePublicationResponses = 1;
  s.state.failCardReads = true;
  const rotated = await call(bob, TOOL_MAIL_MAILBOX_PUBLISH, {
    mailbox_id: first.mailbox_id,
    routes: [ORIGIN],
    rotate_key: true,
  });
  assert.deepEqual(rotated.published, []);
  assert.deepEqual(rotated.mailbox.pending_routes, [ORIGIN]);
  assert.equal(rotated.mailbox.key_available, true);
  const remote = s.relay.card(first.mailbox_id).envelope;
  assert.equal(saved.mail.mailboxes[0].cards.at(-1).hash, remote.hash);
  assert.ok(Object.hasOwn(keys.keys, remote.event.payload.public_key));
  s.state.failCardReads = false;
  const restored = LocalConnector.fromSnapshot(
    AgentSigner.fromSeed(new Uint8Array(32).fill(8)),
    saved,
    { fetchImpl: s.fetchImpl, mailPersistence: persist },
  );
  restored.restoreMailKeys(keys);
  const alice = s.connector(7);
  await call(alice, TOOL_MAIL_SEND, {
    to: rotated.mailbox.address,
    text: "arrived under uncertain rotation",
  });
  const synced = await call(restored, TOOL_MAIL_SYNC, {});
  assert.equal(
    synced.received[0].parts[0].text,
    "arrived under uncertain rotation",
  );
  assert.deepEqual(
    (await call(restored, TOOL_MAIL_MAILBOXES_LIST, {})).mailboxes[0]
      .pending_routes,
    [],
  );
  const recovery = s.connector(8);
  const inventory = await call(recovery, TOOL_MAIL_MAILBOXES_LIST, {
    host: ORIGIN,
    limit: 1,
  });
  assert.equal(inventory.mailboxes[0].card_hash, remote.hash);
  assert.equal(inventory.mailboxes[0].key_available, false);
  assert.equal(
    (await call(recovery, TOOL_MAIL_MAILBOXES_LIST, {})).mailboxes.length,
    1,
  );
  await assert.rejects(
    recovery.callTool(TOOL_MAIL_MAILBOXES_LIST, { limit: 1 }),
  );
});

test("a failed durable checkpoint prevents publication", async () => {
  const s = services();
  const bob = s.connector(8, {
    mailPersistence: () => {
      throw new Error("storage unavailable");
    },
  });
  await assert.rejects(
    bob.callTool(TOOL_MAIL_MAILBOX_PUBLISH, { routes: [ORIGIN] }),
    /storage unavailable/,
  );
  assert.equal(s.relay.snapshot().mailboxes.length, 0);
});

test("nonce resync checkpoints and retains intermediate published cards", async () => {
  const other = "https://second.example.test";
  const a = new MailRelayStore(ORIGIN),
    b = new MailRelayStore(other);
  let rejectOnce = true;
  let saved: any;
  const attempts: string[] = [];
  const c = new LocalConnector(
    AgentSigner.fromSeed(new Uint8Array(32).fill(8)),
    {
      mailPersistence: (state) => {
        saved = structuredClone(state);
      },
      fetchImpl: async (url, init) => {
        const card = JSON.parse(String(init?.body)) as MailboxCard;
        assert.ok(
          saved.mail.mailboxes[0].cards.some(
            (c: MailboxCard) => c.hash === card.hash,
          ),
        );
        attempts.push(card.hash);
        if (new URL(String(url)).origin === other && rejectOnce) {
          rejectOnce = false;
          return Response.json(
            { error: { code: "nonce_not_greater", message: "resync" } },
            {
              status: 409,
              headers: { "Max-Seen-Nonce": String(card.event.nonce + 1) },
            },
          );
        }
        return Response.json(
          (new URL(String(url)).origin === other ? b : a).publish(card),
        );
      },
    },
  );
  for (const host of [ORIGIN, other])
    c.addHost({ host, allowed: true, features: [] });
  const result = await call(c, TOOL_MAIL_MAILBOX_PUBLISH, {
    routes: [ORIGIN, other],
  });
  assert.equal(result.published.length, 2);
  assert.equal(new Set(attempts).size, 2);
  assert.equal(c.snapshot().mail.mailboxes[0].cards.length, 2);
  assert.equal(
    Object.keys(c.snapshot().mail.pending_publications ?? {}).length,
    0,
  );
});

test("pruning a shorter closed card never reopens the previous local card", async () => {
  const s = services(),
    bob = s.connector(8);
  await openMailbox(bob);
  const snapshot = bob.snapshot(),
    keys = bob.mailKeysSnapshot(),
    original = snapshot.mail.mailboxes[0].cards[0];
  const owner = AgentSigner.fromSeed(new Uint8Array(32).fill(8)),
    now = Date.now();
  const old = owner.signEvent({
    ...original.event,
    created_at: now - 60000,
    nonce: 1,
    payload: {
      ...original.event.payload,
      expires_at: now + 60000,
      receive_until: now + 120000,
    },
  });
  const closed = owner.signEvent({
    ...old.event,
    created_at: now - 10000,
    nonce: 2,
    payload: {
      ...old.event.payload,
      routes: [],
      expires_at: now - 2000,
      receive_until: now - 1000,
    },
  });
  snapshot.mail.mailboxes[0].cards = [old, closed];
  const restored = LocalConnector.fromSnapshot(owner, snapshot, {
    fetchImpl: s.fetchImpl,
  });
  restored.restoreMailKeys(keys);
  await call(restored, TOOL_MAIL_SYNC, {});
  const current = (await call(restored, TOOL_MAIL_MAILBOXES_LIST, {}))
    .mailboxes[0];
  assert.equal(current.status, "closed");
  assert.equal(current.card_hash, closed.hash);
  assert.equal(restored.snapshot().mail.mailboxes[0].cards.length, 2);
});

test("a verified current card confirms publication after a lost response", async () => {
  const s = services();
  s.state.losePublicationResponses = 1;
  const bob = s.connector(8);
  const mailbox = await openMailbox(bob);
  assert.deepEqual(mailbox.pending_routes, []);
  assert.equal(mailbox.key_available, true);
  assert.equal(
    s.relay.card(mailbox.mailbox_id).envelope.hash,
    mailbox.card_hash,
  );
});

test("resigning a pending publication updates previously successful routes too", async () => {
  const other = "https://retry.example.test",
    a = new MailRelayStore(ORIGIN),
    b = new MailRelayStore(other);
  let phase = 0;
  const c = new LocalConnector(
    AgentSigner.fromSeed(new Uint8Array(32).fill(8)),
    {
      fetchImpl: async (url, init) => {
        const u = new URL(String(url)),
          relay = u.origin === ORIGIN ? a : b;
        if (init?.method === "POST") {
          const card = JSON.parse(String(init.body)) as MailboxCard;
          if (u.origin === other && phase === 0)
            return Response.json(
              { error: { code: "service_unavailable", message: "offline" } },
              { status: 503 },
            );
          if (u.origin === other && phase === 1) {
            phase = 2;
            return Response.json(
              { error: { code: "nonce_not_greater", message: "resync" } },
              {
                status: 409,
                headers: { "Max-Seen-Nonce": String(card.event.nonce + 1) },
              },
            );
          }
          return Response.json(relay.publish(card));
        }
        if (u.pathname.endsWith("/card"))
          return Response.json(
            { error: { code: "mailbox_unavailable", message: "unknown" } },
            { status: 404 },
          );
        return Response.json({ result: [] });
      },
    },
  );
  for (const host of [ORIGIN, other]) c.addHost({ host, allowed: true });
  const initial = await call(c, TOOL_MAIL_MAILBOX_PUBLISH, {
    routes: [ORIGIN, other],
  });
  assert.deepEqual(initial.mailbox.pending_routes, [other]);
  phase = 1;
  await call(c, TOOL_MAIL_SYNC, {});
  const id = initial.mailbox.mailbox_id;
  assert.equal(a.card(id).envelope.hash, b.card(id).envelope.hash);
  assert.notEqual(a.card(id).envelope.hash, initial.mailbox.card_hash);
  assert.equal(
    Object.keys(c.snapshot().mail.pending_publications ?? {}).length,
    0,
  );
});

test("inventory keeps a lagging relay's older card; disallowed routes are not pending", async () => {
  const other = "https://lagging.example.test",
    a = new MailRelayStore(ORIGIN),
    b = new MailRelayStore(other);
  let offline = false;
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const u = new URL(String(input)),
      relay = u.origin === ORIGIN ? a : b;
    if (init?.method === "POST") {
      if (u.origin === other && offline)
        return Response.json(
          { error: { code: "service_unavailable", message: "offline" } },
          { status: 503 },
        );
      return Response.json(relay.publish(JSON.parse(String(init.body))));
    }
    if (u.pathname === "/v1/me/mailboxes") {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      return Response.json(
        relay.mailboxes(headers.authorization.replace(/^Bearer /, "")),
      );
    }
    return Response.json(
      { error: { code: "mailbox_unavailable", message: "unknown" } },
      { status: 404 },
    );
  }) as typeof fetch;
  const connector = () => {
    const c = new LocalConnector(
      AgentSigner.fromSeed(new Uint8Array(32).fill(8)),
      { fetchImpl },
    );
    for (const host of [ORIGIN, other]) c.addHost({ host, allowed: true });
    return c;
  };
  const owner = connector();
  const first = await call(owner, TOOL_MAIL_MAILBOX_PUBLISH, {
    routes: [ORIGIN, other],
  });
  const id = first.mailbox.mailbox_id;
  offline = true;
  const second = await call(owner, TOOL_MAIL_MAILBOX_PUBLISH, {
    mailbox_id: id,
    routes: [ORIGIN, other],
  });
  assert.deepEqual(second.mailbox.pending_routes, [other]);

  // The first relay pins the newer card; the lagging one still serves the
  // older card, which recovery keeps as history.
  const recovery = connector();
  await call(recovery, TOOL_MAIL_MAILBOXES_LIST, { host: ORIGIN });
  const lagging = await call(recovery, TOOL_MAIL_MAILBOXES_LIST, {
    host: other,
  });
  assert.equal(lagging.mailboxes[0].card_hash, second.mailbox.card_hash);
  assert.equal(recovery.snapshot().mail.mailboxes[0].cards.length, 2);

  // A route the operator stops allowing is reported once, not kept pending.
  owner.addHost({ host: other, allowed: false });
  const third = await call(owner, TOOL_MAIL_MAILBOX_PUBLISH, {
    mailbox_id: id,
    routes: [ORIGIN],
  });
  assert.deepEqual(third.published, [ORIGIN]);
  assert.deepEqual(
    third.failed.map((e: Json) => [e.route, e.code]),
    [[other, "permission_denied"]],
  );
  assert.deepEqual(third.mailbox.pending_routes, []);
});
