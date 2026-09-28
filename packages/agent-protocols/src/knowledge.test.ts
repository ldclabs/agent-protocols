import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  AgentSigner,
  MemoryNonceStore,
  parseStrictJson,
  verifySubmission,
} from "./identity.js";
import { AgentProtocolError } from "./errors.js";
import { KnowledgeClient, HttpResponseError } from "./http-client.js";
import * as k from "./knowledge.js";
const service = "https://knowledge.example.com";
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-knowledge/1.0.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const env = (name: string): k.KnowledgeEnvelope =>
  structuredClone(vectors.fixtures[name].envelope);
const code = (expected: string) => (error: unknown) =>
  error instanceof AgentProtocolError && error.code === expected;
const store = (options: Partial<k.KnowledgeStoreOptions> = {}) =>
  new k.KnowledgeStore({ service, clock: () => vectors.now, ...options });
const discovery: k.KnowledgeDiscovery = {
  protocol: k.KNOWLEDGE_PROTOCOL,
  service,
  features: ["import", "ranked-search"],
  endpoints: {
    events: service + "/custom/events",
    import: service + "/custom/import",
    search: service + "/custom/search",
  },
  search_modes: ["lexical", "semantic"],
};
const json = (value: unknown) =>
  new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });

test("builders preserve omitted fields, explicit empty arrays, and unknown signed profile data", () => {
  const signer = AgentSigner.fromSeed(
    Buffer.from(vectors.seeds[vectors.fixtures.original.signer], "hex"),
  );
  const payload = structuredClone(
    env("original").event.payload,
  ) as k.KnowledgePublishPayload;
  delete payload.evidence;
  payload.relations = [];
  payload.profiles = [
    {
      profile: {
        url: "https://profiles.example/unknown",
        digest: "A".repeat(43),
      },
      data: { arbitrary: [null, [], {}, { new: true }] },
    },
  ];
  const event = k.knowledgePublishEvent(
      signer.agentId(),
      vectors.now,
      1000,
      payload,
    ),
    envelope = signer.signEvent(event);
  k.validateKnowledgeEnvelope(envelope);
  const restored = k.parseKnowledgeEnvelope(JSON.stringify(envelope));
  assert.deepEqual(restored, envelope);
  assert.equal(Object.hasOwn(restored.event.payload, "evidence"), false);
  assert.deepEqual(
    (restored.event.payload as k.KnowledgePublishPayload).relations,
    [],
  );
  assert.equal(
    k.knowledgeAssessEvent(
      signer.agentId(),
      vectors.now,
      1001,
      env("assessment").event.payload as k.KnowledgeAssessPayload,
    ).type,
    "knowledge.assess",
  );
  assert.equal(
    k.knowledgeRetractEvent(
      signer.agentId(),
      vectors.now,
      1002,
      env("retract_original").event.payload as k.KnowledgeRetractPayload,
    ).type,
    "knowledge.retract",
  );
});
test("programmatic non-JSON annotations are rejected without lossy serialization", () => {
  for (const bad of [undefined, NaN, Infinity, new Date(), () => 1]) {
    const item = env("original");
    item.event.payload.extra = { bad };
    assert.throws(
      () => k.validateKnowledgeEnvelope(item),
      code("invalid_event"),
    );
  }
});
test("storage, admission hooks, returned records, and read snapshots are detached", () => {
  const engine = store({
    admit: (item) => {
      (item.event.payload as k.KnowledgePublishPayload).title = "hook changed";
    },
  });
  const item = env("original"),
    receipt = engine.import(item);
  (item.event.payload as k.KnowledgePublishPayload).title = "caller changed";
  (receipt.envelope.event.payload as k.KnowledgePublishPayload).title =
    "receipt changed";
  const page = engine.query();
  (page.result[0].envelope.event.payload as k.KnowledgePublishPayload).title =
    "page changed";
  const known = engine.knownEnvelopes();
  known.clear();
  assert.deepEqual(engine.event(item.hash).envelope, env("original"));
});
test("withholding, pruning and reacquisition preserve receipt identity and sequence high water", () => {
  const engine = store();
  const item = env("original"),
    receipt = engine.submit(item);
  engine.hide(item.hash);
  assert.throws(() => engine.event(item.hash), code("not_found"));
  assert.deepEqual(engine.submit(item), receipt);
  assert.deepEqual(engine.batch({ hashes: [item.hash] }).missing, [item.hash]);
  engine.prune(item.hash);
  assert.equal(engine.checkpoint, 1);
  assert.throws(() => engine.submit(item), code("nonce_not_greater"));
  assert.equal(engine.import(item).seq, 2);
});
test("pruning then reaccepting an ID cannot leak a newer record through an older snapshot", () => {
  const engine = store();
  engine.import(env("text_publication"));
  const second = env("text_regional");
  engine.import(second);
  const first = engine.query({ limit: 1 });
  engine.prune(second.hash);
  engine.import(second);
  const last = engine.query({ limit: 1, cursor: first.next_cursor });
  assert.deepEqual(last.result, []);
  assert.equal(last.checkpoint, 2);
});
test("changes freezes checkpoint, includes late historical imports and preserves gaps", () => {
  const engine = store();
  engine.import(env("original"));
  engine.import(env("branch_left"));
  const first = engine.changes({ limit: 1 });
  engine.import(env("branch_right"));
  const second = engine.changes({ limit: 1, cursor: first.next_cursor });
  assert.equal(second.checkpoint, 2);
  assert.equal(second.result[0].seq, 2);
  engine.prune(env("original").hash);
  assert.equal(engine.changes({ after: 2 }).result[0].seq, 3);
  assert.throws(() => engine.changes({ after: 4 }), code("invalid_request"));
});
test("snapshot limits, expiration and cursor request binding are explicit", () => {
  let clock = vectors.now;
  const engine = store({
    clock: () => clock,
    snapshotTtlMs: 10,
    maxSnapshots: 1,
  });
  engine.import(env("original"));
  engine.import(env("branch_left"));
  const first = engine.query({ limit: 1 });
  engine.query({ limit: 1 });
  assert.throws(
    () => engine.query({ limit: 1, cursor: first.next_cursor }),
    code("invalid_cursor"),
  );
  const page = engine.query({ limit: 1 });
  clock += 10;
  assert.throws(
    () => engine.query({ limit: 1, cursor: page.next_cursor }),
    code("invalid_cursor"),
  );
  const small = store({ maxSnapshotRecords: 1 });
  small.import(env("original"));
  small.import(env("branch_left"));
  assert.throws(() => small.query(), code("query_too_broad"));
});
test("profile conformance requires exact bytes, verified dependencies and all checks", () => {
  const signer = AgentSigner.fromSeed(
      Buffer.from(vectors.seeds[vectors.fixtures.original.signer], "hex"),
    ),
    bytes = Buffer.from("profile-v1"),
    digest = createHash("sha3-256").update(bytes).digest("base64url");
  const event = env("original").event;
  (event.payload as k.KnowledgePublishPayload).profiles = [
    { profile: { url: "https://profiles.example/v1", digest }, data: {} },
  ];
  const item = signer.signEvent(event);
  assert.equal(k.knowledgeProfileResult(item, digest).status, "unchecked");
  assert.equal(
    k.knowledgeProfileResult(item, digest, {
      supported: true,
      artifact: bytes,
      checksPassed: true,
    }).status,
    "unavailable",
  );
  assert.equal(
    k.knowledgeProfileResult(item, digest, {
      supported: true,
      artifact: bytes,
      dependenciesVerified: true,
      checksPassed: false,
    }).status,
    "nonconformant",
  );
  assert.deepEqual(
    k.knowledgeProfileResult(item, digest, {
      supported: true,
      artifact: bytes,
      dependenciesVerified: true,
      checksPassed: true,
    }),
    { event_id: item.hash, profile_digest: digest, status: "conformant" },
  );
});
function transport(engine: k.KnowledgeStore, calls: any[]): typeof fetch {
  return async (input, init) => {
    const url = new URL(String(input));
    calls.push({ url, init });
    assert.equal(init?.redirect, "error");
    assert.equal(new Headers(init?.headers).has("authorization"), false);
    if (url.pathname === "/.well-known/agent-knowledge") return json(discovery);
    const body = init?.body ? parseStrictJson(String(init.body)) : undefined;
    if (url.pathname === "/custom/events")
      return json(
        init?.method === "POST"
          ? engine.submit(body as k.KnowledgeEnvelope)
          : engine.event(url.searchParams.get("hash")!),
      );
    if (url.pathname === "/custom/import")
      return json(engine.import(body as k.KnowledgeEnvelope));
    if (url.pathname === "/knowledge/query")
      return json(engine.query(k.parseKnowledgeQuery(url.searchParams)));
    if (url.pathname === "/knowledge/batch")
      return json(engine.batch(body as k.KnowledgeBatchRequest));
    if (url.pathname === "/knowledge/changes")
      return json(
        engine.changes(
          Object.fromEntries(
            [...url.searchParams].map(([key, value]) => [
              key,
              key === "cursor" ? value : Number(value),
            ]),
          ),
        ),
      );
    if (url.pathname === "/custom/search")
      return json(
        engine.search(body as k.KnowledgeSearchRequest, {
          candidates: [...engine.knownEnvelopes().keys()],
          ranking: { mode: "lexical", id: "literal-v1" },
          coverage: { exhaustive: true, reasons: [] },
        }),
      );
    throw new Error(`Unexpected route ${url}`);
  };
}
test("HTTP discovery uses advertised endpoints, validates live/import results and reads without a signer", async () => {
  const engine = store(),
    calls: any[] = [],
    client = await KnowledgeClient.discover(service, transport(engine, calls));
  const original = env("text_publication"),
    second = env("text_regional");
  await client.submit(original);
  await client.import(second);
  assert.equal(
    (await client.event(original.hash)).envelope.hash,
    original.hash,
  );
  assert.equal(
    (await client.batch([second.hash, original.hash])).result.length,
    2,
  );
  assert.equal(
    (await client.search({ text: "alpha", mode: "lexical" })).result.length,
    2,
  );
  const pages = [];
  for await (const page of client.queryPages({ q: "alpha", limit: 1 }))
    pages.push(page);
  assert.equal(pages.length, 2);
  const changes = [];
  for await (const page of client.changesPages({ limit: 1 }))
    changes.push(page);
  assert.equal(changes.length, 2);
  const searches = [];
  for await (const page of client.searchPages({
    text: "alpha",
    mode: "lexical",
    limit: 1,
  }))
    searches.push(page);
  assert.equal(searches.length, 2);
  const batch = calls.find((c) => c.url.pathname.endsWith("batch"));
  assert.deepEqual(JSON.parse(batch.init.body), {
    hashes: [second.hash, original.hash],
  });
  assert.equal(engine.checkpoint, 2);
});
test("HTTP defaults core routes and never guesses optional support", async () => {
  const engine = store();
  engine.import(env("original"));
  const calls: string[] = [];
  const client = new KnowledgeClient(service, async (input) => {
    calls.push(String(input));
    return json(engine.event(env("original").hash));
  });
  await client.event(env("original").hash);
  assert.equal(new URL(calls[0]).pathname, "/knowledge/events");
  await assert.rejects(
    () => client.import(env("original")),
    code("invalid_request"),
  );
  await assert.rejects(
    () => client.search({ text: "cache", mode: "semantic" }),
    code("unsupported_search_mode"),
  );
  assert.equal(calls.length, 1);
});
test("HTTP rejects duplicate JSON, tampering, wrong IDs, wrong scope, redirects and cross-origin endpoints", async () => {
  const engine = store();
  const record = engine.import(env("original"));
  await assert.rejects(
    () =>
      new KnowledgeClient(
        service,
        async () =>
          new Response(
            '{"result":[],"result":[],"service":"https://knowledge.example.com","checkpoint":0,"as_of":0}',
          ),
      ).query(),
    code("invalid_response"),
  );
  await assert.rejects(
    () =>
      new KnowledgeClient(service, async () => json(record)).event(
        env("branch_left").hash,
      ),
    code("invalid_response"),
  );
  const tampered = structuredClone(record);
  (tampered.envelope.event.payload as k.KnowledgePublishPayload).title =
    "tampered";
  await assert.rejects(
    () =>
      new KnowledgeClient(service, async () => json(tampered)).event(
        record.envelope.hash,
      ),
    code("invalid_event_hash"),
  );
  await assert.rejects(
    () =>
      new KnowledgeClient(service, async () =>
        json({ ...engine.query(), service: "https://other.example" }),
      ).query(),
    code("invalid_response"),
  );
  assert.throws(
    () =>
      new KnowledgeClient(service, fetch, {
        ...discovery,
        endpoints: {
          ...discovery.endpoints,
          events: "https://other.example/events",
        },
      }),
    code("invalid_discovery"),
  );
  const response = json(record);
  Object.defineProperty(response, "url", {
    value: "https://other.example/events",
  });
  await assert.rejects(
    () =>
      new KnowledgeClient(service, async () => response).event(
        record.envelope.hash,
      ),
    code("invalid_response"),
  );
  await assert.rejects(
    () =>
      new KnowledgeClient(service, async (_input, init) => {
        assert.equal(init?.redirect, "error");
        throw new TypeError("redirect refused");
      }).event(record.envelope.hash),
    /redirect refused/,
  );
});
test("HTTP preserves Identity error details and Max-Seen-Nonce without retrying as import", async () => {
  let calls = 0;
  const client = new KnowledgeClient(
    service,
    async () => {
      calls++;
      return new Response(
        JSON.stringify({
          error: {
            code: "nonce_not_greater",
            message: "stale",
            data: { max_nonce: 50 },
          },
        }),
        { status: 409, headers: { "Max-Seen-Nonce": "50" } },
      );
    },
    discovery,
  );
  await assert.rejects(
    () => client.submit(env("original")),
    (e: unknown) =>
      e instanceof HttpResponseError &&
      e.code === "nonce_not_greater" &&
      e.maxSeenNonce === "50",
  );
  assert.equal(calls, 1);
});
test("HTTP authentication is explicit, origin bound, and importing actor need not equal caller", async () => {
  const caller = AgentSigner.generate(),
    now = Math.floor(Date.now() / 1000),
    jwt = caller.signRequestJwt({
      iss: caller.agentId(),
      sub: caller.agentId(),
      aud: service,
      iat: now,
      exp: now + 100,
    });
  const engine = store();
  const client = new KnowledgeClient(
    service,
    async (_url, init) => {
      assert.equal(
        new Headers(init?.headers).get("authorization"),
        `Bearer ${jwt}`,
      );
      return json(engine.import(env("original")));
    },
    discovery,
  );
  assert.equal((await client.import(env("original"), jwt)).seq, 1);
  const other = caller.signRequestJwt({
    iss: caller.agentId(),
    sub: caller.agentId(),
    aud: "https://other.example",
    iat: now,
    exp: now + 100,
  });
  await assert.rejects(() => client.import(env("original"), other));
});
test("page tracker rejects ranking drift, repeated events and cursor cycles", () => {
  const engine = store();
  engine.import(env("text_publication"));
  engine.import(env("text_regional"));
  const request: k.KnowledgeSearchRequest = {
      text: "alpha",
      mode: "lexical",
      limit: 1,
    },
    selection: k.KnowledgeSearchSelection = {
      candidates: [...engine.knownEnvelopes().keys()],
      ranking: { mode: "lexical", id: "v1" },
      coverage: { exhaustive: true, reasons: [] },
    };
  const first = engine.search(request, selection),
    nextRequest = { ...request, cursor: first.next_cursor },
    second = engine.search(nextRequest);
  const tracker = new k.KnowledgePageTracker("search", service);
  tracker.accept(request, first);
  assert.throws(
    () =>
      tracker.accept(nextRequest, {
        ...second,
        ranking: { mode: "lexical", id: "v2" },
      }),
    code("invalid_response"),
  );
  assert.throws(
    () =>
      tracker.accept(nextRequest, {
        ...second,
        result: [{ ...first.result[0], rank: 2 }],
      }),
    code("invalid_response"),
  );
  assert.throws(
    () =>
      tracker.accept(nextRequest, {
        ...second,
        next_cursor: first.next_cursor,
      }),
    code("invalid_response"),
  );
  tracker.accept(nextRequest, second);
  assert.equal(tracker.complete, true);
});

test("HTTP response verification binds the request actually sent despite caller mutation", async () => {
  const engine = store();
  engine.import(env("text_publication"));
  engine.import(env("text_regional"));
  let release!: (response: Response) => void;
  const client = new KnowledgeClient(
    service,
    async () =>
      new Promise<Response>((resolve) => {
        release = resolve;
      }),
  );
  const hashes = [env("text_publication").hash],
    pendingBatch = client.batch(hashes);
  hashes[0] = env("text_regional").hash;
  release(json(engine.batch({ hashes: [env("text_publication").hash] })));
  assert.equal(
    (await pendingBatch).result[0].envelope.hash,
    env("text_publication").hash,
  );
  const request: k.KnowledgeQuery = { q: "alpha" },
    pendingQuery = client.query(request);
  request.q = "will-not-match";
  release(json(engine.query({ q: "alpha" })));
  assert.equal((await pendingQuery).result.length, 2);
  const item = env("original"),
    pendingSubmit = client.submit(item);
  item.hash = env("branch_left").hash;
  release(json(engine.import(env("original"))));
  assert.equal((await pendingSubmit).envelope.hash, env("original").hash);
});
test("HTTP rejects alternate success statuses and omits ambient credentials", async () => {
  const engine = store();
  const record = engine.import(env("original"));
  const client = new KnowledgeClient(service, async (_input, init) => {
    assert.equal(init?.credentials, "omit");
    return new Response(JSON.stringify(record), { status: 201 });
  });
  await assert.rejects(
    () => client.event(record.envelope.hash),
    code("invalid_response"),
  );
});

test("shared actor-wide nonce cache can be injected across protocol services", () => {
  const nonceStore = new MemoryNonceStore();
  verifySubmission(env("branch_left"), nonceStore, { nowMs: vectors.now });
  const engine = store({ nonceStore });
  assert.throws(
    () => engine.submit(env("original")),
    code("nonce_not_greater"),
  );
  assert.equal(engine.import(env("original")).seq, 1);
  assert.equal(engine.maxNonce(env("original").event.actor), 20);
});

test("returned search metadata cannot mutate the frozen snapshot", () => {
  const engine = store();
  engine.import(env("text_publication"));
  engine.import(env("text_regional"));
  const request: k.KnowledgeSearchRequest = {
    text: "alpha",
    mode: "lexical",
    limit: 1,
  };
  const first = engine.search(request, {
    candidates: [...engine.knownEnvelopes().keys()],
    ranking: { mode: "lexical", id: "immutable-v1" },
    coverage: { exhaustive: true, reasons: [] },
  });
  first.ranking.id = "mutated";
  first.coverage.exhaustive = false;
  first.coverage.reasons.push("approximate");
  const second = engine.search({ ...request, cursor: first.next_cursor });
  assert.equal(second.ranking.id, "immutable-v1");
  assert.deepEqual(second.coverage, { exhaustive: true, reasons: [] });
});

test("changes HTTP parameters reject duplicate names, unknown fields and nondecimal integers", () => {
  assert.deepEqual(
    k.parseKnowledgeChanges(new URLSearchParams("after=0001&limit=2")),
    { after: 1, limit: 2 },
  );
  for (const parameters of [
    "after=0&after=1",
    "foo=x",
    "after=1e2",
    "after=-1",
    "limit=0",
    "cursor=",
    "after=9007199254740992",
  ])
    assert.throws(
      () => k.parseKnowledgeChanges(new URLSearchParams(parameters)),
      code("invalid_request"),
    );
});

test("batch and search reject distinct events sharing one acceptance sequence", () => {
  const engine = store();
  const first = engine.import(env("text_publication"));
  const second = engine.import(env("text_regional"));
  const hashes = [second.envelope.hash, first.envelope.hash];
  const batch = engine.batch({ hashes });
  // Caller-selected batch order and ranked search order may decrease in seq.
  k.validateKnowledgeBatchResponse(batch, hashes, service);
  batch.result[1].seq = batch.result[0].seq;
  assert.throws(
    () => k.validateKnowledgeBatchResponse(batch, hashes, service),
    code("invalid_response"),
  );
  const request: k.KnowledgeSearchRequest = { text: "alpha", mode: "lexical" };
  const response = engine.search(request, {
    candidates: hashes,
    ranking: { mode: "lexical", id: "reverse-v1" },
    coverage: { exhaustive: true, reasons: [] },
  });
  k.validateKnowledgeSearchResponse(response, request, service);
  response.result[1].record.seq = response.result[0].record.seq;
  assert.throws(
    () => k.validateKnowledgeSearchResponse(response, request, service),
    code("invalid_response"),
  );
});

test("search tracker rejects reused acceptance sequences across pages while allowing descending seq", () => {
  const engine = store();
  const first = engine.import(env("text_publication"));
  const second = engine.import(env("text_regional"));
  const request: k.KnowledgeSearchRequest = {
    text: "alpha",
    mode: "lexical",
    limit: 1,
  };
  const page = engine.search(request, {
    candidates: [second.envelope.hash, first.envelope.hash],
    ranking: { mode: "lexical", id: "reverse-v1" },
    coverage: { exhaustive: true, reasons: [] },
  });
  const nextRequest = { ...request, cursor: page.next_cursor };
  const last = engine.search(nextRequest);
  const tracker = new k.KnowledgePageTracker("search", service);
  tracker.accept(request, page);
  const conflicting = structuredClone(last);
  conflicting.result[0].record.seq = page.result[0].record.seq;
  assert.throws(
    () => tracker.accept(nextRequest, conflicting),
    code("invalid_response"),
  );
  assert.equal(tracker.complete, false);
  // Rejection must not consume this valid continuation. Rank increases; seq decreases.
  tracker.accept(nextRequest, last);
  assert.equal(last.result[0].rank, 2);
  assert.equal(last.result[0].record.seq, 1);
  assert.equal(tracker.complete, true);
});
