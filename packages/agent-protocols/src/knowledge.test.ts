import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AgentSigner, parseStrictJson } from "./identity.js";
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
  features: ["ranked-search"],
  endpoints: {
    events: service + "/custom/events",
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
test("storage, admission hooks, returned records, and read pages are detached", () => {
  const engine = store({
    admit: (item) => {
      (item.event.payload as k.KnowledgePublishPayload).title = "hook changed";
    },
  });
  const item = env("original"),
    receipt = engine.submit(item);
  (item.event.payload as k.KnowledgePublishPayload).title = "caller changed";
  (receipt.envelope.event.payload as k.KnowledgePublishPayload).title =
    "receipt changed";
  const page = engine.query();
  (page.result[0].envelope.event.payload as k.KnowledgePublishPayload).title =
    "page changed";
  const known = engine.knownEnvelopes();
  (known.get(item.hash)!.event.payload as k.KnowledgePublishPayload).title =
    "known changed";
  assert.deepEqual(engine.event(item.hash).envelope, env("original"));
});
test("acceptance ignores live nonce state and accepts old events", () => {
  const engine = store();
  assert.equal(engine.submit(env("higher_nonce")).seq, 1);
  assert.equal(engine.submit(env("same_nonce_a")).seq, 2);
  assert.equal(engine.submit(env("same_nonce_b")).seq, 3);
  assert.equal(engine.submit(env("old_event")).seq, 4);
  assert.throws(
    () => engine.submit(env("future")),
    code("timestamp_out_of_window"),
  );
  assert.equal(engine.submit(env("future"), vectors.now + 1).seq, 5);
  const strict = store({ futureSkewMs: 0 });
  assert.throws(
    () => strict.submit(env("future"), vectors.now + 1),
    code("timestamp_out_of_window"),
  );
});
test("withholding, pruning and reacquisition preserve receipt identity and sequence high water", () => {
  const engine = store();
  const item = env("original"),
    receipt = engine.submit(item);
  engine.hide(item.hash);
  assert.throws(() => engine.event(item.hash), code("not_found"));
  assert.deepEqual(engine.submit(item), receipt);
  assert.deepEqual(engine.batch({ hashes: [item.hash] }).missing, [item.hash]);
  assert.equal(engine.submit(env("branch_left")).seq, 2);
  assert.equal(engine.submit(env("retract_original")).seq, 3);
  engine.prune(item.hash);
  assert.equal(engine.checkpoint, 3);
  assert.equal(engine.submit(item).seq, 4);
});
test("relationships may cite or dispute assessments but not retractions", () => {
  const known = new Map<string, k.KnowledgeEnvelope>();
  for (const name of ["original", "assessment", "retract_original"])
    known.set(env(name).hash, env(name));
  k.validateKnowledgeDependencies(env("derived_from_assessment"), known);
  k.validateKnowledgeDependencies(env("contradicts_assessment"), known);
  assert.throws(
    () => k.validateKnowledgeDependencies(env("supports_retraction"), known),
    code("invalid_target"),
  );
});
test("checkpoint cursors are stateless and never leak a reaccepted record", () => {
  const engine = store();
  engine.submit(env("text_publication"));
  const second = env("text_regional");
  engine.submit(second);
  const first = engine.query({ limit: 1 });
  engine.prune(second.hash);
  engine.submit(second);
  const last = engine.query({ limit: 1, cursor: first.next_cursor });
  assert.deepEqual(last.result, []);
  assert.equal(last.checkpoint, 2);
  assert.equal(last.next_cursor, undefined);
  assert.equal(engine.query({ after_seq: 2 }).result[0].seq, 3);
  assert.throws(() => engine.query({ after_seq: 4 }), code("invalid_request"));
  for (const cursor of [
    first.next_cursor + "x",
    "1.2.3",
    "9.0.0." + "A".repeat(43),
  ])
    assert.throws(
      () => engine.query({ limit: 1, cursor }),
      code("invalid_cursor"),
    );
  assert.throws(
    () => engine.query({ limit: 2, cursor: first.next_cursor }),
    code("invalid_cursor"),
  );
  assert.throws(
    () => store().query({ limit: 1, cursor: first.next_cursor }),
    code("invalid_cursor"),
  );
});
test("search returns one page and cannot overclaim coverage", () => {
  const engine = store();
  for (const name of ["text_publication", "text_regional", "text_assessment"])
    engine.submit(env(name));
  const candidates = [...engine.knownEnvelopes().keys()].reverse();
  const request: k.KnowledgeSearchRequest = {
    text: "alpha",
    mode: "lexical",
    limit: 2,
  };
  const page = engine.search(request, {
    candidates,
    ranking: { mode: "lexical", id: "reverse-v1" },
    coverage: { exhaustive: false, reasons: ["candidate_limit"] },
    explanations: { [candidates[0]]: "top hit" },
  });
  assert.deepEqual(
    page.result.map((hit) => hit.record.envelope.hash),
    candidates.slice(0, 2),
  );
  assert.deepEqual(
    page.result.map((hit) => hit.explanation),
    ["top hit", undefined],
  );
  assert.equal("next_cursor" in page, false);
  k.validateKnowledgeSearchResponse(page, request, service);
  assert.throws(
    () =>
      engine.search(request, {
        candidates,
        ranking: { mode: "lexical", id: "reverse-v1" },
        coverage: { exhaustive: true, reasons: [] },
      }),
    code("invalid_response"),
  );
});
test("query HTTP parameters reject duplicate names, unknown fields and nondecimal integers", () => {
  assert.deepEqual(
    k.parseKnowledgeQuery(new URLSearchParams("after_seq=0001&limit=2")),
    { after_seq: 1, limit: 2 },
  );
  for (const parameters of [
    "after_seq=0&after_seq=1",
    "after=1",
    "after_seq=1e2",
    "after_seq=-1",
    "limit=0",
    "cursor=",
    "after_seq=9007199254740992",
  ])
    assert.throws(
      () => k.parseKnowledgeQuery(new URLSearchParams(parameters)),
      code("invalid_request"),
    );
});
test("evidence statuses distinguish missing digests, missing bytes and mismatches", () => {
  const bytes = Buffer.from("exact\r\nbytes"),
    digest = createHash("sha3-256").update(bytes).digest("base64url");
  assert.equal(k.verifyKnowledgeEvidence(digest, bytes), "matched");
  assert.equal(
    k.verifyKnowledgeEvidence(digest, bytes.subarray(0, 3)),
    "mismatched",
  );
  assert.equal(k.verifyKnowledgeEvidence(digest, null), "unavailable");
  assert.equal(k.verifyKnowledgeEvidence(digest), "unavailable");
  assert.equal(k.verifyKnowledgeEvidence(undefined, bytes), "unchecked");
  assert.throws(
    () => store({ maxEnvelopeBytes: 100 }).submit(env("original")),
    code("payload_too_large"),
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
    if (url.pathname === "/custom/events" && init?.method === "POST")
      return json(engine.submit(body as k.KnowledgeEnvelope));
    if (url.pathname.startsWith("/custom/events/"))
      return json(engine.event(url.pathname.slice("/custom/events/".length)));
    if (url.pathname === "/v1/knowledge/query")
      return json(engine.query(k.parseKnowledgeQuery(url.searchParams)));
    if (url.pathname === "/v1/knowledge/batch")
      return json(engine.batch(body as k.KnowledgeBatchRequest));
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
test("HTTP discovery uses advertised endpoints, validates results and reads without a signer", async () => {
  const engine = store(),
    calls: any[] = [],
    client = await KnowledgeClient.discover(service, transport(engine, calls));
  const original = env("text_publication"),
    second = env("text_regional");
  await client.submit(original);
  await client.submit(second);
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
  const polls = [];
  for await (const page of client.queryPages({ after_seq: 1 }))
    polls.push(page);
  assert.deepEqual(
    polls[0].result.map((r) => r.seq),
    [2],
  );
  const batch = calls.find((c) => c.url.pathname.endsWith("batch"));
  assert.deepEqual(JSON.parse(batch.init.body), {
    hashes: [second.hash, original.hash],
  });
  assert.equal(engine.checkpoint, 2);
});
test("HTTP defaults to v1 routes and never guesses optional search", async () => {
  const engine = store();
  engine.submit(env("original"));
  const calls: string[] = [];
  const client = new KnowledgeClient(service, async (input) => {
    calls.push(String(input));
    return json(engine.event(env("original").hash));
  });
  await client.event(env("original").hash);
  assert.equal(
    new URL(calls[0]).pathname,
    "/v1/knowledge/events/" + env("original").hash,
  );
  await assert.rejects(
    () => client.search({ text: "cache", mode: "lexical" }),
    code("unsupported_search_mode"),
  );
  assert.equal(calls.length, 1);
});
test("HTTP rejects duplicate JSON, tampering, wrong IDs, wrong scope, redirects and cross-origin endpoints", async () => {
  const engine = store();
  const record = engine.submit(env("original"));
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
    code("invalid_response"),
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
test("HTTP preserves structured error details", async () => {
  let calls = 0;
  const client = new KnowledgeClient(service, async () => {
    calls++;
    return new Response(
      JSON.stringify({
        error: {
          code: "missing_dependency",
          message: "fetch targets",
          data: { missing: [env("original").hash] },
        },
      }),
      { status: 409 },
    );
  });
  await assert.rejects(
    () => client.submit(env("branch_left")),
    (e: unknown) =>
      e instanceof HttpResponseError &&
      e.code === "missing_dependency" &&
      JSON.stringify(e.data) ===
        JSON.stringify({ missing: [env("original").hash] }),
  );
  assert.equal(calls, 1);
});
test("HTTP authentication is explicit, origin bound, and the caller need not be the actor", async () => {
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
  const client = new KnowledgeClient(service, async (_url, init) => {
    assert.equal(
      new Headers(init?.headers).get("authorization"),
      `Bearer ${jwt}`,
    );
    return json(engine.submit(env("original")));
  });
  assert.equal((await client.submit(env("original"), jwt)).seq, 1);
  const other = caller.signRequestJwt({
    iss: caller.agentId(),
    sub: caller.agentId(),
    aud: "https://other.example",
    iat: now,
    exp: now + 100,
  });
  await assert.rejects(() => client.submit(env("original"), other));
});
test("page tracker rejects scope drift, repeated events and changed requests", () => {
  const engine = store();
  engine.submit(env("text_publication"));
  engine.submit(env("text_regional"));
  const request: k.KnowledgeQuery = { q: "alpha", limit: 1 };
  const first = engine.query(request),
    nextRequest = { ...request, cursor: first.next_cursor },
    second = engine.query(nextRequest);
  const tracker = new k.KnowledgePageTracker(service);
  tracker.accept(request, first);
  assert.equal(tracker.checkpoint, undefined);
  assert.throws(
    () => tracker.accept(nextRequest, { ...second, as_of: second.as_of + 1 }),
    code("invalid_response"),
  );
  assert.throws(
    () => tracker.accept(nextRequest, { ...second, result: first.result }),
    code("invalid_response"),
  );
  assert.throws(
    () => tracker.accept({ ...nextRequest, q: "ALPHA" }, second),
    code("invalid_response"),
  );
  tracker.accept(nextRequest, second);
  assert.equal(tracker.complete, true);
  assert.equal(tracker.checkpoint, 2);
});
test("HTTP response verification binds the request actually sent despite caller mutation", async () => {
  const engine = store();
  engine.submit(env("text_publication"));
  engine.submit(env("text_regional"));
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
  release(json(engine.submit(env("original"))));
  assert.equal((await pendingSubmit).envelope.hash, env("original").hash);
});
test("HTTP rejects alternate success statuses and omits ambient credentials", async () => {
  const engine = store();
  const record = engine.submit(env("original"));
  const client = new KnowledgeClient(service, async (_input, init) => {
    assert.equal(init?.credentials, "omit");
    return new Response(JSON.stringify(record), { status: 201 });
  });
  await assert.rejects(
    () => client.event(record.envelope.hash),
    code("invalid_response"),
  );
});
test("batch and search responses reject duplicate events", () => {
  const engine = store();
  const first = engine.submit(env("text_publication"));
  const second = engine.submit(env("text_regional"));
  const hashes = [second.envelope.hash, first.envelope.hash];
  const batch = engine.batch({ hashes });
  // Caller-selected batch order and ranked search order may decrease in seq.
  k.validateKnowledgeBatchResponse(batch, hashes, service);
  batch.result[1] = batch.result[0];
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
  response.result[1] = response.result[0];
  assert.throws(
    () => k.validateKnowledgeSearchResponse(response, request, service),
    code("invalid_response"),
  );
});
