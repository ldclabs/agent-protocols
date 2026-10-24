import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { AgentSigner, MemoryNonceStore, verifySubmission } from "./identity.js";
import { ProfileCache, validateProfileUpdate } from "./profile.js";
import { verifyDelegationCredential } from "./delegation.js";
import {
  TypeRegistry,
  validateRoomCreatePayload,
  validateRoomUpdatePayload,
  validateTypeDef,
  validateMessageCreatePayload,
} from "./discourse.js";
import { ProfileClient } from "./http-client.js";
import { LocalConnector } from "./local-connector.js";

const vectors = (name: string) =>
  JSON.parse(
    readFileSync(
      new URL(
        `../../../docs/protocols/agent-${name}/1.0.vectors.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  );
const identity = vectors("identity"),
  profile = vectors("profile"),
  discourse = vectors("discourse"),
  delegation = vectors("delegation");

test("shared nonce vectors protect the inclusive last live millisecond", () => {
  const c = identity.replay_boundary,
    store = new MemoryNonceStore();
  verifySubmission(c.envelope, store, {
    nowMs: c.accepted_at,
    windowMs: c.window_ms,
    nonceTtlMs: c.nonce_ttl_ms,
  });
  for (const step of c.attempts)
    assert.throws(
      () =>
        verifySubmission(c.envelope, store, {
          nowMs: step.now,
          windowMs: c.window_ms,
          nonceTtlMs: c.nonce_ttl_ms,
          isAccepted: () => false,
        }),
      { code: step.error },
    );
});

for (const c of identity.http_json)
  test(`raw HTTP JSON: ${c.name}`, async () => {
    const client = new ProfileClient(
      "https://profile.example",
      async () => new Response(Buffer.from(c.body_hex, "hex")),
    );
    if (c.valid) {
      const page = await client.profileEvents(identity.keys[0].agent_id);
      validateProfileUpdate(page.result[0]);
    } else
      await assert.rejects(client.profileEvents(identity.keys[0].agent_id), {
        code: "invalid_event",
      });
  });

test("shared Profile pins survive restart and reject rollback or nonce conflicts", () => {
  const c = profile.latest_pins;
  let cache = new ProfileCache();
  let expected: string | undefined;
  for (const step of c.steps) {
    const envelope = c.updates[step.update];
    if (step.error)
      assert.throws(() => cache.observe(envelope, c.owner), {
        code: step.error,
      });
    else {
      assert.equal(cache.observe(envelope, c.owner).hash, envelope.hash);
      expected = envelope.hash;
    }
    cache = new ProfileCache(cache.snapshot());
    assert.equal(cache.get(c.owner)?.hash, expected);
  }
});

test("latest Profile HTTP reads pin updates but historical reads remain available", async () => {
  const c = profile.latest_pins;
  const replies = [c.updates.new, c.updates.old, c.updates.old];
  const client = new ProfileClient("https://profile.example", async () =>
    Response.json({ result: [replies.shift()] }),
  );
  assert.equal(
    (await client.latestProfileUpdate(c.owner)).hash,
    c.updates.new.hash,
  );
  await assert.rejects(client.latestProfileUpdate(c.owner), {
    code: "stale_profile",
  });
  assert.equal(
    (await client.profileEvents(c.owner, 20)).result[0].hash,
    c.updates.old.hash,
  );
  assert.equal(client.profileCache.get(c.owner)?.hash, c.updates.new.hash);
});

test("connector persists Profile pins across restart", async () => {
  const c = profile.latest_pins,
    origin = "https://profile.example";
  let latest = c.updates.new;
  const fetchImpl = (async (url: string | URL) =>
    String(url).includes(".well-known")
      ? Response.json({
          protocol: "agent-profile/1.0",
          service: origin,
          endpoints: { profiles: `${origin}/profiles` },
        })
      : Response.json({ result: [latest] })) as typeof fetch;
  const signer = AgentSigner.fromSeed(
    Buffer.from(identity.keys[0].seed, "hex"),
  );
  const connector = new LocalConnector(signer, { fetchImpl });
  connector.addHost({ host: origin, allowed: true, profile_service: origin });
  await connector.callTool("agent_protocols_profiles_get", {
    profile_service: origin,
    ids: [c.owner],
  });
  const restored = LocalConnector.fromSnapshot(signer, connector.snapshot(), {
    fetchImpl,
  });
  latest = c.updates.old;
  await assert.rejects(
    restored.callTool("agent_protocols_profiles_get", {
      profile_service: origin,
      ids: [c.owner],
    }),
    { code: "stale_profile" },
  );
});

for (const c of delegation.status_checks.cases)
  test(`shared delegation status: ${c.name}`, () => {
    const scope = delegation.status_checks;
    const result = verifyDelegationCredential(
      c.credential,
      c.records,
      scope.document,
      scope.document.id,
      scope.audience,
      c.now,
    );
    assert.equal(result.verified, c.verified);
    assert.equal(result.usable, c.usable);
  });

for (const c of discourse.payload_validation)
  test(`shared ADP payload: ${c.name}`, () => {
    const registry = new TypeRegistry(),
      original = structuredClone(c.schema);
    registry.define({
      type: "review.test",
      kind: "message",
      title: "Test",
      schema: c.schema,
    });
    if (c.valid) registry.validatePayload("review.test", c.value);
    else
      assert.throws(() => registry.validatePayload("review.test", c.value), {
        code: "payload_schema_violation",
      });
    assert.deepEqual(c.schema, original);
  });

test("shared ADP blank-string semantics cover create/update/title/content type", () => {
  for (const c of discourse.blank_strings) {
    const checks = [
      () =>
        validateRoomCreatePayload({
          host: "https://host.example",
          topic: c.value,
          visibility: "public",
          start_time: 1000,
          end_time: 2000,
        }),
      () => validateRoomUpdatePayload({ topic: c.value }),
      () =>
        validateTypeDef({
          type: "review.blank",
          kind: "message",
          title: c.value,
          schema: {},
        }),
      () =>
        validateMessageCreatePayload({
          content_type: c.value,
          content: "test",
        }),
    ];
    for (const check of checks) {
      if (c.valid) assert.doesNotThrow(check);
      else assert.throws(check);
    }
  }
});

test("shared ADP pack rejection leaves the registry unchanged", () => {
  const c = discourse.atomic_import,
    registry = new TypeRegistry();
  registry.define(c.initial);
  const before = structuredClone(registry.definitions());
  assert.throws(() => registry.apply(c.declaration, { [c.pack.id]: c.pack }), {
    code: c.error,
  });
  assert.deepEqual(registry.definitions(), before);
});

test("connector evaluates delegation freshness after history arrives", async (t) => {
  const scope = delegation.status_checks,
    c = scope.cases[0],
    origin = "https://principal.example";
  let now = c.now;
  t.mock.method(Date, "now", () => now);
  const fetchImpl = (async (url: string | URL) => {
    const target = String(url);
    if (target === scope.document.id) return Response.json(scope.document);
    if (target.includes(".well-known"))
      return Response.json({
        protocol: "agent-delegation/1.0",
        service: origin,
        endpoints: {
          delegations: `${origin}/v1/delegations`,
          query: `${origin}/v1/delegations/query`,
        },
      });
    if (target.endsWith("/query"))
      return Response.json({ result: [c.credential] });
    if (target.includes("/events")) {
      now = c.now + 300001;
      return Response.json({ result: c.records });
    }
    throw new Error("unexpected request");
  }) as typeof fetch;
  const signer = AgentSigner.fromSeed(
    Buffer.from(identity.keys[0].seed, "hex"),
  );
  const connector = new LocalConnector(signer, { fetchImpl });
  connector.addHost({ host: origin, allowed: true });
  const result: any = await connector.callTool(
    "agent_protocols_delegation_check",
    {
      principal_id: scope.document.id,
      subject: c.credential.subject,
      audience: scope.audience,
    },
  );
  assert.equal(result.delegations[0].verified, true);
  assert.equal(result.delegations[0].usable, false);
});
