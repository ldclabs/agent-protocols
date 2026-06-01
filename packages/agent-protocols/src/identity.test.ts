import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentSigner,
  MemoryNonceStore,
  createEvent,
  createRequestBinding,
  createRequestJwtClaims,
  verifyEnvelope,
  verifyLiveEnvelope,
  verifyRequestJwtLive,
} from "./identity.js";

test("signs and verifies event envelopes", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(7));
  const event = createEvent(
    "agent-profile/1.0",
    "profile.update",
    signer.agentId(),
    1_779_753_600_000,
    "n_test",
    {
      agent_id: signer.agentId(),
      name: "ResearchAgent",
    },
  );

  const envelope = signer.signEvent(event);

  assert.match(envelope.event_id, /^evt_z/);
  assert.doesNotThrow(() => verifyEnvelope(envelope));
});

test("rejects tampered payloads", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(8));
  const envelope = signer.signEvent(
    createEvent(
      "agent-profile/1.0",
      "profile.update",
      signer.agentId(),
      1000,
      "n_test",
      { name: "before" },
    ),
  );
  envelope.event.payload = { name: "after" };

  assert.throws(() => verifyEnvelope(envelope), /invalid event id|signature/i);
});

test("rejects nonce reuse", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(9));
  const envelope = signer.signEvent(
    createEvent(
      "agent-profile/1.0",
      "profile.update",
      signer.agentId(),
      1000,
      "n_reused",
      { name: "ResearchAgent" },
    ),
  );
  const store = new MemoryNonceStore();

  assert.doesNotThrow(() =>
    verifyLiveEnvelope(envelope, store, { nowMs: 1000, windowMs: 1000 }),
  );
  assert.throws(
    () => verifyLiveEnvelope(envelope, store, { nowMs: 1000, windowMs: 1000 }),
    /nonce/,
  );
});

test("signs and verifies request JWTs", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(10));
  const binding = createRequestBinding("https://api.example.com");
  const claims = createRequestJwtClaims(
    signer.agentId(),
    binding,
    100,
    300,
    "jwt_nonce",
  );
  const token = signer.signRequestJwt(claims);
  const store = new MemoryNonceStore();

  const verified = verifyRequestJwtLive(
    token,
    { ...binding, nowSecs: 120, maxTtlSecs: 300 },
    store,
  );

  assert.equal(verified.jti, "jwt_nonce");
  assert.throws(
    () =>
      verifyRequestJwtLive(
        token,
        { ...binding, nowSecs: 120, maxTtlSecs: 300 },
        store,
      ),
    /nonce/,
  );
});
