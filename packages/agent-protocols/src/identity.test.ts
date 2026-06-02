import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentSigner,
  ClientNonceManager,
  MemoryNonceStore,
  createEvent,
  createRequestBinding,
  createRequestJwtClaims,
  verifyEnvelope,
  verifyLiveEnvelope,
  verifyRequestJwt,
} from "./identity.js";

test("signs and verifies event envelopes", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(7));
  const event = createEvent(
    "agent-profile/1.0",
    "profile.update",
    signer.agentId(),
    1_779_753_600_000,
    1,
    {
      agent_id: signer.agentId(),
      name: "ResearchAgent",
    },
  );

  const envelope = signer.signEvent(event);

  assert.equal(envelope.hash.length, 43);
  assert.ok(!envelope.hash.startsWith("evt_"));
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
      1,
      { name: "before" },
    ),
  );
  envelope.event.payload = { name: "after" };

  assert.throws(
    () => verifyEnvelope(envelope),
    /invalid event hash|signature/i,
  );
});

test("rejects nonce reuse", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(9));
  const envelope = signer.signEvent(
    createEvent(
      "agent-profile/1.0",
      "profile.update",
      signer.agentId(),
      1000,
      1,
      { name: "ResearchAgent" },
    ),
  );
  const store = new MemoryNonceStore();

  assert.equal(
    verifyLiveEnvelope(envelope, store, { nowMs: 1000, windowMs: 1000 }),
    1,
  );
  assert.throws(
    () => verifyLiveEnvelope(envelope, store, { nowMs: 1000, windowMs: 1000 }),
    /nonce/,
  );
});

test("client nonce manager observes server max", () => {
  const manager = new ClientNonceManager();

  assert.equal(manager.nextNonce(), 1);
  manager.observeMaxNonce("5");

  assert.equal(manager.peek(), 6);
  assert.equal(manager.nextNonce(), 6);
});

test("signs and verifies request JWTs", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(10));
  const binding = createRequestBinding("https://api.example.com");
  const claims = createRequestJwtClaims(signer.agentId(), binding, 100, 300);
  const token = signer.signRequestJwt(claims);

  const verified = verifyRequestJwt(token, {
    ...binding,
    nowSecs: 120,
    maxTtlSecs: 300,
  });

  assert.equal(verified.iss, signer.agentId());
});
