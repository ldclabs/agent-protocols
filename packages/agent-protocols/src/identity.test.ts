import assert from "node:assert/strict";
import test from "node:test";

import nacl from "tweetnacl";

import { AgentProtocolError } from "./errors.js";
import { serviceOrigin } from "./identity.js";

import {
  AGENT_ID_PREFIX,
  AgentSigner,
  ClientNonceManager,
  DEFAULT_LIVE_WRITE_WINDOW_MS,
  MAX_SAFE_NONCE,
  MemoryNonceStore,
  agentIdFromPublicKey,
  canonicalEventBytes,
  createEvent,
  createRequestBinding,
  createRequestJwtClaims,
  eventHash,
  eventHashBytes,
  publicKeyBytes,
  signEvent,
  signEventHash,
  unixTimeMillis,
  unixTimeSecs,
  validateAgentId,
  verifyEnvelope,
  verifyEventHashSignature,
  verifyLiveEnvelope,
  verifyRequestJwt,
  verifyTimestamp,
  withMention,
  withRoomHead,
  withRoomId,
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
      id: signer.agentId(),
      name: "ResearchAgent",
    },
  );

  const envelope = signer.signEvent(event);

  assert.equal(envelope.hash.length, 43);
  assert.ok(!envelope.hash.startsWith("evt_"));
  assert.doesNotThrow(() => verifyEnvelope(envelope));
});

test("signs and verifies raw event hash bytes", () => {
  const seed = new Uint8Array(32).fill(18);
  const signer = AgentSigner.fromSeed(seed);
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  const event = createEvent(
    "agent-profile/1.0",
    "profile.update",
    signer.agentId(),
    1_779_753_600_000,
    1,
    { id: signer.agentId(), name: "ResearchAgent" },
  );

  const digest = eventHashBytes(event);
  const signature = signEventHash(keyPair.secretKey, digest);

  assert.equal(signer.signEvent(event).signature, signature);
  assert.doesNotThrow(() =>
    verifyEventHashSignature(signer.publicKey(), digest, signature),
  );
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

test("rejects nonce values outside the safe JSON integer range", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(16));

  assert.throws(
    () =>
      createEvent(
        "agent-profile/1.0",
        "profile.update",
        signer.agentId(),
        1000,
        MAX_SAFE_NONCE + 1,
        { id: signer.agentId(), name: "ResearchAgent" },
      ),
    /nonce/,
  );
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

test("rejects request JWTs with non-positive ttl", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(17));
  const binding = createRequestBinding("https://api.example.com");
  const claims = createRequestJwtClaims(signer.agentId(), binding, 100, 0);
  const token = signer.signRequestJwt(claims);

  assert.throws(
    () =>
      verifyRequestJwt(token, {
        ...binding,
        nowSecs: 100,
        maxTtlSecs: 300,
      }),
    /exp/,
  );
});

test("AgentSigner generates keys and rejects malformed seeds", () => {
  const signer = AgentSigner.generate();
  assert.ok(signer.agentId().startsWith(AGENT_ID_PREFIX));
  assert.equal(signer.publicKey().byteLength, 32);
  assert.throws(() => AgentSigner.fromSeed(new Uint8Array(16)), /32 bytes/);
});

test("signRequestJwt rejects claims for a different agent", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(40));
  const other = AgentSigner.fromSeed(new Uint8Array(32).fill(41));
  assert.throws(
    () =>
      signer.signRequestJwt(
        createRequestJwtClaims(
          other.agentId(),
          createRequestBinding("https://api.example.com"),
          100,
          300,
        ),
      ),
    /iss and sub/,
  );
});

test("agent id helpers validate prefix, length, and encoding", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(42));
  const agentId = signer.agentId();
  assert.equal(agentIdFromPublicKey(signer.publicKey()), agentId);
  assert.deepEqual(publicKeyBytes(agentId), signer.publicKey());
  assert.equal(validateAgentId(agentId), agentId);

  assert.throws(() => agentIdFromPublicKey(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => publicKeyBytes("did:web:example"), /did:agent:/);
  assert.throws(() => publicKeyBytes(`${AGENT_ID_PREFIX}!!!`), /base64url/);
  assert.throws(() => publicKeyBytes(`${AGENT_ID_PREFIX}AAAA`), /32 bytes/);
  // A non-string agent id yields a clean protocol error, not a raw TypeError.
  assert.throws(
    () => publicKeyBytes({ not: "a string" } as unknown as string),
    (error: unknown) =>
      error instanceof AgentProtocolError && /must be a string/.test(error.message),
  );
});

test("createEvent and room helpers build room-scoped events", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(43));
  const target = AgentSigner.fromSeed(new Uint8Array(32).fill(44));
  const event = createEvent(
    "agent-discourse/1.0",
    "message.create",
    signer.agentId(),
    1000,
    1,
    { content: "hi" },
  );
  assert.equal(withRoomId(event, "room1").room_id, "room1");
  const roomEvent = withMention(
    withRoomHead(withRoomId(event, "room1"), 1, "room-create-head"),
    target.agentId(),
  );
  assert.equal(roomEvent.base_seq, 1);
  assert.equal(roomEvent.base_hash, "room-create-head");
  assert.deepEqual(roomEvent.mentions, [target.agentId()]);
  assert.doesNotThrow(() => verifyEnvelope(signer.signEvent(roomEvent)));
  assert.throws(() => withRoomHead(event, 0, "head"), /nonce|base_seq/);
  assert.throws(() => withMention(event, "bad-agent"), /did:agent:/);
  assert.throws(() => createEvent("p", "t", "bad-actor", 1, 1, {}), /did:agent:/);
});

test("free signEvent and eventHash match the signer", () => {
  const seed = new Uint8Array(32).fill(44);
  const signer = AgentSigner.fromSeed(seed);
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  const event = createEvent("p", "t", signer.agentId(), 1000, 1, { a: 1 });

  assert.equal(signEvent(keyPair.secretKey, event), signer.signEvent(event).signature);
  assert.equal(eventHash(event), signer.signEvent(event).hash);
});

test("signEventHash and verifyEventHashSignature enforce byte lengths", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(45));
  const event = createEvent("p", "t", signer.agentId(), 1000, 1, { a: 1 });
  const digest = eventHashBytes(event);
  const signature = signEventHash(
    nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(45)).secretKey,
    digest,
  );

  assert.throws(() => signEventHash(new Uint8Array(10), digest), /64 bytes/);
  assert.throws(
    () => signEventHash(new Uint8Array(64), new Uint8Array(10)),
    /event hash must be 32 bytes/,
  );
  assert.throws(
    () => verifyEventHashSignature(new Uint8Array(31), digest, signature),
    /public key must be 32 bytes/,
  );
  assert.throws(
    () => verifyEventHashSignature(signer.publicKey(), digest, "AAAA"),
    /signature must be 64 bytes/,
  );
  const other = AgentSigner.fromSeed(new Uint8Array(32).fill(46));
  assert.throws(
    () => verifyEventHashSignature(other.publicKey(), digest, signature),
    /verification failed/,
  );
});

test("verifyTimestamp enforces the live-write window", () => {
  assert.doesNotThrow(() => verifyTimestamp(1000, 1200, 1000));
  assert.throws(() => verifyTimestamp(0, 1_000_000, 1000), /window/);
  assert.throws(() => verifyTimestamp(100, 100, -1), /window/);
});

test("verifyLiveEnvelope falls back to the real clock", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(47));
  const envelope = signer.signEvent(
    createEvent("p", "t", signer.agentId(), unixTimeMillis(), 1, { a: 1 }),
  );
  assert.equal(verifyLiveEnvelope(envelope, new MemoryNonceStore()), 1);
});

test("MemoryNonceStore tracks ttl, reuse, and expiry", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(48));
  const actor = signer.agentId();
  const store = new MemoryNonceStore();

  assert.throws(() => store.checkAndUpdate(actor, 1, 1000, -1), /ttl/);
  assert.equal(store.checkAndUpdate(actor, 4, 1000, 1000), 4);
  // a strictly greater nonce is accepted while the record is live
  assert.equal(store.checkAndUpdate(actor, 5, 1100, 1000), 5);
  assert.equal(store.maxNonce(actor, 1500), 5);
  assert.equal(store.maxNonce(actor, 5000), undefined);
  assert.equal(store.maxNonce("did:agent:none", 1500), undefined);
});

test("ClientNonceManager validates seeds and observed values", () => {
  assert.throws(() => new ClientNonceManager(0), /nonce/);
  const manager = new ClientNonceManager(5);
  assert.equal(manager.peek(), 5);

  manager.observeMaxNonce(null);
  manager.observeMaxNonce(undefined);
  manager.observeMaxNonce("");
  assert.equal(manager.peek(), 5);
  manager.observeMaxNonce(9);
  assert.equal(manager.peek(), 10);
  manager.observeMaxNonce(3); // lower values are ignored
  assert.equal(manager.peek(), 10);
  assert.throws(() => manager.observeMaxNonce("not-a-number"), /nonce/);
});

test("time helpers return positive values", () => {
  assert.ok(unixTimeMillis() > 0);
  assert.ok(unixTimeSecs() > 0);
  assert.ok(unixTimeMillis() >= unixTimeSecs() * 1000);
});

function encodeToken(header: unknown, claims: unknown): string {
  const part = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part(header)}.${part(claims)}.${Buffer.alloc(64).toString("base64url")}`;
}

test("verifyRequestJwt rejects malformed headers and claims", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(49));
  const agentId = signer.agentId();
  const other = AgentSigner.fromSeed(new Uint8Array(32).fill(50)).agentId();
  const context = {
    audience: "https://api.example.com",
    nowSecs: 200,
    maxTtlSecs: 300,
  };
  const claims = {
    iss: agentId,
    sub: agentId,
    aud: "https://api.example.com",
    iat: 100,
    exp: 400,
  };

  assert.throws(() => verifyRequestJwt("only.two", context), /three compact/);
  assert.throws(
    () => verifyRequestJwt(encodeToken({ alg: "HS256", typ: "JWT", kid: agentId }, claims), context),
    /alg/,
  );
  assert.throws(
    () => verifyRequestJwt(encodeToken({ alg: "EdDSA", typ: "JWS", kid: agentId }, claims), context),
    /typ/,
  );
  assert.throws(
    () => verifyRequestJwt(encodeToken({ alg: "EdDSA", typ: "JWT", kid: other }, claims), context),
    /kid, iss, and sub/,
  );
  assert.throws(
    () => verifyRequestJwt(encodeToken({ alg: "EdDSA", typ: "JWT", kid: agentId }, claims), context),
    /signature verification failed/,
  );
});

test("verifyRequestJwt enforces audience and time window", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(51));
  const binding = createRequestBinding("https://api.example.com");

  const token = signer.signRequestJwt(
    createRequestJwtClaims(signer.agentId(), binding, 100, 300),
  );
  assert.throws(
    () => verifyRequestJwt(token, { audience: "https://other", nowSecs: 200 }),
    /aud/,
  );

  const expired = signer.signRequestJwt(
    createRequestJwtClaims(signer.agentId(), binding, 1000, 300),
  );
  assert.throws(
    () => verifyRequestJwt(expired, { ...binding, nowSecs: 5000 }),
    /time window/,
  );

  const longTtl = signer.signRequestJwt(
    createRequestJwtClaims(signer.agentId(), binding, 100, 400),
  );
  assert.throws(
    () => verifyRequestJwt(longTtl, { ...binding, nowSecs: 200, maxTtlSecs: 300 }),
    /ttl/,
  );
});

test("DEFAULT_LIVE_WRITE_WINDOW_MS is exported", () => {
  assert.equal(DEFAULT_LIVE_WRITE_WINDOW_MS, 300_000);
});

test("canonicalEventBytes rejects values without a canonical form", () => {
  assert.throws(
    () => canonicalEventBytes(undefined as never),
    /canonical JSON/,
  );
});

test("base64url decoding rejects non-canonical encodings", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(60));
  const agentId = signer.agentId();
  const suffix = agentId.slice("did:agent:".length);

  // Canonical form round-trips.
  validateAgentId(agentId);

  // Padding characters are rejected even when the decoded bytes match.
  assert.throws(
    () => validateAgentId(`did:agent:${suffix}==`),
    /canonical base64url/,
  );
  // Non-zero trailing bits give the same key a second string form: replace
  // the final character with one sharing its used bits but different trailing
  // bits (the last base64url char of a 32-byte value uses 4 of its 6 bits).
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const lastIndex = alphabet.indexOf(suffix.slice(-1));
  const nonCanonicalLast = alphabet[(lastIndex & ~3) | ((lastIndex & 3) ^ 1)];
  assert.throws(
    () =>
      validateAgentId(`did:agent:${suffix.slice(0, -1)}${nonCanonicalLast}`),
    /canonical base64url/,
  );
  // Non-alphabet characters are rejected.
  assert.throws(
    () => validateAgentId(`did:agent:${suffix.slice(0, -1)}+`),
    /canonical base64url/,
  );

  // Signatures must be canonical base64url too.
  const event = createEvent(
    "agent-profile/1.0",
    "profile.update",
    agentId,
    1000,
    1,
    { id: agentId, name: "Agent" },
  );
  const envelope = signer.signEvent(event);
  assert.throws(
    () =>
      verifyEnvelope({
        ...envelope,
        signature: `${envelope.signature}=`,
      }),
    /canonical base64url/,
  );
});

test("serviceOrigin derives the request JWT audience from a URL", () => {
  assert.equal(
    serviceOrigin("https://api.example.com/v1/rooms/room1"),
    "https://api.example.com",
  );
  assert.equal(
    serviceOrigin("https://api.example.com:8443/path?q=1"),
    "https://api.example.com:8443",
  );
  assert.equal(
    serviceOrigin("https://API.Example.com:443/"),
    "https://api.example.com",
  );
  assert.throws(() => serviceOrigin("not a url"), /valid URL/);
  assert.throws(() => serviceOrigin("ftp://example.com"), /HTTP/);
});

test("nonce_not_greater errors carry the effective maximum for Max-Seen-Nonce", () => {
  const actor = AgentSigner.fromSeed(new Uint8Array(32).fill(61)).agentId();
  const store = new MemoryNonceStore();
  store.checkAndUpdate(actor, 7, 1000, 1000);
  try {
    store.checkAndUpdate(actor, 7, 1100, 1000);
    assert.fail("expected nonce_not_greater");
  } catch (error) {
    const protocolFailure = error as AgentProtocolError;
    assert.equal(protocolFailure.code, "nonce_not_greater");
    assert.deepEqual(protocolFailure.data, { max_nonce: 7 });
  }
});
