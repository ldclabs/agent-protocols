import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  PROFILE_PROTOCOL,
  PROFILE_UPDATE,
  ProfileUpdatePayload,
  latestProfileUpdate,
  materializeProfile,
  profileUpdateEvent,
  validateProfileUpdate,
} from "./profile.js";

test("materializes valid profile updates", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(11));
  const payload: ProfileUpdatePayload = {
    id: signer.agentId(),
    name: "ResearchAgent-v3",
    capabilities: ["research"],
    extra: { domain: "research" },
    links: [
      {
        name: "Homepage",
        url: "https://example.com",
        rel: "homepage",
      },
    ],
  };
  const envelope = signer.signEvent(
    profileUpdateEvent(signer.agentId(), 1_779_753_600_000, 1, payload),
  );

  const profile = materializeProfile(envelope);

  assert.equal(profile.id, signer.agentId());
  assert.equal(profile.name, "ResearchAgent-v3");
  assert.ok(!("username" in profile));
  assert.deepEqual(profile.links, payload.links);
  assert.deepEqual(profile.extra, payload.extra);
  assert.equal(profile.updated_at, 1_779_753_600_000);
  assert.equal(profile.event_id, envelope.hash);
});

test("does not materialize the removed username field", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(15));
  const payload: ProfileUpdatePayload = {
    id: signer.agentId(),
    name: "ResearchAgent-v3",
    username: "anda",
  } as unknown as ProfileUpdatePayload;
  const envelope = signer.signEvent(
    profileUpdateEvent(signer.agentId(), 1_779_753_600_002, 1, payload),
  );

  const profile = materializeProfile(envelope);

  assert.equal(profile.id, signer.agentId());
  assert.ok(!("username" in profile));
});

test("latestProfileUpdate picks the accepted update with the greatest nonce", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(16));
  const envelopes = [3, 1, 2].map((nonce) =>
    signer.signEvent(
      profileUpdateEvent(signer.agentId(), 1_779_753_600_000 + nonce, nonce, {
        id: signer.agentId(),
        name: `Agent-v${nonce}`,
      }),
    ),
  );

  assert.equal(latestProfileUpdate([]), undefined);
  const latest = latestProfileUpdate(envelopes);
  assert.equal(latest?.event.nonce, 3);
  assert.equal(materializeProfile(latest!).name, "Agent-v3");
});

test("rejects profile actor mismatch", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(12));
  const other = AgentSigner.fromSeed(new Uint8Array(32).fill(13));
  const payload: ProfileUpdatePayload = {
    id: other.agentId(),
    name: "Imposter",
  };
  const envelope = signer.signEvent(
    profileUpdateEvent(signer.agentId(), 1_779_753_600_000, 1, payload),
  );

  assert.throws(() => validateProfileUpdate(envelope), /actor/);
});

test("rejects legacy agent_id payloads without id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const envelope = signer.signEvent(
    profileUpdateEvent(signer.agentId(), 1_779_753_600_001, 1, {
      agent_id: signer.agentId(),
      name: "LegacyAgent",
    } as unknown as ProfileUpdatePayload),
  );

  assert.throws(() => materializeProfile(envelope), /payload\.id|actor/);
});

test("rejects wrong protocol and event type", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(19));
  const payload: ProfileUpdatePayload = {
    id: signer.agentId(),
    name: "ResearchAgent",
  };

  const wrongProtocol = signer.signEvent(
    createEvent("agent-discourse/1.0", PROFILE_UPDATE, signer.agentId(), 1, 1, payload),
  );
  assert.throws(
    () => validateProfileUpdate(wrongProtocol),
    /got agent-discourse/,
  );

  const wrongType = signer.signEvent(
    createEvent(PROFILE_PROTOCOL, "profile.delete", signer.agentId(), 1, 1, payload),
  );
  assert.throws(() => validateProfileUpdate(wrongType), /got profile.delete/);
});

test("materializes payloads that carry every optional collection", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(20));
  const payload: ProfileUpdatePayload = {
    id: signer.agentId(),
    name: "FullAgent",
    description: "desc",
    avatar_url: "https://example.com/a.png",
    provider: "did:agent:provider",
    capabilities: ["research"],
    service_endpoints: [{ type: "a2a", url: "https://example.com" }],
    links: [{ name: "Home", url: "https://example.com", rel: "homepage" }],
    delegations: [
      {
        id: "del_1",
        principal: {
          id: "https://api.al.ink/d9c6a99cne5g00a6scn0",
          type: "person",
          name: "Yan",
        },
        relationship: "primary_delegate",
        scopes: ["inbox.screen"],
      },
    ],
    extra: { domain: "research" },
  };
  const profile = materializeProfile(
    signer.signEvent(profileUpdateEvent(signer.agentId(), 1, 1, payload)),
  );
  assert.deepEqual(profile.service_endpoints, payload.service_endpoints);
  assert.deepEqual(profile.capabilities, payload.capabilities);
  assert.deepEqual(profile.delegations, payload.delegations);
});
