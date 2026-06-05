import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner } from "./identity.js";
import {
  ProfileUpdatePayload,
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
  assert.equal(profile.username, undefined);
  assert.deepEqual(profile.links, payload.links);
  assert.deepEqual(profile.extra, payload.extra);
  assert.equal(profile.updated_at, 1_779_753_600_000);
  assert.equal(profile.event_id, envelope.hash);
});

test("does not materialize unconfirmed payload username", () => {
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
  assert.equal(profile.username, undefined);
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
