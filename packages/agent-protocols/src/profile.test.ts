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
    agent_id: signer.agentId(),
    name: "ResearchAgent-v3",
    capabilities: ["research"],
  };
  const envelope = signer.signEvent(
    profileUpdateEvent(
      signer.agentId(),
      1_779_753_600_000,
      "n_profile",
      payload,
    ),
  );

  const profile = materializeProfile(envelope);

  assert.equal(profile.name, "ResearchAgent-v3");
  assert.equal(profile.updated_at, 1_779_753_600_000);
  assert.equal(profile.profile_event_id, envelope.event_id);
});

test("rejects profile actor mismatch", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(12));
  const other = AgentSigner.fromSeed(new Uint8Array(32).fill(13));
  const payload: ProfileUpdatePayload = {
    agent_id: other.agentId(),
    name: "Imposter",
  };
  const envelope = signer.signEvent(
    profileUpdateEvent(
      signer.agentId(),
      1_779_753_600_000,
      "n_profile",
      payload,
    ),
  );

  assert.throws(() => validateProfileUpdate(envelope), /actor/);
});
