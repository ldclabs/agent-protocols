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

test("rejects the removed username field: the payload is closed", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(15));
  const payload: ProfileUpdatePayload = {
    id: signer.agentId(),
    name: "ResearchAgent-v3",
    username: "anda",
  } as unknown as ProfileUpdatePayload;
  const envelope = signer.signEvent(
    profileUpdateEvent(signer.agentId(), 1_779_753_600_002, 1, payload),
  );

  assert.throws(() => materializeProfile(envelope), /undefined profile field: username/);
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

test("profile updates must exceed the latest accepted nonce and carry no extra event fields", async () => {
  const { validateProfileSuccession, validateProfileUpdate, profileUpdateEvent } = await import("./profile.js");
  const { AgentSigner } = await import("./identity.js");
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(90));
  const envelope = signer.signEvent(profileUpdateEvent(signer.agentId(), 1_000, 7, { id: signer.agentId(), name: "A" }));
  validateProfileSuccession(envelope, undefined);
  validateProfileSuccession(envelope, 6);
  for (const latest of [7, 8]) {
    assert.throws(() => validateProfileSuccession(envelope, latest), (error: unknown) =>
      (error as { code: string; data: { max_nonce: number } }).code === "nonce_not_greater" &&
      (error as { data: { max_nonce: number } }).data.max_nonce === latest);
  }
  const extra = signer.signEvent({ ...profileUpdateEvent(signer.agentId(), 1_000, 8, { id: signer.agentId(), name: "A" }), room_id: "r" });
  assert.throws(() => validateProfileUpdate(extra), /unknown event field: room_id/);
});

const profileVectors = JSON.parse(
  (await import("node:fs")).readFileSync(
    new URL("../../../docs/protocols/agent-profile/1.0.vectors.json", import.meta.url),
    "utf8",
  ),
);

test("profile vectors: payloads are accepted and rejected as listed", async () => {
  const { validateProfilePayload } = await import("./profile.js");
  for (const vector of profileVectors.payloads.valid) validateProfilePayload(vector.payload, vector.actor);
  for (const vector of profileVectors.payloads.invalid) {
    assert.throws(() => validateProfilePayload(vector.payload, vector.actor), vector.name);
  }
});

test("profile vectors: history materializes the greatest nonce", async () => {
  const { latestProfileUpdate, validateProfileUpdate } = await import("./profile.js");
  const envelopes = profileVectors.history.envelopes;
  for (const envelope of envelopes) validateProfileUpdate(envelope);
  const document = materializeProfile(latestProfileUpdate(envelopes)!) as unknown as Record<string, unknown>;
  for (const [field, expected] of Object.entries(profileVectors.history.latest)) {
    assert.deepEqual(document[field], expected, field);
  }
});

test("profile vectors: explicit empty arrays and objects verify and materialize as signed", async () => {
  const { validateProfileUpdate } = await import("./profile.js");
  const { envelope, document } = profileVectors.explicit_empty;
  validateProfileUpdate(envelope);
  const materialized = materializeProfile(envelope) as unknown as Record<string, unknown>;
  for (const [field, expected] of Object.entries(document)) assert.deepEqual(materialized[field], expected, field);
});
