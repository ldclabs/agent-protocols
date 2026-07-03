import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  DELEGATION_GRANT,
  DELEGATION_PROTOCOL,
  DELEGATION_REVOKE,
  DelegationGrantPayload,
  delegationGrantEvent,
  delegationRevokeEvent,
  materializeDelegationCredential,
  validateDelegationEnvelope,
  validateDelegationGrantPayload,
  validatePrincipalDocument,
} from "./delegation.js";

test("validates and materializes delegation grant events", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(31));
  const subject = AgentSigner.fromSeed(new Uint8Array(32).fill(32));
  const payload: DelegationGrantPayload = {
    id: "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
    principal: {
      id: "https://al.ink/yan",
      type: "person",
      name: "Yan",
    },
    subject: subject.agentId(),
    relationship: "primary_delegate",
    scopes: ["inbox.screen", "meeting.propose"],
    constraints: { requires_human_approval: ["meeting.accept"] },
    not_before: 1_779_753_600_000,
    expires_at: 1_790_000_000_000,
  };
  const envelope = controller.signEvent(
    delegationGrantEvent(controller.agentId(), 1_779_753_600_000, 1, payload),
  );

  assert.doesNotThrow(() => validateDelegationEnvelope(envelope));
  const credential = materializeDelegationCredential(envelope, {
    statusUrl: "https://al.ink/v1/delegations/del/status",
  });

  assert.equal(credential.protocol, DELEGATION_PROTOCOL);
  assert.equal(credential.controller, controller.agentId());
  assert.equal(credential.subject, subject.agentId());
  assert.equal(credential.status, "active");
  assert.equal(credential.event_id, envelope.hash);
});

test("validates revocation events and rejects invalid payloads", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(33));
  const envelope = controller.signEvent(
    delegationRevokeEvent(controller.agentId(), 1_779_753_700_000, 2, {
      id: "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
      principal_id: "https://al.ink/yan",
      reason: "rotated_primary_agent",
    }),
  );

  assert.equal(envelope.event.type, DELEGATION_REVOKE);
  assert.doesNotThrow(() => validateDelegationEnvelope(envelope));
  assert.throws(
    () =>
      validateDelegationGrantPayload({
        id: "del",
        principal: { id: "http://example.com" },
        subject: controller.agentId(),
        scopes: [],
      }),
    /HTTPS|scopes/,
  );
});

test("validates principal documents and event protocol", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(34));
  assert.doesNotThrow(() =>
    validatePrincipalDocument({
      id: "https://profiles.example.com/org/acme",
      controllers: [controller.agentId()],
      delegations_url: "https://profiles.example.com/v1/delegations/query",
    }),
  );
  assert.throws(() =>
    validatePrincipalDocument({
      id: "https://profiles.example.com/org/acme",
      controllers: [],
    }),
  );

  const wrong = controller.signEvent(
    createEvent(DELEGATION_PROTOCOL, "delegation.unknown", controller.agentId(), 1, 1, {
      id: "del",
    }),
  );
  assert.throws(() => validateDelegationEnvelope(wrong as never), /delegation\.grant/);

  const valid = controller.signEvent(
    delegationGrantEvent(controller.agentId(), 1, 1, {
      id: "del",
      principal: { id: "https://example.com/p" },
      subject: controller.agentId(),
      scopes: ["scope"],
    }),
  );
  assert.equal(valid.event.type, DELEGATION_GRANT);
});

test("rejects malformed HTTPS-like principal URLs", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(35));
  for (const principalId of ["https://", "https://[::1", "http://example.com"]) {
    assert.throws(() =>
      validateDelegationGrantPayload({
        id: "del",
        principal: { id: principalId },
        subject: signer.agentId(),
        scopes: ["scope"],
      }),
    );
  }
});
