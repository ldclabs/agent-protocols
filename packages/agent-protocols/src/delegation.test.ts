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
  isPrincipalAlias,
  materializeDelegationCredential,
  validateDelegationEnvelope,
  validateDelegationGrantPayload,
  validateDelegationQueryRequest,
  validatePrincipalDocument,
  validatePrincipalResolution,
} from "./delegation.js";

test("validates and materializes delegation grant events", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(31));
  const subject = AgentSigner.fromSeed(new Uint8Array(32).fill(32));
  const payload: DelegationGrantPayload = {
    id: "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
    principal: {
      id: "https://api.al.ink/d9c6a99cne5g00a6scn0",
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
  const credential = materializeDelegationCredential(envelope);

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
      principal_id: "https://api.al.ink/d9c6a99cne5g00a6scn0",
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
      aliases: ["https://profiles.example.com/acme"],
      delegation_query_url: "https://profiles.example.com/v1/delegations/query",
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

test("grant expiry is checked against not_before and created_at separately", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(45));
  const subject = AgentSigner.fromSeed(new Uint8Array(32).fill(46));
  const base: DelegationGrantPayload = {
    id: "del_1",
    principal: { id: "https://api.al.ink/d9c6a99cne5g00a6scn0" },
    subject: subject.agentId(),
    scopes: ["inbox.screen"],
  };

  // expires_at must be greater than not_before when both are present.
  assert.throws(
    () =>
      validateDelegationGrantPayload(
        { ...base, not_before: 2000, expires_at: 2000 },
        1000,
      ),
    /greater than not_before/,
  );
  // expires_at must be greater than created_at even when not_before is absent.
  assert.throws(
    () => validateDelegationGrantPayload({ ...base, expires_at: 1000 }, 1000),
    /greater than created_at/,
  );
  // And also when not_before is present and already satisfied.
  assert.throws(
    () =>
      validateDelegationGrantPayload(
        { ...base, not_before: 500, expires_at: 800 },
        1000,
      ),
    /greater than created_at/,
  );
  validateDelegationGrantPayload(
    { ...base, not_before: 500, expires_at: 1500 },
    1000,
  );
  assert.equal(controller.agentId().startsWith("did:agent:"), true);
});

test("public delegation queries are existence checks over both subject and principal_id", () => {
  const subject = AgentSigner.fromSeed(new Uint8Array(32).fill(47)).agentId();
  const principal_id = "https://api.al.ink/d9c6a99cne5g00a6scn0";
  validateDelegationQueryRequest({ subject, principal_id, limit: 20 });

  // Enumerating one side is not a public query.
  for (const request of [{ subject }, { principal_id }]) {
    assert.throws(
      () => validateDelegationQueryRequest(request),
      /must include both subject and principal_id/,
    );
    validateDelegationQueryRequest(request, { allowEnumeration: true });
  }
  assert.throws(
    () => validateDelegationQueryRequest({ status: "active" }, { allowEnumeration: true }),
    /at least one of subject or principal_id/,
  );
  assert.throws(
    () => validateDelegationQueryRequest({ subject, principal_id, limit: 0 }),
    /positive integer/,
  );
  assert.throws(
    () => validateDelegationQueryRequest({ subject, principal_id: "http://al.ink/yan" }),
    /HTTPS/,
  );
});

test("principal documents bind controllers only when read at their own id", () => {
  const controller = AgentSigner.fromSeed(new Uint8Array(32).fill(48));
  const document = {
    id: "https://api.al.ink/d9c6a99cne5g00a6scn0",
    controllers: [controller.agentId()],
    aliases: ["https://al.ink/yan"],
  };

  validatePrincipalResolution(document, "https://api.al.ink/d9c6a99cne5g00a6scn0");
  // A copy served away from its identifier carries no authority.
  assert.throws(
    () => validatePrincipalResolution(document, "https://impostor.example.com/yan"),
    /was served at/,
  );

  assert.equal(isPrincipalAlias(document, "https://al.ink/yan"), true);
  assert.equal(isPrincipalAlias(document, "https://impostor.example.com/yan"), false);
  assert.equal(isPrincipalAlias({ id: "https://x.example.com", controllers: [] }, "https://x.example.com"), false);
});
