import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { AgentSigner } from "./identity.js";
import * as d from "./delegation.js";

const fixtures = JSON.parse(readFileSync(new URL("../../../crates/agent-protocols/tests/fixtures/delegation.json", import.meta.url), "utf8"));
for (const fixture of fixtures) test(`controller conformance: ${fixture.name}`, () => {
  if (fixture.valid) d.validatePrincipalDocument(fixture.document);
  else assert.throws(() => d.validatePrincipalDocument(fixture.document));
});

const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(61));
const root = AgentSigner.fromSeed(new Uint8Array(32).fill(62));
const id = "https://example.com/p";
const origin = "https://dmsg.net";
function document(): d.PrincipalDocument {
  return { protocol: d.DELEGATION_PROTOCOL, id, updated_at: 2000, controllers: [
    { id: signer.agentId(), source: origin, valid_from: 100, delegation: { scopes: ["draft"], audiences: [origin] } },
    { id: root.agentId(), source: "local", valid_from: 100, delegation: "*" },
  ] };
}
function grant(actor = signer, nonce = 1, overrides = {}): ReturnType<typeof signer.signEvent<d.DelegationGrantPayload>> {
  return actor.signEvent(d.delegationGrantEvent(actor.agentId(), 200, nonce, {
    id: "del", principal: { id }, subject: root.agentId(), scopes: ["draft"], audiences: [origin], expires_at: 1000, ...overrides,
  }));
}
test("authority, ownership and materialization remain separate from signature validity", () => {
  const doc = document(), envelope = grant();
  d.validateDelegationAcceptance(envelope, doc, id, 250);
  const credential = d.materializeDelegationCredential(envelope, { acceptedAt: 250 });
  assert.equal(credential.accepted_at, 250);
  assert.equal(credential.owner_controller, signer.agentId());
  assert.equal(credential.grant_event_id, envelope.hash);
  d.validateDelegationUse(credential, origin, 300);
  assert.throws(() => d.validateDelegationUse(credential, "https://tokenlist.ing", 300));
  assert.throws(() => d.validateDelegationUse(credential, origin, 1000));
  assert.throws(() => d.validateDelegationAcceptance(grant(signer, 2, { audiences: ["https://tokenlist.ing"] }), doc, id, 250));
  assert.throws(() => d.validateDelegationAcceptance(grant(signer, 2, { scopes: ["admin"] }), doc, id, 250));
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, "https://impostor.example", 250));
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 1000));
  const only = structuredClone(doc); delete only.controllers[0].delegation;
  d.validateDelegationEnvelope(envelope); // Mathematically valid, but not authorized.
  assert.throws(() => d.validateDelegationAcceptance(envelope, only, id, 250));
  const other = d.materializeDelegationCredential(grant(root), { acceptedAt: 250 });
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 300, other));
  assert.throws(() => d.validateControllerEnumeration(doc, signer.agentId(), 300, root.agentId()));
  d.validateControllerEnumeration(doc, root.agentId(), 300, signer.agentId());
  const revoke = root.signEvent(d.delegationRevokeEvent(root.agentId(), 400, 2, { id: "del", principal_id: id }));
  d.validateDelegationAcceptance(revoke, doc, id, 450, credential);
  const revoked = d.materializeDelegationCredential(revoke, { acceptedAt: 450, previous: credential });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.owner_controller, signer.agentId());
  assert.equal(revoked.controller, root.agentId());
  assert.equal(revoked.grant_event_id, envelope.hash);
  assert.deepEqual(revoked.audiences, credential.audiences);
  assert.throws(() => d.validateDelegationAcceptance(revoke, doc, id, 450));
  const replacement = grant(root, 3);
  d.validateDelegationAcceptance(replacement, doc, id, 500, revoked);
  assert.equal(d.materializeDelegationCredential(replacement, { acceptedAt: 500, previous: revoked }).owner_controller, signer.agentId());
});
test("retired history needs hash-bound trusted acceptance evidence and the original ceiling", () => {
  const doc = document(), envelope = grant();
  const retired = doc.controllers.shift()!;
  retired.retired_at = 500; doc.retired_controllers = [retired];
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 600));
  const acceptance = { event_id: envelope.hash, accepted_at: 250 };
  d.validateHistoricalDelegation(envelope, acceptance, doc, id);
  assert.throws(() => d.validateHistoricalDelegation(envelope, { ...acceptance, event_id: "different" }, doc, id));
  assert.throws(() => d.validateHistoricalDelegation(envelope, { ...acceptance, accepted_at: 500 }, doc, id));
  retired.invalid_from = 300;
  d.validateHistoricalDelegation(envelope, acceptance, doc, id);
  retired.invalid_from = 250;
  assert.throws(() => d.validateHistoricalDelegation(envelope, acceptance, doc, id));
  assert.throws(() => d.validateHistoricalDelegation(grant(signer, 2, { scopes: ["admin"] }), acceptance, doc, id));
});
