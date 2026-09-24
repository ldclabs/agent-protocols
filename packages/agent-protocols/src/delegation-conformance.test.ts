import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { AgentSigner } from "./identity.js";
import * as d from "./delegation.js";

const vectors = JSON.parse(readFileSync(new URL("../../../docs/protocols/agent-delegation/1.0.vectors.json", import.meta.url), "utf8"));
for (const fixture of vectors.principal_documents) test(`controller conformance: ${fixture.name}`, () => {
  if (fixture.valid) d.validatePrincipalDocument(fixture.document);
  else assert.throws(() => d.validatePrincipalDocument(fixture.document));
});
test("delegation id grammar vectors", () => {
  for (const id of vectors.delegation_ids.valid) d.validateDelegationId(id);
  for (const id of vectors.delegation_ids.invalid) assert.throws(() => d.validateDelegationId(id), id);
});

const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(61));
const root = AgentSigner.fromSeed(new Uint8Array(32).fill(62));
const successor = AgentSigner.fromSeed(new Uint8Array(32).fill(63));
const other = AgentSigner.fromSeed(new Uint8Array(32).fill(64));
const id = "https://example.com/p";
const origin = "https://dmsg.net";
function document(): d.PrincipalDocument {
  return { protocol: d.DELEGATION_PROTOCOL, id, updated_at: 2000, delegation_query_url: `${id}/query`, controllers: [
    { id: signer.agentId(), source: origin, valid_from: 100, delegation: { scopes: ["draft"], audiences: [origin] } },
    { id: root.agentId(), source: "local", valid_from: 100, delegation: "*" },
  ] };
}
function grant(actor = signer, nonce = 1, overrides = {}): ReturnType<typeof signer.signEvent<d.DelegationGrantPayload>> {
  return actor.signEvent(d.delegationGrantEvent(actor.agentId(), 200, nonce, {
    id: "del", principal_id: id, subject: root.agentId(), scopes: ["draft"], audiences: [origin], expires_at: 1000, ...overrides,
  }));
}
test("authority, ownership and materialization remain separate from signature validity", () => {
  const doc = document(), envelope = grant();
  d.validateDelegationAcceptance(envelope, doc, id, 250);
  const credential = d.materializeDelegationCredential(envelope, { acceptedAt: 250 });
  assert.equal(credential.accepted_at, 250);
  assert.equal(credential.checked_at, 250);
  assert.equal(credential.principal_id, id);
  assert.equal(credential.owner_controller, signer.agentId());
  assert.equal(credential.grant_event_id, envelope.hash);
  d.validateDelegationUse(credential, origin, 300);
  assert.throws(() => d.validateDelegationUse(credential, "https://tokenlist.ing", 300));
  assert.throws(() => d.validateDelegationUse(credential, origin, 1000));
  assert.throws(() => d.validateDelegationAcceptance(grant(signer, 2, { audiences: ["https://tokenlist.ing"] }), doc, id, 250), /ceiling|policy/);
  assert.throws(() => d.validateDelegationAcceptance(grant(signer, 2, { scopes: ["admin"] }), doc, id, 250));
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, "https://impostor.example", 250));
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 1000));
  const only = structuredClone(doc); delete only.controllers[0].delegation;
  d.validateDelegationEnvelope(envelope); // Mathematically valid, but not authorized.
  assert.throws(() => d.validateDelegationAcceptance(envelope, only, id, 250));
  const rootCredential = d.materializeDelegationCredential(grant(root), { acceptedAt: 250 });
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 300, rootCredential));
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
test("a replacement cannot move a credential to another subject", () => {
  const doc = document();
  const credential = d.materializeDelegationCredential(grant(), { acceptedAt: 250 });
  const moved = grant(root, 2, { subject: other.agentId() });
  assert.throws(() => d.validateDelegationAcceptance(moved, doc, id, 300, credential), /immutable/);
});
test("retired history needs trusted accepted records and the original ceiling", () => {
  const doc = document(), envelope = grant();
  const retired = doc.controllers.shift()!;
  retired.retired_at = 500; doc.retired_controllers = [retired];
  assert.throws(() => d.validateDelegationAcceptance(envelope, doc, id, 600));
  const record = { envelope, accepted_at: 250 };
  d.validateHistoricalDelegation(record, doc, id);
  assert.throws(() => d.validateHistoricalDelegation({ ...record, accepted_at: 500 }, doc, id));
  retired.invalid_from = 300;
  d.validateHistoricalDelegation(record, doc, id);
  retired.invalid_from = 250;
  assert.throws(() => d.validateHistoricalDelegation(record, doc, id));
  assert.throws(() => d.validateHistoricalDelegation({ envelope: grant(signer, 2, { scopes: ["admin"] }), accepted_at: 250 }, doc, id));
});
test("a restricted successor manages its predecessor's credentials within its own ceiling", () => {
  const doc = document();
  const retired = doc.controllers.shift()!;
  retired.retired_at = 600; doc.retired_controllers = [retired];
  doc.controllers.push({ id: successor.agentId(), source: origin, valid_from: 600, delegation: { scopes: ["draft", "inbox"], audiences: [origin] }, supersedes: [signer.agentId()] });
  d.validatePrincipalDocument(doc);
  assert.deepEqual([...d.controllerLineage(doc, successor.agentId())].sort(), [signer.agentId(), successor.agentId()].sort());
  const credential = d.materializeDelegationCredential(grant(), { acceptedAt: 250 });
  const revoke = successor.signEvent(d.delegationRevokeEvent(successor.agentId(), 700, 1, { id: "del", principal_id: id }));
  d.validateDelegationAcceptance(revoke, doc, id, 700, credential);
  d.validateControllerEnumeration(doc, successor.agentId(), 700, signer.agentId());
  const widened = successor.signEvent(d.delegationGrantEvent(successor.agentId(), 700, 2, {
    id: "del", principal_id: id, subject: root.agentId(), scopes: ["draft", "inbox"], audiences: [origin], expires_at: 1900,
  }));
  d.validateDelegationAcceptance(widened, doc, id, 700, credential);
  assert.equal(d.materializeDelegationCredential(widened, { acceptedAt: 700, previous: credential }).owner_controller, signer.agentId());
  // Without the supersedes link the successor owns nothing.
  const unlinked = structuredClone(doc); delete unlinked.controllers[1].supersedes;
  assert.throws(() => d.validateDelegationAcceptance(revoke, unlinked, id, 700, credential), /own/);
});
test("verifyDelegationCredential checks the latest grant and use", () => {
  const doc = document();
  const envelope = grant();
  const credential = d.materializeDelegationCredential(envelope, { acceptedAt: 250 });
  const records = [{ envelope, accepted_at: 250 }];
  const ok = d.verifyDelegationCredential(credential, records, doc, id, origin, 300);
  assert.deepEqual([ok.verified, ok.usable, ok.reasons], [true, true, []]);
  const wrongAudience = d.verifyDelegationCredential(credential, records, doc, id, "https://tokenlist.ing", 300);
  assert.deepEqual([wrongAudience.verified, wrongAudience.usable], [true, false]);
  const expired = d.verifyDelegationCredential(credential, records, doc, id, origin, 1000);
  assert.deepEqual(expired.reasons, ["expired"]);
  const forged = { ...credential, subject: other.agentId() };
  assert.equal(d.verifyDelegationCredential(forged, records, doc, id, origin, 300).verified, false);
  assert.equal(d.verifyDelegationCredential(credential, [], doc, id, origin, 300).verified, false);
  const revoke = root.signEvent(d.delegationRevokeEvent(root.agentId(), 400, 2, { id: "del", principal_id: id }));
  const revoked = d.materializeDelegationCredential(revoke, { acceptedAt: 450, previous: credential });
  const history = [...records, { envelope: revoke, accepted_at: 450 }];
  const verdict = d.verifyDelegationCredential(revoked, history, doc, id, origin, 500);
  assert.deepEqual([verdict.verified, verdict.usable, verdict.reasons], [true, false, ["status is revoked"]]);
  // A service that hides the revocation does not match its own history.
  const hidden = { ...revoked, status: "active" as const };
  assert.equal(d.verifyDelegationCredential(hidden, history, doc, id, origin, 500).verified, false);
  // Relying parties need only the latest grant record; auditors replay all.
  assert.equal(d.verifyDelegationCredential(revoked, records, doc, id, origin, 500).verified, true);
  d.auditDelegationHistory(revoked, history, doc, id);
  assert.throws(() => d.auditDelegationHistory(hidden, history, doc, id));
  assert.throws(() => d.auditDelegationHistory(revoked, records, doc, id));
});

test("credential verification binds every grant field while allowing current service metadata", () => {
  const doc = document();
  const envelope = grant(signer, 1, {
    relationship: "assistant", not_before: 210,
    constraints: { limit: 1, project: "alpha" },
  });
  const credential = d.materializeDelegationCredential(envelope, { acceptedAt: 250 });
  const records = [{ envelope, accepted_at: 250 }];
  const changes: Partial<d.DelegationCredential>[] = [
    { protocol: "other/1.0" as never }, { relationship: "owner" },
    { scopes: ["admin"] }, { audiences: ["https://other.test"] },
    { constraints: { limit: true, project: "alpha" } }, { constraints: undefined },
    { not_before: undefined }, { not_before: 0 },
    { expires_at: undefined }, { expires_at: 2000 }, { accepted_at: 251 },
  ];
  for (const change of changes) {
    const verdict = d.verifyDelegationCredential({ ...credential, ...change }, records, doc, id, origin, 300);
    assert.deepEqual([verdict.verified, verdict.usable], [false, false], JSON.stringify(change));
  }
  const control = { ...credential, constraints: { project: "alpha", limit: 1 }, checked_at: 400 };
  assert.equal(d.verifyDelegationCredential(control, records, doc, id, origin, 400).usable, true);
  const suspended = d.verifyDelegationCredential({ ...control, status: "suspended" }, records, doc, id, origin, 400);
  assert.deepEqual([suspended.verified, suspended.usable], [true, false]);
});

test("audience vectors", () => {
  for (const audience of vectors.audiences.valid) d.validateAudience(audience);
  for (const audience of vectors.audiences.invalid) assert.throws(() => d.validateAudience(audience), audience);
});

for (const fixture of vectors.acceptance.cases) test(`acceptance: ${fixture.name}`, () => {
  const document = vectors.acceptance.document as d.PrincipalDocument;
  let outcome = "ok";
  try {
    if (fixture.mode === "live") {
      d.validateDelegationAcceptance(fixture.envelope, document, document.id, fixture.accepted_at, fixture.previous ?? undefined);
    } else {
      d.validateHistoricalDelegation({ envelope: fixture.envelope, accepted_at: fixture.accepted_at }, document, document.id, fixture.previous ?? undefined);
    }
  } catch (error) {
    outcome = (error as { code?: string }).code ?? "other";
  }
  assert.equal(outcome, fixture.expected);
});
