import json
from pathlib import Path
from copy import deepcopy

import pytest
from agent_protocols import delegation as d
from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import AgentSigner

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/protocols/agent-delegation/1.0.vectors.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["principal_documents"], ids=lambda c: c["name"])
def test_controller_conformance(case):
    if case["valid"]:
        d.validate_principal_document(case["document"])
    else:
        with pytest.raises(Exception):
            d.validate_principal_document(case["document"])


def test_delegation_id_grammar_vectors():
    for delegation_id in VECTORS["delegation_ids"]["valid"]:
        d.validate_delegation_id(delegation_id)
    for delegation_id in VECTORS["delegation_ids"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            d.validate_delegation_id(delegation_id)


SIGNER = AgentSigner.from_seed(bytes([61]) * 32)
ROOT = AgentSigner.from_seed(bytes([62]) * 32)
SUCCESSOR = AgentSigner.from_seed(bytes([63]) * 32)
OTHER = AgentSigner.from_seed(bytes([64]) * 32)
ID = "https://example.com/p"
ORIGIN = "https://dmsg.net"


def document():
    return {"protocol": d.DELEGATION_PROTOCOL, "id": ID, "updated_at": 2000, "delegation_query_url": f"{ID}/query", "controllers": [
        {"id": SIGNER.agent_id(), "source": ORIGIN, "valid_from": 100, "delegation": {"scopes": ["draft"], "audiences": [ORIGIN]}},
        {"id": ROOT.agent_id(), "source": "local", "valid_from": 100, "delegation": "*"},
    ]}


def grant(actor=SIGNER, nonce=1, **overrides):
    return actor.sign_event(d.delegation_grant_event(actor.agent_id(), 200, nonce, {
        "id": "del", "principal_id": ID, "subject": ROOT.agent_id(), "scopes": ["draft"], "audiences": [ORIGIN],
        "expires_at": 1000, **overrides,
    }))


def revoke(actor=ROOT, created_at=400, nonce=2):
    return actor.sign_event(d.delegation_revoke_event(actor.agent_id(), created_at, nonce, {"id": "del", "principal_id": ID}))


def test_authority_ownership_and_materialization():
    doc, envelope = document(), grant()
    d.validate_delegation_acceptance(envelope, doc, ID, 250)
    credential = d.materialize_delegation_credential(envelope, accepted_at=250)
    assert credential["accepted_at"] == 250
    assert credential["checked_at"] == 250
    assert credential["principal_id"] == ID
    assert credential["owner_controller"] == SIGNER.agent_id()
    assert credential["grant_event_id"] == envelope["hash"]
    d.validate_delegation_use(credential, ORIGIN, 300)
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_use(credential, "https://tokenlist.ing", 300)
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_use(credential, ORIGIN, 1000)
    with pytest.raises(AgentProtocolError) as ceiling:
        d.validate_delegation_acceptance(grant(nonce=2, audiences=["https://tokenlist.ing"]), doc, ID, 250)
    assert ceiling.value.code == "delegation_ceiling_exceeded"
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_acceptance(grant(nonce=2, scopes=["admin"]), doc, ID, 250)
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_acceptance(envelope, doc, "https://impostor.example", 250)
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_acceptance(envelope, doc, ID, 1000)
    only = deepcopy(doc)
    del only["controllers"][0]["delegation"]
    d.validate_delegation_envelope(envelope)  # Mathematically valid, but not authorized.
    with pytest.raises(AgentProtocolError) as not_permitted:
        d.validate_delegation_acceptance(envelope, only, ID, 250)
    assert not_permitted.value.code == "delegation_not_permitted"
    root_credential = d.materialize_delegation_credential(grant(ROOT), accepted_at=250)
    with pytest.raises(AgentProtocolError) as not_owner:
        d.validate_delegation_acceptance(envelope, doc, ID, 300, root_credential)
    assert not_owner.value.code == "not_owner_controller"
    with pytest.raises(AgentProtocolError):
        d.validate_controller_enumeration(doc, SIGNER.agent_id(), 300, ROOT.agent_id())
    d.validate_controller_enumeration(doc, ROOT.agent_id(), 300, SIGNER.agent_id())
    revocation = revoke()
    d.validate_delegation_acceptance(revocation, doc, ID, 450, credential)
    revoked = d.materialize_delegation_credential(revocation, accepted_at=450, previous=credential)
    assert revoked["status"] == "revoked"
    assert revoked["owner_controller"] == SIGNER.agent_id()
    assert revoked["controller"] == ROOT.agent_id()
    assert revoked["grant_event_id"] == envelope["hash"]
    assert revoked["audiences"] == credential["audiences"]
    with pytest.raises(AgentProtocolError) as missing:
        d.validate_delegation_acceptance(revocation, doc, ID, 450)
    assert missing.value.code == "credential_not_found"
    replacement = grant(ROOT, 3)
    d.validate_delegation_acceptance(replacement, doc, ID, 500, revoked)
    assert d.materialize_delegation_credential(replacement, accepted_at=500, previous=revoked)["owner_controller"] == SIGNER.agent_id()


def test_a_replacement_cannot_move_a_credential_to_another_subject():
    doc = document()
    credential = d.materialize_delegation_credential(grant(), accepted_at=250)
    with pytest.raises(AgentProtocolError, match="immutable") as moved:
        d.validate_delegation_acceptance(grant(ROOT, 2, subject=OTHER.agent_id()), doc, ID, 300, credential)
    assert moved.value.code == "credential_identity_mismatch"


def test_retired_history_needs_accepted_records_and_the_original_ceiling():
    doc, envelope = document(), grant()
    retired = doc["controllers"].pop(0)
    retired["retired_at"] = 500
    doc["retired_controllers"] = [retired]
    with pytest.raises(AgentProtocolError):
        d.validate_delegation_acceptance(envelope, doc, ID, 600)
    record = {"envelope": envelope, "accepted_at": 250}
    d.validate_historical_delegation(record, doc, ID)
    with pytest.raises(AgentProtocolError):
        d.validate_historical_delegation({**record, "accepted_at": 500}, doc, ID)
    retired["invalid_from"] = 300
    d.validate_historical_delegation(record, doc, ID)
    retired["invalid_from"] = 250
    with pytest.raises(AgentProtocolError):
        d.validate_historical_delegation(record, doc, ID)
    del retired["invalid_from"]
    with pytest.raises(AgentProtocolError):
        d.validate_historical_delegation({"envelope": grant(nonce=2, scopes=["admin"]), "accepted_at": 250}, doc, ID)


def test_a_restricted_successor_manages_its_predecessors_credentials():
    doc = document()
    retired = doc["controllers"].pop(0)
    retired["retired_at"] = 600
    doc["retired_controllers"] = [retired]
    doc["controllers"].append({
        "id": SUCCESSOR.agent_id(), "source": ORIGIN, "valid_from": 600,
        "delegation": {"scopes": ["draft", "inbox"], "audiences": [ORIGIN]}, "supersedes": [SIGNER.agent_id()],
    })
    d.validate_principal_document(doc)
    assert d.controller_lineage(doc, SUCCESSOR.agent_id()) == {SIGNER.agent_id(), SUCCESSOR.agent_id()}
    credential = d.materialize_delegation_credential(grant(), accepted_at=250)
    revocation = revoke(SUCCESSOR, 700, 1)
    d.validate_delegation_acceptance(revocation, doc, ID, 700, credential)
    d.validate_controller_enumeration(doc, SUCCESSOR.agent_id(), 700, SIGNER.agent_id())
    widened = SUCCESSOR.sign_event(d.delegation_grant_event(SUCCESSOR.agent_id(), 700, 2, {
        "id": "del", "principal_id": ID, "subject": ROOT.agent_id(), "scopes": ["draft", "inbox"],
        "audiences": [ORIGIN], "expires_at": 1900,
    }))
    d.validate_delegation_acceptance(widened, doc, ID, 700, credential)
    assert d.materialize_delegation_credential(widened, accepted_at=700, previous=credential)["owner_controller"] == SIGNER.agent_id()
    # Without the supersedes link the successor owns nothing.
    unlinked = deepcopy(doc)
    del unlinked["controllers"][1]["supersedes"]
    with pytest.raises(AgentProtocolError, match="own"):
        d.validate_delegation_acceptance(revocation, unlinked, ID, 700, credential)


def test_verify_delegation_credential_replays_accepted_records():
    doc, envelope = document(), grant()
    credential = d.materialize_delegation_credential(envelope, accepted_at=250)
    records = [{"envelope": envelope, "accepted_at": 250}]
    ok = d.verify_delegation_credential(credential, records, doc, ID, ORIGIN, 300)
    assert (ok["verified"], ok["usable"], ok["reasons"]) == (True, True, [])
    wrong = d.verify_delegation_credential(credential, records, doc, ID, "https://tokenlist.ing", 300)
    assert (wrong["verified"], wrong["usable"]) == (True, False)
    assert d.verify_delegation_credential(credential, records, doc, ID, ORIGIN, 1000)["reasons"] == ["expired"]
    forged = {**credential, "subject": OTHER.agent_id()}
    assert not d.verify_delegation_credential(forged, records, doc, ID, ORIGIN, 300)["verified"]
    assert not d.verify_delegation_credential(credential, [], doc, ID, ORIGIN, 300)["verified"]
    revocation = revoke()
    revoked = d.materialize_delegation_credential(revocation, accepted_at=450, previous=credential)
    history = [*records, {"envelope": revocation, "accepted_at": 450}]
    verdict = d.verify_delegation_credential(revoked, history, doc, ID, ORIGIN, 500)
    assert (verdict["verified"], verdict["usable"], verdict["reasons"]) == (True, False, ["status is revoked"])
    # A service that hides the revocation does not match its own history.
    assert not d.verify_delegation_credential({**revoked, "status": "active"}, history, doc, ID, ORIGIN, 500)["verified"]
