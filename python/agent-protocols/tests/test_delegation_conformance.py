import json
from pathlib import Path
from copy import deepcopy

import pytest
from agent_protocols import delegation as d
from agent_protocols.identity import AgentSigner

FIXTURES = json.loads((Path(__file__).resolve().parents[3] / "crates/agent-protocols/tests/fixtures/delegation.json").read_text())

@pytest.mark.parametrize("case", FIXTURES, ids=lambda c: c["name"])
def test_controller_conformance(case):
    if case["valid"]:
        d.validate_principal_document(case["document"])
    else:
        with pytest.raises(Exception):
            d.validate_principal_document(case["document"])

SIGNER = AgentSigner.from_seed(bytes([61]) * 32)
ROOT = AgentSigner.from_seed(bytes([62]) * 32)
ID = "https://example.com/p"
ORIGIN = "https://dmsg.net"

def document():
    return {"protocol":d.DELEGATION_PROTOCOL,"id":ID,"updated_at":2000,"controllers":[
        {"id":SIGNER.agent_id(),"source":ORIGIN,"valid_from":100,"delegation":{"scopes":["draft"],"audiences":[ORIGIN]}},
        {"id":ROOT.agent_id(),"source":"local","valid_from":100,"delegation":"*"},
    ]}

def grant(actor=SIGNER, **overrides):
    return actor.sign_event(d.delegation_grant_event(actor.agent_id(), 200, 1, {
        "id":"del","principal":{"id":ID},"subject":ROOT.agent_id(),"scopes":["draft"],"audiences":[ORIGIN],"expires_at":1000,**overrides,
    }))

def test_authority_ownership_and_materialization():
    doc, envelope = document(), grant()
    d.validate_delegation_acceptance(envelope, doc, ID, 250)
    credential = d.materialize_delegation_credential(envelope, accepted_at=250)
    assert credential["accepted_at"] == 250
    assert credential["owner_controller"] == SIGNER.agent_id()
    d.validate_delegation_use(credential, ORIGIN, 300)
    for audience, time in [("https://tokenlist.ing",300),(ORIGIN,1000)]:
        with pytest.raises(Exception): d.validate_delegation_use(credential, audience, time)
    for bad in [grant(scopes=["admin"]),grant(audiences=["https://tokenlist.ing"])]:
        with pytest.raises(Exception): d.validate_delegation_acceptance(bad, doc, ID, 250)
    with pytest.raises(Exception): d.validate_delegation_acceptance(envelope, doc, "https://impostor.example", 250)
    with pytest.raises(Exception): d.validate_delegation_acceptance(envelope, doc, ID, 1000)
    only = deepcopy(doc); del only["controllers"][0]["delegation"]
    d.validate_delegation_envelope(envelope)
    with pytest.raises(Exception): d.validate_delegation_acceptance(envelope, only, ID, 250)
    other = d.materialize_delegation_credential(grant(ROOT), accepted_at=250)
    with pytest.raises(Exception): d.validate_delegation_acceptance(envelope, doc, ID, 300, other)
    with pytest.raises(Exception): d.validate_controller_enumeration(doc, SIGNER.agent_id(), 300, ROOT.agent_id())
    d.validate_controller_enumeration(doc, ROOT.agent_id(), 300, SIGNER.agent_id())
    revoke = ROOT.sign_event(d.delegation_revoke_event(ROOT.agent_id(), 400, 2, {"id":"del","principal_id":ID}))
    d.validate_delegation_acceptance(revoke, doc, ID, 450, credential)
    revoked = d.materialize_delegation_credential(revoke, accepted_at=450, previous=credential)
    assert revoked["status"] == "revoked"
    assert revoked["controller"] == ROOT.agent_id()
    assert revoked["owner_controller"] == SIGNER.agent_id()
    assert revoked["grant_event_id"] == envelope["hash"]
    assert revoked["audiences"] == credential["audiences"]
    with pytest.raises(Exception): d.validate_delegation_acceptance(revoke, doc, ID, 450)
    replacement = grant(ROOT)
    d.validate_delegation_acceptance(replacement, doc, ID, 500, revoked)
    assert d.materialize_delegation_credential(replacement, accepted_at=500, previous=revoked)["owner_controller"] == SIGNER.agent_id()

def test_retired_history_requires_hash_bound_evidence():
    doc, envelope = document(), grant()
    retired = doc["controllers"].pop(0); retired["retired_at"] = 500
    doc["retired_controllers"] = [retired]
    with pytest.raises(Exception): d.validate_delegation_acceptance(envelope, doc, ID, 600)
    acceptance = {"event_id":envelope["hash"],"accepted_at":250}
    d.validate_historical_delegation(envelope, acceptance, doc, ID)
    with pytest.raises(Exception): d.validate_historical_delegation(envelope, {**acceptance,"event_id":"different"}, doc, ID)
    with pytest.raises(Exception): d.validate_historical_delegation(envelope, {**acceptance,"accepted_at":500}, doc, ID)
    retired["invalid_from"] = 300
    d.validate_historical_delegation(envelope, acceptance, doc, ID)
    retired["invalid_from"] = 250
    with pytest.raises(Exception): d.validate_historical_delegation(envelope, acceptance, doc, ID)
