"""Agent Profile conformance vectors shared by every SDK."""

import json
from pathlib import Path

import pytest

from agent_protocols.errors import AgentProtocolError
from agent_protocols.profile import (
    latest_profile_update,
    materialize_profile,
    validate_profile_payload,
    validate_profile_update,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/protocols/agent-profile/1.0.vectors.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["payloads"]["valid"], ids=lambda c: c["name"])
def test_valid_payloads(case):
    validate_profile_payload(case["payload"], case["actor"])


@pytest.mark.parametrize("case", VECTORS["payloads"]["invalid"], ids=lambda c: c["name"])
def test_invalid_payloads(case):
    with pytest.raises(AgentProtocolError):
        validate_profile_payload(case["payload"], case["actor"])


def test_history_materializes_the_greatest_nonce():
    envelopes = VECTORS["history"]["envelopes"]
    for envelope in envelopes:
        validate_profile_update(envelope)
    document = materialize_profile(latest_profile_update(envelopes))
    for field, expected in VECTORS["history"]["latest"].items():
        assert document[field] == expected, field


def test_explicit_empty_arrays_and_objects_verify_and_materialize_as_signed():
    vector = VECTORS["explicit_empty"]
    validate_profile_update(vector["envelope"])
    document = materialize_profile(vector["envelope"])
    for field, expected in vector["document"].items():
        assert document[field] == expected, field
