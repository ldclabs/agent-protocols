"""Agent Identity conformance vectors shared by every SDK."""

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from copy import deepcopy
from pathlib import Path

import pytest

from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import (
    AgentSigner,
    ClientNonceManager,
    MemoryNonceStore,
    canonical_event_bytes,
    format_agent_url,
    parse_agent_url,
    parse_envelope_json,
    parse_strict_json,
    validate_agent_id,
    validate_event_fields,
    verify_ed25519_strict,
    verify_envelope,
    verify_event_hash_signature,
    verify_submission,
)
from agent_protocols.profile import profile_update_event, validate_profile_succession, validate_profile_update

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/protocols/agent-identity/1.0.vectors.json").read_text()
)


def b64(value):
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_keys_jcs_bytes_hashes_and_signatures_are_reproduced():
    for key in VECTORS["keys"]:
        signer = AgentSigner.from_seed(bytes.fromhex(key["seed"]))
        assert signer.agent_id() == key["agent_id"]
        assert urlsafe_b64encode(signer.public_key()).rstrip(b"=").decode() == key["public_key"]
    for vector in VECTORS["events"]:
        signer = AgentSigner.from_seed(bytes.fromhex(vector["seed"]))
        assert canonical_event_bytes(vector["event"]).decode() == vector["jcs"], vector["name"]
        envelope = signer.sign_event(vector["event"])
        assert envelope["hash"] == vector["hash"], vector["name"]
        assert envelope["signature"] == vector["signature"], vector["name"]
        verify_envelope(envelope)
        # The vector text parses strictly and round-trips.
        assert parse_strict_json(vector["jcs"]) == vector["event"]


@pytest.mark.parametrize("vector", VECTORS["signatures"], ids=lambda v: v["name"])
def test_only_strictly_valid_ed25519_signatures_verify(vector):
    public_key, message = b64(vector["public_key"]), b64(vector["message"])
    assert verify_ed25519_strict(message, b64(vector["signature"]), public_key) is vector["valid"]
    if vector["valid"]:
        verify_event_hash_signature(public_key, message, vector["signature"])
    else:
        with pytest.raises(AgentProtocolError, match="signature verification failed"):
            verify_event_hash_signature(public_key, message, vector["signature"])


def test_malformed_agent_ids_are_rejected():
    for agent_id in VECTORS["agent_ids"]["valid"]:
        validate_agent_id(agent_id)
    for vector in VECTORS["agent_ids"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            validate_agent_id(vector["value"])


def test_agent_urls_parse_into_components_and_format_back_exactly():
    for vector in VECTORS["agent_urls"]["valid"]:
        parsed = parse_agent_url(vector["value"])
        assert {k: v for k, v in parsed.items() if v is not None} == vector["parsed"], vector["value"]
        assert format_agent_url(parsed["agent_id"], parsed["protocol"], parsed["resource"], parsed["routes"]) == vector["value"]
    for vector in VECTORS["agent_urls"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            parse_agent_url(vector["value"])
    with pytest.raises(AgentProtocolError):
        format_agent_url(VECTORS["agent_ids"]["valid"][0], "mail", None)


def test_signed_json_is_parsed_strictly():
    for vector in VECTORS["json"]["valid"]:
        parse_strict_json(vector["text"])
    for vector in VECTORS["json"]["invalid"]:
        with pytest.raises(AgentProtocolError, match="invalid JSON"):
            parse_strict_json(vector["text"])
        # json.loads accepts every one of them silently.
        json.loads(vector["text"])
    for text in ('{"n": NaN}', '{"n": 1e400}', '{"a": 1} x'):
        with pytest.raises(AgentProtocolError):
            parse_strict_json(text)
    envelope = AgentSigner.from_seed(bytes([7]) * 32).sign_event(VECTORS["events"][0]["event"])
    assert parse_envelope_json(json.dumps(envelope)) == envelope
    with pytest.raises(AgentProtocolError, match="unknown envelope field"):
        parse_envelope_json(json.dumps({**envelope, "extra": 1}))
    with pytest.raises(AgentProtocolError, match="hash, event, and signature"):
        parse_envelope_json("[]")


def test_the_event_object_is_closed():
    validate_event_fields(VECTORS["events"][0]["event"])
    validate_event_fields(VECTORS["events"][1]["event"], ["room_id", "base_seq", "base_hash", "mentions"])
    with pytest.raises(AgentProtocolError, match="unknown event field"):
        validate_event_fields(VECTORS["events"][1]["event"])
    for vector in VECTORS["events_closed_shape"]["invalid"]:
        with pytest.raises(AgentProtocolError, match="event"):
            validate_event_fields(vector["event"])


@pytest.mark.parametrize("vector", VECTORS["max_seen_nonce"], ids=lambda v: v["name"])
def test_max_seen_nonce_jumps_are_bounded(vector):
    manager = ClientNonceManager(vector["next_nonce"])
    if vector["accepted"]:
        manager.observe_max_nonce(vector["header"], vector["now_ms"])
        assert manager.peek() == vector["next_after"]
    else:
        with pytest.raises(AgentProtocolError, match="jumps too far|nonce"):
            manager.observe_max_nonce(vector["header"], vector["now_ms"])
        assert manager.peek() == vector["next_nonce"]


def test_clock_derived_nonces_stay_monotonic():
    manager = ClientNonceManager()
    assert manager.next_nonce(1_000) == 1_000
    assert manager.next_nonce(1_000) == 1_001  # two events in one millisecond
    assert manager.next_nonce(900) == 1_002  # a clock step back never reuses a nonce
    assert manager.next_nonce() == 1_003  # without a clock the manager counts
    assert manager.next_nonce(5_000) == 5_000


def test_verify_submission_answers_exact_resubmissions_before_replay_checks():
    signer = AgentSigner.from_seed(bytes([71]) * 32)
    envelope = signer.sign_event(profile_update_event(signer.agent_id(), 1_000, 5, {"id": signer.agent_id(), "name": "A"}))
    store = MemoryNonceStore()
    accepted = verify_submission(envelope, store, now_ms=1_000)
    assert (accepted.kind, accepted.max_nonce) == ("accepted", 5)
    # Far outside the live window, an accepted envelope is still a resubmission.
    replay = verify_submission(envelope, store, now_ms=10_000_000, is_accepted=lambda h: h == envelope["hash"])
    assert replay.kind == "resubmission"
    with pytest.raises(AgentProtocolError) as stale:
        verify_submission(envelope, store, now_ms=1_000)
    assert stale.value.code == "nonce_not_greater"


def test_profile_updates_need_a_greater_nonce_and_the_six_event_fields():
    signer = AgentSigner.from_seed(bytes([72]) * 32)
    envelope = signer.sign_event(profile_update_event(signer.agent_id(), 1_000, 5, {"id": signer.agent_id(), "name": "A"}))
    validate_profile_update(envelope)
    validate_profile_succession(envelope, None)
    validate_profile_succession(envelope, 4)
    with pytest.raises(AgentProtocolError) as stale:
        validate_profile_succession(envelope, 5)
    assert (stale.value.code, stale.value.data) == ("nonce_not_greater", {"max_nonce": 5})
    extra = deepcopy(profile_update_event(signer.agent_id(), 1_000, 6, {"id": signer.agent_id(), "name": "A"}))
    extra["room_id"] = "r1"
    with pytest.raises(AgentProtocolError, match="unknown event field"):
        validate_profile_update(signer.sign_event(extra))


def test_origins_are_serialized_https_origins():
    from agent_protocols.identity import validate_origin

    for origin in VECTORS["origins"]["valid"]:
        validate_origin(origin)
    for origin in VECTORS["origins"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            validate_origin(origin)


def test_request_jwts_verify_exactly_as_listed():
    from agent_protocols.identity import verify_request_jwt

    jwts = VECTORS["request_jwts"]
    options = {"audience": jwts["audience"], "now_secs": jwts["now_secs"], "max_ttl_secs": jwts["max_ttl_secs"]}
    for case in jwts["valid"]:
        assert verify_request_jwt(case["token"], **options) == case["claims"]
    for case in jwts["invalid"]:
        with pytest.raises(Exception):
            verify_request_jwt(case["token"], **options)


def test_submissions_resolve_resubmission_windows_and_nonce_replays():
    submissions = VECTORS["submissions"]
    envelopes = submissions["envelopes"]
    store = MemoryNonceStore()
    for step in submissions["steps"]:
        accepted = {envelopes[name]["hash"] for name in step["accepted"]}
        try:
            outcome = verify_submission(
                envelopes[step["envelope"]],
                store,
                is_accepted=accepted.__contains__,
                now_ms=step["now_ms"],
                window_ms=submissions["window_ms"],
            ).kind
        except AgentProtocolError as error:
            outcome = error.code
        assert outcome == step["expected"], step["name"]
