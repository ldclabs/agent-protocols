import json
from base64 import urlsafe_b64encode
from copy import deepcopy
from hashlib import sha256, sha3_256
from pathlib import Path

import pytest
from jsonschema import ValidationError
from jsonschema.validators import Draft202012Validator

from agent_protocols import discourse as d
from agent_protocols.errors import AgentProtocolError
from agent_protocols.http_client import sse_events_url
from agent_protocols.identity import AgentSigner

DOCS = Path(__file__).resolve().parents[3] / "docs/protocols/agent-discourse"
PACKS_DOCUMENT = json.loads((DOCS / "1.0.packs.json").read_text())
PACKS = d.pack_map(PACKS_DOCUMENT)
SCHEMA = json.loads((DOCS / "1.0.schema.json").read_text())
VECTORS = json.loads((DOCS / "1.0.vectors.json").read_text())
HOST = "https://api.example.com"
ROOM = "d8ftedhpqhsusbg001tg"

FINDING_DEF = {
    "type": "review.finding",
    "kind": "message",
    "title": "Review finding",
    "schema": {
        "type": "object",
        "required": ["severity", "summary"],
        "properties": {
            "severity": {"type": "string", "enum": ["low", "medium", "high"]},
            "summary": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    },
}


def signer(byte):
    return AgentSigner.from_seed(bytes([byte]) * 32)


def room_payload(**overrides):
    return {"host": HOST, "topic": "Research room", "visibility": "public", "start_time": 1000, "end_time": 2000, **overrides}


def message(author, room=ROOM, base_seq=1, base_hash="h", nonce=1, **extra):
    event = d.discourse_event(d.MESSAGE_CREATE, author.agent_id(), 100, nonce, room, base_seq, base_hash,
                              {"content_type": "text/plain", "content": "hi"})
    event.update(extra)
    return author.sign_event(event)


def test_kernel_defines_twelve_builtins_and_freshness_classes():
    assert len(d.BUILTIN_EVENT_TYPES) == 12
    assert d.is_builtin_event_type(d.ROOM_JOIN_REQUEST)
    for kind in d.MEMBERSHIP_EVENT_TYPES:
        assert d.builtin_event_class(kind) == "signal"
        assert not d.event_advances_room_head(kind)
        assert not d.event_requires_room_head(kind)
    for kind in d.CONTRACT_EVENT_TYPES:
        assert d.builtin_event_class(kind) == "contract"
        assert d.event_advances_room_head(kind)
        assert not d.event_requires_room_head(kind)
    assert d.builtin_event_class(d.ROOM_CREATE) == "genesis"
    assert d.record_class(d.ROOM_JOIN_REQUEST) is None
    assert d.event_requires_room_head(d.MESSAGE_CREATE)
    assert d.event_requires_room_head("unknown.custom")
    assert not d.event_requires_base(d.ROOM_JOIN_REQUEST)
    for code in ("host_mismatch", "type_conflict", "invalid_type_schema", "join_request_not_pending"):
        assert code in d.DISCOURSE_ERROR_CODES


def test_vectors_reproduce_chains_redaction_and_heads():
    records = VECTORS["records"]
    for record in records:
        d.verify_server_record(record)
        d.validate_discourse_envelope(record["envelope"])
    d.verify_server_record_chain(records)
    redacted = VECTORS["redacted_records"]
    assert d.is_redacted_record(redacted[2])
    d.verify_server_record_chain(redacted)
    manifest = {"room_id": VECTORS["room_id"], "last_seq": VECTORS["last_seq"], "last_hash": VECTORS["last_hash"]}
    assert d.verify_archive_records(manifest, records) == []
    assert d.verify_archive_records(manifest, redacted) == [3]
    with pytest.raises(AgentProtocolError):
        d.verify_archive_records({**manifest, "last_hash": records[0]["hash"]}, records)
    assert d.redact_server_record(records[2]) == redacted[2]
    registry = d.TypeRegistry.from_declarations(records[0]["envelope"]["event"]["payload"]["types"], PACKS)
    head = 0
    for record, expected in zip(records, VECTORS["head_seq_after"]):
        if d.event_advances_room_head(record["envelope"]["event"]["type"], registry):
            head = record["seq"]
        assert head == expected


def test_vectors_classes_and_patterns():
    freshness = VECTORS["freshness"]
    registry = d.TypeRegistry.from_declarations(freshness["registry"], PACKS)
    for kind, expected in freshness["classes"].items():
        assert d.record_class(kind, registry) == expected, kind
        assert d.event_requires_room_head(kind, registry) == (kind in freshness["head_checked"]), kind
        assert d.event_advances_room_head(kind, registry) == (kind in freshness["head_advancing"]), kind
    for check in freshness["base_checks"]:
        try:
            d.validate_room_base(check["type"], registry, check["base_seq"], "base-hash",
                                 "base-hash" if check["anchored"] else None, check["head_seq"])
            outcome = "ok"
        except AgentProtocolError as error:
            outcome = error.code
        assert outcome == check["expected"], check["name"]
    for name in VECTORS["type_names"]["valid"]:
        d.validate_custom_event_type_name(name)
    for name in VECTORS["type_names"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            d.validate_custom_event_type_name(name)
    for case in VECTORS["open_roles"]["effective"]:
        assert d.effective_open_roles(case["visibility"], case.get("policy")) == case["expected"], case["name"]
    for case in VECTORS["open_roles"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            d.validate_room_policy(case["policy"])
            d.validate_room_visibility_policy(case["visibility"], case["policy"])
    for pattern in VECTORS["patterns"]["valid"]:
        d.validate_portable_pattern(pattern)
    for pattern in VECTORS["patterns"]["invalid"]:
        with pytest.raises(AgentProtocolError):
            d.validate_portable_pattern(pattern)


def test_registered_packs_follow_the_profile():
    assert PACKS_DOCUMENT["protocol"] == d.DISCOURSE_PROTOCOL
    assert len(PACKS) == 5
    for pack in PACKS.values():
        for definition in pack["types"]:
            d.validate_type_def(definition)
    assert any(t["type"] == "claim.update" for t in PACKS[d.PACK_MODERATION]["types"])
    assert not any(t["type"] == "session.candidate" for t in PACKS[d.PACK_REALTIME]["types"])


def test_room_create_is_host_bound_and_closed():
    creator = signer(14)
    envelope = creator.sign_event(d.room_create_event(creator.agent_id(), 100, 1, room_payload()))
    d.validate_discourse_envelope(envelope)
    d.validate_room_path(envelope, ROOM)
    d.validate_room_create_payload(envelope["event"]["payload"])
    d.validate_room_create_host(envelope["event"]["payload"], HOST)
    with pytest.raises(AgentProtocolError) as mismatch:
        d.validate_room_create_host(envelope["event"]["payload"], "https://other.example")
    assert mismatch.value.code == "host_mismatch"
    with pytest.raises(AgentProtocolError):
        d.validate_room_create_payload(room_payload(host=f"{HOST}/v1"))
    with pytest.raises(AgentProtocolError):
        d.validate_room_create_payload(room_payload(topic=" "))
    for extra in ({"room_id": "r1"}, {"audience": "x"}):
        event = {**d.room_create_event(creator.agent_id(), 100, 2, room_payload()), **extra}
        with pytest.raises(AgentProtocolError):
            d.validate_discourse_envelope(creator.sign_event(event))


def test_room_events_require_valid_room_ids_bases_and_mentions():
    author = signer(15)
    d.validate_room_path(message(author, "room1"), "room1")
    with pytest.raises(AgentProtocolError) as mismatch:
        d.validate_room_path(message(author, "room1"), "room2")
    assert mismatch.value.code == "room_id_mismatch"
    with pytest.raises(AgentProtocolError):
        d.validate_discourse_envelope(message(author, "room/../x"))
    no_room = author.sign_event({**d.room_create_event(author.agent_id(), 1, 1, {}), "type": d.MESSAGE_CREATE})
    with pytest.raises(AgentProtocolError) as missing:
        d.validate_discourse_envelope(no_room)
    assert missing.value.code == "missing_room_id"
    mentions = [signer(100 + i).agent_id() for i in range(33)]
    with pytest.raises(AgentProtocolError):
        d.validate_discourse_envelope(message(author, mentions=mentions))
    d.validate_discourse_envelope(message(author, mentions=mentions[:32]))
    with pytest.raises(AgentProtocolError):
        d.validate_discourse_envelope(message(author, mentions=[mentions[0], mentions[0]]))
    with pytest.raises(AgentProtocolError):
        d.validate_discourse_envelope(message(author, base_seq=0))


def test_join_requests_are_signed_unanchored_and_embedded_by_reviews():
    moderator, applicant = signer(21), signer(22)
    request = applicant.sign_event(
        d.room_join_request_event(applicant.agent_id(), 1, 1, ROOM, {"role": "speaker", "perspective": "reviewer"})
    )
    d.validate_discourse_envelope(request)
    d.validate_join_request_envelope(request, ROOM)
    anchored = applicant.sign_event(
        {**d.room_join_request_event(applicant.agent_id(), 1, 2, ROOM, {"role": "speaker"}), "base_seq": 1, "base_hash": "h"}
    )
    with pytest.raises(AgentProtocolError):
        d.validate_discourse_envelope(anchored)
    with pytest.raises(AgentProtocolError):
        d.validate_room_join_request_payload({"role": "speaker", "request_id": "jr"})

    review = {"request": request, "decision": "approve", "role": "speaker"}
    head = "GDt8oHZQfQ3jl5ZUfyNxKZu07yAJdDYuaw_jf_JjLYs"
    signed = moderator.sign_event(d.discourse_event(d.ROOM_JOIN_REVIEW, moderator.agent_id(), 2, 1, ROOM, 1, head, review))
    d.validate_discourse_envelope(signed)
    d.validate_room_join_review_payload(review, ROOM)
    with pytest.raises(AgentProtocolError):
        d.validate_room_join_review_payload({**review, "role": None}, ROOM)
    with pytest.raises(AgentProtocolError):
        d.validate_room_join_review_payload(review, "other")
    tampered = deepcopy(review)
    tampered["request"]["event"]["payload"]["role"] = "moderator"
    with pytest.raises(AgentProtocolError):
        d.validate_room_join_review_payload(tampered, ROOM)

    # The schema embeds the signed request and requires a role on approval.
    validator = Draft202012Validator(SCHEMA)
    validator.validate(signed)
    legacy = deepcopy(signed)
    legacy["event"]["payload"]["request"] = {"id": "jr_1", "applicant": applicant.agent_id(), "role": "speaker"}
    with pytest.raises(ValidationError):
        validator.validate(legacy)
    no_role = deepcopy(signed)
    del no_role["event"]["payload"]["role"]
    with pytest.raises(ValidationError):
        validator.validate(no_role)


def test_direct_join_follows_invites_and_open_roles():
    invited, stranger = signer(23).agent_id(), signer(24).agent_id()
    policy = {"invites": {invited: "moderator"}, "open_roles": ["observer"]}
    d.validate_room_policy(policy)
    assert d.can_join_directly("private", policy, invited, "moderator")
    assert not d.can_join_directly("private", policy, invited, "speaker")
    # Open roles apply to any visibility; a private room cannot list them.
    assert d.can_join_directly("restricted", policy, stranger, "observer")
    with pytest.raises(AgentProtocolError):
        d.validate_room_visibility_policy("private", policy)
    d.validate_room_visibility_policy("restricted", policy)
    with pytest.raises(AgentProtocolError):
        d.validate_room_create_payload(room_payload(visibility="private", policy=policy))
    assert d.can_join_directly("public", policy, stranger, "observer")
    assert not d.can_join_directly("public", policy, stranger, "speaker")
    assert not d.can_join_directly("private", None, stranger, "observer")
    assert d.effective_open_roles("public", None) == ["observer"]
    assert d.effective_open_roles("restricted", None) == []
    assert d.effective_open_roles("public", {"observer_allowed": False}) == []
    for bad in (
        {"open_roles": ["moderator"]},
        {"observer_allowed": False, "open_roles": ["observer"]},
        {"moderator_agent_ids": []},
        {"invites": {invited: "owner"}},
        {"max_speakers": 0},
    ):
        with pytest.raises(AgentProtocolError):
            d.validate_room_policy(bad)


def test_type_schemas_follow_the_portable_profile():
    d.validate_type_schema_profile({
        "type": "object",
        "properties": {"a": {"$ref": "#/$defs/x"}},
        "$defs": {"x": {"type": "string", "pattern": "^a$"}},
    })
    for schema in (
        {"$ref": "https://example.com/schema.json"},
        {"$dynamicRef": "#x"},
        {"$schema": "http://json-schema.org/draft-07/schema#"},
        {"properties": {"a": {"pattern": "\\w"}}},
        {"patternProperties": {"\\d": {}}},
        {"allOf": [{"items": {"pattern": "."}}]},
    ):
        with pytest.raises(AgentProtocolError) as error:
            d.validate_type_schema_profile(schema)
        assert error.value.code == "invalid_type_schema"
    with pytest.raises(AgentProtocolError):
        d.TypeRegistry().define({**FINDING_DEF, "schema": {"type": "string", "pattern": "\\s"}})
    # `format` is an annotation: a non-URI string is not a schema violation.
    registry = d.TypeRegistry.from_declarations([{"use": d.PACK_CURATION}], PACKS)
    registry.validate_payload("resource.add", {"resource_type": "web", "uri": "not a uri"})


def test_registry_imports_packs_and_rejects_conflicts():
    registry = d.TypeRegistry.from_declarations(
        [
            {"use": d.PACK_REACTIONS},
            {"use": d.PACK_DELIBERATION, "overrides": {"poll.vote": {"roles": ["moderator", "speaker", "observer"]}}},
            FINDING_DEF,
        ],
        PACKS,
    )
    assert len(registry) == 6
    assert d.can_submit_event("poll.vote", {"role": "observer"}, registry)
    registry.validate_payload("review.finding", {"severity": "high", "summary": "x"})
    with pytest.raises(AgentProtocolError) as violation:
        registry.validate_payload("review.finding", {"severity": "urgent", "summary": "x"})
    assert violation.value.code == "payload_schema_violation"
    for declarations in ([FINDING_DEF, FINDING_DEF], [{"use": d.PACK_REACTIONS}, {"use": d.PACK_REACTIONS}]):
        with pytest.raises(AgentProtocolError) as twice:
            d.TypeRegistry.from_declarations(declarations, PACKS)
        assert twice.value.code == "type_conflict"
    with pytest.raises(AgentProtocolError) as unavailable:
        d.TypeRegistry.from_declarations([{"use": "adp:unknown/1.0"}], PACKS)
    assert unavailable.value.code == "pack_unavailable"
    with pytest.raises(AgentProtocolError):
        d.validate_pack_import({"use": d.PACK_DELIBERATION, "types": ["poll.vote", "poll.vote"]})
    with pytest.raises(AgentProtocolError):
        d.TypeRegistry.from_declarations([{"use": d.PACK_DELIBERATION, "types": ["does.not.exist"]}], PACKS)
    kinds = d.TypeRegistry()
    kinds.define(FINDING_DEF)
    with pytest.raises(AgentProtocolError) as kind_change:
        kinds.define({**FINDING_DEF, "kind": "signal"})
    assert kind_change.value.code == "type_conflict"
    # Redefinition with the same kind: the latest definition wins.
    kinds.define({**FINDING_DEF, "title": "Finding v2"})
    assert kinds.get("review.finding")["title"] == "Finding v2"


def test_verifies_pack_digests():
    data = b"pack document bytes"
    for algorithm, digest in (("sha256", sha256(data).digest()), ("sha3-256", sha3_256(data).digest())):
        value = f"{algorithm}:" + urlsafe_b64encode(digest).rstrip(b"=").decode()
        d.verify_pack_digest(data, value)
        with pytest.raises(AgentProtocolError):
            d.verify_pack_digest(b"tampered", value)
    with pytest.raises(AgentProtocolError):
        d.verify_pack_digest(data, "md5:abc")


def test_permissions_follow_kinds_and_builtin_rules():
    registry = d.TypeRegistry.from_declarations([{"use": d.PACK_REACTIONS}, {"use": d.PACK_CURATION}], PACKS)
    observer, speaker, moderator = {"role": "observer"}, {"role": "speaker"}, {"role": "moderator"}
    creator = {"role": "observer", "is_creator": True}
    assert d.can_submit_event("reaction.create", observer, registry)
    assert d.can_submit_event("resource.add", speaker, registry)
    assert not d.can_submit_event("resource.add", observer, registry)
    assert d.can_submit_event("graph.update", moderator, registry)
    assert not d.can_submit_event("graph.update", speaker, registry)
    assert d.can_submit_event("graph.update", creator, registry)
    assert not d.can_submit_event("session.offer", speaker, registry)
    assert d.can_submit_event(d.ROOM_LEAVE, observer, registry)
    assert not d.can_submit_event(d.ROOM_LEAVE, {"role": "moderator", "is_creator": True}, registry)
    assert not d.can_submit_event(d.ROOM_JOIN, {}, registry)
    assert d.can_submit_event(d.ROOM_JOIN, {"direct_join_allowed": True}, registry)
    assert d.can_submit_event(d.ROOM_JOIN_REQUEST, {}, registry)
    assert not d.can_submit_event(d.ROOM_JOIN_REQUEST, speaker, registry)
    assert d.can_write_in_state(d.ROOM_JOIN_REQUEST, "scheduled")
    assert not d.can_write_in_state(d.ROOM_JOIN_REQUEST, "ended")
    assert not d.can_write_in_state(d.ROOM_CLOSE, "scheduled")
    assert not d.can_write_in_state(d.ROOM_CANCEL, "active")
    assert d.can_accept_room_write(d.MESSAGE_CREATE, "active", speaker, registry)
    with pytest.raises(AgentProtocolError):
        d.validate_room_write(d.MESSAGE_CREATE, "ended", speaker, registry)


def test_validates_payload_shapes():
    d.validate_message_create_payload({"content_type": "text/plain", "content": "hi"})
    d.validate_message_create_payload({"content_type": "application/json", "content": {"a": 1}})
    for content in (1, [], None):
        with pytest.raises(AgentProtocolError):
            d.validate_message_create_payload({"content_type": "application/json", "content": content})
    with pytest.raises(AgentProtocolError):
        d.validate_room_update_payload({})
    for field in ("host", "visibility", "types"):
        with pytest.raises(AgentProtocolError):
            d.validate_room_update_payload({field: "x"})
    with pytest.raises(AgentProtocolError):
        d.validate_room_update_payload({"start_time": 5, "end_time": 5})
    d.validate_room_update_payload({"topic": "New", "policy": {"open_roles": ["speaker"]}})
    with pytest.raises(AgentProtocolError):
        d.validate_room_join_payload({"role": "speaker", "request_id": "jr"})
    d.validate_room_join_payload({"role": "observer", "perspective": "p"})
    d.validate_room_member_remove_payload({"member": signer(41).agent_id(), "ban": True})
    with pytest.raises(AgentProtocolError):
        d.validate_room_member_remove_payload({"member": signer(41).agent_id(), "ban": "yes"})


def test_builds_redacts_and_verifies_record_chains():
    author = signer(18)
    create = author.sign_event(d.room_create_event(author.agent_id(), 100, 1, room_payload()))
    first = d.build_server_record("room123", 1, None, 110, create)
    second = d.build_server_record("room123", 2, first["hash"], 130, message(author, "room123", 1, first["hash"], 2))
    assert "accepted_at" in first and "received_at" not in first
    d.verify_server_record_chain([first, second])
    with pytest.raises(AgentProtocolError):
        d.verify_server_record_chain([second])
    redacted = d.redact_server_record(second)
    assert redacted["envelope"] == {"hash": second["envelope"]["hash"], "redacted": True, "type": d.MESSAGE_CREATE}
    d.verify_server_record_chain([first, redacted])
    with pytest.raises(AgentProtocolError):
        d.redact_server_record(first)
    forged = {**first, "envelope": {"hash": create["hash"], "redacted": True, "type": d.ROOM_CREATE}}
    with pytest.raises(AgentProtocolError):
        d.verify_server_record(forged)


def test_type_define_events_carry_a_base():
    moderator = signer(19)
    event = d.type_define_event(moderator.agent_id(), 100, 1, ROOM, 3, "h", FINDING_DEF)
    d.validate_discourse_envelope(moderator.sign_event(event))
    assert (event["base_seq"], event["base_hash"]) == (3, "h")


def test_builds_sse_event_stream_url():
    assert sse_events_url(HOST, "room123") == f"{HOST}/v1/rooms/room123/events/live"
    assert sse_events_url(f"{HOST}/", "room 1") == f"{HOST}/v1/rooms/room%201/events/live"
