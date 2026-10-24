"""Shared normative boundary cases plus strict HTTP and restart integration."""
import copy
import json
from pathlib import Path

import pytest
import requests

from agent_protocols import discourse as d
from agent_protocols.delegation import verify_delegation_credential
from agent_protocols.identity import MemoryNonceStore, verify_submission
from agent_protocols.profile import ProfileCache, validate_profile_update
from agent_protocols.http_client import ProfileClient
from agent_protocols.errors import AgentProtocolError

DOCS = Path(__file__).resolve().parents[3] / 'docs/protocols'
def vectors(name): return json.loads((DOCS / f'agent-{name}/1.0.vectors.json').read_text())
I, P, D, A = (vectors(name) for name in ['identity', 'profile', 'discourse', 'delegation'])


def test_inclusive_replay_cache_boundary():
    c = I['replay_boundary']; store = MemoryNonceStore()
    verify_submission(c['envelope'], store, now_ms=c['accepted_at'], window_ms=c['window_ms'], nonce_ttl_ms=c['nonce_ttl_ms'])
    for step in c['attempts']:
        with pytest.raises(AgentProtocolError) as error:
            verify_submission(c['envelope'], store, now_ms=step['now'], window_ms=c['window_ms'], nonce_ttl_ms=c['nonce_ttl_ms'], is_accepted=lambda _: False)
        assert error.value.code == step['error']


class RawSession:
    def __init__(self, bodies): self.bodies = iter(bodies)
    def get(self, *args, **kwargs):
        response = requests.Response(); response.status_code = 200
        response._content = next(self.bodies)
        return response


@pytest.mark.parametrize('case', I['http_json'], ids=lambda c:c['name'])
def test_http_strict_json_before_signature_verification(case):
    client = ProfileClient('https://profile.example', RawSession([bytes.fromhex(case['body_hex'])]))
    if case['valid']: validate_profile_update(client.profile_events(I['keys'][0]['agent_id'])['result'][0])
    else:
        with pytest.raises(AgentProtocolError) as error: client.profile_events(I['keys'][0]['agent_id'])
        assert error.value.code == 'invalid_event'


def test_profile_pins_survive_restore():
    c=P['latest_pins']; cache=ProfileCache(); expected=None
    for step in c['steps']:
        envelope=c['updates'][step['update']]
        if step['error']:
            with pytest.raises(AgentProtocolError) as error: cache.observe(envelope,c['owner'])
            assert error.value.code == step['error']
        else: expected=cache.observe(envelope,c['owner'])['hash']
        cache=ProfileCache(cache.snapshot())
        assert cache.get(c['owner'])['hash'] == expected


def test_latest_profile_http_pins_but_history_does_not_downgrade():
    c=P['latest_pins']
    bodies=[json.dumps({'result':[c['updates'][key]]}).encode() for key in ['new','old','old']]
    client=ProfileClient('https://profile.example',RawSession(bodies))
    assert client.latest_profile_update(c['owner'])['hash'] == c['updates']['new']['hash']
    with pytest.raises(AgentProtocolError) as error: client.latest_profile_update(c['owner'])
    assert error.value.code == 'stale_profile'
    assert client.profile_events(c['owner'],20)['result'][0]['hash'] == c['updates']['old']['hash']
    assert client.profile_cache.get(c['owner'])['hash'] == c['updates']['new']['hash']


@pytest.mark.parametrize('case', A['status_checks']['cases'], ids=lambda c:c['name'])
def test_delegation_freshness_and_known_history(case):
    scope=A['status_checks']
    verdict=verify_delegation_credential(case['credential'],case['records'],scope['document'],scope['document']['id'],scope['audience'],case['now'])
    assert verdict['verified'] == case['verified']
    assert verdict['usable'] == case['usable']


@pytest.mark.parametrize('case',D['payload_validation'],ids=lambda c:c['name'])
def test_portable_schema_payload(case):
    registry=d.TypeRegistry(); original=copy.deepcopy(case['schema'])
    registry.define({'type':'review.test','kind':'message','title':'Test','schema':case['schema']})
    if case['valid']: registry.validate_payload('review.test',case['value'])
    else:
        with pytest.raises(AgentProtocolError) as error: registry.validate_payload('review.test',case['value'])
        assert error.value.code == 'payload_schema_violation'
    assert original == case['schema']


def test_portable_blank_strings():
    for case in D['blank_strings']:
        value=case['value']
        checks=[lambda:d.validate_room_create_payload({'host':'https://host.example','topic':value,'visibility':'public','start_time':1000,'end_time':2000}),lambda:d.validate_room_update_payload({'topic':value}),lambda:d.validate_type_def({'type':'review.blank','kind':'message','title':value,'schema':{}}),lambda:d.validate_message_create_payload({'content_type':value,'content':'test'})]
        for check in checks:
            if case['valid']: check()
            else:
                with pytest.raises(AgentProtocolError): check()


def test_failed_type_pack_is_atomic():
    c=D['atomic_import'];registry=d.TypeRegistry();registry.define(c['initial']);before=copy.deepcopy(registry.definitions())
    with pytest.raises(AgentProtocolError) as error: registry.apply(c['declaration'],{c['pack']['id']:c['pack']})
    assert error.value.code == c['error']
    assert registry.definitions() == before
