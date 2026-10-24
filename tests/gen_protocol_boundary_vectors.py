"""Regenerate additive Identity/Profile/Delegation/Discourse boundary fixtures.

Only fixed, already published test seeds are used. Existing fixtures are kept;
this generator owns the named boundary sections and Max-Seen-Nonce edge cases.
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python/agent-protocols/src'))
from agent_protocols.identity import AgentSigner
from agent_protocols.delegation import materialize_delegation_credential

DOCS = ROOT / 'docs/protocols'
NOW = 1800000000000
OWNER = AgentSigner.from_seed(bytes([7]) * 32)
SUBJECT = AgentSigner.from_seed(bytes([8]) * 32)


def signed(protocol, kind, payload, nonce, at=NOW):
    return OWNER.sign_event({'protocol': protocol, 'type': kind, 'actor': OWNER.agent_id(),
                             'created_at': at, 'nonce': nonce, 'payload': payload})


def profile(name, nonce, at=NOW, marker='valid'):
    return signed('agent-profile/1.0', 'profile.update',
                  {'id': OWNER.agent_id(), 'name': name, 'extra': {'marker': marker}}, nonce, at)


def load(protocol):
    path = DOCS / protocol / '1.0.vectors.json'
    return path, json.loads(path.read_text())


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def generate():
    path, identity = load('agent-identity')
    for case in identity['max_seen_nonce']:
        if case['name'] == 'accept the largest allowed jump':
            case.update(header='4294968295', next_after=4294968296)
        if case['name'] == 'reject a jump beyond the bound':
            case['header'] = '4294968296'
    identity['replay_boundary'] = {
        'envelope': profile('Replay boundary', 1, NOW + 300000), 'accepted_at': NOW,
        'window_ms': 300000, 'nonce_ttl_ms': 600000,
        'attempts': [{'now': NOW + delta, 'error': error} for delta, error in
                     [(599999, 'nonce_not_greater'), (600000, 'nonce_not_greater'), (600001, 'timestamp_out_of_window')]],
    }
    valid = json.dumps({'result': [profile('HTTP fixture', 2)]}, separators=(',', ':'), ensure_ascii=False)
    duplicate = valid.replace('"marker":"valid"', '"marker":"discarded","marker":"valid"')
    replacement = json.dumps({'result': [profile('UTF-8 fixture', 3, marker='\ufffd')]}, separators=(',', ':'), ensure_ascii=False)
    identity['http_json'] = [
        {'name': 'valid signed list', 'body_hex': valid.encode().hex(), 'valid': True},
        {'name': 'duplicate signed nested member', 'body_hex': duplicate.encode().hex(), 'valid': False},
        {'name': 'invalid UTF-8 cannot become a signed replacement character',
         'body_hex': replacement.encode().replace(b'\xef\xbf\xbd', b'\xff').hex(), 'valid': False},
    ]
    save(path, identity)

    path, profiles = load('agent-profile')
    old, new, conflict = profile('Old', 100), profile('New', 101, NOW - 1), profile('Conflict', 101)
    profiles['latest_pins'] = {'owner': OWNER.agent_id(), 'updates': {'old': old, 'new': new, 'conflict': conflict},
                              'steps': [{'update': key, 'error': error} for key, error in
                                        [('old', None), ('new', None), ('new', None), ('old', 'stale_profile'), ('conflict', 'stale_profile')]]}
    save(path, profiles)

    path, delegation = load('agent-delegation')
    principal = 'https://principal.example/review'
    document = {'protocol': 'agent-delegation/1.0', 'id': principal,
                'controllers': [{'id': OWNER.agent_id(), 'source': 'local', 'valid_from': NOW - 1, 'delegation': '*'}],
                'delegation_service': 'https://principal.example', 'updated_at': NOW}
    payload = {'id': 'review', 'principal_id': principal, 'subject': SUBJECT.agent_id(),
               'scopes': ['read'], 'audiences': ['https://app.example']}
    grant = signed('agent-delegation/1.0', 'delegation.grant', payload, 1)
    revoke = signed('agent-delegation/1.0', 'delegation.revoke', {'id': 'review', 'principal_id': principal}, 2)
    replacement = signed('agent-delegation/1.0', 'delegation.grant', {**payload, 'scopes': ['write']}, 3)
    record = {'envelope': grant, 'accepted_at': NOW}
    current = materialize_delegation_credential(grant, accepted_at=NOW)
    cases = []
    for name, checked, now, extras, usable in [
        ('fresh', NOW, NOW, [], True),
        ('last fresh millisecond', NOW, NOW + 300000, [], True),
        ('stale status', NOW, NOW + 300001, [], False),
        ('future status at skew bound', NOW + 60000, NOW, [], True),
        ('future status beyond skew', NOW + 60001, NOW, [], False),
        ('status before acceptance', NOW - 1, NOW, [], False),
        ('known later revocation', NOW + 1000, NOW + 1000, [{'envelope': revoke, 'accepted_at': NOW + 1}], False),
        ('same-millisecond revocation preserves acceptance order', NOW, NOW, [{'envelope': revoke, 'accepted_at': NOW}], False),
        ('known later replacement', NOW + 1000, NOW + 1000, [{'envelope': replacement, 'accepted_at': NOW + 1}], False),
    ]:
        cases.append({'name': name, 'credential': {**current, 'checked_at': checked},
                      'records': [record, *extras], 'now': now, 'verified': True, 'usable': usable})
    delegation['status_checks'] = {'document': document, 'audience': 'https://app.example', 'cases': cases}
    save(path, delegation)

    path, discourse = load('agent-discourse')
    cases = []
    for value, valid in [('a', True), ('a\n', False), ('a\r', False), ('a\u2028', False)]:
        cases.append({'name': 'absolute end ' + repr(value), 'schema': {'type': 'string', 'pattern': '^a$'}, 'value': value, 'valid': valid})
    cases.append({'name': 'unanchored search', 'schema': {'pattern': 'a'}, 'value': 'a\n', 'valid': True})
    schema = {'type': 'object', 'patternProperties': {'^a$': {'type': 'integer'}},
              'properties': {'copy': {'$ref': '#/patternProperties/%5Ea%24'}}, 'additionalProperties': False}
    for value, valid in [({'a': 1}, True), ({'a\n': 1}, False), ({'copy': 1}, True), ({'copy': 'bad'}, False)]:
        cases.append({'name': 'patternProperties ' + repr(value), 'schema': schema, 'value': value, 'valid': valid})
    resource = copy.deepcopy(schema)
    resource['$id'] = 'https://schemas.example/inner'
    cases.append({'name': 'local ref in embedded resource',
                  'schema': {'$defs': {'inner': resource}, 'properties': {'box': {'$ref': '#/$defs/inner'}}},
                  'value': {'box': {'copy': 1}}, 'valid': True})
    cases.append({'name': 'parent pointer into embedded resource',
                  'schema': {'$defs': {'inner': resource}, 'properties': {'copy': {'$ref': '#/$defs/inner/patternProperties/%5Ea%24'}}},
                  'value': {'copy': 1}, 'valid': True})
    discourse['payload_validation'] = cases
    whitespace = [*range(9, 14), 0x20, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]
    discourse['blank_strings'] = [{'value': chr(n), 'valid': False} for n in whitespace] + [
        {'value': '', 'valid': False}, {'value': '\u001c', 'valid': True},
        {'value': '\u200b', 'valid': True}, {'value': '\ufeff topic \u0085', 'valid': True}]
    definition = {'type': 'review.old', 'kind': 'message', 'title': 'Old', 'schema': {'type': 'object'}}
    discourse['atomic_import'] = {'initial': definition, 'declaration': {'use': 'adp:review/1.0'},
                                  'pack': {'id': 'adp:review/1.0', 'title': 'Review', 'types': [
                                      {**definition, 'type': 'review.new', 'title': 'New'}, {**definition, 'kind': 'control'}]},
                                  'error': 'type_conflict'}
    save(path, discourse)


if __name__ == '__main__':
    generate()
    print('Regenerated protocol boundary vectors.')
