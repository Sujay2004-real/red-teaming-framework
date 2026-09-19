from unittest.mock import AsyncMock, patch

import pytest

from modules.analyzer import analyzer_agent
from modules.verification import match_verification
from test_api_workflow import client  # shared isolated in-memory API fixture


def scan(output="GET parameter 'id' is 'AND boolean-based blind' injectable", **changes):
    return {'tool': 'sqlmap', 'command': 'sqlmap -u http://allowed.example/search?id=1 --ignore-redirects',
            'stdout': output, 'stderr': '', 'return_code': 0, **changes}


def finding(**changes):
    return {'title': 'SQL injection', 'endpoint': 'http://allowed.example/search?id=1',
            'parameter': 'id', **changes}


def test_explicit_confirmation_matches_same_flaw_and_normalizes_default_port():
    proof = analyzer_agent.confirmed_verifications([scan()])
    matches = match_verification([finding(endpoint='http://ALLOWED.example:80/search?id=2')], proof)
    assert len(matches) == 1
    assert matches[0][2] == scan()['stdout']


@pytest.mark.parametrize('changes', [
    {'endpoint': 'http://outside.example/search?id=1'},
    {'endpoint': 'https://allowed.example/search?id=1'},
    {'endpoint': 'http://allowed.example:9000/search?id=1'},
    {'endpoint': 'http://allowed.example/other?id=1'},
    {'endpoint': 'http://allowed.example/Search?id=1'},
    {'endpoint': 'http://allowed.example/search?id=1&action=delete'},
    {'endpoint': ''},
    {'parameter': 'email'},
    {'parameter': 'ID'},
    {'title': 'Missing Content-Security-Policy header'},
    {'title': 'Version scanner confirmed: SQLite'},
    {'title': 'Public exploits available for this version'},
])
def test_different_locations_parameters_or_flaws_do_not_verify(changes):
    assert match_verification([finding(**changes)], analyzer_agent.confirmed_verifications([scan()])) == []


@pytest.mark.parametrize('output', [
    "GET parameter 'id' is not injectable",
    "GET parameter 'id' might be injectable",
    "GET parameter 'id' appears vulnerable",
    "GET parameter 'id' is 'AND boolean-based blind'",  # missing confirmation
    "heuristic test: GET parameter 'id' is vulnerable",
    'HTTP/1.1 200 OK\n{"email":"admin@example.test"}',
    'back-end DBMS: SQLite',
])
def test_nonconfirming_output_does_not_create_proof(output):
    assert analyzer_agent.confirmed_verifications([scan(output)]) == []


@pytest.mark.parametrize('changes', [
    {'return_code': -1}, {'return_code': 1}, {'return_code': None},
    {'command': ''}, {'tool': 'curl'},
    {'command': 'sqlmap -u http://allowed.example/ -u http://outside.example/'},
    {'command': 'sqlmap -u http://allowed.example/ --csrf-url http://allowed.example/token'},
])
def test_failed_or_ambiguously_located_runs_cannot_verify(changes):
    assert analyzer_agent.confirmed_verifications([scan(**changes)]) == []


def test_nonempty_ai_evidence_without_scanner_confirmation_cannot_verify():
    fabricated = finding(evidence='This vulnerability has been confirmed', source_tools=['sqlmap'])
    assert match_verification([finding()], [fabricated]) == []


@pytest.mark.parametrize('outcome', ['confirmed', 'failed', 'clean', 'fabricated_ai'])
def test_api_verification_is_grounded_and_does_not_upgrade_headers(client, outcome):
    target = client.post('/targets/', json={
        'name': 'Lab', 'scope_domain_ip': 'allowed.example',
        'authorized_scopes': ['allowed.example'], 'exploitation_authorized': True,
    }).json()
    created = client.post('/assessments/', json={
        'target_id': target['id'], 'objective': 'Verify findings',
        'plan': [{'tool': 'nuclei', 'command': 'nuclei -u http://allowed.example/search?id=1 -dr'}],
    })
    assert created.status_code == 200, created.text
    aid = created.json()['id']
    recon = {'stdout': '[sqli] [http] [high] http://allowed.example/search?id=1\n'
                       '[missing-csp] [http] [medium] http://allowed.example/search?id=1',
             'stderr': '', 'return_code': 0, 'duration_ms': 1}
    with patch('main.schedule_auto_recommendations'), patch('main.executor.execute_command', new=AsyncMock(return_value=recon)):
        assert client.post(f'/assessments/{aid}/execute', json={'step_index': 0, 'approved': True}).status_code == 200
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    plan = client.get(f'/assessments/{aid}').json()['plan']
    result = {'stdout': scan()['stdout'] if outcome in {'confirmed', 'failed'} else 'no injection confirmed',
              'stderr': '', 'return_code': 1 if outcome == 'failed' else 0, 'duration_ms': 1}
    with patch('main.schedule_auto_recommendations'), patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        for index, step in enumerate(plan):
            if step['phase'] == 'exploitation':
                response = client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})
                assert response.status_code == 200, response.text
    if outcome == 'fabricated_ai':
        fabricated = analyzer_agent.analyze_results([scan()], include_metadata=False)
        with patch('main.analyzer_agent.analyze_results', return_value=(fabricated, 'ai-provider')):
            response = client.post(f'/assessments/{aid}/analyze')
    else:
        response = client.post(f'/assessments/{aid}/analyze')
    assert response.status_code == 200, response.text
    detail = client.get(f'/assessments/{aid}').json()
    verified = [f for f in detail['findings'] if f['verification'] == 'verified']
    if outcome == 'confirmed':
        assert len(verified) == 2  # the recon claim and the new sqlmap finding
        assert all('sqli' in f['title'].lower() or 'sql injection' in f['title'].lower() for f in verified)
        assert all(f['verified_by'] == ['sqlmap'] for f in verified)
    else:
        assert verified == []
        assert response.json()['auto_drafted']['steps'] == 0
    assert not any(f['verification'] for f in detail['findings'] if 'missing-csp' in f['title'])
