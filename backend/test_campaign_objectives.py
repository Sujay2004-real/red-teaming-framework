from unittest.mock import AsyncMock, patch

import pytest

from modules.campaign_objectives import evaluate_objectives
from test_api_workflow import client


ENDPOINT = 'http://allowed.example:8080/products?id=1'
CONFIRMATION = "GET parameter 'id' is 'AND boolean-based blind' injectable"
CRITERIA = [{'kind': kind, 'endpoint': ENDPOINT, 'parameter': 'id'}
            for kind in ('sql_injection', 'database_banner')]


def execution(**changes):
    return {'id': 1, 'attempt': 1, 'tool': 'sqlmap', 'phase': 'exploitation',
            'command': f'sqlmap -u {ENDPOINT} --batch --ignore-redirects',
            'stdout': CONFIRMATION, 'stderr': '', 'return_code': 0,
            'approved_by_user': True, 'state': 'completed', 'evidence_sha256': 'a' * 64, **changes}


def evaluate(*executions, phases=('exploitation', 'post_exploitation')):
    return evaluate_objectives({'success_criteria': CRITERIA}, list(executions), phases)


def test_objective_needs_both_confirmation_and_flagged_banner_with_receipts():
    first = evaluate(execution())
    assert first['status'] == 'pending'
    assert first['criteria'][0]['status'] == 'achieved'
    banner = execution(id=2, phase='post_exploitation', command=f'sqlmap -u {ENDPOINT} --ignore-redirects --banner',
                       stdout="banner: '3.50.4'")
    result = evaluate(execution(), banner)
    assert result['status'] == 'achieved'
    assert [proof['execution_id'] for proof in result['criteria'][1]['evidence']] == [1, 2]
    assert result['criteria'][1]['evidence'][1]['evidence_sha256'] == 'a' * 64


@pytest.mark.parametrize('changes', [
    {'return_code': 1}, {'return_code': -1, 'state': 'timed_out'},
    {'state': 'cancelled'}, {'approved_by_user': False}, {'tool': 'curl'},
    {'phase': 'recon'}, {'stdout': "GET parameter 'id' might be injectable"},
    {'stdout': "GET parameter 'id' is not injectable"}, {'stdout': 'HTTP/1.1 200 OK'},
    {'stdout': "POST parameter 'id' is 'AND boolean-based blind' injectable"},
    {'stdout': "Cookie parameter 'id' is 'AND boolean-based blind' injectable"},
    {'command': 'sqlmap -u https://allowed.example:8080/products?id=1'},
    {'command': 'sqlmap -u http://allowed.example:8081/products?id=1'},
    {'command': 'sqlmap -u http://allowed.example:8080/Products?id=1'},
    {'command': 'sqlmap -u http://allowed.example:8080/products?id=1&action=delete'},
    {'command': f'sqlmap -u {ENDPOINT} --second-order http://allowed.example:8080/other'},
    {'command': f'sqlmap -u {ENDPOINT} --csrf-url http://allowed.example:8080/token'},
])
def test_unproven_or_differently_scoped_execution_cannot_achieve_goal(changes):
    assert evaluate(execution(**changes))['criteria'][0]['status'] != 'achieved'


def test_unanalyzed_evidence_and_unflagged_banner_do_not_complete_goal():
    assert evaluate(execution(), phases=[])['status'] == 'pending'
    result = evaluate(execution(stdout=CONFIRMATION + "\nbanner: '3.50.4'"))
    assert result['criteria'][1]['status'] == 'pending'


def test_negative_check_is_not_demonstrated_and_failure_is_inconclusive():
    negative = evaluate(execution(stdout='all tested parameters do not appear to be injectable'))
    assert negative['status'] == 'not_demonstrated'
    assert 'does not establish' in negative['scope_note']
    assert evaluate(execution(return_code=1))['status'] == 'inconclusive'


def create(client, **brief_changes):
    target = client.post('/targets/', json={
        'name': 'Objective test', 'scope_domain_ip': ENDPOINT,
        'authorized_scopes': ['http://allowed.example:8080'], 'exploitation_authorized': True,
    }).json()
    return client.post('/assessments/', json={
        'target_id': target['id'], 'objective': 'Verify injection and bounded impact',
        'plan': [{'tool': 'curl', 'command': f'curl -I {ENDPOINT}'}],
        'engagement_brief': {'success_criteria': CRITERIA, **brief_changes},
    })


@pytest.mark.parametrize('criteria', [
    [{'kind': 'sql_injection', 'endpoint': ENDPOINT, 'parameter': 'id', 'status': 'achieved'}],
    [{'kind': 'arbitrary_regex', 'endpoint': ENDPOINT, 'parameter': 'id'}],
    [{'kind': 'sql_injection', 'endpoint': 'file:///etc/passwd', 'parameter': 'id'}],
    [{'kind': 'sql_injection', 'endpoint': ENDPOINT + '&id=2', 'parameter': 'id'}],
    [{'kind': 'sql_injection', 'endpoint': ENDPOINT, 'parameter': 'missing'}],
    CRITERIA + CRITERIA, 'achieved',
])
def test_client_cannot_supply_a_verdict_or_ambiguous_criterion(client, criteria):
    assert create(client, success_criteria=criteria).status_code == 422


def test_criterion_must_be_in_authorized_scope(client):
    response = create(client, success_criteria=[{**CRITERIA[0], 'endpoint': ENDPOINT.replace(':8080', ':9090')}])
    assert response.status_code == 403


def test_api_snapshot_and_report_use_the_same_analyzed_evidence(client, tmp_path):
    created = create(client)
    assert created.status_code == 200, created.text
    aid = created.json()['id']
    assert client.get(f'/assessments/{aid}/snapshot').json()['objective_result']['status'] == 'pending'
    for phase, output in [('recon', 'HTTP/1.1 200 OK'), ('exploitation', CONFIRMATION),
                          ('post_exploitation', CONFIRMATION + "\nbanner: '3.50.4'")]:
        detail = client.get(f'/assessments/{aid}').json()
        assert detail['current_phase'] == phase
        response = {'stdout': output, 'stderr': '', 'return_code': 0, 'duration_ms': 1}
        with patch('main.schedule_auto_recommendations'), patch('main.executor.execute_command', new=AsyncMock(return_value=response)):
            for index, step in enumerate(detail['plan']):
                if step.get('phase', 'recon') == phase:
                    executed = client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})
                    assert executed.status_code == 200, executed.text
        analyzed = client.post(f'/assessments/{aid}/analyze')
        assert analyzed.status_code == 200, analyzed.text
    snapshot = client.get(f'/assessments/{aid}/snapshot').json()
    assert snapshot['objective_result']['status'] == 'achieved'
    assert client.get(f'/assessments/{aid}/campaign').json()['objective_result'] == snapshot['objective_result']
    with patch('main.REPORTS_DIR', tmp_path):
        report = client.post(f'/assessments/{aid}/report')
    assert report.status_code == 200, report.text
    html = client.get(report.json()['download_url']).text
    assert 'Campaign objective evidence' in html
    for proof in snapshot['objective_result']['criteria'][1]['evidence']:
        assert proof['evidence_sha256'] in html
