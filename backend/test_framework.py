from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from modules.scenarios import Scenario, compile_scenario, builtin_scenarios
from modules.campaign_objectives import evaluate_objectives
from test_api_workflow import client

URL = 'http://allowed.example:8080/products?id=1'


def create(client, scenario='web-baseline'):
    target = client.post('/targets/', json={'name': 'Framework', 'scope_domain_ip': URL,
        'authorized_scopes': ['http://allowed.example:8080'], 'exploitation_authorized': True}).json()
    bindings = {'url': URL, **({'parameter': 'id'} if scenario == 'web-injection' else {})}
    response = client.post('/framework/assessments', json={'scenario_id': scenario, 'version': '1.0.0',
                           'target_id': target['id'], 'bindings': bindings})
    assert response.status_code == 200, response.text
    return response.json()


def execute(client, aid, index, stdout='HTTP/1.1 200 OK\r\nServer: example\r\n', code=0):
    with patch('main.schedule_auto_recommendations'), patch('main.executor.execute_command', new=AsyncMock(return_value={
            'stdout': stdout, 'stderr': '', 'return_code': code, 'duration_ms': 1})):
        return client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})


def snapshot(client, aid):
    response = client.get(f'/assessments/{aid}/framework')
    assert response.status_code == 200, response.text
    return response.json()


def test_catalog_and_graph_validation(client):
    assert len(client.get('/framework/techniques').json()['items']) == 7
    assert client.get('/framework/scenarios').json()['total'] == 3
    for definition in builtin_scenarios():
        assert Scenario.model_validate(definition)
    invalid = builtin_scenarios()[0]
    invalid['steps'][0]['depends_on'] = [{'step': 'exposures'}]
    with pytest.raises(ValueError, match='earlier'):
        Scenario.model_validate(invalid)


def test_scenario_compiler_rejects_injection_and_unknown_inputs():
    scenario = builtin_scenarios()[0]
    for values in ({'url': 'http://user:password@allowed.example'}, {'url': URL, 'shell': 'anything'},
                   {'url': URL + '\n--output=file'}, {'url': '--url http://allowed.example'}):
        with pytest.raises(ValueError):
            compile_scenario(scenario, values)


def test_scenario_objective_must_match_its_technique_and_target():
    scenario = builtin_scenarios()[0]
    scenario['steps'][0]['verify']['endpoint'] = 'http://another.example/'
    with pytest.raises(ValueError, match='must match'):
        compile_scenario(scenario, {'url': URL})
    scenario['steps'][0]['verify'] = {'kind': 'tcp_service', 'endpoint': 'allowed.example', 'port': 8080}
    with pytest.raises(ValueError, match='not supported'):
        compile_scenario(scenario, {'url': URL})


def test_scenario_objectives_cannot_reuse_proof_from_another_node():
    execution = {'id': 1, 'node_id': 'first', 'tool': 'curl', 'command': f'curl -I {URL}',
                 'stdout': 'HTTP/1.1 200 OK\r\n', 'stderr': '', 'return_code': 0,
                 'state': 'completed', 'approved_by_user': True, 'phase': 'recon'}
    criterion = {'kind': 'http_response', 'endpoint': URL, 'node_id': 'second'}
    result = evaluate_objectives({'success_criteria': [criterion]}, [execution], ['recon'])
    assert result['status'] == 'pending'
    assert not result['criteria'][0]['evidence']
    execution.update(node_id='second', stdout='HTTP/1.1 404 Not Found\r\n')
    criterion['expected_status'] = 200
    assert evaluate_objectives({'success_criteria': [criterion]}, [execution], ['recon'])['status'] == 'not_demonstrated'


def test_dependencies_and_frozen_plan_are_enforced_at_api(client):
    row = create(client)
    aid = row['id']
    assert execute(client, aid, 1).status_code == 409
    assert client.put(f'/assessments/{aid}/plan', json={'plan': row['plan']}).status_code == 409
    assert execute(client, aid, 0).status_code == 200
    assert snapshot(client, aid)['nodes'][1]['status'] == 'ready'
    assert execute(client, aid, 1).status_code == 200
    assert execute(client, aid, 2, stdout='').status_code == 200
    result = client.post(f'/assessments/{aid}/analyze')
    assert result.status_code == 200, result.text
    assert result.json()['current_phase'] == 'reporting'
    assert client.get(f'/assessments/{aid}/snapshot').json()['objective_result']['status'] == 'achieved'


def test_failed_prerequisite_skips_branch_without_claiming_execution(client):
    aid = create(client)['id']
    assert execute(client, aid, 0, code=7).status_code == 200
    state = snapshot(client, aid)
    assert [n['status'] for n in state['nodes']] == ['failed', 'skipped', 'skipped']
    assert execute(client, aid, 2).status_code == 409
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    assert snapshot(client, aid)['detection']['total'] == 1


@pytest.mark.parametrize('confirmed', [True, False])
def test_verified_branch_uses_analyzed_proof_and_advances_empty_phase(client, confirmed):
    aid = create(client, 'web-injection')['id']
    assert execute(client, aid, 0).status_code == 200
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    output = "GET parameter 'id' is 'AND boolean-based blind' injectable" if confirmed else 'No injectable parameters found'
    assert execute(client, aid, 1, stdout=output).status_code == 200
    assert execute(client, aid, 2).status_code == 409
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    state = snapshot(client, aid)
    assert state['nodes'][2]['status'] == ('ready' if confirmed else 'skipped')
    if confirmed:
        assert execute(client, aid, 2, stdout="banner: 'example-version'").status_code == 200
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    detail = client.get(f'/assessments/{aid}/snapshot').json()
    assert detail['current_phase'] == 'reporting'
    assert detail['objective_result']['status'] == ('achieved' if confirmed else 'not_demonstrated')


def test_pause_revision_resume_and_terminal_stop(client):
    aid = create(client)['id']
    revision = snapshot(client, aid)['workflow_revision']
    response = client.post(f'/assessments/{aid}/control', json={'workflow_revision': revision, 'action': 'pause', 'note': 'Maintenance'})
    assert response.status_code == 200, response.text
    assert execute(client, aid, 0).status_code == 409
    stale = client.post(f'/assessments/{aid}/control', json={'workflow_revision': revision, 'action': 'resume', 'note': 'Continue'})
    assert stale.status_code == 409
    revision = snapshot(client, aid)['workflow_revision']
    assert client.post(f'/assessments/{aid}/control', json={'workflow_revision': revision, 'action': 'resume', 'note': 'Continue'}).status_code == 200
    assert execute(client, aid, 0).status_code == 200
    revision = snapshot(client, aid)['workflow_revision']
    assert client.post(f'/assessments/{aid}/control', json={'workflow_revision': revision, 'action': 'stop', 'note': 'Engagement ended'}).status_code == 200
    assert execute(client, aid, 1).status_code == 409


def test_telemetry_and_cleanup_bind_to_attempts_and_retest_starts_empty(client):
    aid = create(client)['id']
    assert execute(client, aid, 0, code=7).status_code == 200
    assert client.post(f'/assessments/{aid}/analyze').status_code == 200
    state = snapshot(client, aid)
    item = {'execution_id': state['nodes'][0]['execution_id'], 'attempt': 1, 'source': 'test-siem',
            'external_id': 'evt-1', 'event_type': 'alert', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'summary': 'Connection attempt observed'}
    body = {'workflow_revision': state['workflow_revision'], 'events': [item]}
    response = client.post(f'/assessments/{aid}/telemetry', json=body)
    assert response.status_code == 200, response.text
    state = response.json()
    assert state['detection']['alerted'] == 1
    body['workflow_revision'] = state['workflow_revision']
    assert client.post(f'/assessments/{aid}/telemetry', json=body).status_code == 409
    response = client.post(f'/assessments/{aid}/cleanup', json={'workflow_revision': state['workflow_revision'],
                            'node_id': 'headers', 'note': 'Reviewed target and scanner artifacts'})
    assert response.status_code == 200, response.text
    assert response.json()['can_complete']
    response = client.post(f'/assessments/{aid}/control', json={'workflow_revision': response.json()['workflow_revision'],
                           'action': 'complete', 'note': 'Reviewed results and cleanup'})
    assert response.status_code == 200, response.text
    assert response.json()['control'] == 'completed'
    assert client.post(f'/assessments/{aid}/analyze').status_code == 409
    retest = client.post(f'/assessments/{aid}/retest')
    assert retest.status_code == 200, retest.text
    assert snapshot(client, retest.json()['id'])['detection']['total'] == 0
    assert retest.json()['framework_state']['baseline_id'] == aid
    assert client.delete(f'/assessments/{aid}').status_code == 200


def test_custom_versions_are_immutable_and_preview_checks_scope(client):
    definition = builtin_scenarios()[0]
    definition.update(id='team.web', version='1.0.0')
    assert client.post('/framework/scenarios', json=definition).status_code == 200
    assert client.post('/framework/scenarios', json=definition).status_code == 409
    row = create(client)
    response = client.post('/framework/preview', json={'scenario_id': 'team.web', 'version': '1.0.0',
        'target_id': row['target_id'], 'bindings': {'url': 'http://outside.example'}})
    assert response.status_code == 403, response.text


def test_http_objective_does_not_confuse_reachability_with_exploitation():
    execution = {'id': 1, 'tool': 'curl', 'command': f'curl -sSI {URL}', 'stdout': 'HTTP/1.1 403 Forbidden\r\n',
                 'stderr': '', 'return_code': 0, 'state': 'completed', 'approved_by_user': True, 'phase': 'recon'}
    criterion = {'kind': 'http_response', 'endpoint': URL}
    assert evaluate_objectives({'success_criteria': [criterion]}, [execution], ['recon'])['status'] == 'achieved'
    assert evaluate_objectives({'success_criteria': [{**criterion, 'expected_status': 200}]}, [execution], ['recon'])['status'] == 'not_demonstrated'
    assert evaluate_objectives({'success_criteria': [criterion]}, [execution], [])['status'] == 'pending'


def test_named_roles_and_approval_attribution(client):
    keys = {}
    for role in ('viewer', 'operator', 'admin'):
        response = client.post('/team/credentials', json={'name': 'test-' + role, 'role': role})
        assert response.status_code == 200, response.text
        assert response.headers['cache-control'] == 'no-store'
        keys[role] = response.json()['key']
    row = create(client)
    viewer = {'X-API-Key': keys['viewer']}
    assert client.get('/team/me', headers=viewer).json()['role'] == 'viewer'
    assert client.get('/catalog/assessments', headers=viewer).status_code == 200
    assert client.post(f'/assessments/{row["id"]}/execute', headers=viewer, json={'step_index': 0, 'approved': True}).status_code == 403
    operator = {'X-API-Key': keys['operator']}
    assert client.put('/settings', headers=operator, json={}).status_code == 403
    assert client.post('/team/credentials', headers=operator, json={'name': 'rogue', 'role': 'admin'}).status_code == 403
    with patch('main.schedule_auto_recommendations'), patch('main.executor.execute_command', new=AsyncMock(return_value={
            'stdout': 'HTTP/1.1 200 OK', 'stderr': '', 'return_code': 0, 'duration_ms': 1})):
        response = client.post(f'/assessments/{row["id"]}/execute', headers=operator, json={'step_index': 0, 'approved': True})
    assert response.status_code == 200, response.text
    events = client.get(f'/assessments/{row["id"]}/framework/events').json()['items']
    assert next(e for e in events if e['kind'] == 'approval')['actor'] == 'test-operator'
    credentials = client.get('/team/credentials').json()['items']
    assert all('key' not in c and 'key_hash' not in c for c in credentials)
    identifier = next(c['id'] for c in credentials if c['role'] == 'operator')
    assert client.delete(f'/team/credentials/{identifier}').status_code == 200
    assert client.get('/team/me', headers=operator).status_code == 401


def test_pausing_cancels_queued_job_and_preserves_attempt(client):
    row = create(client)
    aid = row['id']
    response = client.post(f'/assessments/{aid}/execute', json={'step_index': 0, 'approved': True, 'background': True})
    assert response.status_code == 202
    state = snapshot(client, aid)
    response = client.post(f'/assessments/{aid}/control', json={'workflow_revision': state['workflow_revision'],
                                                            'action': 'pause', 'note': 'Hold execution'})
    assert response.status_code == 200, response.text
    detail = client.get(f'/assessments/{aid}/snapshot').json()
    assert detail['executions'][0]['state'] == 'cancelled'
    assert detail['status'] != 'running'


def test_shared_vm_lease_prevents_concurrent_ownership(client):
    from database import get_db
    from main import app
    from modules.worker_resources import reserve, release
    session = next(app.dependency_overrides[get_db]())
    remote = {'host': 'kali.local', 'port': 22, 'username': 'tester'}
    assert reserve(session, remote, 'worker-a', 1)
    session.commit()
    assert not reserve(session, remote, 'worker-b', 2)
    release(session, 'worker-b', 1)
    session.commit()
    assert not reserve(session, remote, 'worker-b', 2)
    release(session, 'worker-a', 1)
    session.commit()
    assert reserve(session, remote, 'worker-b', 2)
    session.close()


@pytest.mark.parametrize('command, allowed', [
    ('curl -I http://app.test:8080/', True), ('curl -I http://app.test:8081/', False),
    ('nmap -sT -Pn -p 8080 app.test', True), ('nmap -sT -Pn -p 8080,8081 app.test', False),
    ('nmap -sT -p 8080 app.test', False),
    ('nmap -sV app.test', False), ('nmap -sU -p 8080 app.test', False),
    ('nmap -sn -p 8080 app.test', False), ('curl -I http://app.test/', False),
])
def test_port_scope_cannot_authorize_whole_host_or_other_ports(command, allowed):
    from modules.policy_engine import policy_engine
    assert policy_engine.validate_command(command, ['app.test:8080'])[0] is allowed


def test_scenario_execution_does_not_schedule_mutating_recommendations(client):
    aid = create(client)['id']
    with patch('main.schedule_auto_recommendations') as schedule, patch('main.executor.execute_command', new=AsyncMock(return_value={
            'stdout': 'HTTP/1.1 200 OK', 'stderr': '', 'return_code': 0, 'duration_ms': 1})):
        assert client.post(f'/assessments/{aid}/execute', json={'step_index': 0, 'approved': True}).status_code == 200
    schedule.assert_not_called()


def test_prerequisite_retry_preserves_executed_branch_history(client):
    aid = create(client)['id']
    assert execute(client, aid, 0, code=7).status_code == 200
    assert execute(client, aid, 0).status_code == 200
    assert execute(client, aid, 1).status_code == 200
    before = snapshot(client, aid)['nodes'][0]
    response = execute(client, aid, 0)
    assert response.status_code == 409, response.text
    assert 'dependent step' in response.json()['detail']
    assert snapshot(client, aid)['nodes'][0] == before


def test_fallback_plan_preserves_https_path_and_filters_port_scope():
    from modules.planner import planner_agent
    from modules.policy_engine import policy_engine
    for target in ('app.test:8080', 'https://app.test:8443/service'):
        plan, source = planner_agent.generate_plan(target, 'Inspect', policy_engine=policy_engine, authorized_scopes=[target])
        assert plan and source == 'default-unconfigured'
        assert all(policy_engine.validate_command(step['command'], [target], expected_tool=step['tool'])[0] for step in plan)
        assert not any(step['tool'] == 'traceroute' for step in plan)
        if target.startswith('https'):
            assert all(target in step['command'] for step in plan)


def test_retest_comparison_requires_matching_analyzed_phases(client):
    baseline = create(client)['id']
    assert execute(client, baseline, 0, code=7).status_code == 200
    assert client.post(f'/assessments/{baseline}/analyze').status_code == 200
    current = client.post(f'/assessments/{baseline}/retest').json()['id']
    route = f'/assessments/{current}/framework/compare/{baseline}'
    assert client.get(route).status_code == 409
    assert execute(client, current, 0).status_code == 200
    assert execute(client, current, 1).status_code == 200
    assert execute(client, current, 2).status_code == 200
    assert client.post(f'/assessments/{current}/analyze').status_code == 200
    comparison = client.get(route)
    assert comparison.status_code == 200, comparison.text
    first = comparison.json()['items'][0]
    assert first['before']['execution'] == 'failed'
    assert first['after']['execution'] == 'completed'
