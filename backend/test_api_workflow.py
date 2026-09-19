from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from main import app
from conftest import OPERATOR_TEST_KEY


@pytest.fixture
def client():
    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app, headers={'X-API-Key': OPERATOR_TEST_KEY})
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def create_assessment(client):
    target = client.post('/targets/', json={
        'name': 'Lab',
        'scope_domain_ip': 'juice-shop:3000',
        'authorized_scopes': ['juice-shop:3000'],
    }).json()
    response = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect the lab',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV juice-shop'},
            {'tool': 'curl', 'command': 'curl -I http://juice-shop:3000'},
        ],
    })
    assert response.status_code == 200
    return response.json()


def test_workflow_rejects_duplicate_and_incomplete_actions(client):
    assessment = create_assessment(client)
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}

    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        first = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
        duplicate = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})

    assert first.status_code == 200
    assert duplicate.status_code == 409
    assert client.post(f"/assessments/{assessment['id']}/analyze").status_code == 409
    assert client.post(f"/assessments/{assessment['id']}/report").status_code == 409


def test_completed_assessment_can_be_analyzed_and_reported(client, tmp_path):
    assessment = create_assessment(client)
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}

    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        for step_index in (0, 1):
            response = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': step_index, 'approved': True})
            assert response.status_code == 200

    analyzed = client.post(f"/assessments/{assessment['id']}/analyze")
    assert analyzed.status_code == 200
    assert analyzed.json()['analyzer'] == 'deterministic-fallback'

    with patch('main.REPORTS_DIR', tmp_path):
        reported = client.post(f"/assessments/{assessment['id']}/report")

    assert reported.status_code == 200


def test_snapshot_reports_discovered_hosts_after_nmap(client):
    """The snapshot is the load path the UI uses, so it must carry the nmap
    host inventory the network-inventory panel renders. A regression here left
    the panel permanently empty even after discovery ran."""
    assessment = create_assessment(client)
    nmap_output = (
        'Nmap scan report for 192.168.198.86\n'
        'Host is up (0.0010s latency).\n'
        'PORT      STATE SERVICE\n'
        '20128/tcp open  http\n'
        '\n'
        'Nmap scan report for 192.168.198.90\n'
        'Host is up (0.0020s latency).\n'
        '80/tcp open  http\n'
    )
    result = {'stdout': nmap_output, 'stderr': '', 'return_code': 0, 'duration_ms': 10}
    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        assert client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True}).status_code == 200

    snapshot = client.get(f"/assessments/{assessment['id']}/snapshot")
    assert snapshot.status_code == 200
    assert snapshot.json()['discovered_hosts'] == ['192.168.198.86', '192.168.198.90']


def test_aggressive_lab_requires_exploitation_authorization(client):
    """aggressive_lab is only stored when exploitation is also authorized, so
    it can never be turned on for a target the letter did not clear."""
    uncoupled = client.post('/targets/', json={
        'name': 'A', 'scope_domain_ip': '192.168.56.10', 'authorized_scopes': ['192.168.56.10'],
        'aggressive_lab': True}).json()
    assert uncoupled['aggressive_lab'] is False
    coupled = client.post('/targets/', json={
        'name': 'B', 'scope_domain_ip': '192.168.56.20', 'authorized_scopes': ['192.168.56.20'],
        'exploitation_authorized': True, 'aggressive_lab': True}).json()
    assert coupled['exploitation_authorized'] is True
    assert coupled['aggressive_lab'] is True


def test_prompt_mode_creates_one_assessment_per_picked_target(client):
    """The second entry mode: registered targets + a free-text prompt.

    The UI calls POST /assessments/ once per picked target with the prompt as
    the objective and no letter brief or requirements. Each assessment must
    come back with a policy-checked plan that still respects the target's
    stored letter restrictions — the prompt mode reuses the same gates as
    the letter mode rather than a parallel path.
    """
    prompt = 'Deep pre-launch check: enumerate services and audit HTTP security headers.'
    target_ids = []
    for name, address, restricted in (
        ('Storefront', 'juice-shop:3000', []),
        ('Legacy server', '192.168.56.20:80', ['traceroute', 'dig', 'sslscan', 'nuclei']),
    ):
        target = client.post('/targets/', json={
            'name': name,
            'scope_domain_ip': address,
            'authorized_scopes': [address],
            'criticality': 80,
            'restricted_tools': restricted,
        }).json()
        target_ids.append(target['id'])

    assessments = []
    for target_id in target_ids:
        response = client.post('/assessments/', json={'target_id': target_id, 'objective': prompt})
        assert response.status_code == 200
        assessments.append(response.json())

    # Both plans exist, carry the prompt as their objective, and were drafted
    # by the deterministic planner (no provider configured in tests).
    assert [a['objective'] for a in assessments] == [prompt, prompt]
    assert all(a['plan_source'] == 'default-unconfigured' for a in assessments)
    assert all(len(a['plan']) >= 1 for a in assessments)
    # The restricted target loses exactly its restricted steps; the
    # unrestricted one loses none.
    assert assessments[0]['restricted_steps_dropped'] == 0
    assert assessments[1]['restricted_steps_dropped'] == 4
    assert all(step['tool'] not in ('traceroute', 'dig', 'sslscan', 'nuclei')
               for step in assessments[1]['plan'])


ATTESTATION = {
    'mode': 'kali_vm', 'host': '192.168.56.15', 'user': 'root', 'hostname': 'kali-vm',
    'os': 'Kali GNU/Linux Rolling', 'kernel': 'Linux 6.12.0-kali',
    'host_key_fingerprint': 'SHA256:testfingerprint',
}


def enable_kali_vm_mode(client):
    saved = client.put('/settings', json={
        'execution_mode': 'kali_vm', 'ssh_host': '192.168.56.15', 'ssh_port': 22,
        'ssh_username': 'root', 'ssh_password': 'toor', 'ssh_fingerprint': 'SHA256:test',
    })
    assert saved.status_code == 200
    trusted = client.put('/settings', json={'ssh_fingerprint': 'SHA256:test'})
    return trusted.json()


def test_kali_vm_settings_round_trip_and_secret_hygiene(client):
    """SSH settings save and reload like the proxy credentials do.

    The password is write-only: it never appears in a GET response, only the
    boolean that says one is stored, and clearing the host clears the stored
    credentials with it.
    """
    saved = enable_kali_vm_mode(client)
    assert saved['execution_mode'] == 'kali_vm'
    assert saved['ssh_host'] == '192.168.56.15'
    assert saved['ssh_username'] == 'root'
    assert saved['ssh_password_configured'] is True
    assert 'ssh_password' not in saved or saved.get('ssh_password') in (None, '')

    cleared_host = client.put('/settings', json={'ssh_host': ''}).json()
    assert cleared_host['ssh_host'] == '' and cleared_host['ssh_username'] == ''
    assert cleared_host['ssh_password_configured'] is False

    rejected = client.put('/settings', json={'execution_mode': 'somewhere-else'})
    assert rejected.status_code == 422


def test_kali_vm_mode_fails_closed_on_incomplete_settings(client):
    """A half-configured VM must never fall back to local execution."""
    client.put('/settings', json={'execution_mode': 'kali_vm', 'ssh_host': '192.168.56.15'})
    assessment = create_assessment(client)
    response = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
    assert response.status_code == 409
    assert 'SSH host, username, or password' in response.json()['detail']


def test_kali_vm_execution_persists_attestation(client):
    """VM-mode results carry where the command physically ran.

    The dispatch must reach the remote path (not the local subprocess), and
    the returned + serialized execution must expose the attestation the UI
    and the report cite as proof the output came from the attacker VM.
    """
    enable_kali_vm_mode(client)
    assessment = create_assessment(client)
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10,
              'execution_host': ATTESTATION}

    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)) as run_command:
        executed = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})

    assert executed.status_code == 200
    # The remote settings were handed to the executor alongside the command.
    _, kwargs = run_command.call_args
    assert kwargs.get('remote') == {'host': '192.168.56.15', 'port': 22, 'username': 'root', 'password': 'toor', 'fingerprint': 'SHA256:test', 'private_key': '', 'key_passphrase': ''}
    assert executed.json()['result']['execution_host'] == ATTESTATION

    stored = client.get(f"/assessments/{assessment['id']}").json()
    assert stored['executions'][0]['execution_host'] == ATTESTATION


def test_local_mode_passes_no_remote_settings(client):
    """The default mode must reach the executor exactly as it did before."""
    assessment = create_assessment(client)
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}

    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)) as run_command:
        executed = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})

    assert executed.status_code == 200
    _, kwargs = run_command.call_args
    assert not kwargs.get('remote')
    stored = client.get(f"/assessments/{assessment['id']}").json()
    assert stored['executions'][0]['execution_host'] is None


def test_ssh_test_endpoint_reports_unreachable_vm(client):
    enable_kali_vm_mode(client)
    # ssh_executor is imported lazily inside the endpoint, so the patch target
    # is the module it comes from.
    with patch('modules.ssh_executor.ssh_executor') as fake:
        fake.test_connection.side_effect = OSError('No route to host')
        response = client.post('/settings/ssh-test')
    assert response.status_code == 502
    assert 'Could not reach the Kali VM' in response.json()['detail']


def test_ssh_test_endpoint_requires_saved_settings(client):
    response = client.post('/settings/ssh-test')
    assert response.status_code == 409
    assert 'Save the Kali VM host' in response.json()['detail']


def test_registering_same_address_returns_existing_target(client):
    """The letter-import path can be re-run, so registration is idempotent.

    A second POST for an address already on file used to fork a duplicate
    target answering to the same scope, which is how one letter's three
    assets turned into five registered targets.
    """
    first = client.post('/targets/', json={
        'name': 'Storefront', 'scope_domain_ip': 'juice-shop:3000',
        'authorized_scopes': ['juice-shop:3000'],
    }).json()
    assert 'already_registered' not in first

    again = client.post('/targets/', json={
        'name': 'Storefront (duplicate)', 'scope_domain_ip': 'juice-shop:3000',
        'authorized_scopes': ['juice-shop:3000'],
    }).json()

    assert again['already_registered'] is True
    assert again['id'] == first['id']
    assert len(client.get('/targets/').json()) == 1


def test_delete_assessment_removes_run_but_keeps_target(client, tmp_path, monkeypatch):
    """Deleting one assessment drops its dependents and report, not the target.

    The target is the client's asset record; the executions, findings and
    rendered report are this run's output and go with the run.
    """
    import main
    monkeypatch.setattr(main, 'REPORTS_DIR', tmp_path)
    assessment = create_assessment(client)
    main.report_path(assessment['id']).write_text('<html>report</html>')

    deleted = client.delete(f"/assessments/{assessment['id']}")

    assert deleted.status_code == 200
    assert client.get(f"/assessments/{assessment['id']}").status_code == 404
    assert len(client.get('/assessments/').json()) == 0
    assert len(client.get('/targets/').json()) == 1
    assert not main.report_path(assessment['id']).exists()
    assert client.delete('/assessments/999').status_code == 404


def test_reset_workspace_clears_runs_but_keeps_settings(client, tmp_path, monkeypatch):
    """The persisted database is why reloads showed the last engagement.

    Reset must empty the board (targets, assessments, executions, findings,
    reports) while the provider and VM configuration survives, because that
    describes the operator's setup, not the engagement.
    """
    import main
    monkeypatch.setattr(main, 'REPORTS_DIR', tmp_path)
    enable_kali_vm_mode(client)
    assessment = create_assessment(client)
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}
    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        for step_index in (0, 1):
            assert client.post(f"/assessments/{assessment['id']}/execute",
                               json={'step_index': step_index, 'approved': True}).status_code == 200
    assert client.post(f"/assessments/{assessment['id']}/analyze").status_code == 200
    main.report_path(assessment['id']).write_text('<html>report</html>')

    reset = client.post('/workspace/reset')

    assert reset.status_code == 200
    counts = reset.json()['deleted']
    assert counts['assessments'] == 1 and counts['targets'] == 1 and counts['executions'] == 2
    assert client.get('/assessments/').json() == []
    assert client.get('/targets/').json() == []
    assert not main.report_path(assessment['id']).exists()
    settings = client.get('/settings').json()
    assert settings['execution_mode'] == 'kali_vm'
    assert settings['ssh_password_configured'] is True


def test_delete_and_reset_refused_while_command_running(client):
    """A mid-flight command owns its rows; deleting them mid-run would let the
    completion write resurrect rows the operator just asked to remove."""
    import threading

    assessment = create_assessment(client)
    started, release = threading.Event(), threading.Event()

    async def slow_command(*args, **kwargs):
        started.set()
        release.wait(timeout=10)
        return {'stdout': 'ok', 'stderr': '', 'return_code': 0, 'duration_ms': 5}

    with patch('main.executor.execute_command', new=AsyncMock(side_effect=slow_command)):
        thread = threading.Thread(
            target=lambda: client.post(f"/assessments/{assessment['id']}/execute",
                                       json={'step_index': 0, 'approved': True}),
            daemon=True)
        thread.start()
        try:
            assert started.wait(timeout=10)
            assert client.delete(f"/assessments/{assessment['id']}").status_code == 409
            assert client.post('/workspace/reset').status_code == 409
        finally:
            release.set()
            thread.join(timeout=10)

    # Once the command has finished, both paths succeed again.
    assert client.delete(f"/assessments/{assessment['id']}").status_code == 200


# Real scanner output, so the analyzer's own parsers produce the findings these
# tests count rather than a stubbed finding list.
SCANNER_OUTPUT = {
    'stdout': ('Nmap scan report for juice-shop (172.18.0.2)\n'
               '80/tcp open http nginx 1.18.0\n'
               'HTTP/1.1 200 OK\r\nServer: nginx\r\n'),
    'stderr': '', 'return_code': 0, 'duration_ms': 10,
}


def run_and_analyze(client, assessment):
    with patch('main.executor.execute_command', new=AsyncMock(return_value=SCANNER_OUTPUT)):
        for step_index in range(len(assessment['plan'])):
            assert client.post(f"/assessments/{assessment['id']}/execute",
                               json={'step_index': step_index, 'approved': True}).status_code == 200
    analyzed = client.post(f"/assessments/{assessment['id']}/analyze")
    assert analyzed.status_code == 200
    return client.get(f"/assessments/{assessment['id']}").json()


def test_next_steps_proposes_without_touching_the_plan(client):
    """Proposing is a question, not a change: it must leave no trace.

    Proposals become plan steps only when the operator accepts them through
    PUT /plan, so this endpoint must not append, execute, or invalidate
    anything on its own.
    """
    assessment = create_assessment(client)
    before = client.get(f"/assessments/{assessment['id']}").json()

    response = client.post(f"/assessments/{assessment['id']}/next-steps")

    assert response.status_code == 200
    proposed = response.json()
    assert proposed['phase'] == 'recon'
    # No provider is configured in tests, so the deterministic path answers —
    # and says so rather than presenting its output as reasoned.
    assert proposed['source'] == 'deterministic-fallback'
    assert proposed['candidates']
    assert proposed['state']['plan_steps'] == len(before['plan'])
    assert all(candidate['enabled'] for candidate in proposed['candidates'])

    after = client.get(f"/assessments/{assessment['id']}").json()
    assert after['plan'] == before['plan']
    assert after['executions'] == []
    assert after['status'] == before['status']


def test_next_steps_refuses_a_phase_that_owns_no_steps(client):
    """vuln_analysis is bookkeeping between two plan phases, not a phase."""
    assessment = create_assessment(client)
    done = run_and_analyze(client, assessment)

    assert done['current_phase'] == 'vuln_analysis'
    response = client.post(f"/assessments/{assessment['id']}/next-steps")

    assert response.status_code == 409
    # The refusal names the door to use instead of just saying no.
    assert 'Draft the exploitation plan' in response.json()['detail']


def test_appending_a_proposal_preserves_earlier_phases_findings(client):
    """Accepting a mid-engagement proposal must not erase the evidence.

    A plan update used to invalidate the whole assessment's findings, so
    accepting one proposal deleted the recon findings and the exploitation
    evidence linking them — the material the report cites. A pure append now
    invalidates only the phases it appends to.
    """
    assessment = create_assessment(client)
    analyzed = run_and_analyze(client, assessment)
    assert analyzed['findings'], 'the scanner output must produce findings for this test to mean anything'
    findings_before = len(analyzed['findings'])

    # An append to a phase that has produced no findings yet — the shape every
    # accepted proposal takes, since the phase the operator is working in is by
    # definition not yet analyzed.
    appended = analyzed['plan'] + [{
        'tool': 'nmap', 'command': 'nmap -sV -p 443 juice-shop',
        'reason': 'Proposed from the current engagement state.', 'phase': 'exploitation',
    }]
    response = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': appended})

    assert response.status_code == 200
    assert len(response.json()['plan']) == len(analyzed['plan']) + 1
    survived = client.get(f"/assessments/{assessment['id']}").json()
    assert len(survived['findings']) == findings_before

    # Any other edit keeps the whole-assessment invalidation: an edit to a step
    # in an earlier phase can change what that phase's analysis produces, and
    # there is no cheap way to know which findings survive that.
    edited = [dict(step) for step in survived['plan']]
    edited[-1]['command'] = 'nmap -sV -p 8443 juice-shop'
    assert client.put(f"/assessments/{assessment['id']}/plan", json={'plan': edited}).status_code == 200
    assert client.get(f"/assessments/{assessment['id']}").json()['findings'] == []


def test_next_steps_refused_while_a_command_is_running(client):
    """Proposing mid-run would reason about a half-written engagement."""
    import threading

    assessment = create_assessment(client)
    started, release = threading.Event(), threading.Event()

    async def slow_command(*args, **kwargs):
        started.set()
        release.wait(timeout=10)
        return SCANNER_OUTPUT

    with patch('main.executor.execute_command', new=AsyncMock(side_effect=slow_command)):
        thread = threading.Thread(
            target=lambda: client.post(f"/assessments/{assessment['id']}/execute",
                                       json={'step_index': 0, 'approved': True}),
            daemon=True)
        thread.start()
        try:
            assert started.wait(timeout=10)
            refused = client.post(f"/assessments/{assessment['id']}/next-steps")
            assert refused.status_code == 409
            assert 'currently executing' in refused.json()['detail']
        finally:
            release.set()
            thread.join(timeout=10)

    assert client.post(f"/assessments/{assessment['id']}/next-steps").status_code == 200
