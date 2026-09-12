# --------------------------------------------------------------- phases

import pytest
from unittest.mock import AsyncMock, patch

from database import Base, get_db
from main import app
from conftest import OPERATOR_TEST_KEY
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


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


def create_authorized_target(client, exploitation=False, address='192.168.56.10:3000'):
    return client.post('/targets/', json={
        'name': 'Exploit lab',
        'scope_domain_ip': address,
        'authorized_scopes': [address],
        'criticality': 80,
        'exploitation_authorized': exploitation,
    }).json()


def test_target_exploitation_authorization_round_trips(client):
    unauthorized = create_authorized_target(client, exploitation=False)
    authorized = create_authorized_target(client, exploitation=True, address='192.168.56.11:3000')
    assert unauthorized['exploitation_authorized'] is False
    assert authorized['exploitation_authorized'] is True


def test_exploitation_step_refused_without_letter_authorization(client):
    """The gate applies at both plan time and execute time."""
    target = create_authorized_target(client, exploitation=False)
    response = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect',
        'plan': [{'tool': 'sqlmap', 'command': 'sqlmap -u http://192.168.56.10:3000 --batch'}],
    })
    # A supplied plan whose every step is exploitation-grade on an
    # unauthorized target is refused at creation, with the reason.
    assert response.status_code == 403
    assert 'does not authorize controlled exploitation' in response.json()['detail']
    # And an operator building the same assessment with a recon plan, then
    # hand-editing an exploit step in, still cannot run it.
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'},
            {'tool': 'sqlmap', 'command': 'sqlmap -u http://192.168.56.10:3000 --batch'},
        ],
    }).json()
    assert [s['tool'] for s in assessment['plan']] == ['nmap']
    client.put(f"/assessments/{assessment['id']}/plan", json={'plan': [
        {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'},
        {'tool': 'sqlmap', 'command': 'sqlmap -u http://192.168.56.10:3000 --batch'},
    ]})
    response = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 1, 'approved': True})
    assert response.status_code == 403
    assert 'does not authorize controlled exploitation' in response.json()['detail']


def test_msfconsole_refused_in_local_mode(client):
    target = create_authorized_target(client, exploitation=True)
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect',
        'plan': [{'tool': 'msfconsole', 'command':
                  'msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS 192.168.56.10; run; exit"'}],
    }).json()
    assert len(assessment['plan']) == 1
    response = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
    assert response.status_code == 409
    assert 'Kali attacker VM' in response.json()['detail']


def test_phase_lifecycle_recon_to_exploitation_to_report(client, tmp_path):
    """The full phased walk: recon steps -> analyze -> draft exploitation ->
    execute -> analyze (verification) -> post-exploitation -> report."""
    target = create_authorized_target(client, exploitation=True)
    # Recon plan with a finding-producing nmap step.
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Phased assessment',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'},
            {'tool': 'curl', 'command': 'curl -sSI http://192.168.56.10:3000'},
        ],
        'engagement_brief': {'targets': [
            {'address': '192.168.56.10:3000', 'verification_endpoints': ['/rest/user/login']}]},
    }).json()
    aid = assessment['id']
    assert all(step['phase'] == 'recon' for step in assessment['plan'])
    assert assessment['current_phase'] == 'recon'

    # Phase order is enforced: exploitation cannot be drafted before recon
    # is analyzed.
    early = client.post(f'/assessments/{aid}/phases/exploitation/plan')
    assert early.status_code == 409

    # Execute recon, then analyze: current_phase advances to vuln_analysis.
    recon_outputs = [
        {'stdout': 'Nmap scan report for 192.168.56.10\n3000/tcp open http Node.js Express framework\n', 'stderr': '', 'return_code': 0, 'duration_ms': 10},
        {'stdout': 'HTTP/1.1 200 OK\nServer: nginx\n', 'stderr': '', 'return_code': 0, 'duration_ms': 10},
    ]
    for index, output in enumerate(recon_outputs):
        with patch('main.executor.execute_command', new=AsyncMock(return_value=output)):
            executed = client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})
            assert executed.status_code == 200
    analyzed = client.post(f'/assessments/{aid}/analyze')
    assert analyzed.status_code == 200
    assert analyzed.json()['phase'] == 'recon'
    assert analyzed.json()['findings_count'] > 0
    # The analysis auto-drafted the exploitation plan (the recommendation
    # loop's Level 1): the phase advanced and the steps are already in the
    # plan, so the operator reviews instead of pressing Draft.
    assert analyzed.json()['auto_drafted'] == {'phase': 'exploitation', 'steps': analyzed.json()['auto_drafted']['steps'], 'note': ''}
    assert analyzed.json()['auto_drafted']['steps'] > 0
    assert analyzed.json()['current_phase'] == 'exploitation'
    drafted = client.get(f'/assessments/{aid}').json()
    exploit_steps = [s for s in drafted['plan'] if s['phase'] == 'exploitation']
    assert exploit_steps
    # The letter's verification endpoint produced a curl PoC step.
    assert any(s['tool'] == 'curl' and '/rest/user/login' in s['command'] for s in exploit_steps)

    # Redrafting the same phase is refused (append-only, like the plan).
    redraft = client.post(f'/assessments/{aid}/phases/exploitation/plan')
    assert redraft.status_code == 409

    # Execute exploitation steps and analyze: verification state lands on
    # the matching recon findings. msfconsole is skipped (VM-only; refused
    # in local mode and covered by its own test).
    for index, step in enumerate(drafted['plan']):
        if step['phase'] != 'exploitation' or step['tool'] == 'msfconsole':
            continue
        output = {'stdout': '', 'stderr': '', 'return_code': 0, 'duration_ms': 10}
        if step['tool'] == 'sqlmap':
            output['stdout'] = ("GET parameter 'email' is 'AND boolean-based blind' injectable\n"
                                "back-end DBMS: SQLite")
        if step['tool'] == 'curl':
            output['stdout'] = 'HTTP/1.1 200 OK\n{"email": "admin@juice-sh.op"}'
        with patch('main.executor.execute_command', new=AsyncMock(return_value=output)):
            executed = client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})
            assert executed.status_code == 200, executed.json()
    analyzed2 = client.post(f'/assessments/{aid}/analyze')
    assert analyzed2.status_code == 200
    assert analyzed2.json()['current_phase'] == 'post_exploitation'
    # The post-exploitation plan was auto-drafted by the same analysis.
    assert analyzed2.json()['auto_drafted']['phase'] == 'post_exploitation'
    assert analyzed2.json()['auto_drafted']['steps'] > 0
    detail = client.get(f'/assessments/{aid}').json()
    verifications = [f for f in detail['findings'] if f['verification']]
    # The recon-phase findings that exploitation proved now carry the
    # verification state and the evidence.
    assert verifications

    # Post-exploitation steps: bounded facts only.
    drafted2 = client.get(f'/assessments/{aid}').json()
    post_steps = [s for s in drafted2['plan'] if s['phase'] == 'post_exploitation']
    assert post_steps
    assert all('--banner' in s['command'] or '--current-user' in s['command'] for s in post_steps)

    for index, step in enumerate(drafted2['plan']):
        if step['phase'] != 'post_exploitation':
            continue
        output = {'stdout': 'back-end DBMS: SQLite\n[INFO] current user: admin', 'stderr': '', 'return_code': 0, 'duration_ms': 10}
        with patch('main.executor.execute_command', new=AsyncMock(return_value=output)):
            client.post(f'/assessments/{aid}/execute', json={'step_index': index, 'approved': True})
    analyzed3 = client.post(f'/assessments/{aid}/analyze')
    assert analyzed3.status_code == 200
    assert analyzed3.json()['current_phase'] == 'reporting'
    # Reporting owns no plan steps, so the loop correctly drafts nothing.
    assert analyzed3.json()['auto_drafted'] == {'phase': None, 'steps': 0, 'note': ''}

    with patch('main.reporter.generate_html_report', return_value=str(tmp_path / 'report.html')):
        reported = client.post(f'/assessments/{aid}/report')
    assert reported.status_code == 200
    final = client.get(f'/assessments/{aid}').json()
    assert final['current_phase'] == 'reporting'


def test_phase_overview_endpoint(client):
    target = create_authorized_target(client, exploitation=True)
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect',
        'plan': [{'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'}],
    }).json()
    overview = client.get(f"/assessments/{assessment['id']}/phases").json()
    assert overview['current_phase'] == 'recon'
    by_phase = {p['phase']: p for p in overview['phases']}
    assert by_phase['recon']['steps'] == 1
    assert by_phase['exploitation']['steps'] == 0


def test_executed_step_freeze_allows_appending(client):
    """The freeze is per step: executed steps are immutable, later steps editable."""
    target = create_authorized_target(client, exploitation=False)
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Inspect',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'},
            {'tool': 'curl', 'command': 'curl -sSI http://192.168.56.10:3000'},
        ],
    }).json()
    with patch('main.executor.execute_command', new=AsyncMock(return_value={'stdout': '3000/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10})):
        client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
    # The executed step cannot be edited or removed...
    edited = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': [
        {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.20'},
    ]})
    assert edited.status_code == 409
    # ...but unexecuted steps can be edited and new steps appended.
    ok = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': [
        {'tool': 'nmap', 'command': 'nmap -sV 192.168.56.10'},
        {'tool': 'dig', 'command': 'dig +short 192.168.56.10'},
    ]})
    assert ok.status_code == 200
