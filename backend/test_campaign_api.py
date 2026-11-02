# --------------------------------------------------- semi-autonomous campaign
#
# The campaign is the lab-only kill chain that runs after post-exploitation:
#
#   post_exploitation -> credential_validation -> lateral_movement -> impact
#
# These tests drive it through the real API against an in-memory database, with
# only the executor mocked. They assert the properties that make it safe to run
# unattended: the aggressive-lab gate, per-step human approval, secrets masked
# in everything that is written down, and a promoted host whose child scope is
# strictly narrower than its parent's.

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from conftest import OPERATOR_TEST_KEY
from database import (
    Assessment, Base, EngagementHost, Loot, Target, ToolExecution, get_db,
)
from fastapi.testclient import TestClient
from main import app, ingest_execution_evidence
from modules.footholds import fingerprint_secret
from modules.secret_store import encrypt_secret
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SECRET = 'Sup3rSecret1'
NT_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'
OPEN_LINE = '[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 192.168.56.10:44552) at 2026-10-07 10:00:00 +0000'
HASHDUMP_LINE = f'Administrator:500:aad3b435b51404eeaad3b435b51404ee:{NT_HASH}:::'


@pytest.fixture
def ctx():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
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
        yield SimpleNamespace(client=TestClient(app, headers={'X-API-Key': OPERATOR_TEST_KEY}),
                              session=TestingSession)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def make_target(ctx, aggressive=True, address='192.168.56.10', scopes=None):
    return ctx.client.post('/targets/', json={
        'name': 'Lab',
        'scope_domain_ip': address,
        'authorized_scopes': scopes or [address],
        'criticality': 70,
        'exploitation_authorized': True,
        'aggressive_lab': aggressive,
    }).json()


def make_assessment(ctx, target, plan=None):
    return ctx.client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Campaign',
        'plan': plan or [{'tool': 'nmap', 'command': f"nmap -sV {target['scope_domain_ip']}"}],
    }).json()


def seed_credential(ctx, assessment_id, host='192.168.56.10', service='smb',
                    username='admin', secret=SECRET, kind='password', validated=True):
    with ctx.session() as db:
        row = Loot(assessment_id=assessment_id, host=host, service=service, username=username,
                   secret_kind=kind, secret_fingerprint=fingerprint_secret(secret),
                   secret_encrypted=encrypt_secret(secret), validated=validated, source_tool='msfconsole')
        db.add(row)
        db.commit()
        return row.id


def advance_to(ctx, assessment_id, phase, analyzed):
    """Put the assessment at a phase without walking the whole chain first."""
    with ctx.session() as db:
        db.query(Assessment).filter_by(id=assessment_id).update(
            {'current_phase': phase, 'analyzed_phases': list(analyzed), 'status': 'awaiting_approval'})
        db.commit()


def test_campaign_stays_locked_without_aggressive_lab(ctx):
    target = make_target(ctx, aggressive=False)
    assessment = make_assessment(ctx, target)

    campaign = ctx.client.get(f"/assessments/{assessment['id']}/campaign").json()
    assert campaign['aggressive_lab'] is False
    assert campaign['campaign_enabled'] is False
    assert campaign['footholds'] == []

    refused = ctx.client.post(f"/assessments/{assessment['id']}/autopilot", json={'enabled': True})
    assert refused.status_code == 403
    assert 'aggressive lab' in refused.json()['detail']

    # And the lab-only phases cannot be drafted for it, whatever the plan says.
    blocked = ctx.client.post(f"/assessments/{assessment['id']}/phases/credential_validation/plan")
    assert blocked.status_code == 422


def test_msf_evidence_becomes_foothold_and_masked_loot(ctx):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    with ctx.session() as db:
        execution = ToolExecution(assessment_id=assessment['id'], step_index=0, tool_name='msfconsole',
                                  command='msfconsole -q -x "sessions -l; exit"', approved_by_user=True,
                                  stdout=OPEN_LINE + '\n' + HASHDUMP_LINE + '\n', stderr='',
                                  return_code=0, state='succeeded')
        db.add(execution)
        db.commit()
        execution_id = execution.id

    with ctx.session() as db:
        summary = ingest_execution_evidence(db, db.get(ToolExecution, execution_id))
        db.commit()  # The caller owns the atomic workflow transaction.
    assert summary['footholds'] == 1
    assert summary['loot'] == 1
    assert summary['hosts'] >= 1

    campaign = ctx.client.get(f"/assessments/{assessment['id']}/campaign").json()
    assert campaign['footholds'][0]['host'] == '192.168.56.10'
    assert campaign['footholds'][0]['kind'] == 'meterpreter'
    assert campaign['loot'][0]['username'] == 'Administrator'
    assert campaign['loot'][0]['has_secret'] is True
    # The plaintext hash never appears in any list response.
    assert NT_HASH not in ctx.client.get(f"/assessments/{assessment['id']}/campaign").text
    assert campaign['loot'][0]['fingerprint'] == fingerprint_secret(
        f"aad3b435b51404eeaad3b435b51404ee:{NT_HASH}")


def test_kill_chain_plan_is_drafted_with_placeholders(ctx):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    loot_id = seed_credential(ctx, assessment['id'])
    advance_to(ctx, assessment['id'], 'credential_validation',
               ['recon', 'exploitation', 'post_exploitation'])

    drafted = ctx.client.post(f"/assessments/{assessment['id']}/phases/credential_validation/plan")
    assert drafted.status_code == 200, drafted.json()
    steps = [s for s in drafted.json()['plan'] if s['phase'] == 'credential_validation']
    assert steps
    assert all(s['tool'] in ('hydra', 'nxc') for s in steps)
    assert any(f'$$loot:{loot_id}$$' in s['command'] for s in steps)
    assert SECRET not in drafted.text


def test_execute_resolves_the_secret_but_persists_only_the_mask(ctx):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    loot_id = seed_credential(ctx, assessment['id'])
    advance_to(ctx, assessment['id'], 'credential_validation',
               ['recon', 'exploitation', 'post_exploitation'])
    ctx.client.post(f"/assessments/{assessment['id']}/phases/credential_validation/plan")

    detail = ctx.client.get(f"/assessments/{assessment['id']}").json()
    index = next(i for i, s in enumerate(detail['plan']) if s['phase'] == 'credential_validation')
    seen = {}

    async def fake_execute(tool, command, *args, **kwargs):
        seen['tool'], seen['command'] = tool, command
        return {'tool': tool, 'command': command, 'stdout': '', 'stderr': '',
                'return_code': 0, 'duration_ms': 1}

    with patch('main.executor.execute_command', new=AsyncMock(side_effect=fake_execute)):
        response = ctx.client.post(f"/assessments/{assessment['id']}/execute",
                                   json={'step_index': index, 'approved': True})
    assert response.status_code == 200, response.json()

    # The executor ran the concrete command...
    assert 'command' in seen, response.json()
    assert SECRET in seen['command']
    assert '$$loot:' not in seen['command']
    # ...and neither the response nor the persisted row carries the secret.
    assert SECRET not in response.text
    with ctx.session() as db:
        row = db.query(ToolExecution).filter_by(assessment_id=assessment['id'], step_index=index).first()
        assert f'$$loot:{loot_id}$$' in row.command
        assert SECRET not in (row.command or '')


def test_loot_reveal_is_the_only_way_to_read_a_secret(ctx):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    loot_id = seed_credential(ctx, assessment['id'])

    assert SECRET not in ctx.client.get(f"/assessments/{assessment['id']}/campaign").text
    reveal = ctx.client.get(f"/assessments/{assessment['id']}/loot/{loot_id}/reveal")
    assert reveal.status_code == 200
    assert reveal.json()['secret'] == SECRET
    assert reveal.json()['service'] == 'smb'


def test_promote_host_spawns_a_narrower_child_assessment(ctx):
    target = make_target(ctx, address='192.168.56.0/24', scopes=['192.168.56.0/24'])
    assessment = make_assessment(ctx, target,
                                 plan=[{'tool': 'nmap', 'command': 'nmap -sn 192.168.56.0/24'}])
    with ctx.session() as db:
        host = EngagementHost(assessment_id=assessment['id'], address='192.168.56.20', state='owned')
        db.add(host)
        db.commit()
        host_id = host.id

    promoted = ctx.client.post(f"/assessments/{assessment['id']}/promote/{host_id}")
    assert promoted.status_code == 200, promoted.json()
    body = promoted.json()
    with ctx.session() as db:
        child_target = db.get(Target, body['target_id'])
        child = db.get(Assessment, body['child_assessment_id'])
    # The child is scoped to exactly the one host, so pivoting cannot widen it.
    assert child_target.authorized_scopes == ['192.168.56.20']
    assert child_target.scope_domain_ip == '192.168.56.20'
    assert child.parent_assessment_id == assessment['id']


def test_autopilot_iteration_drafts_but_never_executes(ctx):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    seed_credential(ctx, assessment['id'])
    advance_to(ctx, assessment['id'], 'credential_validation',
               ['recon', 'exploitation', 'post_exploitation'])
    with ctx.session() as db:
        db.query(Assessment).filter_by(id=assessment['id']).update({'autopilot': True})
        db.commit()

    result = ctx.client.post(f"/assessments/{assessment['id']}/autopilot/run")
    assert result.status_code == 200, result.json()
    body = result.json()
    assert body['drafted']['phase'] == 'credential_validation'
    assert body['drafted']['steps'] > 0
    assert body['next_action']
    # The loop proposes; it does not run anything.
    with ctx.session() as db:
        assert db.query(ToolExecution).filter_by(assessment_id=assessment['id']).count() == 0
        row = db.get(Assessment, assessment['id'])
        assert row.autopilot_state['iterations'] == 1


def test_report_contains_the_post_exploitation_section(ctx, tmp_path):
    target = make_target(ctx)
    assessment = make_assessment(ctx, target)
    seed_credential(ctx, assessment['id'])
    with ctx.session() as db:
        db.add(EngagementHost(assessment_id=assessment['id'], address='192.168.56.10',
                              state='owned', role='owned'))
        db.query(Assessment).filter_by(id=assessment['id']).update({'status': 'analyzed'})
        db.commit()

    with patch('main.REPORTS_DIR', tmp_path):
        response = ctx.client.post(f"/assessments/{assessment['id']}/report")
        assert response.status_code == 200, response.json()
        html = ctx.client.get(response.json()['download_url']).text
    assert 'Post-exploitation evidence' in html
    assert '192.168.56.10' in html
    assert SECRET not in html


def _execute_phase(ctx, assessment_id, phase):
    """Approve and run every enabled step the given phase drafted."""
    plan = ctx.client.get(f"/assessments/{assessment_id}").json()['plan']
    with patch('main.executor.execute_command', new=AsyncMock(return_value={
            'stdout': '', 'stderr': '', 'return_code': 0, 'duration_ms': 1})):
        for index, step in enumerate(plan):
            if step.get('phase') != phase or not step.get('enabled', True):
                continue
            response = ctx.client.post(f"/assessments/{assessment_id}/execute",
                                       json={'step_index': index, 'approved': True})
            assert response.status_code == 200, response.json()


def test_kill_chain_phases_draft_and_advance(ctx, tmp_path):
    target = make_target(ctx, address='192.168.56.10', scopes=['192.168.56.10', '192.168.56.20'])
    assessment = make_assessment(ctx, target)
    aid = assessment['id']
    seed_credential(ctx, aid, host='192.168.56.10', service='smb', username='admin')
    with ctx.session() as db:
        db.add(EngagementHost(assessment_id=aid, address='192.168.56.20', hostname='dc01'))
        db.commit()

    # credential_validation
    advance_to(ctx, aid, 'credential_validation', ['recon', 'exploitation', 'post_exploitation'])
    drafted = ctx.client.post(f"/assessments/{aid}/phases/credential_validation/plan")
    assert drafted.status_code == 200, drafted.json()
    cred_steps = [s for s in drafted.json()['plan'] if s['phase'] == 'credential_validation']
    assert cred_steps and all(s['tool'] in ('hydra', 'nxc') for s in cred_steps)

    # lateral_movement: needs the phase to be current and a second host.
    advance_to(ctx, aid, 'lateral_movement',
               ['recon', 'exploitation', 'post_exploitation', 'credential_validation'])
    drafted = ctx.client.post(f"/assessments/{aid}/phases/lateral_movement/plan")
    assert drafted.status_code == 200, drafted.json()
    lateral_steps = [s for s in drafted.json()['plan'] if s['phase'] == 'lateral_movement']
    assert lateral_steps
    assert any(s['tool'] == 'nxc' and '192.168.56.20' in s['command'] for s in lateral_steps)

    # impact: prove objective through the access obtained.
    advance_to(ctx, aid, 'impact',
               ['recon', 'exploitation', 'post_exploitation', 'credential_validation', 'lateral_movement'])
    drafted = ctx.client.post(f"/assessments/{aid}/phases/impact/plan")
    assert drafted.status_code == 200, drafted.json()
    impact_steps = [s for s in drafted.json()['plan'] if s['phase'] == 'impact']
    assert impact_steps
    assert all(s['tool'] in ('smbclient', 'impacket-secretsdump', 'msfconsole') for s in impact_steps)
    # Every campaign command is a placeholder at rest.
    assert SECRET not in drafted.text
