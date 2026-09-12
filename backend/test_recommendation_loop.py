"""The automatic recommendation loop.

Level 1: analyzing a phase auto-drafts the next phase's plan (policy-gated,
still per-step approved), and reports a refusal as a note when the letter
does not authorize exploitation.

Level 2: each finished execution schedules a persisted proposal batch. The
loop proposes and never acts: a batch becomes plan steps only through the
ordinary plan-save path. These tests call the recording core directly (it is
the sync unit the scheduler offloads to a thread) and then read it back
through the endpoint.
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from conftest import OPERATOR_TEST_KEY
from database import Base, Recommendation, get_db
import main
from main import app


@pytest.fixture
def client(monkeypatch):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    # The automatic loop's sync core opens its own session through
    # main.SessionLocal (it runs off the request lifecycle), so it must see
    # the same in-memory database the override serves.
    monkeypatch.setattr(main, 'SessionLocal', TestingSession)

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


def _target(client, address='juice-shop:3000', exploit=False):
    return client.post('/targets/', json={
        'name': 'Lab', 'scope_domain_ip': address,
        'authorized_scopes': [address], 'criticality': 70,
        'exploitation_authorized': exploit,
    }).json()


def _assessment(client, target_id, plan=None, brief=None):
    response = client.post('/assessments/', json={
        'target_id': target_id, 'objective': 'Inspect the lab',
        'engagement_brief': brief,
        'plan': plan or [
            {'tool': 'nmap', 'command': 'nmap -sV juice-shop'},
            {'tool': 'curl', 'command': 'curl -I http://juice-shop:3000'},
        ],
    })
    assert response.status_code == 200
    return response.json()


def _execute_all(client, assessment, plan=None):
    """Approve every enabled step, exactly as the operator would.

    The nmap step returns a versioned banner so the analyzer produces a
    finding the exploit planner can draft verification steps from.
    """
    outputs = {
        'nmap': {'stdout': 'Nmap scan report for juice-shop (172.28.0.3)\n'
                           '3000/tcp open http Node.js Express framework\n',
                 'stderr': '', 'return_code': 0, 'duration_ms': 10},
    }
    default = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}
    with patch('main.executor.execute_command',
               new=AsyncMock(side_effect=lambda tool, command, proxy_env=None, **kwargs: outputs.get(tool, default))):
        for index, step in enumerate(plan or assessment['plan']):
            if step.get('enabled', True) is False:
                continue
            response = client.post(f"/assessments/{assessment['id']}/execute",
                                   json={'step_index': index, 'approved': True})
            assert response.status_code == 200


def _analyze(client, assessment_id):
    response = client.post(f'/assessments/{assessment_id}/analyze')
    assert response.status_code == 200
    return response.json()


def test_level1_analyze_auto_drafts_exploitation(client):
    """After recon analysis the exploitation plan is already there.

    The letter authorizes verification and its brief declares a verification
    endpoint, so the auto-draft produces steps and the response says so -
    the operator no longer presses Draft to see them.
    """
    target = _target(client, exploit=True)
    brief = {'targets': [{'address': 'juice-shop:3000',
                          'verification_endpoints': ['/rest/user/login']}]}
    assessment = _assessment(client, target['id'], brief=brief)
    _execute_all(client, assessment)
    analysis = _analyze(client, assessment['id'])
    assert analysis['auto_drafted']['phase'] == 'exploitation'
    assert analysis['auto_drafted']['steps'] > 0
    detail = client.get(f"/assessments/{assessment['id']}").json()
    assert any(step.get('phase') == 'exploitation' for step in detail['plan'])
    assert detail['current_phase'] == 'exploitation'


def test_level1_unauthorized_target_reports_refusal_note(client):
    """No exploitation authorization: the refusal is a note, not an error.

    The analysis itself succeeded; the auto-draft correctly refused, and the
    operator is told why - the letter's decision, surfaced the same way the
    policy engine surfaces its refusals.
    """
    target = _target(client, exploit=False)
    assessment = _assessment(client, target['id'])
    _execute_all(client, assessment)
    analysis = _analyze(client, assessment['id'])
    assert analysis['auto_drafted']['phase'] == 'exploitation'
    assert analysis['auto_drafted']['steps'] == 0
    assert 'does not authorize' in analysis['auto_drafted']['note']
    detail = client.get(f"/assessments/{assessment['id']}").json()
    assert not any(step.get('phase') == 'exploitation' for step in detail['plan'])
    assert detail['current_phase'] == 'vuln_analysis'


def test_level2_execution_records_a_recommendation_batch(client):
    """The post-execution loop persists a proposal batch naming its trigger.

    The endpoint schedules the batch off the event loop; the test polls the
    feed (each poll also gives the loop time to finish the scheduled task)
    until the batch for this execution appears.
    """
    import time

    target = _target(client)
    assessment = _assessment(client, target['id'])
    result = {'stdout': '80/tcp open http', 'stderr': '', 'return_code': 0, 'duration_ms': 10}
    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        executed = client.post(f"/assessments/{assessment['id']}/execute",
                               json={'step_index': 0, 'approved': True}).json()
    assert executed['recommendation_pending'] is True

    batch = None
    for _ in range(50):
        feed = client.get(f"/assessments/{assessment['id']}/recommendations").json()
        batch = next((r for r in feed['recommendations']
                      if r['trigger_execution_id'] == executed['execution_id']), None)
        if batch is not None:
            break
        time.sleep(0.1)
    assert batch is not None, 'the scheduled recommendation batch never appeared'
    assert batch['origin'] == 'auto'
    assert batch['phase'] == 'recon'
    # The batch is advice, not action: candidates are listed for review and
    # nothing was added to the plan.
    assert isinstance(batch['candidates'], list)
    detail = client.get(f"/assessments/{assessment['id']}").json()
    assert len(detail['plan']) == 2


def test_level2_budget_caps_the_automatic_batches(client):
    """A run of failing, re-approved steps cannot manufacture endless batches."""
    target = _target(client)
    assessment = _assessment(client, target['id'])
    for _ in range(main.MAX_AUTO_RECOMMENDATIONS):
        assert main.record_auto_recommendations(assessment['id'], None) is not None
    # At the cap, further automatic proposals are simply not made.
    for _ in range(5):
        assert main.record_auto_recommendations(assessment['id'], None) is None
    feed = client.get(f"/assessments/{assessment['id']}/recommendations").json()
    assert feed['total'] == main.MAX_AUTO_RECOMMENDATIONS


def test_level2_no_proposals_in_bookend_phases(client):
    """Scoping and reporting own no plan steps, so the loop stays quiet."""
    target = _target(client)
    assessment = _assessment(client, target['id'])
    # No executions yet, phase is recon -> proposing is fine; flip the
    # assessment into a bookend phase to prove the guard.
    db = next(app.dependency_overrides[get_db]())
    try:
        row = db.query(main.Assessment).filter(main.Assessment.id == assessment['id']).first()
        row.current_phase = 'reporting'
        db.commit()
    finally:
        db.close()
    assert main.record_auto_recommendations(assessment['id'], None) is None
    feed = client.get(f"/assessments/{assessment['id']}/recommendations").json()
    assert feed['total'] == 0


def test_level2_recommendations_die_with_the_assessment(client):
    """Deleting an assessment drops its recommendation batches with it."""
    target = _target(client)
    assessment = _assessment(client, target['id'])
    main.record_auto_recommendations(assessment['id'], None)
    assert client.delete(f"/assessments/{assessment['id']}").status_code == 200
    feed = client.get(f"/assessments/{assessment['id']}/recommendations")
    assert feed.status_code == 404
