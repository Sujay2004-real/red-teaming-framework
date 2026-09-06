from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from main import app


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
        yield TestClient(app)
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

    with patch('main.reporter.generate_html_report', return_value=str(tmp_path / 'report.html')):
        reported = client.post(f"/assessments/{assessment['id']}/report")

    assert reported.status_code == 200


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
