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


def create_restricted_target(client, **overrides):
    payload = {
        'name': 'DVWA internal security-training lab',
        'scope_domain_ip': 'dvwa:80',
        'authorized_scopes': ['dvwa', 'dvwa:80'],
        'criticality': 40,
        'restricted_tools': ['nuclei', 'not-a-real-tool'],
    }
    payload.update(overrides)
    return client.post('/targets/', json=payload).json()


def test_target_stores_only_runnable_restrictions(client):
    target = create_restricted_target(client)
    # 'not-a-real-tool' is outside the policy registry and is dropped rather
    # than refused, so one junk name from a misparse cannot block registration.
    assert target['restricted_tools'] == ['nuclei']


def test_restricted_tool_steps_are_dropped_from_plans(client):
    target = create_restricted_target(client)
    response = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Baseline the training system',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV dvwa'},
            {'tool': 'nuclei', 'command': 'nuclei -u http://dvwa:80'},
            {'tool': 'curl', 'command': 'curl -I http://dvwa:80'},
        ],
    })
    assert response.status_code == 200
    body = response.json()
    assert [step['tool'] for step in body['plan']] == ['nmap', 'curl']
    assert body['restricted_steps_dropped'] == 1


def test_restricted_tool_is_refused_even_if_re_added_to_the_plan(client):
    target = create_restricted_target(client)
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Baseline the training system',
        'plan': [
            {'tool': 'nmap', 'command': 'nmap -sV dvwa'},
            {'tool': 'curl', 'command': 'curl -I http://dvwa:80'},
        ],
    }).json()
    # An operator can still edit the saved plan; the refusal at approval time
    # is what enforces the client's letter.
    edited = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': [
        {'tool': 'nmap', 'command': 'nmap -sV dvwa'},
        {'tool': 'nuclei', 'command': 'nuclei -u http://dvwa:80'},
    ]})
    assert edited.status_code == 200
    refused = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 1, 'approved': True})
    assert refused.status_code == 403
    assert 'engagement letter' in refused.json()['detail']


def test_unrestricted_target_still_accepts_nuclei(client):
    target = client.post('/targets/', json={
        'name': 'Juice Shop pre-release storefront',
        'scope_domain_ip': 'juice-shop:3000',
        'authorized_scopes': ['juice-shop', 'juice-shop:3000'],
        'criticality': 85,
    }).json()
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Full pre-release assessment',
        'plan': [
            {'tool': 'nuclei', 'command': 'nuclei -u http://juice-shop:3000'},
        ],
    }).json()
    result = {'stdout': '', 'stderr': '', 'return_code': 0, 'duration_ms': 5}
    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        executed = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
    assert executed.status_code == 200
