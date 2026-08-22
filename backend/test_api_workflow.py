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
