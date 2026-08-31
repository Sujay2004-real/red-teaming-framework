"""The engagement brief as the agents' standing orders.

Importing the letter is only useful if what was parsed actually reaches the
agents: these tests pin the three hand-offs - the brief is stored on the
assessment, it reaches the planner as labelled facts, and it surfaces in the
report the client reads.
"""

from unittest.mock import AsyncMock, Mock, patch

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


BRIEF = {
    'client_name': 'JuiceBox Retail Ltd',
    'engagement_ref': 'JB/SEC/2026/04',
    'test_window': '3 August 2026 to 14 August 2026',
    'escalation_contact': 'Priya Raman',
    'targets': [
        {'name': 'Juice Shop storefront', 'address': 'juice-shop:3000', 'scopes': ['juice-shop:3000'],
         'criticality': 85, 'restricted_tools': []},
    ],
    'objectives': ['Service discovery: identify exposed ports and service versions.'],
    'out_of_scope': ['Payment provider sandbox'],
    'prohibited': ['Denial of service', 'Credential brute-forcing'],
}


def make_target(client):
    return client.post('/targets/', json={
        'name': 'Juice Shop storefront',
        'scope_domain_ip': 'juice-shop:3000',
        'authorized_scopes': ['juice-shop', 'juice-shop:3000'],
        'criticality': 85,
    }).json()


def test_brief_is_persisted_and_returned(client):
    target = make_target(client)
    created = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Pre-release assessment of the storefront',
        'requirements': 'raw letter text',
        'engagement_brief': BRIEF,
        'plan': [{'tool': 'nmap', 'command': 'nmap -sV juice-shop', 'reason': 'Discovery', 'enabled': True}],
    })
    assert created.status_code == 200
    fetched = client.get(f"/assessments/{created.json()['id']}").json()
    # The brief the operator reviewed is the one stored, so later stages act
    # on the same facts instead of re-reading raw text.
    assert fetched['engagement_brief'] == BRIEF


def test_structured_brief_reaches_the_planner_as_labelled_facts(client):
    target = make_target(client)
    planner = Mock(return_value=([{'tool': 'nmap', 'command': 'nmap -sV juice-shop'}], 'ai-filtered'))
    with patch('main.planner_agent.generate_plan', planner):
        created = client.post('/assessments/', json={
            'target_id': target['id'],
            'objective': 'Pre-release assessment',
            'requirements': 'raw letter text',
            'engagement_brief': BRIEF,
        })
    assert created.status_code == 200
    # generate_plan(target, objective, api_key, base_url, model_name, requirement_context, ...)
    context = planner.call_args.args[5]
    assert 'Client objectives:' in context
    assert 'Prohibited techniques (never do):' in context
    assert 'Out of scope (never touch):' in context
    # Labelled facts lead, raw letter text only follows as supporting context.
    assert context.index('Prohibited techniques') < context.index('raw letter text')


def test_oversized_brief_is_rejected(client):
    target = make_target(client)
    # More list entries than the parser would ever produce: the brief
    # round-trips through the browser, so its bounds are enforced at the edge.
    huge = dict(BRIEF, objectives=['x' * 200] * 150)
    response = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Pre-release assessment',
        'engagement_brief': huge,
    })
    assert response.status_code == 422


def test_report_cites_the_engagement(client, tmp_path):
    target = make_target(client)
    assessment = client.post('/assessments/', json={
        'target_id': target['id'],
        'objective': 'Pre-release assessment',
        'engagement_brief': BRIEF,
        'plan': [{'tool': 'nmap', 'command': 'nmap -sV juice-shop', 'reason': 'Discovery', 'enabled': True}],
    }).json()
    result = {'stdout': '', 'stderr': '', 'return_code': 0, 'duration_ms': 5}
    with patch('main.executor.execute_command', new=AsyncMock(return_value=result)):
        executed = client.post(f"/assessments/{assessment['id']}/execute", json={'step_index': 0, 'approved': True})
    assert executed.status_code == 200
    analyzed = client.post(f"/assessments/{assessment['id']}/analyze")
    assert analyzed.status_code == 200
    reported = client.post(f"/assessments/{assessment['id']}/report")
    assert reported.status_code == 200
    html = client.get(f"/reports/{assessment['id']}").text
    # The deliverable names who asked for the work and under which reference,
    # so the client can file it against their engagement.
    assert 'JuiceBox Retail Ltd' in html
    assert 'JB/SEC/2026/04' in html
    assert 'Payment provider sandbox' in html
