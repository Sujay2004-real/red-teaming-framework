"""Regression coverage for the November backend workflow review."""
import pytest

import main
from database import Assessment, EngagementHost, Finding, Foothold, Loot, Target, ToolExecution
from modules.api_auth import verify_operator_key
from test_workflow_reliability import workspace as workspace, create


def seed_later_phase(client, sessions):
    assessment = create(client)
    with sessions() as db:
        row = db.get(Assessment, assessment['id'])
        row.plan = list(row.plan) + [{'tool': 'curl', 'command': 'curl -I http://lab.test/status',
                                    'phase': 'exploitation', 'enabled': True, 'reason': 'Review status'}]
        row.current_phase = 'exploitation'
        row.analyzed_phases = ['recon']
        db.add(ToolExecution(assessment_id=row.id, step_index=0, tool_name='curl',
                             command=row.plan[0]['command'], return_code=0, state='completed'))
        db.add(Finding(assessment_id=row.id, fingerprint='recon-observation', title='Earlier evidence', phase='recon'))
        db.commit()
        return main.serialize_assessment(row)


def test_editing_an_unexecuted_later_phase_preserves_its_prerequisites(workspace):
    client, sessions = workspace
    assessment = seed_later_phase(client, sessions)
    plan = assessment['plan']
    plan[1]['command'] = 'curl -I http://lab.test/health'
    result = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': plan, 'plan_version': 1})
    assert result.status_code == 200
    assert result.json()['analyzed_phases'] == ['recon']
    with sessions() as db:
        assert db.query(Finding).filter_by(assessment_id=assessment['id'], phase='recon').count() == 1


@pytest.mark.parametrize('reason_only', [False, True])
def test_noop_or_reason_only_plan_save_keeps_analysis_and_report(workspace, reason_only):
    client, sessions = workspace
    assessment = create(client)
    with sessions() as db:
        row = db.get(Assessment, assessment['id'])
        row.status = 'reported'
        row.analyzed_phases = ['recon']
        row.current_phase = 'vuln_analysis'
        row.analysis_metadata = {'mode': 'deterministic-fallback'}
        db.add(Finding(assessment_id=row.id, fingerprint='saved-finding', title='Saved evidence', phase='recon'))
        db.commit()
    path = main.report_path(assessment['id'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('Existing report', encoding='utf-8')
    plan = assessment['plan']
    if reason_only:
        plan[0]['reason'] = 'Clarified rationale'
    response = client.put(f"/assessments/{assessment['id']}/plan", json={'plan': plan, 'plan_version': 1})
    assert response.status_code == 200
    assert response.json()['analyzed_phases'] == ['recon']
    with sessions() as db:
        assert db.query(Finding).filter_by(assessment_id=assessment['id']).count() == 1
        assert db.get(Assessment, assessment['id']).analysis_metadata == {'mode': 'deterministic-fallback'}
    # A changed rationale invalidates a report's text, but never scanner evidence.
    if not reason_only:
        assert response.json()['status'] == 'reported'
        assert path.read_text(encoding='utf-8') == 'Existing report'


def test_recon_redraft_returns_a_controlled_conflict(workspace):
    client, _ = workspace
    assessment = create(client)
    response = client.post(f"/assessments/{assessment['id']}/phases/recon/plan")
    assert response.status_code == 409


def test_non_ascii_operator_key_is_rejected_without_server_error(monkeypatch):
    monkeypatch.setenv('REDTEAM_API_KEY', 'test-key')
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        verify_operator_key(x_api_key='invalid-\u00e9', db=None)
    assert error.value.status_code == 401


def seed_campaign_graph(client, sessions, child=False):
    assessment = create(client)
    with sessions() as db:
        foothold = Foothold(assessment_id=assessment['id'], host='lab.test')
        db.add(foothold)
        db.flush()
        db.add(Loot(assessment_id=assessment['id'], foothold_id=foothold.id, host='lab.test'))
        host = EngagementHost(assessment_id=assessment['id'], address='lab.test')
        db.add(host)
        child_id = None
        if child:
            descendant = Assessment(target_id=assessment['target_id'], parent_assessment_id=assessment['id'],
                                    objective='Child fixture', plan=assessment['plan'])
            db.add(descendant)
            db.flush()
            child_id = descendant.id
            host.child_assessment_id = child_id
        db.commit()
    return assessment['id'], child_id


def test_delete_assessment_removes_campaign_rows(workspace):
    client, sessions = workspace
    assessment_id, _ = seed_campaign_graph(client, sessions)
    assert client.delete(f'/assessments/{assessment_id}').status_code == 200
    with sessions() as db:
        assert db.get(Assessment, assessment_id) is None
        for model in (Loot, Foothold, EngagementHost):
            assert db.query(model).count() == 0


def test_parent_delete_is_a_conflict_until_children_are_removed(workspace):
    client, sessions = workspace
    assessment_id, child_id = seed_campaign_graph(client, sessions, child=True)
    assert client.delete(f'/assessments/{assessment_id}').status_code == 409
    assert client.delete(f'/assessments/{child_id}').status_code == 200
    with sessions() as db:
        assert db.query(EngagementHost).filter_by(assessment_id=assessment_id).one().child_assessment_id is None
    assert client.delete(f'/assessments/{assessment_id}').status_code == 200


def test_workspace_reset_obeys_foreign_keys_without_autoflush(workspace):
    client, sessions = workspace
    # Match the production SessionLocal configuration; legacy tests used the
    # ORM default and missed pending assessment deletes before target cleanup.
    sessions.configure(autoflush=False)
    seed_campaign_graph(client, sessions, child=True)
    response = client.post('/workspace/reset')
    assert response.status_code == 200
    with sessions() as db:
        for model in (Assessment, Target, Loot, Foothold, EngagementHost):
            assert db.query(model).count() == 0
