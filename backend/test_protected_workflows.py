"""Regressions for the backend review's scope, disclosure and atomicity failures."""
import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

import main
from database import Assessment, EngagementHost, ExecutionAttempt, Finding, Loot, Recommendation, ReportVersion, Target, ToolExecution
from modules.evidence import backfill_evidence, evidence_digest, original, redact, unseal
from modules.executor import LiveRegistry
from modules.jobs import run_execution
from test_workflow_reliability import workspace, create, queue

SECRET = 'Synthetic-Audit-Password-47!'
OUTPUT = f'[22][ssh] host: lab.test login: admin password: {SECRET}\n'


def completed(client, sessions, monkeypatch, output=OUTPUT):
    assessment = create(client)
    eid = queue(client, assessment)
    monkeypatch.setattr(main.executor, 'execute_command', AsyncMock(return_value={
        'stdout': output, 'stderr': '', 'return_code': 0, 'duration_ms': 1}))
    result = asyncio.run(run_execution(eid, sessions))
    return assessment['id'], eid, result


@pytest.mark.parametrize('scope,address,excluded,state,expected', [
    ('192.0.2.0/24', '192.0.2.20', [], 'owned', 200),
    ('192.0.2.0/24', '198.51.100.20', [], 'owned', 403),
    ('192.0.2.0/24', '192.0.2.20', ['192.0.2.20'], 'owned', 403),
    ('192.0.2.0/24', '192.0.2.20', ['http://192.0.2.20/private'], 'owned', 403),
    ('192.0.2.0/24', '192.0.2.20', [], 'known', 409),
    ('http://192.0.2.20/app', '192.0.2.20', [], 'owned', 403),
    ('192.0.2.20:8080', '192.0.2.20', [], 'owned', 403),
    ('192.0.2.0/24', '[malformed', [], 'owned', 403),
])
def test_promotion_inherits_parent_permission(workspace, scope, address, excluded, state, expected):
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        target = db.get(Target, db.get(Assessment, aid).target_id)
        target.scope_domain_ip, target.authorized_scopes = scope, [scope]
        target.exploitation_authorized = target.aggressive_lab = True
        target.engagement_policy = {'excluded_scopes': excluded}
        host = EngagementHost(assessment_id=aid, address=address, state=state)
        db.add(host)
        db.commit()
        hid = host.id
    response = client.post(f'/assessments/{aid}/promote/{hid}')
    assert response.status_code == expected, response.text
    with sessions() as db:
        assert db.query(Assessment).count() == (2 if expected == 200 else 1)
    if expected == 200:
        assert client.post(f'/assessments/{aid}/promote/{hid}').status_code == 409


def test_raw_evidence_is_encrypted_redacted_and_audited(workspace, monkeypatch):
    client, sessions = workspace
    aid, eid, result = completed(client, sessions, monkeypatch)
    assert SECRET not in json.dumps(result)
    prefix = f'/assessments/{aid}'
    for suffix in ('', '/snapshot', '/campaign', f'/executions/{eid}/evidence', f'/executions/{eid}/attempts', f'/executions/{eid}/live'):
        response = client.get(prefix + suffix)
        assert response.status_code == 200
        assert SECRET not in response.text
    with sessions() as db:
        execution = db.get(ToolExecution, eid)
        attempt = db.query(ExecutionAttempt).filter_by(execution_id=eid).one()
        assert original(execution)['stdout'] == OUTPUT
        assert unseal(attempt.raw_encrypted)['stdout'] == OUTPUT
        assert execution.evidence_sha256 == evidence_digest({'stdout': OUTPUT, 'stderr': ''})
        assert SECRET not in execution.raw_encrypted
        assert SECRET not in json.dumps(attempt.snapshot)
        db.get(Assessment, aid).status = 'analyzed'
        db.commit()
    generated = client.post(prefix + '/report')
    assert generated.status_code == 200, generated.text
    assert SECRET not in client.get(generated.json()['download_url']).text
    assert SECRET not in client.get(f'/reports/{aid}').text
    reveal = client.post(prefix + f'/executions/{eid}/evidence/reveal')
    assert reveal.status_code == 200
    assert reveal.json()['stdout'] == OUTPUT
    assert reveal.headers['cache-control'] == 'no-store'
    with sessions() as db:
        assert db.query(Recommendation).filter_by(origin='evidence_access').count() == 1
    monkeypatch.setenv('REDTEAM_SECRET_KEY', Fernet.generate_key().decode())
    assert client.post(prefix + f'/executions/{eid}/evidence/reveal').status_code == 409


def test_stream_never_publishes_partial_credential_or_truncated_line():
    stream = LiveRegistry()
    stream.start(1, 'hydra ...')
    for char in OUTPUT:
        stream.append(1, char)
        assert SECRET not in stream.snapshot(1)['output']
        if char != '\n':
            assert stream.snapshot(1)['output'] == ''
    assert '[REDACTED]' in stream.snapshot(1)['output']
    stream.start(2, 'scanner')
    stream.append(2, 'password: ' + 'x' * 250000)
    stream.append(2, '\n')
    assert stream.snapshot(2)['output'] == ''


def test_analysis_failure_rolls_back_findings_and_phase(workspace, monkeypatch):
    client, sessions = workspace
    aid, _, _ = completed(client, sessions, monkeypatch, output='HTTP/1.1 200 OK\n')
    with sessions() as db:
        before = main.serialize_assessment(db.get(Assessment, aid))
        db.add(Finding(assessment_id=aid, title='Original finding', fingerprint='original', phase='recon'))
        db.commit()
    def fail(*args, **kwargs):
        raise RuntimeError('injected ingestion failure')
    monkeypatch.setattr(main, 'ingest_execution_evidence', fail)
    with pytest.raises(RuntimeError, match='injected'):
        client.post(f'/assessments/{aid}/analyze')
    with sessions() as db:
        after = main.serialize_assessment(db.get(Assessment, aid))
        assert after == before
        assert [f.title for f in db.query(Finding).filter_by(assessment_id=aid)] == ['Original finding']


def test_concurrent_analysis_does_not_publish_stale_findings(workspace, monkeypatch):
    client, sessions = workspace
    aid, _, _ = completed(client, sessions, monkeypatch, output='HTTP/1.1 200 OK\n')
    analyze = main.analyzer_agent.analyze_results
    def interleave(*args, **kwargs):
        with sessions() as db:
            row = db.get(Assessment, aid)
            row.plan = [{**s, 'reason': 'Concurrent edit'} for s in row.plan]
            row.plan_version += 1
            db.commit()
        return analyze(*args, **kwargs)
    monkeypatch.setattr(main.analyzer_agent, 'analyze_results', interleave)
    response = client.post(f'/assessments/{aid}/analyze')
    assert response.status_code == 409, response.text
    with sessions() as db:
        assert not db.get(Assessment, aid).analyzed_phases
        assert db.query(Finding).filter_by(assessment_id=aid).count() == 0


def test_stale_report_cannot_replace_published_report(workspace, monkeypatch):
    client, sessions = workspace
    aid, _, _ = completed(client, sessions, monkeypatch, output='HTTP/1.1 200 OK\n')
    with sessions() as db:
        db.get(Assessment, aid).status = 'analyzed'
        db.commit()
    first = client.post(f'/assessments/{aid}/report').json()
    original_html = client.get(first['download_url']).content
    render = main.reporter.generate_html_report
    def interleave(*args, **kwargs):
        render(*args, **kwargs)
        with sessions() as db:
            row = db.get(Assessment, aid)
            row.plan_version += 1
            row.status = 'awaiting_approval'
            row.current_report_version_id = None
            db.commit()
    monkeypatch.setattr(main.reporter, 'generate_html_report', interleave)
    response = client.post(f'/assessments/{aid}/report')
    assert response.status_code == 409, response.text
    assert client.get(f'/reports/{aid}').status_code == 404
    assert client.get(first['download_url']).content == original_html
    assert not list(main.REPORTS_DIR.glob('.staged-*'))
    with sessions() as db:
        assert db.query(ReportVersion).filter_by(assessment_id=aid).count() == 1
        assert db.get(Assessment, aid).status == 'awaiting_approval'


def test_backfill_preserves_originals_and_retires_old_reports(workspace):
    client, sessions = workspace
    aid = create(client)['id']
    main.REPORTS_DIR.mkdir(parents=True)
    path = main.report_path(aid)
    content = ('<html>' + OUTPUT + '</html>').encode()
    path.write_bytes(content)
    with sessions() as db:
        # SQL simulates legacy plaintext without invoking new write protection.
        db.execute(text('UPDATE assessments SET evidence_protected=0, status=:status WHERE id=:id'), {'id': aid, 'status': 'reported'})
        db.execute(text('INSERT INTO tool_executions (assessment_id, step_index, tool_name, command, stdout, stderr, attempt, return_code) VALUES (:aid, 0, :tool, :command, :stdout, :stderr, 1, 0)'),
                   {'aid': aid, 'tool': 'hydra', 'command': 'hydra ...', 'stdout': OUTPUT, 'stderr': ''})
        db.commit()
    backfill_evidence(sessions, main.REPORTS_DIR)
    backfill_evidence(sessions, main.REPORTS_DIR)
    assert not path.exists()
    with sessions() as db:
        row = db.query(ToolExecution).filter_by(assessment_id=aid).one()
        assert original(row)['stdout'] == OUTPUT
        assert SECRET not in row.stdout
        version = db.query(ReportVersion).filter_by(assessment_id=aid).one()
        assert version.digest == hashlib.sha256(content).hexdigest()
        assert version.restricted
        vid = version.id
    assert client.get(f'/assessments/{aid}/reports/{vid}').status_code == 409
    reveal = client.post(f'/assessments/{aid}/reports/{vid}/reveal')
    assert reveal.content == content


@pytest.mark.parametrize('value', [OUTPUT, f'{{"password": "{SECRET}"}}', f'Authorization: Bearer {SECRET}', f'http://admin:{SECRET}@lab.test/'])
def test_recognized_secret_formats(value):
    assert SECRET not in redact(value)


def test_retry_preserves_each_encrypted_original(workspace, monkeypatch):
    client, sessions = workspace
    assessment = create(client)
    eid = queue(client, assessment)
    fake = AsyncMock(return_value={'stdout': OUTPUT, 'stderr': 'failed', 'return_code': 7, 'duration_ms': 1})
    monkeypatch.setattr(main.executor, 'execute_command', fake)
    assert SECRET not in json.dumps(asyncio.run(run_execution(eid, sessions)))
    queue(client, assessment)
    fake.return_value = {'stdout': 'second attempt', 'stderr': '', 'return_code': 0, 'duration_ms': 1}
    asyncio.run(run_execution(eid, sessions))
    prefix = f"/assessments/{assessment['id']}/executions/{eid}"
    assert SECRET not in client.get(prefix + '/attempts').text
    assert client.post(prefix + '/evidence/reveal?attempt=1').json()['stdout'] == OUTPUT
    assert client.post(prefix + '/evidence/reveal?attempt=2').json()['stdout'] == 'second attempt'


def test_provider_receives_redacted_evidence(workspace, monkeypatch):
    client, sessions = workspace
    aid, _, _ = completed(client, sessions, monkeypatch)
    analyze = main.analyzer_agent.analyze_results
    observed = []
    def capture(raw, *args, **kwargs):
        observed.append(raw)
        assert SECRET not in json.dumps(raw)
        return analyze(raw, *args, **kwargs)
    monkeypatch.setattr(main.analyzer_agent, 'analyze_results', capture)
    response = client.post(f'/assessments/{aid}/analyze')
    assert response.status_code == 200, response.text
    assert observed


def test_duplicate_draft_is_rejected_after_concurrent_publication(workspace, monkeypatch):
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        row = db.get(Assessment, aid)
        row.current_phase, row.analyzed_phases = 'vuln_analysis', ['recon']
        db.commit()
    step = {'tool': 'curl', 'command': 'curl -I http://lab.test', 'phase': 'exploitation'}
    def interleave(db, row, target, phase):
        with sessions() as other:
            winner = other.get(Assessment, aid)
            winner.plan = winner.plan + [step]
            winner.plan_version += 1
            winner.current_phase = phase
            other.commit()
        return [step], [], None
    monkeypatch.setattr(main, 'try_draft_phase', interleave)
    response = client.post(f'/assessments/{aid}/phases/exploitation/plan')
    assert response.status_code == 409, response.text
    with sessions() as db:
        assert len(db.get(Assessment, aid).plan) == 2


def test_duplicate_promotion_has_one_winner(workspace, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from modules import scope_rules
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        target = db.get(Target, db.get(Assessment, aid).target_id)
        target.exploitation_authorized = target.aggressive_lab = True
        host = EngagementHost(assessment_id=aid, address='lab.test', state='owned')
        db.add(host)
        db.commit()
        hid = host.id
    barrier = Barrier(2)
    check = scope_rules.promotion_scope
    def synchronized(*args):
        result = check(*args)
        barrier.wait(timeout=10)
        return result
    monkeypatch.setattr(scope_rules, 'promotion_scope', synchronized)
    def promote():
        return client.post(f'/assessments/{aid}/promote/{hid}').status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(promote) for _ in range(2)]
        assert sorted(f.result(timeout=20) for f in futures) == [200, 409]
    with sessions() as db:
        assert db.query(Assessment).filter_by(parent_assessment_id=aid).count() == 1


def test_autopilot_failure_rolls_back_local_transition(workspace, monkeypatch):
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        row = db.get(Assessment, aid)
        row.autopilot = True
        row.current_phase = 'exploitation'
        row.analyzed_phases = ['recon']
        target = db.get(Target, row.target_id)
        target.exploitation_authorized = target.aggressive_lab = True
        db.commit()
        previous = list(row.plan)
    monkeypatch.setattr(main, 'try_draft_phase', lambda *args: ([{'tool': 'curl', 'command': 'curl -I http://lab.test', 'phase': 'exploitation'}], [], None))
    from modules import auto_recommend
    def fail(*args):
        raise RuntimeError('injected bookkeeping failure')
    monkeypatch.setattr(auto_recommend, '_signature', fail)
    with pytest.raises(RuntimeError, match='injected'):
        client.post(f'/assessments/{aid}/autopilot/run')
    with sessions() as db:
        row = db.get(Assessment, aid)
        assert row.plan == previous
        assert row.plan_version == 1
        assert not row.autopilot_state


def test_redaction_does_not_change_the_approved_command(workspace, monkeypatch):
    client, sessions = workspace
    assessment = create(client)
    command = 'curl -sS --data "email=probe&password=x" http://lab.test/login'
    with sessions() as db:
        row = db.get(Assessment, assessment['id'])
        row.plan = [{'tool': 'curl', 'command': command, 'phase': 'recon', 'enabled': True}]
        db.get(Target, row.target_id).exploitation_authorized = True
        db.commit()
    eid = queue(client, assessment)
    fake = AsyncMock(return_value={'stdout': '', 'stderr': '', 'return_code': 0, 'duration_ms': 1})
    monkeypatch.setattr(main.executor, 'execute_command', fake)
    asyncio.run(run_execution(eid, sessions))
    assert fake.call_args.args[1] == command
    with sessions() as db:
        execution = db.get(ToolExecution, eid)
        assert original(execution)['command'] == command
        assert 'password=x' not in execution.command


def test_key_creation_has_one_winner(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from modules import secret_store
    monkeypatch.delenv('REDTEAM_SECRET_KEY', raising=False)
    monkeypatch.setattr(secret_store, 'KEY_PATH', tmp_path / 'key')
    with ThreadPoolExecutor(max_workers=4) as executor:
        ciphertexts = list(executor.map(secret_store.encrypt_value, ['one', 'two', 'three', 'four']))
    assert [secret_store.decrypt_required(value) for value in ciphertexts] == ['one', 'two', 'three', 'four']


def test_envelope_looking_plaintext_is_still_encrypted(workspace):
    client, sessions = workspace
    aid = create(client)['id']
    value = 'enc:v1:this-is-a-credential-not-ciphertext'
    with sessions() as db:
        execution = ToolExecution(assessment_id=aid, step_index=0, tool_name='hydra', command='hydra ...',
            stdout=f'[22][ssh] host: lab.test login: admin password: {value}\n', stderr='', return_code=0)
        db.add(execution)
        db.flush()
        main.ingest_execution_evidence(db, execution)
        db.commit()
        loot = db.query(Loot).filter_by(assessment_id=aid).one()
        assert main.footholds.reveal_secret(loot) == value
        assert value not in execution.stdout


def test_redaction_preserves_workflow_and_credential_identity(workspace):
    from modules.secret_store import encrypt_value
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        db.add(Loot(assessment_id=aid, host='lab.test', service='recon', username='recon',
                    secret_encrypted=encrypt_value('recon'), secret_fingerprint='synthetic'))
        db.commit()
        row = db.get(Assessment, aid)
        row.objective = 'A new recon objective'
        row.plan = [{**step, 'reason': 'Updated recon probe'} for step in row.plan]
        db.commit()
        assert row.current_phase == 'recon'
        assert row.plan[0]['phase'] == 'recon'
        loot = db.query(Loot).filter_by(assessment_id=aid).one()
        assert (loot.username, loot.service) == ('recon', 'recon')


def test_external_worker_waits_for_evidence_backfill(workspace, monkeypatch):
    import worker
    client, sessions = workspace
    aid = create(client)['id']
    with sessions() as db:
        db.execute(text('CREATE TABLE alembic_version (version_num VARCHAR(64))'))
        db.execute(text('INSERT INTO alembic_version (version_num) VALUES (:head)'), {'head': worker.migration_head()})
        db.get(Assessment, aid).evidence_protected = False
        db.commit()
        monkeypatch.setattr(worker, 'engine', db.get_bind())
    monkeypatch.setenv('EXECUTION_WORKER_MODE', 'external')
    waits = []
    async def backfill_after_wait(seconds):
        waits.append(seconds)
        with sessions() as db:
            db.get(Assessment, aid).evidence_protected = True
            db.commit()
    async def poll():
        assert waits == [1]
        with sessions() as db:
            assert db.get(Assessment, aid).evidence_protected
    monkeypatch.setattr(worker.asyncio, 'sleep', backfill_after_wait)
    monkeypatch.setattr(worker.job_runner, 'poll', poll)
    monkeypatch.setattr(worker.job_runner, 'stop', AsyncMock())
    asyncio.run(worker.main())
