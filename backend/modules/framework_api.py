"""Scenario catalog, campaign controls, telemetry and retest API."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import Assessment, FrameworkEvent, ScenarioVersion, Target, ToolExecution, get_db, utcnow
from modules.api_auth import verify_operator_key
from modules import framework
from modules.scenarios import Scenario, StrictModel, builtin_scenarios, compile_scenario, digest
from modules.techniques import catalog
from modules.workflow import claim
from modules.evidence import known_secrets, redact

router = APIRouter(dependencies=[Depends(verify_operator_key)])


def assessment(db, aid):
    row = db.get(Assessment, aid)
    if row is None:
        raise HTTPException(404, 'Assessment not found')
    return row


def find_scenario(db, sid, version):
    for item in builtin_scenarios():
        if item['id'] == sid and item['version'] == version:
            return item
    stored = db.query(ScenarioVersion).filter_by(scenario_id=sid, version=version).first()
    if stored is None:
        raise HTTPException(404, 'Scenario version not found')
    return stored.definition


@router.get('/framework/techniques')
def techniques():
    return {'items': catalog(), 'schema_version': 1}


@router.get('/framework/workers')
def workers(db: Session = Depends(get_db)):
    from datetime import timedelta
    from database import WorkerRegistration
    return {'items': [{'id': row.id, 'hostname': row.hostname, 'local_tools': row.capabilities,
                       'heartbeat_at': row.heartbeat_at, 'online': row.heartbeat_at > utcnow() - timedelta(seconds=15),
                       'active_jobs': db.query(ToolExecution).filter_by(worker_id=row.id, state='running').count()}
                      for row in db.query(WorkerRegistration).order_by(WorkerRegistration.heartbeat_at.desc()).limit(100).all()]}


@router.get('/framework/scenarios')
def scenarios(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db)):
    builtins = builtin_scenarios()
    query = db.query(ScenarioVersion).order_by(ScenarioVersion.id.desc())
    items = ([{**item, 'origin': 'builtin', 'digest': digest(item)} for item in builtins][offset:offset + limit]
             + [{**r.definition, 'origin': 'workspace', 'digest': r.digest}
                for r in query.offset(max(0, offset - len(builtins))).limit(max(0, limit - max(0, len(builtins) - offset))).all()])
    return {'items': items, 'total': len(builtins) + query.count(), 'offset': offset, 'limit': limit}


@router.get('/framework/scenarios/{scenario_id}/{version}')
def export_scenario(scenario_id: str, version: str, db: Session = Depends(get_db)):
    return find_scenario(db, scenario_id, version)


@router.post('/framework/scenarios')
def publish_scenario(payload: Scenario, db: Session = Depends(get_db)):
    if any(item['id'] == payload.id for item in builtin_scenarios()):
        raise HTTPException(409, 'Built-in scenario names are reserved; choose a workspace name')
    definition = payload.model_dump(mode='json')
    row = ScenarioVersion(scenario_id=payload.id, version=payload.version, definition=definition, digest=digest(definition))
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Scenario versions are immutable; publish a new version')
    return {**definition, 'digest': row.digest}


class Instantiate(StrictModel):
    scenario_id: str = Field(max_length=64)
    version: str = Field(max_length=20)
    target_id: int = Field(gt=0)
    bindings: dict[str, str] = Field(default_factory=dict, max_length=20)
    objective: str = Field(default='', max_length=1000)


def prepare(db, payload):
    import main as api
    target = db.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(404, 'Target not found')
    try:
        compiled, plan = compile_scenario(find_scenario(db, payload.scenario_id, payload.version), payload.bindings)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    normalized = api.normalize_plan(plan)
    preview = Assessment(id=-1, plan=normalized, framework_state={}, analyzed_phases=[], target_id=target.id)
    for index, step in enumerate(normalized):
        preview.current_phase = step['phase']
        preview.analyzed_phases = list(api.ALL_PLAN_PHASES)
        api.enforce_engagement(db, preview, target, index, step['command'], step['tool'])
    from modules.scope_rules import scopes_overlap
    for criterion in compiled['criteria']:
        endpoint = criterion['endpoint']
        if criterion['kind'] == 'tcp_service':
            endpoint = f"[{endpoint}]:{criterion['port']}" if ':' in endpoint else f"{endpoint}:{criterion['port']}"
        if not api.policy_engine.validate_target(endpoint, api.authorized_scopes_for(target)) or any(
                scopes_overlap(endpoint, excluded) for excluded in (target.engagement_policy or {}).get('excluded_scopes', [])):
            raise HTTPException(403, 'A scenario objective is outside the engagement scope')
    compiled['plan_digest'] = digest(normalized)
    return compiled, normalized


@router.post('/framework/preview')
def preview(payload: Instantiate, db: Session = Depends(get_db)):
    compiled, plan = prepare(db, payload)
    import os
    import shutil
    from main import get_settings_row
    mode = get_settings_row(db).execution_mode or 'local'
    required = sorted({step['tool'] for step in plan})
    if mode == 'kali_vm':
        availability = {tool: 'check_vm_connection' for tool in required}
    elif os.getenv('EXECUTION_WORKER_MODE', 'embedded') == 'external':
        from datetime import timedelta
        from database import WorkerRegistration
        registered = db.query(WorkerRegistration).filter(WorkerRegistration.heartbeat_at > utcnow() - timedelta(seconds=15)).all()
        availability = {tool: 'available' if any(tool in r.capabilities for r in registered) else
                       'missing' if registered else 'worker_unavailable' for tool in required}
    else:
        availability = {tool: 'available' if shutil.which(tool) else 'missing' for tool in required}
    return {'scenario': compiled, 'plan': plan, 'approval_required': True, 'execution_mode': mode, 'tools': availability}


@router.post('/framework/assessments')
def instantiate(payload: Instantiate, db: Session = Depends(get_db)):
    from main import serialize_assessment
    compiled, plan = prepare(db, payload)
    row = Assessment(target_id=payload.target_id, objective=payload.objective.strip() or compiled['definition']['description'],
                     plan=plan, scenario=compiled, framework_state={'control': 'active'},
                     status='awaiting_approval', current_phase='recon', analyzed_phases=[])
    db.add(row)
    db.flush()
    framework.event(db, row, 'created', {'scenario': payload.scenario_id, 'version': payload.version, 'digest': compiled['digest']})
    db.commit()
    return serialize_assessment(row)


@router.get('/assessments/{assessment_id}/framework')
def campaign(assessment_id: int, db: Session = Depends(get_db)):
    row = assessment(db, assessment_id)
    return redact(framework.snapshot(db, row), known_secrets(db, row.id))


class Change(StrictModel):
    workflow_revision: int = Field(ge=1)
    action: Literal['pause', 'resume', 'stop', 'complete']
    note: str = Field(min_length=1, max_length=2000)


@router.post('/assessments/{assessment_id}/control')
def control(assessment_id: int, payload: Change, db: Session = Depends(get_db)):
    row = assessment(db, assessment_id)
    claim(db, row, payload.workflow_revision, allow_running=True)
    framework.control_campaign(db, row, payload.action, payload.note)
    db.commit()
    return framework.snapshot(db, row)


class Cleanup(StrictModel):
    workflow_revision: int = Field(ge=1)
    node_id: str = Field(max_length=64)
    note: str = Field(min_length=1, max_length=2000)


@router.post('/assessments/{assessment_id}/cleanup')
def cleanup(assessment_id: int, payload: Cleanup, db: Session = Depends(get_db)):
    row = assessment(db, assessment_id)
    nodes = {node['id']: node for node in framework.node_states(db, row)}
    node = nodes.get(payload.node_id)
    if not node or node['status'] not in ('completed', 'failed'):
        raise HTTPException(409, 'Cleanup review needs a finished execution')
    if (row.framework_state or {}).get('control') == 'completed':
        raise HTTPException(409, 'Completed campaigns are immutable')
    claim(db, row, payload.workflow_revision)
    records = {**(row.framework_state or {}).get('cleanup', {})}
    records[payload.node_id] = {'note': redact(payload.note.strip(), known_secrets(db, row.id)),
                                'at': utcnow().isoformat(), 'attempt': node['attempt'], 'actor': db.info.get('principal', {}).get('name', 'operator')}
    row.framework_state = {**(row.framework_state or {}), 'cleanup': records}
    framework.event(db, row, 'cleanup', {'node_id': payload.node_id, **records[payload.node_id]})
    db.commit()
    return framework.snapshot(db, row)


class Telemetry(StrictModel):
    execution_id: int = Field(gt=0)
    attempt: int = Field(ge=1)
    source: str = Field(min_length=1, max_length=120)
    external_id: str = Field(min_length=1, max_length=200)
    event_type: Literal['alert', 'observation', 'reviewed_no_alert']
    observed_at: datetime
    summary: str = Field(min_length=1, max_length=2000)

    @model_validator(mode='after')
    def aware(self):
        if self.observed_at.tzinfo is None:
            raise ValueError('Telemetry timestamps must include a timezone')
        if not self.source.strip() or not self.external_id.strip() or not self.summary.strip():
            raise ValueError('Telemetry text cannot be blank')
        return self


class TelemetryBatch(StrictModel):
    workflow_revision: int = Field(ge=1)
    events: list[Telemetry] = Field(min_length=1, max_length=100)


@router.post('/assessments/{assessment_id}/telemetry')
def import_telemetry(assessment_id: int, payload: TelemetryBatch, db: Session = Depends(get_db)):
    row = assessment(db, assessment_id)
    if (row.framework_state or {}).get('control') == 'completed':
        raise HTTPException(409, 'Completed campaigns are immutable')
    prior = db.query(FrameworkEvent).filter_by(assessment_id=row.id, kind='telemetry').all()
    keys = {(r.payload.get('source'), r.payload.get('external_id')) for r in prior}
    if len(prior) + len(payload.events) > 2000:
        raise HTTPException(422, 'This campaign supports at most 2000 imported events')
    prepared = []
    for item in payload.events:
        execution = db.get(ToolExecution, item.execution_id)
        if not execution or execution.assessment_id != row.id or execution.attempt != item.attempt or execution.return_code is None:
            raise HTTPException(422, 'Telemetry must reference a finished current attempt in this assessment')
        observed = item.observed_at.astimezone(timezone.utc).replace(tzinfo=None)
        if observed < execution.executed_at or observed > utcnow():
            raise HTTPException(422, 'Telemetry time must be between execution start and the current time')
        key = (item.source, item.external_id)
        if key in keys:
            raise HTTPException(409, 'The source event is already imported or repeated in this batch')
        keys.add(key)
        prepared.append({**item.model_dump(mode='json'), 'evidence_sha256': execution.evidence_sha256,
                         'delay_seconds': (observed - execution.executed_at).total_seconds()})
    claim(db, row, payload.workflow_revision)
    for item in prepared:
        framework.event(db, row, 'telemetry', item)
    db.commit()
    return framework.snapshot(db, row)


@router.get('/assessments/{assessment_id}/framework/events')
def events(assessment_id: int, offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100), db: Session = Depends(get_db)):
    row = assessment(db, assessment_id)
    query = db.query(FrameworkEvent).filter_by(assessment_id=row.id)
    result = {'items': [{'id': r.id, 'kind': r.kind, 'actor': r.actor, 'payload': r.payload, 'created_at': r.created_at}
                        for r in query.order_by(FrameworkEvent.id.desc()).offset(offset).limit(limit).all()],
              'total': query.count(), 'offset': offset, 'limit': limit}
    return redact(result, known_secrets(db, row.id))


@router.post('/assessments/{assessment_id}/retest')
def retest(assessment_id: int, db: Session = Depends(get_db)):
    source = assessment(db, assessment_id)
    if not source.scenario:
        raise HTTPException(409, 'Reusable retests require a scenario assessment')
    # Recompile and revalidate the immutable definition, even if its library
    # version is later retired. No execution or verdict carries into the run.
    compiled, plan = compile_scenario(source.scenario['definition'], source.scenario['bindings'])
    import main as api
    target = db.get(Target, source.target_id)
    check = Assessment(id=-1, plan=plan, analyzed_phases=list(api.ALL_PLAN_PHASES), framework_state={})
    for index, step in enumerate(plan):
        check.current_phase = step['phase']
        api.enforce_engagement(db, check, target, index, step['command'], step['tool'])
    compiled['plan_digest'] = digest(plan)
    row = Assessment(target_id=source.target_id, objective=source.objective, plan=plan, scenario=compiled,
                     framework_state={'control': 'active', 'baseline_id': source.id})
    db.add(row)
    db.flush()
    framework.event(db, row, 'retest', {'baseline_id': source.id, 'scenario_digest': compiled['digest']})
    db.commit()
    return api.serialize_assessment(row)


@router.get('/assessments/{assessment_id}/framework/compare/{baseline_id}')
def compare(assessment_id: int, baseline_id: int, db: Session = Depends(get_db)):
    current, baseline = assessment(db, assessment_id), assessment(db, baseline_id)
    if current.id == baseline.id or current.target_id != baseline.target_id or not current.scenario or not baseline.scenario:
        raise HTTPException(422, 'Compare distinct scenario campaigns of the same target')
    if current.scenario['digest'] != baseline.scenario['digest'] or current.scenario['bindings'] != baseline.scenario['bindings']:
        raise HTTPException(409, 'Scenario version and input bindings must match for a controlled comparison')
    if not current.analyzed_phases or set(current.analyzed_phases) != set(baseline.analyzed_phases or []):
        raise HTTPException(409, 'Analyze the same phases in both campaigns before comparing')
    before, after = framework.snapshot(db, baseline), framework.snapshot(db, current)
    return {'baseline_id': baseline.id, 'assessment_id': current.id, 'scenario_digest': current.scenario['digest'],
            'items': [{'node_id': a['id'], 'before': {'execution': b['status'], 'objective': (b['objective'] or {}).get('status', 'not_configured')},
                       'after': {'execution': a['status'], 'objective': (a['objective'] or {}).get('status', 'not_configured')}}
                      for b, a in zip(before['nodes'], after['nodes'])],
            'detection_before': before['detection'], 'detection_after': after['detection']}
