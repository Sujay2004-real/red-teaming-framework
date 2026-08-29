import os
from datetime import timedelta
from urllib.parse import quote, urlparse
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pathlib import Path

from database import AppSettings, Assessment, Finding, Target, ToolExecution, get_db, utcnow
from models import AssessmentCreate, ExecuteRequest, PlanUpdate, SettingsUpdate, TargetCreate
from modules.analyzer import DEFAULT_ASSET_CRITICALITY, analyzer_agent
from modules.executor import EXECUTION_TIMEOUT_SECONDS, executor
from modules.planner import MAX_PLAN_STEPS, planner_agent
from modules.policy_engine import policy_engine
from modules.reporter import reporter
from modules.secret_store import decrypt_secret, encrypt_secret

app = FastAPI(title='Red Teaming Framework API', version='2.0')
# The dev server's origin is the default, but it is not the only place this UI
# can be served from; a hardcoded origin meant any other deployment silently
# failed every request in the browser with no server-side sign of why.
CORS_ORIGINS = [origin.strip() for origin in os.getenv('CORS_ALLOW_ORIGINS', 'http://localhost:5173').split(',') if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

REPORTS_DIR = Path('./data/reports')
MAX_REQUIREMENT_BYTES = 5 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 65_536
# A plan is stored as opaque JSON, so nothing else bounds what a client can put
# in one. Long enough for any real scanner invocation, short enough that fifty
# steps cannot become a multi-megabyte row.
MAX_PLAN_FIELD_CHARS = {'tool': 100, 'command': 4000, 'reason': 2000}
# An execution row is written before the command runs, so a row still holding
# return_code=NULL after the command could not possibly still be running is the
# residue of a disconnect or a restart and may be reclaimed.
EXECUTION_STALE_AFTER = timedelta(seconds=EXECUTION_TIMEOUT_SECONDS + 60)
# The UI blanks these inputs after saving, so an empty submission means "keep
# what is stored" rather than "erase it".
SECRET_SETTING_FIELDS = ('gemini_api_key', 'proxy_password')


def serialize_target(row):
    return {'id': row.id, 'name': row.name, 'scope_domain_ip': row.scope_domain_ip, 'authorized_scopes': row.authorized_scopes or [row.scope_domain_ip], 'criticality': row.criticality if row.criticality is not None else DEFAULT_ASSET_CRITICALITY, 'created_at': row.created_at}


def serialize_assessment(row):
    return {'id': row.id, 'target_id': row.target_id, 'objective': row.objective, 'status': row.status, 'plan': row.plan or [], 'approval_required': row.approval_required, 'created_at': row.created_at, 'completed_at': row.completed_at}


def execution_is_stale(execution):
    if execution.return_code is not None:
        return False
    started = execution.executed_at
    return started is None or utcnow() - started > EXECUTION_STALE_AFTER


def serialize_execution(row):
    return {
        'id': row.id, 'step_index': row.step_index, 'tool_name': row.tool_name, 'command': row.command,
        'stdout': row.stdout, 'stderr': row.stderr, 'return_code': row.return_code,
        'duration_ms': row.duration_ms, 'approved_by_user': row.approved_by_user,
        'attempt': row.attempt or 1, 'executed_at': row.executed_at,
        'complete': row.return_code is not None,
        # A step that never finished or finished badly may be approved again;
        # a successful one may not, so the audit trail stays append-only in
        # the case that matters.
        'retryable': row.return_code != 0 and (row.return_code is not None or execution_is_stale(row)),
    }


def serialize_finding(row):
    return {'id': row.id, 'title': row.title, 'description': row.description, 'severity': row.severity, 'evidence': row.evidence, 'remediation': row.remediation, 'risk_score': row.risk_score, 'priority_score': row.priority_score, 'confidence_score': row.confidence_score, 'source_tools': row.source_tools}


def get_settings_row(db):
    row = db.query(AppSettings).filter(AppSettings.id == 1).first()
    if row:
        return row
    # Created empty on purpose. Seeding a key, endpoint, or model from the
    # environment would mean scanner output could reach a provider the operator
    # never chose, so AI features stay off until someone configures them here.
    row = AppSettings(id=1, gemini_api_key='', api_base_url='', model_name='')
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        # Another request created the singleton row first.
        db.rollback()
        existing = db.query(AppSettings).filter(AppSettings.id == 1).first()
        if existing is None:
            # The insert conflicted with something that is no longer there, so
            # the caller would get an AttributeError on a None row instead of a
            # readable failure.
            raise HTTPException(503, 'Settings are temporarily unavailable; retry the request')
        return existing
    db.refresh(row)
    return row


def provider_credentials(settings):
    """Return (api_key, base_url, model_name), all three or nothing.

    A key without an endpoint and model is not a usable provider, and there is
    no default to fall back on, so a partial configuration reports as unset and
    the caller takes its deterministic path.
    """
    api_key = decrypt_secret(settings.gemini_api_key)
    base_url = (settings.api_base_url or '').strip()
    model_name = (settings.model_name or '').strip()
    if not (api_key and base_url and model_name):
        return '', '', ''
    # requests would reject a non-HTTP scheme deep inside the planner, where it
    # is indistinguishable from the provider being down. Treat an endpoint that
    # can never work as an unconfigured one instead.
    if urlparse(base_url).scheme not in ('http', 'https'):
        return '', '', ''
    return api_key, base_url, model_name


def normalize_plan(plan):
    if not isinstance(plan, list) or not plan:
        raise HTTPException(422, 'Assessment plan must contain at least one step')
    if len(plan) > MAX_PLAN_STEPS:
        raise HTTPException(422, f'Assessment plan cannot contain more than {MAX_PLAN_STEPS} steps')
    normalized = []
    for step in plan:
        if not isinstance(step, dict) or not isinstance(step.get('tool'), str) or not step['tool'].strip() or not isinstance(step.get('command'), str) or not step['command'].strip():
            raise HTTPException(422, 'Every plan step needs a non-empty tool and command')
        item = dict(step)
        item['tool'] = item['tool'].strip()
        item['command'] = item['command'].strip()
        if 'enabled' in item and not isinstance(item['enabled'], bool):
            raise HTTPException(422, 'Plan step enabled must be a boolean')
        item.setdefault('enabled', True)
        item.setdefault('reason', 'User-defined assessment command.')
        for field, limit in MAX_PLAN_FIELD_CHARS.items():
            value = item.get(field)
            if isinstance(value, str) and len(value) > limit:
                raise HTTPException(422, f'Plan step {field} cannot exceed {limit} characters')
        normalized.append(item)
    return normalized


def proxy_environment(settings):
    if not settings.proxy_url:
        return {}
    url = settings.proxy_url
    password = decrypt_secret(settings.proxy_password)
    if settings.proxy_username and password and '://' in url:
        scheme, remainder = url.split('://', 1)
        url = f'{scheme}://{quote(settings.proxy_username)}:{quote(password)}@{remainder}'
    return {'HTTP_PROXY': url, 'HTTPS_PROXY': url, 'http_proxy': url, 'https_proxy': url}


def report_path(assessment_id):
    return REPORTS_DIR / f'report_{assessment_id}.html'


def invalidate_analysis(db, assessment_id):
    """Drop findings and the rendered report for an assessment.

    Called whenever the executions an analysis was derived from change, so
    /reports/{id} can never serve a document describing findings that no
    longer exist.
    """
    db.query(Finding).filter(Finding.assessment_id == assessment_id).delete()
    try:
        report_path(assessment_id).unlink(missing_ok=True)
    except OSError:
        pass


def authorized_scopes_for(target):
    return target.authorized_scopes or [target.scope_domain_ip]


def record_abandoned_execution(db, execution_id, detail):
    """Give an execution a terminal state after its request died mid-flight.

    A client disconnect cancels the request coroutine, and CancelledError is a
    BaseException, so without this the row keeps return_code=NULL forever. That
    left the step unable to be re-run (uniqueness), analysed (NULL return code)
    or edited (executions exist) - a permanently stuck assessment. Runs in its
    own session bound to the same engine, so a poisoned request transaction
    cannot swallow the write.
    """
    session = Session(bind=db.get_bind())
    try:
        execution = session.query(ToolExecution).filter(ToolExecution.id == execution_id).first()
        if execution and execution.return_code is None:
            execution.return_code = -1
            execution.stderr = detail
            # The execute endpoint set the assessment to 'running' before the
            # command started. Reclaiming the execution row without also moving
            # the assessment off 'running' left the UI reporting an in-progress
            # step that had already been given up on.
            session.flush()
            assessment = session.query(Assessment).filter(Assessment.id == execution.assessment_id).first()
            if assessment is not None and assessment.status == 'running':
                refresh_assessment_status(session, assessment)
            session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def refresh_assessment_status(db, row, extra_executed=()):
    enabled = [index for index, step in enumerate(row.plan or []) if step.get('enabled', True)]
    executed = {
        execution.step_index
        for execution in db.query(ToolExecution).filter(ToolExecution.assessment_id == row.id, ToolExecution.return_code.is_not(None)).all()
    } | set(extra_executed)
    # 'running' must not stick between steps: once a command returns, the
    # assessment is idle again and waiting on the next human approval.
    row.status = 'ready_for_analysis' if enabled and all(index in executed for index in enabled) else 'awaiting_approval'
    return row.status


def reconcile_running_status(db, row, executions):
    """Move an assessment off 'running' when nothing is actually running.

    A clean disconnect is handled by record_abandoned_execution, but a hard
    restart of the server kills the request without running anything at all,
    leaving status='running' and a NULL return code behind. Once that row is old
    enough that the command cannot still be alive, the state is stale rather
    than in-progress, and the UI would otherwise report the run as ongoing
    forever with no way to clear it.
    """
    if row.status != 'running':
        return False
    if any(execution.return_code is None and not execution_is_stale(execution) for execution in executions):
        return False
    refresh_assessment_status(db, row)
    db.commit()
    return True


@app.get('/capabilities')
def get_capabilities():
    return policy_engine.public_capabilities()


async def read_bounded_upload(upload, limit):
    """Read an upload in chunks, refusing it as soon as it exceeds the limit.

    Reading the whole body before checking its length would let any client
    buffer arbitrary bytes in memory first.
    """
    chunks, total = [], 0
    while True:
        chunk = await upload.read(UPLOAD_CHUNK_BYTES)
        if not chunk:
            return b''.join(chunks)
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, 'Requirement file must be 5 MB or smaller')
        chunks.append(chunk)


@app.post('/requirements/extract')
async def extract_requirements(file: UploadFile = File(...)):
    allowed = {'.txt', '.md', '.pdf', '.docx'}
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in allowed:
        raise HTTPException(415, 'Supported requirement files: .txt, .md, .pdf, .docx')
    content = await read_bounded_upload(file, MAX_REQUIREMENT_BYTES)
    try:
        if suffix in {'.txt', '.md'}:
            text = content.decode('utf-8', errors='ignore')
        elif suffix == '.pdf':
            from pypdf import PdfReader
            import io
            text = '\n'.join(page.extract_text() or '' for page in PdfReader(io.BytesIO(content)).pages)
        else:
            from docx import Document
            import io
            doc = Document(io.BytesIO(content))
            text = '\n'.join(p.text for p in doc.paragraphs)
    except Exception as exc:
        raise HTTPException(422, f'Could not read requirement file: {exc}')
    text = text.strip()
    if not text:
        raise HTTPException(422, 'Requirement file contains no readable text')
    return {'filename': file.filename, 'text': text[:30000]}


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/settings')
def get_settings(db: Session = Depends(get_db)):
    row = get_settings_row(db)
    # Whether a key is stored is a separate question from whether the provider is
    # usable. Conflating them made a saved key look absent while the model name
    # was still blank, so the UI told the user to enter it again.
    stored_key = decrypt_secret(row.gemini_api_key)
    base_url = (row.api_base_url or '').strip()
    model_name = (row.model_name or '').strip()
    return {
        # Secrets are reported as booleans only. No response on this API ever
        # carries the API key or the proxy password back out, encrypted or not.
        'gemini_configured': bool(stored_key),
        'proxy_configured': bool(row.proxy_url),
        # A key with no endpoint or model cannot reach a provider, so the UI is
        # told the difference between "configured" and "partly filled in".
        'provider_ready': bool(stored_key and base_url and model_name),
        'api_base_url': row.api_base_url or '',
        'model_name': row.model_name or '',
        'proxy_url': row.proxy_url or '',
        'proxy_username': row.proxy_username or '',
    }


@app.put('/settings')
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    row = get_settings_row(db)
    for key, value in payload.model_dump(exclude_unset=True).items():
        if value is None or (value == '' and key in SECRET_SETTING_FIELDS):
            continue
        setattr(row, key, encrypt_secret(value) if key in SECRET_SETTING_FIELDS else value)
    # Credentials with no proxy to authenticate against are dead weight, and
    # keeping a password that can never be cleared is worse than useless.
    if not (row.proxy_url or '').strip():
        row.proxy_username = ''
        row.proxy_password = ''
    db.commit()
    return get_settings(db)


@app.post('/targets/')
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    primary_scope = payload.scope_domain_ip.strip()
    scopes = [scope.strip() for scope in payload.authorized_scopes if scope and scope.strip()] or [primary_scope]
    row = Target(name=payload.name.strip(), scope_domain_ip=primary_scope, authorized_scopes=scopes, criticality=payload.criticality)
    db.add(row)
    db.commit()
    db.refresh(row)
    return serialize_target(row)


@app.get('/targets/')
def get_targets(db: Session = Depends(get_db)):
    return [serialize_target(row) for row in db.query(Target).all()]


@app.post('/assessments/')
def create_assessment(payload: AssessmentCreate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    settings = get_settings_row(db)
    plan = payload.plan
    requirement_context = (payload.requirements or '').strip()
    if not plan:
        api_key, base_url, model_name = provider_credentials(settings)
        plan, source = planner_agent.generate_plan(
            target.scope_domain_ip,
            payload.objective,
            api_key,
            base_url,
            model_name,
            requirement_context,
            policy_engine,
            # Plan-time policy review has to use the same scopes the execute
            # endpoint will, or authorized secondary scopes get silently
            # filtered out of the plan.
            authorized_scopes=authorized_scopes_for(target),
        )
    else:
        source = 'user'
    plan = normalize_plan(plan)
    row = Assessment(target_id=payload.target_id, objective=payload.objective, plan=plan, status='awaiting_approval')
    db.add(row)
    db.commit()
    db.refresh(row)
    result = serialize_assessment(row)
    result['plan_source'] = source
    return result


@app.get('/assessments/')
def get_assessments(db: Session = Depends(get_db)):
    return [serialize_assessment(row) for row in db.query(Assessment).order_by(Assessment.id.desc()).all()]


@app.get('/assessments/{assessment_id}')
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).order_by(ToolExecution.step_index).all()
    reconcile_running_status(db, row, executions)
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    result = serialize_assessment(row)
    result['executions'] = [serialize_execution(execution) for execution in executions]
    result['findings'] = [serialize_finding(finding) for finding in findings]
    return result


@app.put('/assessments/{assessment_id}/plan')
def update_plan(assessment_id: int, payload: PlanUpdate, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).first():
        raise HTTPException(409, 'Plan cannot be edited after execution begins')
    row.plan = normalize_plan(payload.plan)
    row.status = 'awaiting_approval'
    invalidate_analysis(db, assessment_id)
    db.commit()
    return serialize_assessment(row)


@app.post('/assessments/{assessment_id}/execute')
async def execute_step(assessment_id: int, payload: ExecuteRequest, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if not payload.approved:
        raise HTTPException(403, 'Explicit human approval is required')
    if payload.step_index >= len(row.plan or []):
        raise HTTPException(400, 'Invalid step index')
    step = row.plan[payload.step_index]
    if not step.get('enabled', True):
        raise HTTPException(400, 'This step is disabled')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    valid, reason, capability = policy_engine.validate_command(step['command'], authorized_scopes_for(target), expected_tool=step['tool'])
    if not valid:
        raise HTTPException(403, reason)
    settings = get_settings_row(db)

    existing = db.query(ToolExecution).filter(ToolExecution.assessment_id == row.id, ToolExecution.step_index == payload.step_index).first()
    if existing and existing.return_code == 0:
        raise HTTPException(409, 'This plan step has already been executed')
    if existing and existing.return_code is None and not execution_is_stale(existing):
        raise HTTPException(409, 'This plan step is still executing; wait for it to finish or time out')
    if existing:
        # Re-approving a failed or abandoned step reuses its row so the
        # uniqueness constraint keeps guarding concurrency without turning a
        # single bad attempt into a permanently unrunnable step.
        execution = existing
        execution.tool_name, execution.command = step['tool'], step['command']
        execution.stdout, execution.stderr = '', ''
        execution.return_code, execution.duration_ms = None, 0
        execution.approved_by_user = True
        execution.attempt = (execution.attempt or 1) + 1
        execution.executed_at = utcnow()
    else:
        execution = ToolExecution(assessment_id=row.id, step_index=payload.step_index, tool_name=step['tool'], command=step['command'], stdout='', stderr='', return_code=None, duration_ms=0, approved_by_user=True, attempt=1)
        db.add(execution)
    # Re-running a step invalidates any analysis derived from the old output.
    invalidate_analysis(db, assessment_id)
    row.status = 'running'
    row.completed_at = None
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'This plan step has already been executed')
    db.refresh(execution)
    execution_id = execution.id

    try:
        result = await executor.execute_command(step['tool'], step['command'], proxy_environment(settings))
    except BaseException as exc:
        record_abandoned_execution(db, execution_id, f'Execution did not complete: {type(exc).__name__}: {exc}'.strip())
        raise

    execution.stdout = result['stdout']
    execution.stderr = result['stderr']
    execution.return_code = result['return_code']
    execution.duration_ms = result['duration_ms']
    status = refresh_assessment_status(db, row, extra_executed={payload.step_index})
    db.commit()
    return {'message': 'Execution finished', 'policy': reason, 'capability': capability, 'status': status, 'result': result}


@app.post('/assessments/{assessment_id}/analyze')
def analyze_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id, ToolExecution.return_code.is_not(None)).all()
    if not executions:
        raise HTTPException(400, 'Execute at least one approved plan step first')
    enabled_steps = {index for index, step in enumerate(row.plan or []) if step.get('enabled', True)}
    executed_steps = {execution.step_index for execution in executions}
    if not enabled_steps.issubset(executed_steps):
        raise HTTPException(409, 'Execute every enabled plan step before analysis')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    raw = [{'tool': e.tool_name, 'stdout': e.stdout or '', 'stderr': e.stderr or ''} for e in executions]
    settings = get_settings_row(db)
    api_key, base_url, model_name = provider_credentials(settings)
    analyzed, analyzer_mode = analyzer_agent.analyze_results(
        raw,
        api_key,
        base_url,
        model_name,
        include_metadata=True,
        asset_criticality=target.criticality if target else None,
    )
    invalidate_analysis(db, assessment_id)
    for item in analyzed:
        db.add(Finding(assessment_id=assessment_id, fingerprint=item['fingerprint'], title=item.get('title', 'Unknown finding'), description=item.get('description', ''), severity=item['severity'], evidence=item.get('evidence', ''), remediation=item.get('remediation', ''), risk_score=item['risk_score'], priority_score=item['priority_score'], confidence_score=item['confidence_score'], source_tools=item.get('source_tools', [])))
    row.status = 'analyzed'
    row.completed_at = utcnow()
    db.commit()
    failed = [execution.step_index for execution in executions if execution.return_code != 0]
    return {'message': 'Analysis complete', 'findings_count': len(analyzed), 'analyzer': analyzer_mode, 'failed_steps': failed}


@app.post('/assessments/{assessment_id}/report')
def generate_report(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    if row.status not in {'analyzed', 'reported'}:
        raise HTTPException(409, 'Analyze the completed assessment before generating a report')
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).order_by(ToolExecution.step_index).all()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = report_path(assessment_id)
    reporter.generate_html_report(
        target.scope_domain_ip,
        row.objective,
        [serialize_finding(finding) for finding in findings],
        [serialize_execution(execution) for execution in executions],
        str(path),
    )
    row.status = 'reported'
    db.commit()
    return {'message': 'Report generated', 'download_url': f'/reports/{assessment_id}'}


@app.get('/reports/{assessment_id}')
def download_report(assessment_id: int):
    path = report_path(assessment_id)
    if not path.exists():
        raise HTTPException(404, 'Report not generated')
    return FileResponse(str(path), media_type='text/html', filename=f'security-assessment-{assessment_id}.html')
