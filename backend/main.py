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
from modules.engagement_parser import parse_engagement
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
    return {'id': row.id, 'name': row.name, 'scope_domain_ip': row.scope_domain_ip, 'authorized_scopes': row.authorized_scopes or [row.scope_domain_ip], 'criticality': row.criticality if row.criticality is not None else DEFAULT_ASSET_CRITICALITY, 'restricted_tools': row.restricted_tools or [], 'created_at': row.created_at}


def serialize_assessment(row):
    return {'id': row.id, 'target_id': row.target_id, 'objective': row.objective, 'status': row.status, 'plan': row.plan or [], 'engagement_brief': row.engagement_brief, 'approval_required': row.approval_required, 'created_at': row.created_at, 'completed_at': row.completed_at}


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


def restricted_tools_for(target):
    return set(target.restricted_tools or [])


def engagement_restriction_context(target):
    """One-line summary of the client's per-target tool restrictions.

    Appended to the planner's requirement context so an AI plan avoids the
    restricted tools up front instead of having them filtered out afterward.
    """
    restricted = sorted(restricted_tools_for(target))
    if not restricted:
        return ''
    return ('Client engagement restriction: the tools '
            + ', '.join(restricted)
            + ' must not be used against this target.')


def brief_requirement_context(brief):
    """Render the parsed letter as the labelled lines a planner follows best.

    A structured brief states scope and rules as facts ('Out of scope:',
    'Prohibited techniques:') instead of leaving them buried in letter prose,
    so a model asked to plan from it cannot mistake a rule for background.
    """
    if not isinstance(brief, dict):
        return ''
    lines = []
    meta = []
    if brief.get('client_name'):
        meta.append('client ' + str(brief['client_name']))
    if brief.get('engagement_ref'):
        meta.append('engagement ' + str(brief['engagement_ref']))
    if brief.get('test_window'):
        meta.append('test window ' + str(brief['test_window']))
    if meta:
        lines.append('Engagement: ' + ', '.join(meta))
    objectives = [str(item) for item in (brief.get('objectives') or []) if str(item).strip()]
    if objectives:
        lines.append('Client objectives:')
        lines.extend('- ' + item for item in objectives)
    out_of_scope = [str(item) for item in (brief.get('out_of_scope') or []) if str(item).strip()]
    if out_of_scope:
        lines.append('Out of scope (never touch):')
        lines.extend('- ' + item for item in out_of_scope)
    prohibited = [str(item) for item in (brief.get('prohibited') or []) if str(item).strip()]
    if prohibited:
        lines.append('Prohibited techniques (never do):')
        lines.extend('- ' + item for item in prohibited)
    return '\n'.join(lines)


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


def extract_upload_text(suffix, content):
    """Decode an uploaded requirement document to plain text.

    Shared by the requirements extractor and the engagement parser so both
    accept the same formats and fail with the same message.
    """
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
    return text.strip()


@app.post('/requirements/extract')
async def extract_requirements(file: UploadFile = File(...)):
    allowed = {'.txt', '.md', '.pdf', '.docx'}
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in allowed:
        raise HTTPException(415, 'Supported requirement files: .txt, .md, .pdf, .docx')
    content = await read_bounded_upload(file, MAX_REQUIREMENT_BYTES)
    try:
        text = extract_upload_text(suffix, content)
    except Exception as exc:
        raise HTTPException(422, f'Could not read requirement file: {exc}')
    if not text:
        raise HTTPException(422, 'Requirement file contains no readable text')
    return {'filename': file.filename, 'text': text[:30000]}


@app.post('/engagement/parse')
async def parse_engagement_letter(file: UploadFile = File(...)):
    """Import a client engagement letter and hand back what the agent should do.

    The same extraction path as /requirements/extract feeds a deterministic
    parser, so the brief the UI shows - targets, criticalities, per-target
    tool restrictions, objectives, out-of-scope list - is identical to what
    the policy and planning layers will act on.
    """
    allowed = {'.txt', '.md', '.pdf', '.docx'}
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in allowed:
        raise HTTPException(415, 'Supported engagement files: .txt, .md, .pdf, .docx')
    content = await read_bounded_upload(file, MAX_REQUIREMENT_BYTES)
    try:
        text = extract_upload_text(suffix, content)
    except Exception as exc:
        raise HTTPException(422, f'Could not read engagement file: {exc}')
    if not text:
        raise HTTPException(422, 'Engagement file contains no readable text')
    engagement = parse_engagement(text)
    if not engagement['targets']:
        raise HTTPException(422, 'No authorized targets could be found in this document; add the target manually instead')
    return {'filename': file.filename, 'engagement': engagement, 'text': text[:30000]}


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
    # A restriction can only bind tools the framework is able to run, so names
    # outside the policy registry are dropped here rather than refused - a
    # misparsed letter should not block target registration.
    runnable = set(policy_engine.tool_registry())
    restricted = [tool for tool in dict.fromkeys(payload.restricted_tools) if tool in runnable]
    row = Target(name=payload.name.strip(), scope_domain_ip=primary_scope, authorized_scopes=scopes, criticality=payload.criticality, restricted_tools=restricted)
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
    restricted = restricted_tools_for(target)
    # The structured brief leads and the raw letter text follows it, so the
    # planner gets the rules as labelled facts first and the prose only as
    # supporting context. The restriction line stays last, where it already
    # proved effective.
    context_parts = [
        brief_requirement_context(payload.engagement_brief),
        (payload.requirements or '').strip(),
    ]
    restriction_line = engagement_restriction_context(target)
    if restriction_line:
        context_parts.append(restriction_line)
    requirement_context = '\n\n'.join(part for part in context_parts if part)
    plan = payload.plan
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
    if restricted and plan:
        # The client letter outranks both the AI and the operator's pasted
        # plan: steps using a restricted tool never reach the approval list.
        kept = [step for step in plan if step.get('tool') not in restricted]
        dropped = len(plan) - len(kept)
        plan = kept
    else:
        dropped = 0
    plan = normalize_plan(plan)
    row = Assessment(target_id=payload.target_id, objective=payload.objective, plan=plan, engagement_brief=payload.engagement_brief, status='awaiting_approval')
    db.add(row)
    db.commit()
    db.refresh(row)
    result = serialize_assessment(row)
    result['plan_source'] = source
    result['restricted_steps_dropped'] = dropped
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
    if step['tool'] in restricted_tools_for(target):
        # The client's letter restricts this tool for this target even though
        # the global policy would allow it; refusing here keeps a manually
        # edited plan from bypassing the import-time filtering.
        raise HTTPException(403, f"{step['tool']} is restricted for this target by the client's engagement letter")
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
        engagement_brief=row.engagement_brief,
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
