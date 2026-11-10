import asyncio
import logging
from contextlib import asynccontextmanager
import os
import ipaddress
import shlex
from datetime import timedelta
from urllib.parse import quote, urlparse
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import IntegrityError
from pathlib import Path

from database import initialize_database, EngagementHost, ExecutionAttempt, FindingReview, Foothold, Loot, ReportVersion, RecommendationTask, SessionLocal, AppSettings, Assessment, Finding, Recommendation, Target, ToolExecution, get_db, utcnow
from models import AssessmentCreate, AutopilotUpdate, ExecuteRequest, PlanUpdate, PromoteRequest, SettingsUpdate, TargetCreate
from modules.analyzer import DEFAULT_ASSET_CRITICALITY, analyzer_agent, extract_nmap_hosts, match_verification
from modules.api_auth import API_KEY_ENV_VAR, ensure_operator_key, verify_operator_key
from modules.attack_paths import derive_paths, narrate_paths
from modules.campaign_objectives import objective_result
from modules import framework
from database import FrameworkEvent
from modules.engagement_parser import parse_engagement
from modules.executor import EXECUTION_TIMEOUT_SECONDS, executor, live_registry
from modules.exploit_planner import exploit_planner
from modules.next_steps import PHASE_PROPOSAL_REFUSALS, PROPOSAL_PHASES, next_steps_planner
from modules import footholds
from modules.auto_recommend import AUTOPILOT_MAX_ITERATIONS, autopilot_state, run_autopilot_iteration
from modules.phases import (
    ALL_PLAN_PHASES, EXPLOITATION_GATED_TOOLS, PHASES, PHASE_LABELS, PLAN_PHASES, VM_ONLY_TOOLS,
    analysis_advances_to, next_draftable_phase, phase_chain, phase_index, plan_phases,
    preceding_plan_phase, validate_phase,
)
from modules.planners import campaign_planner, resolve_references
from modules.planner import MAX_PLAN_STEPS, planner_agent
from modules.policy_engine import policy_engine
from modules.reporter import reporter
from modules.secret_store import decrypt_secret, encrypt_secret

from modules.jobs import job_runner, run_execution, archive_attempt
from modules.outcomes import outcome, SUCCESS
from modules.scope_rules import scopes_overlap, command_destinations, check_window
from modules.logging_config import configure_logging
from modules.workflow import claim as claim_workflow, retire_current_file
from modules.evidence import redact, original, known_secrets, unseal
from sqlalchemy.orm.exc import StaleDataError

# Configure logging at import so records emitted while the app is being built
# (and by the observability middleware once requests arrive) reach a handler.
# Without this, `uvicorn main:app` leaves the root logger at WARNING with no
# handler and the structured access log is silently dropped.
configure_logging()
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app):
    configure_logging()
    initialize_database()
    _ensure_operator_key_at_startup()
    if os.getenv('EXECUTION_WORKER_MODE', 'embedded') == 'embedded':
        await job_runner.start()
    try:
        yield
    finally:
        await job_runner.stop()
        if recommendation_tasks:
            await asyncio.gather(*list(recommendation_tasks), return_exceptions=True)

app = FastAPI(title='Red Teaming Framework API', version='4.0.0', lifespan=lifespan)


@app.exception_handler(StaleDataError)
async def stale_workflow_handler(request, exc):
    return JSONResponse(status_code=409, content={'detail': 'Assessment changed during this operation; reload and retry'})
from modules.observability import RequestObservability
app.add_middleware(RequestObservability)
# The dev server's origin is the default, but it is not the only place this UI
# can be served from; a hardcoded origin meant any other deployment silently
# failed every request in the browser with no server-side sign of why. Both
# localhost spellings are allowed by default because port-forward links and
# terminals routinely hand out 127.0.0.1 instead.
CORS_ORIGINS = [origin.strip() for origin in os.getenv('CORS_ALLOW_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173').split(',') if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

REPORTS_DIR = Path('./data/reports')
MAX_REQUIREMENT_BYTES = 5 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 65_536
# Every route below declares `dependencies=PROTECTED` except /health, which
# the UI's reachability poll must be able to reach without a key. A route
# without this list is an anonymous route - grep for decorators missing it.
PROTECTED = [Depends(verify_operator_key)]
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
SECRET_SETTING_FIELDS = ('gemini_api_key', 'proxy_password', 'ssh_password', 'ssh_private_key', 'ssh_key_passphrase')
EXECUTION_MODES = ('local', 'kali_vm')


def serialize_target(row):
    network = None
    try:
        network = ipaddress.ip_network(row.scope_domain_ip, strict=False)
    except ValueError:
        pass
    return {'id': row.id, 'name': row.name, 'scope_domain_ip': row.scope_domain_ip, 'authorized_scopes': row.authorized_scopes or [row.scope_domain_ip], 'criticality': row.criticality if row.criticality is not None else DEFAULT_ASSET_CRITICALITY, 'restricted_tools': row.restricted_tools or [], 'exploitation_authorized': bool(row.exploitation_authorized), 'aggressive_lab': bool(row.aggressive_lab), 'created_at': row.created_at, 'engagement_policy': row.engagement_policy or {}, 'scope_type': 'network' if network else 'host', 'network_address_count': network.num_addresses if network else None, 'network_prefix': network.prefixlen if network else None}


def serialize_assessment(row):
    return {'id': row.id, 'target_id': row.target_id, 'objective': row.objective, 'status': row.status, 'plan': row.plan or [], 'engagement_brief': row.engagement_brief, 'plan_version': row.plan_version or 1, 'analysis_metadata': row.analysis_metadata or {}, 'approval_required': row.approval_required, 'analysis_mode': row.analysis_mode or '', 'current_phase': row.current_phase or 'recon', 'analyzed_phases': row.analyzed_phases or [], 'created_at': row.created_at, 'completed_at': row.completed_at, 'scenario': row.scenario, 'framework_state': row.framework_state or {}, 'workflow_revision': row.workflow_revision}


def discovered_hosts_for(executions):
    hosts = []
    for execution in executions:
        if execution.tool_name.lower() != 'nmap':
            continue
        for host in extract_nmap_hosts(execution.stdout or ''):
            if host not in hosts:
                hosts.append(host)
    return hosts


def execution_is_stale(execution):
    if execution.return_code is not None:
        return False
    started = execution.executed_at
    return started is None or utcnow() - started > EXECUTION_STALE_AFTER


def is_retryable(execution):
    """Whether a step may be approved again.

    A step that never finished or finished badly may be re-run; a successful one
    may not, so the audit trail stays append-only in the case that matters. This
    is the single source of truth for that verdict, shared by the full execution
    serializer and the lightweight workspace snapshot so the two cannot drift on
    what counts as a successful terminal state.
    """
    return outcome(execution.tool_name, execution.return_code, execution.stderr, execution.state) not in SUCCESS \
        and (execution.return_code is not None or execution_is_stale(execution))


def serialize_execution(row):
    return {
        'state': outcome(row.tool_name, row.return_code, row.stderr, row.state), 'plan_version': row.plan_version, 'id': row.id, 'step_index': row.step_index, 'tool_name': row.tool_name, 'command': row.command,
        'stdout': row.stdout, 'stderr': row.stderr, 'return_code': row.return_code,
        'duration_ms': row.duration_ms, 'approved_by_user': row.approved_by_user,
        'attempt': row.attempt or 1, 'executed_at': row.executed_at,
        'complete': row.return_code is not None,
        # Where the command physically ran (the Kali VM attestation when VM
        # mode is active) so the UI and report can state it per step.
        'execution_host': row.execution_host,
        'retryable': is_retryable(row),
    }


def serialize_finding(row):
    # The scoring drivers and location fields are persisted so the UI and the
    # report can explain *why* a finding scored the way it did and where it
    # lives, instead of making the reader re-derive both from raw evidence.
    return {
        'fingerprint': row.fingerprint, 'phase': row.phase, 'id': row.id, 'title': row.title, 'description': row.description, 'severity': row.severity,
        'evidence': row.evidence, 'remediation': row.remediation,
        'risk_score': row.risk_score, 'priority_score': row.priority_score, 'confidence_score': row.confidence_score,
        'endpoint': row.endpoint or '', 'parameter': row.parameter or '',
        'exploitability': row.exploitability or 3, 'impact': row.impact or 3, 'exposure': row.exposure or 3,
        'source_tools': row.source_tools,
        # The exploitation-phase outcome: '' (not attempted), 'attempted',
        # 'verified', or 'refuted', with the proof and the tools that
        # produced it.
        'verification': row.verification or '', 'exploit_evidence': row.exploit_evidence or '',
        'verified_by': row.verified_by or [],
    }


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
        db.flush()
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
        # Steps default to the recon phase: an untagged step belongs to the
        # phase the assessment started with, so older plans and operator-added
        # commands read as recon without a schema bump.
        item.setdefault('phase', 'recon')
        if item['phase'] not in ALL_PLAN_PHASES:
            raise HTTPException(422, "Plan step phase is not a real plan phase: " + str(item['phase']))
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


def remote_execution_settings(settings):
    """The Kali VM SSH settings when VM mode is active, else None.

    Failing closed: an incompletely configured VM is reported as an error by
    the caller rather than silently falling back to local execution, which
    would put scanner commands on a host the operator did not choose.
    """
    if (settings.execution_mode or 'local') != 'kali_vm':
        return None
    return {
        'host': (settings.ssh_host or '').strip(),
        'port': settings.ssh_port or 22,
        'username': (settings.ssh_username or '').strip(),
        'password': decrypt_secret(settings.ssh_password),
        'fingerprint': settings.ssh_fingerprint or '',
        'private_key': decrypt_secret(settings.ssh_private_key),
        'key_passphrase': decrypt_secret(settings.ssh_key_passphrase),
    }


def report_path(assessment_id):
    return REPORTS_DIR / f'report_{assessment_id}.html'


def _ensure_operator_key_at_startup():
    """Generate (once) and announce the operator API key.

    Runs at import time, the same pattern database.py uses for migrations.
    When REDTEAM_API_KEY is set, nothing is generated and the env var is the
    key - that is the documented path for Docker, CI and the scripted flows,
    and the recovery path for a generated key nobody wrote down.
    """
    if (os.getenv(API_KEY_ENV_VAR) or '').strip():
        return
    db = SessionLocal()
    try:
        plaintext = ensure_operator_key(db)
    finally:
        db.close()
    if plaintext:
        # The only place the plaintext ever appears. Not logged again, not
        # written to disk, not returned by any endpoint.
        print('=' * 72)
        print('Operator API key (shown once, copy it into the UI now):')
        print(f'  {plaintext}')
        print(f'Lost it? Set {API_KEY_ENV_VAR} in the environment to choose a new one.')
        print('=' * 72)




def invalidate_analysis(db, assessment_id, phase=None):
    """Drop findings (and the rendered report) for an assessment.

    With `phase`, only that phase's findings are dropped: re-running or
    re-analyzing one phase's steps invalidates that phase's findings, while
    earlier phases' findings — the evidence the later phases were planned
    from — survive. The report always goes, since it describes the whole
    finding set.
    """
    query = db.query(Finding).filter(Finding.assessment_id == assessment_id)
    # The finding-bearing phases in engagement order. ALL_PLAN_PHASES extends
    # this through the lab-only campaign phases, so executing a
    # credential-validation step invalidates that phase and the ones after it
    # rather than falling through to "every phase" and wiping the very analysis
    # the campaign phase was drafted from.
    order = list(ALL_PLAN_PHASES)
    affected = order[order.index(phase):] if phase in order else order
    if phase:
        query = query.filter(Finding.phase.in_(affected))
    assessment = db.get(Assessment, assessment_id)
    if assessment:
        assessment.analyzed_phases = [p for p in (assessment.analyzed_phases or []) if p not in affected]
        assessment.analysis_metadata = {}
        assessment.current_report_version_id = None
    query.delete()
    if phase in (None, 'recon', 'exploitation'):
        # Proof derived from a replaced exploitation run is no longer current.
        db.query(Finding).filter(Finding.assessment_id == assessment_id).update(
            {Finding.verification: '', Finding.exploit_evidence: '', Finding.verified_by: []},
            synchronize_session='fetch')
    retire_current_file(db, report_path(assessment_id))


def authorized_scopes_for(target):
    return target.authorized_scopes or [target.scope_domain_ip]


def restricted_tools_for(target):
    return set(target.restricted_tools or [])


def aggressive_lab(target):
    """True when this target walks the full kill chain.

    Aggressive lab mode is a superset of controlled exploitation: it can only be
    on when the letter authorizes exploitation, so this single flag decides both
    the phase chain and the policy engine's aggressive allowlist.
    """
    return bool(target.exploitation_authorized and target.aggressive_lab)


def campaign_evidence(db, assessment_id):
    """The footholds, loot and discovered hosts as serialized views.

    Secrets are never in these views: serialize_loot exposes a fingerprint and a
    masked placeholder only, so an API response or a planner input can never
    carry a recovered credential.
    """
    return {
        'footholds': [footholds.serialize_foothold(row) for row in footholds.footholds_for(db, assessment_id, state=None)],
        'loot': [footholds.serialize_loot(row) for row in footholds.loot_for(db, assessment_id)],
        'hosts': [footholds.serialize_host(row) for row in footholds.hosts_for(db, assessment_id)],
    }


def ingest_execution_evidence(db, execution):
    """Persist everything one finished execution proves about the campaign.

    Idempotent, and bounded by the module's own caps. A parser bug or an
    unexpected output shape can only fail to record evidence, never invent it,
    because every parser returns nothing unless it matched a known pattern.
    """
    if execution is None or execution.return_code is None:
        return {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0}
    return footholds.ingest_execution(db, execution.assessment_id, execution)


def ingest_execution_evidence_in_session(assessment_id, execution_id, sessions=None):
    """ingest_execution_evidence in its own session, for the job runner.

    The job runner has already closed the session it finalized the execution
    row in, so the evidence pass opens its own. A failure here is logged, never
    raised: the command itself succeeded, its transcript is already stored, and
    a derived-evidence problem must not turn a successful run into an error.
    """
    db = (sessions or SessionLocal)()
    try:
        assessment = db.get(Assessment, assessment_id)
        if assessment is None:
            return {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0}
        claim_workflow(db, assessment, allow_running=True)
        result = ingest_execution_evidence(db, db.get(ToolExecution, execution_id))
        db.commit()
        return result
    except Exception:
        db.rollback()
        logger.exception('evidence_ingest_failed', extra={'assessment_id': assessment_id,
                                                          'execution_id': execution_id})
        return {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0}
    finally:
        db.close()


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


def phase_steps(row):
    """The plan indices belonging to the assessment's current phase."""
    return [index for index, step in enumerate(row.plan or [])
            if step.get('phase', 'recon') == (row.current_phase or 'recon')]


def phase_steps_all(row, phase):
    return [index for index, step in enumerate(row.plan or [])
            if step.get('phase', 'recon') == phase]


def enabled_phase_steps(row):
    return [index for index in phase_steps(row)
            if (row.plan or [])[index].get('enabled', True)]


def refresh_assessment_status(db, row, extra_executed=()):
    enabled = enabled_phase_steps(row)
    executed = {
        execution.step_index
        for execution in db.query(ToolExecution).filter(ToolExecution.assessment_id == row.id, ToolExecution.return_code.is_not(None)).all()
    } | set(extra_executed) | framework.skipped_indices(db, row)
    # 'running' must not stick between steps: once a command returns, the
    # assessment is idle again and waiting on the next human approval. Scope
    # is the CURRENT phase only: later phases are drafted later, and an
    # earlier phase's complete step count says nothing about this one.
    row.status = 'ready_for_analysis' if enabled and all(index in executed for index in enabled) else 'awaiting_approval'
    return row.status


def reconcile_running_status(db, row, executions):
    """Move an assessment off 'running' when nothing is actually running.

    Interrupted runs are normally reclaimed by the job runner's heartbeat expiry
    (modules/jobs.py: an execution whose worker lease goes stale is marked
    'interrupted' with return_code -1). But a hard restart of the server kills
    the request without running anything at all, leaving status='running' and a
    NULL return code behind. Once that row is old enough that the command cannot
    still be alive, the state is stale rather than in-progress, and the UI would
    otherwise report the run as ongoing forever with no way to clear it.
    """
    if row.status != 'running':
        return False
    if any(execution.return_code is None and not execution_is_stale(execution) for execution in executions):
        return False
    refresh_assessment_status(db, row)
    db.commit()
    return True


@app.get('/capabilities', dependencies=PROTECTED)
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
    from modules.document_text import extract
    return extract(suffix, content)


@app.post('/requirements/extract', dependencies=PROTECTED)
async def extract_requirements(file: UploadFile = File(...)):
    allowed = {'.txt', '.md', '.pdf', '.docx'}
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in allowed:
        raise HTTPException(415, 'Supported requirement files: .txt, .md, .pdf, .docx')
    content = await read_bounded_upload(file, MAX_REQUIREMENT_BYTES)
    try:
        text = await asyncio.to_thread(extract_upload_text, suffix, content)
    except Exception as exc:
        raise HTTPException(422, f'Could not read requirement file: {exc}')
    if not text:
        raise HTTPException(422, 'Requirement file contains no readable text')
    return {'filename': file.filename, 'text': text[:30000], 'warnings': ['Text was truncated at 30,000 characters; review the original document for omitted rules.'] if len(text) > 30000 else []}


@app.post('/engagement/parse', dependencies=PROTECTED)
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
        text = await asyncio.to_thread(extract_upload_text, suffix, content)
    except Exception as exc:
        raise HTTPException(422, f'Could not read engagement file: {exc}')
    if not text:
        raise HTTPException(422, 'Engagement file contains no readable text')
    engagement = await asyncio.to_thread(parse_engagement, text[:30000])
    if not engagement['targets']:
        raise HTTPException(422, 'No authorized targets could be found in this document; add the target manually instead')
    return {'filename': file.filename, 'engagement': engagement, 'text': text[:30000], 'warnings': ['Text was truncated at 30,000 characters; review the original document for omitted rules.'] if len(text) > 30000 else []}


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/ready')
def readiness(db: Session = Depends(get_db)):
    from sqlalchemy import text
    from database import migration_head
    import time
    try:
        version = db.execute(text('SELECT version_num FROM alembic_version')).scalar()
        if version != migration_head():
            raise ValueError('Migration pending')
        heartbeat = os.getenv('WORKER_HEARTBEAT_FILE')
        if os.getenv('EXECUTION_WORKER_MODE') == 'external' and heartbeat:
            if time.time() - Path(heartbeat).stat().st_mtime > 15:
                raise ValueError('Worker unavailable')
    except Exception:
        raise HTTPException(503, 'Database migration or execution worker is not ready')
    return {'status': 'ready', 'schema': version}


@app.get('/settings', dependencies=PROTECTED)
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
        # The username reloads into the form but its password never does, so
        # without this flag a stored password is indistinguishable from a
        # never-entered one once the page reloads.
        'proxy_password_configured': bool(decrypt_secret(row.proxy_password)),
        'ssh_password_configured': bool(decrypt_secret(row.ssh_password)),
        # A key with no endpoint or model cannot reach a provider, so the UI is
        # told the difference between "configured" and "partly filled in".
        'provider_ready': bool(stored_key and base_url and model_name),
        'api_base_url': row.api_base_url or '',
        'model_name': row.model_name or '',
        'proxy_url': row.proxy_url or '',
        'proxy_username': row.proxy_username or '',
        'execution_mode': row.execution_mode or 'local',
        'ssh_host': row.ssh_host or '',
        'ssh_port': row.ssh_port or 22,
        'ssh_username': row.ssh_username or '',
        'ssh_fingerprint': row.ssh_fingerprint or '',
        'ssh_private_key_configured': bool(decrypt_secret(row.ssh_private_key)),
    }


@app.put('/settings', dependencies=PROTECTED)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    row = get_settings_row(db)
    if payload.api_base_url is not None:
        previous_url = (row.api_base_url or '').strip().rstrip('/')
        next_url = payload.api_base_url.strip().rstrip('/')
        # A saved credential belongs to its endpoint. Switching presets (or
        # disabling the provider) must never forward the old key elsewhere.
        # The loop below can install a new key in the same transaction.
        if next_url != previous_url or not next_url:
            row.gemini_api_key = ''
    host_changed = (payload.ssh_host is not None and payload.ssh_host != row.ssh_host) or (payload.ssh_port is not None and payload.ssh_port != row.ssh_port)
    if host_changed:
        row.ssh_fingerprint = ''
    for key, value in payload.model_dump(exclude_unset=True).items():
        if host_changed and key == 'ssh_fingerprint':
            continue
        if value is None or (value == '' and key in SECRET_SETTING_FIELDS):
            continue
        setattr(row, key, encrypt_secret(value) if key in SECRET_SETTING_FIELDS else value)
    # Credentials with no proxy to authenticate against are dead weight, and
    # keeping a password that can never be cleared is worse than useless.
    if not (row.proxy_url or '').strip():
        row.proxy_username = ''
        row.proxy_password = ''
    # Same rule for the VM: no host means the stored credentials can never be
    # used, so they do not linger in the database.
    if not (row.ssh_host or '').strip():
        row.ssh_username = ''
        row.ssh_password = ''
        row.ssh_private_key = ''
        row.ssh_key_passphrase = ''
        row.ssh_fingerprint = ''
    db.commit()
    return get_settings(db)


@app.post('/settings/ssh-fingerprint', dependencies=PROTECTED)
def inspect_ssh_fingerprint(db: Session = Depends(get_db)):
    from modules.ssh_executor import ssh_executor
    settings = get_settings_row(db)
    if not settings.ssh_host:
        raise HTTPException(409, 'Save the SSH host first')
    try:
        return ssh_executor.inspect_fingerprint({'host': settings.ssh_host, 'port': settings.ssh_port or 22})
    except Exception as exc:
        raise HTTPException(502, 'Could not complete SSH host-key discovery') from exc


@app.post('/settings/ssh-test', dependencies=PROTECTED)
def test_ssh_connection(db: Session = Depends(get_db)):
    """Connect to the configured Kali VM and report what is actually there.

    The operator sees the machine's real identity (OS, kernel, SSH host-key
    fingerprint) and which tools are installed before approving any command -
    and the tmux session the framework will type into is created, so the VM
    console can attach to it right away. Tests the SAVED SSH fields regardless
    of the execution mode, so the VM can be verified before switching to it.
    """
    settings = get_settings_row(db)
    remote = {
        'host': (settings.ssh_host or '').strip(),
        'port': settings.ssh_port or 22,
        'username': (settings.ssh_username or '').strip(),
        'password': decrypt_secret(settings.ssh_password),
        'fingerprint': settings.ssh_fingerprint or '',
        'private_key': decrypt_secret(settings.ssh_private_key),
        'key_passphrase': decrypt_secret(settings.ssh_key_passphrase),
    }
    if not (remote['host'] and remote['username'] and (remote['password'] or remote.get('private_key'))):
        raise HTTPException(409, 'Save the Kali VM host, username, and password first')
    # Lazy so a deployment without paramiko still serves every other endpoint.
    try:
        from modules.ssh_executor import ssh_executor
    except ImportError as exc:
        raise HTTPException(503, f'SSH support is not installed on the backend: {exc}')
    try:
        return ssh_executor.test_connection(remote)
    except Exception as exc:
        detail = str(exc) or type(exc).__name__
        raise HTTPException(502, f'Could not reach the Kali VM ({remote["host"]}:{remote["port"]}): {detail}')


@app.post('/targets/', dependencies=PROTECTED)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    primary_scope = payload.scope_domain_ip.strip()
    # Re-registering an address that is already on file must not fork a second
    # target: the letter-import path can be re-run, and a duplicate row would
    # leave two targets answering to the same scope with different letter
    # restrictions. The existing target is returned with a flag so the caller
    # can say it was already registered.
    existing = db.query(Target).filter(Target.scope_domain_ip == primary_scope).first()
    if existing:
        result = serialize_target(existing)
        result['already_registered'] = True
        return result
    scopes = [scope.strip() for scope in payload.authorized_scopes if scope and scope.strip()] or [primary_scope]
    # A restriction can only bind tools the framework is able to run, so names
    # outside the policy registry are dropped here rather than refused - a
    # misparsed letter should not block target registration.
    runnable = set(policy_engine.tool_registry())
    restricted = [tool for tool in dict.fromkeys(payload.restricted_tools) if tool in runnable]
    row = Target(name=payload.name.strip(), scope_domain_ip=primary_scope, authorized_scopes=scopes, criticality=payload.criticality, restricted_tools=restricted, exploitation_authorized=payload.exploitation_authorized, aggressive_lab=bool(payload.aggressive_lab and payload.exploitation_authorized), engagement_policy=payload.engagement_policy.model_dump(mode='json') if 'engagement_policy' in payload.model_fields_set else {})
    db.add(row)
    db.commit()
    db.refresh(row)
    return serialize_target(row)


@app.get('/targets/', dependencies=PROTECTED)
def get_targets(db: Session = Depends(get_db)):
    return [serialize_target(row) for row in db.query(Target).all()]


@app.post('/assessments/', dependencies=PROTECTED)
def create_assessment(payload: AssessmentCreate, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    for criterion in (payload.engagement_brief or {}).get('success_criteria', []):
        endpoint = criterion['endpoint']
        if criterion['kind'] == 'tcp_service':
            endpoint = f"[{endpoint}]:{criterion['port']}" if ':' in endpoint else f"{endpoint}:{criterion['port']}"
        if not policy_engine.validate_target(endpoint, authorized_scopes_for(target)):
            raise HTTPException(403, 'The success criterion endpoint is outside the authorized scope')
        if any(scopes_overlap(endpoint, excluded) for excluded in (target.engagement_policy or {}).get('excluded_scopes', [])):
            raise HTTPException(403, 'The success criterion endpoint is excluded by the engagement')
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
    # An exploitation-grade step (sqlmap, msfconsole, or curl carrying a
    # request body) is dropped here for exactly the reason the policy engine
    # refuses it at approval time: the letter did not authorize controlled
    # exploitation against this target. Same pattern as the restricted-tool
    # filter, so the operator sees the count instead of a surprise 403 later.
    if not target.exploitation_authorized and plan:
        gated = 0
        kept = []
        for step in plan:
            tool = step.get('tool')
            is_gated = tool in EXPLOITATION_GATED_TOOLS
            if not is_gated and tool == 'curl':
                try:
                    tokens = shlex.split(step.get('command') or '', posix=True)
                except ValueError:
                    tokens = []
                is_gated = any(token.split('=', 1)[0] in
                               {'-d', '--data', '--data-ascii', '--data-binary', '--data-raw',
                                '--data-urlencode', '-F', '--form', '--form-string', '--json'}
                               for token in tokens[1:])
            if is_gated:
                gated += 1
                continue
            kept.append(step)
        plan = kept
        dropped += gated
    if not plan and payload.plan:
        # The operator supplied a plan and every step of it was dropped by
        # the letter's gates: a plan-shaped 403 reads better than an empty
        # plan failing later with a generic 422.
        raise HTTPException(403, "Every step of the supplied plan was refused: the client's engagement letter does not authorize controlled exploitation against this target, and the policy engine refused each command")
    plan = normalize_plan(plan)
    row = Assessment(target_id=payload.target_id, objective=payload.objective, plan=plan, engagement_brief=payload.engagement_brief, status='awaiting_approval', current_phase='recon', analyzed_phases=[])
    db.add(row)
    db.commit()
    db.refresh(row)
    result = serialize_assessment(row)
    result['plan_source'] = source
    result['restricted_steps_dropped'] = dropped
    return result


@app.get('/assessments/', dependencies=PROTECTED)
def get_assessments(db: Session = Depends(get_db)):
    return [serialize_assessment(row) for row in db.query(Assessment).order_by(Assessment.id.desc()).all()]


@app.get('/assessments/{assessment_id}', dependencies=PROTECTED)
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).order_by(ToolExecution.step_index).all()
    reconcile_running_status(db, row, executions)
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    result = serialize_assessment(row)
    result['executions'] = [serialize_execution(execution) for execution in executions]
    result['discovered_hosts'] = discovered_hosts_for(executions)
    result['findings'] = [serialize_finding(finding) for finding in findings]
    result['objective_result'] = objective_result(db, row)
    return result


def running_executions(db, assessment_ids=None):
    """Execution rows a command is still writing to, stale ones excluded.

    A row with a NULL return code that is older than the executor's timeout
    belongs to a dead run and may be cleaned up with its assessment; a fresh
    one is a live command whose completion write would resurrect rows the
    operator just asked to delete.
    """
    query = db.query(ToolExecution).filter(ToolExecution.return_code.is_(None))
    if assessment_ids is not None:
        query = query.filter(ToolExecution.assessment_id.in_(assessment_ids))
    return [row for row in query.all() if not execution_is_stale(row)]


def delete_assessment_rows(db, row):
    """Drop one assessment with everything derived from it."""
    # Campaign credentials reference footholds, so remove them in that order.
    # Other campaign inventories must not retain a link to a deleted child.
    for model in (Loot, Foothold, EngagementHost):
        db.query(model).filter(model.assessment_id == row.id).delete(synchronize_session=False)
    db.query(EngagementHost).filter_by(child_assessment_id=row.id).update(
        {'child_assessment_id': None}, synchronize_session=False)
    for version in db.query(ReportVersion).filter_by(assessment_id=row.id).all():
        Path(version.path).unlink(missing_ok=True)
    for model in (FrameworkEvent, ExecutionAttempt, FindingReview, ReportVersion, RecommendationTask):
        db.query(model).filter(model.assessment_id == row.id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.assessment_id == row.id).delete(synchronize_session=False)
    db.query(ToolExecution).filter(ToolExecution.assessment_id == row.id).delete(synchronize_session=False)
    db.query(Recommendation).filter(Recommendation.assessment_id == row.id).delete(synchronize_session=False)
    report_path(row.id).unlink(missing_ok=True)
    db.delete(row)


@app.delete('/assessments/{assessment_id}', dependencies=PROTECTED)
def delete_assessment(assessment_id: int, db: Session = Depends(get_db)):
    """Remove one assessment so its run does not crowd the workspace.

    Everything the assessment produced goes with it - executions, findings and
    the rendered report - but the registered target stays, because the target
    is the client's asset record, not this run's output.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if running_executions(db, [assessment_id]):
        raise HTTPException(409, 'A command of this assessment is still executing; wait for it to finish or time out before deleting it')
    if db.query(Assessment.id).filter_by(parent_assessment_id=assessment_id).first():
        raise HTTPException(409, 'Delete this assessment\'s child assessments first, or clear the entire workspace')
    delete_assessment_rows(db, row)
    db.commit()
    return {'message': 'Assessment deleted', 'deleted': assessment_id}


@app.get('/assessments/{assessment_id}/discovered-hosts', dependencies=PROTECTED)
def get_discovered_hosts(assessment_id: int, db: Session = Depends(get_db)):
    """Expose nmap inventory without authorizing any follow-up scan."""
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(
        ToolExecution.assessment_id == assessment_id,
        ToolExecution.return_code.is_not(None),
    ).all()
    return {'assessment_id': assessment_id, 'target_id': row.target_id, 'hosts': discovered_hosts_for(executions)}


@app.put('/assessments/{assessment_id}/plan', dependencies=PROTECTED)
def update_plan(assessment_id: int, payload: PlanUpdate, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if row.scenario:
        raise HTTPException(409, 'Scenario plans are immutable; publish a new scenario version or create a retest')
    # The freeze is per step now that phases append: an executed step is an
    # audit fact and keeps its tool, command, and position, while unexecuted
    # steps (including whole not-yet-run phases) stay fully editable. This is
    # what lets the operator add a payload module step while phase 1's
    # recorded output stays immutable.
    executed_indices = {
        execution.step_index
        for execution in db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).all()
    }
    if payload.plan_version is not None and payload.plan_version != row.plan_version:
        raise HTTPException(409, 'The plan changed in another session; reload before saving')
    previous = row.plan or []
    normalized = normalize_plan(payload.plan)
    if any(index >= len(normalized) for index in executed_indices):
        raise HTTPException(409, 'Executed steps cannot be removed from the plan')
    for index in sorted(executed_indices):
        old, new = previous[index], normalized[index]
        if any(old.get(key, 'recon' if key == 'phase' else True if key == 'enabled' else '') != new.get(key, 'recon' if key == 'phase' else True if key == 'enabled' else '') for key in ('tool', 'command', 'phase', 'enabled')):
            raise HTTPException(409, 'Executed steps cannot be edited; re-approving a failed step reuses its own row')
    expected_version = row.plan_version or 1
    claim_workflow(db, row)
    claimed = db.query(Assessment).filter_by(id=row.id, plan_version=expected_version).filter(Assessment.status != 'running').update(
        {'plan_version': expected_version + 1}, synchronize_session=False)
    if not claimed:
        db.rollback()
        raise HTTPException(409, 'The assessment changed or is running; reload before editing')
    row.plan_version = expected_version + 1
    row.plan = normalized
    # Compare execution-bearing fields by position. Editing an unexecuted
    # later phase must not erase the earlier analysis it requires to run.
    # Reasons and other display metadata do not change scanner evidence.
    def execution_fields(step):
        if step is None:
            return None
        return (step['tool'], step['command'], step.get('phase', 'recon'), step.get('enabled', True))
    affected = set()
    for index in range(max(len(previous), len(normalized))):
        old = previous[index] if index < len(previous) else None
        new = normalized[index] if index < len(normalized) else None
        if execution_fields(old) != execution_fields(new):
            affected.update(step.get('phase', 'recon') for step in (old, new) if step is not None)
    if affected:
        row.status = 'awaiting_approval'
        earliest = next(phase for phase in ALL_PLAN_PHASES if phase in affected)
        invalidate_analysis(db, assessment_id, phase=earliest)
    elif normalized != previous:
        # A rationale edit needs a fresh report, but its analyzed evidence
        # remains valid. An unchanged save keeps the existing report usable.
        if row.status == 'reported':
            row.status = 'analyzed'
        row.current_report_version_id = None
        retire_current_file(db, report_path(assessment_id))
    db.commit()
    return serialize_assessment(row)


def try_draft_campaign_phase(db, row, target, phase):
    """Draft a lab-only kill-chain phase from the campaign evidence so far.

    The evidence is read in serialized form, so a planner never sees a
    plaintext secret: it writes a placeholder and the execute path resolves it
    at run time. Returns (steps, notes) like the base planner path.
    """
    evidence = campaign_evidence(db, row.id)
    findings = [serialize_finding(f) for f in db.query(Finding)
                .filter(Finding.assessment_id == row.id)
                .order_by(Finding.priority_score.desc()).all()]
    return campaign_planner.draft_plan(
        phase, findings, target.scope_domain_ip, authorized_scopes_for(target),
        aggressive=True, loot=evidence['loot'],
        footholds=evidence['footholds'], hosts=evidence['hosts'])


def try_draft_phase(db, row, target, phase):
    """The drafting core shared by the phase-plan endpoint and the auto-draft.

    Returns (steps, notes, refusal):
      steps    - the drafted plan steps, or None when drafting was refused
      notes    - planner notes on success, the human-readable refusal reason
                 otherwise
      refusal  - None on success, else a key into DRAFT_REFUSALS

    The phase list is mode-aware: a target without aggressive lab mode can only
    ever draft the base phases, so the extended kill chain is unreachable for a
    production engagement exactly like the tools it drives.
    """
    if row.scenario:
        return None, 'Scenario plans are immutable; their next phase is already defined', 'order'
    aggressive = aggressive_lab(target)
    phases = plan_phases(aggressive)
    phase = validate_phase(phase, aggressive)
    if phase not in phases:
        return None, f'Phase must be one of {", ".join(phases)}', 'invalid_phase'
    current = row.current_phase or 'recon'
    # A phase may only be drafted when the assessment sits at the phase that
    # precedes it OR has already advanced into it (analysis of the preceding
    # phase advances current_phase to the next bookkeeping state, so drafting
    # the newly unlocked phase means drafting the phase we are "in").
    order = {p: i for i, p in enumerate(phases)}
    if order[phase] not in (order.get(current, 0), order.get(current, 0) + 1):
        return None, f'Phase {phase.replace("_", " ")} cannot be drafted while the assessment is in the {current.replace("_", " ")} phase', 'order'
    required_analysis = preceding_plan_phase(phase, aggressive)
    if required_analysis is None:
        return None, 'Reconnaissance is drafted when the assessment is created; edit its existing plan instead', 'order'
    if required_analysis not in (row.analyzed_phases or []):
        return None, f'Analyze the {required_analysis.replace("_", " ")} phase results before drafting the {phase.replace("_", " ")} plan', 'analysis'
    if phase_steps_all(row, phase):
        # A drafted phase is append-only like the rest of the plan: its steps
        # exist, are awaiting approval or already executed, and a re-draft
        # would orphan them.
        return None, f'The {phase.replace("_", " ")} phase has already been drafted; edit or add steps in the plan instead', 'already_drafted'
    if phase == 'exploitation' and not target.exploitation_authorized:
        return None, "The client's engagement letter does not authorize controlled exploitation against this target", 'unauthorized'

    if aggressive:
        steps, notes = try_draft_campaign_phase(db, row, target, phase)
    else:
        findings = [serialize_finding(f) for f in db.query(Finding)
                    .filter(Finding.assessment_id == row.id)
                    .order_by(Finding.priority_score.desc()).all()]
        verification_endpoints = _verification_endpoints_for(row, target)
        steps, notes = exploit_planner.draft_plan(
            phase, findings, target.scope_domain_ip,
            authorized_scopes_for(target), verification_endpoints=verification_endpoints,
            aggressive=False)
    if not steps:
        # Nothing draftable is a legitimate outcome (a clean target has
        # nothing to exploit, an engagement with no recovered credential has
        # nothing to validate), but it must be reported rather than silently
        # leaving the phase empty.
        return None, (' | '.join(notes) or 'No steps could be drafted for this phase'), 'nothing_draftable'
    return steps, notes, None


@app.post('/assessments/{assessment_id}/phases/{phase}/plan', dependencies=PROTECTED)
def draft_phase_plan(assessment_id: int, phase: str, db: Session = Depends(get_db)):
    """Draft the next engagement phase's steps from the current findings.

    The lifecycle is strictly sequential: each phase's plan is drafted from
    the previous phase's ANALYZED findings, so an exploitation step can only
    exist because vulnerability analysis actually produced something to
    verify. Drafting also refuses (403) an exploitation phase for a target
    whose letter did not authorize controlled exploitation - the same gate
    the execute endpoint enforces, applied before a single command is
    proposed.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    steps, notes, refusal = try_draft_phase(db, row, target, phase)
    if refusal == 'invalid_phase':
        raise HTTPException(422, notes)
    if refusal == 'order':
        raise HTTPException(409, notes)
    if refusal == 'analysis':
        raise HTTPException(409, notes)
    if refusal == 'already_drafted':
        raise HTTPException(409, notes)
    if refusal == 'unauthorized':
        raise HTTPException(403, notes)
    if refusal == 'nothing_draftable':
        raise HTTPException(422, notes)

    claim_workflow(db, row)
    row.current_report_version_id = None

    # Copy before extending: row.plan is the loaded JSON object, and mutating
    # it in place would also mutate SQLAlchemy's snapshot of the committed
    # value, so the change-detection at flush would see no difference and
    # silently persist nothing. A copy makes the assignment a real change.
    plan = list(row.plan or []) + steps
    row.plan = normalize_plan(plan)
    row.plan_version = (row.plan_version or 1) + 1
    row.current_phase = phase
    row.status = 'awaiting_approval'
    # The report is invalidated (it describes the whole finding set, and the
    # engagement is not finished), but the findings are NOT: they are the
    # evidence this phase's plan was drafted from and the next phase's input.
    retire_current_file(db, report_path(assessment_id))
    db.commit()
    result = serialize_assessment(row)
    result['drafted_steps'] = len(steps)
    result['planner_notes'] = notes
    return result


def _verification_endpoints_for(row, target):
    """The letter-declared verification endpoint paths for this target.

    The parsed engagement brief carries them per target; the exploit planner
    turns each into a curl proof-of-concept step.
    """
    brief = row.engagement_brief if isinstance(row.engagement_brief, dict) else {}
    for entry in brief.get('targets') or []:
        address = (entry.get('address') or '').strip()
        if address and address.split(':')[0] == (target.scope_domain_ip or '').split(':')[0]:
            return [str(path) for path in (entry.get('verification_endpoints') or [])]
    return []


def gather_proposal_inputs(db, row, target):
    """Everything `next_steps_planner.propose` needs, read from the database.

    Shared by the operator-driven /next-steps endpoint and the automatic
    post-execution loop so both reason from byte-identical engagement state.
    """
    findings = [
        {**serialize_finding(finding), 'phase': finding.phase}
        for finding in db.query(Finding).filter(Finding.assessment_id == row.id)
            .order_by(Finding.priority_score.desc()).all()
    ]
    executions = [
        {'step_index': execution.step_index, 'tool_name': execution.tool_name,
         'command': execution.command, 'return_code': execution.return_code}
        for execution in db.query(ToolExecution)
            .filter(ToolExecution.assessment_id == row.id,
                    ToolExecution.return_code.is_not(None))
            .order_by(ToolExecution.step_index).all()
    ]
    settings = get_settings_row(db)
    api_key, base_url, model_name = provider_credentials(settings)
    # The post-compromise evidence is part of the engagement state the advisor
    # reasons from, in its masked form only.
    evidence = campaign_evidence(db, row.id)
    return {
        'phase': row.current_phase or 'recon',
        'target_address': target.scope_domain_ip,
        'objective': row.objective,
        'criticality': (target.criticality if target.criticality is not None
                        else DEFAULT_ASSET_CRITICALITY),
        'authorized_scopes': authorized_scopes_for(target),
        'restricted_tools': restricted_tools_for(target),
        'exploitation_authorized': bool(target.exploitation_authorized),
        'aggressive_lab': bool(target.exploitation_authorized and target.aggressive_lab),
        'verification_endpoints': _verification_endpoints_for(row, target),
        'findings': findings,
        'executions': executions,
        'loot': evidence['loot'],
        'footholds': evidence['footholds'],
        'hosts': evidence['hosts'],
        'plan': row.plan or [],
        'api_key': api_key,
        'base_url': base_url,
        'model_name': model_name,
    }


def run_proposal(db, row, target):
    """One proposal pass over the current engagement state."""
    inputs = gather_proposal_inputs(db, row, target)
    credentials = {key: inputs.pop(key) for key in ('api_key', 'base_url', 'model_name')}
    inputs = redact(inputs, known_secrets(db, row.id))
    candidates, refused, source, notes = next_steps_planner.propose(**inputs, **credentials)
    return {
        'assessment_id': row.id, 'phase': inputs['phase'], 'source': source,
        'state': {'findings': len(inputs['findings']),
                  'executed_steps': len(inputs['executions']),
                  'plan_steps': len(inputs['plan']),
                  'headroom': MAX_PLAN_STEPS - len(inputs['plan'])},
        'candidates': candidates,
        'refused': refused,
        'notes': notes,
    }


# The automatic recommendation loop's budget: one batch per executed step is
# the natural rate, and this cap is the backstop that keeps a run of failing,
# re-approved commands from manufacturing an endless suggestion stream.
MAX_AUTO_RECOMMENDATIONS = 25
recommendation_tasks = set()


def record_auto_recommendations(assessment_id, trigger_execution_id, sessions=None):
    """Compute and persist the post-execution proposal batch (sync core).

    Runs off the event loop (see schedule_auto_recommendations) in its own
    session, reading only committed state. Every refusal this function can
    meet - wrong phase, mid-flight command, exhausted budget, full plan - is
    a reason to simply not propose, never an error that could disturb the
    engagement the operator just ran.
    """
    db = (sessions or SessionLocal)()
    task = None
    try:
        execution = db.get(ToolExecution, trigger_execution_id) if trigger_execution_id is not None else None
        if execution:
            task = db.query(RecommendationTask).filter_by(execution_id=trigger_execution_id, attempt=execution.attempt).first()
            if task and task.state in {'completed', 'running'}:
                return None
            if task is None:
                task = RecommendationTask(assessment_id=assessment_id, execution_id=trigger_execution_id, attempt=execution.attempt)
                db.add(task)
            task.state = 'running'
            db.commit()
        row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if row is None:
            return None
        current = row.current_phase or 'recon'
        if current not in PROPOSAL_PHASES:
            return None
        if row.status == 'running':
            # Another command is mid-flight; its output is not in the state a
            # proposal should be drawn from.
            return None
        existing = db.query(Recommendation).filter(
            Recommendation.assessment_id == assessment_id).count()
        if existing >= MAX_AUTO_RECOMMENDATIONS:
            return None
        target = db.query(Target).filter(Target.id == row.target_id).first()
        if target is None:
            return None
        if len(row.plan or []) >= MAX_PLAN_STEPS:
            return None
        revision = row.workflow_revision
        payload = run_proposal(db, row, target)
        claim_workflow(db, row, revision)
        record = Recommendation(assessment_id=assessment_id,
                                trigger_execution_id=trigger_execution_id,
                                phase=current, payload=payload, origin='auto')
        db.add(record)
        if task:
            task.state = 'completed'
        db.commit()
        return record.id
    except Exception:
        # The advisor is advisory: a failure here must never surface as an
        # error in the engagement that triggered it.
        db.rollback()
        logger.exception('recommendation_failed', extra={'assessment_id': assessment_id})
        if task:
            task.state, task.detail = 'failed', 'Provider or recommendation processing failed'
            db.commit()
        return None
    finally:
        if task and task.state == 'running':
            task.state, task.detail = 'skipped', 'No eligible phase, plan capacity, or recommendation budget remains'
            db.commit()
        db.close()


def schedule_auto_recommendations(assessment_id, trigger_execution_id, sessions=None):
    """Level 2 of the automatic loop: propose next steps after each execution.

    The proposal may call the AI provider (up to its 60 s timeout), so it runs
    in a worker thread rather than on the event loop - otherwise one slow
    provider answer would freeze every other request, including the live
    terminal the operator is watching.
    """
    task = asyncio.create_task(asyncio.to_thread(
        record_auto_recommendations, assessment_id, trigger_execution_id, sessions))
    recommendation_tasks.add(task)
    task.add_done_callback(recommendation_tasks.discard)
    return task


@app.get('/assessments/{assessment_id}/recommendations', dependencies=PROTECTED)
def get_recommendations(assessment_id: int, db: Session = Depends(get_db)):
    """The automatic recommendation feed for an assessment.

    Newest first, capped. Each batch records which execution triggered it, so
    the UI can match a poll to the step it just ran, and the batches persist
    as engagement evidence: what the system proposed at every juncture,
    including the candidates the policy engine refused with their reasons.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    records = db.query(Recommendation).filter(
        Recommendation.assessment_id == assessment_id
    ).order_by(Recommendation.id.desc()).limit(20).all()
    total = db.query(Recommendation).filter(
        Recommendation.assessment_id == assessment_id).count()
    return {
        'assessment_id': assessment_id,
        'total': total,
        'tasks': [{'execution_id': task.execution_id, 'attempt': task.attempt, 'state': task.state, 'detail': task.detail} for task in db.query(RecommendationTask).filter_by(assessment_id=assessment_id).order_by(RecommendationTask.id.desc()).limit(25).all()],
        'recommendations': [{
            'id': record.id,
            'trigger_execution_id': record.trigger_execution_id,
            'phase': record.phase,
            'origin': record.origin or 'auto',
            'created_at': record.created_at.isoformat() if record.created_at else None,
            **(record.payload or {}),
        } for record in records],
    }


@app.post('/assessments/{assessment_id}/next-steps', dependencies=PROTECTED)
def propose_next_steps(assessment_id: int, db: Session = Depends(get_db)):
    """Propose ranked, policy-checked next steps for the phase in progress.

    Read-only by design: proposals are returned and never persisted. They become
    plan steps only when the operator accepts them through PUT /plan, so
    executed-step immutability, phase tagging, and plan validation keep living in
    exactly one place. What changes is what the human is deciding on — reasoned
    options drawn from what has actually been observed, instead of a list frozen
    before the first command ran.

    Every candidate is re-validated by the policy engine against the same scopes
    and the same exploitation gate the execute endpoint applies, and candidates
    are refused rather than silently dropped: `refused` is the guardrail's
    receipt, and it is part of what the operator is shown.

    With no AI provider configured the question is still answered, from the
    framework's deterministic generators minus whatever has already been run.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    current = row.current_phase or 'recon'
    if current not in PROPOSAL_PHASES:
        raise HTTPException(409, PHASE_PROPOSAL_REFUSALS.get(
            current, 'This phase cannot receive proposals.'))
    if row.status == 'running':
        # A command is mid-flight and its output is not yet in the state the
        # proposals would be drawn from; proposing now would reason about a
        # half-written engagement.
        raise HTTPException(409, 'A step is currently executing; wait for it to finish before proposing more')
    plan = row.plan or []
    if len(plan) >= MAX_PLAN_STEPS:
        raise HTTPException(409, f'The plan is already at its {MAX_PLAN_STEPS}-step limit; no further steps can be added')

    return run_proposal(db, row, target)


@app.get('/assessments/{assessment_id}/phases', dependencies=PROTECTED)
def get_phase_overview(assessment_id: int, db: Session = Depends(get_db)):
    """Phase progress for the stepper: per-phase step counts and analysis state."""
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id, ToolExecution.return_code.is_not(None)).all()
    executed = {execution.step_index for execution in executions}
    target = db.query(Target).filter(Target.id == row.target_id).first()
    aggressive = bool(target and aggressive_lab(target))
    phases = []
    for phase in plan_phases(aggressive):
        indices = phase_steps_all(row, phase)
        enabled = [i for i in indices if (row.plan or [])[i].get('enabled', True)]
        complete = [i for i in enabled if i in executed]
        phases.append({
            'phase': phase, 'label': PHASE_LABELS[phase],
            'steps': len(indices), 'executed': len(complete),
            'analyzed': phase in (row.analyzed_phases or []),
        })
    overview = {'assessment_id': assessment_id, 'current_phase': row.current_phase or 'recon',
                'phases': phases, 'all_phases': phase_chain(aggressive), 'labels': PHASE_LABELS,
                'aggressive_lab': aggressive, 'status': row.status}
    return overview


def resolve_step_command(db, assessment_id, command):
    """The concrete command an execution runs, and the masked form to store.

    A planner-authored step carries $loot:<id>$ / $foothold:<id>$
    placeholders instead of the values they stand for, so a recovered secret
    never reaches the plan, the audit trail, or an API response. Resolution
    happens here, at the last moment before validation and execution: the
    concrete form is what the policy engine sees and what the executor runs,
    and only the masked form is ever written down.
    """
    return resolve_references(
        command,
        footholds.loot_for(db, assessment_id),
        footholds.footholds_for(db, assessment_id, state=None),
    )


def enforce_engagement(db, assessment, target, step_index, command, tool):
    """Re-validate one approved step against the engagement, at run time.

    The command passed in is the concrete, resolved form: placeholders are
    expanded before this point so scope checking sees the real destination. The
    re-check is deliberate - the plan was validated at draft time, but the
    engagement window, the scope, and the target's authorization can all have
    changed since, and approval is not a licence to run something the letter no
    longer permits.
    """
    framework.enforce_node(db, assessment, step_index)
    step = assessment.plan[step_index]
    current = assessment.current_phase or 'recon'
    if step.get('phase', 'recon') != current:
        raise HTTPException(409, 'Only steps in the active phase may execute')
    aggressive = aggressive_lab(target)
    prerequisite = preceding_plan_phase(current, aggressive)
    if assessment.scenario:
        phases = list(dict.fromkeys(s['phase'] for s in assessment.plan))
        position = phases.index(current)
        prerequisite = phases[position - 1] if position else None
    if prerequisite and prerequisite not in (assessment.analyzed_phases or []):
        raise HTTPException(409, 'Analyze the preceding phase before executing this phase')
    policy = target.engagement_policy or {}
    if message := check_window(policy):
        raise HTTPException(403, message)
    if tool in set(restricted_tools_for(target)) | set(policy.get('prohibited_tools', [])):
        raise HTTPException(403, f'{tool} is restricted by the engagement letter or reviewed rules')
    valid, reason, capability = policy_engine.validate_command(command, authorized_scopes_for(target),
        expected_tool=tool, allow_exploitation=bool(target.exploitation_authorized),
        aggressive=aggressive)
    if not valid:
        raise HTTPException(403, reason)
    arguments = []
    targets, _, _ = policy_engine.scan_arguments(shlex.split(command), policy_engine.tool_registry()[tool], arguments)
    targets = command_destinations(command, targets)
    if any(scopes_overlap(destination, excluded) for destination in targets for excluded in policy.get('excluded_scopes', [])):
        raise HTTPException(403, 'A command destination is explicitly excluded by the engagement')
    rate_flags = {'nmap': {'--max-rate', '--min-rate'}, 'nuclei': {'-rl', '-rate-limit'}}.get(tool, set())
    if rate_flags:
        rates = [float(value) for flag, value in arguments if flag in rate_flags]
        # Legacy targets without structured policy retain the global policy.
        if policy and (not rates or any(rate > policy.get('max_rate', 30) for rate in rates)):
            raise HTTPException(403, 'Set an explicit scanner rate within the engagement limit')
    return reason, capability


@app.post('/assessments/{assessment_id}/execute', dependencies=PROTECTED)
async def execute_step(assessment_id: int, payload: ExecuteRequest, db: Session = Depends(get_db)):
    row = db.get(Assessment, assessment_id)
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if not payload.approved:
        raise HTTPException(403, 'Explicit human approval is required')
    if payload.step_index >= len(row.plan or []):
        raise HTTPException(400, 'Invalid step index')
    if payload.plan_version is not None and payload.plan_version != row.plan_version:
        raise HTTPException(409, 'The plan changed; reload and review it before approving')
    step = row.plan[payload.step_index]
    if not step.get('enabled', True):
        raise HTTPException(400, 'This step is disabled')
    target = db.get(Target, row.target_id)
    # Resolve placeholders before validation so scope checking sees the real
    # destination, and keep the masked form as the one that is written down.
    concrete_command, masked_command = resolve_step_command(db, row.id, step['command'])
    reason, capability = enforce_engagement(db, row, target, payload.step_index, concrete_command, step['tool'])
    settings = get_settings_row(db)
    remote = remote_execution_settings(settings)
    if remote and not (remote['host'] and remote['username'] and (remote.get('password') or remote.get('private_key'))):
        raise HTTPException(409, 'SSH host, username, or password/private key is not configured')
    if remote and not remote.get('fingerprint'):
        raise HTTPException(409, 'Inspect and trust the SSH fingerprint before approving a command')
    if step['tool'] in VM_ONLY_TOOLS and not remote:
        raise HTTPException(409, f"{step['tool']} runs only on the Kali attacker VM")
    existing = db.query(ToolExecution).filter_by(assessment_id=row.id, step_index=payload.step_index).first()
    if existing and outcome(existing.tool_name, existing.return_code, existing.stderr, existing.state) in SUCCESS:
        raise HTTPException(409, 'This plan step has already been executed')
    if existing and existing.return_code is None and not execution_is_stale(existing):
        raise HTTPException(409, 'This plan step is still executing')
    if db.query(ToolExecution).filter(ToolExecution.state.in_(['queued', 'running'])).count() >= 100:
        raise HTTPException(429, 'Execution queue is full; retry after a job completes')
    budget = (target.engagement_policy or {}).get('max_executions', 100)
    if db.query(ExecutionAttempt).filter_by(assessment_id=row.id).count() >= budget:
        raise HTTPException(403, 'The engagement execution budget is exhausted')
    # Atomically claim the assessment. Two tabs cannot approve concurrent work
    # or both overwrite the same failed attempt.
    claim_workflow(db, row)
    claimed = db.query(Assessment).filter(Assessment.id == row.id,
        Assessment.plan_version == (row.plan_version or 1), Assessment.status != 'running').update(
        {'status': 'running', 'completed_at': None}, synchronize_session=False)
    if not claimed:
        db.rollback()
        raise HTTPException(409, 'Assessment changed or already has an active execution; reload')
    if existing:
        archive_attempt(db, existing)
        execution = existing
        execution.command = masked_command
        execution.attempt = (execution.attempt or 1) + 1
        execution.stdout, execution.stderr = '', ''
        execution.raw_encrypted, execution.evidence_sha256 = '', ''
        execution._protected_projection = {}
        execution.return_code, execution.duration_ms = None, 0
        execution.executed_at = utcnow()
    else:
        execution = ToolExecution(assessment_id=row.id, step_index=payload.step_index,
            tool_name=step['tool'], command=masked_command, approved_by_user=True, attempt=1)
        db.add(execution)
    execution.state, execution.cancel_requested = 'queued', False
    execution.live_output, execution.output_cursor = '', 0
    execution.plan_version = row.plan_version or 1
    framework.event(db, row, 'approval', {'step_index': payload.step_index, 'attempt': execution.attempt,
                                        'plan_version': execution.plan_version})
    invalidate_analysis(db, assessment_id, phase=step.get('phase', 'recon'))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'This step was claimed by another request')
    execution_id = execution.id
    sessions = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    db.close()
    if payload.background or os.getenv('EXECUTION_WORKER_MODE') == 'external':
        return JSONResponse(status_code=202, content={'execution_id': execution_id, 'state': 'queued',
            'status_url': f'/assessments/{assessment_id}/executions/{execution_id}/live'})
    # Compatibility for scripts: new UI uses durable background execution.
    result = await run_execution(execution_id, sessions)
    if result is None:
        return JSONResponse(status_code=202, content={'execution_id': execution_id, 'state': 'queued'})
    return {'message': 'Execution finished', 'policy': reason, 'capability': capability,
            'result': result, 'execution_id': execution_id, 'recommendation_pending': True}


@app.get('/assessments/{assessment_id}/executions/{execution_id}/live', dependencies=PROTECTED)
def get_live_execution(assessment_id: int, execution_id: int, cursor: int = Query(0, ge=0), db: Session = Depends(get_db)):
    row = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Execution not found')
    snapshot = live_registry.snapshot(execution_id)
    output = snapshot['output'] if snapshot else row.live_output or row.stdout or ''
    end = snapshot['cursor'] if snapshot else row.output_cursor or len(output)
    start = end - len(output)
    reset = cursor < start or cursor > end
    offset = start if reset else max(start, cursor)
    return {'execution_id': execution_id, 'attempt': row.attempt, 'running': row.return_code is None,
            'state': outcome(row.tool_name, row.return_code, row.stderr, row.state),
            'command': row.command, 'output': output[offset-start:], 'cursor': end, 'reset': reset,
            'return_code': row.return_code, 'stderr': row.stderr or '', 'started_at': row.executed_at}


@app.post('/assessments/{assessment_id}/executions/{execution_id}/cancel', dependencies=PROTECTED)
def cancel_execution(assessment_id: int, execution_id: int, db: Session = Depends(get_db)):
    row = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Execution not found')
    if row.return_code is not None:
        return {'state': row.state}
    claim_workflow(db, db.get(Assessment, assessment_id), allow_running=True)
    queued = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id, state='queued', return_code=None).update({'state': 'cancelled', 'return_code': -1, 'stderr': 'Cancelled before execution', 'cancel_requested': True}, synchronize_session=False)
    db.expire(row)
    row.cancel_requested = True
    if queued:
        archive_attempt(db, row)
        refresh_assessment_status(db, db.get(Assessment, assessment_id))
    db.commit()
    return {'state': row.state, 'cancel_requested': True}


@app.get('/assessments/{assessment_id}/executions/{execution_id}/attempts', dependencies=PROTECTED)
def execution_attempts(assessment_id: int, execution_id: int, db: Session = Depends(get_db)):
    return [item.snapshot for item in db.query(ExecutionAttempt).filter_by(
        assessment_id=assessment_id, execution_id=execution_id).order_by(ExecutionAttempt.attempt).all()]


@app.post('/assessments/{assessment_id}/analyze', dependencies=PROTECTED)
def analyze_assessment(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if (row.framework_state or {}).get('control') == 'completed':
        raise HTTPException(409, 'Completed campaigns are immutable; create a retest')
    current = row.current_phase or 'recon'
    phase_indices = set(phase_steps(row))
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id, ToolExecution.return_code.is_not(None)).all()
    if not executions:
        raise HTTPException(400, 'Execute at least one approved plan step first')
    skipped = framework.skipped_indices(db, row)
    enabled_steps = {index for index in phase_steps(row) if (row.plan or [])[index].get('enabled', True)}
    executed_steps = {execution.step_index for execution in executions}
    if not enabled_steps:
        raise HTTPException(409, 'The current phase has no enabled steps to analyze; draft the next phase plan first')
    if not enabled_steps.issubset(executed_steps | skipped):
        raise HTTPException(409, 'Execute every enabled step of the current phase before analysis')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    # Only the current phase's executions feed this analysis run: recon
    # output was already analyzed, and re-analyzing it alongside exploitation
    # output would re-file recon findings against the verification state.
    phase_executions = [execution for execution in executions if execution.step_index in phase_indices]
    raw = [{'tool': e.tool_name, 'return_code': e.return_code, **original(e)} for e in phase_executions]
    settings = get_settings_row(db)
    api_key, base_url, model_name = provider_credentials(settings)
    version_at_start = row.plan_version
    revision_at_start = row.workflow_revision
    attempts_at_start = {e.id: e.attempt for e in phase_executions}
    analyzed, analyzer_mode = analyzer_agent.analyze_results(
        redact(raw, known_secrets(db, assessment_id)),
        api_key,
        base_url,
        model_name,
        include_metadata=True,
        asset_criticality=target.criticality if target else None,
    )
    claim_workflow(db, row, revision_at_start)
    latest_attempts = {e.id: e.attempt for e in db.query(ToolExecution).filter(ToolExecution.id.in_(attempts_at_start)).all()}
    claimed = db.query(Assessment).filter_by(id=assessment_id, plan_version=version_at_start, current_phase=current).filter(Assessment.status != 'running').update({'status': 'analyzing'}, synchronize_session=False)
    if not claimed or latest_attempts != attempts_at_start:
        db.rollback()
        raise HTTPException(409, 'Assessment evidence changed during analysis; reload and analyze again')
    # Only the current phase's findings are recomputed; earlier phases'
    # findings survive, because the later phases' plans were drafted from
    # them and the report cites them.
    invalidate_analysis(db, assessment_id, phase=current)
    for item in analyzed:
        db.add(Finding(
            assessment_id=assessment_id, fingerprint=item['fingerprint'],
            title=item.get('title', 'Unknown finding'), description=item.get('description', ''),
            severity=item['severity'], evidence=item.get('evidence', ''),
            remediation=item.get('remediation', ''),
            risk_score=item['risk_score'], priority_score=item['priority_score'],
            confidence_score=item['confidence_score'],
            endpoint=item.get('endpoint', ''), parameter=item.get('parameter', ''),
            exploitability=item.get('exploitability', 3), impact=item.get('impact', 3),
            exposure=item.get('exposure', 3),
            source_tools=item.get('source_tools', []),
            phase=current,
        ))
    db.flush()
    # Verify only evidence parsed independently from successful scanner runs.
    # AI text, version banners and HTTP 200 responses cannot establish proof.
    verified_count = 0
    if current in ('exploitation', 'post_exploitation'):
        all_rows = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
        proofs = analyzer_agent.confirmed_verifications(raw)
        links = match_verification(
            [{'id': f.id, 'endpoint': f.endpoint, 'parameter': f.parameter, 'title': f.title} for f in all_rows],
            proofs)
        prior_index = {f.id: f for f in all_rows}
        verified_ids = set()
        for recon_data, exploit_data, evidence in links:
            row_finding = prior_index.get(recon_data['id'])
            if row_finding is None:
                continue
            row_finding.verification = 'verified'
            if evidence not in (row_finding.exploit_evidence or '').splitlines():
                row_finding.exploit_evidence = ((row_finding.exploit_evidence or '') + '\n' + evidence).strip()[:20000]
            tools = list(row_finding.verified_by or [])
            for tool in exploit_data.get('source_tools') or []:
                if tool not in tools:
                    tools.append(tool)
            row_finding.verified_by = tools
            verified_ids.add(row_finding.id)
        verified_count = len(verified_ids)
        db.flush()
    # Phase bookkeeping: this phase is now analyzed, and the assessment
    # advances to the phase its analysis unlocks (vuln_analysis after recon,
    # post_exploitation after exploitation, reporting after the last).
    # Everything this phase proved about the campaign - footholds, recovered
    # credentials, discovered hosts - is derived from the same output the
    # findings came from. The ingest is idempotent, so the immediate
    # post-execution ingest in the job runner and this pass cannot double-count.
    for execution in phase_executions:
        ingest_execution_evidence(db, execution)

    analyzed_phases = row.analyzed_phases or []
    if current not in analyzed_phases:
        analyzed_phases = analyzed_phases + [current]
    row.analyzed_phases = analyzed_phases
    aggressive = bool(target and aggressive_lab(target))
    advances_to = framework.next_scenario_phase(row, current) if row.scenario else analysis_advances_to(current, aggressive)
    if advances_to and (row.current_phase or 'recon') == current:
        row.current_phase = advances_to
    row.status = 'analyzed'
    row.analysis_mode = analyzer_mode
    from modules.provider import metadata
    row.analysis_metadata = {**metadata(), 'mode': analyzer_mode, 'version': '3.0', 'phase': current, 'plan_version': row.plan_version, 'execution_ids': [e.id for e in phase_executions]}
    row.completed_at = utcnow()
    db.flush()
    # Level 1 of the automatic recommendation loop: the analysis just
    # unlocked the next phase, so draft it immediately instead of waiting
    # for the operator to press the Draft button. Nothing new is authorized:
    # drafting was already policy-gated and every drafted step still waits
    # for its own approval - the operator just no longer has to ask. A
    # refusal is a note, not an error: the operator did not request this
    # draft, so "the letter does not authorize exploitation" is information
    # about the engagement, worth showing, not worth failing the analysis.
    auto_drafted = {'phase': None, 'steps': 0, 'note': ''}
    next_phase = next_draftable_phase(row.current_phase or '', aggressive)
    if next_phase and not row.scenario:
        steps, notes, refusal = try_draft_phase(db, row, target, next_phase)
        if steps:
            row.plan = normalize_plan(list(row.plan or []) + steps)
            row.plan_version = (row.plan_version or 1) + 1
            row.current_phase = next_phase
            row.status = 'awaiting_approval'
            retire_current_file(db, report_path(assessment_id))
            db.flush()
            auto_drafted = {'phase': next_phase, 'steps': len(steps), 'note': ''}
        else:
            auto_drafted = {'phase': next_phase, 'steps': 0, 'note': notes}
    failed = [execution.step_index for execution in phase_executions if outcome(execution.tool_name, execution.return_code, execution.stderr, execution.state) not in SUCCESS]
    db.commit()
    return {'message': 'Analysis complete', 'findings_count': len(analyzed), 'analyzer': analyzer_mode, 'failed_steps': failed, 'phase': current, 'verified_findings': verified_count, 'current_phase': row.current_phase, 'auto_drafted': auto_drafted}


@app.get('/assessments/{assessment_id}/campaign', dependencies=PROTECTED)
def get_campaign(assessment_id: int, db: Session = Depends(get_db)):
    """The engagement's post-compromise state.

    Footholds, recovered loot and discovered hosts, plus the autopilot
    bookkeeping. Secrets are never in this response: a loot row carries a
    fingerprint and a masked placeholder only, and reading the value behind one
    is a separate, audited action.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    aggressive = bool(target and aggressive_lab(target))
    return {
        'assessment_id': assessment_id,
        'current_phase': row.current_phase or 'recon',
        'aggressive_lab': aggressive,
        'campaign_enabled': aggressive,
        'autopilot': bool(row.autopilot),
        'autopilot_iteration_budget': AUTOPILOT_MAX_ITERATIONS,
        'autopilot_state': autopilot_state(row),
        'objective_result': objective_result(db, row),
        **campaign_evidence(db, assessment_id),
    }


@app.post('/assessments/{assessment_id}/autopilot', dependencies=PROTECTED)
def set_autopilot(assessment_id: int, payload: AutopilotUpdate, db: Session = Depends(get_db)):
    """Turn the semi-autonomous loop on or off for one assessment.

    Opt-in and reversible, and it cannot be enabled for a target that is not in
    aggressive lab mode: the loop only ever drafts the lab-only kill chain, so
    enabling it there would be a promise the policy engine then refuses to keep.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if row.scenario:
        raise HTTPException(409, 'Scenario campaigns follow their versioned workflow')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if payload.enabled and not (target and aggressive_lab(target)):
        raise HTTPException(403, 'Autopilot drives the lab-only kill chain, so it requires a target in '
                                 'aggressive lab mode that authorizes controlled exploitation')
    claim_workflow(db, row, allow_running=True)
    row.autopilot = bool(payload.enabled)
    if payload.enabled and not (row.autopilot_state or {}).get('updated_at'):
        row.autopilot_state = {'iterations': 0, 'stopped': '', 'next_action': '', 'updated_at': utcnow().isoformat()}
    db.commit()
    return {'assessment_id': assessment_id, 'autopilot': bool(row.autopilot),
            'autopilot_state': autopilot_state(row)}


@app.post('/assessments/{assessment_id}/autopilot/run', dependencies=PROTECTED)
def run_autopilot(assessment_id: int, db: Session = Depends(get_db)):
    """One autopilot iteration.

    It ingests evidence, drafts the next phase and records proposals. It never
    approves a step and never runs a command: the summary states which human
    decision comes next.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    if not row.autopilot:
        raise HTTPException(409, 'Enable autopilot for this assessment before running it')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    return run_autopilot_iteration(db, row, target)


@app.get('/assessments/{assessment_id}/loot/{loot_id}/reveal', dependencies=PROTECTED)
def reveal_loot(assessment_id: int, loot_id: int, db: Session = Depends(get_db)):
    """Decrypt one recovered secret. Every reveal is logged.

    Loot is encrypted at rest and masked in every list response, so this is the
    single explicit way to read a value. The structured log record is the audit
    trail for that access: which engagement, which row, which host and account,
    and when.
    """
    row = db.query(Loot).filter(Loot.id == loot_id, Loot.assessment_id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Loot not found')
    try:
        value = footholds.reveal_secret(row)
    except Exception:
        raise HTTPException(409, 'The stored secret could not be decrypted')
    logger.warning('loot_revealed', extra={'assessment_id': assessment_id, 'loot_id': loot_id,
                                           'host': row.host, 'username': row.username,
                                           'service': row.service})
    audit_raw_access(db, assessment_id, 'loot', loot_id)
    return JSONResponse(content={'id': row.id, 'host': row.host, 'service': row.service, 'username': row.username,
            'secret_kind': row.secret_kind, 'secret': value}, headers={'Cache-Control': 'no-store'})


@app.post('/assessments/{assessment_id}/promote/{host_id}', dependencies=PROTECTED)
def promote_host(assessment_id: int, host_id: int, payload: Optional[PromoteRequest] = None,
                 db: Session = Depends(get_db)):
    """Spawn a child assessment scoped to a host the campaign proved it owned.

    The child gets its own target whose authorized scope is exactly that one
    host - strictly narrower than the parent's - so pivoting into it cannot
    widen what the engagement letter permits. It inherits the parent's
    authorization flags so it can itself walk the kill chain.
    """
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    if not aggressive_lab(target):
        raise HTTPException(403, 'Promoting a compromised host is part of the lab-only kill chain, '
                                 'which requires aggressive lab mode')
    host = db.query(EngagementHost).filter(EngagementHost.id == host_id,
                                           EngagementHost.assessment_id == assessment_id).first()
    if not host:
        raise HTTPException(404, 'Host not found')
    if host.child_assessment_id:
        raise HTTPException(409, 'This host already has a child assessment')
    from modules.scope_rules import promotion_scope
    if host.state != 'owned' and host.role != 'owned':
        raise HTTPException(409, 'Only an owned host can be promoted; discovery is not proof of compromise')
    if not promotion_scope(host.address, authorized_scopes_for(target),
                           (target.engagement_policy or {}).get('excluded_scopes', [])):
        raise HTTPException(403, 'Host promotion requires host-wide permission within the parent scope and outside its exclusions')
    claim_workflow(db, row)
    child_target = Target(
        name=f'{target.name} - {host.address}'[:200],
        scope_domain_ip=host.address,
        authorized_scopes=[host.address],
        criticality=target.criticality,
        restricted_tools=list(target.restricted_tools or []),
        exploitation_authorized=bool(target.exploitation_authorized),
        aggressive_lab=bool(target.aggressive_lab),
        engagement_policy=dict(target.engagement_policy or {}),
    )
    db.add(child_target)
    db.flush()
    objective = (payload.objective if payload else None) or f'Independent assessment of the compromised host {host.address}'
    child = Assessment(
        target_id=child_target.id,
        objective=objective,
        plan=normalize_plan([{**step, 'phase': step.get('phase', 'recon')}
                             for step in planner_agent.default_plan(host.address)]),
        current_phase='recon',
        parent_assessment_id=assessment_id,
        engagement_brief=row.engagement_brief if isinstance(row.engagement_brief, dict) else None,
    )
    db.add(child)
    db.flush()
    host.child_assessment_id = child.id
    host.state = 'owned'
    db.commit()
    return {'parent_assessment_id': assessment_id, 'host_id': host.id,
            'child_assessment_id': child.id, 'target_id': child_target.id,
            'objective': objective, 'plan_steps': len(child.plan or [])}


@app.get('/assessments/{assessment_id}/executions/{execution_id}/evidence', dependencies=PROTECTED)
def get_execution_evidence(assessment_id: int, execution_id: int, db: Session = Depends(get_db)):
    """The raw transcript of one execution, for the audit trail's detail view.

    The assessment summary deliberately omits evidence - it is a bounded index,
    not a transcript dump - so the full output is fetched only for the one
    execution the operator opens.
    """
    row = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Execution not found')
    return {'execution_id': row.id, 'attempt': row.attempt, 'tool': row.tool_name,
            'command': row.command, 'state': row.state, 'stdout': row.stdout or '',
            'stderr': row.stderr or '', 'return_code': row.return_code,
            'plan_version': row.plan_version}


@app.post('/assessments/{assessment_id}/report', dependencies=PROTECTED)
def generate_report(assessment_id: int, db: Session = Depends(get_db)):
    row = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not row:
        raise HTTPException(404, 'Assessment not found')
    target = db.query(Target).filter(Target.id == row.target_id).first()
    if not target:
        raise HTTPException(404, 'Target not found')
    if row.status not in {'analyzed', 'reported'}:
        raise HTTPException(409, 'Analyze the completed phase before generating a report')
    revision_at_start = row.workflow_revision
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc()).all()
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment_id).order_by(ToolExecution.step_index).all()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    import uuid
    path = REPORTS_DIR / f'.staged-{assessment_id}-{uuid.uuid4().hex}.html'
    # Per-phase step counts for the report's progress summary, and the
    # verification outcomes for the exploitation section.
    phase_summary = [
        {'phase': phase, 'label': PHASE_LABELS[phase],
         'steps': len(phase_steps_all(row, phase)),
         'analyzed': phase in (row.analyzed_phases or [])}
        for phase in plan_phases(aggressive_lab(target))
    ]
    # The post-compromise evidence: which hosts were owned, which footholds
    # exist, and the masked loot table. Secrets stay encrypted - the report
    # shows a fingerprint and a placeholder, never a recovered credential.
    campaign = campaign_evidence(db, assessment_id)
    campaign['children'] = [
        {'id': child.id, 'objective': child.objective, 'status': child.status,
         'current_phase': child.current_phase}
        for child in db.query(Assessment).filter(Assessment.parent_assessment_id == assessment_id)
            .order_by(Assessment.id).all()
    ]
    # Attack paths: the findings as a graph, so the report shows which of
    # them combine on one origin instead of only a flat prioritised list.
    # The narrative is grounded - cited finding ids are verified to exist -
    # and falls back to the deterministic explanation without a provider.
    serialized_findings = [serialize_finding(finding) for finding in findings]
    paths = derive_paths(serialized_findings, target_address=target.scope_domain_ip)
    if paths:
        paths = narrate_paths(paths)
    from modules.report_versions import provenance, archive_report
    source = provenance(row, executions)
    secrets = known_secrets(db, assessment_id)
    try:
        reporter.generate_html_report(
            target.scope_domain_ip,
            redact(row.objective, secrets),
            redact(serialized_findings, secrets),
            redact([serialize_execution(execution) for execution in executions], secrets),
            str(path),
            engagement_brief=redact(row.engagement_brief, secrets),
            analysis_mode=row.analysis_mode,
            current_phase=row.current_phase or 'recon',
            phase_summary=phase_summary,
            attack_paths=redact(paths, secrets),
            provenance=source,
            campaign=redact(campaign, secrets),
            objective_result=objective_result(db, row),
            framework_report=redact(framework.snapshot(db, row), secrets),
        )
        claim_workflow(db, row, revision_at_start)
        version = archive_report(db, assessment_id, path, source)
        row.current_report_version_id = version.id
        row.status = 'reported'
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        path.unlink(missing_ok=True)
    return {'message': 'Report generated', 'version_id': version.id, 'digest': version.digest, 'download_url': f'/assessments/{assessment_id}/reports/{version.id}'}


def audit_raw_access(db, assessment_id, kind, identifier, attempt=None):
    db.add(Recommendation(assessment_id=assessment_id, origin='evidence_access',
        payload={'action': 'reveal', 'kind': kind, 'id': identifier, 'attempt': attempt}))
    db.commit()  # Access fails if the durable audit record cannot be written.


@app.post('/assessments/{assessment_id}/executions/{execution_id}/evidence/reveal', dependencies=PROTECTED)
def reveal_execution_evidence(assessment_id: int, execution_id: int, attempt: Optional[int] = Query(None, ge=1), db: Session = Depends(get_db)):
    row = db.query(ToolExecution).filter_by(id=execution_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Execution not found')
    selected = row
    if attempt is not None and attempt != row.attempt:
        selected = db.query(ExecutionAttempt).filter_by(execution_id=execution_id, assessment_id=assessment_id, attempt=attempt).first()
        if selected is None:
            raise HTTPException(404, 'Execution attempt not found')
    try:
        raw = unseal(selected.raw_encrypted)
    except Exception:
        raise HTTPException(409, 'The original evidence could not be decrypted; check the evidence key')
    audit_raw_access(db, assessment_id, 'execution', execution_id, selected.attempt)
    return JSONResponse(content={'execution_id': execution_id, 'attempt': selected.attempt,
        'evidence_sha256': selected.evidence_sha256, **raw}, headers={'Cache-Control': 'no-store'})


@app.post('/assessments/{assessment_id}/reports/{version_id}/reveal', dependencies=PROTECTED)
def reveal_legacy_report(assessment_id: int, version_id: int, db: Session = Depends(get_db)):
    row = db.query(ReportVersion).filter_by(id=version_id, assessment_id=assessment_id).first()
    if not row:
        raise HTTPException(404, 'Report version not found')
    try:
        import base64
        content = base64.b64decode(unseal(row.raw_encrypted)['content_base64'], validate=True)
    except Exception:
        raise HTTPException(409, 'The original report could not be decrypted; check the evidence key')
    audit_raw_access(db, assessment_id, 'report', version_id)
    from fastapi.responses import Response
    return Response(content=content, media_type='application/octet-stream', headers={
        'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="assessment-{assessment_id}-original-{version_id}.html"'})


@app.get('/reports/{assessment_id}', dependencies=PROTECTED)
def download_report(assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    version = db.get(ReportVersion, assessment.current_report_version_id) if assessment and assessment.current_report_version_id else None
    if not version or version.restricted or not Path(version.path).is_file():
        raise HTTPException(404, 'Report not generated')
    return FileResponse(version.path, media_type='text/html', filename=f'security-assessment-{assessment_id}.html')


@app.post('/workspace/reset', dependencies=PROTECTED)
def reset_workspace(db: Session = Depends(get_db)):
    """Clear every target, assessment, execution, finding and report.

    A persisted database means every reload shows the last engagement's
    leftovers. This is the explicit way back to an empty board between two
    client letters or two demonstrations. The settings row survives, so a
    configured provider or attacker VM stays configured.
    """
    if running_executions(db):
        raise HTTPException(409, 'A command is still executing; wait for it to finish or time out before clearing the workspace')
    assessments = db.query(Assessment).all()
    for row in assessments:
        report_path(row.id).unlink(missing_ok=True)
    for version in db.query(ReportVersion).all():
        Path(version.path).unlink(missing_ok=True)
    for model in (FrameworkEvent, Loot, Foothold, EngagementHost, ExecutionAttempt, RecommendationTask, FindingReview, ReportVersion):
        db.query(model).delete(synchronize_session=False)
    deleted_findings = db.query(Finding).delete(synchronize_session=False)
    deleted_executions = db.query(ToolExecution).delete(synchronize_session=False)
    db.query(Recommendation).delete(synchronize_session=False)
    deleted_assessments = len(assessments)
    # Explicit database deletes also work with production's autoflush=False.
    # Detach parent links before removing a campaign graph in arbitrary order.
    db.query(Assessment).update({'parent_assessment_id': None}, synchronize_session=False)
    db.query(Assessment).delete(synchronize_session=False)
    deleted_targets = db.query(Target).delete(synchronize_session=False)
    db.commit()
    return {
        'message': 'Workspace cleared',
        'deleted': {
            'assessments': deleted_assessments,
            'executions': deleted_executions,
            'findings': deleted_findings,
            'targets': deleted_targets,
        },
    }


from modules.workspace_api import router as workspace_router
app.include_router(workspace_router)
from modules.framework_api import router as framework_router
app.include_router(framework_router)
from modules.team_api import router as team_router
app.include_router(team_router)
