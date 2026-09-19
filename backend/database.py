import os
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Index, create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker

from modules.secret_store import encrypt_secret, is_encrypted

# Default driver bounds mirrored from the analyzer. Duplicated here because
# importing the analyzer from the database layer would create a circular
# import (the analyzer has no database dependency by design).
FINDING_DRIVER_DEFAULTS = {'exploitability': 3, 'impact': 3, 'exposure': 3}

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./data/redteam.db')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
if DATABASE_URL.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def configure_sqlite(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA busy_timeout=10000')
        connection.execute('PRAGMA journal_mode=WAL')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    scope_domain_ip = Column(String, nullable=False)
    authorized_scopes = Column(JSON, default=list)
    criticality = Column(Integer, default=70)
    # Tools the client's engagement letter rules out for this target, kept as
    # plain names; the execute endpoint refuses them before policy review.
    restricted_tools = Column(JSON, default=list)
    # True only when the client's letter authorizes controlled exploitation
    # (vulnerability verification with bounded evidence) against this target.
    # The policy engine refuses every exploitation-grade command otherwise,
    # fail-closed like every other letter-derived restriction.
    exploitation_authorized = Column(Boolean, default=False)
    # Opt-in "aggressive lab mode": unlocks weaponized exploitation (data
    # extraction, single-command RCE, real Metasploit exploit modules with
    # payloads/sessions) for a target the operator owns. Only ever effective
    # when exploitation_authorized is also true, and every step still needs
    # per-step human approval. Off by default; safe for production targets.
    aggressive_lab = Column(Boolean, default=False)
    engagement_policy = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)

class AppSettings(Base):
    __tablename__ = 'app_settings'
    id = Column(Integer, primary_key=True, default=1)
    # No default provider, model, or key: the operator supplies their own, and a
    # baked-in endpoint would quietly send scanner output to a third party that
    # nobody chose. Empty means "AI features off", which is a safe resting state.
    gemini_api_key = Column(Text, default='')
    api_base_url = Column(String, default='')
    model_name = Column(String, default='')
    proxy_url = Column(String, default='')
    proxy_username = Column(String, default='')
    proxy_password = Column(Text, default='')
    # Where approved commands run: 'local' (subprocess on this host, the
    # Docker path) or 'kali_vm' (typed into the attacker VM's tmux over SSH).
    execution_mode = Column(String, default='local')
    ssh_host = Column(String, default='')
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String, default='')
    ssh_password = Column(Text, default='')
    ssh_fingerprint = Column(String, default='')
    ssh_private_key = Column(Text, default='')
    ssh_key_passphrase = Column(Text, default='')
    # SHA-256 digest of the operator API key (or '' when REDTEAM_API_KEY is
    # used instead). The plaintext is printed to the console on the first
    # start and never stored anywhere.
    operator_key_hash = Column(String, default='')
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

class Assessment(Base):
    __tablename__ = 'assessments'
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    objective = Column(Text, nullable=False)
    status = Column(String, default='awaiting_approval')
    plan = Column(JSON, default=list)
    # The parsed engagement letter this assessment was drafted from, stored so
    # the brief the operator reviewed is the same one the planner, analyzer and
    # report act on - not a re-parse of raw text that can drift.
    engagement_brief = Column(JSON, default=None)
    approval_required = Column(Boolean, default=True)
    # Which analyzer produced the current findings ('ai-provider' or
    # 'deterministic-fallback'). The client letter requires the report to
    # state it so findings can be weighed accordingly.
    analysis_mode = Column(String, default='')
    # The engagement lifecycle phase this assessment currently sits in
    # ('recon', 'vuln_analysis', 'exploitation', 'post_exploitation',
    # 'reporting'). Plan steps carry their own phase tag; this column says
    # which phase the operator is currently working through.
    current_phase = Column(String, default='recon')
    # Phase-level analysis bookkeeping: which plan phases have had their
    # outputs analyzed, so the next phase's plan is only draftable from
    # findings that actually exist.
    analyzed_phases = Column(JSON, default=list)
    plan_version = Column(Integer, default=1, nullable=False)
    analysis_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime)

class ToolExecution(Base):
    __tablename__ = 'tool_executions'
    __table_args__ = (UniqueConstraint('assessment_id', 'step_index', name='uq_tool_execution_step'),)
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False)
    step_index = Column(Integer, default=0)
    tool_name = Column(String, nullable=False)
    command = Column(Text, nullable=False)
    stdout = Column(Text, default='')
    stderr = Column(Text, default='')
    return_code = Column(Integer)
    duration_ms = Column(Integer, default=0)
    approved_by_user = Column(Boolean, default=False)
    attempt = Column(Integer, default=1)
    executed_at = Column(DateTime, default=utcnow)
    # Where this command actually ran (kali_vm attestation: hostname, OS,
    # kernel, SSH host-key fingerprint) - the proof the output came from the
    # attacker VM and not from anywhere the operator could have staged it.
    execution_host = Column(JSON, default=None)
    state = Column(String, default='queued', index=True)
    cancel_requested = Column(Boolean, default=False)
    worker_id = Column(String, default='')
    heartbeat_at = Column(DateTime)
    live_output = Column(Text, default='')
    output_cursor = Column(Integer, default=0)
    plan_version = Column(Integer, default=1)

class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (Index('ix_finding_assessment_priority', 'assessment_id', 'priority_score'),)
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False)
    fingerprint = Column(String, index=True, default='')
    title = Column(String, nullable=False)
    description = Column(Text, default='')
    severity = Column(String, default='Low')
    evidence = Column(Text, default='')
    remediation = Column(Text, default='')
    risk_score = Column(Integer, default=0)
    priority_score = Column(Integer, default=0)
    confidence_score = Column(Integer, default=0)
    # Where the finding lives (URL or host:port) and which parameter is
    # affected when one is known; surfaced in the UI and the report so a
    # remediation team does not have to re-derive the location from evidence.
    endpoint = Column(String, default='')
    parameter = Column(String, default='')
    # The score drivers behind risk/priority. Persisted so the report can show
    # *why* a finding scored the way it did, not just the resulting numbers.
    exploitability = Column(Integer, default=FINDING_DRIVER_DEFAULTS['exploitability'])
    impact = Column(Integer, default=FINDING_DRIVER_DEFAULTS['impact'])
    exposure = Column(Integer, default=FINDING_DRIVER_DEFAULTS['exposure'])
    # Exploitation-phase outcome for this finding: '' (not attempted),
    # 'attempted', 'verified', or 'refuted'. A recon finding the
    # exploitation phase confirmed carries the proof here, so the report can
    # separate "a scanner matched a signature" from "exploitation proved it".
    verification = Column(String, default='')
    # The exact exploitation output that verified the finding (sqlmap
    # vulnerability confirmation, curl PoC response, msfconsole result).
    exploit_evidence = Column(Text, default='')
    # Which exploitation-phase tools produced the verification.
    verified_by = Column(JSON, default=list)
    # The plan phase whose analysis produced this finding ('recon',
    # 'exploitation', 'post_exploitation'). A phase's analysis replaces only
    # its own findings; earlier phases' findings are the evidence the later
    # phases were planned from and survive re-analysis.
    phase = Column(String, default='recon')
    source_tools = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)

class Recommendation(Base):
    """What the framework proposed, automatically, after each executed step.

    The automatic recommendation loop is read-only advice: nothing here
    becomes a plan step without the operator accepting it through the plan
    endpoint. Persisting the proposals is for the audit trail - *what the
    system suggested at every juncture* is engagement evidence worth keeping,
    including the candidates the policy engine refused (with reasons).
    """
    __tablename__ = 'recommendations'
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False, index=True)
    # The execution whose completion triggered this batch, so the UI can
    # match a poll to the step it just ran.
    trigger_execution_id = Column(Integer)
    # The phase the proposals belong to (proposals are phase-scoped by design).
    phase = Column(String, default='recon')
    # The full proposal payload: candidates, refused (with reasons), source,
    # notes, state digest counts.
    payload = Column(JSON, default=dict)
    # 'auto' for the post-execution loop; the manual /next-steps endpoint
    # stays ephemeral by design and never writes here.
    origin = Column(String, default='auto')
    created_at = Column(DateTime, default=utcnow)

class ExecutionAttempt(Base):
    """Immutable completed attempt; ToolExecution is the current projection."""
    __tablename__ = 'execution_attempts'
    __table_args__ = (UniqueConstraint('execution_id', 'attempt'),)
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey('tool_executions.id'), nullable=False, index=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False, index=True)
    attempt = Column(Integer, nullable=False)
    snapshot = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class FindingReview(Base):
    __tablename__ = 'finding_reviews'
    __table_args__ = (UniqueConstraint('assessment_id', 'fingerprint'),)
    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False, index=True)
    fingerprint = Column(String, nullable=False)
    status = Column(String, default='open')
    owner = Column(String, default='')
    due_date = Column(String, default='')
    justification = Column(Text, default='')
    comments = Column(JSON, default=list)
    retest_evidence = Column(Text, default='')
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class ReportVersion(Base):
    __tablename__ = 'report_versions'
    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False, index=True)
    digest = Column(String, nullable=False)
    path = Column(String, nullable=False)
    provenance = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)


class RecommendationTask(Base):
    __tablename__ = 'recommendation_tasks'
    __table_args__ = (UniqueConstraint('execution_id', 'attempt'),)
    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey('assessments.id'), nullable=False, index=True)
    execution_id = Column(Integer, nullable=False)
    attempt = Column(Integer, default=1)
    state = Column(String, default='pending')
    detail = Column(String, default='')
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

def _encrypt_stored_secrets():
    """Bring an existing settings row in line with the no-defaults policy.

    Two one-time fixes, both no-ops once applied:
      - encrypt credentials stored before encryption was introduced
      - clear the provider endpoint and model that earlier versions baked in,
        so the operator is asked for their own instead of silently inheriting
        a third-party endpoint nobody chose
    """
    legacy_defaults = {'api_base_url': 'https://api.openai.com/v1', 'model_name': 'gpt-4o-mini'}
    with engine.begin() as conn:
        rows = conn.execute(text('SELECT id, gemini_api_key, proxy_password, api_base_url, model_name FROM app_settings')).mappings().all()
        for row in rows:
            updates = {
                field: encrypt_secret(row[field])
                for field in ('gemini_api_key', 'proxy_password')
                if row[field] and not is_encrypted(row[field])
            }
            # Only clear the endpoint and model when they still hold the exact
            # values the old build shipped and no key was ever saved: that
            # combination means nobody configured this row deliberately.
            if not row['gemini_api_key']:
                updates.update({
                    field: ''
                    for field, shipped in legacy_defaults.items()
                    if row[field] == shipped
                })
            if updates:
                assignments = ', '.join(f'{field} = :{field}' for field in updates)
                conn.execute(text(f'UPDATE app_settings SET {assignments} WHERE id = :id'), {**updates, 'id': row['id']})
def initialize_database():
    """Run versioned migrations explicitly at application/worker startup."""
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    if engine.url.get_backend_name() == 'sqlite' and engine.url.database not in (None, '', ':memory:'):
        Path(engine.url.database).parent.mkdir(parents=True, exist_ok=True)
    config = Config()
    config.set_main_option('script_location', str(Path(__file__).parent / 'migrations'))
    with engine.begin() as connection:
        config.attributes['connection'] = connection
        command.upgrade(config, 'head')
    _encrypt_stored_secrets()


def migration_head():
    """The Alembic head revision id, derived from the migration scripts.

    The worker startup gate and the /ready check compare the database's applied
    revision against this instead of a hardcoded id, so adding a new migration
    does not silently break either.
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from pathlib import Path
    config = Config()
    config.set_main_option('script_location', str(Path(__file__).parent / 'migrations'))
    return ScriptDirectory.from_config(config).get_current_head()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
