import os
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from modules.secret_store import encrypt_secret, is_encrypted

os.makedirs('./data', exist_ok=True)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./data/redteam.db')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
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

class Finding(Base):
    __tablename__ = 'findings'
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
    source_tools = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow)

Base.metadata.create_all(bind=engine)

def _migrate_sqlite():
    if not DATABASE_URL.startswith('sqlite'):
        return
    additions = {
        # Every column added to AppSettings after the first release has to be
        # listed here. create_all only creates missing tables, so a database
        # from an earlier version keeps its old app_settings shape, and
        # _encrypt_stored_secrets below then SELECTs proxy_password from a
        # table that has no such column - an OperationalError at import time
        # that takes the whole backend down before it can serve anything.
        'app_settings': [
            ('api_base_url', "VARCHAR DEFAULT ''"), ('model_name', "VARCHAR DEFAULT ''"),
            ('proxy_url', "VARCHAR DEFAULT ''"), ('proxy_username', "VARCHAR DEFAULT ''"),
            ('proxy_password', "TEXT DEFAULT ''"), ('updated_at', 'DATETIME'),
        ],
        'targets': [('authorized_scopes', "JSON DEFAULT '[]'"), ('criticality', 'INTEGER DEFAULT 70'), ('restricted_tools', "JSON DEFAULT '[]'")],
        'assessments': [('approval_required', 'BOOLEAN DEFAULT 1'), ('completed_at', 'DATETIME'), ('engagement_brief', 'JSON')],
        'tool_executions': [('step_index', 'INTEGER DEFAULT 0'), ('duration_ms', 'INTEGER DEFAULT 0'), ('approved_by_user', 'BOOLEAN DEFAULT 0'), ('attempt', 'INTEGER DEFAULT 1')],
        'findings': [('fingerprint', "VARCHAR DEFAULT ''"), ('risk_score', 'INTEGER DEFAULT 0'), ('priority_score', 'INTEGER DEFAULT 0'), ('confidence_score', 'INTEGER DEFAULT 0'), ('source_tools', "JSON DEFAULT '[]'"), ('created_at', 'DATETIME')],
    }
    with engine.begin() as conn:
        known = inspect(engine)
        for table, columns in additions.items():
            existing = {column['name'] for column in known.get_columns(table)}
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
        duplicate = conn.execute(text('SELECT 1 FROM tool_executions GROUP BY assessment_id, step_index HAVING COUNT(*) > 1 LIMIT 1')).first()
        if not duplicate:
            conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_execution_step_idx ON tool_executions (assessment_id, step_index)'))
_migrate_sqlite()

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
_encrypt_stored_secrets()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
