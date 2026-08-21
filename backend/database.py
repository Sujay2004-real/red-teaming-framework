import os
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

os.makedirs('./data', exist_ok=True)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./data/redteam.db')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    scope_domain_ip = Column(String, nullable=False)
    authorized_scopes = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

class AppSettings(Base):
    __tablename__ = 'app_settings'
    id = Column(Integer, primary_key=True, default=1)
    gemini_api_key = Column(Text, default='')
    api_base_url = Column(String, default='https://api.openai.com/v1')
    model_name = Column(String, default='gpt-4o-mini')
    proxy_url = Column(String, default='')
    proxy_username = Column(String, default='')
    proxy_password = Column(Text, default='')
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Assessment(Base):
    __tablename__ = 'assessments'
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    objective = Column(Text, nullable=False)
    status = Column(String, default='planning')
    plan = Column(JSON, default=list)
    approval_required = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

class ToolExecution(Base):
    __tablename__ = 'tool_executions'
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
    executed_at = Column(DateTime, default=datetime.utcnow)

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
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def _migrate_sqlite():
    if not DATABASE_URL.startswith('sqlite'):
        return
    additions = {
        'app_settings': [('api_base_url', "VARCHAR DEFAULT 'https://api.openai.com/v1'"), ('model_name', "VARCHAR DEFAULT 'gpt-4o-mini'")],
        'targets': [('authorized_scopes', 'JSON DEFAULT ''[]''')],
        'assessments': [('approval_required', 'BOOLEAN DEFAULT 1'), ('completed_at', 'DATETIME')],
        'tool_executions': [('step_index', 'INTEGER DEFAULT 0'), ('duration_ms', 'INTEGER DEFAULT 0'), ('approved_by_user', 'BOOLEAN DEFAULT 0')],
        'findings': [('fingerprint', "VARCHAR DEFAULT ''"), ('risk_score', 'INTEGER DEFAULT 0'), ('priority_score', 'INTEGER DEFAULT 0'), ('confidence_score', 'INTEGER DEFAULT 0'), ('source_tools', 'JSON DEFAULT ''[]'''), ('created_at', 'DATETIME')],
    }
    with engine.begin() as conn:
        known = inspect(engine)
        for table, columns in additions.items():
            existing = {column['name'] for column in known.get_columns(table)}
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
_migrate_sqlite()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
