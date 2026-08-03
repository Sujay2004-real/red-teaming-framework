from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./data/redteam.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    scope_domain_ip = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer)
    objective = Column(Text)
    status = Column(String, default="planning") # planning, running, completed, reported
    plan = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer)
    tool_name = Column(String)
    command = Column(String)
    stdout = Column(Text)
    stderr = Column(Text)
    return_code = Column(Integer)
    executed_at = Column(DateTime, default=datetime.utcnow)

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    evidence = Column(Text)
    remediation = Column(Text)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
