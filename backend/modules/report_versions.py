"""Atomic report publication and evidence provenance."""
import hashlib
import json
import os
import tempfile
from pathlib import Path
from database import ReportVersion


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.report-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def provenance(assessment, executions):
    return {'application_version': '3.0', 'plan_version': assessment.plan_version,
            'analysis': assessment.analysis_metadata or {},
            'executions': [{'id': e.id, 'attempt': e.attempt, 'tool': e.tool_name,
                'command': e.command, 'state': e.state, 'execution_host': e.execution_host,
                'evidence_sha256': hashlib.sha256(json.dumps([e.stdout or '', e.stderr or ''], ensure_ascii=False).encode()).hexdigest()}
                for e in executions]}


def archive_report(db, assessment_id, path, source):
    content = Path(path).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    existing = db.query(ReportVersion).filter_by(assessment_id=assessment_id, digest=digest).first()
    if existing:
        return existing
    immutable = Path(path).with_name(f'report_{assessment_id}_{digest}.html')
    atomic_write(immutable, content)
    row = ReportVersion(assessment_id=assessment_id, digest=digest, path=str(immutable), provenance=source)
    db.add(row)
    db.flush()
    return row
