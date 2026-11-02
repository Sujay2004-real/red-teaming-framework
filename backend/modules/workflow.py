"""One optimistic revision contract for API and worker writes."""
from fastapi import HTTPException
from sqlalchemy.orm.attributes import set_committed_value
from database import Assessment
from sqlalchemy import event
from sqlalchemy.orm import Session
from pathlib import Path


def claim(db, row, revision=None, allow_running=False):
    """Acquire a write lock only at publication; keep it until caller commits.

    Reads/computation can occur before this call. Every ORM assessment update
    also uses SQLAlchemy versioning, so stale writers cannot overwrite it.
    """
    expected = revision if revision is not None else row.workflow_revision
    with db.no_autoflush:
        query = db.query(Assessment).filter_by(id=row.id, workflow_revision=expected)
        if not allow_running:
            query = query.filter(Assessment.status != 'running')
        changed = query.update({'workflow_revision': expected + 1}, synchronize_session=False)
    if not changed:
        db.rollback()
        raise HTTPException(409, 'Assessment changed during this operation; reload and retry')
    set_committed_value(row, 'workflow_revision', expected + 1)


def retire_current_file(db, path):
    db.info.setdefault('retired_report_files', set()).add(str(path))


@event.listens_for(Session, 'after_commit')
def remove_retired_files(db):
    for path in db.info.pop('retired_report_files', set()):
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass  # Current reports are served through the database pointer.


@event.listens_for(Session, 'after_rollback')
def clear_retired_files(db):
    db.info.pop('retired_report_files', None)
