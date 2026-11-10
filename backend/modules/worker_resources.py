"""Cross-process ownership of shared remote execution surfaces."""
import hashlib
import json
import shutil
import socket
from datetime import timedelta
from sqlalchemy.exc import IntegrityError
from database import ExecutionLease, WorkerRegistration, utcnow
from modules.policy_engine import policy_engine


def reserve(db, remote, worker_id, execution_id):
    if not remote:
        return True
    identity = [remote.get('host'), remote.get('port'), remote.get('username')]
    resource = 'ssh:' + hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    expiry = utcnow() + timedelta(seconds=60)
    changed = db.query(ExecutionLease).filter_by(resource=resource).filter(ExecutionLease.expires_at < utcnow()).update(
        {'worker_id': worker_id, 'execution_id': execution_id, 'expires_at': expiry}, synchronize_session=False)
    if changed:
        return True
    try:
        with db.begin_nested():
            db.add(ExecutionLease(resource=resource, worker_id=worker_id, execution_id=execution_id, expires_at=expiry))
            db.flush()
        return True
    except IntegrityError:
        return False


def renew(db, worker_id, execution_id):
    db.query(ExecutionLease).filter_by(worker_id=worker_id, execution_id=execution_id).update(
        {'expires_at': utcnow() + timedelta(seconds=60)}, synchronize_session=False)


def release(db, worker_id, execution_id):
    db.query(ExecutionLease).filter_by(worker_id=worker_id, execution_id=execution_id).delete(synchronize_session=False)


def heartbeat(db, worker_id):
    row = db.get(WorkerRegistration, worker_id)
    if row is None:
        row = WorkerRegistration(id=worker_id, hostname=socket.gethostname(),
                                 capabilities=[tool for tool in policy_engine.tool_registry() if shutil.which(tool)])
        db.add(row)
    row.heartbeat_at = utcnow()
    db.query(WorkerRegistration).filter(WorkerRegistration.heartbeat_at < utcnow() - timedelta(days=7)).delete(synchronize_session=False)
