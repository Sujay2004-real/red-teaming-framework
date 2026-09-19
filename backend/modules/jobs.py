"""Database-backed execution queue, shared by embedded and separate workers."""
import asyncio
import logging
import os
import uuid
from datetime import timedelta

from fastapi.encoders import jsonable_encoder
from sqlalchemy import func, select, or_

from database import Assessment, ExecutionAttempt, SessionLocal, ToolExecution, utcnow
from modules.executor import live_registry
from modules.outcomes import outcome

logger = logging.getLogger(__name__)
WORKER_ID = uuid.uuid4().hex
MAX_JOBS = max(1, min(8, int(os.getenv('MAX_CONCURRENT_EXECUTIONS', '2'))))


def archive_attempt(db, execution):
    if db.query(ExecutionAttempt.id).filter_by(execution_id=execution.id, attempt=execution.attempt or 1).first():
        return
    fields = ('id', 'step_index', 'tool_name', 'command', 'stdout', 'stderr', 'return_code',
              'duration_ms', 'approved_by_user', 'attempt', 'executed_at', 'execution_host', 'state', 'plan_version')
    db.add(ExecutionAttempt(execution_id=execution.id, assessment_id=execution.assessment_id,
                            attempt=execution.attempt or 1,
                            snapshot=jsonable_encoder({name: getattr(execution, name) for name in fields})))


def _tick(sessions, execution_id):
    with sessions() as db:
        row = db.get(ToolExecution, execution_id)
        if not row or row.state != 'running' or row.worker_id != WORKER_ID:
            return True
        snapshot = live_registry.snapshot(execution_id)
        if snapshot:
            row.live_output, row.output_cursor = snapshot['output'], snapshot['cursor']
        row.heartbeat_at = utcnow()
        cancel = bool(row.cancel_requested)
        db.commit()
        return cancel


async def run_execution(execution_id, sessions=None):
    sessions = sessions or SessionLocal
    import main as api  # API and worker share the same policy/service adapters.
    with sessions() as db:
        active_count = select(func.count(ToolExecution.id)).where(ToolExecution.state == 'running').scalar_subquery()
        claimed = db.query(ToolExecution).filter_by(id=execution_id, state='queued', return_code=None, cancel_requested=False).filter(active_count < MAX_JOBS).update(
            {'state': 'running', 'worker_id': WORKER_ID, 'heartbeat_at': utcnow()}, synchronize_session=False)
        db.commit()
        if not claimed:
            return None
        row = db.get(ToolExecution, execution_id)
        assessment_id, command, tool = row.assessment_id, row.command, row.tool_name
        try:
            assessment = db.get(Assessment, assessment_id)
            target = db.get(api.Target, assessment.target_id)
            if row.plan_version != assessment.plan_version:
                raise ValueError('Plan changed since approval')
            api.enforce_engagement(db, assessment, target, row.step_index, command, tool)
            settings = api.get_settings_row(db)
            proxy = api.proxy_environment(settings)
            remote = api.remote_execution_settings(settings)
        except Exception as exc:
            result = {'stdout': '', 'stderr': f'Execution policy no longer permits this job: {getattr(exc, "detail", type(exc).__name__)}', 'return_code': -1, 'duration_ms': 0}
            proxy = remote = None
        else:
            result = None
    live_registry.start(execution_id, command)
    process_task = None
    final_state = ''
    try:
        if result is None:
            process_task = asyncio.create_task(api.executor.execute_command(tool, command, proxy,
                                                                           execution_id=execution_id, remote=remote))
            while not process_task.done():
                await asyncio.wait({process_task}, timeout=.5)
                if await asyncio.to_thread(_tick, sessions, execution_id):
                    final_state = 'cancelled'
                    process_task.cancel()
                    break
            try:
                result = await process_task
            except asyncio.CancelledError:
                final_state = final_state or 'interrupted'
                snap = live_registry.snapshot(execution_id) or {}
                result = {'stdout': snap.get('output', ''), 'stderr': 'Execution cancelled or worker stopped.',
                          'return_code': -1, 'duration_ms': 0}
    except asyncio.CancelledError:
        if process_task:
            process_task.cancel()
            await asyncio.gather(process_task, return_exceptions=True)
        final_state = 'interrupted'
        result = {'stdout': (live_registry.snapshot(execution_id) or {}).get('output', ''),
                  'stderr': 'Worker stopped; explicit re-approval is required.', 'return_code': -1, 'duration_ms': 0}
    except Exception:
        logger.exception('execution_failed', extra={'execution_id': execution_id})
        result = {'stdout': '', 'stderr': 'Execution worker failed; see the server log.', 'return_code': -1, 'duration_ms': 0}
    finally:
        await asyncio.to_thread(_tick, sessions, execution_id)
        live_registry.finish(execution_id)
    with sessions() as db:
        row = db.get(ToolExecution, execution_id)
        if row is None or row.state != 'running' or row.worker_id != WORKER_ID:
            return result
        for key in ('stdout', 'stderr', 'return_code', 'duration_ms', 'execution_host'):
            setattr(row, key, result.get(key))
        row.state = outcome(tool, row.return_code, row.stderr, final_state)
        final_state = row.state
        row.heartbeat_at = utcnow()
        archive_attempt(db, row)
        assessment = db.get(Assessment, assessment_id)
        api.refresh_assessment_status(db, assessment)
        db.commit()
    if final_state not in {'interrupted', 'cancelled'}:
        api.schedule_auto_recommendations(assessment_id, execution_id, sessions=sessions)
    return {**result, 'tool': tool, 'command': command, 'outcome': final_state}


class JobRunner:
    def __init__(self):
        self.tasks = set()
        self.loop_task = None

    def _done(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception():
            logger.error('execution_task_failed', exc_info=task.exception())

    def submit(self, execution_id, sessions=SessionLocal):
        task = asyncio.create_task(run_execution(execution_id, sessions))
        self.tasks.add(task)
        task.add_done_callback(self._done)
        return task

    async def poll(self, sessions=SessionLocal):
        while True:
            try:
                ids = await asyncio.to_thread(pending_jobs, sessions, max(0, MAX_JOBS - len(self.tasks)))
            except Exception:
                logger.exception('queue_poll_failed')
                await asyncio.sleep(2)
                continue
            heartbeat = os.getenv('WORKER_HEARTBEAT_FILE')
            if heartbeat:
                from pathlib import Path
                Path(heartbeat).touch()
            for execution_id in ids:
                self.submit(execution_id, sessions)
            await asyncio.sleep(.5)

    async def start(self, sessions=SessionLocal):
        self.loop_task = asyncio.create_task(self.poll(sessions))

    async def stop(self):
        tasks = list(self.tasks) + ([self.loop_task] if self.loop_task else [])
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.loop_task = None


job_runner = JobRunner()


def pending_jobs(sessions, capacity):
    """Recover dead leases; late workers cannot overwrite the interrupted attempt."""
    import main as api
    with sessions() as db:
        expired = or_(ToolExecution.heartbeat_at < utcnow() - timedelta(seconds=60), ToolExecution.heartbeat_at.is_(None))
        stale = db.query(ToolExecution).filter(ToolExecution.state == 'running', expired).all()
        for row in stale:
            claimed = db.query(ToolExecution).filter(ToolExecution.id == row.id, ToolExecution.state == 'running', expired).update(
                {'state': 'interrupted', 'return_code': -1, 'stderr': 'Worker heartbeat expired; explicit re-approval is required.'}, synchronize_session=False)
            if claimed:
                db.refresh(row)
                archive_attempt(db, row)
                assessment = db.get(Assessment, row.assessment_id)
                if assessment:
                    api.refresh_assessment_status(db, assessment)
        db.commit()
        return [row.id for row in db.query(ToolExecution).filter_by(state='queued', return_code=None)
                .order_by(ToolExecution.id).limit(capacity).all()]
