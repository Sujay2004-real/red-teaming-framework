"""Separate scanner worker: python worker.py (API mode: external)."""
import asyncio
import logging
import signal
from database import initialize_database, engine, migration_head
from sqlalchemy import text
import os
from modules.jobs import job_runner
from modules.logging_config import configure_logging

logger = logging.getLogger(__name__)


async def main():
    if os.getenv('EXECUTION_WORKER_MODE') == 'external':
        # The API owns schema upgrades. Wait for it instead of racing migrations.
        head = migration_head()
        for attempt in range(60):
            try:
                with engine.connect() as connection:
                    if connection.execute(text('SELECT version_num FROM alembic_version')).scalar() == head:
                        break
            except Exception:
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError('Database migration did not complete')
    else:
        initialize_database()

    # Docker/compose stop the worker with SIGTERM (not SIGINT), so relying on
    # the KeyboardInterrupt that SIGINT raises would skip the drain entirely:
    # the `finally` below never runs and in-flight scans sit `running` until the
    # heartbeat sweep reclaims them ~60s later. Cancel the poll task on either
    # signal so job_runner.stop() runs promptly and in-flight steps become
    # `interrupted` (run_execution already handles CancelledError). Signal-based
    # cancellation is not available on every platform (notably Windows), so fall
    # back silently to the default behavior where it is not.
    poll_task = asyncio.ensure_future(job_runner.poll())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, poll_task.cancel)
        except (NotImplementedError, AttributeError, ValueError):
            pass
    try:
        await poll_task
    except asyncio.CancelledError:
        logger.info('Worker received shutdown signal; draining in-flight jobs')
    finally:
        await job_runner.stop()


if __name__ == '__main__':
    configure_logging()
    asyncio.run(main())
