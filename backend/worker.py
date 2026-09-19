"""Separate scanner worker: python worker.py (API mode: external)."""
import asyncio
import logging
from database import initialize_database, engine, migration_head
from sqlalchemy import text
import os
from modules.jobs import job_runner


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
    try:
        await job_runner.poll()
    finally:
        await job_runner.stop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
