"""Process-wide logging setup shared by the API and the scanner worker.

The RequestObservability middleware and jobs.py emit records through
``logging.getLogger('access')`` and module loggers at INFO. Under
``uvicorn main:app`` uvicorn configures only its own ``uvicorn.*`` loggers, so
without this the root logger stays at WARNING with no handler and every one of
those records is silently discarded — the structured access log and the
worker's queue diagnostics never appear. Both entrypoints call
``configure_logging()`` once at startup so the two processes log identically.
"""
import logging
import os

_configured = False


def configure_logging():
    """Attach a stream handler at LOG_LEVEL (default INFO) to the root logger.

    Idempotent: safe to call from both the FastAPI startup hook and the
    worker's ``__main__`` without doubling handlers. Honors LOG_LEVEL from the
    environment; an unrecognized value falls back to INFO rather than raising.
    """
    global _configured
    if _configured:
        return
    level_name = (os.getenv('LOG_LEVEL') or 'INFO').strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    # basicConfig is a no-op if the root already has handlers (e.g. a host that
    # configured logging before importing us), so we respect an existing setup
    # instead of clobbering it, but still raise the level to what we need.
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
    )
    logging.getLogger().setLevel(level)
    _configured = True
