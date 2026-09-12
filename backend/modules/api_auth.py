"""Operator authentication for the API.

The framework's whole thesis is governance: every command is policy-checked
and individually approved. But the API that enforces all of that was itself
unauthenticated - anyone who could reach port 8000 could register a target
and approve steps. This module closes that hole with the smallest mechanism
that does it: one operator key, sent as the X-API-Key header.

How the key is established (first match wins):

  1. REDTEAM_API_KEY environment variable. The operator chose it, so it can
     be pinned in docker-compose, CI, and the smoke/eval scripts. This is
     also the recovery path: a generated key that was lost can simply be
     overridden from the environment, no database surgery needed.
  2. Otherwise a random key is generated on first start, its SHA-256 digest
     is stored in app_settings, and the plaintext is printed to the console
     exactly once. It is never written to disk and never returned by the API:
     the same "secrets are write-only" rule the provider credentials follow.

The stored form is a digest, not the key, so a copied database file does not
carry the credential. Comparison is constant-time. A missing configuration
fails closed - an API with no key at all refuses everything rather than
allowing everything.
"""
import hashlib
import os
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from database import AppSettings, get_db

API_KEY_ENV_VAR = 'REDTEAM_API_KEY'
KEY_HEADER = 'X-API-Key'
# A generated key is 32 chars of url-safe base64 (24 random bytes). Long
# enough that guessing is hopeless, short enough to paste into the UI.
_GENERATED_KEY_BYTES = 24


def _generated_key():
    return secrets.token_urlsafe(_GENERATED_KEY_BYTES)


def _digest(key):
    return hashlib.sha256((key or '').encode()).hexdigest()


def ensure_operator_key(db):
    """Guarantee a key exists when the env var is unset.

    Returns the plaintext key ONLY on the run that generated it (so the
    startup hook can print it once); every later call returns '' because the
    plaintext is deliberately unrecoverable from the stored digest.
    """
    if (os.getenv(API_KEY_ENV_VAR) or '').strip():
        return ''
    row = db.query(AppSettings).filter(AppSettings.id == 1).first()
    if row is None:
        # get_settings_row's creation logic, repeated here so this module
        # never needs main.py (which would be a circular import).
        row = AppSettings(id=1)
        db.add(row)
    if not (row.operator_key_hash or ''):
        plaintext = _generated_key()
        row.operator_key_hash = _digest(plaintext)
        db.commit()
        return plaintext
    return ''


def verify_operator_key(
    x_api_key: str = Header(default='', alias=KEY_HEADER),
    db: Session = Depends(get_db),
):
    """FastAPI dependency: refuse the request without the operator key.

    Applied to every route except /health, so the UI's reachability banner
    keeps working while nothing else is reachable anonymously.
    """
    expected = (os.getenv(API_KEY_ENV_VAR) or '').strip()
    if expected:
        if secrets.compare_digest(expected, x_api_key or ''):
            return
        raise HTTPException(401, 'The operator API key is missing or wrong. '
                                 f'Send it in the {KEY_HEADER} header.')
    row = db.query(AppSettings).filter(AppSettings.id == 1).first()
    stored = (row.operator_key_hash or '') if row is not None else ''
    if not stored:
        # Unreachable once the startup hook has run; fail closed regardless.
        raise HTTPException(503, 'No operator API key is configured; restart '
                                 'the backend to generate one.')
    if secrets.compare_digest(stored, _digest(x_api_key or '')):
        return
    raise HTTPException(401, 'The operator API key is missing or wrong. '
                             f'Send it in the {KEY_HEADER} header '
                             f'(printed in the backend console on first start, '
                             f'or set {API_KEY_ENV_VAR}).')
