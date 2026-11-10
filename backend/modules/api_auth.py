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

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from database import AppSettings, OperatorCredential, get_db

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
    request: Request = None,
    x_api_key: str = Header(default='', alias=KEY_HEADER),
    db: Session = Depends(get_db),
):
    """FastAPI dependency: refuse the request without the operator key.

    Applied to every route except /health, so the UI's reachability banner
    keeps working while nothing else is reachable anonymously.
    """
    def accept(name, role):
        if request is not None:
            path, method = request.url.path, request.method
            if role == 'viewer' and (method not in ('GET', 'HEAD', 'OPTIONS') or path.endswith('/reveal')):
                raise HTTPException(403, 'Viewer credentials are read-only')
            if role != 'admin' and (path.startswith('/team/credentials') or path.endswith('/reveal')
                    or path == '/workspace/reset' or (path.startswith('/settings') and method not in ('GET', 'HEAD'))):
                raise HTTPException(403, 'This action requires an administrator')
            request.state.principal = {'name': name, 'role': role}
        principal = {'name': name, 'role': role}
        if db is not None:
            db.info['principal'] = principal
        return principal

    expected = (os.getenv(API_KEY_ENV_VAR) or '').strip()
    if expected:
        if secrets.compare_digest(_digest(expected), _digest(x_api_key or '')):
            return accept('bootstrap', 'admin')
    credential = db.query(OperatorCredential).filter_by(key_hash=_digest(x_api_key or ''), active=True).first() if db is not None else None
    if credential:
        return accept(credential.name, credential.role)
    if expected:
        raise HTTPException(401, 'The operator API key is missing or wrong. '
                                 f'Send it in the {KEY_HEADER} header.')
    row = db.query(AppSettings).filter(AppSettings.id == 1).first()
    stored = (row.operator_key_hash or '') if row is not None else ''
    if not stored:
        # Unreachable once the startup hook has run; fail closed regardless.
        raise HTTPException(503, 'No operator API key is configured; restart '
                                 'the backend to generate one.')
    if secrets.compare_digest(stored, _digest(x_api_key or '')):
        return accept('bootstrap', 'admin')
    raise HTTPException(401, 'The operator API key is missing or wrong. '
                             f'Send it in the {KEY_HEADER} header '
                             f'(printed in the backend console on first start, '
                             f'or set {API_KEY_ENV_VAR}).')
