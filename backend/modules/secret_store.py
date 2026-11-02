"""Encryption at rest for the provider credentials held in app_settings.

The API key and proxy password are written to data/redteam.db, which is an
ordinary file: it gets copied into backups, mounted into containers, and
occasionally attached to a bug report. Encrypting the two secret columns means
a leaked database file does not hand over the user's provider credentials.

What this does and does not protect: it protects the database file, not the
host. Anything that can read the master key can read the secrets. Where the
deployment allows it, supply the key through REDTEAM_SECRET_KEY so it never
lands on the same volume as the database; otherwise a key file is generated
next to the database on first use, which still defends against the database
being copied on its own.
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Stored values carry this marker so a credential written before encryption was
# introduced is recognisable as plaintext instead of being fed to Fernet, which
# would reject it and silently discard a key the user had already configured.
PREFIX = 'enc:v1:'
KEY_ENV_VAR = 'REDTEAM_SECRET_KEY'
KEY_PATH = Path('./data/.secret_key')


def _load_key(require_existing=False):
    """Return the Fernet master key, generating a local one on first use.

    Deliberately not cached: settings reads and writes are rare, and re-reading
    means a rotated key file takes effect without a restart.
    """
    from_env = (os.getenv(KEY_ENV_VAR) or '').strip()
    if from_env:
        return from_env.encode()
    if KEY_PATH.exists():
        stored = KEY_PATH.read_bytes().strip()
        if stored:
            return stored
    if require_existing:
        raise ValueError('The evidence encryption key is unavailable')
    # Publish a completely written file atomically. Competing first-use
    # processes must all use the winner's key, never overwrite one another.
    import tempfile
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.key-', dir=KEY_PATH.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(Fernet.generate_key())
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, KEY_PATH)
        except FileExistsError:
            pass
        key = KEY_PATH.read_bytes().strip()
        Fernet(key)  # Refuse an empty or corrupt key, without replacing it.
        return key
    finally:
        Path(temporary).unlink(missing_ok=True)


def decrypt_required(value):
    """Decrypt protected evidence; missing/wrong keys must fail closed."""
    if not is_encrypted(value):
        raise ValueError('Protected evidence is not encrypted')
    return Fernet(_load_key(require_existing=True)).decrypt(value[len(PREFIX):].encode()).decode()


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_secret(value):
    """Encrypt a credential for storage. Already-encrypted input passes through.

    A malformed REDTEAM_SECRET_KEY raises rather than falling back to plaintext:
    storing a secret unencrypted because the key was mistyped is the one outcome
    worse than refusing the write.
    """
    if not value:
        return ''
    if is_encrypted(value):
        return value
    return encrypt_value(value)


def encrypt_value(value):
    """Encrypt new plaintext, including values that resemble our envelope."""
    return PREFIX + Fernet(_load_key()).encrypt(value.encode()).decode()


def decrypt_secret(value):
    """Recover a stored credential, or '' when it cannot be read.

    Returns '' rather than raising when the master key no longer matches the
    ciphertext, so a rotated or lost key degrades to "no provider configured"
    and the user can re-enter the credential instead of every settings read
    failing.
    """
    if not value:
        return ''
    if not is_encrypted(value):
        # Written before encryption existed; re-encrypted by the startup
        # migration and by the next settings write.
        return value
    try:
        return Fernet(_load_key()).decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, ValueError):
        return ''
