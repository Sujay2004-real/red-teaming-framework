"""The operator API key gate.

The framework's value proposition is governance, so the API that enforces
all of it must not itself be anonymous. These tests exercise both
verification paths (environment-chosen key and generated-and-digested key)
and the refusal that must follow a missing or wrong key.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from conftest import OPERATOR_TEST_KEY
from database import Base, get_db
from main import app
from modules import api_auth


@pytest.fixture
def raw_client():
    """A client that sends NO key, against a fresh in-memory database.

    The suite-wide conftest sets REDTEAM_API_KEY, so this fixture swaps in a
    temporary value (or none) per test to exercise each verification path.
    """
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def test_requests_without_key_are_refused(raw_client):
    """The point of the gate: no header, no service.

    A generated key is seeded first so the refusal is the ordinary 401 an
    operator with a configured backend sees; the completely unconfigured
    fail-closed case is covered separately below.
    """
    saved = os.environ.pop(api_auth.API_KEY_ENV_VAR, None)
    try:
        db = next(app.dependency_overrides[get_db]())
        try:
            api_auth.ensure_operator_key(db)
        finally:
            db.close()
        response = raw_client.get('/targets/')
        assert response.status_code == 401
        assert 'X-API-Key' in response.json()['detail']
        # /health stays open: the UI's reachability poll depends on it.
        assert raw_client.get('/health').status_code == 200
    finally:
        if saved is not None:
            os.environ[api_auth.API_KEY_ENV_VAR] = saved


def test_unconfigured_backend_fails_closed(raw_client):
    """No env var and no stored digest: everything but /health is refused."""
    saved = os.environ.pop(api_auth.API_KEY_ENV_VAR, None)
    try:
        # Fresh override DB, no settings row at all.
        response = raw_client.get('/targets/')
        assert response.status_code == 503
        assert raw_client.get('/health').status_code == 200
    finally:
        if saved is not None:
            os.environ[api_auth.API_KEY_ENV_VAR] = saved


def test_wrong_key_is_refused(raw_client):
    response = raw_client.get('/targets/', headers={'X-API-Key': 'not-the-key'})
    assert response.status_code == 401


def test_right_key_is_accepted(raw_client):
    response = raw_client.get('/targets/', headers={'X-API-Key': OPERATOR_TEST_KEY})
    assert response.status_code == 200


def test_generated_key_is_digest_compared(raw_client, monkeypatch):
    """A generated key lives only as a SHA-256 digest; the digest must work.

    ensure_operator_key returns the plaintext exactly once - the run that
    generated it - and a digest-compare of that plaintext must then pass
    while the plaintext is absent from the database entirely.
    """
    saved = os.environ.pop(api_auth.API_KEY_ENV_VAR, None)
    try:
        db = next(app.dependency_overrides[get_db]())
        try:
            plaintext = api_auth.ensure_operator_key(db)
            assert plaintext, 'first call must return the generated plaintext'
            stored = db.query(__import__('database').AppSettings).first()
            assert stored.operator_key_hash
            assert plaintext not in stored.operator_key_hash
            # Second call: the key exists, nothing new to hand out.
            assert api_auth.ensure_operator_key(db) == ''
        finally:
            db.close()
        response = raw_client.get('/targets/', headers={'X-API-Key': plaintext})
        assert response.status_code == 200
    finally:
        if saved is not None:
            os.environ[api_auth.API_KEY_ENV_VAR] = saved


def test_env_key_wins_over_stored_digest(raw_client, monkeypatch):
    """REDTEAM_API_KEY is the documented override: it is checked first."""
    monkeypatch.setenv(api_auth.API_KEY_ENV_VAR, 'env-chosen-key')
    response = raw_client.get('/targets/', headers={'X-API-Key': 'env-chosen-key'})
    assert response.status_code == 200
    response = raw_client.get('/targets/', headers={'X-API-Key': OPERATOR_TEST_KEY})
    assert response.status_code == 401
