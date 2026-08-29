"""Credentials must be encrypted at rest and must never leave through the API."""
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import AppSettings, Base, get_db
from main import app
from modules.secret_store import PREFIX, decrypt_secret, encrypt_secret, is_encrypted

API_KEY = 'sk-live-do-not-leak-me'
PROXY_PASSWORD = 'proxy-secret-do-not-leak'


@pytest.fixture
def key(tmp_path, monkeypatch):
    """Pin the master key so tests never touch the real data/.secret_key."""
    monkeypatch.setenv('REDTEAM_SECRET_KEY', Fernet.generate_key().decode())
    return None


@pytest.fixture
def session_factory():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(session_factory):
    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def test_roundtrip_recovers_the_original_value(key):
    stored = encrypt_secret(API_KEY)

    assert stored != API_KEY
    assert API_KEY not in stored
    assert is_encrypted(stored)
    assert decrypt_secret(stored) == API_KEY


def test_same_value_encrypts_differently_each_time(key):
    """Fernet nonces mean identical keys must not produce identical ciphertext."""
    assert encrypt_secret(API_KEY) != encrypt_secret(API_KEY)


def test_already_encrypted_value_is_not_double_encrypted(key):
    once = encrypt_secret(API_KEY)

    assert encrypt_secret(once) == once


def test_unreadable_ciphertext_degrades_to_unset(key, monkeypatch):
    """A rotated or lost master key must read as 'no provider', not crash."""
    stored = encrypt_secret(API_KEY)
    monkeypatch.setenv('REDTEAM_SECRET_KEY', Fernet.generate_key().decode())

    assert decrypt_secret(stored) == ''


def test_legacy_plaintext_is_still_readable(key):
    """A credential stored before encryption existed must not be lost."""
    assert decrypt_secret(API_KEY) == API_KEY
    assert not is_encrypted(API_KEY)


def test_settings_are_stored_encrypted_and_never_returned(client, session_factory, key):
    response = client.put('/settings', json={
        'gemini_api_key': API_KEY,
        'api_base_url': 'https://provider.example/v1',
        'model_name': 'test-model',
        'proxy_url': 'http://proxy.example:8080',
        'proxy_username': 'operator',
        'proxy_password': PROXY_PASSWORD,
    })

    assert response.status_code == 200
    body = response.text
    # Neither secret may appear anywhere in the response, in any form.
    assert API_KEY not in body
    assert PROXY_PASSWORD not in body
    assert response.json()['gemini_configured'] is True
    assert response.json()['provider_ready'] is True

    db = session_factory()
    try:
        row = db.query(AppSettings).filter(AppSettings.id == 1).first()
        # ...and neither may be sitting in the database as plaintext.
        assert row.gemini_api_key.startswith(PREFIX)
        assert row.proxy_password.startswith(PREFIX)
        assert API_KEY not in row.gemini_api_key
        assert PROXY_PASSWORD not in row.proxy_password
        # Non-secret settings stay readable.
        assert row.api_base_url == 'https://provider.example/v1'
    finally:
        db.close()


def test_get_settings_never_exposes_secret_fields(client, key):
    client.put('/settings', json={'gemini_api_key': API_KEY, 'proxy_url': 'http://p:8080', 'proxy_password': PROXY_PASSWORD})

    payload = client.get('/settings').json()

    assert 'gemini_api_key' not in payload
    assert 'proxy_password' not in payload
    assert API_KEY not in client.get('/settings').text


def test_blank_secret_submission_keeps_the_stored_value(client, key):
    client.put('/settings', json={'gemini_api_key': API_KEY, 'api_base_url': 'https://p.example/v1', 'model_name': 'm'})

    client.put('/settings', json={'gemini_api_key': '', 'model_name': 'changed-model'})

    payload = client.get('/settings').json()
    assert payload['gemini_configured'] is True
    assert payload['model_name'] == 'changed-model'


def test_no_environment_variable_can_seed_a_credential(client, monkeypatch, key):
    """The operator's own key is the only way a provider gets configured."""
    for name in ('GEMINI_API_KEY', 'API_BASE_URL', 'MODEL_NAME'):
        monkeypatch.setenv(name, 'should-be-ignored')

    payload = client.get('/settings').json()

    assert payload['gemini_configured'] is False
    assert payload['provider_ready'] is False
    assert payload['api_base_url'] == ''
    assert payload['model_name'] == ''


def test_partial_configuration_is_not_provider_ready(client, key):
    client.put('/settings', json={'gemini_api_key': API_KEY})

    payload = client.get('/settings').json()

    assert payload['gemini_configured'] is True
    assert payload['provider_ready'] is False


def test_decrypted_password_reaches_the_proxy_environment(client, session_factory, key):
    """Encryption must be transparent to the code that consumes the secret."""
    from main import proxy_environment

    client.put('/settings', json={
        'proxy_url': 'http://proxy.example:8080',
        'proxy_username': 'operator',
        'proxy_password': PROXY_PASSWORD,
    })

    db = session_factory()
    try:
        row = db.query(AppSettings).filter(AppSettings.id == 1).first()
        env = proxy_environment(row)
    finally:
        db.close()

    assert env['HTTP_PROXY'] == f'http://operator:{PROXY_PASSWORD}@proxy.example:8080'


def test_clearing_the_proxy_url_clears_its_credentials(client, session_factory, key):
    client.put('/settings', json={'proxy_url': 'http://p:8080', 'proxy_username': 'u', 'proxy_password': PROXY_PASSWORD})

    client.put('/settings', json={'proxy_url': ''})

    db = session_factory()
    try:
        row = db.query(AppSettings).filter(AppSettings.id == 1).first()
        assert row.proxy_username == ''
        assert row.proxy_password == ''
    finally:
        db.close()
