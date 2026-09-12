"""Shared pytest configuration.

Sets the operator API key the way a scripted deployment would: through the
environment. Every TestClient fixture in the suite passes this value in the
X-API-Key header, so the protected routes behave exactly as they do against a
real backend with a key chosen by the operator. api_auth's own tests bypass
this and exercise the refusal paths directly.
"""
import os

OPERATOR_TEST_KEY = 'test-operator-key'
os.environ.setdefault('REDTEAM_API_KEY', OPERATOR_TEST_KEY)
