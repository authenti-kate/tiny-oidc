"""Shared fixtures and helpers for the spec-conformance test suite.

Each test gets a fresh app backed by a throwaway file-based SQLite database so
the auto-created schema always matches the current models.
"""
import base64
import hashlib
import re
import tempfile
import os
from urllib.parse import urlsplit, parse_qs

import pytest

from app import create_app
from config import Config

# The permanent client seeded by initApplication().
CLIENT_ID = "client_id_12decaf34bad56"
CLIENT_SECRET = "Super-+Secret_=Key0123456789"
REDIRECT_URI = "https://rp.example/cb"
USERNAME = "admin"
PASSWORD = "Hunter2!"


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class TestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
        SECRET_KEY = "test-secret"

    application = create_app(TestConfig)
    yield application
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


def pkce_pair():
    """Return (code_verifier, code_challenge) for S256."""
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _csrf(client):
    body = client.get("/user/login").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)


def obtain_code(client, scope="openid profile groups offline_access",
                state="state123", challenge=None, method="S256"):
    """Drive authorize -> login -> authorize and return the authorization code."""
    params = (
        f"/c2s/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        f"&response_type=code&scope={scope.replace(' ', '%20')}&state={state}&nonce=n1"
    )
    if challenge:
        params += f"&code_challenge={challenge}&code_challenge_method={method}"
    client.get(params)
    resp = client.post("/user/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf_token": _csrf(client),
    })
    # Follow the post-login redirect back into the authorization endpoint.
    resp = client.get(resp.headers["Location"])
    location = resp.headers["Location"]
    return parse_qs(urlsplit(location).query)["code"][0], location


def exchange_code(client, code, verifier=None, client_secret=CLIENT_SECRET):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
    }
    if client_secret is not None:
        data["client_secret"] = client_secret
    if verifier is not None:
        data["code_verifier"] = verifier
    return client.post("/s2s/token", data=data)
