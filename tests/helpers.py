"""Shared constants and flow helpers for the in-process conformance suite.

These live here rather than in conftest.py because tests/e2e/conftest.py is also
importable as the top-level module `conftest`; a `from conftest import ...` would
resolve to whichever of the two landed in sys.modules first.
"""
import base64
import hashlib
import re
from urllib.parse import urlsplit, parse_qs

# The permanent client seeded by initApplication().
CLIENT_ID = "client_id_12decaf34bad56"
CLIENT_SECRET = "Super-+Secret_=Key0123456789"
REDIRECT_URI = "https://rp.example/cb"
USERNAME = "admin"
PASSWORD = "Hunter2!"


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
