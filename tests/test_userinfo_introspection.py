"""UserInfo (RFC 6750) and Introspection (RFC 7662) conformance."""
from helpers import (
    CLIENT_ID, CLIENT_SECRET, obtain_code, exchange_code, pkce_pair,
)


def _tokens(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    return exchange_code(client, code, verifier=verifier).get_json()


def test_userinfo_requires_bearer(client):
    resp = client.get("/s2s/userinfo")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"].startswith("Bearer")


def test_userinfo_rejects_garbage_token(client):
    resp = client.get("/s2s/userinfo", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401
    assert "invalid_token" in resp.headers["WWW-Authenticate"]


def test_userinfo_returns_sub_and_scoped_claims(client):
    tokens = _tokens(client)
    resp = client.get("/s2s/userinfo",
                      headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert resp.status_code == 200
    claims = resp.get_json()
    assert claims["sub"] == "admin"
    # profile + groups were requested by obtain_code's default scope.
    assert "name" in claims and "groups" in claims


def test_userinfo_rejects_id_token(client):
    tokens = _tokens(client)
    resp = client.get("/s2s/userinfo",
                      headers={"Authorization": f"Bearer {tokens['id_token']}"})
    assert resp.status_code == 401


def test_introspection_requires_caller_auth(client):
    tokens = _tokens(client)
    resp = client.post("/s2s/introspection", data={"token": tokens["access_token"]})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid_client"


def test_introspection_active_true_for_valid_token(client):
    tokens = _tokens(client)
    resp = client.post("/s2s/introspection", data={
        "token": tokens["access_token"],
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    })
    body = resp.get_json()
    assert body["active"] is True
    assert body["sub"] == "admin"


def test_introspection_inactive_for_garbage(client):
    resp = client.post("/s2s/introspection", data={
        "token": "garbage",
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    })
    assert resp.status_code == 200
    assert resp.get_json() == {"active": False}
