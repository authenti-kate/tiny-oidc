"""Token endpoint conformance (RFC 6749 §4.1.3/§5.2/§6, RFC 7636, RFC 9700)."""
import base64
from urllib.parse import quote

import pytest

from helpers import (
    CLIENT_ID, CLIENT_SECRET, obtain_code, exchange_code, pkce_pair,
)


def test_unsupported_grant_type(client):
    resp = client.post("/s2s/token", data={"grant_type": "password"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "unsupported_grant_type"


def test_code_exchange_requires_client_secret(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = exchange_code(client, code, verifier=verifier, client_secret=None)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid_client"


def test_code_exchange_rejects_wrong_secret(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = exchange_code(client, code, verifier=verifier, client_secret="wrong")
    assert resp.status_code == 401


def test_pkce_wrong_verifier_rejected(client):
    _, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = exchange_code(client, code, verifier="b" * 64)
    assert resp.status_code == 400


def test_authorization_code_is_single_use(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    assert exchange_code(client, code, verifier=verifier).status_code == 200
    replay = exchange_code(client, code, verifier=verifier)
    assert replay.status_code == 400
    assert replay.get_json()["error"] == "invalid_grant"


def test_full_flow_issues_all_tokens(client):
    verifier, challenge = pkce_pair()
    code, location = obtain_code(client, challenge=challenge)
    assert "state=state123" in location
    body = exchange_code(client, code, verifier=verifier).get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    for key in ("id_token", "access_token", "refresh_token"):
        assert key in body


def _refresh(client, token, secret=CLIENT_SECRET):
    data = {"grant_type": "refresh_token", "refresh_token": token,
            "client_id": CLIENT_ID}
    if secret is not None:
        data["client_secret"] = secret
    return client.post("/s2s/token", data=data)


def test_refresh_rotation_and_replay_revokes_family(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    first = exchange_code(client, code, verifier=verifier).get_json()
    rt1 = first["refresh_token"]

    rotated = _refresh(client, rt1)
    assert rotated.status_code == 200
    rt2 = rotated.get_json()["refresh_token"]

    # Replaying the consumed token is rejected and revokes the family.
    replay = _refresh(client, rt1)
    assert replay.status_code == 400
    assert replay.get_json()["error"] == "invalid_grant"
    # The rotated successor is now revoked too.
    assert _refresh(client, rt2).status_code != 200


def test_refresh_requires_client_auth(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    rt = exchange_code(client, code, verifier=verifier).get_json()["refresh_token"]
    assert _refresh(client, rt, secret=None).status_code == 401


def _basic_exchange(client, code, verifier, client_id, client_secret):
    header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return client.post("/s2s/token", data={
        "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
    }, headers={"Authorization": f"Basic {header}"})


def test_client_secret_basic_accepts_raw_credentials(client):
    """The form used by requests, and by most clients in practice."""
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = _basic_exchange(client, code, verifier, CLIENT_ID, CLIENT_SECRET)
    assert resp.status_code == 200


@pytest.mark.xfail(
    strict=True,
    reason="RFC 6749 §2.3.1 requires the client_id and client_secret to be "
           "form-urlencoded before base64 encoding; client_credentials() never "
           "urldecodes them, so a strictly conformant client is rejected "
           "whenever the secret contains reserved characters (the seeded "
           "secret contains '+' and '='). Remove this marker once "
           "app/views/server_to_server/__init__.py unquotes both parts.",
)
def test_client_secret_basic_accepts_urlencoded_credentials(client):
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = _basic_exchange(
        client, code, verifier,
        quote(CLIENT_ID, safe=""), quote(CLIENT_SECRET, safe=""),
    )
    assert resp.status_code == 200
