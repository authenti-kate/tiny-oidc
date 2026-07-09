"""Token endpoint conformance (RFC 6749 §4.1.3/§5.2/§6, RFC 7636, RFC 9700)."""
import base64
from urllib.parse import quote

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


def test_error_responses_are_json_with_an_error_code(client):
    """RFC 6749 §5.2: errors are a JSON object carrying an `error` code."""
    cases = [
        # (form data, expected error code)
        ({"grant_type": "authorization_code", "client_id": CLIENT_ID,
          "client_secret": CLIENT_SECRET}, "invalid_request"),
        ({"grant_type": "authorization_code", "code": "no-such-code",
          "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, "invalid_grant"),
        ({"grant_type": "refresh_token", "client_id": CLIENT_ID,
          "client_secret": CLIENT_SECRET}, "invalid_request"),
        ({"grant_type": "refresh_token", "refresh_token": "no-such-token",
          "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, "invalid_grant"),
    ]
    for data, expected in cases:
        resp = client.post("/s2s/token", data=data)
        assert resp.status_code == 400, data
        assert resp.mimetype == "application/json", data
        assert resp.get_json()["error"] == expected, data


def test_pkce_failure_is_invalid_grant_json(client):
    """RFC 7636 §4.6 reports a bad verifier through the §5.2 error response."""
    _, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = exchange_code(client, code, verifier="b" * 64)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_grant"


def test_token_responses_are_not_cacheable(client):
    """RFC 6749 §5.1/§5.2: both success and error responses set no-store."""
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    success = exchange_code(client, code, verifier=verifier)
    assert success.status_code == 200
    assert success.headers["Cache-Control"] == "no-store"

    failure = client.post("/s2s/token", data={"grant_type": "password"})
    assert failure.headers["Cache-Control"] == "no-store"


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


def test_client_secret_basic_accepts_urlencoded_credentials(client):
    """RFC 6749 §2.3.1: credentials are form-urlencoded before base64 encoding.

    The seeded secret contains '+' and '=', so a strictly conformant client
    sends something different on the wire from the raw form above. Both must
    authenticate.
    """
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, challenge=challenge)
    resp = _basic_exchange(
        client, code, verifier,
        quote(CLIENT_ID, safe=""), quote(CLIENT_SECRET, safe=""),
    )
    assert resp.status_code == 200
