"""Authorization endpoint conformance (RFC 6749 §4.1, OIDC Core §3.1)."""
from urllib.parse import urlsplit, parse_qs

import jwt

from helpers import (
    CLIENT_ID, REDIRECT_URI, exchange_code, obtain_code, pkce_pair,
)


def _authorize(client, **overrides):
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "state": "st",
    }
    params.update(overrides)
    query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return client.get(f"/c2s/authorize?{query}")


def _error(location):
    return parse_qs(urlsplit(location).query).get("error", [None])[0]


def test_unknown_client_does_not_redirect(client):
    # C1/M8: an invalid client_id must NOT redirect (open-redirect guard).
    resp = _authorize(client, client_id="does-not-exist")
    assert resp.status_code == 400
    assert not resp.headers.get("Location")


def test_bad_response_type_redirects_with_error(client):
    resp = _authorize(client, response_type="token")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert _error(loc) == "unsupported_response_type"
    assert parse_qs(urlsplit(loc).query)["state"] == ["st"]


def test_missing_openid_scope_is_invalid_scope(client):
    resp = _authorize(client, scope="profile")
    assert _error(resp.headers["Location"]) == "invalid_scope"


def test_valid_request_without_state_proceeds_to_login(client):
    # L5: state is optional.
    resp = _authorize(client, state=None)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/user/login")


def test_reused_sso_session_drops_previous_pkce_and_nonce(client):
    """code_challenge and nonce bind to one authorization request, not the SSO
    session (RFC 7636 §4.4, OIDC Core §3.1.3.6).

    A second request that omits them must not inherit the first request's
    values, otherwise the fresh code is bound to a verifier this client never
    chose and the ID token carries a stale nonce.
    """
    _, challenge = pkce_pair()
    obtain_code(client, challenge=challenge)  # first request: PKCE + nonce=n1

    # Second request on the same session: no code_challenge, no nonce.
    resp = _authorize(client)
    code = parse_qs(urlsplit(resp.headers["Location"]).query)["code"][0]

    # Redeemable without a verifier, because no challenge was requested.
    token = exchange_code(client, code)
    assert token.status_code == 200, token.get_data(as_text=True)[:200]

    claims = jwt.decode(
        token.get_json()["id_token"], options={"verify_signature": False}
    )
    assert "nonce" not in claims
