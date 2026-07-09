"""Authorization endpoint conformance (RFC 6749 §4.1, OIDC Core §3.1)."""
import time
from urllib.parse import urlsplit, parse_qs

import jwt
import pytest

from helpers import (
    CLIENT_ID, PASSWORD, REDIRECT_URI, USERNAME, _csrf, exchange_code,
    obtain_code, pkce_pair,
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


def test_prompt_none_without_session_returns_login_required(client):
    """OIDC Core §3.1.2.1: prompt=none must never show a login page."""
    resp = _authorize(client, prompt="none")
    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert _error(location) == "login_required"
    # Reported to the RP, not by redirecting the user to authenticate.
    assert location.startswith(REDIRECT_URI)
    assert parse_qs(urlsplit(location).query)["state"] == ["st"]


def test_prompt_none_with_session_issues_a_code(client):
    """An active session satisfies prompt=none, so the flow completes silently."""
    obtain_code(client)  # establishes the SSO session
    resp = _authorize(client, prompt="none")
    query = parse_qs(urlsplit(resp.headers["Location"]).query)
    assert "code" in query
    assert "error" not in query


def test_prompt_none_combined_with_other_values_is_invalid_request(client):
    resp = _authorize(client, prompt="none%20login")
    assert _error(resp.headers["Location"]) == "invalid_request"


def _code_from(resp):
    return parse_qs(urlsplit(resp.headers["Location"]).query)["code"][0]


def test_prompt_none_does_not_sign_the_user_out(client):
    """A prompt=none probe must never mutate the session it is probing.

    An RP could otherwise sign a user out of the provider from a hidden iframe.
    """
    obtain_code(client)  # establishes the session
    resp = _authorize(client, prompt="none", max_age="0")
    assert _error(resp.headers["Location"]) == "login_required"

    # The session survived: an ordinary request still completes silently.
    assert "code" in parse_qs(urlsplit(_authorize(client).headers["Location"]).query)


@pytest.mark.parametrize("prompt", ["login", "select_account"])
def test_prompt_forces_reauthentication(client, prompt):
    """select_account is aliased to login: this login page IS the account picker."""
    obtain_code(client)  # establishes the session

    resp = _authorize(client, prompt=prompt)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/user/login")


@pytest.mark.parametrize("prompt", ["login", "select_account"])
def test_reauthentication_completes_without_looping(client, prompt):
    """The bounce back from /user/login carries no prompt, so it terminates."""
    obtain_code(client)
    _authorize(client, prompt=prompt)  # sends us to the login page

    resp = client.post("/user/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf_token": _csrf(client),
    })
    # Straight back into /c2s/authorize, which now issues a code rather than
    # bouncing to the login page again.
    resp = client.get(resp.headers["Location"])
    assert "code" in parse_qs(urlsplit(resp.headers["Location"]).query)


def test_max_age_zero_forces_reauthentication(client):
    obtain_code(client)
    resp = _authorize(client, max_age="0")
    assert resp.headers["Location"].endswith("/user/login")


def test_generous_max_age_reuses_the_session(client):
    obtain_code(client)
    resp = _authorize(client, max_age="3600")
    assert "code" in parse_qs(urlsplit(resp.headers["Location"]).query)


def test_max_age_must_be_a_non_negative_integer(client):
    assert _error(_authorize(client, max_age="soon").headers["Location"]) == "invalid_request"
    assert _error(_authorize(client, max_age="-1").headers["Location"]) == "invalid_request"


def test_forced_reauthentication_advances_auth_time(client):
    """auth_time must reflect the new authentication, not the original one.

    A max_age client reads auth_time to decide whether its demand was met, so a
    reused Authorization row carrying a stale authentication_start would let the
    provider silently ignore max_age.
    """
    obtain_code(client)
    before = _auth_time(client, _code_from(_authorize(client)))

    time.sleep(1.1)  # auth_time is integer seconds, so the clock must move
    _authorize(client, prompt="login")
    resp = client.post("/user/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf_token": _csrf(client),
    })
    resp = client.get(resp.headers["Location"])
    after = _auth_time(client, _code_from(resp))

    assert after > before


def _auth_time(client, code):
    body = exchange_code(client, code).get_json()
    return jwt.decode(body["id_token"], options={"verify_signature": False})["auth_time"]


def test_code_lifetime_is_ten_minutes_and_outlived_by_the_sso_session(app):
    """RFC 6749 §4.1.2 RECOMMENDS a 10-minute maximum code lifetime.

    The SSO session deliberately outlives it: a code must expire quickly, while
    a session exists so it can satisfy more than one authorization request.
    """
    from datetime import datetime, timezone

    from app.models.authorization import Authorization

    client = app.test_client()
    obtain_code(client)

    with app.app_context():
        authorization = Authorization.query.one()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        code_ttl = (authorization.code_expires_at - now).total_seconds()
        session_ttl = (authorization.session_valid - now).total_seconds()

    assert 590 < code_ttl <= 600
    assert session_ttl > code_ttl


def test_reissued_code_gets_a_fresh_lifetime(app):
    """A code minted on a partly-spent SSO session still gets its full window."""
    from datetime import datetime, timedelta, timezone

    from app.extensions import db
    from app.models.authorization import Authorization

    client = app.test_client()
    obtain_code(client)

    # Age the SSO session and the outstanding code by five minutes.
    with app.app_context():
        authorization = Authorization.query.one()
        authorization.code_expires_at -= timedelta(minutes=5)
        db.session.commit()

    _authorize(client)  # mints a new code on the same session

    with app.app_context():
        authorization = Authorization.query.one()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        assert (authorization.code_expires_at - now).total_seconds() > 590


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
