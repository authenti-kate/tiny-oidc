"""prompt=consent: a minimal, all-or-nothing, non-persisted consent screen."""
import re
from urllib.parse import parse_qs, urlsplit

from helpers import CLIENT_ID, PASSWORD, REDIRECT_URI, USERNAME, _csrf


def _authorize(client, **overrides):
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid%20profile",
        "state": "st",
    }
    params.update(overrides)
    query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return client.get(f"/c2s/authorize?{query}")


def _log_in(client):
    resp = client.post("/user/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf_token": _csrf(client),
    })
    return client.get(resp.headers["Location"])


def _consent_csrf(client):
    body = client.get("/user/consent").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)


def _decide(client, decision):
    return client.post("/user/consent", data={
        "decision": decision, "csrf_token": _consent_csrf(client),
    })


def _query(resp):
    return parse_qs(urlsplit(resp.headers["Location"]).query)


def test_consent_is_only_asked_for_when_requested(client):
    """No consent store means no consent gate on an ordinary request."""
    _authorize(client)
    resp = _log_in(client)
    assert "code" in _query(resp)


def test_prompt_consent_shows_the_screen_after_login(client):
    """A cold start logs in first, then still owes a consent decision."""
    assert _authorize(client, prompt="consent").headers["Location"].endswith("/user/login")
    resp = _log_in(client)
    assert resp.headers["Location"].endswith("/user/consent")


def test_prompt_consent_shows_the_screen_when_already_signed_in(client):
    _authorize(client)
    _log_in(client)
    resp = _authorize(client, prompt="consent")
    assert resp.headers["Location"].endswith("/user/consent")


def test_consent_screen_lists_the_requested_scopes(client):
    _authorize(client, prompt="consent")
    _log_in(client)
    body = client.get("/user/consent").get_data(as_text=True)
    assert "<code>openid</code>" in body
    assert "<code>profile</code>" in body
    assert CLIENT_ID in body


def test_accepting_consent_issues_a_code(client):
    _authorize(client, prompt="consent")
    _log_in(client)

    resp = _decide(client, "accept")
    # Back into /c2s/authorize, which now falls straight through to a code.
    assert resp.headers["Location"].startswith("/c2s/authorize")
    resp = client.get(resp.headers["Location"])
    assert "code" in _query(resp)


def test_rejecting_consent_returns_access_denied(client):
    """RFC 6749 §4.1.2.1: the resource owner denied the request."""
    _authorize(client, prompt="consent")
    _log_in(client)

    resp = _decide(client, "reject")
    query = _query(resp)
    assert resp.headers["Location"].startswith(REDIRECT_URI)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["st"]


def test_consent_is_not_remembered(client):
    """Nothing is persisted, so the next prompt=consent asks again."""
    _authorize(client, prompt="consent")
    _log_in(client)
    _decide(client, "accept")

    resp = _authorize(client, prompt="consent")
    assert resp.headers["Location"].endswith("/user/consent")


def test_answering_consent_does_not_leave_a_gate_behind(client):
    """Once answered, a request that did not ask for consent goes straight through."""
    _authorize(client, prompt="consent")
    _log_in(client)
    _decide(client, "accept")

    assert "code" in _query(_authorize(client))


def test_consent_screen_escapes_the_scope(client):
    """scope is client-supplied and is rendered, so it must not be reflected raw."""
    _authorize(client, prompt="consent", scope="openid%20%3Cscript%3Ealert(1)%3C/script%3E")
    _log_in(client)

    body = client.get("/user/consent").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_consent_requires_a_csrf_token(client):
    _authorize(client, prompt="consent")
    _log_in(client)

    resp = client.post("/user/consent", data={"decision": "accept", "csrf_token": "wrong"})
    assert resp.headers["Location"].endswith("/user/consent")
    # The decision was not recorded, so the screen is still owed.
    assert _authorize(client).headers["Location"].endswith("/user/consent")


def test_consent_page_is_unreachable_without_a_pending_request(client):
    resp = client.get("/user/consent")
    assert resp.status_code == 302
    assert not resp.headers["Location"].endswith("/user/consent")


def test_prompt_login_and_consent_combine(client):
    """"login consent" re-authenticates first, then asks for consent."""
    _authorize(client)
    _log_in(client)

    assert _authorize(client, prompt="login%20consent").headers["Location"].endswith("/user/login")
    resp = _log_in(client)
    assert resp.headers["Location"].endswith("/user/consent")

    resp = client.get(_decide(client, "accept").headers["Location"])
    assert "code" in _query(resp)
