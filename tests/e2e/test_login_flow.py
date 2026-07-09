"""End-to-end authorization code flow, driven through a real browser.

Each test walks the full workflow:
  1. start at the RP
  2. the RP redirects to the provider
  3. the provider prompts; Playwright picks an authentication profile
  4. the provider redirects back to the RP with a code, which the RP redeems
  5. the RP proves the resulting session works
"""
import pytest

from personas import PERSONAS

pytestmark = pytest.mark.e2e

CLIENT_AUTH_METHODS = ["basic", "post"]
PKCE_MODES = ["S256", "plain", "implicit-plain", "none"]


@pytest.mark.parametrize("auth", CLIENT_AUTH_METHODS)
@pytest.mark.parametrize("pkce", PKCE_MODES)
def test_authorization_code_flow(rp, auth, pkce):
    """Every client-auth x PKCE combination the provider advertises must work."""
    state = rp.login(persona="admin", auth=auth, pkce=pkce)

    assert state["error"] is None, state
    assert state["authenticated"] is True
    assert state["client_auth"] == auth
    assert state["pkce"] == pkce

    # The RP verified the id_token signature, issuer, audience and nonce before
    # storing these claims, so reaching here already proves those hold.
    assert state["id_claims"]["sub"] == "admin"
    assert state["token_type"] == "Bearer"
    assert state["expires_in"] == 3600


@pytest.mark.parametrize("persona", sorted(PERSONAS))
def test_each_persona_yields_its_own_claims(rp, persona):
    """Step 3's profile selection must drive the claims the RP ends up with."""
    state = rp.login(persona=persona)
    expected = PERSONAS[persona]

    assert state["error"] is None, state
    claims = state["id_claims"]
    assert claims["sub"] == persona
    assert claims["name"] == expected["name"]
    assert claims["groups"] == expected["groups"]


def test_scope_controls_claims_released(rp):
    """openid alone releases sub and nothing else (OIDC Core §5.4)."""
    state = rp.login(scope="openid")

    assert state["error"] is None, state
    claims = state["id_claims"]
    assert claims["sub"] == "admin"
    assert "name" not in claims
    assert "groups" not in claims
    assert "email" not in claims
    # offline_access was not requested, so no refresh token is issued.
    assert state["has_refresh_token"] is False


def test_offline_access_yields_a_refresh_token(rp):
    state = rp.login(scope="openid profile offline_access")
    assert state["has_refresh_token"] is True


def test_sso_session_reuses_login_without_reprompting(rp):
    """A second authorization request within the session window skips the prompt.

    The provider reuses the Authorization row but must mint a fresh single-use
    code (authorize.py:158), so the RP still ends up with a working session.
    """
    first = rp.login()
    assert first["error"] is None

    # Start a fresh authorization request in the same browser context. The IdP
    # cookie is still set, so it should go straight through to the callback.
    rp.start_login()
    rp.page.wait_for_url(f"{rp.rp_url}/session")

    second = rp.state()
    assert second["error"] is None, second
    assert second["id_claims"]["sub"] == "admin"
    assert second["id_claims"]["jti"] != first["id_claims"]["jti"]


def test_unknown_client_shows_an_error_without_redirecting(rp):
    """C1/M8: an unregistered client_id must not be redirected anywhere."""
    from urllib.parse import urlencode

    params = urlencode({
        "client_id": "does-not-exist",
        "redirect_uri": f"{rp.rp_url}/callback",
        "response_type": "code",
        "scope": "openid",
        "state": "st",
    })
    resp = rp.page.goto(f"{rp.idp_url}/c2s/authorize?{params}")

    assert resp.status == 400
    # The browser must still be on the provider, not bounced to redirect_uri.
    assert rp.page.url.startswith(rp.idp_url)
