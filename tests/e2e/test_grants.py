"""The refresh_token grant, exercised through the RP's back channel."""
import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("auth", ["basic", "post"])
def test_refresh_token_grant_rotates(rp, auth):
    """RFC 6749 §6 + RFC 9700 §2.2.2: refreshing returns a *new* refresh token."""
    state = rp.login(auth=auth)
    assert state["has_refresh_token"] is True

    rp.visit("/refresh")
    refreshed = rp.state()

    assert refreshed["error"] is None, refreshed
    assert refreshed["refresh_count"] == 1
    assert refreshed["refresh_token_rotated"] is True
    # The refreshed ID token still identifies the same user, and the RP verified
    # its signature and issuer before storing it.
    assert refreshed["id_claims"]["sub"] == "admin"


def test_refresh_requires_client_authentication(rp, idp_server):
    """An unauthenticated refresh must be rejected (RFC 6749 §6)."""
    state = rp.login()
    assert state["has_refresh_token"] is True

    # Pull the refresh token out via the RP, then present it with no credentials.
    resp = rp.page.request.post(
        f"{idp_server}/s2s/token",
        form={"grant_type": "refresh_token", "refresh_token": _refresh_token(rp)},
    )
    assert resp.status == 401
    assert resp.json()["error"] == "invalid_client"


def test_replaying_a_consumed_refresh_token_revokes_the_family(rp):
    """RFC 9700 §2.2.2: replay is detected and the whole family is revoked."""
    rp.login()
    rp.visit("/refresh")
    assert rp.state()["refresh_count"] == 1

    replay = rp.get("/replay-refresh")
    assert replay["status"] == 400
    assert "invalid_grant" in replay["body"]

    # The successor token issued by the rotation is revoked too, so the RP can
    # no longer refresh at all.
    rp.visit("/refresh")
    after = rp.state()
    assert after["error"] == "refresh_failed"


def test_refresh_without_offline_access_is_unavailable(rp):
    state = rp.login(scope="openid profile")
    assert state["has_refresh_token"] is False

    rp.visit("/refresh")
    assert rp.state()["error"] == "no_refresh_token"


def _refresh_token(rp):
    """Read the live refresh token out of the RP's server-side store."""
    return rp.get("/api/refresh-token")["refresh_token"]
