"""Step 5: the tokens the RP was issued actually work against the provider."""
import pytest

pytestmark = pytest.mark.e2e


def test_access_token_works_at_userinfo(rp):
    rp.login(persona="it")

    resp = rp.get("/api/userinfo")
    assert resp["status"] == 200
    claims = resp["body"]
    assert claims["sub"] == "it"
    assert claims["name"] == "Moss"
    assert claims["groups"] == "Users,IT,service_admins"


def test_access_token_is_active_at_introspection(rp):
    rp.login(persona="auditor")

    resp = rp.get("/api/introspect")
    assert resp["status"] == 200
    body = resp["body"]
    assert body["active"] is True
    assert body["sub"] == "auditor"


def test_userinfo_honours_granted_scope(rp):
    """Claims released at UserInfo track the scope actually granted."""
    rp.login(scope="openid")

    claims = rp.get("/api/userinfo")["body"]
    assert claims["sub"] == "admin"
    assert "name" not in claims
    assert "groups" not in claims


def test_rotated_access_token_still_works(rp):
    """A token issued by the refresh grant is usable at protected resources."""
    rp.login()
    rp.visit("/refresh")
    assert rp.state()["refresh_count"] == 1

    resp = rp.get("/api/userinfo")
    assert resp["status"] == 200
    assert resp["body"]["sub"] == "admin"


def test_userinfo_rejects_a_missing_token(rp, idp_server):
    resp = rp.page.request.get(f"{idp_server}/s2s/userinfo")
    assert resp.status == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")
