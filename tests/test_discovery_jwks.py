"""Discovery document and JWKS conformance (OIDC Discovery 1.0, RFC 7517)."""
from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models.application import Application


def test_discovery_required_fields(client):
    doc = client.get("/.well-known/openid-configuration").get_json()
    for field in ("issuer", "authorization_endpoint", "token_endpoint",
                  "jwks_uri", "response_types_supported",
                  "subject_types_supported",
                  "id_token_signing_alg_values_supported"):
        assert field in doc, f"missing required discovery field {field}"


def test_discovery_advertises_only_implemented_behaviour(client):
    doc = client.get("/.well-known/openid-configuration").get_json()
    # C4 / M3-M5: advertised metadata matches the implementation.
    assert doc["response_types_supported"] == ["code"]
    assert set(doc["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert "offline_access" in doc["scopes_supported"]
    assert "offline" not in doc["scopes_supported"]
    assert doc["request_parameter_supported"] is False
    assert set(doc["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic", "client_secret_post"}
    # Every advertised prompt value is actually honoured; "create" is not.
    assert set(doc["prompt_values_supported"]) == {
        "none", "login", "consent", "select_account"}
    assert "create" not in doc["prompt_values_supported"]


def test_fixed_issuer_beats_host_header(app):
    app.config["OIDC_ISSUER"] = "https://oidc.example.com"
    doc = app.test_client().get(
        "/.well-known/openid-configuration", headers={"Host": "evil.example"}
    ).get_json()
    assert doc["issuer"] == "https://oidc.example.com"
    assert doc["jwks_uri"].startswith("https://oidc.example.com")


def test_jwks_shape_and_excludes_expired(app):
    with app.app_context():
        db.session.add(Application(
            client_id="expired", client_secret="x",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
        db.session.commit()
        expired_kid = Application.query.filter_by(client_id="expired").one().key_id

    resp = app.test_client().get("/s2s/keys")
    assert resp.headers.get("Cache-Control")
    keys = resp.get_json()["keys"]
    assert keys, "expected at least the permanent client's key"
    for jwk in keys:
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert jwk["kid"] and jwk["n"] and jwk["e"]
    assert expired_kid not in {k["kid"] for k in keys}
