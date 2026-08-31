"""The `kid` published in JWKS and carried in every JWS header.

RFC 7515 §4.1.4 makes `kid` a hint used to select a key. RFC 7638 defines the
JWK thumbprint, which is the conventional value: short, stable, and derivable
by the client from the JWK it already has.

tiny-oidc previously used the entire PEM public key, via
`base64.b64encode(str(self.rsa_public_key).encode()).hex()` — where
`rsa_public_key` is `bytes`, so `str()` produced the repr and baked a literal
`b'` prefix and `\\n` escapes into the value. The result was a 1240-character
kid and a ~1702-byte JOSE header, which real clients reject: joserfc (the JWS
backend used by Authlib) caps headers at 512 bytes as a denial-of-service
guard, because the header is parsed before any signature is verified.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.extensions import db
from app.models.application import Application


def _expected_thumbprint(pem: bytes) -> str:
    """RFC 7638 §3, computed independently of the implementation: SHA-256 over
    the required members only, lexicographic order, no whitespace."""
    public_key = serialization.load_pem_public_key(pem)
    assert isinstance(public_key, rsa.RSAPublicKey)
    numbers = public_key.public_numbers()

    def b64u(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    canonical = json.dumps(
        {"e": b64u(numbers.e), "kty": "RSA", "n": b64u(numbers.n)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def test_new_application_kid_is_an_rfc7638_thumbprint(app):
    with app.app_context():
        application = Application(client_id="thumbprint-check", client_secret="x")
        db.session.add(application)
        db.session.commit()

        assert application.key_id == _expected_thumbprint(application.rsa_public_key)


def test_kid_is_short_enough_for_a_real_jws_header(app):
    # The specific failure this fixes: a JOSE header over 512 bytes is
    # rejected outright by joserfc, so every ID token was undecodable.
    with app.app_context():
        application = Application(client_id="header-size", client_secret="x")
        db.session.add(application)
        db.session.commit()

        header = json.dumps(
            {"alg": "RS256", "kid": application.key_id, "typ": "JWT"},
            separators=(",", ":"),
        ).encode()
        encoded = base64.urlsafe_b64encode(header).rstrip(b"=")
        assert len(encoded) <= 512, f"JOSE header is {len(encoded)} bytes"


def test_kid_carries_no_pem_armour_or_bytes_repr(app):
    with app.app_context():
        application = Application(client_id="no-armour", client_secret="x")
        db.session.add(application)
        db.session.commit()

        # The old value hex-decoded to base64 of "b'-----BEGIN PUBLIC KEY..."
        assert "BEGIN" not in application.key_id
        try:
            decoded = bytes.fromhex(application.key_id)
        except ValueError:
            decoded = b""
        assert b"BEGIN" not in decoded and not decoded.startswith(b"Yict")


def test_kid_is_stable_for_the_same_key(app):
    with app.app_context():
        application = Application(client_id="stable", client_secret="x")
        db.session.add(application)
        db.session.commit()

        assert Application.compute_key_id(application.rsa_public_key) == application.key_id


def test_kid_differs_between_applications(app):
    with app.app_context():
        first = Application(client_id="first", client_secret="x")
        second = Application(client_id="second", client_secret="x")
        db.session.add_all([first, second])
        db.session.commit()

        assert first.key_id != second.key_id


def test_legacy_kids_are_backfilled(app):
    # Existing deployments have rows carrying the old PEM-derived kid, and
    # there is no migration framework here. Startup must repair them, or the
    # published JWKS keeps serving a kid no client can use.
    from app.models.application import backfill_key_ids

    with app.app_context():
        application = Application(client_id="legacy", client_secret="x")
        db.session.add(application)
        db.session.commit()

        correct = application.key_id
        legacy = base64.b64encode(str(application.rsa_public_key).encode("utf-8")).hex()
        application.key_id = legacy
        db.session.commit()
        assert Application.query.filter_by(client_id="legacy").one().key_id == legacy

        backfill_key_ids()

        assert Application.query.filter_by(client_id="legacy").one().key_id == correct


def test_backfill_leaves_correct_kids_untouched(app):
    from app.models.application import backfill_key_ids

    with app.app_context():
        application = Application(client_id="already-fine", client_secret="x")
        db.session.add(application)
        db.session.commit()
        before = application.key_id

        backfill_key_ids()

        assert Application.query.filter_by(client_id="already-fine").one().key_id == before


def test_backfill_repairs_expired_applications_too(app):
    # /s2s/keys skips expired applications, but /s2s/introspect and
    # /s2s/userinfo still look up by kid, so a stale value there is a live
    # failure for any token issued before expiry.
    from app.models.application import backfill_key_ids

    with app.app_context():
        application = Application(
            client_id="legacy-expired",
            client_secret="x",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db.session.add(application)
        db.session.commit()
        correct = application.key_id
        application.key_id = "clearly-wrong"
        db.session.commit()

        backfill_key_ids()

        assert Application.query.filter_by(client_id="legacy-expired").one().key_id == correct


def test_published_jwks_kid_matches_the_thumbprint_of_the_published_key(app, client):
    # The whole point of a thumbprint kid: a client can recompute it from the
    # `n`/`e` it was just handed and get the same answer.
    resp = client.get("/s2s/keys")
    keys = resp.get_json()["keys"]
    assert keys

    for jwk in keys:
        canonical = json.dumps(
            {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
        assert jwk["kid"] == expected
