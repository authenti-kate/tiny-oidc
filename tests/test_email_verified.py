"""The `email_verified` claim.

OIDC Core §5.1 defines `email_verified` as a boolean stating whether the
provider has verified that the address belongs to the end user. Relying
parties are entitled to treat a bare `email` with no such assertion as
unverified — and security-sensitive ones do: an email claim an IdP has not
vouched for is just a string the token holder chose, which matters wherever
the address is used as an identity rather than as a display value.

tiny-oidc emitted `email` alone, so those clients could not accept its tokens
at all. The claim is now emitted alongside `email`, backed by a per-user
column so the unverified case can be exercised rather than assumed away.
"""
from app.extensions import db
from app.models.user import User


def test_email_verified_accompanies_the_email_claim(app):
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        claims = user.oidc_claim("openid email")

        assert claims["email"] == user.email
        assert claims["email_verified"] is True


def test_email_verified_is_absent_without_the_email_scope(app):
    # It says something about `email`; with no email claim it has nothing to
    # qualify, and OIDC Core §5.4 ties it to the same scope.
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        claims = user.oidc_claim("openid profile")

        assert "email" not in claims
        assert "email_verified" not in claims


def test_email_verified_reflects_an_unverified_user(app):
    with app.app_context():
        user = User(
            username="unverified",
            password="Hunter2!",
            email="unverified@example.org",
            first_name="Un",
            last_name="Verified",
            display_name="Unverified",
            groups="Users",
            email_verified=False,
        )
        db.session.add(user)
        db.session.commit()

        claims = user.oidc_claim("openid email")

        assert claims["email"] == "unverified@example.org"
        assert claims["email_verified"] is False


def test_email_verified_defaults_to_true_for_provisioned_users(app):
    # Accounts here are provisioned directly, not self-registered, so the
    # address is as trustworthy as the account itself.
    with app.app_context():
        user = User(
            username="provisioned",
            password="Hunter2!",
            email="provisioned@example.org",
            first_name="Pro",
            last_name="Visioned",
            display_name="Provisioned",
            groups="Users",
        )
        db.session.add(user)
        db.session.commit()

        assert user.email_verified is True
        assert user.oidc_claim("openid email")["email_verified"] is True


def test_email_verified_is_a_real_boolean_not_a_string(app):
    # A relying party doing `claim is True` — the strict check, and the one
    # that matters — fails on the string "true".
    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        assert isinstance(user.oidc_claim("openid email")["email_verified"], bool)


def test_email_verified_is_advertised_in_discovery(app, client):
    resp = client.get("/.well-known/openid-configuration")
    assert "email_verified" in resp.get_json()["claims_supported"]


def test_userinfo_endpoint_returns_email_verified(app, client):
    # The claim has to survive the UserInfo path too, not just ID token
    # assembly — a client may take the address from either.
    from tests.helpers import exchange_code, obtain_code

    code, _ = obtain_code(client, scope="openid email")
    access_token = exchange_code(client, code).get_json()["access_token"]
    resp = client.get(
        "/s2s/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resp.status_code == 200
    assert resp.get_json()["email_verified"] is True


def test_legacy_rows_get_the_email_verified_column(app):
    # db.create_all() never ALTERs an existing table, and there is no
    # migration framework, so an existing app.db would otherwise fail every
    # query with "no such column".
    from sqlalchemy import text

    from app.models.user import ensure_email_verified_column

    with app.app_context():
        db.session.execute(text("ALTER TABLE user DROP COLUMN email_verified"))
        db.session.commit()

        ensure_email_verified_column()

        rows = db.session.execute(text("SELECT email_verified FROM user")).fetchall()
        assert rows and all(row[0] in (1, True) for row in rows)
