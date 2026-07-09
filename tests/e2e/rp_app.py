#!/usr/bin/env -S uv run
"""A minimal OpenID Connect Relying Party, used to drive tiny-oidc end to end.

This is a *real* client: it discovers the provider, redirects the browser to the
authorization endpoint, exchanges the code over a back-channel HTTP request, and
verifies the returned ID token against the published JWKS. Nothing here reaches
into the provider's database, so a passing test proves the wire protocol works.

The client-authentication method and PKCE mode are chosen per login (via query
parameters on /login) so a single RP process can serve the whole test matrix:

    client auth:  basic | post          (RFC 6749 §2.3.1)
    PKCE:         S256 | plain | implicit-plain | none   (RFC 7636)

"implicit-plain" sends a code_challenge with no code_challenge_method, which the
provider must default to "plain" (RFC 7636 §4.3).

Run standalone for manual poking:

    IDP_ISSUER=http://127.0.0.1:8000 RP_PORT=8001 ./tests/e2e/rp_app.py
"""
import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode

import jwt
import requests
from requests.auth import HTTPBasicAuth
from flask import Flask, jsonify, redirect, request, session, url_for

# Server-side token store. Keeping tokens out of the cookie avoids the 4KB limit
# (two RS256 JWTs comfortably exceed it) and keeps them off the wire.
SESSIONS: dict[str, dict] = {}

CLIENT_AUTH_METHODS = ("basic", "post")
PKCE_MODES = ("S256", "plain", "implicit-plain", "none")


def create_rp(
    issuer: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    secret_key: str = "rp-test-key",
):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key,
        # The RP and the provider share the 127.0.0.1 host, and cookies ignore
        # the port. Without a distinct name the RP's "session" cookie would
        # overwrite the provider's and silently break the login flow.
        SESSION_COOKIE_NAME="rp_session",
    )

    discovery_cache: dict = {}

    def discover():
        if not discovery_cache:
            resp = requests.get(
                f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=10
            )
            resp.raise_for_status()
            discovery_cache.update(resp.json())
            discovery_cache["_jwks_client"] = jwt.PyJWKClient(
                discovery_cache["jwks_uri"]
            )
        return discovery_cache

    def store():
        sid = session.get("sid")
        if not sid:
            sid = secrets.token_urlsafe(16)
            session["sid"] = sid
        return SESSIONS.setdefault(sid, {})

    def token_request(data, client_auth):
        """POST to the token endpoint using the selected client-auth method."""
        conf = discover()
        kwargs = {"data": dict(data), "timeout": 10}
        if client_auth == "basic":
            # requests sends the raw client_id:client_secret base64-encoded,
            # rather than form-urlencoding each part first as RFC 6749 §2.3.1
            # requires. The provider accepts both (see client_credentials).
            kwargs["auth"] = HTTPBasicAuth(client_id, client_secret)
            kwargs["data"]["client_id"] = client_id
        elif client_auth == "post":
            kwargs["data"]["client_id"] = client_id
            kwargs["data"]["client_secret"] = client_secret
        else:
            raise ValueError(f"unknown client auth method: {client_auth}")
        return requests.post(conf["token_endpoint"], **kwargs)

    def verify_id_token(id_token, nonce):
        conf = discover()
        signing_key = conf["_jwks_client"].get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=conf["issuer"],
        )
        # OIDC Core §3.1.3.7 step 11: the nonce must match the one we sent.
        if nonce is not None and claims.get("nonce") != nonce:
            raise ValueError("nonce mismatch in id_token")
        return claims

    @app.route("/")
    def index():
        return '<html><body><h1>Test RP</h1><a href="/login">Log in</a></body></html>'

    @app.route("/health")
    def health():
        return "OK"

    @app.route("/login")
    def login():
        client_auth = request.args.get("auth", "post")
        pkce = request.args.get("pkce", "S256")
        scope = request.args.get("scope", "openid profile groups offline_access")
        if client_auth not in CLIENT_AUTH_METHODS:
            return f"bad auth method {client_auth}", 400
        if pkce not in PKCE_MODES:
            return f"bad pkce mode {pkce}", 400

        conf = discover()
        data = store()
        data.clear()
        data.update(
            client_auth=client_auth,
            pkce=pkce,
            scope=scope,
            state=secrets.token_urlsafe(16),
            nonce=secrets.token_urlsafe(16),
            refresh_count=0,
        )

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": data["state"],
            "nonce": data["nonce"],
        }

        if pkce != "none":
            verifier = secrets.token_urlsafe(64)[:64]
            data["code_verifier"] = verifier
            if pkce == "S256":
                params["code_challenge"] = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(verifier.encode("ascii")).digest()
                    )
                    .rstrip(b"=")
                    .decode("ascii")
                )
                params["code_challenge_method"] = "S256"
            else:
                params["code_challenge"] = verifier
                if pkce == "plain":
                    params["code_challenge_method"] = "plain"
                # "implicit-plain" deliberately omits code_challenge_method.

        return redirect(f"{conf['authorization_endpoint']}?{urlencode(params)}")

    @app.route("/callback")
    def callback():
        data = store()

        if "error" in request.args:
            data["error"] = request.args["error"]
            data["error_description"] = request.args.get("error_description")
            return redirect(url_for("session_page"))

        # RFC 6749 §10.12: reject a callback whose state we did not issue.
        if request.args.get("state") != data.get("state"):
            data["error"] = "state_mismatch"
            return redirect(url_for("session_page"))

        body = {
            "grant_type": "authorization_code",
            "code": request.args["code"],
            "redirect_uri": redirect_uri,
        }
        if data.get("code_verifier"):
            body["code_verifier"] = data["code_verifier"]

        resp = token_request(body, data["client_auth"])
        if resp.status_code != 200:
            data["error"] = "token_request_failed"
            data["token_status"] = resp.status_code
            data["token_body"] = resp.text[:500]
            return redirect(url_for("session_page"))

        tokens = resp.json()
        try:
            claims = verify_id_token(tokens["id_token"], data["nonce"])
        except Exception as exc:  # noqa: BLE001 - surfaced to the test
            data["error"] = "id_token_invalid"
            data["error_description"] = str(exc)
            return redirect(url_for("session_page"))

        data["tokens"] = tokens
        data["id_claims"] = claims
        return redirect(url_for("session_page"))

    @app.route("/refresh")
    def refresh():
        data = store()
        rt = (data.get("tokens") or {}).get("refresh_token")
        if not rt:
            data["error"] = "no_refresh_token"
            return redirect(url_for("session_page"))

        resp = token_request(
            {"grant_type": "refresh_token", "refresh_token": rt}, data["client_auth"]
        )
        if resp.status_code != 200:
            data["error"] = "refresh_failed"
            data["token_status"] = resp.status_code
            data["token_body"] = resp.text[:500]
            return redirect(url_for("session_page"))

        tokens = resp.json()
        try:
            # A refreshed ID token carries no nonce (there was no new
            # authorization request), so do not assert one.
            claims = verify_id_token(tokens["id_token"], None)
        except Exception as exc:  # noqa: BLE001
            data["error"] = "id_token_invalid"
            data["error_description"] = str(exc)
            return redirect(url_for("session_page"))

        data["previous_refresh_token"] = rt
        data["tokens"] = tokens
        data["id_claims"] = claims
        data["refresh_count"] = data.get("refresh_count", 0) + 1
        data.pop("error", None)
        return redirect(url_for("session_page"))

    @app.route("/replay-refresh")
    def replay_refresh():
        """Re-present the previously consumed refresh token (RFC 9700 §2.2.2)."""
        data = store()
        old = data.get("previous_refresh_token")
        if not old:
            return jsonify({"error": "nothing_to_replay"}), 400
        resp = token_request(
            {"grant_type": "refresh_token", "refresh_token": old}, data["client_auth"]
        )
        return jsonify({"status": resp.status_code, "body": resp.text[:500]})

    def _protected(path_key, **extra):
        conf = discover()
        data = store()
        access_token = (data.get("tokens") or {}).get("access_token")
        if not access_token:
            return jsonify({"error": "not_authenticated"}), 401
        if path_key == "userinfo_endpoint":
            resp = requests.get(
                conf[path_key],
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
        else:
            resp = requests.post(
                conf[path_key],
                data={
                    "token": access_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    **extra,
                },
                timeout=10,
            )
        try:
            body = resp.json()
        except ValueError:
            body = resp.text[:500]
        return jsonify({"status": resp.status_code, "body": body})

    @app.route("/api/refresh-token")
    def api_refresh_token():
        """Expose the live refresh token so a test can present it directly."""
        tokens = store().get("tokens") or {}
        return jsonify({"refresh_token": tokens.get("refresh_token")})

    @app.route("/api/userinfo")
    def api_userinfo():
        return _protected("userinfo_endpoint")

    @app.route("/api/introspect")
    def api_introspect():
        return _protected("introspection_endpoint")

    def _state():
        data = store()
        tokens = data.get("tokens") or {}
        return {
            "authenticated": bool(tokens),
            "error": data.get("error"),
            "error_description": data.get("error_description"),
            "token_status": data.get("token_status"),
            "token_body": data.get("token_body"),
            "client_auth": data.get("client_auth"),
            "pkce": data.get("pkce"),
            "scope": data.get("scope"),
            "refresh_count": data.get("refresh_count", 0),
            "id_claims": data.get("id_claims"),
            "token_type": tokens.get("token_type"),
            "expires_in": tokens.get("expires_in"),
            "has_refresh_token": "refresh_token" in tokens,
            "refresh_token_rotated": (
                bool(data.get("previous_refresh_token"))
                and tokens.get("refresh_token") != data.get("previous_refresh_token")
            ),
        }

    @app.route("/api/session")
    def api_session():
        return jsonify(_state())

    @app.route("/session")
    def session_page():
        state = _state()
        sub = (state.get("id_claims") or {}).get("sub", "")
        status = "signed-in" if state["authenticated"] else "signed-out"
        return f"""<!DOCTYPE html>
<html>
    <head><title>Test RP - Session</title></head>
    <body>
        <h1 id="status">{status}</h1>
        <p id="sub">{sub}</p>
        <p id="error">{state.get('error') or ''}</p>
        <pre id="state">{json.dumps(state, indent=2, sort_keys=True)}</pre>
    </body>
</html>"""

    return app


if __name__ == "__main__":
    port = int(os.environ["RP_PORT"])
    rp = create_rp(
        issuer=os.environ["IDP_ISSUER"],
        client_id=os.environ.get("RP_CLIENT_ID", "client_id_12decaf34bad56"),
        client_secret=os.environ.get("RP_CLIENT_SECRET", "Super-+Secret_=Key0123456789"),
        redirect_uri=os.environ.get(
            "RP_REDIRECT_URI", f"http://127.0.0.1:{port}/callback"
        ),
        secret_key=os.environ.get("RP_SECRET_KEY", "rp-test-key"),
    )
    rp.run(host="127.0.0.1", port=port, debug=False)
