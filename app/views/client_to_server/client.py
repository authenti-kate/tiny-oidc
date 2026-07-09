import re
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from flask import request, jsonify
from app.views import bp
from app.log import debug
from app.models.application import Application
from app.extensions import db


@bp.route('/c2s/client', methods=['POST'])
def client_endpoint():
    """OIDC Dynamic Client Registration 1.0 §3.

    Accepts a JSON client-metadata registration request and returns a client
    registration response (HTTP 201) with generated credentials. Registrations
    expire after 7 days, consistent with the /app generator.
    """
    metadata = request.get_json(silent=True) or {}
    debug(f'POST: /c2s/client registration request: {metadata}')

    # redirect_uris is REQUIRED for clients using the authorization code flow
    # (OIDC DCR §2 / §3.1).
    redirect_uris = metadata.get('redirect_uris')
    if not redirect_uris or not isinstance(redirect_uris, list):
        return jsonify({
            "error": "invalid_redirect_uri",
            "error_description": "redirect_uris is required and must be a non-empty array"
        }), 400

    client_id = f"client_{uuid.uuid4().hex}"
    client_secret = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=7)

    application = Application(
        client_id=client_id,
        client_secret=client_secret,
        expires_at=expires_at,
    )
    # Record the registered redirect URIs. The authorization endpoint matches
    # acceptable_redirect_uri as a regex (an intentional feature of this toy —
    # see the C1 discussion); escape and alternate the registered values so a
    # DCR client is scoped to what it registered rather than the '*' default.
    application.acceptable_redirect_uri = '|'.join(re.escape(u) for u in redirect_uris)
    db.session.add(application)
    db.session.commit()

    debug(f'Registered new application {client_id} with expiration {expires_at}')

    response = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(now.timestamp()),
        "client_secret_expires_at": int(expires_at.timestamp()),
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": metadata.get("token_endpoint_auth_method", "client_secret_post"),
        "grant_types": metadata.get("grant_types", ["authorization_code"]),
        "response_types": metadata.get("response_types", ["code"]),
    }
    return jsonify(response), 201
