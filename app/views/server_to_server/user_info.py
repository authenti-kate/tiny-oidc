import jwt
from flask import jsonify, request
from app.log import debug
from app.views import bp
from app.models.user import User
from app.models.application import Application
from app.urls import external_url
from app.views.server_to_server import bearer_error

# OIDC Core §5.3.1: the UserInfo Endpoint MUST support both GET and POST.
@bp.route('/s2s/userinfo', methods=['GET', 'POST'])
def userinfo_endpoint():
    # RFC 6750 §2.1: the access token is presented as a Bearer credential.
    auth = request.authorization
    bearer = auth.token if (auth is not None and (auth.type or '').lower() == 'bearer' and auth.token) else None
    debug(f'{request.method}: /s2s/userinfo bearer present: {bool(bearer)} args: {dict(request.args)}')

    # No credentials: 401 with a bare Bearer challenge and no error code
    # (RFC 6750 §3).
    if not bearer:
        return bearer_error(None, status=401)

    # Any decode/verification failure is an invalid_token (RFC 6750 §3.1),
    # returned as 401 with a WWW-Authenticate header rather than a 500.
    # The signing key is identified by the JWS header `kid` (RFC 7515 §4.1.4).
    try:
        header = jwt.get_unverified_header(bearer)
    except jwt.PyJWTError:
        return bearer_error('invalid_token', 'Malformed access token', 401)

    application: Application = Application.query.filter(
        Application.key_id == header.get('kid')
    ).one_or_none()
    if application is None:
        return bearer_error('invalid_token', 'Unknown signing key', 401)

    try:
        token = jwt.decode(bearer, audience=application.client_id, key=application.rsa_public_key,
                           algorithms=["RS256"], issuer=external_url('views.index'))
    except jwt.PyJWTError:
        return bearer_error('invalid_token', 'Access token failed verification', 401)

    # UserInfo must be presented with an access token, not an ID token.
    if token.get('token_use') != 'access':
        return bearer_error('invalid_token', 'Not an access token', 401)

    user: User = User.query.filter(User.username == token.get('sub')).one_or_none()
    if user is None:
        return bearer_error('invalid_token', 'Unknown subject', 401)

    reply = user.oidc_claim(token.get('scope', ''))
    debug(f"Request: '/s2s/userinfo' Reply: {reply}")
    return jsonify(reply)
