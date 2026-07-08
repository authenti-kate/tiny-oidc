import jwt
import hashlib
from datetime import datetime
from flask import jsonify, url_for, request
from app.log import debug
from app.views import bp
from app.models.application import Application
from app.models.authentication import Authentication
from app.views.server_to_server import client_credentials, ct_equal, token_error

@bp.route('/s2s/introspection', methods=['POST'])
def introspection_endpoint():
    data = {key: request.form.get(key) for key in request.form.keys()}
    debug(f"POST: /s2s/introspection args: {data}")

    # RFC 7662 §2.1: the introspection endpoint MUST require authentication of
    # the calling protected resource. Authenticate it as a registered client.
    caller_id, caller_secret = client_credentials()
    if not caller_id or not caller_secret:
        return token_error('invalid_client', 'Client authentication required', 401)
    caller: Application = Application.query.filter_by(client_id=caller_id).one_or_none()
    if caller is None or not ct_equal(caller_secret, caller.client_secret):
        debug(f'/s2s/introspection - caller authentication failed for {caller_id}')
        return token_error('invalid_client', 'Client authentication failed', 401)

    # RFC 7662 §2.1: the token is passed as the `token` form parameter
    # (`token_type_hint` is optional and advisory), not the Authorization header.
    bearer = request.form.get('token', None)
    if not bearer:
        return token_error('invalid_request', 'Missing token parameter', 400)

    # RFC 7662 §2.2: for any token that is invalid, expired, or otherwise not
    # active, return {"active": false} rather than an error.
    inactive = jsonify({"active": False})

    try:
        first_pass = jwt.decode(bearer, algorithms=["RS256"], options={"verify_signature": False})
    except jwt.PyJWTError:
        return inactive

    application: Application = Application.query.filter(
        Application.key_id == first_pass.get('kid')
    ).one_or_none()
    if application is None:
        return inactive

    try:
        token = jwt.decode(bearer, audience=application.client_id, key=application.rsa_public_key, algorithms=["RS256"])
    except jwt.PyJWTError:
        return inactive

    authentication = Authentication.query.filter(
        Authentication.audience == token['aud'],
        Authentication.subject == token['sub'],
        Authentication.authentication_time >= datetime.fromtimestamp(int(token['iat'])-1).replace(tzinfo=None),
        Authentication.authentication_time <= datetime.fromtimestamp(int(token['iat'])+1).replace(tzinfo=None),
    ).all()

    if len(authentication) == 0:
        return inactive
    authentication = authentication[0]

    reply = {
        "active": True,
        "scope": authentication.scope,
        "exp": authentication.expiry_time.timestamp(),
        "iat": authentication.authentication_time.timestamp(),
        "sub": authentication.subject,
        "iss": request.host_url.removesuffix('/') + url_for('views.index'),
        "aud": authentication.audience,
        "nbf": authentication.not_before.timestamp(),
        "jti": hashlib.md5(str(f"{authentication.id}.{authentication.subject}.{authentication.authentication_time}").encode('utf-8')).hexdigest()
    }
    debug(f"Request: '/s2s/introspection' Reply: {reply}")
    return jsonify(reply)
