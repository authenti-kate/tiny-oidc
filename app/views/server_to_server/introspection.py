import jwt
import hashlib
from datetime import datetime
from flask import jsonify, url_for, request
from app.log import debug
from app.views import bp
from app.models.application import Application
from app.models.authentication import Authentication
from app.views.server_to_server import invalid_token_data

@bp.route('/s2s/introspection', methods=['POST'])
def introspection_endpoint():
    data = {}
    for key in request.form.keys():
        data[key] = request.form.get(key)
    bearer = request.authorization.token if (request.authorization is not None and request.authorization.token is not None) else "None"
    debug(f"POST: /s2s/introspection bearer: {bearer} args: {data}")

    bearer = request.authorization.token
    if bearer:
        first_pass = jwt.decode(bearer, algorithms="RS256", options={"verify_signature": False})
        application: Application = Application.query.filter(Application.key_id == first_pass['kid']).one_or_none()
        token = jwt.decode(bearer, audience=application.client_id, key=application.rsa_public_key, algorithms="RS256")

        query = Authentication.query.filter(
            Authentication.audience == token['aud'],
            Authentication.subject == token['sub'],
            Authentication.authentication_time >= datetime.fromtimestamp(int(token['iat'])-1).replace(tzinfo=None),
            Authentication.authentication_time <= datetime.fromtimestamp(int(token['iat'])+1).replace(tzinfo=None),
        )
        authentication: Authentication = query.all()

        if len(authentication) == 0:
            return invalid_token_data('Invalid logged authentication - no records found')
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
    debug(f'Invalid bearer: {bearer}')
    return invalid_token_data('Invalid authorization')
