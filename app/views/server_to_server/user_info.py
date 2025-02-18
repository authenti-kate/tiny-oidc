import jwt
from flask import jsonify, request
from app.log import debug
from app.views import bp
from app.models.user import User
from app.models.application import Application
from app.views.server_to_server import invalid_token_data

@bp.route('/s2s/userinfo')
def userinfo_endpoint():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    bearer = request.authorization.token if (request.authorization is not None and request.authorization.token is not None) else "None"
    debug(f'GET: /s2s/userinfo bearer: {bearer} args: {data}')

    if bearer:
        first_pass = jwt.decode(bearer, algorithms="RS256", options={"verify_signature": False})
        application: Application = Application.query.filter(Application.key_id == first_pass['kid']).one_or_none()
        token = jwt.decode(bearer, audience=application.client_id, key=application.rsa_public_key, algorithms="RS256")
        if token:
            user: User = User.query.filter(User.username == token['sub']).one_or_none()

            reply = user.oidc_claim(token['scope'])
            debug(f"Request: '/s2s/userinfo' Reply: {reply}")
            return jsonify(reply)
    debug(f'Invalid application: {application.trace()}')
    debug(f'Token: {token or "None"}')
    return invalid_token_data('Invalid authorization')