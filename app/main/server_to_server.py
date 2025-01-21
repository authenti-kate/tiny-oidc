import re
import jwt
from datetime import datetime, timezone, timedelta
from flask import jsonify, url_for, request, Response
from app.log import debug
from app.main import bp
from app.extensions import db
from app.models.user import User
from app.models.application import Application
from app.models.authorization import Authorization


@bp.route('/.well-known/openid-configuration')
def well_known():
    host_url = request.host_url.removesuffix('/')
    reply = {
            # Required Fields
            "issuer": host_url + url_for('main.index').removesuffix('/'),
            'authorization_endpoint': host_url + url_for('main.authorization_endpoint'),
            'token_endpoint': host_url + url_for('main.token_endpoint'),
            "jwks_uri": host_url + url_for('main.keys_endpoint'),
            "response_types_supported": [
                "code",
                "id_token",
                "id_token token"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [
                "RS256"
            ],
            # Recommended Fields
            'userinfo_endpoint': host_url + url_for('main.userinfo_endpoint'),
            "registration_endpoint": host_url + url_for('main.client_endpoint'),
            "scopes_supported": [
                "openid",
                "email",
                "profile",
                "groups"
            ],
            "claims_supported": [
                "iss",
                "sub",
                "aud",
                "iat",
                "exp",
                "auth_time",
                "name",
                "email",
                "preferred_username",
            ## UNMAPPED DATA
            #     "ver", "jti", "amr", "idp", "nonce", "nickname", "given_name", "middle_name",
            #     "family_name", "email_verified", "profile", "zoneinfo", "locale", "address",
            #     "phone_number", "picture", "website", "gender", "birthdate", "updated_at",
            #     "at_hash", "c_hash"
            ],
            # Optional Fields
            "response_modes_supported": ["query", "fragment"],
            "grant_types_supported": [
                "authorization_code",
                "implicit"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "none"
                # "client_secret_post", "client_secret_jwt", "private_key_jwt",
            ],
            "end_session_endpoint": host_url + url_for('main.logout'),
            "request_parameter_supported": True,
            #   "request_object_signing_alg_values_supported": [
            #     "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
            #   ],
        }
    
    debug(f"Request: '/.well-known/openid-configuration' Reply: {reply}")
    return jsonify(reply)

@bp.route('/s2s/token', methods=['POST'])
def token_endpoint():
    invalid_context = []

    # Check inbound request contains required fields
    code = request.form.get('code', None)
    if not code:
        invalid_context.append('code')

    client_id = request.form.get('client_id', None)
    client_secret = request.form.get('client_secret', None)

    # Error if not valid request
    if len(invalid_context) > 0:
        debug(
            f'In /s2s/token - Invalid token context provided : {", ".join(invalid_context)}')
        return invalid_token_data('Invalid token context provided')

    authorization: Authorization = Authorization.query.filter(
        Authorization.code == code
    ).one_or_none()

    if authorization:
        application: Application = Application.query.filter(
            Application.client_id == authorization.application_client_id
        ).one_or_none()
        user: User = User.query.filter(
            User.username == authorization.user).one_or_none()
        if not user:
            return invalid_token_data('Authentication expired')
        if not application:
            return invalid_token_data('Application not acceptable')

        if application.client_id != client_id:
            invalid_context.append('client_id')
        if application.client_secret != client_secret:
            invalid_context.append('client_secret')

        # Error if not valid request
        if len(invalid_context) > 0:
            debug(
                f'In /s2s/token - Invalid application context provided : {", ".join(invalid_context)}')
            return invalid_token_data('Invalid application context provided')
        
        # Key pair from https://chatgpt.com/share/676128c4-ffdc-8002-85b9-0fdea65978d1
        private_key = application.rsa_private_key
        expires_in_minutes=3600

        authentication = Authentication()
        authentication.subject = user.username
        authentication.audience = authorization.application_client_id
        authentication.not_before = datetime.now(timezone.utc).timestamp()
        authentication.authentication_time = datetime.now(timezone.utc).timestamp()
        authentication.expiry_time = (timedelta(minutes=expires_in_minutes) + datetime.now(timezone.utc)).timestamp()
        authentication.scope = authorization.scope
        authentication.token_identifier = hashlib.md5(str(f"{authentication.id}.{authentication.subject}.{authentication.authentication_time}").encode('utf-5')).hexdigest()
        
        db.session.add(authentication)
        db.session.commit()
        debug(authentication.trace())

        access_token = jwt.encode(
            {
                "sub": authentication.subject,
                "aud": authentication.audience,
                "iss": request.host_url.removesuffix('/') + url_for('main.index'),
                # What time was this application's authentication session started?
                "iat": authentication.authentication_time,
                "exp": authentication.expiry_time,
                "scope": authentication.scope,
                "kid": key_id
            },
            private_key,
            algorithm="RS256"
        )
        id_token = jwt.encode(
            {
                "aud": authorization.application_client_id,
                "iss": request.host_url.removesuffix('/') + url_for('main.index').removesuffix('/'),
                # Time stuff
                # What time did the user sign into the OIDC?
                "auth_time": authorization.authentication_start.timestamp(),
                # What time was this application's authentication session started?
                "iat": datetime.now(timezone.utc).timestamp(),
                # When does this session expire?
                "exp": (timedelta(minutes=expires_in_minutes)+datetime.now(timezone.utc)).timestamp(),
                # User context
                # The internal reference for this User ID
                "sub": user.username,
                "email": user.email,
                "preferred_username": user.username,
                "name": user.display_name
            },
            private_key,
            algorithm="RS256"
        )
        reply = {
            "id_token": id_token,
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in_minutes
        }
        debug(f"Request: '/s2s/token' Reply: {reply}")
        return jsonify(reply)
    return invalid_token_data('Authorization expired')


def invalid_token_data(message):
    debug(f"404: {message}")
    return Response(f"""
<html>
    <head>
        <title>Tiny OIDC Server - Error</title>
    </head>
    <body>
        <h1>Tiny OIDC Server - Error</h1>
        <hr>
        <h2 color="red">BE WARNED, THIS SERVER IS NOT SECURE AND IS USED FOR POC TESTING ONLY</h2>
        <hr>
        <p>{message}</p>
    </body>
</html>""", status=400)