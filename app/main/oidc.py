import re
import jwt
from datetime import datetime, timezone, timedelta
from flask import jsonify, url_for, redirect, request, Response
from app.log import debug
from app.main import bp
from app.extensions import db
from app.models.user import User
from app.models.application import Application
from app.models.authorization import Authorization
from app.session import getSessionData, setSessionData, deleteSessionData


@bp.route('/.well-known/openid-configuration')
def well_known():
    host_url = request.host_url.removesuffix('/')
    return jsonify(
        {
            # Required Fields
            "issuer": host_url + url_for('main.index'),
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
    )


@bp.route('/oidc/token', methods=['POST'])
def token_endpoint():
    invalid_context = []

    # Check inbound request contains required fields
    grant_type = request.args.get('grant_type', None)
    if not grant_type:
        invalid_context.append('grant_type')

    code = request.args.get('code', None)
    if not code:
        invalid_context.append('code')

    redirect_uri = request.args.get('redirect_uri', None)
    if not redirect_uri:
        invalid_context.append('redirect_uri')

    client_secret = request.args.get('client_secret', None)
    if not client_secret:
        invalid_context.append('client_secret')

    client_id = request.args.get('client_id', None)
    if not client_id:
        invalid_context.append('client_id')

    else:
        application: Application = Application.query.filter(
            Application.client_id == client_id
        ).one_or_none()
        if not application:
            invalid_context.append('NON_EXISTANT:client_id')

        else:
            if not application.client_secret == client_secret:
                invalid_context.append('NON_MATCHING:client_secret')

            if not application.acceptable_redirect_uri == '*' and not re.match(application.acceptable_redirect_uri, redirect_uri):
                invalid_context.append('NON_MATCHING:redirect_uri')

    # Error if not valid request
    if len(invalid_context) > 0:
        debug(
            f'In /oidc/authorize - Invalid authorization context provided : {", ".join(invalid_context)}')
        return invalid_authorize_data('Invalid authorization context provided')

    authorization: Authorization = Authorization.query.filter(
        Authorization.application == client_id,
        Authorization.session_valid >= datetime.now(timezone.utc),
        Authorization.code == code
    ).one_or_none()

    if authorization:
        user: User = User.query.filter(
            User.username == authorization.user).one_or_none()
        if not user:
            return invalid_authorize_data('Authentication expired')
        # Key pair from https://chatgpt.com/share/676128c4-ffdc-8002-85b9-0fdea65978d1
        private_key = application.rsa_private_key
        expires_in_minutes=3600
        access_token = jwt.encode(
            {
                "sub": user.username,
                "aud": client_id,
                "iss": request.host_url.removesuffix('/') + url_for('main.index'),
                "exp": datetime.now(timezone.utc)+timedelta(minutes=expires_in_minutes).timestamp(),
                # What time was this application's authentication session started?
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": authorization.scope
            },
            private_key,
            algorithm="RS256"
        )
        id_token = jwt.encode(
            {
                "aud": client_id,
                "iss": request.host_url.removesuffix('/') + url_for('main.index'),
                # Time stuff
                # What time did the user sign into the OIDC?
                "auth_time": getSessionData('sign_in'),
                # What time was this application's authentication session started?
                "iat": datetime.now(timezone.utc).timestamp(),
                # When does this session expire?
                "exp": datetime.now(timezone.utc)+timedelta(minutes=expires_in_minutes).timestamp(),
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
        return jsonify(
            {
                "id_token": id_token,
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in_minutes
            }
        )
    return invalid_authorize_data('Authorization expired')

@bp.route('/oidc/authorize')
def authorization_endpoint():
    invalid_context = []

    # Check inbound request contains required fields
    response_type = request.args.get(
        'response_type', getSessionData('response_type'))
    if not response_type:
        invalid_context.append('response_type')

    scope = request.args.get('scope', getSessionData('scope'))
    if not scope:
        invalid_context.append('scope')

    state = request.args.get('state', getSessionData('state'))
    if not state:
        invalid_context.append('state')

    # These two are a bit more complex - but are still checking for required fields
    redirect_uri = request.args.get(
        'redirect_uri', getSessionData('redirect_uri'))
    if not redirect_uri:
        invalid_context.append('redirect_uri')

    client_id = request.args.get('client_id', getSessionData('client_id'))
    if not client_id:
        invalid_context.append('client_id')
    else:
        application: Application = Application.query.filter(
            Application.client_id == client_id
        ).one_or_none()
        if not application:
            invalid_context.append('NON_EXISTANT:client_id')
        elif not application.acceptable_redirect_uri == '*' and not re.match(application.acceptable_redirect_uri, redirect_uri):
            invalid_context.append('NON_MATCHING:redirect_uri')

    # Error if not valid request
    if len(invalid_context) > 0:
        debug(
            f'In /oidc/authorize - Invalid authorization context provided : {", ".join(invalid_context)}')
        return invalid_authorize_data('Invalid authorization context provided')

    # Check user session
    user_key = getSessionData('user')
    if not user_key:
        setSessionData('client_id',     client_id)
        setSessionData('response_type', response_type)
        setSessionData('scope',         scope)
        setSessionData('redirect_uri',  redirect_uri)
        setSessionData('state',         state)
        return redirect(url_for('main.login'))
    else:
        # We got back here, we don't need to keep this now.
        deleteSessionData('client_id')
        deleteSessionData('response_type')
        deleteSessionData('scope')
        deleteSessionData('redirect_uri')
        deleteSessionData('state')

    # Get the authorization record
    authorization: Authorization = Authorization.query.filter(
        Authorization.user == user_key,
        Authorization.application == application.client_id,
        Authorization.session_valid >= datetime.now(timezone.utc)
    ).one_or_none()
    if not authorization:
        authorization: Authorization = Authorization(
            user=user_key,
            application=application.client_id,
            scope=scope
        )
        db.session.add(authorization)
        db.session.commit()

    return redirect(f'{redirect_uri}?code={authorization.code}&state={state}')


def invalid_authorize_data(message):
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


@bp.route('/oidc/userinfo')
def userinfo_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'


@bp.route('/oidc/client')
def client_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'


@bp.route('/oidc/keys')
def keys_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'