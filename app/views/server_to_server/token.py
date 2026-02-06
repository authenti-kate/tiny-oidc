import os
import jwt
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from flask import jsonify, url_for, request
from app.log import debug
from app.views import bp
from app.extensions import db
from app.models.user import User
from app.models.application import Application
from app.models.authentication import Authentication
from app.models.authorization import Authorization
from app.models.refreshtoken import RefreshToken
from app.views.server_to_server import invalid_token_data

@bp.route('/s2s/token', methods=['POST'])
def token_endpoint():
    data = {}
    for key in request.form.keys():
        data[key] = request.form.get(key)
    bearer = request.authorization.token if (request.authorization is not None and request.authorization.token is not None) else "None"
    debug(f"POST: /s2s/token bearer: {bearer} args: {data}")
    
    now_time = datetime.now(timezone.utc)
    
    invalid_context = []

    grant_type = request.form.get('grant_type', None)
    if grant_type == 'refresh_token':
        refresh_token_value = request.form.get('refresh_token', None)
        if not refresh_token_value:
            return invalid_token_data('Missing refresh_token')
        
        refresh_token: RefreshToken = RefreshToken.query.filter_by(token=refresh_token_value).one_or_none()

        refresh_token_expiry_time = refresh_token.expiry_time.replace(tzinfo=timezone.utc)


        # Validate refresh token
        if not refresh_token or refresh_token_expiry_time < now_time:
            # TODO: Check ss this the right reaction?
            return invalid_token_data('Invalid or expired refresh_token')

        # Validate the associated user and application
        user = User.query.filter_by(username=refresh_token.subject).one_or_none()
        application = Application.query.filter_by(client_id=refresh_token.audience).one_or_none()

        if not user or not application:
            # TODO: Check What to do if the application or user are no longer valid?
            return invalid_token_data('Invalid user or application')

        # Extend expiration for non-permanent applications
        if application.client_id != "client_id_12decaf34bad56" and application.expires_at is not None:
            application.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            db.session.commit()
            debug(f'Extended expiration for {application.client_id} to {application.expires_at}')

        client_id = application.client_id
        client_secret = application.client_secret
        scope = refresh_token.scope
        auth_time = refresh_token.auth_time

    elif grant_type == 'authorization_code':
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
            Authorization.code == code,
            Authorization.session_valid >= now_time,
            Authorization.session_start <= now_time
        ).one_or_none()

        if authorization:
            # PKCE validation (RFC 7636)
            code_verifier = request.form.get('code_verifier', None)
            if authorization.code_challenge:
                if not code_verifier:
                    return invalid_token_data('Missing code_verifier for PKCE')
                if authorization.code_challenge_method == 'S256':
                    computed = base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode('ascii')).digest()
                    ).rstrip(b'=').decode('ascii')
                    if computed != authorization.code_challenge:
                        return invalid_token_data('Invalid code_verifier')
                elif authorization.code_challenge_method == 'plain':
                    if code_verifier != authorization.code_challenge:
                        return invalid_token_data('Invalid code_verifier')
                else:
                    return invalid_token_data('Unsupported code_challenge_method')
            elif code_verifier:
                return invalid_token_data('Unexpected code_verifier')

            client_id = authorization.application_client_id
            application: Application = Application.query.filter(
                Application.client_id == authorization.application_client_id
            ).one_or_none()
            user: User = User.query.filter(
                User.username == authorization.user).one_or_none()
            if not user:
                return invalid_token_data('Authentication expired')
            if not application:
                return invalid_token_data('Application not acceptable')

            if client_id is not None and application.client_id != client_id:
                invalid_context.append('client_id')
            if client_secret is not None and application.client_secret != client_secret:
                invalid_context.append('client_secret')

            # Error if not valid request
            if len(invalid_context) > 0:
                # TODO: What should be the correct response here?
                debug(
                    f'In /s2s/token - Invalid application context provided : {", ".join(invalid_context)}')
                return invalid_token_data('Invalid application context provided')

            # Extend expiration for non-permanent applications
            if application.client_id != "client_id_12decaf34bad56" and application.expires_at is not None:
                application.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
                db.session.commit()
                debug(f'Extended expiration for {application.client_id} to {application.expires_at}')

            scope = authorization.scope
            auth_time = authorization.authentication_start
        else:
            return invalid_token_data('Authorization expired')
            
    # Key pair from https://chatgpt.com/share/676128c4-ffdc-8002-85b9-0fdea65978d1
    private_key = application.rsa_private_key
    key_id = application.key_id
    expires_in_minutes=3600

    authentication = Authentication.query.filter(
        Authentication.subject == user.username,
        Authentication.audience == client_id,
        Authentication.not_before <= now_time,
        Authentication.expiry_time >= now_time
    ).one_or_none()
    if authentication is None:
        authentication = Authentication()
        authentication.subject = user.username
        authentication.audience = client_id
        authentication.not_before = now_time
        authentication.authentication_time = now_time
        authentication.expiry_time = (timedelta(minutes=expires_in_minutes) + now_time)
        authentication.scope = scope
        
        db.session.add(authentication)
        db.session.commit()
        debug(authentication.trace())

    access_content = {
        "jti": hashlib.md5(str(f"{authentication.id}.{authentication.subject}.{authentication.authentication_time}").encode('utf-8')).hexdigest(),
        "sub": authentication.subject,
        "aud": client_id,
        "iss": request.host_url.removesuffix('/') + url_for('views.index'),
        # What time was this application's authentication session started?
        "iat": authentication.authentication_time.timestamp(),
        "exp": authentication.expiry_time.timestamp(),
        "scope": authentication.scope,
        "kid": key_id
    }

    debug(f'Access_content: {access_content}')

    access_token = jwt.encode(
        access_content,
        private_key,
        algorithm="RS256"
    )

    id_content = {
        "jti": hashlib.md5(str(f"{authentication.id}.{authentication.subject}.{authentication.authentication_time}").encode('utf-8')).hexdigest(),
        "aud": client_id,
        "iss": request.host_url.removesuffix('/') + url_for('views.index').removesuffix('/'),
        # Time stuff
        # What time did the user sign into the OIDC?
        "auth_time": auth_time.timestamp(),
        # What time was this application's authentication session started?
        "iat": now_time.timestamp(),
        # When does this session expire?
        "exp": (timedelta(minutes=expires_in_minutes)+now_time).timestamp(),
    }

    # Add user claims based on requested scopes
    id_content.update(user.oidc_claim(scope))

    # Add nonce if it was provided in the authorization request (only for authorization_code flow)
    if grant_type == 'authorization_code' and authorization.nonce:
        id_content["nonce"] = authorization.nonce

    debug(f'id_content: {id_content}')

    id_token = jwt.encode(
        id_content,
        private_key,
        algorithm="RS256"
    )

    reply = {
        "jti": hashlib.md5(str(f"{authentication.id}.{authentication.subject}.{authentication.authentication_time}").encode('utf-8')).hexdigest(),
        "id_token": id_token,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in_minutes
    }

    if "offline_access" in scope.split():
        refresh_token = hashlib.sha256(os.urandom(32)).hexdigest()

        # Store the refresh token in the database
        refresh_entry = RefreshToken(
            token=refresh_token,
            subject=user.username,
            audience=client_id,
            scope=scope,
            auth_time=auth_time,
            issued_at=now_time,
            expiry_time=(timedelta(days=30) + now_time)  # Refresh token valid for 30 days
        )
        db.session.add(refresh_entry)
        db.session.commit()
        reply["refresh_token"] = refresh_token  # Add it to the response

    debug(f"Request: '/s2s/token' Reply: {reply}")
    return jsonify(reply)