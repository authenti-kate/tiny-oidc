import os
import uuid
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
from app.crypto import ct_equal
from app.urls import external_url
from app.times import numeric_date
from app.views.server_to_server import (
    token_error,
    client_credentials,
)

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
            return token_error('invalid_request', 'Missing refresh_token', 400)

        refresh_token: RefreshToken = RefreshToken.query.filter_by(token=refresh_token_value).one_or_none()

        # Validate refresh token. Check existence before dereferencing it, otherwise
        # an unknown token raises AttributeError instead of a clean error response.
        if not refresh_token:
            return token_error('invalid_grant', 'Invalid or expired refresh_token', 400)

        # Replay detection (RFC 9700 §2.2.2): a consumed token presented again
        # indicates the token (or its successor) leaked; revoke the whole family.
        if refresh_token.consumed:
            debug('In /s2s/token - refresh token replay detected; revoking token family')
            RefreshToken.query.filter_by(family_id=refresh_token.family_id).delete()
            db.session.commit()
            return token_error('invalid_grant', 'Refresh token has already been used', 400)

        refresh_token_expiry_time = refresh_token.expiry_time.replace(tzinfo=timezone.utc)
        if refresh_token_expiry_time < now_time:
            return token_error('invalid_grant', 'Invalid or expired refresh_token', 400)

        # Validate the associated user and application
        user = User.query.filter_by(username=refresh_token.subject).one_or_none()
        application = Application.query.filter_by(client_id=refresh_token.audience).one_or_none()

        if not user or not application:
            # The grant refers to a user or client that no longer exists, so the
            # grant itself is no longer valid (RFC 6749 §5.2 invalid_grant).
            return token_error('invalid_grant', 'Invalid user or application', 400)

        # Authenticate the client on the refresh grant too (RFC 6749 §6 / §3.2.1);
        # C2 covered the code exchange, but a refresh must not rotate a token
        # family without proving which client is presenting it.
        auth_client_id, auth_client_secret = client_credentials()
        if not auth_client_id or not auth_client_secret:
            return token_error('invalid_client', 'Client authentication required', 401)
        if not ct_equal(auth_client_id, application.client_id) or \
                not ct_equal(auth_client_secret, application.client_secret):
            return token_error('invalid_client', 'Client authentication failed', 401)

        # Extend expiration for non-permanent applications
        if application.client_id != "client_id_12decaf34bad56" and application.expires_at is not None:
            application.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            db.session.commit()
            debug(f'Extended expiration for {application.client_id} to {application.expires_at}')

        client_id = application.client_id
        client_secret = application.client_secret
        scope = refresh_token.scope
        auth_time = refresh_token.auth_time
        # Rotate: consume the presented token now; a replacement in the same
        # family is issued below (RFC 9700 §2.2.2).
        refresh_family = refresh_token.family_id
        refresh_token.consumed = True
        db.session.commit()

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
            return token_error(
                'invalid_request',
                f'Missing required parameter: {", ".join(invalid_context)}',
                400)

        authorization: Authorization = Authorization.query.filter(
            Authorization.code == code,
            Authorization.session_start <= now_time
        ).one_or_none()

        # Authorization code replay detection (RFC 6749 §4.1.2 / §10.5,
        # RFC 9700 §2.1.1): a code may be redeemed only once. If a code that has
        # already been used is presented again, revoke every token previously
        # issued from this authorization and reject the request.
        if authorization is not None and authorization.code_used:
            debug('In /s2s/token - authorization code reuse detected; revoking issued tokens')
            Authentication.query.filter_by(
                subject=authorization.user,
                audience=authorization.application_client_id
            ).delete()
            RefreshToken.query.filter_by(
                subject=authorization.user,
                audience=authorization.application_client_id
            ).delete()
            db.session.commit()
            return token_error('invalid_grant', 'Authorization code has already been used', 400)

        # Reject an expired code (outside the session window). session_valid is
        # stored naive (UTC); make it tz-aware before comparing with now_time.
        if authorization is not None and \
                authorization.session_valid.replace(tzinfo=timezone.utc) < now_time:
            authorization = None

        if authorization:
            # PKCE validation (RFC 7636)
            # RFC 7636 §4.6: a failed verifier check is reported using the
            # RFC 6749 §5.2 error response, with the code invalid_grant.
            code_verifier = request.form.get('code_verifier', None)
            if authorization.code_challenge:
                if not code_verifier:
                    return token_error('invalid_grant', 'Missing code_verifier for PKCE', 400)
                # RFC 7636 §4.3: a stored challenge with no method means "plain".
                method = authorization.code_challenge_method or 'plain'
                if method == 'S256':
                    computed = base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode('ascii')).digest()
                    ).rstrip(b'=').decode('ascii')
                    if not ct_equal(computed, authorization.code_challenge):
                        return token_error('invalid_grant', 'Invalid code_verifier', 400)
                elif method == 'plain':
                    if not ct_equal(code_verifier, authorization.code_challenge):
                        return token_error('invalid_grant', 'Invalid code_verifier', 400)
                else:
                    return token_error('invalid_request', 'Unsupported code_challenge_method', 400)
            elif code_verifier:
                return token_error('invalid_grant', 'Unexpected code_verifier', 400)

            client_id = authorization.application_client_id
            application: Application = Application.query.filter(
                Application.client_id == authorization.application_client_id
            ).one_or_none()
            user: User = User.query.filter(
                User.username == authorization.user).one_or_none()
            if not user:
                return token_error('invalid_grant', 'Authentication expired', 400)
            if not application:
                return token_error('invalid_grant', 'Application not acceptable', 400)

            # Authenticate the client the code was issued to (RFC 6749 §3.2.1 /
            # §4.1.3). The authorization code is bound to
            # authorization.application_client_id, so a confidential client MUST
            # present matching credentials via client_secret_basic or
            # client_secret_post. Without this, anyone holding a code could
            # redeem it. Comparisons are constant-time to avoid a timing oracle.
            auth_client_id, auth_client_secret = client_credentials()
            if not auth_client_id or not auth_client_secret:
                debug('In /s2s/token - missing client authentication')
                return token_error('invalid_client', 'Client authentication required', 401)
            if not ct_equal(auth_client_id, application.client_id) or \
                    not ct_equal(auth_client_secret, application.client_secret):
                debug(f'In /s2s/token - client authentication failed for {auth_client_id}')
                return token_error('invalid_client', 'Client authentication failed', 401)

            # Consume the code now that the request is fully validated, so it
            # cannot be redeemed a second time (single-use, RFC 6749 §4.1.2).
            authorization.code_used = True
            db.session.commit()

            # Extend expiration for non-permanent applications
            if application.client_id != "client_id_12decaf34bad56" and application.expires_at is not None:
                application.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
                db.session.commit()
                debug(f'Extended expiration for {application.client_id} to {application.expires_at}')

            scope = authorization.scope
            auth_time = authorization.authentication_start
            # A fresh authorization starts a new refresh-token family.
            refresh_family = uuid.uuid4().hex
        else:
            return token_error('invalid_grant', 'Authorization code is invalid or has expired', 400)

    else:
        # Any grant_type other than the two supported above (including a missing
        # grant_type) must be rejected with unsupported_grant_type rather than
        # falling through to an UnboundLocalError (RFC 6749 §5.2).
        debug(f'In /s2s/token - unsupported grant_type: {grant_type}')
        return token_error('unsupported_grant_type', f'Unsupported grant_type: {grant_type}', 400)

    # Key pair from https://chatgpt.com/share/676128c4-ffdc-8002-85b9-0fdea65978d1
    private_key = application.rsa_private_key
    key_id = application.key_id
    # Access/ID token lifetime. RFC 6749 §4.2.2 / RFC 6750 define expires_in in
    # SECONDS, so this value is both the actual token expiry and the advertised
    # expires_in — they must stay in the same unit. 3600s = 1 hour.
    expires_in_seconds = 3600

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
        authentication.expiry_time = (timedelta(seconds=expires_in_seconds) + now_time)
        authentication.scope = scope
        
        db.session.add(authentication)
        db.session.commit()
        debug(authentication.trace())
    elif authentication.scope != scope:
        # Refresh scope on a reused authentication so newly requested
        # scopes (e.g. groups) are not dropped from the issued tokens.
        authentication.scope = scope
        db.session.add(authentication)
        db.session.commit()
        debug(authentication.trace())

    access_content = {
        "jti": uuid.uuid4().hex,
        "sub": authentication.subject,
        "aud": client_id,
        "iss": external_url('views.index'),
        # What time was this application's authentication session started?
        "iat": numeric_date(authentication.authentication_time),
        "exp": numeric_date(authentication.expiry_time),
        "scope": authentication.scope,
        # Distinguishes an access token from an ID token so protected resources
        # can reject the wrong token type (see UserInfo).
        "token_use": "access"
        # kid is carried in the JWS header (headers={"kid": ...}) per
        # RFC 7515 §4.1.4, not in the claims.
    }

    debug(f'Access_content: {access_content}')

    access_token = jwt.encode(
        access_content,
        private_key,
        algorithm="RS256",
        headers={"kid": key_id}
    )

    id_content = {
        "jti": uuid.uuid4().hex,
        "aud": client_id,
        "iss": external_url('views.index'),
        # Time stuff
        # What time did the user sign into the OIDC?
        "auth_time": numeric_date(auth_time),
        # What time was this application's authentication session started?
        "iat": numeric_date(now_time),
        # When does this session expire?
        "exp": numeric_date(timedelta(seconds=expires_in_seconds)+now_time),
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
        algorithm="RS256",
        headers={"kid": key_id}
    )

    reply = {
        "jti": uuid.uuid4().hex,
        "id_token": id_token,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in_seconds
    }

    if "offline_access" in scope.split():
        new_refresh_token = hashlib.sha256(os.urandom(32)).hexdigest()

        # Store the (rotated) refresh token in the database, in the same family
        # as the token that produced this request.
        refresh_entry = RefreshToken(
            token=new_refresh_token,
            subject=user.username,
            audience=client_id,
            scope=scope,
            auth_time=auth_time,
            issued_at=now_time,
            expiry_time=(timedelta(days=30) + now_time),  # Refresh token valid for 30 days
            family_id=refresh_family
        )
        db.session.add(refresh_entry)
        db.session.commit()
        reply["refresh_token"] = new_refresh_token  # Add it to the response

    debug(f"Request: '/s2s/token' Reply: {reply}")
    # RFC 6749 §5.1: a successful token response carries credentials and MUST
    # NOT be cached. token_error() already sets these on the failure paths.
    response = jsonify(reply)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response