import re
import uuid
from datetime import datetime, timezone, timedelta
from flask import url_for, redirect, request, current_app
from app.log import debug
from app.views import bp
from app.extensions import db
from app.models.application import Application
from app.models.authorization import Authorization
from app.session import getSessionData, setSessionData, deleteSessionData, _mySession
from app.views.client_to_server import invalid_authorize_data, authorize_error_redirect, authorize_success_redirect


@bp.route('/c2s/authorize')
def authorization_endpoint():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    debug(f'GET: /c2s/authorize args: {data}')

    # Phase 1 — validate client_id and redirect_uri. Per OIDC Core §3.1.2.6 /
    # RFC 6749 §4.1.2.1 these MUST NOT be reported by redirecting (that could
    # deliver an error or code to an attacker-chosen URI); show an error page.
    invalid_context = []
    redirect_uri = request.args.get('redirect_uri', getSessionData('redirect_uri'))
    client_id = request.args.get('client_id', getSessionData('client_id'))
    application = None
    if not client_id:
        invalid_context.append('client_id')
    else:
        application: Application = Application.query.filter(
            Application.client_id == client_id
        ).one_or_none()
        if not application:
            invalid_context.append('NON_EXISTANT:client_id')
    if not redirect_uri:
        invalid_context.append('redirect_uri')
    elif application is not None and not application.acceptable_redirect_uri == '*' \
            and not re.match(application.acceptable_redirect_uri, redirect_uri):
        invalid_context.append('NON_MATCHING:redirect_uri')

    if len(invalid_context) > 0:
        debug(
            f'In /c2s/authorize - Invalid authorization context provided : {", ".join(invalid_context)}', str(_mySession().key))
        return invalid_authorize_data('Invalid authorization context provided')

    # Phase 2 — redirect_uri and client_id are now trusted, so any remaining
    # validation failure is reported to the RP as an OAuth error redirect.
    response_type = request.args.get('response_type', getSessionData('response_type'))
    scope = request.args.get('scope', getSessionData('scope'))
    state = request.args.get('state', getSessionData('state'))
    nonce = request.args.get('nonce', getSessionData('nonce'))
    code_challenge = request.args.get('code_challenge', getSessionData('code_challenge'))
    code_challenge_method = request.args.get('code_challenge_method', getSessionData('code_challenge_method'))
    # prompt and max_age are per-request and deliberately NOT carried across the
    # login round-trip in the session. That is what stops prompt=login looping:
    # the request that /user/login bounces back here carries neither, so the
    # freshly established session satisfies it.
    prompts = (request.args.get('prompt') or '').split()
    max_age = request.args.get('max_age')

    if not response_type:
        return authorize_error_redirect(redirect_uri, 'invalid_request', 'response_type is required', state)
    # Only the authorization code flow is implemented (RFC 6749 §3.1.1).
    if response_type != 'code':
        return authorize_error_redirect(redirect_uri, 'unsupported_response_type', f'Unsupported response_type: {response_type}', state)
    if not scope:
        return authorize_error_redirect(redirect_uri, 'invalid_request', 'scope is required', state)
    if 'openid' not in scope.split():
        # This is an OpenID Provider; the request MUST include openid
        # (OIDC Core §3.1.2.1).
        return authorize_error_redirect(redirect_uri, 'invalid_scope', 'openid scope is required', state)
    # OIDC Core §3.1.2.1: "none" must not be combined with any other prompt
    # value, since the two demands are contradictory.
    if 'none' in prompts and len(prompts) > 1:
        return authorize_error_redirect(redirect_uri, 'invalid_request', 'prompt=none must not be combined with other values', state)
    # max_age is "Maximum Authentication Age" in seconds (OIDC Core §3.1.2.1).
    if max_age is not None:
        try:
            max_age = int(max_age)
        except ValueError:
            max_age = -1
        if max_age < 0:
            return authorize_error_redirect(redirect_uri, 'invalid_request', 'max_age must be a non-negative integer', state)
    # state is RECOMMENDED, not REQUIRED (RFC 6749 §4.1.1); it is echoed back
    # only when the client supplied it.

    # PKCE (RFC 7636). Default a missing method to "plain" (§4.3); only S256
    # (RECOMMENDED) and plain are supported.
    if code_challenge:
        if not code_challenge_method:
            code_challenge_method = 'plain'
        elif code_challenge_method not in ('S256', 'plain'):
            return authorize_error_redirect(redirect_uri, 'invalid_request', 'Unsupported code_challenge_method', state)
    elif current_app.config.get('PKCE_REQUIRED'):
        return authorize_error_redirect(redirect_uri, 'invalid_request', 'PKCE code_challenge is required', state)

    def remember_request():
        """Park this authorization request across an interactive round-trip."""
        setSessionData('client_id',     client_id)
        setSessionData('response_type', response_type)
        setSessionData('scope',         scope)
        setSessionData('redirect_uri',  redirect_uri)
        setSessionData('state',         state)
        if nonce:
            setSessionData('nonce',         nonce)
        if code_challenge:
            setSessionData('code_challenge', code_challenge)
        if code_challenge_method:
            setSessionData('code_challenge_method', code_challenge_method)

    # Record that this request owes a consent decision. Set before the login
    # check below so that "prompt=login consent" still asks for consent once the
    # user has re-authenticated. Cleared by whichever way the user answers.
    #
    # If the user abandons the consent screen the flag survives, so the next
    # authorization request in this browser session will ask again even though
    # it did not request consent. That errs towards asking, and self-heals on
    # the next answer.
    if 'consent' in prompts:
        setSessionData('pending_consent', True)

    # Check user session (OIDC Core §3.1.2.1).
    user_key = getSessionData('user')

    if user_key:
        # prompt=select_account asks the user to pick among their accounts. This
        # server holds exactly one authenticated identity per session, and its
        # login page already lists every account, so re-authenticating IS the
        # account picker. Treating it as prompt=login is the honest mapping;
        # doing better would mean a session holding a set of identities.
        reauthenticate = 'login' in prompts or 'select_account' in prompts
        if not reauthenticate and max_age is not None:
            sign_in = getSessionData('sign_in')
            reauthenticate = (
                sign_in is None
                or datetime.now(timezone.utc).timestamp() - sign_in > max_age
            )
        if reauthenticate:
            # prompt=none forbids any interaction, so report rather than
            # prompt — and do not tear down the session on the way past. An RP
            # must not be able to sign a user out by probing with prompt=none.
            if 'none' in prompts:
                return authorize_error_redirect(redirect_uri, 'login_required', 'Re-authentication required and prompt=none was requested', state)
            deleteSessionData('user')
            deleteSessionData('sign_in')
            user_key = None

    if not user_key:
        # OIDC Core §3.1.2.1: prompt=none forbids any interactive prompt, so an
        # absent session is reported to the RP rather than shown a login page.
        if 'none' in prompts:
            return authorize_error_redirect(redirect_uri, 'login_required', 'No active session and prompt=none was requested', state)
        remember_request()
        return redirect(url_for('views.login'))

    # Signed in, but this request still owes a consent decision. /user/consent
    # redirects back here once answered, carrying no prompt — which is what
    # stops this looping.
    if getSessionData('pending_consent'):
        remember_request()
        return redirect(url_for('views.consent'))

    # We got back here, we don't need to keep this now.
    # But preserve nonce for the authorization creation
    stored_nonce = getSessionData('nonce')
    if stored_nonce and not nonce:
        nonce = stored_nonce
    stored_code_challenge = getSessionData('code_challenge')
    if stored_code_challenge and not code_challenge:
        code_challenge = stored_code_challenge
    stored_code_challenge_method = getSessionData('code_challenge_method')
    if stored_code_challenge_method and not code_challenge_method:
        code_challenge_method = stored_code_challenge_method
    deleteSessionData('client_id')
    deleteSessionData('response_type')
    deleteSessionData('scope')
    deleteSessionData('redirect_uri')
    deleteSessionData('state')
    deleteSessionData('nonce')
    deleteSessionData('code_challenge')
    deleteSessionData('code_challenge_method')

    # Get the authorization record
    auth_state = 'Existing '
    authorization: Authorization = Authorization.query.filter(
        Authorization.user == user_key,
        Authorization.application_client_id == application.client_id,
        Authorization.session_valid >= datetime.now(timezone.utc),
        Authorization.session_start <= datetime.now(timezone.utc)
    ).one_or_none()
    now_utc = datetime.now(timezone.utc)
    code_lifetime = timedelta(seconds=current_app.config['AUTHORIZATION_CODE_LIFETIME'])
    session_lifetime = timedelta(seconds=current_app.config['SSO_SESSION_LIFETIME'])
    # When the user actually authenticated. This is the auth_time claim, so it
    # must track the current login: after a prompt=login or max_age forced
    # re-authentication, sign_in has moved and a reused Authorization row must
    # move with it (OIDC Core §2, auth_time).
    authentication_start = datetime.fromtimestamp(getSessionData('sign_in'), timezone.utc)

    if not authorization:
        auth_state = 'New '
        authorization: Authorization = Authorization(
            user=user_key,
            application_client_id=application.client_id,
            scope=scope,
            authentication_start=authentication_start,
            session_start=now_utc,
            session_valid=now_utc + session_lifetime,
            code_expires_at=now_utc + code_lifetime,
            redirect_uri=redirect_uri,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        db.session.add(authorization)
        db.session.commit()
    else:
        # Reuse the SSO session but mint a FRESH single-use code for this
        # authorization request. Each /authorize must yield a code that can be
        # redeemed exactly once (RFC 6749 §4.1.2); issuing a new code also
        # invalidates any prior unredeemed code for this session.
        authorization.code = str(uuid.uuid4())
        authorization.code_used = False
        # The new code gets its own full lifetime, independent of how much of
        # the SSO session window remains.
        authorization.code_expires_at = now_utc + code_lifetime
        # Replace the per-request parameters with THIS request's values, even
        # when absent. These bind to a single authorization request, not to the
        # SSO session: the code_challenge must bind the code to this request's
        # verifier (RFC 7636 §4.4) and the nonce claim must be the value sent in
        # this request (OIDC Core §3.1.3.6). Only overwriting them when the new
        # request supplies a value leaves a previous request's challenge and
        # nonce attached to a freshly minted code — which makes a non-PKCE
        # request after a PKCE one issue a code that cannot be redeemed, and
        # puts a stale nonce in the ID token.
        authorization.scope = scope
        authorization.nonce = nonce
        authorization.redirect_uri = redirect_uri
        authorization.code_challenge = code_challenge
        authorization.code_challenge_method = code_challenge_method
        authorization.authentication_start = authentication_start
        db.session.commit()
        auth_state = 'Updated '
    debug(auth_state + authorization.trace())

    # If we don't authenticate the user, we should, *strictly speaking*
    # return an error to the RP. We don't do this!
    # See this link for details of how it *should* be implemented!
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    return authorize_success_redirect(redirect_uri, authorization.code, state)
