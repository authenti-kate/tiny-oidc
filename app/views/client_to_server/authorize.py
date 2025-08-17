import re
from datetime import datetime, timezone
from flask import url_for, redirect, request
from app.log import debug
from app.views import bp
from app.extensions import db
from app.models.application import Application
from app.models.authorization import Authorization
from app.session import getSessionData, setSessionData, deleteSessionData, _mySession
from app.views.client_to_server import invalid_authorize_data


@bp.route('/c2s/authorize')
def authorization_endpoint():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    debug(f'GET: /c2s/authorize args: {data}')

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

    nonce = request.args.get('nonce', getSessionData('nonce'))

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
            f'In /c2s/authorize - Invalid authorization context provided : {", ".join(invalid_context)}', str(_mySession().key))
        return invalid_authorize_data('Invalid authorization context provided')

    # Check user session
    #
    # Strictly speaking, at this point we should also verify whether
    # request.args.get('prompt') is populated with the term "consent"
    # then we should also note this, and force them through a step
    # to confirm they're happy with the client_id being able to request
    # your authentication data. This, however, is a toy and shouldn't
    # introduce additional workflows, right now! :)
    #
    # Actually, on further reading, there are three additional options
    # here, "none" - don't prompt, "login" force a re-login! and
    # "select_account" - offer the option to switch to another account,
    # if the user has one.
    # Link: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    user_key = getSessionData('user')
    if not user_key:
        setSessionData('client_id',     client_id)
        setSessionData('response_type', response_type)
        setSessionData('scope',         scope)
        setSessionData('redirect_uri',  redirect_uri)
        setSessionData('state',         state)
        if nonce:
            setSessionData('nonce',         nonce)
        return redirect(url_for('views.login'))
    else:
        # We got back here, we don't need to keep this now.
        deleteSessionData('client_id')
        deleteSessionData('response_type')
        deleteSessionData('scope')
        deleteSessionData('redirect_uri')
        deleteSessionData('state')
        deleteSessionData('nonce')

    # Get the authorization record
    auth_state = 'Existing '
    authorization: Authorization = Authorization.query.filter(
        Authorization.user == user_key,
        Authorization.application_client_id == application.client_id,
        Authorization.session_valid >= datetime.now(timezone.utc),
        Authorization.session_start <= datetime.now(timezone.utc)
    ).one_or_none()
    if not authorization:
        auth_state = 'New '
        authorization: Authorization = Authorization(
            user=user_key,
            application_client_id=application.client_id,
            scope=scope,
            authentication_start=datetime.fromtimestamp(getSessionData('sign_in'), timezone.utc),
            nonce=nonce
        )
        db.session.add(authorization)
        db.session.commit()
    debug(auth_state + authorization.trace())

    # If we don't authenticate the user, we should, *strictly speaking*
    # return an error to the RP. We don't do this!
    # See this link for details of how it *should* be implemented!
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    return redirect(f'{redirect_uri}?code={authorization.code}&state={state}')
