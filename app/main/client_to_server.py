import re
import jwt
from datetime import datetime, timezone
from flask import url_for, redirect, request, Response
from app.log import debug, trace
from app.main import bp
from app.extensions import db
from app.models.application import Application
from app.models.authorization import Authorization
from app.session import getSessionData, setSessionData, deleteSessionData, _mySession

@bp.route('/c2s/authorize')
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
            f'In /c2s/authorize - Invalid authorization context provided : {", ".join(invalid_context)}', str(_mySession().key))
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
        Authorization.application_client_id == application.client_id,
        Authorization.session_valid >= datetime.now(timezone.utc)
    ).one_or_none()
    if not authorization:
        authorization: Authorization = Authorization(
            user=user_key,
            application_client_id=application.client_id,
            scope=scope,
            authentication_start=datetime.fromtimestamp(getSessionData('sign_in'))
        )
        db.session.add(authorization)
        db.session.commit()
        debug(authorization.trace())

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


@bp.route('/unknown/userinfo')
def userinfo_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'


@bp.route('/unknown/client')
def client_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'


@bp.route('/unknown/keys')
def keys_endpoint():
    # @TODO: Write this endpoint
    return 'INCOMPLETE'