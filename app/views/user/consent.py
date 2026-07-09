import secrets
from flask import redirect, request, url_for
from markupsafe import escape
from app.views import bp
from app.log import debug, info, trace
from app.crypto import ct_equal
from app.session import getSessionData, setSessionData, deleteSessionData, _mySession
from app.views.client_to_server import authorize_error_redirect

# The parameters of the authorization request being consented to, parked in the
# session across the round-trip (the same set /c2s/authorize stores for login).
REQUEST_KEYS = (
    'client_id', 'response_type', 'scope', 'redirect_uri', 'state',
    'nonce', 'code_challenge', 'code_challenge_method',
)


@bp.route('/user/consent', methods=['GET', 'POST'])
def consent():
    """A deliberately minimal consent screen (OIDC Core §3.1.2.1, prompt=consent).

    Consent is all-or-nothing and is NOT persisted: there is no consent store,
    so the screen appears exactly when an RP asks for it with prompt=consent and
    never otherwise. That keeps a consent gate out of every other flow, at the
    cost of never being able to answer consent_required for prompt=none — which
    is consistent, since a provider that remembers nothing never needs to ask.

    Approving redirects back into /c2s/authorize, which then issues a code.
    Denying returns access_denied to the RP (RFC 6749 §4.1.2.1).
    """
    debug(f'{request.method}: /user/consent')

    # Only reachable as part of an authorization request that asked for consent.
    if not getSessionData('pending_consent'):
        return redirect(url_for('views.index'))

    client_id = getSessionData('client_id')
    scope = getSessionData('scope')
    redirect_uri = getSessionData('redirect_uri')
    state = getSessionData('state')
    if not client_id or not scope or not redirect_uri:
        # Nothing coherent to consent to; drop the flag rather than loop.
        deleteSessionData('pending_consent')
        return redirect(url_for('views.index'))

    if request.method == 'POST':
        expected_csrf = getSessionData('csrf_token')
        if not expected_csrf or not ct_equal(request.form.get('csrf_token', ''), expected_csrf):
            trace('CSRF token mismatch on consent', str(_mySession().key))
            return redirect(url_for('views.consent'))

        decision = request.form.get('decision')
        # Decided either way: the request no longer owes a consent answer, so
        # the redirect below re-enters /c2s/authorize and falls straight through.
        deleteSessionData('pending_consent')

        if decision == 'accept':
            info(f'Consent granted to {client_id} for scope "{scope}"', str(_mySession().key))
            params = dict(
                client_id=client_id,
                response_type=getSessionData('response_type'),
                scope=scope,
                redirect_uri=redirect_uri,
            )
            if state is not None:
                params['state'] = state
            return redirect(url_for('views.authorization_endpoint', **params))

        info(f'Consent denied to {client_id} for scope "{scope}"', str(_mySession().key))
        for key in REQUEST_KEYS:
            deleteSessionData(key)
        # RFC 6749 §4.1.2.1: the resource owner denied the request.
        return authorize_error_redirect(redirect_uri, 'access_denied', 'The user denied the request', state)

    csrf_token = getSessionData('csrf_token')
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        setSessionData('csrf_token', csrf_token)

    scopes = ''.join(f'<li><code>{escape(s)}</code></li>' for s in scope.split())
    return f"""<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server - Consent</title>
    </head>
    <body>
        <h1>Consent</h1>
        <p>You got here because <b>{escape(client_id)}</b> asked for your consent
           to send it your stuff. It is asking for:</p>
        <ul>{scopes}</ul>
        <p>This is all-or-nothing. There is no partial consent, and nothing is
           remembered: you will be asked again next time an application asks.</p>
        <form action="{url_for('views.consent')}" method="post">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <button type="submit" name="decision" value="accept">Accept</button>
            <button type="submit" name="decision" value="reject">Reject</button>
        </form>
    </body>
</html>"""
