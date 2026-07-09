from urllib.parse import urlencode, urlsplit, urlunsplit
from flask import Response, redirect


def authorize_error_redirect(redirect_uri, error, description=None, state=None):
    """Report an authorization error back to the RP (OIDC Core §3.1.2.6 /
    RFC 6749 §4.1.2.1).

    Only call this once redirect_uri (and client_id) have been validated —
    errors in those MUST NOT be redirected. The error parameters are appended
    to any existing query string on the redirect_uri.
    """
    params = {'error': error}
    if description:
        params['error_description'] = description
    if state:
        params['state'] = state
    parts = urlsplit(redirect_uri)
    query = parts.query + ('&' if parts.query else '') + urlencode(params)
    return redirect(urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)))


def authorize_success_redirect(redirect_uri, code, state=None):
    """Redirect back to the RP with the authorization code (RFC 6749 §4.1.2),
    appending to any existing query string rather than assuming there is none.
    """
    params = {'code': code}
    if state:
        params['state'] = state
    parts = urlsplit(redirect_uri)
    query = parts.query + ('&' if parts.query else '') + urlencode(params)
    return redirect(urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)))


def invalid_authorize_data(message):
    # Note, this does not strictly comply with
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthError or
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
    # We probably should improve this!
    #
    # We should redirect to
    # {redirect_uri}?error={error_code}&error_description={message}&state={state}
    #
    # error_code should be one of "interaction_required", "login_required",
    # "account_selection_required", "consent_required", "invalid_request_uri",
    # "invalid_request_object", "request_not_supported",
    # "request_uri_not_supported" or "registration_not_supported"
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

from . import authorize
from . import client