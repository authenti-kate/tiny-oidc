import hmac
from flask import Response, jsonify, request
from app.log import debug


def ct_equal(a, b):
    """Constant-time string comparison that tolerates None and non-ASCII."""
    return hmac.compare_digest((a or '').encode('utf-8'), (b or '').encode('utf-8'))


def client_credentials():
    """Extract client credentials per RFC 6749 §2.3.1.

    Supports client_secret_basic (HTTP Basic Authorization header) and
    client_secret_post (request body). Returns (client_id, client_secret),
    either of which may be None when absent.
    """
    auth = request.authorization
    if auth is not None and (auth.type or '').lower() == 'basic':
        return auth.username, auth.password
    return request.form.get('client_id', None), request.form.get('client_secret', None)


def token_error(error, description=None, status=400):
    """RFC 6749 §5.2 error response: JSON body {"error", "error_description"}.

    Token-endpoint responses MUST set Cache-Control: no-store / Pragma: no-cache
    (§5.1). A 401 additionally carries a WWW-Authenticate challenge (§5.2).
    """
    body = {"error": error}
    if description:
        body["error_description"] = description
    resp = jsonify(body)
    resp.status_code = status
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    if status == 401:
        resp.headers['WWW-Authenticate'] = 'Basic'
    return resp


def invalid_token_data(message):
    debug(f"400: {message}")
    # Note, this does not strictly comply with
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
    # We probably should improve this!
    #
    # Response should look like:
    # {"error": "{error_code}", "error_description": "{message}"}
    #
    # error_code should be one of "invalid_request", "invalid_client",
    # "invalid_grant", "unauthorized_client", "unsupported_grant_type",
    # "invalid_scope"
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

from . import well_known
from . import introspection
from . import keys
from . import token
from . import user_info