from urllib.parse import unquote

from flask import Response, jsonify, request


def client_credentials():
    """Extract client credentials per RFC 6749 §2.3.1.

    Supports client_secret_basic (HTTP Basic Authorization header) and
    client_secret_post (request body). Returns (client_id, client_secret),
    either of which may be None when absent.

    §2.3.1 requires a Basic-auth client to apply the application/x-www-form-
    urlencoded encoding algorithm to the client_id and client_secret before
    base64-encoding them, so they must be decoded here. Many clients (including
    requests' HTTPBasicAuth) send the values raw instead; unquoting is a no-op
    for those, so both forms are accepted.

    Caveat: a secret containing a literal '%' followed by two hex digits is
    ambiguous between the two forms and will be decoded. Avoid '%' in secrets.
    """
    auth = request.authorization
    if auth is not None and (auth.type or '').lower() == 'basic':
        return unquote(auth.username or ''), unquote(auth.password or '')
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


def bearer_error(error=None, description=None, status=401):
    """RFC 6750 §3 protected-resource error.

    Returns an HTTP 401/403 carrying a WWW-Authenticate: Bearer challenge. When
    no credentials were supplied at all, `error` is None and a bare challenge is
    emitted with no error code (RFC 6750 §3).
    """
    if error is None:
        resp = Response(status=status)
        resp.headers['WWW-Authenticate'] = 'Bearer'
        return resp
    challenge = f'Bearer error="{error}"'
    if description:
        challenge += f', error_description="{description}"'
    body = {"error": error}
    if description:
        body["error_description"] = description
    resp = jsonify(body)
    resp.status_code = status
    resp.headers['WWW-Authenticate'] = challenge
    return resp


from . import well_known
from . import introspection
from . import keys
from . import token
from . import user_info