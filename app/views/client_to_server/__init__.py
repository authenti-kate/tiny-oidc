from flask import Response

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