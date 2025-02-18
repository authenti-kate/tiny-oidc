from flask import Response
from app.log import debug

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