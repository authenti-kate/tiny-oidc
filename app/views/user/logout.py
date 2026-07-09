import re
import jwt
from urllib.parse import urlencode, urlsplit, urlunsplit
from flask import url_for, request, redirect
from app.views import bp
from app.log import debug
from app.models.application import Application
from app.session import deleteSessionData

@bp.route('/user/logout')
def logout():
    """RP-Initiated Logout 1.0.

    Clears the login session and, when a post_logout_redirect_uri is supplied,
    redirects back to the RP (echoing state). If an id_token_hint is present it
    is used to identify the client and validate the redirect target.
    """
    debug('GET: /user/logout')
    id_token_hint = request.args.get('id_token_hint')
    post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    state = request.args.get('state')

    deleteSessionData('user')
    deleteSessionData('sign_in')

    if post_logout_redirect_uri:
        # Validate the redirect target against the hinted client when possible.
        allowed = True
        if id_token_hint:
            try:
                claims = jwt.decode(id_token_hint, options={'verify_signature': False})
                application = Application.query.filter_by(client_id=claims.get('aud')).one_or_none()
                if application and application.acceptable_redirect_uri != '*':
                    allowed = bool(re.match(application.acceptable_redirect_uri, post_logout_redirect_uri))
            except jwt.PyJWTError:
                allowed = False
        if allowed:
            parts = urlsplit(post_logout_redirect_uri)
            query = parts.query
            if state:
                query = query + ('&' if query else '') + urlencode({'state': state})
            return redirect(urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)))
        debug('/user/logout - post_logout_redirect_uri rejected for hinted client')

    return f"""
<html>
    <head>
        <title>Tiny OIDC Server - Logout</title>
    </head>
    <body>
        <h1>Tiny OIDC Server - Logout</h1>
        <hr>
        <h2 color="red">BE WARNED, THIS SERVER IS NOT SECURE AND IS USED FOR POC TESTING ONLY</h2>
        <hr>
        <p><a href="{url_for('views.login')}">Log back in</a></p>
    </body>
</html>"""
