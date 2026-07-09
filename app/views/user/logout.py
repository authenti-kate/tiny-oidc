from urllib.parse import urlencode, urlsplit, urlunsplit
from flask import url_for, request
from markupsafe import escape
from app.views import bp
from app.log import debug
from app.session import deleteSessionData

@bp.route('/user/logout')
def logout():
    """RP-Initiated Logout 1.0, minus the redirect.

    The login session is cleared, but a post_logout_redirect_uri is never
    followed: the target is shown on an interstitial page instead.

    RP-Initiated Logout §2 requires the provider to validate the target against
    the URIs the client registered. Otherwise the end-session endpoint is an
    open redirect on the provider's own origin: an unauthenticated GET that
    bounces a browser anywhere an attacker names, wearing the provider's domain.
    tiny-oidc registers redirect URIs loosely on purpose (the seeded client uses
    the '*' wildcard), so there is nothing meaningful to validate against.
    Displaying the target keeps the endpoint useful for exercising a client's
    logout flow while making the redirect impossible.
    """
    debug('GET: /user/logout')
    post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    state = request.args.get('state')

    deleteSessionData('user')
    deleteSessionData('sign_in')

    if post_logout_redirect_uri:
        # Show the target exactly as the RP would have received it, state and
        # all, so a client author can see what a real provider would have sent.
        parts = urlsplit(post_logout_redirect_uri)
        query = parts.query
        if state:
            query = query + ('&' if query else '') + urlencode({'state': state})
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
        debug(f'/user/logout - not following post_logout_redirect_uri: {target}')
        # The target is caller-controlled, so escape it rather than reflecting
        # it into the page verbatim.
        body = (
            f'<p>You have logged out, you would be redirected to '
            f'<code>{escape(target)}</code>. '
            f'For security reasons, this will not happen here.</p>'
        )
    else:
        body = '<p>You have logged out.</p>'

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
        {body}
        <p><a href="{url_for('views.login')}">Log back in</a></p>
    </body>
</html>"""
