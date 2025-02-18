from flask import url_for
from app.views import bp
from app.log import debug
from app.session import deleteSessionData

@bp.route('/user/logout')
def logout():
    """
    This function removes login session data, forcing a re-login on the next connection attempt.
    """
    debug('GET: /user/logout')
    deleteSessionData('user')
    deleteSessionData('sign_in')
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