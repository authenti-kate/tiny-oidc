from flask import url_for
from app.log import debug
from datetime import datetime, timezone
from app.main import bp
from app.models.user import User
from app.session import getSessionData

@bp.route('/')
def index():
    user_object = None
    user = getSessionData('user')
    if user:
        user_object : User = User.query.filter(User.username == user).one_or_none()
    content = """<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server</title>
    </head>
    <body>
        <h1>Tiny OIDC Server</h1>
        <p>This Tiny OIDC Server is designed to be used for simple OIDC tests in development environments.</p>
        <p>It is based on <a href="https://spapas.github.io/2023/11/29/openid-connect-tutorial/">this blog post</a> and
            <a href="https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660">this set of annotated diagrams</a>.</p>
        <hr>
        <h2 color="red">BE WARNED, THIS SERVER IS NOT SECURE AND IS USED FOR POC TESTING ONLY</h2>
        <hr>"""
    if user_object:
        content += f"""
        <p>Logged in as "{user_object.display_name}" - {user_object.first_name} {user_object.last_name} - "{user_object.email}"</p>
        <p><a href="{url_for('main.logout')}">Log out</a></p>"""
    else:
        content += f"""
        <p>Not currently logged in.</p>
        <p><a href="{url_for('main.login')}">Log In</a> or setup a client.</p>"""
    content += """
    </body>
</html>"""
    return content

@bp.route('/health')
def test_page():
    return """<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server - Health</title>
    </head>
    <body>
        <h1>OK</h1>
    </body>
</html>"""

@bp.route('/cron')
def cron():
    from app.models.session import Session
    rows = Session.query.filter(Session.expires <= datetime.now(timezone.utc)).delete()
    debug(f'Deleted {rows} rows from Session table')
    from app.models.authorization import Authorization
    rows = Authorization.query.filter(Authorization.session_valid <= datetime.now(timezone.utc)).delete()
    debug(f'Deleted {rows} rows from Authorization table')
    return f"""<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server - Cron</title>
    </head>
    <body>
        <h1>OK</h1>
    </body>
</html>"""