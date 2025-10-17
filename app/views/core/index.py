from flask import url_for
from app.views import bp
from app.log import debug
from app.models.user import User
from app.session import getSessionData

@bp.route('/')
def index():
    debug(f'GET: /')
    user_object = None
    user = getSessionData('user')
    if user:
        user_object : User = User.query.filter(User.username == user).one_or_none()
    content = """<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 40px;
                max-width: 900px;
            }
            .info-box {
                background-color: #f0f8ff;
                border: 1px solid #4a90e2;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }
            .code {
                background-color: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
            }
        </style>
    </head>
    <body>
        <h1>Tiny OIDC Server</h1>
        <p>This Tiny OIDC Server is designed to be used for simple OIDC tests in development environments.</p>
        <p>It is based on <a href="https://spapas.github.io/2023/11/29/openid-connect-tutorial/">this blog post</a> and
            <a href="https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660">this set of annotated diagrams</a>.</p>
        <hr>
        <h2 color="red">BE WARNED, THIS SERVER IS NOT SECURE AND IS USED FOR POC TESTING ONLY</h2>
        <hr>

        <div class="info-box">
            <h3>Quick Start: Generate a Client Application</h3>
            <p>Visit <a href="/app">/app</a> to generate a new client_id and client_secret for testing.</p>
            <ul>
                <li><strong>Auto-generated applications expire after 7 days</strong></li>
                <li>Each time you use the credentials, the expiration deadline is extended to 7 days from when you used the credential</li>
                <li>The default application <span class="code">client_id_12decaf34bad56</span> never expires</li>
                <li>The special client_id <span class="code">invalid_client_id</span> will always fail authentication</li>
            </ul>
        </div>"""
    if user_object:
        content += f"""
        <p>Logged in as "{user_object.display_name}" - {user_object.first_name} {user_object.last_name} - "{user_object.email}"</p>
        <p><a href="{url_for('views.logout')}">Log out</a></p>"""
    else:
        content += f"""
        <p>Not currently logged in.</p>
        <p><a href="{url_for('views.login')}">Log In</a> or setup a client.</p>"""
    content += """
    </body>
</html>"""
    return content