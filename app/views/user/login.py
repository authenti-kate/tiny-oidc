from flask import url_for, request, redirect
from datetime import datetime, timezone
from app.log import trace, info
from app.views import bp
from app.models.user import User
from app.log import debug
from app.session import getSessionData, setSessionData, _mySession

@bp.route('/user/login', methods=['GET', 'POST'])
def login():
    """
    This page does three things.
    1. If you are ALREADY LOGGED IN, it will automatically redirect you to the relevant next page (OIDC authorize or logged_in page)
    2. If you are NOT already logged in, but have provided authentication credentials, it will attempt to confirm they are valid, and redirect accordingly
    3. If you are not logged in, and haven't provided credentials, it will present the login page.
    """
    debug(f'{request.method}: /user/login')

    signed_in = False
    user = None

    # Are you already logged in?
    user_session = getSessionData('user')
    if user_session:
        user: User = User.query.filter(
            User.username == user_session
        ).one_or_none()
        signed_in = user is not None

    # Have you provided authentication credentials?
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter(
            User.username == username, User.password == password).one()
        signed_in = user is not None
        if signed_in:
            setSessionData('user', user.username)
            setSessionData('sign_in', datetime.now(timezone.utc).timestamp())
            info(f'Valid sign in for {username}', str(_mySession().key))
        else:
            trace(f'Invalid sign in for user: "{username}"', str(_mySession().key))
            return redirect(url_for('views.login'))

    # Redirect a logged in user accordingly
    if signed_in:
        client_id = getSessionData('client_id')
        response_type = getSessionData('response_type')
        scope = getSessionData('scope')
        redirect_uri = getSessionData('redirect_uri')
        state = getSessionData('state')
        if (
            client_id is not None and response_type is not None and
            scope is not None and redirect_uri is not None and state is not None
        ):
            return redirect(
                url_for(
                    'views.authorization_endpoint',
                    client_id=client_id,
                    response_type=response_type,
                    scope=scope,
                    redirect_uri=redirect_uri,
                    state=state
                )
            )
        else:
            return redirect(url_for('views.index'))

    else:
        # Provide a (horrifically insecure) login screen
        all_users = User.query.all()
        content = """<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server</title>
    </head>
    <body>
        <h1>Login - kinda</h1>
        <p>NEVER EVER implement this in your own code. This is a toy, used to prove certain usecases.</p>
        <table>
            <thead>
                <tr>
                    <th>User Information</th>
                    <th>Login Button</th>
                </tr>
            </thead>
            <tbody>"""
        for user in all_users or []:
            username = user.username
            password = user.password
            email = user.email
            first_name = user.first_name
            last_name = user.last_name
            display_name = user.display_name
            groups = user.groups

            content += f"""
                <tr>
                    <td>
                        <b>{username}</b> - {email}<br>
                        FN: "{first_name}" LN: "{last_name}" DN: "{display_name}"<br>
                        Groups: {groups}
                    </td>
                    <td>
                        <form action="{url_for('views.login')}" method="post">
                            <input type="hidden" name="username" value="{username}">
                            <input type="hidden" name="password" value="{password}">
                            <button type="submit">Login as {username}</button>
                        </form>
                    </td>
                </tr>"""
        content += """
            </tbody>
        </table>
    </body>
</html>"""
        return content
