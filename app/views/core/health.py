from app.log import debug
from datetime import datetime, timezone
from app.views import bp

@bp.route('/health')
def health_and_cron():
    debug(f'GET: /health')

    from app.models.session import Session
    rows = Session.query.filter(Session.expires <= datetime.now(timezone.utc)).delete()
    if rows > 0:
        debug(f'Deleted {rows} rows from Session table')
    from app.models.authorization import Authorization
    rows = Authorization.query.filter(Authorization.session_valid <= datetime.now(timezone.utc)).delete()
    if rows > 0:
        debug(f'Deleted {rows} rows from Authorization table')
    from app.models.application import Application
    rows = Application.query.filter(
        Application.expires_at != None,
        Application.expires_at <= datetime.now(timezone.utc)
    ).delete()
    if rows > 0:
        debug(f'Deleted {rows} expired applications from Application table')

    return """<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server - Health</title>
    </head>
    <body>
        <h1>OK</h1>
    </body>
</html>"""
