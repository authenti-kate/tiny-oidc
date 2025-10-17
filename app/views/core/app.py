import uuid
import secrets
from datetime import datetime, timezone, timedelta
from app.views import bp
from app.log import debug
from app.models.application import Application
from app.extensions import db


@bp.route('/app')
def generate_application():
    """
    Generate a new client_id and client_secret with 7-day expiration.

    This endpoint creates a new application registration with:
    - Random client_id (UUID-based)
    - Random client_secret (secure random token)
    - 7-day expiration that extends on each use
    """
    debug('GET: /app - Generating new application')

    # Generate unique client_id
    client_id = f"client_{uuid.uuid4().hex}"

    # Generate secure random client_secret (32 bytes = 64 hex characters)
    client_secret = secrets.token_urlsafe(32)

    # Create application with 7-day expiration
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    application = Application(
        client_id=client_id,
        client_secret=client_secret,
        expires_at=expires_at
    )
    db.session.add(application)
    db.session.commit()

    debug(f'Created new application {client_id} with expiration {expires_at}')

    # Return HTML page with the credentials
    content = f"""<!DOCTYPE html>
<html>
    <head>
        <title>Tiny OIDC Server - New Application</title>
        <style>
            body {{
                font-family: monospace;
                margin: 40px;
            }}
            .credential-box {{
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                padding: 20px;
                margin: 20px 0;
                border-radius: 5px;
            }}
            .label {{
                font-weight: bold;
                color: #333;
            }}
            .value {{
                color: #0066cc;
                word-break: break-all;
            }}
            .warning {{
                background-color: #fff3cd;
                border: 1px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }}
        </style>
    </head>
    <body>
        <h1>New Application Created</h1>

        <div class="warning">
            <strong>⚠️ IMPORTANT:</strong> Save these credentials now! They will not be shown again.
        </div>

        <div class="credential-box">
            <div class="label">Client ID:</div>
            <div class="value">{client_id}</div>
        </div>

        <div class="credential-box">
            <div class="label">Client Secret:</div>
            <div class="value">{client_secret}</div>
        </div>

        <div class="credential-box">
            <div class="label">Expires At:</div>
            <div class="value">{expires_at.isoformat()}</div>
        </div>

        <p><strong>Note:</strong> This application will expire 7 days from now. Each time you use it, the expiration extends by another 7 days.</p>

        <p><a href="/">Back to Home</a></p>
    </body>
</html>"""

    return content
