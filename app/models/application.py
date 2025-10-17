import base64
from datetime import datetime, timezone, timedelta
from app.extensions import db

def initApplication():
    all_apps = Application.query.all()
    if len(all_apps) == 0:
        app = Application(
            client_id="client_id_12decaf34bad56",
            client_secret="Super-+Secret_=Key0123456789"
        )
        db.session.add(app)
        db.session.commit()


def get_or_create_application(client_id, client_secret=None):
    """
    Get an existing application or create a new one with automatic expiration.

    Args:
        client_id: The client identifier
        client_secret: The client secret (optional for lookups, required for creation)

    Returns:
        Application object if valid, None if invalid_client_id or mismatched secret

    Behavior:
        - "invalid_client_id" always returns None
        - "client_id_12decaf34bad56" never expires
        - Other client_ids expire after 7 days
        - Using an application extends its expiration by 7 days
    """
    from app.log import debug

    # Special case: always reject invalid_client_id
    if client_id == "invalid_client_id":
        debug(f'Rejecting special invalid_client_id')
        return None

    # Look up existing application
    application = Application.query.filter_by(client_id=client_id).one_or_none()

    if application:
        # Verify client_secret if provided
        if client_secret is not None and application.client_secret != client_secret:
            debug(f'Client secret mismatch for {client_id}')
            return None

        # Extend expiration for non-permanent applications
        if client_id != "client_id_12decaf34bad56" and application.expires_at is not None:
            application.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            db.session.commit()
            debug(f'Extended expiration for {client_id} to {application.expires_at}')

        return application

    # Create new application if it doesn't exist
    if client_secret is None:
        debug(f'Cannot create application {client_id} without client_secret')
        return None

    # Determine expiration: permanent for client_id_12decaf34bad56, 7 days for others
    expires_at = None if client_id == "client_id_12decaf34bad56" else datetime.now(timezone.utc) + timedelta(days=7)

    new_application = Application(
        client_id=client_id,
        client_secret=client_secret,
        expires_at=expires_at
    )
    db.session.add(new_application)
    db.session.commit()

    debug(f'Created new application {client_id} with expiration {expires_at}')
    return new_application


class Application(db.Model):
    client_id = db.Column(db.String(255), primary_key=True)
    client_secret = db.Column(db.String(255))
    rsa_private_key = db.Column(db.Text)
    rsa_public_key = db.Column(db.Text)
    key_id = db.Column(db.Text)
    acceptable_redirect_uri = db.Column(db.Text, default='*')
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, client_id, client_secret, expires_at=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.expires_at = expires_at

        # Create a new RSA Public/Private key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        self.rsa_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.key_id = base64.b64encode(str(self.rsa_public_key).encode('utf-8')).hex()

    def trace(self):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'rsa_private_key': self.rsa_private_key,
            'rsa_public_key': self.rsa_public_key,
            'key_id': self.key_id,
            'acceptable_redirect_uri': self.acceptable_redirect_uri,
            'expires_at': self.expires_at
        }
        return f'Application: {data}'

    def __repr__(self):
        return f'<Application {self.client_id}>'
