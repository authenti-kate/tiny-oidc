import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta
from app.extensions import db

def backfill_key_ids():
    """Repair `key_id` on rows written before the thumbprint change.

    There is no migration framework here and `db.create_all()` never rewrites
    existing data, so without this an upgraded deployment keeps publishing the
    old PEM-derived kid — which no client can use, and which the token,
    introspection and userinfo endpoints all look up by.

    Idempotent: the kid is derived from the stored public key, so recomputing
    it for every row leaves already-correct values unchanged. Expired
    applications are repaired too — /s2s/keys skips them, but /s2s/introspect
    and /s2s/userinfo still resolve tokens issued before they expired.
    """
    repaired = 0
    for application in Application.query.all():
        if not application.rsa_public_key:
            continue
        expected = Application.compute_key_id(application.rsa_public_key)
        if application.key_id != expected:
            application.key_id = expected
            repaired += 1
    if repaired:
        db.session.commit()
    return repaired


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

        self.key_id = self.compute_key_id(self.rsa_public_key)

    @staticmethod
    def compute_key_id(public_key_pem):
        """The RFC 7638 JWK thumbprint of an RSA public key, used as `kid`.

        RFC 7638 §3: SHA-256 over a JSON object containing only the members
        required for the key type ("e", "kty", "n" for RSA), with keys in
        lexicographic order and no whitespace, base64url-encoded without
        padding. A client can recompute this from the JWK it was served, which
        is the property that makes a thumbprint a useful key identifier.

        This previously stored the entire PEM public key instead, via
        `base64.b64encode(str(pem).encode()).hex()`. Since the PEM is `bytes`,
        `str()` yielded its repr, baking a literal `b'` prefix and `\\n`
        escapes into the value; the result was a 1240-character kid and a
        ~1702-byte JOSE header. Real clients reject that outright — joserfc,
        the JWS backend behind Authlib, caps headers at 512 bytes because the
        header is parsed before any signature has been verified.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError('Only RSA public keys are supported')

        numbers = public_key.public_numbers()

        def b64u(value):
            raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')
            return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('utf-8')

        canonical = json.dumps(
            {'e': b64u(numbers.e), 'kty': 'RSA', 'n': b64u(numbers.n)},
            separators=(',', ':'),
            sort_keys=True
        ).encode('utf-8')
        digest = hashlib.sha256(canonical).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

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
