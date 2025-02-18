import base64
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


class Application(db.Model):
    client_id = db.Column(db.String(255), primary_key=True)
    client_secret = db.Column(db.String(255))
    rsa_private_key = db.Column(db.Text)
    rsa_public_key = db.Column(db.Text)
    key_id = db.Column(db.Text)
    acceptable_redirect_uri = db.Column(db.Text, default='*')

    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

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
            'acceptable_redirect_uri': self.acceptable_redirect_uri
        }
        return f'Application: {data}'

    def __repr__(self):
        return f'<Application {self.client_id}>'
