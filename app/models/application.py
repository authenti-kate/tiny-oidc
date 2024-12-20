from app.extensions import db


def initApplication():
    all_apps = Application.query.all()
    if len(all_apps) == 0:
        # Create a new RSA Public/Private key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        app = Application(
            client_id="12decaf34bad56",
            client_secret="Super-+Secret_=Key0123456789",
            rsa_private_key=pem_private,
            rsa_public_key=pem_public
        )
        db.session.add(app)
        db.session.commit()


class Application(db.Model):
    client_id = db.Column(db.String(255), primary_key=True)
    client_secret = db.Column(db.String(255))
    rsa_private_key = db.Column(db.Text)
    rsa_public_key = db.Column(db.Text)
    acceptable_redirect_uri = db.Column(db.Text, default='*')

    def trace(self):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'rsa_private_key': self.rsa_private_key,
            'rsa_public_key': self.rsa_public_key,
            'acceptable_redirect_uri': self.acceptable_redirect_uri
        }
        return f'Application: {data}'

    def __repr__(self):
        return f'<Application {self.client_id}>'
