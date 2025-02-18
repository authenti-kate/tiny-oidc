from app.extensions import db
import sqlalchemy as sa

class Authentication(db.Model):
    id = db.Column(sa.Integer(), primary_key=True)
    subject = db.Column(db.String(255))
    audience = db.Column(db.String(255))
    authentication_time = db.Column(sa.DateTime)
    expiry_time = db.Column(sa.DateTime)
    scope = db.Column(db.String(255))
    not_before = db.Column(sa.DateTime)

    def trace(self):
        data = {
            'id': self.id,
            'subject': self.subject,
            'audience': self.audience,
            'authentication_time': self.authentication_time.strftime("%Y-%m-%d %H:%M:%S"),
            'expiry_time': self.expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
            'scope': self.scope,
            'not_before': self.not_before.strftime("%Y-%m-%d %H:%M:%S")
        }
        return f'Authentication: {data}'