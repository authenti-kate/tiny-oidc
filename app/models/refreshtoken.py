import sqlalchemy as sa
from datetime import datetime, timedelta, timezone

from app.extensions import db

class RefreshToken(db.Model):
    token = db.Column(sa.String(255), primary_key=True)
    subject = db.Column(sa.String(255))
    audience = db.Column(sa.String(255))
    scope = db.Column(sa.String(255))
    issued_at = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    expiry_time = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)+timedelta(days=30)))
    auth_time = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    # Rotation / replay detection (RFC 9700 §2.2.2): tokens issued from one
    # authorization share a family_id; a token is consumed when rotated, and
    # re-presenting a consumed token revokes the whole family.
    family_id = db.Column(sa.String(255), index=True)
    consumed = db.Column(sa.Boolean, default=False)

    def trace(self):
        data = {
            'token': self.token,
            'subject': self.subject,
            'audience': self.audience,
            'scope': self.scope,
            'issued_at': self.issued_at.strftime("%Y-%m-%d %H:%M:%S"),
            'expiry_time': self.expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
            'auth_time': self.auth_time.strftime("%Y-%m-%d %H:%M:%S"),
            'family_id': self.family_id,
            'consumed': self.consumed
        }
        return f'RefreshToken: {data}'

    def __repr__(self):
        return f'<RefreshToken for {self.token} until {self.expiry_time.strftime("%Y-%m-%d %H:%M:%S")}>'
