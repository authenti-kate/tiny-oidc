import uuid
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone

from app.extensions import db

class Authorization(db.Model):
    user = db.Column(sa.String(255), index=True)
    application_client_id = db.Column(sa.String(255), index=True)
    authentication_start = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    session_start = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    session_valid = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)+timedelta(hours=4)))
    code = db.Column(sa.String(255), default=str(uuid.uuid4()))
    scope = db.Column(sa.String(255))
    
    __table_args__ = (
        db.PrimaryKeyConstraint(
            user,
            application_client_id,
            session_start
        ),
    )

    def trace(self):
        data = {
            'user': self.user,
            'application': self.application_client_id,
            'authentication_start': self.authentication_start.strftime("%Y-%m-%d %H:%M:%S"),
            'session_start': self.session_start.strftime("%Y-%m-%d %H:%M:%S"),
            'session_valid': self.session_valid.strftime("%Y-%m-%d %H:%M:%S"),
            'code': self.code,
            'scope': self.code
        }
        return f'Authorization: {data}'

    def __repr__(self):
        return f'<Authorization for {self.user} until {self.session_length}>'
