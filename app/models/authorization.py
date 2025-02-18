import uuid
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone

from app.extensions import db

class Authorization(db.Model):
    user = db.Column(sa.String(255), index=True)
    application_client_id = db.Column(sa.String(255), index=True)
    authentication_start = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    session_start = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    session_valid = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)+timedelta(minutes=15)))
    code = db.Column(sa.String(255))
    scope = db.Column(sa.String(255))
    
    __table_args__ = (
        db.PrimaryKeyConstraint(
            user,
            application_client_id,
            session_start
        ),
    )

    def __init__(
        self,
        user = None,
        application_client_id = None,
        authentication_start = None,
        session_start = None,
        session_valid = None,
        code = None,
        scope = None
    ):
        if user is not None:
            self.user = user
            
        if application_client_id is not None:
            self.application_client_id = application_client_id

        if authentication_start is not None:
            self.authentication_start = authentication_start

        if session_start is not None:
            self.session_start = session_start

        if session_valid is not None:
            self.session_valid = session_valid

        if code is not None:
            self.code = code
        else:
            self.code = str(uuid.uuid4())

        if scope is not None:
            self.scope = scope

    def trace(self):
        data = {
            'user': self.user,
            'application': self.application_client_id,
            'authentication_start': self.authentication_start.strftime("%Y-%m-%d %H:%M:%S"),
            'session_start': self.session_start.strftime("%Y-%m-%d %H:%M:%S"),
            'session_valid': self.session_valid.strftime("%Y-%m-%d %H:%M:%S"),
            'code': self.code,
            'scope': self.scope
        }
        return f'Authorization: {data}'

    def __repr__(self):
        return f'<Authorization for {self.user} until {self.session_length}>'
