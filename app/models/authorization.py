import uuid
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone

from app.extensions import db

class Authorization(db.Model):
    user = db.Column(sa.String(255), index=True)
    application = db.Column(sa.String(255), index=True)
    session_start = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)))
    session_valid = db.Column(sa.DateTime, default=(datetime.now(timezone.utc)+timedelta(hours=4)))
    code = db.Column(sa.String(255), default=str(uuid.uuid4()))
    scope = db.Column(sa.String(255))
    
    __table_args__ = (
        db.PrimaryKeyConstraint(
            user,
            application
        ),
    )

    def __repr__(self):
        return f'<Authorization for {self.user} until {self.session_length}>'
