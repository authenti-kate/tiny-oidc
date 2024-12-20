import uuid
import sqlalchemy as sa
from datetime import datetime, timezone, timedelta
from app.extensions import db

class Session(db.Model):
    key = db.Column(sa.Uuid, primary_key=True, default=uuid.uuid4())
    data = db.Column(sa.Text, default="{}")
    expires = db.Column(sa.DateTime, default=datetime.now(timezone.utc) + timedelta(hours=4))

    def trace(self):
        data = {
            'key': self.key,
            'data': self.data,
            'expires': self.expires.strftime("%Y-%m-%d %H:%M:%S")
        }
        return f'Session: {data}'
    
    def __repr__(self):
        return f'<Session {self.key}>'