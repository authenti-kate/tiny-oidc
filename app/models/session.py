import uuid
import sqlalchemy as sa
from datetime import datetime, timezone, timedelta
from app.extensions import db

class Session(db.Model):
    key = db.Column(sa.Uuid, primary_key=True)
    data = db.Column(sa.Text)
    expires = db.Column(sa.DateTime)

    def __init__(self, key: uuid = None, data: str = "{}", expires: datetime = None):
        if key is None:
            key = uuid.uuid4()
        self.key = key
        self.data = data
        if expires is None:
            expires = datetime.now(timezone.utc) + timedelta(hours=4)
        self.expires = expires

    def trace(self):
        data = {
            'key': self.key,
            'data': self.data,
            'expires': self.expires.strftime("%Y-%m-%d %H:%M:%S")
        }
        return f'Session: {data}'
    
    def __repr__(self):
        return f'<Session {self.key}>'