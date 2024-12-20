import uuid
import sqlalchemy as sa
from app.extensions import db
from datetime import datetime, timezone

class enumLevel(sa.Enum):
    info = 'Info'
    debug = 'Debug'
    trace = 'Trace'

class Log(db.Model):
    counter = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(sa.DateTime, default = datetime.now(timezone.utc))
    level = db.Column(enumLevel)
    message = db.Column(sa.Text)
    session = db.Column(sa.String)

    def trace(self):
        data = {
            'counter': self.counter,
            'timestamp': self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'level': self.level,
            'message': self.message,
            'session': self.session
        }
        return f'Log: {data}'
    
    def __repr__(self):
        return f'<Log : {str(self.session)} @ {self.level} {self.message[:20]}>'
