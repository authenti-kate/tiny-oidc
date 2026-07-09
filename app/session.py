import uuid
import json

from flask import session
from app.extensions import db
from app.models.session import Session
from datetime import datetime, timezone, timedelta


def _mySession() -> Session:
    session_key = session['key'] if 'key' in session else None

    if session_key:
        # Indexed primary-key lookup rather than loading and scanning every
        # session row (the previous Session.query.all() was O(n) and a DoS
        # footgun as the table grows).
        my_session = None
        try:
            my_session = Session.query.filter_by(key=uuid.UUID(str(session_key))).one_or_none()
        except (ValueError, AttributeError):
            my_session = None
        if not my_session:
            session_key = None

    if not session_key:
        my_session = Session()
        db.session.add(my_session)
        db.session.commit()

    session['key'] = str(my_session.key)
    return my_session


def rotateSession() -> Session:
    """Issue a fresh session key, preserving the current session data.

    Called after a successful login to mitigate session fixation: any session
    identifier known before authentication is discarded.
    """
    my_session = _mySession()
    new_session = Session(data=my_session.data)
    db.session.add(new_session)
    db.session.delete(my_session)
    db.session.commit()
    session['key'] = str(new_session.key)
    return new_session


def getSessionData(key, default=None):
    my_session = _mySession()
    all_data = json.loads(my_session.data)
    data = all_data.get(key, None)
    return data or default


def setSessionData(key, value):
    my_session = _mySession()
    all_data = json.loads(my_session.data)
    if value is None:
        new_data = {}
        for data_key in all_data.keys():
            if data_key != key:
                new_data[data_key] = all_data[data_key]
        all_data = new_data
    else:
        all_data[key] = value
    my_session.data = json.dumps(all_data)
    db.session.add(my_session)
    db.session.commit()


def deleteSessionData(key):
    setSessionData(key, None)
