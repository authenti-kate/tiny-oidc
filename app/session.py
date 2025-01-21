from flask import session
from app.extensions import db
from app.models.session import Session
from datetime import datetime, timezone, timedelta

import json


def _mySession() -> Session:
    session_key = session['key'] if 'key' in session else None

    if session_key:
        my_session = None
        sessions = Session.query.all()
        for a_session in sessions:
            a_session_key = str(a_session.key)
            if a_session_key == str(session_key):
                my_session = a_session
        if not my_session:
            session_key = None

    if not session_key:
        my_session = Session()
        db.session.add(my_session)
        db.session.commit()

    session['key'] = str(my_session.key)
    return my_session


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
