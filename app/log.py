import os
import logging
from app.extensions import db
from app.session import _mySession
from app.models.log import Log, enumLevel

logging.basicConfig(level=logging.DEBUG)

def info(message, session = None):
    log_level = os.environ.get('LOG_LEVEL', 'trace')
    if log_level.upper() in ['info', 'debug', 'trace']:
        session = session or "None"
        logging.info(f'{session}: {message}')
        new_log = Log(
            level = enumLevel.info,
            session = session,
            message = message
        )
        db.session.add(new_log)
        db.session.commit()

def debug(message, session = None):
    log_level = os.environ.get('LOG_LEVEL', 'trace')
    if log_level.upper() in ['debug', 'trace']:
        session = session or "None"
        logging.info(f'{session}: {message}')
        new_log = Log(
            level = enumLevel.debug,
            session = session,
            message = message
        )
        db.session.add(new_log)
        db.session.commit()

def trace(message, session = None):
    log_level = os.environ.get('LOG_LEVEL', 'trace')
    if log_level.upper() in ['trace']:
        session = session or "None"
        logging.info(f'{session}: {message}')
        new_log = Log(
            level = enumLevel.trace,
            session = session,
            message = message
        )
        db.session.add(new_log)
        db.session.commit()
