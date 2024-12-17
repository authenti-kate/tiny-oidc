import logging
from app.extensions import db
from app.session import _mySession
from app.models.log import Log, enumLevel

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def info(message):
    session = str(_mySession().key)
    logger.info(f'{session}: {message}')
    new_log = Log(
        level = enumLevel.info,
        session = session,
        message = message
    )
    db.session.add(new_log)
    db.session.commit()

def debug(message):
    session = str(_mySession().key)
    logger.debug(f'{session}: {message}')
    new_log = Log(
        level = enumLevel.debug,
        session = session,
        message = message
    )
    db.session.add(new_log)
    db.session.commit()

def trace(message):
    session = str(_mySession().key)
    new_log = Log(
        level = enumLevel.trace,
        session = session,
        message = message
    )
    db.session.add(new_log)
    db.session.commit()