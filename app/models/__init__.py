from app.extensions import db

def db_setup():
    from app.models.application import Application, initApplication
    from app.models.authentication import Authentication
    from app.models.authorization import Authorization
    from app.models.log import Log
    from app.models.refreshtoken import RefreshToken
    from app.models.session import Session
    from app.models.user import User, initUser
    db.create_all()
    initUser()
    initApplication()