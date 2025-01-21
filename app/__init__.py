from flask import Flask

from config import Config
from app.extensions import db
from app.log import debug
from sqlalchemy import MetaData

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    with app.app_context():
        from app.models.application import Application, initApplication
        from app.models.authentication import Authentication
        from app.models.authorization import Authorization
        from app.models.log import Log
        from app.models.session import Session
        from app.models.user import User, initUser
        db.create_all()
        initUser()
        initApplication()

    # Register blueprints here
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app