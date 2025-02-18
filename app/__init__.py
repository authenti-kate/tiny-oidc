from flask import Flask

from config import Config
from app.extensions import db
from app.models import db_setup

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    with app.app_context():
        db_setup()

    # Register blueprints here
    from app.views import bp
    app.register_blueprint(bp)

    return app