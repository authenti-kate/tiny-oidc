from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from app.extensions import db
from app.models import db_setup

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Add ProxyFix middleware to handle X-Forwarded headers from nginx ingress
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Initialize Flask extensions here
    db.init_app(app)
    with app.app_context():
        db_setup()

    # Register blueprints here
    from app.views import bp
    app.register_blueprint(bp)

    return app