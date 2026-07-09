from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from app.extensions import db
from app.models import db_setup

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Add ProxyFix middleware to handle X-Forwarded headers from nginx ingress.
    # The number of trusted proxies is configurable (PROXY_COUNT); the issuer is
    # protected from host-header injection separately via OIDC_ISSUER /
    # TRUSTED_HOSTS (see app.urls.base_url).
    proxies = app.config.get('PROXY_COUNT', 1)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies, x_port=proxies)

    # Initialize Flask extensions here
    db.init_app(app)
    with app.app_context():
        db_setup()

    # Register blueprints here
    from app.views import bp
    app.register_blueprint(bp)

    return app