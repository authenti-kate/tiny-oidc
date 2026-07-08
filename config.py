import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    FLASK_HOST = os.environ.get('FLASK_HOST', '::')
    FLASK_PORT = os.environ.get('FLASK_PORT', '8000')
    FLASK_DEBUG = bool(os.environ.get('FLASK_DEBUG', False))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'TotallyInsecureSecretKey_TotallyInsecureSecretKey!')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = bool(os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', False))
    SQLALCHEMY_ECHO = bool(os.environ.get('SQLALCHEMY_ECHO', False))

    # A fixed issuer / external base URL (e.g. https://oidc.example.com). When
    # set, the issuer and all published endpoint URLs are derived from this
    # rather than the request Host header, avoiding host-header injection.
    OIDC_ISSUER = os.environ.get('OIDC_ISSUER') or None
    # Optional comma-separated allowlist of Host values considered valid when
    # OIDC_ISSUER is not set and the app runs behind a reverse proxy. A request
    # whose Host is not on the list will not have that Host reflected into the
    # issuer.
    # NB: not named TRUSTED_HOSTS — that key is reserved by Flask 3.1+ for
    # Werkzeug's own Host-header validation (an empty list rejects everything).
    OIDC_TRUSTED_HOSTS = [h.strip() for h in os.environ.get('OIDC_TRUSTED_HOSTS', '').split(',') if h.strip()]
    # Number of chained reverse proxies to trust for X-Forwarded-* headers.
    PROXY_COUNT = int(os.environ.get('PROXY_COUNT', '1'))

    # Require PKCE (a code_challenge) on every authorization request. Defaults
    # off so simple test flows still work; RFC 9700 §2.1.1 recommends enabling
    # it (with S256) in production. Only S256 and plain are accepted regardless;
    # S256 is preferred.
    PKCE_REQUIRED = os.environ.get('PKCE_REQUIRED', 'false').lower() in ('1', 'true', 'yes')
