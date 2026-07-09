import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    FLASK_HOST = os.environ.get('FLASK_HOST', '::')
    FLASK_PORT = os.environ.get('FLASK_PORT', '8000')
    FLASK_DEBUG = bool(os.environ.get('FLASK_DEBUG', False))
    # NB: this default is intentionally an obvious placeholder — set SECRET_KEY
    # in the environment for any real deployment (kept default so the toy runs
    # out of the box, consistent with its findable-credentials stance).
    SECRET_KEY = os.environ.get('SECRET_KEY', 'TotallyInsecureSecretKey_TotallyInsecureSecretKey!')
    # Session cookie hardening. SECURE defaults off so plain-HTTP local testing
    # works; enable it (and it is required) when served over HTTPS.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes')
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

    # Authorization code lifetime, in seconds. RFC 6749 §4.1.2 requires codes to
    # be short-lived and RECOMMENDS a maximum lifetime of 10 minutes.
    AUTHORIZATION_CODE_LIFETIME = int(os.environ.get('AUTHORIZATION_CODE_LIFETIME', '600'))
    # How long a signed-in browser session may satisfy a new authorization
    # request without re-authenticating (SSO). Deliberately separate from the
    # code lifetime above: a code must expire quickly, whereas an SSO session
    # exists precisely so that it outlives a single authorization request.
    SSO_SESSION_LIFETIME = int(os.environ.get('SSO_SESSION_LIFETIME', '900'))

    # Require PKCE (a code_challenge) on every authorization request. Defaults
    # off so simple test flows still work; RFC 9700 §2.1.1 recommends enabling
    # it (with S256) in production. Only S256 and plain are accepted regardless;
    # S256 is preferred.
    PKCE_REQUIRED = os.environ.get('PKCE_REQUIRED', 'false').lower() in ('1', 'true', 'yes')
