from flask import current_app, request, url_for


def base_url():
    """Return the issuer / external base URL for this provider (no trailing /).

    Prefers a fixed configured issuer (OIDC_ISSUER) so issued tokens and the
    discovery document do not depend on a client-controlled Host header
    (host-header injection). When no issuer is configured, fall back to the
    request host; if a TRUSTED_HOSTS allowlist is configured and the request
    Host is not on it, use the first trusted host rather than reflecting the
    spoofed value.
    """
    issuer = current_app.config.get('OIDC_ISSUER')
    if issuer:
        return issuer.rstrip('/')

    trusted = current_app.config.get('OIDC_TRUSTED_HOSTS') or []
    if trusted and request.host not in trusted:
        return f'{request.scheme}://{trusted[0]}'

    return request.host_url.rstrip('/')


def external_url(endpoint, **values):
    """Absolute URL for a Flask endpoint, anchored at the provider base URL."""
    path = url_for(endpoint, **values)
    if path == '/':
        return base_url()
    return base_url() + path
