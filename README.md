# Tiny OIDC

This toy OIDC server is designed to provide a minimal OIDC server to develop and unit test against.

## Supported Features

* Authorization Code flow with `openid`, `email`, `profile`, `groups`, and `offline` scopes
* PKCE (RFC 7636) with S256 and plain challenge methods
* Nonce validation for ID tokens
* Refresh token support (via `offline_access` scope)
* OIDC Discovery (`.well-known/openid-configuration`)
* JWKS endpoint for token verification
* End-session endpoint for single sign-out

It is very loosely based on details provided by:

* https://spapas.github.io/2023/11/29/openid-connect-tutorial/
* https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660

It was tested by running against https://openidconnect.net/ and https://github.com/BeryJu/oidc-test-client at various stages of development