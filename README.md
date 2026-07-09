# Tiny OIDC

This toy OIDC server is designed to provide a minimal OIDC server to develop and unit test against.

## Supported Features

* Authorization Code flow with `openid`, `email`, `profile`, `groups`, and `offline_access` scopes
* PKCE (RFC 7636) with S256 and plain challenge methods
* Nonce validation for ID tokens
* `prompt` (`none`, `login`, `consent`, `select_account`) and `max_age`, with a
  very basic all-or-nothing consent screen that is never remembered
* Refresh token support (via `offline_access` scope)
* OIDC Discovery (`.well-known/openid-configuration`)
* JWKS endpoint for token verification
* End-session endpoint for single sign-out

## Testing

Two suites, both run by `uv run pytest`:

* `tests/` — in-process conformance tests against Flask's test client. Fast.
* `tests/e2e/` — the full browser-driven workflow. These start the provider and
  a real Relying Party (`tests/e2e/rp_app.py`) as subprocesses on ephemeral
  ports, then drive a browser through it with Playwright: the RP redirects to
  the provider, Playwright picks an authentication profile from the login page,
  the provider redirects back with a code, and the RP redeems it and uses the
  resulting tokens. They cover both client authentication methods
  (`client_secret_basic`, `client_secret_post`) against every PKCE mode
  (`S256`, `plain`, an implicit-`plain` challenge with no method, and none),
  plus the `refresh_token` grant.

The end-to-end suite needs a browser once:

```sh
uv run playwright install chromium
```

Run one suite at a time with the `e2e` marker:

```sh
uv run pytest -m "not e2e"   # in-process only
uv run pytest -m e2e         # browser-driven only
```

Both suites build a throwaway SQLite database per run, because `db.create_all()`
does not alter existing tables — a stale `app.db` will be missing columns.

It is very loosely based on details provided by:

* https://spapas.github.io/2023/11/29/openid-connect-tutorial/
* https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660

It was tested by running against https://openidconnect.net/ and https://github.com/BeryJu/oidc-test-client at various stages of development