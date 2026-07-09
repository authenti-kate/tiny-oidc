"""The prompt values this provider honours.

Single source of truth for two things that must never drift apart: what
/c2s/authorize accepts, and what the discovery document advertises as
prompt_values_supported. A value advertised but not honoured is a lie to every
client that reads the metadata; a value honoured but not advertised is
unreachable for a client that checks first.

Deliberately excludes "create" (Initiating User Registration via OpenID Connect
1.0): there is no registration flow here, only a fixed set of test accounts.
An unadvertised value gets an HTTP 400 — see client_to_server.unsupported_prompt.
"""

SUPPORTED_PROMPTS = ('none', 'login', 'consent', 'select_account')
