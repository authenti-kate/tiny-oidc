import hmac


def ct_equal(a, b):
    """Constant-time string comparison that tolerates None and non-ASCII.

    Used for comparing secrets, passwords, authorization codes and PKCE
    verifiers so that comparison time does not leak how many leading
    characters matched.
    """
    return hmac.compare_digest((a or '').encode('utf-8'), (b or '').encode('utf-8'))
