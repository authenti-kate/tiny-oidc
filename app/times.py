from datetime import timezone


def numeric_date(dt):
    """Return a JWT NumericDate — integer seconds since the epoch — for dt.

    Datetimes read back from the database are naive but represent UTC. A naive
    datetime's .timestamp() is interpreted in the server's LOCAL timezone, which
    yields the wrong epoch (and e.g. tokens that appear already expired) whenever
    the server is not on UTC. Treat naive values as UTC, and emit an integer per
    RFC 7519 §2.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())
