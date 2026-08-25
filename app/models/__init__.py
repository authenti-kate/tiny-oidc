from app.extensions import db

def db_setup():
    from app.models.application import Application, backfill_key_ids, initApplication
    from app.models.authentication import Authentication
    from app.models.authorization import Authorization
    from app.models.log import Log
    from app.models.refreshtoken import RefreshToken
    from app.models.session import Session
    from app.models.user import User, ensure_email_verified_column, initUser
    db.create_all()
    # create_all() adds missing tables but never alters existing ones, and
    # there is no migration framework here, so a database carried over from an
    # earlier version needs both of these. Each is idempotent and a no-op on a
    # fresh database.
    ensure_email_verified_column()
    backfill_key_ids()
    initUser()
    initApplication()