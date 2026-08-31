from sqlalchemy import inspect, text

from app.extensions import db


def ensure_email_verified_column():
    """Add `user.email_verified` to a database created before it existed.

    `db.create_all()` creates missing tables but never alters existing ones,
    and there is no migration framework here, so an app.db carried over from
    an earlier version would fail every user query with "no such column".
    Existing rows are treated as verified, matching the column default and the
    provisioning model described on the column itself.

    Idempotent, and a no-op on a fresh database where create_all already made
    the column.
    """
    inspector = inspect(db.engine)
    if 'user' not in inspector.get_table_names():
        return False
    columns = {column['name'] for column in inspector.get_columns('user')}
    if 'email_verified' in columns:
        return False

    db.session.execute(text(
        "ALTER TABLE user ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 1"
    ))
    db.session.commit()
    return True


def initUser():
    all_users = User.query.all()
    if len(all_users) == 0:
        admin = User(
            username = 'admin',
            password = 'Hunter2!',
            email = 'admin@example.org',
            first_name = 'Joe',
            last_name = 'Administrator',
            display_name = "TheBOFH",
            groups = 'admins,Users,service_admins'
        )
        it = User(
            username = 'it',
            password = 'Hunter2!',
            email = 'it@example.org',
            first_name = 'Maurice',
            last_name = 'Moss',
            display_name = 'Moss',
            groups = 'Users,IT,service_admins'
        )
        accounts = User(
            username = 'accounts',
            password = 'Hunter2!',
            email = 'finance@example.org',
            first_name = 'Bob',
            last_name = 'Tennor',
            display_name = 'Dollar',
            groups = 'Users,Accounts,service_users'
        )
        auditor = User(
            username = 'auditor',
            password = 'Hunter2!',
            email = 'auditor@example.org',
            first_name = 'Alice',
            last_name = 'Audit',
            display_name = 'Auditor',
            groups = 'Users,auditors'
        )
        sysadmin = User(
            username = 'sysadmin',
            password = 'Hunter2!',
            email = 'sysadmin@example.org',
            first_name = 'Sam',
            last_name = 'System',
            display_name = 'SysAdmin',
            groups = 'Users,system-admins'
        )
        reception = User(
            username = 'reception',
            password = 'Hunter2!',
            email = 'rachel@example.org',
            first_name = 'Rachel',
            last_name = 'Reception',
            display_name = 'Building 42 Reception',
            groups = 'Users,front_door'
        )
        contractor = User(
            username = 'contractor',
            password = 'Hunter2!',
            email = 'chris@contracting.example.com',
            first_name = 'Chris',
            last_name = 'Contractor',
            display_name = 'Christian "Spec Work" Contractor',
            groups = 'Users,Contractors'
        )
        db.session.add(admin)
        db.session.add(it)
        db.session.add(accounts)
        db.session.add(auditor)
        db.session.add(sysadmin)
        db.session.add(reception)
        db.session.add(contractor)
        db.session.commit()

class User(db.Model):
    username = db.Column(db.String(255), primary_key=True)
    password = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    groups = db.Column(db.String(255))
    # OIDC Core §5.1: whether this provider has verified that the address
    # belongs to the end user. Defaults to True because accounts here are
    # provisioned directly rather than self-registered, so the address is
    # exactly as trustworthy as the account itself — but it is a column
    # rather than a hardcoded constant so the unverified case can actually be
    # exercised. Relying parties that use email as an identity rather than a
    # display value are entitled to reject a claim without this, and the
    # stricter ones do.
    email_verified = db.Column(db.Boolean, nullable=False, default=True,
                               server_default='1')

    def trace(self):
        data = {
            'username': self.username,
            'password': self.password,
            'email': self.email,
            'email_verified': self.email_verified,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'display_name': self.display_name,
            'groups': self.groups
        }
        return f'User: {data}'
    
    def oidc_claim(self, target_scopes):
        scopes = (target_scopes or "").split(" ")
        # sub is REQUIRED in every ID token and UserInfo response, regardless of
        # which scopes were granted (OIDC Core §2 and §5.3.2).
        data = {"sub": self.username}
        if 'profile' in scopes:
            data["name"] = self.display_name
            data["given_name"] = self.first_name
            data["family_name"] = self.last_name
            data["preferred_username"] = self.email
        if 'email' in scopes:
            data["email"] = self.email
            # OIDC Core §5.4 scopes both claims to `email`. Coerced to a real
            # bool: a relying party doing the strict `claim is True` check —
            # the one worth doing — fails on a string or a SQLite 1.
            data["email_verified"] = bool(self.email_verified)
        if 'groups' in scopes:
            data["groups"] = self.groups
        return data

    def __repr__(self):
        return f'<User {self.username}>'
