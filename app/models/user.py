from app.extensions import db

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

    def trace(self):
        data = {
            'username': self.username,
            'password': self.password,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'display_name': self.display_name,
            'groups': self.groups
        }
        return f'User: {data}'
    
    def oidc_claim(self, target_scopes):
        data = {}
        scopes = target_scopes.split(" ")
        if 'openid' in scopes or 'profile' in scopes:
            data["sub"] = self.username
            data["name"] = self.display_name
            data["given_name"] = self.first_name
            data["family_name"] = self.last_name
            data["preferred_username"] = self.email
        if 'email' in scopes:
            data["email"] = self.email
        if 'groups' in scopes:
            data["groups"] = self.groups
        return data

    def __repr__(self):
        return f'<User {self.username}>'
