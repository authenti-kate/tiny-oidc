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
            groups = 'Admins,Users,service_admins'
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
        db.session.add(admin)
        db.session.add(it)
        db.session.add(accounts)
        db.session.commit()

class User(db.Model):
    username = db.Column(db.String(255), primary_key=True)
    password = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    groups = db.Column(db.String(255))

    def __repr__(self):
        return f'<User {self.username}>'
