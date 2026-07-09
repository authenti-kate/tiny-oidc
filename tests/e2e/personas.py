"""The users seeded by app/models/user.py:initUser, and the claims they carry.

Kept in its own module rather than in conftest.py: `tests/conftest.py` is
already importable as `conftest` (pyproject sets pythonpath = [".", "tests"]),
so a `from conftest import ...` inside tests/e2e/ would be ambiguous.
"""

PERSONAS = {
    "admin": {"name": "TheBOFH", "groups": "admins,Users,service_admins"},
    "it": {"name": "Moss", "groups": "Users,IT,service_admins"},
    "accounts": {"name": "Dollar", "groups": "Users,Accounts,service_users"},
    "auditor": {"name": "Auditor", "groups": "Users,auditors"},
    "sysadmin": {"name": "SysAdmin", "groups": "Users,system-admins"},
    "reception": {"name": "Building 42 Reception", "groups": "Users,front_door"},
    "contractor": {
        "name": 'Christian "Spec Work" Contractor',
        "groups": "Users,Contractors",
    },
}
