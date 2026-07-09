"""Fixtures for the in-process spec-conformance suite.

Each test gets a fresh app backed by a throwaway file-based SQLite database so
the auto-created schema always matches the current models.

Flow helpers and constants live in tests/helpers.py — see the note there about
the two conftest modules.
"""
import tempfile
import os

import pytest

from app import create_app
from config import Config


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class TestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
        SECRET_KEY = "test-secret"

    application = create_app(TestConfig)
    yield application
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()
