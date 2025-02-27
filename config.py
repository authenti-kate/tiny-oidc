import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    FLASK_HOST = os.environ.get('FLASK_HOST', '::')
    FLASK_PORT = os.environ.get('FLASK_PORT', '8000')
    FLASK_DEBUG = bool(os.environ.get('FLASK_DEBUG', False))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'TotallyInsecureSecretKey_TotallyInsecureSecretKey!')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = bool(os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', False))
    SQLALCHEMY_ECHO = bool(os.environ.get('SQLALCHEMY_ECHO', False))
