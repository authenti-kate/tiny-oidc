from flask import Blueprint

bp = Blueprint('main', __name__)

from . import index
from . import user_auth
from . import client_to_server
from . import server_to_server