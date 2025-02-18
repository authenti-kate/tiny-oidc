from flask import Blueprint

bp = Blueprint('views', __name__)

from . import core
from . import user
from . import server_to_server
from . import client_to_server