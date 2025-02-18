from app.views import bp
from flask import request
from app.log import debug

@bp.route('/c2s/client')
def client_endpoint():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    debug(f'GET: /c2s/client args: {data}')

    # @TODO: Write this endpoint
    return 'INCOMPLETE'