import base64
from flask import jsonify, request
from app.log import debug
from app.views import bp
from app.models.application import Application
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

@bp.route('/s2s/keys')
def keys_endpoint():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    bearer = request.authorization.token if (request.authorization is not None and request.authorization.token is not None) else "None"
    debug(f'GET: /s2s/keys bearer: {bearer} args: {data}')

    all_keys = Application.query.all()
    data = []
    for key in all_keys:
        # Load the public key object
        public_key = serialization.load_pem_public_key(key.rsa_public_key)
        key_id = key.key_id

        # Ensure it's an RSA public key
        if isinstance(public_key, rsa.RSAPublicKey):
            # Get the public numbers
            public_numbers = public_key.public_numbers()
            
            # Derive the modulus (n) and exponent (e)
            modulus_n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder="big")).rstrip(b"=").decode("utf-8")
            exponent_e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder="big")).rstrip(b"=").decode("utf-8")

            data.append(
                {
                    "kid": key_id,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": modulus_n,
                    "e": exponent_e
                }
            )
    debug(f"Request: '/s2s/keys' Reply: {data}")
    return jsonify({"keys": data})
