from app.log import debug
from app.views import bp
from flask import jsonify, url_for, request

def host_url_for(key):
    host_url = request.host_url.removesuffix('/')
    fragment = url_for(key).removesuffix('/')
    return host_url + fragment

@bp.route('/.well-known/openid-configuration')
def well_known():
    data = {}
    for key in request.args.keys():
        data[key] = request.args.get(key)
    bearer = request.authorization.token if (request.authorization is not None and request.authorization.token is not None) else "None"
    debug(f'GET: /.well-known/openid-configuration bearer: {bearer} args: {data}')

    reply = {
            # Required Fields
            "issuer": host_url_for('views.index'),
            'authorization_endpoint': host_url_for('views.authorization_endpoint'),
            'token_endpoint': host_url_for('views.token_endpoint'),
            "jwks_uri": host_url_for('views.keys_endpoint'),
            "response_types_supported": [
                "code",
                "id_token",
                "id_token token"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [
                "RS256"
            ],
            # Recommended Fields
            'userinfo_endpoint': host_url_for('views.userinfo_endpoint'),
            "registration_endpoint": host_url_for('views.client_endpoint'),
            "scopes_supported": [
                "openid",
                "email",
                "profile",
                "groups",
                "offline"
            ],
            "claims_supported": [
                "iss",
                "sub",
                "aud",
                "iat",
                "exp",
                "auth_time",
                "name",
                "email",
                "preferred_username",
            ## UNMAPPED DATA
            #     "ver", "jti", "amr", "idp", "nonce", "nickname", "given_name", "middle_name",
            #     "family_name", "email_verified", "profile", "zoneinfo", "locale", "address",
            #     "phone_number", "picture", "website", "gender", "birthdate", "updated_at",
            #     "at_hash", "c_hash"
            ],
            # Optional Fields
            "response_modes_supported": ["query", "fragment"],
            "grant_types_supported": [
                "authorization_code",
                "implicit"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "none"
                # "client_secret_post", "client_secret_jwt", "private_key_jwt",
            ],
            "end_session_endpoint": host_url_for('views.logout'),
            "request_parameter_supported": True,
            #   "request_object_signing_alg_values_supported": [
            #     "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
            #   ],
            # Required by oidc-test-client1
            "introspection_endpoint": host_url_for('views.introspection_endpoint')
        }
    
    debug(f"Request: '/.well-known/openid-configuration' Reply: {reply}")
    return jsonify(reply)