import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt, JWTError
from urllib.request import urlopen

from urllib3 import HTTPResponse

AUTH0_DOMAIN = 'dev-7vsx8b5f.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'dev'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
   header = request.headers.get('Authorization')
   if header is None:
       raise AuthError('Authorization header missing')
   split_header = header.split()
   if len(split_header) != 2 or split_header[0].lower() != 'bearer':
       raise AuthError('Malformed Authorization header')
   return split_header[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    permissions = payload.get('permissions')
    if permissions is None:
        raise AuthError('Permissions missing from payload')
    if permissions.index(permission) == -1:
        raise AuthError(f'Payload does not include the {permission} permission')
    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):

    keys = None
    with urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json') as response:
        keys = json.loads(response.read())['keys']
    for key in keys:
        try:
            claims = jwt.decode(token, algorithms=ALGORITHMS, audience=API_AUDIENCE, key=key)
            return claims
        except JWTError as e:
            pass
    raise AuthError('Invalid token')


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
