from flask import request
import os
import requests
import logging
import pepclient
import json

iamGlobalUrl = os.environ["IAM_GLOBAL_URL"]
APIKey = os.environ["API_KEY"]

pep = pepclient.PEPClient(
    pdp_url=iamGlobalUrl,
    xacml_url=iamGlobalUrl,
    jwks_url=iamGlobalUrl)

# def get_public_key(url):
#     try:
#         jwks = requests.get(url).json()
#         public_keys = {}
#         for jwk in jwks['keys']:
#             kid = jwk['kid']
#             public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
#         return public_keys
#     except Exception as e:
#         logging.exception("Unable to retrieve public key")
#         logging.exception(e)

"""
get user's iam token from request header
"""
def get_iam_token(authHeader):
    try:
        return authHeader.replace('bearer ', '')
    except:
        logging.exception("Missing authorization header.")

"""
get service access token from api keys
"""
def get_access_token():
    try:
        response = requests.post(f'{iamGlobalUrl}/identity/token', data={
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': APIKey
        })
        json_response = response.json()
        return json_response['access_token']

    except Exception as e:
        logging.exception("Unable to retrieve access token")
        logging.exception(e)


def is_authorized(self, request):

    # public_key_url = "https://iam.test.cloud.ibm.com/identity/keys"
    # public_keys = get_public_key(public_key_url)

    try:
        iam_token = get_iam_token(request.headers.get('Authorization'))
        # kid = jwt.get_unverified_header(iam_token)['kid']
        # key = public_keys[kid]
        # payload = jwt.decode(iam_token, key=key, algorithms=['RS256'])

        subject = pep.getSubjectFromToken(iam_token)
        access_token = get_access_token()

        # Todo: replace resource data
        params = {
            'subject': subject.get('subject'),
            'action': 'vantaui.dashboard.view',
            'resource': {
                'crn': 'crn:...',
                'attributes': {
                    'serviceName': '...'
                }
            },
            'environment': {}
        }

        result = pep.is_authz2(params=params, access_token=access_token)

        return result.get('allowed')

    except Exception as e:
        logging.exception(e)
        return None

