import requests
from datetime import datetime
import hashlib
import hmac
import base64
import configparser
import sys


def main():

    args = sys.argv

    config = configparser.ConfigParser()

    if len(args) > 1:
        config.read(args[1])
    else:
        config.read('attainia_api_test.ini')

    # These variables should be provided by Attainia
    api_key = config['Connection']['api_key']
    secret_key = config['Connection']['secret_key']
    host = config['Connection']['host']
    uri = config['Connection']['uri']

    http_verb = 'GET'
    content_type = 'application/json'
    timestamp = gen_iso_timestamp()

    auth_header_value = gen_auth_string(api_key, secret_key, uri, http_verb, content_type, timestamp)

    full_url = f'{host}{uri}'
    headers = {'att-api-timestamp': timestamp,
               'authorization': auth_header_value, 
               'Content-Type': content_type, 
               'Accept': content_type}

    print(f'Sending request to {full_url} Awaiting reply.')
    r = requests.get(full_url, headers=headers)

    print(r.content)
    print(f'Response status code:{r.status_code}')


def gen_auth_string(api_key, secret_key, uri, http_verb, content_type, timestamp):

    message = f'{http_verb}\n{content_type}\n{uri}\n{timestamp}'

    print(f'Canonical request pre convert: \n{message}\n')

    canonical_request = bytes(message, 'ASCII')
    secret_bytes = bytes(secret_key, 'ASCII')
    digest = hmac.new(secret_bytes, msg=canonical_request, digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode()

    auth_header_value = f'AttAPI {api_key}:{signature}'
    print(f'Auth header: \n{auth_header_value}\n')

    return auth_header_value


def gen_iso_timestamp():
    """generate a timestamp in this format 2018-12-31T23:55:55+00:00"""

    timestamp = datetime.utcnow().replace(microsecond=0).isoformat()
    timestamp = f'{timestamp}+00:00'

    return timestamp


if __name__ == "__main__":
    main()
