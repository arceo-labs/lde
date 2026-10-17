"""AWS Secrets Manager overlay for LDE settings.

Activated when the environment variable ``LDE_SECRETS_SOURCE=aws`` is set.
When active, each secret listed in ``_SECRET_MAP`` is fetched from Secrets
Manager by name and merged on top of the file-based settings dict.

When ``LDE_SECRETS_SOURCE`` is absent or set to any other value the overlay
is a complete no-op — local `.settings.json` continues to be used as before.

Secrets Manager access uses the ECS task role credentials provided by the
EC2 instance metadata endpoint (no explicit AWS credentials needed in code).
The AWS region is read from the ``AWS_DEFAULT_REGION`` or ``AWS_REGION``
environment variable (ECS sets these automatically on Fargate).

Secret format
-------------
All secrets are plain strings except ``lde/basic-auth``, which is a JSON
object of the form ``{"<username>": "<sha256_of_password>", ...}``.

    lde/github-pat        → settings key ``github_pat``
    lde/dtrack-api-key    → settings key ``dtrack_api_key``
    lde/gemini-api-key    → settings key ``gemini_api_key``
    lde/basic-auth        → settings key ``basic_auth_credentials`` (JSON object)
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request

from . import log as log_mod

logger = log_mod.get('secrets_loader')

_ENABLED = os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws'

# Mapping of Secrets Manager secret name → settings key
_SECRET_MAP = {
    'lde/github-pat': 'github_pat',
    'lde/dtrack-api-key': 'dtrack_api_key',
    'lde/gemini-api-key': 'gemini_api_key',
    'lde/basic-auth': 'basic_auth_credentials',
}

_TIMEOUT = 5
_region = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'us-east-1')

# load_settings() runs on every request, ALB health checks included, so an
# uncached overlay made ~25k GetSecretValue calls a day. Each successful fetch
# (or 404) is reused for _CACHE_TTL seconds: a rotated secret takes effect
# within that time. Failed fetches are not cached.
_CACHE_TTL = 60
_cache = {}  # secret name -> (time.monotonic() at fetch, value, or None if absent)
# One lock per secret, not one global lock: a single slow or hung fetch (AWS
# Secrets Manager outage, up to _TIMEOUT=5s x 4 secrets) must not serialize
# every other inbound request behind it, including ALB health checks.
# Pre-created from the static _SECRET_MAP keys, so no lock-creation race.
_cache_locks = {name: threading.Lock() for name in _SECRET_MAP}


def _imds_token():
    """Retrieve an IMDSv2 session token from the EC2 instance metadata service."""
    req = urllib.request.Request(
        'http://169.254.169.254/latest/api/token',
        headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
        method='PUT',
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read().decode()


def _get_aws_credentials():
    """Retrieve temporary credentials from the ECS task credential endpoint.

    ECS Fargate sets the ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` environment
    variable; we read credentials from there.  Falls back to the EC2 IMDS role
    endpoint for local EC2 testing.
    """
    rel_uri = os.environ.get('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')
    if rel_uri:
        url = f'http://169.254.170.2{rel_uri}'
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())

    # Fallback: EC2 IMDS (useful when running on EC2, not Fargate)
    imds_token = _imds_token()
    role_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    req = urllib.request.Request(
        role_url, headers={'X-aws-ec2-metadata-token': imds_token}
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        role_name = resp.read().decode().strip().splitlines()[0]

    creds_url = f'{role_url}{role_name}'
    req = urllib.request.Request(
        creds_url, headers={'X-aws-ec2-metadata-token': imds_token}
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read())


def _sign_and_fetch(secret_name):
    """Fetch a single secret value from AWS Secrets Manager using SigV4.

    Implements a minimal SigV4 signed GET request via the Secrets Manager
    HTTPS endpoint.  Uses the ``GetSecretValue`` action.
    """
    import base64
    import datetime
    import hashlib
    import hmac

    try:
        creds = _get_aws_credentials()
    except Exception as exc:
        raise RuntimeError(f'Cannot retrieve AWS credentials: {exc}') from exc

    access_key = creds.get('AccessKeyId') or creds.get('access_key_id', '')
    secret_key = creds.get('SecretAccessKey') or creds.get('secret_access_key', '')
    session_token = creds.get('Token') or creds.get('security_token', '')

    if not access_key or not secret_key:
        raise RuntimeError('AWS credentials missing AccessKeyId or SecretAccessKey')

    service = 'secretsmanager'
    host = f'{service}.{_region}.amazonaws.com'
    endpoint = f'https://{host}/'

    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')

    payload = json.dumps({'SecretId': secret_name})
    payload_bytes = payload.encode('utf-8')
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    signed_headers_list = ['content-type', 'host', 'x-amz-date', 'x-amz-target']
    if session_token:
        signed_headers_list.append('x-amz-security-token')
    signed_headers_list.sort()
    signed_headers = ';'.join(signed_headers_list)

    headers_dict = {
        'Content-Type': 'application/x-amz-json-1.1',
        'Host': host,
        'X-Amz-Date': amz_date,
        'X-Amz-Target': 'secretsmanager.GetSecretValue',
    }
    if session_token:
        headers_dict['X-Amz-Security-Token'] = session_token

    canonical_headers = ''.join(
        f'{k.lower()}:{v}\n'
        for k, v in sorted(headers_dict.items(), key=lambda x: x[0].lower())
    )

    canonical_request = '\n'.join([
        'POST',
        '/',
        '',
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    credential_scope = f'{date_stamp}/{_region}/{service}/aws4_request'
    string_to_sign = '\n'.join([
        'AWS4-HMAC-SHA256',
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _hmac(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    signing_key = _hmac(
        _hmac(
            _hmac(
                _hmac(f'AWS4{secret_key}'.encode('utf-8'), date_stamp),
                _region,
            ),
            service,
        ),
        'aws4_request',
    )
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    auth_header = (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )
    headers_dict['Authorization'] = auth_header
    headers_dict['Content-Length'] = str(len(payload_bytes))

    req = urllib.request.Request(endpoint, data=payload_bytes, headers=headers_dict, method='POST')
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        result = json.loads(resp.read())

    # GetSecretValue returns SecretString for text secrets
    return result.get('SecretString', '')


def _cached_fetch(secret_name):
    """Return the secret's value, or None when it does not exist.

    Raises on any other failure, which is not cached. Fetches of the same
    secret are single-flight (serialized through that secret's own lock,
    with a re-check after acquiring it in case another thread already
    refreshed the cache); fetches of a *different* secret are not blocked
    by it.
    """
    now = time.monotonic()
    hit = _cache.get(secret_name)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    with _cache_locks[secret_name]:
        now = time.monotonic()
        hit = _cache.get(secret_name)
        if hit and now - hit[0] < _CACHE_TTL:
            return hit[1]
        try:
            value = _sign_and_fetch(secret_name)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            logger.debug('secret %s not found in Secrets Manager, skipping', secret_name)
            value = None
        _cache[secret_name] = (now, value)
        return value


def overlay(settings_dict):
    """Overlay AWS Secrets Manager values onto *settings_dict* in place.

    If ``LDE_SECRETS_SOURCE`` is not ``aws``, returns *settings_dict* unchanged.
    Individual secret fetch failures are logged and skipped so a single
    missing/inaccessible secret does not prevent the server from starting.
    """
    if not _ENABLED:
        return settings_dict

    for secret_name, settings_key in _SECRET_MAP.items():
        try:
            value = _cached_fetch(secret_name)
            if value:
                settings_dict[settings_key] = value
        except urllib.error.HTTPError as exc:
            logger.warning('failed to fetch secret %s: HTTP %d', secret_name, exc.code)
        except Exception as exc:
            logger.warning('failed to fetch secret %s: %s', secret_name, exc)

    return settings_dict
