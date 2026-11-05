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
object of the form ``{"<username>": "<sha256_of_password>", ...}``,
``lde/github-app``, a JSON object holding the GitHub App's ID and PEM
private key, and ``lde/github-pat``, a JSON object mapping each GitHub org to
its (deprecated) PAT.

    lde/github-app       → settings keys ``github_app_id`` and ``github_app_private_key``
                            (JSON object ``{"app_id": "<id>", "private_key": "-----BEGIN…"}``)
    lde/github-pat       → settings key ``github_pats`` (JSON object ``{"<org>": "<token>"}``)
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
    'lde/github-app': '_github_app',  # expands to github_app_id + github_app_private_key
    'lde/github-pat': 'github_pats',
    'lde/dtrack-api-key': 'dtrack_api_key',
    'lde/gemini-api-key': 'gemini_api_key',
    'lde/basic-auth': 'basic_auth_credentials',
}

_TIMEOUT = 5
# Terraform creates each secret shell with this value; it means "not set yet".
_PLACEHOLDER = 'REPLACE_ME'
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
    """Fetch a single secret value from AWS Secrets Manager (``GetSecretValue``)."""
    result = _sm_request('GetSecretValue', {'SecretId': secret_name})
    # GetSecretValue returns SecretString for text secrets
    return result.get('SecretString', '')


def get_secret_fresh(secret_name):
    """Return *secret_name*'s current value straight from AWS (no cache), or None if absent.

    For read-modify-write of a secret. Raises RuntimeError on failure.
    """
    if secret_name not in _SECRET_MAP:
        raise ValueError(f'Not an LDE secret: {secret_name}')
    try:
        return _sign_and_fetch(secret_name)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return None
        raise RuntimeError(f'AWS Secrets Manager refused to read {secret_name} '
                           f'(HTTP {exc.code}).') from None
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f'Could not read {secret_name} from AWS Secrets Manager: '
                           f'{type(exc).__name__}') from None


def put_secret(secret_name, value):
    """Write *value* as the new current version of *secret_name* (``PutSecretValue``).

    Only secrets in _SECRET_MAP can be written, and the cached copy is dropped
    so the next load_settings() reads the new value. The value is never logged.
    Raises RuntimeError on any failure, with no AWS response body in the message.
    """
    if secret_name not in _SECRET_MAP:
        raise ValueError(f'Not an LDE secret: {secret_name}')
    try:
        _sm_request('PutSecretValue', {'SecretId': secret_name, 'SecretString': value})
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RuntimeError(f'AWS Secrets Manager refused the write to {secret_name} '
                           f'(HTTP {exc.code}). The task role needs '
                           f'secretsmanager:PutSecretValue on it.') from None
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f'Could not write {secret_name} to AWS Secrets Manager: '
                           f'{type(exc).__name__}') from None
    with _cache_locks[secret_name]:
        _cache.pop(secret_name, None)


def _sm_request(target, body):
    """Send one SigV4-signed Secrets Manager API call (*target*, JSON *body*); return the JSON reply.

    Implements a minimal SigV4 signed POST via the Secrets Manager HTTPS endpoint.
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

    payload = json.dumps(body)
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
        'X-Amz-Target': f'secretsmanager.{target}',
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
        return json.loads(resp.read())


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


def _parse_pats(raw):
    """Parse the lde/github-pat secret into {org: token}; {} when malformed.

    The value is never logged, only the fact that it was rejected.
    """
    if raw.strip() == _PLACEHOLDER:
        return {}  # PATs are optional now that the GitHub App is the primary credential
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None
    if not isinstance(doc, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in doc.items()):
        logger.warning('secret lde/github-pat must be a JSON object of {org: token} '
                       '(a plain-string token is the old format); ignoring it')
        return {}
    return doc


def _app_entry_ok(e):
    app_id = e.get('app_id') if isinstance(e, dict) else None
    if isinstance(app_id, int) and not isinstance(app_id, bool):
        app_id = str(app_id)
    return (isinstance(app_id, str) and app_id.strip().isdigit()
            and isinstance(e.get('owner', ''), str)
            and isinstance(e.get('private_key'), str) and '-----BEGIN' in e['private_key'])


def _parse_app(raw):
    """Parse lde/github-app into settings keys; {} when unusable.

    Two shapes are accepted:

    - ``{"apps": [{"owner", "app_id", "private_key"}, ...]}`` -> ``github_apps_secret``
    - ``{"app_id", "private_key"}`` (one app) -> ``github_app_id`` + ``github_app_private_key``

    Only the shape is checked here; gh_app validates entries and parses keys. The
    value is never logged, only the fact that it was rejected.
    """
    if raw.strip() == _PLACEHOLDER:
        return {}
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None
    if isinstance(doc, dict) and 'apps' in doc:
        apps = doc['apps']
        if not isinstance(apps, list) or not all(_app_entry_ok(e) for e in apps):
            logger.warning('secret lde/github-app must be {"apps": [{"owner": "<org>", '
                           '"app_id": "<numeric id>", "private_key": "<PEM>"}]}; ignoring it')
            return {}
        return {'github_apps_secret': [
            {'owner': e.get('owner', ''), 'app_id': str(e['app_id']).strip(),
             'private_key': e['private_key']} for e in apps]}
    app_id = doc.get('app_id') if isinstance(doc, dict) else None
    key = doc.get('private_key') if isinstance(doc, dict) else None
    if isinstance(app_id, int) and not isinstance(app_id, bool):
        app_id = str(app_id)
    if (not isinstance(app_id, str) or not app_id.strip().isdigit()
            or not isinstance(key, str) or '-----BEGIN' not in key):
        logger.warning('secret lde/github-app must be a JSON object '
                       '{"app_id": "<numeric id>", "private_key": "<PEM>"}; ignoring it')
        return {}
    return {'github_app_id': app_id.strip(), 'github_app_private_key': key}


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
            if settings_key == '_github_app':
                if value:
                    settings_dict.update(_parse_app(value))
                continue
            if value and settings_key == 'github_pats':
                value = _parse_pats(value)
            if value:
                settings_dict[settings_key] = value
        except urllib.error.HTTPError as exc:
            logger.warning('failed to fetch secret %s: HTTP %d', secret_name, exc.code)
        except Exception as exc:
            logger.warning('failed to fetch secret %s: %s', secret_name, exc)

    return settings_dict
