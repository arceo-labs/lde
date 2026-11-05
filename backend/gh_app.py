"""GitHub App authentication: app JWT -> per-org installation access tokens.

LDE can hold several GitHub Apps, typically one private app per org it scans
(each app owned by, and installed on, its own org), and optionally an
enterprise-owned or public app installed on many orgs. For each org this module
picks the app owned by that org first, then any other configured app that is
installed there, and:

1. signs a short-lived app JWT (RS256) with the app's private key,
2. looks up the app's installation on the org (``GET /orgs/{org}/installation``),
3. mints an installation access token scoped down to ``contents:read`` and
   ``metadata:read`` (``POST /app/installations/{id}/access_tokens``),
4. caches that token in memory until five minutes before it expires.

Apps come from (see ``app_configs``):

- ``github_apps`` in ``.settings.json``: ``[{"owner", "app_id", "private_key_path"}]``;
- ``github_apps_secret``, overlaid from the ``lde/github-app`` secret in AWS:
  ``[{"owner", "app_id", "private_key"}]``;
- the single-app keys ``github_app_id`` with ``github_app_private_key`` or
  ``github_app_private_key_path`` (owner unknown: tried on every org).

Private keys are never accepted over the HTTP API, never returned, never logged.
Only ``gh_app_setup`` writes them, server-side, when the user creates an app.

RSA signing uses the audited ``cryptography`` package; this module only
assembles the JWT's base64url/JSON envelope around that signature.

Every request goes to the hard-coded https://api.github.com with an explicit
timeout, and redirects are refused so a bearer credential cannot follow one.
"""

import base64
import datetime
import hashlib
import json
import os
import re
import stat
import threading
import time
import urllib.error
import urllib.request

from . import log as log_mod

logger = log_mod.get('gh_app')

_API_BASE = 'https://api.github.com'
_API_VERSION = '2022-11-28'
_TIMEOUT = 15
_MAX_RESPONSE = 1024 * 1024  # GitHub's app/installation responses are a few KB
_MAX_KEY_FILE = 16 * 1024    # a 4096-bit RSA PEM is ~3.2 KB

# GitHub rejects an app JWT whose exp is more than 10 minutes out. Backdate
# iat by 60s to tolerate clock drift between this host and GitHub.
_JWT_BACKDATE = 60
_JWT_LIFETIME = 540

# Refresh an installation token this long before GitHub's expires_at (1 hour).
_TOKEN_REFRESH_MARGIN = 300
# How long a found installation id is reused before it is looked up again.
_INSTALL_TTL = 3600
# How long "not installed on this org" is remembered, so a fresh install is
# picked up within minutes without a lookup on every request.
_NOT_INSTALLED_TTL = 300

# Installation tokens never carry more than this, whatever the app is granted.
TOKEN_PERMISSIONS = {'contents': 'read', 'metadata': 'read'}

_APP_ID_RE = re.compile(r'^[0-9]{1,20}$')
_OWNER_RE = re.compile(r'^[A-Za-z0-9._-]+$')


class AppConfigError(RuntimeError):
    """The GitHub App is configured but unusable. The message is safe to show users."""


class AppAuthError(RuntimeError):
    """A GitHub App API call failed. *status* is the HTTP status when there was one."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


# ---- configuration --------------------------------------------------------

def _read_key_file(path):
    """Return the bytes of the PEM file at *path*, enforcing owner-only access.

    The path is canonicalized with realpath() before any check. The file is
    opened once and checked through its descriptor, so the checks and the read
    see the same file.
    """
    if not isinstance(path, str) or not path.strip():
        raise AppConfigError('github_app_private_key_path is empty.')
    real = os.path.realpath(os.path.expanduser(path.strip()))
    try:
        fd = os.open(real, os.O_RDONLY)
    except OSError:
        raise AppConfigError('The GitHub App private key file named by '
                             'github_app_private_key_path cannot be opened.') from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AppConfigError('github_app_private_key_path must name a regular file.')
        if st.st_mode & 0o077:
            raise AppConfigError('The GitHub App private key file is readable by other users. '
                                 'Run chmod 600 on it.')
        if st.st_size > _MAX_KEY_FILE:
            raise AppConfigError('The GitHub App private key file is too large to be a PEM key.')
        with os.fdopen(fd, 'rb') as f:
            fd = None
            return f.read(_MAX_KEY_FILE + 1)
    finally:
        if fd is not None:
            os.close(fd)


def app_config(cfg):
    """Return ``{'app_id', 'pem', 'source'}`` from settings *cfg*, or None.

    None means no GitHub App is configured at all (PAT-only setups). A partial
    or malformed configuration raises AppConfigError: it never silently falls
    back to PATs, so a broken app setup is noticed.

    A key from Secrets Manager (``github_app_private_key``) wins over a local
    key file (``github_app_private_key_path``).
    """
    app_id = cfg.get('github_app_id')
    app_id = str(app_id).strip() if app_id not in (None, '') else ''
    key_inline = cfg.get('github_app_private_key')
    key_inline = key_inline if isinstance(key_inline, str) and key_inline.strip() else ''
    key_path = cfg.get('github_app_private_key_path')
    key_path = key_path if isinstance(key_path, str) and key_path.strip() else ''

    if not app_id and not key_inline and not key_path:
        return None
    if not app_id:
        raise AppConfigError('A GitHub App private key is configured but github_app_id is not.')
    if not _APP_ID_RE.match(app_id):
        raise AppConfigError('github_app_id must be the numeric App ID shown on the app\'s '
                             'GitHub settings page.')
    if key_inline:
        return {'app_id': app_id, 'pem': key_inline.encode('utf-8'), 'source': 'secrets_manager'}
    if key_path:
        return {'app_id': app_id, 'pem': _read_key_file(key_path), 'source': 'file'}
    raise AppConfigError('github_app_id is set but no private key is configured. Set '
                         'github_app_private_key_path in .settings.json, or write the '
                         'lde/github-app secret in AWS.')


_MAX_APPS = 50


def _list_entry(raw, i, key_field):
    """Validate one github_apps / github_apps_secret entry; return (owner, app_id, value)."""
    if not isinstance(raw, dict):
        raise AppConfigError(f'GitHub App entry {i + 1} must be a JSON object.')
    owner = raw.get('owner', '')
    app_id = raw.get('app_id')
    if isinstance(app_id, int) and not isinstance(app_id, bool):
        app_id = str(app_id)
    value = raw.get(key_field)
    if not isinstance(owner, str) or (owner and not _OWNER_RE.match(owner)):
        raise AppConfigError(f'GitHub App entry {i + 1}: owner must be a GitHub org, user or '
                             'enterprise name.')
    if not isinstance(app_id, str) or not _APP_ID_RE.match(app_id.strip()):
        raise AppConfigError(f'GitHub App entry {i + 1}: app_id must be the numeric App ID.')
    if not isinstance(value, str) or not value.strip():
        raise AppConfigError(f'GitHub App entry {i + 1}: {key_field} is missing.')
    return owner.lower(), app_id.strip(), value


def app_configs(cfg):
    """Return every configured app as ``[{'app_id', 'pem', 'source', 'owner'}]`` ([] for none).

    *owner* is the lower-cased account that owns the app, or '' when unknown.
    Any malformed entry, a repeated App ID or two apps for one owner raises
    AppConfigError: a broken app setup is never silently skipped.
    """
    apps = []
    single = app_config(cfg)
    if single is not None:
        apps.append(dict(single, owner=''))
    for field, key_field, source in (('github_apps', 'private_key_path', 'file'),
                                     ('github_apps_secret', 'private_key', 'secrets_manager')):
        entries = cfg.get(field) or []
        if not isinstance(entries, list):
            raise AppConfigError(f'{field} must be a list of GitHub Apps.')
        for i, raw in enumerate(entries):
            owner, app_id, value = _list_entry(raw, i, key_field)
            pem = _read_key_file(value) if source == 'file' else value.encode('utf-8')
            apps.append({'app_id': app_id, 'pem': pem, 'source': source, 'owner': owner})
    if len(apps) > _MAX_APPS:
        raise AppConfigError(f'At most {_MAX_APPS} GitHub Apps can be configured.')
    ids = [a['app_id'] for a in apps]
    if len(set(ids)) != len(ids):
        raise AppConfigError('The same GitHub App ID is configured more than once.')
    owners = [a['owner'] for a in apps if a['owner']]
    if len(set(owners)) != len(owners):
        raise AppConfigError('More than one GitHub App is configured for the same owner.')
    return apps


def app_for_owner(apps, owner):
    """The configured app owned by *owner*, or None."""
    owner = (owner or '').lower()
    return next((a for a in apps if owner and a['owner'] == owner), None)


# ---- JWT ------------------------------------------------------------------

_key_cache = {}  # sha256(pem) -> loaded private key object
_key_lock = threading.Lock()


def _load_private_key(pem):
    """Return the RSA private key object for PEM bytes *pem*; AppConfigError when unusable."""
    digest = hashlib.sha256(pem).digest()
    with _key_lock:
        key = _key_cache.get(digest)
        if key is not None:
            return key
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            raise AppConfigError('GitHub App auth needs the cryptography package. '
                                 'Run pip install -r requirements.txt.') from None
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except Exception:
            # Never chain or echo the parser error: it could quote key bytes.
            raise AppConfigError('The GitHub App private key could not be parsed. It must be '
                                 'the unencrypted PEM file GitHub generated for the app.') from None
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise AppConfigError('The GitHub App private key must be an RSA key of at least '
                                 '2048 bits.')
        if len(_key_cache) >= _MAX_APPS:
            _key_cache.clear()  # bounded: drop everything rather than grow
        _key_cache[digest] = key
        return key


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def make_jwt(app_id, pem, now=None):
    """Return a signed RS256 app JWT (str) for *app_id*, valid for nine minutes."""
    # Load first: it turns a missing cryptography install into AppConfigError.
    key = _load_private_key(pem)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(time.time() if now is None else now)
    header = {'alg': 'RS256', 'typ': 'JWT'}
    claims = {'iat': now - _JWT_BACKDATE, 'exp': now + _JWT_LIFETIME, 'iss': int(app_id)}
    signing_input = (_b64url(json.dumps(header, separators=(',', ':')).encode())
                     + b'.' + _b64url(json.dumps(claims, separators=(',', ':')).encode()))
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b'.' + _b64url(signature)).decode('ascii')


# ---- HTTP -----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would otherwise resend the Authorization header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _call(method, path, bearer, body=None):
    """Call api.github.com *path* with *bearer*; return the parsed JSON body.

    *bearer* None sends no Authorization header (the manifest conversion is
    unauthenticated: the one-time code is the credential).

    Raises AppAuthError. The message names only the method, path and status,
    never a credential or the response body.
    """
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': _API_VERSION,
        'User-Agent': 'LibraryDependencyExplorer/1.0',
    }
    if bearer is not None:
        headers['Authorization'] = f'Bearer {bearer}'
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(f'{_API_BASE}{path}', data=data, headers=headers, method=method)
    try:
        with _opener.open(req, timeout=_TIMEOUT) as resp:
            raw = resp.read(_MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise AppAuthError(f'GitHub API {exc.code} for {method} {path}', status=exc.code) from None
    except urllib.error.URLError as exc:
        raise AppAuthError(f'GitHub API network error for {method} {path}: {exc.reason}') from None
    except OSError as exc:
        raise AppAuthError(f'GitHub API network error for {method} {path}: '
                           f'{type(exc).__name__}') from None
    if len(raw) > _MAX_RESPONSE:
        raise AppAuthError(f'GitHub API response for {method} {path} is too large')
    try:
        return json.loads(raw)
    except ValueError:
        raise AppAuthError(f'GitHub API returned malformed JSON for {method} {path}') from None


# ---- installations and tokens ----------------------------------------------

_installs = {}   # (app id, owner lower) -> (installation id or None, monotonic expiry)
_tokens = {}     # (app id, installation id) -> (token, epoch expiry)
_guard = threading.Lock()
_owner_locks = {}


def _owner_lock(owner):
    with _guard:
        lock = _owner_locks.get(owner)
        if lock is None:
            lock = _owner_locks[owner] = threading.Lock()
        return lock


def _lookup_installation(cfg_app, owner):
    """Return the app's installation id on *owner*, or None when not installed."""
    jwt = make_jwt(cfg_app['app_id'], cfg_app['pem'])
    for kind in ('orgs', 'users'):
        try:
            doc = _call('GET', f'/{kind}/{owner}/installation', jwt)
        except AppAuthError as exc:
            if exc.status == 404:
                continue
            if exc.status == 401:
                raise AppAuthError('GitHub rejected the app JWT (HTTP 401). Check github_app_id '
                                   'and that the private key belongs to that app and has not '
                                   'been revoked.', status=401) from None
            raise
        inst_id = doc.get('id') if isinstance(doc, dict) else None
        if isinstance(inst_id, int) and inst_id > 0:
            return inst_id
        raise AppAuthError(f'GitHub returned no installation id for {owner}')
    return None


def _parse_expiry(value):
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt.timestamp()
    except ValueError:
        return time.time() + 1800  # conservative: refresh in half the usual hour


def _mint_token(cfg_app, inst_id):
    jwt = make_jwt(cfg_app['app_id'], cfg_app['pem'])
    try:
        doc = _call('POST', f'/app/installations/{inst_id}/access_tokens', jwt,
                    body={'permissions': TOKEN_PERMISSIONS})
    except AppAuthError as exc:
        if exc.status == 422:
            raise AppAuthError('The GitHub App does not have Contents: Read and Metadata: Read '
                               'repository permissions, or an org has not accepted them yet.',
                               status=422) from None
        raise
    token = doc.get('token') if isinstance(doc, dict) else None
    if not isinstance(token, str) or not token:
        raise AppAuthError('GitHub returned no installation token')
    return token, _parse_expiry(doc.get('expires_at'))


def installation_token(cfg_app, owner):
    """Return an installation token for *owner*, or None when the app is not installed there.

    Raises AppConfigError for a broken key and AppAuthError for API failures.
    Lookups and mints for one owner are single-flight; other owners are not
    blocked.
    """
    if not _OWNER_RE.match(owner or ''):
        raise ValueError(f'Invalid org name: {owner!r}')
    owner = owner.lower()
    app_id = cfg_app['app_id']
    ikey = (app_id, owner)
    with _owner_lock(ikey):
        now_m = time.monotonic()
        hit = _installs.get(ikey)
        if hit and now_m < hit[1]:
            inst_id = hit[0]
        else:
            inst_id = _lookup_installation(cfg_app, owner)
            ttl = _INSTALL_TTL if inst_id else _NOT_INSTALLED_TTL
            _installs[ikey] = (inst_id, now_m + ttl)
        if inst_id is None:
            return None

        tkey = (app_id, inst_id)
        cached = _tokens.get(tkey)
        if cached and time.time() < cached[1] - _TOKEN_REFRESH_MARGIN:
            return cached[0]
        try:
            token, expires = _mint_token(cfg_app, inst_id)
        except AppAuthError as exc:
            if exc.status in (401, 404):
                # The installation was removed or suspended: look it up again next time.
                _installs.pop(ikey, None)
            raise
        _tokens[tkey] = (token, expires)
        return token


def token_for(apps, owner):
    """Return ``(token, app)`` for *owner* from the first app installed there, else ``(None, None)``.

    The app owned by *owner* is tried first, then the others in config order
    (an enterprise-owned or public app can be installed on many orgs). Errors
    are raised, not skipped: a broken app fails closed.
    """
    own = app_for_owner(apps, owner)
    ordered = ([own] if own else []) + [a for a in apps if a is not own]
    for app in ordered:
        token = installation_token(app, owner)
        if token:
            return token, app
    return None, None


def invalidate(owner):
    """Drop every cached token for *owner* (for example after GitHub answers 401)."""
    owner = (owner or '').lower()
    with _guard:
        keys = [k for k in _installs if k[1] == owner]
    for ikey in keys:
        with _owner_lock(ikey):
            hit = _installs.get(ikey)
            if hit and hit[0]:
                _tokens.pop((ikey[0], hit[0]), None)


def reset_caches():
    """Forget every cached installation and token (tests, key rotation)."""
    with _guard:
        _installs.clear()
        _tokens.clear()
    with _key_lock:
        _key_cache.clear()


def app_identity(cfg_app):
    """Return ``{'slug', 'name', 'owner'}`` for the app via ``GET /app`` (app JWT)."""
    doc = _call('GET', '/app', make_jwt(cfg_app['app_id'], cfg_app['pem']))
    if not isinstance(doc, dict):
        raise AppAuthError('GitHub returned no app for GET /app')
    owner = doc.get('owner') if isinstance(doc.get('owner'), dict) else {}
    login = owner.get('login') or owner.get('slug') or ''
    return {'slug': str(doc.get('slug') or ''), 'name': str(doc.get('name') or ''),
            'owner': str(login) if _OWNER_RE.match(str(login)) else ''}
