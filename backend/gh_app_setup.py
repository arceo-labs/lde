"""One-click GitHub App creation through GitHub's app manifest flow.

Each self-hosted LDE creates its own GitHub Apps, typically one private app
per org it scans (Settings -> "Create app for <org>"):

1. ``start()`` builds a manifest (name, Contents: Read and Metadata: Read, no
   webhook, a redirect back to this LDE) and a single-use ``state`` value. The
   browser form-posts the manifest to github.com, where the user clicks Create.
2. GitHub redirects the browser to ``/api/gh-app/callback?code=…&state=…``.
   ``complete()`` checks the state, exchanges the one-time code with
   ``POST /app-manifests/{code}/conversions`` and receives the App ID and
   private key.
3. The key is stored server-side only and the app is appended to the app list:
   locally a new 0600 file under ``~/.lde`` plus an entry in ``github_apps``,
   on AWS an entry in the ``lde/github-app`` secret. It never reaches the
   browser and is never logged. The client secret and webhook secret GitHub
   also returns are discarded.

An app is only ever added, never replaced: setup is refused when the owner
(as GitHub reports it) already has an app, and when the app config is broken.
"""

import json
import os
import re
import secrets
import threading
import time

from . import gh_app, log as log_mod, secrets_loader, settings as settings_mod

logger = log_mod.get('gh_app_setup')

# GitHub's manifest codes expire after an hour; a state value lives as long.
_STATE_TTL = 3600
_MAX_PENDING = 20

_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,33}$')  # GitHub caps app names at 34
_ORG_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')
_CODE_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,99}$')

_KEY_DIR = '~/.lde'

_pending = {}  # state -> (monotonic expiry, expected owner lower or '')
_pending_lock = threading.Lock()
_complete_lock = threading.Lock()


class SetupError(RuntimeError):
    """Setup failed. *reason* is a fixed key the UI maps to text; the message is safe to show."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _aws():
    return os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws'


def _configured_apps(cfg):
    try:
        return gh_app.app_configs(cfg)
    except gh_app.AppConfigError as exc:
        raise SetupError('config', f'Fix the GitHub App configuration first: {exc}') from None


def _owner_of(app):
    """The app's owner: from config, else asked of GitHub ('' when that fails)."""
    if app['owner']:
        return app['owner']
    try:
        return gh_app.app_identity(app)['owner'].lower()
    except (gh_app.AppConfigError, gh_app.AppAuthError):
        return ''


def _ensure_no_app_for(owner, apps):
    if owner and any(_owner_of(a) == owner for a in apps):
        raise SetupError('exists', f'{owner} already has a GitHub App in LDE. Use '
                                   '"Manage on GitHub" to change it.')


def start(origin, org='', name='', cfg=None):
    """Return ``{'action', 'manifest', 'state'}`` for the browser to form-post to GitHub.

    *origin* must already be checked against the server's allowed origins; it
    becomes the app's redirect and setup URLs. The app is always private: only
    its owner (*org*, or the signed-in user) can install it. Making it public is
    a deliberate step on GitHub's app settings page (docs/github-app.md).
    """
    cfg = settings_mod.load_settings() if cfg is None else cfg
    apps = _configured_apps(cfg)
    # Check before sending anyone to GitHub: without cryptography the callback cannot
    # check the new key, and GitHub would be left with an app LDE has no key for.
    try:
        import cryptography.hazmat.primitives.serialization  # noqa: F401
    except ImportError:
        raise ValueError('Creating a GitHub App needs the cryptography package in the Python '
                         'that runs LDE. Run pip install -r requirements.txt with that Python, '
                         'restart LDE, then try again.') from None
    if not isinstance(origin, str) or not origin:
        raise ValueError('Origin header is required to create a GitHub App')
    org = (org or '').strip() if isinstance(org, str) else None
    if org is None or (org and not _ORG_RE.match(org)):
        raise ValueError('org must be a GitHub organization name, or empty for your own account')
    org = org.lower()
    _ensure_no_app_for(org, apps)
    if name is not None and not isinstance(name, str):
        raise ValueError('name must be a string')
    name = (name or '').strip()
    if not name:
        # App names are unique across GitHub: add a random suffix.
        name = f'LDE {org[:24]} {secrets.token_hex(2)}' if org else f'LDE {secrets.token_hex(3)}'
    if not _NAME_RE.match(name):
        raise ValueError('name must be 1-34 letters, digits, spaces, dots, dashes or underscores, '
                         'starting with a letter or digit')

    manifest = {
        'name': name,
        'url': origin,
        'description': 'Library Dependency Explorer: reads dependency manifests and the '
                       'dependency graph. Read-only.',
        # No hook_attributes: LDE takes no webhooks, and GitHub rejects a hook URL it
        # cannot reach from the internet (localhost) even when the hook is inactive.
        'redirect_url': origin + '/api/gh-app/callback',
        'setup_url': origin + '/settings',
        'setup_on_update': False,
        'public': False,
        'default_permissions': dict(gh_app.TOKEN_PERMISSIONS),
        'default_events': [],
        'request_oauth_on_install': False,
    }
    state = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _pending_lock:
        for s, (exp, _) in list(_pending.items()):
            if exp <= now:
                del _pending[s]
        while len(_pending) >= _MAX_PENDING:
            del _pending[min(_pending, key=lambda k: _pending[k][0])]
        _pending[state] = (now + _STATE_TTL, org)
    base = f'https://github.com/organizations/{org}' if org else 'https://github.com'
    return {'action': f'{base}/settings/apps/new?state={state}',
            'manifest': json.dumps(manifest), 'state': state}


def _take_state(state):
    """Consume *state*; return its expected owner ('' for the user's account), or None."""
    if not isinstance(state, str) or not state:
        return None
    with _pending_lock:
        hit = _pending.pop(state, None)
    if hit is None or time.monotonic() >= hit[0]:
        return None
    return hit[1]


def _convert(code):
    try:
        doc = gh_app._call('POST', f'/app-manifests/{code}/conversions', None, body={})
    except gh_app.AppAuthError as exc:
        # The path holds the one-time code: report only the status.
        status = getattr(exc, 'status', None)
        detail = f'HTTP {status}' if status else 'a network error'
        raise SetupError('exchange', f'GitHub refused to hand over the new app ({detail}). '
                                     'The code is single-use and expires after an hour; '
                                     'start again from Settings.') from None
    if not isinstance(doc, dict):
        raise SetupError('exchange', 'GitHub returned no app')
    app_id, slug, pem = doc.get('id'), doc.get('slug'), doc.get('pem')
    owner = doc.get('owner') if isinstance(doc.get('owner'), dict) else {}
    owner = owner.get('login')
    if (not isinstance(app_id, int) or isinstance(app_id, bool) or app_id <= 0
            or not isinstance(slug, str) or not _SLUG_RE.match(slug)
            or not isinstance(owner, str) or not gh_app._OWNER_RE.match(owner)
            or not isinstance(pem, str) or '-----BEGIN' not in pem):
        raise SetupError('exchange', 'GitHub returned an app without an ID, slug, owner or key')
    try:
        gh_app._load_private_key(pem.encode('utf-8'))
    except gh_app.AppConfigError as exc:
        raise SetupError('exchange', str(exc)) from None
    return {'app_id': str(app_id), 'slug': slug, 'name': str(doc.get('name') or slug),
            'owner': owner.lower(), 'pem': pem}


def _write_key_file(app_id, pem):
    """Write *pem* to a new owner-only file under ~/.lde; return its path."""
    key_dir = os.path.realpath(os.path.expanduser(_KEY_DIR))
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    path = os.path.join(key_dir, f'github-app-{app_id}.pem')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise SetupError('store', f'{_KEY_DIR}/github-app-{app_id}.pem already exists. '
                                  'Move it away and start again.') from None
    except OSError as exc:
        raise SetupError('store', f'Could not create the key file in {_KEY_DIR}: '
                                  f'{exc.strerror or type(exc).__name__}') from None
    with os.fdopen(fd, 'w') as f:
        f.write(pem)
    return path


def _secret_apps(raw, apps):
    """Return lde/github-app's apps as a list of {owner, app_id, private_key} entries."""
    if raw is None or not raw.strip() or raw.strip() == secrets_loader._PLACEHOLDER:
        return []
    parsed = secrets_loader._parse_app(raw)
    if 'github_apps_secret' in parsed:
        return list(parsed['github_apps_secret'])
    if 'github_app_id' in parsed:
        legacy = {'app_id': parsed['github_app_id'],
                  'pem': parsed['github_app_private_key'].encode('utf-8'), 'owner': ''}
        return [{'owner': _owner_of(legacy), 'app_id': parsed['github_app_id'],
                 'private_key': parsed['github_app_private_key']}]
    raise SetupError('store', 'lde/github-app holds something LDE cannot read. Fix it or set it '
                              'back to REPLACE_ME, then start again.')


def _store_aws(app, apps):
    try:
        entries = _secret_apps(secrets_loader.get_secret_fresh('lde/github-app'), apps)
        entries.append({'owner': app['owner'], 'app_id': app['app_id'],
                        'private_key': app['pem']})
        secrets_loader.put_secret('lde/github-app', json.dumps({'apps': entries}))
    except RuntimeError as exc:
        if isinstance(exc, SetupError):
            raise
        raise SetupError('store', str(exc)) from None


def _store_local(app):
    path = _write_key_file(app['app_id'], app['pem'])
    current = settings_mod.load_settings().get('github_apps') or []
    if not isinstance(current, list):
        raise SetupError('config', 'github_apps in .settings.json must be a list')
    settings_mod.save_settings({'github_apps': current + [
        {'owner': app['owner'], 'app_id': app['app_id'], 'private_key_path': path}]})


def complete(code, state):
    """Exchange the manifest *code* for the new app and add it.

    Returns ``{'slug', 'name', 'app_id', 'owner'}``. Raises SetupError (with a
    fixed *reason*) on every failure.
    """
    expected = _take_state(state)
    if expected is None:
        raise SetupError('state', 'This setup link is unknown, used or expired. '
                                  'Start again from Settings.')
    if not isinstance(code, str) or not _CODE_RE.match(code):
        raise SetupError('exchange', 'GitHub sent no usable code')
    with _complete_lock:
        apps = _configured_apps(settings_mod.load_settings())
        _ensure_no_app_for(expected, apps)
        app = _convert(code)
        if expected and app['owner'] != expected:
            raise SetupError('exchange', f'GitHub created the app under {app["owner"]}, not '
                                         f'{expected}. Delete it on GitHub and start again.')
        _ensure_no_app_for(app['owner'], apps)
        if _aws():
            _store_aws(app, apps)
        else:
            _store_local(app)
        gh_app.reset_caches()
    logger.info('created GitHub App %s (id %s) for %s', app['slug'], app['app_id'], app['owner'])
    return {'slug': app['slug'], 'name': app['name'], 'app_id': app['app_id'],
            'owner': app['owner']}


def install_url(slug):
    """The app's public install page, or '' for an unusable slug."""
    return f'https://github.com/apps/{slug}/installations/new' if _SLUG_RE.match(slug or '') else ''
