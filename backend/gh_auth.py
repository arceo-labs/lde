"""GitHub authentication status for every org in the GitHub org map.

Each app is checked with ``GET /app`` (app JWT) and, per org, by minting an
installation token. Deprecated PATs are checked with ``GET /user``.
"""

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import gh_app, gh_app_setup, gh_config
from . import settings as settings_mod

_API_BASE = 'https://api.github.com'
_API_VERSION = '2022-11-28'
_TIMEOUT = 10


def _whoami(token):
    """Return (login, error) for *token* via GET /user. Never echoes the token."""
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': _API_VERSION,
        'User-Agent': 'LibraryDependencyExplorer/1.0',
    }
    req = urllib.request.Request(f'{_API_BASE}/user', headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read()).get('login', 'unknown'), None
    except urllib.error.HTTPError as exc:
        return None, f'HTTP {exc.code}'
    except urllib.error.URLError as exc:
        return None, f'network error: {exc.reason}'
    except (OSError, ValueError) as exc:
        # Read timeouts and malformed bodies are not URLError; report, don't 500.
        return None, f'network error: {type(exc).__name__}'


def check_token(token):
    """Validate one PAT with GET /user. Returns {'ok', 'user', 'message'}.

    Talks only to api.github.com. The token is never echoed or logged.
    """
    login, err = _whoami(token.strip()) if isinstance(token, str) and token.strip() else (None, 'empty token')
    if err is None:
        return {'ok': True, 'user': login, 'message': f'Authenticated as {login}'}
    if err in ('HTTP 401', 'HTTP 403'):
        return {'ok': False, 'user': '', 'message': f'GitHub rejected the token ({err}). '
                                                     'Check that it is valid and has not expired.'}
    return {'ok': False, 'user': '', 'message': f'Could not validate the token ({err}).'}


PAT_DEPRECATION = ('GitHub PATs are deprecated. Create a GitHub App for these orgs in Settings: '
                   '{orgs}. See docs/github-app.md.')


def _not_configured_message():
    where = (' LDE writes them into the lde/github secret.'
             if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws' else '')
    return ('No GitHub orgs configured. In Settings, add an org and click "Create app for '
            f'<org>" (docs/github-app.md).{where}')


class _Apps:
    """Loads each app once per status call and remembers its identity (GET /app)."""

    def __init__(self):
        self._ident = {}

    def identity(self, src):
        key = src['app_id']
        if key not in self._ident:
            try:
                app = gh_config.load_app(src)
                ident = gh_app.app_identity(app)
                self._ident[key] = (app, ident, '')
            except (gh_app.AppConfigError, gh_app.AppAuthError) as exc:
                msg = str(exc)
                if getattr(exc, 'status', None) == 401:
                    msg = (f'GitHub rejected the JWT for app {key} (HTTP 401). Check that the '
                           'private key belongs to that app and has not been revoked.')
                self._ident[key] = (None, None, msg)
        return self._ident[key]


def _check_app_org(apps, src, org):
    """Status fields for an org that authenticates with the app *src*."""
    app, ident, err = apps.identity(src)
    out = {'app': '', 'app_name': '', 'install_url': '', 'user': ''}
    if err:
        return dict(out, ok=False, message=err)
    out.update(app=ident['slug'], app_name=ident['name'] or ident['slug'],
               install_url=gh_app_setup.install_url(ident['slug']))
    try:
        token = gh_app.installation_token(app, org)
    except (gh_app.AppConfigError, gh_app.AppAuthError) as exc:
        return dict(out, ok=False, message=str(exc))
    if not token:
        return dict(out, ok=False, message=f'{out["app_name"]} is not installed on {org}')
    return dict(out, ok=True, user=f'{ident["slug"]}[bot]',
                message=f'GitHub App {out["app_name"]} installed')


def _enterprise_status(apps, src):
    if src is None:
        return None
    app, ident, err = apps.identity(src)
    out = {'enterprise': src['enterprise'], 'app_id': src['app_id'], 'ok': not err,
           'slug': '', 'name': '', 'install_url': '', 'message': err}
    if not err:
        out.update(slug=ident['slug'], name=ident['name'] or ident['slug'],
                   install_url=gh_app_setup.install_url(ident['slug']),
                   message=f'Authenticated as GitHub App {ident["name"] or ident["slug"]}')
    return out


def auth_status():
    """Return a dict describing how every configured org authenticates.

    {
        'installed': bool,      # True when any org or the enterprise app is configured
        'logged_in': bool,      # True when every org in use authenticates
        'mode': str,            # 'app', 'pat', 'mixed' (apps and PATs) or 'none'
        'config_error': str,    # broken org map, else ''
        'source': str,          # 'secret', 'file', 'legacy' or 'none' (backend/gh_config.py)
        'enterprise_app': None | {'enterprise', 'app_id', 'ok', 'slug', 'name',
                                  'install_url', 'message'},
        'orgs': [{'org', 'auth', 'scan', 'ok', 'user', 'app', 'app_name', 'install_url',
                  'token_hint', 'message'}],
        'raw': str,             # human-readable summary for the UI
        'notice': str,          # old-config or PAT deprecation notice, else ''
    }

    Talks only to api.github.com. Tokens and keys are never echoed or logged;
    a PAT appears only as ``token_hint`` (its first four characters).
    """
    notices = [n for n in [settings_mod.legacy_pat_notice()] if n]
    empty = {'installed': False, 'logged_in': False, 'mode': 'none', 'config_error': '',
             'source': 'none', 'enterprise_app': None, 'orgs': []}
    try:
        conf = gh_config.load()
    except gh_config.ConfigError as exc:
        return dict(empty, installed=True, config_error=str(exc),
                    raw=f'GitHub config: {exc}', notice=' '.join(notices))
    notices.extend(conf['notices'])
    if not conf['orgs'] and not conf['enterprise_app']:
        return dict(empty, source=conf['source'], raw=_not_configured_message(),
                    notice=' '.join(notices))

    apps = _Apps()
    enterprise = _enterprise_status(apps, conf['enterprise_app'])

    def check(item):
        org, entry = item
        auth = entry['auth']
        base = {'org': org, 'auth': auth, 'scan': entry['scan'], 'ok': False, 'user': '',
                'app': '', 'app_name': '', 'install_url': '', 'message': '',
                'token_hint': gh_config.token_hint(entry['token']) if auth == 'pat' else ''}
        if auth == 'app':
            return dict(base, **_check_app_org(apps, entry, org))
        if auth == 'enterprise':
            return dict(base, **_check_app_org(apps, conf['enterprise_app'], org))
        if auth == 'pat':
            res = check_token(entry['token'])
            return dict(base, ok=res['ok'], user=res['user'], message=f'PAT: {res["message"]}')
        return dict(base, ok=False, message='no credential yet')

    items = list(conf['orgs'].items())
    results = []
    if items:
        # Identities are fetched first, once per app, so the org checks do not race to fetch them.
        for _, entry in items:
            if entry['auth'] == 'app':
                apps.identity(entry)
        with ThreadPoolExecutor(max_workers=min(8, len(items))) as pool:
            results = list(pool.map(check, items))

    lines = []
    if enterprise:
        lines.append(f'Enterprise app ({enterprise["enterprise"]}): {enterprise["message"]}')
    lines.extend(f'{r["org"]} ({r["auth"]}): {r["message"]}' for r in results)
    pat_orgs = [r['org'] for r in results if r['auth'] == 'pat']
    if pat_orgs:
        notices.append(PAT_DEPRECATION.format(orgs=', '.join(pat_orgs)))
    kinds = {r['auth'] for r in results} - {'none'}
    uses_app = bool(kinds & {'app', 'enterprise'})
    mode = ('mixed' if uses_app and 'pat' in kinds else 'app' if uses_app
            else 'pat' if 'pat' in kinds else 'none')
    in_use = [r for r in results if r['auth'] != 'none' or r['scan']]
    return {
        'installed': True,
        'logged_in': (enterprise is None or enterprise['ok']) and bool(in_use)
                     and all(r['ok'] for r in in_use),
        'mode': mode,
        'config_error': '',
        'source': conf['source'],
        'enterprise_app': enterprise,
        'orgs': results,
        'raw': '\n'.join(lines),
        'notice': ' '.join(notices),
    }
