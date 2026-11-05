"""GitHub authentication status for the GitHub App and any fallback PATs.

The app is checked with ``GET /app`` (app JWT) and, per org, by minting an
installation token. Deprecated PATs are checked with ``GET /user``.
"""

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import gh_app, gh_app_setup
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


PAT_DEPRECATION = ('GitHub PATs are deprecated. Create a GitHub App for these orgs in Settings, '
                   'then remove their PATs: {orgs}. See docs/github-app.md.')


def _not_configured_message():
    where = (' LDE writes the app into the lde/github-app secret.'
             if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws' else '')
    return ('No GitHub credentials configured. In Settings, click "Create GitHub App on '
            f'GitHub" (docs/github-app.md).{where}')


def _apps_status(cfg):
    """Return (apps, app_cfgs, error). Never raises; never includes key material.

    *apps* is one public description per configured app; *app_cfgs* the loaded
    configs (with keys) for token checks; *error* a message when the app config
    is broken, in which case every app-based check fails closed.
    """
    try:
        app_cfgs = gh_app.app_configs(cfg)
    except gh_app.AppConfigError as exc:
        return [], [], str(exc)

    def describe(app_cfg):
        out = {'owner': app_cfg['owner'], 'app_id': app_cfg['app_id'], 'ok': False, 'slug': '',
               'name': '', 'key_source': app_cfg['source'], 'install_url': '', 'message': ''}
        try:
            ident = gh_app.app_identity(app_cfg)
        except (gh_app.AppConfigError, gh_app.AppAuthError) as exc:
            msg = str(exc)
            if getattr(exc, 'status', None) == 401:
                msg = (f'GitHub rejected the JWT for app {app_cfg["app_id"]} (HTTP 401). Check '
                       'that the private key belongs to that app and has not been revoked.')
            out['message'] = msg
            return out
        out.update(ok=True, slug=ident['slug'], name=ident['name'],
                   owner=app_cfg['owner'] or ident['owner'].lower(),
                   install_url=gh_app_setup.install_url(ident['slug']),
                   message=f'Authenticated as GitHub App {ident["name"] or ident["slug"]}')
        return out

    apps = []
    if app_cfgs:
        with ThreadPoolExecutor(max_workers=min(8, len(app_cfgs))) as pool:
            apps = list(pool.map(describe, app_cfgs))
    return apps, app_cfgs, ''


def _org_via_apps(app_cfgs, org):
    """Return (installed, ok, app_id, message) for *org* via the configured apps."""
    try:
        token, app = gh_app.token_for(app_cfgs, org)
    except ValueError:
        return False, False, '', 'invalid org name'
    except (gh_app.AppConfigError, gh_app.AppAuthError) as exc:
        return True, False, '', str(exc)
    if token:
        return True, True, app['app_id'], 'GitHub App installed'
    return False, False, '', 'no GitHub App installed'


def auth_status():
    """Return a dict describing GitHub App and PAT auth status.

    {
        'installed': bool,   # True when any GitHub credential is configured
        'logged_in': bool,   # True when every app works and every listed org is covered
        'mode': str,         # 'app', 'pat', 'mixed' (apps plus PAT fallbacks) or 'none'
        'apps': [{'owner', 'app_id', 'ok', 'slug', 'name', 'key_source', 'install_url',
                  'message'}],
        'apps_error': str,   # broken app config, else ''
        'accounts': [{'host', 'org', 'user', 'ok', 'via', 'app'}],  # via: 'app', 'pat' or ''
        'raw': str,          # human-readable summary for the UI
        'notice': str,       # old-config or PAT deprecation notice, else ''
    }

    Orgs listed are ``default_orgs``, every PAT org and every app owner. Talks
    only to api.github.com. Tokens and keys are never echoed or logged.
    """
    cfg = settings_mod.load_settings()
    pats = settings_mod.github_tokens(cfg)
    notices = [n for n in [settings_mod.legacy_pat_notice()] if n]
    apps, app_cfgs, apps_error = _apps_status(cfg)
    by_id = {a['app_id']: a for a in apps}

    if not apps and not apps_error and not pats:
        return {'installed': False, 'logged_in': False, 'mode': 'none', 'apps': [],
                'apps_error': '', 'accounts': [], 'raw': _not_configured_message(),
                'notice': ' '.join(notices)}

    default_orgs = [o.lower() for o in (cfg.get('default_orgs') or []) if isinstance(o, str)]
    owners = {a['owner'] for a in apps if a['owner']}
    orgs = sorted(set(default_orgs) | {o for o in pats if o != '*'} | owners)
    if '*' in pats:
        orgs.append('*')

    def check(org):
        if org != '*' and (app_cfgs or apps_error):
            if apps_error:
                return {'ok': False, 'via': 'app', 'user': '', 'app': '',
                        'message': f'GitHub App config is broken: {apps_error}'}
            installed, ok, app_id, msg = _org_via_apps(app_cfgs, org)
            if installed:
                slug = by_id.get(app_id, {}).get('slug', '')
                return {'ok': ok, 'via': 'app', 'user': f'{slug}[bot]' if ok and slug else '',
                        'app': slug, 'message': f'{msg} ({slug})' if slug else msg}
        pat = pats.get(org) or (pats.get('*') if org != '*' else None)
        if pat and (org in pats or org == '*'):
            res = check_token(pat)
            return {'ok': res['ok'], 'via': 'pat', 'user': res['user'], 'app': '',
                    'message': f'PAT: {res["message"]}'}
        if pat:
            return {'ok': True, 'via': 'pat', 'user': '', 'app': '',
                    'message': 'covered by the "*" PAT'}
        reason = 'no GitHub App installed and no PAT' if app_cfgs else 'no PAT'
        return {'ok': False, 'via': '', 'user': '', 'app': '', 'message': reason}

    results = []
    if orgs:
        with ThreadPoolExecutor(max_workers=min(8, len(orgs))) as pool:
            results = list(pool.map(check, orgs))

    accounts, lines = [], []
    if apps_error:
        lines.append(f'GitHub App config: {apps_error}')
    for a in apps:
        lines.append(f'GitHub App {a["slug"] or a["app_id"]}: {a["message"]}')
    for org, res in zip(orgs, results):
        accounts.append({'host': 'github.com', 'org': org, 'user': res['user'],
                         'ok': res['ok'], 'via': res['via'], 'app': res['app']})
        label = 'all other orgs (*)' if org == '*' else org
        lines.append(f'{label}: {res["message"]}')

    pat_orgs = [a['org'] for a in accounts if a['via'] == 'pat']
    if pat_orgs:
        notices.append(PAT_DEPRECATION.format(orgs=', '.join(pat_orgs)))
    uses_app = bool(apps) or bool(apps_error)
    mode = 'mixed' if uses_app and pat_orgs else 'app' if uses_app else 'pat'
    apps_ok = not apps_error and all(a['ok'] for a in apps)
    return {
        'installed': True,
        'logged_in': apps_ok and all(a['ok'] for a in accounts),
        'mode': mode,
        'apps': apps,
        'apps_error': apps_error,
        'accounts': accounts,
        'raw': '\n'.join(lines),
        'notice': ' '.join(notices),
    }
