"""GitHub authentication status using a Personal Access Token.

Validates each configured PAT (one per org) by calling GET /user.
"""

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

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


def auth_status():
    """Return a dict describing every configured PAT's auth status.

    {
        'installed': bool,   # True when at least one PAT is configured
        'logged_in': bool,   # True when every configured PAT passes GET /user
        'accounts': [{'host': str, 'org': str, 'user': str, 'ok': bool}],
        'raw': str,          # human-readable summary for the UI
    }
    """
    pats = settings_mod.github_tokens(settings_mod.load_settings())
    notice = settings_mod.legacy_pat_notice()
    if not pats:
        if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws':
            raw = ('No GitHub PATs configured. Write lde/github-pat as a JSON object {org: token} with the command in '
                   'docs/aws-deployment.md Step 4 (GitHub PAT). LDE reads Secrets Manager '
                   'within a minute.')
        else:
            raw = ('No GitHub PATs configured. Add one per org in Settings. Required repository '
                   'permissions: Contents: Read-only (file fetch, tree listing, dependency '
                   'graph SBOM) and Metadata: Read-only (org repo listing).')
        return {'installed': False, 'logged_in': False, 'accounts': [], 'raw': raw,
                'notice': notice}

    accounts, lines = [], []
    orgs = sorted(pats)
    with ThreadPoolExecutor(max_workers=min(8, len(orgs))) as pool:
        results = list(pool.map(lambda o: check_token(pats[o]), orgs))
    for org, res in zip(orgs, results):
        accounts.append({'host': 'github.com', 'org': org, 'user': res['user'], 'ok': res['ok']})
        label = 'all other orgs (*)' if org == '*' else org
        lines.append(f'{label}: {res["message"]}')
    return {
        'installed': True,
        'logged_in': all(a['ok'] for a in accounts),
        'accounts': accounts,
        'raw': '\n'.join(lines),
        'notice': notice,
    }
