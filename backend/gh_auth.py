"""GitHub authentication status using a Personal Access Token.

Replaces the previous `gh auth status` subprocess approach.  Validates the
configured PAT by calling GET /user and returns a dict in the same shape the
Settings UI expects.
"""

import json
import os
import urllib.error
import urllib.request

from . import settings as settings_mod

_API_BASE = 'https://api.github.com'
_API_VERSION = '2022-11-28'
_TIMEOUT = 10


def auth_status():
    """Return a dict describing the configured PAT's auth status.

    {
        'installed': bool,   # True when a PAT is configured in settings
        'logged_in': bool,   # True when GET /user succeeds with the PAT
        'accounts': [{'host': str, 'user': str, 'scopes': [str], 'sso_orgs': [str]}],
        'raw': str,          # human-readable summary for the UI
    }
    """
    token = settings_mod.load_settings().get('github_pat', '').strip()
    if not token:
        if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws':
            return {
                'installed': False,
                'logged_in': False,
                'accounts': [],
                'raw': 'No GitHub PAT configured. Write lde/github-pat with the command in '
                       'docs/aws-deployment.md Step 4 (GitHub PAT). LDE reads Secrets Manager '
                       'within a minute.',
            }
        return {
            'installed': False,
            'logged_in': False,
            'accounts': [],
            'raw': 'No GitHub PAT configured. Add one in Settings. Required repository '
                   'permissions: Contents: Read-only (file fetch, tree listing, dependency '
                   'graph SBOM) and Metadata: Read-only (org repo listing).',
        }
    if token == 'REPLACE_ME':
        return {
            'installed': False,
            'logged_in': False,
            'accounts': [],
            'raw': 'lde/github-pat is still the placeholder REPLACE_ME. '
                   'Write the token with the command in docs/aws-deployment.md Step 4 (GitHub PAT). '
                   'LDE reads Secrets Manager within a minute.',
        }

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': _API_VERSION,
        'User-Agent': 'LibraryDependencyExplorer/1.0',
    }
    req = urllib.request.Request(f'{_API_BASE}/user', headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = json.loads(resp.read())
            scopes_raw = resp.headers.get('X-OAuth-Scopes', '')
    except urllib.error.HTTPError as exc:
        scopes_raw = ''
        if exc.code in (401, 403):
            return {
                'installed': True,
                'logged_in': False,
                'accounts': [],
                'raw': f'PAT is configured but authentication failed (HTTP {exc.code}). '
                       'Check that the token is valid and has not expired.',
            }
        return {
            'installed': True,
            'logged_in': False,
            'accounts': [],
            'raw': f'GitHub API error: HTTP {exc.code}',
        }
    except urllib.error.URLError as exc:
        return {
            'installed': True,
            'logged_in': False,
            'accounts': [],
            'raw': f'Network error reaching GitHub: {exc.reason}',
        }

    login = body.get('login', 'unknown')
    scopes = [s.strip() for s in scopes_raw.split(',') if s.strip()] if scopes_raw else []
    raw_lines = [
        f'Logged in to github.com account {login} (PAT)',
        f'Token scopes: {", ".join(scopes) if scopes else "(fine-grained PAT — scopes not reported)"}',
    ]

    return {
        'installed': True,
        'logged_in': True,
        'accounts': [{
            'host': 'github.com',
            'user': login,
            'scopes': scopes,
            'sso_orgs': [],
        }],
        'raw': '\n'.join(raw_lines),
    }
