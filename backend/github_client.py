"""GitHub API client using urllib.request + a Personal Access Token.

Replaces the previous `gh` CLI subprocess approach so the server can run
headlessly in ECS Fargate (no local gh session required).  The PAT is read
from settings at call-time via `_get_token()` so it can be overlaid by
AWS Secrets Manager at runtime without restarting.

All requests target https://api.github.com only — no user-supplied base URL
is accepted, eliminating SSRF risk from the GitHub layer.
"""

import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

from . import log as log_mod
from . import settings as settings_mod

logger = log_mod.get('gh')

_API_BASE = 'https://api.github.com'
_API_VERSION = '2022-11-28'
_TIMEOUT = 30
_RATELIMIT_BACKOFF_SECS = 30
_MAX_RETRIES = 4

# org / repo names: letters, digits, hyphen, underscore, dot — no path separators
_ID_RE = re.compile(r'^[A-Za-z0-9._-]+$')

# Git branch names: allow path separators for namespaced branches
# (e.g. release/1.2, feature/foo) but the value is always URL-encoded
# before it reaches a GitHub API path segment. `_valid_branch` adds the
# traversal / leading-dash / empty-segment checks the bare regex can't.
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]+$')


def _valid_branch(branch):
    """True when *branch* is a safe git branch ref to interpolate into a URL.

    Rejects empty values, traversal (``..``), empty path segments (``//``),
    leading/trailing slashes, and a leading ``-`` (which could be parsed as
    an option). Callers must still URL-encode the value.
    """
    if not branch or not isinstance(branch, str):
        return False
    if not _BRANCH_RE.match(branch):
        return False
    if branch.startswith(('/', '-')) or branch.endswith('/'):
        return False
    if '..' in branch or '//' in branch:
        return False
    return True


class GhError(RuntimeError):
    """GitHub call failed. *status* is the HTTP status when there was one.

    Callers branch on ``status``, never on the message: the message carries
    the request URL, so an org or repo named ``team404`` would match "404".
    """

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _get_token(org):
    """Return the PAT for *org* from the ``github_pats`` map.

    Fine-grained PATs are bound to one resource owner, so each org has its own
    entry. A ``"*"`` entry is the token for any org without one of its own (for
    example a classic PAT that spans several orgs). Raises GhError when neither
    exists: an unknown org is never sent unauthenticated. Settings carry the
    Secrets Manager overlay applied at load time.
    """
    pats = settings_mod.github_tokens(settings_mod.load_settings())
    key = (org or '').lower()
    if key in pats:
        return pats[key]
    if '*' in pats:
        return pats['*']
    raise GhError(f'No GitHub PAT configured for org {org!r}. Add one in Settings, '
                  f'or add a "*" entry to use one token for every other org.')


def _make_headers(token):
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': _API_VERSION,
        'User-Agent': 'LibraryDependencyExplorer/1.0',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers


def _parse_next_link(link_header):
    """Return the URL for rel="next" from a GitHub Link header, or None."""
    if not link_header:
        return None
    for part in link_header.split(','):
        url_part, _, rel_part = part.strip().partition(';')
        if 'rel="next"' in rel_part:
            return url_part.strip().strip('<>')
    return None


def _request(method, url, *, accept=None, token=None, attempts=0):
    """Perform a single authenticated request with rate-limit retry.

    Returns (response_body_bytes, response_headers_dict).
    Raises GhError on non-recoverable errors.
    """
    headers = _make_headers(token)
    if accept:
        headers['Accept'] = accept

    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return body, resp_headers
    except urllib.error.HTTPError as exc:
        remaining = exc.headers.get('X-RateLimit-Remaining', '1')
        reset_at = exc.headers.get('X-RateLimit-Reset', '0')
        if exc.code == 429 or (exc.code == 403 and remaining == '0'):
            if attempts < _MAX_RETRIES:
                wait = max(int(reset_at) - int(time.time()), 1)
                wait = min(wait, _RATELIMIT_BACKOFF_SECS)
                logger.warning('rate-limited; sleeping %ds (attempt %d)', wait, attempts + 1)
                time.sleep(wait)
                return _request(method, url, accept=accept, token=token, attempts=attempts + 1)
        raise GhError(f'GitHub API {exc.code} for {url}: {exc.reason}', status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise GhError(f'GitHub API network error for {url}: {exc.reason}') from exc


def _get_json(url, *, accept=None, token=None):
    """GET a URL, return parsed JSON."""
    body, _ = _request('GET', url, accept=accept, token=token)
    return json.loads(body)


def _get_paginated(url, *, token=None):
    """Iterate all pages of a GitHub list endpoint, yielding each item."""
    next_url = url
    while next_url:
        body, headers = _request('GET', next_url, token=token)
        items = json.loads(body)
        if isinstance(items, list):
            yield from items
        link = headers.get('link', '')
        next_url = _parse_next_link(link)


def list_repos(org):
    """Return [(repo_name, default_branch), ...] for *org*.

    Uses GET /orgs/{org}/repos with pagination.  Archived repos are
    excluded.  Requires the PAT to be a member of *org* or for the org to
    have public repos accessible to the token.
    """
    if not _ID_RE.match(org or ''):
        raise ValueError(f'Invalid org name: {org!r}')
    params = urlencode({'per_page': 100, 'type': 'all', 'sort': 'full_name'})
    url = f'{_API_BASE}/orgs/{org}/repos?{params}'
    repos = []
    for entry in _get_paginated(url, token=_get_token(org)):
        if entry.get('archived'):
            continue
        name = entry.get('name')
        branch = entry.get('default_branch')
        if name and branch:
            repos.append((name, branch))
    return repos


def get_repo_default_branch(org, repo):
    """Return the repo's default branch name, or None when unavailable.

    A single cheap ``GET /repos/{org}/{repo}`` lookup, used by the
    github_sbom path for explicitly-listed ``org/repo`` pairs where no org
    listing (which would otherwise carry the default branch) is performed.
    """
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org/repo identifier')
    url = f'{_API_BASE}/repos/{org}/{repo}'
    token = _get_token(org)
    try:
        data = _get_json(url, token=token)
    except GhError as exc:
        if exc.status in (404, 403):
            return None
        raise
    return data.get('default_branch') if isinstance(data, dict) else None


def list_tree_paths(org, repo, branch):
    """Return a list of file paths in the repo's tree (recursive)."""
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org/repo identifier')
    if not _valid_branch(branch):
        raise ValueError(f'Invalid branch name: {branch!r}')
    url = f'{_API_BASE}/repos/{org}/{repo}/git/trees/{quote(branch, safe="")}?recursive=1'
    token = _get_token(org)
    try:
        data = _get_json(url, token=token)
    except GhError as exc:
        if exc.status in (404, 409):
            # 409 = empty repo; 404 = branch not found
            return []
        raise
    tree = data.get('tree') or []
    return [item['path'] for item in tree if item.get('type') == 'blob' and item.get('path')]


def fetch_file(org, repo, path):
    """Return the raw content of *path* on the repo's default branch as a string."""
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org/repo identifier')
    parts = path.replace('\\', '/').split('/')
    if '..' in parts or path.startswith('/'):
        raise ValueError(f'Path traversal in {path!r}')
    url = f'{_API_BASE}/repos/{org}/{repo}/contents/{path}'
    body, _ = _request(
        'GET', url,
        accept='application/vnd.github.v3.raw',
        token=_get_token(org),
    )
    return body.decode('utf-8', errors='replace')


def fetch_dependency_sbom(org, repo):
    """Return the parsed SPDX JSON for *repo*, or None if unavailable.

    Returns None on HTTP 404 (repo not found / dependency graph disabled)
    or 403 (repo access denied).  Raises GhError on other errors.

    Note: GitHub only generates this SBOM for the repository's default
    branch — there is no ref parameter. Non-default branches are handled
    via `fetch_dependency_diff` instead.
    """
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org/repo identifier')
    url = f'{_API_BASE}/repos/{org}/{repo}/dependency-graph/sbom'
    token = _get_token(org)
    try:
        return _get_json(url, token=token)
    except GhError as exc:
        if exc.status in (404, 403):
            return None
        raise


def _post_graphql(query, variables=None, *, token=None, attempts=0):
    """POST a GraphQL query to api.github.com/graphql; return the `data` dict.

    Reuses the REST auth headers and timeout. Raises GhError on transport
    failures or GraphQL-level errors (only the first error message is
    surfaced, never the full payload, to avoid leaking internals).

    Transient gateway errors (502/503/504) — which GitHub returns when a
    query is momentarily too expensive — are retried with a short backoff.
    """
    headers = _make_headers(token)
    headers['Content-Type'] = 'application/json'
    payload = json.dumps({'query': query, 'variables': variables or {}}).encode('utf-8')
    req = urllib.request.Request(f'{_API_BASE}/graphql', data=payload,
                                 headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (502, 503, 504) and attempts < _MAX_RETRIES:
            wait = min(2 ** attempts, _RATELIMIT_BACKOFF_SECS)
            logger.warning('GraphQL %d; retrying in %ds (attempt %d)',
                           exc.code, wait, attempts + 1)
            time.sleep(wait)
            return _post_graphql(query, variables, token=token, attempts=attempts + 1)
        raise GhError(f'GitHub GraphQL {exc.code}: {exc.reason}', status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise GhError(f'GitHub GraphQL network error: {exc.reason}') from exc
    data = json.loads(body)
    if data.get('errors'):
        msg = (data['errors'][0] or {}).get('message', 'unknown GraphQL error')
        raise GhError(f'GitHub GraphQL error: {msg}')
    return data.get('data') or {}


def fetch_dependency_diff(org, repo, base, head):
    """Return the dependency-review diff between two refs, or None.

    Calls ``GET /repos/{org}/{repo}/dependency-graph/compare/{base}...{head}``.
    GitHub resolves named revisions to commit SHAs and reports dependency
    changes introduced on *head* relative to *base*. This is the only API
    that operates on arbitrary (non-default) refs.

    Returns the parsed list of change entries (each carries
    ``change_type``/``name``/``version``/``package_url``/``ecosystem``/...),
    or None on 404 (no dependency snapshot on a compared commit) / 403.
    """
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org/repo identifier')
    if not _valid_branch(base) or not _valid_branch(head):
        raise ValueError('Invalid base/head ref')
    basehead = f'{quote(base, safe="")}...{quote(head, safe="")}'
    url = f'{_API_BASE}/repos/{org}/{repo}/dependency-graph/compare/{basehead}'
    token = _get_token(org)
    try:
        result = _get_json(url, token=token)
    except GhError as exc:
        if exc.status in (404, 403):
            return None
        raise
    return result if isinstance(result, list) else []
