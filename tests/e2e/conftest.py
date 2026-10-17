"""End-to-end pytest fixtures: drive the real pipeline against example-org.

Each test that uses the `run_repo` fixture will:

  1. POST /api/runs with a one-repo scope.
  2. Poll /api/runs/{id} until status hits a terminal state.
  3. Yield {run_id, run_status, repos[0]} dict for the test to assert on.

Because the pipeline runs in a background thread inside the server
process, these tests need:

  - The `python3 server.py` orchestrator running on `LDE_E2E_BASE_URL`
    (default http://127.0.0.1:8002).
  - `gh auth status` showing logged-in for the orgs under test.
  - Docker compose up, with ORT, DT, and the three caching proxies.

Tests are marked `@pytest.mark.e2e` so they don't run as part of the
default `pytest` invocation. Use `pytest -m e2e` to opt in.

Skip semantics:
  - Server unreachable → skip (not fail) so a forgetful local dev
    isn't punished for not booting infra.
  - DT unreachable but DT-using test → skip with a clear reason.
  - Single-repo run takes too long → fixture fails the test with a
    descriptive timeout (max wall: LDE_E2E_TIMEOUT seconds, default
    1800 = 30 min — the slowest known repo cold).
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest


BASE_URL = os.environ.get('LDE_E2E_BASE_URL', 'http://127.0.0.1:8002').rstrip('/')
# The e2e suite drives the real pipeline against repositories you control.
# Point it at your own GitHub org and repos via LDE_E2E_ORG (and the repo names
# referenced in the individual test modules). The default below is a placeholder
# that exists for no one — the suite skips unless LDE_E2E_ORG is set explicitly.
ORG_CONFIGURED = 'LDE_E2E_ORG' in os.environ
DEFAULT_ORG = os.environ.get('LDE_E2E_ORG', 'example-org')
TIMEOUT = int(os.environ.get('LDE_E2E_TIMEOUT', '1800'))
POLL_INTERVAL = int(os.environ.get('LDE_E2E_POLL_INTERVAL', '5'))


def pytest_collection_modifyitems(config, items):
    """Make sure `e2e` tests don't accidentally run in default pytest.

    Without this, a CI default of `pytest tests/` would try to drive a
    pipeline that may not be running. The `e2e` marker plus a server
    preflight skip keeps the default invocation green.

    The suite is also skipped unless LDE_E2E_ORG is set, because the tests
    reference specific repositories that only exist in an org you configure.
    """
    dash_m = config.getoption('-m', default='') or ''
    if 'e2e' in dash_m and ORG_CONFIGURED:
        return
    if 'e2e' in dash_m and not ORG_CONFIGURED:
        reason = 'e2e tests require LDE_E2E_ORG (point it at repos you control)'
    else:
        reason = 'e2e tests require -m e2e and a live server'
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if 'e2e' in item.keywords:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class E2EError(RuntimeError):
    pass


def _request(method, path, body=None, timeout=30):
    url = BASE_URL + path
    data = None
    headers = {'Accept': 'application/json'}
    if method != 'GET':
        headers['Content-Type'] = 'application/json'  # required by the CSRF guard
    if body is not None:
        data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            if not payload:
                return resp.status, None
            try:
                return resp.status, json.loads(payload)
            except json.JSONDecodeError:
                return resp.status, payload.decode('utf-8', errors='replace')
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')[:300]
        raise E2EError(f'{method} {path} → HTTP {exc.code}: {detail}') from exc
    except urllib.error.URLError as exc:
        raise E2EError(f'{method} {path} → {exc.reason}') from exc


def _server_is_up():
    try:
        status, _ = _request('GET', '/api/settings', timeout=3)
        return status == 200
    except E2EError:
        return False


def _dtrack_is_configured():
    try:
        status, body = _request('GET', '/api/settings', timeout=5)
        if status != 200 or not isinstance(body, dict):
            return False
        return bool(body.get('dtrack_url')) and bool(body.get('dtrack_api_key'))
    except E2EError:
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def server_url():
    if not _server_is_up():
        pytest.skip(f'Library Dependency Explorer not reachable at {BASE_URL}; '
                    f'set LDE_E2E_BASE_URL or boot the server.')
    return BASE_URL


@pytest.fixture(scope='session')
def dtrack_configured(server_url):
    if not _dtrack_is_configured():
        pytest.skip('Dependency-Track is not configured in settings; '
                    'tests that need DT cannot run.')
    return True


def _post_run(orgs, repos, branch=None, method=None):
    body = {'orgs': orgs, 'repos': repos}
    if branch:
        body['use_default'] = False
        body['branch'] = branch
    if method:
        body['method'] = method
    status, resp = _request('POST', '/api/runs', body=body)
    if status != 202 or not isinstance(resp, dict) or 'run_id' not in resp:
        raise E2EError(f'POST /api/runs returned {status}: {resp!r}')
    return resp['run_id']


def _wait_for_terminal(run_id, timeout):
    """Poll /api/runs/{id} until a terminal status, return the final row."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            _status, body = _request('GET', f'/api/runs/{run_id}', timeout=10)
        except E2EError as exc:
            # Network blips during a long run shouldn't fail the test
            # immediately; retry after the poll interval.
            print(f'[e2e] poll {run_id[:8]} transient error: {exc}', flush=True)
            time.sleep(POLL_INTERVAL)
            continue
        last = body
        if not isinstance(body, dict):
            time.sleep(POLL_INTERVAL)
            continue
        st = body.get('status')
        if st in ('completed', 'failed', 'partial', 'stopped'):
            return body
        time.sleep(POLL_INTERVAL)
    raise E2EError(f'run {run_id} did not reach a terminal status within {timeout}s '
                   f'(last={last!r})')


@pytest.fixture
def run_repo(server_url):
    """Factory fixture: call as `run_repo('example-org', 'aws-examples')`.

    Returns a dict with run_id, run_status, repo_row, manifests, log_path.
    Each invocation is a *separate* run (you can call it multiple times
    inside one test if you need a fresh pipeline).
    """
    created = []

    def _factory(repo, org=DEFAULT_ORG, timeout=TIMEOUT, extra_repos=None,
                 branch=None, method=None):
        scope = [repo] + list(extra_repos or [])
        run_id = _post_run([org], scope, branch=branch, method=method)
        created.append(run_id)
        run = _wait_for_terminal(run_id, timeout)
        # Per-repo state.
        _status, repos_body = _request('GET', f'/api/runs/{run_id}/repos')
        if not isinstance(repos_body, list):
            raise E2EError(f'/api/runs/{run_id}/repos returned non-list: {repos_body!r}')
        target = next((r for r in repos_body if r.get('repo') == repo), None)
        # Manifest catalog (uses our new endpoint).
        _status, manifests_body = _request('GET', f'/api/runs/{run_id}/manifests')
        manifests = [m for m in (manifests_body or [])
                     if m.get('org') == org and m.get('repo') == repo]
        log_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'runs', run_id,
        )
        log_path = os.path.join(log_dir, f'{org}__{repo}.log')
        return {
            'run_id': run_id,
            'run': run,
            'org': org,
            'repo': repo,
            'repo_row': target,
            'manifests': manifests,
            'log_path': log_path if os.path.isfile(log_path) else None,
            'log_dir': log_dir,
        }

    yield _factory
    # We deliberately leave runs in the DB so the operator can re-inspect
    # afterwards. No cleanup.


@pytest.fixture
def latest_run_with_repos(server_url):
    """Return the most-recent terminal run that covers a given set of repos.

    Used by the @tanstack search test: rather than start a fresh full-org
    run (slow), reuse whatever run already covered the named repos.
    """
    def _factory(required_repos, org=DEFAULT_ORG):
        _status, runs = _request('GET', '/api/runs')
        if not isinstance(runs, list):
            return None
        for r in runs:
            if r.get('status') not in ('completed', 'partial'):
                continue
            run_id = r['id']
            _s, repos = _request('GET', f'/api/runs/{run_id}/repos')
            if not isinstance(repos, list):
                continue
            names = {x.get('repo') for x in repos if x.get('org') == org}
            if set(required_repos).issubset(names):
                return {'run_id': run_id, 'run': r, 'repos': repos}
        return None
    return _factory


def fetch_run_coverage(run_id):
    """Helper used by tests to read the new coverage endpoint."""
    _status, body = _request('GET', f'/api/runs/{run_id}/coverage')
    return body


def fetch_dt_components(run_id, org, repo):
    """Helper for the per-repo DT components endpoint."""
    _status, body = _request('GET', f'/api/runs/{run_id}/repos/{org}/{repo}/dtrack-components')
    return body


def fetch_dt_search(query):
    """Helper for the cross-project DT search endpoint."""
    qs = urllib.parse.urlencode({'q': query})
    _status, body = _request('GET', f'/api/dtrack/search?{qs}')
    return body


def assert_no_silent_python_inspector_failure(state, expected_repo):
    """Fail loudly if ORT logged a python-inspector RecursionError without
    the new classifier+fallback also recording a rescue.

    Pre-fix, ``scoped-widget`` and ``example-lib`` both
    hit ``RecursionError: maximum recursion depth exceeded`` inside
    ``python-inspector``'s ``pdt_dfs`` walker for one of their Poetry
    sub-projects. ORT swallowed the failure and exited 0, so any test that
    only asserted ``ort_status == "completed"`` passed even though
    packages were silently dropped.

    Two acceptable outcomes:
      1. Log doesn't contain ``RecursionError`` (no failure happened).
      2. Log contains it AND the run_repos row has both
         ``analyzer_issue_kind`` containing ``python_inspector_recursion``
         and ``poetry_fallback_count > 0`` (classifier + fallback rescued).
    """
    log_path = state.get('log_path')
    if not log_path or not os.path.isfile(log_path):
        return
    with open(log_path, 'r', errors='replace') as fh:
        text = fh.read()
    if 'RecursionError' not in text:
        return
    row = state.get('repo_row') or {}
    issue_kinds = (row.get('analyzer_issue_kind') or '').split(';')
    if 'python_inspector_recursion' not in issue_kinds:
        raise AssertionError(
            f'{expected_repo}: ORT log contains python-inspector RecursionError '
            f'but analyzer_issue_kind={row.get("analyzer_issue_kind")!r}. '
            f'Check pipeline._classify_analyzer_log.'
        )
    if (row.get('poetry_fallback_count') or 0) <= 0:
        raise AssertionError(
            f'{expected_repo}: python-inspector RecursionError logged but '
            f'poetry_fallback_count=0. Check pipeline._maybe_run_poetry_fallback '
            f'— sandbox at ingest time, lock parsing, or merge.'
        )
