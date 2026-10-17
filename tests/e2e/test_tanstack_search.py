"""@tanstack cross-repo DT search test.

Asserts that ``@tanstack/*`` components show up in Dependency-Track
under each of the five repos that are known to use the library:

  - example-org/scoped-widget
  - example-org/nvd
  - example-org/example-service
  - example-org/example-platform
  - example-org/ops-dashboard

Failure here narrows the root cause to one of three buckets:

  (1) The manifest never declared @tanstack — *original_dep_count*
      via ``/api/runs/{id}/manifests/.../{b64path}`` will show this.
  (2) ORT failed to resolve scoped packages — the npm-cache scoped-pkg
      regression test (`tests/test_npm_cache.py`) catches the cache
      bug, but a proxy-blocked direct path still fails.
  (3) BOM uploaded but DT lost the component — the per-repo
      ``/dtrack-components`` endpoint pinpoints this.

The assertion message includes per-repo manifest endpoints so the
operator gets a one-click investigation path for each missing repo.
"""

import os
import urllib.parse

import pytest

from .conftest import (
    BASE_URL,
    fetch_dt_search,
    fetch_dt_components,
    _request,
)

ORG = os.environ.get('LDE_E2E_ORG', 'example-org')

REPOS_WITH_TANSTACK = [
    'scoped-widget',
    'nvd',
    'example-service',
    'example-platform',
    'ops-dashboard',
]

pytestmark = pytest.mark.e2e


def test_tanstack_components_present_in_dtrack(dtrack_configured, latest_run_with_repos):
    """At least one @tanstack/* component must exist in DT for each of the
    five repos. Uses the most recent terminal run that covers them all."""
    body = fetch_dt_search('@tanstack')
    assert isinstance(body, dict), f'dtrack_search returned {body!r}'
    by_project = {p['name']: p['components'] for p in body.get('projects') or []}

    expected = [f'{ORG}/{r}' for r in REPOS_WITH_TANSTACK]
    missing = [name for name in expected if name not in by_project]

    if missing:
        # Build the diagnostic URL list per missing repo so the operator
        # can drill in immediately.
        run_state = latest_run_with_repos(REPOS_WITH_TANSTACK)
        run_id = run_state['run_id'] if run_state else '<no-run-found>'
        details = []
        for name in missing:
            repo = name.split('/', 1)[1]
            manifest_url = f'{BASE_URL}/api/runs/{run_id}/manifests'
            dt_url = f'{BASE_URL}/api/runs/{run_id}/repos/{ORG}/{repo}/dtrack-components'
            details.append(f'  {name}\n    manifests: {manifest_url}\n    dtrack:    {dt_url}')
        msg = (
            f'@tanstack components missing for {len(missing)} repo(s):\n'
            + '\n'.join(details)
            + f'\n\nFound @tanstack only in: {sorted(by_project.keys())}'
        )
        assert not missing, msg

    # Also pin a minimum sanity check: each project we matched should
    # have at least one component returned.
    for name in expected:
        comps = by_project.get(name, [])
        assert comps, (
            f'DT search for @tanstack matched project {name} but returned '
            f'an empty components list — likely a search-index inconsistency.'
        )


def test_tanstack_search_endpoint_rejects_empty_query(dtrack_configured):
    """The endpoint validates input — empty/missing q must 400."""
    qs = urllib.parse.urlencode({'q': ''})
    try:
        _status, _body = _request('GET', f'/api/dtrack/search?{qs}')
    except Exception as exc:
        # E2EError carries the HTTP code in its message.
        assert '400' in str(exc), (
            f'Empty query should 400, got: {exc}'
        )
    else:
        pytest.fail('Empty query should have returned HTTP 400')


def test_tanstack_search_endpoint_caps_long_query(dtrack_configured):
    """200-char-limit is enforced server-side (defence in depth)."""
    long_q = 'A' * 300
    qs = urllib.parse.urlencode({'q': long_q})
    try:
        _request('GET', f'/api/dtrack/search?{qs}')
    except Exception as exc:
        assert '400' in str(exc)
    else:
        pytest.fail('Over-long query should have returned HTTP 400')
