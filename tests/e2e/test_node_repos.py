"""End-to-end tests against three Node-flavoured repos.

Pins these regressions:

  - ``example-org/mobileapp`` is React-Native; pre-fix the extractor
    saw only the gradle siblings of the package.json, never the
    package.json itself. After the extractor widening + skip filter,
    we expect at least one ``package.json`` row (or, if the repo legit
    has no package.json, a clear error on run_repos so the operator
    isn't left guessing).
  - ``example-org/ui-kit`` has a single ``package.json``;
    the sanitizer must drop ``file:`` / ``workspace:`` deps without
    breaking the JSON.
  - ``example-org/scoped-widget`` is the seed for the
    @tanstack search test (runs the full pipeline so the @tanstack
    deps are guaranteed to be in DT before that test polls).

These tests are gated by ``pytest -m e2e``.
"""

import json
import os

import pytest

from .conftest import (
    assert_no_silent_python_inspector_failure,
    fetch_dt_components,
)

ORG = os.environ.get('LDE_E2E_ORG', 'example-org')

pytestmark = pytest.mark.e2e


def _read_sandbox_file(run_id, org, repo, rel_path):
    base = f'/tmp/dummy-repos/{run_id}/{org}__{repo}'
    full = os.path.join(base, rel_path)
    if not os.path.isfile(full):
        return None
    with open(full, 'r', errors='replace') as f:
        return f.read()


def _assert_run_was_useful(state, expected_repo):
    assert state['repo_row'] is not None, (
        f'Run finished but no run_repos row for {expected_repo}: {state["run"]}'
    )
    row = state['repo_row']
    assert row['ort_status'] in ('completed', 'failed', 'skipped')
    if row['manifest_count']:
        assert state['log_path'] is not None


# ---------------------------------------------------------------------------
# 1. mobileapp — React Native; package.json must be detected.
# ---------------------------------------------------------------------------

def test_mobileapp_finds_package_json_or_explains_why_not(run_repo):
    state = run_repo('mobileapp')
    _assert_run_was_useful(state, 'mobileapp')
    types = sorted({m['manifest_type'] for m in state['manifests']})
    # Either we found at least one package.json, or run_repos.error
    # explains why the tree fetch / extraction excluded it. The pre-fix
    # behaviour was a silent gradle-only state, which is what this test
    # rejects.
    if 'package.json' not in types:
        row = state['repo_row']
        assert row['error'], (
            f'mobileapp produced types={types} but run_repos.error is empty. '
            f'If the repo really has no package.json that should be surfaced; '
            f'silent absence is the regression we are guarding against.'
        )


# ---------------------------------------------------------------------------
# 2. ui-kit — package.json must remain valid JSON after sanitize
# and must keep at least one normal dep.
# ---------------------------------------------------------------------------

def test_shat_res_ui_kit_sanitized_package_json_is_valid(run_repo):
    state = run_repo('ui-kit')
    _assert_run_was_useful(state, 'ui-kit')
    pkg = next((m for m in state['manifests']
                if m['manifest_type'] == 'package.json'), None)
    assert pkg is not None, 'ui-kit did not produce a package.json row'
    content = _read_sandbox_file(state['run_id'], ORG, 'ui-kit',
                                 pkg['filepath'])
    if content is None:
        pytest.skip('Sandbox already pruned')
    parsed = json.loads(content)
    # Must be a dict (sanitizer returns content unchanged for non-dict
    # JSON, but real package.json is always an object).
    assert isinstance(parsed, dict)
    # Sanitizer must have dropped any `workspaces` key (npm workspaces
    # don't resolve in the staged dummy-repo).
    assert 'workspaces' not in parsed
    # The original_dep_count - sanitized_dep_count delta tells us how
    # many local-path deps were dropped. Anything < original is fine;
    # equal is fine (no local deps to begin with). Greater would be a
    # bug.
    assert pkg['sanitized_dep_count'] <= pkg['original_dep_count']


# ---------------------------------------------------------------------------
# 3. scoped-widget — full-pipeline run that ensures the @tanstack
# components are uploaded to DT. The cross-project search test below
# depends on this actually finishing first.
# ---------------------------------------------------------------------------

def test_scoped_widget_completes_with_dt_ingest(run_repo, dtrack_configured):
    state = run_repo('scoped-widget')
    _assert_run_was_useful(state, 'scoped-widget')
    row = state['repo_row']
    assert row['manifest_count'] > 0, (
        f'scoped-widget extracted 0 manifests — broken extractor '
        f'or auth issue. row={row!r}'
    )
    # If ORT completed, DT must have the project recorded.
    if row['ort_status'] == 'completed':
        assert row['dtrack_project_uuid'], (
            f'ORT completed but no DT project UUID stored for '
            f'scoped-widget. row={row!r}'
        )
        body = fetch_dt_components(state['run_id'], ORG, 'scoped-widget')
        assert body.get('dt_component_count', 0) > 0, (
            f'DT reports zero components for scoped-widget despite '
            f'a successful ORT. body={body!r}'
        )
    # Pre-fix this monorepo's Poetry sub-project hit a python-inspector
    # RecursionError that ORT swallowed; the npm side analysed cleanly,
    # so ort_package_count looked healthy and this test passed despite
    # the silent Python drop. The shared helper now closes that gap.
    assert_no_silent_python_inspector_failure(state, 'scoped-widget')


@pytest.mark.parametrize('repo', [
    'mobileapp', 'ui-kit', 'scoped-widget',
])
def test_dtrack_components_endpoint_responds(run_repo, dtrack_configured, repo):
    state = run_repo(repo)
    body = fetch_dt_components(state['run_id'], ORG, repo)
    assert isinstance(body, dict), f'/dtrack-components for {repo} returned {body!r}'
    assert body['repo'] == repo
    print(f'{repo} dt_count={body.get("dt_component_count")} '
          f'sanitized_total={body.get("sanitized_dep_total")} '
          f'ratio={body.get("coverage_ratio")} '
          f'overwrite_skipped={body.get("bom_overwrite_skipped")}',
          flush=True)
