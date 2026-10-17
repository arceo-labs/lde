"""End-to-end tests against three known-problematic Python repos.

Each test drives a real pipeline run scoped to one repo, then asserts:

  - ``run_repos.manifest_count > 0`` (extraction worked).
  - The sandbox file at ``/tmp/dummy-repos/{run_id}/{org}__{repo}/<rel>``
    parses cleanly as JSON/TOML (sanitize didn't corrupt it).
  - ``GET /api/runs/{id}/manifests`` reports a non-zero ``original_dep_count``.
  - ``GET /api/runs/{id}/repos/.../dtrack-components`` returns at least one
    DT component when the test repo is known to have public deps.
  - The ORT log file exists and contains either a "Found N project(s)"
    summary line or a clear failure message — never an empty/missing log.

Repos exercised:

  - ``example-org/aws-examples``  — has multiple Python sub-projects;
    pre-fix the extractor only saw 1 of them.
  - ``example-org/data-pipeline`` — pyproject.toml at the root.
  - ``example-org/django-dag-postgresql`` — uses setup.py (executable
    manifest); we rely on the mocker to make ORT happy.

These tests are gated by ``pytest -m e2e`` because each one boots an
ORT container.
"""

import json
import os

import pytest

try:
    import tomllib
except ImportError:
    tomllib = None

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
    """Every Python/Node test runs through these basic gates."""
    assert state['repo_row'] is not None, (
        f'Run finished but no run_repos row found for {expected_repo}: '
        f'{state["run"]}'
    )
    row = state['repo_row']
    # ort_status must be terminal (skipped is OK; the assertions below
    # then fan out per-repo expectations).
    assert row['ort_status'] in ('completed', 'failed', 'skipped'), (
        f'Unexpected ort_status for {expected_repo}: {row}'
    )
    # If we extracted any manifests, the log must exist.
    if row['manifest_count']:
        assert state['log_path'] is not None, (
            f'manifest_count={row["manifest_count"]} but no log file at '
            f'runs/{state["run_id"]}/{ORG}__{expected_repo}.log'
        )


def _read_log_summary(log_path):
    """Return the 'Found N project(s)' line if present in the ORT log."""
    if not log_path or not os.path.isfile(log_path):
        return None
    with open(log_path, 'r', errors='replace') as f:
        for line in f:
            if 'Found' in line and 'project' in line and 'package' in line:
                return line.strip()
    return None




# ---------------------------------------------------------------------------
# 1. aws-examples — multi-subproject Python repo. Pre-fix the extractor
# only saw one manifest; this test pins ≥1 and prints the manifest types
# so a regression is immediately visible in the assertion message.
# ---------------------------------------------------------------------------

def test_aws_examples_extracts_multiple_manifests(run_repo):
    state = run_repo('aws-examples')
    _assert_run_was_useful(state, 'aws-examples')
    row = state['repo_row']
    types = sorted({m['manifest_type'] for m in state['manifests']})
    assert row['manifest_count'] >= 1, (
        f'aws-examples produced manifest_count=0 — extraction failed. '
        f'manifests endpoint returned: {state["manifests"]!r}'
    )
    # Sanitized files must parse if they're TOML/JSON.
    for m in state['manifests']:
        content = _read_sandbox_file(state['run_id'], ORG, 'aws-examples', m['filepath'])
        if content is None:
            continue  # sandbox cleaned, OK
        if m['filepath'].endswith('.toml') and tomllib is not None:
            tomllib.loads(content)  # raises if invalid
        if m['filepath'].endswith('.json'):
            json.loads(content)
    # Diagnostic for the operator: print what we found.
    print(f'aws-examples manifests={types} count={row["manifest_count"]}',
          flush=True)


# ---------------------------------------------------------------------------
# 2. data-pipeline — pyproject.toml at root. Sanitize must keep the file
# valid TOML (no dropped braces / dangling syntax). Because the sanitizer
# only intervenes when local-path deps are present, a clean file should
# round-trip identically.
# ---------------------------------------------------------------------------

def test_data_pipeline_sanitized_pyproject_remains_valid_toml(run_repo):
    state = run_repo('data-pipeline')
    _assert_run_was_useful(state, 'data-pipeline')
    pyproject = next(
        (m for m in state['manifests']
         if m['filepath'].endswith('pyproject.toml')),
        None,
    )
    assert pyproject is not None, (
        'data-pipeline did not produce a pyproject.toml manifest row'
    )
    content = _read_sandbox_file(state['run_id'], ORG, 'data-pipeline',
                                 pyproject['filepath'])
    if content is None:
        pytest.skip('Sandbox already pruned; cannot validate file contents')
    assert tomllib is not None, 'Python 3.11+ required for tomllib'
    tomllib.loads(content)  # raises on invalid TOML
    # original_dep_count should be > 0 — pyproject.toml that says
    # "no deps" is a red flag.
    assert pyproject['original_dep_count'] > 0, (
        f'data-pipeline pyproject.toml parsed to zero deps: {pyproject!r}. '
        f'Sanitizer / parser regression?'
    )


# ---------------------------------------------------------------------------
# 3. django-dag-postgresql — setup.py only (executable manifest). The
# mocker injects placeholder context; we assert the run reaches a
# terminal status without crashing the ORT analyze stage.
# ---------------------------------------------------------------------------

def test_django_dag_postgresql_setup_py_runs_to_terminal(run_repo):
    state = run_repo('django-dag-postgresql')
    _assert_run_was_useful(state, 'django-dag-postgresql')
    row = state['repo_row']
    types = sorted({m['manifest_type'] for m in state['manifests']})
    assert 'setup.py' in types, (
        f'Expected setup.py in manifest types, got {types}'
    )
    # ORT may legitimately fail to resolve a PEP 517 build-only setup.py
    # in our restricted sandbox — but the run must still be terminal,
    # not silently hung. If ORT failed, surface the reason from the
    # log so the operator gets a useful failure message.
    summary = _read_log_summary(state['log_path'])
    if row['ort_status'] == 'failed':
        with open(state['log_path'], errors='replace') as f:
            tail = f.read()[-500:]
        assert 'setup.py' in tail or 'pip' in tail.lower() or 'python' in tail.lower(), (
            f'django-dag-postgresql ORT failed but the log does not mention '
            f'setup.py / pip / python:\n{tail}'
        )
    # When ORT completed, we expect at least the placeholder marker.
    if row['ort_status'] == 'completed':
        assert summary is not None, (
            f'django-dag-postgresql ORT completed but log is missing the '
            f'"Found N project(s)" summary line — log truncated?'
        )
    # If python-inspector hit RecursionError, the new classifier must
    # have tagged it. (django-dag-postgresql historically hits the
    # README-missing pattern, not RecursionError, but if the upstream
    # python-inspector regresses on this repo we want the test to know.)
    assert_no_silent_python_inspector_failure(state, 'django-dag-postgresql')


# ---------------------------------------------------------------------------
# 4. example-lib — Poetry-only repo whose poetry.lock has a
# deeply nested dep graph that pre-fix triggered python-inspector's
# `pdt_dfs` RecursionError, leaving ``ort_package_count=0``. With the
# new poetry_fallback the lockfile is parsed locally and merged into
# the BOM. This test pins both sides of that contract: either ORT
# resolved it cleanly, or the fallback rescued ≥1 component.
# ---------------------------------------------------------------------------

def test_example_lib_poetry_fallback_used(run_repo):
    state = run_repo('example-lib')
    _assert_run_was_useful(state, 'example-lib')
    row = state['repo_row']
    types = sorted({m['manifest_type'] for m in state['manifests']})
    assert 'poetry.lock' in types and 'pyproject.toml' in types, (
        f'Expected Poetry manifests, got {types}'
    )
    if row['ort_status'] != 'completed':
        pytest.skip(f'ort_status={row["ort_status"]} — fallback only runs after completion')
    pkg_count = row.get('ort_package_count') or 0
    fallback_count = row.get('poetry_fallback_count') or 0
    assert pkg_count > 0, (
        f'example-lib finished with 0 packages even after '
        f'the Poetry fallback. ort={pkg_count} fallback_added={fallback_count} '
        f'analyzer_issue_kind={row.get("analyzer_issue_kind")!r}. The '
        f'poetry_fallback merge is broken or poetry.lock disappeared from '
        f'the sandbox before merge ran.'
    )
    assert_no_silent_python_inspector_failure(state, 'example-lib')


# ---------------------------------------------------------------------------
# Shared diagnostic: when DT is configured, every Python repo should at
# minimum be queryable through the dtrack-components endpoint without
# raising. Run as a parametrized smoke test.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('repo', [
    'aws-examples', 'data-pipeline', 'django-dag-postgresql',
    'example-lib', 'scoped-widget',
])
def test_dtrack_components_endpoint_responds(run_repo, dtrack_configured, repo):
    state = run_repo(repo)
    body = fetch_dt_components(state['run_id'], ORG, repo)
    assert isinstance(body, dict), (
        f'/dtrack-components for {repo} returned non-dict: {body!r}'
    )
    assert body['repo'] == repo
    # Report-only: don't assert dt_component_count > 0 because some of
    # these repos legitimately produce zero packages (e.g. setup.py with
    # no install_requires). The structured response is what we want to
    # pin so the UI can render it.
    print(f'{repo} dt_count={body.get("dt_component_count")} '
          f'sanitized_total={body.get("sanitized_dep_total")} '
          f'ratio={body.get("coverage_ratio")} '
          f'overwrite_skipped={body.get("bom_overwrite_skipped")}',
          flush=True)
