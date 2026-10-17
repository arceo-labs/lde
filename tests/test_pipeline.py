"""Coverage for pipeline._finalize and pipeline._dedup_pip_manifest_dirs.

Regression cases:
- 2026-05-11: a run with all ORT=completed but DT ingestion 0% (permission
  error in DT) was incorrectly marked `completed` because the prior
  implementation only inspected ort_status.
"""

import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import cid_manager, db, ort_runner, pipeline  # noqa: E402


def _setup_db(monkeypatch, tmp_path):
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'pipeline_test.db'))
    db.init_db()


def _seed_run(run_id, orgs, repos):
    """Insert a run plus a list of repo rows.

    Each entry in *repos* is a dict with keys: org, repo, manifest_count,
    sanitize_status, ort_status, dtrack_project_uuid, error.
    """
    conn = db.get_db()
    try:
        conn.execute(
            'INSERT INTO runs (id, started_at, status, stage, orgs_json) '
            'VALUES (?, ?, ?, ?, ?)',
            (run_id, '2026-05-11T00:00:00', 'running', 'ingest', json.dumps(orgs)),
        )
        for r in repos:
            conn.execute(
                'INSERT INTO run_repos '
                '(run_id, org, repo, default_branch, manifest_count, '
                ' sanitize_status, ort_status, dtrack_project_uuid, error) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (run_id, r['org'], r['repo'], 'main', r.get('manifest_count', 1),
                 r.get('sanitize_status', 'completed'),
                 r['ort_status'], r.get('dtrack_project_uuid'), r.get('error')),
            )
        conn.commit()
    finally:
        conn.close()


def _read_run_status(run_id):
    conn = db.get_db()
    try:
        row = conn.execute('SELECT status, error FROM runs WHERE id = ?', (run_id,)).fetchone()
    finally:
        conn.close()
    return row['status'], row['error']


_INGEST_CONFIGURED = {'dtrack_url': 'http://localhost:8081', 'dtrack_api_key': 'key'}
_INGEST_DISABLED = {'dtrack_url': '', 'dtrack_api_key': ''}


def test_finalize_all_ort_and_ingest_ok(tmp_path, monkeypatch):
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r1', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'completed', 'dtrack_project_uuid': 'uuid-a'},
        {'org': 'o', 'repo': 'b', 'ort_status': 'completed', 'dtrack_project_uuid': 'uuid-b'},
    ])
    pipeline._finalize('r1', _INGEST_CONFIGURED)
    assert _read_run_status('r1') == ('completed', None)


def test_finalize_all_ingest_failed_when_ort_succeeded(tmp_path, monkeypatch):
    """The regression: 2026-05-11 run 329bb888."""
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r2', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'completed', 'dtrack_project_uuid': None},
        {'org': 'o', 'repo': 'b', 'ort_status': 'completed', 'dtrack_project_uuid': None},
        {'org': 'o', 'repo': 'c', 'ort_status': 'completed', 'dtrack_project_uuid': None},
    ])
    pipeline._finalize('r2', _INGEST_CONFIGURED)
    status, error = _read_run_status('r2')
    assert status == 'failed'
    assert 'ingest' in error.lower()


def test_finalize_partial_when_some_ingests_failed(tmp_path, monkeypatch):
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r3', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'completed', 'dtrack_project_uuid': 'uuid-a'},
        {'org': 'o', 'repo': 'b', 'ort_status': 'completed', 'dtrack_project_uuid': None},
    ])
    pipeline._finalize('r3', _INGEST_CONFIGURED)
    status, error = _read_run_status('r3')
    assert status == 'partial'
    assert '1 DT ingest failure' in error


def test_finalize_partial_when_some_ort_failed(tmp_path, monkeypatch):
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r4', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'completed', 'dtrack_project_uuid': 'uuid-a'},
        {'org': 'o', 'repo': 'b', 'ort_status': 'failed', 'error': 'ORT timed out'},
    ])
    pipeline._finalize('r4', _INGEST_CONFIGURED)
    status, error = _read_run_status('r4')
    assert status == 'partial'
    assert '1 ORT failure' in error


def test_finalize_ignores_dt_when_not_configured(tmp_path, monkeypatch):
    """Deliberately unconfigured DT should not mark a healthy ORT run as failed."""
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r5', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'completed', 'dtrack_project_uuid': None},
    ])
    pipeline._finalize('r5', _INGEST_DISABLED)
    assert _read_run_status('r5') == ('completed', None)


def test_finalize_skipped_only_repos_complete_with_note(tmp_path, monkeypatch):
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r6', ['o'], [
        {'org': 'o', 'repo': 'a', 'ort_status': 'skipped'},
        {'org': 'o', 'repo': 'b', 'ort_status': 'skipped'},
    ])
    pipeline._finalize('r6', _INGEST_CONFIGURED)
    status, error = _read_run_status('r6')
    assert status == 'completed'
    assert 'No repositories had supported manifests' in error


def test_finalize_no_repos_is_failed(tmp_path, monkeypatch):
    _setup_db(monkeypatch, tmp_path)
    _seed_run('r7', ['o'], [])
    pipeline._finalize('r7', _INGEST_CONFIGURED)
    status, error = _read_run_status('r7')
    assert status == 'failed'
    assert 'No repositories enumerated' in error


# ---------------------------------------------------------------------------
# _dedup_pip_manifest_dirs
# ---------------------------------------------------------------------------

def test_dedup_renames_conflicting_pip_dirs(tmp_path):
    """Two requirements.txt in same-named dirs get unique parent names."""
    for parent in ('lambda_a', 'lambda_b'):
        d = tmp_path / parent / 'event_handler'
        d.mkdir(parents=True)
        (d / 'requirements.txt').write_text(f'{parent}\n')

    renamed = pipeline._dedup_pip_manifest_dirs(str(tmp_path))

    assert renamed == 1
    req_files = list(tmp_path.rglob('requirements.txt'))
    assert len(req_files) == 2
    # One stays as event_handler, the other becomes event_handler_2
    dir_names = {f.parent.name for f in req_files}
    assert dir_names == {'event_handler', 'event_handler_2'}


def test_dedup_handles_three_conflicts(tmp_path):
    """Three same-named dirs produce _2 and _3 suffixes."""
    for letter in ('a', 'b', 'c'):
        d = tmp_path / f'svc_{letter}' / 'handler'
        d.mkdir(parents=True)
        (d / 'requirements.txt').write_text(f'{letter}\n')

    renamed = pipeline._dedup_pip_manifest_dirs(str(tmp_path))

    assert renamed == 2
    dir_names = {f.parent.name for f in tmp_path.rglob('requirements.txt')}
    assert dir_names == {'handler', 'handler_2', 'handler_3'}


def test_dedup_no_rename_when_names_unique(tmp_path):
    """No renames when all pip manifest parent dirs already have unique names."""
    for name in ('service_a', 'service_b'):
        d = tmp_path / name
        d.mkdir()
        (d / 'requirements.txt').write_text('boto3\n')

    renamed = pipeline._dedup_pip_manifest_dirs(str(tmp_path))

    assert renamed == 0


def test_dedup_matches_dev_requirements_txt(tmp_path):
    """dev_requirements.txt triggers the same dedup logic as requirements.txt."""
    for parent in ('x', 'y'):
        d = tmp_path / parent / 'dev'
        d.mkdir(parents=True)
        (d / 'dev_requirements.txt').write_text('pytest\n')

    renamed = pipeline._dedup_pip_manifest_dirs(str(tmp_path))

    assert renamed == 1
    dir_names = {f.parent.name for f in tmp_path.rglob('dev_requirements.txt')}
    assert dir_names == {'dev', 'dev_2'}


def test_dedup_preserves_file_contents(tmp_path):
    """Renamed directories retain their files unchanged."""
    d1 = tmp_path / 'svc_a' / 'app'
    d2 = tmp_path / 'svc_b' / 'app'
    d1.mkdir(parents=True)
    d2.mkdir(parents=True)
    (d1 / 'requirements.txt').write_text('flask==3.0.0\n')
    (d2 / 'requirements.txt').write_text('django==5.0.0\n')

    pipeline._dedup_pip_manifest_dirs(str(tmp_path))

    contents = {f.read_text() for f in tmp_path.rglob('requirements.txt')}
    assert contents == {'flask==3.0.0\n', 'django==5.0.0\n'}


# ---------------------------------------------------------------------------
# _classify_analyzer_log: turns ORT log fatal patterns into structured
# tokens so the UI / coverage rollup can flag a "completed" repo whose
# python-inspector silently dropped packages.
# ---------------------------------------------------------------------------

def test_classify_analyzer_log_returns_empty_for_clean_log(tmp_path):
    log = tmp_path / 'clean.log'
    log.write_text('Found 3 project(s) and 47 package(s) in total.\n')
    assert pipeline._classify_analyzer_log(str(log)) == set()


def test_classify_analyzer_log_detects_python_inspector_recursion(tmp_path):
    log = tmp_path / 'recurse.log'
    log.write_text(
        'Some preamble\n'
        '  File "resolution.py", line 763, in pdt_dfs\n'
        'RecursionError: maximum recursion depth exceeded\n'
    )
    assert pipeline._classify_analyzer_log(str(log)) == {'python_inspector_recursion'}


def test_classify_analyzer_log_detects_multiple_kinds(tmp_path):
    """A monorepo can hit several distinct analyzer issues in one run.
    The classifier must emit every match, not just the first one."""
    log = tmp_path / 'multi.log'
    log.write_text(
        "ERROR Pip - Unable to determine dependencies for definition file '/x'\n"
        'NPM: aliases must have a name\n'
        'RecursionError: maximum recursion depth exceeded\n'
    )
    assert pipeline._classify_analyzer_log(str(log)) == {
        'python_inspector_recursion',
        'python_resolver_failed',
        'npm_alias_unnamed',
    }


def test_classify_analyzer_log_swallows_missing_file(tmp_path):
    """Missing log must not crash the pipeline thread; return empty set
    so the surrounding ``_update_repo_status`` call still updates the
    rest of the row instead of leaving the repo in 'running'."""
    assert pipeline._classify_analyzer_log(str(tmp_path / 'no.log')) == set()


def test_classify_recognises_npm_workspace_alias_404(tmp_path):
    """``npm:*`` aliases in a Yarn workspace child cause prelock to ask
    for ``GET /*@*`` from the registry, which 404s. We surface this so
    the operator can fix the upstream package.json (or add an alias
    pre-process step)."""
    log = tmp_path / 'aliases.log'
    log.write_text("ERROR NPM: 404 The requested resource '*@*' could not be found\n")
    assert pipeline._classify_analyzer_log(str(log)) == {'npm_yarn_workspace_alias'}


def test_classify_recognises_readme_missing(tmp_path):
    """``setup.py`` that does ``open('README').read()`` raises
    FileNotFoundError when only README.md is present; tag it so the
    mocker can grow a heuristic later."""
    log = tmp_path / 'readme.log'
    log.write_text(
        "FileNotFoundError: [Errno 2] No such file or directory: '/project/README'\n"
    )
    assert pipeline._classify_analyzer_log(str(log)) == {'readme_missing'}


# ---------------------------------------------------------------------------
# _stage_ort: concurrency and stop propagation
# ---------------------------------------------------------------------------

_ORT_SETTINGS = {
    'ort_image': 'ort:test',
    'ort_egress_network': 'none',
    'ort_max_workers': 2,
    '_npm_cache_url_resolved': None,
    '_pypi_cache_url_resolved': None,
    '_athens_url_resolved': None,
    'dtrack_url': '',
    'dtrack_api_key': '',
}


def _make_entries(tmp_path, repos):
    """Create sandbox dirs and return extracted entries for _stage_ort."""
    entries = []
    for org, repo in repos:
        sandbox = tmp_path / f'{org}__{repo}'
        sandbox.mkdir(parents=True, exist_ok=True)
        entries.append({
            'org': org,
            'repo': repo,
            'manifests': ['package.json'],
            'sandbox_dir': str(sandbox),
        })
    return entries


def test_stage_ort_processes_all_repos(tmp_path, monkeypatch):
    """All repos in extracted are analysed and appear in the returned bom_paths."""
    _setup_db(monkeypatch, tmp_path)
    repos = [('o', 'a'), ('o', 'b'), ('o', 'c')]
    _seed_run('ort1', ['o'], [
        {'org': o, 'repo': r, 'ort_status': 'pending'} for o, r in repos
    ])
    extracted = _make_entries(tmp_path, repos)

    def fake_analyze(sandbox_dir, *args, **kwargs):
        bom = os.path.join(sandbox_dir, 'bom.json')
        open(bom, 'w').close()
        return bom

    monkeypatch.setattr(ort_runner, 'analyze', fake_analyze)

    bom_paths = pipeline._stage_ort('ort1', extracted, dict(_ORT_SETTINGS))

    assert set(bom_paths.keys()) == {('o', 'a'), ('o', 'b'), ('o', 'c')}


def test_stage_ort_stop_cancels_remaining(tmp_path, monkeypatch):
    """StopRequested propagates out of _stage_ort when stop is requested mid-run."""
    _setup_db(monkeypatch, tmp_path)
    repos = [('o', 'a'), ('o', 'b'), ('o', 'c')]
    _seed_run('ort2', ['o'], [
        {'org': o, 'repo': r, 'ort_status': 'pending'} for o, r in repos
    ])
    extracted = _make_entries(tmp_path, repos)

    # The first call to analyze triggers a stop; subsequent calls just produce a BOM.
    _stop_triggered = threading.Event()

    def fake_analyze(sandbox_dir, *args, **kwargs):
        if not _stop_triggered.is_set():
            _stop_triggered.set()
            pipeline.request_stop('ort2')
        bom = os.path.join(sandbox_dir, 'bom.json')
        open(bom, 'w').close()
        return bom

    # Suppress the Docker kill call — no real containers are running in tests.
    monkeypatch.setattr(cid_manager, 'kill_all', lambda run_id: 0)
    monkeypatch.setattr(ort_runner, 'analyze', fake_analyze)

    # ort_max_workers=1 keeps execution serial so the stop fires before
    # the second repo is submitted, making the cancellation deterministic.
    settings = dict(_ORT_SETTINGS, ort_max_workers=1)
    with pytest.raises(pipeline.StopRequested):
        pipeline._stage_ort('ort2', extracted, settings)
