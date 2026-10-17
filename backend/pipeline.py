"""End-to-end pipeline orchestrator.

Stages: extract → sanitize → mock → ort → ingest.

Each stage updates the `runs.stage` column and per-repo status rows so the
UI can poll progress. Runs can be stopped mid-flight (request_stop), resumed
from where they stopped/failed (run_pipeline with resume=True), or restarted
from scratch (server.py creates a fresh run_id and calls start_in_background).
"""

import json
import os
import re
import shutil
import threading
import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

_SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# When LDE_DATA_DIR is set (EFS mount on Fargate), run logs live there so
# they survive container restarts.
_DATA_DIR = os.environ.get('LDE_DATA_DIR', '').strip() or _SERVE_DIR

from . import (
    bom_cache,
    cid_manager,
    db,
    dtrack_client,
    extractor,
    github_client,
    github_sbom,
    mocker,
    ort_runner,
    poetry_fallback,
    prelock,
    sandbox,
    sanitizer,
    settings as settings_mod,
    log as log_mod,
)

logger = log_mod.get('pipeline')


# ---------------------------------------------------------------------------
# Stop-event registry: every active run gets a threading.Event the HTTP layer
# can set to signal cancellation. The pipeline thread polls it at each stage
# boundary and between repos inside the ORT stage.
# ---------------------------------------------------------------------------

_stop_events = {}
_stop_events_lock = threading.Lock()


class StopRequested(Exception):
    """Raised by _check_stop when the run's stop event has been set."""


def request_stop(run_id):
    """Signal the pipeline thread AND kill any in-flight docker containers.

    Without the docker-kill step, a stop request can only take effect at
    stage boundaries — a blocked subprocess.run inside ort_runner /
    prelock would otherwise hold for the full per-call timeout.
    """
    with _stop_events_lock:
        ev = _stop_events.get(run_id)
        if ev is None:
            ev = threading.Event()
            _stop_events[run_id] = ev
        ev.set()
    try:
        killed = cid_manager.kill_all(run_id)
        if killed:
            logger.info('run=%s stop: killed %d in-flight container(s)', run_id, killed)
    except Exception as exc:
        logger.warning('run=%s stop: cid_manager.kill_all raised: %s',
                       run_id, log_mod.safe(exc))


def _reset_stop_event(run_id):
    with _stop_events_lock:
        _stop_events[run_id] = threading.Event()


def _check_stop(run_id):
    with _stop_events_lock:
        ev = _stop_events.get(run_id)
    if ev is not None and ev.is_set():
        raise StopRequested()


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _set_run_stage(run_id, stage, status=None, error=None):
    conn = db.get_db()
    try:
        if status is None:
            conn.execute('UPDATE runs SET stage = ? WHERE id = ?', (stage, run_id))
        else:
            conn.execute(
                'UPDATE runs SET stage = ?, status = ?, error = ? WHERE id = ?',
                (stage, status, error, run_id),
            )
        conn.commit()
    finally:
        conn.close()


def _update_repo_status(run_id, org, repo, **fields):
    if not fields:
        return
    sets = ', '.join(f'{k} = ?' for k in fields)
    params = list(fields.values()) + [run_id, org, repo]
    conn = db.get_db()
    try:
        conn.execute(
            f'UPDATE run_repos SET {sets} WHERE run_id = ? AND org = ? AND repo = ?',
            params,
        )
        conn.commit()
    finally:
        conn.close()


def _clear_run_for_resume(run_id):
    """Reset run-level error/completion fields when resuming. Per-repo state
    is preserved so we can skip already-completed repos."""
    conn = db.get_db()
    try:
        conn.execute(
            'UPDATE runs SET status = ?, stage = ?, error = NULL, completed_at = NULL WHERE id = ?',
            ('running', 'resume', run_id),
        )
        conn.commit()
    finally:
        conn.close()


def _rebuild_extracted_from_db(run_id, sandbox_root):
    """Reconstruct the extractor's `extracted` list from DB rows so resume
    can skip the extract stage when the sandbox is still intact."""
    extracted = []
    conn = db.get_db()
    try:
        repos = conn.execute(
            'SELECT org, repo, default_branch FROM run_repos WHERE run_id = ? ORDER BY org, repo',
            (run_id,),
        ).fetchall()
        for r in repos:
            manifests = [m['filepath'] for m in conn.execute(
                'SELECT filepath FROM manifests WHERE run_id = ? AND org = ? AND repo = ? ORDER BY filepath',
                (run_id, r['org'], r['repo']),
            )]
            extracted.append({
                'org': r['org'],
                'repo': r['repo'],
                'default_branch': r['default_branch'],
                'sandbox_dir': os.path.join(sandbox_root, f'{r["org"]}__{r["repo"]}'),
                'manifests': manifests,
            })
    finally:
        conn.close()
    return extracted


# ---------------------------------------------------------------------------
# Branch resolution
# ---------------------------------------------------------------------------

def _resolve_branch(org, repo, run_branch, default_branch):
    """Pick the branch to analyze for *org/repo*.

    Precedence: explicit run-form branch > the repo's GitHub default branch.
    Returns the resolved branch name (may be None only when *default_branch*
    itself is unknown).
    """
    if run_branch:
        return run_branch
    return default_branch


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

def _stage_extract(run_id, orgs, sandbox_root, repo_filter=None, run_branch=None):
    extracted = []
    for org in orgs:
        _check_stop(run_id)
        repos = extractor.extract_org(run_id, org, sandbox_root,
                                      repo_filter=repo_filter, run_branch=run_branch)
        for entry in repos:
            entry['org'] = org
            extracted.append(entry)
    return extracted


def _stage_sanitize(run_id, extracted):
    for entry in extracted:
        _check_stop(run_id)
        org, repo = entry['org'], entry['repo']
        any_modified = False
        unparseable = 0
        for rel_path in entry['manifests']:
            full = os.path.join(entry['sandbox_dir'], rel_path)
            try:
                with open(full, 'r') as f:
                    content = f.read()
            except OSError:
                continue
            # One malformed manifest in one repo should NOT kill the
            # whole sanitize stage for all the other repos. Catch and
            # leave the file as-is — ORT will then either parse it (if
            # it's more permissive than us) or fail on that specific
            # file with its own error message.
            try:
                new_content, modified = sanitizer.sanitize(rel_path, content)
            except (ValueError, TypeError, KeyError) as exc:
                unparseable += 1
                logger.warning(
                    'run=%s sanitize: %s/%s %s unparseable (%s) — '
                    'leaving file as-is for ORT',
                    run_id, log_mod.safe(org), log_mod.safe(repo),
                    log_mod.safe(rel_path), log_mod.safe(exc),
                )
                continue
            except Exception as exc:
                # Unexpected — log with traceback so we can investigate later.
                unparseable += 1
                logger.exception(
                    'run=%s sanitize: %s/%s %s raised unexpected %s — '
                    'leaving file as-is',
                    run_id, log_mod.safe(org), log_mod.safe(repo),
                    log_mod.safe(rel_path), type(exc).__name__,
                )
                continue
            if modified:
                with open(full, 'w') as f:
                    f.write(new_content)
                any_modified = True
                conn = db.get_db()
                try:
                    conn.execute(
                        'UPDATE manifests SET sanitized = 1 '
                        'WHERE run_id=? AND org=? AND repo=? AND filepath=?',
                        (run_id, org, repo, rel_path),
                    )
                    conn.commit()
                finally:
                    conn.close()
        status = 'completed' if any_modified or entry['manifests'] else 'skipped'
        error_field = f'{unparseable} unparseable manifest(s)' if unparseable else None
        _update_repo_status(run_id, org, repo,
                            sanitize_status=status, error=error_field)


_PIP_MANIFEST_NAMES = frozenset({
    'requirements.txt', 'dev_requirements.txt', 'Pipfile', 'Pipfile.lock',
})
_PIP_DEDUP_SKIP = frozenset({'node_modules', '.git', 'ort-output', '__pycache__'})


def _dedup_pip_manifest_dirs(sandbox_dir):
    """Rename pip manifest parent dirs to avoid ORT duplicate-project-ID errors.

    ORT derives the PIP project name from the parent directory of
    requirements.txt (and similar). When two such files share a parent-dir
    basename (e.g. payments-pipeline/.../event_handler/ and
    o365-logs/.../event_handler/), ORT silently drops one. This function
    renames the duplicates to <name>_2, <name>_3, etc.

    Returns the number of directories renamed.
    """
    groups = defaultdict(list)
    for root, dirs, files in os.walk(sandbox_dir):
        dirs[:] = [d for d in dirs if d not in _PIP_DEDUP_SKIP]
        if _PIP_MANIFEST_NAMES & set(files):
            groups[os.path.basename(root)].append(root)

    renamed = 0
    for basename, dir_paths in groups.items():
        if len(dir_paths) <= 1:
            continue
        for i, src in enumerate(dir_paths[1:], 2):
            parent = os.path.dirname(src)
            dst = os.path.join(parent, f'{basename}_{i}')
            while os.path.exists(dst):
                i += 1
                dst = os.path.join(parent, f'{basename}_{i}')
            shutil.move(src, dst)
            renamed += 1

    return renamed


def _stage_mock(run_id, extracted):
    for entry in extracted:
        _check_stop(run_id)
        org, repo = entry['org'], entry['repo']
        basenames = {p.rsplit('/', 1)[-1] for p in entry['manifests']}
        mocker.mock(entry['sandbox_dir'], basenames)
        n = _dedup_pip_manifest_dirs(entry['sandbox_dir'])
        if n:
            logger.info('run=%s mock: %s/%s renamed %d pip manifest dir(s) to avoid ORT project-ID collision',
                        run_id, log_mod.safe(org), log_mod.safe(repo), n)


def _probe_cache(probe_url, runtime_url, name):
    """Generic 3s HEAD-probe for a caching-proxy service.

    Returns *runtime_url* on success or None when the service is
    unreachable from the orchestrator (host) side.
    """
    if not runtime_url:
        return None
    if not probe_url:
        probe_url = runtime_url
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(probe_url.rstrip('/') + '/', method='HEAD')
        urllib.request.urlopen(req, timeout=3)
        logger.info('%s reachable at %s — pipeline will route through it',
                    name, log_mod.safe(runtime_url))
        return runtime_url
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
        logger.warning(
            '%s probe %s failed (%s) — falling back to direct upstream for this run. '
            'Bring it up with: docker compose up -d %s',
            name, log_mod.safe(probe_url), log_mod.safe(exc), name,
        )
        return None


def _check_pypi_cache_reachable(settings):
    return _probe_cache(
        settings.get('pypi_cache_probe_url'),
        settings.get('pypi_cache_url'),
        'pypi-cache',
    )


def _check_athens_reachable(settings):
    return _probe_cache(
        settings.get('athens_probe_url'),
        settings.get('athens_url'),
        'athens',
    )


def _check_npm_cache_reachable(settings):
    """Detect whether the configured npm-cache service is up.

    The runtime URL (`npm_cache_url`) uses a docker-internal hostname
    like `npm-cache:9999` which is only resolvable from containers on
    the `ort-egress` network. The orchestrator lives on the host, so it
    probes via `npm_cache_probe_url` (defaults to a loopback port the
    compose service exposes for exactly this purpose).

    Returns the runtime URL on success or None when the service is
    unreachable, in which case ORT/prelock fall back to direct
    registry.npmjs.org for this run.
    """
    runtime_url = settings.get('npm_cache_url')
    if not runtime_url:
        return None
    probe_url = settings.get('npm_cache_probe_url') or runtime_url
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(probe_url.rstrip('/') + '/', method='HEAD')
        urllib.request.urlopen(req, timeout=3)
        logger.info('npm-cache reachable at %s — npm CLI will route through it',
                    log_mod.safe(runtime_url))
        return runtime_url
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
        logger.warning(
            'npm-cache probe %s failed (%s) — falling back to direct '
            'registry.npmjs.org for this run. Bring it up with: '
            'docker compose up -d npm-cache',
            log_mod.safe(probe_url), log_mod.safe(exc),
        )
        return None


def _prelock_one_repo(run_id, entry, image, network, cache_dir, npm_cache_url, logs_dir):
    """Run npm prelock for a single repo inside a Docker container.

    Called concurrently by _stage_prelock via ThreadPoolExecutor.
    Re-raises StopRequested so the coordinator thread sees it via fut.result().
    """
    org, repo = entry['org'], entry['repo']
    log_path = os.path.join(logs_dir, f'{org}__{repo}.prelock.log')
    try:
        generated, skipped, failed = prelock.generate_lockfiles_for_repo(
            entry['sandbox_dir'], image, network, log_path,
            check_stop=lambda: _check_stop(run_id),
            cache_dir=cache_dir,
            run_id=run_id,
            npm_cache_url=npm_cache_url,
        )
        logger.info('run=%s prelock %s/%s generated=%d skipped=%d failed=%d',
                    run_id, log_mod.safe(org), log_mod.safe(repo),
                    generated, skipped, failed)
    except StopRequested:
        raise
    except Exception as exc:
        logger.warning('run=%s prelock %s/%s aborted: %s',
                       run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))


def _stage_prelock(run_id, extracted, settings, resume=False):
    """Pre-generate npm lockfiles so ORT can use fast static resolution.

    This runs `npm install --package-lock-only` inside the same ORT image
    for each package.json found in each repo's sandbox. Idempotent — skips
    dirs that already have a lockfile.  Repos are processed in parallel up to
    ``settings['ort_max_workers']`` concurrent Docker containers.

    When *resume* is True, repos whose ``ort_status='completed'`` are skipped
    (their lockfile was already consumed by ORT and the sandbox may be stale).
    """
    if not settings.get('prelock_enabled', True):
        logger.info('run=%s prelock disabled in settings', run_id)
        return
    image = settings['ort_image']
    network = settings['ort_egress_network']
    cache_dir = settings.get('ort_cache_dir') or None
    # Preflight the npm-cache; if it's down, blank out the URL so
    # downstream containers don't hang on DNS for a service that isn't
    # there. We stash the resolved value on settings so _stage_ort picks
    # up the same answer without re-probing.
    settings['_npm_cache_url_resolved'] = _check_npm_cache_reachable(settings)
    settings['_pypi_cache_url_resolved'] = _check_pypi_cache_reachable(settings)
    settings['_athens_url_resolved'] = _check_athens_reachable(settings)
    npm_cache_url = settings['_npm_cache_url_resolved']
    logs_dir = os.path.join(_DATA_DIR,
                            'runs', run_id)
    os.makedirs(logs_dir, exist_ok=True)

    already_done = set()
    if resume:
        conn = db.get_db()
        try:
            for r in conn.execute(
                'SELECT org, repo FROM run_repos WHERE run_id = ? AND ort_status = ?',
                (run_id, 'completed'),
            ):
                already_done.add((r['org'], r['repo']))
        finally:
            conn.close()
        if already_done:
            logger.info('run=%s prelock resume: skipping %d already-completed repo(s)',
                        run_id, len(already_done))

    npm_entries = [
        e for e in extracted
        if any(p.endswith('package.json') for p in e['manifests'])
        and (e['org'], e['repo']) not in already_done
    ]
    if not npm_entries:
        return

    workers = min(settings.get('ort_max_workers', 4), len(npm_entries))
    logger.info('run=%s prelock: %d repo(s) with package.json, %d worker(s)',
                run_id, len(npm_entries), workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_prelock_one_repo, run_id, entry, image, network,
                        cache_dir, npm_cache_url, logs_dir): entry
            for entry in npm_entries
        }
        for fut in as_completed(futures):
            try:
                _check_stop(run_id)
            except StopRequested:
                for f in futures:
                    f.cancel()
                raise
            try:
                fut.result()
            except StopRequested:
                for f in futures:
                    f.cancel()
                raise


def _find_existing_bom(sandbox_dir):
    """Look for a CycloneDX file from a prior ORT run inside this sandbox."""
    output_dir = os.path.join(sandbox_dir, 'ort-output')
    if not os.path.isdir(output_dir):
        return None
    for fn in os.listdir(output_dir):
        if fn.endswith(('.cyclonedx.json', '.cyclonedx.xml')):
            return os.path.join(output_dir, fn)
    return None


_ORT_PKG_COUNT_RE = re.compile(
    r'Found \d+ project\(s\) and (\d+) package\(s\) in total'
)


def _parse_ort_package_count(log_path):
    """Extract resolved package count from an ORT log file, or None if not found."""
    try:
        with open(log_path, 'r', errors='replace') as f:
            content = f.read()
    except OSError:
        return None
    m = _ORT_PKG_COUNT_RE.search(content)
    return int(m.group(1)) if m else None


# Patterns that indicate an ORT analyzer "completed" but silently dropped
# packages — listed in classify-priority order. The first pattern that
# matches per category wins; each repo can be tagged with multiple kinds
# (e.g. NPM 404 plus python-inspector recursion in the same monorepo).
#
# Tokens are persisted to run_repos.analyzer_issue_kind as a
# semicolon-delimited string. Keep them short and stable; the UI keys off
# them as CSS class names.
_ANALYZER_LOG_PATTERNS = (
    ('python_inspector_recursion',
     re.compile(r'RecursionError: maximum recursion depth')),
    ('python_resolver_failed',
     re.compile(r'Unable to determine dependencies for definition file')),
    ('npm_yarn_workspace_alias',
     re.compile(r"NPM: 404.*'\*@\*'")),
    ('npm_alias_unnamed',
     re.compile(r'NPM: aliases must have a name')),
    ('npm_version_not_found',
     re.compile(r'No matching version found for ')),
    ('package_json_malformed',
     re.compile(r'EJSONPARSE.*Bad control character')),
    ('no_definition_files',
     re.compile(r'No definition files found')),
    ('readme_missing',
     re.compile(r"FileNotFoundError.*'/project/README'")),
)


def _classify_analyzer_log(log_path):
    """Scan an ORT log and return the set of fatal-pattern kinds it contains.

    The set is empty when the log is healthy. Caller persists the joined
    tokens on ``run_repos.analyzer_issue_kind`` so the UI / coverage
    rollup can flag the repo even though ORT exited 0.

    Returns an empty set on read errors — the existing ``_parse_ort_package_count``
    already swallows those, and we'd rather under-tag than spuriously alarm.
    """
    try:
        with open(log_path, 'r', errors='replace') as fh:
            content = fh.read()
    except OSError:
        return set()
    issues = set()
    for kind, pattern in _ANALYZER_LOG_PATTERNS:
        if pattern.search(content):
            issues.add(kind)
    return issues


def _find_poetry_locks(sandbox_dir):
    """Locate every ``poetry.lock`` under *sandbox_dir* (depth-limited)."""
    locks = []
    skip = {'node_modules', '.git', 'vendor', '.venv', 'venv', '__pycache__',
            'ort-output'}
    for root, dirs, files in os.walk(sandbox_dir):
        dirs[:] = [d for d in dirs if d not in skip]
        if 'poetry.lock' in files:
            locks.append(os.path.join(root, 'poetry.lock'))
    return locks


def _maybe_run_poetry_fallback(run_id, org, repo, sandbox_dir, bom_path,
                                analyzer_issues):
    """Merge poetry.lock components into ``bom_path`` when ORT failed Python.

    Triggered only for the two analyzer-issue kinds that specifically
    indicate python-inspector dropped packages on the floor. Other kinds
    (npm 404 etc.) have their own prelock/mocker fixes — the Poetry
    fallback would be noise there.

    Returns the number of components added, or 0 if no fallback was run.
    """
    triggers = {'python_inspector_recursion', 'python_resolver_failed'}
    if not (analyzer_issues & triggers):
        return 0
    locks = _find_poetry_locks(sandbox_dir)
    if not locks:
        return 0
    if not os.path.isfile(bom_path):
        # Nothing to merge into; ORT didn't produce a BOM at all.
        return 0
    total_added = 0
    for lock_path in locks:
        try:
            components = poetry_fallback.parse_poetry_lock(lock_path)
        except poetry_fallback.PoetryFallbackError as exc:
            logger.warning(
                'run=%s %s/%s poetry_fallback skip %s: %s',
                run_id, log_mod.safe(org), log_mod.safe(repo),
                log_mod.safe(os.path.relpath(lock_path, sandbox_dir)),
                log_mod.safe(exc),
            )
            continue
        if not components:
            continue
        try:
            added, _ = poetry_fallback.merge_components_into_bom(bom_path, components)
        except poetry_fallback.PoetryFallbackError as exc:
            logger.warning(
                'run=%s %s/%s poetry_fallback merge failed for %s: %s',
                run_id, log_mod.safe(org), log_mod.safe(repo),
                log_mod.safe(os.path.relpath(lock_path, sandbox_dir)),
                log_mod.safe(exc),
            )
            continue
        total_added += added
        logger.info(
            'run=%s %s/%s poetry_fallback merged %d component(s) from %s',
            run_id, log_mod.safe(org), log_mod.safe(repo), added,
            log_mod.safe(os.path.relpath(lock_path, sandbox_dir)),
        )
    return total_added


def _ingest_one_repo(run_id, org, repo, bom_path, settings, branch=None,
                     is_default=True):
    """Upload one CycloneDX BOM to Dependency-Track via safe_upload_bom.

    Inlined into _stage_ort so each repo's BOM lands in DT as soon as its
    analyze + report finish, rather than waiting for every repo to complete
    before the batched ingest fires.

    The DT *project version* is the analyzed branch (``branch``); each branch
    of a repo therefore becomes a sibling version of the same DT project. When
    ``is_default`` is true the upload is also marked ``isLatest`` so DT's
    "outdated component" analysis baselines against the default branch.

    safe_upload_bom enforces an *empty-BOM guard*: if this run produced
    a zero-component BOM AND DT already has a healthy project for
    ``{org}/{repo}@{branch}``, the upload is refused so the prior good
    project isn't clobbered. The pipeline records the reason on
    run_repos.error and run_repos.bom_overwrite_skipped=1; the run
    continues. A regression guard (>50% drop) lets the upload through
    but flags it for the operator.

    Returns the DT project UUID (or the `'auto-created'` sentinel) on
    success, None when DT isn't configured or the upload was refused.
    """
    base_url = settings.get('dtrack_url')
    api_key = settings.get('dtrack_api_key')
    if not base_url or not api_key:
        return None

    project_name = f'{org}/{repo}'
    project_version = branch or 'main'
    try:
        result = dtrack_client.safe_upload_bom(base_url, api_key, project_name,
                                               project_version, bom_path,
                                               is_latest=is_default)
    except dtrack_client.DtrackOverwriteRefused as exc:
        _update_repo_status(run_id, org, repo,
                            bom_overwrite_skipped=1,
                            error=f'overwrite refused: {str(exc)[:400]}')
        logger.warning('run=%s ingest %s/%s refused: %s',
                       run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))
        return None
    except dtrack_client.DtrackError as exc:
        _update_repo_status(run_id, org, repo, error=str(exc)[:500])
        logger.warning('run=%s ingest %s/%s failed: %s',
                       run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))
        return None

    # Wait for DT to finish processing the BOM before querying the count.
    # Without this, new projects always show dtrack_component_count=0 because
    # DT ingests asynchronously. poll_bom_processing blocks (in this worker
    # thread) until {processing: false} or the 15 s timeout; on timeout it
    # returns False and we fall through — the count will be stale but correct
    # on the next run.
    token = result.get('token') if result else None
    dtrack_client.poll_bom_processing(base_url, api_key, token)

    # Best-effort UUID lookup for the UI deep-link column. Requires
    # VIEW_PORTFOLIO; tolerate failure so the upload still counts as success.
    try:
        uuid = dtrack_client.lookup_project(base_url, api_key, project_name, project_version)
    except dtrack_client.DtrackError as lookup_exc:
        logger.debug('uuid lookup failed for %s/%s (non-fatal): %s',
                     log_mod.safe(org), log_mod.safe(repo), log_mod.safe(lookup_exc))
        uuid = None

    # Best-effort post-upload component count so the UI/coverage report
    # can show "DT retains N" alongside ORT's resolved count.
    dt_count = None
    if uuid:
        try:
            dt_count = dtrack_client.project_component_count(base_url, api_key, uuid)
        except dtrack_client.DtrackError:
            dt_count = None

    value = uuid or 'auto-created'
    update_fields = {'dtrack_project_uuid': value, 'error': None,
                     'bom_overwrite_skipped': 0}
    if dt_count is not None:
        update_fields['dtrack_component_count'] = dt_count
    if result and result.get('regression_warning'):
        # Don't clobber a successful upload with a None error, but DO
        # surface the regression note so the operator can review.
        update_fields['error'] = result['regression_warning'][:500]
    _update_repo_status(run_id, org, repo, **update_fields)
    logger.info('run=%s ingest %s/%s -> %s (new=%s prior=%s)',
                run_id, log_mod.safe(org), log_mod.safe(repo),
                uuid or 'auto-created',
                result.get('new_component_count') if result else '?',
                result.get('prior_component_count') if result else '?')
    return value


def _ort_one_repo(run_id, entry, image, network, cache_dir,
                  npm_cache_url, pypi_cache_url, athens_url, logs_dir, settings):
    """Run ORT analyze + classify + fallback + ingest for a single repo.

    Called concurrently by _stage_ort via ThreadPoolExecutor.  The
    already_done and no-manifests fast-paths are handled by _stage_ort
    before submitting to the pool so this function always does real work.

    Returns the bom_path string on success, None on OrtError or skip.
    Does not raise OrtError — it is caught here and the failure recorded
    in the DB so the coordinator only needs to inspect the return value.
    """
    org, repo = entry['org'], entry['repo']

    # Manifest-hash BOM cache lookup: if we've analysed an identical
    # manifest set before (prod/staging mirrors, unchanged-since-last-run
    # repos), skip ORT entirely and copy the cached BOM straight in.
    repo_hash = bom_cache.manifest_hash(entry['sandbox_dir'])
    cached_bom = bom_cache.lookup(cache_dir, repo_hash) if cache_dir else None
    if cached_bom:
        output_dir = os.path.join(entry['sandbox_dir'], 'ort-output')
        os.makedirs(output_dir, exist_ok=True)
        bom_path = os.path.join(output_dir, 'bom.cyclonedx.json')
        shutil.copy2(cached_bom, bom_path)
        pkg_count = bom_cache._bom_component_count(bom_path)
        _update_repo_status(run_id, org, repo, ort_status='completed', error=None,
                            **({'ort_package_count': pkg_count} if pkg_count is not None else {}))
        logger.info('run=%s %s/%s bom_cache HIT (%s) — ORT skipped',
                    run_id, log_mod.safe(org), log_mod.safe(repo),
                    repo_hash[:12] if repo_hash else 'no-hash')
        _ingest_one_repo(run_id, org, repo, bom_path, settings,
                         branch=entry.get('default_branch'),
                         is_default=entry.get('is_default'))
        return bom_path

    log_path = os.path.join(logs_dir, f'{org}__{repo}.log')
    _update_repo_status(run_id, org, repo, ort_status='running', error=None)
    try:
        pms = settings.get('enabled_package_managers') or None
        bom_path = ort_runner.analyze(entry['sandbox_dir'], image, network, log_path,
                                      cache_dir=cache_dir, run_id=run_id,
                                      npm_cache_url=npm_cache_url,
                                      pypi_cache_url=pypi_cache_url,
                                      athens_url=athens_url,
                                      package_managers=tuple(pms) if pms else None)
    except ort_runner.OrtError as exc:
        _update_repo_status(run_id, org, repo, ort_status='failed', error=str(exc)[:500])
        return None

    pkg_count = _parse_ort_package_count(log_path)
    # Classify analyzer-log fatal patterns BEFORE ingest so the
    # poetry_fallback merge happens before safe_upload_bom sees
    # the BOM (otherwise we'd ingest, then have to re-upload).
    analyzer_issues = _classify_analyzer_log(log_path)
    fallback_added = _maybe_run_poetry_fallback(
        run_id, org, repo, entry['sandbox_dir'], bom_path, analyzer_issues)

    update_fields = {'ort_status': 'completed'}
    if pkg_count is not None:
        update_fields['ort_package_count'] = pkg_count + fallback_added
    elif fallback_added:
        update_fields['ort_package_count'] = fallback_added
    if analyzer_issues:
        update_fields['analyzer_issue_kind'] = ';'.join(sorted(analyzer_issues))
    if fallback_added:
        update_fields['poetry_fallback_count'] = fallback_added
    _update_repo_status(run_id, org, repo, **update_fields)

    # Store the freshly produced BOM in the manifest-hash cache so a
    # future repo with the same manifest set (or a re-run) hits.
    # Pass the sibling analyzer-result.json so bom_cache can refuse to
    # cache partial results (analyzer errors during resolution).
    # Skip caching when analyzer_issues triggered the fallback — the
    # BOM we just merged isn't reproducible from the same
    # analyzer-result.json alone, and we'd rather re-run the fallback
    # next time than serve a possibly-stale merged cache.
    if cache_dir and repo_hash and not analyzer_issues:
        try:
            analyzer_result_path = os.path.join(
                entry['sandbox_dir'], 'ort-output', 'analyzer-result.json')
            bom_cache.store(cache_dir, repo_hash, bom_path,
                            analyzer_result_path=analyzer_result_path)
        except OSError as exc:
            logger.warning('run=%s bom_cache store failed for %s/%s: %s',
                           run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))

    # Inline ingest: push this BOM to DT immediately so the UI lights up
    # per-repo as analyze finishes, instead of waiting for every repo to
    # complete before the batched ingest stage fires.
    _ingest_one_repo(run_id, org, repo, bom_path, settings,
                     branch=entry.get('default_branch'),
                     is_default=entry.get('is_default'))
    return bom_path


def _stage_ort(run_id, extracted, settings, resume=False):
    image = settings['ort_image']
    network = settings['ort_egress_network']
    cache_dir = settings.get('ort_cache_dir') or None
    # Reuse the preflight result from _stage_prelock; if prelock was
    # skipped (no manifests with package.json), preflight on demand.
    npm_cache_url = settings.get('_npm_cache_url_resolved')
    if npm_cache_url is None and 'npm_cache_url' in settings:
        npm_cache_url = _check_npm_cache_reachable(settings)
    pypi_cache_url = settings.get('_pypi_cache_url_resolved')
    if pypi_cache_url is None and 'pypi_cache_url' in settings:
        pypi_cache_url = _check_pypi_cache_reachable(settings)
    athens_url = settings.get('_athens_url_resolved')
    if athens_url is None and 'athens_url' in settings:
        athens_url = _check_athens_reachable(settings)
    logs_dir = os.path.join(_DATA_DIR,
                            'runs', run_id)
    os.makedirs(logs_dir, exist_ok=True)

    already_done = set()
    if resume:
        conn = db.get_db()
        try:
            for r in conn.execute(
                'SELECT org, repo FROM run_repos WHERE run_id = ? AND ort_status = ?',
                (run_id, 'completed'),
            ):
                already_done.add((r['org'], r['repo']))
        finally:
            conn.close()
        if already_done:
            logger.info('run=%s resume: skipping ORT for %d already-completed repos',
                        run_id, len(already_done))

    bom_paths = {}
    # Handle fast-path entries inline (no Docker container needed) so pool
    # slots are reserved for repos that actually need ort_runner.analyze.
    pool_entries = []
    for entry in extracted:
        _check_stop(run_id)
        org, repo = entry['org'], entry['repo']

        if (org, repo) in already_done:
            existing = _find_existing_bom(entry['sandbox_dir'])
            if existing:
                bom_paths[(org, repo)] = existing
            continue

        if not entry['manifests']:
            _update_repo_status(run_id, org, repo, ort_status='skipped')
            continue

        pool_entries.append(entry)

    if not pool_entries:
        return bom_paths

    workers = min(settings.get('ort_max_workers', 4), len(pool_entries))
    logger.info('run=%s ort: %d repo(s) to analyse, %d worker(s)',
                run_id, len(pool_entries), workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_ort_one_repo, run_id, entry, image, network, cache_dir,
                        npm_cache_url, pypi_cache_url, athens_url, logs_dir, settings): entry
            for entry in pool_entries
        }
        for fut in as_completed(futures):
            try:
                _check_stop(run_id)
            except StopRequested:
                for f in futures:
                    f.cancel()
                raise
            entry = futures[fut]
            org, repo = entry['org'], entry['repo']
            try:
                bom_path = fut.result()
            except StopRequested:
                for f in futures:
                    f.cancel()
                raise
            except Exception as exc:
                # Unexpected exception from _ort_one_repo; normal OrtError
                # is already caught inside the helper and returns None.
                logger.error('run=%s ort %s/%s raised unexpected %s: %s',
                             run_id, log_mod.safe(org), log_mod.safe(repo),
                             type(exc).__name__, log_mod.safe(exc))
                bom_path = None
            if bom_path:
                bom_paths[(org, repo)] = bom_path

    return bom_paths


def _stage_ingest(run_id, bom_paths, settings, resume=False):
    """Catchup ingest stage.

    The normal flow inlines ingest into `_stage_ort` so each repo's BOM
    lands in DT as soon as analyze + report succeed. This stage handles
    the edge case where a prior run completed ORT for some repos but died
    before they were ingested (a `dtrack_project_uuid IS NULL` row with
    `ort_status='completed'`). On a normal run this finds nothing.
    """
    base_url = settings.get('dtrack_url')
    api_key = settings.get('dtrack_api_key')
    if not base_url or not api_key:
        logger.warning('run=%s ingest skipped: dtrack_url or dtrack_api_key missing', run_id)
        return

    conn = db.get_db()
    try:
        rows = conn.execute(
            'SELECT org, repo, default_branch FROM run_repos '
            'WHERE run_id = ? AND ort_status = ? AND dtrack_project_uuid IS NULL',
            (run_id, 'completed'),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return

    logger.info('run=%s ingest catchup: %d repo(s) need uploads', run_id, len(rows))
    for r in rows:
        _check_stop(run_id)
        key = (r['org'], r['repo'])
        bom_path = bom_paths.get(key)
        if not bom_path:
            logger.warning('run=%s ingest catchup: no BOM path for %s/%s — skipping',
                           run_id, log_mod.safe(r['org']), log_mod.safe(r['repo']))
            continue
        # Catchup can't recompute is_default (the GitHub default isn't stored),
        # so pass is_default=None to leave DT's isLatest flag untouched.
        _ingest_one_repo(run_id, r['org'], r['repo'], bom_path, settings,
                         branch=(r['default_branch'] if 'default_branch' in r.keys() else None),
                         is_default=None)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _stage(run_id, name, fn, *args):
    _check_stop(run_id)
    t0 = time.monotonic()
    logger.info('run=%s stage=%s start', run_id, name)
    _set_run_stage(run_id, name, status='running' if name == 'extract' else None)
    try:
        result = fn(*args)
        logger.info('run=%s stage=%s done (%.1fs)', run_id, name, time.monotonic() - t0)
        return result
    except StopRequested:
        raise
    except Exception:
        logger.exception('run=%s stage=%s failed (%.1fs)', run_id, name,
                         time.monotonic() - t0)
        raise


def _finalize(run_id, settings):
    """Set the final run status based on per-repo outcomes.

    Considers both ORT outcomes AND Dependency-Track ingestion outcomes:

    completed — every relevant repo's BOM landed in DT (or DT wasn't configured)
    partial   — mixed: some repos succeeded, some failed at ORT or ingest
    failed    — no repos extracted, all ORT runs failed, or all ingests failed

    `settings` is consulted so a deliberately-unconfigured DT doesn't get
    treated as an ingest failure.
    """
    ingest_configured = bool(settings.get('dtrack_url') and settings.get('dtrack_api_key'))

    conn = db.get_db()
    try:
        rows = conn.execute(
            'SELECT ort_status, dtrack_project_uuid, manifest_count, error '
            'FROM run_repos WHERE run_id = ?',
            (run_id,),
        ).fetchall()
        total = len(rows)
        ort_ok = sum(1 for r in rows if r['ort_status'] == 'completed')
        ort_failed = sum(1 for r in rows if r['ort_status'] == 'failed')
        ort_skipped = sum(1 for r in rows if r['ort_status'] == 'skipped')
        relevant = total - ort_skipped

        if ingest_configured:
            # Of the repos that completed ORT, how many actually have a DT
            # project UUID stored? Missing = ingest failed for that repo.
            ingest_failed = sum(
                1 for r in rows
                if r['ort_status'] == 'completed' and not r['dtrack_project_uuid']
            )
        else:
            ingest_failed = 0

        # Status decision tree.
        if total == 0:
            status, error = 'failed', 'No repositories enumerated'
        elif relevant == 0:
            status, error = 'completed', 'No repositories had supported manifests'
        elif ort_failed == 0 and ingest_failed == 0:
            status, error = 'completed', None
        elif ort_ok == 0:
            status, error = 'failed', f'All {relevant} repos failed in ORT'
        elif ingest_configured and ingest_failed == ort_ok:
            status, error = 'failed', (
                f'ORT succeeded for {ort_ok} repo(s) but every Dependency-Track '
                'ingest failed (see per-repo errors)'
            )
        else:
            parts = []
            if ort_failed:
                parts.append(f'{ort_failed} ORT failure{"s" if ort_failed != 1 else ""}')
            if ingest_failed:
                parts.append(f'{ingest_failed} DT ingest failure{"s" if ingest_failed != 1 else ""}')
            status, error = 'partial', ', '.join(parts) + f' across {relevant} repo(s)'

        conn.execute(
            'UPDATE runs SET stage = ?, status = ?, completed_at = ?, error = ? WHERE id = ?',
            ('done', status, _now(), error, run_id),
        )
        conn.commit()
        logger.info('run=%s finalize status=%s (ort_ok=%d ort_failed=%d ort_skipped=%d '
                    'ingest_failed=%d ingest_configured=%s)',
                    run_id, status, ort_ok, ort_failed, ort_skipped,
                    ingest_failed, ingest_configured)
    finally:
        conn.close()


def run_pipeline(run_id, resume=False):
    """Run the full pipeline for a previously inserted run row.

    Designed to be called from a background thread.
    """
    logger.info('run=%s starting (resume=%s)', run_id, resume)
    t_total = time.monotonic()
    _reset_stop_event(run_id)
    try:
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT orgs_json, repos_json, branch FROM runs WHERE id = ?', (run_id,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            raise RuntimeError(f'Run {run_id} not found')
        orgs = json.loads(row['orgs_json'])
        repo_filter = set(json.loads(row['repos_json'])) if row['repos_json'] else None
        run_branch = row['branch'] if 'branch' in row.keys() else None
        logger.info('run=%s orgs=%s repo_filter=%s branch=%s', run_id, orgs,
                    sorted(repo_filter) if repo_filter else None, run_branch or '(default)')

        settings = settings_mod.load_settings()
        sandbox_root = sandbox.root_for_run(run_id)
        sandbox_intact = resume and os.path.isdir(sandbox_root)

        if not sandbox_intact:
            sandbox.cleanup_old_runs(settings.get('run_retention', 10))
            sandbox_root = sandbox.prepare(run_id)
            if resume:
                logger.info('run=%s resume requested but sandbox is gone; doing fresh extract', run_id)
                resume = False

        logger.debug('run=%s sandbox_root=%s', run_id, sandbox_root)

        if resume:
            _clear_run_for_resume(run_id)
            extracted = _rebuild_extracted_from_db(run_id, sandbox_root)
            logger.info('run=%s resume: rebuilt %d repos from DB', run_id, len(extracted))
        else:
            extracted = _stage(run_id, 'extract', _stage_extract, run_id, orgs, sandbox_root, repo_filter, run_branch)

        _stage(run_id, 'sanitize', _stage_sanitize, run_id, extracted)
        _stage(run_id, 'mock', _stage_mock, run_id, extracted)
        _stage(run_id, 'prelock', _stage_prelock, run_id, extracted, settings, resume)
        bom_paths = _stage(run_id, 'ort', _stage_ort, run_id, extracted, settings, resume)
        _stage(run_id, 'ingest', _stage_ingest, run_id, bom_paths, settings, resume)

        _finalize(run_id, settings)
        logger.info('run=%s finished in %.1fs', run_id, time.monotonic() - t_total)
    except StopRequested:
        _set_run_stage(run_id, 'stopped', status='stopped', error='Stop requested')
        logger.info('run=%s stopped after %.1fs', run_id, time.monotonic() - t_total)
    except Exception as exc:
        traceback.print_exc()
        _set_run_stage(run_id, 'failed', status='failed', error=str(exc)[:1000])
        logger.error('run=%s failed after %.1fs: %s',
                     run_id, time.monotonic() - t_total, log_mod.safe(exc))
    finally:
        cid_manager.cleanup_run(run_id)


def _fetch_one_github_sbom(run_id, org, repo, logs_dir, settings,
                           run_branch=None, github_default_branch=None):
    """Fetch, convert, and ingest the GitHub SBOM for a single org/repo.

    Resolves the analyzed branch (run_branch > GitHub default). The default
    branch uses GitHub's SBOM export; a non-default branch is approximated
    from the dependency-review diff.
    """
    _check_stop(run_id)
    _set_run_stage(run_id, f'github_sbom:{org}:{repo}')

    # The GitHub default branch is needed both to decide default vs.
    # non-default and to serve as the compare base. Fetch it lazily when the
    # caller couldn't supply it (explicit org/repo pairs skip org listing).
    if github_default_branch is None:
        try:
            github_default_branch = github_client.get_repo_default_branch(org, repo)
        except github_client.GhError as exc:
            logger.warning('run=%s github_sbom %s/%s default-branch lookup failed: %s',
                           run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))
            github_default_branch = None

    branch = _resolve_branch(org, repo, run_branch, github_default_branch)
    is_default = bool(branch) and branch == github_default_branch

    conn = db.get_db()
    try:
        conn.execute(
            'INSERT OR REPLACE INTO run_repos '
            '(run_id, org, repo, default_branch, sanitize_status, ort_status) '
            'VALUES (?,?,?,?,?,?)',
            (run_id, org, repo, branch, 'n/a', 'running'),
        )
        conn.commit()
    finally:
        conn.close()

    bom_path = os.path.join(logs_dir, f'{org}__{repo}.github_sbom.json')
    try:
        count, err = github_sbom.fetch_and_write_bom(
            org, repo, bom_path, branch=branch, default_branch=github_default_branch)
    except github_client.GhError as exc:
        logger.warning('run=%s github_sbom %s/%s gh error: %s',
                       run_id, log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))
        _update_repo_status(run_id, org, repo, ort_status='failed', error=str(exc)[:500])
        return

    if count is None:
        logger.info('run=%s github_sbom %s/%s skipped: %s',
                    run_id, log_mod.safe(org), log_mod.safe(repo), err)
        _update_repo_status(run_id, org, repo, ort_status='skipped', error=err)
        return

    logger.info('run=%s github_sbom %s/%s@%s components=%d',
                run_id, log_mod.safe(org), log_mod.safe(repo),
                log_mod.safe(branch or '(default)'), count)
    _update_repo_status(run_id, org, repo,
                        ort_status='completed', ort_package_count=count, error=None)
    _ingest_one_repo(run_id, org, repo, bom_path, settings,
                     branch=branch, is_default=is_default)


def _stage_github_sbom(run_id, orgs, repo_filter, settings, logs_dir, run_branch=None):
    """Fetch GitHub Dependency Graph SBOMs and ingest them into Dependency-Track.

    repo_filter entries may be plain repo names (checked across every org in
    orgs) or explicit "org/repo" pairs (fetched directly, no listing needed).
    Repos without the Dependency Graph enabled are marked ort_status='skipped'.
    No sandbox, no Docker.

    *run_branch* is an optional run-level branch override forwarded to each
    repo's branch resolution.
    """
    # Split repo_filter into explicit org/repo pairs vs plain names.
    explicit_pairs = []   # [(org, repo), ...] — fetched directly
    plain_filter = set()  # plain names to match within each org via listing
    for r in (repo_filter or set()):
        if '/' in r:
            org_part, _, repo_part = r.partition('/')
            explicit_pairs.append((org_part, repo_part))
        else:
            plain_filter.add(r)

    # Explicit org/repo pairs — no listing required (default branch is
    # resolved lazily inside _fetch_one_github_sbom).
    for org, repo in explicit_pairs:
        _fetch_one_github_sbom(run_id, org, repo, logs_dir, settings,
                               run_branch=run_branch)

    # Plain names — enumerate each org's repo list and filter.
    scan_orgs = orgs if plain_filter or not explicit_pairs else []
    for org in scan_orgs:
        _check_stop(run_id)
        _set_run_stage(run_id, f'github_sbom:{org}:listing-repos')
        logger.info('run=%s github_sbom org=%s listing repos', run_id, log_mod.safe(org))
        try:
            repos = github_client.list_repos(org)
        except github_client.GhError as exc:
            logger.error('run=%s github_sbom org=%s list_repos failed: %s',
                         run_id, log_mod.safe(org), log_mod.safe(exc))
            continue

        if plain_filter:
            listed_names = {r for r, _ in repos}
            missing = plain_filter - listed_names
            for repo_name in sorted(missing):
                conn = db.get_db()
                try:
                    conn.execute(
                        'INSERT OR REPLACE INTO run_repos '
                        '(run_id, org, repo, sanitize_status, ort_status, error) '
                        'VALUES (?,?,?,?,?,?)',
                        (run_id, org, repo_name, 'n/a', 'skipped',
                         'not found in org listing — repo may be empty, archived, or non-existent'),
                    )
                    conn.commit()
                finally:
                    conn.close()
            repos = [(r, b) for r, b in repos if r in plain_filter]

        logger.info('run=%s github_sbom org=%s repos=%d', run_id, log_mod.safe(org), len(repos))
        for repo, github_default_branch in repos:
            _fetch_one_github_sbom(run_id, org, repo, logs_dir, settings,
                                   run_branch=run_branch,
                                   github_default_branch=github_default_branch)


def run_github_sbom_pipeline(run_id):
    """GitHub Dependency Graph SBOM pipeline — no Docker, no sandbox.

    Replaces the full extract → sanitize → mock → prelock → ORT chain with
    direct GitHub API calls.  Shares the DT ingest infrastructure with the
    ORT pipeline.
    """
    logger.info('run=%s github_sbom pipeline starting', run_id)
    t_total = time.monotonic()
    _reset_stop_event(run_id)
    try:
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT orgs_json, repos_json, branch FROM runs WHERE id = ?', (run_id,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            raise RuntimeError(f'Run {run_id} not found')
        orgs = json.loads(row['orgs_json'])
        repo_filter = set(json.loads(row['repos_json'])) if row['repos_json'] else None
        run_branch = row['branch'] if 'branch' in row.keys() else None
        logger.info('run=%s orgs=%s repo_filter=%s branch=%s', run_id, orgs,
                    sorted(repo_filter) if repo_filter else None,
                    run_branch or '(default)')

        settings = settings_mod.load_settings()
        logs_dir = os.path.join(_DATA_DIR,
                                'runs', run_id)
        os.makedirs(logs_dir, exist_ok=True)

        _set_run_stage(run_id, 'github_sbom', status='running')
        _stage_github_sbom(run_id, orgs, repo_filter, settings, logs_dir,
                           run_branch=run_branch)

        _finalize(run_id, settings)
        logger.info('run=%s github_sbom pipeline finished in %.1fs',
                    run_id, time.monotonic() - t_total)
    except StopRequested:
        _set_run_stage(run_id, 'stopped', status='stopped', error='Stop requested')
        logger.info('run=%s stopped after %.1fs', run_id, time.monotonic() - t_total)
    except Exception as exc:
        traceback.print_exc()
        _set_run_stage(run_id, 'failed', status='failed', error=str(exc)[:1000])
        logger.error('run=%s github_sbom pipeline failed after %.1fs: %s',
                     run_id, time.monotonic() - t_total, log_mod.safe(exc))


def reset_repos_for_retry(run_id, repos=None):
    """Reset ort_status='failed' rows back to 'pending' so a resume re-runs them.

    repos: list of (org, repo) tuples to reset, or None to reset every failed
    repo in the run.  The WHERE clause always requires ort_status='failed' so
    callers cannot accidentally demote a completed row.

    Returns the count of rows updated.
    """
    conn = db.get_db()
    try:
        if repos is not None:
            updated = 0
            for org, repo in repos:
                cur = conn.execute(
                    'UPDATE run_repos '
                    'SET ort_status=?, error=NULL, analyzer_issue_kind=NULL, '
                    '    poetry_fallback_count=NULL '
                    'WHERE run_id=? AND org=? AND repo=? AND ort_status=?',
                    ('pending', run_id, org, repo, 'failed'),
                )
                updated += cur.rowcount
        else:
            cur = conn.execute(
                'UPDATE run_repos '
                'SET ort_status=?, error=NULL, analyzer_issue_kind=NULL, '
                '    poetry_fallback_count=NULL '
                'WHERE run_id=? AND ort_status=?',
                ('pending', run_id, 'failed'),
            )
            updated = cur.rowcount
        conn.commit()
        logger.info('run=%s reset_repos_for_retry: %d row(s) reset', run_id, updated)
        return updated
    finally:
        conn.close()


def start_in_background(run_id, resume=False):
    conn = db.get_db()
    try:
        row = conn.execute('SELECT method FROM runs WHERE id = ?', (run_id,)).fetchone()
    finally:
        conn.close()
    method = (row['method'] if row else None) or 'ort'
    if method == 'github_sbom':
        threading.Thread(target=run_github_sbom_pipeline, args=(run_id,), daemon=True).start()
    else:
        threading.Thread(target=run_pipeline, args=(run_id, resume), daemon=True).start()
