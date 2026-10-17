"""Manifest-hash BOM cache.

When a repo's *sanitized* manifest set is byte-identical to one we've
already analysed, we can skip the entire ORT analyze+report cycle and
copy the cached CycloneDX BOM straight to ingest. Useful for prod/staging
mirrors and for week-over-week scans of repos that haven't changed.

Cache key: SHA256 over each manifest's (relative_path \\0 content \\0) in
sorted-path order. Pulling the relative path into the hash protects
against two repos that happen to share file content at different layouts
hashing identically.

Cache layout: {ort_cache_dir}/boms/{sha}.cyclonedx.json
"""

import hashlib
import json
import os
import shutil

from . import log as log_mod

logger = log_mod.get('bom_cache')

_MANIFEST_BASENAMES = {
    'package.json',
    'package-lock.json',
    'requirements.txt',
    'Pipfile',
    'Pipfile.lock',
    'go.mod',
    'go.sum',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'setup.py',
    'pyproject.toml',
    'poetry.lock',
    'yarn.lock',
}

_SKIP_DIRS = {'node_modules', '.git', 'ort-output', '__pycache__', '.venv', 'venv', 'vendor'}


def manifest_hash(sandbox_dir):
    """Return a hex SHA256 fingerprinting every manifest file in the sandbox."""
    h = hashlib.sha256()
    entries = []
    for root, dirs, files in os.walk(sandbox_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if fn in _MANIFEST_BASENAMES:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, sandbox_dir)
                entries.append((rel, full))
    if not entries:
        return None
    for rel, full in sorted(entries, key=lambda x: x[0]):
        h.update(rel.encode())
        h.update(b'\0')
        try:
            with open(full, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError as exc:
            logger.warning('manifest_hash skip %s: %s', log_mod.safe(rel), log_mod.safe(exc))
        h.update(b'\0')
    return h.hexdigest()


def _cache_dir(ort_cache_dir):
    if not ort_cache_dir:
        return None
    d = os.path.join(ort_cache_dir, 'boms')
    os.makedirs(d, exist_ok=True)
    return d


def lookup(ort_cache_dir, sha):
    if not sha:
        return None
    d = _cache_dir(ort_cache_dir)
    if not d:
        return None
    path = os.path.join(d, f'{sha}.cyclonedx.json')
    return path if os.path.isfile(path) and os.path.getsize(path) > 0 else None


def _bom_component_count(bom_path):
    """Return len(components) from a CycloneDX BOM, or None on parse failure."""
    try:
        with open(bom_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    comps = data.get('components')
    return len(comps) if isinstance(comps, list) else 0


def _analyzer_error_count(analyzer_result_path):
    """Return (total_issues, error_severity_issues) from an analyzer-result.json.

    Returns (None, None) when the file is missing/unreadable so callers
    can default to "treat as no errors" if they want.
    """
    if not analyzer_result_path or not os.path.isfile(analyzer_result_path):
        return None, None
    try:
        with open(analyzer_result_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None, None
    result = data.get('analyzer', {}).get('result', {}) or {}
    issues = result.get('issues') or {}
    total = 0
    errors = 0
    for _proj_id, msgs in issues.items():
        for m in msgs:
            total += 1
            if (m.get('severity') or '').upper() == 'ERROR':
                errors += 1
    return total, errors


def store(ort_cache_dir, sha, bom_path, analyzer_result_path=None):
    """Store a freshly produced BOM keyed by manifest sha.

    Refuses to cache when EITHER:
      • The BOM has zero components (resolution failure), OR
      • The analyzer-result.json shows ERROR-severity issues (partial
        resolution — caching this would replay an incomplete result
        forever for the same manifest set, even after the underlying
        toolchain bug is fixed).

    Pass the path to the analyzer-result.json next to the BOM so the
    second check can run. Without it, only the zero-component check
    applies (legacy behavior).
    """
    if not sha or not bom_path:
        return None
    d = _cache_dir(ort_cache_dir)
    if not d:
        return None

    components = _bom_component_count(bom_path)
    if components is None or components == 0:
        logger.info('bom_cache skip-store %s — BOM is empty/unreadable (components=%s); '
                    'caching this would replay a likely resolution failure',
                    sha[:12], components)
        return None

    total_issues, error_issues = _analyzer_error_count(analyzer_result_path)
    if error_issues is not None and error_issues > 0:
        logger.info('bom_cache skip-store %s — analyzer reported %d ERROR issue(s) '
                    '(out of %d total); BOM may be partial. Fix the underlying '
                    'issue and re-run; do not cache this state.',
                    sha[:12], error_issues, total_issues)
        return None

    dest = os.path.join(d, f'{sha}.cyclonedx.json')
    tmp = dest + '.tmp'
    shutil.copy2(bom_path, tmp)
    os.replace(tmp, dest)
    logger.info('bom_cache stored %s (%d bytes, %d components, %d non-error issues)',
                sha[:12], os.path.getsize(dest), components, (total_issues or 0))
    return dest


def purge_empty(ort_cache_dir):
    """Remove any cached BOMs with zero components.

    Useful after a code fix that resolves a class of resolution failure —
    the old empty entries would otherwise live forever in cache and
    short-circuit fresh analyses. Returns the count removed.
    """
    d = _cache_dir(ort_cache_dir)
    if not d:
        return 0
    removed = 0
    for fn in os.listdir(d):
        if not fn.endswith('.cyclonedx.json'):
            continue
        path = os.path.join(d, fn)
        n = _bom_component_count(path)
        if n is None or n == 0:
            try:
                os.unlink(path)
                removed += 1
                logger.info('bom_cache purged empty entry %s', fn[:20])
            except OSError as exc:
                logger.warning('failed to purge %s: %s', fn, log_mod.safe(exc))
    return removed
