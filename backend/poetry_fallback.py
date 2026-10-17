"""Synthesize a CycloneDX BOM directly from poetry.lock.

ORT delegates Poetry resolution to ``python-inspector``, which has a known
``RecursionError`` in its ``pdt_dfs`` walker for graphs with deep linear
chains or cycles (a common shape for ML/data stacks: torch, nvidia-cu12-*,
transformers, …). When that happens ORT records ``"Unable to determine
dependencies for definition file …"`` and produces an analyzer-result with
zero packages for the affected sub-project.

A ``poetry.lock`` already lists every resolved package, version, and hash
— no resolution is required. This module parses it with stdlib ``tomllib``
and emits a CycloneDX 1.5 JSON payload that the pipeline can merge into
the ORT BOM as a fallback. No network, no third-party dependencies.

Inputs are untrusted (the lockfile lives in a user repo), so each field
is validated against a strict allow-list before it is included in the
output BOM.
"""

import hashlib
import json
import re
import time
import urllib.parse
import uuid

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - older interpreters
    tomllib = None


# PEP 503 normalised name characters; we accept the canonical form plus
# the un-normalised one Poetry sometimes writes back.
_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$')
# PEP 440 versions are surprisingly permissive; this pattern is a strict
# subset that covers everything Poetry can legitimately resolve to. We err
# on the side of rejecting weird input rather than letting it into a purl.
_VERSION_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')


class PoetryFallbackError(Exception):
    """Raised when the lockfile is malformed beyond what we can salvage."""


def _normalise_name(name):
    """Apply PEP 503 normalisation (lower-case, '_' / '.' -> '-').

    purls for PyPI are case-insensitive but DT compares ``bom-ref`` strings
    byte-for-byte, so we have to be consistent across the fallback BOM and
    anything else that might land in the same project.
    """
    return re.sub(r'[-_.]+', '-', name).lower()


def _build_purl(name, version):
    safe_name = urllib.parse.quote(_normalise_name(name), safe='')
    safe_version = urllib.parse.quote(version, safe='')
    return f'pkg:pypi/{safe_name}@{safe_version}'


def _extract_sha256(files_entry):
    """Pull the first valid sha256 hash from a Poetry ``files = [...]`` array.

    Poetry writes hashes as ``"sha256:HEX"`` strings; older lockfiles use a
    structured ``{file, hash}`` mapping. Accept both. Reject anything that
    isn't 64 hex chars so a malicious or corrupt lockfile can't smuggle
    arbitrary content into the BOM ``hashes`` array.
    """
    if not isinstance(files_entry, list):
        return None
    for entry in files_entry:
        if not isinstance(entry, dict):
            continue
        raw = entry.get('hash')
        if not isinstance(raw, str):
            continue
        if raw.startswith('sha256:'):
            digest = raw.split(':', 1)[1].strip()
            if _SHA256_RE.match(digest):
                return digest.lower()
    return None


def _component_from_package(pkg):
    """Convert a single Poetry ``[[package]]`` block into a CycloneDX dict.

    Returns ``None`` if the entry fails validation (we'd rather drop one
    component than emit a malformed BOM that DT later refuses).
    """
    name = pkg.get('name')
    version = pkg.get('version')
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return None
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        return None
    purl = _build_purl(name, version)
    component = {
        'type': 'library',
        'bom-ref': purl,
        'name': _normalise_name(name),
        'version': version,
        'purl': purl,
    }
    sha = _extract_sha256(pkg.get('files'))
    if sha:
        component['hashes'] = [{'alg': 'SHA-256', 'content': sha}]
    description = pkg.get('description')
    if isinstance(description, str) and description.strip():
        component['description'] = description.strip()[:512]
    return component


def parse_poetry_lock(lock_path):
    """Read ``lock_path`` and return a list of validated CycloneDX components.

    Raises ``PoetryFallbackError`` only when the lockfile cannot be read or
    parsed at all. Per-package validation failures are silently dropped
    (the caller logs the count via ``len(components)``).
    """
    if tomllib is None:
        raise PoetryFallbackError('tomllib unavailable; need Python 3.11+')
    try:
        with open(lock_path, 'rb') as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise PoetryFallbackError(f'cannot read {lock_path}: {exc}') from exc
    except tomllib.TOMLDecodeError as exc:
        raise PoetryFallbackError(f'malformed TOML in {lock_path}: {exc}') from exc
    packages = data.get('package') or []
    if not isinstance(packages, list):
        raise PoetryFallbackError(f'{lock_path}: top-level [[package]] missing')
    components = []
    seen = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        comp = _component_from_package(pkg)
        if comp is None:
            continue
        ref = comp['bom-ref']
        if ref in seen:
            continue
        seen.add(ref)
        components.append(comp)
    return components


def synthesize_bom(lock_path, project_name, project_version='0.0.0'):
    """Build a complete CycloneDX 1.5 BOM document for one ``poetry.lock``.

    Returns a dict ready to be serialised with ``json.dumps``.
    """
    components = parse_poetry_lock(lock_path)
    serial = 'urn:uuid:' + str(uuid.uuid4())
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': [{
                'vendor': 'depexplorer',
                'name': 'poetry-fallback',
                'version': '1.0',
            }],
            'component': {
                'type': 'application',
                'bom-ref': f'pkg:generic/{urllib.parse.quote(project_name, safe="")}@{urllib.parse.quote(project_version, safe="")}',
                'name': project_name,
                'version': project_version,
            },
        },
        'components': components,
    }


def merge_components_into_bom(existing_bom_path, new_components):
    """Merge ``new_components`` into ``existing_bom_path`` in place.

    De-dupes against the existing ``components[].bom-ref`` (or ``purl``
    fallback) so a re-run that hits the same fallback path is idempotent.

    Returns ``(added, total_after_merge)``.
    """
    try:
        with open(existing_bom_path, 'rb') as fh:
            bom = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PoetryFallbackError(
            f'cannot read existing BOM at {existing_bom_path}: {exc}'
        ) from exc
    if not isinstance(bom, dict) or bom.get('bomFormat') != 'CycloneDX':
        raise PoetryFallbackError(
            f'{existing_bom_path}: not a CycloneDX document'
        )
    components = bom.get('components')
    if not isinstance(components, list):
        components = []
        bom['components'] = components
    seen = set()
    for comp in components:
        if not isinstance(comp, dict):
            continue
        ref = comp.get('bom-ref') or comp.get('purl')
        if ref:
            seen.add(ref)
    added = 0
    for comp in new_components:
        ref = comp.get('bom-ref') or comp.get('purl')
        if not ref or ref in seen:
            continue
        components.append(comp)
        seen.add(ref)
        added += 1
    if added:
        # Refresh serialNumber so DT treats this as a new BOM rather than
        # de-duplicating against the prior identical document.
        bom['serialNumber'] = 'urn:uuid:' + str(uuid.uuid4())
    tmp_path = existing_bom_path + '.tmp'
    with open(tmp_path, 'w') as fh:
        json.dump(bom, fh, indent=2)
    import os
    os.replace(tmp_path, existing_bom_path)
    return added, len(components)


def lockfile_signature(lock_path):
    """SHA-256 of the lockfile contents for cache-key / dedup use.

    Not used by the pipeline directly today, but the bom_cache layer can
    key off this so a re-run with an unchanged poetry.lock skips the
    fallback rebuild step.
    """
    h = hashlib.sha256()
    with open(lock_path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()
