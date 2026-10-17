"""Fetch GitHub Dependency Graph SBOMs and convert SPDX 2.3 → CycloneDX 1.4.

GitHub's /repos/{owner}/{repo}/dependency-graph/sbom endpoint returns an
SPDX 2.3 document. This module fetches it via the existing `gh` CLI wrapper
and converts it to the CycloneDX 1.4 JSON format that Dependency-Track accepts.

Repos without the Dependency Graph enabled return HTTP 404 — callers receive
(None, 'dependency graph not enabled') instead of an exception.
"""

import json
import os
import uuid
from datetime import datetime, timezone

from . import github_client, log as log_mod

logger = log_mod.get('github_sbom')


def _extract_purl(pkg):
    """Return the first purl externalRef from an SPDX package, or None."""
    for ref in pkg.get('externalRefs') or []:
        if ref.get('referenceType') == 'purl':
            return ref.get('referenceLocator')
    return None


def spdx_to_cyclonedx(spdx_data, org, repo):
    """Convert a GitHub SPDX 2.3 response dict to a CycloneDX 1.4 dict.

    Packages without a purl externalRef are skipped — they represent either
    the root repo itself (which has no purl) or unresolvable transient entries.

    SPDX relationships (DEPENDS_ON / DEPENDENCY_OF) are converted to the
    CycloneDX `dependencies` array so Dependency-Track can render the graph view.

    The SPDX root package (identified via the DESCRIBES relationship) is placed
    in `metadata.component` with a `bom-ref` rather than in `components[]` — this
    matches how ORT structures its BOMs and is what DT needs to anchor the
    dependency tree.
    """
    sbom = spdx_data.get('sbom') or {}
    packages = sbom.get('packages') or []
    relationships = sbom.get('relationships') or []

    # Pass 1: build SPDXID → purl for all packages (needed for relationship mapping)
    spdxid_to_purl = {}
    for pkg in packages:
        purl = _extract_purl(pkg)
        spdxid = pkg.get('SPDXID') or ''
        if purl and spdxid:
            spdxid_to_purl[spdxid] = purl

    # Identify root package: the target of the DESCRIBES relationship from the document.
    # This goes in metadata.component (not components[]) so DT can anchor the dep tree.
    root_purl = None
    for rel in relationships:
        if rel.get('relationshipType') == 'DESCRIBES':
            candidate = spdxid_to_purl.get(rel.get('relatedSpdxElement') or '')
            if candidate:
                root_purl = candidate
                break

    # Pass 2: build components[], skipping the root and deduplicating by purl
    seen_purls = set()
    components = []
    for pkg in packages:
        purl = _extract_purl(pkg)
        if not purl or purl in seen_purls:
            continue
        seen_purls.add(purl)
        if purl == root_purl:
            continue  # root belongs in metadata.component
        name = pkg.get('name') or ''
        version = pkg.get('versionInfo') or ''
        comp = {
            'type': 'library',
            'bom-ref': purl,
            'purl': purl,
            'name': name,
        }
        if version:
            comp['version'] = version
        components.append(comp)

    # Convert SPDX relationships → CycloneDX dependencies
    dep_map = {}  # purl → set of purls it directly depends on
    for rel in relationships:
        rel_type = rel.get('relationshipType') or ''
        if rel_type == 'DEPENDS_ON':
            src = spdxid_to_purl.get(rel.get('spdxElementId') or '')
            dst = spdxid_to_purl.get(rel.get('relatedSpdxElement') or '')
            if src and dst and src != dst:
                dep_map.setdefault(src, set()).add(dst)
        elif rel_type == 'DEPENDENCY_OF':
            # "B DEPENDENCY_OF A" is the inverse of "A DEPENDS_ON B"
            dst = spdxid_to_purl.get(rel.get('spdxElementId') or '')
            src = spdxid_to_purl.get(rel.get('relatedSpdxElement') or '')
            if src and dst and src != dst:
                dep_map.setdefault(src, set()).add(dst)

    metadata_component = {'type': 'library', 'name': f'{org}/{repo}'}
    if root_purl:
        metadata_component['bom-ref'] = root_purl
        metadata_component['purl'] = root_purl

    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'version': 1,
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'component': metadata_component,
        },
        'components': components,
    }
    if dep_map:
        bom['dependencies'] = [
            {'ref': purl, 'dependsOn': sorted(deps)}
            for purl, deps in sorted(dep_map.items())
        ]
    return bom


def _empty_bom(org, repo):
    """Return a CycloneDX skeleton with no components (diff-only fallback)."""
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'version': 1,
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'component': {'type': 'library', 'name': f'{org}/{repo}'},
        },
        'components': [],
    }


def _component_key(comp):
    """Stable identity for a component: purl, else name@version."""
    return comp.get('purl') or f"{comp.get('name', '')}@{comp.get('version', '')}"


def _component_from_diff_entry(entry):
    """Build a CycloneDX component from a dependency-review change entry."""
    purl = entry.get('package_url') or ''
    name = entry.get('name') or ''
    version = entry.get('version') or ''
    if not purl and not name:
        return None
    comp = {
        'type': 'library',
        'bom-ref': purl or f'{name}@{version}',
        'name': name,
    }
    if purl:
        comp['purl'] = purl
    if version:
        comp['version'] = version
    return comp


def apply_dependency_diff(base_bom, diff):
    """Apply a dependency-review diff onto *base_bom*, returning a new BOM.

    The compare API reports dependencies ``added`` on / ``removed`` from the
    head ref relative to the base. Applying both to the base-branch component
    set approximates the head branch's set. This is manifest-diff based — it
    does not re-resolve the transitive graph — so the result is approximate
    by design (matching GitHub's own toolkit limitation).
    """
    components = {_component_key(c): c for c in base_bom.get('components', [])}
    for entry in diff or []:
        change_type = entry.get('change_type')
        purl = entry.get('package_url') or ''
        key = purl or f"{entry.get('name', '')}@{entry.get('version', '')}"
        if change_type == 'added':
            comp = _component_from_diff_entry(entry)
            if comp:
                components[_component_key(comp)] = comp
        elif change_type == 'removed':
            components.pop(key, None)
    result = dict(base_bom)
    result['components'] = list(components.values())
    # The synthesized branch BOM no longer matches the base graph edges, so
    # drop dependencies to avoid asserting an inaccurate tree.
    result.pop('dependencies', None)
    return result


def fetch_and_write_bom(org, repo, out_path, branch=None, default_branch=None):
    """Fetch the GitHub SBOM for org/repo@branch and write CycloneDX to out_path.

    For the default branch (``branch`` None, or equal to ``default_branch``)
    this uses GitHub's SBOM export, which only covers the default branch.

    For a non-default branch, GitHub provides no SBOM, so we approximate it:
    take the default-branch SBOM as a base and apply the dependency-review
    diff (``default...branch``) on top. The result is approximate (see
    `apply_dependency_diff`).

    Returns (component_count, None) on success.
    Returns (None, error_msg) when the data needed isn't available.
    Raises github_client.GhError on unexpected API errors.
    """
    is_non_default = bool(branch) and bool(default_branch) and branch != default_branch

    if not is_non_default:
        spdx_data = github_client.fetch_dependency_sbom(org, repo)
        if spdx_data is None:
            return None, 'dependency graph not enabled'
        bom = spdx_to_cyclonedx(spdx_data, org, repo)
    else:
        diff = github_client.fetch_dependency_diff(org, repo, default_branch, branch)
        if diff is None:
            return None, (f'dependency diff unavailable for branch {branch!r} '
                          f'(no dependency snapshot on base/head commit)')
        spdx_data = github_client.fetch_dependency_sbom(org, repo)
        base_bom = (spdx_to_cyclonedx(spdx_data, org, repo)
                    if spdx_data is not None else _empty_bom(org, repo))
        bom = apply_dependency_diff(base_bom, diff)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as fh:
        json.dump(bom, fh, indent=2)
        fh.write('\n')

    return len(bom['components']), None
