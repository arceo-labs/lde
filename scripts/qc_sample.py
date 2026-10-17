#!/usr/bin/env python3
"""Quality-control sampling: verify sampled packages from live manifests appear in Dependency-Track.

Samples ~20% of repos per org from ``default_orgs`` (configured in
``.settings.json``), finds Python and JavaScript manifests in each, samples
3-5 direct dependencies per manifest, and checks each package against the
Dependency-Track instance.

Result classification per package:
  pass            — component found in the DT project for ``{org}/{repo}``,
                    with a purl matching the expected ecosystem (npm / pypi)
  found_elsewhere — component found in DT but under a different project
  fail            — component not found in DT at all
  error           — DT query failed (network / auth)

The CSV also includes an ``in_dt`` column (true/false) that combines
``pass`` and ``found_elsewhere`` into a single "exists anywhere in DT"
signal — useful for ecosystem-level coverage checks independently of
whether it landed in the expected per-repo project.

``@types/*`` TypeScript declaration packages are skipped by default
because ORT/CycloneDX excludes them from SBOMs (no runtime code, no CVE
surface).  Pass ``--include-type-defs`` to sample them anyway.

Usage:
    python scripts/qc_sample.py
    python scripts/qc_sample.py --target 50 --output qc_$(date +%Y%m%d).csv
    python scripts/qc_sample.py --seed 42 --sample-fraction 0.25
    python scripts/qc_sample.py --include-type-defs  # include @types/* packages

Credentials are resolved in priority order:
    1. CLI flags (--url / --api-key)
    2. Environment variables (DTRACK_URL / DTRACK_API_KEY)
    3. .settings.json keys (dtrack_url / dtrack_api_key)
    4. Hardcoded default URL (http://localhost:8081)
"""

import argparse
import csv
import json
import math
import os
import random
import re
import sys
from datetime import datetime, timezone

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SERVE_DIR)

# Manifest basenames we can extract direct deps from.  Lockfiles and
# executable build scripts (setup.py, build.gradle) are excluded because
# we can't reliably parse direct deps from them.
_PYTHON_BASENAMES = frozenset({
    'requirements.txt',
    'dev_requirements.txt',
    'constraints.txt',
    'pyproject.toml',
    'Pipfile',
})
_JS_BASENAMES = frozenset({'package.json'})


def _is_target_manifest(path):
    """True when *path* is a Python or JS manifest we can extract deps from."""
    base = path.rsplit('/', 1)[-1]
    if base in _PYTHON_BASENAMES or base in _JS_BASENAMES:
        return True
    # requirements-dev.txt, requirements-prod.txt, etc.
    if base.startswith('requirements') and base.endswith('.txt'):
        return True
    return False


def _manifest_lang(path):
    base = path.rsplit('/', 1)[-1]
    if base in _JS_BASENAMES:
        return 'javascript'
    return 'python'


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def _load_settings():
    path = os.path.join(SERVE_DIR, '.settings.json')
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# Package extraction per manifest type
# ---------------------------------------------------------------------------

def _extract_package_json(content):
    """Return [(name, version_spec)] from a package.json blob."""
    try:
        data = json.loads(content, strict=False)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    pkgs = []
    for section in ('dependencies', 'devDependencies'):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if spec.startswith(('file:', 'link:', 'workspace:', 'portal:')):
                continue
            pkgs.append((name, spec))
    return pkgs


# Flags and URL-like prefixes we unconditionally skip in requirements files.
_REQ_SKIP_RE = re.compile(
    r'^(-e\s|-r\s|--editable|--requirement|--index-url|--extra-index-url|'
    r'--trusted-host|--find-links|-c\s|#|git\+|svn\+|hg\+|bzr\+|https?://|file://)',
    re.IGNORECASE,
)
# First operator / whitespace / bracket separates name from version constraint.
_REQ_SPLIT_RE = re.compile(r'[\[><=!~^\s@]')


def _parse_req_line(line):
    """Parse one requirements.txt line into (name, version_spec) or None."""
    stripped = line.strip()
    if not stripped or _REQ_SKIP_RE.match(stripped):
        return None
    m = _REQ_SPLIT_RE.search(stripped)
    if m:
        name = stripped[:m.start()]
        version = stripped[m.start():].strip()
        # Drop extras like [security] that may appear before the version op.
        version = re.sub(r'^\[[^\]]*\]', '', version).strip()
    else:
        name = stripped
        version = '*'
    name = re.sub(r'\[.*?\]', '', name).strip()
    if not name or not re.match(r'^[A-Za-z0-9]', name):
        return None
    return (name, version or '*')


def _extract_requirements(content):
    pkgs = []
    for line in content.splitlines():
        result = _parse_req_line(line)
        if result:
            pkgs.append(result)
    return pkgs


def _extract_pyproject(content):
    try:
        import tomllib
    except ImportError:
        return []
    try:
        parsed = tomllib.loads(content)
    except Exception:
        return []
    pkgs = []

    # --- Poetry [tool.poetry.dependencies] / dev-dependencies / groups ---
    poetry = (parsed.get('tool') or {}).get('poetry') or {}
    for section_name in ('dependencies', 'dev-dependencies'):
        for name, spec in (poetry.get(section_name) or {}).items():
            if name.lower() == 'python':
                continue
            if isinstance(spec, str):
                pkgs.append((name, spec))
            elif isinstance(spec, dict) and 'path' not in spec:
                pkgs.append((name, spec.get('version') or '*'))
    for group_data in (poetry.get('group') or {}).values():
        for name, spec in (group_data.get('dependencies') or {}).items():
            if name.lower() == 'python':
                continue
            if isinstance(spec, str):
                pkgs.append((name, spec))
            elif isinstance(spec, dict) and 'path' not in spec:
                pkgs.append((name, spec.get('version') or '*'))

    # --- PEP 621 [project.dependencies] ---
    for dep_str in (parsed.get('project') or {}).get('dependencies') or []:
        if not isinstance(dep_str, str) or ' @ file:' in dep_str:
            continue
        m = re.match(r'^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)', dep_str)
        if m:
            name = m.group(1)
            version = dep_str[len(name):].strip() or '*'
            pkgs.append((name, version))

    return pkgs


def _extract_pipfile(content):
    try:
        import tomllib
    except ImportError:
        return []
    try:
        parsed = tomllib.loads(content)
    except Exception:
        return []
    pkgs = []
    for section in ('packages', 'dev-packages'):
        for name, spec in (parsed.get(section) or {}).items():
            if isinstance(spec, str):
                pkgs.append((name, spec))
            elif isinstance(spec, dict) and 'path' not in spec:
                pkgs.append((name, spec.get('version') or '*'))
    return pkgs


def extract_packages(manifest_path, content):
    """Dispatch to the per-format extractor; return [(name, version_spec)]."""
    base = manifest_path.rsplit('/', 1)[-1]
    if base == 'package.json':
        return _extract_package_json(content)
    if base == 'pyproject.toml':
        return _extract_pyproject(content)
    if base == 'Pipfile':
        return _extract_pipfile(content)
    # requirements*.txt and dev_requirements.txt / constraints.txt
    if (base.startswith('requirements') and base.endswith('.txt')
            or base in ('dev_requirements.txt', 'constraints.txt')):
        return _extract_requirements(content)
    return []


# ---------------------------------------------------------------------------
# Dependency-Track lookup
# ---------------------------------------------------------------------------

# Expected purl prefix per language ecosystem.  Components whose purl starts
# with a *different* known prefix are rejected as cross-ecosystem false
# matches (e.g. a Maven artifact named "react-dom" matching an npm query).
# Components with no purl at all are accepted — we can't determine their
# ecosystem and a miss is worse than a false pass at that point.
_PURL_PREFIX = {
    'javascript': 'pkg:npm/',
    'python': 'pkg:pypi/',
}


def _purl_matches_lang(purl, lang):
    """True when *purl* is compatible with *lang*, or when there is no purl."""
    if not purl:
        return True
    expected = _PURL_PREFIX.get(lang)
    if not expected:
        return True
    purl_lower = purl.lower()
    # Accept the expected ecosystem prefix.
    if purl_lower.startswith(expected):
        return True
    # Reject any other *known* ecosystem prefix — catches Maven, Go, etc.
    known = ('pkg:maven/', 'pkg:golang/', 'pkg:nuget/', 'pkg:gem/',
             'pkg:cargo/', 'pkg:composer/')
    return not any(purl_lower.startswith(k) for k in known)


def check_in_dtrack(base_url, api_key, package_name, expected_project, lang=''):
    """Return (result, dtrack_project, dtrack_component_version).

    *expected_project* is ``{org}/{repo}`` — the DT project name the pipeline
    creates for that repo.  *lang* is ``'javascript'`` or ``'python'``; when
    provided, components whose purl belongs to a different ecosystem are
    excluded so a Maven artifact named "react-dom" cannot masquerade as the
    npm package.

    result values:
      'pass'            — exact name match with correct ecosystem in *expected_project*
      'found_elsewhere' — exact name + ecosystem match but in a different project
      'fail'            — not found in DT (or only found in wrong ecosystem)
      'error'           — DT query raised an exception
    """
    from backend import dtrack_client
    try:
        rows = dtrack_client.search_components_by_name(base_url, api_key, package_name)
    except dtrack_client.DtrackError as exc:
        return 'error', '', str(exc)[:200]

    # Prefer exact case-insensitive name match (avoids false positives from
    # substring hits, e.g. searching "react" matching "react-dom").
    exact = [r for r in rows if r.get('component', '').lower() == package_name.lower()]
    if not exact:
        # Fall back to any result containing the name (handles Python
        # normalisation differences like Pillow vs pillow).
        exact = [r for r in rows
                 if package_name.lower() in r.get('component', '').lower()]

    # Filter to components whose purl matches the expected language ecosystem.
    if lang:
        exact = [r for r in exact if _purl_matches_lang(r.get('purl', ''), lang)]

    if not exact:
        return 'fail', '', ''

    in_expected = [r for r in exact
                   if r.get('project', '').lower() == expected_project.lower()]
    if in_expected:
        r = in_expected[0]
        return 'pass', r.get('project', ''), r.get('component_version', '')

    r = exact[0]
    return 'found_elsewhere', r.get('project', ''), r.get('component_version', '')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    settings = _load_settings()

    parser = argparse.ArgumentParser(
        description='QC: sample packages from live manifests and verify presence in Dependency-Track.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--target', type=int, default=50,
                        help='Target number of test cases (default: 50)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed for reproducible sampling')
    parser.add_argument('--sample-fraction', type=float, default=0.20,
                        help='Fraction of repos to sample per org (default: 0.20)')
    parser.add_argument('--min-packages', type=int, default=3,
                        help='Min packages sampled per manifest (default: 3)')
    parser.add_argument('--max-packages', type=int, default=5,
                        help='Max packages sampled per manifest (default: 5)')
    parser.add_argument('--output', default=None,
                        help='Output CSV path (default: stdout)')
    parser.add_argument('--url', default=None,
                        help='Dependency-Track base URL (env: DTRACK_URL)')
    parser.add_argument('--api-key', default=None,
                        help='Dependency-Track API key (env: DTRACK_API_KEY)')
    parser.add_argument('--orgs', nargs='+', default=None,
                        help='Override default_orgs from settings')
    parser.add_argument('--include-type-defs', action='store_true', default=False,
                        help='Include @types/* TypeScript declaration packages in '
                             'sampling (default: skip — excluded from SBOMs by design)')
    args = parser.parse_args()

    url = (args.url
           or os.environ.get('DTRACK_URL')
           or settings.get('dtrack_url')
           or 'http://localhost:8081')
    api_key = (args.api_key
               or os.environ.get('DTRACK_API_KEY')
               or settings.get('dtrack_api_key')
               or '')
    if not api_key:
        print('Error: --api-key, DTRACK_API_KEY, or dtrack_api_key in .settings.json required.',
              file=sys.stderr)
        sys.exit(1)

    orgs = args.orgs or settings.get('default_orgs') or []
    if not orgs:
        print('Error: no orgs configured. Set default_orgs in .settings.json or pass --orgs.',
              file=sys.stderr)
        sys.exit(1)

    if args.min_packages > args.max_packages:
        print('Error: --min-packages must be <= --max-packages', file=sys.stderr)
        sys.exit(1)

    rng = random.Random(args.seed)

    from backend import github_client
    from backend.extractor import _is_manifest, _path_is_skipped

    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f'[qc_sample] {ts}  target={args.target}  '
          f'fraction={args.sample_fraction:.0%}  '
          f'seed={args.seed}  orgs={orgs}',
          file=sys.stderr)

    # ------------------------------------------------------------------
    # Phase 1: walk orgs → sample repos → fetch manifests → collect candidates
    # ------------------------------------------------------------------
    # Each candidate: (org, repo, manifest_path, manifest_type, pkg_name, pkg_version)
    candidates = []

    for org in orgs:
        print(f'\n[{org}] listing repos…', file=sys.stderr)
        try:
            all_repos = github_client.list_repos(org)
        except github_client.GhError as exc:
            print(f'[{org}] WARN: could not list repos: {exc}', file=sys.stderr)
            continue

        sample_n = max(1, math.ceil(len(all_repos) * args.sample_fraction))
        sampled = rng.sample(all_repos, min(sample_n, len(all_repos)))
        print(f'[{org}] {len(all_repos)} repos → sampling {len(sampled)} '
              f'({args.sample_fraction:.0%})', file=sys.stderr)

        for repo_name, branch in sampled:
            print(f'  {repo_name}… ', file=sys.stderr, end='', flush=True)
            try:
                tree_paths = github_client.list_tree_paths(org, repo_name, branch)
            except github_client.GhError as exc:
                print(f'tree-fetch failed: {exc}', file=sys.stderr)
                continue

            manifest_paths = [
                p for p in tree_paths
                if _is_manifest(p) and not _path_is_skipped(p) and _is_target_manifest(p)
            ]
            if not manifest_paths:
                print('no python/js manifests', file=sys.stderr)
                continue

            repo_total = 0
            for mpath in manifest_paths:
                try:
                    content = github_client.fetch_file(org, repo_name, mpath)
                except github_client.GhError:
                    continue

                pkgs = extract_packages(mpath, content)
                if not pkgs:
                    continue

                lang = _manifest_lang(mpath)
                if not args.include_type_defs:
                    pkgs = [(n, v) for n, v in pkgs
                            if not (lang == 'javascript' and n.startswith('@types/'))]
                if not pkgs:
                    continue

                n = min(rng.randint(args.min_packages, args.max_packages), len(pkgs))
                sampled_pkgs = rng.sample(pkgs, n)
                mtype = mpath.rsplit('/', 1)[-1]
                for pkg_name, pkg_version in sampled_pkgs:
                    candidates.append((org, repo_name, mpath, mtype, lang,
                                       pkg_name, pkg_version))
                    repo_total += 1

            print(f'{len(manifest_paths)} manifest(s), {repo_total} package sample(s)',
                  file=sys.stderr)

    if not candidates:
        print('\nNo candidates found — nothing to test.', file=sys.stderr)
        sys.exit(0)

    # Shuffle so orgs/repos are interleaved then cap at target
    rng.shuffle(candidates)
    test_cases = candidates[:args.target]

    print(f'\n{len(candidates)} total candidates collected; '
          f'testing {len(test_cases)} (target={args.target})', file=sys.stderr)

    # ------------------------------------------------------------------
    # Phase 2: Dependency-Track checks
    # ------------------------------------------------------------------
    fieldnames = [
        'org', 'repo', 'manifest_path', 'manifest_type', 'language',
        'package_name', 'package_version_spec',
        'in_dt', 'dtrack_result', 'dtrack_project', 'dtrack_component_version',
    ]

    rows = []
    counts = {'pass': 0, 'found_elsewhere': 0, 'fail': 0, 'error': 0}

    for i, (org, repo, mpath, mtype, lang, pkg_name, pkg_version) in \
            enumerate(test_cases, 1):
        expected_project = f'{org}/{repo}'
        safe_name = pkg_name.replace('\n', ' ').replace('\r', ' ').replace('\x00', '')
        print(f'  [{i:>3}/{len(test_cases)}] {safe_name:<40} '
              f'({expected_project})… ', file=sys.stderr, end='', flush=True)

        result, dt_project, dt_version = check_in_dtrack(
            url, api_key, pkg_name, expected_project, lang=lang)
        counts[result] = counts.get(result, 0) + 1

        in_dt = result in ('pass', 'found_elsewhere')
        status_icon = {'pass': '✓', 'found_elsewhere': '~', 'fail': '✗',
                       'error': '!'}.get(result, '?')
        print(f'{status_icon} {result}  (in_dt={in_dt})', file=sys.stderr)

        rows.append({
            'org': org,
            'repo': repo,
            'manifest_path': mpath,
            'manifest_type': mtype,
            'language': lang,
            'package_name': pkg_name,
            'package_version_spec': pkg_version,
            'in_dt': 'true' if in_dt else 'false',
            'dtrack_result': result,
            'dtrack_project': dt_project,
            'dtrack_component_version': dt_version,
        })

    total = len(rows)
    in_dt_count = counts['pass'] + counts['found_elsewhere']
    pass_pct    = 100 * counts['pass'] / total if total else 0
    in_dt_pct   = 100 * in_dt_count / total if total else 0
    print(
        f'\n── Summary ──────────────────────────────────────────────────\n'
        f'  Total cases      : {total}\n'
        f'  in_dt (pass+else): {in_dt_count}  ({in_dt_pct:.1f}%)\n'
        f'    pass           : {counts["pass"]}  ({pass_pct:.1f}%)\n'
        f'    found_elsewhere: {counts["found_elsewhere"]}\n'
        f'  fail             : {counts["fail"]}\n'
        f'  error            : {counts["error"]}\n'
        f'─────────────────────────────────────────────────────────────',
        file=sys.stderr,
    )

    # ------------------------------------------------------------------
    # Phase 3: write CSV
    # ------------------------------------------------------------------
    if args.output:
        out_path = args.output
        out_f = open(out_path, 'w', newline='', encoding='utf-8')
    else:
        out_f = sys.stdout
        out_path = '<stdout>'

    writer = csv.DictWriter(out_f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

    if args.output:
        out_f.close()
        print(f'Results written to {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
