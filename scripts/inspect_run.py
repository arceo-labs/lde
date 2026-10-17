#!/usr/bin/env python3
"""CLI wrapper around /api/runs/{id}/manifests + .../coverage.

Talks to the running orchestrator by default — useful when poking at a
live run without firing up a browser. Falls back to direct DB reads
when ``--offline`` is passed (the server isn't running).

Usage:
    python scripts/inspect_run.py <run_id> [--org] [--repo] [--diff <filepath>]
    python scripts/inspect_run.py <run_id> --coverage
    python scripts/inspect_run.py --latest

Examples:
    # Show every manifest in a run with original/sanitized dep counts.
    python scripts/inspect_run.py a22dc9fe

    # Diff one specific manifest.
    python scripts/inspect_run.py a22dc9fe --org example-org --repo aws-examples \\
                                  --diff s3-per-client-encryption/pyproject.toml

    # Run-wide coverage rollup.
    python scripts/inspect_run.py a22dc9fe --coverage

    # Most recent terminal run.
    python scripts/inspect_run.py --latest --coverage
"""

import argparse
import base64
import difflib
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = os.environ.get('LDE_BASE_URL', 'http://127.0.0.1:8002').rstrip('/')
DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'depexplorer.db',
)
_RUN_RE = re.compile(r'^[a-f0-9]+$', re.IGNORECASE)


def _http_get(base_url, path):
    url = base_url + path
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _resolve_run_id(prefix, base_url, offline):
    if not _RUN_RE.match(prefix or ''):
        sys.exit(f'Error: run_id must be hex, got {prefix!r}')
    if offline:
        conn = sqlite3.connect(DEFAULT_DB)
        try:
            rows = conn.execute(
                'SELECT id FROM runs WHERE id LIKE ?', (prefix + '%',)
            ).fetchall()
        finally:
            conn.close()
        if not rows:
            sys.exit(f'Error: no run starts with {prefix!r}')
        if len(rows) > 1:
            sys.exit(f'Error: ambiguous prefix {prefix!r} ({len(rows)} matches)')
        return rows[0][0]
    runs = _http_get(base_url, '/api/runs')
    matches = [r['id'] for r in runs if r['id'].startswith(prefix)]
    if not matches:
        sys.exit(f'Error: no run starts with {prefix!r}')
    if len(matches) > 1:
        sys.exit(f'Error: ambiguous prefix {prefix!r} ({len(matches)} matches)')
    return matches[0]


def _latest_run_id(base_url, offline):
    if offline:
        conn = sqlite3.connect(DEFAULT_DB)
        try:
            row = conn.execute(
                "SELECT id FROM runs WHERE status IN ('completed','partial','failed','stopped') "
                'ORDER BY started_at DESC LIMIT 1'
            ).fetchone()
        finally:
            conn.close()
        if not row:
            sys.exit('No terminal run found')
        return row[0]
    runs = _http_get(base_url, '/api/runs')
    for r in runs:
        if r.get('status') in ('completed', 'partial', 'failed', 'stopped'):
            return r['id']
    sys.exit('No terminal run found')


def _print_manifests_table(rows, org_filter, repo_filter):
    rows = [r for r in rows
            if (not org_filter or r['org'] == org_filter)
            and (not repo_filter or r['repo'] == repo_filter)]
    if not rows:
        print('No manifests matched.')
        return
    cols = ['repo', 'filepath', 'manifest_type', 'sanitized', 'orig→san']
    widths = {c: len(c) for c in cols}
    formatted = []
    for r in rows:
        repo = f'{r["org"]}/{r["repo"]}'
        diff = f'{r["original_dep_count"]}→{r["sanitized_dep_count"]}'
        san = 'yes' if r['sanitized'] else 'no'
        formatted.append((repo, r['filepath'], r['manifest_type'], san, diff))
        for k, v in zip(cols, formatted[-1]):
            widths[k] = max(widths[k], len(str(v)))
    fmt = '  '.join(f'{{:<{widths[c]}}}' for c in cols)
    print(fmt.format(*cols))
    print(fmt.format(*['-' * widths[c] for c in cols]))
    for row in formatted:
        print(fmt.format(*row))


def _print_diff(base_url, run_id, org, repo, filepath, offline):
    if offline:
        conn = sqlite3.connect(DEFAULT_DB)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                'SELECT original_content FROM manifests '
                'WHERE run_id=? AND org=? AND repo=? AND filepath=?',
                (run_id, org, repo, filepath),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            sys.exit(f'No manifest row for {org}/{repo} {filepath}')
        original = row['original_content'] or ''
        # Sanitized side: read from the sandbox if it still exists.
        sandbox = f'/tmp/dummy-repos/{run_id}/{org}__{repo}/{filepath}'
        try:
            with open(sandbox, errors='replace') as f:
                sanitized = f.read()
        except FileNotFoundError:
            sanitized = '<sandbox pruned>'
    else:
        b64 = base64.urlsafe_b64encode(filepath.encode()).decode().rstrip('=')
        body = _http_get(base_url, f'/api/runs/{run_id}/manifests/{org}/{repo}/{b64}')
        original = body.get('original') or ''
        sanitized = body.get('sanitized') or ''
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        sanitized.splitlines(keepends=True),
        fromfile=f'{org}/{repo}/{filepath} (original)',
        tofile=f'{org}/{repo}/{filepath} (sanitized)',
    )
    out = ''.join(diff)
    if not out:
        print('(files identical)')
    else:
        print(out, end='')


def _print_coverage(base_url, run_id, offline):
    if offline:
        conn = sqlite3.connect(DEFAULT_DB)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                'SELECT org, repo, manifest_count, ort_status, ort_package_count, '
                'dtrack_component_count, bom_overwrite_skipped, error '
                'FROM run_repos WHERE run_id = ? ORDER BY org, repo',
                (run_id,),
            ).fetchall()
        finally:
            conn.close()
        for r in rows:
            print(f'{r["org"]}/{r["repo"]}  manifests={r["manifest_count"]}  '
                  f'ort={r["ort_status"]}/{r["ort_package_count"]}  '
                  f'dt={r["dtrack_component_count"]}  '
                  f'overwrite_skipped={bool(r["bom_overwrite_skipped"])}')
        return
    body = _http_get(base_url, f'/api/runs/{run_id}/coverage')
    print(f'Run {run_id}')
    s = body.get('summary') or {}
    print(f'Summary: total={s.get("total")}  with_issue={s.get("with_issue")}  '
          f'no_manifests={s.get("no_manifests")}  '
          f'zero_packages={s.get("zero_packages_after_ort")}  '
          f'overwrites_refused={s.get("overwrites_refused")}')
    print()
    for r in body.get('repos') or []:
        marker = '!' if r.get('issue') else ' '
        print(f' {marker} {r["org"]}/{r["repo"]:<40} '
              f'manifests={r["manifest_count"]:<3} '
              f'sanitized_total={r["sanitized_dep_total"] or 0:<5} '
              f'ort={r["ort_package_count"] or "?":<5} '
              f'dt={r["dtrack_component_count"] or "?":<5} '
              f'{r.get("issue") or ""}')


def main():
    parser = argparse.ArgumentParser(description='Inspect manifests + coverage for a run.')
    parser.add_argument('run_id', nargs='?', help='Run ID or prefix')
    parser.add_argument('--latest', action='store_true', help='Use the most recent terminal run')
    parser.add_argument('--org', help='Filter by org')
    parser.add_argument('--repo', help='Filter by repo')
    parser.add_argument('--diff', metavar='FILEPATH',
                        help='Print original→sanitized unified diff for this manifest path')
    parser.add_argument('--coverage', action='store_true',
                        help='Run-level coverage rollup instead of per-manifest list')
    parser.add_argument('--base-url', default=DEFAULT_BASE_URL,
                        help=f'Server base URL (default: {DEFAULT_BASE_URL})')
    parser.add_argument('--offline', action='store_true',
                        help='Read directly from depexplorer.db without hitting the server')
    args = parser.parse_args()

    if args.latest:
        run_id = _latest_run_id(args.base_url, args.offline)
    elif args.run_id:
        run_id = _resolve_run_id(args.run_id, args.base_url, args.offline)
    else:
        parser.error('Pass a run_id or --latest')

    if args.coverage:
        _print_coverage(args.base_url, run_id, args.offline)
        return

    if args.diff:
        if not args.org or not args.repo:
            parser.error('--diff requires --org and --repo')
        _print_diff(args.base_url, run_id, args.org, args.repo, args.diff, args.offline)
        return

    if args.offline:
        conn = sqlite3.connect(DEFAULT_DB)
        conn.row_factory = sqlite3.Row
        try:
            rows = []
            for r in conn.execute(
                'SELECT org, repo, filepath, manifest_type, sanitized, original_content '
                'FROM manifests WHERE run_id = ? ORDER BY org, repo, filepath', (run_id,)
            ):
                # Fall back to None for dep counts in offline mode (no
                # parser available without importing the backend).
                rows.append({
                    'org': r['org'], 'repo': r['repo'], 'filepath': r['filepath'],
                    'manifest_type': r['manifest_type'],
                    'sanitized': bool(r['sanitized']),
                    'original_dep_count': '?',
                    'sanitized_dep_count': '?',
                })
        finally:
            conn.close()
    else:
        rows = _http_get(args.base_url, f'/api/runs/{run_id}/manifests')
    print(f'Run {run_id}')
    _print_manifests_table(rows, args.org, args.repo)


if __name__ == '__main__':
    main()
