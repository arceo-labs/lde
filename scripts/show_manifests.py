#!/usr/bin/env python3
"""Display sanitized manifests from a given run.

Reads manifest metadata from depexplorer.db and file content from the
on-disk sandbox (/tmp/dummy-repos/{run_id}/). The sandbox is retained
for the 10 most recent runs; older runs show metadata only.

Usage:
    python scripts/show_manifests.py <run_id> [options]

The run_id can be abbreviated to its first 8 hex characters.

Examples:
    python scripts/show_manifests.py a22dc9fe
    python scripts/show_manifests.py a22dc9fe --list
    python scripts/show_manifests.py a22dc9fe --org example-org --repo docgen
    python scripts/show_manifests.py a22dc9fe --type package.json
    python scripts/show_manifests.py a22dc9fe4d2d4623bdcf0a1337ce4dc3
"""

import argparse
import os
import re
import sqlite3
import sys
import tempfile

_RUN_ID_RE = re.compile(r'^[0-9a-f]+$', re.IGNORECASE)

DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'depexplorer.db',
)


def resolve_run_id(conn, prefix):
    if not _RUN_ID_RE.match(prefix):
        print(f'Error: run_id must be hexadecimal, got: {prefix!r}', file=sys.stderr)
        sys.exit(1)
    rows = conn.execute('SELECT id FROM runs WHERE id LIKE ?', (prefix + '%',)).fetchall()
    if not rows:
        print(f'Error: no run found matching {prefix!r}', file=sys.stderr)
        sys.exit(1)
    if len(rows) > 1:
        print(f'Error: ambiguous run_id {prefix!r} — matches {len(rows)} runs:', file=sys.stderr)
        for r in rows:
            print(f'  {r[0]}', file=sys.stderr)
        sys.exit(1)
    return rows[0][0]


def fetch_manifests(conn, run_id, org_filter, repo_filter, type_filter):
    query = (
        'SELECT org, repo, filepath, manifest_type, sanitized '
        'FROM manifests WHERE run_id = ?'
    )
    params = [run_id]
    if org_filter:
        query += ' AND org = ?'
        params.append(org_filter)
    if repo_filter:
        query += ' AND repo = ?'
        params.append(repo_filter)
    if type_filter:
        query += ' AND manifest_type = ?'
        params.append(type_filter)
    query += ' ORDER BY org, repo, filepath'
    return conn.execute(query, params).fetchall()


def _sandbox_path(run_id, org, repo, filepath):
    """Return the absolute sandbox path, or None if filepath would escape it."""
    base = os.path.join(tempfile.gettempdir(), 'dummy-repos')
    repo_dir = os.path.realpath(os.path.join(base, run_id, f'{org}__{repo}'))
    full = os.path.realpath(os.path.join(repo_dir, filepath))
    if not full.startswith(repo_dir + os.sep):
        return None
    return full


def _read(path):
    try:
        with open(path, 'r', errors='replace') as fh:
            return fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f'[read error: {exc}]'


def output_list(rows):
    if not rows:
        print('No manifests found.')
        return
    w_repo = max(len(f'{r[0]}/{r[1]}') for r in rows)
    w_path = max(len(r[2]) for r in rows)
    w_type = max(len(r[3]) for r in rows)
    fmt = f'{{:<{w_repo}}}  {{:<{w_path}}}  {{:<{w_type}}}  {{}}'
    print(fmt.format('REPO', 'PATH', 'TYPE', 'SANITIZED'))
    print(fmt.format('-' * w_repo, '-' * w_path, '-' * w_type, '---------'))
    for org, repo, filepath, mtype, sanitized in rows:
        print(fmt.format(f'{org}/{repo}', filepath, mtype, 'yes' if sanitized else 'no'))


def output_content(run_id, rows):
    if not rows:
        print('No manifests found.')
        return
    for i, (org, repo, filepath, _mtype, sanitized) in enumerate(rows):
        if i:
            print()
        flag = ' (sanitized)' if sanitized else ''
        print(f'=== {org}/{repo}: {filepath}{flag} ===')
        path = _sandbox_path(run_id, org, repo, filepath)
        if path is None:
            print('[skipped: unsafe path in DB record]')
            continue
        content = _read(path)
        if content is None:
            print('[not on disk — sandbox has been cleaned up]')
        else:
            print(content.rstrip())


def main():
    parser = argparse.ArgumentParser(
        description='Display sanitized manifests from a run.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('run_id', help='Run ID or abbreviated prefix (first 8+ hex chars)')
    parser.add_argument('--list', action='store_true',
                        help='Print a manifest table instead of file contents')
    parser.add_argument('--org', default=None, help='Filter by org name')
    parser.add_argument('--repo', default=None, help='Filter by repo name')
    parser.add_argument('--type', dest='manifest_type', default=None,
                        help='Filter by manifest type (e.g. package.json)')
    parser.add_argument('--db', default=DEFAULT_DB,
                        help=f'Path to depexplorer.db (default: auto-detected)')
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f'Error: database not found: {args.db}', file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    try:
        run_id = resolve_run_id(conn, args.run_id)
        rows = fetch_manifests(conn, run_id, args.org, args.repo, args.manifest_type)
    finally:
        conn.close()

    if args.list:
        output_list(rows)
    else:
        print(f'Run: {run_id}')
        print()
        output_content(run_id, rows)


if __name__ == '__main__':
    main()
