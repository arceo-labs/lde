#!/usr/bin/env python3
"""Query Dependency-Track for all components across all projects.

Single-sourced: uses ``backend.dtrack_client.list_projects /
list_components / search_components_by_name`` so the same code path is
exercised by the server's ``/api/runs/{id}/coverage`` endpoint and the
``inspect_run`` / ``dtrack_search`` siblings.

Usage:
    python scripts/dtrack_components.py [options]

Credentials are resolved in priority order:
    1. CLI flags (--url / --api-key)
    2. Environment variables (DTRACK_URL / DTRACK_API_KEY)
    3. .settings.json keys (dtrack_url / dtrack_api_key)
    4. Hardcoded default URL (http://localhost:8081)

Examples:
    python scripts/dtrack_components.py
    python scripts/dtrack_components.py --format csv > components.csv
    python scripts/dtrack_components.py --filter requests
    python scripts/dtrack_components.py --url http://localhost:8081 --api-key abc123
"""

import argparse
import csv
import json
import os
import sys

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SERVE_DIR)


def _load_settings():
    path = os.path.join(SERVE_DIR, '.settings.json')
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def collect_rows(base_url, api_key):
    """Aggregate (project, component) tuples across the entire DT portfolio.

    Full dump — use only when no name filter is supplied.  When a filter is
    given, call ``collect_rows_filtered`` instead to let DT do the filtering
    server-side.
    """
    from backend import dtrack_client
    rows = []
    projects = dtrack_client.list_projects(base_url, api_key)
    for proj in projects:
        proj_name = proj.get('name', '')
        proj_version = proj.get('version', '')
        proj_uuid = proj.get('uuid', '')
        if not proj_uuid:
            continue
        try:
            components = dtrack_client.list_components(base_url, api_key, proj_uuid)
        except dtrack_client.DtrackError as exc:
            print(f'[warn] skipping project {proj_name}: {exc}', file=sys.stderr)
            continue
        for comp in components:
            c_group = comp.get('group') or ''
            c_name  = comp.get('name')  or ''
            c_full  = f'{c_group}/{c_name}' if c_group else c_name
            rows.append({
                'project': proj_name,
                'project_version': proj_version,
                'component': c_full,
                'component_version': comp.get('version', ''),
                'purl': comp.get('purl', ''),
            })
    return rows


def collect_rows_filtered(base_url, api_key, name_filter):
    """Server-side name search — returns only components matching *name_filter*.

    Uses ``/v1/component/identity?name=<name_filter>`` so DT filters
    before serialising.  Avoids downloading the full portfolio (which can
    be hundreds of MB) just to client-side grep a handful of results.
    """
    from backend import dtrack_client
    return dtrack_client.search_components_by_name(base_url, api_key, name_filter)


def output_table(rows):
    if not rows:
        print('No components found.')
        return
    col_widths = {k: len(k) for k in rows[0]}
    for r in rows:
        for k, v in r.items():
            col_widths[k] = max(col_widths[k], len(v))

    headers = list(rows[0].keys())
    sep = '  '.join('-' * col_widths[h] for h in headers)
    header_line = '  '.join(h.upper().ljust(col_widths[h]) for h in headers)
    print(header_line)
    print(sep)
    for r in rows:
        print('  '.join(r[h].ljust(col_widths[h]) for h in headers))


def output_json(rows):
    print(json.dumps(rows, indent=2))


def output_csv(rows):
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)


def main():
    settings = _load_settings()

    parser = argparse.ArgumentParser(description='List all Dependency-Track components with project info.')
    parser.add_argument('--url', default=None,
                        help='Dependency-Track base URL (env: DTRACK_URL, or dtrack_url in .settings.json)')
    parser.add_argument('--api-key', default=None,
                        help='Dependency-Track API key (env: DTRACK_API_KEY, or dtrack_api_key in .settings.json)')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--filter', metavar='NAME', default=None,
                        help='Only show components matching NAME (case-insensitive). '
                             'Uses DT\'s server-side Lucene search followed by a client-side '
                             'precision filter, so multi-part queries like "@wordpress/scripts" '
                             'or "@babel/core" return only exact matches rather than anything '
                             'containing either token. Much faster than a full portfolio dump.')
    args = parser.parse_args()

    # Resolve credentials: CLI flag > env var > .settings.json > built-in default.
    url = (args.url
           or os.environ.get('DTRACK_URL')
           or settings.get('dtrack_url')
           or 'http://localhost:8081')
    api_key = (args.api_key
               or os.environ.get('DTRACK_API_KEY')
               or settings.get('dtrack_api_key')
               or '')

    if not api_key:
        print('Error: --api-key, DTRACK_API_KEY, or .settings.json:dtrack_api_key required.',
              file=sys.stderr)
        sys.exit(1)

    from backend import dtrack_client
    try:
        if args.filter:
            rows = collect_rows_filtered(url, api_key, args.filter)
        else:
            rows = collect_rows(url, api_key)
    except dtrack_client.DtrackError as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)

    if args.format == 'json':
        output_json(rows)
    elif args.format == 'csv':
        output_csv(rows)
    else:
        output_table(rows)


if __name__ == '__main__':
    main()
