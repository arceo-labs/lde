#!/usr/bin/env python3
"""CLI wrapper around DT cross-project component search.

Useful for verifying that a class of components (e.g. ``@tanstack/*``)
actually landed in DT for the projects that should declare them.

Usage:
    python scripts/dtrack_search.py <query> [--format text|json|csv]
                                            [--url URL] [--api-key KEY]

Examples:
    python scripts/dtrack_search.py @tanstack
    python scripts/dtrack_search.py react --format csv > react-projects.csv

Reads DTRACK_URL / DTRACK_API_KEY from the environment when ``--url`` /
``--api-key`` aren't passed; falls back to ``.settings.json`` in the
project root.
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


def _group_by_project(components):
    groups = {}
    for c in components:
        for proj in (c.get('projects') or [{'name': '?'}]):
            name = proj.get('name') or '?'
            groups.setdefault(name, []).append({
                'name': c.get('name') or '',
                'group': c.get('group') or '',
                'version': c.get('version') or '',
                'purl': c.get('purl') or '',
            })
    return groups


def _print_text(query, groups):
    print(f'Query: {query}')
    print(f'Projects: {len(groups)}')
    print(f'Components: {sum(len(v) for v in groups.values())}')
    print()
    for project, comps in sorted(groups.items()):
        print(f'■ {project}  ({len(comps)} component(s))')
        for c in comps:
            ver = f'@{c["version"]}' if c['version'] else ''
            grp = f'{c["group"]}/' if c['group'] else ''
            print(f'    {grp}{c["name"]}{ver}')
        print()


def _print_json(query, groups):
    print(json.dumps({
        'query': query,
        'projects': [{'name': k, 'components': v} for k, v in sorted(groups.items())],
    }, indent=2))


def _print_csv(query, groups):
    writer = csv.writer(sys.stdout)
    writer.writerow(['query', 'project', 'name', 'group', 'version', 'purl'])
    for project, comps in sorted(groups.items()):
        for c in comps:
            writer.writerow([query, project, c['name'], c['group'], c['version'], c['purl']])


def main():
    parser = argparse.ArgumentParser(description='Cross-project DT component search.')
    parser.add_argument('query', help='Search text (matches name/group/version/purl)')
    parser.add_argument('--url', default=os.environ.get('DTRACK_URL'),
                        help='DT base URL (default: $DTRACK_URL or .settings.json)')
    parser.add_argument('--api-key', default=os.environ.get('DTRACK_API_KEY'),
                        help='DT API key (default: $DTRACK_API_KEY or .settings.json)')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    args = parser.parse_args()

    if not args.url or not args.api_key:
        s = _load_settings()
        args.url = args.url or s.get('dtrack_url')
        args.api_key = args.api_key or s.get('dtrack_api_key')
    if not args.url or not args.api_key:
        sys.exit('Error: DT URL/API key required (--url/--api-key, env, or .settings.json)')

    from backend import dtrack_client
    try:
        components = dtrack_client.search_components(args.url, args.api_key, args.query)
    except dtrack_client.DtrackError as exc:
        sys.exit(f'Error: {exc}')

    groups = _group_by_project(components)
    if args.format == 'json':
        _print_json(args.query, groups)
    elif args.format == 'csv':
        _print_csv(args.query, groups)
    else:
        _print_text(args.query, groups)


if __name__ == '__main__':
    main()
