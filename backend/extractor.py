"""Walk GitHub orgs via the `gh` CLI and download manifest files into staging."""

import json
import os

from . import github_client, sanitizer, db, log as log_mod

logger = log_mod.get('extract')


# Exact-match basenames recognised as manifests.
MANIFEST_BASENAMES = {
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'requirements.txt',
    'dev_requirements.txt',
    'constraints.txt',
    'setup.py',
    'setup.cfg',
    'Pipfile',
    'Pipfile.lock',
    'pyproject.toml',
    'poetry.lock',
    'uv.lock',
    'pdm.lock',
    'pylock.toml',
    'go.mod',
    'go.sum',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
}

# Directory components we never recurse into when walking a remote tree.
# These either come from build/install artifacts that real source trees
# shouldn't ship, or they confuse ORT (e.g. duplicate analyzer projects
# from a vendored copy of a dep we already analyse from its own repo).
_SKIP_PATH_COMPONENTS = frozenset({
    'node_modules',
    'vendor',
    '__pycache__',
    '.venv',
    'venv',
    '.tox',
    '.git',
    'site-packages',
})


def _is_manifest(path):
    """Return True for paths whose basename matches a known manifest type.

    Recognises both the explicit basenames and the family of
    `requirements*.txt` files that real-world Python repos use
    (`requirements-dev.txt`, `requirements-prod.txt`,
    `requirements-test.txt`, `requirements-base.txt`, etc.). A previous
    fixed allowlist missed those entirely, which is why repos like
    `example-org/aws-examples` and `example-org/data-pipeline` were
    extracting only one manifest each despite shipping several.
    """
    base = path.rsplit('/', 1)[-1]
    if base in MANIFEST_BASENAMES:
        return True
    # `requirements*.txt` family (requirements-dev.txt, requirements_test.txt, etc.)
    if base.startswith('requirements') and base.endswith('.txt'):
        return True
    return False


def _path_is_skipped(path):
    """Return True when *path* contains a directory we never extract from."""
    parts = path.split('/')
    return any(part in _SKIP_PATH_COMPONENTS for part in parts[:-1])


def extract_org(run_id, org, sandbox_root, set_stage=None, repo_filter=None,
                run_branch=None):
    """Extract manifests for every non-archived repo in *org* into *sandbox_root*.

    *sandbox_root* is the per-run dir; this function creates
    `{sandbox_root}/{org}__{repo}/...` mirrored from the repo tree.

    *repo_filter* is an optional set of repo names; when provided, only repos
    whose name is in the set are extracted. Repos not in the filter are silently
    skipped (no DB row, no sandbox dir).

    *run_branch* is an optional run-level branch override. When set, every
    repo uses that branch; otherwise each repo uses its GitHub default
    branch. The resolved branch is stored in run_repos.default_branch and
    used to fetch the file tree.

    Returns a list of dicts: {repo, default_branch (= resolved branch),
    github_default_branch, is_default, sandbox_dir, manifests: [filepath...]}.
    """
    if set_stage:
        set_stage(f'extract:{org}:listing-repos')

    logger.info('org=%s listing repos…', log_mod.safe(org))
    repos = github_client.list_repos(org)
    logger.info('org=%s repos_found=%d', log_mod.safe(org), len(repos))
    if repo_filter:
        listed_names = {r for r, _ in repos}
        missing = repo_filter - listed_names
        if missing:
            logger.warning(
                'org=%s repo_filter: %d requested repo(s) absent from listing '
                '(empty/archived/non-existent): %s',
                log_mod.safe(org), len(missing), sorted(missing),
            )
        repos = [(r, b) for r, b in repos if r in repo_filter]
        logger.info('org=%s repo_filter=%s repos_after_filter=%d',
                    log_mod.safe(org), sorted(repo_filter), len(repos))
    else:
        missing = set()
    results = []

    conn = db.get_db()
    try:
        for repo_name in sorted(missing):
            conn.execute(
                'INSERT OR REPLACE INTO run_repos (run_id, org, repo, ort_status, error) '
                'VALUES (?,?,?,?,?)',
                (run_id, org, repo_name, 'skipped',
                 'not found in org listing — repo may be empty, archived, or non-existent'),
            )
        if missing:
            conn.commit()

        for idx, (repo, github_default_branch) in enumerate(repos):
            if set_stage:
                set_stage(f'extract:{org}:{repo} ({idx+1}/{len(repos)})')
            # Precedence: run-level override > GitHub default.
            branch = run_branch or github_default_branch
            is_default = (branch == github_default_branch)
            conn.execute(
                'INSERT OR REPLACE INTO run_repos (run_id, org, repo, default_branch) VALUES (?,?,?,?)',
                (run_id, org, repo, branch),
            )

            try:
                tree_paths = github_client.list_tree_paths(org, repo, branch)
            except github_client.GhError as exc:
                # Surface the failure in run_repos.error AND mark the
                # repo as skipped so _finalize doesn't claim "0 manifests"
                # without explanation. Without the explicit skipped marker,
                # the row stayed in `pending` with manifest_count=0 and
                # the only signal was a buried log line — which is how
                # example-org/nvd ended up looking like it had no
                # manifests when really the tree fetch was timing out.
                logger.warning('org=%s repo=%s tree-fetch failed: %s',
                               log_mod.safe(org), log_mod.safe(repo), log_mod.safe(exc))
                conn.execute(
                    'UPDATE run_repos SET ort_status = ?, error = ? '
                    'WHERE run_id=? AND org=? AND repo=?',
                    ('skipped', f'tree-fetch failed: {str(exc)[:400]}',
                     run_id, org, repo),
                )
                conn.commit()
                continue

            manifest_paths = [
                p for p in tree_paths
                if _is_manifest(p) and not _path_is_skipped(p)
            ]
            repo_sandbox = os.path.join(sandbox_root, f'{org}__{repo}')
            saved = []
            fetch_errors = 0

            for path in manifest_paths:
                try:
                    content = github_client.fetch_file(org, repo, path)
                except github_client.GhError as exc:
                    fetch_errors += 1
                    conn.execute(
                        'UPDATE run_repos SET error = ? WHERE run_id=? AND org=? AND repo=?',
                        (f'fetch {path}: {str(exc)[:300]}', run_id, org, repo),
                    )
                    continue

                full_path = os.path.join(repo_sandbox, path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'w') as f:
                    f.write(content)
                saved.append(path)

                # Persist the original blob alongside metadata so the
                # /api/runs/{id}/manifests/{org}/{repo}/{b64path} endpoint
                # can render an original-vs-sanitized diff after the
                # sandbox is cleaned (run_retention only keeps a few).
                conn.execute(
                    'INSERT OR REPLACE INTO manifests '
                    '(run_id, org, repo, filepath, manifest_type, sanitized, original_content) '
                    'VALUES (?,?,?,?,?,0,?)',
                    (run_id, org, repo, path, path.rsplit('/', 1)[-1], content),
                )

            conn.execute(
                'UPDATE run_repos SET manifest_count = ? WHERE run_id=? AND org=? AND repo=?',
                (len(saved), run_id, org, repo),
            )
            conn.commit()
            if fetch_errors:
                logger.info('org=%s repo=%s manifests=%d (fetch_errors=%d)',
                            log_mod.safe(org), log_mod.safe(repo),
                            len(saved), fetch_errors)
            else:
                logger.info('org=%s repo=%s manifests=%d',
                            log_mod.safe(org), log_mod.safe(repo), len(saved))

            results.append({
                'repo': repo,
                'default_branch': branch,
                'github_default_branch': github_default_branch,
                'is_default': is_default,
                'sandbox_dir': repo_sandbox,
                'manifests': saved,
            })
    finally:
        conn.close()

    return results
