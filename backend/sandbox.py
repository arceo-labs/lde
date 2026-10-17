"""Per-run staging sandbox under /tmp/dummy-repos/{run_id}/."""

import os
import shutil
import tempfile


def root_for_run(run_id):
    return os.path.join(tempfile.gettempdir(), 'dummy-repos', run_id)


def prepare(run_id):
    """Create (or clear) the per-run sandbox root and return its path."""
    path = root_for_run(run_id)
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)
    return path


def repo_dir(run_id, org, repo):
    return os.path.join(root_for_run(run_id), f'{org}__{repo}')


def write_file(run_id, org, repo, rel_path, content):
    """Write *content* to the staged file at *rel_path*, creating parents."""
    full = os.path.join(repo_dir(run_id, org, repo), rel_path)
    os.makedirs(os.path.dirname(full) or '.', exist_ok=True)
    with open(full, 'w') as f:
        f.write(content)
    return full


def cleanup_old_runs(keep):
    """Remove all but the *keep* most recent run dirs under dummy-repos/."""
    parent = os.path.join(tempfile.gettempdir(), 'dummy-repos')
    if not os.path.isdir(parent):
        return
    entries = []
    for name in os.listdir(parent):
        path = os.path.join(parent, name)
        if os.path.isdir(path):
            entries.append((os.path.getmtime(path), path))
    entries.sort(reverse=True)
    for _, path in entries[keep:]:
        shutil.rmtree(path, ignore_errors=True)
