"""Track in-flight docker container IDs per pipeline run so Stop can kill them.

Without this, a stop request can only take effect between pipeline stages —
a single `docker run` invocation inside ort_runner / prelock blocks
`subprocess.run()` for minutes or hours.

How it's wired:

1. Each docker invocation creates a uniquely-named cidfile under
   `/tmp/depexplorer-cids/{run_id}/`.
2. The cidfile path is inserted into the docker command via `--cidfile`.
   Docker writes the full container ID to that file as soon as the
   container is created.
3. When `pipeline.request_stop(run_id)` is called, the HTTP handler also
   calls `kill_all(run_id)` here, which reads every cidfile in that run's
   dir and runs `docker kill <id>` on each. The killed containers exit
   with code 137, the blocked `subprocess.run` returns, and the pipeline
   thread sees the StopRequested event at its next stage boundary.
4. After each docker invocation returns, the wrapper removes its
   cidfile. On run termination, `cleanup_run` removes the per-run dir.
"""

import os
import shutil
import subprocess
import uuid

from . import log as log_mod

logger = log_mod.get('cid')

CID_ROOT = '/tmp/depexplorer-cids'

_RUN_ID_RE_CHARS = set('0123456789abcdef')


def _safe_run_id(run_id):
    """Reject anything that isn't a plain hex run_id — prevents path traversal."""
    if not run_id or not all(c in _RUN_ID_RE_CHARS for c in run_id):
        raise ValueError(f'invalid run_id: {run_id!r}')
    return run_id


def _run_dir(run_id):
    run_id = _safe_run_id(run_id)
    return os.path.join(CID_ROOT, run_id)


def new_cidfile(run_id):
    """Reserve a fresh cidfile path for a docker run.

    Returns the path. The file MUST NOT exist before docker writes to it
    (Docker refuses --cidfile if the target already exists), so this
    function unlinks any same-named file defensively.
    """
    d = _run_dir(run_id)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f'{uuid.uuid4().hex}.cid')
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return path


def cleanup_cidfile(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def kill_all(run_id):
    """Read every cidfile under this run's dir and docker kill each container.

    Returns the number of kill commands that exited zero. Tolerant of
    missing files (the docker invocation may have cleaned up already) and
    of docker errors (container may already be gone).
    """
    try:
        d = _run_dir(run_id)
    except ValueError:
        return 0
    if not os.path.isdir(d):
        return 0
    killed = 0
    for name in os.listdir(d):
        if not name.endswith('.cid'):
            continue
        path = os.path.join(d, name)
        try:
            with open(path) as f:
                cid = f.read().strip()
        except OSError:
            continue
        if not cid:
            continue
        try:
            proc = subprocess.run(
                ['docker', 'kill', cid],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            if proc.returncode == 0:
                killed += 1
                logger.info('killed container %s for run %s', cid[:12], run_id)
            else:
                logger.debug('docker kill %s exit=%d: %s',
                             cid[:12], proc.returncode,
                             log_mod.safe((proc.stderr or '').strip()[:200]))
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning('failed to kill container %s: %s', cid[:12], log_mod.safe(exc))
    return killed


def cleanup_run(run_id):
    """Remove the per-run cidfile dir. Called on pipeline termination."""
    try:
        d = _run_dir(run_id)
    except ValueError:
        return
    shutil.rmtree(d, ignore_errors=True)


def inject_cidfile(cmd, cidfile_path):
    """Insert `--cidfile <path>` into a docker command right after `docker run`.

    Raises ValueError if cmd doesn't look like a docker run invocation.
    """
    if len(cmd) < 2 or cmd[0] != 'docker' or cmd[1] != 'run':
        raise ValueError(f'not a docker run command: {cmd[:3]!r}')
    return cmd[:2] + ['--cidfile', cidfile_path] + cmd[2:]
