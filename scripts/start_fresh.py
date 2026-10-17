#!/usr/bin/env python3
"""Start the local LDE stack from a clean slate.

Starts Docker and Dependency-Track, deletes LDE's database and runs/ (or moves
them into a timestamped backup folder with --backup), deletes every
Dependency-Track project, then starts
server.py and checks it. Preflight is read-only: Docker Desktop and
`docker compose up` run only after the summary is confirmed.

Never print the admin password, the session token, or the API key. Secrets are
read only from files.

See docs/start-fresh.md.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SERVE_DIR)

from backend import db as lde_db  # noqa: E402  (needs SERVE_DIR on sys.path)

DEFAULT_PORT = 8002
DEFAULT_DTRACK_URL = 'http://127.0.0.1:8081'
DEFAULT_PASSWORD_FILE = os.path.expanduser('~/.lde/dtrack-admin.txt')
DEFAULT_BACKUP_ROOT = os.path.expanduser('~/.lde/backups')
DTRACK_SERVICES = ['dtrack-apiserver', 'dtrack-frontend']
LDE_STATE_NAMES = ['depexplorer.db', 'depexplorer.db-shm', 'depexplorer.db-wal', 'runs']
PAGE_SIZE = 100
RECOVERY_DOC = 'docs/start-fresh.md#recover-the-dependency-track-admin-password'


def _load_bootstrap():
    path = os.path.join(SERVE_DIR, 'scripts', 'bootstrap_dtrack.py')
    spec = importlib.util.spec_from_file_location('bootstrap_dtrack', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_bootstrap = _load_bootstrap()


def log(msg):
    print(f'[start_fresh] {msg}', flush=True)


# ---------------------------------------------------------------------------
# Docker and Dependency-Track
# ---------------------------------------------------------------------------

def docker_ready():
    try:
        return subprocess.run(['docker', 'info'], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_docker(timeout=180):
    if docker_ready():
        return
    if sys.platform != 'darwin':
        raise RuntimeError('Docker daemon is not running. Start it and re-run.')
    log('Starting Docker Desktop...')
    subprocess.run(['open', '-a', 'Docker'], check=True, timeout=30)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if docker_ready():
            return
        time.sleep(2)
    raise RuntimeError(f'Docker did not become ready within {timeout}s.')


def check_dtrack_url_is_local(url):
    """Raise unless *url*'s host resolves only to loopback addresses.

    This script's contract is local-only: it deletes every Dependency-Track
    project at --dtrack-url with no further confirmation of *that* host. A
    typo or a copy-pasted remote URL must not be able to wipe a shared or
    production Dependency-Track instance.
    """
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        raise RuntimeError(f'--dtrack-url {url!r} has no hostname')
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise RuntimeError(f'--dtrack-url {url!r} host {host!r} did not resolve: {exc}') from exc
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        if not ipaddress.ip_address(addr).is_loopback:
            raise RuntimeError(
                f'--dtrack-url {url!r} resolves to {addr}, which is not loopback. '
                f'This script only deletes Dependency-Track projects on a local instance; '
                f'pass a 127.0.0.1/::1/localhost URL.'
            )


def dtrack_ready(url):
    """True when GET /api/version already returns 200. Does not start compose."""
    try:
        status, _, _ = _bootstrap._request('GET', url, '/api/version')
        return status == 200
    except (urllib.error.URLError, OSError):
        return False


def ensure_dtrack(url, timeout=300):
    log('Starting Dependency-Track (docker compose up -d)...')
    subprocess.run(['docker', 'compose', 'up', '-d'] + DTRACK_SERVICES,
                   cwd=SERVE_DIR, check=True, timeout=900)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if dtrack_ready(url):
            return
        time.sleep(5)
    raise RuntimeError(f'Dependency-Track API at {url} not ready within {timeout}s.')


def read_password_file(path):
    with open(path) as fh:
        lines = fh.read().split('\n')
    if len(lines) < 2 or not lines[0].strip() or not lines[1]:
        raise ValueError(f'{path}: need username on line 1 and password on line 2')
    return lines[0].strip(), lines[1]


def dtrack_login(url, username, password):
    status, body = _bootstrap.login(url, username, password)
    if status != 200:
        # Error bodies are reason codes (INVALID_CREDENTIALS, ...), never the token.
        reason = body.strip()[:80] or f'HTTP {status}'
        raise RuntimeError(
            f'Dependency-Track admin login failed (HTTP {status}: {reason}). '
            f'Nothing was changed. See {RECOVERY_DOC}'
        )
    return body.strip()


def list_projects(url, token):
    projects = []
    page = 1
    while True:
        path = f'/api/v1/project?pageSize={PAGE_SIZE}&pageNumber={page}'
        status, raw, _ = _bootstrap._request('GET', url, path, token=token)
        if status != 200:
            raise RuntimeError(f'list projects failed: HTTP {status}')
        batch = json.loads(raw.decode())
        projects.extend(batch)
        if len(batch) < PAGE_SIZE:
            return projects
        page += 1


def delete_projects(url, token, projects):
    """Delete every project. 404 counts as deleted: removing a parent removes its children."""
    for project in projects:
        status, raw, _ = _bootstrap._request(
            'DELETE', url, f'/api/v1/project/{project["uuid"]}', token=token)
        if status not in (200, 204, 404):
            detail = raw.decode(errors='replace').strip()[:100] or f'HTTP {status}'
            raise RuntimeError(f'delete {project.get("name")} failed: {detail}')
        log(f'  deleted {project.get("name")} {project.get("version") or ""}'.rstrip())
    remaining = list_projects(url, token)
    if remaining:
        raise RuntimeError(f'{len(remaining)} project(s) still present after delete')


# ---------------------------------------------------------------------------
# LDE process and on-disk state
# ---------------------------------------------------------------------------

def is_lde_server(cmdline, cwd, repo=SERVE_DIR):
    """True when cmdline runs this repo's server.py (absolute, or relative to cwd)."""
    repo = os.path.realpath(repo)
    for arg in cmdline.split():
        if os.path.basename(arg) != 'server.py':
            continue
        path = arg if os.path.isabs(arg) else os.path.join(cwd or '', arg)
        if os.path.realpath(path) == os.path.join(repo, 'server.py'):
            return True
    return False


def port_listeners(port):
    """Return [(pid, cmdline, cwd)] for processes listening on the TCP port."""
    out = subprocess.run(['lsof', '-nP', f'-tiTCP:{port}', '-sTCP:LISTEN'],
                         capture_output=True, text=True, timeout=20).stdout
    listeners = []
    for pid in sorted({int(p) for p in out.split()}):
        cmd = subprocess.run(['ps', '-o', 'command=', '-p', str(pid)],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        cwd_out = subprocess.run(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'],
                                 capture_output=True, text=True, timeout=20).stdout
        cwd = next((line[1:] for line in cwd_out.splitlines() if line.startswith('n')), '')
        listeners.append((pid, cmd, cwd))
    return listeners


def check_port_owner(listeners, port):
    """Raise unless every listener is this repo's server.py."""
    for pid, cmd, cwd in listeners:
        if not is_lde_server(cmd, cwd):
            raise RuntimeError(
                f'port {port} is held by PID {pid} ({cmd or "unknown"}), which is not '
                f'this repo\'s server.py. Stop it yourself or pass --port.'
            )


def stop_lde(listeners, port, timeout=15):
    for pid, _, _ in listeners:
        log(f'Stopping LDE (PID {pid})...')
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not port_listeners(port):
            return
        time.sleep(0.25)
    for pid, _, _ in listeners:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def lde_state(data_dir):
    """Describe LDE state in data_dir: existing paths plus run and repo counts."""
    paths = [os.path.join(data_dir, n) for n in LDE_STATE_NAMES]
    existing = [p for p in paths if os.path.exists(p)]
    runs = repos = None
    db_path = os.path.join(data_dir, 'depexplorer.db')
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            try:
                runs = conn.execute('SELECT COUNT(*) FROM runs').fetchone()[0]
                repos = conn.execute('SELECT COUNT(*) FROM run_repos').fetchone()[0]
            finally:
                conn.close()
        except sqlite3.Error:
            pass
    return {'paths': existing, 'runs': runs, 'repos': repos}


def delete_lde_state(paths, data_dir):
    """Permanently delete LDE state. Only allowlisted names directly in data_dir."""
    base = os.path.realpath(data_dir)
    for path in paths:
        if os.path.basename(path) not in LDE_STATE_NAMES:
            raise RuntimeError(f'refusing to delete {path}: not an LDE state file')
        if os.path.islink(path):
            raise RuntimeError(f'refusing to delete {path}: it is a symlink')
        real = os.path.realpath(path)
        if os.path.dirname(real) != base:
            raise RuntimeError(f'refusing to delete {path}: outside {data_dir}')
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def move_lde_state(paths, backup_root, stamp):
    """Move paths into backup_root/lde-local-<stamp>/ (mode 0700). Never deletes."""
    if not paths:
        return None
    os.makedirs(backup_root, mode=0o700, exist_ok=True)
    dest = os.path.join(backup_root, f'lde-local-{stamp}')
    os.mkdir(dest, 0o700)
    for path in paths:
        shutil.move(path, os.path.join(dest, os.path.basename(path)))
    return dest


# ---------------------------------------------------------------------------
# Start and check LDE
# ---------------------------------------------------------------------------

def _get_json(port, path, timeout=30):
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode() or 'null')
    except urllib.error.HTTPError as exc:
        return exc.code, None


def start_lde(port, timeout=60):
    log(f'Starting LDE on http://127.0.0.1:{port} ...')
    proc = subprocess.Popen([sys.executable, 'server.py', '--port', str(port)], cwd=SERVE_DIR)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f'server.py exited with code {proc.returncode}')
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=5) as resp:
                if resp.status == 200:
                    return proc
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    proc.terminate()
    raise RuntimeError(f'LDE did not answer on port {port} within {timeout}s')


def check_lde(port, expect_empty):
    """Return a list of failure strings; warnings are logged, not returned."""
    failures = []
    status, runs = _get_json(port, '/api/runs')
    if status == 401:
        log('WARN Basic Auth is enabled locally; skipping API checks.')
        return failures
    if status != 200:
        failures.append(f'/api/runs returned HTTP {status}')
    elif expect_empty and runs:
        failures.append(f'/api/runs returned {len(runs)} run(s), expected none')
    else:
        log(f'OK   /api/runs: {len(runs or [])} run(s)')

    status, dt = _get_json(port, '/api/dtrack-status')
    if status == 200 and dt and dt.get('ok'):
        log(f'OK   Dependency-Track: {dt.get("message")}')
    else:
        failures.append(f'/api/dtrack-status not ok: {(dt or {}).get("message") or status}')

    status, gh = _get_json(port, '/api/gh-status')
    if status == 200 and gh and gh.get('logged_in'):
        log('OK   GitHub: authenticated')
    else:
        log(f'WARN GitHub: {(gh or {}).get("raw") or status}. github_sbom runs will fail.')
    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def confirm(summary, assume_yes):
    print('\nThis will:\n' + '\n'.join(f'  - {line}' for line in summary) + '\n', flush=True)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise RuntimeError('no terminal to confirm on; pass --yes')
    return input('Continue? [y/N] ').strip().lower() in ('y', 'yes')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Start the local LDE stack from a clean slate.')
    parser.add_argument('--keep-data', action='store_true',
                        help='Restart only; keep LDE data and Dependency-Track projects')
    parser.add_argument('--keep-dtrack', action='store_true',
                        help='Clear LDE data but keep Dependency-Track projects')
    parser.add_argument('--backup', action='store_true',
                        help='Move cleared LDE data to the backup folder instead of deleting it')
    parser.add_argument('--yes', '-y', action='store_true', help='Skip the confirmation prompt')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--dtrack-url', default=DEFAULT_DTRACK_URL)
    parser.add_argument('--dtrack-password-file', default=DEFAULT_PASSWORD_FILE)
    parser.add_argument('--backup-root', default=DEFAULT_BACKUP_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    clear_lde = not args.keep_data
    clear_dtrack = not (args.keep_data or args.keep_dtrack)
    data_dir = lde_db.DATA_DIR

    check_dtrack_url_is_local(args.dtrack_url)

    # 1. Preflight: read-only. Docker Desktop and compose up wait until confirm().
    if not docker_ready() and sys.platform != 'darwin':
        raise RuntimeError('Docker daemon is not running. Start it and re-run.')
    listeners = port_listeners(args.port)
    check_port_owner(listeners, args.port)
    docker_up = docker_ready()
    dt_up = dtrack_ready(args.dtrack_url)
    username = password = token = projects = None
    if clear_dtrack:
        username, password = read_password_file(args.dtrack_password_file)
        if dt_up:
            token = dtrack_login(args.dtrack_url, username, password)
            projects = list_projects(args.dtrack_url, token)
    state = lde_state(data_dir) if clear_lde else None

    # 2. Summary
    summary = []
    if not docker_up:
        summary.append('start Docker Desktop')
    if not dt_up:
        summary.append('start Dependency-Track (docker compose up -d)')
    if listeners:
        summary.append(f'stop LDE on port {args.port} (PID {", ".join(str(p) for p, _, _ in listeners)})')
    if clear_lde:
        if state['paths']:
            counts = f'{state["runs"]} run(s), {state["repos"]} repo result(s)' \
                if state['runs'] is not None else 'database unreadable'
            if args.backup:
                summary.append(f'move LDE data from {data_dir} ({counts}) to {args.backup_root}/lde-local-<timestamp>/')
            else:
                summary.append(f'permanently delete LDE data in {data_dir} ({counts})')
        else:
            summary.append(f'LDE data: nothing to clear in {data_dir}')
    if clear_dtrack:
        if projects is None:
            summary.append('delete Dependency-Track project(s) after the API is up (count unknown until then)')
        else:
            names = ', '.join(sorted(p.get('name', '?') for p in projects)) or 'none'
            summary.append(f'delete {len(projects)} Dependency-Track project(s): {names}')
    summary.append(f'start LDE on http://127.0.0.1:{args.port}')
    if not confirm(summary, args.yes):
        log('Aborted. Nothing was changed.')
        return 1

    # 3-5. Change state
    ensure_docker()
    ensure_dtrack(args.dtrack_url)
    if clear_dtrack and token is None:
        token = dtrack_login(args.dtrack_url, username, password)
        projects = list_projects(args.dtrack_url, token)
    if listeners:
        stop_lde(listeners, args.port)
    if clear_lde and args.backup:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        dest = move_lde_state(state['paths'], args.backup_root, stamp)
        if dest:
            log(f'Moved LDE data to {dest}')
    elif clear_lde and state['paths']:
        delete_lde_state(state['paths'], data_dir)
        log(f'Deleted LDE data in {data_dir}')
    if clear_dtrack and projects:
        log(f'Deleting {len(projects)} Dependency-Track project(s)...')
        delete_projects(args.dtrack_url, token, projects)

    # 6. Start and check
    proc = start_lde(args.port)
    failures = check_lde(args.port, expect_empty=clear_lde)
    if failures:
        for f in failures:
            log(f'FAIL {f}')
    log(f'LDE is running at http://127.0.0.1:{args.port} - Ctrl-C to stop.')
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=15)
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f'start_fresh: {exc}', file=sys.stderr)
        sys.exit(1)
