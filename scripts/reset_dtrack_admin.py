#!/usr/bin/env python3
"""Reset the local Dependency-Track admin password.

Automates docs/start-fresh.md#recover-the-dependency-track-admin-password for
the docker-compose instance on this machine. Writes a new admin hash into the
embedded H2 database (backing up the dtrack_data volume first with --backup),
confirms the login,
then saves the password to ~/.lde/dtrack-admin.txt (mode 0600).

Dependency-Track 4.14 stores bcrypt(lowercase hex SHA-512(password)) at cost
14 with a $2a$ prefix. bcrypt comes from Apache htpasswd, not this script.

Never print the password or the session token. The password travels through
stdin and 0600 files only, never a command line.

Local instance only. Run it yourself: it changes a credential.
"""

import argparse
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import zipfile
from datetime import datetime, timezone

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_DTRACK_URL = 'http://127.0.0.1:8081'
DEFAULT_PASSWORD_FILE = os.path.expanduser('~/.lde/dtrack-admin.txt')
DEFAULT_BACKUP_ROOT = os.path.expanduser('~/.lde/backups')
IMAGE = 'library-dependency-explorer/dtrack-apiserver:local'


def compose_project(serve_dir=SERVE_DIR):
    """Compose project name is the checkout directory (e.g. lde, not a hardcoded folder)."""
    name = os.path.basename(os.path.realpath(serve_dir)).lower()
    name = re.sub(r'[^a-z0-9_-]', '', name)
    return name or 'lde'


CONTAINER = f'{compose_project()}-dtrack-apiserver-1'
VOLUME = f'{compose_project()}_dtrack_data'
SERVICE = 'dtrack-apiserver'
APISERVER_JAR = '/opt/owasp/dependency-track/dependency-track-apiserver.jar'
H2_JAR_RE = re.compile(r'^WEB-INF/lib/(h2-[0-9.]+\.jar)$')
HASH_RE = re.compile(r'^\$2a\$14\$[./A-Za-z0-9]{53}$')
LOCAL_HOSTS = ('127.0.0.1', 'localhost', '::1')
USERNAME = 'admin'


def _load_bootstrap():
    path = os.path.join(SERVE_DIR, 'scripts', 'bootstrap_dtrack.py')
    spec = importlib.util.spec_from_file_location('bootstrap_dtrack', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_bootstrap = _load_bootstrap()


def log(msg):
    print(f'[reset_dtrack_admin] {msg}', flush=True)


def require_tool(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f'{name} not found on PATH.')
    return path


def run(argv, timeout, **kwargs):
    return subprocess.run(argv, check=True, timeout=timeout, **kwargs)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def check_local_url(url):
    host = urllib.parse.urlsplit(url).hostname
    if host not in LOCAL_HOSTS:
        raise ValueError(f'{url}: refusing a non-local Dependency-Track. This script resets the local instance only.')


def preflight(docker):
    if subprocess.run([docker, 'info'], capture_output=True, timeout=20).returncode != 0:
        raise RuntimeError('Docker daemon is not running. Start Docker Desktop and re-run.')
    for kind, name in (('container', CONTAINER), ('image', IMAGE), ('volume', VOLUME)):
        result = subprocess.run([docker, kind, 'inspect', name], capture_output=True, timeout=20)
        if result.returncode != 0:
            raise RuntimeError(f'Docker {kind} {name} not found. Run docker compose up -d {SERVICE} first.')


# ---------------------------------------------------------------------------
# Hash and SQL
# ---------------------------------------------------------------------------

def dtrack_hash(htpasswd, password):
    digest = hashlib.sha512(password.encode()).hexdigest()
    out = run([htpasswd, '-niB', '-C', '14', USERNAME], timeout=60,
              input=digest + '\n', capture_output=True, text=True).stdout
    user, _, hashed = out.strip().partition(':')
    if user != USERNAME:
        raise RuntimeError('htpasswd returned unexpected output.')
    return to_2a(hashed)


def to_2a(hashed):
    if hashed.startswith('$2y$'):
        hashed = '$2a$' + hashed[4:]
    # Fail closed: the hash goes into SQL, so it must be exactly a bcrypt string.
    if not HASH_RE.match(hashed):
        raise RuntimeError('Generated hash is not a cost-14 bcrypt string. Nothing was written.')
    return hashed


def reset_sql(hashed):
    if not HASH_RE.match(hashed):
        raise ValueError('refusing to build SQL from an invalid hash')
    return (f"UPDATE MANAGEDUSER SET PASSWORD='{hashed}', FORCE_PASSWORD_CHANGE=FALSE, "
            f"LAST_PASSWORD_CHANGE=CURRENT_TIMESTAMP WHERE USERNAME='{USERNAME}';\n")


def extract_h2(apiserver_jar, lib_dir):
    with zipfile.ZipFile(apiserver_jar) as zf:
        for name in zf.namelist():
            m = H2_JAR_RE.match(name)
            if m:
                dest = os.path.join(lib_dir, m.group(1))
                with zf.open(name) as src, open(dest, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(dest, 0o644)
                return m.group(1)
    raise RuntimeError('H2 jar not found inside the Dependency-Track apiserver jar.')


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def save_other_password_file(path):
    if not os.path.exists(path):
        return None
    other = path[:-len('.txt')] + '.other.txt' if path.endswith('.txt') else path + '.other'
    if os.path.exists(other):
        log(f'{other} already exists; leaving it as is.')
        return other
    shutil.copy2(path, other)
    os.chmod(other, 0o600)
    return other


def backup_volume(docker, backup_root, stamp):
    os.makedirs(backup_root, mode=0o700, exist_ok=True)
    os.chmod(backup_root, 0o700)
    name = f'dtrack_data-{stamp}.tar'
    run([docker, 'run', '--rm', '--entrypoint', 'tar',
         '-v', f'{VOLUME}:/data:ro', '-v', f'{backup_root}:/backup',
         IMAGE, 'cf', f'/backup/{name}', '-C', '/data', '.'], timeout=900)
    path = os.path.join(backup_root, name)
    os.chmod(path, 0o600)
    return path


def apply_sql(docker, lib_dir, jar_name, sql_path):
    run([docker, 'run', '--rm', '--entrypoint', 'java',
         '-v', f'{VOLUME}:/data', '-v', f'{lib_dir}:/h2:ro', '-v', f'{sql_path}:/reset.sql:ro',
         IMAGE, '-cp', f'/h2/{jar_name}', 'org.h2.tools.RunScript',
         '-url', 'jdbc:h2:/data/.dependency-track/db', '-user', 'sa', '-password', '',
         '-script', '/reset.sql'], timeout=300, capture_output=True)


def wait_for_api(url, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _, _ = _bootstrap._request('GET', url, '/api/version')
            if status == 200:
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(5)
    raise RuntimeError(f'Dependency-Track API at {url} not ready within {timeout}s.')


def restore_hint(backup):
    return (
        'Restore the backup before trying again:\n'
        f'  docker compose stop {SERVICE}\n'
        f'  docker run --rm --entrypoint sh -v {VOLUME}:/data -v {os.path.dirname(backup)}:/backup:ro {IMAGE} \\\n'
        f"    -c 'find /data -mindepth 1 -delete && tar xf /backup/{os.path.basename(backup)} -C /data'\n"
        f'  docker compose start {SERVICE}'
    )


def confirm(summary, assume_yes):
    print('\nThis will:\n' + '\n'.join(f'  - {line}' for line in summary) + '\n', flush=True)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise RuntimeError('no terminal to confirm on; pass --yes')
    return input('Continue? [y/N] ').strip().lower() in ('y', 'yes')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Reset the local Dependency-Track admin password.')
    parser.add_argument('--yes', '-y', action='store_true', help='Skip the confirmation prompt')
    parser.add_argument('--dtrack-url', default=DEFAULT_DTRACK_URL)
    parser.add_argument('--password-out', default=DEFAULT_PASSWORD_FILE)
    parser.add_argument('--backup-root', default=DEFAULT_BACKUP_ROOT)
    parser.add_argument('--backup', action='store_true',
                        help='Back up the volume first so a failed reset can be rolled back')
    args = parser.parse_args(argv)

    # 1. Preflight: nothing below changes state until confirm() returns.
    check_local_url(args.dtrack_url)
    docker = require_tool('docker')
    htpasswd = require_tool('htpasswd')
    preflight(docker)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

    summary = []
    if os.path.exists(args.password_out):
        summary.append(f'copy the existing {args.password_out} to a .other.txt file (kept as is)')
    summary += [
        f'stop {SERVICE}',
        f'back up volume {VOLUME} to {args.backup_root}/dtrack_data-{stamp}.tar' if args.backup
        else f'no backup of volume {VOLUME} (pass --backup for one)',
        f'set a new random password for Dependency-Track user {USERNAME}',
        f'start {SERVICE} and confirm the login',
        f'save the login to {args.password_out} (mode 0600)',
    ]
    if not confirm(summary, args.yes):
        log('Aborted. Nothing was changed.')
        return 1

    other = save_other_password_file(args.password_out)
    if other:
        log(f'Saved the previous password file as {other}')

    password = _bootstrap.generate_password()
    hashed = dtrack_hash(htpasswd, password)

    work = tempfile.mkdtemp(prefix='dtrack-reset-')
    backup = None
    try:
        lib_dir = os.path.join(work, 'lib')
        os.mkdir(lib_dir, 0o755)
        jar = os.path.join(work, 'apiserver.jar')
        log('Extracting the H2 jar...')
        run([docker, 'cp', f'{CONTAINER}:{APISERVER_JAR}', jar], timeout=300, capture_output=True)
        jar_name = extract_h2(jar, lib_dir)

        log(f'Stopping {SERVICE}...')
        run([docker, 'compose', 'stop', SERVICE], timeout=120, cwd=SERVE_DIR)
        try:
            if args.backup:
                backup = backup_volume(docker, args.backup_root, stamp)
                log(f'Backed up the volume to {backup}')

            sql_path = os.path.join(work, 'reset.sql')
            fd = os.open(sql_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, 'w') as fh:
                fh.write(reset_sql(hashed))
            # The container user must read it; it holds the hash, not the password.
            os.chmod(sql_path, 0o644)
            log('Writing the new admin hash...')
            try:
                apply_sql(docker, lib_dir, jar_name, sql_path)
            finally:
                os.remove(sql_path)
        finally:
            log(f'Starting {SERVICE}...')
            run([docker, 'compose', 'start', SERVICE], timeout=120, cwd=SERVE_DIR)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    wait_for_api(args.dtrack_url)
    status, _ = _bootstrap.login(args.dtrack_url, USERNAME, password)
    if status != 200:
        log(f'FAIL login with the new password returned HTTP {status}. {args.password_out} was not changed.')
        log(restore_hint(backup) if backup else 'No backup was taken (no --backup), so there is nothing to restore.')
        return 1

    _bootstrap.write_password_file(args.password_out, USERNAME, password)
    log(f'login: OK. Saved the login to {args.password_out}')
    if backup:
        log(f'Backup kept at {backup}; delete it when no longer needed.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f'reset_dtrack_admin: {exc}', file=sys.stderr)
        sys.exit(1)
