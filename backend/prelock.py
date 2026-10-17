"""Pre-generate npm lockfiles so ORT can do fast static resolution.

ORT 86's NPM analyzer falls back to dynamic version-range resolution when
no `package-lock.json` is present. Through a TLS-intercepting proxy that
adds latency to every HTTPS round-trip, this can take 10–30 minutes per
repo with no externally-visible progress. Pre-generating lockfiles
upfront makes the bottleneck visible per-package.json (one short docker
run each) and lets ORT's analyze run quickly off deterministic input.

We use the existing ORT image as the npm-bearing container so we don't
need a second image. `--entrypoint npm` overrides ORT's default entrypoint.
"""

import os
import subprocess
import time

from . import cid_manager, log as log_mod

logger = log_mod.get('prelock')

_TIMEOUT_PER_PKG = 600  # 10 min per package.json
_SKIP_DIRS = {'node_modules', '.git', 'vendor', '.venv', 'venv', '__pycache__'}


def _find_npm_dirs(sandbox_dir):
    dirs = []
    for root, subdirs, files in os.walk(sandbox_dir):
        subdirs[:] = [d for d in subdirs if d not in _SKIP_DIRS]
        if 'package.json' in files:
            dirs.append(root)
    return dirs


def _run_npm_in_container(host_dir, rel_subdir, image, network, log_path,
                          cache_dir=None, run_id=None, npm_cache_url=None):
    """Run `npm install --package-lock-only` inside a transient container."""
    in_container_cwd = '/project' if not rel_subdir or rel_subdir == '.' else f'/project/{rel_subdir}'
    cmd = [
        'docker', 'run', '--rm',
        '--network', network,
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '-v', f'{host_dir}:/project',
    ]
    if cache_dir:
        npm_cache = os.path.join(cache_dir, 'npm')
        os.makedirs(npm_cache, exist_ok=True)
        cmd += ['-v', f'{npm_cache}:/tmp/.npm-cache']
    cmd += [
        '-w', in_container_cwd,
        '-e', 'NPM_CONFIG_CACHE=/tmp/.npm-cache',
    ]
    if npm_cache_url:
        cmd += ['-e', f'NPM_CONFIG_REGISTRY={npm_cache_url}']
    cmd += [
        '--entrypoint', 'npm',
        image,
        'install',
        '--package-lock-only',
        '--legacy-peer-deps',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--fetch-retry-maxtimeout=20000',
        '--fetch-timeout=20000',
    ]
    cidfile = cid_manager.new_cidfile(run_id) if run_id else None
    if cidfile:
        cmd = cid_manager.inject_cidfile(cmd, cidfile)

    t0 = time.monotonic()
    try:
        with open(log_path, 'a') as log:
            log.write(f'\n=== prelock {rel_subdir or "."} ===\n$ {" ".join(cmd)}\n\n')
            log.flush()
            try:
                result = subprocess.run(
                    cmd, stdout=log, stderr=subprocess.STDOUT,
                    timeout=_TIMEOUT_PER_PKG, shell=False,
                )
                dt = time.monotonic() - t0
                return result.returncode, dt
            except subprocess.TimeoutExpired:
                if cidfile:
                    cid_manager.kill_all(run_id)
                dt = time.monotonic() - t0
                log.write(f'\n[timed out after {dt:.0f}s]\n')
                return -1, dt
    finally:
        if cidfile:
            cid_manager.cleanup_cidfile(cidfile)


def generate_lockfiles_for_repo(sandbox_dir, image, network, log_path,
                                check_stop=None, cache_dir=None, run_id=None,
                                npm_cache_url=None):
    """Generate package-lock.json for every npm project under *sandbox_dir*.

    Always regenerates lockfiles — even when one was downloaded from the repo —
    to guarantee sync with the (possibly sanitized) package.json. A stale
    committed lockfile causes `npm ci` to fail for every package.

    Returns (generated_count, skipped_count=0, failed_count).
    """
    npm_dirs = _find_npm_dirs(sandbox_dir)
    if not npm_dirs:
        return 0, 0, 0

    open(log_path, 'a').close()
    generated = failed = 0

    for npm_dir in npm_dirs:
        if check_stop is not None:
            check_stop()
        rel = os.path.relpath(npm_dir, sandbox_dir)
        # Always regenerate the lockfile from the (possibly sanitized) package.json
        # rather than reusing whatever was committed to the repo. A pre-existing
        # lockfile that is out of sync with package.json causes `npm ci` to fail
        # with errors for every package and resolve 0 dependencies.
        existing_lock = os.path.join(npm_dir, 'package-lock.json')
        if os.path.isfile(existing_lock):
            try:
                os.unlink(existing_lock)
            except OSError as exc:
                logger.warning('prelock: could not remove stale lockfile at %s: %s',
                               log_mod.safe(rel), log_mod.safe(exc))
        logger.info('prelock: generating lockfile for %s', log_mod.safe(rel))
        rc, dt = _run_npm_in_container(sandbox_dir, rel, image, network, log_path,
                                       cache_dir=cache_dir, run_id=run_id,
                                       npm_cache_url=npm_cache_url)
        if rc == 0:
            logger.info('prelock: %s done (%.1fs)', log_mod.safe(rel), dt)
            generated += 1
        else:
            logger.warning('prelock: %s failed rc=%d (%.1fs); ORT will fall back to dynamic resolution',
                           log_mod.safe(rel), rc, dt)
            failed += 1

    return generated, 0, failed
