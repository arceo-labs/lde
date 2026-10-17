"""Invoke OSS Review Toolkit as an ephemeral docker container.

Network posture (TRD §5):
- `--network=none` is NOT used — npm/pip/maven/go must reach public registries.
- Each container attaches to a dedicated `ort-egress` network that does NOT
  include the Dependency-Track services. ORT therefore cannot reach DT by
  service name; the orchestrator pushes BOMs over the host port instead.
- Containers run with `--rm`, dropped capabilities, no new privileges, and
  non-root UID/GID.
"""

import os
import shutil
import subprocess
import time

from . import cid_manager, log as log_mod

logger = log_mod.get('ort')

_DEFAULT_PACKAGE_MANAGERS = ('NPM', 'Yarn', 'PIP', 'Pipenv', 'Poetry', 'GoMod', 'Maven', 'Gradle')


class OrtError(RuntimeError):
    pass


def _purge_node_modules(sandbox_dir):
    """Recursively remove every `node_modules` dir under *sandbox_dir*.

    Frees the ~500MB-1GB per package.json that ORT's NPM analyzer leaves
    behind. Tolerant of permission errors (some dirs may have file modes
    set by the container; we run as a different uid on the host).
    """
    removed_bytes = 0
    for root, dirs, _ in os.walk(sandbox_dir, topdown=True):
        if 'node_modules' in dirs:
            target = os.path.join(root, 'node_modules')
            try:
                # Tally before nuking so we can log how much we recovered.
                for r2, _, fs in os.walk(target):
                    for f in fs:
                        try:
                            removed_bytes += os.path.getsize(os.path.join(r2, f))
                        except OSError:
                            pass
                shutil.rmtree(target, ignore_errors=True)
            except OSError as exc:
                logger.warning('node_modules purge failed at %s: %s',
                               log_mod.safe(target), log_mod.safe(exc))
            # Don't descend into the now-removed node_modules.
            dirs.remove('node_modules')
    if removed_bytes:
        logger.info('purged node_modules from %s (~%d MiB freed)',
                    log_mod.safe(sandbox_dir), removed_bytes // (1024 * 1024))


def _docker_base(image, egress_network, sandbox_dir, cache_dir=None,
                 npm_cache_url=None, pypi_cache_url=None, athens_url=None):
    """Build the common docker run prefix.

    *cache_dir* points at a host directory where ORT/npm/pip/etc. caches
    are persisted across runs. Without it (None), every container starts
    with an empty cache and re-fetches every npm-registry metadata for
    every package — through the corporate proxy that's hours of wall-clock per repo
    once trees get into the thousands. Mounting a persistent cache makes
    cold→warm transition happen exactly once.
    """
    cmd = [
        'docker', 'run', '--rm',
        '--network', egress_network,
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '-v', f'{sandbox_dir}:/project',
    ]
    # Persistent cache mounts. The ORT image runs as root, so cache
    # ownership matches. Subdir layout is mirrored under cache_dir so
    # individual package managers can be cleared independently if they
    # get corrupted.
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        for sub in ('ort', 'npm', 'yarn', 'pip', 'poetry', 'pipenv',
                    'gradle', 'm2', 'go', 'go-build', 'xdg'):
            os.makedirs(os.path.join(cache_dir, sub), exist_ok=True)
        cmd += [
            # ORT writes its cache to $HOME/.ort/cache. The base image's HOME
            # env var is /home/ort even though our Dockerfile.ort switched USER
            # to root for cert imports — changing USER doesn't reset HOME.
            '-v', f'{cache_dir}/ort:/home/ort/.ort/cache',
            '-v', f'{cache_dir}/npm:/tmp/.npm-cache',
            '-v', f'{cache_dir}/yarn:/tmp/.yarn-cache',
            '-v', f'{cache_dir}/pip:/tmp/.pip-cache',
            '-v', f'{cache_dir}/poetry:/tmp/.poetry-cache',
            '-v', f'{cache_dir}/pipenv:/tmp/.pipenv-cache',
            '-v', f'{cache_dir}/gradle:/tmp/.gradle',
            '-v', f'{cache_dir}/m2:/tmp/.m2',
            '-v', f'{cache_dir}/go:/tmp/.go',
            '-v', f'{cache_dir}/go-build:/tmp/.go-build-cache',
            # XDG_CACHE_HOME redirects python-inspector (used by ORT's PIP
            # analyzer), pip, and other tools that respect the XDG spec
            # away from $HOME/.cache (which is owned by the image-build
            # user and unwritable by root once --cap-drop=ALL strips
            # CAP_DAC_OVERRIDE).
            '-v', f'{cache_dir}/xdg:/tmp/.xdg',
            # python-inspector hardcodes ~/.cache/python_inspector (ignores
            # XDG_CACHE_HOME); persisting it across container --rm is the
            # only way to reuse its resolved-dependency-graph cache.
            '-v', f'{cache_dir}/python-inspector:/home/ort/.cache/python_inspector',
        ]
        os.makedirs(os.path.join(cache_dir, 'python-inspector'), exist_ok=True)
    cmd += [
        '-e', 'NPM_CONFIG_CACHE=/tmp/.npm-cache',
        '-e', 'YARN_CACHE_FOLDER=/tmp/.yarn-cache',
        '-e', 'PIP_CACHE_DIR=/tmp/.pip-cache',
        '-e', 'POETRY_CACHE_DIR=/tmp/.poetry-cache',
        '-e', 'PIPENV_CACHE_DIR=/tmp/.pipenv-cache',
        '-e', 'GRADLE_USER_HOME=/tmp/.gradle',
        '-e', 'MAVEN_OPTS=-Dmaven.repo.local=/tmp/.m2',
        '-e', 'GOPATH=/tmp/.go',
        '-e', 'GOCACHE=/tmp/.go-build-cache',
        # Go's module cache defaults to $GOPATH/pkg/mod, but ORT's
        # GoMod analyzer sometimes spawns `go` with an internal temp
        # workspace that resets GOPATH. Setting GOMODCACHE explicitly
        # forces module downloads under our bind-mount regardless of
        # GOPATH overrides. GOFLAGS=-modcacherw makes the cache files
        # writable on host-side reads (Docker Desktop's virtiofs leaves
        # them mode 444 by default, which breaks subsequent `go mod
        # download` calls in re-runs).
        '-e', 'GOMODCACHE=/tmp/.go/pkg/mod',
        '-e', 'GOFLAGS=-modcacherw',
        '-e', 'XDG_CACHE_HOME=/tmp/.xdg',
    ]
    # Route npm metadata fetches through our caching proxy on the
    # ort-egress network so cross-repo and cross-run hits skip the
    # registry round-trip entirely. Opt-out by setting npm_cache_url=""
    # in settings, in which case npm talks directly to registry.npmjs.org.
    if npm_cache_url:
        cmd += ['-e', f'NPM_CONFIG_REGISTRY={npm_cache_url}']
    # Route pip through the proxy via PIP_INDEX_URL. PIP_TRUSTED_HOST
    # suppresses pip's HTTPS-required warning since pypi-cache speaks
    # plain HTTP on the docker-internal network.
    #
    # NOTE: we deliberately do NOT set PYINSP_INDEX_URL even though
    # python-inspector reads that env var. python-inspector enforces
    # HTTPS for its index URL (utils_pypi.get_file_content raises
    # "Unsupported URL scheme" for http://) and our pypi-cache speaks
    # plain HTTP. Routing python-inspector through the cache requires
    # giving pypi-cache a real HTTPS endpoint (see task #18); until
    # then python-inspector goes direct to pypi.org and relies on its
    # own persistent cache (mounted at /home/ort/.cache/python_inspector,
    # backed by .cache/python-inspector/ on the host) for cross-run
    # speedup. pypi-cache still benefits any direct-pip code paths.
    if pypi_cache_url:
        import urllib.parse as _up
        cmd += ['-e', f'PIP_INDEX_URL={pypi_cache_url}']
        host = _up.urlparse(pypi_cache_url).hostname
        if host:
            cmd += ['-e', f'PIP_TRUSTED_HOST={host}']
    # Athens Go-module proxy. Override GOPROXY to point at Athens with
    # NO `,direct` fallback — Athens handles VCS fallback itself, and
    # the host-side `direct` mode is the path that breaks today (DNS /
    # TLS failures through the corporate proxy for various module hosts). If Athens
    # is unreachable, preflight blanks athens_url and we leave Go's
    # GOPROXY at its default (proxy.golang.org,direct).
    if athens_url:
        cmd += ['-e', f'GOPROXY={athens_url}']
    cmd.append(image)
    return cmd


def _run_ort(label, cmd, log_path, timeout, run_id=None):
    """Append a labelled ORT invocation to *log_path* and return its returncode.

    If *run_id* is provided, the command is wrapped with a `--cidfile` so
    that `cid_manager.kill_all(run_id)` (called from pipeline.request_stop)
    can SIGKILL the underlying container immediately.
    """
    cidfile = cid_manager.new_cidfile(run_id) if run_id else None
    if cidfile:
        cmd = cid_manager.inject_cidfile(cmd, cidfile)

    t0 = time.monotonic()
    try:
        with open(log_path, 'a') as log:
            log.write(f'\n=== {label} ===\n$ {" ".join(cmd)}\n\n')
            log.flush()
            try:
                result = subprocess.run(
                    cmd,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    shell=False,
                )
            except subprocess.TimeoutExpired as exc:
                # Make sure the orphaned container is killed too — SIGKILL
                # on the docker CLI doesn't always propagate.
                if cidfile:
                    cid_manager.kill_all(run_id)
                raise OrtError(f'ORT {label} timed out after {timeout}s') from exc
    finally:
        if cidfile:
            cid_manager.cleanup_cidfile(cidfile)

    dt = time.monotonic() - t0
    logger.info('ort %s: exit=%d duration=%.1fs', label, result.returncode, dt)
    return result.returncode


def analyze(sandbox_dir, image, egress_network, log_path, timeout=1800,
            package_managers=None, cache_dir=None,
            run_id=None, npm_cache_url=None, pypi_cache_url=None,
            athens_url=None):
    if not package_managers:
        package_managers = _DEFAULT_PACKAGE_MANAGERS
    """Run ORT `analyze` then `report -f CycloneDX` against *sandbox_dir*.

    Returns the path to the produced CycloneDX BOM file inside *sandbox_dir*.
    """
    if not os.path.isdir(sandbox_dir):
        raise OrtError(f'Sandbox missing: {sandbox_dir}')

    output_dir = os.path.join(sandbox_dir, 'ort-output')
    analyzer_result = os.path.join(output_dir, 'analyzer-result.json')
    skip_analyze = (
        os.path.isfile(analyzer_result)
        and os.path.getsize(analyzer_result) > 0
    )

    if skip_analyze:
        # Resume case: a prior run finished `analyze` (writing this file)
        # but died before `report`. Re-running analyze would burn another
        # 20+ minutes on the same registry calls. Keep the result file
        # and just wipe prior CycloneDX outputs so `report` can write
        # them fresh.
        for fn in os.listdir(output_dir):
            if 'cyclonedx' in fn.lower() or fn == 'bom.json':
                try:
                    os.unlink(os.path.join(output_dir, fn))
                except OSError:
                    pass
        os.chmod(output_dir, 0o777)
        # Append to the existing log so the resume reuse is visible.
    else:
        # Fresh analyze: wipe everything so ORT's overwrite guard doesn't trip.
        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        # World-writable so the container (running as root by default in the
        # ORT image) can write into the bind-mounted output dir. Files come
        # back owned by the host user on macOS via virtiofs UID translation.
        os.chmod(output_dir, 0o777)
        # Reset the log; subsequent stages append.
        open(log_path, 'w').close()

    base = _docker_base(image, egress_network, sandbox_dir, cache_dir,
                        npm_cache_url, pypi_cache_url, athens_url)
    pm_opt = '-Port.analyzer.enabledPackageManagers=' + ','.join(package_managers)
    # Allow npm/pip/etc. to resolve unpinned version ranges when the
    # checked-in manifest has no accompanying lockfile (common in
    # WordPress plugin trees, internal scripts, etc.).
    dyn_opt = '-Port.analyzer.allowDynamicVersions=true'

    # Stage 1: analyze → analyzer-result.json. Global -P options must
    # precede the subcommand for ORT to recognise them.
    analyze_cmd = base + [
        pm_opt,
        dyn_opt,
        'analyze',
        '-i', '/project',
        '-o', '/project/ort-output',
        '-f', 'JSON',
    ]
    if skip_analyze:
        logger.info('reusing existing analyzer-result.json (%d bytes) — skipping analyze stage',
                    os.path.getsize(analyzer_result))
        with open(log_path, 'a') as f:
            f.write('\n=== analyze (skipped: analyzer-result.json already present) ===\n\n')
    else:
        logger.info('analyze: image=%s sandbox=%s log=%s',
                    log_mod.safe(image), log_mod.safe(sandbox_dir), log_mod.safe(log_path))
        logger.debug('analyze cmd: %s', log_mod.safe(' '.join(analyze_cmd)))
        rc = _run_ort('analyze', analyze_cmd, log_path, timeout, run_id=run_id)

        if not os.path.isfile(analyzer_result):
            raise OrtError(f'ORT analyze exited {rc} and produced no analyzer-result.json; see {log_path}')

        if rc != 0:
            # ORT exits non-zero when unresolved analyzer issues hit the WARNING
            # threshold (missing transitives, dep resolution warnings, etc.).
            # The analyzer-result.json is still valid and the partial BOM is
            # still useful to ingest, so we proceed with a warning rather than
            # failing the whole repo.
            logger.warning('ORT analyze exited %d but analyzer-result.json was produced; '
                           'continuing to report stage (issue details in %s)',
                           rc, log_mod.safe(log_path))

        # Copy analyzer-result.json to the persistent log dir so it survives
        # sandbox cleanup. Named {org}__{repo}.analyzer-result.json next to
        # the existing {org}__{repo}.log.
        log_stem = os.path.splitext(os.path.basename(log_path))[0]
        dest = os.path.join(os.path.dirname(log_path),
                            f'{log_stem}.analyzer-result.json')
        try:
            shutil.copy2(analyzer_result, dest)
        except OSError as exc:
            logger.warning('could not preserve analyzer-result.json to %s: %s',
                           log_mod.safe(dest), log_mod.safe(exc))

    # Stage 2: report → CycloneDX BOM.
    report_cmd = base + [
        'report',
        '-i', '/project/ort-output/analyzer-result.json',
        '-o', '/project/ort-output',
        '-f', 'CycloneDX',
    ]
    logger.debug('report cmd: %s', log_mod.safe(' '.join(report_cmd)))
    rc = _run_ort('report', report_cmd, log_path, timeout, run_id=run_id)
    if rc != 0:
        raise OrtError(f'ORT report exited {rc}; see {log_path}')

    bom_path = None
    for entry in os.listdir(output_dir):
        if entry.endswith(('.cyclonedx.json', '.cyclonedx.xml')) or entry == 'bom.json':
            bom_path = os.path.join(output_dir, entry)
            break
    if not bom_path:
        raise OrtError(f'No CycloneDX output found in {output_dir}')

    # ORT's NPM analyzer runs a real `npm install` under the hood (not
    # just lockfile resolution), which leaves behind `node_modules`
    # trees that are commonly 500MB-1GB per package.json and accumulate
    # ~4GB per repo per run. Once the BOM is written we don't need
    # them — they're not reused on resume since smart-resume keys off
    # analyzer-result.json, not node_modules. Reclaim the space now.
    _purge_node_modules(sandbox_dir)

    return bom_path
