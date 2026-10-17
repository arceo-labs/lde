"""Generate placeholder files that dynamic build scripts expect to find.

The sanitizer can't fix `setup.py` or `build.gradle` directly (running them
is required to enumerate deps). Instead, we satisfy their filesystem lookups
with empty stubs so the build tool reaches the dependency-declaration step.
"""

import os


_GENERIC_FILES = ('README.md', 'LICENSE')

_GENERIC_DIRS = ('src', 'lib', 'bin')

_JVM_DIRS = ('src/main/java', 'src/main/resources')

_JVM_MARKERS = ('pom.xml', 'build.gradle', 'build.gradle.kts')
_PYTHON_MARKERS = ('setup.py', 'setup.cfg', 'pyproject.toml')
_NPM_SKIP_DIRS = {'node_modules', '.git'}
_WALK_SKIP_DIRS = {'node_modules', '.git', 'ort-output', '__pycache__', '.venv', 'venv'}


def _emit_pep621_requirements(sandbox_dir):
    """Synthesize a requirements.txt from PEP 621 pyproject.toml files.

    ORT's Poetry analyzer requires [tool.poetry]; ORT's PIP analyzer requires
    requirements.txt or setup.py. A pyproject.toml that uses only PEP 621
    [project.dependencies] is invisible to both — this fills that gap.

    Skips any directory that already has a requirements.txt (don't overwrite
    real lockfiles) or whose pyproject.toml has a [tool.poetry] section (let
    Poetry's analyzer handle it).
    """
    try:
        import tomllib
    except ImportError:
        return

    for root, dirs, files in os.walk(sandbox_dir):
        dirs[:] = [d for d in dirs if d not in _WALK_SKIP_DIRS]
        if 'pyproject.toml' not in files:
            continue
        if 'requirements.txt' in files:
            continue
        pyproject_path = os.path.join(root, 'pyproject.toml')
        try:
            with open(pyproject_path, 'rb') as fh:
                data = tomllib.load(fh)
        except Exception:
            continue
        if data.get('tool', {}).get('poetry'):
            continue
        project = data.get('project', {})
        deps = list(project.get('dependencies') or [])
        for group_deps in (project.get('optional-dependencies') or {}).values():
            deps.extend(group_deps)
        deps = [d for d in deps if isinstance(d, str)]
        if not deps:
            continue
        reqs_path = os.path.join(root, 'requirements.txt')
        with open(reqs_path, 'w') as fh:
            fh.write('\n'.join(deps) + '\n')


def _inject_npmrc(sandbox_dir):
    """Write .npmrc with legacy-peer-deps=true next to each package.json.

    ORT's NPM analyzer runs npm without --legacy-peer-deps, which triggers
    ERESOLVE for repos that have peer-dep conflicts (e.g. a package requiring
    an older @types/* than the root declares). A project-level .npmrc silently
    opts npm into legacy resolution without touching ORT's command line.

    If an .npmrc already exists, the setting is appended only when absent so
    that any registry or auth lines already in the file are preserved.
    """
    for root, dirs, files in os.walk(sandbox_dir):
        dirs[:] = [d for d in dirs if d not in _NPM_SKIP_DIRS]
        if 'package.json' not in files:
            continue
        npmrc_path = os.path.join(root, '.npmrc')
        if not os.path.exists(npmrc_path):
            with open(npmrc_path, 'w') as fh:
                fh.write('legacy-peer-deps=true\n')
        else:
            with open(npmrc_path, 'r') as fh:
                content = fh.read()
            if 'legacy-peer-deps' not in content:
                with open(npmrc_path, 'a') as fh:
                    fh.write('\nlegacy-peer-deps=true\n')


def mock(sandbox_dir, manifest_basenames):
    """Inject placeholder files/dirs into *sandbox_dir*.

    *manifest_basenames* is the set of filenames found in this repo
    (basename only, not full paths). The mocker uses these markers to
    decide which language-specific directories to scaffold.

    Idempotent: never overwrites a non-empty existing file.
    """
    os.makedirs(sandbox_dir, exist_ok=True)

    for name in _GENERIC_FILES:
        path = os.path.join(sandbox_dir, name)
        if not os.path.exists(path):
            open(path, 'w').close()

    for d in _GENERIC_DIRS:
        os.makedirs(os.path.join(sandbox_dir, d), exist_ok=True)

    if manifest_basenames & set(_JVM_MARKERS):
        for d in _JVM_DIRS:
            os.makedirs(os.path.join(sandbox_dir, d), exist_ok=True)

    if manifest_basenames & set(_PYTHON_MARKERS):
        os.makedirs(os.path.join(sandbox_dir, 'src'), exist_ok=True)

    if 'package.json' in manifest_basenames:
        _inject_npmrc(sandbox_dir)

    if 'pyproject.toml' in manifest_basenames:
        _emit_pep621_requirements(sandbox_dir)
