"""Sanitize manifest files so package managers can resolve them in isolation.

Per TRD §5 (AST corruption risk): operate strictly on structured files via
real parsers (json, tomllib, line-based scans). Executable manifests
(`setup.py`, `build.gradle`, `build.gradle.kts`) are left untouched here —
the mocker injects placeholder context to satisfy them at run time.
"""

import json
import re


LOCAL_NPM_PREFIXES = ('file:', 'link:', 'workspace:', 'portal:')

NPM_DEP_SECTIONS = (
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
)

# Characters that start a semver range expression rather than an npm package name.
# Used by _strip_degenerate_npm_alias to distinguish valid aliases from
# degenerate `npm:*` / `npm:^1.0.0` specifiers.
_NPM_VERSION_START = frozenset('*^~>=<0123456789')


def _strip_degenerate_npm_alias(spec):
    """Normalise ``npm:<version-range>`` specifiers to plain ``<version-range>``.

    The npm alias format is ``npm:<package-name>[@version]``.  When the target
    portion starts with a version-range character instead of a valid package
    name character, npm rejects the entry with "aliases must have a name" and
    then fails on the wildcard literal (e.g. ``*@*``).  The declared dep key IS
    the real package name in these cases, so we strip the ``npm:`` prefix and
    let the version range resolve against that key.

    Examples:
        ``npm:*``          → ``*``    (any version of the declared key)
        ``npm:^5.0.0``     → ``^5.0.0``
        ``npm:some-pkg@^1`` → unchanged  (valid alias — target is a package name)
        ``npm:@scope/pkg``  → unchanged  (valid scoped alias)
    """
    if not spec.startswith('npm:'):
        return spec
    target = spec[4:]
    if target[:1] in _NPM_VERSION_START:
        return target or '*'
    return spec

_REQ_LOCAL_RE = re.compile(r'(file://|(^|\s)\./|(^|\s)\.\./)')


def sanitize_package_json(content):
    """Return sanitized JSON text for a package.json blob.

    Drops local-path entries from each dependency section, removes the
    `workspaces` array entirely (npm workspaces won't resolve without the
    sibling packages on disk), and strips top-level VCS / project-URL keys
    so ORT's VCS-info matching against the staged analyzer root succeeds.

    `strict=False` is set because real-world package.json files sometimes
    contain literal control characters (tabs, newlines) inside string
    values — technically invalid JSON but accepted by every npm tool. Our
    own json.dump output won't have them so the round-trip is clean.
    """
    data = json.loads(content, strict=False)
    if not isinstance(data, dict):
        return content

    for section in NPM_DEP_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        new_deps = {}
        for name, spec in deps.items():
            if isinstance(spec, str):
                if spec.startswith(LOCAL_NPM_PREFIXES):
                    continue
                spec = _strip_degenerate_npm_alias(spec)
            new_deps[name] = spec
        data[section] = new_deps

    data.pop('workspaces', None)

    # Strip VCS / homepage / bugs URLs. ORT walks every package.json project
    # and matches its declared repository.url against the analyzer root's
    # VCS info (empty in our staged dirs); a mismatch throws after analyze.
    # Removing these makes the project's vcsInfo empty too, which matches.
    for key in ('repository', 'homepage', 'bugs'):
        data.pop(key, None)

    overrides = data.get('overrides')
    if isinstance(overrides, dict):
        data['overrides'] = {
            name: spec for name, spec in overrides.items()
            if not (isinstance(spec, str) and spec.startswith(LOCAL_NPM_PREFIXES))
        }

    return json.dumps(data, indent=2) + '\n'


def sanitize_requirements_txt(content):
    """Drop editable installs, `-r` requirement-file includes, and local paths."""
    kept = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            kept.append(line)
            continue
        if stripped.startswith('#'):
            kept.append(line)
            continue
        if stripped.startswith(('-e ', '-r ', '--editable', '--requirement')):
            continue
        if _REQ_LOCAL_RE.search(stripped):
            continue
        kept.append(line)
    if not content.endswith('\n'):
        return '\n'.join(kept)
    return '\n'.join(kept) + '\n'


def sanitize_go_mod(content):
    """Remove `replace` directives whose target is a local filesystem path."""
    lines = content.splitlines()
    out = []
    in_replace_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('replace ') and '=>' in stripped:
            _, _, target = stripped.partition('=>')
            target = target.strip()
            if target.startswith(('.', '/')) or target.startswith('./') or target.startswith('../'):
                continue
            out.append(line)
            continue
        if stripped.startswith('replace ('):
            in_replace_block = True
            out.append(line)
            continue
        if in_replace_block:
            if stripped == ')':
                in_replace_block = False
                out.append(line)
                continue
            if '=>' in stripped:
                _, _, target = stripped.partition('=>')
                target = target.strip()
                if target.startswith(('.', '/')):
                    continue
            out.append(line)
            continue
        out.append(line)
    return '\n'.join(out) + ('\n' if content.endswith('\n') else '')


def sanitize_pyproject_toml(content):
    """Drop PEP 621 dependencies that point at on-disk paths.

    Note: tomllib is read-only; we re-serialise by walking the parsed model
    and emitting a minimal subset. To avoid losing comments/formatting, we
    only intervene when local-path deps are present.
    """
    try:
        import tomllib
    except ImportError:
        return content

    parsed = tomllib.loads(content)

    def _drop_local_table(table):
        return {
            k: v for k, v in (table or {}).items()
            if not (isinstance(v, dict) and ('path' in v or v.get('editable') is True))
        }

    poetry_section = parsed.get('tool', {}).get('poetry', {})
    deps = poetry_section.get('dependencies')
    if isinstance(deps, dict):
        cleaned = _drop_local_table(deps)
        if cleaned != deps:
            return _strip_local_path_lines(content)

    deps_dev = poetry_section.get('dev-dependencies') or poetry_section.get('group', {}).get('dev', {}).get('dependencies')
    if isinstance(deps_dev, dict):
        cleaned = _drop_local_table(deps_dev)
        if cleaned != deps_dev:
            return _strip_local_path_lines(content)

    project_deps = parsed.get('project', {}).get('dependencies')
    if isinstance(project_deps, list):
        # PEP 621 deps are strings; nothing to drop unless the spec contains
        # `@ file:` or similar.
        cleaned = [d for d in project_deps if isinstance(d, str) and ' @ file:' not in d]
        if cleaned != project_deps:
            return _strip_local_path_lines(content)

    return content


def _strip_local_path_lines(content):
    """Conservative TOML line filter — drop lines containing path = "..." or editable = true."""
    out = []
    for line in content.splitlines():
        s = line.strip()
        if re.search(r'\bpath\s*=\s*["\']', s):
            continue
        if re.search(r'\beditable\s*=\s*true\b', s):
            continue
        if ' @ file:' in s:
            continue
        out.append(line)
    return '\n'.join(out) + ('\n' if content.endswith('\n') else '')


def sanitize_pipfile(content):
    """Drop Pipfile entries that pull from local paths.

    Pipfile is TOML. We use tomllib to parse and detect; rewrite via line
    filter to preserve formatting.
    """
    try:
        import tomllib
    except ImportError:
        return content
    try:
        parsed = tomllib.loads(content)
    except Exception:
        return content

    needs_filter = False
    for section in ('packages', 'dev-packages'):
        for spec in (parsed.get(section) or {}).values():
            if isinstance(spec, dict) and ('path' in spec or spec.get('editable') is True):
                needs_filter = True

    if not needs_filter:
        return content
    return _strip_local_path_lines(content)


_SANITIZERS = {
    'package.json':           sanitize_package_json,
    'requirements.txt':       sanitize_requirements_txt,
    'dev_requirements.txt':   sanitize_requirements_txt,
    'go.mod':                 sanitize_go_mod,
    'pyproject.toml':         sanitize_pyproject_toml,
    'Pipfile':                sanitize_pipfile,
}

# Manifests we record but do not modify (lockfiles + executable build scripts).
_PASSTHROUGH = {
    'package-lock.json',
    'Pipfile.lock',
    'go.sum',
    'pom.xml',
    'setup.py',
    'build.gradle',
    'build.gradle.kts',
}


def sanitize(filename, content):
    """Dispatch to the per-format sanitizer based on the filename basename.

    Returns (sanitized_content, was_modified).
    """
    base = filename.rsplit('/', 1)[-1]
    if base in _SANITIZERS:
        result = _SANITIZERS[base](content)
        return result, result != content
    if base in _PASSTHROUGH:
        return content, False
    return content, False


def is_supported(filename):
    base = filename.rsplit('/', 1)[-1]
    return base in _SANITIZERS or base in _PASSTHROUGH


# ---------------------------------------------------------------------------
# Declared-dependency counting (used by /api/runs/{id}/manifests endpoints
# and by the e2e tests to reason about coverage).
# ---------------------------------------------------------------------------

def _count_package_json(content):
    try:
        data = json.loads(content, strict=False)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return {}
    out = {}
    for section in NPM_DEP_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            out[section] = len(deps)
    return out


def _count_requirements_txt(content):
    """Count non-blank, non-comment, non-include lines (each = one dep)."""
    n = 0
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith(('-r ', '--requirement')):
            continue
        n += 1
    return {'requirements': n}


def _count_pyproject_toml(content):
    try:
        import tomllib
    except ImportError:
        return None
    try:
        parsed = tomllib.loads(content)
    except Exception:
        return None
    out = {}
    poetry = parsed.get('tool', {}).get('poetry') or {}
    if isinstance(poetry, dict):
        deps = poetry.get('dependencies')
        if isinstance(deps, dict):
            # Poetry models python's runtime as a top-level "python" entry;
            # exclude it from the dep count for parity with PEP 621.
            out['poetry.dependencies'] = sum(1 for k in deps if k.lower() != 'python')
        dev = poetry.get('dev-dependencies') or poetry.get('group', {}).get('dev', {}).get('dependencies')
        if isinstance(dev, dict):
            out['poetry.dev-dependencies'] = len(dev)
    project = parsed.get('project') or {}
    if isinstance(project, dict):
        proj_deps = project.get('dependencies')
        if isinstance(proj_deps, list):
            out['project.dependencies'] = len(proj_deps)
        opt = project.get('optional-dependencies') or {}
        if isinstance(opt, dict):
            for group, items in opt.items():
                if isinstance(items, list):
                    out[f'project.optional-dependencies.{group}'] = len(items)
    return out


def _count_pipfile(content):
    try:
        import tomllib
    except ImportError:
        return None
    try:
        parsed = tomllib.loads(content)
    except Exception:
        return None
    out = {}
    for section in ('packages', 'dev-packages'):
        deps = parsed.get(section)
        if isinstance(deps, dict):
            out[section] = len(deps)
    return out


def _count_go_mod(content):
    """Count `require` directives (single + block forms)."""
    n = 0
    in_require_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue
        if stripped.startswith('require ('):
            in_require_block = True
            continue
        if in_require_block:
            if stripped == ')':
                in_require_block = False
                continue
            n += 1
            continue
        if stripped.startswith('require '):
            n += 1
    return {'require': n}


_DEP_COUNTERS = {
    'package.json':         _count_package_json,
    'requirements.txt':     _count_requirements_txt,
    'dev_requirements.txt': _count_requirements_txt,
    'constraints.txt':      _count_requirements_txt,
    'pyproject.toml':       _count_pyproject_toml,
    'Pipfile':              _count_pipfile,
    'go.mod':               _count_go_mod,
}


def get_dep_count(filename, content):
    """Return a dict of per-section declared-dep counts for *filename*.

    Re-uses the existing per-format parsers so the count semantics match
    what the sanitizer/ORT see. Returns {} for unsupported filenames or
    when content cannot be parsed (callers can use a missing/empty dict
    as a "couldn't determine" signal).

    The dict is intentionally per-section (e.g. {dependencies: 12,
    devDependencies: 3}) so the UI can show a breakdown and the e2e
    tests can assert on individual sections without having to re-derive
    them from the sum.

    Behaviour for `requirements*.txt` family (e.g. requirements-dev.txt):
    treated like requirements.txt — single `requirements` key with a
    line count.
    """
    base = filename.rsplit('/', 1)[-1]
    counter = _DEP_COUNTERS.get(base)
    # Generic match for `requirements*.txt` family.
    if counter is None and base.startswith('requirements') and base.endswith('.txt'):
        counter = _count_requirements_txt
    if counter is None:
        return {}
    try:
        result = counter(content)
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}


def total_deps(counts):
    """Sum a get_dep_count() dict's values; handy for one-line assertions."""
    if not isinstance(counts, dict):
        return 0
    return sum(v for v in counts.values() if isinstance(v, int))
