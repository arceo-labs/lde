"""Unit tests for the per-format sanitizer.

Confirms TRD §5 guardrail: structured files are parsed and re-serialised by
real parsers, executable files are passed through untouched, and output is
always parseable by the original tool.
"""

import json
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import sanitizer  # noqa: E402


def test_package_json_normalises_degenerate_npm_alias():
    """npm:* and npm:^x.y.z are degenerate alias specs that cause npm to fail
    with 'aliases must have a name'.  The sanitizer rewrites them to plain
    version ranges so the declared key is used as the package name."""
    src = json.dumps({
        'name': 'axle-tailwind',
        'dependencies': {
            '@tanstack/react-query': 'npm:*',
            '@tanstack/react-table': 'npm:^8.0.0',
            'react': '^18.0.0',
            # Valid aliases — must be preserved unchanged.
            'lodash-es': 'npm:lodash@^4.0.0',
            '@my/alias': 'npm:@scope/real-pkg@^2',
        },
    })
    out = sanitizer.sanitize_package_json(src)
    parsed = json.loads(out)
    deps = parsed['dependencies']
    assert deps['@tanstack/react-query'] == '*'
    assert deps['@tanstack/react-table'] == '^8.0.0'
    assert deps['react'] == '^18.0.0'
    assert deps['lodash-es'] == 'npm:lodash@^4.0.0'
    assert deps['@my/alias'] == 'npm:@scope/real-pkg@^2'


def test_package_json_drops_file_link_workspace_specs():
    src = json.dumps({
        'name': 'app',
        'dependencies': {
            'react': '^18.0.0',
            'shared-lib': 'file:../lib',
            'pinned-lib': 'workspace:*',
            'linked': 'link:./vendor',
        },
        'devDependencies': {
            'jest': '^29.0.0',
            'local-tool': 'file:../tools/devtool',
        },
        'workspaces': ['packages/*'],
    })
    out = sanitizer.sanitize_package_json(src)
    parsed = json.loads(out)
    assert parsed['dependencies'] == {'react': '^18.0.0'}
    assert parsed['devDependencies'] == {'jest': '^29.0.0'}
    assert 'workspaces' not in parsed


def test_package_json_tolerates_raw_control_characters():
    """Real-world package.json files sometimes have literal tabs or
    newlines inside string values — technically invalid JSON but
    accepted by every npm tool. Strict json.loads rejects them, killing
    the whole sanitize stage for a 132-repo org (regression: another-org
    run 4838d3e1 on 2026-05-12). sanitize_package_json should accept
    them via strict=False."""
    # Raw tab (0x09) inside the description string.
    src = '{"name": "evil",\n  "description": "has a\ttab inside",\n  "dependencies": {"lodash": "^4.0.0"}}'
    out = sanitizer.sanitize_package_json(src)
    # Result must be re-parseable as valid JSON (our json.dump output
    # escapes the control characters so the round-trip is clean).
    parsed = json.loads(out)
    assert parsed['dependencies'] == {'lodash': '^4.0.0'}


def test_package_json_strips_vcs_and_homepage_fields():
    """ORT's analyzer matches project vcsInfo against the analyzer root's
    vcsInfo; staged trees have no git context, so any declared repository
    URL on a child package.json triggers a post-analyze exception. Empty
    on both sides is the cleanest match."""
    src = json.dumps({
        'name': 'pkg',
        'version': '1.0.0',
        'repository': {'type': 'git', 'url': 'https://gitlab.com/example/pkg.git'},
        'homepage': 'https://example.com/pkg',
        'bugs': {'url': 'https://example.com/pkg/issues'},
        'dependencies': {'react': '^18.0.0'},
    })
    out = sanitizer.sanitize_package_json(src)
    parsed = json.loads(out)
    assert 'repository' not in parsed
    assert 'homepage' not in parsed
    assert 'bugs' not in parsed
    assert parsed['dependencies'] == {'react': '^18.0.0'}


def test_package_json_no_changes_when_clean():
    src = json.dumps({'name': 'app', 'dependencies': {'lodash': '^4.0.0'}})
    out = sanitizer.sanitize_package_json(src)
    # Must remain valid JSON regardless.
    json.loads(out)


def test_requirements_txt_drops_editable_and_local_paths():
    src = textwrap.dedent('''\
        # comment
        django==4.2
        -e .
        -e ./libs/shared
        -r dev-requirements.txt
        --editable ../other
        requests>=2.31
        ./wheels/local-1.0.0-py3-none-any.whl
        ''')
    out = sanitizer.sanitize_requirements_txt(src)
    lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith('#')]
    assert 'django==4.2' in lines
    assert 'requests>=2.31' in lines
    assert not any('-e' in l or '-r' in l or './' in l for l in lines)


def test_go_mod_drops_local_replace():
    src = textwrap.dedent('''\
        module example.com/app

        go 1.22

        require (
            github.com/foo/bar v1.2.3
            example.com/internal v0.0.0
        )

        replace example.com/internal => ../internal

        replace (
            golang.org/x/net => golang.org/x/net v0.20.0
            example.com/local => ./local
        )
        ''')
    out = sanitizer.sanitize_go_mod(src)
    assert '../internal' not in out
    assert './local' not in out
    assert 'github.com/foo/bar v1.2.3' in out
    assert 'golang.org/x/net v0.20.0' in out


def test_sanitize_dispatch_passthrough_for_executable_manifests():
    setup_py = "from setuptools import setup\nsetup(name='x', install_requires=['requests'])\n"
    out, modified = sanitizer.sanitize('setup.py', setup_py)
    assert out == setup_py
    assert modified is False

    gradle = "dependencies {\n    implementation 'com.google.guava:guava:32.0.1-jre'\n}\n"
    out, modified = sanitizer.sanitize('build.gradle', gradle)
    assert out == gradle
    assert modified is False


def test_sanitize_dispatch_modifies_package_json():
    src = json.dumps({'dependencies': {'foo': 'file:../foo', 'bar': '^1.0.0'}})
    out, modified = sanitizer.sanitize('package.json', src)
    parsed = json.loads(out)
    assert parsed['dependencies'] == {'bar': '^1.0.0'}
    assert modified is True


def test_dev_requirements_txt_handled_same_as_requirements():
    """dev_requirements.txt must go through the same sanitizer as requirements.txt."""
    src = textwrap.dedent('''\
        # dev tools
        pytest==7.4.0
        -e .
        -r base-requirements.txt
        ./wheels/local-0.1.0.whl
        ''')
    out, modified = sanitizer.sanitize('dev_requirements.txt', src)
    lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith('#')]
    assert 'pytest==7.4.0' in lines
    assert not any('-e' in l or '-r' in l or './' in l for l in lines)
    assert modified is True


def test_is_supported_filters_unknown():
    assert sanitizer.is_supported('package.json')
    assert sanitizer.is_supported('subdir/package.json')
    assert sanitizer.is_supported('setup.py')
    assert sanitizer.is_supported('dev_requirements.txt')
    assert sanitizer.is_supported('subdir/dev_requirements.txt')
    assert not sanitizer.is_supported('README.md')
    assert not sanitizer.is_supported('Dockerfile')


# ---------------------------------------------------------------------------
# get_dep_count helper — used by /api/runs/{id}/manifests.
# ---------------------------------------------------------------------------

def test_get_dep_count_package_json_breaks_down_by_section():
    src = json.dumps({
        'name': 'app',
        'dependencies': {'a': '1', 'b': '2', 'c': '3'},
        'devDependencies': {'d': '4', 'e': '5'},
        'peerDependencies': {'f': '6'},
    })
    counts = sanitizer.get_dep_count('package.json', src)
    assert counts == {'dependencies': 3, 'devDependencies': 2, 'peerDependencies': 1}
    assert sanitizer.total_deps(counts) == 6


def test_get_dep_count_requirements_family_includes_dash_dev_variant():
    src = textwrap.dedent('''
        # comment
        flask==2.0.0
        requests>=2.28
        -r base-requirements.txt

        django>=4.2
    ''')
    assert sanitizer.get_dep_count('requirements.txt', src) == {'requirements': 3}
    assert sanitizer.get_dep_count('requirements-dev.txt', src) == {'requirements': 3}
    assert sanitizer.get_dep_count('requirements_test.txt', src) == {'requirements': 3}


def test_get_dep_count_pyproject_pep621_dependencies_array():
    src = textwrap.dedent('''
        [project]
        name = "x"
        dependencies = ["flask>=2", "requests>=2"]
        [project.optional-dependencies]
        dev = ["pytest", "black"]
    ''')
    counts = sanitizer.get_dep_count('pyproject.toml', src)
    assert counts.get('project.dependencies') == 2
    assert counts.get('project.optional-dependencies.dev') == 2


def test_get_dep_count_returns_empty_for_unsupported_filename():
    assert sanitizer.get_dep_count('README.md', 'whatever') == {}


def test_get_dep_count_returns_empty_for_unparseable_content():
    # Truly broken JSON — parser must not raise; helper returns {}.
    assert sanitizer.get_dep_count('package.json', 'not { real json }') == {}


def test_get_dep_count_pipfile():
    src = textwrap.dedent('''
        [packages]
        flask = "*"
        requests = "*"
        [dev-packages]
        pytest = "*"
    ''')
    counts = sanitizer.get_dep_count('Pipfile', src)
    assert counts.get('packages') == 2
    assert counts.get('dev-packages') == 1


def test_get_dep_count_go_mod():
    src = textwrap.dedent('''
        module example.com/x

        go 1.21

        require (
            github.com/foo/bar v1.0.0
            github.com/baz/qux v2.0.0
        )

        require github.com/single/single v1.0.0
    ''')
    counts = sanitizer.get_dep_count('go.mod', src)
    assert counts.get('require') == 3
