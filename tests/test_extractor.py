"""Unit tests for backend/extractor.py predicate + skip-filter helpers.

Pins the manifest-widening fix that resolved the data-quality regressions
on `example-org/aws-examples` (only saw 1 manifest), `data-pipeline`, and
`django-dag-postgresql`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import extractor  # noqa: E402


# ---------------------------------------------------------------------------
# _is_manifest
# ---------------------------------------------------------------------------

def test_is_manifest_matches_existing_basenames():
    assert extractor._is_manifest('package.json')
    assert extractor._is_manifest('subdir/package.json')
    assert extractor._is_manifest('go.mod')
    assert extractor._is_manifest('pyproject.toml')


def test_is_manifest_matches_requirements_family():
    """Repos like aws-examples ship multiple requirements*.txt variants."""
    assert extractor._is_manifest('requirements.txt')
    assert extractor._is_manifest('requirements-dev.txt')
    assert extractor._is_manifest('requirements-prod.txt')
    assert extractor._is_manifest('requirements-test.txt')
    assert extractor._is_manifest('requirements_test.txt')
    assert extractor._is_manifest('subdir/requirements-base.txt')


def test_is_manifest_matches_modern_python_lockfiles():
    assert extractor._is_manifest('uv.lock')
    assert extractor._is_manifest('pdm.lock')
    assert extractor._is_manifest('poetry.lock')
    assert extractor._is_manifest('pylock.toml')


def test_is_manifest_matches_setup_cfg_and_constraints():
    assert extractor._is_manifest('setup.cfg')
    assert extractor._is_manifest('constraints.txt')


def test_is_manifest_rejects_unrelated_files():
    assert not extractor._is_manifest('README.md')
    assert not extractor._is_manifest('Dockerfile')
    assert not extractor._is_manifest('Makefile')
    assert not extractor._is_manifest('requirements.md')  # not .txt
    assert not extractor._is_manifest('my_requirements_doc.txt')  # doesn't START with 'requirements'


# ---------------------------------------------------------------------------
# _path_is_skipped
# ---------------------------------------------------------------------------

def test_path_is_skipped_for_node_modules():
    assert extractor._path_is_skipped('node_modules/foo/package.json')
    assert extractor._path_is_skipped('packages/sub/node_modules/x/package.json')
    assert not extractor._path_is_skipped('packages/sub/package.json')


def test_path_is_skipped_for_vendor_dirs():
    assert extractor._path_is_skipped('vendor/foo/go.mod')
    assert extractor._path_is_skipped('packages/sub/vendor/x/go.mod')


def test_path_is_skipped_for_python_install_artifacts():
    assert extractor._path_is_skipped('.venv/lib/python3.11/site-packages/foo/setup.py')
    assert extractor._path_is_skipped('venv/lib/x/setup.py')
    assert extractor._path_is_skipped('__pycache__/x.pyc')
    assert extractor._path_is_skipped('.tox/py311/site-packages/foo/setup.py')


def test_path_is_skipped_does_not_match_basename():
    """The skip filter only matches DIRECTORY components, not the filename."""
    assert not extractor._path_is_skipped('node_modules')  # basename only
    assert not extractor._path_is_skipped('vendor.js')     # basename only
