"""Coverage for cache_server/pypi.py — URL rewriting + path sharding.

The HTTP request paths are exercised against a live server in
integration testing; this module covers the pure functions that affect
correctness when the proxy is wired up.
"""

import importlib.util
import os
import sys

import pytest


def _load_pypi_module(tmp_path, monkeypatch):
    """Import cache_server/pypi.py with CACHE_DIR redirected to a tmp dir.

    The module isn't a package and binds CACHE_DIR at import time.
    """
    monkeypatch.setenv('CACHE_DIR', str(tmp_path))
    monkeypatch.setenv('SELF_URL', 'http://pypi-cache:9998')
    spec = importlib.util.spec_from_file_location(
        'pypi_cs',
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     'cache_server', 'pypi.py'),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_rewrite_simple_index_replaces_files_host(tmp_path, monkeypatch):
    pypi = _load_pypi_module(tmp_path, monkeypatch)
    body = (
        b'<html><body>'
        b'<a href="https://files.pythonhosted.org/packages/abc/Django-1.0.tar.gz">Django-1.0</a>'
        b'<a href="https://files.pythonhosted.org/packages/def/Django-2.0.tar.gz">Django-2.0</a>'
        b'</body></html>'
    )
    out = pypi._rewrite_simple_index(body)
    assert b'https://files.pythonhosted.org/' not in out
    assert b'http://pypi-cache:9998/files/packages/abc/Django-1.0.tar.gz' in out
    assert b'http://pypi-cache:9998/files/packages/def/Django-2.0.tar.gz' in out


def test_rewrite_simple_index_preserves_non_pypi_urls(tmp_path, monkeypatch):
    pypi = _load_pypi_module(tmp_path, monkeypatch)
    body = b'<html>see <a href="https://example.com/x">x</a></html>'
    out = pypi._rewrite_simple_index(body)
    assert out == body  # untouched — only files.pythonhosted.org gets rewritten


def test_cache_path_shards_by_sha(tmp_path, monkeypatch):
    pypi = _load_pypi_module(tmp_path, monkeypatch)
    p1 = pypi._cache_path('/simple/django/')
    p2 = pypi._cache_path('/simple/requests/')
    p3 = pypi._cache_path('/simple/django/')

    assert p1 == p3                    # deterministic
    assert p1 != p2                    # different inputs differ
    assert p1.startswith(str(tmp_path))
    # SHA256 hex → 64 chars; basename is the full digest
    assert len(os.path.basename(p1)) == 64
    # Sharding: parents are 2-char dirs
    parent = os.path.basename(os.path.dirname(p1))
    grand = os.path.basename(os.path.dirname(os.path.dirname(p1)))
    assert len(parent) == 2 and len(grand) == 2


def test_self_url_can_be_overridden(tmp_path, monkeypatch):
    monkeypatch.setenv('CACHE_DIR', str(tmp_path))
    monkeypatch.setenv('SELF_URL', 'http://custom-host:1234/')  # trailing slash stripped
    spec = importlib.util.spec_from_file_location(
        'pypi_cs2',
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     'cache_server', 'pypi.py'),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    body = b'<a href="https://files.pythonhosted.org/packages/x">x</a>'
    out = mod._rewrite_simple_index(body)
    assert b'http://custom-host:1234/files/packages/x' in out
