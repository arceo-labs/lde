"""Coverage for cid_manager.inject_cidfile + path validation.

The kill_all() and cleanup_run() paths shell out to docker so they're
exercised by integration runs rather than unit tests.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import cid_manager  # noqa: E402


def test_inject_cidfile_inserts_after_docker_run():
    cmd = ['docker', 'run', '--rm', '--network', 'ort-egress', 'image:tag', 'analyze']
    out = cid_manager.inject_cidfile(cmd, '/tmp/foo.cid')
    assert out == ['docker', 'run', '--cidfile', '/tmp/foo.cid', '--rm',
                   '--network', 'ort-egress', 'image:tag', 'analyze']


def test_inject_cidfile_rejects_non_docker_run():
    with pytest.raises(ValueError, match='not a docker run'):
        cid_manager.inject_cidfile(['npm', 'install'], '/tmp/foo.cid')
    with pytest.raises(ValueError, match='not a docker run'):
        cid_manager.inject_cidfile(['docker', 'ps'], '/tmp/foo.cid')


def test_safe_run_id_rejects_path_traversal():
    # Plain hex passes.
    assert cid_manager._safe_run_id('a1b2c3') == 'a1b2c3'
    # Anything with slashes, dots, dashes, etc. is rejected — prevents
    # writing cidfiles outside the per-run dir.
    for bad in ('../escape', 'with/slash', 'WITH-DASH', '', 'has.dot', 'has space'):
        with pytest.raises(ValueError):
            cid_manager._safe_run_id(bad)


def test_new_and_cleanup_cidfile_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(cid_manager, 'CID_ROOT', str(tmp_path))
    path = cid_manager.new_cidfile('deadbeef')
    assert path.startswith(str(tmp_path))
    assert path.endswith('.cid')
    # Docker requires the cidfile to NOT exist at run time.
    assert not os.path.exists(path)
    # Simulate docker writing a container ID then us cleaning up.
    with open(path, 'w') as f:
        f.write('cafef00d' * 8)
    assert os.path.isfile(path)
    cid_manager.cleanup_cidfile(path)
    assert not os.path.exists(path)


def test_kill_all_tolerates_empty_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cid_manager, 'CID_ROOT', str(tmp_path))
    # No cidfiles yet → no work, no errors.
    assert cid_manager.kill_all('abc123') == 0


def test_cleanup_run_removes_per_run_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cid_manager, 'CID_ROOT', str(tmp_path))
    p = cid_manager.new_cidfile('abc123')
    assert os.path.isdir(os.path.dirname(p))
    cid_manager.cleanup_run('abc123')
    assert not os.path.exists(os.path.dirname(p))
