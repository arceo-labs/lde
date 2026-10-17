"""Sandbox tree-replication smoke test."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import sandbox  # noqa: E402


def test_prepare_clears_existing_run(tmp_path, monkeypatch):
    monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))
    p1 = sandbox.prepare('abc123')
    open(os.path.join(p1, 'leftover'), 'w').close()
    assert os.path.exists(os.path.join(p1, 'leftover'))
    sandbox.prepare('abc123')
    assert not os.path.exists(os.path.join(p1, 'leftover'))


def test_write_file_creates_nested_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))
    sandbox.prepare('xyz789')
    sandbox.write_file('xyz789', 'org', 'repo', 'packages/api/package.json',
                       json.dumps({'name': 'api'}))
    full = os.path.join(tmp_path, 'dummy-repos', 'xyz789', 'org__repo',
                        'packages', 'api', 'package.json')
    assert os.path.isfile(full)
    with open(full) as f:
        assert json.load(f) == {'name': 'api'}
