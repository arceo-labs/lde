"""Unit tests for branch-aware SBOM synthesis in backend/github_sbom.py.

The default branch must use GitHub's SBOM export; a non-default branch
must approximate the BOM from the dependency-review compare diff.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import github_sbom, github_client  # noqa: E402


def _spdx_one_package():
    return {'sbom': {
        'packages': [{
            'SPDXID': 'SPDXRef-pkg',
            'name': 'x',
            'versionInfo': '1',
            'externalRefs': [{'referenceType': 'purl', 'referenceLocator': 'pkg:npm/x@1'}],
        }],
        'relationships': [],
    }}


def test_apply_dependency_diff_adds_and_removes():
    base = {'components': [
        {'type': 'library', 'name': 'keep', 'version': '1',
         'purl': 'pkg:npm/keep@1', 'bom-ref': 'pkg:npm/keep@1'},
        {'type': 'library', 'name': 'gone', 'version': '2',
         'purl': 'pkg:npm/gone@2', 'bom-ref': 'pkg:npm/gone@2'},
    ], 'dependencies': [{'ref': 'x', 'dependsOn': []}]}
    diff = [
        {'change_type': 'removed', 'name': 'gone', 'version': '2', 'package_url': 'pkg:npm/gone@2'},
        {'change_type': 'added', 'name': 'new', 'version': '3', 'package_url': 'pkg:npm/new@3'},
    ]
    out = github_sbom.apply_dependency_diff(base, diff)
    assert sorted(c['name'] for c in out['components']) == ['keep', 'new']
    # Synthesized BOM drops the now-inaccurate dependency graph.
    assert 'dependencies' not in out


def test_default_branch_uses_sbom_not_diff(tmp_path, monkeypatch):
    monkeypatch.setattr(github_client, 'fetch_dependency_sbom', lambda o, r: _spdx_one_package())
    diff_called = {'hit': False}

    def _diff(*a, **k):
        diff_called['hit'] = True
        return []
    monkeypatch.setattr(github_client, 'fetch_dependency_diff', _diff)

    out = tmp_path / 'bom.json'
    count, err = github_sbom.fetch_and_write_bom('o', 'r', str(out),
                                                 branch='main', default_branch='main')
    assert err is None
    assert count == 1
    assert diff_called['hit'] is False


def test_branch_none_uses_sbom(tmp_path, monkeypatch):
    monkeypatch.setattr(github_client, 'fetch_dependency_sbom', lambda o, r: _spdx_one_package())
    out = tmp_path / 'bom.json'
    count, err = github_sbom.fetch_and_write_bom('o', 'r', str(out))
    assert err is None and count == 1


def test_non_default_branch_uses_diff(tmp_path, monkeypatch):
    monkeypatch.setattr(github_client, 'fetch_dependency_sbom', lambda o, r: _spdx_one_package())
    monkeypatch.setattr(github_client, 'fetch_dependency_diff',
                        lambda o, r, base, head: [
                            {'change_type': 'added', 'name': 'y', 'version': '2',
                             'package_url': 'pkg:npm/y@2'}])
    out = tmp_path / 'bom.json'
    count, err = github_sbom.fetch_and_write_bom('o', 'r', str(out),
                                                 branch='develop', default_branch='main')
    assert err is None
    data = json.loads(out.read_text())
    assert sorted(c['name'] for c in data['components']) == ['x', 'y']


def test_non_default_branch_diff_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(github_client, 'fetch_dependency_diff', lambda *a, **k: None)
    monkeypatch.setattr(github_client, 'fetch_dependency_sbom', lambda o, r: None)
    out = tmp_path / 'bom.json'
    count, err = github_sbom.fetch_and_write_bom('o', 'r', str(out),
                                                 branch='develop', default_branch='main')
    assert count is None
    assert 'diff unavailable' in err


def test_non_default_branch_diff_only_when_no_base_sbom(tmp_path, monkeypatch):
    # Dep graph disabled (no base SBOM) but the diff still yields added deps.
    monkeypatch.setattr(github_client, 'fetch_dependency_sbom', lambda o, r: None)
    monkeypatch.setattr(github_client, 'fetch_dependency_diff',
                        lambda o, r, base, head: [
                            {'change_type': 'added', 'name': 'only', 'version': '9',
                             'package_url': 'pkg:npm/only@9'}])
    out = tmp_path / 'bom.json'
    count, err = github_sbom.fetch_and_write_bom('o', 'r', str(out),
                                                 branch='develop', default_branch='main')
    assert err is None
    data = json.loads(out.read_text())
    assert [c['name'] for c in data['components']] == ['only']
