"""Unit tests for branch helpers in backend/github_client.py.

Network is always mocked via _get_json. Also pins the branch-name validator
that gates every value before it reaches a GitHub API URL.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import github_client  # noqa: E402


@pytest.fixture(autouse=True)
def _pat_for_org_o(monkeypatch):
    """Token lookup is per org and reads settings; never touch the real file."""
    monkeypatch.setattr(github_client.settings_mod, 'load_settings',
                        lambda: {'github_pats': {'o': 'github_pat_test'}})


# ---------------------------------------------------------------------------
# _valid_branch
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('b', ['main', 'develop', 'release/1.2', 'feature/x-y', 'v1.0.0'])
def test_valid_branch_accepts(b):
    assert github_client._valid_branch(b)


@pytest.mark.parametrize('b', ['', None, '../e', 'a//b', '/x', 'x/', '-x', 'a b', 'a;b', 'a~b'])
def test_valid_branch_rejects(b):
    assert not github_client._valid_branch(b)


# ---------------------------------------------------------------------------
# fetch_dependency_diff
# ---------------------------------------------------------------------------

def test_fetch_dependency_diff_returns_list(monkeypatch):
    monkeypatch.setattr(github_client, '_get_json',
                        lambda url, **kw: [{'change_type': 'added', 'name': 'x'}])
    out = github_client.fetch_dependency_diff('o', 'r', 'main', 'dev')
    assert out and out[0]['name'] == 'x'


def test_fetch_dependency_diff_404_returns_none(monkeypatch):
    def raise_404(url, **kw):
        raise github_client.GhError('GitHub API 404 for url', status=404)
    monkeypatch.setattr(github_client, '_get_json', raise_404)
    assert github_client.fetch_dependency_diff('o', 'r', 'main', 'dev') is None


def test_fetch_dependency_diff_rejects_bad_ref():
    with pytest.raises(ValueError):
        github_client.fetch_dependency_diff('o', 'r', 'main', '../evil')


# ---------------------------------------------------------------------------
# get_repo_default_branch
# ---------------------------------------------------------------------------

def test_get_repo_default_branch(monkeypatch):
    monkeypatch.setattr(github_client, '_get_json', lambda url, **kw: {'default_branch': 'trunk'})
    assert github_client.get_repo_default_branch('o', 'r') == 'trunk'


def test_get_repo_default_branch_404(monkeypatch):
    def raise_404(url, **kw):
        raise github_client.GhError('GitHub API 404 for url', status=404)
    monkeypatch.setattr(github_client, '_get_json', raise_404)
    assert github_client.get_repo_default_branch('o', 'r') is None


@pytest.mark.parametrize('fn,args', [
    (github_client.get_repo_default_branch, ('team404', 'r')),
    (github_client.fetch_dependency_diff, ('team404', 'r', 'main', 'dev')),
    (github_client.fetch_dependency_sbom, ('team404', 'r')),
    (github_client.list_tree_paths, ('team404', 'r', 'main')),
])
def test_org_name_containing_404_does_not_hide_other_errors(monkeypatch, fn, args):
    # The URL is in the message, so "404"/"403" in an org name must not look like a status.
    monkeypatch.setattr(github_client.settings_mod, 'load_settings',
                        lambda: {'github_pats': {'team404': 'github_pat_test'}})

    def boom(url, **kw):
        raise github_client.GhError('GitHub API 500 for .../team404/r: Server Error', status=500)
    monkeypatch.setattr(github_client, '_get_json', boom)
    with pytest.raises(github_client.GhError):
        fn(*args)
