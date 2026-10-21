"""Unit tests for POST /api/runs (handle_create_run) org resolution."""

import io
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from backend import db  # noqa: E402


def _make_handler(body_dict):
    handler = server.Handler.__new__(server.Handler)
    body_bytes = json.dumps(body_dict).encode('utf-8')
    handler.rfile = io.BytesIO(body_bytes)
    handler.headers = {'Content-Length': str(len(body_bytes))}
    handler._sent_status = None
    handler._buf = io.BytesIO()
    handler.send_response = lambda code, message=None: setattr(handler, '_sent_status', code)
    handler.send_header = lambda key, value: None
    handler.end_headers = lambda: None
    handler.wfile = MagicMock()
    handler.wfile.write = handler._buf.write
    return handler


@pytest.fixture
def no_default_orgs(monkeypatch, tmp_path):
    """Fresh DB, empty default_orgs (a new deploy), and no pipeline thread."""
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'create_run.db'))
    db.init_db()
    monkeypatch.setattr(server.settings_mod, 'load_settings',
                        lambda: {'default_orgs': [], 'github_pats': {'acme': 'github_pat_test'}})
    started = []
    monkeypatch.setattr(server.pipeline, 'start_in_background', started.append)
    return started


def _stored_orgs(run_id):
    conn = db.get_db()
    try:
        row = conn.execute('SELECT orgs_json FROM runs WHERE id = ?', (run_id,)).fetchone()
    finally:
        conn.close()
    return json.loads(row['orgs_json'])


def test_org_repo_without_orgs_derives_org(no_default_orgs):
    handler = _make_handler({'repos': ['acme/example-service'], 'method': 'github_sbom'})
    handler.handle_create_run((), {})
    assert handler._sent_status == 202
    run_id = json.loads(handler._buf.getvalue())['run_id']
    assert _stored_orgs(run_id) == ['acme']
    assert no_default_orgs == [run_id]


def test_bare_repo_without_orgs_is_rejected(no_default_orgs):
    handler = _make_handler({'repos': ['example-service']})
    with pytest.raises(ValueError, match='No orgs provided'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


def _with_settings(monkeypatch, **cfg):
    monkeypatch.setattr(server.settings_mod, 'load_settings', lambda: cfg)


def test_org_without_pat_is_rejected_before_run_is_created(no_default_orgs, monkeypatch):
    _with_settings(monkeypatch, default_orgs=[], github_pats={'acme': 'github_pat_test'})
    handler = _make_handler({'repos': ['other-org/svc'], 'method': 'github_sbom'})
    with pytest.raises(ValueError, match='No GitHub PAT configured for: other-org'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


def test_default_orgs_without_pats_are_rejected(no_default_orgs, monkeypatch):
    _with_settings(monkeypatch, default_orgs=['acme', 'globex'],
                   github_pats={'acme': '', 'globex': ''})
    handler = _make_handler({'method': 'github_sbom'})
    with pytest.raises(ValueError, match='acme, globex'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


def test_star_entry_allows_any_org(no_default_orgs, monkeypatch):
    _with_settings(monkeypatch, default_orgs=[], github_pats={'*': 'ghp_test'})
    handler = _make_handler({'repos': ['other-org/svc'], 'method': 'github_sbom'})
    handler.handle_create_run((), {})
    assert handler._sent_status == 202


@pytest.mark.parametrize('pats', [{'*': 'ghp_test'}, {'example-org': 'github_pat_test'}])
def test_example_orgs_are_rejected_even_with_a_token(no_default_orgs, monkeypatch, pats):
    _with_settings(monkeypatch, default_orgs=['example-org', 'Another-Org', 'acme'], github_pats=pats)
    handler = _make_handler({'method': 'github_sbom'})
    with pytest.raises(ValueError, match='example-org, Another-Org are example orgs'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


def test_example_org_in_repo_pair_is_rejected(no_default_orgs, monkeypatch):
    _with_settings(monkeypatch, default_orgs=[], github_pats={'*': 'ghp_test'})
    handler = _make_handler({'repos': ['example-org/example-service']})
    with pytest.raises(ValueError, match='example org'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


@pytest.mark.parametrize('pats,match', [
    ({'*': 'ghp_test'}, 'example org'),
    ({'acme': 'github_pat_test'}, 'No GitHub PAT configured for: other-org'),
])
def test_mixed_repo_list_checks_qualified_orgs(no_default_orgs, monkeypatch, pats, match):
    # A bare repo keeps requested_orgs at the defaults; the org/repo prefix must still be checked.
    _with_settings(monkeypatch, default_orgs=['acme'], github_pats=pats)
    org = 'example-org' if '*' in pats else 'other-org'
    handler = _make_handler({'repos': [f'{org}/svc', 'shared'], 'method': 'github_sbom'})
    with pytest.raises(ValueError, match=match):
        handler.handle_create_run((), {})
    assert no_default_orgs == []


def test_mixed_repo_list_stores_default_orgs(no_default_orgs, monkeypatch):
    _with_settings(monkeypatch, default_orgs=['acme'], github_pats={'*': 'ghp_test'})
    handler = _make_handler({'repos': ['globex/svc', 'shared'], 'method': 'github_sbom'})
    handler.handle_create_run((), {})
    assert handler._sent_status == 202
    run_id = json.loads(handler._buf.getvalue())['run_id']
    assert _stored_orgs(run_id) == ['acme']
