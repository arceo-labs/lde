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
    monkeypatch.setattr(server.settings_mod, 'load_settings', lambda: {'default_orgs': []})
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
    handler = _make_handler({'repos': ['example-org/example-service'], 'method': 'github_sbom'})
    handler.handle_create_run((), {})
    assert handler._sent_status == 202
    run_id = json.loads(handler._buf.getvalue())['run_id']
    assert _stored_orgs(run_id) == ['example-org']
    assert no_default_orgs == [run_id]


def test_bare_repo_without_orgs_is_rejected(no_default_orgs):
    handler = _make_handler({'repos': ['example-service']})
    with pytest.raises(ValueError, match='No orgs provided'):
        handler.handle_create_run((), {})
    assert no_default_orgs == []
