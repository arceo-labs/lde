"""Coverage for db.mark_orphaned_runs (server-startup cleanup)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import db  # noqa: E402


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'orphan_test.db'))
    db.init_db()


def _insert_run(run_id, status, stage):
    conn = db.get_db()
    try:
        conn.execute(
            'INSERT INTO runs (id, started_at, status, stage, orgs_json) '
            'VALUES (?, ?, ?, ?, ?)',
            (run_id, '2026-05-11T00:00:00', status, stage, json.dumps([])),
        )
        conn.commit()
    finally:
        conn.close()


def _get_run(run_id):
    conn = db.get_db()
    try:
        return conn.execute(
            'SELECT status, stage, error, completed_at FROM runs WHERE id = ?',
            (run_id,),
        ).fetchone()
    finally:
        conn.close()


def test_marks_running_runs_as_failed(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _insert_run('aaaaaaaa', 'running', 'ort')
    _insert_run('bbbbbbbb', 'queued', 'queued')
    _insert_run('cccccccc', 'completed', 'done')

    touched = db.mark_orphaned_runs()
    assert touched == 2

    aa = _get_run('aaaaaaaa')
    assert aa['status'] == 'failed'
    assert aa['stage'] == 'orphaned'
    assert 'interrupted' in aa['error']
    assert aa['completed_at'] is not None

    bb = _get_run('bbbbbbbb')
    assert bb['status'] == 'failed'
    assert bb['stage'] == 'orphaned'

    cc = _get_run('cccccccc')
    assert cc['status'] == 'completed'  # untouched


def test_no_orphans_returns_zero(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    _insert_run('aaaaaaaa', 'completed', 'done')
    _insert_run('bbbbbbbb', 'failed', 'failed')

    assert db.mark_orphaned_runs() == 0
