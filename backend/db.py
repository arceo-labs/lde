"""SQLite schema for runs, per-repo status, and manifest tracking."""

import os
import sqlite3
from datetime import datetime, timezone

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# When LDE_DATA_DIR is set (e.g. an EFS mount on Fargate), the database and
# runs/ log directory live there so they survive container restarts.
DATA_DIR = os.environ.get('LDE_DATA_DIR', '').strip() or SERVE_DIR
DB_PATH = os.path.join(DATA_DIR, 'depexplorer.db')


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.row_factory = sqlite3.Row
    return conn


_NON_TERMINAL_STATUSES = ('running', 'queued', 'resume')


def mark_orphaned_runs():
    """Mark any run still in a non-terminal status as failed.

    Called at server startup. Background pipeline threads are daemons, so
    they die silently when the process restarts (auto-reloader on code
    change, Ctrl-C, OS kill, etc.). Without this cleanup, the run row
    stays in `running` forever and the UI can't surface a Continue
    button. Returns the number of rows touched.
    """
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    conn = get_db()
    try:
        placeholders = ','.join('?' for _ in _NON_TERMINAL_STATUSES)
        rows = conn.execute(
            f'SELECT id FROM runs WHERE status IN ({placeholders})',
            _NON_TERMINAL_STATUSES,
        ).fetchall()
        if not rows:
            return 0
        ids = [r['id'] for r in rows]
        conn.executemany(
            'UPDATE runs SET status = ?, stage = ?, error = ?, completed_at = ? '
            'WHERE id = ?',
            [('failed', 'orphaned',
              'Run interrupted by server restart — partial outputs may be on '
              'disk; click Continue to pick up where it stopped.',
              now, run_id) for run_id in ids],
        )
        conn.commit()
        return len(ids)
    finally:
        conn.close()


def init_db():
    conn = get_db()
    try:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS runs (
                id            TEXT PRIMARY KEY,
                started_at    TEXT NOT NULL,
                completed_at  TEXT,
                status        TEXT NOT NULL DEFAULT 'queued',
                stage         TEXT NOT NULL DEFAULT 'queued',
                orgs_json     TEXT NOT NULL,
                repos_json    TEXT,
                method        TEXT NOT NULL DEFAULT 'ort',
                error         TEXT
            );

            CREATE TABLE IF NOT EXISTS run_repos (
                run_id              TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                org                 TEXT NOT NULL,
                repo                TEXT NOT NULL,
                default_branch      TEXT,
                manifest_count      INTEGER NOT NULL DEFAULT 0,
                sanitize_status     TEXT NOT NULL DEFAULT 'pending',
                ort_status          TEXT NOT NULL DEFAULT 'pending',
                dtrack_project_uuid TEXT,
                error               TEXT,
                PRIMARY KEY (run_id, org, repo)
            );

            CREATE TABLE IF NOT EXISTS manifests (
                run_id          TEXT NOT NULL,
                org             TEXT NOT NULL,
                repo            TEXT NOT NULL,
                filepath        TEXT NOT NULL,
                manifest_type   TEXT NOT NULL,
                sanitized       INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (run_id, org, repo, filepath),
                FOREIGN KEY (run_id, org, repo) REFERENCES run_repos(run_id, org, repo) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_run_repos_run ON run_repos(run_id);
        ''')
        conn.commit()
        # Idempotent migration: repos_json column added 2026-05-12.
        try:
            conn.execute('ALTER TABLE runs ADD COLUMN repos_json TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Idempotent migration: ort_package_count column added 2026-05-12.
        try:
            conn.execute('ALTER TABLE run_repos ADD COLUMN ort_package_count INTEGER')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Idempotent migration: dtrack_component_count column added 2026-05-13.
        # Populated post-ingest by safe_upload_bom so the UI can compare
        # what the run produced vs. what DT actually retains. Diverging
        # values are how we surface partial-BOM overwrites at a glance.
        try:
            conn.execute('ALTER TABLE run_repos ADD COLUMN dtrack_component_count INTEGER')
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: bom_overwrite_skipped column added 2026-05-13.
        # 1 when safe_upload_bom refused an upload to protect a healthy DT
        # project from being clobbered by an empty BOM, NULL/0 otherwise.
        try:
            conn.execute('ALTER TABLE run_repos ADD COLUMN bom_overwrite_skipped INTEGER')
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: manifests.original_content column added 2026-05-13.
        # Stores the raw bytes fetched from GitHub before sanitize. The
        # /api/runs/{id}/manifests/.../{b64path} endpoint diffs original
        # vs sanitized; without this column the diff requires re-fetching
        # via gh which fails offline / on stale runs whose sandbox was
        # already pruned by run_retention.
        try:
            conn.execute('ALTER TABLE manifests ADD COLUMN original_content TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: run_repos.analyzer_issue_kind column added 2026-05-13.
        # Semicolon-delimited tokens (e.g. "python_inspector_recursion;npm_alias_unnamed")
        # produced by pipeline._classify_analyzer_log so the UI can flag a
        # repo whose ORT run "completed" but logged a fatal pattern that
        # silently dropped packages. Fixes the scoped-widget case
        # where a python-inspector RecursionError aborted one Poetry
        # sub-project but ort_status still ended up 'completed'.
        try:
            conn.execute('ALTER TABLE run_repos ADD COLUMN analyzer_issue_kind TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: run_repos.poetry_fallback_count column added 2026-05-13.
        # When poetry_fallback synthesizes a CycloneDX from poetry.lock to
        # rescue a python-inspector failure, this records how many
        # components it added so the operator can tell "228 ORT + 47 fallback"
        # apart from "275 ORT" in the UI.
        try:
            conn.execute('ALTER TABLE run_repos ADD COLUMN poetry_fallback_count INTEGER')
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: runs.method column added 2026-05-13.
        # Distinguishes 'ort' (Docker-based ORT pipeline) from 'github_sbom'
        # (GitHub Dependency Graph API — no Docker, no sandbox).
        try:
            conn.execute("ALTER TABLE runs ADD COLUMN method TEXT NOT NULL DEFAULT 'ort'")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # Idempotent migration: runs.branch column added 2026-06-15.
        # Optional run-level branch override entered on the run form. When
        # set, it takes precedence over the GitHub default branch. NULL means
        # "use each repo's GitHub default".
        try:
            conn.execute('ALTER TABLE runs ADD COLUMN branch TEXT')
            conn.commit()
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()
