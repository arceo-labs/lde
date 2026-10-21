#!/usr/bin/env python3
"""Library Dependency Explorer — HTTP server + REST API + SQLite.

Zero pip runtime dependencies. Run with: python3 server.py
Serves on http://localhost:8002 by default.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import mimetypes
import os
import re
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

from backend import (
    db,
    dtrack_client,
    gh_auth,
    github_client,
    log as log_mod,
    pipeline,
    sanitizer,
    settings as settings_mod,
    task_queue,
)

logger = log_mod.get('server')
HTTP_LOG_ENABLED = False

PORT = int(os.environ.get('PORT', 8002))
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
# When LDE_DATA_DIR is set, run logs and the SQLite DB live on the mounted
# volume (EFS on Fargate).  Matches the same env var used in backend/db.py.
DATA_DIR = os.environ.get('LDE_DATA_DIR', '').strip() or SERVE_DIR

# The only files _serve_static may return. Everything else under SERVE_DIR
# (source, docs, and on AWS the /app/data volume with the SQLite DB and run
# logs) is 404, even to an authenticated user.
_STATIC_FILES = frozenset({'index.html'})
_STATIC_DIRS = ('css', 'js')

# When set, ORT-based ingest is refused with 400 (Fargate has no Docker socket).
_DISABLE_ORT = os.environ.get('LDE_DISABLE_ORT', '').strip() == '1'

# When set, this origin is also allowed in addition to localhost (production hostname).
_ALLOWED_ORIGIN = os.environ.get('LDE_ALLOWED_ORIGIN', '').strip().rstrip('/')
_LOCAL_ORIGIN_RE = re.compile(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?$')
# Methods that change state. They must send JSON, which a cross-site page can
# only do after a CORS preflight that _cors_headers refuses (CSRF guard).
_MUTATING_METHODS = frozenset({'POST', 'PUT'})


def _origin_allowed(origin):
    """True for a local origin or the exact LDE_ALLOWED_ORIGIN."""
    return bool(_LOCAL_ORIGIN_RE.match(origin) or (_ALLOWED_ORIGIN and origin == _ALLOWED_ORIGIN))


def _load_basic_auth_creds():
    """Return {username: sha256_hex, ...} from settings, or {} if not configured.

    Reads ``basic_auth_credentials`` from settings (which may be overlaid by
    AWS Secrets Manager).  The expected format is a JSON string like::

        {"admin": "<sha256_hex_of_password>"}

    Returns an empty dict when Basic Auth is not configured, which disables
    the middleware (for local development).
    """
    raw = settings_mod.load_settings().get('basic_auth_credentials', '')
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        # Malformed secret in AWS mode is a configuration error, not a warning.
        if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws':
            logger.error('basic_auth_credentials is not valid JSON — failing closed in AWS mode')
        else:
            logger.warning('basic_auth_credentials is not valid JSON — Basic Auth disabled')
    return {}


# Cache credentials at module level; reloaded each time a new request comes in
# so Secrets Manager rotations are picked up without a restart.  The cost is
# one settings file read per request, which is negligible for an internal tool;
# secrets_loader reuses each Secrets Manager value for 60 seconds.
_basic_auth_creds = None
_basic_auth_lock = threading.Lock()


def _get_basic_auth_creds():
    return _load_basic_auth_creds()


ROUTES = [
    ('GET',  r'^/api/settings$',                                'handle_get_settings'),
    ('PUT',  r'^/api/settings$',                                'handle_put_settings'),
    ('GET',  r'^/api/gh-status$',                               'handle_gh_status'),
    ('GET',  r'^/api/dtrack-status$',                           'handle_dtrack_status'),
    ('GET',  r'^/api/gemini-status$',                           'handle_gemini_status'),

    ('GET',  r'^/api/runs$',                                    'handle_list_runs'),
    ('POST', r'^/api/runs$',                                    'handle_create_run'),
    ('GET',  r'^/api/runs/([a-f0-9]+)$',                        'handle_get_run'),
    ('GET',  r'^/api/runs/([a-f0-9]+)/repos$',                  'handle_list_run_repos'),
    ('GET',  r'^/api/runs/([a-f0-9]+)/logs/([^/]+)/([^/]+)$',   'handle_get_repo_log'),
    ('POST', r'^/api/runs/([a-f0-9]+)/stop$',                   'handle_stop_run'),
    ('POST', r'^/api/runs/([a-f0-9]+)/continue$',               'handle_continue_run'),
    ('POST', r'^/api/runs/([a-f0-9]+)/restart$',                'handle_restart_run'),
    ('POST', r'^/api/runs/([a-f0-9]+)/retry-failed$',           'handle_retry_failed'),
    ('POST', r'^/api/runs/([a-f0-9]+)/repos/([^/]+)/([^/]+)/retry$', 'handle_retry_repo'),

    # Inspection / data-quality APIs (added 2026-05-13).
    ('GET',  r'^/api/runs/([a-f0-9]+)/manifests$',                                  'handle_list_run_manifests'),
    ('GET',  r'^/api/runs/([a-f0-9]+)/manifests/([^/]+)/([^/]+)/([A-Za-z0-9_\-]+=*)$', 'handle_get_run_manifest'),
    ('GET',  r'^/api/runs/([a-f0-9]+)/repos/([^/]+)/([^/]+)/dtrack-components$',    'handle_get_repo_dtrack_components'),
    ('GET',  r'^/api/runs/([a-f0-9]+)/coverage$',                                   'handle_get_run_coverage'),
    ('GET',  r'^/api/dtrack/search$',                                               'handle_dtrack_search'),
    ('POST', r'^/api/dtrack/package-search$',                                       'handle_package_search'),
    ('POST', r'^/api/extract-packages$',                                            'handle_extract_packages'),

    ('GET',  r'^/api/tasks/([a-f0-9]+)$',                       'handle_get_task'),
]


_ID_RE = re.compile(r'^[A-Za-z0-9._-]+$')
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]+$')


def _validate_org_repo(org, repo):
    """Match the same charset github_client uses to gate `gh` arguments.

    Mirrors backend/github_client.py lines 77-98 so the new inspection
    endpoints can't be coaxed into reading paths outside the run dir.
    """
    if not _ID_RE.match(org or '') or not _ID_RE.match(repo or ''):
        raise ValueError('Invalid org or repo identifier')


def _valid_branch(branch):
    """Mirror github_client._valid_branch so the HTTP layer rejects unsafe
    branch refs before they are stored or forwarded to a GitHub API URL."""
    if not branch or not isinstance(branch, str):
        return False
    if not _BRANCH_RE.match(branch):
        return False
    if branch.startswith(('/', '-')) or branch.endswith('/'):
        return False
    if '..' in branch or '//' in branch:
        return False
    return True


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        if HTTP_LOG_ENABLED:
            line = log_mod.safe(fmt % args)
            logger.debug('%s - %s', self.address_string(), line)

    # ---- Routing -------------------------------------------------------

    def _route(self, method):
        if not self._require_auth():
            return True  # response already sent
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        for route_method, pattern, handler_name in ROUTES:
            if route_method != method:
                continue
            m = re.match(pattern, path)
            if m:
                if method in _MUTATING_METHODS and self._reject_cross_site():
                    return True
                self._response_status = 200
                t0 = time.monotonic()
                try:
                    getattr(self, handler_name)(m.groups(), parse_qs(parsed.query))
                except (ValueError, RuntimeError) as exc:
                    self._json_response(400, {'error': str(exc)})
                except Exception:
                    logger.exception('handler %s raised', handler_name)
                    self._json_response(500, {'error': 'Internal server error'})
                logger.debug('route %s %s -> %d (%dms)',
                             method, log_mod.safe(path), self._response_status,
                             int((time.monotonic() - t0) * 1000))
                return True
        return False

    def _reject_cross_site(self):
        """Send 415/403 and return True for a POST/PUT that could be cross-site."""
        media_type = self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        if media_type != 'application/json':
            self._json_response(415, {'error': 'Content-Type must be application/json'})
            return True
        origin = self.headers.get('Origin')
        if origin and not _origin_allowed(origin):
            self._json_response(403, {'error': 'Origin not allowed'})
            return True
        return False

    def do_GET(self):
        if not self._route('GET'):
            self._serve_static()

    def do_POST(self):
        if not self._route('POST'):
            self._json_response(404, {'error': 'Not found'})

    def do_PUT(self):
        if not self._route('PUT'):
            self._json_response(404, {'error': 'Not found'})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # ---- Helpers -------------------------------------------------------

    def _require_auth(self):
        """Enforce HTTP Basic Auth when credentials are configured.

        Returns True if the request is allowed.  Returns False (and sends the
        401 response) when authentication fails.  When no credentials are
        configured (local dev), always returns True.

        In AWS mode (LDE_SECRETS_SOURCE=aws) an empty credential set is treated
        as a configuration or availability failure and fails closed — it never
        grants open access.
        """
        creds = _get_basic_auth_creds()
        if not creds:
            if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws':
                # Credentials must come from Secrets Manager in AWS mode.
                # A missing, inaccessible, or malformed secret fails closed.
                logger.error('Basic Auth credentials unavailable in AWS mode — denying request')
                self._send_auth_challenge()
                return False
            return True  # local dev: no credentials configured → allow
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Basic '):
            self._send_auth_challenge()
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8', errors='replace')
        except Exception:
            self._send_auth_challenge()
            return False
        user, _, pw = decoded.partition(':')
        expected_hash = creds.get(user)
        if not expected_hash:
            self._send_auth_challenge()
            return False
        actual_hash = hashlib.sha256(pw.encode('utf-8')).hexdigest()
        # Compare bytes: compare_digest raises TypeError on non-ASCII str, and a
        # malformed stored value must deny (401), not escape as an exception.
        if not hmac.compare_digest(actual_hash.encode('ascii'), str(expected_hash).encode('utf-8')):
            self._send_auth_challenge()
            return False
        return True

    def _send_auth_challenge(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Library Dependency Explorer"')
        self.send_header('Content-Length', '0')
        self._cors_headers()
        self._security_headers()
        self.end_headers()

    def _cors_headers(self):
        origin = self.headers.get('Origin', '')
        if _origin_allowed(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        # The ALB terminates TLS and sets X-Forwarded-Proto=https on the hop
        # to this task. Emit HSTS only on the HTTPS path so local dev over
        # plain HTTP does not pin a browser's host to HTTPS.
        if self.headers.get('X-Forwarded-Proto', '').lower() == 'https':
            self.send_header('Strict-Transport-Security',
                             'max-age=63072000; includeSubDomains')

    def _json_response(self, status, data):
        self._response_status = status
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._cors_headers()
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    _MAX_BODY = 1 * 1024 * 1024

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        if length > self._MAX_BODY:
            raise ValueError('Request body too large')
        raw = self.rfile.read(length)
        return json.loads(raw.decode('utf-8'))

    @staticmethod
    def _is_static_asset(rel, full_path):
        """True when *rel* is an allowlisted UI asset whose real path stays in its dir."""
        if rel in _STATIC_FILES:
            return full_path == os.path.realpath(os.path.join(SERVE_DIR, rel))
        top = rel.split('/', 1)[0]
        if top not in _STATIC_DIRS or '/' not in rel:
            return False
        base = os.path.realpath(os.path.join(SERVE_DIR, top))
        return full_path.startswith(base + os.sep)

    def _serve_static(self):
        if not self._require_auth():
            return
        parsed = urlparse(self.path)
        rel = parsed.path.lstrip('/')
        if not rel or rel.endswith('/'):
            rel = 'index.html'

        if any(part.startswith('.') for part in rel.replace('\\', '/').split('/')):
            self.send_error(403, 'Forbidden')
            return

        full_path = os.path.realpath(os.path.join(SERVE_DIR, rel))
        if not full_path.startswith(os.path.realpath(SERVE_DIR) + os.sep) and \
           full_path != os.path.realpath(SERVE_DIR):
            self.send_error(403, 'Forbidden')
            return

        if '.' not in os.path.basename(rel):
            full_path = os.path.join(SERVE_DIR, 'index.html')
        elif not self._is_static_asset(rel, full_path) or not os.path.isfile(full_path):
            self.send_error(404, 'Not Found')
            return

        mime, _ = mimetypes.guess_type(full_path)
        if mime is None:
            mime = 'application/octet-stream'
        with open(full_path, 'rb') as f:
            content = f.read()

        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(content)))
        self._cors_headers()
        self._security_headers()
        self.end_headers()
        self.wfile.write(content)

    # ---- Settings ------------------------------------------------------

    def handle_get_settings(self, groups, qs):
        self._json_response(200, settings_mod.masked(settings_mod.load_settings()))

    def handle_put_settings(self, groups, qs):
        if os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws':
            self._json_response(503, {
                'error': 'Settings cannot be changed through the UI on this deployment. '
                         'Write lde/github-pat, lde/dtrack-api-key, and lde/gemini-api-key in '
                         'AWS Secrets Manager (docs/aws-deployment.md ## Step 4 — Populate secrets). '
                         'LDE reads Secrets Manager within a minute.'
            })
            return
        patch = self._read_body()
        if not isinstance(patch, dict):
            raise ValueError('Body must be a JSON object')
        unknown = set(patch.keys()) - settings_mod.ALLOWED_KEYS
        if unknown:
            raise ValueError(f'Unknown settings keys: {sorted(unknown)}')
        updated = settings_mod.save_settings(patch)
        self._json_response(200, settings_mod.masked(updated))

    def handle_gh_status(self, groups, qs):
        self._json_response(200, gh_auth.auth_status())

    def handle_dtrack_status(self, groups, qs):
        """Validate the saved Dependency-Track API key against DT.

        Tests only the server-side saved settings — never accepts a URL or
        key from the request — so this can't be used as an SSRF probe.
        """
        s = settings_mod.load_settings()
        api_key = (s.get('dtrack_api_key') or '').strip()
        if api_key == 'REPLACE_ME':
            self._json_response(200, {
                'configured': True,
                'ok': False,
                'team': None,
                'permissions': [],
                'missing_permissions': [],
                'message': 'lde/dtrack-api-key is still the placeholder REPLACE_ME. '
                           'Run scripts/bootstrap_dtrack.py (docs/aws-deployment.md Step 5).',
            })
            return
        status = dtrack_client.connection_status(
            s.get('dtrack_url'), s.get('dtrack_api_key'))
        self._json_response(200, status)

    def handle_gemini_status(self, groups, qs):
        """Validate the saved Gemini API key against the saved model.

        Tests only the server-side saved settings — never accepts a key or
        model from the request — so this can't be used as an SSRF or
        credential-probing vector. Uses GET /v1beta/models/{model}, a free
        metadata lookup, so this costs nothing to run.
        """
        from backend import package_extractor
        s = settings_mod.load_settings()
        status = package_extractor.connection_status(
            s.get('gemini_api_key'), s.get('gemini_model'))
        self._json_response(200, status)

    # ---- Runs ----------------------------------------------------------

    def handle_list_runs(self, groups, qs):
        conn = db.get_db()
        try:
            rows = conn.execute(
                'SELECT id, started_at, completed_at, status, stage, orgs_json, repos_json, method '
                'FROM runs ORDER BY started_at DESC LIMIT 100'
            ).fetchall()
        finally:
            conn.close()
        runs = []
        for r in rows:
            runs.append({
                'id': r['id'],
                'started_at': r['started_at'],
                'completed_at': r['completed_at'],
                'status': r['status'],
                'stage': r['stage'],
                'method': r['method'] or 'ort',
                'orgs': json.loads(r['orgs_json'] or '[]'),
                'repos': json.loads(r['repos_json']) if r['repos_json'] else [],
            })
        self._json_response(200, runs)

    _VALID_METHODS = {'ort', 'github_sbom'}

    def _valid_methods_for_env(self):
        if _DISABLE_ORT:
            return self._VALID_METHODS - {'ort'}
        return self._VALID_METHODS

    def handle_create_run(self, groups, qs):
        body = self._read_body()
        requested_orgs = body.get('orgs') or []
        if not isinstance(requested_orgs, list):
            raise ValueError('orgs must be a list')

        repos_raw = body.get('repos') or []
        if not isinstance(repos_raw, list):
            raise ValueError('repos must be a list')
        _REPO_RE = re.compile(r'^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)?$')
        for r in repos_raw:
            if not isinstance(r, str) or not r.strip() or not _REPO_RE.match(r.strip()):
                raise ValueError(
                    f'Invalid repo {r!r}: use "repo-name" or "org/repo-name" format')
        requested_repos = [r.strip() for r in repos_raw]

        # When all repos are in org/repo format, derive orgs from them so
        # the run isn't needlessly scanned across every default org.
        if requested_repos and all('/' in r for r in requested_repos):
            derived_orgs = list(dict.fromkeys(r.split('/')[0] for r in requested_repos))
            requested_orgs = derived_orgs
        if not requested_orgs:
            requested_orgs = settings_mod.load_settings().get('default_orgs') or []
        if not requested_orgs:
            raise ValueError('No orgs provided and no defaults configured')

        method = body.get('method') or 'github_sbom'
        valid = self._valid_methods_for_env()
        if method not in valid:
            if _DISABLE_ORT and method == 'ort':
                raise ValueError('ORT is disabled in this deployment (no Docker socket)')
            raise ValueError(f'Invalid method {method!r}: must be one of {sorted(valid)}')

        # Fail fast: an org with no PAT (and no "*" entry) would only fail later,
        # inside the pipeline, where it is logged and skipped.
        if method == 'github_sbom':
            missing = github_client.orgs_without_token(requested_orgs)
            if missing:
                shown = ', '.join(str(o)[:80] for o in missing[:10])
                raise ValueError(
                    f'No GitHub PAT configured for: {shown}. Add one per org in Settings, '
                    'or add a "*" entry to use one token for every other org.')

        # Optional run-level branch override. `use_default` (or an empty
        # branch) means "use each repo's configured/default branch", stored
        # as NULL. A provided branch is validated with the same rules the
        # GitHub client enforces before it can reach any API URL.
        run_branch = None
        if not body.get('use_default'):
            raw_branch = body.get('branch')
            if isinstance(raw_branch, str) and raw_branch.strip():
                run_branch = raw_branch.strip()
                if not _valid_branch(run_branch):
                    raise ValueError(f'Invalid branch name: {run_branch!r}')

        import uuid as _uuid
        from datetime import datetime, timezone
        run_id = _uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        repos_json = json.dumps(requested_repos) if requested_repos else None
        conn = db.get_db()
        try:
            conn.execute(
                'INSERT INTO runs (id, started_at, status, stage, orgs_json, repos_json, method, branch) '
                'VALUES (?,?,?,?,?,?,?,?)',
                (run_id, now, 'queued', 'queued', json.dumps(requested_orgs),
                 repos_json, method, run_branch),
            )
            conn.commit()
        finally:
            conn.close()
        pipeline.start_in_background(run_id)
        self._json_response(202, {'run_id': run_id})

    def handle_get_run(self, groups, qs):
        run_id = groups[0]
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT id, started_at, completed_at, status, stage, orgs_json, repos_json, '
                'method, branch, error FROM runs WHERE id = ?', (run_id,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Run not found'})
            return
        self._json_response(200, {
            'id': row['id'],
            'started_at': row['started_at'],
            'completed_at': row['completed_at'],
            'status': row['status'],
            'stage': row['stage'],
            'method': row['method'] or 'ort',
            'branch': row['branch'] if 'branch' in row.keys() else None,
            'orgs': json.loads(row['orgs_json'] or '[]'),
            'repos': json.loads(row['repos_json']) if row['repos_json'] else [],
            'error': row['error'],
        })

    _STALE_LOG_SECONDS = 300  # 5 minutes without log activity → flag as stale

    def handle_list_run_repos(self, groups, qs):
        run_id = groups[0]
        conn = db.get_db()
        try:
            rows = conn.execute(
                'SELECT org, repo, default_branch, manifest_count, sanitize_status, ort_status, '
                'ort_package_count, dtrack_project_uuid, dtrack_component_count, '
                'bom_overwrite_skipped, analyzer_issue_kind, poetry_fallback_count, '
                'error FROM run_repos WHERE run_id = ? '
                'ORDER BY org, repo', (run_id,)
            ).fetchall()
        finally:
            conn.close()
        # Decorate currently-running repos with "no recent log activity"
        # info so the UI can surface a stuck-vs-just-slow signal.
        logs_dir = os.path.join(DATA_DIR, 'runs', run_id)
        now = time.time()
        out = []
        for r in rows:
            d = dict(r)
            if d['ort_status'] == 'running':
                log_path = os.path.join(logs_dir, f"{d['org']}__{d['repo']}.log")
                try:
                    mtime = os.path.getmtime(log_path)
                    silent = int(now - mtime)
                    if silent > self._STALE_LOG_SECONDS:
                        d['stale_for_seconds'] = silent
                except OSError:
                    pass
            out.append(d)
        self._json_response(200, out)

    def handle_stop_run(self, groups, qs):
        run_id = groups[0]
        conn = db.get_db()
        try:
            row = conn.execute('SELECT status FROM runs WHERE id = ?', (run_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Run not found'})
            return
        if row['status'] not in ('running', 'queued'):
            raise ValueError(f'Cannot stop a run with status={row["status"]}')
        pipeline.request_stop(run_id)
        self._json_response(202, {'status': 'stopping'})

    def handle_continue_run(self, groups, qs):
        run_id = groups[0]
        conn = db.get_db()
        try:
            row = conn.execute('SELECT status FROM runs WHERE id = ?', (run_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Run not found'})
            return
        if row['status'] not in ('failed', 'partial', 'stopped'):
            raise ValueError(f'Cannot continue a run with status={row["status"]}')
        pipeline.start_in_background(run_id, resume=True)
        self._json_response(202, {'run_id': run_id, 'resumed': True})

    def handle_restart_run(self, groups, qs):
        import uuid as _uuid
        from datetime import datetime, timezone
        src_id = groups[0]
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT orgs_json, repos_json, method, branch FROM runs WHERE id = ?', (src_id,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Run not found'})
            return
        new_id = _uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        method = row['method'] or 'ort'
        src_branch = row['branch'] if 'branch' in row.keys() else None
        conn = db.get_db()
        try:
            conn.execute(
                'INSERT INTO runs (id, started_at, status, stage, orgs_json, repos_json, method, branch) '
                'VALUES (?,?,?,?,?,?,?,?)',
                (new_id, now, 'queued', 'queued', row['orgs_json'], row['repos_json'],
                 method, src_branch),
            )
            conn.commit()
        finally:
            conn.close()
        pipeline.start_in_background(new_id)
        self._json_response(202, {'run_id': new_id})

    def handle_retry_failed(self, groups, qs):
        """Reset all failed repos in a run back to pending and resume."""
        run_id = groups[0]
        conn = db.get_db()
        try:
            row = conn.execute('SELECT status FROM runs WHERE id = ?', (run_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Run not found'})
            return
        if row['status'] not in ('failed', 'partial', 'stopped'):
            raise ValueError(f'Cannot retry a run with status={row["status"]!r}')
        reset = pipeline.reset_repos_for_retry(run_id)
        if reset == 0:
            raise ValueError('No failed repos found to retry')
        pipeline.start_in_background(run_id, resume=True)
        self._json_response(202, {'run_id': run_id, 'reset': reset})

    def handle_retry_repo(self, groups, qs):
        """Reset a single failed repo back to pending and resume the run."""
        run_id, org, repo = groups
        _validate_org_repo(org, repo)
        conn = db.get_db()
        try:
            run_row = conn.execute(
                'SELECT status FROM runs WHERE id = ?', (run_id,)
            ).fetchone()
            repo_row = conn.execute(
                'SELECT ort_status FROM run_repos WHERE run_id = ? AND org = ? AND repo = ?',
                (run_id, org, repo),
            ).fetchone()
        finally:
            conn.close()
        if not run_row:
            self._json_response(404, {'error': 'Run not found'})
            return
        if not repo_row:
            self._json_response(404, {'error': 'Repo not found in this run'})
            return
        if run_row['status'] not in ('failed', 'partial', 'stopped'):
            raise ValueError(f'Cannot retry a repo in a run with status={run_row["status"]!r}')
        if repo_row['ort_status'] != 'failed':
            raise ValueError(
                f'Repo ort_status is {repo_row["ort_status"]!r}; only "failed" repos can be retried')
        pipeline.reset_repos_for_retry(run_id, repos=[(org, repo)])
        pipeline.start_in_background(run_id, resume=True)
        self._json_response(202, {'run_id': run_id, 'org': org, 'repo': repo})

    def handle_get_repo_log(self, groups, qs):
        run_id, org, repo = groups
        log_path = os.path.join(DATA_DIR, 'runs', run_id, f'{org}__{repo}.log')
        if not os.path.isfile(log_path):
            self._json_response(404, {'error': 'Log not found'})
            return
        with open(log_path, 'r', errors='replace') as f:
            self._json_response(200, {'log': f.read()})

    # ---- Inspection / data-quality APIs --------------------------------

    def handle_list_run_manifests(self, groups, qs):
        """List every manifest extracted for *run_id* with dep counts.

        Includes both `original_dep_count` (from the as-fetched blob) and
        `sanitized_dep_count` (from the on-disk file the sanitizer wrote
        back). The diff between these = how many local-path / workspace
        / editable entries the sanitizer dropped — useful for spotting
        when a sanitizer is over-stripping (regression guard: a single
        malformed manifest once killed sanitize for an entire org).
        """
        run_id = groups[0]
        conn = db.get_db()
        try:
            rows = conn.execute(
                'SELECT org, repo, filepath, manifest_type, sanitized, original_content '
                'FROM manifests WHERE run_id = ? ORDER BY org, repo, filepath',
                (run_id,),
            ).fetchall()
        finally:
            conn.close()

        sandbox_root = self._sandbox_root_for_run(run_id)

        out = []
        for r in rows:
            original = r['original_content']
            original_counts = sanitizer.get_dep_count(r['filepath'], original) if original else {}
            sanitized = self._read_sanitized(sandbox_root, r['org'], r['repo'], r['filepath'])
            sanitized_counts = sanitizer.get_dep_count(r['filepath'], sanitized) if sanitized else {}
            out.append({
                'org': r['org'],
                'repo': r['repo'],
                'filepath': r['filepath'],
                'manifest_type': r['manifest_type'],
                'sanitized': bool(r['sanitized']),
                'original_dep_count': sanitizer.total_deps(original_counts),
                'sanitized_dep_count': sanitizer.total_deps(sanitized_counts),
                'original_dep_breakdown': original_counts,
                'sanitized_dep_breakdown': sanitized_counts,
                'sandbox_present': sanitized is not None,
                'original_present': original is not None,
            })
        self._json_response(200, out)

    def handle_get_run_manifest(self, groups, qs):
        """Return original + sanitized + dep counts for one manifest.

        The filepath is base64url-encoded in the URL because manifest
        paths legitimately contain `/` and dots (e.g.
        ``packages/core/package.json``). After decoding we
        ``os.path.realpath``-validate that the resolved path is still
        under the per-run sandbox dir, mirroring the same defence used
        by ``_serve_static`` for static files.
        """
        run_id, org, repo, b64_path = groups
        _validate_org_repo(org, repo)
        try:
            import base64
            padded = b64_path + '=' * ((4 - len(b64_path) % 4) % 4)
            rel_path = base64.urlsafe_b64decode(padded.encode()).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            raise ValueError('Invalid base64-encoded filepath')
        if '..' in rel_path.split('/') or rel_path.startswith('/'):
            raise ValueError('filepath escapes the sandbox')

        # DB lookup first so we return a clean 404 for a path that was
        # never extracted (vs. one that's just absent from disk).
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT manifest_type, sanitized, original_content '
                'FROM manifests WHERE run_id = ? AND org = ? AND repo = ? AND filepath = ?',
                (run_id, org, repo, rel_path),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Manifest not found for this run'})
            return

        sandbox_root = self._sandbox_root_for_run(run_id)
        sanitized = self._read_sanitized(sandbox_root, org, repo, rel_path)
        original = row['original_content']
        original_counts = sanitizer.get_dep_count(rel_path, original) if original else {}
        sanitized_counts = sanitizer.get_dep_count(rel_path, sanitized) if sanitized else {}

        self._json_response(200, {
            'org': org,
            'repo': repo,
            'filepath': rel_path,
            'manifest_type': row['manifest_type'],
            'sanitized_flag': bool(row['sanitized']),
            'original': original,
            'sanitized': sanitized,
            'original_dep_breakdown': original_counts,
            'sanitized_dep_breakdown': sanitized_counts,
            'original_dep_count': sanitizer.total_deps(original_counts),
            'sanitized_dep_count': sanitizer.total_deps(sanitized_counts),
        })

    def handle_get_repo_dtrack_components(self, groups, qs):
        """Return DT components for one repo's project + coverage ratio."""
        run_id, org, repo = groups
        _validate_org_repo(org, repo)
        conn = db.get_db()
        try:
            row = conn.execute(
                'SELECT dtrack_project_uuid, dtrack_component_count, ort_package_count, '
                'manifest_count, ort_status, error, bom_overwrite_skipped '
                'FROM run_repos WHERE run_id = ? AND org = ? AND repo = ?',
                (run_id, org, repo),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            self._json_response(404, {'error': 'Repo not found in this run'})
            return

        s = settings_mod.load_settings()
        base_url = s.get('dtrack_url')
        api_key = s.get('dtrack_api_key')
        components = []
        live_count = None
        live_error = None
        uuid = row['dtrack_project_uuid']
        if uuid and uuid != 'auto-created' and base_url and api_key:
            try:
                components = dtrack_client.list_components(base_url, api_key, uuid)
                live_count = len(components)
            except dtrack_client.DtrackError as exc:
                live_error = str(exc)[:300]

        # Coverage ratio: live DT count / sum of declared deps across
        # manifests for this repo. Uses sanitized counts to avoid
        # penalising the repo for the local refs the sanitizer already
        # dropped.
        manifest_total = self._sum_sanitized_deps(run_id, org, repo)
        ratio = None
        if manifest_total and live_count is not None:
            ratio = round(live_count / manifest_total, 2)

        self._json_response(200, {
            'org': org,
            'repo': repo,
            'dtrack_project_uuid': uuid,
            'dt_component_count': live_count,
            'stored_component_count': row['dtrack_component_count'],
            'ort_package_count': row['ort_package_count'],
            'manifest_count': row['manifest_count'],
            'sanitized_dep_total': manifest_total,
            'coverage_ratio': ratio,
            'bom_overwrite_skipped': bool(row['bom_overwrite_skipped']),
            'ort_status': row['ort_status'],
            'error': row['error'],
            'live_error': live_error,
            'components': [
                {
                    'name': c.get('name'),
                    'group': c.get('group'),
                    'version': c.get('version'),
                    'purl': c.get('purl'),
                }
                for c in (components or [])
            ],
        })

    def handle_get_run_coverage(self, groups, qs):
        """Per-repo rollup: manifest types, ort packages, DT counts."""
        run_id = groups[0]
        conn = db.get_db()
        try:
            repos = conn.execute(
                'SELECT org, repo, manifest_count, ort_status, ort_package_count, '
                'dtrack_project_uuid, dtrack_component_count, bom_overwrite_skipped, '
                'analyzer_issue_kind, poetry_fallback_count, error '
                'FROM run_repos WHERE run_id = ? ORDER BY org, repo',
                (run_id,),
            ).fetchall()
            manifests_by_repo = {}
            for m in conn.execute(
                'SELECT org, repo, manifest_type FROM manifests WHERE run_id = ?',
                (run_id,),
            ):
                key = (m['org'], m['repo'])
                manifests_by_repo.setdefault(key, []).append(m['manifest_type'])
        finally:
            conn.close()

        out = []
        for r in repos:
            key = (r['org'], r['repo'])
            types = manifests_by_repo.get(key, [])
            sanitized_total = self._sum_sanitized_deps(run_id, r['org'], r['repo'])
            issue = None
            issue_kinds = []
            if r['analyzer_issue_kind']:
                issue_kinds = [k for k in r['analyzer_issue_kind'].split(';') if k]
            if r['manifest_count'] == 0 and r['ort_status'] == 'skipped':
                issue = 'no manifests extracted'
            elif r['ort_status'] == 'completed' and (r['ort_package_count'] or 0) == 0 and r['manifest_count']:
                issue = 'ORT resolved 0 packages despite manifests present'
            elif r['bom_overwrite_skipped']:
                issue = 'empty-BOM upload refused (preserved prior DT project)'
            elif issue_kinds:
                # Surface analyzer-log fatal patterns even when ORT exited 0
                # and DT got a non-empty BOM. Without this, a Poetry repo
                # whose python-inspector hit RecursionError looks healthy
                # in the rollup despite silently dropping packages.
                issue = f'analyzer issues: {", ".join(sorted(issue_kinds))}'
            elif r['dtrack_component_count'] is not None and sanitized_total \
                    and r['dtrack_component_count'] < sanitized_total:
                issue = (f'DT has {r["dtrack_component_count"]} components but '
                         f'manifests declare ≥{sanitized_total}')
            out.append({
                'org': r['org'],
                'repo': r['repo'],
                'manifest_count': r['manifest_count'],
                'manifest_types': sorted(set(types)),
                'sanitized_dep_total': sanitized_total,
                'ort_package_count': r['ort_package_count'],
                'dtrack_component_count': r['dtrack_component_count'],
                'ort_status': r['ort_status'],
                'has_dtrack_project': bool(r['dtrack_project_uuid']),
                'bom_overwrite_skipped': bool(r['bom_overwrite_skipped']),
                'analyzer_issue_kinds': issue_kinds,
                'poetry_fallback_count': r['poetry_fallback_count'],
                'issue': issue,
                'error': r['error'],
            })
        self._json_response(200, {
            'run_id': run_id,
            'repos': out,
            'summary': {
                'total': len(out),
                'with_issue': sum(1 for x in out if x['issue']),
                'no_manifests': sum(1 for x in out if x['manifest_count'] == 0),
                'zero_packages_after_ort': sum(
                    1 for x in out
                    if x['ort_status'] == 'completed' and (x['ort_package_count'] or 0) == 0
                    and x['manifest_count']
                ),
                'overwrites_refused': sum(1 for x in out if x['bom_overwrite_skipped']),
                'with_analyzer_issues': sum(1 for x in out if x['analyzer_issue_kinds']),
                'poetry_fallback_active': sum(1 for x in out if (x['poetry_fallback_count'] or 0) > 0),
            },
        })

    def handle_dtrack_search(self, groups, qs):
        """Cross-project DT component search (used by @tanstack test)."""
        q_list = qs.get('q') or qs.get('query') or []
        if not q_list:
            raise ValueError('Missing required query parameter q=<text>')
        q = q_list[0].strip()
        if not q:
            raise ValueError('Query must be non-empty')
        if len(q) > 200:
            raise ValueError('Query too long (max 200 chars)')

        s = settings_mod.load_settings()
        base_url = s.get('dtrack_url')
        api_key = s.get('dtrack_api_key')
        if not base_url or not api_key:
            self._json_response(503, {'error': 'Dependency-Track is not configured'})
            return
        try:
            components = dtrack_client.search_components(base_url, api_key, q)
        except dtrack_client.DtrackError as exc:
            # Non-fatal upstream error — surface to caller without leaking
            # raw stack details (Corridor: don't return verbatim upstream
            # errors).
            logger.warning('dtrack_search %s: %s', log_mod.safe(q), log_mod.safe(exc))
            self._json_response(502, {'error': 'Dependency-Track search failed'})
            return

        # Group by project for a UI-friendly shape.
        grouped = {}
        for c in components:
            for proj in (c.get('projects') or [{'name': '?'}]):
                pname = proj.get('name') or '?'
                grouped.setdefault(pname, []).append({
                    'name': c.get('name'),
                    'group': c.get('group'),
                    'version': c.get('version'),
                    'purl': c.get('purl'),
                })
        self._json_response(200, {
            'query': q,
            'total_components': len(components),
            'project_count': len(grouped),
            'projects': [
                {'name': name, 'components': comps}
                for name, comps in sorted(grouped.items())
            ],
        })

    # ---- Package search ------------------------------------------------

    _MAX_PACKAGES = 500
    _MAX_PACKAGE_NAME_LEN = 200
    _SEARCH_WORKERS = 10  # parallel DT API calls

    def handle_package_search(self, groups, qs):
        """Search Dependency-Track for a list of package names.

        Accepts ``{packages: ["name1", "name2", ...]}``.  For each name calls
        ``search_components_by_name`` and returns a list of match objects that
        include ``project_uuid`` and ``component_uuid`` so the frontend can
        construct DT dependency-graph deep links.
        """
        body = self._read_body()
        packages = body.get('packages')
        if not isinstance(packages, list):
            raise ValueError('Body must contain a "packages" array')
        if len(packages) > self._MAX_PACKAGES:
            raise ValueError(f'Too many packages (max {self._MAX_PACKAGES})')
        cleaned = []
        for p in packages:
            if not isinstance(p, str):
                raise ValueError('Each package name must be a string')
            p = p.strip()
            if not p:
                continue
            if len(p) > self._MAX_PACKAGE_NAME_LEN:
                raise ValueError(f'Package name too long (max {self._MAX_PACKAGE_NAME_LEN} chars): {p[:40]!r}')
            cleaned.append(p)
        if not cleaned:
            raise ValueError('No package names provided')

        s = settings_mod.load_settings()
        base_url = s.get('dtrack_url')
        api_key = s.get('dtrack_api_key')
        if not base_url or not api_key:
            self._json_response(503, {'error': 'Dependency-Track is not configured'})
            return
        # UI URL is where deep links point — separate from the API URL.
        ui_url = (s.get('dtrack_ui_url') or '').rstrip('/') or base_url.rstrip('/')

        def _search_one(pkg_name):
            if (api_key or '').strip() == 'REPLACE_ME':
                return {
                    'query': pkg_name,
                    'error': 'lde/dtrack-api-key is still the placeholder REPLACE_ME. '
                             'Run scripts/bootstrap_dtrack.py (docs/aws-deployment.md Step 5). '
                             'Package search does not use the Gemini key.',
                    'matches': [],
                }
            try:
                matches = dtrack_client.search_components_by_name(base_url, api_key, pkg_name)
            except dtrack_client.DtrackError as exc:
                logger.warning('package_search %s: %s',
                               log_mod.safe(pkg_name), log_mod.safe(exc))
                msg = str(exc)
                if '401' in msg:
                    err = ('Dependency-Track rejected the API key (HTTP 401). '
                           'Confirm the Automation team has PROJECT_CREATION_UPLOAD and VIEW_PORTFOLIO.')
                elif '403' in msg:
                    err = ('Dependency-Track rejected the API key (HTTP 403). '
                           'Confirm the Automation team has PROJECT_CREATION_UPLOAD and VIEW_PORTFOLIO.')
                else:
                    err = 'Dependency-Track search error'
                return {'query': pkg_name, 'error': err, 'matches': []}
            enriched = []
            for m in matches:
                proj_uuid = m.get('project_uuid', '')
                comp_uuid = m.get('component_uuid', '')
                project_link = f'{ui_url}/projects/{proj_uuid}' if proj_uuid else ''
                dep_graph_link = (
                    f'{ui_url}/projects/{proj_uuid}/dependencyGraph/{comp_uuid}'
                    if proj_uuid and comp_uuid else ''
                )
                enriched.append({
                    'project': m.get('project', ''),
                    'project_uuid': proj_uuid,
                    'project_version': m.get('project_version', ''),
                    'component': m.get('component', ''),
                    'component_uuid': comp_uuid,
                    'component_version': m.get('component_version', ''),
                    'purl': m.get('purl', ''),
                    'project_link': project_link,
                    'dep_graph_link': dep_graph_link,
                })
            return {'query': pkg_name, 'matches': enriched}

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self._SEARCH_WORKERS, len(cleaned))) as executor:
            results = list(executor.map(_search_one, cleaned))

        self._json_response(200, {'results': results})

    _MAX_UPLOAD_TEXT = 500 * 1024  # 500 KB

    def handle_extract_packages(self, groups, qs):
        """Submit a URL or raw file text for Gemini-powered package extraction.

        Accepts either:
          - ``{url: "https://..."}`` — fetches the URL server-side
          - ``{text: "<html>...", filename: "advisory.html"}`` — uses supplied
            content directly (client-side file upload path)

        Returns ``{task_id}`` immediately; caller polls ``GET /api/tasks/{id}``.
        """
        body = self._read_body()

        s = settings_mod.load_settings()
        gemini_key = s.get('gemini_api_key', '')
        if not gemini_key:
            self._json_response(503, {'error': 'Gemini API key is not configured (see Settings)'})
            return
        gemini_model = s.get('gemini_model', '') or 'gemini-3.8-flash'

        from backend import package_extractor

        if 'text' in body:
            raw = body.get('text', '')
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError('text must be a non-empty string')
            if len(raw) > self._MAX_UPLOAD_TEXT:
                raise ValueError(f'Uploaded content too large (max {self._MAX_UPLOAD_TEXT // 1024} KB)')
            filename = str(body.get('filename', '')).strip()
            task_id = task_queue.submit(package_extractor.run_from_text, raw, filename, gemini_key, gemini_model)
        else:
            url = body.get('url', '').strip()
            if not url:
                raise ValueError('Request body must contain either "url" or "text"')
            if len(url) > 2048:
                raise ValueError('URL too long (max 2048 chars)')
            task_id = task_queue.submit(package_extractor.run, url, gemini_key, gemini_model)

        self._json_response(202, {'task_id': task_id})

    # ---- Inspection helpers --------------------------------------------

    def _sandbox_root_for_run(self, run_id):
        """Return the realpath of /tmp/dummy-repos/{run_id} (may not exist)."""
        from backend import sandbox as _sandbox
        return os.path.realpath(_sandbox.root_for_run(run_id))

    def _read_sanitized(self, sandbox_root, org, repo, rel_path):
        """Read the post-sanitize file off disk, with a realpath check."""
        repo_dir = os.path.realpath(os.path.join(sandbox_root, f'{org}__{repo}'))
        full = os.path.realpath(os.path.join(repo_dir, rel_path))
        if not full.startswith(repo_dir + os.sep) and full != repo_dir:
            return None
        try:
            with open(full, 'r', errors='replace') as f:
                return f.read()
        except (OSError, FileNotFoundError):
            return None

    def _sum_sanitized_deps(self, run_id, org, repo):
        """Sum get_dep_count() across every manifest in this repo of run.

        Pulls original_content + reads the sandbox file. Falls back to
        original-blob-only counts when the sandbox has been pruned.
        """
        conn = db.get_db()
        try:
            rows = conn.execute(
                'SELECT filepath, original_content FROM manifests '
                'WHERE run_id = ? AND org = ? AND repo = ?',
                (run_id, org, repo),
            ).fetchall()
        finally:
            conn.close()
        sandbox_root = self._sandbox_root_for_run(run_id)
        total = 0
        for r in rows:
            content = self._read_sanitized(sandbox_root, org, repo, r['filepath'])
            if content is None:
                content = r['original_content']
            if content is None:
                continue
            total += sanitizer.total_deps(sanitizer.get_dep_count(r['filepath'], content))
        return total

    # ---- Tasks ---------------------------------------------------------

    def handle_get_task(self, groups, qs):
        task_id = groups[0]
        task = task_queue.get(task_id)
        if not task:
            self._json_response(404, {'error': 'Task not found'})
            return
        resp = {'status': task['status'], 'stage': task['stage']}
        if task['status'] in ('completed', 'failed'):
            resp['result'] = task['result']
            resp['error'] = task['error']
            task_queue.consume(task_id)
        self._json_response(200, resp)


# ---------------------------------------------------------------------------
# Auto-reloader
# ---------------------------------------------------------------------------

_WATCH_EXTENSIONS = {'.py', '.html', '.js', '.css', '.json'}
# Build output (site/), IaC (terraform/), runtime data (runs/), and vendored
# deps are not editable source — skipping them keeps the reload walk cheap.
_IGNORE_NAMES = {'__pycache__', 'node_modules', 'runs', 'site', 'terraform'}
_IGNORE_SUFFIXES = {'.db', '.db-wal', '.db-shm'}


def _collect_mtimes():
    mtimes = {}
    for root, dirs, files in os.walk(SERVE_DIR):
        # Prune ignored dirs and ALL dot-directories (.git, .cache, .pytest_cache,
        # .cursor, …). A stray hidden cache (e.g. .cache with tens of thousands of
        # files) otherwise makes this walk take ~30s and blocks server startup.
        dirs[:] = [d for d in dirs
                   if d not in _IGNORE_NAMES and not d.startswith('.')]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext not in _WATCH_EXTENSIONS:
                continue
            if any(fname.endswith(ig) for ig in _IGNORE_SUFFIXES):
                continue
            path = os.path.join(root, fname)
            try:
                mtimes[path] = os.stat(path).st_mtime
            except OSError:
                pass
    return mtimes


def _start_reloader():
    mtimes = _collect_mtimes()

    def _watch():
        nonlocal mtimes
        while True:
            time.sleep(1)
            new = _collect_mtimes()
            changed = [p for p, t in new.items() if mtimes.get(p) != t]
            added = [p for p in new if p not in mtimes]
            if changed or added:
                for p in changed + added:
                    print(f'  reloader: changed {os.path.relpath(p, SERVE_DIR)}')
                print('Reloading server...')
                os.execv(sys.executable, [sys.executable] + sys.argv)

    threading.Thread(target=_watch, daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description='Library Dependency Explorer')
    parser.add_argument('--port', type=int, default=PORT, help=f'Port (default: {PORT})')
    parser.add_argument('--host', default='127.0.0.1', help='Bind address (default: 127.0.0.1)')
    parser.add_argument('--no-reload', action='store_true', help='Disable auto-reload')
    parser.add_argument('--debug', action='store_true',
                        help='Verbose pipeline + HTTP access logging')
    args = parser.parse_args()

    log_mod.setup(debug=args.debug)
    global HTTP_LOG_ENABLED
    HTTP_LOG_ENABLED = args.debug

    db.init_db()
    orphaned = db.mark_orphaned_runs()
    if orphaned:
        logger.warning('Marked %d orphaned run(s) as failed on startup', orphaned)
    if not args.no_reload:
        _start_reloader()

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'Library Dependency Explorer serving on http://{args.host}:{args.port}'
          + ('' if args.no_reload else ' (auto-reload enabled)'))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down.')
        server.server_close()


if __name__ == '__main__':
    main()
