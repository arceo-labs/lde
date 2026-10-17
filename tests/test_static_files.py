"""_serve_static serves only the UI assets, never source, docs or the data volume."""

import io
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402


@pytest.fixture
def app_dir(tmp_path, monkeypatch):
    """A fake /app laid out like the Fargate image, with /app/data inside it."""
    files = {
        'index.html': '<html>ui</html>',
        'css/styles.css': 'body{}',
        'js/app.js': 'export {}',
        'server.py': 'SOURCE',
        'backend/settings.py': 'SOURCE',
        'AGENTS.md': 'DOC',
        'openapi.json': '{}',
        'depexplorer.db': 'LOCAL DB',
        'data/depexplorer.db': 'AWS DB',
        'data/runs/abc/org__repo.github_sbom.json': '{}',
        '.settings.json': '{"secret": 1}',
    }
    for rel, body in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    (tmp_path / 'js' / 'leak.js').symlink_to(tmp_path / 'server.py')
    (tmp_path / 'css' / 'data').symlink_to(tmp_path / 'data', target_is_directory=True)
    monkeypatch.setattr(server, 'SERVE_DIR', str(tmp_path))
    return tmp_path


def _get(path):
    handler = server.Handler.__new__(server.Handler)
    handler.path = path
    handler.headers = {}
    handler.status = None
    buf = io.BytesIO()
    handler.wfile = MagicMock()
    handler.wfile.write = buf.write
    handler._require_auth = lambda: True
    handler.send_response = lambda code, message=None: setattr(handler, 'status', code)
    handler.send_header = lambda key, value: None
    handler.end_headers = lambda: None
    handler.send_error = lambda code, message=None: setattr(handler, 'status', code)
    handler._serve_static()
    return handler.status, buf.getvalue()


@pytest.mark.parametrize('path, body', [
    ('/', b'<html>ui</html>'),
    ('/index.html', b'<html>ui</html>'),
    ('/css/styles.css', b'body{}'),
    ('/js/app.js', b'export {}'),
    ('/runs', b'<html>ui</html>'),            # SPA route
    ('/package-search', b'<html>ui</html>'),  # SPA route
])
def test_ui_assets_are_served(app_dir, path, body):
    assert _get(path) == (200, body)


@pytest.mark.parametrize('path', [
    '/server.py',
    '/backend/settings.py',
    '/AGENTS.md',
    '/openapi.json',
    '/depexplorer.db',                                  # local data dir = repo root
    '/data/depexplorer.db',                             # AWS: LDE_DATA_DIR=/app/data
    '/data/runs/abc/org__repo.github_sbom.json',
    '/js/leak.js',                                      # symlink out of js/
    '/css/data/depexplorer.db',                         # symlinked dir out of css/
    '/css/missing.css',
])
def test_everything_else_is_404(app_dir, path):
    status, body = _get(path)
    assert status == 404
    assert body == b''


@pytest.mark.parametrize('path', ['/.settings.json', '/css/../server.py', '/js/../data/depexplorer.db'])
def test_dot_segments_are_403(app_dir, path):
    status, body = _get(path)
    assert status == 403
    assert body == b''


def test_auth_is_checked_first(app_dir):
    handler = server.Handler.__new__(server.Handler)
    handler.path = '/index.html'
    handler._require_auth = lambda: False
    handler.send_response = MagicMock()
    handler._serve_static()
    handler.send_response.assert_not_called()
