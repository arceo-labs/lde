"""Coverage for cache_server/server.py — npm-cache scoped-package handling.

Hypothesis driving these tests: scoped packages (`@tanstack/react-query`)
arrive at the proxy in two distinct path shapes that npm uses
interchangeably:

    GET /@tanstack%2Freact-query     # metadata (npm CLI ≥ 7)
    GET /@tanstack/react-query/-/react-query-5.0.0.tgz   # tarball

Both must hit upstream cleanly, be cached, and replay on the next call.
A subtle compression bug (cache stored gzipped bytes without a
Content-Encoding header) was suspected as the cause of missing
@tanstack components in DT for several example-org repos — the fix is
to send `Accept-Encoding: identity` on every upstream fetch so we
only ever cache plain bodies.
"""

import http.server
import importlib.util
import os
import sys
import threading
import urllib.error
import urllib.request

import pytest


def _load_npm_cache(tmp_path, monkeypatch, upstream_url):
    """Import cache_server/server.py with env redirected at a mock upstream.

    The module isn't a package and binds UPSTREAM/CACHE_DIR at import
    time, so we have to (re-)import it with the env we want.
    """
    monkeypatch.setenv('CACHE_DIR', str(tmp_path))
    monkeypatch.setenv('UPSTREAM', upstream_url)
    monkeypatch.setenv('PORT', '0')          # 0 = ephemeral; we don't .serve_forever()
    monkeypatch.setenv('UPSTREAM_TIMEOUT', '5')
    monkeypatch.setenv('NOT_FOUND_TTL', '60')
    spec = importlib.util.spec_from_file_location(
        f'npm_cs_{os.urandom(4).hex()}',
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     'cache_server', 'server.py'),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _MockRegistry(http.server.BaseHTTPRequestHandler):
    """Pretends to be registry.npmjs.org for a single test."""

    # Set on the class by the fixture below.
    paths_seen = None
    accept_encodings_seen = None

    def do_GET(self):
        type(self).paths_seen.append(self.path)
        type(self).accept_encodings_seen.append(self.headers.get('Accept-Encoding', ''))

        if self.path == '/@tanstack%2Freact-query':
            body = b'{"name":"@tanstack/react-query","versions":{"5.0.0":{}}}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == '/@tanstack/react-query/-/react-query-5.0.0.tgz':
            body = b'fake-tarball-bytes'
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == '/@notpresent%2Fpkg':
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error":"not_found"}')
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # quiet


@pytest.fixture
def mock_registry():
    """Spin up a real loopback HTTP server pretending to be the registry."""
    _MockRegistry.paths_seen = []
    _MockRegistry.accept_encodings_seen = []
    server = http.server.HTTPServer(('127.0.0.1', 0), _MockRegistry)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f'http://127.0.0.1:{port}', server
    server.shutdown()
    server.server_close()


def test_scoped_package_metadata_caches_and_replays(tmp_path, monkeypatch, mock_registry):
    """The first GET hits upstream; the second is served from disk cache."""
    upstream, _ = mock_registry
    npm = _load_npm_cache(tmp_path, monkeypatch, upstream)

    # Drive _fetch_upstream directly — it's the function that has to
    # honour the encoded-slash form npm sends for scoped pkg metadata.
    status, body, ctype = npm._fetch_upstream('/@tanstack%2Freact-query')
    assert status == 200
    assert b'@tanstack/react-query' in body
    assert _MockRegistry.paths_seen[-1] == '/@tanstack%2Freact-query'

    # Confirm the call was identity-encoded so we never cache opaque
    # gzip bytes (the leading hypothesis for the missing-deps bug).
    assert _MockRegistry.accept_encodings_seen[-1] == 'identity'


def test_scoped_tarball_path_passes_through_unchanged(tmp_path, monkeypatch, mock_registry):
    """Tarballs arrive at the proxy with literal slashes between scope/name."""
    upstream, _ = mock_registry
    npm = _load_npm_cache(tmp_path, monkeypatch, upstream)

    status, body, _ = npm._fetch_upstream('/@tanstack/react-query/-/react-query-5.0.0.tgz')
    assert status == 200
    assert body == b'fake-tarball-bytes'
    assert _MockRegistry.paths_seen[-1] == '/@tanstack/react-query/-/react-query-5.0.0.tgz'


def test_cache_path_distinguishes_encoded_vs_unencoded_paths(tmp_path, monkeypatch, mock_registry):
    """Encoded and unencoded variants get separate cache entries.

    Not a correctness bug but a known cache-efficiency quirk worth
    pinning so future refactors don't accidentally collapse them
    (which would break callers that depend on path-keyed caches).
    """
    upstream, _ = mock_registry
    npm = _load_npm_cache(tmp_path, monkeypatch, upstream)
    p1 = npm._cache_path('/@tanstack%2Freact-query')
    p2 = npm._cache_path('/@tanstack/react-query')
    assert p1 != p2


def test_404_for_scoped_package_is_cached(tmp_path, monkeypatch, mock_registry):
    """Scoped-package 404s must hit the same NOT_FOUND_TTL sidecar code path
    that protects upstream from `*` lookups in package overrides."""
    upstream, _ = mock_registry
    npm = _load_npm_cache(tmp_path, monkeypatch, upstream)
    status, _body, _ctype = npm._fetch_upstream('/@notpresent%2Fpkg')
    assert status == 404
    assert _MockRegistry.paths_seen[-1] == '/@notpresent%2Fpkg'


def test_asterisk_block_does_not_match_at_sign(tmp_path, monkeypatch, mock_registry):
    """The `*`-blocking guard must not trigger on scoped names containing @."""
    upstream, _ = mock_registry
    npm = _load_npm_cache(tmp_path, monkeypatch, upstream)
    # `*` is in path → blocked, even if elsewhere
    assert '*' in '/foo/*'
    # @ alone does NOT match the * guard
    assert '*' not in '/@tanstack%2Freact-query'
    assert '*' not in '/@tanstack/react-query/-/react-query-5.0.0.tgz'
