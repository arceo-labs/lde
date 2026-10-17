#!/usr/bin/env python3
"""Tiny disk-backed PyPI caching HTTP proxy.

Mirrors the npm-cache design but handles three URL namespaces because pip
and python-inspector talk to TWO upstream hosts:

  /simple/{pkg}/           → pypi.org/simple/{pkg}/         (HTML index — REWRITTEN)
  /pypi/{pkg}/json         → pypi.org/pypi/{pkg}/json       (JSON metadata API)
  /pypi/{pkg}/{ver}/json   → pypi.org/pypi/{pkg}/{ver}/json
  /files/{path}            → files.pythonhosted.org/{path}  (wheel/sdist downloads)

The /simple/ HTML rewrite is the only non-trivial bit: pip parses the index
HTML and follows the file links it finds, which point at
`https://files.pythonhosted.org/packages/...`. We rewrite those to
`${SELF_URL}/files/packages/...` so the follow-up download flows back
through this proxy and gets cached too.

ORT/prelock containers reach us via `http://pypi-cache:9998/simple/` set
through PIP_INDEX_URL. Upstream HTTPS uses the system CA bundle baked
into the container image, which includes the corporate-proxy root CA.

Stdlib-only. Read-only (GET only — pip never uploads through us).
"""

import hashlib
import http.server
import os
import re
import socketserver
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CACHE_DIR = os.environ.get('CACHE_DIR', '/cache')
PORT = int(os.environ.get('PORT', '9998'))
SELF_URL = os.environ.get('SELF_URL', f'http://pypi-cache:{PORT}').rstrip('/')
UPSTREAM_TIMEOUT = int(os.environ.get('UPSTREAM_TIMEOUT', '60'))

_PYPI_HOST = 'https://pypi.org'
_FILES_HOST = 'https://files.pythonhosted.org'

_FILES_REWRITE_RE = re.compile(rb'https://files\.pythonhosted\.org/')


def _cache_path(path):
    """Map a URL path to a disk path under CACHE_DIR. Same scheme as npm-cache."""
    digest = hashlib.sha256(path.encode('utf-8')).hexdigest()
    sub1, sub2 = digest[:2], digest[2:4]
    d = os.path.join(CACHE_DIR, sub1, sub2)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, digest)


def _rewrite_simple_index(body):
    """Rewrite absolute files.pythonhosted.org URLs to point at us.

    Pip's simple-repository protocol expects absolute URLs in the HTML.
    After rewriting, pip's follow-up fetches for the file content route
    back through this proxy under /files/, which we then cache too.
    """
    replacement = f'{SELF_URL}/files/'.encode('ascii')
    return _FILES_REWRITE_RE.sub(replacement, body)


def _fetch_upstream(url, accept=None):
    """Return (status, body, content_type) for a GET to *url*."""
    headers = {'User-Agent': 'depexplorer-pypi-cache/1.0'}
    if accept:
        headers['Accept'] = accept
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
            return resp.status, resp.read(), resp.headers.get('Content-Type', '')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get('Content-Type', '')


class Handler(http.server.BaseHTTPRequestHandler):

    server_version = 'depexplorer-pypi-cache/1.0'

    def _serve_bytes(self, status, body, content_type, cache_status):
        # Stash BEFORE send_response — that call triggers log_request →
        # log_message, which reads self._x_cache. Setting it after would
        # always log empty.
        self._x_cache = cache_status
        self.send_response(status)
        self.send_header('Content-Type', content_type or 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Cache', cache_status)
        self.end_headers()
        self.wfile.write(body)

    def _serve_health(self):
        body = b'pypi-cache ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cached_or_fetch(self, upstream_url, rewrite=False, accept=None):
        """Return (cached_body, was_hit, content_type). Caches 2xx only."""
        cache_key = self.path  # full path including query
        cached = _cache_path(cache_key)
        if os.path.isfile(cached):
            try:
                with open(cached, 'rb') as f:
                    return f.read(), True, None
            except OSError:
                pass  # fall through to refetch

        status, body, ctype = _fetch_upstream(upstream_url, accept=accept)
        if status >= 300:
            return body, False, ctype, status
        if rewrite:
            body = _rewrite_simple_index(body)
        try:
            tmp = cached + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(body)
            os.replace(tmp, cached)
        except OSError as exc:
            sys.stderr.write(f'cache write failed for {self.path}: {exc}\n')
        return body, False, ctype, 200

    def do_GET(self):
        # Health
        if self.path == '/' or self.path == '/health':
            return self._serve_health()

        # Simple index (HTML, with rewriting)
        if self.path.startswith('/simple/'):
            upstream = _PYPI_HOST + self.path
            result = self._cached_or_fetch(upstream, rewrite=True,
                                           accept='text/html')
            if len(result) == 4:
                body, hit, ctype, status = result
            else:
                body, hit, ctype = result
                status = 200
            return self._serve_bytes(
                status, body,
                ctype or 'application/vnd.pypi.simple.v1+html',
                'HIT' if hit else 'MISS',
            )

        # JSON metadata API
        if self.path.startswith('/pypi/'):
            upstream = _PYPI_HOST + self.path
            result = self._cached_or_fetch(upstream, accept='application/json')
            if len(result) == 4:
                body, hit, ctype, status = result
            else:
                body, hit, ctype = result
                status = 200
            return self._serve_bytes(
                status, body,
                ctype or 'application/json',
                'HIT' if hit else 'MISS',
            )

        # File downloads (wheels/sdists)
        if self.path.startswith('/files/'):
            # Strip the /files prefix so we end up with what
            # files.pythonhosted.org expects.
            upstream_path = self.path[len('/files'):]
            upstream = _FILES_HOST + upstream_path
            result = self._cached_or_fetch(upstream)
            if len(result) == 4:
                body, hit, ctype, status = result
            else:
                body, hit, ctype = result
                status = 200
            return self._serve_bytes(
                status, body,
                ctype or 'application/octet-stream',
                'HIT' if hit else 'MISS',
            )

        self.send_error(404, 'Unknown path; expected /simple/, /pypi/, or /files/')

    def do_HEAD(self):
        # Some clients HEAD before GET. Forward without caching.
        if self.path.startswith('/simple/'):
            upstream = _PYPI_HOST + self.path
        elif self.path.startswith('/pypi/'):
            upstream = _PYPI_HOST + self.path
        elif self.path.startswith('/files/'):
            upstream = _FILES_HOST + self.path[len('/files'):]
        else:
            return self._serve_health()
        try:
            req = urllib.request.Request(upstream, method='HEAD')
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() in ('content-type', 'content-length',
                                     'etag', 'last-modified'):
                        self.send_header(k, v)
                self.end_headers()
        except Exception as exc:
            self.send_error(502, f'Upstream HEAD failed: {exc}')

    def log_message(self, fmt, *args):
        cache = getattr(self, '_x_cache', '')
        sys.stderr.write(
            f'{time.strftime("%H:%M:%S")} {self.address_string()} {fmt % args}'
            f'{" [" + cache + "]" if cache else ""}\n'
        )


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    sys.stderr.write(
        f'pypi-cache listening on 0.0.0.0:{PORT}, self_url={SELF_URL}, cache={CACHE_DIR}\n'
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == '__main__':
    main()
