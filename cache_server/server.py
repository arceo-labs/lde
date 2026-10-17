#!/usr/bin/env python3
"""Tiny disk-backed npm-registry caching HTTP proxy.

Listens on :9999 (plain HTTP). For every GET request, computes a SHA256
of the request path, looks for a cached response under
/cache/{sha[:2]}/{sha[2:4]}/{sha}. On hit, serves it. On miss, fetches
https://registry.npmjs.org{path}, writes the response to the cache dir
atomically, then serves it.

404 responses are cached separately in a sidecar file ({cache_path}.404)
for NOT_FOUND_TTL seconds (default 300). This prevents repeated upstream
hits for paths that will never resolve — e.g. packages with invalid names
like `*` that show up in some package.json overrides fields.

Intended to be reached by ORT/prelock containers on the `ort-egress`
docker network as `http://npm-cache:9999` (set via NPM_CONFIG_REGISTRY).
Upstream HTTPS uses the system CA bundle baked into the container image,
which includes the corporate-proxy root CA if `certs/*.crt` are present
at image-build time.

Stdlib-only. Read-only (GET only — npm publish never flows through us).
"""

import hashlib
import http.server
import os
import socketserver
import sys
import time
import urllib.error
import urllib.request

CACHE_DIR = os.environ.get('CACHE_DIR', '/cache')
UPSTREAM = os.environ.get('UPSTREAM', 'https://registry.npmjs.org')
PORT = int(os.environ.get('PORT', '9999'))
UPSTREAM_TIMEOUT = int(os.environ.get('UPSTREAM_TIMEOUT', '30'))
NOT_FOUND_TTL = int(os.environ.get('NOT_FOUND_TTL', '300'))


def _cache_path(path):
    """Map a URL path to a disk path under CACHE_DIR.

    SHA256 of the path keeps filenames safe (no path traversal, no
    filesystem-illegal characters) and gives us a deterministic shard
    structure for filesystems that struggle with many files in one dir.
    """
    digest = hashlib.sha256(path.encode('utf-8')).hexdigest()
    sub1, sub2 = digest[:2], digest[2:4]
    d = os.path.join(CACHE_DIR, sub1, sub2)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, digest)


def _fetch_upstream(path):
    """Return (status, body, content_type).

    `Accept-Encoding: identity` is set explicitly to prevent the
    registry from returning a gzip/deflate-compressed body that we would
    then cache as opaque bytes and serve back to npm without the
    Content-Encoding header — npm would parse the raw gzip as JSON and
    fail. This was the leading hypothesis for missing scoped packages
    like `@tanstack/react-query`: the metadata is small enough that the
    upstream sometimes returns it gzipped, our cache stored the gzipped
    bytes, and downstream parsing silently dropped the dep on every
    later run.
    """
    url = UPSTREAM.rstrip('/') + path
    req = urllib.request.Request(url, headers={
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'User-Agent': 'depexplorer-npm-cache/1.0',
    })
    try:
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
            return resp.status, resp.read(), resp.headers.get('Content-Type', 'application/octet-stream')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get('Content-Type', 'application/json')


class Handler(http.server.BaseHTTPRequestHandler):

    server_version = 'depexplorer-npm-cache/1.0'

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

    def do_GET(self):
        # npm sends GET /* for packages literally named '*' (e.g. overrides: {"*": "..."}).
        # These can never resolve — skip cache and upstream entirely.
        if '*' in self.path:
            self._serve_bytes(404, b'{"error":"Not found"}', 'application/json', 'BLOCKED')
            return

        cached = _cache_path(self.path)

        # Check 2xx cache hit.
        if os.path.isfile(cached):
            try:
                with open(cached, 'rb') as f:
                    body = f.read()
                ctype = 'application/json' if self.path.endswith('/') or '?' in self.path else None
                if not ctype:
                    ctype = 'application/octet-stream' if self.path.endswith('.tgz') else 'application/json'
                self._serve_bytes(200, body, ctype, 'HIT')
                return
            except OSError:
                # Corrupt cache file — fall through and refetch.
                pass

        # Check short-lived 404 cache.  Sidecar format: first line is the
        # expiry timestamp (float), second line is Content-Type, remaining
        # bytes are the response body.  All written atomically.
        not_found_sidecar = cached + '.404'
        if os.path.isfile(not_found_sidecar):
            try:
                with open(not_found_sidecar, 'rb') as f:
                    raw = f.read()
                first_nl = raw.index(b'\n')
                second_nl = raw.index(b'\n', first_nl + 1)
                expiry = float(raw[:first_nl].decode('ascii'))
                if expiry > time.time():
                    ctype = raw[first_nl + 1:second_nl].decode('ascii')
                    body = raw[second_nl + 1:]
                    self._serve_bytes(404, body, ctype, 'HIT(404)')
                    return
                # Expired — remove and let it refetch.
                os.unlink(not_found_sidecar)
            except OSError:
                pass  # missing or unreadable — fall through

        try:
            status, body, ctype = _fetch_upstream(self.path)
        except urllib.error.URLError as exc:
            self.send_error(502, f'Upstream error: {exc.reason}')
            return
        except Exception as exc:
            self.send_error(502, f'Upstream error: {exc}')
            return

        if 200 <= status < 300:
            try:
                tmp = cached + '.tmp'
                with open(tmp, 'wb') as f:
                    f.write(body)
                os.replace(tmp, cached)
            except OSError as exc:
                sys.stderr.write(f'cache write failed for {self.path}: {exc}\n')
        elif status == 404:
            # Cache 404s briefly so invalid/non-existent package names (e.g. a
            # package literally named `*` from an overrides field) don't hammer
            # upstream on every npm invocation across every repo.
            try:
                header = f'{time.time() + NOT_FOUND_TTL}\n{ctype}\n'.encode('ascii')
                tmp = not_found_sidecar + '.tmp'
                with open(tmp, 'wb') as f:
                    f.write(header + body)
                os.replace(tmp, not_found_sidecar)
            except OSError as exc:
                sys.stderr.write(f'404-cache write failed for {self.path}: {exc}\n')

        self._serve_bytes(status, body, ctype, 'MISS')

    def do_HEAD(self):
        # npm sometimes HEADs before GET. Forward without caching.
        try:
            req = urllib.request.Request(UPSTREAM.rstrip('/') + self.path, method='HEAD')
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() in ('content-length', 'content-type', 'etag', 'last-modified'):
                        self.send_header(k, v)
                self.end_headers()
        except Exception as exc:
            self.send_error(502, f'Upstream HEAD failed: {exc}')

    def log_message(self, fmt, *args):
        # Compact one-liner: timestamp, ip, request line, X-Cache (if any)
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
        f'npm-cache listening on 0.0.0.0:{PORT}, upstream={UPSTREAM}, cache={CACHE_DIR}\n'
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == '__main__':
    main()
