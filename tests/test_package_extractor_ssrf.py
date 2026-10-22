"""SSRF checks: resolve once and connect to the validated IP, not the hostname."""

import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import package_extractor  # noqa: E402


def _addrinfo(ip, port):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, '', (ip, port))]


def _addrinfos(ips, port):
    rows = []
    for ip in ips:
        rows.extend(_addrinfo(ip, port))
    return rows


def test_validate_url_blocks_loopback():
    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._validate_url('http://127.0.0.1/')


def test_validate_url_blocks_link_local():
    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._validate_url('http://169.254.169.254/')


def test_validate_url_blocks_shared_cgnat_space():
    # RFC 6598 100.64.0.0/10 — used internally by some cloud providers.
    # Not is_private/is_reserved in Python's ipaddress module.
    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._validate_url('http://100.64.1.1/')


def test_validate_url_blocks_multicast():
    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._validate_url('http://224.0.0.1/')


def test_validate_url_blocks_unspecified():
    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._validate_url('http://0.0.0.0/')


def test_validate_url_allows_public_ip(monkeypatch):
    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo('8.8.8.8', port)

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    assert package_extractor._validate_url('http://public.example/') == 'http://public.example/'


def test_validate_url_rejects_non_http_scheme():
    with pytest.raises(ValueError, match='scheme'):
        package_extractor._validate_url('file:///etc/passwd')


def test_validate_url_rejects_non_default_port():
    with pytest.raises(ValueError, match='port'):
        package_extractor._validate_url('https://example.com:8443/')


class _FakeSock:
    def close(self):
        pass

    def settimeout(self, _timeout):
        pass


class _FakeResp:
    def __init__(self, status=200, headers=None, body=b'', reason='OK'):
        self.status = status
        self.reason = reason
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body

    def getheader(self, name, default=None):
        return self._headers.get(name.lower(), default)

    def read(self, amt=None):
        if amt is None:
            data, self._body = self._body, b''
            return data
        chunk, self._body = self._body[:amt], self._body[amt:]
        return chunk


class _UndrainableResp(_FakeResp):
    """A response whose body must never be read (simulates an unbounded body)."""

    def read(self):
        raise AssertionError('response body was read when it should have been skipped')


class _FakeConn:
    instances = []

    def __init__(self, host, port=None, timeout=None, context=None):
        self.host = host
        self.port = port
        self.sock = None
        self.closed = False
        self.requests = []
        self._responses = []
        _FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self._responses.pop(0)

    def close(self):
        self.closed = True


def _html(n_words=50):
    return ('<html><p>' + 'word ' * n_words + '</p></html>').encode()


def test_host_header_omits_scheme_default_and_keeps_explicit_port():
    assert package_extractor._host_header('example.com', 80, 'http') == 'example.com'
    assert package_extractor._host_header('example.com', 443, 'https') == 'example.com'
    assert package_extractor._host_header('example.com', 443, 'http') == 'example.com:443'
    assert package_extractor._host_header('example.com', 80, 'https') == 'example.com:80'
    assert package_extractor._host_header('2001:db8::1', 80, 'http') == '[2001:db8::1]'
    assert package_extractor._host_header('2001:db8::1', 443, 'http') == '[2001:db8::1]:443'


def test_https_connects_to_resolved_ip_with_sni(monkeypatch):
    ip = '8.8.8.8'
    seen = {}

    def fake_gai(host, port, proto=0, **_kw):
        assert host == 'advisory.example'
        return _addrinfo(ip, port)

    def fake_create(addr, timeout=None):
        seen['addr'] = addr
        seen['timeout'] = timeout
        return _FakeSock()

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            seen['sni'] = server_hostname
            return sock

    _FakeConn.instances = []

    def https_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            headers={'Content-Type': 'text/html; charset=utf-8'},
            body=_html(),
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', fake_create)
    monkeypatch.setattr(package_extractor.ssl, 'create_default_context', lambda: FakeCtx())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPSConnection', https_conn)

    def boom(*_a, **_k):
        raise AssertionError('urlopen must not be used for advisory fetches')

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', boom)

    html = package_extractor._fetch_url('https://advisory.example/cve')
    assert 'word' in html
    assert seen['addr'] == (ip, 443)
    assert seen['sni'] == 'advisory.example'
    assert seen['timeout'] == package_extractor._FETCH_TIMEOUT_S
    headers = _FakeConn.instances[0].requests[0][2]
    assert headers['Host'] == 'advisory.example'


def test_http_explicit_443_is_in_host_header(monkeypatch):
    ip = '8.8.8.8'
    seen = {}
    _FakeConn.instances = []

    def fake_gai(host, port, proto=0, **_kw):
        seen['gai_port'] = port
        return _addrinfo(ip, port)

    def fake_create(addr, timeout=None):
        seen['addr'] = addr
        return _FakeSock()

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            headers={'Content-Type': 'text/html; charset=utf-8'},
            body=_html(),
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', fake_create)
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    html = package_extractor._fetch_url('http://advisory.example:443/cve')
    assert 'word' in html
    assert seen['gai_port'] == 443
    assert seen['addr'] == (ip, 443)
    assert _FakeConn.instances[-1].requests[0][2]['Host'] == 'advisory.example:443'


def test_tries_next_validated_address_without_resolving_again(monkeypatch):
    v6, v4 = '2001:4860:4860::8888', '8.8.8.8'
    gai_calls = []
    connects = []

    def fake_gai(host, port, proto=0, **_kw):
        gai_calls.append(host)
        return _addrinfos([v6, v4], port)

    def fake_create(addr, timeout=None):
        connects.append(addr)
        if addr[0] == v6:
            raise OSError('Network is unreachable')
        return _FakeSock()

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            headers={'Content-Type': 'text/html; charset=utf-8'},
            body=_html(),
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', fake_create)
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    html = package_extractor._fetch_url('http://advisory.example/cve')
    assert 'word' in html
    assert gai_calls == ['advisory.example']
    assert connects == [(v6, 80), (v4, 80)]


def test_redirect_to_blocked_ip_is_rejected_before_connect(monkeypatch):
    public_ip = '8.8.8.8'
    connects = []

    def fake_gai(host, port, proto=0, **_kw):
        if host == 'advisory.example':
            return _addrinfo(public_ip, port)
        if host == '169.254.170.2':
            return _addrinfo('169.254.170.2', port)
        raise socket.gaierror('unexpected host')

    def fake_create(addr, timeout=None):
        connects.append(addr)
        if addr[0] != public_ip:
            raise AssertionError(f'connected to blocked address {addr}')
        return _FakeSock()

    _FakeConn.instances = []

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            status=302,
            reason='Found',
            headers={'Location': 'http://169.254.170.2/latest/meta-data/'},
            body=b'',
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', fake_create)
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='blocked address'):
        package_extractor._fetch_url('http://advisory.example/cve')
    assert connects == [(public_ip, 80)]


def test_redirect_body_is_not_read(monkeypatch):
    # A caller-controlled redirect target could return a huge body; the
    # connection is closed right after, so it must never be read into memory.
    ip = '8.8.8.8'

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo(ip, port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_UndrainableResp(
            status=302,
            headers={'Location': 'http://advisory.example/next'},
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='Too many redirects'):
        package_extractor._fetch_url('http://advisory.example/start')


def test_error_response_body_is_not_read(monkeypatch):
    # Same concern for a non-redirect, non-2xx response (e.g. 500 with a
    # caller-controlled, arbitrarily large body).
    ip = '8.8.8.8'

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo(ip, port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_UndrainableResp(status=500, reason='Internal Server Error')]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='Failed to fetch URL'):
        package_extractor._fetch_url('http://advisory.example/cve')


def test_too_many_redirects(monkeypatch):
    ip = '8.8.8.8'

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo(ip, port)

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            status=302,
            headers={'Location': 'http://advisory.example/next'},
            body=b'',
        )]
        return conn

    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='Too many redirects'):
        package_extractor._fetch_url('http://advisory.example/start')


def test_304_is_not_treated_as_redirect(monkeypatch):
    ip = '8.8.8.8'
    statuses = [304, 200]
    locations = []

    def fake_gai(host, port, proto=0, **_kw):
        locations.append(host)
        return _addrinfo(ip, port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        status = statuses.pop(0)
        conn._responses = [_FakeResp(
            status=status,
            reason='Not Modified' if status == 304 else 'OK',
            headers={'Content-Type': 'text/html; charset=utf-8'},
            body=_html() if status == 200 else b'',
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    html = package_extractor._fetch_url('http://advisory.example/cve')
    assert 'word' in html
    assert locations == ['advisory.example', 'advisory.example']
    assert statuses == []


def test_305_location_is_not_followed(monkeypatch):
    public_ip = '8.8.8.8'
    connects = []

    def fake_gai(host, port, proto=0, **_kw):
        if host != 'advisory.example':
            raise AssertionError(f'resolved unexpected host {host}')
        return _addrinfo(public_ip, port)

    def fake_create(addr, timeout=None):
        connects.append(addr)
        return _FakeSock()

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            status=305,
            reason='Use Proxy',
            headers={'Location': 'http://169.254.170.2/'},
            body=b'',
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', fake_create)
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='Failed to fetch URL'):
        package_extractor._fetch_url('http://advisory.example/cve')
    assert connects == [(public_ip, 80), (public_ip, 80)]


def test_http_error_retries_next_user_agent(monkeypatch):
    ip = '8.8.8.8'
    statuses = [503, 200]

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo(ip, port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        status = statuses.pop(0)
        conn._responses = [_FakeResp(
            status=status,
            reason='Service Unavailable' if status == 503 else 'OK',
            headers={'Content-Type': 'text/html; charset=utf-8'},
            body=_html() if status == 200 else b'nope',
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    html = package_extractor._fetch_url('http://advisory.example/cve')
    assert 'word' in html
    assert statuses == []


def test_content_length_over_limit_is_rejected_without_reading(monkeypatch):
    monkeypatch.setattr(package_extractor, '_MAX_RESPONSE_BYTES', 100)

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo('8.8.8.8', port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_UndrainableResp(
            headers={'Content-Length': '101', 'Content-Type': 'text/html'},
            body=b'x' * 101,
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='exceeds 100 bytes'):
        package_extractor._fetch_url('http://advisory.example/cve')


def test_body_without_content_length_is_capped_while_reading(monkeypatch):
    monkeypatch.setattr(package_extractor, '_MAX_RESPONSE_BYTES', 100)
    monkeypatch.setattr(package_extractor, '_READ_CHUNK', 32)

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo('8.8.8.8', port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            headers={'Content-Type': 'text/html'},
            body=b'x' * 150,
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    with pytest.raises(ValueError, match='exceeds 100 bytes'):
        package_extractor._fetch_url('http://advisory.example/cve')


def test_body_at_limit_is_accepted(monkeypatch):
    body = _html(50)
    monkeypatch.setattr(package_extractor, '_MAX_RESPONSE_BYTES', len(body))

    def fake_gai(host, port, proto=0, **_kw):
        return _addrinfo('8.8.8.8', port)

    def http_conn(*args, **kwargs):
        conn = _FakeConn(*args, **kwargs)
        conn._responses = [_FakeResp(
            headers={'Content-Type': 'text/html; charset=utf-8',
                     'Content-Length': str(len(body))},
            body=body,
        )]
        return conn

    monkeypatch.setattr(socket, 'getaddrinfo', fake_gai)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: _FakeSock())
    monkeypatch.setattr(package_extractor.http.client, 'HTTPConnection', http_conn)

    html = package_extractor._fetch_url('http://advisory.example/cve')
    assert 'word' in html
