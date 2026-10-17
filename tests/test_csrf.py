"""POST/PUT must be JSON from an allowed origin (or no Origin), so a cross-site
page can't drive the API with a "simple" request that skips the CORS preflight."""

import io
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402


@pytest.fixture
def routes(monkeypatch):
    """Swap in test routes whose handlers only record that they ran."""
    calls = []
    monkeypatch.setattr(server, 'ROUTES', [
        ('POST', r'^/api/thing$', 'handle_test_thing'),
        ('PUT', r'^/api/thing$', 'handle_test_thing'),
        ('GET', r'^/api/thing$', 'handle_test_thing'),
    ])

    def handle_test_thing(self, groups, qs):
        calls.append(self.command)
        self._json_response(200, {'ok': True})

    monkeypatch.setattr(server.Handler, 'handle_test_thing', handle_test_thing, raising=False)
    return calls


def _send(method, headers):
    handler = server.Handler.__new__(server.Handler)
    handler.command = method
    handler.path = '/api/thing'
    handler.headers = headers
    handler.status = None
    buf = io.BytesIO()
    handler.wfile = MagicMock()
    handler.wfile.write = buf.write
    handler._require_auth = lambda: True
    handler.send_response = lambda code, message=None: setattr(handler, 'status', code)
    handler.send_header = lambda key, value: None
    handler.end_headers = lambda: None
    assert handler._route(method) is True
    body = buf.getvalue()
    return handler.status, json.loads(body) if body else None


JSON = {'Content-Type': 'application/json'}


@pytest.mark.parametrize('method', ['POST', 'PUT'])
@pytest.mark.parametrize('content_type', [
    None,                                   # fetch(..., {mode: 'no-cors', body}) with no type set
    'text/plain',                           # the classic CSRF "simple" request
    'text/plain;charset=UTF-8',
    'application/x-www-form-urlencoded',    # an HTML <form> post
    'multipart/form-data; boundary=x',
    'application/jsonp',
])
def test_non_json_is_415_and_handler_does_not_run(routes, method, content_type):
    headers = {} if content_type is None else {'Content-Type': content_type}
    status, body = _send(method, headers)
    assert status == 415
    assert body == {'error': 'Content-Type must be application/json'}
    assert routes == []


@pytest.mark.parametrize('origin', ['https://evil.example', 'http://localhost.evil.example',
                                    'null', 'http://127.0.0.1.nip.io'])
def test_json_from_foreign_origin_is_403(routes, origin):
    status, body = _send('POST', {**JSON, 'Origin': origin})
    assert status == 403
    assert body == {'error': 'Origin not allowed'}
    assert routes == []


@pytest.mark.parametrize('headers', [
    JSON,                                                     # curl / scripts: no Origin
    {**JSON, 'Origin': 'http://localhost:8002'},
    {**JSON, 'Origin': 'http://127.0.0.1:8002'},
    {'Content-Type': 'application/json; charset=utf-8'},
    {'Content-Type': 'Application/JSON'},
])
def test_json_from_allowed_or_no_origin_is_dispatched(routes, headers):
    assert _send('POST', headers)[0] == 200
    assert routes == ['POST']


def test_configured_production_origin_is_allowed(routes, monkeypatch):
    monkeypatch.setattr(server, '_ALLOWED_ORIGIN', 'https://lde.example.com')
    assert _send('PUT', {**JSON, 'Origin': 'https://lde.example.com'})[0] == 200
    assert _send('PUT', {**JSON, 'Origin': 'https://lde.example.com.evil.example'})[0] == 403
    assert routes == ['PUT']


def test_get_is_unaffected(routes):
    assert _send('GET', {'Origin': 'https://evil.example'})[0] == 200
    assert routes == ['GET']


def test_cors_headers_use_the_same_allowlist(monkeypatch):
    sent = {}
    handler = server.Handler.__new__(server.Handler)
    handler.send_header = lambda k, v: sent.__setitem__(k, v)
    handler.headers = {'Origin': 'https://evil.example'}
    handler._cors_headers()
    assert 'Access-Control-Allow-Origin' not in sent
    handler.headers = {'Origin': 'http://localhost:8002'}
    handler._cors_headers()
    assert sent['Access-Control-Allow-Origin'] == 'http://localhost:8002'
