"""Unit tests for package_extractor.connection_status (the Settings 'Test
Gemini key' button). Network is always mocked via urllib.request.urlopen.
The API key must never appear in the returned dict and raw Google error
bodies must not be echoed verbatim.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import package_extractor  # noqa: E402


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_connection_status_no_key():
    r = package_extractor.connection_status('', 'gemini-3.8-flash')
    assert r['configured'] is False and r['ok'] is False
    assert 'key' in r['message'].lower()


def test_connection_status_valid(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        captured['headers'] = req.headers
        captured['timeout'] = timeout
        body = json.dumps({
            'name': 'models/gemini-3.8-flash',
            'supportedGenerationMethods': ['generateContent', 'countTokens'],
        }).encode()
        return _FakeResp(body)

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('secret-key', 'gemini-3.8-flash')
    assert r['configured'] is True and r['ok'] is True
    assert r['model'] == 'models/gemini-3.8-flash'
    assert r['supports_generate'] is True
    assert captured['url'].endswith('/v1beta/models/gemini-3.8-flash')
    # GET only — no request body, no generation call, no billable tokens.
    assert 'secret-key' not in str(r)  # never leak the key


def test_connection_status_model_without_generate_content(monkeypatch):
    def fake_urlopen(req, timeout=None):
        body = json.dumps({
            'name': 'models/embedding-001',
            'supportedGenerationMethods': ['embedContent'],
        }).encode()
        return _FakeResp(body)

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('k', 'embedding-001')
    assert r['ok'] is True
    assert r['supports_generate'] is False
    assert 'does not support generateContent' in r['message']


def test_connection_status_invalid_key(monkeypatch):
    def fake_urlopen(req, timeout=None):
        body = json.dumps({'error': {'code': 400, 'status': 'INVALID_ARGUMENT',
                                      'message': 'API key not valid.'}}).encode()
        raise HTTPError(req.full_url, 400, 'Bad Request', {}, _FakeResp(body))

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('bad-key', 'gemini-3.8-flash')
    assert r['configured'] is True and r['ok'] is False
    assert 'rejected' in r['message'].lower()
    assert 'bad-key' not in r['message']
    assert 'API key not valid' not in r['message']  # raw Google body not echoed


def test_connection_status_unknown_model(monkeypatch):
    def fake_urlopen(req, timeout=None):
        body = json.dumps({'error': {'code': 404, 'status': 'NOT_FOUND',
                                      'message': 'Model is not found'}}).encode()
        raise HTTPError(req.full_url, 404, 'Not Found', {}, _FakeResp(body))

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('k', 'gemini-does-not-exist')
    assert r['ok'] is False
    assert 'not found' in r['message'].lower()
    assert 'gemini-does-not-exist' in r['message']


def test_connection_status_quota_exhausted(monkeypatch):
    def fake_urlopen(req, timeout=None):
        body = json.dumps({'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED'}}).encode()
        raise HTTPError(req.full_url, 429, 'Too Many Requests', {}, _FakeResp(body))

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('k', 'gemini-3.8-flash')
    assert r['ok'] is False
    assert 'rate-limited' in r['message'].lower() or 'quota' in r['message'].lower()


def test_connection_status_network_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise URLError('Connection refused')

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    r = package_extractor.connection_status('k', 'gemini-3.8-flash')
    assert r['ok'] is False
    assert 'Could not reach' in r['message']
    assert 'Connection refused' not in r['message']


# ---------------------------------------------------------------------------
# Route-level: GET /api/gemini-status reads only server-saved settings.
# ---------------------------------------------------------------------------

def test_handle_gemini_status_uses_saved_settings_only(monkeypatch):
    import server

    handler = server.Handler.__new__(server.Handler)
    captured = {}

    def fake_json_response(status, payload):
        captured['status'] = status
        captured['body'] = payload

    handler._json_response = fake_json_response

    monkeypatch.setattr(
        server.settings_mod, 'load_settings',
        lambda: {'gemini_api_key': 'server-saved-key', 'gemini_model': 'gemini-3.8-flash'})

    seen = {}

    def fake_connection_status(api_key, model, timeout=10):
        seen['api_key'] = api_key
        seen['model'] = model
        return {'configured': True, 'ok': True, 'model': 'models/gemini-3.8-flash',
                'supports_generate': True, 'message': 'Key valid; model reachable.'}

    monkeypatch.setattr(package_extractor, 'connection_status', fake_connection_status)

    handler.handle_gemini_status(groups=(), qs={})

    assert seen['api_key'] == 'server-saved-key'
    assert seen['model'] == 'gemini-3.8-flash'
    assert captured['status'] == 200
    assert captured['body']['ok'] is True
    assert 'server-saved-key' not in json.dumps(captured['body'])
