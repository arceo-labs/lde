"""Unit tests for dtrack_client.connection_status (the Settings 'Test DT API
key' button). Network is always mocked via _request. The API key must never
appear in the returned dict and raw DT error bodies must not be echoed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import dtrack_client  # noqa: E402


def test_connection_status_no_url():
    r = dtrack_client.connection_status('', 'key')
    assert r['configured'] is False and r['ok'] is False
    assert 'URL' in r['message']


def test_connection_status_no_key():
    r = dtrack_client.connection_status('http://dt:8081', '')
    assert r['configured'] is False and r['ok'] is False
    assert 'key' in r['message'].lower()


def test_connection_status_valid_all_perms(monkeypatch):
    def fake_request(method, base_url, path, api_key, body=None,
                     content_type='application/json', timeout=30):
        assert path == '/api/v1/team/self'
        return {'name': 'Automation', 'uuid': 'abc',
                'permissions': [{'name': 'BOM_UPLOAD'},
                                {'name': 'PROJECT_CREATION_UPLOAD'}]}
    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    r = dtrack_client.connection_status('http://dt:8081', 'secret-key')
    assert r['ok'] is True
    assert r['team'] == 'Automation'
    assert r['missing_permissions'] == []
    assert 'secret-key' not in str(r)  # never leak the key


def test_connection_status_valid_missing_perms(monkeypatch):
    def fake_request(method, base_url, path, api_key, body=None,
                     content_type='application/json', timeout=30):
        return {'name': 'ReadOnly', 'permissions': [{'name': 'VIEW_PORTFOLIO'}]}
    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    r = dtrack_client.connection_status('http://dt:8081', 'k')
    assert r['ok'] is True
    assert 'BOM_UPLOAD' in r['missing_permissions']
    assert 'PROJECT_CREATION_UPLOAD' in r['missing_permissions']
    assert 'Missing recommended permission' in r['message']


def test_connection_status_invalid_key(monkeypatch):
    def fake_request(*a, **k):
        raise dtrack_client.DtrackError('GET /api/v1/team/self → HTTP 401: Unauthorized')
    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    r = dtrack_client.connection_status('http://dt:8081', 'bad')
    assert r['configured'] is True and r['ok'] is False
    assert 'rejected' in r['message'].lower()
    assert 'Unauthorized' not in r['message']  # raw DT body not echoed


def test_connection_status_network_error(monkeypatch):
    def fake_request(*a, **k):
        raise dtrack_client.DtrackError('GET /api/v1/team/self → Connection refused')
    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    r = dtrack_client.connection_status('http://dt:8081', 'k')
    assert r['ok'] is False
    assert 'Could not reach' in r['message']
    assert 'Connection refused' not in r['message']
