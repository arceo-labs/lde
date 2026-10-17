"""Unit tests for the isLatest flag plumbed through dtrack_client.upload_bom.

isLatest must only appear in the PUT body when explicitly True/False; when
None (e.g. ingest catchup, where the GitHub default isn't known) the flag
must be omitted so DT's existing value is left untouched.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import dtrack_client  # noqa: E402


@pytest.fixture
def bom(tmp_path):
    p = tmp_path / 'bom.json'
    p.write_text('{"bomFormat":"CycloneDX","components":[]}')
    return str(p)


def _capture_request(monkeypatch):
    captured = {}

    def fake_request(method, base_url, path, api_key, body=None, content_type='application/json'):
        captured['method'] = method
        captured['path'] = path
        captured['body'] = body
        return {'token': 't'}

    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    return captured


def test_upload_bom_sets_islatest_true(bom, monkeypatch):
    captured = _capture_request(monkeypatch)
    dtrack_client.upload_bom('http://dt', 'k', 'o/r', 'main', bom, is_latest=True)
    assert captured['body']['isLatest'] is True
    assert captured['body']['projectVersion'] == 'main'


def test_upload_bom_sets_islatest_false(bom, monkeypatch):
    captured = _capture_request(monkeypatch)
    dtrack_client.upload_bom('http://dt', 'k', 'o/r', 'develop', bom, is_latest=False)
    assert captured['body']['isLatest'] is False


def test_upload_bom_omits_islatest_when_none(bom, monkeypatch):
    captured = _capture_request(monkeypatch)
    dtrack_client.upload_bom('http://dt', 'k', 'o/r', 'develop', bom)
    assert 'isLatest' not in captured['body']
