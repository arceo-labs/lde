"""S5: Gemini Flash defaults — 65_536 tokens, thinkingLevel low."""

import json
import os
import sys
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import URLError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import package_extractor  # noqa: E402


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_call_gemini_default_model_and_generation_config(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        captured['timeout'] = timeout
        captured['payload'] = json.loads(req.data.decode())
        body = json.dumps({
            'candidates': [{
                'finishReason': 'STOP',
                'content': {'parts': [{'text': '[]'}]},
            }],
        }).encode()
        return _FakeResp(body)

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    result = package_extractor._call_gemini('article text', 'fake-key')
    assert result == []
    assert captured['url'].endswith('/models/gemini-3.8-flash:generateContent')
    assert captured['timeout'] == 300
    cfg = captured['payload']['generationConfig']
    assert cfg['maxOutputTokens'] == 65536
    assert cfg['thinkingConfig'] == {'thinkingLevel': 'low'}
    assert cfg['responseMimeType'] == 'application/json'
