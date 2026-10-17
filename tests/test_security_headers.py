"""HSTS is sent only on the HTTPS path (behind the ALB), never on plain local HTTP."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402


def _headers(request_headers):
    sent = {}
    handler = server.Handler.__new__(server.Handler)
    handler.headers = request_headers
    handler.send_header = lambda k, v: sent.__setitem__(k, v)
    handler._security_headers()
    return sent


@pytest.mark.parametrize('proto', ['https', 'HTTPS'])
def test_hsts_behind_tls(proto):
    assert _headers({'X-Forwarded-Proto': proto})['Strict-Transport-Security'] == \
        'max-age=63072000; includeSubDomains'


@pytest.mark.parametrize('headers', [{}, {'X-Forwarded-Proto': 'http'}, {'X-Forwarded-Proto': ''}])
def test_no_hsts_on_plain_http(headers):
    assert 'Strict-Transport-Security' not in _headers(headers)


def test_baseline_headers_unchanged():
    sent = _headers({})
    assert sent['X-Content-Type-Options'] == 'nosniff'
    assert sent['X-Frame-Options'] == 'DENY'
    assert "style-src 'self'" in sent['Content-Security-Policy']
