"""S3: package-search row errors for REPLACE_ME and HTTP 401."""

import json
import os
import sys
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import dtrack_client  # noqa: E402

PLACEHOLDER_ERR = (
    'lde/dtrack-api-key is still the placeholder REPLACE_ME. '
    'Run scripts/bootstrap_dtrack.py (docs/aws-deployment.md Step 5). '
    'Package search does not use the Gemini key.'
)

HTTP_401_ERR = (
    'Dependency-Track rejected the API key (HTTP 401). '
    'Confirm the Automation team has PROJECT_CREATION_UPLOAD and VIEW_PORTFOLIO.'
)


def _call_package_search(packages, settings, search_side_effect=None):
    import server

    body_bytes = json.dumps({'packages': packages}).encode()
    handler = server.Handler.__new__(server.Handler)
    handler.headers = {'Content-Length': str(len(body_bytes))}
    handler.rfile = BytesIO(body_bytes)
    handler._read_body = lambda: json.loads(body_bytes.decode())
    captured = {}

    def fake_json_response(status, payload):
        captured['status'] = status
        captured['body'] = payload

    handler._json_response = fake_json_response

    with patch('server.settings_mod.load_settings', return_value=settings), \
         patch('server.dtrack_client.search_components_by_name',
               side_effect=search_side_effect or (lambda *a, **k: [])):
        server.Handler.handle_package_search(handler, groups=(), qs={})
    return captured


class PackageSearchErrorTests(unittest.TestCase):
    def test_replace_me_returns_bootstrap_hint_without_calling_dt(self):
        called = []

        def boom(*a, **k):
            called.append(True)
            raise AssertionError('should not call Dependency-Track')

        result = _call_package_search(
            ['lodash'],
            {
                'dtrack_url': 'http://dt:8081',
                'dtrack_api_key': 'REPLACE_ME',
                'dtrack_ui_url': 'http://dt:8080',
            },
            search_side_effect=boom,
        )
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['body']['results'][0]['error'], PLACEHOLDER_ERR)
        self.assertEqual(called, [])

    def test_dtrack_401_names_status_and_permissions(self):
        def raise_401(*a, **k):
            raise dtrack_client.DtrackError('GET /api/v1/search/component → HTTP 401: Unauthorized')

        result = _call_package_search(
            ['requests'],
            {
                'dtrack_url': 'http://dt:8081',
                'dtrack_api_key': 'real-key',
                'dtrack_ui_url': 'http://dt:8080',
            },
            search_side_effect=raise_401,
        )
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['body']['results'][0]['error'], HTTP_401_ERR)


if __name__ == '__main__':
    unittest.main()
