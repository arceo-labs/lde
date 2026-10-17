"""Unit tests for the POST /api/dtrack/package-search endpoint.

Validates the endpoint works correctly with both small and larger batches,
supporting the client-side pagination strategy that avoids ALB 504 timeouts
on large (~440-package) queries.
"""

import io
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from backend import dtrack_client  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler(body_dict):
    """Build a minimal Handler with a JSON body pre-loaded."""
    handler = server.Handler.__new__(server.Handler)

    body_bytes = json.dumps(body_dict).encode('utf-8')
    handler.rfile = io.BytesIO(body_bytes)
    handler.headers = {'Content-Length': str(len(body_bytes))}

    handler._sent_status = None
    handler._sent_headers = {}
    handler._wfile = io.BytesIO()

    def fake_send_response(code, message=None):
        handler._sent_status = code

    def fake_send_header(key, value):
        handler._sent_headers[key] = value

    def fake_end_headers():
        pass

    def fake_wfile_write(data):
        handler._wfile.write(data)

    handler.send_response = fake_send_response
    handler.send_header = fake_send_header
    handler.end_headers = fake_end_headers
    handler.wfile = MagicMock()
    handler.wfile.write = fake_wfile_write

    return handler


def _response_body(handler):
    """Extract the JSON response body from the handler's write buffer."""
    raw = handler._wfile.getvalue()
    return json.loads(raw) if raw else None


def _fake_search_by_name(base_url, api_key, name):
    """Deterministic fake: returns one match per package name."""
    return [{
        'project': f'org/{name}-project',
        'project_uuid': f'proj-uuid-{name}',
        'project_version': 'main',
        'component': name,
        'component_uuid': f'comp-uuid-{name}',
        'component_version': '1.0.0',
        'purl': f'pkg:npm/{name}@1.0.0',
    }]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPackageSearchBatching:
    """Validates that the endpoint handles both small and batch-sized requests."""

    SETTINGS = {
        'dtrack_url': 'http://dtrack:8081',
        'dtrack_api_key': 'test-key',
        'dtrack_ui_url': 'http://dtrack:8080',
    }

    def _run_search(self, packages):
        handler = _make_handler({'packages': packages})
        with patch('backend.settings.load_settings', return_value=self.SETTINGS), \
             patch.object(dtrack_client, 'search_components_by_name',
                          side_effect=_fake_search_by_name):
            handler.handle_package_search((), {})
        return handler

    def test_small_batch_returns_all_results(self):
        """A batch of 5 packages returns 5 result objects."""
        packages = [f'pkg-{i}' for i in range(5)]
        handler = self._run_search(packages)

        assert handler._sent_status == 200
        body = _response_body(handler)
        assert len(body['results']) == 5
        assert body['results'][0]['query'] == 'pkg-0'
        assert body['results'][0]['matches'][0]['component'] == 'pkg-0'

    def test_batch_of_50_completes_within_reason(self):
        """50 packages — the new client-side batch size — works fine."""
        packages = [f'pkg-{i}' for i in range(50)]
        handler = self._run_search(packages)

        assert handler._sent_status == 200
        body = _response_body(handler)
        assert len(body['results']) == 50

    def test_results_ordered_same_as_input(self):
        """Result order matches the input package list."""
        packages = ['zulu', 'alpha', 'mike']
        handler = self._run_search(packages)

        body = _response_body(handler)
        queries = [r['query'] for r in body['results']]
        assert queries == ['zulu', 'alpha', 'mike']

    def test_per_package_error_does_not_abort_batch(self):
        """If one package search fails, others still return results."""
        call_count = [0]

        def _flaky_search(base_url, api_key, name):
            call_count[0] += 1
            if name == 'bad-pkg':
                raise dtrack_client.DtrackError('connection refused')
            return _fake_search_by_name(base_url, api_key, name)

        packages = ['good-a', 'bad-pkg', 'good-b']
        handler = _make_handler({'packages': packages})
        with patch('backend.settings.load_settings', return_value=self.SETTINGS), \
             patch.object(dtrack_client, 'search_components_by_name',
                          side_effect=_flaky_search):
            handler.handle_package_search((), {})

        assert handler._sent_status == 200
        body = _response_body(handler)
        assert len(body['results']) == 3
        assert body['results'][0]['matches'][0]['component'] == 'good-a'
        # Generic (non-401/403) DtrackError -> the generic search-error message.
        assert body['results'][1]['error'] == 'Dependency-Track search error'
        assert body['results'][2]['matches'][0]['component'] == 'good-b'

    def test_rejects_over_max_packages(self):
        """Server still enforces the 500-package ceiling."""
        packages = [f'pkg-{i}' for i in range(501)]
        handler = _make_handler({'packages': packages})
        with patch('backend.settings.load_settings', return_value=self.SETTINGS):
            try:
                handler.handle_package_search((), {})
            except ValueError as exc:
                assert 'Too many packages' in str(exc)
            else:
                pytest.fail('Should have raised ValueError for >500 packages')

    def test_empty_list_rejected(self):
        """An empty package list is rejected with a clear error."""
        handler = _make_handler({'packages': []})
        with patch('backend.settings.load_settings', return_value=self.SETTINGS):
            try:
                handler.handle_package_search((), {})
            except ValueError as exc:
                assert 'No package names' in str(exc)
            else:
                pytest.fail('Should have raised ValueError for empty list')

    def test_whitespace_only_entries_stripped(self):
        """Whitespace-only entries are dropped, not sent to DT."""
        packages = ['lodash', '  ', '', 'express']
        handler = self._run_search(packages)

        body = _response_body(handler)
        queries = [r['query'] for r in body['results']]
        assert queries == ['lodash', 'express']
