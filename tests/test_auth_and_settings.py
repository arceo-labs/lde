"""Unit tests for auth fail-closed behaviour and AWS settings-write guard.

Tests are deliberately self-contained: they patch the minimal surface of
server.py that touches Secrets Manager / settings so no real AWS calls
are made and no server process needs to be running.
"""

import base64
import hashlib
import importlib
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Helpers to build a minimal fake Handler instance without HTTPServer
# ---------------------------------------------------------------------------

def _make_handler(env=None, auth_header=None, body=None):
    """Return a server.Handler instance with faked transport internals.

    *env*        – dict of env vars to inject (merged over os.environ)
    *auth_header*– value of the Authorization header, or None
    *body*       – bytes body for PUT requests
    """
    import server  # noqa: PLC0415 (local import after sys.path setup)

    handler = server.Handler.__new__(server.Handler)

    # Fake headers
    headers = {}
    if auth_header is not None:
        headers['Authorization'] = auth_header
    handler.headers = headers

    # Fake wfile / send_response machinery so we can capture responses
    handler._sent_status = None
    handler._sent_headers = {}
    handler._response_body = b''
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

    # Fake rfile for PUT body
    handler.rfile = io.BytesIO(body or b'')

    # Content-Length header (used by _read_body)
    if body is not None:
        handler.headers['Content-Length'] = str(len(body))

    return handler, env or {}


def _valid_auth_header(username='admin', password='hunter2'):
    """Build a valid Basic Auth header value."""
    token = base64.b64encode(f'{username}:{password}'.encode()).decode()
    return f'Basic {token}'


def _pw_hash(password='hunter2'):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Tests: _require_auth / _load_basic_auth_creds
# ---------------------------------------------------------------------------

class TestRequireAuthFailClosed(unittest.TestCase):

    def _call_require_auth(self, env, creds_return):
        """Call _require_auth() with a given env and creds mock."""
        import server

        handler, _ = _make_handler(env=env)

        with patch.dict(os.environ, env, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds_return):
            result = handler._require_auth()

        return result, handler._sent_status

    # -- Local dev: no creds → allow ------------------------------------------

    def test_local_no_creds_allows(self):
        """Without LDE_SECRETS_SOURCE, empty creds dict bypasses auth (local dev)."""
        allowed, status = self._call_require_auth(
            env={},
            creds_return={},
        )
        self.assertTrue(allowed)
        self.assertIsNone(status)  # no 401 sent

    # -- AWS mode: empty creds → deny -----------------------------------------

    def test_aws_empty_creds_denies(self):
        """In AWS mode, empty creds dict (secrets unavailable) must fail closed."""
        allowed, status = self._call_require_auth(
            env={'LDE_SECRETS_SOURCE': 'aws'},
            creds_return={},
        )
        self.assertFalse(allowed)
        self.assertEqual(status, 401)

    def test_aws_case_insensitive(self):
        """LDE_SECRETS_SOURCE=AWS (uppercase) also fails closed."""
        allowed, status = self._call_require_auth(
            env={'LDE_SECRETS_SOURCE': 'AWS'},
            creds_return={},
        )
        self.assertFalse(allowed)
        self.assertEqual(status, 401)

    # -- AWS mode: valid creds present → normal auth path ---------------------

    def test_aws_valid_creds_correct_password_allows(self):
        """Correct Basic Auth credentials pass in AWS mode."""
        import server

        password = 'hunter2'
        creds = {'admin': _pw_hash(password)}
        handler, _ = _make_handler(auth_header=_valid_auth_header('admin', password))

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds):
            result = handler._require_auth()

        self.assertTrue(result)
        self.assertIsNone(handler._sent_status)

    def test_aws_valid_creds_wrong_password_denies(self):
        """Wrong password fails with 401 in AWS mode."""
        import server

        creds = {'admin': _pw_hash('correct_password')}
        handler, _ = _make_handler(auth_header=_valid_auth_header('admin', 'wrong_password'))

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds):
            result = handler._require_auth()

        self.assertFalse(result)
        self.assertEqual(handler._sent_status, 401)

    # -- Malformed stored hash: deny, never raise ------------------------------

    def test_non_ascii_stored_hash_denies_without_raising(self):
        """A non-ASCII value in basic_auth_credentials gives 401, not a TypeError
        out of hmac.compare_digest (which rejects non-ASCII str)."""
        import server

        creds = {'admin': 'é' * 64}
        handler, _ = _make_handler(auth_header=_valid_auth_header('admin', 'anything'))

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds):
            result = handler._require_auth()

        self.assertFalse(result)
        self.assertEqual(handler._sent_status, 401)

    def test_comparison_is_constant_time(self):
        """The password hash is compared with hmac.compare_digest."""
        import server

        password = 'hunter2'
        creds = {'admin': _pw_hash(password)}
        handler, _ = _make_handler(auth_header=_valid_auth_header('admin', password))

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds), \
             patch('server.hmac.compare_digest', wraps=server.hmac.compare_digest) as cmp:
            self.assertTrue(handler._require_auth())

        cmp.assert_called_once()

    # -- Non-AWS mode: valid creds still work ---------------------------------

    def test_local_valid_creds_allow(self):
        """When creds are configured locally, correct auth is still enforced."""
        import server

        password = 'localpass'
        creds = {'admin': _pw_hash(password)}
        handler, _ = _make_handler(auth_header=_valid_auth_header('admin', password))

        with patch.dict(os.environ, {}, clear=False), \
             patch('server._get_basic_auth_creds', return_value=creds):
            result = handler._require_auth()

        self.assertTrue(result)


# ---------------------------------------------------------------------------
# Tests: _load_basic_auth_creds malformed-JSON log level
# ---------------------------------------------------------------------------

class TestLoadBasicAuthCredsLogging(unittest.TestCase):

    def test_malformed_json_logs_error_in_aws_mode(self):
        """Malformed basic_auth_credentials must log at ERROR level in AWS mode."""
        import server

        fake_settings = {'basic_auth_credentials': 'not-valid-json{{{'}

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server.settings_mod.load_settings', return_value=fake_settings), \
             patch('server.logger') as mock_logger:
            result = server._load_basic_auth_creds()

        self.assertEqual(result, {})
        mock_logger.error.assert_called_once()
        mock_logger.warning.assert_not_called()

    def test_malformed_json_logs_warning_in_local_mode(self):
        """Malformed basic_auth_credentials logs at WARNING level locally."""
        import server

        fake_settings = {'basic_auth_credentials': 'not-valid-json{{{'}

        # Ensure LDE_SECRETS_SOURCE is absent
        env_without_aws = {k: v for k, v in os.environ.items()
                          if k != 'LDE_SECRETS_SOURCE'}
        with patch.dict(os.environ, env_without_aws, clear=True), \
             patch('server.settings_mod.load_settings', return_value=fake_settings), \
             patch('server.logger') as mock_logger:
            result = server._load_basic_auth_creds()

        self.assertEqual(result, {})
        mock_logger.warning.assert_called_once()
        mock_logger.error.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: handle_put_settings AWS guard
# ---------------------------------------------------------------------------

class TestPutSettingsAwsGuard(unittest.TestCase):

    def _call_put_settings(self, env, body_dict=None):
        """Invoke handle_put_settings and return the captured JSON response."""
        import server

        body_bytes = json.dumps(body_dict or {}).encode()
        handler, _ = _make_handler(body=body_bytes)

        captured = {}

        def fake_json_response(status, payload):
            captured['status'] = status
            captured['body'] = payload

        handler._json_response = fake_json_response

        with patch.dict(os.environ, env, clear=False):
            handler.handle_put_settings(groups=(), qs={})

        return captured

    def test_aws_mode_returns_503(self):
        """PUT /api/settings must return 503 when LDE_SECRETS_SOURCE=aws."""
        result = self._call_put_settings(
            env={'LDE_SECRETS_SOURCE': 'aws'},
            body_dict={'dtrack_url': 'http://example.com'},
        )
        self.assertEqual(result['status'], 503)
        self.assertIn('error', result['body'])
        self.assertIn('Secrets Manager', result['body']['error'])
        self.assertIn('lde/github-pat', result['body']['error'])
        self.assertIn('lde/dtrack-api-key', result['body']['error'])
        self.assertIn('lde/gemini-api-key', result['body']['error'])
        self.assertIn('Step 4', result['body']['error'])

    def test_aws_mode_does_not_call_save_settings(self):
        """save_settings must NOT be called when in AWS mode."""
        import server

        body_bytes = json.dumps({'dtrack_url': 'http://example.com'}).encode()
        handler, _ = _make_handler(body=body_bytes)
        handler._json_response = MagicMock()

        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False), \
             patch('server.settings_mod.save_settings') as mock_save:
            handler.handle_put_settings(groups=(), qs={})

        mock_save.assert_not_called()

    def test_local_mode_calls_save_settings(self):
        """PUT /api/settings proceeds normally when not in AWS mode."""
        import server

        patch_data = {'dtrack_url': 'http://localhost:8081'}
        body_bytes = json.dumps(patch_data).encode()
        handler, _ = _make_handler(body=body_bytes)
        handler._json_response = MagicMock()

        fake_updated = {'dtrack_url': 'http://localhost:8081'}
        fake_masked = {'dtrack_url': 'http://localhost:8081'}

        env_without_aws = {k: v for k, v in os.environ.items()
                          if k != 'LDE_SECRETS_SOURCE'}
        with patch.dict(os.environ, env_without_aws, clear=True), \
             patch('server.settings_mod.save_settings', return_value=fake_updated), \
             patch('server.settings_mod.masked', return_value=fake_masked), \
             patch('server.settings_mod.ALLOWED_KEYS', {'dtrack_url'}):
            handler.handle_put_settings(groups=(), qs={})

        handler._json_response.assert_called_once_with(200, fake_masked)


if __name__ == '__main__':
    unittest.main()
