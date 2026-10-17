"""S2: placeholder-aware GitHub auth status and AWS settings 503 text."""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import gh_auth  # noqa: E402


REPLACE_ME_RAW = (
    'lde/github-pat is still the placeholder REPLACE_ME. '
    'Write the token with the command in docs/aws-deployment.md Step 4 (GitHub PAT). '
    'LDE reads Secrets Manager within a minute.'
)

AWS_SETTINGS_503 = (
    'Settings cannot be changed through the UI on this deployment. '
    'Write lde/github-pat, lde/dtrack-api-key, and lde/gemini-api-key in AWS Secrets Manager '
    '(docs/aws-deployment.md ## Step 4 — Populate secrets). '
    'LDE reads Secrets Manager within a minute.'
)


class GhAuthReplaceMeTests(unittest.TestCase):
    def test_replace_me_token_is_not_installed(self):
        with patch('backend.gh_auth.settings_mod.load_settings',
                   return_value={'github_pat': 'REPLACE_ME'}):
            status = gh_auth.auth_status()
        self.assertFalse(status['installed'])
        self.assertFalse(status['logged_in'])
        self.assertEqual(status['raw'], REPLACE_ME_RAW)

    def test_other_token_401_keeps_existing_sentence(self):
        err = HTTPError(
            'https://api.github.com/user', 401, 'Unauthorized',
            hdrs={}, fp=BytesIO(b''),
        )
        with patch('backend.gh_auth.settings_mod.load_settings',
                   return_value={'github_pat': 'github_pat_deadbeef'}), \
             patch('backend.gh_auth.urllib.request.urlopen', side_effect=err):
            status = gh_auth.auth_status()
        self.assertTrue(status['installed'])
        self.assertFalse(status['logged_in'])
        self.assertIn('HTTP 401', status['raw'])
        self.assertIn('has not expired', status['raw'])


class AwsSettings503Tests(unittest.TestCase):
    def test_put_settings_aws_503_names_secrets_and_step_4(self):
        # Import server lazily so ROUTES bind after path setup.
        import server

        body_bytes = json.dumps({'dtrack_url': 'http://example.com'}).encode()
        handler = MagicMock()
        handler.headers = {'Content-Length': str(len(body_bytes))}
        handler.rfile = BytesIO(body_bytes)
        handler._read_body = lambda: json.loads(body_bytes.decode())
        captured = {}

        def fake_json_response(status, payload):
            captured['status'] = status
            captured['body'] = payload

        handler._json_response = fake_json_response
        # Bind unbound method.
        with patch.dict(os.environ, {'LDE_SECRETS_SOURCE': 'aws'}, clear=False):
            server.Handler.handle_put_settings(handler, groups=(), qs={})

        self.assertEqual(captured['status'], 503)
        self.assertEqual(captured['body']['error'], AWS_SETTINGS_503)


if __name__ == '__main__':
    unittest.main()
