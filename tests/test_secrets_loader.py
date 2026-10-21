"""Unit tests for the Secrets Manager overlay cache in backend/secrets_loader.py."""

import io
import os
import sys
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import secrets_loader  # noqa: E402


def _http_error(code):
    return urllib.error.HTTPError('https://example.invalid/', code, 'err', {}, io.BytesIO(b''))


class OverlayCacheTests(unittest.TestCase):
    def setUp(self):
        secrets_loader._cache.clear()
        self.calls = []
        self.values = {name: f'value-of-{name}' for name in secrets_loader._SECRET_MAP}
        self.values['lde/github-pat'] = '{"acme": "tok"}'
        self.now = 1000.0
        patches = [
            patch.object(secrets_loader, '_ENABLED', True),
            patch.object(secrets_loader, '_sign_and_fetch', side_effect=self._fetch),
            patch.object(secrets_loader.time, 'monotonic', side_effect=lambda: self.now),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(secrets_loader._cache.clear)

    def _fetch(self, name):
        self.calls.append(name)
        value = self.values[name]
        if isinstance(value, Exception):
            raise value
        return value

    def test_second_call_within_ttl_does_not_fetch(self):
        first = secrets_loader.overlay({})
        second = secrets_loader.overlay({})
        self.assertEqual(len(self.calls), len(secrets_loader._SECRET_MAP))
        self.assertEqual(first, second)
        self.assertEqual(first['github_pats'], {'acme': 'tok'})

    def test_fetches_again_after_ttl(self):
        secrets_loader.overlay({})
        self.values['lde/github-pat'] = '{"acme": "rotated"}'
        self.now += secrets_loader._CACHE_TTL + 1
        out = secrets_loader.overlay({})
        self.assertEqual(len(self.calls), 2 * len(secrets_loader._SECRET_MAP))
        self.assertEqual(out['github_pats'], {'acme': 'rotated'})

    def test_missing_secret_is_cached_and_left_unset(self):
        self.values['lde/gemini-api-key'] = _http_error(404)
        out = secrets_loader.overlay({'gemini_api_key': 'from-file'})
        secrets_loader.overlay({})
        self.assertEqual(self.calls.count('lde/gemini-api-key'), 1)
        self.assertEqual(out['gemini_api_key'], 'from-file')

    def test_failed_fetch_is_not_cached(self):
        self.values['lde/basic-auth'] = urllib.error.URLError('timed out')
        out = secrets_loader.overlay({})
        self.assertNotIn('basic_auth_credentials', out)
        self.values['lde/basic-auth'] = '{"admin": "hash"}'
        out = secrets_loader.overlay({})
        self.assertEqual(self.calls.count('lde/basic-auth'), 2)
        self.assertEqual(out['basic_auth_credentials'], '{"admin": "hash"}')

    def test_http_error_other_than_404_is_not_cached(self):
        self.values['lde/dtrack-api-key'] = _http_error(500)
        secrets_loader.overlay({})
        secrets_loader.overlay({})
        self.assertEqual(self.calls.count('lde/dtrack-api-key'), 2)

    def test_disabled_does_not_fetch(self):
        with patch.object(secrets_loader, '_ENABLED', False):
            self.assertEqual(secrets_loader.overlay({'a': 1}), {'a': 1})
        self.assertEqual(self.calls, [])


class PerSecretLockingTests(unittest.TestCase):
    """A slow/stuck fetch of one secret must not block fetches of another:
    the fix for the single global _cache_lock serializing every request
    behind one secret's outage."""

    def setUp(self):
        secrets_loader._cache.clear()
        self.addCleanup(secrets_loader._cache.clear)
        patch.object(secrets_loader, '_ENABLED', True).start()
        self.addCleanup(patch.stopall)

    def test_slow_fetch_of_one_secret_does_not_block_another(self):
        slow_secret = 'lde/github-pat'
        other_secret = 'lde/gemini-api-key'
        slow_started = threading.Event()
        release_slow = threading.Event()
        other_done = threading.Event()

        def fake_fetch(name):
            if name == slow_secret:
                slow_started.set()
                assert release_slow.wait(timeout=5), 'test deadlock: slow fetch never released'
            return f'value-of-{name}'

        with patch.object(secrets_loader, '_sign_and_fetch', side_effect=fake_fetch):
            t = threading.Thread(
                target=lambda: secrets_loader._cached_fetch(slow_secret))
            t.start()
            self.assertTrue(slow_started.wait(timeout=5), 'slow fetch never started')

            # While the slow fetch is still in flight, a different secret
            # must resolve immediately rather than queuing behind it.
            start = time.monotonic()
            value = secrets_loader._cached_fetch(other_secret)
            elapsed = time.monotonic() - start
            other_done.set()

            self.assertEqual(value, f'value-of-{other_secret}')
            self.assertLess(elapsed, 1.0, 'fetching an unrelated secret waited on the slow one')

            release_slow.set()
            t.join(timeout=5)
            self.assertFalse(t.is_alive())

    def test_concurrent_fetches_of_the_same_secret_are_single_flight(self):
        secret = 'lde/dtrack-api-key'
        calls = []
        started = threading.Event()
        release = threading.Event()

        def fake_fetch(name):
            calls.append(name)
            started.set()
            assert release.wait(timeout=5), 'test deadlock: fetch never released'
            return 'the-value'

        results = []
        with patch.object(secrets_loader, '_sign_and_fetch', side_effect=fake_fetch):
            def worker():
                results.append(secrets_loader._cached_fetch(secret))

            t1 = threading.Thread(target=worker)
            t1.start()
            self.assertTrue(started.wait(timeout=5), 'first fetch never started')

            t2 = threading.Thread(target=worker)
            t2.start()
            # t2 should block on the per-secret lock rather than starting a
            # second, duplicate fetch while t1's is still in flight.
            time.sleep(0.1)
            self.assertEqual(len(calls), 1, 't2 started a duplicate fetch instead of waiting')

            release.set()
            t1.join(timeout=5)
            t2.join(timeout=5)
            self.assertFalse(t1.is_alive() or t2.is_alive())

        self.assertEqual(results, ['the-value', 'the-value'])
        # t2 picked up the now-cached value; only one network call happened.
        self.assertEqual(calls, [secret])


if __name__ == '__main__':
    unittest.main()
