"""Coverage for backend/bom_cache.py — manifest fingerprinting + BOM reuse."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import bom_cache  # noqa: E402


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)


def test_hash_stable_across_oswalk_order(tmp_path):
    """Hash is determined by sorted (path, content) — not filesystem ordering."""
    a = tmp_path / 'repo-a'
    b = tmp_path / 'repo-b'
    # Identical content/layout but written in different orders.
    _write(str(a / 'package.json'), '{"name":"x","version":"1.0.0"}')
    _write(str(a / 'sub/package.json'), '{"name":"y"}')
    _write(str(b / 'sub/package.json'), '{"name":"y"}')
    _write(str(b / 'package.json'), '{"name":"x","version":"1.0.0"}')
    assert bom_cache.manifest_hash(str(a)) == bom_cache.manifest_hash(str(b))


def test_hash_changes_on_content_change(tmp_path):
    a = tmp_path / 'a'
    _write(str(a / 'package.json'), '{"name":"x","version":"1.0.0"}')
    h1 = bom_cache.manifest_hash(str(a))
    _write(str(a / 'package.json'), '{"name":"x","version":"1.0.1"}')
    h2 = bom_cache.manifest_hash(str(a))
    assert h1 != h2


def test_hash_changes_on_path_change(tmp_path):
    a = tmp_path / 'a'
    _write(str(a / 'package.json'), '{"name":"x"}')
    h_root = bom_cache.manifest_hash(str(a))
    # Same file content but at a different path.
    os.unlink(str(a / 'package.json'))
    _write(str(a / 'sub/package.json'), '{"name":"x"}')
    h_sub = bom_cache.manifest_hash(str(a))
    assert h_root != h_sub


def test_hash_skips_node_modules_and_ort_output(tmp_path):
    a = tmp_path / 'a'
    _write(str(a / 'package.json'), '{"name":"x"}')
    # These dirs MUST be excluded — they're either tooling output or
    # node_modules vendored content.
    _write(str(a / 'node_modules/lodash/package.json'), '{"name":"lodash"}')
    _write(str(a / 'ort-output/bom.cyclonedx.json'), '{}')
    h1 = bom_cache.manifest_hash(str(a))

    # Adding more "vendored" entries should not change the hash.
    _write(str(a / 'node_modules/react/package.json'), '{"name":"react"}')
    h2 = bom_cache.manifest_hash(str(a))
    assert h1 == h2


def test_lookup_miss_returns_none(tmp_path):
    assert bom_cache.lookup(str(tmp_path), 'a' * 64) is None


def test_store_and_lookup_roundtrip(tmp_path):
    cache_root = tmp_path / 'cache'
    cache_root.mkdir()

    bom_src = tmp_path / 'fresh-bom.json'
    # Non-empty components — the cache refuses to store zero-component
    # BOMs because they signal a resolution failure (see test below).
    bom_src.write_text('{"bomFormat":"CycloneDX","components":[{"name":"lodash","version":"4.17.21"}]}')

    sha = 'b' * 64
    stored = bom_cache.store(str(cache_root), sha, str(bom_src))
    assert stored is not None
    assert os.path.isfile(stored)

    looked_up = bom_cache.lookup(str(cache_root), sha)
    assert looked_up == stored
    with open(looked_up) as f:
        assert 'CycloneDX' in f.read()


def test_hash_returns_none_when_no_manifests(tmp_path):
    # A repo with only README/LICENSE (the mocker output) has no manifests.
    a = tmp_path / 'a'
    _write(str(a / 'README.md'), '')
    _write(str(a / 'LICENSE'), '')
    assert bom_cache.manifest_hash(str(a)) is None


def test_empty_cache_dir_argument_returns_none(tmp_path):
    # An empty/falsy cache_dir means BOM cache is disabled — lookups
    # short-circuit to None rather than scribbling cache files to /.
    assert bom_cache.lookup('', 'a' * 64) is None
    assert bom_cache.store('', 'a' * 64, '/dev/null') is None


def test_store_refuses_empty_bom(tmp_path):
    """0-component BOMs almost always indicate a resolution failure
    (python-inspector permission errors, Poetry missing poetry.lock,
    etc.). Caching them would replay the failure for every subsequent
    run on the same manifests."""
    cache_root = tmp_path / 'cache'
    cache_root.mkdir()
    empty_bom = tmp_path / 'empty.json'
    empty_bom.write_text('{"bomFormat":"CycloneDX","components":[]}')

    sha = 'e' * 64
    assert bom_cache.store(str(cache_root), sha, str(empty_bom)) is None
    assert bom_cache.lookup(str(cache_root), sha) is None


def test_store_refuses_bom_when_analyzer_had_errors(tmp_path):
    """Partial-resolution BOMs (some packages resolved, but some
    analyzer issues with severity=ERROR) shouldn't be cached — they'd
    replay the incomplete state forever for the same manifest set.
    Regression: example-org/security-apps run 2c225d0f got 19 components
    cached when the underlying python-inspector partial-failure should
    have invalidated the entry."""
    cache_root = tmp_path / 'cache'
    cache_root.mkdir()

    # A populated BOM
    bom = tmp_path / 'bom.json'
    bom.write_text('{"bomFormat":"CycloneDX","components":[{"name":"requests","version":"2.31.0"}]}')

    # ...but the analyzer-result.json shows ERROR-severity issues
    ar = tmp_path / 'analyzer-result.json'
    ar.write_text(json.dumps({
        'analyzer': {
            'result': {
                'packages': [],
                'issues': {
                    'PIP::requirements.txt::': [
                        {'severity': 'ERROR', 'message': 'python-inspector died'},
                    ],
                },
            },
        },
    }))

    sha = 'e' * 64
    result = bom_cache.store(str(cache_root), sha, str(bom),
                              analyzer_result_path=str(ar))
    assert result is None
    assert bom_cache.lookup(str(cache_root), sha) is None


def test_store_accepts_bom_when_only_warnings_present(tmp_path):
    """WARNING/HINT issues are common (npm-inspector noise) and don't
    invalidate the BOM — only ERROR-severity issues do."""
    cache_root = tmp_path / 'cache'
    cache_root.mkdir()
    bom = tmp_path / 'bom.json'
    bom.write_text('{"bomFormat":"CycloneDX","components":[{"name":"x","version":"1"}]}')

    ar = tmp_path / 'analyzer-result.json'
    ar.write_text(json.dumps({
        'analyzer': {
            'result': {
                'packages': [],
                'issues': {
                    'NPM::package.json::': [
                        {'severity': 'WARNING', 'message': 'mismatch in dep count'},
                        {'severity': 'HINT', 'message': 'unsupported engine'},
                    ],
                },
            },
        },
    }))

    sha = 'd' * 64
    result = bom_cache.store(str(cache_root), sha, str(bom),
                              analyzer_result_path=str(ar))
    assert result is not None
    assert bom_cache.lookup(str(cache_root), sha) == result


def test_purge_empty_removes_zero_component_entries(tmp_path):
    cache_root = tmp_path / 'cache'
    cache_root.mkdir()

    # Mix of good and bad entries written directly (bypassing store()).
    boms = cache_root / 'boms'
    boms.mkdir()
    (boms / ('a' * 64 + '.cyclonedx.json')).write_text('{"components":[]}')
    (boms / ('b' * 64 + '.cyclonedx.json')).write_text('{"components":[{"name":"x"}]}')
    (boms / ('c' * 64 + '.cyclonedx.json')).write_text('not-json')

    removed = bom_cache.purge_empty(str(cache_root))
    assert removed == 2  # empty + unreadable
    # The valid one survived.
    assert (boms / ('b' * 64 + '.cyclonedx.json')).exists()
    assert not (boms / ('a' * 64 + '.cyclonedx.json')).exists()
