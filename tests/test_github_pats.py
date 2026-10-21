"""Per-org fine-grained PAT selection, settings merge, and masking."""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import github_client, settings as settings_mod  # noqa: E402


def _cfg(**kw):
    return patch.object(settings_mod, 'load_settings', return_value=kw)


def test_org_token_preferred_case_insensitive():
    with _cfg(github_pats={'acme': 'tok-acme', 'b': 'tok-b'}):
        assert github_client._get_token('Acme') == 'tok-acme'


def test_star_entry_covers_unlisted_orgs():
    with _cfg(github_pats={'acme': 'tok-acme', '*': 'any'}):
        assert github_client._get_token('acme') == 'tok-acme'
        assert github_client._get_token('other') == 'any'


def test_unknown_org_raises_without_star_entry():
    for pats in ({'acme': 'tok-acme'}, {'a': '1', 'b': '2'}):
        with _cfg(github_pats=pats), pytest.raises(github_client.GhError) as exc:
            github_client._get_token('other')
        assert 'other' in str(exc.value)
        assert not any(t in str(exc.value) for t in pats.values())


def test_legacy_github_pat_is_ignored():
    with _cfg(github_pat='legacy', github_pats={'a': '1', 'b': '2'}), \
            pytest.raises(github_client.GhError):
        github_client._get_token('c')
    with _cfg(github_pat='legacy'), pytest.raises(github_client.GhError):
        github_client._get_token('a')


def test_no_tokens_raises():
    with _cfg(github_pats={}), pytest.raises(github_client.GhError):
        github_client._get_token('acme')


def test_missing_token_is_not_mistaken_for_404_by_callers():
    # An org whose name contains "404" must still surface the missing-token error.
    with _cfg(github_pats={'a': '1', 'b': '2'}), pytest.raises(github_client.GhError):
        github_client.get_repo_default_branch('team404', 'r')
    with _cfg(github_pats={'a': '1', 'b': '2'}), pytest.raises(github_client.GhError):
        github_client.fetch_dependency_sbom('org403', 'r')


def test_request_uses_org_token():
    seen = {}

    def fake_get_json(url, *, accept=None, token=None):
        seen['token'] = token
        return {'default_branch': 'main'}

    with _cfg(github_pats={'acme': 'tok-acme'}), \
            patch.object(github_client, '_get_json', side_effect=fake_get_json):
        assert github_client.get_repo_default_branch('acme', 'r') == 'main'
    assert seen['token'] == 'tok-acme'


def test_merge_accepts_star_key():
    assert settings_mod.merge_github_pats({}, {'*': 't'}) == {'*': 't'}


def test_load_settings_drops_legacy_pat(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"github_pat": "legacy", "github_pats": {"a": "t"}}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)):
        out = settings_mod.load_settings()
    assert out['github_pats'] == {'a': 't'}
    assert 'github_pat' not in out


def test_legacy_notice_when_file_has_github_pat(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"github_pat": "legacy"}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)), \
            patch.dict(os.environ, {}, clear=False):
        os.environ.pop('LDE_GITHUB_PAT', None)
        assert 'github_pats' in settings_mod.legacy_pat_notice()
        assert 'legacy' not in settings_mod.legacy_pat_notice()


def test_no_legacy_notice_for_clean_file(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"github_pats": {"a": "t"}}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)):
        os.environ.pop('LDE_GITHUB_PAT', None)
        assert settings_mod.legacy_pat_notice() == ''


def test_env_override_parses_json_map(tmp_path):
    with patch.object(settings_mod, 'SETTINGS_PATH', str(tmp_path / 'none.json')), \
            patch.dict(os.environ, {'LDE_GITHUB_PATS': '{"a": "t"}'}):
        assert settings_mod.load_settings()['github_pats'] == {'a': 't'}


def test_env_override_ignores_bad_json(tmp_path):
    with patch.object(settings_mod, 'SETTINGS_PATH', str(tmp_path / 'none.json')), \
            patch.dict(os.environ, {'LDE_GITHUB_PATS': 'not json'}):
        assert settings_mod.load_settings()['github_pats'] == {}


def test_secret_overlay_parses_pats_and_rejects_bad_shapes():
    from backend import secrets_loader
    assert secrets_loader._parse_pats('{"a": "t"}') == {'a': 't'}
    assert secrets_loader._parse_pats('nope') == {}
    assert secrets_loader._parse_pats('{"a": 5}') == {}
    assert secrets_loader._parse_pats('["a"]') == {}


def test_merge_adds_updates_removes():
    out = settings_mod.merge_github_pats({'a': 't1', 'b': 't2'}, {'A': 't1b', 'b': '', 'C': 't3'})
    assert out == {'a': 't1b', 'c': 't3'}


def test_merge_normalizes_existing_mixed_case_keys():
    # A hand-edited "Acme" entry must still be removed or replaced by the lower-cased UI key.
    assert settings_mod.merge_github_pats({'Acme': 't1', 'B': 't2'}, {'acme': ''}) == {'b': 't2'}
    assert settings_mod.merge_github_pats({'Acme': 't1'}, {'acme': 't2'}) == {'acme': 't2'}


def test_merge_ignores_masked_values():
    out = settings_mod.merge_github_pats({'a': 'github_pat_real'}, {'a': 'gith…'})
    assert out == {'a': 'github_pat_real'}


@pytest.mark.parametrize('patch_', [{'bad/org': 't'}, {'a': 5}, ['a'], {'': 't'}])
def test_merge_rejects_bad_input(patch_):
    with pytest.raises(ValueError):
        settings_mod.merge_github_pats({}, patch_)


def test_masked_hides_every_token():
    out = settings_mod.masked({'github_pats': {'a': 'github_pat_secret'}})
    assert out['github_pats'] == {'a': 'gith…'}



def test_save_preserves_legacy_github_pat_on_disk(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"github_pat": "legacy-token", "dtrack_url": "http://old"}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)), \
         patch.dict(os.environ, {}, clear=False):
        os.environ.pop('LDE_GITHUB_PAT', None)
        out = settings_mod.save_settings({'dtrack_url': 'http://new'})
        notice = settings_mod.legacy_pat_notice()
    assert 'github_pat' not in out
    stored = json.loads(f.read_text())
    assert stored['github_pat'] == 'legacy-token'
    assert stored['dtrack_url'] == 'http://new'
    assert notice


def test_orgs_without_token_lists_uncovered_orgs():
    with _cfg(github_pats={'acme': 't'}):
        assert github_client.orgs_without_token(['Acme', 'b', 'B', 'c']) == ['b', 'c']
    with _cfg(github_pats={'acme': 't', '*': 'any'}):
        assert github_client.orgs_without_token(['b']) == []
    with _cfg(github_pats={}):
        assert github_client.orgs_without_token(['b']) == ['b']


def test_headers_refuse_to_go_out_unauthenticated():
    with pytest.raises(github_client.GhError):
        github_client._make_headers(None)
    assert github_client._make_headers('t')['Authorization'] == 'Bearer t'
