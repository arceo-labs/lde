"""Per-org credential selection from the GitHub org map (PATs), and the old PAT keys."""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import github_client, settings as settings_mod  # noqa: E402


def _cfg(**kw):
    return patch.object(settings_mod, 'load_settings', return_value=kw)


def _orgs(**orgs):
    return _cfg(github={'orgs': orgs})


def _pat(token, scan=True):
    return {'auth': 'pat', 'scan': scan, 'token': token}


def test_org_token_is_used_case_insensitively():
    with _orgs(acme=_pat('tok-acme'), b=_pat('tok-b')):
        assert github_client._get_token('Acme') == 'tok-acme'


def test_org_not_in_the_map_raises_without_naming_tokens():
    with _orgs(acme=_pat('tok-acme')), pytest.raises(github_client.GhError) as exc:
        github_client._get_token('other')
    assert 'not set up' in str(exc.value)
    assert 'tok-acme' not in str(exc.value)


def test_auth_none_raises():
    with _orgs(acme={'auth': 'none', 'scan': True}), \
            pytest.raises(github_client.GhError, match='Create app for acme'):
        github_client._get_token('acme')


def test_broken_map_fails_every_org_closed():
    with _cfg(github={'orgs': {'acme': _pat('t'), 'bad': {'auth': 'pat'}}}), \
            pytest.raises(github_client.GhError, match='config is broken'):
        github_client._get_token('acme')


def test_old_pats_are_migrated_but_the_star_pat_is_dropped():
    with _cfg(github_pats={'Acme': 'tok-acme', '*': 'any'}):
        assert github_client._get_token('acme') == 'tok-acme'
        with pytest.raises(github_client.GhError, match='not set up'):
            github_client._get_token('other')


def test_legacy_github_pat_is_ignored():
    with _cfg(github_pat='legacy', github_pats={'a': '1', 'b': '2'}), \
            pytest.raises(github_client.GhError):
        github_client._get_token('c')
    with _cfg(github_pat='legacy'), pytest.raises(github_client.GhError):
        github_client._get_token('a')


def test_missing_token_is_not_mistaken_for_404_by_callers():
    # An org whose name contains "404" must still surface the missing-credential error.
    with _orgs(a=_pat('1')), pytest.raises(github_client.GhError):
        github_client.get_repo_default_branch('team404', 'r')
    with _orgs(a=_pat('1')), pytest.raises(github_client.GhError):
        github_client.fetch_dependency_sbom('org403', 'r')


def test_request_uses_org_token():
    seen = {}

    def fake_get_json(url, *, accept=None, token=None):
        seen['token'] = token
        return {'default_branch': 'main'}

    with _orgs(acme=_pat('tok-acme')), \
            patch.object(github_client, '_get_json', side_effect=fake_get_json):
        assert github_client.get_repo_default_branch('acme', 'r') == 'main'
    assert seen['token'] == 'tok-acme'


def test_orgs_without_credentials_lists_each_unusable_org_once():
    with _orgs(acme=_pat('t'), b={'auth': 'none', 'scan': False}):
        missing = github_client.orgs_without_credentials(['Acme', 'b', 'B', 'c', 5])
    assert [o for o, _ in missing] == ['b', 'c', '5']
    assert 'Create app for b' in missing[0][1]
    assert 'not set up' in missing[1][1]


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
        assert 'github_pat' in settings_mod.legacy_pat_notice()
        assert 'legacy' not in settings_mod.legacy_pat_notice()


def test_no_legacy_notice_for_clean_file(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"github": {"orgs": {}}}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)):
        os.environ.pop('LDE_GITHUB_PAT', None)
        assert settings_mod.legacy_pat_notice() == ''


@pytest.mark.parametrize('name,value', [
    ('LDE_GITHUB', '{"orgs": {"a": {"auth": "pat", "token": "github_pat_env"}}}'),
    ('LDE_GITHUB_PATS', '{"a": "github_pat_env"}'),
    ('LDE_DEFAULT_ORGS', '["a"]'),
])
def test_github_env_overrides_are_ignored_with_a_notice(tmp_path, name, value):
    with patch.object(settings_mod, 'SETTINGS_PATH', str(tmp_path / 'none.json')), \
            patch.dict(os.environ, {name: value}):
        cfg = settings_mod.load_settings()
        notice = settings_mod.github_env_notice()
    key = name[len('LDE_'):].lower()
    assert key not in cfg
    assert name in notice and 'github_pat_env' not in notice


def test_no_github_env_notice_without_the_variables():
    with patch.dict(os.environ, {}, clear=False):
        for name in settings_mod.IGNORED_GITHUB_ENV:
            os.environ.pop(name, None)
        assert settings_mod.github_env_notice() == ''


def test_other_env_overrides_still_apply(tmp_path):
    with patch.object(settings_mod, 'SETTINGS_PATH', str(tmp_path / 'none.json')), \
            patch.dict(os.environ, {'LDE_DTRACK_URL': 'http://env'}):
        assert settings_mod.load_settings()['dtrack_url'] == 'http://env'


def test_secret_overlay_parses_old_pats_and_rejects_bad_shapes():
    from backend import secrets_loader
    assert secrets_loader._parse_pats('{"a": "t"}') == {'a': 't'}
    assert secrets_loader._parse_pats('nope') == {}
    assert secrets_loader._parse_pats('{"a": 5}') == {}
    assert secrets_loader._parse_pats('["a"]') == {}


def test_masked_hides_every_github_key():
    out = settings_mod.masked({'github': {'orgs': {'a': _pat('github_pat_secret')}},
                               'github_pats': {'a': 'github_pat_secret'},
                               'default_orgs': ['a'], 'github_secret': {}, 'dtrack_url': 'u'})
    assert out == {'dtrack_url': 'u'}


def test_github_keys_are_not_api_writable():
    for key in ('github', 'default_orgs', 'github_pats'):
        assert key not in settings_mod.API_WRITABLE_KEYS


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


def test_save_removes_the_keys_it_is_told_to(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{"default_orgs": ["a"], "github_pats": {"a": "t"}, "dtrack_url": "u"}')
    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)):
        settings_mod.save_settings({'github': {'orgs': {}}}, remove=('default_orgs', 'github_pats'))
    stored = json.loads(f.read_text())
    assert 'default_orgs' not in stored and 'github_pats' not in stored
    assert stored['github'] == {'orgs': {}} and stored['dtrack_url'] == 'u'


def test_headers_refuse_to_go_out_unauthenticated():
    with pytest.raises(github_client.GhError):
        github_client._make_headers(None)
    assert github_client._make_headers('t')['Authorization'] == 'Bearer t'


def test_placeholder_orgs_cover_the_example_file():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        '.settings.json.example')
    with open(path) as f:
        example = json.load(f)
    names = set(example['github']['orgs'])
    assert names, 'example file lists no orgs'
    assert names <= settings_mod.PLACEHOLDER_ORGS


def test_placeholder_orgs_matches_case_insensitively_and_dedupes():
    assert settings_mod.placeholder_orgs(['Example-Org', 'acme', 'example-org', 5]) == ['Example-Org']
