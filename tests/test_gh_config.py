"""The GitHub org map: strict validation, migration from the old keys, API writes and routes."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import gh_config, secrets_loader, settings as settings_mod  # noqa: E402

PEM = '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n'


def _file(**orgs):
    return {'orgs': orgs}


def _v(raw, path_ok=True, inline_ok=False):
    return gh_config.validate(raw, path_ok=path_ok, inline_ok=inline_ok)


# ---- validation ---------------------------------------------------------------

def test_valid_map_is_normalized():
    conf = _v({'orgs': {
        'Globex': {'auth': 'pat', 'token': ' github_pat_x '},
        'acme': {'auth': 'app', 'scan': False, 'app_id': 12, 'private_key_path': '~/k.pem'},
        'initech': {'auth': 'enterprise'},
        'hooli': {'auth': 'none'}},
        'enterprise_app': {'enterprise': 'My-Ent', 'app_id': '9', 'private_key_path': '/k'}})
    assert list(conf['orgs']) == ['acme', 'globex', 'hooli', 'initech']
    assert conf['orgs']['globex'] == {'auth': 'pat', 'scan': True, 'token': 'github_pat_x'}
    assert conf['orgs']['acme'] == {'auth': 'app', 'scan': False, 'app_id': '12',
                                    'private_key_path': '~/k.pem'}
    assert conf['enterprise_app']['enterprise'] == 'my-ent'


@pytest.mark.parametrize('raw,needle', [
    ({'orgs': {'*': {'auth': 'pat', 'token': 't'}}}, 'no longer supported'),
    ({'orgs': {'a/b': {'auth': 'none'}}}, 'not a GitHub org'),
    ({'orgs': {'a' * 40: {'auth': 'none'}}}, 'not a GitHub org'),
    ({'orgs': {'Acme': {'auth': 'none'}, 'acme': {'auth': 'none'}}}, 'listed twice'),
    ({'orgs': {'acme': {'auth': 'token'}}}, 'auth must be one of'),
    ({'orgs': {'acme': {'auth': 'pat'}}}, 'needs a token'),
    ({'orgs': {'acme': {'auth': 'pat', 'token': 'has space'}}}, 'needs a token'),
    ({'orgs': {'acme': {'auth': 'none', 'token': 't'}}}, 'unknown fields'),
    ({'orgs': {'acme': {'auth': 'pat', 'token': 't', 'scan': 'yes'}}}, 'scan must be'),
    ({'orgs': {'acme': {'auth': 'app', 'private_key_path': '/k'}}}, 'numeric App ID'),
    ({'orgs': {'acme': {'auth': 'app', 'app_id': 'x', 'private_key_path': '/k'}}}, 'numeric App ID'),
    ({'orgs': {'acme': {'auth': 'app', 'app_id': '1'}}}, 'no private key'),
    ({'orgs': {'acme': {'auth': 'app', 'app_id': '1', 'private_key': PEM}}}, 'inline private_key'),
    ({'orgs': {'acme': {'auth': 'enterprise'}}}, 'no enterprise_app'),
    ({'orgs': {}, 'enterprise_app': {'app_id': '1', 'private_key_path': '/k'}}, 'slug'),
    ({'orgs': {}, 'enterprise_apps': []}, 'Unknown GitHub config fields'),
    ({'orgs': []}, '"orgs" must be'),
    ([], 'JSON object'),
])
def test_bad_maps_fail_closed(raw, needle):
    with pytest.raises(gh_config.ConfigError, match=needle):
        _v(raw)


def test_secret_takes_inline_keys_and_refuses_paths():
    raw = _file(acme={'auth': 'app', 'app_id': '1', 'private_key': PEM})
    assert _v(raw, path_ok=False, inline_ok=True)['orgs']['acme']['private_key'] == PEM
    with pytest.raises(gh_config.ConfigError, match='not allowed in the lde/github'):
        _v(_file(acme={'auth': 'app', 'app_id': '1', 'private_key_path': '/k'}),
           path_ok=False, inline_ok=True)


def test_errors_never_quote_tokens_or_keys():
    for raw in (_file(acme={'auth': 'none', 'token': 'github_pat_SECRET'}),
                _file(acme={'auth': 'app', 'app_id': '1', 'private_key': PEM + 'SECRET'})):
        with pytest.raises(gh_config.ConfigError) as exc:
            _v(raw)
        assert 'SECRET' not in str(exc.value)


def test_same_app_on_several_orgs_is_allowed():
    entry = {'auth': 'app', 'app_id': '1', 'private_key_path': '/k'}
    assert len(_v(_file(a=entry, b=dict(entry)))['orgs']) == 2


# ---- load: source and migration ----------------------------------------------------

def test_secret_wins_over_file_and_old_keys():
    conf = gh_config.load({'github_secret': _file(a={'auth': 'none'}),
                           'github': _file(b={'auth': 'none'}), 'github_pats': {'c': 't'}})
    assert list(conf['orgs']) == ['a'] and conf['source'] == 'secret'
    assert any('REPLACE_ME' in n for n in conf['notices'])


def test_file_wins_over_old_keys_and_says_so():
    conf = gh_config.load({'github': _file(b={'auth': 'none'}), 'default_orgs': ['c']})
    assert list(conf['orgs']) == ['b'] and conf['source'] == 'file'
    assert any('default_orgs' in n and 'ignored' in n for n in conf['notices'])


def test_unreadable_secret_fails_closed_instead_of_using_old_keys():
    with pytest.raises(gh_config.ConfigError, match='Could not read'):
        gh_config.load({'github_secret_error': 'Could not read the lde/github secret (x).',
                        'github_pats': {'a': 't'}})


def test_migration_from_default_orgs_and_pats():
    conf = gh_config.load({
        'default_orgs': ['acme', 'Globex'],
        'github_pats': {'acme': 'tok-a', 'pat-only': 'tok-p', '*': 'any'}})
    assert conf['orgs'] == {
        'acme': {'auth': 'pat', 'scan': True, 'token': 'tok-a'},
        'globex': {'auth': 'none', 'scan': True},
        'pat-only': {'auth': 'pat', 'scan': False, 'token': 'tok-p'}}
    assert conf['source'] == 'legacy'
    assert gh_config.STAR_PAT_NOTICE in conf['notices']


def test_migration_reads_comma_separated_default_orgs_from_env():
    assert list(gh_config.load({'default_orgs': 'acme, globex'})['orgs']) == ['acme', 'globex']


def test_unreleased_app_keys_are_not_read():
    # github_app_id / github_apps only existed on the unreleased GitHub App branch.
    conf = gh_config.load({'default_orgs': ['acme'], 'github_app_id': '2',
                           'github_apps': [{'owner': 'acme', 'app_id': '3'}]})
    assert conf['orgs'] == {'acme': {'auth': 'none', 'scan': True}}


def test_nothing_configured():
    conf = gh_config.load({})
    assert conf['orgs'] == {} and conf['source'] == 'none' and conf['notices'] == []


def test_scan_orgs():
    conf = gh_config.load({'github': _file(a={'auth': 'none'}, b={'auth': 'none', 'scan': False})})
    assert gh_config.scan_orgs(conf) == ['a']


# ---- writes -------------------------------------------------------------------------

@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    f = tmp_path / 'settings.json'
    f.write_text(json.dumps({'dtrack_url': 'http://dt'}))
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(f))
    return f


def _orgs(f):
    return json.loads(f.read_text())['github']['orgs']


def test_add_org_defaults_to_none_with_scan_on(local):
    assert gh_config.set_org('Acme') == {'org': 'acme', 'auth': 'none', 'scan': True}
    assert _orgs(local) == {'acme': {'auth': 'none', 'scan': True}}


def test_pat_is_write_only_and_kept_when_masked(local):
    out = gh_config.set_org('acme', auth='pat', token='github_pat_secret')
    assert out == {'org': 'acme', 'auth': 'pat', 'scan': True, 'token_hint': 'gith…'}
    gh_config.set_org('acme', scan=False, token='gith…')
    assert _orgs(local)['acme'] == {'auth': 'pat', 'scan': False, 'token': 'github_pat_secret'}
    gh_config.set_org('acme', token='github_pat_new')
    assert _orgs(local)['acme']['token'] == 'github_pat_new'


def test_switching_away_from_pat_drops_the_token(local):
    gh_config.set_org('acme', auth='pat', token='github_pat_secret')
    gh_config.set_org('acme', auth='none')
    assert 'github_pat_secret' not in local.read_text()


@pytest.mark.parametrize('kw,needle', [
    ({'auth': 'pat'}, 'needs a token'),
    ({'auth': 'app'}, 'Create app for acme'),
    ({'auth': 'enterprise'}, 'No enterprise app'),
    ({'auth': 'none', 'token': 'x'}, 'only used with auth "pat"'),
    ({'auth': 'root'}, 'auth must be'),
    ({'scan': 'yes'}, 'scan must be'),
    ({'token': 5}, 'token must be'),
    ({'auth': 'pat', 'token': 'a b'}, 'no spaces'),
])
def test_bad_api_writes_change_nothing(local, kw, needle):
    before = local.read_text()
    with pytest.raises(ValueError, match=needle):
        gh_config.set_org('acme', **kw)
    assert local.read_text() == before


def test_scan_of_an_app_org_can_be_changed_but_its_key_is_kept(local, tmp_path):
    local.write_text(json.dumps({'github': _file(acme={'auth': 'app', 'app_id': '1',
                                                       'private_key_path': '/k.pem'})}))
    assert gh_config.set_org('acme', auth='app', scan=False)['scan'] is False
    assert _orgs(local)['acme'] == {'auth': 'app', 'scan': False, 'app_id': '1',
                                    'private_key_path': '/k.pem'}


def test_enterprise_auth_needs_the_enterprise_app(local):
    local.write_text(json.dumps({'github': {'orgs': {}, 'enterprise_app': {
        'enterprise': 'ent', 'app_id': '9', 'private_key_path': '/k'}}}))
    gh_config.set_org('initech', auth='enterprise')
    stored = json.loads(local.read_text())['github']
    assert stored['orgs']['initech'] == {'auth': 'enterprise', 'scan': True}
    assert stored['enterprise_app']['app_id'] == '9'


def test_first_write_migrates_and_removes_the_old_keys(local):
    local.write_text(json.dumps({'default_orgs': ['acme'], 'github_pats': {'globex': 'tok'},
                                 'dtrack_url': 'http://dt'}))
    gh_config.set_org('initech', auth='none', scan=False)
    stored = json.loads(local.read_text())
    assert 'default_orgs' not in stored and 'github_pats' not in stored
    assert stored['github']['orgs'] == {
        'acme': {'auth': 'none', 'scan': True},
        'globex': {'auth': 'pat', 'scan': False, 'token': 'tok'},
        'initech': {'auth': 'none', 'scan': False}}
    assert stored['dtrack_url'] == 'http://dt'


def test_a_broken_stored_map_is_never_overwritten(local):
    local.write_text(json.dumps({'github': _file(acme={'auth': 'pat'})}))
    before = local.read_text()
    with pytest.raises(gh_config.ConfigError):
        gh_config.set_org('globex')
    assert local.read_text() == before


def test_remove_org(local):
    gh_config.set_org('acme')
    assert gh_config.remove_org('ACME') is True
    assert _orgs(local) == {}
    assert gh_config.remove_org('acme') is False


def test_aws_writes_go_to_the_secret(monkeypatch):
    monkeypatch.setenv('LDE_SECRETS_SOURCE', 'aws')
    monkeypatch.setattr(secrets_loader, 'get_secret_fresh', lambda name: json.dumps(
        _file(acme={'auth': 'app', 'app_id': '1', 'private_key': PEM})))
    put = MagicMock()
    monkeypatch.setattr(secrets_loader, 'put_secret', put)
    with patch.object(settings_mod, 'save_settings') as save:
        gh_config.set_org('globex', auth='pat', token='github_pat_g')
    save.assert_not_called()
    name, value = put.call_args.args
    assert name == 'lde/github'
    assert json.loads(value)['orgs']['acme']['private_key'] == PEM
    assert json.loads(value)['orgs']['globex']['token'] == 'github_pat_g'


# ---- routes ---------------------------------------------------------------------------

def _handler(body=None):
    import server
    h = MagicMock()
    h._read_body = lambda: body if body is not None else {}
    return server, h


def test_put_route_passes_only_known_fields(local):
    server, h = _handler({'auth': 'pat', 'token': 'github_pat_x', 'scan': False})
    server.Handler.handle_put_github_org(h, ('Acme',), {})
    status, doc = h._json_response.call_args.args
    assert status == 200
    assert doc == {'org': 'acme', 'auth': 'pat', 'scan': False, 'token_hint': 'gith…'}


@pytest.mark.parametrize('body', [{'app_id': '1'}, {'private_key_path': '/etc/passwd'},
                                  {'private_key': PEM}, ['x']])
def test_put_route_never_takes_app_keys(local, body):
    server, h = _handler(body)
    with pytest.raises(ValueError):
        server.Handler.handle_put_github_org(h, ('acme',), {})
    assert 'github' not in json.loads(local.read_text())


def test_delete_route(local):
    gh_config.set_org('acme')
    server, h = _handler()
    server.Handler.handle_delete_github_org(h, ('acme',), {})
    assert h._json_response.call_args.args == (200, {'deleted': 'acme'})
    server.Handler.handle_delete_github_org(h, ('acme',), {})
    assert h._json_response.call_args.args[0] == 404


def test_org_routes_are_registered_and_delete_is_csrf_guarded():
    import server
    routes = {(m, p): n for m, p, n in server.ROUTES}
    assert routes[('PUT', r'^/api/github/orgs/([A-Za-z0-9-]{1,39})$')] == 'handle_put_github_org'
    assert routes[('DELETE', r'^/api/github/orgs/([A-Za-z0-9-]{1,39})$')] == 'handle_delete_github_org'
    assert 'DELETE' in server._MUTATING_METHODS


def test_delete_without_json_content_type_is_refused(monkeypatch):
    import server
    h = server.Handler.__new__(server.Handler)
    h.path = '/api/github/orgs/acme'
    h.headers = {'Content-Type': 'text/plain'}
    h._require_auth = lambda: True
    sent = []
    h._json_response = lambda status, data: sent.append(status)
    with patch.object(gh_config, 'remove_org') as remove:
        h.do_DELETE()
    assert sent == [415]
    remove.assert_not_called()


# ---- review fixes -----------------------------------------------------------------------

def _aws_secrets(monkeypatch, values, cfg=None):
    monkeypatch.setenv('LDE_SECRETS_SOURCE', 'aws')
    monkeypatch.setattr(settings_mod, 'load_settings', lambda: dict(cfg or {}))

    def fresh(name):
        value = values.get(name, 'REPLACE_ME')
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr(secrets_loader, 'get_secret_fresh', fresh)
    put = MagicMock()
    monkeypatch.setattr(secrets_loader, 'put_secret', put)
    return put


def test_aws_first_write_reads_the_old_pats_fresh(monkeypatch):
    # The cached overlay missed lde/github-pat (say a timeout): the fresh read still has it.
    put = _aws_secrets(monkeypatch, {'lde/github-pat': '{"acme": "github_pat_a"}'},
                       cfg={'default_orgs': ['acme']})
    gh_config.set_org('globex')
    orgs = json.loads(put.call_args.args[1])['orgs']
    assert orgs['acme'] == {'auth': 'pat', 'scan': True, 'token': 'github_pat_a'}


@pytest.mark.parametrize('pats', [RuntimeError('Secrets Manager timed out'), 'not json'])
def test_aws_first_write_fails_closed_when_old_pats_are_unreadable(monkeypatch, pats):
    put = _aws_secrets(monkeypatch, {'lde/github-pat': pats})
    with pytest.raises(RuntimeError):
        gh_config.set_org('globex')
    put.assert_not_called()


def test_aws_secret_size_is_capped(monkeypatch):
    big = {f'org{i}': {'auth': 'app', 'app_id': str(i), 'private_key': PEM + 'x' * 2000}
           for i in range(40)}
    put = _aws_secrets(monkeypatch, {'lde/github': json.dumps({'orgs': big})})
    with pytest.raises(gh_config.ConfigError, match='64 KB'):
        gh_config.set_org('globex')
    put.assert_not_called()
    conf = gh_config.load({'github_secret': {'orgs': big}})
    with pytest.raises(gh_config.ConfigError, match='no room'):
        gh_config.check_room_for_app(conf)


def test_old_entries_with_non_github_names_are_skipped_with_a_notice():
    conf = gh_config.load({'default_orgs': ['acme', 'acme/web'],
                           'github_pats': {'my.org': 'tok', 'globex': 'tok-g'}})
    assert sorted(conf['orgs']) == ['acme', 'globex']
    assert any('my.org' in n and 'acme/web' in n for n in conf['notices'])


def test_settings_file_is_written_atomically_and_owner_only(local):
    import stat
    local.unlink()
    gh_config.set_org('acme', auth='pat', token='github_pat_x')
    assert stat.S_IMODE(local.stat().st_mode) == 0o600
    assert not [p for p in local.parent.iterdir() if p.name.endswith('.tmp')]


def test_run_check_reports_a_broken_map_once():
    from backend import github_client
    with patch.object(settings_mod, 'load_settings',
                      return_value={'github': _file(acme={'auth': 'pat'})}), \
            pytest.raises(github_client.GhError, match='config is broken'):
        github_client.orgs_without_credentials(['a', 'b', 'c'])


# ---- PR review fixes ---------------------------------------------------------------------

def test_aws_never_reads_the_map_from_a_file(monkeypatch):
    # On AWS the map is only lde/github, where writes go; a file "github" is not used.
    monkeypatch.setenv('LDE_SECRETS_SOURCE', 'aws')
    conf = gh_config.load({'github': _file(acme={'auth': 'app', 'app_id': '1',
                                                 'private_key_path': '/k.pem'})})
    assert conf['orgs'] == {} and conf['source'] == 'none'


def test_settings_save_never_writes_env_or_secret_values(tmp_path, monkeypatch):
    f = tmp_path / 's.json'
    f.write_text(json.dumps({'dtrack_url': 'u', 'github': _file(acme={'auth': 'none'}),
                             'github_app_id': '7'}))
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(f))
    monkeypatch.setenv('LDE_DTRACK_API_KEY', 'env-only-key')
    out = settings_mod.save_settings({'gemini_model': 'm'})
    stored = json.loads(f.read_text())
    assert 'env-only-key' not in f.read_text()
    assert stored == {'dtrack_url': 'u', 'github': _file(acme={'auth': 'none'}),
                      'github_app_id': '7', 'gemini_model': 'm'}
    assert out['dtrack_api_key'] == 'env-only-key'  # the effective value is still returned


def test_org_saves_ignore_a_leftover_github_env_map(tmp_path, monkeypatch):
    f = tmp_path / 's.json'
    f.write_text(json.dumps({'github': _file(acme={'auth': 'none'})}))
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(f))
    monkeypatch.setenv('LDE_GITHUB', json.dumps(_file(evil={'auth': 'pat',
                                                            'token': 'github_pat_env'})))
    gh_config.set_org('globex')
    assert sorted(json.loads(f.read_text())['github']['orgs']) == ['acme', 'globex']
    assert 'github_pat_env' not in f.read_text()


def test_setup_callback_query_is_not_logged():
    import server
    line = '"GET /api/gh-app/callback?code=abc123&state=xyz HTTP/1.1" 302 -'
    out = server._redact_request_line(line)
    assert 'abc123' not in out and 'xyz' not in out
    assert out == '"GET /api/gh-app/callback?<redacted> HTTP/1.1" 302 -'
    other = '"GET /api/runs?limit=5 HTTP/1.1" 200 -'
    assert server._redact_request_line(other) == other


def test_check_aws_summarizes_the_org_rows():
    from scripts import check_aws
    data = {'logged_in': True, 'enterprise_app': None, 'orgs': [
        {'org': 'acme', 'auth': 'app', 'scan': True, 'ok': True, 'token_hint': ''},
        {'org': 'globex', 'auth': 'pat', 'scan': True, 'ok': True, 'token_hint': 'gith'},
        {'org': 'later', 'auth': 'none', 'scan': False, 'ok': False}]}
    out = check_aws._gh_status_summary(data)
    assert out == '2/2 orgs authenticated (acme via app, globex via pat)'
    assert 'gith' not in out
