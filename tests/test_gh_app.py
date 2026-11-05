"""GitHub App auth: config loading, JWT signing, installation tokens, fallback to PATs."""

import base64
import io
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import gh_app, gh_auth, github_client, secrets_loader, settings as settings_mod  # noqa: E402

FAKE_PEM = '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n'


@pytest.fixture(autouse=True)
def _clean_caches():
    gh_app.reset_caches()
    yield
    gh_app.reset_caches()


@pytest.fixture
def fake_github(monkeypatch):
    """Replace JWT signing and the HTTP layer. Returns the list of calls made."""
    calls = []
    routes = {}

    def fake_call(method, path, bearer, body=None):
        calls.append((method, path, bearer, body))
        result = routes.get((method, path))
        if result is None:
            raise gh_app.AppAuthError(f'GitHub API 404 for {method} {path}', status=404)
        if isinstance(result, Exception):
            raise result
        return result() if callable(result) else result

    monkeypatch.setattr(gh_app, 'make_jwt', lambda app_id, pem, now=None: 'app-jwt')
    monkeypatch.setattr(gh_app, '_call', fake_call)
    fake_call.routes = routes
    fake_call.calls = calls
    return fake_call


def _token_doc(token='ghs_inst', minutes=60):
    expires = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + minutes * 60))
    return {'token': token, 'expires_at': expires}


APP = {'app_id': '123', 'pem': FAKE_PEM.encode(), 'source': 'secrets_manager'}


# ---- app_config -------------------------------------------------------------

def test_no_app_settings_means_no_app():
    assert gh_app.app_config({}) is None
    assert gh_app.app_config({'github_app_id': '', 'github_app_private_key_path': ''}) is None


@pytest.mark.parametrize('cfg,needle', [
    ({'github_app_id': '123'}, 'no private key'),
    ({'github_app_private_key': FAKE_PEM}, 'github_app_id is not'),
    ({'github_app_id': 'my-app', 'github_app_private_key': FAKE_PEM}, 'numeric App ID'),
])
def test_partial_app_config_fails_closed(cfg, needle):
    with pytest.raises(gh_app.AppConfigError, match=needle):
        gh_app.app_config(cfg)


def test_secrets_manager_key_wins_over_file(tmp_path):
    f = tmp_path / 'k.pem'
    f.write_text('file-key')
    f.chmod(0o600)
    out = gh_app.app_config({'github_app_id': 123, 'github_app_private_key': FAKE_PEM,
                             'github_app_private_key_path': str(f)})
    assert out == {'app_id': '123', 'pem': FAKE_PEM.encode(), 'source': 'secrets_manager'}


def test_key_file_is_read_through_symlink(tmp_path):
    f = tmp_path / 'k.pem'
    f.write_text(FAKE_PEM)
    f.chmod(0o600)
    link = tmp_path / 'link.pem'
    link.symlink_to(f)
    out = gh_app.app_config({'github_app_id': '9', 'github_app_private_key_path': str(link)})
    assert out['pem'] == FAKE_PEM.encode() and out['source'] == 'file'


@pytest.mark.parametrize('mode', [0o644, 0o640, 0o604])
def test_key_file_readable_by_others_is_refused(tmp_path, mode):
    f = tmp_path / 'k.pem'
    f.write_text(FAKE_PEM)
    f.chmod(mode)
    with pytest.raises(gh_app.AppConfigError, match='chmod 600'):
        gh_app.app_config({'github_app_id': '9', 'github_app_private_key_path': str(f)})


def test_key_file_errors_do_not_name_the_path(tmp_path):
    missing = str(tmp_path / 'secret-dir' / 'nope.pem')
    with pytest.raises(gh_app.AppConfigError) as exc:
        gh_app.app_config({'github_app_id': '9', 'github_app_private_key_path': missing})
    assert 'secret-dir' not in str(exc.value)
    with pytest.raises(gh_app.AppConfigError, match='regular file'):
        gh_app.app_config({'github_app_id': '9', 'github_app_private_key_path': str(tmp_path)})


# ---- JWT --------------------------------------------------------------------

def _rsa_pem(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return key, pem


def _b64d(part):
    return base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))


def test_jwt_claims_and_signature_verify():
    key, pem = _rsa_pem()
    token = gh_app.make_jwt('123', pem, now=1_000_000)
    header, claims, sig = token.split('.')
    assert json.loads(_b64d(header)) == {'alg': 'RS256', 'typ': 'JWT'}
    assert json.loads(_b64d(claims)) == {'iat': 1_000_000 - 60, 'exp': 1_000_000 + 540, 'iss': 123}
    # Raises InvalidSignature when wrong.
    key.public_key().verify(_b64d(sig), f'{header}.{claims}'.encode(), padding.PKCS1v15(),
                            hashes.SHA256())


def test_jwt_lifetime_is_under_githubs_ten_minute_cap():
    _, pem = _rsa_pem()
    claims = json.loads(_b64d(gh_app.make_jwt('1', pem, now=0).split('.')[1]))
    assert claims['exp'] - claims['iat'] <= 600


def test_short_rsa_key_is_refused():
    _, pem = _rsa_pem(bits=1024)
    with pytest.raises(gh_app.AppConfigError, match='2048'):
        gh_app.make_jwt('1', pem)


def test_missing_cryptography_is_a_config_error_not_a_crash(monkeypatch):
    import builtins
    _, pem = _rsa_pem()
    real_import = builtins.__import__

    def no_cryptography(name, *args, **kwargs):
        if name.startswith('cryptography'):
            raise ImportError(f'No module named {name!r}')
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', no_cryptography)
    with pytest.raises(gh_app.AppConfigError, match='pip install'):
        gh_app.make_jwt('1', pem)


def test_unparseable_key_error_does_not_echo_key():
    with pytest.raises(gh_app.AppConfigError) as exc:
        gh_app.make_jwt('1', FAKE_PEM.encode())
    assert 'not-a-real-key' not in str(exc.value)
    assert exc.value.__cause__ is None


# ---- installation tokens ------------------------------------------------------

def test_token_is_minted_down_scoped_and_cached(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc()
    assert gh_app.installation_token(APP, 'Acme') == 'ghs_inst'
    assert gh_app.installation_token(APP, 'acme') == 'ghs_inst'
    assert [c[:2] for c in fake_github.calls] == [
        ('GET', '/orgs/acme/installation'), ('POST', '/app/installations/7/access_tokens')]
    assert fake_github.calls[1][3] == {'permissions': {'contents': 'read', 'metadata': 'read'}}
    assert all(c[2] == 'app-jwt' for c in fake_github.calls)


def test_token_near_expiry_is_refreshed(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc('old', minutes=4)
    assert gh_app.installation_token(APP, 'acme') == 'old'
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc('new')
    assert gh_app.installation_token(APP, 'acme') == 'new'


def test_user_account_installation_is_found(fake_github):
    fake_github.routes[('GET', '/users/someone/installation')] = {'id': 9}
    fake_github.routes[('POST', '/app/installations/9/access_tokens')] = _token_doc()
    assert gh_app.installation_token(APP, 'someone') == 'ghs_inst'


def test_not_installed_is_none_and_remembered(fake_github):
    assert gh_app.installation_token(APP, 'other') is None
    assert gh_app.installation_token(APP, 'other') is None
    assert len(fake_github.calls) == 2  # /orgs + /users once, then cached


def test_bad_jwt_is_reported_clearly(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = gh_app.AppAuthError('x', status=401)
    with pytest.raises(gh_app.AppAuthError, match='app JWT'):
        gh_app.installation_token(APP, 'acme')


def test_missing_permissions_are_reported_clearly(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = gh_app.AppAuthError(
        'x', status=422)
    with pytest.raises(gh_app.AppAuthError, match='Contents: Read'):
        gh_app.installation_token(APP, 'acme')


def test_removed_installation_is_looked_up_again(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = gh_app.AppAuthError(
        'x', status=404)
    with pytest.raises(gh_app.AppAuthError):
        gh_app.installation_token(APP, 'acme')
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 8}
    fake_github.routes[('POST', '/app/installations/8/access_tokens')] = _token_doc('t8')
    assert gh_app.installation_token(APP, 'acme') == 't8'


def test_invalid_org_name_is_rejected_before_any_call(fake_github):
    with pytest.raises(ValueError):
        gh_app.installation_token(APP, '../evil')
    assert fake_github.calls == []


def test_redirects_are_refused():
    handler = gh_app._NoRedirect()
    assert handler.redirect_request(MagicMock(), None, 302, 'Found', {}, 'https://evil.example') is None


def test_call_errors_never_include_the_bearer(monkeypatch):
    import urllib.error
    err = urllib.error.HTTPError('https://api.github.com/app', 500, 'boom', hdrs={},
                                 fp=io.BytesIO(b'{"leak": "body"}'))
    monkeypatch.setattr(gh_app._opener, 'open', MagicMock(side_effect=err))
    with pytest.raises(gh_app.AppAuthError) as exc:
        gh_app._call('GET', '/app', 'super-secret-jwt')
    assert 'super-secret-jwt' not in str(exc.value) and 'leak' not in str(exc.value)
    assert exc.value.status == 500


def test_call_passes_explicit_timeout(monkeypatch):
    resp = MagicMock()
    resp.__enter__.return_value.read.return_value = b'{"slug": "lde"}'
    opener = MagicMock(return_value=resp)
    monkeypatch.setattr(gh_app._opener, 'open', opener)
    assert gh_app._call('GET', '/app', 'jwt') == {'slug': 'lde'}
    req = opener.call_args.args[0]
    assert req.full_url == 'https://api.github.com/app'
    assert opener.call_args.kwargs['timeout'] == gh_app._TIMEOUT


# ---- github_client credential selection ---------------------------------------

def _cfg(**kw):
    return patch.object(settings_mod, 'load_settings', return_value=kw)


APP_CFG = {'github_app_id': '123', 'github_app_private_key': FAKE_PEM}


def test_app_token_wins_over_pat(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc()
    with _cfg(**APP_CFG, github_pats={'acme': 'github_pat_x'}):
        assert github_client._credential('acme') == ('ghs_inst', 'app')


def test_org_without_install_falls_back_to_pat(fake_github):
    with _cfg(**APP_CFG, github_pats={'*': 'ghp_any'}):
        assert github_client._credential('other') == ('ghp_any', 'pat')


def test_org_without_install_or_pat_fails_closed(fake_github):
    with _cfg(**APP_CFG, github_pats={}), \
            pytest.raises(github_client.GhError, match='No GitHub App is installed on org'):
        github_client._credential('other')


def test_broken_app_config_does_not_fall_back_to_pat():
    with _cfg(github_app_id='123', github_pats={'acme': 'github_pat_x'}), \
            pytest.raises(github_client.GhError, match='misconfigured'):
        github_client._credential('acme')


def test_app_401_retries_once_with_a_fresh_token(fake_github):
    tokens = iter(['first', 'second'])
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = \
        lambda: _token_doc(next(tokens))
    seen = []

    def call(tok):
        seen.append(tok)
        if tok == 'first':
            raise github_client.GhError('GitHub API 401', status=401)
        return 'ok'

    with _cfg(**APP_CFG):
        assert github_client._authed('acme', call) == 'ok'
    assert seen == ['first', 'second']


def test_pat_401_is_not_retried():
    seen = []

    def call(tok):
        seen.append(tok)
        raise github_client.GhError('GitHub API 401', status=401)

    with _cfg(github_pats={'acme': 'github_pat_x'}), pytest.raises(github_client.GhError):
        github_client._authed('acme', call)
    assert seen == ['github_pat_x']


def test_orgs_without_credentials_checks_installations(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc()
    with _cfg(**APP_CFG, github_pats={'globex': 'github_pat_x'}):
        assert github_client.orgs_without_credentials(['acme', 'globex', 'initech']) == ['initech']


# ---- gh-status ------------------------------------------------------------------

def test_auth_status_reports_app_and_pat_fallback(fake_github):
    fake_github.routes[('GET', '/app')] = {'slug': 'lde-reader', 'name': 'LDE Reader'}
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc()
    monkey_ok = {'ok': True, 'user': 'octocat', 'message': 'Authenticated as octocat'}
    with _cfg(**APP_CFG, default_orgs=['acme', 'globex'], github_pats={'globex': 'github_pat_x'}), \
            patch.object(gh_auth, 'check_token', return_value=monkey_ok):
        st = gh_auth.auth_status()
    assert st['mode'] == 'mixed' and st['installed'] and st['logged_in']
    [app] = st['apps']
    assert app['ok'] and app['slug'] == 'lde-reader' and app['key_source'] == 'secrets_manager'
    by_org = {a['org']: a for a in st['accounts']}
    assert by_org['acme']['via'] == 'app' and by_org['acme']['user'] == 'lde-reader[bot]'
    assert by_org['acme']['app'] == 'lde-reader'
    assert by_org['globex']['via'] == 'pat'
    assert 'deprecated' in st['notice'] and 'globex' in st['notice']
    assert 'ghs_inst' not in json.dumps(st) and 'not-a-real-key' not in json.dumps(st)


def test_auth_status_flags_uninstalled_org(fake_github):
    fake_github.routes[('GET', '/app')] = {'slug': 'lde-reader', 'name': 'LDE Reader'}
    with _cfg(**APP_CFG, default_orgs=['initech'], github_pats={}):
        st = gh_auth.auth_status()
    assert st['mode'] == 'app' and not st['logged_in']
    assert st['accounts'] == [{'host': 'github.com', 'org': 'initech', 'user': '', 'ok': False,
                               'via': '', 'app': ''}]


def test_auth_status_reports_broken_config_without_raising():
    with _cfg(github_app_id='123', default_orgs=['acme']):
        st = gh_auth.auth_status()
    assert st['installed'] and not st['logged_in'] and st['apps'] == []
    assert 'no private key' in st['apps_error']
    assert st['accounts'][0]['org'] == 'acme' and not st['accounts'][0]['ok']


# ---- settings and secrets ----------------------------------------------------

def test_masked_drops_private_key_and_path():
    out = settings_mod.masked({'github_app_id': '123', 'github_app_private_key': FAKE_PEM,
                               'github_app_private_key_path': '/home/x/k.pem'})
    assert out == {'github_app_id': '123'}


def test_save_never_persists_secret_manager_key(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{}')
    real_load = settings_mod.load_settings

    def load_with_overlay():
        cfg = real_load()
        cfg['github_app_private_key'] = FAKE_PEM
        return cfg

    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)), \
            patch.object(settings_mod, 'load_settings', load_with_overlay):
        settings_mod.save_settings({'github_app_id': '42'})
    stored = json.loads(f.read_text())
    assert stored['github_app_id'] == '42'
    assert 'github_app_private_key' not in stored


@pytest.mark.parametrize('bad', ['abc', '12a', True, ['1'], 1.5])
def test_app_id_is_validated_on_save(tmp_path, bad):
    with patch.object(settings_mod, 'SETTINGS_PATH', str(tmp_path / 's.json')), \
            pytest.raises(ValueError):
        settings_mod.save_settings({'github_app_id': bad})


def test_private_key_settings_are_not_api_writable():
    assert 'github_app_private_key_path' not in settings_mod.API_WRITABLE_KEYS
    assert 'github_app_private_key' not in settings_mod.API_WRITABLE_KEYS
    assert 'github_app_id' in settings_mod.API_WRITABLE_KEYS


@pytest.mark.parametrize('key', ['github_app_private_key_path', 'github_app_private_key'])
def test_put_settings_rejects_private_key_fields(key, monkeypatch):
    import server
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    handler = MagicMock()
    handler._read_body = lambda: {key: '/etc/passwd'}
    with patch.object(settings_mod, 'save_settings') as save, pytest.raises(ValueError):
        server.Handler.handle_put_settings(handler, groups=(), qs={})
    save.assert_not_called()


def test_secret_overlay_parses_app_secret():
    assert secrets_loader._parse_app(json.dumps({'app_id': 123, 'private_key': FAKE_PEM})) == {
        'github_app_id': '123', 'github_app_private_key': FAKE_PEM}
    assert secrets_loader._parse_app('REPLACE_ME') == {}
    assert secrets_loader._parse_app('{"app_id": "x", "private_key": "k"}') == {}
    assert secrets_loader._parse_app('not json') == {}
    assert secrets_loader._parse_app('{"app_id": true, "private_key": "-----BEGIN"}') == {}


def test_pat_placeholder_secret_is_quietly_empty():
    assert secrets_loader._parse_pats('REPLACE_ME') == {}


# ---- several apps -------------------------------------------------------------

def _apps_cfg(*entries):
    return {'github_apps_secret': [{'owner': o, 'app_id': i, 'private_key': FAKE_PEM}
                                   for o, i in entries]}


@pytest.mark.parametrize('cfg,needle', [
    (_apps_cfg(('acme', '1'), ('globex', '1')), 'more than once'),
    (_apps_cfg(('acme', '1'), ('ACME', '2')), 'same owner'),
    ({'github_apps_secret': [{'owner': 'a', 'app_id': 'x', 'private_key': FAKE_PEM}]}, 'numeric'),
    ({'github_apps_secret': [{'owner': '../a', 'app_id': '1', 'private_key': FAKE_PEM}]}, 'owner'),
    ({'github_apps_secret': [{'owner': 'a', 'app_id': '1'}]}, 'private_key'),
    ({'github_apps_secret': 'nope'}, 'list'),
    ({'github_apps': [{'owner': 'a', 'app_id': '1', 'private_key_path': '/nonexistent'}]}, 'cannot be opened'),
])
def test_bad_app_lists_fail_closed(cfg, needle):
    with pytest.raises(gh_app.AppConfigError, match=needle):
        gh_app.app_configs(cfg)


def test_owner_app_is_tried_first(fake_github):
    tried = []

    def fake_token(app, owner):
        tried.append(app['app_id'])
        return f'tok-{app["app_id"]}' if app['app_id'] == '2' else None
    with patch.object(gh_app, 'installation_token', fake_token):
        token, app = gh_app.token_for(gh_app.app_configs(_apps_cfg(('acme', '1'), ('globex', '2'))),
                                      'globex')
    assert token == 'tok-2' and app['owner'] == 'globex' and tried == ['2']


def test_other_apps_are_tried_when_owner_has_none(fake_github):
    tried = []

    def fake_token(app, owner):
        tried.append(app['app_id'])
        return 'tok-ent' if app['app_id'] == '3' else None
    apps = gh_app.app_configs(_apps_cfg(('acme', '1'), ('my-enterprise', '3')))
    with patch.object(gh_app, 'installation_token', fake_token):
        assert gh_app.token_for(apps, 'initech')[0] == 'tok-ent'
    assert tried == ['1', '3']


def test_caches_are_per_app(fake_github):
    fake_github.routes[('GET', '/orgs/acme/installation')] = {'id': 7}
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc('ghs_a')
    a1, a2 = gh_app.app_configs(_apps_cfg(('acme', '1'), ('globex', '2')))
    assert gh_app.installation_token(a1, 'acme') == 'ghs_a'
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc('ghs_b')
    assert gh_app.installation_token(a2, 'acme') == 'ghs_b'   # not app 1's cached token
    assert gh_app.installation_token(a1, 'acme') == 'ghs_a'


def test_credential_uses_the_orgs_own_app(fake_github):
    fake_github.routes[('GET', '/orgs/globex/installation')] = {'id': 9}
    fake_github.routes[('POST', '/app/installations/9/access_tokens')] = _token_doc('ghs_g')
    with _cfg(**_apps_cfg(('acme', '1'), ('globex', '2'))):
        assert github_client._credential('globex') == ('ghs_g', 'app')
    assert fake_github.calls[0][1] == '/orgs/globex/installation'


def test_secret_overlay_parses_app_list():
    raw = json.dumps({'apps': [{'owner': 'acme', 'app_id': 12, 'private_key': FAKE_PEM}]})
    assert secrets_loader._parse_app(raw) == {'github_apps_secret': [
        {'owner': 'acme', 'app_id': '12', 'private_key': FAKE_PEM}]}
    assert secrets_loader._parse_app(json.dumps({'apps': [{'app_id': 'x'}]})) == {}


def test_github_apps_is_file_only_and_hidden():
    assert 'github_apps' not in settings_mod.API_WRITABLE_KEYS
    out = settings_mod.masked({'github_apps': [{'private_key_path': '/k'}],
                               'github_apps_secret': [{'private_key': FAKE_PEM}], 'x': 1})
    assert out == {'x': 1}
