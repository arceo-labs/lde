"""GitHub App auth: key loading, JWT signing, installation tokens, per-org credentials, status."""

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

from backend import gh_app, gh_auth, gh_config, github_client, secrets_loader, settings as settings_mod  # noqa: E402

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


# ---- key loading -------------------------------------------------------------

def _path_app(path):
    return gh_config.load_app({'app_id': '9', 'private_key_path': str(path)})


def test_inline_key_is_used_as_is():
    out = gh_config.load_app({'app_id': '123', 'private_key': FAKE_PEM})
    assert out == {'app_id': '123', 'pem': FAKE_PEM.encode(), 'source': 'secrets_manager'}


def test_key_file_is_read_through_symlink(tmp_path):
    f = tmp_path / 'k.pem'
    f.write_text(FAKE_PEM)
    f.chmod(0o600)
    link = tmp_path / 'link.pem'
    link.symlink_to(f)
    out = _path_app(link)
    assert out['pem'] == FAKE_PEM.encode() and out['source'] == 'file'


@pytest.mark.parametrize('mode', [0o644, 0o640, 0o604])
def test_key_file_readable_by_others_is_refused(tmp_path, mode):
    f = tmp_path / 'k.pem'
    f.write_text(FAKE_PEM)
    f.chmod(mode)
    with pytest.raises(gh_app.AppConfigError, match='chmod 600'):
        _path_app(f)


def test_key_file_errors_do_not_name_the_path(tmp_path):
    missing = str(tmp_path / 'secret-dir' / 'nope.pem')
    with pytest.raises(gh_app.AppConfigError) as exc:
        _path_app(missing)
    assert 'secret-dir' not in str(exc.value)
    with pytest.raises(gh_app.AppConfigError, match='regular file'):
        _path_app(tmp_path)


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


def _app(app_id='123', scan=True):
    return {'auth': 'app', 'scan': scan, 'app_id': app_id, 'private_key': FAKE_PEM}


ENTERPRISE = {'enterprise': 'my-ent', 'app_id': '555', 'private_key': FAKE_PEM}


def _secret(**orgs):
    """The map as the lde/github secret holds it (inline keys)."""
    return _cfg(github_secret={'orgs': orgs, 'enterprise_app': ENTERPRISE})


def _install(fake_github, org, inst_id=7, token='ghs_inst'):
    fake_github.routes[('GET', f'/orgs/{org}/installation')] = {'id': inst_id}
    fake_github.routes[('POST', f'/app/installations/{inst_id}/access_tokens')] = _token_doc(token)


def test_org_with_app_gets_an_installation_token(fake_github):
    _install(fake_github, 'acme')
    with _secret(acme=_app()):
        assert github_client._credential('acme') == ('ghs_inst', 'app')
    assert fake_github.calls[0][1] == '/orgs/acme/installation'


def test_app_not_installed_does_not_fall_back(fake_github):
    with _secret(acme=_app()), pytest.raises(github_client.GhError, match='not installed'):
        github_client._credential('acme')


def test_only_the_orgs_own_app_is_tried(fake_github):
    _install(fake_github, 'globex', 9, 'ghs_g')
    with _secret(acme=_app('1'), globex=_app('2')):
        assert github_client._credential('globex') == ('ghs_g', 'app')
    with patch.object(gh_app, 'installation_token', return_value=None) as tok, \
            _secret(acme=_app('1'), globex=_app('2')), pytest.raises(github_client.GhError):
        github_client._credential('acme')
    assert [c.args[0]['app_id'] for c in tok.call_args_list] == ['1']


def test_enterprise_org_uses_the_enterprise_app(fake_github):
    _install(fake_github, 'initech', 11, 'ghs_e')
    seen = []
    real = gh_app.installation_token

    def spy(app, owner):
        seen.append(app['app_id'])
        return real(app, owner)
    with _secret(initech={'auth': 'enterprise', 'scan': True}), \
            patch.object(gh_app, 'installation_token', spy):
        assert github_client._credential('initech') == ('ghs_e', 'app')
    assert seen == ['555']


def test_broken_key_fails_closed(fake_github):
    with _cfg(github={'orgs': {'acme': {'auth': 'app', 'app_id': '1',
                                        'private_key_path': '/nonexistent/k.pem'}}}), \
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

    with _secret(acme=_app()):
        assert github_client._authed('acme', call) == 'ok'
    assert seen == ['first', 'second']


def test_pat_401_is_not_retried():
    seen = []

    def call(tok):
        seen.append(tok)
        raise github_client.GhError('GitHub API 401', status=401)

    with _secret(acme={'auth': 'pat', 'token': 'github_pat_x'}), \
            pytest.raises(github_client.GhError):
        github_client._authed('acme', call)
    assert seen == ['github_pat_x']


def test_orgs_without_credentials_checks_installations(fake_github):
    _install(fake_github, 'acme')
    with _secret(acme=_app(), globex={'auth': 'pat', 'token': 'github_pat_x'},
                 initech=_app('9')):
        missing = github_client.orgs_without_credentials(['acme', 'globex', 'initech'])
    assert [o for o, _ in missing] == ['initech']


# ---- gh-status ------------------------------------------------------------------

def test_auth_status_reports_each_org(fake_github):
    fake_github.routes[('GET', '/app')] = {'slug': 'lde-reader', 'name': 'LDE Reader'}
    _install(fake_github, 'acme')
    _install(fake_github, 'initech', 11, 'ghs_e')
    monkey_ok = {'ok': True, 'user': 'octocat', 'message': 'Authenticated as octocat'}
    with _secret(acme=_app(), globex={'auth': 'pat', 'token': 'github_pat_secret'},
                 initech={'auth': 'enterprise', 'scan': False},
                 hooli={'auth': 'none', 'scan': False}), \
            patch.object(gh_auth, 'check_token', return_value=monkey_ok):
        st = gh_auth.auth_status()
    assert st['mode'] == 'mixed' and st['installed'] and st['logged_in']
    assert st['source'] == 'secret' and st['config_error'] == ''
    assert st['enterprise_app']['ok'] and st['enterprise_app']['enterprise'] == 'my-ent'
    by_org = {o['org']: o for o in st['orgs']}
    assert list(by_org) == ['acme', 'globex', 'hooli', 'initech']
    assert by_org['acme']['ok'] and by_org['acme']['user'] == 'lde-reader[bot]'
    assert by_org['acme']['install_url'] == 'https://github.com/apps/lde-reader/installations/new'
    assert by_org['globex']['auth'] == 'pat' and by_org['globex']['token_hint'] == 'gith…'
    assert by_org['initech']['ok'] and not by_org['initech']['scan']
    assert not by_org['hooli']['ok']
    assert 'deprecated' in st['notice'] and 'globex' in st['notice']
    dumped = json.dumps(st)
    for secret in ('ghs_inst', 'ghs_e', 'not-a-real-key', 'github_pat_secret'):
        assert secret not in dumped


def test_auth_status_flags_uninstalled_org(fake_github):
    fake_github.routes[('GET', '/app')] = {'slug': 'lde-reader', 'name': 'LDE Reader'}
    with _secret(initech=_app()):
        st = gh_auth.auth_status()
    assert st['mode'] == 'app' and not st['logged_in']
    [org] = st['orgs']
    assert org['org'] == 'initech' and not org['ok'] and 'not installed' in org['message']


def test_org_with_none_and_scan_off_does_not_fail_the_login(fake_github):
    _install(fake_github, 'acme')
    fake_github.routes[('GET', '/app')] = {'slug': 'lde-reader', 'name': 'LDE Reader'}
    with _secret(acme=_app(), later={'auth': 'none', 'scan': False}):
        assert gh_auth.auth_status()['logged_in']
    with _secret(acme=_app(), later={'auth': 'none', 'scan': True}):
        assert not gh_auth.auth_status()['logged_in']


def test_auth_status_reports_broken_config_without_raising():
    with _cfg(github={'orgs': {'acme': {'auth': 'pat'}}}):
        st = gh_auth.auth_status()
    assert st['installed'] and not st['logged_in'] and st['orgs'] == []
    assert 'needs a token' in st['config_error']


def test_auth_status_config_error_names_the_aws_secret(monkeypatch):
    monkeypatch.setenv('LDE_SECRETS_SOURCE', 'aws')
    with _cfg(github_secret_error='lde/github is not valid JSON.'):
        st = gh_auth.auth_status()
    assert st['config_error'] and st['source'] == 'secret'


def test_auth_status_config_error_locally_names_the_file(monkeypatch):
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    with _cfg(github={'orgs': {'acme': {'auth': 'pat'}}}):
        st = gh_auth.auth_status()
    assert st['config_error'] and st['source'] == 'file'


def test_auth_status_with_nothing_configured():
    with _cfg():
        st = gh_auth.auth_status()
    assert not st['installed'] and st['source'] == 'none' and 'Create app for' in st['raw']


# ---- settings and secrets ----------------------------------------------------

def test_masked_drops_the_org_map_and_its_secret_copy():
    out = settings_mod.masked({'github': {'orgs': {'a': {'auth': 'app', 'app_id': '1',
                                                         'private_key_path': '/k'}}},
                               'github_secret': {'orgs': {}}, 'github_secret_error': 'x', 'x': 1})
    assert out == {'x': 1}


def test_save_never_persists_secret_manager_values(tmp_path):
    f = tmp_path / 's.json'
    f.write_text('{}')
    real_load = settings_mod.load_settings

    def load_with_overlay():
        cfg = real_load()
        cfg['github_secret'] = {'orgs': {'a': {'auth': 'app', 'app_id': '1',
                                               'private_key': FAKE_PEM}}}
        return cfg

    with patch.object(settings_mod, 'SETTINGS_PATH', str(f)), \
            patch.object(settings_mod, 'load_settings', load_with_overlay):
        settings_mod.save_settings({'dtrack_url': 'u'})
    stored = json.loads(f.read_text())
    assert 'github_secret' not in stored and 'not-a-real-key' not in f.read_text()


@pytest.mark.parametrize('key', ['github', 'github_pats', 'default_orgs', 'github_secret',
                                 'github_app_private_key_path', 'github_app_id'])
def test_put_settings_rejects_github_and_key_fields(key, monkeypatch):
    import server
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    handler = MagicMock()
    handler._read_body = lambda: {key: '/etc/passwd'}
    with patch.object(settings_mod, 'save_settings') as save, pytest.raises(ValueError):
        server.Handler.handle_put_settings(handler, groups=(), qs={})
    save.assert_not_called()


def test_secret_overlay_parses_github_map():
    assert secrets_loader._parse_github('REPLACE_ME') == {}
    assert secrets_loader._parse_github(None) == {}
    assert secrets_loader._parse_github('{"orgs": {}}') == {'github_secret': {'orgs': {}}}
    assert 'github_secret_error' in secrets_loader._parse_github('[1]')
    assert 'github_secret_error' in secrets_loader._parse_github('not json')


def test_unreadable_github_secret_fails_closed(monkeypatch):
    monkeypatch.setattr(secrets_loader, '_ENABLED', True)

    def fetch(name):
        if name == 'lde/github':
            raise OSError('timed out')
        return 'REPLACE_ME' if name != 'lde/github-pat' else '{"acme": "github_pat_x"}'
    monkeypatch.setattr(secrets_loader, '_cached_fetch', fetch)
    cfg = secrets_loader.overlay({})
    assert 'github_secret_error' in cfg
    with patch.object(settings_mod, 'load_settings', return_value=cfg), \
            pytest.raises(github_client.GhError, match='Could not read the lde/github secret'):
        github_client._credential('acme')


def test_pat_placeholder_secret_is_quietly_empty():
    assert secrets_loader._parse_pats('REPLACE_ME') == {}


def test_caches_are_per_app(fake_github):
    _install(fake_github, 'acme', 7, 'ghs_a')
    a1 = gh_config.load_app({'app_id': '1', 'private_key': FAKE_PEM})
    a2 = gh_config.load_app({'app_id': '2', 'private_key': FAKE_PEM})
    assert gh_app.installation_token(a1, 'acme') == 'ghs_a'
    fake_github.routes[('POST', '/app/installations/7/access_tokens')] = _token_doc('ghs_b')
    assert gh_app.installation_token(a2, 'acme') == 'ghs_b'   # not app 1's cached token
    assert gh_app.installation_token(a1, 'acme') == 'ghs_a'
