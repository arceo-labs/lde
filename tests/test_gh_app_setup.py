"""GitHub App manifest flow: start, callback, key storage, refusal when an app exists."""

import json
import os
import stat
import sys
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import gh_app, gh_app_setup, gh_auth, secrets_loader, settings as settings_mod  # noqa: E402

ORIGIN = 'http://localhost:8002'


def _pem(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


PEM = _pem()


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    """Empty settings file, key dir under tmp, local mode, no pending states."""
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    for k in ('LDE_GITHUB_APP_ID', 'LDE_GITHUB_APP_PRIVATE_KEY_PATH'):
        monkeypatch.delenv(k, raising=False)
    sfile = tmp_path / 'settings.json'
    sfile.write_text('{}')
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(sfile))
    monkeypatch.setattr(gh_app_setup, '_KEY_DIR', str(tmp_path / 'lde'))
    gh_app_setup._pending.clear()
    gh_app.reset_caches()
    yield tmp_path
    gh_app_setup._pending.clear()
    gh_app.reset_caches()


@pytest.fixture
def github(monkeypatch):
    """Fake the conversion call. Set .doc or .error; .calls records (method, path, bearer)."""
    fake = MagicMock()
    fake.doc = {'id': 4242, 'slug': 'lde-abc123', 'name': 'LDE abc123', 'pem': PEM,
                'owner': {'login': 'Acme'},
                'client_id': 'Iv1.x', 'client_secret': 'CLIENT-SECRET',
                'webhook_secret': 'HOOK-SECRET'}
    fake.error = None
    fake.calls = []

    def call(method, path, bearer, body=None):
        fake.calls.append((method, path, bearer))
        if fake.error:
            raise fake.error
        return fake.doc

    monkeypatch.setattr(gh_app, '_call', call)
    return fake


def _start(**kw):
    return gh_app_setup.start(ORIGIN, **kw)


# ---- start ------------------------------------------------------------------

def test_manifest_is_read_only_with_no_webhook():
    r = _start(name='LDE test')
    m = json.loads(r['manifest'])
    assert m['default_permissions'] == {'contents': 'read', 'metadata': 'read'}
    assert m['default_events'] == []
    # GitHub rejects an unreachable (localhost) hook URL even when inactive: send none.
    assert 'hook_attributes' not in m
    assert m['redirect_url'] == ORIGIN + '/api/gh-app/callback'
    assert m['setup_url'] == ORIGIN + '/settings'
    assert m['public'] is False and m['name'] == 'LDE test'
    assert r['action'] == f'https://github.com/settings/apps/new?state={r["state"]}'


def test_org_owner_posts_to_the_org_and_app_is_private():
    r = _start(org='acme-corp')
    assert r['action'].startswith('https://github.com/organizations/acme-corp/settings/apps/new?state=')
    assert json.loads(r['manifest'])['public'] is False


def test_blank_name_gets_a_random_one():
    assert json.loads(_start()['manifest'])['name'].startswith('LDE ')


@pytest.mark.parametrize('kw', [
    {'org': '../evil'}, {'org': 'a b'}, {'org': ['x']}, {'org': 'a' * 40},
    {'name': '<script>'}, {'name': 'x' * 35}, {'name': 5},
])
def test_bad_input_is_rejected(kw):
    with pytest.raises(ValueError):
        _start(**kw)


def test_start_refused_for_an_org_that_already_has_an_app(monkeypatch):
    # The single-app config has no owner: LDE asks GitHub who owns it.
    monkeypatch.setattr(gh_app, 'app_identity',
                        lambda cfg: {'slug': 's', 'name': 'n', 'owner': 'Acme'})
    cfg = {'github_app_id': '1', 'github_app_private_key': PEM}
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.start(ORIGIN, org='acme', cfg=cfg)
    assert exc.value.reason == 'exists'
    # Another org can still get its own app.
    assert 'organizations/globex/' in gh_app_setup.start(ORIGIN, org='globex', cfg=cfg)['action']


def test_start_refused_when_app_config_is_broken():
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.start(ORIGIN, cfg={'github_app_id': '1'})
    assert exc.value.reason == 'config'


def test_start_refused_without_cryptography(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name.startswith('cryptography'):
            raise ImportError(name)
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, '__import__', fake_import)
    with pytest.raises(ValueError, match='cryptography'):
        _start()
    assert gh_app_setup._pending == {}


def test_pending_states_are_capped():
    for _ in range(gh_app_setup._MAX_PENDING + 5):
        _start()
    assert len(gh_app_setup._pending) == gh_app_setup._MAX_PENDING


# ---- complete ---------------------------------------------------------------

def test_complete_stores_key_file_and_settings(env, github):
    state = _start()['state']
    app = gh_app_setup.complete('abc123code', state)
    assert app == {'slug': 'lde-abc123', 'name': 'LDE abc123', 'app_id': '4242', 'owner': 'acme'}
    assert github.calls == [('POST', '/app-manifests/abc123code/conversions', None)]

    key_file = env / 'lde' / 'github-app-4242.pem'
    assert key_file.read_text() == PEM
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    stored = json.loads((env / 'settings.json').read_text())
    [entry] = stored['github_apps']
    assert entry['owner'] == 'acme' and entry['app_id'] == '4242'
    assert os.path.realpath(entry['private_key_path']) == os.path.realpath(key_file)
    dumped = (env / 'settings.json').read_text()
    assert 'CLIENT-SECRET' not in dumped and 'HOOK-SECRET' not in dumped and 'PRIVATE KEY' not in dumped
    # The stored config is usable as-is.
    [cfg] = gh_app.app_configs(settings_mod.load_settings())
    assert cfg['app_id'] == '4242' and cfg['source'] == 'file' and cfg['owner'] == 'acme'


def test_state_is_single_use(github):
    state = _start()['state']
    gh_app_setup.complete('code1', state)
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code2', state)
    assert exc.value.reason == 'state'
    assert len(github.calls) == 1


@pytest.mark.parametrize('state', ['', 'forged', None])
def test_unknown_state_is_refused_before_any_call(github, state):
    _start()
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', state)
    assert exc.value.reason == 'state' and github.calls == []


def test_expired_state_is_refused(github, monkeypatch):
    state = _start()['state']
    gh_app_setup._pending[state] = (0, '')  # monotonic time long past
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', state)
    assert exc.value.reason == 'state' and github.calls == []


@pytest.mark.parametrize('code', ['', 'a/b', '../x', 'a' * 129, None])
def test_malformed_code_is_refused_before_any_call(github, code):
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete(code, _start()['state'])
    assert exc.value.reason == 'exchange' and github.calls == []


def test_conversion_error_does_not_echo_the_code(github):
    github.error = gh_app.AppAuthError('GitHub API 404 for POST /app-manifests/SECRETCODE/conversions',
                                       status=404)
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('SECRETCODE', _start()['state'])
    assert exc.value.reason == 'exchange'
    assert 'SECRETCODE' not in str(exc.value) and 'HTTP 404' in str(exc.value)


@pytest.mark.parametrize('field,value', [
    ('id', None), ('id', True), ('id', '12'), ('slug', '../x'), ('pem', None), ('pem', 'nope'),
    ('owner', None), ('owner', {'login': '../x'}),
])
def test_bad_conversion_reply_stores_nothing(env, github, field, value):
    github.doc = dict(github.doc, **{field: value})
    with pytest.raises(gh_app_setup.SetupError):
        gh_app_setup.complete('code', _start()['state'])
    assert not (env / 'lde').exists() or not list((env / 'lde').iterdir())
    assert json.loads((env / 'settings.json').read_text()) == {}


def test_short_key_from_github_is_refused(env, github):
    github.doc = dict(github.doc, pem=_pem(1024))
    with pytest.raises(gh_app_setup.SetupError):
        gh_app_setup.complete('code', _start()['state'])
    assert json.loads((env / 'settings.json').read_text()) == {}


def _key_file(env, name='other.pem'):
    path = env / name
    path.write_text(PEM)
    path.chmod(0o600)
    return str(path)


def test_callback_refused_if_the_org_got_an_app_meanwhile(env, github):
    state = _start(org='acme')['state']
    (env / 'settings.json').write_text(json.dumps({'github_apps': [
        {'owner': 'acme', 'app_id': '7', 'private_key_path': _key_file(env)}]}))
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', state)
    assert exc.value.reason == 'exists' and github.calls == []


def test_callback_refused_if_github_reports_an_owner_that_has_an_app(env, github):
    # Personal-account start: the owner is only known from GitHub's reply.
    state = _start()['state']
    (env / 'settings.json').write_text(json.dumps({'github_apps': [
        {'owner': 'acme', 'app_id': '7', 'private_key_path': _key_file(env)}]}))
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', state)
    assert exc.value.reason == 'exists'
    assert len(json.loads((env / 'settings.json').read_text())['github_apps']) == 1


def test_second_org_gets_its_own_app(env, github):
    (env / 'settings.json').write_text(json.dumps({'github_apps': [
        {'owner': 'globex', 'app_id': '7', 'private_key_path': _key_file(env)}]}))
    gh_app_setup.complete('code', _start(org='acme')['state'])
    apps = json.loads((env / 'settings.json').read_text())['github_apps']
    assert [(a['owner'], a['app_id']) for a in apps] == [('globex', '7'), ('acme', '4242')]
    assert [a['owner'] for a in gh_app.app_configs(settings_mod.load_settings())] == ['globex', 'acme']


def test_owner_other_than_the_requested_org_is_refused(env, github):
    github.doc = dict(github.doc, owner={'login': 'someone-else'})
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', _start(org='acme')['state'])
    assert exc.value.reason == 'exchange' and 'someone-else' in str(exc.value)
    assert json.loads((env / 'settings.json').read_text()) == {}


def test_existing_key_file_is_not_overwritten(env, github):
    (env / 'lde').mkdir()
    existing = env / 'lde' / 'github-app-4242.pem'
    existing.write_text('old')
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', _start()['state'])
    assert exc.value.reason == 'store' and existing.read_text() == 'old'


def test_key_file_symlink_is_not_followed(env, github):
    (env / 'lde').mkdir()
    target = env / 'target'
    (env / 'lde' / 'github-app-4242.pem').symlink_to(target)
    with pytest.raises(gh_app_setup.SetupError):
        gh_app_setup.complete('code', _start()['state'])
    assert not target.exists()


def _aws(monkeypatch, current='REPLACE_ME'):
    monkeypatch.setenv('LDE_SECRETS_SOURCE', 'aws')
    monkeypatch.setattr(settings_mod, 'load_settings', lambda: dict(settings_mod.DEFAULTS))
    monkeypatch.setattr(secrets_loader, 'get_secret_fresh', lambda name: current)
    put = MagicMock()
    monkeypatch.setattr(secrets_loader, 'put_secret', put)
    return put


def test_aws_writes_the_secret_and_not_the_file(env, github, monkeypatch):
    put = _aws(monkeypatch)
    gh_app_setup.complete('code', _start()['state'])
    name, value = put.call_args.args
    assert name == 'lde/github-app'
    assert json.loads(value) == {'apps': [{'owner': 'acme', 'app_id': '4242', 'private_key': PEM}]}
    parsed = secrets_loader._parse_app(value)['github_apps_secret']
    assert [a['owner'] for a in gh_app.app_configs({'github_apps_secret': parsed})] == ['acme']
    assert not (env / 'lde').exists()


def test_aws_appends_and_converts_a_single_app_secret(env, github, monkeypatch):
    monkeypatch.setattr(gh_app, 'app_identity',
                        lambda cfg: {'slug': 's', 'name': 'n', 'owner': 'Globex'})
    put = _aws(monkeypatch, json.dumps({'app_id': '7', 'private_key': PEM}))
    gh_app_setup.complete('code', _start(org='acme')['state'])
    apps = json.loads(put.call_args.args[1])['apps']
    assert [(a['owner'], a['app_id']) for a in apps] == [('globex', '7'), ('acme', '4242')]


def test_aws_unreadable_secret_is_not_overwritten(env, github, monkeypatch):
    put = _aws(monkeypatch, 'garbage')
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', _start()['state'])
    assert exc.value.reason == 'store'
    put.assert_not_called()


def test_aws_write_failure_is_a_store_error(github, monkeypatch):
    _aws(monkeypatch)

    def refuse(name, value):
        raise RuntimeError('AWS Secrets Manager refused the write to lde/github-app (HTTP 400).')
    monkeypatch.setattr(secrets_loader, 'put_secret', refuse)
    with pytest.raises(gh_app_setup.SetupError) as exc:
        gh_app_setup.complete('code', _start()['state'])
    assert exc.value.reason == 'store'


def test_install_url():
    assert gh_app_setup.install_url('lde-abc') == 'https://github.com/apps/lde-abc/installations/new'
    assert gh_app_setup.install_url('../x') == ''
    assert gh_app_setup.install_url('') == ''


# ---- secrets_loader.put_secret ------------------------------------------------

def test_put_secret_only_writes_lde_secrets(monkeypatch):
    monkeypatch.setattr(secrets_loader, '_sm_request', MagicMock())
    with pytest.raises(ValueError):
        secrets_loader.put_secret('prod/other', 'x')
    secrets_loader._sm_request.assert_not_called()


def test_put_secret_signs_put_and_drops_cache(monkeypatch):
    sm = MagicMock(return_value={})
    monkeypatch.setattr(secrets_loader, '_sm_request', sm)
    secrets_loader._cache['lde/github-app'] = (0, 'old')
    secrets_loader.put_secret('lde/github-app', 'new')
    sm.assert_called_once_with('PutSecretValue', {'SecretId': 'lde/github-app', 'SecretString': 'new'})
    assert 'lde/github-app' not in secrets_loader._cache


def test_put_secret_http_error_names_the_permission_not_the_value(monkeypatch):
    import io
    import urllib.error

    def deny(target, body):
        raise urllib.error.HTTPError('u', 400, 'denied', {}, io.BytesIO(b'body'))
    monkeypatch.setattr(secrets_loader, '_sm_request', deny)
    with pytest.raises(RuntimeError) as exc:
        secrets_loader.put_secret('lde/github-app', 'SECRET-VALUE')
    assert 'PutSecretValue' in str(exc.value) and 'SECRET-VALUE' not in str(exc.value)


# ---- server routes ----------------------------------------------------------

def _handler(headers=None, body=None):
    import server
    h = MagicMock()
    h.headers = headers or {}
    h._read_body = lambda: body if body is not None else {}
    h.redirects = []
    h._redirect = h.redirects.append
    return server, h


def test_manifest_route_builds_urls_from_origin_not_host():
    server, h = _handler({'Origin': ORIGIN, 'Host': 'evil.example'}, {'name': 'x'})
    server.Handler.handle_gh_app_manifest(h, (), {})
    status, doc = h._json_response.call_args.args
    assert status == 200
    m = json.loads(doc['manifest'])
    assert m['redirect_url'] == ORIGIN + '/api/gh-app/callback'
    assert 'evil' not in doc['manifest']


@pytest.mark.parametrize('origin', [None, 'https://evil.example', 'null'])
def test_manifest_route_needs_an_allowed_origin(origin):
    server, h = _handler({'Origin': origin} if origin else {}, {})
    with pytest.raises(ValueError):
        server.Handler.handle_gh_app_manifest(h, (), {})
    assert gh_app_setup._pending == {}


@pytest.mark.parametrize('body', [{'redirect_url': 'https://evil.example'}, {'public': True}])
def test_manifest_route_rejects_unknown_fields(body):
    server, h = _handler({'Origin': ORIGIN}, body)
    with pytest.raises(ValueError):
        server.Handler.handle_gh_app_manifest(h, (), {})
    assert gh_app_setup._pending == {}


def test_callback_route_redirects_to_install_page(github):
    state = _start()['state']
    server, h = _handler()
    server.Handler.handle_gh_app_callback(h, (), {'code': ['abc'], 'state': [state]})
    assert h.redirects == ['https://github.com/apps/lde-abc123/installations/new']


def test_callback_route_failure_redirects_with_fixed_reason(github):
    server, h = _handler()
    server.Handler.handle_gh_app_callback(h, (), {'code': ['abc'], 'state': ['forged<script>']})
    assert h.redirects == ['/settings?gh_app_error=state']
    assert github.calls == []


def test_routes_are_registered_and_csp_allows_the_github_form_post():
    import server
    routes = {(m, p) for m, p, _ in server.ROUTES}
    assert ('POST', r'^/api/gh-app/manifest$') in routes
    assert ('GET', r'^/api/gh-app/callback$') in routes
    h = MagicMock()
    sent = {}
    h.send_header = lambda k, v: sent.__setitem__(k, v)
    h.headers = {}
    server.Handler._security_headers(h)
    assert "form-action 'self' https://github.com" in sent['Content-Security-Policy']


def test_gh_status_lists_each_app_with_its_manage_link(monkeypatch):
    monkeypatch.setattr(gh_app, 'app_identity', lambda cfg: {
        'slug': f'lde-{cfg["app_id"]}', 'name': 'x', 'owner': 'Acme' if cfg['app_id'] == '1' else 'x'})
    apps, cfgs, err = gh_auth._apps_status({
        'github_app_id': '1', 'github_app_private_key': PEM,
        'github_apps_secret': [{'owner': 'globex', 'app_id': '2', 'private_key': PEM}]})
    assert err == '' and len(cfgs) == 2
    assert [(a['owner'], a['install_url']) for a in apps] == [
        ('acme', 'https://github.com/apps/lde-1/installations/new'),
        ('globex', 'https://github.com/apps/lde-2/installations/new')]
    assert 'PRIVATE KEY' not in json.dumps(apps)
