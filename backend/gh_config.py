"""The GitHub org map: which orgs LDE knows, how each one authenticates, which are scanned.

Shape (docs/github-app.md)::

    {
      "orgs": {
        "acme":    {"auth": "app", "scan": true, "app_id": "123",
                    "private_key_path": "~/.lde/github-app-123.pem"},
        "globex":  {"auth": "pat", "scan": true, "token": "github_pat_..."},
        "initech": {"auth": "enterprise", "scan": false},
        "hooli":   {"auth": "none", "scan": false}
      },
      "enterprise_app": {"enterprise": "my-enterprise", "app_id": "456",
                         "private_key_path": "~/.lde/github-enterprise-app.pem"}
    }

Every org names exactly one way to authenticate. There is no catch-all entry
and no fallback from one kind to another: an org that is missing, or whose
credential fails, is an error.

Where the map lives:

- AWS (``LDE_SECRETS_SOURCE=aws``): the ``lde/github`` secret, overlaid as the
  hidden settings key ``github_secret``. Private keys are inline
  (``private_key``); key paths are refused.
- Locally: the ``github`` key in ``.settings.json``. Keys are files
  (``private_key_path``, owner-only); an inline ``private_key`` is refused, so
  a key never sits in the settings file.
- Neither set: the map is derived, in memory and without network calls, from
  the old keys ``default_orgs`` and ``github_pats`` (on AWS, the
  ``lde/github-pat`` secret). The first write through ``update()`` stores the
  derived map in the new place.

Validation is strict and fails closed: unknown fields, bad names, a missing
token or App ID all raise ConfigError, and every GitHub call then fails.

``update()`` is the only writer. Tokens and keys are never logged and never
returned by ``public_view()``.
"""

import copy
import json
import os
import re
import threading

from . import gh_app, log as log_mod, secrets_loader, settings as settings_mod

logger = log_mod.get('gh_config')

AUTH_KINDS = ('app', 'enterprise', 'pat', 'none')
SECRET_NAME = 'lde/github'

# GitHub org and user names: letters, digits and single hyphens, at most 39.
_ORG_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,38})$')
_ENTERPRISE_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,59})$')
_APP_ID_RE = re.compile(r'^[0-9]{1,20}$')
# Printable ASCII, no spaces: every GitHub token format fits.
_TOKEN_RE = re.compile(r'^[\x21-\x7e]{1,255}$')
_MASK_SUFFIX = '…'
_MAX_ORGS = 500
# AWS Secrets Manager caps a secret at 65,536 bytes; keep headroom. An inline
# RSA-2048 key is about 1.7 KB once JSON-escaped, so this is roughly 35 app orgs.
_SECRET_LIMIT = 60_000
_APP_ROOM = 4096  # room a new app entry needs, checked before GitHub creates the app
_MAX_KEY = 16 * 1024
_MAX_PATH = 4096

_ORG_FIELDS = {
    'app': {'auth', 'scan', 'app_id', 'private_key_path', 'private_key'},
    'enterprise': {'auth', 'scan'},
    'pat': {'auth', 'scan', 'token'},
    'none': {'auth', 'scan'},
}
_ENTERPRISE_FIELDS = {'enterprise', 'app_id', 'private_key_path', 'private_key'}

# Old settings keys the derived map is built from. A local write removes them
# from .settings.json once the map is stored under "github".
LEGACY_FILE_KEYS = ('default_orgs', 'github_pats')

STAR_PAT_NOTICE = ('The "*" GitHub PAT is no longer supported and is ignored. Add each org '
                   'under Settings with its own GitHub App or fine-grained PAT.')


class ConfigError(RuntimeError):
    """The org map is unusable. The message is safe to show users (no tokens or keys)."""


class AppExists(RuntimeError):
    """The org already authenticates with its own GitHub App."""


def _aws():
    return os.environ.get('LDE_SECRETS_SOURCE', '').lower() == 'aws'


def normalize_org(org):
    """Return *org* lower-cased; ValueError unless it is a GitHub org or user name."""
    if not isinstance(org, str) or not _ORG_RE.match(org.strip().lower()):
        raise ValueError('org must be a GitHub organization or user name '
                         '(letters, digits and hyphens, at most 39)')
    return org.strip().lower()


# ---- validation ----------------------------------------------------------------

def _app_id(value, where):
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not _APP_ID_RE.match(value.strip()):
        raise ConfigError(f'{where}: app_id must be the numeric App ID shown on the app\'s '
                          'GitHub settings page.')
    return value.strip()


def _key_fields(raw, where, *, path_ok, inline_ok):
    """Return the one validated key field of an app entry as {field: value}."""
    path, inline = raw.get('private_key_path'), raw.get('private_key')
    if path is not None and inline is not None:
        raise ConfigError(f'{where}: set private_key_path or private_key, not both.')
    if inline is not None:
        if not inline_ok:
            raise ConfigError(f'{where}: an inline private_key is not allowed here. Save the PEM '
                              'file with chmod 600 and set private_key_path instead.')
        if not isinstance(inline, str) or '-----BEGIN' not in inline or len(inline) > _MAX_KEY:
            raise ConfigError(f'{where}: private_key must be the PEM file GitHub generated.')
        return {'private_key': inline}
    if path is not None:
        if not path_ok:
            raise ConfigError(f'{where}: private_key_path is not allowed in the {SECRET_NAME} '
                              'secret. Put the PEM in private_key.')
        if not isinstance(path, str) or not path.strip() or len(path) > _MAX_PATH:
            raise ConfigError(f'{where}: private_key_path must name the app\'s PEM file.')
        return {'private_key_path': path.strip()}
    raise ConfigError(f'{where}: no private key. Set '
                      f'{"private_key_path" if path_ok else "private_key"}.')


def _org_entry(org, raw, *, path_ok, inline_ok):
    where = f'GitHub org {org}'
    if not isinstance(raw, dict):
        raise ConfigError(f'{where} must be a JSON object.')
    auth = raw.get('auth')
    if auth not in AUTH_KINDS:
        raise ConfigError(f'{where}: auth must be one of {", ".join(AUTH_KINDS)}.')
    unknown = set(raw) - _ORG_FIELDS[auth]
    if unknown:
        raise ConfigError(f'{where}: unknown fields for auth "{auth}": {", ".join(sorted(unknown))}.')
    scan = raw.get('scan', True)
    if not isinstance(scan, bool):
        raise ConfigError(f'{where}: scan must be true or false.')
    entry = {'auth': auth, 'scan': scan}
    if auth == 'app':
        entry['app_id'] = _app_id(raw.get('app_id'), where)
        entry.update(_key_fields(raw, where, path_ok=path_ok, inline_ok=inline_ok))
    elif auth == 'pat':
        token = raw.get('token')
        if not isinstance(token, str) or not _TOKEN_RE.match(token.strip()):
            raise ConfigError(f'{where}: auth "pat" needs a token (printable, no spaces).')
        entry['token'] = token.strip()
    return entry


def _enterprise_entry(raw, *, path_ok, inline_ok):
    where = 'enterprise_app'
    if not isinstance(raw, dict):
        raise ConfigError(f'{where} must be a JSON object.')
    unknown = set(raw) - _ENTERPRISE_FIELDS
    if unknown:
        raise ConfigError(f'{where}: unknown fields: {", ".join(sorted(unknown))}.')
    slug = raw.get('enterprise')
    if not isinstance(slug, str) or not _ENTERPRISE_RE.match(slug.strip().lower()):
        raise ConfigError(f'{where}: enterprise must be the enterprise\'s slug '
                          '(github.com/enterprises/<slug>).')
    entry = {'enterprise': slug.strip().lower(), 'app_id': _app_id(raw.get('app_id'), where)}
    entry.update(_key_fields(raw, where, path_ok=path_ok, inline_ok=inline_ok))
    return entry


def validate(raw, *, path_ok, inline_ok):
    """Return the normalized map ``{'orgs': {...}, 'enterprise_app': {...} or None}``.

    Raises ConfigError for anything LDE would not use exactly as written.
    """
    if not isinstance(raw, dict):
        raise ConfigError('The GitHub config must be a JSON object with an "orgs" map.')
    unknown = set(raw) - {'orgs', 'enterprise_app'}
    if unknown:
        raise ConfigError(f'Unknown GitHub config fields: {", ".join(sorted(unknown))}.')
    orgs_raw = raw.get('orgs', {})
    if not isinstance(orgs_raw, dict):
        raise ConfigError('"orgs" must be a JSON object of {"<org>": {...}}.')
    if len(orgs_raw) > _MAX_ORGS:
        raise ConfigError(f'At most {_MAX_ORGS} GitHub orgs can be configured.')
    ent_raw = raw.get('enterprise_app')
    enterprise = (None if ent_raw is None
                  else _enterprise_entry(ent_raw, path_ok=path_ok, inline_ok=inline_ok))
    orgs = {}
    for name, entry in orgs_raw.items():
        if name == '*':
            raise ConfigError('The "*" org is no longer supported: list each org with its own '
                              'GitHub App or PAT.')
        key = name.strip().lower() if isinstance(name, str) else ''
        if not _ORG_RE.match(key):
            raise ConfigError(f'{str(name)[:40]!r} is not a GitHub org or user name.')
        if key in orgs:
            raise ConfigError(f'GitHub org {key} is listed twice (names are case-insensitive).')
        orgs[key] = _org_entry(key, entry, path_ok=path_ok, inline_ok=inline_ok)
        if orgs[key]['auth'] == 'enterprise' and enterprise is None:
            raise ConfigError(f'GitHub org {key} uses the enterprise app, but no enterprise_app '
                              'is configured.')
    return {'orgs': dict(sorted(orgs.items())), 'enterprise_app': enterprise}


def _dump(conf):
    """The stored form of a normalized map."""
    out = {'orgs': copy.deepcopy(conf['orgs'])}
    if conf.get('enterprise_app'):
        out['enterprise_app'] = dict(conf['enterprise_app'])
    return out


# ---- the old keys ---------------------------------------------------------------

def from_legacy(cfg):
    """Derive ``(raw_map, notices, found)`` from the old keys. Pure: no network, no files.

    Each org in ``default_orgs`` or ``github_pats`` becomes ``auth: pat`` when it
    has a PAT, else ``auth: none``. ``scan`` is true for the orgs in
    ``default_orgs``. The ``"*"`` PAT is dropped.
    """
    notices = []
    default_orgs = cfg.get('default_orgs') or []
    if isinstance(default_orgs, str):  # LDE_DEFAULT_ORGS=acme,globex
        default_orgs = default_orgs.split(',')
    scan = {o.strip().lower() for o in default_orgs if isinstance(o, str) and o.strip()}
    pats = settings_mod.github_tokens(cfg)
    if pats.pop('*', None):
        notices.append(STAR_PAT_NOTICE)
    # The old keys allowed names GitHub does not (dots, slashes): skip them rather than
    # fail every org, and say so.
    bad = sorted(o for o in scan | set(pats) if not _ORG_RE.match(o))
    if bad:
        shown = ', '.join(repr(o[:40]) for o in bad[:5])
        notices.append(f'Ignored old GitHub entries that are not GitHub org names: {shown}.')
    orgs = {}
    for org in sorted((scan | set(pats)) - set(bad)):
        entry = {'auth': 'pat', 'token': pats[org]} if org in pats else {'auth': 'none'}
        entry['scan'] = org in scan
        orgs[org] = entry
    return {'orgs': orgs}, notices, bool(orgs or notices)


def _legacy_present(cfg):
    return bool(cfg.get('default_orgs') or settings_mod.github_tokens(cfg))


# ---- loading ------------------------------------------------------------------

def load(cfg=None):
    """Return the validated map plus ``source`` and ``notices``. Raises ConfigError.

    *source* is ``'secret'`` (lde/github), ``'file'`` (.settings.json "github"),
    ``'legacy'`` (derived from the old keys) or ``'none'``.
    """
    cfg = settings_mod.load_settings() if cfg is None else cfg
    notices = []
    if cfg.get('github_secret_error'):
        raise ConfigError(cfg['github_secret_error'])
    if cfg.get('github_secret') is not None:
        raw, source = cfg['github_secret'], 'secret'
        path_ok, inline_ok = False, True
        if _legacy_present(cfg):
            notices.append('lde/github-pat is no longer read now that lde/github is set. '
                           'Set it back to REPLACE_ME.')
    elif cfg.get('github') is not None and not _aws():
        # On AWS the map is only ever lde/github, the place writes go (_stored_base).
        raw, source = cfg['github'], 'file'
        path_ok, inline_ok = True, False
        if _legacy_present(cfg):
            notices.append(f'.settings.json has both "github" and old GitHub keys '
                           f'({", ".join(k for k in LEGACY_FILE_KEYS if cfg.get(k))}); the old '
                           'keys are ignored. Delete them.')
    else:
        raw, legacy_notices, found = from_legacy(cfg)
        notices.extend(legacy_notices)
        source = 'legacy' if found else 'none'
        path_ok = inline_ok = True
        if found:
            where = f'the {SECRET_NAME} secret' if _aws() else '"github" in .settings.json'
            notices.append('GitHub orgs are read from the old settings (default_orgs and '
                           f'github_pats). Saving any org in Settings moves them into {where}.')
    conf = validate(raw, path_ok=path_ok, inline_ok=inline_ok)
    conf['source'] = source
    conf['notices'] = notices
    return conf


def scan_orgs(conf):
    """The orgs a run scans when none are given."""
    return [org for org, e in conf['orgs'].items() if e['scan']]


def app_for(conf, org):
    """Return the ``{'app_id', 'pem', 'source'}`` app that *org* authenticates with.

    Raises ValueError when *org* does not use an app, gh_app.AppConfigError
    when its key cannot be read.
    """
    entry = conf['orgs'].get(org)
    if not entry or entry['auth'] not in ('app', 'enterprise'):
        raise ValueError(f'{org} does not authenticate with a GitHub App')
    src = entry if entry['auth'] == 'app' else conf['enterprise_app']
    return load_app(src)


def load_app(src):
    """Read the key of an app entry; return ``{'app_id', 'pem', 'source'}``."""
    if 'private_key' in src:
        return {'app_id': src['app_id'], 'pem': src['private_key'].encode('utf-8'),
                'source': 'secrets_manager'}
    return {'app_id': src['app_id'], 'pem': gh_app._read_key_file(src['private_key_path']),
            'source': 'file'}


def token_hint(token):
    return token[:4] + _MASK_SUFFIX if len(token) > 4 else _MASK_SUFFIX


# ---- writing ------------------------------------------------------------------

_write_lock = threading.Lock()


def _unset(value):
    return value is None or not value.strip() or value.strip() == secrets_loader._PLACEHOLDER


def _stored_base():
    """Return ``(raw, path_ok, inline_ok)``: the map as stored now, else derived from the old keys.

    Everything a write builds on is read fresh, and any read failure raises: a
    write never stores a map that silently lost orgs because a read failed.
    """
    if _aws():
        value = secrets_loader.get_secret_fresh(SECRET_NAME)
        if not _unset(value):
            try:
                return json.loads(value), False, True
            except ValueError:
                raise ConfigError(f'{SECRET_NAME} is not valid JSON. Fix it or set it back to '
                                  'REPLACE_ME.') from None
        cfg = dict(settings_mod.load_settings())
        pats = secrets_loader.get_secret_fresh('lde/github-pat')
        cfg['github_pats'] = {} if _unset(pats) else secrets_loader._parse_pats(pats)
        if not _unset(pats) and not cfg['github_pats']:
            raise ConfigError('lde/github-pat cannot be read as {"<org>": "<token>"}, so LDE '
                              'will not move it into lde/github. Fix it or set it to REPLACE_ME.')
        return from_legacy(cfg)[0], False, True
    cfg = settings_mod.load_settings()
    if cfg.get('github') is not None:
        return cfg['github'], True, False
    return from_legacy(cfg)[0], True, False


def check_room_for_app(conf):
    """ConfigError when lde/github has no room for one more inline app key (AWS only).

    Called before sending anyone to GitHub, so a full secret does not leave an
    app on GitHub that LDE cannot store.
    """
    if not _aws():
        return
    size = len(json.dumps(_dump(conf)).encode('utf-8'))
    if size + _APP_ROOM > _SECRET_LIMIT:
        raise ConfigError(f'{SECRET_NAME} has no room for another app key (64 KB limit). Use '
                          'the enterprise app for more orgs, or remove orgs you no longer scan.')


def key_field():
    """The key field a newly created app is stored with here."""
    return 'private_key' if _aws() else 'private_key_path'


def update(mutate):
    """Apply ``mutate(map)`` to the stored map, validate it and write it back.

    *mutate* gets the normalized stored form (lower-case org keys) and edits it
    in place; anything it raises propagates and nothing is written. Locally the
    map goes to "github" in .settings.json and the old GitHub keys are removed
    from the file; on AWS it is written to the lde/github secret.
    Returns the new normalized map.
    """
    with _write_lock:
        raw, path_ok, inline_ok = _stored_base()
        current = _dump(validate(raw, path_ok=path_ok, inline_ok=inline_ok))
        mutate(current)
        new = validate(current, path_ok=path_ok, inline_ok=inline_ok)
        out = _dump(new)
        if _aws():
            body = json.dumps(out)
            if len(body.encode('utf-8')) > _SECRET_LIMIT:
                raise ConfigError(f'The GitHub config would exceed the {SECRET_NAME} size limit '
                                  '(64 KB). Use the enterprise app for some orgs, or remove '
                                  'orgs you no longer scan.')
            secrets_loader.put_secret(SECRET_NAME, body)
        else:
            settings_mod.save_settings({'github': out}, remove=LEGACY_FILE_KEYS)
        gh_app.reset_caches()
    return new


def set_org(org, auth=None, scan=None, token=None):
    """Add or change one org from the API. Returns its public view.

    *auth* ``'app'`` is accepted only when the org already has its app (to
    change ``scan``): apps are created through the manifest flow, and keys
    never come over HTTP. A *token* ending in the mask character, or empty,
    keeps the saved one.
    """
    org = normalize_org(org)
    if auth is not None and auth not in AUTH_KINDS:
        raise ValueError(f'auth must be one of {", ".join(AUTH_KINDS)}')
    if scan is not None and not isinstance(scan, bool):
        raise ValueError('scan must be true or false')
    if token is not None and not isinstance(token, str):
        raise ValueError('token must be a string')
    token = (token or '').strip()
    if token.endswith(_MASK_SUFFIX):
        token = ''
    if token and not _TOKEN_RE.match(token):
        raise ValueError('token must be printable with no spaces')

    def mutate(m):
        orgs = m['orgs']
        cur = orgs.get(org)
        new_auth = auth or (cur['auth'] if cur else 'none')
        if new_auth == 'app' and (not cur or cur['auth'] != 'app'):
            raise ValueError(f'Create the app with "Create app for {org}" in Settings; an app '
                             'and its key are never set through the API')
        if new_auth == 'enterprise' and not m.get('enterprise_app'):
            raise ValueError('No enterprise app is configured. Add enterprise_app by hand '
                             '(docs/github-app.md)')
        if token and new_auth != 'pat':
            raise ValueError('token is only used with auth "pat"')
        entry = {'auth': new_auth,
                 'scan': scan if scan is not None else (cur['scan'] if cur else True)}
        if new_auth == 'app':
            entry.update({k: v for k, v in cur.items() if k not in ('auth', 'scan')})
        elif new_auth == 'pat':
            kept = cur.get('token') if cur and cur['auth'] == 'pat' else ''
            if not (token or kept):
                raise ValueError(f'auth "pat" needs a token for {org}')
            entry['token'] = token or kept
        orgs[org] = entry

    conf = update(mutate)
    if auth == 'pat' or (auth is None and conf['orgs'][org]['auth'] == 'pat'):
        logger.info('saved a GitHub PAT for %s', org)
    return public_org(org, conf['orgs'][org])


def remove_org(org):
    """Remove *org* from the map. Returns False when it was not there."""
    org = normalize_org(org)
    found = []

    def mutate(m):
        if m['orgs'].pop(org, None) is not None:
            found.append(org)

    update(mutate)
    return bool(found)


def store_app(owner, app_id, key_value):
    """Point *owner* at its newly created app (manifest flow). AppExists when it already has one.

    *key_value* is the key file path locally and the PEM on AWS (see key_field()).
    """
    owner = normalize_org(owner)

    def mutate(m):
        cur = m['orgs'].get(owner)
        if cur and cur['auth'] == 'app':
            raise AppExists(f'{owner} already has a GitHub App in LDE')
        m['orgs'][owner] = {'auth': 'app', 'scan': cur['scan'] if cur else True,
                            'app_id': str(app_id), key_field(): key_value}

    update(mutate)


# ---- public view ------------------------------------------------------------------

def public_org(org, entry):
    """An org entry without its token, key or key path."""
    out = {'org': org, 'auth': entry['auth'], 'scan': entry['scan']}
    if entry['auth'] == 'app':
        out['app_id'] = entry['app_id']
    if entry['auth'] == 'pat':
        out['token_hint'] = token_hint(entry['token'])
    return out
