"""Settings persisted to .settings.json alongside the server."""

import json
import os
import re

from . import log as log_mod

logger = log_mod.get('settings')

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(SERVE_DIR, '.settings.json')

ALLOWED_KEYS = {
    'default_orgs',
    'github_pats',
    'dtrack_url',
    'dtrack_ui_url',
    'dtrack_api_key',
    'gemini_api_key',
    'gemini_model',
    'ort_image',
    'ort_egress_network',
    'ort_max_workers',
    'run_retention',
    'ort_cache_dir',
    'prelock_enabled',
    'npm_cache_url',
    'npm_cache_probe_url',
    'pypi_cache_url',
    'pypi_cache_probe_url',
    'athens_url',
    'athens_probe_url',
    'enabled_package_managers',
}

SENSITIVE_KEYS = {'github_pats', 'dtrack_api_key', 'gemini_api_key', 'basic_auth_credentials'}

DEFAULTS = {
    'default_orgs': [],
    # GitHub PATs: {"<org-or-user>": "<token>"}. A fine-grained PAT is bound to
    # one resource owner, so reviewing several orgs needs one token each.
    'github_pats': {},
    'dtrack_url': 'http://localhost:8081',
    'dtrack_ui_url': 'http://localhost:8080',
    'dtrack_api_key': '',
    'gemini_api_key': '',
    'gemini_model': 'gemini-3.8-flash',
    'ort_image': 'ghcr.io/oss-review-toolkit/ort:latest',
    'ort_egress_network': 'ort-egress',
    'ort_max_workers': 4,
    # How many recent sandbox dirs to keep under /tmp/dummy-repos/. Each
    # sandbox can be a few hundred MB even after node_modules are purged
    # (sanitized manifests + analyzer-result.json + the CycloneDX BOM).
    # Lowered from 10 → 3 after a real-world run filled the disk.
    'run_retention': 3,
    'ort_cache_dir': os.path.join(SERVE_DIR, '.cache'),
    'prelock_enabled': True,
    # Set to '' (empty) to disable the npm-cache HTTP proxy and have ORT
    # talk to registry.npmjs.org directly. Default points at the
    # compose-managed service on the ort-egress network — that's the
    # hostname ORT/prelock containers use.
    'npm_cache_url': 'http://npm-cache:9999',
    # Host-reachable equivalent used only for liveness probing from the
    # orchestrator (which lives on the host, not on ort-egress, so it
    # can't resolve the docker-internal service name).
    'npm_cache_probe_url': 'http://127.0.0.1:9999',
    # PyPI cache — same model as npm-cache. The /simple/ suffix is
    # required because pip's PIP_INDEX_URL points at the simple-index
    # endpoint, not the proxy root. Set to '' to disable.
    'pypi_cache_url': 'http://pypi-cache:9998/simple/',
    'pypi_cache_probe_url': 'http://127.0.0.1:9998',
    # Athens Go module proxy — caches proxy.golang.org responses AND
    # handles the VCS-fallback case server-side, which is what stock
    # `go list -m all` can't do reliably through the corporate proxy. Set to '' to
    # disable (Go falls back to its default GOPROXY=proxy.golang.org,direct).
    'athens_url': 'http://athens:3000',
    'athens_probe_url': 'http://127.0.0.1:3000',
    # ORT package managers to enable. Pass-through to
    # `-Port.analyzer.enabledPackageManagers=...`. Remove "GoMod" to
    # skip Go entirely (analyses can take 15-25 min per repo on cold
    # cache). Same for Maven/Gradle if Java analyses are slow.
    'enabled_package_managers': [
        'NPM', 'Yarn', 'PIP', 'Pipenv', 'Poetry', 'GoMod', 'Maven', 'Gradle',
    ],
}


LEGACY_PAT_NOTICE = ('"github_pat" is no longer used. Move the token into '
                     '"github_pats": {"<org>": "<token>"} in .settings.json (or add it per org '
                     'in Settings; use "*" for a token that covers every other org), then '
                     'delete "github_pat".')
_legacy_logged = False


def legacy_pat_notice():
    """Return LEGACY_PAT_NOTICE when an old ``github_pat`` is still configured, else ''.

    Checks the settings file and the LDE_GITHUB_PAT env var. Reads only the key
    names, never the values. The notice is logged once per process.
    """
    global _legacy_logged
    present = bool(os.environ.get('LDE_GITHUB_PAT'))
    if not present and os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r') as f:
                present = 'github_pat' in json.load(f)
        except (OSError, ValueError):
            present = False
    if present and not _legacy_logged:
        _legacy_logged = True
        logger.warning(LEGACY_PAT_NOTICE)
    return LEGACY_PAT_NOTICE if present else ''


# Org names that ship in .settings.json.example. Reviewing one of these is almost
# certainly a copied example config, and a "*" token would send it to GitHub.
PLACEHOLDER_ORGS = frozenset({
    'example-org', 'example-org-hris', 'example-org-test', 'another-org', 'example-website',
})


def placeholder_orgs(orgs):
    """Return the entries of *orgs* that are example placeholders (case-insensitive, de-duplicated)."""
    seen, found = set(), []
    for org in orgs:
        key = org.lower() if isinstance(org, str) else ''
        if key in PLACEHOLDER_ORGS and key not in seen:
            seen.add(key)
            found.append(org)
    return found


def github_tokens(cfg):
    """Return {owner: token} from the ``github_pats`` map in *cfg* (owners lower-cased)."""
    pats = {}
    raw = cfg.get('github_pats')
    if isinstance(raw, dict):
        for owner, tok in raw.items():
            if isinstance(owner, str) and isinstance(tok, str) and tok.strip():
                pats[owner.lower()] = tok.strip()
    return pats


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        with open(SETTINGS_PATH, 'r') as f:
            stored = json.load(f)
    else:
        stored = {}
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in stored.items() if k in ALLOWED_KEYS})
    # When LDE_SECRETS_SOURCE=aws, overlay values from AWS Secrets Manager.
    from . import secrets_loader
    secrets_loader.overlay(merged)
    # Allow any allowed key to be overridden via LDE_<KEY_UPPER> env var.
    # Useful for non-sensitive config (e.g. LDE_DTRACK_URL) in ECS task defs.
    for key in ALLOWED_KEYS:
        env_val = os.environ.get('LDE_' + key.upper())
        if env_val is None:
            continue
        if key == 'github_pats':
            try:
                env_val = json.loads(env_val)
            except ValueError:
                continue
            if not isinstance(env_val, dict):
                continue
        merged[key] = env_val
    return merged


_PAT_OWNER_RE = re.compile(r'^(\*|[A-Za-z0-9._-]+)$')
_MASK_SUFFIX = '…'


def merge_github_pats(existing, patch):
    """Return *existing* with the per-org *patch* applied.

    Keys are lower-cased org names. An empty value removes the org; a value
    ending in the mask character (what GET /api/settings returns) is ignored
    so a round-tripped form cannot overwrite a real token.
    """
    if not isinstance(patch, dict):
        raise ValueError('github_pats must be a JSON object of {org: token}')
    merged = ({k.lower(): v for k, v in existing.items() if isinstance(k, str)}
              if isinstance(existing, dict) else {})
    for owner, token in patch.items():
        if not isinstance(owner, str) or not _PAT_OWNER_RE.match(owner):
            raise ValueError('github_pats keys must be GitHub org or user names, or *')
        if not isinstance(token, str):
            raise ValueError('github_pats values must be strings')
        token = token.strip()
        key = owner.lower()
        if not token:
            merged.pop(key, None)
        elif not token.endswith(_MASK_SUFFIX):
            merged[key] = token
    return merged


def save_settings(updates):
    current = load_settings()
    for k, v in updates.items():
        if k not in ALLOWED_KEYS:
            continue
        if k == 'github_pats':
            current[k] = merge_github_pats(current.get(k), v)
        else:
            current[k] = v
    # load_settings() drops the retired github_pat. Keep it on disk, untouched, until
    # the user moves it into github_pats and deletes it, so an unrelated save does not
    # destroy the token or the "old config" notice. It never goes into the return value.
    on_disk = dict(current)
    legacy = _stored_legacy_pat()
    if legacy is not None:
        on_disk['github_pat'] = legacy
    with open(SETTINGS_PATH, 'w') as f:
        json.dump(on_disk, f, indent=2)
    os.chmod(SETTINGS_PATH, 0o600)
    return current


def _stored_legacy_pat():
    """Return the raw ``github_pat`` value stored in the settings file, else None."""
    try:
        with open(SETTINGS_PATH, 'r') as f:
            return json.load(f).get('github_pat')
    except (OSError, ValueError, AttributeError):
        return None


def masked(settings):
    out = dict(settings)
    for k in SENSITIVE_KEYS:
        val = out.get(k)
        if val is None:
            continue
        if isinstance(val, str):
            out[k] = val[:4] + '…' if len(val) > 4 else '…'
        elif k == 'github_pats' and isinstance(val, dict):
            out[k] = {o: (t[:4] + '…' if len(t) > 4 else '…') for o, t in val.items()
                      if isinstance(t, str)}
        else:
            # Non-string sensitive values (e.g. basic_auth_credentials dict)
            # cannot be safely truncated — omit them entirely.
            del out[k]
    return out
