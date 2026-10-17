"""Settings persisted to .settings.json alongside the server."""

import json
import os

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(SERVE_DIR, '.settings.json')

ALLOWED_KEYS = {
    'default_orgs',
    'github_pat',
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

SENSITIVE_KEYS = {'github_pat', 'dtrack_api_key', 'gemini_api_key', 'basic_auth_credentials'}

DEFAULTS = {
    'default_orgs': [],
    'github_pat': '',
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
        if env_val is not None:
            merged[key] = env_val
    return merged


def save_settings(updates):
    current = load_settings()
    for k, v in updates.items():
        if k in ALLOWED_KEYS:
            current[k] = v
    with open(SETTINGS_PATH, 'w') as f:
        json.dump(current, f, indent=2)
    os.chmod(SETTINGS_PATH, 0o600)
    return current


def masked(settings):
    out = dict(settings)
    for k in SENSITIVE_KEYS:
        val = out.get(k)
        if val is None:
            continue
        if isinstance(val, str):
            out[k] = val[:4] + '…' if len(val) > 4 else '…'
        else:
            # Non-string sensitive values (e.g. basic_auth_credentials dict)
            # cannot be safely truncated — omit them entirely.
            del out[k]
    return out
