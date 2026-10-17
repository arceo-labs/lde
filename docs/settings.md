# Settings reference

All settings are stored in `.settings.json` at the repo root (gitignored). The file is created
automatically on first save. Use `.settings.json.example` as a template.

In production (Fargate with `LDE_SECRETS_SOURCE=aws`), settings are injected at startup from AWS
Secrets Manager and the `PUT /api/settings` endpoint returns `503` — the file is not used.

## How settings are resolved

Each key is resolved in this priority order (highest wins):

1. `LDE_<KEY_UPPER>` environment variable (e.g. `LDE_DTRACK_URL`)
2. AWS Secrets Manager overlay (only when `LDE_SECRETS_SOURCE=aws`)
3. `.settings.json` on disk
4. Built-in default

Sensitive keys (`github_pat`, `dtrack_api_key`, `gemini_api_key`) are truncated to 4 chars + `…`
in all API responses. Their full values are never returned to the browser.

---

## GitHub integration

| Key | Type | Default | Sensitive |
|---|---|---|---|
| `github_pat` | string | `""` | Yes — masked in API responses |
| `default_orgs` | array of strings | `[]` | No |

**`github_pat`** — Fine-grained Personal Access Token for the GitHub API. Required permissions:
Contents: Read-only and Metadata: Read-only. Required in Fargate; optional locally if you are
already authenticated with the `gh` CLI.

In AWS: stored as plain string in `lde/github-pat`.

**`default_orgs`** — Org names pre-filled in the Ingest UI. Does not restrict which orgs can be
scanned — it only sets the default input value.

---

## Dependency-Track integration

| Key | Type | Default | Sensitive |
|---|---|---|---|
| `dtrack_url` | string | `http://localhost:8081` | No |
| `dtrack_ui_url` | string | `http://localhost:8080` | No |
| `dtrack_api_key` | string | `""` | Yes — masked in API responses |

**`dtrack_url`** — Dependency-Track API server URL. Used for all DT API calls (BOM uploads,
component searches, project lookups). In Fargate this points at the DT API container via
AWS Cloud Map (set via the `LDE_DTRACK_URL` env var in the ECS task definition).

**`dtrack_ui_url`** — Dependency-Track frontend URL. Used only for constructing deep links in
the LDE UI. Set this to the public-facing DT hostname in production so links open correctly.
Do not confuse with `dtrack_url` — these are two separate URLs serving different purposes.

**`dtrack_api_key`** — DT API key with sufficient permissions to upload BOMs and query projects.
Obtain it from the DT admin panel after first boot. <!-- updated: DT key test button -->
The Settings page has a **Test DT API key** button that validates the *saved* key against the
*saved* `dtrack_url` (via `GET /api/dtrack-status`) and reports the key's team and granted
permissions — save any change before testing.

In AWS: stored as plain string in `lde/dtrack-api-key`.

---

## Package extraction (Gemini)

Package extraction (`POST /api/extract-packages`) uses the Gemini API to identify npm and PyPI
package names from advisory URLs or uploaded files.

| Key | Type | Default | Sensitive |
|---|---|---|---|
| `gemini_api_key` | string | `""` | Yes — masked in API responses |
| `gemini_model` | string | `gemini-3.8-flash` | No |

**`gemini_api_key`** — Google Gemini API key. When absent, the package extraction feature returns
`503`. Obtain a key from [Google AI Studio](https://aistudio.google.com/).

In AWS: stored as plain string in `lde/gemini-api-key`.

**`gemini_model`** — Gemini model name passed to the `generativelanguage.googleapis.com` API.
Change this when Google retires the current model. Override without redeploying via
`LDE_GEMINI_MODEL` or `PUT /api/settings`.

---

## Access control (AWS / Secrets Manager only)

`basic_auth_credentials` is not in the `ALLOWED_KEYS` allowlist and cannot be set via
`.settings.json` or `PUT /api/settings`. It is injected exclusively by the Secrets Manager
overlay at startup.

| Key | Type | AWS secret |
|---|---|---|
| `basic_auth_credentials` | JSON object `{"<username>": "<sha256_hex>"}` | `lde/basic-auth` |

When absent (local dev), all endpoints are unauthenticated. When present, every request requires
HTTP Basic Auth with a password whose SHA-256 hex matches the stored hash.

See [runbook-secrets-rotation.md](runbook-secrets-rotation.md) for instructions on rotating the
password hash.
