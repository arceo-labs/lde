# HTTP API Reference

All endpoints require HTTP Basic Auth when `basic_auth_credentials` is configured. Omit `-u` in local dev if Basic Auth is not set.

Base URL: `http://localhost:8002` (or your `LDE_ALLOWED_ORIGIN` in production).

Every `POST`, `PUT` and `DELETE` must send `Content-Type: application/json`, including requests with no body. This guards against cross-site requests. They also fail when an `Origin` header is present and is neither a `localhost`/`127.0.0.1` origin nor `LDE_ALLOWED_ORIGIN`:

- `415` — `{"error": "Content-Type must be application/json"}`
- `403` — `{"error": "Origin not allowed"}`

---

## Settings

### GET /api/settings

Returns current settings with sensitive keys masked (`dtrack_api_key`, `gemini_api_key` are truncated to 4 chars + `…`). GitHub settings are never returned: not the org map (`github`), not the old `default_orgs` or `github_pats` keys, and no token, key or key path. [`GET /api/gh-status`](#get-apigh-status) describes the orgs without secrets.

```bash
curl -s -u admin:password http://localhost:8002/api/settings | python3 -m json.tool
```

**Response:** `200` — object with the non-GitHub settings keys.

---

### PUT /api/settings

Patches one or more settings keys. Unknown keys return `400`. In Fargate (`LDE_SECRETS_SOURCE=aws`) this endpoint returns `503` — settings are managed via Secrets Manager and cannot be changed through the UI. GitHub orgs are not settings: change them with [`PUT /api/github/orgs/{org}`](#put-apigithuborgsorg), which works in both modes.

```bash
curl -s -u admin:password -X PUT http://localhost:8002/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"dtrack_url": "http://localhost:8081"}'
```

**Request body:** JSON object with any subset of the allowed settings keys.

**Response:** `200` — full settings object with sensitive keys masked.

**Errors:**
- `400` — unknown key, a GitHub key (`github`, `default_orgs`, `github_pats`), or body is not a JSON object
- `503` — deployment is in AWS mode; settings are read-only

---

### PUT /api/github/orgs/{org}

Basic Auth: required when `basic_auth_credentials` is set.

Adds `{org}` to the GitHub org map, or changes its entry ([docs/github-app.md](github-app.md)). `{org}` is a GitHub org or user name (letters, digits, `-`, at most 39), stored lower-cased. Fields left out keep their current value; a new org starts as `{"auth": "none", "scan": true}`.

Locally the map is written to `"github"` in `.settings.json`, and the old GitHub keys are removed from the file. On AWS it is written to the `lde/github` secret. The first write stores the map derived from the old settings, with this change applied.

**Request body** (`Content-Type: application/json`):

| Field | Type | Required | Description |
|---|---|---|---|
| `auth` | string | optional | `pat`, `enterprise` (needs an `enterprise_app` in the map), `none`, or `app` (only when the org already has its own app, for example to change `scan`). An app is created with [`POST /api/gh-app/manifest`](#post-apigh-appmanifest), never here. |
| `scan` | bool | optional | `true` puts the org in runs that name no orgs |
| `token` | string | optional | The org's fine-grained PAT, with `auth: pat` only. Write-only. Empty, or a value ending in `…`, keeps the saved token. |

App IDs, keys and key paths are refused.

```bash
curl -s -u admin:password -X PUT http://localhost:8002/api/github/orgs/globex \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:8002' \
  -d '{"auth": "pat", "scan": true, "token": "github_pat_..."}'
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `org` | string | The org, lower-cased |
| `auth` | string | `app`, `enterprise`, `pat` or `none` |
| `scan` | bool | Whether runs that name no orgs scan it |
| `app_id` | string | `auth: app` only |
| `token_hint` | string | `auth: pat` only: the first four characters and `…` |

```json
{"org": "globex", "auth": "pat", "scan": true, "token_hint": "gith…"}
```

**Errors:**

| Status | When |
|---|---|
| `400` | Invalid org name, unknown field, invalid `auth`/`scan`/`token`, `auth: pat` without a token, `auth: app` for an org without its app, `auth: enterprise` without an enterprise app, a broken stored map, or (AWS) the `lde/github` write failed |
| `403` | `Origin` is not an allowed origin (cross-site guard) |
| `404` | `{org}` is not a GitHub name (letters, digits and `-` only) |
| `415` | `Content-Type` is not `application/json` |

---

### DELETE /api/github/orgs/{org}

Basic Auth: required when `basic_auth_credentials` is set.

Removes `{org}` from the GitHub org map. Locally, its app key file stays in `~/.lde`.

```bash
curl -s -u admin:password -X DELETE http://localhost:8002/api/github/orgs/globex \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:8002'
```

**Response:** `200` — `{"deleted": "globex"}`

**Errors:**

| Status | When |
|---|---|
| `400` | A broken stored map, or (AWS) the `lde/github` write failed |
| `403` | `Origin` is not an allowed origin (cross-site guard) |
| `404` | `{org}` is not in the map, or is not a GitHub name |
| `415` | `Content-Type` is not `application/json` |

---

### GET /api/gh-status

Basic Auth: required when `basic_auth_credentials` is set.

Checks every org in the GitHub org map with its own credential:
- An app org (`auth: app`) or an enterprise org: LDE checks the app with `GET /app`, then mints an installation token on the org.
- A PAT org: LDE checks the token with `GET /user`.

No token, key or key path is ever returned.

```bash
curl -s -u admin:password http://localhost:8002/api/gh-status | python3 -m json.tool
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `installed` | bool | `true` when any org or the enterprise app is configured (or the map is broken) |
| `logged_in` | bool | `true` when the enterprise app (if any) and every org that is not `none` (or has `scan` on) authenticate |
| `mode` | string | `app`, `pat`, `mixed` (apps and PATs), or `none` |
| `config_error` | string | Why the org map is unusable (every GitHub call then fails; `orgs` is empty); `""` otherwise |
| `source` | string | Where the map comes from: `secret` (`lde/github`), `file` (`.settings.json`), `legacy` (derived from the old keys), or `none` |
| `enterprise_app` | object or null | `enterprise`, `app_id`, `ok`, `slug`, `name`, `install_url`, `message` |
| `orgs` | array | One entry per org: `org`, `auth`, `scan`, `ok`, `user` (the app's bot or the PAT's user), `app` (slug), `app_name`, `install_url` (the app's install page, for `app`/`enterprise`), `token_hint` (`pat` only), `message` |
| `notice` | string | PAT deprecation and old-config notices; empty otherwise |
| `raw` | string | Human-readable summary for the Settings UI |

Example (one org on its own app, one still on a PAT, one not set up):

```json
{
  "installed": true,
  "logged_in": true,
  "mode": "mixed",
  "config_error": "",
  "source": "file",
  "enterprise_app": null,
  "orgs": [
    {"org": "acme", "auth": "app", "scan": true, "ok": true, "user": "lde-acme-1f2e[bot]",
     "app": "lde-acme-1f2e", "app_name": "LDE acme 1f2e",
     "install_url": "https://github.com/apps/lde-acme-1f2e/installations/new",
     "token_hint": "", "message": "GitHub App LDE acme 1f2e installed"},
    {"org": "globex", "auth": "pat", "scan": true, "ok": true, "user": "octocat", "app": "",
     "app_name": "", "install_url": "", "token_hint": "gith…",
     "message": "PAT: Authenticated as octocat"},
    {"org": "hooli", "auth": "none", "scan": false, "ok": false, "user": "", "app": "",
     "app_name": "", "install_url": "", "token_hint": "", "message": "no credential yet"}
  ],
  "raw": "acme (app): GitHub App LDE acme 1f2e installed\nglobex (pat): PAT: Authenticated as octocat\nhooli (none): no credential yet",
  "notice": "GitHub PATs are deprecated. Create a GitHub App for these orgs in Settings: globex. See docs/github-app.md."
}
```

---

### POST /api/gh-app/manifest

Basic Auth: required when `basic_auth_credentials` is set.

Starts **Settings → Create GitHub App** (GitHub's app manifest flow). Returns a manifest and the github.com URL the browser form-posts it to. The manifest asks for Contents: Read and Metadata: Read, no webhook, and redirects back to this LDE. The redirect and setup URLs are built from the request's `Origin` header, which must be `http(s)://localhost[:port]`, `http(s)://127.0.0.1[:port]` or exactly `LDE_ALLOWED_ORIGIN`. The `Host` header is never used.

Refused when `org` already has `auth: app` in the org map, or when the map is broken. An org on a PAT, `enterprise` or `none`, or not in the map yet, can get its own app.

**Request body** (`Content-Type: application/json`):

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | optional | App name, 1–34 letters, digits, spaces, `.`, `_`, `-`. Must be unique on GitHub. Blank picks `LDE <org> <4 hex>`, or `LDE <6 hex>` without `org`. |
| `org` | string | optional | Org that owns the app. Blank creates it under the signed-in user's account. The app is always private (`"public": false`), so only this owner can install it. |

```bash
curl -s -u admin:password -X POST http://localhost:8002/api/gh-app/manifest \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:8002' \
  -d '{"name": "LDE reader", "org": "acme"}'
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `action` | string | `https://github.com/organizations/{org}/settings/apps/new?state=…`, or `https://github.com/settings/apps/new?state=…` without `org` |
| `manifest` | string | The manifest JSON, posted as the form field `manifest` |
| `state` | string | Single-use value, valid for one hour, that the callback must return |

**Errors:**

| Status | When |
|---|---|
| `400` | Missing or disallowed `Origin`, invalid field, unknown field, `org` already has its own app, the org map is broken, or `cryptography` is not installed |
| `403` | `Origin` is not an allowed origin (cross-site guard) |
| `415` | `Content-Type` is not `application/json` |

---

### GET /api/gh-app/callback?code={code}&state={state}

Basic Auth: required when `basic_auth_credentials` is set.

GitHub redirects the browser here after the user clicks **Create GitHub App** on github.com. LDE checks `state`, then exchanges `code` with `POST https://api.github.com/app-manifests/{code}/conversions` for the App ID, owner and private key. It sets the owner's entry in the org map to `{"auth": "app", "app_id": …}`, keeping its `scan` flag (a new org gets `scan: true`):

- **Locally:** the key goes to a new 0600 file `~/.lde/github-app-<id>.pem`, referenced as `private_key_path` in `"github"` in `.settings.json`.
- **AWS** (`LDE_SECRETS_SOURCE=aws`): the key goes inline as `private_key` in the `lde/github` secret.

The client secret and webhook secret GitHub also returns are discarded. Nothing is returned to the browser except a redirect. Not meant to be called by hand.

**Response:** always `303`.

| `Location` | When |
|---|---|
| `https://github.com/apps/{slug}/installations/new` | The app was created and stored. The app's setup URL brings the user back to `/settings` after installing. |
| `/settings?gh_app_error=state` | `state` is unknown, used, or older than an hour |
| `/settings?gh_app_error=exchange` | GitHub refused the code, returned an app without a usable ID, slug, owner or RSA key, or created it under a different owner than the requested org |
| `/settings?gh_app_error=store` | The key file, `.settings.json` or the `lde/github` secret could not be written |
| `/settings?gh_app_error=exists` | The new app's owner already has its own app in LDE |
| `/settings?gh_app_error=config` | The org map is unusable (including an `lde/github` value that is not JSON) |

---

### GET /api/dtrack-status

<!-- updated: new endpoint for the Settings "Test DT API key" button -->

Validates the saved `dtrack_api_key` against the saved `dtrack_url` by calling Dependency-Track's `GET /api/v1/team/self`. Tests only the server-side saved settings — it accepts no URL or key from the request — so save any changes before testing.

```bash
curl -s -u admin:password http://localhost:8002/api/dtrack-status | python3 -m json.tool
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `configured` | bool | `true` when both `dtrack_url` and `dtrack_api_key` are set |
| `ok` | bool | `true` when DT accepted the key |
| `team` | string\|null | Team name the key belongs to (when `ok`) |
| `permissions` | array | Permissions granted to the key's team (when `ok`) |
| `missing_permissions` | array | Recommended permissions (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`) not granted — informational only |
| `message` | string | Human-readable summary for the Settings UI |

The endpoint always returns `200`; failures are reported via `ok: false` with a generic `message` (raw DT response bodies are never echoed, and the API key is never returned).

---

### GET /api/gemini-status

Validates the saved `gemini_api_key` against the saved `gemini_model` by calling Google's `GET /v1beta/models/{model}` metadata lookup (free of charge; no generation call is made). Tests only the server-side saved settings — it accepts no key or model from the request — so this can't be used as an SSRF or credential-probing vector, and save any changes before testing.

```bash
curl -s -u admin:password http://localhost:8002/api/gemini-status | python3 -m json.tool
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `configured` | bool | `true` when `gemini_api_key` is non-empty in settings |
| `ok` | bool | `true` when the key was accepted and the model is usable |
| `model` | string\|null | Resource name Google reports (e.g. `models/gemini-3.8-flash`) when `ok` |
| `supports_generate` | bool | `true` when the model supports `generateContent` |
| `message` | string | Human-readable summary for the Settings UI |

The endpoint always returns `200`; failures are reported via `ok: false` with a generic `message` (the raw API key is never returned, and Google's raw error body is never echoed).

---

## Runs

### GET /api/runs

Lists the 100 most recent runs, newest first.

```bash
curl -s -u admin:password http://localhost:8002/api/runs | python3 -m json.tool
```

**Response:** `200` — array of run objects.

| Field | Type | Description |
|---|---|---|
| `id` | string | Hex run ID |
| `started_at` | string | ISO 8601 UTC timestamp |
| `completed_at` | string\|null | ISO 8601 UTC, or null if still running |
| `status` | string | `queued`, `running`, `completed`, `failed`, `partial`, `stopped` |
| `stage` | string | Current pipeline stage |
| `method` | string | `github_sbom` |
| `orgs` | array | Org names scanned |
| `repos` | array | Repo filters applied (empty = all repos in orgs) |

---

### POST /api/runs

Starts a new run.

```bash
# Single repo, github_sbom method (default)
curl -s -u admin:password -X POST http://localhost:8002/api/runs \
  -H 'Content-Type: application/json' \
  -d '{"repos": ["example-org/example-platform"], "method": "github_sbom"}'

# Full org scan using defaults from settings
curl -s -u admin:password -X POST http://localhost:8002/api/runs \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | no | `github_sbom`, the default and only supported method. |
| `orgs` | array | no | Org names to scan. Defaults to the orgs with `scan: true` in the GitHub org map when omitted or empty. |
| `repos` | array | no | Repo filters: plain names (`"bec-api"`) or `org/repo` pairs. When all entries use `org/repo` format, `orgs` is derived from them. |
| `use_default` | bool | no | When `true` (or `branch` is empty), every repo uses its GitHub default branch. |
| `branch` | string | no | Run-level branch override applied to all repos. Ignored when `use_default` is true. Validated against the GitHub branch-ref rules. |

**Response:** `202` — `{"run_id": "<hex>"}`

**Errors:**
- `400` — invalid `method`, invalid repo name format, invalid `branch` name, no orgs given and none with `scan: true`, an example org from `.settings.json.example` (for example `example-org`), a broken GitHub org map, or (for `github_sbom`) an org LDE cannot authenticate to: not in the org map, `auth: none`, or its app not installed or failing. The message gives the reason for each such org

---

### GET /api/runs/{id}

Returns detail for one run.

```bash
curl -s -u admin:password http://localhost:8002/api/runs/a22dc9fe | python3 -m json.tool
```

**Response:** `200` — single run object (same fields as list, plus `branch` — the run-level branch override, or `null` when each repo uses its configured/default branch — and `error`).

**Errors:** `404` — run not found

---

### GET /api/runs/{id}/repos

Per-repo breakdown for a run.

```bash
curl -s -u admin:password http://localhost:8002/api/runs/a22dc9fe/repos | python3 -m json.tool
```

**Response:** `200` — array of repo rows.

| Field | Type | Description |
|---|---|---|
| `org` / `repo` | string | Repository identity |
| `default_branch` | string\|null | Branch this repo was analyzed on (resolved from the run override or the GitHub default) |
| `ort_status` | string | Repo status: `pending`, `running`, `completed`, `failed`, `skipped`. `skipped` means the repo has the Dependency Graph disabled. |
| `ort_package_count` | int\|null | Component count from GitHub's SBOM |
| `dtrack_project_uuid` | string\|null | DT project UUID if ingested |
| `dtrack_component_count` | int\|null | Components DT recorded |
| `bom_overwrite_skipped` | bool | `true` if an empty BOM upload was refused to protect an existing DT project |
| `error` | string\|null | Error message for failed repos |

---

### POST /api/runs/{id}/stop

Signals cancellation for a running or queued run.

```bash
curl -s -u admin:password -X POST -H 'Content-Type: application/json' \
  http://localhost:8002/api/runs/a22dc9fe/stop
```

**Response:** `202` — `{"status": "stopping"}`

**Errors:**
- `400` — run is not in `running` or `queued` status
- `404` — run not found

---

### POST /api/runs/{id}/continue

Restarts a `failed`, `partial`, or `stopped` run under the same run ID. Every repo in the run is fetched again.

```bash
curl -s -u admin:password -X POST -H 'Content-Type: application/json' \
  http://localhost:8002/api/runs/a22dc9fe/continue
```

**Response:** `202` — `{"run_id": "<hex>", "resumed": true}`

**Errors:**
- `400` — run is not in a resumable status
- `404` — run not found

---

### POST /api/runs/{id}/restart

Clones the run's org list into a new run ID and starts from scratch.

```bash
curl -s -u admin:password -X POST -H 'Content-Type: application/json' \
  http://localhost:8002/api/runs/a22dc9fe/restart
```

**Response:** `202` — `{"run_id": "<new_hex>"}`

**Errors:** `404` — source run not found

---

### POST /api/runs/{id}/retry-failed

Resets all repos with `ort_status='failed'` back to `pending` and restarts the run. Every repo in the run is fetched again.

```bash
curl -s -u admin:password -X POST -H 'Content-Type: application/json' \
  http://localhost:8002/api/runs/a22dc9fe/retry-failed
```

**Response:** `202` — `{"run_id": "<hex>", "reset": <count>}`

**Errors:**
- `400` — run is not in `failed`, `partial`, or `stopped` status, or no failed repos found
- `404` — run not found

---

### POST /api/runs/{id}/repos/{org}/{repo}/retry

Resets a single failed repo back to `pending` and restarts the run. Every repo in the run is fetched again.

```bash
curl -s -u admin:password -X POST -H 'Content-Type: application/json' \
  http://localhost:8002/api/runs/a22dc9fe/repos/example-org/bec-api/retry
```

**Response:** `202` — `{"run_id": "<hex>", "org": "<org>", "repo": "<repo>"}`

**Errors:**
- `400` — run is not in a retryable status, or repo is not in `failed` state
- `404` — run or repo not found

---

## Inspection

### GET /api/runs/{id}/repos/{org}/{repo}/dtrack-components

Returns live DT component data for one repo's project.

```bash
curl -s -u admin:password \
  http://localhost:8002/api/runs/a22dc9fe/repos/example-org/bec-api/dtrack-components \
  | python3 -m json.tool
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `dtrack_project_uuid` | string\|null | DT project UUID |
| `dt_component_count` | int\|null | Live component count from DT |
| `stored_component_count` | int\|null | Count stored in the run DB |
| `ort_package_count` | int\|null | Component count from GitHub's SBOM |
| `bom_overwrite_skipped` | bool | Whether an empty-BOM upload was refused |
| `components` | array | `{name, group, version, purl}` for each component |
| `live_error` | string\|null | DT API error if the live fetch failed |

**Errors:** `404` — repo not found in this run

---

## Search

### GET /api/dtrack/search?q={text}

Cross-project DT component search via Lucene index, results grouped by project.

```bash
curl -s -u admin:password "http://localhost:8002/api/dtrack/search?q=%40tanstack%2Fquery-core" \
  | python3 -m json.tool
```

**Query params:** `q` — search text, max 200 chars, required.

**Response:** `200` — `{query, total_components, project_count, projects: [{name, components: [...]}]}`

**Errors:**
- `400` — missing or empty `q`, or query exceeds 200 chars
- `502` — DT search failed
- `503` — DT is not configured

---

### POST /api/dtrack/package-search

Batch search: look up up to 500 package names in parallel (10 concurrent DT calls).

```bash
curl -s -u admin:password -X POST http://localhost:8002/api/dtrack/package-search \
  -H 'Content-Type: application/json' \
  -d '{"packages": ["lodash", "axios", "requests"]}' | python3 -m json.tool
```

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `packages` | array of string | yes | Package names, max 500, each max 200 chars |

**Response:** `200` — `{results: [{query, matches: [{project, project_uuid, project_version, component, component_uuid, component_version, purl, project_link, dep_graph_link}]}]}`

**Errors:**
- `400` — not a list, too many packages, name too long, or no non-empty names
- `503` — DT is not configured

---

### POST /api/extract-packages

Submits a URL or file content for Gemini-powered npm/PyPI package extraction. Returns a task ID immediately; poll `GET /api/tasks/{id}` for the result. Requires `gemini_api_key` in settings. The model used defaults to `gemini-3.8-flash` and can be overridden via the `gemini_model` setting.

```bash
# From URL
curl -s -u admin:password -X POST http://localhost:8002/api/extract-packages \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"}'

# From uploaded file content
curl -s -u admin:password -X POST http://localhost:8002/api/extract-packages \
  -H 'Content-Type: application/json' \
  -d '{"text": "<html>...", "filename": "advisory.html"}'
```

**Request body (URL mode):**

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | yes (if no `text`) | URL to fetch server-side, max 2048 chars |

**Request body (file mode):**

| Field | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes (if no `url`) | File content, max 500 KB |
| `filename` | string | no | Original filename (e.g. `advisory.html`) for MIME hint |

**Response:** `202` — `{"task_id": "<hex>"}`

**Errors:**
- `400` — neither `url` nor `text` provided, URL too long, text too large, or text is empty
- `503` — `gemini_api_key` is not configured

---

## Tasks

### GET /api/tasks/{id}

Polls background task status. Terminal responses (`completed` / `failed`) auto-consume the task — a second poll returns `404`.

```bash
curl -s -u admin:password http://localhost:8002/api/tasks/a1b2c3d4 | python3 -m json.tool
```

**Response:** `200`

| Field | Type | Description |
|---|---|---|
| `status` | string | `pending`, `running`, `completed`, `failed` |
| `stage` | string | Human-readable progress description |
| `result` | any\|null | Task result (terminal responses only) |
| `error` | string\|null | Error message (terminal responses only) |

**Errors:** `404` — task not found or already consumed
