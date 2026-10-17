# Library Dependency Explorer — CLAUDE.md

@AGENTS.md

## Code structure

Single-file stdlib HTTP server, zero pip runtime dependencies.

- `server.py` — all HTTP routes dispatched via `do_GET` / `do_POST` / `_route()`. No framework.
- `backend/` — pipeline logic, GitHub/DependencyTrack clients, DB, settings, auth helpers
- `cache_server/` — standalone PyPI/npm proxy servers (separate processes, not imported by main app)
- `index.html`, `css/` — single-page frontend
- `terraform/` — AWS ECS Fargate infrastructure (Terraform)
- `tests/` — pytest unit tests
- `tests/e2e/` — end-to-end tests; require a running server on `:8002`
- `scripts/` — ad-hoc maintenance utilities (not part of the deployed app)
- `docs/` — one Markdown file per feature or operational topic

Config lives in `.settings.json` (gitignored). See `.settings.json.example` for all keys.
Settings are overlaid by AWS Secrets Manager when `LDE_SECRETS_SOURCE=aws`.

## Build and test

```bash
# Local dev (no Docker required)
python3 server.py                    # serves on http://localhost:8002

# Dependency-Track (API server + frontend)
docker compose up -d dtrack-apiserver dtrack-frontend

# Unit tests
pytest

# E2E tests (requires server already running on :8002)
pytest tests/e2e/
```

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8002` | HTTP listen port |
| `LDE_DATA_DIR` | (repo root) | EFS mount for DB and run logs in Fargate |
| `LDE_SECRETS_SOURCE` | `` | Set to `aws` to activate AWS Secrets Manager overlay |
| `LDE_ALLOWED_ORIGIN` | `` | Production hostname added to CORS allowed origins |

## Documentation format

- Root: `README.md` (user-facing), `TRD.md` (architecture), `AGENTS.md` (instructions for every agent), `CLAUDE.md` (Claude-only instructions; imports `AGENTS.md`)
- Features and ops: `docs/kebab-case-topic.md`
- No frontmatter required — plain Markdown only
- Images: `docs/screenshot-*.png`
- Reference style: `docs/pkg-search.md` (CLI tools), `docs/aws-deployment.md` (deployment guides)

## Documentation style

**API endpoint pages** must include:
- HTTP method and full path
- Whether Basic Auth is required (always required when `basic_auth_credentials` is set)
- Request body schema: JSON field name, type, required/optional
- Response schema: only fields `server.py` actually returns
- Error status codes: only those the code actually sends
- A realistic `curl -u admin:password` example

**CLI tool pages** must include:
- Prerequisite table (tool, version, notes)
- Usage/flags table
- Examples section covering common cases and edge cases
- GitHub API rate limit note when the tool calls the GitHub API
- Security notes section (credential handling, read-only guarantees)

**Deployment guides** must include:
- ASCII architecture diagram
- Numbered phases with self-contained command blocks at every step
- Cost table when AWS resources are involved

Voice: direct and imperative ("Run…", "Set…", "Confirm…"). No marketing copy.
Match the existing voice and formatting of `docs/pkg-search.md`.

## Security invariants (do not violate)

These are enforced throughout `server.py` and `backend/`; new code must maintain them:

- **Request body cap:** all endpoints enforce `_MAX_BODY` (1 MB). New endpoints must do the same.
- **Explicit timeouts:** every outbound network call (`urlopen`) and every `subprocess.run` passes
  an explicit `timeout=`. There is no shared wrapper; set it at each call.
- **Path canonicalization:** file paths are resolved with `os.path.realpath()` before any
  security check. URL hostnames are resolved and checked for SSRF before fetching.
- **Two-tier error responses:** a top-level `_route()` handler catches all exceptions.
  `RuntimeError` → descriptive user-facing message. All other exceptions → generic
  "Internal server error" to prevent stack-trace or path leakage.
- **No inline styles:** the CSP is `style-src 'self'`, so browsers ignore `style="..."`
  attributes. Put styles in `css/styles.css` and reference them by class.
- **Fail-closed auth:** if `basic_auth_credentials` is configured but cannot be parsed,
  authentication fails closed (returns 401), never open.

## Documentation invariants

- **Do not invent routes.** The only source of truth for the HTTP API surface is `server.py`.
- **ORT is deprecated.** GitHub Dependency Graph (`github_sbom`) is the only ingest method. The ORT
  pipeline code is scheduled for removal: leave it out of docs and do not extend it.
- **Settings are never committed.** Always reference `.settings.json.example`; never `.settings.json`.
- **Two DependencyTrack URLs exist** and must not be conflated:
  - `dtrack_url` — API server URL (used for all API calls, default `:8081`)
  - `dtrack_ui_url` — Frontend URL (used for deep links only, default `:8080`)
