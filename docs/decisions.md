# Design decisions

Key design choices and the reasoning behind them.
For the system topology see [Architecture](architecture.md).
For the pipeline mechanics see `TRD.md` and `README.md` in the repository root.

---

## 1. PAT-based GitHub auth replaces `gh` CLI

**Decision:** All GitHub API calls go through `backend/github_client.py` and `backend/gh_auth.py`
using the `github_pats` setting (one PAT per org), not the `gh` CLI subprocess.

**Why:**
The original implementation shelled out to `gh api ...` and relied on the user's interactive
`gh` session. That works on a developer laptop but breaks in ECS Fargate — Fargate tasks have
no persistent home directory, no keychain, and no interactive login flow.
The PAT is stored in AWS Secrets Manager (`lde/github-pat`, a JSON object) and injected at runtime via
`secrets_loader.overlay()`, giving Fargate the same credentials it needs without any host state.

**Trade-off:**
PAT-based auth requires a secret to manage (expiry, rotation, SSO re-authorization). The
`gh` CLI handled token refresh automatically. With a PAT you must rotate it before it expires
and re-authorize each SSO org. See [Runbook: Secrets Rotation](runbook-secrets-rotation.md).

**Scope:** The ingest pipeline calls `github_client.py`.
No backend module shells out to `gh` any longer.

---

## 2. ORT pipeline (deprecated)

ORT (OSS Review Toolkit) previously ran locally in Docker to build SBOMs from committed
manifests. It never ran in Fargate, which has no Docker socket. It is deprecated:
GitHub's Dependency Graph (`github_sbom`) is the only ingest method. The ORT pipeline
code remains in the repository for now and will be removed.

---

## 3. Zero pip runtime dependencies

**Decision:** The server runs on Python 3.11+ stdlib only. `requirements.txt` lists only
`pytest` (a test dependency). No Flask, FastAPI, httpx, or any other runtime package.

**Why:**

- **Supply-chain simplicity.** A web framework and its transitive dependencies are a
  significant attack surface for a security tool. Using only stdlib eliminates that risk.
- **Docker image size.** `python:3.12-slim` with no `pip install` at runtime is materially
  smaller and faster to build than images with framework wheels.
- **Deployment portability.** `python3 server.py` works on any machine with Python 3.11+.
  No virtualenv, no lockfile drift, no pip-resolver conflicts.

**Trade-off:**
Manual routing (`ROUTES` table in `server.py`), manual JSON serialization, and manual
static file serving instead of framework abstractions. The additional boilerplate is
contained to `server.py` and is straightforward to audit.

---

## 4. Settings reloaded per-request

**Decision:** `settings.py::load_settings()` is called on every inbound request, not once
at startup. `secrets_loader.overlay()` (which reads AWS Secrets Manager) runs inside it and
reuses each fetched secret for 60 seconds.

**Why:**
Secrets Manager values can be updated at any time (credential rotation, emergency revocation).
Loading per-request means the change takes effect within a minute without an ECS task
restart or a deployment. For an internal tool handling infrequent requests, the I/O cost of
one settings file read per request is negligible. The 60-second cache exists because ALB
health checks also count as requests: uncached, they caused ~25,000 Secrets Manager calls
a day (see [AWS cost control](aws-cost-control.md)).

**Implication:**
Rotating any credential in Secrets Manager takes effect automatically within 60 seconds.
You do not need to force a new ECS deployment after rotating a secret.

---

## 5. SQLite with WAL mode (not PostgreSQL)

**Decision:** The run database is SQLite in WAL mode, mounted on EFS in Fargate.

**Why:**
The write workload is light — one run starts every few hours at most, with per-repo status
updates serialized through a single pipeline thread per run. SQLite WAL mode handles
concurrent reads (the HTTP handler) alongside the writer (the pipeline thread) without
contention. PostgreSQL would add a separate service to manage, a connection pool to tune,
and a migration toolchain to maintain — all for a workload that's well within SQLite's
operating range.

**EFS mount:** In Fargate, `LDE_DATA_DIR` points at an EFS-backed path so the database
and run logs survive task restarts. `depexplorer.db` is never written to the ephemeral
container filesystem.

---

## 6. Basic Auth instead of a session-based auth system

**Decision:** HTTP Basic Auth over HTTPS, with SHA-256 password hashes stored in
Secrets Manager. No sessions, no cookies, no OAuth.

**Why:**
LDE is an internal tool accessed by a small ops team. It lives behind an ALB with an ACM
TLS certificate. Basic Auth over HTTPS is simple, stateless, and requires no client-side
session management. The credentials are reloaded per-request (see §4), so rotation takes
effect within a minute.

**Fail-closed in AWS mode:** When `LDE_SECRETS_SOURCE=aws` is set, an empty or unparseable
`basic_auth_credentials` secret causes every request to return 401 — it never falls back
to open access. Locally (no `LDE_SECRETS_SOURCE`), an absent credential set disables auth
entirely for development convenience.
