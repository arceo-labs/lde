# Design decisions

Key design choices and the reasoning behind them.
For the system topology see [Architecture](architecture.md).
For the pipeline mechanics see `TRD.md` and `README.md` in the repository root.

---

## 1. PAT-based GitHub auth replaces `gh` CLI (superseded by decision 7)

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

## 3. One pip runtime dependency

**Decision:** The server runs on Python 3.11+ stdlib plus one package, `cryptography`, used only
to sign GitHub App JWTs (decision 7). No Flask, FastAPI, httpx, or any other runtime package.
`requirements.txt` pins `cryptography` and lists `pytest` for tests.

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

**Exception:** The stdlib cannot produce RSA signatures, and hand-written crypto is not an
option for a security tool. `cryptography` (PyCA) is audited, ships wheels for every target, and
is pinned to one version. It is imported only by `backend/gh_app.py`.

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

---

## 7. GitHub App auth replaces per-org PATs

**Decision:** LDE authenticates to GitHub as one GitHub App installed on every scanned org.
`backend/gh_app.py` signs a nine-minute app JWT, finds the org's installation, and mints a
one-hour installation token limited to `contents:read` and `metadata:read`. Per-org PATs
(`github_pats`) remain as a deprecated fallback for orgs without the app.

**Why:**

- **No personal credentials.** A PAT belongs to a person: it leaves with them, expires on their
  schedule, and needs SSO re-authorization per org. The app belongs to the org.
- **Short-lived tokens.** Installation tokens expire after an hour and are never stored. A
  leaked token is useful for at most that hour; the long-lived secret is the private key, which
  never leaves Secrets Manager or a 0600 file.
- **Least privilege, enforced per token.** Each token is minted with only the two read
  permissions LDE needs, whatever the app is granted.
- **Rate limits per org.** Each installation has its own budget (5,000–15,000 requests per hour)
  instead of sharing one user's.

**Trade-off:**
One runtime dependency (decision 3), and an org owner must install the app on each org. A
misconfigured app fails closed for every org rather than quietly falling back to PATs.

See [GitHub App](github-app.md).

## 8. One private GitHub App per org, created from Settings

**Decision:** LDE is self-hosted, so there is no shared LDE app. **Settings → Create app for
&lt;org&gt;** uses GitHub's app manifest flow: GitHub creates a private, read-only app owned by
that org, and `backend/gh_app_setup.py` exchanges the one-time code for the App ID, owner and
key on the server. LDE keeps a list of apps (`github_apps` locally, `lde/github-app` on AWS)
and, for each org, uses the app that org owns, else any other configured app installed there.
An enterprise-owned app, added by hand, can cover every org in an enterprise. Locally the setup
writes a new 0600 key file and `.settings.json`. On AWS it writes `lde/github-app`, which gives
the ECS task role `secretsmanager:PutSecretValue` on that one secret.

**Why:**

- **No hand-copied key.** The manual path has the user download a `.pem`, move it, `chmod` it
  and paste it into a secret. The manifest flow sends the key from GitHub straight to the server.
  It never reaches the browser, so the key is still never entered through, or returned by,
  the UI or API.
- **Right permissions by default.** The manifest fixes Contents: Read, Metadata: Read and no
  webhook, so nobody has to find those settings on GitHub's form.
- **Private apps, any number of orgs.** A private app installs only on its owner, so covering
  several orgs needs either one app per org or an enterprise-owned app. One app per org works for
  every account type and lets each org own, inspect and revoke its own app. Making an app public
  would let any account install it, so LDE never does.

**Trade-off:**
One private key per org to rotate. The task role can now write one secret, not just read it.
Setup only ever adds an app: it is refused when the owner GitHub reports already has one, or
differs from the org setup was started for, and each callback needs a single-use `state` that
LDE issued within the hour. Pending `state` values are in memory: a restart between **Create**
and GitHub's redirect means starting again. Removing an app is a manual config edit.
