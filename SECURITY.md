# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. **Do not open a public
issue for a security report.**

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**), or contact the maintainers at
`security@arceo.ai`.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce (a proof of concept if possible)
- Affected version / commit
- Any suggested remediation

We aim to acknowledge reports within a few business days and will keep you
informed as we investigate and remediate.

## Supported versions

This project is pre-1.0. Security fixes are applied to the `main` branch.
Pin to a commit or release tag for reproducible deployments.

## Security design invariants

Library Dependency Explorer is a security tool and maintains several
invariants throughout `server.py` and `backend/`. Changes must preserve them:

- **Request body cap.** Every endpoint enforces a 1 MB request body limit
  (`_MAX_BODY`). New endpoints must do the same.
- **Explicit timeouts.** Every outbound network call and subprocess sets an
  explicit timeout, so a stalled upstream can't hang a request.
- **Path canonicalization & SSRF checks.** File paths are resolved with
  `os.path.realpath()` before any security check. URL hostnames are resolved
  and validated before fetching, to prevent SSRF.
- **Two-tier error responses.** A top-level handler catches all exceptions.
  `RuntimeError` produces a descriptive, user-facing message; every other
  exception produces a generic "Internal server error" so stack traces and
  filesystem paths are never leaked.
- **Fail-closed auth.** If Basic Auth credentials are configured but cannot be
  parsed, authentication fails closed (HTTP 401) — never open.

## Handling of secrets

- Secrets (GitHub PAT, Dependency-Track API key, Gemini API key, Basic Auth
  credentials) live in `.settings.json`, which is git-ignored. Never commit it.
- In AWS deployments, secrets are overlaid from AWS Secrets Manager
  (`LDE_SECRETS_SOURCE=aws`); see `docs/runbook-secrets-rotation.md`.
- Certificate/key material (`certs/`, `*.crt`, `*.pem`, `*.key`, …) is
  git-ignored by default.
