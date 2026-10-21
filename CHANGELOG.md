# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** GitHub tokens are now one fine-grained PAT per org in `github_pats` (`{"<org>": "<token>"}`). A `"*"` key is the token for any org without its own entry; an org with neither is an error, not an unauthenticated call. The single `github_pat` setting and `LDE_GITHUB_PAT` are no longer read; the Settings page and `/api/gh-status` show an "old config" notice while `github_pat` is still present. On AWS, the secret keeps its name `lde/github-pat` but must now hold a JSON object `{"<org>": "<token>"}`; a plain-string value is ignored. Rewrite it before the next deploy (no Terraform change).
- Ingest Dependencies no longer shows a method menu. New UI runs always use GitHub's Dependency Graph (`github_sbom`). ORT ingest is deprecated in the UI; it previously used the ORT connector to crunch SBOMs locally in Docker.
- Package Search hides the fallback-prompt textarea until **Copy fallback prompt** fails (clipboard unavailable). The native **Choose File** control is hidden; **Upload file** remains the only file picker.

### Added

- Settings page: one row per org, and a Test PAT button that validates every saved token.
- `scripts/check_aws.py preflight|verify`: read-only checks for the AWS deployment. Preflight finds resources left from an earlier stack, a missing ECS cluster, certificate and allowlist mismatches and an unpushed `lde_image`. Verify checks services, targets, DNS, secret shape (never values) and the live endpoints.

### Security

- Basic Auth compares the password hash in constant time (`hmac.compare_digest`), and a malformed stored hash returns 401 instead of raising.
- Behind the ALB (`X-Forwarded-Proto: https`), responses send `Strict-Transport-Security: max-age=63072000; includeSubDomains`. Plain-HTTP local runs don't.
- Finished background tasks that are never polled are dropped after 15 minutes, freeing their stored payloads.
- `POST` and `PUT` now require `Content-Type: application/json`, and are refused when an `Origin` header names a site other than localhost or `LDE_ALLOWED_ORIGIN`. Before this, any web page could drive a local LDE with a cross-site form or `fetch` request: start ingests, or run Gemini extractions on the configured key.
- One package extraction is limited to 20 Gemini calls (3,000 non-blank lines) and 170 seconds, and a failed chunk cancels the rest. A crafted 500 KB upload could previously trigger thousands of calls.
- The web server served any file under the app directory to a logged-in user, not just the UI. On AWS that included the data volume (`/data/depexplorer.db`, `/data/runs/...`) and every source file. It now serves only `index.html`, `css/` and `js/`, and returns 404 for everything else.

### Fixed

- `POST /api/runs` with only `org/repo` entries no longer fails with "No orgs provided" when `default_orgs` is empty, as on a fresh AWS deploy.
- Port 80 on the ALB redirects to HTTPS when the certificates come from `listener_certificate_arns`. It returned 404 unless `route53_zone_id` was set.

## [0.1.0] - 2026-07-12

### Added

- Initial public release.
- **GitHub SBOM ingest** (default): converts GitHub's Dependency Graph
  (SPDX 2.3) to CycloneDX 1.4 and ingests into OWASP Dependency-Track — no
  repository cloning required.
- **ORT ingest** (local, Docker-based): resolves full transitive dependency
  graphs via the OSS Review Toolkit for repositories without the GitHub
  Dependency Graph enabled.
- **Package Search**: find which repositories contain a given npm/PyPI
  package, with deep links into Dependency-Track. Optional Gemini-based
  extraction of package names from an advisory URL or uploaded file.
- **Branch selection**: analyze a non-default branch per repository, with
  branch discovery across an org.
- Vanilla-JS single-page frontend (no build step) served by a stdlib-only
  Python HTTP server.
- Reference AWS ECS Fargate deployment (Terraform) and local `docker-compose`
  stack (Dependency-Track + optional caching proxies).
- Unit test suite (`pytest`) and opt-in end-to-end tests.

[Unreleased]: https://example.com/your-org/library-dependency-explorer/compare/v0.1.0...HEAD
[0.1.0]: https://example.com/your-org/library-dependency-explorer/releases/tag/v0.1.0
