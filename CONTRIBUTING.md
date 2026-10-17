# Contributing

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11+ | `brew install python@3.12` |
| Docker + Compose v2 | 24+ | Runs Dependency-Track locally |
| GitHub PAT | — | Fine-grained token: Contents Read-only + Metadata Read-only |

No pip packages are needed to run the server — it uses Python stdlib only.

Install test dependencies:

```bash
pip install -r requirements.txt
```

## Running the server

```bash
python3 server.py                          # http://localhost:8002, auto-reload on
python3 server.py --port 8003 --no-reload  # custom port, no reload
python3 server.py --debug                  # verbose HTTP + pipeline logging
```

Open `http://localhost:8002` → **Settings** → paste your GitHub PAT → **Save**.

## Running tests

```bash
# Unit tests (fast, no running server, no Docker)
pytest

# Verbose output
pytest -v

# Single module
pytest tests/test_sanitizer.py -v
```

`tests/e2e/` exercises the deprecated ORT pipeline and will be removed with it. CI does not run it; skip it.

## Making changes

### Backend (`backend/`, `server.py`)

- All HTTP routes live in `server.py`'s `ROUTES` list. Add new routes there and implement them as `handle_*` methods on the `Handler` class.
- Follow the existing two-tier error pattern: `RuntimeError` → 400 with the message; all other exceptions → 500 with "Internal server error" (never leak stack traces).
- Cap new endpoint body sizes with `_read_body()` (which enforces `_MAX_BODY = 1 MB`). Add per-endpoint limits on top if the content type warrants it.
- All outbound HTTP calls must go through `_timed_call()` (or a per-module equivalent) with a hard wall-clock timeout.
- File path security: resolve with `os.path.realpath()` and check containment before opening. See `_serve_static()` and `_read_sanitized()` for the pattern.

### Frontend (`index.html`, `css/`, `js/`)

Vanilla JS SPA — no framework, no build step. Edit and refresh.

Put styles in `css/styles.css` and reference them by class. The CSP is `style-src 'self'`, so browsers ignore inline `style="..."` attributes, and a unit test fails on any it finds.

### Infrastructure (`terraform/`)

```bash
cd terraform
terraform fmt        # format before committing
terraform validate   # check syntax
terraform plan       # review changes
```

Always `terraform plan` before `terraform apply`. Infrastructure changes need manual review — do not auto-apply from CI.

### Documentation (`docs/`)

Follow the style in `docs/pkg-search.md`. Run `mkdocs serve` to preview:

```bash
pip install -r requirements-docs.txt
mkdocs serve   # http://127.0.0.1:8000
```

## Human-submitted contributions

AI coding assistants are welcome. Every pull request, issue and review comment comes from a person, who takes responsibility for all of it.

Opening a PR confirms that you:

- can explain every change in it and will respond to review;
- have the right to contribute all of it, including any code or data an assistant produced;
- ran the validation yourself, and put the evidence (`pytest` output, manual checks) in the description.

If an AI tool did a material part of the work, say so in the description: name the tool and the parts it helped with. Describe what you checked rather than pasting prompts.

Pull requests, issues and comments opened by an agent acting on its own are closed. Automated PRs, such as dependency updates, need a maintainer to opt in first and must come from an identifiable bot account.

Human maintainers review and merge. AI review comments are advisory.

Maintainers may decline a PR that is larger than they can review well. Small, focused PRs are reviewed fastest.

## PR conventions

- One logical change per PR.
- Include a test for any new backend logic — unit tests preferred over e2e for speed.
- Security-sensitive changes (auth, input handling, data export) need a comment describing the threat model.
- Run `pytest` before opening a PR and confirm it passes.
- PRs that touch `terraform/` must include `terraform plan` output in the description.
