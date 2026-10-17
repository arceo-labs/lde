# pkg-search.sh

A Bash CLI that searches for a specific package and its pinned version across every repository in one or more GitHub organizations. Reads manifest files directly from the GitHub API — no cloning required — and outputs results as human-readable text or machine-parseable CSV.

This script is kept alongside the full pipeline app (see `README.md` in the repository root) for cases where you just need a quick one-shot lookup without spinning up Docker.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| `bash` | 4.x+ | Ships with macOS via Homebrew (`brew install bash`) |
| [`gh`](https://cli.github.com/) | 2.x+ | GitHub CLI — must be authenticated |
| `jq` | 1.6+ | Required for `package.json` section filtering |

### Authenticate the GitHub CLI

```bash
gh auth login
```

You need at least **read** access (`repo` scope) to every org you intend to scan. For organizations with SSO, also authorize the token:

```bash
gh auth refresh --scopes repo
# then: Settings → Personal access tokens → authorize each SSO org
```

Verify access:

```bash
gh auth status
```

## Usage

```
./pkg-search.sh <package> [options]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--orgs <list>` | `-o` | built-in list | Comma-separated GitHub org names to scan |
| `--dep-type <type>` | `-t` | `all` | `dependencies`, `devDependencies`, `peerDependencies`, or `all` (only applies to `package.json`) |
| `--manifest <file>` | `-m` | `package.json` | Manifest filename to search for |
| `--node` | | | Shortcut for `--manifest package.json` |
| `--python` | | | Shortcut for `--manifest requirements.txt` |
| `--go` | | | Shortcut for `--manifest go.mod` |
| `--format <fmt>` | `-F` | `text` | Output format: `text` or `csv` |
| `--help` | `-h` | | Print usage and exit |

### Default organizations

When `--orgs` is omitted the script scans:

- `example-org`
- `example-org-hris`
- `example-org-test`
- `another-org`
- `example-website`

Pass `--orgs` to override this list entirely.

## Supported manifest formats

| Manifest | Flag shortcut | Version extraction method |
|----------|--------------|--------------------------|
| `package.json` | `--node` | `jq` lookup by key; grep fallback for `--dep-type all` |
| `requirements.txt` | `--python` | Regex on `pkg==`, `pkg>=`, `pkg~=`, etc. |
| `go.mod` | `--go` | Regex on `require` block entries (`pkg vX.Y.Z`) |
| `Pipfile` | *(use `-m Pipfile`)* | Key = value parsing |

## Examples

**Find every repo using `axios` (all orgs, all dependency sections):**

```bash
./pkg-search.sh axios
```

**Limit to `devDependencies` only:**

```bash
./pkg-search.sh lodash --dep-type devDependencies
```

**Scope to specific orgs:**

```bash
./pkg-search.sh express --orgs example-org,another-org
```

**Search Python repos for `requests`:**

```bash
./pkg-search.sh requests --python
```

**Search Go modules for a dependency:**

```bash
./pkg-search.sh golang.org/x/net --go
```

**Export to CSV for spreadsheet analysis:**

```bash
./pkg-search.sh axios --format csv > axios-report.csv
```

### CSV output schema

```
org,repo,filepath,version
example-org,api-service,package.json,^1.7.4
example-org,frontend,packages/web/package.json,^1.6.0
```

| Field | Description |
|-------|-------------|
| `org` | GitHub organization name |
| `repo` | Repository name |
| `filepath` | Path to the manifest file within the repo |
| `version` | Version string exactly as written in the manifest |

## How it works

1. **Repo enumeration** — `gh repo list <org> --limit 4000` fetches all repository names for each org.
2. **Tree traversal** — For each repo, the script calls `GET /repos/{org}/{repo}/git/trees/{branch}?recursive=1` to find every file matching the target manifest name anywhere in the tree.
3. **Content fetch** — Each matching manifest is fetched via `GET /repos/{org}/{repo}/contents/{path}` with the raw media type, keeping the request count proportional to matches rather than all files.
4. **Version extraction** — The `extract_version()` function applies a manifest-specific strategy (jq, grep, awk, or sed) to pull the version string for the requested package.
5. **Output** — Matches are printed as `org/repo — path: version` (text) or appended to a CSV row.

## GitHub API rate limits

The script makes multiple API calls per repository (repo view + tree + one call per matching manifest). For large orgs with hundreds of repositories, you may hit the authenticated rate limit of 5,000 requests/hour. Consider scoping searches with `--orgs` to reduce the call volume.

## Security notes

- No credentials are stored by this script. Authentication relies entirely on `gh auth` tokens managed by the GitHub CLI.
- Do not commit `gh` tokens or Personal Access Tokens to this repository.
- All API calls are read-only; the script never writes to any repository.
