#!/usr/bin/env bash
set -euo pipefail

DEFAULT_ORGS=(
  "example-org"
  "example-org-hris"
  "example-org-test"
  "another-org"
  "example-website"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Enumerate manifest files found across GitHub org repositories.

Options:
  -o, --orgs <list>     Comma-separated orgs to search (default: built-in list)
  -m, --manifest <f>    Manifest filename to search; repeatable for multiple
                          Supports: package.json, requirements.txt, go.mod, Pipfile
      --node            Shortcut for --manifest package.json (clears other manifests)
      --python          Shortcut for --manifest requirements.txt (clears other manifests)
      --go              Shortcut for --manifest go.mod (clears other manifests)
  -r, --repo <pattern>  Filter repos by name (substring match)
  -F, --format <fmt>    Output format: text | csv (default: text)
  -h, --help            Show this help message

  Default (no --manifest/--node/--python/--go): searches package.json + requirements.txt

Examples:
  $(basename "$0")
  $(basename "$0") --python
  $(basename "$0") --repo my-service
  $(basename "$0") --orgs example-org,another-org --manifest go.mod
  $(basename "$0") --python --format csv > report.csv
EOF
}

ORGS=()
MANIFESTS=()
FORMAT="text"
REPO_FILTER=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage; exit 0 ;;
    -o|--orgs)
      IFS=',' read -ra ORGS <<< "$2"; shift 2 ;;
    -m|--manifest)
      MANIFESTS+=("$2"); shift 2 ;;
    --node)
      MANIFESTS=("package.json"); shift ;;
    --python)
      MANIFESTS=("requirements.txt"); shift ;;
    --go)
      MANIFESTS=("go.mod"); shift ;;
    -r|--repo)
      REPO_FILTER="$2"; shift 2 ;;
    -F|--format)
      FORMAT="$2"; shift 2 ;;
    -*)
      echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
      echo "Unexpected argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ ${#ORGS[@]} -eq 0 ]]; then
  ORGS=("${DEFAULT_ORGS[@]}")
fi

if [[ ${#MANIFESTS[@]} -eq 0 ]]; then
  MANIFESTS=("package.json" "requirements.txt")
fi

# Build a single jq filter that matches any of the target manifests.
jq_cond=""
for m in "${MANIFESTS[@]}"; do
  m_esc="${m//\"/\\\"}"
  if [[ -z "$jq_cond" ]]; then
    jq_cond="endswith(\"${m_esc}\")"
  else
    jq_cond="${jq_cond} or endswith(\"${m_esc}\")"
  fi
done
JQ_FILTER=".tree[]? | select(.path | (${jq_cond})) | .path"

if [[ "$FORMAT" == "csv" ]]; then
  echo "org,repo,filepath"
else
  echo "Enumerating manifests (${MANIFESTS[*]}) across ${#ORGS[@]} org(s)..."
  [[ -n "$REPO_FILTER" ]] && echo "Repo filter: ${REPO_FILTER}"
  echo "=================================================================="
fi

for ORG_NAME in "${ORGS[@]}"; do
  [[ "$FORMAT" == "text" ]] && echo "Scanning: $ORG_NAME"

  repo_list=$(gh repo list "$ORG_NAME" --limit 4000 --json name --jq '.[].name' 2>/dev/null) || true

  if [[ -n "$REPO_FILTER" ]]; then
    repo_list=$(echo "$repo_list" | grep -F "$REPO_FILTER" || true)
  fi

  [[ -z "$repo_list" ]] && { [[ "$FORMAT" == "text" ]] && echo ""; continue; }

  echo "$repo_list" | while read -r repo; do
    BRANCH=$(gh repo view "$ORG_NAME/$repo" --json defaultBranchRef --jq .defaultBranchRef.name 2>/dev/null) || true
    [[ -z "$BRANCH" ]] && continue

    files=$(gh api "repos/$ORG_NAME/$repo/git/trees/$BRANCH?recursive=1" \
      --jq "$JQ_FILTER" 2>/dev/null) || true

    [[ -z "$files" ]] && continue

    echo "$files" | while read -r filepath; do
      if [[ "$FORMAT" == "csv" ]]; then
        echo "${ORG_NAME},${repo},${filepath}"
      else
        echo "  $ORG_NAME/$repo — $filepath"
      fi
    done
  done

  [[ "$FORMAT" == "text" ]] && echo ""
done

[[ "$FORMAT" == "text" ]] && echo "=================================================================="
[[ "$FORMAT" == "text" ]] && echo "Enumeration complete."
