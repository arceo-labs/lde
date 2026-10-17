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
Usage: $(basename "$0") <package> [options]

Search for a package version across GitHub org repositories.

Arguments:
  <package>             Package name to search for (required)

Options:
  -o, --orgs <list>     Comma-separated orgs to search (default: built-in list)
  -t, --dep-type <t>    Section to search in package.json:
                          dependencies | devDependencies | peerDependencies | all
                          (default: all)
  -m, --manifest <f>    Manifest filename to search (default: package.json)
                          Supports: package.json, requirements.txt, go.mod, Pipfile
      --node            Shortcut for --manifest package.json
      --python          Shortcut for --manifest requirements.txt
      --go              Shortcut for --manifest go.mod
  -F, --format <fmt>    Output format: text | csv (default: text)
  -h, --help            Show this help message

Examples:
  $(basename "$0") axios
  $(basename "$0") lodash --dep-type devDependencies
  $(basename "$0") express --orgs example-org,another-org
  $(basename "$0") requests --python
  $(basename "$0") axios --format csv > report.csv
EOF
}

PACKAGE=""
ORGS=()
DEP_TYPE="all"
MANIFEST="package.json"
FORMAT="text"

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage; exit 0 ;;
    -o|--orgs)
      IFS=',' read -ra ORGS <<< "$2"; shift 2 ;;
    -t|--dep-type)
      DEP_TYPE="$2"; shift 2 ;;
    -m|--manifest)
      MANIFEST="$2"; shift 2 ;;
    --node)
      MANIFEST="package.json"; shift ;;
    --python)
      MANIFEST="requirements.txt"; shift ;;
    --go)
      MANIFEST="go.mod"; shift ;;
    -F|--format)
      FORMAT="$2"; shift 2 ;;
    -*)
      echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
      if [[ -z "$PACKAGE" ]]; then
        PACKAGE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; usage >&2; exit 1
      fi ;;
  esac
done

if [[ -z "$PACKAGE" ]]; then
  echo "Error: <package> argument is required." >&2
  usage >&2
  exit 1
fi

if [[ ${#ORGS[@]} -eq 0 ]]; then
  ORGS=("${DEFAULT_ORGS[@]}")
fi

# Validate dep-type
if [[ "$MANIFEST" == "package.json" && "$DEP_TYPE" != "all" ]]; then
  case "$DEP_TYPE" in
    dependencies|devDependencies|peerDependencies) ;;
    *)
      echo "Error: --dep-type must be dependencies, devDependencies, peerDependencies, or all." >&2
      exit 1 ;;
  esac
fi

extract_version() {
  local content="$1"
  local pkg="$2"
  local manifest="$3"
  local dep_type="$4"

  case "$manifest" in
    package.json)
      if [[ "$dep_type" == "all" ]]; then
        echo "$content" | grep -E "\"${pkg}\"\s*:" | head -n 1 | awk -F'"' '{print $4}'
      else
        echo "$content" | jq -r ".${dep_type}[\"${pkg}\"] // empty" 2>/dev/null
      fi
      ;;
    requirements.txt)
      echo "$content" | grep -iE "^${pkg}[=><~!]" | head -n 1 | sed -E 's/^[^=><~!]*([=><~!]+)/\1/'
      ;;
    go.mod)
      echo "$content" | grep -E "^\s+?${pkg} v" | head -n 1 | awk '{print $2}'
      ;;
    Pipfile)
      echo "$content" | grep -iE "^${pkg}\s*=" | head -n 1 | awk -F'"' '{print $2}'
      ;;
    *)
      echo "$content" | grep -i "${pkg}" | head -n 1
      ;;
  esac
}

if [[ "$FORMAT" == "csv" ]]; then
  echo "org,repo,filepath,version"
else
  echo "Searching for '${PACKAGE}' (manifest: ${MANIFEST}, dep-type: ${DEP_TYPE}) across ${#ORGS[@]} org(s)..."
  echo "=================================================================="
fi

for ORG_NAME in "${ORGS[@]}"; do
  [[ "$FORMAT" == "text" ]] && echo "Scanning: $ORG_NAME"

  gh repo list "$ORG_NAME" --limit 4000 --json name --jq '.[].name' 2>/dev/null | while read -r repo; do

    BRANCH=$(gh repo view "$ORG_NAME/$repo" --json defaultBranchRef --jq .defaultBranchRef.name 2>/dev/null) || true
    [[ -z "$BRANCH" ]] && continue

    files=$(gh api "repos/$ORG_NAME/$repo/git/trees/$BRANCH?recursive=1" \
      --jq ".tree[]? | select(.path | endswith(\"$MANIFEST\")) | .path" 2>/dev/null) || true

    [[ -z "$files" ]] && continue

    echo "$files" | while read -r filepath; do
      content=$(gh api "repos/$ORG_NAME/$repo/contents/$filepath" \
        -H "Accept: application/vnd.github.v3.raw" 2>/dev/null) || true

      version=$(extract_version "$content" "$PACKAGE" "$MANIFEST" "$DEP_TYPE") || true

      if [[ -n "$version" ]]; then
        if [[ "$FORMAT" == "csv" ]]; then
          echo "${ORG_NAME},${repo},${filepath},${version}"
        else
          echo "  $ORG_NAME/$repo — $filepath: $version"
        fi
      fi
    done
  done

  [[ "$FORMAT" == "text" ]] && echo ""
done

[[ "$FORMAT" == "text" ]] && echo "=================================================================="
[[ "$FORMAT" == "text" ]] && echo "Search complete."
