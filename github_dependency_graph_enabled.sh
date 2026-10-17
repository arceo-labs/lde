#!/bin/bash

# Define your list of organizations
ALL_ORGS=(
  "YOURORGNAMEHERE1"
  "YOURORGNAMEHERE2"
)

CSV_MODE=false
FILTER_ORG=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --csv)
      CSV_MODE=true
      shift
      ;;
    --org)
      if [[ -z "${2:-}" ]]; then
        echo "Error: --org requires a value" >&2
        exit 1
      fi
      # Validate org name: only alphanumeric, hyphens, and dots
      if [[ ! "$2" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: invalid org name '$2'" >&2
        exit 1
      fi
      FILTER_ORG="$2"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--org <org-name>] [--csv]" >&2
      exit 1
      ;;
  esac
done

# Build the list of orgs to scan
if [[ -n "$FILTER_ORG" ]]; then
  ORGS=("$FILTER_ORG")
else
  ORGS=("${ALL_ORGS[@]}")
fi

# Fetch SBOM status with 429 retry logic (max 5 attempts)
fetch_status() {
  local org="$1"
  local repo="$2"
  local max_retries=5
  local attempt=0
  local status

  while [[ $attempt -lt $max_retries ]]; do
    status=$(gh api -i "repos/$org/$repo/dependency-graph/sbom" 2>/dev/null | head -n 1 | awk '{print $2}')
    if [[ "$status" == "429" ]]; then
      attempt=$((attempt + 1))
      if [[ $attempt -lt $max_retries ]]; then
        [[ "$CSV_MODE" == false ]] && echo "  ⏳ Rate limited (429) for $org/$repo — retrying in 30s (attempt $attempt/$max_retries)..." >&2
        sleep 30
      fi
    else
      echo "$status"
      return
    fi
  done
  echo "429"
}

if [[ "$CSV_MODE" == false ]]; then
  echo "📊 Auditing Dependency Graph status across organization(s): ${ORGS[*]}"
  echo "=================================================================="
else
  echo "org/repo,enabled,archived"
fi

for ORG_NAME in "${ORGS[@]}"; do
  [[ "$CSV_MODE" == false ]] && echo "🏢 Scanning Organization: $ORG_NAME"
  [[ "$CSV_MODE" == false ]] && echo "------------------------------------------------------------------"

  gh repo list "$ORG_NAME" --limit 4000 --json name,isArchived --jq '.[] | [.name, .isArchived] | @tsv' 2>/dev/null | while IFS=$'\t' read -r repo archived; do
    STATUS=$(fetch_status "$ORG_NAME" "$repo")

    if [[ "$CSV_MODE" == true ]]; then
      if [[ "$STATUS" == "200" ]]; then
        echo "$ORG_NAME/$repo,true,$archived"
      elif [[ "$STATUS" == "404" || "$STATUS" == "403" ]]; then
        echo "$ORG_NAME/$repo,false,$archived"
      else
        echo "$ORG_NAME/$repo,unknown($STATUS),$archived"
      fi
    else
      if [[ "$archived" == "true" ]]; then
        if [[ "$STATUS" == "200" ]]; then
          echo "📦 $ORG_NAME/$repo — ARCHIVED (Dependency Graph enabled)"
        elif [[ "$STATUS" == "404" || "$STATUS" == "403" ]]; then
          echo "📦 $ORG_NAME/$repo — ARCHIVED (Dependency Graph disabled)"
        elif [[ "$STATUS" == "429" ]]; then
          echo "📦 $ORG_NAME/$repo — ARCHIVED (Rate limited after retries)"
        else
          echo "📦 $ORG_NAME/$repo — ARCHIVED (Unknown status, HTTP $STATUS)"
        fi
      elif [[ "$STATUS" == "200" ]]; then
        echo "✅ $ORG_NAME/$repo — ENABLED"
      elif [[ "$STATUS" == "404" || "$STATUS" == "403" ]]; then
        echo "❌ $ORG_NAME/$repo — DISABLED"
      elif [[ "$STATUS" == "429" ]]; then
        echo "⏱️ $ORG_NAME/$repo — Rate limited after retries"
      else
        echo "⚠️ $ORG_NAME/$repo — Unknown status (HTTP $STATUS)"
      fi
    fi
  done

  [[ "$CSV_MODE" == false ]] && echo " "
done

if [[ "$CSV_MODE" == false ]]; then
  echo "=================================================================="
  echo "🏁 Dependency Graph audit complete!"
fi
