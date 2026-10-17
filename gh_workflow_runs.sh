#!/usr/bin/env bash
# gh_workflow_runs.sh
#
# Lists GitHub Actions workflow runs across multiple GitHub organizations
# that were created within a specified ISO 8601 time window.
#
# Usage:
#   ./gh_workflow_runs.sh [options] <start> <end>
#
# Options:
#   --org ORG         Scan only this org instead of the default list
#   --repo REPO       Scan only this repo (requires --org)
#   --testrun         Connectivity check: scope to YOURORGNAMEHERE1/YOURTESTREPOHERE
#   --all-to-file     Download raw logs for every run found into ./workflow-logs/
#
# Examples:
#   ./gh_workflow_runs.sh 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z
#   ./gh_workflow_runs.sh --org YOURORGNAMEHERE1 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z
#   ./gh_workflow_runs.sh --org YOURORGNAMEHERE1 --repo YOURTESTREPOHERE 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z
#   ./gh_workflow_runs.sh --all-to-file --org YOURORGNAMEHERE1 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z
#   ./gh_workflow_runs.sh --testrun 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z
#
# Prerequisites: gh CLI authenticated with access to the listed orgs.

DEFAULT_ORGS=(
  "YOURORGNAMEHERE1"
  "YOURORGNAMEHERE2"
  "YOURORGNAMEHERE3"
  "YOURORGNAMEHERE4"
  "YOURORGNAMEHERE5"
)

# ── Argument parsing ──────────────────────────────────────────────────────────
TESTRUN=false
ALL_TO_FILE=false
OPT_ORG=""
OPT_REPO=""
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --testrun)      TESTRUN=true;       shift ;;
    --all-to-file)  ALL_TO_FILE=true;   shift ;;
    --org)          OPT_ORG="$2";       shift 2 ;;
    --org=*)        OPT_ORG="${1#*=}";  shift ;;
    --repo)         OPT_REPO="$2";      shift 2 ;;
    --repo=*)       OPT_REPO="${1#*=}"; shift ;;
    -*)             echo "❌  Unknown option: $1"; exit 1 ;;
    *)              POSITIONAL+=("$1"); shift ;;
  esac
done

START="${POSITIONAL[0]:-}"
END="${POSITIONAL[1]:-}"

# ── Validation ───────────────────────────────────────────────────────────────
if [[ -z "$START" || -z "$END" ]]; then
  echo "Usage: $(basename "$0") [--org ORG] [--repo REPO] [--testrun] <start> <end>"
  echo "       $(basename "$0") 2026-03-21T00:00:00Z 2026-03-22T00:00:00Z"
  exit 1
fi

ISO_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
if ! [[ "$START" =~ $ISO_RE && "$END" =~ $ISO_RE ]]; then
  echo "❌  Timestamps must be in ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ"
  exit 1
fi

if [[ -n "$OPT_REPO" && -z "$OPT_ORG" ]]; then
  echo "❌  --repo requires --org to be set"
  exit 1
fi

DATE_RANGE="${START}..${END}"

# ── Resolve effective org list and per-org repo source ────────────────────────
# If --org is given, shrink the list to that single org.
# If --repo is also given, skip the API repo-listing and use it directly.
if [[ -n "$OPT_ORG" ]]; then
  ORGS=("$OPT_ORG")
else
  ORGS=("${DEFAULT_ORGS[@]}")
fi

# ── Helpers ──────────────────────────────────────────────────────────────────
# Sets global _ICON for a given conclusion + status.
# Avoids a subshell fork by writing to a global variable instead of stdout.
resolve_icon() {
  local conclusion="$1" status="$2"
  case "$conclusion" in
    success)         _ICON="✅" ;;
    failure)         _ICON="❌" ;;
    cancelled)       _ICON="🚫" ;;
    skipped)         _ICON="⏭" ;;
    timed_out)       _ICON="⏰" ;;
    action_required) _ICON="⚠️ " ;;
    *)
      case "$status" in
        in_progress) _ICON="🔄" ;;
        queued)      _ICON="⏳" ;;
        waiting)     _ICON="🕐" ;;
        *)           _ICON="⬜" ;;
      esac ;;
  esac
}

# Download raw logs for a single run to LOG_DIR/<org>-<repo>-<run_id>.log
# Prints a status line; errors are noted but do not abort the scan.
download_run_logs() {
  local org="$1" repo="$2" run_id="$3"
  local outfile="$LOG_DIR/${org}-${repo}-${run_id}.log"
  printf "       💾  Saving logs → %s … " "$outfile"
  if gh run view "$run_id" --log --repo "$org/$repo" > "$outfile" 2>&1; then
    printf "done (%s)\n" "$(wc -l < "$outfile" | tr -d ' ') lines)"
  else
    printf "failed (see %s)\n" "$outfile"
  fi
}

# Print all workflow runs for a single org/repo within DATE_RANGE.
# Increments the caller's org_total and grand_total via the global vars.
scan_repo() {
  local org="$1" repo="$2"
  while IFS=$'\t' read -r name run_id status conclusion event actor created branch url; do
    resolve_icon "$conclusion" "$status"
    printf "\n  %s  %s  ·  %s\n"           "$_ICON" "$org/$repo" "$name"
    printf "       Run %-12s  trigger=%-15s  branch=%s\n" "$run_id" "$event" "$branch"
    printf "       Actor: %-25s  result=%s\n"             "$actor"  "${conclusion:--}"
    printf "       Started  : %s\n"                       "$created"
    printf "       Run URL  : %s\n"                       "$url"
    printf "       CLI logs : gh run view %s --log --repo %s/%s\n" "$run_id" "$org" "$repo"
    if [[ "$ALL_TO_FILE" == true ]]; then
      download_run_logs "$org" "$repo" "$run_id"
    fi
    ((org_total++))   || true
    ((grand_total++)) || true
  done < <(
    gh api \
      --paginate \
      --method GET \
      "repos/$org/$repo/actions/runs" \
      -f "created=${DATE_RANGE}" \
      -f "per_page=100" \
      --jq '.workflow_runs[] | [
        .name,
        (.id | tostring),
        .status,
        (.conclusion // "-"),
        .event,
        .actor.login,
        .created_at,
        (.head_branch // "-"),
        .html_url
      ] | @tsv' 2>/dev/null
  )
}

# ── All-to-file setup & confirmation ─────────────────────────────────────────
LOG_DIR="./workflow-logs"

if [[ "$ALL_TO_FILE" == true && "$TESTRUN" != true ]]; then
  echo ""
  echo "⚠️   --all-to-file is enabled."
  echo "    This will call  gh run view --log  for EVERY run found in the window."
  echo "    Large time windows or busy orgs can result in hundreds of API calls"
  echo "    and take a significant amount of time."
  echo ""
  echo "    Logs will be saved to: $LOG_DIR/"
  echo ""
  printf "    Continue? [y/N] "
  read -r confirm
  case "$confirm" in
    [yY]|[yY][eE][sS]) ;;
    *)
      echo "Aborted."
      exit 0
      ;;
  esac
  mkdir -p "$LOG_DIR"
  echo "    📁  Log directory: $(pwd)/$LOG_DIR"
  echo ""
fi

# ── Test-run override ─────────────────────────────────────────────────────────
TEST_ORG="YOURORGNAMEHERE1"
TEST_REPO="YOURTESTREPOHERE"

if [[ "$TESTRUN" == true ]]; then
  echo ""
  echo "🧪  TEST RUN  —  scoped to $TEST_ORG/$TEST_REPO"
  echo "══════════════════════════════════════════════════════════════════"
  echo "    Window : $START  →  $END"
  echo ""

  if ! gh api "repos/$TEST_ORG/$TEST_REPO" --jq '.full_name' &>/dev/null; then
    echo "❌  Cannot reach $TEST_ORG/$TEST_REPO — check gh auth and permissions"
    exit 1
  fi
  echo "  ✅  Auth OK  ·  repo accessible"

  org_total=0; grand_total=0
  scan_repo "$TEST_ORG" "$TEST_REPO"

  echo ""
  echo "══════════════════════════════════════════════════════════════════"
  if [[ "$grand_total" -eq 0 ]]; then
    echo "  ℹ️   No workflow runs found in this window — try widening the range"
  else
    printf "🏁  Test complete  ·  %d run(s) found\n" "$grand_total"
  fi
  echo ""
  exit 0
fi

# ── Main ─────────────────────────────────────────────────────────────────────
echo ""
echo "🔍  GitHub Actions runs:  $START  →  $END"
echo "══════════════════════════════════════════════════════════════════"

grand_total=0

for ORG_NAME in "${ORGS[@]}"; do
  echo ""
  echo "🏢  $ORG_NAME"
  echo "──────────────────────────────────────────────────────────────────"

  org_total=0

  if [[ -n "$OPT_REPO" ]]; then
    # Single repo supplied — skip the API listing entirely
    scan_repo "$ORG_NAME" "$OPT_REPO"
  else
    # Discover all non-archived repos in this org.
    # Uses a while-read loop instead of mapfile for bash 3 compatibility
    # (macOS ships bash 3.2; mapfile requires bash 4+).
    repos=()
    while IFS= read -r r; do
      repos+=("$r")
    done < <(
      gh repo list "$ORG_NAME" --limit 4000 --no-archived \
        --json name --jq '.[].name' 2>/dev/null
    )

    if [[ "${#repos[@]}" -eq 0 ]]; then
      echo "  ⚠️   No repos found or insufficient access"
      continue
    fi

    for repo in "${repos[@]}"; do
      scan_repo "$ORG_NAME" "$repo"
    done
  fi

  echo ""
  if [[ "$org_total" -eq 0 ]]; then
    echo "  ℹ️   No workflow runs found in this window"
  else
    echo "  ──  $org_total run(s) in $ORG_NAME"
  fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════"
printf "🏁  Done  ·  Total workflow runs across all orgs: %d\n" "$grand_total"
if [[ "$ALL_TO_FILE" == true && "$grand_total" -gt 0 ]]; then
  printf "📁  Logs saved to: %s/\n" "$(pwd)/$LOG_DIR"
fi
echo ""
