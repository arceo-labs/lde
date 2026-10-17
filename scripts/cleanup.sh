#!/usr/bin/env bash
# Reclaim disk space across every layer that this app writes to.
#
# Usage: ./scripts/cleanup.sh            # safe defaults
#        ./scripts/cleanup.sh --aggressive  # also wipe persistent caches
#
# Safe defaults preserve the cross-run caches (.cache/npm, .cache/npm-registry,
# .cache/boms) so subsequent runs benefit from prior work. Aggressive mode
# wipes those too — first run after will be cold-cache slow.

set -euo pipefail

cd "$(dirname "$0")/.."

AGGRESSIVE=0
if [[ "${1:-}" == "--aggressive" ]]; then
    AGGRESSIVE=1
fi

human() { du -sh "$1" 2>/dev/null | cut -f1; }

echo "=== Before ==="
df -h / | tail -2
echo

# --------------------------------------------------------------------
# 1. App-managed temp state — always safe to wipe.
# --------------------------------------------------------------------

echo "[1/5] Wiping per-run sandboxes ($(human "${TMPDIR}/dummy-repos" || echo none))"
rm -rf "${TMPDIR}/dummy-repos"/* 2>/dev/null || true

echo "[2/5] Wiping cidfile registry ($(human /tmp/depexplorer-cids || echo none))"
rm -rf /tmp/depexplorer-cids/* 2>/dev/null || true

# --------------------------------------------------------------------
# 2. Docker — image layers, build cache, anonymous volumes.
#    This is usually where the real bloat is (multi-GB per ORT build,
#    each `docker compose build` leaves intermediate layers behind).
# --------------------------------------------------------------------

echo "[3/5] Docker prune (dangling images, stopped containers, build cache)"
if command -v docker >/dev/null; then
    docker container prune -f >/dev/null 2>&1 || true
    docker image prune -f >/dev/null 2>&1 || true
    docker builder prune -f >/dev/null 2>&1 || true
    # Anonymous volumes (created by ORT image's VOLUME declarations etc.)
    docker volume ls -q --filter dangling=true | xargs -r docker volume rm >/dev/null 2>&1 || true
    echo "    docker system df:"
    docker system df 2>&1 | sed 's/^/      /'
else
    echo "    (docker CLI not in PATH; skipping)"
fi

# --------------------------------------------------------------------
# 3. Old run log dirs — keep the most recent N per the retention setting.
# --------------------------------------------------------------------

echo "[4/5] Pruning runs/ log dirs (keeping 5 most recent)"
if [[ -d runs ]]; then
    # macOS-compatible: list by mtime desc, skip first 5, rm the rest.
    /bin/ls -t runs 2>/dev/null | tail -n +6 | while read -r d; do
        rm -rf "runs/$d" 2>/dev/null || true
    done
fi

# --------------------------------------------------------------------
# 4. Aggressive: nuke persistent caches. Costs you the cross-run speedup
#    until they refill.
# --------------------------------------------------------------------

if [[ $AGGRESSIVE -eq 1 ]]; then
    echo "[5/5] AGGRESSIVE: wiping persistent caches"
    for sub in npm npm-registry boms ort go go-build pip poetry pipenv gradle m2 yarn xdg; do
        if [[ -d ".cache/$sub" ]]; then
            sz=$(human ".cache/$sub")
            echo "    .cache/$sub ($sz) → wiping"
            rm -rf ".cache/$sub"/* 2>/dev/null || true
        fi
    done
else
    echo "[5/5] Persistent caches preserved (pass --aggressive to wipe)"
    echo "    .cache/npm:          $(human .cache/npm)"
    echo "    .cache/npm-registry: $(human .cache/npm-registry)"
    echo "    .cache/boms:         $(human .cache/boms)"
fi

echo
echo "=== After ==="
df -h / | tail -2
