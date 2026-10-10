#!/usr/bin/env bash
# Stop: refuse to end the session while engagement state is unsaved or unpushed (R7). Exit 2 blocks the stop once.
# Also usable manually: bash .claude/hooks/stop-guard.sh --manual
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
if [ "${1:-}" = "--manual" ]; then HOOK_INPUT='{}'; ACTIVE=false; else HOOK_INPUT="$(cat 2>/dev/null || true)"; ACTIVE="$(json_get stop_hook_active)"; fi
cd "$REPO" || exit 0
[ "$ACTIVE" = "true" ] || [ "$ACTIVE" = "True" ] && exit 0      # second attempt: let the session end
E="$(active_engagement)"; [ -z "$E" ] && exit 0
rel="${E#$REPO/}"
unc="$(git status --porcelain -- "$rel" 2>/dev/null | wc -l | tr -d ' ')"
ahead=0; git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1 && ahead="$(git rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"
msgs=()
[ "${unc:-0}" -gt 0 ] && msgs+=("$unc uncommitted change(s) under $rel")
[ "${ahead:-0}" -gt 0 ] && msgs+=("$ahead unpushed commit(s)")
if [ -f "$E/report/assessment-status.md" ] && [ "$E/checklist-status.csv" -nt "$E/report/assessment-status.md" ]; then
  msgs+=("checklist-status.csv is newer than report/assessment-status.md — update COMPLETED / NEXT TARGET / BLOCKERS")
fi
if [ "${#msgs[@]}" -gt 0 ]; then
  {
    echo "Do not stop yet (R7 — state lives on disk, pushed):"
    for m in "${msgs[@]}"; do echo "  - $m"; done
    echo "Do this, then stop: update $rel/report/assessment-status.md; git add $rel; git commit -m '<Target> <phase>: <what was settled>'; git push."
    echo "If the push cannot succeed (no network/remote), say so explicitly in your final message."
  } >&2
  [ "${1:-}" = "--manual" ] && exit 1
  exit 2
fi
exit 0
