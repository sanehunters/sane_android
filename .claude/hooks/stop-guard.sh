#!/usr/bin/env bash
# Stop: refuse to end the session while evidence is uncommitted, or unpushed when an evidence remote exists (R7).
# Exit 2 blocks the stop once. Also usable manually: bash .claude/hooks/stop-guard.sh --manual
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
if [ "${1:-}" = "--manual" ]; then HOOK_INPUT='{}'; ACTIVE=false; else HOOK_INPUT="$(cat 2>/dev/null || true)"; ACTIVE="$(json_get stop_hook_active)"; fi
cd "$REPO" || exit 0
[ "$ACTIVE" = "true" ] || [ "$ACTIVE" = "True" ] && exit 0      # second attempt: let the session end
E="$(active_engagement)"; [ -z "$E" ] && exit 0
rel="${E#$REPO/}"
msgs=(); remote=""; ahead=0
if is_evidence_repo "$E"; then
  unc="$(git -C "$E" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  remote="$(evidence_remote "$E")"
  if [ -n "$remote" ]; then
    if git -C "$E" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
      ahead="$(git -C "$E" rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"
    else
      ahead="$(git -C "$E" rev-list --count HEAD 2>/dev/null || echo 0)"   # a remote but no upstream yet: nothing has left this machine
    fi
  fi
else
  # legacy folder tracked by the methodology checkout (never pushed — the methodology repo is public): only the commit matters
  unc="$(git status --porcelain -- "$rel" 2>/dev/null | wc -l | tr -d ' ')"
fi
[ "${unc:-0}" -gt 0 ] && msgs+=("$unc uncommitted change(s) in the evidence repo $rel")
[ "${ahead:-0}" -gt 0 ] && msgs+=("$ahead evidence commit(s) not pushed to $remote")
if [ -f "$E/report/assessment-status.md" ] && [ "$E/checklist-status.csv" -nt "$E/report/assessment-status.md" ]; then
  msgs+=("checklist-status.csv is newer than report/assessment-status.md — update COMPLETED / NEXT TARGET / BLOCKERS")
fi
if [ "${#msgs[@]}" -gt 0 ]; then
  {
    echo "Do not stop yet (R7 — state lives on disk, committed in the evidence repo):"
    for m in "${msgs[@]}"; do echo "  - $m"; done
    echo "Do this, then stop: update $rel/report/assessment-status.md; git -C \"$E\" add -A; git -C \"$E\" commit -m '<Target> <phase>: <what was settled>'$([ -n "$remote" ] && echo "; git -C \"$E\" push")."
    if [ -n "$remote" ]; then echo "If the push cannot succeed (no network), say so explicitly in your final message."
    else echo "$NO_REMOTE_MSG. Local-only evidence: say so in your final message."; fi
  } >&2
  [ "${1:-}" = "--manual" ] && exit 1
  exit 2
fi
exit 0
