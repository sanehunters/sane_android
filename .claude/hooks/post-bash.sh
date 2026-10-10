#!/usr/bin/env bash
# PostToolUse(Bash): push after every commit; remind about adb-as-proof; show coverage after a tracker edit.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
CMD="$(json_get tool_input.command)"
cd "$REPO" || exit 0
ctx=""
add() { ctx="${ctx}${ctx:+ }$1"; }

if echo "$CMD" | grep -Eq '(^|[;&| ])git[[:space:]]+commit' && ! echo "$CMD" | grep -q 'git[[:space:]]*push'; then
  if git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
    ahead="$(git rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"
    if [ "${ahead:-0}" -gt 0 ]; then
      if out="$(git push 2>&1)"; then add "auto-pushed $ahead commit(s) (R7)."; else add "AUTO-PUSH FAILED: $(echo "$out" | tail -1 | cut -c1-120). Push manually before you stop."; fi
    fi
  else
    add "No upstream configured — set one (git push -u origin <branch>) so evidence leaves this machine."
  fi
fi
if echo "$CMD" | grep -Eq 'adb[[:space:]]+shell[[:space:]]+(am[[:space:]]+(start|broadcast|startservice|start-foreground-service)|content[[:space:]]+(query|insert|update|delete|call|read)|cmd[[:space:]]+content)'; then
  add "Reminder (R3): adb runs as the shell UID. What you just observed is discovery, not AM-03 — re-prove from the zero-permission attacker app before recording result=finding."
fi
if echo "$CMD" | grep -Eq 'checklist-status\.csv'; then
  E="$(active_engagement)"
  [ -n "$E" ] && [ -f "$E/checklist-status.csv" ] && add "coverage: $(python3 scripts/coverage.py "$E/checklist-status.csv" --brief 2>/dev/null)"
fi
if echo "$CMD" | grep -Eq 'engagement\.json' && echo "$CMD" | grep -Eq '"phase"|phase'; then
  add "Phase changed? Make sure the previous gate's exit condition was genuinely met and assessment-status.md says so."
fi
[ -z "$ctx" ] && exit 0
python3 -c 'import json,sys; print(json.dumps({"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":sys.argv[1]}}))' "$ctx"
exit 0
