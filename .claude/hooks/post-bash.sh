#!/usr/bin/env bash
# PostToolUse(Bash): push the EVIDENCE repo after every commit (only to its private remote, never to the methodology
# origin); remind about adb-as-proof; show coverage after a tracker edit.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
CMD="$(json_get tool_input.command)"
cd "$REPO" || exit 0
ctx=""
add() { ctx="${ctx}${ctx:+ }$1"; }
CMD_NQ="$(printf '%s' "$CMD" | sed -E "s/\"[^\"]*\"//g; s/'[^']*'//g")"

if echo "$CMD_NQ" | grep -Eq "(^|[;&| ])git${GIT_OPTS}[[:space:]]+commit([[:space:]]|$)" && ! echo "$CMD_NQ" | grep -Eq "git${GIT_OPTS}[[:space:]]+push"; then
  E="$(active_engagement)"
  if is_evidence_repo "$E"; then
    remote="$(evidence_remote "$E")"
    if [ "${SANE_PUSH:-1}" = "0" ]; then
      add "auto-push disabled (SANE_PUSH=0): evidence is committed locally; push the evidence repo yourself before you stop."
    elif [ -z "$remote" ]; then
      add "$NO_REMOTE_MSG"
    elif [ -n "$(methodology_origin)" ] && [ "$remote" = "$(methodology_origin)" ]; then
      add "REFUSED to push: the evidence remote is the methodology origin ($remote), which is public. Point it at a private repository."
    else
      git -C "$E" remote get-url origin >/dev/null 2>&1 || git -C "$E" remote add origin "$remote" 2>/dev/null || true
      if git -C "$E" rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
        ahead="$(git -C "$E" rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"
        [ "${ahead:-0}" -gt 0 ] && { if out="$(git -C "$E" push 2>&1)"; then add "auto-pushed $ahead evidence commit(s) to $remote (R7)."; else add "AUTO-PUSH FAILED: $(echo "$out" | tail -1 | cut -c1-120). Push the evidence repo manually before you stop."; fi; }
      else
        if out="$(git -C "$E" push -u origin HEAD 2>&1)"; then add "auto-pushed the evidence repo to $remote and set its upstream (R7)."; else add "AUTO-PUSH FAILED: $(echo "$out" | tail -1 | cut -c1-120). Push the evidence repo manually before you stop."; fi
      fi
    fi
  elif [ -n "$E" ]; then
    add "The engagement folder is not its own git repository: evidence must not be committed to the methodology repo (public). Migrate it per BugBountyTarget/README.md."
  fi
fi
if echo "$CMD" | grep -Eq 'adb([[:space:]]+-[sdetHP][[:space:]]*[^[:space:]]+)*[[:space:]]+shell[[:space:]]+(am[[:space:]]+(start|broadcast|startservice|start-foreground-service)|content[[:space:]]+(query|insert|update|delete|call|read)|cmd[[:space:]]+content)'; then
  add "Reminder (R3): adb runs as the shell UID. What you just observed is discovery, not AM-03 — re-prove from the zero-permission attacker app before recording result=finding."
fi
if echo "$CMD" | grep -Eq 'scripts/mark\.py|checklist-status\.csv|coverage\.py[^;&|]*--merge|gate\.py[^;&|]*--pass'; then
  E="${E:-$(active_engagement)}"
  [ -n "$E" ] && [ -f "$E/checklist-status.csv" ] && add "coverage: $(python3 scripts/coverage.py "$E/checklist-status.csv" --components "$E/inventory" --brief 2>/dev/null)"
fi
if echo "$CMD" | grep -Eq 'engagement\.json' && echo "$CMD" | grep -Eq '"phase"|phase'; then
  add "Phase changed? Make sure the previous gate's exit condition was genuinely met (scripts/gate.py) and assessment-status.md says so."
fi
[ -z "$ctx" ] && exit 0
python3 -c 'import json,sys; print(json.dumps({"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":sys.argv[1]}}))' "$ctx"
exit 0
