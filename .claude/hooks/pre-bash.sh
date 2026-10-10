#!/usr/bin/env bash
# PreToolUse(Bash): refuse the commands that would destroy evidence or leak artefacts. Exit 2 = block, stderr goes to the model.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
CMD="$(json_get tool_input.command)"
[ -z "$CMD" ] && exit 0
cd "$REPO" || exit 0
deny() { echo "BLOCKED by .claude/hooks/pre-bash.sh: $1" >&2; exit 2; }

# destructive git on the methodology or the evidence
echo "$CMD" | grep -Eq '(^|[;&| ])git[[:space:]]+(push[^;&|]*(--force|-f\b)|reset[[:space:]]+--hard|clean[[:space:]]+-[a-z]*f|checkout[[:space:]]+--[[:space:]]+\.|branch[[:space:]]+-D)' && deny "destructive git ($CMD). Evidence and methodology are append-only; use a new commit."
echo "$CMD" | grep -Eq '(^|[;&| ])rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*[[:space:]]+[^;&|]*(BugBountyTarget|checklist/|docs/|json/|cards/)' && deny "recursive delete inside the repository ($CMD)."

# committing forbidden artefacts or live-looking credentials
if echo "$CMD" | grep -Eq '(^|[;&| ])git[[:space:]]+(commit|add)'; then
  bad="$(git status --porcelain 2>/dev/null | awk '{print $2}' | grep -Ei "$FORBIDDEN_RE" || true)"
  if [ -n "$bad" ] && echo "$CMD" | grep -Eq 'git[[:space:]]+add[[:space:]]+(-A|--all|\.|BugBountyTarget)'; then
    deny "forbidden artefacts in the working tree would be staged:
$bad
Add them to .gitignore or delete them, then stage again. Hashes and metadata go in apk/versions.txt; binaries never do."
  fi
  staged_bad="$(git diff --cached --name-only 2>/dev/null | grep -Ei "$FORBIDDEN_RE" || true)"
  [ -n "$staged_bad" ] && echo "$CMD" | grep -q 'git[[:space:]]*commit' && deny "forbidden artefacts are staged:
$staged_bad
git restore --staged <file>; then commit."
  if echo "$CMD" | grep -q 'git[[:space:]]*commit'; then
    hits="$(git diff --cached -U0 2>/dev/null | grep -E '^\+' | grep -v '^+++' | grep -E "$CRED_RE" | grep -Ev 'docs/|checklist/|AIza\.\.\.|EXAMPLE|<redacted>|example' | head -3 || true)"
    [ -n "$hits" ] && deny "staged diff contains a live-looking credential or JWT:
$(echo "$hits" | cut -c1-120)
Redact it (replace with <redacted> and keep the shape), then commit."
  fi
fi
exit 0
