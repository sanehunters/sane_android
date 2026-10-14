#!/usr/bin/env bash
# Manual equivalent of the PreToolUse guard for models not running under Claude Code hooks.
# Checks the evidence repo of the active engagement (or the one given as $1) and the methodology repo.
# scripts/new-engagement.sh installs the same rules as the evidence repo's own .git/hooks/pre-commit.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
cd "$REPO" || exit 1
rc=0
check_repo() { # check_repo <dir> [methodology]
  local r="$1" kind="${2:-}" problems big
  problems="$(staged_problems "$r" "$kind")" || { echo "$problems"; rc=1; }
  big="$(git -C "$r" diff --cached --name-only -z 2>/dev/null | tr '\0' '\n' | while IFS= read -r f; do [ -n "$f" ] && [ -f "$r/$f" ] && [ "$(wc -c < "$r/$f")" -gt 5242880 ] && echo "$f"; done)"
  [ -n "$big" ] && { echo "files over 5 MB staged in $r:"; echo "$big"; rc=1; }
}
E="${1:-$(active_engagement)}"
if is_evidence_repo "$E"; then check_repo "$E"; elif [ -n "$E" ]; then echo "note: $E is not its own git repository — evidence must not be committed to the methodology repo (public); see BugBountyTarget/README.md"; fi
check_repo "$REPO" methodology
[ "$rc" = 0 ] && echo "pre-commit check clean"
exit $rc
