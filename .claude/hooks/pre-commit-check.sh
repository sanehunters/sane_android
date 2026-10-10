#!/usr/bin/env bash
# Manual equivalent of the PreToolUse guard for models not running under Claude Code hooks.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
cd "$REPO" || exit 1
rc=0
bad="$(git diff --cached --name-only 2>/dev/null | grep -Ei "$FORBIDDEN_RE" || true)"
[ -n "$bad" ] && { echo "forbidden artefacts staged:"; echo "$bad"; rc=1; }
hits="$(git diff --cached -U0 2>/dev/null | grep -E '^\+' | grep -v '^+++' | grep -E "$CRED_RE" | grep -Ev 'docs/|checklist/|EXAMPLE|<redacted>' | head -3 || true)"
[ -n "$hits" ] && { echo "live-looking credential in staged diff:"; echo "$hits" | cut -c1-120; rc=1; }
big="$(git diff --cached --name-only 2>/dev/null | while read -r f; do [ -f "$f" ] && [ "$(wc -c < "$f")" -gt 5242880 ] && echo "$f"; done)"
[ -n "$big" ] && { echo "files over 5 MB staged:"; echo "$big"; rc=1; }
[ "$rc" = 0 ] && echo "pre-commit check clean"
exit $rc
