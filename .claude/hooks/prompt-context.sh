#!/usr/bin/env bash
# UserPromptSubmit: one cheap line of state so every turn knows the phase, the coverage and where evidence goes.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
cd "$REPO" || exit 0
E="$(active_engagement)"; [ -z "$E" ] && exit 0
ph="$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print(j.get("phase","?"), len(j.get("blockers") or []))' "$E/engagement.json" 2>/dev/null || echo '? 0')"
cov="$(python3 scripts/coverage.py "$E/checklist-status.csv" --components "$E/inventory" --brief 2>/dev/null || echo 'coverage unreadable')"
if is_evidence_repo "$E"; then r="$(evidence_remote "$E")"; ev="evidence repo → ${r:-no remote (local-only: $NO_REMOTE_MSG)}"; else ev="evidence folder is NOT a git repo — migrate (BugBountyTarget/README.md)"; fi
echo "[engagement $(basename "$E") · phase ${ph% *} · $cov · blockers ${ph#* } · $ev · R0: no escalation before P7 · commit after every batch]"
exit 0
