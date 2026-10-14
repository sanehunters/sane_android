#!/usr/bin/env bash
# PreCompact: snapshot the resume card to disk so nothing depends on the context that is about to be summarised.
# The marker goes to logs/compactions.log (committed, append-only); report/assessment-status.md is left to the model.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
cd "$REPO" || exit 0
E="$(active_engagement)"; [ -z "$E" ] && exit 0
python3 scripts/state.py "$E" --json > "$E/state-snapshot.json" 2>/dev/null || true
mkdir -p "$E/logs"
printf '%s compaction (%s): phase %s — resume from report/assessment-status.md; state-snapshot.json holds the open items at that moment\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_get trigger)" \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("phase","?"))' "$E/engagement.json" 2>/dev/null || echo '?')" \
  >> "$E/logs/compactions.log"
exit 0
