#!/usr/bin/env bash
# UserPromptSubmit: one cheap line of state so every turn knows the phase and coverage.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
cd "$REPO" || exit 0
E="$(active_engagement)"; [ -z "$E" ] && exit 0
python3 - "$E" <<'PY' 2>/dev/null
import csv,json,os,sys
e=sys.argv[1]; ph="?"; bl=0
try:
    j=json.load(open(os.path.join(e,"engagement.json"))); ph=j.get("phase","?"); bl=len(j.get("blockers") or [])
except Exception: pass
rows=[]; 
try: rows=list(csv.DictReader(open(os.path.join(e,"checklist-status.csv"),encoding="utf-8")))
except Exception: pass
done=sum(1 for r in rows if (r.get("completed") or "").lower()=="true" or (r.get("result") or "").lower() in ("n/a","na"))
print(f"[engagement {os.path.basename(e)} · phase {ph} · coverage {done}/{len(rows)} · blockers {bl} · R0: no escalation before P7 · push after every batch]")
PY
exit 0
