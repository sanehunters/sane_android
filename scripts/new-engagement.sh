#!/usr/bin/env bash
# new-engagement.sh <TargetName> [DDMMYYYY]
# Creates the engagement folder under BugBountyTarget/, seeds the coverage tracker and the state file.
# Portable: Linux and macOS. No operator-specific paths; an optional local mirror is controlled by
# SANE_LOCAL_MIRROR=/path (left unset = no mirror).
set -euo pipefail
T="${1:?usage: $0 <TargetName> [DDMMYYYY]}"
D="${2:-$(date +%d%m%Y)}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="$REPO/BugBountyTarget/${T}_${D}"
LOWER="$(printf '%s' "$T" | tr '[:upper:]' '[:lower:]')"

[ -d "$ENG" ] && { echo "!! $ENG already exists — resume it: python3 scripts/state.py $ENG"; exit 1; }
[ -f "$REPO/checklist.csv" ] || { echo "!! checklist.csv missing — run: python3 scripts/build-checklist.py"; exit 1; }

cp -R "$REPO/BugBountyTarget/_TEMPLATE" "$ENG"
cp "$REPO/checklist.csv" "$ENG/checklist-status.csv"

# portable in-place substitution (GNU and BSD sed differ on -i)
subst() { # subst <file> <sed-expr>
  local f="$1" e="$2" tmp; tmp="$(mktemp)"; sed "$e" "$f" > "$tmp" && mv "$tmp" "$f"
}
[ -f "$ENG/report/assessment-status.md" ] && subst "$ENG/report/assessment-status.md" "s|<Target>_<DDMMYYYY>|${T}_${D}|g; s|<target>|${LOWER}|g"

TODAY="$(date +%Y-%m-%d)"
cat > "$ENG/engagement.json" <<JSON
{
  "schema": 1,
  "target": { "name": "${T}", "package": "", "version": "", "versionCode": "", "targetSdk": null, "minSdk": null, "framework": "", "ota": "" },
  "authorisation": { "basis": "", "scope": "", "programme_url": "", "excluded": [] },
  "accounts": { "a": "", "b": "" },
  "phase": "P0",
  "gates": { "P0": false, "P1": false, "P2": false, "P3": false, "P4": false, "P5": false, "P6": false, "P7": false, "P8": false, "P9": false },
  "domains_in_scope": "all",
  "domains_na": {},
  "blockers": [],
  "created": "${TODAY}",
  "updated": "${TODAY}"
}
JSON

if [ -n "${SANE_LOCAL_MIRROR:-}" ]; then
  mkdir -p "$SANE_LOCAL_MIRROR/$LOWER"
  cp -R "$ENG/." "$SANE_LOCAL_MIRROR/$LOWER/"
  echo "[+] local mirror: $SANE_LOCAL_MIRROR/$LOWER"
fi

ROWS=$(( $(wc -l < "$ENG/checklist-status.csv") - 1 ))
cat <<TXT

[+] engagement created: $ENG
    checklist-status.csv seeded with $ROWS rows, all completed=false
    engagement.json created (phase P0, no gates passed)

NEXT
  1. Fill engagement.json: target identity, authorisation basis, scope, accounts.
  2. Fill the header of report/assessment-status.md.
  3. python3 scripts/state.py "$ENG"      # the resume card — run it at the start of every session
  4. Work P0 → P9 per START.md. Flip rows as you settle them. Commit and push after every batch.
TXT
