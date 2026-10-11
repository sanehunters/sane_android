#!/usr/bin/env bash
# new-engagement.sh <TargetName> [DDMMYYYY] [--json]
# Creates BugBountyTarget/<TargetName>_<DDMMYYYY>/ from _TEMPLATE, seeds checklist-status.csv (every row
# completed=false) and engagement.json (phase P0, no gate passed), and substitutes the template placeholders.
# Portable: Linux and macOS (no sed -i, no stat -f). No operator-specific paths; an optional local mirror is
# controlled by SANE_LOCAL_MIRROR=/path (unset = no mirror).
# Exit codes: 0 created · 1 the engagement already exists (resume it) · 2 usage or environment error.
# --json prints one JSON object instead of the banner (path, row count, phase) for a model to continue from.
set -euo pipefail

usage() { echo "usage: $0 <TargetName> [DDMMYYYY] [--json]   TargetName: [A-Za-z0-9_-]+ ; date defaults to today"; }
JSON=0; POS=()
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --json) JSON=1 ;;
    --*) echo "!! unknown option: $arg" >&2; usage >&2; exit 2 ;;
    *) POS+=("$arg") ;;
  esac
done
[ "${#POS[@]}" -ge 1 ] || { usage >&2; exit 2; }
T="${POS[0]}"
D="${POS[1]:-$(date +%d%m%Y)}"
# the name lands in paths, sed programs and JSON: keep it to a safe alphabet; the date must be DDMMYYYY (START.md §3)
printf '%s' "$T" | grep -Eq '^[A-Za-z0-9_-]+$' || { echo "!! TargetName must match [A-Za-z0-9_-]+ (got: $T)" >&2; exit 2; }
printf '%s' "$D" | grep -Eq '^[0-9]{8}$' || { echo "!! date must be DDMMYYYY (got: $D)" >&2; exit 2; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="$REPO/BugBountyTarget/${T}_${D}"
LOWER="$(printf '%s' "$T" | tr '[:upper:]' '[:lower:]')"

[ -d "$ENG" ] && { echo "!! $ENG already exists — resume it: python3 scripts/state.py \"$ENG\"" >&2; exit 1; }
[ -d "$REPO/BugBountyTarget/_TEMPLATE" ] || { echo "!! BugBountyTarget/_TEMPLATE missing" >&2; exit 2; }
[ -f "$REPO/checklist.csv" ] || { echo "!! checklist.csv missing — run: python3 scripts/build-checklist.py" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "!! python3 is required" >&2; exit 2; }

cp -R "$REPO/BugBountyTarget/_TEMPLATE" "$ENG"
cp "$REPO/checklist.csv" "$ENG/checklist-status.csv"

# portable in-place substitution (GNU and BSD sed differ on -i); fails loudly when the file is missing
subst() { # subst <file> <sed-expr>
  local f="$1" e="$2" tmp
  [ -f "$f" ] || { echo "!! template file missing: $f" >&2; return 1; }
  tmp="$(mktemp)"; sed "$e" "$f" > "$tmp" && mv "$tmp" "$f"
}
subst "$ENG/report/assessment-status.md"    "s|<Target>_<DDMMYYYY>|${T}_${D}|g; s|<target>|${LOWER}|g"
subst "$ENG/report/findings-index.md"       "s|<target>|${T}|g"
subst "$ENG/final/submission-checklist.md"  "s|<target>|${T}|g"
# <package>, <version>, <v>, <n> stay: they are known only after P2 (engagement.json.target is the source)

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
  [ "$JSON" = 1 ] || echo "[+] local mirror: $SANE_LOCAL_MIRROR/$LOWER"
fi

# count rows with the csv module (a quoted field may legitimately contain a newline; wc -l would miscount)
ROWS="$(python3 -c 'import csv,sys; print(sum(1 for _ in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8"))))' "$ENG/checklist-status.csv")"

if [ "$JSON" = 1 ]; then
  printf '{"engagement": "%s", "name": "%s", "date": "%s", "tracker": "%s", "tracker_rows": %s, "phase": "P0", "created": "%s", "next": "python3 scripts/state.py %s"}\n' \
    "$ENG" "$T" "$D" "$ENG/checklist-status.csv" "$ROWS" "$TODAY" "$ENG"
  exit 0
fi
cat <<TXT

[+] engagement created: $ENG
    checklist-status.csv seeded with $ROWS rows, all completed=false
    engagement.json created (phase P0, no gates passed)
    placeholders substituted in report/assessment-status.md, report/findings-index.md, final/submission-checklist.md

NEXT
  1. Fill engagement.json: target identity, authorisation basis, scope, accounts (START.md §6).
  2. Fill the header of report/assessment-status.md.
  3. python3 scripts/state.py "$ENG"      # the resume card — run it at the start of every session
  4. Work P0 → P9 per START.md. Settle rows only through scripts/mark.py. Commit and push after every batch.
engagement: $ENG
TXT
