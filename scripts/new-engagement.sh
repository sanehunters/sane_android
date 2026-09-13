#!/usr/bin/env bash
# new-engagement.sh <TargetName> [DDMMYYYY]
# Creates the GitHub-side engagement folder, the local mirror, and the coverage tracker.
set -euo pipefail
T="${1:?usage: $0 <TargetName> [DDMMYYYY]}"
D="${2:-$(date +%d%m%Y)}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_ROOT="${LAMPPENTEST_ROOT:-$HOME/AndroidStudioProjects/lamppentest}"

GH="$REPO/BugBountyTarget/${T}_${D}"
LOCAL="$LOCAL_ROOT/$(echo "$T" | tr '[:upper:]' '[:lower:]')"

[ -d "$GH" ] && { echo "!! $GH already exists — resume instead of recreating"; exit 1; }

cp -R "$REPO/BugBountyTarget/_TEMPLATE" "$GH"
mkdir -p "$LOCAL"
cp -R "$REPO/BugBountyTarget/_TEMPLATE/"* "$LOCAL/" 2>/dev/null || true

if [ -f "$REPO/checklist.csv" ]; then
  cp "$REPO/checklist.csv" "$GH/checklist-status.csv"
  cp "$REPO/checklist.csv" "$LOCAL/checklist-status.csv"
  echo "[+] coverage tracker seeded ($(( $(wc -l < "$GH/checklist-status.csv") - 1 )) checkpoints, all false)"
else
  echo "!! checklist.csv not found — run scripts/build-checklist.py first"
fi

sed -i '' "s|<Target>_<DDMMYYYY>|${T}_${D}|g; s|<target>|$(echo "$T" | tr '[:upper:]' '[:lower:]')|g" \
  "$GH/report/assessment-status.md" 2>/dev/null || true

cat <<TXT

[+] engagement created
      GitHub : $GH
      local  : $LOCAL

NEXT
  1. Fill the header of $GH/report/assessment-status.md  (target, version, device, framework, OTA)
  2. Work the phases:  gh issue list --repo sanehunters/sane_android --label "type: playbook"
  3. Flip rows in checklist-status.csv to true as you settle each checkpoint
  4. Commit and push after EVERY phase. Mirror to the local tree at the same time.

TXT
