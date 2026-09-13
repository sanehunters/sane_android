#!/usr/bin/env bash
# 05-storage-sweep.sh <pkg>
# Post-login storage sweep. ROOTED DEVICE / EMULATOR ONLY.
# Root here is an EVIDENCE TOOL, not an attack precondition -- see docs/05-attacker-models.md.
# Finding sensitive data on internal storage is VRT P5 on its own. It becomes a finding only
# when a zero-permission attacker can REACH it. This script tells you WHAT is worth reaching.
set -uo pipefail
PKG="${1:?usage: $0 <package>}"
P="/data/data/$PKG"

adb root >/dev/null 2>&1; sleep 3

echo "== file count =="
adb shell "find $P -type f 2>/dev/null | wc -l"
echo
echo "== files containing credential-shaped material =="
adb shell "grep -rlaE 'eyJ[A-Za-z0-9_-]{10,}|Bearer |access_token|refresh_token|api[_-]?key|password|secret' $P 2>/dev/null" | sed 's/^/   /'
echo
echo "== data stores, swept by EXTENSION not directory =="
echo "   (Realm, MMKV, DataStore and Couchbase all live OUTSIDE databases/)"
adb shell "find $P \( -name '*.db' -o -name '*.sqlite*' -o -name '*.realm' -o -name '*.cblite*' \
   -o -name '*.preferences_pb' -o -name '*.mmkv' -o -name '*.xml' -o -name '*.json' \) 2>/dev/null" | sed 's/^/   /'
echo
echo "== shared_prefs contents =="
for f in $(adb shell "ls $P/shared_prefs/ 2>/dev/null"); do
  echo "   -- $f"; adb shell "cat $P/shared_prefs/$f 2>/dev/null" | sed 's/^/      /' | head -25
done
echo
echo "== external / shared storage written by this app =="
adb shell "find /sdcard /storage/emulated/0 -iname \"*${PKG##*.}*\" 2>/dev/null | head -20" | sed 's/^/   /'
echo
echo "== WebView storage (cookies, localStorage) =="
adb shell "find $P/app_webview -type f 2>/dev/null | head -20" | sed 's/^/   /'
echo
echo "== backup reachability -- THIS is what turns storage into a finding =="
adb shell "run-as $PKG cat /data/data/$PKG/../../system/users/0/*.xml" >/dev/null 2>&1
echo "   manifest allowBackup / dataExtractionRules were captured in 01-surface-inventory.sh"
echo "   Now ask: is any file above INSIDE the backup set, and does the restore guard"
echo "   actually authenticate the device? An android_id equality check is a heuristic,"
echo "   not authentication -- and is frequently INVERTED."

cat <<'NOTE'

ESCALATION PATH (do not stop at "data is unencrypted")
  1. Identify the crown-jewel value (session token, PAN, OTP seed, refresh token).
  2. Ask: can a zero-permission app reach this file?  via an exported provider grant?
     a FileProvider root? a traversal? the backup set? shared storage?
  3. If YES -> the finding is the REACH primitive, rated on what the value unlocks.
  4. If NO  -> record it in the ruled-out table and move on. It is P5.
  5. Always test the token from curl, off-device. A "device-bound" token that works
     from curl is a far bigger finding than where it was stored.
NOTE
