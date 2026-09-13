#!/usr/bin/env bash
# 02-component-sweep.sh <pkg>
# Dynamic sweep of exported components. WARM-START ONLY.
# Cold starts route through the launcher activity and invalidate the result.
set -uo pipefail
PKG="${1:?usage: $0 <package>}"

echo "[*] warming app (warm-start discipline: never force-stop between probes)"
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 6
adb logcat -c -b crash 2>/dev/null

printf '%-68s %-22s %s\n' "COMPONENT" "INPUT" "TOP ACTIVITY AFTER"
printf '%.0s-' {1..130}; echo

for A in $(adb shell dumpsys package "$PKG" 2>/dev/null | grep -oE "$PKG/[A-Za-z0-9_.\$/]*" | sort -u); do
  for X in "" "--es url https://example.org/" "--es model x" "--ei id 1" "--esn nullextra" \
           "--es redirect_uri https://example.org/" "--es data content://$PKG.provider/"; do
    adb shell am start -n "$A" $X >/dev/null 2>&1
    sleep 2
    T=$(adb shell dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity | sed 's/.*u0 //;s/ .*//')
    printf '%-68s %-22s %s\n' "$A" "${X:-<bare>}" "$T"
    adb shell input keyevent KEYCODE_BACK >/dev/null 2>&1
    sleep 1
  done
done

echo
echo "== crashes =="
adb logcat -d -b crash 2>/dev/null | grep -E 'FATAL|AndroidRuntime' | head -20

cat <<'NOTE'

READ THE RESULT COLUMN, NOT THE EXIT CODE.
  - component STAYS RESUMED on attacker input  -> candidate, it accepted your data
  - component finishes immediately             -> it is validating something; read the validator
  - a crash                                    -> P5 DoS on its own. Only interesting if it becomes
                                                  memory corruption with a demonstrated primitive.

adb runs as `shell`, which holds far MORE privilege than a real attacker.
Anything that looks live here must be re-proved from a ZERO-PERMISSION ATTACKER APP
before it is a finding. See docs/05-attacker-models.md (AM-03).
NOTE
