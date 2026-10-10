#!/usr/bin/env bash
# doctor.sh — environment and device detection. Portable (Linux/macOS). Never assumes a laptop layout.
#   scripts/doctor.sh            full table + which phases are blocked
#   scripts/doctor.sh --brief    one line
#   scripts/doctor.sh --json     machine view
set -uo pipefail
MODE="${1:-full}"

have() { command -v "$1" >/dev/null 2>&1; }
ver() { "$@" 2>&1 | head -1 | tr -d '\r' | cut -c1-60; }

OS="$(uname -s)"; ARCH="$(uname -m)"
# Android SDK discovery: env first, then conventional locations
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/opt/android-sdk" "/usr/lib/android-sdk" "$HOME/android-sdk"; do
    [ -d "$c" ] && SDK="$c" && break
  done
fi
if [ -n "$SDK" ]; then
  export PATH="$PATH:$SDK/platform-tools:$SDK/emulator:$SDK/cmdline-tools/latest/bin"
  BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
  [ -n "${BT:-}" ] && export PATH="$PATH:$BT"
fi
# Java discovery: env, then Android Studio's bundled JBR on either OS
JAVA_OK=0
if have java; then JAVA_OK=1; else
  for c in "$JAVA_HOME" "/Applications/Android Studio.app/Contents/jbr/Contents/Home" "/opt/android-studio/jbr" "/usr/lib/jvm/default-java"; do
    [ -n "$c" ] && [ -x "$c/bin/java" ] && export PATH="$PATH:$c/bin" && JAVA_OK=1 && break
  done
fi

declare -A T
T[python3]=$(have python3 && echo yes || echo no)
T[java]=$([ "$JAVA_OK" = 1 ] && echo yes || echo no)
T[adb]=$(have adb && echo yes || echo no)
T[aapt2]=$(have aapt2 && echo yes || echo no)
T[apksigner]=$(have apksigner && echo yes || echo no)
T[apktool]=$(have apktool && echo yes || echo no)
T[jadx]=$(have jadx && echo yes || echo no)
T[frida]=$(have frida && echo yes || echo no)
T[objection]=$(have objection && echo yes || echo no)
T[mitmproxy]=$( (have mitmproxy || have mitmdump) && echo yes || echo no)
T[burp]=$( (have burpsuite || ls /opt/BurpSuite* >/dev/null 2>&1 || ls "/Applications/Burp Suite"* >/dev/null 2>&1) && echo yes || echo no)
T[emulator]=$(have emulator && echo yes || echo no)
T[bundletool]=$( (have bundletool || ls "$HOME"/bundletool*.jar >/dev/null 2>&1) && echo yes || echo no)
T[semgrep]=$(have semgrep && echo yes || echo no)
T[r2]=$( (have r2 || have radare2) && echo yes || echo no)
T[ghidra]=$( (have ghidra || have ghidraRun || ls /opt/ghidra* >/dev/null 2>&1) && echo yes || echo no)
T[blutter]=$( (have blutter || ls "$HOME"/blutter* >/dev/null 2>&1) && echo yes || echo no)
T[gradle]=$( (have gradle || ls ./attacker-app/gradlew >/dev/null 2>&1) && echo yes || echo no)
T[git]=$(have git && echo yes || echo no)

DEVICES=""; DEV_COUNT=0; ROOT="unknown"; API=""
if have adb; then
  DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1}' | tr '\n' ' ')"
  DEV_COUNT=$(printf '%s' "$DEVICES" | wc -w | tr -d ' ')
  if [ "$DEV_COUNT" -gt 0 ]; then
    API="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
    if adb shell "su -c id" 2>/dev/null | grep -q uid=0; then ROOT="yes (su)"; elif adb shell id 2>/dev/null | grep -q uid=0; then ROOT="yes (adb root)"; else ROOT="no"; fi
  fi
fi
FRIDA_SERVER="no"
[ "$DEV_COUNT" -gt 0 ] && adb shell "ps -A 2>/dev/null | grep -q frida-server" 2>/dev/null && FRIDA_SERVER="running"

blocked=()
[ "${T[apktool]}" = no ] && [ "${T[jadx]}" = no ] && blocked+=("P2-P4 static analysis: install apktool and jadx")
[ "${T[adb]}" = no ] && blocked+=("P1/P5/P6 dynamic: adb missing (install platform-tools or set ANDROID_SDK_ROOT)")
[ "${T[adb]}" = yes ] && [ "$DEV_COUNT" = 0 ] && blocked+=("P1/P5/P6 dynamic: no device/emulator connected (static-only mode until one is)")
[ "$DEV_COUNT" -gt 0 ] && [ "$ROOT" = no ] && blocked+=("P1 evidence-grade checks needing root (sandbox reads, system CA) — use a rooted AVD or userdebug device")
[ "${T[frida]}" = no ] && blocked+=("runtime instrumentation (D10/D12/D13 live reads): pip install frida-tools")
[ "${T[mitmproxy]}" = no ] && [ "${T[burp]}" = no ] && blocked+=("P6 network/API: no interception proxy (mitmproxy or Burp)")
[ "${T[java]}" = no ] && blocked+=("apksigner/jadx/gradle need a JDK: set JAVA_HOME")
[ "${T[gradle]}" = no ] && blocked+=("attacker-app build (AM-03 proofs): gradle or ./gradlew")

if [ "$MODE" = "--json" ]; then
  python3 - "$OS" "$ARCH" "$SDK" "$DEVICES" "$API" "$ROOT" "$FRIDA_SERVER" "$(for k in "${!T[@]}"; do printf '%s=%s;' "$k" "${T[$k]}"; done)" "$(printf '%s\n' "${blocked[@]}")" <<'PY'
import json,sys
os_,arch,sdk,devs,api,root,fs,tools,blocked=sys.argv[1:10]
t={k:v=="yes" for k,v in (x.split("=") for x in tools.strip(";").split(";") if x)}
print(json.dumps({"os":os_,"arch":arch,"sdk":sdk or None,"tools":t,"devices":devs.split(),"device_api":api or None,
  "root":root,"frida_server":fs,"blocked":[b for b in blocked.split("\n") if b],
  "mode":"dynamic" if devs.strip() else "static-only"},indent=1))
PY
  exit 0
fi
if [ "$MODE" = "--brief" ]; then
  echo "os=$OS devices=$DEV_COUNT api=${API:-?} root=$ROOT apktool=${T[apktool]} jadx=${T[jadx]} frida=${T[frida]} mitm=${T[mitmproxy]}/${T[burp]} mode=$([ "$DEV_COUNT" -gt 0 ] && echo dynamic || echo static-only) blocked=${#blocked[@]}"
  exit 0
fi

echo "══════════════════════ doctor ══════════════════════"
echo "  host      $OS $ARCH   sdk=${SDK:-not found}   java=${T[java]}"
echo "  device    count=$DEV_COUNT ${DEVICES:+ids=$DEVICES}  api=${API:-?}  root=$ROOT  frida-server=$FRIDA_SERVER"
echo "  tools     $(for k in python3 adb aapt2 apksigner apktool jadx frida objection mitmproxy burp emulator bundletool semgrep r2 ghidra blutter gradle git; do printf '%s=%s ' "$k" "${T[$k]}"; done)"
echo "  mode      $([ "$DEV_COUNT" -gt 0 ] && echo DYNAMIC || echo STATIC-ONLY)"
if [ "${#blocked[@]}" -gt 0 ]; then
  echo "  blocked   (settle the affected items as 'blocked' with this exact reason; never fake them)"
  for b in "${blocked[@]}"; do echo "    - $b"; done
else
  echo "  blocked   nothing — all phases runnable"
fi
echo "═════════════════════════════════════════════════════"
