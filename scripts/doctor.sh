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

# bash 3.2 (macOS) has no associative arrays: one T_<tool> variable per tool and an indirect getter.
TOOL_NAMES="python3 java adb aapt2 apksigner apktool jadx frida objection mitmproxy burp emulator bundletool semgrep r2 ghidra blutter gradle git"
T_python3=$(have python3 && echo yes || echo no)
T_java=$([ "$JAVA_OK" = 1 ] && echo yes || echo no)
T_adb=$(have adb && echo yes || echo no)
T_aapt2=$(have aapt2 && echo yes || echo no)
T_apksigner=$(have apksigner && echo yes || echo no)
T_apktool=$(have apktool && echo yes || echo no)
T_jadx=$(have jadx && echo yes || echo no)
T_frida=$(have frida && echo yes || echo no)
T_objection=$(have objection && echo yes || echo no)
T_mitmproxy=$( (have mitmproxy || have mitmdump) && echo yes || echo no)
T_burp=$( (have burpsuite || ls /opt/BurpSuite* >/dev/null 2>&1 || ls "/Applications/Burp Suite"* >/dev/null 2>&1) && echo yes || echo no)
T_emulator=$(have emulator && echo yes || echo no)
T_bundletool=$( (have bundletool || ls "$HOME"/bundletool*.jar >/dev/null 2>&1) && echo yes || echo no)
T_semgrep=$(have semgrep && echo yes || echo no)
T_r2=$( (have r2 || have radare2) && echo yes || echo no)
T_ghidra=$( (have ghidra || have ghidraRun || ls /opt/ghidra* >/dev/null 2>&1) && echo yes || echo no)
T_blutter=$( (have blutter || ls "$HOME"/blutter* >/dev/null 2>&1) && echo yes || echo no)
T_gradle=$( (have gradle || ls ./attacker-app/gradlew >/dev/null 2>&1) && echo yes || echo no)
T_git=$(have git && echo yes || echo no)
t() { local v="T_$1"; printf '%s' "${!v}"; }

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
[ "$(t apktool)" = no ] && [ "$(t jadx)" = no ] && blocked+=("P2-P4 static analysis: install apktool and jadx")
[ "$(t adb)" = no ] && blocked+=("P1/P5/P6 dynamic: adb missing (install platform-tools or set ANDROID_SDK_ROOT)")
[ "$(t adb)" = yes ] && [ "$DEV_COUNT" = 0 ] && blocked+=("P1/P5/P6 dynamic: no device/emulator connected (static-only mode until one is)")
[ "$DEV_COUNT" -gt 0 ] && [ "$ROOT" = no ] && blocked+=("P1 evidence-grade checks needing root (sandbox reads, system CA) — use a rooted AVD or userdebug device")
[ "$(t frida)" = no ] && blocked+=("runtime instrumentation (D10/D12/D13 live reads): pip install frida-tools")
[ "$(t mitmproxy)" = no ] && [ "$(t burp)" = no ] && blocked+=("P6 network/API: no interception proxy (mitmproxy or Burp)")
[ "$(t java)" = no ] && blocked+=("apksigner/jadx/gradle need a JDK: set JAVA_HOME")
[ "$(t gradle)" = no ] && blocked+=("attacker-app build (AM-03 proofs): gradle or ./gradlew")

if [ "$MODE" = "--json" ]; then
  python3 - "$OS" "$ARCH" "$SDK" "$DEVICES" "$API" "$ROOT" "$FRIDA_SERVER" "$(for k in $TOOL_NAMES; do printf '%s=%s;' "$k" "$(t "$k")"; done)" "$(printf '%s\n' ${blocked[@]+"${blocked[@]}"})" <<'PY'
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
  echo "os=$OS devices=$DEV_COUNT api=${API:-?} root=$ROOT apktool=$(t apktool) jadx=$(t jadx) frida=$(t frida) mitm=$(t mitmproxy)/$(t burp) mode=$([ "$DEV_COUNT" -gt 0 ] && echo dynamic || echo static-only) blocked=${#blocked[@]}"
  exit 0
fi

echo "══════════════════════ doctor ══════════════════════"
echo "  host      $OS $ARCH   sdk=${SDK:-not found}   java=$(t java)"
echo "  device    count=$DEV_COUNT ${DEVICES:+ids=$DEVICES}  api=${API:-?}  root=$ROOT  frida-server=$FRIDA_SERVER"
echo "  tools     $(for k in $TOOL_NAMES; do printf '%s=%s ' "$k" "$(t "$k")"; done)"
echo "  mode      $([ "$DEV_COUNT" -gt 0 ] && echo DYNAMIC || echo STATIC-ONLY)"
if [ "${#blocked[@]}" -gt 0 ]; then
  echo "  blocked   (settle the affected items as 'blocked' with this exact reason; never fake them)"
  for b in ${blocked[@]+"${blocked[@]}"}; do echo "    - $b"; done
else
  echo "  blocked   nothing — all phases runnable"
fi
echo "═════════════════════════════════════════════════════"
