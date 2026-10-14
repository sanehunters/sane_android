#!/usr/bin/env bash
# build.sh — build the probe APK without assuming a Gradle wrapper is committed (no jars in this repo).
#   ./build.sh                                   builds app-debug.apk with whichever Gradle is available
#   ./build.sh --victim com.target.app           bakes the victim into <queries> (API 30+ visibility) and BuildConfig
#   ./build.sh --hijack-scheme targetapp         LootActivity claims that custom scheme (D09 scheme hijack)
#   ./build.sh --install                         also adb install -r it (honours ANDROID_SERIAL / -s via ADB_SERIAL)
# Exit 0 built · 1 nothing could build · 2 environment missing (says exactly what to install)
# Toolchain: AGP 8.5.2 needs a JDK >= 17 and Gradle >= 8.7; both are checked BEFORE building so a failure
# is an exit-2 environment message, not an AGP stack trace.
set -uo pipefail
cd "$(dirname "$0")" || exit 2
VICTIM="" HIJACK="" INSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --victim) VICTIM="${2:-}"; shift 2 ;;
    --hijack-scheme) HIJACK="${2:-}"; shift 2 ;;
    --install) INSTALL=1; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; sed -n '2,9p' "$0"; exit 2 ;;
  esac
done
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/opt/android-sdk" "/usr/lib/android-sdk"; do [ -d "$c" ] && SDK="$c" && break; done
fi
[ -z "$SDK" ] && { echo "UNVERIFIED: no Android SDK found — set ANDROID_SDK_ROOT (platform 35 + build-tools required)"; exit 2; }
export ANDROID_SDK_ROOT="$SDK" ANDROID_HOME="$SDK"
if ! command -v java >/dev/null 2>&1 || ! java -version >/dev/null 2>&1; then
  for c in "${JAVA_HOME:-}" "/Applications/Android Studio.app/Contents/jbr/Contents/Home" "/opt/android-studio/jbr" "/usr/lib/jvm/default-java"; do
    [ -n "$c" ] && [ -x "$c/bin/java" ] && export JAVA_HOME="$c" PATH="$c/bin:$PATH" && break
  done
fi
java -version >/dev/null 2>&1 || { echo "UNVERIFIED: no JDK — set JAVA_HOME to a JDK 17+ (Android Studio's jbr works)"; exit 2; }
JMAJ=$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+)(\.[0-9]+)*.*/\1/')
case "$JMAJ" in ''|*[!0-9]*) JMAJ=0 ;; esac
[ "$JMAJ" -ge 17 ] || { echo "UNVERIFIED: JDK $JMAJ found, AGP 8.5.2 needs JDK >= 17 — set JAVA_HOME (Android Studio's jbr is JDK 17/21)"; exit 2; }
gradle_ok() { "$1" --version 2>/dev/null | awk '/^Gradle /{split($2,v,"."); if (v[1]>8 || (v[1]==8 && v[2]>=7)) ok=1} END{exit ok?0:1}'; }
if [ -x ./gradlew ]; then G=./gradlew
elif command -v gradle >/dev/null 2>&1; then
  if ! gradle_ok gradle; then echo "UNVERIFIED: system gradle is $(gradle --version 2>/dev/null | awk '/^Gradle /{print $2}'); AGP 8.5.2 needs Gradle >= 8.7 — install a newer Gradle or open attacker-app/ in Android Studio once"; exit 2; fi
  # Generate the wrapper once (gradle/wrapper/gradle-wrapper.properties pins the version; the jar is never committed).
  gradle --no-daemon -q wrapper --gradle-version 8.9 >/dev/null 2>&1 && [ -x ./gradlew ] && G=./gradlew || G=gradle
else
  echo "UNVERIFIED: neither ./gradlew nor gradle found. Install Gradle >= 8.7 or open attacker-app/ in Android Studio once,"
  echo "which generates the wrapper (the wrapper jar is never committed here). Then re-run."; exit 2
fi
PROPS=()
[ -n "$VICTIM" ] && PROPS+=("-Pvictim=$VICTIM")
[ -n "$HIJACK" ] && PROPS+=("-PhijackScheme=$HIJACK")
echo "build: $G :app:assembleDebug (sdk=$SDK jdk=$JMAJ victim=${VICTIM:-com.victim.app} hijackScheme=${HIJACK:-probe-none})"
"$G" --no-daemon -q ${PROPS[@]+"${PROPS[@]}"} :app:assembleDebug || { echo "build failed"; exit 1; }
APK=app/build/outputs/apk/debug/app-debug.apk
[ -f "$APK" ] || { echo "build produced no APK"; exit 1; }
echo "built $APK ($(wc -c < "$APK" | tr -d ' ') bytes) sha256=$( (shasum -a 256 "$APK" 2>/dev/null || sha256sum "$APK") | cut -c1-16)…"
if [ "$INSTALL" = 1 ]; then
  command -v adb >/dev/null 2>&1 || { echo "UNVERIFIED: adb not found"; exit 2; }
  adb ${ADB_SERIAL:+-s "$ADB_SERIAL"} install -r "$APK" && cat <<EOT
installed. Drive it (ALWAYS -S: a live probe ignores a plain am start; the whole command in double quotes and any value
holding ; & ? > or a space in single quotes — the device shell re-parses the line):
  adb shell "am start -S -n com.sanehunters.probe/.MainActivity --es run baseline,enumerate --es victim ${VICTIM:-com.target.app}"
  adb logcat -s PROBE:V
  adb pull /sdcard/Android/data/com.sanehunters.probe/files/ "\${E:-.}/logs/probe/"     # file mirror (some builds drop app Log output)
EOT
fi
