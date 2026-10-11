#!/usr/bin/env bash
# build.sh — build the probe APK without assuming a Gradle wrapper is committed (no jars in this repo).
#   ./build.sh            builds app-debug.apk with whichever Gradle is available
#   ./build.sh --install  also adb install -r it
# Exit 0 built · 1 nothing could build · 2 environment missing (says what to install)
set -uo pipefail
cd "$(dirname "$0")" || exit 2
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/opt/android-sdk" "/usr/lib/android-sdk"; do [ -d "$c" ] && SDK="$c" && break; done
fi
[ -z "$SDK" ] && { echo "UNVERIFIED: no Android SDK found — set ANDROID_SDK_ROOT (platform 35 + build-tools required)"; exit 2; }
export ANDROID_SDK_ROOT="$SDK" ANDROID_HOME="$SDK"
if ! command -v java >/dev/null 2>&1; then
  for c in "${JAVA_HOME:-}" "/Applications/Android Studio.app/Contents/jbr/Contents/Home" "/opt/android-studio/jbr" "/usr/lib/jvm/default-java"; do
    [ -n "$c" ] && [ -x "$c/bin/java" ] && export JAVA_HOME="$c" PATH="$c/bin:$PATH" && break
  done
fi
command -v java >/dev/null 2>&1 || { echo "UNVERIFIED: no JDK — set JAVA_HOME (Android Studio's jbr works)"; exit 2; }
if [ -x ./gradlew ]; then G=./gradlew
elif command -v gradle >/dev/null 2>&1; then G=gradle
else
  echo "UNVERIFIED: neither ./gradlew nor gradle found. Install Gradle (8.x) or open attacker-app/ in Android Studio once,"
  echo "which generates the wrapper (the wrapper jar is never committed here). Then re-run."; exit 2
fi
echo "build: $G :app:assembleDebug (sdk=$SDK)"
"$G" --no-daemon -q :app:assembleDebug || { echo "build failed"; exit 1; }
APK=app/build/outputs/apk/debug/app-debug.apk
[ -f "$APK" ] || { echo "build produced no APK"; exit 1; }
echo "built $APK ($(wc -c < "$APK" | tr -d ' ') bytes)"
if [ "${1:-}" = "--install" ]; then
  command -v adb >/dev/null 2>&1 || { echo "UNVERIFIED: adb not found"; exit 2; }
  adb install -r "$APK" && echo "installed; drive it: adb shell am start -n com.sanehunters.probe/.MainActivity --es run baseline,enumerate --es victim <pkg>; adb logcat -s PROBE:V"
fi
