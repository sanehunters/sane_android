#!/usr/bin/env bash
# 04-applink-verify.sh <pkg>
# App Link (Digital Asset Links) verification state. A FAILED verification turns every
# "secure" App Link back into a hijackable implicit intent.
set -uo pipefail
PKG="${1:?usage: $0 <package>}"

echo "== on-device verification state =="
adb shell pm get-app-links "$PKG" 2>/dev/null || echo "(pm get-app-links unsupported on this API level)"
echo
echo "== domain-preferred apps =="
adb shell dumpsys package domain-preferred-apps 2>/dev/null | grep -A3 "$PKG" | head -20
echo
echo "== assetlinks.json per declared host =="
for H in $(adb shell dumpsys package "$PKG" 2>/dev/null | grep -oE 'host="[^"]*"' | cut -d'"' -f2 | sort -u); do
  C=$(curl -s -o /tmp/_al.json -w '%{http_code}' --max-time 10 "https://$H/.well-known/assetlinks.json")
  printf '%-42s assetlinks=%s\n' "$H" "$C"
  if [ "$C" = "200" ]; then
    python3 - <<PY 2>/dev/null
import json
try:
    d=json.load(open('/tmp/_al.json'))
except Exception as e:
    print('      !! not valid JSON -> verification FAILS ->', e); raise SystemExit
for e in d:
    t=e.get('target',{})
    print('      package:', t.get('package_name'))
    for fp in t.get('sha256_cert_fingerprints',[]):
        print('      fp     :', fp[:32],'...')
    print('      relation:', e.get('relation'))
PY
  else
    echo "      !! NOT 200 -> autoVerify silently fails -> link falls back to a chooser"
    echo "         an attacker app declaring the same filter can win that chooser."
  fi
done

cat <<'NOTE'

FINDINGS TO LOOK FOR
  - 404/non-200 assetlinks.json on an autoVerify host  -> App Link is hijackable
  - a package_name in assetlinks.json that is not the app  -> over-broad trust
  - a stale sha256 fingerprint (old signing key still trusted)
  - an entry for a subdomain the vendor no longer controls -> takeover -> link hijack
  - host verified=false in `pm get-app-links` while the manifest says autoVerify="true"
NOTE
