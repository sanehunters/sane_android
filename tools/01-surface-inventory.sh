#!/usr/bin/env bash
# 01-surface-inventory.sh <base.apk>
# Static attack-surface inventory from an APK. Produces CANDIDATES, never findings.
# Phase 3 of the engagement workflow. See checklist/D03 and checklist/D04.
set -uo pipefail
APK="${1:?usage: $0 <base.apk>}"
OUT="${2:-surface-inventory}"
mkdir -p "$OUT"
D=$(mktemp -d)

echo "[*] decoding $APK (resources only, fast)"
apktool d -q -f -s "$APK" -o "$D/apk" >/dev/null 2>&1 || { echo "apktool failed"; exit 1; }
M="$D/apk/AndroidManifest.xml"
cp "$M" "$OUT/AndroidManifest.xml" 2>/dev/null

{
echo "=============================================================="
echo " SDK LEVELS   -- these gate whole vulnerability classes"
echo "=============================================================="
grep -oE 'minSdkVersion: [0-9]+|targetSdkVersion: [0-9]+' "$D/apk/apktool.yml" 2>/dev/null
echo
echo "  targetSdk <17 : providers exported by DEFAULT"
echo "  minSdk    <17 : addJavascriptInterface reflection RCE"
echo "  targetSdk <24 : user-installed CAs trusted by default"
echo "  targetSdk <28 : cleartext traffic allowed by default"
echo "  targetSdk <30 : full package visibility (no <queries> needed)"
echo "  targetSdk <31 : components with intent-filters exported by DEFAULT; PendingIntent mutability not enforced"
echo

echo "=============================================================="
echo " APPLICATION FLAGS"
echo "=============================================================="
grep -oE 'allowBackup="[^"]*"|debuggable="[^"]*"|usesCleartextTraffic="[^"]*"|networkSecurityConfig="[^"]*"|sharedUserId="[^"]*"|dataExtractionRules="[^"]*"|fullBackupContent="[^"]*"|intentMatchingFlags="[^"]*"' "$M" | sort -u
echo

echo "=============================================================="
echo " EXPORTED COMPONENTS WITH NO PERMISSION   <-- start here"
echo "=============================================================="
python3 - "$M" <<'PY'
import sys,re,xml.etree.ElementTree as ET
NS='{http://schemas.android.com/apk/res/android}'
try: root=ET.parse(sys.argv[1]).getroot()
except Exception as e: print('parse failed:',e); sys.exit(0)
app=root.find('application')
if app is None: sys.exit(0)
for tag in ('activity','activity-alias','service','receiver','provider'):
    for el in app.iter(tag):
        name=el.get(NS+'name','?')
        exp=el.get(NS+'exported')
        perm=el.get(NS+'permission')
        rperm=el.get(NS+'readPermission'); wperm=el.get(NS+'writePermission')
        has_filter=el.find('intent-filter') is not None
        # implicit export: intent-filter present and exported unset (targetSdk<31)
        effective = (exp=='true') or (exp is None and has_filter)
        if not effective: continue
        flags=[]
        if exp is None: flags.append('IMPLICIT-EXPORT')
        if not perm and not rperm and not wperm: flags.append('NO-PERMISSION')
        if tag=='provider':
            if el.get(NS+'grantUriPermissions')=='true': flags.append('GRANT-URI')
            if rperm and not wperm: flags.append('READ-ONLY-PERM-ASYMMETRY')
            if wperm and not rperm: flags.append('WRITE-ONLY-PERM-ASYMMETRY')
            auth=el.get(NS+'authorities')
            if auth: flags.append('auth='+auth)
        if tag in ('activity','activity-alias'):
            lm=el.get(NS+'launchMode');  ta=el.get(NS+'taskAffinity'); rp=el.get(NS+'allowTaskReparenting')
            if lm in ('singleTask','singleInstance'): flags.append('launchMode='+lm)
            if ta is not None: flags.append('taskAffinity='+repr(ta))
            if rp=='true': flags.append('allowTaskReparenting')
        print(f"  [{tag:14s}] {name}")
        if flags: print(f"                   -> {' | '.join(flags)}")
PY
echo

echo "=============================================================="
echo " TASK-HIJACK SURFACE (StrandHogg)"
echo "=============================================================="
grep -oE 'taskAffinity="[^"]*"|allowTaskReparenting="[^"]*"|launchMode="(singleTask|singleInstance)"' "$M" | sort | uniq -c
echo "  NOTE: no explicit taskAffinity => defaults to package name => hijackable."
echo "        The fix is android:taskAffinity=\"\" on every activity."
echo

echo "=============================================================="
echo " DEEP LINKS / APP LINKS"
echo "=============================================================="
grep -oE '<data[^>]*>' "$M" | sort -u
echo "-- autoVerify count: $(grep -oc 'autoVerify="true"' "$M" 2>/dev/null || echo 0)"
echo

echo "=============================================================="
echo " CONTENT PROVIDER AUTHORITIES"
echo "=============================================================="
grep -oE 'authorities="[^"]*"' "$M" | sort -u
echo
echo "-- FileProvider path configs (look for root-path / path=\".\" / path=\"/\"):"
for f in "$D"/apk/res/xml/*.xml; do
  if grep -qE 'root-path|files-path|cache-path|external-path|external-files-path' "$f" 2>/dev/null; then
    echo "   == $(basename "$f")"; sed 's/^/      /' "$f"
  fi
done
echo

echo "=============================================================="
echo " CUSTOM PERMISSIONS (protectionLevel squatting surface)"
echo "=============================================================="
grep -oE '<permission[^>]*>' "$M" | sort -u
echo "  NOTE: 'normal'/'dangerous' custom permissions can be DEFINED FIRST by an attacker app"
echo "        installed before the victim => permission downgrade."
echo

echo "=============================================================="
echo " PERMISSIONS REQUESTED"
echo "=============================================================="
grep -oE 'uses-permission[^>]*android:name="[^"]*"' "$M" | grep -oE 'android:name="[^"]*"' | sort -u
echo

echo "=============================================================="
echo " NETWORK SECURITY CONFIG"
echo "=============================================================="
NSC=$(grep -oE 'networkSecurityConfig="@xml/[^"]*"' "$M" | sed 's/.*@xml\///;s/"//')
if [ -n "$NSC" ] && [ -f "$D/apk/res/xml/$NSC.xml" ]; then cat "$D/apk/res/xml/$NSC.xml"; else echo "  (none declared)"; fi
echo

echo "=============================================================="
echo " FRAMEWORK DETECTION  -- decides where the logic actually lives"
echo "=============================================================="
unzip -l "$APK" 2>/dev/null | grep -qi 'libflutter.so'          && echo "  FLUTTER    -> logic in libapp.so Dart AOT snapshot; jadx gives you a shell only"
unzip -l "$APK" 2>/dev/null | grep -qi 'index.android.bundle'   && echo "  REACT NATIVE -> logic in the JS bundle"
unzip -l "$APK" 2>/dev/null | grep -qi 'libhermes'              && echo "    ...Hermes bytecode: parse the header/string table yourself, public tools lag"
unzip -l "$APK" 2>/dev/null | grep -qi 'libmonodroid\|assemblies.blob' && echo "  XAMARIN/MAUI -> .NET assemblies"
unzip -l "$APK" 2>/dev/null | grep -qi 'libunity\|global-metadata.dat' && echo "  UNITY/il2cpp"
unzip -l "$APK" 2>/dev/null | grep -qi 'cordova\|www/index.html' && echo "  CORDOVA/CAPACITOR -> the WebView IS the app"
echo
echo "-- OTA code delivery (are you analysing the binary that RUNS?):"
unzip -l "$APK" 2>/dev/null | grep -iE 'expo-updates|CodePush|\.expo-internal' || echo "   (no obvious OTA updater in the package)"
} | tee "$OUT/inventory.txt"

echo
echo "[+] written to $OUT/inventory.txt"
echo "[!] Everything above is a CANDIDATE. Confirm on device before it enters report.md."
rm -rf "$D"
