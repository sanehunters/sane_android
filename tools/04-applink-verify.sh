#!/usr/bin/env bash
# 04-applink-verify.sh <pkg> [--apk base.apk] [--surface surface.json] [--inventory DIR] [--hosts h1,h2]
#                            [--serial S] [--out DIR] [--json] [--help]
# App Link (Digital Asset Links) verification state, and whether each host's assetlinks.json trusts THIS
# package and THIS signing key. A FAILED verification turns every "secure" App Link back into a hijackable
# implicit intent (D09).
#
# Hosts, in order: --hosts; <inventory>/deeplinks.csv (scripts/inventory.py, default $E/inventory: http(s)
# rows, host column); <surface>.json deep links (tools/01; default $E/recon/surface/surface.json); and on
# device from `dumpsys package` (the IntentFilter dump prints `Authority: "host": -1` -- the manifest form
# host="..." never appears there) plus `pm get-app-links` (Android 12+). A `*.` prefix is stripped before
# the fetch. Signer: --apk (apksigner, else keytool -printcert -jarfile) or the surface.json signer digest.
# Verdict per assetlinks statement: MATCH (package + current sha256), STALE (package ok, fingerprint is not
# a current signer: an old key is still trusted), FOREIGN-PACKAGE (another package trusted); per host:
# NOT-200, INVALID-JSON, NO-STATEMENT-FOR-PACKAGE, and verified=false on device while declared autoVerify.
# Fingerprints are printed in FULL. Without a signer digest MATCH/STALE is UNVERIFIED, never a negative.
# Device checks print UNVERIFIED (not a negative) when adb or a device is absent; curl does the fetch.
# Outputs: DIR/results.csv (host,http,statements,for_package,match,stale,foreign,verdict), assetlinks/<host>.json,
#          results.json. DIR defaults to $E/recon/applinks, else ./applinks/<pkg>; the human output is
#          appended to $E/logs/tools-04.txt when $E is set.
# Exit: 0 >=1 CANDIDATE; 1 every host fetched, verified and matching; 2 usage/environment or no host to check.
set -uo pipefail
usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
PKG=""; APK=""; SURF=""; INV=""; HOSTS_CLI=""; SERIAL="${ANDROID_SERIAL:-}"; OUT=""; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --apk) APK="${2:-}"; shift ;;  --surface) SURF="${2:-}"; shift ;;  --inventory) INV="${2:-}"; shift ;;
    --hosts) HOSTS_CLI="${2:-}"; shift ;;  --serial) SERIAL="${2:-}"; shift ;;  --out) OUT="${2:-}"; shift ;;  --json) JSON=1 ;;
    -h|--help) usage 0 ;;  -*) echo "unknown option: $1" >&2; usage ;;
    *) if [ -z "$PKG" ]; then PKG="$1"; else echo "unexpected argument: $1" >&2; usage; fi ;;
  esac
  shift
done
[ -z "$PKG" ] && usage
case "$PKG" in *[!A-Za-z0-9._]*) echo "ERROR: package name has unexpected characters" >&2; exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || { echo "UNVERIFIED: python3 missing"; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "UNVERIFIED: curl missing (needed for the assetlinks fetch)"; exit 2; }
E="${E:-${SANE_ENGAGEMENT:-}}"
[ -z "$INV" ] && [ -n "$E" ] && INV="$E/inventory"
[ -z "$SURF" ] && [ -n "$E" ] && [ -f "$E/recon/surface/surface.json" ] && SURF="$E/recon/surface/surface.json"
if [ -z "$OUT" ]; then if [ -n "$E" ]; then OUT="$E/recon/applinks"; else OUT="applinks/$PKG"; fi; fi
mkdir -p "$OUT/assetlinks" || { echo "ERROR: cannot create $OUT" >&2; exit 2; }
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && exec > >(tee -a "$E/logs/tools-04.txt"); fi
rq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }
cr() { tr -d '\r'; }
NUNV=0; unv() { echo "   UNVERIFIED: $*"; NUNV=$((NUNV + 1)); }

# ---- device ----------------------------------------------------------------------------------------
ADB=(adb); [ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")
DEV=0; DUMP=""; LINKS=""
if command -v adb >/dev/null 2>&1; then
  STATE="$("${ADB[@]}" get-state 2>&1 </dev/null | cr)"
  case "$STATE" in
    device) DEV=1 ;;
    *"more than one"*) unv "more than one device attached: pass --serial S (device checks skipped)" ;;
    *) unv "no device in state 'device' (adb get-state: ${STATE:-none}); device checks skipped" ;;
  esac
else unv "adb not on PATH: device verification state skipped (set ANDROID_SDK_ROOT, see scripts/doctor.sh)"; fi
echo "== on-device verification state (pm get-app-links, Android 12+)"
if [ "$DEV" = 1 ]; then
  DUMP="$("${ADB[@]}" shell "dumpsys package $(rq "$PKG")" </dev/null 2>/dev/null | cr)"
  printf '%s\n' "$DUMP" > "$OUT/dumpsys-package.txt"
  LINKS="$("${ADB[@]}" shell "pm get-app-links $(rq "$PKG")" </dev/null 2>&1 | cr)"
  if printf '%s' "$LINKS" | grep -qiE 'unknown command|not found|Error'; then
    unv "pm get-app-links unavailable (API < 31?): verification state must be read from 'dumpsys package domain-preferred-apps'"; LINKS=""
  else printf '%s\n' "$LINKS" | sed 's/^/   /'; fi
  echo "== domain-preferred apps"
  "${ADB[@]}" shell dumpsys package domain-preferred-apps </dev/null 2>/dev/null | cr | grep -A3 "$PKG" | head -20 | sed 's/^/   /'
else echo "   (skipped: no device)"; fi
echo

# ---- signer digest ---------------------------------------------------------------------------------
SIGNER=""; SSRC=""
if [ -n "$APK" ]; then
  [ -f "$APK" ] || { echo "ERROR: no such APK: $APK" >&2; exit 2; }
  if command -v apksigner >/dev/null 2>&1; then
    SIGNER="$(apksigner verify --print-certs "$APK" 2>/dev/null | grep -oE 'SHA-256 digest: [0-9a-fA-F]{64}' | cut -d' ' -f3 | tr 'A-F' 'a-f' | sort -u)"; SSRC="apksigner"
  fi
  if [ -z "$SIGNER" ] && command -v keytool >/dev/null 2>&1; then
    SIGNER="$(keytool -printcert -jarfile "$APK" 2>/dev/null | grep -oE 'SHA256: [0-9A-Fa-f:]{95}' | cut -d' ' -f2 | tr -d ':' | tr 'A-F' 'a-f' | sort -u)"; SSRC="keytool (v1 block)"
  fi
  [ -z "$SIGNER" ] && unv "could not read the signer of $APK (no apksigner/keytool, or no v1 block): run tools/01 on the APK and pass --surface"
elif [ -n "$SURF" ] && [ -f "$SURF" ]; then
  SIGNER="$(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1])).get("signer",{}).get("sha256",[])))' "$SURF" 2>/dev/null)"; SSRC="$SURF"
fi
echo "== current signer sha256 ($( [ -n "$SIGNER" ] && echo "$SSRC" || echo "UNVERIFIED: pass --apk base.apk or --surface surface.json"))"
[ -n "$SIGNER" ] && printf '%s\n' "$SIGNER" | sed 's/^/   /'
[ -z "$SIGNER" ] && unv "no signer digest: MATCH/STALE per fingerprint cannot be decided from this run"
echo

# ---- hosts -----------------------------------------------------------------------------------------
HOSTS="$(printf '%s' "$HOSTS_CLI" | tr ',' '\n')"
if [ -n "$INV" ] && [ -f "$INV/deeplinks.csv" ]; then
  HOSTS="$HOSTS
$(python3 -I - "$INV/deeplinks.csv" <<'PY'
import csv, re, sys
for r in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")):
    sch, host = r.get("scheme"), r.get("host")
    if sch is None:
        m = re.match(r"^([^:/]+)://([^/:]*)", r.get("uri", "")); sch, host = (m.group(1), m.group(2)) if m else ("", "")
    if sch in ("http", "https") and host and host not in ("*", ""): print(host)
PY
)"
fi
if [ -n "$SURF" ] && [ -f "$SURF" ]; then
  HOSTS="$HOSTS
$(python3 -I -c 'import json,sys
for d in json.load(open(sys.argv[1])).get("deeplinks", []):
    if set(d.get("schemes", [])) & {"http", "https"}:
        for h in d.get("hosts", []): print(h.split(":")[0])' "$SURF" 2>/dev/null)"
fi
if [ -n "$DUMP" ]; then
  HOSTS="$HOSTS
$(printf '%s\n' "$DUMP" | grep -oE 'Authority: "[^"]+"' | cut -d'"' -f2)
$(printf '%s\n' "$LINKS" | grep -oE '^ +[A-Za-z0-9*.-]+\.[A-Za-z]{2,}:' | tr -d ' :')"
fi
HOSTS="$(printf '%s\n' "$HOSTS" | sed 's/^\*\.//;s/:[0-9]*$//' | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | sort -u)"
NH="$(printf '%s\n' "$HOSTS" | grep -c . || true)"
echo "== hosts: $NH (from --hosts, deeplinks.csv, surface.json, dumpsys)"
if [ "$NH" = 0 ]; then
  echo "UNVERIFIED: no http(s) host to check -- pass --hosts, run scripts/inventory.py, or attach the device; exit 2, not a negative"; exit 2
fi

CSV="$OUT/results.csv"; echo "host,http,statements,for_package,match,stale,foreign,verdict" > "$CSV"
NCAND=0; N=0
for H in $HOSTS; do
  N=$((N + 1))
  AL="$OUT/assetlinks/$H.json"
  C="$(curl -s -o "$AL" -w '%{http_code}' --max-time 15 "https://$H/.well-known/assetlinks.json" 2>/dev/null)"
  DEVSTATE="$(printf '%s\n' "$LINKS" | grep -E "^ +$H:" | head -1 | sed 's/^ *//')"
  printf '%-44s assetlinks=%s%s\n' "$H" "${C:-000}" "${DEVSTATE:+   device: $DEVSTATE}"
  V="$(python3 -I - "$AL" "$PKG" "$C" "$SIGNER" <<'PY'
import json, sys
path, pkg, code, signer = sys.argv[1:5]
cur = {s.strip().lower() for s in signer.split() if s.strip()}
def fp_norm(f): return f.replace(":", "").strip().lower()
if code != "200": print("NOT-200|0|0|0|0|0"); sys.exit()
try: d = json.load(open(path))
except Exception as e: print("INVALID-JSON|0|0|0|0|0  %s" % e); sys.exit()
if not isinstance(d, list): print("INVALID-JSON|0|0|0|0|0  top level is not a list"); sys.exit()
n = forpkg = match = stale = foreign = 0
for st in d:
    t = st.get("target", {}) if isinstance(st, dict) else {}
    if t.get("namespace") != "android_app": continue
    n += 1
    rel = st.get("relation", [])
    fps = t.get("sha256_cert_fingerprints", [])
    if t.get("package_name") != pkg:
        foreign += 1; print("      FOREIGN-PACKAGE %s  rel=%s" % (t.get("package_name"), rel)); continue
    forpkg += 1
    for fp in fps:
        f = fp_norm(fp)
        if cur and f in cur: match += 1; print("      MATCH   %s" % fp)
        elif cur: stale += 1; print("      STALE   %s  (not a current signer: old key still trusted)" % fp)
        else: print("      fp      %s  (UNVERIFIED: no signer digest to compare)" % fp)
    if "delegate_permission/common.handle_all_urls" not in rel: print("      relation %s lacks delegate_permission/common.handle_all_urls -> App Link verification fails" % rel)
if forpkg == 0: verdict = "NO-STATEMENT-FOR-PACKAGE"
elif stale: verdict = "STALE-FINGERPRINT"
elif foreign: verdict = "FOREIGN-PACKAGE-ALSO-TRUSTED"
elif match: verdict = "MATCH"
elif not cur: verdict = "UNVERIFIED-NO-SIGNER"
else: verdict = "NO-MATCHING-FINGERPRINT"
print("%s|%d|%d|%d|%d|%d" % (verdict, n, forpkg, match, stale, foreign))
PY
)"
  printf '%s\n' "$V" | sed '$d'
  LAST="$(printf '%s\n' "$V" | tail -1)"; VERDICT="${LAST%%|*}"; REST="${LAST#*|}"
  TAG=""
  case "$VERDICT" in
    NOT-200*)            TAG="CANDIDATE applink/assetlinks-not-200"; echo "      !! NOT 200 -> autoVerify fails -> the link falls back to a chooser an attacker app can win" ;;
    INVALID-JSON*)       TAG="CANDIDATE applink/assetlinks-invalid"; echo "      !! not valid JSON -> verification FAILS" ;;
    NO-STATEMENT-FOR-PACKAGE) TAG="CANDIDATE applink/no-statement-for-package"; echo "      !! no android_app statement names $PKG -> verification FAILS" ;;
    STALE-FINGERPRINT)   TAG="CANDIDATE applink/stale-fingerprint"; echo "      !! a fingerprint that is not the current signer is trusted: whoever holds that key can verify these links" ;;
    FOREIGN-PACKAGE-ALSO-TRUSTED) TAG="CANDIDATE applink/foreign-package-trusted"; echo "      !! another package is trusted for this host (over-broad trust): check who owns it" ;;
    NO-MATCHING-FINGERPRINT) TAG="CANDIDATE applink/fingerprint-mismatch"; echo "      !! statement for $PKG carries no current-signer fingerprint -> verification FAILS for this build" ;;
    UNVERIFIED-NO-SIGNER) unv "$H: fingerprints shown but not compared (no --apk/--surface)" ;;
    MATCH)               TAG="INFO verified-statement" ;;
  esac
  case "$DEVSTATE" in *"verified"*) ;; *"none"*|*"legacy_failure"*|*"1024"*) [ -n "$DEVSTATE" ] && [ -z "$TAG" ] && { TAG="CANDIDATE applink/device-not-verified"; echo "      !! device state '$DEVSTATE' while assetlinks match: verification not (yet) done on this device"; } ;; esac
  case "$TAG" in CANDIDATE*) NCAND=$((NCAND + 1)) ;; esac
  [ -n "$TAG" ] && echo "      $TAG"
  printf '%s,%s,%s,%s\n' "$H" "${C:-000}" "$(printf '%s' "$REST" | tr '|' ',')" "${TAG:-$VERDICT}" >> "$CSV"
done

python3 -I - "$CSV" "$OUT/results.json" "$PKG" "$JSON" "$NUNV" "$SIGNER" <<'PY' 2>/dev/null || true
import csv, json, sys
rows = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")))
s = {"tool": "04-applink-verify", "package": sys.argv[3], "hosts": len(rows), "signer_sha256": sys.argv[6].split(),
     "candidates": sum(r["verdict"].startswith("CANDIDATE") for r in rows), "unverified": int(sys.argv[5]), "rows": rows,
     "note": "a failed/foreign/stale statement is a CANDIDATE: prove the hijack with a second app declaring the same filter (D09)"}
json.dump(s, open(sys.argv[2], "w"), indent=1)
if sys.argv[4] == "1": print(json.dumps(s, indent=1))
PY
echo
echo "[+] $N hosts, $NCAND CANDIDATE, $NUNV UNVERIFIED -> $CSV  (raw statements in $OUT/assetlinks/)"
cat <<'NOTE'

FINDINGS TO LOOK FOR
  - 404/non-200 or invalid assetlinks.json on an autoVerify host  -> App Link is hijackable
  - a package_name in assetlinks.json that is not the app          -> over-broad trust
  - a STALE sha256 fingerprint (old signing key still trusted)      -> whoever holds that key verifies
  - an entry for a subdomain the vendor no longer controls          -> takeover -> link hijack
  - host verified=false in `pm get-app-links` while the manifest says autoVerify="true"
NOTE
if [ "$NCAND" -gt 0 ]; then exit 0; fi
if [ "$NUNV" -gt 0 ]; then echo "UNVERIFIED: no candidate but $NUNV check(s) could not run -> exit 2, not a negative"; exit 2; fi
exit 1
