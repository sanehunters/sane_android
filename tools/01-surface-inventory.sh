#!/usr/bin/env bash
# tools/01-surface-inventory.sh — static attack-surface inventory of ONE APK (phase P3). Prints CANDIDATES, never findings.
#
#   tools/01-surface-inventory.sh <base.apk | AndroidManifest.xml | apktool-dir> [outdir] [--json] [--quiet]
#   tools/01-surface-inventory.sh --help
#
# Input    an APK (decoded with `apktool d -s` into a temp dir that is removed on exit), a decoded text
#          AndroidManifest.xml, or an apktool output directory. With no input and $E set, $E/decompiled/apktool
#          (the canonical decompile path) is used.
# Output   <outdir>/inventory.txt (human) · <outdir>/surface.json (machine) · <outdir>/AndroidManifest.xml (copy).
#          outdir defaults to $E/recon/surface when $E (or SANE_ENGAGEMENT) is set, else ./surface-inventory.
#          The human output is appended to $E/logs/tools-01.txt. --json prints surface.json to stdout instead
#          of the human text (the files are written either way).
# Exit     0 at least one CANDIDATE · 1 ran, nothing exported and no risky flag · 2 usage or environment error.
# Rules    a line that names an attack surface carries the tag CANDIDATE; a check that could not run prints
#          UNVERIFIED: <why> (silence is never a negative). Everything here is static: confirm on device, then
#          re-prove from the zero-permission probe app (attacker-app/, AM-03) before it enters report.md.
# Gates    targetSdk — not minSdk — decides the platform defaults: implicit export of filtered components (<31),
#          provider default export (<17), addJavascriptInterface reflection (<17), user CAs trusted (<24),
#          cleartext (<28), package visibility (<30), PendingIntent mutability (<31). Sources are cited inline.
# Portable Linux/macOS, bash 3.2+, python3 stdlib only. apktool is needed only for APK input. The signer digest
#          comes from apksigner when present (PATH, or the SDK found the way scripts/doctor.sh finds it);
#          otherwise the APK Signing Block (v3.1/v3/v2) is parsed inline and keytool covers v1-only APKs.
set -uo pipefail

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}
die() { echo "ERROR: $*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

INPUT=""; OUT=""; MODE="human"; QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --json) MODE="json" ;;
    --quiet) QUIET=1 ;;
    --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT="$2"; shift ;;
    --out=*) OUT="${1#--out=}" ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) if [ -z "$INPUT" ]; then INPUT="$1"; elif [ -z "$OUT" ]; then OUT="$1"; else die "unexpected argument: $1"; fi ;;
  esac
  shift
done

E="${E:-${SANE_ENGAGEMENT:-}}"
if [ -z "$INPUT" ]; then
  if [ -n "$E" ] && [ -f "$E/decompiled/apktool/AndroidManifest.xml" ]; then
    INPUT="$E/decompiled/apktool"
  else
    usage >&2; die "no input given (and no \$E/decompiled/apktool/AndroidManifest.xml to fall back to)"
  fi
fi
[ -e "$INPUT" ] || die "input not found: $INPUT"
have python3 || die "python3 is required"

if [ -z "$OUT" ]; then
  if [ -n "$E" ]; then OUT="$E/recon/surface"; else OUT="./surface-inventory"; fi
fi
mkdir -p "$OUT" || die "cannot create outdir $OUT"

# Android SDK discovery, same order as scripts/doctor.sh: env, then conventional locations. Only apksigner
# is wanted here; the newest build-tools directory wins (numeric sort — `sort -V` is not portable).
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/opt/android-sdk" "/usr/lib/android-sdk" "$HOME/android-sdk"; do
    [ -d "$c" ] && SDK="$c" && break
  done
fi
if [ -n "$SDK" ] && [ -d "$SDK/build-tools" ]; then
  BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sed 's|.*/||' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
  [ -n "$BT" ] && export PATH="$PATH:$SDK/build-tools/$BT"
fi
APKSIGNER="$(command -v apksigner 2>/dev/null || true)"
KEYTOOL="$(command -v keytool 2>/dev/null || true)"
if [ -z "$KEYTOOL" ] && [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ]; then KEYTOOL="$JAVA_HOME/bin/keytool"; fi

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT

APK=""; DEC=""; MANIFEST=""
case "$INPUT" in
  *.apk|*.APK|*.apks|*.xapk)
    APK="$INPUT"
    have apktool || die "apktool is required to decode an APK (or pass the decoded AndroidManifest.xml / apktool dir)"
    TMP="$(mktemp -d)" || die "mktemp failed"
    [ "$QUIET" = 1 ] || echo "[*] apktool d -s (resources only) $APK" >&2
    if ! apktool d -q -f -s "$APK" -o "$TMP/apk" >"$TMP/apktool.log" 2>&1; then
      # resource decoding fails on some obfuscated/aapt2-edge APKs; the manifest alone is still worth having
      if apktool d -q -f -s --no-res --force-manifest "$APK" -o "$TMP/apk" >>"$TMP/apktool.log" 2>&1; then
        echo "UNVERIFIED: apktool resource decoding failed (res/xml not available: NSC, backup rules, FileProvider paths unresolved); manifest decoded with --no-res --force-manifest" >&2
        echo "res-failed" > "$TMP/apk/.sane-nores"
      else
        tail -5 "$TMP/apktool.log" >&2; die "apktool failed on $APK"
      fi
    fi
    DEC="$TMP/apk"; MANIFEST="$DEC/AndroidManifest.xml"
    ;;
  *.xml) MANIFEST="$INPUT"; DEC="$(cd "$(dirname "$INPUT")" && pwd)" ;;
  *) [ -d "$INPUT" ] || die "input must be an .apk, an AndroidManifest.xml or an apktool directory"
     DEC="$INPUT"; MANIFEST="$DEC/AndroidManifest.xml" ;;
esac
[ -f "$MANIFEST" ] || die "no AndroidManifest.xml at $MANIFEST"
cp "$MANIFEST" "$OUT/AndroidManifest.xml" 2>/dev/null || true

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG=""
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && LOG="$E/logs/tools-01.txt"; fi

# The parser. python3 -I: isolated mode, so a planted module next to the decoded APK is never imported.
python3 -I - "$MANIFEST" "$DEC" "$APK" "$OUT" "$MODE" "$RUN_ID" "$APKSIGNER" "$KEYTOOL" "$LOG" "$QUIET" <<'PY'
import sys, os, re, json, hashlib, struct, subprocess, zipfile, datetime, itertools
import xml.etree.ElementTree as ET

manifest, decdir, apk, out, mode, run_id, apksigner, keytool, logpath, quiet = sys.argv[1:11]
NS = '{http://schemas.android.com/apk/res/android}'
def A(el, k, d=None): return el.get(NS + k, d)
def uniq(xs):
    seen, o = set(), []
    for x in xs:
        if x not in seen: seen.add(x); o.append(x)
    return o

unverified, cands = [], []
def unv(msg): unverified.append(msg)
def cand(tag, where, detail, domain): cands.append({"tag": tag, "where": where, "detail": detail, "domain": domain})

try:
    root = ET.parse(manifest).getroot()
except Exception as e:
    print("ERROR: manifest parse failed: %s" % e, file=sys.stderr); sys.exit(2)
pkg = root.get('package') or ''
if not pkg: unv("manifest has no package attribute (split/merged manifest?) — component names are printed as declared")
raw_text = open(manifest, encoding='utf-8', errors='replace').read()
nores = os.path.exists(os.path.join(decdir, '.sane-nores'))
res_xml = os.path.join(decdir, 'res', 'xml')
have_res = os.path.isdir(res_xml) and not nores
if not have_res:
    unv("res/xml not available (manifest-only input or resource decoding failed): NSC, backup rules and FileProvider path configs are unresolved")

# ---------------------------------------------------------------- SDK levels (targetSdk decides the defaults)
sdk = {"min": None, "target": None, "source": None}
us = root.find('uses-sdk')
if us is not None:
    for k, a in (("min", "minSdkVersion"), ("target", "targetSdkVersion")):
        v = A(us, a)
        if v and v.isdigit(): sdk[k] = int(v); sdk["source"] = "manifest <uses-sdk>"
yml = os.path.join(decdir, 'apktool.yml')
if os.path.exists(yml) and (sdk["target"] is None or sdk["min"] is None):
    t = open(yml, encoding='utf-8', errors='replace').read()
    for k, a in (("min", "minSdkVersion"), ("target", "targetSdkVersion")):
        m = re.search(a + r"""\s*:\s*['"]?(\d+)""", t)   # apktool 2.x quotes the value, 3.x does not
        if m and sdk[k] is None: sdk[k] = int(m.group(1)); sdk["source"] = sdk["source"] or "apktool.yml"
T = sdk["target"]
if T is None:
    unv("targetSdk unknown (no <uses-sdk>, no apktool.yml): every targetSdk-gated default below is evaluated as if it applied — mark the affected rows VERIFY")
def gate(th): return True if T is None else T < th

# (threshold, what applies below it, source)
GATES = [
    (17, "providers with no android:exported are exported by DEFAULT", "MASTG-KNOW-0117 ('Since Android 4.2, the default is false if no <intent-filter> is defined')"),
    (17, "addJavascriptInterface exposes every public method through reflection (no @JavascriptInterface needed)", "MASTG-TEST-0033 (deprecated; see MASTG-TEST-0334) l.37; hacktricks webview-attacks.md 'apps targeting Android versions below 4.2'"),
    (24, "user-installed CAs are trusted by default (default NSC includes <certificates src=\"user\"/>)", "MASTG-KNOW-0014 'Default Configurations' (API 23 and lower block)"),
    (28, "cleartext traffic permitted by default (base-config cleartextTrafficPermitted=\"true\")", "MASTG-KNOW-0014 'Default Configurations'"),
    (30, "full package visibility — no <queries> needed to see other packages", "MASTG-KNOW-0031 l.57-59"),
    (30, "WebView setAllowFileAccess() defaults to true", "MASTG-TEST-0032 (deprecated; see MASTG-TEST-0250) l.26"),
    (31, "components with an <intent-filter> and no android:exported are exported by DEFAULT (targeting 31+ the install is refused instead)", "MASTG-KNOW-0132 l.62, -0133 l.45, -0134 l.71"),
    (31, "PendingIntent mutability not enforced (mutable unless FLAG_IMMUTABLE)", "MASTG-KNOW-0024 l.34"),
]
gates = [{"below": th, "applies": gate(th), "unknown_target": T is None, "effect": eff, "source": src} for th, eff, src in GATES]

# ---------------------------------------------------------------- application flags
app = root.find('application')
if app is None:
    print("ERROR: no <application> element", file=sys.stderr); sys.exit(2)
app_attrs = {k.replace(NS, 'android:'): v for k, v in app.attrib.items()}
app_perm = A(app, 'permission')
app_affinity = A(app, 'taskAffinity')
def resolve_xml(ref):
    """'@xml/name' -> path of res/xml/name.xml (or None)."""
    if not ref or not ref.startswith('@xml/'): return None
    p = os.path.join(res_xml, ref[5:] + '.xml')
    return p if os.path.exists(p) else None
def read_file(p, limit=12000):
    try:
        d = open(p, encoding='utf-8', errors='replace').read()
        return d if len(d) <= limit else d[:limit] + "\n...(truncated)"
    except Exception as e:
        return "(unreadable: %s)" % e

flags = {}
def flag(name, value, note=""):
    flags[name] = {"value": value, "note": note}
v = A(app, 'debuggable'); flag("debuggable", v, "")
if v == 'true': cand("DEBUGGABLE", "<application>", "android:debuggable=true: run-as, JDWP attach, adb backup allowed — MASTG-TEST-0226", "D02")
v = A(app, 'allowBackup')
flag("allowBackup", v if v is not None else "unset (default true)",
     "adb backup is restricted since Android 12 and needs debuggable=true (MASTG-KNOW-0050 l.9); cloud/D2D backup still follows the rules below")
if v != 'false': cand("BACKUP-ALLOWED", "<application>", "allowBackup is %s — check backup rules and what lands in the backup set — MASTG-TEST-0216 / -0262" % (v or "unset (default true)"), "D11")
v = A(app, 'usesCleartextTraffic')
if v is None:
    flag("usesCleartextTraffic", "unset", "default: %s (targetSdk %s; NSC overrides) — MASTG-KNOW-0014" % ("PERMITTED" if gate(28) else "blocked", T))
    if gate(28): cand("CLEARTEXT-DEFAULT", "<application>", "no usesCleartextTraffic and targetSdk<28 (or unknown): cleartext permitted by default", "D14")
else:
    flag("usesCleartextTraffic", v, "explicit; NSC overrides it")
    if v == 'true': cand("CLEARTEXT-EXPLICIT", "<application>", "android:usesCleartextTraffic=true", "D14")
nsc_ref = A(app, 'networkSecurityConfig'); flag("networkSecurityConfig", nsc_ref, "")
v = root.get(NS + 'sharedUserId'); flag("sharedUserId", v, "")
if v: cand("SHARED-USER-ID", "<manifest>", "sharedUserId=%s: any package signed with the same key and declaring it shares the UID (deprecated since API 29)" % v, "D03")
for k in ('dataExtractionRules', 'fullBackupContent', 'requestLegacyExternalStorage', 'testOnly', 'extractNativeLibs', 'usesNonSdkApi', 'allowClearUserData'):
    flag(k, A(app, k), "")
flag("application android:permission", app_perm, "inherited by every component that sets none")
flag("application android:taskAffinity", app_affinity, "")
for m in re.finditer(r'android:(intentMatchingFlags|allowNullAction)="([^"]*)"', raw_text):
    flag(m.group(1), m.group(2), "present in manifest (Android 16 intent-matching attributes) — read the behaviour-change notes before relying on defaults")
if A(app, 'testOnly') == 'true': cand("TEST-ONLY", "<application>", "testOnly=true build", "D02")
if A(app, 'requestLegacyExternalStorage') == 'true': cand("LEGACY-EXTERNAL-STORAGE", "<application>", "requestLegacyExternalStorage=true (effective only when targeting <=29 on Android 10 — MASTG-KNOW-0042 l.21)", "D11")

# ---------------------------------------------------------------- permissions declared / requested
declared = {}
for p in root.iter('permission'):
    declared[A(p, 'name', '?')] = A(p, 'protectionLevel') or 'normal (DEFAULT — implicit)'
perm_trees = [A(p, 'name', '?') for p in root.iter('permission-tree')]
perm_groups = [A(p, 'name', '?') for p in root.iter('permission-group')]
for name, lvl in declared.items():
    if lvl.startswith('normal') or lvl.startswith('dangerous'):
        cand("CUSTOM-PERM-" + lvl.split()[0].upper(), "<permission %s>" % name,
             "protectionLevel %s: an attacker app installed first can define it and hold it (permission squatting); anything gated on it is reachable" % lvl, "D03")
requested = [{"name": A(p, 'name', '?'), "maxSdkVersion": A(p, 'maxSdkVersion')} for p in root.iter('uses-permission')]
requested += [{"name": A(p, 'name', '?') + " (uses-permission-sdk-23)", "maxSdkVersion": A(p, 'maxSdkVersion')} for p in root.iter('uses-permission-sdk-23')]
queries = []
q = root.find('queries')
if q is not None:
    for c in q:
        queries.append({"kind": c.tag, "name": A(c, 'name'), "detail": {k.replace(NS, 'android:'): v for k, v in c.attrib.items()}, "children": [{cc.tag: {k.replace(NS, 'android:'): v for k, v in cc.attrib.items()}} for cc in c]})

# Well-known runtime ("dangerous") platform permissions; confirm on the device: adb shell pm list permissions -d -g
DANGEROUS = set("""READ_CALENDAR WRITE_CALENDAR CAMERA READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION RECORD_AUDIO READ_PHONE_STATE READ_PHONE_NUMBERS CALL_PHONE
ANSWER_PHONE_CALLS READ_CALL_LOG WRITE_CALL_LOG ADD_VOICEMAIL USE_SIP PROCESS_OUTGOING_CALLS BODY_SENSORS
BODY_SENSORS_BACKGROUND SEND_SMS RECEIVE_SMS READ_SMS RECEIVE_WAP_PUSH RECEIVE_MMS READ_EXTERNAL_STORAGE
WRITE_EXTERNAL_STORAGE ACCESS_MEDIA_LOCATION ACTIVITY_RECOGNITION BLUETOOTH_SCAN BLUETOOTH_ADVERTISE
BLUETOOTH_CONNECT POST_NOTIFICATIONS NEARBY_WIFI_DEVICES READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO
READ_MEDIA_VISUAL_USER_SELECTED UWB_RANGING""".split())
def perm_class(perm):
    if not perm: return "none"
    if perm in declared: return "custom:" + declared[perm].split()[0]
    if perm.startswith('android.permission.'):
        return "platform:dangerous" if perm.split('.')[-1] in DANGEROUS else "platform:other"
    return "custom:undeclared-here"
def am_for(cls):
    if cls == "none": return "AM-03"
    kind = cls.split(':', 1)[1]
    if any(s in kind for s in ("signature", "privileged", "system", "knownSigner")):
        return "n/a-third-party (signature-class permission)"
    if kind == "dangerous": return "AM-04 (needs a user-granted permission)"
    if kind == "undeclared-here": return "AM-03 if an attacker app defines the permission first (squatting) — VERIFY who declares it"
    if kind == "other": return "VERIFY protection level: adb shell pm list permissions -f | grep -A3 <perm>"
    return "AM-03 (normal permission: any app can request it)"

# ---------------------------------------------------------------- components
def fq(name):
    if not name: return '?'
    if name.startswith('.'): return pkg + name
    if '.' not in name: return pkg + '.' + name
    return name
def parse_filter(f):
    schemes, hosts, paths, mimes = [], [], [], []
    for d in f.findall('data'):
        s, h, p, m = A(d, 'scheme'), A(d, 'host'), A(d, 'port'), A(d, 'mimeType')
        if s: schemes.append(s)
        if h: hosts.append(h + (':' + p if p else ''))
        for k in ('path', 'pathPrefix', 'pathPattern', 'pathSuffix', 'pathAdvancedPattern'):
            vv = A(d, k)
            if vv is not None: paths.append({"kind": k, "value": vv})
        if m: mimes.append(m)
    return {"actions": [A(a, 'name', '') for a in f.findall('action')],
            "categories": [A(c, 'name', '') for c in f.findall('category')],
            "schemes": uniq(schemes), "hosts": uniq(hosts),
            "paths": [dict(t) for t in uniq(tuple(sorted(p.items())) for p in paths)],
            "mimeTypes": uniq(mimes), "autoVerify": A(f, 'autoVerify') == 'true',
            "priority": A(f, 'priority'), "order": A(f, 'order')}
def path_glob(p):
    k, v = p["kind"], p["value"]
    return {"path": v, "pathPrefix": v + "*", "pathPattern": v, "pathSuffix": "*" + v, "pathAdvancedPattern": v}[k]
def uri_patterns(flt):
    """scheme x host x path — the merge rule (MASTG-TECH-0172 l.39; MASTG-TEST-0028 (deprecated; see MASTG-TEST-0393) l.72)."""
    if not flt["schemes"]:
        return [], ("no scheme in this filter: host/path/port attributes are ignored by the resolver (data-element docs)" if flt["hosts"] or flt["paths"] else "")
    hosts = flt["hosts"] or ['*']
    paths = [path_glob(p) for p in flt["paths"]] or ['']
    pats = ["%s://%s%s" % (s, h, p) for s in flt["schemes"] for h in hosts for p in paths]
    return pats[:200], ("" if len(pats) <= 200 else "(%d patterns, 200 shown)" % len(pats))

def export_state(tag, el, has_filter):
    exp = A(el, 'exported')
    if exp == 'true': return True, "explicit"
    if exp == 'false': return False, "explicit false"
    if has_filter:
        if gate(31): return True, "IMPLICIT (intent-filter, targetSdk<31%s)" % (" or unknown" if T is None else "")
        return True, "intent-filter without android:exported while targetSdk>=31 — install is refused on API 31+; VERIFY (merged manifest?)"
    if tag == 'provider' and gate(17): return True, "IMPLICIT (provider default, targetSdk<17%s)" % (" or unknown" if T is None else "")
    return False, "not exported (default)"

DOM = {"activity": "D04", "activity-alias": "D04", "service": "D06", "receiver": "D05", "provider": "D07"}
components, deeplinks, providers, task_rows = [], [], [], []
n_exported = 0
for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
    for el in app.iter(tag):
        name = fq(A(el, 'name'))
        filters = [parse_filter(f) for f in el.findall('intent-filter')]
        effective, reason = export_state(tag, el, bool(filters))
        enabled = A(el, 'enabled')
        perm = A(el, 'permission')
        rperm = wperm = None
        if tag == 'provider':
            rperm, wperm = A(el, 'readPermission'), A(el, 'writePermission')
        eff_perm = perm or app_perm
        inherited = (perm is None and app_perm is not None)
        gate_perm = eff_perm or rperm or wperm
        cls = perm_class(eff_perm) if eff_perm else ("none" if not (rperm or wperm) else "provider:read/write")
        am = am_for(cls) if cls != "provider:read/write" else "see read/write permissions"
        c = {"type": tag, "name": name, "exported": effective, "export_reason": reason, "enabled": enabled,
             "permission": perm, "permission_inherited_from_application": inherited, "effective_permission": eff_perm,
             "permission_class": cls, "attacker_model": am, "domain": DOM[tag],
             "process": A(el, 'process'), "intent_filters": filters, "flags": []}
        if tag in ('activity', 'activity-alias'):
            for k in ('launchMode', 'taskAffinity', 'allowTaskReparenting', 'targetActivity', 'excludeFromRecents', 'autoRemoveFromRecents', 'documentLaunchMode', 'allowEmbedded', 'noHistory', 'showWhenLocked', 'turnScreenOn'):
                vv = A(el, k)
                if vv is not None: c[k] = vv
        if tag == 'service':
            for k in ('foregroundServiceType', 'isolatedProcess', 'directBootAware'):
                vv = A(el, k)
                if vv is not None: c[k] = vv
        if tag == 'provider':
            c["authorities"] = [a for a in (A(el, 'authorities') or '').split(';') if a]
            c["readPermission"], c["writePermission"] = rperm, wperm
            c["grantUriPermissions"] = A(el, 'grantUriPermissions') == 'true'
            c["grant_uri_permission_paths"] = [{k.replace(NS, ''): v for k, v in g.attrib.items()} for g in el.findall('grant-uri-permission')]
            c["path_permissions"] = [{k.replace(NS, ''): v for k, v in g.attrib.items()} for g in el.findall('path-permission')]
            fp_ref = None
            for md in el.findall('meta-data'):
                if A(md, 'name') == 'android.support.FILE_PROVIDER_PATHS': fp_ref = A(md, 'resource')
            c["file_provider_paths_ref"] = fp_ref
        components.append(c)
        if not effective: continue
        n_exported += 1
        fl = c["flags"]
        if reason.startswith("IMPLICIT"): fl.append("IMPLICIT-EXPORT")
        if reason.startswith("intent-filter without"): fl.append("VERIFY-TARGETSDK")
        if enabled == 'false': fl.append("DISABLED (reachable only after setComponentEnabledSetting)")
        if not gate_perm: fl.append("NO-PERMISSION")
        elif inherited: fl.append("PERMISSION-INHERITED-FROM-APPLICATION")
        if cls == "custom:undeclared-here": fl.append("PERMISSION-NOT-DECLARED-HERE (squatting candidate)")
        if tag in ('activity', 'activity-alias'):
            lm = c.get('launchMode'); ta = c.get('taskAffinity'); rp = c.get('allowTaskReparenting')
            if lm in ('singleTask', 'singleInstance'): fl.append("launchMode=" + lm)
            if ta is not None: fl.append("taskAffinity=%r" % ta)
            if rp == 'true': fl.append("allowTaskReparenting")
            if c.get('targetActivity'): fl.append("alias->" + fq(c['targetActivity']))
            if c.get('showWhenLocked') == 'true': fl.append("showWhenLocked")
            eff_aff = ta if ta is not None else (app_affinity if app_affinity is not None else pkg)
            task_rows.append({"activity": name, "launchMode": lm or "standard", "taskAffinity_effective": eff_aff if eff_aff != "" else '"" (opted out)',
                              "allowTaskReparenting": rp == 'true', "exported": True})
        if tag == 'provider':
            if c["grantUriPermissions"]: fl.append("GRANT-URI" + ("" if c["grant_uri_permission_paths"] else " (whole provider grantable)"))
            if rperm and not wperm: fl.append("READ-ONLY-PERM-ASYMMETRY (write/insert/update/delete gated only by android:permission=%s)" % eff_perm)
            if wperm and not rperm: fl.append("WRITE-ONLY-PERM-ASYMMETRY (query/openFile gated only by android:permission=%s)" % eff_perm)
            if c["path_permissions"]: fl.append("PATH-PERMISSIONS (UriMatcher precision: prefix vs exact, pattern greed, case)")
            if 'FileProvider' in name: fl.append("FILEPROVIDER-EXPORTED (FileProvider refuses to run exported — VERIFY, misconfiguration)")
        cand("EXPORTED-" + tag.upper(), name, "export=%s perm=%s -> %s%s" % (reason, gate_perm or "NONE", am, (" | " + " | ".join(fl)) if fl else ""), DOM[tag])
        # deep links declared on this component
        for flt in filters:
            if 'android.intent.action.VIEW' not in flt["actions"]: continue
            pats, note = uri_patterns(flt)
            if not pats and not flt["mimeTypes"] and not note: continue
            browsable = 'android.intent.category.BROWSABLE' in flt["categories"]
            row = {"component": name, "autoVerify": flt["autoVerify"], "browsable": browsable, "schemes": flt["schemes"], "hosts": flt["hosts"],
                   "paths": flt["paths"], "mimeTypes": flt["mimeTypes"], "uri_patterns": pats, "note": note}
            if flt["mimeTypes"] and not flt["schemes"]:
                row["note"] = (note + "; " if note else "") + "mimeType without scheme: content:// and file:// URIs match (data-element docs)"
            deeplinks.append(row)
            web = [s for s in flt["schemes"] if s in ('http', 'https')]
            custom = [s for s in flt["schemes"] if s not in ('http', 'https')]
            if web and not flt["autoVerify"]:
                cand("WEB-SCHEME-NO-AUTOVERIFY", name, "http(s) hosts %s without autoVerify: plain deep link, any app can claim the same URIs — MASTG-TEST-0393" % (flt["hosts"] or ['*']), "D09")
            if custom:
                cand("CUSTOM-SCHEME", name, "scheme(s) %s%s: unverifiable, hijackable by any app declaring the same filter — MASTG-TEST-0394" % (custom, " (BROWSABLE)" if browsable else ""), "D09")
            if flt["autoVerify"] and custom:
                cand("AUTOVERIFY-FILTER-MIXES-CUSTOM-SCHEME", name, "custom scheme inside an autoVerify filter: before API 31 one non-verifiable link can skip verification of ALL the app's App Links — MASTG-KNOW-0019 l.52", "D09")
            if flt["autoVerify"] and not flt["hosts"]:
                cand("AUTOVERIFY-WITHOUT-HOST", name, "autoVerify on a filter with no host: nothing to verify, resolver treats it as a plain deep link", "D09")

# providers: authorities + FileProvider path configs
for c in components:
    if c["type"] != 'provider': continue
    row = {"name": c["name"], "authorities": c["authorities"], "exported": c["exported"], "export_reason": c["export_reason"],
           "permission": c["effective_permission"], "readPermission": c["readPermission"], "writePermission": c["writePermission"],
           "grantUriPermissions": c["grantUriPermissions"], "grant_uri_permission_paths": c["grant_uri_permission_paths"],
           "path_permissions": c["path_permissions"], "file_provider_paths": None, "file_provider_flags": []}
    ref = c["file_provider_paths_ref"]
    if ref:
        p = resolve_xml(ref)
        if p:
            row["file_provider_paths"] = {"file": os.path.relpath(p, decdir), "entries": []}
            try:
                froot = ET.parse(p).getroot()
                for e in froot:
                    ent = {"tag": e.tag, "name": e.get('name'), "path": e.get('path')}
                    row["file_provider_paths"]["entries"].append(ent)
                    if e.tag == 'root-path':
                        row["file_provider_flags"].append("root-path name=%s path=%s (filesystem root — any grant reaches /data, /sdcard, /proc)" % (ent["name"], ent["path"]))
                    elif ent["path"] in (None, '', '.', '/'):
                        row["file_provider_flags"].append("%s name=%s path=%r (whole directory shared)" % (e.tag, ent["name"], ent["path"]))
            except Exception as e:
                row["file_provider_paths"]["entries"] = "(parse failed: %s)" % e
        else:
            row["file_provider_paths"] = {"file": ref, "entries": "(unresolved: %s)" % ("res/xml not available" if not have_res else "file missing under res/xml")}
            if have_res: unv("FileProvider paths %s referenced by %s not found under res/xml" % (ref, c["name"]))
    for fl in row["file_provider_flags"]:
        cand("FILEPROVIDER-PATHS", c["name"], "%s — exported=%s grantUriPermissions=%s" % (fl, c["exported"], c["grantUriPermissions"]), "D07")
    providers.append(row)

# ---------------------------------------------------------------- network security config
nsc = {"ref": nsc_ref, "file": None, "cleartext_default": "PERMITTED" if gate(28) else "blocked",
       "user_ca_default": "trusted" if gate(24) else "not trusted", "configs": [], "pin_sets": [], "content": None}
if nsc_ref:
    p = resolve_xml(nsc_ref)
    if p:
        nsc["file"] = os.path.relpath(p, decdir); nsc["content"] = read_file(p)
        try:
            for cfg in ET.parse(p).getroot():
                if cfg.tag not in ('base-config', 'domain-config', 'debug-overrides'): continue
                doms = [d.text.strip() for d in cfg.iter('domain') if d.text]
                ct = cfg.get('cleartextTrafficPermitted')
                srcs = [c.get('src') for ta in cfg.findall('trust-anchors') for c in ta.findall('certificates')]
                pins = [{"domains": doms, "pins": len(ps.findall('pin')), "expiration": ps.get('expiration')} for ps in cfg.findall('pin-set')]
                nsc["configs"].append({"tag": cfg.tag, "domains": doms, "cleartextTrafficPermitted": ct, "trust_anchors": srcs, "pin_sets": pins})
                nsc["pin_sets"] += pins
                dbg = " (debug-overrides: debuggable builds only — D02 first)" if cfg.tag == 'debug-overrides' else ""
                if ct == 'true': cand("NSC-CLEARTEXT", nsc["file"], "<%s cleartextTrafficPermitted=true> domains=%s%s — MASTG-TEST-0024" % (cfg.tag, doms or ['(all)'], dbg), "D14")
                if 'user' in srcs: cand("NSC-USER-CA", nsc["file"], "<%s> trusts user-installed CAs domains=%s%s — MASTG-KNOW-0014" % (cfg.tag, doms or ['(all)'], dbg), "D14")
                for ps in pins:
                    if ps["expiration"]: cand("NSC-PIN-EXPIRATION", nsc["file"], "pin-set for %s expires %s: pinning silently stops after that date" % (ps["domains"] or ['(all)'], ps["expiration"]), "D14")
            if not nsc["pin_sets"]: nsc["pinning"] = "no <pin-set> in NSC (pinning may still live in code: OkHttp CertificatePinner, TrustKit, Flutter/RN native)"
        except Exception as e:
            unv("NSC parse failed (%s): %s" % (nsc["file"], e))
    else:
        unv("networkSecurityConfig %s not resolvable (%s)" % (nsc_ref, "res/xml not available" if not have_res else "file missing under res/xml"))
else:
    nsc["content"] = "no NSC: platform defaults apply (cleartext %s, user CAs %s)" % (nsc["cleartext_default"], nsc["user_ca_default"])
    if gate(24): cand("USER-CA-DEFAULT", "<application>", "no NSC and targetSdk<24 (or unknown): user-installed CAs trusted by default — MASTG-KNOW-0014", "D14")

# ---------------------------------------------------------------- backup rules
backup = {"allowBackup": flags["allowBackup"]["value"], "rules": []}
for k in ('fullBackupContent', 'dataExtractionRules'):
    ref = A(app, k)
    if not ref: continue
    if ref in ('true', 'false'):
        backup["rules"].append({"attr": k, "value": ref})
        if k == 'fullBackupContent' and ref == 'false': pass
        continue
    p = resolve_xml(ref)
    if not p:
        unv("%s=%s not resolvable (%s)" % (k, ref, "res/xml not available" if not have_res else "file missing under res/xml")); continue
    txt = read_file(p); rel = os.path.relpath(p, decdir)
    inc, exc = len(re.findall(r'<include\b', txt)), len(re.findall(r'<exclude\b', txt))
    backup["rules"].append({"attr": k, "file": rel, "include": inc, "exclude": exc, "content": txt})
    if k == 'dataExtractionRules' and '<device-transfer' not in txt:
        cand("BACKUP-RULES-NO-D2D", rel, "dataExtractionRules without <device-transfer>: device-to-device transfer uses the defaults (whole sandbox) — MASTG-TEST-0262", "D11")
    if k == 'dataExtractionRules' and '<cloud-backup' not in txt:
        cand("BACKUP-RULES-NO-CLOUD", rel, "dataExtractionRules without <cloud-backup>: cloud backup uses the defaults (whole sandbox)", "D11")
    if exc == 0:
        cand("BACKUP-RULES-NO-EXCLUDE", rel, "%s: %d <include>, 0 <exclude> — nothing is kept out of the backup set; read what the included domains hold" % (k, inc), "D11")
if backup["allowBackup"] != 'false' and not backup["rules"]:
    cand("BACKUP-NO-RULES", "<application>", "allowBackup not false and no fullBackupContent/dataExtractionRules: the whole sandbox (except no_backup/, cache/, code_cache/) is in the backup set — MASTG-TEST-0216", "D11")

# ---------------------------------------------------------------- framework / native libs (apktool keeps lib/ and assets/ with -s)
import fnmatch
names = []
if apk:
    try:
        with zipfile.ZipFile(apk) as z: names = z.namelist()
    except Exception as e:
        unv("APK not readable as zip (%s): framework detection from the decoded tree only" % e)
if not names:
    for sub in ('lib', 'assets'):
        base = os.path.join(decdir, sub)
        for dp, dn, fn in os.walk(base):
            for f in fn: names.append(os.path.relpath(os.path.join(dp, f), decdir).replace(os.sep, '/'))
            if len(names) > 20000: break
FW = [("flutter", ["lib/*/libflutter.so", "lib/*/libapp.so", "assets/flutter_assets/*"]),
      ("react-native", ["lib/*/libreactnativejni.so", "lib/*/libreactnative.so", "assets/index.android.bundle"]),
      ("hermes", ["lib/*/libhermes.so", "lib/*/libhermes_executor.so"]),
      ("xamarin/.net", ["lib/*/libmonodroid.so", "lib/*/libmonosgen-2.0.so", "lib/*/libxamarin-app.so", "assemblies/*"]),
      ("unity", ["lib/*/libunity.so", "lib/*/libil2cpp.so"]),
      ("cordova", ["assets/www/cordova.js"]), ("capacitor", ["assets/capacitor.config.json", "assets/public/index.html"]),
      ("kotlin/compose", ["assets/dexopt/*", "lib/*/libdatastore_shared_counter.so"]),
      ("expo-updates", ["assets/app.manifest", "assets/expo-updates*"]), ("codepush", ["assets/CodePush*"]),
      ("webview-heavy", ["assets/*.html", "assets/www/*"]), ("ionic", ["assets/public/cordova.js"])]
framework = {"detected": [], "native_libs": sorted({n.split('/')[-1] for n in names if n.startswith('lib/') and n.endswith('.so')}),
             "abis": sorted({n.split('/')[1] for n in names if n.startswith('lib/') and n.count('/') >= 2}),
             "source": "APK zip listing" if apk else ("decoded tree lib/ + assets/" if names else None)}
for fw, pats in FW:
    hits = [n for n in names if any(fnmatch.fnmatch(n, p) for p in pats)]
    if hits: framework["detected"].append({"framework": fw, "evidence": hits[:5]})
if not names: unv("framework detection skipped (manifest-only input: no lib/ or assets/ listing) — D19 cannot be marked n/a from this run")
for d in framework["detected"]:
    cand("FRAMEWORK-" + d["framework"].upper().replace('/', '-'), d["evidence"][0], "%s artefacts: route this app through the D19 chapter (cross-platform) before the Java-centric domains" % d["framework"], "D19")
if names and not framework["detected"]: framework["note"] = "no cross-platform artefacts: Java/Kotlin app (D19 n/a candidate — confirm with the dex class list)"

# ---------------------------------------------------------------- signer digest (what assetlinks.json must carry)
signer = {"source": None, "schemes": [], "sha256": [], "note": None}
def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode(errors='replace')
    except Exception as e:
        return 127, str(e)
def sig_block_certs(path):
    """sha256 of every signer certificate in the APK Signing Block (v3.1/v3/v2). Stdlib only."""
    res, schemes = [], []
    with open(path, 'rb') as f:
        f.seek(0, 2); size = f.tell(); f.seek(max(0, size - 65557)); tail = f.read()
        i = tail.rfind(b'PK\x05\x06')
        if i < 0: return res, schemes, "no EOCD"
        cd_off = struct.unpack('<I', tail[i + 16:i + 20])[0]
        if cd_off < 32: return res, schemes, "no central directory"
        f.seek(cd_off - 24); foot = f.read(24)
        if foot[8:] != b'APK Sig Block 42': return res, schemes, "no APK Signing Block (v1-only signature?)"
        blen = struct.unpack('<Q', foot[:8])[0]
        f.seek(cd_off - blen - 8); blk = f.read(blen + 8)
    u32 = lambda b, o: struct.unpack('<I', b[o:o + 4])[0]
    pos, end, found = 8, 8 + blen - 24, {}
    while pos + 12 <= end:
        ln, idv = struct.unpack('<QI', blk[pos:pos + 12]); found[idv] = blk[pos + 12:pos + 8 + ln]; pos += 8 + ln
    for idv, name in ((0x1b93ad61, 'v3.1'), (0xf05368c0, 'v3'), (0x7109871a, 'v2')):
        v = found.get(idv)
        if v is None: continue
        schemes.append(name)
        try:
            o, endv = 4, 4 + u32(v, 0)
            while o + 4 <= endv:
                sl = u32(v, o); sg = v[o + 4:o + 4 + sl]; o += 4 + sl
                sd = sg[4:4 + u32(sg, 0)]
                p = 4 + u32(sd, 0)                       # skip digests
                cl = u32(sd, p); p += 4; cend = p + cl
                while p + 4 <= cend:
                    l = u32(sd, p); res.append((name, hashlib.sha256(sd[p + 4:p + 4 + l]).hexdigest())); p += 4 + l
        except Exception as e:
            return res, schemes, "parse error in %s block: %s" % (name, e)
    return res, schemes, None
if apk:
    if apksigner:
        rc, o = run([apksigner, 'verify', '--print-certs', '--verbose', apk])
        if rc == 0:
            signer["source"] = "apksigner"
            signer["sha256"] = uniq([m.group(1).lower() for m in re.finditer(r'certificate SHA-256 digest: ([0-9a-fA-F]{64})', o)])
            signer["schemes"] = ["v%s" % m.group(1) for m in re.finditer(r'Verified using v([0-9.]+) scheme[^:]*: true', o)]
            signer["rotation"] = "lineage present" if 'lineage' in o.lower() and 'Signer' in o else None
        else:
            unv("apksigner verify failed (%s): falling back to the inline signing-block parser" % o.strip().splitlines()[-1:] )
    if not signer["sha256"]:
        try:
            certs, schemes, err = sig_block_certs(apk)
            if certs:
                signer["source"] = "inline APK Signing Block parser"; signer["schemes"] = schemes
                signer["sha256"] = uniq([h for _, h in certs])
            elif err: unv("signer digest: %s" % err)
        except Exception as e:
            unv("signer digest: inline parser failed: %s" % e)
    if not signer["sha256"] and keytool:
        rc, o = run([keytool, '-printcert', '-jarfile', apk])
        hs = [m.group(1).replace(':', '').lower() for m in re.finditer(r'SHA256:\s*([0-9A-Fa-f:]{95})', o)]
        if hs: signer["source"] = "keytool -printcert -jarfile (v1)"; signer["sha256"] = uniq(hs); signer["schemes"] = ["v1"]
    if not signer["sha256"]: unv("signer digest unavailable: install apksigner (build-tools) or keytool, or read it on device: adb shell dumpsys package %s | grep -A2 signatures" % (pkg or '<pkg>'))
    if signer["sha256"] and len(signer["sha256"]) > 1: signer["note"] = "more than one certificate: rotation lineage or multiple signers — every one must be in assetlinks.json (tools/04 --apk compares)"
else:
    unv("signer digest needs the APK (input was a manifest or a decoded directory): pass base.apk, or tools/04-applink-verify.sh --apk base.apk")
signer["fingerprint_colon"] = [':'.join(h[i:i + 2] for i in range(0, 64, 2)).upper() for h in signer["sha256"]]

# ---------------------------------------------------------------- report
by_domain = {}
for c in cands: by_domain.setdefault(c["domain"], []).append(c)
L = []
w = L.append
w("# tools/01 surface inventory  run=%s  package=%s" % (run_id, pkg or '?'))
w("# input: %s  (%s)" % (manifest, "APK " + apk if apk else "decoded tree"))
w("# targetSdk=%s minSdk=%s (%s)  exported=%d/%d components  CANDIDATE=%d  UNVERIFIED=%d" % (
    sdk["target"], sdk["min"], sdk["source"] or "unknown", n_exported, len(components), len(cands), len(unverified)))
w("")
w("== targetSdk gates (what the platform defaults to for THIS app; targetSdk decides, not minSdk)")
for g in gates:
    w("   %-8s <%-3s %s  [%s]" % ("APPLIES" if g["applies"] else "no", g["below"], g["effect"], g["source"]))
w("")
w("== application flags")
for k, v in flags.items():
    w("   %-36s %s%s" % (k, v["value"], ("   # " + v["note"]) if v["note"] else ""))
w("")
w("== permissions")
w("   declared (%d):" % len(declared))
for k, v in declared.items(): w("      %-60s %s" % (k, v))
if perm_trees: w("   permission-tree: %s" % perm_trees)
if perm_groups: w("   permission-group: %s" % perm_groups)
w("   requested (%d):" % len(requested))
for r in requested:
    nm = r["name"]; base = nm.split(' ')[0]
    w("      %-70s %s%s" % (nm, perm_class(base), ("  maxSdk=" + r["maxSdkVersion"]) if r["maxSdkVersion"] else ""))
w("   <queries>: %s" % (("%d entries" % len(queries)) if queries else ("none (targetSdk<30: full visibility)" if gate(30) else "none")))
for qq in queries: w("      %s %s %s" % (qq["kind"], qq["name"] or "", qq["detail"] if not qq["name"] else ""))
w("")
w("== components (%d; exported %d). Export reason, effective permission (inherited from <application> where noted), attacker model." % (len(components), n_exported))
for c in components:
    mark = "EXPORTED" if c["exported"] else "internal"
    w("   %-8s %-16s %s" % (mark, c["type"], c["name"]))
    w("            export=%s  perm=%s (%s)  AM=%s%s" % (c["export_reason"], c["effective_permission"] or "NONE", c["permission_class"], c["attacker_model"],
                                                     ("  process=" + c["process"]) if c["process"] else ""))
    if c["flags"]: w("            flags: " + " | ".join(c["flags"]))
    if c["type"] == 'provider': w("            authorities=%s read=%s write=%s grant=%s" % (c["authorities"], c["readPermission"], c["writePermission"], c["grantUriPermissions"]))
    for f in c["intent_filters"]:
        w("            filter: actions=%s cats=%s schemes=%s hosts=%s paths=%s mime=%s%s%s" % (
            [a.replace('android.intent.action.', '') for a in f["actions"]], [x.replace('android.intent.category.', '') for x in f["categories"]],
            f["schemes"], f["hosts"], [p["kind"] + "=" + p["value"] for p in f["paths"]], f["mimeTypes"],
            " autoVerify" if f["autoVerify"] else "", (" priority=" + f["priority"]) if f["priority"] else ""))
w("")
w("== task surface (exported activities: launchMode / effective taskAffinity / reparenting — D04 task hijacking, StrandHogg)")
for t in task_rows: w("   %-70s %-14s affinity=%s%s" % (t["activity"], t["launchMode"], t["taskAffinity_effective"], "  allowTaskReparenting" if t["allowTaskReparenting"] else ""))
w("")
w("== deep links (%d VIEW filters on exported components; fire them with tools/07, mutate with tools/08)" % len(deeplinks))
for d in deeplinks:
    w("   %s%s%s" % (d["component"], "  autoVerify" if d["autoVerify"] else "", "  BROWSABLE" if d["browsable"] else "  (not BROWSABLE: app-to-app only)"))
    for u in d["uri_patterns"][:40]: w("      " + u)
    if len(d["uri_patterns"]) > 40: w("      ... %d patterns" % len(d["uri_patterns"]))
    if d["mimeTypes"]: w("      mime=%s" % d["mimeTypes"])
    if d["note"]: w("      note: " + d["note"])
w("")
w("== providers (%d)" % len(providers))
for p in providers:
    w("   %s  %s  authorities=%s" % ("EXPORTED" if p["exported"] else "internal", p["name"], p["authorities"]))
    w("      perm=%s read=%s write=%s grantUri=%s grant-paths=%s path-permissions=%s" % (p["permission"], p["readPermission"], p["writePermission"], p["grantUriPermissions"], p["grant_uri_permission_paths"], p["path_permissions"]))
    fp = p["file_provider_paths"]
    if fp:
        w("      FileProvider paths %s: %s" % (fp["file"], fp["entries"] if isinstance(fp["entries"], str) else ", ".join("%s(name=%s path=%s)" % (e["tag"], e["name"], e["path"]) for e in fp["entries"])))
    for fl in p["file_provider_flags"]: w("      !! " + fl)
w("")
w("== network security config: %s" % (nsc["file"] or nsc_ref or "none"))
w("   defaults for targetSdk %s: cleartext %s, user CAs %s" % (T, nsc["cleartext_default"], nsc["user_ca_default"]))
for cfg in nsc["configs"]:
    w("   <%s> domains=%s cleartext=%s trust-anchors=%s pin-sets=%s" % (cfg["tag"], cfg["domains"] or ['(all)'], cfg["cleartextTrafficPermitted"], cfg["trust_anchors"], cfg["pin_sets"]))
if nsc.get("pinning"): w("   " + nsc["pinning"])
if nsc["content"] and not nsc["configs"]: w("   " + nsc["content"].splitlines()[0])
w("")
w("== backup: allowBackup=%s" % backup["allowBackup"])
for r in backup["rules"]:
    if "file" in r: w("   %s -> %s  (%d include / %d exclude)" % (r["attr"], r["file"], r["include"], r["exclude"]))
    else: w("   %s=%s" % (r["attr"], r["value"]))
w("")
w("== framework: %s" % (", ".join(d["framework"] for d in framework["detected"]) or framework.get("note") or "UNVERIFIED (no listing)"))
for d in framework["detected"]: w("   %-14s %s" % (d["framework"], d["evidence"]))
w("   abis=%s native libs=%d%s" % (framework["abis"], len(framework["native_libs"]), (": " + ", ".join(framework["native_libs"][:12]) + (" ..." if len(framework["native_libs"]) > 12 else "")) if framework["native_libs"] else ""))
w("")
w("== signer (%s): schemes=%s" % (signer["source"] or "unavailable", signer["schemes"]))
for h, fc in zip(signer["sha256"], signer["fingerprint_colon"]): w("   sha256 %s\n          %s" % (h, fc))
if signer["note"]: w("   " + signer["note"])
w("")
w("== CANDIDATES (%d) — static surface; confirm on device, re-prove from attacker-app/ (AM-03) before report.md" % len(cands))
for dom in sorted(by_domain):
    w("   -- %s (%d)" % (dom, len(by_domain[dom])))
    for c in by_domain[dom]: w("   CANDIDATE %-36s %s\n      %s" % (c["tag"], c["where"], c["detail"]))
w("")
w("== UNVERIFIED (%d) — checks that did not run; never record a negative from them" % len(unverified))
for u in unverified: w("   UNVERIFIED: " + u)
w("")
w("NEXT: python3 scripts/inventory.py (registers components/deeplinks/providers from surface.json) -> tools/07 + tools/08 (deep links),")
w("      tools/09 (providers), tools/05 (storage, --manifest), tools/04 --apk (App Link assetlinks vs the signer digest above).")
text = "\n".join(L) + "\n"
try:
    open(os.path.join(out, "inventory.txt"), "w", encoding="utf-8").write(text)
except Exception as e:
    print("ERROR: cannot write inventory.txt: %s" % e, file=sys.stderr); sys.exit(2)
surface = {"tool": "01-surface-inventory", "run_id": run_id, "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
           "package": pkg, "input": {"manifest": manifest, "apk": apk or None, "decoded_dir": decdir, "res_xml_available": have_res},
           "sdk": sdk, "gates": gates, "application": {"attrs": app_attrs, "flags": flags},
           "permissions": {"declared": declared, "permission_trees": perm_trees, "permission_groups": perm_groups, "requested": requested, "queries": queries},
           "components": components, "counts": {"components": len(components), "exported": n_exported, "deeplinks": len(deeplinks), "providers": len(providers),
                                                "candidates": len(cands), "unverified": len(unverified)},
           "task_surface": task_rows, "deeplinks": deeplinks, "providers": providers, "nsc": nsc, "backup": backup, "framework": framework,
           "signer": signer, "candidates": cands, "candidates_by_domain": {d: len(v) for d, v in by_domain.items()}, "unverified": unverified,
           "note": "static inventory: CANDIDATE lines are attack surface, not findings; confirm on device and re-prove from attacker-app/ (AM-03)."}
try:
    json.dump(surface, open(os.path.join(out, "surface.json"), "w", encoding="utf-8"), indent=1, default=str)
except Exception as e:
    print("ERROR: cannot write surface.json: %s" % e, file=sys.stderr); sys.exit(2)
if logpath:
    try:
        open(logpath, "a", encoding="utf-8").write(text + "\n")
    except Exception as e:
        unv("could not append to %s: %s" % (logpath, e))
if mode == "json":
    print(json.dumps(surface, indent=1, default=str))
elif quiet != "1":
    sys.stdout.write(text)
print("[+] %d CANDIDATE, %d UNVERIFIED -> %s/inventory.txt, surface.json, AndroidManifest.xml%s" % (len(cands), len(unverified), out, ("  (appended to %s)" % logpath) if logpath else ""), file=sys.stderr)
sys.exit(0 if cands else 1)
PY
RC=$?
exit $RC
