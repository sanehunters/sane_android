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
python3 -I - "$MANIFEST" "$DEC" "$APK" "$OUT" "$MODE" "$RUN_ID" "$APKSIGNER" "$KEYTOOL" "$LOG" <<'PY'
import sys, os, re, json, hashlib, struct, subprocess, zipfile, datetime, itertools
import xml.etree.ElementTree as ET

manifest, decdir, apk, out, mode, run_id, apksigner, keytool, logpath = sys.argv[1:10]
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