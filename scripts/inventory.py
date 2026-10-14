#!/usr/bin/env python3
"""inventory.py — the per-instance register of ONE application (dimension 2 of coverage).

  python3 scripts/inventory.py <base.apk | AndroidManifest.xml | $E/decompiled/apktool> --out $E/inventory/
          [--target-sdk N] [--all] [--perm-dump perms.txt] [--jadx $E/decompiled/jadx] [--endpoints secrets/routes.csv]
          [--force] [--json]

Why: "domain D07 tested" is not "all eight provider authorities tested". Only a per-instance register backs
the sentence a client pays for — "all 47 exported components, 8 authorities and 23 deep-link patterns in
version X were individually tested; here is the result for each." Every row starts tested=false;
scripts/coverage.py --gate p7 and scripts/gate.py p7 stay closed while any row is false.

Writes into --out (ids are stable across re-runs: a row that already exists keeps its id and its
tested/result/notes; rows of the old register that this run did not produce are kept and listed):
  components.csv  C-NNN  every component reachable from outside the app — exported=true, implicitly exported,
                         exported unknown (VERIFY), or a non-exported provider with grantUriPermissions — plus
                         every <permission> this app declares. Providers are ALWAYS listed (an exported=false provider still
                         answers getType()/URI grants: D07/D08); --all adds non-exported activities/services/receivers (D08 redirect targets).
  deeplinks.csv   U-NNN  one row per scheme × authority × path of every VIEW intent-filter. The <data>
                         elements of ONE filter are merged by Android (MASTG-TECH-0172; MASTG-TEST-0028
                         (deprecated; see MASTG-TEST-0393/0394)): `<data scheme=https/><data host=h port=p/>
                         <data pathPattern=/.*/>` is ONE pattern https://h:p/.*, not three rows.
  webviews.csv    W-NNN  header only; --jadx seeds CANDIDATE rows (WebView users, bridge registrations,
                         @JavascriptInterface methods) from the decompiled sources — confirm them in D10.
  endpoints.csv   E-NNN  header only; --endpoints seeds rows from tools/06 routes.csv (method,path,file,line — the
                         authoritative Retrofit routes) or endpoints.txt (bare URLs → method=URL); raw grep lines are tolerated.

What the rows encode (primary sources: MASTG-KNOW-0133 §Access Control, MASTG-KNOW-0017, hacktricks
drozer/exploiting-content-providers.md):
  exported   activity/service/receiver with an intent-filter and no android:exported → exported when
             targetSdk<31; from targetSdk 31 the attribute is mandatory with a filter (the APK does not install
             on API 31+ without it) → exported=unknown, VERIFY the decode. provider without android:exported →
             exported when targetSdk<17, not exported from 17. targetSdk unknown → exported=unknown, never a guess.
  permission component android:permission (provider: readPermission/writePermission override permission for
             their operation), else the <application android:permission> default, else NONE.
  attacker   none → AM-03 · normal → AM-03 (auto-granted, named in am_reason) · dangerous → AM-04 ("needs
  model      permission X") · signature|appop special access → AM-04 · signature / privileged / system /
             internal → AM-08/AM-12 (no third-party app can hold it) · unresolved level → AM-04 + UNVERIFIED.
             Levels come from this manifest's <permission>s, then --perm-dump (the output of
             `adb shell pm list permissions -f`), then a table of platform permissions; the source is named.

Exit codes 0 wrote rows · 1 nothing reachable (write inventory/EMPTY-components.md with the manifest evidence)
           · 2 usage or environment error (no apktool/androguard, binary manifest, unreadable input).
Silence    a check that could not run prints UNVERIFIED: <why>. Rows are CANDIDATES for testing, never findings.
REMINDER   `adb shell am/content` runs as uid 2000 (shell) and establishes discovery only; AM-03 is proved
           from the zero-permission probe app (attacker-app/). Protected broadcasts need root even from adb.
"""
import argparse, csv, itertools, json, os, re, shutil, subprocess, sys, tempfile
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"
COMP_COLS = ["instance_id", "type", "name", "exported", "export_reason", "permission", "protection_level",
             "attacker_model", "am_reason", "actions", "categories", "mime", "extra", "domain",
             "tested", "result", "finding_id", "notes"]
DL_COLS = ["instance_id", "uri", "scheme", "host", "port", "path", "path_kind", "mime", "component", "browsable",
           "autoVerify", "link_kind", "attacker_model", "assetlinks_checked", "verified_on_device",
           "tested", "result", "finding_id", "notes"]
WV_COLS = ["instance_id", "class", "file_line", "bridge_name", "js_enabled", "file_access", "allowlist_validator",
           "tested", "result", "notes"]
EP_COLS = ["instance_id", "method", "path", "source", "auth_required", "tested_idor", "tested_massassign",
           "result", "notes"]
CARRY = {  # the columns a tester writes; a re-run must never reset them
    "components.csv": ["tested", "result", "finding_id", "notes"],
    "deeplinks.csv": ["assetlinks_checked", "verified_on_device", "tested", "result", "finding_id", "notes"],
    "webviews.csv": ["js_enabled", "file_access", "allowlist_validator", "tested", "result", "notes"],
    "endpoints.csv": ["auth_required", "tested_idor", "tested_massassign", "result", "notes"],
}
DOMAIN = {"activity": "D04", "activity-alias": "D04", "service": "D06", "receiver": "D05", "provider": "D07",
          "permission": "D03", "permission-tree": "D03"}
PATH_KINDS = ("path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix")
SSP_KINDS = ("ssp", "sspPrefix", "sspPattern", "sspAdvancedPattern")

# ── platform permission knowledge ────────────────────────────────────────────
# Protection levels of platform permissions that commonly guard app components. The dangerous set is the
# runtime-permission list (Android 12–15); special = signature|appop "special app access" the user grants in
# Settings; the signature rows include the ones MASTG-KNOW-0017 tabulates. Anything absent is UNVERIFIED —
# the row says so and --perm-dump resolves it from the device. Never extend this table from memory alone.
_P = "android.permission."
PLATFORM_DANGEROUS = {_P + n for n in """
 READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS READ_CALENDAR WRITE_CALENDAR SEND_SMS RECEIVE_SMS READ_SMS
 RECEIVE_WAP_PUSH RECEIVE_MMS READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE ACCESS_MEDIA_LOCATION READ_MEDIA_IMAGES
 READ_MEDIA_VIDEO READ_MEDIA_AUDIO READ_MEDIA_VISUAL_USER_SELECTED ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION
 ACCESS_BACKGROUND_LOCATION READ_PHONE_STATE READ_PHONE_NUMBERS CALL_PHONE ANSWER_PHONE_CALLS READ_CALL_LOG
 WRITE_CALL_LOG ADD_VOICEMAIL USE_SIP ACCEPT_HANDOVER PROCESS_OUTGOING_CALLS RECORD_AUDIO CAMERA BODY_SENSORS
 BODY_SENSORS_BACKGROUND ACTIVITY_RECOGNITION BLUETOOTH_SCAN BLUETOOTH_ADVERTISE BLUETOOTH_CONNECT
 NEARBY_WIFI_DEVICES UWB_RANGING POST_NOTIFICATIONS""".split()}
PLATFORM_NORMAL = {_P + n for n in """
 INTERNET ACCESS_NETWORK_STATE ACCESS_WIFI_STATE CHANGE_WIFI_STATE CHANGE_NETWORK_STATE CHANGE_WIFI_MULTICAST_STATE
 BLUETOOTH BLUETOOTH_ADMIN NFC VIBRATE WAKE_LOCK RECEIVE_BOOT_COMPLETED FOREGROUND_SERVICE SET_WALLPAPER
 SET_WALLPAPER_HINTS USE_FINGERPRINT USE_BIOMETRIC EXPAND_STATUS_BAR KILL_BACKGROUND_PROCESSES MODIFY_AUDIO_SETTINGS
 READ_SYNC_SETTINGS WRITE_SYNC_SETTINGS READ_SYNC_STATS REQUEST_DELETE_PACKAGES REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
 REORDER_TASKS GET_PACKAGE_SIZE MANAGE_OWN_CALLS TRANSMIT_IR QUERY_ALL_PACKAGES BROADCAST_STICKY
 READ_BASIC_PHONE_STATE HIGH_SAMPLING_RATE_SENSORS CALL_COMPANION_APP UPDATE_PACKAGES_WITHOUT_USER_ACTION""".split()} | {
 "com.android.alarm.permission.SET_ALARM", "com.android.launcher.permission.INSTALL_SHORTCUT"}
PLATFORM_SPECIAL = {_P + n for n in """
 SYSTEM_ALERT_WINDOW WRITE_SETTINGS PACKAGE_USAGE_STATS REQUEST_INSTALL_PACKAGES MANAGE_EXTERNAL_STORAGE
 SCHEDULE_EXACT_ALARM MANAGE_MEDIA""".split()}
PLATFORM_SIGNATURE = {_P + n for n in """
 INSTALL_PACKAGES DELETE_PACKAGES WRITE_SECURE_SETTINGS READ_LOGS DUMP CAPTURE_AUDIO_OUTPUT MANAGE_USERS
 INTERACT_ACROSS_USERS INTERACT_ACROSS_USERS_FULL STATUS_BAR BROADCAST_SMS BROADCAST_WAP_PUSH
 BROADCAST_PACKAGE_REMOVED SEND_RESPOND_VIA_MESSAGE READ_PRIVILEGED_PHONE_STATE MODIFY_PHONE_STATE
 CONNECTIVITY_INTERNAL DEVICE_POWER REBOOT MANAGE_DEVICE_ADMINS GRANT_RUNTIME_PERMISSIONS REVOKE_RUNTIME_PERMISSIONS
 INSTALL_GRANT_RUNTIME_PERMISSIONS ACCESS_NOTIFICATIONS READ_FRAME_BUFFER CAPTURE_VIDEO_OUTPUT
 CAPTURE_SECURE_VIDEO_OUTPUT INJECT_EVENTS MANAGE_APP_OPS_MODES WRITE_APN_SETTINGS MOUNT_UNMOUNT_FILESYSTEMS
 COPY_PROTECTED_DATA MANAGE_CA_CERTIFICATES MANAGE_PROFILE_AND_DEVICE_OWNERS LOCATION_HARDWARE BLUETOOTH_PRIVILEGED
 GET_PASSWORD INTERNAL_SYSTEM_WINDOW MANAGE_ONGOING_CALLS CHANGE_COMPONENT_ENABLED_STATE CLEAR_APP_USER_DATA
 DELETE_CACHE_FILES MASTER_CLEAR SET_TIME SET_TIME_ZONE CONTROL_LOCATION_UPDATES HARDWARE_TEST FACTORY_TEST
 ACCESS_SURFACE_FLINGER PACKAGE_VERIFICATION_AGENT SYSTEM_CAMERA""".split()}
# Permissions declared by other well-known packages (level as declared upstream; the device is the authority).
THIRD_PARTY = {"com.google.android.c2dm.permission.SEND": "signature"}
# Protected broadcasts (frameworks/base core/res AndroidManifest.xml <protected-broadcast>): only system uids may
# send these actions; a third-party app AND `adb shell` on a user build get SecurityException (adb root can).
PROTECTED_ACTIONS = {"android.intent.action." + n for n in """
 BOOT_COMPLETED LOCKED_BOOT_COMPLETED USER_UNLOCKED PACKAGE_ADDED PACKAGE_REMOVED PACKAGE_REPLACED
 PACKAGE_FULLY_REMOVED PACKAGE_CHANGED PACKAGE_RESTARTED PACKAGE_DATA_CLEARED PACKAGE_FIRST_LAUNCH
 MY_PACKAGE_REPLACED MY_PACKAGE_SUSPENDED MY_PACKAGE_UNSUSPENDED USER_PRESENT SCREEN_ON SCREEN_OFF BATTERY_CHANGED
 BATTERY_LOW BATTERY_OKAY ACTION_POWER_CONNECTED ACTION_POWER_DISCONNECTED ACTION_SHUTDOWN TIME_SET
 TIMEZONE_CHANGED LOCALE_CHANGED AIRPLANE_MODE CONFIGURATION_CHANGED DEVICE_STORAGE_LOW DEVICE_STORAGE_OK
 NEW_OUTGOING_CALL PHONE_STATE MEDIA_MOUNTED MEDIA_UNMOUNTED MEDIA_EJECT HEADSET_PLUG DREAMING_STARTED
 DREAMING_STOPPED REBOOT""".split()} | {
 "android.net.conn.CONNECTIVITY_CHANGE", "android.net.wifi.STATE_CHANGE", "android.net.wifi.WIFI_STATE_CHANGED",
 "android.provider.Telephony.SMS_RECEIVED", "android.provider.Telephony.SMS_DELIVER",
 "android.provider.Telephony.WAP_PUSH_RECEIVED", "android.bluetooth.adapter.action.STATE_CHANGED",
 "android.app.action.DEVICE_ADMIN_ENABLED", "android.hardware.usb.action.USB_STATE"}
BASE_NAMES = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"}
FLAG_NAMES = {0x10: "privileged", 0x20: "development", 0x40: "appop", 0x80: "pre23", 0x100: "installer",
              0x200: "verifier", 0x400: "preinstalled", 0x800: "setup", 0x1000: "instant", 0x2000: "runtime",
              0x4000: "oem", 0x8000: "vendorPrivileged"}
AM_RANK = {"AM-03": 0, "AM-04": 1, "AM-08/AM-12": 2, "AM-12": 2}


def die(code, msg):
    print("!! " + msg, file=sys.stderr); sys.exit(code)


# ── input: APK / text manifest / apktool dir / binary AXML ───────────────────
def androguard_apk(path):
    try:
        from androguard.core.apk import APK            # androguard ≥ 4
    except Exception:
        try:
            from androguard.core.bytecodes.apk import APK  # androguard 3.x
        except Exception:
            return None
    try:
        apk = APK(path)
        xml = apk.get_android_manifest_axml().get_xml()
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", "replace")
        return xml, apk.get_target_sdk_version(), apk.get_min_sdk_version()
    except Exception:
        return None


def androguard_axml(path):
    try:
        from androguard.core.axml import AXMLPrinter
    except Exception:
        try:
            from androguard.core.bytecodes.axml import AXMLPrinter
        except Exception:
            return None
    try:
        xml = AXMLPrinter(open(path, "rb").read()).get_xml()
        return xml.decode("utf-8", "replace") if isinstance(xml, bytes) else xml
    except Exception:
        return None


def obtain_manifest(target):
    """→ {manifest|xml_text, yml_dir, apk, tmp, how, sdk}"""
    if os.path.isdir(target):
        m = os.path.join(target, "AndroidManifest.xml")
        if not os.path.exists(m):
            die(2, f"{target}/AndroidManifest.xml not found (expected an apktool output directory, e.g. $E/decompiled/apktool)")
        return {"manifest": m, "yml_dir": target, "apk": None, "tmp": None, "how": "apktool directory", "sdk": None}
    if not os.path.isfile(target):
        die(2, f"{target} not found")
    with open(target, "rb") as f:
        head = f.read(4)
    if head[:2] == b"PK":                                   # zip container → APK
        if shutil.which("apktool"):
            tmp = tempfile.mkdtemp(prefix="inv_")
            r = subprocess.run(["apktool", "d", "-q", "-f", "-s", target, "-o", os.path.join(tmp, "apk")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                shutil.rmtree(tmp, True); die(2, "apktool failed: " + (r.stderr or r.stdout)[:300])
            return {"manifest": os.path.join(tmp, "apk", "AndroidManifest.xml"), "yml_dir": os.path.join(tmp, "apk"),
                    "apk": target, "tmp": tmp, "how": "apktool d -s", "sdk": None}
        ag = androguard_apk(target)
        if ag:
            return {"xml_text": ag[0], "yml_dir": None, "apk": target, "tmp": None, "how": "androguard", "sdk": (ag[1], ag[2])}
        die(2, "an APK needs apktool on PATH (scripts/doctor.sh) or `pip install androguard`; neither is available")
    if head == b"\x03\x00\x08\x00":                          # binary AXML (ResChunk RES_XML_TYPE)
        xml = androguard_axml(target)
        if xml:
            return {"xml_text": xml, "yml_dir": os.path.dirname(os.path.abspath(target)), "apk": None, "tmp": None,
                    "how": "androguard AXML", "sdk": None}
        die(2, f"{target} is a binary AndroidManifest.xml (AXML). Pass the .apk, the apktool output directory, "
               "or `pip install androguard` to decode it in place")
    return {"manifest": target, "yml_dir": os.path.dirname(os.path.abspath(target)), "apk": None, "tmp": None,
            "how": "text manifest", "sdk": None}


def resolve_sdk(root, info, override, out_dir):
    """(targetSdk, source, minSdk) — every source is named; None means UNVERIFIED, never a guess."""
    def num(v):
        try:
            return int(str(v).strip().strip("'\""))
        except Exception:
            return None
    msdk = None
    us = root.find("uses-sdk")
    if us is not None:
        msdk = num(us.get(A + "minSdkVersion"))
    yml = os.path.join(info.get("yml_dir") or "", "apktool.yml")
    ytxt = ""
    if info.get("yml_dir") and os.path.exists(yml):
        ytxt = open(yml, encoding="utf-8", errors="replace").read()
        m = re.search(r"minSdkVersion:\s*['\"]?(\d+)", ytxt)
        if m and msdk is None:
            msdk = int(m.group(1))
    if override is not None:
        return override, "--target-sdk", msdk
    if us is not None and num(us.get(A + "targetSdkVersion")) is not None:
        return num(us.get(A + "targetSdkVersion")), "<uses-sdk> in the manifest", msdk
    m = re.search(r"targetSdkVersion:\s*['\"]?(\d+)", ytxt)         # apktool moves <uses-sdk> into apktool.yml
    if m:
        return int(m.group(1)), "apktool.yml sdkInfo", msdk
    if info.get("sdk") and info["sdk"][0] is not None:
        t = num(info["sdk"][0])
        if t is not None:
            return t, "androguard", msdk if msdk is not None else num(info["sdk"][1])
    if info.get("apk") and shutil.which("aapt2"):
        r = subprocess.run(["aapt2", "dump", "badging", info["apk"]], capture_output=True, text=True)
        m = re.search(r"targetSdkVersion:'(\d+)'", r.stdout or "")
        if m:
            return int(m.group(1)), "aapt2 dump badging", msdk
    ej = os.path.join(os.path.dirname(os.path.abspath(out_dir)), "engagement.json")
    if os.path.exists(ej):
        try:
            t = num((json.load(open(ej, encoding="utf-8")).get("target") or {}).get("targetSdk"))
            if t is not None:
                return t, "engagement.json target.targetSdk", msdk
        except Exception:
            pass
    return None, "unknown", msdk


# ── permissions → protection level → attacker model ──────────────────────────
def norm_level(raw):
    """'signature|privileged' or '0x12' → (base, flags, canonical)."""
    s = (raw or "").strip()
    if not s:
        return "normal", [], "normal"                      # <permission> default when the attribute is absent
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", s) or s.isdigit():
        v = int(s, 16) if s.lower().startswith("0x") else int(s)
        base = BASE_NAMES.get(v & 0xF, f"base{v & 0xF}")
        flags = [n for b, n in FLAG_NAMES.items() if v & b]
        rest = v & ~0xF & ~sum(FLAG_NAMES)
        if rest:
            flags.append(f"flag:0x{rest:x}")
        return base, flags, "|".join([base] + flags)
    parts = [p.strip() for p in s.split("|") if p.strip()]
    base = next((p for p in parts if p in ("normal", "dangerous", "signature", "signatureOrSystem", "internal")), None)
    return base or "unknown", [p for p in parts if p != base], "|".join(parts)


def parse_perm_dump(path):
    """`adb shell pm list permissions -f` → {name: protectionLevel}"""
    out, cur = {}, None
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^\+?\s*permission:(\S+)", line)
        if m:
            cur = m.group(1); continue
        m = re.match(r"^\s*protectionLevel:(\S+)", line)
        if m and cur:
            out[cur] = m.group(1)
    return out


def resolve_level(perm, declared, dump):
    """→ (base, flags, canonical, source)"""
    if perm in declared:
        return (*norm_level(declared[perm]), "declared in this manifest")
    if perm in dump:
        return (*norm_level(dump[perm]), "--perm-dump")
    if perm in PLATFORM_DANGEROUS:
        return "dangerous", [], "dangerous", "platform table"
    if perm in PLATFORM_SPECIAL:
        return "signature", ["appop"], "signature|appop", "platform table"
    if perm in PLATFORM_NORMAL or perm.startswith(_P + "FOREGROUND_SERVICE_"):
        return "normal", [], "normal", "platform table"
    if perm in PLATFORM_SIGNATURE or perm.startswith(_P + "BIND_"):
        return "signature", [], "signature", "platform table"
    if perm in THIRD_PARTY:
        return (*norm_level(THIRD_PARTY[perm]), "declared by another package (well-known)")
    return "unknown", [], "unknown", "unresolved"


def attacker_for(perm, declared, dump, unverified):
    """One permission → (AM, reason, canonical level)."""
    if not perm:
        return "AM-03", "no permission required", "none"
    base, flags, level, src = resolve_level(perm, declared, dump)
    if base == "normal":
        return "AM-03", f"needs permission {perm} (normal, {src}): granted at install without user interaction — name it in the precondition", level
    if base == "dangerous":
        return "AM-04", f"needs permission {perm} (dangerous, {src}): user-granted at runtime", level
    if base in ("signature", "signatureOrSystem", "internal"):
        if "appop" in flags and perm.startswith(_P):       # only platform permissions have a Settings toggle
            return "AM-04", f"needs special app access {perm} ({level}, {src}): the user grants it in Settings", level
        if "development" in flags:
            return "AM-12", f"{perm} is {level} ({src}): grantable only by pm grant from shell/root — own device, not an attack", level
        if perm.startswith(_P + "BIND_"):
            return "AM-08/AM-12", f"{perm} is held by the system only: the OS binds this component, no app reaches it directly — test the data the callback receives instead", level
        extra = "; the reachable path is the push payload (AM-01/AM-09: D18 cloud-SDK items + D05 receiver items; a D24 chapter does not exist yet), not direct IPC" if perm == "com.google.android.c2dm.permission.SEND" else ""
        return "AM-08/AM-12", f"{perm} is {level} ({src}): no third-party app can hold it; only in-process code (AM-08) or the tester's own device (AM-12){extra}", level
    unverified.append(f"protectionLevel of {perm} unresolved — run `adb shell pm list permissions -f > perms.txt` and re-run with --perm-dump perms.txt")
    return "AM-04", f"UNVERIFIED: protectionLevel of {perm} unknown (not declared here, not in the platform table) — assume AM-04 until --perm-dump resolves it; if it is signature-level no third-party app reaches this component", "unknown"


def weakest(models):
    """[(AM, reason, level, op)] → the weakest attacker that still works, with the reasons joined."""
    models = sorted(models, key=lambda m: AM_RANK.get(m[0], 1))
    am = models[0][0]
    reasons = []
    for m in models:
        tag = f"{m[3]}: " if m[3] else ""
        reasons.append(tag + m[1])
    return am, " | ".join(dict.fromkeys(reasons))


# ── manifest → rows ──────────────────────────────────────────────────────────
def fqn(name, pkg):
    if not name or name == "?":
        return "?"
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return f"{pkg}.{name}"
    return name


def export_state(tag, el, tsdk):
    """→ (exported: true|false|unknown, reason). Sources: MASTG-KNOW-0133 Access Control; hacktricks providers."""
    exp = (el.get(A + "exported") or "").strip().lower()
    has_filter = el.find("intent-filter") is not None
    if exp == "true":
        return "true", "explicit android:exported=true"
    if exp == "false":
        return "false", "explicit android:exported=false"
    if tag == "provider":
        if tsdk is None:
            return "unknown", "android:exported unset; providers default to exported for targetSdk<17 only — targetSdk unknown, VERIFY (pass --target-sdk)"
        if tsdk < 17:
            return "true", f"IMPLICIT: android:exported unset and targetSdk {tsdk} < 17 → provider exported by default"
        return "false", f"default: android:exported unset and targetSdk {tsdk} ≥ 17 → provider not exported"
    if not has_filter:
        return "false", "default: no intent-filter and android:exported unset → not exported"
    if tsdk is None:
        return "unknown", "intent-filter with android:exported unset; exported by default only for targetSdk<31 — targetSdk unknown, VERIFY (pass --target-sdk)"
    if tsdk < 31:
        return "true", f"IMPLICIT: intent-filter with android:exported unset and targetSdk {tsdk} < 31 → exported by default"
    return "unknown", (f"intent-filter with android:exported unset but targetSdk {tsdk} ≥ 31: such an APK does not install on API 31+ "
                       "— the decode probably lost the attribute; VERIFY with `aapt2 dump xmltree base.apk --file AndroidManifest.xml`")


def filter_summary(el):
    acts, cats, mimes, prio = [], [], [], []
    for f in el.findall("intent-filter"):
        for x in f.findall("action"):
            v = x.get(A + "name", "")
            if v and v not in acts: acts.append(v)
        for x in f.findall("category"):
            v = x.get(A + "name", "")
            if v and v not in cats: cats.append(v)
        for d in f.findall("data"):
            v = d.get(A + "mimeType")
            if v and v not in mimes: mimes.append(v)
        p = f.get(A + "priority")
        if p is not None: prio.append(p)
    return acts, cats, mimes, prio


def component_extra(tag, el, pkg):
    x = []
    if (el.get(A + "enabled") or "").lower() == "false":
        x.append("enabled=false (disabled until the app enables it)")
    for k in ("process", "directBootAware", "singleUser"):
        v = el.get(A + k)
        if v is not None: x.append(f"{k}={v}")
    if tag in ("activity", "activity-alias"):
        for k in ("launchMode", "taskAffinity", "allowTaskReparenting", "excludeFromRecents", "autoRemoveFromRecents"):
            v = el.get(A + k)
            if v is not None: x.append(f"{k}={v!r}" if k == "taskAffinity" else f"{k}={v}")
        if tag == "activity-alias":
            x.append(f"targetActivity={fqn(el.get(A + 'targetActivity', '?'), pkg)} (the alias's own exported/permission apply)")
    if tag == "service":
        for k in ("foregroundServiceType", "isolatedProcess", "externalService"):
            v = el.get(A + k)
            if v is not None: x.append(f"{k}={v}")
    if tag == "provider":
        a = el.get(A + "authorities")
        if a: x.append("authorities=" + a)
        if (el.get(A + "grantUriPermissions") or "").lower() == "true":
            x.append("grantUriPermissions=true")
        for g in el.findall("grant-uri-permission"):
            for k in PATH_KINDS:
                v = g.get(A + k)
                if v is not None: x.append(f"grant-uri-permission {k}={v}")
        for p in el.findall("path-permission"):
            spec = ",".join(f"{k}={p.get(A + k)}" for k in PATH_KINDS if p.get(A + k) is not None) or "(no path)"
            perms = ",".join(f"{k}={p.get(A + k)}" for k in ("permission", "readPermission", "writePermission") if p.get(A + k))
            x.append(f"path-permission {spec} {perms}".strip())
        for md in el.findall("meta-data"):
            if md.get(A + "name") == "android.support.FILE_PROVIDER_PATHS":
                x.append(f"FileProvider paths={md.get(A + 'resource', '?')} (check res/xml for <root-path>/<external-path>)")
        rp, wp, p = el.get(A + "readPermission"), el.get(A + "writePermission"), el.get(A + "permission")
        if rp and not wp and not p: x.append("WRITE UNPROTECTED (readPermission only: insert/update/delete fall back to NONE)")
        if wp and not rp and not p: x.append("READ UNPROTECTED (writePermission only: query falls back to NONE)")
    return x


def build(root, app, pkg, tsdk, declared, dump, include_all):
    comp_rows, dl_rows, unverified = [], [], []
    app_perm = app.get(A + "permission")
    if app_perm:
        unverified.append(f"<application android:permission=\"{app_perm}\"> is the default for every component without its own permission")

    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.iter(tag):
            name = fqn(el.get(A + "name", "?"), pkg)
            exported, reason = export_state(tag, el, tsdk)
            grant = (el.get(A + "grantUriPermissions") or "").lower() == "true"
            if exported == "false" and tag == "provider" and grant:
                reason += "; reachable through a URI grant this app hands out (FLAG_GRANT_*_URI_PERMISSION / <grant-uri-permission>) — D07/D08 confused-deputy target"
            elif exported == "false" and tag != "provider" and not include_all:
                continue      # providers are always listed: getType()/grant paths reach non-exported ones (D07/D08)
            if exported == "unknown":
                unverified.append(f"{tag} {name}: exported unknown — {reason}")

            # effective permission: component > application default; providers split read/write
            if tag == "provider":
                p = el.get(A + "permission")
                read = el.get(A + "readPermission") or p or app_perm
                write = el.get(A + "writePermission") or p or app_perm
                models = []
                for op, perm in (("read", read), ("write", write)):
                    am, why, lvl = attacker_for(perm, declared, dump, unverified)
                    models.append((am, why, lvl, op if read != write else ""))
                perm_col = (read or "NONE") if read == write else f"read={read or 'NONE'};write={write or 'NONE'}"
                level_col = models[0][2] if read == write else f"read={models[0][2]};write={models[1][2]}"
            else:
                perm = el.get(A + "permission") or app_perm
                am, why, lvl = attacker_for(perm, declared, dump, unverified)
                models = [(am, why, lvl, "")]
                perm_col, level_col = perm or "NONE", lvl
            am, am_reason = weakest(models)
            if exported == "false":
                am_reason = "not exported: " + am_reason + " — only via a redirect/grant primitive, not directly"
            acts, cats, mimes, prio = filter_summary(el)
            extra = component_extra(tag, el, pkg)
            if prio:
                extra.append("filter priority=" + ",".join(prio))
            prot = [a for a in acts if a in PROTECTED_ACTIONS]
            if prot and tag == "receiver":
                extra.append("protected-broadcast action(s) " + ",".join(prot) +
                             " (system-only sender; a third-party app and adb shell on a user build get SecurityException — "
                             "test the receiver with an explicit intent carrying an unlisted action)")
            comp_rows.append(dict(instance_id="", type=tag, name=name, exported=exported, export_reason=reason,
                                  permission=perm_col, protection_level=level_col, attacker_model=am, am_reason=am_reason,
                                  actions=" ".join(acts), categories=" ".join(cats), mime=" ".join(mimes),
                                  extra=" | ".join(extra), domain=DOMAIN[tag], tested="false", result="", finding_id="", notes=""))

            if exported == "false":
                continue
            for f in el.findall("intent-filter"):
                if "android.intent.action.VIEW" not in [x.get(A + "name") for x in f.findall("action")]:
                    continue
                dl_rows.extend(deeplinks_of(f, name, exported, unverified))
    for p in ("permission", "permission-tree"):
        for el in root.iter(p):
            pname = el.get(A + "name", "?")
            if p == "permission-tree":
                comp_rows.append(dict(instance_id="", type=p, name=pname, exported="n/a", export_reason="declared by this app",
                                      permission="", protection_level="n/a (tree: names added under it at runtime inherit the owner)",
                                      attacker_model="n/a", am_reason="permission tree, not a permission", actions="", categories="",
                                      mime="", extra="", domain="D03", tested="false", result="", finding_id="", notes=""))
                continue
            raw = el.get(A + "protectionLevel")
            base, flags, level, _ = resolve_level(pname, declared, {})
            if base == "normal":
                am, why = "AM-03", "any app can declare and hold it at install time — custom-permission squatting / pre-definition (D03)"
            elif base == "dangerous":
                am, why = "AM-04", "any app can request it; the user grants it at runtime"
            elif base in ("signature", "signatureOrSystem", "internal"):
                am, why = "AM-08/AM-12", "only apps signed with this app's certificate can hold it"
            else:
                am, why = "AM-04", f"UNVERIFIED: protectionLevel '{raw}' not understood"
            comp_rows.append(dict(instance_id="", type=p, name=pname, exported="n/a", export_reason="declared by this app",
                                  permission="", protection_level=level + ("" if raw else " (DEFAULT — attribute absent)"),
                                  attacker_model=am, am_reason=why, actions="", categories="", mime="",
                                  extra=("permissionGroup=" + el.get(A + "permissionGroup")) if el.get(A + "permissionGroup") else "",
                                  domain="D03", tested="false", result="", finding_id="", notes=""))
    return comp_rows, dl_rows, unverified


def deeplinks_of(f, component, exported, unverified):
    """All <data> attributes of ONE intent-filter merge: schemes × authorities × paths (MASTG-TECH-0172)."""
    schemes, auths, paths, ssps, mimes = [], [], [], [], []
    for d in f.findall("data"):
        s = d.get(A + "scheme")
        if s and s not in schemes: schemes.append(s)
        h, p = d.get(A + "host"), d.get(A + "port")
        if h and (h, p) not in auths: auths.append((h, p))
        elif p and not h:
            unverified.append(f"{component}: <data android:port=\"{p}\"> without a host in the same element is ignored by Android")
        for k in PATH_KINDS:
            v = d.get(A + k)
            if v is not None and (k, v) not in paths: paths.append((k, v))
        for k in SSP_KINDS:
            v = d.get(A + k)
            if v is not None and (k, v) not in ssps: ssps.append((k, v))
        m = d.get(A + "mimeType")
        if m and m not in mimes: mimes.append(m)
    implicit = False
    if not schemes:
        if not mimes:
            return []                         # VIEW with no data constraints: not a URI handler
        schemes, implicit = ["content", "file"], True   # a filter with only mimeType matches content: and file:
    if paths and not auths:
        unverified.append(f"{component}: path attributes without any host are ignored by Android (a path needs an authority); emitted as scheme://*")
        paths = []
    cats = [c.get(A + "name") for c in f.findall("category")]
    browsable = "android.intent.category.BROWSABLE" in cats
    av = (f.get(A + "autoVerify") or "").lower() == "true"
    rows = []
    mime = " ".join(mimes)
    for sch, (host, port), (kind, val) in itertools.product(schemes, auths or [(None, None)], paths or [(None, None)]):
        uri = f"{sch}://{host or '*'}{(':' + port) if port else ''}{val if kind else ''}"
        rows.append(_dl_row(uri, sch, host, port, val, kind, mime, component, browsable, av, exported, implicit))
    for sch in ([s for s in schemes] if ssps else []):
        for kind, val in ssps:
            rows.append(_dl_row(f"{sch}:{val}", sch, None, None, val, kind, mime, component, browsable, av, exported, implicit))
    return rows


def _dl_row(uri, sch, host, port, val, kind, mime, component, browsable, av, exported, implicit):
    if sch in ("http", "https"):
        link = "applink-candidate (autoVerify; confirm with tools/04 and `pm get-app-links`)" if av else \
               "web-unverified (http/https without autoVerify: any app can claim it — MASTG-TEST-0393)"
    elif sch in ("content", "file"):
        link = "content/file" + (" (implicit: filter has mimeType but no scheme)" if implicit else "")
    else:
        link = "custom-scheme (any app can register it; handler input is untrusted — MASTG-TEST-0394)"
    am = "AM-02" if browsable else "AM-03"
    note = "" if exported == "true" else "VERIFY: component exported=unknown — the link is live only if the component is exported"
    return dict(instance_id="", uri=uri, scheme=sch, host=host or "", port=port or "", path=val or "", path_kind=kind or "",
                mime=mime, component=component, browsable=str(browsable).lower(), autoVerify=str(av).lower(), link_kind=link,
                attacker_model=am, assetlinks_checked="false", verified_on_device="", tested="false", result="",
                finding_id="", notes=note)


# ── seeding webviews.csv / endpoints.csv ─────────────────────────────────────
WV_CALLS = re.compile(r"\b(loadUrl|loadData|loadDataWithBaseURL|setJavaScriptEnabled|addJavascriptInterface|"
                      r"addWebMessageListener|evaluateJavascript|postWebMessage)\s*\(")


def seed_webviews(src_dir):
    rows = []
    for dp, _, fns in os.walk(src_dir):
        for fn in sorted(fns):
            if not fn.endswith((".java", ".kt")):
                continue
            p = os.path.join(dp, fn)
            try:
                t = open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if "WebView" not in t and "@JavascriptInterface" not in t:
                continue
            rel = os.path.relpath(p, src_dir)
            cls = re.sub(r"\.(java|kt)$", "", rel).replace(os.sep, ".")
            cls = re.sub(r"^sources\.", "", cls)
            lines = t.split("\n")
            first = next((i + 1 for i, l in enumerate(lines) if WV_CALLS.search(l)), None)
            js = "true" if re.search(r"setJavaScriptEnabled\(\s*true", t) else ("false" if re.search(r"setJavaScriptEnabled\(\s*false", t) else "")
            fa = ",".join(n for n in ("setAllowFileAccess", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs",
                                      "setAllowContentAccess") if re.search(n + r"\(\s*true", t))
            if first is not None:
                rows.append(dict(instance_id="", **{"class": cls}, file_line=f"{rel}:{first}", bridge_name="", js_enabled=js, file_access=fa,
                                 allowlist_validator="", tested="false", result="",
                                 notes="CANDIDATE from jadx grep: confirm the WebView exists at runtime (D10)"))
                for m in re.finditer(r'addJavascriptInterface\s*\(\s*[^,]+,\s*"([^"]+)"', t):
                    rows.append(dict(instance_id="", **{"class": cls}, file_line=f"{rel}:{t.count(chr(10), 0, m.start()) + 1}",
                                     bridge_name=m.group(1), js_enabled=js, file_access=fa, allowlist_validator="", tested="false",
                                     result="", notes="CANDIDATE: bridge object registered here under this JS name; its @JavascriptInterface methods are separate rows"))
            for m in re.finditer(r"@JavascriptInterface\b", t):
                mm = re.search(r"\b(?:fun|[\w<>\[\], ]+?)\s+(\w+)\s*\(", t[m.end(): m.end() + 400])
                rows.append(dict(instance_id="", **{"class": cls}, file_line=f"{rel}:{t.count(chr(10), 0, m.start()) + 1}",
                                 bridge_name=(mm.group(1) if mm else "?") + "()", js_enabled="", file_access="", allowlist_validator="",
                                 tested="false", result="", notes="CANDIDATE: @JavascriptInterface method — callable from any page the WebView loads once the bridge is registered"))
    return rows


def seed_endpoints(path):
    rows, skipped = [], 0
    deny = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org/licenses", "opensource.org/licenses", "creativecommons.org")
    src = os.path.basename(path)
    lines = [l.rstrip("\n") for l in open(path, encoding="utf-8", errors="replace")]
    pairs = []
    if lines and re.match(r"^method,path(,|$)", lines[0].strip(), re.I):          # tools/06 routes.csv (authoritative)
        for r in csv.DictReader(lines):
            if (r.get("path") or "").strip():
                pairs.append(((r.get("method") or "?").strip().upper(), r["path"].strip()))
    else:
        for s in (l.strip() for l in lines):
            if not s:
                continue
            s = re.sub(r"^[^\s:]+:\d+:", "", s).strip()                              # grep -rn provenance prefix file:line:
            m = re.search(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]*)"', s)
            if m:
                pairs.append((m.group(1), m.group(2)))
            elif re.match(r"https?://", s):
                if any(d in s for d in deny):
                    skipped += 1; continue
                pairs.append(("URL", s))                                            # same vocabulary as tools/06 --inventory
            else:
                pairs.append(("?", s))
    for method, route in pairs:
        rows.append(dict(instance_id="", method=method, path=route, source=src, auth_required="", tested_idor="false",
                         tested_massassign="false", result="", notes=f"CANDIDATE from {src}: confirm the route is live, then IDOR and mass-assignment (D15)"))
    return rows, skipped


# ── registers: stable ids, carried status, nothing deleted ──────────────────
def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        return rd.fieldnames or [], list(rd)


def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, lineterminator="\n", extrasaction="ignore")
        w.writeheader(); w.writerows(rows)


def carry(path, cols, rows, key, prefix, force, unverified):
    """Reuse ids and tester columns of the existing register; keep its rows this run did not produce."""
    old_by, max_id, kept, extra = {}, 0, 0, []
    if os.path.exists(path) and not force:
        try:
            _, orows = read_csv(path)
        except Exception as ex:
            unverified.append(f"existing {os.path.basename(path)} unreadable ({ex}) — rewritten with fresh ids"); orows = []
        for r in orows:
            old_by.setdefault(key(r), r)
            m = re.fullmatch(prefix + r"-(\d+)", (r.get("instance_id") or "").strip())
            if m:
                max_id = max(max_id, int(m.group(1)))
    name = os.path.basename(path)
    for r in rows:
        o = old_by.pop(key(r), None)
        if o is not None and re.fullmatch(prefix + r"-\d+", (o.get("instance_id") or "").strip()):
            r["instance_id"] = o["instance_id"].strip()
            for c in CARRY[name]:
                if (o.get(c) or "").strip():
                    r[c] = o[c]
            kept += 1
        else:
            max_id += 1; r["instance_id"] = f"{prefix}-{max_id:03d}"
    for o in old_by.values():                 # never delete a row a tester may have written
        row = {c: (o.get(c) or "") for c in cols}
        if not re.fullmatch(prefix + r"-\d+", row["instance_id"].strip()):
            max_id += 1; row["instance_id"] = f"{prefix}-{max_id:03d}"
        extra.append(row)
    return rows + extra, kept, extra


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="inventory.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="base.apk, a text AndroidManifest.xml, or an apktool output directory ($E/decompiled/apktool)")
    ap.add_argument("--out", default="inventory", metavar="DIR", help="register directory (default ./inventory; use $E/inventory)")
    ap.add_argument("--target-sdk", type=int, metavar="N", help="override/supply targetSdkVersion when no source carries it")
    ap.add_argument("--all", action="store_true", help="also list non-exported activities/services/receivers (intent-redirection targets, D08); providers are always listed")
    ap.add_argument("--perm-dump", metavar="FILE", help="output of `adb shell pm list permissions -f`: resolves protection levels from the device")
    ap.add_argument("--jadx", metavar="DIR", help="jadx output (or its sources/): seed webviews.csv with WebView / bridge candidates")
    ap.add_argument("--endpoints", metavar="FILE", help="tools/06 routes.csv (preferred) or endpoints.txt: seed endpoints.csv")
    ap.add_argument("--force", action="store_true", help="ignore existing registers (fresh ids; tester columns are lost)")
    ap.add_argument("--json", action="store_true", help="machine view on stdout (human lines go to stderr)")
    a = ap.parse_args()
    say = (lambda *x: print(*x, file=sys.stderr)) if a.json else print

    info = obtain_manifest(a.target)
    try:
        try:
            root = ET.parse(info["manifest"]).getroot() if info.get("manifest") else ET.fromstring(info["xml_text"])
        except ET.ParseError as ex:
            die(2, f"manifest is not parseable XML ({ex}); if it is binary, pass the .apk or the apktool directory")
        app = root.find("application")
        if app is None:
            die(2, "no <application> element in the manifest")
        pkg = root.get("package") or ""
        tsdk, tsrc, msdk = resolve_sdk(root, info, a.target_sdk, a.out)
        declared = {el.get(A + "name", "?"): (el.get(A + "protectionLevel") or "") for el in root.iter("permission")}
        dump = {}
        if a.perm_dump:
            try:
                dump = parse_perm_dump(a.perm_dump)
            except Exception as ex:
                die(2, f"--perm-dump {a.perm_dump}: {ex}")
        comp_rows, dl_rows, unverified = build(root, app, pkg, tsdk, declared, dump, a.all)
        if tsdk is None:
            unverified.insert(0, "targetSdk unknown — implicit-export defaults not resolved; pass --target-sdk N "
                                 "(aapt2 dump badging base.apk | grep targetSdk, or apktool.yml sdkInfo)")
    finally:
        if info.get("tmp"):
            shutil.rmtree(info["tmp"], True)

    os.makedirs(a.out, exist_ok=True)
    files = {}
    comp_rows, kept, extra = carry(os.path.join(a.out, "components.csv"), COMP_COLS, comp_rows,
                                   lambda r: (r.get("type") or "", r.get("name") or ""), "C", a.force, unverified)
    write_csv(os.path.join(a.out, "components.csv"), COMP_COLS, comp_rows)
    files["components.csv"] = {"rows": len(comp_rows), "kept": kept, "added": len(comp_rows) - kept - len(extra),
                               "not_in_this_manifest": [r["instance_id"] + " " + r.get("name", "") for r in extra]}
    dl_rows, kept, extra = carry(os.path.join(a.out, "deeplinks.csv"), DL_COLS, dl_rows,
                                 lambda r: (r.get("component") or "", r.get("uri") or ""), "U", a.force, unverified)
    write_csv(os.path.join(a.out, "deeplinks.csv"), DL_COLS, dl_rows)
    files["deeplinks.csv"] = {"rows": len(dl_rows), "kept": kept, "added": len(dl_rows) - kept - len(extra),
                              "not_in_this_manifest": [r["instance_id"] + " " + r.get("uri", "") for r in extra]}

    for name, cols, seeder, key, prefix in (
            ("webviews.csv", WV_COLS, (lambda: (seed_webviews(a.jadx), 0)) if a.jadx else None,
             lambda r: (r.get("class") or "", r.get("bridge_name") or ""), "W"),
            ("endpoints.csv", EP_COLS, (lambda: seed_endpoints(a.endpoints)) if a.endpoints else None,
             lambda r: ((r.get("method") or "").upper(), r.get("path") or ""), "E")):
        p = os.path.join(a.out, name)
        if seeder:
            try:
                rows, skipped = seeder()
            except Exception as ex:
                die(2, f"seeding {name}: {ex}")
            rows, kept, extra = carry(p, cols, rows, key, prefix, a.force, unverified)
            write_csv(p, cols, rows)
            files[name] = {"rows": len(rows), "kept": kept, "added": len(rows) - kept - len(extra), "existing_kept": len(extra), "skipped_noise": skipped}
        elif not os.path.exists(p):
            write_csv(p, cols, [])
            files[name] = {"rows": 0, "kept": 0, "added": 0, "note": f"header only — fill by hand ({prefix}-NNN ids) or seed with " + ("--jadx" if prefix == "W" else "--endpoints")}
        else:
            try:
                files[name] = {"rows": len(read_csv(p)[1]), "note": "left untouched"}
            except Exception as ex:
                files[name] = {"rows": 0, "note": f"UNVERIFIED: unreadable ({ex})"}

    reachable = [r for r in comp_rows if r.get("type") not in ("permission", "permission-tree")]
    rc = 0 if (reachable or dl_rows) else 1
    say(f"package {pkg or '?'} · targetSdk {tsdk if tsdk is not None else 'UNKNOWN'} ({tsrc}) · minSdk {msdk if msdk is not None else '?'} · input: {info['how']}")
    for name in ("components.csv", "deeplinks.csv", "webviews.csv", "endpoints.csv"):
        fi = files[name]
        line = f"  {name:<15} {fi['rows']:>4} rows -> {os.path.join(a.out, name)}"
        if fi.get("added") is not None and (fi.get("kept") or fi.get("not_in_this_manifest") or fi.get("existing_kept")):
            line += f"   (kept {fi.get('kept', 0)} existing · added {fi.get('added', 0)}" + \
                    (f" · {len(fi['not_in_this_manifest'])} old rows NOT in this manifest kept" if fi.get("not_in_this_manifest") else "") + ")"
        if fi.get("note"):
            line += f"   {fi['note']}"
        say(line)
    for name in ("components.csv", "deeplinks.csv"):
        for x in files[name].get("not_in_this_manifest", []):
            say(f"    kept but not produced by this manifest (settle as n/a 'removed in this version' or delete by hand): {x}")
    counts = {}
    for r in reachable:
        counts[r["type"]] = counts.get(r["type"], 0) + 1
    say("  reachable: " + (" · ".join(f"{k} {v}" for k, v in counts.items()) or "NONE") +
        f" · deep-link patterns {len(dl_rows)} · exported=unknown {sum(1 for r in reachable if r['exported'] == 'unknown')}")
    for u in dict.fromkeys(unverified):
        say("  UNVERIFIED: " + u)
    if rc == 1:
        say("  !! no reachable component and no deep link. If that is true, write inventory/EMPTY-components.md with the manifest "
            "evidence (scripts/gate.py p3 accepts it); if the decode is suspect, re-run from the APK.")
    say("\nEVERY ROW STARTS tested=false. coverage.py --gate p7 and gate.py p7 stay closed while any row is false.")
    say("REMINDER: driving these rows with `adb shell am/content` is discovery (uid 2000); AM-03 is proved from the zero-permission probe app.")
    if a.json:
        print(json.dumps({"tool": "inventory.py", "target": a.target, "input": info["how"], "package": pkg,
                          "targetSdk": tsdk, "targetSdk_source": tsrc, "minSdk": msdk, "out": os.path.abspath(a.out),
                          "files": files, "components": comp_rows, "deeplinks": dl_rows,
                          "unverified": list(dict.fromkeys(unverified)), "exit": rc}, ensure_ascii=False, indent=1))
    sys.exit(rc)


if __name__ == "__main__":
    main()
