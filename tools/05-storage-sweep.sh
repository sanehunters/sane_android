#!/usr/bin/env bash
# 05-storage-sweep.sh <pkg> [--user N|all] [--out DIR] [--pull] [--backup] [--manifest FILE]
#                           [--serial S] [--full-values] [--json] [--help]
# Post-login storage sweep: file inventory (path,size,mode,owner,label,sha256), credential-shaped
# CANDIDATE lines, data stores found by EXTENSION, external/shared storage, WebView storage, and the
# backup-set reachability test done for real (bmgr + LocalTransport, MASTG-TECH-0128 / MASTG-TEST-0216).
#
# Why the privilege ladder: `adb root` works only on userdebug/eng/emulator builds. On a Magisk-rooted
# production device adbd answers "adbd cannot run as root in production builds" and every /data/user
# read then silently returns nothing -- a "0 files" false negative. So this script PROVES uid 0 first,
# otherwise wraps every remote command in `su -c`, otherwise falls back to `run-as` (debuggable builds
# only, CE dir of one user), otherwise stops with UNVERIFIED and exit 2. A sweep that could not read is
# never reported as empty.
#
# Quoting: each remote command is built once with single-quoted values ('\'' escaping, rq()) and handed
# to `adb shell` as ONE string; the mode wrapper (su -c / run-as sh -c) quotes it a second time. Verified
# with a local `sh -c` simulator (fake adb/su/run-as) -- no device was attached when this was written.
#
# Root is an EVIDENCE TOOL here, not an attack precondition (docs/05-attacker-models.md). Data on
# internal storage is VRT P5 until a weaker attacker can REACH it; the escalation path is printed at
# the end. adb runs as the shell UID: everything below is DISCOVERY. Re-prove reach from attacker-app/.
#
# stdin: every adb call inside rsh()/rsh_bin() and in the loops gets </dev/null -- `adb shell` drains the
# stdin it inherits, which turns a `find | while read` loop into a one-iteration loop (and blocks when the
# caller's stdin is an open pipe). Secrets: candidates.csv carries MASKED values + sha256 by default;
# --full-values writes the full match (then point --out at $E/sensitive/). --pull trees go to
# $E/sensitive/pulled/<pkg>/ when $E is set (never committed), else DIR/pulled/.
#
# Exit: 0 ran and printed >=1 CANDIDATE (any kind); 1 ran, nothing found; 2 usage/environment, or nothing
#       interpretable (a directory unreadable, zero files listed, backup probe failed) with no candidate.
set -uo pipefail

usage() {
  sed -n '2,4p' "$0" | sed 's/^# //'
  cat <<'EOF'
  --user N|all   sweep /data/user/N (default 0). `all` iterates `pm list users` (work profile, private space)
  --out DIR      evidence dir (default $E/recon/storage, else ./storage-sweep/<pkg>): inventory.csv candidates.csv
                 stores.csv summary.json; the human output is appended to $E/logs/tools-05.txt when $E is set
  --pull         copy the data dirs into DIR/pulled/ (tar stream under su/run-as) and dump sqlite schemas
  --backup       materialise the backup set with bmgr+LocalTransport (root/su only; switches transport, restores it)
  --manifest F   decoded AndroidManifest.xml (apktool) for allowBackup/fullBackupContent/dataExtractionRules
  --serial S     adb -s S (or export ANDROID_SERIAL)
  --full-values  write full credential matches to candidates.csv (default: masked + sha256)
  --json         print summary.json to stdout at the end
EOF
  exit "${1:-2}"
}

PKG=""; USER_SEL="0"; OUT=""; PULL=0; BACKUP=0; MANIFEST=""; SERIAL="${ANDROID_SERIAL:-}"; JSON=0; FULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --user)     USER_SEL="${2:-}"; shift ;;
    --out)      OUT="${2:-}"; shift ;;
    --pull)     PULL=1 ;;
    --backup)   BACKUP=1 ;;
    --manifest) MANIFEST="${2:-}"; shift ;;
    --serial)   SERIAL="${2:-}"; shift ;;
    --json)     JSON=1 ;;
    --full-values) FULL=1 ;;
    -h|--help)  usage 0 ;;
    -*)         echo "unknown option: $1" >&2; usage ;;
    *)          [ -z "$PKG" ] && PKG="$1" || { echo "unexpected argument: $1" >&2; usage; } ;;
  esac
  shift
done
[ -z "$PKG" ] && usage
case "$PKG" in *[!A-Za-z0-9._]*) echo "ERROR: package name has unexpected characters" >&2; exit 2 ;; esac
E="${E:-${SANE_ENGAGEMENT:-}}"
if [ -z "$OUT" ]; then if [ -n "$E" ]; then OUT="$E/recon/storage"; else OUT="storage-sweep/$PKG"; fi; fi

have() { command -v "$1" >/dev/null 2>&1; }
have adb || { echo "UNVERIFIED: adb not on PATH (set ANDROID_SDK_ROOT, see scripts/doctor.sh)"; exit 2; }
have python3 || { echo "UNVERIFIED: python3 missing"; exit 2; }
ADB=(adb); [ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")
# rq: single-quote a value for the REMOTE shell ('\'' escaping). Nothing else is special inside ''.
rq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }
cr() { tr -d '\r'; }

STATE="$("${ADB[@]}" get-state 2>&1 </dev/null | cr)"
case "$STATE" in
  device) ;;
  *"more than one"*) echo "UNVERIFIED: more than one device attached: pass --serial S (or export ANDROID_SERIAL)"; exit 2 ;;
  *) echo "UNVERIFIED: no device in state 'device' (adb get-state: ${STATE:-none})"; exit 2 ;;
esac
API="$("${ADB[@]}" shell getprop ro.build.version.sdk 2>/dev/null | cr)"
BUILD_TYPE="$("${ADB[@]}" shell getprop ro.build.type 2>/dev/null | cr)"

# ---- privilege ladder --------------------------------------------------------------------------
MODE=""
if [ "$("${ADB[@]}" shell getprop ro.debuggable 2>/dev/null | cr)" = "1" ]; then
  "${ADB[@]}" root >/dev/null 2>&1; "${ADB[@]}" wait-for-device 2>/dev/null; sleep 2   # adbd restarts
fi
if "${ADB[@]}" shell id 2>/dev/null | cr | grep -q 'uid=0('; then MODE=root
elif "${ADB[@]}" shell "su -c id" 2>/dev/null | cr | grep -q 'uid=0('; then MODE=su
elif "${ADB[@]}" shell "run-as $(rq "$PKG") id" 2>/dev/null | cr | grep -q 'uid='; then MODE=run-as
fi
if [ -z "$MODE" ]; then
  echo "UNVERIFIED: cannot read $PKG's sandbox -- adb root refused (build=$BUILD_TYPE), 'su -c id' is not uid 0"
  echo "            (Magisk: grant Shell/uid 2000 in the Magisk app), and run-as says the package is not debuggable."
  echo "            Use a rooted AVD/userdebug device. Do NOT record a negative for D11 from this run."
  exit 2
fi
# rsh <cmd>: run one remote command string under the discovered mode. RUNAS_USER set per user below;
# run-as takes --user only AFTER the package name (run-as <pkg> [--user N] <cmd>). </dev/null: never
# inherit a loop's stdin (adb drains it).
RUNAS_USER=""
rsh() {
  case "$MODE" in
    root)   "${ADB[@]}" shell "$1" </dev/null 2>/dev/null ;;
    su)     "${ADB[@]}" shell "su -c $(rq "$1")" </dev/null 2>/dev/null ;;
    run-as) "${ADB[@]}" shell "run-as $(rq "$PKG") ${RUNAS_USER}sh -c $(rq "$1")" </dev/null 2>/dev/null ;;
  esac | cr
}
rsh_bin() {   # binary-safe (tar streams): exec-out, no CR stripping
  case "$MODE" in
    root)   "${ADB[@]}" exec-out "$1" </dev/null 2>/dev/null ;;
    su)     "${ADB[@]}" exec-out "su -c $(rq "$1")" </dev/null 2>/dev/null ;;
    run-as) "${ADB[@]}" exec-out "run-as $(rq "$PKG") ${RUNAS_USER}sh -c $(rq "$1")" </dev/null 2>/dev/null ;;
  esac
}
NUNV=0
unv() { echo "   UNVERIFIED: $*"; NUNV=$((NUNV + 1)); }

mkdir -p "$OUT/logs" || { echo "ERROR: cannot create $OUT" >&2; exit 2; }
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && exec > >(tee -a "$E/logs/tools-05.txt"); fi
INV="$OUT/inventory.csv"; CAND="$OUT/candidates.csv"; STORES="$OUT/stores.csv"
CANDF="$OUT/logs/candidates-all.txt"; : > "$CANDF"     # every CANDIDATE line of any kind is tee'd here and counted at the end
if [ -n "$E" ]; then PULLROOT="$E/sensitive/pulled/$PKG"; else PULLROOT="$OUT/pulled"; fi
echo "user,path,size,mode,owner,label,sha256" > "$INV"
echo "user,shape,path,line,match,sha256" > "$CAND"
echo "user,kind,path,size" > "$STORES"

echo "== target: $PKG   device api=$API build=$BUILD_TYPE   read mode=$MODE"
[ "$MODE" = "run-as" ] && echo "   run-as: debuggable build. CE dir only; DE dir, other users and /data/misc are out of reach."

# ---- users -------------------------------------------------------------------------------------
USERS_ALL="$("${ADB[@]}" shell pm list users 2>/dev/null | cr | grep -oE 'UserInfo\{[0-9]+:[^:}]*' | sed 's/UserInfo{//')"
case "$USER_SEL" in
  all) USERS="$(printf '%s\n' "$USERS_ALL" | cut -d: -f1)" ;;
  *)   USERS="$USER_SEL" ;;
esac
[ -z "$USERS" ] && USERS="0"
echo "== users on device: $(printf '%s' "$USERS_ALL" | tr '\n' ' ')"
if [ "$USER_SEL" != "all" ] && [ "$(printf '%s\n' "$USERS_ALL" | wc -l | tr -d ' ')" -gt 1 ]; then
  echo "   INFO other users exist (work profile / Android 15 private space) and are NOT swept: rerun with --user all"
  echo "        a locked private space has no readable CE directory; unlock it first"
fi

CRED_RE='eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|[Bb]earer [A-Za-z0-9._~+/-]{16,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|name="(access_token|refresh_token|id_token|auth_token|session_token|token|api[_-]?key|apikey|client_secret|password|passwd|pin|secret)"[^>]*>[^<]{4,}|"(access_token|refresh_token|id_token|auth_token|session_token|api[_-]?key|apikey|client_secret|password|secret)"[[:space:]]*:[[:space:]]*"[^"]{4,}"'
STORE_RE='.*\.(db|sqlite|sqlite3|db-wal|db-journal|realm|cblite2?|preferences_pb|pb|mmkv|ldb|log|xml|json|crc)$'

NCAND=0; NFILES=0
for U in $USERS; do
  RUNAS_USER=""; [ "$U" != "0" ] && RUNAS_USER="--user $U "
  CE="/data/user/$U/$PKG"; DE="/data/user_de/$U/$PKG"
  DIRS="$CE $DE"; [ "$MODE" = "run-as" ] && DIRS="$CE"
  for D in $DIRS; do
    echo
    echo "== [$U] $D"
    if ! rsh "test -d $(rq "$D") && echo present" | grep -q present; then
      unv "directory absent or unreadable under mode=$MODE (app never run for this user, or locked CE storage)"
      continue
    fi
    # Inventory: ls -lZ gives mode/owner/SELinux label; sha256sum pairs by path. Both are toybox on
    # API 24+. Paths may contain spaces: the python join scans for the first field starting with '/'.
    rsh "find $(rq "$D") -type f -exec ls -lZ {} +" > "$OUT/logs/ls-$U-$(basename "$D").txt"
    rsh "find $(rq "$D") -type f -exec sha256sum {} +" > "$OUT/logs/sha-$U-$(basename "$D").txt"
    N=$(python3 -I - "$U" "$OUT/logs/ls-$U-$(basename "$D").txt" "$OUT/logs/sha-$U-$(basename "$D").txt" "$INV" <<'PY'
import csv, sys
user, lsf, shaf, inv = sys.argv[1:5]
sha = {}
for line in open(shaf, errors="replace"):
    line = line.rstrip("\n")
    if "  " in line:
        h, p = line.split("  ", 1); sha[p] = h
n = 0
with open(inv, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    for line in open(lsf, errors="replace"):
        parts = line.rstrip("\n").split()
        if len(parts) < 6 or not parts[0].startswith(("-", "l", "d", "c", "b", "p", "s")): continue
        pi = next((i for i in range(4, len(parts)) if parts[i].startswith("/")), None)
        if pi is None: continue
        path = line[line.index(parts[pi]):].rstrip("\n")
        mode, owner = parts[0], parts[2]
        label = parts[4] if parts[4].startswith("u:") or parts[4] == "?" else ""
        size = next((x for x in parts[4:pi] if x.isdigit()), "")
        w.writerow([user, path, size, mode, owner, label, sha.get(path, "")]); n += 1
print(n)
PY
)
    NFILES=$((NFILES + N))
    echo "   files: $N  (inventory.csv)"
    [ "$N" = "0" ] && unv "zero files listed -- a sandbox never has zero files; treat as a read failure, not as empty"
    # World-readable or group-readable files are a reach primitive on their own (targetSdk<24 only).
    rsh "find $(rq "$D") -type f -perm -o+r" | sed 's/^/   CANDIDATE storage\/world-readable  /' | head -20 | tee -a "$CANDF"
    echo "   -- data stores by extension (Realm, MMKV, DataStore, LevelDB, Couchbase live OUTSIDE databases/):"
    rsh "find $(rq "$D") -type f" | grep -E "$STORE_RE" | grep -vE '/code_cache/|/cache/' | while IFS= read -r p; do
      case "$p" in
        *.db|*.sqlite|*.sqlite3|*.db-wal|*.db-journal) k=sqlite ;; *.realm) k=realm ;; *.cblite|*.cblite2) k=couchbase ;;
        *.preferences_pb|*.pb) k=datastore ;; *.mmkv|*/mmkv/*) k=mmkv ;; *.ldb|*.log) k=leveldb ;; *.xml) k=xml ;; *.json) k=json ;; *) k=other ;;
      esac
      printf '%s,%s,"%s",\n' "$U" "$k" "$p" >> "$STORES"
      echo "      [$k] $p"
    done
    echo "   -- credential-shaped material (CANDIDATE lines; full match in candidates.csv):"
    rsh "grep -rnoaE $(rq "$CRED_RE") $(rq "$D")" | LC_ALL=C cut -c1-400 > "$OUT/logs/cred-$U-$(basename "$D").txt"
    B=$(grep -c 'CANDIDATE storage/credential-shape' "$CANDF" || true)
    python3 -I - "$U" "$OUT/logs/cred-$U-$(basename "$D").txt" "$CAND" "$FULL" <<'PY' | tee -a "$CANDF"
import csv, hashlib, re, sys
user, src, out, full = sys.argv[1:5]
n = 0
with open(out, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    for line in open(src, errors="replace"):
        m = re.match(r"^(.*?):(\d+):(.*)$", line.rstrip("\n"))
        if not m: continue
        path, ln, val = m.groups()
        shape = ("jwt" if val.startswith("eyJ") else "bearer" if val.lower().startswith("bearer") else
                 "google-api-key" if val.startswith("AIza") else "aws-access-key" if val.startswith("AKIA") else
                 "stripe-live" if val.startswith("sk_live_") else "private-key" if "PRIVATE KEY" in val else "named-secret")
        masked = val if len(val) <= 14 else val[:8] + "..." + val[-4:]
        w.writerow([user, shape, path, ln, val if full == "1" else masked, hashlib.sha256(val.encode()).hexdigest()]); n += 1
        print(f"   CANDIDATE storage/credential-shape {shape:15s} {path}:{ln}  {masked}")
PY
    C=$(( $(grep -c 'CANDIDATE storage/credential-shape' "$CANDF" || true) - B ))
    [ "$C" = "0" ] && echo "      (none matched; absence of a pattern is not absence of a secret -- read the stores)"
    # shared_prefs: key names and value lengths, never the values, on stdout (the file is pulled below).
    rsh "find $(rq "$D/shared_prefs") -type f -name '*.xml' 2>/dev/null" | while IFS= read -r f; do
      [ -z "$f" ] && continue
      echo "   -- $(basename "$f")"
      rsh "cat $(rq "$f")" | python3 -I -c '
import sys, re
for k, t, v in re.findall(r"<(string|int|long|boolean|float|set)[^>]*name=\"([^\"]*)\"[^>]*(?:>([^<]*)<|/>)", sys.stdin.read()):
    print(f"      {t:7s} {k}  ({len(v)} chars)")' | head -40
    done
    if [ "$PULL" = 1 ]; then
      P="$PULLROOT/$U/$(basename "$D")"; mkdir -p "$P"
      if [ "$MODE" = root ]; then "${ADB[@]}" pull "$D" "$P" </dev/null >/dev/null 2>&1
      elif rsh "command -v tar >/dev/null 2>&1 && echo tar-ok" | grep -q tar-ok; then
        rsh_bin "tar -cf - -C $(rq "$(dirname "$D")") $(rq "$(basename "$D")")" | tar -xf - -C "$P" 2>/dev/null
      else unv "no tar on the device (toybox tar is API 29+): --pull needs root (adb pull) on this build"; fi
      NP="$(find "$P" -type f 2>/dev/null | wc -l | tr -d ' ')"
      if [ "$NP" = 0 ]; then unv "pull produced 0 files in $P (stream failed or unreadable under mode=$MODE)"; else echo "   pulled $NP files -> $P  (sensitive: never commit)"; fi
      find "$P" -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) | while IFS= read -r db; do
        python3 -I - "$db" <<'PY' >> "$OUT/schema.txt" 2>/dev/null
import sqlite3, sys
p = sys.argv[1]; print("==", p)
try:
    c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    for (name, sql) in c.execute("select name, sql from sqlite_master where type='table'"):
        try: n = c.execute(f'select count(*) from "{name}"').fetchone()[0]
        except Exception: n = "?"
        print(f"   {name} rows={n}  {sql[:160] if sql else ''}")
except Exception as e: print("   UNVERIFIED: sqlite open failed:", e)
PY
      done
      [ -s "$OUT/schema.txt" ] && echo "   sqlite schemas + row counts -> $OUT/schema.txt"
    fi
  done

  echo
  echo "== [$U] external / shared storage (app-specific dirs are readable by the shell UID without root)"
  for X in "/storage/emulated/$U/Android/data/$PKG" "/storage/emulated/$U/Android/media/$PKG" "/storage/emulated/$U/Android/obb/$PKG"; do
    ST="$("${ADB[@]}" shell "if [ -d $(rq "$X") ]; then if [ -r $(rq "$X") ]; then echo readable; else echo unreadable; fi; else echo absent; fi" </dev/null 2>/dev/null | cr)"
    case "$ST" in
      readable)   "${ADB[@]}" shell "find $(rq "$X") -type f 2>/dev/null | head -40" </dev/null | cr | sed "s|^|   CANDIDATE storage/external  |" | tee -a "$CANDF" ;;
      unreadable) unv "$X exists but is unreadable to the shell UID (scoped storage on Android 11+, or a locked profile)" ;;
      absent)     echo "   absent: $X" ;;
      *)          unv "could not stat $X (adb returned '${ST:-nothing}')" ;;
    esac
  done
  echo "   -- heuristic name match outside the app dirs (Android/data excluded above; misses renamed files):"
  "${ADB[@]}" shell "find $(rq "/storage/emulated/$U") -path '*/Android/*' -prune -o -type f -iname $(rq "*${PKG##*.}*") -print 2>/dev/null | head -20" </dev/null | cr | sed 's/^/   CANDIDATE storage\/shared-heuristic  /' | tee -a "$CANDF"
  echo
  echo "== [$U] WebView storage (cookies, localStorage, service workers)"
  rsh "if [ -d $(rq "$CE/app_webview") ]; then if [ -r $(rq "$CE/app_webview") ]; then find $(rq "$CE/app_webview") -type f 2>/dev/null | head -30; else echo 'UNVERIFIED: app_webview exists but is unreadable under this mode'; fi; else echo '(absent: no WebView storage for this user)'; fi" | sed 's/^/   /'
done

# ---- backup reachability ------------------------------------------------------------------------
echo
echo "== backup reachability -- THIS is what turns storage into a finding (MASTG-TEST-0216 / -0262, D11)"
DUMP="$("${ADB[@]}" shell dumpsys package "$PKG" </dev/null 2>/dev/null | cr)"
echo "$DUMP" > "$OUT/logs/dumpsys-package.txt"
FLAGS="$(printf '%s\n' "$DUMP" | grep -oE '(pkgFlags|flags)=\[[^]]*\]' | head -1)"
TSDK="$(printf '%s\n' "$DUMP" | grep -oE 'targetSdk=[0-9]+' | head -1 | cut -d= -f2)"
AB="unverified"; DBG="unverified"
if [ -n "$FLAGS" ]; then
  case "$FLAGS" in *ALLOW_BACKUP*) AB=true ;; *) AB=false ;; esac
  case "$FLAGS" in *DEBUGGABLE*) DBG=true ;; *) DBG=false ;; esac
fi
M_AB=""; M_FBC=""; M_DER=""
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
  M_AB="$(grep -oE 'android:allowBackup="[^"]*"' "$MANIFEST" | head -1 | cut -d'"' -f2)"
  M_FBC="$(grep -oE 'android:fullBackupContent="[^"]*"' "$MANIFEST" | head -1 | cut -d'"' -f2)"
  M_DER="$(grep -oE 'android:dataExtractionRules="[^"]*"' "$MANIFEST" | head -1 | cut -d'"' -f2)"
  echo "   manifest: allowBackup=${M_AB:-unset(default true)} fullBackupContent=${M_FBC:--} dataExtractionRules=${M_DER:--}"
  [ -n "$M_FBC$M_DER" ] && echo "   -> read the rules XML (res/xml/): <exclude> is honoured only for the matching domain; a cloud-only rule still leaves D2D/adb paths open"
else
  echo "   manifest: not given (--manifest \$DEC/apktool/AndroidManifest.xml); using dumpsys flags"
fi
echo "   dumpsys: allowBackup=$AB debuggable=$DBG targetSdk=${TSDK:-?}"
[ "$AB" = unverified ] && unv "no pkgFlags line in dumpsys package output"
if [ "$DBG" = true ]; then echo "   adb backup: applicable (debuggable build; Android 12+ requires it) -- but a shipped debuggable build is D02 first"
else echo "   adb backup: not applicable on Android 12+ (not debuggable); the realistic paths are bmgr/cloud and D2D transfer"; fi
if [ "$BACKUP" = 1 ] && [ "$MODE" != run-as ]; then
  echo "   -- materialising the backup set via bmgr + LocalTransport (switches transport; restored afterwards)"
  PREV="$("${ADB[@]}" shell bmgr list transports </dev/null 2>/dev/null | cr | grep -E '^[[:space:]]*\*' | sed 's/^[* ]*//')"
  "${ADB[@]}" shell bmgr enable true </dev/null >/dev/null 2>&1
  "${ADB[@]}" shell "bmgr transport com.android.localtransport/.LocalTransport" </dev/null | cr | grep -q 'Selected transport' \
    || unv "LocalTransport could not be selected"
  "${ADB[@]}" shell "settings put secure backup_local_transport_parameters 'is_encrypted=true'" </dev/null >/dev/null 2>&1   # so rules needing an encrypted transport still run
  BN="$("${ADB[@]}" shell "bmgr backupnow $(rq "$PKG")" </dev/null 2>/dev/null | cr)"
  printf '%s\n' "$BN" > "$OUT/logs/bmgr.txt"
  if printf '%s\n' "$BN" | grep -q 'with result: Success'; then
    mkdir -p "$OUT/backup"
    rsh "find /data/data/com.android.localtransport/files -path $(rq "*$PKG*") -type f" | while IFS= read -r f; do
      [ -z "$f" ] && continue
      rsh_bin "cat $(rq "$f")" > "$OUT/backup/$(basename "$f").ab"
    done
    python3 -I - "$OUT/backup" "$OUT/backup-set.txt" <<'PY' | tee -a "$CANDF"
import glob, io, os, sys, tarfile, zlib
d, out = sys.argv[1:3]; names = []
for ab in glob.glob(os.path.join(d, "*.ab")):
    raw = open(ab, "rb").read()
    for blob in (raw, (lambda r: zlib.decompress(r[24:]) if r.startswith(b"ANDROID BACKUP") else b"")(raw)):
        try:
            with tarfile.open(fileobj=io.BytesIO(blob)) as t: names += [m.name for m in t.getmembers() if m.isfile()]
            break
        except Exception: continue
open(out, "w").write("\n".join(sorted(set(names))) + "\n")
print(f"   backup set: {len(set(names))} files -> {out}" if names else "   UNVERIFIED: backup artefact not parseable as tar/.ab -- inspect " + d)
for n in sorted(set(names))[:40]: print("   CANDIDATE storage/in-backup-set", n)
PY
  else
    unv "bmgr backupnow did not report Success (see logs/bmgr.txt): backup disabled for the app, transport refused, or API<24"
  fi
  [ -n "$PREV" ] && "${ADB[@]}" shell "bmgr transport $(rq "$PREV")" </dev/null >/dev/null 2>&1
  "${ADB[@]}" shell "settings delete secure backup_local_transport_parameters" </dev/null >/dev/null 2>&1
else
  echo "   UNVERIFIED: backup set not materialised (rerun with --backup under root/su on a lab device)."
  echo "   The restore guard matters as much as the set: an android_id equality check is a heuristic, not authentication."
fi

# ---- summary -------------------------------------------------------------------------------------
NCAND=$(grep -c 'CANDIDATE' "$CANDF" || true)
python3 -I - "$OUT" "$PKG" "$MODE" "$API" "$NFILES" "$NCAND" "$AB" "$DBG" "${TSDK:-}" "$USERS" "$JSON" "$NUNV" "$FULL" <<'PY'
import collections, csv, json, os, re, sys
out, pkg, mode, api, nfiles, ncand, ab, dbg, tsdk, users, js, nunv, full = sys.argv[1:14]
rows = lambda p: list(csv.DictReader(open(p, newline="", encoding="utf-8"))) if os.path.exists(p) else []
kinds = collections.Counter(m.group(1) for l in open(os.path.join(out, "logs", "candidates-all.txt"), errors="replace")
                            for m in [re.search(r"CANDIDATE (storage/[^ ]+)", l)] if m)
s = {"tool": "05-storage-sweep", "package": pkg, "read_mode": mode, "device_api": api, "users": users.split(),
     "files_inventoried": int(nfiles), "candidates": int(ncand), "candidates_by_kind": dict(kinds), "unverified": int(nunv),
     "values": "full" if full == "1" else "masked+sha256", "stores": len(rows(os.path.join(out, "stores.csv"))),
     "backup": {"allowBackup": ab, "debuggable": dbg, "targetSdk": tsdk or None,
                "backup_set_file": os.path.join(out, "backup-set.txt") if os.path.exists(os.path.join(out, "backup-set.txt")) else None},
     "files": {k: os.path.join(out, k) for k in ("inventory.csv", "candidates.csv", "stores.csv", "schema.txt", "backup-set.txt") if os.path.exists(os.path.join(out, k))},
     "note": "discovery only: shell/root UID. Reach must be re-proved from attacker-app/ (AM-03) or the backup/transfer path."}
json.dump(s, open(os.path.join(out, "summary.json"), "w"), indent=1)
if js == "1": print(json.dumps(s, indent=1))
PY
echo
echo "[+] $NCAND CANDIDATE ($(sed -n 's/.*CANDIDATE \(storage\/[^ ]*\).*/\1/p' "$CANDF" | sort | uniq -c | awk '{printf "%s%s=%s", (NR>1?", ":""), $2, $1}')), $NUNV UNVERIFIED"
echo "[+] evidence: $OUT  (inventory.csv candidates.csv stores.csv summary.json$([ "$PULL" = 1 ] && printf ' pulled -> %s' "$PULLROOT"))"
[ "$FULL" = 1 ] && echo "    candidates.csv holds FULL values (--full-values): keep it under \$E/sensitive/, never commit it"
cat <<'NOTE'

ESCALATION PATH (do not stop at "data is unencrypted" -- that is P5)
  1. Name the crown-jewel value (session token, PAN, OTP seed, refresh token) from candidates.csv.
  2. Ask: can a weaker attacker REACH that file? exported/grantable provider (D07)? FileProvider root?
     traversal? the backup set above? shared storage? run-as on a shipped debuggable build (D02)?
  3. YES -> the finding is the REACH primitive, rated on what the value unlocks (AM-02/03/04).
  4. NO  -> ruled-out row with the mechanism (mode 0700 + no provider + excluded from backup), move on.
  5. Always replay the token from curl, off-device: a "device-bound" token that works from curl is
     the bigger finding (D13).
REMINDER: adb here ran as shell/root. Everything above is DISCOVERY; nothing is proved for AM-03
          until the zero-permission probe app (attacker-app/) reaches it.
NOTE
if [ "$NCAND" -gt 0 ]; then exit 0; fi
if [ "$NUNV" -gt 0 ] || [ "$NFILES" = 0 ]; then
  echo "UNVERIFIED: no candidate and $NUNV probe(s) could not run (files=$NFILES) -> exit 2, not a negative"; exit 2
fi
exit 1
