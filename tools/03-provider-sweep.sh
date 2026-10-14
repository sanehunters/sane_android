#!/usr/bin/env bash
# 03-provider-sweep.sh <pkg> [--inventory DIR] [--authority A] [--out DIR] [--serial S] [--user N] [--write] [--json] [--help]
# Quick ContentProvider read / selection / write / call() sweep per authority -- the five-minute pass
# before tools/09-provider-fuzz.py (09 adds UriMatcher mining, repeated baselines and the SQL oracle:
# use 09 for depth). read, write and call() are THREE SEPARATE QUESTIONS -- call() is gated by neither
# readPermission nor writePermission.
#
# Authorities: <inventory>/components.csv (type=provider, extra authorities=a;b; default $E/inventory),
# then --authority (repeatable), then `dumpsys package` (ContentProvider Authorities section, Provider{}
# owned by <pkg>).
# Quoting: every URI, selection and bind value is rq()-quoted for the REMOTE shell and the whole remote
# command is ONE argument, so `' OR '1'='1` and `1=1) OR (1=1` reach the provider intact.
# Classifier (the one tools/09 uses): SecurityException / Permission Denial = closed; "Unknown URI" with
# a stack frame inside <pkg> = reachable (the permission gate PASSED, the UriMatcher rejected the path);
# `Result: null` from call() = reachable; rows / a Bundle / an accepted insert = CANDIDATE.
# Writes: `content insert` runs ONLY with --write (it puts a canary row into a real account otherwise).
# Privilege: refuses to run when `adb shell id` is uid 0 (root reaches non-exported providers).
# Outputs: DIR/results.csv (n,authority,op,uri,args,result_class,tag,reason,head), results.json. DIR
#          defaults to $E/recon/provider-sweep, else ./provider-sweep/<pkg>; the human output is appended
#          to $E/logs/tools-03.txt when $E is set.
# Exit: 0 >=1 CANDIDATE; 1 ran, nothing; 2 usage/environment, or nothing interpretable (no authority,
#       uid 0, every probe UNVERIFIED).
set -uo pipefail
usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
PKG=""; INV=""; AUTH_CLI=""; OUT=""; SERIAL="${ANDROID_SERIAL:-}"; USERN=""; WRITE=0; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --inventory) INV="${2:-}"; shift ;;  --authority) AUTH_CLI="$AUTH_CLI ${2:-}"; shift ;;  --out) OUT="${2:-}"; shift ;;
    --serial) SERIAL="${2:-}"; shift ;;  --user) USERN="${2:-}"; shift ;;  --write) WRITE=1 ;;  --json) JSON=1 ;;
    -h|--help) usage 0 ;;  -*) echo "unknown option: $1" >&2; usage ;;
    *) if [ -z "$PKG" ]; then PKG="$1"; else echo "unexpected argument: $1" >&2; usage; fi ;;
  esac
  shift
done
[ -z "$PKG" ] && usage
case "$PKG" in *[!A-Za-z0-9._]*) echo "ERROR: package name has unexpected characters" >&2; exit 2 ;; esac
E="${E:-${SANE_ENGAGEMENT:-}}"
[ -z "$INV" ] && [ -n "$E" ] && INV="$E/inventory"
if [ -z "$OUT" ]; then if [ -n "$E" ]; then OUT="$E/recon/provider-sweep"; else OUT="provider-sweep/$PKG"; fi; fi
command -v adb >/dev/null 2>&1 || { echo "UNVERIFIED: adb not on PATH (set ANDROID_SDK_ROOT, see scripts/doctor.sh)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "UNVERIFIED: python3 missing"; exit 2; }
ADB=(adb); [ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")
rq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }   # single-quote for the REMOTE shell
cr() { tr -d '\r'; }
STATE="$("${ADB[@]}" get-state 2>&1 </dev/null | cr)"
case "$STATE" in
  device) ;;
  *"more than one"*) echo "UNVERIFIED: more than one device attached: pass --serial S (or export ANDROID_SERIAL)"; exit 2 ;;
  *) echo "UNVERIFIED: no device in state 'device' (adb get-state: ${STATE:-none})"; exit 2 ;;
esac
if "${ADB[@]}" shell id </dev/null 2>/dev/null | cr | grep -q 'uid=0('; then
  echo "UNVERIFIED: adb shell is uid 0 (rooted adbd): root reaches non-exported providers, nothing here would be an export result. adb unroot, then rerun."
  exit 2
fi
mkdir -p "$OUT" || { echo "ERROR: cannot create $OUT" >&2; exit 2; }
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && exec > >(tee -a "$E/logs/tools-03.txt"); fi
USERARG=""; [ -n "$USERN" ] && USERARG="--user $USERN "
CSV="$OUT/results.csv"; echo "n,authority,op,uri,args,result_class,tag,reason,head" > "$CSV"

# ---- authorities ---------------------------------------------------------------------------------
AUTHS=""; SRC=""
if [ -n "$INV" ] && [ -f "$INV/components.csv" ]; then
  AUTHS="$(python3 -I - "$INV/components.csv" <<'PY'
import csv, re, sys
for r in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")):
    if r.get("type") != "provider": continue
    m = re.search(r"authorities=(\S+)", r.get("extra", ""))
    for a in (m.group(1).split(";") if m else []): print(a)
PY
)"; SRC="$INV/components.csv"
fi
if [ -n "$AUTH_CLI" ]; then AUTHS="$(printf '%s\n%s\n' "$AUTHS" "$(printf '%s\n' $AUTH_CLI)")"; SRC="${SRC:+$SRC + }--authority"; fi
if [ -z "$(printf '%s' "$AUTHS" | tr -d '[:space:]')" ]; then
  AUTHS="$("${ADB[@]}" shell "dumpsys package $(rq "$PKG")" </dev/null 2>/dev/null | cr | python3 -I - "$PKG" <<'PY'
import re, sys
cur = None
for line in sys.stdin:
    m = re.match(r"\s*\[([^\]]+)\]:\s*$", line)
    if m: cur = m.group(1); continue
    m = re.search(r"Provider\{\S+ (\S+?)/(\S+)\}", line)
    if m and cur:
        if m.group(1) == sys.argv[1]: print(cur)
        cur = None
PY
)"; SRC="dumpsys package"
fi
AUTHS="$(printf '%s\n' "$AUTHS" | grep -E '^[A-Za-z0-9._-]+$' | sort -u)"
NA="$(printf '%s\n' "$AUTHS" | grep -c . || true)"
[ "$NA" = 0 ] && { echo "UNVERIFIED: no provider authority for $PKG (components.csv has none, no --authority, dumpsys shows none) -> exit 2, not a negative"; exit 2; }
echo "== $PKG: $NA authorities from $SRC"; printf '%s\n' "$AUTHS" | sed 's/^/     /'
echo

N=0; NCAND=0; NUNV=0
probe() {   # probe <op> <uri> <args-label> <remote-command>
  local OP="$1" U="$2" ARGS="$3" REMOTE="$4" R CLS TAG WHY
  N=$((N + 1))
  R="$("${ADB[@]}" shell "$REMOTE" </dev/null 2>&1 | cr | head -c 4000)"
  CLS="$(printf '%s\n' "$R" | python3 -I - "$OP" "$PKG" <<'PY'
import re, sys
op, pkg = sys.argv[1:3]; o = sys.stdin.read()
def out(c): print(c); sys.exit(0)
if re.search(r"SecurityException|Permission Denial|Permission denied|requires .* permission", o): out("closed:security")
if re.search(r"Could not find provider|Failed to find provider|No content provider|Unknown authority", o): out("no-provider")
if re.search(r"Unknown UR[IL]", o): out("reachable:unknown-uri" if ("at " + pkg) in o else "no-provider")
if re.search(r"SQLiteException|SQLITE_ERROR|syntax error|no such (table|column)|android\.database\.sqlite", o): out("error:sqlite")
if re.search(r"FileNotFoundException", o): out("reachable:no-file")
if re.search(r"Error while accessing provider|Exception", o): out("error:app" if ("at " + pkg) in o else "error:other")
rows = len(re.findall(r"^Row: \d+", o, re.M))
if op == "query": out("candidate:rows:%d" % rows if rows else "reachable:empty")
if op == "insert": out("candidate:inserted" if "content://" in o else "reachable:write-accepted")
if op == "call": out("candidate:call-returned" if re.search(r"Result: Bundle\[", o) else "reachable:call-null")
out("unknown")
PY
)"
  TAG=closed; WHY=""
  case "$CLS" in
    closed:security)   WHY="SecurityException/Permission Denial for uid 2000" ;;
    no-provider)       TAG="no-provider"; WHY="authority not registered on this device/user" ;;
    candidate:rows:*)  TAG="CANDIDATE provider/readable"; case "$U" in *..*|*%2e*|*%2E*) TAG="CANDIDATE provider/traversal-rows" ;; esac
                       WHY="${CLS##*:} rows returned to the shell UID" ;;
    candidate:inserted|reachable:write-accepted) TAG="CANDIDATE provider/write-reachable"; WHY="insert accepted without SecurityException (asymmetric read/write gate?)" ;;
    candidate:call-returned) TAG="CANDIDATE provider/call-returned"; WHY="call() returned a Bundle" ;;
    reachable:*)       TAG="INFO reachable"; WHY="permission gate passed for uid 2000; ${CLS#*:}" ;;
    error:sqlite)      TAG="INFO sqlite-error"; WHY="the argument reached SQLite: run tools/09 for the row-count oracle" ;;
    error:app)         TAG="INFO reachable"; WHY="exception inside the provider (gate passed)" ;;
    unknown)           TAG=UNVERIFIED; WHY="unclassified output: $(printf '%s' "$R" | head -1 | cut -c1-80)"; NUNV=$((NUNV + 1)) ;;
    *)                 WHY="$CLS" ;;
  esac
  case "$TAG" in CANDIDATE*) NCAND=$((NCAND + 1)) ;; esac
  printf '  %-6s %-52s %-24s %s\n' "$OP" "$(printf '%s %s' "$U" "$ARGS" | cut -c1-52)" "$CLS" "$TAG"
  [ -n "$WHY" ] && [ "$TAG" != closed ] && printf '         %s\n' "$WHY"
  printf '%s,%s,%s,"%s","%s",%s,"%s","%s","%s"\n' "$N" "$AUTH" "$OP" "$(printf '%s' "$U" | sed 's/"/""/g')" "$(printf '%s' "$ARGS" | sed 's/"/""/g')" "$CLS" "$TAG" \
    "$(printf '%s' "$WHY" | sed 's/"/""/g')" "$(printf '%s' "$R" | head -1 | cut -c1-120 | sed 's/"/""/g')" >> "$CSV"
}

for AUTH in $AUTHS; do
  echo "=============================================================="
  echo " $AUTH"
  echo "=============================================================="
  for P in "" "/" "//" "/1" "/x" "/.." "/../.." "/%2e%2e%2f" "/..%2f..%2fshared_prefs"; do
    U="content://$AUTH$P"; probe query "$U" "" "content query ${USERARG}--uri $(rq "$U")"
  done
  for SEL in "1=1" "1=2" "1=1) OR (1=1" "' OR '1'='1"; do
    U="content://$AUTH"; probe query "$U" "where=$SEL" "content query ${USERARG}--uri $(rq "$U") --where $(rq "$SEL")"
  done
  if [ "$WRITE" = 1 ]; then
    probe insert "content://$AUTH" "bind=sane_probe:s:x" "content insert ${USERARG}--uri $(rq "content://$AUTH") --bind $(rq "sane_probe:s:x")"
  else echo "  insert skipped: --write runs it (inserts a canary row sane_probe=x into a real account)"; fi
  for M in test getInfo get query init config; do
    probe call "content://$AUTH" "method=$M" "content call ${USERARG}--uri $(rq "content://$AUTH") --method $(rq "$M")"
  done
  echo
done

python3 -I - "$CSV" "$OUT/results.json" "$PKG" "$JSON" "$NUNV" <<'PY' 2>/dev/null || true
import csv, json, sys
rows = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")))
s = {"tool": "03-provider-sweep", "package": sys.argv[3], "probes": len(rows), "candidates": sum(r["tag"].startswith("CANDIDATE") for r in rows),
     "unverified": int(sys.argv[5]), "rows": rows, "note": "adb (shell UID) establishes discovery only; re-prove from attacker-app/ (AM-03). tools/09 for depth."}
json.dump(s, open(sys.argv[2], "w"), indent=1)
if sys.argv[4] == "1": print(json.dumps(s, indent=1))
PY
echo "[+] $N probes over $NA authorities, $NCAND CANDIDATE, $NUNV UNVERIFIED -> $CSV"
cat <<'NOTE'
WHAT TO ESCALATE
  readable rows on a provider that should be private  -> D07, then chase what the rows contain
  traversal path returns data                          -> server_side_injection.file_inclusion.local (VRT P1)
  where= probe changes the row count                   -> server_side_injection.sql_injection (VRT P1): tools/09 proves it
  insert succeeds but read is permission-protected     -> read/write permission asymmetry
  call() returns a Bundle where query() is blocked     -> the classic ungated call() bug
  "Unknown URI" with the app's stack frame             -> gate passed; mine the UriMatcher paths (tools/09 --jadx)
NOTE
if [ "$NCAND" -gt 0 ]; then exit 0; fi
if [ "$N" -eq 0 ] || [ "$NUNV" -gt 0 ]; then
  echo "UNVERIFIED: no candidate and nothing interpretable (probes=$N unverified=$NUNV) -> exit 2, not a negative"; exit 2
fi
exit 1
