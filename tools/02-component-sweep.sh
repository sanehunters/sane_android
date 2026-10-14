#!/usr/bin/env bash
# 02-component-sweep.sh <pkg> [--inventory DIR] [--out DIR] [--serial S] [--user N] [--settle S] [--json] [--help]
# Dynamic sweep of EXPORTED activities: start each one with a handful of attacker-shaped extras and record
# what stays on top. WARM-START ONLY: the app is launched once and never force-stopped between probes --
# this tool reads `topResumedActivity` after a delay, and a cold start routes through the launcher
# activity and invalidates that reading (tools/07 and 08 read the ActivityManager START line instead,
# which is valid cold or warm; see tools/README "Start discipline").
#
# Components: <inventory>/components.csv (scripts/inventory.py; type activity/activity-alias,
# exported=true) -- the default is $E/inventory. Without it the list falls back to `dumpsys package`
# (every class in the resolver tables, exported or not: the run is marked UNVERIFIED-export).
# Quoting: every remote command is ONE rq()-quoted string, so inner-class names (Foo$Bar) and extras
# with `/`, `:` or spaces survive the device shell. The `am start` error text is kept per row.
# Privilege: refuses to run when `adb shell id` is uid 0 -- root reaches non-exported components, so
# nothing would be an export result (adb unroot first). adb as shell (uid 2000) is still DISCOVERY.
# Outputs: DIR/results.csv (n,component,input,am_status,am_error,top_after,stayed,crash,tag,reason,log),
#          results.json, logs/<n>.txt. DIR defaults to $E/recon/component-sweep, else ./component-sweep/<pkg>;
#          the human output is appended to $E/logs/tools-02.txt when $E is set.
# Exit: 0 >=1 CANDIDATE; 1 ran, nothing; 2 usage/environment, or nothing interpretable (no component,
#       uid 0, every probe UNVERIFIED).
set -uo pipefail
usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
PKG=""; INV=""; OUT=""; SERIAL="${ANDROID_SERIAL:-}"; USERN=""; SETTLE=2; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --inventory) INV="${2:-}"; shift ;;  --out) OUT="${2:-}"; shift ;;  --serial) SERIAL="${2:-}"; shift ;;
    --user) USERN="${2:-}"; shift ;;  --settle) SETTLE="${2:-2}"; shift ;;  --json) JSON=1 ;;
    -h|--help) usage 0 ;;  -*) echo "unknown option: $1" >&2; usage ;;
    *) if [ -z "$PKG" ]; then PKG="$1"; else echo "unexpected argument: $1" >&2; usage; fi ;;
  esac
  shift
done
[ -z "$PKG" ] && usage
case "$PKG" in *[!A-Za-z0-9._]*) echo "ERROR: package name has unexpected characters" >&2; exit 2 ;; esac
E="${E:-${SANE_ENGAGEMENT:-}}"
[ -z "$INV" ] && [ -n "$E" ] && INV="$E/inventory"
if [ -z "$OUT" ]; then if [ -n "$E" ]; then OUT="$E/recon/component-sweep"; else OUT="component-sweep/$PKG"; fi; fi
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
  echo "UNVERIFIED: adb shell is uid 0 (rooted adbd): root reaches non-exported components, nothing here would be an export result. adb unroot, then rerun."
  exit 2
fi
mkdir -p "$OUT/logs" || { echo "ERROR: cannot create $OUT" >&2; exit 2; }
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && exec > >(tee -a "$E/logs/tools-02.txt"); fi
USERARG=""; [ -n "$USERN" ] && USERARG="--user $USERN "
CSV="$OUT/results.csv"; echo "n,component,input,am_status,am_error,top_after,stayed,crash,tag,reason,log" > "$CSV"

# ---- component list ------------------------------------------------------------------------------
SRC=""; COMPS=""; EXPORT_KNOWN=1
if [ -n "$INV" ] && [ -f "$INV/components.csv" ]; then
  COMPS="$(python3 -I - "$INV/components.csv" "$PKG" <<'PY'
import csv, sys
path, pkg = sys.argv[1:3]
for r in csv.DictReader(open(path, newline="", encoding="utf-8")):
    if r.get("type") in ("activity", "activity-alias") and str(r.get("exported", "")).lower() == "true":
        n = r.get("name", "")
        print(pkg + n if n.startswith(".") else n)
PY
)"; SRC="$INV/components.csv (exported activities)"
fi
if [ -z "$COMPS" ]; then
  COMPS="$("${ADB[@]}" shell "dumpsys package $(rq "$PKG")" </dev/null 2>/dev/null | cr | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sed "s|^$PKG/||;s|^\.|$PKG.|" | sort -u)"
  SRC="dumpsys package"; EXPORT_KNOWN=0
fi
M="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$M" = 0 ] && { echo "UNVERIFIED: no component found for $PKG (not installed for this user? no components.csv in $INV?)"; exit 2; }
echo "== $PKG: $M components from $SRC"
[ "$EXPORT_KNOWN" = 0 ] && echo "   UNVERIFIED-export: dumpsys lists every class in the resolver tables (services, receivers, non-exported); a Permission Denial row is the OS gate, not a finding. Run scripts/inventory.py for the exported filter."
echo "[*] warming app (warm-start discipline: never force-stop between probes)"
"${ADB[@]}" shell "monkey -p $(rq "$PKG") -c android.intent.category.LAUNCHER 1" </dev/null >/dev/null 2>&1
sleep 6
"${ADB[@]}" logcat -c -b crash </dev/null >/dev/null 2>&1
top() {
  "${ADB[@]}" shell dumpsys activity activities </dev/null 2>/dev/null | cr \
    | grep -oE '(topResumedActivity|mResumedActivity|ResumedActivity)[=:] ?ActivityRecord\{[^ ]+ u[0-9]+ [^ }]+' | head -1 | sed 's/.* u[0-9]* //'
}
printf '%-60s %-30s %-7s %s\n' "COMPONENT" "INPUT" "STAYED" "TAG"
N=0; NCAND=0; NUNV=0
while IFS= read -r A <&3 || [ -n "$A" ]; do
  [ -z "$A" ] && continue
  CN="$PKG/$A"
  for X in "" "--es url https://attacker.example/" "--es model x" "--ei id 1" "--esn nullextra" \
           "--es redirect_uri https://attacker.example/" "--es data content://$PKG.provider/" "-d https://attacker.example/"; do
    N=$((N + 1))
    REMOTE="am start -W ${USERARG}-n $(rq "$CN")"
    case "$X" in
      "") ;;
      -d\ *) REMOTE="$REMOTE -d $(rq "${X#-d }")" ;;
      *) K="${X%% *}"; R2="${X#* }"; NAME="${R2%% *}"; VAL="${R2#* }"
         REMOTE="$REMOTE $K $(rq "$NAME")"; [ "$K" = "--esn" ] || REMOTE="$REMOTE $(rq "$VAL")" ;;
    esac
    AMOUT="$("${ADB[@]}" shell "$REMOTE" </dev/null 2>&1 | cr)"
    STATUS="$(printf '%s\n' "$AMOUT" | grep -oE '^Status: [a-z]+' | head -1 | cut -d' ' -f2)"
    ERR="$(printf '%s\n' "$AMOUT" | grep -E '^Error|Exception|Permission Denial|unable to resolve' | head -1 | cut -c1-120)"
    sleep "$SETTLE"
    T="$(top)"
    LOG="$OUT/logs/$N.txt"
    { printf '### %s\n%s\n### top=%s\n' "$REMOTE" "$AMOUT" "$T"; "${ADB[@]}" logcat -d -b crash </dev/null 2>/dev/null | cr | tail -40; } > "$LOG"
    CRASH="$(grep -E 'FATAL EXCEPTION|AndroidRuntime' "$LOG" | head -1 | cut -c1-80)"
    STAYED=no; case "$T" in "$CN"|"$PKG/.${A#$PKG.}") STAYED=yes ;; esac
    TAG=closed; WHY=""
    if [ -n "$ERR" ]; then
      case "$ERR" in
        *"Permission Denial"*) WHY="OS export gate: not exported to uid 2000" ;;
        *) TAG=UNVERIFIED; WHY="am start error: $ERR"; NUNV=$((NUNV + 1)) ;;
      esac
    elif [ -n "$CRASH" ]; then TAG="CANDIDATE component/crash"; WHY="$CRASH"
    elif [ "$STAYED" = yes ] && [ -n "$X" ]; then TAG="CANDIDATE component/accepted-input"; WHY="stayed resumed on attacker input: read what it did with it (D04 / D08 / D10 sink)"
    elif [ "$STAYED" = yes ]; then TAG="INFO reachable"; WHY="bare start reached it"
    elif [ -z "$T" ]; then TAG=UNVERIFIED; WHY="could not read the resumed activity (dumpsys keys unknown on this build?)"; NUNV=$((NUNV + 1))
    else WHY="finished immediately (a validator ran: read it) or routed to $T"; fi
    case "$TAG" in CANDIDATE*) NCAND=$((NCAND + 1)) ;; esac
    printf '%-60s %-30s %-7s %s\n' "$(printf '%s' "$A" | cut -c1-60)" "${X:-<bare>}" "$STAYED" "$TAG"
    [ -n "$WHY" ] && printf '    %s\n' "$WHY"
    printf '%s,"%s","%s",%s,"%s","%s",%s,"%s","%s","%s",%s\n' "$N" "$CN" "${X:-<bare>}" "${STATUS:-?}" "$(printf '%s' "$ERR" | sed 's/"/""/g')" "$T" "$STAYED" \
      "$(printf '%s' "$CRASH" | sed 's/"/""/g')" "$TAG" "$(printf '%s' "$WHY" | sed 's/"/""/g')" "$LOG" >> "$CSV"
    "${ADB[@]}" shell input keyevent KEYCODE_BACK </dev/null >/dev/null 2>&1
    sleep 1
  done
done 3<<EOF
$COMPS
EOF

python3 -I - "$CSV" "$OUT/results.json" "$PKG" "$JSON" "$NUNV" "$EXPORT_KNOWN" <<'PY' 2>/dev/null || true
import csv, json, sys
rows = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")))
s = {"tool": "02-component-sweep", "package": sys.argv[3], "probes": len(rows), "candidates": sum(r["tag"].startswith("CANDIDATE") for r in rows),
     "unverified": int(sys.argv[5]), "export_filter_applied": sys.argv[6] == "1", "rows": rows,
     "note": "adb (shell UID) establishes discovery only; re-prove from attacker-app/ (AM-03) before it is a finding"}
json.dump(s, open(sys.argv[2], "w"), indent=1)
if sys.argv[4] == "1": print(json.dumps(s, indent=1))
PY
echo
echo "[+] $N probes over $M components, $NCAND CANDIDATE, $NUNV UNVERIFIED -> $CSV  (am output + crash buffer in $OUT/logs/)"
cat <<'NOTE'

READ THE RESULT COLUMN, NOT THE EXIT CODE.
  - component STAYS RESUMED on attacker input  -> candidate, it accepted your data
  - component finishes immediately             -> it is validating something; read the validator
  - a crash                                    -> P5 DoS on its own. Only interesting if it becomes
                                                  memory corruption with a demonstrated primitive.

adb runs as `shell`, which holds far MORE privilege than a real attacker.
Anything that looks live here must be re-proved from a ZERO-PERMISSION ATTACKER APP
before it is a finding. See docs/05-attacker-models.md (AM-03).
NOTE
if [ "$NCAND" -gt 0 ]; then exit 0; fi
if [ "$N" -eq 0 ] || [ "$NUNV" -gt 0 ]; then
  echo "UNVERIFIED: no candidate and nothing interpretable (probes=$N unverified=$NUNV) -> exit 2, not a negative"; exit 2
fi
exit 1
