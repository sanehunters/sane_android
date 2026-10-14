#!/usr/bin/env bash
# new-engagement.sh <TargetName> [DDMMYYYY] [--remote <git url>] [--json]
# Creates BugBountyTarget/<TargetName>_<DDMMYYYY>/ from _TEMPLATE, seeds checklist-status.csv (every row
# completed=false) and engagement.json (phase P0, no gate passed), substitutes the template placeholders, and
# makes the folder its own git repository — THE EVIDENCE REPO. The methodology repository is public and never
# tracks engagements (.gitignore + pre-bash hook); evidence is pushed only to a PRIVATE remote the operator supplies:
#   SANE_EVIDENCE_REMOTE=<git url>  or  --remote <git url>   → origin of the evidence repo, recorded in
#   engagement.json.evidence_remote. Absent → evidence_remote is null and evidence stays local until one is added
#   (git -C "$E" remote add origin <private url>).
# Optional: SANE_ENGAGEMENT_ROOT=/path (default <repo>/BugBountyTarget) · SANE_LOCAL_MIRROR=/path (one-shot copy).
# Portable: Linux and macOS, bash 3.2 (no sed -i, no stat -f). No operator-specific paths.
# Exit codes: 0 created · 1 the engagement already exists (resume it) · 2 usage or environment error.
# --json prints one JSON object instead of the banner (path, row count, phase, evidence_remote) for a model to continue from.
set -euo pipefail

usage() { echo "usage: $0 <TargetName> [DDMMYYYY] [--remote <git url>] [--json]   TargetName: [A-Za-z0-9_-]+ ; date defaults to today"; }
JSON=0; POS=(); REMOTE="${SANE_EVIDENCE_REMOTE:-}"; want_remote=0
for arg in "$@"; do
  if [ "$want_remote" = 1 ]; then REMOTE="$arg"; want_remote=0; continue; fi
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --json) JSON=1 ;;
    --remote) want_remote=1 ;;
    --remote=*) REMOTE="${arg#--remote=}" ;;
    --*) echo "!! unknown option: $arg" >&2; usage >&2; exit 2 ;;
    *) POS+=("$arg") ;;
  esac
done
[ "$want_remote" = 0 ] || { echo "!! --remote needs a git url" >&2; exit 2; }
[ "${#POS[@]}" -ge 1 ] || { usage >&2; exit 2; }
T="${POS[0]}"
D="${POS[1]:-$(date +%d%m%Y)}"
# the name lands in paths, sed programs and JSON: keep it to a safe alphabet; the date must be DDMMYYYY (START.md §3)
printf '%s' "$T" | grep -Eq '^[A-Za-z0-9_-]+$' || { echo "!! TargetName must match [A-Za-z0-9_-]+ (got: $T)" >&2; exit 2; }
printf '%s' "$D" | grep -Eq '^[0-9]{8}$' || { echo "!! date must be DDMMYYYY (got: $D)" >&2; exit 2; }
printf '%s' "$REMOTE" | grep -Eq "[\"'\\\\]" && { echo "!! remote url contains a quote or backslash" >&2; exit 2; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG_ROOT="${SANE_ENGAGEMENT_ROOT:-$REPO/BugBountyTarget}"
ENG="$ENG_ROOT/${T}_${D}"
LOWER="$(printf '%s' "$T" | tr '[:upper:]' '[:lower:]')"

[ -d "$ENG" ] && { echo "!! $ENG already exists — resume it: python3 scripts/state.py \"$ENG\"" >&2; exit 1; }
[ -d "$REPO/BugBountyTarget/_TEMPLATE" ] || { echo "!! BugBountyTarget/_TEMPLATE missing" >&2; exit 2; }
[ -f "$REPO/checklist.csv" ] || { echo "!! checklist.csv missing — run: python3 scripts/build-checklist.py" >&2; exit 2; }
[ -f "$REPO/.claude/hooks/_lib.sh" ] || { echo "!! .claude/hooks/_lib.sh missing (forbidden-artefact list)" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "!! python3 is required" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "!! git is required (the engagement folder is its own repository)" >&2; exit 2; }
# the ONE forbidden-artefact list: FORBIDDEN_RE / FORBIDDEN_DIR_RE / CRED_RE
. "$REPO/.claude/hooks/_lib.sh"

# the methodology origin is public: it is never a valid evidence remote
MORIGIN="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
if [ -n "$REMOTE" ] && [ -n "$MORIGIN" ] && [ "$REMOTE" = "$MORIGIN" ]; then
  echo "!! the evidence remote must be a PRIVATE repository, not the methodology origin ($MORIGIN)" >&2; exit 2
fi

mkdir -p "$ENG_ROOT"
cp -R "$REPO/BugBountyTarget/_TEMPLATE" "$ENG"
cp "$REPO/checklist.csv" "$ENG/checklist-status.csv"

# portable in-place substitution (GNU and BSD sed differ on -i); fails loudly when the file is missing
subst() { # subst <file> <sed-expr>
  local f="$1" e="$2" tmp
  [ -f "$f" ] || { echo "!! template file missing: $f" >&2; return 1; }
  tmp="$(mktemp)"; sed "$e" "$f" > "$tmp" && mv "$tmp" "$f"
}
subst "$ENG/report/assessment-status.md"    "s|<Target>_<DDMMYYYY>|${T}_${D}|g; s|<target>|${LOWER}|g"
subst "$ENG/report/findings-index.md"       "s|<target>|${T}|g"
subst "$ENG/final/submission-checklist.md"  "s|<target>|${T}|g"
# <package>, <version>, <v>, <n> stay: they are known only after P2 (engagement.json.target is the source)

TODAY="$(date +%Y-%m-%d)"
REMOTE_JSON=null; [ -n "$REMOTE" ] && REMOTE_JSON="\"$REMOTE\""
cat > "$ENG/engagement.json" <<JSON
{
  "schema": 1,
  "target": { "name": "${T}", "package": "", "version": "", "versionCode": "", "targetSdk": null, "minSdk": null, "framework": "", "ota": "" },
  "authorisation": { "basis": "", "scope": "", "programme_url": "", "excluded": [] },
  "accounts": { "a": "", "b": "" },
  "evidence_remote": ${REMOTE_JSON},
  "lab": { "mode": null, "tls_intercept": null, "frida": null, "root": null, "lockscreen": null, "positive_controls": null },
  "phase": "P0",
  "gates": { "P0": false, "P1": false, "P2": false, "P3": false, "P4": false, "P5": false, "P6": false, "P7": false, "P8": false, "P9": false },
  "domains_in_scope": "all",
  "domains_na": null,
  "domains_decided": [],
  "domains_applicable": {},
  "blockers": [],
  "created": "${TODAY}",
  "updated": "${TODAY}"
}
JSON

# ---- the evidence repo: .gitignore derived from FORBIDDEN_RE, the pre-commit guard, the first commit ----
EXTS="$(printf '%s' "$FORBIDDEN_RE" | sed -E 's/^\\\.\(//; s/\)\$$//' | tr '|' ' ')"
{
  echo "# ${T}_${D} — evidence repository (generated by scripts/new-engagement.sh; mirrors .claude/hooks/_lib.sh FORBIDDEN_RE)."
  echo "# Text evidence, hashes, logs, sanitised captures and small videos are committed. Binaries, keys, raw captures never."
  for x in $EXTS; do echo "*.$x"; done
  cat <<'GI'
# regenerable, oversized or secret-bearing scratch
apk/*
!apk/.gitkeep
!apk/versions.txt
decompiled/
jadx_out/
apktool_out/
secrets/
secrets.csv
sensitive/
state-snapshot.json
logs/tmp/
# built PoC output (the signed APK is attached to the submission, never committed; docs/04 §7)
pocs/*/build/
# OS / tooling noise
.DS_Store
__pycache__/
*.pyc
GI
} > "$ENG/.gitignore"

git init -q "$ENG"
# a commit needs an identity; do not touch the operator's global config
git -C "$ENG" config user.email >/dev/null 2>&1 || { git -C "$ENG" config user.name "sane_android"; git -C "$ENG" config user.email "engagement@localhost"; }
{
  printf '#!/usr/bin/env bash\n# evidence-repo pre-commit guard — generated by scripts/new-engagement.sh from .claude/hooks/_lib.sh\n# (same rules as .claude/hooks/pre-commit-check.sh). Regenerate by re-running new-engagement.sh on a fresh folder.\n'
  printf "FORBIDDEN_RE='%s'\nFORBIDDEN_DIR_RE='%s'\nCRED_RE='%s'\nCRED_ALLOW_RE='%s'\n" "$FORBIDDEN_RE" "$FORBIDDEN_DIR_RE" "$CRED_RE" "$CRED_ALLOW_RE"
  cat <<'HOOK'
rc=0
bad="$(git diff --cached --name-only -z 2>/dev/null | tr '\0' '\n' | grep -Ei "$FORBIDDEN_RE|$FORBIDDEN_DIR_RE" | grep -v '/\.gitkeep$' || true)"
[ -n "$bad" ] && { echo "pre-commit: forbidden artefacts staged (binaries, keys, decompiled trees, secrets):"; echo "$bad"; rc=1; }
hits="$(git diff --cached -U0 2>/dev/null | grep -E '^\+' | grep -v '^+++' | grep -E "$CRED_RE" | grep -Ev "$CRED_ALLOW_RE" | head -3 || true)"
[ -n "$hits" ] && { echo "pre-commit: live-looking credential or JWT in the staged diff — redact it (<redacted>, keep the shape):"; echo "$hits" | cut -c1-120; rc=1; }
big="$(git diff --cached --name-only -z 2>/dev/null | tr '\0' '\n' | while IFS= read -r f; do [ -n "$f" ] && [ -f "$f" ] && [ "$(wc -c < "$f")" -gt 5242880 ] && echo "$f"; done)"
[ -n "$big" ] && { echo "pre-commit: files over 5 MB staged:"; echo "$big"; rc=1; }
exit $rc
HOOK
} > "$ENG/.git/hooks/pre-commit"
chmod +x "$ENG/.git/hooks/pre-commit"
git -C "$ENG" add -A
git -C "$ENG" commit -q -m "engage: ${T} P0"
PUSHED=""
if [ -n "$REMOTE" ]; then
  git -C "$ENG" remote add origin "$REMOTE"
  if git -C "$ENG" push -q -u origin HEAD >/dev/null 2>&1; then PUSHED="pushed to $REMOTE"; else PUSHED="origin set to $REMOTE but the first push FAILED (no network or access?) — push before you stop"; fi
fi

if [ -n "${SANE_LOCAL_MIRROR:-}" ]; then
  mkdir -p "$SANE_LOCAL_MIRROR/$LOWER"
  cp -R "$ENG/." "$SANE_LOCAL_MIRROR/$LOWER/"
  [ "$JSON" = 1 ] || echo "[+] local mirror: $SANE_LOCAL_MIRROR/$LOWER"
fi

# count rows with the csv module (a quoted field may legitimately contain a newline; wc -l would miscount)
ROWS="$(python3 -c 'import csv,sys; print(sum(1 for _ in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8"))))' "$ENG/checklist-status.csv")"

if [ "$JSON" = 1 ]; then
  printf '{"engagement": "%s", "name": "%s", "date": "%s", "tracker": "%s", "tracker_rows": %s, "phase": "P0", "created": "%s", "evidence_repo": true, "evidence_remote": %s, "pushed": %s, "next": "python3 scripts/state.py %s"}\n' \
    "$ENG" "$T" "$D" "$ENG/checklist-status.csv" "$ROWS" "$TODAY" "$REMOTE_JSON" "$([ -n "$REMOTE" ] && [ "${PUSHED#pushed}" != "$PUSHED" ] && echo true || echo false)" "$ENG"
  exit 0
fi
cat <<TXT

[+] engagement created: $ENG
    checklist-status.csv seeded with $ROWS rows, all completed=false
    engagement.json created (phase P0, no gates passed)
    placeholders substituted in report/assessment-status.md, report/findings-index.md, final/submission-checklist.md
    evidence repo initialised (git init, .gitignore, pre-commit guard, first commit "engage: ${T} P0")
    evidence remote: ${PUSHED:-NONE — $NO_REMOTE_MSG}

NEXT
  1. Fill engagement.json: target identity, authorisation basis, scope, accounts (START.md §6).
     domains_na starts null (= applicability probes not run); scripts/mark.py <eng> Dnn applies|n/a --note "<probe evidence>"
     records each P3 decision (domains_decided / domains_applicable / domains_na); domains_na {} means "all apply".
  2. Fill the header of report/assessment-status.md.
  3. export SANE_ENGAGEMENT="$ENG"; python3 scripts/state.py "\$SANE_ENGAGEMENT"   # the resume card — run it at the start of every session
  4. Work P0 → P9 per START.md. Settle rows only through scripts/mark.py. After every batch:
     git -C "\$SANE_ENGAGEMENT" add -A && git -C "\$SANE_ENGAGEMENT" commit -m "<Target> <phase>: <what was settled>"
     (the PostToolUse hook pushes to the evidence remote; the methodology repo is public and never receives evidence)
engagement: $ENG
TXT
