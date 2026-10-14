#!/usr/bin/env bash
# shared helpers for the hooks. POSIX-portable bash (3.2 is enough); JSON via python3 (jq is not assumed).
REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
# engagements live under BugBountyTarget/ by default; SANE_ENGAGEMENT_ROOT points the tooling elsewhere
ENG_ROOT="${SANE_ENGAGEMENT_ROOT:-$REPO/BugBountyTarget}"
json_get() { # json_get <key.path> ; reads JSON from $HOOK_INPUT
  python3 -c 'import json,sys
d=json.loads(sys.argv[1] or "{}")
for k in sys.argv[2].split("."):
    d=d.get(k,{}) if isinstance(d,dict) else {}
print(d if isinstance(d,str) else ("" if d=={} else json.dumps(d)))' "$HOOK_INPUT" "$1" 2>/dev/null
}
# the active engagement: $SANE_ENGAGEMENT, else the most recently updated $ENG_ROOT/*_*/
active_engagement() {
  if [ -n "${SANE_ENGAGEMENT:-}" ] && [ -d "$SANE_ENGAGEMENT" ]; then echo "$SANE_ENGAGEMENT"; return; fi
  local best="" bt=0 d t
  for d in "$ENG_ROOT"/*_*/; do
    [ -d "$d" ] || continue; case "$d" in */_TEMPLATE/) continue;; esac
    if [ -f "$d/engagement.json" ]; then
      t=$(python3 -c 'import os,sys; print(int(os.path.getmtime(sys.argv[1])))' "$d/engagement.json" 2>/dev/null || echo 0)
    else t=0; fi
    if [ "$t" -ge "$bt" ]; then bt=$t; best="${d%/}"; fi
  done
  echo "$best"
}
# Every engagement folder is its own git repository (the evidence repo); the methodology repo never tracks it.
eng_git() { git -C "$E" "$@"; }                       # run git inside the active engagement ($E must be set)
is_evidence_repo() { [ -n "${1:-}" ] && [ -d "$1/.git" ]; }
# the private evidence remote: SANE_EVIDENCE_REMOTE, else engagement.json.evidence_remote, else the repo's origin
evidence_remote() { # evidence_remote <engagement>
  local r=""
  if [ -n "${SANE_EVIDENCE_REMOTE:-}" ]; then echo "$SANE_EVIDENCE_REMOTE"; return; fi
  r="$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get("evidence_remote"); print(v or "")' "$1/engagement.json" 2>/dev/null || true)"
  [ -n "$r" ] && { echo "$r"; return; }
  git -C "$1" remote get-url origin 2>/dev/null || true
}
# the methodology repo's own remote — evidence must never be pushed there (the repo is public)
methodology_origin() { git -C "$REPO" remote get-url origin 2>/dev/null || true; }
NO_REMOTE_MSG='no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>'
# git invoked with global options (git -C "$E" commit, git -c x=y add): use as "git${GIT_OPTS}[[:space:]]+commit"
GIT_OPTS='([[:space:]]+(-[A-Za-z]|--[a-z-]+)([[:space:]=][^[:space:]]+)?)*'
# the ONE forbidden-artefact list: .gitignore (methodology + evidence repo), pre-bash, pre-commit-check, hygiene.yml all derive from it
FORBIDDEN_RE='\.(apk|aab|apks|xapk|dex|odex|oat|so|jks|keystore|p12|pfx|pem|key|crt|der|har|pcap|pcapng|smali)$'
FORBIDDEN_DIR_RE='(^|/)(jadx_out|apktool_out|decompiled|secrets|sensitive)/|(^|/)secrets\.csv$'
CRED_RE='AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|Authorization: Bearer [A-Za-z0-9._-]{30,}'
CRED_ALLOW_RE='<redacted>|EXAMPLE|hygiene:allow'
# staged forbidden artefacts / live-looking credentials in one repo; prints the problem, returns 1 when dirty
staged_problems() { # staged_problems <repo-dir> [methodology]
  local r="$1" kind="${2:-}" bad hits
  bad="$(git -C "$r" diff --cached --name-only -z 2>/dev/null | tr '\0' '\n' | grep -Ei "$FORBIDDEN_RE|$FORBIDDEN_DIR_RE" || true)"
  if [ "$kind" = methodology ]; then
    # the methodology legitimately contains credential SHAPES as detection patterns: exclude by path, never by content
    hits="$(git -C "$r" diff --cached -U0 -- . ':(exclude)docs' ':(exclude)checklist' ':(exclude)cards' ':(exclude)json' ':(exclude)CHECKLIST.md' ':(exclude)MASTER-CHECKLIST.md' ':(exclude)checklist.csv' 2>/dev/null | grep -E '^\+' | grep -v '^+++' | grep -E "$CRED_RE" | grep -Ev "$CRED_ALLOW_RE" | head -3 || true)"
  else
    hits="$(git -C "$r" diff --cached -U0 2>/dev/null | grep -E '^\+' | grep -v '^+++' | grep -E "$CRED_RE" | grep -Ev "$CRED_ALLOW_RE" | head -3 || true)"
  fi
  [ -n "$bad" ] && printf 'forbidden artefacts staged in %s:\n%s\n' "$r" "$bad"
  [ -n "$hits" ] && printf 'live-looking credential or JWT in the staged diff of %s:\n%s\n' "$r" "$(echo "$hits" | cut -c1-120)"
  [ -z "$bad" ] && [ -z "$hits" ]
}
