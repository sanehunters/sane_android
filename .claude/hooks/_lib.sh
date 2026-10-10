#!/usr/bin/env bash
# shared helpers for the hooks. POSIX-portable bash; JSON via python3 (jq is not assumed).
REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
json_get() { # json_get <key.path> ; reads JSON from $HOOK_INPUT
  python3 -c 'import json,sys
d=json.loads(sys.argv[1] or "{}")
for k in sys.argv[2].split("."):
    d=d.get(k,{}) if isinstance(d,dict) else {}
print(d if isinstance(d,str) else ("" if d=={} else json.dumps(d)))' "$HOOK_INPUT" "$1" 2>/dev/null
}
# the active engagement: $SANE_ENGAGEMENT, else the most recently updated BugBountyTarget/*_*/
active_engagement() {
  if [ -n "${SANE_ENGAGEMENT:-}" ] && [ -d "$SANE_ENGAGEMENT" ]; then echo "$SANE_ENGAGEMENT"; return; fi
  local best="" bt=0 d t
  for d in "$REPO"/BugBountyTarget/*_*/; do
    [ -d "$d" ] || continue; case "$d" in */_TEMPLATE/) continue;; esac
    if [ -f "$d/engagement.json" ]; then
      t=$(python3 -c 'import os,sys; print(int(os.path.getmtime(sys.argv[1])))' "$d/engagement.json" 2>/dev/null || echo 0)
    else t=0; fi
    if [ "$t" -ge "$bt" ]; then bt=$t; best="${d%/}"; fi
  done
  echo "$best"
}
FORBIDDEN_RE='\.(apk|aab|apks|xapk|dex|odex|oat|so|jks|keystore|p12|pfx|pem|key|har|pcap|pcapng)$'
CRED_RE='AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}'
