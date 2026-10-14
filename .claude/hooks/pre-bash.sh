#!/usr/bin/env bash
# PreToolUse(Bash): refuse the commands that would destroy evidence or leak artefacts. Exit 2 = block, stderr goes to the model.
# Evidence lives in the engagement's own git repository ($E); the methodology repo is public and never tracks it.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
HOOK_INPUT="$(cat 2>/dev/null || true)"
CMD="$(json_get tool_input.command)"
[ -z "$CMD" ] && exit 0
cd "$REPO" || exit 0
deny() { echo "BLOCKED by .claude/hooks/pre-bash.sh: $1" >&2; exit 2; }
# quoted strings (commit messages, notes) are data, not commands
CMD_NQ="$(printf '%s' "$CMD" | sed -E "s/\"[^\"]*\"//g; s/'[^']*'//g")"
# segments that run on the device (adb [-s serial] shell …) are not file operations on this host
CMD_HOST="$(printf '%s' "$CMD" | sed -E 's/adb([[:space:]]+-[sdetHP][[:space:]]*[^[:space:]]+)*[[:space:]]+shell[^;&|]*//g')"

# destructive git on the methodology or the evidence: the force flag must be a whole token
echo "$CMD_NQ" | grep -Eq "(^|[;&| ])git${GIT_OPTS}[[:space:]]+(push[^;&|]*[[:space:]](--force(-with-lease)?|-f)([[:space:]]|$)|reset[[:space:]]+--hard|clean[[:space:]]+-[a-zA-Z]*f|checkout[[:space:]]+--[[:space:]]+\.|branch[[:space:]]+-D)" \
  && deny "destructive git ($CMD). Evidence and methodology are append-only; use a new commit."

# recursive delete of repository-rooted paths (relative or under $REPO); regenerable engagement scratch is allowed
if echo "$CMD_HOST" | grep -Eq '(^|[;&| ])rm[[:space:]]+-[a-zA-Z]*[rR]'; then
  targets="$(printf '%s\n' "$CMD_HOST" | tr ';&|' '\n\n\n' | grep -E '^[[:space:]]*rm[[:space:]]+-[a-zA-Z]*[rR]' | sed -E 's/^[[:space:]]*rm([[:space:]]+-[a-zA-Z-]+)*//')"
  for t in $targets; do
    t="${t#\"}"; t="${t%\"}"; t="${t#\'}"; t="${t%\'}"; t="${t#$REPO/}"; t="${t#./}"; t="${t%/}"
    case "$t" in
      -*|'') continue ;;
      BugBountyTarget/*/decompiled|BugBountyTarget/*/decompiled/*|BugBountyTarget/*/apk/*|BugBountyTarget/*/secrets|BugBountyTarget/*/secrets/*|BugBountyTarget/*/jadx_out*|BugBountyTarget/*/apktool_out*|BugBountyTarget/*/logs/tmp*|\$E/decompiled*|\${E}/decompiled*|\$E/apk/*|\${E}/apk/*|\$E/secrets*|\${E}/secrets*) continue ;;
      checklist|checklist/*|docs|docs/*|json|json/*|cards|cards/*|scripts|scripts/*|tools|tools/*|frida|frida/*|data|data/*|templates|templates/*|prompts|prompts/*|loops|loops/*|.claude|.claude/*|.github|.github/*|BugBountyTarget|BugBountyTarget/*|\$E|\${E}|\$SANE_ENGAGEMENT|\${SANE_ENGAGEMENT})
        deny "recursive delete inside the repository or the engagement ($t). Evidence is append-only; only decompiled/, apk/, secrets/ and logs/tmp are regenerable scratch." ;;
    esac
  done
fi

# staging or committing forbidden artefacts / live-looking credentials — in the methodology repo and in the evidence repo
if echo "$CMD_NQ" | grep -Eq "(^|[;&| ])git${GIT_OPTS}[[:space:]]+(commit|add)([[:space:]]|$)"; then
  E="$(active_engagement)"
  is_add=0; is_commit=0
  echo "$CMD_NQ" | grep -Eq "(^|[;&| ])git${GIT_OPTS}[[:space:]]+add([[:space:]]|$)" && is_add=1
  echo "$CMD_NQ" | grep -Eq "(^|[;&| ])git${GIT_OPTS}[[:space:]]+commit([[:space:]]|$)" && is_commit=1
  # defence in depth over .gitignore: evidence is never staged in the (public) methodology repository
  if [ "$is_add" = 1 ] && ! echo "$CMD_NQ" | grep -Eq '(^|[;&| ])git[[:space:]]+-C' \
     && echo "$CMD" | grep -Eq 'git[[:space:]]+add[^;&|]*(BugBountyTarget/[^_[:space:]/"]+_[0-9]|\$\{?E\}?|\$\{?SANE_ENGAGEMENT\}?)'; then
    deny "evidence is never staged in the methodology repository (it is public). The engagement folder is its own git repository: git -C \"\$E\" add -A && git -C \"\$E\" commit -m '<Target> <phase>: <what was settled>'  (BugBountyTarget/README.md)"
  fi
  repos="$REPO"
  is_evidence_repo "$E" && repos="$repos
$E"
  printf '%s\n' "$repos" | while IFS= read -r r; do
    [ -n "$r" ] || continue
    kind=""; [ "$r" = "$REPO" ] && kind=methodology
    # a broad add (-A, --all, -u, ., a directory, $E) must not sweep in a forbidden file that .gitignore missed
    if [ "$is_add" = 1 ] && echo "$CMD" | grep -Eq "git${GIT_OPTS}[[:space:]]+add([[:space:]]+-[A-Za-z-]+)*[[:space:]]+(-A|--all|-u|--update|\.([[:space:]]|$)|BugBountyTarget|\"?\\\$\{?E\}?)"; then
      bad="$(git -C "$r" status --porcelain -z 2>/dev/null | tr '\0' '\n' | cut -c4- | grep -Ei "$FORBIDDEN_RE|$FORBIDDEN_DIR_RE" || true)"
      [ -n "$bad" ] && deny "forbidden artefacts in the working tree of $r would be staged:
$bad
Add them to .gitignore or delete them, then stage again. Hashes and metadata go in apk/versions.txt; binaries, decompiled trees and secrets never do."
    fi
    if [ "$is_commit" = 1 ]; then
      problems="$(staged_problems "$r" "$kind")" || deny "$problems
git -C $r restore --staged <file> (or redact: replace the value with <redacted>, keep the shape), then commit."
    fi
  done || exit 2
fi
exit 0
