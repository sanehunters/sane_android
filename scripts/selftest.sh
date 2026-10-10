#!/usr/bin/env bash
# selftest.sh — prove the machinery works end to end on a scratch engagement. Runs in CI and before a release.
# Exit 0 = everything the methodology relies on is operable on this host without a device.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 2
fail=0
step() { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok   %s\n' "$1"; }
bad()  { printf '   FAIL %s\n' "$1"; fail=1; }
expect_fail() { if "$@" >/dev/null 2>&1; then bad "expected failure: $*"; else ok "rejected as expected: ${*: -3}"; fi; }
expect_ok()   { if "$@" >/dev/null 2>&1; then ok "$*"; else bad "$*"; fi; }

E="BugBountyTarget/Selftest_$(date +%d%m%Y)"
cleanup() { rm -rf "$E"; }
trap cleanup EXIT
rm -rf "$E"

step "syntax"
for f in scripts/*.sh tools/*.sh .claude/hooks/*.sh; do bash -n "$f" && ok "bash -n $f" || bad "bash -n $f"; done
for f in scripts/*.py tools/*.py; do [ -f "$f" ] && { python3 -m py_compile "$f" && ok "py_compile $f" || bad "py_compile $f"; }; done

step "checklist integrity"
expect_ok python3 scripts/lint-checklist.py
expect_ok python3 scripts/build-checklist.py --check
expect_ok python3 scripts/item.py D10-004
expect_ok python3 scripts/item.py --grep JavascriptInterface
[ -f cards/D10.md ] && ok "cards exist" || bad "cards missing"
[ -f json/index.json ] && ok "json index exists" || bad "json index missing"

step "engagement lifecycle"
expect_ok scripts/new-engagement.sh Selftest
[ -f "$E/engagement.json" ] && ok "engagement.json created" || bad "engagement.json missing"
[ -f "$E/checklist-status.csv" ] && ok "tracker seeded" || bad "tracker missing"
[ -f "$E/report/assessment-status.md" ] && ok "assessment-status.md present in template" || bad "assessment-status.md missing"
expect_fail python3 scripts/mark.py "$E" D10-004 ruled-out --note "found nothing"
expect_ok   python3 scripts/mark.py "$E" D10-004 ruled-out --note "RouterActivity.java:88 exact scheme+host allow-list; every loadUrl call site routes through validate() (logs/D10-004.txt)"
expect_fail python3 scripts/mark.py "$E" D13-020 blocked --note "later"
expect_ok   python3 scripts/mark.py "$E" D13-020 blocked --note "needs: second account"
expect_fail python3 scripts/mark.py "$E" D19 n/a --note "no"
expect_ok   python3 scripts/mark.py "$E" D19 n/a --note "native app: no Flutter/RN/Hermes/Xamarin/Unity/Cordova artefacts in the APK (tools/01 framework detection)"
expect_fail python3 scripts/mark.py "$E" D10-005 finding --note "juicy"
expect_ok   python3 scripts/mark.py "$E" D10-005 finding --note "H-001: bridge method returns session token" --evidence logs/D10-005.txt
expect_fail python3 scripts/gate.py "$E" p0
expect_ok   python3 scripts/gate.py "$E" --all
expect_ok   python3 scripts/state.py "$E"
expect_ok   python3 scripts/state.py "$E" --json
expect_ok   python3 scripts/coverage.py "$E/checklist-status.csv" --brief
[ -f scripts/next.py ]  && expect_ok python3 scripts/next.py "$E"
[ -f scripts/scope.py ] && expect_ok python3 scripts/scope.py "$E"

step "hooks"
export CLAUDE_PROJECT_DIR="$REPO" SANE_ENGAGEMENT="$REPO/$E"
echo '{"tool_input":{"command":"git push --force origin main"}}' | bash .claude/hooks/pre-bash.sh >/dev/null 2>&1 && bad "pre-bash did not block force push" || ok "pre-bash blocks force push"
echo '{"tool_input":{"command":"ls"}}' | bash .claude/hooks/pre-bash.sh >/dev/null 2>&1 && ok "pre-bash allows ls" || bad "pre-bash blocked ls"
out="$(echo '{}' | bash .claude/hooks/session-start.sh 2>/dev/null)"; printf '%s' "$out" | grep -q "ENGAGEMENT" && ok "session-start prints the resume card" || bad "session-start card missing"
echo '{"stop_hook_active":true}' | bash .claude/hooks/stop-guard.sh >/dev/null 2>&1 && ok "stop-guard yields on second attempt" || bad "stop-guard loops"
out="$(echo '{"tool_input":{"command":"adb shell am start -n a/.B"}}' | bash .claude/hooks/post-bash.sh 2>/dev/null)"; printf '%s' "$out" | grep -q "AM-03" && ok "post-bash reminds about adb" || bad "post-bash reminder missing"

step "tools without a device"
for t in tools/*.sh; do bash "$t" --help >/dev/null 2>&1; rc=$?; [ $rc -le 2 ] && ok "$t --help (rc=$rc)" || bad "$t --help rc=$rc"; done
for t in tools/*.py; do [ -f "$t" ] && { python3 "$t" --help >/dev/null 2>&1; rc=$?; [ $rc -le 2 ] && ok "$t --help (rc=$rc)" || bad "$t --help rc=$rc"; }; done
[ -f frida/run.sh ] && { bash frida/run.sh --help >/dev/null 2>&1; rc=$?; [ $rc -le 2 ] && ok "frida/run.sh --help" || bad "frida/run.sh --help rc=$rc"; }
bash scripts/doctor.sh --brief >/dev/null && ok "doctor --brief" || bad "doctor --brief"

printf '\n%s\n' "$([ $fail = 0 ] && echo 'SELFTEST PASSED' || echo 'SELFTEST FAILED')"
exit $fail
