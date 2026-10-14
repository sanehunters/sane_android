#!/usr/bin/env bash
# selftest.sh — prove the machinery works end to end on a scratch engagement. Runs in CI and before a release.
# Exit 0 = everything the methodology relies on is operable on this host without a device.
# Covers: syntax, lint + deterministic build check, item.py, engagement lifecycle (mark.py incl. whole-domain
# n/a / reopen / --show / --partial, gate.py --all and --pass, state.py, next.py, coverage.py --merge with a
# checklist partial carrying H-Dnn-NN and an inventory partial), inventory.py on a fixture manifest, hooks,
# tools --help (rc 0), doctor.sh (non-empty output on bash 3.2 and 5), and the Claude Code layer: settings.json,
# .claude/agents/*.md and .claude/skills frontmatter (documented fields only), .claude/workflows/*.js (meta, agent
# types, phases, no clock/randomness, node --check when node exists). `selftest.sh --claude-layer` runs that step alone.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 2
fail=0
step() { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok   %s\n' "$1"; }
bad()  { printf '   FAIL %s\n' "$1"; fail=1; }
expect_fail() { if "$@" >/dev/null 2>&1; then bad "expected failure: $*"; else ok "rejected as expected: ${*: -3}"; fi; }
expect_ok()   { if "$@" >/dev/null 2>&1; then ok "$*"; else bad "$*"; fi; }
jq_() { python3 -c 'import json,sys; e=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"e": e}))' "$@" 2>/dev/null; }

claude_layer() {
  step "claude code layer (settings, agents, skills, workflows)"
  python3 - <<'PY' || fail=1
import glob, json, os, re, sys
rc = 0
def ok(m): print(f"   ok   {m}")
def no(m):
    global rc; rc = 1; print(f"   FAIL {m}")
def front(path):                      # top-level keys of a YAML frontmatter block
    t = open(path, encoding="utf-8").read()
    m = re.match(r"---\n(.*?)\n---\n", t, re.S)
    if not m: return None
    return {k: v.strip().strip("'\"") for k, v in re.findall(r"^([A-Za-z][A-Za-z0-9_-]*):[ \t]*(.*)$", m.group(1), re.M)}
EFFORT = {"low", "medium", "high", "xhigh"}
TARGET = {"claude-opus-5-5", "claude-opus-5"}            # CLAUDE.md: the repo targets Opus 5.5, Opus 5 as fallback
S = ".claude/settings.json"
try:
    s = json.load(open(S, encoding="utf-8")); ok(f"{S} is valid JSON")
except Exception as e:
    s = {}; no(f"{S} is not valid JSON: {e}")
if s.get("model") in TARGET: ok(f'{S} "model" = {s["model"]}')
else: no(f'{S} "model" must be one of {sorted(TARGET)} (got {s.get("model")!r})')
fb = s.get("fallbackModel")
if fb is not None and not (isinstance(fb, list) and 0 < len(fb) <= 3 and all(isinstance(x, str) and x for x in fb)):
    no(f'{S} "fallbackModel" must be a list of 1-3 model ids')
if "effortLevel" in s and s["effortLevel"] not in EFFORT: no(f'{S} "effortLevel" must be one of {sorted(EFFORT)}')
for mid, ms in (s.get("modelSettings") or {}).items():
    if not isinstance(ms, dict) or ms.get("effortLevel", "high") not in EFFORT: no(f'{S} modelSettings.{mid}.effortLevel invalid')
if s.get("ultracode"): no(f'{S} sets "ultracode": that cost is the operator\'s opt-in (docs/10), never the repo default')
hooks = s.get("hooks") or {}
for ev in ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "PreCompact"):
    cmds = [h.get("command", "") for g in hooks.get(ev, []) for h in g.get("hooks", [])]
    scripts = [m for c in cmds for m in re.findall(r"\.claude/hooks/[\w.-]+\.sh", c)]
    if not scripts: no(f"{S} hooks.{ev} does not run a .claude/hooks script")
    elif not all(os.path.isfile(x) for x in scripts): no(f"{S} hooks.{ev} names a missing script: {scripts}")

AGENT_KEYS = {"name", "description", "tools", "disallowedTools", "model", "permissionMode", "maxTurns", "skills",
              "mcpServers", "hooks", "memory", "background", "omitClaudeMd", "effort", "isolation", "color", "initialPrompt"}
COLORS = {"red", "blue", "green", "yellow", "purple", "orange", "pink", "cyan"}
REQUIRED_AGENTS = {"domain-worker", "verify-reproduce", "verify-guard", "verify-triage", "chain-lead",
                   "evidence-reporter", "checklist-maintainer"}
agents, ap = {}, []
for f in sorted(glob.glob(".claude/agents/*.md")):
    fm, stem = front(f), os.path.basename(f)[:-3]
    if fm is None: ap.append(f"{f}: no frontmatter"); continue
    agents[stem] = fm
    probs = [f"unknown field {k}" for k in fm if k not in AGENT_KEYS]
    probs += [f"missing {k}" for k in ("name", "description") if not fm.get(k)]
    if fm.get("name") and fm["name"] != stem: probs.append(f"name {fm['name']} != file name")
    if "model" in fm and fm["model"] not in TARGET | {"inherit", "opus"}: probs.append(f"model {fm['model']} is not Opus 5.5 / Opus 5 / inherit")
    if "effort" in fm and fm["effort"] not in EFFORT | {"max"}: probs.append(f"effort {fm['effort']}")
    if "color" in fm and fm["color"] not in COLORS: probs.append(f"color {fm['color']}")
    if "isolation" in fm and fm["isolation"] != "worktree": probs.append("isolation must be worktree")
    if probs: ap.append(f"{f}: {'; '.join(probs)}")
missing = sorted(REQUIRED_AGENTS - set(agents))
if missing: ap.append(f".claude/agents: missing {' '.join(missing)} (CLAUDE.md subagent table)")
for x in ap: no(x)
if not ap: ok(f".claude/agents: {len(agents)} agents, documented frontmatter only")

SKILL_KEYS = {"name", "description", "when_to_use", "argument-hint", "arguments", "disable-model-invocation",
              "user-invocable", "allowed-tools", "disallowed-tools", "model", "effort", "context", "agent", "background",
              "hooks", "paths", "shell"}
skills, sp = set(), []
for f in sorted(glob.glob(".claude/skills/*/SKILL.md")):
    fm = front(f) or {}; skills.add(fm.get("name") or os.path.basename(os.path.dirname(f)))
    probs = [f"unknown field {k}" for k in fm if k not in SKILL_KEYS]
    if fm.get("context") not in (None, "fork"): probs.append("context must be fork")
    if fm.get("agent") and fm["agent"] not in {"Explore", "Plan", "general-purpose"} | set(agents): probs.append(f"agent {fm['agent']} does not exist")
    if probs: sp.append(f"{f}: {'; '.join(probs)}")
for x in sp: no(x)
if not sp: ok(f".claude/skills: {len(skills)} skills, documented frontmatter only")

wfs = sorted(glob.glob(".claude/workflows/*.js"))
if not wfs: no(".claude/workflows: no saved workflow")
for f in wfs:
    t, stem, probs = open(f, encoding="utf-8").read(), os.path.basename(f)[:-3], []
    m = re.match(r"\s*export const meta = (\{.*?\n\})\n", t, re.S)
    if not m: no(f"{f}: the first statement must be `export const meta = {{ … }}`"); continue
    mt = m.group(1)
    if "`" in mt or "${" in mt or re.search(r"\b[A-Za-z_]\w*\(", mt): probs.append("meta is not a plain literal")
    name = re.search(r"^\s*name:\s*'([^']+)'", mt, re.M)
    if not name or name.group(1) != stem: probs.append("meta.name must equal the file name (it is the /command)")
    if not re.search(r"^\s*description:\s*'", mt, re.M): probs.append("meta.description missing")
    if name and name.group(1) in skills: probs.append(f"/{name.group(1)} is also a skill")
    titles = set(re.findall(r"title:\s*'([^']+)'", mt))
    used = set(re.findall(r"\bphase\(\s*'([^']+)'", t)) | set(re.findall(r"\bphase:\s*'([^']+)'\s*[,}]", t))
    if used - titles: probs.append(f"phase(s) not in meta.phases: {sorted(used - titles)}")
    for bad in (r"Date\.now\(", r"Math\.random\(", r"new Date\(\s*\)", r"\bimport\(", r"\brequire\("):
        if re.search(bad, t): probs.append(f"uses {bad.replace(chr(92), '')} (breaks resume / not available)")
    for at in re.findall(r"agentType:\s*([^,}\n]+)", t):
        lit = re.fullmatch(r"'([\w-]+)'", at.strip())
        if not lit: probs.append(f"agentType must be a string literal: {at.strip()}")
        elif lit.group(1) not in agents and lit.group(1) != "general-purpose": probs.append(f"agentType {lit.group(1)} has no .claude/agents file")
    if not re.search(r"Authorisation: ", t): probs.append("no 'Authorisation: ' line in the agent briefs")
    if probs: no(f"{f}: {'; '.join(probs)}")
    else: ok(f"{f}: meta, phases, agent types")
sys.exit(rc)
PY
  if command -v node >/dev/null 2>&1; then
    for f in .claude/workflows/*.js; do
      [ -f "$f" ] || continue
      d="$(mktemp -d "${TMPDIR:-/tmp}/wf.XXXXXX")" || { bad "mktemp"; continue; }
      { echo 'async function __w(){'; sed 's/^export const meta/const meta/' "$f"; echo '}'; } > "$d/w.js"
      if node --check "$d/w.js" >/dev/null 2>&1; then ok "node --check $f"; else bad "node --check $f"; fi
      rm -f "$d/w.js"; rmdir "$d"
    done
  else
    printf '   note node is not installed: the workflow syntax check was skipped (the structural checks above ran)\n'
  fi
}
if [ "${1:-}" = "--claude-layer" ]; then
  claude_layer
  printf '\n%s\n' "$([ $fail = 0 ] && echo 'CLAUDE LAYER PASSED' || echo 'CLAUDE LAYER FAILED')"
  exit $fail
fi

E="BugBountyTarget/Selftest_$(date +%d%m%Y)"
cleanup() { rm -rf "$E"; }
trap cleanup EXIT
rm -rf "$E"

step "syntax"
for f in scripts/*.sh tools/*.sh .claude/hooks/*.sh; do bash -n "$f" && ok "bash -n $f" || bad "bash -n $f"; done
for f in scripts/*.py tools/*.py; do [ -f "$f" ] && { python3 -m py_compile "$f" && ok "py_compile $f" || bad "py_compile $f"; }; done

claude_layer

step "checklist integrity"
expect_ok python3 scripts/lint-checklist.py
expect_ok python3 scripts/build-checklist.py --check
expect_ok python3 scripts/item.py D10-004
expect_ok python3 scripts/item.py --domain D17        # the 'varies'-severity items live only in D17 (ITEM-02 regression guard)
expect_ok python3 scripts/item.py --grep JavascriptInterface
[ -f cards/D10.md ] && ok "cards exist" || bad "cards missing"
[ -f json/index.json ] && ok "json index exists" || bad "json index missing"

step "engagement lifecycle"
expect_ok scripts/new-engagement.sh Selftest
[ -f "$E/engagement.json" ] && ok "engagement.json created" || bad "engagement.json missing"
[ -f "$E/checklist-status.csv" ] && ok "tracker seeded" || bad "tracker missing"
[ -f "$E/report/assessment-status.md" ] && ok "assessment-status.md present in template" || bad "assessment-status.md missing"
expect_fail python3 scripts/mark.py "$E" D10-004 ruled-out --note "found nothing"
expect_fail python3 scripts/mark.py "$E" D10-004 ruled-out --note "found nothing: grep over the sources returned nothing at all for the bridge"
expect_ok   python3 scripts/mark.py "$E" D10-004 ruled-out --note "RouterActivity.java:88 exact scheme+host allow-list; every loadUrl call site routes through validate() (logs/D10-004.txt)"
expect_fail python3 scripts/mark.py "$E" D13-020 blocked --note "later"
expect_ok   python3 scripts/mark.py "$E" D13-020 blocked --note "needs: second account"
expect_fail python3 scripts/mark.py "$E" D13-021 blocked --note "needs: second account" --evidence-file logs/x.txt   # unknown option dies
expect_fail python3 scripts/mark.py "$E" D19 n/a --note "no"
expect_ok   python3 scripts/mark.py "$E" D19 n/a --note "native app: no Flutter/RN/Hermes/Xamarin/Unity/Cordova artefacts in the APK (tools/01 framework detection)"
[ "$(jq_ "$E/engagement.json" "'D19' in e['domains_na']")" = True ] && ok "whole-domain n/a recorded in domains_na" || bad "domains_na.D19 missing"
expect_fail python3 scripts/mark.py "$E" D99 n/a --note "a domain that has no chapter and therefore no rows in the tracker"   # no rows → refused
expect_fail python3 scripts/mark.py "$E" D10-005 finding --note "juicy"
expect_ok   python3 scripts/mark.py "$E" D10-005 finding --note "H-001: bridge method returns session token" --evidence logs/D10-005.txt
expect_ok   python3 scripts/mark.py "$E" D10 blocked --note "needs: rooted device for the live bridge checks"
python3 scripts/mark.py "$E" --show D10-005 | grep -q '"result": "finding"' && ok "whole-domain blocked left the finding row alone" || bad "whole-domain blocked overwrote a finding row"
expect_ok   python3 scripts/mark.py "$E" D19 reopen
[ "$(jq_ "$E/engagement.json" "'D19' in e['domains_na']")" = False ] && ok "reopen removed domains_na.D19" || bad "domains_na.D19 survived reopen"
[ "$(jq_ "$E/engagement.json" "'D19' in e.get('domains_decided', [])")" = False ] && ok "reopen removed D19 from domains_decided" || bad "D19 still decided after reopen"
expect_fail python3 scripts/mark.py "$E" D11 applies --note "yes"                                                   # the probe's evidence is required
expect_fail python3 scripts/mark.py "$E" D11-001 applies --note "SharedPreferences + Room database in the APK (jadx: 14 call sites)"   # whole domain only
expect_ok   python3 scripts/mark.py "$E" D11 applies --note "SharedPreferences + Room database in the APK (jadx: 14 getSharedPreferences call sites)"
[ "$(jq_ "$E/engagement.json" "'D11' in e['domains_decided'] and 'D11' in e['domains_applicable']")" = True ] && ok "applies recorded the P3 decision without touching rows" || bad "applies not recorded"
out="$(python3 scripts/gate.py "$E" p3 2>/dev/null)"; printf '%s' "$out" | grep -q 'applicability undecided for D01' && ok "gate p3 lists undecided domains" || bad "gate p3 applicability predicate vacuous"   # capture first: grep -q + pipefail would SIGPIPE a long printer
expect_fail python3 scripts/mark.py "$E" --show
expect_fail python3 scripts/gate.py "$E" p0
expect_fail python3 scripts/gate.py "$E" --pass
expect_ok   python3 scripts/gate.py "$E" --all
python3 - "$E/engagement.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p))
e["authorisation"].update({"basis": "lab", "scope": "selftest fixture"}); e["accounts"]["a"] = "selftest-a"
e["lab"] = {"mode": "static-only", "tls_intercept": False, "frida": False, "root": False, "lockscreen": False, "positive_controls": False}
json.dump(e, open(p, "w"), indent=1)
PY
expect_ok   python3 scripts/gate.py "$E" p1                                    # static-only: lab.* may stay false (START.md §3)
expect_ok   python3 scripts/gate.py "$E" --pass p0
[ "$(jq_ "$E/engagement.json" "e['phase']")" = P1 ] && ok "--pass p0 advanced to P1" || bad "phase after --pass p0"
python3 - "$E/engagement.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["phase"] = "P6"; json.dump(e, open(p, "w"), indent=1)
PY
expect_ok   python3 scripts/gate.py "$E" --pass p0
[ "$(jq_ "$E/engagement.json" "e['phase']")" = P6 ] && ok "re-passing p0 at P6 did not rewind the phase" || bad "phase rewound by --pass p0"
expect_ok   python3 scripts/state.py "$E"
expect_ok   python3 scripts/state.py "$E" --json
out="$(python3 scripts/state.py "$E" --json 2>/dev/null)"; printf '%s' "$out" | grep -q '"settled_predicate": "scripts/gate.py row_valid"' && ok "state.py counts with gate.row_valid" || bad "state.py predicate"   # capture first (pipefail)
expect_ok   python3 scripts/coverage.py "$E/checklist-status.csv" --brief
expect_ok   python3 scripts/next.py "$E"
out="$(python3 scripts/next.py "$E" --domain D10 2>/dev/null)"; printf '%s' "$out" | grep -q 'D10-005' && bad "next.py offers a settled finding row" || ok "next.py skips settled rows (gate.row_valid)"

step "inventory + fan-out merge"
expect_ok   python3 scripts/inventory.py scripts/selftest-fixtures/AndroidManifest.xml --out "$E/inventory"
n="$(tail -n +2 "$E/inventory/components.csv" | grep -c ',provider,')"; [ "$n" = 3 ] && ok "every provider listed by default ($n/3)" || bad "providers listed: $n (expected 3)"
n="$(tail -n +2 "$E/inventory/deeplinks.csv" | wc -l | tr -d ' ')"; [ "$n" = 4 ] && ok "deep-link URI set from one filter (4)" || bad "deeplink rows: $n"
expect_ok   python3 scripts/inventory.py scripts/selftest-fixtures/AndroidManifest.xml --out "$E/inventory" --all
n="$(tail -n +2 "$E/inventory/components.csv" | wc -l | tr -d ' ')"; [ "$n" = 5 ] && ok "--all adds the non-exported service (5)" || bad "--all rows: $n"
expect_ok   python3 scripts/mark.py "$E" D10-006 reopen                      # the slice must carry an OPEN master row, else merge = conflict
expect_ok   python3 scripts/mark.py "$E" D10-006 finding --note "H-D10-01: deep link param reaches loadUrl without validation" --partial D10
[ -f "$E/checklist-status.D10.partial.csv" ] && ok "--partial seeded the D10 slice" || bad "partial slice missing"
expect_fail python3 scripts/mark.py "$E" D11-001 ruled-out --note "RouterActivity.java:88 exact scheme+host allow-list; every loadUrl call site routes through validate()" --partial D10
python3 - "$E/inventory" <<'PY'
import csv, sys, os
inv = sys.argv[1]
rows = list(csv.DictReader(open(os.path.join(inv, "components.csv"), newline="")))
cols = rows[0].keys()
r = dict(rows[1]); r.update({"tested": "true", "result": "ruled-out", "notes": "selftest: provider answers getType() only for its own authority; no path traversal (logs/D07-003.txt)"})
with open(os.path.join(inv, "components.D07.partial.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, cols, lineterminator="\n"); w.writeheader(); w.writerow(r)
PY
expect_ok   python3 scripts/coverage.py "$E/checklist-status.csv" --merge
python3 scripts/mark.py "$E" --show D10-006 | grep -q 'H-D10-01' && ok "merge accepted the H-Dnn-NN finding row" || bad "merge dropped the H-Dnn-NN row"
grep -q ',true,ruled-out,' "$E/inventory/components.csv" && ok "merge folded the inventory partial" || bad "inventory partial not merged"
expect_ok   python3 scripts/coverage.py "$E/checklist-status.csv" --merge --dry-run     # idempotent: nothing new, exit 0

step "hooks"
export CLAUDE_PROJECT_DIR="$REPO" SANE_ENGAGEMENT="$REPO/$E"
echo '{"tool_input":{"command":"git push --force origin main"}}' | bash .claude/hooks/pre-bash.sh >/dev/null 2>&1 && bad "pre-bash did not block force push" || ok "pre-bash blocks force push"
echo '{"tool_input":{"command":"ls"}}' | bash .claude/hooks/pre-bash.sh >/dev/null 2>&1 && ok "pre-bash allows ls" || bad "pre-bash blocked ls"
out="$(echo '{}' | bash .claude/hooks/session-start.sh 2>/dev/null)"; printf '%s' "$out" | grep -q "ENGAGEMENT" && ok "session-start prints the resume card" || bad "session-start card missing"
echo '{"stop_hook_active":true}' | bash .claude/hooks/stop-guard.sh >/dev/null 2>&1 && ok "stop-guard yields on second attempt" || bad "stop-guard loops"
out="$(echo '{"tool_input":{"command":"adb shell am start -n a/.B"}}' | bash .claude/hooks/post-bash.sh 2>/dev/null)"; printf '%s' "$out" | grep -q "AM-03" && ok "post-bash reminds about adb" || bad "post-bash adb reminder missing"

step "tools without a device"
for t in tools/*.sh; do bash "$t" --help >/dev/null 2>&1; rc=$?; [ $rc -eq 0 ] && ok "$t --help" || bad "$t --help rc=$rc (usage must exit 0)"; done
for t in tools/*.py; do [ -f "$t" ] && { python3 "$t" --help >/dev/null 2>&1; rc=$?; [ $rc -eq 0 ] && ok "$t --help" || bad "$t --help rc=$rc"; }; done
out="$(bash scripts/doctor.sh --brief 2>/dev/null)"; [ -n "$out" ] && ok "doctor --brief: $out" || bad "doctor --brief printed nothing (bash ${BASH_VERSION%%.*} — declare -A / set -u regression?)"
out="$(bash scripts/doctor.sh --json 2>/dev/null)"; printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1 && ok "doctor --json is JSON" || bad "doctor --json not parseable"

printf '\n%s\n' "$([ $fail = 0 ] && echo 'SELFTEST PASSED' || echo 'SELFTEST FAILED')"
exit $fail
