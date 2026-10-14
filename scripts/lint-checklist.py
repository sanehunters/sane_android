#!/usr/bin/env python3
"""lint-checklist.py — the format, identifier and consistency gate for the chapters (docs/11 §6 lists the rules).

Exit 1 on any ERROR, 2 on a usage error. Warnings do not fail the build. Run in CI and before every commit
that touches checklist/ or docs/.

  python3 scripts/lint-checklist.py            errors + warnings
  python3 scripts/lint-checklist.py --strict   also: a reference to a domain that is declared in PHASE but has
                                               no chapter yet is an error, not a warning

Checks (the parser is scripts/build-checklist.py, imported here, so the gate and the generator agree)
  structure   every chapter has the required sections (Applicability probe: warning until every chapter has it);
              every item has the five required metadata rows (closed, non-empty) and the five required body
              fields; ids are Dnn-NNN, sequential, unique; every item heading parses; severity in the allowed set
  attacker    every Attacker field resolves to AM-01..AM-12 or n/a
  vrt         every backticked VRT path exists in data/vrt.csv (categories come from the data, not a list);
              warnings: a cell outside the docs/11 §1 grammar (the build classifies it '?'); a parent node
              (no priority) cited as the node; a dotted path that is not a category (a relative path); the
              chapter head's 'VRT ceiling' naming a path not in the taxonomy; '(null)'/'(VARIES)' for '(varies)'
  requires    every Requires tag is in the docs/11 §4 vocabulary; Record names logs/Dnn-NNN.txt (warning)
  standards   every MASTG-*/MASWE-*/MASVS-* id (shorthand lists expanded) exists in data/standards-index.csv;
              every mastg-android-* rule id exists in data/mastg-rules.csv; placeholder/deprecated pages warn
  xrefs       every Dnn-NNN reference points at an item that exists; every Dnn reference is a real domain
  links       every relative markdown link in the repo resolves (hidden dirs and templates included)
  paths       (warning) a backticked data/<file>.csv|json or source-note path (primary/, secondary/, local/,
              architecture/, research/) names a file that does not exist in the repository
  phantoms    no 'SANE-' prefixes, no references to domains that have no chapter
  portability (warnings, aggregated per file) jadx_out/apktool_out instead of $DEC; `frida -U`; `--no-pause`;
              `sed -i`; duplicate item titles across chapters
  style       operator paths (ERROR); a reference to a removed vendor entry file, or that file still on
              disk (ERROR: the repo targets Opus 5.5 / Opus 5 in Claude Code, CLAUDE.md is the entry);
              model names other than the targeted Opus 5.5 / Opus 5 and host-specific wording (warning) in
              docs, templates, skills, agents, workflows, hooks, tools and scripts; SANE_LINT_TARGET_NAMES=<a,b>
              adds real target names as errors (keep the list outside the repo)
"""
import argparse, csv, collections, importlib.util, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CH = os.path.join(ROOT, "checklist")
DATA = os.path.join(ROOT, "data")

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--strict", action="store_true", help="declared-but-absent domain references are errors")
ARGS = ap.parse_args()

# the parser the generator uses: one schema, one set of regexes
_spec = importlib.util.spec_from_file_location("build_checklist", os.path.join(ROOT, "scripts", "build-checklist.py"))
bc = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(bc)

SEV = {"critical", "high", "medium", "low", "support"}
SECTIONS = ["Why this domain pays", "The crux question", "Applicability probe", "Triage order", "Items",
            "Graveyard for this domain", "Cross-surface joins", "Sources"]
SOFT_SECTIONS = {"Applicability probe"}          # warning until every chapter carries it, then promote to err
BODY = ["Test", "How", "Proof", "Escalation", "Ruled out when"]
SOFT_BODY = ["Skip when"]
META = ["Severity ceiling", "VRT", "Attacker", "Applies to", "Maps to"]
SOFT_META = ["Requires", "Record"]
LEGACY_META = bc.META_LEGACY
REQ_TAGS = {"webview", "js-bridge", "native", "flutter", "react-native", "hermes", "xamarin", "unity", "cordova", "capacitor", "kmp",
            "provider", "exported-activity", "exported-service", "exported-receiver", "deeplink", "applink", "backend-api",
            "oauth", "biometric", "payments", "push", "firebase", "ads-sdk", "ai-feature", "two-accounts", "device", "root",
            "mitm", "frida", "physical", "oem-scope", "enterprise", "wear", "tv", "auto", "legacy"}
REQ_NUM = re.compile(r"^(api|targetsdk|minsdk)(<=|>=|<|>|=)\d{1,2}$")   # docs/11 §4 numeric gates
RECORD_RE = re.compile(r'logs/D\d\d-\d{3}\.txt')
STD_RE = re.compile(r'MASTG-[A-Z]+-\d{4}|MASWE-\d{4}|MASVS-[A-Z]+-\d')
RULE_RE = re.compile(r'\bmastg-android-[a-z0-9-]*[a-z0-9](?:\.ya?ml)?\b(?![-*]|\.csv)')   # a rule id; not a glob prefix, folder or csv name

# portability rules over chapter text (warnings, aggregated per file: "<n> lines, first at …")
PORTABILITY = [
    (re.compile(r'\b(jadx_out|apktool_out)\b'), "jadx_out/apktool_out: write $DEC/jadx or $DEC/apktool (START.md §6, docs/11 §1)"),
    (re.compile(r'\bfrida(?:-ps|-trace|-discover)?\s+(?:-U|--usb)\b'), "`frida -U` picks a device silently: use -D \"$SERIAL\""),
    (re.compile(r'--no-pause\b'), "`--no-pause` was removed in frida-tools 17: drop it (use -t <seconds> when needed)"),
    (re.compile(r'\bsed -i\b'), "`sed -i` differs between GNU and BSD sed: use `sed -i.bak` or a temp file"),
]
# style rules over every operator-facing file. Code fences are NOT stripped: a laptop path inside a command is
# exactly the thing a public, host-neutral methodology must not carry.
STYLE_ERR = [(re.compile(r'lamppentest|AndroidStudioProjects'), "operator path"),
             (re.compile(r'/Users/[A-Za-z0-9_.-]+/'), "macOS home path"),
             (re.compile(r'GEMINI\.md|\.windsurfrules|\.cursor/|copilot-instructions\.md'),
              "references a removed vendor entry file (the entry is CLAUDE.md; git history keeps the old files)")]
# the vendor entry files removed when the repo was retargeted at Opus 5.5 / Opus 5 in Claude Code
REMOVED_ENTRY_FILES = ["GEMINI.md", ".windsurfrules", ".cursor", ".github/copilot-instructions.md"]
# Opus is named on purpose (the repo targets Opus 5.5 / Opus 5); any other model name is drift
STYLE_WARN = [(re.compile(r'\b(Sonnet|Haiku) ?\d|\bclaude-(sonnet|haiku)-|GPT-?[45]|Gemini \d'),
               "names a model the repo does not target (Opus 5.5 / Opus 5)"),
              (re.compile(r'~/Library/Android|/Applications/Android Studio'), "macOS path (fine only next to the Linux form)"),
              (re.compile(r'your Mac\b'), "operator-specific"),
              (re.compile(r'\bbrew install\b'), "host-specific installer (give the Linux form too)"),
              (re.compile(r'~/sane_android\b'), "assumes the checkout lives at ~/sane_android (say 'the methodology checkout')")]
TARGET_NAMES = [x.strip() for x in os.environ.get("SANE_LINT_TARGET_NAMES", "").split(",") if x.strip()]
STYLE_EXEMPT = {"docs/08-senior-audit-2026-10.md"}     # the audit record quotes the defects it reports
# docs/11 is the linter's own rulebook: it quotes every pattern it forbids, so it is exempt from the portability and style warnings
RULEBOOK_EXEMPT = {"docs/11-item-schema.md"}
# a macOS path is fine on a line that also gives the Linux form
LINUX_FORM = re.compile(r'~/Android/Sdk|\$HOME/Android/Sdk|/opt/android|/usr/lib/android|\bLinux\b')

errors, warns = [], []
err = lambda f, m: errors.append(f"{f}: {m}")
warn = lambda f, m: warns.append(f"{f}: {m}")


def load_set(path, col):
    s = set()
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                s.add(r[col].strip())
    return s


def line_of(t, pos):
    return t.count("\n", 0, pos) + 1


def portability(f, t):
    if f in STYLE_EXEMPT or f in RULEBOOK_EXEMPT:
        return
    for pat, why in PORTABILITY:
        lines = [line_of(t, m.start()) for m in pat.finditer(t)]
        if lines:
            warn(f, f"{why} — {len(lines)} line(s), first at {', '.join(str(x) for x in lines[:3])}")


def style(f, t):
    if f in STYLE_EXEMPT:
        return
    rulebook = f in RULEBOOK_EXEMPT
    for pat, why in STYLE_ERR:
        m = pat.search(t)
        if m:
            err(f, f"{why} at line {line_of(t, m.start())}: {m.group(0)}")
    for name in TARGET_NAMES:
        m = re.search(re.escape(name), t, re.I)
        if m:
            err(f, f"names a real engagement target at line {line_of(t, m.start())} (SANE_LINT_TARGET_NAMES)")
    if rulebook:
        return
    for pat, why in STYLE_WARN:
        for m in pat.finditer(t):
            line = t[t.rfind("\n", 0, m.start()) + 1: t.find("\n", m.start()) if t.find("\n", m.start()) >= 0 else len(t)]
            if "macOS path" in why and LINUX_FORM.search(line):
                continue
            warn(f, f"{why} at line {line_of(t, m.start())}: {m.group(0)}")
            break


# a backticked path under data/ or the source-note corpus must name a file that exists (data/README; DATA-04/DATA-19).
# Warnings until the chapters and prompts are migrated, then promote to err.
PATH_RE = re.compile(r'`(?:\./)?((?:data|primary|secondary|local|architecture|research)/[A-Za-z0-9_./-]+\.(?:csv|json|md))`')


def phantom_paths(f, t):
    if f in STYLE_EXEMPT:
        return
    missing = sorted(set(x for x in PATH_RE.findall(t) if not os.path.exists(os.path.join(ROOT, x))))
    if missing:
        warn(f, f"names {len(missing)} file(s) that do not exist in the repository: {' '.join(missing[:6])}"
                + (" …" if len(missing) > 6 else ""))


vrt = load_set(os.path.join(DATA, "vrt.csv"), "vrt_path")
VRT_PREFIXES = {k.split(".")[0] for k in vrt}
if not vrt:
    warn("data", "data/vrt.csv missing — VRT paths not validated")
std = load_set(os.path.join(DATA, "standards-index.csv"), "id")
std_status, std_kind = {}, {}
_p = os.path.join(DATA, "standards-index.csv")
if os.path.exists(_p):
    with open(_p, newline="", encoding="utf-8") as _f:
        for _r in csv.DictReader(_f):
            std_status[_r["id"]] = (_r.get("status") or "").strip()
            std_kind[_r["id"]] = (_r.get("kind") or "").strip()
covered_by = {}
_p = os.path.join(DATA, "mastg-tests.csv")
if os.path.exists(_p):
    with open(_p, newline="", encoding="utf-8") as _f:
        for _r in csv.DictReader(_f):
            covered_by[_r["id"]] = (_r.get("covered_by") or "").strip()
rules = set()
_p = os.path.join(DATA, "mastg-rules.csv")
if os.path.exists(_p):
    with open(_p, newline="", encoding="utf-8") as _f:
        for _r in csv.DictReader(_f):
            rules.add(_r["rule_id"].strip()); rules.add(re.sub(r'\.ya?ml$', '', os.path.basename(_r.get("rule_file") or "")))


def deprecation_hint(sid):
    if std_kind.get(sid) == "test":
        cb = covered_by.get(sid)
        return f"covered by {cb}" if cb else "no v2 replacement; cite the MASWE instead"
    return "deprecated upstream, cite a current page"


def check_standards(f, where, text, aggregate=False):
    """Validate every standards id in text (shorthand expanded). where = item id or a section name; aggregate
    folds the warnings of a whole section into one line each."""
    text = bc.expand_std_ids(text)
    placeholders, deprecated = [], []
    if std:
        for sid in sorted(set(STD_RE.findall(text))):
            if sid not in std:
                err(f, f"{where}: unknown standards id {sid}")
            elif std_status.get(sid) == "placeholder":
                placeholders.append(sid)
            elif std_status.get(sid) == "deprecated" and not re.search(re.escape(sid) + r'.{0,40}deprecated|deprecated.{0,40}' + re.escape(sid), text, re.S | re.I):
                deprecated.append(sid)
    if rules:
        for rid in sorted(set(re.sub(r'\.ya?ml$', '', x) for x in RULE_RE.findall(text))):
            if rid not in rules:
                warn(f, f"{where}: unknown MASTG rule id {rid} (data/mastg-rules.csv rule_id/rule_file)")
    if aggregate:
        if placeholders:
            warn(f, f"{where}: cites placeholder pages (no content upstream): {' '.join(placeholders)}")
        if deprecated:
            warn(f, f"{where}: cites deprecated pages without saying so: " + "; ".join(f"{s} ({deprecation_hint(s)})" for s in deprecated))
        return
    for sid in placeholders:
        warn(f, f"{where}: cites {sid}, which is a placeholder page upstream (no content)")
    for sid in deprecated:
        warn(f, f"{where}: cites deprecated {sid} without saying so ({deprecation_hint(sid)})")


chapters = sorted(os.path.join(CH, x) for x in os.listdir(CH) if re.match(r'D\d\d.*\.md$', x))
domains = {os.path.basename(p)[:3] for p in chapters}
# domains declared in the registry (scripts/build-checklist.py PHASE) count as known even before their chapter
# lands; references to them are warnings so CI stays green while a chapter is being written (errors with --strict)
DECLARED = set(bc.PHASE)
planned = DECLARED - domains
if planned:
    warn("registry", f"declared domains without a chapter yet: {' '.join(sorted(planned))}")
known_domains = domains | DECLARED
all_ids = set()
item_blocks = {}
by_title = collections.defaultdict(list)
schema = collections.Counter()
noprobe = []

for p in chapters:
    f = os.path.relpath(p, ROOT)
    t = open(p, encoding="utf-8", errors="replace").read()
    did = os.path.basename(p)[:3]
    if not re.search(r'^#\s*%s\s*[·\-]\s*\S' % did, t, re.M):
        err(f, "missing '# Dnn · Name' title")
    for s in SECTIONS:
        if not re.search(r'^##\s*%s\s*$' % re.escape(s), t, re.M):
            if s in SOFT_SECTIONS:
                noprobe.append(did)
            else:
                err(f, f"missing section '## {s}'")
    blocks = re.split(r'\n(?=###\s+(?:SANE-)?D\d\d-)', t)
    nums = []
    outside = []      # chapter text that belongs to no item: intro, Graveyard, Cross-surface joins, Sources
    spelled = collections.Counter()   # '(null)' / '(VARIES)' in VRT cells: the build reads them, the canonical spelling is '(varies)'
    for b in blocks:
        h = re.match(r'###\s+((?:SANE-)?(D\d\d)-(\d+))\s*[·\-]\s*(.+)', b)
        if not h:
            if re.match(r'###\s+(?:SANE-)?D\d\d-\d+', b):
                err(f, f"unparseable item heading (use '### Dnn-NNN · Title'): {b.splitlines()[0][:70]}")
            outside.append(b)
            continue
        iid, d2, n, title = h.group(1), h.group(2), h.group(3), h.group(4)
        if iid.startswith("SANE-"):
            err(f, f"{iid}: legacy SANE- prefix")
            iid = iid[5:]
        if d2 != did:
            err(f, f"{iid}: item domain does not match chapter {did}")
        if len(n) != 3:
            err(f, f"{iid}: id must be three digits")
        nums.append(int(n))
        if iid in all_ids:
            err(f, f"{iid}: duplicate id")
        all_ids.add(iid)
        by_title[" ".join(title.split()).strip().lower()].append(iid)
        body = bc.cut_at_next_section(b)
        outside.append(b[len(body):])
        item_blocks[iid] = (f, body)
        for m in META + SOFT_META + LEGACY_META:
            present = re.search(r'^\|\s*\*\*%s\*\*\s*\|' % re.escape(m), body, re.M)
            cell = re.search(r'^\|\s*\*\*%s\*\*\s*\|\s*(.*?)\s*\|\s*$' % re.escape(m), body, re.M)
            if present and (not cell or not cell.group(1).strip()):
                err(f, f"{iid}: metadata row '{m}' is empty or has no closing '|'")
            if present and m in LEGACY_META:
                warn(f, f"{iid}: metadata row '{m}' is deprecated (docs/11 §7); fold it into Applies to / Requires / Record")
            if not present and m in META:
                err(f, f"{iid}: missing metadata row '{m}'")
            if present and m in SOFT_META:
                schema[m] += 1
        for bf in BODY + SOFT_BODY:
            present = re.search(r'^- \*\*%s:?\*\*' % re.escape(bf), body, re.M)
            if not present and bf in BODY:
                err(f, f"{iid}: missing field '- **{bf}:**'")
            if present and bf in SOFT_BODY:
                schema[bf] += 1
        sev = bc.meta_field(body, "Severity ceiling")
        if sev:
            cell = sev.replace("**", "").strip().lower()
            if not re.search(r"\b(critical|high|medium|low|support|informational)\b", cell) and \
               not re.search(r"varies|inherit|per (sink|advisory|the)|by the|rated (on|per)|n/a|not a finding|depends", cell):
                err(f, f"{iid}: severity cell has no recognisable level: '{sev[:60]}'")
        a = bc.meta_field(body, "Attacker")
        if a:
            if not re.search(r'AM-(0[1-9]|1[0-2])\b', a) and not re.match(r'^\s*n/a', a, re.I):
                err(f, f"{iid}: Attacker '{a[:40]}' has no AM-xx id")
            for bad in re.findall(r'AM-(\d\d)', a):
                if not (1 <= int(bad) <= 12):
                    err(f, f"{iid}: Attacker AM-{bad} out of range")
        vf = bc.meta_field(body, "VRT")
        if vf and vrt:
            for path in re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', vf):
                if path.split(".")[0] in VRT_PREFIXES and path not in vrt:
                    err(f, f"{iid}: VRT path not in taxonomy: {path}")
                elif path.split(".")[0] not in VRT_PREFIXES:
                    warn(f, f"{iid}: VRT cell names a dotted path that is not a VRT category (a relative path? write the full one): {path}")
                elif bc.VRT.get(path, "x") == "":
                    warn(f, f"{iid}: VRT path is a parent node (no priority in data/vrt.csv; data/README: cite a leaf): {path}")
            spelled.update(re.findall(r'\((null|VARIES)\)', vf))
            if bc.vrt_priority(vf)[0] == "?":
                warn(f, f"{iid}: VRT cell is outside the docs/11 §1 grammar (no path, n/a, varies or inherits/as Dnn-NNN): '{vf[:60]}'")
        check_standards(f, iid, body)
        rq = bc.meta_field(body, "Requires")
        if rq:
            for tag in bc.requires_tags(rq):
                if tag not in REQ_TAGS and not REQ_NUM.match(tag) and tag not in ("—", "-", "none", "all"):
                    err(f, f"{iid}: Requires tag '{tag}' not in the docs/11 §4 vocabulary")
        rc = bc.meta_field(body, "Record")
        if rc and not RECORD_RE.search(rc):
            warn(f, f"{iid}: Record row does not name logs/{iid}.txt (docs/11 §5)")
        rw = re.search(r'- \*\*Ruled out when:?\*\*\s*(.{0,60})', body)
        if rw and len(rw.group(1).strip()) < 25:
            warn(f, f"{iid}: 'Ruled out when' is very short")
    if not nums:
        err(f, "chapter has no parseable items")
    else:
        exp = list(range(1, max(nums) + 1))
        if sorted(nums) != exp:
            err(f, f"item numbering not contiguous 001..{max(nums):03d}: missing {sorted(set(exp) - set(nums))[:10]}")
    check_standards(f, "outside items (intro/Graveyard/joins/Sources)", "\n".join(outside), aggregate=True)
    portability(f, t)
    phantom_paths(f, t)
    if spelled:
        warn(f, "VRT priority spelled " + ", ".join(f"'({k})' x{v}" for k, v in sorted(spelled.items()))
                + " in VRT cells: data/vrt.csv and docs/11 §1 write '(varies)'")
    head_vrt = bc.meta_field(t.split("\n## ")[0], "VRT ceiling")
    bad_head = [x for x in re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', head_vrt) if vrt and x not in vrt]
    if bad_head:
        warn(f, f"chapter head 'VRT ceiling' names {len(bad_head)} path(s) not in data/vrt.csv (relative? write the full path): {' '.join(bad_head[:4])}"
                + (" …" if len(bad_head) > 4 else ""))

for t_, ids in sorted(by_title.items()):
    if len(ids) > 1:
        warn("titles", f"duplicate title in {' '.join(ids)}: {t_[:60]}")
n_items = len(item_blocks)
for m in SOFT_META + SOFT_BODY:
    if schema[m] < n_items:
        warn("schema", f"{schema[m]}/{n_items} items carry '{m}' (docs/11 §1 strongly recommended)")
if noprobe:
    warn("schema", f"{len(noprobe)}/{len(chapters)} chapters lack '## Applicability probe' (docs/11 §2): {' '.join(noprobe)}")

# cross references
for iid, (f, body) in item_blocks.items():
    for x in set(re.findall(r'\b(D\d\d)-(\d{3})\b', body)):
        ref = f"{x[0]}-{x[1]}"
        if ref != iid and ref not in all_ids:
            err(f, f"{iid}: references {ref}, which does not exist")
    for d in set(re.findall(r'\bD(\d\d)\b', body)):
        if "D" + d not in known_domains:
            err(f, f"{iid}: references domain D{d}, which has no chapter")
        elif "D" + d in planned and ARGS.strict:
            err(f, f"{iid}: references domain D{d}, which is declared but has no chapter (--strict)")

# phantom domains + links + style across every operator-facing file (hidden dirs and templates included;
# engagement folders BugBountyTarget/<Target>_<date> are private evidence and are skipped)
md_files = []
for dp, dns, fns in os.walk(ROOT):
    rel = os.path.relpath(dp, ROOT)
    dns[:] = sorted(d for d in dns if d not in (".git", "node_modules", ".refs", "__pycache__")
                    and not (rel == "BugBountyTarget" and "_" in d and not d.startswith("_")))
    for fn in fns:
        if fn.endswith(".md"):
            md_files.append(os.path.join(dp, fn))
extra = [p for sub in ("scripts", "tools", "frida", ".claude/hooks", ".claude/workflows") for p in sorted(
         os.path.join(ROOT, sub, x) for x in (os.listdir(os.path.join(ROOT, sub)) if os.path.isdir(os.path.join(ROOT, sub)) else []))
         if os.path.isfile(p) and not p.endswith(".md") and os.path.basename(p) != "lint-checklist.py"]
PHANTOM_SCOPE = ("docs/", "README", "START", "AGENTS", "CLAUDE", "ISSUES", "CHECKLIST", "flow", "prompts/",
                 ".github/", ".claude/", "templates/", "loops/", "BugBountyTarget/")
for x in REMOVED_ENTRY_FILES:
    if os.path.lexists(os.path.join(ROOT, x)):
        err(x, "removed vendor entry file is back on disk: delete it (the entry is CLAUDE.md)")
for p in sorted(md_files):
    f = os.path.relpath(p, ROOT)
    t = open(p, encoding="utf-8", errors="replace").read()
    if f.startswith(PHANTOM_SCOPE):
        for d in set(re.findall(r'\bD(\d\d)\b', t)):
            if "D" + d not in known_domains and int(d) <= 40:
                err(f, f"references domain D{d}, which has no chapter")
    t_nocode = re.sub(r"```.*?```", "", t, flags=re.S)
    for m in re.finditer(r'\]\(([^)\s]+)\)', t_nocode):
        link = m.group(1)
        if link.startswith(("http", "mailto:", "#")):
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(p), link.split("#")[0]))
        if link.split("#")[0] and not os.path.exists(target):
            err(f, f"dead link {link}")
    if not f.startswith(("checklist/", "cards/", "MASTER-CHECKLIST")):
        style(f, t)
        phantom_paths(f, t)
    if f.startswith(("docs/", "frida/")):
        portability(f, t)
for p in extra:
    f = os.path.relpath(p, ROOT)
    t = open(p, encoding="utf-8", errors="replace").read()
    style(f, t)
    if f.startswith("frida/"):
        portability(f, t)

for w in warns: print("WARN ", w)
for e in errors: print("ERROR", e)
print(f"\n{n_items} items in {len(chapters)} chapters · {len(errors)} errors · {len(warns)} warnings")
sys.exit(1 if errors else 0)
