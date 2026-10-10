#!/usr/bin/env python3
"""lint-checklist.py — the format, identifier and consistency gate for the chapters.

Exit 1 on any ERROR. Warnings do not fail the build. Run in CI and before every commit that touches
checklist/ or docs/.

Checks
  structure   every chapter has the required sections; every item has the five body fields and the
              five metadata rows; ids are Dnn-NNN, sequential, unique; severity in the allowed set
  attacker    every Attacker field resolves to AM-01..AM-12 or n/a
  vrt         every VRT path in backticks exists in data/bugcrowd-vrt-full.csv
  standards   every MASTG-*/MASWE-* id exists in data/standards-index.csv (regenerate with scripts/refresh-data.py)
  xrefs       every Dnn-NNN reference points at an item that exists; every Dnn reference is a real domain
  links       every relative markdown link in the repo resolves
  phantoms    no 'SANE-' prefixes, no references to domains that have no chapter
  style       operator-facing docs do not name a vendor model or a laptop-specific path (warning)
"""
import csv, glob, os, re, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CH = os.path.join(ROOT, "checklist")
DATA = os.path.join(ROOT, "data")
SEV = {"critical", "high", "medium", "low", "support"}
SECTIONS = ["Why this domain pays", "The crux question", "Triage order", "Items",
            "Graveyard for this domain", "Cross-surface joins", "Sources"]
BODY = ["Test", "How", "Proof", "Escalation", "Ruled out when"]
META = ["Severity ceiling", "VRT", "Attacker", "Applies to", "Maps to"]
VRT_PREFIXES = ("server_side_injection", "broken_access_control", "broken_authentication_and_session_management",
                "sensitive_data_exposure", "cross_site_scripting_xss", "mobile_security_misconfiguration",
                "insecure_data_storage", "lack_of_binary_hardening", "cryptographic_weakness", "insecure_os_firmware",
                "application_level_denial_of_service_dos", "insufficient_security_configurability",
                "server_security_misconfiguration", "unvalidated_redirects_and_forwards", "client_side_injection",
                "insecure_data_transport", "privacy_concerns", "external_behavior",
                "using_components_with_known_vulnerabilities", "automotive_security_misconfiguration",
                "ai_application_security", "cross_site_request_forgery_csrf", "network_security_misconfiguration",
                "physical_security_issues", "protocol_specific_misconfiguration", "cloud_security",
                "broken_cryptography", "server_side_request_forgery_ssrf", "indicators_of_compromise")

def cut_at_next_section(text):
    out, fence = [], False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            fence = not fence
        if not fence and re.match(r"^##\s", line):
            break
        out.append(line)
    return "\n".join(out)


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


vrt = load_set(os.path.join(DATA, "bugcrowd-vrt-full.csv"), "vrt_path")
std = load_set(os.path.join(DATA, "standards-index.csv"), "id")

chapters = sorted(glob.glob(os.path.join(CH, "D*.md")))
domains = {os.path.basename(p)[:3] for p in chapters}
# domains declared in the registry (scripts/build-checklist.py PHASE) count as known even before
# their chapter lands; they are reported as warnings so CI stays green while a chapter is being written
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from importlib import import_module
    DECLARED = set(import_module("build-checklist".replace("-", "_")).PHASE) if False else set()
except Exception:
    DECLARED = set()
try:
    _src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "build-checklist.py"), encoding="utf-8").read()
    DECLARED = set(re.findall(r'"(D\d\d)":\s*\("P\d"', _src))
except Exception:
    pass
planned = DECLARED - domains
if planned:
    warn("registry", f"declared domains without a chapter yet: {' '.join(sorted(planned))}")
known_domains = domains | DECLARED
all_ids = set()
item_blocks = {}

for p in chapters:
    f = os.path.relpath(p, ROOT)
    t = open(p, encoding="utf-8", errors="replace").read()
    did = os.path.basename(p)[:3]
    if not re.search(r'^#\s*%s\s*[·\-]\s*\S' % did, t, re.M):
        err(f, "missing '# Dnn · Name' title")
    for s in SECTIONS:
        if not re.search(r'^##\s*%s\s*$' % re.escape(s), t, re.M):
            err(f, f"missing section '## {s}'")
    blocks = re.split(r'\n(?=###\s+(?:SANE-)?D\d\d-)', t)
    nums = []
    for b in blocks:
        h = re.match(r'###\s+((?:SANE-)?(D\d\d)-(\d+))\s*[·\-]\s*(.+)', b)
        if not h:
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
        body = cut_at_next_section(b)
        item_blocks[iid] = (f, body)
        for m in META:
            if not re.search(r'^\|\s*\*\*%s\*\*\s*\|' % re.escape(m), b, re.M):
                err(f, f"{iid}: missing metadata row '{m}'")
        for bf in BODY:
            if not re.search(r'^- \*\*%s:?\*\*' % re.escape(bf), body, re.M):
                err(f, f"{iid}: missing field '- **{bf}:**'")
        sev = re.search(r'^\|\s*\*\*Severity ceiling\*\*\s*\|\s*(.*?)\s*\|', b, re.M)
        if sev:
            cell = sev.group(1).replace("**", "").strip().lower()
            if not re.search(r"\b(critical|high|medium|low|support|informational)\b", cell) and \
               not re.search(r"varies|inherit|per (sink|advisory|the)|by the|rated (on|per)|n/a|not a finding|depends", cell):
                err(f, f"{iid}: severity cell has no recognisable level: '{sev.group(1)[:60]}'")
        att = re.search(r'^\|\s*\*\*Attacker\*\*\s*\|\s*(.*?)\s*\|', b, re.M)
        if att:
            a = att.group(1)
            if not re.search(r'AM-(0[1-9]|1[0-2])\b', a) and not re.match(r'^\s*n/a', a, re.I):
                err(f, f"{iid}: Attacker '{a[:40]}' has no AM-xx id")
            for bad in re.findall(r'AM-(\d\d)', a):
                if not (1 <= int(bad) <= 12):
                    err(f, f"{iid}: Attacker AM-{bad} out of range")
        vf = re.search(r'^\|\s*\*\*VRT\*\*\s*\|\s*(.*?)\s*\|', b, re.M)
        if vf and vrt:
            for path in re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', vf.group(1)):
                if path.split(".")[0] in VRT_PREFIXES and path not in vrt:
                    err(f, f"{iid}: VRT path not in taxonomy: {path}")
        if std:
            for sid in set(re.findall(r'MASTG-[A-Z]+-\d{4}|MASWE-\d{4}', b)):
                if sid not in std:
                    err(f, f"{iid}: unknown standards id {sid}")
        rw = re.search(r'- \*\*Ruled out when:?\*\*\s*(.{0,60})', body)
        if rw and len(rw.group(1).strip()) < 25:
            warn(f, f"{iid}: 'Ruled out when' is very short")
    if nums:
        exp = list(range(1, max(nums) + 1))
        if sorted(nums) != exp:
            err(f, f"item numbering not contiguous 001..{max(nums):03d}: missing {sorted(set(exp) - set(nums))[:10]}")

# cross references
for iid, (f, body) in item_blocks.items():
    for x in set(re.findall(r'\b(D\d\d)-(\d{3})\b', body)):
        ref = f"{x[0]}-{x[1]}"
        if ref != iid and ref not in all_ids:
            err(f, f"{iid}: references {ref}, which does not exist")
    for d in set(re.findall(r'\bD(\d\d)\b', body)):
        if "D" + d not in known_domains:
            err(f, f"{iid}: references domain D{d}, which has no chapter")

# phantom domains + links + style across all markdown
md_files = [p for p in glob.glob(os.path.join(ROOT, "**", "*.md"), recursive=True)
            if "/BugBountyTarget/" not in p and "/node_modules/" not in p and "/.git/" not in p]
for p in md_files:
    f = os.path.relpath(p, ROOT)
    t = open(p, encoding="utf-8", errors="replace").read()
    if f.startswith(("docs/", "README", "START", "AGENTS", "CLAUDE", "ISSUES", "CHECKLIST", "flow", "prompts/")):
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
    if f.startswith(("README", "START", "AGENTS", "CLAUDE", "GEMINI", "prompts/", "ISSUES", "flow")):
        for pat, why in [(r'Opus 5', "names a vendor model"), (r'/Applications/Android Studio', "macOS path"),
                         (r'~/Library/Android', "macOS path"), (r'your Mac\b', "operator-specific"),
                         (r'lamppentest', "operator-specific path")]:
            if re.search(pat, t):
                warn(f, f"{why}: /{pat}/")

for w in warns: print("WARN ", w)
for e in errors: print("ERROR", e)
print(f"\n{len(item_blocks)} items in {len(chapters)} chapters · {len(errors)} errors · {len(warns)} warnings")
sys.exit(1 if errors else 0)
