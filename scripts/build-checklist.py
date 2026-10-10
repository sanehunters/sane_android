#!/usr/bin/env python3
"""build-checklist.py — compile the domain chapters into every machine-consumable view.

The chapters under checklist/D*.md are the single source of truth. Everything below is GENERATED
from them and must never be hand-edited (CI rebuilds and diffs).

  CHECKLIST.md            the index: one row per domain, crux questions, applicability probes
  cards/Dnn.md            one compact card per domain: one line per item (id · ceiling · attacker ·
                          title · applies-to). ~10-20 KB each. THIS is what an agent loads to work a
                          domain; it opens individual items with scripts/item.py.
  json/Dnn.json           every field of every item in the domain, fully parsed (test/how/proof/
                          escalation/ruled-out-when, metadata, normalised ids, cross-references)
  json/index.json         every item id → domain, title, ceiling, attacker, phase, vrt priority
  checklist.csv           the slim coverage tracker. Copied into each engagement as
                          checklist-status.csv; the agent flips completed/result per row.
  MASTER-CHECKLIST.md     one line per item across all domains. For grep, not for reading end-to-end.

Run from anywhere:  python3 scripts/build-checklist.py [--check]
  --check   build to a temp dir and exit 1 if the committed outputs differ (CI mode)
"""
import csv, glob, json, os, re, sys, collections, tempfile, filecmp, shutil, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CH = os.path.join(ROOT, "checklist")
DATA = os.path.join(ROOT, "data")

SEV_ORDER = ["critical", "high", "medium", "low", "support", "varies"]
E = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "support": "⬜", "varies": "🔷"}

# domain -> (phase, milestone). Keep in sync with ISSUES.md.
PHASE = {
    "D01": ("P3", "M3"), "D02": ("P2", "M2"), "D03": ("P3", "M3"), "D04": ("P5", "M5"),
    "D05": ("P5", "M5"), "D06": ("P5", "M5"), "D07": ("P5", "M5"), "D08": ("P5", "M5"),
    "D09": ("P5", "M5"), "D10": ("P5", "M5"), "D11": ("P4", "M4"), "D12": ("P4", "M4"),
    "D13": ("P6", "M6"), "D14": ("P6", "M6"), "D15": ("P6", "M6"), "D16": ("P4", "M4"),
    "D17": ("P4", "M4"), "D18": ("P6", "M6"), "D19": ("P4", "M4"), "D20": ("P4", "M4"),
    "D21": ("P4", "M4"), "D22": ("P4", "M4"), "D23": ("P6", "M6"), "D24": ("P6", "M6"),
    "D25": ("P5", "M5"), "D26": ("P1", "M1"), "D27": ("P9", "M9"), "D28": ("P4", "M4"),
}

META_FIELDS = ["Severity ceiling", "VRT", "Attacker", "Applies to", "Maps to",
               "Prerequisites", "Depends on", "Evidence", "Cost"]
BODY_FIELDS = ["Test", "How", "Proof", "Escalation", "Ruled out when", "Skip when", "Record"]
BODY_KEYS = {"Test": "test", "How": "how", "Proof": "proof", "Escalation": "escalation",
             "Ruled out when": "ruled_out_when", "Skip when": "skip_when", "Record": "record"}

SECTION_KEYS = {
    "Why this domain pays": "why", "The crux question": "crux", "Applicability probe": "applicability",
    "Triage order": "triage", "Items": "items_raw", "Graveyard for this domain": "graveyard",
    "Cross-surface joins": "joins", "Sources": "sources",
}


def cut_at_next_section(text):
    """Return text up to the next '## ' heading, ignoring headings inside fenced code blocks."""
    out, fence = [], False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            fence = not fence
        if not fence and re.match(r"^##\s", line):
            break
        out.append(line)
    return "\n".join(out).rstrip()


LEVELS = ["critical", "high", "medium", "low", "support"]
RANK = {l: i for i, l in enumerate(LEVELS)}


def parse_severity(cell):
    """The chapters write nuanced ceilings ('Medium standalone; High with a reach primitive').
    Return (ceiling, floor, note): ceiling = the highest level the item can reach, floor = the
    standalone level, note = the raw cell. 'varies' when the cell defers to another item/advisory."""
    raw = (cell or "").strip()
    low = raw.replace("**", "").lower().replace("informational", "support")
    found = re.findall(r"\b(critical|high|medium|low|support)\b", low)
    if not found:
        if re.search(r"not a finding|procedure|technique|tooling", low):
            return "support", "support", raw
        if re.search(r"varies|inherit|per (sink|advisory|the)|by the|rated (on|per)|n/a|depends", low):
            return "varies", "varies", raw
        return "support", "support", raw
    floor = found[0]
    m = re.search(r"\b(critical|high|medium|low|support)\b[^;.()]{0,40}\b(standalone|alone|on its own|by itself)", low)
    if m:
        floor = m.group(1)
    ceiling = "support" if found[0] == "support" else min(found, key=lambda x: RANK[x])
    if RANK[floor] < RANK[ceiling]:
        floor = ceiling
    return ceiling, floor, raw


def load_vrt():
    """vrt_path -> priority: 'P1'..'P5', 'varies', or '' for a parent category."""
    out = {}
    p = os.path.join(DATA, "vrt.csv")
    if not os.path.exists(p):
        return out
    with open(p, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            pr = (r.get("priority") or "").strip()
            pr = ("P" + pr) if pr.isdigit() else (pr.upper() if re.fullmatch(r"[pP][1-5]", pr) else pr.lower())
            out[r["vrt_path"].strip()] = pr
    return out


VRT = load_vrt()
VRT_CATEGORIES = {k.split(".")[0] for k in VRT}


def meta_field(blk, name):
    m = re.search(r'^\|\s*\*\*%s\*\*\s*\|\s*(.*?)\s*\|\s*$' % re.escape(name), blk, re.M)
    return m.group(1).strip() if m else ""


def split_body_fields(body):
    """Return {field: text} for the '- **Field:**' bullets, preserving code blocks."""
    out = {}
    pat = re.compile(r'^- \*\*(%s):?\*\*:?\s*' % "|".join(re.escape(f) for f in BODY_FIELDS), re.M)
    marks = list(pat.finditer(body))
    for i, m in enumerate(marks):
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        txt = body[start:end].rstrip()
        # de-indent continuation lines by two spaces
        txt = "\n".join(l[2:] if l.startswith("  ") else l for l in txt.split("\n"))
        out[BODY_KEYS[m.group(1)]] = txt.strip()
    return out


def vrt_priority(vrt_text):
    """Best priority stated or looked up for the first VRT path in the field."""
    m = re.search(r'\(P([1-5])\)', vrt_text)
    if m:
        return "P" + m.group(1)
    paths = re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', vrt_text)
    for p in paths:
        if VRT.get(p):
            return VRT[p]
    if re.search(r'\bvaries\b', vrt_text, re.I):
        return "varies"
    if re.match(r'^\s*(n/a|none|—|-)', vrt_text, re.I) or not vrt_text.strip():
        return "n/a"
    return "?"


def ids_in(text):
    return {
        "mastg": sorted(set(re.findall(r'MASTG-[A-Z]+-\d{4}', text))),
        "maswe": sorted(set(re.findall(r'MASWE-\d{4}', text))),
        "masvs": sorted(set(re.findall(r'MASVS-[A-Z]+-\d', text))),
        "cwe": sorted(set(re.findall(r'CWE-\d+', text))),
        "attack": sorted(set(re.findall(r'\bT1\d{3}(?:\.\d{3})?\b', text))),
        "vrt": sorted(p for p in set(re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', text)) if p.split(".")[0] in VRT_CATEGORIES),
    }


def parse_chapter(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r'^#\s*(D\d\d)\s*[·\-]\s*(.+)$', t, re.M)
    did = m.group(1) if m else os.path.basename(path)[:3]
    name = m.group(2).strip() if m else ""

    def section(title):
        mm = re.search(r'^##\s*%s\s*\n+(.+?)(?=\n##\s|\Z)' % re.escape(title), t, re.S | re.M)
        return mm.group(1).strip() if mm else ""

    ch = {"id": did, "name": name, "file": os.path.basename(path)}
    for title, key in SECTION_KEYS.items():
        if key != "items_raw":
            ch[key] = section(title)
    ch["crux"] = " ".join(ch["crux"].split())
    head = re.search(r'^#\s*D\d\d.*?\n(.*?)(?=\n##\s)', t, re.S | re.M)
    ch["intro"] = head.group(1).strip() if head else ""
    ch["domain_meta"] = {k: meta_field(ch["intro"], k) for k in
                         ["Phases", "Milestones", "VRT ceiling", "Primary attacker model", "Maps to"]}

    items = []
    for blk in re.split(r'\n(?=###\s+(?:SANE-)?D\d\d-)', t):
        h = re.match(r'###\s+((?:SANE-)?D\d\d-\d+)\s*[·\-]\s*(.+)', blk)
        if not h:
            continue
        iid = h.group(1).replace("SANE-", "")
        body = blk[blk.index("\n"):].strip() if "\n" in blk else ""
        # cut the body at the next '## ' section so the last item does not swallow the graveyard
        body = cut_at_next_section(body)
        meta = {k: meta_field(blk, k) for k in META_FIELDS}
        fields = split_body_fields(body)
        full = "\n".join(fields.values())
        sev, sev_floor, sev_note = parse_severity(meta["Severity ceiling"])
        item = {
            "id": iid, "domain": did, "title": h.group(2).strip(),
            "severity": sev, "severity_floor": sev_floor, "severity_note": sev_note,
            "vrt": meta["VRT"], "vrt_priority": vrt_priority(meta["VRT"]),
            "attacker": meta["Attacker"],
            "attacker_ids": sorted(set(re.findall(r'AM-\d\d', meta["Attacker"]))),
            "applies_to": meta["Applies to"],
            "maps_to": meta["Maps to"],
            "prerequisites": meta["Prerequisites"], "depends_on": meta["Depends on"],
            "evidence": meta["Evidence"], "cost": meta["Cost"],
            "ids": ids_in(meta["Maps to"] + " " + meta["VRT"]),
            "xrefs": sorted(set(x for x in re.findall(r'\bD\d\d-\d{3}\b', full) if x != iid)),
            "domain_refs": sorted(set(re.findall(r'\bD\d\d\b', full)) - {did}),
            "has_code": "```" in body,
            "body_md": body,
        }
        item.update({k: fields.get(k, "") for k in BODY_KEYS.values()})
        items.append(item)
    ch["items"] = items
    return ch


def md_escape_cell(s):
    return s.replace("|", "\\|").replace("\n", " ")


def short(s, n):
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def write_outputs(chapters, root):
    os.makedirs(os.path.join(root, "cards"), exist_ok=True)
    os.makedirs(os.path.join(root, "json"), exist_ok=True)
    total = sum(len(c["items"]) for c in chapters)
    sev_all = collections.Counter(i["severity"] for c in chapters for i in c["items"])
    stamp = datetime.date.today().isoformat()

    # ── checklist.csv (slim tracker) ─────────────────────────────────────────
    cols = ["item_id", "domain", "phase", "title", "severity_ceiling", "severity_floor", "attacker_model",
            "vrt_priority", "applies_to", "completed", "result", "finding_id", "evidence", "notes"]
    with open(os.path.join(root, "checklist.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols); w.writeheader()
        for c in chapters:
            ph, _ = PHASE.get(c["id"], ("P4", "M4"))
            for i in c["items"]:
                w.writerow({"item_id": i["id"], "domain": c["id"], "phase": ph, "title": i["title"],
                            "severity_ceiling": i["severity"], "severity_floor": i["severity_floor"],
                            "attacker_model": "/".join(i["attacker_ids"]) or "n/a",
                            "vrt_priority": i["vrt_priority"], "applies_to": short(i["applies_to"], 160),
                            "completed": "false", "result": "", "finding_id": "", "evidence": "", "notes": ""})

    # ── json/Dnn.json + json/index.json ──────────────────────────────────────
    index = {"generated": stamp, "total_items": total, "domains": {}, "items": {}}
    for c in chapters:
        ph, ms = PHASE.get(c["id"], ("P4", "M4"))
        c_out = dict(c); c_out["phase"] = ph; c_out["milestone"] = ms
        with open(os.path.join(root, "json", c["id"] + ".json"), "w", encoding="utf-8") as f:
            json.dump(c_out, f, ensure_ascii=False, indent=1)
        index["domains"][c["id"]] = {"name": c["name"], "file": c["file"], "phase": ph, "milestone": ms,
                                     "items": len(c["items"]), "crux": c["crux"],
                                     "card": "cards/%s.md" % c["id"], "json": "json/%s.json" % c["id"]}
        for i in c["items"]:
            index["items"][i["id"]] = {"domain": c["id"], "title": i["title"], "severity": i["severity"], "severity_floor": i["severity_floor"],
                                       "attacker": "/".join(i["attacker_ids"]) or "n/a",
                                       "vrt_priority": i["vrt_priority"], "phase": ph}
    with open(os.path.join(root, "json", "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)

    # ── cards/Dnn.md ─────────────────────────────────────────────────────────
    for c in chapters:
        ph, ms = PHASE.get(c["id"], ("P4", "M4"))
        cnt = collections.Counter(i["severity"] for i in c["items"])
        L = []; A = L.append
        A(f"# {c['id']} · {c['name']} — card\n")
        A(f"> Generated from [`checklist/{c['file']}`](../checklist/{c['file']}). {len(c['items'])} items · phase **{ph}** · "
          + " · ".join(f"{E[s]} {cnt[s]}" for s in SEV_ORDER if cnt.get(s)) + "\n")
        A("> Open one item in full: `python3 scripts/item.py " + c["items"][0]["id"] + "`. "
          "Load this card to decide applicability and order; load items one at a time to execute.\n")
        if c["crux"]:
            A(f"**Crux question.** {c['crux']}\n")
        if c.get("applicability"):
            A("## Applicability probe\n"); A(c["applicability"] + "\n")
        if c["triage"]:
            A("## Triage order\n"); A(c["triage"] + "\n")
        A("## Items\n")
        A("| ID | Ceiling | VRT | Attacker | Title | Applies to |")
        A("|---|---|---|---|---|---|")
        for i in c["items"]:
            sevcell = "%s %s" % (E[i["severity"]], i["severity"]) + ("" if i["severity_floor"] == i["severity"] else " (%s alone)" % i["severity_floor"])
            A("| `%s` | %s | %s | %s | %s | %s |" % (
                i["id"], sevcell, i["vrt_priority"],
                "/".join(i["attacker_ids"]) or "n/a", md_escape_cell(i["title"]),
                md_escape_cell(short(i["applies_to"], 90))))
        if c["graveyard"]:
            A("\n## Graveyard — do not submit these standalone\n"); A(c["graveyard"] + "\n")
        if c["joins"]:
            A("\n## Cross-surface joins — park now, chase in P7\n"); A(c["joins"] + "\n")
        open(os.path.join(root, "cards", c["id"] + ".md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # ── MASTER-CHECKLIST.md (compact, grep-oriented) ─────────────────────────
    L = []; A = L.append
    A("# MASTER CHECKLIST — compact view\n")
    A(f"> {total} items · {len(chapters)} domains · generated {stamp}. One line per item, for `grep`. "
      "To work a domain load `cards/Dnn.md`; to run an item use `python3 scripts/item.py Dnn-NNN`.\n")
    A("| | Items |"); A("|---|---|")
    for s in SEV_ORDER:
        if sev_all.get(s): A(f"| {E[s]} **{s.title()}** | {sev_all[s]} |")
    A(f"| | **{total} total** |\n")
    for c in chapters:
        ph, ms = PHASE.get(c["id"], ("P4", "M4"))
        A(f"\n## {c['id']} {c['name']} — {ph} · {len(c['items'])} items · [card](cards/{c['id']}.md) · [chapter](checklist/{c['file']})\n")
        if c["crux"]: A(f"> {c['crux']}\n")
        for i in c["items"]:
            A(f"- [ ] `{i['id']}` {E[i['severity']]} {i['vrt_priority']} {('/'.join(i['attacker_ids']) or 'n/a')} — {i['title']}")
    open(os.path.join(root, "MASTER-CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # ── CHECKLIST.md index ───────────────────────────────────────────────────
    I = []; B = I.append
    B("# CHECKLIST.md — domain index\n")
    B(f"> {total} test items across {len(chapters)} domains, generated {stamp} from `checklist/`. "
      "Per-domain cards: [`cards/`](cards/) · per-item lookup: `python3 scripts/item.py Dnn-NNN` · "
      "machine view: [`json/`](json/) · tracker: [`checklist.csv`](checklist.csv) · grep view: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)\n")
    B("| Domain | Phase | Items | Ceiling mix | Card | Chapter |")
    B("|---|---|---|---|---|---|")
    for c in chapters:
        ph, _ = PHASE.get(c["id"], ("P4", "M4"))
        cnt = collections.Counter(i["severity"] for i in c["items"])
        mix = " ".join(f"{E[s]}{cnt[s]}" for s in SEV_ORDER if cnt.get(s))
        B(f"| **{c['id']}** {c['name']} | {ph} | {len(c['items'])} | {mix} | [card](cards/{c['id']}.md) | [`{c['file']}`](checklist/{c['file']}) |")
    B(f"\n**Total: {total} items** — " + " · ".join(f"{E[s]} {sev_all[s]} {s}" for s in SEV_ORDER if sev_all.get(s)))
    B("\n## The crux question for each domain\n")
    B("The single question that decides whether a domain has a bug in this app. Ask it before running anything.\n")
    for c in chapters:
        if c["crux"]: B(f"- **{c['id']}** — {c['crux']}")
    B("\n## Phase → domains\n")
    byph = collections.defaultdict(list)
    for c in chapters: byph[PHASE.get(c["id"], ("P4", "M4"))[0]].append(c["id"])
    B("| Phase | Domains |"); B("|---|---|")
    for p in sorted(byph): B(f"| {p} | {' '.join(byph[p])} |")
    B("\n## Related\n")
    B("| | |\n|---|---|")
    B("| [`START.md`](START.md) | The operator entry point and state machine |")
    B("| [`ISSUES.md`](ISSUES.md) | The ordered phase workflow |")
    B("| [`AGENTS.md`](AGENTS.md) | The SOP |")
    B("| [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md) | Breadth before depth |")
    B("| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding |")
    open(os.path.join(root, "CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(I) + "\n")
    return total, sev_all


def main():
    check = "--check" in sys.argv
    chapters = [parse_chapter(p) for p in sorted(glob.glob(os.path.join(CH, "D*.md")))]
    chapters = [c for c in chapters if c["items"]]
    if not chapters:
        print("no chapters with items found in", CH); sys.exit(1)
    out_root = tempfile.mkdtemp(prefix="build_") if check else ROOT
    if check:
        shutil.copytree(DATA, os.path.join(out_root, "data"))
    total, sev_all = write_outputs(chapters, out_root)
    print(f"  {total} items · {len(chapters)} domains · severity {dict(sev_all)}")
    missing = [d for d in PHASE if d not in {c['id'] for c in chapters}]
    if missing: print("  !! chapters referenced in PHASE but missing:", " ".join(sorted(missing)))
    if check:
        diffs = []
        for rel in ["checklist.csv", "MASTER-CHECKLIST.md", "CHECKLIST.md"] + \
                   ["cards/%s.md" % c["id"] for c in chapters] + ["json/%s.json" % c["id"] for c in chapters]:
            a, b = os.path.join(ROOT, rel), os.path.join(out_root, rel)
            if not os.path.exists(a) or not filecmp.cmp(a, b, shallow=False):
                diffs.append(rel)
        shutil.rmtree(out_root, True)
        if diffs:
            print("  !! generated outputs are STALE — run scripts/build-checklist.py and commit:", *diffs[:10])
            sys.exit(1)
        print("  generated outputs are current")


if __name__ == "__main__":
    main()
