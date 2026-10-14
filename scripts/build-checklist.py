#!/usr/bin/env python3
"""build-checklist.py — compile the domain chapters into every machine-consumable view.

The chapters under checklist/D*.md are the single source of truth. Everything below is GENERATED
from them and must never be hand-edited (CI rebuilds and diffs).

  CHECKLIST.md            the index: one row per domain, crux questions, applicability probes
  cards/Dnn.md            one compact card per domain: one line per item (id · ceiling · attacker ·
                          title · applies-to). ~10-20 KB each. THIS is what an agent loads to work a
                          domain; it opens individual items with scripts/item.py.
  json/Dnn.json           every field of every item in the domain, fully parsed (skip-when/test/how/
                          proof/escalation/ruled-out-when, metadata, normalised ids, cross-references)
  json/index.json         every item id → domain, title, ceiling, attacker, phase, vrt priority
  checklist.csv           the slim coverage tracker. Copied into each engagement as
                          checklist-status.csv; the agent flips completed/result per row.
  MASTER-CHECKLIST.md     one line per item across all domains. For grep, not for reading end-to-end.

The item schema (metadata rows, body fields, the VRT and severity cell grammars) is docs/11-item-schema.md;
scripts/lint-checklist.py imports this module so the gate and the generator parse the same way.

Run from anywhere:  python3 scripts/build-checklist.py [--check]
  --check   build to a temp dir and exit 1 if the committed outputs differ (CI mode)
"""
import argparse, csv, glob, json, os, re, sys, collections, tempfile, filecmp, shutil, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CH = os.path.join(ROOT, "checklist")
DATA = os.path.join(ROOT, "data")

SEV_ORDER = ["critical", "high", "medium", "low", "support", "varies", "?"]
E = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "support": "⬜", "varies": "🔷", "?": "❔"}

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

# docs/11 §1 — the ONE schema the generator, the linter, item.py and apply-item-meta.py share.
META_FIELDS = ["Severity ceiling", "VRT", "Attacker", "Applies to", "Requires", "Maps to", "Record"]
META_LEGACY = ["Prerequisites", "Depends on", "Evidence", "Cost"]      # deprecated (docs/11 §7): parsed, kept only when non-empty
BODY_FIELDS = ["Skip when", "Test", "How", "Proof", "Escalation", "Ruled out when"]
BODY_KEYS = {"Skip when": "skip_when", "Test": "test", "How": "how", "Proof": "proof",
             "Escalation": "escalation", "Ruled out when": "ruled_out_when"}
# '- **Record:**' as a body bullet is the pre-docs/11 form of the Record row: still split off, folded into the row.
BODY_SPLIT = BODY_FIELDS + ["Record"]

SECTION_KEYS = {
    "Why this domain pays": "why", "The crux question": "crux", "Applicability probe": "applicability",
    "Triage order": "triage", "Items": "items_raw", "Graveyard for this domain": "graveyard",
    "Cross-surface joins": "joins", "Sources": "sources",
}

NOTES = []   # parse-time complaints the build prints (the linter reports the same facts as errors/warnings)


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


def section(text, title):
    """The body of '## <title>' up to the next '## ' heading, with the same fence awareness as cut_at_next_section
    (a '## ' line inside a code block is not a heading)."""
    out, fence, on = [], False, False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            fence = not fence
        if not fence and re.match(r"^##\s", line):
            if on:
                break
            on = re.match(r"^##\s*%s\s*$" % re.escape(title), line) is not None
            continue
        if on:
            out.append(line)
    return "\n".join(out).strip()


LEVELS = ["critical", "high", "medium", "low", "support"]
RANK = {l: i for i, l in enumerate(LEVELS)}


def parse_severity(cell):
    """docs/11 §3. The chapters write nuanced cells ('Medium standalone; High with a reach primitive',
    'High (debug certificate) / Low (SHA1withRSA alone)', 'Critical … down to Low'). Return
    (ceiling, floor, note): ceiling = the MOST severe level the cell names, floor = the LEAST severe level it
    names (the standalone level; equal to the ceiling when only one level is named), note = the raw cell.
    'varies' when the cell defers to another item/advisory; '?' when the cell is empty (the linter errors)."""
    raw = (cell or "").strip()
    if not raw:
        return "?", "?", raw
    low = raw.replace("**", "").lower().replace("informational", "support")
    found = re.findall(r"\b(critical|high|medium|low|support)\b", low)
    if not found:
        if re.search(r"not a finding|procedure|technique|tooling", low):
            return "support", "support", raw
        if re.search(r"varies|inherit|per (sink|advisory|the)|by the|rated (on|per)|n/a|depends", low):
            return "varies", "varies", raw
        return "support", "support", raw
    levels = sorted(set(found), key=lambda x: RANK[x])                # most severe first
    ceiling = "support" if found[0] == "support" else levels[0]       # 'Support — never standalone…' stays support
    floor = levels[-1] if len(levels) > 1 else ceiling
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


def source_digest():
    """A content digest of everything the outputs are generated from (the chapters and the VRT table). It replaces
    the old date stamp: a date made `--check` fail on every day except the generation day, which turned the CI
    staleness gate into a false positive. The digest changes exactly when a source changes."""
    h = hashlib.sha256()
    for p in sorted(glob.glob(os.path.join(CH, "D*.md"))) + [os.path.join(DATA, "vrt.csv")]:
        if os.path.exists(p):
            h.update(os.path.basename(p).encode()); h.update(b"\0"); h.update(open(p, "rb").read()); h.update(b"\0")
    return h.hexdigest()[:12]


VRT = load_vrt()
VRT_CATEGORIES = {k.split(".")[0] for k in VRT}
PRIO_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5, "varies": 6}
# a backticked taxonomy path; '...suffix' is the chapters' shorthand for "the sibling node under the same parent"
VRT_PATH = re.compile(r'`(\.\.\.)?([a-z_]+(?:\.[a-z0-9_]+)*)`([^`]*)')
VRT_STATED = re.compile(r'\(\s*\**\s*(P[1-5]|varies|null)\b')
VRT_NA = re.compile(r'^\s*(n/a|none|—|-)(\W|$)', re.I)
VRT_INHERIT = re.compile(r'\b(as D\d\d-\d{3}|see D\d\d-\d{3}|inherits?\b|governs\b|consequence-rated|routes? to\b|routed to\b)', re.I)
VRT_VARIES = re.compile(r'\b(varies|rated? on\b|depends on\b|outcome-rated|per the\b|whichever\b|no (?:dedicated|standalone) (?:vrt )?(?:node|leaf)|rate with\b)', re.I)


def meta_field(blk, name):
    m = re.search(r'^\|\s*\*\*%s\*\*\s*\|\s*(.*?)\s*\|\s*$' % re.escape(name), blk, re.M)
    return m.group(1).strip() if m else ""


def split_body_fields(body):
    """Return {key: text} for the '- **Field:**' bullets. Continuation lines are de-indented by the two spaces
    the bullet adds, EXCEPT inside a column-0 code fence, whose bytes are kept exactly as the chapter wrote them
    (an indented fence is de-indented together with its content)."""
    out = {}
    pat = re.compile(r'^- \*\*(%s):?\*\*:?\s*' % "|".join(re.escape(f) for f in BODY_SPLIT), re.M)
    marks = list(pat.finditer(body))
    for i, m in enumerate(marks):
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        txt = body[start:end].rstrip()
        out_l, in_fence, fence_indented = [], False, False
        for l in txt.split("\n"):
            if l.strip().startswith("```"):
                fence_indented = l.startswith("  ") if not in_fence else fence_indented
                in_fence = not in_fence
                out_l.append(l[2:] if l.startswith("  ") else l)
                continue
            if in_fence and not fence_indented:
                out_l.append(l)
            else:
                out_l.append(l[2:] if l.startswith("  ") else l)
        key = BODY_KEYS.get(m.group(1), "record")
        out[key] = "\n".join(out_l).strip()
    return out


def vrt_pairs(vrt_text):
    """[(path, priority)] in reading order (docs/11 §1 grammar). The priority is the '(Pn)' / '(**Pn**)' /
    '(varies)' / '(null)' stated after the path and before the next backticked path; when none is stated it is
    looked up in data/vrt.csv. 'null' is the VRT json's own spelling of a varies node."""
    pairs = []
    for m in VRT_PATH.finditer(vrt_text):
        ell, path, tail = m.group(1), m.group(2), m.group(3)
        if not ell and "." not in path:
            continue
        pm = VRT_STATED.search(tail)
        pr = pm.group(1) if pm else ("" if ell else VRT.get(path, ""))
        pairs.append((("..." if ell else "") + path, "varies" if pr == "null" else pr))
    return pairs


def vrt_priority(vrt_text):
    """(first, best) for a VRT cell. first = the priority of the FIRST path (the node the Proof lands on,
    docs/11 §1), best = the highest priority among every path named. Prose forms: the 'n/a' family → 'n/a';
    'as Dnn-NNN' / 'inherits …' / 'governs …' / 'consequence-rated' / 'routes to …' → 'inherit' (suffixed with
    the partner id when one is named); 'varies' / 'rated on …' / 'depends on …' → 'varies'; anything else '?'
    (the linter warns: the cell is outside the grammar)."""
    txt = (vrt_text or "").strip()
    pairs = [(p, pr) for p, pr in vrt_pairs(txt) if pr]
    if pairs:
        first = pairs[0][1]
        best = min((pr for _, pr in pairs), key=lambda x: PRIO_RANK.get(x, 9))
        return first, best
    pm = VRT_STATED.search(txt)                       # a stated priority without a backticked path
    if pm:
        v = "varies" if pm.group(1) == "null" else pm.group(1)
        return v, v
    if not txt or VRT_NA.match(txt):
        return "n/a", "n/a"
    if VRT_INHERIT.search(txt):
        ref = re.search(r'\bD\d\d(?:-\d{3})?\b', txt)
        v = "inherit:" + ref.group(0) if ref else "inherit"
        return v, v
    if VRT_VARIES.search(txt):
        return "varies", "varies"
    return "?", "?"


def expand_std_ids(text):
    """Rewrite the shorthand id lists the chapters use — 'MASTG-TEST-0224, -0225', 'MASTG-TEST-0304/0305',
    'MASWE-0003, -0004', 'MASVS-AUTH-1/2/3' — as full ids, so that one regex finds every cited id. Shared with
    scripts/lint-checklist.py (and the same grammar as scripts/standards_builder.py)."""
    def four(m):
        pre, first, rest = m.group(1), m.group(2), m.group(3) or ""
        return pre + first + "".join(" " + pre + n for n in re.findall(r'\d{4}', rest))
    text = re.sub(r'\b(MASTG-[A-Z]+-|MASWE-)(\d{4})((?:\s*,\s*-\d{4}(?!\d)|\s*/\s*\d{4}(?!\d))+)', four, text)
    text = re.sub(r'\b(MASVS-[A-Z]+-)(\d)((?:\s*/\s*\d(?!\d))+)',
                  lambda m: m.group(1) + m.group(2) + "".join(" " + m.group(1) + d for d in re.findall(r'\d', m.group(3))), text)
    return text


def ids_in(text):
    text = expand_std_ids(text)
    return {
        "mastg": sorted(set(re.findall(r'MASTG-[A-Z]+-\d{4}', text))),
        "maswe": sorted(set(re.findall(r'MASWE-\d{4}', text))),
        "masvs": sorted(set(re.findall(r'MASVS-[A-Z]+-\d', text))),
        "rules": sorted(set(re.sub(r'\.ya?ml$', '', x) for x in re.findall(r'\bmastg-android-[a-z0-9-]+(?:\.ya?ml)?', text))),
        "cwe": sorted(set(re.findall(r'CWE-\d+', text))),
        "attack": sorted(set(re.findall(r'\bT1\d{3}(?:\.\d{3})?\b', text))),
        "vrt": sorted(p for p in set(re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', text)) if p.split(".")[0] in VRT_CATEGORIES),
    }


def requires_tags(cell):
    return [x.strip().lower() for x in (cell or "").replace("`", "").split(",") if x.strip()]


def parse_chapter(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r'^#\s*(D\d\d)\s*[·\-]\s*(.+)$', t, re.M)
    did = m.group(1) if m else os.path.basename(path)[:3]
    name = m.group(2).strip() if m else ""

    ch = {"id": did, "name": name, "file": os.path.basename(path)}
    for title, key in SECTION_KEYS.items():
        if key != "items_raw":
            ch[key] = section(t, title)
    ch["crux"] = " ".join(ch["crux"].split())
    head = re.search(r'^#\s*D\d\d.*?\n(.*?)(?=\n##\s)', t, re.S | re.M)
    ch["intro"] = head.group(1).strip() if head else ""
    ch["domain_meta"] = {k: meta_field(ch["intro"], k) for k in
                         ["Phases", "Milestones", "VRT ceiling", "Primary attacker model", "Maps to"]}

    items = []
    for blk in re.split(r'\n(?=###\s+(?:SANE-)?D\d\d-)', t):
        h = re.match(r'###\s+((?:SANE-)?D\d\d-\d+)\s*[·\-]\s*(.+)', blk)
        if not h:
            if re.match(r'###\s+(?:SANE-)?D\d\d-\d+', blk):
                NOTES.append(f"!! {did}: unparseable item heading (use '### Dnn-NNN · Title'): {blk.splitlines()[0][:70]}")
            continue
        iid = h.group(1).replace("SANE-", "")
        body = blk[blk.index("\n"):].strip() if "\n" in blk else ""
        # cut the body at the next '## ' section so the last item does not swallow the graveyard
        body = cut_at_next_section(body)
        meta = {k: meta_field(blk, k) for k in META_FIELDS + META_LEGACY}
        fields = split_body_fields(body)
        record = meta["Record"] or fields.pop("record", "")
        sev, sev_floor, sev_note = parse_severity(meta["Severity ceiling"])
        if sev == "?":
            NOTES.append(f"!! {iid}: empty Severity ceiling cell")
        vfirst, vbest = vrt_priority(meta["VRT"])
        legacy = {k: meta[k] for k in META_LEGACY if meta[k]}
        # cross-references: every field a model reads, body and metadata alike
        full = "\n".join(list(fields.values()) + [meta["Applies to"], meta["Requires"], meta["Maps to"], record] + list(legacy.values()))
        item = {
            "id": iid, "domain": did, "title": h.group(2).strip(),
            "severity": sev, "severity_floor": sev_floor, "severity_note": sev_note,
            "vrt": meta["VRT"], "vrt_priority": vfirst, "vrt_best": vbest,
            "attacker": meta["Attacker"],
            "attacker_ids": sorted(set(re.findall(r'AM-\d\d', meta["Attacker"]))),
            "applies_to": meta["Applies to"],
            "requires": meta["Requires"], "requires_tags": requires_tags(meta["Requires"]),
            "maps_to": meta["Maps to"],
            "record": record,
            "legacy_meta": legacy,
            "ids": ids_in(meta["Maps to"] + " " + meta["VRT"]),
            "xrefs": sorted(set(x for x in re.findall(r'\bD\d\d-\d{3}\b', full) if x != iid)),
            "domain_refs": sorted(set(re.findall(r'\bD\d\d\b', full)) - {did}),
            "has_code": "```" in body,
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


def vrt_cell(i):
    """'P3' or 'P3 ↑P1' when a later-named node rates higher than the node the Proof lands on."""
    return i["vrt_priority"] + ("" if i["vrt_best"] == i["vrt_priority"] else " ↑" + i["vrt_best"])


def write_outputs(chapters, root):
    os.makedirs(os.path.join(root, "cards"), exist_ok=True)
    os.makedirs(os.path.join(root, "json"), exist_ok=True)
    total = sum(len(c["items"]) for c in chapters)
    sev_all = collections.Counter(i["severity"] for c in chapters for i in c["items"])
    stamp = source_digest()

    # ── checklist.csv (slim tracker) ─────────────────────────────────────────
    cols = ["item_id", "domain", "phase", "title", "severity_ceiling", "severity_floor", "attacker_model",
            "vrt_priority", "vrt_best", "applies_to", "requires", "completed", "result", "finding_id", "evidence", "notes"]
    with open(os.path.join(root, "checklist.csv"), "w", newline="", encoding="utf-8") as f:
        # LF, not the csv module's default CRLF: the repo is LF and a stray \r leaks into cut/grep pipelines
        w = csv.DictWriter(f, cols, lineterminator="\n"); w.writeheader()
        for c in chapters:
            ph, _ = PHASE.get(c["id"], ("P4", "M4"))
            for i in c["items"]:
                w.writerow({"item_id": i["id"], "domain": c["id"], "phase": ph, "title": i["title"],
                            "severity_ceiling": i["severity"], "severity_floor": i["severity_floor"],
                            "attacker_model": "/".join(i["attacker_ids"]) or "n/a",
                            "vrt_priority": i["vrt_priority"], "vrt_best": i["vrt_best"],
                            "applies_to": short(i["applies_to"], 160), "requires": ", ".join(i["requires_tags"]),
                            "completed": "false", "result": "", "finding_id": "", "evidence": "", "notes": ""})

    # ── json/Dnn.json + json/index.json ──────────────────────────────────────
    index = {"source_digest": stamp, "total_items": total, "domains": {}, "items": {}}
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
                                       "vrt_priority": i["vrt_priority"], "vrt_best": i["vrt_best"],
                                       "requires": i["requires_tags"], "phase": ph}
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
                i["id"], sevcell, vrt_cell(i),
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
    A(f"> {total} items · {len(chapters)} domains · generated from `checklist/` (source digest `{stamp}`). One line per item, for `grep`. "
      "To work a domain load `cards/Dnn.md`; to run an item use `python3 scripts/item.py Dnn-NNN`. "
      "Coverage lives in `<engagement>/checklist-status.csv` (`scripts/mark.py`); never tick anything here.\n")
    A("| | Items |"); A("|---|---|")
    for s in SEV_ORDER:
        if sev_all.get(s): A(f"| {E[s]} **{s.title()}** | {sev_all[s]} |")
    A(f"| | **{total} total** |\n")
    # Contents + explicit anchors. GitHub slugs a heading from its rendered text (punctuation dropped, nothing
    # collapsed), so a slug computed here drifts whenever the heading carries ' — ', '·', '&' or links; an
    # explicit <a id> is renderer-independent. The blank line after the anchor keeps the heading a heading.
    A("**Contents:** " + " · ".join(f"[{c['id']}](#{c['id'].lower()})" for c in chapters) + "\n")
    for c in chapters:
        ph, ms = PHASE.get(c["id"], ("P4", "M4"))
        A(f'\n<a id="{c["id"].lower()}"></a>\n')
        A(f"## {c['id']} {c['name']} — {ph} · {len(c['items'])} items · [card](cards/{c['id']}.md) · [chapter](checklist/{c['file']})\n")
        if c["crux"]: A(f"> {c['crux']}\n")
        for i in c["items"]:
            A(f"- `{i['id']}` {E[i['severity']]} {vrt_cell(i)} {('/'.join(i['attacker_ids']) or 'n/a')} — {i['title']}")
    open(os.path.join(root, "MASTER-CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # ── CHECKLIST.md index ───────────────────────────────────────────────────
    I = []; B = I.append
    B("# CHECKLIST.md — domain index\n")
    B(f"> {total} test items across {len(chapters)} domains, generated from `checklist/` (source digest `{stamp}`). "
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
    B("| [`ISSUES.md`](ISSUES.md) | How the GitHub tracker mirrors these files |")
    B("| [`AGENTS.md`](AGENTS.md) | The SOP |")
    B("| [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md) | Breadth before depth |")
    B("| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding |")
    open(os.path.join(root, "CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(I) + "\n")
    return total, sev_all


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="build to a temp dir and exit 1 if the committed outputs differ (CI mode)")
    args = ap.parse_args()
    check = args.check
    chapters = [parse_chapter(p) for p in sorted(glob.glob(os.path.join(CH, "D*.md")))]
    for n in NOTES:
        print(" ", n)
    empty = [c["id"] for c in chapters if not c["items"]]
    if empty:
        print("  !! chapters with 0 parseable items (a heading separator other than '·' or '-'?):", *empty); sys.exit(1)
    if not chapters:
        print("no chapters found in", CH); sys.exit(1)
    out_root = tempfile.mkdtemp(prefix="build_") if check else ROOT
    if check:
        shutil.copytree(DATA, os.path.join(out_root, "data"))
    total, sev_all = write_outputs(chapters, out_root)
    print(f"  {total} items · {len(chapters)} domains · severity {dict(sev_all)}")
    missing = [d for d in PHASE if d not in {c['id'] for c in chapters}]
    if missing: print("  !! chapters referenced in PHASE but missing:", " ".join(sorted(missing)))
    noprobe = [c["id"] for c in chapters if not c.get("applicability")]
    if noprobe: print(f"  !! {len(noprobe)}/{len(chapters)} chapters without a '## Applicability probe' (docs/11 §2):", " ".join(noprobe))
    if check:
        diffs = []
        for rel in ["checklist.csv", "MASTER-CHECKLIST.md", "CHECKLIST.md", "json/index.json"] + \
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
