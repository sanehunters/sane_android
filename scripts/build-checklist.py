#!/usr/bin/env python3
"""build-checklist.py — generate the single master checklist from the 27 domain chapters.

Outputs, at the repository root:

  MASTER-CHECKLIST.md   every item from every domain, in one file, with its full body.
                        This is the one file an agent reads to know everything it must test.
  checklist.csv         one row per item, machine-readable. Copied into each engagement as
                        checklist-status.csv, where every row is flipped true/false.
  CHECKLIST.md          the navigable index: per-domain counts, severity mix, crux questions.

Run from anywhere:  python3 scripts/build-checklist.py
"""
import csv, glob, os, re, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CH   = os.path.join(ROOT, "checklist")

SEV_ORDER = ["critical", "high", "medium", "low", "support"]
E = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "support": "⬜"}

# domain -> (phase, milestone)
PHASE = {
 "D01": ("P3", "M3"), "D02": ("P2", "M2"), "D03": ("P3", "M3"), "D04": ("P5", "M5"),
 "D05": ("P5", "M5"), "D06": ("P5", "M5"), "D07": ("P5", "M5"), "D08": ("P5", "M5"),
 "D09": ("P5", "M5"), "D10": ("P5", "M5"), "D11": ("P4", "M4"), "D12": ("P4", "M4"),
 "D13": ("P6", "M6"), "D14": ("P6", "M6"), "D15": ("P6", "M6"), "D16": ("P4", "M4"),
 "D17": ("P4", "M4"), "D18": ("P6", "M6"), "D19": ("P4", "M4"), "D20": ("P4", "M4"),
 "D21": ("P4", "M4"), "D22": ("P4", "M4"), "D23": ("P6", "M6"), "D24": ("P6", "M6"),
 "D25": ("P5", "M5"), "D26": ("P1", "M1"), "D27": ("P9", "M9"),
}

FIELD = lambda blk, name: (
    (re.search(r'\|\s*\*\*%s\*\*\s*\|\s*(.+?)\s*\|' % re.escape(name), blk) or [None, ""])[1]
    if re.search(r'\|\s*\*\*%s\*\*\s*\|' % re.escape(name), blk) else "")


def parse_chapter(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r'^#\s*(D\d\d)\s*[·\-]\s*(.+)$', t, re.M)
    did  = m.group(1) if m else os.path.basename(path)[:3]
    name = m.group(2).strip() if m else ""

    def section(title):
        mm = re.search(r'^##\s*%s\s*\n+(.+?)(?=\n##\s|\Z)' % re.escape(title), t, re.S | re.M)
        return mm.group(1).strip() if mm else ""

    crux = " ".join(section("The crux question").split())
    why  = section("Why this domain pays")
    triage = section("Triage order")
    grave  = section("Graveyard for this domain")
    joins  = section("Cross-surface joins")
    sources = section("Sources")

    items = []
    for blk in re.split(r'\n(?=###\s+(?:SANE-)?D\d\d-)', t):
        h = re.match(r'###\s+((?:SANE-)?D\d\d-\d+)\s*[·\-]\s*(.+)', blk)
        if not h:
            continue
        iid = h.group(1).replace("SANE-", "")
        body = blk[blk.index("\n"):].strip() if "\n" in blk else ""
        sev = (FIELD(blk, "Severity ceiling") or "support").strip().lower()
        sev = sev if sev in SEV_ORDER else "support"
        items.append(dict(
            id=iid, title=h.group(2).strip(), sev=sev,
            vrt=FIELD(blk, "VRT").strip(),
            attacker=FIELD(blk, "Attacker").strip(),
            applies=FIELD(blk, "Applies to").strip(),
            maps=FIELD(blk, "Maps to").strip(),
            body=body,
        ))
    return dict(id=did, name=name, file=os.path.basename(path), crux=crux, why=why,
                triage=triage, grave=grave, joins=joins, sources=sources, items=items)


def one_line(body, field):
    m = re.search(r'-\s*\*\*%s:\*\*\s*(.+?)(?=\n-\s*\*\*|\n##|\Z)' % re.escape(field), body, re.S)
    if not m:
        return ""
    return " ".join(m.group(1).split())


def main():
    chapters = [parse_chapter(p) for p in sorted(glob.glob(os.path.join(CH, "D*.md")))]
    chapters = [c for c in chapters if c["items"]]
    if not chapters:
        print("no chapters with items found in", CH); sys.exit(1)
    total = sum(len(c["items"]) for c in chapters)
    sev_all = collections.Counter(i["sev"] for c in chapters for i in c["items"])

    # ───────────────────────── checklist.csv ─────────────────────────
    cols = ["item_id","domain","domain_name","phase","milestone","title","severity_ceiling",
            "vrt_path","attacker_model","applies_to","maps_to","chapter",
            "completed","result","finding_id","evidence","notes"]
    with open(os.path.join(ROOT, "checklist.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols); w.writeheader()
        for c in chapters:
            ph, ms = PHASE.get(c["id"], ("P4", "M4"))
            for i in c["items"]:
                w.writerow({"item_id": i["id"], "domain": c["id"], "domain_name": c["name"],
                            "phase": ph, "milestone": ms, "title": i["title"],
                            "severity_ceiling": i["sev"], "vrt_path": i["vrt"],
                            "attacker_model": i["attacker"], "applies_to": i["applies"],
                            "maps_to": i["maps"], "chapter": c["file"],
                            "completed": "false", "result": "", "finding_id": "",
                            "evidence": "", "notes": ""})

    # ───────────────────── MASTER-CHECKLIST.md ───────────────────────
    L = []; A = L.append
    A("# MASTER CHECKLIST\n")
    A(f"> **Every test item, from every source, in one file. {total} items across {len(chapters)} domains.**\n")
    A("> **Read this file to know everything you must test.** Each item shows its severity ceiling, the VRT")
    A("> row it aims at, the attacker model and a one-line statement of the test. The exact command, the")
    A("> observable that proves it, the escalation and the mandatory *Ruled out when* mechanism live in the")
    A("> per-domain chapter linked from each section — open that when you actually run the domain.\n")
    A("> **The checklist is the floor, not the ceiling.** You must cover every in-scope item before")
    A("> calling an assessment complete. You are also expected to think past it — park anything novel as")
    A("> a hypothesis and chase it in P7. See [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md).\n")
    A("## Severity ceilings\n")
    A("| | Items |"); A("|---|---|")
    for s in SEV_ORDER:
        if sev_all.get(s): A(f"| {E[s]} **{s.title()}** | {sev_all[s]} |")
    A(f"| | **{total} total** |")
    A("\n> A **Support** item cannot be reported alone — it produces a link in a chain. The entire mobile")
    A("> branch of the Bugcrowd VRT is P5; see [`docs/02`](docs/02-severity-and-reportability.md).\n")

    A("## Contents\n")
    A("| Domain | Phase | Items | Ceiling mix |"); A("|---|---|---|---|")
    for c in chapters:
        ph, _ = PHASE.get(c["id"], ("P4", "M4"))
        cnt = collections.Counter(i["sev"] for i in c["items"])
        mix = " ".join(f"{E[s]}{cnt[s]}" for s in SEV_ORDER if cnt.get(s))
        A(f"| [**{c['id']}** {c['name']}](#{c['id'].lower()}-{re.sub(r'[^a-z0-9]+','-',c['name'].lower()).strip('-')}) | {ph} | {len(c['items'])} | {mix} |")

    A("\n## How to use this file\n")
    A("""1. Copy [`checklist.csv`](checklist.csv) into your engagement as `checklist-status.csv`.
   Every row starts `completed=false`.
2. Work the items in phase order. Flip each row to `true` with a `result` of `finding`,
   `ruled-out`, `blocked` or `n/a`. An `n/a` row **must** carry a reason in `notes`.
3. `Ruled out when` is on every item. It is the field that turns a skipped test into a defensible
   negative — it names the mechanism that closes the item, with `file:line`.
4. Check coverage at any time, and gate escalation on it:

```bash
python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ --gate p7
```
""")

    for c in chapters:
        ph, ms = PHASE.get(c["id"], ("P4", "M4"))
        cnt = collections.Counter(i["sev"] for i in c["items"])
        mix = " · ".join(f"{E[s]} {cnt[s]} {s}" for s in SEV_ORDER if cnt.get(s))
        anchor = c["file"][:-3]
        A(f"\n---\n\n## {c['id']} {c['name']}\n")
        A(f"**Phase {ph} · `{ms}` · {len(c['items'])} items** — {mix}  \n")
        A(f"📄 Full detail, with every command and proof: [`checklist/{c['file']}`](checklist/{c['file']})\n")
        if c["crux"]:
            A(f"> **Crux question.** {c['crux']}\n")
        if c["why"]:
            A(c["why"].split("\n\n")[0] + "\n")
        cur = None
        for i in c["items"]:
            if i["sev"] != cur:
                cur = i["sev"]
                A(f"\n**{E.get(cur,'⬜')} {cur.title()} ceiling**\n")
            bits = []
            v = i["vrt"].strip()
            if v and v.lower() not in ("n/a","none","—","-",""):
                v = re.sub(r'\s*\(P\d\)\s*$', '', v)
                bits.append(f"`{v[:78]}`")
            a = i["attacker"].strip()
            if a and a.lower() not in ("n/a","—","-",""):
                bits.append(re.sub(r'\s+', ' ', a)[:34])
            test = one_line(i["body"], "Test")
            if test:
                bits.append(test[:110] + ("…" if len(test) > 110 else ""))
            tail = ("  \n   <sub>" + " · ".join(bits) + "</sub>") if bits else ""
            A(f"- [ ] **`{i['id']}`** {i['title']}{tail}")
        if c["grave"]:
            A(f"\n<details><summary>⚰️ {c['id']} graveyard — do not submit these standalone</summary>\n")
            A(c["grave"] + "\n\n</details>\n")
        if c["joins"]:
            A(f"\n<details><summary>🔗 {c['id']} cross-surface joins — park these, chase them in P7</summary>\n")
            A(c["joins"] + "\n\n</details>\n")

    master = "\n".join(L) + "\n"
    open(os.path.join(ROOT, "MASTER-CHECKLIST.md"), "w", encoding="utf-8").write(master)

    # ───────────────────────── CHECKLIST.md index ────────────────────
    I = []; B = I.append
    B("# CHECKLIST.md — domain index\n")
    B(f"> {total} test items across {len(chapters)} domains. The merged single-file view is")
    B("> [**MASTER-CHECKLIST.md**](MASTER-CHECKLIST.md); the machine-readable tracker is")
    B("> [`checklist.csv`](checklist.csv).\n")
    B("| Domain | Phase | Items | Ceiling mix | Chapter |")
    B("|---|---|---|---|---|")
    for c in chapters:
        ph, _ = PHASE.get(c["id"], ("P4", "M4"))
        cnt = collections.Counter(i["sev"] for i in c["items"])
        mix = " ".join(f"{E[s]}{cnt[s]}" for s in SEV_ORDER if cnt.get(s))
        B(f"| **{c['id']}** {c['name']} | {ph} | {len(c['items'])} | {mix} | [`{c['file']}`](checklist/{c['file']}) |")
    B(f"\n**Total: {total} items** — " + " · ".join(f"{E[s]} {sev_all[s]} {s}" for s in SEV_ORDER if sev_all.get(s)))
    B("\n## The crux question for each domain\n")
    B("The single question that decides whether a domain has a bug in this app. Ask it before running anything.\n")
    for c in chapters:
        if c["crux"]: B(f"- **{c['id']}** — {c['crux']}")
    B("\n## Related\n")
    B("| | |\n|---|---|")
    B("| [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md) | **Every item in one file** |")
    B("| [`checklist.csv`](checklist.csv) | Machine-readable tracker |")
    B("| [`ISSUES.md`](ISSUES.md) | The ordered phase workflow |")
    B("| [`AGENTS.md`](AGENTS.md) | The SOP |")
    B("| [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md) | Breadth before depth |")
    B("| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding |")
    open(os.path.join(ROOT, "CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(I) + "\n")

    size = len(master.encode()) / 1024
    print(f"  MASTER-CHECKLIST.md  {total} items, {len(chapters)} domains, {size:.0f} KB")
    print(f"  checklist.csv        {total} rows")
    print(f"  CHECKLIST.md         index")
    print("  severity:", dict(sev_all))
    missing = [d for d in PHASE if d not in {c['id'] for c in chapters}]
    if missing: print("  !! chapters still missing:", " ".join(sorted(missing)))


if __name__ == "__main__":
    main()
