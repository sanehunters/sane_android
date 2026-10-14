#!/usr/bin/env python3
"""apply-item-meta.py — apply per-item metadata and text changes to a chapter from compact JSON.

Lets a maintainer (human or model) change dozens of items without rewriting a 200 KB chapter by hand:

  python3 scripts/apply-item-meta.py changes.json            apply
  python3 scripts/apply-item-meta.py changes.json --dry-run  report what would change
  python3 scripts/apply-item-meta.py changes.json --build    apply, then run lint-checklist.py and build-checklist.py

The chapter is the source; the generated views (cards/, json/, checklist.csv, CHECKLIST.md, MASTER-CHECKLIST.md)
lag it until rebuilt. After a write ALWAYS run
    python3 scripts/lint-checklist.py && python3 scripts/build-checklist.py
(or pass --build) and commit the chapter and the views together. Schema: docs/11-item-schema.md.

changes.json:
{
  "domain": "D10",
  "items": {
    "D10-004": {
      "requires": "webview, js-bridge",                      # sets/inserts the | **Requires** | row (after Applies to)
      "record":   "logs/D10-004.txt; screenshots/D10-004-1.png",   # sets/inserts | **Record** | (after Maps to)
      "skip_when": "no @JavascriptInterface in $DEC/jadx/sources → mark n/a: 'no JS bridge'",   # sets/inserts the body field before Test
      "severity": "high", "vrt": "`…` (P1)", "attacker": "AM-02", "applies_to": "…", "maps_to": "…",   # replace a metadata cell
      "title": "new title",                                 # rename (id unchanged)
      "replace": [{"old": "exact text", "new": "replacement"}]  # unique within the item block
    }
  },
  "sections": {                                              # replace or insert whole chapter sections
    "Applicability probe": "markdown body (inserted after 'The crux question' if absent)",
    "Triage order": "markdown body"
  },
  "append_items": "### D10-073 · …\\n\\n| | |\\n…"             # appended after the last item, before '## Graveyard'
}
Exit 1 if any target item or 'old' text is not found (nothing is written in that case).
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
META_ORDER = ["Severity ceiling", "VRT", "Attacker", "Applies to", "Requires", "Maps to", "Record"]
INSERT_AFTER = {"Requires": "Applies to", "Record": "Maps to"}
CELL_KEYS = {"severity": "Severity ceiling", "vrt": "VRT", "attacker": "Attacker", "applies_to": "Applies to",
             "maps_to": "Maps to", "requires": "Requires", "record": "Record"}


def chapter_path(domain):
    import glob
    m = glob.glob(os.path.join(ROOT, "checklist", domain + "-*.md"))
    if len(m) != 1: sys.exit(f"!! chapter for {domain} not found uniquely: {m}")
    return m[0]


def split_blocks(text):
    """Return list of (kind, text). kind: 'item' with id, or 'other'. Fence-aware for '## ' and '### '."""
    lines = text.split("\n"); blocks = []; cur = []; fence = False; kind = ("other", None)
    def flush():
        if cur: blocks.append((kind, "\n".join(cur)))
    for line in lines:
        if line.strip().startswith("```"): fence = not fence
        m = re.match(r'^### (D\d\d-\d{3})\s*[·\-]', line) if not fence else None
        if m or (not fence and re.match(r'^## ', line)):
            flush(); cur = [line]; kind = ("item", m.group(1)) if m else ("other", line.strip())
        else:
            cur.append(line)
    flush()
    return blocks


def set_cell(block, name, value):
    pat = re.compile(r'^(\|\s*\*\*%s\*\*\s*\|\s*)(.*?)(\s*\|\s*)$' % re.escape(name), re.M)
    if pat.search(block):
        return pat.sub(lambda m: m.group(1) + value + " |", block, count=1), "set"   # a function replacement is inserted literally: no escaping
    anchor = INSERT_AFTER.get(name)
    apat = re.compile(r'^\|\s*\*\*%s\*\*\s*\|.*$' % re.escape(anchor), re.M) if anchor else None
    if apat and apat.search(block):
        return apat.sub(lambda m: m.group(0) + f"\n| **{name}** | {value} |", block, count=1), "inserted"
    # fall back: after the last metadata row
    rows = list(re.finditer(r'^\|\s*\*\*[^*]+\*\*\s*\|.*$', block, re.M))
    if rows:
        last = rows[-1]
        return block[:last.end()] + f"\n| **{name}** | {value} |" + block[last.end():], "inserted"
    return block, "no-table"


def set_skip_when(block, value):
    pat = re.compile(r'^- \*\*Skip when:?\*\*.*?(?=^- \*\*(?:Test|How|Proof|Escalation|Ruled out when):?\*\*)', re.M | re.S)
    if pat.search(block):
        return pat.sub(f"- **Skip when:** {value}\n", block, count=1), "set"
    tpat = re.compile(r'^- \*\*Test:?\*\*', re.M)
    if tpat.search(block):
        return tpat.sub(f"- **Skip when:** {value}\n- **Test:**", block, count=1), "inserted"
    return block, "no-test-field"


def main():
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(1)
    if a[0] in ("-h", "--help"): print(__doc__); sys.exit(0)
    unknown = [x for x in a if x.startswith("-") and x not in ("--dry-run", "--build")]
    if unknown or a[0].startswith("-"):      # a mistyped flag must not fall through to a write
        print(f"!! usage: apply-item-meta.py changes.json [--dry-run] [--build] — unknown argument: {' '.join(unknown) or a[0]}", file=sys.stderr)
        sys.exit(2)
    dry = "--dry-run" in a
    spec = json.load(open(a[0], encoding="utf-8"))
    path = chapter_path(spec["domain"])
    text = open(path, encoding="utf-8").read()
    blocks = split_blocks(text)
    ids = {k[1] for k, _ in blocks if k[0] == "item"}
    errors, log = [], []
    items = spec.get("items", {})
    for iid in items:
        if iid not in ids: errors.append(f"item {iid} not found")
    out = []
    for (kind, iid), block in blocks:
        if kind == "item" and iid in items:
            ch = items[iid]
            if "title" in ch:
                block = re.sub(r'^(### %s\s*[·\-]\s*).*$' % re.escape(iid), lambda m: m.group(1) + ch["title"], block, count=1, flags=re.M)
                log.append(f"{iid}: title")
            for key, name in CELL_KEYS.items():
                if key in ch:
                    block, how = set_cell(block, name, ch[key]); log.append(f"{iid}: {name} {how}")
                    if how == "no-table": errors.append(f"{iid}: no metadata table for {name}")
            if "skip_when" in ch:
                block, how = set_skip_when(block, ch["skip_when"]); log.append(f"{iid}: Skip when {how}")
                if how == "no-test-field": errors.append(f"{iid}: no Test field to anchor Skip when")
            for rep in ch.get("replace", []):
                n = block.count(rep["old"])
                if n != 1: errors.append(f"{iid}: replace target found {n} times: {rep['old'][:50]!r}")
                else: block = block.replace(rep["old"], rep["new"]); log.append(f"{iid}: replace")
        out.append(((kind, iid), block))
    # sections
    for name, body in (spec.get("sections") or {}).items():
        idx = next((i for i, ((k, t), _) in enumerate(out) if k == "other" and t == f"## {name}"), None)
        new_block = f"## {name}\n\n{body.strip()}\n"
        if idx is not None:
            out[idx] = (out[idx][0], new_block); log.append(f"section {name}: replaced")
        else:
            anchor = "## The crux question" if name == "Applicability probe" else None
            aidx = next((i for i, ((k, t), _) in enumerate(out) if k == "other" and t == anchor), None) if anchor else None
            if aidx is None: errors.append(f"section {name}: no anchor to insert after")
            else: out.insert(aidx + 1, (("other", f"## {name}"), new_block)); log.append(f"section {name}: inserted")
    if spec.get("append_items"):
        last = max((i for i, ((k, _), _) in enumerate(out) if k == "item"), default=None)
        if last is None: errors.append("append_items: no items in chapter")
        else:
            out.insert(last + 1, (("item", "APPENDED"), spec["append_items"].strip() + "\n")); log.append("append_items: added")
    if errors:
        print("!! nothing written:"); [print("   -", e) for e in errors]; sys.exit(1)
    new_text = "\n".join(b.rstrip("\n") + "\n" for _, b in out)
    if dry:
        print(f"would change {path}: {len(log)} operations"); [print("  ", l) for l in log[:50]]; return
    open(path, "w", encoding="utf-8").write(new_text)
    print(f"{path}: {len(log)} operations applied");
    for l in log[:15]: print("  ", l)
    if len(log) > 15: print(f"   … {len(log) - 15} more")
    if "--build" in a:
        import subprocess
        for script in ("lint-checklist.py", "build-checklist.py"):
            rc = subprocess.call([sys.executable, os.path.join(ROOT, "scripts", script)])
            if rc != 0:
                sys.exit(f"!! {script} exited {rc}: the chapter is written but the views are not regenerated")


if __name__ == "__main__":
    main()
