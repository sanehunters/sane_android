#!/usr/bin/env python3
"""state.py — the resume card. Prints where an engagement is, from disk, in one screen.

  python3 scripts/state.py <engagement-dir>            human card (what hooks print at session start)
  python3 scripts/state.py <engagement-dir> --json     machine view (for hooks, loops and other agents)
  python3 scripts/state.py --find                      locate engagement dirs under BugBountyTarget/

Reads, if present:
  engagement.json          phase, gates, target identity, blockers (written by the agent; see START.md)
  checklist-status.csv     coverage rows (completed/result/notes)
  inventory/*.csv          per-instance registers (tested column)
  hypotheses/H-*.md        parked leads
  report/assessment-status.md   the BLOCKERS and NEXT TARGET sections
  findings/F-*/            finding working folders
Also reports git status for the engagement path (uncommitted / unpushed).
"""
import csv, glob, json, os, re, subprocess, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]
SEV_RANK = {"critical": 0, "high": 1, "varies": 1, "medium": 2, "low": 3, "support": 4}
TRUE = ("true", "yes", "1", "y", "done")


def truthy(v): return str(v or "").strip().lower() in TRUE


def load_csv(p):
    try:
        with open(p, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def git(args, cwd):
    try:
        return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def section(md, name):
    m = re.search(r'^#+\s*%s.*?\n(.*?)(?=\n#+\s|\Z)' % re.escape(name), md, re.S | re.M | re.I)
    return m.group(1).strip() if m else ""


def collect(eng):
    st = {"engagement": os.path.abspath(eng), "phase": None, "gates": {}, "target": {}, "blockers": [],
          "coverage": {}, "open_items": [], "next_items": [], "instances": {}, "hypotheses": [],
          "findings": [], "git": {}, "warnings": []}
    ej = os.path.join(eng, "engagement.json")
    if os.path.exists(ej):
        try:
            e = json.load(open(ej, encoding="utf-8"))
            st["phase"] = e.get("phase"); st["gates"] = e.get("gates", {}); st["target"] = e.get("target", {})
            st["blockers"] = e.get("blockers", []) or []
            st["engagement_json"] = e
        except Exception as ex:
            st["warnings"].append(f"engagement.json unreadable: {ex}")
    else:
        st["warnings"].append("engagement.json missing — create it (see START.md §state)")

    rows = load_csv(os.path.join(eng, "checklist-status.csv"))
    if not rows:
        st["warnings"].append("checklist-status.csv missing or empty")
    by = collections.defaultdict(lambda: {"total": 0, "done": 0, "na": 0, "finding": 0, "blocked": 0})
    open_rows = []
    for r in rows:
        d = (r.get("domain") or "?").strip(); c = by[d]; c["total"] += 1
        res = (r.get("result") or "").strip().lower()
        if truthy(r.get("completed")) or res in ("n/a", "na"):
            c["done"] += 1
            if res in ("n/a", "na"): c["na"] += 1
            if res == "finding": c["finding"] += 1
        else:
            if res == "blocked": c["blocked"] += 1
            open_rows.append(r)
    st["coverage"] = {d: dict(v) for d, v in sorted(by.items())}
    st["totals"] = {"items": len(rows), "done": sum(v["done"] for v in by.values()), "open": len(open_rows)}
    phase_rank = {p: i for i, p in enumerate(PHASES)}
    open_rows.sort(key=lambda r: (phase_rank.get((r.get("phase") or "P4").strip(), 4),
                                  SEV_RANK.get((r.get("severity_ceiling") or "support").strip().lower(), 4),
                                  r.get("item_id") or ""))
    st["open_items"] = [r.get("item_id") for r in open_rows]
    st["next_items"] = [{"id": r.get("item_id"), "phase": r.get("phase"), "severity": r.get("severity_ceiling"),
                         "title": r.get("title")} for r in open_rows[:12]]
    bad_na = [r.get("item_id") for r in rows if (r.get("result") or "").strip().lower() in ("n/a", "na")
              and not (r.get("notes") or "").strip()]
    if bad_na:
        st["warnings"].append(f"{len(bad_na)} rows are n/a without a reason in notes: {', '.join(bad_na[:6])}")

    for f in sorted(glob.glob(os.path.join(eng, "inventory", "*.csv"))):
        rr = load_csv(f)
        if not rr: continue
        key = "tested" if "tested" in rr[0] else ("tested_idor" if "tested_idor" in rr[0] else None)
        if not key: continue
        done = sum(1 for r in rr if truthy(r.get(key)) or (r.get("result") or "").lower() in ("n/a", "na"))
        st["instances"][os.path.basename(f)] = {"total": len(rr), "tested": done}

    for h in sorted(glob.glob(os.path.join(eng, "hypotheses", "H-*.md"))):
        first = open(h, encoding="utf-8", errors="replace").readline().strip("# \n")
        st["hypotheses"].append({"file": os.path.basename(h), "title": first})
    for fd in sorted(glob.glob(os.path.join(eng, "findings", "F-*"))):
        st["findings"].append(os.path.basename(fd))

    status = os.path.join(eng, "report", "assessment-status.md")
    if os.path.exists(status):
        md = open(status, encoding="utf-8", errors="replace").read()
        b = section(md, "BLOCKERS")
        if b and not st["blockers"]:
            st["blockers"] = [l.strip("-* ").strip() for l in b.splitlines() if l.strip("-* ").strip()][:10]
        st["next_target"] = section(md, "NEXT TARGET")[:600]

    repo = git(["rev-parse", "--show-toplevel"], eng if os.path.isdir(eng) else ROOT)
    if repo:
        rel = os.path.relpath(os.path.abspath(eng), repo)
        dirty = git(["status", "--porcelain", "--", rel], repo)
        ahead = git(["rev-list", "--count", "@{u}..HEAD"], repo)
        st["git"] = {"uncommitted": len([l for l in dirty.splitlines() if l.strip()]),
                     "unpushed_commits": int(ahead) if ahead.isdigit() else None,
                     "branch": git(["rev-parse", "--abbrev-ref", "HEAD"], repo)}
    return st


def card(st):
    L = []; A = L.append
    A("═" * 72)
    A(f"  ENGAGEMENT  {st['engagement']}")
    t = st.get("target") or {}
    if t:
        A(f"  TARGET      {t.get('name','?')}  {t.get('package','')}  {t.get('version','')}  framework={t.get('framework','?')}  targetSdk={t.get('targetSdk','?')}")
    A(f"  PHASE       {st.get('phase') or 'unknown'}    gates passed: {', '.join(k for k, v in (st.get('gates') or {}).items() if v) or 'none'}")
    A("═" * 72)
    tot = st.get("totals", {})
    if tot:
        A(f"  COVERAGE    {tot['done']}/{tot['items']} settled · {tot['open']} open")
        for d, c in st["coverage"].items():
            mark = "" if c["done"] == c["total"] else "  <-- open"
            A(f"    {d:<4} {c['done']:>3}/{c['total']:<3} n/a={c['na']:<3} finding={c['finding']:<3} blocked={c['blocked']:<3}{mark}")
    if st["instances"]:
        A("  INSTANCES   " + " · ".join(f"{k} {v['tested']}/{v['total']}" for k, v in st["instances"].items()))
    if st["next_items"]:
        A("  NEXT ITEMS  (phase, then ceiling)")
        for n in st["next_items"]:
            A(f"    [ ] {n['id']:<9} {n['phase']:<3} {str(n['severity']):<9} {(n['title'] or '')[:62]}")
    if st["hypotheses"]:
        A(f"  PARKED      {len(st['hypotheses'])} hypotheses: " + "; ".join(h["title"][:40] for h in st["hypotheses"][:6]))
    if st["findings"]:
        A("  FINDINGS    " + ", ".join(st["findings"]))
    if st["blockers"]:
        A("  BLOCKERS    " + " | ".join(b[:70] for b in st["blockers"][:5]))
    g = st.get("git") or {}
    if g:
        A(f"  GIT         branch={g.get('branch')}  uncommitted={g.get('uncommitted')}  unpushed={g.get('unpushed_commits')}")
    for w in st["warnings"]:
        A("  !! " + w)
    A("═" * 72)
    A("  Resume rule: read report/assessment-status.md, never re-walk RULED OUT, work NEXT ITEMS in order,")
    A("  flip rows as you settle them, commit + push after every item batch. Escalation only in P7.")
    return "\n".join(L)


def main():
    a = sys.argv[1:]
    if a and a[0] == "--find":
        for d in sorted(glob.glob(os.path.join(ROOT, "BugBountyTarget", "*_*"))):
            if os.path.isdir(d) and not d.endswith("_TEMPLATE"): print(d)
        return
    if not a:
        cands = [d for d in sorted(glob.glob(os.path.join(ROOT, "BugBountyTarget", "*_*")))
                 if os.path.isdir(d) and not d.endswith("_TEMPLATE")]
        if len(cands) == 1:
            a = [cands[0]]
        else:
            print(__doc__); print("engagements:", *cands, sep="\n  "); sys.exit(1)
    st = collect(a[0])
    if "--json" in a:
        print(json.dumps(st, ensure_ascii=False, indent=1))
    else:
        print(card(st))


if __name__ == "__main__":
    main()
