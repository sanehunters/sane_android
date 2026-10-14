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
Also reports git status for the engagement path: the engagement folder's OWN repository when it is one (the
private evidence repo, evidence-design: BugBountyTarget/README.md), else the repository that contains it.
Coverage counts use scripts/gate.py row_valid, so the card never disagrees with gate.py / coverage.py.
Engagement discovery honours SANE_ENGAGEMENT_ROOT (default <repo>/BugBountyTarget).
"""
import csv, glob, json, os, re, subprocess, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from gate import row_valid, tested_cols, instance_open   # the single definition of "settled" (gate.py, coverage.py)
except Exception:
    row_valid = None
ENG_ROOT = os.environ.get("SANE_ENGAGEMENT_ROOT") or os.path.join(ROOT, "BugBountyTarget")
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
        st["warnings"].append("engagement.json missing — create it (scripts/new-engagement.sh; keys in START.md §6)")

    rows = load_csv(os.path.join(eng, "checklist-status.csv"))
    if not rows:
        st["warnings"].append("checklist-status.csv missing or empty")
    by = collections.defaultdict(lambda: {"total": 0, "done": 0, "na": 0, "finding": 0, "blocked": 0, "invalid": 0})
    open_rows, invalid = [], []
    for r in rows:
        d = (r.get("domain") or "?").strip(); c = by[d]; c["total"] += 1
        res = (r.get("result") or "").strip().lower()
        if row_valid:
            settled, why = row_valid(r)
        else:  # gate.py not importable: the old approximation, flagged below
            settled, why = (truthy(r.get("completed")) or res in ("n/a", "na")), "open"
        if settled:
            c["done"] += 1
            if res in ("n/a", "na"): c["na"] += 1
            if res == "finding": c["finding"] += 1
            if res == "blocked": c["blocked"] += 1
        else:
            if why != "open":
                c["invalid"] += 1; invalid.append((r.get("item_id"), why))
            open_rows.append(r)
    st["coverage"] = {d: dict(v) for d, v in sorted(by.items())}
    st["totals"] = {"items": len(rows), "done": sum(v["done"] for v in by.values()), "open": len(open_rows),
                    "invalid": len(invalid), "settled_predicate": "scripts/gate.py row_valid" if row_valid else "approximation (gate.py not importable)"}
    if invalid:
        st["warnings"].append(f"{len(invalid)} rows are completed but INVALID under START.md §6 (gate.py rejects them; fix with scripts/mark.py): "
                              + ", ".join(f"{i} ({w})" for i, w in invalid[:6]))
    if not row_valid:
        st["warnings"].append("scripts/gate.py not importable — coverage counts are an approximation")
    phase_rank = {p: i for i, p in enumerate(PHASES)}
    open_rows.sort(key=lambda r: (phase_rank.get((r.get("phase") or "P4").strip(), 4),
                                  SEV_RANK.get((r.get("severity_ceiling") or "support").strip().lower(), 4),
                                  r.get("item_id") or ""))
    st["open_items"] = [r.get("item_id") for r in open_rows]
    st["next_items"] = [{"id": r.get("item_id"), "phase": r.get("phase"), "severity": r.get("severity_ceiling"),
                         "title": r.get("title")} for r in open_rows[:12]]
    for f in sorted(glob.glob(os.path.join(eng, "inventory", "*.csv"))):
        if ".partial." in os.path.basename(f): continue          # worker slices: coverage.py --merge folds them
        rr = load_csv(f)
        if not rr: continue
        if row_valid:
            tc = tested_cols(rr[0].keys())
            if not tc: continue
            done = sum(1 for r in rr if instance_open(r, tc) is None)
        else:
            key = "tested" if "tested" in rr[0] else ("tested_idor" if "tested_idor" in rr[0] else None)
            if not key: continue
            done = sum(1 for r in rr if truthy(r.get(key)) or (r.get("result") or "").lower() in ("n/a", "na"))
        st["instances"][os.path.basename(f)] = {"total": len(rr), "tested": done}

    for h in sorted(glob.glob(os.path.join(eng, "hypotheses", "H-*.md"))):
        first = open(h, encoding="utf-8", errors="replace").readline().strip("# \n")
        if os.path.basename(h) == "H-000-TEMPLATE.md" or first.startswith("H-0NN"): continue   # the template is not a lead
        st["hypotheses"].append({"file": os.path.basename(h), "title": first})
    for fd in sorted(glob.glob(os.path.join(eng, "findings", "F-*"))):
        st["findings"].append(os.path.basename(fd))

    status = os.path.join(eng, "report", "assessment-status.md")
    if os.path.exists(status):
        md = open(status, encoding="utf-8", errors="replace").read()
        b = re.sub(r"<!--.*?-->", "", section(md, "BLOCKERS"), flags=re.S).strip()
        if b and not st["blockers"]:
            st["blockers"] = [l.strip("-* ").strip() for l in b.splitlines() if l.strip("-* ").strip()][:10]
        st["next_target"] = section(md, "NEXT TARGET")[:600]

    # git: the engagement's OWN repo when the folder is one (private evidence repo), else the repo that contains it
    repo = git(["rev-parse", "--show-toplevel"], eng if os.path.isdir(eng) else ROOT)
    if repo:
        own = os.path.realpath(repo) == os.path.realpath(os.path.abspath(eng))
        rel = "." if own else os.path.relpath(os.path.abspath(eng), repo)
        dirty = git(["status", "--porcelain", "--", rel], repo)
        ahead = git(["rev-list", "--count", "@{u}..HEAD"], repo)
        remote = git(["remote", "get-url", "origin"], repo)
        st["git"] = {"repo": repo, "evidence_repo": own, "remote": remote or None,
                     "uncommitted": len([l for l in dirty.splitlines() if l.strip()]),
                     "unpushed_commits": int(ahead) if ahead.isdigit() else None,
                     "branch": git(["rev-parse", "--abbrev-ref", "HEAD"], repo)}
        ej_remote = (st.get("engagement_json") or {}).get("evidence_remote")
        if own and not remote and not ej_remote:
            st["warnings"].append("no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE "
                                  "or git -C $E remote add origin <private url>")
        elif not own:
            st["warnings"].append(f"engagement is not its own git repository (it sits inside {os.path.basename(repo)}); "
                                  "evidence must never be pushed to the public methodology repo — see BugBountyTarget/README.md migration")
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
        A(f"  COVERAGE    {tot['done']}/{tot['items']} settled · {tot['open']} open"
          + (f" · {tot['invalid']} INVALID" if tot.get('invalid') else "") + "   [gate.py row_valid]")
        for d, c in st["coverage"].items():
            mark = "" if c["done"] == c["total"] else "  <-- open"
            A(f"    {d:<4} {c['done']:>3}/{c['total']:<3} n/a={c['na']:<3} finding={c['finding']:<3} blocked={c['blocked']:<3}"
              f"{(' invalid=' + str(c['invalid'])) if c.get('invalid') else ''}{mark}")
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
        A(f"  GIT         {'evidence repo' if g.get('evidence_repo') else 'methodology repo'}  branch={g.get('branch')}  "
          f"uncommitted={g.get('uncommitted')}  unpushed={g.get('unpushed_commits') if g.get('unpushed_commits') is not None else 'n/a (no upstream)'}"
          f"  remote={'yes' if g.get('remote') else 'none'}")
    for w in st["warnings"]:
        A("  !! " + w)
    A("═" * 72)
    A("  Resume rule: read report/assessment-status.md, never re-walk RULED OUT, work NEXT ITEMS in order,")
    A("  flip rows with scripts/mark.py, commit after every item batch (push when an evidence remote is set). Escalation only in P7.")
    return "\n".join(L)


def main():
    a = sys.argv[1:]
    if a and a[0] == "--find":
        for d in sorted(glob.glob(os.path.join(ENG_ROOT, "*_*"))):
            if os.path.isdir(d) and not d.endswith("_TEMPLATE"): print(d)
        return
    if not a:
        cands = [d for d in sorted(glob.glob(os.path.join(ENG_ROOT, "*_*")))
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
