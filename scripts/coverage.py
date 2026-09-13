#!/usr/bin/env python3
"""coverage.py <checklist-status.csv> [options]

Two-dimensional coverage for one engagement.

  DIMENSION 1  the methodology  - checklist-status.csv, one row per checklist item (all 27 domains)
  DIMENSION 2  the application  - inventory/*.csv, one row per component that EXISTS in this app

Dimension 2 is what lets you tell a client "all 47 exported components were individually tested".
Testing a domain is not the same as testing every instance in it.

Options
  --components <dir|csv>   also check the per-instance registers in inventory/
  --gate p7                EXIT NON-ZERO while any in-scope P3-P6 row or component is untested.
                           Escalation may not begin until this exits 0. This is the anti-tunnel-vision
                           gate: depth is earned by breadth.
  --brief                  one line
"""
import csv, sys, os, glob, collections

TRUE = ("true","yes","1","y","done","complete")
def truthy(v): return str(v or "").strip().lower() in TRUE
def isna(r):   return str(r.get("result") or "").strip().lower() in ("n/a","na","not applicable")

# domains worked during the breadth phases P3-P6; D27 etc. are report-time
BREADTH_DOMAINS = {f"D{i:02d}" for i in range(1, 26)}

def load(p):
    try: return list(csv.DictReader(open(p, encoding="utf-8")))
    except Exception: return []

def bar(c, t, w=22):
    if not t: return "-"*w
    f = int(w*c/t); return "█"*f + "░"*(w-f)

def main():
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    path = sys.argv[1]
    brief = "--brief" in sys.argv
    gate  = sys.argv[sys.argv.index("--gate")+1] if "--gate" in sys.argv else None
    comp_arg = sys.argv[sys.argv.index("--components")+1] if "--components" in sys.argv else None

    rows = load(path)
    if not rows: print(f"!! empty or unreadable: {path}"); sys.exit(2)

    done = [r for r in rows if truthy(r.get("completed"))]
    na   = [r for r in rows if isna(r)]
    todo = [r for r in rows if not truthy(r.get("completed")) and not isna(r)]
    pct  = 100.0*len(done)/len(rows)

    # ---- dimension 2
    inst_files, inst_open, inst_total, inst_done = [], [], 0, 0
    if comp_arg:
        if os.path.isdir(comp_arg): inst_files = sorted(glob.glob(os.path.join(comp_arg, "*.csv")))
        else: inst_files = [comp_arg]
        for f in inst_files:
            for r in load(f):
                key = "tested" if "tested" in r else ("tested_idor" if "tested_idor" in r else None)
                if key is None: continue
                inst_total += 1
                if truthy(r.get(key)) or isna(r): inst_done += 1
                else: inst_open.append((os.path.basename(f), r))

    if brief:
        s = f"checklist {len(done)}/{len(rows)} ({pct:.0f}%)"
        if comp_arg: s += f" · instances {inst_done}/{inst_total}"
        print(s + f" · {len(todo)+len(inst_open)} open"); sys.exit(0)

    print(f"\n  DIMENSION 1 — METHODOLOGY   {len(done)}/{len(rows)}  ({pct:.1f}%)")
    print(f"    complete {len(done)} · n/a {len(na)} · OPEN {len(todo)}\n")
    by = collections.defaultdict(lambda: [0,0])
    for r in rows:
        d = (r.get("domain") or "?").strip(); by[d][1] += 1
        if truthy(r.get("completed")) or isna(r): by[d][0] += 1
    for d in sorted(by):
        c,t = by[d]
        print(f"    {d:<5} {bar(c,t)} {c:>3}/{t:<3}{'' if c==t else '   <-- incomplete'}")

    if comp_arg:
        ipct = 100.0*inst_done/inst_total if inst_total else 100.0
        print(f"\n  DIMENSION 2 — THIS APPLICATION   {inst_done}/{inst_total}  ({ipct:.1f}%)")
        for f in inst_files:
            rr = load(f); 
            if not rr: continue
            key = "tested" if "tested" in rr[0] else ("tested_idor" if "tested_idor" in rr[0] else None)
            if key is None: continue
            c = sum(1 for r in rr if truthy(r.get(key)) or isna(r))
            print(f"    {os.path.basename(f):<18} {bar(c,len(rr))} {c:>3}/{len(rr)}")
        if inst_total == 0:
            print("    !! no instance registers found. Run scripts/inventory.py in P3.")
            print("       Without them you CANNOT claim every component was tested.")

    res = collections.Counter((r.get("result") or "-").strip().lower() for r in done)
    if res: print("\n  results:", dict(res))

    if todo:
        print(f"\n  {len(todo)} OPEN checklist items:")
        for r in todo[:25]:
            print(f"    [ ] {(r.get('item_id') or '?'):<11} {(r.get('title') or '')[:76]}")
        if len(todo) > 25: print(f"    ... and {len(todo)-25} more")
    if inst_open:
        print(f"\n  {len(inst_open)} UNTESTED component instances in THIS app:")
        for f,r in inst_open[:25]:
            label = r.get("name") or r.get("uri") or r.get("path") or r.get("class") or "?"
            print(f"    [ ] {f:<16} {(r.get('instance_id') or ''):<7} {str(label)[:60]}")
        if len(inst_open) > 25: print(f"    ... and {len(inst_open)-25} more")

    bad_na = [r for r in na if not (r.get("notes") or "").strip()]
    if bad_na:
        print(f"\n  !! {len(bad_na)} rows marked n/a with NO reason in notes. Not acceptable:")
        for r in bad_na[:10]: print(f"     {r.get('item_id')}  {(r.get('title') or '')[:66]}")

    # ---- the gate
    if gate == "p7":
        blocking = [r for r in todo if (r.get("domain") or "").strip() in BREADTH_DOMAINS]
        if blocking or inst_open or bad_na:
            print("\n" + "="*74)
            print("  ⛔  P7 GATE CLOSED — ESCALATION MAY NOT BEGIN")
            print("="*74)
            print(f"  {len(blocking)} breadth checklist items untested")
            print(f"  {len(inst_open)} component instances untested")
            print(f"  {len(bad_na)} n/a rows with no stated reason")
            print("""
  Depth is earned by breadth. Go back to the sweep.
  If something is genuinely juicy, it belongs in hypotheses/ as a parked stub - NOT chased now.
  See docs/09-coverage-discipline.md.
""")
            sys.exit(1)
        print("\n" + "="*74)
        print("  ✅  P7 GATE OPEN — breadth complete, escalation authorised")
        print("="*74)
        print("  Work hypotheses/ in expected-value order, with every primitive visible at once.")
        print("  Cross-surface joins are only visible from breadth - look for them now.\n")
        sys.exit(0)

    if not todo and not inst_open:
        print("\n  ✅ every in-scope checkpoint and component instance settled.")
    print()

if __name__ == "__main__":
    main()
