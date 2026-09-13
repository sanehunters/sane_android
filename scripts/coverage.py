#!/usr/bin/env python3
"""coverage.py <checklist-status.csv> [--brief]

Coverage report for one engagement. An assessment is complete when no in-scope row is still `false`.
"""
import csv, sys, collections

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    path = sys.argv[1]
    brief = "--brief" in sys.argv
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if not rows:
        print("empty tracker"); sys.exit(1)

    def truthy(v): return str(v).strip().lower() in ("true", "yes", "1", "y")
    done = [r for r in rows if truthy(r.get("completed"))]
    na   = [r for r in rows if (r.get("result") or "").strip().lower() == "n/a"]
    open_rows = [r for r in rows if not truthy(r.get("completed"))
                 and (r.get("result") or "").strip().lower() != "n/a"]
    pct = 100.0 * len(done) / len(rows) if rows else 0

    if brief:
        print(f"{len(done)}/{len(rows)} ({pct:.0f}%) · {len(open_rows)} open"); return

    print(f"\n  COVERAGE  {len(done)}/{len(rows)}  ({pct:.1f}%)")
    print(f"  complete {len(done)} · n/a {len(na)} · OPEN {len(open_rows)}\n")

    by_dom = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        d = r.get("domain", "?")
        by_dom[d][1] += 1
        if truthy(r.get("completed")): by_dom[d][0] += 1
    print("  per domain")
    for d in sorted(by_dom):
        c, t = by_dom[d]
        bar = "█" * int(20 * c / t) + "░" * (20 - int(20 * c / t))
        flag = "" if c == t else "   <-- incomplete"
        print(f"    {d}  {bar}  {c:>3}/{t:<3}{flag}")

    res = collections.Counter((r.get("result") or "").strip().lower() or "-" for r in done)
    print("\n  results:", dict(res))

    if open_rows:
        print(f"\n  {len(open_rows)} OPEN checkpoints — assessment is NOT complete:")
        for r in open_rows[:40]:
            print(f"    [ ] {r.get('item_id','?'):<10} {r.get('title','')[:78]}")
        if len(open_rows) > 40: print(f"    ... and {len(open_rows)-40} more")
    else:
        print("\n  ✅ every in-scope checkpoint settled.")
        miss = [r for r in na if not (r.get("notes") or "").strip()]
        if miss:
            print(f"  !! {len(miss)} rows marked n/a with NO reason in notes — that is not acceptable:")
            for r in miss[:15]: print(f"     {r.get('item_id')}  {r.get('title','')[:70]}")
    print()

if __name__ == "__main__":
    main()
