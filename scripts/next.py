#!/usr/bin/env python3
"""next.py — "what do I do next", computed from disk, in one screen. Companion of state.py ("where am I").

  python3 scripts/next.py <engagement-dir>               the next open items of the current phase, in card triage order
  python3 scripts/next.py <engagement-dir> --domain D10  the next open items of one domain
  python3 scripts/next.py <engagement-dir> -n 25         how many items to list (default 15)
  python3 scripts/next.py <engagement-dir> --json        machine view

Reads engagement.json (phase, domains_na), checklist-status.csv (open rows), json/Dnn.json (the card's triage order:
item ids in the order the "Triage order" section mentions them, then the rest numerically), hypotheses/ (parked leads)
and the gate for the current phase (scripts/gate.py). Never edits anything. The order is the card's triage order,
not numeric order (START.md §5 step 3).
"""
import csv, glob, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "support": "⬜", "varies": "🔷"}
PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]


def load_csv(p):
    try:
        with open(p, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def triage_order(domain):
    """Item ids of a domain in card triage order: ids in the order the Triage order section first names them,
    followed by every other item in numeric order."""
    p = os.path.join(ROOT, "json", domain + ".json")
    if not os.path.exists(p):
        return []
    d = json.load(open(p, encoding="utf-8"))
    ids = [i["id"] for i in d["items"]]
    seen, order = set(), []
    for m in re.finditer(r"\b(D\d\d-\d{3})\b(?:\s*(?:→|->|…|\.\.\.|to)\s*(D\d\d-\d{3}))?", d.get("triage", "")):
        a, b = m.group(1), m.group(2)
        if b and a[:3] == b[:3] == domain:
            lo, hi = int(a[4:]), int(b[4:])
            rng = [f"{domain}-{n:03d}" for n in range(lo, hi + 1)] if lo <= hi else [a, b]
        else:
            rng = [a] + ([b] if b else [])
        for x in rng:
            if x in ids and x not in seen:
                seen.add(x); order.append(x)
    return order + [x for x in ids if x not in seen]


def main():
    a = sys.argv[1:]
    if not a or a[0].startswith("-"):
        print(__doc__); sys.exit(1)
    eng = a[0].rstrip("/")
    as_json = "--json" in a
    n = 15
    if "-n" in a:
        n = int(a[a.index("-n") + 1])
    only = a[a.index("--domain") + 1].upper() if "--domain" in a else None

    ej = os.path.join(eng, "engagement.json")
    e = json.load(open(ej, encoding="utf-8")) if os.path.exists(ej) else {}
    phase = e.get("phase", "P0")
    na = set((e.get("domains_na") or {}).keys())
    rows = load_csv(os.path.join(eng, "checklist-status.csv"))
    if not rows:
        print(f"!! {eng}/checklist-status.csv missing or empty — run scripts/new-engagement.sh"); sys.exit(2)

    by_id = {r["item_id"]: r for r in rows}
    phase_domains = sorted({r["domain"] for r in rows if (r.get("phase") or "") == phase})
    domains = [only] if only else [d for d in phase_domains if d not in na]
    if not domains and not only:
        # between phases (P0, P7, P8): show the open rows of the earliest unfinished phase instead
        for ph in PHASES:
            cand = sorted({r["domain"] for r in rows if (r.get("phase") or "") == ph and r["domain"] not in na
                           and (r.get("completed") or "").lower() != "true"})
            if cand:
                domains = cand; break

    items = []
    for d in domains:
        for iid in triage_order(d):
            r = by_id.get(iid)
            if r and (r.get("completed") or "").lower() != "true" and (r.get("result") or "").lower() not in ("n/a", "na"):
                items.append(r)
    open_total = len(items)
    items = items[:n]

    hyps = sorted(os.path.basename(p) for p in glob.glob(os.path.join(eng, "hypotheses", "H-*.md")) if "TEMPLATE" not in p)
    gate = None
    gp = os.path.join(ROOT, "scripts", "gate.py")
    if os.path.exists(gp) and phase in PHASES[:9]:
        g = phase.lower()
        r = subprocess.run([sys.executable, gp, eng, g], capture_output=True, text=True)
        gate = {"gate": g, "open": r.returncode == 0, "reasons": [l.strip(" -") for l in r.stdout.splitlines()[1:6]]}

    if as_json:
        print(json.dumps({"engagement": eng, "phase": phase, "domains": domains, "open_in_scope": open_total,
                          "next": [{"id": r["item_id"], "domain": r["domain"], "severity": r.get("severity_ceiling"),
                                    "title": r["title"]} for r in items],
                          "parked": hyps, "gate": gate}, ensure_ascii=False, indent=1))
        return

    print(f"NEXT — {os.path.basename(eng)} · phase {phase} · domains {' '.join(domains) or '(none open)'} · "
          f"{open_total} open row(s) in scope · {len(hyps)} parked lead(s)")
    if gate:
        print(f"gate {gate['gate']}: {'OPEN — python3 scripts/gate.py ' + eng + ' --pass ' + gate['gate'] if gate['open'] else 'closed — ' + '; '.join(gate['reasons'][:3])}")
    if not items:
        print("nothing open in this phase: pass the gate, or run the applicability probes of the next phase's cards"); return
    print("work these in order (card triage order), one at a time:")
    for r in items:
        sev = (r.get("severity_ceiling") or "support").lower()
        print(f"  {r['item_id']}  {E.get(sev, '⬜')} {sev:<8} {r['title'][:84]}")
    print(f"run:  python3 scripts/item.py {items[0]['item_id']} --brief     (then scripts/mark.py {eng} {items[0]['item_id']} <result> --note …)")
    if phase in ("P3", "P4", "P5", "P6"):
        print("R0: confirm, park (hypotheses/H-NNN.md), flip the row, move on — no escalation before P7.")


if __name__ == "__main__":
    main()
