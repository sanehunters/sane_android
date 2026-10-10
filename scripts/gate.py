#!/usr/bin/env python3
"""gate.py — the phase gates as predicates over files. Exit 0 = open, 1 = closed (with the reasons).

  python3 scripts/gate.py <eng> p3            may I leave P3 (= may I enter P4)?
  python3 scripts/gate.py <eng> p7            may I begin escalation?   (the breadth gate)
  python3 scripts/gate.py <eng> done          may I call the assessment complete?
  python3 scripts/gate.py <eng> --all         evaluate every gate and print a table
  python3 scripts/gate.py <eng> --pass p3     record gates.P3=true and phase=P4 in engagement.json IF the gate is open

A gate is never a feeling. Each predicate names the file and the row it is waiting for.
Row validity: a row counts as settled only if completed=true AND result is one of
finding | ruled-out | blocked | n/a AND the notes satisfy START.md §6 (mechanism for ruled-out, needs: for
blocked, reason for n/a, F-/H- id for finding). Rows that are "completed" without that are listed as INVALID
and keep the gate closed — this is what makes the gate mechanical.
"""
import csv, glob, json, os, re, sys

PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]
NON_BREADTH = {"D26", "D27"}


def load_csv(p):
    try:
        with open(p, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def truthy(v): return str(v or "").strip().lower() in ("true", "yes", "1", "y", "done")


def row_valid(r):
    """(settled, reason)"""
    res = (r.get("result") or "").strip().lower()
    notes = (r.get("notes") or "").strip()
    if res == "n/a":
        return (len(notes) >= 25, "n/a without a reason")
    if not truthy(r.get("completed")):
        return (False, "open")
    if res == "finding":
        ok = bool(re.search(r"\b[FH]-\d{2,3}\b", notes + " " + (r.get("finding_id") or "")))
        return (ok, "finding without F-/H- id")
    if res == "ruled-out":
        return (len(notes) >= 40, "ruled-out without a mechanism")
    if res == "blocked":
        return ("needs:" in notes.lower(), "blocked without needs:")
    return (False, f"completed=true but result='{res or ''}' is not in the vocabulary")


def phase_domains(rows):
    d = {}
    for r in rows:
        d.setdefault((r.get("phase") or "").strip(), set()).add((r.get("domain") or "").strip())
    return d


def check(eng, gate):
    reasons = []
    ej = os.path.join(eng, "engagement.json")
    e = {}
    if os.path.exists(ej):
        try: e = json.load(open(ej, encoding="utf-8"))
        except Exception as ex: reasons.append(f"engagement.json unreadable: {ex}")
    else:
        reasons.append("engagement.json missing")
    rows = load_csv(os.path.join(eng, "checklist-status.csv"))
    if not rows: reasons.append("checklist-status.csv missing or empty")
    t = e.get("target", {}) or {}; auth = e.get("authorisation", {}) or {}; lab = e.get("lab", {}) or {}
    na = e.get("domains_na", {}) or {}

    def settled_rows(domains):
        bad = []
        for r in rows:
            if (r.get("domain") or "").strip() not in domains: continue
            ok, why = row_valid(r)
            if not ok: bad.append((r.get("item_id"), why))
        return bad

    def instances_open():
        out = []
        for f in sorted(glob.glob(os.path.join(eng, "inventory", "*.csv"))):
            rr = load_csv(f)
            if not rr: continue
            key = "tested" if "tested" in rr[0] else ("tested_idor" if "tested_idor" in rr[0] else None)
            if not key: continue
            for r in rr:
                if not (truthy(r.get(key)) or (r.get("result") or "").lower() in ("n/a", "na")):
                    out.append((os.path.basename(f), r.get("instance_id") or r.get("uri") or r.get("path") or "?"))
        return out

    g = gate.lower()
    if g == "p0":
        for k in ("basis", "scope"):
            if not (auth.get(k) or "").strip(): reasons.append(f"engagement.json.authorisation.{k} empty")
        if not (auth.get("basis") or "").strip() in ("own-app", "sow", "public-programme", "vdp", "lab", "") and not auth.get("basis"):
            pass
        acc = e.get("accounts", {}) or {}
        if not ((acc.get("a") or "").strip()) and not any("account" in b.lower() for b in (e.get("blockers") or [])):
            reasons.append("no account recorded and no blocker says why (accounts.a empty)")
    elif g == "p1":
        if not lab: reasons.append("engagement.json.lab missing — record tls_intercept / frida / root / lockscreen / positive_controls, or mode: static-only")
        elif lab.get("mode") != "static-only":
            for k in ("tls_intercept", "frida", "root", "lockscreen", "positive_controls"):
                if lab.get(k) is not True: reasons.append(f"lab.{k} is not true (docs/03 verification block)")
    elif g == "p2":
        for k in ("package", "version", "versionCode", "targetSdk", "minSdk", "framework", "ota"):
            if t.get(k) in (None, "", []): reasons.append(f"engagement.json.target.{k} empty")
        if not os.path.exists(os.path.join(eng, "apk", "versions.txt")): reasons.append("apk/versions.txt missing (hashes + split list)")
    elif g == "p3":
        inv = os.path.join(eng, "inventory")
        for f in ("components.csv", "deeplinks.csv", "webviews.csv", "endpoints.csv"):
            p = os.path.join(inv, f)
            if not os.path.exists(p): reasons.append(f"inventory/{f} missing (scripts/inventory.py)")
            elif f == "components.csv" and len(load_csv(p)) == 0 and not os.path.exists(os.path.join(inv, "EMPTY-components.md")):
                reasons.append("inventory/components.csv has no rows and no inventory/EMPTY-components.md explaining why")
        if "domains_na" not in e: reasons.append("engagement.json.domains_na not decided (run every card's applicability probe; {} is a valid answer)")
        for iid, why in settled_rows({"D01", "D03"}): reasons.append(f"{iid}: {why}")
    elif g in ("p4", "p5", "p6"):
        pd = phase_domains(rows).get(g.upper(), set())
        for iid, why in settled_rows(pd): reasons.append(f"{iid}: {why}")
    elif g == "p7":
        breadth = {(r.get("domain") or "").strip() for r in rows} - NON_BREADTH
        for iid, why in settled_rows(breadth): reasons.append(f"{iid}: {why}")
        for f, inst in instances_open(): reasons.append(f"inventory/{f} {inst}: tested=false")
        if not os.path.isdir(os.path.join(eng, "inventory")): reasons.append("inventory/ missing — dimension 2 cannot be claimed")
    elif g == "p8":
        for fd in sorted(glob.glob(os.path.join(eng, "findings", "F-*"))):
            fid = os.path.basename(fd)
            if not os.path.exists(os.path.join(fd, "report.md")): reasons.append(f"{fid}: findings/{fid}/report.md missing")
            has = any(glob.glob(os.path.join(eng, d, fid + "*")) for d in ("logs", "screenshots", "videos", "pocs"))
            if not has: reasons.append(f"{fid}: no evidence files named {fid}* under logs/ screenshots/ videos/ pocs/")
        if not glob.glob(os.path.join(eng, "findings", "F-*")) and not any("no findings" in b.lower() for b in (e.get("blockers") or [])):
            reasons.append("no findings/F-* folders; if the assessment genuinely produced none, record it in assessment-status.md FINDINGS and continue")
    elif g in ("p9", "done"):
        for iid, why in settled_rows({(r.get("domain") or "").strip() for r in rows}): reasons.append(f"{iid}: {why}")
        for f, inst in instances_open(): reasons.append(f"inventory/{f} {inst}: tested=false")
        for f in ("report/assessment-status.md", "report/findings-index.md", "final/submission-checklist.md"):
            if not os.path.exists(os.path.join(eng, f)): reasons.append(f"{f} missing")
        gates = e.get("gates", {}) or {}
        for p in PHASES[:9]:
            if gates.get(p) is not True: reasons.append(f"gates.{p} not recorded true")
    else:
        reasons.append(f"unknown gate {gate}")
    return reasons


def main():
    a = sys.argv[1:]
    if len(a) < 2: print(__doc__); sys.exit(1)
    eng = a[0]
    if a[1] == "--all":
        for g in ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "done"]:
            rs = check(eng, g)
            print(f"  {g:<5} {'OPEN  ' if not rs else 'CLOSED'} {('' if not rs else '· ' + str(len(rs)) + ' reason(s): ' + rs[0][:70])}")
        return
    if a[1] == "--pass":
        g = a[2].lower(); rs = check(eng, g)
        if rs:
            print(f"⛔ gate {g} is CLOSED; cannot record it:"); [print("   -", r) for r in rs[:40]]; sys.exit(1)
        ej = os.path.join(eng, "engagement.json"); e = json.load(open(ej, encoding="utf-8"))
        e.setdefault("gates", {})[g.upper()] = True
        nxt = PHASES[min(PHASES.index(g.upper()) + 1, 9)] if g != "done" else "P9"
        e["phase"] = nxt
        import datetime; e["updated"] = datetime.date.today().isoformat()
        json.dump(e, open(ej, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        print(f"✅ gate {g} recorded; phase is now {nxt}. Commit and push."); return
    rs = check(eng, a[1])
    if rs:
        print(f"⛔ gate {a[1]} CLOSED — {len(rs)} reason(s):")
        for r in rs[:60]: print("   -", r)
        if len(rs) > 60: print(f"   … and {len(rs) - 60} more")
        sys.exit(1)
    print(f"✅ gate {a[1]} OPEN"); sys.exit(0)


if __name__ == "__main__":
    main()
