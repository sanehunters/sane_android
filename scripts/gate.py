#!/usr/bin/env python3
"""gate.py — the phase gates as predicates over files. Exit 0 = open, 1 = closed (with the reasons).

  python3 scripts/gate.py <eng> p3            may I leave P3 (= may I enter P4)?
  python3 scripts/gate.py <eng> p7            may I begin escalation?   (the breadth gate)
  python3 scripts/gate.py <eng> done          may I call the assessment complete?
  python3 scripts/gate.py <eng> --all         evaluate every gate and print a table
  python3 scripts/gate.py <eng> --pass p3     record gates.P3=true and phase=P4 in engagement.json IF the gate is open
                                              (the phase never moves backwards: re-passing p0 at P6 leaves P6)

A gate is never a feeling. Each predicate names the file and the row it is waiting for.
Row validity: a row counts as settled only if completed=true AND result is one of
finding | ruled-out | blocked | n/a AND the notes satisfy START.md §6 (mechanism for ruled-out, needs: for
blocked, reason for n/a, F-/H- id for finding). Rows that are "completed" without that are listed as INVALID
and keep the gate closed — this is what makes the gate mechanical.
Instance validity (inventory/*.csv): a row is settled when EVERY tested* column is true (tested, tested_idor,
tested_massassign) or result is n/a. coverage.py and state.py import these predicates; they never re-define them.

engagement.json keys the gates read (seeded by scripts/new-engagement.sh, documented in START.md §6):
  authorisation.basis   one of own-app | sow | public-programme | vdp | lab          (p0)
  lab.mode              "dynamic" | "static-only"; with "dynamic" the five booleans tls_intercept, frida, root,
                        lockscreen, positive_controls must all be true (docs/03 §7); with "static-only" they may
                        stay false (START.md §3) and p1 is open                                        (p1)
  domains_na            {} or {"Dnn": "<probe note>"} — null/absent means the applicability probes were not run (p3)
  domains_decided       ["Dnn", …] every domain whose applicability probe was answered: mark.py adds a domain on
                        `Dnn applies`, `Dnn n/a` or its first settled row; p3 stays closed while any tracker
                        domain is missing (absent list = nothing decided)                                      (p3)
  domains_applicable    {"Dnn": "<probe evidence>"} written by `mark.py <eng> Dnn applies` (informational)
"""
import csv, glob, json, os, re, sys

PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]
NON_BREADTH = {"D26", "D27"}
BASES = ("own-app", "sow", "public-programme", "vdp", "lab")
LAB_KEYS = ("tls_intercept", "frida", "root", "lockscreen", "positive_controls")
LAB_MODES = ("dynamic", "static-only")
REGISTERS = ("components.csv", "deeplinks.csv", "webviews.csv", "endpoints.csv")
# ONE id grammar for the whole repo (mark.py, coverage.py import these): F-NNN findings; H-NNN hypotheses,
# or H-Dnn-NN — the fan-out form a worker allocates before the coordinator renumbers (prompts/05).
F_RE = r"\bF-\d{2,3}\b"
H_RE = r"\bH-(?:D\d{2}-)?\d{2,3}\b"
INST_NA = ("n/a", "na")


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
        ok = bool(re.search(F_RE + "|" + H_RE, notes + " " + (r.get("finding_id") or "")))
        return (ok, "finding without F-/H- id")
    if res == "ruled-out":
        return (len(notes) >= 40, "ruled-out without a mechanism")
    if res == "blocked":
        return ("needs:" in notes.lower(), "blocked without needs:")
    return (False, f"completed=true but result='{res or ''}' is not in the vocabulary")


def tested_cols(fieldnames):
    """Every tested* column of a register (tested, tested_idor, tested_massassign, …)."""
    return [c for c in (fieldnames or []) if c.strip().lower().startswith("tested")]


def instance_open(r, cols):
    """None when the instance is settled, else the tested* column that is still false."""
    if (r.get("result") or "").strip().lower() in INST_NA:
        return None
    for c in cols:
        if not truthy(r.get(c)):
            return c
    return None


def instance_label(r):
    return r.get("instance_id") or r.get("uri") or r.get("path") or r.get("name") or r.get("class") or "?"


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
    na = e.get("domains_na")

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
            if ".partial." in os.path.basename(f): continue      # worker slices are merged by coverage.py --merge
            rr = load_csv(f)
            if not rr: continue
            tc = tested_cols(rr[0].keys())
            if not tc: continue
            for r in rr:
                why = instance_open(r, tc)
                if why: out.append((os.path.basename(f), instance_label(r), why))
        return out

    g = gate.lower()
    if g == "p0":
        for k in ("basis", "scope"):
            if not (auth.get(k) or "").strip(): reasons.append(f"engagement.json.authorisation.{k} empty")
        basis = (auth.get("basis") or "").strip()
        if basis and basis not in BASES:
            reasons.append(f"authorisation.basis '{basis}' is not one of {' | '.join(BASES)} (START.md §3)")
        acc = e.get("accounts", {}) or {}
        if not ((acc.get("a") or "").strip()) and not any("account" in b.lower() for b in (e.get("blockers") or [])):
            reasons.append("no account recorded and no blocker says why (accounts.a empty)")
    elif g == "p1":
        mode = (lab.get("mode") or "").strip().lower() if isinstance(lab, dict) else ""
        if not isinstance(lab, dict) or not lab:
            reasons.append('engagement.json.lab missing — write {"mode": "dynamic"|"static-only", "tls_intercept": bool, "frida": bool, '
                           '"root": bool, "lockscreen": bool, "positive_controls": bool} (docs/03 §7; static-only: START.md §3)')
        elif mode not in LAB_MODES:
            reasons.append(f"lab.mode is '{mode}' — set \"dynamic\" (five checks must pass) or \"static-only\" (no device: START.md §3)")
        elif mode == "dynamic":
            for k in LAB_KEYS:
                if lab.get(k) is not True: reasons.append(f"lab.{k} is not true (docs/03 §7 verification block, logs/harness/)")
        # static-only: the lab.* booleans may stay false; dynamic items are settled as blocked with doctor.sh's reason
    elif g == "p2":
        for k in ("package", "version", "versionCode", "targetSdk", "minSdk", "framework", "ota"):
            if t.get(k) in (None, "", []): reasons.append(f"engagement.json.target.{k} empty")
        vp = os.path.join(eng, "apk", "versions.txt")
        lines = [l for l in (open(vp, encoding="utf-8", errors="replace").read().splitlines() if os.path.exists(vp) else [])
                 if l.strip() and not l.lstrip().startswith("#")]
        if not lines: reasons.append("apk/versions.txt has no sha256 line (the template ships comments only): record hashes + split list")
    elif g == "p3":
        inv = os.path.join(eng, "inventory")
        for f in REGISTERS:
            p = os.path.join(inv, f); stem = f[:-4]
            empty_md = os.path.join(inv, f"EMPTY-{stem}.md")
            if not os.path.exists(p) and not os.path.exists(empty_md):
                reasons.append(f"inventory/{f} missing (scripts/inventory.py), and no inventory/EMPTY-{stem}.md says why the register is empty")
            elif os.path.exists(p) and len(load_csv(p)) == 0 and not os.path.exists(empty_md):
                reasons.append(f"inventory/{f} has no rows and no inventory/EMPTY-{stem}.md explaining why (manifest or code evidence)")
        if not isinstance(na, dict):
            reasons.append("engagement.json.domains_na not decided (run every card's applicability probe; {} is a valid answer, null is not)")
        decided = e.get("domains_decided") if isinstance(e.get("domains_decided"), list) else []   # absent = nothing decided
        undecided = sorted({(r.get("domain") or "").strip() for r in rows} - set(decided) - set(na if isinstance(na, dict) else {}) - {""})
        if undecided:
            reasons.append(f"applicability undecided for {', '.join(undecided)} — run each card's applicability probe, then "
                           "scripts/mark.py <eng> Dnn applies --note \"<evidence>\" or scripts/mark.py <eng> Dnn n/a --note \"<reason>\"")
        for iid, why in settled_rows({"D01", "D03"}): reasons.append(f"{iid}: {why}")
    elif g in ("p4", "p5", "p6"):
        pd = phase_domains(rows).get(g.upper(), set())
        for iid, why in settled_rows(pd): reasons.append(f"{iid}: {why}")
    elif g == "p7":
        breadth = {(r.get("domain") or "").strip() for r in rows} - NON_BREADTH
        for iid, why in settled_rows(breadth): reasons.append(f"{iid}: {why}")
        for f, inst, why in instances_open(): reasons.append(f"inventory/{f} {inst}: {why}=false")
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
        for f, inst, why in instances_open(): reasons.append(f"inventory/{f} {inst}: {why}=false")
        for f in ("report/assessment-status.md", "report/findings-index.md", "final/submission-checklist.md"):
            if not os.path.exists(os.path.join(eng, f)): reasons.append(f"{f} missing")
        gates = e.get("gates", {}) or {}
        for p in PHASES[:9]:
            if gates.get(p) is not True: reasons.append(f"gates.{p} not recorded true")
    else:
        reasons.append(f"unknown gate {gate}")
    return reasons


def fold_open(rs):
    """(specific reasons, open-row ids): hundreds of 'Dnn-NNN: open' lines would otherwise hide the few reasons that
    need a decision (invalid rows, inventory instances, missing files) behind the print limit."""
    opens = [r.split(":")[0] for r in rs if r.endswith(": open")]
    others = [r for r in rs if not r.endswith(": open")]
    if opens:
        others.append(f"{len(opens)} row(s) still open: {', '.join(opens[:10])}{'…' if len(opens) > 10 else ''} (scripts/next.py lists them in triage order)")
    return others


def main():
    a = sys.argv[1:]
    if len(a) < 2: print(__doc__); sys.exit(1)
    eng = a[0]
    if a[1] == "--all":
        for g in ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "done"]:
            rs = check(eng, g)
            first = fold_open(rs)[0][:70] if rs else ""
            print(f"  {g:<5} {'OPEN  ' if not rs else 'CLOSED'} {('' if not rs else '· ' + str(len(rs)) + ' reason(s): ' + first)}")
        return
    if a[1] == "--pass":
        if len(a) < 3 or a[2].lower() not in [p.lower() for p in PHASES[:9]] + ["done"]:
            print("!! usage: gate.py <eng> --pass p0..p8|done"); sys.exit(2)
        g = a[2].lower(); rs = check(eng, g)
        if rs:
            print(f"⛔ gate {g} is CLOSED; cannot record it:"); [print("   -", r) for r in fold_open(rs)[:40]]; sys.exit(1)
        ej = os.path.join(eng, "engagement.json"); e = json.load(open(ej, encoding="utf-8"))
        e.setdefault("gates", {})[g.upper()] = True
        nxt = PHASES[min(PHASES.index(g.upper()) + 1, 9)] if g != "done" else "P9"
        cur = e.get("phase") if e.get("phase") in PHASES else "P0"
        if PHASES.index(nxt) > PHASES.index(cur):
            e["phase"] = nxt; msg = f"phase is now {nxt}"
        else:
            msg = f"phase unchanged (already {cur})"
        import datetime; e["updated"] = datetime.date.today().isoformat()
        json.dump(e, open(ej, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        print(f"✅ gate {g} recorded; {msg}. Commit (and push to the evidence remote when one is configured)."); return
    rs = check(eng, a[1])
    if rs:
        print(f"⛔ gate {a[1]} CLOSED — {len(rs)} reason(s):")
        shown = fold_open(rs)
        for r in shown[:60]: print("   -", r)
        if len(shown) > 60: print(f"   … and {len(shown) - 60} more")
        sys.exit(1)
    print(f"✅ gate {a[1]} OPEN"); sys.exit(0)


if __name__ == "__main__":
    main()
