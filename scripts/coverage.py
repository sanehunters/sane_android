#!/usr/bin/env python3
"""coverage.py — two-dimensional coverage, the P7 breadth gate and the fan-out merge for ONE engagement.

  python3 scripts/coverage.py <eng>/checklist-status.csv [--components <eng>/inventory] [--brief | --json]
  python3 scripts/coverage.py <eng>/checklist-status.csv --gate p7 [--components <eng>/inventory] [--json]
  python3 scripts/coverage.py <eng>/checklist-status.csv --merge [--dry-run] [--overwrite] [--archive] [--json]
  python3 scripts/coverage.py <eng>/checklist-status.csv --domain D10 --open 40     # one domain's open rows
  python3 scripts/coverage.py <eng>/checklist-status.csv --phase P5 --json          # one phase, machine view

DIMENSION 1  the methodology   checklist-status.csv, one row per item. A row is SETTLED only when
             scripts/gate.py row_valid() says so: completed=true, result in the vocabulary and the notes
             contract of START.md §6 (mechanism for ruled-out, needs: for blocked, F-/H- id for finding;
             n/a needs a reason). A row that is completed=true without that is INVALID: it is listed, it
             keeps the gate closed, and it is never counted as done. The predicate is imported from
             gate.py so the two tools cannot disagree.
DIMENSION 2  the application   inventory/*.csv, one row per instance that exists in THIS app. A row is
             settled when EVERY tested* column is true (tested, tested_idor and tested_massassign) or
             result is n/a. Testing a domain is not testing every instance in it.

--gate p7    the breadth gate (R0). Closed while any row of a breadth domain (every domain in the tracker
             except D26/D27) is open or invalid, any instance is untested, or inventory/ is missing. The
             same predicate as `scripts/gate.py <eng> p7` (both read every tested* column of every register).
--merge      fan-out merge (prompts/05): folds <eng>/checklist-status.Dnn.partial.csv into
             checklist-status.csv by item_id. Only status columns move (completed, result, finding_id,
             evidence, notes). A partial row must satisfy row_valid AND mark.py's note contract (the R4
             silence check) or it is REJECTED — merge == mark; H-Dnn-NN ids are accepted as written by the
             worker (renumbering is optional, after the merge). A row outside the file's domain is rejected
             (worker contract); a settled master row is never overwritten silently (CONFLICT, unless
             --overwrite); one item carried by two partials with different content is a conflict. Clean rows
             are merged even when others conflict. A domain whose rows are all n/a after the merge is recorded
             in engagement.json.domains_na. Partials stay in place (re-merging is idempotent); --archive moves
             the cleanly merged ones to <eng>/logs/partials/.
             Dimension 2 under fan-out: a worker writes <eng>/inventory/<register>.Dnn.partial.csv (same
             columns, only the instances it tested); --merge folds every tested* column plus result,
             finding_id, notes into inventory/<register>.csv by instance_id with the same conflict rules.

Exit codes   0 ran (gate open / merge clean) · 1 gate closed, merge had conflicts or rejections, or
             nothing to merge · 2 usage or environment error (unreadable tracker, bad option).
             A check that could not run prints `UNVERIFIED: <why>` — silence is never a negative.
Output       human report by default · --brief one line (CI scrapes `checklist a/b`, `instances c/d`,
             `· n open`) · --json one object on stdout.
"""
import argparse, collections, csv, datetime, glob, json, os, re, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import gate as _gate  # scripts/gate.py — the single definition of "settled"
    row_valid, truthy, NON_BREADTH = _gate.row_valid, _gate.truthy, _gate.NON_BREADTH
    tested_cols, instance_open, instance_label = _gate.tested_cols, _gate.instance_open, _gate.instance_label
    SEMANTICS = "scripts/gate.py row_valid (imported)"
except Exception:  # gate.py absent (script copied out of the repo): verbatim mirror of gate.py
    NON_BREADTH = {"D26", "D27"}

    def truthy(v): return str(v or "").strip().lower() in ("true", "yes", "1", "y", "done")

    def row_valid(r):
        """(settled, reason) — keep identical to scripts/gate.py."""
        res = (r.get("result") or "").strip().lower()
        notes = (r.get("notes") or "").strip()
        if res == "n/a":
            return (len(notes) >= 25, "n/a without a reason")
        if not truthy(r.get("completed")):
            return (False, "open")
        if res == "finding":
            ok = bool(re.search(r"\b(?:F-\d{2,3}|H-(?:D\d{2}-)?\d{2,3})\b", notes + " " + (r.get("finding_id") or "")))
            return (ok, "finding without F-/H- id")
        if res == "ruled-out":
            return (len(notes) >= 40, "ruled-out without a mechanism")
        if res == "blocked":
            return ("needs:" in notes.lower(), "blocked without needs:")
        return (False, f"completed=true but result='{res or ''}' is not in the vocabulary")
    SEMANTICS = "mirror of scripts/gate.py row_valid (gate.py not importable)"

    def tested_cols(fieldnames):
        return [c for c in (fieldnames or []) if c.strip().lower().startswith("tested")]

    def instance_open(r, cols):
        if (r.get("result") or "").strip().lower() in ("n/a", "na"):
            return None
        for c in cols:
            if not truthy(r.get(c)):
                return c
        return None

    def instance_label(r):
        return r.get("instance_id") or r.get("uri") or r.get("path") or r.get("name") or r.get("class") or "?"
try:
    import mark as _mark                      # scripts/mark.py — the note contract (R4), so merge == mark
    note_valid = _mark.validate
except Exception:
    def note_valid(result, note, fid=""): return None   # mark.py absent: row_valid alone (weaker: no silence check)

INST_NA = ("n/a", "na")                       # instance rows: gate.py instances_open()
F_H_RE = r"\b(?:F-\d{2,3}|H-(?:D\d{2}-)?\d{2,3})\b"
INV_CARRY = ("result", "finding_id", "notes")   # inventory partials carry these plus every tested* column
INV_PARTIAL_RE = re.compile(r"^([a-z]+)\.([^.]+)\.partial\.csv$")
STATUS_COLS = ["completed", "result", "finding_id", "evidence", "notes"]
PHASE_RANK = {f"P{i}": i for i in range(10)}
SEV_RANK = {"critical": 0, "high": 1, "varies": 1, "medium": 2, "low": 3, "support": 4}
PARTIAL_RE = re.compile(r"^checklist-status\.([^.]+)\.partial\.csv$")


# ── loading ──────────────────────────────────────────────────────────────────
def load_csv(path):
    """(fieldnames, rows); raises — the caller decides whether that is fatal or UNVERIFIED."""
    with open(path, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        rows = list(rd)
        return (rd.fieldnames or []), rows


def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, lineterminator="\n")  # LF: the repo is LF; \r leaks into shell pipelines
        w.writeheader(); w.writerows(rows)


def stamp_engagement(eng, na=None, decided=()):
    """Stamp `updated`; with na={Dnn: note} also record whole-domain n/a decisions that arrived through partials;
    every domain that received a merged row joins domains_decided (what mark.py does on a direct write)."""
    ej = os.path.join(eng, "engagement.json")
    if not os.path.exists(ej):
        return
    try:
        e = json.load(open(ej, encoding="utf-8"))
        e["updated"] = datetime.date.today().isoformat()
        if na:
            if not isinstance(e.get("domains_na"), dict): e["domains_na"] = {}
            e["domains_na"].update(na)
        if decided:
            dec = e.get("domains_decided")
            if not isinstance(dec, list): dec = e["domains_decided"] = []
            for d in sorted(decided):
                if d and d not in dec: dec.append(d)
        json.dump(e, open(ej, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    except Exception as ex:
        print(f"!! engagement.json not stamped: {ex}", file=sys.stderr)


def na_domains(rows, domains):
    """{Dnn: common note} for each of `domains` whose rows are now ALL n/a (a whole-domain decision merged from a partial)."""
    out = {}
    for d in domains:
        rr = [r for r in rows if (r.get("item_id") or "").upper().startswith(d + "-")]
        if rr and all((r.get("result") or "").strip().lower() == "n/a" for r in rr):
            notes = collections.Counter((r.get("notes") or "").strip() for r in rr)
            out[d] = notes.most_common(1)[0][0]
    return out


def merge_inventory(eng, dry_run, overwrite, R):
    """Fold inventory/<register>.<tag>.partial.csv into inventory/<register>.csv by instance_id (dimension 2 under fan-out)."""
    out = {"merged": [], "unchanged": []}
    inv = os.path.join(eng, "inventory")
    for p in sorted(glob.glob(os.path.join(inv, "*.partial.csv"))):
        base = os.path.basename(p)
        m = INV_PARTIAL_RE.match(base)
        if not m:
            R["rejected"].append({"file": base, "item_id": "*", "why": "name must be <register>.<tag>.partial.csv"}); continue
        reg = m.group(1) + ".csv"
        info = {"file": base, "domain": m.group(2).upper() if re.fullmatch(r"D\d\d", m.group(2), re.I) else None,
                "register": reg, "rows": 0, "carried": 0, "rejected": 0, "conflicts": 0}
        R["partials"].append(info)
        master = os.path.join(inv, reg)
        try:
            mcols, mrows = load_csv(master); pcols, prows = load_csv(p)
        except Exception as ex:
            R["rejected"].append({"file": base, "item_id": "*", "why": f"unreadable ({ex}); the register inventory/{reg} must exist"}); info["rejected"] += 1
            continue
        tc = tested_cols(mcols)
        if "instance_id" not in mcols or not tc:
            R["rejected"].append({"file": base, "item_id": "*", "why": f"inventory/{reg} is not a register (needs instance_id and a tested* column)"}); info["rejected"] += 1
            continue
        carry = [c for c in list(tc) + list(INV_CARRY) if c in mcols]
        by = {(r.get("instance_id") or "").strip().upper(): r for r in mrows}
        info["rows"] = len(prows)
        changed = False
        for pr in prows:
            iid = (pr.get("instance_id") or "").strip().upper()
            if not iid: continue
            mrow = by.get(iid)
            if mrow is None:
                R["rejected"].append({"file": base, "item_id": iid, "why": f"unknown instance_id (not in inventory/{reg}; workers never allocate ids)"}); info["rejected"] += 1
                continue
            if instance_open(pr, tc) and (pr.get("result") or "").strip().lower() not in INST_NA:
                continue                                   # the worker did not finish this instance; nothing to carry
            if (pr.get("result") or "").strip().lower() == "finding" and not re.search(F_H_RE, (pr.get("notes") or "") + " " + (pr.get("finding_id") or "")):
                R["rejected"].append({"file": base, "item_id": iid, "why": "finding without F-/H- id"}); info["rejected"] += 1
                continue
            payload = {c: (pr.get(c) or "").strip() for c in carry}
            current = {c: (mrow.get(c) or "").strip() for c in carry}
            if payload == current:
                out["unchanged"].append(iid); continue
            info["carried"] += 1
            if instance_open(mrow, tc) is None and not overwrite:
                R["conflicts"].append({"item_id": iid, "files": [base], "why": f"inventory/{reg} already settled ('{current.get('notes', '')[:50]}') — resolve by hand or --overwrite"})
                info["conflicts"] += 1
                continue
            mrow.update(payload); changed = True
            out["merged"].append({"instance_id": iid, "register": reg, "file": base})
        if changed and not dry_run:
            write_csv(master, mcols, mrows)
    return out


# ── dimension 1 ──────────────────────────────────────────────────────────────
def classify(r):
    """'settled' | 'invalid' | 'open', plus the result (settled) or the reason (invalid)."""
    ok, why = row_valid(r)
    if ok:
        return "settled", (r.get("result") or "").strip().lower()
    res = (r.get("result") or "").strip().lower()
    if truthy(r.get("completed")) or res == "n/a":
        return "invalid", why
    return "open", ""


def analyse(rows):
    d = {"total": len(rows), "settled": 0, "open": 0, "invalid": 0,
         "results": collections.Counter(), "by_domain": {}, "by_phase": {}, "by_severity": {},
         "open_items": [], "invalid_items": []}
    for r in rows:
        dom = (r.get("domain") or "?").strip(); ph = (r.get("phase") or "?").strip()
        sev = (r.get("severity_ceiling") or "?").strip().lower()
        state, info = classify(r)
        for key, bucket in (("by_domain", dom), ("by_phase", ph), ("by_severity", sev)):
            c = d[key].setdefault(bucket, {"total": 0, "settled": 0, "open": 0, "invalid": 0})
            c["total"] += 1; c[state] += 1
        d[state] += 1
        if state == "settled":
            d["results"][info or "-"] += 1
        elif state == "open":
            d["open_items"].append(r)
        else:
            d["invalid_items"].append((r, info))
    for r in rows:  # phase of each domain (for the json view)
        dom = (r.get("domain") or "?").strip()
        d["by_domain"][dom].setdefault("phase", (r.get("phase") or "?").strip())
    d["open_items"].sort(key=lambda r: (PHASE_RANK.get((r.get("phase") or "").strip(), 9),
                                        SEV_RANK.get((r.get("severity_ceiling") or "").strip().lower(), 9),
                                        r.get("item_id") or ""))
    d["results"] = dict(d["results"])
    d["pct"] = round(100.0 * d["settled"] / d["total"], 1) if d["total"] else 0.0
    return d


# ── dimension 2 ──────────────────────────────────────────────────────────────
def dim2(comp):
    out = {"evaluated": False, "path": comp, "total": 0, "settled": 0, "files": {}, "open": [], "unverified": []}
    if comp is None:
        return out
    if os.path.isdir(comp):
        files = sorted(f for f in glob.glob(os.path.join(comp, "*.csv")) if ".partial." not in os.path.basename(f))
    elif os.path.isfile(comp):
        files = [comp]
    else:
        out["unverified"].append(f"{comp} does not exist — run scripts/inventory.py in P3; dimension 2 not evaluated")
        return out
    out["evaluated"] = True
    for f in files:
        base = os.path.basename(f)
        try:
            cols, rows = load_csv(f)
        except Exception as ex:
            out["unverified"].append(f"{base} unreadable ({ex}) — dimension 2 cannot be claimed")
            continue
        tc = tested_cols(cols)
        if not tc:
            out["unverified"].append(f"{base} has no tested* column — not a register, ignored")
            continue
        n_open = 0
        for r in rows:
            why = instance_open(r, tc)
            if why:
                n_open += 1
                out["open"].append({"file": base, "instance_id": instance_label(r),
                                    "label": r.get("name") or r.get("uri") or r.get("path") or r.get("class") or "",
                                    "why": f"{why}=false"})
        out["files"][base] = {"total": len(rows), "settled": len(rows) - n_open, "open": n_open, "tested_columns": tc}
        out["total"] += len(rows); out["settled"] += len(rows) - n_open
    if not out["files"]:
        out["unverified"].append("no instance registers found in " + comp + " — run scripts/inventory.py in P3")
    return out


# ── the gate ─────────────────────────────────────────────────────────────────
def gate_p7(eng, rows, d2):
    """Same reasons as scripts/gate.py check(eng, 'p7'), plus every tested* column of every register."""
    reasons = []
    ej = os.path.join(eng, "engagement.json")          # gate.py closes every gate without a readable state file
    if not os.path.exists(ej):
        reasons.append("engagement.json missing")
    else:
        try:
            json.load(open(ej, encoding="utf-8"))
        except Exception as ex:
            reasons.append(f"engagement.json unreadable: {ex}")
    if not rows:
        reasons.append("checklist-status.csv missing or empty")
    breadth = {(r.get("domain") or "").strip() for r in rows} - NON_BREADTH
    for r in rows:
        if (r.get("domain") or "").strip() not in breadth:
            continue
        ok, why = row_valid(r)
        if not ok:
            reasons.append(f"{r.get('item_id')}: {why}")
    if not d2["evaluated"]:
        reasons.append("inventory/ missing — dimension 2 cannot be claimed")
    for u in d2["unverified"]:
        reasons.append("UNVERIFIED: " + u)
    for o in d2["open"]:
        reasons.append(f"inventory/{o['file']} {o['instance_id']}: {o['why']}")
    return reasons


# ── human report ─────────────────────────────────────────────────────────────
def bar(c, t, w=22):
    if not t:
        return "-" * w
    f = int(w * c / t)
    return "█" * f + "░" * (w - f)


def report(d, d2, comp_given, gate, reasons, n_list, filt):
    P = print
    P(f"\n  DIMENSION 1 — METHODOLOGY   {d['settled']}/{d['total']}  ({d['pct']:.1f}%)   [{SEMANTICS}]{filt}")
    res = d["results"]
    P(f"    settled: finding {res.get('finding', 0)} · ruled-out {res.get('ruled-out', 0)} · blocked {res.get('blocked', 0)}"
      f" · n/a {res.get('n/a', 0)}    OPEN {d['open']} · INVALID {d['invalid']}\n")
    for dom in sorted(d["by_domain"]):
        c = d["by_domain"][dom]
        flag = "" if c["settled"] == c["total"] else ("   <-- INVALID rows" if c["invalid"] else "   <-- open")
        P(f"    {dom:<5} {bar(c['settled'], c['total'])} {c['settled']:>3}/{c['total']:<3}{flag}")
    sev = d["by_severity"]
    order = sorted(sev, key=lambda s: SEV_RANK.get(s, 9))
    line = " · ".join(f"{s} {sev[s]['open'] + sev[s]['invalid']}" for s in order if sev[s]["open"] + sev[s]["invalid"])
    P("\n    open by ceiling: " + (line or "none"))

    if comp_given or gate:
        ipct = 100.0 * d2["settled"] / d2["total"] if d2["total"] else 100.0
        P(f"\n  DIMENSION 2 — THIS APPLICATION   {d2['settled']}/{d2['total']}  ({ipct:.1f}%)   {d2['path'] or ''}")
        for base, c in d2["files"].items():
            P(f"    {base:<18} {bar(c['settled'], c['total'])} {c['settled']:>3}/{c['total']:<3}   columns: {', '.join(c['tested_columns'])}")
        for u in d2["unverified"]:
            P(f"    UNVERIFIED: {u}")
        if d2["evaluated"] and d2["total"] == 0 and not d2["unverified"]:
            P("    !! registers exist but hold no rows. If the app truly has no instances, inventory/EMPTY-<register>.md must say why.")

    if d["invalid_items"]:
        P(f"\n  {d['invalid']} INVALID rows — completed=true but not settled under START.md §6 (fix with scripts/mark.py):")
        for r, why in d["invalid_items"][:n_list]:
            P(f"    [!] {(r.get('item_id') or '?'):<9} {why:<42} {(r.get('title') or '')[:50]}")
        if d["invalid"] > n_list:
            P(f"    ... and {d['invalid'] - n_list} more")
    if d["open_items"]:
        P(f"\n  {d['open']} OPEN checklist items (phase, then ceiling):")
        for r in d["open_items"][:n_list]:
            P(f"    [ ] {(r.get('item_id') or '?'):<9} {(r.get('phase') or ''):<3} {(r.get('severity_ceiling') or ''):<9} {(r.get('title') or '')[:60]}")
        if d["open"] > n_list:
            P(f"    ... and {d['open'] - n_list} more")
    if d2["open"]:
        P(f"\n  {len(d2['open'])} UNTESTED instances in THIS app:")
        for o in d2["open"][:n_list]:
            P(f"    [ ] {o['file']:<16} {o['instance_id']:<8} {o['why']:<22} {str(o['label'])[:48]}")
        if len(d2["open"]) > n_list:
            P(f"    ... and {len(d2['open']) - n_list} more")

    if gate:
        P("\n" + "=" * 74)
        if reasons:
            P(f"  ⛔  {gate.upper()} GATE CLOSED — ESCALATION MAY NOT BEGIN   ({len(reasons)} reasons)")
            P("=" * 74)
            P(f"  {sum(1 for x in reasons if re.match(r'D\\d\\d-\\d{3}:', x))} breadth checklist rows open or invalid")
            P(f"  {len(d2['open'])} component instances untested")
            P(f"  {sum(1 for x in reasons if x.startswith(('UNVERIFIED', 'inventory/ missing', 'checklist-status')))} environment reasons")
            P("  Depth is earned by breadth. Go back to the sweep; park anything juicy in hypotheses/ (R0).")
            P("  Same verdict from: python3 scripts/gate.py <eng> p7 · doctrine: docs/09-coverage-discipline.md")
        else:
            P(f"  ✅  {gate.upper()} GATE OPEN — breadth complete, escalation authorised")
            P("=" * 74)
            P("  Work hypotheses/ in expected-value order with every primitive visible at once; the")
            P("  cross-surface joins at the bottom of each chapter are only visible from here.")
    elif not d["open_items"] and not d["invalid_items"] and not d2["open"]:
        P("\n  ✅ every in-scope checkpoint and component instance settled.")
    P()


# ── fan-out merge ────────────────────────────────────────────────────────────
def merge(master_path, dry_run, overwrite, archive, as_json):
    eng = os.path.dirname(os.path.abspath(master_path))
    try:
        cols, rows = load_csv(master_path)
    except Exception as ex:
        print(f"!! {master_path}: {ex}", file=sys.stderr); return 2
    if not rows or "item_id" not in cols:
        print(f"!! {master_path}: empty or no item_id column", file=sys.stderr); return 2
    status = [c for c in STATUS_COLS if c in cols]
    by = {(r.get("item_id") or "").strip().upper(): r for r in rows}
    partials = sorted(glob.glob(os.path.join(eng, "checklist-status.*.partial.csv")))
    inv_partials = sorted(glob.glob(os.path.join(eng, "inventory", "*.partial.csv")))
    R = {"tracker": master_path, "dry_run": dry_run, "overwrite": overwrite, "partials": [],
         "merged": [], "overwritten": [], "unchanged": [], "skipped_open": [], "rejected": [], "conflicts": [],
         "archived": []}
    if not partials and not inv_partials:
        msg = f"nothing to merge: no {eng}/checklist-status.Dnn.partial.csv or inventory/<register>.Dnn.partial.csv (workers write those; see prompts/05)"
        if as_json:
            R["note"] = msg; R["exit"] = 1; print(json.dumps(R, ensure_ascii=False, indent=1))
        else:
            print(msg)
        return 1

    candidates, poisoned = {}, set()         # item_id -> (file, payload); items carried twice with different content
    for p in partials:
        base = os.path.basename(p)
        m = PARTIAL_RE.match(base); tag = m.group(1) if m else ""
        dom = tag.upper() if re.fullmatch(r"D\d\d", tag, re.I) else None
        info = {"file": base, "domain": dom, "rows": 0, "carried": 0, "rejected": 0, "conflicts": 0}
        R["partials"].append(info)
        try:
            pcols, prows = load_csv(p)
        except Exception as ex:
            R["rejected"].append({"file": base, "item_id": "*", "why": f"unreadable: {ex}"}); info["rejected"] += 1
            continue
        if "item_id" not in pcols or not any(c in pcols for c in ("completed", "result")):
            R["rejected"].append({"file": base, "item_id": "*", "why": "not a tracker slice (needs item_id and completed/result columns)"})
            info["rejected"] += 1
            continue
        info["rows"] = len(prows)
        for pr in prows:
            iid = (pr.get("item_id") or "").strip().upper()
            if not iid:
                continue
            mrow = by.get(iid)
            if mrow is None:
                R["rejected"].append({"file": base, "item_id": iid, "why": "unknown item_id (not in the tracker)"}); info["rejected"] += 1
                continue
            mdom = (mrow.get("domain") or "").strip().upper()
            if dom and mdom != dom:
                R["rejected"].append({"file": base, "item_id": iid, "why": f"row belongs to {mdom}; this file is the {dom} slice (worker contract: one domain per worker)"})
                info["rejected"] += 1
                continue
            res = (pr.get("result") or "").strip().lower()
            if not (truthy(pr.get("completed")) or res == "n/a"):
                R["skipped_open"].append(iid)      # the worker did not settle it; nothing to carry
                continue
            ok, why = row_valid(pr)
            if ok:
                why = note_valid(res, pr.get("notes") or "", pr.get("finding_id") or "")   # R4: merge == mark
                ok = why is None
            if not ok:
                R["rejected"].append({"file": base, "item_id": iid, "why": why}); info["rejected"] += 1
                continue
            payload = {c: (pr.get(c) or "").strip() if c != "notes" else (pr.get(c) or "") for c in status}
            info["carried"] += 1
            prev = candidates.get(iid)
            if prev and prev[1] != payload:
                poisoned.add(iid)
                R["conflicts"].append({"item_id": iid, "files": [prev[0], base],
                                       "why": "carried by two partials with different content — decide by hand"})
                for other in R["partials"]:
                    if other["file"] in (prev[0], base): other["conflicts"] += 1
            elif not prev:
                candidates[iid] = (base, payload)

    for iid, (src, payload) in candidates.items():
        if iid in poisoned:
            continue
        mrow = by[iid]
        current = {c: (mrow.get(c) or "").strip() if c != "notes" else (mrow.get(c) or "") for c in status}
        if current == payload:
            R["unchanged"].append(iid); continue
        mres = (mrow.get("result") or "").strip().lower()
        master_settled = truthy(mrow.get("completed")) or mres == "n/a"
        if master_settled and not overwrite:
            R["conflicts"].append({"item_id": iid, "files": [src],
                                   "why": f"tracker already {mres or 'completed'} ('{(mrow.get('notes') or '')[:50]}') vs partial "
                                          f"{payload.get('result')} ('{payload.get('notes', '')[:50]}') — resolve by hand or --overwrite"})
            for info in R["partials"]:
                if info["file"] == src: info["conflicts"] += 1
            continue
        mrow.update(payload)
        (R["overwritten"] if master_settled else R["merged"]).append({"item_id": iid, "file": src, "result": payload.get("result")})

    changed = R["merged"] or R["overwritten"]
    if changed and not dry_run:
        write_csv(master_path, cols, rows)
        touched = {x["item_id"][:3].upper() for x in R["merged"] + R["overwritten"]}
        stamp_engagement(eng, na_domains(rows, touched), touched)
    inv = merge_inventory(eng, dry_run, overwrite, R)
    if inv["merged"] and not changed and not dry_run:
        stamp_engagement(eng)
    if archive and not dry_run:
        bad_files = {x["file"] for x in R["rejected"]} | {f for c in R["conflicts"] for f in c["files"]}
        dest = os.path.join(eng, "logs", "partials")
        for info in R["partials"]:
            if info["file"] in bad_files:
                continue
            os.makedirs(dest, exist_ok=True)
            src = os.path.join(eng, "inventory", info["file"]) if info.get("register") else os.path.join(eng, info["file"])
            shutil.move(src, os.path.join(dest, info["file"]))
            R["archived"].append(info["file"])
    rc = 1 if (R["conflicts"] or R["rejected"]) else 0
    R["exit"] = rc
    if as_json:
        print(json.dumps(R, ensure_ascii=False, indent=1)); return rc

    P = print
    P(f"\n  MERGE {'(dry run) ' if dry_run else ''}{len(partials) + len(inv_partials)} partial file(s) → {os.path.basename(master_path)}"
      f"{' + inventory/' if inv_partials else ''}")
    for info in R["partials"]:
        P(f"    {info['file']:<40} rows {info['rows']:>4} · carried {info['carried']:>3} · rejected {info['rejected']:>3} · conflicts {info['conflicts']:>3}")
    P(f"\n  merged {len(R['merged'])} · overwritten {len(R['overwritten'])} · unchanged {len(R['unchanged'])} · "
      f"skipped (still open in the partial) {len(R['skipped_open'])} · rejected {len(R['rejected'])} · conflicts {len(R['conflicts'])}")
    if R["rejected"]:
        P("\n  REJECTED (not merged — the row does not satisfy START.md §6 / the worker contract):")
        for x in R["rejected"][:40]:
            P(f"    {x['item_id']:<9} {x['file']:<36} {x['why']}")
    if R["conflicts"]:
        P("\n  CONFLICTS (not merged — decide by hand):")
        for x in R["conflicts"][:40]:
            P(f"    {x['item_id']:<9} {', '.join(x['files']):<36} {x['why']}")
    if R["archived"]:
        P(f"\n  archived to logs/partials/: {', '.join(R['archived'])}")
    if inv["merged"] or inv["unchanged"]:
        P(f"\n  inventory partials: merged {len(inv['merged'])} · unchanged {len(inv['unchanged'])} instance row(s) into "
          + ", ".join(sorted({x['register'] for x in inv['merged']}) or ["(nothing new)"]))
    if (changed or inv["merged"]) and dry_run:
        P("\n  dry run: nothing written.")
    elif changed or inv["merged"]:
        P(f"\n  written: {master_path}{' + inventory/' if inv['merged'] else ''} (engagement.json.updated stamped)."
          + (f" Exit 1 because {len(R['rejected'])} row(s) were rejected / {len(R['conflicts'])} conflict(s) remain." if rc else ""))
        P("  Instances a worker reported but did not carry in an inventory partial stay tested=false. Optionally renumber")
        P("  H-Dnn-NN → H-0NN (files AND notes together), update report/assessment-status.md, commit, then:")
        P(f"    python3 scripts/coverage.py {master_path} --components {os.path.join(eng, 'inventory')} --gate p7")
    P()
    return rc


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="coverage.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tracker", help="<eng>/checklist-status.csv")
    ap.add_argument("--components", metavar="DIR|CSV",
                    help="inventory/ directory (or one register) for dimension 2; defaults to <eng>/inventory with --gate")
    ap.add_argument("--gate", type=str.lower, choices=["p7"], help="evaluate the breadth gate; exit 1 while closed")
    ap.add_argument("--brief", action="store_true", help="one line: checklist a/b (p%%) · instances c/d · n open")
    ap.add_argument("--json", action="store_true", help="machine view: one JSON object on stdout")
    ap.add_argument("--domain", type=str.upper, metavar="Dnn", help="restrict the dimension-1 views to one domain (the gate always sees everything)")
    ap.add_argument("--phase", type=str.upper, metavar="Pn", help="restrict the dimension-1 views to one phase (the gate always sees everything)")
    ap.add_argument("--open", type=int, default=25, metavar="N", help="how many open / invalid / untested rows to list (default 25)")
    ap.add_argument("--merge", action="store_true", help="fold <eng>/checklist-status.*.partial.csv into the tracker (fan-out)")
    ap.add_argument("--dry-run", action="store_true", help="with --merge: report only, write nothing")
    ap.add_argument("--overwrite", action="store_true", help="with --merge: a partial row replaces an already-settled tracker row")
    ap.add_argument("--archive", action="store_true", help="with --merge: move cleanly merged partials to <eng>/logs/partials/")
    a = ap.parse_args()

    if not os.path.isfile(a.tracker):
        print(f"!! {a.tracker} not found (expected <eng>/checklist-status.csv)", file=sys.stderr); sys.exit(2)
    if a.merge:
        sys.exit(merge(a.tracker, a.dry_run, a.overwrite, a.archive, a.json))

    try:
        cols, rows = load_csv(a.tracker)
    except Exception as ex:
        print(f"!! {a.tracker}: {ex}", file=sys.stderr); sys.exit(2)
    if not rows or "item_id" not in cols:
        print(f"!! {a.tracker}: empty or not a tracker (no item_id column)", file=sys.stderr); sys.exit(2)

    eng = os.path.dirname(os.path.abspath(a.tracker))
    comp = a.components or (os.path.join(eng, "inventory") if a.gate else None)
    d2 = dim2(comp)
    reasons = gate_p7(eng, rows, d2) if a.gate else []

    view = rows
    filt = ""
    if a.domain:
        view = [r for r in view if (r.get("domain") or "").strip().upper() == a.domain]; filt += f"  [domain {a.domain}]"
    if a.phase:
        view = [r for r in view if (r.get("phase") or "").strip().upper() == a.phase]; filt += f"  [phase {a.phase}]"
    if (a.domain or a.phase) and not view:
        print(f"!! no rows match{filt}", file=sys.stderr); sys.exit(1)
    d = analyse(view)
    rc = 1 if (a.gate and reasons) else 0

    if a.json:
        out = {"tool": "coverage.py", "engagement": eng, "tracker": os.path.abspath(a.tracker), "semantics": SEMANTICS,
               "filter": {"domain": a.domain, "phase": a.phase},
               "checklist": {k: d[k] for k in ("total", "settled", "open", "invalid", "pct", "results", "by_domain", "by_phase", "by_severity")},
               "instances": {k: d2[k] for k in ("evaluated", "path", "total", "settled", "files", "unverified")},
               "open_items": [{"item_id": r.get("item_id"), "domain": r.get("domain"), "phase": r.get("phase"),
                               "severity": r.get("severity_ceiling"), "title": r.get("title")} for r in d["open_items"][:a.open]],
               "invalid_items": [{"item_id": r.get("item_id"), "why": why} for r, why in d["invalid_items"][:a.open]],
               "untested_instances": d2["open"][:a.open],
               "gate": ({"name": a.gate, "open": not reasons, "reasons": reasons} if a.gate else None),
               "exit": rc}
        print(json.dumps(out, ensure_ascii=False, indent=1)); sys.exit(rc)

    if a.brief:
        s = f"checklist {d['settled']}/{d['total']} ({d['pct']:.0f}%)"
        if comp:
            s += f" · instances {d2['settled']}/{d2['total']}" if d2["evaluated"] else " · instances UNVERIFIED"
        s += f" · {d['open'] + len(d2['open'])} open"
        if d["invalid"]:
            s += f" · {d['invalid']} invalid"
        if a.gate:
            s += f" · gate {a.gate} {'OPEN' if not reasons else 'CLOSED (' + str(len(reasons)) + ' reasons)'}"
        print(s); sys.exit(rc)

    report(d, d2, bool(comp), a.gate, reasons, a.open, filt)
    sys.exit(rc)


if __name__ == "__main__":
    main()
