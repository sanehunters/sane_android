#!/usr/bin/env python3
"""mark.py — the ONLY supported way to write checklist-status.csv (or a worker's partial slice of it).
Validates the vocabulary so the gates mean something.

  python3 scripts/mark.py <eng> D10-004 finding   --note "H-003: bridge returns session token; see logs/D10-004.txt" --finding F-001 --evidence logs/D10-004.txt
  python3 scripts/mark.py <eng> D10-005 ruled-out --note "RouterActivity.java:88 exact scheme+host allow-list; every loadUrl call site routes through validate() (grep in logs/D10-005.txt)"
  python3 scripts/mark.py <eng> D13-020 blocked   --note "needs: second account (requested 2026-10-10, see BLOCKERS)"
  python3 scripts/mark.py <eng> D10 n/a           --note "no WebView: zero android.webkit imports in jadx; Java.choose('android.webkit.WebView') empty after full UI walk"   # whole domain: OPEN rows only
  python3 scripts/mark.py <eng> D10 n/a --force   --note "..."                                              # also re-settle rows already settled (findings included)
  python3 scripts/mark.py <eng> D11 applies       --note "SharedPreferences + Room in the APK: 14 getSharedPreferences call sites (jadx)"   # the probe says the domain applies: no rows change
  python3 scripts/mark.py <eng> D10-004 reopen                                                           # back to completed=false
  python3 scripts/mark.py <eng> --show D10-004                                                           # print the row
  python3 scripts/mark.py <eng> D10-004 ruled-out --note "..." --partial D10                             # fan-out worker: writes <eng>/checklist-status.D10.partial.csv
  python3 scripts/mark.py <eng> D10-004 ruled-out --note "..." --tracker checklist-status.worker2.partial.csv   # any slice, relative to <eng>

Rules enforced (R4, START.md §6):
  finding    needs --note (the primitive, one sentence) and either --finding F-NNN or an H-NNN / H-Dnn-NN id in the note
  ruled-out  needs --note of at least 40 characters that names a mechanism; a tool's silence ("found nothing") is rejected
             unless the note also cites a file:line, or names the control / experiment / precondition that makes the silence meaningful
  blocked    needs --note containing "needs:" (what is missing / which environment unblocks it)
  n/a        needs --note of at least 25 characters (why the item cannot apply to this app)
  applies    whole domain only; needs --note of at least 25 characters (the probe's evidence that the domain DOES apply);
             writes no rows — it records the P3 applicability decision gate.py p3 waits for (domains_decided)
A whole-domain n/a / blocked touches only OPEN rows and refuses to run over a `finding` row unless --force.
Every write to the master tracker stamps engagement.json.updated; a whole-domain n/a records domains_na.Dnn,
applies records domains_applicable.Dnn, a whole-domain reopen removes both; every write adds the domain to
domains_decided (reopen of a whole domain removes it again). Writes to a partial slice touch nothing else.
--partial Dnn seeds the slice from the master tracker (that domain's rows) the first time; coverage.py --merge
applies exactly these rules again, so merge == mark.
"""
import csv, json, os, re, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from gate import F_RE, H_RE          # one id grammar for the repo
except Exception:
    F_RE, H_RE = r"\bF-\d{2,3}\b", r"\bH-(?:D\d{2}-)?\d{2,3}\b"

RESULTS = ("finding", "ruled-out", "blocked", "n/a", "reopen", "applies")
SILENCE = re.compile(r"(found nothing|no (hits|output|results?)|nothing found|scanner (found|printed|returned) nothing"
                     r"|tool (printed|returned) nothing|empty output)", re.I)
FILE_LINE = re.compile(r"\b[\w$.-]+\.(java|kt|kts|xml|smali|so|js|dex|json|txt|log|py|c|cpp|h|gradle):\d+\b")
MECHANISM_WORDS = re.compile(r"\b(control|experiment|precondition|positive control)\b", re.I)
OPTS_WITH_VALUE = ("note", "finding", "evidence", "partial", "tracker")
FLAGS = ("force",)


def die(m):
    print("!! " + m); sys.exit(2)


def validate(result, note, fid=""):
    """The START.md §6 note contract. Returns None when the row may be written, else the reason (R4)."""
    note = (note or "").strip(); fid = (fid or "").strip().upper()
    if result == "finding":
        if not note: return "finding needs --note (the primitive in one sentence)"
        if not fid and not re.search(H_RE, note):
            return "finding needs --finding F-NNN or an H-NNN / H-Dnn-NN hypothesis id in the note (park it: R0)"
        if fid and not re.fullmatch(r"F-\d{3}", fid): return "finding id must look like F-001"
    elif result == "ruled-out":
        if len(note) < 40:
            return "ruled-out needs a mechanism in --note (≥40 chars, with file:line or the experiment and its precondition)"
        if SILENCE.search(note) and not FILE_LINE.search(note) and not MECHANISM_WORDS.search(note):
            return "a tool's silence is not a mechanism (R4). Name the control, the code path (file:line), or the controlled experiment."
    elif result == "blocked":
        if "needs:" not in note.lower(): return "blocked needs --note containing 'needs: <what is missing / which environment unblocks it>'"
    elif result == "n/a":
        if len(note) < 25: return "n/a needs a reason in --note (≥25 chars): why this item cannot apply to this app"
    elif result == "applies":
        if len(note) < 25: return "applies needs the probe's evidence in --note (≥25 chars): what in the APK makes this domain apply"
    elif result != "reopen":
        return f"result must be one of {RESULTS}"
    return None


def parse_opts(a):
    opts = {}
    i = 0
    while i < len(a):
        tok = a[i]
        if not tok.startswith("--"): die(f"unexpected argument '{tok}' (options are --note --finding --evidence --partial --tracker --force)")
        k = tok[2:]
        if k in FLAGS:
            opts[k] = True; i += 1; continue
        if k not in OPTS_WITH_VALUE: die(f"unknown option --{k} (known: {', '.join('--' + o for o in OPTS_WITH_VALUE + FLAGS)})")
        if i + 1 >= len(a) or a[i + 1].startswith("--"): die(f"--{k} needs a value")
        opts[k] = a[i + 1]; i += 2
    return opts


def read_tracker(path):
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f); return r.fieldnames, list(r)


def write_tracker(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, lineterminator="\n"); w.writeheader(); w.writerows(rows)


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__); sys.exit(1)
    eng = a[0]
    master = os.path.join(eng, "checklist-status.csv")
    if not os.path.exists(master):
        die(f"{master} not found")

    if a[1] == "--show":
        if len(a) < 3: die("usage: --show Dnn-NNN")
        cols, rows = read_tracker(master)
        row = {r["item_id"]: r for r in rows}.get(a[2].upper()) or die(f"no row {a[2]}")
        print(json.dumps(row, ensure_ascii=False, indent=1)); return

    target, result = a[1].upper(), (a[2].lower() if len(a) > 2 else "")
    if result not in RESULTS:
        die(f"result must be one of {RESULTS}")
    opts = parse_opts(a[3:])
    note = (opts.get("note") or "").strip()
    fid = (opts.get("finding") or "").strip().upper()
    ev = (opts.get("evidence") or "").strip()
    force = bool(opts.get("force"))

    # which file: the master tracker, a worker's domain slice (--partial Dnn), or any slice (--tracker)
    path, slice_dom = master, None
    if opts.get("partial"):
        slice_dom = opts["partial"].upper()
        if not re.fullmatch(r"D\d\d", slice_dom): die("--partial takes a domain id: --partial D10")
        path = os.path.join(eng, f"checklist-status.{slice_dom}.partial.csv")
    elif opts.get("tracker"):
        path = opts["tracker"] if os.path.isabs(opts["tracker"]) else os.path.join(eng, opts["tracker"])
        if os.path.abspath(path) != os.path.abspath(master) and not os.path.basename(path).endswith(".partial.csv"):
            die("--tracker must name checklist-status.csv or a *.partial.csv slice")
    partial = os.path.abspath(path) != os.path.abspath(master)
    if partial and result == "applies":
        die("applies is an engagement-level decision (engagement.json): record it on the master tracker, not a slice")
    if partial and not os.path.exists(path):
        if not slice_dom: die(f"{path} not found (a --tracker slice is created with --partial Dnn)")
        cols, mrows = read_tracker(master)
        seed = [r for r in mrows if r["item_id"].startswith(slice_dom + "-")]
        if not seed: die(f"no {slice_dom} rows in the master tracker")
        write_tracker(path, cols, seed)
        print(f"seeded {os.path.basename(path)} with {len(seed)} {slice_dom} row(s) from checklist-status.csv")
    cols, rows = read_tracker(path)
    by = {row["item_id"]: row for row in rows}

    if re.fullmatch(r"D\d\d", target):
        if result not in ("n/a", "blocked", "reopen", "applies"):
            die("a whole domain can only be marked n/a, blocked, applies or reopened")
        all_ids = [k for k in by if k.startswith(target + "-")]
        if not all_ids: die(f"no rows for {target} in {os.path.basename(path)} (no chapter defines that domain)")
        if result == "applies":
            ids, skipped = [], []            # a decision, not a row write
        elif result == "reopen" or force:
            ids, skipped = all_ids, []
        else:
            ids = [k for k in all_ids if not (str(by[k].get("completed") or "").lower() == "true" or (by[k].get("result") or "").lower() == "n/a")]
            skipped = [k for k in all_ids if k not in ids]
            findings = [k for k in skipped if (by[k].get("result") or "").lower() == "finding"]
            if findings and not ids:
                die(f"every {target} row is already settled ({len(findings)} finding row(s): {', '.join(findings[:5])}); use --force to re-settle them")
    elif re.fullmatch(r"D\d\d-\d{3}", target):
        if result == "applies": die("applies is a whole-domain decision: mark.py <eng> Dnn applies --note \"<probe evidence>\"")
        ids, skipped = ([target] if target in by else die(f"no row {target} in {os.path.basename(path)}")), []
    else:
        die("target must be Dnn-NNN or Dnn")
    if slice_dom and any(not i.startswith(slice_dom + "-") for i in ids):
        die(f"{target} is outside the {slice_dom} slice (worker contract: one domain per worker)")

    why = validate(result, note, fid)
    if why: die(why)
    if result == "finding" and fid: fid = fid.upper()

    today = datetime.date.today().isoformat()
    for iid in ids:
        row = by[iid]
        if result == "reopen":
            row.update({"completed": "false", "result": "", "finding_id": "", "evidence": "", "notes": row.get("notes", "")})
        else:
            same = (row.get("result") or "").lower() == result
            row["completed"] = "true"; row["result"] = result
            row["finding_id"] = fid if result == "finding" else ""
            row["evidence"] = ev or (row.get("evidence", "") if same else "")   # stale evidence never survives a result change
            row["notes"] = note
    if ids: write_tracker(path, cols, rows)

    ej = os.path.join(eng, "engagement.json")
    if os.path.exists(ej) and not partial:
        try:
            e = json.load(open(ej, encoding="utf-8")); e["updated"] = today
            dom = target[:3]
            whole = re.fullmatch(r"D\d\d", target)
            for k in ("domains_na", "domains_applicable"):
                if not isinstance(e.get(k), dict): e[k] = {}
            dec = e.get("domains_decided")
            if not isinstance(dec, list): dec = e["domains_decided"] = []
            if result == "n/a" and whole:
                e["domains_na"][target] = note; e["domains_applicable"].pop(target, None)
            elif result == "applies":
                e["domains_applicable"][target] = note; e["domains_na"].pop(target, None)
            elif result == "reopen" and whole:            # the decision is undone with the rows
                e["domains_na"].pop(target, None); e["domains_applicable"].pop(target, None)
                if dom in dec: dec.remove(dom)
            if result != "reopen" and dom not in dec: dec.append(dom)
            json.dump(e, open(ej, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        except Exception as ex:
            print("!! engagement.json not updated:", ex)
    where = f" → {os.path.basename(path)}" if partial else ""
    if result == "applies":
        print(f"recorded {target} applies (engagement.json.domains_applicable + domains_decided); no rows changed — work its items in their phase"); return
    print(f"marked {len(ids)} row(s) {result}{where}: {', '.join(ids[:8])}{'…' if len(ids) > 8 else ''}"
          + (f"  (skipped {len(skipped)} already-settled row(s); --force to include them)" if skipped else ""))


if __name__ == "__main__":
    main()
