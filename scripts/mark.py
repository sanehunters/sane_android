#!/usr/bin/env python3
"""mark.py — the ONLY supported way to write checklist-status.csv. Validates the vocabulary so the gates mean something.

  python3 scripts/mark.py <eng> D10-004 finding   --note "H-003: bridge returns session token; see logs/D10-004.txt" --finding F-001 --evidence logs/D10-004.txt
  python3 scripts/mark.py <eng> D10-005 ruled-out --note "RouterActivity.java:88 exact scheme+host allow-list; every loadUrl call site routes through validate() (grep in logs/D10-005.txt)"
  python3 scripts/mark.py <eng> D13-020 blocked   --note "needs: second account (requested 2026-10-10, see BLOCKERS)"
  python3 scripts/mark.py <eng> D10 n/a           --note "no WebView: zero android.webkit imports in jadx; Java.choose('android.webkit.WebView') empty after full UI walk"   # whole domain
  python3 scripts/mark.py <eng> D10-004 reopen                                                           # back to completed=false
  python3 scripts/mark.py <eng> --show D10-004                                                           # print the row

Rules enforced (R4, START.md §6):
  finding    needs --note (the primitive, one sentence) and either --finding F-NNN or an H-NNN / H-Dnn-NN id in the note
  ruled-out  needs --note of at least 40 characters that names a mechanism; a tool's silence ("found nothing") is rejected
  blocked    needs --note containing "needs:" (what is missing / which environment unblocks it)
  n/a        needs --note of at least 25 characters (why the item cannot apply to this app)
Every write stamps engagement.json.updated.
"""
import csv, json, os, re, sys, datetime

RESULTS = ("finding", "ruled-out", "blocked", "n/a", "reopen")
SILENCE = re.compile(r"(found nothing|no (hits|output|results?)|nothing found|scanner|tool (printed|returned) nothing|empty output)", re.I)


def die(m):
    print("!! " + m); sys.exit(2)


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__); sys.exit(1)
    eng = a[0]
    path = os.path.join(eng, "checklist-status.csv")
    if not os.path.exists(path):
        die(f"{path} not found")
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f); cols = r.fieldnames; rows = list(r)
    by = {row["item_id"]: row for row in rows}

    if a[1] == "--show":
        row = by.get(a[2].upper()) or die(f"no row {a[2]}")
        print(json.dumps(row, ensure_ascii=False, indent=1)); return

    target, result = a[1].upper(), (a[2].lower() if len(a) > 2 else "")
    if result not in RESULTS:
        die(f"result must be one of {RESULTS}")
    opts = {}
    i = 3
    while i < len(a):
        if a[i].startswith("--") and i + 1 < len(a):
            opts[a[i][2:]] = a[i + 1]; i += 2
        else:
            i += 1
    note = (opts.get("note") or "").strip()
    fid = (opts.get("finding") or "").strip().upper()
    ev = (opts.get("evidence") or "").strip()

    if re.fullmatch(r"D\d\d", target):
        ids = [k for k in by if k.startswith(target + "-")]
        if result not in ("n/a", "blocked", "reopen"):
            die("a whole domain can only be marked n/a, blocked or reopened")
    elif re.fullmatch(r"D\d\d-\d{3}", target):
        ids = [target] if target in by else die(f"no row {target}")
    else:
        die("target must be Dnn-NNN or Dnn")

    if result == "finding":
        if not note: die("finding needs --note (the primitive in one sentence)")
        if not fid and not re.search(r"\bH-(?:D\d{2}-)?\d{2,3}\b", note):
            die("finding needs --finding F-NNN or an H-NNN hypothesis id in the note (park it: R0)")
        if fid and not re.fullmatch(r"F-\d{3}", fid): die("finding id must look like F-001")
    elif result == "ruled-out":
        if len(note) < 40: die("ruled-out needs a mechanism in --note (≥40 chars, with file:line or the experiment and its precondition)")
        if SILENCE.search(note) and "file" not in note.lower() and ":" not in note:
            die("a tool's silence is not a mechanism (R4). Name the control, the code path, or the controlled experiment.")
    elif result == "blocked":
        if "needs:" not in note.lower(): die("blocked needs --note containing 'needs: <what is missing / which environment unblocks it>'")
    elif result == "n/a":
        if len(note) < 25: die("n/a needs a reason in --note (≥25 chars): why this item cannot apply to this app")

    today = datetime.date.today().isoformat()
    for iid in ids:
        row = by[iid]
        if result == "reopen":
            row.update({"completed": "false", "result": "", "finding_id": "", "evidence": "", "notes": row.get("notes", "")})
        else:
            row["completed"] = "true"; row["result"] = result
            row["finding_id"] = fid if result == "finding" else ""
            row["evidence"] = ev or row.get("evidence", "")
            row["notes"] = note
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(rows)

    ej = os.path.join(eng, "engagement.json")
    if os.path.exists(ej):
        try:
            e = json.load(open(ej, encoding="utf-8")); e["updated"] = today
            if result == "n/a" and re.fullmatch(r"D\d\d", target):
                e.setdefault("domains_na", {})[target] = note
            json.dump(e, open(ej, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        except Exception as ex:
            print("!! engagement.json not updated:", ex)
    print(f"marked {len(ids)} row(s) {result}: {', '.join(ids[:8])}{'…' if len(ids) > 8 else ''}")


if __name__ == "__main__":
    main()
