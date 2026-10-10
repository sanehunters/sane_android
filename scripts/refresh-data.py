#!/usr/bin/env python3
"""refresh-data.py — regenerate data/ from the primary sources so no identifier can rot.

  python3 scripts/refresh-data.py                 clone/update the sources into .refs/ (gitignored), rebuild data/
  python3 scripts/refresh-data.py --refs DIR      use existing clones under DIR (owasp-mastg, maswe, owasp-masvs,
                                                  vulnerability-rating-taxonomy, www-project-mobile-top-10)
  python3 scripts/refresh-data.py --offline       never touch the network; fail if a source is missing

Sources (all public): OWASP MASTG, MASWE, MASVS; Bugcrowd VRT; OWASP Mobile Top 10; MITRE ATT&CK Mobile (STIX);
CWE Top 25. Downloads land in <refs>/_untrusted_*/ and are only ever parsed, never executed.

Outputs: data/*.csv (see data/README.md), data/versions.json (provenance: commit + date per source),
data/standards-index.csv (every MASTG/MASWE/MASVS id the linter accepts), data/crosswalk.csv
(standard id → checklist items, built from json/D*.json). Run scripts/build-checklist.py first so json/ exists.
"""
import csv, glob, json, os, re, subprocess, sys, shutil, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
BUILDER = os.path.join(ROOT, "scripts", "standards_builder.py")
REPOS = {
    "owasp-mastg": "https://github.com/OWASP/owasp-mastg.git",
    "maswe": "https://github.com/OWASP/maswe.git",
    "owasp-masvs": "https://github.com/OWASP/owasp-masvs.git",
    "vulnerability-rating-taxonomy": "https://github.com/bugcrowd/vulnerability-rating-taxonomy.git",
    "www-project-mobile-top-10": "https://github.com/OWASP/www-project-mobile-top-10.git",
}
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
CWE_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ensure_sources(refs, offline):
    os.makedirs(refs, exist_ok=True)
    for name, url in REPOS.items():
        d = os.path.join(refs, name)
        if os.path.isdir(os.path.join(d, ".git")):
            if not offline:
                r = run(["git", "-C", d, "pull", "--ff-only", "-q"])
                print(f"  {name}: updated" if r.returncode == 0 else f"  {name}: pull failed ({r.stderr.strip()[:80]}) — using existing clone")
        elif offline:
            sys.exit(f"!! {d} missing and --offline given")
        else:
            print(f"  cloning {name} …")
            r = run(["git", "clone", "-q", "--depth", "1", "--single-branch", url, d], timeout=600)
            if r.returncode != 0:
                sys.exit(f"!! clone failed for {name}: {r.stderr.strip()[:200]}")
    att_dir = os.path.join(refs, "_untrusted_attack"); cwe_dir = os.path.join(refs, "_untrusted_cwe")
    os.makedirs(att_dir, exist_ok=True); os.makedirs(cwe_dir, exist_ok=True)
    att = os.path.join(att_dir, "mobile-attack.json"); cwe = os.path.join(cwe_dir, "top25_2025.html")
    if not offline:
        for url, dst in ((ATTACK_URL, att), (CWE_URL, cwe)):
            r = run(["curl", "-sSL", "--max-time", "120", "-o", dst + ".tmp", url])
            if r.returncode == 0 and os.path.getsize(dst + ".tmp") > 1000:
                os.replace(dst + ".tmp", dst); print(f"  fetched {os.path.basename(dst)}")
            else:
                print(f"  !! could not fetch {url} — keeping {'existing' if os.path.exists(dst) else 'nothing'}")
                if os.path.exists(dst + ".tmp"): os.remove(dst + ".tmp")
    return att if os.path.exists(att) else None, cwe if os.path.exists(cwe) else None


def build_standards_index():
    rows = []
    for f, idcol in (("mastg-tests.csv", "id"), ("mastg-techniques.csv", "id"), ("mastg-tools.csv", "id"),
                     ("mastg-knowledge.csv", "id"), ("mastg-best-practices.csv", "id"), ("mastg-apps.csv", "id"),
                     ("mastg-demos.csv", "id"), ("maswe.csv", "id"), ("masvs-controls.csv", "id")):
        p = os.path.join(DATA, f)
        if not os.path.exists(p): continue
        with open(p, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                rows.append({"id": r[idcol], "kind": f.split(".")[0], "status": r.get("status", ""),
                             "platform": r.get("platform", ""), "title": r.get("title") or r.get("statement", ""),
                             "url": r.get("url", "")})
    rows.sort(key=lambda r: r["id"])
    with open(os.path.join(DATA, "standards-index.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "kind", "status", "platform", "title", "url"]); w.writeheader(); w.writerows(rows)
    print(f"  standards-index.csv {len(rows)} ids")
    return {r["id"]: r for r in rows}


def build_crosswalk(index):
    """standard id -> the checklist items that cite it, from json/D*.json (needs scripts/build-checklist.py)."""
    cites = collections.defaultdict(list); titles = {}
    for p in sorted(glob.glob(os.path.join(ROOT, "json", "D*.json"))):
        d = json.load(open(p, encoding="utf-8"))
        for i in d["items"]:
            ids = i.get("ids", {})
            for kind in ("mastg", "maswe", "masvs", "cwe", "attack", "vrt"):
                for sid in ids.get(kind, []):
                    cites[(kind, sid)].append(i["id"])
    vrt = {}
    p = os.path.join(DATA, "vrt.csv")
    if os.path.exists(p):
        with open(p, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh): vrt[r["vrt_path"]] = r
    attack = {}
    p = os.path.join(DATA, "attack-mobile-android.csv")
    if os.path.exists(p):
        with open(p, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh): attack[r["id"]] = r
    out = []
    # every standard entry, cited or not
    universe = [("mastg", k, v.get("title", "")) for k, v in index.items() if k.startswith("MASTG")] + \
               [("maswe", k, v.get("title", "")) for k, v in index.items() if k.startswith("MASWE")] + \
               [("masvs", k, v.get("title", "")) for k, v in index.items() if k.startswith("MASVS")] + \
               [("attack", k, v.get("name", "")) for k, v in attack.items()] + \
               [("vrt", k, v.get("name", "")) for k, v in vrt.items() if v.get("priority")]
    seen = set()
    for kind, sid, title in universe:
        items = sorted(set(cites.get((kind, sid), [])))
        out.append({"standard": kind, "standard_id": sid, "title": title, "known": "true", "n_items": len(items), "item_ids": ";".join(items)})
        seen.add((kind, sid))
    for (kind, sid), items in sorted(cites.items()):
        if (kind, sid) in seen: continue
        known = "true" if kind == "cwe" else "false"
        out.append({"standard": kind, "standard_id": sid, "title": "", "known": known, "n_items": len(set(items)), "item_ids": ";".join(sorted(set(items)))})
    with open(os.path.join(DATA, "crosswalk.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["standard", "standard_id", "title", "known", "n_items", "item_ids"]); w.writeheader(); w.writerows(out)
    unk = [r for r in out if r["known"] == "false"]
    print(f"  crosswalk.csv {len(out)} rows · {sum(1 for r in out if r['n_items'])} cited · {len(unk)} cited-but-unknown ids")
    for r in unk[:10]: print("    !! unknown", r["standard"], r["standard_id"], "cited by", r["item_ids"][:60])


def main():
    a = sys.argv[1:]
    offline = "--offline" in a
    refs = a[a.index("--refs") + 1] if "--refs" in a else os.environ.get("SANE_REFS") or os.path.join(ROOT, ".refs")
    print(f"sources under {refs}")
    att, cwe = ensure_sources(refs, offline)
    os.makedirs(DATA, exist_ok=True)
    cmd = [sys.executable, "-I", BUILDER, "--mastg", os.path.join(refs, "owasp-mastg"), "--maswe", os.path.join(refs, "maswe"),
           "--masvs", os.path.join(refs, "owasp-masvs"), "--vrt", os.path.join(refs, "vulnerability-rating-taxonomy"),
           "--mt10", os.path.join(refs, "www-project-mobile-top-10"), "--out", DATA]
    if att: cmd += ["--attack-stix", att]
    if cwe: cmd += ["--cwe-top25", cwe]
    r = run(cmd, cwd=ROOT)
    print(r.stdout)
    if r.returncode != 0:
        sys.exit("!! builder failed:\n" + r.stderr[-2000:])
    index = build_standards_index()
    build_crosswalk(index)
    print("done — commit data/ together with the chapters that cite it")


if __name__ == "__main__":
    main()
