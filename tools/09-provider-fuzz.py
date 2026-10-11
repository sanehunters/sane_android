#!/usr/bin/env python3
"""09-provider-fuzz.py --inventory <eng>/inventory --pkg <pkg> [options]

ContentProvider matrix for every authority in inventory/components.csv (type=provider; --authority and
--dumpsys add more): query / gettype / read (openFile) / insert / update / delete / call, on the base
paths, their UriMatcher variants and traversal variants, plus an SQL error-oracle on query done the
honest way. Output: CSV + JSON + per-probe logs. Works without a device: --list prints the matrix,
--dry-run prints the exact adb commands.

read, write and call() are THREE SEPARATE QUESTIONS (D07-005/015): a denial on query says nothing
about insert/update/delete/openFile, and call() is gated by neither readPermission nor
writePermission and bypasses UriMatcher/<path-permission> by design (D07-016). Write probes are
side-effect-minimised: update/delete use --where 1=0, insert binds one canary column; --no-write skips
them. call() method names come from --methods, from `Bundle call(` switches mined with --jadx, or a
short guess list (tagged guess).

SQL oracle (why in this order): the `selection` argument IS SQL by API contract, so "the where clause
reaches SQLite" is not a finding. The oracle therefore (1) records a baseline query, (2) repeats the
IDENTICAL request N times (--repeat) and refuses to interpret anything if the responses differ,
(3) only then fires variants and compares row counts/output hashes against the baseline:
  1=2 ) OR ( 1=1  returning MORE rows than baseline  -> an app-added restriction was escaped
  * FROM sqlite_master--  returning CREATE TABLE      -> projection injection (schema read)
  '  -> SQLiteException                              -> INFO: selection reaches SQLite (expected)
(MASTG-TEST-0339 for the static side; D07-004/-005 for the oracle table.)

Quoting (why): `adb shell` hands ONE joined string to the device's /system/bin/sh -c, so every URI,
--where, --projection, --bind and --method value is single-quoted for the REMOTE shell ('\\'' escaping)
and the whole remote command is a single argument. Verified with a local `sh -c` simulator (fake adb);
no device was attached when this file was written.

Exit: 0 ran and >=1 CANDIDATE; 1 ran, nothing; 2 usage/environment. --list/--dry-run exit 0.
"""
import argparse, csv, glob, hashlib, json, os, re, shlex, subprocess, sys, time

REMINDER = ("REMINDER: adb's `content` runs as the shell UID, which holds permissions no third-party app has. Every "
            "row above is DISCOVERY. Re-prove each CANDIDATE from the zero-permission probe app (attacker-app/, "
            "ContentResolver as AM-03) before it becomes a finding (START.md R3); `reachable` rows mean the permission "
            "gate passed for uid 2000, nothing more.")
GUESS_METHODS = ["test", "getInfo", "get", "query", "init", "config", "debug", "dump", "export", "backup", "getToken", "getUser"]
TRAVERSAL = ["/../../shared_prefs/{pkg}_preferences.xml", "/..%2F..%2Fshared_prefs%2F{pkg}_preferences.xml",
             "/%2e%2e/%2e%2e/shared_prefs/{pkg}_preferences.xml", "/../../../../../../system/etc/hosts",
             "/..%2F..%2F..%2F..%2F..%2F..%2Fsystem%2Fetc%2Fhosts", "/./../../databases/"]
WHERE = ["1=1", "1=2", "'", "1=1) OR (1=1", "1=2) OR (1=1", "1=1) AND (1=2", "1=1 --", "1=1 /*", "' OR '1'='1"]
PROJ = ["*", "* FROM sqlite_master--", "* FROM sqlite_master;", "_id", "rowid"]
SORT = ["_id", "(SELECT 1)", "rowid DESC"]


def rq(s):
    """Single-quote s for the REMOTE (device) shell."""
    return "'" + s.replace("'", "'\\''") + "'"


class Device:
    def __init__(self, serial, dry):
        self.adb = ["adb"] + (["-s", serial] if serial else [])
        self.dry, self.api = dry, "?"

    def show(self, *args): return " ".join(shlex.quote(a) for a in self.adb + list(args))

    def shell(self, remote, timeout=15):
        """(rc, stdout_bytes, text). List-form subprocess: no local shell; one remote string."""
        if self.dry: return 0, b"", ""
        try:
            p = subprocess.run(self.adb + ["shell", remote], capture_output=True, timeout=timeout)
            raw = p.stdout
            return p.returncode, raw, (p.stdout + p.stderr).decode(errors="replace").replace("\r", "")
        except subprocess.TimeoutExpired:
            return 124, b"", ""
        except FileNotFoundError:
            return 127, b"", ""

    def preflight(self):
        if self.dry: return
        rc, _, out = self.shell("getprop ro.build.version.sdk", 10)
        if rc == 127: sys.exit("UNVERIFIED: adb not on PATH (set ANDROID_SDK_ROOT; see scripts/doctor.sh)  [exit 2]")
        try:
            p = subprocess.run(self.adb + ["get-state"], capture_output=True, timeout=10, text=True)
            if p.stdout.strip() != "device": sys.exit("UNVERIFIED: no device in state 'device'  [exit 2]")
        except Exception: sys.exit("UNVERIFIED: adb get-state failed  [exit 2]")
        self.api = out.strip()


# ----------------------------------------------------------------------------------------- sources
def inventory_providers(path):
    """{authority: class} from components.csv (type=provider, extra 'authorities=a;b')."""
    out = {}
    if not os.path.exists(path): return out
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("type") != "provider": continue
            m = re.search(r"authorities=(\S+)", r.get("extra", ""))
            for a in (m.group(1).split(";") if m else []): out[a] = r.get("name", "")
    return out


def dumpsys_authorities(dev, pkg):
    """[authority]: lines of the ContentProvider Authorities section whose Provider{} belongs to pkg."""
    _, _, out = dev.shell("dumpsys package %s" % rq(pkg))
    found, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s*\[([^\]]+)\]:\s*$", line)
        if m: cur = m.group(1); continue
        m = re.search(r"Provider\{\S+ (\S+?)/(\S+)\}", line)
        if m and cur:
            if m.group(1) == pkg: found[cur] = m.group(2)
            cur = None
    return found


def mine_jadx(root, providers):
    """addURI paths and call() method names from decompiled sources. Returns (paths{auth:[(path,src)]}, methods{auth:[(m,src)]})."""
    paths, methods, const_paths = {}, {}, []
    cls2auth = {}
    for a, c in providers.items(): cls2auth.setdefault(c.rsplit(".", 1)[-1], []).append(a)
    files = glob.glob(os.path.join(root, "**", "*.java"), recursive=True) + glob.glob(os.path.join(root, "**", "*.kt"), recursive=True)
    for fp in files:
        try: txt = open(fp, encoding="utf-8", errors="replace").read()
        except Exception: continue
        if "addURI(" not in txt and "Bundle call(" not in txt and "content://" not in txt: continue
        base = os.path.basename(fp).split(".")[0]
        auths = cls2auth.get(base, [])
        for ln, line in enumerate(txt.splitlines(), 1):
            for m in re.finditer(r'addURI\(\s*("([^"]*)"|[A-Za-z_][\w.]*)\s*,\s*"([^"]*)"', line):
                p = "/" + m.group(3).lstrip("/") if m.group(3) else ""
                tgt = [m.group(2)] if m.group(2) else (auths or list(providers))
                for a in tgt: paths.setdefault(a, []).append((p, "%s:%d" % (fp, ln)))
            for m in re.finditer(r'content://([A-Za-z0-9_.]+)(/[^"\s]*)?', line):
                if m.group(1) in providers: paths.setdefault(m.group(1), []).append((m.group(2) or "", "%s:%d" % (fp, ln)))
        if "Bundle call(" in txt:
            seg = txt[txt.index("Bundle call("):]
            for ln, line in enumerate(seg.splitlines()[:400], 1):
                if re.search(r'case\s+"|\.equals\(\s*"|equals\("|hashCode\(\)|switch\s*\(', line):
                    for m in re.finditer(r'"([A-Za-z_][A-Za-z0-9_.-]{0,60})"', line):
                        for a in (auths or list(providers)): methods.setdefault(a, []).append((m.group(1), "%s:+%d" % (fp, ln)))
    return paths, methods


def concretise(p):
    """UriMatcher template -> one fireable path (# = number, * = any segment)."""
    return re.sub(r"\*", "x", re.sub(r"#", "1", p))


def variants(p):
    """UriMatcher edge cases around a concrete path."""
    v = []
    if p in ("", "/"): return ["/", "//", "/.", "/x", "/1", "/x/y", "/?x=1", "/#f"]
    v += [p + "/", "/" + p, p + "/.", p + "?x=1", p + "#f", p + "/extra", p[:1] + p[1:2].upper() + p[2:]]
    if re.search(r"/\d+", p):
        for n in ("0", "-1", "999999999", "01", "1a", "1%20"): v.append(re.sub(r"/\d+", "/" + n, p, count=1))
    if re.search(r"/x(?=/|$)", p): v += [re.sub(r"/x(?=/|$)", "/x%20y", p, count=1), re.sub(r"/x(?=/|$)", "/x/y", p, count=1)]
    return list(dict.fromkeys(v))


# ------------------------------------------------------------------------------------------ probes
def classify(op, rc, raw, text, pkg):
    o = text
    if rc == 124: return "unverified:timeout", 0, 0
    if rc == 127: return "unverified:no-adb", 0, 0
    rows = len(re.findall(r"^Row: \d+", o, re.M))
    if re.search(r"SecurityException|Permission Denial|Permission denied|requires .* permission", o): return "closed:security", 0, 0
    if re.search(r"Could not find provider|Failed to find provider|No content provider|Unknown authority", o): return "no-provider", 0, 0
    if re.search(r"Unknown UR[IL]", o): return ("reachable:unknown-uri" if ("at " + pkg) in o else "no-provider"), 0, 0
    if re.search(r"SQLiteException|SQLITE_ERROR|syntax error|no such (table|column)|android\.database\.sqlite", o): return "error:sqlite", 0, 0
    if re.search(r"FileNotFoundException", o): return "reachable:no-file", 0, 0
    if re.search(r"Error while accessing provider|Exception", o): return ("error:app" if ("at " + pkg) in o else "error:other"), 0, 0
    if op == "query":
        if "No result found" in o: return "reachable:empty", 0, 0
        return ("candidate:rows", rows, 0) if rows else ("reachable:empty", 0, 0)
    if op == "read":
        return ("candidate:bytes", 0, len(raw)) if raw.strip() else ("reachable:empty", 0, 0)
    if op == "gettype":
        return ("reachable:type", 0, 0) if o.strip() and "null" not in o else ("reachable:empty", 0, 0)
    if op == "insert":
        return ("candidate:inserted", 0, 0) if "content://" in o else ("reachable:write-accepted", 0, 0)
    if op in ("update", "delete"): return "reachable:write-accepted", 0, 0
    if op == "call":
        if re.search(r"Result: Bundle\[", o): return "candidate:call-returned", 0, 0
        return "reachable:call-null", 0, 0
    return "unknown", rows, len(raw)


def tag_for(op, cls_, pcls, label):
    if cls_.startswith("unverified"): return "UNVERIFIED", cls_
    if cls_ == "closed:security": return "closed", "SecurityException/Permission Denial for uid 2000"
    if cls_ == "no-provider": return "no-provider", "authority not registered on this device/user"
    if cls_ == "candidate:rows": return ("CANDIDATE provider/traversal-rows" if pcls == "traversal" else "CANDIDATE provider/readable"), "rows returned to the shell UID"
    if cls_ == "candidate:bytes": return ("CANDIDATE provider/traversal-bytes" if pcls == "traversal" else "CANDIDATE provider/openFile-readable"), "openFile returned bytes"
    if cls_ in ("candidate:inserted", "reachable:write-accepted"): return "CANDIDATE provider/write-reachable", "%s accepted without SecurityException (0 rows targeted)" % op
    if cls_ == "candidate:call-returned": return "CANDIDATE provider/call-returned", "call(%s) returned a Bundle" % label
    if cls_ == "reachable:call-null": return "INFO reachable", "call() reached the provider; method unknown or returned null"
    if cls_.startswith("reachable"): return "INFO reachable", "permission gate passed for uid 2000; %s" % cls_.split(":", 1)[1]
    if cls_ == "error:sqlite": return "INFO sqlite-error", "the argument reached SQLite (API behaviour); see the oracle rows"
    if cls_ == "error:app": return "INFO reachable", "exception thrown inside the provider (gate passed)"
    return "closed", cls_


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="\n".join(__doc__.split("\n\n")[1:]))
    ap.add_argument("--inventory", required=True, help="dir with components.csv (scripts/inventory.py)")
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--authority", action="append", default=[], help="add an authority (repeatable)")
    ap.add_argument("--dumpsys", action="store_true", help="merge authorities from `dumpsys package <pkg>` (device)")
    ap.add_argument("--paths", help="file with one base path per line (applies to every authority)")
    ap.add_argument("--jadx", help="decompiled sources: mine addURI() paths and call() method names")
    ap.add_argument("--methods", help="comma list of call() method names")
    ap.add_argument("--classes", default="matrix,urimatcher,traversal,sql", help="subset of matrix,urimatcher,traversal,sql")
    ap.add_argument("--user", help="content --user N")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    ap.add_argument("--out", help="evidence dir (default provider-fuzz/<pkg>)")
    ap.add_argument("--repeat", type=int, default=3, help="identical baseline requests before the SQL oracle (default 3)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--no-write", action="store_true", help="skip insert/update/delete")
    ap.add_argument("--max", type=int, default=0, help="cap on probes (0 = all)")
    ap.add_argument("--list", action="store_true", help="print the probe matrix and exit")
    ap.add_argument("--dry-run", action="store_true", help="print the exact adb commands, fire nothing")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not re.match(r"^[A-Za-z0-9._]+$", a.pkg): sys.exit("usage: package name has unexpected characters  [exit 2]")
    classes = set(c.strip() for c in a.classes.split(","))
    bad = classes - {"matrix", "urimatcher", "traversal", "sql"}
    if bad: sys.exit("usage: unknown class %s  [exit 2]" % sorted(bad))
    dev = Device(a.serial, a.dry_run)
    providers = inventory_providers(os.path.join(a.inventory, "components.csv"))
    for x in a.authority: providers.setdefault(x, "")
    if a.dumpsys and not a.dry_run:
        dev.preflight()
        for k, v in dumpsys_authorities(dev, a.pkg).items(): providers.setdefault(k, v)
    if not providers: print("UNVERIFIED: no provider authority (components.csv has none; try --dumpsys / --authority)"); sys.exit(1)
    mined_paths, mined_methods = mine_jadx(a.jadx, providers) if a.jadx else ({}, {})
    user_paths = [l.strip() for l in open(a.paths)] if a.paths else []
    methods_cli = [m.strip() for m in (a.methods or "").split(",") if m.strip()]
    uarg = (" --user %s" % a.user) if a.user else ""

    # ---- build the matrix -------------------------------------------------------------------------
    probes = []
    def add(auth, pcls, op, path, label="", where=None, proj=None, sort=None, bind=None, method=None, src=""):
        uri = "content://%s%s" % (auth, path)
        cmd = "content %s --uri %s%s" % (op, rq(uri), uarg)
        if proj is not None: cmd += " --projection %s" % rq(proj)
        if where is not None: cmd += " --where %s" % rq(where)
        if sort is not None: cmd += " --sort %s" % rq(sort)
        if bind is not None: cmd += " --bind %s" % rq(bind)
        if method is not None: cmd += " --method %s" % rq(method)
        probes.append(dict(probe_id="", authority=auth, user=a.user or "0", **{"class": pcls}, op=op, uri=uri, label=label,
                           args=json.dumps({k: v for k, v in dict(where=where, projection=proj, sort=sort, bind=bind, method=method).items() if v is not None}),
                           remote=cmd, source=src))
    ts = time.strftime("%Y%m%d%H%M%S")
    for auth in sorted(providers):
        base = [("", "default"), ("/", "default"), ("/1", "default"), ("/x", "default")]
        base += [(p, "cli") for p in user_paths] + [(concretise(p), s) for p, s in mined_paths.get(auth, [])]
        base = list(dict.fromkeys(base))
        if "matrix" in classes:
            for p, src in base:
                add(auth, "matrix", "query", p, src=src); add(auth, "matrix", "gettype", p, src=src); add(auth, "matrix", "read", p, src=src)
                if not a.no_write:
                    add(auth, "matrix", "insert", p, bind="sane_probe:s:%s" % ts, src=src)
                    add(auth, "matrix", "update", p, where="1=0", bind="sane_probe:s:x", src=src)
                    add(auth, "matrix", "delete", p, where="1=0", src=src)
            meths = [(m, "cli") for m in methods_cli] + [(m, s) for m, s in mined_methods.get(auth, [])] or [(m, "guess") for m in GUESS_METHODS]
            for m, src in list(dict.fromkeys(meths))[:60]: add(auth, "matrix", "call", "", label=m, method=m, src=src)
        if "urimatcher" in classes:
            for p, src in base:
                for v in variants(p):
                    add(auth, "urimatcher", "query", v, label=v, src=src); add(auth, "urimatcher", "read", v, label=v, src=src)
        if "traversal" in classes:
            for p, src in base:
                for t in TRAVERSAL:
                    v = p.rstrip("/") + t.format(pkg=a.pkg)
                    add(auth, "traversal", "read", v, label=t, src=src); add(auth, "traversal", "query", v, label=t, src=src)
        if "sql" in classes:
            for p, src in base:
                for i in range(a.repeat): add(auth, "sql", "query", p, label="baseline#%d" % (i + 1), src=src)
                for w in WHERE: add(auth, "sql", "query", p, label="where:" + w, where=w, src=src)
                for pj in PROJ: add(auth, "sql", "query", p, label="projection:" + pj, proj=pj, src=src)
                for s in SORT: add(auth, "sql", "query", p, label="sort:" + s, sort=s, src=src)
    probes = list({p["remote"] + p["label"]: p for p in probes}.values())
    for i, p in enumerate(probes, 1): p["probe_id"] = "P-%04d" % i
    if a.max: probes = probes[:a.max]
    print("authorities: %s" % ", ".join("%s (%s)" % (k, v or "class?") for k, v in sorted(providers.items())))
    print("probes: %d  classes: %s  repeat: %d" % (len(probes), ",".join(sorted(classes)), a.repeat))
    if a.list:
        for p in probes: print("%s %-12s %-10s %-7s %-40s %s" % (p["probe_id"], p["authority"][:12], p["class"], p["op"], p["uri"][:40], p["label"]))
        print(REMINDER); return 0
    out = a.out or os.path.join("provider-fuzz", a.pkg)
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    if a.dry_run:
        for p in probes: print("# %s %s %s %s\n  %s" % (p["probe_id"], p["class"], p["op"], p["label"], dev.show("shell", p["remote"])))
    else:
        dev.preflight(); print("device api=%s" % dev.api)

    # ---- fire ---------------------------------------------------------------------------------------
    results, baselines = [], {}
    for p in probes:
        rec = dict(p, command=dev.show("shell", p["remote"]), rc="", result_class="", rows="", bytes="", response_head="", hash="",
                   baseline_hash="", tag="", reason="", log="")
        if a.dry_run: rec["tag"] = "DRY-RUN"; results.append(rec); continue
        rc, raw, text = dev.shell(p["remote"], a.timeout)
        cls_, rows, nbytes = classify(p["op"], rc, raw, text, a.pkg)
        h = hashlib.sha256(text.encode()).hexdigest()[:12]
        logp = os.path.join(out, "logs", p["probe_id"] + ".txt")
        with open(logp, "w", encoding="utf-8") as f: f.write("### %s\n### rc=%s class=%s rows=%s bytes=%s\n%s" % (p["remote"], rc, cls_, rows, nbytes, text))
        tag, why = tag_for(p["op"], cls_, p["class"], p["label"])
        key = (p["authority"], p["uri"])
        if p["class"] == "sql":
            b = baselines.setdefault(key, {"classes": [], "rows": [], "hashes": []})
            if p["label"].startswith("baseline#"):
                b["classes"].append(cls_); b["rows"].append(rows); b["hashes"].append(h)
                stable = len(set(b["hashes"])) == 1 and len(b["hashes"]) == a.repeat
                tag, why = ("INFO baseline", "%s rows=%s" % (cls_, rows)) if len(b["hashes"]) < a.repeat else \
                           (("INFO baseline-stable", "%d identical responses, rows=%s" % (a.repeat, rows)) if stable else
                            ("UNVERIFIED", "baseline unstable: %d distinct responses -> oracle rows below are not interpreted" % len(set(b["hashes"]))))
                if cls_ == "closed:security": tag, why = "closed", "SecurityException on baseline; SQL oracle skipped"
            else:
                stable = len(set(b["hashes"])) == 1 and len(b["hashes"]) == a.repeat
                brows = b["rows"][0] if b["rows"] else 0
                bcls = b["classes"][0] if b["classes"] else ""
                rec["baseline_hash"] = b["hashes"][0] if b["hashes"] else ""
                if bcls == "closed:security" or cls_ == "closed:security": tag, why = "closed", "SecurityException"
                elif not stable: tag, why = "UNVERIFIED", "baseline unstable; not interpreted"
                elif p["label"] == "where:'" and cls_ == "error:sqlite": tag, why = "INFO sqlite-error", "selection reaches SQLite (API contract, not a finding)"
                elif p["label"].startswith("projection:* FROM sqlite_master") and re.search(r"CREATE TABLE|sql=", text):
                    tag, why = "CANDIDATE provider/projection-injection", "schema read through the projection (SQLiteQueryBuilder without strict mode)"
                elif p["label"] in ("where:1=2) OR (1=1", "where:' OR '1'='1") and cls_ == "candidate:rows" and rows > brows:
                    tag, why = "CANDIDATE provider/selection-escapes-restriction", "rows %d > baseline %d: an app-added WHERE was escaped" % (rows, brows)
                elif p["label"] == "where:1=2" and cls_ == "candidate:rows" and rows and rows == brows:
                    tag, why = "INFO selection-ignored", "1=2 returned the baseline rows: selection not applied (or not SQL)"
                elif cls_ == "candidate:rows" and rows == brows: tag, why = "INFO same-as-baseline", "no change"
                elif cls_ == "error:sqlite": tag, why = "INFO sqlite-error", "variant rejected by SQLite / strict mode"
                elif cls_.startswith("reachable"): tag, why = "INFO reachable", cls_
        rec.update(rc=rc, result_class=cls_, rows=rows, bytes=nbytes, response_head=text.strip().replace("\n", " | ")[:160], hash=h, tag=tag, reason=why, log=logp)
        results.append(rec)
        print("%s %-10s %-7s %-44s %-22s %s" % (p["probe_id"], p["class"], p["op"], (p["uri"] + (" " + p["label"] if p["label"] else ""))[:44], cls_, tag) + ("  " + why if why and not tag.startswith("INFO") else ""))

    cols = ["probe_id", "authority", "user", "class", "op", "uri", "label", "args", "source", "command", "rc", "result_class", "rows", "bytes",
            "response_head", "hash", "baseline_hash", "tag", "reason", "log"]
    with open(os.path.join(out, "results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, extrasaction="ignore"); w.writeheader(); w.writerows(results)
    ncand = sum(r["tag"].startswith("CANDIDATE") for r in results)
    per_auth = {au: {"probes": sum(r["authority"] == au for r in results),
                     "candidates": [r["probe_id"] + " " + r["tag"] for r in results if r["authority"] == au and r["tag"].startswith("CANDIDATE")],
                     "closed": sum(r["authority"] == au and r["tag"] == "closed" for r in results)} for au in sorted(providers)}
    summary = dict(tool="09-provider-fuzz", package=a.pkg, device_api=dev.api, dry_run=a.dry_run, authorities=providers, probes=len(results),
                   candidates=ncand, unverified=sum(r["tag"] == "UNVERIFIED" for r in results), per_authority=per_auth, note=REMINDER, probes_detail=results)
    with open(os.path.join(out, "results.json"), "w") as f: json.dump(summary, f, indent=1)
    if a.json: print(json.dumps(summary, indent=1))
    print("\n[+] %d probes, %d CANDIDATE -> %s/results.csv, results.json, logs/" % (len(results), ncand, out))
    print(REMINDER)
    if a.dry_run: return 0
    return 0 if ncand else 1


if __name__ == "__main__":
    sys.exit(main())
