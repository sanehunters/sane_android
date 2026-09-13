#!/usr/bin/env python3
"""inventory.py <base.apk | AndroidManifest.xml> --out inventory/

Builds the PER-INSTANCE component register for ONE application.

Why this exists
---------------
Testing "domain D07" is not the same as testing all eight provider authorities. Only a per-instance
register lets you tell a client:

    "All 47 exported components, 8 provider authorities and 23 deep-link hosts in version 18.15.0 were
     individually tested. Here is the result for each."

That sentence is the audit. This file is what backs it.

Every row starts tested=false. You flip rows to true as you settle them. coverage.py --gate p7 refuses
to let escalation begin while any row is still false.
"""
import csv, os, re, subprocess, sys, tempfile, shutil, xml.etree.ElementTree as ET

NS = '{http://schemas.android.com/apk/res/android}'
COLS = ["instance_id","type","name","exported","export_reason","permission","extra",
        "domain","attacker_model","tested","result","finding_id","notes"]

def decode(target):
    """Return a path to a text AndroidManifest.xml."""
    if target.endswith(".xml"):
        return target, None
    tmp = tempfile.mkdtemp(prefix="inv_")
    r = subprocess.run(["apktool","d","-q","-f","-s",target,"-o",os.path.join(tmp,"apk")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("apktool failed:", r.stderr[:300], file=sys.stderr); shutil.rmtree(tmp, True); sys.exit(1)
    return os.path.join(tmp,"apk","AndroidManifest.xml"), tmp

def target_sdk(manifest_path):
    yml = os.path.join(os.path.dirname(manifest_path), "apktool.yml")
    if os.path.exists(yml):
        m = re.search(r'targetSdkVersion:\s*[\'"]?(\d+)', open(yml, errors="replace").read())
        if m: return int(m.group(1))
    return None

def main():
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    target = sys.argv[1]
    out = "inventory"
    if "--out" in sys.argv: out = sys.argv[sys.argv.index("--out")+1]
    os.makedirs(out, exist_ok=True)

    mpath, tmp = decode(target)
    tsdk = target_sdk(mpath)
    root = ET.parse(mpath).getroot()
    app = root.find("application")
    if app is None: print("no <application>", file=sys.stderr); sys.exit(1)

    rows, dl_rows, n = [], [], 0
    def add(kind, name, exported, reason, perm, extra, domain, am):
        nonlocal n
        n += 1
        rows.append(dict(instance_id=f"C-{n:03d}", type=kind, name=name,
                         exported=str(exported).lower(), export_reason=reason,
                         permission=perm or "NONE", extra=extra, domain=domain,
                         attacker_model=am, tested="false", result="", finding_id="", notes=""))

    DOM = {"activity":"D04","activity-alias":"D04","service":"D06","receiver":"D05","provider":"D07"}
    for tag in ("activity","activity-alias","service","receiver","provider"):
        for el in app.iter(tag):
            name = el.get(NS+"name","?")
            exp  = el.get(NS+"exported")
            has_filter = el.find("intent-filter") is not None
            perm = el.get(NS+"permission")
            if tag == "provider":
                perm = perm or "/".join(filter(None,[el.get(NS+"readPermission"), el.get(NS+"writePermission")]))
            if exp == "true":
                effective, reason = True, "explicit"
            elif exp is None and has_filter:
                # implicit export default flipped at targetSdk 31
                effective = True
                reason = "IMPLICIT (intent-filter, targetSdk<31)" if (tsdk is None or tsdk < 31) \
                         else "intent-filter present but targetSdk>=31 requires explicit — VERIFY"
            elif exp is None and tag == "provider" and (tsdk is None or tsdk < 17):
                effective, reason = True, "IMPLICIT (provider default, targetSdk<17)"
            else:
                effective, reason = False, "not exported"
            if not effective: continue

            extra = []
            if tag == "provider":
                a = el.get(NS+"authorities")
                if a: extra.append("authorities="+a)
                if el.get(NS+"grantUriPermissions") == "true": extra.append("grantUriPermissions")
            if tag in ("activity","activity-alias"):
                for k in ("launchMode","taskAffinity","allowTaskReparenting"):
                    v = el.get(NS+k)
                    if v is not None: extra.append(f"{k}={v}")
            add(tag, name, True, reason, perm, " ".join(extra), DOM[tag], "AM-03")

            # deep links declared on this component
            for f in el.findall("intent-filter"):
                av = f.get(NS+"autoVerify") == "true"
                acts = [a.get(NS+"name","") for a in f.findall("action")]
                if "android.intent.action.VIEW" not in acts: continue
                for d in f.findall("data"):
                    sch, host = d.get(NS+"scheme"), d.get(NS+"host")
                    if not sch and not host: continue
                    path = d.get(NS+"path") or d.get(NS+"pathPrefix") or d.get(NS+"pathPattern") or ""
                    dl_rows.append(dict(uri=f"{sch or '*'}://{host or '*'}{path}", component=name,
                                        autoVerify=str(av).lower(),
                                        assetlinks_checked="false", verified_on_device="",
                                        tested="false", result="", notes=""))

    for p in ("permission","permission-group","permission-tree"):
        for el in root.iter(p):
            add(p, el.get(NS+"name","?"), "n/a",
                "declared by this app", el.get(NS+"protectionLevel") or "normal (DEFAULT — implicit)",
                "", "D03", "AM-03")

    with open(os.path.join(out,"components.csv"),"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, COLS); w.writeheader(); w.writerows(rows)
    with open(os.path.join(out,"deeplinks.csv"),"w",newline="",encoding="utf-8") as f:
        cols = ["uri","component","autoVerify","assetlinks_checked","verified_on_device","tested","result","notes"]
        w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(dl_rows)

    for extra_file, cols in (("webviews.csv", ["instance_id","class","file_line","bridge_name",
                                               "js_enabled","file_access","allowlist_validator",
                                               "tested","result","notes"]),
                             ("endpoints.csv", ["instance_id","method","path","source",
                                                "auth_required","tested_idor","tested_massassign",
                                                "result","notes"])):
        p = os.path.join(out, extra_file)
        if not os.path.exists(p):
            with open(p,"w",newline="",encoding="utf-8") as f: csv.DictWriter(f, cols).writeheader()

    if tmp: shutil.rmtree(tmp, True)
    print(f"targetSdk: {tsdk}")
    print(f"  components.csv  {len(rows):>4} exported/declared instances  -> {out}/components.csv")
    print(f"  deeplinks.csv   {len(dl_rows):>4} deep-link patterns         -> {out}/deeplinks.csv")
    print(f"  webviews.csv    (fill during P4 — one row per WebView and per bridge method)")
    print(f"  endpoints.csv   (fill from tools/06-secrets-endpoints.sh — one row per route)")
    print("\nEVERY ROW STARTS tested=false. That is the point.")
    print("coverage.py --gate p7 will refuse to let escalation begin while any row is false.")

if __name__ == "__main__":
    main()
