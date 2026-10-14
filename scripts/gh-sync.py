#!/usr/bin/env python3
"""gh-sync.py — project the methodology onto the GitHub issue tracker, idempotently.

  GH_TOKEN=… python3 scripts/gh-sync.py --dry-run                 plan only
  GH_TOKEN=… python3 scripts/gh-sync.py                           labels + milestones + standing issues
  GH_TOKEN=… python3 scripts/gh-sync.py --only domains            just the D01…D28 batteries (or: phases, doctrine, start, labels, milestones)
  GH_TOKEN=… python3 scripts/gh-sync.py --audit docs/08-senior-audit-2026-10.md   one 'type: audit' issue per open defect row
  GH_TOKEN=… python3 scripts/gh-sync.py --prune-labels            also delete GitHub's default labels that the taxonomy does not use
  --repo owner/name   (default: parsed from `git remote get-url origin`)

Every standing issue carries a hidden marker `<!-- sane:key=<kind>:<id> -->` in its body; the script finds
it by that marker, else by title prefix, else by LEGACY_TITLES (issues created before markers existed, whose
titles differ: "⚖️ DOCTRINE — Severity & reportability …" is docs/02); it updates body/labels/milestone when
they changed (the marker is added on that update) and never closes it. It never creates a duplicate for a
key that resolves to an existing issue.
Bodies are generated from START.md, cards/Dnn.md, json/index.json and docs/*.md — edit the files, not the
issues. Uses the REST API via urllib (no gh CLI needed); needs `repo` scope.
"""
import base64, glob, json, os, re, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://api.github.com"
TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

LABELS = {
    # family: [(name, color, description)]
    "type": [("type: methodology", "0E8A16", "Standing doctrine. Never closed."),
             ("type: playbook", "0E8A16", "A phase of the state machine. Never closed."),
             ("type: checklist", "1D76DB", "A standing per-domain test battery. Never closed."),
             ("type: engagement", "5319E7", "Parent tracker for one target"),
             ("type: finding", "B60205", "A confirmed vulnerability from an engagement"),
             ("type: ruled-out", "0E8A16", "A clean sweep with the mechanism that closes it"),
             ("type: gap", "FBCA04", "A proposed new or corrected checklist item"),
             ("type: audit", "D93F0B", "A defect in the methodology itself")],
    "phase": [(f"phase: {i} {n}", "C5DEF5", f"Phase P{i}") for i, n in enumerate(
        ["scope", "lab", "acquire", "inventory", "static", "ipc", "network", "chain", "evidence", "report"])],
    "domain": [],   # filled from json/index.json (only domains that have a chapter), see _domain_labels()
    "area": [(f"area: {a}", "D4C5F9", "") for a in ["recon", "manifest-perms", "ipc", "deeplink-webview", "storage-crypto",
             "auth-session", "network-api", "native-supplychain", "cloud-sdk", "cross-platform", "privacy", "resilience",
             "platform", "payments", "push-messaging", "device-oem", "ai-llm", "tooling-reporting"]],
    "am": [(f"am: {a}", "F9D0C4", "") for a in ["remote", "one-click", "zero-perm-app", "one-perm-app", "cross-account",
           "network", "sdk", "backend", "physical"]],
    "sev": [("sev: critical", "B60205", "VRT P1"), ("sev: high", "D93F0B", "VRT P2"), ("sev: medium", "FBCA04", "VRT P3"),
            ("sev: low", "0E8A16", "VRT P4"), ("sev: informational", "C2E0C6", "VRT P5 — do not submit standalone")],
    "needs": [(f"needs-{n}", "E99695", "") for n in ["device", "root", "mitm", "frida", "two-accounts", "otp-route",
              "payment-sandbox", "kyc", "physical-device", "oem-image", "source", "staging"]],
    "flags": [("do-not-close", "000000", "Standing reference. Reopened automatically if closed."),
              ("high-yield", "B60205", "Where to spend the week"), ("graveyard", "7F7F7F", "Never pays standalone"),
              ("static-only", "C5DEF5", "Can be settled without a device"), ("blocked-by-operator", "E99695", "Waiting on something only the operator can supply"),
              ("good-first-hunt", "7057FF", "Cheap, high base rate"), ("legacy", "7F7F7F", "Only reachable below a stated API/targetSdk gate")],
}
DEFAULT_LABELS = ["bug", "documentation", "duplicate", "enhancement", "good first issue", "help wanted", "invalid", "question", "wontfix", "accessibility"]
AREA_BY_DOMAIN = {"D01": "recon", "D02": "recon", "D03": "manifest-perms", "D04": "ipc", "D05": "ipc", "D06": "ipc", "D07": "ipc", "D08": "ipc",
                  "D09": "deeplink-webview", "D10": "deeplink-webview", "D11": "storage-crypto", "D12": "storage-crypto", "D13": "auth-session",
                  "D14": "network-api", "D15": "network-api", "D16": "native-supplychain", "D17": "native-supplychain", "D18": "cloud-sdk",
                  "D19": "cross-platform", "D20": "privacy", "D21": "resilience", "D22": "platform", "D23": "payments", "D24": "push-messaging",
                  "D25": "device-oem", "D26": "tooling-reporting", "D27": "tooling-reporting", "D28": "ai-llm"}
# issues #2–#8 of the original tracker: no marker, different prefixes. key -> a phrase that appears in the legacy title.
LEGACY_TITLES = {"doc:02-severity-and-reportability.md": "severity & reportability",
                 "doc:03-lab-and-harness.md": "lab & harness",
                 "doc:04-poc-and-evidence-standard.md": "poc video & evidence",
                 "doc:05-attacker-models.md": "attacker models",
                 "doc:06-triage-playbook.md": "triage response",
                 "doc:07-coverage-crosswalk.md": "coverage crosswalk",
                 "start": "start here"}


def _domain_labels():
    try:
        doms = sorted(json.load(open(os.path.join(ROOT, "json", "index.json"), encoding="utf-8"))["domains"])
    except Exception:
        doms = [f"D{i:02d}" for i in range(1, 29)]
    return [(f"domain: {d}", "BFD4F2", f"Domain {d}") for d in doms]


LABELS["domain"] = _domain_labels()
AM_LABEL = {"AM-01": "remote", "AM-02": "one-click", "AM-03": "zero-perm-app", "AM-04": "one-perm-app", "AM-05": "cross-account",
            "AM-06": "network", "AM-07": "network", "AM-08": "sdk", "AM-09": "backend", "AM-10": "physical", "AM-11": "physical"}
PHASE_NAMES = ["Scope & Authorisation", "Lab & Harness", "Acquisition & Binary Identity", "Attack-Surface Inventory", "Static Deep Review",
               "IPC & Component Attack", "Network & Backend API", "Chaining & Escalation", "Evidence & PoC", "Report, Triage & Retest"]


def repo_slug(arg):
    if arg: return arg
    url = subprocess.run(["git", "-C", ROOT, "remote", "get-url", "origin"], capture_output=True, text=True).stdout.strip()
    if not url:  # linked worktrees and detached checkouts: fall back to the config value, then to the pushed branch's remote
        url = subprocess.run(["git", "-C", ROOT, "config", "--get", "remote.origin.url"], capture_output=True, text=True).stdout.strip()
    m = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', url)
    return f"{m.group(1)}/{m.group(2)}" if m else sys.exit("!! cannot determine repo; pass --repo owner/name")


def api(method, path, data=None, params=None):
    url = API + path + (("?" + urllib.parse.urlencode(params)) if params else "")
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {TOKEN}"); req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json"); req.add_header("User-Agent", "sane-android-gh-sync")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                txt = r.read().decode()
                return json.loads(txt) if txt else {}
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < 3:
                time.sleep(5 * (attempt + 1)); continue
            if e.code == 404: return None
            raise SystemExit(f"!! {method} {path}: {e.code} {e.read().decode()[:300]}")
    return None


def paged(path, params=None):
    out, page = [], 1
    while True:
        p = dict(params or {}); p.update({"per_page": 100, "page": page})
        r = api("GET", path, params=p)
        if not r: break
        out.extend(r)
        if len(r) < 100: break
        page += 1
    return out


class Sync:
    def __init__(self, slug, dry):
        self.slug, self.dry = slug, dry
        self.issues = paged(f"/repos/{slug}/issues", {"state": "all"}) if TOKEN else []
        self.issues = [i for i in self.issues if "pull_request" not in i]
        self.by_key = {}
        for i in self.issues:
            m = re.search(r'<!-- sane:key=([^ ]+) -->', i.get("body") or "")
            if m: self.by_key[m.group(1)] = i
        self.labels = {l["name"]: l for l in (paged(f"/repos/{slug}/labels") if TOKEN else [])}
        self.milestones = {m["title"]: m for m in (paged(f"/repos/{slug}/milestones", {"state": "all"}) if TOKEN else [])}
        self.actions = []

    def act(self, what): self.actions.append(what); print("  " + what)

    def ensure_labels(self, prune=False):
        for fam, items in LABELS.items():
            for name, color, desc in items:
                cur = self.labels.get(name)
                if not cur:
                    self.act(f"create label {name}")
                    if not self.dry: api("POST", f"/repos/{self.slug}/labels", {"name": name, "color": color, "description": desc})
                elif cur.get("color", "").lower() != color.lower() or (desc and (cur.get("description") or "") != desc):
                    self.act(f"update label {name}")
                    if not self.dry: api("PATCH", f"/repos/{self.slug}/labels/{urllib.parse.quote(name)}", {"new_name": name, "color": color, "description": desc})
        if prune:
            for name in DEFAULT_LABELS:
                if name in self.labels:
                    self.act(f"delete default label {name}")
                    if not self.dry: api("DELETE", f"/repos/{self.slug}/labels/{urllib.parse.quote(name)}")

    def ensure_milestones(self):
        for i, n in enumerate(PHASE_NAMES):
            title = f"M{i} · {n}"
            if not any(t.startswith(f"M{i} ") for t in self.milestones):
                self.act(f"create milestone {title}")
                if not self.dry:
                    m = api("POST", f"/repos/{self.slug}/milestones", {"title": title, "description": f"Phase P{i} — see START.md §4"})
                    if m: self.milestones[title] = m

    def milestone_number(self, i):
        for t, m in self.milestones.items():
            if t.startswith(f"M{i} ") or t.startswith(f"M{i}·") or t == f"M{i}": return m["number"]
        return None

    def upsert(self, key, title, body, labels, milestone=None):
        body = body.rstrip() + f"\n\n<!-- sane:key={key} -->\n"
        cur = self.by_key.get(key)
        if not cur:  # title fallback for issues created before markers existed
            pref = title.split(" — ")[0]
            unmarked = [i for i in self.issues if "sane:key=" not in (i.get("body") or "")]
            cands = [i for i in unmarked if (i.get("title") or "").startswith(pref)]
            if len(cands) != 1 and key in LEGACY_TITLES:          # looser: the legacy title phrase (case-insensitive)
                cands = [i for i in unmarked if LEGACY_TITLES[key] in (i.get("title") or "").lower()]
            if len(cands) == 1:
                cur = cands[0]; self.by_key[key] = cur
        payload = {"title": title, "body": body, "labels": sorted(set(labels))}
        if milestone: payload["milestone"] = milestone
        if not cur:
            self.act(f"create issue {title[:70]}")
            if not self.dry:
                r = api("POST", f"/repos/{self.slug}/issues", payload)
                if r: self.by_key[key] = r; self.issues.append(r)
            return
        changed = (cur.get("title") != title or (cur.get("body") or "").rstrip() != body.rstrip()
                   or sorted(l["name"] for l in cur.get("labels", [])) != payload["labels"]
                   or (milestone and (cur.get("milestone") or {}).get("number") != milestone))
        if cur.get("state") != "open" and "do-not-close" in labels:
            self.act(f"reopen #{cur['number']} {title[:60]}"); payload["state"] = "open"; changed = True
        if changed:
            self.act(f"update #{cur['number']} {title[:60]}")
            if not self.dry: api("PATCH", f"/repos/{self.slug}/issues/{cur['number']}", payload)


def read(p): return open(os.path.join(ROOT, p), encoding="utf-8").read()


def start_sections():
    t = read("START.md")
    secs = {}
    for m in re.finditer(r'^## (\d+)\. (.+?)\n(.*?)(?=^## \d+\.|\Z)', t, re.S | re.M):
        secs[int(m.group(1))] = (m.group(2).strip(), m.group(3).strip())
    return secs


def phase_rows():
    secs = start_sections()
    body = secs.get(4, ("", ""))[1]
    rows = []
    for line in body.splitlines():
        m = re.match(r'^\| \*\*(P\d) ([^*]+)\*\* \| (.*?) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \|$', line)
        if m: rows.append(m.groups())
    return rows


def domain_issue(d, meta, slug):
    card = read(f"cards/{d}.md")
    i = int(d[1:])
    ph = meta["phase"]; phn = int(ph[1:])
    labels = ["type: checklist", f"domain: {d}", f"phase: {phn} {['scope','lab','acquire','inventory','static','ipc','network','chain','evidence','report'][phn]}",
              f"area: {AREA_BY_DOMAIN.get(d, 'platform')}", "do-not-close"]
    ams = set()
    for it in json.load(open(os.path.join(ROOT, "json", d + ".json"), encoding="utf-8"))["items"]:
        for a in it.get("attacker_ids", []): ams.add(AM_LABEL.get(a))
    labels += [f"am: {a}" for a in sorted(x for x in ams if x)][:3]
    if d in ("D04", "D05", "D06", "D07", "D08", "D09", "D10", "D13", "D15", "D18", "D23"): labels.append("high-yield")
    if d in ("D21",): labels.append("graveyard")
    base = f"https://github.com/{slug}/blob/main"
    head = f"""## {d} · {meta['name']} — {meta['items']} items · phase {ph}

| Read | Why |
|---|---|
| [`START.md`]({base}/START.md) §5 | how to work one domain: card → applicability probe → items in triage order → `scripts/mark.py` |
| [`cards/{d}.md`]({base}/cards/{d}.md) | this battery (mirrored below) |
| `python3 scripts/item.py {d}-001` | any item in full; never load the chapter |
| [`checklist/{meta['file']}`]({base}/checklist/{meta['file']}) | the chapter — graveyard and cross-surface joins only |

**Rule R0.** Breadth before depth: confirm, park (`/park`), flip the row, move on. Escalation is P7.
**Done when** `python3 scripts/gate.py <eng> {ph.lower()}` no longer lists a `{d}` row and every matching `inventory/*.csv` instance is `tested=true`.

---

"""
    body = head + card.split("\n", 1)[1] if card.startswith("#") else head + card
    tail = "\n\n---\n> ### ⛔ DO NOT CLOSE\n> A standing battery, regenerated from the files by `scripts/gh-sync.py`. Track engagements in their folder (`scripts/state.py`), never by closing this."
    body = body[:60000] + tail
    return f"{d} · {meta['name']} — {meta['items']} tests", body, labels, phn


def main():
    a = sys.argv[1:]
    dry = "--dry-run" in a
    only = a[a.index("--only") + 1] if "--only" in a else "all"
    slug = repo_slug(a[a.index("--repo") + 1] if "--repo" in a else None)
    if not TOKEN and not dry: sys.exit("!! GH_TOKEN not set")
    print(f"repo {slug}  dry_run={dry}  only={only}")
    s = Sync(slug, dry)
    if only in ("all", "labels"): s.ensure_labels(prune="--prune-labels" in a)
    if only in ("all", "milestones"): s.ensure_milestones()
    index = json.load(open(os.path.join(ROOT, "json", "index.json"), encoding="utf-8"))
    base = f"https://github.com/{slug}/blob/main"
    if only in ("all", "start"):
        secs = start_sections()
        body = f"# START HERE\n\nThis issue mirrors [`START.md`]({base}/START.md). Read that file in full; this is the summary.\n\n"
        for n in (1, 2, 4):
            if n in secs: body += f"## {secs[n][0]}\n\n{secs[n][1]}\n\n"
        body += "\n---\n> ### ⛔ DO NOT CLOSE\n> Standing reference regenerated by `scripts/gh-sync.py`."
        s.upsert("start", "📖 START HERE — the operating procedure for any model", body[:60000], ["type: methodology", "phase: 0 scope", "do-not-close"], s.milestone_number(0))
    if only in ("all", "phases"):
        for (p, name, domains, entry, work, exit_, writes) in phase_rows():
            i = int(p[1:])
            body = (f"# {p} — {name}\n\n| | |\n|---|---|\n| **Domains** | {domains} |\n| **Entry** | {entry} |\n| **Work** | {work} |\n"
                    f"| **Exit (the gate)** | {exit_} |\n| **Writes** | {writes} |\n\n"
                    f"```bash\npython3 scripts/gate.py <eng> {p.lower()}            # what is still missing\npython3 scripts/gate.py <eng> --pass {p.lower()}     # record the gate when it is open\n```\n\n"
                    f"Skills: `/domain Dnn` for each domain above · `/park` · `/push` · `/status`. Full table and rules: [`START.md`]({base}/START.md) §4.\n\n"
                    "---\n> ### ⛔ DO NOT CLOSE\n> A standing playbook regenerated by `scripts/gh-sync.py`.")
            phn = ['scope', 'lab', 'acquire', 'inventory', 'static', 'ipc', 'network', 'chain', 'evidence', 'report'][i]
            s.upsert(f"phase:{p}", f"{i}️⃣ PHASE {i} — {name}", body, ["type: playbook", f"phase: {i} {phn}", "do-not-close"], s.milestone_number(i))
    if only in ("all", "domains"):
        for d, meta in sorted(index["domains"].items()):
            if not os.path.exists(os.path.join(ROOT, "cards", d + ".md")): continue
            title, body, labels, phn = domain_issue(d, meta, slug)
            s.upsert(f"domain:{d}", title, body, labels, s.milestone_number(phn))
    if only in ("all", "doctrine"):
        for p in sorted(glob.glob(os.path.join(ROOT, "docs", "*.md"))):
            name = os.path.basename(p)
            t = open(p, encoding="utf-8").read()
            title_line = t.splitlines()[0].lstrip("# ").strip()
            first = re.split(r'\n## ', t, maxsplit=1)[0][:3000]
            body = f"📄 [`docs/{name}`]({base}/docs/{name})\n\n{first}\n\n---\n> ### ⛔ DO NOT CLOSE\n> Standing doctrine regenerated by `scripts/gh-sync.py`."
            s.upsert(f"doc:{name}", f"📚 DOCTRINE — {title_line}"[:200], body, ["type: methodology", "do-not-close"])
    if "--audit" in a:
        path = a[a.index("--audit") + 1]
        t = read(path)
        n = 0
        rows5 = [[x.strip() for x in m.groups()] for m in re.finditer(r'^\| (L\d+|C\d+) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \|$', t, re.M)]
        rows4 = [[x.strip() for x in m.groups()] for m in re.finditer(r'^\| (L\d+|C\d+) \| (.*?) \| (.*?) \| (.*?) \|$', t, re.M)]
        seen = {r[0] for r in rows5}
        rows = rows5 + [[k, d, w, w, s] for k, d, w, s in rows4 if k not in seen]   # 4-cell tables: impact = why it matters
        for key, defect, why, impact, status in rows:
            if not key: continue
            open_ = not status.startswith("✅")
            title = f"[AUDIT {key}] {re.sub(r'[*`]', '', defect)[:110]}"
            body = f"From [`{path}`]({base}/{path}) row **{key}**.\n\n**Defect.** {defect}\n\n**Evidence / why it matters.** {why}\n\n**Impact.** {impact}\n\n**Status in the file.** {status}\n"
            cur = s.by_key.get(f"audit:{key}")
            if open_:
                s.upsert(f"audit:{key}", title, body, ["type: audit"]); n += 1
            elif cur and cur.get("state") == "open":
                s.act(f"close #{cur['number']} (fixed) {title[:50]}")
                if not dry: api("PATCH", f"/repos/{slug}/issues/{cur['number']}", {"state": "closed", "state_reason": "completed", "body": body + f"\n<!-- sane:key=audit:{key} -->"})
        print(f"audit rows open: {n}")
    print(f"{len(s.actions)} action(s){' planned' if dry else ' applied'}")


if __name__ == "__main__":
    main()
