#!/usr/bin/env bash
# 06-secrets-endpoints.sh <decompiled-dir> [OUT] [--out DIR] [--inventory DIR] [--full-values] [--json] [--help]
# 06-secrets-endpoints.sh --selftest        (positive control: a built-in fixture must yield >=3 secrets, >=1 route)
# Endpoint map + secret extraction from a jadx/apktool tree, with file:line provenance on every hit.
# Produces CANDIDATES. VERIFY RESTRICTION BEFORE REPORTING ANY KEY (hints are printed per shape, never run).
#
# Portability: grep -I (binary files skipped -- BSD grep otherwise prints "Binary file ... matches" on
# stdout and pollutes the lists), [[:space:]] instead of \s, --exclude-dir globs that both greps accept.
# The heavy scan is grep; classification, masking, the Basic-auth decode filter and the CSV/JSON
# writers are python3 (stdlib only).
#
# Outputs in OUT (default: $E/recon/secrets when $E is set, else ./secrets/; the human output is appended to
# $E/logs/tools-06.txt when $E is set):
#   endpoints.txt    unique URLs            endpoints-hits.csv  url,file,line
#   routes.csv       method,path,file,line  (Retrofit annotation VALUES survive R8 -- authoritative)
#   routes.txt       one bare @GET("/path") line per route -- the form scripts/inventory.py --endpoints parses
#   endpoints.csv    inventory schema: instance_id(E-NNN),method,path,source,auth_required,tested_idor,
#                    tested_massassign,result,notes   (--inventory DIR merges into DIR/endpoints.csv)
#   fields.txt       @SerializedName / R8-renamed @x("name") on field lines (mass-assignment candidates)
#   graphql.txt      operation names        base-urls.txt   Retrofit baseUrl()/BASE_URL constants
#   secrets.csv      shape,value,sha256,file,line,confidence,verify,restricted_signature
#                    value is MASKED (first 6 + last 4) and de-duplicated by sha256 unless --full-values; with
#                    --full-values point --out at $E/sensitive/ -- full values never belong in a committed tree
#   verify-hints.sh  one benign read-only probe per secret, commented out, for the operator to run
#                    (written only with --full-values: a probe needs the full value); raw/secrets.txt is
#                    deleted after parsing unless --full-values
#   cloud.csv        host,kind,file,line,probe      summary.json
# Exit: 0 ran and found >=1 secret/cloud/endpoint candidate; 1 ran, nothing found; 2 usage/environment.
#
# Third-party scanners (engagement-tested; the grep sweep here is PRIMARY, run them only as a second opinion):
#   gitleaks   `gitleaks dir <ONE path>` -- several paths scan 0 bytes; its gcp rule needs a quote/space/';'
#              after the key, so an AIza key inside XML (>AIza...<) is never matched (0 leaks on a tree with keys).
#   semgrep    needs --no-git-ignore on a gitignored jadx tree, else it scans nothing.
#   mobsfscan  dies silently on ~40k+ files: copy sources/ in chunks.
#   apkleaks   re-runs jadx (15-20 min) and its JSON_Web_Token / Facebook_Secret_Key buckets are TLD/word lists:
#              pre-filter those buckets before reading.
#   Always run --selftest first: a scanner that cannot find the fixture's keys cannot clear the target.
set -uo pipefail

usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
DIR=""; OUT=""; INV=""; JSON=0; FULL=0; SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out)       OUT="${2:-}"; shift ;;
    --inventory) INV="${2:-}"; shift ;;
    --json)      JSON=1 ;;
    --full-values) FULL=1 ;;
    --selftest)  SELFTEST=1 ;;
    -h|--help)   usage 0 ;;
    -*)          echo "unknown option: $1" >&2; usage ;;
    *)           if [ -z "$DIR" ]; then DIR="$1"; elif [ -z "$OUT" ]; then OUT="$1"; else echo "unexpected: $1" >&2; usage; fi ;;
  esac
  shift
done
command -v python3 >/dev/null 2>&1 || { echo "UNVERIFIED: python3 missing"; exit 2; }
if [ "$SELFTEST" = 1 ]; then
  # Positive control: a tiny decompiled tree with an XML-embedded Google key, a JWT and an AWS id in
  # assets/, and one Retrofit route. If this does not fire, nothing this tool says about a target counts.
  TD="$(mktemp -d)" || exit 2; trap 'rm -rf "$TD"' EXIT
  mkdir -p "$TD/tree/res/values" "$TD/tree/assets" "$TD/tree/sources/com/example/api"
  printf '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <string name="maps_key">AIzaSyA1234567890abcdefghijklmnopqrstuv</string>\n</resources>\n' > "$TD/tree/res/values/strings.xml"
  printf '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJlc2lnbmF0dXJl","aws":"AKIAIOSFODNN7EXAMPLE","api":"https://api.selftest.invalid/v1/users"}\n' > "$TD/tree/assets/config.json"
  printf 'package com.example.api;\npublic interface Api {\n    @GET("/v1/users/{id}")\n    Call<User> user(@Path("id") String id);\n    @SerializedName("user_id") String userId;\n}\n' > "$TD/tree/sources/com/example/api/Api.java"
  E= SANE_ENGAGEMENT= bash "$0" "$TD/tree" --out "$TD/out" >"$TD/log" 2>&1; rc=$?
  NS=$(( $(grep -c '' "$TD/out/secrets.csv" 2>/dev/null || echo 1) - 1 )); NR=$(( $(grep -c '' "$TD/out/routes.csv" 2>/dev/null || echo 1) - 1 ))
  if [ "$rc" = 0 ] && [ "$NS" -ge 3 ] && [ "$NR" -ge 1 ]; then echo "selftest OK: rc=$rc secrets=$NS routes=$NR"; exit 0; fi
  echo "selftest FAILED: rc=$rc secrets=$NS (want >=3) routes=$NR (want >=1) -- see:"; cat "$TD/log"; exit 2
fi
[ -z "$DIR" ] && usage
[ -d "$DIR" ] || { echo "ERROR: not a directory: $DIR" >&2; exit 2; }
E="${E:-${SANE_ENGAGEMENT:-}}"
if [ -z "$OUT" ]; then if [ -n "$E" ]; then OUT="$E/recon/secrets"; else OUT="secrets"; fi; fi
mkdir -p "$OUT/raw" || { echo "ERROR: cannot create $OUT" >&2; exit 2; }
if [ -n "$E" ] && [ -d "$E" ]; then mkdir -p "$E/logs" && exec > >(tee -a "$E/logs/tools-06.txt"); fi

# G <ERE>: recursive, file:line:match, text files only, skipping native libs and image resources.
G() {
  grep -rnoIE --exclude-dir=lib --exclude-dir=META-INF --exclude-dir=original --exclude-dir='drawable*' \
       --exclude-dir='mipmap*' --exclude-dir=font --exclude-dir=.git "$1" "$DIR" 2>/dev/null
}

echo "[*] scanning $DIR  (grep -I: binaries skipped; provenance kept as file:line)"
G 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]{6,}'                                   > "$OUT/raw/urls.txt"
G '@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\("[^"]*"\)|@HTTP\(method = "[A-Z]+", path = "[^"]*"' > "$OUT/raw/routes.txt"
G 'baseUrl\("[^"]+"\)|BASE_URL[[:space:]]*=[[:space:]]*"[^"]+"'                     > "$OUT/raw/baseurls.txt"
G '@SerializedName\("[^"]+"\)|@Json\(name = "[^"]+"\)|@SerialName\("[^"]+"\)|@JsonProperty\("[^"]+"\)' > "$OUT/raw/fields.txt"
# R8 renames the annotation class to any 1-3 letter name but the VALUE survives; the python filter keeps
# only hits that sit on a field declaration line to drop @c("x") on methods/classes.
grep -rnIE --exclude-dir=lib --exclude-dir=META-INF --exclude-dir=original --exclude-dir='drawable*' \
     --exclude-dir='mipmap*' --exclude-dir=font --exclude-dir=.git \
     '^[[:space:]]*@[A-Za-z]{1,3}\("[^"]+"\)[[:space:]]+(public |private |protected |final |static |transient )*[A-Za-z0-9_.<>?,\[\]]+ [A-Za-z0-9_]+( =.*)?;' "$DIR" 2>/dev/null \
     > "$OUT/raw/fields-r8.txt"
G '(query|mutation|subscription)[[:space:]]+[A-Za-z0-9_]+[[:space:]]*[({]'          > "$OUT/raw/graphql.txt"
G 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|(sk|rk)_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9A-Za-z-]{10,}|sk-(proj-)?[A-Za-z0-9_-]{32,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|AC[0-9a-f]{32}|SK[0-9a-f]{32}|[ps]k\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|Basic [A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"current_key"[[:space:]]*:[[:space:]]*"[^"]+"|[Aa][Ww][Ss][A-Za-z_]{0,20}[Ss][Ee][Cc][Rr][Ee][Tt][^"'"'"']{0,30}["'"'"'][A-Za-z0-9/+=]{40}["'"'"']' \
                                                                                      > "$OUT/raw/secrets.txt"
G '[a-z0-9.-]+\.(firebaseio\.com|firebasedatabase\.app|appspot\.com|cloudfunctions\.net|run\.app|supabase\.co|blob\.core\.windows\.net|storage\.googleapis\.com|amazonaws\.com)|firebasestorage\.googleapis\.com/v0/b/[a-z0-9.-]+|s3://[a-z0-9.-]+|storage\.googleapis\.com/[a-z0-9._-]+' \
                                                                                      > "$OUT/raw/cloud.txt"

python3 -I - "$OUT" "$INV" "$JSON" "$DIR" "$FULL" <<'PY'
import base64, csv, hashlib, json, os, re, sys
out, inv, js, root, full = sys.argv[1:6]
full = full == "1"
raw = lambda n: [l.rstrip("\n") for l in open(os.path.join(out, "raw", n), errors="replace")]
def split(line):                       # grep -rno -> file:line:match ; the match may itself contain ':'
    m = re.match(r"^(.*?):(\d+):(.*)$", line)
    return m.groups() if m else None
def rel(p): return os.path.relpath(p, root)
def mask(v): return v if len(v) <= 14 else v[:6] + "..." + v[-4:]
def w(name, header, rows):
    with open(os.path.join(out, name), "w", newline="", encoding="utf-8") as f:
        c = csv.writer(f); c.writerow(header); c.writerows(rows)

# -- endpoints -------------------------------------------------------------------------------------
urls = {}
for l in raw("urls.txt"):
    s = split(l)
    if not s: continue
    f, n, u = s
    u = u.rstrip(").,;'\"")
    if re.search(r"schemas\.android\.com|w3\.org|apache\.org/licenses|xmlpull\.org|example\.com|developer\.android\.com", u): continue
    urls.setdefault(u, (rel(f), n))
open(os.path.join(out, "endpoints.txt"), "w").write("\n".join(sorted(urls)) + ("\n" if urls else ""))
w("endpoints-hits.csv", ["url", "file", "line"], [[u, f, n] for u, (f, n) in sorted(urls.items())])
routes = {}
for l in raw("routes.txt"):
    s = split(l)
    if not s: continue
    f, n, a = s
    m = re.match(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\("([^"]*)"', a) or re.match(r'@HTTP\(method = "([A-Z]+)", path = "([^"]*)"', a)
    if m: routes.setdefault((m.group(1), m.group(2)), (rel(f), n))
w("routes.csv", ["method", "path", "file", "line"], [[m, p, f, n] for (m, p), (f, n) in sorted(routes.items())])
open(os.path.join(out, "routes.txt"), "w").write("".join('@%s("%s")\n' % (m, p) for (m, p) in sorted(routes)))   # scripts/inventory.py --endpoints form
bases = sorted({split(l)[2] for l in raw("baseurls.txt") if split(l)})
open(os.path.join(out, "base-urls.txt"), "w").write("\n".join(bases) + ("\n" if bases else ""))
# inventory schema (scripts/inventory.py): one row per route, plus literal URLs as method=URL
cols = ["instance_id", "method", "path", "source", "auth_required", "tested_idor", "tested_massassign", "result", "notes"]
existing, target = [], os.path.join(inv, "endpoints.csv") if inv else os.path.join(out, "endpoints.csv")
if inv and os.path.exists(target):
    existing = list(csv.DictReader(open(target, newline="", encoding="utf-8")))
have = {(r.get("method", ""), r.get("path", "")) for r in existing}
nid = 1 + max([int(m.group(1)) for r in existing for m in [re.match(r"E-(\d+)", r.get("instance_id", ""))] if m] or [0])
new = []
for (m, p), (f, n) in sorted(routes.items()):
    if (m, p) in have: continue
    new.append(dict(instance_id=f"E-{nid:03d}", method=m, path=p, source=f"{f}:{n}", auth_required="", tested_idor="false",
                    tested_massassign="false", result="", notes="CANDIDATE from tools/06 (retrofit)")); nid += 1
for u, (f, n) in sorted(urls.items()):
    if ("URL", u) in have: continue
    new.append(dict(instance_id=f"E-{nid:03d}", method="URL", path=u, source=f"{f}:{n}", auth_required="", tested_idor="false",
                    tested_massassign="false", result="", notes="CANDIDATE from tools/06 (literal URL)")); nid += 1
if inv: os.makedirs(inv, exist_ok=True)
with open(target, "w", newline="", encoding="utf-8") as fh:
    c = csv.DictWriter(fh, cols); c.writeheader(); c.writerows(existing + new)
# -- fields / graphql ------------------------------------------------------------------------------
fields = sorted({re.search(r'"([^"]+)"', split(l)[2]).group(1) for l in raw("fields.txt") if split(l) and re.search(r'"([^"]+)"', split(l)[2])})
r8 = []
for l in raw("fields-r8.txt"):
    m = re.match(r'^(.*?):(\d+):\s*(@[A-Za-z]{1,3}\("[^"]+"\).*)$', l)
    if m: r8.append(f'{m.group(3).strip()[:120]}    # {rel(m.group(1))}:{m.group(2)}')
open(os.path.join(out, "fields.txt"), "w").write("\n".join(fields + ["# R8-renamed annotation on a field line (heuristic):"] + sorted(set(r8))[:400]) + "\n")
gql = sorted({split(l)[2] for l in raw("graphql.txt") if split(l)})
open(os.path.join(out, "graphql.txt"), "w").write("\n".join(gql) + ("\n" if gql else ""))

# -- secrets ---------------------------------------------------------------------------------------
SHAPES = [  # (name, regex, confidence, probe template, restricted/unrestricted signature)
 ("google-api-key", r"AIza[0-9A-Za-z_-]{35}", "high",
  'curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key={v}" | head -c 300',
  'REQUEST_DENIED + "Requests from this Android client are blocked" = package+SHA-1 restricted (P5, ruled-out row); "status": "OK" = unrestricted -> D18-010/012'),
 ("google-services-key", r'"current_key"\s*:\s*"([^"]+)"', "high",
  'curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key={v}" | head -c 300',
  'same as google-api-key; google-services.json keys are usually restricted by design'),
 ("aws-access-key", r"AKIA[0-9A-Z]{16}", "medium",
  'AWS_ACCESS_KEY_ID={v} AWS_SECRET_ACCESS_KEY=<40-char value near the hit> aws sts get-caller-identity',
  'InvalidClientTokenId = dead; an ARN = live (never paste the secret into the report)'),
 ("aws-secret-key", r"[Aa][Ww][Ss][A-Za-z_]{0,20}[Ss][Ee][Cc][Rr][Ee][Tt][^\"']{0,30}[\"']([A-Za-z0-9/+=]{40})[\"']", "low",
  '# pair with the AKIA id in the same tree, then: aws sts get-caller-identity', 'as aws-access-key'),
 ("github-token", r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}", "high",
  'curl -s -o /dev/null -w "%{http_code}\\n" -H "Authorization: token {v}" https://api.github.com/user', '200 = live; 401 = revoked'),
 ("stripe-secret", r"sk_live_[0-9a-zA-Z]{24,}", "high",
  'curl -s -o /dev/null -w "%{http_code}\\n" -u "{v}:" https://api.stripe.com/v1/balance', '200 = live secret key (P1); 401 = revoked'),
 ("stripe-restricted", r"rk_live_[0-9a-zA-Z]{24,}", "medium",
  'curl -s -o /dev/null -w "%{http_code}\\n" -u "{v}:" https://api.stripe.com/v1/balance', 'restricted key: rate on its granted permissions, not P1 by default'),
 ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "high",
  'curl -s -H "Authorization: Bearer {v}" https://slack.com/api/auth.test', '"ok":true = live'),
 ("openai-key", r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}", "medium",
  'curl -s -o /dev/null -w "%{http_code}\\n" -H "Authorization: Bearer {v}" https://api.openai.com/v1/models', '200 = live; 401 = revoked'),
 ("sendgrid-key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "high",
  'curl -s -o /dev/null -w "%{http_code}\\n" -H "Authorization: Bearer {v}" https://api.sendgrid.com/v3/scopes', '200 = live; 401 = revoked'),
 ("twilio-sid", r"AC[0-9a-f]{32}", "low",
  'curl -s -o /dev/null -w "%{http_code}\\n" -u "{v}:<auth token or SK key near the hit>" https://api.twilio.com/2010-04-01/Accounts/{v}.json', '200 = live; 401 = dead'),
 ("twilio-api-key", r"SK[0-9a-f]{32}", "low", '# pair with the AC... SID; same probe as twilio-sid', 'as twilio-sid'),
 ("mapbox-token", r"[ps]k\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "medium",
  'curl -s "https://api.mapbox.com/tokens/v2?access_token={v}" | head -c 300',
  'pk. = public by design (P5) unless scopes exceed styles:read/fonts:read; sk. = secret token'),
 ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "medium",
  "python3 -c 'import base64,sys; [print(base64.urlsafe_b64decode(p+\"=\"*(-len(p)%4)).decode(errors=\"replace\")) for p in sys.argv[1].split(\".\")[:2]]' '{v}'",
  'read alg/role/exp: a Supabase anon key ("role":"anon") is public by design; anything else is replayed against its issuer'),
 ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "high",
  '# openssl pkey -in <file> -noout -text | head -3 ; is it a client-cert key (D14 mTLS) or a signing key?', 'rate on what it signs or authenticates, never on presence'),
 ("basic-auth", r"Basic [A-Za-z0-9+/=]{20,}", "medium",
  '# decoded user:pass is in secrets.csv; replay against the host it sits next to in the same file', 'live credentials = P1-P2 by asset'),
]
rows, seen = [], set()
for l in raw("secrets.txt"):
    s = split(l)
    if not s: continue
    f, n, v = s
    for name, rx, conf, probe, sig in SHAPES:
        m = re.search(rx, v)
        if not m: continue
        val = m.group(1) if m.groups() else m.group(0)
        if name == "basic-auth":
            try: dec = base64.b64decode(val[6:].strip() + "=" * (-len(val[6:].strip()) % 4)).decode()
            except Exception: dec = ""
            if ":" not in dec or not dec.isprintable(): break   # prose that happens to look like base64
            val = f"{val}  ({dec})"
        key = (name, val)
        if key in seen: break
        seen.add(key)
        bare = val.split("  ")[0]
        rows.append([name, val if full else mask(bare), hashlib.sha256(bare.encode()).hexdigest(), rel(f), n, conf,
                     probe.replace("{v}", bare) if full else probe, sig]); break
w("secrets.csv", ["shape", "value", "sha256", "file", "line", "confidence", "verify", "restricted_signature"], rows)
hints = os.path.join(out, "verify-hints.sh")
if full:
    with open(hints, "w") as fh:
        fh.write("#!/usr/bin/env bash\n# Benign, read-only probes. Run ONE AT A TIME, by hand, and record the exact response in the\n# ruled-out table or the finding. Nothing here is executed by 06-secrets-endpoints.sh.\n")
        for r in rows: fh.write(f"\n# {r[0]}  {r[3]}:{r[4]}\n#   expect: {r[7]}\n# {r[6]}\n")
elif os.path.exists(hints): os.remove(hints)
# -- cloud -----------------------------------------------------------------------------------------
cloud, cseen = [], set()
for l in raw("cloud.txt"):
    s = split(l)
    if not s: continue
    f, n, h = s
    kind = ("firebase-rtdb" if re.search(r"firebaseio\.com|firebasedatabase\.app", h) else "firebase-storage" if "firebasestorage" in h else
            "appspot" if "appspot" in h else "cloud-functions" if "cloudfunctions" in h or "run.app" in h else "supabase" if "supabase" in h else
            "azure-blob" if "blob.core.windows" in h else "gcs" if "storage.googleapis" in h else "s3" if "amazonaws" in h or h.startswith("s3://") else "cloud")
    probe = {"firebase-rtdb": f'curl -s "https://{h}/.json?shallow=true" -w "\\nHTTP %{{http_code}}\\n" | head -c 300',
             "firebase-storage": f'curl -s "https://{h}" | head -c 300',
             "supabase": f'curl -s "https://{h}/rest/v1/" -H "apikey: <anon JWT from secrets.csv>" | head -c 300'}.get(kind,
             f'curl -s -o /dev/null -w "%{{http_code}}\\n" "https://{h.replace("s3://", "")}"')
    if h in cseen: continue
    cseen.add(h); cloud.append([h, kind, rel(f), n, probe])
w("cloud.csv", ["host", "kind", "file", "line", "probe"], cloud)

# -- report ----------------------------------------------------------------------------------------
print(f"    unique URLs: {len(urls)}   retrofit routes: {len(routes)}   base URLs: {len(bases)}   graphql ops: {len(gql)}   serialized fields: {len(fields)}")
print(f"    endpoints.csv: {len(new)} new rows -> {target}")
print("[*] secret-shaped CANDIDATES (%s in secrets.csv; probe template in the verify column%s):" % (
      "FULL values" if full else "masked values + sha256", "" if full else " -- rerun with --full-values --out $E/sensitive/secrets for verify-hints.sh"))
for r in rows: print(f"    CANDIDATE secret/{r[0]:20s} {r[3]}:{r[4]}  {mask(r[1].split('  ')[0])}  [{r[5]}]")
if not rows: print("    (none; a negative here only means these shapes were absent -- check strings.xml, assets/*.json, native .so (D16) and the network capture)")
print("[*] cloud resources (probe column in cloud.csv):")
for c in cloud: print(f"    CANDIDATE cloud/{c[1]:17s} {c[0]}  ({c[2]}:{c[3]})")
summary = {"tool": "06-secrets-endpoints", "dir": root, "out": out, "urls": len(urls), "routes": len(routes), "base_urls": bases,
           "graphql": len(gql), "fields": len(fields), "values": "full" if full else "masked+sha256",
           "secrets": [{"shape": r[0], "masked": mask(r[1].split("  ")[0]), "sha256": r[2], "file": r[3], "line": r[4], "confidence": r[5]} for r in rows],
           "cloud": [{"host": c[0], "kind": c[1], "file": c[2], "line": c[3]} for c in cloud], "endpoints_csv": target,
           "note": "candidates only; every key must be verified with the benign probe and the exact response recorded either way"}
json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
if js == "1": print(json.dumps(summary, indent=1))
sys.exit(0 if (rows or cloud or urls or routes) else 1)
PY
RC=$?
[ "$FULL" = 1 ] || rm -f "$OUT/raw/secrets.txt"    # the raw grep carries full values

cat <<'NOTE'

  ****  DO NOT REPORT A KEY UNTIL YOU HAVE VERIFIED IT IS UNRESTRICTED  ****
  Most Google/Maps/Firebase keys in APKs are package+signature restricted and PUBLIC BY DESIGN.
  VRT: sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid = P5
       sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset        = P1
  The difference is one benign probe (verify-hints.sh). Run it by hand, record the exact response
  either way (ruled-out table or finding). Rate on what the key reaches (D18-012), not on its presence.
NOTE
exit "$RC"
