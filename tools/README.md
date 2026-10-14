# tools/ — device and tree sweeps

Every tool here produces **candidates**, never findings. Each prints `--help` (exit 0) and exits `0`
when it ran and surfaced at least one candidate, `1` when it ran, every probe fired and all of them
closed — the only code a worker may record as a negative — and `2` on a usage or environment error
**or when nothing was interpretable**: no probe fired, fewer fired than given, no component/authority/
host to test, or every fired probe `UNVERIFIED` (timeout, hung device, unreadable directory, uid 0 where
export gates would not apply). Exit 2 means rerun, never "ruled out" (START.md R4). Every tool prints
`UNVERIFIED: <why>` wherever a check could not run — silence is never a negative — and `--json` (or a
`results.json` / `summary.json`) sits next to every human view. Discover the SDK the way
`scripts/doctor.sh` does (`ANDROID_SDK_ROOT`/`ANDROID_HOME`, then the conventional paths); set
`ANDROID_SERIAL` or pass `--serial` with more than one device (the tools refuse to guess and exit 2).

| Tool | Needs | Inputs | Outputs | Exit |
|---|---|---|---|---|
| `01-surface-inventory.sh <base.apk \| AndroidManifest.xml \| apktool-dir> [OUT] [--json] [--quiet]` | python3; apktool for an APK input | the APK, a decoded manifest or an apktool tree (with no input and `$E` set: `$E/decompiled/apktool`) | `OUT/inventory.txt`, `surface.json`, `AndroidManifest.xml`: targetSdk gates, flags, permissions, exported components (export reason, effective permission, attacker model), task-hijack surface, deep links, authorities + FileProvider paths, NSC, backup rules, framework, signer digest (APK input only) | 0 ≥1 candidate · 1 nothing exported, no risky flag · 2 usage/apktool failed |
| `02-component-sweep.sh <pkg> [--inventory DIR] [--out DIR] [--serial S] [--user N] [--settle S] [--json]` | device as uid 2000 (refuses uid 0) | exported activities from `inventory/components.csv` (fallback `dumpsys`, every class, marked UNVERIFIED-export) | `DIR/results.csv` (n,component,input,am_status,am_error,top_after,stayed,crash,tag,reason,log), `results.json`, `logs/<n>.txt` | 0 ≥1 candidate · 1 none · 2 no device/uid 0/no component/all UNVERIFIED |
| `03-provider-sweep.sh <pkg> [--inventory DIR] [--authority A] [--out DIR] [--serial S] [--user N] [--write] [--json]` | device (refuses uid 0) | authorities from `components.csv`, `--authority`, `dumpsys` | `DIR/results.csv` (n,authority,op,uri,args,result_class,tag,reason,head), `results.json` — the five-minute read/selection/write/call() pass; `09` adds UriMatcher mining, repeated baselines and the SQL oracle | 0 ≥1 candidate · 1 none · 2 no device/uid 0/no authority/all UNVERIFIED |
| `04-applink-verify.sh <pkg> [--apk base.apk] [--surface surface.json] [--inventory DIR] [--hosts h1,h2] [--serial S] [--out DIR] [--json]` | curl, python3; device optional (device checks print UNVERIFIED without one) | hosts from `--hosts`, `deeplinks.csv`, `surface.json` and the `dumpsys` `Authority:` lines; signer from `--apk` (apksigner, else keytool) or `surface.json` | `DIR/results.csv` (host,http,statements,for_package,match,stale,foreign,verdict), `assetlinks/<host>.json`, `results.json`; full fingerprints with MATCH / STALE / FOREIGN-PACKAGE per statement, `pm get-app-links` state | 0 ≥1 candidate · 1 every host fetched, verified and matching · 2 usage/no host |
| `05-storage-sweep.sh <pkg> [--user N\|all] [--out DIR] [--pull] [--backup] [--manifest F] [--serial S] [--full-values] [--json]` | device read as **uid 0 → `su -c` → `run-as`** (proved in that order; Magisk production builds refuse `adb root`) | package; optional decoded manifest | `DIR/inventory.csv` (user,path,size,mode,owner,label,sha256), `candidates.csv` (credential shapes with path:line, value MASKED + sha256 unless `--full-values`), `stores.csv` (by extension), `schema.txt` + pulled tree under `$E/sensitive/pulled/<pkg>/` (with `--pull`), `backup-set.txt` (with `--backup`: bmgr + LocalTransport, MASTG-TECH-0128), `summary.json`; every `CANDIDATE storage/*` line counts | 0 ≥1 candidate (any kind) · 1 none · 2 no device/no read mode/unreadable dir/0 files |
| `06-secrets-endpoints.sh <decompiled-dir> [OUT] [--inventory DIR] [--full-values] [--json]` · `06-secrets-endpoints.sh --selftest` | python3, grep | jadx/apktool tree | `OUT/endpoints.txt`, `endpoints-hits.csv`, `routes.csv` (method,path,file,line), `routes.txt` (bare `@GET("/path")` lines), `endpoints.csv` (inventory schema; `--inventory DIR` merges into `DIR/endpoints.csv`), `base-urls.txt`, `fields.txt`, `graphql.txt`, `secrets.csv` (shape,value,sha256,file,line,confidence,verify,restricted_signature — value MASKED unless `--full-values`), `verify-hints.sh` (only with `--full-values`), `cloud.csv`, `summary.json` | 0 ≥1 secret/cloud/endpoint candidate · 1 none · 2 usage · `--selftest` 0 pass / 2 fail |
| `07-deeplink-sweep.sh <pkg> <uris-file> [--out DIR] [--user N] [--serial S] [--pin] [--warm] [--settle S] [--dry-run] [--json]` | device | one URI per line (`intent:` URIs fired positionally); `mutations.txt` from 08 | `DIR/results.csv` (n,uri,am_status,am_activity,resumed,start_cmp,handled_by,crash,tag,reason,log), `results.json`, `logs/<n>.txt` (am -W output + logcat slice); prints `fired N of M` | 0 ≥1 candidate · 1 none · 2 usage/no device/fewer fired than given/all UNVERIFIED · `--dry-run` 0 |
| `08-deeplink-fuzz.py --inventory DIR --pkg P [--manifest F] [--out DIR] [--classes ...] [--params ...] [--only-base U-001] [--max N] [--pin] [--warm] [--screenshot] [--list] [--dry-run] [--json]` | python3; device unless `--list`/`--dry-run` | `DIR/deeplinks.csv` (+ `components.csv` for exported activities and provider authorities); a `*.host` is fired as `sub.host` and gets a `wildcard-root` mutation | `OUT/results.csv`, `results.json`, `mutations.txt` (feedable to 07), `logs/<probe>.txt`, `screenshots/` | 0 ≥1 candidate · 1 none · 2 usage/no device/no fireable base/nothing fired/all UNVERIFIED · `--list`/`--dry-run` 0 |
| `09-provider-fuzz.py --inventory DIR --pkg P [--authority A] [--dumpsys] [--paths F] [--jadx DIR] [--methods a,b] [--classes matrix,urimatcher,traversal,sql] [--repeat N] [--no-write] [--user N] [--out DIR] [--list] [--dry-run] [--json]` | python3; device unless `--list`/`--dry-run` | `DIR/components.csv` providers; optional decompiled sources | `OUT/results.csv` (probe,authority,op,uri,args,result_class,rows,bytes,hash,baseline_hash,tag,reason), `results.json` (per-authority summary), `logs/<probe>.txt` | 0 ≥1 candidate · 1 none · 2 usage/no device/no authority/nothing fired/all UNVERIFIED · `--list`/`--dry-run` 0 |

## Tags

`CANDIDATE <domain>/<what>` marks a line worth a human or a probe-app re-proof; `INFO` is context
(baseline handled, gate passed with nothing returned); `closed` names the mechanism that closed it;
`UNVERIFIED` means the check did not run and must not be recorded as a negative.

## Quoting through adb

`adb shell a b c` joins its arguments and hands **one string** to the device's `/system/bin/sh -c`.
Anything with `&`, `;`, `|`, `$`, `#`, spaces or quotes — every deep-link mutation, every SQL probe,
every inner-class name (`Foo$Bar`) — is re-parsed there unless it is quoted for the *remote* shell. The
rule used by every tool here:

```
rq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }        # bash
def rq(s): return "'" + s.replace("'", "'\\''") + "'"                      # python
adb shell "am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d $(rq "$U")"
adb shell "content query --uri $(rq "$URI") --where $(rq "$SEL")"
```

Values are single-quoted for the device shell and the whole remote command is a single argument. Under
`su -c` or `run-as <pkg> [--user N] sh -c` the wrapper quotes the finished command once more (05 does
this). A Python caller passes the finished string as ONE argv element after `shell`; a list such as
`['adb','shell','am','start','-d',u]` is joined with spaces and re-parsed on the device.

**stdin.** `adb shell` drains the stdin it inherits, so a foreground adb call inside
`while read … done < file` eats the rest of the file and the loop stops after one row. The tools read
their corpus on fd 3 (`done 3< "$FILE"`) and give every adb call `</dev/null`; copy that pattern into any
ad-hoc loop, and check the `fired N of M` line.

The device tools (02, 03, 04, 05, 07, 08, 09) were checked against a local `sh -c` simulator (a fake
`adb` on PATH that drains stdin and logs argv) because no device was attached when they were written; a
real device run is still owed — see each header.

## Start discipline (cold vs warm)

07 and 08 `am force-stop` the package before every probe and read the ActivityManager `START u0 … cmp=`
logcat line, which names the resolved component whether the start was cold or warm; `--warm` is the
second pass (no force-stop: `onNewIntent`, `singleTask`/`singleTop` reuse behave differently). Run
both. 02 reads `topResumedActivity` after `--settle` seconds, and a cold start routes through the
launcher activity and invalidates that reading, so 02 launches the app once and never force-stops it
(WARM-START ONLY). The two rules are not in conflict: they follow from what each tool reads.

## Writes on a real account

03 runs `content insert` only with `--write` (it puts a canary row `sane_probe=x` into a real account).
09's default matrix WRITES — a canary insert, update/delete with `--where 1=0` — pass `--no-write` on an
account you cannot wipe. 05 `--backup` switches the backup transport to LocalTransport and restores it.
Plant canaries; never touch a third party's rows (START.md "Never").

## adb is not an attacker model

`adb shell am/content` runs as the shell UID (2000), which holds permissions no third-party app has,
and on a rooted AVD it is uid 0, which reaches non-exported components (02 and 03 refuse to run there;
`adb unroot` first). Every result in this directory is **discovery**. Re-prove each candidate from the
zero-permission probe app (`../attacker-app/`, AM-03) or from a real HTML page in a real browser
(AM-02; the `intent://` browser matrix is D09-008) before it enters `findings/`. See `../START.md` R3
and `../docs/05-attacker-models.md`. Installing the target: `adb install --no-incremental` (or
`install-multiple --no-incremental` for splits) — with apksigner's `.idsig` files beside the APKs adb
switches to incremental installation and its "Incremental installation not allowed" error hides the
signature verdict.

## Secrets, masked values and what never gets committed

05 `candidates.csv` and 06 `secrets.csv` carry **masked** values (first 6–8 + last 4) plus the sha256
of the full value (de-duplication and later proof of identity). `--full-values` writes the real values
and 06's `verify-hints.sh`; use it only with `--out $E/sensitive/<name>` — `sensitive/`, `secrets/`,
`secrets.csv` and `verify-hints.sh` are gitignored by name, and `--pull` trees always land in
`$E/sensitive/pulled/<pkg>/`. A hit is a candidate until the benign read-only probe in the verify column
has been run by hand and its response recorded (D18-012: rate on what the key reaches).

## Third-party scanners and the positive control

The grep sweep in 06 is primary; run `06-secrets-endpoints.sh --selftest` first (a built-in fixture with
an XML-embedded `AIza…` key, a JWT in `assets/config.json` and a Retrofit interface must yield ≥3
secrets and ≥1 route) — a scanner that cannot find the fixture's keys cannot clear the target. Second
opinions, with their engagement-tested failure modes: `gitleaks dir <ONE path>` (several paths scan 0
bytes; its gcp rule needs a quote/space/`;` after the key, so `>AIza…<` inside XML never matches);
`semgrep --no-git-ignore` on a gitignored decompiled tree (else it scans nothing); `mobsfscan` dies
silently on ~40k+ files (copy `sources/` in chunks); `apkleaks` re-runs jadx for 15–20 min and its
JSON_Web_Token / Facebook_Secret_Key buckets are word lists (pre-filter them). A scanner's 0 is not
corroboration of 06's 0 unless it found the fixture. Chapter cross-references: D02-047, D18-004,
D26-025/026, D01-064.

## Hand-off to the inventory

One supported route: `python3 scripts/inventory.py <apk> --out $E/inventory --endpoints
$E/recon/secrets/routes.csv` (header-detected; `routes.txt` and `endpoints.txt` are also accepted).
06 `--inventory $E/inventory` merges the same rows directly, with the same vocabulary (`method=URL`
for literal URLs, `notes=CANDIDATE from tools/06 (…)`), so the two writers never mint two E-ids for one
URL; without `--inventory` 06 prints the inventory.py command and the register is untouched.
`inventory.py` registers components, deep links, WebViews and providers from the APK itself
(`python3 scripts/inventory.py base.apk --out $E/inventory`); 01's `surface.json` is the cross-check, and
04 reads its hosts from `deeplinks.csv` but writes its verdicts only to its own `results.csv`.

## Where outputs go

Every tool defaults `--out` to `$E/recon/<name>/` (`surface`, `component-sweep`, `provider-sweep`,
`applinks`, `storage`, `secrets`, `deeplink-sweep`, `deeplink-fuzz`, `provider-fuzz`) when `$E` or
`SANE_ENGAGEMENT` is set, and appends its human output to `$E/logs/tools-NN.txt` by itself (no `| tee`
needed; redirect only when you want a second copy). Without `$E` the fallback is `./<name>/<pkg>` in the
current directory, which is **not** gitignored: run from inside the engagement or pass `--out`, never
from the methodology checkout. Per-probe logs are `logs/<probe>.txt` under the tool's out dir; when one
supports an item, copy it to `$E/logs/<item_id>.txt` — the evidence convention of START.md §6 that
`../docs/04-poc-and-evidence-standard.md` builds on.

## Regression checks

`bash -n` and `--help` for every tool (`scripts/selftest.sh`), `tools/06 --selftest`, `tools/01` against a
fixture manifest (one exported activity with a VIEW filter, one provider: expect `surface.json`, exit 0),
and the stdin check for 05/07: a fake `adb` on PATH that drains stdin and logs argv must show as many
`am start` (07) or `cat shared_prefs/…` (05) calls as there are rows.
