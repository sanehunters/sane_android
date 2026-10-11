# tools/ — device and tree sweeps

Every tool here produces **candidates**, never findings. Each prints `--help`, exits `0` when it ran
and surfaced at least one candidate, `1` when it ran and found nothing (every probe closed/absent),
`2` on a usage or environment error, and prints `UNVERIFIED: <why>` wherever a check could not run —
silence is never a negative (START.md R4). `--json` (or a `results.json`) sits next to every human
view. Discover the SDK the way `scripts/doctor.sh` does (`ANDROID_SDK_ROOT`/`ANDROID_HOME`, then the
conventional paths); set `ANDROID_SERIAL` or pass `--serial` with more than one device.

| Tool | Needs | Inputs | Outputs | Exit |
|---|---|---|---|---|
| `01-surface-inventory.sh <base.apk> [OUT]` | apktool, python3 | the APK | `OUT/inventory.txt`, `OUT/AndroidManifest.xml`: SDK gates, flags, exported components, task-hijack surface, deep links, authorities, FileProvider paths, NSC, framework | 0 ran · 1 apktool failed |
| `02-component-sweep.sh <pkg>` | device | package | table: component × input → top activity, crash list | 0 ran |
| `03-provider-sweep.sh <pkg>` | device | package (authorities from dumpsys) | R/Q/W/C rows per authority — superseded for depth by `09-provider-fuzz.py` | 0 ran |
| `04-applink-verify.sh <pkg>` | device, curl | package | `pm get-app-links`, domain-preferred apps, `assetlinks.json` per host | 0 ran |
| `05-storage-sweep.sh <pkg> [--user N\|all] [--out DIR] [--pull] [--backup] [--manifest F] [--serial S] [--json]` | device read as **uid 0 → `su -c` → `run-as`** (proved in that order; Magisk production builds refuse `adb root`) | package; optional decoded manifest | `DIR/inventory.csv` (user,path,size,mode,owner,label,sha256), `candidates.csv` (credential shapes with path:line), `stores.csv` (by extension), `schema.txt` (with `--pull`), `backup-set.txt` (with `--backup`: bmgr + LocalTransport, MASTG-TECH-0128), `summary.json` | 0 ≥1 candidate · 1 none · 2 no device/no read mode |
| `06-secrets-endpoints.sh <decompiled-dir> [OUT] [--inventory DIR] [--json]` | python3, grep | jadx/apktool tree | `OUT/endpoints.txt`, `endpoints-hits.csv`, `routes.csv`, `base-urls.txt`, `fields.txt`, `graphql.txt`, `secrets.csv` (shape,value,file,line,confidence,verify,restricted_signature — full values, keep out of git), `verify-hints.sh` (benign probes, never executed), `cloud.csv`, `summary.json`, and `endpoints.csv` in the `scripts/inventory.py` schema (`E-NNN`; `--inventory` merges into `<eng>/inventory/endpoints.csv`) | 0 ≥1 candidate · 1 none · 2 usage |
| `07-deeplink-sweep.sh <pkg> <uris-file> [--out DIR] [--user N] [--pin] [--warm] [--settle S] [--dry-run] [--json]` | device | one URI per line (`intent:` URIs fired positionally) | `DIR/results.csv` (n,uri,am_status,am_activity,resumed,start_cmp,handled_by,crash,tag,reason,log), `results.json`, `logs/<n>.txt` (am -W output + logcat slice) | 0 ≥1 candidate · 1 none · 2 usage/no device |
| `08-deeplink-fuzz.py --inventory DIR --pkg P [--manifest F] [--classes ...] [--params ...] [--only-base U-001] [--max N] [--pin] [--warm] [--screenshot] [--list] [--dry-run] [--json]` | python3; device unless `--list`/`--dry-run` | `DIR/deeplinks.csv` (+ `components.csv` for exported activities and provider authorities) | `deeplink-fuzz/<pkg>/results.csv`, `results.json`, `mutations.txt` (feedable to 07), `logs/<probe>.txt`, `screenshots/` | 0 ≥1 candidate · 1 none · 2 usage/no device · `--list`/`--dry-run` 0 |
| `09-provider-fuzz.py --inventory DIR --pkg P [--authority A] [--dumpsys] [--paths F] [--jadx DIR] [--methods a,b] [--classes matrix,urimatcher,traversal,sql] [--repeat N] [--no-write] [--user N] [--list] [--dry-run] [--json]` | python3; device unless `--list`/`--dry-run` | `DIR/components.csv` providers; optional decompiled sources | `provider-fuzz/<pkg>/results.csv` (probe,authority,op,uri,args,result_class,rows,bytes,hash,baseline_hash,tag,reason), `results.json` (per-authority summary), `logs/<probe>.txt` | 0 ≥1 candidate · 1 none · 2 usage/no device · `--list`/`--dry-run` 0 |

## Tags

`CANDIDATE <domain>/<what>` marks a line worth a human or a probe-app re-proof; `INFO` is context
(baseline handled, gate passed with nothing returned); `closed` names the mechanism that closed it;
`UNVERIFIED` means the check did not run and must not be recorded as a negative.

## Quoting through adb

`adb shell a b c` joins its arguments and hands **one string** to the device's `/system/bin/sh -c`.
Anything with `&`, `;`, `|`, `$`, `#`, spaces or quotes — every deep-link mutation, every SQL probe —
is re-parsed there unless it is quoted for the *remote* shell. The rule used by every tool here:

```
rq() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }        # bash
def rq(s): return "'" + s.replace("'", "'\\''") + "'"                      # python
adb shell "am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d $(rq "$U")"
adb shell "content query --uri $(rq "$URI") --where $(rq "$SEL")"
```

Values are single-quoted for the device shell and the whole remote command is a single argument. Under
`su -c` or `run-as … sh -c` the wrapper quotes the finished command once more (05 does this). The five
device tools were checked against a local `sh -c` simulator (fake `adb`, `am`, `content`) because no
device was attached when they were written; a real device run is still owed — see each header.

## adb is not an attacker model

`adb shell am/content` runs as the shell UID (2000), which holds permissions no third-party app has.
Every result in this directory is **discovery**. Re-prove each candidate from the zero-permission probe
app (`../attacker-app/`, AM-03) or from a real HTML page in a real browser (AM-02; the `intent://`
browser matrix is D09-008) before it enters `findings/`. See `../START.md` R3 and
`../docs/05-attacker-models.md`.

## Where outputs go

Point `--out` at the engagement: `tools/05-storage-sweep.sh pkg --out $E/evidence/storage`,
`python3 tools/08-deeplink-fuzz.py --inventory $E/inventory --pkg pkg --out $E/evidence/deeplink-fuzz`.
Per-probe logs are the `logs/<item_id>.txt` evidence of `../docs/04-poc-and-evidence-standard.md`;
copy the relevant ones next to the finding they support.
