# attacker-app — `probe`

The zero-permission test application. **This is how attacker model AM-03 is established.**

> `adb shell am start` runs as the **shell** UID, which holds far more privilege than any installed app.
> Discovery with adb is fine; **a finding proved only by adb has not established AM-03.** Re-prove every
> candidate from this app, and commit its manifest as evidence — the empty permission block is the argument.

## Build (no wrapper jar is committed)

```bash
cd attacker-app && ./build.sh            # uses ./gradlew if present, else a system gradle; tells you what is missing
./build.sh --install                     # also adb install -r
```

`app/build.gradle` sets `targetSdk 35`; raise or lower it to match what you are testing — component
export defaults and PendingIntent mutability are gated on it. Set the victim package in the manifest's
`<queries>` element (API 30+ package visibility) before building.

## Drive it headlessly (what a model does)

```bash
adb shell am start -n com.sanehunters.probe/.MainActivity \
  --es run baseline,enumerate,provider,read,redirect,deeplink \
  --es victim com.target.app \
  --es authority com.target.app.fileprovider \
  --es uri "content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/session.xml" \
  --es proxy com.target.app.ProxyActivity --es extra intent --es mode loot \
  --es deeplink "targetapp://open?url=https://example.test/" \
  --ez finish false
adb logcat -s PROBE:V          # one line per result:  PROBE|<step>|<key>=<value>
```

| Step | Domain | Prints |
|---|---|---|
| `baseline` | — | Beat 4 of the evidence standard: `checkUriPermission=-1 (DENIED)` and the failing direct read, *before* any test |
| `enumerate` | D03–D06 | the victim's exported components as an unprivileged UID sees them (package-visibility artefacts flagged) |
| `provider` | D07 | `query` / `call()` tested as separate questions, with raw results |
| `read` | D07 | the read under test, with byte count and head |
| `redirect` | D08 | a nested Intent through the victim's exported proxy; `mode=loot` targets our `LootActivity` so a forwarded URI grant is recorded (`PROBE|loot|…`), `mode=internal` targets a victim-internal component (reachability only) |
| `deeplink` | D09 | fires a `BROWSABLE` `VIEW` intent — exactly what a web page can do |

`HijackActivity` (D04) and `Sniffer` (D05) are compiled but disabled; enable their manifest blocks as needed.

## The log pane is the narration

Raw platform return values with their meaning in parentheses — `checkUriPermission=0 (0=GRANTED, -1=DENIED)`
— never a paraphrase. Everything it prints is a **candidate**; the finding is what the chain reaches (P7).
See [`docs/04-poc-and-evidence-standard.md`](../docs/04-poc-and-evidence-standard.md).

## Never

Point this at an app you are not authorised to test · exfiltrate a third party's data (plant canary values) ·
commit a built APK or a Gradle wrapper jar to this repository.
