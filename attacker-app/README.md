# attacker-app — `probe`

The zero-permission attacker application. **This is how AM-03 is established.**

> `adb shell am start` runs as the **shell** UID, which holds far more privilege than any real
> attacker. Discovery with adb is fine. **A finding proved only by adb has not established AM-03.**
> Re-prove every candidate from this app, and commit its manifest as evidence.

## The manifest is the argument

`app/src/main/AndroidManifest.xml` has an **empty** permission block, on purpose. Screenshot it for the
evidence tree — that emptiness is the single most rating-relevant fact in any finding proved here.

If a test genuinely needs a permission, you have dropped to **AM-04** and the finding must say so.

## Use

```bash
# 1. edit the CONFIGURE block at the top of MainActivity.java
#    VICTIM, FINDING, CLASS, PRECOND, PROXY, NONEXPORT, AUTHORITY, TRAVERSAL, DEEPLINK
# 2. also set <queries><package android:name="com.victim.app"/> in the manifest (API 30+)
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb logcat -s PROBE:V          # LootActivity reports here
```

`targetSdk` in `app/build.gradle` matters: raise or lower it to match what you are testing, because
component export defaults and PendingIntent mutability are gated on it.

## What each button proves

| Button | Domain | Proves |
|---|---|---|
| `0) BASELINE` | — | **Beat 4 of the PoC standard.** What the app *cannot* do, before any exploit, in the same take |
| `1) ENUMERATE` | D03–D06 | The victim's exported surface as an unprivileged UID actually sees it |
| `2) PROVIDER` | D07 | `query` / `call` / traversal tested as **three separate questions** |
| `3) EXPLOIT` | D07 | The read primitive, with byte count and content |
| `4) REDIRECTION` | D08 | Nested Intent through an exported proxy, with all four `FLAG_GRANT_*` set |
| `5) DEEP LINK` | D09 | Fires as a `BROWSABLE` `VIEW` intent — exactly what a web page can do |

`LootActivity` catches whatever the victim redirects, takes a persistable URI permission if the grant
allows, and dumps the bytes. That is the payload half of intent redirection: the confused deputy grants
*you* access to *its own* non-exported provider.

Commented-out in the manifest, enable as needed: `HijackActivity` for task hijacking (D04) and
`Sniffer` for implicit-intent interception (D05).

## The log pane is the narration

No voiceover, no captions. Print the **raw** platform return value with its meaning in parentheses —
`checkUriPermission -> 0 (0 = GRANTED, -1 = DENIED)` — never a paraphrase. Finish with one line naming
the impact. See [`docs/04-poc-and-evidence-standard.md`](../docs/04-poc-and-evidence-standard.md).

## Never

Point this at an app you are not authorised to test. Exfiltrate a third party's data — use planted
canary values. Commit a built APK to this repository.
