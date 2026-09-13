# MASTER CHECKLIST

> **Every test item, from every source, in one file. 1933 items across 26 domains.**

> **Read this file to know everything you must test.** Each item shows its severity ceiling, the VRT
> row it aims at, the attacker model and a one-line statement of the test. The exact command, the
> observable that proves it, the escalation and the mandatory *Ruled out when* mechanism live in the
> per-domain chapter linked from each section — open that when you actually run the domain.

> **The checklist is the floor, not the ceiling.** You must cover every in-scope item before
> calling an assessment complete. You are also expected to think past it — park anything novel as
> a hypothesis and chase it in P7. See [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md).

## Severity ceilings

| | Items |
|---|---|
| 🟥 **Critical** | 333 |
| 🟧 **High** | 436 |
| 🟨 **Medium** | 165 |
| 🟩 **Low** | 32 |
| ⬜ **Support** | 967 |
| | **1933 total** |

> A **Support** item cannot be reported alone — it produces a link in a chain. The entire mobile
> branch of the Bugcrowd VRT is P5; see [`docs/02`](docs/02-severity-and-reportability.md).

## Contents

| Domain | Phase | Items | Ceiling mix |
|---|---|---|---|
| [**D01** Recon & Attack-Surface Mapping](#d01-recon-attack-surface-mapping) | P3 | 80 | 🟥8 🟧22 🟨19 🟩3 ⬜28 |
| [**D02** APK/AAB Structure, Signing & Build Integrity](#d02-apk-aab-structure-signing-build-integrity) | P2 | 72 | 🟥6 🟧8 🟨1 🟩1 ⬜56 |
| [**D03** AndroidManifest & Permission Model](#d03-androidmanifest-permission-model) | P3 | 76 | ⬜76 |
| [**D04** Exported Activities, Task & UI-Redress Attacks](#d04-exported-activities-task-ui-redress-attacks) | P5 | 72 | 🟥4 🟧24 🟨23 🟩6 ⬜15 |
| [**D05** Broadcast Receivers & Implicit Intents](#d05-broadcast-receivers-implicit-intents) | P5 | 64 | 🟥7 🟧28 🟨8 🟩1 ⬜20 |
| [**D06** Services, AIDL & Bound IPC](#d06-services-aidl-bound-ipc) | P5 | 81 | 🟥22 🟧33 🟨10 ⬜16 |
| [**D07** ContentProviders & FileProvider](#d07-contentproviders-fileprovider) | P5 | 76 | 🟥23 🟧29 🟨1 🟩1 ⬜22 |
| [**D08** Intent Redirection, PendingIntent & URI Grants](#d08-intent-redirection-pendingintent-uri-grants) | P5 | 66 | 🟥18 🟧29 🟨7 ⬜12 |
| [**D09** Deep Links, App Links & Custom URI Schemes](#d09-deep-links-app-links-custom-uri-schemes) | P5 | 80 | 🟥22 🟧30 🟨9 🟩1 ⬜18 |
| [**D10** WebView & JavaScript Bridges](#d10-webview-javascript-bridges) | P5 | 72 | 🟥26 🟧35 🟨5 🟩1 ⬜5 |
| [**D11** Local Data Storage](#d11-local-data-storage) | P4 | 73 | 🟧1 🟨1 ⬜71 |
| [**D12** Cryptography & Key Management](#d12-cryptography-key-management) | P4 | 80 | 🟥18 🟧38 🟨13 🟩2 ⬜9 |
| [**D13** Authentication, Session, OTP & Biometrics](#d13-authentication-session-otp-biometrics) | P6 | 90 | 🟥19 🟧15 🟨1 ⬜55 |
| [**D14** Network Security, TLS & Certificate Pinning](#d14-network-security-tls-certificate-pinning) | P6 | 58 | 🟥14 🟧15 🟨13 🟩4 ⬜12 |
| [**D15** Backend API, IDOR/BOLA, Mass Assignment & Business Logic](#d15-backend-api-idor-bola-mass-assignment-business-logic) | P6 | 90 | 🟥27 🟧4 🟨1 ⬜58 |
| [**D16** Native Code, JNI & Memory Safety](#d16-native-code-jni-memory-safety) | P4 | 60 | 🟥15 🟧1 🟨3 🟩4 ⬜37 |
| [**D17** Dynamic Code Loading, Deserialization & Supply Chain](#d17-dynamic-code-loading-deserialization-supply-chain) | P4 | 80 | 🟥1 🟧7 🟨1 ⬜71 |
| [**D18** Cloud Backend & Third-Party SDK Configuration](#d18-cloud-backend-third-party-sdk-configuration) | P6 | 72 | 🟥31 🟧14 🟨4 🟩2 ⬜21 |
| [**D19** Cross-Platform Frameworks](#d19-cross-platform-frameworks) | P4 | 79 | 🟥31 🟧12 🟨6 🟩2 ⬜28 |
| [**D20** Privacy, PII, Logging & Data Leakage](#d20-privacy-pii-logging-data-leakage) | P4 | 70 | 🟧12 🟨10 🟩3 ⬜45 |
| [**D21** Anti-Tampering, RASP, Root/Emulator Detection & Resilience](#d21-anti-tampering-rasp-root-emulator-detection-resilience) | P4 | 57 | 🟥2 🟧11 🟨3 ⬜41 |
| [**D22** Platform & OS Version-Specific Behaviour](#d22-platform-os-version-specific-behaviour) | P4 | 82 | 🟥8 🟧37 🟨18 🟩1 ⬜18 |
| [**D23** Payments, Entitlements, Subscriptions & Fraud](#d23-payments-entitlements-subscriptions-fraud) | P6 | 66 | 🟥17 🟧20 ⬜29 |
| [**D25** Device, OEM, Firmware & Privileged Surfaces](#d25-device-oem-firmware-privileged-surfaces) | P5 | 79 | 🟥14 🟧11 🟨1 ⬜53 |
| [**D26** Runtime Instrumentation, Tooling & Harness](#d26-runtime-instrumentation-tooling-harness) | P1 | 79 | 🟨7 ⬜72 |
| [**D27** Reporting, Severity Rating & Evidence](#d27-reporting-severity-rating-evidence) | P9 | 79 | ⬜79 |

## How to use this file

1. Copy [`checklist.csv`](checklist.csv) into your engagement as `checklist-status.csv`.
   Every row starts `completed=false`.
2. Work the items in phase order. Flip each row to `true` with a `result` of `finding`,
   `ruled-out`, `blocked` or `n/a`. An `n/a` row **must** carry a reason in `notes`.
3. `Ruled out when` is on every item. It is the field that turns a skipped test into a defensible
   negative — it names the mechanism that closes the item, with `file:line`.
4. Check coverage at any time, and gate escalation on it:

```bash
python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ --gate p7
```


---

## D01 Recon & Attack-Surface Mapping

**Phase P3 · `M3` · 80 items** — 🟥 8 critical · 🟧 22 high · 🟨 19 medium · 🟩 3 low · ⬜ 28 support  

📄 Full detail, with every command and proof: [`checklist/D01-recon-and-surface-mapping.md`](checklist/D01-recon-and-surface-mapping.md)

> **Crux question.** **Am I analysing the bytes that are actually executing on a current device, in the runtime that actually holds the logic — and for every host, route and component I recovered from those bytes, can I name which attacker model reaches it and which version of the backend answers?**

It mostly does not pay directly. Read the Bugcrowd VRT honestly: there is no "good recon" node, and the entire mobile branch it would otherwise land in is P5. An exported-component inventory, a host list, a framework fingerprint, an obfuscation verdict — every one of those is evidence, not a finding, and a report whose headline is an inventory gets triaged as Informational. The corpus is unanimous on this: "report it only as the evidence table backing a concrete finding".


**⬜ Support ceiling**

- [ ] **`D01-001`** Pull every split the device actually installed, not just base.apk  
   <sub>`n/a — coverage control; a missed split silently caps the whole engagement` · n/a (tester method) · Confirm you have `base.apk` **and** every `split_config.*` / `split_feature_*`. Native libraries live in the A…</sub>
- [ ] **`D01-002`** Rebuild one analysable artefact from the split set, an AAB or an XAPK  
   <sub>`n/a — coverage control` · n/a (tester method) · Produce one merged artefact so that cross-split references resolve, then verify the merge did not drop compone…</sub>
- [ ] **`D01-003`** Record artefact provenance: acquisition path, per-split SHA-256, signer digest  
   <sub>`n/a — evidence integrity control` · n/a (tester method) · A client-supplied APK, a Play-downloaded APK and an APKMirror copy of "the same version" can differ in signer,…</sub>

**🟩 Low ceiling**

- [ ] **`D01-004`** Establish which APK signature schemes verify and pin the signer SHA-256  
   <sub>`n/a standalone; escalates into `broken_access_control.privilege_escalation` (v` · AM-08 / AM-11 (an attacker who can · The signing certificate binds the app's UID, its `signature`-protected permissions, its `sharedUserId` group a…</sub>

**🟧 High ceiling**

- [ ] **`D01-005`** Play App Signing: the artefact you were handed is signed with a different key than users run  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-02 remote one click (victim tap · With Play App Signing the developer signs the bundle with the **upload key** and Google re-signs the delivered…</sub>

**⬜ Support ceiling**

- [ ] **`D01-006`** Establish minSdkVersion and targetSdkVersion from two authoritative sources  
   <sub>`n/a — but it sets the "Applies to" line of every other finding in the engageme` · n/a (tester method) · apktool frequently **drops `<uses-sdk>`** from the regenerated manifest, so reading the rebuilt manifest gives…</sub>

**🟩 Low ceiling**

- [ ] **`D01-007`** Enumerate SDK Extension versions before declaring a modern API unreachable  
   <sub>`n/a standalone; the reachable legacy branch it exposes is rated in its own dom` · AM-03 zero-permission local app (r · Modular APIs (Photo Picker, `ad_services`) ship via Google Play system updates and exist on *older* OS version…</sub>

**⬜ Support ceiling**

- [ ] **`D01-008`** Prove version currency against the programme's staleness clause  
   <sub>`n/a — but staleness is a blanket disqualifier that voids an otherwise valid P1` · n/a (tester method) · Every major programme requires reproduction on current software. A perfect exploit against last quarter's buil…</sub>
- [ ] **`D01-009`** Freeze the artefact and detect mid-window build drift  
   <sub>`n/a — dispute-prevention control` · n/a (tester method) · Clients ship during your window. Without a freeze, half a report can describe code that no longer exists — the…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-010`** Mine the published version history for secrets the vendor believes are retired  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 remote no interaction · Secrets removed in the current build are frequently still **live server-side**. The old APK is the only place …</sub>

**🟨 Medium ceiling**

- [ ] **`D01-011`** Version-diff two consecutive releases and test the delta first  
   <sub>`n/a standalone; inherits the class the diff reveals` · n/a (tester method); the resulting · A silent fix tells you exactly which sink the developer distrusts. Then grep for the same sink elsewhere, wher…</sub>

**🟧 High ceiling**

- [ ] **`D01-012`** Version rollback: does the backend still serve a superseded, legitimately signed client  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-02 remote one click (user sidel · An attacker who can uninstall-then-install can plant an older, **legitimately signed** build whose bug the ven…</sub>
- [ ] **`D01-013`** Diff the on-device install against the store artefact for post-install code  
   <sub>`n/a standalone; escalates to `server_side_injection.remote_code_execution_rce`` · AM-06 network attacker no trusted  · Some apps unpack or download components after first launch. The on-device state can contain code the store art…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-014`** Enumerate the whole developer-account app catalogue from the store listing  
   <sub>`n/a for the enumeration; severity comes from what the extra APK leaks` · AM-01 remote no interaction · The target ships more than the one app you were handed. A multi-brand parent org typically has 5–10 packages u…</sub>
- [ ] **`D01-015`** Brand-permutation package guessing for unlisted dealer, partner and internal builds  
   <sub>`n/a for the discovery; rated on what the unlisted build exposes` · AM-01 remote no interaction · Dealer, partner and employee companion apps are often unlisted on the developer page but still resolvable by p…</sub>

**⬜ Support ceiling**

- [ ] **`D01-016`** Ownership triage gate: prove the app is the target's before you touch it  
   <sub>`n/a — scope-safety control` · n/a (tester method) · ASM tooling keyword-matches the brand word. For any dictionary-word brand, most "owned" mobile apps belong to …</sub>

**🟨 Medium ceiling**

- [ ] **`D01-017`** Pivot to the iOS twin through the App Store lookup API  
   <sub>`n/a for the discovery; rated on the backend delta it reveals` · AM-01 remote no interaction · The same conglomerate reuses `com.<corp>.<sub-brand>` naming across both platforms, and the iOS twin often shi…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-018`** Code-search dorking anchored on the exact applicationId  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 remote no interaction · Mobile teams leak `google-services.json`, keystore passwords, CI secrets and staging credentials far more ofte…</sub>

**⬜ Support ceiling**

- [ ] **`D01-019`** Read the programme rules that set the payout ceiling and the admissible attacker model  
   <sub>`n/a — routing and scoping control` · n/a (tester method) · Two rules decide whether a week converts. (a) **Tier and publisher**: for a Google-published app the package n…</sub>
- [ ] **`D01-020`** Bind a commercial engagement with a scoping sheet and an RoE that authorises mobile-test acts  
   <sub>`n/a — legal and planning control` · n/a (tester method) · Get written answers to a fixed question set and turn them into the test plan. Without §5.2 of an RoE, installi…</sub>

**🟧 High ceiling**

- [ ] **`D01-021`** Day-0 intake: prior reports, regression checks and the feature-flag list  
   <sub>`rated on what the regressed or flag-gated capability exposes; a staff-only cap` · AM-05 another user of the same app · Ninety minutes with the people who built the app surfaces what no week of static analysis finds: internal debu…</sub>

**⬜ Support ceiling**

- [ ] **`D01-022`** Fingerprint the framework from the archive listing before writing a single test case  
   <sub>`n/a — but misclassification silently zeroes D10, D11, D12, D15 and D19` · n/a (tester method) · Determine which runtime actually holds the business logic. A clean jadx grep on a Flutter or Hermes app is a *…</sub>
- [ ] **`D01-023`** Run APKiD for compiler, obfuscator, packer and anti-analysis signatures  
   <sub>``lack_of_binary_hardening.lack_of_obfuscation` (P5) if you were tempted to rep` · n/a (tester method) · Identify whether the DEX is R8/D8/dexlib, whether native libs are OLLVM-protected, and whether anti-VM / anti-…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-024`** A decompiler that "sees nothing" is anti-analysis, not a clean app  
   <sub>`n/a standalone; escalate on whatever the recovered payload does` · AM-08 malicious third-party SDK /  · When jadx or apktool abort on `AndroidManifest.xml`, or when different ZIP parsers disagree about the entry li…</sub>

**⬜ Support ceiling**

- [ ] **`D01-025`** Determine whether the RN bundle is Hermes bytecode or plain JS, and read the HBC version  
   <sub>`n/a — prerequisite for every RN static finding` · n/a (tester method) · React Native ships either a plain-JS Metro bundle or Hermes bytecode. The two need completely different toolch…</sub>

**🟧 High ceiling**

- [ ] **`D01-026`** Select a Hermes tool by bytecode version; mine the string table when none supports it  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote no interaction (for a · Verify your decompiler actually supports the app's HBC version instead of silently producing garbage. This is …</sub>

**🟨 Medium ceiling**

- [ ] **`D01-027`** Recover the Metro module map as a JS-side SBOM  
   <sub>`n/a standalone; the reachable vulnerable dependency is rated in D17` · AM-02 remote one click (input reac · A Metro bundle is a map of numbered modules (`__d(factory, moduleId, deps)`). Recovering it gives a de-facto S…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-028`** Harvest the Dart object pool from a Flutter AOT snapshot  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote no interaction · In Flutter release builds every string constant, class name and crypto parameter used by the app is reachable …</sub>

**🟧 High ceiling**

- [ ] **`D01-029`** Treat the Cordova/Capacitor web root as a source drop and hunt shipped sourcemaps  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote no interaction · For Cordova/Ionic/Capacitor, all application logic ships as readable (sometimes minified) web assets. Treat `a…</sub>

**⬜ Support ceiling**

- [ ] **`D01-030`** Extract the managed type graph from a Unity IL2CPP or Xamarin/MAUI build  
   <sub>`n/a — enabler; the findings it unlocks (client-side entitlement, hardcoded key` · n/a (tester method) · Both stacks compile the real logic away from the DEX. Unity IL2CPP ships `global-metadata.dat` next to `libil2…</sub>

**🟧 High ceiling**

- [ ] **`D01-031`** Locate the Kotlin Multiplatform shared module and its generated constants  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 for the key; AM-06 network a · KMP compiles shared Kotlin to normal JVM bytecode on Android, so the shared module *is* in the DEX — but secre…</sub>

**⬜ Support ceiling**

- [ ] **`D01-032`** Determine which binary is ACTUALLY executing (expo-updates, CodePush, DexClassLoader)  
   <sub>`n/a — but it prevents a whole class of *wrong findings with perfectly accurate` · n/a (tester method) · For any app with over-the-air code delivery, the running JS or DEX is not the one in the APK. Analysing the AP…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-033`** Check whether the OTA code channel is signed and the signature enforced  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when an unsigned or une` · AM-06 network attacker no trusted  · An OTA channel delivers executable code. If the payload is not code-signed, or the signature is configured but…</sub>

**⬜ Support ceiling**

- [ ] **`D01-034`** Never conclude "obfuscated, therefore unanalysable" — grep the anchors R8 cannot rename  
   <sub>`n/a — method` · n/a (tester method) · R8 renames identifiers; it does **not** remove data flows, and it does not rewrite string values inside runtim…</sub>
- [ ] **`D01-035`** Build the component inventory from the MERGED manifest and compute implicit export per targetSdk  
   <sub>`n/a — this is the map. Each `perm=NONE` row is a candidate for `broken_access_` · AM-03 zero-permission local app (t · The manifest inside the APK is the *merged* manifest — library and SDK manifests are merged at build time and …</sub>

**🟨 Medium ceiling**

- [ ] **`D01-036`** Isolate the SDK-injected components by class-prefix delta  
   <sub>`n/a standalone; `broken_access_control.exposed_sensitive_android_intent` (null` · AM-08 malicious third-party SDK /  · Most exported-component findings in real engagements live in code the client did not write. Developers never s…</sub>
- [ ] **`D01-037`** Reconcile the static manifest against the runtime resolver tables  
   <sub>`n/a standalone; the delta is where the paying bugs live (Mobile VRP explicitly` · AM-03 zero-permission local app · The manifest is the declared surface; the package manager is the effective one. Context-registered receivers, …</sub>

**⬜ Support ceiling**

- [ ] **`D01-038`** Close the component-coverage register: zero TODO rows at delivery  
   <sub>`n/a — coverage-proof artefact` · n/a (tester method) · A ruled-out register records disproven *hypotheses*. A coverage register enumerates every component the app de…</sub>

**🟧 High ceiling**

- [ ] **`D01-039`** Enumerate every custom permission the app defines and its resolved protectionLevel  
   <sub>`n/a standalone; the guarded component's finding inherits it — commonly `broken` · AM-03 zero-permission local app (a · Build the complete list of `<permission>` elements the target defines and the resolved level of each. Anything…</sub>
- [ ] **`D01-040`** sharedUserId redefines the target boundary — triage the weakest sibling  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-08 malicious third-party SDK in · If the manifest declares `android:sharedUserId`, the target's attack surface is the **union of every package i…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-041`** Map the process topology before believing a "sandboxed process" claim  
   <sub>`n/a standalone; the false isolation claim is what you report, rated on what th` · AM-09 malicious backend or CDN (re · A single APK can span several Linux processes, but each `android:process` value is a separate address space sh…</sub>
- [ ] **`D01-042`** Read `<queries>` as the declared trust graph, then check how each peer is verified  
   <sub>`n/a standalone; `broken_access_control.privilege_escalation` (null) once a squ` · AM-03 zero-permission local app re · Since `targetSdk 30` an app must declare which packages it can see, so `<queries>` is a free, machine-readable…</sub>
- [ ] **`D01-043`** QUERY_ALL_PACKAGES plus egress is a privacy exfiltration, not a lint warning  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — r` · AM-08 malicious third-party SDK (t · Does the app hold `QUERY_ALL_PACKAGES` or enumerate `PackageManager` broadly, **and does that inventory leave …</sub>
- [ ] **`D01-044`** Enumerate the auto-generated providers and read the FileProvider roots  
   <sub>`n/a standalone; High once paired with a grant primitive — rate through `broken` · AM-03 zero-permission local app · Modern apps ship several providers nobody on the team authored — `androidx.startup.InitializationProvider`, Fi…</sub>

**🟧 High ceiling**

- [ ] **`D01-045`** Find privileged listener services declared without their BIND_* permission  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 zero-permission local app · Apps shipping an AccessibilityService, NotificationListenerService, AutofillService, TileService, CarAppServic…</sub>

**🟩 Low ceiling**

- [ ] **`D01-046`** Inventory foreground-service types as a background-capability map  
   <sub>`n/a standalone; High once chained to an exported or implicit start — rate via ` · AM-03 zero-permission local app (s · From `targetSdk 34` every FGS must declare `android:foregroundServiceType`, and each type requires a specific …</sub>

**🟨 Medium ceiling**

- [ ] **`D01-047`** Harvest shortcuts.xml, share-targets and widget metadata as an undeclared entry-point list  
   <sub>`n/a standalone; `broken_access_control.exposed_sensitive_android_intent` (null` · AM-03 zero-permission local app (v · `res/xml/shortcuts.xml` and `<share-target>` entries carry `<intent>` elements with fully specified actions, `…</sub>

**🟧 High ceiling**

- [ ] **`D01-048`** Inventory the deep-link surface including the `<data>` cross-product and the App Links verdict  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-02 remote one click · Three things testers routinely miss. (a) `<data>` elements inside one `<intent-filter>` are merged **combinato…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-049`** Enumerate `android_secret_code` dialer receivers  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-11 physical unlocked (dialer) / · `<data android:scheme="android_secret_code" android:host="NNNN"/>` declares a receiver that fires when the cod…</sub>
- [ ] **`D01-050`** Find binary-SMS receivers bound to a port  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); escalates thr` · AM-01 remote no interaction (any s · `<data android:port="NNNN"/>` on a receiver's intent-filter declares a data-SMS listener. The payload is parse…</sub>

**⬜ Support ceiling**

- [ ] **`D01-051`** Enumerate the physical-accessory entry points: USB, NFC, BLE and CompanionDeviceManager  
   <sub>`n/a — recon; the D25 items it feeds run High` · AM-10 physical locked / AM-11 phys · These are components the attacker triggers by *touching the phone with hardware*, and they are frequently un-p…</sub>
- [ ] **`D01-052`** Enumerate every instance of the app on the device: users, work profile, Private Space, OEM clones  
   <sub>`n/a — recon; converts D13 device-binding and D23 entitlement items from "unver` · AM-05 another user of the same app · Most checklists assume one install per device. In reality the app may exist as user 0, a work profile (user 10…</sub>

**🟧 High ceiling**

- [ ] **`D01-053`** Enumerate the device's inbound network surface created by the app  
   <sub>``server_security_misconfiguration.exposed_portal.admin_portal` (P1) when the l` · AM-06 network attacker no trusted  · Apps ship local HTTP servers — Wi-Fi transfer, casting/DLNA, WebRTC pairing, leftover RN dev servers. A `0.0.0…</sub>
- [ ] **`D01-054`** Enumerate the binder services the app's own UID can reach  
   <sub>``broken_access_control.privilege_escalation` (null) when an app-reachable vend` · AM-03 zero-permission local app · `/dev/binder` is the universal trust boundary between an app and everything privileged, and AIDL performs no a…</sub>
- [ ] **`D01-055`** Device-wide sweep for debuggable packages  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) at min` · AM-03 zero-permission local app (J · Debuggable *release* builds still ship — staging/QA APKs published to the store by mistake, OEM preinstalls, S…</sub>

**⬜ Support ceiling**

- [ ] **`D01-056`** Build the per-attacker-model reachability matrix by attempting reach, not by reading the manifest  
   <sub>`n/a — this artefact sets the severity of everything else, and its absence is w` · all of AM-01…AM-12 (that is the po · A component × exported × permission table does not say **who** can reach each row. Fill the attacker column by…</sub>
- [ ] **`D01-057`** Bind every user-visible feature to its components, endpoints and on-disk artefacts  
   <sub>`n/a — coverage control; it is how whole features avoid being tested at all` · n/a (tester method) · A "complete" component sweep and a "complete" endpoint list can both be finished without ever having exercised…</sub>
- [ ] **`D01-058`** Harvest the complete Retrofit route map from an R8-minified DEX and shortlist by ID shape  
   <sub>`n/a — recon. The routes it produces become `broken_access_control.idor.modify_` · n/a (tester method); the resulting · R8 renames classes and methods but **does not rewrite the string values inside runtime-visible annotations** —…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-059`** Recover hidden request parameters from Retrofit parameter annotations  
   <sub>`n/a standalone; `broken_access_control.privilege_escalation` (null) when the r` · AM-05 another user of the same app · Enumerate every field name the client is *capable* of sending. `@Query`, `@QueryMap`, `@Field`, `@FieldMap`, `…</sub>

**🟧 High ceiling**

- [ ] **`D01-060`** Flag `@Url` and runtime base URLs as host-substitution surface  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-09 malicious backend or CDN (th · Retrofit's `@Url` lets the *caller* supply the whole URL, and `Retrofit.Builder().baseUrl(...)` can take a run…</sub>

**⬜ Support ceiling**

- [ ] **`D01-061`** Read the OkHttp interceptor chain to reconstruct the auth envelope byte-for-byte  
   <sub>`n/a — enabler. Without it, "the token doesn't work from curl" is an unproven c` · n/a (tester method) · Determine exactly how the app authenticates every request, because you must reproduce it byte-for-byte when yo…</sub>

**🟧 High ceiling**

- [ ] **`D01-062`** Tap OkHttp in-process and diff against the proxy log  
   <sub>`n/a for the tap; the **delta** is what gets rated, and an endpoint visible onl` · n/a (tester method) · Capture full request/response pairs from inside the process. This is immune to pinning, to proxy-unaware clien…</sub>

**⬜ Support ceiling**

- [ ] **`D01-063`** Build the host inventory from DEX, resources, assets, native libs and remote WebView bundles  
   <sub>`n/a — recon. It is the evidence base that converts "no pinning" from Informati` · n/a (tester method) · Extract every URL and host embedded in DEX, native libs, resources and assets, then classify first-party (deve…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-064`** Run apkleaks across every split and prove every hit with a live request  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote no interaction · Run the regex corpus across `classes*.dex` strings, `res/`, `assets/`, `lib/*/*.so` and **every split** — spli…</sub>

**⬜ Support ceiling**

- [ ] **`D01-065`** Recover GraphQL operations and persisted-query hashes from the client  
   <sub>`n/a — recon; enables the GraphQL authz tests in D15. GraphQL introspection alo` · n/a (tester method) · If the backend is GraphQL, the client ships either the operation documents (Apollo codegen) or only their SHA-…</sub>

**🟧 High ceiling**

- [ ] **`D01-066`** Recover gRPC service and method names, drive them with grpcurl, and edit protobuf blind  
   <sub>``broken_access_control.privilege_escalation` (null) for an unauthenticated or ` · AM-01 remote no interaction · gRPC traffic is invisible to a naive HTTP proxy and is often the *entire* API for newer apps. Recover the full…</sub>

**🟥 Critical ceiling**

- [ ] **`D01-067`** Build the API-version inventory and walk superseded versions with the same token  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 remote no interaction · Mobile backends accumulate versions because old installs must keep working, and the old version is the one wit…</sub>
- [ ] **`D01-068`** SHADOW API — diff the mobile-sourced version against the current one BEHAVIOURALLY  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 remote no interaction · A mobile app's hardcoded backend calls are frequently an **older** API version than the current web app uses —…</sub>

**🟧 High ceiling**

- [ ] **`D01-069`** Diff the mobile route set against the web route set  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 another user of the same app · Mobile clients frequently get endpoints the web app does not expose — bulk sync, device registration, offline …</sub>

**🟥 Critical ceiling**

- [ ] **`D01-070`** Diff the same privileged operation across every channel host  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `br` · AM-05 another user of the same app · The same business object is usually exposed by three or more front doors — `www.` with a web session cookie, `…</sub>

**🟧 High ceiling**

- [ ] **`D01-071`** Find the staging and QA hosts shipped in the release build, then test them with a production token  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) f` · AM-01 remote no interaction · Release builds routinely carry the full host inventory including staging, UAT and regional shards. Staging bac…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-072`** Recover the debug parameters and debug flags the client ships  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for an` · AM-05 another user of the same app · Mobile backends carry `?debug=1`, `?test=true`, `X-Debug: 1` switches that dump stack traces, SQL or internal …</sub>

**🟧 High ceiling**

- [ ] **`D01-073`** Sweep archived specs and the Wayback index for routes the client no longer calls  
   <sub>`follows the regression found, up to `broken_authentication_and_session_managem` · AM-01 remote no interaction · A deprecated version's OpenAPI spec often stays indexed after the live link is removed, and old app builds pin…</sub>
- [ ] **`D01-074`** Enumerate the non-HTTP channels the proxy will never show you  
   <sub>`the delta is a testability observation (Low); a WebSocket that accepts command` · AM-05 another user of the same app · WebSockets, MQTT, XMPP and raw TLS sockets carry authenticated commands in many apps — chat, ride-hailing disp…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-075`** Treat every third-party SDK endpoint as a separate target  
   <sub>`rating follows the data class exposed — `sensitive_data_exposure.disclosure_of` · AM-08 malicious third-party SDK /  · Analytics, crash, CDN, attribution and feature-flag endpoints are often in scope by virtue of holding the clie…</sub>

**🟧 High ceiling**

- [ ] **`D01-076`** Inventory bundled native libraries and the resolved dependency graph, then prove reachability  
   <sub>`n/a standalone; the memory-corruption finding is rated in D16. Presence alone ` · AM-02 remote one click (attacker-s · A bundled vulnerable parser is only a finding if app-supplied data reaches it. Bundled libraries are patched o…</sub>

**🟨 Medium ceiling**

- [ ] **`D01-077`** Region- and locale-gated features hidden from your test device  
   <sub>``broken_access_control.privilege_escalation` (null) when the gate is regulator` · AM-05 another user of the same app · Commercial apps ship features to some markets only — UPI/PIX/wallet top-up, regional KYC tiers, age gates, pri…</sub>

**⬜ Support ceiling**

- [ ] **`D01-078`** The layer-ordering trap: a 400 from an APK-derived endpoint is not an auth bypass  
   <sub>`n/a — kill gate. It prevents a false `broken_authentication_and_session_manage` · n/a (tester method) · The highest-confidence false positive in the entire auth-bypass class. Many stacks put a global input sanitise…</sub>
- [ ] **`D01-079`** The soft-404 and body-diff controls before you call an APK-derived endpoint "live"  
   <sub>`n/a — false-positive gate. Status-code-only claims are the most common rejecte` · n/a (tester method) · Two controls, both mandatory before an APK-derived host or route enters a finding. **Soft-404:** SPA catch-all…</sub>
- [ ] **`D01-080`** The shell-loop ban: count your results or the sweep silently lied  
   <sub>`n/a — method-integrity gate` · n/a (tester method) · Shell array expansion fails **silently**. A loop like `for x in "${arr[@]}"` can produce zero iterations with …</sub>

<details><summary>⚰️ D01 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app is not obfuscated / R8 is not enabled" | `lack_of_binary_hardening.lack_of_obfuscation` is **P5**. Obfuscation is not a security control and its absence harms nobody | Nothing on its own. Report the secret, route or logic you recovered — the readability is context in that finding, never the finding |
| "The app exports N components" (a count, with no reachability verdict) | An inventory is the map, not the territory. Triage reads a bare count as Informational | One named component, reached from a zero-permission PoC app, performing a privileged action — then it is `broken_access_control.exposed_sensitive_android_intent` (null), rated on what it exposes |
| "The APK contains hardcoded URLs including staging hosts" | A string is not a host. MASTG-TEST-0233 is explicit that HTTP URLs in a binary do not mean they are used | The host resolving, answering with the app's API, and accepting a production token or serving production data (D01-071) |
| "The APK contains an API key" | Most client-side keys are public by design and package-plus-signature restricted. `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` is **P5** | A live authenticated response from the provider using that key, from a clean host (D01-064). An OAuth `client_secret` in a mobile app specifically is on the never-submit list |
| "An expired JWT is hardcoded in the binary" | An expired token authenticates nothing | The claim names, the `alg`, and the `/v1/*` paths around it are reconnaissance-grade — file it as the internal-API-surface map at Medium, or fold it into the endpoint inventory. If the HS256 secret is also recoverable, that is a different, Critical finding |
| "The app allows backup / `android:allowBackup="true"`" | `mobile_security_misconfiguration.auto_backup_allowed_by_default` is **P5** | Only as a chain: backup extraction yielding a session token that authenticates → D11 then `broken_authentication_and_session_management.authentication_bypass` (P1) |
| "No certificate pinning" discovered during host inventory | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` is **P5**, and AM-07 (network attacker with a trusted CA) is a tester convenience, not an attacker | Only where the programme prices MitM (D01-019) and only against a **first-party** host that demonstrably carries session tokens (D01-063). Otherwise it is harness setup, not a finding |
| "drozer reports 0 exported components" | drozer is `[DEGRADED]` on API 29+ and its own agent needs `<queries>` on `targetSdk >= 30`; a zero is frequently a package-visibility artefact | Reconcile with the merged manifest and `dumpsys` resolver tables (D01-035, D01-037). Agreement between three sources is the negative; a lone drozer zero is not |
| "The app runs on an emulator / root detection is absent" | `lack_of_binary_hardening.lack_of_jailbreak_detection` is **P5** and AM-12 (your own rooted device) is not an attack | Nothing. Use the rooted device for discovery, then re-prove every finding on a stock device with a zero-permission APK, `adb shell am`/`content`, or a `network_security_config` that already trusts user CAs |
| "Version N of the API exists alongside version N+1" | A version difference alone is **Informational** — that is the explicit rule | A behavioural regression on the old path: weaker auth, absent throttling, accepted payloads, or extra fields (D01-068) |
| "GraphQL introspection is enabled" / "gRPC server reflection is enabled" | Introspection alone is on the never-submit list; reflection alone is Low | An operation or RPC discovered through it that is unauthenticated or over-privileged for your identity (D15) |
| "The app requests `QUERY_ALL_PACKAGES`" | A manifest declaration is a policy question, not an exploit | The enumerated list captured leaving the device in a request body, correlated with an account identifier and a named recipient (D01-043) |
| "The app opens a loopback socket" | Binding is not a vulnerability | An unauthenticated request from a second process or host returning app-private bytes or accepting a file write (D01-053) |
| "The signing certificate is self-signed / valid for 30 years" | Every Android release certificate is self-signed; long validity is required by Play | A mismatch between the artefact you tested and the store artefact, or a `knownSigner` allow-list containing a key the target no longer controls (D01-004, D01-005) |

</details>


<details><summary>🔗 D01 cross-surface joins — park these, chase them in P7</summary>

These are pairs of surfaces that separate people review separately, whose JOIN is the bug.

- **Config splits × the secret sweep (D01-001 × D01-064 → D18).** Almost every secret sweep in the wild runs against `base.apk`. Native libraries and whole feature modules live in `split_config.*` and `split_feature_*`, and `apkleaks` on base alone never sees them. The join is: a signing key or cloud credential that exists **only** in the arm64 split, in an app whose vendor SAST scans the bundle's base module. Also check both ABIs — a vulnerable `.so` may ship only to `armeabi-v7a`, i.e. to the oldest and most-at-risk device population.
- **Superseded builds × the live backend (D01-010 × D01-067 → D15).** Nobody joins "APKMirror has builds N-1 through N-12" with "the backend still routes `/v1/`". The vendor's mental model is that removing a key from the client retired it, and that deprecating an API version removed it. Each half is separately boring; the join is a credential from build N-3 authenticating against a version the current client never calls, which is P1 twice over.
- **`<queries>` × the caller-verification code path (D01-042 × D03/D06).** Manifest reviewers read `<queries>` as a compatibility declaration. Code reviewers read `checkSignatures` call sites without knowing which peers matter. The join — a `<queries><package>` entry whose peer is resolved by **name only**, with no `GET_SIGNING_CERTIFICATES` comparison anywhere on the call path — is a squattable trust anchor, and it is only visible if the same person holds both halves.
- **Merged-manifest SDK delta × the URI-grant primitive (D01-036 × D08/D07).** The app vendor does not know the component exists; the SDK vendor does not know it is exported in this host app. An exported SDK proxy activity plus `FLAG_GRANT_READ_URI_PERMISSION` handling is the EngageLab shape — persistent read/write grants over the host app's private storage, at 50M+ installs. Neither party reviews the join.
- **Process topology × the WebView renderer (D01-041 × D10/D11).** A "`:webview` process" is presented internally as isolation. It shares the UID and the data directory unless `isolatedProcess` was also set. The join makes any renderer compromise reach the token store — and it is the specific claim ("our payment WebView runs isolated") that makes it reportable.
- **Foreground-service types × an exported starter (D01-046 × D06).** The FGS type table is read as a compliance chore; the exported-service list is read as an IPC chore. `android:foregroundServiceType="microphone"` on a service an unprivileged app can `startForegroundService()` is remote-triggered background mic capture, and neither list alone says that.
- **Package enumeration × the RASP blocklist (D01-043 × D21).** The installed-app enumeration is written up as a privacy issue; the root/Frida detection is written up as a hardening note. They are usually the **same code**: the enumeration exists to feed a competitor/security-app blocklist, and reading that blocklist tells you exactly which branch to flip to disable the RASP.
- **Deep-link `<data>` cross-product × the App Links verdict (D01-048 × D09/D13).** Testers enumerate schemes; separately, someone checks `assetlinks.json`. The join — a synthetic `scheme × host` combination that reaches a handler which skips the validation applied to the canonical `https` form, on a host whose App Links verification failed — is how a password-reset token reaches an arbitrary installed app.
- **Dialer secret codes × the environment switch (D01-049 × D22/D14).** Secret codes are treated as an OEM curiosity. Environment switchers are treated as a debug-build artefact. A `*#*#code#*#*` receiver in a production build that flips the backend to staging or disables pinning joins them into a physical-access MitM primitive with no permission and no UI trail.
- **OTA channel × the network position (D01-032/-033 × D14/D17).** The OTA channel is a release-engineering concern; pinning is a network concern. The join is that an unsigned or unenforced update payload fetched over an unpinned channel is `server_side_injection.remote_code_execution_rce` (P1) — and it is invisible to anyone who only analysed the APK, because the APK is not what runs.
- **App instances × entitlement counting (D01-052 × D23/D13).** Nobody tests the work profile, the Private Space copy and the OEM clone as *separate installs of the same account*. A trial or device-binding scheme that counts installs is defeated by a feature the platform ships, and the vendor's own compat documentation warns that work-profile logic breaks on Private Space.
- **In-process OkHttp tap × the packet capture (D01-062 × D01-074 × D15).** Proxy-only testers miss non-proxied HTTP; packet-capture-only testers see destinations but not bodies. Running both and taking the three-way set difference — proxy log, Frida tap, pcap destinations — names exactly which stack is unproxied and which endpoints nobody has ever tested.
- **Feature matrix × the coverage register (D01-057 × D01-038).** Component coverage and feature coverage are different axes, and an engagement can be complete on one and empty on the other. A component with a TESTED-CLEAN status that appears in no feature row was tested in isolation and never driven with real state; a feature with no component row was never bound to code at all.

</details>


---

## D02 APK/AAB Structure, Signing & Build Integrity

**Phase P2 · `M2` · 72 items** — 🟥 6 critical · 🟧 8 high · 🟨 1 medium · 🟩 1 low · ⬜ 56 support  

📄 Full detail, with every command and proof: [`checklist/D02-apk-structure-signing.md`](checklist/D02-apk-structure-signing.md)

> **Crux question.** Does any security decision anywhere — this app's own self-check, a sibling app's signature-level permission, an in-app updater's verifier, or the backend — actually depend on this APK's signing identity or its unmodified bytes, because if nothing does, the only payable thing left in the package is a live secret.

Mostly it does not — and you should know that before you spend a day here. The entire classical content of this domain (v1-only signing, 1024-bit keys, "the app can be repackaged", "the app is not obfuscated", "no binary hardening") is pinned at P5 by the Bugcrowd VRT, and `lack_of_binary_hardening` carries the impact vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` — the taxonomy itself scores it at literally zero impact. Google's own Invalid Reports page says outright that being able to determine how an app works internally "is not a vulnerability". Grab, Spotify, Starbucks and Xiaomi all carry "lack of obfuscation / repackaging protection is out of scope" verbatim. Janus (CVE-2017-13156) is LEGACY. Master Key (CVE-2013-4787) is LEGACY. A v1-only APK is a hygiene note unless you can state a `minSdkVersion` that reaches a platform that still verifies v1 only.


**⬜ Support ceiling**

- [ ] **`D02-001`** Artefact provenance record: hashes, acquisition path, signer and scheme set  
   <sub>`— (methodology gate; every finding in this chapter inherits its artefact ident` · n/a (engagement control) · Record, for every input byte, where it came from and what it hashes to. A client-supplied APK, a Play-download…</sub>
- [ ] **`D02-002`** The binary on the device is not the binary you were handed  
   <sub>`— (methodology gate)` · Hash the APK actually installed on the device and compare with the artefact you were given. Divergence invalid…</sub>
- [ ] **`D02-003`** Truncated APK/XAPK acquisition — recover before concluding "no secrets"  
   <sub>`— (methodology gate)` · CDN rate-limiting returns a truncated XAPK with a missing end-of-central-directory signature. `unzip` fails, a…</sub>
- [ ] **`D02-004`** Pull the complete split set — and count what you pulled  
   <sub>`— (methodology gate; suppresses false negatives across D03–D19)` · Native libraries, some resources and config-specific manifest fragments live only in splits. Pulling only `bas…</sub>
- [ ] **`D02-005`** AAB handover: rebuild the device-exact split set with bundletool  
   <sub>`— (methodology gate)` · The universal APK is not what users run. `--mode=universal` merges code that is never co-resident on a real de…</sub>
- [ ] **`D02-006`** Play App Signing: the key you were handed is not the key users get  
   <sub>`— (methodology gate; the consequence is rated in D09)` · n/a for the check; AM-03 for the r · With Play App Signing the developer signs with the **upload key** and Google re-signs the delivered APKs with …</sub>
- [ ] **`D02-007`** Obtain and load the R8 `mapping.txt` for the exact versionCode  
   <sub>`— (methodology gate with a direct coverage consequence)` · "Full APK review" engagements routinely run against obfuscated DEX because nobody asked for the mapping file. …</sub>
- [ ] **`D02-008`** Source-to-artefact correspondence: does the repo you reviewed build the APK you tested  
   <sub>`— (methodology gate)` · If the repo checkout and the APK diverge — a different branch, a patched dependency, a post-build script, a re…</sub>

**🟧 High ceiling**

- [ ] **`D02-009`** Version-history mining: retired secrets that are still live, and the older hardcoded API surface  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote, no interaction (the  · Two distinct payloads live in old builds. (a) A credential removed from the current build is frequently still …</sub>

**⬜ Support ceiling**

- [ ] **`D02-010`** Record `minSdkVersion` and `targetSdkVersion` before running anything else  
   <sub>`— (the qualifier attached to every other finding's "Applies to")` · A large fraction of Android "the platform fixed that" claims are gated on the app's declared SDK levels. These…</sub>
- [ ] **`D02-011`** Signature-scheme inventory: which of v1/v2/v3/v3.1/v4 actually verify  
   <sub>`— (baseline; the findings are D02-012 through D02-018)` · The signing certificate is what binds the app's UID, its signature-level permissions, its `sharedUserId` group…</sub>
- [ ] **`D02-012`** v1-only signing: Janus DEX prepend (CVE-2017-13156)  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-02 remote one click (sideload l · The v1 (JAR) scheme does not cover the whole APK file. On an affected platform, a DEX prepended to the archive…</sub>
- [ ] **`D02-013`** Duplicate ZIP-entry / "Master Key" class  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-02 · Add a second DEX under a near-name, then hex-edit the central-directory entry so both entries read `classes.de…</sub>

**🟩 Low ceiling**

- [ ] **`D02-014`** APK signing key below 2048-bit RSA  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · n/a (no realistic attacker at 1024 · MASTG-TEST-0225 fails when the signer key size is under 2048 bits (RSA).</sub>

**⬜ Support ceiling**

- [ ] **`D02-015`** Signer certificate identity: the Android debug certificate or a weak signature algorithm  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-03 zero-permission local app si · A production APK signed with the Android debug key (`CN=Android Debug, O=Android, C=US`) is signed with a *pub…</sub>
- [ ] **`D02-016`** v3.1 rotation split-brain: a different authoritative key per SDK range  
   <sub>``broken_access_control.privilege_escalation` (varies, rated on what the permis` · AM-03 (an app signed with the hist · v3.1 lets a developer rotate signing keys **only for SDK versions at or above `--rotation-min-sdk-version`**, …</sub>

**🟧 High ceiling**

- [ ] **`D02-017`** `knownSigner` / `android:knownCerts` allowlist enumeration  
   <sub>``broken_access_control.privilege_escalation` (varies — rated on what the permi` · AM-03 / AM-08 (a low-trust partner · `knownSigner` grants a permission to any app whose signing certificate appears in a hard-coded allowlist, *not…</sub>

**⬜ Support ceiling**

- [ ] **`D02-018`** Update-identity continuity: a differently-signed build must be refused  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4) a` · AM-09 malicious backend/CDN; AM-03 · Confirm the platform boundary holds, then confirm no side channel goes around it — an in-app updater, an OEM i…</sub>
- [ ] **`D02-019`** The app's own signer check reads `GET_SIGNATURES` / `signatures[0]` instead of `hasSigningCertificate`  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-03 zero-permission local app · Apps that gate a privileged IPC path on "is the caller signed by us" frequently read the legacy `PackageInfo.s…</sub>
- [ ] **`D02-020`** Installer-identity gating (`getInstallerPackageName` / `getInstallSourceInfo`)  
   <sub>``lack_of_binary_hardening.runtime_instrumentation_based` (P5) — never file sta` · AM-03 · Apps that only trust `com.android.vending` as the installer can be defeated by installing via a spoofed instal…</sub>
- [ ] **`D02-021`** Client-computed integrity signal that the backend never validates  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.identit` · AM-03 (attacker runs a repacked cl · If the app computes a signing-certificate hash or `getInstallerPackageName()` and sends it as a header or fiel…</sub>
- [ ] **`D02-022`** Repack → re-sign → run: is there any runtime integrity check at all  
   <sub>``lack_of_binary_hardening.lack_of_obfuscation` (P5) / `mobile_security_misconf` · AM-03 for the resulting trojanised · Decompile, alter a security-relevant branch, rebuild, sign with your own key, install. If the app runs normall…</sub>
- [ ] **`D02-023`** Locate and patch the in-app signer check rather than reimplementing it  
   <sub>``lack_of_binary_hardening.runtime_instrumentation_based` (P5) — never filed` · AM-12 (this is your own tooling st · When repackaging breaks the app, find the signer-verification routine and patch the **final branch**, not the …</sub>
- [ ] **`D02-024`** Server-verified attestation: stop, and re-scope  
   <sub>Before repacking, establish whether the integrity gate is local (hookable, patchable) or a **server-verified a…</sub>

**🟥 Critical ceiling**

- [ ] **`D02-025`** Custom APK verifier confusion: v3→v2 fallback and the unvalidated content digest  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-03 zero-permission local app (p · Stores, updaters, plugin managers and enterprise installers that run their own signature check frequently disa…</sub>

**⬜ Support ceiling**

- [ ] **`D02-026`** Deterministic installer cache: artefact substitution before install  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4) a` · AM-03 zero-permission local app (w · If a store, updater or helper downloads an installable artefact to a **deterministic path** and decides "alrea…</sub>

**🟥 Critical ceiling**

- [ ] **`D02-027`** Self-hosted / side-loaded update channel without pinned signature verification  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4 ba` · AM-09 malicious backend/CDN; AM-06 · Can the app fetch and run code after install — a DEX/JAR/SO/AAB fragment, a JS bundle, a plugin, a full APK? T…</sub>

**⬜ Support ceiling**

- [ ] **`D02-028`** The app enables unknown-sources installation or installs other packages  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4) w` · AM-02 remote one click (the user a · Does the app hold `REQUEST_INSTALL_PACKAGES`, drive the user to the unknown-sources settings screen, or call `…</sub>

**🟧 High ceiling**

- [ ] **`D02-029`** `android:debuggable="true"` in a release build → private-storage read on a stock device  
   <sub>`The flag alone is `insecure_data_storage.sensitive_application_data_stored_une` · AM-03 zero-permission local app /  · Detect the flag three independent ways (a repacked or SDK-injected build can differ from what you expect), the…</sub>
- [ ] **`D02-030`** Debuggable build → JDWP attach → arbitrary code in the app's UID  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 / AM-11 · `android:debuggable="true"` allows a JDWP debugger to attach and execute arbitrary code **inside the app's pro…</sub>
- [ ] **`D02-031`** Debuggable re-enables `adb backup` at targetSdk 31+  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) for the` · AM-11 physical unlocked with USB d · For `targetSdk >= 31`, `adb backup` excludes app data **unless** `android:debuggable="true"`. A release build …</sub>
- [ ] **`D02-032`** `setWebContentsDebuggingEnabled(true)` shipped unconditionally  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-11 physical unlocked with USB d · If called unconditionally, a connected host attaches Chrome DevTools to **every** WebView in the app, reads th…</sub>

**⬜ Support ceiling**

- [ ] **`D02-033`** `android:testOnly="true"` — you were handed the wrong binary  
   <sub>`— (scope control)` · `android:testOnly` marks the app installable only via `adb` and unpublishable to Play. Its presence in a build…</sub>
- [ ] **`D02-034`** `BuildConfig.DEBUG == true` inside a bundled AAR/JAR  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when i` · AM-06 network attacker (if the bra · Find every `BuildConfig` class in the decompiled tree — not just the app's — and then find what the flag actua…</sub>
- [ ] **`D02-035`** Debug/QA components and hidden menus surviving into the release variant  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-03 zero-permission local app · Hunt build-variant leakage: staging endpoints, auth-bypass toggles, payment-skip switches, "developer options"…</sub>
- [ ] **`D02-036`** Debug-only deep links and debug navigation routes in the release manifest  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-03 zero-permission local app (a · Debug routes left reachable from an exported filter. The severity hinges entirely on whether the session survi…</sub>
- [ ] **`D02-037`** Build residue shipped inside the package: mapping files, unstripped symbols, source maps  
   <sub>``sensitive_data_exposure.sensitive_data_hardcoded.file_paths` (P5) for paths a` · AM-01 (anyone who downloads the ap · Look inside the APK/AAB for shipped build residue that hands you the source model — ProGuard mapping, unstripp…</sub>
- [ ] **`D02-038`** Base-only install: does the app fail closed without its required splits  
   <sub>``broken_access_control.privilege_escalation` (varies) when the removed module ` · AM-03 (installs the base-only arte · Bundled apps normally refuse to run without their required splits. Check whether the app degrades **open** rat…</sub>
- [ ] **`D02-039`** `SplitInstallManager.getInstalledModules()` not checked before using module code  
   <sub>`— (mechanism; the finding is rated under D02-038)` · AM-03 · Find every entry point into a dynamic feature module and check whether the installation state is verified firs…</sub>
- [ ] **`D02-040`** Code and native libraries that exist only in a config split  
   <sub>`Follows the content — commonly `sensitive_data_exposure.disclosure_of_secrets.` · Follows the content · `config.arm64_v8a` and `config.<lang>` splits sometimes carry different code paths, different strings, and the…</sub>
- [ ] **`D02-041`** Re-signing and reinstalling a split set correctly  
   <sub>AM-12 · A repack of `base.apk` alone will not install over a split-delivered app. Every split must be rebuilt and re-s…</sub>

**🟧 High ceiling**

- [ ] **`D02-042`** `lib-*/` and extracted-native-library drop zones  
   <sub>``broken_access_control.privilege_escalation` (varies) — realistically rated as` · AM-03 zero-permission local app wi · `/data/data/<pkg>/lib-*/` is loaded at process start. Any primitive that writes an attacker-chosen filename in…</sub>

**⬜ Support ceiling**

- [ ] **`D02-043`** Merged-manifest diff: components and permissions no first-party code declared  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (varies — rated on wh` · AM-03 / AM-08 malicious third-part · Third-party AARs contribute `<activity>`, `<provider>`, `<receiver>` and `<uses-permission>` entries into the …</sub>
- [ ] **`D02-044`** Manifest-merger creep: an SDK re-opened cleartext or replaced the network security config  
   <sub>`Routes to the network finding it re-enables; the permission over-grant alone i` · AM-06 network attacker (cleartext) · A dependency can add a dangerous permission, re-enable `usesCleartextTraffic`, or replace the `networkSecurity…</sub>
- [ ] **`D02-045`** Resource-level feature gating flipped and rebuilt  
   <sub>``broken_access_control.privilege_escalation` (varies) / `broken_authentication` · AM-03 (an attacker running a repac · Search resources for booleans and strings that **gate functionality** rather than merely style it. If the serv…</sub>

**🟥 Critical ceiling**

- [ ] **`D02-046`** Signing and keystore material shipped inside the package  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote, no interaction (anyo · Search the package for keystore and private-key blobs. A private key that authenticates the app to a backend (…</sub>
- [ ] **`D02-047`** Live credentials recoverable from the artefact — routing and the liveness proof  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote, no interaction · Extract every credential-looking string from the artefact, then **prove liveness** against the real service. A…</sub>

**⬜ Support ceiling**

- [ ] **`D02-048`** Non-release artefacts shipped in the package  
   <sub>`Per the artefact: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_` · AM-01 · Walk the unpacked structure and flag every file that is not part of a release: test fixtures, `.sql` dumps, se…</sub>
- [ ] **`D02-049`** Packed / superpacked builds — recover the DEX that actually runs  
   <sub>``lack_of_binary_hardening.lack_of_obfuscation` (P5) for the packing itself — n` · n/a for the technique · If the APK's code is compressed into a single opaque file or a packer is in use, a static-only report is incom…</sub>

**🟥 Critical ceiling**

- [ ] **`D02-050`** `android:appComponentFactory` plus `createPackageContext` as a code-execution sink  
   <sub>``broken_access_control.privilege_escalation` (varies) — arbitrary code executi` · AM-03 zero-permission local app · A malicious app that claims a package name a victim passes to `createPackageContext()` and exports `android:ap…</sub>

**⬜ Support ceiling**

- [ ] **`D02-051`** Recover `base.odex` when DEX decompilation is fighting you  
   <sub>AM-12 (your own rooted device) · When jadx chokes on obfuscated or packed DEX, the AOT-compiled `base.odex` on device can carry resolved symbol…</sub>
- [ ] **`D02-052`** Gradle dependency verification absent or neutered  
   <sub>``using_components_with_known_vulnerabilities` (varies) — realistically this is` · AM-08 malicious third-party SDK · Absence of `gradle/verification-metadata.xml` means every dependency and every plugin is accepted on trust fro…</sub>

**🟨 Medium ceiling**

- [ ] **`D02-053`** Verification enabled but bypassed: the gpg-without-checksum hole  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-08 / AM-06 (MitM on the build h · On the affected Gradle range, an entry with a `gpg` element but no `checksum` element is accepted without vali…</sub>

**🟧 High ceiling**

- [ ] **`D02-054`** `pluginManagement` repository content filters are ignored  
   <sub>``using_components_with_known_vulnerabilities` (varies) — a live dependency-con` · AM-08 (publishes a squatted public · On the affected range, `content { includeGroup ... }` and `exclusiveContent` filters inside a `settings.gradle…</sub>

**🟥 Critical ceiling**

- [ ] **`D02-055`** MavenGate: hijackable `groupId` domains in the dependency tree  
   <sub>``using_components_with_known_vulnerabilities` (varies) — realistically supply-` · AM-08 malicious third-party SDK · Maven `groupId` ownership is proved by DNS control of the reversed domain. If that domain has lapsed, an attac…</sub>

**⬜ Support ceiling**

- [ ] **`D02-056`** Duplicate-class shadowing (Maven-Hijack) in the release classpath  
   <sub>``using_components_with_known_vulnerabilities` (varies); `cryptographic_weaknes` · AM-08 · Two dependencies both provide the same fully-qualified class; the classloader takes the first on the classpath…</sub>
- [ ] **`D02-057`** Gradle wrapper jar and distribution URL integrity  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check`` · AM-06 (MitM on the build host's ne · `gradle-wrapper.jar` executes on every build with full developer and CI privileges and is committed as a binar…</sub>
- [ ] **`D02-058`** Dependencies fetched over plaintext HTTP  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check`` · AM-06 network attacker on the deve · An `http://` Maven repository means every artefact — including ones that execute during the build — is MitM-ab…</sub>
- [ ] **`D02-059`** SBOM of the shipped binary, reconciled against the declared graph  
   <sub>``using_components_with_known_vulnerabilities` (varies)` · AM-08 · Prove the SBOM describes the artefact that reaches users. Scanning a lockfile proves nothing about a DEX plus …</sub>
- [ ] **`D02-060`** osv-scanner over the reconciled list, then the reachability gate  
   <sub>``using_components_with_known_vulnerabilities.outdated_software_version` (**P5*` · Follows the CVE · Map coordinates to advisories with an ecosystem-native database rather than NVD CPE matching, which has poor c…</sub>
- [ ] **`D02-061`** Library version fingerprinting when R8 stripped the version markers  
   <sub>When `META-INF/*.version` and `BuildConfig` are gone you still must produce a version. Use bytecode-structure …</sub>
- [ ] **`D02-062`** Build artefacts left on the API or CDN host  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote, no interaction · Run the old/backup/unreferenced-file hunt against the **mobile API and release-distribution hosts** specifical…</sub>
- [ ] **`D02-063`** Version rollback: does the backend still serve an older signed build  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-11 physical unlocked / AM-03 wi · An attacker who can uninstall then install plants an **older, legitimately-signed** build whose bug the vendor…</sub>
- [ ] **`D02-064`** Minimum installable `targetSdkVersion` and the documented bypass  
   <sub>`— (harness); the finding, where one exists, routes through the distribution ch` · AM-03 (an attacker distributing a  · Confirm whether the app under test can even be installed on the target OS — and note that testers can bypass t…</sub>
- [ ] **`D02-065`** `@ChangeId` / `enableAfterTargetSdk` audit: security checks gated on the app's chosen targetSdk  
   <sub>`Routes to the gated weakness (for the cited case, `server_side_injection.sql_i` · Any app that declares an old `targ · `@ChangeId` / `@EnabledAfter(targetSdkVersion = …)` annotations mark behaviour that is **off** for legacy-targ…</sub>
- [ ] **`D02-066`** Platform-signed non-system APK without a signature-permission allowlist entry  
   <sub>``broken_access_control.privilege_escalation` (varies)` · n/a directly; this is a platform-k · On Android 15+, a platform-signed non-system app's platform `signature` permissions must be allowlisted. If no…</sub>
- [ ] **`D02-067`** Privileged-app permission allowlisting on OEM images  
   <sub>``broken_access_control.privilege_escalation` (varies)` · AM-03 (an unprivileged app proxyin · For apps in `/system/priv-app` or the vendor/product equivalents, every `signature|privileged` permission must…</sub>
- [ ] **`D02-068`** Establish the partition before claiming persistence  
   <sub>Before writing up a "persistent compromise", establish which partition the artefact lives on. An artefact in `…</sub>
- [ ] **`D02-069`** Shell-Loop Ban on artefact sweeps — count your results  
   <sub>zsh array expansion fails **silently** on edge cases. A loop like `for x in "${arr[@]}"` can produce zero iter…</sub>
- [ ] **`D02-070`** Run the pre-severity gate against the Critical claim, not against the repack  
   <sub>Write the draft Critical title, then substitute **the Critical claim** — not the bug — into each question: (1)…</sub>
- [ ] **`D02-071`** Chain-filing order for D02 primitives  
   <sub>D02 is a primitive factory: debuggable, a missing integrity check, an unsigned update channel, a writable lib …</sub>
- [ ] **`D02-072`** Evidence capture for an integrity finding: what to show and what to mask  
   <sub>A D02 state-change finding needs the same five-shot discipline as any state-change bug, adapted to the artefac…</sub>

<details><summary>⚰️ D02 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The APK can be decompiled / is not obfuscated" | `lack_of_binary_hardening.lack_of_obfuscation` = **P5**. Google Invalid Reports: "Most applications (including Android apps) can be reverse engineered... in itself, being able to determine internal information about how an application works is not a vulnerability." HackenProof, Grab, Spotify, Starbucks and Xiaomi all list it out of scope verbatim. | Recover a *specific* secret or algorithm from behind the obfuscation — call the app's own string-decryptor with Frida and print the HMAC key or API base — then report the crypto/authz finding underneath (D02-047, -> D12, -> D15). |
| "The app can be repackaged and re-signed" | P5. The repack is a tool, not a bug. Ask whether the impact sentence survives deleting the words "an attacker can decompile the APK"; if not, it is not a finding. | The repack unlocks a server-honoured entitlement, auth bypass or price change — and the **server** accepts the request the stock client could never send (D02-045, D02-022). |
| "Missing binary hardening: no PIE, no stack canaries, no ARC" | `lack_of_binary_hardening.lack_of_exploit_mitigations` = **P5**, CWE-693, with the all-zeros impact vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` — the taxonomy scores it at no impact. | Nothing in this domain. Fold into a hardening appendix in a client report; never a bounty submission. |
| "No root / emulator / tamper detection" | `lack_of_binary_hardening.lack_of_jailbreak_detection` = **P5**. Your own rooted device is AM-12 and is not an attacker. | Only as the enabling sentence of a finding whose impact is demonstrated elsewhere (D21), never as the finding. |
| "v1 signature present alongside v2/v3" | Not a finding at all. v1 co-presence is normal for backward compatibility; only **v1-only** is the Janus precondition, and only with a `minSdkVersion` reaching an affected platform. | `apksigner verify --verbose` showing v2 **and** v3 false, plus a successful `adb install -r` of a modified build on an in-scope OS version (D02-012). |
| "No v4 signature / no `.idsig` file" | v4 (Android 11+) supports ADB incremental install; its absence is a delivery-performance characteristic, not a security control. | Nothing. Record the scheme set (D02-011) and move on. |
| "1024-bit RSA signing key" | MASTG-TEST-0225 fails it, but forging a 1024-bit RSA signature is not practical today, so programs rate it Low at best. | Fold it into a single combined "app integrity is not cryptographically assured" item with D02-012 and D02-015 rather than filing a standalone Low. |
| "`android:allowBackup="true"`" | `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5**. H1 #1225158 (Zivver), "ADB Backup is enabled within AndroidManifest", paid **$0** — the flag was the whole report. | A live session token or credential recovered from the unpacked `.ab` tarball and replayed successfully against the production API (D02-031, -> D11, -> D13). |
| "`android:debuggable="true"`" with nothing extracted | The flag alone. MASTG links Android's own note that it "is not considered a direct vulnerability". | `run-as` output on a **stock, non-rooted, `ro.build.type=user`** device containing an actual token or credential, plus the replayed 200 (D02-029). |
| "OAuth `client_secret` found in the APK" | `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` = **P5**, and it is on the never-submit list: a mobile app is a *public* client and is not supposed to hold a confidential secret. | The inversion: the reportable finding is **PKCE non-enforcement** at the authorisation server — show that an authorisation code obtained without a `code_verifier` still exchanges for a token (-> D13). |
| "Firebase web API key / Maps key in `strings.xml`" | `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` = **P5**; a billable-but-not-sensitive key is `...pay_per_use_abuse` = **P4**, not P1. | The key has no package+SHA-1 restriction and reaches a *sensitive* asset — verified by calling the API from an unrestricted host and getting data back (D02-047, -> D18). |
| "Library X is at an outdated version" with no reachability | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5**. R8/LLVM dead-code elimination routinely strips the vulnerable method entirely. | The symbol survives into `classes*.dex`, a caller chain reaches it from an exported entry point, and a Frida hook proves the frame is entered with attacker-supplied data (D02-060). |
| "The app crashes when a split is missing" | Fail-closed is the **correct** behaviour. Crash-only DoS via intents is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5** (H1 #3399016 scored 0.0). | The opposite observation: the app launches base-only and a module-gated control is skipped (D02-038). |
| "`adb install` failed with `INSTALL_FAILED_DEPRECATED_SDK_VERSION`" | A harness artefact of the test device's Android version, not a property of the app. | The client's own distribution channel (enterprise MDM, sideload updater) ships a sub-minimum-target APK that the platform would otherwise refuse (D02-064). |
| "A Frida gadget can be injected / the app can be instrumented" | `lack_of_binary_hardening.runtime_instrumentation_based` = **P5**. This is your tooling. | Nothing in this domain. Report what the instrumentation revealed, in whichever domain owns it. |
| "Testing on my own rooted device showed X" | AM-12 is not an attacker model. A root-only observation is at most P5 storage. | Demonstrate the same read via a no-root path — `run-as` on a debuggable build, `adb backup`, a backup transport, or a same-UID sibling (D02-029, D02-031). |
| "Duplicate `classes.dex` / Master Key reproduces" (claimed, untested) | Long fixed on every supported Android; the class is LEGACY. | A successful `adb install -r` **on an in-scope OS version**, with the injected DEX executing (D02-013). Verify very carefully before reporting. |

</details>


<details><summary>🔗 D02 cross-surface joins — park these, chase them in P7</summary>

- **D02 split set × D03 manifest model.** Reviewers decode `base.apk` and enumerate components from its manifest. A `config.*` or feature split ships its **own** manifest fragment, so an exported provider or receiver that exists only in a split is invisible to a base-only review and to every drozer scan run against the base package's declared components. Join: run the `aapt2 d xmltree` component sweep over **every** split (D02-040), then feed the delta into D03/D05/D06/D07 as a second pass. The delta is where the unreviewed components live.
- **D02 Play App Signing key × D09 Digital Asset Links.** The `assetlinks.json` fingerprint must match the **app signing key** Google re-signs with, not the upload key that signed the artefact you were handed. A team that rotates the upload key, or that publishes the upload fingerprint, ships App Links that never verify — and a malicious app registering the same host filter then wins link traffic. Nobody checks these two surfaces together because one lives in Play Console and the other on a web server (D02-006).
- **D02 `android:debuggable` × D12 Android Keystore.** A "the key never leaves Keystore, so extraction is impossible" design is defeated without extracting anything: JDWP-attach the debuggable process and **call the app's own decrypt routine in-process**. The Keystore review concludes "hardware-backed, not extractable" and the D02 review concludes "debuggable, P5 hardening note" — the join is arbitrary decryption of every locally stored ciphertext (D02-030).
- **D02 missing-split fail-open × D21 RASP/attestation.** The RASP review tests whether the root check can be hooked. The feature-delivery review tests whether the app runs without its modules. Nobody asks whether the **attestation code lives in a split** — if it does, a base-only install removes the control entirely, with `base.apk`'s signature untouched and no instrumentation for RASP to detect (D02-038).
- **D02 version history × D15 shadow API.** The endpoints hardcoded in build N-3 are an *older API version* than the current web app uses, with weaker auth, weaker rate limits, weaker validation and more field exposure. The mobile reviewer looks at the current APK; the API reviewer looks at the current web traffic; neither looks at the artefact that documents the version the vendor forgot to retire. Diff **behaviourally**, per operation — a version difference alone is Informational (D02-009).
- **D02 `knownSigner` allowlist × D06 bound services.** The IPC reviewer sees `protectionLevel="signature"` and marks the service protected. The signing reviewer sees a certificate digest array and marks it inventory. Joined on Android 12+, `knownSigner` means *any* party holding *any* key in that array — including a rotated-away key or a low-trust partner's — takes the permission automatically and with no user notification (D02-017).
- **D02 merged-manifest creep × D14 network security config.** The network reviewer confirms `cleartextTrafficPermitted="false"` from the app's source manifest and concedes the cleartext finding as mitigated. The **merged** manifest is the one that ships, and an SDK can re-add `usesCleartextTraffic="true"` or replace the `networkSecurityConfig` reference through ordinary merger rules. The join re-opens a finding both reviewers had closed (D02-044).
- **D02 `lib-*/` drop zone × D07 FileProvider path traversal.** The provider reviewer finds a traversal write and rates it "arbitrary file write into the app sandbox" — Medium. The package-layout reviewer knows `/data/data/<pkg>/lib-*/` is loaded at process start. Joined, the write primitive lands a `.so` under the name of a library the app loads and becomes persistent code execution in the app's UID on next launch (D02-042; the Evernote and Mattermost shape).
- **D02 resource flag flip × D23 entitlements × D15 backend.** Three reviewers each see a third of this: a `is_premium` string in `res/values`, a paywall in the payments flow, an entitlement field in an API response. The join is one test — flip the resource, rebuild, and check whether the **server** honours the premium-only call. If it does, a P5 "app can be repackaged" becomes a payments finding (D02-045).
- **D02 custom verifier × D07 path traversal × D02 deterministic cache.** The Samsung Galaxy Store chain is exactly this join: a verifier that checks the signature over a digest without recomputing it, a deterministic cache path, and a write primitive to reach that path. Each alone is a Medium-at-best observation; together they are arbitrary app installation under a trusted signer allowlist (D02-025, D02-026).

</details>


---

## D03 AndroidManifest & Permission Model

**Phase P3 · `M3` · 76 items** — ⬜ 76 support  

📄 Full detail, with every command and proof: [`checklist/D03-manifest-and-permissions.md`](checklist/D03-manifest-and-permissions.md)

> **Crux question.** **Is there any component whose only access control is a permission string that a zero-permission app can obtain — by declaring it, by defining it first, or because nobody ever defined it — and if the string does hold, does the code behind it interrogate the *caller* rather than itself?**

Most of what this domain produces is worthless on its own. "allowBackup is true", "the app requests 14 permissions", "component X is exported" — Google's own invalid-report page says backups enabled is intended behaviour, Xiaomi lists `allowbackup:True` as out of scope, Bugcrowd pins `mobile_security_misconfiguration.auto_backup_allowed_by_default` at P5 with the vector `AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`, and Google's invalid-reports guidance states plainly that "excessive permissions alone do not have enough of a security impact to qualify for a reward". If your D03 output is a permission inventory, you have produced nothing.


**⬜ Support ceiling**

- [ ] **`D03-001`** Analyse the MERGED manifest, and attribute every entry to the module that injected it  
   <sub>`none (enabler)` · The manifest that is enforced is the one inside the built APK, not `app/src/main/AndroidManifest.xml`. `AD_ID`…</sub>
- [ ] **`D03-002`** Fix the API-level matrix from the app's own declaration and bind every finding to it  
   <sub>`none (enabler; it is also the severity-honesty control)` · `minSdkVersion` is the security floor; `targetSdkVersion` selects which platform defaults apply to *this* app.…</sub>
- [ ] **`D03-003`** Build the effective-export table, resolving the default per component type and targetSdk  
   <sub>`none (the *reached behaviour* is what gets filed, under `broken_access_control` · AM-03 · The documented defaults are not uniform and are the most commonly mis-stated fact in Android testing: `<provid…</sub>
- [ ] **`D03-004`** Reconcile the manifest against the live PackageManager resolver tables  
   <sub>`none (enabler)` · AM-03 · The manifest and the enforced state diverge when a component is enabled or disabled at runtime with `PackageMa…</sub>
- [ ] **`D03-005`** Read the permission model from PackageManager, not from the manifest, and decode the numeric protectionLevel  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The manifest string and the *enforced* level diverge — another app defined the name first, an OEM overrode it,…</sub>
- [ ] **`D03-006`** Prove every reachability claim from a separate, zero-permission attacker APK — never from `adb shell am` alone  
   <sub>`none (evidence discipline)` · AM-03 · `adb shell am` runs as UID 2000 (`shell`), which holds permissions no ordinary app has, and drozer's agent lik…</sub>
- [ ] **`D03-007`** Count your sweep results — the shell-loop ban applied to manifest and permission enumeration  
   <sub>`none (false-positive / false-negative discipline)` · zsh array expansion fails **silently**. A loop such as `for c in "${components[@]}"; do adb shell am start -n …</sub>
- [ ] **`D03-008`** Orphan permission — a component guarded by a permission string nobody defines  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) escalating to ` · AM-03 · The highest-yield item in the domain. If the target protects a component with `android:permission="com.target.…</sub>
- [ ] **`D03-009`** Custom `<permission>` with no `protectionLevel` — it silently becomes `normal`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A `<permission>` element without an explicit `protectionLevel` attribute defaults to `normal`, which is auto-g…</sub>
- [ ] **`D03-010`** `normal` or `dangerous` protectionLevel guarding a privileged action  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) or `broken_acc` · AM-03 (normal) / AM-04 (dangerous  · `normal` "most apps can request and get it" — it is auto-granted with no prompt. `dangerous` is "approved by m…</sub>
- [ ] **`D03-011`** Permission-name typo, case mismatch, or a non-permission literal  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Two failure shapes, both silent at build time. (a) The component is guarded by `MY_PREM` while the manifest de…</sub>
- [ ] **`D03-012`** `android:uses-permission` on a component tag, or `<uses-permission>` nested inside one  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Two structural mistakes the platform ignores without a build error. (a) `android:uses-permission="..."` writte…</sub>
- [ ] **`D03-013`** Permission squatting — the attacker defines the target's custom permission first  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · Android resolves a duplicated custom-permission *name* on a first-definer-wins basis. If the target defines `c…</sub>
- [ ] **`D03-014`** Protection-level downgrade after the defining app is uninstalled  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 (requires the legitimate def · Test the full lifecycle, not just a fresh install. If the app that *defined* a custom permission is uninstalle…</sub>
- [ ] **`D03-015`** Ecosystem missing-redeclaration — defined in App A, only *used* by App B  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · A `signature` permission defined only in App A but merely *used* by App B is unenforceable when only App B is …</sub>
- [ ] **`D03-016`** `<permission-tree>` and runtime `PackageManager.addPermission()`  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 / AM-09 (a backend that cont · `<permission-tree>` lets an app add permissions under a namespace at runtime via `PackageManager.addPermission…</sub>
- [ ] **`D03-017`** Custom permission mapped into a platform `permissionGroup`  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-04 · Runtime prompts are presented per group. A `dangerous` custom permission that names a *platform* `android:perm…</sub>
- [ ] **`D03-018`** `knownSigner` / `android:knownCerts` — enumerate the certificate allow-list  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-08 (a partner or rotated-away k · A `knownSigner` permission is granted to any app whose signing certificate appears in a hard-coded allow-list …</sub>
- [ ] **`D03-019`** `signatureOrSystem` — deprecated at API 23, and a weaker claim than the developer thinks  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-08 / OEM scope · `signatureOrSystem` grants to apps on the system image **or** same-signature apps. On an OEM image with a perm…</sub>
- [ ] **`D03-020`** `PROTECTION_INTERNAL` with no gating flag  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `internal` is a no-op *base* protection that exists only to be combined with flags (`role`, `privileged`, `ins…</sub>
- [ ] **`D03-021`** `development`-flagged permission grantable straight from the shell  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when t` · AM-11 (physical unlocked / ADB), A · A permission carrying the `development` flag can be granted from the shell with `pm grant` even though it is s…</sub>
- [ ] **`D03-022`** Role-protected permission (`PROTECTION_FLAG_ROLE`) — taking the role takes the permission  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-02 (one user tap to change the  · A `role`-flagged permission is granted to whichever app currently holds a system Role — default SMS app, defau…</sub>
- [ ] **`D03-023`** A "platform" signature permission whose definer is not `android`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `signature` on a permission defined by a third-party app means "same key as *that app*", not "same key as the …</sub>
- [ ] **`D03-024`** `checkSelfPermission()` in an exported entry point — the confused-deputy core  
   <sub>``broken_access_control.privilege_escalation` (null) escalating to `broken_auth` · AM-03 · The single highest-value code review in this domain. `checkSelfPermission()` asks *"does **my** app hold this …</sub>
- [ ] **`D03-025`** `checkCallingOrSelfPermission()` / `enforceCallingOrSelfPermission()` — passes because *you* pass  
   <sub>``broken_access_control.privilege_escalation` (null) -> P1 as above` · AM-03 · The `...OrSelf` variants return success whenever **either** the caller **or** the callee holds the permission.…</sub>
- [ ] **`D03-026`** `checkCallingPermission()` result discarded — it returns an `int`, it does not throw  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `checkCallingPermission()` returns `PackageManager.PERMISSION_GRANTED` (0) or `PERMISSION_DENIED` (-1). Code t…</sub>
- [ ] **`D03-027`** `Binder.clearCallingIdentity()` launders the caller before the check runs  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · `clearCallingIdentity()` swaps the Binder thread's notion of the caller to the **callee's own** identity. Any …</sub>
- [ ] **`D03-028`** `Binder.getCallingUid()` on a same-process call returns your own UID  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Any authorisation helper written as `if (Binder.getCallingUid() == Process.myUid()) allow;`, or any helper rea…</sub>
- [ ] **`D03-029`** `getCallingPackage()` / `getCallingActivity()` null-handling used as authorisation  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `getCallingPackage()` and `getCallingActivity()` are populated only when the caller used `startActivityForResu…</sub>
- [ ] **`D03-030`** Package-name substring / prefix matching used as a trust boundary  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `contains()`, `startsWith()`, `endsWith()` and `indexOf()` on a caller's package name are trivially satisfiabl…</sub>
- [ ] **`D03-031`** Permission re-delegation — the app holds the permission, the caller does not, and the app will use it for them  
   <sub>``broken_access_control.privilege_escalation` (null); files to P1 when the dele` · AM-03 · Cross-reference every dangerous permission the app holds against the exported components that surface that dat…</sub>
- [ ] **`D03-032`** `android:permission` on `<application>` silently **overridden**, not supplemented, by a per-component value  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 / AM-04 · Developers set `android:permission` once on `<application>` and believe it is a floor. It is not — a per-compo…</sub>
- [ ] **`D03-033`** `<activity-alias>` inherits nothing from its target  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · An alias can be `exported="true"` with no `android:permission` while its `targetActivity` is `exported="false"…</sub>
- [ ] **`D03-034`** `android:exported="true"` written to satisfy the targetSdk 31 build  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Since Android 12 an intent-filtered component cannot install without an explicit `android:exported`. The pre-1…</sub>
- [ ] **`D03-035`** `android:path` used where `pathPrefix` was meant — the subtree is unguarded  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `android:path` matches the **exact** path only. A provider whose permission is scoped with `android:path` leav…</sub>
- [ ] **`D03-036`** `<path-permission>` coverage gap and `<grant-uri-permission>` scoped to the whole provider  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Two halves. (a) Any path **not** matched by a `<path-permission>` falls back to the provider-level permission …</sub>
- [ ] **`D03-037`** Provider declares `readPermission` but omits `writePermission`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Splitting `android:readPermission` and `android:writePermission` creates a gap: a provider that declares only …</sub>
- [ ] **`D03-038`** `android:process` with a global name, and missing `isolatedProcess` on untrusted-input services  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-08 · An `android:process` value beginning with a lowercase letter (no leading `:`) puts the component in a **global…</sub>
- [ ] **`D03-039`** `android:directBootAware="true"` — components that run before the user unlocks  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-10 (physical locked — this is t · A Direct-Boot-aware component can run before the user unlocks and can only touch *device-protected* storage du…</sub>
- [ ] **`D03-040`** Context-registered receivers are invisible to manifest analysis — and `RECEIVER_NOT_EXPORTED` is mandatory from API 33  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Receivers created with `Context.registerReceiver` appear in neither the manifest nor `drozer app.broadcast.inf…</sub>
- [ ] **`D03-041`** Dialler secret-code receivers (`android.provider.Telephony.SECRET_CODE`)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 (broadcast it programmatical · A `SECRET_CODE` receiver exposes app functionality to anyone who can type `*#*#<code>#*#*` into the dialler — …</sub>
- [ ] **`D03-042`** Accessory intent filters (USB / NFC) — exported by necessity, therefore audit them as exported components  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the crash-onl` · AM-03 (forge the intent from an ap · An activity carrying these filters **must** be exported — the system delivers the intent — and usually carries…</sub>
- [ ] **`D03-043`** Account-type squatting against `AbstractAccountAuthenticator`  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) once` · AM-03 (install order matters — dem · If the app declares an account authenticator, the `android:accountType` string is claimed **first-installer-wi…</sub>
- [ ] **`D03-044`** `android:intentMatchingFlags` — `"none"` is an explicit opt-*out* of Android 16 intent hardening  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Three sub-cases. (a) `intentMatchingFlags="none"` **disables all special matching rules and takes precedence**…</sub>
- [ ] **`D03-045`** `resolveActivity() == null` used as a security gate — the package-visibility trap  
   <sub>``broken_access_control.privilege_escalation` (null); rate on the control the g` · AM-03 · A very common modern pattern: the app decides whether a competitor, clone, root manager, overlay app or offici…</sub>
- [ ] **`D03-046`** `QUERY_ALL_PACKAGES` and over-broad `<queries>` — and using `<queries><package>` to remove your own PoC's precondition  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies) for the collection hal` · AM-03 / AM-08 · Two opposite uses. (a) The app holds `QUERY_ALL_PACKAGES` or a wildcard `<queries><intent>` block and ships th…</sub>
- [ ] **`D03-047`** App-op-gated special permissions fail open at `MODE_IGNORED`  
   <sub>``mobile_security_misconfiguration.tapjacking` (**P5**) when the failed-open co` · AM-11 (to set the op) / AM-08 · For `appop`-flagged permissions (`SYSTEM_ALERT_WINDOW`, `WRITE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE`, `REQUEST_…</sub>
- [ ] **`D03-048`** Foreground-only permissions: probe the background path where the op flips to `MODE_IGNORED`  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies)` · n/a — this is a client-behaviour f · The platform implements "while in use" by flipping the app-op to `MODE_IGNORED` on backgrounding — it does **n…</sub>
- [ ] **`D03-049`** Restricted permissions and installer-granted allow-list exemptions  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-08 / AM-09 (the installer is th · Hard-restricted permissions (the SMS and Call Log classes) cannot be granted without an allow-list entry, and …</sub>
- [ ] **`D03-050`** `GRANTED_BY_DEFAULT` / `SYSTEM_FIXED` flags — read the flags, not just `granted=true`  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies); `broken_access_contro` · n/a — this is a multi-party-author · `GRANTED_BY_DEFAULT` means `DefaultPermissionGrantPolicy` pre-granted it with no user interaction; `SYSTEM_FIX…</sub>
- [ ] **`D03-051`** `NEARBY_WIFI_DEVICES` without `usesPermissionFlags="neverForLocation"`  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies); `privacy_concerns.unn` · n/a — client-behaviour finding · Android 13 introduced `NEARBY_WIFI_DEVICES` so apps can do Wi-Fi work without `ACCESS_FINE_LOCATION`. The `nev…</sub>
- [ ] **`D03-052`** Attribution tags and `AppOpsManager.OnOpNotedCallback` — attribute every protected-data read to the SDK that made it  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies); escalates to `sensiti` · AM-08 · Two findings from one hook. (a) Who inside the process actually reads the protected data — the app, or a bundl…</sub>
- [ ] **`D03-053`** SDK-injected permissions and components — attribute them, then find who consumes them  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies)` · AM-08 · AARs merge their `<uses-permission>` and their components into the app. Find permissions with no corresponding…</sub>
- [ ] **`D03-054`** `android:maxSdkVersion`, permission splits, and the held-versus-requested delta  
   <sub>`none (evidence discipline)` · `aapt2 d permissions` prints the **requested** set. What the app *holds on the device you are testing* is a di…</sub>
- [ ] **`D03-055`** Bind every dangerous permission to a consuming code path and a user-facing feature  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies), escalating to `sensit` · AM-08 (the SDK doing the collectio · Build a three-column table — permission, the API call that consumes it, the screen that justifies it. Rows wit…</sub>
- [ ] **`D03-056`** Device-administrator receiver (`BIND_DEVICE_ADMIN`) with an attacker-reachable policy sink  
   <sub>``broken_access_control.privilege_escalation` (null); the destructive outcome f` · AM-03 (to reach the sink) · Does the manifest contain a receiver with `android.permission.BIND_DEVICE_ADMIN` and a `DEVICE_ADMIN_ENABLED` …</sub>
- [ ] **`D03-057`** AccessibilityService scope — `typeAllMask` with no `packageNames` allow-list  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) ` · AM-08 (the SDK inside the app) / A · Does the app bind `android.accessibilityservice.AccessibilityService`, and what does its config request? `canR…</sub>
- [ ] **`D03-058`** Default-SMS-handler role and `SMS_DELIVER` — read, send, and erase  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3) via the OTP ` · AM-02 (the role change needs a tap · Does the app request the default-SMS role or register `SMS_DELIVER`? Only the default handler receives it — an…</sub>
- [ ] **`D03-059`** Telephony call control — `CALL_PHONE`, `ANSWER_PHONE_CALLS`, `CallScreeningService` and MMI forwarding  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 (local app driving an export · Call forwarding is the quiet one. An MMI string such as `**21*<number>#` reaching the dialler silently redirec…</sub>
- [ ] **`D03-060`** `USE_EXACT_ALARM` and `USE_FULL_SCREEN_INTENT` — auto-granted permissions that dodge the prompt  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) for the FSI ph` · AM-01/AM-09 (a push payload) for t · (a) `USE_EXACT_ALARM` is granted automatically and is restricted to alarm/timer and calendar apps; an app decl…</sub>
- [ ] **`D03-061`** `SYSTEM_ALERT_WINDOW` held — and the inverse, the app's own screens undefended against other apps' overlays  
   <sub>``mobile_security_misconfiguration.tapjacking` (**P5** — a pinned node). This i` · AM-04 — the overlay app needs `SYS · Two halves, and the second is the one worth your time. (a) Does the app hold `SYSTEM_ALERT_WINDOW`, and does a…</sub>
- [ ] **`D03-062`** `foregroundServiceType` and the sensor held while the app is not visible  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies), escalating to `sensit` · AM-08 (the SDK doing it inside the · `startForeground()` is the documented way to keep sensor access after Android 9 cut background sensors off, so…</sub>
- [ ] **`D03-063`** `ACCESS_BACKGROUND_LOCATION` and the always-on location posture  
   <sub>``privacy_concerns.unnecessary_data_collection` (varies) for the collection; th` · AM-05 (another user of the same ap · Declaring the permission is not the finding, and neither is the app polling — both are privacy observations th…</sub>
- [ ] **`D03-064`** Health Connect `android.permission.health.*` — the most sensitive permission family most checklists ignore  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) ` · AM-08 / AM-09 · `android.permission.health.*` is a large, granular, per-data-type family covering reproductive health (`READ_M…</sub>
- [ ] **`D03-065`** `MANAGE_EXTERNAL_STORAGE` / `requestLegacyExternalStorage` — the scoped-storage escape  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_extern` · AM-04 (a second app with storage/m · Two halves: does the app opt out of scoped storage or hold "All files access", and — the half that decides sev…</sub>
- [ ] **`D03-066`** Privileged-permission tiers on preloaded and OEM apps  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · For preloaded or OEM apps in scope, enumerate the `signature` / `signatureOrSystem` / privileged permissions t…</sub>
- [ ] **`D03-067`** `sharedUserId` — one compromised sibling is all of them  
   <sub>``broken_access_control.privilege_escalation` (null) escalating through whateve` · AM-08 (compromise the weak sibling · Apps with the same `android:sharedUserId` and identical signing certificates share one Linux UID, one permissi…</sub>
- [ ] **`D03-068`** `allowBackup` — the flag is P5; the finding is the credential you extract and replay  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**, CWE` · AM-11 (physical unlocked + ADB) fo · `allowBackup="true"` (and the attribute missing, which defaults to true) is not a finding. The finding is a fi…</sub>
- [ ] **`D03-069`** `dataExtractionRules` — cloud backup and device transfer are configured **separately**  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-05 / AM-11 · Read the referenced rules file, not the attribute. `allowBackup="true"` with a rules file that excludes `datab…</sub>
- [ ] **`D03-070`** Backup **restore** as a write primitive — `restoreAnyVersion`, a custom `backupAgent`, and a tampered archive  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**) cov` · AM-11 (physical, unlocked, with de · Everyone reads the backup in one direction. The other direction is where the severity is: extract, **edit**, r…</sub>
- [ ] **`D03-071`** `android:debuggable` and `android:testOnly` in a shipped build  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-11 (physical unlocked with USB  · A debuggable release lets any local principal attach JDWP, read and rewrite live memory, and `run-as` the pack…</sub>
- [ ] **`D03-072`** `<uses-native-library>` and `System.load()` from a path outside the APK  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) is the wrong node for a` · AM-03 / AM-04 (write the file), AM · From API 31 an app must declare native libraries it loads from outside its own APK. An app that instead `Syste…</sub>
- [ ] **`D03-073`** Framework meta-data keys in the merged manifest — the code-delivery configuration hides here  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when an attacker-contro` · AM-09 (malicious backend/CDN) / AM · Each cross-platform framework stores security-relevant configuration as `<meta-data>` in the merged manifest. …</sub>
- [ ] **`D03-074`** Manifest-derived backend hosts and API versions — the shadow-API bridge  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) / `b` · AM-01 · The manifest and its `<meta-data>` / `strings.xml` references are the first place an engagement learns which b…</sub>
- [ ] **`D03-075`** `REQUEST_INSTALL_PACKAGES` and the update-identity boundary  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the attacker-contro` · AM-06 / AM-09 · Confirm the update path genuinely requires signature continuity, and that no side channel — an in-app updater,…</sub>
- [ ] **`D03-076`** Rate the reached behaviour, not the manifest attribute — and file the chain in the right order  
   <sub>`n/a — this is the rule for *choosing* the VRT node` · Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute your draft title int…</sub>

<details><summary>⚰️ D03 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app requests excessive permissions" / permission-inventory report | Google's invalid-reports page: *"excessive permissions alone do not have enough of a security impact to qualify for a reward."* HackenProof: *"permissions declared but unused — common in many Android apps and not a security issue."* MASTG-TEST-0254 rates it under the privacy profile. | The permission -> consumer -> feature table (D03-055) has a row with a consumer and no feature, or a dangerous permission the app holds is reachable by a third party through an exported component (D03-031 re-delegation), or the collected data reaches a host not named in the Play Data safety declaration (-> D20). |
| `android:allowBackup="true"` | `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5**, vector `AV:P`. Google: *"backups are enabled by default ... we don't consider it a security vulnerability if an app allows backups."* Xiaomi lists it out of scope. `adb backup` is dead on most modern builds. | A demonstrated extraction, on a non-rooted device without developer mode, of a credential that then authenticates against the production API — or the same credential surviving a **cloud** backup restored on an attacker-controlled device, which removes `AV:P` (D03-068). |
| "Component X is exported" | The export is the map, not the territory. Bugcrowd's `broken_access_control.exposed_sensitive_android_intent` is priority **VARIES** precisely because you must demonstrate the effect. ownCloud #145402 listed four and paid nothing. | The sink behind it: an extra reaching a WebView, a URI reaching a fetch, an intent being forwarded, a state change occurring — reached from a zero-permission app (D03-034, then D04–D08). |
| SSL pinning absent or defeatable | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` and `.defeatable` are both **P5**. A user-installed CA is a tester convenience (AM-07), not an attacker. | Not in this domain at all — see D14. The `minSdk<24` user-CA-trust and `<certificates src="user"/>` items there are the reportable shapes. |
| Missing jailbreak/root detection, missing exploit mitigations | `lack_of_binary_hardening.lack_of_jailbreak_detection` and `.lack_of_exploit_mitigations` = **P5**. AM-12 (own rooted device) is not an attack. | Not in this domain — see D22. |
| Malformed-intent crash on an exported component | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**. | The same unchecked parcelable reaching a memory-unsafe native parser (-> D16), or the crash being a reliable pre-condition for another primitive. |
| `minSdkVersion` is low | A number is not a bug. The corpus is unanimous: report the legacy issue it enables, at that issue's severity. | A working reproduction of the enabled bypass on an emulator at that API level (D03-002). |
| MASTG-TEST-0255 / -0256 / -0257 (permission minimisation, rationale, auto-reset) | All three carry `status: placeholder` in MASTG — empty stubs with no procedure. Compliance/UX, no attacker primitive. Demote to Informational. | Nothing in a bounty context. Keep as a programme-hygiene note in a pentest/WAPT deliverable where hygiene is a contracted output. |
| `android:sharedUserId` present | Deprecated, yes; a finding, no. Enormously common in OEM and long-lived enterprise families. | The sibling set enumerated on-device (same `userId=` in `dumpsys package`), one sibling identified as lower-assurance, and a cross-read of the privileged sibling's private data demonstrated (D03-067). |
| `QUERY_ALL_PACKAGES` declared | On `targetSdk < 30` package enumeration was free anyway; on ≥ 30 the permission is Play-policy-restricted, which is a policy matter, not a vulnerability. | The package list appearing in a request body to a third-party host (D03-046a), or the list feeding a targeting decision that changes security behaviour. |
| Absence of `android:intentMatchingFlags="enforceIntentFilter"` | Defence-in-depth on API 36+ only; its absence on an app that does not target 36 is meaningless. | A component that trusts intent data and is only reachable because the flag is absent, especially where a **sibling app in the same family sets it** — that sibling comparison converts it from a hardening note to a defect (D03-044). |
| Cleartext permitted / `usesCleartextTraffic="true"` | Manifest flag only. MASTG-TEST-0235's logic is precise and commonly mis-stated: it does **not** fail when the manifest sets it true but an NSC exists, even an empty one. | A captured plaintext request carrying a token or PII — and that finding belongs to D14, not here. D03's job is only to resolve the `@xml/...` reference so D14 can evaluate it. |
| `SYSTEM_ALERT_WINDOW` declared in the manifest | The overlay permission needs a Settings trip from API 23 and is Play-policy restricted, and `mobile_security_misconfiguration.tapjacking` is **P5** anyway. An app *holding* the permission is an over-request row, not a vulnerability. | The **inverse**: the app's own consent/payment/permission screens lack `filterTouchesWhenObscured` and `setHideOverlayWindows`, and a recorded overlay PoC drives one of the three surfaces Google's Mobile VRP still accepts — a permission approval, an app-installation approval, or a hidden privacy-sensor indicator (D03-061 -> D04). |
| `ACCESS_BACKGROUND_LOCATION` declared | Declaration is not collection, and on Android 10+ the user had to walk into Settings to grant "all the time". Filing the manifest line is a privacy note at best. | `dumpsys location` showing an active request while backgrounded with the screen off **plus** lat/long in the proxy (D03-063) — and, far better, the history endpoint returning a second controlled account's marker, which is a P1/P3 BOLA in D15. |
| `foregroundServiceType` declared, or a foreground service running | Every media, navigation and sync app runs one; the type declaration is mandatory from API 29. | `dumpsys media.camera` / `dumpsys audio` showing the package holding a sensor while its UI is not visible, with a transparent or sensor-less notification, and the capture leaving the device (D03-062). |
| A `backupAgent` / `restoreAnyVersion` attribute in the manifest | An attribute, exactly like `allowBackup`. `AV:P` and developer mode both apply. | A tampered archive restored on an in-scope device that flips a decision the client makes locally — entitlement, PIN lockout, API host — with the five-shot state-change set to prove it (D03-070). |
| A drozer `app.package.attacksurface` count | An inventory. Informational by construction; the corpus is explicit: do not report standalone. | Each entry driven to an observable effect from a third-party APK (D03-006). |

</details>


<details><summary>🔗 D03 cross-surface joins — park these, chase them in P7</summary>

- **Orphan custom permission (D03-008) × the provider it guards (D07).** Nobody joins the `comm -23 used.txt defined.txt` output to the provider authority list. The provider reviewer sees `android:readPermission="com.target.X"` and moves on; the permission reviewer sees an undefined string and files it as a hygiene note. Joined, it is: any installed app defines `X`, is granted it silently, and reads the provider — which, if the provider is keyed by a user id, is `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` at **P1**.
- **`resolveActivity()==null` as a gate (D03-045) × name-only caller trust (D01/D03-030) × implicit-intent hijack (D05).** Three separate "the attacker cannot be there" assumptions that all fail to the same attacker app. The app decides it is safe because nothing else resolves, trusts the caller because the package name matches a prefix, and sends an implicit intent because no competitor is installed. One PoC APK with a chosen `applicationId`, a matching `<intent-filter>` at priority 999, and no `<queries>` entry defeats all three at once. Nobody reviews package visibility and intent resolution together.
- **`sharedUserId` (D03-067) × Android Keystore (D12) × the weakest sibling's exported surface (D04–D07).** Same UID means the same Keystore namespace. The sibling review and the crypto review never meet: the crypto reviewer proves keys are hardware-backed and non-exportable, and the sibling reviewer proves two packages share a UID, and neither states the consequence — that a bug in the low-assurance sibling *uses* the strong sibling's keys through the shared Keystore without ever extracting them.
- **Dangerous-permission inventory (D03-031) × exported component sinks (D04–D07) × the backend (D15).** Permission lists and IPC lists are produced by different passes and stapled together in the report. The join is the confused deputy: the app holds `READ_CONTACTS`/`ACCESS_FINE_LOCATION`/`INTERNET`, an exported component performs the gated action with attacker extras, and the resulting request reaches the backend **with the victim's session attached** — so the same primitive that leaks local data is also an authenticated request generator against D15.
- **Manifest-declared backend hosts (D03-074) × API versioning (D15).** The manifest, `strings.xml` and framework `<meta-data>` are read for secrets, then discarded. They are actually a version inventory: the hardcoded endpoints in a mobile build are routinely an older API generation than the live web client uses, and the four behavioural diffs (auth strength, throttling, validation, field exposure) on that older generation are where a P1 lives. Nobody diffs the mobile-derived host list against the web app's.
- **`<grant-uri-permission pathPrefix="/">` (D03-036) × intent redirection (D08) × FileProvider (D07).** The manifest reviewer records the over-broad grant scope as a hygiene note; the intent reviewer finds a redirect primitive and rates it on "an attacker can make the app start an activity". Joined, the redirect carries a grant flag and the over-broad scope turns one granted URI into arbitrary read across the whole authority.
- **`appop`-gated defensive controls (D03-047) × overlay/tapjacking (D04/D21).** The overlay reviewer tests whether an overlay can be drawn over the target; the permission reviewer records that the app's anti-overlay warning depends on `SYSTEM_ALERT_WINDOW`. The join is that setting the target's own op to `ignore` silently disables its defence with no exception and no user-visible error — so the tapjacking PoC that "failed" on a clean device succeeds on one where the op was flipped.
- **`android:process` global name (D03-038) × `sharedUserId` (D03-067) × native libraries (D16).** Individually: a shared process, a shared UID, a native parser. Together: attacker code from a same-key sibling executing in the target's address space alongside a memory-unsafe parser, which is the OEM-app shape that produces platform-level findings.
- **Account-type squatting (D03-043) × `FLAG_SECURE` and overlay hardening (D04).** The UI-redress reviewer verifies `FLAG_SECURE` and `filterTouchesWhenObscured` and declares the login screen hardened. Neither control touches an authenticator activity rendered *inside the victim's own task* by a squatted account type — the phishing surface survives every overlay defence the app has.
- **Default-SMS role / call forwarding (D03-058, D03-059) × the OTP delivery channel (D13) × the backend's factor list (D15).** The permission reviewer notes `SMS_DELIVER` and `CALL_PHONE`; the auth reviewer tests the OTP's length, lifetime and rate limit. Neither asks the joined question: if the app can *read and delete* the SMS, or silently set `**21*` forwarding, then the second factor is not a second factor for anyone who can drive that component — and the backend still treats the account as MFA-protected. That is a `two_fa_bypass` (P3) or, where the voice/SMS factor is the whole of step-up, an `authentication_bypass` (P1).
- **Held-versus-requested (D03-054) × every impact sentence in the report (D27).** The single most common downgrade in this domain is an impact claim resting on a permission the app does not hold on the tested device — `WRITE_EXTERNAL_STORAGE` above API 29, a `maxSdkVersion`-capped declaration, a runtime permission the user never granted. Nobody joins the manifest pass to the `dumpsys` grant record before writing the sentence, and the triager does it for you, at your expense.
- **Backup restore (D03-070) × the app lock / in-app PIN (D13) × client-side entitlement (D23).** The storage reviewer reads the backup for secrets and finds none, because the app stores its token in the Keystore. The restore direction is never tested — and the failed-PIN counter, the "biometric enrolled" boolean and the cached entitlement all live in the plain preference file that *is* in the archive. One edited XML file converts a P5 backup flag into an app-lock bypass.

</details>


---

## D04 Exported Activities, Task & UI-Redress Attacks

**Phase P5 · `M5` · 72 items** — 🟥 4 critical · 🟧 24 high · 🟨 23 medium · 🟩 6 low · ⬜ 15 support  

📄 Full detail, with every command and proof: [`checklist/D04-exported-activities-and-task.md`](checklist/D04-exported-activities-and-task.md)

> **Crux question.** **Is there any screen in this app whose security depends on the user having arrived from the previous screen — and can I start it directly, from a package that holds no permissions, with the arguments of my choice?**

It pays through exactly one door. An exported activity that renders the logged-in user's address book, or
that takes `userId` from an extra and asks the backend for that user's record, converts straight out of the
P5 mobile branch into `broken_authentication_and_session_management.authentication_bypass` (P1) or
`broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1). The MASTG's
own worked example — `am start -n com.mwr.example.sieve/.PWList` walking past a password manager's login
form — is thirteen years old and still the single highest-frequency shape in the disclosed corpus. Google's
own rule is the calibration: "It is not a vulnerability if an app exports an activity … **unless it can be
used to gain unauthorized access to application data or functionality**." The export is never the finding.
The data behind it is.


**⬜ Support ceiling**

- [ ] **`D04-001`** Build the exported-activity register from the installed package, not the source manifest  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 · Enumerate every `<activity>` and `<activity-alias>` with its `exported`, `permission`, `taskAffinity`, `launch…</sub>
- [ ] **`D04-002`** Resolve the real export default per component type and targetSdk before calling anything "not exported"  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · For `<activity>`, `<activity-alias>`, `<service>` and `<receiver>` the default is `"false"` with no intent fil…</sub>

**🟧 High ceiling**

- [ ] **`D04-003`** `<activity-alias>` re-exporting an activity that is itself `exported="false"`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · "With the exception of `targetActivity`, `<activity-alias>` attributes are a subset of `<activity>` attributes…</sub>

**⬜ Support ceiling**

- [ ] **`D04-004`** Fire every exported activity from an unprivileged UID and read `topResumedActivity`, not the exit code  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Manifest reachability is a claim. Launching from the `shell` UID, which holds no app permissions, is the first…</sub>
- [ ] **`D04-005`** Re-prove every candidate from a zero-permission attacker APK — an adb-only proof does not establish AM-03  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `adb shell am start` runs as `shell` (uid 2000), which holds `android.permission.*` grants no third-party app …</sub>

**🟨 Medium ceiling**

- [ ] **`D04-006`** `android:intentMatchingFlags` absent, or a per-component `none` hole punched in the app's own hardening  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 16 adds `android:intentMatchingFlags`, settable on `<application>`, `<activity>`, `<activity-alias>`, …</sub>

**🟥 Critical ceiling**

- [ ] **`D04-007`** Post-authentication activity renders account data with no session check  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · The canonical shape. Identify the activities that render authenticated content — account list, balance, order …</sub>

**🟨 Medium ceiling**

- [ ] **`D04-008`** In-app lock / PIN / biometric gate bypassed by starting an inner activity  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 where the inner activity is  · An app lock is almost always one check in a base `Activity.onResume()`. Any re-entry path that lands *below* t…</sub>

**⬜ Support ceiling**

- [ ] **`D04-009`** Do not claim an auth bypass from a rendered screen — prove the layer you actually passed  
   <sub>`governs `broken_authentication_and_session_management.authentication_bypass` (` · n/a — kill gate · An exported activity that renders is evidence that the *client* gate was skipped, nothing more. When you then …</sub>

**🟥 Critical ceiling**

- [ ] **`D04-010`** Attacker-chosen extras name an identity, a role or an amount that the backend honours  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-03 · Find the extras each exported activity reads, then supply values that name somebody else's object, a privilege…</sub>

**🟧 High ceiling**

- [ ] **`D04-011`** Exported activity writes attacker data straight into persistent identity state  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the permanent` · AM-03; AM-02 where the same activi · Some exported activities do not navigate, they **persist**. The pattern is `getIntent().getData()` -> `getQuer…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-012`** Exported activity commits a server-side state change for the logged-in user  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A "boring" share target is still a finding when it mutates server-side user state on behalf of an unauthentica…</sub>

**🟧 High ceiling**

- [ ] **`D04-013`** Debug, developer or internal tooling activity left exported in a release build  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_da` · AM-03 · Analytics event viewers, feature-flag toggles, environment switchers and framework dev menus. The severity is …</sub>
- [ ] **`D04-014`** Fragment injection — an exported activity instantiates a class named in an extra  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `PreferenceActivity` instantiates by reflection whatever class name arrives in `:android:show_fragment`. If th…</sub>

**🟥 Critical ceiling**

- [ ] **`D04-015`** Exported activity loads an attacker-supplied URL into a WebView  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03; AM-02 where the same activi · The single highest-yield exported-activity shape in the disclosed corpus. An activity reads a string extra and…</sub>

**🟧 High ceiling**

- [ ] **`D04-016`** Exported activity loads an attacker-supplied HTML **body** into a WebView  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Worse than a URL extra, because the host check is skipped entirely — your markup executes on the origin the ap…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-017`** Extra re-launched as an external `ACTION_VIEW` — phishing navigation under the app's identity  
   <sub>``server_side_injection.content_spoofing.external_authentication_injection` (P4` · AM-03 · Distinct from D04-015: here the app launches an *external* navigation the attacker chose, so the phishing page…</sub>

**🟧 High ceiling**

- [ ] **`D04-018`** Flutter `route` / `dart_entrypoint` / `cached_engine_id` extras on an exported `FlutterActivity`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · `FlutterActivityLaunchConfigs.getInitialRoute()` checks `intent.hasExtra("route")` **first**, before manifest …</sub>

**🟨 Medium ceiling**

- [ ] **`D04-019`** Exported start activity destroys the authenticated session  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `application_` · AM-03 · A `singleInstance` start activity fired externally re-runs its startup navigation and tears down the authentic…</sub>

**🟧 High ceiling**

- [ ] **`D04-020`** Exported share/receive activity consumes a caller-supplied `EXTRA_STREAM` — and the `/data/user/0/` path-check bypass  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_da` · AM-03 · Share-target activities take `EXTRA_STREAM` and copy the referenced file somewhere less protected — the user's…</sub>
- [ ] **`D04-021`** `android:requireContentUriPermissionFromCaller` absent on an activity that opens a caller-supplied `content://` URI  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 15 added a manifest-level enforcement that the **caller** must already hold permission on any content …</sub>
- [ ] **`D04-022`** Exported activity returns sensitive data to its caller through `setResult`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · An exported, unprotected activity that calls `setResult(RESULT_OK, intent)` with extras hands those extras to …</sub>

**🟥 Critical ceiling**

- [ ] **`D04-023`** Full-intent echo — `setResult(RESULT_OK, getIntent())` launders URI grants  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); rate on the p` · AM-03 · A one-line pattern with disproportionate impact. The activity hands you back an Intent whose grant flags the f…</sub>

**🟧 High ceiling**

- [ ] **`D04-024`** Activity result spoofing — the app trusts whatever an implicit responder returns  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); rate on the s` · AM-03 · The inverse direction of D04-022: the *victim* fires an implicit `ACTION_PICK` / `ACTION_GET_CONTENT` / `ACTIO…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-025`** `FLAG_ACTIVITY_FORWARD_RESULT` — the result is delivered to a recipient you chose  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `FLAG_ACTIVITY_FORWARD_RESULT` makes the new activity return its result to the *original* requester rather tha…</sub>

**🟧 High ceiling**

- [ ] **`D04-026`** `getCallingActivity()` / `getCallingPackage()` used as an authentication signal  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · Treating a non-null `getCallingActivity()` as proof of a trusted caller. It is populated only for `startActivi…</sub>
- [ ] **`D04-027`** `checkCallingPermission()` called as if it threw — the return value is discarded  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · `checkCallingPermission()` and `checkCallingOrSelfPermission()` return an `int` (`PackageManager.PERMISSION_GR…</sub>
- [ ] **`D04-028`** `singleTask` / `singleTop` re-delivery — `onNewIntent` re-drives an already-authenticated screen  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-03 · `singleTask` reuses the existing instance and destroys everything above it, delivering the new intent to `onNe…</sub>
- [ ] **`D04-029`** Caller validated in `onCreate` but not in `onNewIntent` (`ComponentCaller`, API 35)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 15 finally gives activities a real caller identity. The two errors that follow it are checking the cal…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-030`** `FLAG_ACTIVITY_NEW_TASK` plus matching affinity resurfaces a mid-flow authenticated task  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · With `FLAG_ACTIVITY_NEW_TASK`, an existing task with the same affinity is **brought to the foreground with its…</sub>

**⬜ Support ceiling**

- [ ] **`D04-031`** Task-manipulation flag sweep — the full `FLAG_ACTIVITY_*` grammar against every exported activity  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Run the exported set once more under each task flag. This is how you learn whether a third party can manipulat…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-032`** Task hijacking via inherited `taskAffinity` + `allowTaskReparenting` (StrandHogg v1)  
   <sub>`no dedicated path. File as `broken_access_control.exposed_sensitive_android_in` · AM-03 · Every activity inherits `taskAffinity` equal to the application package name unless the developer sets `androi…</sub>
- [ ] **`D04-033`** `launchMode="singleTask"` on the launcher activity with `targetSdk < 28` (the MobSF `task_hijacking` rule)  
   <sub>`as D04-032` · AM-03 · The specific manifest shape scanners flag, and the one clients will ask you about. With `singleTask` the activ…</sub>
- [ ] **`D04-034`** StrandHogg 2.0 — reflective task hijack that ignores `taskAffinity` (CVE-2020-0096)  
   <sub>`as D04-032` · AM-03 · A zero-permission app iterates running tasks and uses `Context.startActivities()` and hidden APIs to re-parent…</sub>
- [ ] **`D04-035`** `android:allowCrossUidActivitySwitchFromBelow` not set to `false` — the modern task-hijack opt-in was not taken  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 15 added an opt-in defence: with `android:allowCrossUidActivitySwitchFromBelow="false"` on `<applicati…</sub>
- [ ] **`D04-036`** `setAllowCrossUidActivitySwitchFromBelow(true)` called at runtime — a self-inflicted hardening opt-out  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Even when the manifest sets `false`, an individual activity can re-open itself by calling `setAllowCrossUidAct…</sub>
- [ ] **`D04-037`** `android:allowEmbedded` without `knownActivityEmbeddingCerts`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `android:allowEmbedded="true"` lets an activity be launched as an embedded child of another activity — rendere…</sub>

**⬜ Support ceiling**

- [ ] **`D04-038`** Background-Activity-Launch is the make-or-break precondition — state it or the PoC is not reproducible  
   <sub>`governs every redirected- or background-launch PoC in this chapter` · AM-03 · On API 34+ the victim app can only launch your redirected Intent **while it has a visible window** (`BAL_ALLOW…</sub>

**🟧 High ceiling**

- [ ] **`D04-039`** Non-exported activity started through a system deputy (LaunchAnyWhere)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · A privileged app — Settings, a vendor launcher, an account-authenticator host — that takes an `Intent` or `Bun…</sub>
- [ ] **`D04-040`** Bubble activity — `allowEmbedded` + `documentLaunchMode="always"` is a permission-free float-over-other-apps surface  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_acces` · AM-03 · Chat and support features that implement Android Bubbles must declare the bubble target with `allowEmbedded="t…</sub>

**🟩 Low ceiling**

- [ ] **`D04-041`** `documentLaunchMode="always"` leaves one Recents entry — and one snapshot — per document  
   <sub>``insecure_data_storage.screen_caching_enabled`` · AM-11 · `documentLaunchMode="always"` (and `FLAG_ACTIVITY_NEW_DOCUMENT`) creates a new task per document, and each tas…</sub>
- [ ] **`D04-042`** `FLAG_SECURE` set on login and forgotten on the card, OTP and transaction screens  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5); escalate through `sensiti` · AM-04 (a screen-capture-capable co · Developers set `FLAG_SECURE` on the login activity and forget the screens that actually hold the secret. Enume…</sub>
- [ ] **`D04-043`** Recover the on-disk task snapshot rather than relying on the Recents thumbnail  
   <sub>``insecure_data_storage.screen_caching_enabled`` · AM-12 for the file read itself — * · The Recents thumbnail is backed by a file. Pulling it proves the content persisted rather than being a transie…</sub>
- [ ] **`D04-044`** `clearFlags(FLAG_SECURE)` and the three surfaces `FLAG_SECURE` does not cover  
   <sub>``insecure_data_storage.screen_caching_enabled`` · AM-04 / AM-11 · Three gaps sit under a correctly-set `FLAG_SECURE`: a transition that clears it, a `SurfaceView` (video, camer…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-045`** Orientation and aspect-ratio locks ignored on large screens (targetSdk 36) unmask a field the portrait layout hid  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-11 · Apps that masked a field, truncated a PAN, or positioned a security affordance assuming fixed portrait geometr…</sub>
- [ ] **`D04-046`** Edge-to-edge enforcement (targetSdk 35/36) hides the material terms of a confirmation  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); rate on the a` · AM-01 (no attacker required — the  · At targetSdk 35 all apps are edge-to-edge by default; at 36 the opt-out is disabled entirely. Security-relevan…</sub>

**🟩 Low ceiling**

- [ ] **`D04-047`** Classic full-occlusion tapjacking — and verifying whether the platform already stops it  
   <sub>``mobile_security_misconfiguration.tapjacking` (**P5**)` · AM-04 (`SYSTEM_ALERT_WINDOW` is a  · Whether the app's security-relevant confirmation views accept a touch while another window covers them. The ap…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-048`** Partial occlusion — the variant Android 12 does not block  
   <sub>``mobile_security_misconfiguration.tapjacking` (P5) as filed; move it to the ac` · AM-04 · In partial occlusion the touch target itself stays unobscured — so `filterTouchesWhenObscured` never fires — w…</sub>

**⬜ Support ceiling**

- [ ] **`D04-049`** Prove the *trigger*, not just the overlay  
   <sub>`governs every tapjacking claim` · AM-04 · Triage closes overlay findings as theoretical because the attacker cannot know **when** the confirm button is …</sub>

**🟧 High ceiling**

- [ ] **`D04-050`** `TYPE_ACCESSIBILITY_OVERLAY` — a full-screen overlay with no "draw over other apps" prompt  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the captured-` · AM-04 (the user enables an accessi · A window of type `TYPE_ACCESSIBILITY_OVERLAY` is added **without ever triggering the "draw over other apps" di…</sub>
- [ ] **`D04-051`** TapTrap — animation-driven tapjacking that needs no overlay permission  
   <sub>``mobile_security_misconfiguration.tapjacking` (P5) as filed; the *outcome* (a ` · AM-03 — no overlay permission requ · A malicious app launches the target activity **into the same task** with a custom transition animation at roug…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-052`** The activity sandwich — launch the victim's exported activity, then overlay your own in the same task  
   <sub>``mobile_security_misconfiguration.tapjacking` (P5) as filed; rate on the actio` · AM-03 — no overlay permission · A malicious app launches an activity from the victim and then overlays it with its own activity in the same ta…</sub>

**🟩 Low ceiling**

- [ ] **`D04-053`** `Window.setHideOverlayWindows(true)` absent on the screens that authorise something  
   <sub>``mobile_security_misconfiguration.tapjacking`` · AM-04 · From API 31 an app can require that no non-system overlay coexists with its window, via `setHideOverlayWindows…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-054`** Predictive back (targetSdk 36) silently disables a security control implemented in `onBackPressed()`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); rate on what ` · AM-01 (the platform disables it) e · At targetSdk 36 the system enables predictive back by default: `onBackPressed()` is no longer called and `KEYC…</sub>
- [ ] **`D04-055`** `PRIORITY_SYSTEM_NAVIGATION_OBSERVER` used as if it blocked navigation  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); usually a bus` · AM-01 · Android 16 added an observer-only back priority that does **not** consume the event. Code that registers a "co…</sub>

**🟧 High ceiling**

- [ ] **`D04-056`** `showWhenLocked` / `turnScreenOn` activity reachable before unlock  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-10 physical locked; AM-03 where · An activity with `android:showWhenLocked="true"` (or `setShowWhenLocked(true)`) displays **over the keyguard**…</sub>
- [ ] **`D04-057`** `android:showForAllUsers` / `android:directBootAware` on an activity that renders user data  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_acces` · AM-05 another user of the same dev · Either attribute on a data-rendering component is a boundary crossing: `showForAllUsers` shows one profile's c…</sub>

**⬜ Support ceiling**

- [ ] **`D04-058`** Map the deep-link trampoline / router activity's route table before testing anything downstream  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03; AM-02 through the browser · Most modern apps funnel every external entry through one exported trampoline activity that turns a `Uri` into …</sub>

**🟨 Medium ceiling**

- [ ] **`D04-059`** Notification trampoline restriction as a locator for the arbitrary-activity-start gadget  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); inherits the ` · AM-03 / AM-08 · From targetSdk 31 an app cannot start an activity from a service or receiver used as a notification trampoline…</sub>

**⬜ Support ceiling**

- [ ] **`D04-060`** Null-intent and type-confusion fuzzing as a triage-ordering signal, not a finding  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-03 · Send null, absent and wrong-typed extras to every exported activity. An unhandled `NullPointerException` or `C…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-061`** Persistent crash loop — the only DoS shape in this domain that is payable  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-03 · A one-shot crash the user dismisses is informational. The payable version is one where the bad value is **pers…</sub>

**⬜ Support ceiling**

- [ ] **`D04-062`** Exported-component crash as a process-restart primitive  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-03 · The real value of a crash is that it **restarts the process at a moment you choose**, resetting any process-li…</sub>

**🟨 Medium ceiling**

- [ ] **`D04-063`** The app's own launcher entry can be disabled by an attacker-reachable path  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `application_` · AM-03 · Can any exported component — or the app's own logic driven by an attacker-controlled extra — reach `PackageMan…</sub>

**🟧 High ceiling**

- [ ] **`D04-064`** The activity's backend call is an older API version than the web app uses  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 / AM-06 (the API is reachabl · The highest-value bridge from this chapter into the backend. A mobile app's hardcoded backend calls are freque…</sub>

**⬜ Support ceiling**

- [ ] **`D04-065`** Evidence: the five-screenshot pattern for an exported-activity state change  
   <sub>`governs every state-changing finding in this chapter` · A state change needs pre-state, the bug, and post-state — plus the out-of-band side effect. An exported-activi…</sub>
- [ ] **`D04-066`** Chain filing: primitives first, consumer second, then backfill  
   <sub>This domain produces primitives, and a chain is a **severity amplifier, not a merge request**. One fix equals …</sub>
- [ ] **`D04-067`** The pre-severity gate — run it against the Critical *claim*, not against the bug  
   <sub>`governs every P1/P2 claim originating in this chapter` · Write the draft Critical title, then substitute the Critical claim for "the bug" in each question: 1. Have I v…</sub>

**🟧 High ceiling**

- [ ] **`D04-068`** Quick Settings `TileService` performs its action, or launches its activity, over the keyguard  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-10 physical locked · A Quick Settings tile is tappable from the shade on a **locked** device. A tile whose `onClick()` performs a p…</sub>
- [ ] **`D04-069`** A bundled library's exported activity writes to a caller-supplied `Uri` inside the host app's private storage  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on the ` · AM-03 zero-permission local app; A · The exported-activity register (D04-001) contains components the app's own developers never wrote. A library a…</sub>
- [ ] **`D04-070`** Exported engine/player activity whose extras are consumed by game or framework code  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); rises with wh` · AM-03 · Engine-hosted apps export a player activity as `MAIN`/`LAUNCHER` by construction, and the managed code behind …</sub>

**🟨 Medium ceiling**

- [ ] **`D04-071`** The widget or lock-screen surface renders the account data the in-app screen protects  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5) as filed; escalate through` · AM-10 physical locked · The app may set `FLAG_SECURE` on the balance screen and `VISIBILITY_SECRET` on its notifications and still dra…</sub>

**⬜ Support ceiling**

- [ ] **`D04-072`** False-positive discipline for the four claims this chapter makes  
   <sub>`governs every claim in this chapter` · n/a — kill gate · This domain produces four claim shapes, and each has a matching false positive that triage knows and you must …</sub>

<details><summary>⚰️ D04 graveyard — do not submit these standalone</summary>

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

</details>


<details><summary>🔗 D04 cross-surface joins — park these, chase them in P7</summary>

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

</details>


---

## D05 Broadcast Receivers & Implicit Intents

**Phase P5 · `M5` · 64 items** — 🟥 7 critical · 🟧 28 high · 🟨 8 medium · 🟩 1 low · ⬜ 20 support  

📄 Full detail, with every command and proof: [`checklist/D05-receivers-and-implicit-intents.md`](checklist/D05-receivers-and-implicit-intents.md)

> **Crux question.** Does any broadcast this app sends or receives carry, or act on, a value that decides authentication, entitlement, or where the app sends its data — and can an app that declares no permissions supply or read that value?

It pays because it is the one Android-native surface that is not pinned to P5. The entire
`mobile_security_misconfiguration` branch is Informational; `broken_access_control.exposed_sensitive_android_intent`
is the single Android-native node whose priority is `null`, which means it inherits whatever you can prove.
A `sendBroadcast` that carries a bearer token converts directly into
`sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) the moment you replay the
token against the API and show the 200. An intercepted OTP converts into
`broken_authentication_and_session_management.two_fa_bypass` (P3), or `authentication_bypass` (P1) with the
full takeover. Nothing else in the IPC block has a cleaner path out of the P5 ghetto.


**⬜ Support ceiling**

- [ ] **`D05-001`** Build the manifest receiver inventory with exported, permission and filter columns  
   <sub>`n/a — enabler for `broken_access_control.exposed_sensitive_android_intent` (nu` · AM-03 · Produce one row per receiver: class, exported state, `android:permission`, filter count, and every action stri…</sub>
- [ ] **`D05-002`** Enumerate runtime-registered receivers — the surface the manifest never shows  
   <sub>`n/a — enabler` · AM-03 · Dump the receivers the app registers at runtime, with their filter actions, their export flag and their `broad…</sub>

**🟧 High ceiling**

- [ ] **`D05-003`** `RECEIVER_EXPORTED` audit — the Android 13/14 compile fix that widened the surface  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rate on the h` · AM-03 · Find registrations that pass `RECEIVER_EXPORTED` for an action that is plainly app-private (`com.target.app.IN…</sub>
- [ ] **`D05-004`** LEGACY — context-registered receivers below targetSdk 33 are exported by omission  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · On a low-target build, treat **every** two-argument `registerReceiver(receiver, filter)` as exported and test …</sub>

**⬜ Support ceiling**

- [ ] **`D05-005`** Classify each receiver action against the protected-broadcast list  
   <sub>`n/a — enabler; prevents a false positive and a false negative simultaneously` · AM-03 · An action on the platform's protected-broadcast list can only be sent by the system, so a receiver listening o…</sub>
- [ ] **`D05-006`** Explicit-component reachability of "protected broadcast" receivers  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A receiver whose only filter is a protected broadcast — `MY_PACKAGE_REPLACED`, `BOOT_COMPLETED`, `ACTION_SHUTD…</sub>
- [ ] **`D05-007`** `setPackage(victim)` defeats the Android 8 manifest implicit-broadcast restriction  
   <sub>`n/a — enabler; kills the single most common false negative in this domain` · AM-03 · Community checklists read the Android 8 restriction as "manifest receivers are safe now". They are not. An att…</sub>
- [ ] **`D05-008`** The stopped-package false negative — your broadcast never reached a freshly installed app  
   <sub>`n/a — enabler` · AM-03 · Half of all "the receiver did not fire, so it is safe" conclusions are this. Establish the positive control be…</sub>
- [ ] **`D05-009`** The `result=0` trap — a completed broadcast is not a handled broadcast  
   <sub>`n/a — enabler; the domain's equivalent of the layer-ordering trap` · AM-03 · `am broadcast` prints `Broadcast completed: result=0` whether or not any receiver matched, and whether or not …</sub>
- [ ] **`D05-010`** Marker discipline for broadcast-driven side effects  
   <sub>`n/a — enabler` · AM-03 · An app that polls, syncs on connectivity, or refreshes on resume will produce network requests and preference …</sub>
- [ ] **`D05-011`** `adb shell` is not AM-03 — re-prove every receiver finding from a zero-permission APK  
   <sub>`n/a — enabler; decides whether the report is credible` · AM-03 · Discovery with `am broadcast` is fine. A finding proved only by adb has not established AM-03 and a good triag…</sub>

**🟧 High ceiling**

- [ ] **`D05-012`** Enumerate and replay every extra key `onReceive` actually reads  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The receiver's real API is the set of extra keys its handler consumes. Read `onReceive` in jadx, list every `g…</sub>

**🟥 Critical ceiling**

- [ ] **`D05-013`** Receiver extras piped into a permission-holding API — permission re-delegation  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269) and `broken_acces` · AM-03 · The classic. An exported receiver takes caller-supplied extras and calls an API the **app** holds the permissi…</sub>
- [ ] **`D05-014`** Receiver that repoints the backend base URL, environment or a security feature flag  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); chain to `sen` · AM-03 · Does any receiver write a base URL, an environment name, a certificate-pinning toggle or a "debug" flag into `…</sub>

**🟧 High ceiling**

- [ ] **`D05-015`** Receiver that flips entitlement, subscription or premium state  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); if the entitl` · AM-03 · Broadcast the app's own entitlement-change signal with a premium payload and see whether the client unlocks. T…</sub>
- [ ] **`D05-016`** Receiver that terminates, rotates or fixates the session  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · Two different bugs hide behind "logout receiver". Clearing the session from any app is a nuisance-grade availa…</sub>
- [ ] **`D05-017`** Receiver that renders an attacker-supplied notification or in-app message  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `server_side_` · AM-03 · A receiver whose extras drive notification title, body, image URL or deep link lets any app impersonate the ve…</sub>
- [ ] **`D05-018`** Receiver guarded by a squattable or non-signature custom permission  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269) plus `broken_acce` · AM-03 · Resolve every `android:permission` on a receiver to its **declared protection level on the device**, not to th…</sub>
- [ ] **`D05-019`** Broadcast sent with a `receiverPermission` that is not signature level  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The subtle sibling of D05-030. The developer *did* pass a receiver permission to `sendBroadcast(intent, permis…</sub>
- [ ] **`D05-020`** Receiver makes a trust decision with no caller identity at all  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null), CWE-925` · AM-03 · Find receivers that branch on something they treat as proof of sender identity — a `"sender"`/`"from_package"`…</sub>
- [ ] **`D05-021`** Weak receiver challenge-response seeded from wall-clock time  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · Where a receiver expects a `VERIFY_*` / `AUTH_*` token returned on a second broadcast within a 30-60 second wi…</sub>
- [ ] **`D05-022`** AppWidgetProvider receiver custom actions — exported by construction  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Widget providers routinely cache a session token to render "logged-in" content and expose custom refresh/actio…</sub>
- [ ] **`D05-023`** `DownloadManager` completion receivers that trust `EXTRA_DOWNLOAD_ID`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `server_side_` · AM-03 · Apps that use `DownloadManager` register for `ACTION_DOWNLOAD_COMPLETE` and then act on the completed file — i…</sub>
- [ ] **`D05-024`** Boot / package-replaced receiver that reads configuration from a writable location  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); chain to `sen` · AM-03 / AM-04 (storage) · Auto-start paths run before any user is present, which is exactly when nobody is watching. Does the boot/`MY_P…</sub>
- [ ] **`D05-025`** FCM / c2dm push receiver reachable locally  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Push payloads routinely drive deep-link navigation, WebView loads, silent sync or config changes. If the legac…</sub>
- [ ] **`D05-026`** Receiver that hands attacker input to a deferred `WorkManager` / `JobScheduler` / `AlarmManager` job  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Deferred execution hides the trigger from both the tester and the user: the broadcast lands now, the privilege…</sub>
- [ ] **`D05-027`** Reading any single extra deserialises the whole Bundle  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `server_side_` · AM-03 · A component that never references your malicious key still instantiates your `Serializable`/`Parcelable` gadge…</sub>
- [ ] **`D05-028`** Receiver that forwards a nested Intent — the redirection sink discovered in D05  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269) / `broken_access_` · AM-03 · Receivers are the most commonly forgotten intent-redirection sink. Any `onReceive` that pulls a `Parcelable` I…</sub>

**🟥 Critical ceiling**

- [ ] **`D05-029`** Receiver that copies files from caller-supplied URIs (the Play Core / SmartSwitch shape)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `server_side_` · AM-03 · A receiver that copies content from URIs supplied in an extra into the app's own data directory, with the dest…</sub>
- [ ] **`D05-030`** Implicit broadcast carrying a session token, OTP or credential  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · The flagship item of the domain. `sendBroadcast(new Intent("com.target.app.TOKEN_REFRESHED") .putExtra("token"…</sub>
- [ ] **`D05-031`** The whole-API-response broadcast  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-03 · A specific, high-value instance of D05-030: the app's network layer broadcasts a request-complete event carryi…</sub>

**🟩 Low ceiling**

- [ ] **`D05-032`** Location, file-event and upload broadcasts — the permission-bypass framing  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null, CW` · AM-03 · Same primitive as D05-030 with a lower-value payload, and it still pays — but only when framed as a **permissi…</sub>

**⬜ Support ceiling**

- [ ] **`D05-033`** `LocalBroadcastManager` removal regression  
   <sub>`n/a — enabler; the finding it surfaces is D05-030` · AM-03 · `LocalBroadcastManager` in the codebase means the developer *knew* that traffic was internal. The bug is what …</sub>

**🟨 Medium ceiling**

- [ ] **`D05-034`** Sticky broadcast read — `registerReceiver(null, filter)` (LEGACY)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A sticky broadcast persists **with its extras** in `ActivityManager` and is delivered to any app that register…</sub>
- [ ] **`D05-035`** Sticky broadcast overwrite, and `setPackage()` being ignored on re-broadcast (LEGACY)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Three documented defects, of which only the first is commonly tested. The second and third make this a **tampe…</sub>

**⬜ Support ceiling**

- [ ] **`D05-036`** Ordered-broadcast priority interception — and the Android 16 per-process narrowing  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · Nine community sources teach "register a receiver with a higher `android:priority` to intercept, modify or abo…</sub>

**🟨 Medium ceiling**

- [ ] **`D05-037`** `abortBroadcast()` suppression of a security-relevant flow  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); to be paid as` · AM-03 · Suppressing a fraud alert, a security notification, a session-expiry signal or a remote-wipe trigger is a targ…</sub>

**🟧 High ceiling**

- [ ] **`D05-038`** `setResultData` / `setResultExtras` tampering  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · Ordered broadcasts deliver one receiver at a time, and each may rewrite the payload the next receiver sees. A …</sub>
- [ ] **`D05-039`** The app trusts `getResultData()` — sender-side ordered-result trust, broken on Android 16  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The mirror of D05-036, and almost nobody covers it. An app that sends an ordered broadcast and trusts `getResu…</sub>

**⬜ Support ceiling**

- [ ] **`D05-040`** Implicit-intent sender inventory  
   <sub>`n/a — enabler for D05-041 to D05-049` · AM-03 · Systematically list every implicit dispatch in the app, with the extras each carries. Each one is interceptabl…</sub>

**🟥 Critical ceiling**

- [ ] **`D05-041`** Implicit intent carrying sensitive extras to an unconstrained recipient  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · The activity/service counterpart of D05-030. An Intent with an action but no `setPackage`/`setClass`/`setCompo…</sub>

**🟧 High ceiling**

- [ ] **`D05-042`** Implicit intent used for internal app communication — hijack by matching filter  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null, CWE-927)` · AM-03 · Distinct from D05-041: here the payload may be harmless but the **delivery** is hijackable. The app uses an ac…</sub>
- [ ] **`D05-043`** `android:priority="999"` chooser win plus silent forward-on  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null, CWE-927)` · AM-03 · Winning the resolution is half the technique; the other half is making the user see nothing wrong. Capture the…</sub>

**🟨 Medium ceiling**

- [ ] **`D05-044`** `queryIntentActivities` / `resolveActivity` ordering trusted as a gate  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A common "defence" is `if (intent.resolveActivity(pm) != null) startActivity(intent)`, or `queryIntentActiviti…</sub>
- [ ] **`D05-045`** Implicit `startService` / `bindService`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); if the reache` · AM-03 · An implicit `startService` is strictly worse than an implicit `startActivity` because there is no chooser and …</sub>
- [ ] **`D05-046`** Poisoned result from a hijacked `ACTION_GET_CONTENT` / `ACTION_PICK`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); with an arbit` · AM-03 (plus one user tap on your a · When the victim launches `ACTION_PICK`, `ACTION_GET_CONTENT` or `ACTION_IMAGE_CAPTURE` and trusts the returned…</sub>

**🟧 High ceiling**

- [ ] **`D05-047`** Responder-controlled `DISPLAY_NAME` and `ClipData` — path traversal in the consumer  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the chain tar` · AM-03 + one user tap · The responder app fully controls `Intent.getData()`, `ClipData`, the extras, **and** the provider metadata the…</sub>
- [ ] **`D05-048`** targetSdk 34 implicit-intent restriction — and the `exported="true"` fix that replaced it  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — rate on the ` · AM-03 · The behaviour change broke apps that used implicit intents to reach their own internal components. Two fixes w…</sub>
- [ ] **`D05-049`** Android 14 did not fix implicit *sending* — the half the checklists get wrong  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); P1 via the to` · AM-03 · The Android 14 change constrains delivery *to your own unexported components*. It does nothing about the app b…</sub>

**⬜ Support ceiling**

- [ ] **`D05-050`** SMS User Consent receiver registered without `SmsRetriever.SEND_PERMISSION`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · The documented registration passes `SmsRetriever.SEND_PERMISSION` so that **only Google Play services** may de…</sub>

**🟥 Critical ceiling**

- [ ] **`D05-051`** `EXTRA_CONSENT_INTENT` arbitrary-Intent-launch gadget and the self-grant exfiltration chain  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269) plus `sensitive_d` · AM-04 (the PoC needs `INTERNET` to · The highest-value single receiver class in Android. On a success status with no OTP-message extra, the receive…</sub>

**⬜ Support ceiling**

- [ ] **`D05-052`** The OTP-injection variant — trace the handshake before claiming it  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3), or `authent` · AM-03 · The same receiver shape yields two different findings. The Intent-launch variant (D05-051) is nearly always re…</sub>

**🟧 High ceiling**

- [ ] **`D05-053`** Telephony `SMS_RECEIVED` receiver fed a forged OTP body  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3); `broken_acc` · AM-03 · `android.provider.Telephony.SMS_RECEIVED` is a protected broadcast, so you cannot send it by action — but the …</sub>

**🟨 Medium ceiling**

- [ ] **`D05-054`** Restricted App Standby Bucket suppresses `BOOT_COMPLETED` — disarming a security control  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-03 / AM-11 · If the app relies on a boot receiver to re-arm a security control — device-loss tracking, MDM check-in, remote…</sub>
- [ ] **`D05-055`** Android 15 force-stop cancels every `PendingIntent` — time-based controls silently die  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-11 (the user or anyone with the · Apps that treat an outstanding `PendingIntent` as a durable capability — a scheduled session expiry, a wipe-on…</sub>

**🟧 High ceiling**

- [ ] **`D05-056`** Bluetooth `ACTION_KEY_MISSING` / `ACTION_ENCRYPTION_CHANGE` unhandled  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-06 (proximity) · An app pairing with a companion device that matters — a smart lock, a medical device, a payment dongle — and i…</sub>
- [ ] **`D05-057`** `CONNECTIVITY_ACTION` and Wi-Fi broadcast stale assumptions that fail open  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); chain to the ` · AM-06 · Apps that made a trust decision from these broadcasts — "we are on the corporate SSID, relax pinning", "we are…</sub>

**⬜ Support ceiling**

- [ ] **`D05-058`** `intent://` in a WebView — the vector that upgrades every receiver primitive to one click  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — rated on the` · AM-02 (remote, one click) — this i · Decide the attacker model **before** you write the severity paragraph. Every finding in this chapter is AM-03 …</sub>

**🟧 High ceiling**

- [ ] **`D05-059`** `directBootAware="true"` receiver that runs before the device is ever unlocked  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); chain to `sen` · AM-03 (an attacker app can declare · A direct-boot-aware receiver executes in a state the rest of the app never designs for: no user has authentica…</sub>

**⬜ Support ceiling**

- [ ] **`D05-060`** Turn the broadcast-harvested route inventory into a shadow-API version diff  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 (once it is the backend, no  · The broadcast bus is a free route inventory: a request-complete broadcast carries the URL, the method and ofte…</sub>
- [ ] **`D05-061`** Prove delivery-order and spray wins statistically, never from one lucky run  
   <sub>`n/a — enabler; governs D05-036, D05-037, D05-038, D05-042, D05-043, D05-046 an` · AM-03 · Delivery order, resolver ordering and the background-activity-launch spray are all **races**. One success is a…</sub>
- [ ] **`D05-062`** Run the pre-severity gate against the Critical claim, not against the receiver  
   <sub>`n/a — governs every Critical/High filing in this domain` · Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each question. (1)…</sub>
- [ ] **`D05-063`** The five-screenshot pattern for a receiver state-change finding  
   <sub>`n/a — evidence standard` · A state change needs a pre-state, the bug, and a post-state — plus the out-of-band side effect. For a receiver…</sub>
- [ ] **`D05-064`** Chain-filing order for receiver primitives  
   <sub>`n/a — filing strategy` · A chain is a **severity amplifier, not a merge request.** File the primitives first so their ids exist, then t…</sub>

<details><summary>⚰️ D05 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `am broadcast` with a malformed extra crashes the app | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**. Grab, Spotify, Xiaomi, Reddit and TikTok all exclude crash-only Intent reports; Google's invalid-reports list: "Triggering a local temporary Denial of Service ... resolved by removing the app and rebooting" is ineligible. | The crash survives reinstall and reboot (persistent DoS), or the malformed input reaches a memory-safety sink you can steer (→ D16), or the same parser is remotely triggerable. Then file `application_level_denial_of_service_dos.critical_impact_and_or_easy_difficulty` (P2) or the RCE path. |
| "Receiver X is `exported="true"`" with no sink read | An exported component is a **primitive, not a finding**. The VRT node is priority-null; with nothing demonstrated it rates nothing. | Read `onReceive` to its sink and show a state change, a data disclosure, or a forwarded Intent. The inventory row becomes a finding only when paired with an effect. |
| `sendStickyBroadcast` found in a bundled library, never called on the tested platform | Deprecated at API 21; `BROADCAST_STICKY` is no longer grantable to normal third-party apps. A grep hit in dead code is not reachability. | The call executes on the tested platform and `registerReceiver(null, filter)` returns the extras — or the target is an OEM/preinstalled/low-`minSdk` app where it still works. |
| Effect reproduced only from `adb shell` | `shell` (uid 2000) holds far more than any installable app. The finding has not established AM-03 and a triager will say so. | Reproduce from a zero-permission APK and ship its installed `requested permissions` block. |
| `Broadcast completed: result=0` with no observed side effect | `am broadcast` prints `result=0` when nothing matched at all. It is the domain's layer-ordering trap. | A pid-scoped logcat line, a prefs byte diff, a `dumpsys` delta or a marker-bearing network request, with a junk-action negative control showing the identical `result=0`. |
| `android:priority` above 100 in the target's own manifest (MobSF `high_intent_priority_found`) | A red flag for the *target*, not an attack against it. In your PoC it is the technique, not the bug. | The high priority lets the target pre-empt another app's ordered broadcast in a way that hides security-relevant content from the user — and it still works on the tested API level. |
| `LocalBroadcastManager` present and deprecated | Deprecation is not a vulnerability; `LocalBroadcastManager` is the *safe* option here. | The migration away from it converted an internal message into a global `sendBroadcast` carrying the same extras (D05-033). |
| A `BOOT_COMPLETED` receiver exists | `RECEIVE_BOOT_COMPLETED` is a normal permission and auto-start is ordinary behaviour. | The boot path reads attacker-writable configuration (D05-024), or the receiver is reachable explicitly and does privileged work (D05-006). |
| Ordered-broadcast interception demonstrated only on an API 36+ device | On Android 16 cross-process `android:priority` ordering is not guaranteed and priorities are clamped. The PoC will not reproduce for the triager. | Demonstrate on API <= 35 and version-gate the report ("affects the installed base below Android 16"), or switch to the sender-side result-trust variant (D05-039) which is *created* by the same change. |
| Implicit broadcast intercepted, extras contain only non-sensitive state | The payout tracks the payload. Twitter #185862 paid $560 and Nextcloud #167481 paid nothing; Shopify #56002's `access_token` is what made that class matter. | Extras carry a session token, OTP, credential or precise location — then lead with the replayed 200, not with the architecture. |
| OTP auto-read receiver is exported but drops the broadcast without a live handshake identifier | A verified true negative: no forged code reaches the auth flow, and the backend verifies independently. | The handshake identifier is guessable, absent, or not checked — and a forged code produces a successful server-side `verify`. |
| Download-completion receiver acts on `extra_download_id` but `DownloadManager.query` is UID-scoped | The victim's query for your id returns an empty cursor, so no cross-app injection occurs. Record the empty cursor. | The handler resolves the id through a path that is not UID-scoped, or it accepts a `content://`/`file://` URI directly from the extras. |
| A `Parcelable` extra crashes the receiver, with no gadget identified | Reachable deserialisation without a proven gadget is a primitive, and a crash alone is the P5 node. | A gadget class in the app's own dependency set is constructed in the victim's process (Frida `[REACHED]`), or the deserialisation reaches a file or code sink (→ D17). |
| Receiver clears the session ("logout from any app") | Nuisance-grade availability; the user simply logs back in. | The receiver **sets** session state from an extra — that is fixation, and the victim then operates inside the attacker's account (D05-016). |
| Interception, resolver win or consent-Intent spray demonstrated in a single run | A race proved once is an anecdote; the triager who fails to reproduce closes it. Scheduler jitter alone produces single-shot outliers. | n >= 10 interleaved trials with the win count, the failure mode named, and the device API level recorded (D05-061). |
| The mobile client calls `/api/v1` while the web app calls `/api/v3` | **A version difference alone is Informational.** Old-but-identical is operational debt, not a vulnerability. | A behavioural delta on the old path for the same operation and the same account — weaker auth, a missing 429, weaker input validation, or fields the current version redacts — shown as a body diff, not a status-code diff (D05-060). |
| An unauthenticated call to a harvested route returns `400 "field X is required"` | That is the layer-ordering trap: many stacks run the body parser or sanitiser in front of the auth middleware, so a validation error proves nothing about auth. | Re-test with a minimal well-formed `{}` body; only a response that performs the operation (or leaks its data) without a token is an auth bypass. |
| A component declares `android:directBootAware="true"` | The attribute alone is ordinary for boot, messaging and MDM paths; the default is `false`, so its presence is a decision, not yet a defect. | The pre-unlock handler fails open with credential-encrypted state unreadable, or a token/key is written through `createDeviceProtectedStorageContext()` and read back from `/data/user_de/0/<pkg>` before the PIN (D05-059). |
| OAuth `client_secret` recovered from the app and seen in a broadcast extra | A mobile client secret is public by design and is on every program's never-submit list. | The reportable adjacent finding is **PKCE non-enforcement** on the public client (→ D13), not the secret's presence. |

</details>


<details><summary>🔗 D05 cross-surface joins — park these, chase them in P7</summary>

- **D05 SMS User Consent receiver × D07 FileProvider root breadth × D08 URI grants.** Nobody reviews
  `provider_paths.xml` next to the receiver registration list. Individually each is Medium at best: an
  unguarded receiver with nothing to steal, and a wide provider root nothing can reach. Joined, the victim
  starts your Intent with `FLAG_GRANT_READ_URI_PERMISSION` aimed at a `content://` URI under its own
  `files/` root and self-grants a zero-permission app read access to its session store. The join is the
  Critical; file the three parts per D05-064.
- **D05 implicit broadcast of API responses × D15 shadow API.** The action strings and payloads you sniff
  in D05-031 hand you the mobile client's full endpoint inventory for free — and a mobile app's hardcoded
  backend calls are frequently an **older API version** than the current web app uses, with weaker auth,
  weaker rate limits, weaker input validation and more field exposure. Diff the two versions
  **behaviourally** for the same operation (does v1 accept no token, an expired token, or a lower-privilege
  token that v2 rejects? does v1 return internal ids the current version redacts?). A version difference
  alone is Informational; the weakened control is the finding.
- **D05 receiver-driven config repoint × D14 network security config and pinning.** A receiver that writes
  the base URL (D05-014) is rated Medium by most testers as "local state change". Joined with the network
  chapter it is a full MitM with **no CA installed and no proxy configured** — every later authenticated
  request goes to your host. The join also often disables pinning as a side effect, because pinning
  configurations are host-scoped and your host is not in them.
- **D05 AppWidgetProvider receiver × D08 PendingIntent template and `fillInIntent`.** Widget code lives
  outside the main app module and is rarely reviewed. The provider receiver **must** be exported, and
  collection widgets supply one template `PendingIntent` plus a per-item `fillInIntent` whose data
  frequently originates from server content. An under-specified template lets the fill-in choose the launch
  component, from the app's UID.
- **D05 ordered-broadcast interception × D13 OTP pipeline × D24 push.** On API <= 35, intercept the ordered
  broadcast carrying the code, `abortBroadcast()` the fraud alert that would have warned the user, and
  replay the code — three surfaces owned by three different reviewers, and the chain is a 2FA bypass with a
  suppressed alarm.
- **D05 boot receiver × D22 auto-backup and restore.** The boot handler runs before any user is present and
  reads configuration that a restore can control. Backup rules that include a preferences file the boot path
  trusts turn a restore into pre-authentication config injection — the two are never reviewed in the same
  session because one is "storage" and the other is "components".
- **D05 receiver registration lifetime × D04 activity lifecycle.** The single most common false negative in
  this chapter. Runtime receivers exist only while a particular screen is foreground — the SMS-consent
  receiver lives exactly as long as the OTP screen. A component sweep run from the launcher screen
  enumerates none of them and produces a clean, wrong, ruled-out register. Drive the app into each
  authenticated state and re-run `dumpsys activity broadcasts` in every one.
- **D05 implicit `ACTION_GET_CONTENT` result × D16/D17 the import parser.** The hijacked result (D05-046,
  D05-047) is usually filed as a disclosure. Joined with the consumer, the attacker-chosen URI and
  display name feed a native parser or land a file in a directory the app later loads from — which is the
  path from a Medium to the RCE band.
- **D05 receiver-forged notification × D09 deep link × D10 WebView.** A receiver that renders
  attacker-supplied notification content (D05-017) usually also carries a deep-link extra for the tap
  target. The notification supplies the credibility (it is inside the trusted app), the deep link supplies
  the routing, and the WebView supplies the session — none of the three reviewers sees the other two.
- **D05 `intent://` from a WebView × every local receiver primitive.** A WebView that calls
  `Intent.parseUri(url, 0)` in `shouldOverrideUrlLoading` turns any attacker page into a remote broadcast
  launcher: `intent://…#Intent;scheme=app;package=com.target.app;end`. That single D10 defect upgrades every
  AM-03 finding in this chapter to AM-02, one click, which is a whole severity band. Check for it before you
  settle on the attacker model.

</details>


---

## D06 Services, AIDL & Bound IPC

**Phase P5 · `M5` · 81 items** — 🟥 22 critical · 🟧 33 high · 🟨 10 medium · ⬜ 16 support  

📄 Full detail, with every command and proof: [`checklist/D06-services-aidl-bound-ipc.md`](checklist/D06-services-aidl-bound-ipc.md)

> **Crux question.** **For every method behind this app's exported binder: does it check *who* is calling — on the thread the transaction actually arrives on — or does it only validate *what* is being asked?**

Services are the least-tested exported component class, and the reason is mechanical rather than
intellectual: an activity or a receiver can be driven with one `adb shell am` line, but a bound service
needs you to recover a method table out of a `$Stub` class and write a client. Most testers enumerate
services, see `Permission: null`, write "exported service" as a P5 inventory note and move on. That is
precisely where the money sits. Oversecured's banking and fintech research names AIDL interface abuse —
"service exposes AIDL interface performing auth operations without validating calling UID/package" — as
one of its account-takeover classes, and the TikTok `IndependentProcessDownloadService.tryDownload()`
case turned exactly this shape into arbitrary code execution in the victim's UID by writing
`libuserinfo.so` into `/data/user/0/com.zhiliaoapp.musically/app_lib/`.


**⬜ Support ceiling**

- [ ] **`D06-001`** Build the service register from the MERGED manifest, not from `base.apk`  
   <sub>`n/a — coverage method` · Services contributed by AAR dependencies and by feature/config splits appear in the installed app's merged man…</sub>
- [ ] **`D06-002`** Classify every exported service by reachability and by the protection level of its guard  
   <sub>`n/a — inventory; `broken_access_control.exposed_sensitive_android_intent` (nul` · AM-03 · For each service, record three independent facts: is it start-reachable, is it bind-reachable, and what is the…</sub>

**🟧 High ceiling**

- [ ] **`D06-003`** `android:permission` on `<service>` is checked at bind/start time only, never per transaction  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-04 (holds the bind permission)  · The manifest permission is enforced by the system at `Context.startService()`, `stopService()` and `bindServic…</sub>

**⬜ Support ceiling**

- [ ] **`D06-004`** `android:process=":remote"` — instrument the right PID or you will report a false negative  
   <sub>`n/a — method` · A service in a separate process serves its binder transactions from that PID. Hooks attached to the main proce…</sub>
- [ ] **`D06-005`** Do not claim Instant-App or browser reach for a service without `android:visibleToInstantApps`  
   <sub>`n/a — precondition control` · Governs whether AM-02 can be claim · A service is reachable by an Instant App **only** when `android:visibleToInstantApps="true"`. Claiming a one-c…</sub>

**🟧 High ceiling**

- [ ] **`D06-006`** Enumerate the service classes that *cannot* be un-exported, and test what they added  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 · Several service types are bound by the framework and therefore must be exported: `AccountAuthenticator`, `Sync…</sub>

**⬜ Support ceiling**

- [ ] **`D06-007`** Recover the complete AIDL method table before touching the device  
   <sub>`n/a — method` · drozer cannot craft a parcel for an AIDL interface. You must recover the method table from the generated `$Stu…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-008`** Build the per-method check matrix — interfaces check one method and forget the rest  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · Per-method asymmetry is the norm, not the exception. Interfaces check the caller in one or two methods and for…</sub>

**⬜ Support ceiling**

- [ ] **`D06-009`** Trace the Dagger/Hilt generated wrapper to the real delegate before concluding anything  
   <sub>`n/a — method; prevents a confident false negative` · An exported `Foo_Service extends <obfuscated>` whose constructor is `super(SomeInterface.class)` is a **genera…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-010`** Hook `onTransact` at runtime to recover codes, arguments and the real calling UID  
   <sub>``broken_access_control.privilege_escalation` (null) — rated on the transaction` · AM-03 · Static recovery misses obfuscated and dynamically registered stubs. Hook the binder entry point in the *servin…</sub>

**🟧 High ceiling**

- [ ] **`D06-011`** Sweep the raw transaction space with the NPE-versus-`SecurityException` oracle  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · Call each transaction code with no or garbage arguments and read *which* exception comes back. A `NullPointerE…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-012`** Raw `IBinder.transact()` bypasses hidden-API restrictions entirely  
   <sub>``broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.` · AM-03 · Where a system-service (or app-service) method is not reachable from the SDK, call it by transaction code over…</sub>
- [ ] **`D06-013`** Audit the `dump*` / `*Proto` method family for a missing `DUMP` enforcement  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · Services expose dozens of diagnostic methods over binder, and each is a separate place the `DUMP` signature pe…</sub>

**⬜ Support ceiling**

- [ ] **`D06-014`** Start the pipe reader thread *before* the transaction on any FD-returning API  
   <sub>`n/a — prevents a false negative on a Critical` · Any dump-style API that writes to a `ParcelFileDescriptor` writes **synchronously**. If the 64 KB pipe buffer …</sub>

**🟥 Critical ceiling**

- [ ] **`D06-015`** No caller check anywhere in the `$Stub` body — the base bug of the domain  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · AIDL adds no authentication of its own. A service that reads its arguments but never calls `Binder.getCallingU…</sub>
- [ ] **`D06-016`** `Binder.getCallingUid()` evaluated off the transaction thread returns *your own* UID  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) — a ` · AM-03 · `Binder.getCallingUid()` is only meaningful while the current thread is executing an incoming transaction. Cod…</sub>

**🟧 High ceiling**

- [ ] **`D06-017`** The three ways a permission check inside a Binder method is a no-op  
   <sub>``broken_access_control.privilege_escalation` (null) — "a permission check that` · AM-03 · Three distinct failure shapes, all of which grep as "a check is present": 1. **Discarded return.** `checkCalli…</sub>
- [ ] **`D06-018`** `clearCallingIdentity()` scope creep — the confused deputy in one line  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · `clearCallingIdentity()` resets the identity of the incoming IPC on the current thread and returns a token to …</sub>
- [ ] **`D06-019`** `getCallingPackage()` / `getCallingActivity()` used inside a Service  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · Teams port the Activity-era habit into services and providers. `getCallingActivity()` returns **null** when th…</sub>
- [ ] **`D06-020`** Caller allow-list keyed on package name with no signature check  
   <sub>``broken_access_control.privilege_escalation` (null); escalates to `broken_auth` · AM-03 · The correct pattern is `Binder.getCallingUid()` inside the transaction, then `PackageManager.getPackagesForUid…</sub>
- [ ] **`D06-021`** UID→package resolution that assumes one package per UID  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 (with a shared-UID sibling)  · `getPackagesForUid()` can return **multiple** packages, and `getNameForUid()` returns a `shared:com.example.gr…</sub>
- [ ] **`D06-022`** Caller identity taken from `getCallingPid()` — the PID-reuse race  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · PID-based caller identification is racy: the caller can exit and have its PID reused before the service resolv…</sub>
- [ ] **`D06-023`** The caller check never compares the Android **user id**  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-03 inside a work profile / Priv · Everything else in this chapter binds from user 0. A work profile, Private Space or OEM-clone instance of the …</sub>
- [ ] **`D06-024`** Permission enforced only in `onBind()`, then the binder handle is relayed  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 (the relaying app holds noth · `onBind()` runs once per *service*, not once per client: a second client bound to an already-running service r…</sub>
- [ ] **`D06-025`** Session state cleaned up only in `binderDied()`  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · Servers commonly register a `DeathRecipient` to drop a client's session when the client process dies. If the s…</sub>
- [ ] **`D06-026`** The guarding permission's `protectionLevel` is not `signature`  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 (requests the permission) or · A `<service android:permission="com.target.app.BIND_SYNC">` looks protected in the register. It is only protec…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-027`** Exported service reached through `onStartCommand` — the path reviewers skip  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on the ` · AM-03 · Exported services *started* rather than bound execute `onStartCommand` with the attacker's Intent. This is rou…</sub>
- [ ] **`D06-028`** Service as a network-egress confused deputy — attacker URL, victim's credentials  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · An exported service that takes a URL or host from the caller and fetches it with the app's own HTTP client is …</sub>
- [ ] **`D06-029`** Upload-helper service with caller-chosen file **and** destination  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · Upload-helper libraries (`net.gotev.uploadservice`, WorkManager wrappers, custom sync services) are frequently…</sub>
- [ ] **`D06-030`** AIDL method that trusts a caller-supplied `savePath` / `filename` — write into `app_lib`, get RCE  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · The highest-severity shape in this domain. An unguarded AIDL method that downloads or copies to a caller-chose…</sub>

**🟨 Medium ceiling**

- [ ] **`D06-031`** Stopping a security-relevant service from an unprivileged app  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-03 · The inverse of D06-027. An exported, unguarded RASP/integrity/heartbeat/sync service can be stopped by any app…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-032`** `Messenger` service — enumerate every `what` code and every `Bundle` key  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · A `Messenger`'s real attack surface is the set of `msg.what` codes its `handleMessage` switches on, plus the `…</sub>
- [ ] **`D06-033`** `Messenger` IPC is structurally unauthenticatable with the public SDK — say so, then test it  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-03 · `Messenger` is Binder underneath, but the transaction is `send(Message)` and the framework then **posts the me…</sub>

**🟧 High ceiling**

- [ ] **`D06-034`** `msg.replyTo` trusted as the result channel — and as a binder the target now holds  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · Two consequences of `replyTo`. First, the service sends its results to a `Messenger` the *caller* supplied, so…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-035`** Exported entry point that starts a `camera` / `microphone` / `location` foreground service  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — r` · AM-03 · At targetSdk 34 each FGS type maps to a capability. If any exported component — service, receiver or activity …</sub>

**🟨 Medium ceiling**

- [ ] **`D06-036`** `specialUse` foreground service — compare the declared subtype with what the service does  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) wh` · AM-12 for the observation; the *fi · `specialUse` is the catch-all apps reach for to keep a persistent background process. The declaration must car…</sub>
- [ ] **`D06-037`** `systemExempted` FGS type claimed by an app with no qualifying role  
   <sub>``broken_access_control.privilege_escalation` (null) — background-execution res` · n/a (app-configuration finding) · `systemExempted` is reserved and permitted only under specific conditions. An ordinary app declaring it is try…</sub>
- [ ] **`D06-038`** FGS timeout budgets as a starvation attack on a security-relevant background task  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-06 / AM-09 (needs to slow the a · Two budgets, one attack. `shortService` runs ~3 minutes from `startForeground()` and ANRs on overrun even when…</sub>
- [ ] **`D06-039`** Android 15 FGS start restrictions — the fallback path is the finding  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · n/a for the restriction; the fallb · Two Android 15 changes break patterns apps depended on. An app that re-armed a protective capability at boot n…</sub>

**🟧 High ceiling**

- [ ] **`D06-040`** Background FGS launch used to acquire while-in-use permissions  
   <sub>``broken_access_control.privilege_escalation` (null) — a permission-model bypas` · AM-03 · Whether an unprivileged app can cause the target to start a foreground service **from the background** and the…</sub>

**🟨 Medium ceiling**

- [ ] **`D06-041`** Attribute every declared `foregroundServiceType` — and every service — to its owning package namespace  
   <sub>``broken_access_control.privilege_escalation` (null) — a third party holds a se` · AM-08 (malicious or compromised th · Services *and* their foreground-service types arrive by manifest merge from AARs, so the declared capability s…</sub>

**🟧 High ceiling**

- [ ] **`D06-042`** Implicit `Intent` used to start or bind a service — the attacker answers  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); Critical when` · AM-03 · The inverse direction. The victim binds or starts a service by action name; your app registers that action and…</sub>
- [ ] **`D06-043`** The app binds a peer resolved by package name, with no signature check on the connection  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The client side of D06-020. When the app binds a partner service by `setPackage("com.partner")` and trusts wha…</sub>
- [ ] **`D06-044`** `BIND_ALLOW_ACTIVITY_STARTS` handed to a third-party service  
   <sub>``broken_access_control.privilege_escalation` (null) — a delegated background a` · AM-03 (the peer) or AM-08 · Android 14 requires the *binder* to opt in with `BIND_ALLOW_ACTIVITY_STARTS` before a bound background service…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-045`** gRPC-over-binder — the `SecurityPolicy` is the caller check, not the manifest  
   <sub>``broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.` · AM-03 · A `<service android:exported="true">` with `<action android:name="grpc.io.action.BIND"/>` and **no** manifest …</sub>

**🟧 High ceiling**

- [ ] **`D06-046`** Privileged listener service declared **without** its `BIND_*` permission  
   <sub>``broken_access_control.privilege_escalation` (null) — rated on what the callba` · AM-03 · This is "validates the action but never the caller" in its purest form. A listener service is written on the a…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-047`** The app's own `AccessibilityService`, and the app's exposure to someone else's  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-04 (the user must enable the se · Two directions. (a) If the *target* ships an `AccessibilityService`, check the declaration and the bind permis…</sub>
- [ ] **`D06-048`** `NotificationListenerService` as an OTP and `PendingIntent` siphon  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3) at the VRT d` · AM-04 (the user grants notificatio · Once enabled, a listener receives `onNotificationPosted(StatusBarNotification)` for **every** app and can `get…</sub>

**🟨 Medium ceiling**

- [ ] **`D06-049`** Sensitive fields not excluded from the Autofill `AssistStructure`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 (the user enables a third-pa · An enabled `AutofillService` receives an `AssistStructure` — the full view hierarchy of the foreground app, tr…</sub>

**🟧 High ceiling**

- [ ] **`D06-050`** `TileService` action performed while the device is locked  
   <sub>``broken_access_control.bypass_of_password_confirmation.change_password` (P4) s` · AM-10 (physical access, device loc · A Quick Settings tile can be tapped on the lock screen. A tile that performs a privileged action in `onClick()…</sub>

**🟨 Medium ceiling**

- [ ] **`D06-051`** Exported `SliceProvider` whose `onBindSlice` acts on the URI  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `` · AM-03 · The documented setup exports the provider (`android:exported="true"` with `<category android:name="android.app…</sub>

**🟧 High ceiling**

- [ ] **`D06-052`** `AppWidgetProvider` accepts a forged `APPWIDGET_UPDATE` or custom action  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_da` · AM-03 · An `AppWidgetProvider` is a `BroadcastReceiver` that **must** be exported so the system can drive it. Its `onR…</sub>
- [ ] **`D06-053`** `MediaBrowserService` with no `onGetRoot` package validation  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `` · AM-03 · Any app with audio or video playback that supports Android Auto, Wear, Assistant or system media controls decl…</sub>
- [ ] **`D06-054`** `CarAppService` shipped with `ALLOW_ALL_HOSTS_VALIDATOR`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); `` · AM-03 · An Android Auto integration exposes `CarAppService` with `<action android:name="androidx.car.app.CarAppService…</sub>
- [ ] **`D06-055`** `WearableListenerService` path routing with no node or capability verification  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · The Wear Data Layer delivers `DataItem`s and messages addressed by **path** (`/sync`, `/auth`, `/logout`). The…</sub>

**🟨 Medium ceiling**

- [ ] **`D06-056`** `ChooserTargetService` — LEGACY, but still shipping in old code  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-03 when the bind permission is  · A `ChooserTargetService` returns Direct Share targets to the system chooser. Two questions: is it guarded by `…</sub>
- [ ] **`D06-057`** `androidx.startup.InitializationProvider` — the pre-authentication code path nobody wrote  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); t` · AM-08 (an SDK's initializer) for t · Every `<meta-data android:name="com.example.SomeInitializer" android:value="androidx.startup" />` names a clas…</sub>

**🟧 High ceiling**

- [ ] **`D06-058`** `JobService` missing `BIND_JOB_SERVICE`  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · `JobScheduler` requires `android:permission="android.permission.BIND_JOB_SERVICE"` on the `JobService` so that…</sub>
- [ ] **`D06-059`** WorkManager's persisted `WorkSpec` input and its injected components  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 only once the reach is prove · WorkManager persists work in an internal SQLite database that survives reboot, and its manifest contributes `a…</sub>
- [ ] **`D06-060`** `WorkManager` / `AlarmManager` job input hijack from an exported entry point  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `sensitive_da` · AM-03 · Where background work is scheduled with input data that originates from an Intent, check whether an attacker c…</sub>
- [ ] **`D06-061`** `androidx.work.multiprocess` — `RemoteWorkerService` is a bound service with a parcel boundary  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-03 · Multiprocess WorkManager exposes a bound service so one process can enqueue work in another. Two questions: is…</sub>
- [ ] **`D06-062`** `JobIntentService` entry points — LEGACY, and still the enqueue path in old builds  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · `JobIntentService.enqueueWork(context, cls, jobId, intent)` hands the service an `Intent` that `onHandleWork(I…</sub>
- [ ] **`D06-063`** A security decision implemented as a `oneway` transaction  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-03 (must be able to interpose,  · A `oneway` call returns immediately and the caller learns nothing about success. Security- relevant state chan…</sub>
- [ ] **`D06-064`** Transaction-buffer exhaustion and a fail-open `TransactionTooLargeException` catch  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-03 · The transaction buffer is a fixed ~1 MB region **shared by all in-flight transactions of a process**. An attac…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-065`** A `ParcelFileDescriptor` returned over binder is a live FD in your process  
   <sub>``server_side_injection.file_inclusion.local` (P1) for a sandbox-crossing read;` · AM-03 · A service returning a `ParcelFileDescriptor` hands the caller a kernel FD with whatever access mode it was ope…</sub>
- [ ] **`D06-066`** The app's own `Parcelable` has a `writeToParcel`/`createFromParcel` mismatch  
   <sub>``broken_access_control.privilege_escalation` (null); Critical when it turns a ` · AM-03 · It is the `Parcelable` implementation's responsibility to ensure `createFromParcel` reads the same number of b…</sub>

**⬜ Support ceiling**

- [ ] **`D06-067`** `isolatedProcess` — a real containment boundary, in both directions  
   <sub>`n/a standalone — it modifies the rating of a memory-safety finding` · `android:isolatedProcess="true"` is the correct container for parsing untrusted input (media, archives, native…</sub>
- [ ] **`D06-068`** Binder domains and vendor interfaces are not app-reachable — the false-positive gate  
   <sub>`n/a — this gate stops an over-rated report` · Apps talk on `/dev/binder` **only**. A "vulnerability" in a HIDL or vendor-AIDL HAL is an app-level finding on…</sub>

**🟧 High ceiling**

- [ ] **`D06-069`** Binder threadpool re-entrancy — check-then-act races, proved statistically  
   <sub>``broken_access_control.privilege_escalation` (null); `broken_access_control.id` · AM-03 · Incoming binder calls are dispatched on a pool of threads. Any service that validates and then acts on shared …</sub>

**🟥 Critical ceiling**

- [ ] **`D06-070`** Local socket or localhost HTTP server bound by the app without authentication  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 for localhost; **AM-06** for · Debug bridges, RN dev servers, WebView-backing local servers and SDK IPC channels all bind sockets. Any app on…</sub>

**⬜ Support ceiling**

- [ ] **`D06-071`** Shell-backed binder brokers (Shizuku-class) as an assumed-privilege path  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-04 (the user completes the pair · Whether the target app, or any app on a managed fleet, brokers privileged binder calls through an ADB/shell-ba…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-072`** Service acting as a network proxy or registering a `VpnService`  
   <sub>``broken_access_control.privilege_escalation` (null); `sensitive_data_exposure.` · AM-06 for a LAN-reachable listener · Does the app open a listening socket, relay traffic, or register a `VpnService`? Either turns the user's devic…</sub>
- [ ] **`D06-073`** Remote-support / screen-share module embedded as a service  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 / AM-02 depending on how a s · Does the app embed screen-sharing or remote-control functionality — a VNC/agent SDK, a support module that str…</sub>

**🟧 High ceiling**

- [ ] **`D06-074`** Cast / remote-playback session as an unauthenticated control and content channel  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-06 (same LAN) · Cast-enabled apps hand a receiver device a media URL and, frequently, an auth token or signed URL in `MediaInf…</sub>

**⬜ Support ceiling**

- [ ] **`D06-075`** THE LAYER-ORDERING TRAP, binder edition — an argument error does not prove you passed the caller check  
   <sub>The single highest-confidence false positive in the whole auth-bypass class. On the wire, many stacks run a bo…</sub>

**🟥 Critical ceiling**

- [ ] **`D06-076`** Shadow API — the bound service is a bridge to an older backend version  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 (against the backend) reache · A mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, …</sub>

**⬜ Support ceiling**

- [ ] **`D06-077`** Confirm the SELinux domain before claiming an escalation `untrusted_app` cannot perform  
   <sub>Before writing "the attacker then gains root" or "then reads another app's data directory", confirm the SELinu…</sub>
- [ ] **`D06-078`** Marker discipline and the body-diff rule for binder returns  
   <sub>Two failure modes specific to this domain. (a) **Reflection false positives:** you put a value in a `Bundle`, …</sub>
- [ ] **`D06-079`** Evidence hygiene for a service-driven state change  
   <sub>A state change needs pre-state, the bug, and post-state — plus the out-of-band side effect. Five artefacts, ta…</sub>
- [ ] **`D06-080`** `adb shell` is UID 2000 — re-prove every candidate from a zero-permission app  
   <sub>Decides whether you may write AM-0 · `adb shell am startservice`, `service call` and drozer all run as UID 2000 (`shell`), which holds far more pri…</sub>
- [ ] **`D06-081`** Severity governance and chain-filing order for binder findings  
   <sub>`n/a — governs the VRT choice for every other item` · Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute the claim into each …</sub>

<details><summary>⚰️ D06 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Service X is exported" | An inventory item, not a finding. The entire mobile branch of the VRT is P5 and this is not even in it. Google's own invalid-report guidance says the export is only a finding if it "can be used to gain unauthorized access to application data or functionality". | Reach a privileged action, another user's data, or a non-exported component through it, from a zero-permission PoC app. |
| "`onServiceConnected` fired, so I can bind" — especially on a gRPC-over-binder service | `onBind` succeeds regardless of the `SecurityPolicy`, which rejects at the RPC layer. A successful bind proves reachability, not authorisation. | Complete an RPC and show what it returned, or quote a `permitAll()` / package-name-only policy body. |
| A `SecurityException` on one AIDL method | Proves that one method is gated. Interfaces are asymmetric by default. | Test every method in the table from D06-007 and report the ones with no check. |
| Crash from a malformed parcel or a huge `byte[]` | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**. | Turn it into memory corruption with a demonstrated primitive (→ D16), or show the exception handler fails open (D06-064). |
| A `NullPointerException` returned from `service call` | It proves the method body executed — an oracle, not an impact. On its own it is a probe result. | Build the real parcel and return the data (D06-012), or show the method performs a privileged action. |
| Token or secret found in the WorkManager `WorkSpec` database | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` is **P5**; the UID sandbox already protects it and you read it with root or `run-as`. | Show a zero-permission app reaching it — through an exported upload service (D06-029), a provider (D07), or a backup (D11). The reach is the finding. |
| "The app runs a service in a separate `:remote` process" | A design choice, and usually a *good* one. | The interface that process serves is unguarded (D06-015). |
| "`isolatedProcess` is not set on service Y" | Hardening only. No boundary is crossed. | Pair it with a memory-safety finding in the parser that runs there (→ D16); the absence is the severity amplifier, not the bug. |
| A HIDL / vendor-AIDL HAL weakness reachable from `adb shell` | Apps talk on `/dev/binder` only; `/dev/hwbinder` and `/dev/vndbinder` are separate contexts, and `shell` is not an app. | Prove an app-reachable framework proxy on `/dev/binder` that forwards to it (D06-068), then it is D25. |
| "Root detection in the integrity service is bypassable" | P5 (`lack_of_binary_hardening.lack_of_jailbreak_detection`). Most such services only report signals to a backend — telemetry, not a control. | Show the bypass defeats a control that gates money, DRM or anti-fraud — and if you can *stop* the service from an unprivileged app, report D06-031 instead. |
| "Foreground-service notification discloses the sync endpoint / job name" | Informational disclosure to the device owner, who already sees the notification. | The notification discloses another user's data, or the service accepts a caller-chosen endpoint (D06-028). |
| An exported `JobService` you can bind but whose `onStartJob` ignores your parameters | Reachability with no effect. | The job body consumes `JobParameters.getExtras()` and you can steer it (D06-060). |
| `android:visibleToInstantApps` absent, but you claimed browser reach anyway | Overstated attacker model; it gets the whole report downgraded. | Recheck the attribute. Without it the finding is AM-03, which is still valuable — write it that way. |
| SQL injection inside a provider-backed service that crosses no permission boundary | Google's invalid-reports guidance: "if an application has permissions to read and write contacts and can use SQL injection to read and write contacts, it is not an issue." Samsung's ineligible list says the same. | Show read-only access escalated to write, or data returned that the caller's permissions do not cover. That sentence is the difference between $0 and a valid High. |

</details>


<details><summary>🔗 D06 cross-surface joins — park these, chase them in P7</summary>

- **D06 × D08 — the binder handle inside a `PendingIntent`'s `Bundle`.** Reviewers check
  `PendingIntent` mutability and they check AIDL caller authorisation, never together. A `Bundle` can
  carry an `IBinder` (`Bundle.putBinder`), and a `PendingIntent` carries a `Bundle`. A service that
  enforces its permission only in `onBind` (D06-024) and an app that hands out a `PendingIntent`
  containing that handle produce a permission-free path to a permission-gated interface — the recipient
  never touches the service's manifest guard at all.
- **D06 × D07 — the `ParcelFileDescriptor` that a provider would never have granted.** Provider review
  covers `grantUriPermissions`, path traversal and `openFile`. Binder review covers method authorisation.
  Nobody checks that an AIDL method returns an FD onto a file the provider deliberately does not expose
  (D06-065). The FD carries the mode it was opened with and bypasses every URI-grant control the app
  designed — including a writable handle into the directory D06-030 needs.
- **D06 × D13 — the `NotificationListenerService` that reads the OTP the service just triggered.** The
  auth review tests the OTP flow; the IPC review tests the listener. Join them: use an exported service or
  a `Messenger` code (D06-032) to *trigger* the OTP send, then read the code with the listener (D06-048),
  then cancel the notification so the victim never sees it. That is a complete 2FA bypass built entirely
  from components each of which is individually "low".
- **D06 × D15 — the bound service as a shadow-API bridge.** The backend tester works from the web app's
  current API version; the mobile tester works from the manifest. The service's hardcoded endpoint is
  frequently an older version with weaker auth and more field exposure (D06-076) — and the service will
  call it *with the victim's credentials attached* (D06-028). The join is: enumerate the service's
  endpoints, diff them behaviourally against the web API, and drive the weaker one through the service.
- **D06 × D17 — the unauthenticated method that writes where the loader reads.** Dynamic-code-loading
  review lists the directories the app `System.load()`s from. IPC review lists the methods that take a
  path. Cross the two lists and the intersection is an RCE (D06-030). Neither list is interesting alone,
  and neither reviewer usually sees the other's.
- **D06 × D22 × D21 — the Android 15 FGS restriction that silently disarms a security control.** Version
  behaviour review notes the compat flags; resilience review notes the control exists. The join is that
  the control is re-armed from a `BOOT_COMPLETED` receiver starting a restricted FGS type (D06-039), so on
  Android 15 it throws and never re-arms — and the app's fallback (a `specialUse` FGS, a notification
  trampoline, a newly visible overlay) is a fresh attack surface nobody reviewed.
- **D06 × D03 × D02 — the signature check that is not one.** Permission review checks protection levels;
  signing review checks v3.1 rotation. The join: a service whose caller check is
  `checkSignatures()`-based (D06-020) is sound only while the rotation story holds, and a `sharedUserId`
  family (D06-021) means the *weakest* app in the family passes it. Three reviews, one bypass.
- **D06 × D26 — the process you did not instrument.** Tooling review sets up Frida; IPC review writes the
  hooks. If the service runs in `:remote` (D06-004) and you attached to the main process, every hook
  reports "no caller check reached" — a false negative that looks exactly like a clean result. This join
  is the most common way a D06 engagement produces a confidently wrong negative.

</details>


---

## D07 ContentProviders & FileProvider

**Phase P5 · `M5` · 76 items** — 🟥 23 critical · 🟧 29 high · 🟨 1 medium · 🟩 1 low · ⬜ 22 support  

📄 Full detail, with every command and proof: [`checklist/D07-contentproviders-and-fileprovider.md`](checklist/D07-contentproviders-and-fileprovider.md)

> **Crux question.** **Does any caller outside this app's UID reach a provider method that either resolves a caller-controlled string into a filesystem path or concatenates a caller-controlled string into SQL — and if the answer is no, can the app itself be made to call that method on the attacker's behalf?**

Providers pay because the platform's whole confidentiality story for app data is `/data/data/<pkg>` being
mode `0700` from `targetSdkVersion >= 24`. A traversal in `openFile()` or an injectable `selection` does
not weaken that boundary — it walks through the one door the platform deliberately left in it. That is why
the same bug that would be "information disclosure" on a web target is an app-sandbox escape here, and why
`server_side_injection.file_inclusion.local` (P1) is a defensible analogue rather than a stretch. Oversecured
state that more than 90% of the apps they analyse contain provider implementation errors of varying
criticality; that is a base rate for *defects*, not for payable findings, and the gap between the two is the
whole craft of this chapter.


**⬜ Support ceiling**

- [ ] **`D07-001`** Enumerate every declared authority with all six access-control attributes  
   <sub>`n/a (enabler)` · AM-03 · Extract every `<provider>` with `authorities`, `exported`, `permission`, `readPermission`, `writePermission` a…</sub>
- [ ] **`D07-002`** The targetSdk<17 default-export gate — state it or lose the report  
   <sub>`n/a (rating qualifier)` · AM-03 · A `<provider>` with no `android:exported` attribute defaults to `true` when the app targets API < 17, and to `…</sub>
- [ ] **`D07-003`** Cross-check the merged manifest against the runtime provider table  
   <sub>`n/a (enabler)` · AM-03 · The authorities the app's own developers wrote are a subset of the authorities the app ships. Manifest merging…</sub>
- [ ] **`D07-004`** Recover the URI path space the manifest never names  
   <sub>`n/a (enabler)` · AM-03 · The manifest gives you an authority; it never gives you the paths. Those live in `UriMatcher.addURI()` calls, …</sub>

**🟥 Critical ceiling**

- [ ] **`D07-005`** Read, write and `call()` are three separate questions  
   <sub>``server_side_injection.file_inclusion.local` (P1) where it yields file bytes; ` · AM-03 · A denial on `query` says nothing about `insert`, `update`, `delete`, `openFile` or `call`. `android:readPermis…</sub>

**⬜ Support ceiling**

- [ ] **`D07-006`** Classify the exception by layer before recording a positive or a negative  
   <sub>`n/a (false-positive gate)` · AM-03 · This is the provider form of the layer-ordering trap. Testers read "no `SecurityException`" as "readable" and …</sub>
- [ ] **`D07-007`** Re-prove every provider hit from an app UID, not the `shell` UID  
   <sub>`n/a (false-positive gate)` · AM-03 · `adb shell content` runs as uid 2000, which holds platform permissions no third-party app has. A finding prove…</sub>
- [ ] **`D07-008`** Declare `<queries>` in the PoC app, or you will manufacture your own false negative  
   <sub>`n/a (false-negative gate)` · AM-03 · Package visibility is filtered for a caller that itself targets SDK 30 or above. An undeclared target package …</sub>
- [ ] **`D07-009`** Sweep authorities with a counted loop, never a bare shell array  
   <sub>`n/a (methodology control)` · AM-03 · A provider sweep is the classic case: dozens of authorities crossed with a dozen path variants crossed with si…</sub>
- [ ] **`D07-010`** Prove the negative with the exact exception text  
   <sub>`n/a (deliverable)` · AM-03 · "The scanner found nothing" is not a negative. A ruled-out entry must carry the evidence that killed the hypot…</sub>

**🟧 High ceiling**

- [ ] **`D07-011`** Read the provider from a second Android user and from a locked Private Space  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 on a secondary user / work p · Everyone queries as user 0. Cross-user data access is an explicitly purchased impact class, and an app that ke…</sub>
- [ ] **`D07-012`** `readPermission` / `writePermission` asymmetry  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The two directions are independent and are enforced independently. Declaring only `readPermission` leaves `ins…</sub>
- [ ] **`D07-013`** `android:permission` silently overridden by a weaker per-direction permission  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · `android:readPermission` and `android:writePermission` *override* `android:permission` for their direction. A …</sub>
- [ ] **`D07-014`** Resolve the protectionLevel of the custom permission that "protects" the provider  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · A provider guarded by `com.target.app.permission.READ_DATA` is only as strong as that permission's `protection…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-015`** `call()` is gated by neither the read nor the write permission  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-03 · Beyond the provider-acquisition check, the platform applies no permission logic to `call()`. Every `call()` im…</sub>
- [ ] **`D07-016`** `call()` bypasses `UriMatcher` and `<path-permission>` by design  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · `ContentProvider.call(authority, method, arg, extras)` is addressed by *authority and method name*, not by a U…</sub>

**⬜ Support ceiling**

- [ ] **`D07-017`** Enumerate the `call()` method table out of the DEX  
   <sub>`n/a (enabler for D07-015)` · AM-03 · `call()` method names are never in the manifest and rarely in a string resource you would notice. They live in…</sub>

**🟧 High ceiling**

- [ ] **`D07-018`** Inventory the whole Binder entry-point surface, not the eight verbs the CLI exposes  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) for the acce` · AM-03 · `adb shell content` gives you `query`, `insert`, `update`, `delete`, `call`, `read`, `write` and `gettype`. `C…</sub>
- [ ] **`D07-019`** `applyBatch()` and `bulkInsert()` — the write sinks `adb shell content` cannot reach  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-03 · The `content` CLI has no batch verb, so an override of `bulkInsert()` or `applyBatch()` is a write path that e…</sub>
- [ ] **`D07-020`** `<path-permission>` form coverage — the five path attributes  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · `<path-permission>` protects only the paths its attribute matches. `android:path` is an exact string match; `p…</sub>
- [ ] **`D07-021`** `/Keys` versus `/Keys/` — the trailing-slash path-permission bypass  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The canonical provider bug and still a live one. A `<path-permission android:path="/Keys">` protects exactly `…</sub>
- [ ] **`D07-022`** `UriMatcher` normalisation variant fuzz  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · Never treat an authority as one object. `addURI()` patterns and the permission-checking branch are hand-writte…</sub>
- [ ] **`D07-023`** `getCallingPackage()` versus `getCallingPackageUnchecked()`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · A provider that self-authorises using `getCallingPackageUnchecked()` (or the package name out of a `Bundle` ex…</sub>
- [ ] **`D07-024`** `grantUriPermissions="true"` with no `<grant-uri-permission>` restriction  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 (needs a grant primitive fro · `grantUriPermissions="true"` at provider level means *any* URI under the authority can be handed out temporari…</sub>
- [ ] **`D07-025`** `exported="false"` plus `grantUriPermissions="true"` is reachable, not closed  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The single most common wrongly-recorded negative in this domain. A redirected or echoed Intent carrying `FLAG_…</sub>
- [ ] **`D07-026`** `FLAG_GRANT_PREFIX_URI_PERMISSION` grants the subtree, not the file  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03/AM-04 · An app that shares one photo with `FLAG_GRANT_PREFIX_URI_PERMISSION` has shared the directory. After receiving…</sub>
- [ ] **`D07-027`** Persistable grants survive reboot and the user's "delete"  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES)` · AM-03/AM-04, recipient of a legiti · The corpus covers `takePersistableUriPermission` only defensively; nobody tests **retention**. When the app ha…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-028`** `openFile()` / `openAssetFile()` / `openTypedAssetFile()` path traversal  
   <sub>``server_side_injection.file_inclusion.local` (P1); fallback `server_security_m` · AM-03 · The provider builds a `File` from a URI path segment and returns a `ParcelFileDescriptor` without canonicalisi…</sub>
- [ ] **`D07-029`** The `%2F` decode mismatch — `Uri` accessors decode after the string check  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 · `Uri.getPath()`, `Uri.getLastPathSegment()` and `Uri.getPathSegments()` return **decoded** values. A developer…</sub>

**⬜ Support ceiling**

- [ ] **`D07-030`** Depth sweep with harmless canaries before you touch real data  
   <sub>`n/a (technique — the canary alone is never the report; the pivot lands on D07-` · AM-03 · Traversal depth is not statically knowable — it depends on where the provider's root sits. Sweep depths 1..8 w…</sub>
- [ ] **`D07-031`** Infer file-backed versus SQLite-backed before you fuzz  
   <sub>`n/a (triage control)` · AM-03 · An authority that resolves but where every `content query` fails is almost always an `openFile` provider. Feed…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-032`** The encoding-variant matrix the scanners never send  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 · Naive `contains("..")` filters, single-pass `replace("../","")` sanitisers and decode-order bugs each fall to …</sub>

**⬜ Support ceiling**

- [ ] **`D07-033`** Never accept `scanner.provider.traversal` reporting "Not Vulnerable"  
   <sub>`n/a (false-negative control)` · AM-03 · The scanner sends exactly one payload against exactly one file, with a fixed 16-level prefix and a non-empty-r…</sub>

**🟧 High ceiling**

- [ ] **`D07-034`** `openFile()` that ignores the `mode` argument  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The framework checks the caller's requested **mode** against the read or the write permission, then hands the …</sub>

**🟥 Critical ceiling**

- [ ] **`D07-035`** Write-mode traversal into a code-load path  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) once execution is demon` · AM-03 · The same primitive as D07-028 in the other direction. The write alone underpays; plan the write-then-load chai…</sub>
- [ ] **`D07-036`** `openFileHelper()` and the `_data` column — insert your own path, then open it  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 · `ContentProvider.openFileHelper(uri, mode)` opens whatever path sits in the row's `_data` column. If the provi…</sub>

**🟧 High ceiling**

- [ ] **`D07-037`** Symlink and TOCTOU against the provider's own canonicalisation  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03/AM-04 · A provider that calls `getCanonicalPath()`, validates the prefix, and *then* opens the file has a window. An a…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-038`** Provider `selection` SQL injection — make the error hand you the query  
   <sub>``server_side_injection.sql_injection` (P1) — note it is defined server-side; f` · AM-03 · Establish that your string reaches SQL, then break it. A vulnerable provider's error leaks the real table name…</sub>
- [ ] **`D07-039`** Projection injection is a separate sink from selection  
   <sub>``server_side_injection.sql_injection`` · AM-03 · `projection` is never parameterisable — it is a column list spliced into the `SELECT` clause, so even an app t…</sub>

**🟧 High ceiling**

- [ ] **`D07-040`** `sortOrder` injection — the third sink nobody sends  
   <sub>``server_side_injection.sql_injection`` · AM-03 · `sortOrder` is spliced into `ORDER BY` and is as unparameterisable as `projection`. It is the least-tested of …</sub>

**🟥 Critical ceiling**

- [ ] **`D07-041`** URI path-segment injection into `appendWhere()`  
   <sub>``server_side_injection.sql_injection`` · AM-03 · A second, distinct sink from the `selection` parameter: the provider concatenates a URI path segment. The MAST…</sub>
- [ ] **`D07-042`** Injection in `update()`/`delete()`/`insert()` selection — the blind boolean oracle  
   <sub>``server_side_injection.sql_injection` (P1); `broken_authentication_and_session` · AM-03 · `query()` is the method everyone tests. The write methods take a caller-controlled `WHERE` too, and when a pro…</sub>
- [ ] **`D07-043`** Balanced-subquery injection that survives `setStrict(true)`  
   <sub>``server_side_injection.sql_injection`` · AM-03 (holding any legitimate gran · The interesting question is never "can I break out of the `WHERE` clause" — paren-wrapping stopped that years …</sub>

**⬜ Support ceiling**

- [ ] **`D07-044`** Establish whether strict SQL checking is on — your own negative control  
   <sub>`n/a (negative control)` · AM-03 · Before you claim an injection, prove the defence exists and that you are outside it. Android's hardening ships…</sub>

**🟧 High ceiling**

- [ ] **`D07-045`** Cross-provider SQL injection through a shared SQLite database  
   <sub>``server_side_injection.sql_injection`` · AM-03 · The permission boundary between two providers is void if they share one `SQLiteOpenHelper` or one database fil…</sub>
- [ ] **`D07-046`** Projection-map or caller check applied to only one `UriMatcher` branch  
   <sub>``server_side_injection.sql_injection`` · AM-03 · Providers restrict columns or check the caller for the "root" URI and forget the sibling branches. Read the `s…</sub>

**⬜ Support ceiling**

- [ ] **`D07-047`** `scanner.provider.injection` has a one-string oracle  
   <sub>`n/a (false-negative control)` · AM-03 · Any provider that catches the exception, returns an empty cursor, or emits a different SQLite message is repor…</sub>
- [ ] **`D07-048`** Drive the provider surface through Burp with `auxiliary.webcontentresolver`  
   <sub>`n/a (tooling)` · AM-03 · Turning a suspected blind provider injection into a demonstrated full-table dump by hand is slow. Exposing the…</sub>
- [ ] **`D07-049`** Oracle discipline — body-diff and the n>=10 interleaved sample  
   <sub>`n/a (false-positive gate)` · AM-03 · Two failure modes kill provider-injection reports at triage. (a) **Body-diff**: a cursor with the same row cou…</sub>
- [ ] **`D07-050`** Marker discipline for provider write and reflection claims  
   <sub>`n/a (false-positive gate)` · AM-03 · A provider write is only proven if the value you see afterwards is unmistakably yours. Writing `test`, `admin`…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-051`** Provider that proxies a caller-supplied `content://` URI  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) — argue P1/P` · AM-03 · A provider that takes a URI as a *parameter* — a path segment, a query parameter, a `call()` bundle key — and …</sub>
- [ ] **`D07-052`** Provider forwarding to a system provider under the app's own permission  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The narrower, more common cousin of D07-051: the provider does not take an arbitrary URI, it just serves a *fi…</sub>

**🟧 High ceiling**

- [ ] **`D07-053`** Fallback-response enumeration against a thumbnail or avatar deputy  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-03 · A deputy that returns a **stable fallback** for missing objects — a default avatar, a placeholder thumbnail, a…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-054`** The app's own `ContentResolver` fed an attacker `file://` URI  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 (delivery via an exported co · `openFile()`, `openFileDescriptor()`, `openInputStream()`, `openOutputStream()` and `openAssetFileDescriptor()…</sub>

**🟧 High ceiling**

- [ ] **`D07-055`** MIME-type-only intent filters implicitly accept `content:` and `file:`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · A filter declaring only `<data android:mimeType="image/*"/>` with no `scheme` is an open door for `file://` an…</sub>
- [ ] **`D07-056`** Non-exported provider reached through the app's own URI sink  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 · The vector most testers skip after reading `exported="false"`. Android checks the rights of the *accessing* pr…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-057`** FileProvider `<paths>` rooted at `/`, `.` or empty  
   <sub>``server_side_injection.file_inclusion.local` (P1) when reachable; `server_secu` · AM-03 (needs an exported provider  · The paths XML is the whole access-control surface of a FileProvider. Each element maps a URI prefix (`name`) t…</sub>

**🟧 High ceiling**

- [ ] **`D07-058`** `<external-path>` and the shared-volume exposure  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_extern` · AM-03/AM-04 · `<external-path>` maps the shared volume, which is not part of the app sandbox at all. Anything the provider s…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-059`** `FileProvider.getUriForFile()` called with attacker-controlled input  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03/AM-02 · Even a narrowly-scoped provider becomes a read primitive if the `File` argument comes from outside. The app th…</sub>

**🟧 High ceiling**

- [ ] **`D07-060`** Concede what FileProvider actually blocks — `files/` and `cache/`, not `shared_prefs/`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · `<files-path path="."/>` exposes the whole of `getFilesDir()`, but AndroidX `FileProvider` canonicalises the r…</sub>

**⬜ Support ceiling**

- [ ] **`D07-061`** `grantUriPermissions="true"` on a FileProvider is mandatory, not the defect  
   <sub>`n/a (false-positive gate)` · Scanners and inexperienced testers file `grantUriPermissions="true"` on a FileProvider as a finding. It is a f…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-062`** Dirty Stream — trusting `DISPLAY_NAME` from a foreign ContentProvider  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) once execution is shown` · AM-03 (the victim must open/accept · The inverted direction, and the single most commonly missed ContentProvider test. When the app receives a `con…</sub>
- [ ] **`D07-063`** Implicit-intent result interception returning a `file://` URI  
   <sub>``server_side_injection.file_inclusion.local`` · AM-03 (the victim must pick your a · The victim launches a picker; a malicious responder returns a `file://` URI pointing at the victim's own priva…</sub>
- [ ] **`D07-064`** DocumentsProvider / SAF restore-import traversal in the consumer  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the write lands on` · AM-03 · When an exported receiver, service or activity accepts `DocumentsContract` tree/document URIs and copies them …</sub>

**🟧 High ceiling**

- [ ] **`D07-065`** Side-effecting logic inside provider methods  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · Developers model providers as CRUD, so nobody audits the maintenance code they put inside them: a `query()` ar…</sub>

**🟨 Medium ceiling**

- [ ] **`D07-066`** Exported `SliceProvider` whose `onBindSlice` acts on the URI  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES)` · AM-03/AM-04 (needs slice permissio · Slices are bound by external hosts (Assistant, system search), and the documented setup exports the provider o…</sub>

**🟧 High ceiling**

- [ ] **`D07-067`** `CloudMediaProvider` inside the Photo Picker  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 · The Photo Picker can surface media from an eligible cloud media provider. If the app under test *is* one, its …</sub>

**🟥 Critical ceiling**

- [ ] **`D07-068`** Rate the provider by what the rows contain, not by the fact it is exported  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · The severity is set entirely by the columns, so inventory them by sensitivity rather than reporting "provider …</sub>

**🟧 High ceiling**

- [ ] **`D07-069`** Chain two providers — one names the object, the other returns its bytes  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES)` · AM-03 · A provider that is "only" a file listing is not a finding on its own, and a cache provider that needs an exact…</sub>

**🟥 Critical ceiling**

- [ ] **`D07-070`** Take provider rows to the backend — the mobile-to-backend shadow-API bridge  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `br` · AM-03 -> AM-01 · A provider row is not the end of the finding, it is the input to the next one. Providers carry session tokens,…</sub>

**🟧 High ceiling**

- [ ] **`D07-071`** The Downloads provider and the signed URL that outlives the session  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES);` · AM-03 · Three questions, not one. Where does the downloaded document rest, is the download URL (with its query-string …</sub>
- [ ] **`D07-072`** MediaStore cross-owner read and `OWNER_PACKAGE_NAME` redaction  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03/AM-04 · Two questions. (a) Can the app read media belonging to other apps, and does it hold `MANAGE_EXTERNAL_STORAGE` …</sub>

**🟩 Low ceiling**

- [ ] **`D07-073`** `androidx.startup` authority collision — HYPOTHESIS, run the experiment before reporting  
   <sub>``application_level_denial_of_service_dos` (VARIES) — availability only, and **` · AM-03 · Android refuses to install a package whose provider authority is already claimed by an installed package. **Hy…</sub>

**⬜ Support ceiling**

- [ ] **`D07-074`** Evidence package for a provider finding  
   <sub>`n/a (deliverable)` · A provider read needs the bytes; a provider **write** needs a state change, and a state change needs five arte…</sub>
- [ ] **`D07-075`** Pre-severity gate against the Critical claim, not against the bug  
   <sub>`n/a (governance)` · Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each question. Thi…</sub>
- [ ] **`D07-076`** Chain-filing order for provider primitives  
   <sub>`n/a (submission mechanics)` · D07 is a primitive factory: the traversal, the over-broad paths XML, the grant configuration and the injection…</sub>

<details><summary>⚰️ D07 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Exported ContentProvider" flagged by a scanner on an app targeting SDK 34 with an explicit `signature`-level `readPermission` | The permission gate holds; export is a design decision, not a defect | Show the protectionLevel is `normal`/`dangerous` (D07-014), or a path variant that bypasses the gate (D07-022) |
| The `targetSdk < 17` default-export rule fired on a modern app | The default has been `false` since Android 4.2; MobSF gates it on `min_sdk < 17` and reports anyway | The manifest genuinely declares `targetSdkVersion < 17`, quoted from `aapt dump badging` |
| `grantUriPermissions="true"` on a `FileProvider` | Mandatory for the class — without it the provider throws `SecurityException: Provider must grant uri permissions` | The **path scope** is over-broad (D07-057) or a grant reaches an attacker (D07-024/-022) |
| `<root-path>` present, provider not exported, no grant path, no URI sink in the app | A configuration observation with no reachable caller; it is a blast-radius multiplier waiting for a primitive | Any of: the provider is exported, a redirector issues grants (D08), or the app opens attacker URIs (D07-056) |
| Sensitive data found in `/data/data/<pkg>` via `run-as` or root | AM-12 is not an attack, and the VRT prices it at P5 (`insecure_data_storage...on_internal_storage`). Xiaomi, Grab and Spotify all list app-private storage explicitly out of scope; Google: "Access to non-sensitive internal files of another app also does not qualify" | Pair it with a provider read, traversal or grant that a non-root third party can use, and refile as the **access** bug with the data as the payload |
| `adb shell content query` returns rows but the same query from a PoC app throws `SecurityException` | `shell` is uid 2000 and holds permissions no third-party app has | Reproduce from an app UID (D07-007). If it only works from `shell`, it is an artefact |
| drozer `scanner.provider.traversal` / `scanner.provider.injection` reporting "Not Vulnerable" | One payload against one file, and a single-error-string oracle respectively | The manual matrix (D07-032) or the `1=1`/`1=0` body diff (D07-049) plus a source-level check |
| `/etc/hosts` canary failing | Some OEM SELinux policies block it outright; the scanner's only oracle silently reads empty | Re-run with `/proc/version`, which is readable on API 30+, and state the policy caveat |
| A provider crash from a malformed URI or a null extra | VRT `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**, and it is a self-inflicted local crash | The crash is a memory-safety primitive in native provider code, or it is persistent (crash-on-launch) — then it is a D19/D04 finding, not D07 |
| Unbounded `insert` growing the app's database ("flood the provider") | App-local availability loss with no confidentiality impact; most programmes rate it Low or out of scope | The provider backs a critical-path service **and** the programme buys availability — quote the before/after `du -sh` figures and the failure state |
| Provider SQL injection reachable only through the app's own UI | You are injecting into your own database, as your own user | The same concatenation is reachable through an **exported** provider's `selection`/`projection`/`sortOrder`, i.e. attacker-controlled by any installed app |
| A `MediaStore` / `Downloads` row returned to your own app | Those providers are designed to be readable; the platform's `SecurityException` on cross-owner reads is the control working | A cross-*owner* read succeeding, or a signed URL in a row that replays off-device (D07-071) |
| `takePersistableUriPermission` present in the app's code | Defensive use is normal SAF practice | The app **hands out** persistable grants and never revokes them, and you still read after reboot and after the user deleted the item (D07-027) |

</details>


<details><summary>🔗 D07 cross-surface joins — park these, chase them in P7</summary>

- **D07 × D08 — the paths XML and the redirector.** Nobody reads `res/xml/file_paths.xml` and
  `startActivity(getIntent().getParcelableExtra(...))` in the same sitting. The XML decides what a grant
  reaches; the redirector decides who gets one. Individually: a config note and a "component forwards an
  intent". Joined: `content://<pkg>.fileprovider/root/data/data/<pkg>/shared_prefs/auth.xml` read by a
  zero-permission app. This is the single highest-yield join in the chapter, and it is the reason
  `exported="false"` is never a ruled-out basis on its own (D07-025).
- **D07 × D03 — the provider line and the permission line.** A provider guarded by
  `com.target.app.permission.READ_DATA` reads as protected in the manifest review, and the
  `<permission android:protectionLevel="normal">` two hundred lines above reads as unremarkable in the
  permission review. Join them and the guard is auto-granted to any app that asks (D07-014).
- **D07 × D17 — the write primitive and the loader.** A traversal that honours `"w"` is Medium on its own
  and the Google Mobile VRP says so explicitly. Enumerate `System.load`/`DexClassLoader`/plugin directories
  *first*, choose the destination to match, and the same primitive is the VRP's top-paying category
  (D07-035, D07-062).
- **D07 × D15 — provider rows as the backend's keys.** Object ids, share tokens and API version strings sit
  in provider rows, and the mobile client's API version is usually older than the web app's. The local read
  is Low at a programme that discounts same-device apps; the forged public share URL from the same token is
  a remote finding at the same programme (H1 #518669). Always take the row off-device (D07-070).
- **D07 × D10 — `setAllowContentAccess` is on by default.** A WebView that loads any untrusted content can
  `XMLHttpRequest` a `content://` URI. The WebView reviewer tests XSS and origins; the provider reviewer
  tests `adb shell content`. Neither tests the provider *from inside the WebView*, which is where the
  app's own authority is reachable without any IPC at all (MASTG-TEST-0250).
- **D07 × D09 — deep-link parameters that name a URI.** `targetapp://share?file=...` and
  `?uri=content://...` are tested for open redirect and XSS and never for a `content://` or `file://`
  payload aimed at the app's own provider. That is the AM-02 delivery route into D07-056 and D07-059.
- **D07 × D11 — reachability is what converts storage into a finding.** An unencrypted token in
  `shared_prefs` is P5 by VRT and explicitly out of scope at several programmes. The provider traversal is
  the thing that makes it a P1 read. File the access as the bug and the storage as the payload — never the
  other way round.
- **D07 × D05/D13 — the telephony provider and the OTP.** A blind `update()` oracle on an OEM provider that
  shares a database file with `sms` (CVE-2025-10184) reads OTP bodies with no `READ_SMS`. The SMS reviewer
  looks at the receiver and the permission; the provider reviewer looks at the columns. The join is
  account takeover on every service that uses SMS 2FA.
- **D07 × D02 — the merged manifest is where the SDK's provider lives.** The app's own source contains no
  `FileProvider`, so the source reviewer records a negative; the merged manifest contains three, each with
  its own paths XML written by a vendor the client has never audited (D07-003).
- **D07 × D19/D04 — the side-effecting `call()` and the crash surface.** A `call()` method table
  (D07-017) is simultaneously the richest authorisation-bypass surface and the best-shaped fuzzing corpus
  in the app. Enumerate once, use twice.

</details>


---

## D08 Intent Redirection, PendingIntent & URI Grants

**Phase P5 · `M5` · 66 items** — 🟥 18 critical · 🟧 29 high · 🟨 7 medium · ⬜ 12 support  

📄 Full detail, with every command and proof: [`checklist/D08-intent-redirection-and-pendingintent.md`](checklist/D08-intent-redirection-and-pendingintent.md)

> **Crux question.** **Does any attacker-reachable entry point in this app hand a `Intent`, `Uri`, `Bundle` or `PendingIntent` that the attacker fully or partially controls to a framework call that executes with the app's own UID — and if so, which non-exported component, private provider URI or held runtime permission does that reach that the attacker cannot reach directly?**

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


**⬜ Support ceiling**

- [ ] **`D08-001`** Census every unparcel-to-launch sink in the app  
   <sub>`none — inventory feeding `broken_access_control.exposed_sensitive_android_inte` · AM-03 · Build the complete candidate list before testing anything: every place attacker-controlled bytes become an `In…</sub>
- [ ] **`D08-002`** Enable `StrictMode.detectUnsafeIntentLaunch()` and drive the app  
   <sub>`none — detector feeding the redirection items` · AM-12 (own device instrumentation, · The platform ships a runtime detector for exactly this class: it fires when the app unparcels a nested intent …</sub>
- [ ] **`D08-003`** Frida census of the redirection and PendingIntent surface at runtime  
   <sub>`none — instrumentation` · AM-12 · Static analysis misses reflective launches, SDK code obfuscated past your greps, and PendingIntents built by l…</sub>
- [ ] **`D08-004`** Two-API-level control run before any redirection claim  
   <sub>`none — governs the severity narrative of every item below` · AM-12 · Android 16 applies intent-redirection protection by default to **all** apps regardless of target SDK. The iden…</sub>

**🟧 High ceiling**

- [ ] **`D08-005`** Sweep the merged manifest for SDK-added exported proxies  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — argue it)` · AM-03, AM-08 · The vulnerable component is frequently not the developer's. Manifest merging pulls activities, services and re…</sub>

**⬜ Support ceiling**

- [ ] **`D08-006`** Census the URI-grant preconditions before testing any grant item  
   <sub>`none — precondition inventory for D08-010 through D08-012 and D08-053 through ` · AM-03 · A redirect that carries grant flags only pays if there is something worth granting. Enumerate which authoritie…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-007`** Classic nested-Intent forward to a non-exported activity  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — argue up to ` · AM-03 · An exported component pulls an `Intent` out of its own extras and passes it to `startActivity()`. `Intent` is …</sub>

**🟧 High ceiling**

- [ ] **`D08-008`** The same forward through service, foreground-service and broadcast sinks  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Reviewers stop at `startActivity`. The same unparcel-and-launch shape in `startService`, `startForegroundServi…</sub>
- [ ] **`D08-009`** Literal `startActivity(getIntent())` self-forward  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The degenerate case that greps for `getParcelableExtra` miss entirely: the component forwards the **whole rece…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-010`** Forwarded `FLAG_GRANT_READ/WRITE_URI_PERMISSION` — the grant is the payload  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · The reached component does not have to be interesting. Point the nested intent at **your own** activity, set t…</sub>
- [ ] **`D08-011`** `FLAG_GRANT_PREFIX_URI_PERMISSION` — one file becomes the whole authority  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · Testers set `FLAG_GRANT_READ_URI_PERMISSION` and stop. `FLAG_GRANT_PREFIX_URI_PERMISSION` converts the grant f…</sub>
- [ ] **`D08-012`** `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` — a grant that survives reboot  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-03 · Persistable turns a one-shot confused deputy into a durable exfiltration channel. The receiving app calls `tak…</sub>

**🟧 High ceiling**

- [ ] **`D08-013`** Component allow-list present, but extras, data and flags still attacker-controlled  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A team that "fixed" intent redirection usually validated the nested intent's package and class only. The neste…</sub>
- [ ] **`D08-014`** `resolveActivity()`-based validation bypass  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The hand-rolled guard that looks safe and is not: ```java Intent forward = (Intent) getIntent().getParcelableE…</sub>
- [ ] **`D08-015`** `setSelector()` smuggling past `setComponent(null)`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03; AM-02 when delivered throug · An `Intent` can carry a *selector* Intent. When present, the selector — not the intent's own action/data/compo…</sub>
- [ ] **`D08-016`** Implicit inner Intent matched against a non-exported component's filter  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Two sides of the same coin. (a) A fix that blocks `component=` on the nested intent does not block an **implic…</sub>

**⬜ Support ceiling**

- [ ] **`D08-017`** No `IntentSanitizer` and no component allow-list on a forwarding path  
   <sub>`inherits the redirect it enables` · AM-03 · The structural half of the finding, and the part that survives a "we will fix it later" response: the platform…</sub>

**🟧 High ceiling**

- [ ] **`D08-018`** `IntentSanitizer` present but configured permissively  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A mitigation that is present and believed effective is worse than none, because it stops further review by bot…</sub>
- [ ] **`D08-019`** `Intent.removeLaunchSecurityProtection()` present in app code  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 16 blocks launching an unparcelled embedded Intent when the provenance token is invalid, when the crea…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-020`** `android:intentMatchingFlags="none"` on an exported component  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 16 requires explicit intents to match the target component's intent filter and blocks action-less inte…</sub>
- [ ] **`D08-021`** Task and launch flags preserved through the forward  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Grant flags are not the only ones that matter. A forward that preserves `FLAG_ACTIVITY_NEW_TASK`, `FLAG_ACTIVI…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-022`** `Intent.parseUri()` on attacker-controlled text  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — argue toward` · AM-02 (a link is enough; no attack · Any place the app turns a string into an `Intent` — a deep-link parameter, a WebView URL, a QR payload, a push…</sub>
- [ ] **`D08-023`** `Intent.URI_ALLOW_UNSAFE` (flag value 4) on externally sourced data  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03, AM-02 · `URI_ALLOW_UNSAFE` preserves fields that the safe parse modes strip — including flags. Because the resulting i…</sub>
- [ ] **`D08-024`** WebView `shouldOverrideUrlLoading` turned into an arbitrary-component launcher  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the JS-in-pri` · AM-02, AM-09 (malicious backend/CD · `shouldOverrideUrlLoading` that calls `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` and then `startActivity…</sub>

**🟧 High ceiling**

- [ ] **`D08-025`** Legacy `Intent.getIntent()` / `getIntentOld()` parsers  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-02 · `Intent.getIntent(String)` and `Intent.getIntentOld(String)` are the deprecated ancestors of `parseUri` and ca…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-026`** Push / messaging payload field parsed into an Intent  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); with the gran` · AM-09 (malicious or compromised ba · The redirection sink is often not reached from another app at all — it is reached from the network. A push han…</sub>
- [ ] **`D08-027`** `Parcel.unmarshall()` + `readParcelable()` on a deep-link parameter  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); RCE outcome `` · AM-02 · Some routers base64-decode a deep-link parameter into a `Parcel` and read an `Intent` out of it. This is an in…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-028`** Untyped `getParcelableExtra` / `getParcelable` / `getSerializableExtra`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The legacy untyped overloads instantiate whatever class the Parcel names, using the supplied `ClassLoader`, *b…</sub>

**🟧 High ceiling**

- [ ] **`D08-029`** App-defined `Parcelable` whose write and read byte counts disagree  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · A `Parcelable` whose `writeToParcel` and `createFromParcel` do not consume the same number of bytes lets an at…</sub>
- [ ] **`D08-030`** Whole-`Bundle` forward carrying smuggled `IBinder` / `PendingIntent` keys  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · A `Bundle` can carry live `IBinder` handles (`putBinder`) and `PendingIntent` objects. An app that receives a …</sub>
- [ ] **`D08-031`** Parcel mismatch across the app's own `android:process` boundary  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The mismatch class exists because data is validated in one process and re-serialised to another. An app with i…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-032`** Untyped `getSerializableExtra` on an exported forwarder  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); with a demons` · AM-03 · An exported component that deserialises an object it does not type-check instantiates attacker-chosen classes …</sub>

**🟥 Critical ceiling**

- [ ] **`D08-033`** `setResult(RESULT_OK, getIntent())` — the full-Intent echo  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · An exported activity that returns the incoming Intent as its result also returns the URI grants that Intent ca…</sub>
- [ ] **`D08-034`** Echo or redirect aimed at a system provider the victim holds permission for  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — r` · AM-03 (the attacker holds **no** r · The echo and the forward do not only re-delegate the victim's *own* provider access. They re-delegate every ru…</sub>

**🟧 High ceiling**

- [ ] **`D08-035`** `onActivityResult` trusting a third-party result Intent — the reverse direction  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 + one user tap (the picker/c · Everyone tests the app as a *receiver* of intents. The responder side is the one nobody reviews: when the app …</sub>

**🟥 Critical ceiling**

- [ ] **`D08-036`** Path traversal via `OpenableColumns.DISPLAY_NAME` from a hostile provider  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the write lands on` · AM-03 + one user tap · The inverse of the usual provider test, and the single most commonly missed one. The victim queries your provi…</sub>
- [ ] **`D08-037`** Mutable `PendingIntent` with a blank or implicit base Intent  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269) or `broken_access` · AM-03; AM-04 when acquisition need · AOSP's own javadoc: "By giving a PendingIntent to another application, you are granting it the right to perfor…</sub>

**🟧 High ceiling**

- [ ] **`D08-038`** Mutable `PendingIntent` with `setPackage()` only — the targetSdk-34-compliant variant  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269)` · AM-03, AM-04 · Android 14's check is satisfied by a package alone. That narrows your target set to the victim's own component…</sub>
- [ ] **`D08-039`** `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` present  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269)` · AM-03 · Android 14 blocks the mutable-plus-implicit combination. `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` is the documented…</sub>
- [ ] **`D08-040`** PendingIntent harvested from a notification by a `NotificationListenerService`  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269)` · AM-04 (needs the user to enable th · The acquisition half. A mutable PendingIntent is only a finding if you can reach it. The notification drawer i…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-041`** `getCreatorPackage()` / `getCreatorUid()` used to authenticate the *sender*  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-04 (acquisition via notificatio · The receiving side of the class. An app that takes a `PendingIntent` from elsewhere and decides whether to act…</sub>

**🟧 High ceiling**

- [ ] **`D08-042`** Missing `FLAG_ONE_SHOT` on a non-idempotent PendingIntent → replay  
   <sub>``broken_access_control.privilege_escalation` (null); financial replay argues i` · AM-03, AM-04 · A PendingIntent representing a one-time action — confirm payment, consume a voucher, complete a transfer, veri…</sub>
- [ ] **`D08-043`** `filterEquals()` + constant `requestCode` collision, with or without `FLAG_UPDATE_CURRENT`  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 (another user of the same ap · Two `PendingIntent`s whose base intents are `filterEquals()`-equal and whose request codes match are the **sam…</sub>
- [ ] **`D08-044`** Direct-reply `RemoteInput` PendingIntent — legitimately mutable, so audit what that exposes  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-04 · Direct reply genuinely requires `FLAG_MUTABLE` — the system fills in the typed text. That means every direct-r…</sub>
- [ ] **`D08-045`** Widget `setPendingIntentTemplate()` with an attacker-influenced `fillInIntent`  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-09 (server content chooses the  · Collection widgets use one template PendingIntent plus a per-item `fillInIntent`. The template's unfilled fiel…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-046`** Slice `primaryAction` PendingIntent fired by a host on your behalf  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 (any app able to obtain slic · A slice's `primaryAction` is a PendingIntent built by the app, handed to a host (Assistant, search) and fired …</sub>

**🟧 High ceiling**

- [ ] **`D08-047`** PendingIntent handed out over AIDL, `IntentSender` or a `Bundle` extra  
   <sub>``broken_access_control.privilege_escalation` (null, CWE-269)` · AM-03 (no user grant needed — this · The notification drawer is the famous acquisition route and the weakest one, because it costs a user grant. Th…</sub>
- [ ] **`D08-048`** Background-activity-launch opt-ins on a PendingIntent handed to third parties  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the phishing ` · AM-03, AM-08 · Android 15 blocks background activity launches from PendingIntents by default. An app that opts back in — espe…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-049`** Notification trampoline removal that traded a UX bug for this one  
   <sub>`inherits the PendingIntent finding it enables` · AM-04 · At targetSdk 31 a service or receiver used as a notification trampoline may not call `startActivity()`. The co…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-050`** Payment PendingIntent replay and misrouting, composed  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-03, AM-04 · Compose D08-042 and D08-043 against the payment flow specifically, because that is where the two combine into …</sub>

**⬜ Support ceiling**

- [ ] **`D08-051`** Control for Android 15 force-stop cancelling PendingIntents  
   <sub>AM-12 · On Android 15+ the system cancels **all** of an app's pending intents when it enters the stopped state. Force-…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-052`** PendingIntent whose base Intent carries `FLAG_GRANT_*` — `send()` issues the grant  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-03, AM-04 · The two halves of this chapter meet here. A PendingIntent fires **as the creator**, so a fill-in that adds `FL…</sub>

**🟧 High ceiling**

- [ ] **`D08-053`** `grantUriPermission()` called with a caller-supplied package name  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · The app-initiated version of the grant bug. Code that calls `grantUriPermission(callerPackage, uri, flags)` us…</sub>
- [ ] **`D08-054`** Outbound implicit intent carrying grant flags → resolver hijack  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) or` · AM-03 · The direction nobody tests: the target **sending** an implicit intent that carries `FLAG_GRANT_READ_URI_PERMIS…</sub>
- [ ] **`D08-055`** Persistable grant retention after the share is "over"  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-03 + one user share action · The lifecycle question nobody asks. When the target shares a `content://` URI with `FLAG_GRANT_PERSISTABLE_URI…</sub>

**🟨 Medium ceiling**

- [ ] **`D08-056`** `android:requireContentUriPermissionFromCaller` absent on a URI-consuming activity  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 15 lets an activity declare that the *caller* must already hold permission on any `content://` URI it …</sub>

**🟧 High ceiling**

- [ ] **`D08-057`** `ComponentCaller` checked in `onCreate` but not in `onNewIntent`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_authe` · AM-03 · Android 15 finally gives activities a real caller identity. The new bug is where the check is placed. A `singl…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-058`** Inbound `content://` URI consumed without `checkUriPermission` / authority validation  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — ` · AM-03 · The proxy-read direction. The app receives a URI and reads it on the caller's behalf, either from its **own in…</sub>

**🟧 High ceiling**

- [ ] **`D08-059`** `getCallingActivity()` non-null used as an authentication signal  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if t` · AM-03 · `getCallingActivity()` is populated only for `startActivityForResult()`, and its contents are attacker-control…</sub>
- [ ] **`D08-060`** `android.intent.extra.REFERRER` or a caller-supplied "source app" string trusted  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · Because `getCallingPackage()` is null for plain `startActivity`, developers reach for the spoofable extra inst…</sub>

**🟥 Critical ceiling**

- [ ] **`D08-061`** GMS SMS User Consent receiver as an arbitrary-Intent-launch gadget  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 (attacker app declares **onl · The broadcast carries `SmsRetriever.EXTRA_CONSENT_INTENT` — an `Intent` the app is *expected* to start. An exp…</sub>

**⬜ Support ceiling**

- [ ] **`D08-062`** The byte-returning gadget — prove exfiltration, not a proxied read  
   <sub>`n/a (governance) — it is what separates `sensitive_data_exposure.disclosure_of` · Separate a real exfiltration primitive from one where the victim reads its own file and **nothing crosses the …</sub>
- [ ] **`D08-063`** Marker discipline and the paired-refusal control on every redirection claim  
   <sub>`n/a (false-positive discipline)` · Two failure modes kill redirection reports in triage. First, attributing a launch to your payload when the app…</sub>
- [ ] **`D08-064`** Counted sweeps and the two-stack reproduction bar  
   <sub>`n/a (method)` · The D08-001 join is a loop over hundreds of grep hits, and a zsh array loop that iterates zero times prints no…</sub>
- [ ] **`D08-065`** Pre-severity gate against the Critical claim, not against the bug  
   <sub>`n/a (governance)` · Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each question. Thi…</sub>
- [ ] **`D08-066`** Evidence package, chain-filing order and the severity-request paragraph  
   <sub>`n/a (deliverable and submission mechanics)` · A redirection finding is a state change (a component ran, a grant was issued, a transaction repeated), so one …</sub>

<details><summary>⚰️ D08 graveyard — do not submit these standalone</summary>

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

</details>


<details><summary>🔗 D08 cross-surface joins — park these, chase them in P7</summary>

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

</details>


---

## D09 Deep Links, App Links & Custom URI Schemes

**Phase P5 · `M5` · 80 items** — 🟥 22 critical · 🟧 30 high · 🟨 9 medium · 🟩 1 low · ⬜ 18 support  

📄 Full detail, with every command and proof: [`checklist/D09-deeplinks-and-applinks.md`](checklist/D09-deeplinks-and-applinks.md)

> **Crux question.** **Does any URI an attacker can put in front of the victim — a web link, a QR code, a push payload, another app's intent — reach a parser inside this app that hands attacker-controlled bytes to a sink that runs with the user's session, and is the entry point ownership-verified on the device or merely claimed in the manifest?**

Three things make deep links the highest-yield mobile-native surface. First, the attacker model: a deep link
is **AM-02**, remote with one click, which is the strongest model any purely client-side Android bug reaches.
Nothing else in the checklist converts a manifest line into "any web page the victim visits" for free.
Second, the base rate of a *correct* validator is low — Liu et al. (USENIX Security 2017, cited in the corpus)
measured that **only two percent of Android apps shipping deep links passed full App Link verification**, and
Oversecured's own deep-link taxonomy exists because the same five bypasses keep working. Third, the payouts
are real and public: KAYAK #1667998 (**Critical 9.3**, one-click ATO via `EXTRA_REDIRECT_URL`), Basecamp
#1372667 (**High 8.7, $6,337**, `proceed_to` surviving the internal-URL check), Grab #401793
(**High 7.1, $7,500** per Intigriti's write-up, deep link → WebView → `getGrabUser` bridge), TikTok #2417516
(**High 8.1, CVE-2024-45240**), Zomato #532225 (High, $750), Periscope #583987 (Low, but **$1,540** — and the
iOS twin #805073 paid **$2,940**).


**⬜ Support ceiling**

- [ ] **`D09-001`** Census every BROWSABLE filter in the merged manifest, resolving string references  
   <sub>`none — inventory feeding `broken_access_control.exposed_sensitive_android_inte` · AM-02, AM-03 · Produce the complete `scheme://host:port/path → component` table from the **merged** manifest, not from source…</sub>

**🟨 Medium ceiling**

- [ ] **`D09-002`** Expand the `<data>` cross-product — attributes merge, they do not pair  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-02, AM-03 · Android documents this verbatim: "All the `<data>` elements contained within the same `<intent-filter>` elemen…</sub>

**⬜ Support ceiling**

- [ ] **`D09-003`** Attribute every scheme to the AAR that contributed it  
   <sub>`none — inventory feeding `broken_access_control.exposed_sensitive_android_inte` · AM-03, AM-08 · The client's engineers can account for the schemes they wrote. They cannot account for the ones an AAR merged …</sub>
- [ ] **`D09-004`** Enumerate the routes declared in code, not in the manifest  
   <sub>`none — inventory` · AM-02, AM-03 · The manifest names the *doorway*; the route table is in code. The common shape is one trampoline activity clai…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-005`** Schemes the app emits but never registers  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · The inverse of squatting, and structurally invisible to a manifest review. The app *sends* a URI on a scheme i…</sub>

**⬜ Support ceiling**

- [ ] **`D09-006`** Classify every entry point by its ownership proof before rating anything  
   <sub>`none — the classifier that decides which VRT path every later item uses` · AM-02 vs AM-03 — this item is what · Three classes with three different attacker stories. **(a) Verified App Link** — `https`, `autoVerify="true"`,…</sub>
- [ ] **`D09-007`** Prove browser reachability, not adb reachability  
   <sub>`none — the evidence rule that sets the attacker model on every other item` · AM-02 · `adb shell am start` runs as `shell`, which holds more privilege than any real attacker and bypasses resolutio…</sub>
- [ ] **`D09-008`** Per-browser `intent://` capability matrix  
   <sub>`none — reach calibration for every AM-02 claim` · AM-02 · "A web page can fire an `intent://`" is not one capability. Chrome, Firefox, Samsung Internet and every embedd…</sub>

**🟧 High ceiling**

- [ ] **`D09-009`** Flutter: `flutter_deeplinking_enabled` defaults to ON, so jadx shows you nothing  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on the ` · AM-02, AM-03 · `FlutterActivityLaunchConfigs.deepLinkEnabled(metaData)` returns **true when the key is missing**. So a Flutte…</sub>
- [ ] **`D09-010`** React Native: the Java→JS `Linking` handoff  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-02, AM-03 · In RN the URI crosses a boundary: Java `ReactActivity` receives it, JS consumes it. The validator, if any, liv…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-011`** Cordova / Capacitor: `appUrlOpen`, `allow-navigation` and `server.url`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · In a Cordova/Capacitor app the *entire app* is one WebView with the plugin bridge attached. If a deep link, an…</sub>

**⬜ Support ceiling**

- [ ] **`D09-012`** Runtime handler discovery — hook `Intent.getData()` with a stack trace  
   <sub>`none — instrumentation that converts an enumerated scheme into a proven sink` · AM-12 own device (evidence tool, n · Stop guessing parameter names. Observe every URI the app consumes *and constructs*, and — the whole point — ge…</sub>
- [ ] **`D09-013`** Fire the whole URI corpus and record where each one lands  
   <sub>`none — candidate generation for D09-059 onwards` · AM-03 (discovery only — re-prove p · Mechanically fire every declared URI plus its mutation set, recording the resolved activity for each. The deli…</sub>

**🟧 High ceiling**

- [ ] **`D09-014`** `pm get-app-links` — the on-device verification state is the only truth  
   <sub>`no VRT node for App Links — file the consequence: `server_security_misconfigur` · AM-03 (a competing app wins the ch · `android:autoVerify="true"` is a *request*, not a result. The real state lives in the package manager, per hos…</sub>
- [ ] **`D09-015`** Fetch `assetlinks.json` for every declared host and diff the fingerprint  
   <sub>`file the consequence — `broken_access_control.exposed_sensitive_android_intent` · AM-03 · The required statement shape is exact. Fetch it for **every** declared host — each subdomain needs its own fil…</sub>
- [ ] **`D09-016`** Play App Signing: the fingerprint you checked may be the wrong certificate  
   <sub>`consequence-rated; the mechanism is a verifiable App Links break` · AM-03 · With Play App Signing the developer signs the bundle with the **upload key**, and Google re-signs the APKs use…</sub>
- [ ] **`D09-017`** The Digital Asset Links failure taxonomy — redirects, transport, JSON, per-host files  
   <sub>`consequence-rated (see D09-014)` · AM-03 · When `pm get-app-links` says a host is not verified, the report is only useful if you name the cause. The docu…</sub>
- [ ] **`D09-018`** Wildcard or extra `package_name` in the statement file  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentic` · AM-03, AM-08 · The statement is an allow-list of packages permitted to handle the domain's URLs. Read every entry, not just t…</sub>
- [ ] **`D09-019`** Stale `sha256_cert_fingerprints` after a signing-key rotation  
   <sub>`consequence-rated; the retired key remains trusted for domain handling` · AM-03 (with the retired key), AM-0 · Statements accumulate fingerprints; nobody removes them. A fingerprint that corresponds to a retired signing k…</sub>
- [ ] **`D09-020`** A statement host the vendor no longer owns, or a dangling subdomain  
   <sub>``server_security_misconfiguration.misconfigured_dns.subdomain_takeover` (P3) f` · AM-01 for the takeover, AM-02 for  · Static analysis structurally cannot find this. A host in the manifest — or a CNAME behind it — may point at a …</sub>
- [ ] **`D09-021`** Pre-Android-12 verification poisoning: one bad filter de-verifies every host  
   <sub>`consequence-rated` · AM-03 · On pre-12 devices verification was all-or-nothing across the app. One dead subdomain, one forgotten `http` fil…</sub>
- [ ] **`D09-022`** A custom scheme declared inside an `autoVerify` intent filter  
   <sub>`consequence-rated` · AM-03 · A custom scheme can never be auto-verified. Putting one in the same filter as the verified https data elements…</sub>

**⬜ Support ceiling**

- [ ] **`D09-023`** Re-verification cadence — write the remediation-verification clause correctly  
   <sub>`none — report-quality item that decides whether your retest is valid` · Two traps. (1) You fix-verify too early: on Android 15+ the client's corrected statement file may take up to a…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-024`** Third-party link domains: curl the SDK's `assetlinks.json`, not only the client's  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · The app registers the *vendor's* domain in its manifest, but the statement file on that domain is served by th…</sub>

**🟧 High ceiling**

- [ ] **`D09-025`** `assetlinks.json` relation confusion: link handling versus credential sharing  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if a` · AM-03, AM-09 · Two distinct relations live in the same file: `delegate_permission/common.handle_all_urls` governs App Link ha…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-026`** Custom-scheme squat from the zero-permission attacker app  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 · Declare the target's scheme in your own app and see what arrives. This is the base primitive for every interce…</sub>
- [ ] **`D09-027`** Unverified https host squat with a matching `pathPattern`  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-03 · An unverified https link is an ordinary implicit intent. Register the exact host and path pattern of the app's…</sub>
- [ ] **`D09-028`** OAuth authorization-code interception over a custom-scheme redirect  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2` · AM-03 · Extract the real `redirect_uri` from the `/authorize` request in the proxy (not from the manifest — they diffe…</sub>

**🟧 High ceiling**

- [ ] **`D09-029`** PKCE not enforced at the token endpoint (the reportable half)  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2` · AM-03 (the interceptor), AM-01 aga · PKCE is only a control if the server enforces it. Four probes, in order.</sub>
- [ ] **`D09-030`** Predictable PKCE code verifier  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover`` · AM-03 · PKCE protects a code only if the verifier is unguessable. `java.util.Random`, `Math.random()`, a time-seeded g…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-031`** Magic-link / one-tap-login token interception  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-03 · Find every flow that mints a bearer credential into a URL, then check whether that URL travels on a class (b) …</sub>

**⬜ Support ceiling**

- [ ] **`D09-032`** `android:priority` is capped — do not claim a priority win  
   <sub>`none — false-positive prevention on every squat claim` · Half the public write-ups say "register with `android:priority="999"` and you win". A non-privileged third-par…</sub>

**🟧 High ceiling**

- [ ] **`D09-033`** Android 12+ web-intent resolution, and the custom scheme added to work around it  
   <sub>`consequence-rated; the workaround scheme is a class (c) entry point` · AM-03 (app-to-app), AM-02 (the lin · Two consequences of the Android 12 change that testers get backwards. (1) An unverified https link no longer r…</sub>
- [ ] **`D09-034`** Scheme collision across every app that embeds the same SDK  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2` · AM-03, AM-08 · When an SDK registers a fixed scheme rather than a per-app one, every app embedding that SDK claims the same s…</sub>
- [ ] **`D09-035`** Deferred deep links from an attribution SDK — a router input the OS never validated  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on the ` · AM-09 (the SDK's backend or whoeve · A deferred deep link never travels as an `Intent`. The SDK resolves it server-side (or from the install referr…</sub>
- [ ] **`D09-036`** `INSTALL_REFERRER` payload trusted for routing or entitlement  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) for the routin` · AM-01 (anyone who can construct th · The Play install-referrer string is whatever the referring URL said — fully attacker-controlled, delivered bef…</sub>
- [ ] **`D09-037`** QR / barcode scan treated as a trusted deep-link source  
   <sub>`consequence-rated; `broken_access_control.exposed_sensitive_android_intent` (n` · AM-02 (a printed sticker over a le · A scanner is an unauthenticated physical-world input channel that usually terminates in the app's most powerfu…</sub>

**⬜ Support ceiling**

- [ ] **`D09-038`** NFC tag as the delivery vehicle  
   <sub>`consequence-rated` · AM-02 variant — one physical tap,  · A printed tag costs cents and works on a victim who would never tap a link. Check whether the app registers `A…</sub>

**🟧 High ceiling**

- [ ] **`D09-039`** Notification-origin trust signature on privileged deep-link routes  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentic` · AM-02 (a web link carrying a forge · Some routers unlock a privileged route set only when the link "came from a notification", proven by a signatur…</sub>
- [ ] **`D09-040`** Retired routes that still resolve: pinned shortcuts and instant-app-era paths  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentic` · AM-04 (launcher/shortcut access),  · Two retired-route classes nobody tests, because the tester upgrades the app by reinstalling — which is exactly…</sub>

**⬜ Support ceiling**

- [ ] **`D09-041`** Trace the router: URI → parser → route → sink, and produce the route table  
   <sub>`none — the artefact every later item cites` · AM-02, AM-03 · Follow how the entry activity turns the `Uri` into an internal route, and write the table. Without it you are …</sub>

**🟥 Critical ceiling**

- [ ] **`D09-042`** Host validation by `startsWith` / `endsWith` / `contains` — run the whole matrix  
   <sub>`set by the sink: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_a` · AM-02 · Almost every app that validates a URL validates it wrongly. Find the predicate, then run the **whole** matrix …</sub>
- [ ] **`D09-043`** The host is checked and the scheme is not  
   <sub>``server_side_injection.file_inclusion.local` (P1) for `file://`; `cross_site_s` · AM-02 · The most common half-validation: the code extracts `getHost()`, compares it correctly, and never looks at the …</sub>

**🟧 High ceiling**

- [ ] **`D09-044`** Backslash and userinfo divergence between `Uri.parse().getHost()` and the loader  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · `Uri.parse("https://attacker.example\\@trusted.example").getHost()` returns `trusted.example` while `WebView.l…</sub>
- [ ] **`D09-045`** `Uri` object smuggling via reflection (`HierarchicalUri`)  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) → the sink's p` · AM-03 (requires app-to-app deliver · When a third-party app (not a browser) hands the victim a `Uri` **object** in an intent, that object can be bu…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-046`** Parser-differential sweep: where the validator's parse and the sink's parse disagree  
   <sub>`inherits the sink — `sensitive_data_exposure.disclosure_of_secrets.for_publicl` · AM-02 · Stop trying one malformed URL. The bug class is **two parsers, one string**: `android.net.Uri` at the validato…</sub>

**🟧 High ceiling**

- [ ] **`D09-047`** Java validator versus JS/Dart router — the cross-boundary differential  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) → the framewor` · AM-02, AM-03 · Two parsers again, but now in two languages with different URL semantics: `android.net.Uri` on the Java side, …</sub>
- [ ] **`D09-048`** `pathPattern` glob semantics — no backtracking, lazy `.*`, greedy `*`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — rated on the` · AM-02 · `pathPattern` is not a regex and does not behave like one. Developers write a pattern believing it matches mor…</sub>

**🟨 Medium ceiling**

- [ ] **`D09-049`** `pathPrefix` escape via `../` in the path  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) — rated on wha` · AM-02 · The filter matches on the *literal* path, but the handler (or the WebView it hands the URL to) normalises `../…</sub>

**🟧 High ceiling**

- [ ] **`D09-050`** Host wildcards, case sensitivity, trailing dots and Unicode  
   <sub>`consequence-rated; chains with `server_security_misconfiguration.misconfigured` · AM-02 · Four separate mistakes live in `android:host`. A wildcard admitting an unmanaged subdomain; an uppercase host …</sub>

**🟨 Medium ceiling**

- [ ] **`D09-051`** `UriRelativeFilterGroup` exclusion rules bypassed by encoding  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-02 · Android 15 added precise intent filters that match on query parameters and fragments, including **exclusion** …</sub>
- [ ] **`D09-052`** `allowNullAction` — an action-less intent takes a different branch  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 16's default hardening rejects action-less intents against intent filters. `allowNullAction` re-permit…</sub>

**🟧 High ceiling**

- [ ] **`D09-053`** `enforceIntentFilter` absent: an explicit `VIEW` with an arbitrary URI  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 (local app; browser delivery · Without `enforceIntentFilter`, a local app can send an **explicit** `ACTION_VIEW` intent carrying an *arbitrar…</sub>
- [ ] **`D09-054`** `intentMatchingFlags="none"` — a hole punched in the app's own hardening  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · The security-relevant pattern is an app that sets `enforceIntentFilter` globally and then sets `android:intent…</sub>

**🟨 Medium ceiling**

- [ ] **`D09-055`** Over-broad path scope on a correctly verified App Link  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) → the sink's p` · AM-02 · When `pm get-app-links` says `verified`, interception is genuinely closed and D09-026/-027 are dead. Do not st…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-056`** An expired or registrable domain inside the code-side allow-list  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (register the domain), AM-02 · The allow-list is not bypassed; it is *correct*, and one of its entries is a domain the original owner let lap…</sub>
- [ ] **`D09-057`** Shared-tenant wildcard hosts in the allow-list  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · Validation that accepts `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.herokuapp.com`, `*.github.io`, `*.…</sub>

**🟧 High ceiling**

- [ ] **`D09-058`** Router traversal inside the route or path segment  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); `broken_acces` · AM-02 · When the router builds an API path or an internal route by string-concatenating a URI segment, a traversal in …</sub>

**🟥 Critical ceiling**

- [ ] **`D09-059`** A deep-link parameter becomes the URL of a session-bearing WebView  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · The single most-paid Android bug class in the corpus. A `scheme://host?url=` route loads your value in a WebVi…</sub>
- [ ] **`D09-060`** `loadUrl(url, headers)` — the app attaches its auth headers to your origin  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · The two-argument `loadUrl` overload attaches a header map to the request. If the URL is attacker-steerable, th…</sub>
- [ ] **`D09-061`** A redirect parameter followed *after* the internal-URL check  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · The app decides "is this URL internal?" **on the wrapper**, then extracts and follows a redirect parameter *af…</sub>
- [ ] **`D09-062`** The app appends the session to *your* URL  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · The inverse of the redirect bug. The app does not load your URL blindly — it *builds* a URL from your value an…</sub>
- [ ] **`D09-063`** `file://` or `content://` pushed through the router into a reading sink  
   <sub>``server_side_injection.file_inclusion.local`` · AM-02 · The same `url=`/`path=`/`filepath=` parameter that feeds a WebView often also feeds a file API. Test both sink…</sub>

**🟨 Medium ceiling**

- [ ] **`D09-064`** Path traversal in a deep-link parameter used as a save path  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_extern` · AM-02 (an in-product link; no mali · A deep link that takes a `filename` and writes the response to it. Traverse out of the private directory into …</sub>

**🟥 Critical ceiling**

- [ ] **`D09-065`** `intent://` smuggling and `Intent.parseUri` inside the deep-link handler  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) → P1 by what t` · AM-02 (delivered from a web page — · `Intent.parseUri()` reconstructs a full `Intent` — component, action, flags and extras — from a string. A deep…</sub>
- [ ] **`D09-066`** A deep link performs a state-changing action with no confirmation  
   <sub>``cross_site_request_forgery_csrf.action_specific.authenticated_action` (varies` · AM-02 · Web endpoints have CSRF tokens; their deep-link equivalents usually do not. Any page the victim visits can mak…</sub>

**🟧 High ceiling**

- [ ] **`D09-067`** A deep link reaches an authenticated screen when fired cold  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if i` · AM-02, AM-03 · Deep links bypass the navigation graph. An activity that assumes "the user got here through login" is reachabl…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-068`** A deep-link parameter is an object identifier the server does not authorise  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 (another user of the same ap · The deep-link router is often the most convenient place to find the app's object identifiers, because the rout…</sub>

**🟨 Medium ceiling**

- [ ] **`D09-069`** A reserved or sentinel value reachable from a URI  
   <sub>`consequence-rated — business logic; file under the affected flow` · AM-02 · Transfer, entitlement and pricing models reserve magic strings — `(all)`, `max`, `-1`, `unlimited`, `null`, `d…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-070`** A deep-link parameter switches the backend host or environment  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · A parameter such as `env=`, `endpoint=`, `baseUrl=`, `server=`, `host=`, `cluster=` or `region=` that reaches …</sub>

**🟨 Medium ceiling**

- [ ] **`D09-071`** A deep-link parameter drives a device-side request to an attacker or internal host  
   <sub>``server_security_misconfiguration.server_side_request_forgery_ssrf.internal_da` · AM-02 · Two distinct cases, and conflating them is a common reporting error. **(a)** The parameter is forwarded to the…</sub>
- [ ] **`D09-072`** Deep-link parameters persisted to logcat, Recents or analytics  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when a` · AM-04 (a crash-reporting SDK or an · Fire a token-bearing link with a unique marker and see where the marker ends up. The high-value case is not lo…</sub>

**🟩 Low ceiling**

- [ ] **`D09-073`** A deep link that crashes the handler — and whether the session dies with it  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-02 · Crash-only is worth zero. Crash-plus-logout is a paid DoS. The whole test is the second half, and almost nobod…</sub>

**🟥 Critical ceiling**

- [ ] **`D09-074`** Shadow API: the route's backend call is an older API version than the web app uses  
   <sub>`whichever control is weakened: `broken_authentication_and_session_management.a` · AM-05, AM-01 · This is the highest-value structural idea for a mobile engagement, and the deep-link router is the cheapest pl…</sub>

**⬜ Support ceiling**

- [ ] **`D09-075`** Bound the finding by what the NEXT layer does, before you rate it  
   <sub>`none — rating discipline that moves findings a whole band in both directions` · A weak native shell can still be defanged by the framework or server layer. Unvalidated raw-URI injection is a…</sub>
- [ ] **`D09-076`** Prove AM-03 from the attacker app and AM-02 from a page — `adb` proves neither  
   <sub>`none — the evidence rule that decides the attacker model on every finding` · AM-02 / AM-03 (this item is how yo · `adb shell am start` runs as `shell`, a UID with far more privilege than any attacker in the threat model. Dis…</sub>
- [ ] **`D09-077`** The layer-ordering trap when you replay an intercepted token  
   <sub>`none — kill gate that prevents a false Critical` · You intercepted a token (D09-026 → D09-031) and replayed it, and the API answered `400 {"message":"accountId i…</sub>
- [ ] **`D09-078`** False-positive discipline on the router sweep  
   <sub>`none — the discipline that keeps your validity ratio` · Four specific ways a deep-link finding turns out to be nothing, and the control for each. 1. **Marker collisio…</sub>
- [ ] **`D09-079`** Evidence standard for a deep-link finding  
   <sub>`none — submission quality` · A deep-link ATO is a state change, and a state change needs five artefacts, not one. And because the PoC neces…</sub>
- [ ] **`D09-080`** Pre-severity gate, chain-filing order, and the programme's deep-link stance  
   <sub>`none — the item that decides whether the chapter's work converts into paid fin` · Three gates, in order, before you submit anything from this chapter: scope, the pre-severity gate run against …</sub>

<details><summary>⚰️ D09 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `android:autoVerify="true"` missing on an `https` filter | The VRT has no node for it; Reddit excludes it by name ("due to current Google limitation with AMP"); on Android 12+ the link goes to the browser rather than to a chooser | A demonstrated interception of a token-bearing link by a stub app that registers the same host (D09-027), with `pm get-app-links` showing the state |
| `pm get-app-links` shows `legacy_failure` and nothing else was tested | Configuration observation; no attacker has done anything | The same host receiving an OAuth code, magic link or reset token in your stub app, and that artefact redeemed (D09-024, D09-031) |
| The app registers a custom scheme | Custom schemes are universal and expected on Android; their existence is not a defect | The scheme carries a credential, code or token, and you captured it during a real flow (D09-026) |
| A disambiguation chooser appears when you install a competing app | That is the platform working as designed; it is the *mechanism*, not the impact | The user-selectable chooser leading to your app receiving a live secret, or your app being the only handler so no chooser appears at all |
| `android:priority="999"` in your PoC "wins" | Priority is documented as capped to 0 for `ACTION_VIEW`/`SEND`/`SENDTO`/`SEND_MULTIPLE` from a non-privileged app — the claim is refutable from the documentation (D09-032) | Report the win condition that actually applies: sole handler, chooser selection, or an existing user default |
| A deep link crashes the app | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**; Nextcloud #3399016 scored **0.0** | The crash invalidates the session or destroys stored state (Yelp #3829030, Low 3.3), or it is persistent crash-on-launch reachable from a plain web link (D09-073) |
| Open redirect from a deep-link parameter, with nothing behind it | On the never-submit list as a standalone; `unvalidated_redirects_and_forwards.open_redirect.get_based` is P4 at best | The redirect target is an OAuth `redirect_uri`, or the app attaches its session headers to the redirected origin (D09-060), or the loaded origin reaches a JS bridge (D10) |
| OAuth `client_secret` found hardcoded in the APK | Known and expected for a public client; `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` is **P5** and the class is on the never-submit list | **PKCE non-enforcement** at the token endpoint is the reportable finding instead (D09-029) |
| An enumerated list of schemes, hosts and paths | Inventory. Necessary, but it is the worksheet, not the report | Any row of it traced to a sink and fired (D09-041 onwards) |
| A deep link opens an in-app screen the user could have reached anyway | No boundary crossed | The same route reached with **no session** (D09-067), with **another user's identifier** (D09-068), or performing an action with no confirmation (D09-066) |
| `Intent.getData()` used without validation, sink unknown | Pattern-matching, not a finding; MASTG explicitly carves out apps that intentionally accept arbitrary values (a search scheme) | The traced sink: `loadUrl`, a file API, `parseUri`, a base-URL setter, or a state change |
| A QR code containing a deep link is accepted by the scanner | Scanners accept codes; that is their function | The scanned URI reaching a sink with no confirmation that names the destination (D09-037) |
| A deferred deep link from an attribution SDK routes the user | Attribution routing is the SDK's purpose | The SDK-supplied value reaching a privileged route or a WebView URL that the intent path validates and this path does not (D09-035) |
| `enforceIntentFilter` absent on a pre-Android-16 target | The attribute does not exist below API 36 — its absence there is a platform limitation, not a defect | The app targets 36+ and a sibling app in the same family sets it (D09-053), or a component carries `intentMatchingFlags="none"` inside a hardened application (D09-054) |
| "A malicious app could register this scheme" with no PoC app built | Assertion, not evidence; and it is precisely the class Starbucks and Grab exclude | The stub app installed, the real flow run, the secret captured, and the secret redeemed |

</details>


<details><summary>🔗 D09 cross-surface joins — park these, chase them in P7</summary>

- **D09 (router) × D10 (bridge) — the single highest-yield join in mobile.** A deep link whose `url=` /
  `web_view_url=` / `page=` parameter reaches `loadUrl` on a *bridged* WebView is the delivery half; the
  token-returning `@JavascriptInterface` method is the payload half. Neither is filed alone. Nobody reviews
  the deep-link route table and the bridge method inventory in the same sitting, which is exactly why the
  Grab, Basecamp and TikTok reports exist. File the router primitive first (its id exists), then the bridge
  finding as the consumer, then backfill (D09-080).
- **D09 × D02/D03 (signing and manifest) — the fingerprint join.** The signer SHA-256 you capture once in
  D02 is the input to three unrelated checks: the `assetlinks.json` comparison here (D09-015), the
  `protectionLevel="signature"` analysis in D03/D06, and the API-key restriction check in D18. The specific
  trap nobody joins up: with **Play App Signing** the statement may list the *upload* key, so App Links fail
  for every real user while passing on the developer's machine (D09-016) — and the same wrong fingerprint
  silently unrestricts a Maps or Firebase key.
- **D09 × D01/D18 (infrastructure) — the allow-list-decay join.** The app's trusted-host list and the org's
  DNS inventory are owned by different teams and never compared. A lapsed registration or a dangling CNAME
  inside the allow-list (D09-056) or inside `assetlinks.json` (D09-020) converts a *correct* validator into an
  attacker-controlled origin with the app's headers attached. Static analysis structurally cannot find this;
  only a WHOIS/DNS sweep of the extracted host list can.
- **D09 × D24 (push/FCM) — the notification-trust join.** Routes gated on "this came from a notification"
  are gated on a signature whose key is often in the APK (D09-039). Join it the other way too: a notification
  listener with the user's grant reads a deep link **and its one-time token** out of `Notification.extras`,
  then replays the route itself. The push team and the router team each assume the other validates.
- **D09 × D13 (OAuth) × D10 (WebView allow-list) — the three-way.** (1) An unverified deep-link host is
  claimable by an attacker app. (2) The in-app WebView's "is this our domain" classifier accepts a lookalike.
  (3) The OAuth `redirect_uri` allow-list accepts a path or subdomain that one of the first two controls.
  **Any two of the three is enough**, and each is owned by a different reviewer.
- **D09 × D23 (payments) — the sentinel join.** The transfer model's reserved strings (`(all)`, `max`,
  negative amounts) are reviewed as a business-logic surface, while the URI router is reviewed as an IPC
  surface. The join is whether any URI parameter reaches a reserved value with a different parser than the
  in-app form uses (D09-069) — Monero's case exactly.
- **D09 × D15 (backend) — the shadow-API join.** The deep-link route table is the cheapest endpoint
  inventory in the engagement, because each route names its call. The mobile app's hardcoded backend is
  frequently an **older API version** than the current web app's, with weaker auth, weaker rate limits and
  more field exposure. Diff behaviourally, not by response shape; the weakened control is the finding, a
  version difference alone is Informational (D09-074). And when you replay an intercepted token, run the
  layer-ordering control first (D09-077).
- **D09 × D19 (cross-platform) — the two-parser join.** In Flutter and React Native the Java shell and the
  Dart/JS router parse the same URI with different libraries. A Java reviewer sees a validator and closes the
  surface; a framework reviewer sees a router and assumes the native side filtered. The bug lives in the
  disagreement (D09-047), and `flutter_deeplinking_enabled` defaulting to **true** (D09-009) means the
  handoff exists even when the Java side appears empty.
- **D09 × D04 (task and UI redress) — the plausibility join.** A deep link that lands an attacker-controlled
  screen inside the victim app's *task* (via `taskAffinity`/`singleTask`) makes the phishing surface wear the
  app's own chrome and back stack. Neither surface is interesting alone; together, a link becomes a credible
  credential-capture screen the user cannot distinguish from the real one.
- **D09 × D20/D25 (physical and ambient delivery).** QR stickers (D09-037) and NFC tags (D09-038) deliver the
  *same* router payload to a victim who would never tap a link — and from Android 16 an `http(s)` NFC tag
  reaches ordinary App Link filters with no NFC declaration at all. The router review and the "do we have a
  scanner?" question are never asked together.

</details>


---

## D10 WebView & JavaScript Bridges

**Phase P5 · `M5` · 72 items** — 🟥 26 critical · 🟧 35 high · 🟨 5 medium · 🟩 1 low · ⬜ 5 support  

📄 Full detail, with every command and proof: [`checklist/D10-webview-and-js-bridges.md`](checklist/D10-webview-and-js-bridges.md)

> **Crux question.** **Can attacker-influenced content — a deep-link `url=`, an open redirect on the allowed origin, a third-party iframe, a MitM'd subresource, a stored profile field, a malicious `content://` — end up executing JavaScript inside a WebView that also carries a JS bridge, the app's session cookies, file/content access, or a real web origin; and if so, what is the single most sensitive thing that reachable context can read or do?**

Three bodies buy this class by name and the base rate is high. Google's App Security Improvement
programme has run WebView campaigns since 2015: *Webview SSLErrorHandler* (2015-07-17, `answer/7071387`),
*File-based Cross-Site Scripting* (2018-06-05, `answer/7668153`), *JavaScript Interface Injection*
(2018-12-04, `answer/9095419`) and *Cross App Scripting* (2018-10-30, `answer/9084685`) — Google itself
measures each base rate as high enough for a store-wide remediation deadline, and FireEye's *JS-Binding-Over-HTTP*
research found "at least 47% of the top 40 ad libraries" carried the interface bug in an actively-used version.
On HackerOne the paid shapes are dense: TikTok #1065500 (**Critical 9.6**, WebView chain to RCE), #2417516
(High 8.1, **CVE-2024-45240**), LinkedIn #3475626 (High 8.1, static header map leaking cookies), Twitter
#906433 (High 8.1, **CVE-2020-6506** UXSS), Grab #401793 (High 7.1, `getGrabUser` bridge), Basecamp #1343300
(High 7.7), Exness #532836 (`loadDataWithBaseURL` cookie theft), Amazon (`LocalAssetHandler` traversal),
KuCoin (`HybridJsInterface.prompt` trading-as-the-victim, CVSS 4.3 as filed).


**⬜ Support ceiling**

- [ ] **`D10-001`** Map every WebView and audit its WebSettings on the concrete class, not the abstract one  
   <sub>`n/a (enabler; the reachable misconfiguration it uncovers is the finding)` · AM-02 · Locate every WebView activity/fragment, every custom `WebView` subclass, every framework WebView (`RNCWebView`…</sub>
- [ ] **`D10-002`** Locate the single URL/origin validator that gates both loads and bridge attach  
   <sub>`n/a (enabler)` · AM-02 · One class usually decides the security of the whole surface: the URL/allow-list validator that both authorises…</sub>
- [ ] **`D10-003`** Enumerate every `@JavascriptInterface` method and build the bridge→capability table rated by return  
   <sub>`n/a (enabler; the reachable sensitive method is the finding)` · AM-02 · Do not stop at "a bridge exists". Read every annotated method body and classify each by what it reaches: token…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-004`** JS bridge method reachable from attacker-controlled content returns a live credential → ATO  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · With a reachable token-returning method (D10-003) and a way to load attacker content (D10-016+), call the meth…</sub>
- [ ] **`D10-005`** `minSdk<17` `addJavascriptInterface` reflection RCE  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-02 (with cleartext/MitM or a re · Below API 17 an injected object exposes **all public methods** including those inherited from `Object`, so JS …</sub>
- [ ] **`D10-006`** Bridge injected into every frame → cross-origin iframe reaches it (main-frame-only enforcement)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 / AM-09 · `addJavascriptInterface` injects the object into **every frame**, but nav/bridge gates commonly run only under…</sub>
- [ ] **`D10-007`** The same bridge is registered twice and only one variant re-checks origin  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · Apps ship several bridge objects (checkout, BNPL, rewards) under the same or similar JS-visible names. One has…</sub>

**🟧 High ceiling**

- [ ] **`D10-008`** Unvalidated sibling load path (prefetcher, raw WebView, third-party SDK WebView)  
   <sub>``unvalidated_redirects_and_forwards.open_redirect.get_based` (P4) floor; `sens` · AM-02 · A *different* code path loads the same URL without the allow-list, or a raw (non-custom) `WebView` instance sk…</sub>
- [ ] **`D10-009`** Per-call origin guard built on `webView.getUrl()` is unreliable  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · A bridge method that authorises itself by reading `webView.getUrl()` is checking the top-level document URL, n…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-010`** `addWebMessageListener` with a wildcard `allowedOriginRules`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · The modern replacement for `addJavascriptInterface` is `WebViewCompat.addWebMessageListener(webView, jsObjectN…</sub>

**🟧 High ceiling**

- [ ] **`D10-011`** `postWebMessage` / `WebMessagePort.postMessage` with a `*` target origin  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · A `MessageChannel` bridge posting to `"*"` has no origin binding and accepts messages from any frame, includin…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-012`** Dispatcher-style bridge (`invokeMethod`+`handlerName`) reaching a URI→`File` read  
   <sub>``server_security_misconfiguration.path_traversal` (VARIES) → `sensitive_data_e` · AM-02 · A single exported method that deserialises attacker JSON and dispatches on a handler name is a generic gateway…</sub>

**🟧 High ceiling**

- [ ] **`D10-013`** JS bridge file-write method with an unvalidated filename → sandbox path traversal  
   <sub>``server_security_misconfiguration.path_traversal` (VARIES); `server_side_injec` · AM-02 · Bridges that write attacker `content` to `fileName` under cache/files with no canonicalisation let a `../` fil…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-014`** Callback-wrapping to steal a credential-returning bridge result  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · Many bridges return a token asynchronously by invoking a global JS callback (`window.callWebView({action:'refr…</sub>

**⬜ Support ceiling**

- [ ] **`D10-015`** `removeJavascriptInterface()` not called before loading untrusted content (or called too late)  
   <sub>`inherits the bridge severity (D10-004)` · AM-02 · The documented mitigation is to remove the interface before loading untrusted content "such as in `shouldInter…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-016`** Break the URL allow-list validator  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · A weak validator uses `contains`/`endsWith`/`startsWith`, is scheme-blind, or disagrees between the parsed fie…</sub>
- [ ] **`D10-017`** Scheme never validated → `javascript:` / `file:` / `content:` / `data:` accepted  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · Host allow-lists that check the host but never the scheme. Independent of any host bypass — a `javascript:`/`f…</sub>

**🟧 High ceiling**

- [ ] **`D10-018`** JavaScript enabled before the allow-list completes (order-of-checks bug)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · A pipeline of parse → partial-validate → **configure WebView (JS on)** → final-verify → `loadUrl` leaves JavaS…</sub>
- [ ] **`D10-019`** `getReferrer()` / scheme-only check used as authorisation for a bridged WebView  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 / AM-03 · An exported `VIEW`/`BROWSABLE` activity that forwards `url=` into `loadUrl()` while the bridge stays attached …</sub>
- [ ] **`D10-020`** `shouldOverrideUrlLoading` / `shouldInterceptRequest` allow-list blind spots  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · An allow-list enforced only in these callbacks has documented holes. `shouldOverrideUrlLoading` is **not** cal…</sub>
- [ ] **`D10-021`** WebView vs Custom Tab trust-classifier confusion  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · Apps route "our domains" to a bridged WebView (with the session cookie) and "external" links to a Chrome Custo…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-022`** `loadDataWithBaseURL` with an attacker-influenced `baseUrl` (Universal XSS / same-origin session theft)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · `loadDataWithBaseURL(baseUrl, html, ...)` runs `html` in the origin of `baseUrl`. Control both and you have XS…</sub>

**🟧 High ceiling**

- [ ] **`D10-023`** WebView XSS from an Intent extra rendered with `loadData()` / `loadDataWithBaseURL(null,...)`  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) if cross-user; else` · AM-02 / AM-03 · Reading an attacker-controlled extra and injecting it into a WebView via `loadData()`/`loadDataWithBaseURL(nul…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-024`** `onNewIntent` context-reuse UXSS (`javascript:` into a reused WebView)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · `onNewIntent(i){ webView.loadUrl(i.getDataString()); }` on a reused WebView lets an attacker first load a legi…</sub>

**🟧 High ceiling**

- [ ] **`D10-025`** Native→JS string-concatenation injection (`evaluateJavascript` / `loadUrl("javascript:")`)  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) when the concatenat` · AM-02 / AM-05 · Untrusted input concatenated into `evaluateJavascript("f('"+x+"')")` or `loadUrl("javascript:f('"+x+"')")` let…</sub>
- [ ] **`D10-026`** HTML injection into a string-concatenated WebView template  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone`` · AM-02 / AM-05 · Apps that build HTML by concatenation and render it. Any field reaching the template — image URL, title, autho…</sub>
- [ ] **`D10-027`** Stored XSS in server content rendered by a WebView (cross-user)  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone` (P2); Critical when it r` · AM-05 (another user of the same ap · Content the backend returns (article body, chat message, profile field, image title, filename) rendered into a…</sub>
- [ ] **`D10-028`** Second-order WebView XSS through `ContentProvider` metadata  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone`` · AM-03 (malicious local app supplyi · Do not limit source-tracing to Intent extras or file bytes. An app may query an attacker-owned `content://` UR…</sub>
- [ ] **`D10-029`** UXSS via `setSupportMultipleWindows()` default — CVE-2020-6506  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 (one tap/keypress required) · With multi-window support off (the default), a cross-origin iframe can call `window.open()` with a `javascript…</sub>
- [ ] **`D10-030`** `onCreateWindow` / `window.open` child window inheriting the bridge  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · When multi-window is supported, `onCreateWindow` cannot reliably tell which frame requested the window ("the r…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-031`** `setAllowUniversalAccessFromFileURLs` / `setAllowFileAccessFromFileURLs` → XHR file exfiltration  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · With either enabled and any attacker-influenced content reachable, a `file://` page can XHR the app's private …</sub>
- [ ] **`D10-032`** `setAllowFileAccess` + a `file://` load path (get the defaults right)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · `setAllowFileAccess(true)` (or unset on targetSdk < 30) plus JS on plus a `file://` load path lets the page re…</sub>

**🟧 High ceiling**

- [ ] **`D10-033`** `setAllowContentAccess` → WebView reads `content://` providers (including non-exported)  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-02 · With content access on (the default), JS in the WebView can `XMLHttpRequest` any `content://` URI the app can …</sub>

**🟥 Critical ceiling**

- [ ] **`D10-034`** `shouldInterceptRequest` path traversal + wildcard CORS → universal local-file read  
   <sub>``server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.d` · AM-02 · A custom `shouldInterceptRequest` that serves a local file from a user-influenced path — `getLastPathSegment()…</sub>

**⬜ Support ceiling**

- [ ] **`D10-035`** `WebViewAssetLoader` not used where local content is served  
   <sub>`inherits the file-inclusion severity (D10-034/D10-031)` · AM-02 · The recommended replacement serves assets over `https://appassets.androidplatform.net/assets/...` with the fou…</sub>

**🟧 High ceiling**

- [ ] **`D10-036`** WebView loading content from external storage  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 / AM-04 · `webView.loadUrl("file://" + getExternalStorageDirectory() + ...)` renders content any app (pre-scoped storage…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-037`** `onShowFileChooser` implicit-intent interception (malicious picker returns a `file://` URI)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-03 (malicious app registering a · `onShowFileChooser` fires an implicit `GET_CONTENT` via `createIntent()`; if `onActivityResult` passes `data.g…</sub>
- [ ] **`D10-038`** Symlink the WebView cookie DB into a `file://` render path (no-root session theft)  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-03 · Combining a `file://` render path with a symlink turns "XSS in a WebView" into "exfiltrate the raw cookie data…</sub>

**🟧 High ceiling**

- [ ] **`D10-039`** `onReceivedSslError` calling `handler.proceed()` (WebView TLS bypass)  
   <sub>``insecure_data_transport.cleartext_transmission_of_sensitive_data` (VARIES, CW` · AM-06 (network attacker, no truste · An `onReceivedSslError` implementation that calls `handler.proceed()` (or prompts and proceeds) disables certi…</sub>
- [ ] **`D10-040`** `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-06 · `MIXED_CONTENT_ALWAYS_ALLOW` (0) lets an HTTPS page pull HTTP subresources; a network attacker then injects sc…</sub>
- [ ] **`D10-041`** MitM-injected JS into an `http://` WebView page (LEGACY — needs a stated precondition)  
   <sub>`depends on the origin reached; not reproducible on a modern target without a p` · AM-06 · Any 2014–2016-style PoC that MitM-injects JS into an `http://` page in a WebView needs a reachability precondi…</sub>
- [ ] **`D10-042`** `CookieManager.setCookie` to an unvalidated domain (cookie injection)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · `CookieManager.getInstance().setCookie(url, token)` with a non-constant `url` writes a sensitive cookie into t…</sub>
- [ ] **`D10-043`** Static / reused header map leaking cookies across origins  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · A WebView helper that stores the outgoing header map in a **static** field never clears it, so cookies gathere…</sub>
- [ ] **`D10-044`** `setAcceptThirdPartyCookies` on the sign-in / OAuth / checkout WebView  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-02 · `CookieManager.setAcceptThirdPartyCookies(webView, true)` re-enables cross-site cookies inside the app's brows…</sub>
- [ ] **`D10-045`** Modern SameSite default (targetSdk 31) pushing the session token into a URL or bridge  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · At targetSdk 31, WebView treats no-`SameSite` cookies as `Lax` and requires `Secure` for `SameSite=None`. A ba…</sub>
- [ ] **`D10-046`** WebView storage not cleaned up on logout (eternal cookies)  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-03 / AM-10 / AM-11 (needs file  · WebViews persist HTTP cache, DOM storage, IndexedDB, cookies and OPFS/SQLite-Wasm under `/data/data/<pkg>/app_…</sub>

**🟨 Medium ceiling**

- [ ] **`D10-047`** `setSavePassword` / `setSaveFormData` / DOM-storage / DB residue on disk  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 / AM-11 · Check `setSavePassword`, `setSaveFormData`, `setDatabaseEnabled`, `setDomStorageEnabled`, then look at what is…</sub>

**🟧 High ceiling**

- [ ] **`D10-048`** `loadUrl` without `loadUrlWithoutCookies` → session cookies sent to any host  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-02 · Returning `false` from `shouldOverrideUrlLoading` (or not handling a scheme) lets the WebView navigate anywher…</sub>
- [ ] **`D10-049`** `setWebContentsDebuggingEnabled(true)` in a release build  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 (any local process reaching  · `setWebContentsDebuggingEnabled(true)` shipped in release (or enabled process-wide by a library) exposes every…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-050`** `onPermissionRequest` auto-granting camera/microphone to web content  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 · The default `onPermissionRequest` denies. An override calling `request.grant(request.getResources())` uncondit…</sub>

**🟧 High ceiling**

- [ ] **`D10-051`** `onGeolocationPermissionsShowPrompt` / `setGeolocationEnabled` auto-grant  
   <sub>`precise-location disclosure to an attacker origin — rate on impact` · AM-02 · An override of `onGeolocationPermissionsShowPrompt` that calls `callback.invoke(origin, true, true)` silently …</sub>

**🟩 Low ceiling**

- [ ] **`D10-052`** Safe Browsing explicitly disabled  
   <sub>``mobile_security_misconfiguration.*` (P5) alone; Medium as an aggravator with ` · AM-02 · Disabled via manifest meta-data or in code (code takes precedence). Removes the platform's last backstop on a …</sub>

**🟧 High ceiling**

- [ ] **`D10-053`** `setDownloadListener` — attacker-chosen filename path traversal / cookie leak  
   <sub>``server_security_misconfiguration.path_traversal` (VARIES) for the write; `sen` · AM-02 · A WebView cannot download by itself; the app supplies a `DownloadListener` whose callback receives `url`, `con…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-054`** Credential Manager invoked from WebView without origin verification  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-02 · Credential Manager integrates with WebView and the docs are explicit that "when using WebView, proper origin v…</sub>
- [ ] **`D10-055`** Capacitor `/_capacitor_file_` arbitrary app-private file read  
   <sub>``server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.d` · AM-02 (needs script execution in t · Capacitor's local server maps any path starting `/_capacitor_file_` to `new FileInputStream(path)` — prefix st…</sub>
- [ ] **`D10-056`** Capacitor `/_capacitor_http_interceptor_` SOP bypass / SSRF-from-device  
   <sub>``server_side_injection.file_inclusion.local` (P1)-class read primitive; SSRF i` · AM-02 · `/_capacitor_http_interceptor_?u=<absolute-url>` performs the request **natively**, copying the page's request…</sub>
- [ ] **`D10-057`** Capacitor `androidBridge.postMessage` plugin surface (+ `addJavascriptInterface` fallback)  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for a plugin reaching c` · AM-02 · Every registered Capacitor plugin method is invokable from JS by posting a JSON message. Enumerate the plugin …</sub>
- [ ] **`D10-058`** Cordova `_cordovaNative` / `gap:` prompt bridge and its bridge-secret gate  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) if `exec()` succeeds; H` · AM-02 · Cordova exposes `exec()` via `_cordovaNative`, guarded by an integer `bridgeSecret` handed out only to a permi…</sub>
- [ ] **`D10-059`** Cordova `AndroidInsecureFileModeEnabled` — one-preference universal file-read SOP bypass  
   <sub>``server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.d` · AM-02 · This preference switches the WebView back to a `file://` origin **and** sets `setAllowFileAccess(true)` + `set…</sub>

**🟧 High ceiling**

- [ ] **`D10-060`** Cordova `<allow-navigation href="*">` / `<access origin="*">` + missing CSP  
   <sub>`precondition for bridge access — rate on the bridge PoC` · AM-02 · `<allow-navigation href="*">` lets the WebView top-level navigate anywhere including `data:`; `<access origin=…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-061`** React Native `ReactNativeWebView` bridge + re-enabled file-access props  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when `onMessage` routes` · AM-02 · `react-native-webview` installs a `ReactNativeWebView` interface with `postMessage`, and exposes props that re…</sub>

**🟧 High ceiling**

- [ ] **`D10-062`** Cordova-Android < 4.1.1 whitelist redirect bypass / config injection (LEGACY)  
   <sub>`plugin access from an attacker origin → P1-class device/file access` · AM-02 / AM-06 · Fingerprint the Cordova-Android version. Below 4.1.1 the whitelist cannot stop a redirect from a whitelisted o…</sub>

**🟨 Medium ceiling**

- [ ] **`D10-063`** CSP not enforced in the in-app browser (response header vs `<meta>`)  
   <sub>``cross_site_scripting_xss.*` on visited content; higher when it reaches a wall` · AM-02 · An app's embedded browser that ignores the CSP *header* (while honouring the `<meta>` tag) silently removes th…</sub>

**🟧 High ceiling**

- [ ] **`D10-064`** CDN- or remote-served asset loaded into a bridged WebView (supply chain)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-09 (malicious backend/CDN, subd · A WebView that loads remote HTML/JS from a CDN (help centre, promo, terms, campaign) **and** has `addJavascrip…</sub>
- [ ] **`D10-065`** `intent://` handling in `shouldOverrideUrlLoading` → arbitrary activity launch / redirection  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null, rated on what ` · AM-02 (web content already in the  · The handler does `Intent.parseUri(url, 0)` + `startActivity` without resetting component/selector, so **web co…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-066`** Ad / analytics SDK WebView with a JS interface reachable over cleartext  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) on minSdk<17; else `sen` · AM-06 (network) / AM-08 (malicious · An SDK WebView that both registers a JS interface and loads content over HTTP is remotely controllable by a ne…</sub>

**🟧 High ceiling**

- [ ] **`D10-067`** Support-chat SDK WebView rendering agent-/bot-supplied HTML  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone` (P2); Critical when it r` · AM-05 / AM-09 (agent side, bot tem · Support-chat SDKs render conversation content in a WebView and many expose a bridge for "actions" and file pre…</sub>

**🟨 Medium ceiling**

- [ ] **`D10-068`** In-app browser URL / origin spoofing (calibration)  
   <sub>`content/UI spoofing — most programs discount heavily; High only when a signing` · AM-02 · Whether the displayed URL and the rendering origin can diverge — a redirect the address bar does not follow, o…</sub>

**🟧 High ceiling**

- [ ] **`D10-069`** DNS rebinding against the app's embedded localhost HTTP/WebSocket server  
   <sub>`rated on what the endpoint exposes; Critical when it accepts a command reachin` · AM-02 (any browser page on the pho · A loopback server is not protected by SOP: a web page the victim visits in any browser on the phone can be poi…</sub>

**🟨 Medium ceiling**

- [ ] **`D10-070`** Custom Tabs navigation-callback cross-site login oracle (web-side finding)  
   <sub>`cross-site state inference — file against the *website* scope, not the app` · AM-03 (any installed app, no permi · A malicious app launches a target site in a Custom Tab (which shares the browser cookie jar) and reads the seq…</sub>
- [ ] **`D10-071`** Predictive back inside WebView escaping the app's history guard (targetSdk 36)  
   <sub>`broken flow control; High if it leaves an inconsistent server-side state an at` · AM-11 (physical/unlocked) / AM-05 · With predictive back default-on at targetSdk 36, a WebView-hosted flow that relied on `onBackPressed()` to int…</sub>

**🟥 Critical ceiling**

- [ ] **`D10-072`** Trusted-origin content renders attacker HTML → the allow-list is a non-defence → bridge credential theft  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-05 (another user writes the fie · A strict scheme+host allow-list (D10-016) is worthless if the *trusted* origin itself renders attacker-influen…</sub>

<details><summary>⚰️ D10 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `addJavascriptInterface` is used somewhere in the app | The bridge existing is not the finding; on API 17+ only annotated methods are reachable | An annotated method that returns a credential/file/native action, reachable from attacker content (D10-004) |
| `setWebContentsDebuggingEnabled(true)` guarded by `BuildConfig.DEBUG` | Not present in the release build; a debug-only switch | Prove the socket exists on a **release-signed, non-debuggable** build (D10-049) |
| `setAllowContentAccess(true)` (the default) with no JS-injection vector | MASTG: content access alone is not a vulnerability | A demonstrated JS-injection vector that reaches a private `content://` provider (D10-033) |
| `MIXED_CONTENT_ALWAYS_ALLOW` / Safe Browsing off with no reachable untrusted origin | P5 misconfiguration; removed defence-in-depth only | An injected HTTP subresource executing script in the HTTPS origin (D10-040), or the WebView loading a known-malicious URL with no interstitial + weak validation (D10-052) |
| Address-bar spoofing in an in-app browser | Content/UI spoofing pays $0 empirically across Brave/MetaMask/LINE | Spoofing that changes what a signing/payment prompt attributes the request to (D10-068 → D23) |
| Self-XSS in a WebView (victim pastes your payload) | HackerOne Core Ineligible: self-exploitation; `stored.self` is P5 | Cross-user delivery: stored, or via a deep link another user opens (D10-027) |
| Native→JS string concatenation where the value is app/server-internal | Not attacker-controlled — a defence-in-depth nit (Meesho's were) | A data-flow path from a deep-link/IPC/provider/profile source into the concatenated string (D10-025) |
| `setForceDark`/`prefers-color-scheme` reflecting the app theme to web content | A single fingerprint bit; no confidentiality impact | The theme encodes a privacy-relevant mode (e.g. "incognito") and it is part of a fingerprinting finding (→ D20) |
| A bridge finding dismissed as "the renderer is sandboxed" | The renderer isolates web content; the `@JavascriptInterface` object runs in the app process with the app UID | `ps -Z` showing `webview_zygote`/`:sandboxed_process` under an isolated UID while the app PID (running the bridge) is `u0_aNNN` — keeps the bridge finding rated correctly |
| "MitM inject JS into an `http://` WebView" with no stated reachability | Not reproducible on targetSdk ≥ 28 without a precondition | An NSC cleartext domain, an `http://` load path, or an existing XSS on the loaded origin (D10-041) |

</details>


<details><summary>🔗 D10 cross-surface joins — park these, chase them in P7</summary>

- **D09 (deep links) × D10 (bridge):** the single highest-yield join in mobile. A deep link whose `url=`/`web_view_url=`
  parameter reaches `loadUrl` on a bridged WebView is the delivery half; the token-returning bridge is the payload half.
  Neither is filed alone — file the deep-link primitive first (its id exists), then the bridge finding as the consumer,
  then backfill the link. One fix = one bounty; the chain is a severity amplifier, not a merge request.
- **D08 (intent redirection) × D10:** `intent://` in `shouldOverrideUrlLoading` (D10-065) turns web content already in
  the WebView into the local intent-redirection primitive — a pure remote-web path to non-exported components, with no
  malicious app. Conversely, an exported activity that forwards a `url` extra into a WebView (D08) is the redirection
  half of a WebView XSS/token-theft chain.
- **D10 (bridge/UXSS token) × D15 (backend) — the Shadow-API join:** a bridge or `loadDataWithBaseURL` UXSS that lifts a
  session token is only Informational until you replay it. The mobile app's hardcoded backend is frequently an *older*
  API version than the web app uses, with weaker auth, weaker rate limits and more field exposure — diff its
  *behaviour*, not its response shape; the weakened control (not the version difference) is the escalation finding.
  Remember the layer-ordering trap when you replay: a 400 "field X required" from the token'd request does not prove
  auth passed — re-test with a minimal well-formed body before claiming a bypass.
- **D07 (ContentProvider) × D10:** `setAllowContentAccess` + a JS foothold reads the app's own **non-exported**
  providers from the WebView (D10-033); and a stateful malicious `content://` provider is the source of second-order
  WebView XSS via `DISPLAY_NAME` (D10-028). Nobody reviews the provider export table and the WebView content-access
  setting together — the join is a private-provider read with no exported component.
- **D11/D12 (storage/keystore) × D10:** universal file access, `shouldInterceptRequest` traversal, the file-chooser
  and the cookie-DB symlink (D10-031/-034/-037/-038) each read exactly what D11/D12 measured as sensitive; and eternal
  WebView cookies (D10-046) are the artifact those primitives exfiltrate. The bridge file-read reaches Keystore-wrapped
  blobs and their IVs even when the renderer looks locked down.
- **D14 (TLS) × D10:** `onReceivedSslError→proceed()` and `MIXED_CONTENT_ALWAYS_ALLOW` (D10-039/-040) give a network
  attacker script injection into the WebView origin, which is the delivery vehicle for every bridge/token item above —
  the two surfaces are usually audited by different testers.
- **D18 (secrets/infra) × D10:** a bridged WebView loading remote HTML from a CDN/bucket (D10-064) makes a subdomain
  takeover or stale bucket a direct bridge-access primitive — file the takeover against infra, then the bridge as the
  consumer.
- **D28 (OAuth) × D10:** OAuth run in an embedded WebView instead of a Custom Tab, plus third-party cookies
  (D10-044) or the targetSdk-31 SameSite regression (D10-045), converts into session fixation / code interception —
  the WebView-vs-Custom-Tab classifier (D10-021) is the same bug from the routing side.

</details>


---

## D11 Local Data Storage

**Phase P4 · `M4` · 73 items** — 🟧 1 high · 🟨 1 medium · ⬜ 71 support  

📄 Full detail, with every command and proof: [`checklist/D11-local-data-storage.md`](checklist/D11-local-data-storage.md)

> **Crux question.** **For each sensitive value the app persists: which principal other than the app's own UID can read it, or write it, without root — and if the answer is "none", is there any value in the backup set that the app trusts on next launch?**

Mostly, it does not. The base rate of *defects* here is close to 100% — every app stores something in
cleartext — and the base rate of *payable findings* is close to zero, because the entire internal-storage
branch of the VRT is pinned at P5 and several major programmes exclude it by name. Google's Mobile VRP is
explicit that access to non-sensitive internal files of another app does not qualify. GitHub Security Lab's
$4,500 payout (H1 #1122661, CWE-312) is routinely miscited as precedent for reporting cleartext
SharedPreferences; it was a **CodeQL detection query** contributed upstream, not a report that one app stored
a token in plaintext. H1 #1225158 (Zivver), "ADB Backup is enabled within AndroidManifest", paid **$0**. If
your D11 output is a list of files containing tokens, you have produced an inventory, not findings.


**⬜ Support ceiling**

- [ ] **`D11-001`** The reachability rule — name the unprivileged reader before writing the word "storage"  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 / AM-04 / AM-11; explicitly  · Before writing anything, answer in one sentence: *which actor, holding what, reads this file?* The VRT encodes…</sub>
- [ ] **`D11-002`** Build the read-primitive inventory before the storage sweep, not after  
   <sub>`n/a (enabler)` · AM-03 · Enumerate every way a non-root principal reaches `/data/data/$PKG` on this target, and record a yes/no for eac…</sub>
- [ ] **`D11-003`** `run-as` — the fastest private-storage read primitive that exists  
   <sub>`n/a here; the debuggable flag itself is filed in D02` · AM-11 physical unlocked with ADB a · One command tells you whether root is needed for the whole chapter. On a shipped debuggable release it is simu…</sub>
- [ ] **`D11-004`** Sweep by file EXTENSION across the whole data dir, never by directory  
   <sub>`n/a (enabler)` · AM-03 once paired with a reader · `databases/` and `shared_prefs/` are two of roughly a dozen places a modern app writes. Couchbase Lite `.cblit…</sub>
- [ ] **`D11-005`** Differential sandbox dump with 8+ character markers, baseline-searched first  
   <sub>`n/a (enabler)` · Snapshot the data directory, exercise every sensitive flow typing **unique random markers**, snapshot again, d…</sub>
- [ ] **`D11-006`** Confirm a WRITE PATH before claiming anything is persisted  
   <sub>`n/a (accuracy gate)` · A field in a model class proves nothing about storage. R8 keeps Gson-annotated dead fields, and a payment mode…</sub>
- [ ] **`D11-007`** Two storage-forensics regexes that silently return nothing  
   <sub>`n/a (accuracy gate)` · Two grep traps that produce clean-looking false negatives and have each caused a real "clean" verdict on a tar…</sub>
- [ ] **`D11-008`** Substring searches for short numeric secrets are noise, not evidence  
   <sub>`n/a (accuracy gate)` · Grepping app storage for a card's last four digits flipped 0 -> 1 -> 0 across three runs of the same engagemen…</sub>
- [ ] **`D11-009`** Before declaring a storage or crypto subsystem absent, find the SECOND implementation  
   <sub>`n/a (accuracy gate)` · The most instructive retraction in the corpus is a finding whose every `file:line` citation was **accurate** a…</sub>
- [ ] **`D11-010`** Shell-Loop Ban — count your results or the storage sweep lies to you  
   <sub>`n/a (accuracy gate)` · Shell array loops and `for f in $(adb shell ...)` pipelines fail silently — a device path with a space, an `ad…</sub>
- [ ] **`D11-011`** Plaintext session/refresh token in SharedPreferences — rate it honestly  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 only via a reach primitive;  · Establish three things and no more: (a) the write site, (b) the resolved filename, (c) the storage mode. Never…</sub>

**🟨 Medium ceiling**

- [ ] **`D11-012`** `EncryptedSharedPreferences` used for one store but not another  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive · The strongest version of the plaintext-prefs argument is not "you should encrypt" — it is "you already decided…</sub>

**⬜ Support ceiling**

- [ ] **`D11-013`** `EncryptedSharedPreferences` present but the key is not user-authentication-bound  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-11 physical unlocked; AM-03 onl · "It uses Keystore" is not the finding. The finding is whether the Keystore key is (a) bound to user authentica…</sub>
- [ ] **`D11-014`** Jetpack DataStore `.preferences_pb` and Proto DataStore without a secure serializer  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive · DataStore is the modern replacement for SharedPreferences and is *not* encrypted by default. Its files live in…</sub>
- [ ] **`D11-015`** MMKV stores — enumerate them, and check the version for the logged-key CVE  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive; AM-0 · MMKV keeps its files under `files/mmkv/` (one file per instance plus a `.crc`), not in `databases/` or `shared…</sub>
- [ ] **`D11-016`** Realm database left unencrypted  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive · Realm is invisible to every SQLite tool and is omitted by most checklists. By default the file is named `defau…</sub>
- [ ] **`D11-017`** Couchbase Lite `.cblite` — the contents are plain JSON  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive · `.cblite`/`.cblite2` files (with their `-wal` and `-shm` siblings) sit in `files/`, outside every directory a …</sub>
- [ ] **`D11-018`** Locate the cross-platform framework's default store by name, not by guessing  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive · Each framework has a default key/value store in a predictable file. Because the storage **key names** are alre…</sub>
- [ ] **`D11-019`** `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` and the numeric-mode grep  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 · Grep the constants *and the numeric modes* — obfuscated call sites pass `1`, `2` or `3` rather than the named …</sub>
- [ ] **`D11-020`** SharedPreferences `.bak` ghost file — convert a create-only write into a settings overwrite  
   <sub>`file the outcome: `broken_authentication_and_session_management.authentication` · AM-03 with an existing directory-w · `SharedPreferencesImpl` writes `<name>.xml.bak` and, on the next load, **renames a present `.bak` over the liv…</sub>
- [ ] **`D11-021`** Client-side entitlement / premium flag stored locally and trusted  
   <sub>`outcome-rated; many programmes exclude IAP bypass — check the policy first` · AM-11 physical unlocked; AM-03 wit · Local booleans and strings that gate paid functionality — `premium_status`, `lifetime_purchase`, `subscription…</sub>
- [ ] **`D11-022`** Unencrypted SQLite/Room holding PII or session data, plus WAL/journal residue  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive; AM-0 · Pull every `.db` and its `-wal`, `-shm` and `-journal` siblings. Two findings live here: the live table conten…</sub>
- [ ] **`D11-023`** Any string argument to `getWritableDatabase()` / SQLCipher with a literal passphrase  
   <sub>``insecure_os_firmware.hardcoded_password.non_privileged_user` (**P2**, CWE-259` · AM-03 with a reach primitive; the  · The framework `getWritableDatabase()` / `getReadableDatabase()` overloads take **no** argument. SQLCipher's ta…</sub>
- [ ] **`D11-024`** Crafted `*-journal` file to rewrite a database you cannot open  
   <sub>`outcome-rated: `broken_authentication_and_session_management.authentication_by` · AM-03 chained to any arbitrary-fil · This is the reason an "arbitrary file *create*" primitive (not overwrite) is still High/Critical. SQLite repla…</sub>
- [ ] **`D11-025`** Device-protected (Direct Boot / DE) storage readable before first unlock  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-10 physical locked (pre-unlock  · Data written via `createDeviceProtectedStorageContext()` lands in `/data/user_de/<user>/<pkg>/` and is decrypt…</sub>
- [ ] **`D11-026`** Cache directories retaining authenticated responses and KYC images  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03 with a reach primitive; AM-0 · Do not stop at `shared_prefs` and `databases`. `cache/`, `code_cache/`, `no_backup/`, the OkHttp or Volley HTT…</sub>
- [ ] **`D11-027`** Secrets in app-bundled assets, `res/raw` and generated `strings.xml`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (the APK is public; no devic · This is storage the attacker reads *from the APK*, with no device at all — the closest this chapter comes to a…</sub>
- [ ] **`D11-028`** SDK-written token/credential files in app-private storage  
   <sub>``insecure_data_storage...on_internal_storage` (P5); file the replay outcome in` · AM-03 with a reach primitive · Find what the *SDK* wrote, not what the app wrote. Exercise the SDK flows (social login, open chat, trigger a …</sub>
- [ ] **`D11-029`** CodePush / expo-updates OTA bundle cache — a second copy of the code and a write target  
   <sub>`outcome-rated; the analysis value is Support` · AM-03 (read); AM-09 malicious CDN  · OTA frameworks cache downloaded JS and assets on disk. That cache is (a) a second copy of the code you must an…</sub>
- [ ] **`D11-030`** Unity `PlayerPrefs` / `persistentDataPath` authoritative game state  
   <sub>`outcome-rated; often IAP/economy scope — check the programme` · AM-11 physical unlocked; AM-03 wit · Unity games persist currency, entitlements and progression in `PlayerPrefs` (`shared_prefs/<pkg>.v2.playerpref…</sub>
- [ ] **`D11-031`** WebView cookie store as the exfiltration target  
   <sub>`outcome-rated: `broken_authentication_and_session_management.authentication_by` · AM-03 with a reach primitive; AM-0 · Testers grep `shared_prefs` and stop. The WebView keeps its own SQLite cookie store, including `httpOnly` cook…</sub>
- [ ] **`D11-032`** Firebase / Realtime-DB config and cached documents inside the sandbox  
   <sub>``insecure_data_storage...on_internal_storage` (P5) for the cache; the open-dat` · AM-03 (read); AM-01 for the result · Beyond the four standard directories, enumerate library-specific stores. A Firebase config here (the RTDB URL …</sub>
- [ ] **`D11-033`** Secrets surviving logout and account switch (shared-device residue)  
   <sub>``insecure_data_storage...on_internal_storage` (P5); `insecure_os_firmware.fail` · AM-05 another user of the same app · Nobody tests what logout leaves *on disk* — which is what the next person to pick up a family tablet, a ward d…</sub>
- [ ] **`D11-034`** Session or entitlement surviving uninstall / reinstall  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if t` · AM-11 physical unlocked, device ha · Verify that reinstalling does not restore a session — via cloud backup, via an account left in `AccountManager…</sub>
- [ ] **`D11-035`** Search history, recent queries and autocomplete cache holding PII  
   <sub>``insecure_data_storage...on_internal_storage` (P5); `broken_access_control.exp` · AM-05 cross-account on a shared de · Search boxes in marketplace, health, banking and messaging apps persist recent queries locally (a Room table, …</sub>
- [ ] **`D11-036`** The offline write-queue — tamper the pending mutations before they sync  
   <sub>`outcome-rated: `broken_access_control.idor.modify_sensitive_information_iterab` · AM-11 physical unlocked; AM-03 wit · Offline-first apps serialise pending mutations to disk — a Room "outbox" table, a JSON queue, a `WorkManager` …</sub>
- [ ] **`D11-037`** Chat and media caches that survive "delete for everyone"  
   <sub>``insecure_data_storage...on_internal_storage` (P5) / `...on_external_storage` ` · AM-05 (next user); AM-03 (shared s · Two failures: a message deleted "for everyone" server-side remains on the recipient's disk, and the media cach…</sub>
- [ ] **`D11-038`** Sensitive data left in a view that is merely hidden  
   <sub>`outcome-rated; the storage-adjacent node is `insecure_data_storage...on_intern` · AM-04 accessibility-service abuser · `setVisibility(View.GONE | INVISIBLE)` does not clear the value — it stays in the view hierarchy, in memory, a…</sub>
- [ ] **`D11-039`** No `FLAG_SECURE` — recents snapshot on disk and screen capture  
   <sub>``insecure_data_storage.screen_caching_enabled` (**P5**)` · AM-11 physical unlocked; AM-04 scr · Without `FLAG_SECURE`, the OS writes a task-snapshot to disk when the app backgrounds, and the screen is captu…</sub>
- [ ] **`D11-040`** Deleted-record and unallocated-space residue in structured stores  
   <sub>``insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES` · AM-11 physical unlocked; AM-05 · A SQLite `DELETE` marks pages free but does not zero them; the `-wal`, `-shm` and `-journal` siblings and the …</sub>
- [ ] **`D11-041`** Sensitive data written to external / shared storage (the one class rated above P5)  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_extern` · AM-03 zero-permission (legacy/scop · External storage is world-readable to any app holding the storage permission and survives uninstall — and the …</sub>
- [ ] **`D11-042`** Scoped-storage bypass and `MANAGE_EXTERNAL_STORAGE` over-request  
   <sub>``insecure_data_storage...on_external_storage` (P4); the permission over-reques` · AM-03; AM-04 · External storage is user-controlled data. Establish whether the app holds All-Files access, whether it still r…</sub>
- [ ] **`D11-043`** Cross-app access to `Android/data` and `Android/obb` (version-gated)  
   <sub>``insecure_data_storage...on_external_storage` (P4) on affected versions` · AM-03 · Determine whether the tested platform still permits reading another app's `/sdcard/Android/data/<pkg>` directo…</sub>
- [ ] **`D11-044`** MediaStore `_data` column disclosure and path re-use  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) ` · AM-03 (other apps create the Media · Two separate bugs. (1) The app **returns** `MediaStore.MediaColumns.DATA` to a caller or logs it, disclosing a…</sub>
- [ ] **`D11-045`** Attacker-controlled `RELATIVE_PATH` / `DISPLAY_NAME` on MediaStore insert  
   <sub>`MASWE-0050; outcome-rated if the planted file is later parsed/loaded` · AM-03 · When the app inserts into MediaStore using a filename or subdirectory derived from remote or IPC-supplied data…</sub>
- [ ] **`D11-046`** Man-in-the-Disk: app reads executable or trust-bearing data from shared storage  
   <sub>`outcome-rated: `server_side_injection.remote_code_execution_rce` (P1) analogue` · AM-04 (storage permission); AM-03  · Does the app load a config, a DEX/JAR/SO, an update file, or a signature-verification input from external stor…</sub>
- [ ] **`D11-047`** Zip-slip on the app's import/update path (and the `ZipPathValidator` opt-out)  
   <sub>`outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue for ` · AM-02 (a crafted archive delivered · Any unzip routine that uses `ZipEntry.getName()` as a path writes outside the target directory when an entry c…</sub>
- [ ] **`D11-048`** `Content-Disposition` / provider `_display_name` filename traversal on download  
   <sub>`outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue` · AM-02 remote one-click (no malicio · Download code that takes the filename from the server's `Content-Disposition` header, or from a `content://` p…</sub>
- [ ] **`D11-049`** TOCTOU / symlink race on a file handed over as `file://` or a descriptor  
   <sub>`outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue` · AM-03 (a symlink in a shared direc · If the app validates a path *string* and then opens it later, swap the path for a symlink in between. Google's…</sub>
- [ ] **`D11-050`** Data written to a hidden `.nomedia` directory the user cannot see or manage  
   <sub>``insecure_data_storage...on_external_storage` (P4) if world-readable; otherwis` · AM-11; AM-03 if the directory is w · If the app captures imagery and hides it from the Gallery with a `.nomedia` file or a dot-directory while reta…</sub>
- [ ] **`D11-051`** Backup rules — read the RULES, then extract, never report the flag  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**) for` · AM-11 physical unlocked with ADB;  · `allowBackup="true"` (or unset, which defaults true) is **not** a finding. Auto Backup always *excludes* `getC…</sub>
- [ ] **`D11-052`** Asymmetric `dataExtractionRules` — excluded from cloud, wide open to device transfer  
   <sub>``insecure_data_storage...on_internal_storage` (P5) for the store; escalates vi` · AM-11 physical (device resale, rep · Android 12+ `dataExtractionRules` splits `<cloud-backup>` from `<device-transfer>`, and **if a section is miss…</sub>
- [ ] **`D11-053`** Modify-and-restore — prove a client-side entitlement/PIN is authoritative  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-11 physical unlocked · Flip a value in the backup set and restore it, then show the app honouring the tampered value. For the legacy …</sub>
- [ ] **`D11-054`** Inverted or absent restore guard on a device-bound value  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-11 physical unlocked (a backup  · Apps that must not restore a device-bound secret usually store an identifier (`Settings.Secure.ANDROID_ID`, an…</sub>
- [ ] **`D11-055`** The session token written a SECOND time, in plaintext, backup-reachable  
   <sub>``insecure_data_storage...on_internal_storage` (P5); file the replay/restore ou` · AM-11 (backup); AM-03 via FileProv · Apps frequently duplicate the session into a plain file — e.g. `files/session_backup_payload` written by the a…</sub>
- [ ] **`D11-056`** Restorable control-plane values — the highest-ceiling item in the chapter  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) via ` · AM-11 physical unlocked · The high-value inversion of "is my token backed up". Look for values in backed-up storage the app *trusts on n…</sub>
- [ ] **`D11-057`** SDK-written files included in the backup set  
   <sub>``insecure_data_storage...on_internal_storage` (P5); file the extracted-and-rep` · AM-11 physical unlocked with ADB · If `allowBackup` is not false, SDK-written token files leave the device in cloud/adb/D2D backups unless the ap…</sub>
- [ ] **`D11-058`** Build the backup/restore rig once — then every backup item is routine  
   <sub>Most teams never test backup because the rig is fiddly, so they silently skip the highest-ceiling storage item…</sub>
- [ ] **`D11-059`** Sensitive value placed on the system clipboard without `EXTRA_IS_SENSITIVE`  
   <sub>``mobile_security_misconfiguration.clipboard_enabled` (**P5**, baseline `AV:L/A` · AM-04 foreground app / IME / acces · An app that copies (or lets the user copy) a password, OTP, card number, recovery phrase or token to the clipb…</sub>
- [ ] **`D11-060`** Clipboard READ of another app's clip, shipped off-device  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) ` · the target app is the reader here  · Since Android 12 the first `getPrimaryClip()` against another app's clip raises a toast. An app that silently …</sub>
- [ ] **`D11-061`** Keyboard cache on sensitive input fields  
   <sub>`outcome-rated; MASWE-0036, CWE-524. No dedicated VRT node — argue Medium for a` · AM-05 (the cached suggestion surfa · A field that is not a non-caching input type has its contents learned by the IME dictionary and re-offered as …</sub>
- [ ] **`D11-062`** Sensitive data written to logcat — name the reader or it is informational  
   <sub>``sensitive_data_exposure.disclosure_of_secrets` (VARIES); the base observation` · AM-04 (a `READ_LOGS`-holding OEM p · "The app logs to logcat" is not a finding — since Android 4.1 apps read only their own logs. It becomes a find…</sub>
- [ ] **`D11-063`** StrictMode / debug logging left enabled in production  
   <sub>``sensitive_data_exposure.disclosure_of_secrets` (VARIES) only if it leaks a se` · AM-11; AM-04 · `StrictMode` left on in production emits implementation detail (SQL, file paths, thread policy violations) to …</sub>
- [ ] **`D11-064`** AccountManager-stored credentials and auth tokens  
   <sub>``insecure_data_storage...on_internal_storage` (P5); file the token replay` · AM-11; AM-03 with `GET_ACCOUNTS` / · `AccountManager` stores account credentials and auth tokens in `/data/system_ce/<user>/accounts_ce.db` (system…</sub>
- [ ] **`D11-065`** Work-profile / Private Space data separation assumptions  
   <sub>`outcome-rated; `insecure_data_storage...on_external_storage` (P4) if the cross` · AM-05 (the personal-profile instan · If the app is deployed into a work profile or Private Space, verify it does not write shared state to a locati…</sub>
- [ ] **`D11-066`** Secrets recoverable from process memory (contributing factor, not headline)  
   <sub>``cryptographic_weakness.incomplete_cleanup_of_keying_material` (P5) for the re` · AM-12 own rooted device (not an at · Values the app decrypts only in memory (keys, PANs, tokens, mnemonics) are recoverable from the live process. …</sub>

**🟧 High ceiling**

- [ ] **`D11-067`** Keystore holding plaintext data rather than keys  
   <sub>``insecure_data_storage...on_internal_storage` (P5); the key-usage half is D12` · AM-12 rooted / AM-04 instrumentabl · The Keystore is the right place for key material, but apps store plaintext data there or use the keys in leaky…</sub>

**⬜ Support ceiling**

- [ ] **`D11-068`** Test/config artefacts shipped in the package (`assets/`, `res/raw/`, properties)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (the APK is public) · Leftover test data, private keys and internal endpoint lists in `assets/`, `res/raw/` and bundled JSON/propert…</sub>
- [ ] **`D11-069`** WorkManager / job-scheduler input and Firebase installation files as token homes  
   <sub>``insecure_data_storage...on_internal_storage` (P5); file the token replay` · AM-11; AM-03 with a reach primitiv · Testers stop at `shared_prefs`, `databases` and `files/*.xml`. Two under-checked token homes: the WorkManager …</sub>
- [ ] **`D11-070`** Chain-filing order — file the storage payload as a primitive, the reach as the consumer  
   <sub>`n/a (reporting mechanics)` · A D11 payload (a plaintext token) and its reach primitive (a FileProvider traversal, a debuggable build) are t…</sub>
- [ ] **`D11-071`** Evidence hygiene for a storage-exfil PoC — the five-shot pattern and the PII split  
   <sub>`n/a (reporting mechanics)` · A storage-theft PoC needs the same rigour as a web state-change: pre-state, the extraction, the replay, and th…</sub>
- [ ] **`D11-072`** The mobile store points at an OLDER, weaker backend — the shadow API  
   <sub>`outcome-rated: `broken_access_control.idor.modify_view_sensitive_information_i` · AM-01 remote (the endpoint is reac · A mobile app's hardcoded backend calls — recovered from `shared_prefs`, a bundled config, a restored control-p…</sub>
- [ ] **`D11-073`** Layer-ordering: a "field required" 400 from a storage-derived request is not an auth pass  
   <sub>`n/a (methodology)` · When you replay a recovered token (D11-011), a tampered offline-queue mutation (D11-036) or a shadow-API probe…</sub>

<details><summary>⚰️ D11 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| Sensitive data found in `/data/data/<pkg>` via `run-as` or `su` on your own rooted/emulator device | AM-12 (own rooted device) is not an attack; the VRT prices internal storage at P5 (`insecure_data_storage...on_internal_storage`), and Xiaomi, Grab and Spotify list app-private storage explicitly out of scope | Pair it with a non-root reach primitive a third party has — a debuggable build (D02), an exported/grantable provider (D07), a `file://` WebView (D10), a backup extraction (D11-051), or a world-readable mode bit — and refile as the **access** bug with the data as payload (D11-001) |
| `android:allowBackup="true"` (or unset) | `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5**, vector `AV:P`; Google states backups enabled is intended; H1 #1225158 (Zivver) paid **$0** for exactly this | A credential extracted via `bmgr`/backup on a non-rooted device and replayed against the production API (D11-051), or a control-plane value restored to repoint the app (D11-056) |
| A failed or header-only `adb backup` archive | `adb backup` is gutted on Android 12+ and dead on many OEM builds — its silence is a platform property, not an app property | Re-run via the `bmgr` local transport / D2D transport (D11-058); the negative is an empty `bmgr` archive, not an empty `adb backup` |
| `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` constant in the source | These throw `SecurityException` from targetSdk 24, and SELinux confines `/data/data` cross-app regardless of DAC bits; Android 11+ blocks reading another app's internal dir even for world-readable files | The `stat` output on-device shows the loose mode bits **and** a second unprivileged app reads the file (D11-019) — on a build with targetSdk < 24 or via native `chmod` |
| `insecure_data_storage.screen_caching_enabled` — no `FLAG_SECURE`, recents thumbnail | P5; Grab and Spotify exclude "Snapshot/Pasteboard leakage"; remediation is phrased as a best practice | The cached screen shows an unmasked credential/PAN **and** a chain reaches the snapshot store (D02 backup, D04/D21); or, on a platform program, a `FLAG_SECURE` bypass of a control the app *did* set |
| `mobile_security_misconfiguration.clipboard_enabled` — the app copies to the clipboard | P5, vector `AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N` designed to score low; the VRT flattened the sensitive/non-sensitive children into one P5 parent; background reads blocked since Android 10 | The copied value is an OTP/PAN/seed phrase, read by a **foreground** PoC app on the in-scope OS, and then used to complete an authentication (file the ATO, D13) |
| Keyboard cache on a generic (non-sensitive) field | CWE-524 but no real credential leaks; most programs rate it Low | The cached value is a PIN/OTP/card number/seed phrase suggested in a *second* app (D11-061), demonstrated with a canary |
| Reading the personal dictionary / `READ_USER_DICTIONARY` | The permission was removed at API 23; the store is not third-party readable on modern Android | n/a on modern Android — do not report |
| `/data/system/users/0/accounts.db` read | System-owned; not reachable by a third-party app | An auth token recovered via `AccountManager` API from an app of the same account type or shared signature (D11-064) |
| A field named `_cvv` / `card_token` in a decompiled model class | R8 keeps Gson-annotated dead fields; a field is not a write | A `putString`/`insert`/file-write that actually carries the field to disk (D11-006), confirmed with a runtime hook |
| A four-digit string matching a card's last four across cache files | A four-digit run occurs by chance across hundreds of binary cache files (D11-008) | A Luhn-valid PAN-shaped 16-digit run, or a field-name hit, in a post-transaction dump |
| `EncryptedSharedPreferences` / `flutter_secure_storage` / `react-native-keychain` present | Presence is not protection, but presence alone is also not a finding | The key has no `setUserAuthenticationRequired` and a Frida `Cipher` hook decrypts it on a merely-unlocked device (D11-013), or the app also stores the same class in cleartext elsewhere (D11-012) |
| `getExternalFilesDir()` write on a targetSdk 30+ device | On Android 11+ `Android/data/<pkg>` is not readable by other ordinary apps; `WRITE_EXTERNAL_STORAGE` grants no extra access | The read succeeds from a second package (prove it, don't assert it), or the data lands in `Download`/`DCIM`/a public MediaStore collection which stay broadly readable (D11-041) |
| A cleartext token at rest with no replay attempted | Storage without impact is informational; GitHub Security Lab's $4,500 was a CodeQL query, not a report of plaintext prefs — do not cite it as precedent | The token replayed from a clean host returns the victim's data (D11-011); the replay is the finding |
| Process memory holds a decrypted secret on a rooted device | AM-12 is not an attack; MASTG deprecated the standalone memory test; immutable `String`s cannot be reliably cleared, so this is expected | It falsifies a "never stored / hardware-backed" design claim, or the recovered key decrypts the local store and turns a Medium into a Critical (D11-066) — filed as a contributing factor to a root/debuggable finding |
| A restorable preference that the app re-derives from the server on launch | The restore changes nothing; the server overwrites it before first use | The app trusts the restored value before contacting the server (D11-056) — proven by the first outbound request going to the attacker host |

</details>


<details><summary>🔗 D11 cross-surface joins — park these, chase them in P7</summary>

- **D11 × D14 — the backup set and the network interceptor (J01).** Nobody reads `data_extraction_rules.xml`
  and the OkHttp `CertificatePinner` construction in the same sitting. If the client reads its base URL or
  its pin set from a preference or cached JSON that is inside the backup set, a restored attacker copy
  repoints the whole app *before first launch* — and pinning cannot save it, because the pin set was restored
  too. Individually: a config note and a pinning implementation. Joined: pre-authentication MitM of a pinned
  app with no runtime instrumentation (D11-056 -> D14).
- **D11 × D18 — the App Startup initializer and the restored preference (J12).** Initializers run before any
  gate. An initializer that reads a restored control-plane value acts on it before the app can validate
  anything — before a remote kill switch or server-side config could correct it. The storage reviewer sees a
  restorable preference; the startup reviewer sees an initializer; the join is pre-auth config injection
  (Critical if the value is the API host).
- **D11 × D13 — the biometric-lock boolean in the backup set (J13).** When "app lock enabled" is persisted
  as a plain boolean rather than bound to a `CryptoObject`, and that boolean is in the backup set, restoring
  it as `false` disables the gate with neither root nor Frida. The auth reviewer checks the biometric flow;
  the storage reviewer checks the backup rules; neither checks the flag's *restorability*.
- **D11 × D23 — the entitlement cache and backup restore (J18).** If entitlement state is cached in a
  backed-up preference and trusted on cold start (to work offline), the entitlement is portable and
  forgeable — restore it `true` on a device that never purchased. The same primitive (D11-056) unlocks any
  other cached trust decision.
- **D11 × D16 — the planted MediaStore file and the app's own importer (J20).** D11-045's attacker-chosen
  `RELATIVE_PATH`/`DISPLAY_NAME` meets any "import from device" feature: plant a file where the importer
  scans, with the name and MIME it keys on, and the app ingests attacker bytes with no user selection —
  reaching the parser in D16 zero-click.
- **D11 × D07 — reachability is the whole finding.** An unencrypted token in `shared_prefs` is P5 and out of
  scope at several programmes; a FileProvider traversal or a grantable provider is the thing that makes it a
  P1 read. File the access as the bug and the storage as the payload — never the other way round (D11-070).
- **D11 × D10 — the WebView cookie jar reached from inside the WebView.** `setAllowFileAccess` /
  `setAllowContentAccess` let untrusted web content `XMLHttpRequest` a `content://` or read
  `app_webview/Default/Cookies`. The WebView reviewer tests XSS and origins; the storage reviewer dumps the
  cookie DB with `run-as`; neither tests the store *from inside the WebView*, which is where the cross-surface
  ATO (D11-031) lives.
- **D11 × D17 — the write primitive and the loader.** A traversal, zip-slip, `.db-journal` or `.xml.bak`
  write is Medium on its own; enumerate `System.load`/`DexClassLoader`/plugin directories *first*, choose
  the destination to match, and the same primitive becomes local code execution (D11-020, D11-024, D11-046,
  D11-047).
- **D11 × D15 — the stored host is an older, weaker backend (shadow API).** The mobile client's hardcoded or
  restored API host is frequently an older version than the web app's, with weaker auth and more field
  exposure. The stored token from this chapter unlocks it; the behavioural version diff is the finding
  (D11-072).
- **D11 × D20 — the shared-device residue and cross-account bleed.** Logout, account switch and
  delete-for-everyone all leave data on disk (D11-033, D11-037, D11-040). On a family tablet, kiosk or ward
  device [T.P4], the next authorised-but-different user reads the previous user's conversations, queries and
  live sessions — a supported scenario nobody tests.

</details>


---

## D12 Cryptography & Key Management

**Phase P4 · `M4` · 80 items** — 🟥 18 critical · 🟧 38 high · 🟨 13 medium · 🟩 2 low · ⬜ 9 support  

📄 Full detail, with every command and proof: [`checklist/D12-crypto-and-key-management.md`](checklist/D12-crypto-and-key-management.md)

> **Crux question.** **Is there a key, nonce, salt or signature that some component still trusts, which I can reproduce either from the public APK or from code running in the app's own UID — and what does the server do when I use it?**

It pays because the entry ticket is free. Every other domain needs a victim, a link, a permission or a
malicious app on the device; this one needs the Play Store. A hardcoded `SecretKeySpec` is a shared secret
with the entire install base the moment the build ships, and the same is true of an HS256 signing secret, an
mTLS client `.p12`, a Dart-embedded AES seed in `libapp.so`, or an Algolia admin key in a Hermes bundle.
Bugcrowd's own doctrine agrees with the shape: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`
is **P1**, and a shipped APK is a publicly accessible asset. The IQCrafter Flutter study pulled two complete
2048-bit RSA private keys out of `libapp.so` at offsets `0x85bb0` and `0x9f486` and then produced
byte-identical request signatures from a standalone Python client — that is a P1-shaped finding that never
touched a user.


**⬜ Support ceiling**

- [ ] **`D12-001`** Build the transformation and key-provenance census before judging anything  
   <sub>`n/a (method — feeds every item below)` · AM-12 (harness) · Produce one frequency-ordered table of every cipher transformation, every digest, every key construction and e…</sub>
- [ ] **`D12-002`** Universal runtime key and plaintext capture at `SecretKeySpec` / `Cipher`  
   <sub>`n/a (method)` · AM-12 (harness) · Do not reverse the key derivation. The key must exist in the clear at `SecretKeySpec.<init>` and the plaintext…</sub>
- [ ] **`D12-003`** A clean Java crypto grep on RN / Flutter / Cordova / Unity is a FALSE NEGATIVE  
   <sub>`n/a (method — prevents a wrong negative)` · AM-12 (harness) · On cross-platform builds the key derivation, the storage-key names and the transformation live in `assets/inde…</sub>
- [ ] **`D12-004`** Enumerate the Keystore at runtime and read every key's real `KeyInfo`  
   <sub>`n/a (method — the measurement behind D12-048 → D12-061)` · AM-12 (harness) · "We use the Android Keystore" is a claim. This is the measurement: which aliases exist, what each one is for, …</sub>

**🟥 Critical ceiling**

- [ ] **`D12-005`** Hardcoded symmetric key reaching `SecretKeySpec`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · A key that is a compile-time constant is shared with every user and every attacker. The finding is not the con…</sub>
- [ ] **`D12-006`** Private key, PKCS#12, JKS/BKS or service-account file shipped in the package  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Anything shipped to every user is public. A client certificate, a PKCS#12 bundle, a keystore file or a cloud c…</sub>

**🟧 High ceiling**

- [ ] **`D12-007`** mTLS client identity recovered from the live PKCS#12 reload  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if t` · AM-11 / AM-08 (in-process), then A · The common pattern — generate a keypair, store the key and the issued client certificate in a PKCS#12 with a r…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-008`** PEM private key or HMAC seed inside `libapp.so` / `libil2cpp.so` / managed assemblies  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · DEX-oriented secret scanners never look in the native blob. Sweep it statically and then at runtime, because k…</sub>
- [ ] **`D12-009`** Flutter: reconstruct a Dart-embedded key from Smi-encoded constants  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Dart AOT stores small integer constants tagged (Smi): `actual = raw >> 1`. A key built character-by-character …</sub>
- [ ] **`D12-010`** Unity / Xamarin: read the crypto straight out of restored managed code  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · In IL2CPP `dump.cs` and in restored `.dll`s the crypto is plain C#. This is the fastest path to a hardcoded-ke…</sub>
- [ ] **`D12-011`** Keys shipped in the JS bundle that authenticate server-side  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · "Public" bundle keys are frequently privileged in practice: Firebase server keys, Algolia admin keys, Stripe s…</sub>

**🟧 High ceiling**

- [ ] **`D12-012`** Key derived from a device identifier or other attacker-recomputable value  
   <sub>``cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (` · AM-01 (with a device image or back · A key derived from `ANDROID_ID`, IMEI, `Build.SERIAL`, the package name, the install time or a fixed salt plus…</sub>
- [ ] **`D12-013`** Cryptographic keys held outside the platform Keystore  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-03/AM-04 with a read primitive; · A correctly generated key written to `SharedPreferences`, a file or a DataStore is extractable. Oversecured's …</sub>
- [ ] **`D12-014`** ECB mode, including the bare `"AES"` transformation  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primit` · AM-01 (ciphertext off the wire) /  · `Cipher.getInstance("AES")` silently means **AES/ECB** because ECB is the JCA default — that is the form devel…</sub>
- [ ] **`D12-015`** Broken or withdrawn symmetric algorithm (DES, 3DES, RC4, Blowfish, RC2)  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primit` · AM-01 · Inspect the algorithm string at `Cipher.getInstance`, `SecretKeyFactory.getInstance` and `KeyGenerator.getInst…</sub>
- [ ] **`D12-016`** Weak hash making a security decision (MD5 / SHA-1 / MD4)  
   <sub>``cryptographic_weakness.weak_hash.predictable_hash_collision` (varies — by imp` · AM-01 · The finding is never "MD5 exists" — it is "MD5 decides a security outcome". Trace every digest to its consumer…</sub>
- [ ] **`D12-017`** CBC without integrity — ciphertext malleability on a field the app or server trusts  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-01 · Unauthenticated CBC is malleable. If the app or its API decrypts a blob and then trusts a field inside it, you…</sub>
- [ ] **`D12-018`** Padding oracle: CBC + PKCS#5/7 with a distinguishable decrypt failure  
   <sub>``cryptographic_weakness.side_channel_attack.padding_oracle_attack` (**P4** — t` · AM-01 · Where the app or its API decrypts attacker-supplied ciphertext and distinguishes a padding error from any othe…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-019`** Static or predictable IV  
   <sub>``cryptographic_weakness.insufficient_entropy.predictable_initialization_vector` · AM-01 · `IvParameterSpec(new byte[16])`, an IV derived from the key, an IV hardcoded as a string, or the same IV acros…</sub>

**🟧 High ceiling**

- [ ] **`D12-020`** IV / nonce reuse under a fixed key (CTR keystream reuse, GCM forgery)  
   <sub>``cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` (**P` · AM-01 · CTR nonce reuse under one key XORs two plaintexts together; GCM nonce reuse under one key leaks the authentica…</sub>
- [ ] **`D12-021`** Non-standard GCM IV length, or a bundled provider re-enabling what the platform refuses  
   <sub>``cryptographic_weakness.insecure_implementation.improper_following_of_specific` · AM-01 · Android 12 started rejecting three specific things. Apps that hit these commonly added `org.bouncycastle:bcpro…</sub>
- [ ] **`D12-022`** RSA without OAEP (PKCS#1 v1.5 or `NoPadding`)  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primit` · AM-01 · `RSA/ECB/NoPadding` is malleable outright; `RSA/ECB/PKCS1Padding` for *encryption* is Bleichenbacher-vulnerabl…</sub>
- [ ] **`D12-023`** Home-grown "encryption" that is a XOR loop  
   <sub>``cryptographic_weakness.insecure_implementation.improper_following_of_specific` · AM-01 · A method whose *name* implies cryptography and whose *body* is a XOR loop. Rarely checked, frequently present.</sub>
- [ ] **`D12-024`** Encoding presented as encryption, and reversible custom transforms on identity parameters  
   <sub>`rate as the underlying exposure: `insecure_data_storage.sensitive_application_` · AM-01 / AM-03 · Two related shapes. First, values that look encrypted but are only encoded. Second — the higher value one — a …</sub>

**🟨 Medium ceiling**

- [ ] **`D12-025`** Insufficient key size  
   <sub>``cryptographic_weakness.insecure_key_generation.insufficient_key_space` (P3, C` · AM-01 · Read the size argument to `KeyGenerator.init(int)`, `KeyPairGenerator.initialize(int)` and `KeyGenParameterSpe…</sub>

**🟧 High ceiling**

- [ ] **`D12-026`** Insufficient key stretching — plain hash, PBKDF1, or low-iteration PBKDF2  
   <sub>``cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (` · AM-01 with a pulled blob / AM-03 w · Keys derived from passwords or PINs must use PBKDF2, scrypt or Argon2 with a per-user random salt and a curren…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-027`** Missing, hardcoded or predictable salt  
   <sub>``cryptographic_weakness.weak_hash.lack_of_salt` (varies); `cryptographic_weakn` · AM-01 · A salt that is a constant byte array, an empty array, the username, or reused across users makes one precomput…</sub>

**🟧 High ceiling**

- [ ] **`D12-028`** Low-entropy input (a 4–6 digit PIN) not combined with Keystore-held material  
   <sub>``cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (` · AM-01 with a pulled vault / AM-03  · No KDF work factor saves a 4-digit PIN from an offline attack: 10,000 candidates is trivially enumerable regar…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-029`** One key, many purposes — decode the `KeyGenParameterSpec` purpose bitmask  
   <sub>``cryptographic_weakness.key_reuse.intra_environment` (**P5** on its own — you ` · AM-03 / AM-08 · NIST requires one purpose per key. On Android the purposes are a bitmask, and the decompile shows the **combin…</sub>

**🟧 High ceiling**

- [ ] **`D12-030`** Same key across environments — production and staging share key material  
   <sub>``cryptographic_weakness.key_reuse.inter_environment` (**P2**, CWE-323) — this ` · AM-01 · Compare key material across build flavours, across the production and staging APKs, and across the app's own e…</sub>
- [ ] **`D12-031`** Same key across every install — no per-device key derivation  
   <sub>``cryptographic_weakness.key_reuse.intra_environment` (**P5** as a bare observa` · AM-01 · Determine whether the key is per-install or baked in. A shared key converts any single-device compromise into …</sub>

**🟨 Medium ceiling**

- [ ] **`D12-032`** One key reused across subsystems (storage, signing, transport, integrity)  
   <sub>``cryptographic_weakness.key_reuse.intra_environment` (P5); High only when you ` · AM-01 / AM-08 · One key for local DB encryption, token signing, transport protection and integrity means the weakest context s…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-033`** `java.util.Random` / `Math.random()` at a security sink  
   <sub>``cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4) / `.s` · AM-01 · `java.util.Random` is a 48-bit linear congruential generator; given the seed the whole sequence is reproducibl…</sub>
- [ ] **`D12-034`** Time- or counter-derived "randomness"  
   <sub>``cryptographic_weakness.insufficient_entropy.small_seed_space_in_prng` (P4) / ` · AM-01 · The same impact class as D12-033 but harder to grep: `System.currentTimeMillis()`, `new Date().getTime()`, `Ca…</sub>

**🟧 High ceiling**

- [ ] **`D12-035`** `SecureRandom` with a fixed seed, or an uninitialised all-zero key array  
   <sub>``cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4); `.pr` · AM-01 · Three distinct shapes, all producing reproducible keys: (a) `new SecureRandom("seed".getBytes())`, (b) key byt…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-036`** Seed-space collapse via a restart oracle  
   <sub>``cryptographic_weakness.insufficient_entropy.small_seed_space_in_prng` (P4); e` · AM-03 (needs the restart primitive · A time-seeded generator is only as strong as your uncertainty about the seed. If you can force the process to …</sub>

**🟧 High ceiling**

- [ ] **`D12-037`** PKCE `code_verifier` generated from a non-cryptographic PRNG  
   <sub>``cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4); exit` · AM-02 (needs the code-interception · PKCE only protects the code if the verifier is unguessable. A predictable verifier means a malicious app that …</sub>

**⬜ Support ceiling**

- [ ] **`D12-038`** Prove predictability statistically, not anecdotally  
   <sub>`n/a (false-positive discipline governing D12-018, D12-033 → D12-037)` · AM-12 (harness) · Single outliers are not signal, and a sweep that silently ate half its iterations looks exactly like a clean n…</sub>

**🟧 High ceiling**

- [ ] **`D12-039`** MAC construction misuse — `hash(key‖msg)`, truncated tags, CRC as integrity  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.identit` · AM-01 · Where the app authenticates messages or stored data, inspect the construction rather than the primitive name. …</sub>

**🟨 Medium ceiling**

- [ ] **`D12-040`** Non-constant-time tag or signature comparison  
   <sub>``cryptographic_weakness.side_channel_attack.timing_attack`` · AM-01 (remote, against the server- · `Arrays.equals` and `String.equals` short-circuit on the first differing byte. Where the comparator is remotel…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-041`** Request-signing scheme the server never enforces  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-01 · If the app signs requests, three questions decide everything, and all three are answered on the **server**, no…</sub>

**🟧 High ceiling**

- [ ] **`D12-042`** Signature verified and the result discarded, or the verifier trusts the data it verifies  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-09 (malicious backend/CDN) / AM · This is the scope's "signature verification the app performs on data it trusts". Three failure shapes: the boo…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-043`** The shadow-API bridge: an older API version that does not enforce the signature at all  
   <sub>`rate the weakened control: `broken_access_control.idor.modify_view_sensitive_i` · AM-01 · The highest-value structural idea available to a mobile crypto reviewer. The app's request signing, payload en…</sub>
- [ ] **`D12-044`** Hardcoded HS256 signing secret in the binary → forge arbitrary identities  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-01 · If the build ships the symmetric signing secret — or the secret is weak enough to recover offline from a captu…</sub>
- [ ] **`D12-045`** RS256 → HS256 algorithm confusion using the public key as the HMAC secret  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · The verifier trusts the token's own `alg` header instead of pinning the algorithm server-side. The mobile-spec…</sub>
- [ ] **`D12-046`** `alg:none`, `kid`, `jku`/`x5u` and `jwk` header attacks on the app's own token  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · Four header-level forgeries, all free to try against the token the app carries, plus the claim half.</sub>

**🟨 Medium ceiling**

- [ ] **`D12-047`** An expired JWT in the binary is reconnaissance, not a dead end  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.sensitive_information_disclosed` · AM-12 (recon) → AM-01 · An eight-year-expired token is still intel. Its claim names tell you how to shape a forgery later; its `alg` t…</sub>

**🟧 High ceiling**

- [ ] **`D12-048`** `setUserAuthenticationRequired` absent on a key that gates a sensitive action  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-11 physical unlocked / AM-08 ma · Hardware backing protects **extraction**, not **use**. A key with no auth requirement is usable by anything ru…</sub>
- [ ] **`D12-049`** Time-window auth presented as per-operation auth — the keyguard-asserted differential  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-11 / AM-08 · A non-zero duration means the key is usable by *anything* in the UID for that window after any qualifying unlo…</sub>
- [ ] **`D12-050`** `setInvalidatedByBiometricEnrollment(false)` — enrol your own finger  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-11 physical unlocked (a borrowe · The default invalidates a biometric-bound key on new enrolment. Setting it `false` means an attacker with brie…</sub>
- [ ] **`D12-051`** `setUnlockedDeviceRequired` absent on a key used only in the foreground  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-10 physical locked · Without it, the key remains usable while the device is locked — so a background service, an exported entry poi…</sub>
- [ ] **`D12-052`** Smart Lock and trusted places — `setUnlockedDeviceRequired` is not "user present"  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-11 (an attacker in the trusted  · `setUnlockedDeviceRequired(true)` asserts only that the device is *not locked*. With Smart Lock extend-unlock …</sub>
- [ ] **`D12-053`** The no-secure-lock device — the auth-bound key silently becomes an unprotected key  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-10/AM-11 — and this is exactly  · A key with `setUserAuthenticationRequired(true)` **cannot be generated** on a device with no PIN, pattern or p…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-054`** StrongBox requested, software fallback taken silently  
   <sub>``cryptographic_weakness.insecure_key_generation.insufficient_key_space` (P3) i` · AM-11 with a device that lacks Str · Read the `catch` block. Apps commonly fall back to a *software* key while the UI continues to claim hardware p…</sub>

**🟧 High ceiling**

- [ ] **`D12-055`** `KeyStoreException` / `ProviderException` catch-all → permanent software downgrade  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-03/AM-08 after the downgrade; A · `catch (Exception e) { useSoftwareFallback(); }` around key generation means a **transient** KeyMint error per…</sub>
- [ ] **`D12-056`** The key also exists as a `byte[]` in-process — there is no hardware guarantee at all  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-08/AM-03 with in-process code e · A key visible in a `SecretKeySpec`/`Cipher.init` hook is by definition extractable — it never lived in hardwar…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-057`** `setRandomizedEncryptionRequired(false)` — the caller supplies the IV on a Keystore key  
   <sub>``cryptographic_weakness.insufficient_entropy.predictable_initialization_vector` · AM-03/AM-08 · By default a Keystore key requires randomised encryption — the system generates the IV and the caller cannot c…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-058`** Keystore used as a decryption or signing oracle by an exported surface  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 zero-permission local app · Key material can be perfectly protected while the *capability* is fully delegated. Find every path that perfor…</sub>
- [ ] **`D12-059`** `KeyStoreManager.grantKeyAccess()` (Android 16) — a Keystore key shared to another UID  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-08 / AM-03 (the grantee) · Any grant widens the key's trust boundary. A grant to a UID the app does not control, or a grant that is never…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-060`** `EncryptedSharedPreferences` / `MasterKey` present but the master key is not auth-bound  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-08/AM-03 with an in-process or  · "It uses `EncryptedSharedPreferences`" is not an answer. Encrypted-at-rest is defeated by any in-process primi…</sub>

**🟩 Low ceiling**

- [ ] **`D12-061`** Keying material not cleared on logout or account removal  
   <sub>``cryptographic_weakness.incomplete_cleanup_of_keying_material` (**P5**, CWE-45` · AM-11 / AM-03 with a read primitiv · Keys, passphrases and wrapped blobs that survive an explicit logout. This is P5 on its own; its value is as a …</sub>
- [ ] **`D12-062`** No StrongBox request and no attestation verification — the fair comment on any device  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (v` · AM-12 (static observation) · You cannot characterise hardware backing from an emulator, but you can always state, by `file:line`, that the …</sub>

**🟧 High ceiling**

- [ ] **`D12-063`** Key attestation verified on the client instead of on a server  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-12 for the bypass demonstration · The whole point of attestation is that the device may be compromised. Verification performed in the app — pars…</sub>

**🟥 Critical ceiling**

- [ ] **`D12-064`** Attestation challenge not bound to a fresh server nonce (replay)  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 · `setAttestationChallenge()` must carry a fresh, server-issued, single-use value. A constant, a client-generate…</sub>
- [ ] **`D12-065`** Attestation extension read from the wrong certificate in the chain  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · If the server does verify, check *which* certificate it parses the extension from. Trusting the leaf lets anyo…</sub>

**🟧 High ceiling**

- [ ] **`D12-066`** `attestationSecurityLevel` `SOFTWARE` accepted, or no CRL check  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-01 · Verifiers commonly (a) skip the revocation list, (b) accept `attestationSecurityLevel = SOFTWARE`, and (c) do …</sub>
- [ ] **`D12-067`** `RootOfTrust` present and ignored — `deviceLocked` / `verifiedBootState`  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-01 (from a bootloader-unlocked  · A verified attestation carries the boot state. Check that the server actually gates on it — an unlocked bootlo…</sub>
- [ ] **`D12-068`** `attestationApplicationId` [709] not checked — the clean-device relay  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-11/AM-12 for the relay, AM-01 f · The extension proves that *some* acceptable TEE/StrongBox generated the leaf key for that challenge. It does *…</sub>
- [ ] **`D12-069`** Attestation root rotation and RKP certificate lifetimes  
   <sub>``cryptographic_weakness.use_of_expired_cryptographic_key_or_cert` (P4) for acc` · AM-01 · Two moving parts. A verifier that pins only the old root is about to break; a verifier that skips validity che…</sub>

**🟨 Medium ceiling**

- [ ] **`D12-070`** Explicitly named JCA provider, and bundled BouncyCastle re-registered  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_li` · AM-01 · Naming a provider is a compatibility and a security problem: providers have been removed, the call can silentl…</sub>
- [ ] **`D12-071`** A provider inserted ahead of Conscrypt, opting the process out of Mainline fixes  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_li` · AM-06/AM-01 · Conscrypt is Mainline-updated. An app that inserts its own provider at position 1 opts out of those security u…</sub>
- [ ] **`D12-072`** Bundled OpenSSL or SQLCipher crypto version  
   <sub>``cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_li` · AM-06/AM-09 · Extract the version string from the binary, not from the wrapper's version number — the SQLCipher release numb…</sub>

**🟧 High ceiling**

- [ ] **`D12-073`** SQLCipher passphrase recoverable — the "encrypted" database is decorative  
   <sub>`rate the recovered plaintext: `sensitive_data_exposure.disclosure_of_secrets.*` · AM-03 with a read primitive; AM-01 · The encryption is only as strong as the passphrase source. A literal, a device-id derivation or a trivially-de…</sub>
- [ ] **`D12-074`** Offline DRM `keySetId` persisted without binding to the account or the entitlement  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_guid` (P4) as fi` · AM-05 another user of the same app · Media3/ExoPlayer offline playback stores a licence key-set id alongside the downloaded media. If that blob is …</sub>
- [ ] **`D12-075`** `E2eeContactKeysManager` (Android 15) — silent key substitution  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-09 malicious backend / AM-08 · For a messaging app the verification UX and the key-change handling *are* the security boundary. Does the app …</sub>
- [ ] **`D12-076`** E2EE key verification not performed, or the E2EE passphrase is low-entropy  
   <sub>``cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptog` · AM-09 / AM-05 · Two halves, and the verification half pays fifteen times what the hygiene half pays. Does the client verify th…</sub>

**⬜ Support ceiling**

- [ ] **`D12-077`** Emulator Keystore artefacts that must NEVER be reported  
   <sub>`n/a — this is a false-positive suppression rule` · AM-12 (harness) · On a standard AVD the Keystore is software-backed and the attestation chain terminates in Google's **Software*…</sub>
- [ ] **`D12-078`** Auth-bound key generation failing without a lockscreen is a harness problem  
   <sub>`n/a — prevents a fabricated crypto finding` · AM-12 (harness) · A key with `setUserAuthenticationRequired(true)` **cannot be generated** on a device with no secure lock. "Key…</sub>
- [ ] **`D12-079`** The impact requirement — a crypto finding without a decryption or a forgery is Informational  
   <sub>`n/a (severity governance for the whole chapter)` · AM-12 (discipline) · Before filing anything from this chapter, answer three questions in writing. **(1)** What is the key-material …</sub>
- [ ] **`D12-080`** Severity and filing discipline for a crypto chain  
   <sub>`n/a (reporting governance — see D27)` · AM-12 (discipline) · Crypto findings are almost always chains — extract key → decrypt store → replay token → reach data — and chain…</sub>

<details><summary>⚰️ D12 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `KeyInfo.isInsideSecureHardware() == false` / `getSecurityLevel() == 0` on an emulator | A property of the AVD's software Keystore, not of the app. Physical devices report `TrustedEnvironment`/`StrongBox` | The same measurement on a **physical device**, with the model named, on a key the app documents as hardware-backed (D12-056) |
| `StrongBoxUnavailableException` on a device without `android.hardware.strongbox_keystore` | Documented behaviour of `setIsStrongBoxBacked(true)` on hardware that lacks StrongBox | The app's silent **software fallback** after the exception while the UI still claims hardware protection (D12-054) |
| Auth-bound key generation throwing on your lockscreen-less test device | Keys with `setUserAuthenticationRequired(true)` cannot be generated without a secure lock — set a PIN (D12-078) | The **app's** fallback to an unprotected key on a real user's lock-less device (D12-053) |
| "The app uses `Cipher.getInstance("AES")`" with no reachable secret | A grep hit. MASTG-TEST-0350 requires the "Further Validation" step: confirm the encrypted data is sensitive | Identical ciphertext blocks on real user data, or a block-swap the server accepts (D12-014) |
| `RSA/ECB/OAEPPadding` or `RSA/ECB/PKCS1Padding` reported as ECB mode | `ECB` is a JCA API placeholder for RSA; RSA does not use a block-cipher mode | Nothing — this is always a false positive. Do not file it |
| MD5 or SHA-1 present anywhere in the app | Usually a cache key, ETag, dedup id or a third-party library's bookkeeping | The digest deciding an integrity or authentication outcome, with a passing forged input (D12-016) |
| `new Random()` present anywhere in the app | MASTG-TEST-0204 requires the value to be "used for security-relevant purposes". UI jitter and shuffles are not | The predicted **next** value accepted by the app or server (D12-033) |
| IV reuse with no demonstrated consequence | `cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` = **P5** | Recovered plaintext (CTR XOR) or a forged GCM tag (D12-020), or a padding oracle built on it (D12-018) |
| PRNG seed reuse with no demonstrated prediction | `.prng_seed_reuse` = **P5** | Seed recovery plus a first-attempt prediction the server accepts (D12-035, D12-036) |
| Same key used for two purposes inside one environment | `cryptographic_weakness.key_reuse.intra_environment` = **P5** | The same key across **prod and staging** = `key_reuse.inter_environment` **P2** (D12-030), or a built cross-protocol attack |
| Predictable salt on its own | `cryptographic_weakness.weak_hash.use_of_predictable_salt` = **P5** | Paired with a weak KDF and an executed offline brute force that recovers the plaintext (D12-026) |
| E2EE or session keys not cleared on logout | `cryptographic_weakness.incomplete_cleanup_of_keying_material` = **P5**; Nextcloud paid $100 for exactly this | The **verification** failure beside it, which paid $1,500 at the same programme (D12-076) |
| A hardcoded third-party API key (Maps, Sentry, Crashlytics, Firebase, Branch, Kinesis) | Google Mobile VRP: "Hardcoded API keys" flatly non-qualifying. Xiaomi, Spotify, Grab, Reddit exclude these by name. `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` = **P5** | The key returning **customer data** or performing a privileged action — then it is `disclosure_of_secrets.for_publicly_accessible_asset` **P1** (D12-011) |
| An OAuth `client_secret` recovered from the mobile app | Never-submit. Public clients are not expected to hold a confidential secret; Xiaomi and Spotify name it out of scope explicitly | **PKCE non-enforcement** on the same flow is the reportable finding (D12-037), as is a weak `code_verifier` PRNG |
| An expired JWT found in the binary | `sensitive_data_exposure.disclosure_of_secrets.sensitive_information_disclosed_jwt` = **P5** | Its claim shape and path inventory driving a shadow-API version diff or a secret-recovery forge (D12-047 → D12-043/D12-044) |
| A named JCA provider (`getInstance(alg, "BC")`) | Often Informational under HackerOne rating; a compatibility issue as much as a security one | The bundled provider supplying a weak primitive the platform refuses, with the primitive shown in use (D12-070, D12-021) |
| An embedded OpenSSL version string in a bundled `.so` | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5** without reachability | A Frida hook showing the app routing crypto/TLS through that module, plus a specific advisory (D12-072) |
| AES-128 reported as an insufficient key size | MASTG's AES-128 position is explicitly forward-looking ("considering quantum computing attacks") | RSA-1024 or below, EC below 224, or a 64-bit symmetric key (D12-025) |
| A Frida hook bypassing the biometric prompt on your own rooted device | Triage reads this as "root detection bypass" and closes it; AM-12 is not an attacker | The **absence of key binding** shown by a null `CryptoObject` plus the secret released (D12-048) |
| "The app does not use StrongBox" | A hardening observation, not a vulnerability, on a device class where StrongBox may not exist | Paired with a server that trusts a client-asserted hardware claim (D12-062 → D12-063) |
| Certificate pinning absent or defeatable | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` / `.defeatable` = **P5**, and AM-07 (a trusted CA you installed) is a tester convenience, not an attacker | Belongs to D14 entirely; here it matters only as the means of capturing ciphertext for D12-018/D12-041 |
| Data stored unencrypted on internal storage | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` = **P5**; SELinux confines `/data/data` per app and `MODE_WORLD_*` throws at API 24+ | A demonstrated read primitive from D07/D08, or the same data on external storage (P4) — and it is D11's finding, not D12's |

</details>


<details><summary>🔗 D12 cross-surface joins — park these, chase them in P7</summary>

- **D12 key provenance × D11 storage mode.** Everyone reviews "is the data encrypted?" and "where is the
  key?" separately, and both pass in isolation: the store is `EncryptedSharedPreferences` and the key is in
  `AndroidKeyStore`. The join is the master key's `KeyGenParameterSpec`: with `userAuthRequired=false` the
  encryption is defeated by any in-process primitive, so the D11 "encrypted at rest" mitigation is void and
  the D11 finding's severity should be recalculated. File the D12 key property as the primitive and attach
  it to the storage report — that is the pairing that turns a P5 storage note into a rated finding.
- **D12 Keystore-as-oracle × D05/D06/D07 exported components.** The IPC reviewer sees a receiver that takes
  a string and returns a string, and rates it Low because "it does not leak anything". The crypto reviewer
  sees a key with perfect hardware protection and rates it safe. Joined: the receiver is a decryption and
  signing oracle driven by any zero-permission app on the device (AM-03), and hardware protection of the
  *key* is irrelevant because the *capability* was exported. AOSP says this in its own security model and
  almost no checklist tests it (D12-058).
- **D12 hardcoded signing key × D12-043 shadow API × D15 business logic.** Three surfaces nobody joins. The
  binary's base URL points at `/v1/`; the current web app uses `/v3/`. The reverser recovers the `/v3/`
  signing scheme and spends a day on it — while `/v1/` never required a signature at all. Behaviourally
  diff every versioned path the binary knows about, with and without the signing headers, before reversing
  anything. This is the highest-yield structural move available in a mobile crypto review.
- **D12 weak PRNG × D04/D05 restart primitive.** A time-seeded `java.util.Random` is theoretically
  predictable and practically not — unless you can control *when* the process starts. The activity reviewer
  has a crash or a launcher intent and calls it a P5 DoS; the crypto reviewer has a seed with an unknown
  value. Joined, the seed space collapses to a few hundred milliseconds and the challenge becomes
  predictable on the first attempt (D12-036; the Galaxy Store chain's bug 4).
- **D12 key attestation × D21 root/RASP × D23 payments.** The RASP reviewer proves root detection can be
  bypassed and gets told "that requires a rooted device, out of scope". The crypto reviewer sees an
  attestation chain and assumes it is sound. Joined: the chain never binds to the session or the
  transaction, so a clean-device relay produces genuine hardware attestation for a rooted attacker, and
  every fraud control built on "this is a real, locked device" collapses — without breaking any
  cryptography (D12-068).
- **D12 auth-bound keys × the device's lock state.** Every checklist tests the key properties on a
  PIN-protected device. Nobody tests the no-secure-lock device — which is exactly the device a thief has —
  or the Smart Lock trusted-place device, where `setUnlockedDeviceRequired(true)` is satisfied while the
  phone sits unattended on a desk. Two device states in which the standard recommendations silently do
  nothing (D12-052, D12-053).
- **D12 crypto census × D19 framework detection.** The single largest false-negative generator in this
  domain is a clean `jadx/sources` crypto grep on a React Native or Flutter app. The framework reviewer
  knows the app is RN; the crypto reviewer records "no crypto misuse found". Joined, the same grep over the
  Hermes string table or the blutter object-pool dump returns the key, the storage-key names and the route
  table (D12-003).
- **D12 request signing × D14 pinning × D26 harness.** Pinning is P5 and worth nothing as a finding, but
  without defeating it you never see the signed request body, and without the signed body you cannot run
  the four-probe server-enforcement test that produces the actual P1. The join is procedural: D14 work is
  the *cost* of the D12 finding, so budget it first and never file it as a finding of its own.
- **D12 key reuse across installs × D18 backend multi-tenancy.** A shared key is P5 `intra_environment`
  until you can reach another user's ciphertext. The backend reviewer has an endpoint that returns an
  encrypted field for an arbitrary object id; the crypto reviewer has the key. Joined, you decrypt another
  tenant's data with a key from the public APK — cross-user impact with no physical access, which is
  precisely the exclusion escape hatch every program writes into its policy (D12-031).

</details>


---

## D13 Authentication, Session, OTP & Biometrics

**Phase P6 · `M6` · 90 items** — 🟥 19 critical · 🟧 15 high · 🟨 1 medium · ⬜ 55 support  

📄 Full detail, with every command and proof: [`checklist/D13-auth-session-otp-biometrics.md`](checklist/D13-auth-session-otp-biometrics.md)

> **Crux question.** **Does anything the server checks actually depend on the user having authenticated — or is every gate in this app a boolean the client computes, a header the client echoes, and a token the client can hand to `curl`?**

It pays because it is the only Android-adjacent domain whose findings are priced on outcome rather than on category. The entire mobile branch of the Bugcrowd VRT is pinned at P5 — pinning absent or defeatable, auto-backup, clipboard, tapjacking, root-detection absence, unencrypted internal storage — so a report whose headline is "the app stores a token in `shared_prefs`" is P5 by construction. The *same* token, replayed with `curl` from a host that has never run the app and returning another account's `/me`, is filed as `authentication_bypass` at P1. That reframing is the single highest-leverage move in mobile bug bounty, and it lives entirely in D13. Every local primitive from D07, D08, D09, D10, D11 and D14 terminates here or terminates nowhere.


**⬜ Support ceiling**

- [ ] **`D13-001`** The layer-ordering trap: a validation error does not prove you passed auth  
   <sub>`n/a — kill gate protecting `broken_authentication_and_session_management.authe` · AM-01 · Many stacks run a global body parser, schema filter or input sanitiser *in front of* the auth middleware. A ma…</sub>
- [ ] **`D13-002`** Body-diff rule and server-policy-vs-state on every auth bypass claim  
   <sub>`n/a — evidence gate` · AM-01 · A bypass claim needs a response **body** differential, not a status code. A byte-identical 200 is not a bypass…</sub>
- [ ] **`D13-003`** Marker discipline when proving cross-account or pre-auth reach  
   <sub>`n/a — evidence gate` · AM-05 · The "victim" account must carry a marker that cannot occur naturally. Random alphanumeric, **8+ characters**, …</sub>
- [ ] **`D13-004`** Statistical-sample rule for throttle, race and timing claims  
   <sub>`n/a — evidence gate for `server_security_misconfiguration.no_rate_limiting_on_` · AM-01 · Single outliers are not signal. For timing, a minimum of **n ≥ 10 interleaved trials per group**, randomised o…</sub>
- [ ] **`D13-005`** Shell-loop ban on OTP and credential sweeps — count your results  
   <sub>`n/a — methodology gate` · AM-01 · zsh array expansion fails **silently**. A `for x in "${arr[@]}"` loop can produce zero iterations with no erro…</sub>
- [ ] **`D13-006`** Severity governance: run the pre-severity gate against the Critical claim  
   <sub>`n/a — governs every P1/P2 claim in this chapter` · Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each question. (1)…</sub>
- [ ] **`D13-007`** Retraction discipline — and not retracting a Critical the client patched  
   <sub>Two opposite rules that are easy to confuse. When a claimed finding fails reproduction, document the retractio…</sub>
- [ ] **`D13-008`** Evidence hygiene for credential-change findings: the five-screenshot pattern and the PII split  
   <sub>`n/a — evidence gate` · A state change needs pre-state, the bug, both post-states and the out-of-band side effect. Five captures, take…</sub>
- [ ] **`D13-009`** Chain-filing order for auth chains  
   <sub>`n/a — submission mechanics` · File the primitives **first**, so their submission ids exist, then file the chain consumer, then backfill the …</sub>
- [ ] **`D13-010`** Does the "device-bound" token still work from curl?  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 (with a leaked token), AM-12 · Vendors routinely describe their tokens as device-bound because the *client* attaches a device id. A header th…</sub>

**🟧 High ceiling**

- [ ] **`D13-011`** DPoP is declared — is the proof actually validated?  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) once` · AM-01 · A server with the appearance of sender-constraining and none of the substance. Degrade the proof five ways and…</sub>

**⬜ Support ceiling**

- [ ] **`D13-012`** Shadow API: the mobile app's backend calls are an older, weaker API version  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 · Old API versions stay reachable without receiving the same fixes, and a mobile app's hardcoded endpoints are t…</sub>

**🟧 High ceiling**

- [ ] **`D13-013`** The mobile auth endpoint does not inherit the web login's lockout  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 · Rate limiting, CAPTCHA, device fingerprinting and account lockout are frequently implemented on the web login …</sub>

**⬜ Support ceiling**

- [ ] **`D13-014`** ROPC (`grant_type=password`) or implicit grant on the token endpoint  
   <sub>``server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) standal` · AM-01 · Some apps POST the user's username and password straight to `/oauth/token`. That puts the credential in the ap…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-015`** Hardcoded backdoor credential or alternate authentication path in the login code  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · Read the login code path end to end for special-cased usernames, build-flavour branches, or a *second* HTTP cl…</sub>
- [ ] **`D13-016`** App-level service credential in the binary (authenticates the app, not the user)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Distinct from a user session token: a credential that authenticates *the app*. Once it leaks, user-level authe…</sub>

**⬜ Support ceiling**

- [ ] **`D13-017`** Attestation-gated endpoints: is the verdict checked on the server?  
   <sub>`rated on what the gate protects; the client-side bypass alone is `lack_of_bina` · AM-12 for the bypass, AM-01 for th · Many apps request the verdict, check it locally, and send an unauthenticated boolean to the server. The findin…</sub>
- [ ] **`D13-018`** Session not invalidated server-side on logout  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-01 (with a stolen token), AM-11 · Many implementations only delete the client cookie or the local store. Replay the **captured value explicitly*…</sub>
- [ ] **`D13-019`** Sibling sessions survive password change and email change  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-01 · Apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). Sibling survival is the ex…</sub>
- [ ] **`D13-020`** Refresh-token rotation and reuse detection  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 · Three distinct outcomes with three different severities: (a) no rotation at all — RT1 == RT0, a long-lived ste…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-021`** Revoked OAuth grant that comes back to life — the 20-hour re-test  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.pe` · AM-01 · Almost every tester checks revocation immediately, sees the app break, and stops. The bug lives on the other s…</sub>

**🟧 High ceiling**

- [ ] **`D13-022`** Active-devices screen: revoke-by-id IDOR and the invisible session class  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-05 · "Where you're logged in" is a component almost no mobile test exercises, and it carries two bugs. The revoke c…</sub>

**🟨 Medium ceiling**

- [ ] **`D13-023`** Deactivated or de-provisioned account still authenticates on mobile  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-05 · Offboarding is implemented in the web admin and enforced by the web session layer. The mobile login path and t…</sub>

**⬜ Support ceiling**

- [ ] **`D13-024`** Session identifier quality: fixation across the auth boundary, and measured entropy  
   <sub>``broken_authentication_and_session_management.session_fixation.remote_attack_v` · AM-02 (fixation), AM-01 (entropy) · Two properties of the same artefact. (1) The server must regenerate the session id at login — PHP `session_sta…</sub>

**🟧 High ceiling**

- [ ] **`D13-025`** Authenticated API calls before the biometric prompt; the session outlives the app lock  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-11, AM-03 (any in-process primi · The lock screen is cosmetic if the session is already live behind it. Watch the request timeline *before* touc…</sub>
- [ ] **`D13-026`** The account-state transition matrix  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.*`` · AM-01, AM-11 (shared device) · Drive every state transition the app supports and replay the pre-transition token after each. The transitions …</sub>

**🟥 Critical ceiling**

- [ ] **`D13-027`** JWT algorithm, key and claim battery against the server  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-01 · Run the standard battery against the **server**, from curl, starting from a token you legitimately own.</sub>

**⬜ Support ceiling**

- [ ] **`D13-028`** JWT lifetime, `jti` and the absence of a revocation list  
   <sub>``broken_authentication_and_session_management.excessive_jwt_lifetime` (P5); `i` · AM-01 · Missing `exp` (or `exp` years out) means permanent access. Missing `jti` means the server cannot maintain a re…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-029`** Social-login `id_token`: `aud`, `iss` and `email_verified` validation  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-01 · Three independent checks the backend must perform and frequently does not. (1) Does `aud` match *its own* clie…</sub>

**⬜ Support ceiling**

- [ ] **`D13-030`** PKCE enforcement, not PKCE presence  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2` · AM-03 (a co-installed app with no  · The presence of `code_challenge` in the app's request proves nothing about server enforcement. Four degradatio…</sub>
- [ ] **`D13-031`** Custom-scheme redirect interception by a competing app  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2` · AM-03 · Private-use scheme redirects (`com.example.app:/oauth2redirect`) can be registered by **any** installed app; t…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-032`** `redirect_uri` matching laxity  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.insecure_redirect_uri` · AM-02 · Exact matching is the only safe configuration. Anything looser — prefix match, regex, "starts with", subdomain…</sub>

**⬜ Support ceiling**

- [ ] **`D13-033`** `state` binding, authorization-code reuse and mix-up defence  
   <sub>``server_security_misconfiguration.oauth_misconfiguration.missing_state_paramet` · AM-02 · Three token-endpoint behaviours worth a single sitting. (1) `state` may be present because the IdP requires it…</sub>
- [ ] **`D13-034`** OAuth in an embedded WebView instead of a Custom Tab  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) only` · AM-08 (the host app or an SDK insi · An embedded WebView lets the host app read the credentials the user types and the IdP's session cookies — whic…</sub>

**🟧 High ceiling**

- [ ] **`D13-035`** The OAuth path skips a control the direct signup enforces  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 · Compare what direct signup enforces against what the OAuth path enforces — email verification, scope/permissio…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-036`** Identity-provider self-service attribute abuse (Cognito / Firebase Auth / Auth0 class)  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · The app delegates identity to a provider and misconfigures it — self-service attribute updates, unverified-ema…</sub>

**⬜ Support ceiling**

- [ ] **`D13-037`** The OAuth claim-field substring trap  
   <sub>`n/a — kill gate protecting an identity-provider Critical claim` · Microsoft's MFA-required (`AADSTS50076`) and Conditional-Access claims-challenge response bodies contain the l…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-038`** OTP verify throttling — measure the boundary, do not assume absence  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) with` · AM-01 · A 6-digit OTP is a 10^6 keyspace; a 4-digit one is 10,000. The reportable fact is the **threshold**, not "six …</sub>

**⬜ Support ceiling**

- [ ] **`D13-039`** Client-only rate limit the API never enforces  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · The app shows "3 attempts remaining" and locks its own UI. The server never counted. A recovery code in the co…</sub>
- [ ] **`D13-040`** Rate-limit bypass by rotating the client-IP header  
   <sub>``server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) standal` · AM-01 · The limiter reads the client IP from a request header without validating it against the trusted-proxy chain. *…</sub>
- [ ] **`D13-041`** Capped verify × uncapped resend = an unbounded attempt budget  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) with` · AM-01 · The highest-value auth bug shape in the disclosed corpus. Verification is capped at N attempts before the code…</sub>

**🟧 High ceiling**

- [ ] **`D13-042`** OTP replay: the code does not burn, and old codes survive a new request  
   <sub>``insufficient_security_configurability.weak_two_fa_implementation.old_two_fa_c` · AM-01 · After a successful submit, the "used" flag may never be written. Separately, requesting a **new** OTP may leav…</sub>

**⬜ Support ceiling**

- [ ] **`D13-043`** Race the OTP validate (non-atomic check → mark-used → issue)  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3); `authentica` · AM-01 · The check-and-spend window lets multiple submissions of the same code succeed. This is distinct from a pure lo…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-044`** OTP echoed in a response body, header or log  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 (response echo); AM-04 (logc · Look at the `/otp/send` response body, not only `/otp/verify`. The code, a hash of it, or a `requestId` that *…</sub>

**⬜ Support ceiling**

- [ ] **`D13-045`** OTP verified client-side — response manipulation  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-06/AM-07 for the tester; AM-01  · The client branches on a boolean in the response rather than on a server-issued credential. Flip it — and then…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-046`** OTP not bound to the requesting device, session or user id  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `br` · AM-01, AM-05 · Three bindings the server should enforce and frequently does not: the code is tied to the requesting **device/…</sub>

**⬜ Support ceiling**

- [ ] **`D13-047`** OTP request side: SMS flooding and cost abuse  
   <sub>``server_security_misconfiguration.no_rate_limiting_on_form.sms_triggering` (P4` · AM-01 · `/otp/send` is a separate control surface from `/otp/verify`. Unlimited requests mean the attacker bills the v…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-048`** The four on-device OTP interception channels, tested as a set  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3) as the floor` · AM-03 (implicit broadcast, accessi · An OTP that protects login can be read by any of four independent principals. Test **all four against the same…</sub>
- [ ] **`D13-049`** SMS User Consent receiver registered without `SmsRetriever.SEND_PERMISSION`  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-03 · The documented registration passes `SmsRetriever.SEND_PERMISSION` so that **only Google Play services** may de…</sub>

**🟧 High ceiling**

- [ ] **`D13-050`** SMS OTP delivery posture: `READ_SMS` where SMS Retriever would do, and Android 15 redaction  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3); `sensitive_` · AM-04 · Two halves. (a) Does the app hold `READ_SMS`/`RECEIVE_SMS` with a plain `BroadcastReceiver` when the SMS Retri…</sub>

**⬜ Support ceiling**

- [ ] **`D13-051`** SIM-binding and MSISDN checks that trust local telephony APIs  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-12 for the forge, AM-01 for the · Flows that bind an account to a number by reading `TelephonyManager.getLine1Number()`, `SubscriptionInfo.getNu…</sub>
- [ ] **`D13-052`** SMS/voice recovery survives SIM swap; recycled numbers inherit accounts  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · A design finding you can demonstrate without any device access. Walk every recovery flow — "Forgot password", …</sub>

**🟥 Critical ceiling**

- [ ] **`D13-053`** Password-reset token: leak, non-expiry, reuse and unbinding  
   <sub>``insufficient_security_configurability.weak_password_reset_implementation.toke` · AM-01 · Four independent failures on one token. In that moment the token **is** the whole authentication.</sub>

**🟧 High ceiling**

- [ ] **`D13-054`** Reset-link poisoning via `Host` / `X-Forwarded-Host`  
   <sub>``sensitive_data_exposure.weak_password_reset_implementation.token_leakage_via_` · AM-01 · The reset-link generator builds the URL from the request host. Frameworks make this easy — Django/Rails/Expres…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-055`** Weak reset-token keyspace  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-01 · A 4-digit numeric reset token is 10,000 combinations; a 6-digit one is 10^6. Also test whether the token expir…</sub>

**⬜ Support ceiling**

- [ ] **`D13-056`** Reset or magic-link token delivered through an unverified deep link, or consumed by a prefetch  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-03 · Three mobile-specific failures on the same token. (1) The scheme is unverified, so another app claims it and h…</sub>
- [ ] **`D13-057`** Recovery / backup codes: server-returned, client-generated, or not single-use  
   <sub>``insufficient_security_configurability.weak_two_fa_implementation.two_fa_secre` · AM-01 (API), AM-03/AM-11 (screen c · Recovery codes are password-equivalent and permanently bypass 2FA. Four failures: they are returned by a fat p…</sub>
- [ ] **`D13-058`** Knowledge-based recovery and security-question abuse  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · Security answers are low-entropy and the endpoint is usually unthrottled. Two extra angles that are frequently…</sub>
- [ ] **`D13-059`** CAPTCHA token reuse or omission on an auth form  
   <sub>``server_security_misconfiguration.captcha.implementation_vulnerability` (P4); ` · AM-01 · The control is only a finding when it unlocks a consequential abuse — OTP/credential brute force or mass accou…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-060`** Account pre-hijacking on the mobile signup path — five classes  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-01 · Register against a victim's identifier **before** the victim signs up, then test whether the victim's later si…</sub>

**⬜ Support ceiling**

- [ ] **`D13-061`** Case and Unicode normalisation collision in the mobile signup path  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 · Whether the mobile signup path normalises the identifier the same way the login path does. A mismatch lets an …</sub>
- [ ] **`D13-062`** Email-verification gate enforced only in the UI  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 · Sign up in the app and, at the "check your email" screen, press **Back**, then log in with the credentials jus…</sub>
- [ ] **`D13-063`** Username/email enumeration on the app's own endpoints  
   <sub>``broken_access_control.username_enumeration.non_brute_force` (P4); `sensitive_` · AM-01 · Divergent responses on login, reset and registration confirm account existence. The app's endpoints frequently…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-064`** Enumerate every code path that returns a session  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `tw` · AM-01 · MFA enforcement is rarely middleware-level — it is checked at the end of the *primary* login handler. Every ot…</sub>
- [ ] **`D13-065`** Pre-MFA session carries post-MFA capability  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · Pre-MFA and post-MFA sessions frequently share the same cookie or token name; the flag that distinguishes them…</sub>

**🟧 High ceiling**

- [ ] **`D13-066`** MFA channel downgrade to the weakest configured factor  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3); `authentica` · AM-01 · An account offering TOTP *and* SMS/email OTP is only as strong as the weaker path, which frequently lives on a…</sub>

**⬜ Support ceiling**

- [ ] **`D13-067`** 2FA enrolment without the current factor, and factor binding before identity verification  
   <sub>``server_security_misconfiguration.lack_of_password_confirmation.manage_two_fa`` · AM-01, AM-02 (the CSRF variant) · Two related failures. (a) A second phone number or authenticator can be attached without proving control of th…</sub>
- [ ] **`D13-068`** MFA disable or TOTP-secret regeneration without step-up; secret still obtainable after enrolment  
   <sub>``insufficient_security_configurability.weak_two_fa_implementation.two_fa_secre` · AM-01, AM-11 · A "disable 2FA" toggle or "regenerate TOTP secret" action that does not require the current OTP or the passwor…</sub>
- [ ] **`D13-069`** "Remember this device" trust token unbound to anything  
   <sub>``broken_authentication_and_session_management.two_fa_bypass`` · AM-01 · A 30-day trust cookie that is a bare bearer of "MFA already done". Complete MFA on device A, capture the artef…</sub>
- [ ] **`D13-070`** The step-up matrix for sensitive actions on an unlocked device  
   <sub>``server_security_misconfiguration.lack_of_password_confirmation.change_email_a` · AM-11 (borrowed/unattended unlocke · On a borrowed or briefly-unattended unlocked phone, can the attacker perform the actions that convert temporar…</sub>
- [ ] **`D13-071`** Email or phone change without re-auth and without notifying the old identifier  
   <sub>``server_security_misconfiguration.lack_of_password_confirmation.change_email_a` · AM-01, AM-11 · The change-of-identifier flow is the shortest path to persistent ATO and is almost always weaker in the app th…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-072`** WebAuthn / passkey assertion replay across sessions  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · If the server does not bind the challenge to the session or track challenge uniqueness, the strongest commonly…</sub>

**🟧 High ceiling**

- [ ] **`D13-073`** Credential Manager legacy fallback, and Restore Credentials  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-03, AM-11 · Apps migrating to Credential Manager frequently keep the legacy path (Smart Lock, the FIDO2 API, Google Sign-I…</sub>

**⬜ Support ceiling**

- [ ] **`D13-074`** Biometric gate with no `CryptoObject` — the boolean an attacker can force  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) if i` · AM-11, AM-03 (any in-process code- · The load-bearing distinction in this whole sub-domain. `authenticate(promptInfo)` yields a boolean delivered t…</sub>

**🟧 High ceiling**

- [ ] **`D13-075`** `CryptoObject` present but the authorised cipher is never used  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) with` · AM-11, AM-03 · Class 2. Even with a `CryptoObject`, an app that does not use the *authorised* cipher for the protected data c…</sub>
- [ ] **`D13-076`** Keys not invalidated on new biometric enrolment  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-11 (attacker holds the device a · With `setInvalidatedByBiometricEnrollment(false)`, an attacker who obtains the device passcode can enrol **the…</sub>

**⬜ Support ceiling**

- [ ] **`D13-077`** Device-credential fallback, weak-class biometrics, and authenticator downgrade  
   <sub>`rated on the protected action; the configuration alone is not a VRT node` · AM-11 · Three related weakenings. (a) `setAllowedAuthenticators(... | DEVICE_CREDENTIAL)` or `setDeviceCredentialAllow…</sub>
- [ ] **`D13-078`** Passive confirmation and long key-validity windows  
   <sub>`rated on the protected action` · AM-11 · Two configuration weakenings that compound. With `setConfirmationRequired(false)`, a passive biometric (face/i…</sub>
- [ ] **`D13-079`** `requestDismissKeyguard()` or `isKeyguardLocked()` treated as authentication  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-10, AM-11 · Apps sometimes gate a sensitive screen on "the keyguard was dismissed" or "the device is secure" rather than o…</sub>

**🟧 High ceiling**

- [ ] **`D13-080`** Local PIN / passcode gate as client-side UI state  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-11, AM-12 for the measurement · App-level PIN and pattern locks are almost always client-side UI state. Four approaches, cheapest first: launc…</sub>

**⬜ Support ceiling**

- [ ] **`D13-081`** Client-side identity or liveness decision (KYC face match)  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-12 for the forge, AM-01 for the · A KYC or liveness check implemented client-side is a classification decision you can influence three ways: inj…</sub>
- [ ] **`D13-082`** Cross-platform apps: the gate lives in JS/Dart, and OTA can re-enable it  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-11 for the local flip; AM-09 (m · In cross-platform apps the "unlock" decision frequently lives in JS or Dart and only *then* fetches the secret…</sub>
- [ ] **`D13-083`** Device registration / enrolment endpoint: forge, re-point or cross-enrol  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-01, AM-05 · Mobile apps register a device — push token, device id, attestation blob, hardware key — against the account. F…</sub>
- [ ] **`D13-084`** Multi-device linking and "scan to log in" QR pairing  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-02 (the phish), AM-01 (the poll · Three failure modes in the pairing flow, plus three in the linking flow. **Pairing:** the QR payload is guessa…</sub>
- [ ] **`D13-085`** Lock-screen notification action performs an authenticated action  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-10 (physical, locked) · The corpus covers notification *content* on the lock screen and `RemoteInput` PendingIntent mutability separat…</sub>
- [ ] **`D13-086`** Account deletion without re-authentication, or reachable from an exported surface  
   <sub>``server_security_misconfiguration.lack_of_password_confirmation.delete_account` · AM-03 (exported activity / deep li · Deletion is the most destructive action in the app and is often a plain authenticated `DELETE` behind a confir…</sub>

**🟧 High ceiling**

- [ ] **`D13-087`** Deletion that does not revoke tokens, grants, push registrations or identities  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.al` · AM-01 · After deletion, check what **still** authenticates: the access token, the refresh token, the FCM registration …</sub>

**⬜ Support ceiling**

- [ ] **`D13-088`** Support-chat identity verification disabled or computed on-device  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-01, AM-05 · Support SDKs authenticate the end user with an HMAC or JWT the vendor requires to be produced **server-side**.…</sub>
- [ ] **`D13-089`** Autofill and Credential Manager leaking credentials into a WebView or an unverified package  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `se` · AM-03, AM-08 · Two sides. **Client:** a password, OTP or CVC field left at `importantForAutofill="auto"` participates in auto…</sub>

**🟥 Critical ceiling**

- [ ] **`D13-090`** Credential or long-lived token stored on device instead of a short-lived service token  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) once` · AM-03/AM-04 (via a D07/D08/D11 pri · What is actually at rest — a password, a long-lived refresh token, an `AccountManager` credential, or a short-…</sub>

<details><summary>⚰️ D13 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Session not invalidated on logout" (server-side only) | `failure_to_invalidate_session.on_logout_server_side_only` is **P5**, and it is on the never-submit list standalone. Reddit and several other programs exclude it by name. The user has already chosen to end the session. | A theft chain: a token recovered through D07/D08/D10/D11 that still authenticates after logout **and** after the password change (D13-019), replayed from a host that never ran the app. |
| Excessive JWT lifetime / `exp` months out | `excessive_jwt_lifetime` = **P5**. A long-lived token nobody can obtain is a design note. | Pair it with a token-disclosure primitive and file it *inside* that report as the amplifier (D13-028), never separately. |
| Weak JWT hashing algorithm; PII inside the JWT payload | `weak_jwt_hashing_algorithm` = **P5**; `disclosure_of_secrets.sensitive_information_disclosed_jwt` = **P5**. The algorithm being weak is not the same as the signature being forgeable. | A **forged** token the server accepts (D13-027) — cracked secret, `alg:none`, `jwk`/`jku`/`kid`, or RS256→HS256 — demonstrated on an endpoint scoped to another principal. |
| Concurrent logins allowed / no session-count limit | `concurrent_logins` = **P5**. Multi-device is a product decision. | Only if concurrency defeats a documented control — e.g. a licensing or seat limit the vendor sells (→ D23). |
| "No 2FA implementation" / "no account lockout" | `no_two_fa_implementation` = **P5**; `no_account_lockout` = **P5**. Absence of an optional control is a recommendation, not a vulnerability. | Demonstrate the exhaustion the missing control permits and show the resulting session (D13-038/041). |
| OAuth `client_secret` extracted from the APK | On the never-submit list as known and expected — a public client has no confidential secret by definition. | **PKCE non-enforcement** at the token endpoint (D13-030) is the reportable finding; the secret is context. |
| Bare host-header injection (`X-Forwarded-Host` reflected) | On the never-submit list without the downstream PoC. A reflected host is a parser artefact. | The **delivered reset email** containing `https://evil.com/reset?token=…` (D13-054) — `token_leakage_via_host_header_poisoning` = **P2**. |
| Rate-limit bypass with no demonstrated abuse | HackerOne Core Ineligible ("most issues related to rate limiting"); Grab, Reddit and HackenProof all exclude it. The bypass is the primitive; the bug is the abuse case. | Carry it through to the accepted OTP or recovery code and the issued session (D13-038/040), then file as `authentication_bypass`. |
| Username/email enumeration returning only existence | `username_enumeration.non_brute_force` = **P4**, and many programs class it low-risk information. | The response leaking **more than existence** — a real name, avatar, masked phone (→ PII exposure); or file it as the enabling half of a credential-stuffing chain with the stuffing demonstrated. |
| Biometric bypass demonstrated only with Frida on an emulator, with no `CryptoObject` analysis | Lands in `lack_of_binary_hardening.runtime_instrumentation_based` = **P5**, and invites "not a real-world bypass". Google Mobile VRP excludes secondary lockscreen bypasses outright. | The missing `CryptoObject` *plus* the released secret *plus* the server accepting it, demonstrated on a physical device (D13-074). |
| `setDeviceCredentialAllowed(true)` / `DEVICE_CREDENTIAL` in the allowed authenticators | MASTG-TEST-0326 states plainly that this "is not inherently a vulnerability… better categorized as a security weakness or hardening issue". | A finance/health/government vertical where a shoulder-surfed PIN is the realistic attack, **or** a second non-key-bound `createConfirmDeviceCredentialIntent` path (D13-077). |
| `setConfirmationRequired(false)` | MASTG: "not inherently a vulnerability. It may be appropriate for low-risk operations." | A payment or data-release action completing on a passive face match with no deliberate user action (D13-078). |
| "The app does not check for a device passcode" | Informational-to-Low; MASTG notes apps "cannot force users to enable biometrics at the system level". | The **bypass**: show the check exists, is the sole gate, and is trivially hooked or satisfied on a swipe-only device (D13-079). |
| "The login form does not support autofill / password managers" | MASWE-0019 is a usability-driven weakness; no VRT node rates it. | Show it forces the credential through the clipboard, then chain to the clipboard read in D20 (D13-089). |
| Root/emulator detection defeated, so "the biometric gate can be bypassed" | `lack_of_binary_hardening.*` is **P5** across the board. A defeated client-side check is expected on an attacker-controlled device. | Reframe entirely: the finding is that the *server* trusts a client assertion (D13-017), or that the authentication decision was never cryptographically bound (D13-074). |
| Certificate pinning absent or defeatable, used to justify "MitM against the auth flow" | `ssl_certificate_pinning.absent` and `.defeatable` are both **P5**; AM-07 (network attacker with a trusted CA) is a tester convenience, not an attacker. | A real AM-06 exposure: the auth assertion carried over **cleartext** (D13-051 silent-auth SDKs), or a token leaked to a third party the app talks to. |
| Response manipulation makes the app show the authenticated screen | Cosmetic if every subsequent API call 401s. The client's opinion of your identity is not a security boundary. | The **subsequent** API call returning real server data, or proof that a usable session was issued at the password step (D13-045). |
| An APK-derived endpoint is an older API version than the web app's | "A version difference alone is Informational." | The **weakened control** on the old path, diffed behaviourally on auth strength, rate limiting, input validation or field exposure (D13-012). |
| Pre-account takeover shown only as "I registered the victim's address" | On the never-submit list "(usually)" — the squat alone has no demonstrated victim impact. | The completed claim: the attacker's token reading the victim's **post-signup** data, or the attacker's recovery identifier surviving the victim's recovery (D13-060). |

</details>


<details><summary>🔗 D13 cross-surface joins — park these, chase them in P7</summary>

- **The OTP verify throttle × the OTP resend cooldown (D13-038 × D13-047).** Nobody tests these together because they are different endpoints owned, in large organisations, by different teams — one is "auth", the other is "notifications". Individually both look defensible: three attempts before expiry is a real cap, and a 30-second SMS cooldown is a real cost control. Joined, they are 8,640 guesses a day against a 10,000-value keyspace. This join *is* H1 #205000, and it is the single highest-yield pairing in the chapter.
- **Biometric call site (D13-074) × local token storage (→ D11) × server-side revocation (D13-018).** The three are reviewed by three different specialisms — mobile reverse engineering, storage analysis, and API testing — and each alone is P5 or Medium. Joined, they are the canonical mobile Critical: the gate is a boolean, the secret behind it is a long-lived token on disk, and the token answers from `curl` after logout. Always assemble this triple before writing any of the three separately.
- **SMS User Consent receiver (D13-049) × exported-component intent redirection (→ D08) × FileProvider grants (→ D07).** The auth tester greps for OTP handling and stops; the IPC tester enumerates receivers and does not know the GMS consent contract. The join is the self-grant gadget: the receiver launches an attacker-supplied `EXTRA_CONSENT_INTENT` **as the victim's UID**, and that intent carries `FLAG_GRANT_READ_URI_PERMISSION` to the victim's own `FileProvider`. One receiver registration yields both an OTP-injection candidate and a full file-read primitive, and the corpus's own field experience is that the second is the real finding while the first is a recorded negative.
- **Custom-scheme OAuth redirect (D13-031) × App Link verification state (→ D09) × PKCE enforcement (D13-030).** Three teams again: identity owns the token endpoint, mobile owns the manifest, and nobody owns `assetlinks.json` after the domain moves. `pm get-app-links` returning anything but `verified`, plus a token endpoint that redeems without a `code_verifier`, is AM-03 account takeover by an app with **no dangerous permissions**. Test the two together on the same afternoon — separately they read as hygiene.
- **Password-reset link generation (D13-054) × email deliverability (SPF/DMARC) × the mobile deep-link handler (D13-056).** The reset token's whole journey crosses three surfaces nobody reviews as one: the backend that builds the URL from a request header, the mail infrastructure that decides whether a spoof lands in the inbox, and the Android component that receives the resulting link. Poison the host, deliver through a spoofable domain, and have an unverified scheme handler catch the token — each step is a low-rated finding and the join is P2/P1.
- **Step-up matrix (D13-070) × the session-list UI (D13-022) × notification posture (D13-085).** An unlocked-device attacker changes the recovery email with no step-up; the victim's session list never showed the attacker's session class so there is nothing to revoke; and the "your email was changed" notification was never sent to the **old** address. Three separate teams' omissions, and together they are silent, permanent account takeover. The absent notification is the cheapest evidence in the whole chapter and the one most often left out of reports.
- **Refresh-token rotation (D13-020) × device-to-device restore / Restore Credentials (D13-073) × backup extraction (→ D02/D11).** Rotation is an identity-team property, restore is a platform-integration property, and backup configuration is a manifest property. Joined: a non-rotating refresh token that travels in a device-to-device transfer means the victim's *new phone setup* hands an attacker who holds the backup a credential that survives every password change. Ask explicitly whether the app opts out of D2D transfer for its credential store.
- **Support-chat identity verification (D13-088) × support-agent reset powers (D13-058) × the in-app support WebView (→ D10).** Security reviews treat the support SDK as a third-party integration and skip it. But the support thread is frequently a *recovery channel* — agents perform resets from it — so an SDK whose HMAC secret ships in the APK is not a privacy issue, it is an authentication issue, and its severity is set by what the agent on the other end is permitted to do.
- **Biometric enrolment invalidation (D13-076) × device-credential fallback (D13-077) × the device's own lock settings.** Each is a MASTG checkbox; together they collapse the gate. `setInvalidatedByBiometricEnrollment(false)` plus `DEVICE_CREDENTIAL` in the allowed authenticators means: know the PIN, enrol your own finger, and the app's "biometric protection" is the PIN you already have. Neither flag alone earns more than Medium; the pair is a High with a no-instrumentation PoC.

</details>


---

## D14 Network Security, TLS & Certificate Pinning

**Phase P6 · `M6` · 58 items** — 🟥 14 critical · 🟧 15 high · 🟨 13 medium · 🟩 4 low · ⬜ 12 support  

📄 Full detail, with every command and proof: [`checklist/D14-network-tls-pinning.md`](checklist/D14-network-tls-pinning.md)

> **Crux question.** **Is there any request on this app's wire that an attacker holding no trusted CA can read or rewrite — and does that request carry an authentication assertion, PII, or content the app will execute?** If the answer needs your CA installed to be true, you have a P5 pinning observation, not a finding.

It mostly does not, and you should know that before you start. Bugcrowd rates
`mobile_security_misconfiguration|ssl_certificate_pinning|absent` **P5** and `|defeatable` **P5** —
bypassing an existing pin is worth exactly as much as never having one. HackerOne's Core Ineligible
Findings list carries "Lack of SSL Pinning" under *Optional security hardening steps / Missing best
practices*, and HackerOne Platform Standards states the rule outright: "If a report requires an attacker
to disable Certificate Pinning in an application, then that is not a valid vulnerability." Xiaomi, Grab,
Spotify, Starbucks and Snapchat all exclude it by name. The VRT changelog even records the node being
moved *out of* `insecure_data_transport` and *into* `mobile_security_misconfiguration` — a formal
reclassification from a transport flaw to a configuration preference. Add to that HackerOne's blanket
"SSL/TLS Configurations" exclusion, Grab's "weak TLS/SSL versions & ciphers", Reddit's "Weak SSL/TLS/SSH
algorithms", Basecamp's "insecure SSL/TLS ciphers unless you have a working proof of concept", and the
graveyard in this chapter is larger than the findings list.


**⬜ Support ceiling**

- [ ] **`D14-001`** Fix the TLS baseline from `targetSdkVersion` before reading any config  
   <sub>`n/a (baseline; governs the rating of every item below)` · Establish the platform defaults that apply to *this* build, so a default is never written up as a finding and …</sub>
- [ ] **`D14-002`** Pass the harness acceptance gate before asserting anything about pinning  
   <sub>n/a (AM-07 tooling) · Prove your CA is trusted *from inside a forked app process* before you conclude the target pins. A bind-mount …</sub>
- [ ] **`D14-003`** Never infer pinning from a failed MitM — use the failure *shape* and the platform log  
   <sub>`n/a (false-positive gate for `mobile_security_misconfiguration\` · Decide "pinned / not pinned" from three independent signals, never from whether your proxy happened to work.</sub>
- [ ] **`D14-004`** Run a pcap beside the proxy and chase every destination the proxy never saw  
   <sub>`n/a (coverage; the severity belongs to what the unproxied channel carries)` · A proxy is a filter, not a capture. It sees only what honours the system HTTP proxy. Raw sockets, gRPC, QUIC/H…</sub>

**🟩 Low ceiling**

- [ ] **`D14-005`** Transparent/gateway interception, and forcing QUIC down to TCP  
   <sub>`n/a as tooling; the proxy-ignoring behaviour is a testability observation` · n/a (lab form of AM-06) · When a flow will not appear under a configured proxy, fall back to layer-3 redirection rather than to more pro…</sub>

**⬜ Support ceiling**

- [ ] **`D14-006`** Test the cellular path, not just the lab Wi-Fi  
   <sub>`n/a (the severity belongs to the cellular-only behaviour found)` · AM-06 · Carrier-network behaviour differs — header enrichment, carrier-specific endpoints, a different edge/CDN, and i…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-007`** Custom `X509TrustManager` whose `checkServerTrusted` does not validate  
   <sub>``insecure_data_transport\` · AM-06 · Any connection configured with a `TrustManager` whose `checkServerTrusted` does not validate the chain accepts…</sub>
- [ ] **`D14-008`** `checkServerTrusted` that validates *something* but not the chain  
   <sub>``insecure_data_transport\` · AM-06 · The empty body is the easy case. The paying case is a body that *looks* like validation and is not. MASTG enum…</sub>
- [ ] **`D14-009`** `HostnameVerifier` returning `true`, or `ALLOW_ALL_HOSTNAME_VERIFIER`  
   <sub>``insecure_data_transport\` · AM-06 (and any attacker who can bu · Chain validation can be perfect and the connection still worthless if the hostname is not checked: any certifi…</sub>
- [ ] **`D14-010`** `SSLSocket` used with no hostname verification at all — and the NSC does not cover it  
   <sub>``insecure_data_transport\` · AM-06 · `SSLSocket` does **not** perform hostname verification by default, and MASTG states the consequence explicitly…</sub>

**🟧 High ceiling**

- [ ] **`D14-011`** Incomplete verification coverage — right on the main client, wrong on a secondary channel  
   <sub>``insecure_data_transport\` · AM-06 · Enumerate every TLS-bearing channel in the app and test each one separately. Validation is routinely correct o…</sub>
- [ ] **`D14-012`** `WebViewClient.onReceivedSslError` calling `handler.proceed()`  
   <sub>``insecure_data_transport\` · AM-06 · An app can validate correctly on its API client and still ship a WebView that proceeds through certificate err…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-013`** A third-party SDK installing a process-global permissive verifier or socket factory  
   <sub>``insecure_data_transport\` · AM-08 (malicious/negligent SDK) de · `HttpsURLConnection.setDefaultHostnameVerifier(...)` and `HttpsURLConnection.setDefaultSSLSocketFactory(...)` …</sub>

**🟧 High ceiling**

- [ ] **`D14-014`** OkHttp below 4.9.2 — hostname-verification bypass (CVE-2021-0341)  
   <sub>``insecure_data_transport\` · AM-06 · Version alone is informational. The reachability condition is whether the app or an SDK makes **manual** verif…</sub>

**⬜ Support ceiling**

- [ ] **`D14-015`** Separate trust-all from a legitimate TLS-1.2 enablement shim (false-positive gate)  
   <sub>`n/a (kill gate for D14-007..D14-010)` · Three things look alike in decompiled code and only one is a bug: (a) an empty `checkServerTrusted` that trust…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-016`** Cleartext permitted by configuration — read against the right default  
   <sub>``insecure_data_transport\` · AM-06 · Determine whether HTTP is *allowed*, and by which mechanism, with the API-level default stated. On a modern ta…</sub>

**🟧 High ceiling**

- [ ] **`D14-017`** Per-domain `cleartextTrafficPermitted="true"` carve-outs on first-party hosts  
   <sub>``insecure_data_transport\` · AM-06 · The global default being secure hides the per-domain exception. Enumerate every `<domain-config>` and classify…</sub>
- [ ] **`D14-018`** Cleartext observed on the wire and attributed to the app's UID  
   <sub>``insecure_data_transport\` · AM-06 · Static config shows what is *possible*. Capture what actually happens, and attribute the socket to the app — M…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-019`** Hardcoded `http://` URLs proven to be reachable — and the unregistered-domain check  
   <sub>``insecure_data_transport\` · AM-06; **AM-01** when the hardcode · MASTG is explicit that presence is not enough: "The presence of HTTP URLs alone does not necessarily mean they…</sub>

**🟧 High ceiling**

- [ ] **`D14-020`** `ws://` WebSocket transport, and per-message authorisation on `wss://`  
   <sub>``insecure_data_transport\` · AM-06 for `ws://`; AM-05 for the a · Two separate bugs. (a) The socket URL is `ws://`, so the whole channel is in clear including the token used to…</sub>
- [ ] **`D14-021`** HTTPS→HTTP downgrade: does the client follow a redirect to `http://`?  
   <sub>``insecure_data_transport\` · AM-06 (needs only to answer the fi · Even a fully HTTPS app can be downgraded if the client follows a cross-scheme redirect, or if the very first r…</sub>
- [ ] **`D14-022`** The NSC does not govern non-platform HTTP stacks — "cleartext is impossible" is false  
   <sub>``insecure_data_transport\` · AM-06 · A Network Security Configuration that forbids cleartext constrains the platform `HttpsURLConnection`/OkHttp pa…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-023`** Loopback and LAN listeners: the sockets the NSC and Local Network Protection do not cover  
   <sub>``broken_authentication_and_session_management\` · **AM-03** zero-permission local ap · Android does **not** isolate loopback sockets between apps. An app implementing the desktop-style "local HTTP …</sub>

**🟧 High ceiling**

- [ ] **`D14-024`** Non-HTTP and non-standard-port channels that escape the harness  
   <sub>`rated on the channel's contents; `insecure_data_transport\` · AM-06 · MQTT, XMPP, raw TCP, gRPC over h2c, WebSocket on an odd port and QUIC/UDP routinely carry the most sensitive p…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-025`** Sensitive values in the request line rather than the body  
   <sub>``sensitive_data_exposure\` · AM-09 (log-holder), AM-06 over cle · Tokens, OTPs, PANs and PII in the query string land in server logs, proxy logs, CDN logs and `Referer` headers…</sub>

**🟧 High ceiling**

- [ ] **`D14-026`** `<certificates src="user"/>` shipped in a production trust anchor  
   <sub>``insecure_data_transport\` · AM-06 for the consequence; the ena · An app that re-enables user-CA trust voluntarily reverses a platform hardening and makes interception possible…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-027`** `minSdkVersion < 24` — implicit user-CA trust on old devices (LEGACY)  
   <sub>``insecure_data_transport\` · AM-06 after a user-CA install · Apps installable on API ≤ 23 inherit the pre-NSC default that trusts both the system **and** the user store, w…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-028`** `<debug-overrides>` shipped **and** the app is debuggable  
   <sub>``insecure_data_transport\` · AM-06 plus anyone with adb/USB acc · A release APK containing debug overrides is normally inert and **informational only**. It becomes a shipped Mi…</sub>
- [ ] **`D14-029`** `overridePins="true"` outside `<debug-overrides>`, or a user anchor in `base-config`  
   <sub>``insecure_data_transport\` · AM-06 after a user-CA install (no  · `<certificates src="user" overridePins="true"/>` in `base-config` or a production `domain-config` means any us…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-030`** Custom trust anchor (`<certificates src="@raw/…"/>`) — and the Certificate Transparency it silently disables  
   <sub>``insecure_data_transport\` · AM-06 with a certificate from the  · A bundled CA in `res/raw` replaces (not augments) the anchors for its scope. Two consequences: the private CA'…</sub>
- [ ] **`D14-031`** Certificate Transparency turned off per domain (API 36 opt-in, API 37 default-on)  
   <sub>``insecure_data_transport\` · AM-06 holding a mis-issued certifi · A `domain-config` that sets `enabled="false"` for a sensitive domain is a deliberate removal of CT enforcement…</sub>

**🟩 Low ceiling**

- [ ] **`D14-032`** `<domainEncryption mode="disabled"/>` — opting out of Encrypted Client Hello  
   <sub>`no direct node; argue under `insecure_data_transport\` · AM-06 performing traffic analysis · An app that pre-emptively sets `mode="disabled"` on its API domain opts out of SNI encryption, leaving the des…</sub>
- [ ] **`D14-033`** Interception-detection (RASP) reading the wrong trust-store path on API 34+  
   <sub>``lack_of_binary_hardening\` · AM-12 own rooted device (**not an  · An app that detects MitM by enumerating `/system/etc/security/cacerts` is reading a path the runtime ignores o…</sub>

**⬜ Support ceiling**

- [ ] **`D14-034`** Pinning inventory, per host, per stack — the P5 item that steers everything else  
   <sub>``mobile_security_misconfiguration\` · AM-07 (tester convenience, not an  · Build a host-by-host table: pinned / unpinned / bypassed-with-which-hook, and the mechanism (NSC `<pin-set>`, …</sub>

**🟨 Medium ceiling**

- [ ] **`D14-035`** Expired `<pin-set expiration="…">` — pinning that silently stopped being enforced  
   <sub>``mobile_security_misconfiguration\` · AM-06 with a certificate from any  · Once past the `expiration` date Android **stops enforcing that pin set** and falls back to the configured trus…</sub>
- [ ] **`D14-036`** Pin scope error: first-party pinned, an SDK/analytics host unpinned and carrying identifiers  
   <sub>``insecure_data_transport\` · AM-06 · Pinning is almost always declared per-domain. Enumerate the hosts that are *not* in the pin set and read what …</sub>
- [ ] **`D14-037`** The pin set an SDK's own HTTP stack never consults  
   <sub>``insecure_data_transport\` · AM-06 · The app declares pins in the NSC or with `CertificatePinner`, but an SDK uses its own socket layer that consul…</sub>

**⬜ Support ceiling**

- [ ] **`D14-038`** The pinning-bypass ladder — technique, not a finding  
   <sub>``mobile_security_misconfiguration\` · AM-07/AM-12 (tester) · Work the ladder in order of effort, and **record which hook fired** — that names the pinning stack, which is t…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-039`** Pinned certificates in `assets/` disclose unadvertised internal hosts  
   <sub>`rated on the discovered host — up to `sensitive_data_exposure\` · AM-01 once the host is reachable · A bundled `.cer`/`.der`/`.pem`/`.crt` names the host it pins in its Subject and SANs. That host is real by con…</sub>

**🟧 High ceiling**

- [ ] **`D14-040`** mTLS: client-certificate handling, and the edge-terminated verdict header  
   <sub>``broken_authentication_and_session_management\` · AM-01 (the header spoof needs no n · Two halves. (a) Client-side: where does the client certificate and its passphrase live, and is it extractable?…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-041`** Insecure TLS versions explicitly enabled in code  
   <sub>``server_security_misconfiguration\` · AM-06 with a downgrade-capable pos · Apps re-enable old versions through `SSLContext.getInstance("TLSv1.1")`, `SSLSocket.setEnabledProtocols(...)`,…</sub>
- [ ] **`D14-042`** Negotiated TLS version and cipher observed in live traffic  
   <sub>``server_security_misconfiguration\` · AM-06 · Version negotiation is a client/server agreement — only a capture shows what is actually used. This item exist…</sub>
- [ ] **`D14-043`** A bundled TLS stack that the Android 15 protocol floor does not reach  
   <sub>``insecure_data_transport\` · AM-06 · An app that needs a legacy endpoint on a modern target must have installed a custom socket factory or bundled …</sub>

**🟩 Low ceiling**

- [ ] **`D14-044`** GMS Security Provider not updated, updated too late, or with the failure swallowed  
   <sub>`no dedicated node; often **Informational** under HackerOne rating (a defence-i` · AM-06 against a device with an unp · Three failure modes, and MASTG makes the ordering explicit — "Check that these calls occur before any network …</sub>

**🟧 High ceiling**

- [ ] **`D14-045`** Custom DNS resolution bypassing Private DNS, and behaviour under a hijacked name  
   <sub>``insecure_data_transport\` · AM-06 controlling DHCP/DNS on the  · Two things. (a) Does the app resolve through its own resolver, bypassing the user's Private DNS setting? (b) W…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-046`** Backend host derived from a mutable source  
   <sub>``broken_authentication_and_session_management\` · AM-09 / AM-06 when the source is n · Is the API base URL fixed at build time, or does it come from a remote config, a push payload, a deep link, a …</sub>
- [ ] **`D14-047`** Executable, module, bundle or security-relevant config fetched without an integrity check  
   <sub>``insecure_data_transport\` · AM-06 (MitM) or AM-09 (malicious C · Watch for `.so`, `.dex`, `.jar`, `.zip`, `.apk`, `.js`/Hermes bundle, `.wasm`, model files or a security-relev…</sub>

**🟧 High ceiling**

- [ ] **`D14-048`** `DownloadManager` used for security-relevant downloads  
   <sub>``insecure_data_transport\` · AM-03 (querying the downloads prov · Google's own guidance is to replace `DownloadManager` with Cronet + WorkManager, citing three patched Download…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-049`** React Native dev bundle server or inspector reachable in a release build  
   <sub>``server_side_injection\` · AM-06 (serves the bundle), AM-03/A · RN's dev support fetches the JS bundle over plain HTTP from a packager host and exposes inspector endpoints. I…</sub>
- [ ] **`D14-050`** DRM licence request carrying the app's bearer token to a server-chosen licence URI  
   <sub>``sensitive_data_exposure\` · AM-09 (playback API / manifest) or · `MediaItem.DrmConfiguration.Builder.setLicenseRequestHeaders()` attaches app headers — commonly `Authorization…</sub>

**🟧 High ceiling**

- [ ] **`D14-051`** Media manifest, segment or subtitle URL taken from an untrusted source  
   <sub>``insecure_data_transport\` · AM-02 (deep link, push payload, ch · If a deep link, push payload, chat message, scanned QR or WebView bridge can set the player's media URL, the m…</sub>

**🟨 Medium ceiling**

- [ ] **`D14-052`** Hostile captive portal: a 200 with portal HTML treated as data or as success  
   <sub>`rated on the consequence; `broken_authentication_and_session_management\` · AM-06 running the AP · Apps launched on a captive-portal network receive HTTP 200s with portal HTML for every request. Some parse it …</sub>

**🟧 High ceiling**

- [ ] **`D14-053`** Background network restrictions (Android 15) making a security check fail open  
   <sub>``broken_authentication_and_session_management\` · AM-11 / AM-05, exploiting a condit · On Android 15 a request started outside a valid process lifecycle fails. Check the error handling of any *secu…</sub>

**🟥 Critical ceiling**

- [ ] **`D14-054`** Shadow API: every endpoint you recovered from the APK is a version-diff candidate  
   <sub>``broken_authentication_and_session_management\` · AM-01 · A mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, …</sub>

**⬜ Support ceiling**

- [ ] **`D14-055`** The layer-ordering trap on a "no-auth" endpoint you found by interception  
   <sub>`n/a (kill gate for every auth-bypass claim that starts in this chapter)` · A `400 "field X is required"` from an unauthenticated request does **not** prove you passed auth. Many stacks …</sub>
- [ ] **`D14-056`** Discipline for network sweeps: body diffs, statistics, and counted loops  
   <sub>`n/a (governs D14-021, D14-040, D14-054 and every "bypass" claim in this chapte` · Four rules, each of which kills a category of false positive that this chapter's tooling produces in bulk.</sub>
- [ ] **`D14-057`** Evidence hygiene for a network finding  
   <sub>A transport finding lives or dies on one thing: proving the victim's device was **clean**. Build the evidence …</sub>
- [ ] **`D14-058`** Severity governance for this chapter  
   <sub>Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute the claim into each …</sub>

<details><summary>⚰️ D14 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app does not implement certificate pinning" | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` = **P5**. HackerOne Core Ineligible lists "Lack of SSL Pinning" under missing best practices; Xiaomi, Grab, Spotify, Starbucks and Snapchat exclude it by name. Shopify #55644 was rated **none, $0** | An interceptable secret **plus** a realistic AM-06 path — i.e. broken validation (D14-007/-009/-010), an expired pin set (D14-035), or an unpinned channel carrying identifiers (D14-036) |
| "I bypassed the app's pinning with objection/Frida" | `\|ssl_certificate_pinning\|defeatable` = **P5**. HackerOne Platform Standards: "If a report requires an attacker to disable Certificate Pinning in an application, then that is not a valid vulnerability" | Nothing about the bypass. Report what the decrypted traffic then reveals, filed under D15 with its own VRT |
| "Weak TLS ciphers / TLS 1.0 supported" | HackerOne Core Ineligible "SSL/TLS Configurations"; Grab, Reddit, Basecamp and HackenProof all exclude it without a PoC. `server_security_misconfiguration\|insecure_ssl\|*` children are P5 | A captured session actually negotiating the weak parameters **and** a demonstrated decryption or downgrade consequence |
| "Missing HSTS on the auth subdomain" | Exploitation needs an active MitM position you cannot demonstrate remotely; `server_security_misconfiguration\|lack_of_security_headers\|strict_transport_security` = P5 | A demonstrated downgrade of a real session on a network you controlled, with the token captured |
| "Missing CAA / DNSSEC / SPF-DKIM-DMARC" | P5 nodes, and reading `p=none` from `dig` is not a finding | A spoofed mail **delivered to the Inbox** of a real receiver you control, with headers — and even then it belongs to the email domain, not here |
| "`<debug-overrides>` present in the release APK" | The block is inert unless `android:debuggable="true"` — MobSF itself gates the finding on that flag | The store build is also debuggable (→ D14-028) |
| "The app trusts user CAs" on a `targetSdk < 24` build | That is the documented platform default for that target, not a deviation | `targetSdk ≥ 24` with an explicit `<certificates src="user"/>` (→ D14-026), or `overridePins="true"` (→ D14-029) |
| "Cleartext is permitted" on a `targetSdk < 28` build | Default-allow below 28; the attribute's presence proves nothing | Sensitive data observed on the wire (→ D14-018), or an explicit opt-in on a `targetSdk ≥ 28` build |
| "An analytics ping goes over HTTP" | Informational unless it carries something | The ping carries a session token, a stable user id, an advertising id tied to an account, or PII |
| "ARP poisoning lets me intercept the app" | True of every OS, needs same-L2 presence, defeated by Wi-Fi client isolation and MAC randomisation. Use the lab-gateway form purely as a capture mechanism | Nothing — it is not an Android finding. Report the app-side defect the capture revealed |
| "Play Integrity / SafetyNet can be bypassed with Frida" | Verdicts are checked server-side and cannot be forged by a local hook. If the gate is a server-verified attestation, stop and re-scope | The **server** accepting requests carrying no integrity verdict at all — a separate, server-side finding |
| "The interception-detection routine can be defeated" | `lack_of_binary_hardening\|runtime_instrumentation_based` = P5; AM-12 (own rooted device) is not an attacker | Only if a client SoW explicitly buys MAS-R resilience controls — then it is a contractual gap, not a vulnerability |
| "OkHttp version X has CVE-YYYY-NNNN" | `using_components_with_known_vulnerabilities\|outdated_software_version` = P5; a version string is not reachability | The vulnerable code path demonstrably reached — e.g. a manual `HostnameVerifier` call plus an accepted confusable-hostname certificate (→ D14-014) |
| "Traffic fails to intercept, therefore the app pins" | Uniform failure across unrelated hosts including CDNs is your trust store, not the app. On API 34+ the `/system/etc/security/cacerts` push succeeds and changes nothing | A `<pin-set>`/`CertificatePinner` call site **plus** `I/X509Util: … Pin verification failed` in logcat (→ D14-003) |
| "The app ignores the system proxy" | A testability observation, not a vulnerability | The proxy-bypassing client also skipping validation (→ D14-007), or a channel carrying secrets that no review ever covered (→ D14-004) |
| "`<domainEncryption>` is not enabled" | Below API 37 it is disabled by default; the hostname is visible on every other platform too | The hostname itself is the sensitive datum (health, dating, whistleblowing) **and** the app explicitly sets `mode="disabled"` |
| "OAuth `client_secret` is embedded in the APK" | Known and expected for a public client; on the corpus's never-submit list | **PKCE non-enforcement** at the token endpoint — that is the reportable inversion (→ D13) |

</details>


<details><summary>🔗 D14 cross-surface joins — park these, chase them in P7</summary>

- **NSC pin set × the `SSLSocket`/native channel (D14-010, D14-022, D19).** Nobody reviews the pin set
  and the socket inventory together. NSC pins and NSC cleartext rules cover framework traffic —
  `HttpsURLConnection`, OkHttp, WebView — and cover **neither** `SSLSocket` nor Dart's `HttpClient` nor
  Cronet's own stack. The join is: enumerate every TLS-bearing channel from the pcap, then check each one
  against the pin set and the trust code separately. A vendor's "our NSC is strict" answer closes exactly
  one of them.
- **Cleartext carve-out × OTA / dynamic code loading (D14-017 × D14-047 × D17).** The single domain the
  team allowed cleartext for "because it is just the CDN" is routinely the one serving the JS bundle, the
  feature-flag JSON, the downloadable module or the model file. Read the `<domain-config
  cleartextTrafficPermitted="true">` list against the list of hosts that serve loadable artefacts — the
  intersection is a P4 that argues to P1.
- **Pinned certificate in `assets/` × recon (D14-039 × D01).** The bundled `.cer` names a host by
  construction. Pull its Subject and SANs, feed them into a certificate-transparency search for
  siblings, then sweep the new host for unauthenticated routes. The APK is the only place that internal
  name is published.
- **DRM licence URI × session token (D14-050 × D13).** The media team owns `setLicenseUri`, the auth team
  owns the bearer token, and `setLicenseRequestHeaders` quietly joins them on an HTTP client outside the
  pin set. Nobody reviews the licence request as an auth surface.
- **Deep link × player source / base URL (D09 × D14-046 × D14-051).** The deep-link reviewer checks for
  intent redirection; the network reviewer checks TLS. Neither checks whether a link parameter can set
  the host the app then sends its `Authorization` header to. One `am start` answers it.
- **Debuggable flag × `<debug-overrides>` (D02/D26 × D14-028).** Each is graveyard alone — a debuggable
  release is a hardening finding, a stray debug-override block is inert — and together they are a
  shipped, no-root MitM backdoor plus JDWP into the app's UID.
- **Third-party SDK × the app's own pinning (D18 × D14-013).** One SDK calling
  `HttpsURLConnection.setDefaultHostnameVerifier` with a permissive implementation neuters the app's own
  pinned connections process-wide. The SDK reviewer looks at permissions and endpoints; the TLS reviewer
  looks at the app's own code; the process-global setter sits between them.
- **DNS control × an unpinned config host (D14-045 × D14-046 × D17).** DNS is reviewed as a privacy
  matter and pinning as a transport matter. Joined, a name the app resolves but does not pin, which
  serves config the app trusts, is a mass-redirection primitive that needs no TLS break at all.
- **Loopback listener × any installed app (D14-023 × D13 × AM-03).** The OAuth reviewer checks PKCE and
  `redirect_uri` registration; the IPC reviewer checks exported components. Neither checks
  `/proc/net/tcp` during the login flow — and Android does not isolate loopback between apps.
- **Decrypted mobile endpoint × the current web API (D14-054 × D15).** The pinning bypass is P5 and the
  endpoint list looks unremarkable — until you diff the mobile-era version against the web app's current
  one for auth strength, throttling, validation and field exposure. The weakened control is the finding;
  the version delta alone is informational.

</details>


---

## D15 Backend API, IDOR/BOLA, Mass Assignment & Business Logic

**Phase P6 · `M6` · 90 items** — 🟥 27 critical · 🟧 4 high · 🟨 1 medium · ⬜ 58 support  

📄 Full detail, with every command and proof: [`checklist/D15-backend-api-and-authz.md`](checklist/D15-backend-api-and-authz.md)

> **Crux question.** **For every object identifier and every security-relevant field the client is capable of sending, does the server re-derive the answer from its own state — or does it trust the identifier, the field, the version, the header or the client's arithmetic?**

Three independent sources in the corpus say the same thing without coordinating. Bugcrowd's own mobile
guidance: *"the network and server related vulnerabilities are where the higher impact vulnerabilities are
found."* The senior-researcher corpus: IDOR/BOLA through the mobile API is *"consistently the best-paying
app-layer class because impact is self-evident and server-side."* The MAS project concedes the same by
omission — it has no client-side test for any of it. On a platform grid like YesWeHack's Gojek Android scope
(Critical $3,500 / High $1,800 / Medium $600 / Low $50), a P5 mobile misconfiguration pays nothing and one
cross-account read pays the top band.


**⬜ Support ceiling**

- [ ] **`D15-001`** Harvest the complete Retrofit endpoint map from an R8-minified APK  
   <sub>`n/a (enabler; the authz flaw you then demonstrate is the finding)` · AM-12 harness → AM-05/AM-01 target · Recover every server route the app is capable of calling. R8/ProGuard renames classes and methods but **does n…</sub>
- [ ] **`D15-002`** Shortlist IDOR candidates by path-parameter shape, not by guesswork  
   <sub>`n/a (enabler)` · AM-05 · Of the recovered routes, isolate those whose path embeds a client-supplied object identifier. These are exactl…</sub>

**🟨 Medium ceiling**

- [ ] **`D15-003`** Recover hidden request parameters from Retrofit parameter annotations  
   <sub>``broken_access_control.privilege_escalation` (VARIES) when a recovered paramet` · AM-05 · Enumerate every field name the client is *capable* of sending. `@Query`, `@QueryMap`, `@Field`, `@FieldMap`, `…</sub>

**⬜ Support ceiling**

- [ ] **`D15-004`** Build the mass-assignment candidate list from the request-body model classes  
   <sub>`n/a (enabler; D15-065 carries the finding)` · AM-05 · Read the `*RequestBody`/`*Request`/DTO classes to learn exactly which fields the client is allowed to send, an…</sub>
- [ ] **`D15-005`** Read the OkHttp interceptor chain and reconstruct the auth envelope byte-for-byte  
   <sub>`n/a (enabler for every off-device replay)` · AM-12 harness · Determine exactly how the app authenticates every request, because you must reproduce it byte-for-byte when yo…</sub>
- [ ] **`D15-006`** Install a runtime OkHttp tap to capture flows the proxy never shows  
   <sub>`n/a (enabler)` · AM-12 harness · Capture full request/response pairs from inside the process. This is immune to pinning, to proxy-unaware clien…</sub>
- [ ] **`D15-007`** Extract the endpoint map from a cross-platform bundle when Retrofit finds nothing  
   <sub>`n/a (enabler)` · AM-12 harness · On cross-platform stacks zero Retrofit hits is *expected*, and the endpoint map lives in the bundle/snapshot. …</sub>
- [ ] **`D15-008`** Locate GraphQL operation documents and persisted-query hashes inside the APK  
   <sub>`n/a (enabler for D15-072 … D15-081)` · AM-05 · If the backend is GraphQL the client ships the operation documents (Apollo codegen) or only their SHA-256 hash…</sub>
- [ ] **`D15-009`** Recover gRPC service and method names, then drive them with grpcurl  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) f` · AM-01 / AM-05 · gRPC traffic is invisible to a naive HTTP proxy and is often the *entire* API for newer apps. Recover fully-qu…</sub>
- [ ] **`D15-010`** Decode and re-encode protobuf bodies without a `.proto`  
   <sub>`n/a (enabler — once you can edit protobuf, every item in this chapter applies ` · AM-12 harness · Protobuf is self-describing enough to decode blind: each field is `(field_number << 3) | wire_type` and the wi…</sub>
- [ ] **`D15-011`** Extract the full host inventory, including staging and QA hosts shipped in the release build  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4); ` · AM-01 · Find every host the client knows about, not just the one it uses. Staging backends are the classic API9 findin…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-012`** Diff the mobile route set against the web app's — the shadow-API bridge  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 / AM-05 · The single highest-value structural idea in a mobile engagement. Mobile clients get endpoints the web app does…</sub>

**⬜ Support ceiling**

- [ ] **`D15-013`** Walk the API-version ladder with the same token  
   <sub>``broken_access_control.idor.*` per the read/write fork; `broken_authentication` · AM-01 / AM-05 · Mobile backends accumulate versions because old installs must keep working, and the old version is the one wit…</sub>
- [ ] **`D15-014`** Downgrade the app-version headers to reach legacy backend routing  
   <sub>``broken_access_control.privilege_escalation` (VARIES) / `broken_access_control` · AM-01 / AM-05 · Gateways often route by `X-App-Version` or `User-Agent` to keep old installs working. Downgrading those header…</sub>
- [ ] **`D15-015`** Extract the companion-surface (Wear / Auto / TV / widget) endpoint set  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · Companion code paths frequently call *different* endpoints, or the same endpoints with a different client id o…</sub>
- [ ] **`D15-016`** Probe endpoints left live from a retired Instant App experience  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) b` · AM-01 · Instant apps could only use a restricted subset of APIs and permissions, so teams built *permission-light, fre…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-017`** Diff the consumer APK's routes against the vendor's driver / merchant / staff APK  
   <sub>``broken_access_control.privilege_escalation` (VARIES); `server_security_miscon` · AM-05 · Staff, driver, merchant and partner builds of the same backend expose `/admin/`, `/internal/`, `/ops/`, `/part…</sub>

**⬜ Support ceiling**

- [ ] **`D15-018`** Hunt the OpenAPI/Swagger spec, live and archived  
   <sub>``cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfa` · AM-01 · The spec discloses every endpoint, method, parameter name/type/format/max-length, model and validation rule — …</sub>

**🟥 Critical ceiling**

- [ ] **`D15-019`** Call the webhook, callback and server-to-server endpoints directly  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-01 · Payment callbacks, delivery-partner webhooks and internal reconciliation endpoints are frequently on the same …</sub>

**⬜ Support ceiling**

- [ ] **`D15-020`** Get the lab egress IP allow-listed, and record which controls were suppressed  
   <sub>AM-12 harness · WAF, bot defence, fraud engines and per-IP limits will throttle or ban the test accounts mid-sweep. Testers ro…</sub>
- [ ] **`D15-021`** The cross-boundary check: does a "device-bound" token still work from curl?  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-05 (and AM-03/AM-06 once combin · The single highest-value mobile auth check and it takes two minutes. Take the exact `Authorization` value the …</sub>
- [ ] **`D15-022`** Establish a control response before declaring any endpoint unauthenticated  
   <sub>`n/a (enabler)` · AM-01 · You cannot claim "this route has no auth" until you know what *correct* rejection looks like on this stack. A …</sub>

**🟥 Critical ceiling**

- [ ] **`D15-023`** Sweep every APK-derived route unauthenticated — and read the error taxonomy  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1); `br` · AM-01 · The APK's endpoint inventory is the API surface for free. Strip the `Authorization` header and replay each rou…</sub>

**⬜ Support ceiling**

- [ ] **`D15-024`** THE LAYER-ORDERING TRAP — a validation error does NOT prove you passed auth  
   <sub>AM-01 · The highest-confidence false positive in the entire auth-bypass class. Many stacks put a global input sanitise…</sub>
- [ ] **`D15-025`** Prove non-determinism before you diff anything  
   <sub>AM-12 harness · Before drawing any conclusion from a response difference, establish the endpoint's baseline variability. This …</sub>
- [ ] **`D15-026`** Establish the error oracle before any injection testing  
   <sub>AM-12 harness · Measure how the endpoint responds to a spectrum of *non-payload* inputs before sending a single injection payl…</sub>
- [ ] **`D15-027`** Recognise modern input-validation signatures and stop early  
   <sub>AM-12 harness · Framework-level typed validation closes whole injection classes before the value reaches storage. Recognising …</sub>
- [ ] **`D15-028`** Know which layer answered you  
   <sub>AM-12 harness · Four specific misreads that look like application behaviour: - **Zero-byte body + 4xx** (md5 `d41d8cd98f00b204…</sub>
- [ ] **`D15-029`** Marker discipline and the Body-Diff Rule  
   <sub>AM-05 · Two rules that together kill most false positives in this domain. **Marker discipline:** the second account mu…</sub>
- [ ] **`D15-030`** The Statistical-Sample Rule for timing and rate-limit claims  
   <sub>AM-12 harness · Single outliers are not signal; network jitter routinely produces 2× outliers. Minimum **n ≥ 10 interleaved tr…</sub>
- [ ] **`D15-031`** Server-Policy-vs-State: a policy that always denies is not an oracle  
   <sub>AM-12 harness · Establish whether the differentiator tracks *your input* or a *fixed deny-list*. The corpus's case: a `downloa…</sub>
- [ ] **`D15-032`** Shell-Loop Ban — count your results on every sweep  
   <sub>AM-12 harness · zsh array expansion fails **silently**. `for x in "${arr[@]}"` can produce zero iterations with no error when …</sub>
- [ ] **`D15-033`** Multi-Tool Reproduction Bar for every Critical/High claim  
   <sub>AM-12 harness · Before labelling anything Critical or High, reproduce it via **two independent tools with different HTTP stack…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-034`** Two-account BOLA sweep across every path-parameter endpoint (read direction)  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · For each route from `idor_candidates.txt`, replay account **A**'s authenticated request with account **B**'s o…</sub>
- [ ] **`D15-035`** Test the write direction separately — the P3→P1 fork  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · Read and write are different VRT nodes spanning three priority levels. Record precisely whether you can **view…</sub>

**🟧 High ceiling**

- [ ] **`D15-036`** HTTP method swap and `X-HTTP-Method-Override`  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-05 · Routers dispatch to different handlers per method, and not all handlers receive the auth middleware. GET may b…</sub>

**⬜ Support ceiling**

- [ ] **`D15-037`** Systematic authorisation sweep with Autorize, then verify every row by hand  
   <sub>`per the underlying endpoint` · AM-05 / AM-01 · Rather than testing endpoints one at a time, replay *every* observed request under a lower-privileged and an u…</sub>
- [ ] **`D15-038`** Single-account check: object-id predictability  
   <sub>`the VRT distinguishes **Iterable** (P1/P2/P3) from **GUID** (P4) object identi` · AM-05 · You do not need a second account to establish enumerability, and enumerability is what converts a single-recor…</sub>
- [ ] **`D15-039`** Decode the UUID version nibble, then find the in-app leak that defeats AC:H  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_guid` (**P4**) f` · AM-05 · "UUID" is not synonymous with "random". UUIDv1 encodes a 100 ns-resolution timestamp in the first 60 bits plus…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-040`** 401/403 bypass with client-trusted authorisation headers and path-shape tricks  
   <sub>``broken_authentication_and_session_management.authentication_bypass`` · AM-01 · Some gateways authorise on a header the client can set, or on a normalised path that differs from the one the …</sub>

**🟧 High ceiling**

- [ ] **`D15-041`** Array-wrap and parameter pollution against an equality ownership check  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · When the check is `if record.user_id == current_user.id`, supplying both ids can pass the check on the first v…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-042`** Smuggle a hidden ownership field into the JSON body  
   <sub>``broken_access_control.privilege_escalation` (VARIES); `broken_access_control.` · AM-05 · The endpoint infers ownership from the session and omits an id field in normal requests. Adding one explicitly…</sub>
- [ ] **`D15-043`** Tenant-id swap in the URL path  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · The tenant derives from the URL, not the session. The app checks that you are *authenticated* but not that you…</sub>
- [ ] **`D15-044`** Search, filter and sort parameters as an authorisation bypass  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · Filtering is often applied *after* an unscoped query, or the filter field itself is attacker-controlled — lett…</sub>
- [ ] **`D15-045`** Bulk and sync endpoints: the mobile-specific mass-extraction surface  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · Offline-capable apps expose "give me everything changed since T" endpoints. They are designed to return a lot,…</sub>

**⬜ Support ceiling**

- [ ] **`D15-046`** Single-account check: excessive data exposure in responses  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · Compare what the API returns against what the app renders. Mobile clients over-fetch because the server serial…</sub>
- [ ] **`D15-047`** Filename-IDOR and pre-signed media URLs  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-01 (pre-signed URLs usually nee · Mobile apps fetch images and documents through pre-signed URLs or `/files/{id}` routes. Test four things separ…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-048`** "Download my data" / GDPR export: IDOR on the job id and on the artefact  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 / AM-01 · Data-export is a low-traffic feature that hands out a single archive containing *everything*. Test the job id …</sub>

**⬜ Support ceiling**

- [ ] **`D15-049`** Support-ticket, message and attachment IDOR — three ids, tested separately  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · Support tickets carry the highest-sensitivity free text in the product. Test the **ticket id**, the **message …</sub>

**🟥 Critical ceiling**

- [ ] **`D15-050`** KYC document retrieval IDOR and re-upload overwrite  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · Identity verification is absent from most checklists as a *component*. Three separate questions: can you fetch…</sub>
- [ ] **`D15-051`** Bulk-action authorisation gap  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-05 · "Bulk delete / archive / export" accepts a list of object ids and checks ownership on none of them, or only on…</sub>
- [ ] **`D15-052`** Soft-delete and revoked access that the auth cache still honours  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-05 (a former member of the tena · The "remove member" endpoint flips `active=false` but does not invalidate the session or the personal access t…</sub>

**🟧 High ceiling**

- [ ] **`D15-053`** Share and invite token reuse, non-expiry and cross-resource scope  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_guid` (P4) basel` · AM-01 / AM-05 · Tokens that look random but are guessable, sequential, or never burn. Also: a token granting collaboration on …</sub>

**⬜ Support ceiling**

- [ ] **`D15-054`** IDOR through the caching layer, and web cache deception on authenticated paths  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-01 / AM-02 · Two related defects. **Cross-user caching:** a response cached at a layer whose cache key omits the user dimen…</sub>

**🟧 High ceiling**

- [ ] **`D15-055`** Push-token and device registration accepting another user's identifier  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · The `/devices` or `/push/register` endpoint takes an FCM token and a device id. If it does not bind them to th…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-056`** FCM topic namespace derived from a guessable identifier  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 (any user of the app) · `subscribeToTopic()` is a **client-side** call with no server authorisation. If the app subscribes to `user_<i…</sub>

**⬜ Support ceiling**

- [ ] **`D15-057`** Notification-preference and unsubscribe endpoints keyed on a guessable identifier  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-01 / AM-05 · Notification settings and email/SMS unsubscribe links are usually the least-protected endpoint in the product …</sub>

**🟥 Critical ceiling**

- [ ] **`D15-058`** Feed locally-harvested identifiers into the IDOR sweep  
   <sub>`per the object; the identifiers themselves are Support` · AM-03 (a zero-permission local app · Close the loop between the client-side domains and this one: identifiers harvested locally — exported ContentP…</sub>
- [ ] **`D15-059`** Test the destructive verbs deliberately  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-05 · DELETE, unlink, revoke, transfer, cancel and "remove member" IDORs are under-tested and pay the most, because …</sub>

**⬜ Support ceiling**

- [ ] **`D15-060`** The operator-level composition question — read-IDOR into the three terminal chains  
   <sub>`composed: `broken_authentication_and_session_management.authentication_bypass`` · AM-05 · When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same id, and might also be …</sub>

**🟥 Critical ceiling**

- [ ] **`D15-061`** Broken function-level authorisation: role-crossing endpoints shipped in one binary  
   <sub>``broken_access_control.privilege_escalation` (VARIES, CWE-269); `server_securi` · AM-05 · Mobile apps for two-sided marketplaces (buyer/seller, rider/driver, patient/clinician) ship **one** binary con…</sub>
- [ ] **`D15-062`** Hidden functionality gated only by the client not rendering a button  
   <sub>``broken_access_control.privilege_escalation` (VARIES); `cloud_security.misconf` · AM-05 · Feature flags, remote config and `isPremium`/`isAdmin` booleans decide what the UI draws. They do not decide w…</sub>

**⬜ Support ceiling**

- [ ] **`D15-063`** Client-side authorisation the architecture cannot enforce — response-field tampering  
   <sub>``broken_access_control.privilege_escalation` (VARIES)` · AM-05 · Anything the app decides in-process — role, entitlement, price, limit, KYC state — is advisory. Enumerate ever…</sub>
- [ ] **`D15-064`** Mass assignment on the profile/settings endpoint, with field names from three sources  
   <sub>``broken_access_control.privilege_escalation` (VARIES, CWE-269); escalates to `` · AM-05 · A profile/settings/account endpoint merges the JSON body into the user object. Expected fields `name`, `email`…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-065`** Mass assignment at registration, including the nested-object form  
   <sub>``broken_access_control.privilege_escalation` (VARIES); `broken_authentication_` · AM-01 (registration is usually una · Account creation is the highest-value mass-assignment target, because a single extra field can grant a role or…</sub>
- [ ] **`D15-066`** Mass assignment plus IDOR on team membership = cross-tenant privilege escalation  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · The most efficient takeover chain on team-management APIs: the IDOR gets you into the victim team, the mass as…</sub>

**⬜ Support ceiling**

- [ ] **`D15-067`** Sync conflict resolution driven by a client-supplied timestamp or version  
   <sub>``broken_access_control.idor.modify_sensitive_information_iterable_object_ident` · AM-05 · Offline-capable apps resolve conflicts with last-write-wins on a timestamp the *client* sends, or with a clien…</sub>
- [ ] **`D15-068`** Server-side prototype pollution — pollute, then prove the sink  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) at the RCE end; `broken` · AM-05 · Do not stop at a 200 on `__proto__`. Prove that polluted prototype state reaches a **later** operation, on a d…</sub>
- [ ] **`D15-069`** Server-side parameter pollution in backend URL construction  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · The server interpolates your input into a *backend* URL path or query (`/api/internal/users/<username>/field/e…</sub>
- [ ] **`D15-070`** GraphQL schema recovery: introspection, its bypasses, and suggestion mining  
   <sub>``sensitive_data_exposure.graphql_introspection_enabled` (**P5**) for the expos` · AM-01 · Confirm the endpoint is GraphQL, then recover the schema — by introspection if it is enabled, by a naive-block…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-071`** Relay `node(id:)` global-object-handle IDOR, including cross-type confusion  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-05 · The most-paid GraphQL bug class. Relay APIs expose `node(id: ID!)` returning any object by global id. Type-spe…</sub>

**⬜ Support ceiling**

- [ ] **`D15-072`** GraphQL field-level and nested-path authorisation  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 · GraphQL resolvers authorise per *field*, and teams routinely protect the top-level query while leaving a neste…</sub>
- [ ] **`D15-073`** GraphQL aliasing and batching to defeat per-request rate limits  
   <sub>``server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) as the ` · AM-01 / AM-05 · The rate limiter counts HTTP requests, not resolver invocations. Two independent multipliers: **aliases** (man…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-074`** Persisted-query (APQ) allow-list fallback bypass  
   <sub>``broken_access_control.privilege_escalation` (VARIES) — the impact is **mutati` · AM-01 / AM-05 · An endpoint that claims "persisted queries only" and rejects ad-hoc queries may silently fall back to executin…</sub>
- [ ] **`D15-075`** Operation-shape confusion: side-effecting resolvers under `Query`, and mutations over GET  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-01 (Query confusion) / AM-02 (m · Two shapes of the same mistake. (a) Auth middleware guards mutations strictly and treats `query` as anonymous-…</sub>

**⬜ Support ceiling**

- [ ] **`D15-076`** Price, amount, total and quantity tampering at checkout  
   <sub>``decentralized_application_misconfiguration.marketplace_security.price_or_fee_` · AM-05 · Whether the server recomputes the payable amount from server-side state (cart id, catalogue price) or trusts a…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-077`** Currency confusion and minor-unit mismatch  
   <sub>``decentralized_application_misconfiguration.marketplace_security.price_or_fee_` · AM-05 · The server stores price in one currency but accepts a client-supplied `currency`, or assumes a minor-unit scal…</sub>

**⬜ Support ceiling**

- [ ] **`D15-078`** Coupon and discount abuse: reuse, stacking, scope and late application  
   <sub>`no dedicated VRT leaf — file under business logic and quantify the loss` · AM-05 · Four distinct behaviours, tested separately: reuse of a single-use code; stacking multiple supposedly-exclusiv…</sub>
- [ ] **`D15-079`** Referral, invite and signup-bonus fraud  
   <sub>`no dedicated VRT leaf — business logic, quantified` · AM-05 · Whether the referral flow can be self-referred, automated or replayed — with tester-owned accounts only. The m…</sub>

**🟥 Critical ceiling**

- [ ] **`D15-080`** State-machine abuse: skip a step, reorder it, reverse it, or change the cart after pricing  
   <sub>`no dedicated VRT leaf; `broken_access_control.privilege_escalation` (VARIES) w` · AM-05 · Multi-step flows — `cart → payment → fulfilment`, `KYC → limit raise`, `address verify → delivery`, `submit → …</sub>

**⬜ Support ceiling**

- [ ] **`D15-081`** Replay of state transitions: idempotency keys, duplicate submission and signed webhooks  
   <sub>`no dedicated VRT leaf; rate with CVSS and the ledger delta` · AM-05 (client replay); AM-01 (webh · The non-concurrent cousin of the race tests, and it often succeeds where the race does not: can a state-changi…</sub>
- [ ] **`D15-082`** KYC / verification status and OCR fields asserted by the client  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) as t` · AM-05 · Vendor SDKs return a completion callback to the app; weak integrations then tell the *backend* "KYC complete" …</sub>
- [ ] **`D15-083`** Enforced-update bypass (client-side version gating)  
   <sub>``broken_access_control.privilege_escalation` (VARIES) as the nearest node` · AM-05 / AM-12 · An app that gates access on a minimum version is enforcing a business-logic control in the client. MASTG gives…</sub>
- [ ] **`D15-084`** Client-computed integrity claims the server does not verify  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-05 / AM-12 · Four claims the client makes and the server usually fails to verify, tested as one battery. (a) **A request si…</sub>
- [ ] **`D15-085`** Race conditions: limit overrun, multi-endpoint collision, and the sequential baseline that must precede both  
   <sub>``server_security_misconfiguration.race_condition` (VARIES)` · AM-05 · Check-then-act flows read state, validate, then mutate, with a window between read and write. Three shapes: **…</sub>
- [ ] **`D15-086`** Measure the rate limit on every mobile-only endpoint, then work out what it keys on  
   <sub>``server_security_misconfiguration.no_rate_limiting_on_form.login` / `.registra` · AM-01 · The web login has CAPTCHA, device fingerprinting and WAF rules. The mobile token endpoint often has none, beca…</sub>
- [ ] **`D15-087`** Account and data enumeration through response differentials, including the search oracle  
   <sub>``broken_access_control.username_enumeration.non_brute_force` (P4); `server_sec` · AM-01 · Four dimensions on login, registration, password-reset and "check availability": status code, body, field set,…</sub>
- [ ] **`D15-088`** CORS policy on the mobile API host  
   <sub>``server_security_misconfiguration.unsafe_cross_origin_resource_sharing` (paren` · AM-02 · `Access-Control-Allow-Origin` reflecting the request origin (or `null`) together with `Access-Control-Allow-Cr…</sub>
- [ ] **`D15-089`** Content-type manipulation against the mobile API  
   <sub>``broken_access_control.privilege_escalation` (VARIES) when it bypasses a contr` · AM-02 / AM-05 · The same handler often behaves differently when the body is form-encoded rather than JSON — bypassing validati…</sub>
- [ ] **`D15-090`** Hand the client-only parameter set to the injection and SSRF batteries  
   <sub>``server_side_injection.sql_injection` (P1), `server_side_injection.remote_code` · AM-05 · This chapter's job is not to re-run a web injection catalogue; it is to hand the injection and SSRF work the p…</sub>

<details><summary>⚰️ D15 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| GraphQL introspection enabled | `sensitive_data_exposure.graphql_introspection_enabled` is **P5**, and "introspection alone" is on the never-submit list | A specific undocumented mutation reached from a low-privilege session, or a field-level authz failure found via the schema (D15-072) |
| `{"data":{"__schema":null}}` reported as "introspection enabled" | `null` means **disabled** — not "worked but empty" | Nothing; re-test with suggestions and the APK operation documents instead |
| A 200 OK returned for another user's id | "200 OK without actually leaked data" is the single biggest N/A driver on H1/Bugcrowd; the body may be empty, may be your own session-scoped data, may be a cached impersonation response, or may be fields already public on the profile page | The second account's 8+ char marker present in the response and absent from the baseline (D15-029) |
| A 403→200 flip whose body is byte-identical | The edge normalised your input; the Body-Diff Rule says a byte-identical 200 is not a bypass | A body differential, with the changed bytes identified |
| `400 "field X is required"` from an unauthenticated request | A body parser or sanitiser may sit in front of the auth middleware — the layer-ordering trap | The same route still returning the field error for a minimal well-formed `{}` body (D15-024) |
| "The API version v1 still exists" | A version difference alone is **Informational** | A demonstrated regression on the old path: weaker auth, missing 429, weaker validation, or extra fields (D15-013) |
| A negative price accepted in the cart | Many cart APIs accept arbitrary client state while payment capture rejects it — the cart display is fiction | The credit settling as wallet balance, store credit or a refund to your payment instrument (D15-076) |
| A discount shown as `-$50.00` in the cart | Systems commonly cap the applied discount at 100%: captured payment `$0.00`, no refund issued | The captured payment or the issued refund reflecting the stacked discount (D15-078) |
| 100 aliased mutations all returning `success:true` | Apollo/GraphQL-Ruby/Graphene resolve aliases **sequentially**; this is quota enforcement, not a race | Server state showing N applied benefits, or a true parallel single-packet race (D15-085) |
| A single slow response for a valid username | Network jitter routinely produces 2× outliers | n ≥ 10 interleaved trials with the suspect mean ≥ 2σ above control (D15-030) |
| An md5 differential across identical requests | Unordered collections serialise differently: same set, same length, different hash | The differential surviving normalisation (sorted arrays, volatile keys stripped) (D15-025) |
| A uniform 401 on every endpoint from curl | Usually a stale `__cf_bm`-class bot cookie or a duplicated cookie row, not a revoked session | The same request failing when issued by the app itself (D15-028) |
| A zero-byte 4xx body (md5 `d41d8cd9…`) | Edge/protocol rejection — HTTP header values are ISO-8859-1, so unicode payloads die at the proxy | An origin response with a body |
| A "file existence oracle" on a blocked extension | A fixed deny-list is a server policy, not a state oracle | The differentiator tracking a value that cannot exist in the dataset (D15-031) |
| Client-sent `finalCustomerAmount` / `senderId` in the request body | A client-sent security value is an **enabling condition**; the server may recompute from the cart session | The server honouring the tampered value in the persisted object, read back with a separate GET (D15-004, D15-076) |
| OAuth `client_secret` found in the APK | Known and expected for a public client — on the never-submit list | PKCE non-enforcement at the token endpoint, which is the reportable finding (→ D13) |
| SSRF confirmed by a DNS callback only | "SSRF DNS callback only" is on the never-submit list | Cloud metadata or an internal admin API reached, with content returned or exfiltrated OOB (D15-081) |
| No certificate pinning on the API host | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` is **P5**; once you decrypt, pinning is irrelevant to severity | Nothing on its own — it is the harness, not the finding (→ D14) |
| "No application-layer payload encryption" | A MAS-R resilience control (MASWE-0062); Informational on most programs | Whatever you achieve once inside it — a tampered amount or object id accepted (D15-084) |
| A mobile-only endpoint that exists | Enumeration is Support, not a finding | The missing authorisation, missing throttle or extra fields demonstrated on it (D15-012) |
| A UUID-keyed IDOR with no leak path | Defaults to P4 and `AC:H`; some programs exclude UUID-dependent access control outright | An in-app, repeatable method to obtain the specific ids — another API response, a share link, a push payload, a provider row (D15-039) |
| Admin-only data returned to every client but hidden in the UI | Rated as privilege escalation, and often only Medium | Showing the value is used as a credential, or that it unlocks an action the role cannot perform (D15-046) |

</details>


<details><summary>🔗 D15 cross-surface joins — park these, chase them in P7</summary>

- **D10/D11/D07/D20 (any token-leak primitive) × D15-021 — the cross-boundary join.** A bridge that returns
  the session header, a world-readable `shared_prefs` blob, a provider row or a logcat line is **Informational
  until you replay it**. The join nobody runs is the two-minute curl check: move the token to a host that never
  ran the app and strip the device header. A leaked token that works from anywhere is
  `broken_authentication_and_session_management.authentication_bypass` (P1); the same leak with a genuinely
  sender-constrained token is a P5 storage note. File the storage primitive first, then the server-side
  consumer, then link them.
- **D07 provider rows / D09 deep-link parameters / D24 push payloads × D15-039 — the AC:H join.** The
  HackerOne standard sets `AC:H` on a UUID-keyed IDOR by default and drops it to `AC:L` when you demonstrate a
  reliable way to obtain the ids. Nobody reviews the exported-provider table and the API's object-id space
  together — but an exported provider that hands out server object ids is exactly that demonstration, and it
  moves the same bug two VRT bands.
- **D01 binary inventory × the live web API — the shadow-API join.** The app's hardcoded endpoints are
  frequently an older API version than the web app uses. Diff the *behaviour* (auth strength, 429, validation,
  field exposure) rather than the response shape, for the same operation. The version difference is
  Informational; the weakened control is the finding, and it is the single highest-value structural move
  available on a mobile engagement.
- **D21 attestation × every "requires a modified client" caveat.** Vendors downgrade findings by asserting that
  root detection or Play Integrity prevents exploitation. D15-084 answers that in one request: if the server
  accepts the call with the verdict stripped or replayed, every such caveat evaporates and each affected
  finding must be re-rated upward. Test the attestation *before* you accept a downgrade, not after.
- **D12 hardcoded keys × D15-076/D15-081 — the signed-request join.** An HMAC key recovered from the binary
  turns "the request is signed, so it cannot be tampered" into a price-tampering and webhook-forgery primitive.
  The crypto team reviews the key; the API team reviews the endpoint; nobody joins them.
- **D18 storage buckets / CDN × D15-047 and D15-088.** A pre-signed media URL, a subdomain takeover on an
  allow-listed CORS origin, and an unauthenticated CDN path for private documents are three surfaces owned by
  three different teams. Together they are unauthenticated bulk retrieval of KYC documents from a page the
  attacker controls.
- **D11 offline queue × D15-080.** Offline-first apps persist pending mutations locally and replay them on
  reconnect. Editing the queued transition on disk delivers an out-of-order or forged state change through a
  path the UI never shows and the server treats as first-party — the state-machine bug with a local delivery
  vehicle.
- **D10 WebView × D15-046/D15-064 — the stored-payload join.** A profile field the API lets you write
  (sometimes keyed only on a non-secret identifier) rendered by a first-party WebView that carries a bridge is
  the cleanest full chain in mobile: weak API authorisation → stored XSS on a trusted origin → bridge → token →
  ATO. Test every free-text field the API accepts against every screen that renders server-supplied HTML.
- **D13 OTP/session × D15-086/D15-087 — the chain that must be filed as one.** Enumeration gives the target
  list, the missing mobile-side rate limit gives the attempts, and a 4–6 digit OTP gives the takeover. Filed
  separately they are P4, P4 and "expected"; filed as one chain with the arithmetic, it is an authentication
  bypass.
- **D23 payments × D15-085.** The payments team tests the happy path and the fraud engine; nobody fires 30
  single-packet requests at the top-up, referral-credit or scratch-card endpoints that exist only in the mobile
  client. Those are the "you may do this once" controls with no lock.

</details>


---

## D16 Native Code, JNI & Memory Safety

**Phase P4 · `M4` · 60 items** — 🟥 15 critical · 🟧 1 high · 🟨 3 medium · 🟩 4 low · ⬜ 37 support  

📄 Full detail, with every command and proof: [`checklist/D16-native-code-and-memory.md`](checklist/D16-native-code-and-memory.md)

> **Crux question.** **Which bytes that an attacker fully controls reach C/C++ inside this app's process, by what path they get there, and does the code that consumes them compute a size, an index or a lifetime from those same bytes without checking it?**

The base rate is real and it is published. AOSP's own security-model analysis puts **about 85% of Android
security vulnerabilities in unsafe memory access**, and the platform has spent a decade adding mitigations
(ASLR, CFI from 9.0, ShadowCallStack from 10, BoundSan/IntSan from 10, Scudo from 10, MTE software support
from 12, BTI and PAC-RET from 14, Rust from 12) precisely because the class does not go away. None of that
hardening applies automatically to the `.so` files the *app vendor* compiled and shipped. The academic
measurement is the number to quote to a client: LibRARIAN's study of the top 200 Google Play apps found
**53 of 200 (26.5%) carrying a known-vulnerable bundled native library**, those libraries averaged
**859.17 ± 137.55 days out of date**, and app developers took **528.71 ± 40.20 days** to adopt a patch that
the library maintainers had shipped in **54.59 ± 8.12 days**. That ten-to-one patch lag is the single
strongest argument you have for why a native-library finding is not theatre.


**⬜ Support ceiling**

- [ ] **`D16-001`** Pull every ABI split before concluding the app has no native code  
   <sub>`n/a (enabler; a missed split is a false negative across the whole chapter)` · n/a (acquisition) · Confirm you hold `base.apk` **and every** `split_config.*`. Native libraries are packaged into the ABI split, …</sub>

**🟨 Medium ceiling**

- [ ] **`D16-002`** Diff the runtime module list against the APK — find the `.so` that is never on disk  
   <sub>`n/a standalone; the hidden code's behaviour decides the path (→ D17)` · AM-12 for the dump itself (evidenc · Packers and some SDKs decrypt a `.so` at runtime and map it from memory or a `memfd`, so it never appears in t…</sub>

**⬜ Support ceiling**

- [ ] **`D16-003`** Enumerate every `Java_*` export and bind each one to its Java declaration  
   <sub>`n/a (enabler; the reachable entry point is the finding)` · n/a (mapping) · `Java_<pkg>_<Class>_<method>` exports are the exact set of native functions the managed layer can call by stat…</sub>
- [ ] **`D16-004`** Catch the `RegisterNatives` methods that have no `Java_*` export  
   <sub>`n/a (enabler; this is the single largest false-negative source in native enume` · n/a (mapping) · A library that calls `RegisterNatives()` inside `JNI_OnLoad` binds native methods at runtime. Those methods ha…</sub>
- [ ] **`D16-005`** Build the reachability table: `.so` → JNI entry → data source → attacker model  
   <sub>`n/a (enabler; this table is what scopes every other item in the chapter)` · n/a (it assigns the attacker model · For every native entry point, answer one question: **what attacker-controlled data reaches it, and through whi…</sub>
- [ ] **`D16-006`** Version-fingerprint every bundled third-party library from `.rodata`  
   <sub>``using_components_with_known_vulnerabilities.outdated_software_version` (**P5*` · AM-02 / AM-09 for the decoder clas · Native libraries are the least-patched part of an Android app and are invisible to dependency scanners. Recove…</sub>
- [ ] **`D16-007`** `JNI_OnLoad` and `.init_array` constructors: code that runs before any Java  
   <sub>``lack_of_binary_hardening.runtime_instrumentation_based` (**P5**) if you file ` · AM-12 (your own instrumentation is · ELF constructors in `.init_array` run at `dlopen` time — **before `JNI_OnLoad`** and long before any Java code…</sub>
- [ ] **`D16-008`** Per-`.so` mitigation sweep — run it on THIS binary, and count your results  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) standalone` · n/a (rating input) · The mitigation timeline is per-release **and** per-NDK. An app's own `.so` built with an old NDK can lack PIE,…</sub>
- [ ] **`D16-009`** Partial RELRO — the writable GOT is the one mitigation gap that is a primitive  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) alone; cite it` · AM-03 / AM-02, whichever reaches t · `GNU_RELRO` alone marks only the non-PLT relocations read-only. Without `BIND_NOW` the GOT stays writable for …</sub>

**🟩 Low ceiling**

- [ ] **`D16-010`** Non-PIE library (`Type: EXEC`) — LEGACY, and what it actually tells you in 2026  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**)` · n/a (rating input) · Check the ELF type on every shipped library. On a modern build a non-PIE result is almost never an exploitabil…</sub>
- [ ] **`D16-011`** Stack canaries absent — and the four documented false positives you must exclude first  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**)` · n/a (rating input) · Count references to `__stack_chk_fail` in each library. Then throw out the four documented false positives bef…</sub>
- [ ] **`D16-012`** FORTIFY verification — check for `_chk` symbols, not for a compiler flag  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**)` · n/a (rating input) · `_FORTIFY_SOURCE` replaces `memcpy`/`strcpy`/`sprintf` with `__memcpy_chk`-style variants that carry a compile…</sub>

**⬜ Support ceiling**

- [ ] **`D16-013`** Executable stack, executable heap and RWX mappings at runtime  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**)` · n/a (rating input) · Two separate questions. Statically: is `GNU_STACK` marked `RWE` (or absent)? Dynamically: does the running pro…</sub>
- [ ] **`D16-014`** Establish which platform mitigations are actually live on the test build  
   <sub>`n/a (this is the evidence for the D16-053 layer list)` · Before rating anything, record which platform-side mitigations the *device under test* enforces. AOSP's list, …</sub>

**🟩 Low ceiling**

- [ ] **`D16-015`** Debugging symbols, source paths and build machine paths left in the shipped binary  
   <sub>``lack_of_binary_hardening.lack_of_obfuscation` (**P5**) standalone` · n/a (reconnaissance) · Unstripped `.so` files expose function names, variable names and source-file references, which hands the rever…</sub>

**⬜ Support ceiling**

- [ ] **`D16-016`** 16 KB page alignment and the toolchain-identity diff across libraries  
   <sub>`n/a standalone; `using_components_with_known_vulnerabilities.outdated_software` · n/a (recon); AM-09 if the compat r · A 16 KB-aligned library shows `0x4000` alignment on its LOAD segments; 4 KB shows `0x1000`. Mixed alignment ac…</sub>
- [ ] **`D16-017`** Trace the JNI boundary with jnitrace before disassembling anything  
   <sub>`n/a as a technique; `sensitive_data_exposure.disclosure_of_secrets.for_publicl` · AM-12 for the trace (evidence tool · Every JNI function receives the `JNIEnv*` interface pointer. Tracing calls through it reveals the strings nati…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-018`** Length, offset and size values crossing JNI that native code trusts  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with demonstrated e` · AM-03 / AM-02 / AM-01 per the D16- · Java bounds-checks arrays; C does not. The classic defect is a JNI method that receives a buffer plus an offse…</sub>

**⬜ Support ceiling**

- [ ] **`D16-019`** The layer-ordering trap at the JNI boundary — a Java-side rejection does not prove the native parser is safe  
   <sub>n/a (methodology) · Two symmetrical mistakes live here. (1) **False negative:** you send an oversized length, the *Java* wrapper t…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-020`** Unsafe C string and memory sinks reachable from a JNI entry point  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P` · AM-03 / AM-02 per the D16-005 row · Enumerate the classic overflow-prone imports, then — and only then — determine whether any of them sits on a p…</sub>
- [ ] **`D16-021`** Native `system()` / `popen()` / `Runtime.exec` with concatenated attacker input  
   <sub>``insecure_os_firmware.command_injection` (**P1**, CWE-77) or `server_side_inje` · AM-03 / AM-02 · Does the app shell out at all — from Java or from native — and does any attacker-influenced string reach the c…</sub>
- [ ] **`D16-022`** Secrets and request-signing keys recovered at the JNI boundary  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-12 recovers it; the **impact**  · "Native = protected" is false. A key in `libnative.so` is no harder to recover than one in `strings.xml` — it …</sub>

**⬜ Support ceiling**

- [ ] **`D16-023`** Native anti-fraud, root-detection and pinning libraries: do they gate anything?  
   <sub>``lack_of_binary_hardening.lack_of_jailbreak_detection` (**P5**) / `.runtime_in` · AM-12 (the bypass is on your own d · Do not report "root detection can be bypassed" — that is P5 by definition. The only question worth answering i…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-024`** `int * int` size arithmetic — the highest-yield memory-safety grep in this chapter  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P` · AM-01 / AM-02 for a decoder fed by · Any allocation size or loop bound computed as `a * b` where both values come from attacker data. The giveaway …</sub>
- [ ] **`D16-025`** Signed/unsigned truncation on a file-controlled count  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P` · AM-01 (0-click font/image/document · The rule, verbatim from the research that found it: *"Any time you see `(short)` or `(int16_t)` on a value rea…</sub>
- [ ] **`D16-026`** Additive wrap that defeats a bound check (`x + n <= size`)  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**); **P3** crash-only` · AM-01 / AM-02 · The bound check itself is the bug. When `value` is attacker-supplied and near the type maximum, `value + const…</sub>
- [ ] **`D16-027`** Two-source dimension mismatch: the allocator reads one header, the writer reads another  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · AM-01 (a file delivered by MMS/RCS · When a format declares the same quantity twice, check whether the code that **allocates** and the code that **…</sub>
- [ ] **`D16-028`** Treat an out-of-bounds read as a latent out-of-bounds write  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) when the write is d` · AM-01 / AM-02 · If the same code reads a length from the input and writes that many bytes to an output buffer, the read primit…</sub>

**⬜ Support ceiling**

- [ ] **`D16-029`** Uninitialised and adjacent heap disclosure — prove the bytes cross the trust boundary  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 / AM-02 / AM-09 · An out-of-bounds read is a Medium. An out-of-bounds read whose bytes reach the attacker is a heap memory discl…</sub>
- [ ] **`D16-030`** Use-after-free, double free, and the controllability question you must answer explicitly  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with control; **P3*` · AM-02 / AM-03 · A use-after-free giving `pc = 0` may be completely unexploitable if you cannot reallocate the freed chunk with…</sub>
- [ ] **`D16-031`** Attacker-controlled native pointer smuggled through IPC deserialisation  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with control; **P3*` · **AM-03** — a zero-permission inst · A Java class that stores a native heap pointer in a **non-transient** `long` field, and passes it to a JNI fre…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-032`** C++ vtable pointer at offset 0 — the standard hijack, and the one indirection  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · AM-02 / AM-03, whichever supplies  · GCC and Clang place the vftable pointer at **offset 0** of a polymorphic object, so overwriting offset 0 of a …</sub>
- [ ] **`D16-033`** Negative or unchecked array index → write-four-anywhere → reuse the target's own imports  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · AM-02 / AM-03 · A negative or unchecked index is an arbitrary write. Before writing shellcode or building a ROP chain, check w…</sub>
- [ ] **`D16-034`** The stack cookie only checks at RETURN — never call a stack overflow "mitigated"  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · AM-02 / AM-03 · `-fstack-protector` inserts a check in the **epilogue**. Corrupt something the function uses *before* it retur…</sub>
- [ ] **`D16-035`** Exported component → native crash: the tombstone is what changes the VRT category  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; `ap` · **AM-03** zero-permission local ap · Drive the exported entry point that reaches native code with oversized, negative, truncated and UTF-16-surroga…</sub>

**⬜ Support ceiling**

- [ ] **`D16-036`** Enumerate the 0-click delivery paths that reach a decoder without a tap  
   <sub>`the parser bug's own path; delivery decides the multiplier (Meta: 0-click ×1, ` · **AM-01** remote, no interaction · For any parser bug, establish the highest-privilege, least-interaction path that reaches it. The rule to inter…</sub>
- [ ] **`D16-037`** Decoder reached from network-fetched bytes the app requests itself  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; oth` · **AM-09** malicious backend/CDN; * · The prime remote surface is not a parser the app exposes — it is a decoder the app *calls* on bytes it fetched…</sub>
- [ ] **`D16-038`** Same-process HALs: vendor GPU code inside the app's address space, holding a kernel fd  
   <sub>`n/a directly; it is the argument that an in-process memory bug is not merely "` · AM-02 / AM-09 (shaders, textures,  · Confirm that vendor code is mapped into the app's own process and that the process holds an open GPU device no…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-039`** Native library loaded from a path the attacker can write  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · **AM-03** (a co-located app writin · Find every loader and where it reads from. `System.load()` on an absolute path under the data directory, the c…</sub>

**🟨 Medium ceiling**

- [ ] **`D16-040`** Linker-namespace violation: the app loads a private platform or vendor library  
   <sub>`n/a standalone; it is a portability *and* security observation` · AM-12 to observe; the risk is vend · An app that loads `/system/lib64/<private>.so` or a vendor library is either targeting an old SDK or relying o…</sub>

**🟥 Critical ceiling**

- [ ] **`D16-041`** Framework-plugin `.so` files: the JNI boundary an "otherwise managed" app still has  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) with execution; oth` · AM-02 / AM-03 depending on which b · A "managed" cross-platform app still has a native attack surface: every plugin ships a `.so` with `Java_*` exp…</sub>

**🟧 High ceiling**

- [ ] **`D16-042`** Debug and ptrace exposure of the running process  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03/AM-04 **only if** the app is · Can another process attach to the app? The three conditions are the `android:debuggable` flag, the device's `p…</sub>

**🟨 Medium ceiling**

- [ ] **`D16-043`** `mlock` reduced to 64 KB per process (Android 14) — key buffers the app thought were pinned  
   <sub>`rate on the material exposed; `sensitive_data_exposure.disclosure_of_secrets.*` · AM-10/AM-11 (memory captured from  · Native code that `mlock`ed a key buffer to keep it out of swap and hibernation now fails for anything larger t…</sub>

**⬜ Support ceiling**

- [ ] **`D16-044`** Choose the fuzzer from the constraint, then build a harness that drives the DEEP path  
   <sub>Pick the engine from what you actually have, not from fashion: - source + a callable parser/decoder → **libFuz…</sub>
- [ ] **`D16-045`** Build the ASan/UBSan harness against the app's own `.so` and cross-compile it on-device  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) via the bug it find` · AM-01/AM-02 per the delivery path · An out-of-bounds read does not always crash. ASan is the bug oracle that turns "it did not crash" into a named…</sub>
- [ ] **`D16-046`** Replicate the caller's exact call sequence — the reachability rule that decides payout  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**)` · per the real path, not per your ha · A crash you produced by `dlopen`-ing a library and calling its internal functions directly is **not a finding*…</sub>
- [ ] **`D16-047`** Binary-only targets: AFL++ QEMU persistent mode, LibAFL QEMU, LibAFL Frida  
   <sub>Fork-per-execution in QEMU mode is the usual reason a campaign is "too slow to find anything". Choose the back…</sub>
- [ ] **`D16-048`** Ship the Android ASan runtime with the emulated target  
   <sub>A harness built with ASan against a firmware rootfs runs on **Bionic, not glibc** — it needs ASan's *Android* …</sub>
- [ ] **`D16-049`** Capture the tombstone, not the fact of a crash  
   <sub>`n/a; without this artefact a memory-safety claim will not triage at all` · "The app crashed" is not evidence. Collect the full tombstone with build fingerprint, faulting thread name, si…</sub>
- [ ] **`D16-050`** Triage at scale: replay → parse → bucket → rank  
   <sub>A pile of crashes is not a set of findings. Convert every crash into a structured record and collapse it to un…</sub>
- [ ] **`D16-051`** Root cause is the first ill behaviour, not the crash site  
   <sub>`n/a; it is what makes the report a root-cause analysis rather than a crash dum` · Work backwards from the crash to the first incorrect state transition. Two techniques pay: **interdependent br…</sub>
- [ ] **`D16-052`** A sanitizer shipping in production changes the finding, not just the crash  
   <sub>`moves the finding to `application_level_denial_of_service_dos.*` instead of RC` · unchanged · If UBSan ships in the release build, an integer overflow that would have been silent corruption becomes a guar…</sub>
- [ ] **`D16-053`** The mitigation reality check — name the layer that stopped you before writing "arbitrary write → RCE"  
   <sub>`it is what decides between `server_side_injection.remote_code_execution_rce` (` · unchanged · Before writing a severity, walk the chain from your primitive to code execution and mark each layer as **verif…</sub>
- [ ] **`D16-054`** Check the SELinux domain before claiming any post-exploitation step  
   <sub>`it bounds what you may claim after `server_side_injection.remote_code_executio` · unchanged · Before writing "the attacker then gains root", "reads another app's data directory" or "installs a package", c…</sub>
- [ ] **`D16-055`** `isolatedProcess` around the parser: the honest upgrade and the honest downgrade  
   <sub>`n/a standalone; it moves the parser finding up or down one band` · unchanged · A service declared `android:isolatedProcess="true"` runs with no Android permissions and almost no binder acce…</sub>
- [ ] **`D16-056`** Zygote-shared layout and kernel address hiding: do not over-credit ASLR  
   <sub>`it bounds the "needs an information leak" argument` · AM-03 — "the attacker also has an  · Two common over-credits. (1) **ASLR:** every app forks from the same zygote, so the library layout is shared a…</sub>
- [ ] **`D16-057`** A Java-reachable native overflow is a managed→native escape — state the capability gain precisely  
   <sub>``server_side_injection.remote_code_execution_rce` (**P1**) only when you demon` · AM-03 — a **zero-permission** app, · A memory-safety bug reachable from a public Java API is not "just a crash". It converts a managed app into a *…</sub>
- [ ] **`D16-058`** The evidence package for a native finding: negative control, one-shot script, and what to leave visible  
   <sub>`n/a; it is what makes the severity survive triage` · Assemble five artefacts for every native finding, in this order — the native equivalent of the five-beat state…</sub>
- [ ] **`D16-059`** Run the pre-severity gate against the CRITICAL CLAIM, and hold the retraction line  
   <sub>`it is what decides whether you file P1 or P3` · Write the draft Critical title, then substitute **the Critical claim** — not the bug — into each question: 1. …</sub>
- [ ] **`D16-060`** File the native chain as primitives first, consumer second — and count your sweep results  
   <sub>`it determines how many of the P1/P2 nodes you actually reach` · A native chain in this chapter is usually three reports, not one: an IPC/deserialisation primitive (D16-031, o…</sub>

<details><summary>⚰️ D16 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "`libtarget.so` is missing PIE / RELRO / stack canaries / FORTIFY" | `lack_of_binary_hardening.lack_of_exploit_mitigations` = **P5**. It is a build-configuration observation with no attacker action attached. PIE in particular has been enforced since API 21, so a `Type: EXEC` result is usually a vendored prebuilt, not an exposure | A reachable memory-safety bug in **that same library**, with the missing mitigation named as the layer that would otherwise have blocked your chain (D16-053) |
| "The `.so` files are unstripped and expose internal function names" | `lack_of_binary_hardening.lack_of_obfuscation` = **P5**; MASTG-TEST-0288 is a MASVS-RESILIENCE item | A symbol or embedded path that reveals something concrete — an internal hostname, a build-server path, or the exact attestation routine you then bypass (D16-015 → D21) |
| "The app bundles libwebp 1.3.0 / OpenSSL 1.1.1 / an old FFmpeg" | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5**. Every programme in the corpus rejects a CVE with no exploit: PayPal ("without showing specific impact to the target application"), Reddit, Grab, HackenProof, Basecamp | The D16-005 reachability row plus a crash or ASan verdict through a real app surface (D16-046). Without that it belongs in the client's hardening appendix, stated as such |
| A crash produced by `dlopen`-ing the library and calling its internal functions with malformed input | Google and Samsung both reject this in writing; it proves nothing about the app | Reconstruct the real caller's sequence and deliver the same input through the app's own surface (D16-046) |
| A native crash with `fault addr 0x0` from an intent extra | A null dereference is a crash, not memory corruption; via an intent it is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5** | A fault address derived from **your** input, with `pc` inside the app's own `.so` (D16-035) — or a persistent crash-on-launch loop, which is the one DoS shape worth filing |
| "`strcpy`/`sprintf`/`memcpy` are imported by the library" | An unreached unsafe sink is informational noise; modern compilers also inline these, so absence proves nothing either | A cross-reference chain from a reachable JNI entry to the sink, with the length source identified (D16-020) |
| "Root/emulator detection in `libtoolChecker.so` can be bypassed with Frida" | `lack_of_binary_hardening.lack_of_jailbreak_detection` / `.runtime_instrumentation_based` = **P5**, on your own rooted device (AM-12), which is not an attack | The detection result gating a payment, entitlement or auth decision, with the app behaving differently when you flip it (D16-023 → D23) |
| "The app maps vendor GPU libraries and holds `/dev/mali0`" | That is how every Android app renders; SP-HALs are documented architecture | An app-reachable input path into that vendor code plus a crash, or a shipped debuggable production variant used to keep restricted GPU IOCTLs working (D16-038 → D02/D25) |
| "Native libraries are only 4 KB-aligned" | A compatibility issue, Low at most | Mixed alignment or mismatched toolchains proving an unreviewed prebuilt swap, or a runtime download of a replacement `.so` over an unpinned channel (D16-016 → D17) |
| "I attached Frida to the release build and read a token out of memory" | On your own rooted device this is AM-12. Root is an evidence tool, not an attacker | The app ships `android:debuggable="true"` so a non-rooted device can attach (D16-042 → D02) |
| "The app uses native code, which is harder to analyse" | ATT&CK T1575 describes an adversary's technique, not a defect in the target | Nothing — delete it. The finding is always a specific reachable entry point |
| A raw pile of fuzzer crashes attached to a report | "Raw, un-minimized fuzzer crashes are not actionable and will be closed" | Bucketed to unique root causes, minimised, ranked, with one report per root cause and a proposed patch (D16-050, D16-051) |
| Java/Kotlin-side memory leaks (unregistered `BroadcastReceiver`s, static `Activity`/`View` references, `Context` in singletons, `AsyncTask`/`Handler`/`TimerTask` references) | MASTG flags these, but they are code-quality issues — **Informational** for bounty | Nothing in this domain; if a leak is reachable as a resource-exhaustion DoS, rate it there |

</details>


<details><summary>🔗 D16 cross-surface joins — park these, chase them in P7</summary>

- **D07 (ContentProvider `openFile`) × D16 (native decoder):** everyone tests a provider for path traversal
  and stops. The join nobody runs is: the provider hands a **file descriptor** straight into a native
  decoder, so a zero-permission app can deliver arbitrary parser input with no file written to shared
  storage and no user interaction. Enumerate the provider's MIME types (`getStreamTypes`), then feed
  malformed bytes of exactly those types through `openFile` and watch for a tombstone. The traversal is a
  D07 finding; the decoder crash reached through it is this chapter's, and they are two reports (D16-060).
- **D08 (intent redirection / Bundle deserialisation) × D16-031 (native pointer fields):** the intent
  redirection people look for a `parcelable` extra that becomes a new `Intent`; the native people look for
  a `long ptr` field. The join is that **any exported component reading a single extra deserialises the
  whole Bundle**, so an intent-redirection hop into an internal component delivers a native-pointer gadget
  into a process the attacker could not otherwise reach — turning a Medium redirection into an arbitrary
  free in the victim's UID.
- **D24 (push/messaging) × D16-036 (0-click delivery):** the push testers check FCM authentication and
  payload injection; the native testers check the decoder. Nobody checks whether a push payload's
  **large-icon or big-picture URL** reaches `LocalImageResolver` and thus a decoder, with no tap. That is
  the difference between Meta's ×0.5 two-click multiplier and its ×1 zero-click one, on the same bug.
- **D09/D10 (deep links and WebView) × D16-037 (decoder from network bytes):** a deep-link parameter or a
  WebView bridge that sets a media/image source URL gives an AM-02 attacker a first-party fetch into the
  app's own bundled decoder — with the app's cookies and User-Agent on the request. The deep-link team
  files an open-redirect-shaped Low; the join is attacker-controlled bytes into a native demuxer.
- **D02 (build integrity) × D16-039 (writable library path):** `android:extractNativeLibs` is a build flag
  nobody reads, and it decides whether the `lib-*/` planting primitive exists at all. Reviewing the manifest
  flag and the loader code **together** is what separates a real Critical from a claim that dies on a
  modern build.
- **D06 (service architecture) × D16-055 (`isolatedProcess`):** the IPC reviewer reads the service list for
  exported-ness and stops; the native reviewer rates the parser bug without checking where it runs. The
  join — which service hosts the parser, and in which SELinux domain — is worth a full severity band and
  costs one `ps -AZ`.
- **D12 (crypto) × D16-022 (native signing key) × D15 (backend):** a request-signing key recovered at the
  JNI boundary is usually filed as "hardcoded secret, Medium". The join is that it un-gates the **entire**
  API surface for off-device testing, which is what lets you exercise the app's older, weaker backend
  version behaviourally — a mobile app's hardcoded backend calls are frequently an older API version than
  the web app uses, with weaker auth and validation. The signing key is the enabler; the weakened control is
  the finding.
- **D17 (dynamic code loading) × D16-033 (arbitrary write):** an arbitrary **write** beats an arbitrary read
  the moment it lands where the app later loads code. The DCL reviewer enumerates `DexClassLoader` paths;
  the native reviewer proves a write primitive; neither checks whether the write can target the other's
  path. That intersection is the shortest route from a memory bug to persistent code execution.
- **D19 (cross-platform) × D16-041 (plugin `.so`):** Flutter/React Native apps are routinely reported as
  "no native surface" because the reviewer looked for `Java_com_target_*` and found only framework
  runtimes. The join is the **plugin** libraries plus the channel/bridge names — the bridge enumeration is
  D19's, the `Java_*` exports are this chapter's, and the bug lives between them.
- **D25 (OEM/kernel) × D16-057 (managed→native escape):** app-scope engagements stop at "code execution in
  the app UID". The join is the capability table — `/dev/binder`, `/dev/dma_heap`, `Seccomp: 0`,
  `/proc/self/maps` — which is the documented first stage of a kernel chain and belongs in the report as
  *what the primitive unlocks*, clearly separated from what you demonstrated.

</details>


---

## D17 Dynamic Code Loading, Deserialization & Supply Chain

**Phase P4 · `M4` · 80 items** — 🟥 1 critical · 🟧 7 high · 🟨 1 medium · ⬜ 71 support  

📄 Full detail, with every command and proof: [`checklist/D17-dynamic-loading-and-supplychain.md`](checklist/D17-dynamic-loading-and-supplychain.md)

> **Crux question.** **Does any byte this app executes arrive after the APK was signed — and if so, what cryptographic check stands between the attacker-influenceable source of those bytes and the `ClassLoader`/`dlopen`/JS-engine call that runs them?**

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


**⬜ Support ceiling**

- [ ] **`D17-001`** Inventory every code-load call site in the shipped artefact  
   <sub>`n/a — inventory step that feeds `server_side_injection.remote_code_execution_r` · n/a (tester step) · Enumerate every API that can turn bytes into executable code in this process, then trace each one's path argum…</sub>
- [ ] **`D17-002`** Runtime code-load trace before you believe any static conclusion  
   <sub>n/a (tester step) · Grep sees only what R8 left behind and nothing a packer decrypts. Hook the loaders and drive the app through e…</sub>
- [ ] **`D17-003`** Enumerate class loaders — the classes `Java.use` cannot see  
   <sub>n/a (tester step) · Code loaded from a secondary DEX, a downloaded plugin or a dynamic feature module lives in a *different* `Clas…</sub>

**🟥 Critical ceiling**

- [ ] **`D17-004`** In-memory DEX loading that leaves no file artefact  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the upstream input` · AM-03 / AM-06 / AM-09 depending on · An updater that decrypts into a `ByteBuffer` and calls `InMemoryDexClassLoader` produces no `.dex` on disk, so…</sub>

**⬜ Support ceiling**

- [ ] **`D17-005`** Packer / obfuscator detection before you conclude "no dynamic loading"  
   <sub>`n/a — obfuscation alone is informational and must never be filed` · n/a (tester step) · If `jadx` output is empty, trivial, or an obvious stub, the real DEX is decrypted at runtime and every grep in…</sub>

**🟨 Medium ceiling**

- [ ] **`D17-006`** Executing-artefact identity — are you analysing the code that actually runs?  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4) a` · n/a for the method; AM-09 for the  · If OTA is enabled, the bundle inside the APK is only the *fallback*. Every static finding, and every "we fixed…</sub>

**⬜ Support ceiling**

- [ ] **`D17-007`** The app ships an ingress capability — it downloads and stores executables  
   <sub>``insecure_data_transport.executable_download.no_secure_integrity_check` (P4) →` · AM-06 / AM-09 · Does the app download binaries, scripts or archives to the device? Each download is simultaneously a substitut…</sub>
- [ ] **`D17-008`** DexClassLoader / PathClassLoader over an attacker-writable path  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); the Android-native ana` · AM-03 (local app writing the path) · A `ClassLoader` constructed over a file the app (or anyone else) can rewrite, with no **load-time** signature …</sub>
- [ ] **`D17-009`** Map every file-write primitive to a code-load path — the chain rule  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · A write is not execution. The moment you obtain any write primitive, the next question is not "what can I over…</sub>
- [ ] **`D17-010`** Dynamically loaded file not marked read-only before write (Android 14 race)  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) with the race won; othe` · AM-03 · The documented pattern is `setReadOnly()` **then** write. An app that writes first and marks read-only afterwa…</sub>
- [ ] **`D17-011`** External-storage staging of executable content (man-in-the-disk)  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); the storage half alone` · AM-03 (pre-scoped-storage) / AM-04 · If an archive, plugin or library is written to external storage before being loaded, another app can tamper wi…</sub>
- [ ] **`D17-012`** SplitCompat / `verified-splits` as the write target  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · Play Core's split-loading machinery adds any `config.`-prefixed file in the `verified-splits` directory to the…</sub>
- [ ] **`D17-013`** Native library loaded from a writable path (`System.load` / `dlopen`)  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · `System.load()` takes an absolute path; `System.loadLibrary()` resolves against `nativeLibraryDir` and `lib-*/…</sub>
- [ ] **`D17-014`** Android 17 native read-only enforcement as a locator, not a wall  
   <sub>n/a (tester step) · On a matching API level the platform throws when the app loads a writable dynamic artefact — `UnsatisfiedLinkE…</sub>
- [ ] **`D17-015`** "Verified" in a name is not verification at load time  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (V` · AM-03 / AM-09 · Directory names like `verified-splits`, method names like `unZipAndVerify`, and configuration keys with `SIGNA…</sub>
- [ ] **`D17-016`** The SELinux gate — check `execute` before you write "RCE"  
   <sub>n/a (tester step) · A write into an app-private directory is not automatically execution. From `untrusted_app_29` the domain is de…</sub>
- [ ] **`D17-017`** Prove the code ran under the VICTIM's UID, not yours  
   <sub>n/a (tester step) · The single most common reason a Critical here gets downgraded is that the evidence shows the attacker's own pr…</sub>
- [ ] **`D17-018`** Play Core version check — CVE-2020-8913, including the worked negative  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when exploited; `using_` · AM-03 · Resolve the **actual** bundled version, not the coordinate. The monolithic `com.google.android.play:core` was …</sub>
- [ ] **`D17-019`** The dynamically-registered split-install receiver (invisible in the manifest)  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · The receiver that made CVE-2020-8913 exploitable is **registered at runtime**, so it appears in no manifest an…</sub>
- [ ] **`D17-020`** Post-install split delivery — test whether a modified split installs  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 / AM-11 · Feature modules are code delivered *after* install. The signing story rests entirely on the delivery channel, …</sub>
- [ ] **`D17-021`** `createPackageContext(CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)` with prefix-only matching  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · Plugin, theme, filter, font and "companion app" architectures load code from a package identified by **name**.…</sub>
- [ ] **`D17-022`** `checkSignatures` present but satisfiable — rotation and historical certificates  
   <sub>``cryptographic_weakness.insecure_implementation.improper_following_of_specific` · AM-03 · The documented fix for D17-021 is a signature comparison. Test that the comparison is actually binding: code t…</sub>
- [ ] **`D17-023`** `RemoteViews` / `ApplicationInfo` — objects that carry paths to code through IPC  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-04 (requires `POST_NOTIFICATION · A less-known but generalisable shape: `RemoteViews` embeds a serialized `ApplicationInfo` from a remote proces…</sub>
- [ ] **`D17-024`** SDK Runtime — `<uses-sdk-library>` without a pinned `certDigest`, and secrets crossing the boundary  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for th` · AM-08 · The SDK Runtime moves a runtime-enabled SDK into a separate process with no access to the app's data directory…</sub>
- [ ] **`D17-025`** Detect the OTA / plugin channel at all, and where it points  
   <sub>``insecure_data_transport.executable_download.secure_integrity_check` (P5) if t` · n/a for the discovery step · Establish that a post-install code channel exists and where it points, before testing anything about it. This …</sub>
- [ ] **`D17-026`** expo-updates with no code-signing certificate, or `ALLOW_UNSIGNED_MANIFESTS=true`  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_dat` · AM-09 (update host / CDN / EAS its · expo-updates verifies an update **only** when a code-signing certificate is configured. If `CODE_SIGNING_CERTI…</sub>
- [ ] **`D17-027`** CodePush without `CodePushPublicKey` — no bundle signature verification  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_dat` · AM-09 / AM-06 · CodePush verifies the downloaded bundle only when a public key is configured (`mPublicKey`, checked against th…</sub>

**🟧 High ceiling**

- [ ] **`D17-028`** The CodePush deployment key is shipped in the APK  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 / AM-09 · The deployment key is a string resource in the APK. Establish what that key actually authorises on the service…</sub>

**⬜ Support ceiling**

- [ ] **`D17-029`** Runtime override of the update source from a deep link, bridge or extra  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-02 (one click on a link) · Both OTA runtimes let the update source be changed at runtime. If any of that is reachable from a deep link pa…</sub>

**🟧 High ceiling**

- [ ] **`D17-030`** OTA rollback / downgrade as a security-control bypass  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) or w` · AM-03 (local corruption of the cur · CodePush keeps the previous package and rolls back on failure; expo has anti-bricking measures that can be dis…</sub>

**⬜ Support ceiling**

- [ ] **`D17-031`** Custom updater — forge the metadata and deliver your own plugin  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-06 (with the app's own TLS weak · With a trust-all `TrustManager`, a cleartext payload download, or any MitM position, plus a recoverable metada…</sub>
- [ ] **`D17-032`** Verification that exists but is not cryptographically bound  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (V` · AM-06 / AM-09 · If the updater does verify, determine whether the check is cryptographically bound to the payload and to a dev…</sub>
- [ ] **`D17-033`** Cordova / Capacitor live-update and `setServerBasePath`  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 (writable staging dir) / AM- · The web-stack frameworks have the same problem in a different shape: a plugin downloads a new `www`/`public` p…</sub>
- [ ] **`D17-034`** Android 14's read-only mandate does not cover JS/Dart bundles  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 / AM-09 · Teams routinely believe Android 14 secured their OTA. It did not: the mandate covers DEX/JAR/APK only. A `.bun…</sub>
- [ ] **`D17-035`** A trusted updater that installs packages which do not exist yet  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the install primiti` · AM-09 · Do not test only *replacement* updates. A preinstalled or privileged updater may deserialise a remote boolean …</sub>
- [ ] **`D17-036`** Configuration-driven reflective module loading  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-09 / AM-08 · Look beyond hardcoded command handlers. A compact implant receives integer task IDs, fetches JSON descriptors …</sub>

**🟧 High ceiling**

- [ ] **`D17-037`** Remote config / feature flags as an unsigned security control plane  
   <sub>`rated by the control the flag disables — `broken_authentication_and_session_ma` · AM-09 (console or backend compromi · A flag delivered over TLS but with no signature that disables pinning, lowers an auth requirement, enables a d…</sub>
- [ ] **`D17-038`** Reflection-heavy SDK code as a remote code-activation channel  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) with a demonstrated new` · AM-08 / AM-09 · Heavy `Class.forName`/`getMethod`/`invoke` inside an SDK usually means either string-obfuscated functionality …</sub>
- [ ] **`D17-039`** SDK behaviour that only activates when you are not looking  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES);` · AM-08 · An SDK that disables its own collection under a debugger, proxy, VPN or emulator reads clean in a normal dynam…</sub>

**⬜ Support ceiling**

- [ ] **`D17-040`** The update endpoint is a shadow API — diff it behaviourally  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) or `` · AM-01 · The OTA manifest endpoint, the remote-config endpoint and the plugin-catalogue endpoint are backend APIs that …</sub>
- [ ] **`D17-041`** Enforced-update mechanism absent or bypassable  
   <sub>`rate on the defect the stale version retains; the control gap alone is `using_` · AM-11 (the user's own device stayi · Without enforcement a device stays indefinitely on a version with a known, already-fixed vulnerability. MASTG-…</sub>
- [ ] **`D17-042`** Hostile-response pass — every server-controlled value that reaches a client-side sink  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the code-load sink;` · AM-09 (compromised backend, stale/ · The malicious-backend attacker model is systematically under-tested. Whoever controls the response body — incl…</sub>
- [ ] **`D17-043`** Java deserialization from an exported component — the precision rule  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) with a gadget executing` · AM-03 · `getSerializableExtra` / `ObjectInputStream` / `readObject` reachable from an **exported** component **plus a …</sub>
- [ ] **`D17-044`** Build the gadget from the target's own DEX  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · You do not need a public gadget library. The victim's own classes are on its classpath, so the gadget you want…</sub>
- [ ] **`D17-045`** Untyped `getParcelableExtra` / `getSerializableExtra` on an API 33+ target  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) for the reac` · AM-03 · The untyped overloads instantiate whatever class the `Parcel` names, using the supplied `ClassLoader`, *before…</sub>
- [ ] **`D17-046`** `Parcelable` write/read byte mismatch — the self-changing Bundle  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) for the app-` · AM-03 · It is the responsibility of a `Parcelable` implementation to ensure `createFromParcel` reads the same number o…</sub>
- [ ] **`D17-047`** A `Bundle` validated in one place and re-read in another  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES); `broken_aut` · AM-03 · The greppable corollary to D17-046. Find every place the app reads a value from an externally sourced `Bundle`…</sub>
- [ ] **`D17-048`** JSON / wrapper deserialization with an attacker-controlled class name  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the memory-corrupti` · AM-03 · Code that parses attacker-controlled JSON into an **attacker-controlled `Class`** — Gson, Jackson, Fastjson, o…</sub>
- [ ] **`D17-049`** Exotic deserializers — `Intent.parseUri`, byte-array→`Parcel`, custom unmarshallers  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES); P1 with a g` · AM-02 / AM-03 · Beyond `Parcel` and `ObjectInputStream`: `Intent.parseUri(..., URI_INTENT_SCHEME)` on attacker data reconstruc…</sub>
- [ ] **`D17-050`** `ObjectInputFilter` absent on an untrusted stream  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (V` · AM-03 · A look-ahead filter rejects unexpected classes *before* they are instantiated. Its absence on a stream fed fro…</sub>
- [ ] **`D17-051`** The native-pointer `Serializable` / `Parcelable` gadget shape  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-03 · Search the app **and its dependencies** for the shape that made Android's historic deserialization bugs exploi…</sub>
- [ ] **`D17-052`** jackson-databind — prove the three preconditions, never the version  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) with all three; `using_` · AM-03 / AM-09 · Do not file a jackson gadget CVE on version alone. Prove the three conditions the maintainers themselves defin…</sub>
- [ ] **`D17-053`** Gson below 2.8.9 — reachability or nothing  
   <sub>``using_components_with_known_vulnerabilities.outdated_software_version` (P5) w` · AM-03 · Establish the Gson version, then establish whether **Java serialization** of Gson internal types ever touches …</sub>
- [ ] **`D17-054`** XXE in the app's own XML parsing  
   <sub>``server_side_injection.xml_external_entity_injection_xxe` (P1); the read primi` · AM-02 (a file or deep-link payload · XML parsers configured to resolve external entities on attacker-influenced input read local files as the app's…</sub>
- [ ] **`D17-055`** `Runtime.exec` — the nuance that bounds the claim  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) with a shell; `insecure` · AM-02 / AM-03 · `Runtime.getRuntime().exec(String)` is **shell-less** — it splits on whitespace with no metacharacter shell — …</sub>
- [ ] **`D17-056`** Zip Slip into a code-load path — the four landing sites  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the write lands on` · AM-02 (the user imports an archive · Any extraction loop that concatenates `entry.getName()` onto a base directory without canonical validation wri…</sub>
- [ ] **`D17-057`** `ZipPathValidator.clearCallback()` — a deliberate opt-out of the platform fix  
   <sub>``server_security_misconfiguration.path_traversal` (VARIES) → `server_side_inje` · AM-02 / AM-03 · Its presence in a 34+ app means a developer deliberately turned the mitigation off — usually because a legitim…</sub>
- [ ] **`D17-058`** Symlink entries and non-empty destination directories  
   <sub>``server_security_misconfiguration.path_traversal` (VARIES) → `server_side_inje` · AM-02 / AM-03 · A canonical-path check defeats `../` but not a **symlink entry**: the archive creates `a/link -> /data/data/co…</sub>
- [ ] **`D17-059`** Generate the SBOM from the shipped binary, then scan it  
   <sub>`n/a for the SBOM; each hit inherits its own node after D17-060` · n/a (tester step) · Scanning `node_modules` or a lockfile proves nothing about a DEX plus ARM64 binary. Produce **two** SBOMs — so…</sub>
- [ ] **`D17-060`** Prove reachability before filing any dependency CVE — the closed-informative killer  
   <sub>`without it, `using_components_with_known_vulnerabilities.outdated_software_ver` · n/a (tester step) · For each CVE hit, demonstrate (a) the vulnerable class/method survived R8 into `classes*.dex` or the vulnerabl…</sub>
- [ ] **`D17-061`** Fingerprint library versions that R8 stripped the marker from  
   <sub>n/a (tester step) · When `META-INF/*.version` and `BuildConfig` are gone you still owe the triager a version. Use bytecode-structu…</sub>
- [ ] **`D17-062`** Version-fingerprint every bundled `.so`, including engine-vendored parsers  
   <sub>`rate on the demonstrated sink; version alone is `using_components_with_known_v` · AM-02 (a crafted file through the  · Native libraries are the least-patched part of an Android app and are invisible to Maven-coordinate SCA by con…</sub>
- [ ] **`D17-063`** MavenGate — a groupId whose publisher domain is purchasable  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) is where it lands if de` · AM-01 (an unauthenticated third pa · Maven `groupId`s are reverse domains and repositories prove ownership by DNS TXT. If a dependency's groupId ma…</sub>

**🟧 High ceiling**

- [ ] **`D17-064`** Dependency confusion against internal coordinates  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the build compromis` · AM-01 (needs only the coordinate n · If the build lists a public repository alongside an internal one **without content filtering**, an attacker wh…</sub>
- [ ] **`D17-065`** `pluginManagement` content filters silently ignored (LEGACY)  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-01 · On those Gradle versions, the filter that the team believes confines internal **plugin** coordinates to the in…</sub>

**⬜ Support ceiling**

- [ ] **`D17-066`** Gradle dependency verification — absent, or present and bypassed  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (V` · AM-01 (as the enabler) · Absence of `gradle/verification-metadata.xml` means every dependency and every plugin is accepted on trust fro…</sub>
- [ ] **`D17-067`** Version ranges, `+`, `latest.release` and `SNAPSHOT`  
   <sub>``cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (V` · AM-01 · A dynamic version means the build output is not reproducible and anyone who can publish *any* higher version i…</sub>
- [ ] **`D17-068`** Gradle plugins, the wrapper, and plaintext repositories — code that runs *in the build*  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-01 / AM-06 (on the CI network,  · Build scripts are executable Groovy/Kotlin. Any plugin, wrapper jar or artefact resolved from an unvetted or p…</sub>
- [ ] **`D17-069`** Duplicate-class shadowing (Maven-Hijack) in the release classpath  
   <sub>``cryptographic_weakness.insecure_implementation.improper_following_of_specific` · AM-01 / AM-08 · Two dependencies provide the same fully-qualified class; the classloader takes the first on the classpath. An …</sub>
- [ ] **`D17-070`** One library, several groupIds — the SCA blind spot  
   <sub>`n/a for the process finding; whatever bug you then demonstrate carries the rat` · n/a (tester step) · An SCA rule keyed on one `groupId` sees only a fraction of a forked library family. Search for *all* known coo…</sub>
- [ ] **`D17-071`** Abandoned library with no advisory stream  
   <sub>`rate the demonstrated bug; `using_components_with_known_vulnerabilities.outdat` · n/a (tester step) · Libraries whose upstream is archived accumulate unpatched bugs with **no advisory stream**, so neither `osv-sc…</sub>
- [ ] **`D17-072`** npm packages with known malicious releases (React Native)  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) on the build host; scop` · AM-01 against the build host · Check the lockfile and the extracted bundle for the specific compromised versions, and the developer/CI hosts …</sub>
- [ ] **`D17-073`** Developer-toolchain RCE — scope it as a build-host finding  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) against the build host` · AM-01 on the developer/CI network · The 2025 mobile-tooling RCEs landed on the developer machine, not the device. Report them that way; conflating…</sub>
- [ ] **`D17-074`** Flutter / Dart pub supply chain  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-01 · Two distinct issues: a malicious or compromised pub package, and the Zip Slip in the toolchain itself. Pub pac…</sub>
- [ ] **`D17-075`** Vendored or patched third-party code is unambiguously the vendor's bug  
   <sub>`whichever node the introduced behaviour lands in` · per the behaviour · Compare the bundled library's behaviour against upstream at the same version. A shaded, forked or hand-patched…</sub>
- [ ] **`D17-076`** Trojanised shipped artifact — the release-to-release diff  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) / `sensitive_data_expos` · AM-08 / AM-01 (compromised build) · Analyse the release build for code, permissions or endpoints nobody intended — the supply-chain *outcome* rath…</sub>
- [ ] **`D17-077`** Route the SDK finding correctly, or lose it to a duplicate  
   <sub>`per the bug` · n/a (reporting step) · Determine whether the flaw is in the app's own code or in a third-party SDK **before** filing. Check the packa…</sub>
- [ ] **`D17-078`** Run the pre-severity gate against the RCE claim, not against the bug  
   <sub>n/a (reporting step) · This domain produces more overclaimed Criticals than any other, because a write primitive and an unsigned chan…</sub>
- [ ] **`D17-079`** Chain-filing order — primitives first, consumer second  
   <sub>n/a (reporting step) · This chapter's findings are almost always chains: a write primitive owned by D07/D08 plus a load path owned by…</sub>
- [ ] **`D17-080`** False-positive discipline for substitution proofs  
   <sub>n/a (tester step) · Three specific ways this domain's evidence goes wrong, and the mechanical guard for each.</sub>

<details><summary>⚰️ D17 graveyard — do not submit these standalone</summary>

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

</details>


<details><summary>🔗 D17 cross-surface joins — park these, chase them in P7</summary>

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

</details>


---

## D18 Cloud Backend & Third-Party SDK Configuration

**Phase P6 · `M6` · 72 items** — 🟥 31 critical · 🟧 14 high · 🟨 4 medium · 🟩 2 low · ⬜ 21 support  

📄 Full detail, with every command and proof: [`checklist/D18-cloud-and-sdk-config.md`](checklist/D18-cloud-and-sdk-config.md)

> **Crux question.** For every backend identity the package contains — project id, bucket, identity-pool id, anon key, vendor API key — does it still do anything when it is used from a host that is not the app, by an identity that is not a legitimate user?

It pays because the severity is decided on a server that is in scope, by an attacker model with no preconditions at all. A Firebase Realtime Database that answers `GET /.json` is read by anyone on the internet who has done nothing more than download a free app from Google Play — no device, no root, no proximity, no user interaction, no installed malicious app. Contrast the rest of the mobile surface, where the best exported-component finding still has to argue that a victim installed the attacker's app. Bugcrowd's VRT reflects this asymmetry exactly: the whole `mobile_security_misconfiguration` branch is P5, while `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` is P1 and `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` is P1. The corpus's disclosed-report base rate says the same thing from the other direction: the Firebase open-database finding is the single most repeated mobile-recon finding in the HackerOne set (Zego #1065134 High 7.5, Periscope #684099 Critical, MTN #1447751 / #1351326 / #1351329 / #1691888, MobiSystems #731724 for the Firestore variant), and the FCM server-key class alone earned one researcher a reported $30,000+ in aggregate across programs.


**⬜ Support ceiling**

- [ ] **`D18-001`** Recover the Google Services configuration from compiled resources, not from `google-services.json`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_` · AM-01 · The Gradle Google Services plugin compiles `google-services.json` into string resources at build time, so the …</sub>

**🟥 Critical ceiling**

- [ ] **`D18-002`** Sweep `assets/`, `res/raw/`, `META-INF/` and `.properties` for the config the `strings.xml` grep misses  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Client keys live in `strings.xml`; genuine server-side credentials live in `assets/`, in bundled `.properties`…</sub>
- [ ] **`D18-003`** Pull keys out of native libraries and cross-platform bundles, where DEX-and-resource scanners do not look  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · MobSF-class scanners parse DEX and resources. For cross-platform apps the backend config is in `libapp.so`, `g…</sub>
- [ ] **`D18-004`** The high-signal secret-prefix sweep, run with result counting  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Word-grep produces noise; vendor prefixes do not. The corpus's explicit anti-pattern is "don't grep only for `…</sub>

**⬜ Support ceiling**

- [ ] **`D18-005`** Build the backend-identity table before issuing any probe  
   <sub>`n/a — methodology artefact` · Every item below is parameterised by a small set of identifiers. Collect them once, in one file, with provenan…</sub>

**🟩 Low ceiling**

- [ ] **`D18-006`** Reconstruct the SDK inventory from the merged manifest  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) once a speci` · AM-03 for the components it reveal · In a stripped, R8-renamed APK the merged manifest is the only reliable SDK list: providers, services, receiver…</sub>

**🟧 High ceiling**

- [ ] **`D18-007`** Test the key against older published versions of the APK, not just the current one  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Google's own remediation guidance for exposed FCM keys states that removing the key from the app does not fix …</sub>

**⬜ Support ceiling**

- [ ] **`D18-008`** Fingerprint SDK versions under R8 using string, resource and JNI anchors  
   <sub>``using_components_with_known_vulnerabilities.outdated_software_version` (P5) o` · With classes renamed, grepping for `com.vendor.Sdk` fails. R8 does not rename string constants, resource ident…</sub>
- [ ] **`D18-009`** MANDATORY GATE — verify Google/Firebase API-key restriction precisely, and learn the three distinct responses  
   <sub>`decides between `sensitive_data_exposure.disclosure_of_secrets.for_publicly_ac` · AM-01 · Never report "hardcoded API key". Report what the key does from a host that is not the app. There are three di…</sub>
- [ ] **`D18-010`** Maps / Places / Directions key: test both restriction axes, not one  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse` (P4); rate u` · AM-01 · The Maps key is in `AndroidManifest.xml` or `strings.xml` by construction, so extractability is never the find…</sub>

**🟨 Medium ceiling**

- [ ] **`D18-011`** Show that the package/certificate restriction is client-asserted, not an authentication boundary  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse`` · AM-01 · The Android application restriction is enforced by two headers the client sends. Both are attacker-supplied an…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-012`** Enumerate the full Google service surface a single `AIza…` key unlocks  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · "It's just the Maps key" is an assumption. Without an API restriction the key reaches every API in the project…</sub>

**⬜ Support ceiling**

- [ ] **`D18-013`** Decide P5-versus-P1 for every extracted key with an explicit written test  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_` · AOSP's own security model rule ① states that all static code and data in an APK "is considered to be public… i…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-014`** Firebase Realtime Database: unauthenticated read  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · RTDB rules are opt-in. Append `.json` to the instance URL and read it with no credential.</sub>
- [ ] **`D18-015`** Firebase Realtime Database: unauthenticated write, with marker discipline and cleanup  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Write is strictly more severe than read and the two rules are separate, so a read-denied database can still be…</sub>
- [ ] **`D18-016`** Firebase RTDB cascading-rules pitfall: a denied parent does not protect a granted child  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · Rules grant downwards and never revoke downwards. A project with `".read": false` at the root can still have a…</sub>
- [ ] **`D18-017`** Firestore: unauthenticated read via the REST API  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · Firestore and RTDB are different products with different rules and different endpoints. An app can have a lock…</sub>
- [ ] **`D18-018`** Firestore: unauthenticated document creation and patch  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Write rules are separate from read rules here too. Create a document in a scratch collection, read it back, de…</sub>
- [ ] **`D18-019`** The `request.auth != null` rule — any signed-in user reads everyone's data  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 (self-enrolment) or AM-05 (a · This is the most common *serious* Firebase misconfiguration and it is invisible to every unauthenticated scann…</sub>

**⬜ Support ceiling**

- [ ] **`D18-020`** Self-enrolment: anonymous auth or open sign-up turns "authenticated-only" into "public"  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 · If Anonymous auth or open email/password sign-up is enabled on the project, you can mint a project identity yo…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-021`** Firebase Cloud Storage: bucket object listing  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · Cheapest high-signal probe in the domain. One unauthenticated `GET` against the object-list endpoint. For Stor…</sub>
- [ ] **`D18-022`** Firebase Cloud Storage: write, overwrite and the download-token model  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · Write is the higher-severity half and is separately ruled. Also check whether you can overwrite an **existing*…</sub>

**🟧 High ceiling**

- [ ] **`D18-023`** Remote Config read via the public fetch API  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for le` · AM-01 · Remote Config is delivered to every client, so its whole payload is readable by anyone holding the app id and …</sub>

**🟥 Critical ceiling**

- [ ] **`D18-024`** Remote Config used as a secret store — read the values the device actually received  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (fetch API) or AM-11/AM-12 ( · Teams move a secret out of `strings.xml` into Remote Config believing that hides it. It does not: the value is…</sub>

**🟧 High ceiling**

- [ ] **`D18-025`** Remote Config (or any server-delivered config) used as a trust boundary  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) a` · AM-09 malicious backend/CDN, or AM · Find config values that gate security behaviour — API base URL, "enforce pinning", "require signature", a maxi…</sub>

**🟨 Medium ceiling**

- [ ] **`D18-026`** Remote Config conditions: the values you do not see exist for another cohort  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when a` · AM-01 · A single fetch shows you one cohort's template. Conditions target by app version, platform, user property, cou…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-027`** Cloud Functions, function URLs and API Gateway stages reachable without the app  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-01 · These are plain internet-facing HTTP endpoints; the SDK wrapper in the app is not a control. Critically, a fun…</sub>

**🟨 Medium ceiling**

- [ ] **`D18-028`** Identity Toolkit as an account-enumeration and provider-disclosure oracle  
   <sub>``broken_access_control.username_enumeration.non_brute_force` (P4); the provide` · AM-01 · Several Identity Toolkit endpoints differentiate existing from non-existing accounts, and `createAuthUri` addi…</sub>

**⬜ Support ceiling**

- [ ] **`D18-029`** Firebase App Check absent, monitoring-only, or shipping the debug provider in a release build  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) s` · AM-01 · App Check is the control that makes "only our app may call this backend" true. Without it, every finding in D1…</sub>

**🟧 High ceiling**

- [ ] **`D18-030`** The `appspot.com` / App Engine variant and its CORS posture  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-02 remote, one click (a web pag · The same project id usually also answers on `<project>.appspot.com`. Probe it separately, and check its CORS r…</sub>

**⬜ Support ceiling**

- [ ] **`D18-031`** Legacy FCM server key shipped in the package (LEGACY — verify the endpoint is still live)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · The client needs only the **sender id**. A *server* key in the APK lets anyone send push notifications to the …</sub>

**🟥 Critical ceiling**

- [ ] **`D18-032`** Google service-account JSON shipped in the package (the modern, worse equivalent)  
   <sub>``cloud_security.identity_and_access_management_iam_misconfigurations.publicly_` · AM-01 · With FCM HTTP v1 the send credential is an OAuth2 service account, not a server key. A service account typical…</sub>

**🟩 Low ceiling**

- [ ] **`D18-033`** Sender id is not a server key — the calibration that prevents the downgrade  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_` · `gcm_defaultSenderId` and `google_app_id` are client identifiers and belong in the package by design. Confusin…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-034`** The push data-message handler as a remote-control channel  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES — rated on wh` · AM-01 once you hold a send credent · A stolen send credential is worth far more when the app *acts* on data messages: opens a deep link, loads a UR…</sub>
- [ ] **`D18-035`** Long-lived AWS credentials in the package: prove scope, then stop  
   <sub>``cloud_security.identity_and_access_management_iam_misconfigurations.publicly_` · AM-01 · An `AKIA…`/`ASIA…` key is only as severe as its IAM policy. Enumerate the policy; do not pivot into production…</sub>
- [ ] **`D18-036`** AWS Cognito identity pool with guest (unauthenticated) access  
   <sub>``cloud_security.identity_and_access_management_iam_misconfigurations.publicly_` · AM-01 · An identity-pool id in the APK plus enabled guest access hands anyone temporary AWS credentials under the pool…</sub>
- [ ] **`D18-037`** Cognito *authenticated* role over-scope — one sign-up away  
   <sub>``cloud_security.identity_and_access_management_iam_misconfigurations.overly_pe` · AM-01 (self-registration) or AM-05 · Teams disable guest access and consider the pool hardened, while the *authenticated* role still carries `s3:*`…</sub>
- [ ] **`D18-038`** Azure storage connection strings and SAS tokens in the package  
   <sub>``cloud_security.identity_and_access_management_iam_misconfigurations.publicly_` · AM-01 · Azure ships its credential as a single connection string (`DefaultEndpointsProtocol=…;AccountName=…;AccountKey…</sub>
- [ ] **`D18-039`** Object-storage buckets named in the package: anonymous listing  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · Harvest every bucket/container/CDN host from the package and test anonymous listing on each. Bucket names embe…</sub>
- [ ] **`D18-040`** Anonymous write to an app-referenced bucket  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · World-writable beats world-readable by a band. Test a **benign** `PutObject` into a scratch key, read it back,…</sub>

**🟧 High ceiling**

- [ ] **`D18-041`** Guessable bucket names derived from the app and organisation, with ownership triage  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · Bucket names are a single global namespace, so `<org>-assets`, `<app>-prod`, `<brand>-static` exist for *someo…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-042`** Bucket takeover: the app still fetches a name nobody owns  
   <sub>``cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (` · AM-01 · If a bucket the app still requests has been deleted, the name is claimable in the global namespace and whoever…</sub>
- [ ] **`D18-043`** Object-key structure in a listing as an IDOR primitive  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 or AM-05 · The listing is not the end of the finding — the *shape* of the keys is. `users/1041/passport.jpg` is an enumer…</sub>
- [ ] **`D18-044`** Non-Google BaaS: anon/publishable key and row-level security (Supabase, Appwrite, PocketBase)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · These platforms ship a public `anon`/publishable key in the client and rely entirely on row-level security. If…</sub>
- [ ] **`D18-045`** AWS AppSync / managed GraphQL with API-key authorisation mode  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 · An AppSync endpoint with `API_KEY` as its authorisation mode accepts any caller holding the key in the APK. Th…</sub>
- [ ] **`D18-046`** Vendor SDK keys: separate the ingest key from the management/read key  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · Most of these SDKs ship two credentials: a write-only ingest key that belongs in the client, and a management/…</sub>
- [ ] **`D18-047`** Payment-processor secret key in the package  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · PSPs give the client a *publishable* key and keep the *secret* key server-side. The finding is a secret/privat…</sub>

**🟧 High ceiling**

- [ ] **`D18-048`** Client-asserted payment success: the SDK callback treated as authoritative  
   <sub>``broken_access_control.privilege_escalation` (VARIES) — rate on the value obta` · AM-05 (a user of the app) · The PSP SDK's local "payment succeeded" callback is client state. If the backend marks the order paid on the c…</sub>
- [ ] **`D18-049`** Media and CDN vendor credentials (Cloudinary, Backblaze B2, image/video pipelines)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · These SDKs' quick-start guides tell developers to paste the full credential URL into the client, so the findin…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-050`** Search-vendor admin key shipped where the search key belongs (Algolia class)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · Hosted search platforms issue a search-only key for the client and an admin key for the backend. They look ide…</sub>

**🟧 High ceiling**

- [ ] **`D18-051`** Identity-verification vendor SDK token: scope, lifetime and applicant binding  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_guid` (P4) for t` · AM-05 · These SDKs initialise with a short-lived, applicant-scoped token that the backend must mint. Test three things…</sub>

**⬜ Support ceiling**

- [ ] **`D18-052`** Support/chat SDK identity verification disabled, or the HMAC computed on-device  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 (with the extracted secret)  · Support SDKs authenticate the end user with an HMAC or JWT that the vendor requires to be produced **server-si…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-053`** Support/chat SDK minting predictable identity tokens from a hardcoded secret  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 · Where the SDK mints its own identity token client-side from a shared secret plus a sequential id, the token sp…</sub>

**🟧 High ceiling**

- [ ] **`D18-054`** Support/chat SDK WebView rendering agent- and bot-supplied HTML  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES); rate at wha` · AM-05 (the peer or agent side of t · Support SDKs render conversation content in a `WebView` and many expose a bridge for actions and file previews…</sub>
- [ ] **`D18-055`** Inter-environment key reuse: the staging key is the production key  
   <sub>``cryptographic_weakness.key_reuse.inter_environment`` · AM-01 · Compare the credentials in the release build against those in any debug, staging, beta or internal-track build…</sub>

**⬜ Support ceiling**

- [ ] **`D18-056`** Static inventory of SDK APIs known to handle sensitive user data  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) ` · AM-08 · Identify every third-party SDK and, for each, the specific entry-point methods through which app data flows in…</sub>
- [ ] **`D18-057`** Runtime capture of the argument values SDK entry points receive  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES, ` · AM-08 · Hook the entry points found in D18-056 and capture the **argument values** plus a stack trace while exercising…</sub>

**🟧 High ceiling**

- [ ] **`D18-058`** SDK transmission before consent, or after consent is declined  
   <sub>``privacy_concerns.unnecessary_data_collection` (VARIES); `sensitive_data_expos` · AM-08 · Clean install, proxy attached before first launch, decline or ignore every consent prompt, then inspect what a…</sub>

**⬜ Support ceiling**

- [ ] **`D18-059`** Session-replay SDK capturing screens the app believes are masked  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES)` · AM-08 · Masking in these SDKs is opt-in per view. They routinely capture card numbers, CVVs, OTPs, recovery codes and …</sub>

**🟧 High ceiling**

- [ ] **`D18-060`** Crash reporter shipping logcat, breadcrumbs and request bodies off-device  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES);` · AM-08 · This is the item that converts a D20 logcat observation — whose severity is capped by on-device reachability —…</sub>

**⬜ Support ceiling**

- [ ] **`D18-061`** Map the in-process capability of every bundled SDK (the peer-threat model)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES)` · AM-08 malicious third-party SDK · Every SDK in the APK runs with the app's UID, its permissions, its Keystore access and its network identity. T…</sub>

**🟧 High ceiling**

- [ ] **`D18-062`** Attribution SDK acting as a second, undocumented deep-link router  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) — rated on t` · AM-02 remote, one click · These SDKs register their own link handlers and accept a routing parameter in the attribution payload. That is…</sub>

**⬜ Support ceiling**

- [ ] **`D18-063`** Install-referrer / attribution receiver exported without a permission  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES)` · AM-03 zero-permission local app · Attribution receivers exported with no guarding permission let any installed app forge attribution data.</sub>
- [ ] **`D18-064`** Ad SDK WebView settings and client-side rewarded-ad completion  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) for the brid` · AM-09 malicious backend/CDN (the a · Ad SDKs render remote HTML in WebViews inside the app's process. Two questions: does the ad WebView have file/…</sub>

**🟧 High ceiling**

- [ ] **`D18-065`** App Startup initialisers running before any authentication or consent gate  
   <sub>``privacy_concerns.unnecessary_data_collection` (VARIES) for the egress; rate u` · AM-08; AM-09 for the config-fetch  · Every `<meta-data android:value="androidx.startup" />` names an `Initializer` that runs in `InitializationProv…</sub>

**🟨 Medium ceiling**

- [ ] **`D18-066`** Permissions, foreground-service types and components the SDKs merged into the manifest  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) for a compon` · AM-03 for components; AM-08 for pe · The app's effective attack surface is larger than its own code, and manifest merge is how. Review the **merged…</sub>

**⬜ Support ceiling**

- [ ] **`D18-067`** SDK-declared exported component: prove ownership so the report is not closed as "third party"  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (VARIES) — rated on w` · AM-03 · These reports most often die as "third-party code, not ours". Pre-empt that by proving three things, in this o…</sub>

**🟥 Critical ceiling**

- [ ] **`D18-068`** Shadow API: the backend host hardcoded in the app is an older version than the web client's  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 · A mobile app's hardcoded backend calls are frequently an **older** API version than the current web app uses, …</sub>

**⬜ Support ceiling**

- [ ] **`D18-069`** The layer-ordering trap when probing BaaS and serverless endpoints  
   <sub>`n/a — validation discipline` · A `400 "field X is required"` returned to an unauthenticated request does **not** prove you passed authenticat…</sub>
- [ ] **`D18-070`** Sweep hygiene: count your results, and never claim a negative from an uncounted loop  
   <sub>`n/a — validation discipline` · Shell array expansion fails **silently**. A loop over an array that the previous command did not populate prod…</sub>
- [ ] **`D18-071`** Body-diff and restriction claims: a status code is not a result  
   <sub>`n/a — validation discipline` · A bypass or an "unrestricted key" claim requires a response **body** differential, not a status code. A 200 wi…</sub>
- [ ] **`D18-072`** Evidence hygiene, severity governance and filing order for cloud findings  
   <sub>`n/a — reporting discipline` · Cloud findings distribute other people's data by construction, so the evidence rules are stricter here than an…</sub>

<details><summary>⚰️ D18 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Hardcoded Google API key found in `strings.xml`" | The APK is public by construction (AOSP security model rule ①: all static code and data in an APK is public). Firebase Web API keys are documented as embeddable; Reddit explicitly excludes them; Bugcrowd rates `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` P5. | Show the key authenticating from a host that is not the app and returning data or performing a billable/mutating operation — then it is `…for_publicly_accessible_asset` (P1) or `…pay_per_use_abuse` (P4). |
| Maps key returning `REQUEST_DENIED` with "Requests from this Android client are blocked" | The key is package + SHA-1 restricted. The corpus is explicit that this is a ruled-out entry, not a Low. | Nothing, for that key. Move to D18-012 and find one that is not restricted, or show an IP-unrestricted key reaching a data API. |
| `gcm_defaultSenderId` / `google_app_id` in the package | Client identifiers, required by the SDK. H1 #941590 rated a sender key **Low**; the server key in H1 #789370 was **Critical**. | A **server** key (`AAAA…:APA91b…`) or a service-account JSON, validated against the send endpoint using only a device token you own. |
| Firestore/RTDB returning `{"error":"Permission denied"}` at the root | Rules are in force at that node. | A permissive child path (rules cascade downwards only — D18-016), an authenticated read with a self-minted identity (D18-019/-020), or a callable function that reads with admin credentials (D18-027). |
| A public assets bucket that lists CSS, fonts and marketing images | Public by design; it is a CDN. | Object keys that identify users or documents (D18-043), anonymous **write** (D18-040), or a bucket the app loads code/config from. |
| Stripe `pk_live_` publishable key, Braintree client token, analytics ingest write key | Documented public client credentials; the vendor's own model expects them in the client. | The same vendor's **secret**/management key (D18-047), or the ingest key accepted by the vendor's export/read API (D18-046). |
| GraphQL introspection enabled on an AppSync endpoint | On the never-submit list on its own. | A query executed with the packaged key that returns records it should not — then it is the data finding, not the introspection. |
| Wildcard `Access-Control-Allow-Origin` on a `*.appspot.com` host | A wildcard ACAO without a credential-exfil PoC is on the never-submit list, and a wildcard cannot be combined with credentials by browsers anyway. | A **reflected** origin plus `Access-Control-Allow-Credentials: true` on a path returning authenticated data, with a working cross-origin read (D18-030). |
| "This SDK is outdated (version X)" | `using_components_with_known_vulnerabilities.outdated_software_version` is P5, and most of the named ASI library CVEs (Libpng, Libjpeg-turbo, OpenSSL logjam/CVE-2015-3194/CVE-2014-0224, Libupup CVE-2015-8540, Apache Cordova CVE-2015-5256/CVE-2015-1835/CVE-2014-3500/-3501/-3502, GnuTLS) are **LEGACY**. | A matched version string **plus** a demonstration that the vulnerable code path is reachable from app input (D18-067, -> D17). |
| An SDK-declared component is exported | Exported and inert is not a finding — it is one of the corpus's named non-paying classes. | The three-artefact ownership proof of D18-067: it ships here, a zero-permission app reaches it, and the impact lands on *this* app's data. |
| Remote Config contains feature flags | Flags are what Remote Config is for. | A credential in a value (D18-024), an internal/staging hostname that resolves (D18-023), or a value the client obeys for a security decision (D18-025). |
| MobSF/AndroBugs flagged "Firebase database found" | Unverified scanner output is, per the corpus, the single fastest route to N/A and a damaged platform reputation. | The `.json` probe result — either the data (finding) or the permission-denied body (ruled-out entry). |
| An AWS key that returns `InvalidClientTokenId` | Dead credential. | A live one, proved with `sts get-caller-identity` and its attached policy names — and nothing further. |
| App Check not implemented | Medium at best standalone; it is a defence-in-depth control, and on its own it is not attacker-attainable harm. | Pair it with a rules or callable finding and write it as the missing-mitigation line that makes that finding remotely reachable rather than on-device only (D18-029). |
| Session-replay SDK present in the package | Presence is inventory. | A canary typed into a sensitive field found in the decompressed upload payload, or visible in the vendor's replay (D18-059). |
| Analytics SDK sends an advertising id | Pseudonymous identifier, the SDK's stated purpose, and most vendors run privacy at a much lower band anyway. | The identifier **joined to an account id**, an email, a phone number, precise location, or a session token — and transmitted before consent (D18-057, D18-058). |

</details>


<details><summary>🔗 D18 cross-surface joins — park these, chase them in P7</summary>

- **Merged manifest (D18-006/-066) × WebView configuration (D10).** Nobody reviews a third-party SDK's WebView. The Grab case (H1 #401793) is exactly this join: a *support SDK's* activity, reachable by deep link, hosting a WebView with `addJavascriptInterface` exposing `getGrabUser()`. The app team audited their own WebViews and the vendor audited theirs in isolation; the bridge lived in the seam. Enumerate every WebView **outside** the first-party package prefix and rate it by what its bridge methods return.
- **Writable object storage (D18-040/-022) × dynamic code and content loading (D17/D02).** The storage test and the code-loading test are usually run by different people on different days. Join them: take the bucket you can write to and ask whether any path in it is a JS bundle, a config JSON, an OTA payload or an image the app renders in a WebView. A writable asset bucket that the app loads code from is remote code execution for every install, and is rated there — not as a storage misconfiguration.
- **Remote Config (D18-023/-025) × certificate pinning (D14) × the shadow API (D18-068).** Pinning is P5 on its own and config is "just flags" on its own. Joined: a config value named `enforce_pinning` or `api_base_url` that the client obeys, fetched over a channel that is itself unpinned, means an AM-06 network attacker redirects authenticated traffic to a host of their choosing — and the staging host the config leaks is usually the weaker API version. Three P5-to-P4 observations compose into a remote finding.
- **Firebase Auth self-enrolment (D18-020) × the app's own API (D15).** The project identity you minted for the rules test is frequently the *same* identity the app's backend trusts. Take the `idToken` from `accounts:signUp` and present it to the first-party API. Where the backend verifies the Firebase token but derives authorisation from a claim the client controls, an anonymous identity becomes an authenticated one on the real API.
- **Push send credential (D18-031/-032) × the message handler (D18-034) × deep links (D09).** A server key is High as mass phishing. Joined with a handler that routes on message content and a deep link that reaches a sensitive route, the same credential is remote, zero-interaction navigation control over every install — the D09 chain without needing the victim to click anything.
- **Crash reporter configuration (D18-060) × logcat findings (D20) × the OkHttp interceptor (D14).** Each is capped: logcat needs a local reader, `HttpLoggingInterceptor` is a code smell, the crash SDK is inventory. Joined, the interceptor writes the bearer token to logcat, the reporter attaches logcat to crash reports, and the token leaves the device to a third party — which removes the on-device reachability cap that limited the logcat finding.
- **Cognito/identity-pool role scope (D18-036/-037) × object-key structure (D18-043) × the app's own IDOR surface (D15).** The role decides *whether* you can call S3; the key structure decides *whose* object you get. Testers usually stop at the role. Enumerate the per-identity prefix convention from the listing and then test the same substitution against the app's own download endpoint — the two surfaces frequently disagree about who owns an object.
- **App Startup initialisers (D18-065) × backup and restore (D11/D28).** An initialiser that reads a config or token from `SharedPreferences` before any gate, combined with permissive backup rules, means an attacker-supplied restore seeds the app's control plane before the lock screen is drawn. Neither surface is interesting alone.
- **SDK-injected permissions (D18-066) × confused-deputy components (D05).** The permission an SDK merged in is exactly what an exported first-party receiver inherits. Cross the merged-manifest permission list against the exported-component list: an SDK-contributed `READ_PHONE_STATE` or location permission raises the ceiling of every confused-deputy primitive the app already had.

</details>


---

## D19 Cross-Platform Frameworks

**Phase P4 · `M4` · 79 items** — 🟥 31 critical · 🟧 12 high · 🟨 6 medium · 🟩 2 low · ⬜ 28 support  

📄 Full detail, with every command and proof: [`checklist/D19-cross-platform-frameworks.md`](checklist/D19-cross-platform-frameworks.md)

> **Crux question.** **Which artefact in this package actually holds the app's logic, and once I have opened it, does it hand me a credential that authenticates, an endpoint the UI never calls, a bridge that reaches native capability, or a code channel that can replace the app after the store review?**

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


**⬜ Support ceiling**

- [ ] **`D19-001`** Fingerprint the runtime and record targetSdk before running any Java-centric test  
   <sub>`n/a (coverage control; the finding is whatever the correct pipeline then recov` · Determine which runtime holds the business logic from the APK's own artefact list, and record `targetSdkVersio…</sub>
- [ ] **`D19-002`** Collect every split APK, XAPK and feature module before declaring a framework library absent  
   <sub>`n/a (coverage control)` · Flutter, RN and Unity apps are routinely distributed as split APKs, where `libapp.so`, `libil2cpp.so` and `lib…</sub>

**🟨 Medium ceiling**

- [ ] **`D19-003`** Verify you are analysing the code that actually runs — OTA-aware artefact identity  
   <sub>`n/a standalone; the associated finding is `server_side_injection.remote_code_e` · AM-09 · If an OTA channel exists, the bundle inside the APK is only the fallback. Every static finding must be re-chec…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-004`** Read the framework's own manifest meta-data and `strings.xml` keys  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the keys show an u` · AM-09 · Each framework stores security-relevant configuration as `<meta-data>` in the merged manifest or as string res…</sub>

**⬜ Support ceiling**

- [ ] **`D19-005`** Rebut the "it is obfuscated, so it is not exploitable" defence with recovered artefacts  
   <sub>`n/a (report-defence control)` · Vendors close real findings by asserting that Flutter `--obfuscate`, Hermes bytecode, IL2CPP or ProGuard makes…</sub>
- [ ] **`D19-006`** Decide Hermes vs JSC vs the new architecture before choosing any React Native tooling  
   <sub>`n/a (coverage control)` · RN ships three runtime shapes that need different attacks: Hermes bytecode bundles, JSC plain-JS bundles, and …</sub>
- [ ] **`D19-007`** Read the Hermes header and the exact bytecode version yourself  
   <sub>`n/a (prerequisite for every RN static finding)` · The HBC version number decides which tools can parse the file at all, and the `sourceHash` is a stable build f…</sub>
- [ ] **`D19-008`** Pick a Hermes tool by bytecode version — public tooling lags the shipped HBC  
   <sub>`n/a (coverage control)` · Verify your decompiler actually supports the app's HBC version instead of silently producing garbage or refusi…</sub>
- [ ] **`D19-009`** Parse the Hermes string table yourself when no decompiler supports the version  
   <sub>`n/a directly; routinely produces the `sensitive_data_exposure.disclosure_of_se` · Even with an unsupported HBC version, every string literal is recoverable: the string table is a flat blob ful…</sub>

**🟧 High ceiling**

- [ ] **`D19-010`** Mine routes, screen names and permission gates out of the bundle, then drive them  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-02 remote one-click via a deep  · RN navigation declares screens as string names. That list is the app's true page inventory, including screens …</sub>

**🟥 Critical ceiling**

- [ ] **`D19-011`** Build the endpoint inventory from the bundle or snapshot, not from observed traffic  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 remote no interaction (once  · Traffic observation only reveals the endpoints the UI happens to exercise. The bundle or snapshot contains the…</sub>
- [ ] **`D19-012`** Validate every bundle-resident credential against the live service before reporting it  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · RN and Ionic apps routinely embed keys that are "public" by the vendor's framing but privileged in practice — …</sub>

**🟨 Medium ceiling**

- [ ] **`D19-013`** Source map shipped in the APK or fetchable from the update host  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when t` · AM-01 · An `index.android.bundle.map`, or a map reachable on the CDN/OTA host, collapses the whole static analysis pro…</sub>
- [ ] **`D19-014`** Enumerate Metro module boundaries — a JS SBOM no DEX-based SCA produces  
   <sub>`n/a as inventory; the finding is whatever the reachable vulnerable package yie` · AM-08 · A Metro bundle is a map of numbered modules (`__d(factory, moduleId, deps)`). Recovering that map gives a de-f…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-015`** Vulnerable and malicious npm packages in the React Native dependency set  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-08 malicious third-party SDK (t · Two distinct classes. (a) A shipped library version with a known defect whose impact you can demonstrate on-de…</sub>

**⬜ Support ceiling**

- [ ] **`D19-016`** `@react-native-community/cli` dev-server RCE (CVE-2025-11953) — scope it to the build environment  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) against the developer/C` · AM-06 network attacker on the deve · The CLI exposed an unauthenticated OS-command path through its development server. The exposure is the build h…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-017`** React Native dev support, Metro bundle server and dev activities in the shipped build  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); `cloud_security.miscon` · AM-06 network attacker (serves the · RN's dev support fetches the JS bundle over plain HTTP from a packager host and exposes inspector endpoints. I…</sub>
- [ ] **`D19-018`** Enumerate the React Native native-module surface and invoke it from injected JS  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-09 (an OTA bundle chooses the c · RN's bridge exposes every registered native module to JS. Enumerate the registry, then rate the bridge **by wh…</sub>

**⬜ Support ceiling**

- [ ] **`D19-019`** React Native static-analysis false negatives: module naming and `getConstants()` timing  
   <sub>`n/a (retraction prevention)` · Two specific ways an RN review produces a confident wrong negative. (1) **The JS-visible module name is not th…</sub>
- [ ] **`D19-020`** Load your own JS into the running RN app and intercept XHR above TLS  
   <sub>`n/a (harness; it converts a "pinned, untestable" app into a fully testable one` · AM-12 own rooted device — **not an · Injecting a second script at `loadScriptFromAssets` time gives you a live JS console inside the app's own runt…</sub>
- [ ] **`D19-021`** Patch a Hermes string, reassemble, and prove the bundle carries no integrity control  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (P5) standalone — **do ` · AM-12 own rooted device for the de · Replace or edit the bundle, re-sign, install, and confirm the app runs attacker-controlled JS. This converts "…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-022`** `react-native-webview`: bridge props, `injectedJavaScriptObject`, and the media auto-grant  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-02 remote one-click · `react-native-webview` installs a JS interface named `ReactNativeWebView` with `postMessage`, and exposes prop…</sub>

**🟩 Low ceiling**

- [ ] **`D19-023`** React Native certificate pinning implemented only in JavaScript  
   <sub>``mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (**P5**)` · AM-06/AM-07 · When pinning lives in a JS library rather than a Network Security Config or an OkHttp `CertificatePinner`, it …</sub>

**🟧 High ceiling**

- [ ] **`D19-024`** Read the framework's storage backend using the key names you already mined  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-11 physical unlocked / AM-12 ow · Each framework has a default key/value store in a predictable file. Because the *key names* are already in you…</sub>

**⬜ Support ceiling**

- [ ] **`D19-025`** Establish whether the app can replace its own code over the air at all  
   <sub>`n/a directly` · AM-09 · OTA JS/web delivery converts the app into a remote-code-execution surface whose trust anchor is a server and, …</sub>

**🟥 Critical ceiling**

- [ ] **`D19-026`** expo-updates with no code-signing certificate, or `CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS=true`  
   <sub>``server_side_injection.remote_code_execution_rce` (P1). The nearest literal no` · AM-09 malicious backend/CDN; AM-06 · expo-updates verifies an update only when a code-signing certificate is configured. If `CODE_SIGNING_CERTIFICA…</sub>
- [ ] **`D19-027`** CodePush with no `CodePushPublicKey` — no bundle signature verification  
   <sub>``server_side_injection.remote_code_execution_rce` (P1); baseline `insecure_dat` · AM-09; AM-06 where TLS is the only · CodePush verifies the downloaded bundle only when a public key is configured — `mPublicKey` is checked against…</sub>
- [ ] **`D19-028`** Runtime override of the OTA update channel reachable from a deep link or bridge  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-02 remote one-click · Both OTA runtimes allow the update source to be changed at runtime. If any of that plumbing is reachable from …</sub>

**🟧 High ceiling**

- [ ] **`D19-029`** OTA rollback and downgrade as a security-control bypass  
   <sub>``broken_access_control.privilege_escalation` (null — rated on the control the ` · AM-03 zero-permission local app (c · CodePush keeps the previous package and rolls back on failure; expo-updates has anti-bricking measures that ca…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-030`** Cordova / Capacitor live-update payload substitution  
   <sub>``server_side_injection.remote_code_execution_rce`` · AM-09 · The web-stack frameworks have the same problem in a different shape: a plugin downloads a new `www`/`public` p…</sub>

**⬜ Support ceiling**

- [ ] **`D19-031`** Capture OTA findings with before/after bundle identity, not a screenshot  
   <sub>`n/a (evidence control)` · For any OTA/code-delivery finding the decisive evidence is that the running code changed without a reinstall. …</sub>

**🟨 Medium ceiling**

- [ ] **`D19-032`** Flutter: distinguish release AOT from debug/profile — `kernel_blob.bin` in a store build  
   <sub>``cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfa` · AM-01 for the artefact; AM-03/AM-0 · A debug or profile Flutter build ships `kernel_blob.bin`, `isolate_snapshot_data` and `vm_snapshot_data` under…</sub>

**⬜ Support ceiling**

- [ ] **`D19-033`** Flutter: string-mine the Dart AOT snapshot — this always works  
   <sub>`n/a directly` · jadx gives only the thin Java shell. The router, WebView configuration, API authentication and business logic …</sub>
- [ ] **`D19-034`** Flutter: recover Dart symbols with Blutter, and fall back to reFlutter when it cannot build  
   <sub>Dart AOT snapshots resist normal reversing (custom registers and calling conventions, sequential class metadat…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-035`** Flutter: harvest the Dart object pool for endpoints, keys and crypto parameters  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · Every string constant, class name and crypto parameter the app uses is reachable from the AOT snapshot's objec…</sub>
- [ ] **`D19-036`** Flutter: resolve pool-relative loads and Smi encoding to reconstruct an embedded key  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (offline, from the public AP · Two mechanics make Dart constants look like noise. (1) Dart AOT keeps the object pool in `x27` (`PP`); pool lo…</sub>
- [ ] **`D19-037`** Flutter, Unity and .NET: private keys and signing material inside the native blob  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · Cross-platform builds bury PEM blobs and HMAC seeds in the native blob. Scan the file statically, and also sca…</sub>
- [ ] **`D19-038`** Flutter: recover the request-signing algorithm by hooking Dart string concatenation  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 · When the signing material is derived rather than stored, hook the signing function Blutter named and capture t…</sub>

**⬜ Support ceiling**

- [ ] **`D19-039`** Flutter carries its own BoringSSL trust store — the Android CA store and system proxy do not apply  
   <sub>``mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (**P5**)` · AM-07 network attacker with a trus · Dart's `HttpClient` uses BoringSSL compiled into `libflutter.so` with its **own** CA list. It does not read th…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-040`** Flutter: enumerate `MethodChannel`, `EventChannel` and `BasicMessageChannel`, then exercise the handlers  
   <sub>``server_side_injection.file_inclusion.local` (P1) for a path-taking handler; o` · AM-03 zero-permission local app wh · Every Dart↔native capability crosses a channel with a string name. Those names point at privileged native acti…</sub>

**🟧 High ceiling**

- [ ] **`D19-041`** Flutter: `flutter_deeplinking_enabled` defaults to ON when the meta-data is absent  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-02 remote one-click · `FlutterActivityLaunchConfigs.deepLinkEnabled(metaData)` returns **true** when the key is missing. A Flutter a…</sub>
- [ ] **`D19-042`** Flutter: force an arbitrary in-app route via the `route` intent extra  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 zero-permission local app (a · `getInitialRoute()` checks `intent.hasExtra("route")` first. Any exported `FlutterActivity` or subclass — incl…</sub>

**🟩 Low ceiling**

- [ ] **`D19-043`** Flutter: engine substitution goes undetected — reFlutter and LIEF gadget injection  
   <sub>``lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) — do not file;` · AM-12 own device — **not an attack · reFlutter-patched engines and gadget-injected builds are the standard testing path. An app that claims tamper …</sub>

**🟨 Medium ceiling**

- [ ] **`D19-044`** Flutter: obfuscation symbol maps leaking from CI or crash infrastructure  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when t` · AM-01 · `--obfuscate --split-debug-info` only renames symbols and stores the map externally. It does not encrypt `flut…</sub>

**⬜ Support ceiling**

- [ ] **`D19-045`** Dart and pub supply chain — Zip Slip in package extraction and malicious pub packages  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) against the build host ` · AM-08 malicious third-party SDK · Two distinct issues: a malicious or compromised pub package, and the Zip Slip in the toolchain itself. Both hi…</sub>

**🟧 High ceiling**

- [ ] **`D19-046`** Cordova / Capacitor: inventory the web root — the entire app is in `assets/`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 · For these frameworks all application logic ships as readable (sometimes minified) web assets. Treat `assets/ww…</sub>

**⬜ Support ceiling**

- [ ] **`D19-047`** Cordova allow-lists: `*` on `allow-navigation` also grants `data:`  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the plugin-driven f` · AM-02 remote one-click · `<allow-navigation href="*">` and `<access origin="*">` are extremely common copy-paste defaults. The first le…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-048`** Capacitor `server.url` shipped as a live-reload or staging origin  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) — whoever controls that` · AM-06 network attacker (with `serv · `server.url` makes the WebView load an **external** URL instead of the bundled assets. Shipped in a release bu…</sub>
- [ ] **`D19-049`** Capacitor `/_capacitor_file_` — arbitrary app-private file read from inside the WebView  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) once` · AM-02 remote one-click (given any  · Capacitor's local server maps any request whose path starts with `/_capacitor_file_` to `new FileInputStream(p…</sub>
- [ ] **`D19-050`** Capacitor `/_capacitor_http_interceptor_?u=` — SOP bypass and device-sourced SSRF  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) where it reaches an int` · AM-02 · The local server intercepts `/_capacitor_http_interceptor_?u=<absolute-url>` and performs the request **native…</sub>
- [ ] **`D19-051`** Enumerate the full Capacitor plugin surface reachable from `androidBridge.postMessage`  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for a Filesystem/exec-c` · AM-02 · Every registered plugin method is invokable from JS by posting a JSON message. Enumerate the plugin list from …</sub>
- [ ] **`D19-052`** Cordova `_cordovaNative` bridge and its `bridgeSecret` gate  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when `exec()` succeeds ` · AM-02 · Cordova exposes `exec()` through `addJavascriptInterface(exposedJsApi, "_cordovaNative")`, guarded by an integ…</sub>
- [ ] **`D19-053`** Cordova `AndroidInsecureFileModeEnabled` — a one-preference universal file-read SOP bypass  
   <sub>``server_side_injection.file_inclusion.local` (P1); `broken_authentication_and_` · AM-02 · This single preference switches the WebView back to a `file://` origin **and** enables both file access and un…</sub>

**🟧 High ceiling**

- [ ] **`D19-054`** Cordova plugins instantiated at startup via `onload`  
   <sub>`rated by behaviour; `cloud_security.misconfigured_services_and_apis.exposed_de` · AM-01/AM-03 depending on what the  · `ConfigXmlParser` honours `<param name="onload" value="true"/>`, instantiating the plugin before any page load…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-055`** Audit every custom plugin's exposed method surface  
   <sub>``server_side_injection.file_inclusion.local` (P1) for a path-taking method; `s` · AM-02 · Hand-written plugins are where the interesting bugs live: a `@PluginMethod` that takes a path, a URL or SQL an…</sub>
- [ ] **`D19-056`** The WebView is the entire app — run the full web methodology against the bundled assets  
   <sub>``cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) for the cross-user ` · AM-02 · For these frameworks there is no separate "native app" to test — the app *is* a web app with a native bridge. …</sub>

**⬜ Support ceiling**

- [ ] **`D19-057`** The CSP meta tag is the last control once the allow-list is loose  
   <sub>`no standalone node — a missing CSP alone is on the never-submit list; file the` · AM-02 · For these frameworks the CSP meta tag in `index.html` is the only real defence once `allow-navigation` is loos…</sub>

**🟧 High ceiling**

- [ ] **`D19-058`** `webContentsDebuggingEnabled` / `InspectableWebview` in the release build  
   <sub>``cloud_security.misconfigured_services_and_apis.exposed_debug_or_admin_interfa` · AM-11 physical unlocked, or anyone · All three WebView frameworks expose a switch that enables remote debugging. In a release build this hands anyo…</sub>
- [ ] **`D19-059`** Capacitor's native HTTP path silently skipping pinning  
   <sub>``insecure_data_transport.cleartext_transmission_of_sensitive_data` (null) wher` · AM-06 network attacker · `handleCapacitorHttpRequest()` installs the pinning-aware socket factory only when the domain is **not** exclu…</sub>

**🟨 Medium ceiling**

- [ ] **`D19-060`** Capacitor scheme, `minWebViewVersion` and `allowMixedContent`  
   <sub>`no standalone node; it is the context that makes the D19-047 → D19-053 finding` · AM-06 for mixed content; AM-01 for · The local-server scheme determines the WebView's origin, and therefore which origin your allow-list and CSP ac…</sub>

**⬜ Support ceiling**

- [ ] **`D19-061`** Unity: recover the C# type graph from `libil2cpp.so` and `global-metadata.dat`  
   <sub>`n/a as recon; `lack_of_binary_hardening.lack_of_obfuscation` (**P5**) if filed` · IL2CPP ships `global-metadata.dat` alongside `libil2cpp.so`; together they regenerate near-complete class, met…</sub>
- [ ] **`D19-062`** Unity: defeat encrypted, renamed or relocated `global-metadata.dat`  
   <sub>`n/a (metadata protection is a resilience control; report only what the recover` · When Il2CppDumper reports `ERROR: Metadata file supplied is not valid metadata file.`, the metadata is protect…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-063`** Unity: client-authoritative entitlement and economy logic in `dump.cs`  
   <sub>``broken_access_control.privilege_escalation` (null — rated on the entitlement ` · AM-12 own device for the manipulat · Unity games commonly grant entitlements client-side and tell the server afterwards. Find the grant function, c…</sub>

**🟧 High ceiling**

- [ ] **`D19-064`** Unity: PlayerPrefs and `persistentDataPath` treated as authoritative state  
   <sub>``broken_access_control.privilege_escalation` (null) when the server accepts th` · AM-12 own device · Unity games routinely persist currency, entitlements and progression in `PlayerPrefs` or under `Application.pe…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-065`** Unity: exported player activity, intent extras, and the `unity` CLI extras bridge  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) for the CLI-extras libr` · AM-03 zero-permission local app · Unity apps typically export a player activity as `MAIN`/`LAUNCHER`, and the Unity runtime honours a `unity` co…</sub>

**⬜ Support ceiling**

- [ ] **`D19-066`** Xamarin / .NET MAUI: extract the assemblies — the layout changed at .NET 9  
   <sub>`n/a as recon` · All Xamarin/MAUI business logic is IL in .NET assemblies. Where those assemblies live changed between generati…</sub>
- [ ] **`D19-067`** Xamarin / MAUI: managed-layer pinning, root checks and crypto  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 for the key; AM-06/AM-07 for · .NET apps pin, root-check and encrypt in managed code, typically via `ServicePointManager.ServerCertificateVal…</sub>
- [ ] **`D19-068`** Xamarin / MAUI: patch IL and rebuild the assembly store to prove a client-side check is the only control  
   <sub>``lack_of_binary_hardening.lack_of_jailbreak_detection` (**P5**) if filed as a ` · AM-12 own device · The cleanest Xamarin PoC is an IL edit: flip the method that gates a feature, repack the assembly store, re-si…</sub>
- [ ] **`D19-069`** Kotlin Multiplatform: map `commonMain` versus `androidMain` before rating the finding  
   <sub>`n/a directly` · In a KMP app a defect in `commonMain` affects every target; a defect in `androidMain` affects only Android. Th…</sub>

**🟥 Critical ceiling**

- [ ] **`D19-070`** Kotlin Multiplatform: secret injection via `expect/actual` and generated constants  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`` · AM-01 · KMP guidance routes secrets through `BuildConfig` fields fed from `local.properties`, or a Gradle-generated co…</sub>
- [ ] **`D19-071`** WebAssembly modules shipped in the WebView or the app runtime  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 (offline analysis) / AM-12 ( · Some apps ship `.wasm` modules for crypto, DRM, licence checks or ML inside the web assets, or load them from …</sub>
- [ ] **`D19-072`** Other embedded JS runtimes evaluating network-fetched script  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the script text is` · AM-09 malicious backend/CDN; AM-06 · Beyond React Native, apps ship general JS engines (QuickJS, Duktape, JerryScript, V8, JavaScriptCore) for rule…</sub>
- [ ] **`D19-073`** Shadow API — the mobile build's hardcoded backend calls are usually an older API version  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-01 remote no interaction · Old API versions stay reachable without receiving the same fixes, and a mobile app's hardcoded backend calls a…</sub>
- [ ] **`D19-074`** Client-side-only validation, rate limits and MFA because the logic moved to shared code  
   <sub>``broken_access_control.privilege_escalation` (null) or `broken_authentication_` · AM-01 · Cross-platform teams frequently implement validation once, in shared code, and assume the server mirrors it. E…</sub>

**🟧 High ceiling**

- [ ] **`D19-075`** Framework cleartext and TLS configuration outside the Android Network Security Config  
   <sub>``insecure_data_transport.cleartext_transmission_of_sensitive_data` (null — rat` · AM-06 network attacker, no trusted · A Network Security Config that forbids cleartext constrains the platform `HttpsURLConnection`/OkHttp path only…</sub>
- [ ] **`D19-076`** Framework verbose logging carrying bridge payloads  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); C` · AM-04 local app with a common perm · Capacitor logs every plugin call and every Cordova-compat call including `actionArgs`. If verbose logging surv…</sub>

**⬜ Support ceiling**

- [ ] **`D19-077`** False-positive discipline for framework-recovered endpoints, strings and behaviours  
   <sub>`n/a (validity control)` · Framework recovery produces a very high volume of candidate strings and routes. Four disciplines keep the resu…</sub>
- [ ] **`D19-078`** Report discipline: state the runtime and artefact identity; never report recovery as the finding  
   <sub>`n/a (triage control)` · A cross-platform finding is not reproducible without the runtime, the bundle/snapshot identity and the tool ve…</sub>
- [ ] **`D19-079`** Chain-filing order for framework chains  
   <sub>`n/a (submission control)` · The high-value outcomes here are chains: *bundle-recovered endpoint* + *shadow-API auth regression*; *loose al…</sub>

<details><summary>⚰️ D19 graveyard — do not submit these standalone</summary>

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

</details>


<details><summary>🔗 D19 cross-surface joins — park these, chase them in P7</summary>

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

</details>


---

## D20 Privacy, PII, Logging & Data Leakage

**Phase P4 · `M4` · 70 items** — 🟧 12 high · 🟨 10 medium · 🟩 3 low · ⬜ 45 support  

📄 Full detail, with every command and proof: [`checklist/D20-privacy-and-data-leakage.md`](checklist/D20-privacy-and-data-leakage.md)

> **Crux question.** **For each sensitive value the app handles: which principal other than the app and its own backend ends up holding that value — a co-resident app with one user grant, a third-party host, the lock screen, another signed-in user — and if none does, is any value the app emits an authenticator?**

Mostly it does not, and the base rates from the corpus say so with unusual clarity. Google's Mobile VRP
Invalid Reports page excludes logging outright: *"We aim to keep Android logs free of personally
identifiable information, but since debugging privileges are required to access logs, an app logging
sensitive data is not considered a severe enough vulnerability to qualify."* Superhuman/Grammarly's
"Grammarly Keyboard for Android <4.1 leaks user input through logs" paid **$0** on 84 upvotes (H1 #462416).
NordVPN's advertising-identifier misuse (H1 #803941) paid **$0**. Basecamp lists "EXIF information not
stripped from uploaded images" as out of scope. Xiaomi excludes "any data leak because the malicious APP has
acquired the appropriate permissions". Intigriti's triage standard rejects *"functional bugs or process flaws
resulting in compliance, privacy and governance issues that do not pose an immediate and exploitable
threat"*. If your D20 output is a list of things the app logs, you have produced hygiene notes.


**⬜ Support ceiling**

- [ ] **`D20-001`** The reader test — name the principal who holds the value before writing the word "leak"  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null = r` · AM-04 / AM-08 / AM-10 / AM-05; exp · Before writing anything, answer in one sentence: *which principal other than this app ends up holding this val…</sub>
- [ ] **`D20-002`** Build the canary identity and the marker set before you capture anything  
   <sub>`n/a — method` · Every leak claim in this chapter is "value X reached place Y". That is only greppable if X is unique. Register…</sub>
- [ ] **`D20-003`** The crown-jewel sink map — follow the value, not the API  
   <sub>`n/a — method` · Catalogues are organised by *mechanism* (logs, clipboard, notifications). Attackers care about *the value*. Pi…</sub>
- [ ] **`D20-004`** Count your sweep results — the shell-loop ban applied to log and traffic sweeps  
   <sub>`n/a — method` · A privacy sweep that returns nothing is indistinguishable from a privacy sweep that silently failed. `adb logc…</sub>
- [ ] **`D20-005`** Tester-side data minimisation — your evidence bundle is a breach surface  
   <sub>`n/a — method, with a real consequence` · The redaction rules in D20-006 govern the *rendered* evidence. They do not govern what your tooling hoovers up…</sub>
- [ ] **`D20-006`** Redact victim PII in the PoC while keeping the proof intact  
   <sub>`n/a — method; it is what makes a `pii_leakage_exposure` report land instead of` · The evidence must convince a triager and distribute nothing further. The useful part is the split, and testers…</sub>
- [ ] **`D20-007`** The controlled one-flow logcat sweep — never read the buffer passively  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — ` · AM-04 (a `READ_LOGS` holder), AM-0 · Clear the buffers, capture **all** of them, drive exactly **one** flow, then sweep. Passive reading produces n…</sub>
- [ ] **`D20-008`** Cap logcat severity honestly — enumerate the readers or rate it P5  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · AM-04 / AM-08 / AM-11 · `READ_LOGS` has been `signature|privileged` since **Android 4.1 (API 16)**, so a third-party app cannot read a…</sub>
- [ ] **`D20-009`** Hook the logging APIs, not just the buffer — wrappers, Timber, println, stack traces  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · n/a — instrumentation · Apps route logging through their own wrapper (`AppLog`, `Timber`, a Kotlin `inline fun log`), through `System.…</sub>
- [ ] **`D20-010`** `HttpLoggingInterceptor` / Chucker / Stetho left at BODY in a release build  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · AM-04 / AM-08 / AM-11 · The single most common form of "insecure logging" that actually matters. A debug network interceptor dumps the…</sub>
- [ ] **`D20-011`** Cross-platform framework verbose logging carrying bridge payloads  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 / AM-11 · Capacitor logs every plugin call including `actionArgs`, and Cordova-compat calls the same way. Plugin argumen…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-012`** ORM query logging enabled in production  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 / AM-11 · A rarely-checked variant: the app's own logging hygiene can be immaculate while the ORM dumps every statement,…</sub>

**🟩 Low ceiling**

- [ ] **`D20-013`** `StrictMode` violations logged in a production build  
   <sub>``sensitive_data_exposure.visible_detailed_error_page.full_path_disclosure` (P5` · AM-11 · `StrictMode` policy-violation logging in release leaks implementation detail — file paths, SQL, network call s…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-014`** Tombstones, DropBox, ANR traces and `adb bugreport` — the off-app log path  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-11 (physical unlocked with ADB) · Logcat is not the only system-held copy. Native crashes write tombstones, the framework writes DropBox entries…</sub>

**🟧 High ceiling**

- [ ] **`D20-015`** Full request URLs with tokens in the query string, written to the log  
   <sub>``sensitive_data_exposure.sensitive_token_in_url.user_facing` (P4); the log cop` · AM-04 / AM-08 / AM-11 · A token in a query string is copied into every log that touches the request: the app's log, the CDN's, the pro…</sub>
- [ ] **`D20-016`** Crash reporter shipping the log buffer, breadcrumbs and custom keys off-device  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · AM-08 (the SDK's own backend is no · This is the item that converts a P5 logcat observation into a reportable disclosure: the log line no longer re…</sub>
- [ ] **`D20-017`** Crash reporter capturing a view hierarchy or screenshot of a `FLAG_SECURE` screen  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — ` · AM-08 · The inversion worth knowing: **`FLAG_SECURE` does not stop an in-process capture.** It excludes the window fro…</sub>

**⬜ Support ceiling**

- [ ] **`D20-018`** Session-replay / heatmap SDK recording payment, KYC and OTP screens unmasked  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — H` · AM-08 · Replay SDKs record the view hierarchy or the rendered frames. Masking is **opt-in per view**, so the default s…</sub>
- [ ] **`D20-019`** Per-SDK egress attribution — which class opened the socket  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-08 · "The app talks to eleven hosts" is an inventory. "This analytics SDK sent this user's email and precise locati…</sub>

**🟧 High ceiling**

- [ ] **`D20-020`** The consent-off differential — identical traffic with every toggle off  
   <sub>``privacy_concerns.unnecessary_data_collection` (null; the only concrete child,` · AM-08 · The single most convincing privacy test, and it takes two captures. Run one identical flow with every consent …</sub>
- [ ] **`D20-021`** Pre-consent transmission — data leaving before the dialog is dismissed  
   <sub>``privacy_concerns.unnecessary_data_collection` (null); `sensitive_data_exposur` · AM-08 · Pre-consent transmission is the step that converts a hygiene note into a reportable finding — the app has not …</sub>

**⬜ Support ceiling**

- [ ] **`D20-022`** `AppOpsManager.OnOpNotedCallback` — make the app confess its own private-data reads  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · n/a — instrumentation that produce · The platform will tell you which code read the user's private data — including code inside bundled SDKs — with…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-023`** Attribution-tag mismatch — the Privacy Dashboard shows the wrong reason  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · n/a — transparency defect · Attribution tags feed the system's access records, which the user sees in the Privacy Dashboard. An app that p…</sub>

**⬜ Support ceiling**

- [ ] **`D20-024`** Archived or encrypted telemetry batches — hook the pre-compression boundary  
   <sub>`rate on what the decoded payload contains` · n/a — instrumentation · When a telemetry batch is gzipped, protobuf-encoded or encrypted before upload, the proxy shows you an opaque …</sub>
- [ ] **`D20-025`** Undeclared PII on the wire versus the Play Data safety declaration  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-08 (a third-party recipient) —  · The evaluation is a compliance **delta**, not a judgement: capture decrypted traffic while entering the marker…</sub>
- [ ] **`D20-026`** PII placed in URL query parameters, and the referer consequence  
   <sub>``sensitive_data_exposure.sensitive_token_in_url.user_facing` (P4), `…on_passwo` · AM-08 / AM-09 · A value in a query string is copied into CDN logs, proxy logs, WebView history and — if the URL is loaded in a…</sub>
- [ ] **`D20-027`** Fat profile endpoints returning fields the app never renders  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); a` · AM-05 (own account, own token — th · The mobile client displays three fields; the API returns forty — including recovery codes, internal flags, mod…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-028`** Authenticated responses cacheable, and cached on disk  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); t` · AM-05 (a shared device), AM-04 whe · Two halves. Server side: does a PII-bearing response carry `Cache-Control: no-store`? Client side: does the ap…</sub>

**🟧 High ceiling**

- [ ] **`D20-029`** Contacts and calendar harvesting on the invite / find-friends flow  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — ` · AM-08; the data subjects are peopl · Four questions, each a different finding: (a) is the **whole** address book uploaded or only the contact the u…</sub>

**⬜ Support ceiling**

- [ ] **`D20-030`** Lock-screen notification content — visibility, channel override, and `setPublicVersion`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · **AM-10** physical locked — the ra · Three settings interact and developers get the precedence wrong. `VISIBILITY_PUBLIC` shows full content on the…</sub>
- [ ] **`D20-031`** `NotificationListenerService` reading `Notification.extras` — build the PoC listener  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · **AM-04** — notification access is · Lock-screen visibility settings are irrelevant here: a listener reads `Notification.extras` regardless, includ…</sub>

**🟧 High ceiling**

- [ ] **`D20-032`** Android 15 OTP redaction for listeners, and the apps that route around it  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (**P3**)` · AM-04 · Android 15 redacts OTP content from untrusted listeners, with a carve-out for trusted companion-device associa…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-033`** Notification history retains the content after dismissal  
   <sub>``insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null);` · AM-11 physical unlocked, AM-05 sha · Dismissing a notification does not remove it. Android 11's notification history keeps recent notifications in …</sub>

**⬜ Support ceiling**

- [ ] **`D20-034`** Notification content during screen sharing, and the default-recorder exemption  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · AM-02 (a remote party on a support · Android 15 hides notification content during screen sharing and lets the app supply an alternative via `setPub…</sub>

**🟧 High ceiling**

- [ ] **`D20-035`** `RemoteInput` / Direct Reply actions exposed on a sensitive notification  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null = rated on what` · AM-04 (notification access) · A notification listener does not only read — it can **fire** a notification's actions and fill a `RemoteInput`…</sub>

**⬜ Support ceiling**

- [ ] **`D20-036`** The screen-capture consumer inventory — decide who can capture before testing whether they can  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5) is the trap node; the esca` · AM-04 (MediaProjection or accessib · "No `FLAG_SECURE`" is P5 (`screen_caching_enabled`) and Bugcrowd's own remediation text calls the fix "a best …</sub>
- [ ] **`D20-037`** `MediaProjection` per-session consent (Android 14) and the fallbacks apps chose instead  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 for a third-party capturer;  · From targetSdk 34 an app can no longer cache the projection consent `Intent` and silently re-capture. Two dire…</sub>

**🟧 High ceiling**

- [ ] **`D20-038`** `setContentSensitivity` / screen-share protection unused on payment and PIN views  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-02 (the remote viewer in a supp · Android 15 hides sensitive password input and OTP-bearing notification content from remote viewers, and lets a…</sub>

**⬜ Support ceiling**

- [ ] **`D20-039`** Screenshot and screen-recording detection callbacks available but unused  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5) for the capture itself; th` · AM-04 / AM-11 · For an app whose threat model includes remote-access-trojan scams — banking, crypto, brokerage — the absence o…</sub>

**🟩 Low ceiling**

- [ ] **`D20-040`** Recents snapshot and the `FLAG_SECURE` family — the privacy framing that changes the rating  
   <sub>``insecure_data_storage.screen_caching_enabled` (**P5**)` · AM-11 / AM-05 · Run D04-042/043/044 once, then bring the result here and answer the only question that changes the rating: **w…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-041`** Framework single-surface rendering — one missing flag exposes the whole screen  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5); escalate on data class` · AM-04 / AM-11 · Native Android lets you protect a single activity. Flutter and Unity render every screen into one surface on o…</sub>
- [ ] **`D20-042`** `uiautomator dump` — the on-screen text an accessibility-capable consumer reads  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 (an enabled accessibility se · The underrated check. A screenshot proves a human can read the screen; a `uiautomator` dump proves a **program…</sub>

**⬜ Support ceiling**

- [ ] **`D20-043`** Sensitive value copied to the clipboard without `EXTRA_IS_SENSITIVE`  
   <sub>``mobile_security_misconfiguration.clipboard_enabled` (**P5**). The VRT changel` · AM-04 (the default IME's clipboard · "Copy" buttons on account numbers, IBANs, card numbers, recovery phrases, OTPs and API tokens. Without the sen…</sub>
- [ ] **`D20-044`** Prove the cross-app clipboard read from a different UID — and state the mitigations honestly  
   <sub>``mobile_security_misconfiguration.clipboard_enabled` (**P5**); `external_behav` · AM-04 — a **foreground** app, or t · The claim that carries weight is "a *different* application read this value", demonstrated from a different UI…</sub>
- [ ] **`D20-045`** Clipboard READ by the app, and the paste-validation direction  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) fo` · For the read: the app itself as AM · Two directions nobody runs together. (a) Does the app read the clipboard on resume and ship what it finds — of…</sub>
- [ ] **`D20-046`** Keyboard cache on sensitive fields, and `IME_FLAG_NO_PERSONALIZED_LEARNING`  
   <sub>``external_behavior.browser_feature.autocorrect_enabled` (P5), `…autocomplete_e` · AM-04 (the IME), AM-05 (a shared d · A field that is not a non-caching input type has its contents learned by the IME dictionary and re-offered as …</sub>
- [ ] **`D20-047`** The third-party IME as a single-grant attacker against unmarked fields  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · **AM-04** — being the default IME  · An IME sees every keystroke in every app, including apps with no WebView at all. The app's only defences are m…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-048`** Autofill `AssistStructure` exposure — `importantForAutofill` and `setDataIsSensitive`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 — the user enabling a third- · An enabled `AutofillService` receives an `AssistStructure` — the **full view hierarchy of the foreground app**…</sub>

**⬜ Support ceiling**

- [ ] **`D20-049`** Credential and OTP fields rendered in plain text  
   <sub>``external_behavior.browser_feature.plaintext_password_field` (**P5**)` · AM-11 (shoulder surfing), and it m · Access codes and verification codes must be masked: in XML `android:inputType="textPassword"`; in Compose `Sec…</sub>
- [ ] **`D20-050`** Accessibility node text exposing secrets, and `accessibilityDataSensitive`  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); w` · **AM-04** — an enabled accessibili · A service declaring `android:canRetrieveWindowContent="true"` reads `AccessibilityNodeInfo.text` across the wh…</sub>
- [ ] **`D20-051`** App-side defences against an untrusted accessibility service or an active overlay  
   <sub>`no VRT node for the missing control; file the demonstrated capture under `sens` · AM-04 · The platform-level abuse of accessibility is a device-compromise scenario, not an app bug. The *app-side* find…</sub>
- [ ] **`D20-052`** Non-resettable hardware identifiers — IMEI, MEID, ESN, IMSI, build/SIM/USB serials  
   <sub>``privacy_concerns.unnecessary_data_collection` (null); if it becomes an auth f` · AM-08 (the recipient); AM-03 on an · Their presence in modern code means one of three things and you must say which: a legacy path that now returns…</sub>

**🟨 Medium ceiling**

- [ ] **`D20-053`** `ANDROID_ID` / SSAID and advertising-ID linkage to a persistent identity  
   <sub>``privacy_concerns.unnecessary_data_collection` (null); a resettable advertisin` · AM-08 · The reportable shape is not "the app collects an advertising ID" — that is expected. It is (a) the advertising…</sub>

**⬜ Support ceiling**

- [ ] **`D20-054`** Hardware MAC recovery through `/sys`, native code, or an OEM hook  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · AM-08; AM-03 on an OEM build · MAC randomisation removed a stable identifier deliberately. An app that recovers the **hardware** MAC — throug…</sub>
- [ ] **`D20-055`** High-rate motion sensors as an inference channel  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · AM-08 · An app holding `HIGH_SAMPLING_RATE_SENSORS` without a stated high-rate use case (fitness tracking, a game cont…</sub>

**🟩 Low ceiling**

- [ ] **`D20-056`** Installed-package enumeration as a fingerprinting surface  
   <sub>``privacy_concerns.unnecessary_data_collection` (null) — and see the Graveyard:` · AM-08 · The installed-app list is a high-entropy, stable fingerprint. The finding is not "the app can enumerate packag…</sub>

**🟧 High ceiling**

- [ ] **`D20-057`** The identifier that *is* the authentication factor — the one that escapes a privacy rating  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (**P1**) ` · AM-03 (any local app that can read · The inversion that pays. If `ANDROID_ID`, the advertising ID, the serial, a MAC or an installation id is used …</sub>

**🟨 Medium ceiling**

- [ ] **`D20-058`** EXIF geolocation not stripped — and the only variant with a rated VRT node  
   <sub>``sensitive_data_exposure.exif_geolocation_data_not_stripped_from_uploaded_imag` · **AM-05** — another signed-in user · The self-directed finding — "my own photo keeps its GPS" — is discounted everywhere. The payable variant is cr…</sub>

**⬜ Support ceiling**

- [ ] **`D20-059`** Photo-picker versus full media grant — metadata for images the user never selected  
   <sub>``privacy_concerns.unnecessary_data_collection` (null); `sensitive_data_exposur` · AM-08 · An app that asks for the full media permission when the photo picker would do gains read access to the whole g…</sub>
- [ ] **`D20-060`** Data surviving logout and account switch  
   <sub>``insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null, ` · **AM-05** — another user of the sa · Log out, then diff. The question is not "is anything left" (something always is) but "is what is left either a…</sub>
- [ ] **`D20-061`** Account deletion that does not actually delete  
   <sub>``insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null);` · AM-05 / AM-11 for the device side; · Delete the account, then check both ends. Server side: does `GET /me` 404, does the user still appear in searc…</sub>

**🟧 High ceiling**

- [ ] **`D20-062`** Deletion that does not revoke tokens, push registrations or third-party grants  
   <sub>``broken_authentication_and_session_management.failure_to_invalidate_session.on` · AM-05 / whoever holds a previously · Deletion usually flips a flag on a row. Enumerate everything that was issued in the account's name and test ea…</sub>

**⬜ Support ceiling**

- [ ] **`D20-063`** Uninstall / reinstall residue and Auto Backup restore  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**); th` · AM-11 / AM-05 · Uninstall and reinstall, then see what returns and what was left behind. Two distinct findings: data that **re…</sub>
- [ ] **`D20-064`** Camera or microphone access not tied to a visible user action  
   <sub>``privacy_concerns.unnecessary_data_collection` (null); the recorded artefact f` · AM-08 / the app itself · `appops` records a last-access timestamp per operation. Compare that record against your own interaction log: …</sub>
- [ ] **`D20-065`** Concealment of collection — screen-off, muted device, invisible overlay  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · the app / an SDK inside it (AM-08) · Does the app suppress its own UI indications while collecting — a black or transparent overlay, a muted stream…</sub>

**🟧 High ceiling**

- [ ] **`D20-066`** A foreground service held purely to keep sensor or capture access alive  
   <sub>``privacy_concerns.unnecessary_data_collection` (null)` · the app / an SDK inside it · Android 9+ blocks background sensor access, so an app that wants continuous access keeps a foreground service …</sub>

**⬜ Support ceiling**

- [ ] **`D20-067`** Run the pre-severity gate against the Critical claim, not against the leak  
   <sub>`n/a — governance` · Write the draft Critical title first, then substitute the **Critical claim** — not the bug — into each questio…</sub>
- [ ] **`D20-068`** Retraction discipline, and the finding you must **not** retract  
   <sub>`n/a — governance` · Privacy findings are unusually prone to mid-engagement change: an SDK is remotely reconfigured, a feature flag…</sub>
- [ ] **`D20-069`** Chain-filing order for privacy primitives — file the primitive, then the consumer  
   <sub>`n/a — submission mechanics` · Almost everything in this chapter is a primitive whose severity comes from a consumer in another domain: the l…</sub>
- [ ] **`D20-070`** The five-screenshot pattern adapted to a data-leak PoC  
   <sub>`n/a — evidence` · A leak PoC needs the same five-shot discipline as a state change, remapped: (1) **pre-state** — the value insi…</sub>

<details><summary>⚰️ D20 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app writes to logcat" / `Log.d` calls present in the release build | `READ_LOGS` has been `signature\|privileged` since API 16 and API 30+ adds a consent dialog; Google's Mobile VRP excludes logging by name ("debugging privileges are required to access logs"). The mechanism has no rated node. | A **sensitive value** in the line, plus a named reader: a shipped package holding `READ_LOGS`, a debuggable build, or an SDK that forwards the buffer off-device (D20-008, D20-016). |
| Debug stack trace or verbose error in logcat | HackenProof: "Debug Logs / Stack Traces — unless they expose sensitive data like credentials or tokens". `StrictMode` output is a resilience artefact. | The trace containing a credential, an internal endpoint you can then reach, or a framework version with a working exploit (D20-013, D20-014). |
| Missing `FLAG_SECURE` / Recents thumbnail shows the screen | `insecure_data_storage.screen_caching_enabled` is **P5** outright and Bugcrowd's remediation text calls the fix "a best practice". A root read of `/data/system_ce/0/snapshots` is AM-12, which is not an attack. | A named consumer that captures it (a MediaProjection holder, an in-process SDK capture that `FLAG_SECURE` cannot stop, a remote screen-share viewer), plus a data class worth capturing (D20-017, D20-018, D20-037, D20-038). |
| "Clipboard is enabled" / a Copy button exists on a sensitive field | `mobile_security_misconfiguration.clipboard_enabled` is **P5**; the finer children `on_sensitive_content` / `on_non_sensitive_content` were **removed** and the parent pinned at P5 "due to children removal" — Bugcrowd will not entertain a sensitivity argument on category grounds. | A cross-app read demonstrated from a different UID in the foreground, of an OTP or recovery phrase, that persists in keyboard clipboard history after the app closes (D20-043, D20-044). |
| "A background app can read the clipboard" | Dead since **Android 10 (API 29)** — foreground or default-IME only, and Android 12 shows an access toast. Claiming it is a fast N/A. | Demonstrate the foreground or IME read, and describe the platform mitigation honestly (D20-044). |
| Keyboard cache / autocomplete enabled on a password field | `external_behavior.browser_feature.autocomplete_enabled` and `…autocorrect_enabled` are **P5**; "autocomplete on password fields" is on the never-submit list. | The cached value being a full PAN, password or recovery phrase, shown surfacing in a **different** app's suggestion strip (D20-046). |
| Password or token found in process memory | `external_behavior.user_password_persisted_in_memory` is **P5** and requires local code execution to reach. | Only as the second half of a chain whose first half is root, a debuggable build, or a native bug — and even then it raises another finding's impact rather than standing alone (see D11-066). |
| "The API returns more fields than necessary" | An explicitly named anti-pattern: field count is not a finding. | Name the field and why it is sensitive — recovery codes, a password hash, an auth token, another user's identifier (D20-027). |
| EXIF not stripped from my own uploaded photo | Basecamp lists it out of scope; HackenProof excludes image metadata "unless they expose sensitive user information"; Google requires location to be "combined with the ability to uniquely identify an individual". There is **no rated VRT node** without the user-enumeration qualifier. | Fetch the original as a **different** account, recover the GPS, and tie it to an identifiable person (D20-058). |
| The app collects an advertising ID | Expected and declared behaviour; H1 #803941 paid **$0**. | The advertising ID transmitted in the same payload as a persistent identifier, correlated across two third-party destinations, or sent after opt-out (D20-053). |
| The app can enumerate installed packages | Google Mobile VRP, Intended Behavior: *"the ability of an application to tell which versions of which apps are installed is intended functionality of the Android platform which we do not consider a vulnerability"*. | The list transmitted to a third party as a tracking signal, with `QUERY_ALL_PACKAGES` declared and no feature that needs it (D20-056). |
| My PoC app read the data — while holding the matching permission | Xiaomi excludes "any data leak because the malicious APP has acquired the appropriate permissions". A permission-holding PoC demonstrates the permission, not a flaw. | A **zero-permission** PoC obtaining the data, or a permission boundary being bypassed. State your PoC's permission set (ideally empty) in the report — triagers look for it. |
| Location data collected | "Location information alone does not qualify (unless combined with the ability to uniquely identify an individual)." | Location joined to an identity, or precise location broadcast to any installed app (H1 #185862, Twitter, is the shape). |
| "This violates GDPR / the privacy policy" | Intigriti's standard rejects *"functional bugs or process flaws resulting in compliance, privacy and governance issues that do not pose an immediate and exploitable threat"*. An argument is not evidence. | A captured payload showing a named data type reaching a named unauthorised recipient, with the declaration that omits it (D20-025). The regulation is the framing, never the finding. |
| Session not invalidated on logout (client side only) | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout_server_side_only` is **P5**; "session not invalidated on logout" is on the never-submit list. | The old token returning 200 with the victim's data after logout **or after account deletion** — which is D13's report, not this chapter's (D20-062). |
| `allowBackup="true"` in the manifest | `mobile_security_misconfiguration.auto_backup_allowed_by_default` is **P5**; H1 #1225158 (Zivver) paid **$0**. `adb backup` is LEGACY from API 31. | A restored device opening into an authenticated session, demonstrated through Auto Backup / device transfer, not `adb backup` (D20-063, D11-051 to D11-058). |
| A third-party SDK exists in the app | Presence is not collection. | A captured payload from that SDK's host carrying user data, attributed to the SDK by stack trace, and absent from the Data safety declaration (D20-019, D20-025). |

</details>


<details><summary>🔗 D20 cross-surface joins — park these, chase them in P7</summary>

- **Notification extras × the deep-link router (D20-031 × D09).** A `NotificationListenerService` reads the
  notification's `contentIntent` and its extras, then **replays the deep link itself** — often carrying a
  one-time token or an object id lifted straight out of the notification. Nobody reviews the notification
  payload and the URL router together, because one is a UI concern and the other is a routing concern.
  `adb shell dumpsys notification --noredact | grep -iE 'contentIntent|Intent\{'`, then
  `am start -a android.intent.action.VIEW -d '<the url you found>'` and see whether it yields authenticated
  content. Notification access — a single user toggle — becomes authenticated app access.
- **Session-replay or crash SDK × the app's own `FLAG_SECURE` policy (D20-017/D20-018 × D04-042).** The
  security team sets `FLAG_SECURE` on the card screen and signs it off; the growth team adds a replay SDK
  that captures the view hierarchy **in-process**, where `FLAG_SECURE` has no effect. The two changes are
  reviewed by different people and the join is invisible in either diff. Test by crashing on the secure
  screen with the proxy up, then carving any PNG out of the upload body.
- **Crash reporter × logcat (D20-016 × D20-008).** The logcat finding is P5 because nobody can read the
  buffer — until the crash SDK attaches the last N log lines to every report. One configuration flag
  converts an excluded-by-Google hygiene note into a cross-boundary disclosure with a named recipient. Grep
  for `enableLogcat` / `attachLogs` / breadcrumb configuration, then force a crash after the token appears.
- **EXIF × the user-search oracle (D20-058 × D15).** A listing photo's GPS is "a location". The same GPS,
  joined to a user-search endpoint that resolves a handle to a real name and phone, is "this named person's
  home address". Neither half is reportable alone; the join satisfies the VRT's *user enumeration* qualifier
  and reaches P3.
- **Accessibility readability × an unbound biometric gate (D20-050 × D13).** A service with
  `canRetrieveWindowContent` reads the transfer-confirmation screen, and with `canPerformGestures`
  dispatches the tap. If `BiometricPrompt` gates a boolean rather than a `CryptoObject` bound to the
  transaction, "the user must confirm with biometrics" becomes fully automatable. This is the mechanism of
  the current Android banking-trojan generation, and the two halves live in different chapters.
- **Backup restore × account deletion (D20-063 × D20-061).** The account is deleted server-side; the device
  transfer or cloud restore then re-materialises the local cache — messages, cached profile, KYC images — on
  a **new** device, after deletion. Nobody tests deletion and restore in the same pass because one is a
  server concern and the other a device concern.
- **Consent toggles × SDK-injected permissions (D20-020 × D03/D18).** A permission appears in the merged
  manifest that no app feature uses; the SDK that injected it also ignores the consent flag. Separately each
  is a shrug; together they are "the app requests a dangerous permission solely so a third party can collect
  under it, and the user's refusal changes nothing".
- **IME field marking × the deliberately non-password OTP field (D20-046/D20-047 × D13).** Apps make OTP and
  CVV fields plain numeric **on purpose**, so the digits are visible and paste works. That decision removes
  the IME's personalisation protection at the same time. The usability choice and the keyboard-learning
  consequence are never reviewed together.
- **Photo-picker scope × EXIF egress (D20-059 × D20-058).** A full `READ_MEDIA_IMAGES` grant plus an
  unstripped upload pipeline means the app can enumerate and ship metadata for images the user never chose.
  Either alone is Low; together it is bulk location history the user believes they never shared.
- **Shadow API × telemetry (D20-025 × D15/D01).** The mobile client's hardcoded analytics or profile
  endpoint is frequently an **older** API version than the web app uses — with weaker auth, weaker rate
  limits and **more field exposure**, which is precisely what makes it a privacy finding as well as an
  access-control one. Diff the two versions **behaviourally**, not by response shape: a version difference
  alone is Informational, the weakened control is the finding.
- **Lock-screen OTP × SIM-swap or device theft (D20-030 × D13).** A physical attacker holding a locked phone
  who can read the OTP from the keyguard does not need the password *and* the second factor — the second
  factor is on the screen. The notification setting and the account-recovery design are owned by different
  teams and never tested as one path.

</details>


---

## D21 Anti-Tampering, RASP, Root/Emulator Detection & Resilience

**Phase P4 · `M4` · 57 items** — 🟥 2 critical · 🟧 11 high · 🟨 3 medium · ⬜ 41 support  

📄 Full detail, with every command and proof: [`checklist/D21-resilience-and-rasp.md`](checklist/D21-resilience-and-rasp.md)

> **Crux question.** **Does any decision that matters get made off this device on the strength of something this device claimed — and if so, is that claim an opaque, server-verified, freshly-bound attestation, or a boolean the client chose?** If the honest answer is "the check only stops the device's own owner from seeing their own data", you have a P5 hardening observation, and the correct output is a ruled-out entry, not a report.

Mostly it does not, and the honest number is close to zero. Bugcrowd prices the entire
`lack_of_binary_hardening` family at **P5** with the baseline vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
— an all-None impact, which is Bugcrowd stating in machine-readable form that these are not
vulnerabilities. HackerOne's Core Ineligible Findings list carries "Lack of jailbreak detection in mobile
apps" under *Optional security hardening steps / Missing best practices*. Google's Mobile VRP lists
"Attacks that require a rooted device" as non-qualifying and its Invalid Reports page is blunter still:
"Rooted devices and emulators do not have the same security boundaries as regular devices. Bugs that only
occur when a device is rooted are not eligible." Xiaomi, Grab and Spotify carry the identical line about
"runtime hacking exploits using tools like but not limited to Frida/Appmon". PayPal excludes
"vulnerabilities requiring a rooted, jailbroken, or otherwise modified device". HackenProof qualifies it
usefully — "Root/Jailbreak Detection Bypass — **if the app doesn't promise root/jailbreak protection
explicitly**" — and that qualifier is the whole exception. AOSP's own severity-modifier table caps it
independently of any programme: "a local attack that requires the bootloader chain to be unlocked" and
"a local attack that requires Developer Mode to be currently enabled" are both **no higher than Low**.
MASVS says the quiet part out loud: "the absence of any MAS-R measures does not inherently introduce
vulnerabilities."


**⬜ Support ceiling**

- [ ] **`D21-001`** Settle the engagement mode before writing a single resilience line  
   <sub>`n/a (governs whether every other item in this chapter is a deliverable or a wa` · The same observation is a paid contractual finding in a signed-SoW pentest and an auto-closed informative on a…</sub>
- [ ] **`D21-002`** The six-condition gate every root-required observation must pass before it is filed  
   <sub>`n/a (a filing gate)` · AM-12 on input; the gate's job is  · A root-required observation is reportable only if you can additionally demonstrate at least **one** of six con…</sub>
- [ ] **`D21-003`** Settle the integrity blocker in the RoE at Gate 1, and read the verdict the app actually gets  
   <sub>If the app hard-fails on a rooted or emulated device, the whole dynamic phase is blocked on day one. Treat tha…</sub>
- [ ] **`D21-004`** Inventory every defence before hooking one  
   <sub>Checks are scattered across an obfuscated utility class, a vendor SDK **and** a native library. Stubbing one o…</sub>
- [ ] **`D21-005`** Control or telemetry? Decide it by running the app, not by reading the code  
   <sub>Most commercial RASP SDKs *report* signals to a backend and never block anything. A signal that reaches analyt…</sub>
- [ ] **`D21-006`** The attestation consumption fork: does an opaque token actually reach the server?  
   <sub>One observation splits this domain in half. Either the app forwards an **opaque token** that the backend decry…</sub>
- [ ] **`D21-007`** Distinguish "the app detected you" from "your hook was wrong"  
   <sub>When the app exits or degrades under instrumentation there are two explanations, and testers routinely write u…</sub>
- [ ] **`D21-008`** Detection that only runs at process spawn  
   <sub>``lack_of_binary_hardening\` · AM-12 — i.e. not an attacker · Many checks execute only during spawn or `Application.onCreate()`. Spawn-time injection (`-f`) and gadget buil…</sub>
- [ ] **`D21-009`** Enumerate which Frida fingerprints the app greps for, then defeat exactly those  
   <sub>``lack_of_binary_hardening\` · AM-12 · Anti-Frida detection is a fixed list of artefacts. Enumerate the list from the binary rather than guessing, so…</sub>
- [ ] **`D21-010`** Re-derive every finding on a stock device before writing it up  
   <sub>`n/a (payout precondition)` · converts AM-12 to AM-01/AM-03 · Keep two devices: a rooted analysis device and a stock verification device. Every candidate finding is re-run …</sub>
- [ ] **`D21-011`** State every precondition the PoC needed, including the ones that lower your severity  
   <sub>Omitting a precondition inflates severity and gets the whole report downgraded when the triager finds it. List…</sub>
- [ ] **`D21-012`** Apply the body-diff and layer-ordering gates to every "I stripped the token and got 200"  
   <sub>Three false positives dominate this domain's payable half, and all three look like a bypass. Run the controls …</sub>
- [ ] **`D21-013`** The server makes a security decision on a client-asserted integrity boolean  
   <sub>``broken_access_control\` · AM-01 — any client can make the cl · This is the payable form of root detection, and it has nothing to do with the detection. Find every request wh…</sub>

**🟧 High ceiling**

- [ ] **`D21-014`** The integrity verdict is decoded and branched on inside the app  
   <sub>``broken_access_control\` · AM-01 (the consequence); AM-12 for · Play Integrity tokens can be decrypted on Google's servers or on the app's server. Decrypting **in the app** p…</sub>
- [ ] **`D21-015`** Classic request with no server-generated nonce — one captured token, replayed forever  
   <sub>``broken_access_control\` · AM-01 · The reportable bug is not that a verdict can be spoofed on a rooted device — it is the **integration**. A back…</sub>
- [ ] **`D21-016`** `requestHash` not bound to the request body — token relay from a clean device  
   <sub>``broken_access_control\` · AM-01 · Standard requests have Google-side replay mitigation, so testers assume binding is handled. It is not: if the …</sub>
- [ ] **`D21-017`** Freshness not enforced — `timestampMillis` ignored, or verdicts cached  
   <sub>``broken_access_control\` · AM-01 · Even a correctly-nonce-bound integration fails if the backend never checks how old the token is, or if the cli…</sub>

**⬜ Support ceiling**

- [ ] **`D21-018`** Verdict tier collapse — `MEETS_BASIC_INTEGRITY` or `MEETS_VIRTUAL_INTEGRITY` accepted as "passed"  
   <sub>``broken_access_control\` · AM-01 (an emulator farm is a remot · These labels are not equivalent and the backend's tier logic frequently collapses them into a single "passed" …</sub>
- [ ] **`D21-019`** App-identity fields in the verdict never checked — `appRecognitionVerdict`, `appLicensingVerdict`, `requestPackageName`  
   <sub>``broken_access_control\` · AM-01 · A backend that checks only `deviceIntegrity` accepts a token from a **modified** build of the app on a perfect…</sub>

**🟧 High ceiling**

- [ ] **`D21-020`** The integrity error branch fails open  
   <sub>``broken_access_control\` · AM-01 (anyone can induce the error · The API has documented local error conditions and a daily quota. An app whose failure listener logs and contin…</sub>
- [ ] **`D21-021`** SafetyNet Attestation still shipped — the gate has been unconditionally open since January 2025  
   <sub>``broken_access_control\` · AM-01 · SafetyNet Attestation was fully turned down. The `attest` API now *always* invokes the failure listener. An ap…</sub>

**🟨 Medium ceiling**

- [ ] **`D21-022`** PII placed in `nonce` or `requestHash`  
   <sub>``sensitive_data_exposure\` · AM-09 / third-party processor expo · Apps routinely stuff a user id, an email address or a session token straight into the nonce. The documentation…</sub>

**⬜ Support ceiling**

- [ ] **`D21-023`** `appAccessRiskVerdict` / `playProtectVerdict` requested but never enforced  
   <sub>``mobile_security_misconfiguration\` · AM-04 (a local app holding one com · These opt-in verdicts exist precisely to detect screen-capturing, overlaying and device-controlling apps. Team…</sub>

**🟨 Medium ceiling**

- [ ] **`D21-024`** `deviceRecall` / `recentDeviceActivity` in use — a reset-resistant identifier  
   <sub>``sensitive_data_exposure\` · n/a (privacy/compliance, not an at · `deviceRecall` lets a developer store custom per-device data on Google's servers that **survives app reinstall…</sub>

**⬜ Support ceiling**

- [ ] **`D21-025`** Firebase App Check absent, monitoring-only, or shipping the debug provider  
   <sub>``broken_access_control\` · AM-01 · App Check is the control that makes "only our app may call this backend" true. Without it, every Firestore/RTD…</sub>

**🟧 High ceiling**

- [ ] **`D21-026`** Hardware key attestation checked on the device, or a boolean sent instead of the chain  
   <sub>``broken_access_control\` · AM-01 · Attestation checked on the device is worthless: a compromised OS controls the checker. The DER-encoded certifi…</sub>

**🟥 Critical ceiling**

- [ ] **`D21-027`** Attestation extension parsed from the leaf instead of the first occurrence nearest the root  
   <sub>``cryptographic_weakness\` · AM-01 · If the server verifies the chain but reads `KeyDescription` from the **leaf**, an attacker who can mint a leaf…</sub>

**⬜ Support ceiling**

- [ ] **`D21-028`** `attestationChallenge` not bound to a fresh server nonce — the chain replays  
   <sub>``broken_authentication_and_session_management\` · AM-01 · `setAttestationChallenge()` must carry a fresh, server-issued, single-use value. A constant, a client-generate…</sub>

**🟧 High ceiling**

- [ ] **`D21-029`** `RootOfTrust` present in the attestation and ignored by the backend  
   <sub>``broken_access_control\` · AM-01 · A verified attestation *carries* the boot state. The common defect is a backend that validates the chain corre…</sub>
- [ ] **`D21-030`** `attestationSecurityLevel` and revocation not checked — a Software root is accepted  
   <sub>``cryptographic_weakness\` · AM-01 · Two checks are commonly missing: the security level (a *software* attestation chain is generable on any emulat…</sub>
- [ ] **`D21-031`** Hardware attestation treated as a device-integrity boolean — the clean-device relay  
   <sub>``broken_access_control\` · AM-01 (the attacker runs the modif · OID `1.3.6.1.4.1.11129.2.1.17` proves that *some* acceptable TEE or StrongBox generated the leaf key for `atte…</sub>

**⬜ Support ceiling**

- [ ] **`D21-032`** Verified Boot state read from a system property instead of from attestation  
   <sub>``broken_access_control\` · AM-01 for the consequence · An app reading `ro.boot.verifiedbootstate` or `ro.boot.flash.locked` to decide device integrity is asking the …</sub>
- [ ] **`D21-033`** Root/emulator/Frida detection that gates a security decision — rate what the bypass unlocked  
   <sub>``lack_of_binary_hardening\` · AM-12 for the bypass — which is wh · Locate the check, establish **what it gates**, bypass it, then demonstrate the delta in the thing it gated. If…</sub>
- [ ] **`D21-034`** Detection that fails open — make it throw rather than bypassing it  
   <sub>``broken_access_control\` · AM-12 for the mechanism; AM-01 whe · This is a different, better test than bypassing. Detection routines wrapped in a broad `try/catch` that swallo…</sub>

**🟨 Medium ceiling**

- [ ] **`D21-035`** Detection verdict cached in a backed-up, attacker-writable file  
   <sub>``broken_access_control\` · AM-11 physical unlocked / AM-03 wh · A detection result cached in SharedPreferences (`"is_rooted":false`, `"integrity_ok":true`, `"tamper_strikes":…</sub>

**⬜ Support ceiling**

- [ ] **`D21-036`** Security-relevant local state consumed without an integrity check  
   <sub>``broken_access_control\` · AM-11 / AM-12 locally; AM-01 once  · The R-profile test that produces genuine findings, because its failure condition is behavioural rather than "m…</sub>
- [ ] **`D21-037`** Self-signature / installer check that neither fails closed nor covers what executes  
   <sub>``lack_of_binary_hardening\` · AM-12 · Apps that check their own signature at runtime read `PackageManager` data that an instrumented process control…</sub>
- [ ] **`D21-038`** RASP initialised after an attacker-controlled library is already mapped  
   <sub>``broken_access_control\` · AM-03/AM-08 where the writable pat · Ordering matters. If any attacker-writable `.so`, DEX or reference hash resolves *before* the integrity check …</sub>
- [ ] **`D21-039`** Destructive or lockout tamper response that an attacker can trigger  
   <sub>``application_level_denial_of_service_dos\` · AM-03 zero-permission local app wh · Nobody checks this, and it is the one item in the chapter with a Critical ceiling. Does the app's tamper respo…</sub>
- [ ] **`D21-040`** The app weakens the device's or the user's own security posture  
   <sub>``broken_access_control\` · AM-02 remote one click (the user i · The inverse of the rest of this chapter. Does the app *reduce* a platform protection to make itself work — dis…</sub>
- [ ] **`D21-041`** App-level virtualization / cloning not detected — the sandbox has already collapsed  
   <sub>``broken_access_control\` · AM-02 (the user installs the conta · Container and cloning frameworks run the target inside a host process. Where the guest executes under the host…</sub>
- [ ] **`D21-042`** MitM-detection that reads only the legacy CA path, blind to the Conscrypt APEX  
   <sub>``broken_access_control\` · AM-07 for the mechanism (tester co · RASP implementations commonly detect "MITM in progress" by hashing `/system/etc/security/cacerts`. On Android …</sub>
- [ ] **`D21-043`** The RASP SDK's own native component is the vulnerable dependency  
   <sub>``using_components_with_known_vulnerabilities\` · AM-08 malicious third-party SDK /  · Security SDKs are dependencies too. Fingerprint the RASP vendor's `.so` and check whether the protection layer…</sub>
- [ ] **`D21-044`** The SDK gates its own behaviour on proxy/VPN/debugger — your evidence is being suppressed  
   <sub>Before concluding "the SDK does nothing interesting", verify the SDK is not gating on your presence. A compone…</sub>
- [ ] **`D21-045`** Hook detection absent — extract the secret and report the secret  
   <sub>``lack_of_binary_hardening\` · AM-12 for the extraction; the find · Hook the APIs that handle secrets. If the hooks fire and return data, the app has no runtime integrity verific…</sub>
- [ ] **`D21-046`** Debugger detection absent, or present only in debug variants  
   <sub>``lack_of_binary_hardening\` · AM-11 physical unlocked with USB d · Confirm whether debugging detection exists **and executes in release**, then attach. The frequent defect is a …</sub>

**🟥 Critical ceiling**

- [ ] **`D21-047`** `android:debuggable="true"` in the release build — the resilience story collapses entirely  
   <sub>``broken_authentication_and_session_management\` · AM-11 physical unlocked with USB a · If the shipped build is debuggable, every RASP control is bypassable without root, without Frida and without a…</sub>

**🟧 High ceiling**

- [ ] **`D21-048`** `setWebContentsDebuggingEnabled(true)` in production  
   <sub>``broken_authentication_and_session_management\` · AM-11 physical unlocked with USB/a · This exposes the app's WebViews to Chrome DevTools over the adb socket — full DOM and JS access to authenticat…</sub>

**⬜ Support ceiling**

- [ ] **`D21-049`** Debug, staging and god-mode surfaces surviving into the release build  
   <sub>``broken_authentication_and_session_management\` · AM-03 zero-permission local app wh · Debug activities, staging endpoints, feature-flag overrides, "god mode" switches and test accounts left in the…</sub>
- [ ] **`D21-050`** `StrictMode` left enabled in the production build  
   <sub>``lack_of_binary_hardening\` · AM-11 · "Leaving `StrictMode` enabled can expose sensitive implementation details in the logs." The finding, if there …</sub>
- [ ] **`D21-051`** Insufficient obfuscation — report the recovered business rule, never the absence  
   <sub>``lack_of_binary_hardening\` · AM-01 (anyone can download the APK · Decompile and determine whether security-relevant logic can be located and understood with reasonable effort. …</sub>
- [ ] **`D21-052`** Partial obfuscation that leaves the security-critical routines in the clear  
   <sub>``lack_of_binary_hardening\` · AM-01 · "Not obfuscated" is informational. The sharper version is a *partially* obfuscated build where the key derivat…</sub>
- [ ] **`D21-053`** A client-side-only policy engine that the server trusts  
   <sub>``broken_access_control\` · AM-01 · The generalisation that catches what the integrity items miss: **any** decision the app makes locally — transa…</sub>
- [ ] **`D21-054`** The shadow API version that never enforced the integrity gate  
   <sub>``broken_authentication_and_session_management\` · AM-01 · The highest-value mobile-to-backend bridge, and it belongs in this chapter because the attestation and rate-li…</sub>
- [ ] **`D21-055`** Emulator detection absent — the finding is the automation, not the absence  
   <sub>``lack_of_binary_hardening\` · AM-01 (an emulator farm is a remot · Hook and trace the common emulator checks while running on an emulator. The observation is Informational; the …</sub>
- [ ] **`D21-056`** Compat-framework and `device_config` toggles — prove the protection is per-package switchable  
   <sub>AM-11 (shell access on the user's  · The Android compatibility framework enables and disables individual behaviour changes **per package** from the…</sub>
- [ ] **`D21-057`** Evidence, retraction and filing discipline for a domain that triagers distrust  
   <sub>Resilience-adjacent findings arrive at triage with a presumption against them, so the evidence and the filing …</sub>

<details><summary>⚰️ D21 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Root detection is missing" | `lack_of_binary_hardening\|lack_of_jailbreak_detection` = **P5** with an all-zero CVSS impact vector. HackerOne Core Ineligible lists it under "Optional security hardening steps / Missing best practices" | Nothing about the absence. Only what the rooted session reached, re-derived on a stock device or through a stock-reachable path (D21-002, D21-010) |
| "Root detection is bypassable" | Same node, same P5. Every major programme excludes it: Google Mobile VRP "Attacks that require a rooted device", Xiaomi/Grab/Spotify "runtime hacking exploits using tools like Frida/Appmon", PayPal, Basecamp, Snapchat, Reddit, HackenProof, YesWeHack Gojek "Lack of binary protection / jailbreak and root detection / anti-debugging controls" | The **server** honouring the client's verdict (D21-013), or the specific control the bypass unlocked, filed under that control's domain (D21-033) |
| "Frida can attach / the app has no hook detection" | `lack_of_binary_hardening\|runtime_instrumentation_based` = **P5**. AM-12 is not an attacker model | The credential the hook extracted, proved to authenticate other users or off the device (D21-045 + D21-002 condition 6) |
| "The APK can be repackaged and re-signed" | HackenProof "Lack of obfuscation or repackaging protections"; Grab/Spotify/Starbucks/Xiaomi "Lack of binary protection control". The repackaged app attacks only its own installer | A distribution channel you can poison so the repackaged build reaches **other** users — that is D17, not D21 |
| "The app is not obfuscated" | `lack_of_binary_hardening\|lack_of_obfuscation` = **P5**; MASVS: "the absence of any MAS-R measures does not inherently introduce vulnerabilities" | The business rule you read out of the decompile — a fraud threshold, a velocity limit, an allowlist of privileged account ids (D21-051) |
| "Emulator detection is missing" | P5, and an emulator is not a security boundary. Google Invalid Reports: "Rooted devices and emulators do not have the same security boundaries as regular devices" | The backend accepting `MEETS_VIRTUAL_INTEGRITY` where its own policy requires device integrity (D21-018), with the abuse rate quantified |
| "Debugger detection is missing" | P5 standalone, and attaching needs USB debugging plus an unlocked device | What the attached debugger extracted or modified (D21-046), or `android:debuggable="true"` on the store build, which is a different item entirely (D21-047) |
| "I bypassed the app's RASP with objection/Frida in five minutes" | A statement about your tooling. AOSP's own modifier table caps anything needing an unlocked bootloader or Developer Mode at **no higher than Low** | Nothing. Report what you reached afterwards, on a stock device where possible |
| "Play Integrity can be defeated with Magisk + TrickyStore + a keybox" | This spoofs attestation *inputs*; Google's backend signature verification still succeeds because the JWT is genuine. It is an operator capability, not an app vulnerability — and abused keyboxes get revoked | The backend accepting a **replayed** or **relayed** token (D21-015, D21-016), or accepting one with no freshness or nonce binding — none of which needs a keybox |
| "The app's root check can be defeated, and it uses Play Integrity" | If the verdict is server-verified, no local hook forges it. Stop and re-scope to server-side testing rather than burning hours on Frida | The server accepting requests that carry **no** integrity verdict at all, or carrying one bound to nothing (D21-006 routes you) |
| "Production images cannot be rooted / `adb root` is denied" | `adbd cannot run as root in production builds` is a platform property of `user` builds, not an app finding | Nothing. It is a harness fact; record it in the methodology |
| "The app stores a token in internal storage and root can read it" | `insecure_data_storage\|sensitive_application_data_stored_unencrypted\|on_internal_storage` = **P5**; the sandbox holds against every attacker except the device owner | The token authenticating a **different** account from your own machine, or a non-root path to the same bytes (backup, exported provider, debuggable build) |
| "The app does not use Play Integrity at all" | MASWE-0054/-0056 are hardening gaps. An app is not obliged to attest | Only in a MAS-R-scoped SoW engagement (D21-001), where it is a contractual finding, not a vulnerability |
| "`StrictMode` violations appear in logcat" | Debug artefact; since Android 4.1 no ordinary app reads another app's log | A violation line that itself carries a token, a private path revealing an unreleased feature, or a reader you can name (a log-uploading SDK, a crash reporter, a debuggable build) |
| "A RASP telemetry beacon fires when I attach Frida" | The SDK reporting a signal is working as designed. Telemetry is not a control | The beacon's *absence* changing a server decision — i.e. the backend gating on a signal a modified client simply never sends (D21-005 -> D21-013) |
| "The app runs on my rooted phone and I can see my own data" | AM-12. You are the device owner attacking yourself | Any one of the six conditions in D21-002, with its artefact |
| "The tamper response logs the user out" | A non-destructive response is the app behaving correctly | The response wiping data, locking the account or bricking the session **and** a trigger another app can plant (D21-039) |
| "`attestationSecurityLevel: Software` on my test device" | On a standard AVD the Keystore is software-backed and the chain terminates in Google's Software attestation root — an artefact of the harness | The same observation reproduced on a **physical** device, or the server accepting a software-rooted chain for a hardware-gated action (D21-030) |
| "The app asks for battery-optimisation exemption" | A functional request, not a security defect, on its own | A code path or on-screen instruction that disables Play Protect, relaxes SELinux, or talks the user through sideloading (D21-040) |
| "The obfuscated build took me two days to understand" | Effort is not a severity axis, and MASVS-RESILIENCE-3 is explicitly about raising cost, not preventing access | What you found at the end of the two days |

</details>


<details><summary>🔗 D21 cross-surface joins — park these, chase them in P7</summary>

- **Play Integrity verdict × the backend's *other* clients (D21-013/-015 × D15 × D21-054).** The mobile
  team wires attestation into the mobile client; the web client and the partner API call the same
  endpoints with no integrity header at all, because they cannot produce one. Nobody reviews the two
  together. Enumerate every endpoint that carries a token from the app, then call each one from `curl`
  with a valid session and no token — the endpoints that answer are the ones where the control was never
  a control. This is the single highest-yield join in the chapter, and it needs no device bypass.
- **Detection verdict × the backup set (D21-035 × D11 × D02).** The resilience reviewer tests whether the
  check can be hooked; the storage reviewer inventories `allowBackup` and shrugs because "it's only
  preferences". The join is the intersection: a cached `integrity_ok` or `tamper_strikes` value that is
  both consumed on next launch **and** in the backup set is a detection bypass with no instrumentation at
  all, at a far weaker attacker model than anything else in this domain.
- **Tamper-response trigger × shared-storage write (D21-039 × D07 × D11).** Two teams own the halves: the
  security team wrote a response that wipes data on detection, and the storage team allowed a path on
  shared storage that the check inspects. Neither is a finding alone. Together, any zero-permission app on
  the device destroys the client's users' data — the only Critical in this chapter, and it is found by
  grepping the detection code for `wipeData` and then asking who can write the path it looks at.
- **Obfuscation coverage × the fraud engine (D21-051 × D23).** The app-security reviewer rates
  obfuscation as P5 and moves on; the fraud team never sees the decompile. The join is to grep the
  decompiled output specifically for the fraud engine's constants — thresholds, velocity limits, amount
  bands, allowlisted account ids — because those are the values that turn a P5 hardening gap into a
  structuring attack with a number attached.
- **Attestation nonce × PII (D21-022 × D20).** The integrity integration and the privacy review never
  meet. The nonce is a security control to one team and an opaque blob to the other, and in between
  somebody put the user's email in it. One base64 decode answers it, and it is a disclosure to a third
  party outside the declared data flow.
- **App Check enforcement × Firebase rules (D21-025 × D18).** The Firebase rules reviewer argues "an
  attacker would need to be in the app"; the App Check console is owned by a different team and is set to
  monitoring-only. Read the two together and the "on-device only" mitigation in every Firestore finding
  evaporates — which changes those findings' attacker model from AM-12 to AM-01.
- **`android:debuggable` × the entire resilience budget (D21-047 × D02 × D14).** A debuggable release is
  usually filed as a hardening issue by whoever finds it in the manifest. Read it beside the RASP
  inventory and the NSC: it makes every detection routine bypassable via JDWP with no root, makes
  `<debug-overrides>` live, and makes `run-as` a data-extraction primitive. The client paid for a RASP SDK
  and shipped the key to it in the manifest.
- **Key-attestation chain × the session it is supposed to bind (D21-031 × D13).** The crypto reviewer
  validates the chain; the auth reviewer validates the session. Nobody asks whether the *same* hardware
  that produced the chain signs anything afterwards. If it does not, a chain generated on a clean phone
  binds nothing, and every "device-bound" claim in the product documentation is false.
- **SafetyNet remnant × App Check provider (D21-021 × D21-025 × D18).** An app can carry a dead
  `SafetyNetAppCheckProviderFactory` while the team believes App Check is enforcing. The dependency scan
  finds the library and calls it outdated; the backend team sees App Check enabled in the console.
  The join is that the provider has returned failures since January 2025 and nobody read the enforcement
  metrics.
- **RASP vendor `.so` × the dependency inventory (D21-043 × D16 × D17).** The SDK reviewer inventories
  analytics and ad libraries and treats the security SDK as a control rather than as a dependency. Its
  native component is the one nobody version-checks, and it is loaded first, in-process, on every launch.

</details>


---

## D22 Platform & OS Version-Specific Behaviour

**Phase P4 · `M4` · 82 items** — 🟥 8 critical · 🟧 37 high · 🟨 18 medium · 🟩 1 low · ⬜ 18 support  

📄 Full detail, with every command and proof: [`checklist/D22-platform-version-behaviour.md`](checklist/D22-platform-version-behaviour.md)

> **Crux question.** **For every candidate finding in this engagement: at which `minSdkVersion`, `targetSdkVersion` and device API level is it actually reachable — and has this app explicitly opted out of the platform hardening that would otherwise close it?**

It pays negatively, and that is worth more than it sounds. The single largest structural defect the
research corpus found in the public Android checklist literature is stated plainly by the
Indusface/hackwithsingh/riya78 review: **"None of the three sources gate any item by API level. That is
the single largest gap between these checklists and a usable 2026 methodology."** Every circulating
checklist still tells testers to report `MODE_WORLD_READABLE`, `adb backup` extraction, user-CA trust,
implicit component export, sticky broadcasts and the `addJavascriptInterface` reflection RCE as if the
platform had not closed each of them at a specific, knowable API level. A consultancy whose report is
compared against what independent hunters submit cannot afford to file any of those against a
targetSdk-35 app, and equally cannot afford to *drop* one against an app whose `minSdkVersion` is 24.


**⬜ Support ceiling**

- [ ] **`D22-001`** Pin the real min/target/compileSdk triplet from the installed package  
   <sub>`none — the gate that decides every other item's applicability` · AM-12 (own device; not an attack) · Read `minSdkVersion`, `targetSdkVersion` and `compileSdkVersion` from the **installed** APK set and from the p…</sub>
- [ ] **`D22-002`** Record the device's API level, build fingerprint, patch level and Mainline/SDK-extension versions  
   <sub>`none — evidence metadata` · AM-12 · Half the behaviour changes in Android 12-16 are *device-OS* gated rather than targetSdk gated (the Conscrypt t…</sub>
- [ ] **`D22-003`** Build the four-image version matrix and install the same build on each  
   <sub>`none — harness` · AM-12 · A single-device test produces false negatives in one direction and unreportable findings in the other. The min…</sub>
- [ ] **`D22-004`** Emit a mechanical LEGACY/CURRENT verdict for every candidate finding  
   <sub>`none — rating qualifier` · Take the candidate list produced by D03-D17 and mark each row CURRENT, LEGACY-live (the gate is open because t…</sub>
- [ ] **`D22-005`** Distinguish a platform block from an app-side check before writing any negative  
   <sub>`none — kill gate that prevents both a false negative and a false positive` · AM-03 · This is the Android edition of the layer-ordering trap. When your crafted intent, broadcast, zip entry or clas…</sub>
- [ ] **`D22-006`** Diff behaviour across API levels, never response shape  
   <sub>`none — evidence standard for every version-gated claim` · AM-03 · The shadow-API principle transfers exactly from the backend to the platform. An older API level, an older targ…</sub>
- [ ] **`D22-007`** Use `am compat` as the single-variable negative control  
   <sub>`none — evidence technique` · AM-12 · The compatibility framework flips an individual behaviour change on or off **per package** from the shell. Tha…</sub>
- [ ] **`D22-008`** Harvest the platform's own refusal strings as evidence artefacts  
   <sub>`none — evidence capture` · AM-12 · Each platform mitigation emits a distinctive log line. Collect them once per run; they are simultaneously your…</sub>
- [ ] **`D22-009`** Inject StrictMode detectors rather than waiting for the app to ship them  
   <sub>`none — discovery technique feeding D08/D04` · AM-12 · The platform ships runtime detectors for two of the classes this chapter gates. Inject them into a release bui…</sub>
- [ ] **`D22-010`** Verify package-visibility filtering has not silently zeroed your own tooling  
   <sub>`none — false-negative control` · AM-03 (the attacker app is subject · On a modern device your own PoC app, drozer agent or enumeration harness may be unable to *see* the target pac…</sub>

**🟧 High ceiling**

- [ ] **`D22-011`** `android:exported` is mandatory at targetSdk 31 — audit the value chosen, not its absence  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null — rated on what` · AM-03 · Since Android 12, a component carrying an `<intent-filter>` cannot install without an explicit `android:export…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-012`** PendingIntent mutability mandate made the flag explicit, not safe  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03 (holder of the PendingIntent · Android 12 forces an explicit `FLAG_IMMUTABLE` or `FLAG_MUTABLE`. It does not stop a developer choosing `FLAG_…</sub>

**🟧 High ceiling**

- [ ] **`D22-013`** `adb backup` excluded at targetSdk 31 — and the `android:debuggable` escape hatch  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-11 physical unlocked (USB debug · From targetSdk 31, `adb backup` returns nothing for the app **unless** the manifest carries `android:debuggabl…</sub>
- [ ] **`D22-014`** `<device-transfer>` omitted from `dataExtractionRules` — D2D transfers what cloud backup excludes  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-11 (attacker performing a "rest · Android 12 split backup into `<cloud-backup>` and `<device-transfer>` (with `<cross-platform-transfer>` added …</sub>
- [ ] **`D22-015`** Notification trampoline block (Android 12) and the redesign that replaced it  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · At targetSdk 31 a service or receiver used as a notification trampoline may no longer call `startActivity()`. …</sub>

**🟩 Low ceiling**

- [ ] **`D22-016`** Untrusted-touch blocking (Android 12) — check whether the app is the one being let through  
   <sub>``mobile_security_misconfiguration.tapjacking` (P5) — must chain to be reportab` · AM-04 (overlay app holding `SYSTEM · Android 12 drops touches that pass through another UID's overlay window above the documented opacity threshold…</sub>

**🟧 High ceiling**

- [ ] **`D22-017`** BouncyCastle removed in Android 12 — find the bundled provider re-registered at priority 1  
   <sub>``cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` (P5)` · AM-08 / AM-09 (whoever can obtain  · Android 12 removed the BouncyCastle implementations in favour of Conscrypt, which rejected three things apps w…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-018`** App hibernation and permission auto-reset — a security control that decays  
   <sub>`none directly; rate on the control that stops working. `insufficient_security_` · AM-01 (time, not an actor) · The platform resets runtime permissions for unused apps and hibernates them. If the app builds a security func…</sub>
- [ ] **`D22-019`** POST_NOTIFICATIONS default-deny suppresses the app's only breach-alert channel  
   <sub>``insufficient_security_configurability.lack_of_notification_email` (P5) standa` · AM-04 (an app or a user action tha · On Android 13+ notifications are off by default for new installs. If the app delivers security-relevant events…</sub>
- [ ] **`D22-020`** Call-style and media-session exemptions used to post notifications the user declined  
   <sub>``broken_access_control.privilege_escalation` (null) — a permission decision ci` · AM-08 (an SDK that adds the scaffo · Call-style notifications are exempt from `POST_NOTIFICATIONS` when the app implements `MANAGE_OWN_CALLS` plus …</sub>

**🟧 High ceiling**

- [ ] **`D22-021`** Granular media permissions taken instead of the Photo Picker  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — r` · AM-05 / AM-09 (the app's own backe · The Photo Picker requires **no permission** and grants URI access to the selected items only. An app that inst…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-022`** `READ_MEDIA_VISUAL_USER_SELECTED` absent at targetSdk 34 — silent compatibility mode  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-05 · Android 14 Selected Photos Access applies to targetSdk 34+. An app that does not declare `READ_MEDIA_VISUAL_US…</sub>

**⬜ Support ceiling**

- [ ] **`D22-023`** Restricted Settings for sideloaded apps — state the gate or your severity is wrong  
   <sub>`none — a precondition that changes the rating of D13/D20/D21 findings` · AM-04 (the attacker app needs the  · Android 13+ blocks a sideloaded app from being granted an accessibility service or notification-listener acces…</sub>

**🟧 High ceiling**

- [ ] **`D22-024`** `android:sharedUserId` retained past API 32  
   <sub>``broken_access_control.privilege_escalation` (null); `insecure_os_firmware.sha` · AM-08 (compromise of the weakest m · Shared user ID is deprecated and the documented migration is `android:sharedUserMaxSdkVersion="32"` — which se…</sub>
- [ ] **`D22-025`** APK Signature Scheme v3.1 rotation targeting — two keys, two OS ranges  
   <sub>``broken_access_control.privilege_escalation` (null) when a signature-protected` · AM-03 on a pre-Android-13 device · Android 13 added v3.1, which lets a developer rotate signing keys **only for SDK versions at or above `--rotat…</sub>
- [ ] **`D22-026`** Keystore/KeyMint structured errors swallowed into a software fallback  
   <sub>``insecure_data_storage.sensitive_application_data_stored_unencrypted.on_intern` · AM-11 / AM-12 (recovering the key  · Android 13 added structured Keystore/KeyMint error reporting, including whether the failure is retryable. The …</sub>

**🟨 Medium ceiling**

- [ ] **`D22-027`** Foreground-service notifications dismissable and the high-priority FCM downgrade  
   <sub>`none directly — rate on the security function that stops running; `application` · AM-01 (the user, or time) · Two Android 13 changes break the same assumption. Users can dismiss FGS notifications and stop apps with ongoi…</sub>

**🟧 High ceiling**

- [ ] **`D22-028`** Foreground-service type mandate at targetSdk 34 as a capability map  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) when an unpriv` · AM-03 · From targetSdk 34 every foreground service must declare `android:foregroundServiceType`, and each type require…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-029`** `specialUse` and `systemExempted` foreground-service types claimed without a matching reality  
   <sub>``broken_access_control.privilege_escalation` (null)` · AM-08 · `specialUse` is the escape hatch of the FGS type system and requires a declared subtype string that Play revie…</sub>

**🟧 High ceiling**

- [ ] **`D22-030`** Context-registered receivers must declare an export flag at targetSdk 34  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Runtime-registered receivers never appear in the manifest, so manifest-only enumeration misses them entirely. …</sub>
- [ ] **`D22-031`** Implicit intents no longer reach internal components — find the export regression that "fixed" it  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · From targetSdk 34, implicit intents are delivered only to **exported** components, so an app's own `context.st…</sub>
- [ ] **`D22-032`** Mutable PendingIntent with `setPackage()` but no component — the targetSdk-34-compliant variant  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); P1 via D08 wh` · AM-03 · Android 14 made a blank-base mutable `PendingIntent` throw, and the check is satisfied by `setPackage(context.…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-033`** Dynamic-code-load read-only mandate at targetSdk 34 — and the paths apps moved to  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when you execute code i` · AM-03 (with a co-writable path) /  · Android 14 requires DEX/JAR/APK files to be `setReadOnly()` **before** content is written, or the class loader…</sub>
- [ ] **`D22-034`** Zip path validation on by default at targetSdk 34 — find `ZipPathValidator.clearCallback()`  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) when the write lands on` · AM-02 (a downloaded archive) / AM- · The platform blocks zip-slip by default for targetSdk 34+ apps — and ships a documented process-wide opt-out. …</sub>

**🟧 High ceiling**

- [ ] **`D22-035`** The CA trust store moved into the Conscrypt APEX at API 34  
   <sub>``mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` (P5) for` · AM-06 for the real attack; AM-07/A · Three consequences, and only one of them is a finding. (1) Your harness: writing a CA into `/system/etc/securi…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-036`** Screenshot and screen-recording detection APIs present but unused  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5) is the nearest mobile path` · AM-04 (a screen-capturing app the  · For an app whose threat model includes remote-access-trojan scams — banking, crypto, brokerage — the absence o…</sub>

**🟧 High ceiling**

- [ ] **`D22-037`** MediaProjection per-session consent at targetSdk 34 — and the fallbacks it pushed apps to  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-04 / the app itself against its · From targetSdk 34 each capture session needs fresh consent and reusing a cached projection throws. Apps that c…</sub>
- [ ] **`D22-038`** `OWNER_PACKAGE_NAME` redaction (Android 14) — provenance checks that now fail open  
   <sub>``broken_access_control.privilege_escalation` (null) — a provenance-based autho` · AM-03 (an app that places a file i · From Android 14 the owner-package column is redacted for most callers. An app that used that column to decide …</sub>
- [ ] **`D22-039`** SDK Runtime (Privacy Sandbox) — `<uses-sdk-library>` pinning and what still crosses the boundary  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) fo` · AM-08 malicious third-party SDK · Android 14 moved runtime-enabled SDKs into a separate process with no access to the app's data directory, only…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-040`** `ad_services` SDK-extension gating — Privacy Sandbox code reachable below its nominal API level  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-05 · `SdkExtensions.getExtensionVersion(SdkExtensions.AD_SERVICES)` gates Privacy Sandbox advertising APIs on Andro…</sub>
- [ ] **`D22-041`** Minimum installable targetSdk and `--bypass-low-target-sdk-block`  
   <sub>``using_components_with_known_vulnerabilities.outdated_software_version` (P5) s` · AM-11 · Two things to establish. Can the app under test even install on the OS versions the client claims to support? …</sub>

**🟧 High ceiling**

- [ ] **`D22-042`** `USE_FULL_SCREEN_INTENT` held by a non-calling, non-alarm app  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) when the desti` · AM-02 (push-delivered) / AM-08 · Android 14 restricts full-screen intents to calling and alarm apps and adds a runtime capability check. An app…</sub>
- [ ] **`D22-043`** Non-SDK interface restrictions — and the raw-Binder bypass that means "blocked" is not "unreachable"  
   <sub>`none directly — rate on the security control that fails open` · AM-12 for the bypass technique; th · Two halves. The **finding**: apps use reflection against hidden APIs for exactly the things that matter here —…</sub>
- [ ] **`D22-044`** TLS 1.0/1.1 disallowed at targetSdk 35 — find the stack that re-enables them  
   <sub>``broken_authentication_and_session_management.cleartext_transmission_of_sessio` · AM-06 · Apps targeting Android 15 cannot negotiate TLS 1.0/1.1 through the platform stack. An app that still needs a l…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-045`** Background activity launch: sender opt-in at 34, creator opt-in at 35  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null); the phishing ` · AM-03 (the party holding the Pendi · Android 14 required the **sender** of a PendingIntent to opt into background activity launches; Android 15 req…</sub>
- [ ] **`D22-046`** Android 15 force-stop cancels every PendingIntent — a methodology trap and a persistence finding  
   <sub>`none as a vulnerability; it prevents a false negative in D08 and is rated on t` · AM-01 (the user, or an app that ca · Two sides. As **method**: force-stopping the app between PendingIntent setup and PendingIntent trigger invalid…</sub>

**🟧 High ceiling**

- [ ] **`D22-047`** OTP redaction from `NotificationListenerService` (Android 15) — and the delivery shapes that route around it  
   <sub>``broken_authentication_and_session_management.two_fa_bypass` (P3); `broken_aut` · AM-04 (a co-installed app holding  · Android 15 redacts OTP content from untrusted notification listeners, with trusted companion-device associatio…</sub>
- [ ] **`D22-048`** Screen-share protection and `setContentSensitivity` (Android 15)  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null)` · AM-02 (a remote-access support or  · Android 15 hides notification content and password fields from remote viewers during screen sharing, and gives…</sub>
- [ ] **`D22-049`** Private space (Android 15) — a second profile your enumeration must account for  
   <sub>``broken_access_control.idor.view_sensitive_information_iterable_object_identif` · AM-05 (another user of the same de · Private space installs apps into a separate, hidden-when-locked user profile. Two consequences: an app that as…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-050`** Foreground-service time limits (Android 15) and the `device_config` compression that makes them testable  
   <sub>``application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty`` · AM-03 (an app that keeps the targe · Android 15 caps `dataSync` and `mediaProcessing` foreground services at a cumulative six hours in a 24-hour wi…</sub>
- [ ] **`D22-051`** Edge-to-edge and large-screen layout enforcement hiding a security affordance  
   <sub>``mobile_security_misconfiguration.tapjacking` (P5) is the nearest mobile path ` · AM-01 (no actor — the platform cha · Two layout enforcements, one consequence: UI redress by layout rather than by overlay. Security-relevant conte…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-052`** Intent-redirection hardening on by default at Android 16 — grep `removeLaunchSecurityProtection()`  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-03; AM-02 for the deep-link del · Android 16 blocks the nested-intent launch class by default for every app on the device. There is exactly one …</sub>

**🟧 High ceiling**

- [ ] **`D22-053`** `android:intentMatchingFlags` — the opt-in, and the per-component opt-out that undoes it  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Android 16 lets an app opt into strict matching with `android:intentMatchingFlags="enforceIntentFilter"` — whi…</sub>

**⬜ Support ceiling**

- [ ] **`D22-054`** Ordered-broadcast priority scope no longer global (Android 16)  
   <sub>`none — it changes the applicability of a D05 finding` · AM-03 · The classic ordered-broadcast interception — register at a very high `android:priority` and `abortBroadcast()`…</sub>

**🟧 High ceiling**

- [ ] **`D22-055`** Predictive back at targetSdk 36 — the security gate inside `onBackPressed()` that stopped running  
   <sub>``insecure_data_storage.screen_caching_enabled` (P5) for the residual-state fra` · AM-11 (whoever next holds the unlo · At targetSdk 36 the system enables predictive back by default: `onBackPressed()` is no longer called and `KEYC…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-056`** `PRIORITY_SYSTEM_NAVIGATION_OBSERVER` used as a gate it cannot be  
   <sub>``broken_access_control.bypass_of_password_confirmation.change_password` (P4) w` · AM-01 · Android 16 added an observer-only back priority. Code that registers a "confirm before leaving" handler at thi…</sub>
- [ ] **`D22-057`** Local network permission (Android 16) and the `RESTRICT_LOCAL_NETWORK` compat phase  
   <sub>``broken_access_control.privilege_escalation` (null) where the LAN protocol let` · AM-06 (an attacker on the same LAN · Android 16 gates raw sockets to RFC1918 and link-local ranges, mDNS, SSDP, `NsdManager` and local unicast/mult…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-058`** `KeyStoreManager.grantKeyAccess()` (Android 16) — Keystore keys shared across UIDs  
   <sub>``cryptographic_weakness.key_reuse.inter_environment` (P2) for the shared-key f` · AM-08 (the grantee) · Android 16 added an API to share Android Keystore keys with other apps by UID. Any grant widens the key's trus…</sub>
- [ ] **`D22-059`** Health Connect granular permissions replace `BODY_SENSORS` at targetSdk 36  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — ` · AM-05 / AM-09 · Two halves. First, audit the declared `android.permission.health.*` set against what the app functionally need…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-060`** Certificate Transparency: opt-in at Android 16, default at API 37 — and the custom-trust-anchor caveat  
   <sub>``mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) standal` · AM-06 with a mis-issued certificat · Two things. A `domain-config` that sets `<certificateTransparency enabled="false"/>` on a sensitive domain is …</sub>
- [ ] **`D22-061`** ART and Mainline module updates changing behaviour under a shipped app  
   <sub>`none directly — rate on the security control that changes behaviour` · AM-01 (no actor; a Google Play sys · ART, Conscrypt and several other modules now update through Google Play system updates, independently of the O…</sub>

**⬜ Support ceiling**

- [ ] **`D22-062`** The API 37 horizon — changes already landing that will invalidate current PoCs  
   <sub>`none — forward-looking applicability` · Three changes on the near horizon each close a class this chapter currently treats as live, and one opens a ne…</sub>

**🟧 High ceiling**

- [ ] **`D22-063`** App Bundle split delivery — the code that is not in `base.apk`  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null) when a split e` · AM-03 · Play Feature Delivery ships `com.android.dynamic-feature` modules as separate split APKs after install. A revi…</sub>
- [ ] **`D22-064`** Base-only install — does the app fail closed when the integrity split is missing?  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-11 (sideload) / AM-12 · Bundled apps normally refuse to run without their required splits. Test whether this one degrades **open** rat…</sub>
- [ ] **`D22-065`** SafetyNet Attestation still called — dead since January 2025  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-12 initially, but the gate is o · SafetyNet Attestation was fully turned down in January 2025. The `attest` API now always invokes the failure l…</sub>
- [ ] **`D22-066`** Play Integrity verdict consumed client-side, or without the four baseline checks  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-12 for the on-device decryption · The documented server-side baseline is four checks in order: `requestDetails` match the expected values; `requ…</sub>
- [ ] **`D22-067`** Key attestation verified on-device, or accepted without CRL, security level and expiry checks  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-12 for the on-device case; AM-0 · The whole premise of attestation is that the device may be compromised, so verification performed **in the app…</sub>
- [ ] **`D22-068`** Credential Manager adopted with the legacy sign-in path left in place  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) when` · AM-02 (phishing origin) / AM-03 · Apps migrating to Credential Manager and passkeys almost always keep the legacy path — Smart Lock, the FIDO2 A…</sub>
- [ ] **`D22-069`** Restore Credentials and cross-device credential transfer  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) wher` · AM-11 (restoring the victim's back · Credential Manager integrates with a Restore Credentials mechanism for "seamless sign-in on a new device". Any…</sub>
- [ ] **`D22-070`** LEGACY-live: targetSdk < 31 — components with an intent-filter exported without anyone typing it  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (null)` · AM-03 · Below targetSdk 31, any component carrying an `<intent-filter>` is exported by default with no attribute prese…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-071`** LEGACY-live: targetSdk < 17 — ContentProviders exported by default  
   <sub>``server_side_injection.sql_injection` (P1) for a provider with a raw query pat` · AM-03 · On targetSdk <= 16 a `<provider>` with no `android:exported` is exported. On any modern target an exported pro…</sub>

**🟧 High ceiling**

- [ ] **`D22-072`** LEGACY-live: minSdk < 24 — user-added CAs trusted by default  
   <sub>``mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) standal` · AM-06 (a real network attacker sti · Below API 24 an app trusts the user CA store with no configuration at all, so pushing a CA through Settings in…</sub>
- [ ] **`D22-073`** LEGACY-live: targetSdk < 28 — cleartext HTTP permitted by default  
   <sub>``broken_authentication_and_session_management.cleartext_transmission_of_sessio` · AM-06 · Below targetSdk 28, cleartext is permitted with no manifest entry at all. At 28+ the correct framing is always…</sub>

**🟥 Critical ceiling**

- [ ] **`D22-074`** LEGACY-live: minSdk < 17 — `addJavascriptInterface` reflection RCE  
   <sub>``server_side_injection.remote_code_execution_rce` (P1) — code execution in the` · AM-02 (attacker-controlled content · Below minSdk 17, every public method of an injected bridge object is callable from JavaScript, which yields th…</sub>

**🟨 Medium ceiling**

- [ ] **`D22-075`** LEGACY-live: targetSdk < 30 — free package visibility, and why it changes discovery not delivery  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) wh` · AM-03 · Two directions. If the app under test targets 29 or lower, it can enumerate every installed package with no de…</sub>

**🟧 High ceiling**

- [ ] **`D22-076`** LEGACY-live: device <= Android 11 — `adb backup` still yields app data  
   <sub>``mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) standal` · AM-11 · `adb backup` extraction is the most over-reported dead technique in the corpus. It is live on Android 11 and l…</sub>
- [ ] **`D22-077`** LEGACY: Zygote `--runtime-flags` command injection (CVE-2024-31317)  
   <sub>``broken_access_control.privilege_escalation` (null) — it is a platform bug, re` · a principal holding `WRITE_SECURE_ · On an unpatched device, a principal with `WRITE_SECURE_SETTINGS` can force **arbitrary** apps to start with `D…</sub>

**⬜ Support ceiling**

- [ ] **`D22-078`** The three-line preconditions block on every version-gated finding  
   <sub>`none — report quality, which directly determines the triager's rating` · Every version-gated report must state three things: the device OS you proved it on; the app's targetSdk and th…</sub>
- [ ] **`D22-079`** Prove the platform-mitigated negative explicitly  
   <sub>`none — it is what stops a P5 being filed as a High` · Several classic Android findings are blocked by default on modern devices: tapjacking through most overlay typ…</sub>
- [ ] **`D22-080`** Do not retract when the platform changed under you mid-engagement  
   <sub>`none — it preserves a real finding that would otherwise be discarded` · A version-gated PoC can stop reproducing for three different reasons, and they demand three different response…</sub>
- [ ] **`D22-081`** File version-gated primitives before their consumer  
   <sub>`none — submission strategy` · A hardening opt-out found here (`removeLaunchSecurityProtection()`, `ZipPathValidator.clearCallback()`, `inten…</sub>
- [ ] **`D22-082`** Check the programme's OS-version floor before spending the day  
   <sub>`none — eligibility control` · Programmes set an OS-version floor and a physical-access exclusion. A LEGACY-live finding can be technically c…</sub>

<details><summary>⚰️ D22 graveyard — do not submit these standalone</summary>

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

</details>


<details><summary>🔗 D22 cross-surface joins — park these, chase them in P7</summary>

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

</details>


---

## D23 Payments, Entitlements, Subscriptions & Fraud

**Phase P6 · `M6` · 66 items** — 🟥 17 critical · 🟧 20 high · ⬜ 29 support  

📄 Full detail, with every command and proof: [`checklist/D23-payments-and-entitlements.md`](checklist/D23-payments-and-entitlements.md)

> **Crux question.** **Does any monetary or entitlement decision in this app get made anywhere other than the vendor's own server — and where the server does decide, does it independently re-derive the amount, the payer identity and the uniqueness of the receipt, or does it echo what the client sent?**

It pays because it is the only mobile domain where the impact statement writes itself. Everything else in
a mobile report has to be argued into a severity band; a payment finding arrives with an arithmetic figure
attached. Cobalt's Patricio Castagnaro puts the consultancy version bluntly for financial clients: *"we
don't care about the platform protections … we want to focus on the business logic. Why? Because we are
moving money, or we are banking."* Grab's reward philosophy says the same thing from the programme side —
they pay for demonstrated business consequence and explicitly ask researchers to "spend extra time to
provide a realistic attack/threat scenario adapted to our business". Reddit's policy is the sharpest
formulation of the rule this chapter operates under: *"We generally do not accept logic bugs unless they
result in the disclosure of security information or financial data, escalate privileges, or cause
disruption to our services."* Xiaomi's Critical band is literally "vulnerabilities that could cause
significant financial loss to users."


**⬜ Support ceiling**

- [ ] **`D23-001`** Build the monetisation map before touching anything  
   <sub>`n/a (it decides which of the other 60 items exist in this app)` · Enumerate every place the app makes or reports a money/entitlement decision, and for each one record **who dec…</sub>

**🟧 High ceiling**

- [ ] **`D23-002`** Purchase signature verified on the device with a key shipped in the APK  
   <sub>``broken_access_control\` · AM-12 to discover, AM-01 to exploi · The single most common billing defect. The app RSA-verifies the purchase payload against a base64 public key c…</sub>
- [ ] **`D23-003`** Entitlement granted from a local flag with no server round-trip  
   <sub>``broken_access_control\` · AM-12 locally; the reportable form · Find the storage key that decides the gate, flip it, restart cold, and then make a *server* call that should b…</sub>

**⬜ Support ceiling**

- [ ] **`D23-004`** The non-root route to the entitlement store: modify-and-restore backup  
   <sub>``mobile_security_misconfiguration\` · AM-11 physical unlocked; AM-12 for · The value of this item is not the flip — it is removing root from the PoC. A triager who sees `adb root` disco…</sub>
- [ ] **`D23-005`** The two-half rule: does the backend honour the state the client claims?  
   <sub>``broken_access_control\` · AM-01 · Every local-unlock item in this chapter terminates here. Strip the app out of the loop entirely and make the r…</sub>

**🟧 High ceiling**

- [ ] **`D23-006`** `purchaseToken` replayed to the same account (idempotency)  
   <sub>``broken_access_control\` · AM-01 · Buy one consumable or subscription with your own test account, capture the verification call, then submit the …</sub>

**🟥 Critical ceiling**

- [ ] **`D23-007`** `purchaseToken` redeemed against a second account (uniqueness and binding)  
   <sub>``broken_access_control\` · AM-05 another user of the same app · One legitimate purchase entitling unlimited accounts. This is the shape that turns a billing bug into a resale…</sub>

**⬜ Support ceiling**

- [ ] **`D23-008`** `setObfuscatedAccountId()` never called, so the eligibility check cannot exist  
   <sub>``cryptographic_weakness\` · AM-05 · The documented fraud signal is that the purchase carries an app-side account identifier the backend can compar…</sub>

**🟧 High ceiling**

- [ ] **`D23-009`** SKU substitution: a cheap product's token redeemed for an expensive entitlement  
   <sub>``broken_access_control\` · AM-01 · The backend is supposed to read the product from Google's verification response. Many read it from the request…</sub>
- [ ] **`D23-010`** Signature / `signedData` fields removed from the verification request  
   <sub>``cryptographic_weakness\` · AM-01 · If the request carries `signedData`/`signature`, find out whether the server actually uses them. Three probes,…</sub>
- [ ] **`D23-011`** Client-side acknowledgement and the three-day auto-refund loop  
   <sub>``broken_access_control\` · AM-01 (the attacker is the purchas · Acknowledge locally, grant locally, and never let the acknowledgement reach Google. The user keeps the entitle…</sub>
- [ ] **`D23-012`** Refund, chargeback and voided-purchase reconciliation  
   <sub>``broken_access_control\` · AM-01 · Whether a completed refund or chargeback removes the entitlement, and whether the grant is idempotent across a…</sub>

**⬜ Support ceiling**

- [ ] **`D23-013`** Trial re-granted after `pm clear`, reinstall or a rotated device identifier  
   <sub>``broken_access_control\` · AM-01 · The "you already used your trial" guard is usually local state or an install-scoped identifier. Clear it three…</sub>
- [ ] **`D23-014`** Entitlement keyed to the install, so clones, work profiles and Private Space multiply it  
   <sub>``broken_access_control\` · AM-11 physical unlocked, scaling t · If a trial, free credit, referral bonus or device-limited licence is keyed on an install-scoped identifier — a…</sub>
- [ ] **`D23-015`** Subscription expiry cached client-side and extended in place  
   <sub>``broken_access_control\` · AM-12 to set up, AM-01 to prove · Many apps cache the entitlement with an expiry and only re-check on a schedule. Editing the cached expiry exte…</sub>

**🟧 High ceiling**

- [ ] **`D23-016`** Cancellation, grace period and pause/resume abuse  
   <sub>``broken_access_control\` · AM-01 · The lifecycle states — active, cancelled, in grace, on hold, paused, expired — are a state machine that is rar…</sub>

**⬜ Support ceiling**

- [ ] **`D23-017`** Entitlement state driven by a broadcast, a `PendingIntent` or a deep link  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · Entitlement refresh is frequently plumbed through a broadcast or a callback `PendingIntent`. Each of those is …</sub>

**🟧 High ceiling**

- [ ] **`D23-018`** Entitlement row writable through an exported `ContentProvider`  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · Where the entitlement lives in a database fronted by a provider, the flip does not need root at all — any inst…</sub>

**⬜ Support ceiling**

- [ ] **`D23-019`** Implicit bind to `InAppBillingService.BIND` — the billing-proxy app  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · Binding the billing service with an implicit intent lets any installed app answer instead of Play and return a…</sub>
- [ ] **`D23-020`** Play Integrity `appLicensingVerdict` unused, or evaluated on the client  
   <sub>``broken_access_control\` · AM-01 · Where the app uses the licensing verdict at all, check that it is read from a **server-decoded token** rather …</sub>

**🟥 Critical ceiling**

- [ ] **`D23-021`** Client-computed price, total or credit posted to the server  
   <sub>``broken_access_control\` · AM-01 · Find every money field the client *names* in a request and change it. The enabling condition is that the clien…</sub>

**⬜ Support ceiling**

- [ ] **`D23-022`** Negative quantity, negative price and numeric-boundary values — carried to settlement  
   <sub>``broken_access_control\` · AM-01 · Cart endpoints validate "is it a number" and nothing else. The false-positive trap is explicit and it is the r…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-023`** Currency swap mid-checkout  
   <sub>``broken_access_control\` · AM-01 · The server stores the price in one currency but accepts a client-supplied `currency` parameter. Send the same …</sub>
- [ ] **`D23-024`** Cart-state TOCTOU: total priced at step 1, cart mutated at step 2, captured at step 3  
   <sub>``broken_access_control\` · AM-01 · Begin with a cheap cart, capture the priced total from step 1, add expensive items, then submit the payment ca…</sub>

**🟧 High ceiling**

- [ ] **`D23-025`** Free-amount fields: tip, donation, round-up, custom top-up  
   <sub>``broken_access_control\` · AM-01 · Free-amount inputs get materially less validation than the cart because there is no catalogue price to compare…</sub>
- [ ] **`D23-026`** Limits, thresholds and risk rules that live only in the client  
   <sub>``broken_access_control\` · AM-01 · Two findings in one sweep. First, whether min/max/daily/monthly limits are enforced anywhere but the UI. Secon…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-027`** Step-skip and state-machine reversal in the order flow  
   <sub>``broken_access_control\` · AM-01 · `cart -> payment -> fulfilment`, each at a separate endpoint. The state machine enforces the happy path but no…</sub>
- [ ] **`D23-028`** Payment callback / return-URL forged through a deep link  
   <sub>``broken_access_control\` · AM-02 remote one click (a web page · After the hand-off, the app learns the outcome from a return URI or an activity result. If it believes the par…</sub>

**🟧 High ceiling**

- [ ] **`D23-029`** PSP SDK local "payment succeeded" callback treated as authoritative  
   <sub>``broken_access_control\` · AM-01 · The SDK hands the client a success object. The correct design waits for the server-confirmed webhook. Test whe…</sub>
- [ ] **`D23-030`** Payment webhook replay — signature-verified but not idempotent  
   <sub>``server_security_misconfiguration\` · AM-01 if the webhook endpoint is r · The backend verifies the PSP signature and never records whether it has already processed that event id. The s…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-031`** Saved payment instrument reusable across accounts or on a new device  
   <sub>``broken_access_control\` · AM-05 another user of the same app · Two questions. Is the saved-card token scoped to its owning account server-side? And is a step-up (CVV, 3DS, b…</sub>
- [ ] **`D23-032`** Step-up not bound to the transaction it authorises  
   <sub>``broken_authentication_and_session_management\` · AM-01 · Capture the artefact the app sends after the user approves, then replay it against a **modified** transaction …</sub>

**⬜ Support ceiling**

- [ ] **`D23-033`** Money-moving action not bound to a user-presence-verified key (Protected Confirmation)  
   <sub>``cryptographic_weakness\` · AM-03 local app with a driving pri · Whether the "confirm payment" step is a plain dialog plus an ordinary key, or a TEE-displayed message whose ha…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-034`** High-risk flow fully automatable: overlay plus accessibility drives the payment  
   <sub>``broken_authentication_and_session_management\` · AM-04 local app with one common pe · Whether the payment confirmation can be completed end to end by programmatic UI interaction. This is the on-de…</sub>
- [ ] **`D23-035`** 3-D Secure / SCA challenge outcome asserted by the client  
   <sub>``broken_authentication_and_session_management\` · AM-01 · Card step-up is almost always a `WebView` on Android. Two questions: does the app decide "authentication succe…</sub>

**🟧 High ceiling**

- [ ] **`D23-036`** Google Pay `PaymentsClient` built on the client, and `ENVIRONMENT_TEST` in a release build  
   <sub>``broken_access_control\` · AM-01 · The Google Pay request is assembled on the device — gateway and merchant parameters, allowed auth methods, and…</sub>
- [ ] **`D23-037`** Test or sandbox payment instrument accepted in production  
   <sub>``cryptographic_weakness\` · AM-01 · Whether the production build can be steered onto the PSP's sandbox — by a shipped test key, a flavour switch, …</sub>

**🟥 Critical ceiling**

- [ ] **`D23-038`** Payment-processor **secret** key shipped in the client  
   <sub>``sensitive_data_exposure\` · AM-01 (anyone who downloads the AP · Key **ids** are usually fine; **secrets** are not. Separate the two before writing anything, then prove livene…</sub>

**⬜ Support ceiling**

- [ ] **`D23-039`** Hardcoded Basic credential for a production payment or vault host — the severity fork  
   <sub>``sensitive_data_exposure\` · AM-01 · A `grep` hit is the *start*. Its value comes from tracing **which client sends it** and **what the endpoint do…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-040`** Payment bridge methods reachable from a non-allow-listed WebView origin  
   <sub>``broken_access_control\` · AM-02 remote one click · Payment bridges (`initiateTxn`, `getTxnParams`, `pay`, `signTransaction`) reachable from a frame the origin al…</sub>
- [ ] **`D23-041`** Payment `PendingIntent` replay and misrouting  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · Two defects, both against the payment flow specifically: a missing `FLAG_ONE_SHOT` on a "confirm payment" `Pen…</sub>

**⬜ Support ceiling**

- [ ] **`D23-042`** Promo, voucher and gift-code enumeration through the mobile API  
   <sub>``server_security_misconfiguration\` · AM-01 · The mobile promo endpoint frequently lacks the rate limiting on the web equivalent, and the code space is smal…</sub>
- [ ] **`D23-043`** One-time incentive reused: coupon, fee waiver, referral credit  
   <sub>``broken_access_control\` · AM-01 · No server-side idempotency on a single-use benefit. **Run ten sequential redemptions before any parallel work*…</sub>

**🟧 High ceiling**

- [ ] **`D23-044`** Referral self-redemption and referral farming  
   <sub>``broken_access_control\` · AM-01 · Three variants, cheapest first: make yourself your own referrer; claim the bonus on both sides of a self-refer…</sub>

**⬜ Support ceiling**

- [ ] **`D23-045`** Redemption and checkout races — single-packet, with a sequential baseline and a ledger read  
   <sub>``server_security_misconfiguration\` · AM-01 · Check-then-act windows on any "you may do this once" control. The discipline is what makes it reportable: **se…</sub>
- [ ] **`D23-046`** Loyalty, points and in-app-currency ledgers: negative, fractional, over-balance  
   <sub>``broken_access_control\` · AM-01 · Point ledgers are a bolt-on and lack the invariants the money ledger has. Four probes: negative redemption (wh…</sub>

**🟧 High ceiling**

- [ ] **`D23-047`** Gift card and stored value: balance-check oracle, enumeration, and the double-burn  
   <sub>``broken_access_control\` · AM-01, frequently unauthenticated · "Check balance" and "redeem" are usually unauthenticated or lightly authenticated and return different respons…</sub>

**🟥 Critical ceiling**

- [ ] **`D23-048`** Wallet, payout and withdrawal races and limit overruns  
   <sub>``server_security_misconfiguration\` · AM-01 · The mobile-specific version of the classic overdraft race, hitting endpoints (in-app top-up, instant payout, p…</sub>

**⬜ Support ceiling**

- [ ] **`D23-049`** Refund and cancellation races, and refund-after-fulfilment  
   <sub>``server_security_misconfiguration\` · AM-01 · Refund an order twice, cancel after fulfilment, and race a refund against the fulfilment job.</sub>
- [ ] **`D23-050`** GraphQL alias batching misread as a race — the false-positive gate  
   <sub>`n/a (a kill gate for a claim that would otherwise be filed as `server_security` · 100 aliases of `redeemCoupon` all returning `success:true` is commonly misreported as a double-spend race. It …</sub>

**🟥 Critical ceiling**

- [ ] **`D23-051`** Multi-step money flows where one step is unauthorised  
   <sub>``broken_access_control\` · AM-05 · These features chain several API calls, and the authorisation is usually checked only at the step the UI makes…</sub>
- [ ] **`D23-052`** Payment-app hand-off: UPI, wallet and bank-app deep links  
   <sub>``broken_access_control\` · AM-02 remote one click; AM-03 loca · Three separate questions, and they are different bugs. (1) Does the app **emit** a payment URI whose payee or …</sub>
- [ ] **`D23-053`** Transaction executed without confirmation from a scanned or external input  
   <sub>``broken_authentication_and_session_management\` · AM-02 (a poisoned QR code in the p · Generate a payment QR encoding an attacker payee and amount, scan it in the app, and record whether a confirma…</sub>

**🟧 High ceiling**

- [ ] **`D23-054`** The confirmation prompt does not name the counterparty or amount that will execute  
   <sub>``broken_access_control\` · AM-02 · Compare, field by field, what the prompt displays against what the transaction body contains. An origin-spoof …</sub>
- [ ] **`D23-055`** Payment confirmation under edge-to-edge and predictive back  
   <sub>``broken_access_control\` · AM-01 (the victim is the user; the · Two platform defaults that developers have not re-tested their payment screens against. Is the amount or recip…</sub>

**⬜ Support ceiling**

- [ ] **`D23-056`** Shadow API: the app's billing endpoints are an older API version than the web  
   <sub>`rate on the regression found: `broken_authentication_and_session_management\` · AM-01 · The hardcoded backend calls in an APK are frequently an **older** API version than the current web app uses, w…</sub>
- [ ] **`D23-057`** The layer-ordering trap on a billing or payment endpoint  
   <sub>`n/a (a kill gate for `broken_authentication_and_session_management\` · A `400 "field X is required"` from an unauthenticated request does **not** prove you passed auth. Many stacks …</sub>
- [ ] **`D23-058`** Card data persisted, logged or left in memory on the device  
   <sub>``sensitive_data_exposure\` · AM-11 physical unlocked, AM-04 for · Whether the PAN, CVV or expiry is stored, logged, autocompleted, screenshot-able or left in process memory aft…</sub>

**🟧 High ceiling**

- [ ] **`D23-059`** NFC Observe Mode and polling-frame handling — pre-authentication emission  
   <sub>``sensitive_data_exposure\` · AM-10 physical locked (a reader pr · Android 15 lets an app listen to a reader's polling frames without responding, and act on them **before** any …</sub>

**⬜ Support ceiling**

- [ ] **`D23-060`** Wallet role versus the legacy default-payment assumption  
   <sub>``broken_access_control\` · AM-03 local app that holds or acqu · An app that assumes it is the default payment handler because of the legacy setting, or that does not handle l…</sub>
- [ ] **`D23-061`** HCE service configuration: AID registration, `requireDeviceUnlock` and relay exposure  
   <sub>``broken_access_control\` · AM-10 physical locked for the rela · Three checks against the app's own configuration. Does the AID service set `android:requireDeviceUnlock="false…</sub>
- [ ] **`D23-062`** Billable action reachable from an exported surface with no user consent  
   <sub>``broken_access_control\` · AM-03 zero-permission local app (t · Any exported surface that sends SMS/MMS, dials, consumes an entitlement, or triggers a premium-rate action is …</sub>
- [ ] **`D23-063`** Rules of engagement for payment testing — the boundary, and what you must not do  
   <sub>Settle in writing, before Gate 1: sandbox PSP keys? test cards? is any real card or real settlement in scope (…</sub>
- [ ] **`D23-064`** Evidence discipline for money findings  
   <sub>A money finding needs pre-state, the bug, post-state and the out-of-band side effect. Triagers rate what they …</sub>
- [ ] **`D23-065`** The pre-severity gate, applied to the Critical claim rather than to the bug  
   <sub>`n/a (it governs every Critical/High in this chapter)` · Write the draft Critical title, then substitute **the Critical claim** for "the bug" in each question. Payment…</sub>
- [ ] **`D23-066`** Chain-filing order for a payment chain  
   <sub>A consumer report references the primitives' ids, which only exist once the primitives are filed. Filing the c…</sub>

<details><summary>⚰️ D23 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| Premium unlocked on your own rooted device and it reverts on the next sync | AM-12 is not an attacker model; the server is the control and it held. Files as `lack_of_binary_hardening\|runtime_instrumentation_based` (**P5**) | A premium-only **server** response under a free account's token, from `curl`, outside the app (D23-005) |
| `BASE64_PUBLIC_KEY` / `base64EncodedPublicKey` found in the decompile | A Play licensing public key is meant to be in the APK; its presence alone proves nothing about where verification happens | The same key used by an in-app `Signature.verify` **and** no `purchaseToken` leaving the device (D23-002) |
| `verifyPurchase()` hooked with Frida and it returned `true` | A hook on your own process is the expected outcome of an untrusted execution environment | The entitlement persisting after a clean install and login on a second device (D23-005, D23-012) |
| Negative price or quantity accepted by the cart endpoint | The explicit FP trap: cart APIs accept arbitrary client state while capture rejects negative totals. The cart display is fiction | The credit **settling** — wallet balance, store credit, or a refund to your instrument (D23-022) |
| The cart shows `-$50.00` after stacking five coupons | Most systems silently cap the applied discount at 100%; the captured payment is `$0.00` and no refund issues | The captured payment, or a refund, reflecting the stacked discount (D23-043) |
| 100 GraphQL aliases of `redeemCoupon` all returned `success:true` | Apollo/GraphQL-Ruby/Graphene resolve aliases sequentially inside one request; the response is not the state | A ledger read showing 100 applications — and then it is a quota bug, not a race (D23-050) |
| 30 parallel requests all returned 200 | N×200 is not a ledger effect, and races reproduce 1/10 or 2/100 | The balance/ledger arithmetic before, after the sequential baseline, and after the parallel run (D23-045) |
| `400 "purchaseToken is required"` on an unauthenticated billing call | A body parser or schema filter in front of the auth middleware produces exactly this | A minimal well-formed `{}` still returning the domain-field error rather than a 401 (D23-057) |
| An older `/api/v1/` billing path is still live | A version difference alone is Informational | A behavioural regression on the old path — weaker auth, no 429, laxer validation, more fields (D23-056) |
| `rzp_test_…`, `pk_test_…` or a Stripe publishable key in the APK | Publishable and test identifiers are public by design; filing them lands on `...\|intentionally_public_sample_or_invalid` (**P5**) | A **secret** authenticating with one read-only call (D23-038), or a sandbox key live against production (D23-037) |
| `ENVIRONMENT_TEST` in a debug flavour | Debug flavours are not distributed | The same constant in the store-distributed release artefact (D23-036) |
| The payment confirmation screen can be tapjacked | `mobile_security_misconfiguration\|tapjacking` is **P5** and the overlay alone moves no money | A transaction completed end to end by overlay plus accessibility, recorded, with the server record (D23-034) |
| No certificate pinning on the payment host | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` and `\|defeatable` are both **P5**, and AM-07 is tester convenience, not an attacker | Cleartext transmission of a token or PAN to a network attacker with no trusted CA (that is D14, not D23) |
| Card fields are screenshot-able / appear in the recents thumbnail | `insecure_data_storage\|screen_caching_enabled` is **P5** — Bugcrowd's own remediation text calls `FLAG_SECURE` a best practice | The PAN recoverable from a third party's session-replay dashboard, or from disk after dismissal (D23-058) |
| A promo code works more than once | Many marketing codes are multi-use by design | The code documented or labelled single-use, or a per-account limit that the parallel run overruns (D23-043) |
| `purchaseToken` visible in the proxy on your own device | It is your own purchase on your own device over your own proxy | The same token accepted under a second account (D23-007) |
| The Play Billing Library version is out of date | Version currency is not a vulnerability without a reachable defect | A reachable defect — e.g. the legacy implicit `InAppBillingService.BIND` path (D23-019) |
| "The app trusts the client for `isPremium`" with no server call shown | An architectural observation, not a demonstrated impact; triagers close these as theoretical | The gated server response, plus the untampered negative control (D23-005) |
| IAP bypass on a programme that excludes IAP bypass by name | Out of scope is out of scope; filing it damages the validity ratio | Nothing — unless the entitlement also gates **other users' data**, which re-files it as access control (D23-005) |

</details>


<details><summary>🔗 D23 cross-surface joins — park these, chase them in P7</summary>

- **D11 backup/restore × D23 entitlement store.** Nobody reviews the backup agent and the entitlement
  read path together. If the entitlement key (or a `dynamic_api_hosts`-style config) is inside the backup
  set and trusted on read, the `star` / `abe.jar pack-kk` / `adb restore` pipeline flips it on a **stock,
  unrooted** device — which is the difference between a P5 "rooted device required" and a reportable
  finding. Applies to ≤ Android 11; `[DEGRADED]` on 12+. (D23-004)
- **D02 packaging/multi-user × D23 install-scoped entitlement.** The trial or referral bonus is keyed on
  a generated install UUID; the work profile, the OEM dual-app feature and Private Space (Android 15+)
  each mint a new one on the same physical device. Nobody tests entitlement uniqueness against the
  platform's own multi-instance features. (D23-014, D23-044)
- **D08 PendingIntent × D23 payment confirmation.** The `PendingIntent` review looks for mutability and
  redirection; the payments review looks at amounts. Neither notices that the "confirm payment"
  `PendingIntent` lacks `FLAG_ONE_SHOT` and carries a constant `requestCode`, so one confirmation replays
  N times and order A's confirmation lands on order B. (D23-041)
- **D10 WebView origin allow-list × D23 payment bridge.** The bridge audit rates methods by what they
  return; the payment audit assumes the bridge is internal. The join is a payment method whose origin
  guard covers the main frame only, reachable from a cross-origin iframe inside an allow-listed page —
  transaction parameters out, transactions in. (D23-040)
- **D13 event-bound biometrics × D23 transaction signing.** The auth review checks whether the biometric
  prompt can be hooked; the payments review checks whether the amount can be changed. The join is that a
  hooked approval produces an artefact which is then **replayable against a different transaction**,
  because nothing binds the approval to the parameters. Either surface alone is a Medium; together they
  are a P1. (D23-032, D23-033)
- **D24 push/FCM × D23 entitlement refresh.** Entitlement state is refreshed by a push-triggered
  broadcast. The push review looks for data leakage in the payload; the payments review never sees the
  push at all. If the receiver is exported (targetSdk < 31, or a runtime registration without
  `RECEIVER_NOT_EXPORTED` on Android 14+), the entitlement is assertable locally — and if the backend
  accepts the resulting state, remotely. (D23-017)
- **D20 session-replay SDK × D23 card entry.** The privacy review lists which SDKs receive PII; the
  payments review checks whether the PAN is stored locally. Neither notices that UXCam/Smartlook/
  Clarity/FullStory record the card screen unmasked, putting the PAN and CVV in a **third party's**
  dashboard in replayable form — a PCI exposure whose artefact is the vendor replay, not the device.
  (D23-058)
- **D18 SDK credentials × D23 merchant account.** The secrets sweep finds `sk_live_`/`key_secret` and
  rates it as a hardcoded credential; the payments review never reads the secrets list. The join is that
  the credential's capability is *refunds and customer PII on the merchant account* — the same string,
  two orders of magnitude of severity. (D23-038, D23-039)
- **D09 deep links × D23 payment callback.** The deep-link review enumerates schemes and checks for
  redirection; the payments review checks the PSP integration. The join is that the PSP return URI is a
  deep link, so a web page fires the "payment succeeded" callback and the order ships — an AM-02 finding
  that neither review reaches alone. (D23-028, D23-052)
- **D15 shadow API × D23 billing verify.** The API review version-diffs generic endpoints; the payments
  review tests only the version the app calls. The join is `/api/v1/billing/verify` still accepting a
  replayed `purchaseToken` that `/api/v3/` rejects, because the uniqueness check was never backported.
  (D23-056, D23-007)
- **D21 integrity/RASP × D23 licensing.** The resilience review reports "Play Integrity is bypassable" as
  a P5. The payments review reports "the entitlement is client-side" as a P5. The join — the integrity
  verdict is the *only* thing gating the entitlement, and it is evaluated on the client — is a single
  reportable defect. (D23-020)
- **D07 ContentProvider × D23 entitlement row.** The provider review tests for injection and file read;
  the payments review tests the API. Neither runs `content update --bind active:i:1` against the
  entitlements table from a zero-permission app. (D23-018)

</details>


---

## D25 Device, OEM, Firmware & Privileged Surfaces

**Phase P5 · `M5` · 79 items** — 🟥 14 critical · 🟧 11 high · 🟨 1 medium · ⬜ 53 support  

📄 Full detail, with every command and proof: [`checklist/D25-device-oem-and-privileged.md`](checklist/D25-device-oem-and-privileged.md)

> **Crux question.** **Is the device, the OEM image, or a preinstalled build of this app in scope — and if only the app is, which of its own manifest-declared physical, companion and cross-user surfaces hands an attacker a channel that the phone UI and the lock screen never gate?**

It pays because the ordinary rules of mobile severity do not apply here. Everywhere else in this
checklist the VRT caps the native Android categories at P5 and you have to argue your way into a
server-side or access-control node. In `insecure_os_firmware` the taxonomy already agrees with you:
a hardcoded credential for a privileged user is P1 with the baseline vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`,
command injection on the image is P1, local administrator on the default environment is P2, and
over-permissioned credentials on storage is P2. Nothing in this chapter needs the escalation gymnastics
that D11 or D21 need. What it needs instead is authorisation.


**⬜ Support ceiling**

- [ ] **`D25-001`** Settle device / image / app scope and route each finding to the correct programme  
   <sub>Three different products can be "the target": the Play build of an app, a preinstalled build of the same app o…</sub>
- [ ] **`D25-002`** Switch to the device taxonomy and state the vector separately from the surface  
   <sub>AM-01 through AM-11, one per vecto · When the target is a device rather than an app, the app-centric component taxonomy stops being useful. Re-enum…</sub>
- [ ] **`D25-003`** Rate a surface on its four properties before spending a day attacking it  
   <sub>Rank every enumerated surface on four properties and attack in that order: **vector requirements** (does it ne…</sub>
- [ ] **`D25-004`** Record the device posture block that every finding in this chapter is defended by  
   <sub>AM-12 (own device; not an attack) · A finding produced on a permissive, unlocked, non-current device is closed as unrealistic and you will not be …</sub>
- [ ] **`D25-005`** `adb shell` is not an app — re-prove every reachability claim from a zero-permission PoC APK  
   <sub>AM-03 · The `shell` UID holds permissions no third-party app holds — `READ_LOGS` on some builds, `DUMP`, `WRITE_SECURE…</sub>
- [ ] **`D25-006`** Count your results — the shell-loop ban applied to whole-device package sweeps  
   <sub>Every high-yield sweep here iterates 200–400 packages. Shell array and command-substitution loops fail **silen…</sub>
- [ ] **`D25-007`** Name which sandbox layer stopped you — DAC, type enforcement, or MLS categories  
   <sub>AM-03 · A cross-app compromise must defeat all three layers. When a read or write primitive fails, the report that nam…</sub>
- [ ] **`D25-008`** Determine whether the target ships as a preinstalled, privileged or platform-signed build  
   <sub>``broken_access_control\` · AM-03 · The same code defect in a `priv_app` is a far higher-severity finding than in an `untrusted_app`, because an e…</sub>

**🟥 Critical ceiling**

- [ ] **`D25-009`** Tier the privileged permissions a preloaded build holds, and treat each as a multiplier  
   <sub>``broken_access_control\` · AM-03 · Enumerate every `signature` / `signatureOrSystem` / privileged permission the preloaded package holds and rate…</sub>

**🟧 High ceiling**

- [ ] **`D25-010`** Privileged-permission allowlist enforcement disabled on the image  
   <sub>``insecure_os_firmware\` · AM-03 (the consequence); AM-12 for · Every `signature|privileged` permission held by an app in `/system/priv-app` (or the vendor and product equiva…</sub>

**🟨 Medium ceiling**

- [ ] **`D25-011`** Android 15 `signature-permissions` allowlist for platform-signed non-system apps  
   <sub>``insecure_os_firmware\` · AM-12 for the observation · Android 15 added a second allowlist covering platform signature permissions held by platform-signed apps that …</sub>

**🟧 High ceiling**

- [ ] **`D25-012`** `sharedUserId` — the target's sandbox is the union of its weakest sibling  
   <sub>``broken_access_control\` · AM-03 via the weakest sibling · Packages declaring the same `android:sharedUserId` and signed with the same key share a UID and therefore have…</sub>

**⬜ Support ceiling**

- [ ] **`D25-013`** The app's SELinux domain, and the `untrusted_app_NN` versioned-domain widening  
   <sub>AM-03 · A lower `targetSdk` places the app in a versioned SELinux domain with a materially wider policy. This is an AP…</sub>

**🟧 High ceiling**

- [ ] **`D25-014`** Device-wide debuggable sweep — a preinstalled debuggable package  
   <sub>``insecure_os_firmware\` · AM-11 physical unlocked, or AM-06/ · Debuggable *release* builds still ship — staging APKs published by mistake, OEM preinstalls, SDK-injected buil…</sub>

**⬜ Support ceiling**

- [ ] **`D25-015`** Name a `READ_LOGS` holder on the target's actual device population  
   <sub>``insecure_os_firmware\` · AM-03 (the preinstalled reader is  · The standard triage response to a logcat leak is "logcat needs root or a privileged permission, so it is Infor…</sub>
- [ ] **`D25-016`** Diff the OEM build against AOSP to produce the non-AOSP inventory  
   <sub>AM-12 for the diff · OEM and carrier code is the least-audited code on the device and it is where the exported-component and set-ui…</sub>

**🟥 Critical ceiling**

- [ ] **`D25-017`** OEM system app exporting a component that performs a privileged action  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · The shape is identical to D04–D08 — the impact is device-wide because the caller inherits the system package's…</sub>
- [ ] **`D25-018`** Vendor method added beside an AOSP one with the permission check dropped  
   <sub>``broken_access_control\` · AM-03 · The highest-yield OEM bug class. An OEM adds a method next to an AOSP one and omits the enforcement that the A…</sub>
- [ ] **`D25-019`** Unprotected vendor broadcast action triggering privileged behaviour  
   <sub>``broken_access_control\` · AM-03 · OEM system components register receivers for vendor-specific actions with no `android:permission`, so any inst…</sub>
- [ ] **`D25-020`** OEM ROM add-on ContentProvider that bypasses the permission it should require  
   <sub>``broken_access_control\` · AM-03 · OxygenOS, ColorOS, MIUI, One UI and the rest add providers that are not in AOSP and that frequently miss a `wr…</sub>
- [ ] **`D25-021`** Factory, test, diagnostic and engineering packages on a production image  
   <sub>``insecure_os_firmware\` · AM-03 · Debug and factory packages that were meant for the production line ship to retail. They hold system privileges…</sub>
- [ ] **`D25-022`** OEM-added framework service reachable from `untrusted_app`  
   <sub>``broken_access_control\` · AM-03 · OEMs register services that AOSP does not have. Test each for a missing caller check by driving raw transactio…</sub>
- [ ] **`D25-023`** Preinstalled app holding a squattable or over-broad custom permission  
   <sub>``broken_access_control\` · AM-03 · OEM images define custom permissions at `normal` that gate genuinely privileged vendor interfaces. A `normal` …</sub>

**🟧 High ceiling**

- [ ] **`D25-024`** The target trusts an OEM sibling by package name rather than by signature  
   <sub>``broken_access_control\` · AM-03 on a non-vendor device; AM-0 · Apps integrated with an OEM trust a vendor package by name — `com.samsung.*`, `com.miui.*`, `com.oneplus.*`, `…</sub>

**🟥 Critical ceiling**

- [ ] **`D25-025`** Preinstalled privileged implant, whitelabel firmware, and expired management infrastructure  
   <sub>``insecure_os_firmware\` · AM-01 remote (the implant's operat · Some malicious packages are baked into OEM or reseller firmware as *privileged* packages rather than sideloade…</sub>

**⬜ Support ceiling**

- [ ] **`D25-026`** SELinux downgrade discipline — an arbitrary write from `untrusted_app` is not code execution  
   <sub>AM-03 · Before rating any native or filesystem write primitive, check what the policy on **that build** actually allow…</sub>

**🟧 High ceiling**

- [ ] **`D25-027`** Vendor sepolicy over-permission — diff the OEM's granted set against AOSP  
   <sub>``insecure_os_firmware\` · AM-03 · OEMs add `allow` rules to make preinstalled apps work, and the rules land too broad. The diff is the method: e…</sub>
- [ ] **`D25-028`** `neverallow` violations and permissive domains on a production build  
   <sub>``insecure_os_firmware\` · AM-03 for the exercised impact · `neverallow` assertions are build-time invariants that CTS re-tests. An OEM build shipping a policy that viola…</sub>
- [ ] **`D25-029`** `seapp_contexts` and `mac_permissions.xml` — the domain-assignment table  
   <sub>``broken_access_control\` · AM-03 · These two files decide which SELinux domain a package runs in. A `name=`-matched rule that a repackaged app ca…</sub>

**⬜ Support ceiling**

- [ ] **`D25-030`** AVC denials as a live oracle — and the `dontaudit` and `setenforce 0` traps  
   <sub>AM-03 · A denial tells you that you **reached the check** — your input travelled all the way to a real file or binder …</sub>
- [ ] **`D25-031`** Do not hunt classic Flask/SELinux features Android does not have  
   <sub>Four parts of the classic model do not transfer. Testers who learned SELinux on servers burn days on them. Rea…</sub>

**🟧 High ceiling**

- [ ] **`D25-032`** App-writable `persist.` or vendor system property that gates a security control  
   <sub>``insecure_os_firmware\` · AM-03 · If an OEM labels a `persist.*` or vendor property with a context that permits writes from app domains, an app …</sub>

**⬜ Support ceiling**

- [ ] **`D25-033`** Verified Boot state — what it guarantees and what it does not  
   <sub>``insecure_os_firmware\` · AM-11 physical unlocked · A green, locked boot state means the platform's chain of trust is intact. It says nothing about the app's own …</sub>
- [ ] **`D25-034`** Kernel and GKI posture as context for every in-process native finding  
   <sub>AM-12 · Record the kernel version, GKI status and hardening sysctls. This is the layer under everything and it sets th…</sub>
- [ ] **`D25-035`** Firmware acquisition and partition extraction  
   <sub>AM-12 · Code that is not in the APK — vendor codecs, HALs, kernel, bootloader — has to come from the official firmware…</sub>
- [ ] **`D25-036`** Extract a vendor parser from firmware and fuzz it off-device  
   <sub>``server_side_injection\` · AM-01 remote no interaction, where · OEM-specific codecs and parsers are absent from AOSP, therefore under-fuzzed, and they sit on the highest-valu…</sub>
- [ ] **`D25-037`** Build a stable C-ABI shim instead of `dlsym`-ing C++ symbols  
   <sub>Direct `dlopen`/`dlsym` against a vendor C++ library is brittle: symbols are inlined, hidden, optimised away o…</sub>
- [ ] **`D25-038`** Derive struct offsets from the shipped image's own BTF rather than porting them  
   <sub>Offsets ported from another device with a different kernel generation or physical base are the classic wasted …</sub>
- [ ] **`D25-039`** Identify which mitigation killed the payload before changing offsets  
   <sub>When a payload dies, the generalisable habit is to identify *which* mitigation killed it and change the techni…</sub>

**🟥 Critical ceiling**

- [ ] **`D25-040`** Firmware or OTA update accepted without integrity validation  
   <sub>``insecure_os_firmware\` · AM-06 network attacker, or AM-11 p · Intercept the update fetch, modify the package, and observe whether it installs. Do the same for the companion…</sub>
- [ ] **`D25-041`** Hardcoded or shared credentials on the device image  
   <sub>``insecure_os_firmware\` · AM-01 remote where the credential  · Static credentials in a system app, a `/vendor` config, or a firmware blob. This is the highest-rated single o…</sub>
- [ ] **`D25-042`** The client's own deployment writes to boot or system, or requires an unlocked bootloader  
   <sub>``insecure_os_firmware\` · AM-11 physical unlocked, or AM-03  · For a kiosk, fleet or provisioned-hardware client: does their own software write to boot or system, install in…</sub>

**⬜ Support ceiling**

- [ ] **`D25-043`** `adb` left listening over TCP, and wireless debugging  
   <sub>``insecure_os_firmware\` · AM-06 network attacker on the same · Two separate questions. (a) Does the *device* expose adb to the network, turning a Wi-Fi attacker into a shell…</sub>
- [ ] **`D25-044`** Developer-settings and USB posture the client's deployment depends on  
   <sub>``insecure_os_firmware\` · AM-11 physical unlocked · Does the app or the fleet require USB debugging, accept data over USB, or rely on a charging/kiosk integration…</sub>
- [ ] **`D25-045`** Dialler secret codes into engineering and diagnostic menus  
   <sub>``broken_access_control\` · AM-11 physical unlocked (dialler), · `android.provider.Telephony.SECRET_CODE` receivers fire when `*#*#<code>#*#*` is typed, with no permission, no…</sub>
- [ ] **`D25-046`** Local network listeners opened by the app or the image — check the bind address  
   <sub>``server_side_injection\` · AM-06 network attacker on the same · Apps that run an embedded HTTP server, media proxy, WebSocket or debug port expose it to every app on the devi…</sub>
- [ ] **`D25-047`** Enumerate the local escalation surface mechanically  
   <sub>``broken_access_control\` · AM-03 · This is where an app-level foothold becomes root. Enumerate every filesystem-exposed endpoint, socket and shar…</sub>
- [ ] **`D25-048`** Enumerate the USB modes one connector exposes simultaneously  
   <sub>``physical_security_issues\` · AM-10 physical locked / AM-11 phys · USB modes are mutually exclusive function sets, but Android supports several **simultaneously** through the Mu…</sub>
- [ ] **`D25-049`** USB `device_filter` auto-launch grants the app USB access with no permission prompt  
   <sub>``broken_access_control\` · AM-10/AM-11 physical (malicious ac · The filter declares the VID/PID an attacker must present. Accepting the launch dialog grants USB access **with…</sub>
- [ ] **`D25-050`** USB accessory matching is done on strings the accessory itself supplies  
   <sub>``cryptographic_weakness\` · AM-10/AM-11 physical · `accessory_filter.xml` matches on `manufacturer`, `model` and `version` — values the accessory sends during AO…</sub>
- [ ] **`D25-051`** BFU versus AFU — state which physical state your threat model assumes  
   <sub>``insecure_os_firmware\` · AM-10 physical locked (BFU) / AM-1 · Separate **BFU** (before first unlock — CE data still cryptographically protected) from **AFU** (after first u…</sub>
- [ ] **`D25-052`** AFU USB kernel surface — the lock screen is not the boundary  
   <sub>``physical_security_issues\` · AM-10 physical locked · In AFU state, forensic chains attack the **USB-reachable kernel surface** exposed while locked — HID, USB Audi…</sub>
- [ ] **`D25-053`** Biometric TA AuthToken forgery — root into PIN recovery  
   <sub>``cryptographic_weakness\` · AM-11 physical unlocked plus root; · Vendor biometric TAs that share the AuthToken HMAC trust domain with Gatekeeper and KeyMint can be abused to s…</sub>
- [ ] **`D25-054`** Target activity reachable over the lock screen  
   <sub>``broken_access_control\` · AM-10 physical locked · An activity that can show over the keyguard and then exposes data or a state-changing control is a lock-screen…</sub>
- [ ] **`D25-055`** NFC dispatch as a no-touch entry point into the app  
   <sub>``broken_access_control\` · AM-10/AM-11 physical proximity (<8 · Components registered for NFC dispatch **must** be exported, because the system delivers the intent, and they …</sub>
- [ ] **`D25-056`** HCE `HostApduService` — the payment category, and Android 15 observe mode  
   <sub>``broken_access_control\` · AM-02 remote one click (the user i · Two questions. (a) Does the app register a `HostApduService` in the `payment` category and ask to become the d…</sub>
- [ ] **`D25-057`** BLE link content is readable by every app on the device  
   <sub>``broken_authentication_and_session_management\` · AM-04 local app with one common pe · Google documents the channel as device-wide readable. If the app's BLE protocol carries tokens, health reading…</sub>
- [ ] **`D25-058`** The app's own GATT server accepts writes from an unbonded peer  
   <sub>``broken_access_control\` · AM-10 proximity, no app installed  · Apps exposing a GATT server for companion pairing, file transfer or "connect your watch" frequently register c…</sub>
- [ ] **`D25-059`** CompanionDeviceManager association with an attacker-controlled device, and `removeBond()`  
   <sub>``broken_access_control\` · AM-10 proximity; AM-03 for the exp · `CompanionDeviceManager.associate()` presents a picker of nearby devices filtered by name, MAC or UUID pattern…</sub>
- [ ] **`D25-060`** Scanner acting on `Barcode.getWifi()` — joining an attacker-chosen network on a scan  
   <sub>``insecure_data_transport\` · AM-02 remote one click (the user s · A scanner that supports the Wi-Fi barcode type (`WIFI:T:WPA;S:…;P:…;;`) can offer to join a network from a sca…</sub>

**🟧 High ceiling**

- [ ] **`D25-061`** Android Auto `CarAppService` with `ALLOW_ALL_HOSTS_VALIDATOR`  
   <sub>``broken_access_control\` · AM-03 zero-permission local app · The `CarAppService` is exported by necessity so the car host can bind it. The library's gate deciding *which* …</sub>

**⬜ Support ceiling**

- [ ] **`D25-062`** Wear OS `WearableListenerService` dispatching on path with no node or capability check  
   <sub>``broken_authentication_and_session_management\` · AM-03 (an app that can reach the D · The Wear Data Layer delivers `DataItem`s and messages addressed by **path** (`/sync`, `/auth`, `/logout`). The…</sub>
- [ ] **`D25-063`** The companion-surface API is a second, weaker client  
   <sub>``broken_access_control\` · AM-05 another user of the same app · Wear, Auto, TV and widget code paths frequently call *different* endpoints, or the same endpoints with a diffe…</sub>
- [ ] **`D25-064`** Instant-App reachability and the endpoints a retired instant experience left live  
   <sub>``broken_access_control\` · AM-01 remote no interaction (for t · Two halves. (a) **Reachability discipline:** do not claim browser-triggerable Instant-App reach for a componen…</sub>
- [ ] **`D25-065`** Enumerate every instance of the app that exists on the device  
   <sub>AM-05 / AM-11 · Every checklist assumes one install per device. On a real device the app may exist as user 0, a work profile (…</sub>
- [ ] **`D25-066`** Cross-user provider read and cross-user service bind  
   <sub>``broken_access_control\` · AM-05 another user of the same dev · Everything in every checklist binds and queries from user 0. A work profile, Private Space or OEM clone instan…</sub>

**🟧 High ceiling**

- [ ] **`D25-067`** Private Space boundary (Android 15)  
   <sub>``broken_access_control\` · AM-05 / AM-11 · Private space installs apps into a separate user profile that is hidden when locked. Two consequences: an app …</sub>

**⬜ Support ceiling**

- [ ] **`D25-068`** Work-profile data crossing the profile boundary  
   <sub>``broken_access_control\` · AM-05 / AM-11 · In a managed setup, confirm the app does not leak work data into the personal profile via clipboard, sharing i…</sub>
- [ ] **`D25-069`** App behaviour under a device-policy restriction it claims to honour  
   <sub>``broken_access_control\` · AM-11 physical unlocked (the enrol · Apply the policy restrictions the target claims to support — screen capture disabled, camera disabled, backup …</sub>

**🟥 Critical ceiling**

- [ ] **`D25-070`** Work-profile required-app replacement  
   <sub>``broken_access_control\` · AM-11 physical unlocked (temporary · An MDM that marks an app *required* for the work profile auto-installs it if missing. Combined with Android St…</sub>

**🟧 High ceiling**

- [ ] **`D25-071`** Device Policy Controller removal and enterprise-control bypass  
   <sub>``broken_access_control\` · AM-11 physical unlocked; AM-03 whe · Whether a managed device's DPC can be removed, or its policies neutered, without authorisation — including thr…</sub>

**⬜ Support ceiling**

- [ ] **`D25-072`** Kiosk, lock-task and screen-pinning escape from inside the app  
   <sub>``insecure_os_firmware\` · AM-11 physical unlocked (a member  · Where the app runs as a kiosk or is used under screen pinning, look for a path out — a WebView that opens an e…</sub>
- [ ] **`D25-073`** OEM MDM and firmware layers (Knox, E-FOTA and equivalents), and the null-means-compliant trap  
   <sub>``broken_access_control\` · AM-03 / AM-11 · Where the app relies on an OEM container or policy API, check whether its assumptions hold when that layer is …</sub>
- [ ] **`D25-074`** Device-admin or accessibility status obtainable without informed consent  
   <sub>``broken_access_control\` · AM-02 remote one click · Whether the app's own flows, or a TapTrap-style animation attack against them, can result in Device Administra…</sub>

**🟥 Critical ceiling**

- [ ] **`D25-075`** Mobile foothold as an enterprise pivot  
   <sub>``sensitive_data_exposure\` · AM-03 / AM-11 · For an enterprise or BYOD app, assess whether compromising the app yields corporate credentials, VPN profiles …</sub>

**⬜ Support ceiling**

- [ ] **`D25-076`** Run the pre-severity gate against the Critical claim, not against the primitive  
   <sub>This domain produces more mid-chain primitives than any other — a policy rule, a reachable service, an exporte…</sub>
- [ ] **`D25-077`** Body-diff, layer-ordering and server-policy-vs-state gates on privileged-surface probes  
   <sub>Four false positives dominate this domain, and all four look like a bypass.</sub>
- [ ] **`D25-078`** Chain-filing order, evidence hygiene and retraction discipline for a device chain  
   <sub>Device chains are long — a policy rule, an exported component, a file write, an install — and each link usuall…</sub>
- [ ] **`D25-079`** Never instrument production hardware; record the root path you used  
   <sub>AM-12 (own device; not an attack) · A rooted device changes the validity of every resilience claim and most device claims. Obtain root explicitly …</sub>

<details><summary>⚰️ D25 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The bootloader on my test device is unlocked / `verifiedbootstate=orange`" | You unlocked it. AM-12 is not an attacker. Samsung lists "reports requiring enabling Developer Mode persistently on the device" as an explicit downgrade factor | The **client's own deployment** requires an unlocked bootloader or a disabled Verified Boot to function (D25-042), or a production retail unit ships orange |
| "The device runs an old kernel / the security patch level is behind" | Version disclosure with no demonstrated reachability. Every vendor excludes "vulnerabilities that do not work on the latest available operating system version" | A specific CVE in that kernel, reached from an app UID, with the reachability shown — then it is D16 with D25 context |
| "SELinux is permissive" — on an emulator or a `userdebug` build | Expected on non-`user` builds. `permissive=1` on `userdebug` is the platform working as designed | A permissive domain on a **`user` build** of a retail device (D25-028), with a `neverallow` cited and the impact exercised |
| "`adb shell service call <vendor> N` returned data" | The `shell` UID has permissions and an SELinux domain no app has. The corpus is explicit: always re-prove from an ordinary third-party app UID | The same transaction succeeding from a zero-permission PoC APK, with `ps -AZ` showing it in `untrusted_app_NN` (D25-005) |
| "`sesearch` shows an OEM `allow` rule that AOSP does not have" | A policy rule is a capability, not a bug. An unexercised `allow` line is a hardening note | An app that uses the rule, fired, with the effect demonstrated (D25-027) |
| "There is an exported component in a preinstalled OEM app" | Exported is intended behaviour; the finding is the unauthorised access it grants | The component driven from a zero-permission app to produce a privileged effect (D25-017) |
| "I found a root exploit / I rooted the device" | Rooting your own device is not an attack on the app, and most programmes exclude root-required findings outright | The root was obtained **from an app UID** with no user interaction on a stock, locked, enforcing retail device |
| "The app's data is readable once I have root" | Root defeats the sandbox by definition. Xiaomi, Grab and Spotify all exclude "sensitive data stored in the app private directory" | A non-root reader — a debuggable build (D25-014), a cross-user path (D25-066), or a backup/extraction path |
| "`allowBackup="true"` on an OEM build" | P5 everywhere and excluded by name at Google and Xiaomi; VRT `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5** with a physical-vector, high-privilege CVSS baseline | The credential you actually extracted from the backup and replayed (D11/D13) |
| "Firmware is not encrypted" | VRT `insecure_os_firmware\|weakness_in_firmware_updates\|firmware_is_not_encrypted` = **P5**. Obscurity was never the control | The update is not *integrity*-validated (D25-040), which is a different node at P3 and argues upward |
| "The OEM image contains 40 preinstalled apps with dangerous permissions" | An inventory is not a finding, and the permission set is the OEM's product decision | One of them exporting a component that re-delegates the permission to a zero-permission caller (D25-009, D25-017) |
| "This OEM bug is Critical" — filed against the app client | Wrong programme. It is the OEM's bug and the app client cannot fix it | Two artefacts: an environmental-risk note to the app client, and a separate report to the OEM's VRP (D25-001) |
| "Malformed USB/NFC/BLE input crashes the app" | VRT `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**; Xiaomi, Grab and Spotify all exclude crash-only reports; "a valid exploit must achieve arbitrary code execution, not just trigger an application crash" | A controlled write with an attacker-controlled fault address, quoted from the tombstone (D25-049, D16) — or a persistent DoS requiring a factory reset |
| "A companion endpoint is on `/v1` while the web app uses `/v3`" | A version difference alone is Informational. The bug is the delta, not the number | A behavioural regression on the older path — weaker auth, no throttling, wider field set — shown side by side (D25-063) |
| "The app has no jailbreak/root detection" and "the device has no lock screen set" | `lack_of_binary_hardening.lack_of_jailbreak_detection` = **P5**; MASTG-TEST-0247 itself notes apps "cannot force users to enable biometrics at the system level, only enforce their use within the app" | The app stores auth-bound keys and never calls `isDeviceSecure()`/`canAuthenticate()`, on a financial or health app where a stolen unlocked device yields the account (MASWE-0017) — Medium, not High |
| "The device exposes MTP when plugged in" | MTP is the modern default and is gated behind unlock on current builds | A data function reachable **while locked** that reaches a parser (D25-048, D25-052) |
| "Work data can be pasted into the personal profile" | Cross-profile sharing is intended unless a restriction is configured | `DISALLOW_CROSS_PROFILE_COPY_PASTE` explicitly configured and the paste still succeeding (D25-068) |

</details>


<details><summary>🔗 D25 cross-surface joins — park these, chase them in P7</summary>

- **`privapp-permissions` enforcement (D25-010) × an exported component in the same package (D04–D08).**
  Nobody reads the allowlist file and nobody re-rates an exported activity by the *permissions its
  package actually holds*. The join is: `ro.control_privapp_permissions=log` means a privileged permission
  was granted that the platform itself flagged as un-allowlisted, and the exported activity in that
  package is now the delegation route to it. Neither half is a finding alone; together they are the OEM
  escalation class.
- **`sharedUserId` (D25-012) × the sibling's exported surface (D06/D07).** Reviewers audit the target's
  own components and stop. The weakest app in the UID group defines the security of all of them — so the
  right question is not "is *this* app's provider exported" but "is any provider in this UID exported",
  and the answer is frequently yes in a package nobody in the engagement has opened. This is exactly the
  Samsung SecSettings shape.
- **USB `device_filter` auto-launch (D25-049) × the native parser behind it (D16).** USB is reviewed as a
  permissions question ("does the app ask for USB access?") and native code is reviewed as a reachability
  question ("can an attacker reach this parser?"). The join answers both at once: the platform *grants*
  USB access automatically on filter match, so an attacker-built gadget with the declared VID/PID feeds
  attacker-controlled bytes straight into the app's native parser with no network, no app install and no
  permission prompt.
- **Wear OS path routing (D25-062) × the authentication state machine (D13).** Auth reviewers test the
  login screen, the OTP endpoint and the biometric gate. Nobody tests the `/auth`-prefixed Data Layer
  path, because it is not a screen and not an HTTP endpoint. A phone app that enters an authenticated
  state because a *message path* said so is an authentication bypass with no credential involved at all.
- **Android Auto `ALLOW_ALL_HOSTS_VALIDATOR` (D25-061) × the account data the car templates render
  (D15/D20).** The Auto integration is reviewed, if at all, as a UI feature. Bind it from an unprivileged
  app and every template the app renders — trips, saved places, vehicle, payment method — is readable
  without the phone UI, without the lock screen, and without a single permission.
- **Cross-user reach (D25-066) × the `getCallingUid()` guard (D03/D06).** Every IPC reviewer checks that
  the service interrogates the caller. Almost nobody checks that it compares
  `UserHandle.getUserId(uid)` — so a *clone of the same app* in a work profile or a Private Space passes
  a same-signature or same-UID check trivially. The join turns a correct-looking guard into a
  cross-account data path.
- **Preinstalled-app privilege (D25-008/D25-009) × the logcat leak (D20).** The standard closure for a
  logcat finding is "requires a privileged permission". Enumerating the actual `READ_LOGS` holders on the
  client's real device demographic (D25-015) converts that closure into a named attacker, which is the
  single highest-leverage rewrite available for a whole class of D20 findings.
- **Dialler secret code (D25-045) × the staging-backend switch (D14/D21).** Secret codes are catalogued as
  a curiosity and pinning is tested as a transport question. A code that flips the app to a staging
  backend or disables pinning is a complete MitM primitive that requires neither a proxy CA nor root — and
  it can be fired as a broadcast, removing the physical precondition entirely.
- **Instant-app remnants (D25-064) × the deep links that used to launch them (D09).** The client is dead,
  so nobody looks. But the installed app still declares the URL patterns the instant experience used, and
  those handlers were written for a permission-light, unauthenticated context. A live App Link into an
  instant-era handler is an auth-skip nobody has tested since 2021.
- **Device-policy restriction (D25-069) × the app's own screen-capture defences (D20).** The MDM
  reviewer tests whether the policy is set; the app reviewer tests whether `FLAG_SECURE` is present. The
  join is the app rendering a payment or PIN screen that honours neither, in a managed profile where the
  client believes screen capture is disabled fleet-wide.

</details>


---

## D26 Runtime Instrumentation, Tooling & Harness

**Phase P1 · `M1` · 79 items** — 🟨 7 medium · ⬜ 72 support  

📄 Full detail, with every command and proof: [`checklist/D26-instrumentation-and-tooling.md`](checklist/D26-instrumentation-and-tooling.md)

> **Crux question.** **Before I write "not vulnerable" anywhere in this report: has this exact instrument produced a positive result on this exact device in this session — and if the answer is "the tool printed nothing", what is my positive control?**

It does not pay directly, and any chapter that pretends otherwise is selling you a P5. Bugcrowd prices
runtime instrumentation at P5 with an all-zero impact vector; Google's Mobile VRP excludes "attacks that
require a rooted device"; Xiaomi, Grab and Spotify exclude "runtime hacking exploits using tools like
Frida/Appmon" by name. If your report contains the sentence "we were able to attach Frida and bypass the
root check", you have written an invoice for nothing.


**⬜ Support ceiling**

- [ ] **`D26-001`** Run a green-baseline harness acceptance script before any billable testing  
   <sub>`none — the gate that decides whether every other chapter's negative is defensi` · AM-12 (own device; not an attack) · Prove, with a positive control, that the lab can actually produce the observations you are about to rely on: r…</sub>
- [ ] **`D26-002`** Pin and record the lab manifest so the engagement is reproducible a year later  
   <sub>AM-12 · Record exactly which binaries, images and patch levels produced the results, so a retest is a mirror copy of t…</sub>
- [ ] **`D26-003`** Check all three rootable-AVD constraints before promising root-dependent work  
   <sub>AM-12 · Three *independent* constraints decide whether an AVD can be rooted at all. Check all three before quoting any…</sub>
- [ ] **`D26-004`** Install the proxy CA into the system store — API 33 and below  
   <sub>`none; note `mobile_security_misconfiguration.ssl_certificate_pinning.defeatabl` · AM-07 network attacker with a trus · Put the proxy CA where a `targetSdk >= 24` app will actually trust it, and route traffic.</sub>
- [ ] **`D26-005`** API 34+: the Conscrypt APEX trust store and the zygote mount-namespace bind  
   <sub>AM-07 (tester convenience, not an  · On API 34+ the system trust store lives in the updatable Conscrypt APEX and `/system/etc/security/cacerts` is …</sub>
- [ ] **`D26-006`** Verify which trust store the target process actually sees, not which one your shell sees  
   <sub>AM-12 · The adb shell and the target app live in different mount namespaces. Confirm the app's own view before you acc…</sub>
- [ ] **`D26-007`** `system.certs.enabled` — the per-process switch back to the legacy trust store  
   <sub>AM-12 · Where namespace surgery is impractical, flip the app's own Conscrypt source back to `$ANDROID_ROOT/etc/securit…</sub>
- [ ] **`D26-008`** Non-root MitM: repack with a network security config that trusts user CAs  
   <sub>AM-07 (tester convenience) · When no rootable image is available, add a debug-friendly NSC and re-sign.</sub>
- [ ] **`D26-009`** Non-root instrumentation: objection `patchapk` / Frida gadget injection  
   <sub>`none — but it removes the "requires root" discount, which is worth one to two ` · AM-12 becoming AM-11 (physical unl · Embed the Frida gadget in the APK so instrumentation works with no device compromise, which materially changes…</sub>
- [ ] **`D26-010`** Lock Frida client, server and ABI versions — and prove it with a control hook  
   <sub>AM-12 · A version or ABI mismatch fails in ways that look exactly like target hardening — attach hangs, `frida-ps -U` …</sub>
- [ ] **`D26-011`** Frida 17+ moved the Java bridge out of GumJS — an agent with no `Java` object records nothing  
   <sub>AM-12 · Confirm the `Java` namespace exists in your agent before concluding a Java hook "did not fire".</sub>
- [ ] **`D26-012`** Run the two-device lab: rooted device for discovery, stock device for proof  
   <sub>`none directly; it is what moves a finding off `lack_of_binary_hardening.*` (P5` · AM-12 for the research device; the · Keep two devices with the same account and the same build. Discover on the rooted one; prove on the stock one.…</sub>
- [ ] **`D26-013`** Physical-device lane: wireless debugging, the two-port trap, and the proxy path  
   <sub>AM-12 · Two-device evidence (attacker phone + victim phone) needs the USB port free and a second device recording. On …</sub>
- [ ] **`D26-014`** Publish the device-capability matrix — decide up front what the emulator cannot answer  
   <sub>`none — its purpose is to stop you filing emulator artefacts as findings` · AM-12 · State, before testing, which classes the emulator cannot authoritatively answer, so those rows become priced o…</sub>
- [ ] **`D26-015`** Per-engagement clean device state, and the target-state restoration inventory  
   <sub>AM-12 · Engagement N+1 must not run on a device still carrying engagement N's attacker APKs, hooks, CA binds, accounts…</sub>
- [ ] **`D26-016`** Clock discipline across host, device and proxy, or the evidence does not correlate  
   <sub>AM-12 · A finding's proof is usually three streams that must line up — screen recording, `logcat`, and the proxy's flo…</sub>
- [ ] **`D26-017`** Keep a symptom-keyed harness failure runbook  
   <sub>AM-12 · Index the traps by **the observable the tester actually sees**, so a junior tester resolves in minutes what a …</sub>
- [ ] **`D26-018`** Pull the complete split set before any static tool runs  
   <sub>`none — but missing a split causes false negatives on every P1 in D04–D09 and D` · AM-12 · Apps shipped as an AAB install as `base.apk` plus `config.*.apk` splits. Manifest entries, native libraries an…</sub>
- [ ] **`D26-019`** jadx: the flags that matter, and the two-decompiler cross-check rule  
   <sub>AM-12 · Decompile once, keep the output for the whole engagement, and never treat a single tool's failure as evidence …</sub>
- [ ] **`D26-020`** apktool: `-s`, `-r`, `--force-manifest`, and the `<uses-sdk>` that it drops  
   <sub>AM-12 · Use apktool for the decoded manifest, the resources and the smali patch loop — and know the one thing it silen…</sub>
- [ ] **`D26-021`** aapt2 `dump badging` / `dump xmltree` as the manifest ground truth  
   <sub>AM-12 · Read identity, SDK levels, permissions and manifest attributes from the binary manifest rather than from a dec…</sub>
- [ ] **`D26-022`** `apksigner verify --print-certs`: signer identity and which schemes actually cover the file  
   <sub>`none in this chapter; the consumer is D02/D17` · AM-12 · Establish who signed the artefact you are analysing, and prove it is the same artefact the store ships — befor…</sub>
- [ ] **`D26-023`** APKiD: fingerprint compiler, obfuscator, packer and anti-analysis before budgeting  
   <sub>`none — **"the app is not obfuscated" is never reportable**` · AM-12 · Three seconds of fingerprinting tells you whether the next three days are jadx reading or snapshot recovery, a…</sub>
- [ ] **`D26-024`** apkleaks and apkurlgrep: the secret/endpoint sweep, and the liveness rule that gives it a severity  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-01 remote no interaction (the A · Sweep the DEX, native libraries and resources for endpoint and credential-shaped strings, including inside thi…</sub>
- [ ] **`D26-025`** semgrep with the MASTG rule set as a checklist source  
   <sub>`none — every hit is a hypothesis routed to another chapter` · AM-12 · Run the canonical MASTG rules over the decompiled sources. They are the grep patterns the rest of this methodo…</sub>
- [ ] **`D26-026`** mobsfscan and the mindedsecurity rule set, ranked by impact × confidence  
   <sub>AM-12 · These two rule sets together encode several hundred of the checks in this methodology. Use them to build the w…</sub>
- [ ] **`D26-027`** MobSF as a coverage net, never as the report  
   <sub>`none. **Submitting raw scanner output is the fastest route to a duplicate-or-N` · AM-12 · Run the automated pass to catch what your manual review missed, then verify every hit by hand.</sub>
- [ ] **`D26-028`** MobSF assisted dynamic analysis, and "Capture String Comparisons"  
   <sub>`rated by what the recovered comparison protects — `broken_authentication_and_s` · AM-12 for capture; **must be conve · MobSF's dynamic analyser runs a broad first pass while you learn the app. Its most valuable single feature is …</sub>

**🟨 Medium ceiling**

- [ ] **`D26-029`** Anchor on strings, resources and JNI exports when R8 has renamed every class  
   <sub>`rated by the SDK behaviour you then prove reachable; the anchoring itself is S` · AM-12 for the technique; the resul · With R8 renaming, grepping for an SDK's class name fails. Anchor on the three things R8 does **not** rename — …</sub>

**⬜ Support ceiling**

- [ ] **`D26-030`** Establish the drozer session and record the agent's own privilege ceiling first  
   <sub>`none — it is what makes every later drozer negative admissible` · AM-03 zero-permission local app (t · Stand up the console/agent pair, then immediately record what permissions the **agent** holds. Every drozer mo…</sub>
- [ ] **`D26-031`** Tag drozer `[DEGRADED]` and state its two modern blockers in the report  
   <sub>AM-03 · Two platform changes make drozer's enumeration output misleading unless you state them.</sub>
- [ ] **`D26-032`** The `app.*` module reference, mapped to what each module PROVES  
   <sub>`routed: `broken_access_control.exposed_sensitive_android_intent` (**null — rat` · AM-03 zero-permission local app · Use the module that proves the claim you intend to make, not the one you remember.</sub>
- [ ] **`D26-033`** The `scanner.*` blind spots, read from source — and why you must probe manually anyway  
   <sub>``server_side_injection.sql_injection` (P1) or `broken_access_control.idor.view` · AM-03 · The drozer scanners use single hardcoded probes. Know each one's blind spot, and run the manual equivalent aga…</sub>
- [ ] **`D26-034`** drozer 3.1.0: `scanner.provider.exported` and `app.provider.grant`  
   <sub>`routed to D07` · AM-03 · On modern targets the older modules mis-report two classes: providers that are declared but not exported, and …</sub>

**🟨 Medium ceiling**

- [ ] **`D26-035`** The community drozer modules, and reading their declared permissions before believing them  
   <sub>`routed: `sensitive_data_exposure.*` for the `post.*` capture modules; `cloud_s` · AM-04 local app + one common permi · Install the community set with `module install <path>`, and read each module's `permissions =` declaration bef…</sub>

**⬜ Support ceiling**

- [ ] **`D26-036`** `adb shell content` / `cmd content` — the agent-free provider client that reads better at triage  
   <sub>`routed to D07: `broken_access_control.idor.view_sensitive_information_iterable` · shell UID 2000 for the command; ** · Prove a provider is reachable with no tooling at all. It reads better at triage than a drozer screenshot and r…</sub>

**🟨 Medium ceiling**

- [ ] **`D26-037`** Use the device as a network pivot into the app's internal network  
   <sub>``cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4), ` · AM-04 local app with `INTERNET` on · Where the app talks to an internal host reachable only from the device's network, prove that reachability from…</sub>

**⬜ Support ceiling**

- [ ] **`D26-038`** Sweep the device for debuggable packages and check JDWP acceptance  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) — JD` · AM-11 physical unlocked, or AM-04  · Sweep the whole device, not just the target — a debuggable *sibling* app that shares a `sharedUserId` or holds…</sub>
- [ ] **`D26-039`** Ship the PoC as a replayable command file, not as prose  
   <sub>`none — but Google's Mobile VRP prices report quality at a 0.5x / 1x / **1.5x**` · Package the exploit path so a triager reproduces it in one paste, unattended.</sub>
- [ ] **`D26-040`** `dozermapper/dozer` is a Java bean mapper — it is not this tool  
   <sub>Strike "dozer" from any tooling list. Several circulating community checklists cite `dozermapper/dozer` for mo…</sub>
- [ ] **`D26-041`** Choose spawn or attach deliberately — `-f`, `-N`, `-p`, `-W` reach different code  
   <sub>AM-12 · Spawning catches `Application.onCreate`-time behaviour — key derivation, pinning setup, root checks, anti-tamp…</sub>
- [ ] **`D26-042`** `Java.available` versus `Java.perform` — pick the right guard  
   <sub>AM-12 · Use the correct guard, or the script dies on the wrong OS and you spend the morning debugging the target inste…</sub>
- [ ] **`D26-043`** Hooking an abstract framework class records NOTHING — hook the concrete type  
   <sub>`none; the cost is a **false negative** on a D10/D11/D06 finding` · AM-12 · Zero events from a hook on a framework base class is a **false negative**, not a result. Print `$className` of…</sub>
- [ ] **`D26-044`** Prefer `Java.choose` on live objects over intercepting setters  
   <sub>`none; the cost is a false negative` · AM-12 · A setter hook only catches calls made **after** the hook lands. Splash screens, `Application.onCreate` and lib…</sub>
- [ ] **`D26-045`** Deoptimise the VM when a hook on a hot method demonstrably does not fire  
   <sub>`none; the cost is the false claim "the app does not call X"` · AM-12 · If a method you can see in jadx is provably executing — the app behaves as though it ran — but your hook print…</sub>
- [ ] **`D26-046`** Blanket-trace Java with `frida-trace -j` to find the method that touches your data  
   <sub>`none standalone; it is the enabling step for High/Critical findings in D09, D1` · AM-12 · On a large or obfuscated app, locate the handler for a value you control by tracing wide and grepping the trac…</sub>
- [ ] **`D26-047`** `frida-trace` reporting "Started tracing 0 functions" is a load-order artefact  
   <sub>AM-12 · When a `-j` pattern matches nothing on spawn, re-run attached to the live PID before concluding the class does…</sub>
- [ ] **`D26-048`** Reach classes in secondary dex and custom class loaders  
   <sub>`routed to D17` · AM-12 · `Java.use` resolves against the default class factory only. A class loaded by a different loader is invisible …</sub>
- [ ] **`D26-049`** The six Frida corrections that each cost a working day  
   <sub>AM-12 · Six specific, recurring corrections. Each one produced a wrong conclusion before it was known.</sub>
- [ ] **`D26-050`** objection as the pre-built hook harness — with job discipline and the sqlite caveat  
   <sub>`none. A pinning bypass is a *technique*; `mobile_security_misconfiguration.ssl` · AM-12 · Get instant coverage of the common hooks, then verify you are not stacking conflicting jobs — a root bypass th…</sub>
- [ ] **`D26-051`** Strip `FLAG_SECURE` so the evidence can actually be captured  
   <sub>`none. `mobile_security_misconfiguration.*` and `insecure_data_storage.screen_c` · AM-12 (evidence capture only) · `FLAG_SECURE` blocks screenshots, remote displays and recents snapshots — including the evidence a triager nee…</sub>
- [ ] **`D26-052`** Inject StrictMode's own detectors and let the app find its unsafe intent launches for you  
   <sub>`routed to D08: `broken_access_control.exposed_sensitive_android_intent` (**nul` · AM-03 zero-permission local app fo · Rather than reading code for nested-intent launches, make the app report them. Inject the detector at process …</sub>

**🟨 Medium ceiling**

- [ ] **`D26-053`** Instrument the binder layer, not only the Java API  
   <sub>`routed to D06/D08` · AM-12 for observation; AM-03 for t · Hooking `BinderProxy.transact` and `Binder.execTransact` gives you every IPC the app makes and every one it se…</sub>

**⬜ Support ceiling**

- [ ] **`D26-054`** The one-file framework-API hook pack for obfuscated apps  
   <sub>`routed: `cryptographic_weakness.key_reuse.inter_environment` (P2) for captured` · AM-12 for capture; convert before  · Instrument the framework APIs every bug class funnels through, so one trace file becomes the evidence trail fo…</sub>
- [ ] **`D26-055`** Force a stack trace at the sink to supply the reachability argument  
   <sub>`none; it is what converts "this method is dangerous" into "this method is reac` · AM-12 for capture · When you have a sink — a network call, a crypto method, a file write — but not the path that reaches it, force…</sub>

**🟨 Medium ceiling**

- [ ] **`D26-056`** JDWP and `jdb` — the Frida-free path when instrumentation is detected  
   <sub>`routed to whatever the read variable protects (D10 bridge allow-list, D13 gate` · AM-11 physical unlocked · When Frida is detected or the app crashes under instrumentation, break in the validator and read exactly what …</sub>

**⬜ Support ceiling**

- [ ] **`D26-057`** Syscall and file-operation tracing as the ground truth under the Java API  
   <sub>`routed to D11/D16/D21` · AM-12 · Catch behaviour that never crosses a Java API — native file access, root checks, WebView internals, linker- an…</sub>
- [ ] **`D26-058`** jnitrace for the JNI boundary  
   <sub>`routed to D16/D12` · AM-12 · When the Java side hands work to native code, trace the boundary rather than reversing the library first. jnit…</sub>
- [ ] **`D26-059`** r2frida and rabin2 for the live native process  
   <sub>`routed to D16/D21` · AM-12 · When static analysis leaves the question "what value does this actually get at runtime?", attach to the live, …</sub>
- [ ] **`D26-060`** The cross-platform instrumentation matrix — one entry point per framework  
   <sub>`routed to D19` · AM-12 · Each framework needs a different instrumentation entry point, and the wrong one produces silence that looks li…</sub>
- [ ] **`D26-061`** Native fuzzing harness: pick the engine by what you have, and ship the Android ASan runtime  
   <sub>`routed to D16/D25 and rated on the reachable crash: `application_level_denial_` · AM-03 or AM-09 depending on where  · Choose the engine from the constraint, not from fashion, and make the bug oracle work before you burn CPU. Mob…</sub>
- [ ] **`D26-062`** Carry the validity-tagged tooling table, and the DEAD list, so you downgrade correctly  
   <sub>`none — every row exists to stop you filing a P5 or a non-issue` · Reach for the right primitive first, and tag anything degraded in the report. Two standing rules for every `[D…</sub>

**🟨 Medium ceiling**

- [ ] **`D26-063`** A tool's silence is never a negative result — calibrate against a known-vulnerable control  
   <sub>`none; it prevents shipping a false clean that leaves an exploitable component ` · **A zero is only a negative once the instrument is proven able to produce a positive.** Before any "not vulner…</sub>

**⬜ Support ceiling**

- [ ] **`D26-064`** Control-app comparison — separate app behaviour from platform default  
   <sub>`none; it is the cheapest false-positive filter available` · Many "findings" are the platform doing what it always does — backup semantics, recents screenshots, clipboard,…</sub>
- [ ] **`D26-065`** Reproduce the final PoC from a real app UID, never from `adb shell`  
   <sub>`none; it is what separates a rated finding from a rejected one` · converts AM-12 -> AM-03 · `adb shell` runs as uid 2000 in the `shell` SELinux domain — **more** privileged than a third-party app on som…</sub>
- [ ] **`D26-066`** Prove your attacker app is actually as weak as you claim  
   <sub>`none; it decides whether a High is paid or closed` · n/a — it is the *proof* of the att · Reports die on the claim "a malicious app with no permissions can do X" when the PoC APK quietly requests `QUE…</sub>
- [ ] **`D26-067`** The Shell-Loop Ban — count your results  
   <sub>zsh and bash array expansion fails **silently** on edge cases. `for x in "${arr[@]}"` can produce zero iterati…</sub>
- [ ] **`D26-068`** Marker Discipline — search the BASELINE for your marker before claiming reflection  
   <sub>`none; it is the single check that kills most false-positive reflection reports` · The injected marker must be unique and unmistakable, or your "reflection" is a word collision.</sub>
- [ ] **`D26-069`** The Body-Diff Rule — a byte-identical 200 is not a bypass  
   <sub>`none. **Status-code-only claims are the most common rejected-as-N/A category o` · A bypass claim requires a response **body** differential, not a status code.</sub>
- [ ] **`D26-070`** The Statistical-Sample Rule — n >= 10 interleaved, >= 2 sigma  
   <sub>Single outliers are not signal. Network jitter routinely produces 2x outliers, and a mobile client's own retry…</sub>
- [ ] **`D26-071`** Server-Policy-vs-State — is the differentiator tracking your input, or a fixed deny-list?  
   <sub>A server-side policy that always denies is not a state oracle. Establish whether the differentiator tracks *yo…</sub>
- [ ] **`D26-072`** The Multi-Tool Reproduction Bar for anything you call Critical or High  
   <sub>`none; it governs every Critical/High claim in the report` · Before labelling anything Critical or High, reproduce it via **two independent tools with different HTTP stack…</sub>
- [ ] **`D26-073`** Repeat-count and cold-start discipline for every dynamic claim  
   <sub>A one-shot observation on a warm app with a populated cache is the commonest source of a finding the client's …</sub>
- [ ] **`D26-074`** Warm-start discipline for component sweeps — do **not** `force-stop` before each launch  
   <sub>This is the exact inverse of D26-073 and the distinction matters. `force-stop` routes the next cold start **th…</sub>
- [ ] **`D26-075`** One normaliser, shared by every tool in the engagement  
   <sub>Two harnesses with different normalisation will disagree about whether a response changed, and you will spend …</sub>
- [ ] **`D26-076`** Capture the mobile client and the web client in one proxy project — the shadow-API harness  
   <sub>``broken_access_control.idor.modify_view_sensitive_information_iterable_object_` · AM-01 remote no interaction (the e · A mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, …</sub>

**🟨 Medium ceiling**

- [ ] **`D26-077`** Run a scripted full-feature tour so no screen is left unvisited  
   <sub>`none directly; it is the control that prevents an entire feature — and its bug` · AM-12 · Guarantee that every feature was driven at least once with instrumentation on, and produce the literal list of…</sub>

**⬜ Support ceiling**

- [ ] **`D26-078`** Keep the evidence workspace and the command journal from the first minute  
   <sub>At retest, or when a developer disputes a step, the tester reconstructs from memory — and that is where invent…</sub>
- [ ] **`D26-079`** Calibrate the harness against a known-vulnerable app before touching the client build  
   <sub>Verify each harness capability end to end on an app whose bug you already know, so a negative on the client bu…</sub>

<details><summary>⚰️ D26 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Frida attaches to the app / the app has no anti-instrumentation" | `lack_of_binary_hardening.runtime_instrumentation_based` = **P5**, all-zero impact vector. AM-12 is not an attacker model, and Google, Xiaomi, Grab and Spotify all exclude "runtime hacking exploits using tools like Frida/Appmon" by name | The credential the hook extracted, proved to authenticate a *different* user or to work off the device — filed in D13/D15, not here |
| "objection disabled SSL pinning in five minutes" | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` = **P5**. The bypass is the method, never the finding | The data the decrypted channel revealed, or the server accepting a request the app would never send — filed in D14/D15 |
| "The APK can be repackaged and re-signed so I injected the gadget" | The repackaged app attacks only its own installer. This is your patch, not the vendor's defect | A distribution channel you can poison so the repacked build reaches **other** users — that is D17 |
| "`isInsideSecureHardware()` returns false" on an AVD | The emulator's keystore is software-backed. A harness artefact (D26-014) | The same observation on a **physical** device, or the server accepting a software-rooted attestation chain for a hardware-gated action — D12/D21 |
| "Play Integrity returns an empty verdict on my device" | Rooted and emulated devices produce an empty verdict by design | The **server** accepting a request carrying no verdict at all, or one bound to nothing — D21 |
| "`adb backup` produced an empty archive" | Android 12+ excludes app data from `adb backup` unless `android:debuggable="true"`. An expected default | Data extracted through `bmgr` + the local or D2D transport, which is the current technique — D11 |
| "drozer reported no exported components" | On `targetSdk >= 31` every component with an intent-filter must declare `android:exported`, so this is the **platform default**. On `targetSdk >= 30` the agent also needs `QUERY_ALL_PACKAGES` or it sees a truncated view | The merged manifest and `dumpsys package` resolver tables read by hand, showing a component drozer could not see — D03/D04 |
| "`scanner.provider.injection` says Not Vulnerable" | It probes a single `'` and flags only on `unrecognized token` in the exception text. Any provider that catches or rewraps its exception reads clean | A manual `app.provider.query --projection "'"` and a `UNION SELECT`, plus a traversal to a path other than `/etc/hosts` — D07 (D26-033) |
| "MobSF/mobsfscan/semgrep produced 60 findings" | Scanner output is a hypothesis list. Submitting it raw is the fastest route to duplicate-or-N/A on every platform, and on a mature programme the easy hits are already filed | Each hit reproduced by hand with the observable its owning chapter names, and the guard the rule could not see recorded for the ones that fall away |
| "The app is not obfuscated / APKiD found no packer" | `lack_of_binary_hardening.lack_of_obfuscation` = **P5**. MASVS is explicit that the absence of MAS-R measures does not inherently introduce a vulnerability | The business rule you read out of the decompile — a fraud threshold, a velocity limit, an allowlist of privileged account ids — D21/D23 |
| "`adb root` is refused: `adbd cannot run as root in production builds`" | A property of `user` builds and of `google_apis_playstore` images. A harness fact | Nothing. Record it in the methodology and pick a `google_apis` image (D26-003) |
| "The system CA push to `/system/etc/security/cacerts` succeeded but TLS still fails on every host" | On API 34+ that directory is ignored at runtime; this is the classic false "the app pins everything" | Per-host TLS failure **after** the Conscrypt APEX bind and the zygote `nsenter` are verified from inside the app's namespace (D26-005, D26-006) — then it really is pinning, and it is still P5 |
| "I can read `/data/data/<pkg>/shared_prefs/auth.xml` as root" | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` = **P5**; the sandbox holds against everyone except the device owner | The token authenticating a **different** account from your own machine, or a non-root path to the same bytes (backup, exported provider, debuggable build) — D11 |
| "The app sets `FLAG_SECURE` so I had to strip it to record the PoC" | The app behaving correctly. `insecure_data_storage.screen_caching_enabled` = P5 even when it is absent | Nothing about the flag. The finding is whatever the recorded screen shows — D20/D27 |
| "`dozermapper/dozer` is a mobile pentest tool" | It is a Java Bean-to-Java Bean mapper with no Android-security relevance. The Android tool is **drozer** | Nothing. Fix the citation (D26-040) |
| "`adb shell monkey` crashed the app 40 times" | A crude crash-fuzzer with no security signal, and `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5** anyway | A crash reachable from a **third-party app's** crafted Intent that corrupts state or persists (a crash loop that survives restart) — D04/D17, and still rated on impact |
| "A tool printed nothing, therefore the app is clean" | The four documented silent-zero sources (abstract class, R8 rename, init-time path, narrow scanner probe) each produce exactly this output | A positive control fired in the same session, cited next to the negative in the ruled-out register (D26-063) |
| "I bypassed the client-side premium check with `hooking set return_value`" | A client-side gate flipped on your own device. The UI changing proves nothing | The **subsequent API calls** succeeding server-side — D23/D15, with a body diff (D26-069) |
| "The mobile app uses `/v1` and the website uses `/v3`" | A version difference alone is Informational | The **weakened control** on the older path: unauthenticated read, cross-account object access, absent rate limit, mass-assignable field, extra exposed fields — D15 (D26-076) |
| "Response timing differed by 800 ms for a valid username" | A single outlier. Network jitter routinely produces 2x outliers | n >= 10 interleaved trials showing the suspect group's mean >= 2 sigma above control, with the distribution in the report (D26-070) |
| "The request returned 200 instead of 403 with my header" | Status-code-only claims are the most common rejected-as-N/A category. A byte-identical body is not a bypass | A body differential after normalisation, with the changed content identified (D26-069) |
| "Cydia Substrate / Xposed / AndroidSSLTrustKiller / QARK did not work" | All DEAD on modern Android (D26-062). A failed legacy technique is not evidence the app is secure | Nothing from the failure. Re-test with the current tool and report what *that* shows |

</details>


<details><summary>🔗 D26 cross-surface joins — park these, chase them in P7</summary>

- **The harness acceptance script x the pinning conclusion (D26-001/D26-005 x D14 x D15).** Nobody
  reviews the lab build and the network findings together, because one is "setup" and the other is
  "results". The join is the single highest-value one in this chapter: a CA bind that never reached the
  zygote's mount namespace makes *every* host fail TLS, which is reported as "the app pins all traffic",
  which closes the entire D15 API section as untestable. One line in an acceptance script — a control app
  that is known not to pin, decrypting — separates a real pinning finding from a dead lab. Run it before
  any network conclusion is written, and put its timestamp in the report.
- **The `frida-trace` zero-match x the split set x dynamic loading (D26-047/D26-018 x D17 x D19).** The
  instrumentation reviewer reads "Started tracing 0 functions" as "the class does not exist"; the
  acquisition reviewer pulled only `base.apk`; the supply-chain reviewer never hears about either. The
  join is mechanical and it finds a whole hidden code path: a pattern that matches zero on `-f` and N on
  `-p`, against an app whose `pm path` returned four lines, is a class that lives in a feature split or a
  runtime class loader — which is exactly the code that ships outside the reviewed artefact.
- **The scanner's "Not Vulnerable" x the provider inventory x the file-read primitive (D26-033 x D07 x
  D11).** The IPC reviewer runs `scanner.provider.injection` and moves on; the storage reviewer
  inventories `shared_prefs` and rates a plaintext token P5 because it needs root. Neither is a finding
  alone. The join is the intersection: a provider the scanner dismissed, manually probed with
  `app.provider.download content://<auth>/x/../../../../data/data/<pkg>/shared_prefs/auth.xml`, converts
  the P5 storage observation into a zero-permission remote read of another user's session token. The
  scanner's own source is the reason nobody looks — one quote, one payload, one oracle.
- **The mobile client's endpoint list x the web client's endpoint list (D26-076 x D15 x D01).** The mobile
  team and the web team ship against the same backend and are reviewed by different people in different
  engagements. The join is to put both clients through **one** proxy project and diff behaviourally: the
  app's hardcoded `/v1` path routinely predates the site's `/v3`, and the controls added at v2 and v3 were
  never backported. This produces P1s from a harness step, and it needs no device compromise at all —
  once you have the endpoint list, the probes run from `curl`.
- **The instrumentation job list x the evidence bundle (D26-050 x D27 x D21).** The tester knows which
  hooks were loaded; the triager reading the report does not. A screenshot of a premium feature unlocked,
  captured while `root-detection-disable` and a return-value override were both installed, is
  indistinguishable from a real server-side authorisation flaw — and indistinguishable from a fabrication.
  `jobs list` pasted next to the screenshot is what makes the evidence legible, and it is also what forces
  the tester to notice that the finding is client-side only.
- **The `FLAG_SECURE` strip x the screenshot-control review (D26-051 x D20 x D27).** The evidence engineer
  strips the flag to record a PoC; the privacy reviewer separately tests whether sensitive screens are
  protected. If the two never talk, the report can simultaneously contain a screenshot of a screen the
  report also claims is protected. Run the capture **twice** — once with the strip, once without — and let
  the black frame be the positive evidence for the D20 control while the stripped frame carries the PoC.
- **The device-capability matrix x the payments and identity scope (D26-014 x D12 x D13 x D23).** Scoping
  happens in week zero; the discovery that StrongBox, real biometrics and NFC cannot be exercised on the
  emulator happens in week two. The join is to run the matrix **at kickoff** against the feature list, so
  every hardware-dependent row becomes a priced physical-device lane or a named coverage limitation in the
  SoW — rather than a silently skipped class, or worse, an emulator artefact reported as a finding.
- **APKiD's `anti_root` line x the resilience chapter's hook list (D26-023 x D21 x D16).** The recon pass
  runs APKiD and records "RootBeer present" as an informational line; the resilience pass separately
  writes a generic root bypass. The join is that APKiD names the **exact `.so`**, which turns a generic
  `fridantiroot` script into a targeted `Interceptor.attach` on one export, and — more importantly — tells
  the native reviewer which library is worth an hour of Ghidra. The same line also tells you the check is
  native, so a Java-only hook set will silently fail to bypass it.

</details>


---

## D27 Reporting, Severity Rating & Evidence

**Phase P9 · `M9` · 79 items** — ⬜ 79 support  

📄 Full detail, with every command and proof: [`checklist/D27-reporting-and-evidence.md`](checklist/D27-reporting-and-evidence.md)

> **Crux question.** **For this finding, what is the cheapest attacker position from which I have actually observed the boundary being crossed — and does the title, the VRT node, the CVSS vector and the recorded evidence all say exactly that, with the unproven link named rather than hidden?**

It pays negatively and enormously. The corpus contains a controlled comparison that settles the argument:
the *same* class of Android finding, written two ways, produced **$0** (H1 #1225158, titled "ADB Backup is
enabled within AndroidManifest") and **High** (H1 #288955, titled "Theft of arbitrary files leading to
token leakage"). H1 #3399016 — "improper input validation on exported deep-link handler crashes
FileDisplayActivity" — closed at **0.0**. H1 #1667998 — "1 click Account takeover via deeplink" — closed
at **Critical 9.3** and was patched by the vendor in **24 hours**. Nothing about the underlying Android
mechanism separates those outcomes. The title, the precondition wording and the evidence package do.


**⬜ Support ceiling**

- [ ] **`D27-001`** Title the impact category, never the Android mechanism  
   <sub>`none directly — but the title is what routes the report to `broken_authenticat` · AM-03 (the model most mobile title · The title must contain a noun the attacker **gains** (token, session, file, money, code execution, another use…</sub>
- [ ] **`D27-002`** The preconditions-and-boundary block, as the first thing in the body  
   <sub>`none — this block is what moves a `null`-priority node to its final priority` · AM-01 … AM-12, stated by ID · Three facts, before any prose: the attacker's starting position, the boundary crossed, and what was obtained. …</sub>
- [ ] **`D27-003`** The artefact fingerprint header block  
   <sub>AM-12 (own harness; not an attack) · A version-blind Android report is the single most common cause of a valid finding being closed as "not applica…</sub>
- [ ] **`D27-004`** Cite the executing artefact, not the shipped one  
   <sub>`none — but omitting it produces a finding whose every `file:line` is accurate ` · AM-08 / AM-09 (the SDK or backend  · For any app that can replace its own code after install, the APK you decompiled may not be the code that ran. …</sub>
- [ ] **`D27-005`** The per-finding template — fill every field, because blanks are what triage attacks  
   <sub>AM-03 · Every finding carries the same fields in the same order. A missing field is not neutral; it is the gap a triag…</sub>
- [ ] **`D27-006`** Ban "could potentially", "may allow", "could be used to"  
   <sub>AM-03 · Either the thing happens or it does not. Conditional-impact language is the triager's signal that the report i…</sub>
- [ ] **`D27-007`** Optimise the first 600 words for the triager's read sequence  
   <sub>AM-03 · The observed read sequence is title (≈3 s) → first impact paragraph (≈15 s) → **the curl command or HTTP reque…</sub>
- [ ] **`D27-008`** Name the defence that fails, quoting the method that implements it  
   <sub>AM-03 · Every finding sits next to a control someone believed worked. Write the mechanism, not the pattern. A sentence…</sub>
- [ ] **`D27-009`** State what the finding is NOT  
   <sub>AM-03 · Write a short "what this is and is not" paragraph next to the impact claim. This is the single behaviour most …</sub>
- [ ] **`D27-010`** Give every finding an OWNER  
   <sub>A mobile assessment delivered only to the mobile team dies for every finding whose fix is server-side — and on…</sub>
- [ ] **`D27-011`** Reportability opinion and submission order are part of the deliverable  
   <sub>For every finding, state plainly whether it is **reportable**, **informative** or a **likely duplicate**, with…</sub>
- [ ] **`D27-012`** Never file under a mobile VRT node when an impact node exists  
   <sub>`target `broken_authentication_and_session_management.authentication_bypass` (P` · AM-03 · Bugcrowd's mobile-specific taxonomy is almost entirely P5/P4. The same technical issue filed under its impact …</sub>
- [ ] **`D27-013`** "Varies" is an invitation, not a rejection  
   <sub>``broken_access_control.exposed_sensitive_android_intent` (priority **null**, C` · AM-03 · The placeholder vector is all-None on every impact metric. That is the taxonomy telling you the rating is enti…</sub>
- [ ] **`D27-014`** Pick the most specific *accurate* VRT node, then set severity separately  
   <sub>`whichever node genuinely fits; `... → Other` with a mapping note when none doe` · The VRT dropdown's default severity is bound to the node. Choosing a node that misrepresents the bug in order …</sub>
- [ ] **`D27-015`** The severity-request paragraph, as the first body section  
   <sub>Triagers auto-close when they see P4 in the form. Pre-empt it with a literal, recognisable opening section rat…</sub>
- [ ] **`D27-016`** Rate by acquisition path, not by data class  
   <sub>`the path decides the node: root-only reads land at `insecure_data_storage...on` · AM-12 at the bottom of the ladder, · "Token stored in plaintext" spans P5 to Critical depending only on how an attacker gets it. State which rung y…</sub>
- [ ] **`D27-017`** AV:L / PR:N / UI:N — the zero-permission local app vector  
   <sub>`n/a — this is the vector convention behind every mobile rating` · AM-03 · Three metrics do most of the work on mobile. Get them right and the band follows; get them wrong and the whole…</sub>
- [ ] **`D27-018`** S:C only where you demonstrated the sandbox crossing  
   <sub>AM-03 · `S:C` means the impact crossed a **security authority**. On Android that authority is the UID sandbox: an app-…</sub>
- [ ] **`D27-019`** CVSS v4.0 on mobile — SC/SI/SA carry the cross-app impact; base is yours, environmental is theirs  
   <sub>AM-03 · v4.0 splits impact into the **vulnerable** system (VC/VI/VA) and the **subsequent** system (SC/SI/SA). For a m…</sub>
- [ ] **`D27-020`** Know which calculator the programme actually runs  
   <sub>The same vector produces different numbers on different platforms. Check which calculator the programme enable…</sub>
- [ ] **`D27-021`** The two-verified-links rule  
   <sub>`the chain's end node, not the entry node` · AM-03 typically at the entry, AM-0 · **Two verified links plus one unproven link is a Medium with a stated precondition, not a Critical.** Rate on …</sub>
- [ ] **`D27-022`** The pre-severity gate — five questions against the Critical claim, not against the bug  
   <sub>`n/a — this gate governs every P1/P2 claim you make` · Write the draft Critical title, then substitute **the Critical claim** for "the bug" in each of the five quest…</sub>
- [ ] **`D27-023`** Audit the draft against the eleven downgrade triggers, and use the counter-wording  
   <sub>AM-01 … AM-12 · Eleven triggers account for almost every unexplained downgrade. Audit the draft against each and rewrite the i…</sub>
- [ ] **`D27-024`** Choose the attack-scenario column deliberately  
   <sub>AM-01 (column 1) → AM-02 (column 2 · For each finding identify the **cheapest realistic delivery** and build the PoC for that one, not for the one …</sub>
- [ ] **`D27-025`** Classify the exfiltrated data in the programme's own words  
   <sub>``sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` ` · AM-03 · State explicitly whether the data you obtained is High Impact or Low Impact, quoting the programme's own defin…</sub>
- [ ] **`D27-026`** State the MAS profile; MAS-R gaps are hardening, not vulnerabilities  
   <sub>`the whole `lack_of_binary_hardening` branch is P5 with an all-zero CVSS baseli` · AM-12 (the user as adversary) for  · Declare the profiles in scope, using the MASVS threat assumptions verbatim, and filter the findings table by t…</sub>
- [ ] **`D27-027`** Route the severity into the vendor's own vocabulary  
   <sub>varies · Use the target vendor's own severity words so the triager can map your report directly onto their table. Sever…</sub>
- [ ] **`D27-028`** The escalation matrix — interrogate every finding before you rate it  
   <sub>`n/a — the matrix's output is which node D27-012 aims at` · AM-03 at entry · VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD → REPORT. Ask the same questions of every finding before r…</sub>
- [ ] **`D27-029`** The evidence tree — one directory per finding id  
   <sub>Every finding gets a directory; every dynamically demonstrable finding gets a verified `.mp4`. Code-verified-b…</sub>
- [ ] **`D27-030`** The PoC video seven-beat standard  
   <sub>`n/a — but the negative-control beat is what converts a demo into evidence` · AM-03 · Seven beats, in this order, in one continuous take per beat. Beats 4 and 5 are the two most omitted and the tw…</sub>
- [ ] **`D27-031`** The canary rule  
   <sub>AM-03 · Plant a unique, obviously synthetic value in the victim data **before** recording, so the bytes the attacker d…</sub>
- [ ] **`D27-032`** screenrecord mechanics and the frame-extraction gate  
   <sub>Capture on-device with no extra installs, then **verify the artefact before shipping it**. A recording that do…</sub>
- [ ] **`D27-033`** Composite sync and identity coherence  
   <sub>Two failure modes sink composited evidence: a sync offset derived from the wrong transition, and identities th…</sub>
- [ ] **`D27-034`** Root-for-evidence, with the roles labelled on screen  
   <sub>`n/a — without the label the finding is closed as "requires root"` · AM-03 for the attack; AM-12 for th · When the primitive proves a read happened but returns nothing to the attacker, the *contents* claim is unprove…</sub>
- [ ] **`D27-035`** Redact in the rendering, never in the targeting  
   <sub>AM-03 · Pointing the primitive at a boring cache file to keep credentials out of the report reads to a triager as "he …</sub>
- [ ] **`D27-036`** The PII split — mask this, leave that visible  
   <sub>AM-05 (another user of the same ap · The evidence must convince a triager and nothing more. Over-redaction destroys the proof of the boundary cross…</sub>
- [ ] **`D27-037`** The five-screenshot state-change pattern  
   <sub>`supports `broken_access_control.bypass_of_password_confirmation.change_passwor` · AM-05 · A state change needs a pre-state, the bug, and a post-state — plus the out-of-band side effect that shows whet…</sub>
- [ ] **`D27-038`** Sanitise flows and HARs at capture time, then grep the bundle before delivery  
   <sub>`n/a — the risk here is a breach you caused while being paid to prevent them` · A mitmproxy flow file holding thousands of production responses, a full `logcat` of a live app, or a `content …</sub>
- [ ] **`D27-039`** Your own capture is subject to the protections you are testing  
   <sub>`FLAG_SECURE` screens record as black, notification content is hidden during screen sharing on Android 15, and…</sub>
- [ ] **`D27-040`** Prove the caller's privilege level — shell UID is not app UID  
   <sub>`decides whether the finding lands at the P1 consumer node or is dropped entire` · AM-03 vs AM-12 — this item is what · The single most common false-High in Android reports is a finding demonstrated only from `adb shell` (UID 2000…</sub>
- [ ] **`D27-041`** The two controls: baseline denial and negative control, in the same take  
   <sub>`n/a — this is what converts "I launched an activity" into "I bypassed an acces` · AM-03 · A positive alone is not proof. **Every dynamic claim needs its negative control in the same take**, and every …</sub>
- [ ] **`D27-042`** Ship a runnable zero-permission attacker APK, not a manifest screenshot  
   <sub>`the difference between `broken_access_control.exposed_sensitive_android_intent` · AM-03 · Triagers reproduce. An `adb`-only PoC is frequently dismissed as requiring ADB or physical access. The deliver…</sub>
- [ ] **`D27-043`** The one-shot reproduction script and the replayable command file  
   <sub>The report should contain a command a triager runs unmodified, end to end, with no tribal knowledge. Package s…</sub>
- [ ] **`D27-044`** Capture the response delta, not the screenshot  
   <sub>`supports the P1 IDOR and auth-bypass nodes` · AM-05 · Auth and API findings triage on the **difference** between the failure and the success response. A screenshot …</sub>
- [ ] **`D27-045`** Capture the tombstone, not the fact of a crash  
   <sub>``application_level_denial_of_service_dos.app_crash.malformed_android_intents` ` · AM-02 / AM-03 depending on the del · Collect the full tombstone with the build fingerprint, faulting thread name, signal, abort message and backtra…</sub>
- [ ] **`D27-046`** Evidence integrity — a SHA-256 manifest and a synced device clock  
   <sub>The client must be able to verify that the bundle they hold is the bundle you produced, and the timestamps in …</sub>
- [ ] **`D27-047`** When evidence is unobtainable, substitute source-derived proof — never fabricate  
   <sub>AM-03 · When you cannot show the contents, prove what the file *contains* from the app's own code. A vendor verifies t…</sub>
- [ ] **`D27-048`** The ruled-out register as a deliverable  
   <sub>`n/a — this is the section that makes a clean report worth its fee` · Keep a living `report.md` from minute one with three standing sections, written **as you go**. The ruled-out s…</sub>
- [ ] **`D27-049`** A tool's silence is not a negative result  
   <sub>"drozer found no exported components", "finduris returned nothing", "`adb backup` produced an empty `.ab`", "f…</sub>
- [ ] **`D27-050`** Never assert what you have not grepped  
   <sub>Two classes of sentence are trivially falsifiable and are therefore the first things a reviewer checks: "there…</sub>
- [ ] **`D27-051`** The five-way false-positive taxonomy — accurate citations do not make a finding correct  
   <sub>Five ways a finding is wrong while every `file:line` in it is correct. Run all five before the finding leaves …</sub>
- [ ] **`D27-052`** Marker discipline  
   <sub>The injected marker must be unique and unmistakable, or your "reflection" is a word collision. **Search the BA…</sub>
- [ ] **`D27-053`** The body-diff rule  
   <sub>AM-05 · A bypass claim requires a response **body** differential, not a status code. A 200 with a byte-identical body …</sub>
- [ ] **`D27-054`** The statistical-sample rule  
   <sub>`governs claims against `server_security_misconfiguration.no_rate_limiting_on_f` · AM-01 · Single outliers are not signal; network jitter routinely produces 2x outliers, and a mobile client's radio add…</sub>
- [ ] **`D27-055`** Server policy versus state  
   <sub>AM-01 · A server-side policy that always denies is not a state oracle. Establish whether the differentiator tracks **y…</sub>
- [ ] **`D27-056`** The layer-ordering trap — a validation error does not prove you passed auth  
   <sub>`governs every claim at `broken_authentication_and_session_management.authentic` · AM-01 · The highest-confidence false positive in the entire auth-bypass class. Many stacks put a global input sanitise…</sub>
- [ ] **`D27-057`** The shell-loop ban — count your results  
   <sub>zsh array expansion fails **silently**. `for x in "${arr[@]}"` can produce zero iterations with no error when …</sub>
- [ ] **`D27-058`** Emulator artefacts that must never be reported  
   <sub>`none; filing one lands in the P5 hardening branch at best and damages the SNR ` · AM-12 (own harness — not an attack · Three observations are properties of the harness, not of the app. Re-test on a physical device or with the pre…</sub>
- [ ] **`D27-059`** MASTG's own documented false-positive classes  
   <sub>`n/a — pre-empting these stops a valid finding being closed as noise and stops ` · MASTG documents expected false positives and negatives. Check the finding against them before filing, and cite…</sub>
- [ ] **`D27-060`** The multi-tool reproduction bar, and the adversarial verification pass  
   <sub>`governs every P1/P2 claim` · Two gates before submission. First: reproduce every Critical or High via **two independent tools with differen…</sub>
- [ ] **`D27-061`** The pre-delivery QA gate — reviewed by someone who did not write it  
   <sub>The adversarial pass (D27-060) attacks the technical claim. This gate catches the errors clients actually noti…</sub>
- [ ] **`D27-062`** Retraction discipline — never silently drop a failed finding  
   <sub>When a claimed finding fails reproduction, document the retraction in an appendix rather than deleting it. A q…</sub>
- [ ] **`D27-063`** Do not retract a confirmed finding the client patched mid-engagement  
   <sub>`the finding keeps its original node` · A confirmed finding that stops reproducing is not automatically a false positive. On a monitored target the li…</sub>
- [ ] **`D27-064`** The triage ladder — have the next artefact ready so you climb a rung per reply  
   <sub>`moves the report from a P5 close to its true node` · AM-03 · Triage rejections are specific and predictable. Build the next rung's artefact **before** submitting, so each …</sub>
- [ ] **`D27-065`** The eight-step pushback playbook  
   <sub>Answer the literal bar the triager set, in their words, and lead with the artefact rather than the argument.</sub>
- [ ] **`D27-066`** Out-of-scope-clause rebuttals  
   <sub>Triagers map findings to an out-of-scope clause without reading. Include an "In-scope justification" section t…</sub>
- [ ] **`D27-067`** Chain-filing order — primitives first, consumer second, then backfill  
   <sub>`each primitive at its standalone node (typically P3/P4), the consumer at the c` · AM-03 at the primitives, AM-02 or  · A consumer report references the primitives' submission ids — which only exist once the primitives are filed. …</sub>
- [ ] **`D27-068`** Duplicate avoidance — go where scanners do not  
   <sub>A duplicate pays nothing and costs the same effort. Choose the surface before choosing the technique.</sub>
- [ ] **`D27-069`** First-actionable, and one root cause equals one payout  
   <sub>Filing a placeholder to secure a timestamp now actively loses the bounty, and one root cause pays once no matt…</sub>
- [ ] **`D27-070`** Signal-to-noise is a managed asset  
   <sub>`n/a — but every P5 you file costs you future access` · The graveyard is not merely unpaid work — filing it damages future access. Treat submission validity as a reso…</sub>
- [ ] **`D27-071`** The demotion-trap list — the claim/reality pairs triage resolves against you  
   <sub>`each row names the P5/P4 node the claim actually lands on, and the node it cou` · AM-03 / AM-12 depending on the row · Twenty-three claim/reality pairs account for nearly every unexplained downgrade. Check the draft against each;…</sub>
- [ ] **`D27-072`** Re-test every fix, and file the bypass under a new ID  
   <sub>`the bypass's own node, rated on its own merits` · AM-02 / AM-03 · Two of the better payouts in the disclosed corpus came from re-testing a patched report rather than finding so…</sub>
- [ ] **`D27-073`** Finding-ID stability across draft, final and retest  
   <sub>Renumbering between the draft, the final and the retest destroys the client's ability to track remediation and…</sub>
- [ ] **`D27-074`** Meet the programme's mandatory submission format  
   <sub>Confirm the report includes every field the vendor requires before sending. Some of it is checked mechanically…</sub>
- [ ] **`D27-075`** Shadow-API reporting — the version delta is not the finding, the weakened control is  
   <sub>``broken_authentication_and_session_management.authentication_bypass` (P1) for ` · AM-01 (the old endpoint is reachab · A mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, …</sub>
- [ ] **`D27-076`** Coverage attestation — state what was not tested, and why  
   <sub>Every engagement has features that could not be exercised — payments in production, KYC that consumes a real d…</sub>
- [ ] **`D27-077`** Incidental third-party data — stop, notify, retain nothing  
   <sub>`the authz node the mechanism supports — `broken_access_control.idor.*`, `sensi` · AM-05 · Real users' data arrives unbidden — an IDOR returning a stranger's record, a misconfigured bucket, a support i…</sub>
- [ ] **`D27-078`** The critical-notification SLA  
   <sub>Holding a Critical found on day 3 until delivery on day 10 leaves the client exposed for a week and is indefen…</sub>
- [ ] **`D27-079`** Hard lines that hold under pressure  
   <sub>Four lines, each of which costs more to cross than any technical gap is worth. Say the boundary in one or two …</sub>

<details><summary>⚰️ D27 graveyard — do not submit these standalone</summary>

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| Scanner output (MobSF, AndroBugs, mobsfscan) submitted unverified | The fastest route to N/A and to a damaged SNR. mobsfscan's own best-practice rules (`android_root_detection`, `android_prevent_screenshot`, `android_certificate_pinning`, `android_safetynet_api`) are `severity: INFO` because they describe an **absent hardening**, not a vulnerability | Manual reproduction of one rule hit, carried through to a demonstrated impact with the acquisition path named (D27-016) |
| "Assessed against the OWASP MAS Checklist" | As of MASTG v2.0.0 the generated checklist spreadsheet is **no longer an official release artefact**; `mas.owasp.org/checklists/` redirects to the removal notice. A coverage claim against a document the project does not publish is the easiest thing for a client's auditor to falsify | A coverage table generated from the MASTG repo front-matter, stating N tests run in profiles L1+L2, M excluded as `status: placeholder`, K as `status: deprecated` (D27-076) |
| A CVSS vector with no per-metric justification | The vector is the argument; an unjustified string is an assertion. Triage rewrites it, usually downwards, and the rewritten score is the one that sticks | One sentence per metric, each pointing at a named evidence artefact (D27-017) |
| A PoC video with no negative control | A positive alone shows something happened, not that the control is absent. This is the most commonly omitted beat and the one that converts a demo into evidence | Beat 5 in the same take: the identical action with the control enabled, failing (D27-030, D27-041) |
| A finding whose only proof lives in a video | A report that cannot be triaged by a reader who skims will not be triaged. The video illustrates; it must never carry information the written finding lacks | The same claim written out with the command, the raw output and the file path, with the video as corroboration |
| Padding the findings list with P5 hardening notes | Padding actively lowers the credibility of the real findings beside it, and each P5 costs SNR (D27-070) | Move them to the hardening appendix or the ruled-out register, clearly separated so the client can tell the difference |
| A chain severity claimed on an unproven link | Two verified links plus one unproven link is a Medium with a stated precondition. An inflated chain that collapses at triage takes the verified half with it | Verify the link, or state the ceiling separately with the negative test attached (D27-021) |
| The same SDK bug filed across many apps | "Multiple reports of the same SDK or library vulnerability … even across different apps … will be considered duplicates of the earliest report submission due to having the same root cause." One root cause pays once | File once, against the SDK, with reachability demonstrated in at least one consuming app (D27-069) |
| A severity argument that leads with money | It hands the triager a clean non-technical reason to close the report | Agree severity on the evidence first; discuss reward afterwards or not at all (D27-079) |
| "Requires root" presented as a cross-app finding | Root-only findings are excluded by name at Google, HackerOne, Bugcrowd, Xiaomi, Grab, Spotify, Starbucks, PayPal, Basecamp, Snapchat, Reddit and HackenProof | A zero-permission app path, a `run-as` path on a debuggable build, a backup path, or a second display-only device with the roles labelled on screen (D27-034, D27-040) |
| A retraction handled by silent deletion | A quietly deleted finding reads as nothing at all, and the reviewer may find the error first | A retraction appendix entry with the original signal, the disproving evidence, why it looked like a bug, and the date (D27-062) |
| `KeyInfo.isInsideSecureHardware() == false` on an emulator | A property of the harness. Software-backed keystores are what an emulator has | The same result on hardware that supports StrongBox, with key attestation showing the key is not hardware-bound (D27-058, -> D12) |
| A finding rated on the ATT&CK technique's prestige | Techniques ATT&CK itself marks as not mitigable by preventive controls (T1533, T1544, T1575, T1631, T1633, T1639, T1646, T1509, T1604, T1637, T1471, T1423 among others) are post-compromise descriptions of malware behaviour, not client-app defects | The client app being the **victim** of the technique, with the defect in its own code, filed under the domain that owns that surface (D27-028) |
| "The API returns more fields than necessary" | Without the sensitivity argument this is an anti-pattern, not a finding | Name the sensitive fields returned — recovery codes, password hashes, auth tokens, cross-user identifiers — and show they reach a principal who should not see them (-> D15) |
| A coverage claim whose sweep was a shell array loop | zsh array expansion fails silently; the transcript looks complete and the ruled-out row is a false negative nobody will check | The same sweep in Python with per-iteration logging and an asserted result count (D27-057) |

</details>


<details><summary>🔗 D27 cross-surface joins — park these, chase them in P7</summary>

- **The ruled-out register (D27-048) × the version matrix (D22).** A negative established on one API level
  is not a negative on the client's fleet. "Providers not reachable" established on an Android 15 lab says
  nothing about an app whose `minSdkVersion` is 24, where targetSdk<17 export defaults and free package
  visibility still apply. Every ruled-out row must carry the API level it was established on, and any row
  whose mechanism is version-gated must be re-established at `minSdkVersion`. This is the single
  commonest way a "tested and clean" statement is false.
- **Evidence capture (D27-030, D27-039) × RASP and screen protection (D21).** The app's own defences
  break your capture: `FLAG_SECURE` screens record black, Android 15 hides notification content during
  screen sharing, and an anti-instrumentation control may kill the process mid-take. Testers then disable
  the protection to get the recording — and the disabled control silently becomes an unstated
  precondition that the triager cannot reproduce with. Every capture must declare which protections were
  suppressed, and the finding must be re-run with them restored.
- **VRT routing (D27-012) × backend authorisation (D15).** The highest-severity finding in a typical
  mobile engagement is a server-side authorisation defect discovered through the app. Filed as a mobile
  finding it lands in a P5 branch; filed as
  `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` it is P1.
  Nobody reviews the taxonomy and the backend together, so the mobile tester files the mechanism they
  touched rather than the boundary they crossed.
- **The APK endpoint inventory (D01) × live API versioning (D15) × severity framing (D27-075).** The
  app's hardcoded base URLs are an inventory of API versions the current web client has already moved
  off. The join is behavioural: the same operation, both versions, four axes (auth strength, rate
  limiting, input validation, field exposure). The version delta alone is Informational; the weakened
  control on the old path is a P1. This is the highest-value mobile-to-backend bridge in the corpus and
  almost nobody runs it, because it requires the APK reader and the API tester to be the same person.
- **The PoC video (D27-030) × privacy and PII (D20).** The frame that proves the boundary crossing is
  also the frame that ships the victim's data into a shared bug tracker with an unknown reader set. The
  join is the split in D27-036: mask the victim's identity, keep the key names, your own attacker uid and
  the trace id, because those are what prove the crossing. Redacting the wrong half destroys the proof;
  redacting neither is a breach you caused.
- **Chain filing (D27-067) × IPC primitives (D08) and WebView consumers (D10).** An intent-redirection
  primitive and the non-exported WebView it reaches have **independent fix surfaces** — one is a manifest
  and `getParcelableExtra` change, the other an origin allow-list. "One fix, one bounty" means they are
  two reports and two payouts, but only if the primitive is filed first so the consumer can cite its id.
  Filed as one report, the chain pays once and the primitive's own severity disappears.
- **The retest (D27-072) × artefact identity (D02) and OTA channels (D17).** A fix verified against a
  staging build, or against an APK you already had locally, is not verified. The join is the store
  artefact's hash plus the executing bundle's hash: an app with an OTA channel can ship the fix in the
  store build and revert it remotely without a release, and an app with no forced-upgrade enforcement
  leaves the vulnerable build transacting against production indefinitely — which is a finding in its own
  right.
- **The evidence tree (D27-029) × the harness manifest (D26).** `repro.sh` only reproduces on a lab that
  can be rebuilt. Diff the lab manifest between the original test and the retest: a behaviour change may
  be the platform rather than the fix, and without the baseline run against the original artefact a
  broken lab reads as "fixed".
- **The false-positive gates (D27-052 → D27-056) × the automated pipeline (D26).** An agent-driven sweep
  produces a hypothesis list, not findings. The join is that the gates must run **inside** the pipeline —
  baseline marker grep, body diff, n≥10 interleaved sampling, the well-formed `{}` re-test, and an
  asserted result count — because the failure mode of an unfiltered pipeline is not a wrong report, it is
  a permanent loss of programme access.

</details>

