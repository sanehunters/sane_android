# D01 · Recon & Attack-Surface Mapping

> This domain decides what the other twenty-six domains are allowed to find: which bytes you analysed, which runtime holds the logic, which components and endpoints actually exist, and which of them a given attacker can reach. Almost every item here is Support on its own — its severity ceiling is whatever it hands to the next domain — with three exceptions that carry their own P1: a live credential recovered from a superseded build or split, a superseded API version recovered from the client that is missing the current version's authorisation control, and an OTA code channel with no enforced signature.

| | |
|---|---|
| **Phases** | P1 acquisition, scoping & OSINT · P2 static inventory (framework, manifest, endpoints) · P3 runtime confirmation & version diffing |
| **Milestones** | M1 artefact identity fixed (you can name the exact bytes and the exact runtime) · M2 component + endpoint inventory complete and reconciled against the device · M3 every inventory row carries a reachability verdict and an attacker model |
| **VRT ceiling** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a recon artefact yields a credential that still authenticates; `broken_authentication_and_session_management.authentication_bypass` (P1) when a superseded API version recovered from the client accepts a request the current version rejects. Everything else in this chapter tops out at Support and must be reported as evidence inside another finding, never standalone. |
| **Primary attacker model** | AM-01 remote no interaction (shadow API, staging hosts, superseded versions, leaked credentials). Secondary AM-03 zero-permission local app for the component inventory, AM-08 malicious third-party SDK for the merged-manifest delta. |
| **Maps to** | MASVS-PLATFORM-1, MASVS-AUTH-1; MASTG-TECH-0003, -0019, -0020, -0022, -0029, -0117, -0126, -0141, -0145, -0150, -0156, -0157, -0160, -0161, -0162, -0163, -0165, -0172; MASTG-TOOL-0004, -0009, -0011, -0018, -0078, -0104, -0116, -0125, -0129, -0146; MASTG-TEST-0217, -0233, -0236, -0237, -0238, -0242, -0355, -0364, -0365, -0366, -0393; MASTG-KNOW-0017, -0020; MASWE-0018; CWE-200, CWE-306, CWE-494, CWE-798, CWE-862, CWE-926, CWE-927; ATT&CK T1418, T1418.001, T1420, T1421, T1422, T1422.001, T1422.002, T1423, T1424, T1426, T1430, T1627.001, mitigation M1006, analytic AN1646; OWASP API1/API3/API5/API8/API9/API10:2023; OWASP Mobile M3, M8 |

## Why this domain pays

It mostly does not pay directly. Read the Bugcrowd VRT honestly: there is no "good recon" node, and the entire mobile branch it would otherwise land in is P5. An exported-component inventory, a host list, a framework fingerprint, an obfuscation verdict — every one of those is evidence, not a finding, and a report whose headline is an inventory gets triaged as Informational. The corpus is unanimous on this: "report it only as the evidence table backing a concrete finding".

There are three real exceptions, and they are the reason this chapter exists rather than being a preamble. First, **the superseded artefact**. Secrets removed in the current build are frequently still live server-side, and the old APK on APKMirror is the only place the value survives; a credential recovered from build N-3 that still authenticates today is `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` at P1. Second, **the shadow API** — the single highest-value structural idea in a mobile engagement. A mobile app's hardcoded backend calls are frequently an *older* API version than the current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure; when the old version is missing the current version's authorisation check, that is `broken_authentication_and_session_management.authentication_bypass` or `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers`, both P1. Third, **the OTA channel**: an app with expo-updates or CodePush is not running the code in the APK, and if the update payload is not code-signed and signature-enforced, a network position is remote code execution.

The rest of the chapter's value is negative and it is enormous. The corpus records the same three failure modes over and over: a tester who pulled only `base.apk` and concluded there was no native or Flutter surface; a tester who ran jadx on a Flutter or Hermes app, found a thin shell, and wrote "no findings" — a false negative with perfectly accurate citations; and a tester who spent an engagement on an APK whose JS was superseded by an OTA bundle days earlier. Missing a split is the difference between finding and not finding the entire native surface. Misclassifying the framework silently zeroes D10, D11, D12, D15 and D19. Not establishing `targetSdkVersion` invalidates the "Applies to" line of every other finding you write. There is no base rate published for this; the base rate that matters is that these three mistakes are each individually capable of producing a clean report on a vulnerable app.

One commercial note, because it changes what you write. In bug-bounty mode the inventory is never a deliverable. In a signed-SoW pentest the inventory **is** part of what the client bought — a coverage register that says "214 declared components, 9 exported, here is the disposition of each" is what justifies the fee on a clean report. Decide the mode before you write, and when the instruction is ambiguous default to bug-bounty discipline: it is the stricter of the two, and you can relax later, whereas the reverse gets findings retracted at delivery.

## The crux question

**Am I analysing the bytes that are actually executing on a current device, in the runtime that actually holds the logic — and for every host, route and component I recovered from those bytes, can I name which attacker model reaches it and which version of the backend answers?**

## Triage order

1. **Pull every split and hash them** (D01-001…003). Everything downstream is wrong if the artefact set is wrong, and it costs ninety seconds.
2. **Fingerprint the framework** (D01-022). This branches the entire plan. A Flutter or Hermes app analysed as native yields a thin-shell review and misses the router, the WebView config and the API auth entirely.
3. **Establish min/targetSdk and version currency** (D01-006, -008). These gate roughly a dozen vulnerability classes and are the most common cause of a valid finding being closed as non-current.
4. **Determine which binary is executing** (D01-032). On an OTA app, everything after this point is either real or a study of dead code.
5. **Build the endpoint and host inventory** (D01-058, -063, -064). This is the input to the highest-severity work in the whole engagement — D15's authz sweep — and to the two P1 items in this chapter.
6. **Run the version and channel diffs** (D01-067, -068, -069, -070). Highest severity available from recon alone, and nobody else on the programme is doing it.
7. **Build the merged-manifest component inventory and reconcile it against `dumpsys`** (D01-035, -037). Lower yield per hour than the API work but it is the coverage floor: an untested exported component is where the Highs hide.
8. **Mine the superseded builds and the OSINT surface** (D01-010, -014, -018). Cheap, asynchronous, and occasionally the whole engagement.
9. **Sweep the device-local surfaces** (D01-053, -055). The debuggable sweep and the listening-socket sweep are the two cheapest High-yield device checks that exist.
10. **Close the register and run the discipline gates last** (D01-038, -078, -079, -080). This is what converts "we looked at the app" into a defensible set of positives and negatives.

## Items

### D01-001 · Pull every split the device actually installed, not just base.apk

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — coverage control; a missed split silently caps the whole engagement |
| **Attacker** | n/a (tester method) |
| **Applies to** | All app-bundle-delivered apps, i.e. effectively every Play-distributed app since Play's AAB requirement |
| **Maps to** | MASTG-TECH-0145, MASTG-TECH-0003, MASTG-TOOL-0004, MASTG-TOOL-0018 |

- **Test:** Confirm you have `base.apk` **and** every `split_config.*` / `split_feature_*`. Native libraries live in the ABI split, not in base; feature modules carry whole activities and sometimes the payment or admin code.
- **How:**
```bash
PKG=com.example.app
mkdir -p work/apk && cd work/apk
adb shell pm path "$PKG"            # one line per split — count them
for p in $(adb shell pm path "$PKG" | sed 's/package://' | tr -d '\r'); do adb pull "$p" .; done
shasum -a 256 *.apk                 # record: this is the artefact identity
unzip -l split_config.arm64_v8a.apk | grep '\.so$'
unzip -l base.apk | grep '\.so$'    # expect EMPTY on a split-delivered app
for f in split_*.apk; do echo "== $f"; aapt2 dump badging "$f" | head -5; done
```
- **Proof:** `pm path` prints ≥2 lines and your local directory contains the same count; `.so` names appear only in the ABI split listing and not in `base.apk`; a `split_feature_*.apk` lists an `<activity>` absent from base.
- **Escalation:** The ABI split feeds D16 (`readelf` mitigations, native CVE matching) and D19 (Flutter snapshot / Hermes bundle); a feature split's exported activity is unreviewed surface delivered post-install and goes straight to D04.
- **Ruled out when:** `adb shell pm path <pkg>` returns exactly one `package:` line and `aapt2 dump badging base.apk` shows no `split=` attribute — a genuine monolithic APK (sideload-only or legacy build). Record the single line in the artefact manifest so the negative is auditable.

### D01-002 · Rebuild one analysable artefact from the split set, an AAB or an XAPK

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — coverage control |
| **Attacker** | n/a (tester method) |
| **Applies to** | AAB-delivered apps; XAPK downloads from APKPure/APKMirror; any engagement handed an `.aab` |
| **Maps to** | MASTG-TECH-0145 (Working with XAPK Files), MASTG-TOOL-0011 (apktool), MASTG-TOOL-0018 (jadx) |

- **Test:** Produce one merged artefact so that cross-split references resolve, then verify the merge did not drop components. XAPK is a plain ZIP, not an Android format.
- **How:**
```bash
# (a) from split APKs already pulled
java -jar APKEditor.jar m -i splits/ -o merged.apk
java -jar uber-apk-signer.jar -a merged.apk --allowResign -o merged_signed

# (b) from an XAPK download
unzip app.xapk -d app_extracted && ls -1 app_extracted
adb install-multiple -r app_extracted/*.apk

# (c) from an .aab you were handed
java -jar bundletool.jar build-apks --bundle=app-release.aab \
     --output=app.apks --mode=universal --overwrite
unzip -o app.apks -d apks/ && ls apks/

# verify the merge kept everything
for f in splits/*.apk; do apkanalyzer manifest print "$f" \
  | grep -cE '<(activity|service|receiver|provider)'; done | paste -sd+ - | bc
apkanalyzer manifest print merged.apk | grep -cE '<(activity|service|receiver|provider)'
```
- **Proof:** `unzip -l merged.apk` lists `lib/<abi>/*.so` and resource entries absent from `base.apk` alone, and the summed per-split component count equals the merged count.
- **Escalation:** The merged APK is the input for D02 signing checks, D16 native-library CVE matching and D19 bundle extraction; it is also what you patch for D21/D26 harness work.
- **Ruled out when:** The target is a single monolithic APK (D01-001 ruled out), so there is nothing to merge — or the engagement supplies the universal APK directly and `bundletool` output matches the device install hash.

### D01-003 · Record artefact provenance: acquisition path, per-split SHA-256, signer digest

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence integrity control |
| **Attacker** | n/a (tester method) |
| **Applies to** | All |
| **Maps to** | `apksigner verify --print-certs --verbose`; MASTG-TOOL-0004 |

- **Test:** A client-supplied APK, a Play-downloaded APK and an APKMirror copy of "the same version" can differ in signer, split set and bytes. Fix the identity of what you tested before you test it, or every disputed finding becomes arguable.
- **How:**
```bash
mkdir -p evidence
for f in apk/*.apk; do
  printf '%s\t%s\t%s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$(stat -f%z "$f")" "$f"
done | tee evidence/ARTEFACT-MANIFEST.txt

apksigner verify --print-certs --verbose apk/base.apk \
  | grep -E 'Signer #1 certificate (SHA-256|DN)|Verified using v[1234] scheme'

adb shell dumpsys package com.target.app \
  | grep -E 'versionName|versionCode|firstInstallTime|lastUpdateTime|targetSdk|minSdk'
```
Record in the report: source (`client SFTP 2026-09-02` / `adb pull from a Play-installed build` / `Play Console internal app sharing link`), the SHA-256 of each split, the signer SHA-256, and which schemes verified.
- **Proof:** An appendix table a client build engineer can re-derive hash-for-hash, plus the `versionName`/`versionCode` pair quoted as text (Google explicitly asks for text, not a screenshot).
- **Escalation:** The signer SHA-256 is reused by D09 (Digital Asset Links) and D03/D06 (`checkSignatures` analysis) — capture it once. The per-split hashes are what defeat a "we already fixed that" dismissal.
- **Ruled out when:** Never. This field has no true negative; its absence is a delivery defect, not a clean result.

### D01-004 · Establish which APK signature schemes verify and pin the signer SHA-256

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | n/a standalone; escalates into `broken_access_control.privilege_escalation` (varies) via D03 when a signature-protected surface is reachable |
| **Attacker** | AM-08 / AM-11 (an attacker who can get a resigned build installed) |
| **Applies to** | All; v3 key rotation is Android 9.0+, `knownSigner` is Android 12+ |
| **Maps to** | source.android.com APK signing schemes v1/v2/v3/v3.1/v4; `PROTECTION_FLAG_KNOWN_SIGNER`; MASTG-TECH-0117 |

- **Test:** The signing certificate binds the app's UID, its `signature`-protected permissions, its `sharedUserId` group and its update identity. Establish which schemes verify — v1-only is strippable — and enumerate any `knownSigner` allow-list, because a rotated-away or partner-held key in that list takes the permission for free.
- **How:**
```bash
apksigner verify -v --print-certs base.apk
# expect explicit lines: "Verified using v1 scheme (JAR signing): true/false", v2, v3, v3.1, v4
unzip -l base.apk | grep -E 'META-INF/.*\.(RSA|DSA|EC|SF)'

grep -nE 'knownSigner|knownCerts' out/AndroidManifest.xml
grep -rn 'knownCerts' out/res/values/*.xml       # digest list is usually a string-array
adb shell pm list permissions -f | grep -A3 -i knownSigner
```
- **Proof:** `Verified using v2 scheme ... false` together with `v1 scheme ... true` proves v1-only. A `protectionLevel` string containing `knownSigner` plus a resolvable `android:knownCerts` array of SHA-256 digests is the enumerable allow-list; the finding is a build signed with a *historical* key from that array being granted the permission.
- **Escalation:** → D03 (permission squatting, protection-level downgrade), → D02 (build integrity), → D09 (the same digest must appear in `assetlinks.json`).
- **Ruled out when:** `apksigner verify -v` reports v2 **and** v3 verified true, no `knownSigner` level appears in the manifest, and no `android:knownCerts` array resolves. Quote the four scheme lines verbatim as the negative.

### D01-005 · Play App Signing: the artefact you were handed is signed with a different key than users run

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the hijacked link exposes) when the mismatch breaks App Links |
| **Attacker** | AM-02 remote one click (victim taps a link that falls back to a chooser) |
| **Applies to** | Any app distributed through Play App Signing — the default for AAB uploads |
| **Maps to** | MASTG-TECH-0172; `pm get-app-links`; Digital Asset Links `sha256_cert_fingerprints` |

- **Test:** With Play App Signing the developer signs the bundle with the **upload key** and Google re-signs the delivered APKs with the **app signing key**. Every conclusion that depends on the certificate — `signature` permissions, `checkSignatures`, App Links, Maps/OAuth key restrictions, an SDK allow-list — is wrong if you only inspected the client's local build.
- **How:**
```bash
# what you were given
apksigner verify --print-certs apk/base.apk | grep -i 'SHA-256'
# what users actually run
adb shell pm path com.target.app | sed 's/package://' | while read -r p; do adb pull "$p" store/; done
apksigner verify --print-certs store/base.apk | grep -i 'SHA-256'
# what the world is told to trust
curl -s https://target.example/.well-known/assetlinks.json | python3 -m json.tool
adb shell pm get-app-links com.target.app
```
Ask the client for the **App signing key** SHA-256 from Play Console (*Protected with Play → Play Store distribution → Play app signing*) and put it in the scoping sheet.
- **Proof:** Three fingerprints side by side. A mismatch between the `assetlinks.json` fingerprint and the app signing key, confirmed by `pm get-app-links` reporting the domain in state `none` / `legacy_failure` / `verification_failure` rather than `verified`.
- **Escalation:** → D09 App Link hijack: a second app declaring the same host filter wins link traffic, and a password-reset or OAuth `code=` URL is delivered to it.
- **Ruled out when:** `pm get-app-links` reports every declared web host `verified: true` on a clean install, and the `assetlinks.json` fingerprint equals the store artefact's signer SHA-256. Capture both outputs.

### D01-006 · Establish minSdkVersion and targetSdkVersion from two authoritative sources

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but it sets the "Applies to" line of every other finding in the engagement |
| **Attacker** | n/a (tester method) |
| **Applies to** | All |
| **Maps to** | `aapt2 dump badging`; `dumpsys package`; MASTG-TECH-0117 |

- **Test:** apktool frequently **drops `<uses-sdk>`** from the regenerated manifest, so reading the rebuilt manifest gives a false (absent) answer. Get two independent readings that agree.
- **How:**
```bash
adb shell dumpsys package "$PKG" \
  | grep -E 'versionName|versionCode|targetSdk|minSdk|firstInstall|primaryCpuAbi'
grep -E 'minSdkVersion|targetSdkVersion' base_apktool/apktool.yml
aapt2 dump badging base.apk | grep -E 'sdkVersion|targetSdkVersion|compileSdkVersion|package:'
# drozer equivalent (needs the agent):  run app.package.manifest <pkg>
```
- **Proof:** Two sources print the same two integers and you can quote them in the report body.
- **Escalation:** Every API-level gate in this checklist is evaluated against these numbers — `targetSdk<17` providers exported by default and `addJavascriptInterface` reflection RCE at `minSdk<17`; `<24` user-CA trust; `<28` cleartext allowed; `<30` free package visibility; `<31` implicit component export and unenforced PendingIntent mutability. A deliberately low `targetSdk` on a current app is itself the root cause of Medium/High findings → D22.
- **Ruled out when:** Never — this has no negative. If the two sources disagree, you have the wrong artefact (go back to D01-001/-003) and that disagreement is itself the result.

### D01-007 · Enumerate SDK Extension versions before declaring a modern API unreachable

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | n/a standalone; the reachable legacy branch it exposes is rated in its own domain |
| **Attacker** | AM-03 zero-permission local app (reaching a code path the developer believed dead) |
| **Applies to** | API 30+ devices receiving Google Play system updates |
| **Maps to** | `SdkExtensions.getExtensionVersion()`, `SdkExtensions.AD_SERVICES`, `android:minExtensionVersion` |

- **Test:** Modular APIs (Photo Picker, `ad_services`) ship via Google Play system updates and exist on *older* OS versions through SDK Extensions. "We're on Android 11 so feature X can't exist" is often wrong — for the developer and for you.
- **How:**
```bash
adb shell getprop | grep build.version.extensions
# [build.version.extensions.r]: [3]  [build.version.extensions.s]: [3]  [build.version.extensions.t]: [3]
grep -rn 'SdkExtensions.getExtensionVersion(\|SdkExtensions.AD_SERVICES' jadx_out/sources
grep -n 'minExtensionVersion' out/AndroidManifest.xml
```
- **Proof:** `build.version.extensions.r >= 2` on an Android 11/12 device proves `ACTION_PICK_IMAGES` is live there, so the app's "legacy storage permission fallback" branch is reachable on a device the developer assumed was modern.
- **Escalation:** → D11 (a compiled-in `READ_EXTERNAL_STORAGE` branch that is still reachable), → D22 (behaviour-change reasoning).
- **Ruled out when:** `getprop | grep build.version.extensions` returns nothing (pre-API-30 image) or the app contains no `getExtensionVersion` / `minExtensionVersion` gate at all, so no branch is version-selected.

### D01-008 · Prove version currency against the programme's staleness clause

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but staleness is a blanket disqualifier that voids an otherwise valid P1 |
| **Attacker** | n/a (tester method) |
| **Applies to** | All bug-bounty and VRP engagements |
| **Maps to** | Google Mobile VRP non-qualifying "Vulnerabilities that do not work on the latest available operating system version"; Android & Google Devices "must reproduce on the latest publicly available build"; Samsung, Xiaomi, Uber and Meta version-currency exclusions |

- **Test:** Every major programme requires reproduction on current software. A perfect exploit against last quarter's build is unpayable everywhere. Establish currency before you spend the week, not after.
- **How:**
```bash
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.fingerprint
adb shell dumpsys package "$PKG" | grep -E 'versionName|versionCode|firstInstallTime|lastUpdateTime'
adb shell pm list packages --show-versioncode | grep "$PKG"
```
Then compare `versionName`/`versionCode` against the live store listing. Record all four values as **text** in the report body.
- **Proof:** `versionName`/`versionCode` matching the current listing and `ro.build.version.security_patch` inside the current patch cycle, quoted verbatim.
- **Escalation:** If the bug only reproduces on an older API level, do not burn the submission — reclassify it as a D22 behaviour-change item, or pivot to proving it at current `targetSdk`. Note the inverse trap: a device reporting SPL `2026-07-05` was still fully vulnerable to a `2026-07-01`-fixed issue, so a patch string is a claim, not a proof — verify the specific gate behaviourally.
- **Ruled out when:** `versionCode` on the device equals the current store `versionCode` and the SPL is within the current cycle. That pair is the auditable negative.

### D01-009 · Freeze the artefact and detect mid-window build drift

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — dispute-prevention control |
| **Attacker** | n/a (tester method) |
| **Applies to** | All; acutely for weekly release trains and any OTA-updatable app |
| **Maps to** | `dumpsys package` fields `versionName` / `versionCode` / `lastUpdateTime` |

- **Test:** Clients ship during your window. Without a freeze, half a report can describe code that no longer exists — the fastest route to every finding being disputed.
- **How:**
```bash
# day 0 — freeze
adb shell dumpsys package "$PKG" | grep -E 'versionName|versionCode|lastUpdateTime|firstInstallTime'
for f in apk/*.apk; do shasum -a 256 "$f"; done | tee evidence/ARTEFACT-MANIFEST.txt
adb shell pm disable-user --user 0 com.android.vending   # optional: stop auto-update mid-window

# daily
adb shell pm list packages --show-versioncode | grep "$PKG"
```
RoE clause to insert: *"Findings are stated against versionName X (versionCode N), SHA-256 listed in Appendix B. Builds released during the test window are out of scope unless both parties agree a re-baseline in writing; a re-baseline resets the affected phase's budget."*
- **Proof:** The artefact manifest in the report plus a dated note for any re-baseline.
- **Escalation:** Pairs with D01-003 provenance and with D01-032 — an OTA bundle can change **without** `versionCode` moving, so a frozen `versionCode` is not a frozen artefact on an OTA app.
- **Ruled out when:** `versionCode` and every split SHA-256 are unchanged at delivery versus day 0, and the app has no OTA channel (D01-032 ruled out). Both conditions are required.

### D01-010 · Mine the published version history for secrets the vendor believes are retired

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Any app with published version history (APKMirror, APKCombo, APKPure, `apkeep`) |
| **Maps to** | CWE-798; OWASP API8:2023; H1 #1241116 (Reddit, Critical), #789370 (Smule, Critical) |

- **Test:** Secrets removed in the current build are frequently still **live server-side**. The old APK is the only place the value survives. Do not reverse only the latest version.
- **How:**
```bash
# pull the version history
apkeep -a com.target.app@'*' -o 'arch=arm64-v8a' ./history/
ls history/    # com.target.app_1234.apk ...

for a in history/*.apk; do
  echo "== $a"
  apktool d -q -f "$a" -o /tmp/h && \
  grep -rhoE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}|ya29\.[0-9A-Za-z_-]+|ghp_[A-Za-z0-9]{36}|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}' \
    /tmp/h | sort -u
  grep -rniE 'consumer_secret|consumer_key|client_secret|api[_-]?secret|firebase_database_url' \
    /tmp/h/res/values/ /tmp/h/assets/ 2>/dev/null | sort -u
done

# then VALIDATE — a string is not a finding
curl --user "$KEY:$SECRET" --data 'grant_type=client_credentials' https://api.twitter.com/oauth2/token
```
- **Proof:** A credential present in build N-3 and absent in build N that still returns an authenticated response today — e.g. `{"token_type":"bearer","access_token":"..."}` — captured as a request/response pair. A raw string with no successful API call is Informational and must not be reported.
- **Escalation:** → D18 (cloud/SDK backend takeover with the recovered key), → D24 (mass push if it is an FCM server key).
- **Ruled out when:** Every candidate recovered from every historical build returns 401/403/`invalid_client` when replayed from a clean host, or the key is demonstrably package-plus-signature restricted (probe once, benignly, and record the restriction response either way).

### D01-011 · Version-diff two consecutive releases and test the delta first

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; inherits the class the diff reveals |
| **Attacker** | n/a (tester method); the resulting finding carries its own model |
| **Applies to** | All apps with historical builds available |
| **Maps to** | MASTG-TECH-0117; MASTG-TOOL-0011 |

- **Test:** A silent fix tells you exactly which sink the developer distrusts. Then grep for the same sink elsewhere, where they forgot. New exported components, new deep-link paths and new permissions are where the untested code lives.
- **How:**
```bash
apktool d -f old.apk -o v1 && apktool d -f new.apk -o v2
diff <(grep -oE 'android:name="[^"]+"' v1/AndroidManifest.xml | sort -u) \
     <(grep -oE 'android:name="[^"]+"' v2/AndroidManifest.xml | sort -u)
diff -r v1/ v2/ > changes.txt
grep -nE 'exported|intent-filter|android:scheme|permission|autoVerify' changes.txt

# method-level delta
for v in v1 v2; do unzip -p "${v}.apk" classes.dex > "$v.dex"; \
  dexdump -f -m "$v.dex" | grep 'name *:' | sort -u > "$v.m"; done
comm -13 v1.m v2.m | head -100

# SDK churn
diff -u <(unzip -p old.apk 'META-INF/*.version' | sort) \
        <(unzip -p new.apk 'META-INF/*.version' | sort)
diff -rq v1/lib v2/lib
```
- **Proof:** A diff hunk adding a path-canonicalisation or signature check in one handler, plus a grep showing an unchanged second handler using the identical pattern; or a manifest line present only in `v2` such as a newly added `<data android:scheme="targetapp" android:host="pay"/>`.
- **Escalation:** New deep link → D09; newly exported component → D04/D08; an ad or push SDK jumping several majors in one release points at the vendor's last incident → D17/D18.
- **Ruled out when:** `diff -r` across two consecutive releases shows changes only in `resources.arsc`, locale strings and build-id constants, with no manifest, `lib/`, or method-set delta. Record the diff summary as the negative.

### D01-012 · Version rollback: does the backend still serve a superseded, legitimately signed client

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the old build contains an already-patched auth or crypto bug you can re-run live; otherwise rate as the resurrected class |
| **Attacker** | AM-02 remote one click (user sideloads from a mirror) / AM-11 physical unlocked |
| **Applies to** | All. Android blocks in-place downgrade, so the precondition is uninstall-then-install — state that in the report, it sets the severity |
| **Maps to** | CWE-494; `apksigner verify --print-certs` |

- **Test:** An attacker who can uninstall-then-install can plant an older, **legitimately signed** build whose bug the vendor already fixed. The question is whether the *server* still serves that client. A fix that only exists in the current client is not a fix.
- **How:**
```bash
# certs MUST match, or you are testing a repack, not a rollback
apksigner verify --print-certs old.apk     | grep -i sha-256
apksigner verify --print-certs current.apk | grep -i sha-256

adb uninstall com.target.app && adb install old.apk
# exercise the API with the old client's headers
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-App-Version: 3.1.0' -H 'User-Agent: <old UA>' \
  -H "Authorization: Bearer $TOKEN" https://api.target.example/v1/profile

# does a minimum-client gate exist at all?
grep -rniE 'minSupportedVersion|force.?update|minimum_version|versionCode *<' jadx_out/sources
```
- **Proof:** The old client authenticating and transacting — HTTP 200 on a call the current client also makes — with no `426`, `403` or force-upgrade screen, paired with the already-fixed bug reproducing under the old build.
- **Escalation:** Resurrects any previously-patched client-side finding; combine with D08/D10 items the vendor believes are closed. → D15 for the server-side half.
- **Ruled out when:** The backend returns a force-upgrade response (`426`, or a JSON `min_version` gate) to the old client's version headers before any business call succeeds, and the gate is enforced server-side rather than rendered client-side — verify by stripping the version header entirely and confirming the gate still fires.

### D01-013 · Diff the on-device install against the store artefact for post-install code

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | n/a standalone; escalates to `server_side_injection.remote_code_execution_rce` (P1) via D17 when the fetch channel is influenceable |
| **Attacker** | AM-06 network attacker no trusted CA / AM-09 malicious backend or CDN |
| **Applies to** | All; especially Play Feature Delivery, CodePush-style OTA and plugin architectures |
| **Maps to** | CWE-494; MASTG-TECH-0003 |

- **Test:** Some apps unpack or download components after first launch. The on-device state can contain code the store artefact does not.
- **How:**
```bash
adb shell pm list packages -f | grep -i com.target.app
adb pull /data/app/~~xxxx==/com.target.app-yyyy==/base.apk ondevice.apk
shasum -a 256 ondevice.apk store/base.apk

# code written AFTER install
adb shell run-as com.target.app find . \
  \( -name '*.dex' -o -name '*.jar' -o -name '*.so' -o -name '*.apk' \) -newer lib -ls
adb shell run-as com.target.app ls -la code_cache files
adb shell ls -lZ /data/app/*/com.target.app*/oat/arm64/
grep -rn 'DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader\|System.load(' jadx_out/sources
```
- **Proof:** A `.dex`/`.jar`/`.so` under the app data dir with an mtime after install time whose contents are not in the store APK, plus the `DexClassLoader` call site that loads it.
- **Escalation:** → D17 dynamic code loading. If the path is group-writable or on external storage, it is a plant-and-execute primitive; if the fetch is over a channel you can influence, it is remote code delivery.
- **Ruled out when:** `run-as ... find -newer` returns only caches and databases, no code-loading API appears in the decompiled tree, and the on-device `base.apk` hash equals the store artefact's.

### D01-014 · Enumerate the whole developer-account app catalogue from the store listing

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a for the enumeration; severity comes from what the extra APK leaks |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Any target with a store presence; especially multi-brand parent orgs |
| **Maps to** | OWASP API9:2023 Improper Inventory Management |

- **Test:** The target ships more than the one app you were handed. A multi-brand parent org typically has 5–10 packages under one developer name, and the least-maintained one carries the secrets.
- **How:**
```bash
curl -sk -A "Mozilla/5.0" \
  "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o /tmp/dev.html
grep -oE 'id=[a-zA-Z0-9._]+' /tmp/dev.html | sed 's/^id=//' | sort -u
# confirm same signing key across the family
for p in $(cat pkglist.txt); do
  apkeep -a "$p" ./fam/ 2>/dev/null && \
  printf '%s\t%s\n' "$p" "$(apksigner verify --print-certs fam/$p.apk | grep -m1 'SHA-256')"
done
```
- **Proof:** A package list containing an app that was not in the stated scope but is owned by the same developer account and signed with the same certificate; then confirmed in scope or reported as adjacent surface.
- **Escalation:** Each extra package re-enters this whole chapter. A same-key sibling also means `signature`-protected permissions are shared → D03, and the weakest sibling's exported component reaches the flagship's data → D01-040.
- **Ruled out when:** The developer page lists exactly the packages already in scope and the signing certificates of any other candidate differ, so they are not the same publisher. Keep the quarantine list.

### D01-015 · Brand-permutation package guessing for unlisted dealer, partner and internal builds

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a for the discovery; rated on what the unlisted build exposes |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Multi-brand conglomerates, dealer/partner ecosystems, franchise and field-staff apps |
| **Maps to** | OWASP API9:2023 |

- **Test:** Dealer, partner and employee companion apps are often unlisted on the developer page but still resolvable by package ID — and are systematically less hardened (debug logging on, staging hosts hardcoded).
- **How:**
```bash
BRAND=acme
for p in com.$BRAND.app com.$BRAND.mobile com.$BRAND.android com.${BRAND}connect.app \
         in.$BRAND.dealer in.co.$BRAND.app com.$BRAND.partner com.$BRAND.staff \
         com.$BRAND.internal com.$BRAND.qa com.$BRAND.uat; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://play.google.com/store/apps/details?id=$p")
  echo "$code $p"
done
# and against the mirrors, which carry unlisted/withdrawn builds
for p in ...; do curl -s -o /dev/null -w "%{http_code} $p\n" "https://apkpure.com/x/$p"; done
```
- **Proof:** A 200/redirect on a download URL for a package that does not appear in any public store listing, whose signing certificate matches the confirmed in-scope family.
- **Escalation:** Unlisted build → staging API host (D01-071) → shadow-API version diff (D01-068). Internal builds routinely ship the debug flag set (D01-072).
- **Ruled out when:** Every permutation returns 404 on both the store and the mirrors, or the ones that resolve carry a different signer. Record the permutation set tried — an untried permutation is not a negative.

### D01-016 · Ownership triage gate: prove the app is the target's before you touch it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — scope-safety control |
| **Attacker** | n/a (tester method) |
| **Applies to** | Any target whose brand is a common word; any handed-over ASM/recon report |
| **Maps to** | n/a — method; the delta itself is reportable as a programme observation |

- **Test:** ASM tooling keyword-matches the brand word. For any dictionary-word brand, most "owned" mobile apps belong to unrelated companies with the same name — banks, credit unions, dating apps and dispensaries are all documented collision categories. Testing one is real harm, not a wasted hour.
- **How:** An app is the target's only when a concrete signal ties it:
  1. the store publisher account **is** the org;
  2. the package reverse-DNS resolves to an owned domain (`com.<owneddomain>.app`);
  3. the signing certificate matches other confirmed apps (D01-004 digest);
  4. the app calls confirmed-owned API hosts (D01-063).
  Mature ASM emits an `apps_accepted=0` / ownership-confidence field — read it. Quarantine everything else:
```bash
: > loot/quarantined_mobile.txt
for p in $(cat candidates.txt); do
  sig=$(apksigner verify --print-certs "apks/$p.apk" | grep -m1 'SHA-256')
  if [ "$sig" = "$KNOWN_GOOD_SIG" ]; then echo "$p OWNED"; else echo "$p $sig" >> loot/quarantined_mobile.txt; fi
done
wc -l loot/quarantined_mobile.txt      # count, don't eyeball
```
- **Proof:** A documented ownership signal per tested app, plus an auditable quarantine list of the ones you deliberately did not touch.
- **Escalation:** The *delta* is itself reportable: "N candidates → M after ownership and soft-404 triage" is a Medium strategic finding about the client's ASM programme.
- **Ruled out when:** The engagement supplies an explicit package list in the scope document and you test nothing outside it — the gate is then satisfied by the scope document, and you say so.

### D01-017 · Pivot to the iOS twin through the App Store lookup API

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a for the discovery; rated on the backend delta it reveals |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Cross-platform targets |
| **Maps to** | OWASP API9:2023 |

- **Test:** The same conglomerate reuses `com.<corp>.<sub-brand>` naming across both platforms, and the iOS twin often ships a **different backend version** — which is a shadow-API candidate by construction. TestFlight and enterprise builds are additionally less hardened and are not FairPlay-encrypted.
- **How:**
```bash
curl -s "https://itunes.apple.com/search?term=<brand>&country=us&entity=software&limit=50" \
  | python3 -m json.tool | grep -E '"bundleId"|"sellerName"|"version"|"trackId"'
curl -s "https://itunes.apple.com/lookup?bundleId=com.<brand>.app&country=us" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["results"][0]; print(d["version"]); print(d["releaseNotes"])'
# enterprise / ad-hoc OTA distribution
curl -s "https://<target>/manifest.plist" | plutil -convert xml1 -o - -
```
- **Proof:** A sibling bundle ID under the same `sellerName` that was not in the handed-over asset list, or `releaseNotes` naming a removed/deprecated API behaviour you can then probe.
- **Escalation:** `releaseNotes` mentioning a removed endpoint → the zombie-endpoint hunt (D01-073); an iOS build pinned to an older API version → the shadow-API diff (D01-068).
- **Ruled out when:** The lookup returns no bundle under the confirmed seller name, or the iOS twin's recovered host and route set is byte-identical to the Android client's. State which comparison you ran.

### D01-018 · Code-search dorking anchored on the exact applicationId

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | All |
| **Maps to** | CWE-798; H1 #766346 "API Keys Hardcoded in Github repository" |

- **Test:** Mobile teams leak `google-services.json`, keystore passwords, CI secrets and staging credentials far more often than web teams, and the exact `applicationId` from the manifest is a perfect dork anchor.
- **How:** Read the real `applicationId` first (`aapt2 dump badging base.apk | head -1`), then:
```
"com.example.app" db_password
"com.example.app" "Authorization: Bearer"
"com.example.app" filename:google-services.json
"com.example.app" filename:local.properties
"com.example.app" language:yaml ssh
"Example Inc" fb_secret
"com.example.app" keystore password
```
Automate with `GitDorker` (`Dorks/alldorksv3`), `gitGraber`, `github-search`, `GitGot`. Then validate every hit:
```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $FOUND" https://api.target.example/v1/me
```
- **Proof:** A live credential: the leaked key returns HTTP 200 with account-scoped data from the vendor API. Screenshot the request/response pair, then rotate-notify.
- **Escalation:** → D18 (pivot the leaked key into the cloud backend); a CI token reaching source or build is Critical on its own.
- **Ruled out when:** Every dork returns only forks of public sample code or the app's own open-source dependencies, and every candidate credential returns 401/403 when replayed. Record the dork set run, because an unrun dork is not a negative.

### D01-019 · Read the programme rules that set the payout ceiling and the admissible attacker model

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — routing and scoping control |
| **Attacker** | n/a (tester method) |
| **Applies to** | All bounty/VRP engagements; for a paying client, substitute their own severity matrix |
| **Maps to** | Google Mobile VRP application tiers and reward table; Android & Google Devices programme; Chrome VRP routing; HackerOne Core Ineligible list |

- **Test:** Two rules decide whether a week converts. (a) **Tier and publisher**: for a Google-published app the package name changes the ceiling by roughly 7×, and scope is by Play *developer account*, not brand. (b) **Attacker model pricing**: "same network (MitM)" and "physical access" are a priced column in some programmes and an instant close in others.
- **How:**
```bash
aapt2 dump badging app.apk | grep -E '^package|targetSdkVersion'
apksigner verify --print-certs app.apk | grep -E 'Signer #1 (subject|certificate SHA-256)'
```
Compare the package against the Mobile VRP Tier 1 list verbatim — `com.google.android.gms`, `com.google.android.googlequicksearchbox`, `com.google.android.apps.cloudconsole`, `com.google.android.gm` — and the publisher against the in-scope developer list (Google LLC, Developed with Google, Research at Google, Red Hot Labs, Google Samples, Fitbit LLC, Nest Labs Inc., Waymo LLC, Waze). Then grep the policy page for the three strings `Man-in-the-Middle`, `physical access`, `rooted`. Reference points from the corpus: Mobile VRP prices MitM as its own column at roughly 1/33 of the remote column for ACE; PayPal lists MitM **and** physical access as in scope for mobile; Uber excludes MitM *except* in mobile apps; Grab and Reddit exclude MitM, physical and root outright; HackerOne Core Ineligible excludes physical access unless explicitly in scope. Routing: AOSP/platform bugs → Android & Google Devices; Chrome on Android → Chrome VRP; a non-Google SDK bug → the SDK maintainer first.
- **Proof:** The `package: name=` line matched against the tier table, and the policy line quoted verbatim in your report's attack-scenario section.
- **Escalation:** Where MitM is in scope it converts a cleartext-transport observation from an unpayable hardening note into a priced attack scenario (D14). Where it is not, AM-07 is a tester convenience only and must never be the PoC's attacker.
- **Ruled out when:** n/a — this is a gate, not a test. The negative is "policy read on <date>, MitM excluded, physical excluded", recorded in the test plan.

### D01-020 · Bind a commercial engagement with a scoping sheet and an RoE that authorises mobile-test acts

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — legal and planning control |
| **Attacker** | n/a (tester method) |
| **Applies to** | All client engagements. For bounty work the programme policy substitutes and cannot be negotiated |
| **Maps to** | NIST SP 800-115 Appendix B §1.2, §1.3, §2.1, §2.2, §3.2, §4, §5.3, §6, §7; §6.6 Legal Considerations |

- **Test:** Get written answers to a fixed question set and turn them into the test plan. Without §5.2 of an RoE, installing your own attacker APK on the client's device is an unauthorised installation.
- **How:** A 20-question sheet, answered in writing, appended as Appendix A. The load-bearing questions for mobile:
```
1  Exact package name(s) + every flavour in scope (prod, staging, whitelabel, Wear, Auto, TV)
2  Distribution channels: Play, Galaxy Store, sideload, managed Play, enterprise
3  Authoritative artefact: AAB or APK set? versionName/versionCode? who hands it over, how
4  Is the shipped build OTA-updatable after install (expo-updates / CodePush / DexClassLoader)? which channel?
5  Backend hosts: which are FIRST-PARTY and IN SCOPE, which are third-party SDK endpoints
6  Explicit EXCLUDE list (hosts, tenants, partner APIs, PSP sandboxes)
8  Test accounts: how many, which roles, who provisions, how reset      <-- no 2nd account = no IDOR/BOLA
11 Payments: sandbox PSP keys? test cards? real settlement? (default NO)
12 Play Integrity / RASP present? is a detection-disabled build available?
13 Source access: repo? mapping.txt? CI config? or black-box
14 Rate limits / WAF / fraud engine that will ban the test accounts; who allow-lists us
17 Incident definition + stop conditions + RESUME AUTHORITY
20 Data handling: retention, destruction, evidence-transmission channel
```
RoE §5.2 must explicitly authorise: installing/creating/modifying/executing files on test devices and inside the app sandbox, installing an attacker APK, repacking the client's APK, hooking with Frida, and MitM of the app's TLS — plus what must be removed afterwards.
- **Proof:** A countersigned PDF referenced by filename and date in the report's Scope & Methodology section, and a test plan whose phase list is derivable from the sheet line by line (Q11 "no real card" → D23 payment-capture testing appears in the ruled-out table as *out of scope*, not as *clean*).
- **Escalation:** Q4 + Q13 together decide whether D01-032/D17 are testable at all; Q12 decides whether the dynamic phase is viable and therefore whether you can quote fixed-price; Q8 is the single control that determines whether the High/Critical IDOR-BOLA class is reachable.
- **Ruled out when:** Bug-bounty mode — the published programme policy is the RoE and replaces Q1–Q6 and Q14–Q17. Say which document you are operating under.

### D01-021 · Day-0 intake: prior reports, regression checks and the feature-flag list

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rated on what the regressed or flag-gated capability exposes; a staff-only capability reachable in production is commonly `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-05 another user of the same app |
| **Applies to** | All engagements with engineer access; repeat engagements especially |
| **Maps to** | NIST SP 800-115 §8.2 (results as a benchmark for tracking progress), Appendix C (white-box efficiency) |

- **Test:** Ninety minutes with the people who built the app surfaces what no week of static analysis finds: internal debug menus, feature flags, staff-only deep links, the admin build variant, the "temporary" endpoint nobody removed. Separately, a repeat client's last report tells you what regressed.
- **How:** Request before recon and build `recon/prior-findings.tsv` — `id | source | title | severity | claimed status | our verdict` — then schedule a 10-minute regression check for every row claimed FIXED. In the walkthrough, run a fixed agenda:
```
1  Draw the trust boundaries: app<->backend, app<->SDKs, app<->other apps, app<->companion, app<->OTA channel
2  Which components are intentionally exported, and to whom? which by accident/history?
3  Feature flags & remote config: who can flip them? is there a staff/debug flag reachable in prod builds?
   ("show me the flag list" is the single highest-yield question in the meeting)
4  Debug/staff menus: gated by a flag, a deep link, a build variant, or an account claim?
5  Deep links: the full route table (ask for the router source file), not the manifest's filters
6  Which endpoints does the app call that are NOT in the public API docs?
7  Authorization model: enforced at client, gateway, or service? name the file
8  What broke last year? what has never been tested?
```
Then verify every claim against the artefact. A claim that proves false ("that menu is only in debug builds") is frequently the finding.
- **Proof:** Minutes attached to the test plan; a list of surfaces discovered here that were **not** visible in the manifest; `prior-findings.tsv` with a verdict on every row, shipped as "Status of previously reported issues".
- **Escalation:** Anything described as "internal only" goes to the top of the D04/D09 queue. A pattern of regressions is itself a finding about the release process and belongs in the executive summary.
- **Ruled out when:** Pure black-box or bounty work with no engineer access — the substitute is the app's own route table (D01-047) and its remote-config payload, and you say so.

### D01-022 · Fingerprint the framework from the archive listing before writing a single test case

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but misclassification silently zeroes D10, D11, D12, D15 and D19 |
| **Attacker** | n/a (tester method) |
| **Applies to** | All |
| **Maps to** | MASTG-TECH-0165, MASTG-TOOL-0009 (APKiD), MASTG-TEST-0237 (Cross-Platform Framework Configurations, placeholder in MASTG beta) |

- **Test:** Determine which runtime actually holds the business logic. A clean jadx grep on a Flutter or Hermes app is a **false negative, not a negative** — the DEX is a thin shell and the router, WebView config and API auth all live elsewhere.
- **How:**
```bash
unzip -l base.apk split_*.apk > /tmp/apk.list
grep -E 'assets/index.android.bundle|assets/main.jsbundle'                 /tmp/apk.list  # React Native
grep -E 'lib/[^/]+/libhermes(_executor)?\.so|libjsc\.so|libreactnative'    /tmp/apk.list  # RN engine
grep -E 'lib/[^/]+/libflutter\.so|lib/[^/]+/libapp\.so|assets/flutter_assets/' /tmp/apk.list  # Flutter
grep -E 'assets/www/|res/xml/config\.xml|assets/www/cordova\.js'           /tmp/apk.list  # Cordova/Ionic
grep -E 'assets/capacitor\.config\.json|assets/capacitor\.plugins\.json|assets/public/' /tmp/apk.list  # Capacitor
grep -E 'assets/bin/Data/|libil2cpp\.so|libunity\.so|global-metadata\.dat' /tmp/apk.list  # Unity
grep -E 'assemblies/|assemblies\.blob|libassemblies\.[^ ]*\.blob\.so|libmonosgen-2\.0\.so|libxamarin-app\.so' /tmp/apk.list  # Xamarin/MAUI
grep -E 'lib/[^/]+/lib.*shared.*\.so|META-INF/.*kotlin_module'             /tmp/apk.list  # Kotlin/KMP
grep -q 'io.flutter' out/AndroidManifest.xml && echo Flutter
grep -n 'flutter_deeplinking_enabled' out/AndroidManifest.xml
file out/assets/index.android.bundle 2>/dev/null
```

| Marker | Framework | Where the logic is | jadx gives you |
|---|---|---|---|
| `libflutter.so` + `libapp.so`, `io.flutter.*` | Flutter | Dart AOT snapshot in the `.so` | thin Java shell only |
| `index.android.bundle` + `libhermes*.so` | React Native (Hermes) | Hermes bytecode | shell + native modules |
| `assets/index.android.bundle` as UTF-8 text | React Native (JSC/no Hermes) | readable JS — grep it directly | shell |
| `assets/www/` or `assets/public/` | Cordova / Ionic / Capacitor | web assets in `assets/` | shell |
| `libil2cpp.so` + `global-metadata.dat` | Unity IL2CPP | C# compiled to native | nothing useful |
| `assemblies/` or `libassemblies.*.blob.so` | Xamarin / .NET MAUI | .NET IL assemblies | nothing useful |
| real Kotlin/Java logic in the DEX | Native | the DEX | everything |

- **Proof:** A concrete artefact list — e.g. `assets/index.android.bundle` plus `lib/arm64-v8a/libhermes.so` present ⇒ React Native on Hermes; `lib/arm64-v8a/libapp.so` present ⇒ Flutter release AOT — plus evidence that the DEX classes for the named feature are a single `ReactActivity`/`FlutterActivity` subclass with no business logic.
- **Escalation:** Chooses the extraction pipeline (hermes-dec / Blutter / pyxamstore / Il2CppDumper) that produces the endpoint list, secret list and route list consumed by D15, D12 and D09; routes all deep analysis to D19.
- **Ruled out when:** None of the marker files is present in **any** split (you checked splits, not just base — see D01-001) **and** jadx recovers real business logic under the app's own package: named domain classes, Retrofit interfaces, a router. Both halves are required; marker-absence alone is not proof on an obfuscated build.

### D01-023 · Run APKiD for compiler, obfuscator, packer and anti-analysis signatures

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `lack_of_binary_hardening.lack_of_obfuscation` (P5) if you were tempted to report the absence — do not; see the Graveyard |
| **Attacker** | n/a (tester method) |
| **Applies to** | All |
| **Maps to** | MASTG-TECH-0165 (Identifying Compilers, Obfuscators, and Packers in Android Apps), MASTG-TOOL-0009 (APKiD), MASTG-TOOL-0146 (RootBeer) |

- **Test:** Identify whether the DEX is R8/D8/dexlib, whether native libs are OLLVM-protected, and whether anti-VM / anti-root signatures are present. The actionable output is the **named protection library**, which becomes your hook target.
- **How:**
```bash
apkid base.apk
apkid split_config.arm64_v8a.apk     # packers frequently sit in the ABI split
```
Real output shape (MASTG worked example against `r2pay-v1.0.apk`):
```
[*] /input/r2pay-v1.0.apk!classes.dex
 |-> anti_vm : Build.TAGS check, possible ro.secure check
 |-> compiler : r8
 |-> obfuscator : unreadable field names, unreadable method names
[*] ...!lib/arm64-v8a/libnative-lib.so
 |-> obfuscator : Obfuscator-LLVM version unknown (string encryption)
[*] ...!lib/armeabi-v7a/libtool-checker.so
 |-> anti_root : RootBeer
```
- **Proof:** The `anti_root` / `anti_vm` lines naming the exact `.so` implementing the check — that string is what you hand to D21/D26 as a hook target.
- **Escalation:** → D21 (RASP bypass) and D26 (harness). A packer signature changes the whole plan: you are analysing a loader, and the real DEX is unpacked at runtime → D17.
- **Ruled out when:** APKiD reports only a `compiler` line with no `obfuscator`, `packer`, `anti_vm` or `anti_root` entries across every split. Never write "app is not obfuscated" as a finding on the strength of it — see D01-036.

### D01-024 · A decompiler that "sees nothing" is anti-analysis, not a clean app

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; escalate on whatever the recovered payload does |
| **Attacker** | AM-08 malicious third-party SDK / AM-09 malicious backend (for trojanised or repackaged builds) |
| **Applies to** | All; especially repackaged, trojanised and NFC-fraud samples |
| **Maps to** | MASTG-TOOL-0011, MASTG-TOOL-0018; CWE-494 |

- **Test:** When jadx or apktool abort on `AndroidManifest.xml`, or when different ZIP parsers disagree about the entry list, the APK is deliberately malformed — a parser differential hiding a payload. Also run the reverse check: two decompilers disagreeing on the *file list* or the manifest is the signal, and a single tool's silent failure is itself a result.
- **How:**
```bash
unzip -l app.apk   > /tmp/unzip.list
zipinfo -1 app.apk > /tmp/zipinfo.list
diff <(sort /tmp/unzip.list) <(sort /tmp/zipinfo.list)
zipinfo -v app.apk | grep -E 'offset|compressed size|uncompressed size' | head -40

jadx   app.apk -d out-jadx    2>&1 | tail -20
apktool d app.apk -o out-apktool 2>&1 | tail -20
apkanalyzer manifest print app.apk 2>&1 | head -5

# normalise, then re-run both
python malfixer.py /path/to/app.apk --output-dir /path/to/output
```
- **Proof:** `unzip -l` and `zipinfo -v` reporting different filenames, offsets or sizes for the same entry; or apktool throwing on the binary manifest while the APK still installs on-device. After normalisation, the `*-fixed.apk` decompiles and reveals the hidden `assets/` payload.
- **Escalation:** Recovered `assets/*.dat` / `*.enc` blobs feed D17 dynamic-code-loading analysis; a deliberate anti-analysis control on a vendor-distributed build is a supply-chain observation for D02/D17.
- **Ruled out when:** Both ZIP parsers produce identical entry lists, both jadx and apktool complete without error, and `apkanalyzer manifest print` renders the manifest. Record the three clean outputs.

### D01-025 · Determine whether the RN bundle is Hermes bytecode or plain JS, and read the HBC version

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — prerequisite for every RN static finding |
| **Attacker** | n/a (tester method) |
| **Applies to** | React Native apps; Hermes is the RN default from 0.70 |
| **Maps to** | MASTG-TOOL-0104 (hermes-dec); facebook/hermes `BytecodeFileFormat.h` |

- **Test:** React Native ships either a plain-JS Metro bundle or Hermes bytecode. The two need completely different toolchains, and the HBC version number decides which tools can parse it at all.
- **How:**
```bash
unzip -o base.apk 'assets/index.android.bundle' -d ext/
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
print('bytecodeVersion', ver, 'sourceHash', sha1,
      'fileLength', fl, 'functionCount', fnc, 'stringCount', strc)
PY
```
- **Proof:** `magic == 0x1F1903C103BC1FC6` (on-disk LE bytes `c6 1f bc 03 c1 03 19 1f`) and a decimal `bytecodeVersion`. `functionCount` / `stringCount` size the job before you start.
- **Escalation:** The version selects the decompiler (D01-026); `sourceHash` is a stable build fingerprint you diff across releases and, crucially, against the on-device OTA bundle (D01-032).
- **Ruled out when:** `file` reports UTF-8 text — the bundle is plain JS and you read it directly, no Hermes tooling needed. Or the app has no `index.android.bundle` in any split and is not React Native (D01-022).

### D01-026 · Select a Hermes tool by bytecode version; mine the string table when none supports it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the table yields a live credential; otherwise Support |
| **Attacker** | AM-01 remote no interaction (for a recovered credential) |
| **Applies to** | React Native / Hermes, all versions |
| **Maps to** | MASTG-TOOL-0104 (hermes-dec); facebook/hermes `BytecodeFileFormat.h` (`stringCount`, `overflowStringCount`, `stringStorageSize`) |

- **Test:** Verify your decompiler actually supports the app's HBC version instead of silently producing garbage. This is the number-one reason RN apps get written up as "not analysable". Even when nothing supports the version, the string table is a flat blob you can always recover.
- **How:** Version support as read from each project:
  - `hbctool` (bongtrop): HBC **59, 62, 74, 76 only** — LEGACY, i.e. roughly RN ≤ 0.69-era bundles.
  - `hermes-dec` (P1sec): HBC **59** upward; ships `hbc-file-parser`, `hbc-disassembler`, `hbc-decompiler`; the decompiler "does not retranscribe loop/conditional structures".
  - `hermes_rs` (Pilfer): disassembler + binary assembler for HBC **76, 89, 90, 93, 94, 95, 96**; no decompiler.
  - `hermes-decomp` (SymbioticSec, Rust): claims HBC **40–99**, with `decompile`, `disasm`, `strings`, `modules`, `xref`, `callgraph`, `secrets`, `frida-hooks`, `patch-string`, `asm`.
  - `react-native-decompiler`: plain-JS bundles only, not bytecode.
  - Upstream `facebook/hermes` `BYTECODE_VERSION` is **96**; React Native ships its own Hermes fork, so field versions run ahead of hbctool.
```bash
hbc-file-parser  ext/assets/index.android.bundle          # header + table sizes
hbc-disassembler ext/assets/index.android.bundle out.hasm
hbc-decompiler   ext/assets/index.android.bundle out.js
hermes-decomp decompile ext/assets/index.android.bundle -o out/
npx react-native-decompiler -i ext/assets/index.android.bundle -o ./output   # plain-JS only

# always-works fallback: the string table
strings -n 6 ext/assets/index.android.bundle | sort -u > hbc.strings
grep -aiE 'https?://|/api/|/v[0-9]+/' hbc.strings | sort -u
grep -aiE 'AIza[0-9A-Za-z_-]{35}|sk_live_|pk_live_|AKIA[0-9A-Z]{16}|Bearer |xox[baprs]-' hbc.strings
grep -aiE 'secret|token|apikey|api_key|password|private_key|client_secret|jwt' hbc.strings
hermes-decomp strings ext/assets/index.android.bundle     # resolves table order — adjacency is meaningful
```
- **Proof:** A `.hasm`/`.js` output whose string operands resolve to real app strings — your own API hostnames, `AsyncStorage` keys, screen names. Garbage opcodes or an immediate "unsupported version" error means the version gate bit you. For the string-table path, the proof is a first-party hostname or path that appears nowhere in the DEX, proving the routing and API surface lives in JS.
- **Escalation:** Endpoints → D15 IDOR/BOLA sweep; keys → D18 third-party account takeover; storage key names → D11 targeted `AsyncStorage` dump; route table → D09. Note `strings(1)` under-reports on Hermes because strings are stored contiguously without terminators — parse the table (`SmallStringTableEntry` packs `isUTF16` in bit 0, offset in bits 1–23, length in bits 24–31, `0xFF` meaning "look in the overflow table") when completeness matters.
- **Ruled out when:** A supported tool produces a full disassembly and the recovered string set contains no first-party host, route, or credential-shaped literal beyond what the DEX already showed. **Table adjacency is a hint, never proof of a call site** — say which you have.

### D01-027 · Recover the Metro module map as a JS-side SBOM

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; the reachable vulnerable dependency is rated in D17 |
| **Attacker** | AM-02 remote one click (input reaching the vulnerable JS package) |
| **Applies to** | React Native (Metro), both Hermes and plain-JS bundles |
| **Maps to** | hermes-decomp `modules`/`deps`/`extract`; react-native-decompiler `--unpackOnly` |

- **Test:** A Metro bundle is a map of numbered modules (`__d(factory, moduleId, deps)`). Recovering it gives a de-facto SBOM for the JS half of the app — including vulnerable or abandoned npm packages that no DEX-based SCA tool will ever see.
- **How:**
```bash
hermes-decomp modules ext/assets/index.android.bundle
hermes-decomp deps    ext/assets/index.android.bundle
# plain-JS bundle
npx react-native-decompiler -i ext/assets/index.android.bundle -o ./output --unpackOnly
ls output/ | head -50
grep -rl "react-native-" output/ | sed 's#.*/##' | sort -u
grep -rhoE '"version" *: *"[0-9][^"]*"' output/ | sort -u
```
- **Proof:** Module filenames and paths such as `node_modules/react-native-webview/...`, `node_modules/@react-native-async-storage/...`, with version strings inside them.
- **Escalation:** → D17 supply chain. A vulnerable `react-native-webview` version chains straight into D10. Report only the **reachable** ones — an inventory on its own is Informational.
- **Ruled out when:** The module map resolves and every third-party package is at or above its advisory-fixed version, or the vulnerable ones are demonstrably unreachable from any app input path (name the input you traced).

### D01-028 · Harvest the Dart object pool from a Flutter AOT snapshot

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when an asymmetric private key or request-signing secret is recovered |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Flutter release (AOT) Android builds; Blutter is **arm64 only** |
| **Maps to** | MASTG-TECH-0156 (Reverse Engineering Flutter Applications), MASTG-TOOL-0116 (blutter); CWE-321, CWE-798 |

- **Test:** In Flutter release builds every string constant, class name and crypto parameter used by the app is reachable from the AOT snapshot's object pool — including in `--obfuscate` builds, where names are mangled but constants are not.
- **How:**
```bash
unzip -o split_config.arm64_v8a.apk 'lib/arm64-v8a/*' -d ext/
python3 blutter.py ext/lib/arm64-v8a out_dir
grep -aiE 'https?://|/api/|/v[0-9]+/' out_dir/pp.txt | sort -u
grep -aiE 'secret|token|apikey|iv|salt|BEGIN (RSA )?PRIVATE KEY|AES|HMAC|nonce=' out_dir/pp.txt
less out_dir/objs.txt        # nested object dump: maps, lists, const class instances
ls out_dir/asm/              # per-library reconstructed assembly with symbol names

# some constants live in .rodata, not the pool
strings -n 8 ext/lib/arm64-v8a/libapp.so | grep -aiE 'https?://|BEGIN .*PRIVATE KEY|/api/'
```
- **Proof:** `pp.txt` lines containing the target's real hostnames; `asm/` files naming real package paths (`[package:flutter_secure_storage/...]`, `[package:dio/...]`). Reference case: two 2048-bit RSA private keys recovered directly out of `libapp.so` at fixed offsets.
- **Escalation:** A recovered signing key lets you mint valid `X-Signature`-style headers and drive the API from outside the app entirely → D15 authenticated abuse without the client; a recovered private key → D12.
- **Ruled out when:** Blutter completes on the arm64 snapshot and `pp.txt` + `.rodata` contain no key material and no first-party host absent from the DEX. Note Blutter's own open TODO — "Obfuscated app (still missing many functions)" — so on an obfuscated build state that symbol recovery was partial rather than claiming a clean sweep.

### D01-029 · Treat the Cordova/Capacitor web root as a source drop and hunt shipped sourcemaps

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the bundle yields live backend credentials; Medium when it only reveals internal topology |
| **Attacker** | AM-01 remote no interaction |
| **Applies to** | Cordova, Ionic (Cordova or Capacitor), Capacitor |
| **Maps to** | Capacitor `CapConfig.java` (`capacitor.config.json`), `PluginManager.java` (`capacitor.plugins.json`), Cordova `ConfigXmlParser.java` (`res/xml/config.xml`); MASTG-TOOL-0011 |

- **Test:** For Cordova/Ionic/Capacitor, all application logic ships as readable (sometimes minified) web assets. Treat `assets/www/` or `assets/public/` as a web-application source drop — and check whether they shipped the `.map` files by accident.
- **How:**
```bash
apktool d base.apk -o out/
ls out/assets/www out/assets/public 2>/dev/null
cat out/res/xml/config.xml               # Cordova
cat out/assets/capacitor.config.json     # Capacitor
cat out/assets/capacitor.plugins.json    # Capacitor plugin class list
cat out/assets/www/cordova_plugins.js    # Cordova plugin -> JS module map
grep -rnoE 'https?://[A-Za-z0-9._/-]+' out/assets/{www,public} 2>/dev/null | sort -u | head -100
grep -rniE 'api[_-]?key|secret|token|password|firebase|amazonaws|sentry' out/assets/{www,public}
find out/assets -name '*.map' -o -name '*.js.map'
```
- **Proof:** A readable bundle (`main.*.js`, `polyfills.*.js`) plus, best case, a `.map` that restores the original TypeScript with comments and internal endpoint names; then a credential from it returning 200 from the live service.
- **Escalation:** The plugin list tells you exactly which native capabilities the WebView can reach → D10; the endpoint list → D15; an admin API base URL or a shipped `.map` exposing service topology → D18.
- **Ruled out when:** `assets/www/` and `assets/public/` are absent from every split (not a hybrid app), or the bundle is present and contains no `.map`, no credential-shaped literal that validates, and no host absent from the already-known set.

### D01-030 · Extract the managed type graph from a Unity IL2CPP or Xamarin/MAUI build

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler; the findings it unlocks (client-side entitlement, hardcoded keys) are rated in D12/D23 |
| **Attacker** | n/a (tester method) |
| **Applies to** | Unity IL2CPP builds; Xamarin.Android and .NET MAUI |
| **Maps to** | Il2CppDumper (Unity 5.3–2022.2); Zygisk-Il2CppDumper; frida-il2cpp-bridge (Unity 5.3.0–6000.3.x); pyxamstore; `0xFAB11BAF` metadata constant; `XABA` assembly-store magic |

- **Test:** Both stacks compile the real logic away from the DEX. Unity IL2CPP ships `global-metadata.dat` next to `libil2cpp.so`; Xamarin/MAUI ships .NET IL assemblies whose **location changed at .NET 9** — a tester who only knows the old layout concludes "there's nothing here".
- **How:**
```bash
# --- Unity IL2CPP ---
unzip -o base.apk 'assets/bin/Data/Managed/Metadata/global-metadata.dat' \
                   'lib/arm64-v8a/libil2cpp.so' -d ext/
xxd -l 8 ext/assets/bin/Data/Managed/Metadata/global-metadata.dat   # expect AF 1B B1 FA -> 0xFAB11BAF
Il2CppDumper.exe ext/lib/arm64-v8a/libil2cpp.so \
                 ext/assets/bin/Data/Managed/Metadata/global-metadata.dat ./out
grep -nE 'IsPremium|Entitlement|Purchase|Verify|License|Token|Secret' out/dump.cs | head -50
# metadata encrypted? dump from memory instead
adb shell su -c 'cat /data/data/<pkg>/files/dump.cs' > dump.cs        # Zygisk-Il2CppDumper
npm exec frida-il2cpp-bridge -- -f <pkg> dump --out-dir dumps          # metadata-free

# --- Xamarin / .NET <= 8 ---
apktool d base.apk -o out/
pyxamstore unpack -d out/unknown/assemblies/     # auto-decompresses LZ4 "XALZ" entries
ls out/assemblies/out/*.dll

# --- .NET MAUI 9+ ---
llvm-readelf -S ext/lib/arm64-v8a/libassemblies.arm64-v8a.blob.so | grep payload
llvm-objcopy --dump-section=payload=payload.bin ext/lib/arm64-v8a/libassemblies.arm64-v8a.blob.so
xxd -l 4 payload.bin        # expect 58 41 42 41 -> "XABA"
# 20-byte header (magic, version, entry_count, index_entry_count, index_size);
# 28-byte descriptors (mapping_index, data_offset, data_size, debug_offset, debug_size,
# config_offset, config_size); length-prefixed UTF-8 names; raw data. XALZ entries are
# LZ4 block-compressed with the uncompressed size at bytes 8..12.
```
Then decompile the `.dll` set with ILSpy / AvaloniaILSpy / dnSpy / dotPeek.
- **Proof:** `dump.cs` containing real namespaced classes with method RVAs and loadable `DummyDll/*.dll`; or a directory of `.dll` files including app assemblies (not just `System.*`/`Mono.*`) opening in ILSpy with readable C#. `ERROR: Metadata file supplied is not valid metadata file.` from Il2CppDumper means the metadata is protected — use the memory/runtime path.
- **Escalation:** → D23 client-side entitlement logic, → D12 hardcoded keys, → D21 pinning and root-check callbacks written in C#.
- **Ruled out when:** Neither `global-metadata.dat`/`libil2cpp.so` nor `assemblies*`/`libassemblies.*.blob.so` is present in any split. Note the Mono-backend Unity variant ships managed `.dll` under `assets/bin/Data/Managed/` and is directly ILSpy-able — check for that before concluding.

### D01-031 · Locate the Kotlin Multiplatform shared module and its generated constants

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the shared key is live; `server_security_misconfiguration.insecure_ssl.certificate_error` (P5) for the TLS half — report the TLS defect through D14 with a demonstrated interception |
| **Attacker** | AM-01 for the key; AM-06 network attacker for the trust-manager defect |
| **Applies to** | Kotlin Multiplatform / Compose Multiplatform Android targets |
| **Maps to** | no external identifier verified — method only |

- **Test:** KMP compiles shared Kotlin to normal JVM bytecode on Android, so the shared module *is* in the DEX — but secrets are injected through `expect`/`actual` plus Gradle-generated files and land in `BuildConfig` or a generated constants class that a "grep the manifest" pass misses entirely.
- **How:**
```bash
jadx -d out base.apk
grep -rl "kotlin.Metadata" out/sources | head
grep -rnE 'class BuildConfig' out/sources | head
grep -rniE 'API_KEY|CLIENT_SECRET|BASE_URL|TOKEN *=|SECRET *=' out/sources --include='*.java' | head -50
# the usual KMP stack
grep -rnE 'io\.ktor|app\.cash\.sqldelight|com\.russhwolf\.settings|okio' out/sources | head
grep -rn 'HttpClient(' out/sources | head        # ktor engine + any trustManager override
```
- **Proof:** A generated constants or `BuildConfig` class holding a key that authenticates live, or a `ktor` `HttpClient` configured with a permissive `TrustManager` — quoted with its class and method.
- **Escalation:** A shared-module TLS or secret defect is a **multi-platform** finding: report it once and note it affects the iOS build too (cross-check with D01-017). → D14 for the TLS half, → D18 for the key.
- **Ruled out when:** No `kotlin_module` shared-library marker in the splits and no generated constants class outside the app's own `BuildConfig` with a build-time-injected secret. If KMP is present but every secret in the shared module is a placeholder that the release build overrides from a server call, say so and name the call.

### D01-032 · Determine which binary is ACTUALLY executing (expo-updates, CodePush, DexClassLoader)

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but it prevents a whole class of *wrong findings with perfectly accurate citations* |
| **Attacker** | n/a (tester method) |
| **Applies to** | React Native/Expo, CodePush, any custom DEX or JS updater |
| **Maps to** | MASTG-TECH-0003; CWE-494 |

- **Test:** For any app with over-the-air code delivery, the running JS or DEX is not the one in the APK. Analysing the APK alone can mean an entire engagement spent on dead code. Compare **content identity**, never file size.
- **How:**
```bash
# markers
grep -rn 'expo.modules.updates' out/AndroidManifest.xml
grep -rn 'dev.expo.updates.prefs\|CODE_SIGNING_CERTIFICATE' out/AndroidManifest.xml
adb shell run-as "$PKG" ls files/.expo-internal/ databases/updates.db 2>/dev/null
grep -rn 'CodePushConfig\|codepush' out/assets/ jadx_out/sources | head
grep -rn 'DexClassLoader\|InMemoryDexClassLoader' jadx_out/sources

# content identity
unzip -p base.apk assets/index.android.bundle > /tmp/embedded.bundle
adb shell "su 0 cp /data/data/$PKG/files/.expo-internal/<hash> /data/local/tmp/ota.bundle; \
           su 0 chmod 644 /data/local/tmp/ota.bundle"
adb pull /data/local/tmp/ota.bundle /tmp/ota.bundle
python3 - <<'PY'
import struct
for p in ('/tmp/embedded.bundle','/tmp/ota.bundle'):
    d = open(p,'rb').read(64)
    print(p, 'ver', struct.unpack('<I', d[8:12])[0],
          'sourceHash', d[12:32].hex(),
          'functions', struct.unpack('<I', d[40:44])[0])
PY
```
Also compare the app's self-reported build string (User-Agent, analytics payload) against the installed `versionName`.
- **Proof:** Differing Hermes `sourceHash` or function count between the embedded and on-device bundle; or a self-reported version that differs from `versionName` — observed case: APK 5.67.0, executing OTA bundle 5.67.1.
- **Escalation:** → D01-033 (is the channel signed?) and D17 (dynamic code loading). Re-base **all** logic analysis on the on-device bundle and say so in the report's AFFECTED VERSION line.
- **Ruled out when:** No updates marker in the manifest, no `.expo-internal`/`updates.db`/CodePush directory under the app's data dir, no `DexClassLoader` call site, **and** the on-device bundle's `sourceHash` equals the APK's. All four.

### D01-033 · Check whether the OTA code channel is signed and the signature enforced

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when an unsigned or unenforced channel plus a network or backend position yields code execution |
| **Attacker** | AM-06 network attacker no trusted CA (if the manifest fetch is also unpinned) / AM-09 malicious backend or CDN |
| **Applies to** | Any app with an OTA code channel confirmed by D01-032 |
| **Maps to** | CWE-494 (Download of Code Without Integrity Check); `expo.modules.updates.CODE_SIGNING_CERTIFICATE`, `CODE_SIGNING_METADATA` |

- **Test:** An OTA channel delivers executable code. If the payload is not code-signed, or the signature is configured but not *enforced*, an attacker who controls the update host — or who sits on the network for an unpinned manifest fetch — executes code inside the app.
- **How:**
```bash
grep -rn 'expo.modules.updates.CODE_SIGNING_CERTIFICATE\|CODE_SIGNING_METADATA' out/AndroidManifest.xml
grep -rn 'EXPO_UPDATE_URL\|expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH' out/AndroidManifest.xml
grep -rn 'codePushPublicKey\|CodePush.*publicKey' out/res/values/*.xml jadx_out/sources
# is the manifest/bundle fetch itself pinned?
cat out/res/xml/network_security_config.xml 2>/dev/null

# behavioural test: serve a modified bundle from a host you control
#  1. point the update URL at your server (hosts file / DNS / proxy rewrite)
#  2. serve a bundle with one changed string
#  3. relaunch and look for your string on screen or in logcat
adb logcat -c && adb shell am force-stop "$PKG" && adb shell monkey -p "$PKG" 1
adb logcat -d | grep -iE 'expo-updates|codepush|signature|verif'
```
- **Proof:** The absence of `CODE_SIGNING_CERTIFICATE` in the manifest **plus** the app rendering your modified bundle after relaunch. A configured-but-unenforced signature shows as the app loading an unsigned or wrongly-signed bundle with only a warning in logcat.
- **Escalation:** → D17 (dynamic code loading as the primary write-up), → D14 (if the fetch is also unpinned, the network position is enough). This is the item that turns "the app uses OTA updates" from a note into a Critical.
- **Ruled out when:** `CODE_SIGNING_CERTIFICATE` and `CODE_SIGNING_METADATA` are present, the channel host is pinned in `network_security_config.xml`, **and** a deliberately re-signed or unsigned bundle is rejected at launch (logcat shows the verification failure and the app falls back to the embedded bundle). The behavioural half is mandatory — configuration alone is not the negative.

### D01-034 · Never conclude "obfuscated, therefore unanalysable" — grep the anchors R8 cannot rename

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a (tester method) |
| **Applies to** | All R8/ProGuard-minified Java/Kotlin apps |
| **Maps to** | MASTG-TECH-0019 (Retrieving Strings), MASTG-TECH-0020 (Retrieving Cross References) |

- **Test:** R8 renames identifiers; it does **not** remove data flows, and it does not rewrite string values inside runtime-visible annotations or resources. Build the map from stable anchors, then read the classes and trace callers.
- **How:**
```bash
S=jadx_out/sources
# framework API names survive
grep -rn 'addJavascriptInterface\|setJavaScriptEnabled\|setAllowUniversalAccessFromFileURLs\|onReceivedSslError' $S
grep -rn 'openFile\|getHost\|startActivity\|grantUriPermission\|Cipher.getInstance\|Runtime.getRuntime().exec' $S
grep -rl '@JavascriptInterface' $S
grep -rn 'System.loadLibrary\|DexClassLoader\|getSerializableExtra' $S
# Retrofit annotation VALUES survive minification verbatim
grep -rhoE '@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\("[^"]+"\)' $S | sort -u
# Gson @SerializedName becomes @c("…") — the field names are still there
grep -rhoE '@c\("[^"]*"\)' $S | sort -u | head -50
# manifest class names are never renamed
grep -oE 'android:name="[^"]+"' out/AndroidManifest.xml | sort -u
```
- **Proof:** Anchor hits resolving to concrete method bodies in jadx even when class names are `C19575i`-style; a deduplicated route list produced from an app whose class graph is entirely mangled.
- **Escalation:** Anchor hits become the source list for every source→sink trace in D04–D10; the route list feeds D15. If `mapping.txt` is available (ask — see D01-020 Q13), retrace stack traces and re-derive real names.
- **Ruled out when:** The app is not Java/Kotlin at all (D01-022 routed it to Flutter/RN/Unity/Xamarin) — in which case this item does not apply and the D19 technique replaces it. "jadx produced mangled names" is never the negative.

### D01-035 · Build the component inventory from the MERGED manifest and compute implicit export per targetSdk

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this is the map. Each `perm=NONE` row is a candidate for `broken_access_control.exposed_sensitive_android_intent` (null) in D04–D08 |
| **Attacker** | AM-03 zero-permission local app (that is what each row is scored against) |
| **Applies to** | All. `implicit-true` rows exist only on `targetSdk < 31` |
| **Maps to** | MASTG-TECH-0117, MASTG-TECH-0141, MASTG-TECH-0150, MASTG-TECH-0160, MASTG-TECH-0161, MASTG-TECH-0162, MASTG-TECH-0163; MASTG-TEST-0355, -0364, -0365, -0366; MASVS-PLATFORM-1; CWE-926, CWE-927 |

- **Test:** The manifest inside the APK is the *merged* manifest — library and SDK manifests are merged at build time and a component the app author never wrote can be exported. Enumerate every activity, activity-alias, service, receiver and provider with its effective `exported`, `permission`, `readPermission`, `writePermission`, `process`, `directBootAware` and `intentMatchingFlags`, and compute the implicit default correctly for the app's `targetSdk`.
- **How:**
```bash
apktool d -s -f base.apk -o base_apktool
python3 - <<'PY' > recon/components.tsv
import xml.etree.ElementTree as ET
A = '{http://schemas.android.com/apk/res/android}'
r = ET.parse('base_apktool/AndroidManifest.xml').getroot()
app = r.find('application')
print("kind\tname\texported\tpermission\tintent_filters\tprocess\tstatus\tmethod\tevidence")
for kind in ('activity','activity-alias','service','receiver','provider'):
    for e in app.findall(kind):
        n   = e.get(A+'name')
        exp = e.get(A+'exported')
        perm = e.get(A+'permission') or e.get(A+'readPermission') or e.get(A+'writePermission') or ''
        ifs = len(e.findall('intent-filter'))
        if exp is None:
            exp = 'implicit-true' if ifs else 'implicit-false'
        print(f"{kind}\t{n}\t{exp}\t{perm}\t{ifs}\t{e.get(A+'process') or ''}\tTODO\t\t")
PY
xmllint --format base_apktool/AndroidManifest.xml | grep -nE \
  'android:(exported|permission|readPermission|writePermission|authorities|process|intentMatchingFlags|taskAffinity|launchMode|documentLaunchMode)='
apkanalyzer manifest print base.apk | grep -cE '<(activity|service|receiver|provider)'
```
Prove reachability rather than trusting the attribute:
```bash
adb shell am start        -n "$PKG/<cmp>"                 # "Status: ok" vs SecurityException
adb shell am startservice -n "$PKG/<cmp>"
adb shell am broadcast    -n "$PKG/<cmp>" -a "<action>"
adb shell content query --uri "content://<authority>/"
```
- **Proof:** A table whose third column is literally "reachable by an unprivileged third-party app: yes/no", with the `am`/`content` command that reached it, or the literal denial string that blocked it. Any row with `exported=true` and an empty permission column is the entry point for D04–D08.
- **Escalation:** Every row feeds D04 (activities), D05 (receivers), D06 (services), D07 (providers), D08 (redirection).
- **Ruled out when:** Every component either resolves `exported=false` with no intent-filter, or carries a `signature`-level permission you have verified against `pm list permissions -f` (D01-039). On `targetSdk >= 31` the platform refuses to install a filtered component without an explicit attribute, so any `implicit-*` row you computed there means you mis-parsed — re-check against `dumpsys`.

### D01-036 · Isolate the SDK-injected components by class-prefix delta

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; `broken_access_control.exposed_sensitive_android_intent` (null) once one proves reachable |
| **Attacker** | AM-08 malicious third-party SDK / AM-03 zero-permission local app |
| **Applies to** | All; especially any app with a push, analytics, attribution or wallet SDK |
| **Maps to** | CVE-2020-8913 (Play Core `SplitInstallUpdateIntentService`, ~13% of Play apps); EngageLab SDK ≤ v4.5.4 `MTCommonActivity`, fixed v5.2.1 (2025-11-03); CWE-926 |

- **Test:** Most exported-component findings in real engagements live in code the client did not write. Developers never see AAR-injected components, so they are never reviewed. Isolate them mechanically.
- **How:**
```bash
apktool d -f base.apk -o out
python3 - <<'PY'
import re
m = open('out/AndroidManifest.xml').read()
pkg = re.search(r'package="([^"]+)"', m).group(1)
root = pkg.rsplit('.',1)[0]
for tag in ('activity','activity-alias','service','receiver','provider'):
    for mm in re.finditer(r'<%s\b[^>]*android:name="([^"]+)"[^>]*>' % tag, m):
        name = mm.group(1)
        fq = pkg + name if name.startswith('.') else name
        if not fq.startswith(root):
            print(tag, fq, 'exported' in mm.group(0))
PY
# with source access, the merger report names the exact AAR
./gradlew :app:processReleaseManifest
grep -nE 'ADDED from .*\.aar' app/build/outputs/logs/manifest-merger-release-report.txt
```
- **Proof:** A row such as `activity com.engagelab.privates.push.platform.MTCommonActivity exported=True`, whose class package differs from the app's own, plus the merger-report line attributing it to a named AAR. Cross-confirm in `dumpsys package` that the device registered it.
- **Escalation:** → D08 intent redirection (the EngageLab case yielded persistent read/write URI grants over the host app's private storage across 50M+ installs), → D07 provider-grant abuse, → D17 supply chain. Report the vulnerable SDK to its maintainer as well as the app vendor where the programme requires it.
- **Ruled out when:** Every exported component's fully qualified class name sits under the app's own package root, or the SDK-contributed ones all carry a `signature`-level guard. Note that on `targetSdk < 31` the SDK author may not have *intended* export at all — an intent-filter with no attribute defaults to exported — so state which rule produced the export.

### D01-037 · Reconcile the static manifest against the runtime resolver tables

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; the delta is where the paying bugs live (Mobile VRP explicitly rewards redirection into non-exported components) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All |
| **Maps to** | MASTG-TECH-0160, -0161, -0162, -0163, MASTG-KNOW-0020, MASTG-TOOL-0004; Google's vulnerability-classes guidance: "Look at manifest file **and** for `Context.registerReceiver` calls" |

- **Test:** The manifest is the declared surface; the package manager is the effective one. Context-registered receivers, activity-aliases, runtime-enabled components (`setComponentEnabledSetting`) and provider authorities created at runtime appear only on-device.
- **How:**
```bash
adb shell dumpsys package "$PKG" > recon/dumpsys-package.txt
awk '/^Activity Resolver Table:/{s=1} /^Receiver Resolver Table:/{s=0} s'  recon/dumpsys-package.txt
awk '/^Receiver Resolver Table:/{s=1} /^Service Resolver Table:/{s=0} s'   recon/dumpsys-package.txt
awk '/^Service Resolver Table:/{s=1} /^Domain verification status:/{s=0} s' recon/dumpsys-package.txt
grep -i 'Provider{' recon/dumpsys-package.txt
adb shell dumpsys activity providers  | grep -A5 "$PKG"
adb shell dumpsys activity broadcasts | grep -i "$PKG"
grep -rn 'registerReceiver(\|setComponentEnabledSetting\|PendingIntent.get' jadx_out/sources
```
Capture the intents you will never see statically (post-login flows, push payloads, QR scans, chained proxies):
```bash
python3 -m intent_monitor --database ./iris.db monitor --device-id <device-id>
python3 -m intent_monitor --database ./iris.db list --target-package "$PKG"
python3 -m intent_monitor --database ./iris.db list --scheme https --host example.com
```
- **Proof:** A component present in a `dumpsys` resolver table but absent from the decompiled manifest's exported set, or a recorded runtime intent whose action/data/extras shape you could not derive statically and which reproduces on replay.
- **Escalation:** → D05 (runtime receivers), → D06, → D08 (redirection into non-exported components). A runtime-registered receiver with no permission is reachable by `am broadcast` while the app is foregrounded.
- **Ruled out when:** The resolver-table entry set equals your merged-manifest exported set, there is no `registerReceiver` call with a null broadcast permission, and no `setComponentEnabledSetting` call site enables a component post-install. Runtime-trace output is a discovery aid, not proof of external reachability — confirm each with an app-external replay.

### D01-038 · Close the component-coverage register: zero TODO rows at delivery

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — coverage-proof artefact |
| **Attacker** | n/a (tester method) |
| **Applies to** | All, mandatory on signed-SoW engagements; optional in bounty mode |
| **Maps to** | `apkanalyzer manifest print` / `manifest permissions`; drozer `app.package.attacksurface` |

- **Test:** A ruled-out register records disproven *hypotheses*. A coverage register enumerates every component the app declares and assigns each a tested status. Without it you cannot answer "did you test all of them?" and the client cannot tell a clean component from an unvisited one.
- **How:** Take `recon/components.tsv` from D01-035 and close every row out to `status` ∈ `{TESTED-CLEAN, FINDING-F0NN, NOT-REACHABLE, OUT-OF-SCOPE, BLOCKED-<reason>}`, with a `method` (e.g. `am start -n … with 14 extra permutations`, `drozer app.provider.query`, `code read only`) and an `evidence` path. Then run the loop-closing regression check:
```bash
drozer console connect
dz> run app.package.attacksurface com.target.app
# compare against your own count
awk -F'\t' '$3 ~ /true/ {print $1}' recon/components.tsv | sort | uniq -c
grep -c 'TODO' recon/components.tsv        # MUST be 0 at delivery
```
A mismatch between drozer's counts and yours names the component you missed — often one declared in a library manifest that only appears post-merge.
- **Proof:** A TSV with zero `TODO` rows whose row count equals `apkanalyzer manifest print base.apk | grep -cE '<(activity|service|receiver|provider)'`, shipped as a report appendix. This is what converts "we looked at the app" into "we tested 214 declared components, 9 exported, here is the disposition of each".
- **Escalation:** The same register drives the retest (only changed rows need re-walking) and next year's diff. Any newly surfaced component enters D04–D07.
- **Ruled out when:** n/a — no true negative. Treat drozer's zero with suspicion: it is `[DEGRADED]` on API 29+ and needs `<queries>` in its own agent on `targetSdk >= 30` (see D01-042), so a drozer zero can be a package-visibility artefact rather than a result.

### D01-039 · Enumerate every custom permission the app defines and its resolved protectionLevel

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | n/a standalone; the guarded component's finding inherits it — commonly `broken_access_control.exposed_sensitive_android_intent` (null) or `broken_access_control.privilege_escalation` (null) |
| **Attacker** | AM-03 zero-permission local app (a `normal` permission is granted silently at install) |
| **Applies to** | All apps declaring `<permission>`. Definer-wins resolution is PackageManager behaviour, not a targetSdk gate |
| **Maps to** | `android:protectionLevel` values; MASTG-TECH-0126 (Obtaining App Permissions), MASTG-KNOW-0017; CWE-862 |

- **Test:** Build the complete list of `<permission>` elements the target defines and the resolved level of each. Anything not `signature` (or `signature|privileged`) is silently acquirable by an attacker app; anything the app *uses* to protect a component but never *defines* is an orphan an attacker can define first.
- **How:**
```bash
aapt2 dump permissions base.apk
apkanalyzer manifest permissions base.apk
grep -nE '<(permission|uses-permission|permission-tree|permission-group)' out/AndroidManifest.xml

# authoritative: what PackageManager actually enforces
adb shell pm list permissions -f -g | grep -B4 -A4 '<target-vendor-prefix>'
adb shell dumpsys package "$PKG" | sed -n '/declared permissions/,/requested permissions/p'
# drozer
dz> run information.permissions
dz> run app.package.list -d com.target.permission.RECEIVE_DATA
```
Cross-reference: every string used in `android:permission`, `android:readPermission`, `android:writePermission` and `<path-permission>` must appear in a `<permission>` element of *some* package on the device.
- **Proof:** `pm list permissions -f` printing `permission:com.target.permission.SYNC ... protectionLevel:normal` with `package:com.target.app` — silently grantable to any installed app. A permission string used in the manifest that `pm list permissions -f` does not print at all proves it is an orphan.
- **Escalation:** → D03 (permission squatting: define the victim's custom permission first; protection-level downgrade after uninstall). A weak custom permission means the "protected" component in D04–D07 is effectively unguarded — test it as if bare.
- **Ruled out when:** Every custom permission resolves to `signature` or `signature|privileged` in `pm list permissions -f`, and every permission string referenced by a component is actually defined by the target package. Note the signature case is only as strong as the weakest app holding that key — see D01-040.

### D01-040 · sharedUserId redefines the target boundary — triage the weakest sibling

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` is only P5 — do **not** report it that way. Rate the outcome: a session token read from the flagship's data dir by a sibling is `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-08 malicious third-party SDK inside the sibling / AM-03 via the sibling's weakest exported component |
| **Applies to** | LEGACY-skewed: `sharedUserId` is deprecated at API 29 and cannot be added or removed post-install without a data wipe, so it now marks exactly the OEM, preinstalled and long-lived enterprise targets where VRP payouts live |
| **Maps to** | drozer `app.package.shareduid`; CWE-200 |

- **Test:** If the manifest declares `android:sharedUserId`, the target's attack surface is the **union of every package in the cluster**. Cluster members run under one Linux UID and read each other's `/data/data` directly, with no IPC and no permission check.
- **How:**
```bash
grep -n 'sharedUserId' out/AndroidManifest.xml
adb shell pm list packages -U                            # package -> uid
adb shell dumpsys package "$PKG" | grep -iE 'userId|sharedUser'
adb shell ps -A -o USER,PID,NAME | grep -i target
dz> run app.package.shareduid -u 10011                   # prints "Accumulated permissions:"
dz> run app.package.list -u 10011
# then prove the crossing
adb shell run-as com.sibling.app ls -la /data/data/com.target.app/shared_prefs
```
- **Proof:** Two or more packages printing the same `userId=` in `dumpsys`, plus drozer's `Accumulated permissions:` union — that union is the effective permission set an attacker obtains by compromising *any* member. The finding is a file listing or read of the flagship's token store performed from the sibling's UID.
- **Escalation:** Compromise the weakest sibling → read `/data/data/<flagship>` directly (D11) or act with its permissions (D03). The same logic applies to **signature-level custom permissions**: any sibling signed with the same certificate holds them for free, so a signature-protected component is only as strong as the weakest app sharing that key.
- **Ruled out when:** No `sharedUserId` attribute in the merged manifest **and** `pm list packages -U` shows the target's UID is unique on the device. Both, because an OEM image can place a sibling you did not decompile in the same cluster.

### D01-041 · Map the process topology before believing a "sandboxed process" claim

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; the false isolation claim is what you report, rated on what the compromised process then reaches |
| **Attacker** | AM-09 malicious backend or CDN (renderer compromise), AM-08 |
| **Applies to** | All |
| **Maps to** | developer.android.com "Processes and threads": components in the same app default to one process; a colon prefix creates an app-private process; "Different applications can share the same process if they have the same Linux user ID and are signed with the same certificate" |

- **Test:** A single APK can span several Linux processes, but each `android:process` value is a separate address space sharing **one UID** — so a WebView renderer, a "sandboxed" plugin process and the main process all read the same `/data/data` unless the app also used `isolatedProcess`.
- **How:**
```bash
grep -Rn 'android:process' out/AndroidManifest.xml
grep -Rn 'isolatedProcess' out/AndroidManifest.xml
adb shell ps -A -o PID,USER,NAME | grep "$PKG"
PID=$(adb shell pidof "$PKG")
adb shell ps -A -Z | grep "$PKG"                   # SELinux domain + UID per process
adb shell cat /proc/$PID/status | grep -E 'Uid|Gid|Groups|Seccomp|NoNewPrivs'
adb shell ls -l /proc/$PID/ns/
adb shell cat /proc/$PID/maps | awk '{print $6}' | sort -u | grep -E '\.so|\.apk|\.oat|\.vdex|\.art'
```
A leading colon (`:remote`) is an app-private process; a fully qualified name is a **global** process another app with the same UID and signing certificate can join.
- **Proof:** Multiple PIDs with distinct `NAME` columns but an identical `USER` (`u0_a231`), proving the "separate process" is not a separate sandbox. Pair with the vendor's own claim (marketing copy, architecture doc, the D01-021 walkthrough minutes).
- **Escalation:** A globally named process plus a shared UID plus a same-key sibling app means code from app B executes inside app A's process → D03. Any renderer RCE then reaches the token store → D10/D11. The mapped `.so` list feeds D16; the SELinux domain tells you whether a file you can plant is executable.
- **Ruled out when:** Every `android:process` value is colon-prefixed **and** the app does not claim the split as a security boundary, or the split process carries `android:isolatedProcess="true"` (verify it runs under a distinct `isolated_app` UID in `ps -A -Z`).

### D01-042 · Read `<queries>` as the declared trust graph, then check how each peer is verified

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; `broken_access_control.privilege_escalation` (null) once a squatted package defeats a name-only check |
| **Attacker** | AM-03 zero-permission local app registering the queried package name |
| **Applies to** | `targetSdk >= 30` for the declaration. **LEGACY:** below 30 package visibility is free and `<queries>` is usually absent — its absence proves nothing there |
| **Maps to** | MASVS-PLATFORM-1; MASWE-0018 (Caller Not Verified on IPC Interfaces); developer.android.com package-visibility filtered APIs: `queryIntentActivities()`, `getPackageInfo()`, `getInstalledApplications()`, `resolveActivity()`, `bindService()`; H1 #331302 (Nextcloud) |

- **Test:** Since `targetSdk 30` an app must declare which packages it can see, so `<queries>` is a free, machine-readable map of the app's trust relationships — companion apps, authenticators, wallets, SSO brokers, MDM agents. Then determine **how** the app trusts each one: a package-name comparison is defeated by squatting the name on a device where the real peer is absent; only a signing-certificate comparison is sound.
- **How:**
```bash
xmllint --format out/AndroidManifest.xml | sed -n '/<queries>/,/<\/queries>/p'
grep -n 'QUERY_ALL_PACKAGES\|forceQueryable' out/AndroidManifest.xml
adb shell dumpsys package queries                 # forceQueryable set + per-UID visibility

grep -rnE 'setPackage\(|resolveActivity\(|queryIntentActivities\(|getPackageInfo\(|bindService\(' jadx_out/sources | head -50
grep -rnE 'checkSignatures|GET_SIGNING_CERTIFICATES|GET_SIGNATURES|hasSigningCertificate|getPackagesForUid|getCallingPackage' jadx_out/sources
frida-trace -U -f "$PKG" -j 'android.content.pm.PackageManager!resolve*' \
                          -j 'android.content.pm.PackageManager!queryIntent*'
```
- **Proof:** A `<queries><package android:name="com.bank.mobile"/>` entry paired with a call site that resolves that package by **name only** — `contains()` / `startsWith()` / a string equality on `getCallingPackage()` — with no `checkSignatures` or `GET_SIGNING_CERTIFICATES` comparison anywhere in the call path.
- **Escalation:** → D06 (bind-service peer impersonation), → D08 (implicit-intent hijack of a declared flow), → D17 (`createPackageContext` on a squatted peer). Also note the inverse: an app reading `PackageInfo.signatures` instead of `GET_SIGNING_CERTIFICATES` accepts a rotated-away v3 historical key → D03.
- **Ruled out when:** Every `<queries><package>` peer is resolved with a signing-certificate comparison on the call path, or the app declares no `<queries>` and no `QUERY_ALL_PACKAGES` on `targetSdk >= 30` and makes no cross-package call at all. **If you are writing the attacker PoC, remember your own APK needs `<queries>` for the target** — without it `getContentResolver().query()` and `resolveActivity()` return null on Android 11+ and you will record a false negative:
```xml
<queries><package android:name="com.target.app"/></queries>
```
Build once without and once with, and diff — the delta proves the block, not the target's hardening, was the blocker.

### D01-043 · QUERY_ALL_PACKAGES plus egress is a privacy exfiltration, not a lint warning

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — rated on the data) when the inventory reaches a third party |
| **Attacker** | AM-08 malicious third-party SDK (the SDK is usually the caller) |
| **Applies to** | `targetSdk >= 30` for the permission to matter. **LEGACY:** `targetSdk <= 29` gets the full list with no permission and no declaration at all — call that out explicitly |
| **Maps to** | ATT&CK T1418 Software Discovery, T1418.001 Security Software Discovery, mitigation M1006, analytic AN1646; developer.android.com package visibility ("treats the list of installed apps as personal and sensitive user data"; `QUERY_ALL_PACKAGES` requires Play approval); CWE-200 |

- **Test:** Does the app hold `QUERY_ALL_PACKAGES` or enumerate `PackageManager` broadly, **and does that inventory leave the device**? An installed-app list is a durable cross-app fingerprint and a sensitive-inference vector (health, dating, finance, political apps). Enumeration alone is informational; enumeration **plus egress** is the finding.
- **How:**
```bash
aapt2 dump permissions base.apk | grep -i QUERY_ALL_PACKAGES
sed -n '/<queries>/,/<\/queries>/p' out/AndroidManifest.xml
grep -rnE 'getInstalledPackages|getInstalledApplications|queryIntentActivities|pm list packages' jadx_out/sources
```
```javascript
Java.perform(function () {
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getInstalledPackages.overload('int').implementation = function (f) {
    var r = this.getInstalledPackages(f);
    console.log('[T1418] getInstalledPackages -> ' + r.size());
    console.log(Java.use('android.util.Log')
      .getStackTraceString(Java.use('java.lang.Exception').$new()));
    return r;
  };
});
```
Install a control package first (`com.example.canary`), then search every proxied body for that exact string.
- **Proof:** The Frida hook firing with a caller frame inside a third-party SDK package **and** a captured request body containing the package-name array — verified by searching for your canary package name, not by eyeballing. Count-matching between the hook's `size=` and the array length is the corroboration.
- **Escalation:** → D18 (which SDK received it), → D20 (consent/disclosure finding), → D21 (the same enumeration is usually the app's root/Frida/competitor-detection routine — read its blocklist, that list gates a RASP branch you can flip). Combine with D20 identifiers to build a cross-app fingerprint.
- **Ruled out when:** The app declares a targeted `<queries>` block rather than `QUERY_ALL_PACKAGES`, the enumeration hook never fires outside a user-initiated share sheet, or the list is truncated to the declared peers and unlinked from any account identifier in every captured body. State which.

### D01-044 · Enumerate the auto-generated providers and read the FileProvider roots

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; High once paired with a grant primitive — rate through `broken_access_control.exposed_sensitive_android_intent` (null) in D08 |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | Any app using AndroidX App Startup, Firebase, WorkManager or `androidx.core.content.FileProvider` |
| **Maps to** | developer.android.com App Startup (`${applicationId}.androidx-startup`, documented `android:exported="false"`); MASTG-TEST-0355; CWE-927 |

- **Test:** Modern apps ship several providers nobody on the team authored — `androidx.startup.InitializationProvider`, FileProvider variants, Firebase init providers, `ProfileInstallerInitializer` — merged in from AARs and invisible in the app's own source tree. Separately, the FileProvider's `<meta-data>` points at an XML file defining which directories are shareable; over-broad roots turn any URI-grant primitive into a full private-storage read.
- **How:**
```bash
adb shell dumpsys package "$PKG" | sed -n '/Provider Resolver Table/,/^$/p'
grep -nA6 '<provider' out/AndroidManifest.xml
grep -nB2 -A2 'androidx.startup' out/AndroidManifest.xml    # every cold-start initializer
grep -rn 'FILE_PROVIDER_PATHS' out/AndroidManifest.xml
cat out/res/xml/file_paths.xml                              # or whatever the meta-data points at
# the killers:  <files-path path="."/>  <external-path path="Download/"/>  <root-path path="/"/>
grep -rn 'content://' out/smali/ out/res/ | sort -u         # runtime-built, undeclared URIs
grep -rn 'Landroid/net/Uri;->parse' out/smali/ | head
```
- **Proof:** A provider list longer than the set of providers present in the decompiled first-party packages; each `<meta-data android:name="com.example.SomeInitializer" android:value="androidx.startup"/>` names a class that runs **before** the launcher activity's `onCreate`. For FileProvider, a `path="."` or `path="/"` entry quoted verbatim. For undeclared URIs, a `content://` literal in smali or `res/` whose path segment is absent from the manifest's `<provider>` declarations, followed by a successful `content query`.
- **Escalation:** Cold-start initializer order is a pre-authentication code path → D18. Each recovered URI goes into the UriMatcher variant fuzz → D07. `<files-path path="."/>` exposes the whole `files/` dir — but FileProvider canonicalises and blocks `../shared_prefs` traversal, so concede that and point at the equivalent prize that *is* reachable (session-backup payloads written into `files/`).
- **Ruled out when:** Every provider row in `dumpsys` corresponds to a declared first-party or AndroidX provider with `exported=false` and no `grantUriPermissions`, the `file_paths.xml` roots are each scoped to a single subdirectory that holds no credential material, and no `content://` literal in smali or resources names a path absent from the manifest.

### D01-045 · Find privileged listener services declared without their BIND_* permission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the callback accepts and returns) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All. Declaration-side issue, independent of targetSdk |
| **Maps to** | MASWE-0018 (Lack of Authentication or Authorization on App Components); MASVS-PLATFORM-1; CWE-862 |

- **Test:** Apps shipping an AccessibilityService, NotificationListenerService, AutofillService, TileService, CarAppService or WearableListenerService expose a *system-bound* component. The bug is never "it exists" — it is that the component is declared **without** its matching `android:permission` guard, so any third-party app can `bindService()` and drive the callback directly. The docs are explicit that the bind permission "strictly enforces that only the system can bind to your service".
- **How:**
```bash
grep -nE 'android\.accessibilityservice\.AccessibilityService|android\.service\.notification\.NotificationListenerService|android\.service\.autofill\.AutofillService|android\.service\.quicksettings\.action\.QS_TILE|androidx\.car\.app\.CarAppService|com\.google\.android\.gms\.wearable\.(BIND_LISTENER|MESSAGE_RECEIVED|DATA_CHANGED)|android\.service\.voice|android\.app\.slice\.category\.SLICE' out/AndroidManifest.xml
```
For each hit read upward to the enclosing `<service>`/`<provider>` and record whether the matching bind permission is present: `BIND_ACCESSIBILITY_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_AUTOFILL_SERVICE`, `BIND_QUICK_SETTINGS_TILE`. Confirm from an unprivileged PoC app:
```java
bindService(new Intent().setComponent(new ComponentName(
    "com.target.app", "com.target.app.MyNotificationListener")),
    conn, Context.BIND_AUTO_CREATE);
// onServiceConnected(name, binder) -> a non-null IBinder is the proof
```
- **Proof:** A `<service>` carrying the listener `<intent-filter>` and `android:exported="true"` with **no** `android:permission="android.permission.BIND_*"`, plus a non-null `IBinder` delivered to your zero-permission app's `onServiceConnected`. Attach `dumpsys package <attacker> | sed -n '/requested permissions/,/install permissions/p'` showing an empty block.
- **Escalation:** → D06. Whatever the callback does with the `AccessibilityEvent` / `StatusBarNotification` / `FillRequest` objects it now accepts from an attacker is the impact — a listener that trusts its caller was written on the assumption that its only caller is `system_server`.
- **Ruled out when:** Every listener `<service>` carries its matching `BIND_*` permission, or is `exported="false"` (in which case the system cannot bind it either, which is itself a functional bug worth mentioning). A bind attempt returning `SecurityException: Not allowed to bind to service` is the auditable negative.

### D01-046 · Inventory foreground-service types as a background-capability map

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | n/a standalone; High once chained to an exported or implicit start — rate via `broken_access_control.exposed_sensitive_android_intent` (null) in D06 |
| **Attacker** | AM-03 zero-permission local app (starting the FGS) |
| **Applies to** | `targetSdk >= 34` (Android 14+) for the declaration requirement |
| **Maps to** | developer.android.com foreground service types table: `camera`/`FOREGROUND_SERVICE_CAMERA`, `microphone`/`FOREGROUND_SERVICE_MICROPHONE`, `location`, `health`, `mediaProjection`, `connectedDevice`, `dataSync`, `mediaProcessing`, `remoteMessaging`, `shortService`, `specialUse`, `systemExempted` |

- **Test:** From `targetSdk 34` every FGS must declare `android:foregroundServiceType`, and each type requires a specific `FOREGROUND_SERVICE_*` permission plus, for some, a runtime permission. The manifest therefore hands you the list of sensitive capabilities the app can hold while backgrounded.
- **How:**
```bash
grep -nE 'foregroundServiceType|FOREGROUND_SERVICE' out/AndroidManifest.xml
adb shell dumpsys activity services "$PKG" | grep -i 'foreground\|fgType'
# who can start it?
awk -F'\t' '$1=="service" && $3 ~ /true|implicit-true/' recon/components.tsv
```
- **Proof:** `android:foregroundServiceType="microphone"` together with `RECORD_AUDIO` proves a background recording path exists; pair it with a service row from D01-035 that an unprivileged app can start, and the combination is remote-triggered mic capture.
- **Escalation:** → D06 (start the FGS from an unprivileged app), → D20 (the privacy disclosure for an undeclared background capability).
- **Ruled out when:** Every declared FGS type is `dataSync`/`shortService`-class with no sensor or projection permission attached, or every FGS-hosting service is `exported=false` with no implicit-intent start path. On `targetSdk < 34` the attribute is absent by design — use the permission list instead and say so.

### D01-047 · Harvest shortcuts.xml, share-targets and widget metadata as an undeclared entry-point list

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; `broken_access_control.exposed_sensitive_android_intent` (null) once the named internal activity is reached |
| **Attacker** | AM-03 zero-permission local app (via D08 redirection) / AM-11 physical unlocked (pinned shortcut) |
| **Applies to** | All |
| **Maps to** | developer.android.com shortcut management; `<share-target>` in shortcuts.xml; MASTG-TECH-0172 |

- **Test:** `res/xml/shortcuts.xml` and `<share-target>` entries carry `<intent>` elements with fully specified actions, `targetClass` and extras. They frequently name internal activities that are **not** in the public deep-link documentation and are never exercised by normal testing.
- **How:**
```bash
cat out/res/xml/shortcuts.xml 2>/dev/null
grep -rn 'android.app.shortcuts\|share-target\|chooser_target_service\|android.appwidget.provider' \
     out/AndroidManifest.xml out/res/xml/
ls out/res/xml/ | grep -iE 'shortcut|widget|share'
adb shell dumpsys shortcut | sed -n "/$PKG/,/^  [A-Za-z]/p"
# then try each named target directly
adb shell am start -n "$PKG/<targetClass>" --es <extra> <value>
```
- **Proof:** An `<intent android:targetClass="...">` naming an activity that the manifest marks `android:exported="false"`, or one carrying a hard-coded extra such as `"skipOnboarding"` / `"isDebug"` / `"internal"`. The confirming observable is the app reaching that screen or state.
- **Escalation:** → D08 (intent redirection makes the non-exported target reachable from an unprivileged app), → D09 (pinned-shortcut staleness), → D28/D07 (share-receiver plus FileProvider join).
- **Ruled out when:** `res/xml/shortcuts.xml` is absent, or every `<intent>` in it names an activity that is already exported and already in your D01-035 register with a tested status, carrying no state-skipping extra.

### D01-048 · Inventory the deep-link surface including the `<data>` cross-product and the App Links verdict

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the hijacked link carries); a one-time credential delivered to an arbitrary app is `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-02 remote one click |
| **Applies to** | All. `autoVerify="true"` App Links exist from API 23; from Android 12 (API 31) unverified web links no longer default to the app at all |
| **Maps to** | MASTG-TECH-0172 (Listing Deep Links), MASTG-TEST-0393, MASVS-PLATFORM-1; H1 #1667998 (KAYAK, Critical 9.3), #328486 (Zomato), #583987 (Periscope, $1540) |

- **Test:** Three things testers routinely miss. (a) `<data>` elements inside one `<intent-filter>` are merged **combinatorially**, not pairwise — a filter declaring `scheme=https host=www.example.com` and `scheme=app host=open.my.app` accepts four URLs, and the two synthetic combinations frequently reach handlers that skip the validation applied to the "real" scheme. (b) Filters with `pathPattern` or `mimeType` only are separately reachable entry points. (c) Whether App Links actually verified is a runtime fact, not a manifest attribute.
- **How:**
```bash
python3 - <<'PY'
import xml.dom.minidom as m
d = m.parse('out/AndroidManifest.xml'); NS = 'android'
for a in d.getElementsByTagName('activity') + d.getElementsByTagName('activity-alias'):
    for c in a.getElementsByTagName('category'):
        if c.getAttribute(f'{NS}:name') == 'android.intent.category.BROWSABLE':
            print('==', a.getAttribute(f'{NS}:name'))
            for dt in a.getElementsByTagName('data'):
                print('   ', {k: dt.getAttribute(f'{NS}:{k}') for k in
                     ('scheme','host','port','path','pathPrefix','pathPattern','mimeType')
                     if dt.getAttribute(f'{NS}:{k}')})
PY
adb shell dumpsys package "$PKG" | sed -n '/Schemes:/,/^$/p'
adb shell pm get-app-links "$PKG"                       # API 31+ verification state
adb shell dumpsys package domain-preferred-apps
python3 deeplink_analyser.py -op list-all -apk base.apk

for h in app.example.com m.example.com; do
  printf '%s ' "$h"
  curl -s -o /tmp/al.json -w '%{http_code} ' --max-redirs 0 "https://$h/.well-known/assetlinks.json"
  grep -c sha256_cert_fingerprints /tmp/al.json
done
# expand the cross-product by hand and fire each one
adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
  -d "app://www.example.com/reset?token=X"
```
- **Proof:** A table of `scheme://host/path -> Activity`. Entries with `android:scheme` and no `android:host` are unrestricted. A synthetic combination that launches a handler the developer never intended to expose over that scheme, confirmed by `dumpsys activity activities | grep -i <activity>` showing it on top of a task that is not your attacker app's. For the App Links half: `pm get-app-links` reporting a domain in `none` / `legacy_failure` / `verification_failure`, plus a second app declaring the same `<data android:host>` receiving the URL — its `onCreate` logging the full URI including the query string.
- **Escalation:** → D09 (host-validation bypass, parameter injection), → D10 (route ends in a WebView `loadUrl`), → D13 (a password-reset or magic-link token, or an OAuth `code=`, delivered to an arbitrary installed app is full ATO).
- **Ruled out when:** `pm get-app-links` reports every declared web host `verified: true` on a clean install, every custom-scheme filter also constrains `host` and `path`, and every synthetic scheme×host combination you fired either fails to resolve or lands in the same validated router entry point as the canonical form. Enumerate the combinations you fired — an unfired combination is not a negative.

### D01-049 · Enumerate `android_secret_code` dialer receivers

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the code unlocks); High on an OEM image, route to D25 |
| **Attacker** | AM-11 physical unlocked (dialer) / AM-03 zero-permission local app (the broadcast needs no permission) |
| **Applies to** | All devices with a telephony stack; more common in OEM, carrier and telematics apps |
| **Maps to** | MobSF `dialer_code_found`; drozer `scanner.misc.secretcodes` |

- **Test:** `<data android:scheme="android_secret_code" android:host="NNNN"/>` declares a receiver that fires when the code is typed in the dialer — no permission, no consent dialog, no UI trail. They frequently open engineering or diagnostic menus.
- **How:**
```bash
grep -rn 'android_secret_code' out/AndroidManifest.xml out/res/
dz> run scanner.misc.secretcodes
dz> run scanner.misc.secretcodes -v
# trigger without the dialer UI
adb shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://1234
adb shell dumpsys activity activities | grep -i "$PKG"
```
- **Proof:** `Broadcast completed: result=0` followed by the hidden activity appearing in `dumpsys activity activities`, or logcat showing the diagnostic handler running. Screenshot the resulting screen.
- **Escalation:** → D22 (a secret code that flips the app to a staging backend or disables certificate pinning is a full MitM primitive), → D04 (the reached activity is an exported component, test it as one), → D25 on an OEM image (IMEI/serial dump, ADB toggle, engineering flags).
- **Ruled out when:** No `android_secret_code` scheme appears in the merged manifest of any split, and `scanner.misc.secretcodes` returns nothing for the package. Record both.

### D01-050 · Find binary-SMS receivers bound to a port

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); escalates through whatever the parser does |
| **Attacker** | AM-01 remote no interaction (any sender who knows the number) |
| **Applies to** | All devices with a telephony stack |
| **Maps to** | MobSF `sms_receiver_port_found` ("the application should assume that the SMS being received is from an untrusted source"); CWE-20 |

- **Test:** `<data android:port="NNNN"/>` on a receiver's intent-filter declares a data-SMS listener. The payload is parsed by app code that usually assumes the SMS is trusted — and the channel is remote.
- **How:**
```bash
grep -A3 -B6 'android:port' out/AndroidManifest.xml
# emulator console can inject a text SMS:  telnet localhost 5554 ; sms send +15551234 <payload>
# to prove the parser is reachable, drive the receiver directly:
adb shell am broadcast -n "$PKG/.SmsReceiver" \
  -a android.intent.action.DATA_SMS_RECEIVED -d sms://localhost:16998
```
Then read the handler and trace what it does with the bytes — deserialisation, a native parser, a command switch.
- **Proof:** The receiver's parsing code executing on input you fully control, shown by a logcat line or a Frida trace on the handler.
- **Escalation:** → D05 (receiver testing), → D16/D17 if the payload reaches a deserializer or a native parser. A command switch on a data SMS is a remote command channel.
- **Ruled out when:** No `android:port` attribute on any receiver `<data>` element, or the receiver is guarded by `android.permission.BROADCAST_SMS` (a signature-level permission held only by the system) **and** rejects a directly injected broadcast with a `SecurityException`.

### D01-051 · Enumerate the physical-accessory entry points: USB, NFC, BLE and CompanionDeviceManager

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — recon; the D25 items it feeds run High |
| **Attacker** | AM-10 physical locked / AM-11 physical unlocked; NFC reaches AM-02-adjacent proximity |
| **Applies to** | Any app shipping a `device_filter`, `accessory_filter`, NFC tech-list or AID XML — wallets, fitness, IoT companions, POS, automotive, medical, camera and drone apps |
| **Maps to** | developer.android.com USB host (`<usb-device vendor-id product-id>`), USB accessory (`<usb-accessory manufacturer model version>`), NFC dispatch actions and tech-list XML |

- **Test:** These are components the attacker triggers by *touching the phone with hardware*, and they are frequently un-permissioned because the platform, not another app, delivers the intent. No generic manifest sweep catches them as a class.
- **How:**
```bash
grep -nE 'android.hardware.usb.action.USB_(DEVICE|ACCESSORY)_ATTACHED' out/AndroidManifest.xml -B6 -A6
grep -nE 'android.nfc.action.(NDEF|TECH|TAG)_DISCOVERED'                out/AndroidManifest.xml -B6 -A6
ls out/res/xml/ | grep -iE 'device_filter|accessory_filter|nfc_tech|apduservice|aid'
cat out/res/xml/device_filter.xml out/res/xml/accessory_filter.xml 2>/dev/null
grep -rnE 'BLUETOOTH_(CONNECT|SCAN|ADVERTISE)|REQUEST_COMPANION|CompanionDeviceManager' \
     out/AndroidManifest.xml jadx_out/sources
grep -rnE 'openAccessory|openDevice|UsbManager|BluetoothGattServer|connectGatt|onCharacteristicWrite' jadx_out/sources
adb shell dumpsys package "$PKG" | grep -A5 USB_DEVICE_ATTACHED
adb shell dumpsys bluetooth_manager | grep name:
```
- **Proof:** The XML filter files printed, plus `dumpsys package` confirming the filter is registered on the device. For a BLE companion, enumerate custom GATT services *and* standard characteristics (Generic Access / Device Name `0x2a00`) for leaked SSIDs, PSKs, IPs, ports or tokens.
- **Escalation:** → D25 (auto-launch on attach, auto-granted accessory permission, accessory-supplied match strings). A proximity/file-transfer stack that stacks BLE discovery, WiFi Direct, a control socket and a pull-based HTTP download must be audited end to end: send dummy key material through any ECDH/RSA/AES step and continue in plaintext — a receiver that still acks after a fake key exchange, or that reports `DownloadFinished` while the victim UI stays empty, is a zero-click file drop.
- **Ruled out when:** No accessory filter XML, no NFC dispatch action, no `CompanionDeviceManager` call and no GATT server in the decompiled tree. Absence of the XML files alone is not enough — a runtime-registered `BroadcastReceiver` for `USB_DEVICE_ATTACHED` does not appear in the manifest, so check the code too.

### D01-052 · Enumerate every instance of the app on the device: users, work profile, Private Space, OEM clones

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — recon; converts D13 device-binding and D23 entitlement items from "unverified" to "demonstrated" |
| **Attacker** | AM-05 another user of the same app / AM-11 physical unlocked |
| **Applies to** | Android 5+ for multi-user; Android 15+ for Private Space; OEM clone features vary |
| **Maps to** | developer.android.com Android 15 Private Space — "the private space uses a separate user profile", "apps in the private space are installed as separate copies", plus the compat warning about apps whose work-profile logic assumes any non-main copy is a work-profile copy |

- **Test:** Most checklists assume one install per device. In reality the app may exist as user 0, a work profile (user 10+), a Private Space profile, an OEM "dual app" clone and a guest instance — each with its own data dir, its own FCM token and its own session. Any device-binding or entitlement scheme that counts installs is then wrong.
- **How:**
```bash
adb shell pm list users
adb shell pm list packages --user all | grep target
adb shell pm path --user 10 "$PKG"
adb shell dumpsys package "$PKG" | grep -E 'userId|User [0-9]+:|installed=|ceDataInode'
adb shell ls -la /data/user/0/"$PKG" /data/user/10/"$PKG" 2>&1
adb shell pm list users | grep -iE 'dual|clone|999'
# create one to test with
adb shell pm create-user gap && adb shell pm install --user 10 -r base.apk
```
- **Proof:** Two live data directories for the same package under different user ids, each with its own session-token file — screenshot both `ls -la` outputs side by side.
- **Escalation:** → D11 (cross-user data), → D23 (trial and entitlement duplication: one free trial per user profile), → D13 (device binding that counts a device but is actually counting an install).
- **Ruled out when:** `pm list users` shows a single user, the device has no OEM clone feature, and the app's entitlement or device-binding logic keys on a server-issued identifier rather than anything derived from the install. Say which of the three you verified.

### D01-053 · Enumerate the device's inbound network surface created by the app

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.exposed_portal.admin_portal` (P1) when the listener serves an unauthenticated admin/file surface; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it returns app-private bytes |
| **Attacker** | AM-06 network attacker no trusted CA (LAN) for a `0.0.0.0` bind; AM-03 zero-permission local app for a loopback bind — local sockets have **no permission model** |
| **Applies to** | All. Not blocked by package visibility or scoped storage |
| **Maps to** | CVE-2019-6447 (ES File Explorer 4.1.9.7.4, EDB 50070); AirDroid unauthenticated upload (EDB 37504); WiFi Baby Monitor ports 8257/8258 (EDB 44242); Ftp Server 1.32 (EDB 44852, 46464); CWE-306 |

- **Test:** Apps ship local HTTP servers — Wi-Fi transfer, casting/DLNA, WebRTC pairing, leftover RN dev servers. A `0.0.0.0` bind is reachable by anyone on the network; a loopback bind is still reachable by **any other app on the device**. Baseline first, then launch, then diff.
- **How:**
```bash
adb shell cat /proc/net/tcp /proc/net/tcp6 > /tmp/before.txt     # app KILLED
adb shell am start -n "$PKG/.MainActivity"
# exercise the feature — many bind the port only while a screen is open
adb shell cat /proc/net/tcp /proc/net/tcp6 > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt
adb shell ss -lntup
adb shell cat /proc/net/unix | grep -i "$PKG"    # abstract-namespace sockets: NO access control at all

nmap -sT -p- <device-lan-ip>
curl -v http://<device-lan-ip>:<port>/
# the ES File Explorer shape, for reference:
curl -s -X POST http://<device-ip>:59777/ -d '{"command":"getFile"}'
curl -s "http://<device-ip>:59777//data/data/com.target.app/shared_prefs/prefs.xml"
```
- **Proof:** A new row after launch. `00000000:PORT` = bound to `0.0.0.0` (LAN-reachable); `0100007F:PORT` = loopback. The finding is an HTTP 200 returning app-private bytes to an unauthenticated request **from a second host**, captured with the request.
- **Escalation:** Arbitrary file read → session token → D13 account takeover. Arbitrary file **write** → D17 code execution. Any unauthenticated RPC surface → D15.
- **Ruled out when:** The `/proc/net/tcp` diff across a full feature walk-through (including every share/cast/transfer screen) shows no new listening row, `ss -lntup` attributes no listening socket to the app's UID, and `cat /proc/net/unix` shows no abstract-namespace socket under the package name. Note the baseline must be taken with the app force-stopped, or you will attribute a system socket to the app.

### D01-054 · Enumerate the binder services the app's own UID can reach

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (null) when an app-reachable vendor service exposes an ungated privileged transaction |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All; yield is highest on OEM ROMs (MediaTek, Qualcomm, OnePlus, Samsung vendor services). `service_manager find` denial granularity is per-app-domain from Android 9 / targetSdk 28 |
| **Maps to** | AOSP Binder IPC (`/dev/binder`, AIDL interfaces); AOSP SELinux `service_contexts`; AOSP AIDL-for-HALs `<hal format="aidl">…<fqname>`; CWE-862 |

- **Test:** `/dev/binder` is the universal trust boundary between an app and everything privileged, and AIDL performs no access control of its own. Enumerate the registered services, then determine which the app's SELinux domain and permissions actually let it `getService()` and call — reachability from *inside the target UID* is what matters, not the global list.
- **How:**
```bash
adb shell service list      # framework AIDL services on /dev/binder
adb shell dumpsys -l
adb shell cmd -l            # services exposing a shell command surface
frida -U -n "$PKG" -e '
Java.perform(function(){
  var SM = Java.use("android.os.ServiceManager");
  SM.listServices().forEach(function(n){
    var b = SM.getService(n);
    console.log((b ? "REACHABLE " : "denied    ") + n);
  });
});'
adb shell dmesg | grep -i avc | tail -40
# vendor-declared, non-AOSP services live here
adb shell cat /vendor/etc/vintf/manifest.xml
adb shell ls /vendor/etc/vintf/manifest/
adb shell lshal 2>/dev/null | head -50
# probe transaction codes on a reachable service
adb shell 'for i in $(seq 1 50); do printf "[+] %2d -> " $i; service call <svc> $i 2>/dev/null | head -1; done'
```
- **Proof:** A list where `getService()` returns a non-null `IBinder` from inside the target UID; `denied` lines correspond to `avc: denied { find }` in `dmesg`. For a vendor service, a transaction that returns a normal `Parcel` (not `Parcel(00000000 00000000)`) and not a `SecurityException`, whose `Stub.onTransact()` implementation — decompiled from `/system/framework`, `/system_ext` or `/vendor` — has no `enforceCallingOrSelfPermission()` / `isPermissionAllowed()` / `uid == 1000` gate.
- **Escalation:** → D25 (OEM privileged surfaces; this is the classic Samsung/Xiaomi VRP shape), → D06 (a Binder method accepting a `ParcelFileDescriptor` plus a raw `byte[]` is the VPN-bypass confused-deputy shape), → D26 (`fuzzService` target), → D17 (Parcel-mismatch privilege escalation). Also cross-reference `/apex` module versions: `adb shell ls -l /apex | grep '@'` and `cmd package list packages --apex-only --show-versioncode` — a stale Conscrypt or Media module is a real exposure window on a fleet the client controls (D14/D16).
- **Ruled out when:** Every non-AOSP entry in `/vendor/etc/vintf/manifest.xml` is registered on `/dev/vndbinder` (vendor↔vendor only, not app-reachable), and every service the Frida sweep marks REACHABLE is a standard framework service whose transactions all return `SecurityException` to `untrusted_app`. An AOSP/Pixel image will legitimately have few or no non-AOSP entries — say so.

### D01-055 · Device-wide sweep for debuggable packages

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) at minimum; `broken_authentication_and_session_management.authentication_bypass` (P1) when `run-as` yields a session token that authenticates |
| **Attacker** | AM-03 zero-permission local app (JDWP attach needs no permission) / AM-11 physical unlocked |
| **Applies to** | All API levels. The single cheapest high-yield device sweep that exists |
| **Maps to** | drozer `app.package.debuggable`; `dumpsys package … flags=…DEBUGGABLE`; CWE-489-class exposure (no ID verified in corpus — cite the flag itself) |

- **Test:** Debuggable *release* builds still ship — staging/QA APKs published to the store by mistake, OEM preinstalls, SDK-injected builds. A successful `run-as` **is** the proof.
- **How:**
```bash
for p in $(adb shell pm list packages | sed 's/package://' | tr -d '\r'); do
  adb shell run-as "$p" id >/dev/null 2>&1 && echo "DEBUGGABLE $p"
done | tee recon/debuggable.txt
wc -l recon/debuggable.txt          # count — a shell loop that silently ate entries is worthless
adb shell dumpsys package "$PKG" | grep -i 'flags=.*DEBUGGABLE'
dz> run app.package.debuggable -f com.target
# then take the data
adb shell run-as "$PKG" ls -la shared_prefs databases files
adb shell run-as "$PKG" cat shared_prefs/session.xml
adb jdwp                                  # JDWP-attachable pids
```
- **Proof:** `run-as <pkg> id` printing the app's uid instead of `package not debuggable`, followed by a read of a credential-bearing file from the app's private storage — and that credential authenticating against the API from your own host.
- **Escalation:** `run-as` → private storage read (D11); JDWP attach → code execution in the app's UID (D26). On an OEM or carrier handset in a VRP scope, a preinstalled debuggable app means any local actor reads its private storage and runs code as it.
- **Ruled out when:** `run-as "$PKG" id` returns `package not debuggable` and `dumpsys package` shows no `DEBUGGABLE` flag, on the **release** artefact pulled from the device (not a locally built variant). Record the literal denial string.

### D01-056 · Build the per-attacker-model reachability matrix by attempting reach, not by reading the manifest

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this artefact sets the severity of everything else, and its absence is why shell-UID and root-required findings get downgraded |
| **Attacker** | all of AM-01…AM-12 (that is the point) |
| **Applies to** | All |
| **Maps to** | CVSS v3.1 AV/PR metrics; AOSP local-vs-proximal-vs-remote definitions; HackerOne Platform Standards self-sign-up rule ("If self-sign-up is possible, and no other privileges are required, set Privileges Required to None") |

- **Test:** A component × exported × permission table does not say **who** can reach each row. Fill the attacker column by *attempting reach*, and record the literal failure string for every blocked cell — the negative is evidence too.
- **How:**
```bash
# AM-03 zero-permission app: adb shell UID approximates it for activities/services/receivers
adb shell am start        -n "$PKG/<cmp>"; echo "rc=$?"
adb shell am startservice -n "$PKG/<cmp>"
adb shell am broadcast    -n "$PKG/<cmp>" -a "<action>"
adb shell content query --uri "content://<authority>/"
# AM-02 remote one click: does a browser reach it?
adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "<scheme>://…"
# AM-10 physical locked / AM-11 unlocked
adb shell input keyevent 26 && adb shell am start -n "$PKG/<cmp>"     # screen off
# AM-05 another user of the same app
adb shell pm create-user gap; adb shell pm list users
adb shell pm install --user 10 -r attacker.apk
adb shell am start --user 10 -n "$PKG/<cmp>"
```
Then prove the PoC app needs **no** permissions — it is worth a full band:
```xml
<manifest package="com.poc.attacker"><application android:label="PoC"/></manifest>
```
```bash
adb install -r attacker.apk
adb shell dumpsys package com.poc.attacker | sed -n '/requested permissions/,/install permissions/p'
```
- **Proof:** A filled matrix where each reachable cell carries the literal command that reached it and each blocked cell carries the literal denial (`SecurityException`, `Permission Denial`, `does not exist for user 10`). Plus a `dumpsys package` block showing an empty "requested permissions:" list on the attacker APK, with the exploit still succeeding — screenshot both in one recording.
- **Escalation:** The matrix directly produces the "Applies to" and "Severity" lines of every finding, exposes the components no model can reach (drop them) and the ones three models can (test first). It also drives the framing sentence the report must open with: *"The PoC is a zero-permission APK installed by the victim (local) / a web page the victim visits (remote) / a hostile Wi-Fi network (remote-proximal)."* On the AOSP scale, remote arbitrary code execution in an unprivileged context is High while the local equivalent is Moderate — a deep link or WebView that reaches the same sink from a web page converts AV:L into AV:N.
- **Ruled out when:** n/a — no true negative. A row with no attempted-reach cell is untested, not clean. Remember AM-07 (network attacker with a trusted CA) and AM-12 (your own rooted device) are tester conveniences, never attackers: a finding that needs either is not a finding.

### D01-057 · Bind every user-visible feature to its components, endpoints and on-disk artefacts

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — coverage control; it is how whole features avoid being tested at all |
| **Attacker** | n/a (tester method) |
| **Applies to** | All |
| **Maps to** | no external identifier verified — method only |

- **Test:** A "complete" component sweep and a "complete" endpoint list can both be finished without ever having exercised KYC, gift cards or offline sync. Bind each user-visible feature to the component, endpoint and storage that implement it; every later domain consumes this table.
- **How:**
```bash
mkdir -p feat
for F in onboarding register login_password login_social login_biometric otp session profile settings \
         inapp_browser upload download camera gallery media_play maps chat notifications search \
         checkout subscription referral coupon kyc support deeplink widget shortcut share offline \
         sync bgjob logout delete_account; do
  adb logcat -c
  echo ">>> now exercise: $F"; read -r _
  adb shell dumpsys activity activities | grep -E 'ResumedActivity|topResumedActivity' > "feat/$F.top"
  adb logcat -d -v brief > "feat/$F.log"
  adb shell "run-as $PKG ls -laR /data/data/$PKG" > "feat/$F.files"
done
# then one Burp scope note per feature, so every host and path has an owning feature
```
- **Proof:** A table with one row per feature and four populated columns — Activity/Fragment class, exported components touched, backend paths hit, on-disk artefacts created. Any row with an empty column is an untested surface, **named**.
- **Escalation:** Each empty cell becomes a work item in D04–D25. Rows that never appear in the proxy are candidates for offline-only or client-authoritative logic → D23. Rows whose files column shows a new credential-bearing file → D11.
- **Ruled out when:** n/a. The negative is a fully populated table, and a feature you could not reach (no KYC-approved account, no payment sandbox) goes to the blocked register with what was tried and what would unblock it — never silently into the clean column.
