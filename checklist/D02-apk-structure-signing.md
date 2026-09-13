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
