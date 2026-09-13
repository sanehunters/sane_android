# D27 · Reporting, Severity Rating & Evidence

> This domain owns no vulnerability of its own. It owns the conversion rate: the same demonstrated
> primitive lands at `broken_authentication_and_session_management.authentication_bypass` (P1) or at
> `mobile_security_misconfiguration.ssl_certificate_pinning.absent` (P5) depending on how it is titled,
> which VRT node it is filed under, whether a negative control was recorded in the same take, and whether
> the chain's unproven link was named or hidden. Its own severity ceiling is **Support** on every item
> but two — the VRT-routing item (D27-012) and the shadow-API framing item (D27-074) — and those two are
> worth more than most technical items in the whole checklist.

| | |
|---|---|
| **Phases** | P8 write-up and severity, P9 submission, triage and retest |
| **Milestones** | M8, M9 |
| **VRT ceiling** | No node of its own. The domain's job is to reach the consumer node the evidence supports: `server_side_injection.remote_code_execution_rce` (P1), `broken_authentication_and_session_management.authentication_bypass` (P1), `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1), `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1), `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1) — and, where the finding is genuinely Android-native, `broken_access_control.exposed_sensitive_android_intent` (**priority null — rated entirely on what you demonstrate**, CWE-927) |
| **Primary attacker model** | AM-03 zero-permission local app — the model most mobile findings actually claim, and the one whose wording decides the rating. AM-12 own rooted device appears throughout as the model that must never be presented as an attack |
| **Maps to** | MASVS-STORAGE-1/2, MASVS-AUTH-1, MASVS-PLATFORM-1/2, MASVS-CODE-4, MASVS-RESILIENCE-1..4, MASVS-PRIVACY-1..4 (all 24 v2 controls are the anchoring vocabulary); MASTG-TEST-0003, MASTG-TEST-0028 (`status: deprecated`, `covered_by: [MASTG-TEST-0393, MASTG-TEST-0394]`), MASTG-TEST-0204, MASTG-TEST-0223, MASTG-TEST-0226, MASTG-TEST-0232, MASTG-TEST-0235, MASTG-TEST-0242, MASTG-TEST-0243, MASTG-TEST-0244, MASTG-TEST-0304 (`status: placeholder`), MASTG-TEST-0316, MASTG-TEST-0324, MASTG-TEST-0325, MASTG-TEST-0326, MASTG-TEST-0329, MASTG-TEST-0338, MASTG-TEST-0341, MASTG-TEST-0351, MASTG-TEST-0352, MASTG-TEST-0353, MASTG-TEST-0399; MASTG-TECH-0009, MASTG-TECH-0023, MASTG-TECH-0033, MASTG-TECH-0035, MASTG-TECH-0043, MASTG-TECH-0165, MASTG-TECH-0173; MASTG-TOOL-0024 (Scrcpy), MASTG-TOOL-0104, MASTG-TOOL-0140; MASWE-0001..MASWE-0078 as the impact vocabulary; CWE-319, CWE-798, CWE-321, CWE-359, CWE-266, CWE-306, CWE-925, CWE-926, CWE-927, CWE-939, CWE-919, CWE-729, CWE-922, CWE-311, CWE-693, CWE-929; ATT&CK Mobile tactics TA0027, TA0041, TA0028, TA0029, TA0030, TA0031, TA0032, TA0033, TA0035, TA0036, TA0037, TA0034; NIST SP 800-115 §6.6, §8.1, §8.2, §8.3, Appendix B §3.1, §3.2, §5.3, §6; FIRST CVSS v3.1 and v4.0 |

## Why this domain pays

It pays negatively and enormously. The corpus contains a controlled comparison that settles the argument:
the *same* class of Android finding, written two ways, produced **$0** (H1 #1225158, titled "ADB Backup is
enabled within AndroidManifest") and **High** (H1 #288955, titled "Theft of arbitrary files leading to
token leakage"). H1 #3399016 — "improper input validation on exported deep-link handler crashes
FileDisplayActivity" — closed at **0.0**. H1 #1667998 — "1 click Account takeover via deeplink" — closed
at **Critical 9.3** and was patched by the vendor in **24 hours**. Nothing about the underlying Android
mechanism separates those outcomes. The title, the precondition wording and the evidence package do.

The structural reason is the taxonomy. The entire mobile branch of the Bugcrowd VRT (release
`2026-07-08`) is **P5**: pinning absent and pinning defeatable, auto-backup, clipboard, tapjacking,
screen caching, every `lack_of_binary_hardening` child, sensitive data unencrypted on internal storage,
and malformed-intent app crash. External storage and plaintext server-side credential storage are
**P4**. Exactly one Android-native node is not pinned to a priority —
`broken_access_control.exposed_sensitive_android_intent`, whose priority is `null` and whose placeholder
CVSS is all-None (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`). That is not a rejection; it is an instruction
to supply the impact yourself. Every other route to P1 runs through a node borrowed from the web
taxonomy. A tester who files the mechanism they found rather than the impact they proved has
pre-selected a P5 before a triager has read a word.

There is no base rate to quote for "reporting quality" and the corpus does not invent one. What it does
give is the cost of the failure modes: Google's Android & Google Devices programme states it "actively
monitors the Signal-to-Noise Ratio (SNR) of all participating researchers", that unverified, automated
or AI-generated "hallucinated" findings are Code of Conduct violations, and that low-SNR accounts "will
be subject to automated rate limiting … and may face permanent removal". Google's Mobile VRP multiplies
the whole payout by **0.5x for Low Quality and 1.5x for Exceptional Quality** (a root-cause analysis plus
a proposed patch) — a 3x spread on analysis and wording alone. And the corpus records one of its own
authors shipping a false existential claim ("there is no `createChooser` anywhere in the app's own code"
— there were nine, several attaching a FileProvider URI with `FLAG_GRANT_READ_URI_PERMISSION`) inside an
already-submitted report. The conclusion survived; the credibility would not have.

## The crux question

**For this finding, what is the cheapest attacker position from which I have actually observed the
boundary being crossed — and does the title, the VRT node, the CVSS vector and the recorded evidence all
say exactly that, with the unproven link named rather than hidden?**

## Triage order

1. **Run the pre-severity gate against the Critical claim, not the bug** (D27-022). It is the only step
   that prevents a retraction, and a retraction costs more than the finding was worth.
2. **Choose the VRT node by demonstrated impact** (D27-012, D27-013). A wrong node caps the payout before
   triage begins and no amount of body text recovers it.
3. **Write the title as the impact category** (D27-001). Triagers read titles in about three seconds and
   order the queue from them.
4. **Fix the acquisition path and the attacker model, then the precondition wording** (D27-016, D27-002,
   D27-023). Reducing the precondition is worth more than inflating the impact — consistently 5–10x on
   the same bug.
5. **Run the false-positive gates** (D27-051 through D27-061). Marker discipline, the body-diff rule and
   the layer-ordering trap between them kill most of what would otherwise be retracted.
6. **Assemble the evidence package with both controls in the take** (D27-029, D27-030, D27-041). A
   positive alone is not proof; the differential is the proof.
7. **Score CVSS from the demonstrated attack only, metric by metric** (D27-017 → D27-021).
8. **Write the ruled-out register** (D27-048). It is a deliverable, it pre-empts "did you check X?", and
   it is what makes a clean report worth its fee.
9. **File in chain order — primitives first, consumer second, backfill the links** (D27-067).
10. **Have the next rung of the triage ladder already built before you submit** (D27-064).

## Items

### D27-001 · Title the impact category, never the Android mechanism

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none directly — but the title is what routes the report to `broken_authentication_and_session_management.authentication_bypass` (P1) instead of `mobile_security_misconfiguration.*` (P5) |
| **Attacker** | AM-03 (the model most mobile titles claim) |
| **Applies to** | every report |
| **Maps to** | H1 #1225158, #288955, #3399016, #3829030, #1667998; Bugcrowd VRT release `2026-07-08`; CWE-927 |

- **Test:** The title must contain a noun the attacker **gains** (token, session, file, money, code
  execution, another user's record) or a state the victim **loses**. A title naming a manifest attribute,
  a WebView setting or an Android class is an informational note before it is read.
- **How:** Use one of the two forms, and check the draft against the corpus's own price list.
  ```text
  FORM A  <Impact> via <component/mechanism>, exploitable by <attacker model>
  FORM B  [Bug class] in [exact component/endpoint] allows [attacker role] to [impact] [victim scope]

  $0        "ADB Backup is enabled within AndroidManifest"                       H1 #1225158
  High      "Theft of arbitrary files leading to token leakage"                  H1 #288955
  0.0       "Improper input validation on exported deep-link handler crashes …"  H1 #3399016
  Low 3.3   "Debug Deep Link Abuse Allows Repeated Forced Logout"                H1 #3829030
  Crit 9.3  "1 click Account takeover via deeplink"                              H1 #1667998

  GOOD "Session token disclosure to any zero-permission app via exported ContentProvider
        com.target.provider/auth"
  BAD  "Exported ContentProvider" / "Insecure data storage" / "Security issue in API"
  ```
- **Proof:** The title, read alone with no body, states who the attacker is, what they obtain and whose
  it is. Read it to someone who has not seen the report and ask them to state the severity.
- **Escalation:** The title is the routing decision for D27-012 (VRT node selection); get it right and the
  node follows. -> D15 where the impact is server-side, -> D08/D10 where the mechanism is IPC or WebView.
- **Ruled out when:** The finding genuinely has no impact noun — in which case it is not a finding, it is
  a ruled-out register row or a hardening note (D27-048), and the correct action is to delete the draft,
  not to rename it.

### D27-002 · The preconditions-and-boundary block, as the first thing in the body

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — this block is what moves a `null`-priority node to its final priority |
| **Attacker** | AM-01 … AM-12, stated by ID |
| **Applies to** | every finding |
| **Maps to** | AOSP security-model paper §2.3 adversary taxonomy and §4.3.1 (DAC = apps, MAC = platform, Android permissions = users); AOSP "Application Sandbox"; Bugcrowd VRT `broken_access_control.exposed_sensitive_android_intent` (priority null) |

- **Test:** Three facts, before any prose: the attacker's starting position, the boundary crossed, and
  what was obtained. If any of the three is missing the finding is not yet reportable. Add the AOSP
  adversary-class tags where the programme's threat model uses them.
- **How:**
  ```text
  Attacker model : AM-03 — an installed app with zero requested permissions, signed with an unrelated key
  AOSP class     : [T.A2] abusing other apps' APIs        (others: T.P1–T.P4, T.N1–T.N3, T.A1–T.A8, T.D1–T.D2)
  Boundary       : UID sandbox (u0_a231 -> attacker uid) via exported ContentProvider
  Obtained       : /data/data/com.target.app/databases/app.db — session JWT + 1,204 PII rows
  Replay         : HTTP 200 from api.target.example/v1/me using the extracted JWT
  Preconditions  : victim has the app installed and has logged in once; no user interaction thereafter
  Tested on      : Pixel 7a, Android 15 (API 35), patch 2026-08-01, stock non-rooted, USB debugging off
  ```
  Name which of the three enforcement mechanisms was defeated — DAC, MAC (SELinux) or Android
  permissions — and whose authorisation was bypassed (user, developer, platform, or the DPC in a managed
  deployment).
- **Proof:** The block itself, plus the command output backing each line (`dumpsys package com.attacker`
  showing an empty requested-permissions list; `pm list permissions -f` showing the enforced protection
  level of the custom permission the developer believed was `signature`).
- **Escalation:** This block is the input to the CVSS vector (D27-017 → D27-019) — each line maps to a
  metric, so a vector that disagrees with the block is a defect in one of them.
- **Ruled out when:** You cannot name a boundary. A capability the attacker already had (reading their
  own sandbox, screenshotting their own screen, decompiling a public APK) crosses nothing; file it as a
  hardening note, not a finding.

### D27-003 · The artefact fingerprint header block

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 (own harness; not an attack) |
| **Applies to** | every finding, every report |
| **Maps to** | H1 #2553411 (Basecamp), #1737358 (Shopify), #1667998 (KAYAK) — all three opened with this block and all three were reproduced by the vendor first try; Exploit-DB entry format (`Version:` / `Tested on:` / `CVE:`; EDB 44690 and 46933 are visibly weaker for omitting them) |

- **Test:** A version-blind Android report is the single most common cause of a valid finding being closed
  as "not applicable". Capture the identity of the artefact, the device and the platform, in text, not as
  a screenshot — Google's submission guidance requires device and build **in text**.
- **How:**
  ```bash
  PKG=com.target.app
  aapt2 dump badging base.apk | grep -E 'package: name|versionName|versionCode|sdkVersion|targetSdkVersion'
  sha256sum base.apk
  apksigner verify --print-certs base.apk | grep -i 'Signer #1 certificate SHA-256'
  adb shell dumpsys package $PKG | grep -E 'versionName|versionCode|targetSdk|minSdk|firstInstallTime|flags='
  adb shell getprop ro.build.version.release; adb shell getprop ro.build.version.sdk
  adb shell getprop ro.build.version.security_patch; adb shell getprop ro.build.fingerprint
  adb shell getprop ro.product.model; adb shell getprop | grep build.version.extensions
  date -u
  ```
- **Proof:** A fixed header on every finding carrying package name, versionName + versionCode, APK
  SHA-256, signer SHA-256, min/target SDK, device model and fingerprint, Android release + API level, and
  security patch level. `user/release-keys` in the fingerprint is what proves the finding is not an
  emulator artefact.
- **Escalation:** -> D22 for the version-gate verdict; -> D02 where the pulled artefact's hash does not
  match the store build. The same block is the retest baseline (D27-071).
- **Ruled out when:** Never — this block is unconditional. The only variation is that OTA-capable apps
  additionally require D27-004.

### D27-004 · Cite the executing artefact, not the shipped one

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — but omitting it produces a finding whose every `file:line` is accurate and whose conclusion is wrong |
| **Attacker** | AM-08 / AM-09 (the SDK or backend that can change the executing code) |
| **Applies to** | React Native with CodePush or expo-updates; Cordova/Capacitor live-update plugins; any app with `DexClassLoader`/`System.load` from a writable path |
| **Maps to** | MASTG-TOOL-0104 (`file`-based engine identification), MASTG-TECH-0165; `CodePushConstants.DEFAULT_JS_BUNDLE_NAME`, `CODE_PUSH_FOLDER_PREFIX`, `STATUS_FILE`; expo `UpdatesConfiguration.kt` |

- **Test:** For any app that can replace its own code after install, the APK you decompiled may not be the
  code that ran. Every citation must come from the artefact that was **executing** at test time.
- **How:**
  ```bash
  adb shell "run-as $PKG find files -name 'index.android.bundle' -exec md5sum {} \;"
  adb shell "run-as $PKG ls -la files/CodePush files/.expo-internal 2>/dev/null"
  adb shell dumpsys package $PKG | grep -E 'versionCode|lastUpdateTime'
  file lib/arm64-v8a/libapp.so            # Flutter AOT snapshot identity
  file assets/index.android.bundle        # Hermes bytecode version
  ```
  Record in the finding: framework and engine version (e.g. "Hermes JavaScript bytecode, version 94"),
  the bundle `sourceHash` or snapshot hash, whether OTA is enabled, which bundle was live at test time,
  the extraction tool and version, and the exact path inside the APK.
- **Proof:** For an OTA finding the decisive pair is a **changed bundle hash with unchanged `versionCode`
  and `lastUpdateTime`**, plus a recording of the injected behaviour. That pair is what makes an
  RCE-class OTA finding undeniable.
- **Escalation:** -> D17 dynamic loading and OTA integrity; -> D19 cross-platform frameworks. Supports
  `server_side_injection.remote_code_execution_rce` (P1) when the channel is unsigned.
- **Ruled out when:** `aapt2 dump badging` shows no OTA library, a grep across the decompiled tree for
  `CodePush|expo-updates|LiveUpdate|DexClassLoader|createPackageContext` returns nothing, and the app's
  code directory contains no writable bundle. Attach the grep output.

### D27-005 · The per-finding template — fill every field, because blanks are what triage attacks

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG v2 test structure Overview → Steps → **Observation** → **Evaluation** → "Further Validation Required"; developer.android.com `privacy-and-security/risks` page structure (Overview → Impact → Mitigations → MASVS category) — triagers recognise both shapes |

- **Test:** Every finding carries the same fields in the same order. A missing field is not neutral; it is
  the gap a triager probes first.
- **How:**
  ```text
  FINDING ID · TITLE
  SEVERITY (+ CVSS vector)  ·  CWE  ·  MASVS control  ·  CONFIDENCE (confirmed / probable / hypothesis)
  STATUS  SUSPECTED | NEEDS-VERIFICATION | VERIFIED | REPORTABLE | DUPLICATE | NOT-SECURITY-IMPACTING | OUT-OF-SCOPE
  AFFECTED VERSION / COMPONENT    (versionName+versionCode; for OTA apps the EXECUTING bundle — D27-004)
  ATTACKER MODEL & PRECONDITIONS  (D27-002 block)
  ROOT CAUSE                      the mechanism, precisely, at file:line
  EXISTING DEFENCE & WHY IT FAILS (or holds)
  ATTACK FLOW -> DETAILED REPRODUCTION -> MINIMAL PoC
  OBSERVATION vs EVALUATION       raw output first, then why it fails
  EXPECTED vs ACTUAL
  SECURITY IMPACT                 (+ impact ceiling if chain-dependent)
  EVIDENCE                        paths into the evidence tree (D27-029)
  CHAINING                        links, each marked verified or unproven
  REMEDIATION                     exact change, exact place, developer-runnable verification, residual risk
  OWNER                           CLIENT-FIX | SERVER-FIX | BOTH | THIRD-PARTY-SDK
  LIMITATIONS                     what was NOT proven, and the environment that would prove it
  ```
- **Proof:** A completed template per finding with no empty field; `LIMITATIONS` and `EXISTING DEFENCE`
  populated even when the answer is "none found, grep attached".
- **Escalation:** The `CHAINING` field is the input to D27-021 (two-verified-links) and D27-067
  (chain-filing order).
- **Ruled out when:** Never skipped. For a single-paragraph bounty submission, compress rather than drop:
  title, preconditions block, reproduction, observation, impact, evidence — the rest moves below the
  fold.

### D27-006 · Ban "could potentially", "may allow", "could be used to"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | every sentence in every report |
| **Maps to** | Google Mobile VRP: "Impact is judged based on the actual reported impact … not on a potential impact … if you do not demonstrate this in your report, the reward amount will not reflect this" |

- **Test:** Either the thing happens or it does not. Conditional-impact language is the triager's signal
  that the report is theoretical, and theoretical reports are closed.
- **How:** Two valid paths only — demonstrate the impact end to end with the full request/response
  sequence, or **downgrade the severity claim to match what you actually demonstrated**. Never split the
  difference.
  ```text
  BAD  "This vulnerability could potentially allow an attacker to access user data."
  GOOD "An attacker can access any user's order history by changing the user_id parameter. Confirmed
        with two test accounts: attacker@test.com (ID 123) retrieved victim@test.com (ID 456) orders,
        including shipping address and payment-method last four digits."
  ```
  Grep the draft before sending:
  ```bash
  grep -nEi 'could (potentially|be used|lead)|may allow|might allow|possibly|in theory|theoretically' report.md
  ```
- **Proof:** The grep returns nothing, or returns only sentences inside the explicit `LIMITATIONS` field
  where conditional language is correct and honest.
- **Escalation:** Where the conditional is load-bearing, convert it into an explicit **severity fork**
  (D27-021): state both branches, say static evidence cannot distinguish them, say you did not test which
  is true, and ask the vendor the question they can answer from their own logs.
- **Ruled out when:** The sentence is inside `LIMITATIONS` or a severity fork and is labelled as such.

### D27-007 · Optimise the first 600 words for the triager's read sequence

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | bug-bounty submissions; the client-report equivalent is the executive summary |
| **Maps to** | Intigriti Triage Standards ("All submissions are required to come with a written, step-by-step demonstration of an attack", "the simplest possible demonstration that proves the vulnerability's exploitability and impact beyond reasonable doubt"); Bugcrowd "Reporting a Bug" (overview, walkthrough/PoC, evidence, demonstrated impact) |

- **Test:** The observed read sequence is title (≈3 s) → first impact paragraph (≈15 s) → **the curl
  command or HTTP request block (≈30 s)** → reproduction steps only if the first three convinced →
  everything else only on follow-up. Build the report in that order.
- **How:** Put, in this sequence: the title; the one-sentence impact; the preconditions block; the single
  copy-pasteable command that does the whole thing; then the evidence index. Keep the top under 600
  words and push analysis below it.
  ```bash
  # the one line that must appear above the fold
  adb shell am start -W -a android.intent.action.VIEW -d "<the exact payload>"
  ```
- **Proof:** A reader who stops after 600 words can restate the mechanism and the impact correctly.
- **Escalation:** For a client deliverable the same discipline produces the executive summary: what was
  tested, the bottom line in one repeatable sentence, the severity roll-up, the top five actions ordered
  by risk reduction per unit of effort, what was verified as **working**, and coverage/limitations — with
  no CVEs, class names, CVSS vectors, tool names or unexpanded acronyms.
- **Ruled out when:** The finding genuinely needs a long root-cause analysis above the fold — it does
  not. Move it to a "Root cause" section; Google pays 1.5x for having one, not for it being first.

### D27-008 · Name the defence that fails, quoting the method that implements it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0023 (Reviewing Decompiled Java Code); Google Mobile VRP "Exceptional Quality (1.5x)" — "includes a root cause analysis, which helps us find other similar variants of the issue" |

- **Test:** Every finding sits next to a control someone believed worked. Write the mechanism, not the
  pattern. A sentence a triager can verify by reading one method beats a page of argument.
- **How:**
  ```text
  GOOD "The validator parses the host with OkHttp topPrivateDomain() and does exact set-membership, so
        an @-userinfo authority resolves to the real host and is rejected — but the same value is
        re-parsed by Uri.parse() at Router.java:214 without the check, and that is the call site the
        deep link reaches."
  BAD  "The host check looks bypassable."
  ```
  Find the control before you claim the bypass: grep for the **validator** and enumerate every call
  site — the unguarded sibling is the finding.
  ```bash
  grep -rn 'isAllowedHost\|validateUrl\|checkOrigin\|ALLOWED_HOSTS' jadx_out/sources | tee validator-sites.txt
  ```
- **Proof:** The mitigation's code quoted alongside the residual gap. The corpus's own worked example: the
  first hypothesis was "JS bridges persist across cross-origin navigation"; reading
  `shouldInterceptRequest` showed bridges **are** stripped on main-frame navigation, so the real,
  narrower and defensible bug was **main-frame-only enforcement -> cross-origin iframe**.
- **Escalation:** The unguarded sibling call site is usually a second finding. -> D10 WebView, -> D09
  deep links, -> D07 providers.
- **Ruled out when:** You read the mitigation path in full and it holds on every call site — then the
  correct output is a ruled-out register row naming the method and the call-site enumeration (D27-048),
  which is worth more to the client than the finding would have been.

### D27-009 · State what the finding is NOT

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | every High or Critical claim |
| **Maps to** | MHL CVE-2025-48595 ("Important: What This Is (and Isn't)"); MHL CVE-2026-28576 TL;DR severity row, where the authors argue **down** against GitHub's 10.0 Critical because "the victim must pick a contact inside the attacker's app" while the Android bulletin rates it High |

- **Test:** Write a short "what this is and is not" paragraph next to the impact claim. This is the single
  behaviour most strongly correlated with a triager trusting the rest of the report.
- **How:** Name the boundaries you did **not** cross, in the triager's own vocabulary:
  ```text
  This is not a privilege escalation to system or root. It does not break the app sandbox, grant new
  permissions, or compromise system_server. What it does is let a zero-permission app escape the managed
  ART execution environment into native code execution inside its own process — which then unlocks
  <the capability table>.
  ```
  If your own analysis disagrees with a published score, say so and show the arithmetic rather than
  silently adopting the higher number.
- **Proof:** The paragraph, plus a capability table showing what the limited primitive does unlock.
- **Escalation:** The capability table is the bridge to the chain (D27-021) — it says precisely which
  further finding would raise this one.
- **Ruled out when:** The finding genuinely has no adjacent over-claim to disclaim (a clean cross-account
  IDOR with two accounts demonstrated). Even then, state that testing stopped at two records.

### D27-010 · Give every finding an OWNER

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | client engagements; useful on bounty reports where the programme routes internally |
| **Maps to** | NIST SP 800-115 §8.2 (results "made available to the appropriate staff… as well as appropriate program managers or system owners"), §8.3 (POA&M coordination through the configuration control board) |

- **Test:** A mobile assessment delivered only to the mobile team dies for every finding whose fix is
  server-side — and on a well-run engagement that is most of the High-severity ones: authorisation,
  token lifetime, rate limiting, object-level access control.
- **How:** Add an `OWNER` line to the template and classify every finding as `CLIENT-FIX`, `SERVER-FIX`,
  `BOTH` or `THIRD-PARTY-SDK`:
  ```text
  OWNER: API / platform team — the enforcement point is server-side authorisation on GET /v1/orders/{id};
         the mobile change (stop sending the id from client state) is a hardening measure, not the fix.
  ```
  For `THIRD-PARTY-SDK`, first establish it really is the SDK and not the client's integration of it, and
  give the client a mitigation that does not depend on the vendor:
  ```bash
  unzip -p apk/base.apk 'META-INF/*.version' 2>/dev/null | head -40
  apkanalyzer dex packages apk/base.apk | awk '$1=="P"{print $4}'
  # client-side mitigations available today: tools:node="remove", or android:exported="false" override
  ```
- **Proof:** A remediation tracker whose `owner` column is fully populated, and a readout attendee list
  that matches it.
- **Escalation:** A `SERVER-FIX` finding discovered through the mobile client is still a mobile-engagement
  finding (-> D15); do not let it be deferred as "out of scope for the app team". Upstream disclosure of
  an SDK defect is the **client's** decision — offer to write the report, never send it without written
  instruction.
- **Ruled out when:** The finding is unambiguously in the app's own code and has no server-side
  enforcement point — state that explicitly rather than leaving the field blank.

### D27-011 · Reportability opinion and submission order are part of the deliverable

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | corpus reportability convention (`reportable / informative / likely duplicate`) |

- **Test:** For every finding, state plainly whether it is **reportable**, **informative** or a **likely
  duplicate**, with the reason — and rank what to submit first. Have the answer ready before anyone asks.
- **How:** Add two columns to the findings table and populate them at the verification gate:
  ```text
  | id | title | sev | conf | reportability | rank | rationale |
  | F-007 | Session token to any zero-perm app via provider | High | confirmed | reportable | 1 | crosses UID, server replay shown |
  | F-011 | allowBackup=true                                 | Info | confirmed | informative | — | no credential in backup; ruled-out row |
  | F-014 | Deep-link host startsWith() bypass               | Med  | confirmed | likely dup  | 4 | fixed pattern appears in changelog 8.2.1 |
  ```
- **Proof:** The ranked submission order with a one-line rationale each, dated.
- **Escalation:** The ranking drives D27-067's filing sequence (primitives → consumer → clean standalone
  → scope-risky last).
- **Ruled out when:** Never — an unranked finding set is an unfinished deliverable.

### D27-012 · Never file under a mobile VRT node when an impact node exists

| | |
|---|---|
| **Severity ceiling** | **Critical** — this item is the difference between P5 and P1 on identical technical facts |
| **VRT** | target `broken_authentication_and_session_management.authentication_bypass` (P1), `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1), `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1), `server_side_injection.remote_code_execution_rce` (P1), `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1), `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2), `cryptographic_weakness.key_reuse.inter_environment` (P2) |
| **Attacker** | AM-03 |
| **Applies to** | Bugcrowd directly; the logic transfers to HackerOne, Intigriti and YesWeHack |
| **Maps to** | Bugcrowd VRT JSON, `metadata.release_date` `2026-07-08`, parsed directly; Bugcrowd guidance that the recommended priority "might apply without context" and that researchers should "submit the issue regardless and use the Bugcrowd Crowdcontrol commenting system to clearly communicate their reasoning" |

- **Test:** Bugcrowd's mobile-specific taxonomy is almost entirely P5/P4. The same technical issue filed
  under its impact category is P1/P2. Before submitting, look up where the finding lands in **both**
  places and file under the impact.
- **How:** The mobile-native bands, verbatim, and the impact nodes to reach instead:
  ```text
  P5  mobile_security_misconfiguration|auto_backup_allowed_by_default
  P5  mobile_security_misconfiguration|clipboard_enabled
  P5  mobile_security_misconfiguration|ssl_certificate_pinning|absent
  P5  mobile_security_misconfiguration|ssl_certificate_pinning|defeatable
  P5  mobile_security_misconfiguration|tapjacking
  P5  insecure_data_storage|sensitive_application_data_stored_unencrypted|on_internal_storage
  P4  insecure_data_storage|sensitive_application_data_stored_unencrypted|on_external_storage
  P4  insecure_data_storage|server_side_credentials_storage|plaintext
  P5  insecure_data_storage|screen_caching_enabled
  P5  insecure_data_storage|non_sensitive_application_data_stored_unencrypted
  P5  lack_of_binary_hardening|{lack_of_exploit_mitigations,lack_of_jailbreak_detection,
                                lack_of_obfuscation,runtime_instrumentation_based}
  P5  application_level_denial_of_service_dos|app_crash|malformed_android_intents
  P4  sensitive_data_exposure|via_localstorage_sessionstorage|sensitive_token
  P5  sensitive_data_exposure|sensitive_data_hardcoded|oauth_secret
  null broken_access_control|exposed_sensitive_android_intent          <- the ONE that is rated on impact
  ```
  Re-verify the file rather than trusting this snapshot:
  ```bash
  jq -r '.metadata.release_date' vulnerability-rating-taxonomy.json
  jq -r '.content[] | .. | objects | select(has("id") and has("priority")) | "\(.id)\t\(.priority)"' \
     vulnerability-rating-taxonomy.json | grep -Ei 'mobile|binary_hardening|insecure_data_storage'
  ```
- **Proof:** The submission is accepted at the impact category's priority, not the mobile category's.
- **Escalation:** Bundle the P5 observations **into** the chain that produced the P1 rather than filing
  them separately — one Critical beats five informationals, and five informationals damage the SNR that
  gates private-programme invitations (D27-070).
- **Ruled out when:** No impact node fits because the finding genuinely has no demonstrated impact — in
  which case D27-001 already told you not to file it.

### D27-013 · "Varies" is an invitation, not a rejection

| | |
|---|---|
| **Severity ceiling** | **High** (realistically; the node has no ceiling of its own) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (priority **null**, CWE-927, placeholder CVSS `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`) |
| **Attacker** | AM-03 |
| **Applies to** | Bugcrowd; the only Android-native node not pinned to P5 |
| **Maps to** | Bugcrowd VRT `broken_access_control/exposed_sensitive_android_intent`; CWE-927 (Use of Implicit Intent for Sensitive Communication) |

- **Test:** The placeholder vector is all-None on every impact metric. That is the taxonomy telling you
  the rating is entirely determined by what you demonstrate — so supply the three things the placeholder
  leaves blank.
- **How:** In the body, spell out: (1) **who can reach the component** — "any installed app, zero
  requested permissions, shown by `dumpsys package com.attacker`"; (2) **what it does** — the specific
  sensitive action or data, not "it is exported"; (3) **what the victim loses**. Attach the
  third-party-app PoC (D27-042), and propose the vector yourself with one sentence per metric.
  ```bash
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Service Resolver Table/p'
  adb shell dumpsys package com.attacker | sed -n '/requested permissions/,/install permissions/p'
  ```
- **Proof:** A priority assigned above P4 on a node whose default is nothing.
- **Escalation:** Where the exposed intent reaches a WebView, a provider or an auth flow, the correct node
  is the consumer's (-> D10, -> D07, -> D13) and this node becomes the mechanism paragraph.
- **Ruled out when:** The component is exported but inert — no reachable sink behind it. Show the
  `onCreate`/`onReceive`/`onBind` body and the absence of a sink, and file it as a ruled-out row.

### D27-014 · Pick the most specific *accurate* VRT node, then set severity separately

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | whichever node genuinely fits; `... → Other` with a mapping note when none does |
| **Attacker** | n/a |
| **Applies to** | Bugcrowd submissions |
| **Maps to** | Bugcrowd VRT node→default-severity binding; the corpus's own caveat that VRT defaults are not constants — Bugcrowd revises the schema and programmes remap defaults |

- **Test:** The VRT dropdown's default severity is bound to the node. Choosing a node that misrepresents
  the bug in order to inherit a higher default gets reassigned and may be flagged. Choose accurately,
  then move severity with the argument (D27-015).
- **How:** Search the taxonomy in this order — primary bug class → data category exposed → control
  bypassed → endpoint type → generic parent node. Worked mappings:
  ```text
  ATO via missing re-auth on password change  -> Broken Auth → 2FA/MFA → Bypass
                                       else   -> Broken Auth → Authentication Bypass → Other
  Password oracle with no rate limit          -> Broken Auth → Authentication Bypass → Other
                                       else   -> Server Security Misconfig → No Rate Limiting on Form → Login
  GraphQL persisted-query allow-list bypass   -> Server Security Misconfig → Other (justify in body)
  Username -> real-name PII enumeration       -> Sensitive Data Exposure → PII Leakage → Non-Corporate User
  Email-change OTP / reset-token brute force  -> Broken Auth → Authentication Bypass → Other
  ```
  If nothing fits, pick `→ Other` and lead the body with a **"VRT mapping note"**.
- **Proof:** The node you chose is one a triager would also have chosen, and the severity argument is in
  the body rather than smuggled into the node.
- **Escalation:** Pair with D27-015; the node sets the default, the severity-request paragraph moves it.
- **Ruled out when:** The programme is not on Bugcrowd. Read the current form for **this** programme
  rather than a cached table — defaults are remapped per programme.

### D27-015 · The severity-request paragraph, as the first body section

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Bugcrowd; the framing transfers to HackerOne and Intigriti |
| **Maps to** | Bugcrowd Crowdcontrol commenting guidance; the observation that CVSS 3.1, the Bugcrowd VRT and HackerOne's default severity disagree roughly 30% of the time |

- **Test:** Triagers auto-close when they see P4 in the form. Pre-empt it with a literal, recognisable
  opening section rather than arguing after the close.
- **How:**
  ```markdown
  ## Severity request — please review carefully before applying VRT default

  The closest VRT category is "[chosen VRT]," which Bugcrowd defaults to **P[N]**.
  **I am requesting evaluation at P[M] [standalone | in chain with submission XXXX]** because:

  1. **[Impact axis 1]** — why this exceeds the VRT default's example
  2. **[Impact axis 2]** — cite the programme's own Focus Areas by exact name
  3. **[Impact axis 3]** — compare to the programme's historical handling of the same data class
  ```
  Anchor in the CVSS vector plus business impact. Route *within* the system — cite the platform's own VRT
  entry rather than arguing against the taxonomy.
- **Proof:** P4-default findings assigned at P3 or above with the reasoning recorded in the thread.
- **Escalation:** Where the disagreement is about a single metric, name it explicitly: "I scored S:C =
  7.9; if you read the sandbox crossing as S:U the same vector gives 6.8" keeps the conversation on the
  vector instead of on the number (D27-065 step 6).
- **Ruled out when:** The VRT default already matches your evidence. Asking for an escalation you cannot
  support costs credibility on the next report.

### D27-016 · Rate by acquisition path, not by data class

| | |
|---|---|
| **Severity ceiling** | Support (the ladder itself); the finding it rates reaches Critical |
| **VRT** | the path decides the node: root-only reads land at `insecure_data_storage...on_internal_storage` (P5); an app-reachable read lands at `broken_access_control.exposed_sensitive_android_intent` (null) or the consumer's P1 node |
| **Attacker** | AM-12 at the bottom of the ladder, AM-02/AM-01 at the top |
| **Applies to** | every storage, crypto and client-side finding |
| **Maps to** | Bugcrowd VRT priority semantics; MAS testing profiles (MAS-L1 assumes co-installed apps are adversaries and the OS is intact; MAS-L2 assumes the OS may not be intact and the user may be an adversary; MAS-R assumes the primary user is the adversary) |

- **Test:** "Token stored in plaintext" spans P5 to Critical depending only on how an attacker gets it.
  State which rung you demonstrated, in the title.
- **How:** The ladder, ascending:
  ```text
  1  root / custom ROM / unlocked bootloader          -> Low      (attacker already owns the device)
  2  Frida on a rooted device                         -> Low      (the method is not the finding)
  3  adb backup / bmgr local transport        (D03)   -> High     (no root; brief physical or ADB access)
  4  run-as on a debuggable release build     (D02)   -> High     (no root)
  5  another installed app (D04–D08)                  -> High/Critical  (no physical access)
  6  a network position                       (D14)   -> High/Critical
  7  a clicked link (D09) or a push            (D24)  -> Critical (no attacker app, no physical access)
  ```
  If your only path is (1) or (2), spend the remaining time finding a (3)–(7) path before submitting. It
  usually exists.
- **Proof:** The acquisition path is in the title: "Session token recoverable by any installed app via
  unprotected ContentProvider", not "Insecure data storage".
- **Escalation:** Moving one rung is worth more than any amount of impact prose. Google prices the same
  concept in columns (D27-024); Meta multiplies by clicks (0-click 1x, 1-click 0.75x, 2+ click 0.5x).
- **Ruled out when:** You enumerated rungs 3–7 and each is genuinely closed — provider non-exported,
  backup gutted at targetSdk 31+, release build non-debuggable, no network-reachable path, no deep-link
  or push route. Attach the evidence for each closure; that is a ruled-out row, not a downgraded finding.

### D27-017 · AV:L / PR:N / UI:N — the zero-permission local app vector

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this is the vector convention behind every mobile rating |
| **Attacker** | AM-03 |
| **Applies to** | every CVSS v3.1 vector on an Android finding |
| **Maps to** | FIRST CVSS v3.1 specification; Bugcrowd VRT baseline vectors — `insecure_data_storage|...|on_external_storage` is `AV:P/AC:H/…`, `mobile_security_misconfiguration|auto_backup_allowed_by_default` is `AV:P/AC:L/PR:H/…`, `mobile_security_misconfiguration|clipboard_enabled` is `AV:L/AC:H/PR:N/UI:R/S:C/C:L/…`; HackerOne Platform Standards |

- **Test:** Three metrics do most of the work on mobile. Get them right and the band follows; get them
  wrong and the whole vector is rewritten by triage, usually downwards.
- **How:**
  ```text
  AV  AV:N only if the trigger is reachable from the network or a web page — a deep link the browser
      hands over, a push, a WebView load, an API call. A malicious-app PoC is AV:L. A device-in-hand PoC
      is AV:P. Do not claim AV:N because the data ends up on a server.
  AC  AC:L requires a reliable, repeatable path. Unpredictable identifiers make AC:H by platform standard.
  PR  PR:N when self-sign-up is possible and nothing more is needed, AND when your PoC app declares zero
      permissions. A zero-permission installed app is PR:N, not PR:L — installing an app is not a
      privilege, it is the attacker model.
  UI  UI:N when the victim does nothing after the normal use of their own app. UI:R for a tap on a link.
      "The victim must log in again for the receiver to fire" is a recurring event, not UI — say so in
      prose (D27-023) rather than burying it in the vector.
  ```
  Bands are identical in v3.1 and v4.0: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0.
- **Proof:** The vector string in the report with **one sentence per metric** justifying the value, each
  sentence pointing at an evidence artefact.
- **Escalation:** -> D27-018 for Scope, -> D27-019 for v4.0. Where the same finding is also reachable by
  link, produce a second vector for that path and lead with it (D27-024).
- **Ruled out when:** The programme scores by its own ladder rather than CVSS (Samsung, Xiaomi, AOSP) —
  then use theirs (D27-027) and keep the CVSS vector as an appendix.

### D27-018 · S:C only where you demonstrated the sandbox crossing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | every v3.1 vector claiming Scope: Changed |
| **Maps to** | FIRST CVSS v3.1 Scope definition; AOSP "Application Sandbox" (UID/SELinux as the security authority); Bugcrowd's own `clipboard_enabled` baseline, which uses `S:C` for a cross-app read |

- **Test:** `S:C` means the impact crossed a **security authority**. On Android that authority is the UID
  sandbox: an app-sandbox escape, a URI grant handed to another UID, a token belonging to one package
  read by another, a compromise of the device rather than the app. It is not "the data ended up
  somewhere else in the same app".
- **How:** Before setting `S:C`, produce the two-UID evidence:
  ```bash
  adb shell dumpsys package com.target.app  | grep -E 'userId=|pkgFlags'
  adb shell dumpsys package com.attacker    | grep -E 'userId=|pkgFlags'
  adb shell run-as com.attacker cat files/stolen.txt      # the bytes, inside the attacker's own sandbox
  adb shell dumpsys activity providers | grep -A3 'Granted Uri Permissions'
  ```
  Then write the sentence: "the vulnerable component is `com.target.app` (uid u0_a231); the impacted
  component is `com.attacker` (uid u0_a244), which received the bytes. Scope: Changed."
- **Proof:** The stolen artefact readable **inside the attacker package's own data directory**, not in
  `/sdcard` and not in a shell redirect. `dumpsys activity providers` showing the transient grant is the
  stronger form.
- **Escalation:** A crossing proven here is what lifts the same finding from the P5 storage node to the
  P1 consumer node (D27-012).
- **Ruled out when:** The bytes never leave the target's own UID — a confused-deputy **read** where the
  attacker never receives the data is real but bounded. Set `S:U`, say so explicitly, and then go looking
  for the gadget that does return the bytes (`setResult`, a `FLAG_GRANT_*` self-grant, a webhook) or
  state plainly that it does not exist in this build.

### D27-019 · CVSS v4.0 on mobile — SC/SI/SA carry the cross-app impact; base is yours, environmental is theirs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | programmes and clients scoring on v4.0 |
| **Maps to** | FIRST CVSS v4.0 specification — four metric groups; Base AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA; Threat E; Environmental CR, IR, AR and MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA; Supplemental S, AU, R, V, RE, U ("supplemental metrics will not modify the final score"); NIST SP 800-115 §8.3 |

- **Test:** v4.0 splits impact into the **vulnerable** system (VC/VI/VA) and the **subsequent** system
  (SC/SI/SA). For a mobile sandbox crossing, the cross-app impact belongs in SC/SI/SA — say so explicitly
  in the justification, because that is where v3.1's `S:C` went.
- **How:** Run the five steps and publish both scores:
  ```text
  1 Base            from the DEMONSTRATED attack only: AV/AC/AT/PR/UI + VC/VI/VA + SC/SI/SA
  2 Threat (E)      set from what YOU shipped — a working PoC in the evidence bundle is a fact about
                    exploit maturity; state it rather than implying it
  3 Environmental   hand the client CR/IR/AR plus the Modified Base metrics and let THEM set them against
                    their data classification. Record both: "Base 7.3 / Environmental (client-set) 8.4"
  4 Supplemental    S (Safety), AU (Automatable), R (Recovery), V (Value Density), RE, U — these do not
                    change the score; use them to carry context a number cannot (AU for a fully scriptable
                    account enumeration; S for a health, automotive or industrial app)
  5 Sanity check    does the vector imply more than you proved? Fix the vector, not the prose.
  ```
  Two further rules: do **not** inflate Availability for data deletion — HackerOne's Core Clarifications
  state "the ability to delete the data in an application does not impact the Availability metric in a
  CVSS score"; raise Integrity and set `A:N`/`VA:N`. Where the client's programme still runs CVSS 3.1,
  publish **both** vectors rather than converting; they are not interchangeable.
- **Proof:** Every finding carries a full vector string plus a one-line justification tying each metric to
  a named evidence artefact.
- **Escalation:** Step 3 defuses the commonest commercial severity dispute by giving the client the
  legitimate lever (D27-065). Do not export the environmental step into a bounty report — there the
  programme's own vocabulary wins.
- **Ruled out when:** The programme mandates a single calculator (D27-020); then produce that one and put
  the other in an appendix.

### D27-020 · Know which calculator the programme actually runs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | HackerOne, Intigriti, Bugcrowd |
| **Maps to** | HackerOne's CVSS 3.0 is a **custom** implementation that "factors in BOTH the environmental score and the base score" with environmental modifiers ×0.0 / ×0.5 / ×1.0 / ×1.5; Bugcrowd VRT `mappings/cvss_v3/cvss_v3.json` whose `metadata.default` is `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` (score 0.0 — which is why the whole `lack_of_binary_hardening` branch scores zero); Intigriti uses CVSS v3.1 and v4.0 |

- **Test:** The same vector produces different numbers on different platforms. Check which calculator the
  programme enabled before arguing a number, or the argument is about the wrong arithmetic.
- **How:** Read the programme's brief for the enabled calculator (CVSS 3.0 HackerOne / 3.1 / 4.0 /
  manual). On Intigriti, additionally determine the **scoring mode**:
  ```text
  PoC assessment (default)     CVSS calculated "based on the impact demonstrated", scoring "with the
                               greatest potential impact in mind" -> demonstrate the DEEPEST link of the chain
  Vulnerability-type assessment impact scored "based on their initial and immediate effect on the
                               vulnerable system, and additional exploitation steps or probabilities are
                               not considered" -> a long chain is scored at its FIRST link; file the
                               highest-value link as its own report
  ```
  Two further Intigriti rules that bite mobile testers: **unused code** is "Marked 'severity none' by
  default unless evidence shows backend use or future integration" — a dead-code secret or unreachable
  exported component needs evidence of live use; and **third-party vulnerabilities** must be reported to
  the vendor first, which matters when the bug is in `react-native-webview`, `unity-webview`, OkHttp or
  Play Core rather than the client's own code.
- **Proof:** A severity that matches your chain depth rather than being cut at the first step.
- **Escalation:** Under vulnerability-type assessment, the correct strategy is D27-067's split filing, not
  a single chain report.
- **Ruled out when:** The programme scores by its own published ladder (D27-027) rather than CVSS at all.

### D27-021 · The two-verified-links rule

| | |
|---|---|
| **Severity ceiling** | Support (the rule); the chain it governs reaches Critical |
| **VRT** | the chain's end node, not the entry node |
| **Attacker** | AM-03 typically at the entry, AM-05 or AM-01 at the end |
| **Applies to** | every multi-step finding |
| **Maps to** | HackerOne Platform Standards bug-chain rule ("These reports should be evaluated by their overall impact and paid accordingly"); Bugcrowd VRT README ("application complexity, bounty brief restrictions or unusual impact could result in a different rating") |

- **Test:** **Two verified links plus one unproven link is a Medium with a stated precondition, not a
  Critical.** Rate on the crown jewel only when every hop to it is demonstrated; otherwise keep the base
  severity and state the ceiling separately.
- **How:** Write the chain explicitly before assigning severity, and mark each link:
  ```text
  entry point -> primitive -> amplifier -> crown jewel
  exported receiver [VERIFIED] -> arbitrary file create [VERIFIED] -> shared_prefs .bak overwrite [VERIFIED]
    -> System.load() as the app [UNPROVEN — no loader reads a path this primitive can write]

  Rating sentence: "Medium (arbitrary file write within the app's data directory). Impact ceiling =
  code execution as the app IF a loader reads from a writable path; hooked System.load, dlopen,
  DexClassLoader and PathClassLoader for the session and observed none — see evidence/F-014/loaders.log."
  ```
  Where the fork genuinely cannot be resolved from outside, state both branches, say static evidence
  cannot distinguish them, say you did not test which is true, and ask the vendor the question they can
  answer from their own logs. That fork is stronger than a guess because it cannot be dismissed as
  unauthorised probing.
- **Proof:** The severity argument traces to specific demonstrated steps, and the unproven link has its
  own negative evidence attached.
- **Escalation:** Chains are rated on the end state — a finding spanning three ATT&CK tactics is a chain
  by construction (D27-028). A known or out-of-scope component used inside the chain should still lift the
  rating.
- **Ruled out when:** Every link is verified — then rate the crown jewel and say so plainly. Optimise for
  accuracy, never for bounty size; a severity that later drops is remembered as the number.

### D27-022 · The pre-severity gate — five questions against the Critical claim, not against the bug

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this gate governs every P1/P2 claim you make |
| **Attacker** | n/a |
| **Applies to** | every Critical or High claim |
| **Maps to** | the bug-hunting corpus's PRE-SEVERITY GATE and its worked failure: a JWT `alg:none` finding labelled Critical on a confirmed signature-bypass primitive at the audience-validation layer — the issuer-trust check still rejected unsigned tokens, the ATO chain never completed, and the finding had to be retracted |

- **Test:** Write the draft Critical title, then substitute **the Critical claim** for "the bug" in each
  of the five questions. Running the gate against the bug rather than the claim is what lets a confirmed
  mid-chain primitive masquerade as a completed attack.
- **How:**
  ```text
  1 Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle?
    "Primitive confirmed at layer N" is not "exploitable".
  2 What does the attacker walk away with, in one concrete sentence? "Session token for any logged-in
    user, replayed from curl" is concrete. "Could lead to account takeover" is High at best, often Medium.
  3 Have I personally reproduced the full chain end to end AT LEAST TWICE — once during discovery, once
    for the PoC? "I'm sure it would work" is not a reproduction.
  4 Is there an inheritance gate, signature check, audience check, permission check or other validation
    still gating the chain? If yes it is not Critical — document it as "primitive present" at lower severity.
  5 Has the programme rejected this severity class before? (Check the brief, the disclosed reports and
    the published threat model.)
  ```
  Precede it with the seven-question finding gate where the finding is still a candidate: can an attacker
  use this right now step by step (if you cannot write the request, kill it); is the impact on the
  programme's accepted list; is the root cause in an in-scope asset; does it require privileged access an
  attacker cannot realistically get; is it already known or intended; can you prove impact beyond
  "technically possible" (failing this **downgrades**, it does not kill); is it on the never-submit list.
- **Proof:** A recorded pass/kill decision per finding, with the answer to Q4 naming the gate you checked
  and the command that showed it absent.
- **Escalation:** Kill-fast rules keep it cheap: five minutes to write the attacker's request or move on;
  more than two simultaneous preconditions is a kill; thirty minutes on "prove impact" with no
  reproducible PoC is a kill.
- **Ruled out when:** All five answers are clean and recorded. Then the Critical claim is the one you
  file, and the gate output is the defence when it is challenged.

### D27-023 · Audit the draft against the eleven downgrade triggers, and use the counter-wording

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-01 … AM-12 |
| **Applies to** | every submission |
| **Maps to** | Google Mobile VRP "Report Quality" and the four attack-scenario columns; Android & Google Devices "Evaluation Criteria for Maximum Payouts"; Samsung "Severity rating can be lowered by the following downgrade factors"; Meta mobile-RCE click multipliers; HackerOne Core Ineligible Findings |

- **Test:** Eleven triggers account for almost every unexplained downgrade. Audit the draft against each
  and rewrite the impact sentence rather than arguing afterwards.
- **How:**
  ```text
  1  User interaction        -> "No user interaction is required beyond the victim opening the app" / the
                                link is delivered by <realistic vector>. If a malicious app is needed,
                                state its permission set: "the PoC app declares no permissions."
  2  Rooted / dev mode       -> "Reproduced on a stock, unrooted <model> running <version>, build <id>,
                                Play release build, USB debugging disabled."
  3  Non-current version     -> "Reproduced on versionName <x> (versionCode <y>), the current Play release
                                as of <date>, security patch <yyyy-mm-dd>."
  4  Artificial reachability -> "Input is delivered through the app's own exported activity / a received
                                message / a deep link; no internal API is invoked directly at any point."
  5  Impact asserted         -> replace every "could lead to" with the demonstrated outcome plus artefact.
  6  Excessive preconditions -> state the count explicitly and argue each is realistic, or cut a step.
  7  Limited scope           -> "Reproduced on <n> models across <regions>; the vulnerable code is in
                                <shared component>, so all builds since <version> are affected."
  8  Mitigation present      -> name the mitigation and show it defeated, or say why it does not apply.
  9  Crash without exploit   -> "The crash is a controlled <write/read> of <n> bytes at <offset>;
                                <register> is attacker-controlled, per the attached tombstone."
  10 Missing patch           -> attach the diff (mandatory for memory safety on Android & Google Devices).
  11 Self-inflicted impact   -> "Account A (attacker) obtains data belonging to Account B (victim); both
                                are separate registrations under my control, shown by distinct emails/IDs."
  ```
  Then the honest-precondition move that the highest-paying disclosed reports all share: state the
  precondition and **neutralise it in the same paragraph**. H1 #1372667 (High 8.7, **$6,337**): "Prior to
  exploitation you would be required to know the account id… Whilst this makes it difficult to attack an
  application in a generic way — **the account is not secret information as it is included in any links
  to a user's basecamp organisation.**" H1 #855618 adds a **"### Bonus"** section showing the malicious
  app can trigger the login email itself rather than waiting. H1 #205000 (High 7.5) concedes "the victim
  will be informed that something is wrong because of few incoming SMSes with codes" and "the process may
  take many hours" — and was still paid High.
- **Proof:** A preconditions block where every item has a neutralising sentence next to it, and an impact
  paragraph with no conditional verbs (D27-006).
- **Escalation:** Reducing the precondition is the highest-leverage move available — moving a finding
  from "requires a malicious app installed" to "requires only clicking a link" is routinely a 5–10x
  difference on the same bug (D27-024).
- **Ruled out when:** The precondition genuinely cannot be neutralised (a specific OEM ROM, a physically
  unlocked device). Say so, price the finding accordingly, and check whether the programme excludes it
  outright before spending more time.

### D27-024 · Choose the attack-scenario column deliberately

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-01 (column 1) → AM-02 (column 2) → AM-03/AM-04 (column 3) → AM-06 (column 4) |
| **Applies to** | Google Mobile VRP directly; the logic applies wherever user interaction is priced (Meta's click multipliers, Samsung's User Interaction criterion, Xiaomi's Remote/Local split) |
| **Maps to** | Google Mobile VRP's four attack-scenario columns: Remote/No User Interaction · User must follow a link · User must install a malicious app or the app is configured non-default · Attacker on the same network. **The reward figures in the corpus disagree between sources — do not quote a figure to a triager; re-read the live rules page before scoping** |

- **Test:** For each finding identify the **cheapest realistic delivery** and build the PoC for that one,
  not for the one that was easiest to develop.
- **How:** Rank your delivery options against the four columns, then ask two questions:
  ```text
  Can the malicious-app PoC be replaced by a web page?   (BROWSABLE intent-filter? unverified App Link?
                                                          an Instant App route? -> D09, D22)
  Can the link be replaced by a push or by a message the app already renders?  (-> D24)
  ```
  Then rebuild the PoC on the higher-value vector and re-record the video from that entry point.
  ```bash
  adb shell dumpsys package com.target.app | sed -n '/android.intent.category.BROWSABLE/,+6p'
  adb shell pm get-app-links com.target.app
  adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "<payload>"
  ```
- **Proof:** The PoC delivered by the higher-value vector, recorded from the browser or the push
  notification rather than from `adb`.
- **Escalation:** Where a vendor's published threat model discounts same-device attackers (Nextcloud's
  calls attacks involving other Android apps "minimal risk", which is why H1 #242727 rated **Low, $75**
  and #291764 **Low 0.9, $150**), the browser-triggerable variant removes the discount entirely.
- **Ruled out when:** The component is genuinely not browser-reachable — no BROWSABLE filter, no verified
  App Link, no push handler that renders attacker content. Attach `pm get-app-links` and the manifest
  section, and file at the column you can actually demonstrate.

### D27-025 · Classify the exfiltrated data in the programme's own words

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) vs `.for_internal_asset` (P3) vs `.pay_per_use_abuse` (P4) vs `.intentionally_public_sample_or_invalid` (P5) |
| **Attacker** | AM-03 |
| **Applies to** | every data-theft finding |
| **Maps to** | Google Mobile VRP "Theft of sensitive data" definitions, quoted verbatim; the rules also note rewards are calculated with the **HIGHEST** impact where several apply |

- **Test:** State explicitly whether the data you obtained is High Impact or Low Impact, quoting the
  programme's own definition rather than asserting sensitivity.
- **How:**
  ```text
  High Impact Data  "Data that enables unauthorized access to a user's account (e.g. login credentials,
                     or authentication tokens that are able to perform sensitive state-changing actions
                     that result in non-trivial damage to the victim, government IDs, medical or payment
                     information)"
  Low  Impact Data  "contact list information, photos (unless made public by default), content of a
                     user's messages (email, instant messages, text messages), call/SMS logs, web
                     history …, or browser bookmarks", plus "information that is linked or linkable to
                     an individual, such as educational, and employment information"
  ```
  A token that only **reads** is Low Impact; the same token performing a **state-changing** action is
  High Impact. Always try the state-changing call on your own account.
- **Proof:** The quoted definition plus your evidence that the data meets it — for a token, the
  authenticated state-changing request and its response.
- **Escalation:** For a hardcoded secret, the evidence bar is the extraction location **plus** a liveness
  proof (one authenticated response) — then stop. An app-scoped public identifier (a Firebase `apiKey`,
  an unrestricted-looking Maps key) is not automatically a finding; check the restriction and show it
  absent (-> D18).
- **Ruled out when:** The value is a public client identifier by design. `sensitive_data_hardcoded.
  oauth_secret` is **P5** — a public OAuth client is expected to be unable to keep a secret. The
  reportable finding there is PKCE non-enforcement or a redirect-URI weakness (-> D13), not the secret.

### D27-026 · State the MAS profile; MAS-R gaps are hardening, not vulnerabilities

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | the whole `lack_of_binary_hardening` branch is P5 with an all-zero CVSS baseline |
| **Attacker** | AM-12 (the user as adversary) for MAS-R |
| **Applies to** | every engagement sold as standards-aligned |
| **Maps to** | MASVS v2.0.0 (verification levels removed; MAS Testing Profiles in the MASTG, aligned with NIST OSCAL); MASTG test front-matter `profiles:` field with values `L1`, `L2`, `R`, `P`; `mas.owasp.org/checklists/` now redirects to the removal notice "MASTG v2.0.0 Removes MAS Checklists" (2026/07/14) |

- **Test:** Declare the profiles in scope, using the MASVS threat assumptions verbatim, and filter the
  findings table by them. This is the rule that decides whether "root detection bypassable" is a finding
  or noise.
- **How:**
  ```text
  MAS-L1  Baseline. OS controls trusted; the primary user is not an adversary; other installed apps ARE.
  MAS-L2  Defence-in-depth. OS controls may NOT be intact; the app user MAY be an adversary.
  MAS-R   Resilience. The primary user IS the adversary (reverse engineer, cheater, modder). Augments
          L1/L2, never standalone. MASVS: "MAS-R controls can ultimately be bypassed and should never be
          used as a replacement for proper security controls."
  MAS-P   Privacy / PII baseline.
  Valid combinations: L1 · L1+R · L2 · L2+R.  MASVS: "When testing using a MAS profile you don't have to
  apply each and every test."
  ```
  ```bash
  git clone --depth 1 https://github.com/OWASP/mastg.git
  grep -l 'profiles: \[R\]' mastg/tests-beta/android/*/*.md    # the MAS-R-only tests
  grep -l 'profiles: \[P\]' mastg/tests-beta/android/*/*.md    # the privacy-profile tests
  ```
- **Proof:** A findings table where every row carries its profile, so the client can see that the "no
  obfuscation / no root detection / no emulator detection" rows are recommendations and the rest are
  defects. Quote MASVS directly when asked why: "the absence of any MAS-R measures does not inherently
  introduce vulnerabilities" and MAS-R "is meant to augment and not replace MAS-L1 and MAS-L2."
- **Escalation:** An R failure becomes a finding only when chained into an L1/L2 impact — the corpus's
  own line: report the internal logic flow that changed, the feature unlocked after repackaging, or the
  server trusting the client's integrity verdict (-> D21, -> D23).
- **Ruled out when:** The engagement is L1-only and the observation is an R-profile item. Record it as a
  hardening recommendation in the appendix, clearly separated from findings so the client can tell the
  difference. **Do not promise "coverage against the OWASP MAS Checklist" — as of MASTG v2.0.0 the
  spreadsheet is no longer an official release artefact.** Build your own coverage table from the repo
  front-matter instead and state the count you actually ran.

### D27-027 · Route the severity into the vendor's own vocabulary

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | varies |
| **Applies to** | Samsung, Xiaomi, Google-owned apps, AOSP; the technique generalises |
| **Maps to** | Samsung Mobile Security Risk Classification ("Last updated: September 8, 2026") and its explicit appeal clause; Xiaomi's Remote/Local and privileged/ordinary/restricted process definitions; AOSP severity table and modifiers at `source.android.com/docs/security/overview/updates-resources` |

- **Test:** Use the target vendor's own severity words so the triager can map your report directly onto
  their table. Severity appeals succeed far more often when you quote the vendor's own row than when you
  argue CVSS.
- **How:** Samsung's ladder, condensed:
  ```text
  Critical  ACE in TEE/SE; remote ACE in a privileged process, bootloader or TCB; unauthorised access to
            SE-secured data; secure-boot bypass; remote bypass of user-interaction requirements for
            package installation or security/privacy settings; remote permanent DoS
  High      remote ACE in an unprivileged process; local ACE in a privileged process; remote access to
            protected data including auth credentials; bypass of OS protections across application/user/
            profile boundaries; bypass of SELinux/FBE/seccomp; lockscreen bypass; FRP bypass; local
            permanent DoS
  Moderate  remote ACE in a constrained process; local ACE in an unprivileged process; remote access to
            locally-installed-app-accessible data; local access to privileged-process data incl.
            credentials; remote temporary DoS via hang/reboot
  Low       local ACE in a constrained process; local access to app-accessible data; bypass of a
            normal-protection-level permission
  ```
  AOSP adds: **NSI** for mitigated issues and reboot-resolvable local DoS, and caps a PoC needing an
  unlocked bootloader or Developer Mode at "no higher than Low". Samsung permits appeal explicitly: "if
  the reporter has a different opinion, reporter can claim to change the severity rating by providing
  clear evidence of the security impact."
- **Proof:** Your severity claim phrased in the vendor's own terms with the matching table row cited.
- **Escalation:** Credit expectations follow the same tables — Samsung: "SVE/CVE ID's will be assigned and
  credited for Moderate and above security issues only"; low-severity issues are deferred to the next OS
  update or device generation.
- **Ruled out when:** The programme publishes no ladder — then CVSS plus the VRT node is the vocabulary,
  and D27-017 governs.

### D27-028 · The escalation matrix — interrogate every finding before you rate it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — the matrix's output is which node D27-012 aims at |
| **Attacker** | AM-03 at entry |
| **Applies to** | every finding set, run once the candidate list is complete |
| **Maps to** | ATT&CK Mobile tactics TA0027 Initial Access, TA0041 Execution, TA0028 Persistence, TA0029 Privilege Escalation, TA0030 Defense Evasion, TA0031 Credential Access, TA0032 Discovery, TA0033 Lateral Movement, TA0035 Collection, TA0037 Command and Control, TA0036 Exfiltration, TA0034 Impact (verified on attack.mitre.org/tactics/mobile/) |

- **Test:** VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD → REPORT. Ask the same questions of every
  finding before rating any of them, because the answers change each other's severity.
- **How:** Build the table and walk the chain-discovery graph:
  ```text
  | Finding | Sev | Conf | Root cause | Current impact | Missing evidence | Escalation path |

  Questions: current impact? attacker capability? boundary crossed? what prevents exploitation? can that
  protection be INFLUENCED? can another feature remove the prerequisite? can two findings chain? can the
  same primitive hit another account or resource? does it affect authN / authZ / confidentiality /
  integrity / money? can it cross client->server, web->native, untrusted-app->privileged, or become remote?

  Graph to walk: WebView+DeepLink+Bridge · TokenLeak+APIAuthz · FileDisclosure+Credential ·
  ExportedComponent+PrivilegedFn · BusinessLogic+Race · ClientValue+ServerTrust · OTP+Bridge ·
  Prefetch+AttackerURL.   Mark each link VERIFIED or UNPROVEN.
  ```
  Where the programme uses ATT&CK, add the per-finding narrative line: "Exported receiver accepts a
  base-URL command → T1624.001 (TA0028 Persistence) → T1638 (TA0035 Collection) → T1646 (TA0036
  Exfiltration)." Cite technique IDs exactly as they appear on attack.mitre.org; never invent a
  sub-technique number.
- **Proof:** The completed matrix, with every `UNPROVEN` link carrying the negative test that was run.
- **Escalation:** A finding spanning three tactics is a chain by construction, and chains are rated on
  the end state, not the entry (D27-021). **Only raise severity if the resulting impact is demonstrated.**
- **Ruled out when:** Every question is answered and the answer is "no further reach" — then the matrix
  row is the justification for the rating you assigned, and it belongs in the report.

### D27-029 · The evidence tree — one directory per finding id

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | corpus evidence-tree layout; NIST SP 800-115 Appendix B §5.3 (Data Handling — gathering, storing, transmitting and destroying test data) |

- **Test:** Every finding gets a directory; every dynamically demonstrable finding gets a verified `.mp4`.
  Code-verified-but-not-device-reproducible findings get code evidence **plus an honest limitation** —
  never a reconstructed video.
- **How:**
  ```text
  <engagement>/
    INDEX.md
    ARTEFACT-MANIFEST.txt          # sha256 of every APK/split analysed  (-> D02)
    LAB-MANIFEST.txt               # the harness that reproduces it      (-> D26)
    findings/F-0NN/finding.md      # the template (D27-005)
    findings/F-0NN/code/           # the decompiled snippets, at file:line
    recordings/F-0NN/F-0NN_POC.mp4
    screenshots/F-0NN/01-… 02-… 03-…   # named in beat order (D27-037)
    requests/F-0NN/  responses/F-0NN/  # the captured HTTP pairs
    logs/F-0NN/logcat.txt              # bounded to the target pid
    pocs/F-0NN/repro.sh                # runs clean on a lab rebuilt from LAB-MANIFEST.txt
    pocs/F-0NN/attacker-app/           # source + signed debug APK
    ruled-out.md                       # the register (D27-048)
    retest/F-0NN/                      # baseline-on-old-build + run-on-new-build (D27-071)
  ```
- **Proof:** The tree, populated, with `INDEX.md` mapping every finding id to its artefacts and every
  artefact referenced by path from the report body.
- **Escalation:** The tree is the input to the hash manifest (D27-046), the leak grep (D27-038) and the
  remediation tracker. Emit the tracker mechanically so the client can import it:
  ```bash
  printf 'id,title,severity,cvss,cwe,component,evidence,repro,owner,status\n' > final/remediation-tracker.csv
  for f in findings/F-*/finding.md; do id=$(basename "$(dirname "$f")"); printf '%s,"%s",%s,%s,%s,"%s",%s,%s,%s,OPEN\n' \
    "$id" "$(grep -m1 '^# ' "$f" | sed 's/^# //')" "$(grep -m1 -i '^severity:' "$f" | cut -d: -f2- | xargs)" \
    "$(grep -m1 -o 'CVSS:[34]\.[01][^ ]*' "$f")" "$(grep -m1 -o 'CWE-[0-9]\+' "$f")" \
    "$(grep -m1 -i '^component:' "$f" | cut -d: -f2- | xargs)" "evidence/$id" "pocs/$id/repro.sh" \
    "$(grep -m1 -i '^owner:' "$f" | cut -d: -f2- | xargs)" >> final/remediation-tracker.csv; done
  ```
- **Ruled out when:** Never — a single-finding bounty submission still needs the directory, because the
  triage ladder (D27-064) consumes it one rung at a time.

### D27-030 · The PoC video seven-beat standard

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but the negative-control beat is what converts a demo into evidence |
| **Attacker** | AM-03 |
| **Applies to** | every dynamically demonstrable finding |
| **Maps to** | MHL's own shipped PoC assets (`read-contacts-poc.mp4` 489,883 B; `dng-crash.mp4` 638,354 B; `crash-apv.mp4` 13,097,642 B; `Steal-images.mp4` 2,465,779 B) — all muted, looping, `controls` present, embedded above the analysis; corpus four-beat differential PoC; MASTG-TOOL-0024 (Scrcpy) |

- **Test:** Seven beats, in this order, in one continuous take per beat. Beats 4 and 5 are the two most
  omitted and the two that make the recording evidence rather than a demonstration.
- **How:**
  ```text
  1 IDENTITY      device build, patch level and app version on camera — not claimed in the description
                  adb shell getprop ro.build.fingerprint ; adb shell getprop ro.build.version.security_patch
                  adb shell dumpsys package $PKG | grep -E 'versionName|versionCode'
  2 CLEAN STATE   the victim data exists and belongs to the victim; the attacker app is NOT installed
                  adb shell pm list packages | grep poc            # empty, on camera
                  adb shell ls -la /data/data/$PKG/shared_prefs/   # name the owning UID out loud
  3 ZERO PERMS    install on camera and show the permission surface — this is the claim carrying severity
                  adb install -r poc.apk
                  adb shell dumpsys package com.poc.app | sed -n '/requested permissions/,/install permissions/p'
                  and the system's own App info → Permissions screen, which reads faster than dumpsys
  4 BASELINE DENIAL  the legitimate path is closed on an ordinary device: the same read from the shell UID
                  returns Permission denied, and `run-as $PKG id` returns "package not debuggable".
                  Two independent proofs there is no legitimate way in.
  5 NEGATIVE CONTROL  fire the primitive at a non-existent path in the same directory, or with the control
                  enabled. The component must visibly fail. THIS is what a blocked read looks like.
                  adb shell am compat enable <CHANGE_ID> com.poc.app     # or install the patched build
  6 THE BUG       same command, real target, victim doing only what a real victim would do. Show the
                  result on screen, counted, with the canary visible (D27-031).
  7 DOWNSTREAM    the bytes arriving somewhere the attacker controls, or the authenticated request the
                  stolen token performs, or the change visible in the victim's own session.
  ```
  If the finding is a crash, beat 6 is the crash and beat 7 is the tombstone on screen
  (`adb logcat -b crash -d | tail -40`), with beat 5 the same input on the patched build producing none.
  Use `topResumedActivity` rather than `mCurrentFocus` as the oracle for "the component stayed up":
  ```bash
  TOP(){ adb -s "$1" shell dumpsys activity activities | grep -m1 topResumedActivity | sed 's/.*u0 //;s/ .*//'; }
  ```
- **Proof:** A frame extracted from beat 6 that shows the claim, and a frame from beat 5 that shows the
  same action failing. Target 20–45 seconds for a single primitive, up to about two minutes for a chain.
- **Escalation:** Package the video with the stills it is drawn from (`01-…`, `02-…`, `03-…` in beat
  order, with real caption text), a plain-text transcript of the PoC app's console output, the one-shot
  reproduction script and the prebuilt artefact. Add "For research and authorised testing only." next to
  any downloadable attack artefact.
- **Ruled out when:** The finding is code-verified only and cannot be reproduced on-device — then state
  the environment blocker explicitly and substitute source-derived proof (D27-047). **Never reconstruct a
  video; the triager re-runs the PoC.**

### D27-031 · The canary rule

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | every exfiltration, read-primitive or cross-account PoC |
| **Maps to** | Marker Discipline from the bug-hunting corpus (8+ random characters, search the baseline first) combined with the corpus's coherence requirement for recorded demos |

- **Test:** Plant a unique, obviously synthetic value in the victim data **before** recording, so the
  bytes the attacker displays are provably the same bytes as the victim's — not a coincidence, not a
  cached value, and not staged. Without it, "the attacker app printed a token" is an assertion about two
  strings that happen to match.
- **How:**
  ```bash
  CANARY="cpz$(openssl rand -hex 6)"        # 8+ chars, random, no English words, no protocol keywords
  echo "$CANARY"
  # 1. plant it through the app's own UI (a note title, a display name, a saved address)
  # 2. prove it is in the victim's private store, on camera, before the attack
  adb shell run-as com.target.app cat shared_prefs/com.target.app.xml | grep -o "$CANARY"
  # 3. run the attack; the attacker app must print the SAME string
  adb logcat -s evil | grep -o "$CANARY"
  # 4. baseline check: the canary must NOT appear anywhere before the attack
  adb logcat -d | grep -c "$CANARY"          # expect 0 in the pre-attack capture
  ```
  Never use `test`, `marker`, `evil`, `attacker`, `payload`, `AAAA` or your own domain as the canary —
  word collisions in help text, SDK strings and framework resources produce false reflections. Where the
  finding involves multiple sinks, sub-tag each canary per sink so you can tell which one fired.
- **Proof:** The same 8+ character random string visible in the victim's private file and in the
  attacker's own log, with a pre-attack capture in which it does not appear.
- **Escalation:** The canary is what makes D27-036's coherence requirement mechanically checkable — grep
  every shipped frame's OCR or the transcript for the canary and confirm one identity throughout.
- **Ruled out when:** The finding's value is inherently not plantable (a device identifier, a
  server-issued token). Then substitute the token's own first/last six characters plus a hash of the full
  value, shown identically on both sides.

### D27-032 · screenrecord mechanics and the frame-extraction gate

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all on-device capture |
| **Maps to** | `adb shell screenrecord` — **default and maximum time limit is 180 seconds** per invocation, no audio capture; MASTG-TECH-0009 (system log inspection) for the paired logcat |

- **Test:** Capture on-device with no extra installs, then **verify the artefact before shipping it**. A
  recording that does not show the claim is worthless, and you cannot tell without looking at a frame.
- **How:**
  ```bash
  adb logcat -c
  adb exec-out screencap -p > shot.png                                   # instant still
  adb shell screenrecord --time-limit 180 --bit-rate 8000000 --size 720x1560 /sdcard/poc.mp4 &
  #  ... perform the actions with sleeps between them; let splash and interstitials settle ...
  wait; adb pull /sdcard/poc.mp4 poc.mp4; adb shell rm /sdcard/poc.mp4
  adb logcat -d --pid=$(adb shell pidof -s com.target.app) > poc-logcat.txt

  # QUALITY GATE — extract the money-shot frame and READ it
  ffprobe -v error -show_entries format=duration -of csv=p=0 poc.mp4
  ffmpeg -ss 9 -i poc.mp4 -frames:v 1 frame.png
  ```
  Keep the file small: at `--bit-rate 8000000 --size 720x1560` a 30-second single-screen PoC lands under
  a megabyte and loads instantly in a bug-tracker preview; a 60 MB file does not get watched. Take
  explicit `screencap` stills at the key moments rather than relying on video-frame timing. Rehearse — a
  demo where the operator visibly hunts for a button reads as unreliable.
- **Proof:** The extracted frame, opened and read, showing the claim. File naming
  `<finding-id>-<what-it-shows>.mp4`, lowercase and hyphenated.
- **Escalation:** For anything over 90 seconds, put a timestamp chapter list in the finding's `EVIDENCE`
  field. For chains, record each stage separately so a partial fix can be re-verified independently.
- **Ruled out when:** The demo genuinely needs more than 180 seconds — then record consecutive segments
  and concatenate, and say in the report that the cut falls **between** beats, never inside one. Do not
  discover the 180-second cap mid-demo.

### D27-033 · Composite sync and identity coherence

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any side-by-side terminal + device rendering; every recorded demo |
| **Maps to** | corpus PoC-video conventions (side-by-side, time-synchronised, 1920×1080, per-scene labelling); corpus coherence rule |

- **Test:** Two failure modes sink composited evidence: a sync offset derived from the wrong transition,
  and identities that do not match across frames. Both are invisible in the logs and obvious in one frame.
- **How:**
  ```bash
  ffmpeg -i terminal.mp4 -itsoffset "$OFF" -i device.mp4 \
         -filter_complex "[0:v][1:v]hstack=inputs=2" -c:v libx264 -crf 20 composite.mp4
  ```
  Sync rules: detect a modal by its **scrim** — sample a mid-screen band and look for *dimming* — not by
  overall brightness, because app home screens are frequently white in the same region a bottom sheet
  occupies. Derive the offset from **two independent transitions** and require them to agree. Then
  extract frames at the moments the terminal claims a result and read them.
  Labelling rules: label the attacker side in a per-scene header — `ATTACKER APP — com.poc.<name> (ZERO
  permissions)` / `VICTIM'S PHONE`. The header must be **per-finding and accurate**; a leftover "attacker
  app" header on a finding with no attacker app is a defect that costs the whole report credibility.
  Coherence rule: **every value shown must match.** If the OTP screen says one number while the
  exfiltrated file holds a different account, the recording looks staged. Use one identity — the canary
  (D27-031), the account email, the profile name and the stolen record must all be the same person.
- **Proof:** Two independent transitions yielding the same offset, and frames whose on-screen identities
  agree with the terminal output and with each other.
- **Escalation:** Where a stand-in identity is used, make the on-screen number, the profile and the
  stolen record the same identity, and say in the report that it is a tester-owned stand-in.
- **Ruled out when:** The take is single-source (device only) with the commands typed into an on-device
  terminal — then there is no offset to derive, and only the coherence half applies.

### D27-034 · Root-for-evidence, with the roles labelled on screen

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — without the label the finding is closed as "requires root" |
| **Attacker** | AM-03 for the attack; AM-12 for the display device only |
| **Applies to** | sandbox-violation findings where the bug yields no bytes to the attacker |
| **Maps to** | corpus root-for-evidence convention; the HackerOne, Bugcrowd, Xiaomi, Grab, Spotify and Google exclusions for root-only findings |

- **Test:** When the primitive proves a read happened but returns nothing to the attacker, the *contents*
  claim is unproven. Resolve it with a second, rooted device used **only as a display**, and say so on
  screen — or the exclusion list closes the report.
- **How:**
  ```bash
  adb shell pm path com.target.app && adb pull <each split> ./apk/
  adb -s <rooted>    install-multiple -r -t apk/base.apk apk/split_config.*.apk
  adb -s <rooted>    root && adb -s <rooted> shell id           # must print uid=0(root)
  adb -s <nonrooted> shell cat /data/data/com.target.app/shared_prefs/com.target.app.xml   # Permission denied
  adb -s <rooted>    shell cat /data/data/com.target.app/shared_prefs/com.target.app.xml   # the contents
  ```
  Rules: the rooted device is display-only; the exploit itself runs with zero permissions and no root on
  the same take; both devices use the **same account and the same APK build**; and the on-screen caption
  says *"root is NOT part of the attack — section N uses none"*. State any API-level difference between
  the two devices in the report rather than letting it look as though the device quietly changed.
- **Proof:** One take, both devices, labelled by serial: non-rooted → `Permission denied`; rooted, same
  account, same APK → the file's contents.
- **Escalation:** Once the contents are established, go back and look for the gadget that returns the
  bytes to the attacker (`setResult`, a `FLAG_GRANT_*` self-grant via an intent-redirection receiver, a
  webhook) — that removes the need for the second device entirely and moves the finding up a rung
  (D27-016).
- **Ruled out when:** The attacker already receives the bytes. Then the second device adds nothing, and
  introducing root into the video only invites the exclusion.

### D27-035 · Redact in the rendering, never in the targeting

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | every PoC against the operator's own data |
| **Maps to** | corpus evidence-grade lessons; the verbatim triage response received when a PoC was pointed at a harmless file: *"if you are able to read shared preferences with sensitive information … else the impact here is none"* |

- **Test:** Pointing the primitive at a boring cache file to keep credentials out of the report reads to a
  triager as "he only proved it on something worthless". Point it at the crown jewel and redact the
  **rendering**.
- **How:** Aim at `shared_prefs/<pkg>.xml`, the MMKV store, the token database — whatever the app actually
  keeps the session in — and redact in the video or screenshot, and only when redaction costs nothing. If
  redaction weakens the proof, show the value and **rotate it immediately after filing** (log out, change
  the password, revoke the session).
  ```bash
  adb shell run-as com.target.app ls -la shared_prefs/ databases/ files/
  adb shell run-as com.target.app cat shared_prefs/com.target.app.xml | grep -iE 'token|auth|session|refresh'
  ```
- **Proof:** The sensitive file on screen with the rendering redacted, plus a note that the value was
  rotated after submission.
- **Escalation:** Under operator pressure the line that is load-bearing is **ownership, not sensitivity**:
  on the operator's own account, device and card, extract fully and show fully. Other people's data and
  other people's systems stay out — a third party's production payment vault is out even with the
  cardholder's consent, because consent covers the card, not the system (-> D27-077).
- **Ruled out when:** The data is a **third party's** rather than the operator's. Then the rule inverts:
  redact at **capture**, because retention itself is the harm (D27-077).

### D27-036 · The PII split — mask this, leave that visible

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-05 (another user of the same app) |
| **Applies to** | every cross-account finding |
| **Maps to** | the bug-hunting corpus's evidence-hygiene category split; HackerOne PII handling standards |

- **Test:** The evidence must convince a triager and nothing more. Over-redaction destroys the proof of
  the boundary crossing; under-redaction distributes the victim's data. The split is what matters.
- **How:**
  ```text
  MASK          other user's first/last name · email local part · phone (last 7 digits) · address below
                city · DOB year · government IDs · face images · correlatable account IDs
  LEAVE VISIBLE the JSON key names and field shape · YOUR OWN attacker-session uid/email (this is what
                proves the crossing) · the endpoint URL and HTTP method · the trace id
                (x-request-id, x-datadog-trace-id) so the triager can correlate to their own logs
  ```
  ```json
  {"data":{"contact":{"first_name":"Nadene","email":"nadene.afton@example.com","phone":"+1-555-867-5309"}}}
  {"data":{"contact":{"first_name":"<REDACTED — real first name>","email":"<REDACTED>@example.com","phone":"<REDACTED>"}}}
  ```
  State it in the body: "Real PII fields in the response are masked to limit unauthorised exposure of
  victim data, per responsible-disclosure hygiene. The unredacted response is available privately on
  request." For a PII finding the evidence bar is **two distinct victims' records, field names shown,
  values redacted, and a statement that testing stopped**.
- **Proof:** A PoC that proves the boundary crossing without distributing the victim's data — the key
  names and your own uid visible, the values masked.
- **Escalation:** Session cookies and bearer tokens have their own protocol (D27-038). Cloudflare
  bot-management cookies (`__cf_bm`, `_cfuvid`) and analytics cookies (`_ga`) are safe to leave visible.
- **Ruled out when:** Both accounts are tester-owned and separately registered — then leave both visible
  and say so, because that is precisely what answers the "self-inflicted impact" downgrade (D27-023 #11).

### D27-037 · The five-screenshot state-change pattern

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | supports `broken_access_control.bypass_of_password_confirmation.change_password` (P4) and, where the change is another user's, the P1 IDOR nodes |
| **Attacker** | AM-05 |
| **Applies to** | password, email, MFA-enrolment and any other state-change finding |
| **Maps to** | the bug-hunting corpus's evidence-hygiene §7 |

- **Test:** A state change needs a pre-state, the bug, and a post-state — plus the out-of-band side
  effect that shows whether a passive defence exists.
- **How:**
  ```text
  1  Pre-state verification      verify_password("current") -> true      (proves you knew the start state)
  2  THE BUG                     the change succeeds without step-up      (the most important screenshot)
  3  Post-state negative         verify_password("old") -> false          (proves the change took effect)
  4  Post-state positive         verify_password("new") -> true
  5  Side effect                 the inbox: did a notification email arrive?  (passive defence present or not)

  Filenames: {finding-#}-step{n}-{description}.png
             04-step2-update-password-no-stepup.png
  ```
  Take all five in **one sitting** and do not reload pages between them — reloads regenerate cookies and
  invalidate the earlier captures. Reference each by filename from the report body.
- **Proof:** Five numbered, cross-referenced images in which the same session and the same account appear
  throughout.
- **Escalation:** Screenshot 5 is frequently its own finding — a security-relevant change with no
  notification is a separate weakness (-> D13, -> D20).
- **Ruled out when:** The finding is read-only. Then the pattern collapses to the three-artefact rule:
  the request, the response proving the boundary was crossed, and a control showing the boundary exists
  for everyone else (D27-041).

### D27-038 · Sanitise flows and HARs at capture time, then grep the bundle before delivery

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — the risk here is a breach you caused while being paid to prevent them |
| **Attacker** | n/a |
| **Applies to** | every engagement with a live backend |
| **Maps to** | NIST SP 800-115 Appendix B §5.3 (Data Handling), §6.6 ("captured data may include sensitive data that does not belong to the organization—or personal employee data, which may create privacy concerns") |

- **Test:** A mitmproxy flow file holding thousands of production responses, a full `logcat` of a live
  app, or a `content query` dump of a provider full of real records is the tester's own data-breach
  surface. Redact on the way to disk, not on the way to the report.
- **How:**
  ```bash
  cat > scripts/strip.py <<'PY'
  import re
  SENS = re.compile(rb'(?i)(authorization|cookie|set-cookie|x-api-key|otp|password|pan|cvv)')
  def response(flow):
      for h in list(flow.request.headers):
          if SENS.search(h.encode()): flow.request.headers[h] = "<redacted-at-capture>"
      for h in list(flow.response.headers):
          if SENS.search(h.encode()): flow.response.headers[h] = "<redacted-at-capture>"
  PY
  mitmdump --set stream_large_bodies=1m --allow-hosts '^(api|auth)\.target\.example$' \
           -s scripts/strip.py -w evidence/flows.mitm
  adb shell pidof com.target.app | xargs -I{} adb logcat --pid={} -d > evidence/F-007/logcat.txt
  ```
  For a HAR:
  ```bash
  jq '.log.entries |= map(
    (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
    (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
    (.request.cookies  |= map(.value="<REDACTED>")) |
    (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
  grep -i 'authorization\|"cookie"\|set-cookie' out.sanitized.har | head -20     # verify
  ```
  Cookie protocol, in order of preference: **A — do not capture them at all** (use `credentials:
  'include'` in DevTools PoCs and screenshot the Console, never the Network Headers panel; in Burp
  Repeater drag the divider down to hide the request body; for rate-limit demos show only the Intruder
  results columns). **B —** black-bar in an image editor. **C —** find/replace on transcripts. Keep the
  unredacted originals locally for triager verification through the platform's private attachment
  system — never email.
  Then the hard gate before the bundle is encrypted:
  ```bash
  grep -rEl '(?i)authorization: bearer|set-cookie:|[0-9]{13,16}' engagement/evidence | tee /tmp/leaks.txt
  ```
- **Proof:** The leak grep returns only the deliberate instances — where the unredacted value **is** the
  finding (a token in a log, a key in prefs), keep exactly one instance, in one file, referenced by one
  finding, and rotate or invalidate it immediately after delivery.
- **Escalation:** Post-submission, log out and back in to rotate the session and rotate the test account's
  password, so every value visible in a shipped frame is already dead.
- **Ruled out when:** No live backend was in scope and no production data was captured — record that as a
  positive statement in the methodology section rather than leaving it unsaid.

### D27-039 · Your own capture is subject to the protections you are testing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Android 14+ for screenshot detection; Android 15+ for screen-share protections |
| **Maps to** | `developer.android.com/about/versions/14/features/screenshot-detection` (`FLAG_SECURE` prevents capture); `developer.android.com/about/versions/15/behavior-changes-all` (Developer Options "Disable screen share protections", testing only) |

- **Test:** `FLAG_SECURE` screens record as black, notification content is hidden during screen sharing on
  Android 15, and sensitive password input is hidden from remote viewers. Plan the capture around it —
  and never disable a protection silently.
- **How:**
  ```bash
  adb shell screenrecord --bit-rate 8000000 /sdcard/poc.mp4      # FLAG_SECURE content will be black
  adb exec-out screencap -p > shot.png
  # if a protection must be disabled to record, RECORD THAT YOU DID:
  adb shell settings put global disable_screen_share_protections 1
  adb shell settings get global disable_screen_share_protections
  ```
- **Proof:** The PoC video **plus** a written note in the finding naming every protection disabled to
  record it and stating that none of them was part of the attack.
- **Escalation:** A disabled protection that goes unstated becomes an unstated precondition, which is the
  fastest route to a retraction when the triager cannot reproduce with it on (-> D21, -> D26).
- **Ruled out when:** No protection was disabled — then say so explicitly: "no developer settings,
  compat toggles or RASP bypasses were active during this capture."

### D27-040 · Prove the caller's privilege level — shell UID is not app UID

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | decides whether the finding lands at the P1 consumer node or is dropped entirely |
| **Attacker** | AM-03 vs AM-12 — this item is what distinguishes them |
| **Applies to** | every IPC, provider and file finding |
| **Maps to** | HackTricks content-protocol (`adb shell content …` runs as the `shell` UID, so always retest interesting findings from a normal app context); Shizuku privileged-API note (shell is UID 2000, root is UID 0; `Shizuku.getUid()` says which) |

- **Test:** The single most common false-High in Android reports is a finding demonstrated only from `adb
  shell` (UID 2000) or a rooted shell, then written up as "any app can do this". Record **two** results.
- **How:**
  ```bash
  adb shell id                                                          # uid=2000(shell)
  adb shell cmd content query --uri content://com.target.provider/items  # shell UID
  # then from an installed app context
  drozer> run app.provider.query content://com.target.provider/items     # app UID, no permissions
  adb shell dumpsys package com.attacker | sed -n '/requested permissions/,/install permissions/p'
  ```
  State the PoC app's declared permissions in its manifest and in the report.
- **Proof:** Both succeed → app-reachable, report at full severity. Only the shell succeeds → shell-only;
  downgrade or drop with an explicit note saying which. Bugcrowd's evidence bar for insecure storage is
  the same rule from the other direction: the file contents **plus a named unprivileged reader** —
  root-only reads do not clear it.
- **Escalation:** Where only the shell path works, the escalation is to find the app-reachable route
  (exported provider, backup, debuggable build, traversal) rather than to argue the shell result
  (-> D07, -> D11, -> D02).
- **Ruled out when:** The app-context attempt returns `SecurityException … not exported from uid` or
  `Permission Denial`. Quote the exception verbatim in the ruled-out register — that is a strong
  negative, unlike a tool's silence (D27-049).

### D27-041 · The two controls: baseline denial and negative control, in the same take

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this is what converts "I launched an activity" into "I bypassed an access-control boundary" |
| **Attacker** | AM-03 |
| **Applies to** | every dynamic claim, every access-control finding |
| **Maps to** | HackTricks drozer content-provider exploitation ("Test the protected backend URI directly from a no-permission app to confirm it is blocked … Send the same URI through the exported provider and compare the response"); MHL's negative-control examples (contacts SQLi → `IllegalArgumentException: Invalid token SELECT` with strict checks on; libarchive → "Bad RAR file data" on the fixed build; ImageIO → "Every crash reproduces … on 26.6.1 and is silently fixed on 26.6.2") |

- **Test:** A positive alone is not proof. **Every dynamic claim needs its negative control in the same
  take**, and every access-control claim needs its baseline denial first. The differential *is* the proof.
- **How:**
  ```bash
  # BASELINE DENIAL — the direct path must fail
  adb shell am start -n com.target/.SensitiveActivity          # expect: Permission Denial … not exported
  adb shell content query --uri content://com.target.internal/ # expect: SecurityException

  # THE BUG — the indirect path succeeds
  adb shell am start -n com.target/.ProxyActivity \
    --es redirect_intent 'intent:#Intent;component=com.target/.SensitiveActivity;end'

  # NEGATIVE CONTROL — the identical action with the control present must fail
  adb shell am compat enable <CHANGE_ID> com.poc.app     # or install the patched build / flip the server flag
  #   repeat the exact same command and capture the exception, the empty result or the SecurityException
  ```
  Where a "stable fallback" response exists (a default avatar, a placeholder record), compare **size, hash
  or decoded pixels** rather than eyeballing — that is also what makes enumeration provable.
- **Proof:** The paired transcript: the direct attempt denied, the indirect attempt succeeding, and the
  identical attempt failing with the control enabled. For an IDOR the triplet is the victim's own 200,
  the attacker's 200 on the victim's object, and a control 403/404.
- **Escalation:** The negative control is also what distinguishes a **platform** block from a **vendor**
  fix (-> D22): reproduce on two API levels and quote the blocking log line, because an app bug that
  Android 16 happens to block is still an app bug for users on older releases.
- **Ruled out when:** There is no control to enable — no compat change id, no patched build, no
  server-side flag. Then say so, and substitute the "non-existent path in the same directory" control
  from D27-030 beat 5, which always exists.

### D27-042 · Ship a runnable zero-permission attacker APK, not a manifest screenshot

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | the difference between `broken_access_control.exposed_sensitive_android_intent` rated at P4 and rated on impact |
| **Attacker** | AM-03 |
| **Applies to** | every D04–D08 IPC finding |
| **Maps to** | the Oversecured PoC style (attacker activity/provider/receiver with `android:priority="999"` and no permissions); YesWeHack programmes' third-party-app PoC requirement; the observation that "requires root" and "requires physical access" are the two commonest ways a technically valid mobile finding is closed |

- **Test:** Triagers reproduce. An `adb`-only PoC is frequently dismissed as requiring ADB or physical
  access. The deliverable is a minimal APK that reproduces the exploit from a zero-permission package.
- **How:** The PoC app declares **no** permissions and a single activity, and logs its results. Ship the
  source plus a signed debug APK.
  ```bash
  # prove the attacker app really holds nothing
  adb shell dumpsys package com.attacker | sed -n '/requested permissions/,/install permissions/p'
  adb install -r attacker.apk && adb shell am start -n com.attacker/.Main && adb logcat -s evil
  ```
  Build the non-rooted PoC path **first** — objection `patchapk`, or the debuggable-repack plus `run-as`
  route — because that is the path that survives the exclusion lists.
- **Proof:** `dumpsys package com.attacker` showing an empty requested-permissions list, next to the
  successful exfiltration log. That pairing is what upgrades a report from Medium to High.
- **Escalation:** The same APK is rung 2 and rung 3 of the triage ladder (D27-064) — build it once and
  you climb two rungs without a round trip.
- **Ruled out when:** The finding's attacker model genuinely is not a local app (a network position, a
  clicked link). Then ship the equivalent artefact for that model: the crafted URL, the mitmproxy script,
  the malicious page.

### D27-043 · The one-shot reproduction script and the replayable command file

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MHL's `exploit.sh --setup-emulator` pattern (CVE-2026-0047), `deploy_exploit_mp4.sh` + `REPRODUCE.md` (CVE-2026-0006), and the CVE-2026-28576 repo shape ("the complete source for the PoC app, a prebuilt APK, step-by-step reproduction instructions, and the captured evidence logs"); drozer `load`/`set`/`unset`; objection `commands save`, `import` |

- **Test:** The report should contain a command a triager runs unmodified, end to end, with no tribal
  knowledge. Package setup, build, install, exploit and artefact extraction into one script and document
  the two invocations.
- **How:**
  ```bash
  ./exploit.sh --setup-emulator     # full run: create the AVD, build, install, exploit, extract
  ./exploit.sh                      # already have a matching emulator
  ```
  End it in a machine-readable results block: Build, Patch level, raw bytes obtained, output files,
  permissions used, output directory. The IPC equivalent is a replayable command file:
  ```text
  # poc.dz
  set PKG com.target.app
  run app.package.attacksurface com.target.app
  run app.provider.info -a com.target.app -v
  run app.provider.query content://com.target.app.provider/users
  run app.provider.download content://com.target.app.fileprovider/x/../../../../data/data/com.target.app/shared_prefs/auth.xml /tmp/auth.xml
  ```
  ```text
  dz> load poc.dz
  ```
  objection equivalent: `commands save /tmp/poc.txt` emits the unique command list from the session;
  `import /path/to/poc.js` replays a Frida agent.
- **Proof:** The triager runs `load poc.dz` or `./exploit.sh` and reproduces your output byte for byte.
  Reproduction commands must be **paste-into-shell ready**; include a Python alternative where the curl
  form needs unusual flags.
- **Escalation:** The same script is the retest harness (D27-071) and the developer's fix-verification
  step — a modified `repro.sh` that must now fail is the strongest remediation acceptance criterion there
  is.
- **Ruled out when:** The finding is static-only (a recovered key, an unreachable code path). Then ship
  the grep and the decompiled snippet instead, and say that no runtime reproduction exists.

### D27-044 · Capture the response delta, not the screenshot

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | supports the P1 IDOR and auth-bypass nodes |
| **Attacker** | AM-05 |
| **Applies to** | every auth, authorisation and API finding |
| **Maps to** | H1 #202425 (Grab, Medium 4.3), #1343300 (Basecamp, High 7.7 — `GET /?exfiltration=USER_EMAIL@gmail.com` straight from the attacker's access log), #1241116 (Reddit, Critical — the bearer-token exchange) |

- **Test:** Auth and API findings triage on the **difference** between the failure and the success
  response. A screenshot does not carry that. Paste both, verbatim, with headers.
- **How:**
  ```http
  # failure (control)
  HTTP/1.1 400 Bad Request
  {"status":400,"code":4000}

  # success (same endpoint, tampered value)
  HTTP/1.1 204 No Content
  X-Request-Id: 9d0eae1a-9c16-4aa5-8b40-01105a7cb994
  ```
  ```bash
  curl -isS -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/orders/$B_ID | tee poc-idor.txt
  diff <(curl -sS ... control) <(curl -sS ... test)      # body-level, not status-level (D27-053)
  ```
  For file theft show the file contents; for token theft show the token **and** an authenticated request
  made with it; for a JS bridge show the returned JSON arriving in your own access log.
- **Proof:** A triager reproduces from the report alone. Pair every screen artefact with the exact
  request/response that produced it, and redact tokens to first and last six characters plus a hash of
  the full value.
- **Escalation:** The UI-visible half still matters where the consequence is in the app — a 60-second
  video of account A's app displaying account B's data, alongside the timestamped proxy log of the
  request that caused it, converts a disputed report into an accepted one more often than any prose.
- **Ruled out when:** The responses are byte-identical. That is not a bypass (D27-053) — identify what
  changed before claiming anything.

### D27-045 · Capture the tombstone, not the fact of a crash

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**; the tombstone is what moves a crash toward memory safety instead |
| **Attacker** | AM-02 / AM-03 depending on the delivery path |
| **Applies to** | every crash and memory-safety finding |
| **Maps to** | MHL CVE-2026-0049 (production Android 15, `user/release-keys`), CVE-2026-0006 (`mediaswcodec`); Bugcrowd's evidence bar for native memory safety — a tombstone with the fault inside the app's own `.so` plus the triggering input |

- **Test:** Collect the full tombstone with the build fingerprint, faulting thread name, signal, abort
  message and backtrace. `user/release-keys` in the fingerprint is what proves the finding is not
  emulator-only.
- **How:**
  ```bash
  adb shell getprop ro.build.fingerprint
  adb logcat -b crash -d -v threadtime > crash.txt
  adb shell ls -t /data/tombstones | head -1
  adb pull /data/tombstones/<tombstone_N>
  adb shell 'ps -AZ | grep -E "ipservice|media\.codec|mediacodec"'
  PID=$(adb shell pidof <proc> | tr -d '\r'); adb shell su -c "grep -E 'quram|codec|skia|hwui' /proc/$PID/maps"
  ```
  The exemplar shape:
  ```text
  F DEBUG : Build fingerprint: 'google/sdk_gphone64_arm64/emu64a:15/AE3A.240806.036/12592187:user/release-keys'
  F DEBUG : Cmdline: com.google.android.documentsui
  F DEBUG : pid: 28652, tid: 28725, name: loads.documents
  F DEBUG : Abort message: 'ubsan: add-overflow by 0x00000075ec2dcc18'
  F DEBUG : backtrace: #02 pc 0000000000088c14 libdng_sdk.so (dng_opcode_MapTable::ProcessArea+388) …
  ```
- **Proof:** The tombstone naming the faulting library, plus the exact triggering input, plus the delivery
  path: a crash in a **background privileged process with the user never opening the file** is 0-click; a
  crash only on explicit open is user-interaction-required, and you must say so.
- **Escalation:** If the release build ships UBSan (`__ubsan_handle_*` frames, `ubsan:` abort messages)
  the finding **re-rates**: an integer overflow that would have been silent corruption becomes a
  guaranteed `SIGABRT`, i.e. DoS with a crash loop rather than memory corruption. Say that explicitly
  rather than claiming RCE you cannot demonstrate. -> D16.
- **Ruled out when:** The crash is a Java exception from a malformed intent with no native fault and no
  persistence across `force-stop` and reboot. That is P5; do not file it (-> Graveyard).

### D27-046 · Evidence integrity — a SHA-256 manifest and a synced device clock

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all; strictly required where the report may be relied on by a third party (finance, health, regulatory) |
| **Maps to** | NIST SP 800-115 Appendix B §5.3 (Data Handling), §6.6 (data-handling requirements set by the legal department) |

- **Test:** The client must be able to verify that the bundle they hold is the bundle you produced, and
  the timestamps in the video, the logcat and the HTTP capture must agree.
- **How:**
  ```bash
  cd engagement
  adb shell date -u            # confirm the device clock is synced BEFORE capture
  find evidence pocs findings -type f -print0 | sort -z | xargs -0 shasum -a 256 > EVIDENCE-MANIFEST.sha256
  shasum -a 256 EVIDENCE-MANIFEST.sha256 | tee EVIDENCE-MANIFEST.digest
  # the verification line printed in the report body:
  #   shasum -a 256 -c EVIDENCE-MANIFEST.sha256
  ```
  Deliver through the client-nominated channel only — their SFTP, their tenant, or an encrypted archive
  whose passphrase travels out of band. Never an unencrypted email attachment and never a public link.
  ```bash
  age -R client-recipients.txt -o deliverable.age deliverable.tar     # record the recipient fingerprint
  ```
- **Proof:** `shasum -a 256 -c` returning OK for every line on the client's copy, and the top-level digest
  in the report matching.
- **Escalation:** Pairs with the artefact manifest (-> D02) and the lab manifest (-> D26): together they
  prove *what* was tested, *what* was observed and *on what harness*, all immutably. State a retention
  window and issue a destruction certificate at closure; confirm in writing that the client revoked every
  credential they issued.
- **Ruled out when:** The engagement is an open bug-bounty submission through a platform that holds the
  attachments itself — then the platform is the integrity mechanism, and the manifest is optional.

### D27-047 · When evidence is unobtainable, substitute source-derived proof — never fabricate

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | findings where `adb root` is refused, the app is not debuggable, or the bug returns no bytes |
| **Maps to** | MASTG-TECH-0023 (Reviewing Decompiled Java Code); corpus evidence-grade lessons |

- **Test:** When you cannot show the contents, prove what the file *contains* from the app's own code. A
  vendor verifies that in a minute and cannot dispute it.
- **How:** Show three things, in order:
  ```text
  1 the WRITE SITE          editor.putString("access_token", resp.accessToken)         Auth.java:311
  2 the FILENAME RESOLUTION b() -> context.getPackageName()                            Prefs.java:44
  3 the STORAGE MODE        getSharedPreferences(name, 0)   // MODE_PRIVATE, unencrypted
  ```
  ```bash
  grep -rn 'getSharedPreferences\|putString(\s*"' jadx_out/sources | grep -iE 'token|auth|session'
  ```
  State the environment blocker explicitly instead of faking evidence: "the device is a Play `user` build
  and cannot be rooted (`adbd cannot run as root`); the file's contents were therefore established from
  the app's own write path. A physical device with an unlocked bootloader, or a debuggable build supplied
  by the vendor, would allow direct confirmation."
- **Proof:** The three code citations, quoted, with the limitation stated in the finding's `LIMITATIONS`
  field.
- **Escalation:** -> D27-034 (root-for-evidence on a second, display-only device) is the next rung when
  the vendor pushes back.
- **Ruled out when:** Direct evidence is obtainable — then obtain it. **Never invent a captured token, a
  request/response pair, a CVE, a report ID, a CVSS vector or a video.** The triager re-runs the PoC, and
  faked footage ends the report and the account.

### D27-048 · The ruled-out register as a deliverable

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this is the section that makes a clean report worth its fee |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | corpus living-report convention (*Confirmed* / *Candidate* / *Ruled out*); MASTG v2 "Observation → Evaluation" structure; NIST SP 800-115 §8.2 |

- **Test:** Keep a living `report.md` from minute one with three standing sections, written **as you go**.
  The ruled-out section is a deliverable in its own right: it stops you re-walking disproven ground and
  pre-empts "did you check X?".
- **How:** The commercial-grade row format — the bare `| # | Hypothesis | Evidence | Verdict |` is one
  column short for a coverage claim:
  ```text
  | # | Hypothesis | Method (static-read / dynamic-exec / tool-output) | Artefact (versionCode + sha256 prefix) | Evidence path | API level | Verdict | Confidence |
  ```
  Rules: (a) `tool-output` **alone is never sufficient for a negative** — pair it with a static read;
  (b) every negative names the API level it was established on; (c) a negative that depended on a
  suppressed control (an allow-listed WAF, a disabled RASP) says so; (d) include the rows that refuted
  **your own** earlier claims, keeping the superseded text with a `(Superseded:)` marker.
  Worked rows the corpus treats as exemplary: Maps and Firebase keys checked and found restricted; the
  WebView allow-list blocks `@`, `data:` and `javascript:`; providers non-exported with the
  `SecurityException` quoted; no SSL-error bypass in `onReceivedSslError`; CVE-X present but the
  vulnerable path unreachable, with the "Find Usage" output attached.
  The API-side equivalent needs a **positive control**: "seven input variants returned byte-identical
  400s with field-scoped validation errors; a valid request in the same window returned 200 — injection
  is structurally ruled out on this parameter."
- **Proof:** A register where every row has a non-empty Method, Evidence path and API level, and every
  negative carries the command and its observed output.
- **Escalation:** Rows with Confidence below high are the first candidates for the next engagement's
  scope. In the executive summary, three to five ruled-out lines become the "what was verified as
  working" section — the part clients quote internally and competitors omit.
- **Ruled out when:** Never. A report with no ruled-out register is a list of complaints rather than an
  assessment.

### D27-049 · A tool's silence is not a negative result

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every negative you intend to write down |
| **Maps to** | drozer scanner sources — `scanner.provider.injection` probes a single `'` and flags only when the exception text contains `unrecognized token`; `scanner.provider.traversal` uses one fixed payload, sixteen `../` levels, `/etc/hosts` only; `scanner.misc.native` sees only libraries bundled inside the APK; Frida hooks miss inlined, late-loaded and abstract-class targets |

- **Test:** "drozer found no exported components", "finduris returned nothing", "`adb backup` produced an
  empty `.ab`", "frida-trace reported 0 functions" are **expected defaults** on modern Android —
  exported-required from Android 12, backup gutted in 12, classes not yet loaded — not evidence of
  hardening. Only a manifest or code read establishes a negative.
- **How:**
  ```bash
  # establish the negative from the artefact, then record WHY the tool was silent
  apkanalyzer manifest print base.apk | grep -c 'android:exported="true"'
  grep -c 'android:exported' out/AndroidManifest.merged.xml
  adb shell getprop ro.build.version.sdk          # the platform default that produced the zero
  ```
  Three correctness rules that govern every runtime negative: hooking an **abstract** framework class
  records nothing (print `$className` of a live instance and hook that — `android.webkit.WebSettings` is
  abstract, the concrete type is typically `com.android.webview.chromium.ContentSettingsAdapter`);
  reading state off live objects with `Java.choose` beats intercepting setters, because the setter may
  have run during `Application.onCreate`; and every "not vulnerable" must be backed by a **positive
  control** proving the instrument works.
- **Proof:** The manifest or code citation supporting the negative, **plus the named platform default
  that caused the tool's zero**, both recorded in the ruled-out register.
- **Escalation:** Where the tool's blind spot is documented (drozer's single-quote injection probe), say
  which probe was used and what it cannot see, then run the manual variant.
- **Ruled out when:** The negative was established by reading the artefact and confirmed by a positive
  control on the same instrument in the same session. Attach both.

### D27-050 · Never assert what you have not grepped

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every global negative and every user-facing string in the report |
| **Maps to** | the corpus's own recorded failure: a false existential claim in an already-submitted report — "there is no `createChooser` … anywhere in the app's own code" — where there were nine, several attaching a FileProvider URI with `FLAG_GRANT_READ_URI_PERMISSION` |

- **Test:** Two classes of sentence are trivially falsifiable and are therefore the first things a
  reviewer checks: "there is no X anywhere in the app", and any quoted screen name, route, button label
  or error message. Both must be grepped before they are written.
- **How:**
  ```bash
  # before writing "there is no X anywhere"
  grep -rn '<X>' jadx_out/sources out/smali/ base_apktool/res/ | tee evidence/negatives/X.txt | wc -l

  # before quoting a user-facing string, grep the EXECUTING bundle/resources for the literal
  grep -rn 'Verify your identity' base_apktool/res/values*/strings.xml
  strings -a assets/index.android.bundle | grep -F 'Verify your identity'
  ```
  Attach the grep output next to the sentence it supports.
- **Proof:** The grep output backing every global negative, and the literal found for every quoted
  string. An invented UI detail in an impact bullet is **fabricated evidence** even when the technical
  core of the finding is sound.
- **Escalation:** This check belongs in the pre-delivery QA gate (D27-061), run by someone who did not
  write the findings — every global negative has its grep attached, and every user-facing string is
  spot-checked.
- **Ruled out when:** The sentence is scoped rather than existential ("no `createChooser` call in the
  three activities reachable from the deep-link router, enumerated below") — which is almost always the
  better sentence anyway.

### D27-051 · The five-way false-positive taxonomy — accurate citations do not make a finding correct

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every finding, before it leaves Candidate |
| **Maps to** | corpus false-positive taxonomy; the refuted example — a finding asserting the app's secure storage was a no-op stub, refuted by a fully implemented `com.oblador.keychain.KeychainModule` (`RNKeychainManager`) registered alongside it and actually used by the JS |

- **Test:** Five ways a finding is wrong while every `file:line` in it is correct. Run all five before the
  finding leaves Candidate status.
- **How:**
  ```text
  1 YOU READ THE WRONG BINARY. For OTA-capable apps, confirm the hash of the EXECUTING bundle before
    citing any line.                                                              (D27-004, D01, D19)
  2 YOU READ *AN* IMPLEMENTATION, NOT *THE* IMPLEMENTATION. Before claiming a subsystem is absent,
    stubbed or broken:
      - grep for a SECOND implementation of the same capability
      - check the REGISTRATION LIST (generated PackageList, the DI graph, the merged manifest) — is the
        thing you analysed even wired up?
      - check the CALLER — does the JS/native layer actually call the one you analysed?
  3 VOLATILE RESPONSE CONTENT MISTAKEN FOR SIGNAL.                                (D15, D27-053)
  4 A TOOL'S SILENCE MISTAKEN FOR A NEGATIVE RESULT.                              (D27-049)
  5 AN EMULATOR ARTEFACT REPORTED AS A FINDING.                                   (D27-058)
  ```
  ```bash
  # check 2, mechanically
  grep -rn 'class .*Keychain\|class .*SecureStorage\|class .*CryptoManager' jadx_out/sources
  grep -rn 'new .*Package()' jadx_out/sources | grep -i packagelist      # what is actually registered
  grep -rn 'NativeModules\.\|require(.*keychain' assets/*.bundle          # what the caller actually uses
  ```
- **Proof:** The five check results recorded next to the finding, each with its command output.
- **Escalation:** Check 2 is also a discovery technique: the second implementation is often the
  interesting one, and the registration list frequently contains components the app's own team never
  wrote (-> D17, -> D18).
- **Ruled out when:** All five checks pass with evidence. Then the finding leaves Candidate and enters the
  adversarial verification pass (D27-060).

### D27-052 · Marker discipline

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | reflection, injection, cache poisoning, parameter pollution and out-of-band SSRF claims made through the mobile API |
| **Maps to** | the bug-hunting corpus's Marker Discipline; the recorded case — `X-Forwarded-Proto: javascript` appeared to reflect across multiple pages because the word `javascript` occurs naturally in SharePoint help-link hrefs |

- **Test:** The injected marker must be unique and unmistakable, or your "reflection" is a word collision.
  **Search the BASELINE response for the marker before claiming reflection** — this single check kills
  roughly eighty per cent of false reflection reports.
- **How:**
  ```bash
  MARK="x4hd2k9pq$(openssl rand -hex 3)"          # 8+ chars, random alphanumeric, no English words
  curl -s "$URL" | grep -c "$MARK"                # BASELINE first — must be 0
  curl -s "$URL?q=$MARK" | grep -o "$MARK"        # only now is a hit signal
  ```
  Never use `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA` or your own
  domain. Good forms: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`, or a Collaborator
  subdomain prefix. For out-of-band tests, sub-tag each payload per sink so you can tell which one fired.
- **Proof:** The marker present in the test response and **absent from the baseline**, with both outputs
  attached.
- **Escalation:** The same discipline is the canary rule for on-device evidence (D27-031) — one mechanism,
  two surfaces.
- **Ruled out when:** The baseline already contains the marker string, or the marker is a natural-language
  word. Then the observation is a collision, and it goes in the retraction appendix if it was ever
  claimed (D27-062).

### D27-053 · The body-diff rule

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-05 |
| **Applies to** | every bypass claim made against the mobile backend |
| **Maps to** | the bug-hunting corpus's Body-Diff Rule; the recorded case — `Host: target.example:80@evil.example.com` returned 200 instead of the baseline 403, body byte-identical at 8,341 bytes both ways; the AWS ELB had normalised the Host and dropped the `@evil` portion. **Status-code-only claims are the most common rejected-as-N/A category on bug-bounty platforms** |

- **Test:** A bypass claim requires a response **body** differential, not a status code. A 200 with a
  byte-identical body is not a bypass.
- **How:**
  ```bash
  diff <(curl -sS "$BASE" -H "$CTRL") <(curl -sS "$BASE" -H "$TEST")
  curl -sS "$BASE" -H "$CTRL" -o /tmp/a -w '%{http_code} %{size_download}\n'
  curl -sS "$BASE" -H "$TEST" -o /tmp/b -w '%{http_code} %{size_download}\n'
  cmp -l /tmp/a /tmp/b | head        # identify WHAT changed, byte by byte
  ```
  A five-byte difference might be real — identify it. A correlation id or a timestamp is not content; a
  changed record is.
- **Proof:** A byte-level diff in the report, with the changed bytes identified and explained.
- **Escalation:** Where the body does differ, the next question is whether it differs because of *your
  input* or because of a fixed server policy (D27-055).
- **Ruled out when:** The bodies are identical. Record it in the ruled-out register with the byte counts —
  that is a strong, citable negative.

### D27-054 · The statistical-sample rule

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs claims against `server_security_misconfiguration.no_rate_limiting_on_form.*` (P4) and username-enumeration nodes (P4) |
| **Attacker** | AM-01 |
| **Applies to** | timing oracles, user enumeration, rate-limit absence, race conditions |
| **Maps to** | the bug-hunting corpus's Statistical-Sample Rule; the recorded case — `Administrator` took 1,527 ms against a ~700 ms control on a single shot; n=80 interleaved across eight groups collapsed every group to mean 685–716 ms, σ 25–74 ms, and the finding was retracted |

- **Test:** Single outliers are not signal; network jitter routinely produces 2x outliers, and a mobile
  client's radio adds more. Minimum **n ≥ 10 interleaved trials per group**, randomised order, not
  back-to-back.
- **How:**
  ```python
  import random, statistics, requests
  groups = {"control": CTRL_PAYLOADS, "test": TEST_PAYLOADS}
  trials = [(g, p) for g, ps in groups.items() for p in ps for _ in range(10)]
  random.shuffle(trials)                      # interleave; never run one group to completion first
  res = {g: [] for g in groups}
  for g, p in trials:
      r = requests.post(URL, json=p, timeout=20); res[g].append(r.elapsed.total_seconds()*1000)
  for g, v in res.items():
      print(g, "n=%d mean=%.1f median=%.1f sd=%.1f" % (len(v), statistics.mean(v),
            statistics.median(v), statistics.pstdev(v)))
  # signal requires the suspect group's mean >= 2 sigma above the control's
  ```
  For rate limits, sample 100+ attempts before claiming absence, and distinguish per-IP, per-account,
  per-session and per-username throttling — then quantify: "10/min × 60 × 24 across N parallel sessions
  reaches 10^6 in X days". TOTP uniformity is not a pattern: RFC 6238 truncates an HMAC-SHA1 hash mod
  10^6, so the output is uniform and three "pattern-like" samples prove nothing.
- **Proof:** The distribution — n, mean, median and σ per group — not the outlier.
- **Escalation:** A confirmed rate-limit absence is P4 alone; carry it to OTP brute force → account
  takeover (-> D13) for `broken_authentication_and_session_management.authentication_bypass` (P1).
- **Ruled out when:** The groups collapse within 2σ. Record n, the means and the σ values in the ruled-out
  register — that is a defensible negative and it takes ten minutes.

### D27-055 · Server policy versus state

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-01 |
| **Applies to** | every oracle or bypass claim |
| **Maps to** | the bug-hunting corpus's Server-Policy-vs-State rule; the recorded case — a `download.aspx` "file existence oracle" that was actually an extension blocklist: `.ashx`, `.asmx`, `.svc`, `.config` are always blocked regardless of whether the file exists |

- **Test:** A server-side policy that always denies is not a state oracle. Establish whether the
  differentiator tracks **your input** or a **fixed deny-list**.
- **How:** Probe the axis you are *not* claiming:
  ```bash
  # if you think the response reveals existence, test a definitely-absent name with an ALLOWED extension
  curl -sS "$URL?f=definitely-absent-$RANDOM.txt" -o /dev/null -w '%{http_code} %{size_download}\n'
  # and a definitely-present name with a BLOCKED extension
  curl -sS "$URL?f=known-present.config"          -o /dev/null -w '%{http_code} %{size_download}\n'
  ```
  The mirror-image error: a `403 → 200` flip when a spoofed header is added is meaningful; a `200` both
  with and without the header means the path was never protected in the first place.
- **Proof:** A 2×2 table — input present/absent against the policy axis — showing the response tracks the
  state rather than the policy.
- **Escalation:** Where it is policy, the finding may still exist one layer down (the policy is applied at
  the edge but not at origin) — test the origin directly if scope allows.
- **Ruled out when:** The 2×2 shows a fixed deny-list. Record it; this is the cheapest retraction to avoid.

### D27-056 · The layer-ordering trap — a validation error does not prove you passed auth

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every claim at `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | every auth-bypass claim against an endpoint found in the APK |
| **Maps to** | the bug-hunting corpus's LAYER-ORDERING TRAP — described there as the single most transferable item in the repository; it applies equally to WAF and CDN layers, where an edge block is not an origin response |

- **Test:** The highest-confidence false positive in the entire auth-bypass class. Many stacks put a
  global input sanitiser, body parser or schema filter **in front of** the auth middleware, so a
  malformed body is rejected before auth is ever consulted — and the response is indistinguishable from
  "auth passed, validation failed". A 400 saying "field X is required" from an unauthenticated request
  does **not** prove you reached business logic.
- **How:** Re-send with a minimal **well-formed** body.
  ```bash
  curl -s -X POST https://target/api/v1/resource -d '{'
  # 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}  <- looks like bypass

  curl -s -X POST https://target/api/v1/resource -H 'Content-Type: application/json' -d '{}'
  # 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}   <- where auth actually sits
  ```
  Only the second response tells you where the auth layer is. If the error text is about **input shape or
  character class**, you are talking to a parser. If it names a **domain field** (`accountId is
  required`) *and* a well-formed `{}` still returns it, that is real signal — and mandatory fields named
  `is_admin`, `is_internal`, `requested_by`, `role_id` or `account_type` mean authorisation is derived
  from client-supplied parameters, which is Critical-class (-> D15).
- **Proof:** Both responses side by side, with the well-formed `{}` request as the decisive one.
- **Escalation:** Once the auth layer is located, the mobile-specific follow-ups are the client-only rate
  limit the API never enforces, and client-side-only MFA checks — where response manipulation is a real
  finding **only if the subsequent API calls also work** (-> D13, -> D15).
- **Ruled out when:** The minimal well-formed body returns 401/403. Record both responses in the
  ruled-out register; this gate has prevented false Criticals against production financial infrastructure.

### D27-057 · The shell-loop ban — count your results

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every automated sweep, including agent-driven ones |
| **Maps to** | the bug-hunting corpus's Shell-Loop Ban; the recorded case — roughly fifty probes' worth of verb-tampering testing silently lost to zsh array expansion, with output that looked complete |

- **Test:** zsh array expansion fails **silently**. `for x in "${arr[@]}"` can produce zero iterations with
  no error when the array was not populated by the previous command, and the transcript still looks
  correct. A sweep that quietly did nothing becomes a false negative in the ruled-out register, which is
  worse than a false positive because nobody checks it.
- **How:** Loops of five or fewer hardcoded items in shell are fine. Anything iterating a list, a file or
  a computed range goes to Python with `try/except` per iteration and explicit per-iteration logging —
  and **always count**:
  ```python
  import sys
  targets = [l.strip() for l in open("uris.txt") if l.strip()]
  ok = 0
  for i, t in enumerate(targets, 1):
      try:
          probe(t); ok += 1
      except Exception as e:
          print(f"[{i}/{len(targets)}] FAIL {t}: {e}", file=sys.stderr)
      print(f"[{i}/{len(targets)}] {t}")
  assert ok == len(targets), f"expected {len(targets)} probes, completed {ok}"
  ```
  ```bash
  wc -l probe-results.txt          # compare against the input count, every time
  ```
- **Proof:** The result count equals the input count, asserted rather than eyeballed. If you expected 100
  probes and got fewer than 50 lines, the loop ate something.
- **Escalation:** Apply the same counting discipline to `adb shell` loops over provider URIs, deep-link
  payloads and component names — those are exactly the sweeps whose zero results end up as ruled-out rows.
- **Ruled out when:** The sweep is five or fewer hardcoded items typed inline and visible in the
  transcript.

### D27-058 · Emulator artefacts that must never be reported

| | |
|---|---|
| **Severity ceiling** | Support — these are lab artefacts, never findings |
| **VRT** | none; filing one lands in the P5 hardening branch at best and damages the SNR at worst |
| **Attacker** | AM-12 (own harness — not an attack) |
| **Applies to** | every emulator-based engagement |
| **Maps to** | corpus never-report list; MASTG false-positive notes |

- **Test:** Three observations are properties of the harness, not of the app. Re-test on a physical device
  or with the precondition satisfied before the observation reaches the candidate list.
- **How:**
  ```text
  1 KeyInfo.isInsideSecureHardware() == false / getSecurityLevel() == 0
      Emulator keystores are software-backed. NEVER report this. Re-test on hardware, or state the
      limitation and check the app's key attestation instead (-> D12).
  2 "Key generation throws" with setUserAuthenticationRequired(true) on a fresh emulator
      There is no screen lock. Set one and retry:   adb shell locksettings set-pin 1234
  3 "adbd cannot run as root" on a production user-build / Play image
      Production images cannot be rooted. NOT A FINDING; it is the definition of the platform.
  ```
- **Proof:** The corrected result on a device where the precondition holds, or an explicit limitation note
  saying the claim was not testable on this harness.
- **Escalation:** The genuine finding adjacent to #1 is a key that is **not** hardware-bound on a device
  that supports StrongBox, demonstrated with attestation — that requires hardware (-> D12).
- **Ruled out when:** The observation was made on a physical device with a screen lock set and a
  production build. Then it is a real result and belongs in the report.

### D27-059 · MASTG's own documented false-positive classes

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — pre-empting these stops a valid finding being closed as noise and stops you filing an invalid one |
| **Attacker** | n/a |
| **Applies to** | any engagement mapped to MASTG |
| **Maps to** | MASTG-TEST-0223, MASTG-TEST-0232, MASTG-TEST-0235, MASTG-TEST-0242, MASTG-TEST-0243, MASTG-TEST-0244, MASTG-TEST-0316, MASTG-TEST-0325, MASTG-TEST-0338 (`false_negative_prone: true`), MASTG-TEST-0351, MASTG-TEST-0352, MASTG-TEST-0353, MASTG-TEST-0204 |

- **Test:** MASTG documents expected false positives and negatives. Check the finding against them before
  filing, and cite the test id when a scanner disagrees with you.
- **How:**
  ```text
  Stack canaries      Flutter mitigates buffer overflows differently; React Native .so files that are
                      empty in release or contain no stack buffers (libruntimeexecutor.so,
                      libreact_render_debug.so, libreact_utils.so, libreact_config.so, libreact_debug.so)
                      — RN maintainers explicitly declined -fstack-protector-all as "a performance hit
                      for no effective security gain".
  ECB mode            "RSA/ECB/OAEPPadding" / "RSA/ECB/PKCS1Padding" — ECB is a JCA placeholder for RSA,
                      not a block mode. Not a finding.
  Masked input        Custom text controls in game engines and custom UI frameworks produce expected
                      false negatives for MASTG-TEST-0316.
  Storage integrity   Mac / Signature / MessageDigest are commonly used for networking, analytics and
                      generic checksums — presence does not prove an integrity mechanism.
  Detection controls  Absence of hook hits does not prove absence of the control (obfuscation, dynamic
                      loading, anti-instrumentation).
  Cleartext config    manifest usesCleartextTraffic="true" PLUS any network-security-config (even an
                      empty one) does NOT fail MASTG-TEST-0235.
  Pinning             Do not fail an app for unpinned THIRD-PARTY domains — MASTG-TEST-0242/0243/0244
                      all say so explicitly.
  Randomness          MASTG-TEST-0204 requires confirming the random value is used for security-relevant
                      purposes before it is a finding ("Further Validation Required").
  ```
- **Proof:** The exclusion cited by test id in the ruled-out register, so a client's own scanner output
  can be reconciled against your report.
- **Escalation:** The MASTG informational block is a demotion list, not a finding list — root/emulator/
  debugger/hook detection (0324, 0325, 0341, 0351, 0352, 0353), obfuscation (0368, 0369), debug symbols
  (0288), PIC/canaries (0222, 0223), StrictMode (0263–0265), SDK_INT checks (0245), screen-lock detection
  (0247, 0249), dangerous permissions (0254), GMS provider (0295), JCA provider (0312), biometric
  device-credential fallback (0326, which MASTG itself calls "a hardening issue, not a critical
  vulnerability"), `setConfirmationRequired(false)` (0329, "not inherently a vulnerability"), SafeBrowsing
  (0399), `AllowContentAccess`/`AllowFileAccess` (0250–0253, "does not represent a security vulnerability
  by itself"), and `android:debuggable="true"` (0226, which links Android's own "not considered a direct
  vulnerability" note). Each is reportable only as the escalation, in the domain named.
- **Ruled out when:** The observation is on the list and the escalation does not exist in this build. File
  the ruled-out row citing the test id, not a finding.

### D27-060 · The multi-tool reproduction bar, and the adversarial verification pass

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | governs every P1/P2 claim |
| **Attacker** | n/a |
| **Applies to** | every Critical and High |
| **Maps to** | the bug-hunting corpus's Multi-Tool Reproduction Bar and its recorded case — a curl-only timing differential that vanished under Python `requests` was a tool artefact, not a bug; corpus adversarial-verification practice, which in one run refuted one of the author's own findings whose every citation was accurate |

- **Test:** Two gates before submission. First: reproduce every Critical or High via **two independent
  tools with different HTTP stacks**, to rule out tool artefacts. Second: run one sceptic per finding,
  tasked to **refute** it.
- **How:**
  ```text
  Tool pairs      curl + Burp Repeater · Python requests + a raw socket over ssl · Burp + python urllib
                  On-device: adb am/content + a zero-permission PoC APK + drozer from the agent
  Sceptic's brief For each finding: does each citation say what is claimed? Is there a guard the finder
                  walked past? Is the binary the executing one? Is there a second implementation? Was the
                  negative established by a tool's silence? Is the crossing actually demonstrated?
  ```
  Budget for the sceptic. Adversarial verification is the highest-value use of parallelism in this work
  and it is the difference between a credible report and a retraction.
- **Proof:** Two independent reproductions attached per Critical/High, and a recorded refutation attempt
  per finding — including the ones that succeeded.
- **Escalation:** A successful refutation goes into the ruled-out register next to the finding it killed
  (D27-048), not into the bin — a visibly self-correcting report reads as rigour.
- **Ruled out when:** The finding is Low or Informational and the cost of the second tool exceeds its
  value. Everything at Medium and above gets both gates.

### D27-061 · The pre-delivery QA gate — reviewed by someone who did not write it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | client deliverables; the top half applies to bounty submissions too |
| **Maps to** | operationalises the corpus's "never write a global negative without running the global grep" and "never assert a user-facing string you have not grepped" into a gate with a named owner; NIST SP 800-115 §8.2 |

- **Test:** The adversarial pass (D27-060) attacks the technical claim. This gate catches the errors
  clients actually notice: a wrong package name, a severity that contradicts the vector, a screenshot
  showing a different account, a remediation naming a class that does not exist in the shipped build.
- **How:** A named reviewer who did not write the findings runs and signs this list:
  ```text
  [ ] Every finding's package name, versionName and versionCode match ARTEFACT-MANIFEST.txt
  [ ] Every file:line citation resolves in the jadx tree of the TESTED artefact (spot-check 3 per finding)
  [ ] Every user-facing string, screen name, route and error message quoted is grepped and found
  [ ] Every global negative has its grep output attached
  [ ] Every CVSS vector recomputes to the stated score and matches the narrative (no S:C without a crossing)
  [ ] Every severity is supported by an artefact in the evidence tree, not by an adjective
  [ ] Every screenshot/video was opened and shows the claim (extract a frame; look at it)
  [ ] Identity coherence: the same account/identifier appears in every frame of a given PoC
  [ ] No credential, token, OTP or third-party PII visible in any shipped frame or log
  [ ] Every repro.sh runs clean on a lab rebuilt from LAB-MANIFEST.txt
  [ ] Coverage register has zero TODO rows; blocked register OPEN rows appear as stated limitations
  [ ] Ruled-out rows each carry their evidence and the reason for the negative
  [ ] Demotion-trap list applied (D27-071); no padding findings
  [ ] Exec summary's top-5 actions correspond to the top-5 findings by severity
  [ ] Remediation for each finding names the concrete change, not a principle
  [ ] No other client's name, path or data anywhere in the bundle
  ```
- **Proof:** A signed checklist with the reviewer's name and date, retained rather than shipped.
- **Escalation:** A failed item **blocks delivery**; it does not become a footnote.
- **Ruled out when:** Single-operator bounty work with no second reviewer — then run the list against
  yourself after a break, and treat the first five rows as mandatory.

### D27-062 · Retraction discipline — never silently drop a failed finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every engagement |
| **Maps to** | the bug-hunting corpus's RETRACTION DISCIPLINE — "a clean 11-finding report with a retraction appendix is more trustworthy than a 13-finding report where 2 fall apart at triage" |

- **Test:** When a claimed finding fails reproduction, document the retraction in an appendix rather than
  deleting it. A quietly deleted finding reads as nothing at all — and the reviewer may find the error
  first.
- **How:**
  ```markdown
  ### Retracted: <finding name>
  - **Original signal:** <what looked like a bug>
  - **Disproving evidence:** <reproduction step + the observation that disproves it>
  - **Why it looked like a bug:** <root cause of the FP — marker collision, jitter, status-code-only
    confidence, layer ordering, second implementation>
  - **Retraction date:** <YYYY-MM-DD>
  ```
  If a finding stops reproducing within 24 hours of submission, **retract pre-emptively**: a
  self-retraction reads "the researcher validates their own work", a triager retraction reads "the
  researcher submitted noise", and self-retractions do not hit the same platform-tracked metric.
- **Proof:** The appendix, with the retracted finding keeping its original id (D27-072) and appearing in
  the ruled-out register as WITHDRAWN with the reason.
- **Escalation:** Every retraction should produce a guardrail: what validation step or wording would have
  prevented it? That guardrail belongs in this chapter, not just in the appendix.
- **Ruled out when:** The finding stopped reproducing because **the client patched it** — that is the
  opposite case (D27-063). The distinguishing test is whether you hold timestamped pre-patch evidence.

### D27-063 · Do not retract a confirmed finding the client patched mid-engagement

| | |
|---|---|
| **Severity ceiling** | Support — it preserves a real Critical that would otherwise be discarded |
| **VRT** | the finding keeps its original node |
| **Attacker** | n/a |
| **Applies to** | live engagements against monitored targets |
| **Maps to** | the bug-hunting corpus's recorded engagement — a client SOC patched a confirmed SQLi within roughly thirty minutes of the first probe, and a separate external attacker was observed locking legitimate users' accounts during the test window |

- **Test:** A confirmed finding that stops reproducing is not automatically a false positive. On a
  monitored target the likeliest explanation is that the client fixed it while you were writing it up.
- **How:** Keep the finding, with **timestamped pre-patch evidence**, and document the detection itself as
  a deliverable observation.
  ```bash
  # this is why every capture carries a synced clock and a timestamp (D27-046)
  date -u; adb shell date -u
  ls -l --time-style=full-iso evidence/F-009/
  ```
  In the finding, state: the time of first observation, the time reproduction stopped, the evidence held
  from before the change, and the fact that you notified the client at <timestamp>.
- **Proof:** A timestamped request/response or on-device capture from before the patch, plus the
  notification record.
- **Escalation:** In red-team mode the detection timeline is a **positive** finding about the client's
  SOC. In an assessment it belongs in the timeline section and in the retest scope (D27-071).
- **Ruled out when:** You hold no pre-patch evidence. Then you cannot distinguish this case from a false
  positive, and the honest action is the retraction appendix (D27-062) — which is the argument for
  capturing evidence at the moment of discovery rather than at write-up time.

### D27-064 · The triage ladder — have the next artefact ready so you climb a rung per reply

| | |
|---|---|
| **Severity ceiling** | Support — it converts a "no impact" close into a paid finding |
| **VRT** | moves the report from a P5 close to its true node |
| **Attacker** | AM-03 |
| **Applies to** | every confused-deputy and read-primitive report |
| **Maps to** | corpus triage-ladder table and the verbatim triage responses it was built from |

- **Test:** Triage rejections are specific and predictable. Build the next rung's artefact **before**
  submitting, so each reply is an artefact rather than an argument.
- **How:**
  | Triager says | What they actually want | Deliver |
  |---|---|---|
  | "no impact" / "N/A" | proof the read reaches sensitive data | the primitive pointed at the crown-jewel file; token or PII on screen (D27-035) |
  | "you're just reading via shell" | proof an *app*, not adb, can do it | a zero-permission APK that reads into its own process (D27-042, D27-040) |
  | "exfiltrate to your own server/webhook" | the bytes leaving to an attacker host | full read → POST → attacker server, shown arriving |
  | "confirm on a real device with an APK" | on-device, no adb, believable | two-phone, no-shell video on a production-equivalent device (D27-034) |

  Rules that make each reply land:
  ```text
  - Answer the literal sentence, in their words. "You asked X — here is X" beats a re-explanation.
  - Re-concede the honest limitation every time. Conceding the weak half is what makes the strong half
    believable.
  - Distinguish READ from EXFIL explicitly. A confused-deputy read where the attacker never receives the
    bytes is real but bounded; say so, then either find the gadget that returns them or state plainly
    that it does not exist in this build.
  - Name inherent preconditions as recurring events, not caveats to bury: "fires on the victim's next
    login" is honest and still impactful; hiding it and being caught is fatal.
  - For rung 4, state the device is a non-rooted, non-debuggable Play image (production-equivalent) and
    offer physical hardware.
  ```
- **Proof:** Each rung answered with the literal artefact, in one reply, with no round trip spent
  clarifying.
- **Escalation:** Build rungs 2 and 3 during the engagement, not during triage — the zero-permission APK
  and the exfil endpoint cost an hour each and save a week of thread latency.
- **Ruled out when:** The report already ships all four rungs. Then the ladder is a pre-emptive structure
  for the body: read → app-reachable → exfiltrated → on real hardware.

### D27-065 · The eight-step pushback playbook

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every disputed report |
| **Maps to** | corpus triage-pushback playbook; the verbatim rejection it was built from — "if you are able to read shared preferences with sensitive information **or** perform any unwanted action", which is two acceptance criteria, not one |

- **Test:** Answer the literal bar the triager set, in their words, and lead with the artefact rather than
  the argument.
- **How:**
  ```text
  1 Re-read their sentence as a CHECKLIST. Address each criterion explicitly, labelled, in their order.
  2 Fix the DEMONSTRATION, not the rhetoric. If the PoC targeted a harmless file, re-run it on the real one.
  3 Prove the data is sensitive FROM THEIR CODE: write site → filename resolution → storage mode. A vendor
    verifies that faster than any screenshot and cannot argue with it.
  4 Concede the weak half in your own words, first.
  5 Self-correct any error in your own report before they find it: quote the wrong sentence, give the
    corrected reasoning, show the conclusion still stands.
  6 Name the disagreement instead of letting it be resolved silently against you: "I scored S:C = 7.9; if
    you read the sandbox crossing as S:U the same vector gives 6.8."
  7 Offer the NEXT test rather than repeating the last one.
  8 Never discuss money before severity is agreed.
  ```
  The counter-lines for the four commonest pushbacks: "requires authentication" → "only a free account,
  no special role"; "limited impact" → "affects N users / exposes <PII type> / $X at risk"; "already
  known" → "show me the report number — I searched the programme's disclosed reports and found none"; "by
  design" → "show me the documentation stating this is intended".
- **Proof:** The reply reads as rigour rather than advocacy, and the next message from triage is about
  the artefact rather than about the claim.
- **Escalation:** For a client rather than a triager, separate the three things being disputed: the FACTS
  (is the mechanism real — settled by demonstration only, screen-shared), the SCORE (does the vector
  match the facts — challenge a metric, not the number), and the RISK RATING (does the score match their
  business context — legitimately theirs, via CVSS Environmental, D27-019). Most disputes are the third
  dressed as the first. A finding is never deleted from a report on request; it stays, with their stated
  position recorded as a signed risk-acceptance row.
- **Ruled out when:** The triager is right. Then step 5 applies and you correct the report yourself.

### D27-066 · Out-of-scope-clause rebuttals

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Bugcrowd; the framing transfers to HackerOne and Intigriti |
| **Maps to** | the bug-hunting corpus's OOS rebuttal templates and their honest caveat |

- **Test:** Triagers map findings to an out-of-scope clause without reading. Include an "In-scope
  justification" section that quotes the clause and explains why it does not fit.
- **How:** Four templates worth reusing:
  ```text
  "Rate limiting on non-authentication endpoints"
      "<endpoint> is the canonical authentication endpoint — it accepts a password/token/OTP and returns
       whether it matches the stored credential. By definition an authentication primitive; the
       'non-authentication' qualifier does not apply."

  "Debug information disclosure"  (for schema/introspection findings)
      "The persisted-query allow-list is acting as an AUTHORISATION control. The bypass converts that
       gate into a no-op — mutations become reachable that the official clients cannot invoke. The schema
       disclosure is incidental; the impact is mutation-surface unlock, not information leakage."

  "User enumeration with low-risk information"
      "The data leaked includes the matched user's <full real name / phone / last four of SSN>.
       Real-identity knowledge is the same data class that gates the programme's own account-recovery and
       support-call verification, so this lookup defeats one of their own anti-fraud controls. This is
       PII disclosure, not handle enumeration."

  "Theoretical / not exploitable"
      "Exploitable end to end as demonstrated: <one-sentence path>. The PoC includes <N HTTP requests
       with redacted cookies / N screenshots / a sanitised HAR> showing the attacker's session reading
       victim data / changing victim credentials."
  ```
  Pre-check the programme's mobile exclusions **before** testing, not after. Verbatim from one public
  programme: "Vulnerabilities requiring physical access to a user's smartphone"; "Exploits that are only
  possible on Android version 8 and below"; "Exploits that are only possible on a jailbroken device";
  "Exploiting a generic Android or iOS vulnerability."; "Lack of code obfuscation"; "Lack of binary
  protection / jailbreak and root detection / anti-debugging controls"; "Crashing your own application";
  "Non important secrets (such as 3rd party secrets)". Qualifying, on the same programme: "Sensitive
  Information Exposure Through insecure data storage on device" and "Leaked information from Mobile
  (without rooting)".
- **Proof:** The rebuttal plus the evidence it names.
- **Escalation:** Where a clause genuinely applies, the escalation is to change the attacker model
  (D27-024), not to argue the clause.
- **Ruled out when:** You have only an "API behaviour" observation with no demonstrated exploitation
  path. Then the finding **is** theoretical — do not file it.

### D27-067 · Chain-filing order — primitives first, consumer second, then backfill

| | |
|---|---|
| **Severity ceiling** | Support — worth two payouts instead of one |
| **VRT** | each primitive at its standalone node (typically P3/P4), the consumer at the chained node (P1/P2) |
| **Attacker** | AM-03 at the primitives, AM-02 or AM-01 at the consumer |
| **Applies to** | every multi-finding engagement |
| **Maps to** | the bug-hunting corpus's chain-filing workflow and submission-order strategy; HackerOne's systemic-issue standard, which fully rewards "typically the first 3 unique submissions establishing the systemic issue" and treats later same-fix instances as duplicates |

- **Test:** A consumer report references the primitives' submission ids — which only exist once the
  primitives are filed. File in dependency order, then backfill the links.
- **How:**
  ```text
  1 Identify the highest-severity chained outcome.
  2 File each chain primitive as its own report at its standalone severity, leaving a placeholder
    cross-reference line.
  3 File the chain consumer with the full ATO/RCE narrative at the chained severity, filling in the real
    primitive ids.
  4 Edit each primitive to backfill the consumer's id.
  ```
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — [primitive 1: intent redirection into the non-exported WebView]
  - **submission [UUID-2]** — [primitive 2: deep-link host validation bypass]
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do **not** paste the whole chain narrative into every primitive, claim each primitive is independently
  P1, or ask for a single combined bounty. Frame the chain as a **severity amplifier, not a merge
  request**. Submission order across the engagement: primitives → consumer → clean standalone P3s →
  scope-risky findings last, so the risky one is read against an established track record. **Never file
  everything in one batch within minutes** — triagers read that as low-effort spam.
- **Proof:** Cross-referenced ids in both directions, and each primitive reproducing on its own.
- **Escalation:** Under Intigriti's vulnerability-type assessment mode the chain is scored at its first
  link (D27-020) — there, file the highest-value link as its own report and keep the chain narrative as
  context.
- **Ruled out when:** The links share a single fix surface — then it is one bug with several symptoms and
  one report. Chaining two genuinely separate bugs into one report is an anti-pattern that costs a payout.

### D27-068 · Duplicate avoidance — go where scanners do not

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all bounty work |
| **Maps to** | corpus duplicate-avoidance guidance; the disclosed-payout dataset in which heavily-hunted apps yield many $0 reports for shallow classes while larger payouts cluster on unusual surfaces |

- **Test:** A duplicate pays nothing and costs the same effort. Choose the surface before choosing the
  technique.
- **How:**
  ```text
  - Anything an automated tool flags in the manifest is already reported. The classes that require code
    reading and chaining are not scanner-reachable: intent redirection into a non-exported WebView,
    FLAG_GRANT_* provider theft, task hijacking, backup/restore, package visibility, privileged listener
    services, orphaned or mistyped custom permissions.
  - Prefer the NEWEST release. A feature shipped in the last two releases has the shortest queue of prior
    reports. Diff versions.
  - Prefer SPLIT APKs and secondary flavours — miss a split, miss code, and so does everyone who pulled
    only base.apk.
  - CROSS TWO SURFACES. A bug needing both an Android primitive and a backend behaviour has a near-zero
    duplicate rate because it needs two skill sets to find.
  - Read the programme's DISCLOSED REPORTS first, and its changelog for silent fixes.
  - Read the programme's KNOWN-ISSUES admissions — they cost nothing and save whole days.
  ```
  ```bash
  apktool d old.apk -o old/ && apktool d new.apk -o new/
  diff -r old/smali new/smali | grep -A5 '^[<>].*\(startsWith\|contains\|equals\|check\|valid\)'
  ```
- **Proof:** A written rationale for the chosen target and feature, dated before the testing started.
- **Escalation:** Finish one chain to demonstrated impact rather than opening four — the second and third
  hop is where the value is, and it is exactly the work an unfocused engagement never reaches.
- **Ruled out when:** The programme is private and newly launched — then the duplicate risk is low and
  breadth beats depth for the first pass.

### D27-069 · First-actionable, and one root cause equals one payout

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Google programmes directly; the rules are spreading |
| **Maps to** | Android & Google Devices "How We Handle Duplicate Reports", "Reward Adjustments for Known and Trending Issues", "Published Threat Models and Non-Bugs"; Google Mobile VRP SDK duplicate rule; Xiaomi General Assessment Rules |

- **Test:** Filing a placeholder to secure a timestamp now actively loses the bounty, and one root cause
  pays once no matter how many apps it appears in.
- **How:**
  ```text
  1 "First actionable", not "first filed": "the date and time a report is created is not the sole factor
    … A report becomes actionable only when it meets all baseline requirements, including a functional
    Proof of Concept … Reports submitted prematurely without a PoC, simply to secure a timestamp in the
    bug tracker, will be superseded."   -> finish the PoC first.
  2 A superior late report can still be paid: where a later report "provides a technically superior PoC,
    a more comprehensive root-cause analysis, or a viable patch that engineering actively uses … the VRP
    panel reserves the right to split the final financial reward", with possible shared CVE credit.
    -> if you are duplicated, submit the patch and the root-cause analysis anyway.
  3 NEVER mass-file one SDK bug across many apps: "If multiple reports of the same SDK or library
    vulnerability are received, EVEN ACROSS DIFFERENT APPS, they will be considered duplicates of the
    earliest report submission due to having the same root cause." File once, against the SDK.
  4 Expect payout freezes on trending classes: programmes "reserve the right to freeze or enforce strict
    payout caps for specific exploit chains or vulnerability types if the underlying root cause is
    already known and under active, comprehensive remediation." Check the recent security bulletins and
    the programme blog before committing a week to a class mid-remediation.
  5 Read the published threat model and non-bugs list: "Reports identifying issues already classified on
    this list will be closed as unactionable."
  ```
- **Proof:** A submission with a working PoC at first filing, and an SDK finding filed once against the
  SDK rather than N times against N apps.
- **Escalation:** Attach the two artefacts that earn the quality multiplier: a root-cause analysis naming
  the specific function and the missing check with the source line, and a proposed patch or effective
  mitigation plus a note on where the same pattern recurs. Google's Mobile VRP pays **1.5x** for both and
  **0.5x** by default for anything below Good Quality.
- **Ruled out when:** The programme has no duplicate policy published — then the general rule still
  applies: finish the PoC before filing.

### D27-070 · Signal-to-noise is a managed asset

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — but every P5 you file costs you future access |
| **Attacker** | n/a |
| **Applies to** | all bounty work, especially anyone running an automated or agent-driven pipeline |
| **Maps to** | Android & Google Devices Code of Conduct and SNR clause, quoted verbatim; Samsung's per-researcher submission limits and deprioritisation of "repeated or bulk submissions of substantially similar reports"; Google's April 2026 VRP statements about automated tooling |

- **Test:** The graveyard is not merely unpaid work — filing it damages future access. Treat submission
  validity as a resource you spend.
- **How:**
  ```text
  - "we actively monitor the Signal-to-Noise Ratio (SNR) of all participating researchers. Submitting
    frivolous 'shell' reports, submitting unverified, automated, or AI-generated 'hallucinated'
    findings, or repeatedly ignoring the Published Threat Models are considered violations of our Code
    of Conduct. Accounts demonstrating a low SNR will be subject to automated rate limiting … and may
    face permanent removal."
  - Never file unverified pipeline output. An agent's finding is a HYPOTHESIS LIST; dynamic confirmation
    is now the difference between a payout and a ban, not a nicety.
  - Reputation gates private-programme invitations, and private programmes are where duplicate rates are
    low.
  - Lead with the artefact — video, logcat, the exact code path with file:line. Machine-generated reports
    are long on prose and short on evidence; being obviously the opposite gets you read.
  - Volume is now anti-correlated with income. One confirmed, chained, well-evidenced finding beats
    twenty candidates.
  - Programmes are "prioritizing categories that remain more challenging for automated AI tooling".
    Shallow, greppable, fuzzer-reachable findings are both the most duplicated and the least rewarded.
  ```
- **Proof:** A submission history with a high validity ratio, and a pipeline whose output is gated by
  D27-022 before anything is filed.
- **Escalation:** The unescalatable observations still have a home — the client report's hardening
  appendix and the ruled-out register (D27-048). They are unpayable as bounties, not worthless as advice.
- **Ruled out when:** Never — this applies to every submission decision.

### D27-071 · The demotion-trap list — the claim/reality pairs triage resolves against you

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | each row names the P5/P4 node the claim actually lands on, and the node it could reach |
| **Attacker** | AM-03 / AM-12 depending on the row |
| **Applies to** | every draft, checked before the QA gate |
| **Maps to** | Bugcrowd VRT demotion pairs; HackerOne Core Ineligible Findings (19 May 2025); AOSP "no higher than Low" cap for unlocked-bootloader and Developer-Mode PoCs; HackerOne Core Clarifications on Availability |

- **Test:** Twenty-three claim/reality pairs account for nearly every unexplained downgrade. Check the
  draft against each; demote or delete anything matching a left-hand row unless the right-hand condition
  is demonstrated.
- **How:**
  ```text
  CLAIM AS WRITTEN                          LANDS AT                     REQUIRED TO SURVIVE
  "Insecure data storage", root-only read   ...on_internal_storage P5     name the unprivileged reader
  "No pinning" / "I bypassed pinning"       ssl_certificate_pinning P5    a request failing CA or hostname
                                                                          validation, scored AV:A/AC:L/PR:N/
                                                                          UI:N/S:U/C:H/I:H/A:N = High
  "Root/emulator/Frida detection bypass"    runtime_instrumentation P5    the server trusting the client verdict
  "App is not obfuscated"                   lack_of_obfuscation P5        what you extracted + a liveness proof
  "Missing PIE/RELRO/canary"                lack_of_exploit_mitigations P5 context inside a real memory-safety bug
  "allowBackup=true"                        auto_backup P5 (AV:P baseline) a live token pulled AND replayed
  "App crashes on a malformed intent"       app_crash|malformed P5        persistence across force-stop+reboot,
                                                                          or pivot to memory safety
  "Tapjacking is possible"                  tapjacking P5                 overlay a permission grant, an install
                                                                          confirmation or a transaction, + version
  "Clipboard can be read"                   clipboard_enabled P5          the copied value is an auth secret AND
                                                                          you state the foreground constraint
                                                                          yourself (background reads blocked API 29+)
  "Hardcoded API key found"                 intentionally_public P5       one authenticated response; then the split
                                                                          public asset P1 / internal P3 / billable P4
  "OAuth client_secret in the APK"          sensitive_data_hardcoded P5   a redirect-URI or state weakness ->
                                                                          oauth_misconfiguration|account_takeover P2
  "IDOR" with a UUID, no leak path          ...guid P4 + AC:H             produce the in-app leak path
  "IDOR" claimed Critical but read-only     ...view... P3                 the P1 node requires modify AND view
  "No rate limiting"                        ineligible / P4               carry it to OTP brute force -> ATO
  "Session persists after logout"           ...on_logout_server_side_only P5  prove the SERVER still honours it
  "Outdated library with CVE-XXXX"          outdated_software_version P5  trigger it in THIS app (reachability)
  "Self-XSS in the WebView"                 xss|stored|self P5            usable against a different account
  "Open redirect via deep link"             open_redirect|get_based P4    land in a WebView with a bridge, or
                                                                          steal an OAuth code
  "Screen caching / no FLAG_SECURE"         screen_caching_enabled P5     name who retrieves the thumbnail
  "Data deletion = availability impact"     rewritten vector              set A:N, raise Integrity instead
  "Physical access" findings                ineligible unless in scope    check the brief before investing
  "Unlocked bootloader / Developer Mode"    AOSP: no higher than Low      rebuild the PoC without them
  "Weak cipher / MD5 found"                 broken_cryptography P3 at best reach the call site with
                                                                          security-relevant data
  ```
  Anything demoted goes into the ruled-out register **with the reason** — which is worth more to a client
  than the finding would have been. Note also HackerOne's systemic-issue standard: multiple instances of
  the same class with the same fix are duplicates after the first three.
- **Proof:** A findings list where every entry survives its row, and a ruled-out register that visibly
  absorbed the rest.
- **Escalation:** Rows that fail only for want of one more test become blocked-register entries, not
  deletions — and the next engagement's scope.
- **Ruled out when:** The right-hand condition is demonstrated and attached. Then the claim is not a
  demotion trap, it is a finding at the node the condition unlocks.

### D27-072 · Re-test every fix, and file the bypass under a new ID

| | |
|---|---|
| **Severity ceiling** | **High** — bypasses are frequently more severe than the original, because the client now believes the surface is safe |
| **VRT** | the bypass's own node, rated on its own merits |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | every resolved report and every client retest |
| **Maps to** | H1 #1408692 bypassing #1142918 (Nextcloud, Low 2.3, $250); #479139 bypassing #447975 (New Relic, $500 after $750); #1377748 / #1362313 (Evernote); #377107 (ownCloud); #284346 "Download attachments with traversal path into any sdcard directory (**incomplete fix 106097**)"; NIST SP 800-115 §8.3 — verification requires "a **mirror copy of the original test**" |

- **Test:** Two of the better payouts in the disclosed corpus came from re-testing a patched report rather
  than finding something new. Diff the new APK, find the added check, and attack the check itself.
- **How:**
  ```bash
  apktool d old.apk -o old/ && apktool d new.apk -o new/
  diff -r old/smali new/smali | grep -A5 '^[<>].*\(startsWith\|contains\|equals\|check\|valid\)'
  ```
  Known-incomplete fix shapes from the corpus: `startsWith("/data/data/")` (bypass with `/data/user/0/`);
  a host allow-list with no scheme check (bypass with `javascript:`); a check on one `UriMatcher` branch
  only (bypass via a sibling branch); a fix on one screen while a second screen exposes the same value.
  The commercial retest procedure:
  ```text
  Scope      ONLY the findings in the original report, plus any finding whose fix touches a shared
             component (name them). New surfaces are a new engagement.
  Method     a MIRROR COPY of the original test — the same repro.sh, the same lab rebuilt from
             LAB-MANIFEST.txt, the same accounts. Diff the lab manifests and call out every delta,
             because a behaviour change may be the platform, not the fix.
  Baseline   re-run repro.sh against the ORIGINAL artefact FIRST, to prove the harness still reproduces
             the bug. Without this, a broken lab reads as "fixed". This is the step everybody skips and
             it is the only thing separating a retest from a guess.
  Artefact   the FIXED build, hashed into a new ARTEFACT-MANIFEST, with versionName/versionCode stated
  Verdicts   FIXED | PARTIALLY FIXED (state what remains) | NOT FIXED | MITIGATED (control elsewhere,
             tested) | RISK ACCEPTED (carry the signed row) | NOT RETESTABLE (state why — never silently
             "fixed")
  ```
  Verify against the build users actually get, not staging:
  ```bash
  adb shell pm path com.target.app | sed 's/package://' | while read p; do adb pull "$p" retest/store/; done
  shasum -a 256 retest/store/*.apk | tee retest/ARTEFACT-MANIFEST.txt
  adb uninstall com.target.app && adb install --bypass-low-target-sdk-block old-vulnerable.apk
  adb logcat -d | grep -iE 'force.?update|min.?version|unsupported.?version|upgrade required'
  ```
- **Proof:** Per finding: the baseline run against the old build (bug reproduces) and the run against the
  new build (bug does not), both in `retest/F-0NN/`. Plus either a forced-upgrade block on the old build,
  or the old build transacting normally — which is a finding in its own right, because a fix nobody
  installs is not remediation.
- **Escalation:** A bypass is a **new finding with a new ID**, cross-referenced to the original, not a
  reopened one — collapsing them into one history loses the second one's severity. Two consecutive
  incomplete fixes on the same root cause is an architectural finding about the validation approach; say
  so.
- **Ruled out when:** The fix holds against the original PoC **and** against the encoding, alternate
  component, alternate scheme and second-order variants. List the variants you tried.

### D27-073 · Finding-ID stability across draft, final and retest

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | corpus convention that refutations are recorded next to the findings they kill |

- **Test:** Renumbering between the draft, the final and the retest destroys the client's ability to track
  remediation and makes year-on-year comparison impossible.
- **How:**
  ```text
  Format  <ENGAGEMENT>-F-0NN      e.g. ACME-AND-2026Q3-F-007
  Rules   - allocated once, at Candidate stage; never reused and never renumbered
          - a WITHDRAWN finding keeps its id and appears in the ruled-out register with the reason
          - the retest reuses the original id; only genuinely new issues get new ids (D27-072)
          - the next engagement's scoping sheet references prior ids
  ```
- **Proof:** The same id appearing in the draft, the final, the tracker CSV, the evidence-tree path and
  the retest.
- **Escalation:** ID stability is the mechanism by which a withdrawn finding stays visible instead of
  vanishing (D27-062) — which is what makes a self-correcting report read as rigour.
- **Ruled out when:** Never.

### D27-074 · Meet the programme's mandatory submission format

| | |
|---|---|
| **Severity ceiling** | Support — some of it is machine-checked, and an incomplete template reduces the base reward outright |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | the named programmes; check every brief for an equivalent |
| **Maps to** | Google Mobile VRP "how to submit a complete bug report" and Good Quality criteria; Samsung "Report Quality" items 1–4 and `submission_template_v10.yaml`; PayPal "Bug Submission Requirements"; Xiaomi "General Assessment Rules"; Intigriti Triage Standards |

- **Test:** Confirm the report includes every field the vendor requires before sending. Some of it is
  checked mechanically and some of it gates a bonus.
- **How:**
  ```text
  Google     device model, Android version, build version, app version, step-by-step repro, PoC APK or
             the adb line, impact analysis — device/build IN TEXT, NOT A SCREENSHOT.
  Samsung    affected product version including build number, practical security impact, detailed repro,
             a working PoC, disclosure plans, AND a completed submission_template_v10.yaml. The Good
             Report Bonus (up to double the base reward for High/Critical) is unavailable without it and
             unavailable for wearable, PC, server-side or backend findings, or Low-rated ones.
  PayPal     register accounts as <username>+pp@wearehackerone.com, include your IP, send
             X-PP-BB: HackerOne-<username> on all traffic. To demonstrate root: cat /proc/1/maps (read),
             touch /root/<your H1 username> (write), id / hostname / pwd (execute).
  Xiaomi     manually reproduce anything found by a scanner; test SSRF via their sheriff service.
  Intigriti  "a written, step-by-step demonstration of an attack" and "the simplest possible
             demonstration that proves the vulnerability's exploitability and impact beyond reasonable
             doubt"; third-party vulnerabilities go to the vendor first.
  ```
- **Proof:** The completed template, headers or identifiers present in the submission before you click
  send.
- **Escalation:** Coordinated disclosure terms are part of the format: "Publicly disclosing a
  vulnerability before a patch is available, or without prior written agreement … will result in
  immediate disqualification from financial reward and potential removal from the program." Samsung
  assigns SVE/CVE credit "for Moderate and above security issues only".
- **Ruled out when:** The programme publishes no format requirements — then D27-005's template is the
  default and exceeds them.

### D27-075 · Shadow-API reporting — the version delta is not the finding, the weakened control is

| | |
|---|---|
| **Severity ceiling** | **Critical** where the old version bypasses auth entirely |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for an auth regression; `broken_access_control.idor.*` (P1–P3) for a field-exposure or object-authz regression; `server_security_misconfiguration.no_rate_limiting_on_form.*` (P4) for a throttling regression |
| **Attacker** | AM-01 (the old endpoint is reachable from anywhere) |
| **Applies to** | any versioned backend behind a mobile client |
| **Maps to** | the bug-hunting corpus's shadow-API material — "a mobile app whose hardcoded backend calls look older than the current web app's" is named there as the highest-value mobile-to-backend bridge |

- **Test:** A mobile app's hardcoded backend calls are frequently an **older API version** than the
  current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field
  exposure. Diff **behaviourally** across versions, not by response shape. **A version difference alone
  is Informational**; the weakened control is the finding.
- **How:** Enumerate, then diff four security-relevant behaviours for the **same operation**:
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
  ```text
  AUTH STRENGTH     does v1 accept no token / an expired token / a lower-privilege token that v2 rejects?
  RATE LIMITING     burst both; a missing 429 on v1 means throttling was never backported
  INPUT VALIDATION  the same injection or oversized payload to both
  FIELD EXPOSURE    does v1 return internal ids or PII that the current version redacts?
  ```
  Anything other than 404 or connection-refused means live. A static "this version is deprecated" 200 is
  not a finding — the underlying operation must actually execute.
- **Proof:** A security regression on the old path, demonstrated with the **same request** against both
  versions, side by side in the report. Run the layer-ordering check (D27-056) before claiming the auth
  regression.
- **Escalation:** Treat **every** APK-sourced endpoint as a version-diff candidate against the live web
  API (-> D01 inventory, -> D15 backend authz). The endpoint list comes from the APK; the finding lives
  on the server.
- **Ruled out when:** Every version answers identically on all four axes, or only the current version is
  live (everything else returns 404 or refuses the connection). Record the enumeration output and the
  four-axis table in the ruled-out register — that is a strong, citable negative for a class most
  engagements never test.

### D27-076 · Coverage attestation — state what was not tested, and why

| | |
|---|---|
| **Severity ceiling** | Support — but an unstated coverage gap is treated by several programmes as a deliverable defect |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | client engagements; optional for open bounty submissions |
| **Maps to** | NIST SP 800-115 §8.2 ("Because a report may have multiple audiences, multiple report formats may be required") and Appendix B §1.3 (Assumptions and Limitations); MASTG v2 coverage built from the repo front-matter rather than the withdrawn checklists |

- **Test:** Every engagement has features that could not be exercised — payments in production, KYC that
  consumes a real document, irreversible deletion, region-locked flows, a role you were not given. Naming
  them converts an invisible gap into a client decision.
- **How:**
  ```text
  | Feature             | Reached | Instrumented | Blocked by                    | Residual risk |
  | KYC document upload | partial | yes          | no sandbox applicant provided | HIGH — untested IDOR surface |
  | Account deletion    | no      | n/a          | irreversible on prod account  | HIGH |
  | Payments (live)     | no      | n/a          | no test PSP mode              | HIGH |
  | Region: IN wallet   | no      | n/a          | geo-gated build               | MEDIUM |
  ```
  For a standards-aligned engagement, build the MASTG coverage table from the authoritative source rather
  than promising a checklist that no longer exists:
  ```bash
  git clone --depth 1 https://github.com/OWASP/mastg.git
  for f in mastg/tests/android/*/*.md mastg/tests-beta/android/*/*.md; do
    printf '%s | %s | %s | %s\n' "$(basename "$f" .md)" "$(basename "$(dirname "$f")")" \
      "$(grep -m1 '^status:' "$f" | sed 's/^status: *//')" "$(grep -m1 '^title:' "$f" | sed 's/^title: *//')"
  done | sort > final/mastg-coverage.tsv
  ```
  The only defensible sentence is of this form: *"Assessed against N MASTG v2 Android tests in profiles
  L1+L2 (list attached); M tests were excluded as `status: placeholder` (no published procedure) and K as
  `status: deprecated`."*
- **Proof:** The coverage table with zero TODO rows, cross-referenced to the screens never reached and to
  the blocked register.
- **Escalation:** Each HIGH residual-risk row is the scoping ask for the next engagement: test accounts, a
  PSP sandbox, a staging KYC applicant, a driver or merchant role, a geo-unlocked build.
- **Ruled out when:** Everything in scope was exercised — then say that explicitly, with the register
  showing full coverage, rather than leaving the section out.

### D27-077 · Incidental third-party data — stop, notify, retain nothing

| | |
|---|---|
| **Severity ceiling** | Support (the procedure); the finding it evidences is frequently High or Critical |
| **VRT** | the authz node the mechanism supports — `broken_access_control.idor.*`, `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies, up to Critical) |
| **Attacker** | AM-05 |
| **Applies to** | every engagement touching production data |
| **Maps to** | NIST SP 800-115 §6.6 ("captured data may include sensitive data that does not belong to the organization—or personal employee data, which may create privacy concerns") and Appendix B §5.3 (Data Handling), §3.2 (Incident Handling and Response) |

- **Test:** Real users' data arrives unbidden — an IDOR returning a stranger's record, a misconfigured
  bucket, a support inbox, evidence of a prior intruder. This is the **opposite** of D27-035's rule:
  redaction must happen at capture, because retention itself is the harm.
- **How:**
  ```text
  1 STOP interacting with that object immediately. Do NOT iterate the identifier "to measure the impact".
  2 Prove the CLASS, not the CONTENT: one record, field NAMES and types only, values redacted at capture.
      {"id":<int>,"email":"<redacted>","dob":"<redacted>"}      not the values
  3 Do not download, store or transmit the data. If it is already in a proxy flow file, delete that flow
    and record that you did.
  4 Notify the incident point of contact within the Critical SLA; state exactly what was observed and
    what was retained — ideally nothing.
  5 Impact is then evidenced by the ENUMERABILITY of the identifier and the AUTHZ gap, not by a victim's
    record. In a client report that is STRONGER than a victim screenshot.
  6 Prior-intruder evidence is the client's incident, not your finding: stop, notify, hand over.
  ```
  Out-of-scope discovery follows the same shape: discovery is not authorisation. One unauthenticated
  request that establishes the host exists is the ceiling; record the leak as a finding in its own right,
  notify, and get any scope extension in writing as a dated amendment.
- **Proof:** A redacted-at-capture screenshot, a deleted-flow note, and the notification timestamp.
- **Escalation:** The finding remains High or Critical — it is evidenced by the authorisation mechanism
  and the identifier space (-> D15). If the exposed credential belongs to a **third party**, the same
  procedure applies to it.
- **Ruled out when:** Both accounts are tester-owned and separately registered. Then D27-036 governs and
  the data can be shown with the victim-side values masked.

### D27-078 · The critical-notification SLA

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | client engagements; the bounty equivalent is simply submitting immediately |
| **Maps to** | NIST SP 800-115 Appendix B §3.2 (Incident Handling and Response — halt criteria, the client's call tree, and a process for resuming testing) and §6 (interim report frequency); H1 #1667998, patched by the vendor within 24 hours of a well-formed report |

- **Test:** Holding a Critical found on day 3 until delivery on day 10 leaves the client exposed for a
  week and is indefensible if it is exploited in the interim. Write the SLA into the rules of engagement
  and honour it.
- **How:**
  ```text
  Critical (or any finding with live production impact on real users' data or funds):
    - notify the named security contact within 4 working hours, by the pre-agreed channel, not as an
      email attachment
    - interim one-pager: mechanism, minimal repro, immediate mitigation options, blast radius if known
    - agree IN WRITING whether testing of that surface CONTINUES or PAUSES — that decision is the
      client's, not yours; record who made it
    - reproduce the interim note verbatim in the final report, with its timestamp
  High:        notify within 1 working day
  Medium/Low:  batched to the final report
  Suspected live compromise or real user data observed: STOP that surface immediately (D27-077)
  ```
  A short daily note during the window costs five lines and prevents every delivery surprise: what was
  covered, what was found (under validation, **no severity assigned before the verification gate**), what
  is blocked, and what is next. A blocker repeated three days running gets escalated by the client
  themselves.
- **Proof:** The interim note with its timestamp, in the client's inbox on the right day and reproduced in
  the report.
- **Escalation:** A NOT FIXED or PARTIALLY FIXED retest verdict on a Critical re-triggers the SLA
  (D27-072).
- **Ruled out when:** Nothing Critical or High was found — then the daily note still goes out, saying so.

### D27-079 · Hard lines that hold under pressure

| | |
|---|---|
| **Severity ceiling** | Support — holding these is what keeps the whole report credible |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | corpus hard-lines list; NIST SP 800-115 §6.6 (Legal Considerations); the ownership boundary as stated in the corpus |

- **Test:** Four lines, each of which costs more to cross than any technical gap is worth. Say the
  boundary in one or two sentences, offer the legitimate route, and move on.
- **How:**
  ```text
  1 Do not extract data for accounts or numbers you cannot verify the operator owns — even when they
    insist. "Extract any person's info" is the hard line. Offer a controlled two-owned-account IDOR test
    instead.
  2 Do not replay a recovered session token against the vendor's production API, even for the operator's
    own account, unless the engagement authorises it. Prove account-takeover impact from the stolen
    file's own contents (identity + token) and from the app's auth-interceptor code.
  3 Do not fabricate evidence under deadline or payout pressure. The triager re-runs the PoC.
  4 Do not let money enter the triage thread before severity is agreed. Pressuring a triager for payment
    is the fastest way to lose a winnable report and gives them a clean non-technical reason to close it.

  And the standing limits, regardless of engagement type: never test accounts or data you do not own
  (use two tester-owned accounts for cross-account IDOR); no DoS; no automated scanners against
  production; minimise traffic; never exfiltrate a third party's data. Under operator pressure the line
  is OWNERSHIP, not sensitivity — on the operator's own account, device and data, extract fully and show
  fully, because under-proving is what gets reports closed.
  ```
  Engagement-type calibration, decided before any tooling: bug bounty = impact-demonstrated bugs only;
  external red team = hygiene, recon, IoCs and defensive observations are all deliverables; signed
  pentest = per the statement of work; internal audit = compliance-mapped findings. When the brief is
  mixed — and clients routinely write assessment-shaped statements of work and call them red team —
  **default to bug-bounty discipline**, the strictest; you can relax later, whereas the reverse gets
  findings retracted at delivery.
- **Proof:** N/A — this is a rule. The observable is a report with nothing in it you would not defend in
  writing a year later.
- **Escalation:** Where a line blocks a proof you need, ask for what would unblock it (an OTP, a second
  test account, a sandbox card the operator owns). **Blocking on politeness is worse than asking.**
- **Ruled out when:** Never.

## Graveyard for this domain

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

## Cross-surface joins

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

## Sources

- **Bugcrowd Vulnerability Rating Taxonomy**, release `2026-07-08` (581 entries), parsed directly from
  `vulnerability-rating-taxonomy.json` and its `mappings/cvss_v3/cvss_v3.json` and CWE mappings; mirrored
  locally at `data/bugcrowd-vrt-full.csv`. Every VRT path and priority quoted in this chapter came from
  that file.
- **HackerOne**: Platform Standards (IDOR attack complexity, PII handling, AITM, leaked credentials, the
  bug-chain rule), Core Ineligible Findings (19 May 2025), Core Clarifications (the Availability/deletion
  rule), the systemic-issue standard, and the custom CVSS 3.0 implementation with ×0.0/×0.5/×1.0/×1.5
  environmental modifiers.
- **Disclosed HackerOne reports** used as the price list and the wording corpus: #1225158, #288955,
  #3399016, #3829030, #1667998, #1372667, #855618, #205000, #637194, #859469, #3648638, #202425,
  #1343300, #1241116, #1408692/#1142918, #479139/#447975, #1377748/#1362313, #377107, #284346/#106097,
  #242727, #291764, #1650264, #2553411, #1737358, #906433, #563870.
- **Intigriti** Triage Standards (in effect 6 January 2025): PoC assessment versus vulnerability-type
  assessment, the unused-code rule, third-party reporting. **YesWeHack** programme non-qualifying lists.
- **Google**: Mobile VRP report-quality criteria, the four attack-scenario columns, the High/Low Impact
  Data definitions, the SDK duplicate rule and the 0.5x/1.5x quality multipliers; Android & Google
  Devices "How We Handle Duplicate Reports", "Reward Adjustments for Known and Trending Issues", "Code of
  Conduct and Account Reputation (SNR)", "Published Threat Models and Non-Bugs", and the AOSP severity
  table at `source.android.com/docs/security/overview/updates-resources`; the Android app
  vulnerability-classes CWE set. **The reward figures in the corpus disagree between sources and are not
  quoted here — re-read the live rules page before scoping, and never quote a figure to a triager.**
- **Samsung** Mobile Security Risk Classification (last updated 8 September 2026), downgrade factors,
  `submission_template_v10.yaml` and the Good Report Bonus; **Xiaomi** General Assessment Rules and
  severity bands; **PayPal** bug-submission requirements.
- **OWASP MAS**: MASVS v2 (24 controls, verbatim from the `masvs` repo `controls/`), MAS Testing Profiles
  (L1/L2/R/P, NIST OSCAL-aligned), MASTG v2 test structure and front-matter (`id`, `platform`, `type`,
  `maswe`, `profiles`, `status`, `covered_by`), the documented false-positive classes, the informational
  test list, and the checklist-removal notice `mas.owasp.org/news/2026/07/14/checklists-removal/`; MASWE
  impact vocabulary and `cwe:` front-matter mappings.
- **MITRE ATT&CK Mobile**: the twelve tactic IDs, verified on `attack.mitre.org/tactics/mobile/`, and the
  malware-side technique list that is out of scope for a client-app assessment.
- **MobileHackingLab**: the shipped PoC video assets and their metadata, the four-beat differential, the
  crash-triage pipeline (674 crashes → 12 unique root causes), the tombstone exemplar, the UBSan
  re-rating, the one-shot `exploit.sh` pattern, and the negative-control examples from CVE-2026-28576,
  CVE-2026-0047, CVE-2026-0049, CVE-2026-0006, CVE-2025-48595, CVE-2025-5915, CVE-2026-65346.
- **The senior-researcher local corpus**: the per-finding template, the living `report.md` with
  Confirmed/Candidate/Ruled-out sections, the evidence tree, the four-beat differential PoC,
  root-for-evidence, the `screenrecord` and side-by-side conventions, the redact-in-the-rendering rule,
  the triage ladder, the eight-step pushback playbook, the five-way false-positive taxonomy, the
  never-report emulator artefacts, the ownership line, and the graveyard of classes that do not pay.
- **A 4,467-star bug-hunting corpus**: the 7-question gate, the pre-severity gate against the Critical
  claim, Marker Discipline, the Body-Diff Rule, the Statistical-Sample Rule, Server-Policy-vs-State, the
  Layer-Ordering Trap, the Shell-Loop Ban, the Multi-Tool Reproduction Bar, retraction discipline and its
  client-patched exception, the five-screenshot state-change pattern, the cookie-redaction protocol and
  PII split, the Bugcrowd severity-request and OOS-rebuttal templates, chain-filing order, the
  never-submit list, and the shadow-API behavioural-diff method.
- **HackTricks and community checklists** for the shell-UID-versus-app-UID rule, the baseline-denial
  pattern, the delivery-path proof for media findings, and the drozer/objection module semantics
  (including each scanner's documented blind spot).
- **NIST SP 800-115** §6.6, §8.1, §8.2, §8.3 and Appendix B §1.3, §3.1, §3.2, §4, §5.3, §6 for the
  reporting, mitigation-recommendation, retest ("mirror copy of the original test"), incident-handling
  and data-handling requirements.
- **FIRST CVSS v3.1 and v4.0** specifications for the metric groups, the band boundaries and the
  base/threat/environmental/supplemental split.
