# Severity & Reportability Doctrine

> **Read this before you test anything.** It decides what you are allowed to call a finding, and it is the
> single biggest difference between a report that pays and a report that is closed as informative.
>
> Ground truth used here: Bugcrowd VRT release **2026-07-08** (581 entries, mirrored in
> [`data/bugcrowd-vrt-full.csv`](../data/bugcrowd-vrt-full.csv)).

---

## 1. The rule this company works to

We report only findings that land at **Low, Medium, High or Critical**. We do not submit informational
findings. That is not a style preference — it is a business rule. Informational submissions cost the
client's triage budget, cost our reputation with the program, and cost the tester a day.

Bugcrowd's priority scale maps to that language as:

| VRT priority | Severity | We submit? |
|---|---|---|
| P1 | Critical | Yes |
| P2 | High | Yes |
| P3 | Medium | Yes |
| P4 | Low | Yes |
| P5 | Informational | **No** — unless it is a step in a chain that reaches P4 or better |
| null | **Varies** — rated on demonstrated impact | Yes, once you have demonstrated the impact |

A `null` priority is not "unrated". It means the taxonomy refuses to rate it without context, and the
context is **your evidence**. IDOR is the worked example Bugcrowd itself gives: the same class runs from
P4 to P1 depending entirely on what the tester proved.

---

## 2. The uncomfortable fact about Android findings

Pull the mobile branch of the VRT and read the priorities. Every single leaf is **P5**:

| VRT path | Priority |
|---|---|
| `mobile_security_misconfiguration.ssl_certificate_pinning.absent` | P5 |
| `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` | P5 |
| `mobile_security_misconfiguration.auto_backup_allowed_by_default` | P5 |
| `mobile_security_misconfiguration.clipboard_enabled` | P5 |
| `mobile_security_misconfiguration.tapjacking` | P5 |
| `lack_of_binary_hardening.lack_of_jailbreak_detection` | P5 |
| `lack_of_binary_hardening.lack_of_exploit_mitigations` | P5 |
| `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` | P5 |
| `insecure_data_storage.screen_caching_enabled` | P5 |
| `insecure_data_storage.non_sensitive_application_data_stored_unencrypted` | P5 |

Read that last group again. **Sensitive application data stored unencrypted on internal storage is P5.**
The single most common "finding" in commercial Android reports is rated informational by the taxonomy,
because internal storage is already protected by the UID sandbox — an attacker who can read it has
already won by some other means.

So the entire "run MobSF, paste the red rows" methodology produces a report of P5s. That is why clients
churn vendors, and it is the gap this checklist exists to close.

### 2.1 The one Android-native category that is not pinned to P5

| VRT path | Priority |
|---|---|
| `broken_access_control.exposed_sensitive_android_intent` | **null — varies** |

That is the door. An exported Android component is rated on **what it exposes**, not on the fact that it
is exported. The export is the vector. The rating comes from the impact.

---

## 3. The doctrine: re-categorise out of the mobile tree

> **An Android finding is worth money only when you can move it out of the mobile branch of the taxonomy
> and into the access-control, authentication, injection or data-exposure branches.**

These are the categories a mobile engagement can actually reach at P1 and P2:

| VRT path | Priority | How a mobile finding gets there |
|---|---|---|
| `server_side_injection.remote_code_execution_rce` | **P1** | WebView bridge to command execution; dynamic code load from an attacker-writable path; deserialization with a controlled ClassLoader |
| `server_side_injection.sql_injection` | **P1** | Exported ContentProvider with concatenated selection reaching the backing DB, or an app API endpoint |
| `server_side_injection.file_inclusion.local` | **P1** | `openFile()` path traversal in a provider; over-broad FileProvider root |
| `server_side_injection.xml_external_entity_injection_xxe` | **P1** | App-side XML parser fed from an exported component or API response |
| `broken_authentication_and_session_management.authentication_bypass` | **P1** | Deep-link/OAuth code interception; exported activity reaching a post-auth screen; biometric gate not bound to a Keystore key |
| `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` | **P1** | Cross-account read+write on the mobile API with two tester-owned accounts |
| `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` | **P1** | A key extracted from the APK that is **verified unrestricted** against a live, public asset |
| `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` | **P2** | Cross-account write only |
| `cryptographic_weakness.key_reuse.inter_environment` | **P2** | The same app key trusted across prod and non-prod |
| `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` | **P3** | Cross-account read only |
| `broken_authentication_and_session_management.two_fa_bypass` | **P3** | OTP/2FA step skippable through a mobile-only endpoint or an exported screen |
| `broken_access_control.idor.modify_view_sensitive_information_guid` | **P4** | Same as above but the identifier is a GUID, so it must be leaked first |

**The practical consequence for every tester on this team:** when you find an exported component, a leaked
token or a bridge, you are not finished. You are holding a *primitive*. The report is written when that
primitive has been driven into one of the rows above, and the title of your report should name **the row**,
not the Android mechanism.

Write `Account takeover via OAuth code interception in the exported callback activity`.
Do not write `Activity is exported`.

---

## 4. The graveyard — do not submit these standalone

Each of these is a real observation. None of them is a finding on its own. Record them in the
[ruled-out table](../templates/ruled-out-table.md) as coverage evidence, and move on.

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| Certificate pinning absent or bypassable | P5. Pinning is anti-analysis, not a user-facing control. TLS still protects the user. | Nothing on its own. Use the MitM you gained to find the API bug — *that* is the report. |
| Root / emulator / Frida detection bypassed | P5. Most such SDKs only report signals to a backend; that is telemetry, not a control. | Prove the bypass defeats a control that actually gates money, DRM or anti-fraud. |
| App is not obfuscated / ProGuard missing | P5. Obfuscation is not a security boundary. | Nothing. |
| `allowBackup="true"` | P5 by default. | Prove a *session token or credential* is in the backup set **and** that the restore guard fails on a foreign device. Then it is authentication. |
| Sensitive data in `shared_prefs` on internal storage | P5. The UID sandbox already protects it. | Prove a **zero-permission app** can reach it — via a provider grant, a traversal, or a backup. The finding is then the reach primitive, not the storage. |
| Hardcoded API key in the APK | P5 if intentionally public. Most Google/Maps/Firebase keys are package+signature restricted. | **Verify the restriction with one benign request.** If unrestricted against a public asset, it is P1. If restricted, it is not a finding. Never report an unverified key. |
| Exported activity / service / receiver | Not a finding. It is an inventory item. | Reach a non-exported component, a privileged action, or user data through it. |
| Tapjacking / overlay | P5, and largely mitigated on modern `targetSdk`. | Demonstrate a complete credential-capture or transaction-authorisation flow on the target's actual `targetSdk`. |
| App is debuggable | Only a finding on a **release** build from the store. On a debug build it is the expected state. | Confirm the binary came from the production track. |
| Logcat contains data | P5 since API 30 removed cross-app log reads. | Prove the logged value is sensitive **and** reachable — for example written to a world-readable file, or read by a co-installed SDK. |
| Missing binary hardening (PIE, canaries, RELRO) | P5. | Only relevant as a multiplier on an actual memory-corruption finding. |
| Screenshot / Recents caching | P5. | Requires physical device access, which most programs exclude. |
| Crash from a malformed Intent | P5 (`application_level_denial_of_service_dos.app_crash.malformed_android_intents`). | Only if it becomes memory corruption with a demonstrated primitive. |

---

## 5. Preconditions decide the rating — state yours exactly

Triagers downgrade for vagueness. The precondition ladder, best to worst:

1. **Remote, no interaction** — the victim does nothing.
2. **Remote, one click** — victim taps a link. *This is the sweet spot for deep-link and WebView chains.*
3. **Local, zero-permission app** — any app the victim installs, requesting nothing. *The Oversecured model.*
4. **Local, app holding one common permission** — weaker, still accepted.
5. **Physical access to an unlocked device** — usually out of scope.
6. **Rooted device / attacker's own device** — almost always out of scope, because the attacker is
   attacking themselves.

Write the precondition as a sentence in the report, not as an implication. "Any app installed on the
device, declaring no permissions, can do X" is worth several rating steps over "an attacker can do X".

**The rooted-device trap.** If your PoC needs root to demonstrate, you have usually proved nothing about a
real attacker. Root is legitimate as an *evidence tool* — to show that the token you stole over IPC is the
same token in the app's sandbox. It is not legitimate as an *attack precondition*. Say which one you are
doing.

---

## 6. Honest severity, and the two-verified-links rule

> Two verified links plus one unproven link is a **Medium with a stated precondition**, not a Critical.

Severity comes from **demonstrated** capability. Never from "could theoretically". When a link in the
chain is unproven, you have three options, in order of preference:

1. Go and prove it.
2. Report at the severity the proven part supports, and name the missing link explicitly.
3. Do not report.

Inflating severity is the fastest way to lose a program. Naming your own missing link, by contrast, is
what makes triagers trust the rest of the report.

---

## 7. CVSS on mobile

Programs that want CVSS v3.1/v4.0 usually mis-rate mobile because the vector was designed for servers.
Conventions this team uses:

- A **zero-permission local app** is `AV:L` with `PR:N` and `UI:N`. It is local *access*, but it needs no
  privilege and no user interaction beyond installing an unrelated app.
- A **deep link the victim clicks** is `AV:N` with `UI:R`.
- **Scope changed (`S:C`)** applies when you cross the UID sandbox — reaching another app's data, or the
  victim's server-side account, from your own app's context. Mobile reports routinely under-claim this.
- Attach the vector string, but lead with the sentence-form impact. Triagers read the sentence.

---

## 8. Before you submit — the checklist

- [ ] The title names the **impact category**, not the Android mechanism.
- [ ] The finding maps to a VRT path that is **not** P5, or is a `null`/varies path with impact proven.
- [ ] The precondition is a sentence and is as weak as you can honestly make it.
- [ ] Every link in the chain is either demonstrated on device, or explicitly named as unproven.
- [ ] There is a negative control in the same evidence take (see
      [PoC standard](04-poc-and-evidence-standard.md)).
- [ ] Any extracted secret has had its restriction **verified**, with the probe recorded.
- [ ] Emulator artefacts are excluded — see §9.
- [ ] You have re-read the program's exclusions and confirmed the class is in scope.

---

## 9. Emulator artefacts that must never be reported

These present as findings and are environment properties. Reporting one discredits the whole submission.

- `KeyInfo.isInsideSecureHardware() == false` / `securityLevel == 0` — an emulator property. Physical
  devices report TrustedEnvironment.
- A Keystore key with `setUserAuthenticationRequired(true)` failing to generate — that requires a secure
  lockscreen. On a fresh emulator with no PIN, failure is expected.
- "Production build is rootable" — `user`-build Play images are not. If yours is rooted, it is not a
  production image.
- A TLS handshake failing for *every* host after a system-CA install is almost never pinning. It is
  usually the zygote mount-namespace step being skipped, or the API 34+ Conscrypt APEX trust-store move.
  Confirm pinning by finding `<pin-set>` or `CertificatePinner` **in the app**, never by whether MitM
  happened to fail. See [lab setup](03-lab-and-harness.md).

---

## 10. Related

- [Attacker models](05-attacker-models.md) — pick the weakest attacker that still works.
- [PoC & evidence standard](04-poc-and-evidence-standard.md) — what proves a chain.
- [Triage response playbook](06-triage-playbook.md) — what to send when they push back.
- [`data/bugcrowd-vrt-full.csv`](../data/bugcrowd-vrt-full.csv) — the full taxonomy with priorities.
