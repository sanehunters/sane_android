# CHECKLIST.md — domain index

> 2161 test items across 28 domains, generated from `checklist/` (source digest `b82eae24e57d`). Per-domain cards: [`cards/`](cards/) · per-item lookup: `python3 scripts/item.py Dnn-NNN` · machine view: [`json/`](json/) · tracker: [`checklist.csv`](checklist.csv) · grep view: [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)

| Domain | Phase | Items | Ceiling mix | Card | Chapter |
|---|---|---|---|---|---|
| **D01** Recon & Attack-Surface Mapping | P3 | 84 | 🟥8 🟧22 🟨19 🟩3 ⬜32 | [card](cards/D01.md) | [`D01-recon-and-surface-mapping.md`](checklist/D01-recon-and-surface-mapping.md) |
| **D02** APK/AAB Structure, Signing & Build Integrity | P2 | 73 | 🟥11 🟧31 🟨4 🟩5 ⬜22 | [card](cards/D02.md) | [`D02-apk-structure-signing.md`](checklist/D02-apk-structure-signing.md) |
| **D03** AndroidManifest & Permission Model | P3 | 79 | 🟥23 🟧43 🟨4 ⬜9 | [card](cards/D03.md) | [`D03-manifest-and-permissions.md`](checklist/D03-manifest-and-permissions.md) |
| **D04** Exported Activities, Task & UI-Redress Attacks | P5 | 73 | 🟥4 🟧24 🟨24 🟩6 ⬜15 | [card](cards/D04.md) | [`D04-exported-activities-and-task.md`](checklist/D04-exported-activities-and-task.md) |
| **D05** Broadcast Receivers & Implicit Intents | P5 | 66 | 🟥11 🟧32 🟨8 🟩1 ⬜14 | [card](cards/D05.md) | [`D05-receivers-and-implicit-intents.md`](checklist/D05-receivers-and-implicit-intents.md) |
| **D06** Services, AIDL & Bound IPC | P5 | 87 | 🟥22 🟧38 🟨11 ⬜16 | [card](cards/D06.md) | [`D06-services-aidl-bound-ipc.md`](checklist/D06-services-aidl-bound-ipc.md) |
| **D07** ContentProviders & FileProvider | P5 | 80 | 🟥24 🟧31 🟨1 🟩1 ⬜23 | [card](cards/D07.md) | [`D07-contentproviders-and-fileprovider.md`](checklist/D07-contentproviders-and-fileprovider.md) |
| **D08** Intent Redirection, PendingIntent & URI Grants | P5 | 70 | 🟥20 🟧31 🟨6 ⬜13 | [card](cards/D08.md) | [`D08-intent-redirection-and-pendingintent.md`](checklist/D08-intent-redirection-and-pendingintent.md) |
| **D09** Deep Links, App Links & Custom URI Schemes | P5 | 87 | 🟥23 🟧36 🟨9 🟩1 ⬜18 | [card](cards/D09.md) | [`D09-deeplinks-and-applinks.md`](checklist/D09-deeplinks-and-applinks.md) |
| **D10** WebView & JavaScript Bridges | P5 | 77 | 🟥30 🟧36 🟨5 🟩1 ⬜5 | [card](cards/D10.md) | [`D10-webview-and-js-bridges.md`](checklist/D10-webview-and-js-bridges.md) |
| **D11** Local Data Storage | P4 | 76 | 🟥18 🟧35 🟨7 🟩2 ⬜14 | [card](cards/D11.md) | [`D11-local-data-storage.md`](checklist/D11-local-data-storage.md) |
| **D12** Cryptography & Key Management | P4 | 84 | 🟥19 🟧40 🟨14 🟩2 ⬜9 | [card](cards/D12.md) | [`D12-crypto-and-key-management.md`](checklist/D12-crypto-and-key-management.md) |
| **D13** Authentication, Session, OTP & Biometrics | P6 | 95 | 🟥52 🟧31 🟨2 ⬜10 | [card](cards/D13.md) | [`D13-auth-session-otp-biometrics.md`](checklist/D13-auth-session-otp-biometrics.md) |
| **D14** Network Security, TLS & Certificate Pinning | P6 | 63 | 🟥15 🟧16 🟨15 🟩4 ⬜13 | [card](cards/D14.md) | [`D14-network-tls-pinning.md`](checklist/D14-network-tls-pinning.md) |
| **D15** Backend API, IDOR/BOLA, Mass Assignment & Business Logic | P6 | 97 | 🟥61 🟧14 🟨1 🟩1 ⬜20 | [card](cards/D15.md) | [`D15-backend-api-and-authz.md`](checklist/D15-backend-api-and-authz.md) |
| **D16** Native Code, JNI & Memory Safety | P4 | 65 | 🟥24 🟧4 🟨6 🟩9 ⬜22 | [card](cards/D16.md) | [`D16-native-code-and-memory.md`](checklist/D16-native-code-and-memory.md) |
| **D17** Dynamic Code Loading, Deserialization & Supply Chain | P4 | 86 | 🟥49 🟧14 🟨6 🟩2 ⬜12 🔷3 | [card](cards/D17.md) | [`D17-dynamic-loading-and-supplychain.md`](checklist/D17-dynamic-loading-and-supplychain.md) |
| **D18** Cloud Backend & Third-Party SDK Configuration | P6 | 77 | 🟥40 🟧21 🟨4 🟩2 ⬜10 | [card](cards/D18.md) | [`D18-cloud-and-sdk-config.md`](checklist/D18-cloud-and-sdk-config.md) |
| **D19** Cross-Platform Frameworks | P4 | 84 | 🟥40 🟧14 🟨6 🟩1 ⬜23 | [card](cards/D19.md) | [`D19-cross-platform-frameworks.md`](checklist/D19-cross-platform-frameworks.md) |
| **D20** Privacy, PII, Logging & Data Leakage | P4 | 74 | 🟥6 🟧35 🟨16 🟩3 ⬜14 | [card](cards/D20.md) | [`D20-privacy-and-data-leakage.md`](checklist/D20-privacy-and-data-leakage.md) |
| **D21** Anti-Tampering, RASP, Root/Emulator Detection & Resilience | P4 | 63 | 🟥12 🟧26 🟨6 🟩2 ⬜17 | [card](cards/D21.md) | [`D21-resilience-and-rasp.md`](checklist/D21-resilience-and-rasp.md) |
| **D22** Platform & OS Version-Specific Behaviour | P4 | 86 | 🟥8 🟧38 🟨19 🟩1 ⬜20 | [card](cards/D22.md) | [`D22-platform-version-behaviour.md`](checklist/D22-platform-version-behaviour.md) |
| **D23** Payments, Entitlements, Subscriptions & Fraud | P6 | 74 | 🟥33 🟧32 🟨1 ⬜8 | [card](cards/D23.md) | [`D23-payments-and-entitlements.md`](checklist/D23-payments-and-entitlements.md) |
| **D24** Push, Notifications & Messaging | P6 | 52 | 🟥11 🟧20 🟨11 ⬜10 | [card](cards/D24.md) | [`D24-push-notifications-messaging.md`](checklist/D24-push-notifications-messaging.md) |
| **D25** Device, OEM, Firmware & Privileged Surfaces | P5 | 84 | 🟥27 🟧29 🟨2 ⬜26 | [card](cards/D25.md) | [`D25-device-oem-and-privileged.md`](checklist/D25-device-oem-and-privileged.md) |
| **D26** Runtime Instrumentation, Tooling & Harness | P1 | 85 | 🟥3 🟧7 🟨7 ⬜68 | [card](cards/D26.md) | [`D26-instrumentation-and-tooling.md`](checklist/D26-instrumentation-and-tooling.md) |
| **D27** Reporting, Severity Rating & Evidence | P9 | 83 | 🟥2 🟧2 ⬜79 | [card](cards/D27.md) | [`D27-reporting-and-evidence.md`](checklist/D27-reporting-and-evidence.md) |
| **D28** AI/LLM Features in Apps | P4 | 57 | 🟥17 🟧16 🟨15 ⬜9 | [card](cards/D28.md) | [`D28-ai-llm-features.md`](checklist/D28-ai-llm-features.md) |

**Total: 2161 items** — 🟥 613 critical · 🟧 718 high · 🟨 229 medium · 🟩 47 low · ⬜ 551 support · 🔷 3 varies

## The crux question for each domain

The single question that decides whether a domain has a bug in this app. Ask it before running anything.

- **D01** — **Am I analysing the bytes that are actually executing on a current device, in the runtime that actually holds the logic — and for every host, route and component I recovered from those bytes, can I name which attacker model reaches it and which version of the backend answers?**
- **D02** — Does any security decision anywhere — this app's own self-check, a sibling app's signature-level permission, an in-app updater's verifier, or the backend — actually depend on this APK's signing identity or its unmodified bytes, because if nothing does, the only payable thing left in the package is a live secret.
- **D03** — **Is there any component whose only access control is a permission string that a zero-permission app can obtain — by declaring it, by defining it first, or because nobody ever defined it — and if the string does hold, does the code behind it interrogate the *caller* rather than itself?**
- **D04** — **Is there any screen in this app whose security depends on the user having arrived from the previous screen — and can I start it directly, from a package that holds no permissions, with the arguments of my choice?**
- **D05** — Does any broadcast this app sends or receives carry, or act on, a value that decides authentication, entitlement, or where the app sends its data — and can an app that declares no permissions supply or read that value?
- **D06** — **For every method behind this app's exported binder: does it check *who* is calling — on the thread the transaction actually arrives on — or does it only validate *what* is being asked?**
- **D07** — **Does any caller outside this app's UID reach a provider method that either resolves a caller-controlled string into a filesystem path or concatenates a caller-controlled string into SQL — and if the answer is no, can the app itself be made to call that method on the attacker's behalf?**
- **D08** — **Does any attacker-reachable entry point in this app hand a `Intent`, `Uri`, `Bundle` or `PendingIntent` that the attacker fully or partially controls to a framework call that executes with the app's own UID — and if so, which non-exported component, private provider URI or held runtime permission does that reach that the attacker cannot reach directly?**
- **D09** — **Does any URI an attacker can put in front of the victim — a web link, a QR code, a push payload, another app's intent — reach a parser inside this app that hands attacker-controlled bytes to a sink that runs with the user's session, and is the entry point ownership-verified on the device or merely claimed in the manifest?**
- **D10** — **Can attacker-influenced content — a deep-link `url=`, an open redirect on the allowed origin, a third-party iframe, a MitM'd subresource, a stored profile field, a malicious `content://` — end up executing JavaScript inside a WebView that also carries a JS bridge, the app's session cookies, file/content access, or a real web origin; and if so, what is the single most sensitive thing that reachable context can read or do?**
- **D11** — **For each sensitive value the app persists: which principal other than the app's own UID can read it, or write it, without root — and if the answer is "none", is there any value in the backup set that the app trusts on next launch?**
- **D12** — **Is there a key, nonce, salt or signature that some component still trusts, which I can reproduce either from the public APK or from code running in the app's own UID — and what does the server do when I use it?**
- **D13** — **Does anything the server checks actually depend on the user having authenticated — or is every gate in this app a boolean the client computes, a header the client echoes, and a token the client can hand to `curl`?**
- **D14** — **Is there any request on this app's wire that an attacker holding no trusted CA can read or rewrite — and does that request carry an authentication assertion, PII, or content the app will execute?** If the answer needs your CA installed to be true, you have a P5 pinning observation, not a finding.
- **D15** — **For every object identifier and every security-relevant field the client is capable of sending, does the server re-derive the answer from its own state — or does it trust the identifier, the field, the version, the header or the client's arithmetic?**
- **D16** — **Which bytes that an attacker fully controls reach C/C++ inside this app's process, by what path they get there, and does the code that consumes them compute a size, an index or a lifetime from those same bytes without checking it?**
- **D17** — **Does any byte this app executes arrive after the APK was signed — and if so, what cryptographic check stands between the attacker-influenceable source of those bytes and the `ClassLoader`/`dlopen`/JS-engine call that runs them?**
- **D18** — For every backend identity the package contains — project id, bucket, identity-pool id, anon key, vendor API key — does it still do anything when it is used from a host that is not the app, by an identity that is not a legitimate user?
- **D19** — **Which artefact in this package actually holds the app's logic, and once I have opened it, does it hand me a credential that authenticates, an endpoint the UI never calls, a bridge that reaches native capability, or a code channel that can replace the app after the store review?**
- **D20** — **For each sensitive value the app handles: which principal other than the app and its own backend ends up holding that value — a co-resident app with one user grant, a third-party host, the lock screen, another signed-in user — and if none does, is any value the app emits an authenticator?**
- **D21** — **Does any decision that matters get made off this device on the strength of something this device claimed — and if so, is that claim an opaque, server-verified, freshly-bound attestation, or a boolean the client chose?** If the honest answer is "the check only stops the device's own owner from seeing their own data", you have a P5 hardening observation, and the correct output is a ruled-out entry, not a report.
- **D22** — **For every candidate finding in this engagement: at which `minSdkVersion`, `targetSdkVersion` and device API level is it actually reachable — and has this app explicitly opted out of the platform hardening that would otherwise close it?**
- **D23** — **Does any monetary or entitlement decision in this app get made anywhere other than the vendor's own server — and where the server does decide, does it independently re-derive the amount, the payer identity and the uniqueness of the receipt, or does it echo what the client sent?**
- **D24** — Can a party who is not the victim — a second account, an unauthenticated request, a leaked send credential, or an app with notification access — cause content to be delivered to, rendered by, or acted upon in the victim's client, and does the client or backend treat that content as more trusted than the party who supplied it?
- **D25** — **Is the device, the OEM image, or a preinstalled build of this app in scope — and if only the app is, which of its own manifest-declared physical, companion and cross-user surfaces hands an attacker a channel that the phone UI and the lock screen never gate?**
- **D26** — **Before I write "not vulnerable" anywhere in this report: has this exact instrument produced a positive result on this exact device in this session — and if the answer is "the tool printed nothing", what is my positive control?**
- **D27** — **For this finding, what is the cheapest attacker position from which I have actually observed the boundary being crossed — and does the title, the VRT node, the CVSS vector and the recorded evidence all say exactly that, with the unproven link named rather than hidden?**
- **D28** — Does any text, image, file or screen the model reads come from someone other than the user — and does anything the model says afterwards get rendered, opened, executed, sent, stored, retrieved for another account or billed without a human confirming it?

## Phase → domains

| Phase | Domains |
|---|---|
| P1 | D26 |
| P2 | D02 |
| P3 | D01 D03 |
| P4 | D11 D12 D16 D17 D19 D20 D21 D22 D28 |
| P5 | D04 D05 D06 D07 D08 D09 D10 D25 |
| P6 | D13 D14 D15 D18 D23 D24 |
| P9 | D27 |

## Related

| | |
|---|---|
| [`START.md`](START.md) | The operator entry point and state machine |
| [`ISSUES.md`](ISSUES.md) | How the GitHub tracker mirrors these files |
| [`AGENTS.md`](AGENTS.md) | The SOP |
| [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md) | Breadth before depth |
| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding |
