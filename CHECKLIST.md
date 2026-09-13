# CHECKLIST.md — domain index

> 837 test items across 14 domains. The merged single-file view is
> [**MASTER-CHECKLIST.md**](MASTER-CHECKLIST.md); the machine-readable tracker is
> [`checklist.csv`](checklist.csv).

| Domain | Phase | Items | Ceiling mix | Chapter |
|---|---|---|---|---|
| **D01** Recon & Attack-Surface Mapping | P3 | 46 | 🟥4 🟧10 🟨12 🟩3 ⬜17 | [`D01-recon-and-surface-mapping.md`](checklist/D01-recon-and-surface-mapping.md) |
| **D02** APK/AAB Structure, Signing & Build Integrity | P2 | 72 | 🟥6 🟧8 🟨1 🟩1 ⬜56 | [`D02-apk-structure-signing.md`](checklist/D02-apk-structure-signing.md) |
| **D03** AndroidManifest & Permission Model | P3 | 76 | ⬜76 | [`D03-manifest-and-permissions.md`](checklist/D03-manifest-and-permissions.md) |
| **D04** Exported Activities, Task & UI-Redress Attacks | P5 | 72 | 🟥4 🟧24 🟨23 🟩6 ⬜15 | [`D04-exported-activities-and-task.md`](checklist/D04-exported-activities-and-task.md) |
| **D05** Broadcast Receivers & Implicit Intents | P5 | 64 | 🟥7 🟧28 🟨8 🟩1 ⬜20 | [`D05-receivers-and-implicit-intents.md`](checklist/D05-receivers-and-implicit-intents.md) |
| **D06** Services, AIDL & Bound IPC | P5 | 81 | 🟥22 🟧33 🟨10 ⬜16 | [`D06-services-aidl-bound-ipc.md`](checklist/D06-services-aidl-bound-ipc.md) |
| **D07** ContentProviders & FileProvider | P5 | 76 | 🟥23 🟧29 🟨1 🟩1 ⬜22 | [`D07-contentproviders-and-fileprovider.md`](checklist/D07-contentproviders-and-fileprovider.md) |
| **D08** Intent Redirection, PendingIntent & URI Grants | P5 | 66 | 🟥18 🟧29 🟨7 ⬜12 | [`D08-intent-redirection-and-pendingintent.md`](checklist/D08-intent-redirection-and-pendingintent.md) |
| **D09** Deep Links, App Links & Custom URI Schemes | P5 | 58 | 🟥12 🟧29 🟨5 ⬜12 | [`D09-deeplinks-and-applinks.md`](checklist/D09-deeplinks-and-applinks.md) |
| **D10** WebView & JavaScript Bridges | P5 | 72 | 🟥26 🟧35 🟨5 🟩1 ⬜5 | [`D10-webview-and-js-bridges.md`](checklist/D10-webview-and-js-bridges.md) |
| **D11** Local Data Storage | P4 | 69 | 🟧1 🟨1 ⬜67 | [`D11-local-data-storage.md`](checklist/D11-local-data-storage.md) |
| **D13** Authentication, Session, OTP & Biometrics | P6 | 9 | ⬜9 | [`D13-auth-session-otp-biometrics.md`](checklist/D13-auth-session-otp-biometrics.md) |
| **D14** Network Security, TLS & Certificate Pinning | P6 | 53 | 🟥11 🟧15 🟨11 🟩4 ⬜12 | [`D14-network-tls-pinning.md`](checklist/D14-network-tls-pinning.md) |
| **D16** Native Code, JNI & Memory Safety | P4 | 23 | 🟥4 🟨1 🟩4 ⬜14 | [`D16-native-code-and-memory.md`](checklist/D16-native-code-and-memory.md) |

**Total: 837 items** — 🟥 137 critical · 🟧 241 high · 🟨 85 medium · 🟩 21 low · ⬜ 353 support

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
- **D13** — **Does anything the server checks actually depend on the user having authenticated — or is every gate in this app a boolean the client computes, a header the client echoes, and a token the client can hand to `curl`?**
- **D14** — **Is there any request on this app's wire that an attacker holding no trusted CA can read or rewrite — and does that request carry an authentication assertion, PII, or content the app will execute?** If the answer needs your CA installed to be true, you have a P5 pinning observation, not a finding.
- **D16** — **Which bytes that an attacker fully controls reach C/C++ inside this app's process, by what path they get there, and does the code that consumes them compute a size, an index or a lifetime from those same bytes without checking it?**

## Related

| | |
|---|---|
| [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md) | **Every item in one file** |
| [`checklist.csv`](checklist.csv) | Machine-readable tracker |
| [`ISSUES.md`](ISSUES.md) | The ordered phase workflow |
| [`AGENTS.md`](AGENTS.md) | The SOP |
| [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md) | Breadth before depth |
| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding |
