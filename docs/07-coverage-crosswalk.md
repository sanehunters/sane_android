# Coverage Crosswalk

> Maps our 27 domains onto every standard a client, an auditor or a bounty triager might ask about.
>
> Use it two ways: to prove coverage in the report's appendix, and to answer "does your methodology cover
> MASVS-PLATFORM / ATT&CK T1635 / OWASP M3?" without guessing.

Every identifier below was machine-extracted from the primary source, not transcribed. The raw datasets
are in [`data/`](../data/):

| Dataset | Rows | Source |
|---|---|---|
| [`mastg-android-tests.csv`](../data/mastg-android-tests.csv) | 163 | OWASP MASTG (51 stable + 112 beta) |
| [`mastg-android-techniques.csv`](../data/mastg-android-techniques.csv) | 78 | MASTG Android techniques |
| [`mastg-android-tools.csv`](../data/mastg-android-tools.csv) | 48 | MASTG Android tools |
| [`mastg-android-rules.csv`](../data/mastg-android-rules.csv) | 51 | MASTG static-analysis rules |
| [`mitre-attack-mobile-android.csv`](../data/mitre-attack-mobile-android.csv) | 122 | ATT&CK Mobile, Android-applicable |
| [`bugcrowd-vrt-full.csv`](../data/bugcrowd-vrt-full.csv) | 581 | Bugcrowd VRT, release 2026-07-08 |

---

## 1. Domain → standards

`VRT ceiling` is the best realistic rating a finding in that domain reaches **once impact is
demonstrated**. A domain whose ceiling is P5 is a support domain: it produces links in a chain, not
submissions. See [severity doctrine](02-severity-and-reportability.md).

| Domain | MASVS | Representative MASTG Android tests | ATT&CK Mobile | OWASP MT10 2024 | VRT ceiling |
|---|---|---|---|---|---|
| **D01** Recon & surface mapping | — | TECH-0003, TECH-0007, TECH-0117, TECH-0141, TECH-0150 | — | — | support |
| **D02** APK/AAB, signing, build integrity | RESILIENCE | TEST-0038, TEST-0224, TEST-0225, TEST-0226, TEST-0039 | T1577, T1645, T1661 | M8 Security Misconfiguration | P4 |
| **D03** Manifest & permission model | PLATFORM, PRIVACY | TEST-0024, TEST-0254, TEST-0255, TEST-0256, TEST-0257 | T1626, T1626.001 | M8 | P3 |
| **D04** Exported activities, task & UI redress | PLATFORM | TEST-0029, TEST-0035, TEST-0340, TEST-0364 | T1516, T1417.002, T1628 | M8 | **P1** via auth bypass |
| **D05** Broadcast receivers & implicit intents | PLATFORM, CODE | TEST-0026, TEST-0366, TEST-0372, TEST-0374, TEST-0375 | T1624.001, T1516 | M8 | **P1** via data theft |
| **D06** Services, AIDL & bound IPC | PLATFORM | TEST-0029, TEST-0365 | T1575, T1623 | M8 | **P1** |
| **D07** ContentProviders & FileProvider | PLATFORM, CODE | TEST-0007, TEST-0339, TEST-0355, TEST-0356, TEST-0357 | T1409, T1533, T1636 | M4 Insufficient I/O Validation | **P1** `server_side_injection.sql_injection` / `file_inclusion.local` |
| **D08** Intent redirection, PendingIntent, URI grants | PLATFORM | TEST-0030, TEST-0381 | T1625, T1516 | M8 | **P1** |
| **D09** Deep links, App Links, URI schemes | PLATFORM | TEST-0028, TEST-0393, TEST-0394; TECH-0172, TECH-0173, TECH-0174 | T1635.001 URI Hijacking | M4 | **P1** `authentication_bypass` |
| **D10** WebView & JS bridges | PLATFORM, CODE | TEST-0027, TEST-0031, TEST-0032, TEST-0033, TEST-0037, TEST-0250–0253, TEST-0320, TEST-0334, TEST-0398–0400 | T1635, T1658 | M4 | **P1** `remote_code_execution_rce` |
| **D11** Local data storage | STORAGE | TEST-0001, TEST-0003, TEST-0009, TEST-0200–0203, TEST-0207, TEST-0216, TEST-0262, TEST-0287, TEST-0304–0306 | T1409, T1420, T1533 | M9 Insecure Data Storage | P5 alone — **P1** once a zero-permission app can reach it |
| **D12** Cryptography & key management | CRYPTO | TEST-0013–0016, TEST-0204, TEST-0205, TEST-0208, TEST-0212, TEST-0221, TEST-0232, TEST-0307–0312, TEST-0350 | T1521 | M10 Insufficient Cryptography | **P2** `key_reuse.inter_environment` |
| **D13** Auth, session, OTP, biometrics | AUTH | TEST-0017, TEST-0018, TEST-0326–0330 | T1634, T1635 | M1 Improper Credential Usage | **P1** `authentication_bypass` |
| **D14** Network security, TLS, pinning | NETWORK | TEST-0019–0023, TEST-0217, TEST-0218, TEST-0233–0244, TEST-0282–0286, TEST-0295 | T1638 AiTM, T1521.003 | M5 Insecure Communication | P5 for pinning; **P4** for cleartext of sensitive data |
| **D15** Backend API, IDOR/BOLA, business logic | AUTH, NETWORK | (MASTG is thin here — this is API testing) | T1639, T1646 | M6 Inadequate Privacy Controls | **P1** `broken_access_control.idor.*` |
| **D16** Native code, JNI, memory safety | CODE | TEST-0043, TEST-0222, TEST-0223, TEST-0288; TECH-0018, TECH-0024, TECH-0034, TECH-0035 | T1575 Native API | M7 Insufficient Binary Protections | **P1** if a primitive is demonstrated |
| **D17** Dynamic code loading, deserialization, supply chain | CODE | TEST-0034, TEST-0042, TEST-0272, TEST-0274, TEST-0337 | T1407, T1474, T1474.001 | M2 Inadequate Supply Chain Security | **P1** `remote_code_execution_rce` |
| **D18** Cloud backend & third-party SDK config | STORAGE, PRIVACY | TEST-0004, TEST-0318, TEST-0319 | T1481, T1639 | M2 | **P1** `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` |
| **D19** Cross-platform frameworks | CODE, NETWORK | TEST-0237; TECH-0109, TECH-0156, MASTG-TOOL-0116 (blutter) | T1407 | M7 | inherits the class it exposes |
| **D20** Privacy, PII, logging, leakage | PRIVACY, STORAGE | TEST-0003, TEST-0005, TEST-0006, TEST-0008, TEST-0010, TEST-0206, TEST-0231, TEST-0258, TEST-0289–0294, TEST-0315, TEST-0316 | T1409, T1414, T1417, T1513, T1517 | M6 | P4 |
| **D21** Anti-tampering, RASP, resilience | RESILIENCE | TEST-0045–0051, TEST-0247, TEST-0249, TEST-0263–0265, TEST-0324, TEST-0325, TEST-0338, TEST-0341, TEST-0351–0353, TEST-0368, TEST-0369 | T1633, T1629, T1630, T1617 | M7 | **P5 — graveyard** |
| **D22** Platform & OS version behaviour | CODE, PLATFORM | TEST-0036, TEST-0245, TEST-0382, TEST-0392 | T1661 | M8 | modifier on other domains |
| **D23** Payments, entitlements, fraud | AUTH | (not covered by MASTG) | T1641 Data Manipulation | M6 | **P1** business logic |
| **D24** Push, notifications, messaging | PLATFORM, STORAGE | TEST-0005, TEST-0315 | T1517, T1582, T1636.004 | M6 | **P2** |
| **D25** Device, OEM & privileged surfaces | PLATFORM | TECH-0030, TECH-0044 | T1404, T1428, T1664 | M8 | **P1** (usually a vendor VRP, not the app programme) |
| **D26** Runtime instrumentation & tooling | — | TECH-0015, TECH-0026, TECH-0031–0045; TOOL-0001, TOOL-0015, TOOL-0029 | — | — | support |
| **D27** Reporting, severity & evidence | — | — | — | — | support |

---

## 2. MASVS group → our domains

| MASVS v2 group | Domains |
|---|---|
| MASVS-STORAGE | D11, D18, D20 |
| MASVS-CRYPTO | D12 |
| MASVS-AUTH | D13, D15, D23 |
| MASVS-NETWORK | D14, D15, D19 |
| MASVS-PLATFORM | D03–D10, D24, D25 |
| MASVS-CODE | D02, D05, D10, D16, D17, D19, D22 |
| MASVS-RESILIENCE | D02, D21 |
| MASVS-PRIVACY | D03, D18, D20 |

---

## 3. OWASP Mobile Top 10 (2024) → our domains

| # | Title | Domains | Note |
|---|---|---|---|
| M1 | Improper Credential Usage | D13, D18 | The key-restriction verification step is what makes this reportable |
| M2 | Inadequate Supply Chain Security | D17, D18, D19 | Reachability is the whole argument |
| M3 | Insecure Authentication/Authorization | D13, D15 | Where the P1s live |
| M4 | Insufficient Input/Output Validation | D05, D07, D09, D10 | The IPC block |
| M5 | Insecure Communication | D14 | Mostly P5 unless sensitive data is in cleartext |
| M6 | Inadequate Privacy Controls | D20, D23, D24 | |
| M7 | Insufficient Binary Protections | D16, D19, D21 | Largely graveyard for bounty |
| M8 | Security Misconfiguration | D02, D03, D04, D22 | |
| M9 | Insecure Data Storage | D11 | **P5 standalone** — must be chained |
| M10 | Insufficient Cryptography | D12 | |

---

## 4. ATT&CK Mobile — what applies and what does not

Of the 122 Android-applicable techniques, roughly a third describe **malware behaviour** rather than an
app weakness. Do not waste tester time on those. The split:

**Directly testable against a client app** — the app either enables the technique or fails to defend it:

| Technique | Domain | The question a tester asks |
|---|---|---|
| T1635.001 URI Hijacking | D09 | Can another app claim this scheme or win this App Link? |
| T1635 Steal Application Access Token | D09, D10, D13 | Can a token be extracted via deep link, WebView or IPC? |
| T1636.* Protected User Data | D07 | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1409 Stored Application Data | D11 | Is stored data reachable by another app? |
| T1517 Access Notifications | D24 | Does the app put sensitive content in notifications? |
| T1414 Clipboard Data | D20 | Are high-value values copied to the clipboard? |
| T1417.002 GUI Input Capture | D04 | Is the app task-hijackable or overlayable? |
| T1516 Input Injection | D04, D05 | Can injected input drive a privileged action? |
| T1513 Screen Capture | D20 | Is `FLAG_SECURE` set on sensitive screens? |
| T1624.001 Broadcast Receivers | D05 | Is an exported receiver a persistence or injection point? |
| T1625 Hijack Execution Flow | D08 | Intent redirection |
| T1407 Download New Code at Runtime | D17, D19 | Is OTA code signature-verified? |
| T1474.001 Compromise Software Dependencies | D17 | Reachable vulnerable SDK versions |
| T1638 Adversary-in-the-Middle | D14 | Cleartext, custom trust managers |
| T1626 Abuse Elevation Control | D03 | Device-admin and accessibility posture |
| T1658 Exploitation for Client Execution | D10, D16 | App-reachable parser and WebView bugs |

**Malware-side, out of scope for an app assessment** — record once, do not test:
T1406 Obfuscated Files, T1628 Hide Artifacts, T1629 Impair Defenses, T1630 Indicator Removal,
T1633 Virtualization/Sandbox Evasion, T1655 Masquerading, T1660 Phishing, T1451 SIM Card Swap,
T1637 Dynamic Resolution, T1481 Web Service C2, T1521 Encrypted Channel (as C2), T1663 Remote Access
Software, T1670 Virtualization Solution, T1643 Generate Traffic from Victim.

These describe what an attacker's *own* malware does. A client app is not made insecure by them. The
exception is when the client app is itself a security product — then they become requirements.

---

## 5. Using this in a report

Appendix A of the [assessment report](../templates/assessment-report.md) should state coverage as:

> Testing covered MASVS-STORAGE, -CRYPTO, -AUTH, -NETWORK, -PLATFORM, -CODE, -RESILIENCE and -PRIVACY
> across 27 internal domains, comprising N checklist items. M items produced findings; K items were
> tested and ruled out and are listed in Appendix C with the mechanism that closes each. MASTG Android
> tests referenced: [list]. The following were out of scope by agreement: [list].

The ruled-out half is what distinguishes an audit from a sample. Do not omit it.
