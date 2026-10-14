# Coverage Crosswalk

> Maps our 26 domains (D24 and D28 chapters are in progress) onto every standard a client, an auditor or a bounty triager might ask about.
>
> Use it two ways: to prove coverage in the report's appendix, and to answer "does your methodology cover
> MASVS-PLATFORM / ATT&CK T1635 / OWASP M3?" without guessing.

Every identifier below was machine-extracted from the primary source, not transcribed. The raw datasets
are in [`data/`](../data/):

| Dataset | Rows | Source |
|---|---|---|
| [`mastg-tests.csv`](../data/mastg-tests.csv) | 163 | MASTG Android tests with status (98 current v2, 51 deprecated v1, 14 placeholders) |
| [`mastg-techniques.csv`](../data/mastg-techniques.csv) · [`mastg-tools.csv`](../data/mastg-tools.csv) · [`mastg-knowledge.csv`](../data/mastg-knowledge.csv) · [`mastg-rules.csv`](../data/mastg-rules.csv) | 91 · 81 · 75 · 71 | the other MASTG object types, Android + generic + network |
| [`maswe.csv`](../data/maswe.csv) · [`masvs-controls.csv`](../data/masvs-controls.csv) | 77 · 24 | MASWE weaknesses and MASVS v2 controls |
| [`attack-mobile-android.csv`](../data/attack-mobile-android.csv) | 122 | MITRE ATT&CK Mobile 19.2, Android-applicable techniques |
| [`crosswalk.csv`](../data/crosswalk.csv) | 1,335 | **generated** standard id → checklist items that cite it (the proof behind every generated row below; `n_items = 0` rows are the gap list) |
| [`vrt.csv`](../data/vrt.csv) | 581 | Bugcrowd VRT, release 2026-07-08 |

---

<!-- generated:start -->
_Generated from `data/crosswalk.csv` (1335 rows, 781 cited), `data/mastg-tests.csv` and `json/*.json` (source digest `f4334ccf62dc`, 1933 items, 26 chapters). Ids are abbreviated (`MASTG-` dropped). Do not edit by hand — rebuild with §6._

## 1. Domain → standards

`VRT ceiling` is the best realistic rating a finding in that domain reaches **once impact is
demonstrated** (doctrine, hand-maintained in the generator). A domain whose ceiling is P5 is a support domain:
it produces links in a chain, not submissions. See [severity doctrine](02-severity-and-reportability.md).
Every other column lists only identifiers the chapter's items actually cite (`Maps to` rows): current MASTG
tests first, deprecated ones marked with their current successor, placeholders omitted (see Known gaps).

| Domain | MASVS (cited) | MASTG Android tests cited | ATT&CK Mobile (cited) | OWASP MT10 2024 (cited) | VRT ceiling |
|---|---|---|---|---|---|
| **D01** Recon & Attack-Surface Mapping | AUTH, PLATFORM | TEST-0217, TEST-0233, TEST-0236, TEST-0242, TEST-0355, TEST-0393, + 2 KNOW, 16 TECH, 10 TOOL | T1418, T1418.001, T1422.001, T1627.001 | — | support |
| **D02** APK/AAB Structure, Signing & Build Integrity | CODE, RESILIENCE, STORAGE | TEST-0212, TEST-0224–0227, TEST-0272, TEST-0274, + 3 KNOW, 12 TECH, 12 TOOL | T1406, T1406.002, T1407, T1409, T1474.003, T1533, T1544, T1577, T1623.001, T1632, T1632.001, T1645, T1661 | M1 | P4 |
| **D03** AndroidManifest & Permission Model | STORAGE | TEST-0216, TEST-0252, TEST-0254, TEST-0262, TEST-0315, TEST-0355, TEST-0364, + 1 KNOW, 8 TECH, 2 TOOL | T1417, T1417.001, T1417.002, T1429, T1430, T1453, T1512, T1516, T1533, T1541, T1582, T1616, T1624.001, T1626, T1626.001, T1627.001, T1629.002, T1630.002, T1636.001, T1636.002, T1636.003, T1636.004, T1636.005, T1642, T1643, T1644 | — | P3 |
| **D04** Exported Activities, Task & UI-Redress Attacks | AUTH, PLATFORM | TEST-0289, TEST-0291, TEST-0340, TEST-0364, TEST-0029 (deprecated; see TEST-0364, TEST-0365, TEST-0366), + 1 BEST, 2 KNOW, 4 TECH, 2 TOOL | T1417.002, T1453, T1516, T1626, T1628, T1628.001, T1655.001 | M1, M3 | **P1** via auth bypass |
| **D05** Broadcast Receivers & Implicit Intents | CODE | TEST-0366, TEST-0372, TEST-0374, TEST-0029 (deprecated; see TEST-0364, TEST-0365, TEST-0366), + 1 APP, 1 BEST, 2 KNOW, 3 TECH, 2 TOOL | T1398, T1533, T1603, T1624.001, T1635 | — | **P1** via data theft |
| **D06** Services, AIDL & Bound IPC | PLATFORM | TEST-0365, TEST-0005 (deprecated; see TEST-0315), TEST-0007 (deprecated; see TEST-0339, TEST-0355, TEST-0356, TEST-0357), TEST-0029 (deprecated; see TEST-0364, TEST-0365, TEST-0366), + 1 BEST, 2 KNOW, 5 TECH, 2 TOOL | T1428, T1513, T1516, T1517, T1541, T1575, T1604, T1626, T1635, T1636.004, T1638, T1663 | M3 | **P1** |
| **D07** ContentProviders & FileProvider | — | TEST-0202, TEST-0250, TEST-0254, TEST-0339, TEST-0355–0357, TEST-0025 (deprecated; see TEST-0339), + 3 KNOW, 3 TECH, 3 TOOL | T1636, T1641 | — | **P1** `server_side_injection.sql_injection` / `file_inclusion.local` |
| **D08** Intent Redirection, PendingIntent & URI Grants | — | TEST-0250, TEST-0315, TEST-0357, TEST-0372, TEST-0374, TEST-0381, TEST-0030 (deprecated; see TEST-0381), + 2 BEST, 4 KNOW, 1 TECH | T1409, T1517, T1533, T1624.001, T1635, T1635.001 | — | **P1** |
| **D09** Deep Links, App Links & Custom URI Schemes | AUTH | TEST-0393, TEST-0028 (deprecated; see TEST-0393, TEST-0394), + 1 DEMO, 1 KNOW, 3 TECH, 2 TOOL | T1635, T1635.001 | — | **P1** `authentication_bypass` |
| **D10** WebView & JavaScript Bridges | — | TEST-0227, TEST-0250–0253, TEST-0284, TEST-0320, TEST-0334, TEST-0398–0400, + 1 DEMO, 1 KNOW, 2 TECH | T1407, T1635 | — | **P1** `remote_code_execution_rce` |
| **D11** Local Data Storage | — | TEST-0200–0203, TEST-0207, TEST-0216, TEST-0231, TEST-0258, TEST-0262–0265, TEST-0287, TEST-0316, TEST-0006 (deprecated; see TEST-0258), TEST-0009 (deprecated; see TEST-0216), TEST-0011 (deprecated; no current successor), + 3 BEST, 1 DEMO, 11 KNOW, 6 TECH, 3 TOOL | T1407, T1533, T1544, T1628.003, T1635, T1638 | — | P5 alone — **P1** once a zero-permission app can reach it |
| **D12** Cryptography & Key Management | CRYPTO, STORAGE | TEST-0204, TEST-0208, TEST-0212, TEST-0221, TEST-0232, TEST-0307, TEST-0312, TEST-0330, TEST-0350, TEST-0018 (deprecated; see TEST-0326, TEST-0327, TEST-0328, TEST-0329, TEST-0330), + 4 BEST, 5 KNOW, 2 TECH, 4 TOOL | T1406, T1426, T1474.001, T1521, T1521.001, T1521.002, T1533, T1635, T1641.001 | — | **P2** `key_reuse.inter_environment` |
| **D13** Authentication, Session, OTP & Biometrics | AUTH, CRYPTO | TEST-0247, TEST-0249, TEST-0315, TEST-0326–0330, TEST-0005 (deprecated; see TEST-0315), TEST-0010 (deprecated; see TEST-0289, TEST-0291), TEST-0012 (deprecated; see TEST-0247, TEST-0249), TEST-0017 (deprecated; see TEST-0327, TEST-0330), TEST-0018 (deprecated; see TEST-0326, TEST-0327, TEST-0328, TEST-0329, TEST-0330), + 4 BEST, 1 KNOW | T1451, T1453, T1461, T1517, T1582, T1617, T1629.002, T1636.004, T1640, T1642, T1644, T1660, T1676 | — | **P1** `authentication_bypass` |
| **D14** Network Security, TLS & Certificate Pinning | CODE, NETWORK | TEST-0217, TEST-0233–0236, TEST-0242–0244, TEST-0282, TEST-0285, TEST-0295, TEST-0022 (deprecated; see TEST-0242, TEST-0243, TEST-0244), + 2 BEST, 4 KNOW, 8 TECH, 15 TOOL | T1437.001, T1481.002, T1509, T1521, T1632, T1637, T1638, T1639.001 | M2 | P5 for pinning; **P4** for cleartext of sensitive data |
| **D15** Backend API, IDOR/BOLA, Mass Assignment & Business Logic | AUTH, CODE, RESILIENCE | TEST-0217, TEST-0236, TEST-0338, TEST-0382, TEST-0392, + 1 KNOW, 2 TECH, 1 TOOL | T1426, T1428, T1533, T1630.003, T1633.001, T1636.004, T1641, T1641.001 | M3, M4, M8 | **P1** `broken_access_control.idor.*` |
| **D16** Native Code, JNI & Memory Safety | CODE, RESILIENCE | TEST-0222, TEST-0288, + 3 KNOW, 11 TECH, 10 TOOL | T1407, T1575, T1617, T1623, T1623.001, T1625.001, T1631, T1631.001, T1658 | M7 | **P1** if a primitive is demonstrated |
| **D17** Dynamic Code Loading, Deserialization & Supply Chain | CODE | TEST-0272, TEST-0274, TEST-0337, TEST-0382, TEST-0392, TEST-0034 (deprecated; see TEST-0337), + 3 KNOW, 7 TECH, 6 TOOL | T1406.002, T1407, T1474, T1474.001, T1474.003, T1544, T1661 | — | **P1** `remote_code_execution_rce` |
| **D18** Cloud Backend & Third-Party SDK Configuration | PRIVACY | TEST-0318, TEST-0004 (deprecated; see TEST-0318, TEST-0319), + 2 KNOW, 5 TECH, 4 TOOL | T1437.001, T1474.001, T1481.002, T1532, T1533, T1646 | M6, M9 | **P1** `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` |
| **D19** Cross-Platform Frameworks | — | TEST-0334, + 1 KNOW, 14 TECH, 15 TOOL | T1407, T1521.003, T1533, T1575 | — | inherits the class it exposes |
| **D20** Privacy, PII, Logging & Data Leakage | PRIVACY | TEST-0203, TEST-0206, TEST-0231, TEST-0254, TEST-0258, TEST-0263–0265, TEST-0289, TEST-0291, TEST-0315, TEST-0318–0320, TEST-0340, TEST-0003 (deprecated; see TEST-0203, TEST-0231), TEST-0005 (deprecated; see TEST-0315), TEST-0006 (deprecated; see TEST-0258), TEST-0008 (deprecated; see TEST-0316), TEST-0010 (deprecated; see TEST-0289, TEST-0291), TEST-0041 (deprecated; see TEST-0263), + 4 BEST, 5 KNOW, 2 TECH, 8 TOOL | T1414, T1422, T1429, T1430, T1453, T1512, T1513, T1517, T1532, T1533, T1541, T1628, T1628.002, T1636, T1636.001, T1636.003, T1636.004, T1641.001, T1644, T1646 | M6 | P4 |
| **D21** Anti-Tampering, RASP, Root/Emulator Detection & Resilience | CODE, RESILIENCE | TEST-0263–0265, TEST-0324, TEST-0338, TEST-0341, TEST-0351–0353, TEST-0368, TEST-0046 (deprecated; see TEST-0352, TEST-0353), TEST-0049 (deprecated; see TEST-0351), TEST-0051 (deprecated; see TEST-0368, TEST-0369), + 5 BEST, 12 KNOW, 11 TECH, 14 TOOL | T1471, T1617, T1629, T1629.002, T1629.003, T1630.002, T1630.003, T1632.001, T1633, T1633.001, T1642, T1662 | — | **P5 — graveyard** |
| **D22** Platform & OS Version-Specific Behaviour | CODE, PLATFORM | TEST-0217, TEST-0224, TEST-0235, TEST-0242, TEST-0245, TEST-0262, TEST-0285, TEST-0307, TEST-0312, TEST-0315, TEST-0334, TEST-0340, TEST-0381, + 8 KNOW, 7 TECH, 1 TOOL | T1407, T1418, T1426, T1429, T1512, T1626, T1632, T1633.001, T1638, T1639.001, T1661 | — | modifier on other domains |
| **D23** Payments, Entitlements, Subscriptions & Fraud | AUTH, RESILIENCE | TEST-0327, TEST-0338, TEST-0340, TEST-0368, + 1 BEST, 1 KNOW, 3 TECH | T1417.002, T1453, T1516, T1582, T1616, T1641, T1641.001, T1643, T1660 | M3, M7 | **P1** business logic |
| **D24** Push, Notifications & Messaging | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | **P2** (planned) |
| **D25** Device, OEM, Firmware & Privileged Surfaces | — | TEST-0203, TEST-0364–0366, + 3 KNOW, 1 TOOL | T1398, T1458, T1474.002, T1474.003, T1625.001, T1645 | — | **P1** (usually a vendor VRP, not the app programme) |
| **D26** Runtime Instrumentation, Tooling & Harness | — | + 49 TECH, 44 TOOL | T1406, T1406.002, T1617, T1623.001, T1632, T1638 | — | support |
| **D27** Reporting, Severity Rating & Evidence | — | TEST-0204, TEST-0223, TEST-0232, TEST-0235, TEST-0242–0244, TEST-0316, TEST-0325, TEST-0338, TEST-0351–0353, + 3 TECH, 2 TOOL | — | — | support |
| **D28** AI/LLM-in-App Surfaces | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | inherits the class it exposes (planned) |

---

## 2. MASVS group → our domains

| MASVS v2 group | Domains citing a control of the group |
|---|---|
| MASVS-STORAGE | D02, D03, D12 |
| MASVS-CRYPTO | D12, D13 |
| MASVS-AUTH | D01, D04, D09, D13, D15, D23 |
| MASVS-NETWORK | D14 |
| MASVS-PLATFORM | D01, D04, D06, D22 |
| MASVS-CODE | D02, D05, D14, D15, D16, D17, D21, D22 |
| MASVS-RESILIENCE | D02, D15, D16, D21, D23 |
| MASVS-PRIVACY | D18, D20 |

---

## 3. OWASP Mobile Top 10 (2024) → our domains

`Domains` is the doctrine mapping (hand-maintained); `Cited by` lists the domains whose items name the risk
(`Mobile Top 10 2024 Mn` in a Sources or Maps-to row). A doctrine domain missing from `Cited by` is a chapter to-do.

| # | Title | Domains | Cited by | Note |
|---|---|---|---|---|
| M1 | Improper Credential Usage | D13, D18 | D02, D04 | The key-restriction verification step is what makes this reportable |
| M2 | Inadequate Supply Chain Security | D17, D18, D19 | D14 | Reachability is the whole argument |
| M3 | Insecure Authentication/Authorization | D13, D15 | D04, D06, D15, D23 | Where the P1s live |
| M4 | Insufficient Input/Output Validation | D05, D07, D09, D10 | D15 | The IPC block |
| M5 | Insecure Communication | D14 | — | Mostly P5 unless sensitive data is in cleartext |
| M6 | Inadequate Privacy Controls | D20, D23 | D18, D20 | D24 (planned) will join this row |
| M7 | Insufficient Binary Protections | D16, D19, D21 | D16, D23 | Largely graveyard for bounty |
| M8 | Security Misconfiguration | D02, D03, D04, D22 | D15 |  |
| M9 | Insecure Data Storage | D11 | D18 | **P5 standalone** — must be chained |
| M10 | Insufficient Cryptography | D12 | — |  |

---

## 4. ATT&CK Mobile — what applies and what does not

Of the 122 Android-applicable techniques, roughly a third describe **malware behaviour** rather than an
app weakness. Do not waste tester time on those. The split:

**Directly testable against a client app** — every technique at least one item cites, with the citing domains:

| Technique | Domains (items) | The question a tester asks |
|---|---|---|
| T1398 Boot or Logon Initialization Scripts | D05 (1), D25 (1) |  |
| T1406 Obfuscated Files or Information | D02 (1), D12 (2), D26 (1) |  |
| T1406.002 Software Packing | D02 (1), D17 (1), D26 (1) |  |
| T1407 Download New Code at Runtime | D02 (3), D10 (1), D11 (1), D16 (2), D17 (1), D19 (4), D22 (1) | Is OTA code signature-verified? |
| T1409 Stored Application Data | D02 (2), D08 (3) | Is stored data reachable by another app? |
| T1414 Clipboard Data | D20 (3) | Are high-value values copied to the clipboard? |
| T1417 Input Capture | D03 (1) |  |
| T1417.001 Keylogging | D03 (1) |  |
| T1417.002 GUI Input Capture | D03 (1), D04 (5), D23 (1) | Is the app task-hijackable or overlayable? |
| T1418 Software Discovery | D01 (1), D22 (1) |  |
| T1418.001 Security Software Discovery | D01 (1) |  |
| T1422 System Network Configuration Discovery | D20 (1) |  |
| T1422.001 Internet Connection Discovery | D01 (1) |  |
| T1426 System Information Discovery | D12 (1), D15 (1), D22 (1) |  |
| T1428 Exploitation of Remote Services | D06 (1), D15 (2) |  |
| T1429 Audio Capture | D03 (1), D20 (1), D22 (1) |  |
| T1430 Location Tracking | D03 (3), D20 (1) |  |
| T1437.001 Web Protocols | D14 (1), D18 (1) |  |
| T1451 SIM Card Swap | D13 (1) |  |
| T1453 Abuse Accessibility Features | D03 (2), D04 (2), D13 (1), D20 (2), D23 (1) |  |
| T1458 Replication Through Removable Media | D25 (3) |  |
| T1461 Lockscreen Bypass | D13 (1) |  |
| T1471 Data Encrypted for Impact | D21 (1) |  |
| T1474 Supply Chain Compromise | D17 (1) |  |
| T1474.001 Compromise Software Dependencies and Development Tools | D12 (1), D17 (1), D18 (1) | Reachable vulnerable SDK versions |
| T1474.002 Compromise Hardware Supply Chain | D25 (2) |  |
| T1474.003 Compromise Software Supply Chain | D02 (1), D17 (1), D25 (1) |  |
| T1481.002 Bidirectional Communication | D14 (1), D18 (2) |  |
| T1509 Non-Standard Port | D14 (1) |  |
| T1512 Video Capture | D03 (1), D20 (1), D22 (1) |  |
| T1513 Screen Capture | D06 (3), D20 (2) | Is `FLAG_SECURE` set on sensitive screens? |
| T1516 Input Injection | D03 (1), D04 (2), D06 (2), D23 (1) | Can injected input drive a privileged action? |
| T1517 Access Notifications | D06 (1), D08 (1), D13 (2), D20 (5) | Does the app put sensitive content in notifications? |
| T1521 Encrypted Channel | D12 (1), D14 (1) |  |
| T1521.001 Symmetric Cryptography | D12 (1) |  |
| T1521.002 Asymmetric Cryptography | D12 (1) |  |
| T1521.003 SSL Pinning | D19 (1) |  |
| T1532 Archive Collected Data | D18 (1), D20 (1) |  |
| T1533 Data from Local System | D02 (2), D03 (1), D05 (1), D08 (2), D11 (1), D12 (1), D15 (1), D18 (1), D19 (1), D20 (1) |  |
| T1541 Foreground Persistence | D03 (2), D06 (3), D20 (2) |  |
| T1544 Ingress Tool Transfer | D02 (2), D11 (1), D17 (1) |  |
| T1575 Native API | D06 (1), D16 (12), D19 (2) |  |
| T1577 Compromise Application Executable | D02 (1) |  |
| T1582 SMS Control | D03 (1), D13 (1), D23 (1) |  |
| T1603 Scheduled Task/Job | D05 (2) |  |
| T1604 Proxy Through Victim | D06 (1) |  |
| T1616 Call Control | D03 (1), D23 (1) |  |
| T1617 Hooking | D13 (1), D16 (2), D21 (1), D26 (1) |  |
| T1623 Command and Scripting Interpreter | D16 (1) |  |
| T1623.001 Unix Shell | D02 (1), D16 (1), D26 (1) |  |
| T1624.001 Broadcast Receivers | D03 (1), D05 (6), D08 (1) | Is an exported receiver a persistence or injection point? |
| T1625.001 System Runtime API Hijacking | D16 (1), D25 (1) |  |
| T1626 Abuse Elevation Control Mechanism | D03 (1), D04 (1), D06 (1), D22 (2) | Device-admin and accessibility posture |
| T1626.001 Device Administrator Permissions | D03 (1) |  |
| T1627.001 Geofencing | D01 (1), D03 (1) |  |
| T1628 Hide Artifacts | D04 (1), D20 (1) |  |
| T1628.001 Suppress Application Icon | D04 (1) |  |
| T1628.002 User Evasion | D20 (1) |  |
| T1628.003 Conceal Multimedia Files | D11 (1) |  |
| T1629 Impair Defenses | D21 (1) |  |
| T1629.002 Device Lockout | D03 (1), D13 (2), D21 (1) |  |
| T1629.003 Disable or Modify Tools | D21 (1) |  |
| T1630.002 File Deletion | D03 (1), D21 (1) |  |
| T1630.003 Disguise Root/Jailbreak Indicators | D15 (1), D21 (1) |  |
| T1631 Process Injection | D16 (1) |  |
| T1631.001 Ptrace System Calls | D16 (1) |  |
| T1632 Subvert Trust Controls | D02 (1), D14 (2), D22 (1), D26 (2) |  |
| T1632.001 Code Signing Policy Modification | D02 (1), D21 (1) |  |
| T1633 Virtualization/Sandbox Evasion | D21 (1) |  |
| T1633.001 System Checks | D15 (1), D21 (2), D22 (1) |  |
| T1635 Steal Application Access Token | D05 (2), D06 (1), D08 (1), D09 (1), D10 (1), D11 (1), D12 (1) | Can a token be extracted via deep link, WebView or IPC? |
| T1635.001 URI Hijacking | D08 (1), D09 (3) | Can another app claim this scheme or win this App Link? |
| T1636 Protected User Data | D07 (1), D20 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1636.001 Calendar Entries | D03 (2), D20 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1636.002 Call Log | D03 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1636.003 Contact List | D03 (1), D20 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1636.004 SMS Messages | D03 (2), D06 (1), D13 (1), D15 (2), D20 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1636.005 Accounts | D03 (1) | Does the app proxy contacts/SMS/calendar to an unprivileged caller? |
| T1637 Dynamic Resolution | D14 (1) |  |
| T1638 Adversary-in-the-Middle | D06 (1), D11 (1), D14 (6), D22 (1), D26 (1) | Cleartext, custom trust managers |
| T1639.001 Exfiltration Over Unencrypted Non-C2 Protocol | D14 (1), D22 (1) |  |
| T1640 Account Access Removal | D13 (4) |  |
| T1641 Data Manipulation | D07 (1), D15 (2), D23 (3) |  |
| T1641.001 Transmitted Data Manipulation | D12 (1), D15 (1), D20 (1), D23 (2) |  |
| T1642 Endpoint Denial of Service | D03 (1), D13 (1), D21 (1) |  |
| T1643 Generate Traffic from Victim | D03 (2), D23 (1) |  |
| T1644 Out of Band Data | D03 (1), D13 (1), D20 (1) |  |
| T1645 Compromise Client Software Binary | D02 (1), D25 (1) |  |
| T1646 Exfiltration Over C2 Channel | D18 (1), D20 (3) |  |
| T1655.001 Match Legitimate Name or Location | D04 (1) |  |
| T1658 Exploitation for Client Execution | D16 (3) | App-reachable parser and WebView bugs |
| T1660 Phishing | D13 (2), D23 (1) |  |
| T1661 Application Versioning | D02 (1), D17 (1), D22 (1) |  |
| T1662 Data Destruction | D21 (1) |  |
| T1663 Remote Access Software | D06 (2) |  |
| T1676 Linked Devices | D13 (1) |  |

**Malware-side, out of scope for an app assessment** — record once, do not test:
T1406 Obfuscated Files or Information, T1628 Hide Artifacts, T1629 Impair Defenses, T1630 Indicator Removal on Host, T1633 Virtualization/Sandbox Evasion, T1655 Masquerading, T1660 Phishing, T1451 SIM Card Swap, T1637 Dynamic Resolution, T1481 Web Service, T1521 Encrypted Channel, T1663 Remote Access Software, T1670 Virtualization Solution, T1643 Generate Traffic from Victim.

These describe what an attacker's *own* malware does. A client app is not made insecure by them. The
exception is when the client app is itself a security product — then they become requirements.

_Cited by items although listed malware-side (the item argues an app-side defence; keep or re-map): T1406 (D02, D12, D26); T1451 (D13); T1521 (D12, D14); T1628 (D04, D20); T1629 (D21); T1633 (D21); T1637 (D14); T1643 (D03, D23); T1660 (D13, D23); T1663 (D06)._

---

## Known gaps (from `crosswalk.csv` rows with `n_items = 0`)

**MASWE weaknesses no item cites** (10 of 77):

- MASWE-0010 Improper Generation of Cryptographic Signatures — D12 candidate item
- MASWE-0015 Cryptographic Key Rotation Not Implemented — D12 candidate item
- MASWE-0052 App Virtualization Environment Detection Not Implemented — resilience graveyard by design (docs/02)
- MASWE-0055 Malware Detection Not Implemented — resilience graveyard by design
- MASWE-0060 Resource Obfuscation Not Implemented — resilience graveyard by design
- MASWE-0065 Dynamic Analysis Tools Detection Not Implemented — resilience graveyard by design
- MASWE-0071 Inadequate Defaults for Privacy Relevant Actions — D20 candidate item
- MASWE-0072 Inadequate Privacy Policy — D20 candidate item
- MASWE-0076 Lack of Proper Data Management Controls — D20 candidate item
- MASWE-0077 Inadequate Data Visibility Controls — D20 candidate item

**MASTG tests:** all 98 current MASTG v2 Android tests are cited by at least one item.
Deprecated v1 ids still cited (marked above; rewrite to the successor when the item is next touched): D04 (1), D05 (1), D06 (3), D07 (1), D08 (1), D09 (1), D11 (3), D12 (1), D13 (5), D14 (1), D17 (1), D18 (1), D20 (6), D21 (3).
Placeholder ids cited by items — **must be replaced** (cite the MASWE instead): D01: TEST-0237, TEST-0238; D04: TEST-0292, TEST-0293, TEST-0294; D11: TEST-0304, TEST-0305, TEST-0306; D14: TEST-0238; D15: TEST-0237, TEST-0238; D19: TEST-0237; D20: TEST-0255, TEST-0292, TEST-0293, TEST-0294.

**ATT&CK techniques neither cited nor listed malware-side** (16) — each is either a chapter to-do or belongs in the malware list:

T1404 Exploitation for Privilege Escalation, T1420 File and Directory Discovery, T1421 System Network Connections Discovery, T1422.002 Wi-Fi Discovery, T1423 Network Service Scanning, T1424 Process Discovery, T1430.001 Remote Device Management Services, T1430.002 Impersonate SS7 Nodes, T1437 Application Layer Protocol, T1456 Drive-By Compromise, T1464 Network Denial of Service, T1624 Event Triggered Execution, T1625 Hijack Execution Flow, T1627 Execution Guardrails, T1639 Exfiltration Over Alternative Protocol, T1664 Exploitation for Initial Access.
<!-- generated:end -->

---

## 5. Using this in a report

Appendix A of the [assessment report](../templates/assessment-report.md) should state coverage as:

> Testing covered MASVS-STORAGE, -CRYPTO, -AUTH, -NETWORK, -PLATFORM, -CODE, -RESILIENCE and -PRIVACY
> across 26 internal domains, comprising N checklist items. M items produced findings; K items were
> tested and ruled out and are listed in Appendix C with the mechanism that closes each. MASTG Android
> tests referenced: [list]. The following were out of scope by agreement: [list].

The ruled-out half is what distinguishes an audit from a sample. Do not omit it.

---

## 6. Regenerating this document

Sections 1–4 and "Known gaps" (everything between the two `generated` HTML comments) are built from
`data/` and `json/`, never typed. Rebuild them after `scripts/build-checklist.py` and `scripts/refresh-data.py`
(order in [`data/README.md`](../data/README.md) "Regenerate"), from the repository root:

```bash
python3 - <<'EOF'
# Regenerates docs/07 sections 1-4 and "Known gaps" between the generated markers.
# Inputs: data/crosswalk.csv, data/mastg-tests.csv, data/standards-index.csv,
# data/attack-mobile-android.csv, data/maswe.csv, data/mobile-top10-2024.csv, json/*.json.
# Run from the repository root AFTER scripts/build-checklist.py and scripts/refresh-data.py.
import collections, csv, glob, json, os, re
ROOT = os.getcwd()
def rd(name):
    with open(os.path.join(ROOT, "data", name), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
idx = json.load(open(os.path.join(ROOT, "json", "index.json"), encoding="utf-8"))
tests = {r["id"]: r for r in rd("mastg-tests.csv")}
sidx = {r["id"]: r for r in rd("standards-index.csv")}
attack = {r["id"]: r["name"] for r in rd("attack-mobile-android.csv")}
maswe = {r["id"]: r["title"] for r in rd("maswe.csv")}
mt10 = {r["id"]: r["title"] for r in rd("mobile-top10-2024.csv")}
xw = rd("crosswalk.csv")
cite = collections.defaultdict(lambda: collections.defaultdict(set))   # domain -> kind -> ids
mt_cite = collections.defaultdict(set)
for p in sorted(glob.glob(os.path.join(ROOT, "json", "D*.json"))):
    for i in json.load(open(p, encoding="utf-8"))["items"]:
        for k, v in i["ids"].items():
            cite[i["domain"]][k].update(v)
        for m in re.findall(r"Mobile Top 10[^\n]{0,12}?\b(M(?:10|[1-9]))\b", i.get("body_md", "")):
            mt_cite[i["domain"]].add(m)
# chapters registered in the PHASE table of scripts/build-checklist.py but not yet written
PLANNED = {"D24": ("Push, Notifications & Messaging", "P6"), "D28": ("AI/LLM-in-App Surfaces", "P4")}
# doctrine, hand-maintained (see docs/02): the best realistic rating once impact is demonstrated
CEILING = {"D01": "support", "D02": "P4", "D03": "P3", "D04": "**P1** via auth bypass", "D05": "**P1** via data theft",
 "D06": "**P1**", "D07": "**P1** `server_side_injection.sql_injection` / `file_inclusion.local`", "D08": "**P1**",
 "D09": "**P1** `authentication_bypass`", "D10": "**P1** `remote_code_execution_rce`",
 "D11": "P5 alone — **P1** once a zero-permission app can reach it", "D12": "**P2** `key_reuse.inter_environment`",
 "D13": "**P1** `authentication_bypass`", "D14": "P5 for pinning; **P4** for cleartext of sensitive data",
 "D15": "**P1** `broken_access_control.idor.*`", "D16": "**P1** if a primitive is demonstrated",
 "D17": "**P1** `remote_code_execution_rce`",
 "D18": "**P1** `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`",
 "D19": "inherits the class it exposes", "D20": "P4", "D21": "**P5 — graveyard**", "D22": "modifier on other domains",
 "D23": "**P1** business logic", "D24": "**P2** (planned)", "D25": "**P1** (usually a vendor VRP, not the app programme)",
 "D26": "support", "D27": "support", "D28": "inherits the class it exposes (planned)"}
MT10_DOCTRINE = [("M1", "D13, D18", "The key-restriction verification step is what makes this reportable"),
 ("M2", "D17, D18, D19", "Reachability is the whole argument"), ("M3", "D13, D15", "Where the P1s live"),
 ("M4", "D05, D07, D09, D10", "The IPC block"), ("M5", "D14", "Mostly P5 unless sensitive data is in cleartext"),
 ("M6", "D20, D23", "D24 (planned) will join this row"), ("M7", "D16, D19, D21", "Largely graveyard for bounty"),
 ("M8", "D02, D03, D04, D22", ""), ("M9", "D11", "**P5 standalone** — must be chained"), ("M10", "D12", "")]
QUESTION = {"T1635.001": "Can another app claim this scheme or win this App Link?",
 "T1635": "Can a token be extracted via deep link, WebView or IPC?",
 "T1636": "Does the app proxy contacts/SMS/calendar to an unprivileged caller?",
 "T1409": "Is stored data reachable by another app?", "T1517": "Does the app put sensitive content in notifications?",
 "T1414": "Are high-value values copied to the clipboard?", "T1417.002": "Is the app task-hijackable or overlayable?",
 "T1516": "Can injected input drive a privileged action?", "T1513": "Is `FLAG_SECURE` set on sensitive screens?",
 "T1624.001": "Is an exported receiver a persistence or injection point?", "T1625": "Intent redirection",
 "T1407": "Is OTA code signature-verified?", "T1474.001": "Reachable vulnerable SDK versions",
 "T1638": "Cleartext, custom trust managers", "T1626": "Device-admin and accessibility posture",
 "T1658": "App-reachable parser and WebView bugs"}
MALWARE = ["T1406", "T1628", "T1629", "T1630", "T1633", "T1655", "T1660", "T1451", "T1637", "T1481", "T1521", "T1663", "T1670", "T1643"]
GAP_NOTE = {"MASWE-0052": "resilience graveyard by design (docs/02)", "MASWE-0055": "resilience graveyard by design",
 "MASWE-0060": "resilience graveyard by design", "MASWE-0065": "resilience graveyard by design",
 "MASWE-0010": "D12 candidate item", "MASWE-0015": "D12 candidate item", "MASWE-0071": "D20 candidate item",
 "MASWE-0072": "D20 candidate item", "MASWE-0076": "D20 candidate item", "MASWE-0077": "D20 candidate item"}
def short(t): return t.replace("MASTG-", "")
def tnum(t): return [int(x) for x in re.findall(r"\d+", t)]
def status(t): return (tests.get(t) or sidx.get(t) or {}).get("status", "unknown")
def runs(nums):
    out, nums, i = [], sorted(nums), 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1: j += 1
        out.append("TEST-%04d" % nums[i] if j - i < 2 else "TEST-%04d–%04d" % (nums[i], nums[j]))
        i = j + 1
    return out
def mastg_cell(dom):
    ids = cite[dom]["mastg"]; cur, dep, ph = [], [], []
    for t in ids:
        if "-TEST-" in t:
            st = status(t); (cur if st == "current" else dep if st == "deprecated" else ph).append(t)
    parts = runs(int(t[-4:]) for t in cur)
    for t in sorted(dep):
        succ = [short(c) for c in tests[t]["covered_by"].split(";") if c and status(c) == "current"]
        parts.append("%s (deprecated; see %s)" % (short(t), ", ".join(succ)) if succ else "%s (deprecated; no current successor)" % short(t))
    kinds = collections.Counter(t.split("-")[1] for t in ids if "-TEST-" not in t)
    if kinds: parts.append("+ " + ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())))
    return (", ".join(parts) or "—"), len(cur), len(dep), sorted(ph)
def att_sort(ids): return sorted(ids, key=tnum)
doms = sorted(set(idx["domains"]) | set(PLANNED))
L = []
digest = idx.get("source_digest", "?")
L.append("_Generated from `data/crosswalk.csv` (%d rows, %d cited), `data/mastg-tests.csv` and `json/*.json` "
         "(source digest `%s`, %d items, %d chapters). Ids are abbreviated (`MASTG-` dropped). Do not edit by hand — "
         "rebuild with §6._" % (len(xw), sum(1 for r in xw if int(r["n_items"])), digest, idx["total_items"], len(idx["domains"])))
L += ["", "## 1. Domain → standards", "",
      "`VRT ceiling` is the best realistic rating a finding in that domain reaches **once impact is",
      "demonstrated** (doctrine, hand-maintained in the generator). A domain whose ceiling is P5 is a support domain:",
      "it produces links in a chain, not submissions. See [severity doctrine](02-severity-and-reportability.md).",
      "Every other column lists only identifiers the chapter's items actually cite (`Maps to` rows): current MASTG",
      "tests first, deprecated ones marked with their current successor, placeholders omitted (see Known gaps).", "",
      "| Domain | MASVS (cited) | MASTG Android tests cited | ATT&CK Mobile (cited) | OWASP MT10 2024 (cited) | VRT ceiling |",
      "|---|---|---|---|---|---|"]
stats = {}
for d in doms:
    if d in PLANNED:
        L.append("| **%s** %s | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | _chapter in progress_ | %s |" % (d, PLANNED[d][0], CEILING.get(d, "—")))
        continue
    name = idx["domains"][d]["name"]
    masvs = sorted({m.group(1) for m in (re.match(r"MASVS-([A-Z]+)-\d", x) for x in cite[d]["masvs"]) if m})
    mcell, ncur, ndep, ph = mastg_cell(d); stats[d] = (ncur, ndep, ph)
    att = att_sort(cite[d]["attack"]); mt = sorted(mt_cite[d], key=tnum)
    L.append("| **%s** %s | %s | %s | %s | %s | %s |" % (d, name, ", ".join(masvs) or "—", mcell, ", ".join(att) or "—", ", ".join(mt) or "—", CEILING.get(d, "—")))
L += ["", "---", "", "## 2. MASVS group → our domains", "", "| MASVS v2 group | Domains citing a control of the group |", "|---|---|"]
for g in ["STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]:
    ds = [d for d in doms if d not in PLANNED and any(x.startswith("MASVS-%s-" % g) for x in cite[d]["masvs"])]
    L.append("| MASVS-%s | %s |" % (g, ", ".join(ds) or "— (no item cites a control yet)"))
L += ["", "---", "", "## 3. OWASP Mobile Top 10 (2024) → our domains", "",
      "`Domains` is the doctrine mapping (hand-maintained); `Cited by` lists the domains whose items name the risk",
      "(`Mobile Top 10 2024 Mn` in a Sources or Maps-to row). A doctrine domain missing from `Cited by` is a chapter to-do.", "",
      "| # | Title | Domains | Cited by | Note |", "|---|---|---|---|---|"]
for m, ds, note in MT10_DOCTRINE:
    cited = [d for d in doms if m in mt_cite[d]]
    L.append("| %s | %s | %s | %s | %s |" % (m, mt10.get(m, ""), ds, ", ".join(cited) or "—", note))
L += ["", "---", "", "## 4. ATT&CK Mobile — what applies and what does not", "",
      "Of the %d Android-applicable techniques, roughly a third describe **malware behaviour** rather than an" % len(attack),
      "app weakness. Do not waste tester time on those. The split:", "",
      "**Directly testable against a client app** — every technique at least one item cites, with the citing domains:", "",
      "| Technique | Domains (items) | The question a tester asks |", "|---|---|---|"]
tested = []
for r in xw:
    if r["standard"] == "attack" and int(r["n_items"]) > 0:
        tested.append(r)
tested.sort(key=lambda r: tnum(r["standard_id"]))
stray = []
for r in tested:
    tid = r["standard_id"]; ds = collections.Counter(i[:3] for i in r["item_ids"].split(";") if i)
    q = QUESTION.get(tid) or (QUESTION["T1636"] if tid.startswith("T1636.") else "")
    if tid in MALWARE: stray.append("%s (%s)" % (tid, ", ".join(sorted(ds))))
    L.append("| %s %s | %s | %s |" % (tid, attack.get(tid, r["title"]), ", ".join("%s (%d)" % kv for kv in sorted(ds.items())), q))
L += ["", "**Malware-side, out of scope for an app assessment** — record once, do not test:",
      ", ".join("%s %s" % (t, attack.get(t, "")) for t in MALWARE) + ".", "",
      "These describe what an attacker's *own* malware does. A client app is not made insecure by them. The",
      "exception is when the client app is itself a security product — then they become requirements."]
if stray: L += ["", "_Cited by items although listed malware-side (the item argues an app-side defence; keep or re-map): %s._" % "; ".join(stray)]
L += ["", "---", "", "## Known gaps (from `crosswalk.csv` rows with `n_items = 0`)", ""]
mw0 = [r for r in xw if r["standard"] == "maswe" and int(r["n_items"]) == 0]
L += ["**MASWE weaknesses no item cites** (%d of %d):" % (len(mw0), sum(1 for r in xw if r["standard"] == "maswe")), ""]
for r in mw0: L.append("- %s %s — %s" % (r["standard_id"], r["title"], GAP_NOTE.get(r["standard_id"], "unassigned: decide chapter candidate or out of scope")))
cur_all = [t for t, r in tests.items() if r["status"] == "current"]
xw_n = {(r["standard"], r["standard_id"]): int(r["n_items"]) for r in xw}
cur_uncited = [t for t in cur_all if xw_n.get(("mastg", t), 0) == 0]
L += ["", "**MASTG tests:** %s" % ("all %d current MASTG v2 Android tests are cited by at least one item." % len(cur_all) if not cur_uncited
      else "%d of %d current MASTG v2 Android tests are cited by no item: %s." % (len(cur_all) - len(cur_uncited), len(cur_all), ", ".join(short(t) for t in sorted(cur_uncited))))]
dep = {d: s[1] for d, s in stats.items() if s[1]}; ph = {d: s[2] for d, s in stats.items() if s[2]}
if dep: L.append("Deprecated v1 ids still cited (marked above; rewrite to the successor when the item is next touched): " + ", ".join("%s (%d)" % kv for kv in sorted(dep.items())) + ".")
if ph: L.append("Placeholder ids cited by items — **must be replaced** (cite the MASWE instead): " + "; ".join("%s: %s" % (d, ", ".join(short(t) for t in ts)) for d, ts in sorted(ph.items())) + ".")
att0 = [r for r in xw if r["standard"] == "attack" and int(r["n_items"]) == 0 and r["standard_id"].split(".")[0] not in MALWARE]
L += ["", "**ATT&CK techniques neither cited nor listed malware-side** (%d) — each is either a chapter to-do or belongs in the malware list:" % len(att0), "",
      ", ".join("%s %s" % (r["standard_id"], attack.get(r["standard_id"], "")) for r in sorted(att0, key=lambda r: tnum(r["standard_id"]))) + "."]
S, E = "<!-- generated:" + "start -->", "<!-- generated:" + "end -->"
path = os.path.join(ROOT, "docs", "07-coverage-crosswalk.md")
txt = open(path, encoding="utf-8").read()
a, b = txt.index(S) + len(S), txt.index(E)
open(path, "w", encoding="utf-8").write(txt[:a] + "\n" + "\n".join(L) + "\n" + txt[b:])
print("docs/07 regenerated: %d domains, %d planned, %d testable ATT&CK, %d MASWE gaps" % (len(idx["domains"]), len(PLANNED), len(tested), len(mw0)))
EOF
```

Doctrine that cannot be derived (VRT ceilings, the Mobile Top 10 domain mapping, the tester questions, the
malware-side list, the MASWE gap dispositions) lives in the small dicts at the top of that script; edit them there.
