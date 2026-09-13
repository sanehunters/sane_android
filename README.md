<div align="center">

# sane_android

### A bug-bounty-grade Android application penetration testing methodology

**Not a scanner checklist. A system for finding bugs that actually pay.**

[![Engagement Board](https://img.shields.io/badge/Engagement_Board-Projects_v2-1D76DB?logo=github)](https://github.com/orgs/sanehunters/projects/1)
[![Start here](https://img.shields.io/badge/Start_here-ISSUES.md-0E8A16)](ISSUES.md)
[![Severity doctrine](https://img.shields.io/badge/Read_first-Severity_doctrine-B60205)](docs/02-severity-and-reportability.md)

</div>

---

## The problem this exists to solve

Run MobSF against a client's app. Paste the red rows into a report. Ship it.

Now check those findings against the Bugcrowd VRT:

| Finding | VRT priority |
|---|---|
| SSL certificate pinning absent | **P5** |
| SSL certificate pinning defeatable | **P5** |
| Auto backup allowed by default | **P5** |
| Tapjacking | **P5** |
| Lack of jailbreak/root detection | **P5** |
| Clipboard enabled | **P5** |
| Screen caching enabled | **P5** |
| **Sensitive application data stored unencrypted on internal storage** | **P5** |

P5 is Informational. That report contains no findings. It is why clients churn vendors, and it is the gap
this repository closes.

> The entire `mobile_security_misconfiguration` branch of the taxonomy is rated P5. **An Android finding
> is worth money only when you move it out of the mobile branch and into the access-control,
> authentication, injection or data-exposure branches** — which is where P1 and P2 live.

Everything here is organised around that conversion. An exported component is a **primitive**, not a
finding. Phase 7 of the workflow exists entirely to turn primitives into impact.

---

## What is in here

| | |
|---|---|
| **[`ISSUES.md`](ISSUES.md)** | **Start here.** The ordered engagement workflow: what to do first, second and third, across ten phases, with entry and exit conditions for each. |
| **[`CHECKLIST.md`](CHECKLIST.md)** | Index into 27 domain chapters. Every item carries a test, an exact command, the observable that proves it, a severity ceiling with its VRT path, an attacker model, and an escalation. |
| **[`checklist/`](checklist/)** | The 27 domain chapters. |
| **[`docs/`](docs/)** | The doctrine: architecture as attack surface, severity, lab harness, PoC standard, attacker models, triage playbook, coverage crosswalk. |
| **[`templates/`](templates/)** | Finding report, assessment report, ruled-out register, scoping questionnaire. |
| **[`tools/`](tools/)** | Seven executable sweep harnesses. Every one emits candidates, never findings. |
| **[`data/`](data/)** | Machine-extracted standards datasets. No transcribed IDs. |

### The datasets are extracted, not typed

Every mapping identifier in this repository was pulled programmatically from the primary source, so no
citation here is invented:

| Dataset | Rows |
|---|---|
| OWASP MASTG Android tests (51 stable + 112 beta) | **163** |
| MASTG Android techniques | **78** |
| MASTG Android tools | **48** |
| MASTG static-analysis rules | **51** |
| MITRE ATT&CK Mobile, Android-applicable techniques | **122** |
| Bugcrowd VRT entries, release 2026-07-08 | **581** |

---

## How the team runs an engagement on GitHub

This repository is not documentation you read once. It is the working surface.

```
Open a 🎯 Engagement issue          ->  parent tracker for the client
Work phases P0..P9 in order          ->  Milestones M0..M9 give you a progress bar per phase
Work the domain issues in each phase ->  each is a test battery of checkboxes
Test produces something?             ->  open a 🐞 Finding issue
Test comes back clean?               ->  open a ✅ Ruled-out issue   (this is also a deliverable)
Checklist missed something?          ->  open a 📋 Checklist gap issue, the same week
```

| Mechanism | Role |
|---|---|
| **Milestones** `M0`–`M9` | The ten engagement phases |
| **Methodology & checklist issues** | Permanent reference. Labelled `do-not-close`. **Never closed.** |
| **Finding & ruled-out issues** | Per-engagement output. These do get closed. |
| **Labels** | `phase:` `area:` `sev:` `am:` for filtering; `high-yield` and `graveyard` for where to spend the week |
| **[Project board](https://github.com/orgs/sanehunters/projects/1)** | Columns: Reference → Not started → Testing → Blocked → Evidence → Finding → Reported → Clean. Fields: Phase, Domain, Severity, Attacker Model, VRT Path, Engagement |

Progress is tracked by **moving cards and opening new issues**, never by closing the methodology.

---

## What makes this different

**It tells you what not to test.** The `graveyard` label marks classes that are near-universally out of
scope: pinning bypass, root detection, missing obfuscation, unverified hardcoded keys, backup of
non-sensitive data. Knowing where not to spend a day is worth as much as knowing where to.

**Negative results are a deliverable.** The [ruled-out register](templates/ruled-out-table.md) records
what was tested and found clean, and **the mechanism that closes it** — not the tool that missed it. A
findings list without one looks like a sample; with one it looks like an audit.

**It is built to stop you fooling yourself.** A tool's silence is never a negative result. Normalise
before you diff. Establish the error oracle before injection testing. Check for the second
implementation — the most instructive retraction on record had entirely accurate `file:line` citations
and was still wrong.

**Every dynamic finding ships with a video**, in a fixed seven-beat format with a negative control in the
same take and a planted canary value. See the [PoC standard](docs/04-poc-and-evidence-standard.md).

**Attacker models are explicit.** AM-01 to AM-12, with the rule: report the weakest attacker that still
works. AM-12, an attacker rooting their own phone to read their own token, is marked as what it is —
not an attack.

---

## Quick start for a new tester

1. Read [`docs/02 — Severity & Reportability`](docs/02-severity-and-reportability.md). Twenty minutes.
   It will change what you report.
2. Read [`ISSUES.md`](ISSUES.md). That is the workflow.
3. Build the lab from [`docs/03`](docs/03-lab-and-harness.md) and run its verification block.
4. Practise on a deliberately vulnerable app — OVAA, InsecureShop, InjuredAndroid, DIVA, Damn Vulnerable
   Bank, or the OWASP MAS Crackmes. Never on production.
5. Pick up a domain issue labelled `good-first-hunt`.

---

## Sources

Built from the Android platform architecture and security documentation, OWASP MASTG/MASVS/MASWE, MITRE
ATT&CK Mobile, the Bugcrowd Vulnerability Rating Taxonomy, OWASP Mobile Top 10, Exploit-DB and the
Android Security Bulletins, Mobile Hacking Lab research, the Oversecured vulnerability-class corpus,
disclosed HackerOne and Bugcrowd mobile reports, vendor VRP rules, and the community checklists that
came before this one. Per-item provenance is in the domain chapters.

---

## Authorisation

Every technique here is legal only against a target you are authorised to test. Read
[`SECURITY.md`](SECURITY.md) before your first engagement. Contributions are governed by
[`CONTRIBUTING.md`](CONTRIBUTING.md).
