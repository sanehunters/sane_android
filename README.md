<div align="center">

# sane_android

### An Android bug-bounty methodology built to be **executed by Claude Opus 5**, not read by a human

You supply an APK. The session loads the SOP from this repo, opens a dated engagement folder,
works 27 domains of checkpoints tracked as `true`/`false`, chains every primitive into a payable
impact category, records what it ruled out and why, and pushes the evidence to GitHub and your Mac
at the same time.

[![Start here](https://img.shields.io/badge/START_HERE-prompt.md-0E8A16?style=for-the-badge)](prompt.md)
[![Board](https://img.shields.io/badge/Engagement_Board-Projects_v2-1D76DB?style=for-the-badge&logo=github)](https://github.com/orgs/sanehunters/projects/1)
[![Checklist](https://img.shields.io/badge/MASTER-CHECKLIST-B60205?style=for-the-badge)](MASTER-CHECKLIST.md)

</div>

---

## Two problems this exists to solve

### 1. The reports are full of findings that are worth nothing

Run MobSF, paste the red rows. Now check them against the Bugcrowd VRT (release 2026-07-08, mirrored in
[`data/bugcrowd-vrt-full.csv`](data/bugcrowd-vrt-full.csv)):

| Finding | VRT |
|---|---|
| SSL certificate pinning absent / defeatable | **P5** |
| Auto backup allowed by default | **P5** |
| Tapjacking | **P5** |
| Lack of root detection | **P5** |
| **Sensitive application data stored unencrypted on internal storage** | **P5** |

P5 is Informational. That report contains no findings.

> **An Android finding is worth money only when you move it out of the mobile branch of the taxonomy and
> into access-control, authentication, injection or data-exposure** — which is where P1 and P2 live.
> An exported component is a **primitive**, not a finding. Phase 7 exists entirely to convert them.

### 2. The agent finds one good bug and stops looking

An agent sweeping an app finds an arbitrary file read in hour two. It is genuinely interesting, so it
chases it. Six hours later it has one finding and has never opened the WebView, the deep-link router or
the other forty exported components. The client's programme then pays an outside hunter for the account
takeover nobody looked for.

That is a **control-flow problem**, not a knowledge problem, so the fix is mechanical:

> **Breadth before depth.** During P3–P6 escalation is *forbidden*. Confirm the primitive, park a stub in
> `hypotheses/`, flip the row, move on. `coverage.py --gate p7` **exits non-zero** until every checkpoint
> and every component instance is settled. Depth is earned by breadth.

Full doctrine: [`docs/09-coverage-discipline.md`](docs/09-coverage-discipline.md).

---

## Start an engagement

```bash
# 1. open a fresh Claude Code session and paste prompt.md with the four slots filled
# 2. that session does the rest:
git clone https://github.com/sanehunters/sane_android.git ~/sane_android
~/sane_android/scripts/new-engagement.sh Nisho          # GitHub folder + local mirror + tracker
python3 ~/sane_android/scripts/inventory.py base.apk --out <eng>/inventory/
python3 ~/sane_android/scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ --gate p7
```

---

## What is in here

| | |
|---|---|
| **[`prompt.md`](prompt.md)** | **The bootstrap prompt.** Fill four slots, paste into a fresh session, walk away. |
| **[`CLAUDE.md`](CLAUDE.md)** | Standing orders, auto-loaded by Claude Code. Six rules, starting with breadth-before-depth. |
| **[`AGENTS.md`](AGENTS.md)** | The SOP, written for a session with no prior context. |
| **[`flow.md`](flow.md)** | How prompt + repo + skill + engagement folder combine, with a diagram. |
| **[`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md)** | **Every item, from every source, in one file.** |
| **[`checklist.csv`](checklist.csv)** | The same items as rows. Becomes `checklist-status.csv` per engagement. |
| [`CHECKLIST.md`](CHECKLIST.md) · [`checklist/`](checklist/) | The navigable index and the 27 domain chapters |
| [`ISSUES.md`](ISSUES.md) | The ordered ten-phase workflow |
| [`docs/`](docs/) | Architecture, severity, lab, PoC standard, attacker models, triage, crosswalk, coverage discipline |
| [`BugBountyTarget/`](BugBountyTarget/) | One dated folder per engagement. The permanent archive. |
| [`attacker-app/`](attacker-app/) | The zero-permission APK that makes AM-03 claims real |
| [`frida/`](frida/) | Six runtime scripts with the correctness rules baked in |
| [`tools/`](tools/) | Seven sweep harnesses — all emit candidates, never findings |
| [`scripts/`](scripts/) | `new-engagement.sh` · `inventory.py` · `coverage.py` · `build-checklist.py` |
| [`skills/android-bounty/`](skills/android-bounty/) | Claude Code skill that auto-loads the methodology |
| [`data/`](data/) | Machine-extracted standards datasets |

### The identifiers are extracted, not typed

Every mapping ID was pulled programmatically from the primary source, so no citation here is invented:

| Dataset | Rows |
|---|---|
| OWASP MASTG Android tests (51 stable + 112 beta) | **163** |
| MASTG Android techniques · tools · rules | **78 · 48 · 51** |
| MITRE ATT&CK Mobile, Android-applicable techniques | **122** |
| Bugcrowd VRT entries, release 2026-07-08 | **581** |

---

## How the team runs on GitHub

```
Open a 🎯 Engagement issue          → parent tracker for the client
Work phases P0..P9 in order          → Milestones M0..M9 give a progress bar per phase
Work the domain issues in each phase → each names the exact files to read; no repo exploration needed
Test produced something?             → 🐞 Finding issue
Test came back clean?                → ✅ Ruled-out issue   (also a deliverable)
Checklist missed something?          → 📋 Checklist gap issue, the same week
```

| Mechanism | Role |
|---|---|
| **Milestones** `M0`–`M9` | The ten engagement phases |
| **`do-not-close` issues** | Permanent methodology. Progress is tracked by opening *new* issues, never by closing these |
| **Labels** | `phase:` `area:` `sev:` `am:` for filtering · `high-yield` and `graveyard` for where to spend the week |
| **[Project board](https://github.com/orgs/sanehunters/projects/1)** | Reference → Not started → Testing → Blocked → Evidence → Finding → Reported → Clean, with Phase, Domain, Severity, Attacker Model and VRT Path fields |
| **Actions** | `coverage.yml` publishes each engagement's coverage; `hygiene.yml` blocks committed APKs and live-looking credentials |

---

## What makes this different

**It tells you what not to test.** The `graveyard` label marks classes that are near-universally out of
scope. Knowing where not to spend a day is worth as much as knowing where to.

**Negative results are a deliverable.** Every clean sweep records **the mechanism** that closes it, with
`file:line` — never "the scanner found nothing". A findings list without a ruled-out register looks like
a sample; with one it looks like an audit.

**Coverage is two-dimensional and external.** `checklist-status.csv` proves the methodology was walked.
`inventory/components.csv` proves *every component in this app* was individually tested — which is the
sentence the client is actually paying for.

**It is built to stop the agent fooling itself.** Normalise before you diff. Establish the error oracle
before injection testing. Beware the layer-ordering trap. Check for the second implementation — the most
instructive retraction on record had entirely accurate `file:line` citations and was still wrong.

**Every dynamic finding ships with a video** in a fixed seven-beat format, with a negative control in the
same take and a planted canary value.

---

## Sources

Built from the Android platform architecture and security documentation, OWASP MASTG/MASVS/MASWE, MITRE
ATT&CK Mobile, the Bugcrowd VRT, OWASP Mobile Top 10, Exploit-DB and the Android Security Bulletins,
Mobile Hacking Lab research, the Oversecured vulnerability-class corpus, disclosed HackerOne and Bugcrowd
mobile reports, vendor VRP rules, MobSF and semgrep rule sets, and ~20 community checklists — mined into
a 75,000-line research corpus, then merged. Per-item provenance is in the domain chapters.

## Authorisation

Every technique here is legal only against a target you are authorised to test. Read
[`SECURITY.md`](SECURITY.md) before your first engagement. Contributions:
[`CONTRIBUTING.md`](CONTRIBUTING.md).
