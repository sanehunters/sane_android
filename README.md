<div align="center">

# sane_android

### An Android bug-bounty methodology built to be **executed by an autonomous AI model**, not read by a human

26 chapters · 1,933 addressable test items (D24 and D28 in progress) · a state machine with mechanical gates · a
harness that keeps the agent honest and its evidence pushed to a private evidence repository

[![Start here](https://img.shields.io/badge/MODEL%3F_START_HERE-START.md-0E8A16?style=for-the-badge)](START.md)
[![Index](https://img.shields.io/badge/DOMAIN_INDEX-CHECKLIST.md-1D76DB?style=for-the-badge)](CHECKLIST.md)
[![Audit](https://img.shields.io/badge/WHAT_CHANGED-docs%2F08-B60205?style=for-the-badge)](docs/08-senior-audit-2026-10.md)

</div>

---

## If you are a model

Read [`START.md`](START.md). It is the only file you must read in full; it tells you which situation you
are in, the eight rules, the exact bootstrap sequence, the P0–P9 state machine with its gates, how to work
one domain, how to record, and what to load (never a whole chapter). Everything else is loaded per item.

## If you are a human

You supply an APK (or package), a scope and an authorisation basis, and paste
[`prompts/00-bootstrap.md`](prompts/00-bootstrap.md) into a fresh session of any frontier model (Claude Code,
Codex, Gemini CLI, Cursor…). The session creates a dated engagement folder (its own git repository), works 26 domains of checkpoints
tracked as rows, proves primitives from a zero-permission attacker app, chains them into payable impact
categories in a dedicated phase, records what it ruled out and why, and pushes the evidence to a private remote as it goes — never to this public repository.
You read `BugBountyTarget/<Target>_<date>/report/assessment-status.md` and the findings.

---

## Why this exists — two failure modes it is engineered against

**1. Reports full of findings worth nothing.** Run a scanner, paste the red rows, check them against the
Bugcrowd VRT (mirrored in [`data/vrt.csv`](data/vrt.csv)): absent pinning, `allowBackup`, tapjacking, root
detection, *even sensitive data stored unencrypted on internal storage* — all **P5**. An Android finding pays
only when it is driven out of the mobile branch into access-control, authentication, injection or data
exposure. An exported component is a **primitive**; Phase 7 exists to convert primitives into impact.

**2. The agent finds one good bug and stops looking.** Hour two: an arbitrary file read. Six hours later:
one finding, forty exported components never opened, and the programme pays an outside hunter for the
account takeover. That is a control-flow problem, so the fix is mechanical: **breadth before depth** is a
phase boundary, leads are parked in `hypotheses/`, and `scripts/gate.py p7` refuses to open escalation until
every checkpoint and every component instance is settled.

---

## Architecture

```mermaid
flowchart LR
    subgraph ENTRY["Entry layer — any vendor"]
        S[START.md<br/>situation · rules · state machine]
        A[AGENTS.md<br/>the SOP]
        V[CLAUDE.md · GEMINI.md<br/>.cursor · copilot]
        P[prompts/<br/>bootstrap · resume · fan-out …]
        V --> S
        P --> S
        S --> A
    end

    subgraph KB["Knowledge — three loading tiers"]
        I[CHECKLIST.md<br/>26 domains · crux questions]
        C[cards/Dnn.md<br/>one line per item]
        IT[scripts/item.py Dnn-NNN<br/>one item in full]
        CH[checklist/Dnn-*.md<br/>source of truth]
        J[json/Dnn.json · json/index.json]
        D[docs/01…11<br/>doctrine]
        DATA[data/<br/>MASTG · MASWE · MASVS · VRT · ATT&CK<br/>regenerated from primary sources]
        I --> C --> IT
        CH -- build-checklist.py --> C
        CH -- build-checklist.py --> J
        CH -- build-checklist.py --> I
        DATA -. lint-checklist.py .-> CH
    end

    subgraph ENG["Engagement state — on disk, its own private git repo"]
        EJ[engagement.json<br/>phase · gates · identity · blockers]
        CSV[checklist-status.csv<br/>written only by mark.py]
        INV[inventory/*.csv<br/>C · U · W · E instances]
        H[hypotheses/H-NNN.md]
        F[findings/F-NNN · chains/X-NNN]
        AS[report/assessment-status.md<br/>the resume point]
    end

    subgraph TOOLS["Tooling"]
        DR[doctor.sh]
        NE[new-engagement.sh]
        ST[state.py · next.py]
        MK[mark.py · gate.py · coverage.py]
        TL[tools/01–09 sweeps + fuzzers]
        FR[frida/01–06]
        PA[attacker-app<br/>zero-permission probe]
    end

    subgraph HARNESS["Harness (.claude/)"]
        HK[hooks: session-start · prompt-context<br/>pre-bash · post-bash · stop-guard · pre-compact]
        SK[20 skills · loops/]
    end

    S --> DR --> NE --> EJ
    C --> ST --> IT
    IT --> TL & FR & PA
    TL & FR & PA --> MK --> CSV & INV
    MK --> EJ
    H --> F --> AS
    HK -. enforce R7 .-> ENG
    HK -. resume card .-> S
    SK --> ST & MK
```

### The three loading tiers

| Tier | File | Size | When a model loads it |
|---|---|---|---|
| 1 | [`CHECKLIST.md`](CHECKLIST.md) | 16 KB | once — which domains exist, their crux questions, the phase map |
| 2 | [`cards/Dnn.md`](cards/) | 10–30 KB | per domain — applicability probe, triage order, one line per item |
| 3 | `python3 scripts/item.py Dnn-NNN` | ~2 KB | per item — Test / How / Proof / Escalation / Ruled out when |
| — | [`checklist/Dnn-*.md`](checklist/) | 140–245 KB | only when writing the methodology; never during an engagement |

### The state machine

`P0 Scope → P1 Lab → P2 Acquire → P3 Inventory → P4 Static → P5 IPC → P6 Network/API → P7 Chain → P8 Evidence → P9 Report`

Each phase has an entry condition, work, an exit condition and a gate that is a **predicate over files**
(`scripts/gate.py <eng> p3`). A row counts as settled only when its result and notes satisfy the recording
contract; `completed=true` with no mechanism keeps the gate closed. Details: [`START.md`](START.md) §4.

### What is enforced, not merely stated

| Mechanism | Guarantee |
|---|---|
| `scripts/lint-checklist.py` (CI) | every item has its required fields (`docs/11`); every MASTG/MASWE/VRT id exists; cross-references resolve; no phantom domains; no vendor/laptop strings in operator docs |
| `scripts/build-checklist.py --check` (CI) | the cards, JSON, CSV and index are never stale relative to the chapters |
| `scripts/refresh-data.py` | `data/` is regenerated from the OWASP, Bugcrowd and MITRE repositories with provenance |
| `scripts/mark.py` | `ruled-out` needs a mechanism, `blocked` needs `needs:`, `n/a` needs a reason, a finding needs an id |
| `scripts/gate.py` | no phase advances on a feeling |
| `.claude/hooks/` | no destructive git; no APK/DEX/SO/keystore/credential in a commit; auto-push of the evidence repo after every commit (when a private remote is set); a session is blocked once from ending with unpushed engagement state; the resume card prints on every start |

---

## Repository map

| Path | What |
|---|---|
| [`START.md`](START.md) · [`AGENTS.md`](AGENTS.md) · [`CLAUDE.md`](CLAUDE.md) · [`GEMINI.md`](GEMINI.md) | entry point, SOP, vendor files |
| [`CHECKLIST.md`](CHECKLIST.md) · [`cards/`](cards/) · [`checklist/`](checklist/) · [`json/`](json/) · [`checklist.csv`](checklist.csv) · [`MASTER-CHECKLIST.md`](MASTER-CHECKLIST.md) | the checklist in its tiers |
| [`docs/`](docs/) | 01 architecture as attack surface · 02 severity doctrine · 03 lab · 04 evidence standard · 05 attacker models · 06 triage ladder · 07 coverage crosswalk · 08 senior audit · 09 coverage discipline · 11 item schema |
| [`scripts/`](scripts/) | doctor · new-engagement · state · next · mark · gate · coverage · item · inventory · apply-item-meta · build-checklist · lint-checklist · refresh-data · gh-sync · selftest |
| [`tools/`](tools/) · [`frida/`](frida/) · [`attacker-app/`](attacker-app/) | sweeps and fuzzers · runtime scripts · the zero-permission probe |
| [`prompts/`](prompts/) · [`loops/`](loops/) · [`.claude/`](.claude/) | vendor-neutral prompts · recurring self-checks · hooks and skills |
| [`templates/`](templates/) · [`BugBountyTarget/`](BugBountyTarget/) | report templates · the engagement folders (one dated folder per target, each its own private git repo — ignored here; only `README.md` and `_TEMPLATE/` are tracked) |
| [`data/`](data/) | the standards, regenerated — see [`data/README.md`](data/README.md) |
| [`ISSUES.md`](ISSUES.md) | how the GitHub issue tracker mirrors the methodology |

## Sources

Built from the Android platform documentation, OWASP MASTG / MASVS / MASWE, MITRE ATT&CK Mobile, the
Bugcrowd VRT, OWASP Mobile Top 10 2024, the Android Security Bulletins, Mobile Hacking Lab and Oversecured
research, disclosed HackerOne and Bugcrowd mobile reports, vendor VRP rules, MobSF and semgrep rule sets, the
HackTricks Android pages and ~20 community checklists. Every standards identifier is verified against the
primary repository at build time; the audit that reshaped the first build is in
[`docs/08-senior-audit-2026-10.md`](docs/08-senior-audit-2026-10.md).

## Authorisation

Every technique here is legal only against a target you are authorised to test. Read
[`SECURITY.md`](SECURITY.md). Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
