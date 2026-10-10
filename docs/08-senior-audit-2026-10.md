# 08 — Senior audit of this repository (October 2026)

> A record of what was wrong with the first build of this methodology, what was changed, and why. Kept in
> the repository on purpose: a model operating this checklist should know where the previous version was
> unreliable, and a maintainer should be able to see every structural decision with its evidence.
>
> **Status legend:** ✅ fixed · 🔧 in progress · 📋 planned · ❌ won't fix (with reason)

## 0. Verdict

The first build (26 chapters, 1,933 items) is **worth keeping and rebuilding around, not discarding**:

- Every one of the 917 distinct MASTG/MASWE identifiers cited across the chapters exists in the OWASP
  repositories (verified by filename against local clones of `owasp-mastg` and `maswe`). Nothing was invented.
- Every item carries the full five-field body (`Test / How / Proof / Escalation / Ruled out when`) and the
  five metadata rows. The doctrine (severity, attacker models, breadth-before-depth) is sound and opinionated.

What was broken was the **machinery around the content** and its **fitness for a model operator**, plus a
set of **structural holes** (a missing domain that thirty places point at, a phantom domain, an issue tracker
covering 11 of 26 domains, operator-laptop and single-vendor assumptions). Those are fixed or being fixed below.

## 1. Logical and data defects (objective, machine-checked)

| # | Defect | Evidence | Impact | Status |
|---|---|---|---|---|
| L1 | **Severity parser collapsed every nuanced ceiling to `support`.** The chapters write ceilings like `Medium standalone; High with a reach primitive` or `**High**`; the generator only accepted five bare words, so 561 of 1,933 rows were written to `checklist.csv` as `support`. | Published mix was 333 critical / 436 high / 165 medium / 32 low / 967 support. True mix: **542 critical / 649 high / 196 medium / 47 low / 496 support / 3 varies**. D03 showed "⬜76" (all support) when it holds 21 critical and 42 high. | Coverage ordering, the "ceiling mix" tables, the P7 gate's sense of what is left, and every downstream triage priority were wrong for 29% of items. | ✅ `scripts/build-checklist.py` now parses ceiling, standalone floor and keeps the raw note (`severity`, `severity_floor`, `severity_note`). |
| L2 | **A `##` heading inside a fenced code block truncated the item.** Eight items (D02-071, D05-064, D06-081, D07-076, D13-009, D20-069, D23-066, D25-078) lost their `Proof / Escalation / Ruled out when` in every generated view. | `re.split(r'\n##\s', body)` in the old generator. | Those items looked incomplete to any consumer of the CSV/master file. | ✅ Fence-aware section cutting in the generator and the linter. |
| L3 | **D24 does not exist but is load-bearing.** "Push, notifications, messaging" is referenced in the build script's phase map, `docs/05`, `docs/07`, `ISSUES.md` (P6 domain list) and 17 chapter escalations. | `grep -rn D24` → 30+ hits, no chapter. | A model following an escalation arrow lands nowhere; P6 lists a domain it cannot open. | 🔧 D24 chapter being written (see §4). |
| L4 | **Phantom D28** referenced 12 times with three different meanings (OAuth, backup/restore, share-receiver, notification listener). | `grep -rn D28` | Same as L3. | ✅ References remapped to the real owners (D13 OAuth, D11 backup, D07 share-receiver, D24 notifications). D28 is reserved for the new AI/LLM-in-app domain. |
| L5 | **"27 domains" claimed; 26 exist.** README, CLAUDE.md, prompt.md, flow.md, `docs/07`. | counts | Credibility; a model counting domains finds a mismatch. | 🔧 Resolves when D24 and D28 land (28 domains); all counts are now generated, not typed. |
| L6 | Three invalid Bugcrowd VRT paths (`broken_cryptography.*` without the `cryptographic_weakness.` prefix in D12 prose; `server_side_injection.server_side_request_forgery_ssrf` in D15-090 — SSRF lives under `server_security_misconfiguration`). | VRT JSON release 2026-07-08 | A model copying the path into a report would cite a node that does not exist. | ✅ |
| L7 | Two dangling item references (D13-026 → `D13-091`, D16-024 → `D16-062`); 13 `Attacker` cells with no attacker-model id (`unchanged`, `varies`, `Follows the CVE`…); one false "link" inside a JS code block. | linter | A model resolving references fails. | ✅ Prose fixed; the two referenced items are added in the rebuild (Restore Credentials, managed→native overflow). |
| L8 | Generated artefacts were **stale relative to the chapters** and nothing checked it. | no `--check` mode, no CI step | Silent drift between source and tracker. | ✅ `build-checklist.py --check` + CI job (see §3). |
| L9 | Eight item titles duplicated across domains. | `checklist.csv` | Ambiguous `--grep` hits. | 📋 Resolved per-domain in the rebuild (merge or cross-reference). |

## 2. Conceptual defects for a frontier-model operator

| # | Defect | Why it matters for a model | Status |
|---|---|---|---|
| C1 | **Nothing was addressable.** The only ways to read an item were a 140–245 KB chapter (35–60k tokens) or a 913 KB master file (~230k tokens). Reading all 26 chapters is ~1.3M tokens. | A model cannot "load the checklist"; it must load the *right 2 KB*. | ✅ Three tiers: `CHECKLIST.md` index → `cards/Dnn.md` (one line per item, 10–30 KB) → `python3 scripts/item.py Dnn-NNN` (one item, ~2 KB) → chapter only when writing. `json/Dnn.json` + `json/index.json` for programmatic access. |
| C2 | **The tracker copied 1.1 MB of prose into every engagement.** `checklist.csv` carried `maps_to` and `vrt_path` text. | Every `coverage.py` run and every CSV edit touched a megabyte; diffs were unreadable. | ✅ Slim tracker (344 KB): id, domain, phase, title, ceiling, floor, attacker, VRT priority, short applies-to, status columns. Metadata lives in `json/`. |
| C3 | **Vendor lock-in.** "Claude Opus 5" named in README/CLAUDE/AGENTS/prompt/flow/SKILL; "1M-token context and ultracode enabled" asserted in the bootstrap prompt. | The target audience is *any* frontier model. A GPT/Gemini/Codex/Cursor session has no entry file (`AGENTS.md` existed but pointed at Claude-specific assumptions). | 🔧 Vendor-neutral `START.md` as the single entry; `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `.github/copilot-instructions.md` all point to it. |
| C4 | **Operator-laptop lock-in.** macOS SDK/JBR paths, `sed -i ''` (BSD), "push to your Mac", a hardcoded `~/AndroidStudioProjects/lamppentest` dual-write mirror, "never launch an AVD from Bash — it hangs" (true of one machine). | Fails on Linux (the author's current host is Kali) and on any other operator's machine. | ✅ `new-engagement.sh` is portable; the mirror is opt-in via `SANE_LOCAL_MIRROR`. 🔧 Environment detection (`scripts/doctor.sh`) replaces hardcoded paths; SKILL.md rewritten. |
| C5 | **No machine-readable engagement state.** Phase, gates and blockers lived only in prose (`assessment-status.md`) and in the agent's context. | After a context compaction or a new session nothing can *compute* "where am I". Hooks and loops have nothing to read. | ✅ `engagement.json` (phase, gates, target identity, blockers, domain applicability) created by `new-engagement.sh`; `scripts/state.py` renders the resume card from disk. |
| C6 | **No harness.** No hooks to stop a session from ending with unpushed evidence, no block on committing an APK or a credential, no automatic resume card, no slash commands, no loop definitions. | The doctrine said "commit and push after every phase"; nothing enforced it. | 🔧 `.claude/` harness: hooks (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop, PreCompact), skills, loops, prompts — see `docs/10-agent-harness.md`. |
| C7 | **Phase time budgets in human days** ("P4: 3 days"). | Meaningless to a model; what it needs are exit conditions and tool-call budgets per item. | 🔧 Budgets restated as exit conditions + per-item call budgets (the three-strike rule, already in docs/09). |
| C8 | **No domain-level applicability probe.** `Applies to` existed per item, but nothing told a model how to decide in two commands that an app has no WebView and mark all 72 D10 rows `n/a` with one reason. | A model either wastes a domain's worth of calls or skips it without a defensible mechanism. | 🔧 Every chapter gets an `## Applicability probe` section (commands → decision → the exact `notes` text to write); the card surfaces it. |
| C9 | **Work queue covered 42% of the checklist.** GitHub domain issues existed for D01–D11 only. | `AGENTS.md` called the issues "your work queue and your SOP". | 📋 Issues for D12–D28 generated from the cards; phase issues updated. |
| C10 | **No verification layer for the checklist itself.** No linter, no ID check against MASTG, no VRT path check, no dead-link check. | An LLM-written corpus drifts; the first build's own doctrine ("never invent an identifier") had no enforcement. | ✅ `scripts/lint-checklist.py` + `data/standards-index.csv` (1,073 ids regenerated from the OWASP clones) + CI. |
| C11 | **Docs numbered 01–07, 09.** The gap suggested a missing doctrine file. | Minor, but a model notices. | ✅ This file is 08. |
| C12 | **Modern surfaces thin or absent** (Android 15/16 intent-redirect launch protections, OTP redaction from notification listeners, Credential Manager / passkeys / Restore Credentials, Privacy Sandbox / SDK Runtime, AI/LLM features embedded in apps, Wear/TV/Auto form factors, Android Enterprise). | A 2026 checklist must cover 2026 attack surface. | 🔧 Being measured by the coverage critics; gaps land per domain plus D24 and D28. |

## 3. What enforces this from now on

| Mechanism | Guarantees |
|---|---|
| `python3 scripts/lint-checklist.py` (CI, every push) | format, contiguous ids, attacker ids, VRT paths in the taxonomy, MASTG/MASWE ids in `data/standards-index.csv`, cross-references resolve, no phantom domains, no dead links, no vendor/laptop strings in operator docs |
| `python3 scripts/build-checklist.py --check` (CI) | generated views are never stale |
| `python3 scripts/refresh-data.py` | regenerates `data/` from the OWASP and VRT repositories so identifiers cannot rot |
| `.claude/hooks/*` | no session ends with unpushed engagement state; no APK/credential enters git; resume card on every start |

## 4. The deep audit (in progress)

Sixty-two independent reviewers are working the chapters and infrastructure against the local OWASP MASTG,
MASWE, MASVS, HackTricks, Bugcrowd VRT and lab-app sources: one senior reviewer per chapter (technical
errors, coverage gaps, operability, redundancy, severity), one adversarial verifier per chapter (every
claimed error must survive refutation before it is applied), seven infrastructure reviewers (code, docs,
entry points, GitHub layer, data, severity calibration, harness design) and three coverage critics
(standards, community corpus, modern platform + AI). Their confirmed findings are applied per chapter and
summarised in §5 as they land.

## 5. Per-chapter changes (filled in as the rebuild lands)

_pending_
