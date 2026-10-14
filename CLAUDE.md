# CLAUDE.md — standing orders for Claude Opus 5.5 / Opus 5 in Claude Code

This repository is operated by **Claude Opus 5.5** (`claude-opus-5-5`, primary) or **Claude Opus 5**
(`claude-opus-5`, fallback) running in Claude Code (v2.1.280 or later for Opus 5.5). Claude Code loads this file
into every session and every subagent, so it is deliberately short. The methodology is
[`START.md`](START.md) — entry point and state machine; **your first action in a new session is to read it in
full** — and [`AGENTS.md`](AGENTS.md), the SOP. The operating layer (model, effort, context, agents,
workflows, interruptions) is [`docs/10-agent-operations.md`](docs/10-agent-operations.md). Nothing in this file
overrides `START.md`.

## Model and defaults

| Setting | Value | Set in |
|---|---|---|
| Model | `claude-opus-5-5` (pin the full id; aliases drift) | `.claude/settings.json` `"model"` |
| Fallback | `claude-opus-5`, used automatically on availability failures | `"fallbackModel"` |
| Effort | `high` for both models; the three verifier lenses and `chain-lead` run at `xhigh` | `"modelSettings"` → `effortLevel`; agent `effort` |
| Subagents | `inherit`: they run on the session model, so a manual `/model` switch reaches them too | agent `model` frontmatter |
| Manual switch | `/model claude-opus-5` when Opus 5.5 is unavailable (usage limit, credits, outage); `/model claude-opus-5-5` to return | docs/10 §1 |

## Authorisation travels with every delegation

The `START.md` §1 authorisation gate comes before anything else. Every subagent brief, workflow invocation and
`/loop` prompt states, in its first lines, the authorisation basis, programme and in-scope assets exactly as
`engagement.json.authorisation` records them, and every agent writes that line first in its work log. No
recorded basis, no delegation.

## Where evidence goes (this repository is public)

The methodology repo holds no engagements. Each engagement folder `BugBountyTarget/<Target>_<DDMMYYYY>/` is
**its own git repository — the evidence repo** — created by `scripts/new-engagement.sh`, ignored by this repo's
`.gitignore` and refused by the PreToolUse hook. Evidence is committed there (`git -C "$E" add -A && git -C "$E"
commit`) and pushed only to a **private** remote the operator supplies: `SANE_EVIDENCE_REMOTE=<git url>` or
`scripts/new-engagement.sh <Target> --remote <url>` (recorded as `engagement.json.evidence_remote`). When no
remote is configured the hooks say "no evidence remote configured: evidence is committed locally only — set
SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>" and never push anything to the methodology
origin. `SANE_PUSH=0` disables the auto-push for a session. Subagents never commit or push; the coordinator does.

## Hooks

| Hook | What it does | Where |
|---|---|---|
| **SessionStart** | prints the resume card (`scripts/state.py`), the evidence-remote state and the environment line (`scripts/doctor.sh --brief`; an empty line is reported as UNVERIFIED) | `.claude/hooks/session-start.sh` |
| **UserPromptSubmit** | one line of phase + coverage (`scripts/coverage.py --brief`) + evidence-remote context on every turn | `.claude/hooks/prompt-context.sh` |
| **PreToolUse(Bash)** | blocks destructive git, recursive deletes of repository paths, staging engagement paths in the methodology repo, staging/committing APK/DEX/SO/keystore/key/HAR/PCAP, decompiled trees and secret dumps, and commits whose diff contains a live-looking credential or JWT — in the methodology repo and in the evidence repo | `.claude/hooks/pre-bash.sh` |
| **PostToolUse(Bash)** | after every commit pushes the **evidence repo** to its private remote (never the methodology origin; states the blocker when none is set); reminds you that `adb shell am …` is not AM-03 proof (R3); prints coverage after `mark.py` / `gate.py --pass` / `coverage.py --merge` | `.claude/hooks/post-bash.sh` |
| **Stop** | refuses to end the session while evidence is uncommitted, unpushed (only when an evidence remote exists) or `assessment-status.md` is stale — once; the second attempt passes | `.claude/hooks/stop-guard.sh` |
| **PreCompact** | snapshots the resume card to `state-snapshot.json` and appends a line to `logs/compactions.log` before context compaction | `.claude/hooks/pre-compact.sh` |

Set `SANE_ENGAGEMENT=BugBountyTarget/<Target>_<DDMMYYYY>` when more than one engagement exists; otherwise
the hooks pick the most recently updated one. `SANE_ENGAGEMENT_ROOT=/path` keeps engagements outside the checkout.

## Skills (`.claude/skills/*/SKILL.md`)

| When | Skills |
|---|---|
| Start, resume, orient | `/engage` · `/sane-resume` · `/sane-status` · `/sane-doctor` · `/lab` · `/opus` (operating notes: model, effort, context, when to fan out) |
| Breadth (P3–P6) | `/inventory` · `/domain` · `/item` · `/park` · `/ruled-out` · `/coverage` · `/breadth` (runs `/breadth-phase`) · `/fanout` |
| Verify and chain (P5–P7) | `/verify` (runs `/verify-candidates`) · `/chain` |
| Evidence and report (P8–P9) | `/evidence` · `/finding` · `/report` · `/triage` · `/retest` · `/push` |
| Methodology | `/gap` |

The `sane-` prefix avoids Claude Code's built-in `/resume`, `/status` and `/doctor`. The auto-skill
`android-bounty` triggers whenever an APK, package, manifest, deep link, WebView, provider, Frida, jadx or a
bounty programme is mentioned. `loops/` holds self-paced recurring checks for `/loop`.

## Subagents (`.claude/agents/*.md`)

| Agent | Phase | Job | Writes |
|---|---|---|---|
| `domain-worker` | P3–P6 | one domain: P3 its applicability probe; P4–P6 its items in card triage order, rows via `mark.py … --partial Dnn` | its partial CSVs, `logs/Dnn-*`, `hypotheses/H-Dnn-NN.md` |
| `verify-reproduce` | P5–P7 | lens 1: re-run the proof independently from the weakest attacker model | a verdict |
| `verify-guard` | P5–P7 | lens 2: find the guard, second implementation or platform gate that kills it | a verdict |
| `verify-triage` | P5–P7 | lens 3: read it as the programme's triager (VRT node, exclusions, P5 graveyard) | a verdict |
| `chain-lead` | P7 | the single P7 agent: every parked primitive, expected-value order | `chains/`, `findings/` |
| `evidence-reporter` | P8–P9 | evidence tree per `docs/04`, report per template, submission checklist | `findings/F-NNN/`, `final/` |
| `checklist-maintainer` | methodology | `/gap` and audit work under `docs/11` and lint | `checklist/`, never engagement files |

## Saved workflows (`.claude/workflows/*.js`)

| Workflow | Use | Then |
|---|---|---|
| `/breadth-phase` | "Run /breadth-phase for P5 on BugBountyTarget/<Target>_<DDMMYYYY>": one `domain-worker` per applicable domain, one lane per device; ends with `coverage.py --merge` | re-dispatch rejected rows; update `assessment-status.md`; commit the evidence repo |
| `/verify-candidates` | three lenses per candidate; survives with at least two of three not refuting | verdict table into `report/assessment-status.md`; commit |
| `/chapter-audit` | methodology maintenance: one review-only `checklist-maintainer` per chapter plus an adversarial verifier; edits nothing | fix the defects (`docs/11` vocabulary) via `/gap` or the agent |

`args` come from `engagement.json` (authorisation, `lab.mode`) and `scripts/doctor.sh --json` (devices); a workflow
refuses to start without a permitted basis and a recorded scope. A stopped run (interruption, usage limit) is
resumed or re-run for what is still open on disk; every worker's write is idempotent and re-checked against the
current text (docs/10 §5, §7). All agents of a session share one rate budget: never more device-bound workers than
devices (docs/10 §6). Operator messages sent mid-turn can cancel running agents.

## The rules in one breath

R0 breadth before depth (no escalation before P7) · R1 the checklist is the floor · R2 a primitive is not a
finding (the mobile VRT branch is P5) · R3 weakest attacker that still works; adb is not AM-03 · R4 negative
results name the mechanism · R5 do not fool yourself; never fabricate · R6 coverage is two CSVs on disk ·
R7 state on disk: committed in the evidence repo after every batch, pushed to its private remote when one exists.

## Decide, do not ask

You are operating autonomously. Decide which surface next, which tool, which domains to fan out, how to
structure a PoC, how to word a finding, whether a result is a true negative — and say what you decided. Ask the
operator only for what only they can supply (second account, OTP, KYC state, payment sandbox, scope decision,
hardware, the private evidence remote), by writing it into `engagement.json.blockers`.

## Never

Test an app you are not authorised to test · delegate work without the authorisation basis and scope in the
brief · use a real third party's account or data (plant canaries) · fabricate a CVE, report id, bounty figure,
CVSS vector or PoC · reconstruct a video for something you did not execute · commit an APK, a decompiled tree, a
credential or un-redacted third-party data · commit or push engagement evidence to the methodology repository
(it is public) · let a subagent commit or push · run two device-bound workers on one device · report a P5
standalone · claim coverage the CSVs do not show · end a session with uncommitted evidence.
