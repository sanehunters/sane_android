# 10 — Agent operations: running this methodology with Claude Opus 5.5 / Opus 5 in Claude Code

> `START.md` is the methodology and `AGENTS.md` the SOP; this file is the operating layer underneath them: the
> model, effort and context budget, the skills, subagents and saved workflows, the hooks lifecycle, and what
> interruptions do to a multi-agent run. It uses only documented Claude Code settings and frontmatter fields;
> when a session ignores one, `claude doctor` lists the rejected settings entries.

## 1. Model and fallback

| | Value | Where it is set |
|---|---|---|
| Primary model | Claude Opus 5.5, `claude-opus-5-5` (needs Claude Code v2.1.280 or later) | `.claude/settings.json` `"model"` |
| Fallback model | Claude Opus 5, `claude-opus-5` — used automatically on availability failures only | `.claude/settings.json` `"fallbackModel": ["claude-opus-5"]` |
| Effort | `high` for both models | `.claude/settings.json` `"modelSettings"` → `effortLevel` |

- Pin the full ids. The `opus` alias resolves to Opus 5.5 on most providers today, but aliases drift. The seven
  subagents set `model: inherit` in their frontmatter: they run on the session model, which the settings pin to
  `claude-opus-5-5`, so a manual `/model` switch (below) reaches every agent and workflow step as well.
- When Opus 5.5 is unavailable (a usage limit, exhausted credits, an outage) and the automatic fallback did not
  take over, switch the session with `/model claude-opus-5`, and back with `/model claude-opus-5-5` when it
  returns. The methodology, hooks, skills, agents and workflows are identical on both models; nothing else changes.
  Switching is an availability decision only.
- Claude Code documents classifier-based model routing for flagged requests, and documents security-testing
  workloads as frequently routed: expected routing, not an account flag. This repository sets nothing that
  changes or works around that behaviour.

## 2. Authorisation context in every delegation

Every prompt that hands work to another agent — a subagent brief, the `args` of a saved workflow, a `/loop`
prompt — states, in its first lines, the authorisation basis, the programme and the in-scope assets exactly as
`engagement.json.authorisation` records them (`basis`, `programme_url`, `scope`, `excluded`). Every agent writes
the same line first in its work log. A reviewer, human or model, needs that context to judge a security task, and
a worker that carries the scope in its own context cannot drift outside it. No recorded basis means no
delegation: the `START.md` §1 authorisation gate comes first.

## 3. Effort per phase

Opus 5.5 starts at `medium` unless a source sets a level; this repository sets `high`. The top-level
`effortLevel` setting accepts `low | medium | high | xhigh`; `max` is available only per agent (the agent's
`effort` frontmatter) or per workflow step (`agent(…, {effort})`).

| Phase | Who | Effort |
|---|---|---|
| P0–P2 scope, lab, acquire | the main session (coordinator) | `high` (project default) |
| P3–P6 breadth | `domain-worker`, one per domain | `high` |
| P5–P7 verification | `verify-reproduce`, `verify-guard`, `verify-triage` | `xhigh` (each agent's `effort` frontmatter) |
| P7 chain | `chain-lead`, one agent | `xhigh` (its `effort` frontmatter) |
| P8–P9 evidence and report | `evidence-reporter` | `high` |
| Methodology maintenance | `checklist-maintainer` | `high` |

Breadth is where the volume is, so it runs at the default; the extra effort is spent where a wrong verdict
is expensive: deciding whether a candidate survives, and building the chain. The workflows' bookkeeping steps
(resolving the domain list, the merge) set a lower effort per step.

## 4. Context budget

- `CLAUDE.md` is loaded into every session and into every subagent whose frontmatter does not set
  `omitClaudeMd`. That is why it stays under 200 lines and *points* to `START.md` instead of importing it with
  `@START.md`: an import would put the whole entry file (about 30 KB) into every domain worker.
- The coordinator reads `START.md` in full once per session. A worker reads `START.md` §2, §5 and §6 once, its
  card `cards/Dnn.md`, and one item at a time with `python3 scripts/item.py Dnn-NNN --brief`. Nobody loads a
  whole chapter, `MASTER-CHECKLIST.md` or a `json/Dnn.json` during an engagement (`START.md` §7).
- Hook context is capped at 10,000 characters, so the SessionStart resume card is a summary; the rest is one
  command away (`python3 scripts/state.py <eng> --json`, `python3 scripts/next.py <eng>`).
- Before a context compaction the PreCompact hook snapshots the resume card to `state-snapshot.json`; after one,
  re-derive state from disk (`state.py`), never from memory.

## 5. Skills, subagents and saved workflows

**Skills** (`.claude/skills/<name>/SKILL.md`) are the operator's verbs; the full table is in `CLAUDE.md`. Three
belong to this layer: `/opus` (these operating notes in short), `/breadth` (runs `breadth-phase` for the
current phase) and `/verify` (runs `verify-candidates` on the parked leads).

**Subagents** (`.claude/agents/<name>.md`) each own one job and one set of files. None of them commits or
pushes: the coordinator commits the evidence repo.

| Agent | Phase | Job | Writes |
|---|---|---|---|
| `domain-worker` | P3–P6 | one domain: in P3 the card's applicability probe (returned, recorded by the merge step); in P4–P6 the items in card triage order → `mark.py … --partial Dnn` | `checklist-status.Dnn.partial.csv`, `inventory/<register>.Dnn.partial.csv`, `logs/Dnn-*`, `hypotheses/H-Dnn-NN.md` |
| `verify-reproduce` | P5–P7 | lens 1: re-run the candidate's proof independently, from the weakest attacker model | a verdict only |
| `verify-guard` | P5–P7 | lens 2: hunt the guard, the second implementation or the platform gate that kills it | a verdict only |
| `verify-triage` | P5–P7 | lens 3: read it as the programme's triager (VRT node, exclusions, the P5 graveyard) | a verdict only |
| `chain-lead` | P7 | the single P7 agent: every parked primitive, expected-value order, VERIFY → … → RECORD | `chains/`, `findings/` |
| `evidence-reporter` | P8–P9 | evidence tree per `docs/04`, report per template, submission checklist | `findings/F-NNN/`, `final/` |
| `checklist-maintainer` | methodology | `/gap` and audit work on chapters, `docs/11` schema, lint clean | `checklist/` only, never engagement files |

**Saved workflows** (`.claude/workflows/*.js`) are invoked by name, with the parameters in plain words —
"Run /breadth-phase for P5 on BugBountyTarget/<Target>_<DDMMYYYY>" — and the coordinator fills their `args`
from `engagement.json` (`authorisation`, `lab.mode`) and `bash scripts/doctor.sh --json` (device serials). A
workflow refuses to start without a permitted authorisation basis and a recorded scope. After editing one,
`/reload-skills`. To pre-approve one in permissions, the rule is `Workflow(<name>)`.

| Workflow | Arguments | Does | Output |
|---|---|---|---|
| `/breadth-phase` | engagement, phase, authorisation; optional domains, devices, lanes, lab_mode | one `domain-worker` per applicable domain of the phase (P3: the applicability probe only); device-bound phases run in one lane per device; ends with a merge step (`coverage.py --merge`; in P3 it first records each domain's applicability decision) | per-domain counts, candidates for `/verify-candidates`, gaps, rejected rows; the coordinator re-dispatches rejected rows, updates `assessment-status.md` and commits |
| `/verify-candidates` | engagement, authorisation, candidates (`id`, `claim`, `evidence_paths`); optional devices, lanes, lab_mode | the three lenses per candidate (`verify-reproduce` in device lanes, the other two in parallel); a candidate survives when at least two of three do not refute it | the verdict table for `report/assessment-status.md`; the lenses write nothing |
| `/chapter-audit` | chapters | one review-only `checklist-maintainer` per chapter plus one adversarial verifier per review; touches no engagement, device or target and edits nothing | a defect list in the `docs/11` vocabulary for the `/gap` and chapter-fix work that follows |

No committed workflow names a target, host, account, device serial or PIN: they come from `engagement.json`
at run time, and device facts from `bash scripts/doctor.sh --json`.

**Resuming after an interruption or a usage limit.** A run that stopped can be resumed rather than restarted
(ask Claude to resume the stopped run: the Workflow tool's `resumeFromRunId` with the same `args` returns the
unchanged agent calls from cache and runs the rest live), or re-invoked for the domains still open. Either way, what counts is
disk, not the run's return values: before re-dispatching, the coordinator lists which partial files exist and
what is still open (`python3 scripts/next.py <eng> --domain Dnn`), and dispatches only that.

## 6. One rate budget, shared

Every agent of a session draws on the same rate budget: N parallel workers do not get N budgets, they drain one
budget N times faster, and the run stalls for everyone at once. Partition the fan-out by what it contends for:

- **Devices.** Never run more device-bound workers than there are devices (`scripts/doctor.sh --json` lists
  them), and give each device-bound worker its own serial. Two workers on one device collide on app state,
  Frida sessions and logcat. The workflows enforce this: P5/P6 domains run in lanes, one per serial passed in
  `devices`, and a `lanes` value above the device count is clamped. Static work (P3, P4) needs no device and
  fans out wider.
- **Hosts.** Workers that send traffic to the same backend share the programme's rate rules as well; split them
  by host, keep the programme's stated limits, and never let parallelism turn into automated scanning of
  production (`START.md` §1 hard limits).
- When the budget runs low, narrow the fan-out rather than letting every worker fail mid-item.

## 7. Interruptions: cancelled agents and half-finished edits

- **Operator messages sent mid-turn can cancel running agents.** Send instructions between turns, or after a
  workflow reports back. After a cancellation, a worker that returned nothing has not necessarily done nothing:
  check its partial files, logs and transcript before re-dispatching the domain.
- **A session or usage limit can stop an agent in the middle of an edit.** Therefore every unit of work is
  idempotent and re-checked: rows are written only through `mark.py` (which validates every write) and merged
  only through `coverage.py --merge` (which rejects invalid rows); logs are append-only; and before any edit an
  agent re-reads the current text and edits that, never a version computed from an earlier read. A
  `checklist-maintainer` re-reads the item before each change; a `domain-worker` re-reads the row's current state
  (`mark.py <eng> --show Dnn-NNN --partial Dnn`, `next.py`) before settling it.

## 8. Hooks lifecycle

| When | Hook | Effect |
|---|---|---|
| session start | `SessionStart` → `session-start.sh` | resume card, evidence-remote state, environment line |
| every operator turn | `UserPromptSubmit` → `prompt-context.sh` | one line of phase, coverage and evidence-remote state |
| before every Bash call | `PreToolUse(Bash)` → `pre-bash.sh` | refuses destructive git, forbidden artefacts, engagement paths in the methodology repo, credential-bearing commits |
| after every Bash call | `PostToolUse(Bash)` → `post-bash.sh` | after a commit, pushes the evidence repo to its private remote (or states the blocker); coverage after `mark.py` / `gate.py --pass` / `coverage.py --merge` |
| before compaction | `PreCompact` → `pre-compact.sh` | `state-snapshot.json` and a line in `logs/compactions.log` |
| session end | `Stop` → `stop-guard.sh` | refuses once to stop with uncommitted or unpushed evidence or a stale `assessment-status.md` |

Claude Code also offers `SubagentStart` / `SubagentStop` and `PreModelSwitch` / `PostModelSwitch` events; this
repository does not wire them. If the SessionStart card is missing, the hooks did not run: do their work by hand
(`START.md` §10).

## 9. Evidence-repo push cadence

Workers never commit. The coordinator commits the evidence repo (`git -C "$E" add -A && git -C "$E" commit`)
after every merge and after every batch of items it settles itself (R7); the PostToolUse hook pushes that commit
to the private remote in `engagement.json.evidence_remote`, or states the blocker when there is none. A
`/loop 20m` on `loops/push-cadence.md` catches a long stretch without a commit, and the Stop hook catches the
end of a session. Nothing from an engagement is ever committed or pushed to the methodology repository.

## 10. Settings the repository leaves to the operator

| Setting | What it does | Why it is not set here |
|---|---|---|
| `"ultracode": true` | starts sessions with ultracode on | cost is the operator's call |
| `workflowSizeGuideline` (`unrestricted` · `small` · `medium` · `large`) | a size guideline for the workflows Claude writes | depends on the operator's budget and devices |
| top-level `effortLevel` | a session-wide effort level | `modelSettings` already sets `high` per model |

Set them in user or local settings, never in the committed `.claude/settings.json`.
