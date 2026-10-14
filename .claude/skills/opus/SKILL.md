---
name: opus
description: Operating notes for running the sane_android methodology with Claude Opus 5.5 (claude-opus-5-5, primary) and Claude Opus 5 (claude-opus-5, fallback) in Claude Code — model and effort defaults, context budget, when to fan out to agents and when to stay single-agent, interruptions and resume. The full text is docs/10-agent-operations.md.
when_to_use: At the start of a session, before fanning out with /breadth or /verify, when a usage limit or model availability changes mid-engagement, or when the operator asks how the repository is meant to be operated.
---

# /opus — operating notes (full text: `docs/10-agent-operations.md`)

| Setting | Value | Set in |
|---|---|---|
| Model | `claude-opus-5-5`; Claude Code v2.1.280 or later (`claude --version`) | `.claude/settings.json` `model` |
| Fallback | `claude-opus-5`, automatic on availability failures only | `fallbackModel` |
| Effort | `high` for both models | `modelSettings` → `effortLevel` |
| Agents | `inherit` (the session model, so a `/model` switch reaches them); `high` for `domain-worker`, `evidence-reporter`, `checklist-maintainer`; `xhigh` for the three verifier lenses and `chain-lead` | `.claude/agents/*.md` `model`, `effort` |

`claude doctor` lists any settings entry Claude Code rejected. When Opus 5.5 is unavailable for a reason the
automatic fallback does not cover (usage limit, credits, outage), switch with `/model claude-opus-5`, note the
switch in the work log, and return with `/model claude-opus-5-5`.

**When to fan out, when to stay single.**

| Work | Shape |
|---|---|
| P0–P2, P3 applicability decisions, merges, commits | single agent — you, the coordinator |
| P3–P6 breadth | `/breadth` → `/breadth-phase`: one `domain-worker` per applicable domain |
| parked leads | `/verify` → `/verify-candidates`: three lenses per lead, in parallel |
| P7 | `/chain` → `chain-lead`, one agent: chains need every primitive in one context |
| P8–P9 | `/report` → `evidence-reporter` |

**Budgets.** Every agent of a session draws on one rate budget: partition by device and host, and never run more
device-bound agents than devices (`bash scripts/doctor.sh --json`). Context: `cards/Dnn.md` and
`python3 scripts/item.py Dnn-NNN --brief`, never a whole chapter; state lives on disk (R7), and the PreCompact
hook snapshots the resume card before compaction.

**Interruptions.** An operator message sent mid-turn can cancel running agents, and a usage limit can stop one
mid-edit. Workers re-read the current row or file before editing, so every step is safe to repeat; resume the
interrupted workflow run (`docs/10`) or re-run it for what is still open on disk; `coverage.py --merge` is
idempotent. Check `git -C "$E" status` before continuing.

**Delegation.** Every brief you hand to an agent or a workflow opens with the authorisation basis, programme and
in-scope assets exactly as `engagement.json.authorisation` records them, plus the exclusions; each agent writes
that line first in its work log. A reviewer, human or model, needs that context to judge a security task. No
recorded basis, no delegation.

**Commits.** Agents never commit or push. You commit into the evidence repo after every merge and batch (`/push`);
the methodology repository never receives evidence.
