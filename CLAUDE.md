# CLAUDE.md — standing orders for Claude Code sessions in this repository

Claude Code loads this file automatically. It is deliberately short: the methodology lives in
[`START.md`](START.md) (entry point and state machine — **read it in full before acting**) and
[`AGENTS.md`](AGENTS.md) (the SOP). Nothing in this file overrides them.

## Where evidence goes (this repository is public)

The methodology repo holds no engagements. Each engagement folder `BugBountyTarget/<Target>_<DDMMYYYY>/` is
**its own git repository — the evidence repo** — created by `scripts/new-engagement.sh`, ignored by this repo's
`.gitignore` and refused by the PreToolUse hook. Evidence is committed there (`git -C "$E" add -A && git -C "$E"
commit`) and pushed only to a **private** remote the operator supplies: `SANE_EVIDENCE_REMOTE=<git url>` or
`scripts/new-engagement.sh <Target> --remote <url>` (recorded as `engagement.json.evidence_remote`). When no
remote is configured the hooks say "no evidence remote configured: evidence is committed locally only — set
SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>" and never push anything to the methodology
origin. `SANE_PUSH=0` disables the auto-push for a session.

## What is wired up for you

| Mechanism | What it does | Where |
|---|---|---|
| **SessionStart hook** | prints the resume card (`scripts/state.py`), the evidence-remote state and the environment line (`scripts/doctor.sh --brief`; an empty line is reported as UNVERIFIED) | `.claude/hooks/session-start.sh` |
| **UserPromptSubmit hook** | one line of phase + coverage (`scripts/coverage.py --brief`) + evidence-remote context on every turn | `.claude/hooks/prompt-context.sh` |
| **PreToolUse(Bash) hook** | blocks destructive git, recursive deletes of repository paths, staging engagement paths in the methodology repo, staging/committing APK/DEX/SO/keystore/key/HAR/PCAP, decompiled trees and secret dumps, and commits whose diff contains a live-looking credential or JWT — in the methodology repo and in the evidence repo | `.claude/hooks/pre-bash.sh` |
| **PostToolUse(Bash) hook** | after every commit pushes the **evidence repo** to its private remote (never the methodology origin; states the blocker when none is set); reminds you that `adb shell am …` is not AM-03 proof (R3); prints coverage after `mark.py` / `gate.py --pass` / `coverage.py --merge` | `.claude/hooks/post-bash.sh` |
| **Stop hook** | refuses to end the session while evidence is uncommitted, unpushed (only when an evidence remote exists) or `assessment-status.md` is stale — once; the second attempt passes | `.claude/hooks/stop-guard.sh` |
| **PreCompact hook** | snapshots the resume card to `state-snapshot.json` and appends a line to `logs/compactions.log` before context compaction | `.claude/hooks/pre-compact.sh` |
| **Skills** | `/engage`, `/sane-resume`, `/sane-status`, `/sane-doctor`, `/domain`, `/item`, `/inventory`, `/coverage`, `/park`, `/chain`, `/evidence`, `/finding`, `/ruled-out`, `/report`, `/triage`, `/retest`, `/gap`, `/push`, `/fanout`, `/lab` (the `sane-` prefix avoids Claude Code's built-in `/resume`, `/status`, `/doctor`) | `.claude/skills/*/SKILL.md` |
| **Auto-skill** | `android-bounty` triggers whenever an APK, package, manifest, deep link, WebView, provider, Frida, jadx or a bounty programme is mentioned | `.claude/skills/android-bounty/SKILL.md` |
| **Loops** | self-paced recurring checks (coverage watchdog, push cadence, rabbit-hole check, hypothesis sweeper, status heartbeat) for `/loop` | `loops/` |

Set `SANE_ENGAGEMENT=BugBountyTarget/<Target>_<DDMMYYYY>` when more than one engagement exists; otherwise
the hooks pick the most recently updated one. `SANE_ENGAGEMENT_ROOT=/path` keeps engagements outside the checkout.

## The rules in one breath

R0 breadth before depth (no escalation before P7) · R1 the checklist is the floor · R2 a primitive is not a
finding (the mobile VRT branch is P5) · R3 weakest attacker that still works; adb is not AM-03 · R4 negative
results name the mechanism · R5 do not fool yourself; never fabricate · R6 coverage is two CSVs on disk ·
R7 state on disk: committed in the evidence repo after every batch, pushed to its private remote when one exists.

## Decide, do not ask

You are operating autonomously. Decide which surface next, which tool, how to structure a PoC, how to word a
finding, whether a result is a true negative — and say what you decided. Ask the operator only for what only
they can supply (second account, OTP, KYC state, payment sandbox, scope decision, hardware, the private
evidence remote), by writing it into `engagement.json.blockers`.

## Never

Test an app you are not authorised to test · use a real third party's account or data (plant canaries) ·
fabricate a CVE, report id, bounty figure, CVSS vector or PoC · reconstruct a video for something you did not
execute · commit an APK, a decompiled tree, a credential or un-redacted third-party data · commit or push
engagement evidence to the methodology repository (it is public) · report a P5 standalone · claim coverage
the CSVs do not show · end a session with uncommitted evidence.
