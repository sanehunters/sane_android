# CLAUDE.md — standing orders for Claude Code sessions in this repository

Claude Code loads this file automatically. It is deliberately short: the methodology lives in
[`START.md`](START.md) (entry point and state machine — **read it in full before acting**) and
[`AGENTS.md`](AGENTS.md) (the SOP). Nothing in this file overrides them.

## What is wired up for you

| Mechanism | What it does | Where |
|---|---|---|
| **SessionStart hook** | prints the resume card (`scripts/state.py`) for the active engagement and the environment line (`scripts/doctor.sh --brief`) | `.claude/hooks/session-start.sh` |
| **UserPromptSubmit hook** | one line of phase + coverage context on every turn | `.claude/hooks/prompt-context.sh` |
| **PreToolUse(Bash) hook** | blocks destructive git, blocks staging/committing APK/DEX/SO/keystore/HAR/PCAP, blocks commits whose diff contains a live-looking credential or JWT | `.claude/hooks/pre-bash.sh` |
| **PostToolUse(Bash) hook** | auto-pushes after every commit (R7); reminds you that `adb shell am …` is not AM-03 proof (R3); prints coverage after a tracker edit | `.claude/hooks/post-bash.sh` |
| **Stop hook** | refuses to end the session while engagement state is uncommitted, unpushed, or `assessment-status.md` is stale — once; the second attempt passes | `.claude/hooks/stop-guard.sh` |
| **PreCompact hook** | snapshots the resume card to `state-snapshot.json` before context compaction | `.claude/hooks/pre-compact.sh` |
| **Skills** | `/engage`, `/resume`, `/status`, `/doctor`, `/domain`, `/item`, `/inventory`, `/coverage`, `/park`, `/chain`, `/evidence`, `/finding`, `/ruled-out`, `/report`, `/triage`, `/retest`, `/gap`, `/push`, `/fanout`, `/lab` | `.claude/skills/*/SKILL.md` |
| **Auto-skill** | `android-bounty` triggers whenever an APK, package, manifest, deep link, WebView, provider, Frida, jadx or a bounty programme is mentioned | `.claude/skills/android-bounty/SKILL.md` |
| **Loops** | self-paced recurring checks (coverage watchdog, push cadence, rabbit-hole check, hypothesis sweeper) for `/loop` | `loops/` |

Set `SANE_ENGAGEMENT=BugBountyTarget/<Target>_<DDMMYYYY>` when more than one engagement exists; otherwise
the hooks pick the most recently updated one.

## The rules in one breath

R0 breadth before depth (no escalation before P7) · R1 the checklist is the floor · R2 a primitive is not a
finding (the mobile VRT branch is P5) · R3 weakest attacker that still works; adb is not AM-03 · R4 negative
results name the mechanism · R5 do not fool yourself; never fabricate · R6 coverage is two CSVs on disk ·
R7 state on disk, committed and pushed after every batch.

## Decide, do not ask

You are operating autonomously. Decide which surface next, which tool, how to structure a PoC, how to word a
finding, whether a result is a true negative — and say what you decided. Ask the operator only for what only
they can supply (second account, OTP, KYC state, payment sandbox, scope decision, hardware), by writing it
into `engagement.json.blockers`.

## Never

Test an app you are not authorised to test · use a real third party's account or data (plant canaries) ·
fabricate a CVE, report id, bounty figure, CVSS vector or PoC · reconstruct a video for something you did not
execute · commit an APK, a decompiled tree, a credential or un-redacted third-party data · report a P5
standalone · claim coverage the CSVs do not show · end a session with unpushed state.
