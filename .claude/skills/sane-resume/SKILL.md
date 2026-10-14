---
name: sane-resume
description: Resume an existing engagement from disk after a new session or a context reset. Use whenever a BugBountyTarget/<Target>_<date> folder exists.
argument-hint: "[engagement-dir]"
---

# /sane-resume [engagement-dir]   (`sane-` because `/resume` is a Claude Code built-in)

1. `python3 scripts/state.py <eng>` — the resume card (phase, gates, coverage, NEXT ITEMS, parked hypotheses, blockers, git state).
2. Read `<eng>/report/assessment-status.md` in full. **Never re-walk anything under RULED OUT.**
3. `cat <eng>/hypotheses/*.md` — what was parked and why.
4. If the card shows uncommitted or unpushed evidence, `/push` first (R7; the evidence repo is `git -C <eng>`).
5. Continue from NEXT TARGET / NEXT ITEMS in the card's order (phase, then ceiling). Use `/domain Dnn` for the current domain.

Exit: you are executing the first open item of the current phase.
