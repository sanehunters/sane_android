---
name: sane-status
description: "Print where the engagement is: phase, gates, coverage per domain, next items, blockers, git state."
argument-hint: "[engagement-dir]"
allowed-tools: Bash(python3 scripts/state.py:*), Bash(python3 scripts/coverage.py:*), Bash(python3 scripts/next.py:*)
---

# /sane-status   (`sane-` because `/status` is a Claude Code built-in)

`python3 scripts/state.py <eng>` and `python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory --brief`.
Report the one-line summary, then the first five NEXT ITEMS. If `n/a without a reason` warnings appear, fix those rows before anything else.
