---
name: status
description: Print where the engagement is: phase, gates, coverage per domain, next items, blockers, git state.
---

# /status

`python3 scripts/state.py <eng>` and `python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory --brief`.
Report the one-line summary, then the first five NEXT ITEMS. If `n/a without a reason` warnings appear, fix those rows before anything else.
