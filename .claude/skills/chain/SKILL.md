---
name: chain
description: Phase 7 — drive every parked primitive to a rated impact or concede it, in the single chain-lead agent. Only after the P7 gate opens.
when_to_use: After /verify has recorded its verdict table and `python3 scripts/gate.py <eng> p7` exits 0; never during P3–P6 (R0).
argument-hint: "[engagement-dir]"
context: fork
agent: chain-lead
---

# /chain [engagement-dir]

Arguments: `$ARGUMENTS`. Engagement `E`: the folder named there, else `$SANE_ENGAGEMENT`, else the most recently
updated `BugBountyTarget/<Target>_<DDMMYYYY>/`. Write the authorisation line from `engagement.json` first.

Precondition: `python3 scripts/coverage.py "$E/checklist-status.csv" --components "$E/inventory" --gate p7` and
`python3 scripts/gate.py "$E" p7` exit 0. If not, return BLOCKED with the rows they list — go back to the sweep.

1. List `hypotheses/*.md`; order by expected value (ceiling × confidence ÷ cost), survivors of `/verify` first.
2. For each: VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD (AGENTS.md §4). Write `chains/X-0NN.md` (chain `X-NNN`, START.md §6 — `C-NNN` is a component instance) with one row per link and its status (verified on device / unproven).
3. Work the cross-surface joins listed at the bottom of every relevant card — chains live at the joins.
4. A primitive that cannot reach a non-P5 VRT node is conceded in the ruled-out register with the reason it is bounded.
5. Each proven chain becomes `findings/F-0NN/` → `/evidence`, `/finding`.
6. Return the chain-lead summary. The coordinator then runs its `MARK` lines, adds its `INDEX` rows to `report/findings-index.md`, updates `report/assessment-status.md` and runs `/push`.
