---
name: chain
description: Phase 7: drive every parked primitive to a rated impact or concede it. Only after the P7 gate opens.
---

# /chain

Precondition: `python3 scripts/coverage.py … --gate p7` exits 0. If it does not, go back to the sweep.

1. List `hypotheses/*.md`; order by expected value (ceiling × confidence ÷ cost).
2. For each: VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD (AGENTS.md §4). Write `chains/C-0NN.md` with one row per link and its status (verified on device / unproven).
3. Work the cross-surface joins listed at the bottom of every relevant card — chains live at the joins.
4. A primitive that cannot reach a non-P5 VRT node is conceded in the ruled-out register with the reason it is bounded.
5. Each proven chain becomes `findings/F-0NN/` → `/evidence`, `/finding`.
