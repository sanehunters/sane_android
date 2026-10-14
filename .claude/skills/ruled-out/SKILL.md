---
name: ruled-out
description: Record a defensible negative for an item (rule R4).
argument-hint: "Dnn-NNN"
---

# /ruled-out Dnn-NNN

The row's `notes` must name **the mechanism** that closes it with `file:line` (e.g. the validator and the proof that every call site routes through it), or the controlled experiment with its verified precondition. A tool's silence is never a mechanism. Add the entry to the ruled-out register (`templates/ruled-out-table.md`) with the attacker model it rules out. Settle it with `python3 scripts/mark.py $E Dnn-NNN ruled-out --note "<mechanism, file:line>"` (never by editing the CSV).
