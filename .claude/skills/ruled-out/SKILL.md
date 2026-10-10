---
name: ruled-out
description: Record a defensible negative for an item (rule R4).
---

# /ruled-out Dnn-NNN

The row's `notes` must name **the mechanism** that closes it with `file:line` (e.g. the validator and the proof that every call site routes through it), or the controlled experiment with its verified precondition. A tool's silence is never a mechanism. Add the entry to the ruled-out register (`templates/ruled-out-table.md`) with the attacker model it rules out. Set `completed=true, result=ruled-out`.
