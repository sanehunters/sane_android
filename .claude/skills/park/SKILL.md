---
name: park
description: Park a promising lead as a hypothesis stub and return to the sweep (rule R0).
---

# /park Dnn-NNN <short title>

Write `<eng>/hypotheses/H-0NN.md` (next free number) with exactly these fields:
`Found during` (phase, domain, instance) · `Looks juicy because` (one sentence with the file:line) · `Minimum proof obtained` · `Next experiment` · `Estimated escalation cost` · `DEFERRED TO P7`.
Flip the row (`completed=true`, `result=finding`, `notes=H-0NN: …`), commit, and go to the next item. Thirty seconds, no more.
