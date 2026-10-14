---
name: park
description: Park a promising lead as a hypothesis stub and return to the sweep (rule R0).
---

# /park Dnn-NNN <short title>

Copy `<eng>/hypotheses/H-000-TEMPLATE.md` to `H-0NN.md` (next free number) and fill all seven fields:
`Found during` (phase, domain, instance) · `Looks juicy because` (one sentence with the file:line) · `Minimum proof obtained` · `What it would become` (the VRT row it could reach) · `Next experiment` · `Estimated escalation cost` · `Status: DEFERRED TO P7`.
Settle the row with `python3 scripts/mark.py $E Dnn-NNN finding --note "H-0NN: …"`, commit, and go to the next item. Thirty seconds, no more.
