# rabbit-hole-check — every 15 minutes during P3–P6

```
/loop 15m Answer in one line each: (1) which checklist item am I on and for how many tool calls?
(2) have I re-run a variant of the same probe three times? (3) have I written exploit code? If any answer
trips the three-strike rule, write hypotheses/H-0NN.md for the current lead, flip the row, and move to the
next open item from `python3 scripts/state.py <eng>`. Stop this loop when engagement.json.phase is P7.
```
