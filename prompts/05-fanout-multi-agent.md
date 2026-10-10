# 05 — multi-agent fan-out (breadth phases only)

Use when your runner can spawn sub-agents. Chains (P7) are always single-agent.

```text
COORDINATOR. Engagement: BugBountyTarget/<<< Target_DDMMYYYY >>>. Phase: <<< P4|P5|P6 >>>.
Spawn one worker per domain in this phase (START.md §4 table). Give each worker: START.md §5–§6, its card
cards/Dnn.md, the inventory/*.csv rows for its domain, and the write contract below. Do not give two workers
the same domain. Merge when all return.

WORKER CONTRACT (paste into each worker)
  You own domain Dnn only. Read START.md §5–§6 and cards/Dnn.md. Run the applicability probe, then the items
  in triage order via `python3 scripts/item.py`. Write your rows to
  <eng>/checklist-status.Dnn.partial.csv (same columns as checklist-status.csv; only Dnn rows), your raw
  output to <eng>/logs/Dnn-NNN.txt, parked leads to <eng>/hypotheses/H-Dnn-NN.md. Do NOT edit
  checklist-status.csv, engagement.json, assessment-status.md or inventory/*.csv. No escalation (R0).
  Return: counts of finding/ruled-out/blocked/n-a and the ids of parked hypotheses.

MERGE
  For each partial file: replace the matching item_id rows in checklist-status.csv; mark the domain's
  inventory instances tested per the worker's report; renumber H-Dnn-NN → H-0NN; update assessment-status.md;
  commit; push. Then run `python3 scripts/coverage.py … --gate p7`.
```
