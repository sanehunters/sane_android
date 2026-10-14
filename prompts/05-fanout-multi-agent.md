# 05 — multi-agent fan-out (breadth phases only)

Use when your runner can spawn sub-agents. Chains (P7) are always single-agent.

```text
COORDINATOR. Engagement: BugBountyTarget/<<< Target_DDMMYYYY >>>. Phase: <<< P4|P5|P6 >>>.
Spawn one worker per domain in this phase (START.md §4 table). Give each worker: START.md §5–§6, its card
cards/Dnn.md, the inventory/*.csv rows for its domain, and the write contract below. Do not give two workers
the same domain. Merge when all return.

WORKER CONTRACT (paste into each worker)
  You own domain Dnn only. Read START.md §5–§6 and cards/Dnn.md. Run the applicability probe, then the items
  in triage order via `python3 scripts/item.py`. Settle every row with the validated writer, into your own
  partial file — never by hand:
    python3 scripts/mark.py <eng> Dnn-NNN <result> --note "..." --tracker checklist-status.Dnn.partial.csv
  (same columns as checklist-status.csv; only Dnn rows; the same R4 rules apply). Raw output goes to
  <eng>/logs/Dnn-NNN.txt; parked leads to <eng>/hypotheses/H-Dnn-NN.md (that id is valid as-is in notes and
  is never renumbered). The instances you tested go to <eng>/inventory/<register>.Dnn.partial.csv (same
  columns as inventory/<register>.csv; only the rows you tested, with tested/result/finding_id/notes filled).
  Do NOT edit checklist-status.csv, engagement.json, assessment-status.md or inventory/*.csv. No escalation (R0).
  Return: counts of finding/ruled-out/blocked/n-a, the H-Dnn-NN ids parked, and one line per instance
  tested: `instance_id · result · notes`.

MERGE
  python3 scripts/coverage.py <eng>/checklist-status.csv --merge   # folds every checklist-status.Dnn.partial.csv
  AND every inventory/<register>.Dnn.partial.csv (same row_valid and conflict rules as mark.py; a REJECTED
  row goes back to its worker). Then update assessment-status.md; git -C <eng> commit; git -C <eng> push.
  Then run `python3 scripts/coverage.py … --gate p7`.
```
