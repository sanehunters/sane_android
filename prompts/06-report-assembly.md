# 06 — report assembly prompt

```text
Assemble the deliverables for BugBountyTarget/<<< Target_DDMMYYYY >>> per START.md §4 P9 (first
`python3 scripts/gate.py <eng> --pass p8` — it moves phase to P9 only when every finding has report.md and its
evidence tree): final/assessment-report.md from templates/assessment-report.md (findings severity-ordered, the
attack-surface appendix from inventory/*.csv, the ruled-out register from checklist-status.csv, the
coverage statement from scripts/coverage.py and docs/07), final/submission-checklist.md per finding, and one
programme-format submission per finding. Every finding title names the impact; every VRT path is non-P5
and exists in data/vrt.csv (its priority column, never a parent node); every unproven link is marked. Commit and
push the evidence repo (git -C <eng>); finish with `python3 scripts/gate.py <eng> done`.
```
