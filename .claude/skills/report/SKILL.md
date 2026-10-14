---
name: report
description: Assemble the assessment report, the ruled-out register and the submission checklist (phase 9).
---

# /report

1. `templates/assessment-report.md` → `<eng>/final/assessment-report.md` (delete every guidance blockquote before delivery): executive summary, scope and method, findings severity-ordered (from `findings-index.md`), the attack-surface inventory appendix (from `inventory/*.csv`), the **ruled-out register** (from the CSV rows with `result=ruled-out`), coverage statement (`coverage.py` output + `docs/07` crosswalk), limitations and what was not tested.
2. `final/submission-checklist.md` per finding: root cause `file:line`, precondition, failing control, positive and negative control, reproduced on device, video, max impact tested not assumed, severity justified, remediation.
3. `final/<programme>-F-0NN.md` (the programme's format) per finding.
4. `python3 scripts/gate.py $E --pass p8` — moves phase to P9 only if every finding has `report.md` and its evidence; never set `phase` by hand. Before submitting, `python3 scripts/gate.py $E done`.
5. `/push` (commits the evidence repo; pushes only to the private evidence remote).
