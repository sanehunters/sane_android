---
name: report
description: Assemble the assessment report, the ruled-out register and the submission checklist (phase 9).
---

# /report

1. `templates/assessment-report.md` → `<eng>/final/assessment-report.md`: executive summary, scope and method, findings severity-ordered (from `findings-index.md`), the attack-surface inventory appendix (from `inventory/*.csv`), the **ruled-out register** (from the CSV rows with `result=ruled-out`), coverage statement (`coverage.py` output + `docs/07` crosswalk), limitations and what was not tested.
2. `final/submission-checklist.md` per finding: root cause `file:line`, precondition, failing control, positive and negative control, reproduced on device, video, max impact tested not assumed, severity justified, remediation.
3. `final/hackerone-F-0NN.md` (or the programme's format) per finding.
4. Set `engagement.json.phase = P9`; commit and push.
