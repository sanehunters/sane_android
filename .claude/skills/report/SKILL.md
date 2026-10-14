---
name: report
description: Assemble the assessment report, the ruled-out register and the submission checklist (phase 9), in the evidence-reporter agent.
when_to_use: P8–P9, once every confirmed finding has its evidence tree; again after a retest or a triage exchange changes a finding.
argument-hint: "[engagement-dir]"
context: fork
agent: evidence-reporter
---

# /report [engagement-dir]

Arguments: `$ARGUMENTS`. Engagement `E`: the folder named there, else `$SANE_ENGAGEMENT`, else the most recently
updated `BugBountyTarget/<Target>_<DDMMYYYY>/`. Write the authorisation line from `engagement.json` first.

1. `templates/assessment-report.md` → `<eng>/final/assessment-report.md` (delete every guidance blockquote before delivery): executive summary, scope and method, findings severity-ordered (from `findings-index.md`), the attack-surface inventory appendix (from `inventory/*.csv`), the **ruled-out register** (from the CSV rows with `result=ruled-out`), coverage statement (`coverage.py` output + `docs/07` crosswalk), limitations and what was not tested.
2. `final/submission-checklist.md` per finding: root cause `file:line`, precondition, failing control, positive and negative control, reproduced on device, video, max impact tested not assumed, severity justified, remediation.
3. `final/<programme>-F-0NN.md` (the programme's format) per finding.
4. Check `python3 scripts/gate.py "$E" p8` and, before submitting, `python3 scripts/gate.py "$E" done` — report what each lists; never set `phase` by hand.
5. Return the evidence-reporter summary. The coordinator runs `python3 scripts/gate.py "$E" --pass p8` (moves the phase to P9 only if every finding has `report.md` and its evidence) and `/push` (commits the evidence repo; pushes only to the private evidence remote).
