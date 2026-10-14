# 01 — resume prompt

```text
Continue the Android engagement in this repository. First:
  cd <methodology checkout> && git pull --ff-only && cat START.md
  python3 scripts/state.py BugBountyTarget/<<< Target_DDMMYYYY >>>
Read report/assessment-status.md in full and hypotheses/*.md. Never re-walk anything under RULED OUT.
Resume from NEXT TARGET in expected-value order (START.md §3b); keep the state machine and recording rules of
START.md; commit and push the evidence repo (git -C <eng>) after every batch. Report what you settled and what remains.
```
