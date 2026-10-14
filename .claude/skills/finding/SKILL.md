---
name: finding
description: Write up a confirmed finding in the house format and register it.
---

# /finding F-0NN

1. `templates/finding-report.md` → `<eng>/findings/F-0NN/report.md` (heading `F-0NN`, evidence at `videos/F-0NN.mp4`, `pocs/F-0NN/` source only — never a built APK — `logs/Dnn-NNN.txt`, START.md §6). Title = impact category, never the mechanism. State: attacker model, precondition (one sentence, as weak as honestly possible), the control that should have stopped it and the path that skips it (`file:line`), reproduction (copy-pasteable), the delta, the chain table with unproven links marked, impact, remediation specific to their code, limitations.
2. VRT path must be non-P5 and must exist in `data/vrt.csv`. Two verified links + one unproven = Medium with a stated precondition.
3. Add the row to `<eng>/report/findings-index.md`; set `finding_id` on the checklist row(s).
4. If GitHub issues are in use: open a Finding issue (`01-finding.yml`) **only on the private evidence repository** (`SANE_EVIDENCE_REMOTE`); never on the public methodology repo — its tracker carries no vulnerability details.
5. `/push` (evidence repo only).
