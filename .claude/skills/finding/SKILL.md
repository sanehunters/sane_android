---
name: finding
description: Write up a confirmed finding in the house format and register it.
---

# /finding F-0NN

1. `templates/finding-report.md` → `<eng>/findings/F-0NN/report.md`. Title = impact category, never the mechanism. State: attacker model, precondition (one sentence, as weak as honestly possible), the control that should have stopped it and the path that skips it (`file:line`), reproduction (copy-pasteable), the delta, the chain table with unproven links marked, impact, remediation specific to their code, limitations.
2. VRT path must be non-P5 and must exist in `data/bugcrowd-vrt-full.csv`. Two verified links + one unproven = Medium with a stated precondition.
3. Add the row to `<eng>/report/findings-index.md`; set `finding_id` on the checklist row(s).
4. If GitHub issues are in use: open a Finding issue with the `01-finding.yml` template fields.
5. Commit and push.
