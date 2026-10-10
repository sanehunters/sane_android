---
name: gap
description: File a checklist gap or correction so the methodology compounds (CONTRIBUTING.md).
---

# /gap

If an engagement surfaced a class with no item, or an item that is wrong: write the item in the house format (`CONTRIBUTING.md` — Test / How / Proof / Escalation / Ruled out when + the five metadata rows, verified identifiers only), append it to the right chapter with the next id, run `python3 scripts/build-checklist.py && python3 scripts/lint-checklist.py`, commit on a branch, and open a Checklist-gap issue (`04-checklist-gap.yml`) describing the mechanism. Corrections outrank additions.
