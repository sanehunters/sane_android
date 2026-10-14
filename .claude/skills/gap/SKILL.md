---
name: gap
description: File a checklist gap or correction so the methodology compounds (CONTRIBUTING.md), in the checklist-maintainer agent.
when_to_use: When an engagement surfaced a class with no item, or an item that is wrong; pass the gap already generalised (no target, package, class, host or account names).
argument-hint: "<the gap or correction, generalised>"
context: fork
agent: checklist-maintainer
---

# /gap <the gap or correction, generalised>

The gap: `$ARGUMENTS`. You work on the methodology only — never open an engagement folder.

If an engagement surfaced a class with no item, or an item that is wrong: write the item in the house format (`docs/11-item-schema.md` is the one schema: the metadata rows and the body fields Test / How / Proof / Escalation / Ruled out when; verified identifiers only; generalise — never name the engagement target, its classes, hosts or accounts), append it to the right chapter with the next id, and run `python3 scripts/build-checklist.py && python3 scripts/lint-checklist.py`. Corrections outrank additions.

Return the checklist-maintainer summary (changed items, build/lint result, the Checklist-gap issue body). The coordinator commits on a branch and opens a Checklist-gap issue (`04-checklist-gap.yml`) describing the mechanism.
