---
name: retest
description: Re-verify a finding against a new build and record the outcome.
---

# /retest F-0NN <new-apk>

Re-run the exact reproduction from `findings/F-0NN/report.md` on the new build (record version/versionCode). Outcome: `fixed` (the control now present, `file:line`), `not fixed`, or `partially fixed` (state what still works). Add a dated retest section to the finding, update `findings-index.md`, commit, push.
