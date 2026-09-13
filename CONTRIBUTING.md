# Contributing

This checklist is the team's shared memory. It is only worth what gets fed back into it.

## The rule that matters most

> **If an engagement turned up a class we had no item for, that gap cost us on this client and will cost
> us on the next one.** File it the same week, while you still remember the mechanism.

Open a [Checklist gap](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml)
issue. Corrections to existing items outrank new items.

## Standard every item must meet

An item is not accepted until it has all seven fields:

| Field | Requirement |
|---|---|
| **Test** | What to check, in one or two sentences |
| **How** | The exact command, grep, manifest attribute or tool step. Not "look for X" |
| **Proof** | The specific observable that confirms it — a log line, returned bytes, a status delta |
| **Severity** | Critical/High/Medium/Low **and the VRT path it reaches**. A P5-only item needs an escalation |
| **Maps to** | Only identifiers you actually verified. Never invent a MASTG or ATT&CK ID |
| **Escalation** | What this primitive chains into |
| **Applies to** | API level, framework or app-type preconditions, or "all" |

## House rules

1. **Mechanism over pattern.** "Grep for `addJavascriptInterface`" is weak. "Grep it, confirm the bridge
   object is reachable from a cross-origin iframe because the allow-list only gates the main frame" is
   an item.
2. **Mark legacy items LEGACY with the API level.** Most public Android checklists are stale. Ours says
   so explicitly: `addJavascriptInterface` reflection RCE is `minSdk < 17`; implicit component export is
   `targetSdk < 31`; user-CA trust is `targetSdk < 24`.
3. **No informational padding.** If an item cannot reach Low or better, either give it an escalation
   path or put it in the graveyard table with a `graveyard` label.
4. **Never fabricate.** No invented CVEs, report IDs, bounty figures or test IDs. Unverified means
   labelled HYPOTHESIS, with the experiment that would confirm it.
5. **Corrections stay visible.** When an item turns out wrong, strike it through and record why rather
   than deleting it. The correction is the evidence of rigour.

## Never commit

Client data, APKs, evidence, videos, credentials or a live `report.md`. See `.gitignore`. This repository
is methodology; engagement artifacts live in the engagement's own private store.
