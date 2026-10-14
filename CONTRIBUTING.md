# Contributing

This checklist is the team's shared memory. It is only worth what gets fed back into it.

## The rule that matters most

> **If an engagement turned up a class we had no item for, that gap cost us on this client and will cost
> us on the next one.** File it the same week, while you still remember the mechanism.

Open a [Checklist gap](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml)
issue. Corrections to existing items outrank new items.

## Standard every item must meet

The format is `docs/11-item-schema.md`; validate with `python3 scripts/build-checklist.py && python3 scripts/lint-checklist.py`.
An item is not accepted until it has the ten required fields:

| Field | Requirement |
|---|---|
| **Severity ceiling** | Critical/High/Medium/Low — the most the item can reach on its own. A P5-only item needs an escalation |
| **VRT** | The Bugcrowd VRT path it reaches (`data/vrt.csv`), never a P5 mobile leaf as the final rating |
| **Attacker** | The weakest attacker model that still works (AM-01…AM-12, `docs/05`) |
| **Applies to** | API level, framework or app-type preconditions, or "all" |
| **Maps to** | Only identifiers you actually verified. Never invent a MASTG or ATT&CK ID |
| **Test** | What to check, in one or two sentences |
| **How** | The exact command, grep, manifest attribute or tool step. Not "look for X" |
| **Proof** | The specific observable that confirms it — a log line, returned bytes, a status delta |
| **Escalation** | What this primitive chains into |
| **Ruled out when** | The mechanism that closes the item, as the `notes` of a `ruled-out` row would state it |

Strongly recommended: **Requires** (device/root/MitM/accounts), **Record** (what goes to `logs/`), **Skip when**.

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

APKs, decompiled trees, keystores, raw HAR/PCAP captures, videos over 5 MB, credentials, or any third
party's data. **Never an engagement folder to this repository**: it is public, `.gitignore` ignores
`BugBountyTarget/*_*/` and only `BugBountyTarget/README.md` and `_TEMPLATE/` are tracked. Each engagement folder is
its own git repository (created by `scripts/new-engagement.sh`) whose hashes, logs, sanitised captures, notes and
small videos are committed there and pushed to a private remote (`engagement.json.evidence_remote`). See
`.gitignore` and `BugBountyTarget/README.md`.
