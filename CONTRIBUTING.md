# Contributing

This checklist is the team's shared memory. It is only worth what gets fed back into it.

## The rule that matters most

> **If an engagement turned up a class we had no item for, that gap cost us on this client and will cost
> us on the next one.** File it the same week, while you still remember the mechanism.

Open a [Checklist gap](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml)
issue. Corrections to existing items outrank new items.

## Standard every item must meet

`docs/11-item-schema.md` §1 is the only item schema — the metadata rows (`Severity ceiling`, `VRT`, `Attacker`, `Applies to`,
`Requires`, `Maps to`, `Record`), the body fields (`Skip when`, `Test`, `How`, `Proof`, `Escalation`, `Ruled out when`), which of
them are required and the grammar of each. It is not repeated here so that it cannot drift. An item is not accepted until it
carries every required field; validate with `python3 scripts/build-checklist.py && python3 scripts/lint-checklist.py`.
The two rules most often missed: **Maps to** cites only identifiers you verified in `data/` (never invent a MASTG or ATT&CK
id), and **Ruled out when** names the mechanism exactly as the `notes` of a `ruled-out` row would state it.

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
party's data. **Never commit or push engagement evidence to the methodology repository (it is public)**: `.gitignore` ignores
`BugBountyTarget/*_*/` and only `BugBountyTarget/README.md` and `_TEMPLATE/` are tracked. Each engagement folder is its own git repository — the evidence repo
(created by `scripts/new-engagement.sh`) — whose hashes, logs, sanitised captures, notes and
small videos are committed there and pushed to a private remote (`engagement.json.evidence_remote`); without one the hooks
state the blocker `no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>`.
A folder committed in an operator's checkout before this design (never pushed) is left alone until you migrate it:
`cd BugBountyTarget/<eng> && git init && git add -A && git commit -m "import" && git remote add origin <private url>
&& git push -u origin HEAD`, then in the methodology checkout `git rm -r --cached BugBountyTarget/<eng>`.
See `.gitignore` and `BugBountyTarget/README.md`.
