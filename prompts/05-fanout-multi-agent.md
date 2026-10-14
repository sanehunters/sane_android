# 05 — multi-agent fan-out (breadth phases, then verification)

The fan-out is a saved workflow; you do not hand-assemble it. P7 (chains) is always one agent, `chain-lead`.
Operating details — rate budget, devices, interruptions, resuming a stopped run — are in
`docs/10-agent-operations.md`.

```text
COORDINATOR. Engagement: BugBountyTarget/<<< Target_DDMMYYYY >>>. Phase: <<< P3|P4|P5|P6 >>>.
Authorisation, programme and scope: as recorded in engagement.json.authorisation — state them at the top of
every delegated task.

1. Run /breadth-phase for <<< phase >>> on BugBountyTarget/<<< Target_DDMMYYYY >>>
   (optionally: only domains <<< Dnn Dnn >>>). Fill its args from engagement.json (authorisation, lab.mode) and
   scripts/doctor.sh --json (device serials). It starts one domain-worker per applicable domain, one lane per
   device in P5/P6, and ends with the merge below.
2. When it returns: send every rejected row back to its worker (re-run that domain), update
   assessment-status.md, commit the evidence repo.
3. Run /verify-candidates on BugBountyTarget/<<< Target_DDMMYYYY >>> with the candidates the workers returned
   (or the parked H-Dnn-NN leads). Record the verdict table in assessment-status.md; refuted candidates go to
   the ruled-out register with the lens that refuted them.
```

**Worker contract** (P4–P6) — what every `domain-worker` is bound to; also the brief when you dispatch one worker by
hand. In P3 a worker only runs its card's applicability probe and returns the decision with its evidence; the
merge step records it.

```text
You own domain Dnn only. Read START.md §2, §5–§6 and cards/Dnn.md. Write the authorisation basis, programme and
scope from engagement.json as the first line of your log. Applicability was decided by the coordinator in P3
(engagement.json.domains_decided): never run `mark.py <eng> Dnn applies` or a whole-domain n/a (applies is
refused on a slice). Work the items in triage order via `python3 scripts/item.py`. Settle every row with the
validated writer, into your own partial file — never by hand:
  python3 scripts/mark.py <eng> Dnn-NNN <result> --note "..." --partial Dnn
(--partial Dnn seeds <eng>/checklist-status.Dnn.partial.csv from the tracker on first use: same columns, only
Dnn rows, the same R4 rules apply). Before settling a row, re-check its current state (`python3 scripts/next.py
<eng> --domain Dnn`): a stopped run may already have settled it. Raw output goes to <eng>/logs/Dnn-NNN.txt;
parked leads to <eng>/hypotheses/H-Dnn-NN.md (that id is valid as-is in notes and is never renumbered). The
instances you tested go to <eng>/inventory/<register>.Dnn.partial.csv (same columns as
inventory/<register>.csv; only the rows you tested, with tested/result/finding_id/notes filled).
Do NOT edit checklist-status.csv, engagement.json, assessment-status.md or inventory/*.csv; never commit or
push. No escalation (R0). Return: counts of finding/ruled-out/blocked/n-a, the H-Dnn-NN ids parked, the
candidates for verification, and one line per instance tested: `instance_id · result · notes`.
```

**Merge** (the last step of `/breadth-phase`; by hand after a worker you dispatched yourself):

```text
python3 scripts/coverage.py <eng>/checklist-status.csv --merge   # folds every checklist-status.Dnn.partial.csv
AND every inventory/<register>.Dnn.partial.csv (same row_valid and conflict rules as mark.py; H-Dnn-NN ids are
accepted as-is — renumbering to H-NNN is optional and AFTER the merge; a REJECTED row goes back to its worker).
Then update assessment-status.md; git -C <eng> commit; the PostToolUse hook pushes the evidence repo.
Then run `python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory --gate p7`.
```
