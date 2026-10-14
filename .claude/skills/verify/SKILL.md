---
name: verify
description: Run the saved workflow /verify-candidates on the parked leads in hypotheses/ — three independent lenses per lead (verify-reproduce, verify-guard, verify-triage); a lead survives when at least two of three do not refute it — then record the verdict table.
when_to_use: After a breadth run returns candidates (P5–P6), and at the start of P7 before /chain, for every parked lead without a recorded verdict.
argument-hint: "[engagement-dir] [H-id ...]"
allowed-tools: Workflow(verify-candidates), Bash(python3 scripts/state.py:*), Bash(bash scripts/doctor.sh:*)
---

# /verify [engagement-dir] [H-id …]

Arguments: `$ARGUMENTS`. Engagement `E`: the folder named there, else `$SANE_ENGAGEMENT`, else the most recently
updated `BugBountyTarget/<Target>_<DDMMYYYY>/`. Lead ids given there restrict the run.

1. Authorisation and lab mode from `engagement.json` (the one-liner in `/breadth` step 1). Basis `MISSING` or
   scope empty → stop: no recorded basis, no delegation.
2. Candidates: the `candidates` a `/breadth-phase` run returned, or every `hypotheses/H-*.md` (never
   `H-000-TEMPLATE.md`) whose status line carries no verdict yet:
   `grep -H '^\*\*Status:\*\*' "$E"/hypotheses/H-*.md | grep -v H-000-TEMPLATE | grep -v 'VERIFY'`.
   Each becomes `{"id": "H-Dnn-NN", "claim": "<one sentence: the primitive and its attacker model>",
   "evidence_paths": ["hypotheses/H-Dnn-NN.md", "logs/Dnn-NNN.txt"]}` — paths relative to `E`, read from the file.
3. Devices: `bash scripts/doctor.sh --json` → `devices`. Only the reproduce lens is device-bound: one lane per device.
4. Run `/verify-candidates` with args `{"engagement": "<E>", "authorisation": <engagement.json.authorisation>,
   "candidates": [ … ], "devices": [<serials>], "lab_mode": "<lab.mode>"}`. The workflow opens every lens brief
   with the authorisation line.
5. Keep the evidence: each lens's `reasoning` → `logs/verify/<id>-<lens>.txt`, so it outlives the run.
6. Per lead, in the hypothesis file's status line: `**Status:** SURVIVED VERIFY (<n>/3) — DEFERRED TO P7` or
   `**Status:** REFUTED BY VERIFY — <lens>: <reason>`; an `incomplete` lead is re-run, not guessed. Never delete a
   refuted lead; the refutation stays next to it. Checklist rows do not change here: P7's `chain-lead` returns
   the `mark.py` lines for findings and concessions.
7. The returned `table` goes into `report/assessment-status.md`: survivors under CHAINING IDEAS in expected-value
   order, refuted leads under RULED OUT with the deciding lens. Then `/push`.
