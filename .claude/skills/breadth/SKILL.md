---
name: breadth
description: Run the saved workflow /breadth-phase for the engagement's current phase (read from engagement.json) — one domain-worker per domain of the phase, each into its own partial tracker, then the merge — and record and push the result.
when_to_use: In P3–P6 whenever more than one domain of the current phase is open (in P3, the applicability probes). Never for P0–P2 or P7–P9, which are single-agent.
argument-hint: "[engagement-dir] [Dnn ...]"
allowed-tools: Workflow(breadth-phase), Bash(python3 scripts/state.py:*), Bash(python3 scripts/gate.py:*), Bash(python3 scripts/coverage.py:*), Bash(bash scripts/doctor.sh:*)
---

# /breadth [engagement-dir] [Dnn …]

Arguments: `$ARGUMENTS`. Engagement `E`: the folder named there, else `$SANE_ENGAGEMENT`, else the most recently
updated `BugBountyTarget/<Target>_<DDMMYYYY>/`. Domain ids given there restrict the run.

1. Read the phase, the authorisation and the lab mode from disk:
   ```bash
   python3 scripts/state.py "$E"
   python3 -c 'import json,sys;e=json.load(open(sys.argv[1]+"/engagement.json"));a=e["authorisation"];print("PHASE:",e.get("phase"),"| lab:",(e.get("lab") or {}).get("mode"));print("AUTH:",a.get("basis") or "MISSING","| programme:",a.get("programme_url") or "-","| scope:",a.get("scope") or "-","| excluded:",a.get("excluded") or []);print("DECIDED:",e.get("domains_decided") or []);print("NA:",sorted((e.get("domains_na") or {}).keys()))' "$E"
   ```
   Basis `MISSING` or scope empty → stop: P0 is not passed, and there is no delegation without a recorded basis.
2. The phase decides the move: P0–P2 → `/engage`, `/lab`; **P3–P6 → continue**; P7 → `/chain`; P8–P9 → `/evidence`,
   `/report`. In P3 the workers run the applicability probes and return decisions; the workflow's merge step
   records them with `mark.py <eng> Dnn applies|n/a` (undecided ones you settle with `/domain`).
3. Devices: `bash scripts/doctor.sh --json` → `devices`. P5 and P6 are device-bound: one worker per device at a
   time; every agent of the session shares one rate budget.
4. Run `/breadth-phase` with args built from those files, never from memory:
   `{"engagement": "<E>", "phase": "<Pn>", "authorisation": <engagement.json.authorisation>, "devices": [<serials>],
   "lab_mode": "<lab.mode>"}` — add `"domains": ["Dnn", …]` to restrict it. The workflow opens every worker brief
   with that authorisation line and merges the partials itself.
5. Confirm the merge (idempotent): `python3 scripts/coverage.py "$E/checklist-status.csv" --merge --dry-run` shows
   nothing pending, else run `--merge --archive`. A REJECTED row goes back to its domain in the next run; a domain
   in the result's `missing` list is re-run.
6. Update `report/assessment-status.md` (COMPLETED / IN PROGRESS / NEXT TARGET / BLOCKERS from the `gaps`; the
   `candidates` under CHAINING IDEAS), then `/push`. A `checklist-gap` gap → `/gap`, generalised.
7. The returned `candidates` → `/verify`. Phase exit: `python3 scripts/gate.py "$E" p<n>`; `--pass p<n>` only when open.
