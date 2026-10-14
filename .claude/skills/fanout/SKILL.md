---
name: fanout
description: Split breadth work across sub-agents by domain without clobbering shared state — the manual protocol behind /breadth.
when_to_use: P3–P6 when /breadth (the saved workflow /breadth-phase) is not the right fit, e.g. a hand-picked set of domains with custom device assignments.
argument-hint: "[phase] [Dnn ...]"
---

# /fanout

Prefer `/breadth`, which runs the saved workflow `/breadth-phase`; this is the protocol it implements. Use `prompts/05-fanout-multi-agent.md` with the `domain-worker` agent. Rules: one domain per worker, never two workers on one domain; every worker brief opens with the authorisation basis, programme and scope from `engagement.json`; never more device-bound workers than devices (`bash scripts/doctor.sh --json`) — every agent of a session shares one rate budget; the coordinator alone edits `engagement.json` and `report/assessment-status.md`; workers write `checklist-status.Dnn.partial.csv` and `logs/Dnn-*.txt`; the coordinator merges with `python3 scripts/coverage.py <eng>/checklist-status.csv --merge [--dry-run] [--archive]` (a partial row must satisfy `row_valid` or it is rejected; a row outside the file's domain is rejected), commits the evidence repo, `/push`. Worker hypothesis ids `H-Dnn-NN` are accepted as-is by `mark.py`/`gate.py`/`coverage.py --merge`; renumbering to `H-NNN` is optional and only after the merge. Workers never run `mark.py … applies` or a whole-domain `n/a` — applicability is the coordinator's P3 decision. Workers never commit or push. P7 is single-agent (`/chain`).
