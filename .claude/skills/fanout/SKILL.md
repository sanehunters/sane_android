---
name: fanout
description: Split breadth work across sub-agents by domain without clobbering shared state.
---

# /fanout

Use `prompts/05-fanout-multi-agent.md`. Rules: one domain per worker, never two workers on one domain; the coordinator alone edits `engagement.json` and `report/assessment-status.md`; workers write `checklist-status.Dnn.partial.csv` and `logs/Dnn-*.txt`; the coordinator merges with `python3 scripts/coverage.py <eng>/checklist-status.csv --merge [--dry-run] [--archive]` (a partial row must satisfy `row_valid` or it is rejected; a row outside the file's domain is rejected), commits the evidence repo, `/push`. Worker hypothesis ids `H-Dnn-NN` are accepted by `mark.py`/`gate.py`; renumber to `H-NNN` when the stub is adopted into `hypotheses/`. P7 is single-agent.
