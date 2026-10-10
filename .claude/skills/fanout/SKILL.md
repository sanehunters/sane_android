---
name: fanout
description: Split breadth work across sub-agents by domain without clobbering shared state.
---

# /fanout

Use `prompts/05-fanout-multi-agent.md`. Rules: one domain per worker, never two workers on one domain; the coordinator alone edits `engagement.json` and `report/assessment-status.md`; workers write `checklist-status.Dnn.partial.csv` and `logs/Dnn-*.txt`; the coordinator merges rows by `item_id`, commits, pushes. P7 is single-agent.
