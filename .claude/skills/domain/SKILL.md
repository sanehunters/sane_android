---
name: domain
description: Work one checklist domain end to end: card, applicability probe, items in triage order, recording, pushing. Use for 'work domain Dnn' or when the state machine reaches a domain.
---

# /domain Dnn

1. `cat cards/Dnn.md` — crux question, applicability probe, triage order, one line per item.
2. Run the **Applicability probe**. If the domain does not apply: set every Dnn row `completed=true, result=n/a, notes=<the probe's exact note>`, add `engagement.json.domains_na.Dnn`, commit, done.
3. For each item in the card's **triage order**:
   - `python3 scripts/item.py Dnn-NNN` → run **How**, compare with **Proof**, save raw output to `logs/Dnn-NNN.txt`.
   - Settle the row per START.md §6 (`finding` with `H-0NN` · `ruled-out` with the mechanism and `file:line` · `blocked` with what is missing · `n/a` with why).
   - Juicy? `/park Dnn-NNN` and move on (R0). Three strikes (≈15 calls / same probe ×3 / exploit code before P7) → park.
4. Every 10–15 items: update `report/assessment-status.md`, `git add <eng> && git commit && git push`.
5. Done when every Dnn row is settled **and** every matching row in `inventory/*.csv` is `tested=true`.

Open `checklist/Dnn-*.md` only for the graveyard (never file standalone) and the cross-surface joins (park for P7).
