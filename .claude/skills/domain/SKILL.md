---
name: domain
description: "Work one checklist domain end to end: card, applicability probe, items in triage order, recording, pushing. Use for 'work domain Dnn' or when the state machine reaches a domain."
argument-hint: "Dnn"
---

# /domain Dnn

1. `cat cards/Dnn.md` — crux question, applicability probe, triage order, one line per item.
2. Run the **Applicability probe**. If the domain does not apply: `python3 scripts/mark.py $E Dnn n/a --note "<the probe's exact note, ≥25 chars>"` (writes every Dnn row and `engagement.json.domains_na.Dnn` in one validated call), commit, done. If it does apply: `python3 scripts/mark.py $E Dnn applies --note "<probe evidence, ≥25 chars>"` (records `engagement.json.domains_applicable.Dnn` and `domains_decided`; writes no rows — they are worked in step 3; `python3 scripts/gate.py $E p3` lists every domain still undecided).
3. For each item in the card's **triage order**:
   - `python3 scripts/item.py Dnn-NNN` → run **How**, compare with **Proof**, save raw output to `logs/Dnn-NNN.txt`.
   - Settle the row only through `python3 scripts/mark.py $E Dnn-NNN <result> --note "..." [--evidence logs/Dnn-NNN.txt]` (START.md §6: `finding` with `H-0NN` · `ruled-out` with the mechanism and `file:line` · `blocked` with `needs: …` · `n/a` with why).
   - Juicy? `/park Dnn-NNN` and move on (R0). Three strikes (≈15 calls / same probe ×3 / exploit code before P7) → park.
4. Every 10–15 items: update `report/assessment-status.md`, then `/push` (`git -C $E add -A && git -C $E commit`; the hook pushes only to the private evidence remote).
5. Done when every Dnn row is settled **and** every matching row in `inventory/*.csv` is `tested=true`.

Open `checklist/Dnn-*.md` only for the graveyard (never file standalone) and the cross-surface joins (park for P7).
