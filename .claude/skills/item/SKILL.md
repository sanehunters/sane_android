---
name: item
description: Run one checklist item by id and record the result.
---

# /item Dnn-NNN

`python3 scripts/item.py Dnn-NNN` (add `--field how` for just the commands, `--xrefs` for related items). Run **How**; the result is only a finding if **Proof** is observed. Record only through `python3 scripts/mark.py $E Dnn-NNN <result> --note "..." --evidence logs/Dnn-NNN.txt` (START.md §6); raw output to `logs/Dnn-NNN.txt`. If it is juicy, `/park` it — escalation is P7.
