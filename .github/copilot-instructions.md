# Copilot / Codex instructions

Read `START.md` in full before acting; `AGENTS.md` is the standard operating procedure. Phases P0→P9 in
order, no escalation before P7. Load `cards/Dnn.md` and `python3 scripts/item.py Dnn-NNN`, never a whole
chapter. Every settled item goes into the engagement's `checklist-status.csv` with the mechanism; keep
`engagement.json` and `report/assessment-status.md` current; commit and push after every batch with `git -C <eng>`
(each engagement folder is its own git repository — the evidence repo — pushed only to its private remote; never commit or push
engagement evidence to the methodology repository (it is public); with no remote the hooks state the blocker `no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>`). Never commit
an APK, DEX, `.so`, keystore, HAR or credential. Before committing run `bash .claude/hooks/pre-commit-check.sh`;
before stopping run `bash .claude/hooks/stop-guard.sh --manual`.
