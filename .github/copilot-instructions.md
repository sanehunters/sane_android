# Copilot / Codex instructions

Read `START.md` in full before acting; `AGENTS.md` is the standard operating procedure. Phases P0→P9 in
order, no escalation before P7. Load `cards/Dnn.md` and `python3 scripts/item.py Dnn-NNN`, never a whole
chapter. Every settled item goes into the engagement's `checklist-status.csv` with the mechanism; keep
`engagement.json` and `report/assessment-status.md` current; commit and push after every batch with `git -C <eng>`
(the engagement folder is its own private evidence repo; never commit it to the methodology repo). Never commit
an APK, DEX, `.so`, keystore, HAR or credential. Before committing run `bash .claude/hooks/pre-commit-check.sh`;
before stopping run `bash .claude/hooks/stop-guard.sh --manual`.
