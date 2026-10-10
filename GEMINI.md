# GEMINI.md — for Gemini CLI / Gemini Code Assist sessions

This repository is an Android bug-bounty methodology executed by an autonomous model. **Read `START.md` in
full first**, then `AGENTS.md`. They are vendor-neutral and complete. The Claude Code hooks under `.claude/`
will not run for you, so follow `START.md` §10: run `python3 scripts/state.py <engagement>` at the start of
every session, `bash .claude/hooks/pre-commit-check.sh` before every commit, and
`bash .claude/hooks/stop-guard.sh --manual` before you stop. Never end a session with unpushed engagement state.
