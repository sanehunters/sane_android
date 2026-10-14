---
name: push
description: Commit the engagement's evidence repo now and push it to the private evidence remote (rule R7).
argument-hint: "[engagement-dir]"
when_to_use: After every batch of 10–15 settled items, after every merge, at every phase gate and before the session ends (R7).
---

# /push

1. Update `<eng>/report/assessment-status.md` (COMPLETED / IN PROGRESS / NEXT TARGET / BLOCKERS) and `engagement.json.updated`.
2. `bash .claude/hooks/pre-commit-check.sh <eng>` — must print clean.
3. `git -C <eng> add -A && git -C <eng> commit -m "<Target> <phase>: <what was settled>"` — the engagement folder is its own git repository; the methodology repo (public) never receives evidence.
4. Push goes only to the private evidence remote: the PostToolUse hook does it when `engagement.json.evidence_remote` / `SANE_EVIDENCE_REMOTE` is set (manually: `git -C <eng> push`). Without one, say "evidence is committed locally only" and keep the blocker in `engagement.json.blockers`.
Never commit APK/AAB/DEX/SO/keystore/key/HAR/PCAP, decompiled trees, `secrets/`, videos over 5 MB, credentials or third-party data.
