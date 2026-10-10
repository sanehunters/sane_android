---
name: push
description: Commit and push the engagement state now (rule R7).
---

# /push

1. Update `<eng>/report/assessment-status.md` (COMPLETED / IN PROGRESS / NEXT TARGET / BLOCKERS) and `engagement.json.updated`.
2. `bash .claude/hooks/pre-commit-check.sh` — must print clean.
3. `git add <eng> && git commit -m "<Target> <phase>: <what was settled>" && git push`.
Never commit APK/AAB/DEX/SO/keystore/HAR/PCAP, videos over 5 MB, credentials or third-party data.
