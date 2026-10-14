# push-cadence — every 20 minutes

```
/loop 20m If `git -C <eng> status --porcelain` is non-empty or (an evidence remote is configured and
`git -C <eng> rev-list --count @{u}..HEAD` is greater than 0): update <eng>/report/assessment-status.md
(COMPLETED / IN PROGRESS / NEXT TARGET / BLOCKERS), run `bash .claude/hooks/pre-commit-check.sh <eng>`, then
`git -C <eng> add -A && git -C <eng> commit -m "<Target> <phase>: progress"`; the hook pushes to the private
evidence remote (never the methodology origin). Report one line: what was pushed, "committed locally only — no
evidence remote", or "nothing to commit".
```
