# push-cadence — every 20 minutes

```
/loop 20m If `git status --porcelain -- <eng>` is non-empty or `git rev-list --count @{u}..HEAD` is
greater than 0: update <eng>/report/assessment-status.md (COMPLETED / IN PROGRESS / NEXT TARGET / BLOCKERS),
run `bash .claude/hooks/pre-commit-check.sh`, then `git add <eng> && git commit -m "<Target> <phase>: progress" && git push`.
Report one line: what was pushed, or "nothing to push".
```
