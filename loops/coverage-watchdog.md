# coverage-watchdog — every 30 minutes

```
/loop 30m Run `python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory --brief`
and compare with the previous run recorded in <eng>/logs/loop-coverage.log. If fewer than 5 rows were
settled since the last run, state which item you have been on, apply the three-strike rule (park it in
hypotheses/ and move to the next open item in the current phase). Append the new count to the log.
Stop this loop when engagement.json.phase is P9.
```
