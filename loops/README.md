# loops/ — recurring self-checks for a long-running session

A model working a two-week engagement in one session drifts: it chases one bug, forgets to push, stops
updating state. These loops are the mechanical counter. Start one with `/loop <interval> <prompt>` (paste the
prompt block; `<eng>` is the engagement folder, its own git repo). Each loop is idempotent and cheap. A loop
prompt is a delegated task: keep the engagement path in it, so the authorisation and scope in that engagement's
`engagement.json` apply (`docs/10-agent-operations.md` §2).

| Loop | Interval | Stops when |
|---|---|---|
| `coverage-watchdog.md` | 30 min | the engagement reaches P9 |
| `push-cadence.md` | 20 min | — |
| `rabbit-hole-check.md` | 15 min during P3–P6 | P7 begins |
| `hypothesis-sweeper.md` | 30 min during P7 | no parked hypothesis remains |
| `status-heartbeat.md` | 60 min | — |
