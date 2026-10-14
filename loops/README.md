# loops/ — recurring self-checks for a long-running session

A model working a two-week engagement in one session drifts: it chases one bug, forgets to push, stops
updating state. These loops are the mechanical counter. Under Claude Code start one with
`/loop <interval> <prompt>` (paste the prompt block; `<eng>` is the engagement folder, its own git repo); under other runners schedule the same prompt with
whatever timer you have. Each loop is idempotent and cheap.

| Loop | Interval | Stops when |
|---|---|---|
| `coverage-watchdog.md` | 30 min | the engagement reaches P9 |
| `push-cadence.md` | 20 min | — |
| `rabbit-hole-check.md` | 15 min during P3–P6 | P7 begins |
| `hypothesis-sweeper.md` | 30 min during P7 | no parked hypothesis remains |
| `status-heartbeat.md` | 60 min | — |
