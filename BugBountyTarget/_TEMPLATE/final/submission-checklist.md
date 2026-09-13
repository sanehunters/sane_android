# Submission checklist — <target> <version>

## Per-finding readiness
| | F-001 | F-002 | F-003 |
|---|---|---|---|
| Root cause at exact `file:line` | | | |
| Precondition stated exactly | | | |
| Control that fails is named | | | |
| Positive **and** negative control run | | | |
| Reproduced on device | | | |
| Video PoC (seven-beat format) | | | |
| Canary value planted and shown twice | | | |
| Max impact tested, not assumed | | | |
| Severity justified from demonstrated capability | | | |
| Maps to a non-P5 VRT path | | | |
| Remediation written | | | |

## Before you submit
- [ ] Confirm the app is **in scope** for the programme, and that local dynamic testing is permitted
- [ ] Re-verify on the current store build — record the exact version tested
- [ ] Redact any third party's data from screenshots and HAR files
- [ ] File separate findings for separate components; do **not** bundle
- [ ] File one finding per root cause — three call sites of one defect is **one** finding. Filing three
      inflates the count for a single defect and triagers penalise that
- [ ] File chains in order: primitives first so their ids exist, then the consumer, then backfill
- [ ] Do not submit anything from the ruled-out or verified-non-issue lists

## Honest gaps to disclose if asked
- <what was not tested, why, and which environment would test it>
