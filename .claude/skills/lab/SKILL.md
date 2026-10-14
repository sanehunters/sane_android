---
name: lab
description: Build and verify the analysis harness (phase 1) and record it.
---

# /lab

Follow `docs/03-lab-and-harness.md`. Verification block must pass: TLS intercepted from a host that does not pin; Frida attaches to a test process; root works (or static-only declared); a lockscreen exists on the device; every instrument has a positive control. Record results as `engagement.json.lab = {"mode": "dynamic"|"static-only", "tls_intercept": true|false, "frida": true|false, "root": true|false, "lockscreen": true|false, "positive_controls": true|false}` (the keys `scripts/gate.py p1` checks; new-engagement.sh seeds them as null) with the proof under `logs/harness/` (one file per instrument's positive control). The commonest false conclusion in mobile testing is "the app is pinned" when the CA was installed where the OS ignores it — confirm pinning from the binary, never from behaviour.
