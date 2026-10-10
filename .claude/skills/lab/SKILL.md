---
name: lab
description: Build and verify the analysis harness (phase 1) and record it.
---

# /lab

Follow `docs/03-lab-and-harness.md`. Verification block must pass: TLS intercepted from a host that does not pin; Frida attaches to a test process; root works (or static-only declared); a lockscreen exists on the device; every instrument has a positive control. Record results in `engagement.json.lab` and `logs/harness/`. The commonest false conclusion in mobile testing is "the app is pinned" when the CA was installed where the OS ignores it — confirm pinning from the binary, never from behaviour.
