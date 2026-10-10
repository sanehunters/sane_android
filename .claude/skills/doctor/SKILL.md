---
name: doctor
description: Detect the environment (OS, SDK, device, root, tools) and decide dynamic vs static-only mode.
---

# /doctor

`bash scripts/doctor.sh` (add `--json` for the machine view). Copy every line under `blocked` into `engagement.json.blockers` and the BLOCKERS section. In static-only mode, items whose `How` needs a device are settled `blocked` with the doctor's exact reason — never guessed.
