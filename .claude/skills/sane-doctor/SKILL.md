---
name: sane-doctor
description: Detect the environment (OS, SDK, device, root, tools) and decide dynamic vs static-only mode.
allowed-tools: Bash(bash scripts/doctor.sh:*)
---

# /sane-doctor   (`sane-` because `/doctor` is a Claude Code built-in)

`bash scripts/doctor.sh` (add `--json` for the machine view). Empty output means the environment is UNVERIFIED (bash <4 or a crash) — record that, never a guessed mode. Copy every line under `blocked` into `engagement.json.blockers` and the BLOCKERS section. In static-only mode, items whose `How` needs a device are settled `blocked` with the doctor's exact reason — never guessed.
