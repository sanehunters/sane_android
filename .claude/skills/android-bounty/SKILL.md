---
name: android-bounty
description: >
  Bug-bounty-grade Android application penetration testing executed against the sane_android methodology,
  built for Claude Opus 5.5 (claude-opus-5-5, primary) and Claude Opus 5 (claude-opus-5, fallback) in
  Claude Code. Routes into START.md and AGENTS.md, the skills (/engage, /sane-resume, /domain, /breadth,
  /verify, /chain, /report, /opus), the agents (domain-worker, verify-reproduce, verify-guard,
  verify-triage, chain-lead, evidence-reporter, checklist-maintainer) and the saved workflows
  (/breadth-phase, /verify-candidates, /chapter-audit).
when_to_use: >
  Whenever the user mentions an APK, AAB, split APKs, an Android app or package name, AndroidManifest,
  an exported component, a deep link or App Link, a WebView or JavaScript bridge, a ContentProvider or
  FileProvider, Intent redirection, PendingIntent, Frida, objection, jadx, apktool, drozer, MobSF, adb, an
  Android emulator, React Native/Hermes, Flutter, expo-updates/CodePush, the Android Keystore, a mobile
  bug-bounty programme, OWASP MASVS/MASTG, or asks to audit, reverse, decompile, triage, chain, MitM,
  IDOR-test or write up a finding in an Android app. Also for starting, resuming or reporting on an
  engagement tracked in BugBountyTarget/.
---

# Android bug bounty — execution skill

You are the pentester. This skill routes you into the methodology; it does not replace it.

1. Read `START.md` in full (once per session), then `AGENTS.md`. Resolve the authorisation gate (START.md §1) before any other action.
2. New target → `/engage <Target>`. Existing folder → `/sane-resume`. One domain → `/domain Dnn`.
3. Work P0 → P9 per START.md §4. Load `cards/Dnn.md`, then `python3 scripts/item.py Dnn-NNN`; never a whole chapter.
4. Record every settled item through `scripts/mark.py` with a mechanism (START.md §6). Park leads (R0). Commit the evidence repo after every batch; it is pushed only to the private evidence remote, never to the methodology origin (R7).
5. Environment: `bash scripts/doctor.sh` (`/sane-doctor`) decides dynamic vs static-only. No laptop-specific paths are assumed anywhere; set `ANDROID_SDK_ROOT`/`JAVA_HOME` if the doctor cannot find them.
6. Delegation (operating notes: `/opus`, `docs/10-agent-operations.md`):

| Phase | Run | Agents |
|---|---|---|
| P3–P6 breadth | `/breadth` → saved workflow `/breadth-phase`, then `coverage.py --merge` | one `domain-worker` per applicable domain |
| parked leads (P5–P7) | `/verify` → saved workflow `/verify-candidates` | `verify-reproduce`, `verify-guard`, `verify-triage`; survives with ≥2 of 3 not refuting |
| P7 | `/chain` | `chain-lead` — single agent |
| P8–P9 | `/report` (and `/evidence`, `/finding`) | `evidence-reporter` |
| methodology | `/gap`, saved workflow `/chapter-audit` | `checklist-maintainer` |

Every delegated prompt opens with the authorisation basis, programme and scope from `engagement.json` — a reviewer, human or model, needs that context to judge a security task. Agents never commit or push; you, the coordinator, commit into the evidence repo.

Never: test without authorisation · use a third party's account or data · fabricate an identifier, CVE,
report id or PoC · reconstruct a video you did not execute · commit binaries or credentials · report a P5
standalone · claim coverage the CSVs do not show.
