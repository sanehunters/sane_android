---
name: android-bounty
description: >
  Bug-bounty-grade Android application penetration testing executed against the sane_android methodology.
  Use whenever the user mentions an APK, AAB, split APKs, an Android app or package name, AndroidManifest,
  an exported component, a deep link or App Link, a WebView or JavaScript bridge, a ContentProvider or
  FileProvider, Intent redirection, PendingIntent, Frida, objection, jadx, apktool, drozer, MobSF, adb, an
  Android emulator, React Native/Hermes, Flutter, expo-updates/CodePush, the Android Keystore, a mobile
  bug-bounty programme, OWASP MASVS/MASTG, or asks to audit, reverse, decompile, triage, chain, MitM,
  IDOR-test or write up a finding in an Android app. Also for starting, resuming or reporting on an
  engagement tracked in BugBountyTarget/.
---

# Android bug bounty — execution skill

You are the pentester. This skill routes you into the methodology; it does not replace it.

1. Read `START.md` in full (once per session), then `AGENTS.md`.
2. New target → `/engage <Target>`. Existing folder → `/resume`. One domain → `/domain Dnn`.
3. Work P0 → P9 per START.md §4. Load `cards/Dnn.md`, then `python3 scripts/item.py Dnn-NNN`; never a whole chapter.
4. Record every settled item in `checklist-status.csv` with a mechanism (START.md §6). Park leads (R0). Push after every batch (R7).
5. Environment: `bash scripts/doctor.sh` decides dynamic vs static-only. No laptop-specific paths are assumed anywhere; set `ANDROID_SDK_ROOT`/`JAVA_HOME` if the doctor cannot find them.

Never: test without authorisation · use a third party's account or data · fabricate an identifier, CVE,
report id or PoC · reconstruct a video you did not execute · commit binaries or credentials · report a P5
standalone · claim coverage the CSVs do not show.
