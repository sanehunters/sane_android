---
name: engage
description: Start a new Android engagement: environment check, engagement folder, state file, first commit. Use when the operator hands over an APK or package plus a scope and an authorisation basis.
---

# /engage <TargetName>

Preconditions: an authorisation basis is stated (own app · signed SoW · public programme · vendor VDP · lab app). If not, ask once and stop.

1. `bash scripts/doctor.sh` — record whether you are in dynamic or static-only mode.
2. `scripts/new-engagement.sh <TargetName>` → `E=BugBountyTarget/<TargetName>_<DDMMYYYY>`.
3. Fill `$E/engagement.json`: `target.*` (package, version, versionCode, targetSdk, minSdk, framework, ota), `authorisation.*` (basis, scope, programme_url, excluded), `accounts.a/b`. Set `updated`.
4. Fill the header of `$E/report/assessment-status.md`; put doctor's blocked list under BLOCKERS verbatim.
5. `git add $E && git commit -m "engage: <TargetName> P0" && git push`.
6. Continue with START.md §4 at P0 (scoping questionnaire → accounts, OTP route, sandbox, KYC), then `/lab`.

Exit: `python3 scripts/state.py $E` shows phase P0 with the target identity filled and zero warnings.
