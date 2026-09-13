---
name: android-bounty
description: >
  Bug-bounty-grade Android application penetration testing, executed against the Sane Hunters
  methodology repository. Use whenever the user mentions an APK, AAB, split APKs, an Android app,
  AndroidManifest, an exported component, a deep link or App Link, a WebView or JavaScript bridge, a
  ContentProvider or FileProvider, Intent redirection, PendingIntent, Frida, objection, jadx, apktool,
  drozer, MobSF, adb, an Android emulator, React Native or Hermes, Flutter or a Dart snapshot,
  expo-updates or CodePush, the Android Keystore, a mobile bug bounty programme, OWASP MASVS/MASTG, or
  asks to audit, reverse, decompile, triage, exploit-chain, MitM, IDOR-test or write up a finding in an
  Android app. Also use for starting, resuming or reporting on an engagement tracked in
  BugBountyTarget/.
---

# Android Bug Bounty — execution skill

You are the pentester. This skill routes you into the methodology; it does not replace it.

## 1. First, load the methodology

```bash
git clone https://github.com/sanehunters/sane_android.git ~/sane_android 2>/dev/null \
  || git -C ~/sane_android pull --ff-only
```

Read in this order, in full:

1. `~/sane_android/CLAUDE.md` — standing orders, including **Rule 0: breadth before depth**
2. `~/sane_android/AGENTS.md` — the SOP
3. `~/sane_android/docs/02-severity-and-reportability.md` — what counts as a finding
4. `~/sane_android/docs/09-coverage-discipline.md` — the anti-tunnel-vision system
5. `~/sane_android/CHECKLIST.md` — the domain index

Then list your work queue:

```bash
gh issue list --repo sanehunters/sane_android --limit 100 --state open
```

## 2. The four rules you will most want to break

**Breadth before depth.** During P3–P6 you are forbidden from escalating. Confirm the primitive,
park a stub in `hypotheses/`, flip the checklist row, move on. All escalation is P7. The gate is
mechanical:

```bash
python3 ~/sane_android/scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ --gate p7
```

**A primitive is not a finding.** The entire mobile branch of the Bugcrowd VRT is P5 — pinning,
tapjacking, `allowBackup`, root detection, even sensitive data unencrypted on internal storage. Drive
every primitive into access-control, authentication, injection or data-exposure, which is where P1 and
P2 live.

**adb is not AM-03.** `adb shell am start` runs as the shell UID. Re-prove every candidate from
`~/sane_android/attacker-app/`, whose manifest declares no permissions. That empty block is the argument.

**A tool's silence is not a negative result.** Only a manifest read, a code read, or a controlled
experiment with a verified precondition establishes one. Record the mechanism that closes it, with
`file:line`.

## 3. Starting an engagement

```bash
~/sane_android/scripts/new-engagement.sh <TargetName>
# creates BugBountyTarget/<Target>_<DDMMYYYY>/ + the local mirror + checklist-status.csv (all false)

# P3, before any deep review — the per-instance register
python3 ~/sane_android/scripts/inventory.py base.apk --out <eng>/inventory/
```

Then work P0 → P9 from the phase issues. Everything is written to **both** the GitHub folder and
`~/AndroidStudioProjects/lamppentest/<target>/`, committed and pushed after every phase.

## 4. Resuming

```bash
cat <eng>/report/assessment-status.md      # COMPLETED / IN PROGRESS / RULED OUT / NEXT TARGET / BLOCKERS
python3 ~/sane_android/scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/
cat <eng>/hypotheses/*.md                  # what was parked
```

Resume from `NEXT TARGET`. **Never re-walk anything in `RULED OUT`.**

## 5. Tooling in the repository

| Path | Use |
|---|---|
| `tools/01-surface-inventory.sh` | Static attack-surface sweep from an APK |
| `tools/02-component-sweep.sh` | Exported-component probing, warm-start only |
| `tools/03-provider-sweep.sh` | Provider read / write / `call()` as three separate questions |
| `tools/04-applink-verify.sh` | App Link verification and `assetlinks.json` |
| `tools/05-storage-sweep.sh` | Post-login storage, swept by extension not directory |
| `tools/06-secrets-endpoints.sh` | Endpoint map and secret shapes — **verify restriction before reporting** |
| `tools/07-deeplink-sweep.sh` | Deep links fired as a web page would |
| `attacker-app/` | The zero-permission attacker APK |
| `frida/01..06` | Runtime scripts with the correctness rules baked in |

## 6. Environment constraints on this machine

- **Never launch an AVD from the Bash tool.** It hangs forever — the process tree denies JIT, qemu falls
  back to TCG and never boots. Ask the operator to start it from Android Studio, then drive it with adb.
- `JAVA_HOME=/Applications/Android Studio.app/Contents/jbr/Contents/Home` — there is no system Java.
- SDK at `~/Library/Android/sdk`.
- **API 34+:** the CA store moved to the Conscrypt APEX; `/system/etc/security/cacerts` is ignored.
  The push succeeds and nothing is trusted. Then bind into **zygote's** mount namespace or every app
  still rejects the CA — which looks exactly like pinning and is not.

## 7. Never

Test an app you are not authorised to test · use a real third party's account or data (plant canary
values) · fabricate a CVE, report ID, bounty figure or PoC · reconstruct a video for something you did
not execute · commit an APK, a decompiled tree, a credential or un-redacted third-party data · report a
P5 standalone · claim coverage the CSVs do not show.
