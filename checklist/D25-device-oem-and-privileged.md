# D25 · Device, OEM, Firmware & Privileged Surfaces

> This is the one Android domain whose own VRT branch is not pinned to P5: `insecure_os_firmware`
> carries P1 and P2 leaves, and `broken_access_control|privilege_escalation` is rated on what you
> demonstrate. The price of that ceiling is a scope gate — almost every app bounty brief scopes the Play
> build only, and everything in this chapter dies at "out of scope" unless the device, the OEM image or
> a preinstalled build of the target is explicitly in scope. Establish that first; the rest of the
> chapter is worthless without it.

| | |
|---|---|
| **Phases** | P4 static and image analysis, P5 IPC and privileged-surface probing |
| **Milestones** | M4, M5 |
| **VRT ceiling** | `insecure_os_firmware.hardcoded_password.privileged_user` (**P1**, CWE-259) and `insecure_os_firmware.command_injection` (**P1**) for device/firmware scope; `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) for a preinstalled-app confused deputy; `insecure_os_firmware.local_administrator_on_default_environment` (**P2**, CWE-276) and `insecure_os_firmware.over_permissioned_credentials_on_storage` (**P2**, CWE-250). When the device is out of scope the same observations are environment notes with no rating at all — say so rather than filing them |
| **Primary attacker model** | AM-03 zero-permission local app (the OEM confused-deputy class); AM-10/AM-11 physical for the accessory, USB and AFU items; AM-12 own rooted device for the policy and firmware machinery, which is **not an attack** |
| **Maps to** | MASVS-PLATFORM, MASVS-STORAGE-1, MASVS-STORAGE-2, MASVS-CRYPTO-2; MASTG-KNOW-0017, MASTG-KNOW-0020, MASTG-KNOW-0049, MASTG-TEST-0203, MASTG-TEST-0247, MASTG-TEST-0249, MASTG-TEST-0364, MASTG-TEST-0365, MASTG-TEST-0366, MASTG-TOOL-0004; MASWE-0005, MASWE-0017, MASWE-0018, MASWE-0026, MASWE-0029, MASWE-0032, MASWE-0050, MASWE-0070, MASWE-0078; CWE-16, CWE-250, CWE-259, CWE-269, CWE-276, CWE-434, CWE-532, CWE-798, CWE-926, CWE-927; ATT&CK T1398, T1458, T1474.002, T1474.003, T1625.001, T1645, mitigations M1001, M1002, M1004, M1012 |

## Why this domain pays

It pays because the ordinary rules of mobile severity do not apply here. Everywhere else in this
checklist the VRT caps the native Android categories at P5 and you have to argue your way into a
server-side or access-control node. In `insecure_os_firmware` the taxonomy already agrees with you:
a hardcoded credential for a privileged user is P1 with the baseline vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`,
command injection on the image is P1, local administrator on the default environment is P2, and
over-permissioned credentials on storage is P2. Nothing in this chapter needs the escalation gymnastics
that D11 or D21 need. What it needs instead is authorisation.

The base rate is real and it is published. Oversecured's Samsung work recorded 176 vulnerabilities in
preinstalled apps across 2022–2025 for $200k+ in Samsung bounties, on a fleet of 100M+ devices
pre-patch, and its named exemplars are all the same handful of shapes: `com.sec.factory.camera`, a
debug package left on production with system privileges and an unprotected receiver accepting test
commands, giving silent video recording; `WifiServiceImpl.semAddPublicDnsAddr()`, a DNS hijack from a
zero-permission caller; the `themecenter` ThemeManager path traversal into arbitrary file write with
system privileges; `com.sec.android.app.dexonpc`, an exported service giving screen capture without
consent. The 2021 Samsung set is a pattern library in itself — `DualDARInitService` (CVE-2021-25388),
`com.android.managedprovisioning` (CVE-2021-25356), `KnoxSettingCheckLockTypeActivity` (CVE-2021-25391),
`com.android.settings` in an `android.uid.system` package (CVE-2021-25393), `NotificationBnRReceiver`
(CVE-2021-25392), `PhotoringReceiver` (CVE-2021-25397), `PermissionsRequestActivity` (CVE-2021-25390).
The same class is still producing CVEs: CVE-2026-20983 (Samsung Dialer, improper component export →
arbitrary activity launch with Dialer privileges), CVE-2026-21059 (Samsung Contacts → arbitrary file
delete at system privilege), CVE-2025-10184 (OnePlus OxygenOS telephony provider permission bypass).
CWE-926 "Improper Export of Android Application Components" had 15 new CVEs recorded in 2026 alone at
the time the corpus was read. None of this is exotic. It is D04–D08 run against a package that happens
to hold `INSTALL_PACKAGES`.

Be honest about the other half. For a standard store-app engagement most of this chapter is graveyard,
and the corpus says so repeatedly and in the vendors' own words: "out of scope for most app-only bounty
briefs — check the brief before spending time here". The three things that survive an app-only scope
are (a) whether the *target app itself* ships as a preinstalled or privileged build somewhere, because
that turns every other chapter's finding up a band; (b) the accessory and companion surfaces the app
declares in its own manifest — USB filters, GATT servers, `CarAppService`, `WearableListenerService`,
CDM associations — which are app-owned and in scope by definition; and (c) the multi-user, work-profile
and Private Space boundaries, which the Android & Google Devices programme buys explicitly
("Multi-User & Private Space: Cross-user sensitive data access") and which the corpus identifies as the
weakest-covered attacker model in the entire public checklist literature. Everything else in this
chapter is for a device programme, and belongs in the OEM's VRP rather than the app client's report.

## The crux question

**Is the device, the OEM image, or a preinstalled build of this app in scope — and if only the app is,
which of its own manifest-declared physical, companion and cross-user surfaces hands an attacker a
channel that the phone UI and the lock screen never gate?**

## Applicability probe

This domain is never wholly n/a — D25-001, D25-004..008, D25-012, D25-024, D25-043, D25-046, D25-054, D25-065..066, D25-074 and D25-076..079 apply to every app. The probe decides the four **blocks** and writes a partial-n/a note for the rest. Run it once, before the triage order.

```bash
# 1. Scope: which surfaces the brief authorises (the clause itself goes in the note)
jq '.authorisation.scope' engagement.json          # look for: oem-scope / device image, enterprise (enrolled device), physical access, wear|auto|tv
# 2. Is the target privileged on any device you hold?  (flag, not path — Mainline/updated system apps live in /data/app)
adb -s $SERIAL shell dumpsys package $PKG | grep -E 'codePath=|pkgFlags=|privateFlags=|sharedUser'
# 3. App-owned physical / companion / lock-screen / admin surfaces in the manifest and code
grep -cE 'android.hardware.usb.action|android.nfc.action|HostApduService|androidx.car.app.CarAppService|com.google.android.gms.wearable|showWhenLocked|BIND_DEVICE_ADMIN|BIND_ACCESSIBILITY_SERVICE|CompanionDeviceManager' $DEC/apktool/AndroidManifest.xml
grep -rlE 'BluetoothGattServer|CompanionDeviceManager|getWifi\(\)|INTERACT_ACROSS_PROFILES|CrossProfileApps' $DEC/jadx/sources | wc -l
# 4. Hardware the physical block needs on THIS test device (false = blocked, never n/a)
adb -s $SERIAL shell 'for f in android.hardware.nfc android.hardware.nfc.hce android.hardware.bluetooth_le android.hardware.usb.host android.hardware.usb.accessory android.software.managed_users; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done; pm list users; pm get-max-users'
```

Decision table (all four read together):

| Block | Items | Applies when |
|---|---|---|
| OEM / image / sepolicy / firmware | D25-002..003, D25-009..011, D25-016..023, D25-025, D25-027..029, D25-031, D25-035..042, D25-047..048, D25-052..053, D25-081 | step 1 names the device image or OEM scope, **or** step 2 shows `pkgFlags=[ SYSTEM` / a `priv_app` domain for the target (then only D25-008..015 and the re-rating apply, not the OEM inventory) |
| Enterprise / managed device | D25-044 (fleet half), D25-068..073, D25-075, D25-082..083 | step 1 includes an enrolled device or the client's DPC / managed configuration |
| Physical / accessory / companion | D25-049..050, D25-055..059, D25-061..062 (+ D25-063 when wear/auto/tv endpoints exist) | step 3 declares the surface **and** step 4 shows the feature on the test device; physical-access vector accepted per D25-001 |
| Multi-user / Private Space | D25-065..067 | always (`pm list users` shows the capability); D25-067 needs API ≥ 35 |

n/a note (write it into the tracker for every row the table excludes, verbatim shape):

`D25 partial n/a — brief scopes the store build only (clause: "<quoted scope text>"); target is not preinstalled on any held device (pkgFlags has no SYSTEM, domain untrusted_app_NN on <fingerprint>) → OEM/image/firmware block D25-016..042/047/048/052/053/081 n/a; no enrolled device in scope → enterprise block D25-068..073/075/082/083 n/a; physical block limited to manifest-declared surfaces: <list or "none"> → remaining physical rows n/a. Hardware absent on <serial>: <features> → D25-<ids> BLOCKED (hardware), not n/a. Decided <date>, re-open if scope changes.`

## Triage order

1. **Settle scope and routing** (D25-001). Thirty seconds of reading the brief decides whether the next
   forty items are billable work or unauthorised testing. Nothing else here is safe to run first.
2. **Is the target itself privileged anywhere?** (D25-008 → D25-013). One `pm list packages -s -f` and a
   `dumpsys package`. If the answer is yes, every D04–D08 finding you already have goes up a band, and
   you should re-rate them before writing anything else.
3. **The app's own accessory and companion manifest surfaces** (D25-049, D25-050, D25-057, D25-058,
   D25-061, D25-062). These are in scope on an app-only brief, they are almost never reviewed, and they
   are reachable without the phone's UI or lock screen.
4. **Cross-user, work-profile and Private Space reach** (D25-065 → D25-068). Explicitly bought impact,
   cheap to test, and the corpus's weakest-covered model.
5. **The device posture block** (D25-004) before any dynamic work, because a finding produced on a
   permissive, unlocked, non-current device will be closed and you will not know why.
6. **The device-wide debuggable sweep** (D25-014). The single cheapest high-yield sweep that exists on
   an OEM handset: one loop, and `run-as` on a preinstalled package is the whole proof.
7. **OEM system-app exported surface** (D25-016 → D25-022), on a device brief only. Run the D04–D08
   battery against the non-AOSP inventory, not against AOSP packages.
8. **SELinux honesty gates** (D25-026 → D25-031) *before* you write the word "escalation" anywhere. Most
   "arbitrary write → RCE" claims die at policy, and dying in your own notes is free.
9. **Firmware and kernel work** (D25-035 → D25-042) last, and only on an explicit device/firmware scope —
   it is the most expensive work in the chapter and the most likely to be out of scope.
10. **Managed-device block** (D25-068 → D25-073, D25-075, D25-082 → D25-083) only when an enrolled device
    or the client's DPC is in scope — the Applicability probe decides.
11. **Reporting discipline** (D25-076 → D25-079) before submission, because this domain's findings are
    the ones triagers most often bounce for vector vagueness and for shell-UID reachability claims.

## Items

`$DEC` = `$E/decompiled` (START.md §6): `$DEC/jadx/sources` for jadx output, `$DEC/apktool` for the apktool tree.

### D25-001 · Settle device / image / app scope and route each finding to the correct programme

| | |
|---|---|
| **Severity ceiling** | Support (it is the gate that makes every other item in this chapter billable or not) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Requires** | — |
| **Maps to** | Google's three-programme routing rules; Samsung Mobile Security Rewards eligible-device list; Xiaomi VRP mobile/hardware tiers |

- **Test:** Three different products can be "the target": the Play build of an app, a preinstalled build
  of the same app on an OEM image, and the device image itself. They belong to three different
  programmes with three different rule sets, and a finding filed against the wrong one is closed as out
  of scope regardless of quality.
- **How:** Read the brief and write the answer down before touching the device. Apply the published
  routing: AOSP/platform bugs go to the Android and Google Devices Security Reward Program; a bug in a
  non-Google SDK used by a first-party app goes to the SDK maintainer first; Samsung preinstalled-app
  and firmware bugs go to Samsung Mobile Security Rewards against its published eligible-device list;
  Xiaomi's mobile and hardware tiers are on its HackerOne policy. Then record the three-line scope block:
```
SCOPE: app build = <Play | preinstalled on <model>/<fingerprint> | both>
       device image in scope = <yes/no>   OEM VRP separately notified = <yes/no>
       physical-access vector accepted by this programme = <yes/no>
```
  Check the physical/MitM clause specifically — programmes differ: PayPal lists "Attacks requiring
  physical access to a mobile device" **in scope**; Reddit excludes "Attacks requiring physical access
  to, root privileges on, or MITM of a user's device"; HackerOne's Core Ineligible list excludes
  physical-access attacks "unless explicitly in scope".
- **Proof:** The written scope block in the report's environment section, quoting the clause you relied
  on. When you find an OEM bug during an app engagement, the correct output is two artefacts: an
  environmental-risk note to the app client, and a separate report to the OEM's VRP.
- **Escalation:** A "yes" on device scope unlocks D25-016 → D25-042. A "no" reduces this chapter to
  D25-008 → D25-015, the accessory/companion block, and the multi-user block.
- **Ruled out when:** The brief scopes the Play Store build only and the app is not preinstalled on any
  image you can obtain. Record that as a coverage decision with the clause quoted — it is a defensible
  negative, and it stops a reviewer asking why the OEM surface is untested.

### D25-002 · Switch to the device taxonomy and state the vector separately from the surface

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-01 through AM-11, one per vector |
| **Applies to** | device, STB, IVI and companion-hardware engagements |
| **Requires** | oem-scope |
| **Maps to** | the senior-researcher corpus's device-attack-surface taxonomy (remote / network-adjacent / local / physical) |

- **Test:** When the target is a device rather than an app, the app-centric component taxonomy stops
  being useful. Re-enumerate along remote → network-adjacent → local → physical. Then, for every sink
  you report, state the **vector** and the **surface** as two separate sentences: the vector sets the
  requirements (interaction, authentication, proximity) and therefore the severity; the surface is the
  code, and it exists with or without a bug.
- **How:** Build the table before testing, and fill the last column by enumerating *other* vectors into
  the same sink:

| Tier | What it covers | Typical entry |
|---|---|---|
| Remote | no proximity, no interaction | baseband, kernel network stack, auto-rendering parsers (MMS/RCS, thumbnailer, notification image), vendor cloud |
| Network-adjacent | attacker on the same link | rogue AP, exposed listeners, `adb tcpip`, hotspot-materialised DNS/DHCP on `192.168.43.1` |
| Local | code already executing on the device | binder services, sockets, set-uid binaries, world-writable chardevs, netlink |
| Physical | attacker touches the hardware | USB modes, NFC, accessory channels, JTAG/UART, AFU state |

  Then write the two-part statement into the finding itself:
```
SURFACE: <library/service/parser>, reachable at <entry point>
VECTOR : <MMS | link | attached USB device | installed app | rogue AP>, requiring
         <no interaction | one tap | proximity <8 cm | physical contact>
OTHER VECTORS INTO THE SAME SURFACE: <list>
```
- **Proof:** The explicit two-part statement, plus the other-vectors list. One surface with many vectors
  means one fix is rarely the whole fix — an image parser reachable from the browser is also reachable
  from MMS, e-mail and any auto-rendering client, so when the vendor says "fixed", re-test every vector.
- **Escalation:** The vector list is what turns a Medium local finding into a High or Critical remote
  one without changing a line of the exploit.
- **Ruled out when:** The engagement is app-only and every sink you found is reachable only through the
  app's own IPC. Then the app-component taxonomy is the right one and this item does not apply — say so
  rather than inventing a physical vector to inflate the rating.

### D25-003 · Rate a surface on its four properties before spending a day attacking it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | device/OEM engagements |
| **Requires** | oem-scope |
| **Maps to** | the senior-researcher corpus's surface-ranking method |

- **Test:** Rank every enumerated surface on four properties and attack in that order: **vector
  requirements** (does it need interaction, authentication, proximity?), **privileges gained** (kernel >
  root/system > app sandbox), **memory safety** (C/C++ ≫ managed code for bug classes), and
  **complexity** (complex protocols and parsers make more mistakes).
- **How:** Score each surface 0–3 on the four axes and sort. Written out, the ordering explains itself:
  an un-interactive, system-privileged, memory-unsafe, complex parser — a vendor image codec reached by
  the thumbnailer — outranks an exported activity that needs a tap. Keep the table in the notes; it is
  the artefact that justifies what you did *not* test.
- **Proof:** A written triage order for the engagement, with the scores.
- **Escalation:** The top of the table is where D16 and D26 fuzzing effort goes; the bottom is what you
  document as deliberately deprioritised.
- **Ruled out when:** There is exactly one surface in scope. Then ordering is meaningless — go straight
  at it.

### D25-004 · Record the device posture block that every finding in this chapter is defended by

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 (own device; not an attack) |
| **Applies to** | all |
| **Requires** | device |
| **Maps to** | AOSP Verified Boot (hardware root of trust → bootloader → dm-verity-verified partitions; AVB footers and rollback protection from Android 8.0); AOSP kernel documentation (ACK 5.10+ GKI, KMI, vendor modules/DLKMs) |

- **Test:** A finding produced on a permissive, unlocked, non-current device is closed as unrealistic and
  you will not be told why. Capture the posture block once, at the start, and paste it into the report's
  environment section verbatim.
- **How:**
```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.release ro.build.version.sdk ro.build.version.security_patch
adb shell getprop ro.boot.verifiedbootstate ro.boot.flash.locked
adb shell getprop ro.boot.vbmeta.digest ro.boot.vbmeta.device_state
adb shell getenforce                         # expect Enforcing
adb shell uname -a ; adb shell cat /proc/version
adb shell lsmod 2>/dev/null | head -30
adb shell cat /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict \
             /proc/sys/kernel/perf_event_paranoid
adb shell ls /apex | head -40                # Mainline module inventory
adb shell ls -l /apex | grep '@'             # versioned mounts: name@version
```
- **Proof:** The property values recorded in the report so a reader can tell whether findings were
  produced on a locked, enforcing, current device. `verifiedbootstate=green` with `flash.locked=1` and
  `getenforce=Enforcing` is what makes the rest of the chapter credible.
- **Escalation:** → D21 (attestation), D22 (version matrix), D27 (scoping). A `verifiedbootstate` other
  than `green` on a production image the client treats as trusted is itself a finding on a device brief.
- **Ruled out when:** Nothing — this is unconditional. An engagement without a recorded posture block
  cannot defend a single dynamic result in this chapter.

### D25-005 · `adb shell` is not an app — re-prove every reachability claim from a zero-permission PoC APK

| | |
|---|---|
| **Severity ceiling** | Support (it is the kill gate for this chapter's best finding class) |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | every reachability claim in this chapter |
| **Requires** | device |
| **Maps to** | MASTG-KNOW-0020 caveat: `adb shell` runs as the `shell` user with extra permissions; always re-prove from an ordinary third-party app UID; How owner for receivers: D05-011 (this item keeps the SELinux-domain difference and the probe discipline) |

- **Test:** The `shell` UID holds permissions no third-party app holds — `READ_LOGS` on some builds,
  `DUMP`, `WRITE_SECURE_SETTINGS` on userdebug, `INTERACT_ACROSS_USERS` behaviour, and a *different
  SELinux domain* (`u:r:shell:s0`, not `u:r:untrusted_app:s0:c…`). A `service call` or `content query`
  that succeeds from `adb shell` frequently fails from an app, and a report built on the shell result is
  closed as unreproducible.
- **How:** D05-011 owns this gate for receivers; this item adds the SELinux-domain difference and the probe
  discipline for the whole chapter. Probe prerequisite: the shared probe app ships no `binder` step
  (`getService` + `writeInterfaceToken` + transaction-code sweep with the reply bytes dumped); build
  `pocs/D25/probe-D25` from the D05/D06 probe templates before running D25-005, D25-019 and D25-022, and
  list its steps in the evidence. Run discipline: `am start -S -n com.probe/.MainActivity -a probe.fire.$N`
  with a distinct action per iteration (a filterEquals-equal relaunch returns `START_DELIVERED_TO_TOP` and
  `onCreate` never runs — a silently EMPTY sweep); mirror every PROBE line to `getExternalFilesDir()`
  because some OEM builds drop app-level `Log.i`. Confirm the domain difference, then re-run from a PoC
  APK that declares **no** permissions:
```bash
adb -s "$SERIAL" shell id -Z                       # u:r:shell:s0
adb -s "$SERIAL" shell ps -AZ | grep com.poc.app   # u:r:untrusted_app:s0:c123,… (unversioned for targetSdk 34+; untrusted_app_NN below that)
```
```java
// in the zero-permission PoC app
IBinder b = (IBinder) Class.forName("android.os.ServiceManager")
        .getMethod("getService", String.class).invoke(null, "vendor_svc");
Parcel data = Parcel.obtain(), reply = Parcel.obtain();
data.writeInterfaceToken("com.oem.IVendorService");
b.transact(3, data, reply, 0);
Log.i("poc", "reply=" + reply.readInt() + " " + reply.readString());
```
  Ship the PoC as an APK with the manifest permission list visibly empty, and `dumpsys package com.poc.app
  | sed -n '/requested permissions/,/install permissions/p'` in the evidence.
- **Proof:** The same effect achieved twice — once from `adb shell` (discovery) and once from the
  zero-permission app (the finding) — with `ps -AZ` showing the PoC in an `untrusted_app*` domain.
- **Escalation:** A claim that survives this gate is the one that reaches
  `broken_access_control|privilege_escalation`; one that does not is an environment note.
- **Ruled out when:** The app-UID attempt returns `Permission Denial` or an AVC denial naming
  `untrusted_app`. Quote the denial — the negative is evidence, and it tells you which deputy to look for
  next (D25-030).

### D25-006 · Count your results — the shell-loop ban applied to whole-device package sweeps

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every sweep in this chapter that iterates the package list |
| **Requires** | — |
| **Maps to** | the bug-hunting corpus's Shell-Loop Ban |

- **Test:** Every high-yield sweep here iterates 200–400 packages. Shell array and command-substitution
  loops fail **silently** — a `for p in $(adb shell pm list packages)` can produce zero or partial
  iterations with no error while the output still looks complete. The corpus records an engagement
  losing roughly fifty probes to exactly this, with plausible-looking output.
- **How:** Loops of five or fewer hardcoded items in shell are fine. Anything iterating a list goes to
  Python with per-iteration `try/except` and explicit logging — and you count:
```python
import re, subprocess
SERIAL = '<serial>'
pkgs = [l.split(':',1)[1].strip() for l in subprocess.run(
    ['adb','-s',SERIAL,'shell','pm','list','packages'], capture_output=True, text=True
).stdout.splitlines() if l.startswith('package:')]
print(f'input packages: {len(pkgs)}')
hits, errs = [], 0
# one `dumpsys package packages` parsed offline replaces 300-400 per-package adb round-trips (and 300-400 chances to lose one silently)
raw = subprocess.run(['adb','-s',SERIAL,'shell','dumpsys','package','packages'], capture_output=True, text=True, timeout=120).stdout
raw = raw.split('\nHidden system packages:')[0]       # updated system apps are listed twice; parse the live section only
blocks = re.split(r'\n  Package \[', raw)[1:]
missing = sorted(set(pkgs) - {b.split(']')[0] for b in blocks})
print('packages parsed', len(blocks), 'missing', len(missing))   # missing must be 0; otherwise the dump was cut — do not interpret it
for b in blocks:
    try:
        p = b.split(']')[0]
        if 'android.permission.READ_LOGS: granted=true' in b: hits.append(p)
    except Exception as e:
        errs += 1; print(f'ERR {b[:40]}: {e}')
print(f'probed={len(blocks)-errs} errors={errs} hits={len(hits)}')
```
  Rule: if you expected 300 probes and the log shows fewer than 300 lines, the loop ate something. Fix
  the loop, do not interpret the output. Second silent failure: never nest `sh -c` through adb.
  `adb` joins its argv with spaces and the remote shell re-splits, so quotes inside the inner command
  vanish and the sub-query returns empty with rc=0. Pass the whole remote command as ONE string and quote
  inside it — `subprocess.run(['adb','-s',SERIAL,'shell', "dumpsys package packages | grep -c 'granted=true'"], capture_output=True, text=True)` —
  and quote the remote command whenever it contains `*`, `[`, `$`, `;`, `|`, `&` or a space (under zsh an
  unquoted glob is expanded, or aborts with "no matches found", on the host before adb runs). Add a
  positive control to every sweep (one package you know matches) and require `probed == input` AND the
  control hit before any zero-hit result is written as a negative.
- **Proof:** The `probed=`/`errors=`/`hits=` counter line in the evidence, with `probed` equal to the
  input count.
- **Escalation:** n/a — it is a correctness gate on D25-014, D25-015, D25-017 and D25-021.
- **Ruled out when:** Nothing. A sweep without a result count is not a sweep; it is an assumption.

### D25-007 · Name which sandbox layer stopped you — DAC, type enforcement, or MLS categories

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Requires** | device |
| **Maps to** | the three-layer sandbox model: per-app UID DAC, SELinux type enforcement, per-app MLS categories |

- **Test:** A cross-app compromise must defeat all three layers. When a read or write primitive fails,
  the report that names the layer reads as research; "it didn't work" reads as a failed test. When one
  *succeeds* across apps, the first triager question is "how did you beat the categories?" — and the
  honest answer is almost always "I didn't, a deputy in the victim's own domain did the read".

| Layer | Separates | Defeated by |
|---|---|---|
| DAC — per-app UID, `/data/data/<pkg>` mode 700 | app ↔ app | running *as* the target (confused deputy), or a world-accessible path |
| MAC — domain `untrusted_app` × type `app_data_file` | domain ↔ type | an `allow` rule that should not exist, usually vendor-added |
| MLS categories — per-app category set on process and files | same-type app ↔ app | almost nothing from `untrusted_app`; this is why confused-deputy shapes are the only realistic route |

- **How:**
```bash
adb shell getenforce
adb shell id -Z
adb shell ps -AZ | grep $PKG               # the app's actual domain + categories
adb shell ls -laZ /data/data/$PKG          # u:object_r:app_data_file:s0:c123,c256,c512,c768
```
- **Proof:** For a negative: the denial plus the layer name, e.g. "blocked by MLS categories — the
  attacker process is `:c10,c256,c512,c768`, the target's files are `:c123,c256,c512,c768`". For a
  positive: the deputy that performed the read on your behalf, named.
- **Escalation:** A failure at the MAC layer that a `sesearch` shows *should* have been allowed is the
  finding (D25-027).
- **Ruled out when:** The primitive succeeded and you can name the deputy. Then the sandbox was not
  defeated at all, which is the correct and much stronger framing.

### D25-008 · Determine whether the target ships as a preinstalled, privileged or platform-signed build

| | |
|---|---|
| **Severity ceiling** | Support for the determination; it escalates every other chapter's findings by a band |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) once a component is driven |
| **Attacker** | AM-03 |
| **Applies to** | any app that also ships on an OEM, carrier or enterprise image |
| **Requires** | device |
| **Maps to** | AOSP Application Sandbox (privileged vs non-privileged app domains); AOSP System API "available only to partners and OEMs for inclusion in bundled applications"; MASTG-KNOW-0017 |

- **Test:** The same code defect in a `priv_app` is a far higher-severity finding than in an
  `untrusted_app`, because an exported component in a privileged package is a privilege-escalation
  primitive for every installed app. Find out which the target is before you rate anything. (The tier
  table for the permissions it then holds is D25-009; D03-066 is the manifest-side counterpart.)
- **How:**
```bash
adb shell pm list packages -f | grep -i target
adb -s "$SERIAL" shell 'ls -l /system/priv-app /system/app /system_ext/priv-app /system_ext/app /product/priv-app /product/app /vendor/app /vendor/priv-app /odm/app /odm/priv-app /apex/*/priv-app 2>/dev/null'   # quoted: the glob expands on the device
adb shell dumpsys package com.target.app | grep -E 'codePath|flags=|privateFlags=|pkgFlags='
adb shell ps -A -Z | grep target                       # priv_app vs untrusted_app domain
adb -s "$SERIAL" shell 'cat /system/etc/permissions/privapp-permissions*.xml /system_ext/etc/permissions/privapp-permissions*.xml /product/etc/permissions/privapp-permissions*.xml /vendor/etc/permissions/privapp-permissions*.xml /odm/etc/permissions/privapp-permissions*.xml 2>/dev/null' | grep -B2 -A10 com.target.app
adb shell dumpsys package com.target.app | grep -iE 'sharedUser|signatures|userId='
```
- **Proof:** `codePath=/system/priv-app/…` with `pkgFlags=[ SYSTEM ]`, an SELinux domain of `priv_app` in
  `ps -A -Z`, and a `privapp-permissions` allowlist entry granting signature-level permissions.
- **Escalation:** Re-rate every D04–D08 finding you already hold against this package. An exported
  activity in a Play build is a Medium; the same activity in a `priv_app` holding
  `WRITE_SECURE_SETTINGS` is the OEM VRP class.
- **Ruled out when:** `codePath` is under `/data/app/`, `pkgFlags` carries no `SYSTEM`, and `ps -A -Z`
  shows `untrusted_app_NN`. Judge by the flag, never by the path alone: a Mainline/updated system app keeps
  `pkgFlags=[ SYSTEM UPDATED_SYSTEM_APP ]` with `codePath=/data/app/…`. The app is an ordinary third-party install on this image; record the model
  and fingerprint you checked, because the answer can differ per OEM.

### D25-009 · Tier the privileged permissions a preloaded build holds, and treat each as a multiplier

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 |
| **Applies to** | preloaded, OEM, carrier and enterprise-imaged apps |
| **Requires** | oem-scope, device |
| **Maps to** | MASTG-KNOW-0017 (the Uraniborg-derived risk-scored permission table), MASTG-TEST-0364, MASTG-TEST-0365, MASTG-TEST-0366, MASWE-0018; D03-066 is the manifest-side counterpart (this item owns the tier table) |

- **Test:** Enumerate every `signature` / `signatureOrSystem` / privileged permission the preloaded
  package holds and rate it against MASTG's risk table. An exported, unprotected component in a package
  holding one of the top-tier permissions is a full device compromise from a zero-permission caller.
- **How:**
```bash
adb shell pm list packages -s -f
adb shell dumpsys package com.oem.app | grep -A40 "requested permissions:"
adb shell dumpsys package com.oem.app | grep "granted=true"
aapt2 d permissions com.oem.app.apk
adb shell pm list permissions -d -g
```
  The tiers to match against, all `signature` unless noted:
  - **ASTRONOMICAL:** `INSTALL_PACKAGES`.
  - **CRITICAL:** `COPY_PROTECTED_DATA`, `WRITE_SECURE_SETTINGS`, `READ_FRAME_BUFFER`,
    `MANAGE_CA_CERTIFICATES`, `MANAGE_APP_OPS_MODES`, `GRANT_RUNTIME_PERMISSIONS`, `DUMP`,
    `SYSTEM_CAMERA` (signatureOrSystem), `MANAGE_PROFILE_AND_DEVICE_OWNERS`,
    `MOUNT_UNMOUNT_FILESYSTEMS`, `DYNAMIC_INSTRUMENTATION`, `BIND_ACCESSIBILITY_SERVICE`,
    `INJECT_KEY_EVENTS`, `RECORD_SENSITIVE_CONTENT`, `RECEIVE_SENSITIVE_NOTIFICATIONS`,
    `PROVIDE_DEFAULT_ENABLED_CREDENTIAL_SERVICE`, `PROVIDE_REMOTE_CREDENTIALS`,
    `THREAD_NETWORK_PRIVILEGED`, `ALLOW_CONTROL_SYSTEM_REQUIRED_PACKAGES`.
  - **HIGH:** `READ_LOGS`, `GET_PASSWORD`, `CAPTURE_AUDIO_OUTPUT`, `ACCESS_NOTIFICATIONS`,
    `READ_PRIVILEGED_PHONE_STATE`, `SEND_SMS_NO_CONFIRMATION`, `INTERACT_ACROSS_USERS_FULL`,
    `BLUETOOTH_PRIVILEGED`, `BIND_AUTOFILL_SERVICE`, `LOCATION_HARDWARE`, `INTERNAL_SYSTEM_WINDOW`,
    `MANAGE_ONGOING_CALLS`, `READ_DROPBOX_DATA`, `COPY_ACCOUNTS`, `LISTEN_FOR_KEY_ACTIVITY`,
    `READ_ASSIST_STRUCTURE_SCREEN_CONTENT`, `com.android.voicemail.permission.READ_VOICEMAIL`.
  - **MEDIUM:** `CHANGE_COMPONENT_ENABLED_STATE`, `SYSTEM_ALERT_WINDOW`, `MANAGE_EXTERNAL_STORAGE`,
    `INTERACT_ACROSS_USERS`, `MANAGE_USERS`, `ACCESS_BLOBS_ACROSS_USERS`, `CONNECTIVITY_INTERNAL`.
- **Proof:** The held permission from `granted=true`, plus an exported unprotected component of the same
  package driven from a zero-permission PoC app to produce the capability's effect — a package
  installed, a secure setting written, a runtime permission granted, a key event injected.
- **Escalation:** `INSTALL_PACKAGES`, `WRITE_SECURE_SETTINGS`, `GRANT_RUNTIME_PERMISSIONS` or
  `INJECT_KEY_EVENTS` reached through a confused deputy is full device compromise → D04/D05/D06/D08 for
  the component mechanics.
- **Ruled out when:** Every permission in the `granted=true` set is `normal` or `dangerous`, or every
  component of the package that could reach one is guarded by a `signature`-level permission the caller
  cannot obtain (verify by trying from the PoC app, not by reading the manifest).

### D25-010 · Privileged-permission allowlist enforcement disabled on the image

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 (the consequence); AM-12 for the observation |
| **Applies to** | OEM images, Android 8.0+ for the mechanism, Android 9+ for boot-blocking enforcement |
| **Requires** | oem-scope, device |
| **Maps to** | AOSP privileged-permission allowlist documentation (`ro.control_privapp_permissions`, per-partition allowlists, boot-blocking from Android 9) |

- **Test:** Every `signature|privileged` permission held by an app in `/system/priv-app` (or the
  `system_ext`, `product`, `vendor` and `odm` equivalents, and `/apex/*/priv-app`) must be allowlisted in
  that partition's `/etc/permissions/privapp-permissions-*.xml` **on the same partition**. A device booting with `ro.control_privapp_permissions=log` has the platform's own
  guard rail for privileged permissions switched off on a shipping image.
- **How:**
```bash
adb shell getprop ro.control_privapp_permissions          # expect "enforce"
adb shell cat /etc/permissions/privapp-permissions-platform.xml
adb -s "$SERIAL" shell 'cat /system/etc/permissions/privapp-permissions-*.xml /system_ext/etc/permissions/privapp-permissions-*.xml /product/etc/permissions/privapp-permissions-*.xml /vendor/etc/permissions/privapp-permissions-*.xml /odm/etc/permissions/privapp-permissions-*.xml 2>/dev/null' | grep -A20 'com.oem.target'   # quoted so the device expands the glob
adb logcat -b all | grep 'not in privapp-permissions allowlist'
adb shell dumpsys package com.oem.target | sed -n '/install permissions/,/runtime permissions/p'
```
- **Proof:** `ro.control_privapp_permissions` returning `log` rather than `enforce`, plus logcat lines of
  the documented form `Privileged permission {PERMISSION_NAME} for package {PACKAGE_NAME} - not in
  privapp-permissions allowlist`, **while** `dumpsys package` still shows that permission `granted=true`.
  The pairing is the finding: the platform noticed and granted anyway.
- **Escalation:** Whatever the un-allowlisted permission guards — commonly `READ_PRIVILEGED_PHONE_STATE`,
  secure-settings writes or carrier billing → D25-009 for the impact tier.
- **Ruled out when:** `ro.control_privapp_permissions=enforce` and logcat carries no allowlist-violation
  lines across a full boot. On Android 9+ an enforcing device with violations would not have booted, so
  a clean boot on an enforcing build is a real negative.

### D25-011 · Android 15 `signature-permissions` allowlist for platform-signed non-system apps

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 through the over-privileged app's exported surface (AM-12 to observe) |
| **Applies to** | Android 15+, platform-signed **non-system** apps only (platform-signed system apps are explicitly unaffected); not enforced on debuggable builds |
| **Requires** | oem-scope, device |
| **Maps to** | AOSP signature-permission allowlist documentation (`<signature-permissions package="…">` under `/etc/permissions/`, named `signature-permissions-OEM_NAME.xml` / `signature-permissions-DEVICE_NAME.xml`) |

- **Test:** Android 15 added a second allowlist covering platform signature permissions held by
  platform-signed apps that are not system apps. An app shipping with un-allowlisted platform signature
  permissions either breaks in production or indicates over-broad use of the platform key.
- **How:**
```bash
adb shell ls -la /etc/permissions/ | grep -i signature-permissions
adb -s "$SERIAL" shell 'cat /etc/permissions/signature-permissions-*.xml 2>/dev/null'   # quoted: zsh would otherwise abort on the unmatched local glob
adb shell dumpsys package com.oem.target | grep -E 'signatures|granted=true'
adb shell getprop ro.build.type                    # not enforced on userdebug/eng
```
- **Proof:** A platform-signed non-system package holding a platform signature permission with no
  matching `<signature-permissions package="…">` entry, on a `user` build.
- **Escalation:** An over-granted platform signature permission is a system-UID-adjacent capability →
  D25-009.
- **Ruled out when:** The device is below Android 15, the build is `userdebug`/`eng` (where the mechanism
  is not enforced and the observation means nothing), or the package is a system app — the documentation
  states those are unaffected.

### D25-012 · `sharedUserId` — the target's sandbox is the union of its weakest sibling

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 via the weakest sibling |
| **Applies to** | all; deprecated from API 29 but still shipping in OEM and enterprise apps |
| **Requires** | — |
| **Maps to** | Oversecured "Android security checklist: theft of arbitrary files" §9 Shared User ID Exploitation; "Two weeks of securing Samsung devices: Part 1" (CVE-2021-25393 / SVE-2021-20731) |

- **Test:** Packages declaring the same `android:sharedUserId` and signed with the same key share a UID
  and therefore have full access to each other's private files and components. The Samsung SecSettings
  chain turned on exactly this: `com.sec.imsservice` sharing `android.uid.system` meant two apps could
  "share absolutely all resources and have full access to each other's components".
- **How:**
```bash
grep -n 'sharedUserId' $DEC/apktool/AndroidManifest.xml
adb shell dumpsys package com.target.app | grep -iE 'userId=|sharedUser'
UID=$(adb shell dumpsys package com.target.app | grep -oE 'userId=[0-9]+' | head -1 | cut -d= -f2)
adb shell pm list packages -U | grep -w "uid:$UID"
# then enumerate the whole group's exported surface — in Python, with the D25-006 counter (no shell list loops)
python3 - <<'PY'
import subprocess
S='<serial>'; UID='<uid>'
pk=[l.split(':',1)[1].split()[0] for l in subprocess.run(['adb','-s',S,'shell','pm','list','packages','-U'],capture_output=True,text=True).stdout.splitlines() if l.endswith('uid:'+UID)]
print('input',len(pk)); hits=0
for p in pk:
    d=subprocess.run(['adb','-s',S,'shell','dumpsys','package',p],capture_output=True,text=True).stdout
    n=d.count('exported=true'); hits+=n; print('==',p,'exported',n)
print('probed',len(pk),'hits',hits)
PY
```
- **Proof:** A second installed package resolving to the same `userId`, plus a file read across the two
  data directories or a component call that succeeds without permission. When the shared UID is
  `android.uid.system`, the group's weakest exported component is a system-UID entry point.
- **Escalation:** → D07/D11 across the whole UID group; → D25-009 when the group includes a privileged
  package.
- **Ruled out when:** `grep sharedUserId` returns nothing in the merged manifest and `pm list packages -U`
  shows the target alone on its UID. Note that the *absence* of the attribute in the app's own manifest
  is not enough — check the merged manifest and the live UID.

### D25-013 · The app's SELinux domain, and the `untrusted_app_NN` versioned-domain widening

| | |
|---|---|
| **Severity ceiling** | Support (rating input that multiplies other findings) |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Requires** | device |
| **Maps to** | the versioned app-domain model (`untrusted_app_NN` selected by `minTargetSdkVersion` in `seapp_contexts`); `execute` on `app_data_file` denied outright for `untrusted_app_29`+ |

- **Test:** A lower `targetSdk` places the app in a versioned SELinux domain with a materially wider
  policy. This is an API-gate table in disguise, and it decides whether a native write primitive in the
  app's own sandbox can ever become execution.
- **How:**
```bash
adb shell ps -AZ | grep $PKG            # u:r:untrusted_app_30:s0:c… etc.
adb shell dumpsys package $PKG | grep -E 'targetSdk|minSdk'
adb -s "$SERIAL" shell 'grep -n minTargetSdkVersion /system/etc/selinux/plat_seapp_contexts'   # the authoritative targetSdk→domain table for THIS build (currently _25/_27/_29/_30/_32, unversioned untrusted_app for 34+)
```
  Then cross-reference the domain name against the policy (D25-026).
- **Proof:** The domain name from `ps -AZ` next to the `targetSdk` value, and the `sesearch` result for
  that specific domain — not for the generic `untrusted_app` attribute.
- **Escalation:** → D25-026. A `untrusted_app_27` domain on a legacy build is a materially different
  ceiling from the unversioned `untrusted_app` domain that apps targeting 34+ run in (the versioned
  domains stop at `untrusted_app_32`), and rating a write primitive without checking which one you are in is
  how "arbitrary write → RCE" claims get closed.
- **Ruled out when:** `ps -AZ` shows the current unversioned or highest-versioned domain and `sesearch`
  shows no writable-and-executable type for it. Write the sentence out; it is the defensible negative.

### D25-014 · Device-wide debuggable sweep — a preinstalled debuggable package

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16); `broken_access_control.privilege_escalation` (**VARIES**) when the debuggable package is privileged |
| **Attacker** | AM-11 physical unlocked, or AM-06/AM-04 where `adb` is reachable |
| **Applies to** | all API levels; highest yield on OEM and carrier handsets |
| **Requires** | device |
| **Maps to** | drozer `app.package.debuggable`, `exploit.jdwp.check`; ATT&CK M1012 (do not enable USB debugging unless needed) |

- **Test:** Debuggable *release* builds still ship — staging APKs published by mistake, OEM preinstalls,
  SDK-injected builds. A successful `run-as` **is** the proof: any local actor reads that package's
  private storage and can run code in its UID over JDWP. On a preinstalled privileged package that is a
  direct path to system-adjacent capability.
- **How:** Use Python, not a shell loop (D25-006):
```python
import re, subprocess
S='<serial>'
raw=subprocess.run(['adb','-s',S,'shell','dumpsys','package','packages'],capture_output=True,text=True,timeout=120).stdout
raw=raw.split('\nHidden system packages:')[0]       # live section only (updated system apps appear twice)
blocks=re.split(r'\n  Package \[', raw)[1:]
cands=[b.split(']')[0] for b in blocks if re.search(r'\n\s+flags=\[[^\]]*DEBUGGABLE', b)]   # pre-filter on the flag; run-as only the candidates
print('parsed',len(blocks),'candidates',len(cands)); hits=[]
for p in cands:
    r=subprocess.run(['adb','-s',S,'shell','run-as',p,'id'],capture_output=True,text=True)
    if 'uid=' in r.stdout: hits.append(p); print('DEBUGGABLE',p,r.stdout.strip())
print('probed',len(cands),'hits',len(hits))        # probed must equal candidates
```
```bash
adb shell dumpsys package <pkg> | grep -i 'flags=.*DEBUGGABLE'
adb shell run-as <pkg> ls -la /data/data/<pkg>/shared_prefs
adb jdwp                                      # confirm the JDWP port is live
```
- **Proof:** `run-as <pkg> id` printing the app's uid instead of `package not debuggable`, followed by a
  private file read from that package's `shared_prefs` or database, with the package's `codePath` under
  `/system` or `/product` in the same evidence block.
- **Escalation:** `run-as` → private storage read (D11); JDWP attach → code execution in that UID (D26);
  if the package is privileged, → D25-009.
- **Ruled out when:** The sweep completes with `probed == input` and zero hits, and spot-checking two
  named preinstalled packages confirms `package not debuggable`. A partial sweep is not a negative.

### D25-015 · Name a `READ_LOGS` holder on the target's actual device population

| | |
|---|---|
| **Severity ceiling** | Medium (it is the argument that lifts a D20 logcat leak off the floor, not a finding on its own) |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) for the image observation; the rated finding stays in D20 |
| **Attacker** | AM-03 (the preinstalled reader is already on the device) |
| **Applies to** | all; strength depends on the target's device demographics |
| **Requires** | device |
| **Maps to** | MASTG-TEST-0203 (verbatim: "the vast ecosystem of Android devices includes pre-loaded apps with the `READ_LOGS` privilege, increasing the risk of sensitive data exposure"), MASTG-KNOW-0017 (`READ_LOGS` rated HIGH, `signature`), MASTG-KNOW-0049, MASWE-0005 (CWE-532); How owner for the reader enumeration: D20-008 (this item keeps the device-demographic argument) |

- **Test:** D20-008 owns the reader enumeration for the leak itself; this item adds the device-demographic
  argument. The standard triage response to a logcat leak is "logcat needs root or a privileged
  permission, so it is Informational". The counter is a named preinstalled package on a device from the
  client's real user base that already holds `READ_LOGS`.
- **How:** On the OEM handsets the client's users actually run, not on a Pixel emulator:
```python
import re, subprocess
S='<serial>'
pk={l.split(':',1)[1].strip() for l in subprocess.run(['adb','-s',S,'shell','pm','list','packages'],capture_output=True,text=True).stdout.splitlines() if l.startswith('package:')}
raw=subprocess.run(['adb','-s',S,'shell','dumpsys','package','packages'],capture_output=True,text=True,timeout=120).stdout   # one call, not one per package
raw=raw.split('\nHidden system packages:')[0]       # live section only (updated system apps appear twice)
blocks=re.split(r'\n  Package \[', raw)[1:]
print('packages parsed',len(blocks),'input',len(pk),'missing',len(pk-{b.split(']')[0] for b in blocks}))   # missing must be 0
holders=[b.split(']')[0] for b in blocks if 'android.permission.READ_LOGS: granted=true' in b]
print('holders',holders)
```
```bash
adb shell getprop ro.build.fingerprint           # record which image this is
adb logcat --pid=$(adb shell pidof -s com.target.app) | grep -iE 'token|bearer|otp|passw'
```
- **Proof:** The sensitive value in the app's own logcat output **plus** the named preinstalled package
  holding `READ_LOGS` with `granted=true` on a stated build fingerprint.
- **Escalation:** → D20 for the leak itself. Named reader + logged token is a complete chain and is the
  difference between P5 and a rated finding.
- **Ruled out when:** The sweep finds no `granted=true` `READ_LOGS` holder on any device in the client's
  demographic. Then the logcat observation stays at its D20 floor and you say why — this is a genuine
  negative and worth writing down, because it also tells the client their fleet is unusually clean.

### D25-016 · Diff the OEM build against AOSP to produce the non-AOSP inventory

| | |
|---|---|
| **Severity ceiling** | Support (it is the inventory that every OEM finding below is drawn from) |
| **VRT** | n/a |
| **Attacker** | AM-12 for the diff |
| **Applies to** | OEM/VRP engagements |
| **Requires** | oem-scope, device |
| **Maps to** | the senior-researcher corpus's "third-party modifications" method; Oversecured "Discovering vendor-specific vulnerabilities in Android" |

- **Test:** OEM and carrier code is the least-audited code on the device and it is where the
  exported-component and set-uid findings live. Do not audit AOSP packages on an OEM handset — diff them
  out first.
- **How:** Take a Pixel/AOSP build of the same release as the reference and diff four inventories:
```bash
# on each device
adb shell ps -A            > ps.$DEV
adb shell ls /system/bin /system/xbin /vendor/bin /vendor/bin/hw 2>/dev/null | sort > bin.$DEV
adb shell ls /system/lib64 /vendor/lib64 2>/dev/null | sort      > lib.$DEV
adb -s "$SERIAL" shell pm list packages -f -s | sed 's/^package://' | tr -d '\r' | sort > apps.$DEV   # <apk path>=<pkg>; covers system_ext, odm and /apex/*/priv-app too
adb shell 'cat /init*.rc /vendor/etc/init/*.rc 2>/dev/null' | grep -E '^service|^on ' > initrc.$DEV
# then
comm -23 <(sed 's/.*=//' apps.oem | sort) <(sed 's/.*=//' apps.aosp | sort) > oem-only-pkgs.txt ; wc -l oem-only-pkgs.txt   # PACKAGE NAMES — what dumpsys and pm path accept (a directory name is neither)
comm -23 bin.oem  bin.aosp  > oem-only-bins.txt ; wc -l oem-only-bins.txt
adb shell service list | sort > svc.$DEV ; comm -23 svc.oem svc.aosp > oem-only-services.txt
```
- **Proof:** The four `comm -23` outputs, with counts. Each line is an unaudited surface; triage them by
  D25-003's four properties rather than reading them in alphabetical order.
- **Escalation:** Feeds D25-014 (debuggable sweep over the OEM-only set), D25-017 (exported surface),
  D25-022 (services), and the sepolicy diff in D25-027.
- **Ruled out when:** The device is a Pixel/AOSP build and the diff is empty. Record the reference build
  fingerprint so a reader can reproduce the comparison.

### D25-017 · OEM system app exporting a component that performs a privileged action

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | OEM/VRP engagements and managed-device assessments |
| **Requires** | oem-scope, device |
| **Maps to** | CVE-2026-20983 (Samsung Dialer, improper export → arbitrary activity launch at Dialer privilege); CVE-2026-21059 (Samsung Contacts, arbitrary file delete at Contacts' system privilege, fixed SMR Aug-2026 Release 1); CVE-2026-20990 (Secure Folder, fixed SMR Mar-2026 Release 1); CVE-2015-7889, CVE-2015-7893; Oversecured "176 vulnerabilities in Samsung preinstalled apps"; CWE-926 |

- **Test:** The shape is identical to D04–D08 — the impact is device-wide because the caller inherits the
  system package's UID. Run the full exported-component battery against the OEM-only app inventory from
  D25-016, not against every package on the image.
- **How:**
```bash
python3 - <<'PY'      # D25-006 form; oem-only-pkgs.txt holds package names (D25-016)
import subprocess
S='<serial>'; pk=[l.strip() for l in open('oem-only-pkgs.txt') if l.strip()]; print('input',len(pk)); hits=[]; errs=0
for p in pk:
    try:
        d=subprocess.run(['adb','-s',S,'shell','dumpsys','package',p],capture_output=True,text=True,timeout=30).stdout
        ex=[l.strip() for l in d.split('Permissions:')[0].splitlines() if 'exported=true' in l]
        if ex: hits.append(p); print('EXPORTED',p,len(ex))
    except Exception as e:
        errs+=1; print('ERR',p,e)
print('probed',len(pk)-errs,'errors',errs,'hits',len(hits))
PY
adb -s "$SERIAL" shell pm path <oem.pkg> | sed 's/^package://' | tr -d '\r' | while IFS= read -r a; do adb -s "$SERIAL" pull "$a" "oem/<oem.pkg>-$(basename "$a")"; done   # one file per base/split APK
drozer> run app.package.attacksurface <oem.pkg>
```
  Then drive each unprotected component from a zero-permission PoC app (D25-005) and apply the
  D04 (activity), D05 (receiver), D06 (service/AIDL), D07 (provider) and D08 (redirection/URI-grant)
  tests in turn. The historically productive shapes: an exported service copying an attacker-supplied
  URI into a world-readable location; a receiver downloading from an attacker URL to an attacker-chosen
  path; an exported activity leaking URI grants; a receiver whose extra names a `SAVE_PATH`.
- **Proof:** The privileged effect performed for you — a file written to a path you chose and readable
  from your app, a package installed, a setting changed, another app's data returned — with
  `dumpsys package com.poc.app` in the same evidence block showing the PoC holds no permissions.
- **Escalation:** → D25-009 for the capability tier. The published end-to-end shape is the S25 chain:
  crash → restore → seed-predict → path-traverse → signature-downgrade → arbitrary APK install with no
  user interaction and no permissions.
- **Ruled out when:** Every exported component in the OEM-only set is guarded by a `signature` or
  `signature|privileged` permission that your PoC app provably cannot obtain (D03-013 squatting checked
  and refuted), or the invocation returns `Permission Denial` from an app UID. Quote the denial.

### D25-018 · Vendor method added beside an AOSP one with the permission check dropped

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | OEM-scope engagements |
| **Requires** | oem-scope, device |
| **Maps to** | Oversecured "Discovering vendor-specific vulnerabilities in Android" — the `semIsBackupEnabled()`-beside-`isBackupEnabled()` pattern ("returns the value with no checks at all") and the `IPowerManager.reboot()` `enforceCallingOrSelfPermission()` contrast |

- **Test:** The highest-yield OEM bug class. An OEM adds a method next to an AOSP one and omits the
  enforcement that the AOSP sibling has. The diff against AOSP for the same interface *is* the method.
- **How:**
```bash
adb -s "$SERIAL" pull /system/framework/framework.jar ./     # interfaces only: Stub TRANSACTION_ codes and the vendor method NAMES
adb -s "$SERIAL" pull /system/framework/services.jar ./      # system_server implementations: where enforceCallingOrSelfPermission() checks ARE
unzip -l services.jar | grep -c 'classes.*dex' || {   # dex-preopted user build: recover the dex from the vdex (oatdump --oat-file=services.odex --export-dex-to=. is the fallback)
  adb -s "$SERIAL" pull /system/framework/oat/arm64/services.vdex ./ && vdexExtractor -i services.vdex -o . ; }
adb -s "$SERIAL" shell service list | head -80
adb -s "$SERIAL" shell dumpsys -l | head -80
# decompile the service impls and compare the vendor *ManagerService against AOSP's for the same interface name
jadx -d svc_oem services.jar ; jadx -d svc_aosp aosp-services.jar   # vdex route: point jadx at the extracted *classes*.dex files instead of the dex-less jar
grep -rnE 'public .*\b(sem|oem|mi|op|vivo|hw)[A-Z][A-Za-z]+\(' svc_oem/ | head -50      # vendor-added public methods on service impls
# then, per method, read the body for an enforce/check call — framework.jar holds only Stub/Proxy glue and never contains them
grep -rLn 'enforceCallingPermission\|enforceCallingOrSelfPermission\|checkPermission\|checkCallingOrSelfPermission' \
     $(grep -rlE 'extends I[A-Za-z]+\.Stub' svc_oem/ | head -200)
```
- **Proof:** The vendor method invoked from an unprivileged app producing a privileged effect — a reboot,
  a settings write, a data read — with the AOSP sibling throwing `SecurityException` for the same caller.
  Put both transcripts side by side; the contrast is the report.
- **Escalation:** System-UID capability from a zero-permission app → D25-022 for the transaction-code
  mechanics.
- **Ruled out when:** Every vendor-added method on the interface calls an enforcement helper before
  touching state, verified by reading the decompiled body rather than by grep alone (a helper may be
  renamed). A `SecurityException` from the PoC app for every vendor method you could reach is the
  negative.

### D25-019 · Unprotected vendor broadcast action triggering privileged behaviour

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `application_level_denial_of_service_dos.critical_impact_and_or_easy_difficulty` (**P2**) for a locally triggerable reboot |
| **Attacker** | AM-03 |
| **Applies to** | OEM-scope engagements |
| **Requires** | oem-scope, device |
| **Maps to** | Oversecured — the Samsung `StorageManagerService.java` case where the broadcast action `com.samsung.intent.action.RESTART_OF_SDCARDBADREMOVED_HASAPK` triggers a device reboot, "effectively sidestepping permission restrictions" |

- **Test:** OEM system components register receivers for vendor-specific actions with no
  `android:permission`, so any installed app can trigger the behaviour behind them.
- **How:**
```bash
adb shell dumpsys package r | grep -iE '^\s+[a-z0-9.]*(samsung|oneplus|xiaomi|oppo|vivo|honor|motorola|sec)' | head -60
adb shell dumpsys activity broadcasts | grep -iE 'vendor|sem\.|oem' | head -40
# for each candidate action, read the receiver's guard
adb shell dumpsys package <oem.pkg> | sed -n '/Receiver Resolver Table/,/Service Resolver/p'
# implicit broadcasts never reach manifest receivers of apps targeting API 26+: send EXPLICITLY (works regardless of targetSdk)
adb -s "$SERIAL" shell am broadcast -a com.oem.intent.action.SOME_PRIVILEGED_ACTION -n <oem.pkg>/<ReceiverClass>
```
  Then re-fire from the zero-permission PoC app with
  `sendBroadcast(new Intent("com.oem…").setPackage("<oem.pkg>"))` — package-scoped intents are delivered,
  a bare action is not. The shared probe's `broadcast` step takes the explicit component; build the
  binder/broadcast probe per D25-005 before this item.
- **Proof:** The privileged effect occurring — a reboot, a mode change, a log dump written to a readable
  path — from the PoC app, with the vendor receiver's manifest entry showing no `android:permission`.
  For a reboot, record the uptime before and after.
- **Escalation:** DoS at minimum; a state change that opens a further surface at best. Check whether the
  reboot is recoverable — a crash fixed by reboot is not payable, one requiring a factory reset is.
- **Ruled out when:** Every vendor receiver in the resolver table carries an `android:permission` at
  `signature` or `signature|privileged`, or the **explicit** broadcast from an app UID produces
  `Permission Denial: not exported from uid`. An implicit send that produced nothing is not a negative —
  only the explicit send's denial or the receiver's `android:permission` is.

### D25-020 · OEM ROM add-on ContentProvider that bypasses the permission it should require

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (**VARIES**) for what comes back |
| **Attacker** | AM-03 |
| **Applies to** | OEM builds — enumerate per ROM, not per app |
| **Requires** | oem-scope, device |
| **Maps to** | CVE-2025-10184 (OnePlus OxygenOS Telephony provider permission bypass, Rapid7); HackTricks android-checklist "Check OEM ROM add-ons … for extra exported ContentProviders that bypass permissions" |

- **Test:** OxygenOS, ColorOS, MIUI, One UI and the rest add providers that are not in AOSP and that
  frequently miss a `writePermission` or a read gate. The test is to run the query **without** the
  permission the AOSP equivalent would require.
- **How:**
```bash
adb shell dumpsys activity providers | grep -iE 'telephony|push|service-number|shop|sem|mi\.'
adb shell content query --uri content://com.android.providers.telephony/ServiceNumberProvider
adb shell cmd content query --uri content://service-number/service_number
# then from the zero-permission PoC app, with no READ_SMS in the manifest:
#   getContentResolver().query(Uri.parse("content://service-number/service_number"), …)
adb shell content update --uri content://<authority>/<path> --bind x:s:y   # write gate
```
- **Proof:** Rows returned to a caller that holds none of the relevant permissions, or a successful
  `update()` write from an unprivileged context. Show the PoC app's empty permission list alongside.
- **Escalation:** Then apply the blind-`update()` SQLi oracle from D07 to read co-located protected
  tables — a provider with no read gate and a co-resident SMS table is the OnePlus shape.
- **Ruled out when:** The unprivileged query returns `java.lang.SecurityException: Permission Denial:
  reading … requires android.permission.READ_SMS`. Record the exact exception; it is the negative and it
  differs per ROM version.

### D25-021 · Factory, test, diagnostic and engineering packages on a production image

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) escalating to `broken_access_control.privilege_escalation` (**VARIES**) |
| **Attacker** | AM-03 |
| **Applies to** | OEM builds |
| **Requires** | oem-scope, device |
| **Maps to** | Oversecured Samsung `com.sec.factory.camera` — a debug app on production with system privileges and an unprotected receiver accepting test commands, producing silent video recording with no camera indicator |

- **Test:** Debug and factory packages that were meant for the production line ship to retail. They hold
  system privileges, they were written on the assumption that only the factory harness talks to them,
  and their receivers take commands.
- **How:**
```bash
adb shell pm list packages | grep -iE 'factory|test|debug|diag|engineer|hidden|secret|qa|lab'
adb shell dumpsys package com.sec.factory.camera | grep -A10 -E 'Receiver|exported'
adb shell dumpsys package <candidate> | grep -E 'codePath|pkgFlags|granted=true'
adb shell am broadcast -a <the receiver action> --es cmd <value>
adb shell dumpsys media.camera | grep -i 'active\|clients'    # confirm the effect
```
- **Proof:** A production device carrying a debug package whose receiver executes a test command from an
  arbitrary caller, with the effect demonstrated — a recording started, a diagnostic file written to a
  readable path, a flag set. Show the privacy indicator's absence if the effect is capture.
- **Escalation:** A privacy violation with no user indicator is in the Android & Google Devices in-scope
  list ("hiding privacy-sensitive system indicators"), which is a much better framing than "debug app
  present".
- **Ruled out when:** The candidate packages are disabled (`dumpsys package` shows `enabled=2/3` or
  `COMPONENT_ENABLED_STATE_DISABLED`), or every receiver is guarded by a signature permission. Note that
  "disabled" is defeatable if any package holds `CHANGE_COMPONENT_ENABLED_STATE` — check before calling
  it a negative.

### D25-022 · OEM-added framework service reachable from `untrusted_app`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | OEM builds; out of scope for most app engagements — confirm scope first |
| **Requires** | oem-scope, device |
| **Maps to** | AOSP Binder IPC (`/dev/binder` context for framework and app AIDL); AOSP `service_contexts` / `hal_attribute_service` access model; MASTG-KNOW-0020, MASTG-TOOL-0004; AOSP AIDL fuzzing as the systematic follow-up |

- **Test:** OEMs register services that AOSP does not have. Test each for a missing caller check by
  driving raw transaction codes, then confirm reachability from an app UID rather than from `shell`.
- **How:**
```bash
adb shell service list | grep -viE '^[0-9]+\s+(activity|package|window|power|notification|media|audio|wifi|connectivity|telephony|input|display|clipboard|content|batterystats|appops|permission|user|account|alarm|jobscheduler|device_policy|bluetooth|location|sensor|usb|vibrator|statusbar|search|print|dropbox|netstats|procstats|settings|shortcut|slice|storage|telecom|textservices|trust|uimode|wallpaper|webviewupdate)'
# raw probe from shell first (discovery)
for c in $(seq 1 40); do echo "== code $c"; adb -s "$SERIAL" shell service call <svcname> $c i32 0; echo "rc=$?"; done   # hardcoded range, so shell is fine; print rc so a silent adb failure is visible
adb shell dmesg | grep -i 'avc: denied.*service_manager'
# which services may an app domain even look up?
adb shell su 0 cat /sys/fs/selinux/policy > policy.bin
sesearch -A -s untrusted_app -c service_manager policy.bin
```
  Then re-issue the winning transaction from the zero-permission PoC app via `ServiceManager.getService`
  + `IBinder.transact` — the shared probe has no `binder` step; build it per D25-005 first.
- **Proof:** A non-AOSP service returning a non-error `Parcel` for a transaction issued from a plain app
  UID, where the returned data is something the app should not have — an IMEI, a file path, a config
  blob. Decode and quote the reply bytes, and pair with the `sesearch -c service_manager` line proving
  the lookup is policy-allowed for `untrusted_app`.
- **Escalation:** → D26 for systematic AIDL fuzzing of the same interface; a client-app finding only if
  the app under test depends on that service.
- **Ruled out when:** `sesearch -A -s untrusted_app -c service_manager` does not list the service (an app
  cannot even obtain the binder), or every transaction from the app UID returns
  `SecurityException`/`Permission Denial`. A `shell`-only success is explicitly not a finding here.

### D25-023 · Preinstalled app holding a squattable or over-broad custom permission

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | OEM-scope engagements |
| **Requires** | oem-scope, device |
| **Maps to** | `protectionLevel` semantics; AOSP permissions documentation on OEMs being able to define custom permissions as `normal` or `dangerous`; AOSP privileged-permission allowlist |

- **Test:** OEM images define custom permissions at `normal` that gate genuinely privileged vendor
  interfaces. A `normal` permission is granted to any app that asks, so the gate is decorative.
- **How:**
```bash
adb shell pm list permissions -f | awk '/^permission:/{p=$0} /protectionLevel:/{print p" -> "$0}' \
  | grep -vE 'permission:android\.' | grep -E 'normal|dangerous'
adb -s "$SERIAL" shell pm list packages -s | sed 's/package://' | tr -d '\r' > syspkgs.txt
python3 - <<'PY'      # one dumpsys, parsed offline (D25-006)
import re, subprocess
S='<serial>'; pk=[l.strip() for l in open('syspkgs.txt') if l.strip()]; print('input',len(pk))
raw=subprocess.run(['adb','-s',S,'shell','dumpsys','package','packages'],capture_output=True,text=True,timeout=120).stdout
raw=raw.split('\nHidden system packages:')[0]       # live section only (updated system apps appear twice)
blocks={b.split(']')[0]: b for b in re.split(r'\n  Package \[', raw)[1:]}
print('parsed',len(blocks)); hits=0
for p in pk:
    d=blocks.get(p,'')
    if 'protectionLevel=normal' in d and 'declared permissions' in d: hits+=1; print('CANDIDATE',p)
print('probed',sum(1 for p in pk if p in blocks),'hits',hits)
PY
```
  Then declare the permission in the PoC app's manifest, install, confirm it is granted, and call the
  interface it guards.
- **Proof:** `dumpsys package com.poc.app | grep <permission>` showing it granted at install, followed by
  a successful call into the vendor interface.
- **Escalation:** → D03 for the squatting and install-order mechanics on the same image; → D25-009 for
  the capability the interface exposes.
- **Ruled out when:** Every vendor permission guarding a privileged interface resolves to
  `signature`, `signature|privileged` or `internal`, read from `pm list permissions -f` rather than from
  the manifest source.

### D25-024 · The target trusts an OEM sibling by package name rather than by signature

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 on a non-vendor device; AM-08 where the sibling is the SDK's |
| **Applies to** | OEM-bundled or OEM-integrated apps |
| **Requires** | — |
| **Maps to** | Oversecured "Discovering vendor-specific vulnerabilities in Android", "20 Security Issues Found in Xiaomi Devices", "176 vulnerabilities in Samsung preinstalled apps"; `developer.android.com/privacy-and-security/risks/create-package-context` |

- **Test:** Apps integrated with an OEM trust a vendor package by name — `com.samsung.*`, `com.miui.*`,
  `com.oneplus.*`, `com.sec.android.*` — or bind to a vendor service. On a vendor device the vendor
  component is the surface; on a **non-vendor** device the name is unclaimed and therefore claimable.
- **How:**
```bash
grep -rnE 'com\.samsung|com\.miui|com\.xiaomi|com\.huawei|com\.oppo|com\.vivo|com\.oneplus|com\.sec\.android' \
     $DEC/jadx/sources/ $DEC/apktool/AndroidManifest.xml
grep -rnE 'createPackageContext|getPackagesForUid|checkSignatures|getPackageInfo\(.*GET_SIGNING' $DEC/jadx/sources/ -A6
adb shell pm list packages -s | head -50
```
  For each hit, determine whether the app verifies the signing certificate or merely the string. Then
  install a package with that exact `applicationId` on a device where the real vendor package is absent.
- **Proof:** A name-only trust decision in the decompiled code, plus your sideloaded package with the
  claimed name being accepted — receiving the bind, supplying the configuration, or being handed a token.
- **Escalation:** High when the trusted sibling supplies configuration, tokens or code → D17 if it
  supplies code, D18 if it supplies endpoints.
- **Ruled out when:** Every cross-package trust site calls `checkSignatures()` or compares a pinned
  signing-certificate digest, or the app uses `android:knownCerts`/`knownSigner`. Read the comparison
  body — a `getSigningCertificates()` call whose result is discarded is not a check.

### D25-025 · Preinstalled privileged implant, whitelabel firmware, and expired management infrastructure

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16); `insecure_os_firmware.hardcoded_password.privileged_user` (**P1**, CWE-259) where credentials are embedded |
| **Attacker** | AM-01 remote (the implant's operator) |
| **Applies to** | cheap and whitelabel devices, TV boxes, carrier and reseller firmware |
| **Requires** | oem-scope, device |
| **Maps to** | HackTricks README "Pre-installed privileged Android TV-box implants (OEM / reseller firmware abuse)", citing Bitsight's Fuyao Enterprise research; ATT&CK T1474.002 Compromise Hardware Supply Chain, T1474.003, mitigation M1001 |

- **Test:** Some malicious packages are baked into OEM or reseller firmware as *privileged* packages
  rather than sideloaded. Treat them as a firmware supply-chain foothold, and prioritise five checks.
- **How:**
```bash
adb shell pm list packages -f
adb shell dumpsys package <package> | grep -E 'codePath|pkgFlags|sharedUser|granted=true'
adb shell find /data/local/system -maxdepth 2 -type f 2>/dev/null
adb shell getprop | grep -E 'ro.product|ro.board|ro.hardware|ro.build'
adb shell dumpsys accessibility
unzip -o implant.apk -d impl && ls impl/assets
strings impl/lib/*/*.so | grep -EiA1 'http|socks|backconnect|\.onion'
```
  The five prioritised checks:
  1. **Package origin/privilege mismatch** — compare `codePath`, shared UID, requested permissions and
     install path against stock firmware; APKs outside `/data/app` that are not removable, or that
     reappear across unrelated brands and models.
  2. **Trusted follow-on install paths** — `/data/local/system` holding dynamically dropped APKs/JARs.
  3. **Cross-layer identity spoofing** — reconcile `getprop`, screen size, chipset remnants
     (`rockchip`, `amlogic`, `allwinner`), launcher/settings packages and browser-visible CPU/GPU data.
  4. **Selector-independent UI automation** — inspect `assets/` for ML models, OCR libraries, browser
     stealth scripts and generated JS task modules.
  5. **Proxy-only monetisation** — bootstrap endpoints fetching backconnect servers, long-lived tunnels
     multiplexing SOCKS5 over custom framing.
- **Proof:** A privileged package whose install path and permission set cannot be explained by stock
  firmware, plus its observed C2 or backconnect behaviour in a capture.
- **Escalation:** **Expired management infrastructure.** Extract every hardcoded domain and IP from
  privileged apps and management agents and verify DNS and TLS ownership still matches the vendor. An
  expired root-capable management domain is a mass-device-takeover opportunity, not a dangling record —
  and that is the finding, not the implant's existence.
- **Ruled out when:** Every preinstalled package's `codePath`, signer and permission set matches the
  vendor's published stock image, and every hardcoded management host resolves to vendor-controlled
  infrastructure with a valid certificate chain the vendor owns.

### D25-026 · SELinux downgrade discipline — an arbitrary write from `untrusted_app` is not code execution

| | |
|---|---|
| **Severity ceiling** | Support (it is the gate that stops an over-rated report, and the discovery path to a real one) |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | every write-primitive finding in the engagement |
| **Requires** | device, root |
| **Maps to** | the senior-researcher corpus's SELinux discipline; W^X enforced by MAC, not only by `mprotect`; `execute` on `app_data_file` denied for `untrusted_app_29`+ |

- **Test:** Before rating any native or filesystem write primitive, check what the policy on **that
  build** actually allows. Claim RCE without this and the report comes back N/A.
- **How:**
```bash
adb shell su 0 cat /sys/fs/selinux/policy > policy.bin
sesearch -A -s untrusted_app -t system_file -c file policy.bin
sesearch -A -s untrusted_app -c file -p write policy.bin
sesearch -A -s untrusted_app -c file -p execute policy.bin
sesearch -A -s <domain from ps -AZ> -c file -p execute,execmem,execmod,execute_no_trans policy.bin   # setools 4: -p is comma-separated; a space-joined token silently matches nothing
sesearch -A -s untrusted_app -c file -p read policy.bin | head -3     # positive control: must be non-empty before any empty result above is trusted
sesearch -A -t app_data_file policy.bin
```
  Facts to verify rather than assume on the target build: `untrusted_app` cannot write `system_file`,
  `vendor_file` or `apk_data_file`; `execmem`/`execmod`/`execute_no_trans` are denied for most types;
  `execute` on `app_data_file` is denied outright for `untrusted_app_29`+.
- **Proof:** The honest sentence, with the command output behind it: *"arbitrary write within the app's
  own sandbox; code execution would additionally require a type the app may both write and execute —
  `sesearch` shows none on this build"*, quoting the empty result.
- **Escalation:** If `sesearch` **does** show a type the app may both write and execute, that is the
  finding, and it is a High on an OEM brief because it is a vendor-added rule.
- **Ruled out when:** The `sesearch` write∩execute intersection is empty for the app's actual versioned
  domain (D25-013). Paste the two commands and their output; that is what makes the negative defensible.

### D25-027 · Vendor sepolicy over-permission — diff the OEM's granted set against AOSP

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 |
| **Applies to** | OEM/VRP engagements, Android 8.0+ (Treble) |
| **Requires** | oem-scope, root |
| **Maps to** | AOSP SELinux device-policy documentation (the "5–10% device-specific policy" model; Treble assembling policy at boot from `system` and `vendor`); AOSP security-model paper §4.8 |

- **Test:** OEMs add `allow` rules to make preinstalled apps work, and the rules land too broad. The diff
  is the method: every line the OEM added for `untrusted_app` is a capability an ordinary third-party app
  has on this device and nowhere else.
- **How:** Context files are readable from `shell` on a stock device; for the binary policy without root,
  extract it from the factory image.
```bash
adb shell ls -la /system/etc/selinux/     # plat_sepolicy.cil, plat_file_contexts, plat_seapp_contexts,
                                          # plat_mac_permissions.xml, precompiled_sepolicy …
adb shell ls -la /vendor/etc/selinux/     # vendor_sepolicy.cil + vendor_* contexts  <- audit this
sesearch -A -s untrusted_app oem_policy.bin  | sort > oem.txt
sesearch -A -s untrusted_app aosp_policy.bin | sort > aosp.txt
comm -23 oem.txt aosp.txt                 # capabilities this OEM handed every unprivileged app
sesearch -A -s untrusted_app -c service_manager  oem_policy.bin
sesearch -A -s untrusted_app -c property_service oem_policy.bin
sesearch -A -s priv_app -t <oem_type> oem_policy.bin
seinfo -adomain -x oem_policy.bin
```
- **Proof:** Every line of `comm -23` output, **plus reachability**. A policy rule is a capability, not a
  bug: write the app that uses it, fire it, and show the effect. An unexercised `allow` line is a
  hardening note, not a finding.
- **Escalation:** → D25-028 (`neverallow` and permissive domains), D25-022 (the services the rule now
  lets you reach), D25-032 (the properties it lets you set).
- **Ruled out when:** `comm -23` is empty for `untrusted_app`, or every added rule targets a type no app
  can reach in practice and you demonstrated the refusal. State the AOSP reference build you diffed
  against — the negative is only as good as the baseline.

### D25-028 · `neverallow` violations and permissive domains on a production build

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 for the exercised impact |
| **Maps to** | AOSP `system/sepolicy` `neverallow` assertions, enforced at build time and re-tested by CTS; AOSP SELinux concepts (permissive vs enforcing; `permissive=0` in an AVC means enforcing) |
| **Applies to** | OEM builds |
| **Requires** | oem-scope, root |

- **Test:** `neverallow` assertions are build-time invariants that CTS re-tests. An OEM build shipping a
  policy that violates one — or a permissive domain on a production build — has failed a compatibility
  requirement Google publishes and tests. That is a much stronger report than one asking the triager to
  agree with your threat model.
- **How:**
```bash
seinfo --permissive oem_policy.bin                  # permissive domains <- finding candidate (setools 4, pip-installable; `sepolicy-analyze oem_policy.bin permissive` when an AOSP build tree exists)
adb shell dmesg | grep -E 'avc: .*permissive=1'
adb shell ps -Z | awk '{print $1}' | sort -u | \
  grep -vE 'untrusted_app|isolated_app|platform_app|priv_app|system_app'
adb shell ls -Z /vendor/bin/hw/ | head -40
# then locate the corresponding neverallow in AOSP's system/sepolicy and cite it by file:line
grep -rn 'neverallow untrusted_app' system/sepolicy/
```
  AOSP-shape invariants worth checking: no domain may transition to a non-domain; `untrusted_app` may
  never gain `sys_admin`; app domains may never read `/proc/kmsg` or raw block devices.
- **Proof:** The permissive domain or the violating rule, paired with the CTS/VTS test name **and** the
  exercised impact — an app reaching something the invariant forbids.
- **Escalation:** A reachable permissive vendor daemon → kernel and driver attack surface → D16/D26.
- **Ruled out when:** `seinfo --permissive` (or `sepolicy-analyze … permissive`) returns nothing on a `user` build and `ps -Z`
  shows no unexpected domains. Note that a permissive domain on a `userdebug` build is expected and is
  not a finding — check `ro.build.type` first.

### D25-029 · `seapp_contexts` and `mac_permissions.xml` — the domain-assignment table

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | OEM engagements |
| **Requires** | oem-scope, root |
| **Maps to** | AOSP `seapp_contexts` selectors (`user=`, `seinfo=`, `name=`, `isPrivApp=`, `minTargetSdkVersion=`, `levelFrom=`) and `mac_permissions.xml` mapping signing certificates to `seinfo`; zygote assigning the domain at fork from signing cert, priv status and targetSdk |

- **Test:** These two files decide which SELinux domain a package runs in. A `name=`-matched rule that a
  repackaged app can satisfy, or a `seinfo` a third-party app can reach, is a sandbox-escape lead.
- **How:**
```bash
adb shell cat /system/etc/selinux/plat_seapp_contexts
adb shell cat /vendor/etc/selinux/vendor_seapp_contexts 2>/dev/null
adb shell cat /system/etc/selinux/plat_mac_permissions.xml
adb shell cat /vendor/etc/selinux/vendor_mac_permissions.xml 2>/dev/null
# does any rule select on name= rather than seinfo=?
adb -s "$SERIAL" shell 'cat /system/etc/selinux/*seapp_contexts /vendor/etc/selinux/*seapp_contexts 2>/dev/null' | grep -n 'name='
adb shell ps -AZ | grep com.poc.app     # what domain did YOUR app actually get?
```
- **Proof:** A `seapp_contexts` rule selecting on a package name that a third-party app can claim, plus
  `ps -AZ` showing your own installed package landing in the privileged domain that rule assigns.
- **Escalation:** A domain wider than `untrusted_app` obtained by an installable package is the finding;
  everything reachable from it (D25-027) is the impact.
- **Ruled out when:** Every non-`untrusted_app` rule selects on `seinfo=` backed by a signing certificate
  in `mac_permissions.xml` that you do not hold, or on `isPrivApp=true` with a `/system/priv-app` path you
  cannot write. Show `ps -AZ` for your own package landing in `untrusted_app_NN`.

### D25-030 · AVC denials as a live oracle — and the `dontaudit` and `setenforce 0` traps

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-03 |
| **Applies to** | all dynamic testing on rooted or userdebug devices |
| **Requires** | device, root |
| **Maps to** | AOSP SELinux concepts (AVC, `dontaudit`, `permissive=0`/`permissive=1` in the denial line) |

- **Test:** A denial tells you that you **reached the check** — your input travelled all the way to a real
  file or binder operation and the app-layer validation did not stop you, SELinux did. That is a far more
  promising result than silence, and it tells you exactly which deputy to look for next.
- **How:**
```bash
adb shell su 0 dmesg -w | grep -i avc
adb logcat -b all | grep -i 'avc:'
# fire the probe in another terminal, then read:
#   avc: denied { read } for ... scontext=u:r:untrusted_app:s0:c...
#        tcontext=u:object_r:<type>:s0 tclass=file permissive=0
```
  **Trap 1 — `dontaudit` hides denials silently.** Absence of an AVC line is *not* proof the operation was
  allowed or even attempted. Recompile the policy without `dontaudit` (`secilc` on the CIL) or reason from
  `sesearch` instead.
  **Trap 2 — never run the PoC with `setenforce 0`.** Use permissive only to *discover* which denials sit
  between you and impact. The recorded proof must run on a stock enforcing device or the finding is closed
  as unrealistic. If you used permissive at any point, say so and show the enforcing re-run.
- **Proof:** The denial line quoted verbatim alongside the intent or transaction you fired, and — for the
  positive case — an enforcing-mode run with `getenforce` in the same capture.
- **Escalation:** The denied `tcontext` names the type you now need a deputy for → D25-017.
- **Ruled out when:** `sesearch` shows the operation is genuinely allowed and it still failed — then the
  block is DAC or app-layer, not MAC (D25-007). Do not conclude "no denial, therefore allowed" without
  ruling out `dontaudit`.

### D25-031 · Do not hunt classic Flask/SELinux features Android does not have

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | OEM engagements |
| **Requires** | oem-scope, root |
| **Maps to** | Android's documented divergence from classic Flask/SELinux |

- **Test:** Four parts of the classic model do not transfer. Testers who learned SELinux on servers burn
  days on them. Read the table once and skip them.

| Classic SELinux | On Android |
|---|---|
| RBAC — roles, role dominance, `newrole` | **Vestigial.** Every subject is `u:r:<domain>:s0`, every object `u:object_r:<type>:s0`. There are no role bugs to find |
| User identity model (`users` file, `login`/`sshd` setting the SELinux user) | **Replaced** by `seapp_contexts` + `mac_permissions.xml` |
| MLS sensitivities (`s0`–`s15`, dominance) | Sensitivity is always `s0`; **categories** (`c0`–`c1023`) are repurposed as the per-app/per-user sandbox discriminator |
| Hand-written `.te` + m4, one monolithic policy | **CIL**, compiled and split by Treble across `plat`/`system_ext`/`product`/`vendor`/`odm` and linked at boot — vendor policy is a separate auditable artefact, and that is where the bugs are |

  What transfers unchanged and matters: type enforcement, the `allow`/`auditallow`/`dontaudit`/
  `neverallow` rule kinds, `type_transition`, attributes, constraints, the AVC, and "denied unless
  explicitly allowed".
- **How:**
```bash
seinfo --portcon --user --role policy.bin     # confirms the RBAC emptiness on this build
seinfo --stats policy.bin
```
- **Proof:** The `seinfo` output showing the empty role and user space, recorded once so the decision not
  to test those areas is documented rather than assumed.
- **Escalation:** The time saved goes into D25-027, which is where OEM policy bugs actually are.
- **Ruled out when:** n/a — this is a scoping item, not a test. It is "ruled out" only in the sense that
  the `seinfo` output is the evidence that these classes do not exist on the target.

### D25-032 · App-writable `persist.` or vendor system property that gates a security control

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 |
| **Applies to** | OEM builds mostly; always verify from an app UID, never from `adb shell` |
| **Requires** | device, root |
| **Maps to** | AOSP system-property documentation (`ro.` set once by init and immutable; `persist.` survives reboot; `property_contexts` with `system_internal_prop` / `system_restricted_prop` / `system_vendor_config_prop` / `system_public_prop`; vendor prefixes `vendor.`, `persist.vendor.`, `ro.vendor.`, `odm.`, `ro.odm.`) |

- **Test:** If an OEM labels a `persist.*` or vendor property with a context that permits writes from app
  domains, an app can set a reboot-surviving value. Test whether any property the target app or a
  security control reads is app-writable.
- **How:**
```bash
adb shell getprop | grep -E '^\[persist\.' | head -40
adb shell cat /system/etc/selinux/plat_property_contexts | grep -E 'persist\.' | head
adb shell cat /vendor/etc/selinux/vendor_property_contexts 2>/dev/null | head
sesearch -A -s untrusted_app -c property_service policy.bin
adb shell dmesg | grep -i 'avc: denied.*property_service'
# from the PoC app, not from shell:
#   SystemProperties.set("persist.vendor.foo.debug", "1")  via reflection
adb shell 'getprop persist.vendor.foo.debug'
adb reboot && adb wait-for-device && adb shell getprop persist.vendor.foo.debug
```
- **Proof:** A successful `set` **from an app UID** (the `shell` domain has different property
  permissions), the value surviving a reboot, and the app's behaviour changing as a result.
- **Escalation:** High when the property gates logging, debug mode, a certificate path, or a feature flag
  — it is a persistent, reboot-surviving control bypass → D21 and D26. `system.certs.enabled` is the
  canonical offensive example of the class.
- **Ruled out when:** `sesearch -A -s untrusted_app -c property_service` returns nothing relevant, and the
  `set` attempt from the app UID produces an AVC denial naming `property_service`. A success from
  `adb shell` alone is not this finding.

### D25-033 · Verified Boot state — what it guarantees and what it does not

| | |
|---|---|
| **Severity ceiling** | Critical on a device brief when the client's own deployment requires it off; otherwise Support |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-11 physical unlocked |
| **Applies to** | all for the recording; device/firmware engagements for the finding |
| **Requires** | device |
| **Maps to** | AOSP Verified Boot (chain of trust from hardware root → bootloader → boot and other verified partitions; dm-verity from Android 4.4, FEC in 7.0; AVB standardised footers and rollback protection in Android 8.0); ATT&CK mitigation M1004 System Partition Integrity, M1002 Attestation |

- **Test:** A green, locked boot state means the platform's chain of trust is intact. It says nothing
  about the app's own integrity, and nothing about an APEX the user cannot modify but Google can update.
  Record it, and check separately whether the client's own software requires it to be off.
- **How:** This item is the environment record only; the finding half (a client footprint under an
  init/service directory, a deployment that needs an unlocked bootloader) lives wholly in D25-042.
```bash
adb -s "$SERIAL" shell getprop ro.boot.verifiedbootstate ro.boot.flash.locked
adb -s "$SERIAL" shell getprop ro.boot.vbmeta.digest ro.boot.vbmeta.device_state
```
- **Proof:** The four property values, with one sentence on what green/locked does and does not guarantee
  (platform chain of trust intact; nothing about the app's own integrity or an updatable APEX).
- **Escalation:** → D25-042 when `verifiedbootstate` is not `green` on a device the client treats as
  trusted, or the client's deployment requires Verified Boot off or an unlocked bootloader (Critical there;
  the OEM VRP owns a system-partition write).
- **Ruled out when:** `verifiedbootstate=green`, `flash.locked=1`, and the client's install footprint is
  entirely inside `/data/app`. Note explicitly that your own test device being unlocked does **not**
  make this a finding (see the Graveyard).

### D25-034 · Kernel and GKI posture as context for every in-process native finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Requires** | device |
| **Maps to** | AOSP kernel documentation (ACK 5.10+ GKI separating hardware-agnostic core from vendor modules via the KMI; vendor modules/DLKMs); AOSP security enhancements (seccomp for all untrusted apps in Android 8; hardened usercopy, KASLR, PAN emulation, read-only-after-init; HWASan/BoundSan/IntSan/XOM/Scudo/ShadowCallStack in Android 10) |

- **Test:** Record the kernel version, GKI status and hardening sysctls. This is the layer under
  everything and it sets the realistic ceiling for a sandbox escape from an in-process native bug. It is
  **not** a finding on its own — "old kernel" filed against an app is closed immediately.
- **How:** The posture block from D25-004 already holds `uname`, `lsmod` and the hardening sysctls — do not
  re-run them; this item adds only the GKI/mitigation read:
```bash
adb -s "$SERIAL" shell getprop ro.kernel.version ro.build.version.security_patch
adb -s "$SERIAL" shell 'cat /proc/config.gz 2>/dev/null' | gunzip | grep -E 'CC_STACKPROTECTOR|CFI|SHADOW_CALL|KASAN'
```
- **Proof:** A kernel version, security-patch level and sysctl block recorded as environment.
- **Escalation:** → D16 for the reachability argument. It is also the reason an in-process memory bug is
  not merely "the app crashes".
- **Ruled out when:** n/a — it is unconditional context. Do not file it.

### D25-035 · Firmware acquisition and partition extraction

| | |
|---|---|
| **Severity ceiling** | Support (it is the precondition for D25-036 → D25-042) |
| **VRT** | n/a |
| **Attacker** | AM-12 |
| **Applies to** | OEM/firmware engagements only; explicitly out of scope for a store-app assessment |
| **Requires** | oem-scope, device |
| **Maps to** | Mobile Hacking Lab's Samsung firmware workflow (official firmware pulled from a mirror, unpacked to a rootfs, target `.so` extracted); its prerequisite article "Accessing Samsung Firmware Files" was 404 at the time the corpus was read, so the steps below are the ones the corpus records working |

- **Test:** Code that is not in the APK — vendor codecs, HALs, kernel, bootloader — has to come from the
  official firmware image. Get the same build the target device is running, not the newest one.
- **How:**
```bash
adb shell getprop ro.build.fingerprint    # match the firmware to THIS build
# unpack to a rootfs the harness can point at
mkdir -p rootfs && cd rootfs
# extract the partition images from the vendor package, then mount/unpack each
# and assemble the loader view the harness needs:
export QEMU_LD_PREFIX=$PWD
export QEMU_SET_ENV="LD_LIBRARY_PATH=/system/lib64:/vendor/lib64"
ls system/lib64 vendor/lib64 | head
# on-device cross-check of what actually loads
adb shell cat /proc/$(adb shell pidof -s com.target.app)/maps | awk '{print $6}' | sort -u | grep '\.so$'
```
- **Proof:** The extracted rootfs decoding a known-good vendor file through the harness (D25-036), and the
  fingerprint match between the firmware package and the device build.
- **Escalation:** → D25-036 (fuzzing), D25-038 (BTF offsets), D16.
- **Ruled out when:** The engagement is app-only. Say so and stop — this is the most expensive block in
  the chapter and the easiest to run out of scope.

### D25-036 · Extract a vendor parser from firmware and fuzz it off-device

| | |
|---|---|
| **Severity ceiling** | Critical when the parser is reachable 0-click |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) framing when the chain completes; otherwise rated by the reached impact |
| **Attacker** | AM-01 remote no interaction, where the parser is on an auto-render path |
| **Applies to** | OEM/firmware research; not applicable to a pure app-scoped engagement |
| **Requires** | oem-scope, native |
| **Maps to** | CVE-2020-8899 (Samsung Qmage in `libhwui.so`, 0-click MMS); Mobile Hacking Lab's rediscovery write-up; AOSP AIDL/native fuzzing guidance |

- **Test:** OEM-specific codecs and parsers are absent from AOSP, therefore under-fuzzed, and they sit on
  the highest-value 0-click paths (MMS/RCS auto-download, thumbnailing, notification image rendering).
- **How:**
```bash
export QEMU_LD_PREFIX=/path/to/android/rootfs
export QEMU_SET_ENV="LD_LIBRARY_PATH=/system/lib64:/vendor/lib64"
AFL_INST_LIBS=1 afl-fuzz -Q -i seeds/ -o out/ -- ./harness_shim @@
```
  Validate the setup **negatively first**: the harness must decode a known-good vendor file and print
  correct metadata before you trust a single crash.
- **Proof:** The harness decoding a known-good vendor file, then producing crashes. The corpus records the
  first crash matching CVE-2020-8899 at 47 minutes and 674 crashes collected overall — use that as the
  sanity bar for whether your harness is actually reaching the parser.
- **Escalation:** → D16 for triage of the crash, D05/D09 for the MMS/RCS delivery vector (no messaging
  chapter exists yet), D27 for the
  controlled-write write-up ("a controlled write of N bytes at offset X; register R is attacker-controlled,
  as shown in the attached tombstone").
- **Ruled out when:** The vendor parser is not reachable from any auto-render path you can enumerate, or
  the crash is an unexploitable null dereference with no attacker-controlled fault address. A crash alone
  is not a finding at any vendor.

### D25-037 · Build a stable C-ABI shim instead of `dlsym`-ing C++ symbols

| | |
|---|---|
| **Severity ceiling** | Support (harness engineering) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any closed-source C++ target |
| **Requires** | oem-scope, native |
| **Maps to** | Mobile Hacking Lab "Building a Shim Layer Around Skia (SkData + SkAndroidCodec)" |

- **Test:** Direct `dlopen`/`dlsym` against a vendor C++ library is brittle: symbols are inlined, hidden,
  optimised away or renamed between firmware builds, so the harness breaks on every OTA.
- **How:** Write a thin wrapper that links the target's *public C++ API* and exports a plain C interface:
```
harness (C)  ->  libshim_<target>.so (C++, stable C ABI)  ->  libhwui.so (vendor)
   shim_make_codec_from_data() / shim_get_info() / shim_get_android_pixels() / shim_destroy_codec()
```
```bash
nm -D --defined-only /path/rootfs/system/lib64/libhwui.so | c++filt | grep -i codec | head
```
- **Proof:** The failure mode first — mangled symbols such as `_ZN6SkData14MakeFromMallocEPKvm`
  "often returned nullptr or crashed immediately when fuzz input was provided" — then the shim validated
  by decoding a known-good file and printing correct image metadata (width, height, colour type, alpha
  type).
- **Escalation:** → D26 persistent-mode fuzzing, D16.
- **Ruled out when:** The target exposes a C API already. Then the shim is unnecessary overhead; link
  directly and say why.

### D25-038 · Derive struct offsets from the shipped image's own BTF rather than porting them

| | |
|---|---|
| **Severity ceiling** | Support (technique) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | GKI and Android kernels shipping BTF |
| **Requires** | oem-scope, root, native |
| **Maps to** | Mobile Hacking Lab "Porting ghostlock (CVE-2026-43499) to the Samsung Galaxy A17", Step 1 |

- **Test:** Offsets ported from another device with a different kernel generation or physical base are
  the classic wasted week. Extract them from the target image's own debug info and validate them at boot.
- **How:** Unpack `boot.img` → `vmlinux.elf`; if the kernel ships BTF, read the offsets for every
  structure the exploit touches and validate against a boot-time profile table.
```bash
bpftool btf dump file vmlinux.elf format c | grep -A30 'struct pipe_buffer'
pahole -C workqueue_struct vmlinux.elf
```
  The corpus's audited set for that exploit: `workqueue_struct`, `pool_workqueue`, `worker_pool`,
  `subprocess_info`, `pipe_inode_info`, `pipe_buffer`, `file`.
- **Proof:** A boot-time profile table validating against the extracted image — the corpus records
  "12/12 against the extracted image".
- **Escalation:** → D25-039 and the kernel endgame.
- **Ruled out when:** The kernel ships no BTF. Then say so and fall back to symbol-based derivation, and
  state the confidence penalty in the write-up.

### D25-039 · Identify which mitigation killed the payload before changing offsets

| | |
|---|---|
| **Severity ceiling** | Support (technique) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Samsung KDP/RKP-era devices and OEM builds with exec restrictions; kernel-scope engagements only |
| **Requires** | oem-scope, root, native |
| **Maps to** | Mobile Hacking Lab's CVE-2026-43499 port (`github.com/mobilehackinglab/ghostlock-a17`, target SM-A175F, GKI 6.12.23, BZA5); its NX/UXN/PXN and DEFEX notes |

- **Test:** When a payload dies, the generalisable habit is to identify *which* mitigation killed it and
  change the technique, not the offsets. Three signatures:
  - instruction fetch fault → NX/UXN/PXN;
  - a silent no-op on a credential write → **KDP at EL2** keeps credential and SELinux state read-only
    to EL1, so the classic "patch `cred`" endgame fails while every offset is correct;
  - `exit 137` with no output → DEFEX safeplace.
- **How:** The observable for KDP is the *absence* of effect with verified-correct candidates. The corpus
  records "20+ clean runs with verified-correct candidates, zero creds landed" before concluding KDP
  rather than a wrong offset.
```bash
adb shell id            # still the original uid after a "successful" cred write => suspect KDP
adb logcat -b all | grep -iE 'defex|rkp|kdp'
```
  The alternative endgame recorded in the corpus: forge a workqueue work item whose function is the
  usermode-helper exec path, so the helper runs with full init credentials and no cred write ever
  happens — ending at `uid=0(root) gid=0(root) context=u:r:kernel:s0`.
- **Proof:** The negative result across repeated runs with validated offsets, then the alternative
  endgame's `id` output.
- **Escalation:** Boot the extracted vendor kernel in QEMU with the minimum patches (KDP store NOP'd,
  `is_boot_state_unlocked()` forced true) and iterate at ~30 s per cycle instead of a 60–90 s device
  reboot — the corpus caught four distinct panic classes before spending a single device boot.
- **Ruled out when:** The payload succeeds. Otherwise this item never produces a negative — it produces a
  redirection.

### D25-040 · Firmware or OTA update accepted without integrity validation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.weakness_in_firmware_updates.firmware_does_not_validate_update_integrity` (**P3** baseline, CWE-434, baseline vector `AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H` — if your PoC needs neither `PR:H` nor `UI:R`, say so and argue the score up); `insecure_os_firmware.weakness_in_firmware_updates.firmware_is_not_encrypted` (**P5**); `insecure_os_firmware.weakness_in_firmware_updates.firmware_cannot_be_updated` (**VARIES**) |
| **Attacker** | AM-06 network attacker, or AM-11 physical for a local update path |
| **Applies to** | device/IoT/companion-hardware programmes |
| **Requires** | oem-scope, device |
| **Maps to** | ATT&CK T1474.002 Compromise Hardware Supply Chain, mitigation M1001 |

- **Test:** Intercept the update fetch, modify the package, and observe whether it installs. Do the same
  for the companion-hardware firmware pushed over BLE or USB by the phone app.
- **How:**
```bash
rg -n -i 'BluetoothGatt|writeCharacteristic|createBond|setPin|firmware|dfu|OTA|\.bin"|crc|signature' $DEC/jadx/sources
# capture the fetch
mitmproxy --listen-port 8080
# flip one byte in the image and re-serve it; then watch the device
adb logcat -b all | grep -iE 'update|ota|dfu|verify|signature'
```
- **Proof:** The device booting or running your modified package. Record the byte you changed and the
  version string the device reports afterwards.
- **Escalation:** Firmware control on a payment terminal is Critical and is typically the highest-value
  finding in the engagement. Where the phone app is the update conduit, the same finding also reaches
  D17 (the app ships the code) and D14 (the fetch's transport).
- **Ruled out when:** The modified image is rejected with a signature error the device logs, and the
  rejection is reproducible with a single flipped byte anywhere in the payload — including in a region a
  naive CRC would not cover. A CRC-only check is *not* integrity validation; test with a corrected CRC.

### D25-041 · Hardcoded or shared credentials on the device image

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.hardcoded_password.privileged_user` (**P1**, CWE-259, baseline `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`); `\|non_privileged_user` (**P2**, baseline `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`); `insecure_os_firmware.shared_credentials_on_storage` (**P3**, CWE-798); `insecure_os_firmware.over_permissioned_credentials_on_storage` (**P2**, CWE-250) |
| **Attacker** | AM-01 remote where the credential authenticates to a network service |
| **Applies to** | device and firmware programmes |
| **Requires** | oem-scope, device |
| **Maps to** | the VRT `insecure_os_firmware` credential branch — the one place in the mobile-adjacent taxonomy that reaches P1 without a chain |

- **Test:** Static credentials in a system app, a `/vendor` config, or a firmware blob. This is the
  highest-rated single observation in the whole chapter and it needs no escalation argument at all — only
  a successful authentication.
- **How:**
```bash
adb shell 'grep -rniE "password|passwd|secret|token|apikey" /system/etc /vendor/etc 2>/dev/null' | head -30
strings /path/to/firmware.bin | grep -EiA1 'password|BEGIN .*PRIVATE KEY|ssh-rsa'
python3 - <<'PY'     # resolve each package to its APK path first (D25-016 lists package names, not paths); D25-006 counts
import subprocess
S='<serial>'; pk=[l.strip() for l in open('oem-only-pkgs.txt') if l.strip()]; print('input',len(pk)); pulled=0
for p in pk:
    for l in subprocess.run(['adb','-s',S,'shell','pm','path',p],capture_output=True,text=True).stdout.splitlines():
        if l.startswith('package:'):
            a=l[8:].strip(); r=subprocess.run(['adb','-s',S,'pull',a,f'oem/{p}-'+a.rsplit('/',1)[-1]],capture_output=True,text=True); pulled+=(r.returncode==0)
print('probed',len(pk),'pulled',pulled)
PY
rg -n -i --no-ignore 'password|secret|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY' ./oem/
```
- **Proof:** The credential **plus a successful authentication with it**. A string that looks like a
  password is not a finding; the authenticated session is.
- **Escalation:** Cross-device reuse multiplies impact enormously. State explicitly whether the credential
  is per-device (derived from a serial or a per-unit key) or global — that single sentence is the
  difference between P2 and P1.
- **Ruled out when:** The recovered string does not authenticate anywhere, or it is a per-device value
  derived at provisioning time and differs across two units you checked. Check two devices before
  claiming "global".

### D25-042 · The client's own deployment writes to boot or system, or requires an unlocked bootloader

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-11 physical unlocked, or AM-03 once persistence exists |
| **Applies to** | rooted / OEM / firmware engagements only — out of scope for a store-app-only assessment; say so explicitly so the tester does not burn time |
| **Requires** | device |
| **Maps to** | ATT&CK T1398 Boot or Logon Initialization Scripts (these "are part of the operating system and require device rooting or jailbreaking to access"; OldBoot "leverages elevated privileges to alter init scripts on the boot partition"; FlexiSpy "installs boot hooks into `/system/su.d`"); T1645 Compromise Client Software Binary; T1625.001 System Runtime API Hijacking (Zen S0494 "can replace `framework.jar`"); mitigations M1004, M1002 |

- **Test:** For a kiosk, fleet or provisioned-hardware client: does their own software write to boot or
  system, install init scripts, or require an unlocked bootloader to function?
- **How:**
```bash
adb shell "su -c 'ls -la /system/etc/init /system/su.d /data/adb/service.d 2>/dev/null'"
adb shell getprop ro.boot.verifiedbootstate ro.boot.flash.locked
adb shell "su -c 'ls -la /system/app /system/priv-app'" | grep -i <client>
rg -n -i 'init\.rc|remount|/system/priv-app|magisk module|adb root' $DEC/jadx/sources provisioning-docs/
```
- **Proof:** A client-installed file under an init or service directory that survives reboot, or
  `verifiedbootstate` not `green` on the client's standard build.
- **Escalation:** The device's whole integrity model is off, which invalidates every app-level control in
  the rest of the report — state that consequence explicitly rather than filing it as a configuration note.
- **Ruled out when:** The client's footprint is entirely inside `/data/app` and `/data/data`, and the
  fleet ships locked and green. Record the two property values as the negative.

### D25-043 · `adb` left listening over TCP, and wireless debugging

| | |
|---|---|
| **Severity ceiling** | High for the app-level consequence on a debuggable build; the bare open port is an environment observation |
| **VRT** | `insecure_os_firmware.local_administrator_on_default_environment` (**P2**, CWE-276) on a fleet build where it is the default; otherwise `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**) |
| **Attacker** | AM-06 network attacker on the same Wi-Fi; AM-11 physical unlocked for the enablement |
| **Applies to** | all — but be explicit that adb-over-TCP requires the user or the fleet image to have enabled it. Do not present it as a default |
| **Requires** | device |
| **Maps to** | `developer.android.com/privacy-and-security/risks/android-debuggable` and the test/debug-features risk page; ATT&CK T1458 Replication Through Removable Media, mitigation M1012 ("prevent enabling USB debugging on Android devices unless specifically needed") |

- **Test:** Two separate questions. (a) Does the *device* expose adb to the network, turning a Wi-Fi
  attacker into a shell? (b) Is the *app* debuggable, so that shell reads its private data with no root?
  Only (b) is an app-scope finding; (a) is an environment observation on a fleet.
- **How:**
```bash
# network side
nmap -Pn -p 5555,5037,5554-5585 <victim-ip>
adb connect <victim-ip>:5555 && adb -s <victim-ip>:5555 shell id
# device-side posture
adb shell getprop service.adb.tcp.port
adb shell settings get global adb_enabled
adb shell settings get global adb_wifi_enabled          # Android 11+ wireless debugging
adb shell settings get global development_settings_enabled
# the app-level consequence
adb -s <victim-ip>:5555 shell run-as com.target.app cat shared_prefs/auth.xml
```
- **Proof:** A shell prompt from `adb connect` over the network, plus the app's private file read through
  `run-as` **in the same session**. The pairing is what makes it an app finding rather than a device note.
- **Escalation:** Every AM-12 (own rooted device) observation in the report becomes AM-04/AM-06 reachable
  once this holds — which is exactly the gate condition for the D21 triage item. → D11 for the data.
- **Ruled out when:** `adb_enabled=0` and `adb_wifi_enabled=0` on the fleet image, or the app is not
  debuggable so `run-as` returns `package not debuggable` even with the shell. Rate the bare open port as
  an environment observation and say so in the report.

### D25-044 · Developer-settings and USB posture the client's deployment depends on

| | |
|---|---|
| **Severity ceiling** | High on a kiosk, fleet, POS or enterprise deployment; Low elsewhere |
| **VRT** | `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-11 physical unlocked |
| **Applies to** | kiosk, fleet, POS and enterprise deployments especially; consumer apps where the client ships a companion desktop tool |
| **Requires** | device |
| **Maps to** | ATT&CK T1458 (adversaries "may utilize the physical connection of a device to a compromised or malicious charging station or PC to bypass application store requirements and install malicious applications directly"; DualToy side-loads "to both Android and iOS devices via a USB connection"), mitigation M1012 |

- **Test:** Does the app or the fleet require USB debugging, accept data over USB, or rely on a
  charging/kiosk integration? Each is a physical-access path into the app's data, and on a fleet the
  setting is a deployment decision rather than a user's.
- **How:**
```bash
# adb/developer-settings posture: D25-043 already reads adb_enabled and development_settings_enabled — reuse its row
adb -s "$SERIAL" shell getprop persist.sys.usb.config
adb -s "$SERIAL" shell dumpsys usb | grep -iE 'mCurrentFunctions|mScreenUnlockedFunctions|permission'
rg -n -i 'UsbManager|UsbAccessory|UsbDevice|ACTION_USB_DEVICE_ATTACHED|MTP|adb' $DEC/jadx/sources $DEC/apktool/AndroidManifest.xml
rg -n 'android.hardware.usb.action' -A6 $DEC/apktool/AndroidManifest.xml
```
- **Proof:** A fleet device with `adb_enabled=1` from which the app's private data is recovered — via
  `run-as` on a debuggable build (D25-014), via the OEM's backup/clone agent, or via `adb pull` of an
  app-written external path — or `persist.sys.usb.config` exposing a data function on a locked device.
  `adb backup` applies only to debuggable apps from Android 12 (API 31) onward; on older fleet images it
  still honours `allowBackup`.
- **Escalation:** ADB access plus a debuggable build (D02/D25-014) is full app compromise from a charging
  cable. → D25-049 for the auto-launch path.
- **Ruled out when:** `adb_enabled=0` and `development_settings_enabled=0` are enforced by the DPC
  (`DISALLOW_DEBUGGING_FEATURES` visible in `dumpsys device_policy`), and `persist.sys.usb.config` is
  charging-only until unlock.

### D25-045 · Dialler secret codes into engineering and diagnostic menus

| | |
|---|---|
| **Severity ceiling** | High when the reached screen exposes logs, identifiers or a security toggle; Medium otherwise |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (**VARIES**) for what the screen shows |
| **Attacker** | AM-11 physical unlocked (dialler), or AM-03 via the broadcast |
| **Applies to** | all devices with a telephony stack; yield highest on OEM, carrier and telematics builds |
| **Requires** | device |
| **Maps to** | drozer `scanner.misc.secretcodes`; MobSF `dialer_code_found` (level `warning`, `[android:scheme="android_secret_code"]`); How owner for the target's receiver: D03-041 (this item runs it across the OEM image) |

- **Test:** D03-041 owns the receiver test for the target; this item runs it across the whole OEM image.
  `android.provider.Telephony.SECRET_CODE` receivers fire when `*#*#<code>#*#*` is typed, with
  no permission, no consent dialog and no UI trail. On an OEM image they routinely open engineering
  menus; the receiver is exported, so a zero-permission app can deliver the `SECRET_CODE` action
  explicitly (`setComponent`/`setPackage`), which removes the physical precondition —
  `TelephonyManager.sendDialerSpecialCode()` itself is restricted to the default dialer, and an implicit
  send does not reach a receiver in an app targeting API 26+.
- **How:**
```bash
grep -rn 'android_secret_code' $DEC/apktool/AndroidManifest.xml $DEC/apktool/res/
drozer> run scanner.misc.secretcodes
drozer> run scanner.misc.secretcodes -v
# trigger without the dialler UI (and then from a zero-permission PoC app):
adb -s "$SERIAL" shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://1234 -n <pkg>/<SecretCodeReceiver>   # explicit: implicit sends are dropped for API 26+ receivers
adb shell dumpsys activity activities | head -30
```
  `scanner.misc.secretcodes` loads a helper class onto the drozer agent and iterates
  `packageManager().getPackages()` printing per-package codes; it needs the agent's `GET_CONTEXT`
  permission.
- **Proof:** `Broadcast completed: result=0` followed by the hidden activity appearing in
  `dumpsys activity activities`, or the diagnostic handler's logcat lines — plus a screenshot of the
  reached screen showing IMEI, serial, a log dump path, or a toggle.
- **Escalation:** A code that flips the app to a staging backend or disables pinning is a full MitM
  primitive → D14/D21. The reached activity is an exported component — run D04 against it. Combine with
  tapjacking (D04) to make a user dial it.
- **Ruled out when:** No `android_secret_code` scheme appears in the merged manifest or in
  `scanner.misc.secretcodes` output for the packages in scope, and the broadcast produces no resolver
  hit. On a device brief, note that the sweep covers all packages, not just the target.

### D25-046 · Local network listeners opened by the app or the image — check the bind address

| | |
|---|---|
| **Severity ceiling** | Critical when it binds `0.0.0.0` and serves files; High on loopback |
| **VRT** | `server_side_injection.file_inclusion.local` (**P1**) where a path handler traverses; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when the served file is a credential |
| **Attacker** | AM-06 network attacker on the same Wi-Fi for the `0.0.0.0` case; AM-03 zero-permission local app for loopback |
| **Applies to** | all. Android 16 ships Local Network Protection as an **opt-in** (developer option / app-level opt-in behind `RESTRICT_LOCAL_NETWORK`); it is not enforced for any shipping targetSdk, and **loopback is outside it either way**, so LNP mitigates neither variant today |
| **Requires** | device |
| **Maps to** | H1 #292761 (VK, "Stealing Private Information in VK Android App through PlayerProxy Port **Remotely**", $700); Oversecured "Android security checklist: theft of arbitrary files", local-web-servers section — "these servers become available from the local network while the app is running, which makes a possible vulnerability even more dangerous"; How owner for the listener inventory: D14-023 (this item keeps the bind-address test) |

- **Test:** D14-023 owns the listener inventory for the app; this item adds the bind-address test and the
  image-level listeners. Apps that run an embedded HTTP server, media proxy, WebSocket or debug port expose
  it to every app on the device and — if the bind address is not loopback — to the LAN. The bind address is the crux,
  not the port.
- **How:**
```bash
adb shell netstat -tulpn 2>/dev/null | grep LISTEN
adb shell ss -ltnp 2>/dev/null
adb shell 'cat /proc/net/tcp /proc/net/tcp6' | awk '{print $2, $4}'   # 0A == LISTEN
grep -rn 'NanoHTTPD\|ServerSocket\|newFixedLengthResponse\|serve(IHTTPSession\|WebSocketServer' $DEC/jadx/sources
# stock Android ships no curl: reach the loopback socket through adb forward (tests the HANDLER, not the bind address)
adb -s "$SERIAL" forward tcp:18080 tcp:<port>
curl -s "http://127.0.0.1:18080/cache/../../shared_prefs/secrets.xml"
adb -s "$SERIAL" shell 'cat /proc/net/tcp /proc/net/tcp6' | awk '$4=="0A"{print $2}'   # 00000000:PORT = all interfaces, 0100007F = loopback
# then from ANOTHER host on the same Wi-Fi: the bind-address test
curl -s "http://<device-ip>:<port>/cache/../../shared_prefs/secrets.xml"
# local-app variant: the zero-permission probe opens the socket itself (HttpURLConnection to 127.0.0.1:<port>)
```
  The canonical vulnerable shape:
```java
private static final String CACHE_PREFIX = "/cache/";
final String requestUri = session.getUri();
if (requestUri.startsWith(CACHE_PREFIX)) {
    String path = requestUri.substring(CACHE_PREFIX.length());
    File requestedFile = new File(context.getCacheDir(), path);   // path traversal
```
- **Proof:** The app's private file returned over HTTP **to a different machine on the LAN** (for the
  remote variant) or to a zero-permission app (for the loopback variant). Include the `0A` listen line
  showing the bind address as `00000000` rather than `0100007F`.
- **Escalation:** → D11 for the file contents, D13 if a session token comes back. Also check WebSocket and
  gRPC listeners, and debug ports left on in release (`adb forward tcp:x tcp:y` then probe).
- **Ruled out when:** Every listener binds `127.0.0.1`/`::1` (verify from `/proc/net/tcp`, not from the
  code) **and** the path handler canonicalises before opening. Test on a real network, not only loopback.

### D25-047 · Enumerate the local escalation surface mechanically

| | |
|---|---|
| **Severity ceiling** | Critical when a writable privileged endpoint is reachable from an app UID |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `insecure_os_firmware.local_administrator_on_default_environment` (**P2**, CWE-276) |
| **Attacker** | AM-03 |
| **Applies to** | device/OEM engagements |
| **Requires** | oem-scope, root |
| **Maps to** | the senior-researcher corpus's local-surface enumeration (`canhazaxs`, `/proc/net/unix`, netlink forging as the GingerBreak/Exploid shape) |

- **Test:** This is where an app-level foothold becomes root. Enumerate every filesystem-exposed endpoint,
  socket and shared-memory region reachable by the victim UID and groups.
- **How:**
```bash
# file-system-exposed endpoints reachable by the VICTIM uid/groups (canhazaxs is a 2014 binary with no releases — cite it, do not depend on it)
adb -s "$SERIAL" shell 'id; cat /proc/$(pidof -s com.target.app)/status | grep Groups'      # the victim's uid+groups
adb -s "$SERIAL" shell 'find /dev /dev/socket /data/local /sys/kernel/debug -perm -o+w ! -type l 2>/dev/null'
adb -s "$SERIAL" shell 'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null'
adb -s "$SERIAL" shell 'ls -lZ /dev /dev/socket'
# sockets (quote every remote command that carries a glob: zsh expands it on the host otherwise)
adb -s "$SERIAL" shell 'cat /proc/net/unix'      # PF_UNIX + abstract namespace (@name) - NO filesystem entry => cannot be permissioned
adb -s "$SERIAL" shell 'cat /proc/net/tcp /proc/net/udp'   # PF_INET - needs the inet group (AID 3003)
adb -s "$SERIAL" shell 'cat /proc/net/netlink'   # kernel<->user events; USER PROCESSES CAN FORGE KERNEL MESSAGES
adb -s "$SERIAL" shell 'netstat -anp | grep /dev/socket/'   # toybox netstat; -p resolves other UIDs only as root
# else: inode from /proc/net/unix -> ls -l /proc/[0-9]*/fd/* | grep <inode> -> ps <pid>
adb -s "$SERIAL" shell 'ls -l /proc/[0-9]*/fd/* 2>/dev/null | grep /dev/ashmem'       # shared memory (+ vendor pmem/NvMap/ION)
```
- **Proof:** Set-uid and set-gid binaries, writable character devices, writable sockets and writable
  directories reachable by the victim UID — quoted from the tool output, then exercised from an app UID.
- **Escalation:** Abstract-namespace sockets (`@android:debuggerd` and vendor equivalents) are a prime
  target because they cannot be permissioned; netlink forging is the GingerBreak/Exploid shape. → D16 for
  the primitive.
- **Ruled out when:** the `find -perm` sweeps return no writable privileged endpoint for the app's UID and group set,
  and every abstract socket you found belongs to a process in a domain `sesearch` shows `untrusted_app`
  cannot `connectto`.

### D25-048 · Enumerate the USB modes one connector exposes simultaneously

| | |
|---|---|
| **Severity ceiling** | High for a physical-access vector; state the vector requirements explicitly |
| **VRT** | `physical_security_issues.bypass_of_physical_access_control` (**VARIES**) where it defeats a lock; otherwise rated by the reached parser |
| **Attacker** | AM-10 physical locked / AM-11 physical unlocked |
| **Applies to** | device engagements. Pre-4.2.2 unauthenticated ADB over USB is **LEGACY**; 4.2.2 added RSA host allow-listing |
| **Requires** | oem-scope, physical |
| **Maps to** | the senior-researcher corpus's USB-surface enumeration; ATT&CK T1458 |

- **Test:** USB modes are mutually exclusive function sets, but Android supports several
  **simultaneously** through the Multifunction Composite Gadget — so one connector exposes several
  protocol parsers at once. Enumerate them rather than assuming "it's just charging".
- **How:**
```bash
adb -s "$SERIAL" shell 'cat /vendor/etc/init/hw/init.*.usb.rc /vendor/etc/init/*usb*.rc 2>/dev/null | grep -E "^on property:sys.usb.config=|functions"'   # every supported mode
adb -s "$SERIAL" shell 'ls /config/usb_gadget/g1/functions/ /config/usb_gadget/g1/configs/b.1/ 2>/dev/null; cat /config/usb_gadget/g1/UDC'   # configfs (4.4+ kernels, every Android 10+ device): the live function set
adb -s "$SERIAL" shell getprop persist.sys.usb.config sys.usb.config sys.usb.state
adb -s "$SERIAL" shell dumpsys usb | grep -iE 'mCurrentFunctions|mScreenUnlockedFunctions|mCurrentUsbFunctions'
adb -s "$SERIAL" shell 'ls /sys/class/android_usb/android0/ 2>/dev/null'   # LEGACY (3.x kernels) android_usb driver — absent on current devices
lsusb -v -d <VID>:<PID>                           # interfaces + endpoints, from the host
# `git grep USB_FUNCTION_ frameworks/base` lists the modes the framework knows about — needs an AOSP checkout
```
  Modes seen in the wild: ADB, fastboot, vendor download (Odin/RUU), MTP (the modern default), PTP, mass
  storage (≤4.0), RNDIS tethering, audio source.
- **Proof:** The enumerated mode list for the actual target build, plus the parser each exposes, plus
  which of them are reachable while the screen is locked.
- **Escalation:** ADB over USB is still the fastest physical win where USB debugging is on (D25-043); the
  rest feed D25-052 and D16.
- **Ruled out when:** `sys.usb.config` is charging-only until unlock and `/config/usb_gadget/g1/configs/b.1/`
  (legacy: `/sys/class/android_usb/android0/functions`) shows no data function on a locked device. State the Android version — behaviour differs.

### D25-049 · USB `device_filter` auto-launch grants the app USB access with no permission prompt

| | |
|---|---|
| **Severity ceiling** | High when the parser is native and crashes controllably, or when device data drives an authenticated action; Medium when it only DoSes |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927) for the entry point; the reached impact sets the rating |
| **Attacker** | AM-10/AM-11 physical (malicious accessory) |
| **Applies to** | apps shipping a `device_filter`. Requires physical USB contact — a charging kiosk, a rental car, a borrowed cable — state that precondition |
| **Requires** | physical |
| **Maps to** | `developer.android.com/develop/connectivity/usb/host`, verbatim: "When users connect a device that matches your device filter, the system presents them with a dialog that asks if they want to start your application… **If users accept, your application automatically has permission to access the device until the device is disconnected**"; and "If your application uses an intent filter to discover USB devices as they're connected, it automatically receives permission if the user allows your application to handle the intent" |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.usb.host; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for USB host on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** The filter declares the VID/PID an attacker must present. Accepting the launch dialog grants
  USB access **without a separate permission prompt**, after which the app opens the device and parses
  whatever it sends. The attacker builds or emulates a device with the declared identifiers.
- **How:**
```bash
cat $DEC/apktool/res/xml/device_filter.xml     # VID/PID the attacker must present
grep -rnE 'openDevice|UsbDeviceConnection|bulkTransfer|controlTransfer|claimInterface|UsbRequest' $DEC/jadx/sources/ -A10
# emulate with Linux gadget mode (Pi Zero / Facedancer / USB-IP)
modprobe libcomposite
echo 0x1234 > /sys/kernel/config/usb_gadget/g1/idVendor
echo 0x5678 > /sys/kernel/config/usb_gadget/g1/idProduct
# on the phone
adb shell dumpsys usb | grep -iE 'device|permission|mDevicePermissionMap'
adb logcat | grep -E "START u0 .*USB_DEVICE_ATTACHED"
```
  Then send oversized and malformed frames on the bulk endpoint and watch the parser.
- **Proof:** The app launching on attach (the `START u0 … USB_DEVICE_ATTACHED` logcat line), followed by
  either a native crash with a controllable fault address (`adb logcat -b crash`, tombstone under
  `/data/tombstones/`) or the app acting on your forged device data.
- **Escalation:** → D16 native memory safety with a fully attacker-controlled input channel that needs no
  network and no app install; → D23 where the device data drives a payment or unlock action.
- **Ruled out when:** The app ships no `device_filter` and calls `requestPermission()` explicitly for every
  device, or the read loop validates a device-side challenge/response before parsing. Read
  `res/xml/device_filter.xml`; an empty `res/xml` directory is the negative.

### D25-050 · USB accessory matching is done on strings the accessory itself supplies

| | |
|---|---|
| **Severity ceiling** | High when the accessory channel drives an action or feeds a native parser; Medium when it only supplies display data |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (**VARIES**) where the app derives trust from the identity; otherwise rated by the reached sink |
| **Attacker** | AM-10/AM-11 physical |
| **Applies to** | apps shipping an `accessory_filter` |
| **Requires** | physical |
| **Maps to** | `developer.android.com/develop/connectivity/usb/accessory` — the filter attributes `manufacturer`, `model`, `version`, the `openAccessory()` → `FileInputStream(fd)` pattern, and the documentation's own statement that "The accessory sends these attributes [to] the Android-powered device" |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.usb.accessory; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for USB accessory on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** `accessory_filter.xml` matches on `manufacturer`, `model` and `version` — values the accessory
  sends during AOA enumeration. There is no cryptographic identity. Any accessory can claim to be the
  genuine one, after which the app opens a raw `FileDescriptor` and reads.
- **How:**
```bash
cat $DEC/apktool/res/xml/accessory_filter.xml
grep -rnE 'openAccessory|UsbAccessory|getManufacturer\(\)|getModel\(\)|getSerial\(\)|FileInputStream\(.*fd' $DEC/jadx/sources/ -A12
adb shell dumpsys usb | grep -A5 accessory
```
  Determine whether the app verifies anything beyond the filter — a challenge/response, a signature, a
  serial allow-list — then present those exact strings from your own AOA gadget and stream malformed data
  into the read loop.
- **Proof:** `dumpsys usb` showing your forged manufacturer/model as the connected accessory, the app's own
  log line for a connected accessory, and the effect of your payload — a crash, a state change, or a
  command executed.
- **Escalation:** → D16 for the parser; → D12 if the app derives a key or a trust decision from the
  accessory identity.
- **Ruled out when:** The read loop performs a challenge/response or verifies a serial against a
  server-held allow-list before acting, demonstrated by your forged accessory being rejected. The filter
  matching alone is never the control — say so even when the app is otherwise fine.

### D25-051 · BFU versus AFU — state which physical state your threat model assumes

| | |
|---|---|
| **Severity ceiling** | High for apps whose entire protection is "Android encrypts storage" |
| **VRT** | `insecure_os_firmware.data_not_encrypted_at_rest.sensitive` (**VARIES**); `insecure_os_firmware.poorly_configured_disk_encryption` (**VARIES**); `insecure_os_firmware.recovery_of_disk_contains_sensitive_material` (**VARIES**) |
| **Attacker** | AM-10 physical locked (BFU) / AM-11 physical unlocked or AFU |
| **Applies to** | all apps handling regulated or high-value data |
| **Requires** | physical, root |
| **Maps to** | HackTricks android-physical-attacks, citing AOSP authentication / Gatekeeper / Weaver / KeyMint documentation |

- **Test:** Separate **BFU** (before first unlock — CE data still cryptographically protected) from
  **AFU** (after first unlock — CE keys resident in memory, so the lock screen is largely a UI barrier
  until reboot). Every physical finding in the report must name which state it assumes.
- **How:**
```bash
adb shell su -c 'ls -l /data/system_de/0/spblob /data/system_ce/0/snapshots'
adb shell getprop ro.crypto.type ro.crypto.state
# reboot, do NOT unlock, then:
adb shell su -c 'ls /data/user/0/com.target.app' ; echo "BFU rc=$?"
# unlock once, lock again, then repeat -> AFU
```
  Artefact locations worth knowing: scrypt parameters and salt for the Synthetic Password under
  `/data/system_de/<user_id>/spblob`; background task snapshots under `/data/system_ce/0/snapshots`.
- **Proof:** For an app assessment the reportable output is: which app data becomes readable in AFU state,
  and whether the app adds its own cryptographic boundary on top of FBE. Show the BFU failure and the AFU
  success side by side.
- **Escalation:** The credential path is Gatekeeper (verify + rate-limit) → Keymaster/KeyMint (release
  auth-bound keys on a valid token) → Synthetic Password (protects the `fscrypt` CE keys) →
  StrongBox/Weaver (moves secret material and throttling into a separate chip). **TEE compromise and
  lock-screen bypass are not the same thing.** With Weaver/StrongBox, guesses often remain online-only
  with exponential backoff — which is why short PINs stay weak but long alphanumeric passwords become
  much more resistant. → D11, D12.
- **Ruled out when:** The app's sensitive data is protected by a key bound to user authentication with a
  short validity window, so AFU state alone does not release it (demonstrate by reading the file in AFU
  and getting ciphertext). "Android encrypts it" is not that demonstration.

### D25-052 · AFU USB kernel surface — the lock screen is not the boundary

| | |
|---|---|
| **Severity ceiling** | Critical (device compromise), reported as a threat-model caveat for app findings |
| **VRT** | `physical_security_issues.bypass_of_physical_access_control` (**VARIES**) |
| **Attacker** | AM-10 physical locked |
| **Applies to** | any engagement with a physical-access threat model; scope-gated — most programmes exclude it |
| **Requires** | oem-scope, physical |
| **Maps to** | HackTricks android-physical-attacks; the iOS parallel worth citing in a cross-platform report is checkm8 for Boot ROM devices and CVE-2025-24200 as a USB Restricted Mode policy-enforcement bypass re-enabling USB data on a locked device |

- **Test:** In AFU state, forensic chains attack the **USB-reachable kernel surface** exposed while
  locked — HID, USB Audio/ALSA, UVC, MTP/MSC — not the password. A malicious peripheral emulator presents
  crafted descriptors and reports to reachable drivers.
- **How:** Enumerate what is reachable while locked (from D25-048), then map each to its kernel driver:
```bash
adb -s "$SERIAL" shell 'ls /config/usb_gadget/g1/configs/b.1/ 2>/dev/null; ls /sys/class/android_usb/android0/functions 2>/dev/null'   # configfs; the android_usb path is LEGACY
adb -s "$SERIAL" shell dumpsys usb | grep -iE 'mScreenUnlockedFunctions|mCurrentFunctions'
adb -s "$SERIAL" shell dmesg | grep -iE 'usb|hid|uvc|snd-usb|mtp' | tail -40
adb shell cat /proc/net/ptype /proc/net/protocols | head -40
```
- **Proof:** Kernel code execution followed by reading already-decrypted CE storage — at which point app
  databases, cached tokens, previews and in-memory secrets are all exposed.
- **Escalation:** Caveat every app-level storage finding with it: on an AFU device, filesystem-level
  compromise exposes app data regardless of the app's own storage choices → D11.
- **Ruled out when:** The programme excludes physical-access attacks (check D25-001), or the locked device
  exposes no data function at all. Where it is out of scope, state it as a threat-model note and do not
  test it.

### D25-053 · Biometric TA AuthToken forgery — root into PIN recovery

| | |
|---|---|
| **Severity ceiling** | Critical (device-level) |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (**VARIES**); `broken_authentication_and_session_management.authentication_bypass` (**P1**) where it reaches the account |
| **Attacker** | AM-11 physical unlocked plus root; scope-gated |
| **Applies to** | devices without a real Secure Element or Weaver path |
| **Requires** | oem-scope, root, physical |
| **Maps to** | HackTricks android-physical-attacks "Biometric TA AuthToken forgery", citing the DarkNavy research |

- **Test:** Vendor biometric TAs that share the AuthToken HMAC trust domain with Gatekeeper and KeyMint
  can be abused to sign attacker-controlled data or to leak the per-boot HMAC key, upgrading Android root
  into PIN recovery.
- **How:** `hw_auth_token_t` is a fixed **69-byte** structure — `challenge`, `user_sid`,
  `authenticator_id`, `authenticator_type`, `timestamp`, and a trailing **32-byte HMAC-SHA256** with a
  per-boot shared secret; `authenticator_type = 1` is the Gatekeeper/PIN type. Four patterns to hunt:
  1. a **signing oracle** — a TA command that HMAC-signs an arbitrary 69-byte buffer without confirming a
     real biometric match;
  2. a **biometric result oracle + verifier confusion** — a valid type-2 token accepted where type-1 is
     required;
  3. **error-path secret leakage** of the 32-byte per-boot key via TrustZone logs, shared memory or
     secure logs;
  4. **TA memory disclosure** after defeating weak TA ASLR.
  Invoke the TA directly with `libTEEC` or an equivalent TEE client.
- **Proof:** A forged type-1 token accepted by Keymaster to decrypt the first-stage Synthetic Password
  blob, then offline PIN brute force using the AES-GCM tag as the correctness oracle.
- **Escalation:** Multiple dormant fingerprint TAs in one firmware image increase the surface because each
  may hold the same per-boot HMAC material. StrongBox/Weaver-backed designs reduce the chain's usefulness
  because the Keymaster-gated intermediate is not always enough for an offline oracle.
- **Ruled out when:** The device backs the lock factor with Weaver or a StrongBox Secure Element, so PIN
  guesses stay online-only with hardware-enforced throttling — demonstrate the backoff rather than
  asserting it. Also ruled out when the programme excludes root-required findings (D25-001).

### D25-054 · Target activity reachable over the lock screen

| | |
|---|---|
| **Severity ceiling** | High; Critical where it reaches the account |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927); `broken_authentication_and_session_management.authentication_bypass` (**P1**) if it reaches the account |
| **Attacker** | AM-10 physical locked |
| **Applies to** | all |
| **Requires** | device |
| **Maps to** | AOSP severity guidance rating "Lockscreen bypass" as High; the Android & Google Devices top-tier table entry "Software-Based Lockscreen Bypass"; Google Mobile VRP's non-qualifying "Secondary lockscreen bypasses" — check which lock you are bypassing before filing; How owner for the static half: D04-056 (this item keeps the keyguard experiment) |

- **Test:** An activity that can show over the keyguard and then exposes data or a state-changing control
  is a lock-screen-scoped finding on the app rather than on the platform.
- **How:**
  D04-056 owns the static half and the first launch; this chapter adds the keyguard experiment that proves
  reach from an **app**, because the shell UID is exempt from background-activity-launch limits and the
  keyguard gate — `am start` while locked is NOT an AM-03 proof.
```bash
grep -nE 'showWhenLocked|turnScreenOn|FLAG_SHOW_WHEN_LOCKED|FLAG_DISMISS_KEYGUARD|setShowWhenLocked|requestDismissKeyguard' \
     $DEC/apktool/AndroidManifest.xml $DEC/apktool/smali/ $DEC/jadx/sources/
adb -s "$SERIAL" shell locksettings set-pin 1234            # a real keyguard must exist on the test device (keyevent 26 only toggles power); afterwards: locksettings clear --old 1234
# probe: its MainActivity schedules startActivity(<target>/.LockscreenActivity) after --ei delay_ms; its own
# LockActivity is declared android:showWhenLocked="true" and is the positive control
adb -s "$SERIAL" shell "am start -S -n com.probe/.MainActivity --ei delay_ms 20000 --es target com.target.app/.LockscreenActivity"
adb -s "$SERIAL" shell input keyevent KEYCODE_SLEEP          # lock inside the delay window
adb -s "$SERIAL" logcat -d -b all | grep -E 'ActivityTaskManager: (START u0|Background activity launch blocked|Abort background activity)'
adb -s "$SERIAL" shell dumpsys window | grep -iE 'mShowWhenLocked|KeyguardOccluded|isKeyguardShowing'
```
- **Proof:** Sensitive content or a usable state-changing control on a locked device, recorded end to end
  with the lock visibly engaged before and after — the target activity's `START u0 … callingUid=<probe uid>`
  line with `isKeyguardShowing=true` in the same capture, AND the negative control (the probe launching a
  non-`showWhenLocked` activity from the background) producing the BAL-blocked line.
- **Escalation:** → D13 when it reaches the session; → D20 when it only renders data.
- **Ruled out when:** No component declares `showWhenLocked`/`FLAG_SHOW_WHEN_LOCKED`, or the probe's launch
  of the target is BAL-blocked or lands behind the keyguard while the probe's own LockActivity (control)
  shows — quote both logcat lines; a shell `am start` result proves nothing either way. Distinguish the platform
  keyguard from the app's own PIN screen — Google does not pay for secondary lock-screen bypasses, while
  Xiaomi rates an app-lock bypass Medium and a system lock-screen bypass High.

### D25-055 · NFC dispatch as a no-touch entry point into the app

| | |
|---|---|
| **Severity ceiling** | High when the dispatched data reaches a router, WebView or file sink |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927); rated by the reached sink |
| **Attacker** | AM-10/AM-11 physical proximity (<8 cm) |
| **Applies to** | apps registering `ACTION_NDEF_DISCOVERED` / `TECH_DISCOVERED` / `TAG_DISCOVERED` |
| **Requires** | physical |
| **Maps to** | `developer.android.com/develop/connectivity/nfc/nfc` — the three dispatch actions and their priority order (`NDEF_DISCOVERED` > `TECH_DISCOVERED` > `TAG_DISCOVERED`), AAR precedence, and the tech-list XML |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.nfc; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for NFC (also `service check nfc` must not say `not found`) on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** Components registered for NFC dispatch **must** be exported, because the system delivers the
  intent, and they usually carry no permission. Some NFC actions fire with no interaction at all. An
  attacker-written tag therefore delivers attacker bytes into an exported component with proximity as the
  only precondition.
- **How:**
```bash
grep -nE 'android.nfc.action.(NDEF|TECH|TAG)_DISCOVERED' $DEC/apktool/AndroidManifest.xml -B6 -A10
ls $DEC/apktool/res/xml/ | grep -iE 'nfc_tech'
cat $DEC/apktool/res/xml/nfc_tech*.xml 2>/dev/null
# emulate without a tag
adb -s "$SERIAL" shell "am start -a android.nfc.action.NDEF_DISCOVERED -n com.target.app/.NfcActivity -d 'https://attacker.example/path'"
# router precedence: a host-less, non-BROWSABLE NFC filter can hand the full https route table to a router that checks host before scheme
adb -s "$SERIAL" shell "am start -a android.nfc.action.NDEF_DISCOVERED -n com.target.app/.NfcActivity -d 'https://<verified-host>/<auth-gated route>'"
# with a real tag: write the NDEF record with NFC Tools onto an NTAG215
adb logcat -d | grep -iE 'NfcDispatch|NDEF_DISCOVERED|START u0 .*com.target'
```
- **Proof:** The dispatch line in logcat showing the activity started from the tag, plus the effect of the
  payload — a URL loaded, a route taken, a file written.
- **Escalation:** → D09 when the payload is a URI (the tag becomes a deep-link delivery vector with no
  browser and no click); → D10 when it reaches a WebView; → D16 when it reaches a native parser. Record
  every route the NDEF path reaches that the BROWSABLE path gates → D09-002 / D09-022.
- **Ruled out when:** The app registers no NFC action in the merged manifest, or the handler validates
  the record's origin (an AAR pinned to the app's own package plus a signed payload) before acting.

### D25-056 · HCE `HostApduService` — the payment category, and Android 15 observe mode

| | |
|---|---|
| **Severity ceiling** | Critical for a relay of live EMV transactions; High for pre-auth logic running before consent |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**) for the role; the financial impact is rated in D23 |
| **Attacker** | AM-02 remote one click (the user installs the relay app) for the relay; AM-10 proximity for the reader side |
| **Applies to** | apps registering `HostApduService`; Android 15+ for observe mode and polling-frame handling |
| **Requires** | payments, device |
| **Maps to** | `HostApduService.processPollingFrames()`, `CardEmulation.registerPollingLoopPatternFilterForService()` and the Android 15 observe-mode APIs; `res/xml/apduservice.xml` AID registration; How owner for the configuration checks: D23-059 / D23-061 (this item keeps the relay framing) |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.nfc android.hardware.nfc.hce; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for either NFC feature (the AVD has no NFC controller) on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** D23-059 (observe mode, polling frames) and D23-061 (AID registration, `requireDeviceUnlock`,
  relay exposure) own the configuration checks — run them and reuse the rows; this item keeps only the
  relay framing. Two questions. (a) Does the app register a `HostApduService` in the `payment` category and ask
  to become the default NFC payment app — the shape that allows relaying live EMV transactions, with the
  POS talking ISO 14443-4/EMV to the phone and the app forwarding APDUs over a C2 channel while a backend
  crafts responses? (b) On Android 15+, does the app run logic in `processPollingFrames()` *before* the
  user has consented to anything?
- **How:**
```bash
grep -n 'HostApduService\|android.nfc.cardemulation' $DEC/apktool/AndroidManifest.xml -A8
cat $DEC/apktool/res/xml/apduservice.xml 2>/dev/null
grep -rnE 'processCommandApdu|processPollingFrames|registerPollingLoopPatternFilterForService|setPreferredService|CardEmulation' $DEC/jadx/sources/ -A10
adb shell dumpsys nfc | grep -iE 'aid|default|payment|observe'
```
- **Proof:** For (a): the registered AIDs from `apduservice.xml` plus a captured APDU exchange being
  forwarded off-device. For (b): pre-consent code paths executing on a polling frame, shown in logcat
  before any user interaction.
- **Escalation:** → D23 for the payment impact; → D15 for the C2 channel's backend.
- **Ruled out when:** No `HostApduService` is registered, or the service's `processCommandApdu` refuses
  every APDU until an in-app authenticated session exists (demonstrate with a reader before login).

### D25-057 · BLE link content is readable by every app on the device

| | |
|---|---|
| **Severity ceiling** | High when the payload is a credential or an actuation command; Medium for telemetry |
| **VRT** | `broken_authentication_and_session_management.cleartext_transmission_of_session_token` (**P4**) where a token crosses; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (**VARIES**) otherwise |
| **Attacker** | AM-04 local app with one common permission; AM-10 proximity for the replay |
| **Applies to** | any app using BLE. Android 12+ splits `BLUETOOTH_CONNECT`/`SCAN`/`ADVERTISE` — note which the eavesdropping app needs |
| **Requires** | device |
| **Maps to** | `developer.android.com/develop/connectivity/bluetooth/ble/ble-overview`, verbatim caution: "When a user pairs their device with another device using BLE, the data that's communicated between the two devices is accessible to **all** apps on the user's device. For this reason, if your app captures sensitive data, you should implement app-layer security to protect the privacy of that data"; MASWE-0026 |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.bluetooth_le; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for BLE on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** Google documents the channel as device-wide readable. If the app's BLE protocol carries tokens,
  health readings, door or vehicle commands, or firmware, and relies on BLE link-layer encryption rather
  than app-layer crypto, then any other app on the phone can read it — no root, one common permission.
- **How:**
```bash
grep -rnE 'connectGatt|BluetoothGatt|writeCharacteristic|readCharacteristic|setCharacteristicNotification|BluetoothGattServer|PERMISSION_(READ|WRITE)_ENCRYPTED|createBond' $DEC/jadx/sources/ -A8
adb -s "$SERIAL" shell setprop persist.bluetooth.btsnooplogmode full   # Android 9+; or Developer options > Enable Bluetooth HCI snoop log (the pre-9 `bluetooth_hci_log` setting is LEGACY)
adb -s "$SERIAL" shell 'svc bluetooth disable; sleep 2; svc bluetooth enable'   # the mode is read at stack start
# reproduce the app's flow, then collect the log (written to /data/misc/bluetooth/logs/, retrievable without root via bugreport)
adb -s "$SERIAL" shell dumpsys bluetooth_manager | grep -iE 'snoop|bonded|GATT'
adb -s "$SERIAL" bugreport br.zip && unzip -o br.zip 'FS/data/misc/bluetooth/logs/btsnoop_hci.log' -d br/
# rooted: adb -s "$SERIAL" shell su -c 'cat /data/misc/bluetooth/logs/btsnoop_hci.log' > btsnoop_hci.log
wireshark br/FS/data/misc/bluetooth/logs/btsnoop_hci.log   # filter: btatt
```
- **Proof:** The plaintext token, command or reading visible in a Wireshark ATT packet from the snoop log,
  with the corresponding app action timestamped. The finding is "no app-layer confidentiality on a channel
  the platform explicitly documents as device-wide readable" — quote the caution.
- **Escalation:** Replay the captured command from a second phone → unauthorised actuation. → D12 if the
  payload is key material; → D23 if it is a payment or unlock command.
- **Ruled out when:** The ATT payloads are ciphertext under an app-layer key that is not itself derivable
  from the APK (check D12), or the sensitive values never traverse the link. Show the captured packets as
  the negative.

### D25-058 · The app's own GATT server accepts writes from an unbonded peer

| | |
|---|---|
| **Severity ceiling** | Critical when the write can push firmware or a credential; High when it triggers an action, changes configuration, or feeds a parser |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `broken_authentication_and_session_management.authentication_bypass` (**P1**) where it grants access |
| **Attacker** | AM-10 proximity, no app installed on the victim's phone |
| **Applies to** | apps that expose a `BluetoothGattServer`. Android 16's improved bond-loss handling changes bond-removal UX but not this |
| **Requires** | physical |
| **Maps to** | the BLE overview's app-layer-security requirement; MASWE-0018 |

- **Skip when:** `adb -s "$SERIAL" shell 'for f in android.hardware.bluetooth_le; do pm has-feature $f >/dev/null && echo "$f=true" || echo "$f=false"; done'` prints `false` for BLE on the test device: record the row as `blocked (hardware: <feature> absent on <serial>)` — never `n/a` and never a negative; move it to a device that has the feature.
- **Test:** Apps exposing a GATT server for companion pairing, file transfer or "connect your watch"
  frequently register characteristics with `PERMISSION_WRITE` rather than `PERMISSION_WRITE_ENCRYPTED` or
  `_SIGNED`, so any nearby device can connect and write without bonding.
- **How:**
```bash
grep -rnE 'BluetoothGattServer|addService|BluetoothGattCharacteristic\(|PERMISSION_WRITE|PERMISSION_WRITE_ENCRYPTED|PROPERTY_WRITE|onCharacteristicWriteRequest|getBondState|BOND_BONDED' $DEC/jadx/sources/ -A10
```
  The vulnerable shape is `onCharacteristicWriteRequest(...)` acting on `value` with no
  `device.getBondState() == BOND_BONDED` check and no app-layer authentication. From a second machine:
```bash
bluetoothctl scan on           # find the advertised name/UUID
bluetoothctl connect <MAC>     # then interactively: menu gatt / select-attribute <uuid> / write "0x01 0x02"   (gatttool is deprecated in BlueZ 5 and not built by default)
python3 - <<'PY'               # or bleak (pip install bleak), the same write without pairing
import asyncio
from bleak import BleakClient
async def main():
    async with BleakClient("<MAC>") as c:
        await c.write_gatt_char("<uuid>", bytes([0x01, 0x02]), response=True)
asyncio.run(main())
PY
# or: nRF Connect on a second phone, write the characteristic
```
- **Proof:** The app reacting to a write from an unbonded peer — logcat from the target app plus the
  `bluetoothctl`/`bleak` or nRF transcript showing no pairing occurred.
- **Escalation:** → D16 if the written bytes reach native code; → D17 if they are a firmware image; →
  D25-040 for the firmware-integrity question.
- **Ruled out when:** Every writable characteristic is declared `PERMISSION_WRITE_ENCRYPTED` or `_SIGNED`,
  or `onCharacteristicWriteRequest` returns `GATT_INSUFFICIENT_AUTHENTICATION` for an unbonded device —
  show the refusal in the `bluetoothctl`/`bleak` transcript.

### D25-059 · CompanionDeviceManager association with an attacker-controlled device, and `removeBond()`

| | |
|---|---|
| **Severity ceiling** | High when the association grants a persistent background channel into a privileged code path, or when `removeBond()` is reachable from an exported component; Medium for the association alone (it needs a tap in the picker) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (**VARIES**, CWE-927) for the exported `removeBond()` path; rated by the reached impact |
| **Attacker** | AM-10 proximity; AM-03 for the exported-component variant |
| **Applies to** | apps using CDM; `CompanionDeviceManager#removeBond(int)` is Android 16+ |
| **Requires** | physical |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` (`CompanionDeviceManager#removeBond(int)`; monitor `BluetoothDevice#ACTION_BOND_STATE_CHANGED`); `developer.android.com/about/versions/16/behavior-changes-all` — "Companion apps no longer notified of discovery timeouts": companion apps now receive `RESULT_USER_REJECTED` instead of `RESULT_DISCOVERY_TIMEOUT`, which changes the error handling your PoC will see on API 36+ |

- **Test:** `CompanionDeviceManager.associate()` presents a picker of nearby devices filtered by name, MAC
  or UUID pattern. A spoofed advertiser matching the filter appears in that picker; a user who taps it
  grants an association, after which the app may auto-connect, sync and — with
  `REQUEST_COMPANION_RUN_IN_BACKGROUND` — act on the attacker device's data indefinitely. Separately,
  check whether the app exposes `removeBond()` through an exported component, which lets an unprivileged
  app force a companion peripheral to unpair.
- **How:**
```bash
grep -rnE 'CompanionDeviceManager|AssociationRequest|BluetoothLeDeviceFilter|BluetoothDeviceFilter|WifiDeviceFilter|setNamePattern|REQUEST_COMPANION|removeBond' \
     $DEC/jadx/sources/ $DEC/apktool/AndroidManifest.xml -A8
adb shell dumpsys companiondevice
adb shell dumpsys companiondevice | grep -A5 com.target.app
```
  Then advertise from a second device with a name matching the app's `setNamePattern` regex and complete
  the association. For the `removeBond()` path, drive the exported component from a zero-permission app.
- **Proof:** `dumpsys companiondevice` listing your spoofed device as associated with the target package,
  followed by the app syncing or acting on data you supplied. For `removeBond()`: the companion device
  unpairing on command from the PoC app, with `ACTION_BOND_STATE_CHANGED` in the log.
- **Escalation:** → D25-057/D25-058 with a durable, user-blessed channel. Forced unpairing of a lock, a
  key fob or a medical device either denies service or forces a re-pair the attacker can intercept.
- **Ruled out when:** The association request uses a `BluetoothDeviceFilter` pinned to a MAC address or a
  service UUID the attacker cannot claim, **and** no exported component reaches `removeBond()`. An
  over-broad name pattern (`.*` or a common prefix) is itself worth calling out even when nothing else
  holds.

### D25-060 · Scanner acting on `Barcode.getWifi()` — joining an attacker-chosen network on a scan

| | |
|---|---|
| **Severity ceiling** | High when the app has any unpinned host; Medium otherwise |
| **VRT** | `insecure_data_transport.cleartext_transmission_of_sensitive_data` (**VARIES**, CWE-319 — rated on what the network position then reaches) via the network position; the rated finding is whatever the MitM then reaches |
| **Attacker** | AM-02 remote one click (the user scans a sticker); then AM-06 network attacker |
| **Applies to** | apps whose scanner enables the Wi-Fi barcode format |
| **Requires** | device |
| **Maps to** | `developers.google.com/ml-kit/vision/barcode-scanning/android` — `Barcode.getWifi()`, `getValueType()`; the page gives no validation guidance |

- **Test:** A scanner that supports the Wi-Fi barcode type (`WIFI:T:WPA;S:…;P:…;;`) can offer to join a
  network from a scanned code. The attacker chooses the SSID and PSK and therefore the DNS and the
  gateway — a scan becomes a network-position attack delivered by a sticker.
- **How:**
```bash
grep -rnE 'getWifi\(\)|Barcode\.TYPE_WIFI|WifiNetworkSuggestion|WifiNetworkSpecifier|addNetwork|enableNetwork|WifiManager' $DEC/jadx/sources
qrencode -o wifi.png 'WIFI:T:WPA;S:AttackerAP;P:Passw0rd123;;'
# scan it, then:
adb shell dumpsys wifi | grep -iE 'SSID|Suggestion'
```
- **Proof:** The device joining, or offering a one-tap join to, the attacker's SSID directly from the scan
  — screen-record the scan-to-join, then show the app's subsequent traffic traversing the attacker's
  gateway.
- **Escalation:** Network position plus any unpinned host is the D14 MitM chain with the hardest part
  (getting the position) solved by the app itself.
- **Ruled out when:** The scanner restricts `getValueType()` to the formats the feature needs, or the app
  never calls a Wi-Fi join API with scanned values. Check `setBarcodeFormats()` — an unrestricted scanner
  that nonetheless ignores `TYPE_WIFI` in its handler is a true negative; say which.

### D25-061 · Android Auto `CarAppService` with `ALLOW_ALL_HOSTS_VALIDATOR`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (**VARIES**) for the rendered account data |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | any app shipping an Android for Cars integration (categories `androidx.car.app.category.NAVIGATION` / `.POI` / `.IOT` / `.WEATHER`) |
| **Requires** | auto |
| **Maps to** | `developer.android.com/training/cars/apps` — the docs name `createHostValidator()` and `HostValidator.ALLOW_ALL_HOSTS_VALIDATOR` and explicitly warn to validate the binding host; MASWE-0018; How owner: D06-054 |

- **Test:** The `CarAppService` is exported by necessity so the car host can bind it. The library's gate
  deciding *which* host may bind is `createHostValidator()`. Shipping
  `HostValidator.ALLOW_ALL_HOSTS_VALIDATOR` means any app on the phone can bind and drive the car session
  — a surface no phone-app checklist covers, and one that renders account data with no phone UI and no
  lock-screen involvement.
- **How:** Run D06-054 — it owns the `createHostValidator()` grep and the bind-from-an-unprivileged-app
  PoC; reuse its row. This chapter adds only the scope note: the car surface renders account data with no
  phone UI and no lock-screen involvement, so route the finding to the programme that owns the Auto
  integration and rate the rendered data, not the bind.
- **Proof:** As D06-054 (the car-session lifecycle logs with your package as the client, and the template
  contents captured in the bind callback).
- **Escalation:** Session data read → account enumeration; command injection into navigation. Join with
  D25-063: the car surface's endpoints are a second, weaker client.
- **Ruled out when:** `createHostValidator()` returns a validator built with `addAllowedHosts()` pinned to
  the Google host package and signature, or the service is not exported. Show the bind attempt being
  refused, not just the source line.

### D25-062 · Wear OS `WearableListenerService` dispatching on path with no node or capability check

| | |
|---|---|
| **Severity ceiling** | Critical if a path puts the phone app into an authenticated state; High to Medium otherwise |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (**P1**) for the auth-shaped path; `broken_access_control.privilege_escalation` (**VARIES**) otherwise |
| **Attacker** | AM-03 (an app that can reach the Data Layer) / AM-10 (a paired attacker node) |
| **Applies to** | any app with a Wear OS companion. The Data Layer is Android-phone-only, so the path set is often *less* tested than the main API |
| **Requires** | wear |
| **Maps to** | `developer.android.com/training/wearables/data/data-layer` and `.../data/messages` (`DataClient`, `MessageClient`, `WearableListenerService`, `sendMessage(nodeId, path, data)`); MASWE-0018, MASWE-0032; CVE-2025-12080 (intent abuse in Google Messages for Wear OS, patched May 2025) as evidence the form factor is a live surface; How owner: D06-055 |

- **Test:** The Wear Data Layer delivers `DataItem`s and messages addressed by **path** (`/sync`, `/auth`,
  `/logout`). The receiving service is exported so Google Play services can bind it. Test whether
  `onMessageReceived` / `onDataChanged` dispatches on path alone with no `getSourceNodeId()` comparison
  against a known, capability-verified node.
- **How:** Run D06-055 — it owns the path/`getSourceNodeId()` greps and the attacker-node delivery; reuse
  its row. This chapter adds only the scope note: the watch is a second device, so the paired-node attacker
  (AM-10) and the programme's wearable scope decide where the report goes; enumerate every `pathPrefix`
  as the channel's undocumented API.
- **Proof:** As D06-055 (a path-only dispatch with no node comparison, then the phone app acting on
  attacker-chosen bytes delivered on that path).
- **Escalation:** A trusted-by-path "auth complete" message is a direct authentication bypass over a
  channel nobody tested → D13. On Wear the surface widens further: activities, foreground services (with
  `FLAG_ACTIVITY_NEW_TASK`), Tiles and Complications can all fire the same payload — exercise all four.
- **Ruled out when:** Every handler compares `getSourceNodeId()` against a node obtained from
  `CapabilityClient` for the app's own capability, and rejects unknown nodes. Show the rejection path.

### D25-063 · The companion-surface API is a second, weaker client

| | |
|---|---|
| **Severity ceiling** | Critical (BOLA on a companion-only endpoint) |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**); `\|view_sensitive_information_iterable_object_identifiers` (**P3**) for read-only |
| **Attacker** | AM-05 another user of the same app |
| **Applies to** | apps with Wear, Auto, TV, widget or Tile companions |
| **Requires** | backend-api |
| **Maps to** | the shadow-API method from the bug-hunting corpus: a mobile client's hardcoded backend calls are frequently an *older* API version than the current web app uses, with weaker auth, weaker rate limits, weaker validation and more field exposure. **Diff behaviourally, not by response shape. A version difference alone is Informational; the weakened control is the finding** |

- **Test:** Wear, Auto, TV and widget code paths frequently call *different* endpoints, or the same
  endpoints with a different client id or scope, and were built by a smaller team under time pressure.
  Extract those endpoints specifically and test them for the authorisation bugs already fixed on the
  phone client.
- **How:**
```bash
# endpoints referenced only by companion code
grep -rnE 'https?://[a-zA-Z0-9./_-]+' $DEC/jadx/sources/ | grep -iE 'wear|watch|auto|car|tv|widget|tile|glance' | sort -u > companion-hosts.txt
wc -l companion-hosts.txt          # count, per the shell-loop ban
# diff against the phone client's endpoint set
comm -23 <(sort -u companion-hosts.txt) <(sort -u phone-hosts.txt)
```
  Then diff four security-relevant behaviours for the **same operation** across the phone path and the
  companion path: auth strength (does the companion path accept no token, an expired token, or a
  lower-privilege token the phone path rejects?), rate limiting (burst both; a missing 429 means
  throttling was never applied to the companion path), input validation (same oversized or injected
  payload to both), field exposure (does the companion response carry internal ids or PII the phone
  response redacts?). Replay each with a low-privilege token and with another user's object id.
- **Proof:** A 200 with another user's data from a companion-only endpoint that the phone endpoint rejects
  with 403 — the status-code delta between the two paths, with both requests side by side and both
  bodies diffed.
- **Escalation:** → D15 for the full authorisation surface on the newly found path.
- **Ruled out when:** The companion paths are byte-identical to the phone paths in auth handling,
  throttling and field set across all four behavioural axes. A different *URL* with identical behaviour is
  Informational — do not file it.

### D25-064 · Instant-App reachability and the endpoints a retired instant experience left live

| | |
|---|---|
| **Severity ceiling** | Medium to High, depending on what the endpoint returns |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (**P3**) or higher depending on the data; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (**VARIES**) |
| **Attacker** | AM-01 remote no interaction (for the live endpoints); AM-02 for the browser-triggered client path |
| **Applies to** | **LEGACY client, live server.** Google Play Instant is discontinued — as of December 2025 instant apps cannot be published and the Play services Instant APIs stop working. Any app that ever shipped an instant experience |
| **Requires** | backend-api |
| **Maps to** | `developer.android.com/topic/google-play-instant/overview` (discontinuation timeline; `InstantApps.isInstantApp()`; the restricted API and permission subset); H1 #258460 (Quora) — the researcher's own published correction is the caution to heed: "services can be accessed by Instant Apps only in case when `android:visibleToInstantApps` flag is enabled" |

- **Test:** Two halves. (a) **Reachability discipline:** do not claim browser-triggerable Instant-App reach
  for a component without checking `android:visibleToInstantApps` — this is a documented correction a
  researcher had to publish about his own report. (b) **Live server exposure:** instant experiences were
  built permission-light and often unauthenticated because instant apps could only use a subset of APIs
  and permissions. Those endpoints frequently remain deployed long after the client is dead.
- **How:**
```bash
grep -n 'visibleToInstantApps' $DEC/apktool/AndroidManifest.xml
grep -rnE 'InstantApps|isInstantApp|dist:instant|dist:module|targetSandboxVersion' $DEC/jadx/sources/ $DEC/apktool/AndroidManifest.xml
grep -rnE 'instant|/i/|/lite/|guest' $DEC/jadx/sources/ | grep -iE 'http' | sort -u
# the deep links that used to launch the instant experience usually still resolve
grep -nE 'android:host=|android:pathPrefix=' $DEC/apktool/AndroidManifest.xml | sort -u
adb shell am start -a android.intent.action.VIEW -d 'https://<host>/<instant-era-path>'
```
  Then probe the discovered server paths unauthenticated.
- **Proof:** An unauthenticated 200 from an instant-flavoured endpoint returning user or catalogue data;
  or an instant-era deep-link path resolving to a handler that skips an auth or consent step present in
  the normal flow.
- **Escalation:** → D15 for the endpoint's authorisation surface; → D09 for the deep-link handler. Almost
  nobody checks this now that the client side is dead, which is precisely why it is worth ten minutes.
- **Ruled out when:** The merged manifest carries no `dist:instant`, no `InstantApps` reference and no
  `visibleToInstantApps`, and no instant-flavoured host appears in the host inventory. For the
  reachability half: absence of `visibleToInstantApps="true"` on a service is the negative — state it
  rather than claiming browser reach.

### D25-065 · Enumerate every instance of the app that exists on the device

| | |
|---|---|
| **Severity ceiling** | Support (it converts D13 device-binding and D23 entitlement items from "unverified" to "demonstrated") |
| **VRT** | n/a |
| **Attacker** | AM-05 / AM-11 |
| **Applies to** | Android 5+ for multi-user; Android 15+ for Private Space; OEM clone features vary |
| **Requires** | device |
| **Maps to** | `developer.android.com/about/versions/15/features#private-space` — "The private space uses a separate user profile", "Apps in the private space are installed as separate copies from any apps in the main space", and the explicit compatibility warning about apps "with work profile logic that assume any installed copies of their app that aren't in the main profile are in the work profile"; How owner: D01-052 |

- **Test:** Every checklist assumes one install per device. On a real device the app may exist as user 0, a
  work profile (user 10+), a Private Space profile, an OEM dual-app/clone instance, and a guest-user
  instance. Each has its own data directory, its own FCM token and its own session — so any device-binding
  or entitlement scheme that counts installs is wrong.
- **How:** Run D01-052 — it owns the enumeration (`pm list users`, `pm list packages --user all`, per-user
  data directories, OEM clone ids); reuse its row. This chapter adds only what the enumeration feeds:
  the reach tests in D25-066/067 and the device-demographic note (which OEM clone features the client's
  fleet actually ships).
- **Proof:** As D01-052 (two live data directories for the same package under different user ids, side by
  side).
- **Escalation:** Feeds D11 (cross-user data), D13 (device binding), D23 (trial and entitlement
  duplication), and D25-066 (the reach tests).
- **Ruled out when:** `pm list users` shows only user 0 and the OEM provides no clone feature on this
  model. Record which OEM features you checked — the answer is model-specific.

### D25-066 · Cross-user provider read and cross-user service bind

| | |
|---|---|
| **Severity ceiling** | High (cross-user data access is an explicitly bought impact class) |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**) where it returns another user's records; `broken_access_control.privilege_escalation` (**VARIES**) otherwise |
| **Attacker** | AM-05 another user of the same device |
| **Applies to** | Android 5+ multi-user; Private Space Android 15+ |
| **Requires** | device |
| **Maps to** | Android & Google Devices in-scope impact, verbatim: "**Multi-User & Private Space:** Cross-user sensitive data access, or unlocking Private Space without the designated lock factor"; Samsung High: "Bypass Operating System protections including access memory or file contents across application, user, or profile boundaries"; How owners for the per-component tests: D07-011, D06-023 (this item keeps the crossing routes) |

- **Test:** D07-011 (provider from a second user / locked Private Space) and D06-023 (caller check never
  compares the user id) own the per-component tests; this item adds the crossing **routes**. Everything in
  every checklist binds and queries from user 0. A work profile, Private Space or OEM clone instance runs
  as a different UID with a different data directory — and a service that guards on `getCallingUid()` or
  on a same-signature check passes trivially for a *clone of the same app*. A plain app cannot resolve
  another user's provider or bind its service without `INTERACT_ACROSS_USERS*` — which `adb shell` holds,
  so every shell `--user` success is a false positive. The routes to test are: (1) a clone/work instance
  in the SAME profile group reached through connected apps (D25-082) or `CrossProfileApps`; (2) a
  preinstalled target with `android:singleUser="true"` services or an `INTERACT_ACROSS_USERS*` holder
  acting as deputy; (3) user-shared storage (`/storage/emulated/<id>` on OEM clones, MediaStore); (4) a
  backend identity keyed by device id rather than account.
- **How:**
```bash
UID2=$(adb -s "$SERIAL" shell pm create-user gapuser | tr -d '\r' | grep -oE '[0-9]+$')   # never assume 10 (10 is usually the work profile)
adb -s "$SERIAL" shell am switch-user $UID2
adb -s "$SERIAL" install --user $UID2 probe.apk     # host path; a managed/private profile with DISALLOW_DEBUGGING_FEATURES needs `pm install-existing --user <id> com.probe` or the DPC test app
# the probe (NOT shell) queries content://0@com.target.app.provider/data and binds the service -> expect SecurityException naming INTERACT_ACROSS_USERS
# shell is the DISCOVERY tool only: proves the data exists, not reachability
adb -s "$SERIAL" shell content query --user 0 --uri content://com.target.app.provider/data
adb -s "$SERIAL" shell dumpsys activity services com.target.app | grep -E 'user|clientUid|ConnectionRecord'
# the guard itself
grep -rnE 'getCallingUid|getCallingPackage|checkSignatures|getPackagesForUid|singleUser|INTERACT_ACROSS_USERS' $DEC/jadx/sources/ $DEC/apktool/AndroidManifest.xml -A6
```
  The specific defect to look for: a guard that checks the UID or the signature but never compares
  `UserHandle.getUserId(uid)`. Also test the file form: `file:///data/user/$UID2/com.target.app/…`.
- **Proof:** The probe's result from user B with its uid in `dumpsys activity services` / the provider's
  log — never a `--user` shell call. Screenshot `pm list users` and the dumpsys together. A
  `Permission Denial … requires android.permission.INTERACT_ACROSS_USERS_FULL` for the probe is also a
  reportable data point — it is the negative.
- **Escalation:** → D11 cross-user data read → D23 entitlement duplication → D15 if the rows contain
  server object ids you can then enumerate.
- **Ruled out when:** The probe gets `Permission Denial … INTERACT_ACROSS_USERS_FULL` for both query and
  bind **and** routes 1–4 above were each tested, including the clone/work-profile variant (same profile
  group, different UID), which is the case that most often crosses when a plain second user does not. By default a second user cannot see user 0's
  packages — prove whether your call actually crossed rather than assuming it did.

### D25-067 · Private Space boundary (Android 15)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**) where data crosses; `broken_authentication_and_session_management.authentication_bypass` (**P1**) for unlocking without the designated factor |
| **Attacker** | AM-05 / AM-11 |
| **Applies to** | Android 15+ |
| **Requires** | device, api>=35 |
| **Maps to** | `developer.android.com/about/versions/15/behavior-changes-all` (private space as a separate user profile; launcher requirements `ROLE_HOME`, `ACCESS_HIDDEN_PROFILES`, `getLauncherUserInfo()`, `requestQuietModeEnabled()`, `ACTION_PROFILE_AVAILABLE`/`ACTION_PROFILE_UNAVAILABLE`; app stores must declare `android.intent.category.APP_MARKET`); `developer.android.com/about/versions/15/features` |

- **Test:** Private space installs apps into a separate user profile that is hidden when locked. Two
  consequences: an app that assumes "another install of me must be in a work profile" mis-handles private
  space, and data isolation between the private-space copy and the main copy must hold.
- **How:**
```bash
adb shell pm list users
adb shell pm list packages --user <privateSpaceUserId> | grep com.target.app
adb shell am start --user <privateSpaceUserId> -n com.target.app/.MainActivity
grep -rn 'ACCESS_HIDDEN_PROFILES\|getLauncherUserInfo\|requestQuietModeEnabled\|ACTION_PROFILE_AVAILABLE\|ACTION_PROFILE_UNAVAILABLE\|ROLE_HOME' $DEC/jadx/sources/ $DEC/apktool/AndroidManifest.xml
# then lock the private space and retry - apps there should be stopped
adb shell am get-current-user
```
- **Proof:** Data written by the private-space instance readable from the main-profile instance or vice
  versa — via a shared external path, a cloud account keyed only by device id, or a content provider that
  does not scope by user. Or the private-space instance still responding after the space is locked.
- **Escalation:** → D11/D20. The privacy boundary broken by the app's own storage or sync design is the
  finding, not the platform's.
- **Ruled out when:** The private-space copy's data lives only under `/data/user/<id>/`, the app's
  server-side identity is per-account rather than per-device, and the instance is stopped when the space
  is locked. Test all three.

### D25-068 · Work-profile data crossing the profile boundary

| | |
|---|---|
| **Severity ceiling** | High in an enterprise-scoped engagement (DLP bypass); out of scope for a consumer app without a managed configuration in scope |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (**P3**) for the leaked corporate data |
| **Attacker** | AM-05 / AM-11 |
| **Applies to** | managed devices only — work profile API 21+, fully managed API 21+. Confirm the engagement includes an enrolled device |
| **Requires** | enterprise |
| **Maps to** | community work-profile checklists on cross-profile clipboard, sharing, notifications and file mediation; `DISALLOW_CROSS_PROFILE_COPY_PASTE` |

- **Test:** In a managed setup, confirm the app does not leak work data into the personal profile via
  clipboard, sharing intents, notifications, contacts or a shared account.
- **How:**
```bash
adb shell dpm list-owners
adb shell pm list users
adb shell am start --user 10 -n com.target/.MainActivity
adb shell dumpsys device_policy | sed -n '/Profile/,/^$/p'
adb shell dumpsys package | grep -A10 'Cross-profile'
```
  Then copy a work-profile secret to the clipboard and attempt to paste it in a personal-profile app;
  share a work document to a personal app; check whether work notifications render in the personal
  profile.
- **Proof:** Work-profile content appearing in a personal-profile app — a screenshot of the paste, or the
  personal app receiving the shared file — **against an explicitly configured restriction** such as
  `DISALLOW_CROSS_PROFILE_COPY_PASTE`. Without the restriction configured, cross-profile sharing is
  intended behaviour and not a finding.
- **Escalation:** Enterprise DLP bypass; combine with D07 provider access across users.
- **Ruled out when:** The restriction is configured and the paste or share is refused. Note that many
  items in the public work-profile checklists target the **MDM/EMM platform**, not the app — those belong
  in the MDM vendor's scope and should be routed there rather than filed against the app.

### D25-069 · App behaviour under a device-policy restriction it claims to honour

| | |
|---|---|
| **Severity ceiling** | Medium to High in an enterprise engagement |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-11 physical unlocked (the enrolled user) |
| **Applies to** | managed devices only |
| **Requires** | enterprise |
| **Maps to** | community MDM checklists on screen-capture, camera, backup and managed-configuration enforcement |

- **Test:** Apply the policy restrictions the target claims to support — screen capture disabled, camera
  disabled, backup disabled, app restrictions via managed configuration — and confirm the app actually
  honours them rather than silently proceeding.
- **How:**
```bash
adb shell dpm set-profile-owner com.dpc/.Receiver          # on a test device
adb shell dumpsys device_policy | grep -iE 'screenCapture|camera|backup|restrictions'
adb shell am get-config
adb shell screencap /sdcard/t.png && adb pull /sdcard/t.png
```
  Then attempt a screenshot, a camera use and a backup from inside the app.
- **Proof:** A successful `screencap` while `setScreenCaptureDisabled(true)` is in force for the profile,
  or the app writing a backup despite the restriction.
- **Escalation:** Enterprise policy bypass → D20 for the captured content, D11 for the backup contents.
- **Ruled out when:** `screencap` returns a black frame or fails, the camera call throws, and the backup
  is refused — with `dumpsys device_policy` in the same capture showing the restriction active.

### D25-070 · Work-profile required-app replacement

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `broken_authentication_and_session_management.authentication_bypass` (**P1**) where the replaced app holds the enterprise session |
| **Attacker** | AM-11 physical unlocked (temporary access to enable Developer Options and USB debugging) |
| **Applies to** | Android Enterprise BYOD work profiles with required-app policies |
| **Requires** | enterprise |
| **Maps to** | CVE-2023-21257 (the patch being bypassed — ADB sideloads blocked under `DISALLOW_INSTALL_APPS` / `DISALLOW_DEBUGGING_FEATURES`); HackTricks android-enterprise-work-profile-bypass |

- **Test:** An MDM that marks an app *required* for the work profile auto-installs it if missing.
  Combined with Android Studio's "Install for all users" staging, that lets an attacker with brief
  physical access replace any required work-profile app — after the CVE-2023-21257 patch.
- **How:**
```bash
adb shell pm list users          # user 0 = Owner, user 10 = Work profile
adb install --user 10 legit.apk  # expected: SecurityException: Shell does not have permission to access user 10
```
  Build the payload with the **same package name** and a much larger `versionCode`:
```gradle
android { namespace = "com.workday.workdroidapp"
  defaultConfig { applicationId = "com.workday.workdroidapp"
    versionCode = 900000004; versionName = "9000000004.0" } }
```
  Deploy from Android Studio with *Deploy as instant app → Install for all users* (`INSTALL_ALL_USERS`).
  The work-user install is denied, but the legitimate app is marked uninstalled and the staged APK stays
  cached. Within roughly 1–10 minutes the MDM notices the required package is missing and the
  work-profile Play client reinstalls it — choosing the locally staged build because it has the highest
  `versionCode`.
- **Proof:** The malicious build running inside the work profile under the genuine package name, reported
  as compliant by the MDM. Record the MDM's compliance screen alongside `pm path --user 10`.
- **Escalation:** Enterprise data theft plus persistence — the MDM reinstalls it whenever it is removed.
  If the replaced package is mapped to a per-app VPN, the malicious build inherits the VPN profile and
  reaches internal hosts directly.
- **Ruled out when:** The device enforces `DISALLOW_INSTALL_UNKNOWN_SOURCES` and
  `DISALLOW_DEBUGGING_FEATURES` such that Developer Options cannot be enabled at all, or the MDM pins the
  required app to a signing certificate and refuses a higher `versionCode` with a different signer. Test
  the signer check explicitly — `versionCode` precedence is the mechanism.

### D25-071 · Device Policy Controller removal and enterprise-control bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-11 physical unlocked; AM-03 where an app surface reaches the removal |
| **Applies to** | managed and enterprise deployments |
| **Requires** | enterprise |
| **Maps to** | Android & Google Devices in-scope impact, verbatim: "**Enterprise Bypasses:** Unauthorized removal of the Device Policy Controller (DPC)" — explicitly named in-scope and rarely covered in public checklists |

- **Test:** Whether a managed device's DPC can be removed, or its policies neutered, without
  authorisation — including through the app under test's own surfaces.
- **How:**
```bash
adb shell dpm list-owners
adb shell dumpsys device_policy | head -40
adb shell pm list packages -d | grep -i dpc
# then attempt removal through the app surface under test, and through the OEM's own flows
adb shell dpm remove-active-admin com.dpc/.Receiver
```
- **Proof:** `dpm list-owners` showing no owner after your action, with the previously enforced policies
  no longer applied (re-run the D25-069 checks and show them now passing).
- **Escalation:** Full managed-device compromise; combine with D25-070 for persistence.
- **Ruled out when:** `dpm remove-active-admin` is refused, `DISALLOW_REMOVE_MANAGED_PROFILE` is set, and
  no app surface reaches `removeActiveAdmin` / `clearProfileOwner`. Grep the app for those calls before
  concluding.

### D25-072 · Kiosk, lock-task and screen-pinning escape from inside the app

| | |
|---|---|
| **Severity ceiling** | High in a kiosk engagement (the device *is* the security boundary); N/A otherwise |
| **VRT** | `insecure_os_firmware.kiosk_escape_or_breakout` (**VARIES**) |
| **Attacker** | AM-11 physical unlocked (a member of the public at the kiosk) |
| **Applies to** | dedicated/COSU/kiosk deployments only; scope it explicitly |
| **Requires** | enterprise |
| **Maps to** | VRT `insecure_os_firmware > kiosk_escape_or_breakout`; community COSU/lock-task checklists |

- **Test:** Where the app runs as a kiosk or is used under screen pinning, look for a path out — a WebView
  that opens an external browser, a share sheet, a settings deep link, a file picker, a print dialog, or
  a crash that drops to the launcher.
- **How:**
```bash
adb shell dumpsys activity activities | grep -i 'lockTask\|mLockTaskModeState'
# from inside the app: exercise every link, share button, file picker and error dialog
adb shell am start -a android.settings.SETTINGS
adb shell am start -a android.intent.action.VIEW -d "https://x"
adb shell am start -a android.intent.action.GET_CONTENT -t '*/*'
```
- **Proof:** Reaching Settings, a browser or the launcher from inside the pinned app — screen recording
  with `mLockTaskModeState` shown before and after.
- **Escalation:** Full device access from a public kiosk → D25-044 (developer settings) → D25-043 (adb) →
  the whole device.
- **Ruled out when:** `mLockTaskModeState` remains `LOCK_TASK_MODE_LOCKED` through every exit attempt and
  the allow-list (`setLockTaskPackages`) contains only the kiosk app. Enumerate the allow-list — a
  permitted browser or file-manager package is the escape.

### D25-073 · OEM MDM and firmware layers (Knox, E-FOTA and equivalents), and the null-means-compliant trap

| | |
|---|---|
| **Severity ceiling** | Medium to High in an enterprise engagement; a bug in the OEM layer itself belongs to the **OEM's** VRP, not the app vendor's |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 / AM-11 |
| **Applies to** | OEM-managed fleets; out of scope for a standard app engagement unless the app itself ships the integration |
| **Requires** | enterprise |
| **Maps to** | community enterprise checklists on Knox Guard, Knox Platform for Enterprise, E-FOTA, enterprise firmware update abuse, and generic Android Enterprise / EMM / UEM bypasses |

- **Test:** Where the app relies on an OEM container or policy API, check whether its assumptions hold when
  that layer is absent, stubbed or downgraded. The recurring defect is treating a `null` return from the
  vendor API as "policy satisfied".
- **How:**
```bash
adb shell getprop | grep -iE 'knox|oem|miui|emui|coloros|oneui'
adb shell pm list packages | grep -iE 'knox|enterprise|kme|efota'
grep -rn 'com.samsung.android.knox\|EnterpriseDeviceManager\|KnoxContainerManager' $DEC/jadx/sources -A10
```
  Then run the app on a device where the OEM API is absent (a non-Samsung handset, or one with the Knox
  packages disabled) and observe whether it proceeds with its normal security posture.
- **Proof:** The app proceeding normally on a device where the OEM container API is stubbed or absent —
  the code path where `null` is treated as success, plus the runtime behaviour.
- **Escalation:** Enterprise fleet compromise; route platform bugs to the OEM programme and the
  null-handling bug to the app vendor. They are two reports.
- **Ruled out when:** The app fails closed when the OEM API is unavailable — it refuses to enter the
  protected mode and says so in the UI. Show the refusal on a non-OEM device.

### D25-074 · Device-admin or accessibility status obtainable without informed consent

| | |
|---|---|
| **Severity ceiling** | Critical when obtained without informed consent |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-02 remote one click |
| **Applies to** | all |
| **Requires** | — |
| **Maps to** | TapTrap (USENIX Security 2025), which explicitly lists Device Administrator status — "enables remote device wipe" — among the reachable outcomes; MASWE-0070 / MASWE-0078 (inadequate awareness/consent for privacy-relevant actions) |

- **Test:** Whether the app's own flows, or a TapTrap-style animation attack against them, can result in
  Device Administrator activation or an accessibility grant that the user did not understand they were
  giving.
- **How:**
```bash
grep -n 'BIND_DEVICE_ADMIN\|DeviceAdminReceiver\|BIND_ACCESSIBILITY_SERVICE' $DEC/apktool/AndroidManifest.xml -A6
adb shell dpm list-owners
adb shell settings get secure enabled_accessibility_services
adb shell dumpsys device_policy | head -40
adb shell dumpsys accessibility
```
  Then run the tested flow and check whether the admin or service is active afterwards.
- **Proof:** `dpm list-owners` or `dumpsys device_policy` showing the admin activated as a result of the
  tested flow, or `enabled_accessibility_services` naming the service — with a recording of the consent
  UI the user actually saw.
- **Escalation:** An enabled accessibility service reads and drives every app on the device — the
  mechanism behind Android banking-trojan overlays. → D20 for what it can read, D13 for OTP interception,
  D23 for automated confirmation. **From Android 13 (API 33) a sideloaded app cannot be granted
  accessibility without the user passing through "Allow restricted settings"** — state the OS version
  your PoC used and whether the app was Play-installed, or the severity will be argued down.
- **Ruled out when:** The app declares neither `BIND_DEVICE_ADMIN` nor `BIND_ACCESSIBILITY_SERVICE`, and
  the consent UI in the tested flow is the platform's own unmodified dialog with no overlay or animation
  covering it.

### D25-075 · Mobile foothold as an enterprise pivot

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (**P3**) for the recovered credential; the demonstrated corporate access sets the real rating |
| **Attacker** | AM-03 / AM-11 |
| **Applies to** | enterprise and BYOD apps |
| **Requires** | enterprise |
| **Maps to** | the "From APK to Golden Ticket" write-up (Pierini & Trotta, 2017) as the canonical shape of a mobile foothold leading to domain compromise |

- **Test:** For an enterprise or BYOD app, assess whether compromising the app yields corporate
  credentials, VPN profiles or certificates — and say so in the app report even when you cannot use them.
- **How:** After any D11 or D07 primitive, search the recovered data specifically:
```bash
rg -n -i 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|\.p12|\.pfx|krb5|NTLM|\\\\[A-Za-z0-9.-]+\\|vpn|ipsec|ikev2|enrol|mdm_token' loot/
adb shell run-as com.target.app find . -name '*.p12' -o -name '*.pfx' -o -name '*.conf'
adb shell dumpsys connectivity | grep -i vpn
```
- **Proof:** The recovered credential authenticating against a corporate service — **with the client's
  written permission for that step**, recorded in the RoE. Without that permission, stop at the recovered
  artefact and describe what it is for.
- **Escalation:** Domain compromise is the highest-impact framing available for an enterprise client and
  is worth writing even as a conditional: "this `.p12` is the enrolment certificate for `<realm>`".
- **Ruled out when:** The recovered data contains no corporate credential, certificate or VPN
  configuration — searched with the pattern set above, not by eye.

### D25-076 · Run the pre-severity gate against the Critical claim, not against the primitive

| | |
|---|---|
| **Severity ceiling** | Support (it governs every Critical and High in this chapter) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every Critical/High claim in this domain |
| **Requires** | — |
| **Maps to** | the bug-hunting corpus's Pre-Severity Gate and Multi-Tool Reproduction Bar |

- **Test:** This domain produces more mid-chain primitives than any other — a policy rule, a reachable
  service, an exported vendor component, a writable property — and each one *looks* like a device
  compromise. Write the draft Critical title, then substitute the Critical claim for "the bug" in five
  questions:
  1. Have I validated the **full chain** to attacker-attainable impact, or only one primitive in the
     middle? "Policy rule confirmed" is not "escalation demonstrated".
  2. What does the attacker walk away with, in one concrete sentence?
  3. Have I personally reproduced the full chain end to end **at least twice** — once during discovery,
     once for the PoC?
  4. Is there an inheritance gate, signature check, SELinux type or user-id comparison still gating the
     chain? If yes, it is not Critical — document it as "primitive present" at a lower severity.
  5. Has the programme rejected this severity class before?
- **How:** For any Critical or High, reproduce through **two independent tools with different stacks** —
  `adb shell` plus a PoC APK, or `service call` plus a reflected `IBinder.transact`; the reproduction
  commands in the report must be paste-into-shell ready.
```bash
# question 4, mechanised for this domain
sesearch -A -s untrusted_app -t <target_type> -c <class> policy.bin      # is MAC still in the way?
adb shell dumpsys package com.poc.app | sed -n '/requested permissions/,/install permissions/p'
```
- **Proof:** Two independent reproductions, and an explicit answer to question 4 quoting the `sesearch`
  or `Permission Denial` output that shows nothing is still gating the chain.
- **Escalation:** n/a — it is a kill gate. The corpus's own worked failure is instructive: a confirmed
  signature-bypass primitive was labelled Critical, a further trust check still rejected it, the chain
  never completed, and the finding had to be retracted.
- **Ruled out when:** All five answers are clean. Then file at the Critical severity and say in the report
  that you ran the gate — it reads as rigour, not padding.

### D25-077 · Body-diff, layer-ordering and server-policy-vs-state gates on privileged-surface probes

| | |
|---|---|
| **Severity ceiling** | Support (it is the false-positive kill gate for D25-020, D25-022 and D25-063) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every probe in this chapter that reads a status, a Parcel or an HTTP response |
| **Requires** | — |
| **Maps to** | the bug-hunting corpus's Body-Diff Rule, the Layer-Ordering Trap, Server-Policy-vs-State, Marker Discipline and the Statistical-Sample Rule |

- **Test:** Four false positives dominate this domain, and all four look like a bypass.
- **How:**
```bash
# 1. BODY DIFF - a byte-identical 200 is not a bypass. Applies to the companion-API diff (D25-063)
diff <(curl -s -H "Authorization: Bearer $TOK" https://api.target/v2/orders/9001) \
     <(curl -s -H "Authorization: Bearer $TOK" https://api.target/v1/orders/9001)
wc -c /tmp/baseline /tmp/test     # a 5-byte delta may be a correlation id, not content

# 2. LAYER ORDERING - a validation error does NOT prove you passed auth. Re-test with a minimal {}
curl -s -X POST https://api.target/v1/companion/sync -d '{'
# 400 {"message":"Invalid text. Only permitted characters are allowed"}  <- body parser, not auth
curl -s -X POST https://api.target/v1/companion/sync -H 'Content-Type: application/json' -d '{}'
# 401 {"message":"Not authenticated."}  <- NOW you know where the auth layer sits

# 3. SERVER POLICY vs STATE - the on-device analogue: a provider that denies EVERY uri is a
#    fixed policy, not an oracle. Query a URI you know does not exist and compare.
adb shell content query --uri content://<authority>/definitely-not-a-real-path
adb shell content query --uri content://<authority>/real-path

# 4. MARKER DISCIPLINE - write an 8+ char random marker through the surface, and search the
#    BASELINE for it first. Never use "test", "marker", "AAAA" or a dictionary word.
MARK=$(head -c16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c10); echo "$MARK"
adb shell content insert --uri content://<authority>/x --bind note:s:$MARK
adb shell content query  --uri content://<authority>/x | grep -c "$MARK"
```
  For any claim about a missing rate limit or a timing difference on a privileged surface: n ≥ 10
  interleaved trials per group in randomised order, and require the suspect group's mean to sit at least
  2σ from the control's. A single outlier is jitter.
- **Proof:** The byte-level diff, the two-request layer-ordering pair, the non-existent-URI control, and
  the baseline marker search — whichever apply — present in the report alongside the claim.
- **Escalation:** n/a — it is a correctness gate on this chapter's HTTP- and Parcel-shaped findings.
- **Ruled out when:** The bodies are byte-identical, or the well-formed `{}` request returns the auth
  error while only the malformed one returned a parser error. Write the retraction into the appendix with
  the disproving evidence rather than silently dropping the claim.

### D25-078 · Chain-filing order, evidence hygiene and retraction discipline for a device chain

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every multi-finding device or OEM engagement |
| **Requires** | — |
| **Maps to** | the bug-hunting corpus's chain-filing order, five-screenshot pattern, PII mask/leave-visible split, and retraction discipline |

- **Test:** Device chains are long — a policy rule, an exported component, a file write, an install — and
  each link usually has its own fix surface and therefore its own bounty. Filing the chain as one report
  costs you money; filing each link as a Critical costs you credibility.
- **How:** (1) Identify the highest-severity chained outcome. (2) File each primitive as a separate report
  at its **standalone** severity — typically P3/P4 — with a placeholder cross-reference line. (3) File the
  chain consumer with the full narrative at the chained severity, filling in the real primitive ids.
  (4) Edit each primitive to backfill the consumer's id.
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** - exported vendor receiver accepting SAVE_PATH (primitive)
- **submission [UUID-2]** - privapp-permissions enforcement set to `log` (primitive)
These primitives have independent fix surfaces and are filed separately per the programme's
"one fix = one bounty" rule.
```
  Do **not** paste the whole chain narrative into every primitive, claim each primitive is independently
  P1, or ask for a single combined bounty — frame the chain as a *severity amplifier*, not a merge
  request. Order of submission: primitives → consumer → clean standalone findings → scope-risky findings
  last. Never file everything in one batch within minutes; triagers read that as low-effort spam.
  **Evidence:** use the five-screenshot state-change pattern — pre-state, the bug firing, the negative
  post-state (what it looks like without the attack), the positive post-state, and the side effect. Mask
  victim PII; **leave visible** the trace ids, your own attacker uid, the package names, the SELinux
  contexts and the JSON key names — the triager needs those to reproduce.
- **Proof:** Cross-referenced ids in both directions, and an evidence bundle whose masking has not
  destroyed the reproduction path.
- **Escalation:** Two payouts instead of one.
- **Ruled out when:** There is a single finding with a single fix surface. **Do not retract a confirmed
  finding that stopped reproducing** — assume the client patched mid-engagement, and keep the timestamped
  pre-patch evidence. Retract only what you disproved, and do it in an appendix with the disproving
  evidence attached.

### D25-079 · Never instrument production hardware; record the root path you used

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | AM-12 (own device; not an attack) |
| **Applies to** | test devices only; never on client-owned production hardware without written authorisation |
| **Requires** | — |
| **Maps to** | the bug-hunting corpus's operational boundary; drozer `tools.setup.minimalsu`, `tools.setup.toybox`, `shell.exec`, `shell.start`, `shell.send`, `clean` |

- **Test:** A rooted device changes the validity of every resilience claim and most device claims. Obtain
  root explicitly and reversibly, record that you did, and state it next to every root-dependent finding.
- **How:**
```
dz> run tools.setup.minimalsu
dz> run tools.setup.toybox
dz> run shell.exec "id"
dz> run shell.start
dz> clean
```
  `tools.setup.minimalsu` "prepares 'minimal-su' binary installation on the device" — it uploads
  `minimal-su` and `install-minimal-su.sh`, `chmod 770`s the script, and instructs you to execute it
  *from root context*. It **does not gain root for you**; it stages `su` for use after a root exploit.
  `clean` removes drozer's temporary device files.
- **Proof:** `run shell.exec "id"` output showing the UID you were operating as, recorded next to every
  root-dependent finding so the reader can judge realism.
- **Escalation:** Enables `--privileged` scanner runs and `/data` inspection — and nothing else. Any
  finding that required root must say so; one that requires root **and** has no non-root path is usually
  Low unless the app's own threat model claims to defend rooted devices.
- **Ruled out when:** n/a — it is a rule, not a test. The only acceptable output is the recorded UID and
  the `clean` confirmation.

### D25-080 · The target, or an OEM preload, holds UICC carrier privileges — a privileged class the permission tables miss

| | |
|---|---|
| **Severity ceiling** | Support for the determination; High when an exported component re-delegates a carrier-privileged call |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 |
| **Applies to** | packages whose signing certificate is in the SIM's ARA-M access rules or in `carrier_config` `carrier_certificate_string_array`; carrier, MVNO and OEM telephony apps |
| **Requires** | device |
| **Maps to** | MASTG-KNOW-0017; AOSP "UICC Carrier Privileges" documentation; `TelephonyManager.hasCarrierPrivileges()` / `getCarrierPrivilegeStatus()` |
| **Record** | `logs/D25-080.txt` (the tracker and carrier_config dumps, the SIM MCC/MNC); `pocs/F-NNN/` for a re-delegated call |

- **Skip when:** no SIM is inserted in any held device (`adb -s "$SERIAL" shell getprop gsm.sim.state` prints only `ABSENT` / `NOT_READY`) — write `D25-080 blocked: no SIM`, not n/a, because the privileges are granted per inserted SIM.
- **Test:** Carrier privileges grant identifier reads (IMEI/IMSI), `iccOpenLogicalChannel`/`iccTransmitApdu`, `setLine1NumberForDisplay`, carrier-config overrides and network-selection control with no manifest permission and no runtime prompt. They are granted per inserted SIM and never appear as `granted=true`, so every permission sweep in this chapter misses them. A holder is a privileged package by another route and its exported surface re-rates like D25-009.
- **How:**
```bash
adb -s "$SERIAL" shell dumpsys phone | grep -iA6 -e 'CarrierPrivilegesTracker' -e 'UiccCarrierPrivilegeRules'   # privileged packages per subscription (the tracker on 13+, the UICC rules dump before)
adb -s "$SERIAL" shell dumpsys carrier_config | grep -iE 'carrier_certificate|privileged'
grep -rnE 'hasCarrierPrivileges|getCarrierPrivilegeStatus|iccOpenLogicalChannel|iccTransmitApdu|setLine1NumberForDisplay|CarrierConfigManager' $DEC/jadx/sources | head
# hasCarrierPrivileges() answers only for the calling app and getCarrierPrivilegeStatus(uid) is a SystemApi: a zero-permission
# probe cannot census other packages — the dumps above are the census; the probe is for exercising a holder's exported component
```
- **Proof:** `CarrierPrivilegesTracker` naming the package for the active subscription (or `hasCarrierPrivileges()==true` in its own log), plus an exported component of that package returning a restricted identifier or performing a call/SMS/APDU action for the zero-permission PoC.
- **Escalation:** → D25-009 (treat as HIGH tier), D20-052 (identifiers), D13 (SMS/call interception), D25-017 (the component mechanics).
- **Ruled out when:** no package on the image is carrier-privileged for the inserted SIM (tracker empty for every subscription) and the target never calls the carrier APIs; state the SIM MCC/MNC checked — privileges differ per SIM, so a negative on one carrier is not a negative on another.

### D25-081 · A preload's effective capability is permissions + app-ops + roles + pre-enabled services — census all four

| | |
|---|---|
| **Severity ceiling** | Support; High when a pre-granted op, role or listener is reachable through an exported component |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**, CWE-16) |
| **Attacker** | AM-03 |
| **Applies to** | OEM/carrier images; the target where it is preloaded |
| **Requires** | oem-scope, device |
| **Maps to** | MASTG-KNOW-0017; Android `AppOpsManager` / `RoleManager` documentation; D03-022 for role mechanics; MASTG-DEMO-0104 (`SYSTEM_ALERT_WINDOW`) |
| **Record** | `logs/D25-081.txt` (the four dumps and the counted app-ops sweep); `inventory/oem-capabilities.csv`: `package \| grant table \| capability \| exported component that re-delegates it` |

- **Skip when:** the Applicability probe excluded the OEM block (store build only, target not preinstalled) — write the partial-n/a note; on an OEM scope this item always runs.
- **Test:** `granted=true` (D25-009) is one of four grant tables. OEM images pre-allow app-ops (`PROJECT_MEDIA`, `SYSTEM_ALERT_WINDOW`, `GET_USAGE_STATS`, `ACCESS_RESTRICTED_SETTINGS`), pre-hold roles (gallery, dialer, SMS, assistant, wallet, notes) and pre-enable accessibility, notification-listener and device-admin components for vendor packages with no prompt; each is a capability, and an exported component in the holder re-delegates it to a zero-permission caller (the factory/diagnostic-preload shape).
- **How:**
```bash
adb -s "$SERIAL" shell dumpsys role | grep -iE 'name=|role\.|holders' | head -80     # holders per role (or: cmd role get-role-holders <role>)
adb -s "$SERIAL" shell settings get secure enabled_accessibility_services
adb -s "$SERIAL" shell settings get secure enabled_notification_listeners
adb -s "$SERIAL" shell 'dpm list-owners; dumpsys device_policy | grep -A3 Admin'
python3 - <<'PY'     # app-ops per OEM-only package, counted (D25-006)
import subprocess
S='<serial>'; pk=[l.strip() for l in open('oem-only-pkgs.txt') if l.strip()]; print('input',len(pk)); hits=[]
OPS=('PROJECT_MEDIA','SYSTEM_ALERT_WINDOW','GET_USAGE_STATS','ACCESS_RESTRICTED_SETTINGS','MANAGE_EXTERNAL_STORAGE','RECORD_AUDIO','CAMERA','ACCESS_ACCESSIBILITY')
for p in pk:
    o=subprocess.run(['adb','-s',S,'shell','appops','get',p],capture_output=True,text=True).stdout
    bad=[l.strip() for l in o.splitlines() if ':' in l and l.split(':')[0].strip() in OPS and l.split(':',1)[1].split(';')[0].strip()=='allow']   # line = "OP: mode; time=…"
    if bad: hits.append((p,bad)); print('OP',p,bad)
print('probed',len(pk),'hits',len(hits))
PY
```
- **Proof:** The op/role/listener line naming the package, plus the effect reached from the zero-permission PoC through that package's exported surface — a screen capture started under `PROJECT_MEDIA`, a notification body returned, an accessibility action performed.
- **Escalation:** → D25-009 tiers; → D25-021 when the holder is a factory/diag package; → D20 for what a listener reads; → D04 overlay items for `SYSTEM_ALERT_WINDOW`.
- **Ruled out when:** every pre-allowed op, role holder and enabled listener belongs to a package whose components are all guarded by signature permissions (verified from the PoC, D25-017), and `appops get` over the OEM-only set shows only `default`/`ignore` for the listed ops — with `probed == input`.

### D25-082 · Connected-apps / `INTERACT_ACROSS_PROFILES` — the sanctioned IPC bridge between the work and personal instances is unauthenticated

| | |
|---|---|
| **Severity ceiling** | High (work↔personal data crossing in a managed deployment) |
| **VRT** | `broken_access_control.privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (**P3**) |
| **Attacker** | AM-03 — a zero-permission app in the personal (or work) profile of the same device |
| **Applies to** | apps requesting `INTERACT_ACROSS_PROFILES` (Android 11+) or shipping `CrossProfileApps` / a connected-apps SDK, on a managed device whose DPC allow-lists them |
| **Requires** | enterprise, device |
| **Maps to** | Android `CrossProfileApps`, `DevicePolicyManager#setCrossProfilePackages`, the `INTERACT_ACROSS_PROFILES` app-op; MASWE-0018 |
| **Record** | `logs/D25-082.txt`; `pocs/F-NNN/` with the probe's bind transcript |

- **Skip when:** `grep -rlE 'INTERACT_ACROSS_PROFILES|CrossProfileApps|CrossProfileConnector|@CrossProfile' $DEC/jadx/sources $DEC/apktool/AndroidManifest.xml` is empty — write `D25-082 n/a: no cross-profile bridge in the APK`.
- **Test:** An allow-listed connected app binds its own instance in the other profile and exposes an internal binder across the boundary — the one route a plain app has across users (D25-066). The defect is the bridge service accepting any caller: exported, or `getCallingUid()` never compared by signing certificate, or the work instance trusting the personal instance for work data.
- **How:**
```bash
grep -rnE 'INTERACT_ACROSS_PROFILES|CrossProfileApps|getTargetUserProfiles|canInteractAcrossProfiles|CrossProfileConnector|@CrossProfile' $DEC/jadx/sources $DEC/apktool/AndroidManifest.xml
adb -s "$SERIAL" shell appops get $PKG INTERACT_ACROSS_PROFILES          # allow = bridge live on this device
adb -s "$SERIAL" shell dumpsys device_policy | grep -iE 'crossProfilePackages|CrossProfile'
adb -s "$SERIAL" shell dumpsys activity services $PKG | grep -E 'ConnectionRecord|user'
# bind the bridge service from the zero-permission probe in the personal profile; then from a repackaged personal instance
```
- **Proof:** The bridge service returning work-profile data (or performing a work action) to a caller that is not the app's own signed instance — `ConnectionRecord` naming the probe UID as client, and the data in the probe log.
- **Escalation:** → D25-068 (the restriction bypassed), D11 for the data, D06 for the service mechanics.
- **Ruled out when:** the bridge service is not exported and every cross-profile call checks `PackageManager.checkSignatures(getCallingUid(), Process.myUid()) == SIGNATURE_MATCH` before serving; or the app-op is `default`/`ignore` on the enrolled device (then record "bridge not enabled by DPC").

### D25-083 · Enterprise provisioning payload (QR / NFC bump / zero-touch): weak DPC binding or a reusable enrolment secret

| | |
|---|---|
| **Severity ceiling** | High (a rogue device enrolled into the fleet, or a downgraded DPC on a fleet device); Critical only if a device installs a substituted DPC from an unpinned download |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (**P3**) for a reusable enrolment token or PSK; `insecure_os_firmware.weakness_in_firmware_updates.firmware_does_not_validate_update_integrity` (**P3**, argue up) for an unbound or downgradable DPC download |
| **Attacker** | AM-06 network attacker during enrolment; AM-11 physical at a factory-reset device, holding a copy of the payload (QR codes are routinely printed or posted) |
| **Applies to** | fleets provisioned by QR, NFC bump or zero-touch; the client's DPC |
| **Requires** | enterprise |
| **Maps to** | Android `DevicePolicyManager` `EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION` / `_PACKAGE_CHECKSUM` / `_SIGNATURE_CHECKSUM`, `EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE`, `EXTRA_PROVISIONING_WIFI_PASSWORD`; the Android Enterprise provisioning guide |
| **Record** | `logs/D25-083.txt` (the decoded payload, redacted of the Wi-Fi PSK and the token); `pocs/F-NNN/` with the enrolment transcript |

- **Skip when:** the client provisions no device (no QR, NFC or zero-touch payload exists; BYOD work profile only) — write `D25-083 n/a: no provisioning payload in scope`.
- **Test:** The payload names where the DPC is downloaded from and how it is verified, and usually carries secrets. Current ManagedProvisioning refuses a download location that has neither `…_PACKAGE_CHECKSUM` nor `…_SIGNATURE_CHECKSUM` — confirm that on the test unit instead of assuming it, because a device that provisions from an unpinned download hands device owner to whoever serves the APK (the Critical). The realistic defects are weaker and common: (1) `SIGNATURE_CHECKSUM` alone pins the signer, not the build, so an `http://` or attacker-reachable download location can serve an **older, vulnerable** DPC signed by the same key; (2) the enrolment token in `…_ADMIN_EXTRAS_BUNDLE` is reusable, unexpiring or not device-bound, so anyone holding the payload enrols a rogue device and receives the fleet's managed configuration; (3) the enrolment Wi-Fi PSK travels in the clear inside the payload.
- **How:**
```bash
zbarimg -q --raw enrol.png | jq .      # or decode the NFC NDEF record / the zero-touch configuration JSON
# inspect: android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION (scheme, host),
#   PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM (pins the file) vs PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM (pins only the signer),
#   PROVISIONING_ADMIN_EXTRAS_BUNDLE (the enrolment token: single-use? expiry? device-bound?), PROVISIONING_WIFI_PASSWORD,
#   PROVISIONING_SKIP_ENCRYPTION, PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED
grep -rnE 'PROVISIONING_DEVICE_ADMIN_(PACKAGE|SIGNATURE)_CHECKSUM|DOWNLOAD_LOCATION|ADMIN_EXTRAS_BUNDLE' $DEC/jadx/sources provisioning-docs/
# on a factory-reset test unit, with the client's written permission: enrol a second unit with the same payload (token reuse);
# where only the signer is pinned, serve an older signed DPC build from the download location (downgrade)
adb -s "$SERIAL" logcat -d | grep -iE 'ManagedProvisioning|checksum|DownloadPackage|VerifyPackage'
adb -s "$SERIAL" shell dpm list-owners
```
- **Proof:** The decoded payload showing the weakness, plus one of: a second unit enrolled with the same token and receiving the managed configuration (`dpm list-owners` naming the DPC on both); an older DPC build installed from your host under a signature-only pin (`dumpsys package <dpc> | grep versionName`); or — the Critical — a unit provisioning from an unpinned download, with the logcat.
- **Escalation:** device owner = every policy in D25-068..073 is the attacker's; → D25-075 enterprise pivot; the Wi-Fi PSK in the payload → D14 (a network position on the enrolment SSID).
- **Ruled out when:** the payload pins the file with `…_PACKAGE_CHECKSUM` (or the unit refuses an unpinned or substituted download — the ManagedProvisioning checksum failure in logcat), the download URL is https on a client-controlled host, and the second enrolment with the same token is refused — quote the refusal.

### D25-084 · Advanced Protection Mode (Android 16) in the posture block, and the app's handling of it

| | |
|---|---|
| **Severity ceiling** | Support (posture); Medium when the app claims a mode-dependent control it does not read from the API |
| **VRT** | n/a for the record; `insecure_os_firmware.poorly_configured_operating_system_security` (**VARIES**) for a vector still open with the mode on (OEM VRP) |
| **Attacker** | AM-12 for the record; AM-10 / AM-11 / AM-03 for the vectors it closes |
| **Applies to** | Android 16+ (API 36) devices |
| **Requires** | device, api>=36 |
| **Maps to** | Android 16 Advanced Protection (`android.security.advancedprotection.AdvancedProtectionManager`, `isAdvancedProtectionEnabled()`, `registerAdvancedProtectionCallback()`): blocks unknown-source installs and USB data while locked, disables 2G, enables MTE where supported |
| **Record** | `logs/D25-084.txt` (the mode state beside every physical-vector finding) |

- **Skip when:** `adb -s "$SERIAL" shell getprop ro.build.version.sdk` prints less than 36 on every held device — write `Advanced Protection: n/a, API <36`.
- **Test:** With the mode on, locked-device USB data (D25-048/052) and sideload-dependent AM-03 proofs (`adb install` of the probe) change; record the state with every physical-vector finding. Separately, an app offering to honour the mode must read it from the API, not infer it.
- **How:**
```bash
adb -s "$SERIAL" shell getprop ro.build.version.sdk                          # >= 36 or record n/a
adb -s "$SERIAL" shell 'settings list secure | grep -i advanced_protection; dumpsys advanced_protection 2>/dev/null | head'   # discover the OEM's flag/service name
grep -rnE 'AdvancedProtectionManager|isAdvancedProtectionEnabled|AdvancedProtectionCallback' $DEC/jadx/sources
# from the probe (declares the normal permission QUERY_ADVANCED_PROTECTION_MODE): AdvancedProtectionManager.isAdvancedProtectionEnabled() -> log; toggle the mode in Settings > Security and re-run D25-043, D25-048 and an `adb install` of the probe
```
- **Proof:** The mode state in the posture block; for a finding: the app asserting a mode-dependent control while `isAdvancedProtectionEnabled()` returned false, or a USB/sideload vector still open with the mode on (route that to the OEM VRP).
- **Escalation:** → D25-004 posture; → D21 if the app's risk engine keys on it; → D25-048/052 re-run under both states.
- **Ruled out when:** device < API 36 (recorded as above), or the state is recorded and every physical-vector finding names the state it was produced in.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The bootloader on my test device is unlocked / `verifiedbootstate=orange`" | You unlocked it. AM-12 is not an attacker. Samsung lists "reports requiring enabling Developer Mode persistently on the device" as an explicit downgrade factor | The **client's own deployment** requires an unlocked bootloader or a disabled Verified Boot to function (D25-042), or a production retail unit ships orange |
| "The device runs an old kernel / the security patch level is behind" | Version disclosure with no demonstrated reachability. Every vendor excludes "vulnerabilities that do not work on the latest available operating system version" | A specific CVE in that kernel, reached from an app UID, with the reachability shown — then it is D16 with D25 context |
| "SELinux is permissive" — on an emulator or a `userdebug` build | Expected on non-`user` builds. `permissive=1` on `userdebug` is the platform working as designed | A permissive domain on a **`user` build** of a retail device (D25-028), with a `neverallow` cited and the impact exercised |
| "`adb shell service call <vendor> N` returned data" | The `shell` UID has permissions and an SELinux domain no app has. The corpus is explicit: always re-prove from an ordinary third-party app UID | The same transaction succeeding from a zero-permission PoC APK, with `ps -AZ` showing it in `untrusted_app_NN` (D25-005) |
| "`sesearch` shows an OEM `allow` rule that AOSP does not have" | A policy rule is a capability, not a bug. An unexercised `allow` line is a hardening note | An app that uses the rule, fired, with the effect demonstrated (D25-027) |
| "There is an exported component in a preinstalled OEM app" | Exported is intended behaviour; the finding is the unauthorised access it grants | The component driven from a zero-permission app to produce a privileged effect (D25-017) |
| "I found a root exploit / I rooted the device" | Rooting your own device is not an attack on the app, and most programmes exclude root-required findings outright | The root was obtained **from an app UID** with no user interaction on a stock, locked, enforcing retail device |
| "The app's data is readable once I have root" | Root defeats the sandbox by definition. Xiaomi, Grab and Spotify all exclude "sensitive data stored in the app private directory" | A non-root reader — a debuggable build (D25-014), a cross-user path (D25-066), or a backup/extraction path |
| "`allowBackup="true"` on an OEM build" | P5 everywhere and excluded by name at Google and Xiaomi; VRT `mobile_security_misconfiguration.auto_backup_allowed_by_default` = **P5** with a physical-vector, high-privilege CVSS baseline; and from Android 12 (API 31) `adb backup` includes only debuggable apps regardless of `allowBackup` | The credential you actually extracted from the backup and replayed (D11/D13) |
| "Firmware is not encrypted" | VRT `insecure_os_firmware.weakness_in_firmware_updates.firmware_is_not_encrypted` = **P5**. Obscurity was never the control | The update is not *integrity*-validated (D25-040), which is a different node at P3 and argues upward |
| "The OEM image contains 40 preinstalled apps with dangerous permissions" | An inventory is not a finding, and the permission set is the OEM's product decision | One of them exporting a component that re-delegates the permission to a zero-permission caller (D25-009, D25-017) |
| "This OEM bug is Critical" — filed against the app client | Wrong programme. It is the OEM's bug and the app client cannot fix it | Two artefacts: an environmental-risk note to the app client, and a separate report to the OEM's VRP (D25-001) |
| "Malformed USB/NFC/BLE input crashes the app" | VRT `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**; Xiaomi, Grab and Spotify all exclude crash-only reports; "a valid exploit must achieve arbitrary code execution, not just trigger an application crash" | A controlled write with an attacker-controlled fault address, quoted from the tombstone (D25-049, D16) — or a persistent DoS requiring a factory reset |
| "A companion endpoint is on `/v1` while the web app uses `/v3`" | A version difference alone is Informational. The bug is the delta, not the number | A behavioural regression on the older path — weaker auth, no throttling, wider field set — shown side by side (D25-063) |
| "The app has no jailbreak/root detection" and "the device has no lock screen set" | `lack_of_binary_hardening.lack_of_jailbreak_detection` = **P5**; MASTG-TEST-0247 itself notes apps "cannot force users to enable biometrics at the system level, only enforce their use within the app" | The app stores auth-bound keys and never calls `isDeviceSecure()`/`canAuthenticate()`, on a financial or health app where a stolen unlocked device yields the account (MASWE-0017) — Medium, not High |
| "The device exposes MTP when plugged in" | MTP is the modern default and is gated behind unlock on current builds | A data function reachable **while locked** that reaches a parser (D25-048, D25-052) |
| "Work data can be pasted into the personal profile" | Cross-profile sharing is intended unless a restriction is configured | `DISALLOW_CROSS_PROFILE_COPY_PASTE` explicitly configured and the paste still succeeding (D25-068) |

## Cross-surface joins

- **`privapp-permissions` enforcement (D25-010) × an exported component in the same package (D04–D08).**
  Nobody reads the allowlist file and nobody re-rates an exported activity by the *permissions its
  package actually holds*. The join is: `ro.control_privapp_permissions=log` means a privileged permission
  was granted that the platform itself flagged as un-allowlisted, and the exported activity in that
  package is now the delegation route to it. Neither half is a finding alone; together they are the OEM
  escalation class.
- **`sharedUserId` (D25-012) × the sibling's exported surface (D06/D07).** Reviewers audit the target's
  own components and stop. The weakest app in the UID group defines the security of all of them — so the
  right question is not "is *this* app's provider exported" but "is any provider in this UID exported",
  and the answer is frequently yes in a package nobody in the engagement has opened. This is exactly the
  Samsung SecSettings shape.
- **USB `device_filter` auto-launch (D25-049) × the native parser behind it (D16).** USB is reviewed as a
  permissions question ("does the app ask for USB access?") and native code is reviewed as a reachability
  question ("can an attacker reach this parser?"). The join answers both at once: the platform *grants*
  USB access automatically on filter match, so an attacker-built gadget with the declared VID/PID feeds
  attacker-controlled bytes straight into the app's native parser with no network, no app install and no
  permission prompt.
- **Wear OS path routing (D25-062) × the authentication state machine (D13).** Auth reviewers test the
  login screen, the OTP endpoint and the biometric gate. Nobody tests the `/auth`-prefixed Data Layer
  path, because it is not a screen and not an HTTP endpoint. A phone app that enters an authenticated
  state because a *message path* said so is an authentication bypass with no credential involved at all.
- **Android Auto `ALLOW_ALL_HOSTS_VALIDATOR` (D25-061) × the account data the car templates render
  (D15/D20).** The Auto integration is reviewed, if at all, as a UI feature. Bind it from an unprivileged
  app and every template the app renders — trips, saved places, vehicle, payment method — is readable
  without the phone UI, without the lock screen, and without a single permission.
- **Cross-user reach (D25-066) × the `getCallingUid()` guard (D03/D06).** Every IPC reviewer checks that
  the service interrogates the caller. Almost nobody checks that it compares
  `UserHandle.getUserId(uid)` — so a *clone of the same app* in a work profile or a Private Space passes
  a same-signature or same-UID check trivially. The join turns a correct-looking guard into a
  cross-account data path.
- **Preinstalled-app privilege (D25-008/D25-009) × the logcat leak (D20).** The standard closure for a
  logcat finding is "requires a privileged permission". Enumerating the actual `READ_LOGS` holders on the
  client's real device demographic (D25-015) converts that closure into a named attacker, which is the
  single highest-leverage rewrite available for a whole class of D20 findings.
- **Dialler secret code (D25-045) × the staging-backend switch (D14/D21).** Secret codes are catalogued as
  a curiosity and pinning is tested as a transport question. A code that flips the app to a staging
  backend or disables pinning is a complete MitM primitive that requires neither a proxy CA nor root — and
  it can be fired as a broadcast, removing the physical precondition entirely.
- **Instant-app remnants (D25-064) × the deep links that used to launch them (D09).** The client is dead,
  so nobody looks. But the installed app still declares the URL patterns the instant experience used, and
  those handlers were written for a permission-light, unauthenticated context. A live App Link into an
  instant-era handler is an auth-skip nobody has tested since 2021.
- **Device-policy restriction (D25-069) × the app's own screen-capture defences (D20).** The MDM
  reviewer tests whether the policy is set; the app reviewer tests whether `FLAG_SECURE` is present. The
  join is the app rendering a payment or PIN screen that honours neither, in a managed profile where the
  client believes screen capture is disabled fleet-wide.

## Sources

- **Senior-researcher corpus (local):** the device-attack-surface taxonomy (remote / network-adjacent /
  local / physical) and the four-property surface ranking; `canhazaxs` local-surface enumeration with the
  victim UID and group set; `/proc/net/unix` abstract-namespace and netlink forging notes; the USB mode
  enumeration (`/init.*.usb.rc`, `/sys/class/android_usb/android0/`, the Multifunction Composite Gadget
  and the pre-4.2.2 unauthenticated-ADB LEGACY note); the RF-proximity range table (baseband, Wi-Fi,
  Bluetooth profiles, NFC <8 cm with no-interaction dispatch, GPS, QR) and the hotspot-materialised
  DNS/DHCP services on `192.168.43.1`; the AOSP-diff method for OEM builds; the three-layer sandbox table
  (DAC / type enforcement / MLS categories) and the "name the layer that stopped you" discipline; the
  SELinux downgrade discipline with the exact `sesearch` invocations; the vendor sepolicy diff
  (`comm -23` over `sesearch -A -s untrusted_app`), `sepolicy-analyze … permissive`, `seinfo`, and the
  `neverallow`/CTS framing; `seapp_contexts` and `mac_permissions.xml` as the domain-assignment table;
  AVC denials as a live oracle with the `dontaudit` and `setenforce 0` traps; the Android-versus-classic-Flask
  divergence table; `untrusted_app_NN` versioned domains as an API gate; the kernel networking
  enumeration (`/proc/net/ptype`, `/proc/net/protocols`); the debuggable-package device sweep; the
  Conscrypt-APEX trust-store note at API 34+.
- **AOSP / Android developer documentation:** Application Sandbox and privileged versus non-privileged app
  domains; System API availability to partners and OEMs; Binder IPC and `/dev/binder`; AIDL for HALs and
  `service_contexts`; AIDL fuzzing; Verified Boot (hardware root of trust, dm-verity from 4.4, FEC in 7.0,
  AVB footers and rollback protection in 8.0); kernel documentation (ACK 5.10+ GKI, KMI, vendor
  modules/DLKMs) and the security-enhancements list (seccomp for untrusted apps in Android 8; hardened
  usercopy, KASLR, PAN emulation, read-only-after-init; HWASan/BoundSan/IntSan/XOM/Scudo/ShadowCallStack
  in Android 10); system properties (`ro.`/`persist.`/vendor prefixes and `property_contexts` types);
  the privileged-permission allowlist (`ro.control_privapp_permissions`, per-partition allowlists,
  boot-blocking from Android 9) and the Android 15 signature-permission allowlist; SELinux concepts and
  device-policy documentation (the 5–10% device-specific policy model, Treble's boot-time policy
  assembly); APEX and Conscrypt modular-system documentation; USB host (`<usb-device vendor-id
  product-id>` and the automatic-permission wording) and USB accessory (`manufacturer`/`model`/`version`
  and `openAccessory()` → `FileInputStream(fd)`); NFC dispatch priority, AAR precedence and the tech-list
  XML; BLE overview (the "accessible to **all** apps" caution and the app-layer-security requirement);
  Android for Cars (`createHostValidator()`, `ALLOW_ALL_HOSTS_VALIDATOR`); Wear Data Layer and Messages
  (`DataClient`, `MessageClient`, `WearableListenerService`, `sendMessage(nodeId, path, data)`); Nearby
  Connections (`getAuthenticationDigits()` and the "connections established without authentication are
  insecure" wording); Google Play Instant discontinuation and `InstantApps.isInstantApp()`; Android 13,
  14, 15 and 16 behaviour-change pages (`BluetoothAdapter#enable()`/`#disable()` returning `false` with
  Device Owner / Profile Owner / system-app exemptions; `killBackgroundProcesses()` scoped to self;
  `ACTION_CLOSE_SYSTEM_DIALOGS` `SecurityException` at targetSdk 31; private space; Local Network
  Protection and `RESTRICT_LOCAL_NETWORK`; `CompanionDeviceManager#removeBond(int)`; the
  `RESULT_USER_REJECTED` change); the `android-debuggable`, test-and-debug-features,
  `create-package-context` and access-control-to-exported-components risk pages; ML Kit barcode scanning
  (`Barcode.getWifi()`).
- **OWASP MASTG / MASVS / MASWE:** MASTG-KNOW-0017 (the Uraniborg-derived preloaded-app permission risk
  table, quoted in full), MASTG-KNOW-0020 (Binder, `service list`, and the `adb shell`-is-not-an-app
  caveat), MASTG-KNOW-0049, MASTG-TOOL-0004; MASTG-TEST-0203 (the `READ_LOGS`-on-preloaded-apps threat
  model, verbatim), MASTG-TEST-0247 and MASTG-TEST-0249 (device secure lock), MASTG-TEST-0364/0365/0366;
  MASWE-0005, MASWE-0017, MASWE-0018, MASWE-0026, MASWE-0029, MASWE-0032, MASWE-0050, MASWE-0070,
  MASWE-0078; MASVS-PLATFORM, MASVS-STORAGE-1, MASVS-STORAGE-2, MASVS-CRYPTO-2.
- **Bugcrowd VRT (release 2026-07-08):** the whole `insecure_os_firmware` branch with its priorities and
  CVSS baselines — `hardcoded_password|privileged_user` P1, `|non_privileged_user` P2,
  `over_permissioned_credentials_on_storage` P2, `shared_credentials_on_storage` P3,
  `local_administrator_on_default_environment` P2, `command_injection` P1,
  `weakness_in_firmware_updates|firmware_does_not_validate_update_integrity` P3 (with the `PR:H/UI:R`
  baseline to argue against), `|firmware_is_not_encrypted` P5, `kiosk_escape_or_breakout`,
  `poorly_configured_operating_system_security`, `poorly_configured_disk_encryption`,
  `data_not_encrypted_at_rest|sensitive`, `recovery_of_disk_contains_sensitive_material`;
  `broken_access_control|privilege_escalation`, `|exposed_sensitive_android_intent`, the IDOR leaves;
  `physical_security_issues|bypass_of_physical_access_control`;
  `broken_authentication_and_session_management|authentication_bypass` P1;
  `sensitive_data_exposure|disclosure_of_secrets|*`; and the P5 mobile branch used throughout the
  Graveyard.
- **MITRE ATT&CK Mobile:** T1458 Replication Through Removable Media (USB charging stations and side-load
  installs; DualToy) with mitigation M1012; T1398 Boot or Logon Initialization Scripts (OldBoot altering
  boot-partition init scripts; FlexiSpy installing hooks into `/system/su.d`); T1645 Compromise Client
  Software Binary; T1625.001 System Runtime API Hijacking (Zen S0494 replacing `framework.jar`);
  T1474.002 and T1474.003 Compromise Hardware Supply Chain (the Allwinner backdoored kernel);
  mitigations M1001, M1002 Attestation and M1004 System Partition Integrity.
- **OEM and vendor research:** Oversecured — "Discovering vendor-specific vulnerabilities in Android"
  (the `semIsBackupEnabled()`-beside-`isBackupEnabled()` pattern and the `IPowerManager.reboot()`
  contrast; the Samsung `StorageManagerService` reboot broadcast
  `com.samsung.intent.action.RESTART_OF_SDCARDBADREMOVED_HASAPK`), "Two weeks of securing Samsung devices"
  Parts 1 and 2 (`DualDARInitService` CVE-2021-25388/SVE-2021-20636, `com.android.managedprovisioning`
  CVE-2021-25356/SVE-2021-20733, `KnoxSettingCheckLockTypeActivity` CVE-2021-25391/SVE-2021-20500,
  `com.android.settings` CVE-2021-25393/SVE-2021-20731, `NotificationBnRReceiver`
  CVE-2021-25392/SVE-2021-20690, `PhotoringReceiver` CVE-2021-25397/SVE-2021-20716,
  `PermissionsRequestActivity` CVE-2021-25390/SVE-2021-20724), "176 vulnerabilities in Samsung
  preinstalled apps" ($200k+, 100M+ devices; `com.sec.factory.camera`, `WifiServiceImpl.semAddPublicDnsAddr()`,
  themecenter ThemeManager path traversal, `com.samsung.android.oneconnect` McsBridge,
  DualOutFocusViewer `System.load()`, `com.sec.android.app.dexonpc`; SVE-2023-1112, SVE-2023-0760,
  SVE-2023-0928), "20 Security Issues Found in Xiaomi Devices", and the arbitrary-file-theft checklist
  (local web servers and the NanoHTTPD `new File(context.getCacheDir(), path)` shape). Conference index:
  "Still Vulnerable Out of the Box: Prepaid Android Carrier Devices" (DEF CON 31), "Securing the System:
  Reversing Android Pre-Installed Apps" (Black Hat USA 2019). Current CVEs: CVE-2026-20983,
  CVE-2026-21059, CVE-2026-20990, CVE-2025-10184, CVE-2025-12080, CVE-2023-21257, CVE-2018-9445,
  CVE-2018-9488, CVE-2016-10277, CVE-2015-7889, CVE-2015-7893; CWE-926.
- **Mobile Hacking Lab:** "Rediscovering a 0-Click MMS Vulnerability in Samsung S10 (CVE-2020-8899)" —
  firmware extraction to a rootfs, `QEMU_LD_PREFIX`/`QEMU_SET_ENV`, `AFL_INST_LIBS=1 afl-fuzz -Q`, first
  matching crash at 47 minutes and 674 crashes collected, and the `dlsym`-brittleness lesson with the
  stable-C-ABI shim (`_ZN6SkData14MakeFromMallocEPKvm`); "Porting ghostlock (CVE-2026-43499) to the
  Samsung Galaxy A17" — BTF-derived struct offsets validated 12/12 against the extracted image, the QEMU
  boot harness at ~30 s per cycle, and Samsung KDP at EL2 defeating the classic `cred`-patch endgame
  ("20+ clean runs with verified-correct candidates, zero creds landed") with the usermode-helper
  workqueue alternative; the mitigation-identification habit (NX/UXN/PXN, KDP, DEFEX `exit 137`);
  "Kernel Fuzzing in Userspace with LKL" as the kernel-scope note.
- **HackTricks and community:** the OEM-ROM-add-on provider checklist item, the pre-installed privileged
  TV-box implant research (Bitsight Fuyao Enterprise) with the five prioritised checks and the expired
  management-infrastructure escalation, the Android Enterprise work-profile bypass (CVE-2023-21257
  `INSTALL_ALL_USERS` + `versionCode` precedence), the physical-attacks page (BFU/AFU, `spblob`,
  `/data/system_ce/0/snapshots`, the Gatekeeper → KeyMint → Synthetic Password → StrongBox/Weaver chain,
  the AFU USB kernel surface, and the 69-byte `hw_auth_token_t` biometric-TA forgery patterns from the
  DarkNavy research; the iOS parallels checkm8 and CVE-2025-24200), the HCE relay shape, and the drozer
  module set (`information.deviceinfo`, `scanner.misc.secretcodes`, `scanner.misc.sflagbinaries`,
  `app.package.shareduid`, `app.package.debuggable`, `exploit.jdwp.check`, `tools.setup.minimalsu`,
  `shell.exec`, `clean`). TapTrap (USENIX Security 2025) for the device-admin consent outcome. MobSF
  `dialer_code_found`. "From APK to Golden Ticket" (Pierini & Trotta, 2017) for the enterprise pivot.
- **Programme economics and disclosed reports:** Android & Google Devices in-scope impact statements
  ("Multi-User & Private Space: Cross-user sensitive data access, or unlocking Private Space without the
  designated lock factor"; "Enterprise Bypasses: Unauthorized removal of the Device Policy Controller
  (DPC)"; "Destructive Remote DoS"; the software-based lock-screen bypass tier); Google Mobile VRP
  routing and non-qualifying list (secondary lock-screen bypasses, hardcoded API keys, Strandhogg and
  tapjacking variants); Samsung Mobile Security Rewards risk classification and its ten downgrade factors
  (developer mode, artificial reachability, complexity, limited model range, existing mitigations,
  crash-without-exploitability); Xiaomi's HackerOne policy tiers and mobile out-of-scope list; the
  physical/MitM scope split across PayPal, Uber, Reddit, Grab and HackerOne Core Ineligible; H1 #292761
  (VK PlayerProxy, $700) and #258460 (Quora, and the researcher's own `visibleToInstantApps` correction).
- **Bug-hunting corpus (cross-domain discipline applied here):** the Layer-Ordering Trap (re-test with a
  minimal well-formed `{}` before claiming an auth bypass), the Body-Diff Rule (a byte-identical 200 is
  not a bypass), Marker Discipline (8+ character random markers, search the baseline first),
  Server-Policy-vs-State, the Statistical-Sample Rule (n ≥ 10 interleaved, ≥ 2σ), the Shell-Loop Ban
  (count your results), the shadow/zombie-API behavioural-diff method as the mobile-to-backend bridge
  applied to companion surfaces, the Multi-Tool Reproduction Bar for Critical/High, the Pre-Severity Gate
  run against the Critical claim, the five-screenshot state-change pattern and the PII mask/leave-visible
  split, retraction-appendix discipline and its inversion for client-patched findings, and chain-filing
  order (primitives first, consumer second, backfill the ids).
