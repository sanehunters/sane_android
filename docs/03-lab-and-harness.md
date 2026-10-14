# Lab & Harness

> Phase 1. Build this once, verify it works, and never debug it during an engagement.
>
> Most "the app is pinned" conclusions are wrong. They are a broken CA install. This document exists
> mainly so that never happens to you.

---

## 1. What you actually need

| Role | Device | Why |
|---|---|---|
| **Primary analysis** | Rooted AVD, `userdebug`, x86_64 or arm64 | Writable system, Frida server, sandbox inspection |
| **Reality check** | Physical device, stock, **non-rooted** | Production behaviour, hardware Keystore, real attestation |
| **Attacker** | Either | Runs your zero-permission attacker app |

You need **both** the rooted and the stock device. Several claims are only true on one of them:

- `KeyInfo.isInsideSecureHardware() == false` is an **emulator artefact**. A physical device reports
  TrustedEnvironment. Reporting that as a finding discredits the submission.
- A key with `setUserAuthenticationRequired(true)` cannot be generated without a secure lockscreen. On a
  fresh emulator with no PIN, generation failure is expected, not a bug.
- Production `user`-build Play images cannot be rooted. "The production build is rootable" means you are
  not testing a production image.

---

## 2. Toolchain

`bash scripts/doctor.sh` prints what is present and what is missing; install only what it names. Host-neutral:

```bash
# Android SDK (Linux default ~/Android/Sdk; macOS ~/Library/Android/sdk) — one variable, used by every script here
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
sdkmanager "platform-tools" "build-tools;35.0.0" "emulator" "cmdline-tools;latest"
export PATH="$SDK/platform-tools:$SDK/build-tools/35.0.0:$SDK/cmdline-tools/latest/bin:$SDK/emulator:$PATH"
# aapt2 and apksigner ship in build-tools (there is no separate package for them in any package manager)

# Decompilation / static: package manager where one exists (apt/brew: jadx apktool), else the GitHub release zips
#   jadx    https://github.com/skylot/jadx/releases        -> unzip, put bin/ on PATH
#   apktool https://github.com/iBotPeaches/Apktool/releases -> the wrapper script + apktool.jar on PATH
pipx install apkleaks

# Instrumentation (pipx keeps each tool's own frida version apart; objection pins ITS frida — check it against
# the frida-server you push, D26-010: `pipx runpip objection show frida`)
pipx install frida-tools objection
# drozer: the Android tool is WithSecureLabs/drozer.
#   NOTE: github.com/dozermapper/dozer is a Java bean-mapping library and is NOT this tool.
pipx install drozer

# MitM
pipx install mitmproxy
```

Validity note: several tools that appear in older checklists are dead or degraded. `Xposed` is superseded
by `LSPosed`; `Android-SSL-TrustKiller` and `JustTrustMe` predate modern pinning; `adb backup` is gutted
on API 31+. Do not read their silence as a negative result.

---

## 3. The rooted-emulator + system-CA + proxy harness

This is the step sequence that actually works on current Android. **Step 3 is the one everyone skips.**

### Step 0 — Create a writable-system AVD

Use a **Google APIs** image, never a **Google Play** image. Play images are `user` builds and cannot be
rooted.

```bash
sdkmanager "system-images;android-34;google_apis;arm64-v8a"
avdmanager create avd -n pentest34 -k "system-images;android-34;google_apis;arm64-v8a" --device pixel_6
emulator -avd pentest34 -writable-system -no-snapshot-load -http-proxy 127.0.0.1:8080

# Once per AVD: a SECURE lockscreen (a credential, not a swipe) — auth-bound Keystore keys cannot be generated
# without one, and §7 check 5 verifies this property, not whether a keyguard happens to be on screen.
adb shell locksettings set-pin 1234
adb shell locksettings get-disabled        # expect: false
```
Record the PIN in `engagement.json.lab.pin` so a later session can unlock (`adb shell input text 1234; adb shell input keyevent 66`).

### Step 1 — mitmproxy, and its CA in Android's system format (the push is API ≤ 33 only)

Android's system store keys certificates by the hash of their subject, with a `.0` suffix.

```bash
mitmproxy --listen-port 8080   # once, to generate ~/.mitmproxy/mitmproxy-ca-cert.pem

HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem "${HASH}.0"

# API <= 33 only. On API 34+ (the AVD from Step 0) this directory is IGNORED at runtime: skip to Step 2.
adb root && adb remount          # first use on a fresh -writable-system AVD may answer "reboot required": reboot, repeat
adb push "${HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
```

### Step 2 — API 34+ only: the trust store moved

On **API 34 and later** the CA store lives in the updatable **Conscrypt APEX**, and
`/system/etc/security/cacerts` is **ignored at runtime**.

The push and the `chmod` in Step 1 both **succeed**, and nothing is trusted. Operators then see TLS
failures on every host and conclude the app is pinned. It is not.

This is the one canonical recipe (D26-005 is the same text; docs/01 points here). Three details are load-bearing:
every remote glob is **quoted** (an unquoted `/apex/.../cacerts/*` is expanded by *your* shell — under zsh it
aborts with `no matches found` and the overlay is built empty); the files are **relabelled** (a file pushed under
`/data/local/tmp` carries `shell_data_file`, which app domains cannot read under enforcing SELinux — the bind
"succeeds" and TLS still fails everywhere); and the overlay is a **tmpfs**, so the labels stick.

```bash
# API 34+ : build the overlay (as root: adb root on an AVD, su -c on a Magisk phone)
adb shell 'mkdir -p /data/local/tmp/cacerts && cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/'
adb push "${HASH}.0" /data/local/tmp/cacerts/
adb shell 'ls /data/local/tmp/cacerts | wc -l'       # expect > 100: the system roots PLUS yours; a small number = empty overlay, stop
adb shell 'mount -t tmpfs tmpfs /system/etc/security/cacerts &&
  cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/ &&
  chown root:root /system/etc/security/cacerts/* && chmod 644 /system/etc/security/cacerts/* &&
  (chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/* 2>/dev/null ||
   chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*)'
adb shell 'mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts'   # the shell's namespace only
```

### Step 3 — The step everyone misses: the zygote mount namespaces

App processes **fork from zygote and inherit zygote's mount namespace**. A bind mount made in the shell's
namespace is invisible to every app. The bind must exist in the namespace of **every zygote** — `zygote`,
`zygote64` **and `webview_zygote`** (WebView renderers fork from it) — and in every app process that is
**already running** (it keeps the old store until restarted).

```bash
# Bind in every zygote's namespace (not PID 1: init is optional and only matters for a `stop && start` soft reboot)
adb shell 'for Z in $(pidof zygote zygote64 webview_zygote); do
  nsenter --mount=/proc/$Z/ns/mnt -- mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; done'
# ...and in every already-running process (errors for kernel threads are expected and silenced)
adb shell 'for P in $(ls /proc | grep -E "^[0-9]+$"); do
  nsenter --mount=/proc/$P/ns/mnt -- mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null; done'
adb shell am force-stop com.target.app

# Verify from the TARGET's namespace, never from the shell's (D26-006) — this is the only proof that counts
adb shell am start -W com.target.app/.MainActivity >/dev/null; PID=$(adb shell pidof com.target.app | tr -d '\r')
adb shell "nsenter --mount=/proc/$PID/ns/mnt -- ls /apex/com.android.conscrypt/cacerts" | grep -c "$HASH"   # expect 1
adb shell dmesg | grep -i 'avc:.*cacerts'      # negative control: any denial here = the relabel did not take
```

Use `--rbind` when `/system/etc/security/cacerts` already carries nested mounts (Magisk modules). **Runtime only:**
every bind is lost on reboot and on a snapshot resume — redo Steps 2–3 after every boot, never resume from a
snapshot taken before them, and run the D26-006 check at the start of each session.

**Symptom of skipping this step:** `Client TLS handshake failed ... does not trust the proxy's certificate`
for **every single host**, including hosts the app has no reason to pin.

### Step 4 — Route traffic

```bash
adb shell settings put global http_proxy 127.0.0.1:8080
# or launch the emulator with -http-proxy as in Step 0
```

The proxy setting is honoured only by proxy-aware clients (OkHttp, HttpURLConnection, WebView). A Flutter/dart:io,
native-socket, gRPC or HTTP/3 client ignores it and shows **no flow at all** — §4 cause 6 has the transparent recipe.

### Step 5 — Install the full APK set

Miss a config split and you miss code and native libraries.

```bash
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk split_config.en.apk
```

---

## 4. Confirming pinning — the discipline

> **Never conclude "the app is pinned" because MitM failed.**

Failure to intercept has at least six causes, and only one of them is pinning:

1. The CA is in `/system/etc/security/cacerts` on API 34+, which is ignored (§3 Step 2).
2. The bind mount is missing from a zygote's namespace or from the already-running process (§3 Step 3).
3. The app was not restarted after the mount, or the device rebooted/resumed a snapshot and the bind is gone.
4. The app uses a framework with its own trust store — **Flutter uses Dart's own BoringSSL roots and
   ignores the Android store entirely**. So does any app statically linking its own TLS.
5. The app genuinely pins.
6. **The client never uses the proxy.** Distinguishing symptom: causes 1–5 show `Client TLS handshake failed` in
   mitmproxy (a handshake reached it); cause 6 shows **no flow at all** while the app clearly talks to the network.
   Flutter/dart:io, native sockets, gRPC and QUIC/HTTP3 are proxy-unaware. Go transparent, and prove the app tried:

   ```bash
   # transparent: redirect TCP/443 from the device to mitmproxy; block UDP/443 so HTTP/3 falls back to TCP
   HOST=10.0.2.2   # the host as the AVD sees it; a phone uses the host's LAN IP
   adb shell 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination '"$HOST"':8080; iptables -A OUTPUT -p udp --dport 443 -j DROP'
   mitmproxy --mode transparent --listen-port 8080          # or --mode wireguard with the official WireGuard app
   # "did it try at all": a per-UID byte counter with another UID as the positive control
   UID=$(adb shell dumpsys package com.target.app | grep -m1 -o 'userId=[0-9]*' | cut -d= -f2)
   adb shell "iptables -N PROBE_$UID; iptables -I OUTPUT -m owner --uid-owner $UID -j PROBE_$UID"; adb shell "iptables -L PROBE_$UID -v -n"
   # or a Frida libc hook: Interceptor.attach(Module.getExportByName('libc.so','connect'), ...) printing the sockaddr
   ```

**Confirm pinning from the binary, never from behaviour:**

Paths are the canonical decompiled tree (`$DEC` = `$E/decompiled`, START.md §6). R8 renames `CertificatePinner`
and most class names in release builds, so only the **pin-string shape** (`sha256/<base64>`) or an NSC `<pin-set>`
is decisive; a zero on a class-name grep is not.

```bash
# Declarative pinning (decisive)
grep -A5 '<pin-set' "$DEC/apktool/res/xml/network_security_config.xml"

# Pin strings survive R8 (decisive); class names do not (indicative only)
grep -rn 'sha256/' "$DEC/jadx/sources" "$DEC/apktool/res" "$DEC/apktool/assets" 2>/dev/null
grep -rn 'CertificatePinner' "$DEC/jadx/sources"

# Custom trust (method names on framework interfaces survive R8)
grep -rln 'checkServerTrusted\|X509TrustManager\|HostnameVerifier\|setDefaultHostnameVerifier' "$DEC/jadx/sources"

# Native pinning
strings "$DEC"/apktool/lib/arm64-v8a/*.so | grep -iE 'sha256/|pin|X509_check'
```

Then, and only then, bypass it — and remember that **the bypass is not the finding**. The finding is what
the visibility lets you discover in the API. Pinning absent or defeatable is VRT P5.

---

## 5. Frida, and how not to fool yourself

**Frida discipline** — every line below exists because its absence produced a false negative in a real engagement:

```bash
export ANDROID_SERIAL=emulator-5554      # never -U: with a phone and an AVD attached it picks silently (the phone)
adb -s "$ANDROID_SERIAL" root            # frida-server from a non-root shell fails silently; Magisk phone: su -c
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell 'chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'
frida-ps -D "$ANDROID_SERIAL" | head -3  # answers from THIS device; frida host and server versions must match (D26-010)

# spawn: hooks are in place before the first line of app code runs (login-time crypto, first WebView, prefs writes)
frida -D "$ANDROID_SERIAL" -f com.target.app -l frida/01-webview-settings.js -t 120 -q | tee "$E/logs/frida-01-$(date +%s).log"
#   -q without -t detaches right after the script loads and EVERY hook shows zero hits. -t is honoured in spawn mode only.
# attach: the app is already running, or spawning trips its RASP (D21). Foreground it FIRST:
adb shell am start -W com.target.app/.MainActivity
timeout 120 frida -D "$ANDROID_SERIAL" -n com.target.app -l frida/01-webview-settings.js     # REPL: rpc.exports.dump()
#   A cached app is FROZEN (cat /sys/fs/cgroup/uid_<uid>/pid_<pid>/cgroup.freeze == 1): attaching hangs, the half-injected
#   process then SIGSEGVs. "unexpectedly timed out while waiting for stop" leaves the target dead — restart it, re-attach.
objection -g com.target.app explore      # objection pins its own frida: `pipx runpip objection show frida` vs the server
```

Rules of the device: **one Frida session per device.** Another worker's `frida -f`, `am force-stop` or `pm clear`
on the same serial kills your session mid-run; a fan-out takes a device lock (`$E/logs/device.lock` holding the
serial + PID, checked by every worker before `adb -s`) or gets its own AVD. Never `Java.registerClass` against an
obfuscated interface on Frida 17 (it crashes the target); poll the state instead. The positive control for the
whole setup is D26-010 with `-t 30`: a hook on a method you *know* fires (e.g. `android.util.Log.i`) prints at least
once, or nothing else you record today is evidence.

Three correctness rules that cost people entire engagements:

**Hooking an abstract framework class records nothing.** Hooks on `android.webkit.WebSettings` yield zero
calls because the concrete implementation is `ContentSettingsAdapter`. Zero hits from a base-class hook is
a **false negative**, not a clean result.

**Prefer reading state off live objects over intercepting setters.** `Java.choose` on the concrete class
and reading its current state tells you what is true now. Setter interception only tells you about calls
that happened while you were attached.

Read the settings **through the public API by virtual dispatch** (MASTG-DEMO-0030): `android.webkit.WebView` is in
the app's class loader, its `getSettings()` returns the provider's concrete object, and the getters dispatch into
it. A `Java.choose` on `org.chromium.android_webview.AwSettings` or `ContentSettingsAdapter` through the default
class factory throws `ClassNotFoundException` (they live in the WebView provider's own loader — see the header of
`frida/01-webview-settings.js`, which locates that loader for the setter-provenance hooks).

```javascript
Java.perform(function () {
  Java.choose('android.webkit.WebView', {
    onMatch: function (wv) {
      Java.scheduleOnMainThread(function () {          // WebView methods assert the UI thread
        var s = wv.getSettings();
        console.log('[settings]', s.getClass().getName(), 'js=' + s.getJavaScriptEnabled(),
                    'file=' + s.getAllowFileAccess(), 'fileFromFile=' + s.getAllowFileAccessFromFileURLs(),
                    'universal=' + s.getAllowUniversalAccessFromFileURLs());
      });
    },
    onComplete: function () {}
  });
});
```

`frida/01-webview-settings.js` is the maintained, loader-aware version of this (`rpc.exports.dump()`), with the
"zero result means" rules in its header; use it rather than retyping the snippet.

**A tool's silence is never a negative result.** "drozer found nothing", "adb backup was empty" and "no
exported components" are expected defaults on modern Android. Only a manifest read or a code read
establishes a negative.

---

## 6. The attacker app

Your PoC for AM-03 is a **second application**, not an adb command. `adb shell am start` runs as `shell`,
a far more privileged UID than any real attacker. A finding proved only by adb has not established AM-03.

Use the repository's own [`attacker-app/`](../attacker-app/README.md) — **extend it, never write a second one.**
It is a zero-permission probe with a headless `PROBE|<step>|<key>=<value>` logcat contract plus a file mirror,
driven entirely from adb, so a model can run and read it:

```bash
cd attacker-app && ./build.sh --victim com.target.app --install
adb shell am start -S -n com.sanehunters.probe/.MainActivity --es run baseline,enumerate,provider --es victim com.target.app --es authority com.target.app.provider
adb logcat -s PROBE:V
adb pull /sdcard/Android/data/com.sanehunters.probe/files/ "$E/logs/probe/"     # some builds drop app Log output
```

Steps: `baseline enumerate provider read redirect deeplink start broadcast bind getservice sniff picanary`
(its README has every extra). The argument is the **absence of any `<uses-permission>` element** — screenshot
the manifest — and the `ready` line measures it (`requestedPermissions=[]`) together with the targetSdk, API
level and `deviceSecure`. Acceptance list for any extension: the self-narrating monospace log pane from the
[PoC standard](04-poc-and-evidence-standard.md), numbered action buttons, raw platform return values with their
meaning in parentheses, a positive control before any zero, and every fact mirrored to the file

---

## 7. Harness verification — run before every engagement

Do not start testing until all of these pass. Ten minutes here saves a day later.

Six checks; each maps 1:1 to a key of `engagement.json.lab` that `scripts/gate.py p1` reads. Tee the whole block
into `$E/logs/harness/verify-$(date +%F).txt`.

```bash
export ANDROID_SERIAL=emulator-5554; export E=BugBountyTarget/<Target>_<DDMMYYYY>; mkdir -p "$E/logs/harness"
# 1) Device is what you think it is  (lab.serial)
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.type          # expect userdebug on the analysis AVD

# 2) Root works  (lab.root)
adb root && adb shell id                 # expect uid=0(root)

# 3) TLS interception works FROM AN APP UID  (lab.tls_intercept)
#    Never `adb shell curl`: it runs in the shell's mount namespace, passes without Step 3, and stock images ship no curl.
curl -sx 127.0.0.1:8080 -o /dev/null -w '%{http_code}\n' https://example.com      # host side: proxy reachable at all
adb shell am start -a android.intent.action.VIEW -d https://example.com           # an app UID (any browser) through the device store
#    expect the flow in mitmproxy with a 200, NOT "Client TLS handshake failed"; then the D26-006 listing from the TARGET's PID:
PID=$(adb shell pidof com.target.app | tr -d '\r'); adb shell "nsenter --mount=/proc/$PID/ns/mnt -- ls /apex/com.android.conscrypt/cacerts" | grep -c "$HASH"   # 1

# 4) Frida attaches on THIS device  (lab.frida)
frida-ps -D "$ANDROID_SERIAL" | head

# 5) A SECURE lockscreen exists — a credential, not a keyguard on screen  (lab.lockscreen)
adb shell locksettings get-disabled      # expect false (set with: adb shell locksettings set-pin 1234)
adb shell dumpsys lock_settings | grep -iE 'credential|quality'
#    or from inside the probe app: the `ready` line prints deviceSecure=true (KeyguardManager.isDeviceSecure)

# 6) Positive controls: the instruments can produce a positive BEFORE any zero is read  (lab.positive_controls)
frida -D "$ANDROID_SERIAL" -n com.target.app -q -t 30 -e "Java.perform(function(){Java.use('android.util.Log').i.overload('java.lang.String','java.lang.String').implementation=function(t,m){console.log('[ctl] Log.i '+t);return this.i(t,m);};});"   # D26-010: at least one [ctl] line
adb shell am start -S -n com.sanehunters.probe/.MainActivity --es run baseline,provider --es authority settings   # probe app: control=content://settings/secure returns rows
```

That last one matters more than it looks. A first attempt at proving a Keystore auth window once produced
**inverted** results because keyguard state was never asserted. Every dynamic claim needs its negative
control, with the precondition verified, **in the same take**.

### Record it — the exact object `scripts/gate.py p1` checks

Write the result into `engagement.json` (`scripts/new-engagement.sh` seeds `"lab": {}`); every key is one of the
six checks above, `true` only when that check passed **today** on **that serial**:

```json
"lab": {
  "mode": "dynamic",                 // or "static-only": then the five booleans are not required and P1 passes with a stated reason
  "serial": "emulator-5554",         // check 1
  "root": true,                      // check 2
  "tls_intercept": true,             // check 3 (app-UID flow seen + D26-006 listing)
  "frida": true,                     // check 4
  "lockscreen": true,                // check 5 (locksettings get-disabled = false)
  "positive_controls": true,         // check 6 (control hook fired + probe control query returned rows)
  "pin": "1234",
  "verified": "YYYY-MM-DD",
  "log": "logs/harness/verify-YYYY-MM-DD.txt"
}
```

A `false` or missing key is a stated blocker, not a value to guess; `mode: "static-only"` is the honest answer when
no device passes, and the report then says so.

---

## 8. Related

- [Attacker models](05-attacker-models.md) — why the attacker app matters
- [PoC & evidence standard](04-poc-and-evidence-standard.md)
- [`tools/`](../tools/) — the sweep harnesses that run against this lab
