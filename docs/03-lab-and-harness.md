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

```bash
# Decompilation / static
brew install jadx apktool aapt2 apksigner
pipx install apkleaks

# Device
# platform-tools usually at ~/Library/Android/sdk/platform-tools
export PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/cmdline-tools/latest/bin:$PATH"

# Instrumentation
pipx install frida-tools objection
# drozer: the Android tool is WithSecureLabs/drozer.
#   NOTE: github.com/dozermapper/dozer is a Java bean-mapping library and is NOT this tool.
pipx install drozer

# MitM
brew install mitmproxy
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
```

### Step 1 — mitmproxy, and its CA in Android's system format

Android's system store keys certificates by the hash of their subject, with a `.0` suffix.

```bash
mitmproxy --listen-port 8080   # once, to generate ~/.mitmproxy/mitmproxy-ca-cert.pem

HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem "${HASH}.0"

adb root && adb remount
adb push "${HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
```

### Step 2 — API 34+ only: the trust store moved

On **API 34 and later** the CA store lives in the updatable **Conscrypt APEX**, and
`/system/etc/security/cacerts` is **ignored at runtime**.

The push and the `chmod` in Step 1 both **succeed**, and nothing is trusted. Operators then see TLS
failures on every host and conclude the app is pinned. It is not.

```bash
# API 34+ : overlay the APEX trust store
adb shell mkdir -p /data/local/tmp/cacerts
adb shell cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/
adb push "${HASH}.0" /data/local/tmp/cacerts/
adb shell chmod 644 /data/local/tmp/cacerts/*
adb shell mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts
```

### Step 3 — The step everyone misses: the zygote mount namespace

App processes **fork from zygote and inherit zygote's mount namespace**. A bind mount made in the shell's
namespace is invisible to every app. The bind must exist in zygote's namespace too, and the app must then
be restarted.

```bash
# Re-enter zygote's mount namespace and bind there as well
adb shell 'nsenter --mount=/proc/1/ns/mnt -- mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts'
for Z in $(adb shell pidof zygote zygote64); do
  adb shell "nsenter --mount=/proc/$Z/ns/mnt -- mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts"
done
adb shell am force-stop com.target.app
```

**Symptom of skipping this step:** `Client TLS handshake failed ... does not trust the proxy's certificate`
for **every single host**, including hosts the app has no reason to pin.

### Step 4 — Route traffic

```bash
adb shell settings put global http_proxy 127.0.0.1:8080
# or launch the emulator with -http-proxy as in Step 0
```

### Step 5 — Install the full APK set

Miss a config split and you miss code and native libraries.

```bash
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk split_config.en.apk
```

---

## 4. Confirming pinning — the discipline

> **Never conclude "the app is pinned" because MitM failed.**

Failure to intercept has at least five causes, and only one of them is pinning:

1. The CA is in `/system/etc/security/cacerts` on API 34+, which is ignored (§3 Step 2).
2. The bind mount is missing from zygote's namespace (§3 Step 3).
3. The app was not restarted after the mount.
4. The app uses a framework with its own trust store — **Flutter uses Dart's own BoringSSL roots and
   ignores the Android store entirely**. So does any app statically linking its own TLS.
5. The app genuinely pins.

**Confirm pinning from the binary, never from behaviour:**

```bash
# Declarative pinning
grep -A5 '<pin-set' res/xml/network_security_config.xml

# OkHttp
grep -rn 'CertificatePinner' sources/

# Custom trust
grep -rn 'X509TrustManager\|checkServerTrusted\|HostnameVerifier\|setDefaultHostnameVerifier' sources/

# Native pinning
strings lib/arm64-v8a/*.so | grep -iE 'sha256/|pin|X509_check'
```

Then, and only then, bypass it — and remember that **the bypass is not the finding**. The finding is what
the visibility lets you discover in the API. Pinning absent or defeatable is VRT P5.

---

## 5. Frida, and how not to fool yourself

```bash
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
frida-ps -Ua
objection -g com.target.app explore
```

Three correctness rules that cost people entire engagements:

**Hooking an abstract framework class records nothing.** Hooks on `android.webkit.WebSettings` yield zero
calls because the concrete implementation is `ContentSettingsAdapter`. Zero hits from a base-class hook is
a **false negative**, not a clean result.

**Prefer reading state off live objects over intercepting setters.** `Java.choose` on the concrete class
and reading its current state tells you what is true now. Setter interception only tells you about calls
that happened while you were attached.

```javascript
Java.perform(function () {
  Java.choose('org.chromium.android_webview.AwSettings', {
    onMatch: function (s) {
      console.log('[bridge]', s.getJavaScriptEnabled(), s.getAllowFileAccess(),
                  s.getAllowFileAccessFromFileURLs(), s.getAllowUniversalAccessFromFileURLs());
    },
    onComplete: function () {}
  });
});
```

**A tool's silence is never a negative result.** "drozer found nothing", "adb backup was empty" and "no
exported components" are expected defaults on modern Android. Only a manifest read or a code read
establishes a negative.

---

## 6. The attacker app

Your PoC for AM-03 is a **second application**, not an adb command. `adb shell am start` runs as `shell`,
a far more privileged UID than any real attacker. A finding proved only by adb has not established AM-03.

Keep a template attacker app in your toolkit with:

- an **empty** `<uses-permission>` block, visible in the manifest
- the self-narrating monospace log pane from the
  [PoC standard](04-poc-and-evidence-standard.md)
- numbered action buttons
- helpers for: sending a nested Intent, querying a provider, calling `call()`, opening a `content://`
  URI, registering a matching intent filter, and declaring a victim `taskAffinity`

---

## 7. Harness verification — run before every engagement

Do not start testing until all of these pass. Ten minutes here saves a day later.

```bash
# 1) Device is what you think it is
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.type          # expect userdebug on the analysis AVD

# 2) Root works
adb root && adb shell id                 # expect uid=0(root)

# 3) TLS interception works against a host that definitely does not pin
adb shell curl -s https://example.com -o /dev/null -w '%{http_code}\n'
#    ...and confirm the request appeared in mitmproxy. If not, you are at §3 Step 3.

# 4) Frida attaches
frida-ps -Ua | head

# 5) A lockscreen exists (required for auth-bound Keystore keys)
adb shell dumpsys window | grep -i isKeyguardShowing
```

That last one matters more than it looks. A first attempt at proving a Keystore auth window once produced
**inverted** results because keyguard state was never asserted. Every dynamic claim needs its negative
control, with the precondition verified, **in the same take**.

---

## 8. Related

- [Attacker models](05-attacker-models.md) — why the attacker app matters
- [PoC & evidence standard](04-poc-and-evidence-standard.md)
- [`tools/`](../tools/) — the sweep harnesses that run against this lab
