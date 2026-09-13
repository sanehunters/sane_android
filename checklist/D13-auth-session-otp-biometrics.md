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
