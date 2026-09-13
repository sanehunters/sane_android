# Attacker Models

> Every checklist item in this repository is tagged with the attacker model it assumes. Before you test an
> item, know which attacker you are playing. Before you report one, know that your attacker is weak enough
> to be credible.

The rating of a mobile finding is dominated by **who has to do what** before the attack works. Two testers
can find the identical bug and get P1 and P5 for it, purely on how they framed the attacker. This document
fixes the framing.

---

## 1. The twelve models

Ranked roughly by how much a program will pay for them.

| ID | Attacker | Holds | Typical ceiling |
|---|---|---|---|
| **AM-01** | Remote, no interaction | Nothing. Sends a request or a push. | Critical |
| **AM-02** | Remote, one click | Victim taps a link (browser, SMS, chat, QR) | Critical |
| **AM-03** | Zero-permission local app | Any app the victim installs. Declares **no** permissions. | Critical |
| **AM-04** | Local app with one common permission | e.g. `INTERNET` plus one of storage/notifications | High |
| **AM-05** | Another user of the same app | A second, legitimate account | Critical |
| **AM-06** | Network attacker, no trusted CA | Same Wi-Fi, cannot install a CA | High |
| **AM-07** | Network attacker with a trusted CA | Managed device, or a CA the app trusts | Medium |
| **AM-08** | Malicious or compromised third-party SDK | Code inside the app's own process | High |
| **AM-09** | Malicious backend / compromised CDN | Serves responses or OTA code to the app | High |
| **AM-10** | Physical access, device locked | The handset, screen locked | Medium |
| **AM-11** | Physical access, device unlocked | The handset, unlocked | Low |
| **AM-12** | Attacker's own rooted device | Root on their own handset, own account | **Informational** |

### The rule

> **Report the weakest attacker that still works.** If a bug fires for AM-03, never write it up as AM-11.

And the corollary that saves the most wasted days:

> **AM-12 is not an attack.** An attacker rooting their own phone to read their own token has not crossed a
> boundary. Root is an *evidence tool* — legitimate for showing that the token you stole over IPC is the
> same token in the sandbox. It is not a *precondition*. Say which one you are doing, every time.

---

## 2. What each model can actually reach

### AM-01 — Remote, no interaction
The rarest and most valuable. On mobile this is almost always the **backend**, not the app: an
unauthenticated API endpoint, an IDOR reachable without a session, a push-notification handler that acts
on unauthenticated content, or an OTA/update channel with no signature check.

Test surfaces: `D15` backend API, `D24` push/FCM, `D17` OTA and dynamic code loading.

### AM-02 — Remote, one click
The highest-yield *mobile-native* model. The victim taps a link; the link is a deep link or App Link the
app claims; the app routes attacker-controlled data into a privileged sink.

This is the model behind most mobile account takeovers: `myapp://` or `https://host/path` reaching a
WebView that carries the session, or an OAuth redirect the attacker's app can claim.

Test surfaces: `D09` deep links, `D10` WebView, `D13` auth/OAuth.

### AM-03 — Zero-permission local app
The workhorse. This is the Oversecured model and it is what most Android app bounties are actually paid
for. The attacker ships an app that asks for nothing and is therefore trivially installable.

What it can do with no permissions at all:
- send Intents to any exported activity, service or receiver
- query, write to and `call()` any exported ContentProvider
- receive any implicit broadcast the victim sends
- register intent filters matching the victim's implicit Intents and win the race or the chooser
- declare `taskAffinity` matching the victim and insert itself into the victim's task
- receive URI grants a confused-deputy victim hands out
- read anything on shared storage the victim wrote there

Your PoC for this model is a **second app**, not an adb command. `adb shell am start` is a fine discovery
tool, but it runs as `shell`, which holds far more privilege than a real attacker. A finding proved only
by adb has not established AM-03.

Test surfaces: `D04`–`D08` the whole IPC block.

### AM-04 — Local app with one common permission
Weaker but still credible, because users grant storage and notification permissions routinely. Notably
covers `NotificationListenerService` and accessibility abuse, which require a user-granted special access.

Rate one step below the equivalent AM-03 finding, and state the permission in the precondition sentence.

### AM-05 — Another user of the same app
This is where the money is on the server side. Two tester-owned accounts, A and B. Everything in `D15`
that says "cross-account" assumes this model.

**Never use a real third party's account.** Two accounts you own, both created for the engagement.

### AM-06 / AM-07 — Network attackers
Split these carefully because programs rate them very differently.

**AM-06** (no trusted CA) is the real-world attacker: coffee-shop Wi-Fi, hostile ISP. It reaches cleartext
traffic, downgrade issues, and anything the app does over plain HTTP. Findings here are real.

**AM-07** (trusted CA installed) is the tester's convenience, not an attacker. Everything you see through
your own mitmproxy CA is *analysis*, not a finding. The finding is what you **do** with the visibility —
the IDOR, the mass assignment, the auth bypass. Pinning being absent is what let you look; it is not
itself the bug. See the graveyard in [severity doctrine](02-severity-and-reportability.md).

### AM-08 — Malicious or compromised SDK
In-process, so the app sandbox gives it everything the app has. Increasingly credible given real
supply-chain compromises. Relevant when the app hands secrets to SDKs, or when an SDK can read the app's
storage, intercept its network layer, or register its own components.

Test surfaces: `D17` supply chain, `D18` third-party SDK config, `D20` privacy.

### AM-09 — Malicious backend / compromised CDN
The model that makes **OTA code delivery** (expo-updates, CodePush, custom DEX/JS updaters) a critical
surface. If the app fetches executable content without verifying a signature, whoever controls that
channel controls the app.

Also covers remote-config that changes security behaviour (host allow-lists, feature flags, pinning
toggles) — a control-plane write is a security finding even when the transport is fine.

### AM-10 / AM-11 — Physical access
Most programs exclude these, or rate them Low. Check the program rules *before* spending time here.
`AM-10` (locked) occasionally pays for lockscreen bypasses into app content and for data readable without
unlocking. `AM-11` (unlocked) almost never pays.

### AM-12 — Attacker's own rooted device
Not a finding. See §1.

---

## 3. Choosing the model during testing

Ask these three questions of every primitive you find, in this order:

1. **Can a zero-permission app do this?** If yes, you are at AM-03 and you should stop looking for a
   weaker framing — build the attacker app.
2. **Can a link do this?** If yes, you are at AM-02, which is stronger still. Build the HTML page.
3. **Does this cross to another user's data?** If yes, you are at AM-05 and the finding belongs to the
   server-side taxonomy, which is where the P1s live.

If the answer to all three is no, be honest about which model you are actually in, and expect the rating
to follow.

---

## 4. Coverage requirement

A complete engagement tests every model that is in scope, and says so. The
[ruled-out table](../templates/ruled-out-table.md) has a column for the attacker model precisely so the
client can see that, for example, AM-03 was swept across every exported component and came back clean.

"We found nothing for AM-03" is a deliverable. "We didn't look" is not, and the difference is only
visible if you recorded it.

---

## 5. Related

- [Severity & reportability](02-severity-and-reportability.md)
- [PoC & evidence standard](04-poc-and-evidence-standard.md) — Beat 3 puts the model on screen
- [`templates/ruled-out-table.md`](../templates/ruled-out-table.md)
