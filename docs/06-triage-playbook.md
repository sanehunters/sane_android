# Triage Response Playbook

> A report is not finished when you submit it. It is finished when it is accepted at the right severity.
> Most of the value a senior tester adds over a junior one happens *after* submission.

Triage pushback is not hostility. It is a triager working through a ladder of doubts in a fixed order.
Each rung demands one specific artifact. Send that artifact, not an argument.

---

## 1. The ladder

Triagers descend this ladder. Answer the rung you are actually on.

| Rung | What they say | What they mean | What you send |
|---|---|---|---|
| 1 | "Cannot reproduce" | Your steps are incomplete or environment-specific | The APK, exact build fingerprint, and `commands.txt` verbatim |
| 2 | "This is intended behaviour" | They think the export/grant is deliberate | The code path showing the *guard that was meant to stop you*, and where it fails |
| 3 | "No security impact" | You reported a primitive, not an impact | The chain to a non-P5 VRT category, with the delta on video |
| 4 | "Requires a malicious app" | They think that is an unreasonable precondition | The zero-permission manifest, plus the observation that this is the standard Android threat model |
| 5 | "Requires root" | Fatal if true | Prove it does not. If it does, concede and downgrade |
| 6 | "Requires physical access" | Usually out of scope | Re-frame to AM-02/AM-03 if you can; otherwise concede |
| 7 | "Duplicate" | Someone got there first | Ask for the overlap boundary; your chain may extend theirs |
| 8 | "Severity is lower" | Rating dispute | The VRT path, the CVSS vector, and the demonstrated (not theoretical) capability |
| 9 | "Won't fix / accepted risk" | Business decision | Ask for it in writing for the client report. Do not argue |

---

## 2. Rung-by-rung responses

### Rung 1 — "Cannot reproduce"

Almost always an environment mismatch. Do not resend the same steps.

Send, in one message:
- the **prebuilt attacker APK** (they will not build your source)
- `adb shell getprop ro.build.fingerprint` from your device
- the target app's `versionName` and `targetSdk` as you tested them
- `commands.txt`, copy-pasteable, no placeholders

Then ask one question: *what build and API level did you test on?* Version-gated behaviour is the single
most common cause, and naming it converts the exchange from a dispute into a joint diagnosis.

### Rung 2 — "This is intended behaviour"

The strongest possible reply is the **developer's own guard**. Find the validator, the permission check,
the allow-list, the `setComponent(null)` — and show that it exists, which proves the developer intended a
boundary, and then show the path that skips it.

> "`RouterActivity.validate()` at line 88 allow-lists three hosts before calling `startActivity`. The
> `onNewIntent` path at line 140 reaches the same `startActivity` without calling `validate()`. The
> boundary is intended; this path misses it."

If there genuinely is no guard anywhere, you are on Rung 3, not Rung 2. Be honest about which.

### Rung 3 — "No security impact"

This is the most common rung, and it is usually **correct**. You reported a primitive.

Go back to [severity doctrine §3](02-severity-and-reportability.md) and drive the primitive into a
non-P5 category. Then resubmit with:
- the video showing the **delta** (authorised vs actual)
- one sentence naming the VRT path you are now claiming
- the canary value proving the data is real

If you genuinely cannot reach an impact category, withdraw the finding. Withdrawing one report buys
credibility that makes the next three land.

### Rung 4 — "Requires a malicious app"

Do not get defensive. State the model plainly:

> "The attacker app declares zero permissions — manifest attached. Installing an unrelated app is the
> baseline Android threat model that the permission system and the UID sandbox exist to contain. The
> finding is that data crosses that boundary without the user's consent."

Attach the attacker manifest. The empty `<uses-permission>` block *is* the argument.

### Rung 5 — "Requires root"

Be ruthless with yourself here. Ask: does the **attack** need root, or did only my **evidence** use it?

- Evidence-only: re-record without root. If the attack works on a stock device, prove it on one.
- Attack needs root: concede immediately, downgrade, and say so before they have to push again.

Conceding fast on Rung 5 costs you one finding. Fighting it costs you the program's trust.

### Rung 7 — "Duplicate"

Ask precisely: *does the existing report cover the same entry point and the same impact, or only the same
component?*

Frequently someone reported "activity X is exported" and you have the chain from X to account takeover.
That is not a duplicate; it is the impact the original lacked. Say exactly that, and offer to have yours
merged as additional impact if they prefer.

### Rung 8 — "Severity is lower"

Argue with the taxonomy, not with adjectives.

> "This maps to `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers`
> (VRT P1). The video shows read **and** write on account B from account A's session, with sequential
> integer identifiers. If the program rates on CVSS, the vector is AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N."

Name the VRT path. Name the demonstrated capability. Never say "this is clearly critical".

---

## 3. Things never to do

- **Never fabricate** a CVE, a report ID, a bounty figure, a CVSS vector or a PoC.
- **Never re-record** a video for something you did not execute.
- **Never argue severity with adjectives.** Use the taxonomy and the evidence.
- **Never escalate to social media** over a rating dispute.
- **Never test a third party's account** to strengthen a report.
- **Never resend the same artifact** with more insistence. If they did not accept it, it did not answer
  their rung.

---

## 4. When you were wrong

You will sometimes be wrong. The finding dies during triage, or you notice the flaw yourself first.

**Say so immediately, in the thread, and record the refutation next to the finding in the report** rather
than deleting it. A findings list that shows one item struck through with the reason is dramatically more
credible than one that shows only survivors.

The most instructive failure mode: a finding whose every `file:line` citation was **accurate** and which
was still wrong, because a second, fully-implemented module provided the capability and was what the app
actually used. Accurate citations do not make a finding correct. Before you defend a finding on Rung 2,
check for the second implementation.

---

## 5. Client-facing version

On a paid engagement there is no external triager — you are writing for the client's engineers, who will
push back on the same rungs. Two additions:

- Attach a **fix** to every finding, specific to their code, not a generic recommendation.
- Offer a **retest window** in writing, and hold it. Retest is where the relationship renews.

---

## 6. Related

- [Severity & reportability](02-severity-and-reportability.md)
- [PoC & evidence standard](04-poc-and-evidence-standard.md)
- [`templates/finding-report.md`](../templates/finding-report.md)
