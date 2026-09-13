# ISSUES.md — The Ordered Engagement Workflow

> **This file is the index of the methodology. The issues it points to are permanent reference
> material. They are never closed.**
>
> Closing a methodology issue destroys the index for every future engagement. Per-engagement progress is
> tracked on the [Engagement Board](https://github.com/orgs/sanehunters/projects/1) by moving cards
> between columns, and by opening **new** Finding / Ruled-Out issues. The methodology issues stay open
> forever. They carry the `do-not-close` label so this is unambiguous.

---

## 0. How to use this repository

You are a tester who has just been handed an Android app and two weeks. Here is the whole system in five
lines:

1. Open a **[🎯 Engagement issue](https://github.com/sanehunters/sane_android/issues/new?template=02-engagement.yml)**. It is the parent tracker for this client.
2. Work the **phases below in order**, P0 through P9. Do not skip. The order exists because each phase
   consumes the previous phase's output.
3. In each phase, work the **domain issues** assigned to that phase's milestone. Each domain issue is a
   test battery with checkboxes.
4. When a test produces something, open a **[🐞 Finding](https://github.com/sanehunters/sane_android/issues/new?template=01-finding.yml)**.
   When a test comes back clean, open a **[✅ Ruled out](https://github.com/sanehunters/sane_android/issues/new?template=03-ruled-out.yml)**.
   Both are deliverables.
5. If the checklist missed something, open a **[📋 Checklist gap](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml)**
   the same week, while you still remember the mechanism.

### The GitHub layout

| Mechanism | What it carries |
|---|---|
| **Milestones** `M0`–`M9` | The ten engagement phases. The progress bar on a milestone is your phase completion. |
| **Issues** labelled `type: methodology` / `type: checklist` | Permanent doctrine and test batteries. **Never closed.** |
| **Issues** labelled `type: finding` / `type: ruled-out` | Per-engagement output. These *do* get closed, when reported or accepted. |
| **Labels** `phase:` `area:` `sev:` `am:` | Filtering. `sev:` and `am:` on findings; `phase:` and `area:` on everything. |
| **Labels** `high-yield` / `graveyard` | Where to spend the week, and where not to. Read `graveyard` before you argue with it. |
| **Project board** | Status columns (Reference → Not started → Testing → Blocked → Evidence → Finding → Reported → Clean) plus Phase, Domain, Severity, Attacker Model and VRT Path fields. |

---

## 1. The rule that governs everything

Before the phases, internalise the one thing that separates our reports from a vendor's:

> **An Android finding is worth money only when you can move it out of the mobile branch of the Bugcrowd
> taxonomy and into the access-control, authentication, injection or data-exposure branches.**

The entire `mobile_security_misconfiguration` branch is rated **P5**. So is "sensitive data stored
unencrypted on internal storage". So is missing pinning, tapjacking, root-detection bypass and
`allowBackup`. A report made of those is a report of informationals, and it is why clients churn vendors.

Every exported component, leaked token and JS bridge you find is a **primitive**, not a finding. Phase 7
exists entirely to convert primitives into impact. Read
[**docs/02 — Severity & Reportability**](docs/02-severity-and-reportability.md) before Phase 0. It is not
optional.

---

## 2. The phases

Each phase has an **entry condition**, the **work**, an **exit condition**, and a **time budget** for a
two-week engagement. The exit condition is a definition of done: if you cannot state it, you are not
finished, regardless of how much you have read.

---

### Phase 0 — Scope & Authorisation · Milestone `M0` · ½ day

**Goal.** Never touch the target without authorisation, and never discover on day 9 that you cannot test
payments because nobody asked for a sandbox account.

**Entry.** A client engagement exists.

**Work.**
- Complete [`templates/scoping-questionnaire.md`](templates/scoping-questionnaire.md) in full.
- Get signed authorisation naming the exact packages and hosts. File it.
- Agree which [attacker models](docs/05-attacker-models.md) are in scope. This decides half the checklist.
- **Chase the prerequisites now, not later.** Two tester-owned accounts, KYC state, payment sandbox, an
  OTP route you can actually receive, and confirmation the build is production and not debug.

**Exit.** Authorisation on file; two accounts working; you can log in on a device.

**The failure this prevents.** Cross-account IDOR is where the P1s are. Without a second account you
cannot test it, and provisioning one takes clients a week. Ask on day 0.

---

### Phase 1 — Lab & Harness · Milestone `M1` · ½ day

**Goal.** A working analysis environment, verified, before any testing.

**Entry.** Phase 0 exit met.

**Work.** Follow [**docs/03 — Lab & Harness**](docs/03-lab-and-harness.md) exactly. Build both devices:
a rooted `userdebug` AVD for analysis and a stock non-rooted physical device for reality checks.

Then run the harness verification block at the end of that document. All five checks must pass.

**Exit.** You have intercepted TLS from a host that does not pin, Frida attaches, root works, and a
lockscreen exists.

**The failure this prevents.** The single most common wrong conclusion in mobile testing is "the app is
pinned", when in fact the CA was installed into `/system/etc/security/cacerts` on API 34+ where it is
ignored, or the bind mount was never made in zygote's namespace. Both produce TLS failures on *every*
host, which looks exactly like pinning. Confirm pinning from the binary, never from behaviour.

---

### Phase 2 — Acquisition & Binary Identity · Milestone `M2` · ½ day

**Goal.** Be certain you are analysing the code that actually runs.

**Entry.** Lab verified.

**Work.** Answer three questions, explicitly, in writing, before any analysis:

1. **What framework is this?** It decides where the logic lives. `libflutter.so` means the logic is in a
   Dart AOT snapshot and jadx will show you a thin shell. `index.android.bundle` means React Native.
   Getting this wrong wastes the engagement.
2. **Am I analysing the binary that is actually running?** Apps with OTA code delivery — `expo-updates`,
   CodePush, any custom updater — routinely execute code that is not in the APK. If present, compare the
   packaged bundle against the on-device one and **re-base all analysis on the on-device bundle**.
3. **What are `minSdkVersion` and `targetSdkVersion`?** Whole vulnerability classes are gated on them.
   `apktool` often drops `<uses-sdk>`; get the real values from `apktool.yml` or `dumpsys package`.

Pull the **full APK set** — base plus every config split. Miss a split, miss code and native libraries.

**Exit.** Framework identified, OTA question answered, SDK levels recorded, full APK set on disk, and the
signature verified.

---

### Phase 3 — Attack-Surface Inventory · Milestone `M3` · 1 day

**Goal.** A complete enumeration of everything reachable. **Candidates, never findings.**

**Entry.** Phase 2 exit met.

**Work.** Run the sweeps, then read the manifest yourself:

```bash
tools/01-surface-inventory.sh base.apk
tools/06-secrets-endpoints.sh sources/
tools/04-applink-verify.sh com.client.app
```

Domains: **D01, D02, D03**. Produce the inventory that goes into the report's attack-surface appendix —
every exported component and its permission, every provider authority, every deep-link host and its
verification state, every WebView, the endpoint map, and the SDK list.

**Exit.** You can name every entry point into the app. The inventory is written down.

**The discipline.** Everything the sweeps print is a candidate. A tool's silence is never a negative
result: "drozer found nothing" and "adb backup was empty" are expected defaults on modern Android, not
evidence. Only a manifest read or a code read establishes a negative.

---

### Phase 4 — Static Deep Review · Milestone `M4` · 3 days

**Goal.** Find the guard that was meant to stop an attacker, and the path that skips it.

**Entry.** Inventory complete.

**Work.** Walk the domain issues for every surface the inventory turned up. This is the largest phase.
Domains: **D02, D03, D05, D07, D10, D11, D12, D13, D16, D17, D18, D19, D20, D22**.

The method that produces findings rather than notes:

> The bug is rarely "no validation". It is "validation on the main frame only", "validation on the
> display name but not the content", "the check on `read()` but not on `call()`". **Grep for the
> validator, then enumerate its call sites. The unguarded sibling is the finding.**

Do not conclude "obfuscated, therefore unanalysable". R8 renames identifiers; it does not remove data
flows. Retrofit annotation *values* survive R8, so the endpoint map is authoritative even on a fully
obfuscated build.

**Exit.** Every inventory item has been read to its sink, or explicitly deferred with a reason.

---

### Phase 5 — IPC & Component Attack · Milestone `M5` · 2 days

**Goal.** Prove, from a **zero-permission attacker app**, what the static review suggested.

**Entry.** Phase 4 candidates exist.

**Work.** Domains: **D04, D05, D06, D07, D08, D09, D10**.

```bash
tools/02-component-sweep.sh com.client.app
tools/03-provider-sweep.sh com.client.app
tools/07-deeplink-sweep.sh com.client.app uris.txt
```

**The rule that decides whether this phase produced anything real:** `adb shell am start` runs as `shell`,
which holds far more privilege than any real attacker. Discovery with adb is fine. **A finding proved only
by adb has not established AM-03.** Re-prove every candidate from your attacker app, whose manifest
declares no permissions, and put that manifest in the evidence tree.

Triage within the phase in this order, because the base rates justify it: intent redirection → deep links
→ WebView and bridges → ContentProviders and FileProvider → implicit-intent interception → task hijack.

**Exit.** Every exported surface either produced a confirmed primitive, or has a ruled-out entry naming
the mechanism that closes it.

---

### Phase 6 — Network & Backend API · Milestone `M6` · 3 days

**Goal.** The other half of the engagement, and usually where the Criticals are.

**Entry.** MitM working; two accounts logged in.

**Work.** Domains: **D14, D15, D18, D23, D24**.

Mobile apps expose endpoints the web app does not, versioned endpoints kept alive for old clients, and
device-bound flows nobody tests. Exercise the endpoint map you extracted in Phase 3.

Then the authorization work that pays:
- **Cross-account IDOR** with accounts A and B, testing read *and* write separately. Read-only is P3;
  read+write on iterable identifiers is P1.
- **Mass assignment** derived from the request-body model classes.
- **Business logic** — price and quantity tampering, negative values, currency confusion, entitlement
  replay, referral and coupon abuse, race conditions on redemption.
- **The cross-boundary check:** does a token the app treats as device-bound still work from `curl`?

Before any injection testing, establish the error oracle and prove non-determinism first. Hashing a raw
response body manufactures phantom differentials: send the identical request N times and hash the results
**before** any payload work. If every invalid variant returns a byte-identical response, injection is
structurally ruled out and no number of payloads changes that — which is a defensible negative, and a
faster one.

**Exit.** Endpoint map exercised; cross-account matrix complete for both read and write.

---

### Phase 7 — Chaining & Escalation · Milestone `M7` · 2 days

**Goal.** Convert every primitive into a non-P5 impact category. **This phase is why we get paid.**

**Entry.** A set of confirmed primitives from Phases 5 and 6.

**Work.** For each primitive, run the loop: **VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD.**

Ask of every primitive:
- Arbitrary read → *which* file? `shared_prefs`, the token store, the MMKV blob. Then: what does that
  token unlock **server-side**?
- A write → does it land where the app later loads code, or reads configuration?
- A leaked token → does it work from `curl`, off-device, from another IP?
- A confused-deputy read where the attacker never receives the bytes is **bounded**. Either find a gadget
  that returns bytes, or concede it.

Then do the **cross-surface move**, which is where genuinely novel findings live. Every catalogue entry is
single-surface; the findings that surprise vendors sit at the joins. Backup rules × network interceptor.
Share receiver × FileProvider roots. Deep link × WebView allow-list × OAuth redirect. Notification
listener × deep-link router. When you finish a surface, ask what *other* surface consumes its output.

**Exit.** Every primitive is either driven to a rated impact category, or written into the ruled-out
register with the reason it is bounded.

---

### Phase 8 — Evidence & PoC · Milestone `M8` · 1 day

**Goal.** Evidence a hostile triager cannot dismiss.

**Entry.** Findings confirmed.

**Work.** Follow [**docs/04 — PoC & Evidence Standard**](docs/04-poc-and-evidence-standard.md). Every
dynamically demonstrable finding gets a video in the seven-beat house format: environment in frame,
ground truth from the legitimate app, attacker identity, **negative control in the same take**, the
legitimate flow, the granted scope printed from the platform's own API, then the exploit and the delta.

Plant a **canary** before recording. A value that can only have come from the target store, shown in the
ground-truth beat and again in the exploit output, is what proves the read was real.

**Exit.** Every finding has a complete evidence tree, and a second tester has run the reviewer checklist
against each video.

---

### Phase 9 — Report, Triage & Retest · Milestone `M9` · 1 day + follow-up

**Goal.** Get accepted at the right severity.

**Work.**
- Write findings with [`templates/finding-report.md`](templates/finding-report.md). Title names the
  **impact category**, never the Android mechanism.
- Rate against the VRT. State the precondition as a sentence. Name any unproven link.
- Assemble the [assessment report](templates/assessment-report.md), including the
  [ruled-out register](templates/ruled-out-table.md) — that register is what makes it an audit rather
  than a sample.
- Defend through the [triage ladder](docs/06-triage-playbook.md). Answer the rung you are actually on,
  with the artifact it demands.
- Hold the retest window.

**Exit.** Findings accepted or explicitly declined with reasons; retest complete.

---

## 3. The daily loop

Inside any phase, the loop is the same:

1. Pick the next unchecked item in the current domain issue.
2. Run it. Record the raw output.
3. **Clean?** Open a Ruled-Out issue naming the mechanism that closes it. Move on.
4. **Interesting?** It is a *candidate*. Verify it with a negative control in the same take before it is
   anything else.
5. **Confirmed?** It is a *primitive*. Note it, keep going — do not stop to write it up.
6. At the end of the phase, take all primitives into Phase 7 together. Chains are found by looking at
   primitives side by side, not one at a time.

---

## 4. How not to fool yourself

Most wasted engagements are not "found nothing". They are "found something that was not there". The
recurring causes, each of which has burned a real engagement:

- **A tool's silence is not a negative result.** Hooking an abstract framework class records nothing
  because the concrete class differs. Zero hits from a base-class hook is a false negative.
- **Normalise before you diff.** An API returning an unordered set in non-deterministic order produces
  different hashes for identical content, and manufactures phantom anomalies.
- **Establish the error oracle before injection testing**, and recognise input-validation signatures.
  An enum allow-list error means ORDER BY injection is structurally impossible; no payload count
  changes that.
- **Distinguish the layer that answered you.** A zero-byte body with a 4xx is usually an edge rejection,
  not an application response. A stale bot-management cookie makes every request return a uniform 401
  that looks exactly like a revoked session.
- **Look for the second implementation.** The most instructive retraction on record had *accurate*
  `file:line` citations and was still wrong, because a second, fully implemented module provided the
  capability and was what the app actually used. Accurate citations do not make a finding correct.
- **Emulator artefacts are not findings.** See [docs/02 §9](docs/02-severity-and-reportability.md).

---

## 5. Index

The full checklist lives in [`CHECKLIST.md`](CHECKLIST.md) and the per-domain chapters under
[`checklist/`](checklist/). Every domain has a corresponding GitHub issue, listed in the table at the
bottom of `CHECKLIST.md`, assigned to the milestone of the phase where that domain is worked.

| Document | Purpose |
|---|---|
| [`docs/01-android-architecture-attack-surface.md`](docs/01-android-architecture-attack-surface.md) | The architecture, read as an attack surface |
| [`docs/02-severity-and-reportability.md`](docs/02-severity-and-reportability.md) | What counts as a finding. **Read first.** |
| [`docs/03-lab-and-harness.md`](docs/03-lab-and-harness.md) | Building the lab, and the failure modes that fake pinning |
| [`docs/04-poc-and-evidence-standard.md`](docs/04-poc-and-evidence-standard.md) | The mandatory PoC video format |
| [`docs/05-attacker-models.md`](docs/05-attacker-models.md) | AM-01 to AM-12 |
| [`docs/06-triage-playbook.md`](docs/06-triage-playbook.md) | The nine-rung ladder |
| [`docs/07-coverage-crosswalk.md`](docs/07-coverage-crosswalk.md) | MASVS / MASTG / ATT&CK / MT10 / VRT mapping |
| [`templates/`](templates/) | Finding, assessment, ruled-out, scoping |
| [`tools/`](tools/) | Seven sweep harnesses |
| [`data/`](data/) | The machine-extracted standards datasets |
