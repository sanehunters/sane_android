# PoC & Evidence Standard

> Every dynamically demonstrable finding ships with a video. This document is the house style, and it is
> mandatory. A finding without evidence in this format does not leave the building.

The reference artifact this standard is derived from is Mobile Hacking Lab's PoC for the Android contacts
provider SQL injection (CVE-2026-28576), published alongside their write-up:
`https://www.mobilehackinglab.com/assets/blog/CVE-2026-28576/read-contacts-poc.mp4`

It is 25 seconds, portrait, 354×806, and 478 KB. Watch it before you record your first PoC. We do not
redistribute it; go to the source. What follows is the grammar it uses, generalised into our standard.

---

## 1. Why video, and why this shape

A triager has minutes. They will not build your harness. The video has to answer four questions without
anyone narrating:

1. **What was true before?** (ground truth)
2. **What was the attacker allowed to do?** (the negative control)
3. **What did the attacker actually do?** (the exploit)
4. **How do I know the result is real and not staged?** (the canary)

Every rule below exists to answer one of those.

---

## 2. The seven beats

Record in this order. Do not cut between beats — one continuous take is the point, because a cut is where
a triager suspects staging.

### Beat 1 — Environment, in frame and never removed
Keep the emulator window title or a device banner visible for the entire recording. The reference PoC
shows `Android Emulator - A17-Userdebug:5554` in every single frame. The viewer can therefore read the
API level and build type at any moment without trusting your write-up.

On a physical device, put the banner in the app's own header instead (see Beat 3) and show
`adb shell getprop ro.build.fingerprint` output in the evidence tree.

### Beat 2 — Ground truth in the legitimate app
Open the **real** app that owns the data and show what is there. The reference PoC opens the stock
Contacts app and shows three contacts, then drills into one record to display its phone number and email
address.

This is the beat everyone skips, and it is the beat that makes the video persuasive. Without it, the dump
in Beat 7 is just text on a screen. With it, the triager can compare the dump against something they
watched you display from a trusted source thirty seconds earlier.

### Beat 3 — Attacker identity
Return to the launcher. Show the attacker app sitting among the ordinary apps. Launch it.

The app's first screen carries a header that states, permanently:
- the identifier (CVE, or our finding ID)
- the vulnerability class in four or five words
- **the preconditions** — the reference PoC shows `no permissions · targetSdk 36`

Those preconditions are the single most rating-relevant fact in the whole video, so they live on screen,
not in a caption file.

### Beat 4 — The negative control, stated by the app itself
Before any exploit, the app prints what it **cannot** do. The reference PoC prints:

```
Stored grant was revoked (reinstall/force-stop clears grants).
No grant yet. Tap the button — the SYSTEM picker opens,
the app itself cannot see your contacts list.
```

Three things are happening there, and all three are deliberate:
- it asserts the starting state is clean,
- it names *how* it was made clean, so the triager can reproduce it,
- it states the security expectation that is about to be violated.

A negative control in a separate take is worth much less than one in the same take. Keep it in the same
take.

### Beat 5 — The legitimate flow
Perform the *intended*, benign action first. In the reference PoC the user taps
`1) PICK ONE CONTACT (SYSTEM PICKER)` and picks one contact through the system UI.

This establishes that the attacker took only the access the platform meant to give — which is exactly what
makes the next beat a vulnerability rather than a permission grant.

### Beat 6 — The scope of granted access, printed
The app prints the precise authority it holds:

```
== system picker returned ==
grant URI: content://com.android.contacts/contacts/lookup/2712r1-2B413B2F33553B2F513B43/1
checkUriPermission -> 0  (0 = READ granted, only this URI)
What I am ALLOWED to see: Alice Victim  (one contact)
```

Note `checkUriPermission -> 0` — the app queries the platform's own API and prints the raw return value
with its meaning in parentheses. Do not paraphrase platform state. Print the call and its result.

### Beat 7 — The exploit, and the delta
One button. `2) EXPLOIT: READ ALL CONTACTS`. Then the log fills:

```
== exploiting: boolean-oracle SQL injection ==
-- name rows in DB: 3
   name #1: Alice Victim
   name #2: Bob Manager
   name #3: Carol Doctor
-- phone rows in DB: 3
   phone #1: +1-555-SECRET-01
   ...
== done — all of the above was read WITHOUT READ_CONTACTS ==
```

The vulnerability is the **delta**: authorised to see 1, actually read 3. The video makes that delta
arithmetic, not rhetoric. Close with a single sentence stating the impact in the user's language.

---

## 3. The canary rule

Look again at `+1-555-SECRET-01`.

That value was planted in the contacts database before recording, and it appears in the exploit output.
It cannot have come from the system picker, because the picker only returned Alice Victim. Its presence
proves the read reached the database.

**Rule:** before recording, plant at least one value that can only have come from the target store, and
make it visually distinctive. Then show it in Beat 2 and again in Beat 7.

Canaries by surface:

| Surface | Canary |
|---|---|
| Contacts / SMS / calendar | a contact or message containing the literal string `SECRET` |
| App database or prefs | a record with a value like `CANARY-D07-014` |
| File read primitive | a file whose content is a known UUID you generated on camera |
| Token theft | decode the stolen token on screen and show a claim matching the logged-in account |
| Cross-account IDOR | account B holds a resource named after account B |

Never use a real person's data as a canary. Use planted, synthetic values — the reference PoC uses
`Alice Victim`, `Bob Manager`, `Carol Doctor` at `corp.example`.

---

## 4. The self-narrating log pane

The reference PoC has no voiceover, no captions and no external annotation. Every explanatory word is
printed by the attacker app into a monospace log pane that occupies most of the screen.

This is the highest-leverage choice in the whole format, and we adopt it wholesale:

- The evidence and the explanation are the same artifact, so they cannot drift apart.
- The video is legible with the sound off, in a ticketing system, on a phone.
- The log text is copy-pasteable into the written report.
- There is nothing to re-render when you revise the report.

Build the log pane into your PoC app template once and reuse it forever. Rules for it:

- Monospace, high contrast, large enough to read at 50% scale.
- Section markers in `== double equals ==`.
- Raw API return values, with the meaning in parentheses — never the meaning alone.
- Plain-English lines for the beats a triager must not misread ("the app itself cannot see your contacts
  list").
- A final `== done — <one-sentence impact> ==` line.

---

## 5. Numbered buttons enforce reproduction order

The reference PoC's two buttons are literally labelled `1)` and `2)`. A triager rebuilding the PoC knows
the order without reading anything. Any PoC app with more than one action numbers its buttons.

---

## 6. Recording mechanics

```bash
# Clean state first — this is part of the evidence, not preparation for it
adb shell pm clear com.attacker.poc
adb shell am force-stop com.victim.app

# Record. 25-60s. Stop with Ctrl-C.
adb shell screenrecord --bit-rate 4000000 --size 720x1600 /sdcard/poc.mp4
adb pull /sdcard/poc.mp4 evidence/SANE-D07-014/poc.mp4

# Shrink for the report. Target well under 5 MB; the reference is 478 KB.
ffmpeg -i poc.mp4 -vcodec libx264 -crf 30 -preset veryslow -an poc-small.mp4

# Environment provenance, stored next to the video
adb shell getprop ro.build.fingerprint  > evidence/SANE-D07-014/device.txt
adb shell getprop ro.build.version.sdk >> evidence/SANE-D07-014/device.txt
adb shell dumpsys package com.victim.app | grep -E 'versionName|targetSdk|firstInstallTime' \
  >> evidence/SANE-D07-014/device.txt
```

Constraints:
- **Portrait**, native aspect ratio. Never letterbox or rotate.
- **25 to 60 seconds.** The reference is 25. If you need longer, your chain needs splitting into two
  findings or your beats are slow.
- **No cuts, no speed ramps, no background music, no cursor-highlight effects.**
- **No voiceover.** If it needs narrating, put it in the log pane.
- **Under 5 MB** so it attaches to any ticketing system.

---

## 7. Evidence tree

One directory per finding ID, delivered with the report:

```
evidence/
└── SANE-D07-014/
    ├── poc.mp4                 # the video, this standard
    ├── device.txt              # fingerprint, SDK, target versionName/targetSdk
    ├── attacker-app/           # full source of the PoC app — buildable
    │   ├── AndroidManifest.xml
    │   └── src/...
    ├── attacker-app.apk        # prebuilt, so triage can install in one command
    ├── commands.txt            # every adb/curl line, in order, copy-pasteable
    ├── log.txt                 # the log-pane text, as text
    ├── baseline/               # Beat 2 screenshots
    ├── negative-control/       # Beat 4 evidence
    └── notes.md                # what was ruled out, what is unproven
```

`notes.md` is not optional. It carries the honest caveats — the link you did not prove, the environment
you could not test. That section is what makes a triager believe the rest.

---

## 8. When you cannot record

Some findings are code-verified only — a chain you read but could not trigger because it needs KYC state,
a second account, or a server-side condition you do not control.

For those: ship code evidence (file, line, the call path) **plus an explicit statement of the limitation**,
and name the environment that would prove it.

**Never reconstruct a video for a finding you did not actually execute.** A staged PoC discovered during
triage ends the engagement and the relationship.

---

## 9. Reviewer checklist

Before a video is attached to a report, a second tester confirms:

- [ ] Device/build identity readable in every frame
- [ ] Ground truth shown from the legitimate app before the attack
- [ ] Negative control in the **same take** as the exploit
- [ ] Preconditions on screen (permissions held, targetSdk)
- [ ] Raw platform API return values printed, not paraphrased
- [ ] Canary value planted, shown in Beat 2 and Beat 7
- [ ] The delta between authorised and actual access is explicit
- [ ] Closing one-sentence impact line
- [ ] One continuous take, portrait, under 60s, under 5 MB
- [ ] Nothing on screen belongs to a real third party

---

## 10. Related

- [Severity & reportability](02-severity-and-reportability.md) — what the impact line must claim
- [Triage playbook](06-triage-playbook.md) — which artifact answers which pushback
- [`templates/finding-report.md`](../templates/finding-report.md)
