# Finding Template

> One file per finding: copy to `findings/F-NNN/report.md` in the engagement (evidence repo), fill, delete every
> blockquote before delivery. Rules that decide acceptance live in docs/02 (severity doctrine) in the methodology repo.
> Ids and paths follow START.md §6: finding `F-NNN`, checklist item `Dnn-NNN` (never a legacy prefixed id).

---

## F-NNN — <Impact-category title, not the Android mechanism>

> Good: `Account takeover via OAuth code interception in the exported callback activity`
> Bad:  `Activity com.target.AuthCallbackActivity is exported`

| Field | Value |
|---|---|
| **Severity** | Critical / High / Medium / Low |
| **VRT path** | e.g. `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **CVSS 3.1** | vector string + score |
| **CWE** | CWE-nnn |
| **MASTG / MASVS** | MASTG-TEST-nnnn, MASVS-<GROUP> |
| **MITRE ATT&CK Mobile** | Tnnnn |
| **Checklist items** | `Dnn-NNN`, … (the rows whose `finding_id` is this F-NNN) |
| **Attacker model** | AM-nn (docs/05 attacker models, methodology repo) |
| **Affected** | package, versionName, versionCode, targetSdk, build fingerprint tested |
| **Status** | `candidate → confirmed → evidence-complete → reported → accepted \| declined \| retracted` (START.md §6, one lifecycle) |

### Precondition
> One sentence. As weak as you can honestly make it. This drives the rating more than anything else.

Any application installed on the device, declaring no permissions, can ...

### Summary
> Two or three sentences. Mechanism first. A senior engineer should be able to act on this alone.

### Mechanism
> Name the control that was supposed to stop this, and the exact path that misses it.
> Cite `file.java:line`. Explain *why* it fails, never "the check looks bypassable".

- The guard: `path/File.java:88` — ...
- The path that skips it: `path/File.java:140` — ...
- Why it fails: ...

### Reproduction
> Numbered, copy-pasteable, no placeholders. Someone who has never seen the app must succeed.

1.
2.
3.

```bash
# exact commands
```

### Evidence
> Paths are relative to the engagement root (START.md §6). A built APK is never committed: the probe-app SOURCE
> is, and the sha256 of any build delivered to the programme goes in `apk/versions.txt`.

- `videos/F-NNN.mp4` — one continuous take, under 5 MB, conforming to the PoC standard (docs/04)
- `pocs/F-NNN/attacker-app/` — attacker-app source only (zero permissions), never a built APK
- `pocs/F-NNN/attacker-app/AndroidManifest.xml` — declares no permissions (the Rung-4 artefact, committed as evidence)
- built APK: `pocs/F-NNN/build/` (gitignored) — attached to the submission together with the video, never committed (docs/04 §7 "Where the APK lives")
- `logs/Dnn-NNN.txt` — raw tool output of the item(s) that produced the finding
- `screenshots/Dnn-NNN-<n>.png` — stills, third-party data redacted
- `findings/F-NNN/device.txt` — build fingerprint, SDK, target version · `commands.txt` — exact commands run · `notes.md`
- Canary value used: `...` — shown in ground truth and again in exploit output

### Impact
> What an attacker gains, in the user's language. Quantify the blast radius: which users, how many,
> what data, what actions. This paragraph is what sets the severity.

### The delta
> The arithmetic that makes this a vulnerability.

- Authorised access: ...
- Actual access obtained: ...

### Chain
> Each link, and its status. Be explicit about anything unproven — two verified links plus one unproven
> link is a Medium with a stated precondition, not a Critical.

| # | Link | Status |
|---|---|---|
| 1 | ... | Verified on device |
| 2 | ... | Verified on device |
| 3 | ... | **Unproven** — requires ... |

### Remediation
> Specific to their code, not generic advice.

```java
// concrete patch
```

### What was ruled out
> Adjacent things you tested that were clean. This pre-empts "did you check X?" and demonstrates coverage.

### Limitations
> Anything the environment could not prove, and which environment would prove it.
