# 11 — The item schema: what every checklist item must contain, and the machine-readable fields

> The chapters under `checklist/` are the single source of truth. `scripts/build-checklist.py` parses them;
> `scripts/lint-checklist.py` rejects anything that violates this schema. A model that writes a new item
> (`/gap`) follows this file exactly.

## 1. Shape

```markdown
### Dnn-NNN · <title: the test as a claim about the app, not a topic>

| | |
|---|---|
| **Severity ceiling** | <what this item's Proof demonstrates standalone; conditional ranges allowed, see §3> |
| **VRT** | `<bugcrowd path>` (Pn) [; `<second path>` (Pn)] — the node the Proof lands on, not the chain target |
| **Attacker** | AM-xx [/ AM-yy] [— one clause of context] — the weakest model that still works |
| **Applies to** | <prose: API levels, frameworks, app types, or "all"> |
| **Requires** | <tags from §4, comma-separated; empty means "always applicable"> |
| **Maps to** | <MASTG/MASWE/MASVS/CWE/ATT&CK ids and named sources; ids only if verified> |
| **Record** | <the evidence artefacts to write, e.g. logs/Dnn-NNN.txt; screenshots/Dnn-NNN-1.png> |

- **Skip when:** <the two-command check that settles the item as n/a, with the exact notes text to write>
- **Test:** <what to check, one or two sentences, mechanism-first>
- **How:** <the exact commands / greps / Frida, copy-pasteable, portable; `$DEC` for decompiled output>
- **Proof:** <the specific observable that confirms it: a log line, returned bytes, a status delta>
- **Escalation:** <what this primitive chains into, by item id; the chain ceiling lives here>
- **Ruled out when:** <the mechanism that closes it, with file:line or the controlled experiment and its precondition>
```

Required: the five metadata rows `Severity ceiling / VRT / Attacker / Applies to / Maps to` and the five
body fields `Test / How / Proof / Escalation / Ruled out when`. Strongly recommended: `Requires`, `Record`,
`Skip when`. Items are numbered contiguously `001…` within a chapter; ids are never reused or renumbered.

## 2. Chapter shape

`# Dnn · Name` · intro paragraph · the domain metadata table (`Phases`, `Milestones`, `VRT ceiling`,
`Primary attacker model`, `Maps to`) · `## Why this domain pays` · `## The crux question` ·
`## Applicability probe` (the 2–5 commands that decide whether the whole domain applies, and the exact
`n/a` note to write when it does not) · `## Triage order` · `## Items` · `## Graveyard for this domain` ·
`## Cross-surface joins` · `## Sources`.

## 3. Severity vocabulary

`critical | high | medium | low | support | varies`. `support` = cannot be reported alone; it produces a link
in a chain or a rating input. `varies` = rated on demonstrated impact (the VRT node is a "varies" node).
A cell may state a standalone level and a chained level — `Medium standalone; High with a reach primitive` —
the build records the first as `severity_floor` and the highest as `severity` (the ceiling) and keeps the
raw text as `severity_note`. **The ceiling is what this item's Proof can demonstrate**, not what a chain that
starts here can reach; the chain's ceiling belongs in `Escalation`.

## 4. `Requires` tags — the applicability vocabulary `scripts/scope.py` understands

An item carries the tags that must all be true for it to apply. The engagement records the facts in
`engagement.json` (`target.framework`, `target.targetSdk`, `target.minSdk`, `app_facts.*` filled in P2/P3,
`lab.mode`, `accounts`, `authorisation.scope`) and `scripts/scope.py` proposes `n/a` or `blocked` rows with
generated reasons. Untagged items are always applicable.

| Tag | True when | Source of truth |
|---|---|---|
| `webview` · `js-bridge` | the app has a WebView / an `addJavascriptInterface` or `addWebMessageListener` | `app_facts.has_webview`, `inventory/webviews.csv` |
| `native` | the APK ships `.so` libraries the app loads | `app_facts.has_native` |
| `flutter` · `react-native` · `hermes` · `xamarin` · `unity` · `cordova` · `capacitor` · `kmp` | the framework (`target.framework`) | P2 |
| `provider` · `exported-activity` · `exported-service` · `exported-receiver` | the inventory has such an instance | `inventory/components.csv` |
| `deeplink` · `applink` | `inventory/deeplinks.csv` has a row (`applink` = `autoVerify=true`) | P3 |
| `backend-api` | the app talks to a backend the scope includes | `authorisation.scope` |
| `oauth` · `biometric` · `payments` · `push` · `firebase` · `ads-sdk` · `ai-feature` | the feature is present (P2/P3 recon) | `app_facts.*` |
| `two-accounts` | accounts A and B exist | `accounts` |
| `device` · `root` · `mitm` · `frida` · `physical` | the capability exists | `scripts/doctor.sh --json`, `lab.*` |
| `oem-scope` · `enterprise` · `wear` · `tv` · `auto` | the engagement scope includes that surface | `authorisation.scope` |
| `api<=N` · `api>=N` · `targetsdk<N` · `targetsdk>=N` · `minsdk<N` | numeric gates on the app or device | `target.*`, device API |
| `legacy` | the item is only reachable on builds below a stated gate; always paired with a numeric tag | — |

Example: `| **Requires** | webview, js-bridge, targetsdk<17, legacy |` for the reflection escape.

## 5. `Record` — the evidence contract

Name the artefacts the item produces so a future session and a triager can find them without reading the
notes: `logs/Dnn-NNN.txt` (raw tool output, always), `screenshots/Dnn-NNN-<n>.png`, `requests/E-NNN.http`,
`pocs/F-NNN/` for anything that became a finding. The row's `evidence` column points at the first of these.

## 6. What the linter rejects

Missing sections or fields · non-contiguous or duplicate ids · a severity cell with no recognisable level ·
an `Attacker` cell with no `AM-xx` (unless `n/a` for a method/discipline item) · a VRT path not in
`data/vrt.csv` · a MASTG/MASWE id not in `data/standards-index.csv` · a reference to an item or domain that
does not exist · a dead relative link · `SANE-` prefixes · a `Requires` tag outside §4 · (warning) a
citation of a deprecated or placeholder MASTG page without saying so · (warning) a `Ruled out when` shorter
than a mechanism.
