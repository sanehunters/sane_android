# Assessment status — <Target>_<DDMMYYYY>

> **The resume point.** A future session reads this file first, then `engagement.json`, then
> `checklist-status.csv`. Keep every section current; the Stop hook refuses to end a session while
> `checklist-status.csv` is newer than this file. Dates are ISO (YYYY-MM-DD). Never delete history —
> strike it through.

| | |
|---|---|
| **Target** | `<package>` · versionName `<v>` · versionCode `<n>` · targetSdk `<n>` · minSdk `<n>` |
| **Framework / OTA** | `<native | flutter | react-native(hermes) | xamarin | unity | cordova | capacitor>` · `<none | expo-updates | codepush | custom>` |
| **Authorisation** | `<public programme <url> | signed SoW | own app | vendor VDP | lab app>` · exclusions: `<…>` |
| **Accounts** | A: `<id>` · B: `<id>` (or: requested YYYY-MM-DD, see BLOCKERS) |
| **Device(s)** | `<rooted AVD API nn | stock device model, API nn, patch YYYY-MM>` · mode: `<dynamic | static-only>` |
| **Phase** | `P0` (mirrors `engagement.json.phase`) |
| **Started / updated** | YYYY-MM-DD / YYYY-MM-DD |

## COMPLETED
<!-- one line per phase or domain settled, with the date and the gate command that opened it -->
- (none yet)

## IN PROGRESS
<!-- the current domain(s) and the item you are on -->
- P0 scope and authorisation

## FINDINGS
<!-- F-NNN · impact title · ceiling · VRT path · attacker model · status: candidate → confirmed → evidence-complete → reported → accepted | declined | retracted (START.md §6) -->
| ID | Title (impact, not mechanism) | Ceiling | VRT | AM | Status |
|---|---|---|---|---|---|

## RULED OUT — do NOT re-walk
<!-- domain or item · the mechanism that closes it (file:line / experiment + precondition) · date -->
| Scope | Mechanism | Date |
|---|---|---|

## NEXT TARGET (ordered by expected value)
<!-- ceiling × confidence ÷ cost. Parked hypotheses first in P7. -->
1. (none yet)

## BLOCKERS (stated, not faked)
<!-- what is missing · what it blocks (items / phases) · requested from whom / when -->
- (none)

## CHAINING IDEAS
<!-- cross-surface joins noticed during breadth; chase only in P7 -->
- (none yet)

## SESSION LOG
<!-- one line per session: date · phase · what was settled · commit hash -->
- YYYY-MM-DD · P0 · engagement created · `<hash>`
