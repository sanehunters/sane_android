# 11 — The item schema: what every checklist item must contain, and the machine-readable fields

> The chapters under `checklist/` are the single source of truth. `scripts/build-checklist.py` parses them;
> `scripts/lint-checklist.py` imports that parser and rejects the violations listed in §6 (the rest of this
> file is reviewed by hand). A model that writes a new item (`/gap`) follows this file exactly;
> `scripts/apply-item-meta.py` edits items in place with the same row names.

## 1. Shape

```markdown
### Dnn-NNN · <title: the test as a claim about the app, not a topic>

| | |
|---|---|
| **Severity ceiling** | <the levels this item can demonstrate, standalone first; see §3> |
| **VRT** | `<bugcrowd path>` (Pn) [; `<second path>` (Pn)] — the node the Proof lands on, not the chain target; grammar below |
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
body fields `Test / How / Proof / Escalation / Ruled out when`. Strongly recommended (the linter counts them
and warns on the migration gap): `Requires`, `Record`, `Skip when`. The heading separator is `·` (or `-`);
any other character makes the item invisible to the build. Items are numbered contiguously `001…` within a
chapter; ids are never reused or renumbered. Every metadata row is closed with a trailing `|` and non-empty.

**The item separator and the heading.** A row with a title but no parseable id is an error, not a silently
dropped item: the build and the linter use the same regex.

**Paths in `How`.** `$E` is the engagement folder, `$DEC` = `$E/decompiled` (`$DEC/jadx/sources`,
`$DEC/apktool`): never `jadx_out/` or `apktool_out/`. `frida -D "$SERIAL"`, never `frida -U` (it picks a
device silently); no `--no-pause` (removed in frida-tools 17). `sed -i.bak`, not bare `sed -i` (BSD sed).
Each of these is a linter warning today.

**The VRT cell grammar.** Exactly one of:

| Form | Example | `vrt_priority` / `vrt_best` |
|---|---|---|
| one or more backticked paths, each optionally followed by its priority `(Pn)`, `(**Pn**)`, `(varies)` or `(null)` | `` `broken_access_control.idor` (P1); `…` (P4) `` | first = the first path's priority (the node the Proof lands on); best = the highest priority named. A path without a stated priority is looked up in `data/vrt.csv`; `null` is the VRT json's spelling of a varies node |
| `n/a [— reason]`, `none`, `—` | `n/a — method` | `n/a` |
| `as Dnn-NNN`, `inherits …`, `governs …`, `consequence-rated`, `routed to …` | `inherits the bridge severity (D10-004)` | `inherit:D10-004` (the partner id when one is named) |
| `varies`, `rated on …`, `depends on …`, `outcome-rated`, `whichever node …`, `no dedicated node/leaf …` | `rated on the demonstrated sink` | `varies` |

Anything else is classified `?` by the build and warned by the linter. The priority suffix is optional; the
taxonomy's own priority is used when it is omitted, so `(Pn)` is worth writing only when the chapter argues a
different level than the node's default.

## 2. Chapter shape

`# Dnn · Name` · intro paragraph · the domain metadata table (`Phases`, `Milestones`, `VRT ceiling`,
`Primary attacker model`, `Maps to`) · `## Why this domain pays` · `## The crux question` ·
`## Applicability probe` (the 2–5 commands that decide whether the whole domain applies, and the exact
`n/a` note to write when it does not — **planned (C8)**: no chapter carries it yet, so the linter warns and
the build prints the count; it becomes an error once every chapter has one; the card renders it when present) ·
`## Triage order` · `## Items` · `## Graveyard for this domain` · `## Cross-surface joins` ·
`## Chain partners (filed as separate reports)` (optional) · `## Sources`.

## 3. Severity vocabulary

`critical | high | medium | low | support | varies`. `support` = cannot be reported alone; it produces a link
in a chain or a rating input. `varies` = rated on demonstrated impact (the VRT node is a "varies" node).
A cell may name a standalone level and a chained level, in either order — `Medium standalone; High with a reach
primitive`, `High (debug certificate) / Low (SHA1withRSA alone)`, `Critical … down to Low`. The build records
the **least** severe level named as `severity_floor` (the standalone level) and the **most** severe as
`severity` (the ceiling: what the Proof plus the one partner the cell names can demonstrate) and keeps the raw
text as `severity_note`. A cell that starts with `Support` stays `support` whatever else it names. The
tracker's `severity_ceiling` column is therefore the chained ceiling *as the cell states it*; anything the chain
reaches beyond what the cell names belongs in `Escalation`, not in the cell. An empty cell is an error.

## 4. `Requires` tags — the applicability vocabulary

An item carries the tags that must all be true for it to apply. The engagement records the facts in
`engagement.json` (`target.framework`, `target.targetSdk`, `target.minSdk`, `app_facts.*` filled in P2/P3,
`lab.mode`, `accounts`, `authorisation.scope`). `scripts/scope.py` (planned; not shipped yet) will propose
`n/a` or `blocked` rows with generated reasons from these tags; until then the `requires` column of
`checklist.csv` and the card are what a model reads to skip a block of items. Untagged items are always
applicable.

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
| `api<op>N` · `targetsdk<op>N` · `minsdk<op>N` with `<op>` one of `<`, `<=`, `=`, `>=`, `>` and N one or two digits | numeric gates on the app or device (`api` = the device/emulator API level) | `target.*`, device API |
| `legacy` | the item is only reachable on builds below a stated gate; always paired with a numeric tag | — |

The numeric grammar is exactly `REQ_NUM` in `scripts/lint-checklist.py`:
`^(api|targetsdk|minsdk)(<=|>=|<|>|=)\d{1,2}$`. Example: `| **Requires** | webview, js-bridge, targetsdk<17, legacy |`
for the reflection escape. The build exposes the tags as `requires_tags` (json) and `requires` (csv).

## 5. `Record` — the evidence contract

A metadata row (not a body bullet; the pre-schema `- **Record:**` bullet is still read and folded into the
row). Name the artefacts the item produces so a future session and a triager can find them without reading
the notes: `logs/Dnn-NNN.txt` (raw tool output, always — the linter warns when the row does not name it),
`screenshots/Dnn-NNN-<n>.png`, `requests/E-NNN.http`, `pocs/F-NNN/` for anything that became a finding.
The tracker row's `evidence` column points at the first of these.

## 6. What the linter checks

Errors (exit 1):

- a missing required section (§2, except the Applicability probe) · a missing required metadata row or
  body field · a metadata row that is empty or not closed with `|` · an item heading that does not parse ·
  a chapter with no parseable item · non-contiguous or duplicate ids · `SANE-` prefixes
- a severity cell with no recognisable level · an `Attacker` cell with no `AM-xx` (unless `n/a`) · a
  backticked VRT path whose category exists in `data/vrt.csv` but the path does not · a `Requires` tag
  outside §4
- a MASTG/MASWE/MASVS id (shorthand lists such as `MASTG-TEST-0224, -0225` and `MASVS-AUTH-1/2` are
  expanded first) not in `data/standards-index.csv`, in items and in the chapter's intro/Graveyard/joins/Sources
- a reference to an item or domain that does not exist (`--strict`: also a domain declared in the registry
  without a chapter) · a dead relative link in any markdown file, hidden directories and templates included
- an operator or laptop path (the `STYLE_ERR` patterns in `scripts/lint-checklist.py`: the known operator
  folder names and `/Users/<name>/`) in any operator-facing file, and a real target name listed in
  `SANE_LINT_TARGET_NAMES` (a comma-separated env var; keep the list outside the repo)

Warnings (reported, do not fail): a chapter without `## Applicability probe` · the count of items without
`Requires` / `Record` / `Skip when` · a deprecated row (§7) · a VRT cell outside the §1 grammar · a dotted
path in the VRT cell that is not a VRT category · a `Record` row that does not name `logs/Dnn-NNN.txt` · a
citation of a placeholder or deprecated MASTG page without saying so (tests: the `covered_by` replacement;
tools/knowledge: cite a current page) · an unknown `mastg-android-*` rule id · a `Ruled out when` shorter
than a mechanism · duplicate item titles across chapters · `jadx_out`/`apktool_out`, `frida -U`,
`--no-pause`, `sed -i` (per file, with the first line numbers) · a vendor model name, `your Mac`,
`brew install` without the Linux form, or a macOS SDK path.

Reviewed by hand (no lint rule): whether `Test` states a mechanism, whether `Proof` is an observable,
whether `Escalation` names real partners, whether `$DEC` is used consistently inside a command.

## 7. Deprecated rows

`Prerequisites`, `Depends on`, `Evidence`, `Cost` were metadata rows of an earlier draft. No chapter uses
them. The build still parses them (into `legacy_meta`, only when present) and `item.py` renders them marked
deprecated; the linter warns. Fold their content into `Applies to` / `Requires` (prerequisites and
dependencies), `Record` (evidence) and `Skip when` (cost of the probe) and delete the row.
