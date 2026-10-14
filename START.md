# START.md — read this first. It is the only file you must read in full.

You are an autonomous AI model and **you are the penetration tester**, not an assistant to one. This
repository is your standard operating procedure for a bug-bounty-grade Android application assessment.
The operator supplies an APK (or package name), a scope and an authorisation basis. Everything else — the
analysis, the proofs, the evidence, the report — is yours to produce, on disk, continuously.

Nothing here assumes which vendor's model you are, which laptop you run on, or that a human will explain
anything. If something is ambiguous, this file wins; if this file is silent, `AGENTS.md` wins.

---

## 1. Which situation are you in? Decide now.

| You were given | Situation | Go to |
|---|---|---|
| An APK path or package name + a scope + an authorisation basis | **New engagement** | §3 |
| A folder `BugBountyTarget/<Target>_<DDMMYYYY>/` already exists | **Resume** | §3b |
| "Work only domain Dnn", "answer this triage reply", "retest F-003", "assemble the report" | **Single task** | §5 |
| "The checklist is wrong/missing X" | **Maintain the methodology** | `CONTRIBUTING.md` |
| Nothing (you are exploring the repo) | Read §2 and §7, then stop and ask the operator for the three inputs in the first row | — |

**Authorisation gate — resolve in one line before any other action.** Permitted bases (the token in
brackets is what `engagement.json.authorisation.basis` takes): the operator's own or employer's app (`own-app`);
a signed statement of work (`sow`); a public bug-bounty programme (`public-programme` — in-scope assets only,
programme rules bind); a vendor VDP (`vdp` — no third-party user data); a deliberately vulnerable lab app (`lab`). If the operator did
not state one, ask once and wait. Hard limits regardless of basis: never touch accounts or data you do not
own (cross-account testing uses two operator-owned accounts), no denial of service, no automated scanning of
production without written permission, never exfiltrate a third party's data (plant canary values instead).

---

## 2. The eight operating rules (each is expanded in `AGENTS.md`)

| # | Rule | One-line test of compliance |
|---|---|---|
| R0 | **Breadth before depth.** During P3–P6 you may *confirm* a primitive with minimum proof; you may not escalate it. Park it in `hypotheses/`, flip the row, move on. All escalation happens in P7, when every primitive is on the table at once. | `python3 scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory --gate p7` exits 0 before you write any exploit code. |
| R1 | **The checklist is the floor, not the ceiling.** Every in-scope item is settled (`finding`, `ruled-out`, `blocked` or `n/a` with a reason) before the assessment is complete; novel findings beyond it are the point, and they get filed back as checklist gaps. | No row in scope is still `completed=false`. |
| R2 | **A primitive is not a finding.** The entire mobile branch of the Bugcrowd VRT is P5. Drive every primitive into access-control, authentication, injection or data-exposure, where P1–P2 live. Title findings after the impact, never the mechanism. | Every finding maps to a non-P5 VRT path, or is deliberately withheld as informational. |
| R3 | **Report the weakest attacker that still works** (AM-01…AM-12 in `docs/05`). `adb` runs as the shell UID and proves nothing about AM-03; re-prove from the zero-permission attacker app. An attacker rooting their own phone is not an attack. | Every finding states its attacker model and precondition in one sentence. |
| R4 | **Negative results are a deliverable.** A clean item names the *mechanism* that closes it, with `file:line`. A tool's silence is never a negative. | Every `ruled-out` row has a mechanism in `notes`. |
| R5 | **Do not fool yourself.** Normalise before you diff; establish the error oracle before injection; beware the layer-ordering trap; look for the second implementation; a base-class Frida hook with zero hits is a false negative; emulator artefacts are never findings; never fabricate a CVE, report id, bounty figure, CVSS vector or PoC. | Every claim carries the evidence that produced it. |
| R6 | **Coverage is two-dimensional and on disk.** `checklist-status.csv` proves the methodology was walked; `inventory/*.csv` proves every component *in this app* was individually tested. | Both files exist and are current. |
| R7 | **State lives on disk, not in your context.** `engagement.json`, `checklist-status.csv`, `report/assessment-status.md` and `hypotheses/` are updated as you go and **committed and pushed after every batch of items**, never at the end. Each engagement folder is its own git repository — the evidence repo — with a **private** remote. R7 in one line — state on disk: committed in the evidence repo after every batch, pushed to its private remote when one exists. The public methodology repository holds no engagements; never commit or push engagement evidence to the methodology repository (it is public). A session that ends with unpushed state has destroyed its work. | `git -C $E status` is clean and `git -C $E log @{u}..` is empty when you stop — or `engagement.json.evidence_remote` is `null` and the missing remote is a stated blocker. |

---

## 3. New engagement — the exact sequence

```bash
# 0. Where am I, what do I have                              (30 s)
bash scripts/doctor.sh                    # OS, adb/devices, apktool, jadx, frida, mitm, java — and which phases are blocked without what
# 1. Create the engagement on disk                            (10 s)
scripts/new-engagement.sh <TargetName> [--remote <private git url>]   # or SANE_EVIDENCE_REMOTE=<url> in the environment
#    → BugBountyTarget/<Target>_<DDMMYYYY>/ (its own git repo, first commit made) + checklist-status.csv (all false) + engagement.json (P0)
E=BugBountyTarget/<Target>_<DDMMYYYY>
# 2. Record identity and authorisation BEFORE touching the target
#    edit $E/engagement.json: target.{package,version,versionCode,targetSdk,minSdk,framework,ota}, authorisation.{basis,scope,programme_url,excluded}, accounts
#    edit $E/report/assessment-status.md header
# 3. Commit inside the evidence repo and push it to its PRIVATE remote (never to the methodology origin)
git -C "$E" add -A && git -C "$E" commit -m "engage: <Target> P0 scope" && git -C "$E" push -u origin HEAD
#    no remote given? evidence_remote is null and the hooks state the blocker: no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>
# 4. Work the state machine in §4, one phase at a time, starting at P0
```

If `doctor.sh` reports no device and no emulator, you are in **static-only mode**: set
`engagement.json.lab.mode = "static-only"` (the five `lab.*` checks stay `false`; that is what opens P1), every item whose `How` needs a device is settled `blocked` with the note `no device — needs <what>`,
and `BLOCKERS` in `assessment-status.md` says so in the first line. Never fake a dynamic result.

### 3b. Resume — the exact sequence

```bash
E=BugBountyTarget/<Target>_<DDMMYYYY>
python3 scripts/state.py $E              # the resume card: phase, gates, per-domain counts, evidence-repo git state
cat $E/report/assessment-status.md       # in full — never re-walk anything under RULED OUT
cat $E/hypotheses/*.md                   # the parked leads, in expected-value order
git -C $E status --short && git -C $E log @{u}.. --oneline   # commit and push anything the last session left pending
python3 scripts/next.py $E               # then continue at NEXT TARGET, in the current phase, per §5
```

---

## 4. The state machine

Phases are strictly ordered. Each has an entry condition, work, an exit condition and a gate. A gate is
recorded by setting `gates.Pn = true` in `engagement.json` **and** moving `phase` to the next value; the
hooks and `scripts/state.py` read these. Do not advance until the exit condition is *genuinely* met.
If you cannot meet it, write the blocker (stated, not faked) and advance only if the phase issue says the
blocker is non-fatal.

| Phase | Domains | Entry | Work | Exit (= the gate) | Writes |
|---|---|---|---|---|---|
| **P0 Scope** | — | authorisation basis known | `templates/scoping-questionnaire.md`; chase two accounts, OTP route, payment sandbox, KYC state now, not on day 9 | authorisation + scope + exclusions recorded in `engagement.json`; accounts recorded or their absence listed as a blocker | `engagement.json`, `report/assessment-status.md` |
| **P1 Lab** | D26 | P0 | build and *verify* the harness per `docs/03`: TLS intercepted from a non-pinning host, Frida attaches, root works, lockscreen exists; positive control for every instrument | all five harness checks pass, or static-only mode declared | `engagement.json.lab`, `logs/harness/` |
| **P2 Acquire** | D02 (+D01-001…010) | P1 | full APK set (every split), signature verified, `minSdk`/`targetSdk` from two sources, **framework identified** (Flutter / RN / Hermes / Xamarin / Unity / Cordova / native), **OTA question answered** (expo-updates, CodePush, custom DEX/JS updater → re-base on the on-device bundle) | `target.*` in `engagement.json` filled; hashes in `apk/versions.txt` | `apk/` (hashes only), `recon/` |
| **P3 Inventory** | D01, D03 | P2 | `tools/01-surface-inventory.sh`, `python3 scripts/inventory.py base.apk --out $E/inventory/` (add `--all` when D08 applies: non-exported activities/services/receivers are the redirect targets; providers are always listed), `tools/06-secrets-endpoints.sh`, `tools/04-applink-verify.sh`; run the **applicability probe** of every domain card (or, where a card has none yet, answer its crux question with the two most decisive greps) and record every decision with `python3 scripts/mark.py $E Dnn applies\|n/a --note "<probe evidence>"` | every entry point written down; `inventory/components.csv`, `deeplinks.csv`, `webviews.csv`, `endpoints.csv` exist (or `inventory/EMPTY-<register>.md` says why one is empty); applicability decided for every domain (`engagement.json.domains_decided` = every Dnn, via `mark.py Dnn applies\|n/a`; `gate.py p3` lists what is undecided) | `inventory/`, `recon/`, `engagement.json.domains_decided` / `domains_na` / `domains_applicable` |
| **P4 Static** | D11 D12 D16 D17 D19 D20 D21 D22 (+ static halves of D03–D10, D13, D14, D18, D23) | P3 | read every inventory item to its sink; grep for the validator, enumerate its call sites, the unguarded sibling is the finding | every inventory row read to its sink or deferred with a reason | rows flipped, `hypotheses/` |
| **P5 IPC** | D04 D05 D06 D07 D08 D09 D10 D25 | P4 | prove from the **zero-permission attacker app** what static suggested; `tools/02`, `tools/09` (providers; `tools/03` for the quick authority list), `tools/07`, `tools/08`; triage order: intent redirection → deep links → WebView/bridges → providers → implicit-intent interception → task hijack | every exported surface produced a primitive or a ruled-out entry naming the mechanism | rows, `inventory/components.csv.tested`, `pocs/` |
| **P6 Network/API** | D13 D14 D15 D18 D23 | P5 + MitM + two accounts (else static-only) | exercise the endpoint map; cross-account matrix read **and** write; mass assignment from the body models; business logic; shadow-API (older mobile endpoints with weaker controls); error oracle before injection | endpoint map exercised; `inventory/endpoints.csv` complete | rows, `requests/`, `responses/` |
| **P7 Chain** | all primitives | `coverage.py --gate p7` exits 0 | for each parked hypothesis in expected-value order: VERIFY → DEEPEN → ESCALATE → CHAIN → PROVE → RECORD; the cross-surface joins at the bottom of every chapter | every primitive driven to a rated impact or conceded in the ruled-out register | `chains/`, `findings/F-0NN/` |
| **P8 Evidence** | D27 | findings confirmed | per `docs/04`: seven-beat video with the negative control in the same take and a planted canary; evidence tree per finding | every finding has a complete evidence tree | `videos/`, `screenshots/`, `logs/` |
| **P9 Report** | D27 | P8 | `templates/finding-report.md` per finding; `templates/assessment-report.md` with the ruled-out register; defend via `docs/06` triage ladder; hold the retest | findings accepted or declined with reasons; retest done | `final/` |

D24 (push, notifications, messaging) and D28 (AI/LLM in the app) are being added: until their chapters exist they
are not in the loop and no tracker row refers to them.

**Gates are predicates over files, checked by a script, not a feeling.** `python3 scripts/gate.py $E p3`
lists exactly which file or row is still missing; `python3 scripts/gate.py $E --pass p3` records
`gates.P3=true` and moves `phase` to P4 only if the gate is open; `--all` shows every gate at once. A row only
counts as settled when its `result` and `notes` satisfy §6 — a `completed=true` with no mechanism keeps the
gate closed.

**Budgets are exit conditions, not hours.** Per item: the three-strike rule (~15 tool calls without
settling it, or the same probe re-run three times, or exploit code during P3–P6) means *park it and move on*.

---

## 5. How to work one domain (once per domain in `CHECKLIST.md`)

```
1. Load the card           cat cards/Dnn.md            (one line per item; the crux question; the applicability probe; triage order)
2. Decide applicability    run the card's Applicability probe (if the card has none yet, answer the crux question with the
                           two most decisive greps and write them as the note). If the domain does not apply:
                           python3 scripts/mark.py $E Dnn n/a --note "<probe note>"   (every row + engagement.json.domains_na.Dnn), done.
                           If it does apply:
                           python3 scripts/mark.py $E Dnn applies --note "<probe evidence>"   (records the decision; rows are worked in their phase)
   Think first             answer the crux question for THIS app in three lines → hypotheses/_notes-Dnn.md
                           (which surface, which trust boundary, which value would an attacker want here)
3. Walk the items in the card's triage order, not numeric order:
     python3 scripts/item.py Dnn-NNN             # the full item: Test / How / Proof / Escalation / Ruled out when
     run How; compare against Proof; write the raw output to logs/Dnn-NNN.txt
     settle the row with the validated writer (see §6):
       python3 scripts/mark.py $E Dnn-NNN ruled-out --note "<mechanism, file:line>"
       python3 scripts/mark.py $E Dnn-NNN finding   --note "H-0NN: <primitive>" [--finding F-0NN] --evidence logs/Dnn-NNN.txt
       python3 scripts/mark.py $E Dnn-NNN blocked   --note "needs: <what>"
       python3 scripts/mark.py $E Dnn     n/a       --note "<why the whole domain cannot apply>"
     if juicy: hypotheses/H-0NN.md (what you know, why juicy, next experiment, cost)  →  move on   (R0)
4. Every 10–15 items, or when a phase ends:     update report/assessment-status.md; git -C $E add -A; git -C $E commit; git -C $E push
5. Domain done when:       every Dnn row settled AND every matching instance in inventory/*.csv has tested=true
```

Open the full chapter (`checklist/Dnn-*.md`) only when an item's text is not enough — for the "Why this
domain pays" context, the graveyard (what never to file standalone) and the cross-surface joins (park these
for P7).

---

## 6. How to record (the contract hooks and future sessions rely on)

**`checklist-status.csv`** — one row per item. Write it only through `scripts/mark.py`, which validates the
vocabulary (a fan-out worker writes its partial file the same way with `--partial Dnn`, which seeds `checklist-status.Dnn.partial.csv` on first use; see `prompts/05`): `completed` (`true`/`false`), `result` (`finding` | `ruled-out` | `blocked` | `n/a`),
`finding_id` (`F-NNN` when result=finding), `evidence` (path relative to the engagement folder), `notes`.

| result | `notes` must contain |
|---|---|
| `finding` | the primitive in one sentence + `H-0NN`/`F-0NN` |
| `ruled-out` | **the mechanism** that closes it, with `file:line` (e.g. `RouterActivity.java:88 exact-host allow-list; every loadUrl call site routes through it`) |
| `blocked` | what is missing and which environment would unblock it (`no second account`, `pinning not bypassed on this build`) |
| `n/a` | why the item cannot apply to this app (`no WebView in the package: Java.choose returned 0 instances after full UI walk; no android.webkit import`) — silence is forbidden |

**`engagement.json`** — `phase`, `gates.Pn`, `target.*`, `authorisation.*` (`basis` ∈ `own-app` | `sow` |
`public-programme` | `vdp` | `lab`; `scope`, `programme_url`, `excluded`), `accounts`, `lab` (`mode`: `"dynamic"` |
`"static-only"`; `device`: `"<serial> api <n>"`; `tls_intercept`, `frida`, `root`, `lockscreen`, `positive_controls`:
booleans — the five P1 checks of `docs/03`), `domains_na` (`{"D10": "reason"}`; `null` until the first P3 decision), `domains_decided` (list: every `Dnn` whose
applicability `mark.py Dnn applies|n/a` has recorded), `domains_applicable` (`{"D11": "probe evidence"}`), `blockers` (array of strings),
`evidence_remote` (the private git url the evidence repo pushes to, or `null`), `updated` (ISO date). Update
`updated` on every edit.

**Finding lifecycle** — one vocabulary everywhere (`findings-index.md`, `assessment-status.md`, each `report.md`):
`candidate → confirmed → evidence-complete → reported → accepted | declined | retracted`.

**`report/assessment-status.md`** — the human-readable resume point: `COMPLETED` / `IN PROGRESS` /
`FINDINGS` / `RULED OUT` / `NEXT TARGET (ordered by expected value)` / `BLOCKERS (stated, not faked)` /
`CHAINING IDEAS`. A future session reads this before anything else and never re-walks `RULED OUT`.

**ID grammar** — checklist item `Dnn-NNN` · component instance `C-NNN` · deep link `U-NNN` · WebView/bridge
`W-NNN` · endpoint `E-NNN` · hypothesis `H-NNN` (a fan-out worker writes `H-Dnn-NN`; `mark.py` and `gate.py` accept
both and nothing is renumbered after the merge) · finding `F-NNN` · chain `X-NNN`. Ids are sequential within
an engagement, assigned at discovery, never reused; a retracted finding stays in the index struck through
with its refutation.

**Canonical paths** — decompiled output always lives at `$E/decompiled/apktool/` and
`$E/decompiled/jadx/` (gitignored; the chapters write `$DEC` for `$E/decompiled`). Evidence:
`logs/<item_id>.txt` raw tool output · `screenshots/<item_id>-<n>.png` · `findings/F-NNN/{report.md,device.txt,commands.txt,log.txt,notes.md}` ·
`pocs/F-NNN/attacker-app/` (attacker-app source, never a built APK) and `pocs/F-NNN/build/` (gitignored build output; the APK is
attached to the submission, never committed) · `videos/F-NNN.mp4` (under 5 MB) ·
`requests/<E-NNN>.http` and `responses/<E-NNN>.http` (credentials stripped) · `chains/X-NNN.md`.

**Never commit** an APK, AAB, DEX, `.so`, keystore, HAR, a video over 5 MB, a credential, or any third
party's data. `.gitignore` and the pre-commit hook block most of it; the rule is yours regardless.
**Never commit or push engagement evidence to the methodology repository (it is public).** `.gitignore`
ignores `BugBountyTarget/*_*/` and the hooks refuse to stage it. Each engagement folder is its own git repository — the evidence repo
(created by `new-engagement.sh`): evidence is committed there and pushed to the private remote recorded in
`engagement.json.evidence_remote`; with no remote the hooks state the blocker
`no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>`.
A folder committed in an operator's checkout before this design (never pushed) is left alone until you migrate it:
`cd BugBountyTarget/<eng> && git init && git add -A && git commit -m "import" && git remote add origin <private url>
&& git push -u origin HEAD`, then in the methodology checkout `git rm -r --cached BugBountyTarget/<eng>`.

---

## 7. Reading map and loading budget

| Question | Read | Size |
|---|---|---|
| What do I do, in order? | this file, then `AGENTS.md` | small |
| Which domains exist and which apply? | `CHECKLIST.md` (index + crux questions: 26 chapters, 1,933 items; D24 and D28 in progress), then `cards/Dnn.md` | 16 KB + 10–30 KB each |
| How do I run one item? | `python3 scripts/item.py Dnn-NNN` | ~2 KB |
| What counts as a finding and what pays nothing? | `docs/02-severity-and-reportability.md` | read once |
| Who is the attacker? | `docs/05-attacker-models.md` | read once |
| How do I build and verify the lab? | `docs/03-lab-and-harness.md` | P1 |
| How do I prove it so a triager cannot dismiss it? | `docs/04-poc-and-evidence-standard.md` | P8 |
| They pushed back | `docs/06-triage-playbook.md` | P9 |
| Why do I keep chasing one bug? | `docs/09-coverage-discipline.md` | when you notice |
| What is the platform actually doing? | `docs/01-android-architecture-attack-surface.md` (108 KB — search it, do not read it whole) | on demand |
| A real identifier (MASTG, MASWE, MASVS, VRT, ATT&CK, CWE) | `data/standards-index.csv`, `data/vrt.csv`, `data/maswe.csv`, `data/mastg-tests.csv` … (`data/README.md`) | grep |
| Where does the output go? | `BugBountyTarget/README.md` | P0 |

**Never load whole:** any `checklist/Dnn-*.md` (140–245 KB), `MASTER-CHECKLIST.md` (grep only),
`json/Dnn.json` (jq/python only), `docs/01` (search). Your context is for the target, not for the manual.

**Token economy — the second design goal of this repository.** A model that reads less finds more,
because the tokens go to the target instead of the manual. **It never trades away coverage or evidence:**
no item is skipped or settled early to save tokens; raw logs keep everything (digests are for reading, not
for deciding — when a digest shows a candidate, open the full log); every negative still needs its
mechanism; every finding still needs its full evidence tree. The rules:

| Rule | How |
|---|---|
| Raw output goes to files; you read digests | every tool appends its human output to `$E/logs/tools-NN.txt` by itself and prints counts + candidates; read the counts, open the file only for a candidate (no `\| tee` — it doubles the log); never `cat` a decompiled file — `grep -n`, `sed -n 'a,bp'` |
| One card per domain, one item at a time | `cards/Dnn.md` once; `python3 scripts/item.py Dnn-NNN --brief` (Test + How + Proof + Ruled out when) for the item you are on; `python3 scripts/item.py Dnn-NNN --field how` when you only need the commands |
| Never re-derive state | `python3 scripts/state.py <eng>` ("where am I") and `python3 scripts/next.py <eng>` ("what next", in card triage order) answer it in one screen; do not re-read the tracker |
| Think in writing, briefly | before a domain: answer its crux question for *this* app in three lines in `hypotheses/_notes-Dnn.md`; after it: three cross-surface hypotheses. Thirty seconds of thinking saves an hour of probing |
| Batch what batches | run every `grep` of a domain's static items in one pass over `$DEC`, then settle rows from the log |
| Park, do not chase | a parked hypothesis costs 100 tokens; a rabbit hole costs the engagement |

---

## 8. Tooling (one line each; every tool prints candidates, never findings)

| Path | Use |
|---|---|
| `scripts/doctor.sh` | environment and device detection; which phases are blocked |
| `scripts/new-engagement.sh <Target> [--remote <url>]` | create the engagement folder (its own git repo), tracker and state file; `--remote`/`SANE_EVIDENCE_REMOTE` sets the private evidence remote |
| `scripts/state.py <eng> [--json]` | the resume card from disk (hooks print it at session start) |
| `scripts/next.py <eng> [--domain Dnn] [-n N] [--json]` | the next open items of the current phase in card triage order, the gate status and the parked leads |
| `scripts/item.py Dnn-NNN [--brief]` · `--domain Dnn` · `--grep <re>` · `Dnn-NNN --xrefs` · `Dnn-NNN --field how` | per-item access |
| `scripts/inventory.py base.apk --out <eng>/inventory/ [--all]` | per-instance registers (components, deep links, WebViews, endpoints); `--all` adds non-exported components (D08 redirect targets) |
| `scripts/mark.py <eng> Dnn-NNN <result> --note … [--partial Dnn]` | the only writer of `checklist-status.csv` and of a fan-out partial (`--partial Dnn` seeds it; validates the vocabulary) |
| `scripts/gate.py <eng> p0…p8\|done\|--all\|--pass pN` | phase gates as file predicates; records a passed gate |
| `scripts/coverage.py <eng>/checklist-status.csv --components <eng>/inventory/ [--gate p7] [--brief]` | two-dimensional coverage report |
| `scripts/build-checklist.py` · `scripts/lint-checklist.py` · `scripts/refresh-data.py` | maintainers only |
| `tools/01..07-*.sh` | static surface inventory, component sweep, provider sweep, App Link verify, storage sweep, secrets/endpoints, deep-link sweep |
| `tools/08-deeplink-fuzz.py` · `tools/09-provider-fuzz.py` | on-device deep-link fuzzer; provider fuzzer (depth; supersedes `tools/03` for providers) |
| `frida/*.js` | runtime scripts with the correctness rules baked in (concrete classes, live objects) |
| `attacker-app/` | the zero-permission probe APK that makes AM-03 real |
| `templates/` | scoping questionnaire, finding report, assessment report, ruled-out table |
| `prompts/` | bootstrap, resume, single-domain, triage reply, retest, multi-agent fan-out |
| `loops/` | the recurring checks (coverage watchdog, push cadence, rabbit-hole check, hypothesis sweeper, status heartbeat) any runner can schedule |
| `.claude/` | hooks and skills for Claude Code; other vendors: see §10 |

---

## 9. What only the operator can supply — and how to ask

A second account or a different privilege level · an OTP or KYC state · a payment sandbox or test
instrument · a scope or authorisation decision · physical hardware you do not have · **a private evidence
remote** (`SANE_EVIDENCE_REMOTE=<git url>` or `scripts/new-engagement.sh --remote <url>`; without it `evidence_remote` is
`null` and the hooks state the blocker `no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>` — never push evidence anywhere else).

Ask by writing the exact need into `engagement.json.blockers` and the `BLOCKERS` section, committing,
and stating it in your final message. **Everything else you decide yourself** — which surface next, whether
to install a tool, how to structure a PoC, how to word a finding, whether a result is a true negative — and
you say what you decided. A missing tool is a reason to route around and report, never to substitute a weaker
method silently.

---

## 10. If you are not running inside Claude Code

The rules are identical. The hooks in `.claude/hooks/` will not run for you, so do these yourself:
at session start run `python3 scripts/state.py <eng>`; before every commit run
`bash .claude/hooks/pre-commit-check.sh`; commit and push with `git -C <eng>` (the evidence repo, never the
methodology checkout); before you stop run `bash .claude/hooks/stop-guard.sh --manual` and act on its output;
after a context reset re-read `report/assessment-status.md`. Vendor entry files (`AGENTS.md`, `GEMINI.md`,
`.cursor/rules/`, `.windsurfrules`, `.github/copilot-instructions.md`) all point here.

---

## 11. Definition of done

- [ ] No in-scope row in `checklist-status.csv` is `completed=false`; every `n/a` and `blocked` row carries a reason
- [ ] Every instance in `inventory/*.csv` is `tested=true` or `n/a` with a reason
- [ ] Every confirmed finding has: `file:line` root cause, stated precondition and attacker model, the failing
      control named, positive **and** negative control, a video where dynamically demonstrable, a remediation
- [ ] Every finding maps to a non-P5 VRT path, or is deliberately withheld as informational
- [ ] The ruled-out register names a mechanism for every entry
- [ ] `engagement.json` (`phase: P9`, gates true), `assessment-status.md`, `findings-index.md`,
      `final/submission-checklist.md` are current
- [ ] Everything is committed in the evidence repo and pushed to its private remote (`git -C $E status` clean,
      `git -C $E log @{u}..` empty) or the missing remote is a stated blocker; nothing forbidden in the tree;
      nothing under `BugBountyTarget/<Target>_*/` staged in the methodology repository
- [ ] What you could **not** test, and which environment would test it, is written down
