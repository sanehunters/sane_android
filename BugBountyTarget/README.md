# BugBountyTarget — where engagements live

One folder per engagement, named `<Target>_<DDMMYYYY>`, e.g. `Example_01012026`. **This methodology repository
is public and holds no engagements**: under `BugBountyTarget/` it tracks only this file and `_TEMPLATE/`.

Each engagement folder is **its own git repository — the evidence repo**. `scripts/new-engagement.sh` creates it
(`git init`, a `.gitignore` with the forbidden-artefact list, the pre-commit guard, the first commit
`engage: <Target> P0`). The methodology's `.gitignore` ignores `BugBountyTarget/*_*/` and the PreToolUse hook
refuses to stage an engagement path here. State still lives on disk and is still committed after every batch (R7);
"pushed" means pushed to a **private** evidence remote, one per engagement.

```
BugBountyTarget/
├── README.md               this file
├── _TEMPLATE/              copied by new-engagement.sh (includes .github/workflows for the evidence repo)
└── Example_01012026/       an engagement = a separate git repository, never tracked here
```

---

## Start an engagement

```bash
bash scripts/doctor.sh                                       # environment: dynamic or static-only
scripts/new-engagement.sh <Target> [DDMMYYYY] [--remote <private git url>]
export SANE_ENGAGEMENT="$PWD/BugBountyTarget/<Target>_<DDMMYYYY>"   # or let the hooks pick the newest folder
E="$SANE_ENGAGEMENT"
```

The evidence remote is an operator input: `SANE_EVIDENCE_REMOTE=<git url>` (env) or `--remote <url>` sets
`origin` of the evidence repo and is recorded as `engagement.json.evidence_remote`. When it is absent,
`evidence_remote` is `null`, the hooks say "no evidence remote configured: evidence is committed locally only —
set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>" as a stated blocker, and never push
anything to the methodology origin. A private remote is the operator's responsibility (START.md §9).
`SANE_LOCAL_MIRROR=/path` is an opt-in one-shot copy at creation; `SANE_ENGAGEMENT_ROOT=/path` keeps engagement
folders outside this checkout.

## Committing and pushing

```bash
python3 scripts/mark.py "$E" Dnn-NNN <result> --note "..."          # the only writer of checklist-status.csv
git -C "$E" add -A && git -C "$E" commit -m "<Target> <phase>: <what was settled>"   # after every batch (R7)
# the PostToolUse hook pushes the evidence repo to its private remote; manually: git -C "$E" push
bash .claude/hooks/pre-commit-check.sh "$E"                         # the same guard, for runners without hooks
```

An engagement that exists only in a context window is lost work. Coverage of the evidence repo:
`python3 scripts/coverage.py "$E/checklist-status.csv" --components "$E/inventory" --brief` — the template ships
`.github/workflows/coverage.yml` and `hygiene.yml` so the private repo reports the same thing in CI.

### Migrating an existing local folder

A folder committed in an operator's checkout before this design (never pushed) is left alone until you migrate it:
`cd BugBountyTarget/<eng> && git init && git add -A && git commit -m "import" && git remote add origin <private url>
&& git push -u origin HEAD`, then in the methodology checkout `git rm -r --cached BugBountyTarget/<eng>`.

---

## The folder contract (START.md §6 is the authority; `_TEMPLATE/` is the shape)

| Path | Contents (file pattern · id family) | Committed? |
|---|---|---|
| `engagement.json` | phase, gates, target, authorisation, accounts, `lab`, `domains_na`, `blockers`, `evidence_remote` | ✅ |
| `checklist-status.csv` | the coverage tracker, one row per item `Dnn-NNN`; written only through `scripts/mark.py` (`result` ∈ finding · ruled-out · blocked · n/a, `notes` = the mechanism) | ✅ |
| `apk/` | `versions.txt` — hashes, signer, split list. The binaries themselves | ✅ versions.txt only |
| `decompiled/` | `jadx/`, `apktool/` (`$DEC`) | ❌ never (regenerable) |
| `recon/` | `manifest.md` `components.md` `deep-links.md` `webviews.md` `apis.md` `permissions.md` `dependencies.md` `native.md` | ✅ |
| `inventory/` | `components.csv` (`C-NNN`) · `deeplinks.csv` (`U-NNN`) · `webviews.csv` (`W-NNN`) · `endpoints.csv` (`E-NNN`) from `scripts/inventory.py`; `EMPTY-<register>.md` for a genuinely empty register | ✅ |
| `hypotheses/` | `H-NNN.md`, one parked lead each (copy `H-000-TEMPLATE.md`) | ✅ |
| `findings/F-NNN/` | `report.md` (from `templates/finding-report.md`), `device.txt`, `commands.txt`, `notes.md` | ✅ |
| `chains/` | `X-NNN.md`, one row per link with its status | ✅ |
| `pocs/F-NNN/` | attacker-app **source** — never a built APK (hashes of a delivered build go in `apk/versions.txt`) | ✅ source only |
| `videos/` | `F-NNN.mp4`, one continuous take, under 5 MB | ✅ |
| `screenshots/` | `<item_id>-<n>.png` — **redact third-party data before committing** | ✅ |
| `logs/` | `<item_id>.txt` raw tool output · `harness/` (lab verification) · `compactions.log` · `loop-*.log` | ✅ |
| `requests/` `responses/` | `<E-NNN>.http` — credentials stripped | ✅ sanitised |
| `report/` | `assessment-status.md` (resume point) · `findings-index.md` | ✅ |
| `final/` | `assessment-report.md` · `submission-checklist.md` · per-finding programme submissions · `triage-F-NNN.md` | ✅ |
| `scripts/` | target-specific scripts you wrote | ✅ |
| `state-snapshot.json`, `secrets/`, `jadx_out/`, `apktool_out/`, `sensitive/` | regenerable or secret-bearing scratch | ❌ ignored |

### Never commit

APKs · decompiled trees · videos over 5 MB · credentials or tokens · any third party's real data ·
un-redacted screenshots of other people's information · **anything under an engagement folder to the
methodology repository**.

The evidence repo's `.gitignore` and pre-commit hook block most of this. **Check before every push.**

---

## The three files that carry the engagement

### `report/assessment-status.md` — the resume point
A future session reads this **first**. Sections: `COMPLETED` · `IN PROGRESS` · `FINDINGS` ·
`RULED OUT` · `NEXT TARGET (ordered by expected value)` · `BLOCKERS (stated, not faked)` ·
`CHAINING IDEAS`.

### `report/findings-index.md` — the finding table
ID · title · status (`candidate → confirmed → evidence-complete → reported → accepted | declined | retracted`) ·
severity · CWE · component. Plus severity reasoning and a **"Ruled out — do NOT re-walk"** list. That list is
what stops the next session wasting a day.

### `checklist-status.csv` — the coverage contract
One row per item. The assessment is **not complete** while any in-scope row is open (`completed=false`) or
settled without a valid `result`/`notes` pair (`scripts/gate.py` and `scripts/coverage.py` reject those rows).

```bash
python3 scripts/coverage.py "$E/checklist-status.csv" --components "$E/inventory"
```

---

## Finding IDs

`F-001`, `F-002`, … sequential within an engagement, assigned at discovery and never reused — even if
the finding is later retracted. A retracted finding stays in the index, struck through, with the
refutation. That is what makes the surviving findings credible.

## Cross-engagement queries (over the evidence repos you have checked out locally)

```bash
# every finding across every engagement
grep -h '^| F-' BugBountyTarget/*/report/findings-index.md

# which engagements recorded a D07 finding
grep -l 'D07-.*,true,finding' BugBountyTarget/*/checklist-status.csv

# portfolio coverage
for f in BugBountyTarget/*/checklist-status.csv; do
  echo "$(dirname "$f"): $(python3 scripts/coverage.py "$f" --brief)"
done
```
