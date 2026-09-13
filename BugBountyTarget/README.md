# BugBountyTarget — the engagement archive

One folder per engagement. Named `<Target>_<DDMMYYYY>`, e.g. `Nisho_07092026`.

This is the permanent record. A session opened years from now reads these folders to know what was
tested, what was found, what was ruled out and why — across every target we have ever assessed.

```
BugBountyTarget/
├── _TEMPLATE/              copy this to start
├── Nisho_07092026/
├── Blinkit_12082026/
└── Zomato_11092026/
```

---

## Start an engagement

```bash
~/sane_android/scripts/new-engagement.sh Nisho
```

That creates the GitHub-side folder, the local mirror at
`~/AndroidStudioProjects/lamppentest/<target>/`, and seeds `checklist-status.csv` with every checkpoint
set to `false`.

## The dual-write rule

Every artefact is written to **both** places, continuously, not at the end:

| | Path |
|---|---|
| **GitHub** | `~/sane_android/BugBountyTarget/<Target>_<DDMMYYYY>/` — committed and **pushed after every phase** |
| **Local** | `~/AndroidStudioProjects/lamppentest/<target>/` — the operator's working tree |

An engagement that exists only in a context window is lost work.

---

## The folder contract

| Directory | Contents | Committed? |
|---|---|---|
| `apk/` | The APK set, hashes, `versions.txt` | ❌ hashes and metadata only |
| `decompiled/` | jadx / apktool output | ❌ never |
| `recon/` | `manifest.md` `components.md` `deep-links.md` `webviews.md` `apis.md` `permissions.md` `dependencies.md` `native.md` | ✅ |
| `inventory/` | Machine-readable surface inventory (CSV/JSON from `tools/`) | ✅ |
| `hypotheses/` | One file per untested idea, with the experiment that would settle it | ✅ |
| `findings/F-0NN/` | Working notes per finding | ✅ |
| `chains/` | Multi-primitive chains, each link with its status | ✅ |
| `pocs/F-0NN/` | Attacker-app source and prebuilt APK | ✅ source only |
| `videos/F-0NN/` | PoC recordings | ✅ if under 5 MB |
| `screenshots/F-0NN/` | Stills. **Redact third-party data before committing.** | ✅ |
| `logs/F-0NN/` | logcat, tool output | ✅ |
| `requests/` `responses/` | HTTP captures. **Strip credentials.** | ✅ sanitised |
| `report/` | `assessment-status.md` `findings-index.md` `api-map.md` | ✅ |
| `final/` | `hackerone-F-0NN.md` submissions, `verified-findings.md`, `submission-checklist.md`, triage replies | ✅ |
| `scripts/` | Target-specific scripts you wrote | ✅ |
| `checklist-status.csv` | **Coverage tracker — every checkpoint `true`/`false`** | ✅ |

### Never commit

APKs · decompiled trees · videos over 5 MB · credentials or tokens · any third party's real data ·
un-redacted screenshots of other people's information.

`.gitignore` blocks most of this. **Check before every push.**

---

## The three files that carry the engagement

### `report/assessment-status.md` — the resume point
A future session reads this **first**. Sections: `COMPLETED` · `IN PROGRESS` · `FINDINGS` ·
`RULED OUT` · `NEXT TARGET (ordered by expected value)` · `BLOCKERS (stated, not faked)` ·
`CHAINING IDEAS`.

### `report/findings-index.md` — the finding table
ID · title · status · severity · CWE · component. Plus severity reasoning and a
**"Ruled out — do NOT re-walk"** list. That list is what stops the next session wasting a day.

### `checklist-status.csv` — the coverage contract
One row per checkpoint. The assessment is **not complete** while any in-scope row is `false`.

```bash
python3 ~/sane_android/scripts/coverage.py Nisho_07092026/checklist-status.csv
```

---

## Finding IDs

`F-001`, `F-002`, … sequential within an engagement, assigned at discovery and never reused — even if
the finding is later retracted. A retracted finding stays in the index, struck through, with the
refutation. That is what makes the surviving findings credible.

## Cross-target queries

```bash
# every finding across every engagement
grep -h '^| F-' BugBountyTarget/*/report/findings-index.md

# which targets we tested for exported providers
grep -l 'D07-' BugBountyTarget/*/checklist-status.csv

# portfolio coverage
for f in BugBountyTarget/*/checklist-status.csv; do
  echo "$(dirname $f): $(python3 scripts/coverage.py "$f" --brief)"
done
```
