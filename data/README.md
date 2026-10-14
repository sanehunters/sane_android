# data/ — the standards the checklist cites, regenerated from primary sources

Every file here is **generated** by `python3 scripts/refresh-data.py` from clones of the public sources;
`versions.json` records the exact commit and date of each source. Nothing is typed by hand, so an
identifier in a chapter either exists here or the linter rejects it. **Never invent an identifier.**

| File | Rows | What | Key columns |
|---|---|---|---|
| `standards-index.csv` | 671 | every MASTG (TEST/TECH/TOOL/KNOW/BEST/APP/DEMO), MASWE and MASVS id the linter accepts | `id, kind, status, platform, title, url` |
| `mastg-tests.csv` | 163 | MASTG Android tests, **with status**: `current` (v2), `deprecated` (v1, superseded — see `covered_by`), `placeholder` (no content yet). Cite v2 ids; if you cite a deprecated one, say so | `id, version, status, masvs_v2_ids, maswe_ids, covered_by, knowledge_ids, apis` |
| `mastg-techniques.csv` · `mastg-tools.csv` · `mastg-knowledge.csv` · `mastg-best-practices.csv` · `mastg-apps.csv` · `mastg-demos.csv` | 91 · 81 · 75 · 44 · 22 · 94 | the other MASTG object types, Android + generic + network, with `status` (three tools are deprecated upstream) | `id, status, platform, title, url` (+ `test_id, rule_files` for demos) |
| `mastg-rules.csv` | 71 | the MASTG semgrep rules and the tests they implement | `rule_id, rule_file, severity, test_ids` |
| `maswe.csv` | 77 | MASWE weaknesses applicable to Android, with MASVS v2, CWE and the MASTG v2 tests that cover each (37 have no Android test yet — the checklist must cover those itself) | `id, title, masvs_v2_ids, cwe_ids, mastg_test_ids` |
| `masvs-controls.csv` | 24 | MASVS v2 controls | `id, group, statement` |
| `vrt.csv` | 581 | Bugcrowd VRT, every node, with `priority` as `P1`…`P5`, **`varies`** (rated on impact) or empty (parent category), plus CWE and CVSS v3/v4 mappings | `vrt_path, name, type, priority, parent, cwe, cvss_v3, cvss_v4, release` |
| `vrt-deprecated-nodes.csv` | 113 | old VRT paths → their current replacement | `old_path, vrt_version, new_path` |
| `attack-mobile-android.csv` | 122 | MITRE ATT&CK Mobile techniques whose platforms include Android, with the ATT&CK version | `id, name, tactics, platforms, attack_version` |
| `mobile-top10-2024.csv` · `cwe-top25.csv` | 10 · 25 | OWASP Mobile Top 10 2024 and the CWE Top 25 (2025). Not in the crosswalk universe: items cite them as free text (`Mobile Top 10 2024 Mn`, `CWE-n` in a Maps-to row) and the generated `docs/07` §3 derives that coverage from `json/` | `id, title` / `rank, id, name, year, url` |
| `crosswalk.csv` | 1,335 | **standard id → checklist item ids** that cite it, for every standard entry (cited or not). This is how `docs/07` is proven rather than asserted: an uncited MASWE weakness is a coverage gap | `standard, standard_id, title, known, n_items, item_ids` |
| `versions.json` | — | provenance: commit + date of each source, row counts of every file above (the two derived files included), platforms kept | |

## How a model should use this

- Need a real identifier for a finding or a Maps-to row → `grep` the id or title here; copy the id exactly.
- Rating a finding → `vrt.csv`: the `priority` column is authoritative; `varies` means "rated on demonstrated
  impact" and the finding must argue the impact; parents (empty priority) are never cited as the node.
- Citing a MASTG test → prefer `status=current`; a `deprecated` id must be written as
  `MASTG-TEST-0017 (deprecated; see MASTG-TEST-0327)`; never cite a `placeholder`. When `covered_by` names only
  placeholders (today: MASTG-TEST-0001 → 0304–0306, 0013 → 0309/0310, 0019 → 0237–0239), keep the deprecated id,
  marked deprecated, and cite the weakness from its `maswe_ids` instead.
- Proving coverage to a client → `crosswalk.csv` filtered to `n_items > 0` per standard; the rows with
  `n_items = 0` are the honest gap list; `docs/07` §1–§4 and its "Known gaps" are generated from this file and `json/` (rebuild
  with the heredoc in `docs/07` §6), so the two never disagree. The crosswalk is only as fresh as `json/`: rebuild
  it (step 3 below) whenever a chapter changed.

## Regenerate

```bash
python3 scripts/refresh-data.py             # clones/updates sources into .refs/ (gitignored), rebuilds data/ incl. vrt.csv
                                            #   needs PyYAML once (python3 -m pip install pyyaml); the script says so before cloning
python3 scripts/build-checklist.py          # views (cards/, json/, checklist.csv): VRT priorities come from the fresh vrt.csv
python3 scripts/refresh-data.py --offline   # rebuilds crosswalk.csv from the fresh json/ (no network; .refs/ already present)
python3 scripts/build-checklist.py --check  # must report current — a refresh that changed a priority is now in the views
python3 scripts/lint-checklist.py           # every cited id must still resolve
# then rebuild docs/07 (dataset table, §1–§4, Known gaps) with the heredoc in docs/07 §6; it warns when
# versions.json row_counts disagree with crosswalk.csv
```

`.refs/` holds the clones and two downloaded files (ATT&CK STIX, CWE Top 25 HTML) under `_untrusted_*`;
they are parsed only, never executed, and never committed.
