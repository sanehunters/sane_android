# inventory/ — dimension 2 of coverage: every instance that exists in THIS app

Generated in P3 by `python3 scripts/inventory.py base.apk --out <eng>/inventory/`, then completed by hand:

| File | One row per | ID | Filled by |
|---|---|---|---|
| `components.csv` | exported/declared component and custom permission | `C-NNN` | inventory.py |
| `deeplinks.csv` | deep-link / App Link pattern | `U-NNN` | inventory.py (+ `tools/04-applink-verify.sh`) |
| `webviews.csv` | WebView instance and bridge method | `W-NNN` | you, during D10 |
| `endpoints.csv` | backend route | `E-NNN` | `tools/06-secrets-endpoints.sh` + you |

Every row starts `tested=false`. If a register is genuinely empty (the app has no exported components),
write `inventory/EMPTY-<register>.md` — `<register>` is one of the four file stems `components`, `deeplinks`,
`webviews`, `endpoints` — with the manifest or code evidence; `scripts/gate.py p3` accepts that instead of rows
(a missing or row-less register without its `EMPTY-<register>.md` keeps the gate closed). The P7 gate stays
closed while any row is `tested=false`.
