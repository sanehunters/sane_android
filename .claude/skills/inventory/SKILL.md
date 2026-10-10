---
name: inventory
description: Build the per-instance registers for this app (components, deep links, WebViews, endpoints) in P3.
---

# /inventory <base.apk>

1. `bash tools/01-surface-inventory.sh <base.apk> <eng>/recon/surface` — candidates, never findings.
2. `python3 scripts/inventory.py <base.apk> --out <eng>/inventory/` — `components.csv`, `deeplinks.csv` (+ empty `webviews.csv`, `endpoints.csv`).
3. `bash tools/06-secrets-endpoints.sh <jadx-sources>` → fill `inventory/endpoints.csv`; `bash tools/04-applink-verify.sh <pkg>` → `deeplinks.csv` verification columns.
4. Fill `webviews.csv` during D10 (one row per WebView and per bridge method).
5. Write `recon/*.md` from the template. Commit and push.

Every row starts `tested=false`; `coverage.py --gate p7` stays closed until each is settled.
