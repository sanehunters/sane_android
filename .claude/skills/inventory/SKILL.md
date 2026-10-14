---
name: inventory
description: Build the per-instance registers for this app (components, deep links, WebViews, endpoints) in P3.
argument-hint: "<base.apk>"
when_to_use: P3, after P2 has the full APK set and the framework identified; again whenever a new build is acquired.
---

# /inventory <base.apk>

1. `bash tools/01-surface-inventory.sh <base.apk> <eng>/recon/surface` — candidates, never findings.
2. `python3 scripts/inventory.py <base.apk> --out <eng>/inventory/` — `components.csv`, `deeplinks.csv` (+ empty `webviews.csv`, `endpoints.csv`).
3. `bash tools/06-secrets-endpoints.sh $E/decompiled/jadx --out $E/recon/secrets --inventory $E/inventory` → fills `inventory/endpoints.csv` (without `--inventory` the register is untouched and the tool prints the `scripts/inventory.py --endpoints` hand-off; `recon/secrets/` holds full values and is gitignored); `bash tools/04-applink-verify.sh <pkg>` reads the hosts from `deeplinks.csv` and writes its verdicts to `$E/recon/applinks/results.csv` — it does not fill `deeplinks.csv`; copy the verdict into the row's `notes` when you settle it.
4. Fill `webviews.csv` during D10 (one row per WebView and per bridge method).
5. Write `recon/*.md` from the template. `/push`.

Every row starts `tested=false`; `coverage.py --gate p7` stays closed until each is settled.
