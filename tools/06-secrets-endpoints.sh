#!/usr/bin/env bash
# 06-secrets-endpoints.sh <decompiled-dir>
# Endpoint map + secret extraction. VERIFY RESTRICTION BEFORE REPORTING ANY KEY.
set -uo pipefail
DIR="${1:?usage: $0 <decompiled-dir>}"
OUT="${2:-secrets}"
mkdir -p "$OUT"

echo "[*] endpoints"
grep -rhoE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]{6,}' "$DIR" 2>/dev/null | sort -u > "$OUT/endpoints.txt"
wc -l < "$OUT/endpoints.txt" | xargs echo "    unique URLs:"

echo "[*] Retrofit/OkHttp route map (annotation VALUES survive R8 -- authoritative even when obfuscated)"
grep -rhoE '@(GET|POST|PUT|DELETE|PATCH|HEAD)\("[^"]*"' "$DIR" 2>/dev/null | sort -u > "$OUT/routes.txt"
wc -l < "$OUT/routes.txt" | xargs echo "    routes:"

echo "[*] Gson @SerializedName after R8 (mass-assignment candidates)"
grep -rhoE '@c\("[^"]*"\)|@SerializedName\("[^"]*"\)' "$DIR" 2>/dev/null | sort -u | head -200 > "$OUT/fields.txt"

echo "[*] GraphQL documents"
grep -rhoE '(query|mutation|subscription)\s+[A-Za-z0-9_]+\s*[({]' "$DIR" 2>/dev/null | sort -u > "$OUT/graphql.txt"

echo "[*] high-signal secret shapes"
grep -rhoE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]{10,}|Basic [A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' \
  "$DIR" 2>/dev/null | sort -u | tee "$OUT/secrets.txt"

echo "[*] firebase / cloud config"
grep -rhoE '[a-z0-9-]+\.firebaseio\.com|[a-z0-9-]+\.appspot\.com|firebasestorage\.googleapis\.com/v0/b/[a-z0-9.-]+' \
  "$DIR" 2>/dev/null | sort -u | tee "$OUT/cloud.txt"

cat <<'NOTE'

  ****  DO NOT REPORT A KEY UNTIL YOU HAVE VERIFIED IT IS UNRESTRICTED  ****

  Most Google/Maps/Firebase keys in APKs are package+signature restricted and are
  PUBLIC BY DESIGN. Reporting one unverified is the fastest way to lose credibility.
  VRT: sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid = P5
       sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset        = P1
  The difference is one benign probe. Run it, and record the result either way.

  Maps key:      curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=X&key=<KEY>" | head -c 300
  Firebase RTDB: curl -s "https://<project>.firebaseio.com/.json?shallow=true" | head -c 300
  FB Storage:    curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o" | head -c 300
  Record the exact response in the ruled-out table if it is restricted.
NOTE
