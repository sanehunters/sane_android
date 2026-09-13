# D11 · Local Data Storage

> Everything the app writes to disk: SharedPreferences, SQLite/Room, DataStore, MMKV, Realm, Couchbase
> Lite, files, caches, external and shared storage, the backup set, the clipboard, the keyboard cache and
> the process heap. Stated bluntly: **storage alone is P5.** Bugcrowd prices
> `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` at P5 with the
> baseline vector `AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`, and Xiaomi, Grab and Spotify list app-private
> storage as explicitly out of scope. This chapter exists to produce the **payload** for a reach primitive
> that lives in another domain, and to find the two storage sub-classes that escape P5 on their own:
> shared storage (P4) and backup/device-transfer **restore** (a write primitive, not a read one).

| | |
|---|---|
| **Phases** | P4 static deep review, P5 on-device dynamic & data-at-rest |
| **Milestones** | M4, M5 |
| **VRT ceiling** | Inside the storage branch, **P4** — `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (CWE-312). The honest ceiling is reached by **leaving the branch**: a restored backup that authenticates on an attacker device files as `broken_authentication_and_session_management.authentication_bypass` (**P1**); a server-side credential recovered from a local store files as `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) or `...for_internal_asset` (P3); a hardcoded DB passphrase files as `insecure_os_firmware.hardcoded_password.non_privileged_user` (**P2**) and, if reused across environments, `cryptographic_weakness.key_reuse.inter_environment` (**P2**). Never file a storage payload under `insecure_data_storage.*` when a reach primitive exists — file the reach. |
| **Primary attacker model** | **AM-03** zero-permission local app (shared storage, MediaStore, world-readable legacy files). **AM-04** where a routinely granted `READ_MEDIA_*` is needed. **AM-11** physical unlocked, for the backup/device-transfer restore chain. **AM-05** another user of the same app, for shared-device and account-switch residue. **AM-12 own rooted device is not an attack** and is the single most common reason a D11 report closes as informational. |
| **Maps to** | MASVS-STORAGE-1, MASVS-STORAGE-2, MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-CODE · MASTG-TEST-0009, MASTG-TEST-0200, MASTG-TEST-0201, MASTG-TEST-0202, MASTG-TEST-0203, MASTG-TEST-0207, MASTG-TEST-0216, MASTG-TEST-0231, MASTG-TEST-0258, MASTG-TEST-0262, MASTG-TEST-0287, MASTG-TEST-0304, MASTG-TEST-0305, MASTG-TEST-0306, MASTG-TEST-0316, MASTG-TEST-0011 (deprecated), MASTG-TEST-0006 (deprecated) · MASTG-TECH-0002, MASTG-TECH-0008, MASTG-TECH-0043, MASTG-TECH-0044, MASTG-TECH-0127, MASTG-TECH-0128, MASTG-TECH-0142 · MASTG-KNOW-0036, MASTG-KNOW-0037, MASTG-KNOW-0038, MASTG-KNOW-0039, MASTG-KNOW-0040, MASTG-KNOW-0041, MASTG-KNOW-0042, MASTG-KNOW-0050, MASTG-KNOW-0051, MASTG-KNOW-0055, MASTG-KNOW-0142 · MASTG-TOOL-0029, MASTG-TOOL-0106, MASTG-TOOL-0036, MASTG-TOOL-0129, MASTG-TOOL-0144 · MASTG-BEST-0004, MASTG-BEST-0019, MASTG-BEST-0050 · MASTG-DEMO-0002 · MASWE-0001, MASWE-0002, MASWE-0005, MASWE-0006, MASWE-0024, MASWE-0030, MASWE-0036, MASWE-0038, MASWE-0040, MASWE-0050, MASWE-0061 · CWE-200, CWE-256, CWE-259, CWE-276, CWE-284, CWE-312, CWE-313, CWE-321, CWE-359, CWE-459, CWE-524, CWE-532, CWE-668, CWE-729, CWE-732, CWE-919, CWE-921, CWE-922 · T1409, T1420, T1533, T1532, T1635, T1638, T1628.003, T1513, T1417.001, M1006, AN1840 |

## Why this domain pays

Mostly, it does not. The base rate of *defects* here is close to 100% — every app stores something in
cleartext — and the base rate of *payable findings* is close to zero, because the entire internal-storage
branch of the VRT is pinned at P5 and several major programmes exclude it by name. Google's Mobile VRP is
explicit that access to non-sensitive internal files of another app does not qualify. GitHub Security Lab's
$4,500 payout (H1 #1122661, CWE-312) is routinely miscited as precedent for reporting cleartext
SharedPreferences; it was a **CodeQL detection query** contributed upstream, not a report that one app stored
a token in plaintext. H1 #1225158 (Zivver), "ADB Backup is enabled within AndroidManifest", paid **$0**. If
your D11 output is a list of files containing tokens, you have produced an inventory, not findings.

Three things in this chapter escape that. **First, shared storage.** The VRT rates
`...on_external_storage` a full band higher at P4 precisely because no root is required, and the word
"external" in your title is worth a priority band. **Second, the write direction.** Backup/device-transfer
restore, MediaStore inserts with attacker-chosen `RELATIVE_PATH`, symlink races on shared directories,
hot-journal and `.bak` ghost files: these are all *writes into the victim's sandbox*, and a write that lands
on a config the app trusts or a path ART will execute is Critical, not P5. The single highest-value
inversion in this domain is to stop asking "is my token backed up" and start asking "what security-relevant
value in the backup set does the app **trust on next launch**" — an API base URL, a certificate-pin set, a
feature flag, an `is_rooted` cache, a biometric-lock boolean. Restoring an attacker-authored copy of any of
those reconfigures the app before it ever contacts the server, and restore happens after APK installation
but **before the user can launch the app**. **Third, the shared device.** The AOSP security-model paper's
threat [T.P4] — "screen unlocked (shared) devices under control of an authorized but different user" — is a
supported scenario for kiosks, POS terminals, hospital ward tablets and family devices, and nobody tests what
logout leaves on disk.

The discipline that makes the rest of the chapter worth running is that every storage observation is half a
finding. The other half is a named unprivileged reader. Write that sentence first — *which actor reads this
file, and with what* — and the rating follows mechanically: a zero-permission app reading it is High; an
unlocked-device attacker is Medium; only root reaches it, and it is Low or informational.

## The crux question

**For each sensitive value the app persists: which principal other than the app's own UID can read it, or
write it, without root — and if the answer is "none", is there any value in the backup set that the app
trusts on next launch?**

## Triage order

1. **`adb shell run-as $PKG id`.** One command decides whether the whole chapter needs root. If it works on
   a release build you also have a D02 finding, and every item below becomes a non-root PoC.
2. **Post-login sweep by file EXTENSION across the whole data dir** (D11-004). `databases/` plus
   `shared_prefs/` misses Couchbase `.cblite`, Realm, MMKV and DataStore `.preferences_pb`, all of which
   live in `files/`. Ten minutes, and it tells you what the rest of the day is about.
3. **Read the backup rules file, then exercise the D2D transport** (D11-051, D11-052). The asymmetry
   between `<cloud-backup>` and `<device-transfer>` is the least-tested configuration in Android, and a
   missing section means that mode is *fully enabled*.
4. **Grep the control-plane keys against the backup set** (D11-056). This is the item with the highest
   ceiling in the chapter and it takes one grep plus one `cat`.
5. **`getWritableDatabase("` with any string argument** (D11-023). The framework overload takes no
   argument, so an argument is SQLCipher and a literal there is the whole finding, mechanically.
6. **External / shared storage diff** (D11-041). The only storage class the VRT rates above P5 on its own.
7. **The write direction: MediaStore `RELATIVE_PATH`, symlink races, zip-slip, `Content-Disposition`**
   (D11-045 to D11-049). Slower to set up, and the only route from this chapter to Critical.
8. **Logout / account-switch / uninstall residue** (D11-033 to D11-035). Cheap, and it is the one class
   that produces a cross-user finding on a device the vendor explicitly supports sharing.
9. **Clipboard, keyboard cache, recents snapshot** (D11-059 to D11-062). All P5 by VRT. Run them for
   completeness and for the chain, never as headline findings.
10. **Memory** (D11-066, D11-067). Requires instrumentation, so it is a contributing factor that raises
    another finding's impact, not a headline of its own.

## Items

### D11-001 · The reachability rule — name the unprivileged reader before writing the word "storage"

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) — this item exists to get you **out** of that node |
| **Attacker** | AM-03 / AM-04 / AM-11; explicitly **not** AM-12 |
| **Applies to** | all — this is the gate for every other item in the chapter |
| **Maps to** | VRT baseline vector `AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`; CWE-312; MASWE-0001 |

- **Test:** Before writing anything, answer in one sentence: *which actor, holding what, reads this file?*
  The VRT encodes the answer in its tree — internal storage P5, external storage P4 — and neither is payable
  without a demonstrated reader. `AV:P` (physical) in the baseline vector is exactly the precondition you must
  remove.
- **How:**
```bash
# 1. what is there (internal)
adb shell run-as $PKG find /data/data/$PKG -type f | head -60
# 2. what is there (shared)
adb shell ls -laR /sdcard/Android/data/$PKG/ /sdcard/Download /sdcard/Android/media/$PKG 2>/dev/null
# 3. THE STEP THAT DECIDES THE RATING — read the same path from a zero-permission PoC app
#    (not from `adb shell`: shell is uid 2000 and holds permissions no third-party app has)
adb install poc-reader.apk && adb shell am start -n com.poc.reader/.MainActivity \
  --es path /sdcard/Android/data/$PKG/files/session.json
adb logcat -s POC:E -d
```
- **Proof:** Either (a) the PoC app's own logcat tag printing the file contents, or (b) a named reach
  primitive you also demonstrate — `run-as` on a shipped debuggable build (D02), a `bmgr` backup extraction,
  an exported provider read (D07), a FileProvider traversal (D07), a `file://` WebView read (D10), or a
  world-readable mode bit. Without one of those the finding is P5 and closes.
- **Escalation:** The reach primitive is the report; the storage is its payload. -> D07 providers, -> D08 URI
  grants, -> D10 WebView file read, -> D02 debuggable.
- **Ruled out when:** Every sensitive file sits under `/data/data/$PKG` with mode `0600`, the app's home
  directory is `0700` (`targetSdkVersion >= 24`), a zero-permission PoC app receives `Permission denied` on
  every path, `allowBackup` is effectively false or the rules exclude those paths, and no provider, WebView
  or debuggable path reaches them. Record the PoC app's `Permission denied` output — that is the defensible
  negative, not the absence of a scanner hit.

### D11-002 · Build the read-primitive inventory before the storage sweep, not after

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-03 |
| **Applies to** | all |
| **Maps to** | MASTG-TECH-0008; AOSP "Application Sandbox" (UID + per-app SELinux categories) |

- **Test:** Enumerate every way a non-root principal reaches `/data/data/$PKG` on this target, and record a
  yes/no for each. The list is finite: `run-as` (debuggable), same-`sharedUserId` sibling package, backup
  (`bmgr` / `adb backup` / D2D), an exported or grantable ContentProvider, a WebView with
  `setAllowFileAccess`, a file descriptor handed over binder, and a world-readable mode bit from a legacy
  write. Knowing which are open decides which storage items are worth a day.
- **How:**
```bash
adb shell run-as $PKG id                                     # debuggable?
grep -n 'sharedUserId' out/AndroidManifest.xml               # sibling UID?
adb shell pm list packages -U | grep " uid:$(adb shell dumpsys package $PKG | awk '/userId=/{print $1}' | head -1 | cut -d= -f2)"
grep -nE 'allowBackup|fullBackupContent|dataExtractionRules' out/AndroidManifest.xml
adb shell dumpsys package $PKG | sed -n '/Provider Resolver Table/,/Key Set Manager/p'
grep -rnE 'setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs' out/sources/
adb shell run-as $PKG find . -type f ! -perm 600 -exec ls -l {} \;
```
- **Proof:** A seven-row table with a yes/no and the evidence command for each primitive, pasted into the
  report's preconditions section.
- **Escalation:** Each "yes" row is itself a finding in its own domain (D02, D03, D07, D10) and should be
  filed there — see D11-070 on chain-filing order.
- **Ruled out when:** Every row is "no" **and** you have re-tested the provider row from a PoC app that
  declares `<queries>` (a caller targeting SDK 30+ cannot see an undeclared package, and that failure looks
  identical to a closed provider). A blank table with no PoC app is not a negative.

### D11-003 · `run-as` — the fastest private-storage read primitive that exists

| | |
|---|---|
| **Severity ceiling** | High (as a D02 finding on a shipped debuggable build); Support otherwise |
| **VRT** | n/a here; the debuggable flag itself is filed in D02 |
| **Attacker** | AM-11 physical unlocked with ADB authorised; AM-03 if a shell-broker app is present |
| **Applies to** | `android:debuggable="true"` builds, and all packages on `userdebug`/`eng` images |
| **Maps to** | MASTG-TECH-0008; AOSP `run-as` semantics |

- **Test:** One command tells you whether root is needed for the whole chapter. On a shipped debuggable
  release it is simultaneously a D02 High and the non-root retrieval path that lifts every storage payload
  in this chapter out of P5.
- **How:**
```bash
adb shell run-as $PKG id
adb shell run-as $PKG ls -R /data/data/$PKG
adb shell run-as $PKG cat /data/data/$PKG/shared_prefs/*.xml
adb exec-out run-as $PKG cat databases/app.db > app.db          # exfil without root
# whole-tree copy (adb pull will not traverse run-as; do it file by file)
dir="/data/data/$PKG"; IFS=$'\n'
for d in $(adb shell run-as $PKG find "$dir" -type d); do mkdir -p ".$d"; done
for f in $(adb shell run-as $PKG find "$dir" -type f); do adb exec-out run-as $PKG cat "$f" > ".$f"; done
```
- **Proof:** Content returned where a plain `adb shell cat` on the same path returns `Permission denied`.
  Show both commands side by side — that contrast is what proves the boundary and the bypass.
- **Escalation:** -> D02 (`debuggable` on a release build), -> D26 (JDWP attach gives code execution in the
  app's UID, which reaches everything in D12 and D13 as well).
- **Ruled out when:** `run-as` returns `package not debuggable` on a build whose signature matches the Play
  Store artefact, verified with `aapt dump badging` and an `apksigner verify --print-certs` comparison. A
  `run-as` failure on your own rebuilt/patched APK proves nothing about the shipped build.

### D11-004 · Sweep by file EXTENSION across the whole data dir, never by directory

| | |
|---|---|
| **Severity ceiling** | Support (the finding is whatever the sweep recovers) |
| **VRT** | n/a (enabler) |
| **Attacker** | AM-03 once paired with a reader |
| **Applies to** | all; mandatory on any app using Couchbase Lite, Realm, MMKV or DataStore |
| **Maps to** | MASTG-TECH-0008; MASTG-KNOW-0040 (Realm), MASTG-KNOW-0142 (Android DataStore) |

- **Test:** `databases/` and `shared_prefs/` are two of roughly a dozen places a modern app writes. Couchbase
  Lite `.cblite` files sit in `files/` and their contents are **plain JSON**; Realm, MMKV and DataStore
  `.preferences_pb` are also in `files/`. Sweeping by directory produces a clean-looking false negative.
- **How:** Run it *after a real login and a real transaction*, not on a fresh install:
```bash
#!/bin/bash   # astore.sh <pkg>
P=/data/data/$1
adb shell "find $P -type f" | wc -l
adb shell "grep -rlaE 'eyJ[A-Za-z0-9_-]{10,}|Bearer |access_token|refresh_token|api[_-]?key' $P 2>/dev/null"
adb shell "find $P \( -name '*.db' -o -name '*.cblite*' -o -name '*.realm' -o -name '*.preferences_pb' \
  -o -name '*.mmkv' -o -name '*.sqlite*' -o -name '*.json' -o -name '*.xml' \) 2>/dev/null"
# non-root / debuggable equivalent
adb shell run-as $1 find /data/data/$1 -type f
# once pulled:
find pulled/ \( -iname '*.cblite*' -o -iname '*.realm' -o -iname '*.db' -o -iname '*.sqlite*' \
  -o -iname '*.xml' -o -iname '*.json' -o -iname '*.mmkv' -o -iname '*.preferences_pb' \) -print
strings pulled/files/*.cblite | grep -iE 'pass|token|card|cvv|secret|auth|bearer|eyJ'
```
- **Proof:** Credential material recovered by `strings` + `grep` with **no database client at all**, with the
  full path of each file. A `.cblite` hit is the clearest demonstration in the chapter that "we use an
  embedded database" is not encryption.
- **Escalation:** Feeds every store-specific item below; the recovered token goes to D13 (what does it
  unlock?) then D15 (replay it).
- **Ruled out when:** The `find` returns no file outside `cache/`, `code_cache/` and `no_backup/` whose
  contents match the credential regexes **after** an authenticated session and a state-changing action —
  and you have confirmed the write path exists at all (D11-006) rather than concluding from an empty sweep
  on a fresh install.

### D11-005 · Differential sandbox dump with 8+ character markers, baseline-searched first

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0207, MASTG-TECH-0008, MASTG-TECH-0002, MASWE-0001, MASTG-KNOW-0041, MASTG-BEST-0050 |

- **Test:** Snapshot the data directory, exercise every sensitive flow typing **unique random markers**, snapshot
  again, diff, then hunt the markers *and their encodings*. The diff is what attributes a file to a specific
  user action, which is what makes the write-up defensible. Marker discipline is not optional: the marker
  must be 8+ random alphanumeric characters with no English word and no protocol keyword, and you must
  **search the BEFORE snapshot for the marker before claiming a hit** — a word collision in a churning
  binary cache is the commonest false positive in this domain.
- **How:**
```bash
M=x4hd2k9pq7                                            # never: test, marker, password, AAAA
adb shell run-as $PKG tar -cf - . > before.tar          # or, rooted: adb pull /data/data/$PKG ./before/
# ... log in, save a card, send a message, all using $M as the value ...
adb shell run-as $PKG tar -cf - . > after.tar
mkdir b a && tar xf before.tar -C b && tar xf after.tar -C a
grep -rl "$M" b/ && echo "BASELINE CONTAINS THE MARKER -- pick a new one, this hit is worthless"
diff -rq b a | tee changed.txt
grep -rl --binary-files=text "$M" a/
grep -rl "$(printf "$M" | base64)" a/
grep -rl "$(printf "$M" | xxd -p)" a/
grep -rl "$(printf "$M" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')" a/
```
  MASTG-TEST-0207's evaluation note is worth following literally: decode base64, hex, URL-encoding, escape
  sequences, wide characters and simple XOR, and decompress archives — "these methods obscure but do not
  protect sensitive data", so a base64'd token is still a cleartext finding.
- **Proof:** The marker, or a decodable transformation of it, present in a named file under `shared_prefs/`,
  `databases/`, `files/` or `cache/`, **and absent from the baseline**. Quote the file path and the key name.
- **Escalation:** The recovered key names become the probes for D11-004's sweep and for the backup-rules
  review (D11-051).
- **Ruled out when:** The diff shows the store changing and the marker is present in **neither** cleartext
  nor any of the listed encodings, and a `Cipher.doFinal` hook (D11-011) shows the value passing through
  encryption before the write. "Grep found nothing" without the encoding pass is not a negative.

### D11-006 · Confirm a WRITE PATH before claiming anything is persisted

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (accuracy gate) |
| **Attacker** | n/a |
| **Applies to** | all; critical on R8-minified builds |
| **Maps to** | MASTG-TEST-0287 (the `putString` hook is the write-path evidence) |

- **Test:** A field in a model class proves nothing about storage. R8 keeps Gson-annotated dead fields, and
  a payment model can declare `_all_digits`, `_cvv` and `_isCardSavedOnlyLocally` where all three are
  vestigial — no getters, and the flag only ever copied object-to-object, never gating a write. For each
  suspicious field find a `putString`/`toJson`/`insert`/file-write that actually carries it.
- **How:**
```bash
grep -rn 'edit()\.put\|putString(\|putBoolean(\|putInt(' out/sources/ | grep -iE 'token|auth|session|card|cvv|pin'
grep -rn 'openFileOutput(\|FileOutputStream(\|\.writeText(\|Files\.write(' out/sources/
grep -rn 'insert(\|Room\.databaseBuilder\|@Entity' out/sources/ | grep -iE 'card|token|user'
```
```javascript
// runtime confirmation — hook the write, print a backtrace, and watch for a preceding Cipher
Java.perform(function () {
  var E = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  E.putString.implementation = function (k, v) {
    console.log('[putString] ' + k + ' = ' + v);
    console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return this.putString(k, v);
  };
  var C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function (b) {
    console.log('[Cipher.doFinal] ' + this.getAlgorithm());
    return this.doFinal(b);
  };
});
```
- **Proof:** Either the write site with its backtrace, or the verified negative written out in full — e.g.
  "card data is never persisted locally: tokenise-and-discard, confirmed with a rooted dump taken after the
  saved-cards screen was loaded, and with a `putString` hook showing only the last four digits and the
  network token".
- **Escalation:** The verified negative is a deliverable (D27) and it is what makes the positive claims in
  the same report credible.
- **Ruled out when:** The field exists but no write site carries it and the runtime hook never fires during
  the flow that populates it. State both halves.

### D11-007 · Two storage-forensics regexes that silently return nothing

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (accuracy gate) |
| **Attacker** | n/a |
| **Applies to** | all R8-minified apps |
| **Maps to** | mechanism (observed in a real engagement; no external identifier) |

- **Test:** Two grep traps that produce clean-looking false negatives and have each caused a real "clean"
  verdict on a target that was not clean.
- **How:**
  1. **SharedPreferences integers and booleans are attributes, not element text.** `<int name="user_id"
     value="13688488" />` will never match a `name="k"[^>]*>([^<]*)<` pattern — the field renders empty and
     the extractor reports nothing.
  2. **Gson's `@SerializedName` survives R8 but its class is renamed**, typically to
     `com.google.gson.annotations.c`, so the decompiled source reads `@c("card_token")`. Grep the annotation
     **values**, not the annotation name.
```bash
# 1 — match both shapes
grep -oE '<(string|int|long|boolean|float) name="[^"]+"( value="[^"]*")?>?[^<]*' shared_prefs/*.xml
# 2 — R8-renamed annotations
grep -rnE '@[a-z]\("(card|token|cvv|pan|auth|session|refresh|pin)[a-z_]*"\)' out/sources/
```
- **Proof:** The corrected pattern returning hits where the naive one returned zero, shown as two greps
  side by side.
- **Escalation:** The recovered field names become the storage-sweep probes (D11-004) and the backup-rules
  keys (D11-051).
- **Ruled out when:** Both corrected patterns return nothing on a fully exercised, authenticated data
  directory. The naive pattern returning nothing is never the negative.

### D11-008 · Substring searches for short numeric secrets are noise, not evidence

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (accuracy gate) |
| **Attacker** | n/a |
| **Applies to** | all payment, wallet and identity engagements |
| **Maps to** | mechanism; feeds the D23 payment-data claim |

- **Test:** Grepping app storage for a card's last four digits flipped 0 -> 1 -> 0 across three runs of the
  same engagement, because a four-digit string occurs by chance across hundreds of churning binary cache
  files. Use probes that cannot fire randomly: **field names**, **Luhn-valid BIN-shaped 16-digit runs**, and
  database `strings` output.
- **How:**
```bash
strings -a pulled/**/* | grep -oE '\b[2-6][0-9]{15}\b' | sort -u | while read -r n; do
  python3 - "$n" <<'PY'
import sys
n = sys.argv[1]; d = [int(c) for c in n][::-1]
s = sum(d[0::2]) + sum(sum(divmod(x*2, 10)) for x in d[1::2])
print(n) if s % 10 == 0 else None
PY
done
grep -rnE '"(pan|card_number|cardNumber|cvv|cvc|expiry|exp_month)"' pulled/
```
- **Proof:** A Luhn-valid PAN-shaped hit or a field-name hit — never a bare four-digit coincidence. State in
  the report that bare four-digit matches were excluded and why; a triager who has seen that paragraph trusts
  the rest of the payment section.
- **Escalation:** -> D23 payment data; a stored PAN materially raises the data class and is one of the few
  ways a storage finding survives the P5 default.
- **Ruled out when:** The Luhn filter returns nothing and the field-name grep returns nothing across the
  full post-transaction dump. Record both, plus the count of raw four-digit matches you discarded.

### D11-009 · Before declaring a storage or crypto subsystem absent, find the SECOND implementation

| | |
|---|---|
| **Severity ceiling** | Support (it prevents a retracted High) |
| **VRT** | n/a (accuracy gate) |
| **Attacker** | n/a |
| **Applies to** | all; acute on React Native, Flutter and any DI-heavy app |
| **Maps to** | mechanism; the canonical retraction case in the local corpus |

- **Test:** The most instructive retraction in the corpus is a finding whose every `file:line` citation was
  **accurate** and which was still wrong, because a second, fully implemented module provided the capability
  and was the one the app actually used. Accurate citations do not make a finding correct. Before writing
  "the app does not use secure storage", enumerate every registered module and resolve the JS/native name
  mapping.
- **How:**
```bash
grep -rn 'createNativeModules\|ReactPackage\|getPackages\|@Provides\|@Binds\|@Module' out/sources/
grep -rniE 'keychain|securestore|EncryptedSharedPreferences|MasterKey|MMKV|AsyncStorage|preferences_pb' out/sources/
# read the generated PackageList / DI graph END TO END, then check what the JS layer actually calls
grep -rn 'NativeModules\.' assets/index.android.bundle | sort -u | head -40
```
- **Proof:** The worked case: a genuine stub module existed **while** `com.oblador.keychain.KeychainModule`
  (JS name `RNKeychainManager`) was also registered and was what the JS called. The JS-visible module name
  is not the Java class name — resolve that mapping before writing the sentence.
- **Escalation:** The same rule applies to user-facing text: never assert the app tells the user something
  without grepping `res/values/strings.xml` for it. One invented impact bullet discredits the whole report.
- **Ruled out when:** Every module list, DI graph and generated `PackageList` has been read end to end and
  the capability appears in none of them, **and** the JS/native call sites confirm it. A grep of the app's
  own source package only is not the negative.

### D11-010 · Shell-Loop Ban — count your results or the storage sweep lies to you

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (accuracy gate) |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | mechanism (false-positive discipline) |

- **Test:** Shell array loops and `for f in $(adb shell ...)` pipelines fail silently — a device path with a
  space, an `adb` reconnect, a `run-as` denial mid-loop, or a `find` returning nothing all yield an empty
  result set that reads exactly like "clean". Anything iterating more than five items goes in Python, and
  every sweep prints a count.
- **How:**
```bash
# always emit the denominator
N=$(adb shell run-as $PKG find /data/data/$PKG -type f | wc -l); echo "files scanned: $N"
[ "$N" -lt 5 ] && echo "SWEEP FAILED -- run-as denied or app never launched; do not record a negative"
```
```python
import subprocess, re
PKG = "com.target.app"
files = subprocess.run(["adb","shell","run-as",PKG,"find",f"/data/data/{PKG}","-type","f"],
                       capture_output=True, text=True).stdout.split()
print(f"files: {len(files)}")
pat = re.compile(rb"eyJ[A-Za-z0-9_-]{10,}|Bearer |refresh_token|access_token|api[_-]?key", re.I)
hits = 0
for f in files:
    data = subprocess.run(["adb","exec-out","run-as",PKG,"cat",f], capture_output=True).stdout
    if pat.search(data):
        hits += 1; print("HIT", f)
print(f"scanned {len(files)} files, {hits} hits")
```
- **Proof:** Every sweep result in the report carries its denominator ("scanned 412 files, 3 hits"), so a
  reader can tell a real negative from a broken loop.
- **Escalation:** This is what makes the ruled-out register in this chapter trustworthy.
- **Ruled out when:** n/a — this item is always run.
