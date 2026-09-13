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
  removed the need for an information leak entirely — pre-4.0 the dynamic linker itself sat at `0xb0001000`
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
